"""
main.py

FastAPI backend for the SOAR Capsule.

Responsibilities:
  1. Untrusted ingestion boundary — payloads are forced through RawLogEntry
     (Pydantic) before anything touches the UICR or the graph.
  2. Background ingest jobs — POST /api/ingest_file returns a job_id at once;
     the batch runs in a worker thread and reports progress (GET /api/jobs/{id}
     + SSE). The old blocking endpoint made the dashboard time out on any file
     producing more than a couple of incidents.
  3. HITL decisions — POST /api/incidents/{id}/decision resumes the paused
     graph with Command(resume=...) on the SAME thread_id. A per-incident
     asyncio.Lock plus an "is it actually paused?" check make double-clicks
     and operator/timeout races safe (409 instead of a second resume).
  4. HITL timeout — LangGraph's interrupt() has no clock, so a watcher task
     per paused incident fires TIMEOUT. The deadline is derived from
     state.hitl_paused_at (persisted by the hitl_arm node), so watchers are
     re-armed with the REMAINING time after a backend restart.
  5. Read APIs for the UI (incidents, health, playbooks, reports, audit) and
     a Server-Sent Events stream of pipeline progress.

Everything is localhost-only: Ollama and ChromaDB are local, no outbound calls.
Run with: uvicorn main:app --port 8000
"""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from langgraph.types import Command
from pydantic import BaseModel, Field

from core import events
from core.audit import audit, tail as audit_tail
from core.checkpointer import thread_config_for_incident
from core.graph import get_compiled_graph
from core.graph_config import PROJECT_ROOT, load_config, reasoning_model_for
from core.uicr_schema import ActionType, HitlDecision, RawLogEntry, new_incident_state
from ingestion import log_store
from ingestion.batch_processor import preview_log_file, process_log_file
from ingestion.cheap_filter import parse_log_file

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("soar.main")

FRONTEND_DIST = PROJECT_ROOT / "frontend" / "dist"
SAMPLES_DIR = PROJECT_ROOT / "data" / "samples"

TIMEOUT_TASKS: dict[str, asyncio.Task] = {}
_incident_locks: dict[str, asyncio.Lock] = {}
JOBS: dict[str, dict] = {}


def _lock_for(incident_id: str) -> asyncio.Lock:
    return _incident_locks.setdefault(incident_id, asyncio.Lock())


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Lifespan: bind the event bus, check Ollama, re-arm HITL watchers
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(_app: FastAPI):
    events.bind_loop(asyncio.get_running_loop())

    from agents.llm_client import ollama_status
    status = await asyncio.to_thread(ollama_status, _required_models())
    if not status["online"]:
        logger.warning("Ollama is not reachable — incidents will fail until `ollama serve` is running.")
    elif status["missing"]:
        logger.warning("Models not pulled: %s — run `ollama pull <model>`.", status["missing"])

    rearmed = await _rearm_paused_incidents()
    if rearmed:
        logger.info("Re-armed HITL timeout watchers for %d paused incident(s).", rearmed)
    yield
    for task in list(TIMEOUT_TASKS.values()):
        task.cancel()


app = FastAPI(title="Agentic SOAR Capsule", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],  # Vite dev server only
    allow_methods=["*"],
    allow_headers=["*"],
)


def _required_models() -> list[str]:
    cfg = load_config()["models"]
    names = {cfg["reasoning"]["model"], cfg["embedding"]["model"]}
    names |= {m for m in (cfg["reasoning"].get("per_agent") or {}).values() if m}
    return sorted(names)


# ---------------------------------------------------------------------------
# Graph helpers
# ---------------------------------------------------------------------------

def _graph_is_paused_at_hitl(graph, config) -> bool:
    snapshot = graph.get_state(config)
    return bool(snapshot.next) and "hitl_gate_node" in snapshot.next


def _all_thread_ids() -> list[str]:
    saver = get_compiled_graph().checkpointer
    with saver.cursor(transaction=False) as cur:
        cur.execute("SELECT DISTINCT thread_id FROM checkpoints")
        return [r[0] for r in cur.fetchall()]


def _remaining_s(state: dict, paused: bool) -> int | None:
    if not paused:
        return None
    timeout_s = load_config()["hitl"]["timeout_seconds"]
    paused_at = state.get("hitl_paused_at")
    if not paused_at:
        return timeout_s
    deadline = datetime.fromisoformat(paused_at) + timedelta(seconds=timeout_s)
    return max(0, int((deadline - _now()).total_seconds()))


def _summary(incident_id: str, state: dict, paused: bool) -> dict:
    triage = state.get("triage") or {}
    plan = state.get("action_plan") or {}
    forensics = state.get("forensics") or {}
    history = state.get("phase_history") or []
    return {
        "incident_id": incident_id,
        "created_at": state.get("created_at"),
        "group_key": state.get("group_key"),
        "attack_vector": triage.get("attack_vector"),
        "triage_confidence": triage.get("triage_confidence"),
        "mitre_techniques": triage.get("mitre_techniques", []),
        "ioc_count": len(triage.get("iocs") or []),
        "event_count": len(state.get("raw_logs") or []),
        "forensics_score": forensics.get("final_similarity_score"),
        "playbook": forensics.get("best_playbook"),
        "action_type": plan.get("action_type"),
        "action_target": plan.get("target"),
        "current_phase": state.get("current_phase"),
        "threat_status": state.get("threat_status"),
        "hitl_decision": state.get("hitl_decision"),
        "awaiting_hitl": paused,
        "hitl_timeout_remaining_seconds": _remaining_s(state, paused),
        "error": state.get("error"),
        "pipeline_seconds": round(sum(h.get("duration_s", 0) for h in history
                                      if h.get("node") != "hitl_gate_node"), 2),
        "rolled_back": bool(state.get("rollback_result")),
    }


def _load_incident(incident_id: str) -> tuple[dict, bool]:
    snapshot = get_compiled_graph().get_state(thread_config_for_incident(incident_id))
    if not snapshot or not snapshot.values:
        raise HTTPException(status_code=404, detail="Incident not found.")
    paused = bool(snapshot.next) and "hitl_gate_node" in snapshot.next
    return snapshot.values, paused


# ---------------------------------------------------------------------------
# HITL: resume + timeout watchers
# ---------------------------------------------------------------------------

async def _resume(incident_id: str, decision: str, actor: str, note: str | None = None) -> dict:
    """Single resume path for operator decisions and timeouts."""
    async with _lock_for(incident_id):
        graph = get_compiled_graph()
        config = thread_config_for_incident(incident_id)
        if not await asyncio.to_thread(_graph_is_paused_at_hitl, graph, config):
            raise HTTPException(status_code=409, detail="Incident is not awaiting a decision.")

        task = TIMEOUT_TASKS.pop(incident_id, None)
        if task and task is not asyncio.current_task():
            task.cancel()

        audit("hitl_decision", incident_id, actor=actor, decision=decision, note=note)
        events.publish("hitl_decided", incident_id=incident_id, decision=decision, actor=actor)
        result = await asyncio.to_thread(
            graph.invoke, Command(resume={"decision": decision, "note": note}), config
        )
        audit("incident_closed", incident_id, threat_status=result.get("threat_status"),
              phase=result.get("current_phase"))
        return result


async def _timeout_watcher(incident_id: str, delay_s: float):
    try:
        await asyncio.sleep(max(0.0, delay_s))
        logger.warning("Incident %s reached the HITL timeout; auto-resuming with TIMEOUT.", incident_id)
        try:
            await _resume(incident_id, HitlDecision.TIMEOUT.value, actor="system")
        except HTTPException:
            pass  # operator decided in the meantime
    except asyncio.CancelledError:
        pass


async def _arm_watcher(incident_id: str) -> None:
    """Starts (or restarts) the timeout watcher using the persisted pause time."""
    try:
        state, paused = await asyncio.to_thread(_load_incident, incident_id)
    except HTTPException:
        return
    if not paused:
        return
    old = TIMEOUT_TASKS.pop(incident_id, None)
    if old:
        old.cancel()
    remaining = _remaining_s(state, paused) or 0
    TIMEOUT_TASKS[incident_id] = asyncio.create_task(_timeout_watcher(incident_id, remaining))


async def _rearm_paused_incidents() -> int:
    try:
        thread_ids = await asyncio.to_thread(_all_thread_ids)
    except Exception:  # noqa: BLE001 — fresh DB without tables
        return 0
    for tid in thread_ids:
        await _arm_watcher(tid)
    return len(TIMEOUT_TASKS)


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------

class IngestPayload(BaseModel):
    source: str
    log_type: str
    raw_text: str


async def _run_single(payload: IngestPayload) -> dict:
    try:
        entry = RawLogEntry(source=payload.source, log_type=payload.log_type, raw_text=payload.raw_text)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=422, detail=f"Log validation failed: {e}")

    state = new_incident_state()
    state["raw_logs"] = [entry.model_dump(mode="json")]
    incident_id = state["incident_id"]
    parsed = parse_log_file(entry.raw_text, default_log_type=entry.log_type)
    stamp = next((l.timestamp for l in parsed if l.timestamp), entry.received_at)
    state["time_window"] = {"first_seen": stamp.isoformat(), "last_seen": stamp.isoformat()}
    try:
        await asyncio.to_thread(log_store.add_lines, f"single:{incident_id}", parsed)
    except Exception:  # noqa: BLE001 — enrichment only
        logger.exception("Failed to persist line to the log store")
    audit("ingest", incident_id, source=payload.source, lines=1)
    events.publish("incident_created", incident_id=incident_id, group_key=None)

    graph = get_compiled_graph()
    result = await asyncio.to_thread(graph.invoke, state, thread_config_for_incident(incident_id))
    await _arm_watcher(incident_id)
    return {"incident_id": incident_id, "state_snapshot": result}


@app.post("/api/ingest")
async def api_ingest(payload: IngestPayload):
    return await _run_single(payload)


class BatchIngestPayload(BaseModel):
    file_text: str = Field(..., max_length=5_000_000)
    default_log_type: str = Field(default="GENERIC", max_length=32)
    delimiter: str | None = None
    filename: str | None = Field(default=None, max_length=200)


@app.post("/api/ingest_file/preview")
async def api_ingest_preview(payload: BatchIngestPayload):
    if not payload.file_text.strip():
        raise HTTPException(status_code=422, detail="file_text is empty.")
    return await asyncio.to_thread(
        preview_log_file, payload.file_text, payload.default_log_type, payload.delimiter
    )


@app.post("/api/ingest_file", status_code=202)
async def api_ingest_file(payload: BatchIngestPayload):
    if not payload.file_text.strip():
        raise HTTPException(status_code=422, detail="file_text is empty.")
    job_id = str(uuid.uuid4())
    job = {
        "job_id": job_id,
        "filename": payload.filename,
        "status": "screening",
        "created_at": _now().isoformat(),
        "finished_at": None,
        "total_lines": None,
        "suspicious_lines": None,
        "total_groups": None,
        "completed": 0,
        "incidents": [],
        "error": None,
    }
    JOBS[job_id] = job
    audit("batch_ingest", None, job_id=job_id, filename=payload.filename, bytes=len(payload.file_text))
    asyncio.create_task(_run_job(job, payload))
    return dict(job)


async def _run_job(job: dict, payload: BatchIngestPayload) -> None:
    loop = asyncio.get_running_loop()

    def on_groups(groups):
        job["status"] = "running"
        job["total_groups"] = len(groups)
        events.publish("job_progress", job=dict(job))

    def on_incident(summary: dict):
        job["incidents"].append(summary)
        job["completed"] += 1
        events.publish("incident_created", incident_id=summary["incident_id"], group_key=summary["group_key"])
        events.publish("job_progress", job=dict(job))
        asyncio.run_coroutine_threadsafe(_arm_watcher(summary["incident_id"]), loop)

    try:
        result = await asyncio.to_thread(
            process_log_file, payload.file_text, payload.default_log_type, payload.delimiter,
            on_incident, on_groups,
        )
        job.update(
            status="done",
            total_lines=result["total_lines"],
            suspicious_lines=result["suspicious_lines"],
            total_groups=result["incident_groups_created"],
        )
    except Exception as e:  # noqa: BLE001
        logger.exception("Batch job %s failed", job["job_id"])
        job.update(status="failed", error=str(e)[:500])
    job["finished_at"] = _now().isoformat()
    events.publish("job_progress", job=dict(job))


@app.get("/api/jobs/{job_id}")
async def api_job(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
    return job


@app.get("/api/jobs")
async def api_jobs():
    return sorted(JOBS.values(), key=lambda j: j["created_at"], reverse=True)[:20]


@app.get("/api/samples")
async def api_samples():
    if not SAMPLES_DIR.exists():
        return []
    return [{"name": p.name, "bytes": p.stat().st_size} for p in sorted(SAMPLES_DIR.iterdir()) if p.is_file()]


@app.get("/api/samples/{name}")
async def api_sample(name: str):
    path = (SAMPLES_DIR / name).resolve()
    if path.parent != SAMPLES_DIR.resolve() or not path.is_file():
        raise HTTPException(status_code=404, detail="Sample not found.")
    return {"name": path.name, "text": path.read_text(encoding="utf-8", errors="replace")}


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

@app.get("/api/incidents")
async def api_incidents(limit: int = Query(default=200, le=1000)):
    def _collect():
        graph = get_compiled_graph()
        out = []
        for tid in _all_thread_ids():
            snap = graph.get_state(thread_config_for_incident(tid))
            if snap and snap.values:
                paused = bool(snap.next) and "hitl_gate_node" in snap.next
                out.append(_summary(tid, snap.values, paused))
        out.sort(key=lambda s: s.get("created_at") or "", reverse=True)
        return out[:limit]

    try:
        return await asyncio.to_thread(_collect)
    except Exception:  # noqa: BLE001 — fresh DB without tables
        logger.exception("Incident listing failed")
        return []


@app.get("/api/incidents/{incident_id}")
async def api_incident(incident_id: str):
    state, paused = await asyncio.to_thread(_load_incident, incident_id)
    cfg = load_config()
    return {
        "incident_id": incident_id,
        "summary": _summary(incident_id, state, paused),
        "state": state,
        "hitl_timeout_seconds": cfg["hitl"]["timeout_seconds"],
        "threshold": cfg["forensics"]["similarity_hard_threshold"],
        "dry_run": cfg["execution"]["dry_run"],
    }


class DecisionPayload(BaseModel):
    decision: str
    note: str | None = Field(default=None, max_length=500)
    operator: str = Field(default="operator", max_length=64)


@app.post("/api/incidents/{incident_id}/decision")
async def api_decision(incident_id: str, body: DecisionPayload):
    if body.decision not in (HitlDecision.APPROVED.value, HitlDecision.REJECTED.value):
        raise HTTPException(status_code=400, detail="decision must be APPROVED or REJECTED (TIMEOUT is system-fired only).")
    await _resume(incident_id, body.decision, actor=body.operator, note=body.note)
    state, paused = await asyncio.to_thread(_load_incident, incident_id)
    return {"incident_id": incident_id, "summary": _summary(incident_id, state, paused)}


_ROLLBACKS = {
    ActionType.ISOLATE_HOST.value: "remove_host_isolation",
    ActionType.LOCK_ACCOUNT.value: "unlock_account",
    ActionType.TERMINATE_PROCESS.value: "restore_process",
    ActionType.QUARANTINE_PROCESS.value: "restore_process",
    ActionType.BLOCK_PROXY_IP.value: "unblock_proxy_ip",
}


class RollbackPayload(BaseModel):
    operator: str = Field(default="operator", max_length=64)
    note: str | None = Field(default=None, max_length=500)


@app.post("/api/incidents/{incident_id}/rollback")
async def api_rollback(incident_id: str, body: RollbackPayload):
    from execution import wrapper

    async with _lock_for(incident_id):
        state, paused = await asyncio.to_thread(_load_incident, incident_id)
        result = state.get("execution_result") or {}
        if paused or not result.get("success"):
            raise HTTPException(status_code=409, detail="No successfully executed action to roll back.")
        if state.get("rollback_result"):
            raise HTTPException(status_code=409, detail="Action was already rolled back.")
        fn_name = _ROLLBACKS.get(result.get("action_type"))
        if not fn_name:
            raise HTTPException(status_code=409, detail="This action type has no rollback.")

        # Static dispatch through the wrapper's charset-checked rollback functions.
        fn = {
            "remove_host_isolation": wrapper.remove_host_isolation,
            "unlock_account": wrapper.unlock_account,
            "restore_process": wrapper.restore_process,
            "unblock_proxy_ip": wrapper.unblock_proxy_ip,
        }[fn_name]
        try:
            response = await asyncio.to_thread(fn, result["target"])
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        rollback = {"action": fn_name, "target": result["target"], "by": body.operator,
                    "note": body.note, "at": _now().isoformat(), "response": response}
        await asyncio.to_thread(
            get_compiled_graph().update_state, thread_config_for_incident(incident_id),
            {"rollback_result": rollback}, "generate_report",
        )
        audit("rollback", incident_id, actor=body.operator, action=fn_name, target=result["target"], note=body.note)
        events.publish("incident_updated", incident_id=incident_id)
        return rollback


@app.get("/api/incidents/{incident_id}/report")
async def api_report(incident_id: str):
    state, _ = await asyncio.to_thread(_load_incident, incident_id)
    path = state.get("report_path")
    if not path or not Path(path).exists():
        raise HTTPException(status_code=404, detail="Report not generated yet.")
    return {"incident_id": incident_id, "markdown": Path(path).read_text(encoding="utf-8")}


@app.get("/api/incidents/{incident_id}/audit")
async def api_incident_audit(incident_id: str):
    return await asyncio.to_thread(audit_tail, 200, incident_id)


# ---------------------------------------------------------------------------
# System
# ---------------------------------------------------------------------------

_gpu_cache: dict = {"at": -100.0, "value": None}


def _gpu_info() -> dict | None:
    if time.monotonic() - _gpu_cache["at"] < 10:
        return _gpu_cache["value"]
    value = None
    try:
        res = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,memory.total,memory.used", "--format=csv,nounits,noheader"],
            capture_output=True, text=True, timeout=5.0,
        )
        if res.returncode == 0 and res.stdout.strip():
            name, total, used = [x.strip() for x in res.stdout.strip().splitlines()[0].split(",")]
            value = {"name": name, "vram_total_mb": int(total), "vram_used_mb": int(used)}
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    _gpu_cache.update(at=time.monotonic(), value=value)
    return value


@app.get("/api/health")
async def api_health():
    from agents.llm_client import ollama_status
    from rag.chroma_store import collection_count

    cfg = load_config()
    ollama, chunks, gpu = await asyncio.gather(
        asyncio.to_thread(ollama_status, _required_models()),
        asyncio.to_thread(collection_count),
        asyncio.to_thread(_gpu_info),
    )
    return {
        "backend": True,
        "ollama": ollama,
        "reasoning_model": cfg["models"]["reasoning"]["model"],
        "embedding_model": cfg["models"]["embedding"]["model"],
        "num_ctx": cfg["models"]["reasoning"]["num_ctx"],
        "playbook_chunks": chunks,
        "dry_run": cfg["execution"]["dry_run"],
        "security": cfg["security"],
        "hitl_timeout_seconds": cfg["hitl"]["timeout_seconds"],
        "gpu": gpu,
        "awaiting_hitl": len(TIMEOUT_TASKS),
    }


@app.post("/api/system/benchmark")
async def api_benchmark():
    from agents.llm_client import call_embedding_model, call_reasoning_model_ex

    cfg = load_config()
    out: dict = {}
    t0 = time.perf_counter()
    try:
        await asyncio.to_thread(call_embedding_model, "search_query: diagnostic check", cfg["models"]["embedding"]["model"])
        out["embedding_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    except Exception as e:  # noqa: BLE001
        out["embedding_error"] = str(e)[:200]
    try:
        model = reasoning_model_for("triage")
        resp = await asyncio.to_thread(
            call_reasoning_model_ex,
            "You are a diagnostics probe.", "List three common network ports and their services, one line each.",
            model["model"], 1024, 0.0,
        )
        out.update(
            model=resp.model, output_tokens=resp.output_tokens, prompt_tokens=resp.prompt_tokens,
            tokens_per_s=round(resp.tokens_per_s, 1), generation_s=round(resp.duration_s, 2),
        )
    except Exception as e:  # noqa: BLE001
        out["reasoning_error"] = str(e)[:200]
    return out


@app.get("/api/playbooks")
async def api_playbooks():
    pdir = Path(load_config()["forensics"]["playbook_dir"])
    books = []
    for p in sorted(pdir.glob("*.md")):
        text = p.read_text(encoding="utf-8")
        title = next((l[2:].strip() for l in text.splitlines() if l.startswith("# ")), p.stem)
        books.append({"id": p.name, "title": title, "markdown": text})
    return books


@app.get("/api/config")
async def api_config():
    cfg = load_config()
    return {k: cfg[k] for k in ("execution", "security", "hitl", "forensics", "models", "mitre") if k in cfg}


def _latest_results(kind: str) -> dict:
    runs = sorted((PROJECT_ROOT / "data" / kind).glob("run_*/results.json"))
    if not runs:
        raise HTTPException(status_code=404, detail=f"No {kind} results yet. Run scripts/{'eval' if kind == 'eval' else 'redteam'}.py.")
    data = json.loads(runs[-1].read_text(encoding="utf-8"))
    data.pop("results", None)  # per-scenario rows are large; the UI only needs metrics
    data.pop("rows", None)
    return data


@app.get("/api/eval/latest")
async def api_eval_latest():
    return await asyncio.to_thread(_latest_results, "eval")


@app.get("/api/redteam/latest")
async def api_redteam_latest():
    return await asyncio.to_thread(_latest_results, "redteam")


@app.get("/api/audit")
async def api_audit(limit: int = Query(default=100, le=1000)):
    return await asyncio.to_thread(audit_tail, limit)


@app.get("/api/events")
async def api_events():
    q = events.subscribe()

    async def stream():
        try:
            yield "retry: 3000\n\n"
            while True:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=15)
                    yield f"event: {event['type']}\ndata: {json.dumps(event, default=str)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
        finally:
            events.unsubscribe(q)

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------------------------------------------------------------------------
# Legacy routes (kept for scripts and the README curl examples)
# ---------------------------------------------------------------------------

@app.post("/ingest")
async def ingest_logs(payload: IngestPayload):
    return await _run_single(payload)


@app.post("/ingest_file")
async def ingest_log_file(payload: BatchIngestPayload):
    """Blocking variant kept for scripts; the UI uses POST /api/ingest_file."""
    if not payload.file_text.strip():
        raise HTTPException(status_code=422, detail="file_text is empty.")
    summary = await asyncio.to_thread(
        process_log_file, payload.file_text, payload.default_log_type, payload.delimiter
    )
    for incident in summary["incidents"]:
        await _arm_watcher(incident["incident_id"])
    return summary


class ResumeDecision(BaseModel):
    decision: str


@app.post("/resume/{incident_id}")
async def resume_incident(incident_id: str, body: ResumeDecision):
    if body.decision not in (HitlDecision.APPROVED.value, HitlDecision.REJECTED.value):
        raise HTTPException(status_code=400, detail="decision must be APPROVED or REJECTED (TIMEOUT is system-fired only).")
    result = await _resume(incident_id, body.decision, actor="operator")
    return {"incident_id": incident_id, "state_snapshot": result}


@app.get("/incident/{incident_id}")
async def get_incident_state(incident_id: str):
    state, paused = await asyncio.to_thread(_load_incident, incident_id)
    return {
        "incident_id": incident_id,
        "state": state,
        "paused_at": ["hitl_gate_node"] if paused else [],
        "hitl_timeout_remaining_seconds": _remaining_s(state, paused),
    }


# ---------------------------------------------------------------------------
# React UI (Phase 2) — served from frontend/dist when built
# ---------------------------------------------------------------------------

@app.get("/{full_path:path}", include_in_schema=False)
async def spa(full_path: str):
    if full_path.startswith(("api/", "docs", "openapi")):
        raise HTTPException(status_code=404)
    if not FRONTEND_DIST.exists():
        return {"detail": "UI not built. Run `npm run build` in frontend/, or use /docs."}
    candidate = (FRONTEND_DIST / full_path).resolve()
    if full_path and candidate.is_file() and FRONTEND_DIST.resolve() in candidate.parents:
        return FileResponse(candidate)
    return FileResponse(FRONTEND_DIST / "index.html")
