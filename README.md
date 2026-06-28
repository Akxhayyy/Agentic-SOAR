# SOAR Capsule — Setup & Run

## 1. Prerequisites (all local, no internet required at runtime)

```bash
pip install -r requirements.txt --break-system-packages

# Pull the two models into your local Ollama runtime (one-time, needs
# internet ONLY for this pull step — the capsule itself never calls out
# once these are cached):
ollama pull qwen2.5:7b-instruct-q4_K_M
ollama pull nomic-embed-text
```

## 2. Ingest the playbook corpus into ChromaDB (one-time, or after editing playbooks)

```bash
python -m rag.ingest_playbooks
```

## 3. Run the backend

```bash
uvicorn main:app --reload --port 8000
```

## 4. Run the dashboard (separate terminal)

```bash
streamlit run dashboard/app.py
```

## 5. Trigger a test incident

```bash
curl -X POST http://127.0.0.1:8000/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "source": "auth-gateway-01",
    "log_type": "AUTH",
    "raw_text": "Failed login for user svc-backup from 10.0.4.17 x14 in 45s, followed by successful login"
  }'
```

This returns an `incident_id`. Paste it into the Streamlit "Incident ID" box
to watch it move through TRIAGED → FORENSICS → (NEUTRALIZER_PLANNED →
AWAITING_HITL, if forensics clears 0.70) or straight to the escalation
report (if it doesn't).

If it reaches AWAITING_HITL, you have 300 seconds (config.hitl.timeout_seconds)
to click APPROVE or REJECT in the dashboard before the system auto-fires
TIMEOUT and escalates.

## Key files to read first, in order of "if this is wrong nothing else matters"

1. `core/uicr_schema.py` — every validation gate the system has
2. `agents/neutralizer.py` + `execution/wrapper.py` — the hash-verification
   tamper-detection contract (these two `_canonical_payload`/`_recompute_hash`
   functions MUST stay byte-identical)
3. `core/graph.py` — the two conditional edge functions
   (`route_after_forensics`, `route_after_hitl`) are the only places
   threshold/decision logic actually branches the graph
4. `config/hitl_config.yaml` — flip `execution.dry_run: false` ONLY after
   wiring a real infra client into `execution/wrapper.py:_get_infra_client()`
   (currently raises `NotImplementedError` by design — fail-closed default)

## What's stubbed vs. production-faithful

| Component | Demo state | Production swap point |
|---|---|---|
| Firewall/directory-service calls | `execution/stub_infra_api.py` (in-memory, simulated) | `execution/wrapper.py:_get_infra_client()` |
| MemorySaver → SqliteSaver | Already done — `core/checkpointer.py` | N/A, already durable |
| Ollama models | Local, already production-faithful | N/A |
| ChromaDB playbooks | One sample playbook included | Add more `.md` files to `config/playbooks/`, re-run ingest |
