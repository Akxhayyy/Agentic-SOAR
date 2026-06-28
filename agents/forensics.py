"""
agents/forensics.py

Forensics Agent Node - the 2-pass confidence-routing RAG loop.

Critical clarification baked into this implementation per your answer #5:
0.70 is the ONLY value the escalation conditional edge inspects. The 0.35
"similarity_floor" on pass 2 is purely a retrieval-recall knob - it widens
what ChromaDB is willing to return as candidate chunks so Qwen has a bigger
context window to re-evaluate, but it never directly decides escalation.

Flow:
  Pass 1: +/-30s window, top_k=5, query ChromaDB -> get best similarity score.
    - If best_score >= 0.70: cleared_threshold=True, done, 1 pass used.
  Pass 2 (only if pass 1 failed): +/-5m window, top_k=8, ChromaDB query uses
    similarity_floor=0.35 to retrieve a wider candidate set -> Qwen
    re-evaluates the full candidate set and the node recomputes
    final_similarity_score from that evaluation.
    - If final_similarity_score >= 0.70: cleared_threshold=True.
    - Else: cleared_threshold=False -> conditional edge in graph.py routes
      straight to emergency escalation, bypassing the Neutralizer entirely.

Note this node does NOT make the escalation decision itself - it only
populates ForensicsResult.cleared_threshold. The actual graph routing logic
lives in core/graph.py's conditional edge function, kept separate so the
decision boundary is auditable in one place.
"""

from __future__ import annotations

import logging

from core.uicr_schema import ForensicsResult, PipelinePhase, PlaybookMatch, UICRState
from core.graph_config import load_config
from rag.chroma_store import query_playbooks

logger = logging.getLogger("soar.forensics")


def forensics_node(state: UICRState) -> UICRState:
    full_cfg = load_config()
    cfg = full_cfg["forensics"]
    hard_threshold = cfg["similarity_hard_threshold"]  # 0.70 - the only decision value

    triage = state["triage"]
    query_text = triage["triage_summary"] if triage else ""

    # --- Pass 1 ---------------------------------------------------------
    p1_cfg = cfg["pass_1"]
    pass1_matches = query_playbooks(
        query_text=query_text,
        top_k=p1_cfg["top_k"],
        similarity_floor=None,  # pass 1 uses ChromaDB's default ranking, no floor relax
    )
    best_score_p1 = max((m.similarity_score for m in pass1_matches), default=0.0)

    if best_score_p1 >= hard_threshold:
        result = ForensicsResult(
            matches=pass1_matches,
            pass_count=1,
            final_similarity_score=best_score_p1,
            cleared_threshold=True,
            rag_timeline_notes=f"Cleared on pass 1 (+/-{p1_cfg['window_seconds']}s window).",
        )
        state["forensics"] = result.model_dump(mode="json")
        state["current_phase"] = PipelinePhase.FORENSICS_PASS_1.value
        return state

    # --- Pass 2 (only reached if pass 1 failed) --------------------------
    logger.info(
        "Pass 1 best_score=%.3f below hard threshold %.2f; expanding to pass 2",
        best_score_p1, hard_threshold,
    )
    p2_cfg = cfg["pass_2"]
    pass2_matches = query_playbooks(
        query_text=query_text,
        top_k=p2_cfg["top_k"],
        similarity_floor=p2_cfg["similarity_floor"],  # 0.35 - recall widening ONLY
    )

    # Qwen re-evaluates the broader candidate set to recompute a final score.
    # This is a re-ranking step, not a second independent similarity metric -
    # it asks the model "given these wider candidates, how well does the best
    # one actually match the incident", producing final_similarity_score.
    final_score = _rerank_with_llm(query_text, pass2_matches, cfg=full_cfg)

    cleared = final_score >= hard_threshold
    result = ForensicsResult(
        matches=pass2_matches,
        pass_count=2,
        final_similarity_score=final_score,
        cleared_threshold=cleared,
        rag_timeline_notes=(
            f"Pass 2 (+/-{p2_cfg['window_seconds']}s window, floor={p2_cfg['similarity_floor']}): "
            f"final_score={final_score:.3f}, "
            f"{'cleared' if cleared else 'did NOT clear'} hard threshold {hard_threshold}."
        ),
    )
    state["forensics"] = result.model_dump(mode="json")
    state["current_phase"] = PipelinePhase.FORENSICS_PASS_2.value
    return state


def _rerank_with_llm(query_text: str, candidates: list[PlaybookMatch], cfg: dict) -> float:
    """
    Asks the reasoning model to score the single best-matching candidate
    against the incident summary on a 0-1 scale. Kept deliberately simple
    (single float out) - this is a confidence re-score, not a generative
    task, so it stays zero-temperature and schema-constrained like triage.
    """
    from agents.llm_client import call_reasoning_model
    import json

    if not candidates:
        return 0.0

    candidate_block = "\n\n".join(
        f"[{i}] (vector_score={c.similarity_score:.3f}) {c.chunk_text}"
        for i, c in enumerate(candidates)
    )
    system_prompt = (
        "You score how well ONE of the provided playbook chunks matches the "
        "incident summary. Output ONLY JSON: {\"best_index\": int, \"match_score\": float 0-1}. "
        "No commentary."
    )
    model_cfg = cfg["models"]["reasoning"]
    raw = call_reasoning_model(
        system_prompt=system_prompt,
        user_prompt=f"Incident summary: {query_text}\n\nCandidates:\n{candidate_block}",
        model=model_cfg["model"],
        num_ctx=model_cfg["num_ctx"],
        temperature=model_cfg["temperature"],
    )
    try:
        parsed = json.loads(raw)
        score = float(parsed["match_score"])
        return max(0.0, min(1.0, score))
    except (ValueError, KeyError, TypeError) as e:
        logger.warning("Rerank parse failed (%s); falling back to max vector score", e)
        return max((c.similarity_score for c in candidates), default=0.0)
