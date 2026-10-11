"""
rag/chroma_store.py

Local, CPU-bound ChromaDB wrapper. ChromaDB itself runs entirely on CPU/disk
(no GPU dependency) — the only thing we have to be careful about is that the
embedding FUNCTION we hand it also stays off the GPU, which is why we pass a
custom embedding callable (using llm_client.call_embedding_model, which pins
num_gpu=0) rather than letting Chroma default to a GPU-capable local model.

similarity_floor semantics:
  Chroma's default query() returns the top_k nearest neighbors by distance
  with no minimum-similarity filtering. "similarity_floor" is implemented
  here as a POST-FILTER + top_k inflation: we over-fetch (top_k * 3, capped)
  and then keep up to top_k results whose score >= floor. This widens recall
  on pass 2 without Chroma needing native floor support, and never affects
  the hard 0.70 escalation decision made later in forensics.py.
"""

from __future__ import annotations

import os
from pathlib import Path

import chromadb

from core.uicr_schema import PlaybookMatch
from core.graph_config import load_config
from agents.llm_client import call_embedding_model

_COLLECTION_NAME = "soar_playbooks"
_COLLECTION_METADATA = {"hnsw:space": "cosine"}

# nomic-embed-text is trained with task prefixes; omitting them noticeably
# lowers similarity for genuinely matching query/document pairs.
QUERY_PREFIX = "search_query: "
DOCUMENT_PREFIX = "search_document: "
_client = None  # lazy singleton, initialized on first call


def _get_client():
    global _client
    if _client is None:
        cfg = load_config()["forensics"]
        persist_dir = Path(cfg["chroma_persist_dir"]).resolve()
        persist_dir.mkdir(parents=True, exist_ok=True)
        _client = chromadb.PersistentClient(path=str(persist_dir))
    return _client


def _get_collection():
    # Always pass the cosine metadata: previously a query that ran before
    # ingest created the collection in Chroma's default L2 space, making the
    # `1 - distance` similarity math below meaningless.
    client = _get_client()
    return client.get_or_create_collection(name=_COLLECTION_NAME, metadata=_COLLECTION_METADATA)


def collection_count() -> int:
    try:
        return _get_collection().count()
    except Exception:  # noqa: BLE001 — health probe only
        return 0


def _embedding_model_name() -> str:
    return load_config()["models"]["embedding"]["model"]


def query_playbooks(
    query_text: str,
    top_k: int,
    similarity_floor: float | None,
) -> list[PlaybookMatch]:
    """
    Returns up to top_k PlaybookMatch objects.

    - similarity_floor=None (pass 1): straightforward top_k nearest-neighbor
      query, no post-filtering. Highest precision, narrowest recall.
    - similarity_floor=X (pass 2): over-fetch then filter by score >= X,
      widening the candidate pool Qwen sees during re-ranking.
    """
    collection = _get_collection()
    if collection.count() == 0:
        return []

    query_embedding = call_embedding_model(QUERY_PREFIX + query_text, model=_embedding_model_name())

    fetch_n = top_k if similarity_floor is None else min(top_k * 3, collection.count())
    raw = collection.query(
        query_embeddings=[query_embedding],
        n_results=fetch_n,
    )

    matches: list[PlaybookMatch] = []
    ids = raw.get("ids", [[]])[0]
    documents = raw.get("documents", [[]])[0]
    distances = raw.get("distances", [[]])[0]
    metadatas = (raw.get("metadatas") or [[]])[0] or [{}] * len(ids)

    for doc_id, doc_text, distance, meta in zip(ids, documents, distances, metadatas):
        # Chroma's default distance is L2 or cosine-distance depending on
        # collection config; we configure cosine space at collection
        # creation time, so similarity = 1 - cosine_distance.
        similarity = max(0.0, 1.0 - distance)

        if similarity_floor is not None and similarity < similarity_floor:
            continue

        matches.append(
            PlaybookMatch(
                playbook_id=str((meta or {}).get("source_file") or doc_id)[:128],
                chunk_text=doc_text[:2048],
                similarity_score=round(similarity, 4),
            )
        )
        if len(matches) >= top_k:
            break

    # Highest similarity first, regardless of Chroma's native ordering.
    matches.sort(key=lambda m: m.similarity_score, reverse=True)
    return matches


def reset_collection():
    """
    Drops and recreates the collection in cosine space. Called by
    rag/ingest_playbooks.py so a re-ingest never mixes vectors embedded with
    different prefixes/models, and a legacy L2 collection gets replaced.
    """
    client = _get_client()
    try:
        client.delete_collection(_COLLECTION_NAME)
    except Exception:  # noqa: BLE001 — collection may not exist yet
        pass
    return client.get_or_create_collection(name=_COLLECTION_NAME, metadata=_COLLECTION_METADATA)
