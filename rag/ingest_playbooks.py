"""
rag/ingest_playbooks.py

Run once (or any time you add/edit a playbook .md file under
config/playbooks/). Idempotent: re-running re-embeds and upserts by
deterministic chunk ID (filename + chunk index), so duplicate runs don't
create duplicate vectors.

Usage:
    python -m rag.ingest_playbooks
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from core.graph_config import load_config
from rag.chroma_store import _get_collection, ensure_cosine_collection, _embedding_model_name
from agents.llm_client import call_embedding_model

CHUNK_SIZE_CHARS = 1200
CHUNK_OVERLAP_CHARS = 150


def _chunk_text(text: str) -> list[str]:
    chunks = []
    start = 0
    while start < len(text):
        end = start + CHUNK_SIZE_CHARS
        chunks.append(text[start:end])
        start = end - CHUNK_OVERLAP_CHARS
        if start <= 0:
            break
    return [c for c in chunks if c.strip()]


def _deterministic_chunk_id(filename: str, chunk_index: int) -> str:
    digest = hashlib.sha256(f"{filename}:{chunk_index}".encode()).hexdigest()[:16]
    return f"{filename}__chunk{chunk_index}__{digest}"


def ingest_all():
    cfg = load_config()["forensics"]
    playbook_dir = Path(cfg["playbook_dir"])
    if not playbook_dir.exists():
        raise FileNotFoundError(f"Playbook directory not found: {playbook_dir}")

    ensure_cosine_collection()
    collection = _get_collection()
    embedding_model = _embedding_model_name()

    md_files = sorted(playbook_dir.glob("*.md"))
    if not md_files:
        print(f"No .md playbooks found in {playbook_dir} — nothing to ingest.")
        return

    total_chunks = 0
    for md_file in md_files:
        text = md_file.read_text(encoding="utf-8")
        chunks = _chunk_text(text)

        ids, embeddings, documents, metadatas = [], [], [], []
        for i, chunk in enumerate(chunks):
            chunk_id = _deterministic_chunk_id(md_file.name, i)
            embedding = call_embedding_model(chunk, model=embedding_model)
            ids.append(chunk_id)
            embeddings.append(embedding)
            documents.append(chunk)
            metadatas.append({"source_file": md_file.name, "chunk_index": i})

        collection.upsert(
            ids=ids,
            embeddings=embeddings,
            documents=documents,
            metadatas=metadatas,
        )
        total_chunks += len(chunks)
        print(f"Ingested {len(chunks)} chunks from {md_file.name}")

    print(f"Done. {total_chunks} total chunks across {len(md_files)} playbooks "
          f"in collection (count={collection.count()}).")


if __name__ == "__main__":
    ingest_all()
