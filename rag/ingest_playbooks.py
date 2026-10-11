"""
rag/ingest_playbooks.py

Run once (or any time you add/edit a playbook .md file under
config/playbooks/). Idempotent: the collection is rebuilt from scratch on
every run, so edits and deletions are reflected and no stale vectors remain.

Chunking is by markdown "## " section (Detection / Containment / Escalation /
False Positives), with the playbook title prepended to every chunk so each
vector carries its playbook context. Oversized sections fall back to a
fixed-size character split.

Usage:
    python -m rag.ingest_playbooks
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from core.graph_config import load_config
from rag.chroma_store import DOCUMENT_PREFIX, _embedding_model_name, reset_collection
from agents.llm_client import call_embedding_model

CHUNK_SIZE_CHARS = 1200
CHUNK_OVERLAP_CHARS = 150


def _split_fixed(text: str) -> list[str]:
    chunks, start = [], 0
    while start < len(text):
        end = start + CHUNK_SIZE_CHARS
        chunks.append(text[start:end])
        if end >= len(text):  # previously re-emitted a duplicate tail chunk
            break
        start = end - CHUNK_OVERLAP_CHARS
    return chunks


def _chunk_text(text: str) -> list[str]:
    lines = text.splitlines()
    title = next((l for l in lines if l.startswith("# ")), "").strip()
    sections: list[str] = []
    current: list[str] = []
    for line in lines:
        if line.startswith("## ") and current:
            sections.append("\n".join(current))
            current = []
        if not line.startswith("# "):
            current.append(line)
    if current:
        sections.append("\n".join(current))

    chunks: list[str] = []
    for section in sections:
        if not section.strip():
            continue
        for piece in _split_fixed(section.strip()):
            chunks.append(f"{title}\n{piece}" if title else piece)
    return chunks


def _deterministic_chunk_id(filename: str, chunk_index: int) -> str:
    digest = hashlib.sha256(f"{filename}:{chunk_index}".encode()).hexdigest()[:16]
    return f"{filename}__chunk{chunk_index}__{digest}"


def ingest_all():
    cfg = load_config()["forensics"]
    playbook_dir = Path(cfg["playbook_dir"])
    if not playbook_dir.exists():
        raise FileNotFoundError(f"Playbook directory not found: {playbook_dir}")

    collection = reset_collection()
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
            embedding = call_embedding_model(DOCUMENT_PREFIX + chunk, model=embedding_model)
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
