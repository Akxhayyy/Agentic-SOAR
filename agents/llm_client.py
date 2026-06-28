"""
agents/llm_client.py

Thin wrapper around the local Ollama runtime. Two separate call paths
because they have different hardware routing requirements:

- call_reasoning_model(): hits the quantized Qwen2.5-7B-Instruct-Q4_K_M
  model. Ollama will use GPU by default if available; the ≤6GB VRAM
  ceiling is enforced by the model's quantization choice (Q4_K_M ≈ 4.4GB
  weights + KV cache, which is why num_ctx is hard-capped at 4096 — a
  larger context window is what would actually blow the 6GB ceiling on
  this card, not the weights themselves).

- call_embedding_model(): explicitly sets OLLAMA_NUM_GPU=0 in the request
  options so nomic-embed-text never touches the GPU, leaving full VRAM
  headroom for the reasoning model. This must be passed per-request, not
  just relied on as a global env var, because Streamlit/FastAPI worker
  processes may not inherit the same environment depending on how they're
  launched.
"""

from __future__ import annotations

import logging

import httpx

logger = logging.getLogger("soar.llm_client")

OLLAMA_BASE_URL = "http://localhost:11434"


def call_reasoning_model(
    system_prompt: str,
    user_prompt: str,
    model: str,
    num_ctx: int,
    temperature: float,
    timeout_s: float = 120.0,
) -> str:
    """Calls the local Ollama reasoning model. Returns raw text response."""
    if num_ctx > 4096:
        # Hard architectural invariant — never let a caller silently widen
        # the context window past the VRAM-safe ceiling.
        raise ValueError(f"num_ctx={num_ctx} exceeds the hard cap of 4096")

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "stream": False,
        "options": {
            "num_ctx": num_ctx,
            "temperature": temperature,
        },
    }

    with httpx.Client(timeout=timeout_s) as client:
        resp = client.post(f"{OLLAMA_BASE_URL}/api/chat", json=payload)
        resp.raise_for_status()
        data = resp.json()
        return data["message"]["content"]


def call_embedding_model(text: str, model: str, timeout_s: float = 30.0) -> list[float]:
    """
    Calls the local Ollama embedding model, explicitly pinned to CPU via
    num_gpu=0. nomic-embed-text is small enough that CPU inference is fast
    relative to the rest of the pipeline; the explicit pin matters more for
    leaving GPU memory free for Qwen than for raw embedding speed.
    """
    payload = {
        "model": model,
        "prompt": text,
        "options": {
            "num_gpu": 0,  # 0-byte VRAM cost, runs on CPU threads
        },
    }
    with httpx.Client(timeout=timeout_s) as client:
        resp = client.post(f"{OLLAMA_BASE_URL}/api/embeddings", json=payload)
        resp.raise_for_status()
        data = resp.json()
        return data["embedding"]
