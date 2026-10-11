"""
agents/llm_client.py

Thin wrapper around the local Ollama runtime. Two separate call paths
because they have different hardware routing requirements:

- call_reasoning_model(): hits the configured reasoning model (default
  qwen3:8b Q4_K_M). Ollama uses the GPU when available; the VRAM ceiling is
  enforced by the quantization choice plus a hard num_ctx cap — a larger
  context window is what would actually blow the VRAM budget, not the
  weights themselves.

  When a `schema` is given, it is passed as Ollama's structured-output
  `format` (a JSON schema), so the model is grammar-constrained to emit
  valid JSON for that schema. This replaced prompt-only "please output
  JSON" instructions, which small models regularly ignored by wrapping the
  output in ```json fences — every such response used to fail json.loads()
  and silently degrade the incident to UNKNOWN / NO_ACTION.

- call_embedding_model(): pins num_gpu=0 per request so nomic-embed-text
  never touches the GPU, leaving full VRAM headroom for the reasoning model.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from dataclasses import dataclass
from functools import lru_cache

import httpx

logger = logging.getLogger("soar.llm_client")

OLLAMA_BASE_URL = "http://localhost:11434"
NUM_CTX_HARD_CAP = 8192

_FENCE_RE = re.compile(r"^\s*```[a-zA-Z0-9_-]*\s*\n?(.*?)\n?\s*```\s*$", re.S)
_THINK_RE = re.compile(r"<think>.*?</think>", re.S)


class LLMUnavailableError(RuntimeError):
    """Ollama is unreachable or the requested model is not pulled."""


# Process-wide token accounting (read by scripts/eval.py between scenarios).
_usage_lock = threading.Lock()
_usage = {"calls": 0, "prompt_tokens": 0, "output_tokens": 0}


def reset_usage() -> None:
    with _usage_lock:
        _usage.update(calls=0, prompt_tokens=0, output_tokens=0)


def usage_snapshot() -> dict:
    with _usage_lock:
        return dict(_usage)


def record_usage(prompt_tokens: int, output_tokens: int) -> None:
    with _usage_lock:
        _usage["calls"] += 1
        _usage["prompt_tokens"] += prompt_tokens
        _usage["output_tokens"] += output_tokens


@dataclass
class LLMResponse:
    text: str
    model: str
    prompt_tokens: int
    output_tokens: int
    duration_s: float

    @property
    def tokens_per_s(self) -> float:
        return self.output_tokens / self.duration_s if self.duration_s > 0 else 0.0


def strip_fences(text: str) -> str:
    """Removes <think> blocks and a single wrapping ``` fence, if present."""
    text = _THINK_RE.sub("", text).strip()
    m = _FENCE_RE.match(text)
    return m.group(1).strip() if m else text


def parse_json_response(text: str) -> dict:
    """json.loads with fence stripping and a last-resort {...} extraction."""
    cleaned = strip_fences(text)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        start, end = cleaned.find("{"), cleaned.rfind("}")
        if start != -1 and end > start:
            return json.loads(cleaned[start : end + 1])
        raise


def strict_schema(model_cls) -> dict:
    """
    JSON schema for structured output with EVERY property required.
    Pydantic omits defaulted fields from "required", and Ollama's grammar
    then lets the model skip them — e.g. triage silently dropped "iocs".
    """
    schema = model_cls.model_json_schema()

    def _require_all(node: dict) -> None:
        if isinstance(node.get("properties"), dict):
            node["required"] = list(node["properties"].keys())
        for sub in (node.get("$defs") or {}).values():
            _require_all(sub)

    _require_all(schema)
    return schema


@lru_cache(maxsize=16)
def _model_capabilities(model: str) -> frozenset[str]:
    try:
        resp = httpx.post(f"{OLLAMA_BASE_URL}/api/show", json={"model": model}, timeout=10.0)
        if resp.status_code == 200:
            return frozenset(resp.json().get("capabilities") or [])
    except httpx.HTTPError:
        pass
    return frozenset()


def call_reasoning_model_ex(
    system_prompt: str,
    user_prompt: str,
    model: str,
    num_ctx: int,
    temperature: float,
    schema: dict | None = None,
    timeout_s: float = 180.0,
    max_tokens: int | None = None,
) -> LLMResponse:
    """Calls the local Ollama reasoning model and returns text + token stats."""
    if num_ctx > NUM_CTX_HARD_CAP:
        # Hard architectural invariant — never let a caller silently widen
        # the context window past the VRAM-safe ceiling.
        raise ValueError(f"num_ctx={num_ctx} exceeds the hard cap of {NUM_CTX_HARD_CAP}")

    payload: dict = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "stream": False,
        "options": {"num_ctx": num_ctx, "temperature": temperature},
    }
    if max_tokens:
        payload["options"]["num_predict"] = max_tokens
    if schema is not None:
        payload["format"] = schema
    if "thinking" in _model_capabilities(model):
        # Qwen3-style hybrid models: skip the reasoning trace for these
        # short, schema-constrained calls (faster, and keeps output clean).
        payload["think"] = False

    started = time.perf_counter()
    try:
        with httpx.Client(timeout=timeout_s) as client:
            resp = client.post(f"{OLLAMA_BASE_URL}/api/chat", json=payload)
    except httpx.ConnectError as e:
        raise LLMUnavailableError(
            f"Ollama is not reachable at {OLLAMA_BASE_URL}. Start it with `ollama serve`."
        ) from e
    if resp.status_code == 404:
        raise LLMUnavailableError(f"Model '{model}' is not pulled. Run `ollama pull {model}`.")
    resp.raise_for_status()
    data = resp.json()
    elapsed = time.perf_counter() - started

    eval_ns = data.get("eval_duration") or 0
    return LLMResponse(
        text=data["message"]["content"],
        model=model,
        prompt_tokens=data.get("prompt_eval_count") or 0,
        output_tokens=data.get("eval_count") or 0,
        duration_s=(eval_ns / 1e9) if eval_ns else elapsed,
    )


def call_reasoning_model(
    system_prompt: str,
    user_prompt: str,
    model: str,
    num_ctx: int,
    temperature: float,
    schema: dict | None = None,
    timeout_s: float = 180.0,
    max_tokens: int | None = None,
) -> str:
    """Calls the local Ollama reasoning model. Returns the raw text response."""
    resp = call_reasoning_model_ex(
        system_prompt, user_prompt, model, num_ctx, temperature, schema, timeout_s, max_tokens
    )
    record_usage(resp.prompt_tokens, resp.output_tokens)
    return resp.text


def call_embedding_model(text: str, model: str, timeout_s: float = 30.0) -> list[float]:
    """
    Calls the local Ollama embedding model, explicitly pinned to CPU via
    num_gpu=0. Callers are responsible for nomic task prefixes
    ("search_query: " / "search_document: ") — see rag/chroma_store.py.
    """
    payload = {
        "model": model,
        "prompt": text,
        "options": {"num_gpu": 0},  # 0-byte VRAM cost, runs on CPU threads
    }
    try:
        with httpx.Client(timeout=timeout_s) as client:
            resp = client.post(f"{OLLAMA_BASE_URL}/api/embeddings", json=payload)
    except httpx.ConnectError as e:
        raise LLMUnavailableError(f"Ollama is not reachable at {OLLAMA_BASE_URL}.") from e
    if resp.status_code == 404:
        raise LLMUnavailableError(f"Embedding model '{model}' is not pulled. Run `ollama pull {model}`.")
    resp.raise_for_status()
    return resp.json()["embedding"]


def ollama_status(required_models: list[str]) -> dict:
    """Health probe: is Ollama up, which required models are pulled / loaded."""
    try:
        tags = httpx.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=3.0).json().get("models", [])
        ps = httpx.get(f"{OLLAMA_BASE_URL}/api/ps", timeout=3.0).json().get("models", [])
    except (httpx.HTTPError, ValueError):
        return {"online": False, "pulled": [], "missing": required_models, "loaded": []}

    def _norm(n: str) -> str:
        return n if ":" in n else f"{n}:latest"

    pulled = {_norm(m["name"]) for m in tags}
    return {
        "online": True,
        "pulled": sorted(pulled),
        "missing": [m for m in required_models if _norm(m) not in pulled],
        "loaded": [
            {"name": m["name"], "vram_bytes": m.get("size_vram", 0)} for m in ps
        ],
    }
