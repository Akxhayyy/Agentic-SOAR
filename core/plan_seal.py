"""
core/plan_seal.py

Keyed integrity seal for containment plans: HMAC-SHA256 over the canonical
JSON of everything the operator approves.

Why an HMAC and not a plain hash (the original design):
  A plain SHA-256 of the plan catches accidental or naive mutation, but
  anyone who can write to the incident state can also recompute a plain
  hash after changing the target — there is no secret involved. With an
  HMAC, producing a valid seal requires the signing key, which lives
  outside the checkpoint database (data/secrets/plan_signing.key or the
  SOAR_PLAN_KEY environment variable). Write access to incident state is
  no longer enough to forge an executable plan.

What is sealed (canonical JSON, sorted keys, no whitespace):
  incident_id    binds the plan to ONE incident — a sealed plan copied into
                 another incident's state fails verification (no replay)
  action_type, target, params
                 what will actually execute
  justification  what the operator READ when approving — altering the text
                 shown at the HITL gate also breaks the seal

What it does NOT protect against (see THREAT_MODEL.md):
  - a bad plan produced honestly by the model (grounding + HITL handle that)
  - an attacker who can read the key file or modify this code (host compromise)

Both the Neutralizer (seal) and the execution wrapper (verify) call into
this module; the wrapper recomputes the seal from the fields it is about
to act on and compares in constant time.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
from pathlib import Path

from core.graph_config import load_config

logger = logging.getLogger("soar.plan_seal")

_lock = threading.Lock()
_cached: tuple[str, bytes] | None = None  # (source, key)


def canonical_plan(incident_id: str, action_type: str, target: str, params: dict, justification: str) -> str:
    """The exact byte string that gets sealed. Order- and whitespace-independent."""
    return json.dumps(
        {
            "incident_id": incident_id,
            "action_type": action_type,
            "target": target,
            "params": {str(k): str(v) for k, v in (params or {}).items()},
            "justification": justification,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _key_path() -> Path:
    return Path(load_config()["security"]["plan_key_path"])


def signing_key() -> bytes:
    """
    Resolution order: SOAR_PLAN_KEY env var (hex) > key file > generate a
    new 256-bit key file on first use. Cached per source so tests that
    point plan_key_path elsewhere get their own key.
    """
    global _cached
    env = os.environ.get("SOAR_PLAN_KEY")
    source = "env" if env else str(_key_path())
    with _lock:
        if _cached and _cached[0] == source:
            return _cached[1]
        if env:
            key = bytes.fromhex(env.strip())
        else:
            path = _key_path()
            if path.exists():
                key = bytes.fromhex(path.read_text(encoding="ascii").strip())
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                key = secrets.token_bytes(32)
                path.write_text(key.hex(), encoding="ascii")
                try:
                    os.chmod(path, 0o600)  # best effort; Windows ignores most mode bits
                except OSError:
                    pass
                logger.info("Generated new plan-signing key at %s", path)
        if len(key) < 32:
            raise ValueError("plan signing key must be at least 256 bits")
        _cached = (source, key)
        return key


def seal(incident_id: str, action_type: str, target: str, params: dict, justification: str) -> str:
    msg = canonical_plan(incident_id, action_type, target, params, justification).encode("utf-8")
    return hmac.new(signing_key(), msg, hashlib.sha256).hexdigest()


def verify(seal_hex: str, incident_id: str, action_type: str, target: str, params: dict, justification: str) -> bool:
    expected = seal(incident_id, action_type, target, params, justification)
    return hmac.compare_digest(expected, str(seal_hex))
