"""
core/graph_config.py

Tiny shared loader so every module reads config the same way. Fails loudly
on missing/malformed config rather than silently defaulting — a SOAR
platform should never guess at DRY_RUN.

Every relative path in the config is resolved against the PROJECT ROOT, not
the process CWD. Previously the backend, the dashboard and the ingest script
could each open a different SQLite DB / reports folder depending on which
directory they were launched from.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_ROOT / "config" / "hitl_config.yaml"

# (section, key) pairs holding filesystem paths that must be root-anchored.
_PATH_KEYS = (
    ("execution", "exec_result_dir"),
    ("execution", "report_dir"),
    ("hitl", "checkpointer_db_path"),
    ("forensics", "chroma_persist_dir"),
    ("forensics", "playbook_dir"),
    ("forensics", "log_store_path"),
    ("forensics", "threat_intel_path"),
    ("logging", "audit_log_path"),
)


def _resolve(p: str) -> str:
    path = Path(p)
    if not path.is_absolute():
        path = (PROJECT_ROOT / path).resolve()
    return str(path)


@lru_cache(maxsize=1)
def load_config() -> dict:
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(
            f"Required config file missing at {CONFIG_PATH}. "
            "Refusing to start with implicit defaults for a SOAR platform."
        )
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    # Fail loudly on missing critical keys rather than KeyError deep in a node.
    required_top_level = ("execution", "hitl", "forensics", "models")
    missing = [k for k in required_top_level if k not in cfg]
    if missing:
        raise ValueError(f"Config missing required top-level sections: {missing}")

    cfg["execution"].setdefault("report_dir", "./data/reports")
    cfg["execution"].setdefault("protected_targets", [])
    cfg["forensics"].setdefault("log_store_path", "./data/logstore.db")
    cfg["forensics"].setdefault("threat_intel_path", "./data/threat_intel/blocklist.csv")
    agent = cfg["forensics"].setdefault("agent", {})
    agent.setdefault("enabled", False)
    agent.setdefault("max_tool_calls", 5)
    agent.setdefault("min_tool_calls", 1)
    agent.setdefault("related_logs_default_window_s", 300)
    sec = cfg.setdefault("security", {})
    for flag in ("grounding", "deny_list", "hash_check"):
        sec.setdefault(flag, True)
    cfg.setdefault("logging", {}).setdefault("audit_log_path", "./data/audit.log")

    for section, key in _PATH_KEYS:
        if key in cfg.get(section, {}):
            cfg[section][key] = _resolve(cfg[section][key])

    # Env override so a different local model can be tried without editing YAML.
    env_model = os.environ.get("SOAR_REASONING_MODEL")
    if env_model:
        cfg["models"]["reasoning"]["model"] = env_model

    return cfg


def reasoning_model_for(agent: str) -> dict:
    """
    Returns the effective reasoning-model settings for one agent:
    {"model", "num_ctx", "temperature"}. `models.reasoning.per_agent.<agent>`
    may override the model name; everything else is shared.
    """
    base = load_config()["models"]["reasoning"]
    per_agent = base.get("per_agent") or {}
    return {
        "model": per_agent.get(agent) or base["model"],
        "num_ctx": base["num_ctx"],
        "temperature": base["temperature"],
    }
