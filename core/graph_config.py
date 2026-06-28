"""
core/graph_config.py

Tiny shared loader so every module reads config the same way. Fails loudly
on missing/malformed config rather than silently defaulting — a SOAR
platform should never guess at DRY_RUN.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "hitl_config.yaml"


@lru_cache(maxsize=1)
def load_config() -> dict:
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(
            f"Required config file missing at {CONFIG_PATH}. "
            "Refusing to start with implicit defaults for a SOAR platform."
        )
    with open(CONFIG_PATH, "r") as f:
        cfg = yaml.safe_load(f)

    # Fail loudly on missing critical keys rather than KeyError deep in a node.
    required_top_level = ("execution", "hitl", "forensics", "models", "dashboard")
    missing = [k for k in required_top_level if k not in cfg]
    if missing:
        raise ValueError(f"Config missing required top-level sections: {missing}")

    return cfg
