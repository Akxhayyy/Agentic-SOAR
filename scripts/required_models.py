"""
Prints every Ollama model the current config needs, one per line.
Used by run_soar.bat so the installer always pulls exactly what
config/hitl_config.yaml asks for (the launcher used to hardcode a
different model than the config, so fresh installs failed).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.graph_config import load_config  # noqa: E402

models = load_config()["models"]
names = {models["reasoning"]["model"], models["embedding"]["model"]}
names |= {m for m in (models["reasoning"].get("per_agent") or {}).values() if m}
print("\n".join(sorted(names)))
