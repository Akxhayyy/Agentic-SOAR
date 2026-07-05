# Agentic SOAR Capsule

> **AI-Powered Security Orchestration, Automation & Response — fully local, air-gapped, zero cloud dependencies.**

A production-grade SOAR platform that uses a 4-agent LangGraph pipeline with local LLM inference (Ollama), RAG-based forensics (ChromaDB), and a Human-in-the-Loop approval gate — all running on a single laptop with ≤6GB VRAM.

---

## Table of Contents

- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the System](#running-the-system)
- [Usage Guide](#usage-guide)
- [Project Structure](#project-structure)
- [Testing & Verification](#testing--verification)
- [Troubleshooting](#troubleshooting)

---

## Architecture

```
                    ┌──────────────────────────────────────────────────────────┐
                    │                   FastAPI Backend                        │
                    │   POST /ingest ─► POST /ingest_file ─► POST /resume     │
                    └────────────────────────┬─────────────────────────────────┘
                                             │
                    ┌────────────────────────▼─────────────────────────────────┐
                    │              LangGraph StateGraph Pipeline                │
                    │                                                          │
                    │  ┌─────────┐   ┌───────────┐   ┌──────────────┐          │
                    │  │ Triage  │──►│ Forensics │──►│ Neutralizer  │          │
                    │  │ Agent   │   │ Agent(RAG)│   │   Agent      │          │
                    │  └─────────┘   └─────┬─────┘   └──────┬───────┘          │
                    │                      │                 │                  │
                    │              ┌───────▼───┐    ┌───────▼────────┐          │
                    │              │ Escalation│    │   HITL Gate    │          │
                    │              │  Report   │    │ (300s timeout) │          │
                    │              └───────────┘    └───────┬────────┘          │
                    │                                       │                  │
                    │                              ┌────────▼────────┐         │
                    │                              │Execution Wrapper│         │
                    │                              │ (hash-verified) │         │
                    │                              └────────┬────────┘         │
                    │                                       │                  │
                    │                              ┌────────▼────────┐         │
                    │                              │ Report Generator│         │
                    │                              └─────────────────┘         │
                    └──────────────────────────────────────────────────────────┘
                                             │
                    ┌────────────────────────▼─────────────────────────────────┐
                    │           Streamlit SOC Command Center Dashboard          │
                    └──────────────────────────────────────────────────────────┘
```

**Agent Pipeline Flow:**
1. **Triage Agent** — Classifies attack vector, extracts IOCs from raw logs via Qwen LLM
2. **Forensics Agent** — 2-pass RAG lookup against playbook corpus (ChromaDB + Qwen re-ranking)
3. **Neutralizer Agent** — Plans containment action with SHA-256 tamper-detection hash
4. **HITL Gate** — Pauses for operator approval (300s timeout → auto-escalation)
5. **Execution Wrapper** — Hash-verified, charset-checked, allow-list-dispatched action execution
6. **Responder** — Compresses UICR state and generates Markdown audit report

---

## Prerequisites

### Hardware Requirements

| Component | Minimum | Recommended |
|---|---|---|
| **RAM** | 8 GB | 16 GB |
| **GPU VRAM** | 4 GB (for Q4_K_M quantized model) | 6 GB |
| **Disk** | 10 GB free | 20 GB free |
| **CPU** | Any modern x86-64 | 4+ cores |

> **No GPU?** The system works on CPU-only machines — Ollama will fall back to CPU inference automatically. It will be slower but fully functional.

### Software Requirements

| Software | Version | Purpose |
|---|---|---|
| **Python** | 3.10+ | Runtime |
| **Ollama** | Latest | Local LLM inference server |
| **Git** | Any | Version control |

---

## Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/Akxhayyy/Agentic-SOAR.git
cd Agentic-SOAR
```

### Step 2: Install Ollama

**Windows:**
1. Download from [ollama.com/download](https://ollama.com/download)
2. Run the installer
3. Verify: open a terminal and run `ollama --version`

**macOS:**
```bash
brew install ollama
```

**Linux:**
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

### Step 3: Pull the Required Models

```bash
# Reasoning model (~4.4GB download, runs on GPU)
ollama pull qwen2.5:7b-instruct-q4_K_M

# Embedding model (~274MB download, runs on CPU — zero GPU cost)
ollama pull nomic-embed-text
```

> **Low-spec machine?** Use the smaller 3B model instead:
> ```bash
> ollama pull qwen2.5:3b-instruct
> ```
> Then update `config/hitl_config.yaml` → `models.reasoning.model` to `"qwen2.5:3b-instruct"`.

### Step 4: Create a Python Virtual Environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 5: Install Python Dependencies

```bash
pip install -r requirements.txt
```

### Step 6: Ingest Playbooks into ChromaDB

This embeds the 7 response playbooks into the local vector store for RAG forensics:

```bash
python -m rag.ingest_playbooks
```

Expected output:
```
Ingested 2 chunks from brute_force_auth.md
Ingested 3 chunks from data_exfiltration.md
Ingested 3 chunks from malware_execution.md
Ingested 3 chunks from network_intrusion.md
Ingested 3 chunks from privilege_escalation.md
Ingested 3 chunks from proxy_anomaly.md
Ingested 3 chunks from unknown_threat.md
Done. 20 total chunks across 7 playbooks in collection (count=20).
```

> **Re-run this** any time you add or edit playbook `.md` files in `config/playbooks/`.

---

## Configuration

All runtime configuration lives in a single file: **`config/hitl_config.yaml`**

### Key Settings

```yaml
execution:
  dry_run: true          # true = stubbed API (safe demo), false = real OS commands
  exec_result_dir: "./data/exec_results"

hitl:
  timeout_seconds: 300   # Operator has 5 min to APPROVE/REJECT before auto-escalation
  checkpointer_db_path: "./data/vectorstore/graph_state.db"

forensics:
  similarity_hard_threshold: 0.70   # THE escalation decision threshold
  pass_1:
    window_seconds: 30
    top_k: 5
  pass_2:
    window_seconds: 300
    top_k: 8
    similarity_floor: 0.35          # Recall-widening only, NOT a decision threshold

models:
  reasoning:
    model: "qwen2.5:7b-instruct-q4_K_M"   # Change to 3b for low-spec machines
    num_ctx: 4096                          # Hard VRAM ceiling — do NOT increase
    temperature: 0.0                       # Zero-temp for deterministic output
  embedding:
    model: "nomic-embed-text"
    device: "cpu"                          # Pinned off-GPU to preserve VRAM
```

### Critical Configuration Notes

> **`execution.dry_run`**: When `true` (default for safety), all containment actions are simulated via `execution/stub_infra_api.py`. When `false`, real OS commands execute (`taskkill`, `netsh firewall rules`). **Only set to `false` if you understand the consequences.**

> **`models.reasoning.num_ctx`**: Hard-capped at 4096. Do **not** increase — the VRAM ceiling is enforced at the code level and will raise a `ValueError` if exceeded.

> **`forensics.similarity_hard_threshold`**: This is the **only** value that decides whether an incident routes to the Neutralizer (≥0.70) or straight to escalation (<0.70). The 0.35 floor in pass 2 only widens retrieval recall.

---

## Running the System

You need **three terminal windows** (or use the batch script):

### Option A: Manual Start (3 Terminals)

**Terminal 1 — Ollama Server** (if not already running as a service):
```bash
ollama serve
```

**Terminal 2 — FastAPI Backend:**
```bash
# Activate venv first
uvicorn main:app --reload --port 8000
```

**Terminal 3 — Streamlit Dashboard:**
```bash
# Activate venv first
streamlit run dashboard/app.py
```

### Option B: One-Click Batch Script (Windows)

```bash
run_soar.bat
```

This starts Ollama, the FastAPI backend, and the Streamlit dashboard in sequence.

### Verify Services Are Running

| Service | URL | Expected |
|---|---|---|
| FastAPI Backend | http://127.0.0.1:8000/docs | Swagger UI |
| Ollama | http://127.0.0.1:11434 | `Ollama is running` |
| Streamlit Dashboard | http://localhost:8501 | SOC Command Center |

---

## Usage Guide

### Method 1: Upload Log Files via Dashboard

1. Open the Streamlit dashboard at `http://localhost:8501`
2. Go to **SOC Overview** → **LOG INGESTION WORKSPACE**
3. Drag and drop a log file (`.txt`, `.csv`, `.json`, or `.log`)
4. Select the appropriate delimiter (auto-detected for CSV/JSON)
5. Click **SUBMIT TO CORE AUTOMATION GRAPH**
6. Watch incidents appear in the **BATCH INCIDENT CASE RUNS** section
7. Click any incident to view it in **Case Investigation**

### Method 2: API — Single Log Ingestion

```bash
curl -X POST http://127.0.0.1:8000/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "source": "auth-gateway-01",
    "log_type": "AUTH",
    "raw_text": "Failed login for user admin from 10.0.4.17 x14 in 45s, followed by successful login"
  }'
```

### Method 3: API — Batch File Ingestion

```bash
curl -X POST http://127.0.0.1:8000/ingest_file \
  -H "Content-Type: application/json" \
  -d '{
    "file_text": "timestamp,ip,username,message\n2026-01-01T00:00:01Z,192.168.1.100,admin,failed login\n2026-01-01T00:00:05Z,192.168.1.100,admin,failed login\n2026-01-01T00:00:10Z,192.168.1.100,admin,successful login",
    "default_log_type": "AUTH"
  }'
```

### Operator Decision (HITL Gate)

When an incident reaches the HITL gate:
- **Dashboard**: Click **APPROVE** or **REJECT** in the Case Investigation panel
- **API**: `POST /resume/{incident_id}` with `{"decision": "APPROVED"}` or `{"decision": "REJECTED"}`
- **Timeout**: If no decision in 300s, the system auto-escalates with `TIMEOUT`

### Sample Test Files

Pre-built test files are included in `data/samples/`:

| File | Format | Scenario |
|---|---|---|
| `syslog_brute_force.txt` | Syslog | 5 failed + 1 success login |
| `brute_force_success.csv` | CSV | Brute force with timestamps |
| `e2e_verify.csv` | CSV | End-to-end verification data |
| `network_scan.json` | JSON-Lines | nmap scan + unauthorized access |
| `demo_attack.txt` | Raw text | Malware execution alert |

---

## Project Structure

```
soar_capsule/
├── main.py                          # FastAPI backend (ingest, resume, timeout)
├── requirements.txt                 # Python dependencies
├── config/
│   ├── hitl_config.yaml             # Single source of truth for all config
│   └── playbooks/                   # RAG corpus (7 playbook .md files)
│       ├── brute_force_auth.md
│       ├── data_exfiltration.md
│       ├── malware_execution.md
│       ├── network_intrusion.md
│       ├── privilege_escalation.md
│       ├── proxy_anomaly.md
│       └── unknown_threat.md
├── core/
│   ├── uicr_schema.py               # Pydantic models, enums, UICR state
│   ├── graph.py                     # LangGraph pipeline wiring & edges
│   ├── graph_config.py              # Config loader
│   └── checkpointer.py             # SQLite persistence for graph state
├── agents/
│   ├── llm_client.py                # Ollama API wrapper (GPU/CPU routing)
│   ├── triage.py                    # Triage Agent — attack classification
│   ├── forensics.py                 # Forensics Agent — 2-pass RAG
│   ├── neutralizer.py               # Neutralizer Agent — action planning
│   └── responder.py                 # UICR compression + report generation
├── execution/
│   ├── wrapper.py                   # Hash-verified execution gate
│   ├── stub_infra_api.py            # Simulated infra (dry_run=true)
│   └── real_infra_api.py            # Real OS commands (dry_run=false)
├── ingestion/
│   ├── cheap_filter.py              # Zero-LLM pre-screening (regex/keyword)
│   ├── grouping.py                  # IP/user burst grouping
│   └── batch_processor.py           # Orchestrates filter→group→graph
├── rag/
│   ├── chroma_store.py              # ChromaDB vector store wrapper
│   └── ingest_playbooks.py          # Playbook embedding pipeline
├── dashboard/
│   └── app.py                       # Streamlit SOC Command Center
├── data/
│   ├── samples/                     # Test log files
│   └── reports/                     # Generated incident reports (auto-created)
├── comprehensive_audit.py           # Full codebase verification (135 tests)
├── run_soar.bat                     # Windows one-click launcher
├── run_capsule.bat                  # Alternative launcher
└── VSSC_DEMO_GUIDE.md              # Live demo presentation guide
```

### Key Files (Read Order)

1. **`core/uicr_schema.py`** — Every validation gate in the system
2. **`agents/neutralizer.py`** + **`execution/wrapper.py`** — The hash-verification tamper-detection contract
3. **`core/graph.py`** — The two conditional edge functions that branch the pipeline
4. **`config/hitl_config.yaml`** — Runtime behavior configuration

---

## Testing & Verification

### Run the Full Audit Suite (No Ollama Required)

```bash
python comprehensive_audit.py
```

This runs **135 automated checks** across 10 categories:

| Category | Tests | What It Checks |
|---|---|---|
| Schema & Enum Validation | 19 | Pydantic models, enum cardinality, charset enforcement |
| Ingestion Pipeline | 19 | CSV/JSON/syslog parsing, filtering, grouping, timestamp extraction |
| Execution Wrapper | 30 | Hash verification, API signature matching, rollback tracking |
| Responder | 12 | UICR compression, escalation path detection |
| Graph Wiring | 8 | Conditional edge routing for all decision paths |
| Config Loading | 17 | YAML parsing, required sections, threshold values |
| Playbook Files | 8 | All 7 playbooks present and non-empty |
| LLM Client Contracts | 2 | Localhost URL, VRAM guard |
| Adversarial Edge Cases | 7 | SQL injection, Unicode, path traversal, overlength inputs |
| Cross-Module Imports | 4 | All inter-module dependencies resolve correctly |

### Quick Smoke Test

```bash
python verify_expansion.py
```

---

## Troubleshooting

### Ollama Not Responding

```bash
# Check if Ollama is running
curl http://127.0.0.1:11434

# Start it manually
ollama serve

# Verify models are pulled
ollama list
```

### FastAPI Backend Won't Start

```bash
# Check if port 8000 is in use
netstat -ano | findstr :8000     # Windows
lsof -i :8000                    # Linux/macOS

# Start with verbose logging
uvicorn main:app --reload --port 8000 --log-level debug
```

### ChromaDB Empty (Forensics Returns No Matches)

```bash
# Re-ingest playbooks
python -m rag.ingest_playbooks

# Verify the vector store exists
ls data/vectorstore/     # should contain chroma.sqlite3
```

### VRAM Out of Memory

- Use the smaller 3B model: edit `config/hitl_config.yaml` → `models.reasoning.model: "qwen2.5:3b-instruct"`
- Ensure `num_ctx` stays at 4096 (the code enforces this)
- Close other GPU-heavy applications

### Dashboard Shows "Backend Unreachable"

The FastAPI backend must be running at `http://127.0.0.1:8000` before the dashboard can communicate. Start the backend first, then the dashboard.

### "Config file missing" Error

Ensure `config/hitl_config.yaml` exists. The system refuses to start with implicit defaults — this is by design for a security platform.

---

## License

This project is part of an academic/research demonstration. See the repository for licensing details.
