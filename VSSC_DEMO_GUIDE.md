# 🛡️ SOAR Capsule — VSSC Live Demo Guide

> **Purpose:** Step-by-step instructions for downloading, setting up, and presenting a live attack-neutralization demo at Vikram Sarabhai Space Centre.

---

## 📋 Table of Contents

1. [Before You Leave (Tonight)](#1-before-you-leave-tonight)
2. [At the VSSC System — Setup](#2-at-the-vssc-system--setup)
3. [Verify Everything Works](#3-verify-everything-works)
4. [The Live Attack Demo](#4-the-live-attack-demo--the-climax)
5. [Talking Points for the Panel](#5-talking-points-for-the-panel)
6. [Troubleshooting](#6-troubleshooting)
7. [After the Demo — Cleanup](#7-after-the-demo--cleanup)

---

## 1. Before You Leave (Tonight)

### ✅ Push Your Code to GitHub

Your code is already pushed to your GitHub repository. Confirm by visiting your repo page in a browser and checking that these files exist:

| File | Purpose |
|------|---------|
| `run_soar.bat` | One-click installer + launcher |
| `execution/real_infra_api.py` | Real OS-level action adapter |
| `execution/wrapper.py` | Updated to support live execution |
| `data/samples/demo_attack.txt` | Pre-crafted attack log template |
| `VSSC_DEMO_GUIDE.md` | This file |

### ✅ Know Your Config Toggle

Your system has ONE switch that controls dry-run vs. live execution:

**File:** `config/hitl_config.yaml`, **Line 12:**

```yaml
execution:
  dry_run: true    # ← Change to false for the live kill demo
```

- `true` = All actions are simulated (safe for testing)
- `false` = `TERMINATE_PROCESS` will actually kill the target PID

> ⚠️ **IMPORTANT:** Leave it as `true` during setup and testing. Only flip to `false` right before the live demo in front of the panel.

---

## 2. At the VSSC System — Setup

### Step 1: Install Ollama (2 minutes)

1. Open the web browser on the VSSC system
2. Go to **https://ollama.com**
3. Click **Download for Windows**
4. Run the installer — it's a simple next-next-finish wizard
5. After install, open a **Command Prompt** and type `ollama --version` to confirm it's working

### Step 2: Download Your Project (1 minute)

1. Go to your GitHub repository page in the browser
2. Click the green **Code** button → **Download ZIP**
3. Extract the ZIP to the **Desktop** (e.g., `C:\Users\<name>\Desktop\soar_capsule`)

### Step 3: Run the One-Click Installer (10-15 minutes)

1. Open the extracted `soar_capsule` folder
2. **Double-click `run_soar.bat`**
3. The script will automatically:
   - ✅ Create a Python virtual environment
   - ✅ Install all pip dependencies
   - ✅ Download `nomic-embed-text` embedding model (~274 MB)
   - ✅ Download `qwen2.5:3b-instruct` reasoning model (~1.9 GB)
   - ✅ Index all 8 threat playbooks into ChromaDB
   - ✅ Launch the FastAPI backend (port 8000)
   - ✅ Launch the Streamlit SOC Dashboard (port 8501)

4. Two new terminal windows will appear. **Don't close them.** They are the running backend and dashboard processes.

### Step 4: Open the Dashboard

1. Open the browser
2. Go to **http://localhost:8501**
3. You should see the dark-themed **SOC Command Station** dashboard with:
   - KPI cards showing 0 incidents (fresh install)
   - Trend charts
   - The **LOG INGESTION WORKSPACE** with a file upload area

---

## 3. Verify Everything Works

### Quick Smoke Test (Dry Run Mode)

Before touching the config, do a quick dry-run test to make sure the full pipeline works:

1. On the SOC Dashboard, drag and drop any sample file from `data/samples/` (e.g., `demo_attack.txt` with any placeholder PID) into the **DRAG & DROP RAW TELEMETRY FILE** area
2. Click **🚀 SUBMIT TO CORE AUTOMATION GRAPH**
3. Wait 30-60 seconds for the AI to process
4. You should see a batch incident appear with:
   - Attack vector: `MALWARE_EXECUTION`
   - Action plan: `TERMINATE_PROCESS`
   - Pipeline paused at `AWAITING_HITL`
5. Click into the incident → Click **✅ APPROVE**
6. The execution result should show `"dry_run": true, "simulated": true`

✅ If this works, your entire pipeline is healthy. Move to the live demo.

---

## 4. The Live Attack Demo — The Climax

> **Perform these steps in front of the panel, narrating each one.**

### 4.1 Prepare the Stage

1. **Open Notepad** — Click Start → type `Notepad` → open it. Leave the blank Notepad window visible on screen.

2. **Find Notepad's PID** — Right-click the taskbar → **Task Manager** → go to the **Details** tab → find `notepad.exe` → note the **PID** number (e.g., `8432`).

   > 💡 **Pro tip:** You can also open Command Prompt and run:
   > ```
   > tasklist | findstr notepad
   > ```
   > This will show something like: `notepad.exe    8432    Console    1    12,288 K`

3. **Prepare the Attack Log** — Open `data\samples\demo_attack.txt` in a text editor. Replace `REPLACE_WITH_ACTUAL_PID` with the real PID number you just found:

   ```
   ALERT: Malware execution confirmed. Rogue process PID:8432 spawning encoded reverse shell via powershell -enc on workstation WS-DEMO-01
   ```

   Save the file.

4. **Enable Live Execution** — Open `config\hitl_config.yaml` in a text editor. Change line 12:

   ```yaml
   execution:
     dry_run: false
   ```

   Save the file. **No restart needed** — the config is read fresh on every request.

### 4.2 Arrange Your Screen

Position your windows so the panel can see EVERYTHING simultaneously:

```
┌─────────────────────────────────────────────┐
│                                             │
│   ┌──────────────┐  ┌────────────────────┐  │
│   │              │  │                    │  │
│   │   NOTEPAD    │  │   SOC DASHBOARD    │  │
│   │   (target)   │  │   (browser)        │  │
│   │              │  │                    │  │
│   └──────────────┘  └────────────────────┘  │
│                                             │
└─────────────────────────────────────────────┘
```

### 4.3 The Presentation Flow

**🎤 Say to the panel:**

> *"I'm going to demonstrate a real-time attack detection and neutralization pipeline. The Notepad window you see represents a rogue process — malware that has been detected running on this machine. I have its actual Process ID from Task Manager. Let me show you how our multi-agent AI system handles this threat."*

**Step-by-step:**

1. **Upload the attack log:**
   - On the SOC Dashboard, drag `demo_attack.txt` into the upload area
   - Click **🚀 SUBMIT TO CORE AUTOMATION GRAPH**

2. **Narrate while the AI processes (30-60 seconds):**
   > *"Right now, our first-stage deterministic filter has detected the keywords 'powershell -enc' — a known obfuscation technique. The log has been forwarded to our Triage Agent, which is a locally-running Qwen 2.5 3-billion parameter model. It's classifying the attack vector and extracting Indicators of Compromise..."*

3. **Click into the incident** when it appears in the batch results

4. **Show the panel the Case Investigation page:**
   - **Left column:** The raw log stream and extracted IOCs
   - **Center column:** The Live Topology Node Tracker showing each pipeline stage lighting up
   - **Right column:** The Action Plan showing `TERMINATE_PROCESS` targeting the Notepad PID

   > *"Our Neutralizer Agent has formulated a containment plan: terminate process [PID]. This plan has been cryptographically signed with SHA-256. The system is now waiting for human-in-the-loop approval before taking any action."*

5. **Show the countdown timer** ticking in the right column:
   > *"If I don't respond within 300 seconds, the system automatically escalates to a security team. No threat ever goes unaddressed."*

6. **THE CLIMAX — Click ✅ APPROVE:**
   > *"Watch the Notepad window."*

   **→ The Notepad window will instantly vanish from the desktop.**

7. **Show the execution result** in the dashboard:
   > *"The execution result confirms: simulated=false, status=TERMINATED. This was a real operating system command — our system identified the threat, planned the response, verified the plan's cryptographic integrity, waited for human authorization, and then neutralized the process. All running locally, with no cloud dependencies, no API keys, and no internet required after initial setup."*

### 4.4 After the Kill — Show the Audit Trail

1. Navigate to **Reporting Hub** in the sidebar
2. Show the auto-generated incident audit report
3. Navigate to **Playbook Viewer** to show the defensive playbooks the system consulted
4. Navigate to **Configuration Manager** to show the single-source-of-truth YAML config

---

## 5. Talking Points for the Panel

Use these when answering questions:

### "Why is it air-gapped / local-first?"
> *"In a defense/space context, security infrastructure cannot depend on external cloud APIs. Our entire system — the AI reasoning model, the vector database, the execution engine — runs on localhost. After initial setup, you can disconnect the internet cable and it still works."*

### "What prevents the AI from executing arbitrary commands?"
> *"Four independent safety layers: (1) SHA-256 hash verification ensures the plan wasn't tampered with between planning and execution, (2) a charset regex allow-list blocks shell metacharacters, (3) a static allow-list dispatch prevents dynamic code execution, and (4) human-in-the-loop approval gate with a 300-second timeout. All four must pass before any action fires."*

### "What attacks can it detect?"
> *"Seven attack vectors: Brute Force Authentication, Network Intrusion, Malware Execution, Data Exfiltration, Privilege Escalation, Proxy Anomaly, and Unknown Threats. Each has a corresponding defensive playbook stored in our RAG knowledge base."*

### "How does the RAG forensics work?"
> *"After triage, the system embeds the incident context and searches our ChromaDB vector store for matching playbook chunks. It runs a two-pass retrieval — narrow window first, then wider context — with a hard similarity threshold of 0.70. Only incidents that clear this threshold proceed to the neutralization pipeline."*

### "What's the model and why this specific one?"
> *"Qwen 2.5 3B Instruct. This lightweight model fits in under 2GB VRAM, making it runnable even on systems without a dedicated GPU. The context window is hard-capped at 4,096 tokens to prevent memory overflow. The embedding model (nomic-embed-text) is explicitly pinned to CPU to avoid GPU contention. For production deployments with more capable hardware, we can scale up to the 7B or 14B variants without any code changes — it's a single config line swap."*

---

## 6. Troubleshooting

### Problem: "Backend unreachable" error on dashboard
**Fix:** The backend hasn't started yet. Check the "SOAR Backend" terminal window for errors. Common cause: port 8000 is already in use. Kill the other process or change the port.

### Problem: AI response is garbage / JSON parse errors
**Fix:** The wrong model may be loaded. Run `ollama list` in Command Prompt and verify `qwen2.5:3b-instruct` appears. If you see `qwen2.5:1.5b-instruct` instead, run:
```
ollama pull qwen2.5:3b-instruct
```

### Problem: Notepad doesn't close when I click Approve
**Possible causes:**
1. `dry_run` is still `true` — check `config/hitl_config.yaml`
2. The LLM extracted the wrong target (not the PID). Check the Action Plan JSON in the dashboard right column. The `target` field should be the PID number.
3. Notepad was closed/reopened and has a new PID. Re-check Task Manager.

### Problem: "Playbook ingestion failed"
**Fix:** Ollama must be running and `nomic-embed-text` must be pulled. Run:
```
ollama pull nomic-embed-text
python -m rag.ingest_playbooks
```

### Problem: Script says "Python not found"
**Fix:** Python 3.10+ must be installed AND added to PATH. During Python installation, check the "Add Python to PATH" checkbox.

### Problem: Very slow AI responses (>2 minutes)
**Cause:** No GPU available — the model is running on CPU. This is fine, just slower. Wait patiently. The 3B model takes ~30-60 seconds per call on CPU.

---

## 7. After the Demo — Cleanup

1. **Reset dry_run** — Open `config/hitl_config.yaml` and set `dry_run: true` again
2. **Close the terminal windows** — The "SOAR Backend" and "SOAR Dashboard" windows
3. **Optional:** Delete the extracted folder if on a shared system

---

## Quick Reference Card

| Item | Value |
|------|-------|
| Dashboard URL | http://localhost:8501 |
| Backend API | http://127.0.0.1:8000 |
| Config file | `config/hitl_config.yaml` |
| Demo attack file | `data/samples/demo_attack.txt` |
| Live kill toggle | `execution.dry_run: false` |
| Reasoning model | `qwen2.5:3b-instruct` |
| Embedding model | `nomic-embed-text` |
| HITL timeout | 300 seconds |
| RAG threshold | 0.70 similarity |

---

*Generated for the SOAR Capsule project. All systems run locally — no cloud, no API keys, fully air-gapped after setup.*
