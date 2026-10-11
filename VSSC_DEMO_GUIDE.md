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
   - ✅ Download every model listed in `config/hitl_config.yaml` (default `qwen3:8b`, ~5.2 GB)
   - ✅ Index all 7 threat playbooks into ChromaDB
   - ✅ Build the web console (first run only; needs Node.js 18+)
   - ✅ Launch the backend + console on port 8000 and open your browser

4. One new terminal window ("SOAR Capsule") will appear. **Don't close it.** It is the running backend.

### Step 4: Open the Console

1. The browser opens automatically. If not, go to **http://127.0.0.1:8000**
2. You should see the **Incidents** page with:
   - Green health pills in the top bar (Backend, Ollama, Model, RAG, Live) and a **DRY-RUN** badge
   - KPI cards showing 0 incidents (fresh install)
   - An **Ingest logs** button

---

## 3. Verify Everything Works

### Quick Smoke Test (Dry Run Mode)

Before touching the config, do a quick dry-run test to make sure the full pipeline works:

1. Open **Ingest**, pick `demo_attack.txt` from **Or load a bundled sample** (or drag the file in)
2. Check the **Pre-screen preview**: 1 line flagged, 1 incident will be created. Click **Send 1 incident to the agents**
3. Wait about a minute: the progress panel shows the agents working
4. Open the incident from the progress panel. The **Agent timeline** shows:
   - Triage: `Malware execution`, IOCs including the PID
   - Forensics agent: its tool calls and the similarity score against the 0.70 threshold
   - Containment plan: `Terminate process <PID>`, grounding ✓, SHA-256
5. In the **Your decision is needed** panel, click **Approve**
6. The Outcome panel shows **Contained** and the execution step says `dry-run`

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
│   │   NOTEPAD    │  │   SOC CONSOLE      │  │
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
   - Open **Ingest** and drag `demo_attack.txt` into the drop area
   - Point at the **Pre-screen preview** (1 flagged line → 1 incident, no AI used yet)
   - Click **Send 1 incident to the agents**, then open the incident from the progress panel

2. **Narrate while the agents work (about a minute; the timeline lights up live):**
   > *"Our first-stage deterministic filter flagged 'powershell -enc', a known obfuscation technique, without any AI. The Triage agent, a locally-running Qwen3 8B, is classifying the attack and extracting indicators. Next, the forensics agent investigates with read-only tools, checking our offline threat-intel feed and related logs, and picks a response playbook..."*

3. **Click into the incident** when it appears in the batch results

4. **Show the panel the incident page:**
   - **Agent timeline:** each agent's real output and real duration, lighting up live as it runs, including the forensics agent's tool calls
   - **Decision panel (right):** the plan, `Terminate process <Notepad PID>`, with the evidence-grounding check ✓
   - **Raw logs (bottom):** the log line with the PID highlighted

   > *"Our Neutralizer Agent has formulated a containment plan: terminate process [PID]. This plan has been cryptographically signed with SHA-256. The system is now waiting for human-in-the-loop approval before taking any action."*

5. **Show the countdown timer** ticking in the right column:
   > *"If I don't respond within 300 seconds, the system automatically escalates to a security team. No threat ever goes unaddressed."*

6. **THE CLIMAX: approve.** In LIVE mode the console asks you to **type the target (the PID) to enable Approve**. This is deliberate friction before a real OS action, so mention it:
   > *"Because this will run a real command, the console makes me type the PID to confirm."*

   Then click **Approve**:
   > *"Watch the Notepad window."*

   **→ The Notepad window will instantly vanish from the desktop.**

7. **Show the outcome** in the incident page (Outcome panel and the Execution step):
   > *"The execution result confirms: simulated=false, status=TERMINATED. This was a real operating system command — our system identified the threat, planned the response, verified the plan's cryptographic integrity, waited for human authorization, and then neutralized the process. All running locally, with no cloud dependencies, no API keys, and no internet required after initial setup."*

### 4.4 After the Kill — Show the Audit Trail

1. Scroll the incident page to **Incident report** (auto-generated; facts are rendered from the record, the narrative by the LLM) and the **Audit trail** (who approved, when, with what note)
2. Open **Playbooks** to show the defensive playbooks and how many incidents matched each
3. Open **Evaluation** to show the benchmark and red-team tables: attack success with a fully hijacked model drops from 78% to 16% with the defences on
4. Open **System** to show the safety controls, the real tokens/s benchmark and the read-only config

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
> *"Qwen3 8B, 4-bit quantised, about 5 GB, which fits an 8 GB laptop GPU with an 8K context window. Every agent's output is grammar-constrained to a JSON schema, so the model can't produce malformed or invented values: the containment target must be one of the indicators actually found in the logs. The embedding model (nomic-embed-text) is pinned to CPU to avoid GPU contention. The model is one config line, and we benchmark alternatives (Gemma 4, Foundation-Sec-8B, Qwen 2.5) with scripts/eval.py."*

---

## 6. Troubleshooting

### Problem: the Backend pill is red / the page doesn't load
**Fix:** The backend hasn't started yet. Check the "SOAR Capsule" terminal window for errors. Common cause: port 8000 is already in use. Kill the other process or change the port.

### Problem: the Model pill is red ("not pulled" banner)
**Fix:** The configured model isn't downloaded. Run `ollama pull qwen3:8b` (or whatever `config/hitl_config.yaml` names), or start the backend with `set SOAR_REASONING_MODEL=<a model you have>`.

### Problem: Notepad doesn't close when I click Approve
**Possible causes:**
1. `dry_run` is still `true` — check `config/hitl_config.yaml`
2. The plan targets the process name instead of the PID. Check the **Containment plan** step: the target should be the PID number. (Terminating by name kills every process with that name, which is why the planner prefers the PID.)
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
2. **Close the terminal window**: the "SOAR Capsule" window
3. **Optional:** Delete the extracted folder if on a shared system

---

## Quick Reference Card

| Item | Value |
|------|-------|
| SOC console | http://127.0.0.1:8000 |
| API docs | http://127.0.0.1:8000/docs |
| Config file | `config/hitl_config.yaml` |
| Demo attack file | `data/samples/demo_attack.txt` |
| Live kill toggle | `execution.dry_run: false` |
| Reasoning model | `qwen3:8b` (override: `SOAR_REASONING_MODEL`) |
| Embedding model | `nomic-embed-text` |
| HITL timeout | 300 seconds |
| RAG threshold | 0.70 similarity |

---

*Generated for the SOAR Capsule project. All systems run locally — no cloud, no API keys, fully air-gapped after setup.*
