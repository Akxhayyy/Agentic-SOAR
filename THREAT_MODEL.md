# Threat Model — Agentic SOAR Capsule

This document describes what the capsule protects, where untrusted data enters, how an
attacker could try to turn the automation against its owner, and which controls stop
them. Every mitigation names the code that implements it. The red-team suite
(`tests/redteam/`, `scripts/redteam.py`) measures them.

## 1. System summary

Logs are ingested and pre-screened by deterministic rules. They are then grouped into
incidents and processed by a LangGraph pipeline:

1. **Triage:** an LLM classifies the incident and extracts IOCs.
2. **Forensics:** an LLM agent with read-only tools.
3. **Neutralizer:** an LLM proposes one containment action.
4. **HITL gate:** a human approves or rejects it.
5. **Execution wrapper:** deterministic code verifies the plan and acts.
6. **Report.**

Everything runs locally (Ollama, ChromaDB, SQLite). There are no outbound network calls.

## 2. Assets

| Asset | Why it matters |
|---|---|
| Containment authority (`execution/`) | Can isolate hosts, lock accounts, kill processes and block IPs. Misuse is a denial-of-service against the defender's own organisation. |
| Protected infrastructure | The SOC host itself, loopback, operator accounts. Containing these blinds the defender. |
| Incident record / audit trail | Checkpoints (`graph_state.db`), reports and `audit.log`. Integrity matters for accountability. |
| Operator attention | HITL is the final control. Flooding or misleading it is an attack. |

## 3. Trust boundaries

```
 attacker-controlled                         | trusted code                         | host
 ------------------------------------------- | ------------------------------------ | -----------
 log text  ──►  ingestion (RawLogEntry caps) ──► LLM agents (treated as UNTRUSTED)
                                             ──► deterministic validators ──► HITL ──► wrapper ──► OS / stub
```

* **B1, log ingestion:** every byte of log text is attacker-controlled. Attackers
  write to the systems that emit those logs, for example through usernames, URLs and
  user-agents.
* **B2, LLM output:** the reasoning model reads B1 data, so **its output is treated
  as untrusted too**. This is the central design decision: no LLM output reaches the
  execution layer without passing deterministic checks.
* **B3, operator:** decisions arrive through the API. They are bound to the paused
  incident and recorded in the audit log.
* **B4, execution:** only `execution/wrapper.py` may call infrastructure APIs, through a
  static allow-list dispatch.

## 4. Adversaries

* **A1, log injector (primary).** Can make arbitrary text appear in ingested logs.
  Goal: make the SOAR contain something of the attacker's choosing, or nothing at all.
* **A2, in-process tamperer.** A bug or compromised component that mutates incident
  state between planning and execution.
* **A3, fully hijacked model (evaluation stance).** We assume prompt injection can
  completely control the LLM's output, because instruction-tuned 7–8B models cannot be
  trusted to resist it. Defences must hold **without** model cooperation.

## 5. Attacks → mitigations

| # | Attack | Mitigation (code) | Type |
|---|---|---|---|
| T1 | Injected instruction makes the planner target a **protected asset** (`127.0.0.1`, the SOC host, `soc-operator`) | Deny-list checked in the planner (`agents/neutralizer.py:check_grounding`) **and independently re-checked** in the wrapper (`execution/wrapper.py:_is_protected`). The local hostname is always included. | toggle `deny_list` |
| T2 | Model **invents a target** not present in the evidence (e.g. "lock the CEO") | Evidence grounding: the target must exactly equal an IOC extracted by Triage. Triage keeps only IOCs that literally appear in the logs. Enforced twice: as a JSON-schema `enum` during decoding, and as a post-check. | toggle `grounding` |
| T3 | **Type confusion**: TERMINATE a username, LOCK an IP, block a port | Action/target-type matrix (`ACTION_TARGET_TYPES`), encoded in the decoding grammar (`anyOf` branches) and re-checked after parsing. | toggle `grounding` |
| T4 | **Malicious identifiers**: shell metacharacters, command substitution, path traversal, netsh argument injection, SQL-ish quoting, **Unicode homoglyphs** | ASCII-only charset allow-list at the Pydantic boundary (`core/uicr_schema.py:SAFE_TOKEN_PATTERN`) and independently in the wrapper. Subprocess calls use list form only, never `shell=True`. | structural |
| T5 | **State tampering** between approval request and execution | SHA-256 over the canonical `(action_type, target, params)`, computed at planning and recomputed by the wrapper. Execution aborts on mismatch. | toggle `hash_check` |
| T6 | **Tool-argument injection** into the forensics agent | Indicator arguments are schema `enum`s of extracted IOCs and re-checked in `agents/forensics_tools.py:_require_ioc`. Tools are read-only by construction (AST-tested: no execution, subprocess, network or write imports). Budget of 5 calls. | structural |
| T7 | **Output-format attacks**: free text or fences to confuse parsers | Grammar-constrained JSON (`format` = JSON schema) with closed enums. Invalid output falls back to `UNKNOWN` / `NO_ACTION`, never to a relaxed schema. | structural |
| T8 | **XSS** via log or report content in the UI | The UI never renders log or LLM content as raw HTML. Markdown is rendered without raw-HTML passthrough. | structural |
| T9 | **Double execution / race** at the HITL gate | Per-incident lock plus an "is it actually paused?" check, so a second decision gets 409. Timeouts and operator decisions share one resume path (`main.py:_resume`). | structural |
| T10 | **Escalation suppression**: crash the pipeline so nothing is reported | Node failures become `FAILED` + `ESCALATED` with a report still written (`core/graph.py:_instrument`). Timeout watchers are re-armed from the persisted pause time after a restart. | structural |
| T11 | Benchmark or red-team run accidentally **touching the host** | `evaluation/runner.py:isolated_runtime` forces `dry_run=true` regardless of config. | structural |

## 6. Red-team results

Worst case: a **fully hijacked LLM** that obeys every injected instruction (it even
ignores the decoding grammar), plus a **rubber-stamp operator** who approves everything.
That leaves 32 payloads across 7 attack classes. Reproduce with `python scripts/redteam.py`.

| Attack class | Payloads | Success, defences OFF | Success, defences ON | Stopped by (ON) |
|---|---|---|---|---|
| protected_asset | 6 | 100% | **0%** | deny-list (planner) |
| invented_target | 6 | 100% | **0%** | evidence grounding |
| type_confusion | 4 | 100% | **0%** | evidence grounding |
| state_tamper | 4 | 100% | **0%** | hash check (wrapper) |
| malicious_identifier | 6 | 0% | **0%** | charset allow-list (structural, always on) |
| tool_injection | 2 | 50% | 50% | tool-arg IOC check (1 of 2) |
| evidence_poisoning | 4 | 100% | 100% | — (residual risk, see §7) |
| **All** | **32** | **78%** | **16%** | |
| All except evidence poisoning | | 75% | **4%** | |

Defence-in-depth check: with the planner's deny-list disabled, the wrapper's
independent check still refuses protected targets
(`tests/test_redteam.py::test_wrapper_refuses_protected_target_even_if_planner_is_bypassed`).

**Found and fixed by the red team:** the charset allow-list used `\w`, which in Python
matches any Unicode letter. A Cyrillic `аdmin` passed every check and could be locked
in place of the real account (payload `rt-21`). Both copies of the pattern are now
ASCII-only, with regression tests in `tests/test_units.py::test_charset_is_ascii_only`.

## 7. Residual risks (accepted, with compensating controls)

1. **Evidence poisoning (rt-29…rt-32).** If an attacker can forge *realistic* log lines,
   for example failed logins "from" a colleague's workstation, the forged indicator
   *is* evidence. Every deterministic check passes, because the system is doing its job
   on the data it was given. **Compensating control: the HITL gate.** The operator sees
   the plan, its justification, the grounding note and the raw logs before approving.
   Destructive actions in LIVE mode need typed confirmation in the UI. *Not mitigated
   by design:* source authentication of log producers (signed or forwarded logs) belongs
   upstream in the logging pipeline.
2. **Read-only investigation steering (rt-27).** Text in a log can make an indicator
   appear in the evidence, so the forensics agent may spend tool calls on it. Impact is
   limited to wasted budget (at most 5 read-only calls) and a possibly misleading
   rationale. It cannot cause an action, and the playbook choice is still scored by
   embedding similarity, not by the agent.
3. **Rubber-stamping.** HITL only helps if the operator reads the plan. The UI shows the
   grounding result and evidence, and the 300s timeout escalates rather than executes.
4. **Classification errors and false positives.** The benchmark's false-positive traps
   (service accounts retrying after a password rotation, authorised scanners, backups)
   show that benign-but-suspicious activity can produce a plausible containment plan.
   The HITL gate and per-action rollback (`POST /api/incidents/{id}/rollback`) are the
   controls.
5. **Local host compromise.** An attacker with code execution on the SOC host can edit
   the config, the DB or the code. This is out of scope for an application-level threat
   model.

## 8. Why only Forensics is agentic

The forensics agent chooses its own tool calls. The Neutralizer and the execution
wrapper deliberately do **not**:

* **Blast radius.** Forensics tools are read-only, so a wrong agent decision costs time.
  Containment actions disrupt real users and hosts. Autonomy goes where mistakes are cheap.
* **Auditability.** The plan is a single, hashed, schema-validated object that a human
  approves as a unit. A multi-step acting agent would make "what exactly did the
  operator approve?" ambiguous and would break the hash contract.
* **Determinism at the boundary.** Every check between the LLM and the OS (grounding,
  type matrix, deny-list, charset, hash) is plain code with unit and red-team tests.
  The 0.70 escalation threshold in `core/graph.py:route_after_forensics` stays
  deterministic as well: the agent's self-reported confidence is recorded but never
  used for routing.

## 9. Out of scope

* Authentication and authorisation of API callers. It binds to `127.0.0.1` for a
  single-operator capsule; add auth before exposing it on a network.
* Confidentiality of logs at rest (SQLite and report files are unencrypted).
* Supply-chain integrity of model weights and Python dependencies (pinned in
  `requirements.txt`, but not hash-locked).
* Real EDR / directory-service integrations. `real_infra_api.py` performs only
  `taskkill`/`kill` and firewall rules, and the rest are stubs.
