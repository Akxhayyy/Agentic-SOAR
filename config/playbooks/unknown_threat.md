# Playbook: Unknown Threat Response

## Detection Criteria
This playbook activates when the Triage Agent classifies an incident as
`UNKNOWN` — meaning the log evidence does not match any of the six defined
attack vector categories (BRUTE_FORCE_AUTH, NETWORK_INTRUSION,
MALWARE_EXECUTION, DATA_EXFILTRATION, PRIVILEGE_ESCALATION, PROXY_ANOMALY)
with sufficient confidence.

An UNKNOWN classification occurs when:
1. The suspicious log patterns flagged by the cheap filter do not align with
   any recognized attack taxonomy after LLM evaluation.
2. The triage confidence score is below 0.50 for all known attack vectors,
   indicating ambiguous or novel threat indicators.
3. The log evidence contains mixed signals spanning multiple attack categories
   without a clear primary vector.

## Containment Steps

**HARD DIRECTIVE: ZERO AUTOMATED CONTAINMENT.**

1. Recommend `NO_ACTION` — this is mandatory, not optional. Unknown threats
   must NEVER trigger automated containment actions (`ISOLATE_HOST`,
   `LOCK_ACCOUNT`, `QUARANTINE_PROCESS`, `TERMINATE_PROCESS`,
   `BLOCK_PROXY_IP`) because the risk of disrupting legitimate operations
   based on an unclassified, ambiguous signal exceeds the risk of delayed
   response.
2. The Neutralizer Agent MUST output `action_type="NO_ACTION"` with a
   justification explaining that the threat classification is UNKNOWN and
   automated response is not authorized.
3. All automated pipeline stages (Forensics RAG match, Neutralizer planning,
   Execution Wrapper) run as normal but MUST converge on NO_ACTION. The
   pipeline exists to DOCUMENT, not to ACT.

## Escalation Criteria

**ALL unknown threats are escalated. There is no non-escalation path.**

- Mandatory Tier-3 operator escalation is triggered immediately upon
  pipeline completion, regardless of forensics confidence score.
- The generated incident report MUST include the full raw log evidence
  (subject to the standard 200-char uicr_compress truncation for the
  Responder's context window) and the Triage Agent's reasoning for the
  UNKNOWN classification.
- The operator escalation notification MUST include a clear banner:
  `ESCALATION_REQUIRED_REPORT — UNKNOWN THREAT — MANUAL ANALYSIS REQUIRED`.

## Common False Positives
- Benign log entries that happen to contain suspicious keywords in non-security
  contexts (e.g. application error messages mentioning "unauthorized" in a
  business logic sense, not a security sense).
- Malformed or truncated log lines that lack sufficient context for accurate
  classification — the cheap filter correctly flagged them as suspicious, but
  the Triage Agent cannot determine the attack vector from the available text.
- Legitimate but unusual administrative operations that combine multiple
  tool invocations in an atypical sequence, triggering multiple cheap filter
  rules without actually constituting an attack.

## Operator Guidance
When a Tier-3 operator receives an UNKNOWN threat escalation:
1. Review the full raw log evidence in the incident report.
2. Cross-reference with SIEM correlation rules and threat intelligence feeds
   not available to the local SOAR capsule.
3. If the threat is confirmed, manually reclassify it under the appropriate
   attack vector and initiate the corresponding playbook's containment steps.
4. If the threat is a false positive, close the incident with documentation
   explaining the benign root cause to improve future triage accuracy.
