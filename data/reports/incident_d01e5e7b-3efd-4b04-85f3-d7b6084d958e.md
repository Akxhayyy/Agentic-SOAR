```markdown
# Security Incident Audit Summary

## Incident ID
d01e5e7b-3efd-4b04-85f3-d7b6084d958e

## Incident Details
- **Created At:** 2026-06-24T18:58:30.676756+00:00
- **Attack Vector:** BRUTE_FORCE_AUTH
- **Discovered Layout:** syslog

### Indicators of Compromise (IOCs)
- **IP Address:** 172.16.2.80, Confidence: 1.0
- **Username:** db_admin, Confidence: 1.0

### Triage Summary
Multiple failed login attempts followed by a successful one from the same IP and user.

### Triage Confidence
90%

## Forensics
- **Playbook Matches:**
  - # Playbook: Brute Force Authentication Response (Similarity Score: 0.7125)
  - Common False Positives (Similarity Score: 0.6536)

- **Pass Count:** 1
- **Final Similarity Score:** 0.7125
- **Cleared Threshold:** True

## Action Plan
- **Action Type:** LOCK_ACCOUNT
- **Target:** user@192.168.1.100
- **Justification:** High confidence in brute force attack attempt followed by successful login from the same IP and user, requiring account lock to prevent further unauthorized access.

## Execution Result
- **Dry Run:** True
- **Success:** True
- **Hash Verified:** True
- **Simulated Response:**
  - API: `directory_service.lock_account`
  - Account Locked at: 2026-06-24T19:02:03.890792+00:00

## Human-in-the-Loop Decision
- **Decision:** APPROVED

## Threat Status
- **Status:** OPEN
```