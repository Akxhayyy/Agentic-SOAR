```markdown
# Security Incident Audit Summary

## Incident ID
d201dbd0-b3e7-422c-9ffb-8e943edf6780

## Created At
2026-06-22T15:54:00.469105+00:00

### Triage Summary
- **Attack Vector:** BRUTE_FORCE_AUTH
- **Indicators of Compromise (IOCs):**
  - Username: `svc-backup` (Confidence: 0.9)
  - IP Address: `10.0.4.17` (Confidence: 0.85)
- **Summary:** Multiple failed login attempts followed by a successful one for svc-backup from IP 10.0.4.17.
- **Triage Confidence:** 0.95

### Forensics
- **Playbook Matches:**
  - `brute_force_auth.md__chunk0__70ebc9f87db8ce55` (Similarity Score: 0.6463)
  - `brute_force_auth.md__chunk1__c684d02cab88ab77` (Similarity Score: 0.6153)
- **Pass Count:** 2
- **Final Similarity Score:** 0.92
- **Cleared Threshold:** True

### Action Plan
- **Action Type:** LOCK_ACCOUNT
- **Target:** svc-backup
- **Justification:** High confidence brute force attack on svc-backup account from IP 10.0.4.17.
- **Payload Hash:** aeff94fd8ed6d3ad3a4fe40db999c8533b2565a2f818f50a8f1ac66e6ce0096f

### Execution Result
- **Action Type:** LOCK_ACCOUNT
- **Target:** svc-backup
- **Dry Run:** True
- **Success:** True
- **Hash Verified:** True
- **Stub Response:**
  - Simulated: True
  - API: `directory_service.lock_account`
  - Account: `svc-backup`
  - Status: LOCKED
  - Timestamp: 2026-06-22T15:57:40.990105+00:00
- **Executed At:** 2026-06-22T15:57:40.990105Z
- **Error Message:** None

### HITL Decision
APPROVED

### Threat Status
OPEN
```