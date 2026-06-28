```markdown
# Security Incident Audit Summary

## Incident ID
e35f4cab-d72a-4e91-a7c2-1f2170faab65

## Incident Details
- **Created At**: 2026-06-24T18:40:50.502935+00:00
- **Attack Vector**: BRUTE_FORCE_AUTH
- **Discovered Layout**: syslog

### Triage Summary
Multiple failed login attempts followed by a successful login from the same IP and username.

### Indicators of Compromise (IOCs)
- **IP Address**: 192.168.1.200 (Confidence: 1.0)
- **Username**: test_operator (Confidence: 1.0)

### Triage Confidence
0.9

## Forensics Summary
- **Playbook Matches**:
  - # Playbook: Brute Force Authentication Response (Similarity Score: 0.7137)
  - Common False Positives (Similarity Score: 0.6613)

### Action Plan
- **Action Type**: LOCK_ACCOUNT
- **Target**: user@example.com
- **Justification**: Multiple failed login attempts followed by a successful login from the same IP and username suggest a brute force attack.
- **Payload Hash**: 3e116f5124ba0e14d15c871ef4ce391a25eedc64cf3cf9a3d1894b9027eeebb0

## Execution Result
- **Action Type**: LOCK_ACCOUNT
- **Target**: user@example.com
- **Dry Run**: true
- **Success**: true
- **Hash Verified**: true
- **Stub Response**:
  - Simulated: true
  - API: directory_service.lock_account
  - Account: user@example.com
  - Status: LOCKED
  - Timestamp: 2026-06-24T18:44:36.384011+00:00

### HITL Decision
APPROVED

### Threat Status
OPEN
```