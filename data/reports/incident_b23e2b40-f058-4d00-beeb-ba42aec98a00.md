# Security Incident Audit Summary

## Incident ID
b23e2b40-f058-4d00-beeb-ba42aec98a00

## Created At
2026-06-24T17:10:39.099648+00:00

### Triage Summary
- **Attack Vector:** BRUTE_FORCE_AUTH
- **Indicators of Compromise (IOCs):**
  - IP Address: `10.0.0.99`
  - Port: `22`
- **Summary:** Multiple unauthorized access attempts on port 22, followed by an nmap scan and failed attempts on ports 80 and 443.
- **Confidence Level:** 0.9

### Forensics
- **Playbook Matches:**
  - Playbook ID: `brute_force_auth.md__chunk0__70ebc9f87db8ce55`
    - Similarity Score: 0.6442
  - Playbook ID: `brute_force_auth.md__chunk1__c684d02cab88ab77`
    - Similarity Score: 0.6179
- **Pass Count:** 2
- **Final Similarity Score:** 0.8
- **Cleared Threshold:** True
- **RAG Timeline Notes:** Pass 2 (+/-300s window, floor=0.35): final_score=0.800, cleared hard threshold 0.7.

### Action Plan
- **Action Type:** LOCK_ACCOUNT
- **Target:** user1234
- **Justification:** Multiple unauthorized access attempts on port 22 and subsequent nmap scan indicate a brute force attack. Locking the account prevents further unauthorized access.
- **Payload Hash:** cd7c5a81040b73e83e742d42279a9aab1c9e5335c171ec0eb2635b2a17dfb8f4

### Execution Result
- **Action Type:** LOCK_ACCOUNT
- **Target:** user1234
- **Dry Run:** True
- **Success:** True
- **Hash Verified:** True
- **Stub Response:**
  - Simulated: True
  - API: `directory_service.lock_account`
  - Account: `user1234`
  - Status: LOCKED
  - Timestamp: 2026-06-24T17:11:36.419679+00:00
- **Executed At:** 2026-06-24T17:11:36.419679Z
- **Error Message:** None

### HITL Decision
APPROVED

### Threat Status
OPEN