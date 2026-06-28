```markdown
# Security Incident Audit Summary

## Incident ID
f2aa1795-af48-45a3-ad52-71765db48fcd

## Incident Details
- **Created At**: 2026-06-24T17:37:23.413634+00:00
- **Attack Vector**: BRUTE_FORCE_AUTH
- **Triage Confidence**: 0.95

### Triage Summary
Multiple failed login attempts followed by a successful one for user `db_admin` from IP `172.16.2.80`.

### Indicators of Compromise (IOCs)
- **IP Address**: 172.16.2.80 (Confidence: 1.0)
- **Username**: db_admin (Confidence: 1.0)

## Forensics
- **Playbook Matches**:
  - `brute_force_auth.md__chunk0__70ebc9f87db8ce55` with a similarity score of 0.6534.
  - `brute_force_auth.md__chunk1__c684d02cab88ab77` with a similarity score of 0.6091.
- **Final Similarity Score**: 0.92
- **Cleared Threshold**: True

## Action Plan
- **Action Type**: LOCK_ACCOUNT
- **Target**: db_admin
- **Justification**: High confidence brute force attack on `db_admin` account from a single IP address indicates potential compromise.

## Execution Result
- **Dry Run**: True
- **Success**: True
- **Hash Verified**: True
- **Simulated Response**:
  - API: `directory_service.lock_account`
  - Account: `db_admin`
  - Status: LOCKED
  - Timestamp: 2026-06-24T17:39:11.221242+00:00

## Human-in-the-Loop Decision
- **Decision**: APPROVED

## Threat Status
- **Status**: OPEN
```