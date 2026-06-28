# Playbook: Brute Force Authentication Response

## Detection Criteria
Repeated failed authentication attempts (5+) against a single account
within a 60-second window, originating from one or more source IPs,
optionally followed by a single successful login.

## Containment Steps
1. If the account shows a successful login after a burst of failures,
   treat the account as potentially compromised — recommend LOCK_ACCOUNT.
2. If the source IP is internal and shows scanning behavior across multiple
   accounts, recommend ISOLATE_HOST against the source, not the target account.
3. Do not recommend QUARANTINE_PROCESS for pure auth-log-only evidence;
   that action requires endpoint/process telemetry corroboration.

## Escalation Criteria
If failed attempts exceed 50 within the window, or originate from more than
10 distinct source IPs (distributed brute force), escalate regardless of
whether a successful login occurred — this pattern frequently indicates
credential-stuffing using a leaked password list rather than a targeted
attack, and warrants manual review of the full account population, not just
the single flagged account.

## Common False Positives
- Misconfigured service accounts retrying with stale cached credentials
  after a password rotation. Check for a single source IP/host pattern
  with mechanically regular retry intervals (e.g. exactly every 30s) —
  this is a strong signal of an automated retry loop rather than an
  attacker, and should lower confidence in BRUTE_FORCE_AUTH classification.
