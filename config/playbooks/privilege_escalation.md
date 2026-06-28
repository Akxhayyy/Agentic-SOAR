# Playbook: Privilege Escalation Response

## Detection Criteria
Unauthorized elevation of system privileges by a user account not authorized
for administrative operations, identified by one or more of the following
signals:

1. **Unauthorized sudo usage**: `sudo` commands executed by user accounts not
   present in the sudoers file or not members of an authorized admin group,
   logged in auth/security logs within any time window.
2. **Permission widening on system paths**: `chmod 777` or `chmod +x` applied
   to files in system-critical directories (`/usr/bin`, `/usr/sbin`, `/etc`,
   `/var`, `C:\Windows\System32`) — indicates an attempt to make system
   binaries world-writable or to grant execute permission to planted payloads.
3. **SUID/SGID manipulation**: `chmod u+s` or `chmod g+s` applied to any
   binary, enabling privilege inheritance on execution — a classic local
   privilege escalation vector.
4. **Unexpected root shell access**: Direct `su -` or `su root` invocations
   from non-admin accounts, or evidence of `setuid(0)` calls in audit logs.

## Containment Steps
1. Recommend `LOCK_ACCOUNT` against the offending user account immediately —
   privilege escalation implies the actor already has or is actively pursuing
   full system control; credential revocation is the highest-priority
   containment action.
2. If the escalated commands include process execution (e.g. `sudo /bin/sh`,
   `sudo python malicious.py`), additionally recommend `QUARANTINE_PROCESS`
   against the spawned process to halt any ongoing malicious activity running
   under elevated privileges.
3. Do not recommend `ISOLATE_HOST` for a first-occurrence privilege escalation
   unless concurrent network indicators (lateral movement, C2 beaconing)
   corroborate a broader compromise beyond the single account.

## Escalation Criteria
- The escalating account is a service account or machine account — indicates
  possible credential theft or automated exploitation rather than an
  interactive attacker, requiring full credential rotation and service audit.
- SUID bit modifications detected on any binary — this is a persistence
  mechanism that survives password resets and account locks, requiring manual
  filesystem remediation.
- More than 3 distinct privilege escalation attempts detected across different
  user accounts within a 600-second window — suggests a coordinated attack or
  automated privilege enumeration tool (e.g. LinPEAS, WinPEAS).

## Common False Positives
- System administrators performing legitimate maintenance tasks (package
  installation, service restarts) via `sudo`. Verify the user is a member of
  the authorized admin group and the commands match known maintenance patterns.
- Configuration management tools (Ansible, Puppet, Chef) executing `sudo`
  commands as part of automated deployments. These typically originate from
  a known automation service account with a consistent command pattern.
- Developers using `chmod +x` on their own scripts in home directories or
  project workspaces — only flag when the target path is a system-critical
  directory, not user-owned workspace paths.
