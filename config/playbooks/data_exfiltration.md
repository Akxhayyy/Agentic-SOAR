# Playbook: Data Exfiltration Response

## Detection Criteria
Evidence of unauthorized outbound data transfer from internal systems to
external or untrusted destinations, identified by one or more of the
following signals:

1. **Outbound transfer utilities**: Usage of `scp`, `rsync`, `ftp put`,
   `curl --upload-file`, or `curl -X PUT/POST` targeting external IP
   addresses or hostnames not on the approved egress whitelist, logged in
   shell history, audit logs, or proxy access logs.
2. **Bulk data patterns**: Log entries containing keywords `bulk download`,
   `bulk export`, `bulk transfer`, `bulk copy`, or explicit `exfiltration`
   references — indicating large-volume data movement outside normal
   operational parameters.
3. **Anomalous outbound volume**: Network flow logs showing a single internal
   host or user account transferring more than 50MB outbound to a single
   external destination within a 300-second window, where that destination
   has no prior 30-day communication history with the source.
4. **Staging indicators**: Creation of compressed archives (`.tar.gz`,
   `.zip`, `.7z`) in temporary directories (`/tmp`, `/var/tmp`, `%TEMP%`)
   immediately preceding an outbound transfer, suggesting deliberate
   pre-staging for exfiltration.

## Containment Steps
1. Recommend `LOCK_ACCOUNT` against the user account associated with the
   transfer activity — prevents the actor from initiating additional
   transfers or pivoting to other data stores using the same credentials.
2. Recommend `BLOCK_PROXY_IP` against the egress destination IP if the
   transfer was routed through the organization's web proxy — cuts the
   active exfiltration channel at the network edge.
3. If the source host shows signs of compromise beyond the data transfer
   (e.g. concurrent malware indicators), additionally recommend
   `ISOLATE_HOST` to contain the endpoint entirely.

## Escalation Criteria
- Estimated exfiltrated volume exceeds 100MB based on flow log byte counts —
  indicates a significant data breach requiring legal/compliance notification
  assessment.
- Exfiltration targets multiple distinct external destinations (3+ unique IPs
  or hostnames) — suggests an automated exfiltration tool rather than manual
  one-off transfer, implying deeper compromise.
- The compromised user account is a service account or holds elevated database
  access privileges — the potential data exposure scope is unbounded and
  requires immediate DBA-led access audit.

## Common False Positives
- Scheduled backup jobs using `rsync` or `scp` to off-site backup servers.
  Verify the destination against the approved backup target list and confirm
  the transfer occurred during the registered backup window.
- Developers pushing large build artifacts to external CI/CD systems or
  package registries. Cross-reference with approved DevOps tool integrations.
- Cloud sync agents (OneDrive, Dropbox, Google Drive) performing normal
  synchronization — these generate high-volume outbound traffic but use
  well-known destination IP ranges that should be whitelisted.
