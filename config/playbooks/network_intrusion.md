# Playbook: Network Intrusion Response

## Detection Criteria
Unauthorized network reconnaissance or lateral movement indicators originating
from a single source IP, identified by one or more of the following signals:

1. **Port scanning**: nmap, masscan, or equivalent tool signatures detected in
   network/IDS logs, targeting 3+ distinct destination ports within a 120-second
   window from the same source IP.
2. **Lateral movement**: Connection attempts to multiple internal hosts (3+ distinct
   destination IPs) on administrative ports (22/SSH, 3389/RDP, 445/SMB, 5985/WinRM)
   within a 300-second window from a single internal source.
3. **Unauthorized access**: Explicit IDS/firewall alerts flagging "unauthorized access
   attempt" against any network service, regardless of port count.

## Containment Steps
1. If port scanning is detected from an **external** source IP, recommend
   `ISOLATE_HOST` against the targeted internal host to prevent exploitation of
   any discovered open ports while the perimeter firewall rule is updated.
2. If port scanning or lateral movement is detected from an **internal** source IP,
   recommend `ISOLATE_HOST` against the source host — an internal scanner is
   either a compromised host or a policy violation, both requiring immediate
   network quarantine.
3. Do not recommend `LOCK_ACCOUNT` for pure network-layer activity unless
   authentication log correlation provides a specific username tied to the
   scanning source. Network intrusion is host-identified, not user-identified.

## Escalation Criteria
- Source IP probes more than 20 distinct destination hosts within the detection
  window — indicates automated scanning at a scale suggesting a compromised host
  running a worm or an active adversary performing network enumeration.
- Any detection of scanning on OT/SCADA ports (502/Modbus, 47808/BACnet,
  20000/DNP3) triggers immediate Tier-3 escalation regardless of scan volume.

## Common False Positives
- Authorized vulnerability scanners (Nessus, Qualys, OpenVAS) running scheduled
  assessments. Cross-reference the source IP against the asset inventory's
  "authorized scanner" list. If it matches and the scan falls within a
  registered maintenance window, lower confidence to below the 0.70 threshold.
- Network monitoring tools (Nagios, Zabbix) performing ICMP/TCP health checks
  across many hosts — these typically target a single known port per host, not
  the multi-port sweep pattern characteristic of offensive scanning.
