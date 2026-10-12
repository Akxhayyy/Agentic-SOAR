"""
scripts/build_otrf_benchmark.py — public-data scenarios from OTRF Security-Datasets.

Source: https://github.com/OTRF/Security-Datasets (MIT License) — real Windows
Security / Sysmon event recordings of attack techniques, each mapped to
MITRE ATT&CK by the authors. This script:

  1. downloads 12 small recordings (~2.1 MB) into data/public_datasets/otrf/raw/
     (git-ignored; untrusted data — zips are read in memory, never extracted
     or executed),
  2. renders the attack-relevant events (process creation, registry, process
     access, services, logons, network) as one log line each, keeping the
     benign background events from the same window so the scenario is noisy,
  3. writes labelled scenarios to data/benchmark/otrf_scenarios.jsonl.

Labels come from the recording's documented ATT&CK technique. Real telemetry
often supports more than one reading (credential dumping is both "malware
execution" and "privilege escalation" in this system's 7-vector taxonomy), so
each scenario lists acceptable vectors / actions / targets rather than a
single answer. The OTRF atomic Windows set contains no brute-force,
exfiltration or proxy recordings — those vectors are covered only by the
synthetic benchmark.

Usage: python scripts/build_otrf_benchmark.py [--offline]
"""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = ROOT / "data" / "public_datasets" / "otrf" / "raw"
OUT = ROOT / "data" / "benchmark" / "otrf_scenarios.jsonl"
BASE_URL = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/"

MAL, PRIV, NET, UNK = "MALWARE_EXECUTION", "PRIVILEGE_ESCALATION", "NETWORK_INTRUSION", "UNKNOWN"
HOST_ACTIONS = ["TERMINATE_PROCESS", "QUARANTINE_PROCESS", "ISOLATE_HOST", "LOCK_ACCOUNT"]

# (path under atomic/windows, expected vector, acceptable vectors, ATT&CK, attack keywords, playbook)
DATASETS = [
    ("execution/host/psh_powershell_httplistener.zip", MAL, [MAL], ["T1059.001"],
     r"httplistener|powershell", "malware_execution.md"),
    ("defense_evasion/host/cmd_mshta_vbscript_execute_psh.zip", MAL, [MAL], ["T1218", "T1059"],
     r"mshta|vbscript", "malware_execution.md"),
    ("defense_evasion/host/cmd_bitsadmin_download_psh_script.zip", MAL, [MAL], ["T1197", "T1105"],
     r"bitsadmin", "malware_execution.md"),
    ("persistence/host/empire_persistence_registry_modification_run_keys_elevated_user.zip", MAL, [MAL, PRIV],
     ["T1547.001"], r"currentversion.{1,4}run", "malware_execution.md"),  # JSON-escaped backslashes
    ("privilege_escalation/host/cmd_service_mod_fax.zip", PRIV, [PRIV, MAL], ["T1543.003"],
     r"\bfax\b|sc(\.exe)? config", "privilege_escalation.md"),
    ("defense_evasion/host/psh_cmstp_execution_bypassuac.zip", PRIV, [PRIV, MAL], ["T1548.002", "T1218.003"],
     r"cmstp", "privilege_escalation.md"),
    ("privilege_escalation/host/empire_uac_shellapi_fodhelper.zip", PRIV, [PRIV, MAL], ["T1548.002"],
     r"fodhelper|ms-settings", "privilege_escalation.md"),
    ("credential_access/host/psh_lsass_memory_dump_comsvcs.zip", MAL, [MAL, PRIV], ["T1003.001"],
     r"comsvcs|minidump|lsass", "malware_execution.md"),
    ("credential_access/host/cmd_sam_copy_esentutl.zip", MAL, [MAL, PRIV], ["T1003.002"],
     r"esentutl|\\sam\b", "malware_execution.md"),
    ("lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl.zip", NET, [NET, MAL], ["T1021.002", "T1569.002"],
     r"psexe|svcctl|services\.exe", "network_intrusion.md"),
    ("lateral_movement/host/covenant_sharpwmi_create_dcerpc_wmi.zip", NET, [NET, MAL], ["T1047", "T1021"],
     r"wmiprvse|win32_process|sharpwmi", "network_intrusion.md"),
    ("discovery/host/empire_shell_net_localgroup_administrators.zip", NET, [NET, UNK, PRIV], ["T1069.001"],
     r"net1?(\.exe)? +localgroup", "network_intrusion.md"),
]

# Event IDs worth rendering (Sysmon + Security + System); image-load noise etc. is skipped.
KEEP_EVENTS = {1, 3, 8, 10, 11, 12, 13, 17, 18, 4624, 4625, 4672, 4688, 4697, 4698, 4720, 4732, 7045}
FIELDS = ["Image", "CommandLine", "ParentImage", "TargetObject", "Details", "SourceImage", "TargetImage",
          "GrantedAccess", "ServiceName", "ImagePath", "DestinationIp", "DestinationPort", "TargetFilename",
          "NewProcessName", "ParentProcessName", "TargetUserName", "IpAddress"]
MAX_EVENTS = 220
MAX_BACKGROUND = 120


def fetch(path: str, offline: bool) -> bytes:
    local = RAW_DIR / Path(path).name
    if local.exists():
        return local.read_bytes()
    if offline:
        raise FileNotFoundError(f"{local} missing and --offline set")
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(BASE_URL + path, timeout=60) as resp:  # noqa: S310 — fixed https URL
        data = resp.read()
    zipfile.ZipFile(io.BytesIO(data)).testzip()
    local.write_bytes(data)
    return data


def events_from_zip(data: bytes) -> list[dict]:
    out = []
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for name in zf.namelist():
            if not name.lower().endswith(".json"):
                continue
            for line in zf.read(name).decode("utf-8", errors="replace").splitlines():
                line = line.strip()
                if line.startswith("{"):
                    try:
                        out.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    return out


def _short_user(u: str) -> str:
    return re.split(r"[\\/]", str(u))[-1]


def render(ev: dict) -> str:
    ts = str(ev.get("@timestamp") or ev.get("EventTime") or ev.get("TimeCreated") or "")
    if ts and "T" not in ts[:11]:
        ts = ts.replace(" ", "T", 1)
    channel = "Sysmon" if "sysmon" in str(ev.get("Channel", "")).lower() else str(ev.get("Channel", "") or "Windows")
    parts = [ts, f"host={ev.get('Hostname') or ev.get('Computer') or '?'}", f"EventID={ev.get('EventID')}", channel]
    user = ev.get("User") or ev.get("SubjectUserName")
    if user:
        parts.append(f"user: {_short_user(user)}")
    pid = ev.get("ProcessId") or ev.get("NewProcessId")
    if pid:
        parts.append(f"PID:{int(pid, 16) if isinstance(pid, str) and pid.startswith('0x') else pid}")
    for f in FIELDS:
        v = ev.get(f)
        if v not in (None, "", "-"):
            parts.append(f"{f}={str(v)[:220]}")
    return " ".join(str(p) for p in parts)[:1000]


def targets_from(events: list[dict]) -> list[str]:
    vals: set[str] = set()
    for ev in events:
        for k in ("Hostname", "Computer"):
            if ev.get(k):
                vals.add(str(ev[k]).split(".")[0])
                vals.add(str(ev[k]))
        u = ev.get("User") or ev.get("SubjectUserName")
        if u and not str(u).upper().startswith(("NT AUTHORITY", "SYSTEM")):
            vals.add(_short_user(u))
        pid = ev.get("ProcessId") or ev.get("NewProcessId")
        if pid:
            vals.add(str(int(pid, 16) if isinstance(pid, str) and pid.startswith("0x") else pid))
        img = ev.get("Image") or ev.get("NewProcessName")
        if img:
            vals.add(re.split(r"[\\/]", str(img))[-1].lower())
    return sorted(v for v in vals if v and re.match(r"^[A-Za-z0-9_.:\-@]+$", v))


def build_scenario(path: str, vector: str, vectors: list[str], mitre: list[str], kw: str, playbook: str,
                   events: list[dict]) -> dict:
    rx = re.compile(kw, re.I)
    kept = [e for e in events if int(e.get("EventID") or 0) in KEEP_EVENTS]
    attack = [e for e in kept if rx.search(json.dumps(e))][:MAX_EVENTS]
    background = [e for e in kept if not rx.search(json.dumps(e))][:MAX_BACKGROUND]
    chosen = sorted(attack + background, key=lambda e: str(e.get("@timestamp") or e.get("EventTime") or ""))
    return {
        "id": "otrf-" + Path(path).stem[:40],
        "category": "attack",
        "difficulty": "public",
        "source": f"OTRF/Security-Datasets datasets/atomic/windows/{path} (MIT)",
        "logs": [render(e) for e in chosen],
        "expected_attack_vector": vector,
        "acceptable_vectors": vectors,
        "expected_action_type": HOST_ACTIONS[0],
        "expected_target": None,
        "acceptable_actions": HOST_ACTIONS,
        "acceptable_targets": targets_from(attack),
        "mitre": mitre,
        "expected_playbook": playbook,
        "notes": f"{len(attack)} attack-relevant + {len(background)} background events",
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--offline", action="store_true", help="use already-downloaded zips only")
    args = p.parse_args()
    rows = []
    for path, vector, vectors, mitre, kw, playbook in DATASETS:
        events = events_from_zip(fetch(path, args.offline))
        row = build_scenario(path, vector, vectors, mitre, kw, playbook, events)
        rows.append(row)
        print(f"{row['id']:<45} {len(events):>6} events -> {len(row['logs']):>4} lines  ({row['notes']})")
    OUT.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    print(f"Wrote {len(rows)} scenarios to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
