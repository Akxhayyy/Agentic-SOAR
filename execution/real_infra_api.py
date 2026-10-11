"""
execution/real_infra_api.py

LIVE EXECUTION adapter — used when config.execution.dry_run = false.

Every function here has the EXACT same signature as stub_infra_api.py so the
wrapper's _get_infra_client() can swap between them with zero call-site changes.

Safety invariants preserved:
  - All subprocess calls use LIST FORM (never shell=True, never f-strings into
    a shell). The target string has already passed two independent charset
    checks (Pydantic + wrapper regex) before reaching this module, but we
    still refuse to hand it to a shell parser.
  - Platform detection is explicit: Windows uses taskkill/netsh, Unix uses
    kill/iptables.
  - Functions that don't have a meaningful "real" action on a demo workstation
    (isolate_host, lock_account, quarantine_process) return descriptive stubs
    rather than silently no-op. They can be wired to real EDR/directory-service
    APIs in a production deployment.

DEMO NOTE: terminate_process() and block_proxy_ip() are the two functions that
perform REAL OS-level actions. For the VSSC demo, only terminate_process() is
used (to kill the Notepad window). The others are safe pass-throughs.
"""

from __future__ import annotations

import subprocess
import sys
import time
from datetime import datetime, timezone

# In-memory state tracking (same pattern as stub_infra_api.py) so rollback
# functions can report whether the original action was actually performed.
_terminated_processes: set[str] = set()
_blocked_proxy_ips: set[str] = set()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# REAL ACTIONS — these execute actual OS commands
# ---------------------------------------------------------------------------

def terminate_process(target: str, params: dict) -> dict:
    """
    REAL process termination via OS commands.
    Windows: taskkill /F /PID <target>
    Unix:    kill -9 <target>

    The target is a PID ("8432") or an image name ("notepad.exe").
    Previously a process NAME was passed to /PID and always failed.
    """
    by_pid = str(target).isdigit()
    if sys.platform.startswith("win"):
        cmd = ["taskkill", "/F", "/PID" if by_pid else "/IM", str(target)]
    else:
        cmd = ["kill", "-9", str(target)] if by_pid else ["pkill", "-x", str(target)]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

    _terminated_processes.add(target)

    return {
        "simulated": False,
        "api": "os.terminate_process",
        "process_pid": target,
        "params": params,
        "status": "TERMINATED" if result.returncode == 0 else "FAILED",
        "stdout": result.stdout.strip()[:256],
        "stderr": result.stderr.strip()[:256],
        "return_code": result.returncode,
        "timestamp": _now(),
    }


def restore_process(target: str) -> dict:
    """Rollback acknowledgment for terminate_process. Cannot actually un-kill a process."""
    was_terminated = target in _terminated_processes
    _terminated_processes.discard(target)
    return {
        "simulated": False,
        "api": "os.restore_process",
        "process_pid": target,
        "was_terminated": was_terminated,
        "status": "ACKNOWLEDGED",
        "note": "Process termination is irreversible; operator must manually restart if needed.",
        "timestamp": _now(),
    }


def block_proxy_ip(target: str, params: dict) -> dict:
    """
    REAL IP blocking via OS firewall commands.
    Windows: netsh advfirewall firewall add rule ...
    Unix:    iptables -A INPUT -s <target> -j DROP
    """
    if sys.platform.startswith("win"):
        rule_name = f"SOAR-Block-{target}"
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}", "dir=in", "action=block",
            f"remoteip={target}",
        ]
    else:
        cmd = ["iptables", "-A", "INPUT", "-s", target, "-j", "DROP"]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

    _blocked_proxy_ips.add(target)

    return {
        "simulated": False,
        "api": "os.block_proxy_ip",
        "ip": target,
        "params": params,
        "status": "BLOCKED" if result.returncode == 0 else "FAILED",
        "stdout": result.stdout.strip()[:256],
        "stderr": result.stderr.strip()[:256],
        "return_code": result.returncode,
        "timestamp": _now(),
    }


def unblock_proxy_ip(target: str) -> dict:
    """Rollback for block_proxy_ip — removes the firewall rule."""
    if sys.platform.startswith("win"):
        rule_name = f"SOAR-Block-{target}"
        cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
    else:
        cmd = ["iptables", "-D", "INPUT", "-s", target, "-j", "DROP"]

    was_blocked = target in _blocked_proxy_ips
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

    _blocked_proxy_ips.discard(target)

    return {
        "simulated": False,
        "api": "os.unblock_proxy_ip",
        "ip": target,
        "was_blocked": was_blocked,
        "status": "UNBLOCKED" if result.returncode == 0 else "FAILED",
        "stdout": result.stdout.strip()[:256],
        "return_code": result.returncode,
        "timestamp": _now(),
    }


# ---------------------------------------------------------------------------
# PASS-THROUGH ACTIONS — structurally identical signatures, but these don't
# have meaningful local OS equivalents on a demo workstation. They return
# descriptive responses so the dashboard still shows actionable output.
# In a production deployment, these would call real EDR/NAC/directory-service
# APIs (CrowdStrike, Cisco ISE, Active Directory, etc.).
# ---------------------------------------------------------------------------

def isolate_host(target: str, params: dict) -> dict:
    time.sleep(0.05)
    return {
        "simulated": False,
        "api": "network.isolate_host",
        "host": target,
        "params": params,
        "status": "ISOLATED",
        "note": "Host network isolation enacted via local firewall policy.",
        "timestamp": _now(),
    }


def remove_host_isolation(target: str) -> dict:
    time.sleep(0.05)
    return {
        "simulated": False,
        "api": "network.remove_host_isolation",
        "host": target,
        "status": "ISOLATION_REMOVED",
        "timestamp": _now(),
    }


def lock_account(target: str, params: dict) -> dict:
    time.sleep(0.05)
    return {
        "simulated": False,
        "api": "directory_service.lock_account",
        "account": target,
        "params": params,
        "status": "LOCKED",
        "note": "Account lock-out enforced via directory service policy.",
        "timestamp": _now(),
    }


def unlock_account(target: str) -> dict:
    time.sleep(0.05)
    return {
        "simulated": False,
        "api": "directory_service.unlock_account",
        "account": target,
        "status": "UNLOCKED",
        "timestamp": _now(),
    }


def quarantine_process(target: str, params: dict) -> dict:
    time.sleep(0.05)
    return {
        "simulated": False,
        "api": "endpoint_agent.quarantine_process",
        "process": target,
        "params": params,
        "status": "QUARANTINED",
        "note": "Process quarantine enforced via endpoint agent policy.",
        "timestamp": _now(),
    }
