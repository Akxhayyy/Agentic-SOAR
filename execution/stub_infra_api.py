"""
execution/stub_infra_api.py

Stubbed infrastructure API used when config.execution.dry_run=true. Every
function here has the EXACT signature a real production client would need
(see the NotImplementedError comment in execution/wrapper.py:_get_infra_client).
That's the whole point: swapping DRY_RUN off in production should be a
one-line change in _get_infra_client(), not a rewrite of call sites.

No real system call, file mutation, or network request happens here —
everything is an in-memory simulation that returns a structurally identical
response shape to what the real client would return.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

# In-memory simulated infra state, purely for demo realism (e.g. so a
# rollback call can report "host was isolated, now removing isolation"
# instead of always returning a context-free canned response).
_isolated_hosts: set[str] = set()
_locked_accounts: set[str] = set()
_quarantined_processes: set[str] = set()
_terminated_processes: set[str] = set()
_blocked_proxy_ips: set[str] = set()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def isolate_host(target: str, params: dict) -> dict:
    time.sleep(0.05)  # simulate API latency for realistic dashboard pacing
    _isolated_hosts.add(target)
    return {
        "simulated": True,
        "api": "firewall.isolate_host",
        "host": target,
        "params": params,
        "status": "ISOLATED",
        "timestamp": _now(),
    }


def remove_host_isolation(target: str) -> dict:
    time.sleep(0.05)
    was_isolated = target in _isolated_hosts
    _isolated_hosts.discard(target)
    return {
        "simulated": True,
        "api": "firewall.remove_host_isolation",
        "host": target,
        "was_isolated": was_isolated,
        "status": "ISOLATION_REMOVED",
        "timestamp": _now(),
    }


def lock_account(target: str, params: dict) -> dict:
    time.sleep(0.05)
    _locked_accounts.add(target)
    return {
        "simulated": True,
        "api": "directory_service.lock_account",
        "account": target,
        "params": params,
        "status": "LOCKED",
        "timestamp": _now(),
    }


def unlock_account(target: str) -> dict:
    time.sleep(0.05)
    was_locked = target in _locked_accounts
    _locked_accounts.discard(target)
    return {
        "simulated": True,
        "api": "directory_service.unlock_account",
        "account": target,
        "was_locked": was_locked,
        "status": "UNLOCKED",
        "timestamp": _now(),
    }


def quarantine_process(target: str, params: dict) -> dict:
    time.sleep(0.05)
    _quarantined_processes.add(target)
    return {
        "simulated": True,
        "api": "endpoint_agent.quarantine_process",
        "process": target,
        "params": params,
        "status": "QUARANTINED",
        "timestamp": _now(),
    }


def terminate_process(target: str, params: dict) -> dict:
    """Simulates forceful process termination (e.g. kill -9 on a malicious PID)."""
    time.sleep(0.05)
    _terminated_processes.add(target)
    return {
        "simulated": True,
        "api": "endpoint_agent.terminate_process",
        "process": target,
        "params": params,
        "status": "TERMINATED",
        "timestamp": _now(),
    }


def restore_process(target: str) -> dict:
    """Rollback for terminate_process — marks the process as cleared for restart."""
    time.sleep(0.05)
    was_terminated = target in _terminated_processes
    _terminated_processes.discard(target)
    return {
        "simulated": True,
        "api": "endpoint_agent.restore_process",
        "process": target,
        "was_terminated": was_terminated,
        "status": "RESTORED",
        "timestamp": _now(),
    }


def block_proxy_ip(target: str, params: dict) -> dict:
    """Simulates blocking a proxy transit IP at the network edge."""
    time.sleep(0.05)
    _blocked_proxy_ips.add(target)
    return {
        "simulated": True,
        "api": "proxy_gateway.block_ip",
        "ip": target,
        "params": params,
        "status": "BLOCKED",
        "timestamp": _now(),
    }


def unblock_proxy_ip(target: str) -> dict:
    """Rollback for block_proxy_ip — removes the IP from the proxy block list."""
    time.sleep(0.05)
    was_blocked = target in _blocked_proxy_ips
    _blocked_proxy_ips.discard(target)
    return {
        "simulated": True,
        "api": "proxy_gateway.unblock_ip",
        "ip": target,
        "was_blocked": was_blocked,
        "status": "UNBLOCKED",
        "timestamp": _now(),
    }
