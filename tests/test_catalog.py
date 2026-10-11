"""Static catalog checks ported from the old verify_expansion.py / comprehensive_audit.py scripts."""

from __future__ import annotations

import pytest

from core.graph_config import PROJECT_ROOT, load_config
from core.uicr_schema import ActionType, AttackVector, IOCType

PLAYBOOKS = {
    "brute_force_auth.md", "network_intrusion.md", "malware_execution.md", "data_exfiltration.md",
    "privilege_escalation.md", "proxy_anomaly.md", "unknown_threat.md",
}


def test_closed_vocabularies():
    assert len(AttackVector) == 7
    assert {"TERMINATE_PROCESS", "BLOCK_PROXY_IP", "NO_ACTION"} <= {a.value for a in ActionType}
    assert len(IOCType) == 6


def test_playbooks_present_and_sectioned():
    found = {p.name: p for p in (PROJECT_ROOT / "config" / "playbooks").glob("*.md")}
    assert set(found) == PLAYBOOKS
    for p in found.values():
        text = p.read_text(encoding="utf-8")
        assert text.startswith("# ") and "## " in text


def test_config_safe_defaults():
    cfg = load_config()
    assert cfg["forensics"]["similarity_hard_threshold"] == 0.70
    assert cfg["forensics"]["pass_2"]["similarity_floor"] < cfg["forensics"]["similarity_hard_threshold"]
    assert all(cfg["security"].values())
    assert "127.0.0.1" in cfg["execution"]["protected_targets"]
    assert set(cfg["mitre"]["allowed_techniques"]) >= {"T1110", "T1059", "T1041", "T1068", "T1046", "T1090"}


def test_shipped_config_is_dry_run():
    import yaml

    raw = yaml.safe_load((PROJECT_ROOT / "config" / "hitl_config.yaml").read_text(encoding="utf-8"))
    assert raw["execution"]["dry_run"] is True


def test_stub_api_rollback_state_tracking():
    from execution import stub_infra_api as api

    assert api.terminate_process("evil_proc", {"signal": "9"})["status"] == "TERMINATED"
    assert api.restore_process("evil_proc")["was_terminated"] is True
    assert api.block_proxy_ip("10.0.0.99", {})["status"] == "BLOCKED"
    assert api.unblock_proxy_ip("10.0.0.99")["was_blocked"] is True


def test_stub_and_real_apis_share_signatures():
    import inspect

    from execution import real_infra_api, stub_infra_api

    for name in ("isolate_host", "remove_host_isolation", "lock_account", "unlock_account",
                 "quarantine_process", "terminate_process", "restore_process",
                 "block_proxy_ip", "unblock_proxy_ip"):
        assert inspect.signature(getattr(stub_infra_api, name)) == inspect.signature(getattr(real_infra_api, name))


@pytest.mark.parametrize("line,reason", [
    ("Jun 27 10:00:00 masscan detected on port range", "mass_scanning_tool"),
    ("Jun 27 10:00:01 scp user@external:/data /tmp/exfil.tar", "data_exfiltration_scp"),
    ("Jun 27 10:00:02 CONNECT 8443 proxy bypass attempt", "proxy_connect_tunnel"),
    ("Jun 27 10:00:03 chmod +x /usr/bin/backdoor", "executable_permission_grant"),
    ("Jun 27 10:00:06 rsync data@10.0.0.1:/secrets ./loot", "data_exfiltration_rsync"),
    ("Jun 27 10:00:08 ftp put sensitive_data.csv", "data_exfiltration_ftp"),
    ("powershell -enc SQBFAFgA", "obfuscated_powershell"),
])
def test_cheap_filter_patterns(line, reason):
    from ingestion.cheap_filter import parse_log_file

    parsed = parse_log_file(line)[0]
    assert parsed.is_suspicious and parsed.match_reason == reason


@pytest.mark.parametrize("payload", [
    "'; DROP TABLE incidents; --",
    "admin$(whoami)",
    "../../etc/passwd",
    "ad‮min",
    "a" * 300,
])
def test_adversarial_ioc_values_rejected(payload):
    from pydantic import ValidationError

    from core.uicr_schema import IOC

    with pytest.raises(ValidationError):
        IOC(ioc_type="USERNAME", value=payload, confidence=1.0)
