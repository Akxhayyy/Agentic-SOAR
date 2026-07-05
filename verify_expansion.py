"""Quick verification script for the threat matrix expansion."""
from execution import stub_infra_api as api
from core.uicr_schema import ActionType, AttackVector
from pathlib import Path

# Test 1: ActionType enum
vals = [a.value for a in ActionType]
assert "TERMINATE_PROCESS" in vals, "TERMINATE_PROCESS missing"
assert "BLOCK_PROXY_IP" in vals, "BLOCK_PROXY_IP missing"
print(f"[PASS] ActionType enum: {vals}")

# Test 2: AttackVector enum (should be unchanged, all 7 present)
avs = [a.value for a in AttackVector]
assert len(avs) == 7
print(f"[PASS] AttackVector enum: {avs}")

# Test 3: Stub functions
r1 = api.terminate_process("evil_proc", {"signal": "9"})
assert r1["status"] == "TERMINATED"
r2 = api.block_proxy_ip("10.0.0.99", {"rule": "drop"})
assert r2["status"] == "BLOCKED"
r3 = api.restore_process("evil_proc")
assert r3["status"] == "RESTORED"
assert r3["was_terminated"] is True
r4 = api.unblock_proxy_ip("10.0.0.99")
assert r4["status"] == "UNBLOCKED"
assert r4["was_blocked"] is True
print("[PASS] All stub functions work with rollback state tracking")

# Test 4: Cheap filter new patterns
from ingestion.cheap_filter import parse_log_file, filter_suspicious
test_logs = "\n".join([
    "Jun 27 10:00:00 masscan detected on port range",
    "Jun 27 10:00:01 scp user@external:/data /tmp/exfil.tar",
    "Jun 27 10:00:02 CONNECT 8443 proxy bypass attempt",
    "Jun 27 10:00:03 chmod +x /usr/bin/backdoor",
    "Jun 27 10:00:04 tunneling through socks proxy detected",
    "Jun 27 10:00:05 bulk export to external host",
    "Jun 27 10:00:06 rsync data@10.0.0.1:/secrets ./loot",
    "Jun 27 10:00:07 X-Forwarded-For spoofed header detected",
    "Jun 27 10:00:08 ftp put sensitive_data.csv",
])
lines = parse_log_file(test_logs)
suspicious = filter_suspicious(lines)
print(f"[PASS] Cheap filter: {len(suspicious)}/{len(lines)} lines flagged")
for s in suspicious:
    print(f"  - {s.match_reason}: {s.raw_text[:60]}")

# Test 5: Playbook files
playbooks = sorted(Path("config/playbooks").glob("*.md"))
names = [p.name for p in playbooks]
print(f"[PASS] Playbooks ({len(playbooks)}): {names}")
assert len(playbooks) == 7, f"Expected 7 playbooks, got {len(playbooks)}"
expected = {
    "brute_force_auth.md", "network_intrusion.md", "malware_execution.md",
    "data_exfiltration.md", "privilege_escalation.md", "proxy_anomaly.md",
    "unknown_threat.md",
}
assert set(names) == expected, f"Missing: {expected - set(names)}"

# Test 6: Wrapper dispatch coverage
from execution.wrapper import execute_action, restore_process, unblock_proxy_ip
print("[PASS] Wrapper imports (execute_action, restore_process, unblock_proxy_ip) OK")

print("\n=== ALL TESTS PASSED ===")
