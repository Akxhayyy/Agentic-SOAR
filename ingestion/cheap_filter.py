"""
ingestion/cheap_filter.py

Stage 1 of the hybrid pre-screening pipeline. Pure deterministic
pattern-matching, ZERO LLM calls, runs over an entire log file instantly.

This is intentionally simple and intentionally over-inclusive: false
positives here just mean a line gets passed on to Qwen (mildly wasteful but
harmless); false negatives mean a real attack never reaches the AI at all
(actually dangerous). So every rule below is written to err toward flagging
too much rather than too little — the expensive, more accurate judgment
happens downstream in the Triage agent, not here.

This is NOT a replacement for proper SIEM correlation rules in a real
deployment — it's a cheap gate sized for a demo/capsule context. Treat the
keyword lists as a starting point you'll want to expand for your actual
log sources and threat model.
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass
from datetime import datetime


def safe_decode(data: bytes, encoding: str = "utf-8") -> str:
    """Safely decodes raw byte streams, replacing malformed binary tokens."""
    try:
        return data.decode(encoding, errors="replace")
    except Exception:
        try:
            return data.decode(encoding, errors="ignore")
        except Exception:
            return data.decode("latin-1", errors="replace")


@dataclass
class ParsedLogLine:
    raw_text: str
    log_type: str
    source: str
    timestamp: datetime | None
    extracted_ip: str | None
    extracted_user: str | None
    is_suspicious: bool
    match_reason: str | None
    is_success_login: bool = False


# --- Suspicion rules ---------------------------------------------------
# Each rule is (compiled_regex, reason_label). Case-insensitive throughout.

_SUSPICIOUS_PATTERNS: list[tuple[re.Pattern, str]] = [
    # --- Authentication issues ---
    (re.compile(r"failed login", re.I), "failed_login"),
    (re.compile(r"authentication failure", re.I), "auth_failure"),
    (re.compile(r"invalid (user|password)", re.I), "invalid_credential"),
    (re.compile(r"account locked|account disabled", re.I), "account_lockout_event"),
    (re.compile(r"multiple failed attempts", re.I), "brute_force_phrase"),
    # --- Privilege escalation ---
    (re.compile(r"\bsudo\b", re.I), "privilege_escalation_attempt"),
    (re.compile(r"chmod\s+777", re.I), "permission_widening"),
    (re.compile(r"chmod\s*\+x", re.I), "executable_permission_grant"),
    # --- Reconnaissance / scanning ---
    (re.compile(r"\bnmap\b|port\s*scan", re.I), "scanning_tool"),
    (re.compile(r"\bmasscan\b", re.I), "mass_scanning_tool"),
    # --- Remote fetch ---
    (re.compile(r"\b(wget|curl)\b.*https?://", re.I), "remote_fetch"),
    # --- Obfuscation / payloads ---
    (re.compile(r"base64\s*-d|base64\s*--decode", re.I), "obfuscated_payload"),
    (re.compile(r"\bpowershell\b.*-enc(odedcommand)?", re.I), "obfuscated_powershell"),
    (re.compile(r"reverse shell|/bin/sh -i|nc -e", re.I), "reverse_shell_indicator"),
    # --- Data exfiltration ---
    (re.compile(r"\bscp\b.*@", re.I), "data_exfiltration_scp"),
    (re.compile(r"\brsync\b.*@", re.I), "data_exfiltration_rsync"),
    (re.compile(r"\bftp\b.*\bput\b", re.I), "data_exfiltration_ftp"),
    (re.compile(r"bulk\s*(download|export|transfer|copy)", re.I), "bulk_data_transfer"),
    (re.compile(r"exfiltrat", re.I), "explicit_exfiltration_keyword"),
    # --- Proxy anomaly ---
    (re.compile(r"CONNECT\s+\d", re.I), "proxy_connect_tunnel"),
    (re.compile(r"proxy\s*bypass", re.I), "proxy_bypass_attempt"),
    (re.compile(r"\btunnel(ing|ed)?\b.*\b(proxy|socks|http)\b", re.I), "proxy_tunnel_indicator"),
    (re.compile(r"X-Forwarded-For.*spoof", re.I), "forwarded_header_spoofing"),
    # --- General malicious keywords ---
    (re.compile(r"unauthorized access", re.I), "unauthorized_access"),
    (re.compile(r"malware|trojan|ransomware", re.I), "explicit_threat_keyword"),
]

_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USER_PATTERN = re.compile(r"\buser[:\s]+([\w.\-@]+)", re.I)

# Common timestamp formats seen in auth/proxy/syslog exports. Extend as needed.
_TIMESTAMP_PATTERNS = [
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%b %d %H:%M:%S",  # syslog style, e.g. "Jun 22 15:54:00"
]


def _try_parse_timestamp(text: str) -> datetime | None:
    # Look for an ISO-ish or syslog-ish timestamp token at the start of the line.
    candidate = text[:32].strip()
    # Try ISO format
    try:
        val = candidate.replace("Z", "+00:00")
        return datetime.fromisoformat(val)
    except ValueError:
        pass
    for fmt in _TIMESTAMP_PATTERNS:
        for token_len in (19, 15):
            try:
                return datetime.strptime(candidate[:token_len].strip(), fmt)
            except ValueError:
                continue
    return None


_SUCCESS_LOGIN_PATTERN = re.compile(r"successful login|login succeeded|authentication succeeded", re.I)


def parse_log_file(
    file_text: str, 
    default_log_type: str = "GENERIC", 
    delimiter: str | None = None
) -> list[ParsedLogLine]:
    """
    Splits raw multi-line log text into individual ParsedLogLine records.
    Automatically discovers layout structure (JSON lines or CSV) if present,
    supporting custom delimiter options, and falls back to unstructured line parsing.
    """
    lines = [l.strip() for l in file_text.splitlines() if l.strip()]
    if not lines:
        return []

    parsed: list[ParsedLogLine] = []

    # Check for custom delimiter override
    use_delim = None
    if delimiter and delimiter != "None":
        use_delim = delimiter

    # 1. Detect JSON-Lines (JSONL)
    is_jsonl = False
    if not use_delim:
        try:
            if lines[0].startswith("{") and lines[0].endswith("}"):
                json.loads(lines[0])
                is_jsonl = True
        except Exception:
            pass

    if is_jsonl:
        for line in lines:
            try:
                data = json.loads(line)
                # Find message/raw text or format dictionary
                msg_val = None
                for k in ["message", "msg", "log", "raw_text", "text", "event"]:
                    if k in data:
                        msg_val = str(data[k])
                        break
                if not msg_val:
                    msg_val = json.dumps(data)

                # Extract IP
                extracted_ip = None
                for k in ["ip", "src_ip", "dst_ip", "source_ip", "host", "hostname", "src"]:
                    if k in data and re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", str(data[k])):
                        extracted_ip = str(data[k])
                        break
                if not extracted_ip:
                    ip_match = _IP_PATTERN.search(msg_val)
                    if ip_match:
                        extracted_ip = ip_match.group(0)

                # Extract user
                extracted_user = None
                for k in ["user", "username", "account", "login"]:
                    if k in data:
                        extracted_user = str(data[k])
                        break
                if not extracted_user:
                    user_match = _USER_PATTERN.search(msg_val)
                    if user_match:
                        extracted_user = user_match.group(1)

                # Extract timestamp
                timestamp = None
                for k in ["timestamp", "time", "date"]:
                    if k in data:
                        timestamp = _try_parse_timestamp(str(data[k]))
                        if timestamp:
                            break
                if not timestamp:
                    timestamp = _try_parse_timestamp(line)

                # Determine suspicion
                is_suspicious = False
                reason = None
                for pattern, label in _SUSPICIOUS_PATTERNS:
                    if pattern.search(msg_val):
                        is_suspicious = True
                        reason = label
                        break

                parsed.append(
                    ParsedLogLine(
                        raw_text=msg_val[:1024],
                        log_type="JSON_LOG",
                        source="batch_upload",
                        timestamp=timestamp,
                        extracted_ip=extracted_ip,
                        extracted_user=extracted_user,
                        is_suspicious=is_suspicious,
                        match_reason=reason,
                        is_success_login=bool(_SUCCESS_LOGIN_PATTERN.search(msg_val)),
                    )
                )
            except Exception:
                parsed.append(_parse_single_raw_line(line, default_log_type))
        return parsed

    # 2. Detect CSV
    is_csv = False
    if use_delim:
        is_csv = True
    elif len(lines) > 1:
        first_line = lines[0]
        header_keywords = {"ip", "host", "user", "username", "message", "log", "timestamp", "event", "time", "src", "dst", "action"}
        try:
            reader = csv.reader(io.StringIO(first_line))
            row = next(reader)
            if len(row) > 1:
                if any(any(kw in field.lower() for kw in header_keywords) for field in row):
                    is_csv = True
                    use_delim = ","
        except Exception:
            pass

    if is_csv:
        delim_char = use_delim if use_delim else ","
        f = io.StringIO(file_text)
        reader = csv.DictReader(f, delimiter=delim_char)
        for row in reader:
            row_str = ", ".join(f"{k}={v}" for k, v in row.items())

            # Extract IP
            extracted_ip = None
            for k in row:
                k_lower = k.lower()
                if any(ip_kw in k_lower for ip_kw in ["ip", "host", "src", "dst"]):
                    val = str(row[k])
                    if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", val):
                        extracted_ip = val
                        break
            if not extracted_ip:
                ip_match = _IP_PATTERN.search(row_str)
                if ip_match:
                    extracted_ip = ip_match.group(0)

            # Extract User
            extracted_user = None
            for k in row:
                k_lower = k.lower()
                if any(u_kw in k_lower for u_kw in ["user", "username", "account", "login"]):
                    extracted_user = str(row[k])
                    break
            if not extracted_user:
                user_match = _USER_PATTERN.search(row_str)
                if user_match:
                    extracted_user = user_match.group(1)

            # Extract Timestamp
            timestamp = None
            for k in row:
                k_lower = k.lower()
                if any(ts_kw in k_lower for ts_kw in ["time", "date", "timestamp"]):
                    timestamp = _try_parse_timestamp(str(row[k]))
                    if timestamp:
                        break
            if not timestamp:
                timestamp = _try_parse_timestamp(row_str)

            # Determine suspicion
            is_suspicious = False
            reason = None
            for pattern, label in _SUSPICIOUS_PATTERNS:
                if pattern.search(row_str):
                    is_suspicious = True
                    reason = label
                    break

            parsed.append(
                ParsedLogLine(
                    raw_text=row_str[:1024],
                    log_type="CSV_LOG",
                    source="batch_upload",
                    timestamp=timestamp,
                    extracted_ip=extracted_ip,
                    extracted_user=extracted_user,
                    is_suspicious=is_suspicious,
                    match_reason=reason,
                    is_success_login=bool(_SUCCESS_LOGIN_PATTERN.search(row_str)),
                )
            )
        return parsed

    # 3. Fallback: Raw Unstructured Text (standard behavior)
    for line in lines:
        parsed.append(_parse_single_raw_line(line, default_log_type))

    return parsed


def _parse_single_raw_line(line: str, default_log_type: str) -> ParsedLogLine:
    prefix_re = re.compile(r"^\[([A-Za-z0-9_]+)\]\s*(.*)$")
    log_type = default_log_type
    message = line
    m = prefix_re.match(line)
    if m:
        log_type = m.group(1).upper()
        message = m.group(2)

    ip_match = _IP_PATTERN.search(message)
    user_match = _USER_PATTERN.search(message)

    is_suspicious = False
    reason = None
    for pattern, label in _SUSPICIOUS_PATTERNS:
        if pattern.search(message):
            is_suspicious = True
            reason = label
            break

    return ParsedLogLine(
        raw_text=message[:1024],
        log_type=log_type[:32],
        source="batch_upload",
        timestamp=_try_parse_timestamp(line),
        extracted_ip=ip_match.group(0) if ip_match else None,
        extracted_user=user_match.group(1) if user_match else None,
        is_suspicious=is_suspicious,
        match_reason=reason,
        is_success_login=bool(_SUCCESS_LOGIN_PATTERN.search(message)),
    )


def filter_suspicious(lines: list[ParsedLogLine]) -> list[ParsedLogLine]:
    """Returns only the lines the cheap filter flagged as worth Qwen's time."""
    return [l for l in lines if l.is_suspicious]
