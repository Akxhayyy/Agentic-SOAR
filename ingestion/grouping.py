"""
ingestion/grouping.py

Stage 2 of the hybrid pre-screening pipeline — only runs on lines that
already passed the cheap filter (ingestion/cheap_filter.py).

Why grouping matters for THIS system specifically: agents/forensics.py
matches against playbooks like config/playbooks/brute_force_auth.md,
which describes multi-event patterns ("5+ failed attempts... followed by
a successful login"). If every suspicious line became its own incident,
the Triage agent would only ever see one isolated failure at a time and
could never recognize the burst pattern the playbook is written to detect.
Grouping reconstructs that context before it ever reaches the LLM.

Grouping key: (extracted_ip OR extracted_user) — whichever is present.
If a line has neither, it becomes its own single-line group rather than
being dropped; we never silently discard a flagged line.

Time window: lines are grouped together only if they fall within
GROUP_WINDOW_SECONDS of each other for the same key. This mirrors the
"burst" framing in the playbook and avoids merging unrelated incidents
that happen to share an IP but occurred hours apart (e.g. an IP that
shows up sporadically over a workweek isn't one incident).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from ingestion.cheap_filter import ParsedLogLine

GROUP_WINDOW_SECONDS = 300  # 5 minutes — matches forensics pass_2 window in hitl_config.yaml
_HOST_RE = re.compile(r"\bhost=([A-Za-z0-9][A-Za-z0-9_.\-]{0,62})")


@dataclass
class IncidentGroup:
    group_key: str           # e.g. "ip:10.0.4.17" or "user:svc-backup" or "single:<n>"
    lines: list[ParsedLogLine] = field(default_factory=list)

    @property
    def combined_text(self) -> str:
        """
        Concatenated text handed to the Triage agent as ONE log blob — this
        is what lets Qwen see "14 failures then a success" as one pattern
        instead of 14 isolated, context-free events.
        """
        return "\n".join(
            f"[{l.log_type}] {l.raw_text}" for l in self.lines
        )

    @property
    def primary_log_type(self) -> str:
        # Most common log_type in the group; falls back to the first line's type.
        if not self.lines:
            return "GENERIC"
        types = [l.log_type for l in self.lines]
        return max(set(types), key=types.count)


def group_suspicious_entries(
    suspicious_lines: list[ParsedLogLine],
    window_seconds: int = GROUP_WINDOW_SECONDS,
    all_lines: list[ParsedLogLine] | None = None,
) -> list[IncidentGroup]:
    """
    Groups suspicious lines by shared IP or username within a sliding time
    window. Lines without a usable timestamp are grouped purely by key
    (IP/user) with no time constraint — better to over-group an untimed
    line than silently drop it from analysis.

    all_lines (optional): if provided, this is the FULL parsed line set
    (suspicious + benign) for the file. When present, after grouping by key
    and time window, each group additionally absorbs any later
    is_success_login=True line from all_lines that shares the same key and
    falls within window_seconds of the group's last suspicious line.

    Why this matters: config/playbooks/brute_force_auth.md specifically
    keys on "a burst of failures followed by a successful login" — but a
    lone successful login never trips any rule in cheap_filter.py's
    suspicion patterns on its own (correctly so; a successful login is not
    inherently suspicious). Without pulling it in here, the Triage agent
    would only ever see the failure burst and never the pattern the
    playbook actually matches against, weakening forensics confidence
    relative to a hand-written incident covering the same scenario.
    """
    # Bucket first by key, preserving file order.
    by_key: dict[str, list[ParsedLogLine]] = {}
    ungrouped_counter = 0

    for line in suspicious_lines:
        host = _HOST_RE.search(line.raw_text)
        if line.extracted_ip:
            key = f"ip:{line.extracted_ip}"
        elif line.extracted_user:
            key = f"user:{line.extracted_user}"
        elif host:
            # Endpoint telemetry (Sysmon/EDR) often has neither IP nor user on a
            # line; without this, one attack on one host became hundreds of
            # single-line incidents (found on the OTRF public recordings).
            key = f"host:{host.group(1).lower()}"
        else:
            ungrouped_counter += 1
            key = f"single:{ungrouped_counter}"
        by_key.setdefault(key, []).append(line)

    groups: list[IncidentGroup] = []

    for key, lines in by_key.items():
        # Within a key, further split by time window if timestamps exist.
        timed = [l for l in lines if l.timestamp is not None]
        untimed = [l for l in lines if l.timestamp is None]

        if not timed:
            # No timestamps to split on — keep them as one group for this key.
            groups.append(IncidentGroup(group_key=key, lines=lines))
            continue

        timed.sort(key=lambda l: l.timestamp)
        current_group: list[ParsedLogLine] = [timed[0]]
        window = timedelta(seconds=window_seconds)

        for prev, curr in zip(timed, timed[1:]):
            if curr.timestamp - prev.timestamp <= window:
                current_group.append(curr)
            else:
                groups.append(IncidentGroup(group_key=key, lines=current_group))
                current_group = [curr]
        groups.append(IncidentGroup(group_key=key, lines=current_group))

        if untimed:
            # Attach untimed lines from the same key to the largest group
            # for that key, rather than spinning up yet another fragment.
            groups[-1].lines.extend(untimed)

    if all_lines:
        _absorb_success_context(groups, all_lines, window_seconds)

    return groups


def _absorb_success_context(
    groups: list[IncidentGroup],
    all_lines: list[ParsedLogLine],
    window_seconds: int,
) -> None:
    """
    Mutates groups in place: for each group, finds the matching key in
    all_lines and pulls in any is_success_login=True line that shares the
    group's key and falls within window_seconds after the group's last
    timestamped line. This is the only place a non-suspicious line can
    enter a group — deliberately narrow (same key + tight window + must be
    a recognized success-login pattern) so it can't be used to smuggle
    arbitrary benign noise into an incident.
    """
    window = timedelta(seconds=window_seconds)

    for group in groups:
        timed_in_group = [l for l in group.lines if l.timestamp is not None]
        if not timed_in_group:
            continue
        last_ts = max(l.timestamp for l in timed_in_group)

        # Determine which raw value (ip or user) this group's key refers to.
        if group.group_key.startswith("ip:"):
            key_value = group.group_key[len("ip:"):]
            key_field = "extracted_ip"
        elif group.group_key.startswith("user:"):
            key_value = group.group_key[len("user:"):]
            key_field = "extracted_user"
        else:
            continue  # "single:" groups have no shared key to match against

        for line in all_lines:
            if not line.is_success_login or line in group.lines:
                continue
            if getattr(line, key_field) != key_value:
                continue
            if line.timestamp is None:
                continue
            if last_ts <= line.timestamp <= last_ts + window:
                group.lines.append(line)
