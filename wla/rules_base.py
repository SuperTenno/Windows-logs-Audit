"""检测规则的公共基础设施。"""

from __future__ import annotations

import datetime as dt
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

from .models import DT_MIN, Event, Finding, Severity, fmt_time, ip_kind


@dataclass
class RuleOptions:
    """影响规则灵敏度与报告输出的参数。"""

    brute_threshold: int = 5
    brute_window_minutes: int = 10
    compromise_window_minutes: int = 60
    spray_distinct_users: int = 5
    enumeration_threshold: int = 30
    max_evidence: int = 8
    since: Optional[dt.datetime] = None
    min_severity: Severity = Severity.INFO
    rdp_external_only: bool = True


def event_sort_key(event: Event) -> tuple:
    return (event.time or DT_MIN, event.record_id or 0)


class RuleContext:
    """保存事件索引与本次检测累积的发现。"""

    def __init__(
        self,
        events: Iterable[Event],
        options: Optional[RuleOptions] = None,
        posture: Optional[dict] = None,
    ):
        self.events: list[Event] = list(events)
        self.options = options or RuleOptions()
        self.posture = posture or {}
        self.findings: list[Finding] = []
        self.by_id: dict[int, list[Event]] = defaultdict(list)
        self.by_log: dict[str, list[Event]] = defaultdict(list)
        self.notes: list[str] = []
        for event in self.events:
            self.by_id[event.event_id].append(event)
            self.by_log[event.log].append(event)
        for bucket in list(self.by_id.values()) + list(self.by_log.values()):
            bucket.sort(key=event_sort_key)

    def get(self, event_id: int) -> list[Event]:
        return self.by_id.get(event_id, [])

    def log(self, log_key: str) -> list[Event]:
        return self.by_log.get(log_key, [])

    def add(self, finding: Finding) -> Finding:
        if finding.first_seen is None or finding.last_seen is None:
            times = [e.time for e in finding.events if e.time]
            if times:
                finding.first_seen = finding.first_seen or min(times)
                finding.last_seen = finding.last_seen or max(times)
        self.findings.append(finding)
        return finding

    def note(self, text: str) -> None:
        if text and text not in self.notes:
            self.notes.append(text)


def make_finding(
    rule_id: str,
    title: str,
    severity: Severity,
    *,
    tactic: str = "",
    technique: str = "",
    description: str = "",
    recommendation: str = "",
    entities: Optional[dict] = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        tactic=tactic,
        technique=technique,
        description=description,
        recommendation=recommendation,
        entities=entities or {},
    )


def peak_in_window(times: Iterable[Optional[dt.datetime]], minutes: int) -> int:
    """滑动窗口内的最大事件数。"""
    ordered = sorted(t for t in times if t is not None)
    if not ordered:
        return 0
    window = dt.timedelta(minutes=max(1, minutes))
    best = 0
    start = 0
    for end, current in enumerate(ordered):
        while current - ordered[start] > window:
            start += 1
        best = max(best, end - start + 1)
    return best


def top_counter(
    events: Iterable[Event], getter: Callable[[Event], str], limit: int = 10
) -> list[tuple[str, int]]:
    counter = Counter()
    for event in events:
        value = (getter(event) or "").strip()
        if value and value != "-":
            counter[value] += 1
    return counter.most_common(limit)


def evidence_lines(
    events: Iterable[Event],
    fields: tuple[str, ...] = (),
    limit: int = 8,
) -> list[str]:
    """把事件格式化为可读的证据行，去重并限制数量。"""
    lines: list[str] = []
    for event in events:
        text = fmt_time(event.time) + f"  EventID={event.event_id}"
        details = []
        for name in fields:
            value = event.get(name)
            if value:
                details.append(f"{name}={value}")
        if details:
            text += " | " + "; ".join(details)
        if event.message and not details:
            text += " | " + event.message[:160]
        if text not in lines:
            lines.append(text)
        if len(lines) >= limit:
            break
    return lines


def command_line(event: Event) -> str:
    return event.get("CommandLine", "ProcessCommandLine", "Command")


def process_name(event: Event) -> str:
    return event.get("NewProcessName", "Image", "ProcessName", "ProcessPath")


def parent_name(event: Event) -> str:
    return event.get("ParentProcessName", "ParentImage", "ParentProcessPath")


def basename(path: str) -> str:
    text = (path or "").strip().strip('"').strip("'").replace("/", "\\")
    return text.rsplit("\\", 1)[-1].lower()


def is_public_ip(value: str) -> bool:
    return ip_kind(value) == "public"


def severity_by_count(
    count: int, medium: int, high: int, critical: int = 0
) -> Severity:
    if critical and count >= critical:
        return Severity.CRITICAL
    if count >= high:
        return Severity.HIGH
    if count >= medium:
        return Severity.MEDIUM
    return Severity.LOW


_TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")
