"""数据模型：事件、发现（Finding）、审计报告。

时间统一使用带时区的 UTC ``datetime``，展示时再转换到分析者本地时区，
避免跨时区取证时的时间错位。
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import math
import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Iterable, Optional

from . import __version__

UTC = dt.timezone.utc
DT_MIN = dt.datetime.min.replace(tzinfo=UTC)

# ATT&CK 战术的展示顺序（也是攻击链的自然顺序）
TACTIC_ORDER = (
    "初始访问",
    "执行",
    "持久化",
    "权限提升",
    "防御规避",
    "凭据访问",
    "发现",
    "横向移动",
    "外带",
    "影响",
    "加固配置",
)

_SEVERITY_LABEL = {
    0: "信息",
    1: "低危",
    2: "中危",
    3: "高危",
    4: "严重",
}
_SEVERITY_COLOR = {
    0: "6B7280",
    1: "3B82F6",
    2: "D97706",
    3: "EA580C",
    4: "DC2626",
}
_SEVERITY_WEIGHT = {
    0: 0.5,
    1: 1.5,
    2: 5.0,
    3: 14.0,
    4: 30.0,
}


class Severity(IntEnum):
    """告警严重级别。"""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return _SEVERITY_LABEL[int(self)]

    @property
    def color(self) -> str:
        return _SEVERITY_COLOR[int(self)]

    @property
    def weight(self) -> float:
        return _SEVERITY_WEIGHT[int(self)]

    @classmethod
    def parse(cls, value: Any) -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, (int, float)):
            return cls(max(0, min(4, int(value))))
        text = str(value or "").strip().lower()
        aliases = {
            "info": cls.INFO,
            "informational": cls.INFO,
            "信息": cls.INFO,
            "low": cls.LOW,
            "低危": cls.LOW,
            "medium": cls.MEDIUM,
            "中危": cls.MEDIUM,
            "high": cls.HIGH,
            "高危": cls.HIGH,
            "critical": cls.CRITICAL,
            "严重": cls.CRITICAL,
        }
        return aliases.get(text, cls.INFO)


def fmt_time(value: Optional[dt.datetime], fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """把 UTC 时间格式化为分析者本地时间。"""
    if not value:
        return "-"
    try:
        return value.astimezone().strftime(fmt)
    except (ValueError, OSError):
        return value.strftime(fmt)


def parse_duration_minutes(text: str) -> int:
    """解析 ``30m`` / ``2h`` / ``7d`` 形式的时长，返回分钟数。"""
    match = _DURATION_RE.match((text or "").strip())
    if not match:
        return 0
    value = float(match.group(1))
    unit = match.group(2).lower()
    factor = {"m": 1, "h": 60, "d": 1440}.get(unit, 1)
    return max(1, int(value * factor))



_DURATION_RE = re.compile(r"^(\d+(?:\.\d+)?)\s*([mhd])$", re.I)


_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "fc00::/7",
    )
)
# 文档/测试网段（TEST-NET）绝对不是内网资产，演示与测试中按公网处理
_DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "2001:db8::/32",
    )
)


def ip_kind(value: Any) -> str:
    """判断 IP 类型：public / private / loopback / linklocal / other / unknown。"""
    text = str(value or "").strip().strip("[]")
    if not text or text in {"-", "::", "0.0.0.0"}:
        return "unknown"
    text = text.split("%", 1)[0]
    if text.lower().startswith("::ffff:"):
        text = text[7:]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return "unknown"
    if any(ip in network for network in _DOCUMENTATION_NETWORKS):
        return "public"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "linklocal"
    if any(ip in network for network in _PRIVATE_NETWORKS):
        return "private"
    if ip.is_unspecified or ip.is_multicast or ip.is_reserved:
        return "other"
    return "public"


def is_external_ip(value: Any) -> bool:
    """是否为公网 IP（排除内网、回环、链路本地与无法解析的机器名）。"""
    return ip_kind(value) == "public"


@dataclass
class Event:
    """一条已解析的 Windows 事件。

    ``data`` 来自 EventData 或 UserData（名称 -> 文本），保留原始字段名，
    便于不同 Windows 版本 / 语言之间做兼容取值。
    """

    log: str
    event_id: int
    time: Optional[dt.datetime] = None
    data: dict[str, str] = field(default_factory=dict)
    record_id: Optional[int] = None
    provider: str = ""
    computer: str = ""
    level: Optional[int] = None
    channel: str = ""
    message: str = ""

    # ---- 通用字段取值 ----
    def get(self, *names: str, default: str = "") -> str:
        for name in names:
            value = self.data.get(name)
            if value is None:
                continue
            value = str(value).strip()
            if value and value != "-":
                return value
        return default

    def get_int(self, *names: str, default: Optional[int] = None) -> Optional[int]:
        value = self.get(*names)
        if not value:
            return default
        try:
            return int(value, 0)
        except (TypeError, ValueError):
            return default

    # ---- 语义化快捷属性 ----
    @property
    def actor(self) -> str:
        return self.get("SubjectUserName", "SubjectUserSid", "UserID")

    @property
    def target(self) -> str:
        return self.get(
            "TargetUserName",
            "User",
            "NewTargetUserName",
            "MemberName",
            "AccountName",
            "ObjectName",
        )

    @property
    def ip(self) -> str:
        return self.get(
            "IpAddress",
            "Address",
            "ClientAddress",
            "RemoteAddress",
            "SourceIp",
            "SourceAddress",
        )

    @property
    def logon_type(self) -> str:
        return self.get("LogonType", "LogonTypeId")

    @property
    def workstation(self) -> str:
        return self.get("WorkstationName", "Workstation", "ClientName")

    @property
    def is_machine_account(self) -> bool:
        user = self.target
        return user.endswith("$") or user.upper() in {
            "SYSTEM",
            "LOCAL SERVICE",
            "NETWORK SERVICE",
            "ANONYMOUS LOGON",
        }

    def brief(self, limit: int = 160) -> str:
        parts = [fmt_time(self.time), f"[{self.log}] {self.event_id}"]
        if self.provider:
            parts.append(self.provider)
        extra = []
        for key in (
            "TargetUserName",
            "SubjectUserName",
            "IpAddress",
            "Address",
            "LogonType",
            "ServiceName",
            "TaskName",
            "NewProcessName",
            "CommandLine",
        ):
            value = self.data.get(key)
            if value:
                extra.append(f"{key}={value}")
        text = " ".join(parts)
        if extra:
            text += " | " + "; ".join(extra)
        return text[:limit]


@dataclass
class Finding:
    """一条检测结论，对应报告中一个可追溯的风险项。"""

    rule_id: str
    title: str
    severity: Severity
    tactic: str = ""
    technique: str = ""
    description: str = ""
    recommendation: str = ""
    count: int = 1
    first_seen: Optional[dt.datetime] = None
    last_seen: Optional[dt.datetime] = None
    entities: dict[str, str] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    key: str = ""

    def add_evidence(self, text: str, limit: int = 12) -> None:
        text = (text or "").strip()
        if not text or len(self.evidence) >= limit:
            return
        if text not in self.evidence:
            self.evidence.append(text)

    def add_event(self, event: Event, limit: int = 40) -> None:
        if len(self.events) < limit:
            self.events.append(event)
        if event.time:
            if self.first_seen is None or event.time < self.first_seen:
                self.first_seen = event.time
            if self.last_seen is None or event.time > self.last_seen:
                self.last_seen = event.time

    @property
    def score(self) -> float:
        base = float(self.severity.weight)
        if self.severity <= Severity.LOW:
            return base
        bonus = 1.0 + min(2.0, math.log10(max(1, self.count)))
        return round(base * bonus, 2)

    @property
    def ident(self) -> str:
        return self.key or f"{self.rule_id}|" + "|".join(
            f"{k}={v}" for k, v in sorted(self.entities.items())
        )

    def to_dict(self, include_events: bool = False) -> dict:
        data = {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": int(self.severity),
            "severity_label": self.severity.label,
            "tactic": self.tactic,
            "technique": self.technique,
            "description": self.description,
            "recommendation": self.recommendation,
            "count": self.count,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "entities": self.entities,
            "evidence": self.evidence,
            "score": self.score,
        }
        if include_events:
            data["events"] = [
                {
                    "log": e.log,
                    "event_id": e.event_id,
                    "time": e.time.isoformat() if e.time else None,
                    "computer": e.computer,
                    "data": e.data,
                }
                for e in self.events
            ]
        return data


@dataclass
class AuditReport:
    """一次审计的完整结果，供各类报告渲染器使用。"""

    target: str = ""
    mode: str = "remote"
    started: dt.datetime = field(default_factory=lambda: dt.datetime.now(UTC))
    finished: Optional[dt.datetime] = None
    host_info: dict = field(default_factory=dict)
    event_counts: dict[str, int] = field(default_factory=dict)
    parse_errors: int = 0
    findings: list[Finding] = field(default_factory=list)
    coverage: list[str] = field(default_factory=list)
    collection: list[dict] = field(default_factory=list)
    iocs: dict[str, list[str]] = field(default_factory=dict)
    iis_stats: dict = field(default_factory=dict)
    tomcat_stats: dict = field(default_factory=dict)
    posture: dict = field(default_factory=dict)
    timeline: list[dict] = field(default_factory=list)
    risk_score: float = 0.0
    verdict: str = ""
    severity_counts: dict[str, int] = field(default_factory=dict)
    top_source_ips: list[tuple[str, int]] = field(default_factory=list)
    top_users: list[tuple[str, int]] = field(default_factory=list)
    logon_stats: dict = field(default_factory=dict)
    geo: dict[str, str] = field(default_factory=dict)
    tactics: dict[str, int] = field(default_factory=dict)
    options: dict = field(default_factory=dict)

    @property
    def total_events(self) -> int:
        return sum(self.event_counts.values())

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max(f.severity for f in self.findings)

    @property
    def actionable_findings(self) -> list[Finding]:
        return [
            f
            for f in self.findings
            if f.severity >= Severity.LOW
        ]

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (-int(f.severity), -f.score, f.title),
        )

    def count_by_severity(self) -> dict[str, int]:
        counts = {s.label: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.label] += 1
        return counts

    def to_dict(self, include_events: bool = False) -> dict:
        return {
            "tool_version": __version__,
            "target": self.target,
            "mode": self.mode,
            "started": self.started.isoformat(),
            "finished": self.finished.isoformat() if self.finished else None,
            "host_info": self.host_info,
            "event_counts": self.event_counts,
            "total_events": self.total_events,
            "parse_errors": self.parse_errors,
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "severity_counts": self.severity_counts,
            "findings": [f.to_dict(include_events) for f in self.sorted_findings()],
            "coverage": self.coverage,
            "collection": self.collection,
            "iocs": self.iocs,
            "iis_stats": self.iis_stats,
            "tomcat_stats": self.tomcat_stats,
            "posture": self.posture,
            "timeline": self.timeline,
            "top_source_ips": self.top_source_ips,
            "top_users": self.top_users,
            "logon_stats": self.logon_stats,
            "geo": self.geo,
            "tactics": self.tactics,
        }


def group_by(items: Iterable[Any], key) -> dict:
    result: dict = {}
    for item in items:
        result.setdefault(key(item), []).append(item)
    return result
