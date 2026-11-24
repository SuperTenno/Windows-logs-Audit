"""IIS W3C 日志解析与 Web 攻击痕迹检测。"""

from __future__ import annotations

import datetime as dt
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import unquote_plus

from .knowledge import IIS_PATTERNS, IIS_PATTERN_TARGETS, Pattern
from .models import Finding, Severity, fmt_time, ip_kind
from .rules_base import make_finding

UTC = dt.timezone.utc

_FILE_MARKER = "@@@WLAFILE "
_FIELDS_RE = re.compile(r"^#Fields:\s*(.*)$", re.I)
_DATE_RE = re.compile(r"^#Date:\s*(\S+)", re.I)


@dataclass
class IISRecord:
    time: Optional[dt.datetime]
    ip: str
    method: str
    uri: str
    status: int
    user_agent: str
    user: str
    source: str
    uri_raw: str = ""


def _decode(value: str) -> str:
    try:
        return unquote_plus(value)
    except (TypeError, ValueError):
        return value or ""


def _field(fields: list[str], parts: list[str], name: str, default: str = "") -> str:
    try:
        index = fields.index(name)
    except ValueError:
        return default
    if index >= len(parts):
        return default
    return parts[index]


def parse_iis_text(text: str, source: str = "") -> list[IISRecord]:
    """解析一段（可能包含多个文件的）IIS W3C 文本。"""
    records: list[IISRecord] = []
    fields: list[str] = []
    current_date = ""
    current_source = source

    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith(_FILE_MARKER):
            current_source = line[len(_FILE_MARKER):].strip()
            continue
        if line.startswith("#"):
            date_match = _DATE_RE.match(line)
            if date_match:
                current_date = date_match.group(1)
                continue
            fields_match = _FIELDS_RE.match(line)
            if fields_match:
                fields = fields_match.group(1).split()
            continue
        if not fields:
            continue

        parts = line.split()
        if len(parts) > len(fields):
            # User-Agent 等字段可能包含空格：把多余部分并入最后一列
            parts = parts[: len(fields) - 1] + [" ".join(parts[len(fields) - 1:])]
        if len(parts) < len(fields):
            continue
        if "date" in fields:
            date_text = _field(fields, parts, "date")
        else:
            date_text = current_date
        time_text = _field(fields, parts, "time")
        stamp = None
        if date_text and time_text:
            try:
                stamp = dt.datetime.strptime(
                    f"{date_text} {time_text}", "%Y-%m-%d %H:%M:%S"
                ).replace(tzinfo=UTC)
            except ValueError:
                stamp = None

        uri_raw = _field(fields, parts, "cs-uri-stem")
        query_raw = _field(fields, parts, "cs-uri-query")
        if query_raw and query_raw != "-":
            uri_raw = f"{uri_raw}?{query_raw}"
        user_agent = _field(fields, parts, "cs(User-Agent)")
        status_text = _field(fields, parts, "sc-status", "0")

        records.append(
            IISRecord(
                time=stamp,
                ip=_field(fields, parts, "c-ip"),
                method=_field(fields, parts, "cs-method"),
                uri=_decode(uri_raw),
                status=int(status_text) if status_text.isdigit() else 0,
                user_agent=_decode(user_agent) if user_agent != "-" else "",
                user=_field(fields, parts, "cs-username"),
                source=current_source,
                uri_raw=uri_raw,
            )
        )
    return records


def _pattern_matches(record: IISRecord, pattern: Pattern) -> bool:
    target = IIS_PATTERN_TARGETS.get(pattern.name, "uri")
    uri = (record.uri or "").lower()
    raw = (record.uri_raw or "").lower()
    ua = (record.user_agent or "").lower()
    if target == "ua":
        haystack = ua
    elif target == "put":
        if (record.method or "").upper() not in {"PUT", "POST", "DELETE"}:
            return False
        haystack = uri
    else:
        haystack = uri + " " + raw
    return bool(pattern.regex.search(haystack))


def analyze(
    records: list[IISRecord],
    geo_lookup: Optional[Callable[[str], str]] = None,
) -> tuple[dict, list[Finding]]:
    """返回 (统计信息, 发现列表)。"""
    if not records:
        return {"total": 0}, []

    status_counter = Counter(record.status for record in records)
    ip_counter = Counter(record.ip for record in records if record.ip)
    url_counter = Counter(record.uri for record in records if record.uri)
    ua_counter = Counter(record.user_agent for record in records if record.user_agent)
    users = Counter(record.user for record in records if record.user and record.user != "-")
    files = sorted({record.source for record in records if record.source})
    times = [record.time for record in records if record.time]

    hits: dict[str, list[IISRecord]] = defaultdict(list)
    for record in records:
        for pattern in IIS_PATTERNS:
            if _pattern_matches(record, pattern):
                hits[pattern.name].append(record)

    findings: list[Finding] = []
    for pattern in IIS_PATTERNS:
        matched = hits.get(pattern.name)
        if not matched:
            continue
        by_ip: dict[str, list[IISRecord]] = defaultdict(list)
        for record in matched:
            by_ip[record.ip or "未知"].append(record)

        for ip, items in sorted(by_ip.items(), key=lambda kv: -len(kv[1]))[:8]:
            severity = pattern.severity
            success_hits = [r for r in items if 200 <= r.status < 400]
            if pattern.name in {"iis_webshell", "iis_log4shell"} and success_hits:
                severity = Severity.CRITICAL
            elif pattern.name in {"iis_sqli", "iis_traversal", "iis_cmd_injection"} and success_hits:
                severity = max(severity, Severity.HIGH)

            finding = make_finding(
                f"WEB-{pattern.name.upper().replace('IIS_', '')}",
                f"{pattern.description}（{ip}）",
                severity,
                tactic="初始访问",
                technique=_iis_technique(pattern.name),
                description=(
                    f"来自 {ip} 的 {len(items)} 条请求命中“{pattern.description}”特征，"
                    f"其中 {len(success_hits)} 条返回 2xx/3xx 状态码。"
                ),
                recommendation=(
                    "核查对应请求与响应内容；对成功请求立即排查是否已落地 WebShell 或执行命令，"
                    "并部署 WAF、限制目录执行权限、及时打补丁。"
                ),
                entities={"ip": ip},
            )
            finding.key = f"iis|{pattern.name}|{ip}"
            finding.count = len(items)
            for record in items[:6]:
                finding.add_evidence(
                    f"{fmt_time(record.time)} {record.method or '-'} "
                    f"{record.uri[:180]} -> {record.status} "
                    f"UA={record.user_agent[:70] or '-'}"
                )
            finding.first_seen = min((r.time for r in items if r.time), default=None)
            finding.last_seen = max((r.time for r in items if r.time), default=None)
            findings.append(finding)

    findings.extend(_behavior_findings(records))

    stats = {
        "total": len(records),
        "unique_ips": len(ip_counter),
        "status_distribution": status_counter.most_common(),
        "top_ips": ip_counter.most_common(15),
        "top_urls": url_counter.most_common(15),
        "top_user_agents": ua_counter.most_common(10),
        "authenticated_users": users.most_common(10),
        "files": files[:20],
        "first_seen": min(times) if times else None,
        "last_seen": max(times) if times else None,
        "attack_counts": {
            pattern.description: len(hits.get(pattern.name, []))
            for pattern in IIS_PATTERNS
            if hits.get(pattern.name)
        },
        "error_4xx": sum(count for status, count in status_counter.items() if 400 <= status < 500),
        "error_5xx": sum(count for status, count in status_counter.items() if status >= 500),
        "geo_top_ips": [],
    }
    if geo_lookup:
        for ip, count in ip_counter.most_common(10):
            if ip_kind(ip) == "public":
                geo = geo_lookup(ip)
                if geo:
                    stats["geo_top_ips"].append((ip, count, geo))
    return stats, findings


def _iis_technique(name: str) -> str:
    mapping = {
        "iis_sqli": "T1190 利用面向公众的应用",
        "iis_xss": "T1059.007 JavaScript",
        "iis_traversal": "T1005 本地数据收集",
        "iis_file_inclusion": "T1190 利用面向公众的应用",
        "iis_cmd_injection": "T1059 命令执行",
        "iis_log4shell": "T1190 利用面向公众的应用",
        "iis_webshell": "T1505.003 Web Shell",
        "iis_sensitive_file": "T1083 文件和目录发现",
        "iis_encoded_payload": "T1027 混淆文件或信息",
        "iis_scanner_ua": "T1595 主动扫描",
        "iis_put_upload": "T1505.003 Web Shell",
    }
    return mapping.get(name, "T1190 利用面向公众的应用")


def _behavior_findings(records: list[IISRecord]) -> list[Finding]:
    findings: list[Finding] = []

    # 404 目录枚举
    by_ip_404: dict[str, list[IISRecord]] = defaultdict(list)
    for record in records:
        if record.status == 404:
            by_ip_404[record.ip or "未知"].append(record)
    for ip, items in by_ip_404.items():
        distinct = {record.uri for record in items}
        if len(distinct) < 30:
            continue
        finding = make_finding(
            "WEB-ENUM",
            f"目录/文件枚举扫描：{ip}（{len(distinct)} 个 404 路径）",
            Severity.MEDIUM,
            tactic="发现",
            technique="T1595.003 目录扫描",
            description=(
                f"来源 {ip} 产生 {len(items)} 次 404，涉及 {len(distinct)} 个不同路径，"
                "符合目录爆破或漏洞扫描器行为。"
            ),
            recommendation="封禁来源 IP 或限速，隐藏敏感路径，部署 WAF 的扫描器识别规则。",
            entities={"ip": ip},
        )
        finding.key = f"iis-enum|{ip}"
        finding.count = len(items)
        for record in items[:6]:
            finding.add_evidence(f"{fmt_time(record.time)} {record.uri[:160]} -> 404")
        findings.append(finding)

    # 401 认证爆破
    by_ip_401 = Counter(r.ip for r in records if r.status == 401 and r.ip)
    for ip, count in by_ip_401.most_common(5):
        if count < 20:
            continue
        finding = make_finding(
            "WEB-AUTH-BRUTE",
            f"Web 认证爆破：{ip}（{count} 次 401）",
            Severity.MEDIUM,
            tactic="凭据访问",
            technique="T1110 暴力破解",
            description=f"来源 {ip} 触发 {count} 次 401 未授权响应，疑似对 Web 认证进行口令猜测。",
            recommendation="启用账户锁定与 MFA，封禁来源 IP，检查是否有成功认证记录。",
            entities={"ip": ip},
        )
        finding.key = f"iis-401|{ip}"
        finding.count = count
        for record in [r for r in records if r.ip == ip and r.status == 401][:6]:
            finding.add_evidence(f"{fmt_time(record.time)} {record.method} {record.uri[:140]}")
        findings.append(finding)

    # 高频访问（可能为 CC/爬虫/爆破）
    by_ip = Counter(r.ip for r in records if r.ip)
    for ip, count in by_ip.most_common(3):
        if count < 2000:
            continue
        ip_records = [r for r in records if r.ip == ip]
        errors = sum(1 for r in ip_records if r.status >= 400)
        if errors / max(1, count) < 0.3:
            continue
        finding = make_finding(
            "WEB-FLOOD",
            f"高频异常请求：{ip}（{count} 次，{errors} 次错误）",
            Severity.MEDIUM,
            tactic="影响",
            technique="T1499 端点拒绝服务",
            description=f"来源 {ip} 的请求量显著高于其他来源，且错误率较高，可能为扫描或拒绝服务尝试。",
            recommendation="在 WAF/负载均衡层限速并封禁，分析请求特征作为 IOC。",
            entities={"ip": ip},
        )
        finding.key = f"iis-flood|{ip}"
        finding.count = count
        findings.append(finding)

    return findings
