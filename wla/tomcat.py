"""Tomcat 中间件日志分析：access log 攻击检测 + catalina 异常/部署痕迹。"""

from __future__ import annotations

import datetime as dt
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Callable, Optional

from .knowledge import IIS_PATTERNS, IIS_PATTERN_TARGETS, Pattern
from .models import Finding, Severity, fmt_time, ip_kind
from .rules_base import make_finding

UTC = dt.timezone.utc

_FILE_MARKER = "@@@WLAFILE "
_ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\S+)"
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)
_CATALINA_RE = re.compile(
    r"^(?P<time>\d{2}-[A-Za-z]{3}-\d{4} \d{2}:\d{2}:\d{2}\.\d{3})\s+"
    r"(?P<level>SEVERE|WARNING|INFO|CONFIG|FINE|FINER|FINEST|ALL|OFF)\s+"
    r"\[(?P<thread>[^\]]*)\]\s+(?P<rest>.*)$"
)
_CAT_TIME_RE = re.compile(
    r"(\d{2})-([A-Za-z]{3})-(\d{4})\s+(\d{2}):(\d{2}):(\d{2})\.(\d{3})"
)
_VERSION_RE = re.compile(r"Apache Tomcat/(\d+)\.(\d+)\.(\d+)")
_DEPLOY_RE = re.compile(
    r"(?:Deploying|Deployed|Undeploying|Undeployed) (?:web application archive|web application directory|WAR|webapp) \[([^\]]+)\]",
    re.I,
)
_TIME_ACCESS_RE = re.compile(r"(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s+([+-]\d{4}))?")
_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# 复用的通用 Web 攻击特征（去掉 IIS 专属的 WebShell / PUT 规则）
_GENERIC = tuple(
    pattern
    for pattern in IIS_PATTERNS
    if pattern.name not in {"iis_webshell", "iis_put_upload"}
)

_TOMCAT_SPECS: tuple[tuple[str, str, Severity, str], ...] = (
    (
        "tomcat_webshell",
        r"/(?:shell|cmd|exec|backdoor|webshell|behinder|godzilla|antsword|cmdjsp|upload)\.jspx?|"
        r"[?&](?:cmd|exec|command|shell|pass|password)=",
        Severity.HIGH,
        "JSP WebShell 访问特征",
    ),
    (
        "tomcat_web_inf",
        r"/(?:WEB-INF|META-INF)/",
        Severity.HIGH,
        "尝试访问 WEB-INF/META-INF 受保护目录",
    ),
    (
        "tomcat_manager",
        r"^/(?:manager|host-manager)/(?:html|text|status|deploy|undeploy|jmxproxy)",
        Severity.LOW,
        "访问 Tomcat Manager 管理控制台",
    ),
    (
        "tomcat_war",
        r"\.war(?:$|[?&])|/manager/(?:html|text)/deploy",
        Severity.HIGH,
        "WAR 包部署/上传行为",
    ),
)

_TOMCAT_PATTERNS: tuple[Pattern, ...] = tuple(
    Pattern(name, re.compile(regex, re.I), severity, description)
    for name, regex, severity, description in _TOMCAT_SPECS
)

_RISKY_STACK = (
    ("jndi", r"javax\.naming|initialcontext|\.lookup\(|ldap://|rmi://|jndi"),
    ("deserialization", r"templatesimpl|ysoserial|objectinputstream|readobject|commons-collections|invokertransformer"),
    ("command_exec", r"java\.lang\.runtime[^\n]*exec|processbuilder|runtime\.getruntime"),
    ("script_engine", r"scriptenginemanager|elprocessor|expressionfactory"),
    ("log4shell", r"log4j|jndi:ldap|jndi:rmi"),
)


@dataclass
class TomcatAccess:
    time: Optional[dt.datetime]
    ip: str
    user: str
    method: str
    uri: str
    protocol: str
    status: int
    size: str
    referer: str
    user_agent: str
    source: str = ""


@dataclass
class TomcatLogEvent:
    time: Optional[dt.datetime]
    level: str
    logger: str
    message: str
    stack: list[str] = field(default_factory=list)
    source: str = ""

    def text(self) -> str:
        return "\n".join([self.message] + self.stack)


def _parse_access_time(value: str) -> Optional[dt.datetime]:
    match = _TIME_ACCESS_RE.search(value or "")
    if not match:
        return None
    day, month, year, hour, minute, second, zone = match.groups()
    month_number = _MONTHS.get(month.title())
    if not month_number:
        return None
    offset = 0
    if zone:
        sign = 1 if zone[0] == "+" else -1
        offset = sign * (int(zone[1:3]) * 60 + int(zone[3:5]))
    try:
        return dt.datetime(
            int(year), month_number, int(day), int(hour), int(minute), int(second),
            tzinfo=dt.timezone(dt.timedelta(minutes=offset)),
        ).astimezone(UTC)
    except ValueError:
        return None


def _parse_catalina_time(value: str) -> Optional[dt.datetime]:
    match = _CAT_TIME_RE.search(value or "")
    if not match:
        return None
    day, month, year, hour, minute, second, millis = match.groups()
    month_number = _MONTHS.get(month.title())
    if not month_number:
        return None
    try:
        return dt.datetime(
            int(year), month_number, int(day), int(hour), int(minute),
            int(second), int(millis) * 1000, tzinfo=UTC,
        )
    except ValueError:
        return None


def parse_access_log(text: str, source: str = "") -> list[TomcatAccess]:
    records: list[TomcatAccess] = []
    current_source = source
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith(_FILE_MARKER):
            current_source = line[len(_FILE_MARKER):].strip()
            continue
        match = _ACCESS_RE.match(line)
        if not match:
            continue
        request = match.group("request").split()
        method = request[0] if request else ""
        uri = request[1] if len(request) > 1 else ""
        protocol = request[2] if len(request) > 2 else ""
        status_text = match.group("status")
        records.append(
            TomcatAccess(
                time=_parse_access_time(match.group("time")),
                ip=match.group("ip"),
                user="" if match.group("user") == "-" else match.group("user"),
                method=method,
                uri=uri,
                protocol=protocol,
                status=int(status_text) if status_text.isdigit() else 0,
                size=match.group("size"),
                referer=match.group("referer") or "",
                user_agent=match.group("ua") or "",
                source=current_source,
            )
        )
    return records


def parse_catalina_log(text: str, source: str = "") -> list[TomcatLogEvent]:
    events: list[TomcatLogEvent] = []
    current_source = source
    for raw_line in (text or "").splitlines():
        line = raw_line.rstrip()
        if line.startswith(_FILE_MARKER):
            current_source = line[len(_FILE_MARKER):].strip()
            continue
        match = _CATALINA_RE.match(line)
        if match:
            rest = match.group("rest").strip()
            logger, message = rest, ""
            if " " in rest:
                logger, message = rest.split(" ", 1)
                logger = logger.rstrip(":")
            events.append(
                TomcatLogEvent(
                    time=_parse_catalina_time(match.group("time")),
                    level=match.group("level"),
                    logger=logger,
                    message=message.strip(),
                    source=current_source,
                )
            )
        elif events and (
            line.startswith(" ")
            or line.startswith("\t")
            or line.startswith("Caused by")
        ):
            events[-1].stack.append(line.strip())
    return events


def parse_tomcat_text(text: str) -> tuple[list[TomcatAccess], list[TomcatLogEvent]]:
    """按文件标记/内容区分 access 与 catalina 日志。"""
    access: list[TomcatAccess] = []
    catalina: list[TomcatLogEvent] = []
    chunks: list[tuple[str, list[str]]] = []
    current_name = ""
    current_lines: list[str] = []
    for line in (text or "").splitlines():
        if line.startswith(_FILE_MARKER):
            if current_name or current_lines:
                chunks.append((current_name, current_lines))
            current_name = line[len(_FILE_MARKER):].strip()
            current_lines = []
        else:
            current_lines.append(line)
    chunks.append((current_name, current_lines))

    for name, lines in chunks:
        content = "\n".join(lines)
        lower = name.lower()
        if "access" in lower:
            access.extend(parse_access_log(content, name))
        elif "catalina" in lower or "localhost." in lower or "manager." in lower:
            catalina.extend(parse_catalina_log(content, name))
        else:
            # 通过首行格式判断
            if _CATALINA_RE.match(next((l for l in lines if l.strip()), "")):
                catalina.extend(parse_catalina_log(content, name))
            else:
                access.extend(parse_access_log(content, name))
    return access, catalina


def _matches(record: TomcatAccess, pattern: Pattern) -> bool:
    target = IIS_PATTERN_TARGETS.get(pattern.name, "uri")
    uri = record.uri.lower()
    ua = record.user_agent.lower()
    if target == "ua":
        return bool(pattern.regex.search(ua))
    return bool(pattern.regex.search(uri))


def analyze(
    access: list[TomcatAccess],
    catalina: list[TomcatLogEvent],
    geo_lookup: Optional[Callable[[str], str]] = None,
) -> tuple[dict, list[Finding]]:
    findings: list[Finding] = []

    # ---- access log 攻击特征 ----
    hits: dict[str, list[TomcatAccess]] = defaultdict(list)
    for record in access:
        for pattern in _GENERIC + _TOMCAT_PATTERNS:
            if _matches(record, pattern):
                hits[pattern.name].append(record)

    severity_map = {pattern.name: pattern.severity for pattern in _GENERIC + _TOMCAT_PATTERNS}
    desc_map = {pattern.name: pattern.description for pattern in _GENERIC + _TOMCAT_PATTERNS}

    for name, records in hits.items():
        by_ip: dict[str, list[TomcatAccess]] = defaultdict(list)
        for record in records:
            by_ip[record.ip or "未知"].append(record)
        for ip, items in sorted(by_ip.items(), key=lambda kv: -len(kv[1]))[:8]:
            severity = severity_map[name]
            success = [r for r in items if 200 <= r.status < 400]
            if name in {"tomcat_webshell", "tomcat_war", "iis_log4shell"} and success:
                severity = Severity.CRITICAL
            elif name == "tomcat_manager":
                severity = Severity.MEDIUM if success else Severity.LOW
            elif name in {"iis_sqli", "iis_traversal", "iis_cmd_injection", "iis_file_inclusion"} and success:
                severity = max(severity, Severity.HIGH)
            suffix = name.upper()
            for prefix in ("TOMCAT_", "IIS_"):
                if suffix.startswith(prefix):
                    suffix = suffix[len(prefix):]
                    break
            finding = make_finding(
                f"TOMCAT-{suffix}",
                f"{desc_map[name]}（{ip}）",
                severity,
                tactic="初始访问",
                technique=_technique(name),
                description=(
                    f"来自 {ip} 的 {len(items)} 条 Tomcat 请求命中“{desc_map[name]}”，"
                    f"其中 {len(success)} 条返回 2xx/3xx。"
                ),
                recommendation=(
                    "核查请求与响应；对成功利用立即检查 webapps 目录是否新增 JSP/WAR，"
                    "封禁来源 IP，升级 Tomcat 并限制 Manager 访问。"
                ),
                entities={"ip": ip},
            )
            finding.key = f"tomcat|{name}|{ip}"
            finding.count = len(items)
            for record in items[:6]:
                finding.add_evidence(
                    f"{fmt_time(record.time)} {record.method} {record.uri[:180]} "
                    f"-> {record.status} UA={record.user_agent[:70] or '-'}"
                )
            finding.first_seen = min((r.time for r in items if r.time), default=None)
            finding.last_seen = max((r.time for r in items if r.time), default=None)
            findings.append(finding)

    findings.extend(_access_behavior(access))
    findings.extend(_catalina_findings(catalina))

    stats = _stats(access, catalina, hits, geo_lookup)
    return stats, findings


def _technique(name: str) -> str:
    return {
        "iis_sqli": "T1190 利用面向公众的应用",
        "iis_traversal": "T1005 本地数据收集",
        "iis_cmd_injection": "T1059 命令执行",
        "iis_log4shell": "T1190 利用面向公众的应用",
        "iis_scanner_ua": "T1595 主动扫描",
        "tomcat_webshell": "T1505.003 Web Shell",
        "tomcat_war": "T1505.003 Web Shell",
        "tomcat_web_inf": "T1005 本地数据收集",
        "tomcat_manager": "T1078 有效账户",
    }.get(name, "T1190 利用面向公众的应用")


def _access_behavior(access: list[TomcatAccess]) -> list[Finding]:
    findings: list[Finding] = []
    by_ip_404: dict[str, list[TomcatAccess]] = defaultdict(list)
    manager_401: dict[str, list[TomcatAccess]] = defaultdict(list)
    for record in access:
        if record.status == 404:
            by_ip_404[record.ip].append(record)
        if record.status in {401, 403} and "/manager" in record.uri.lower():
            manager_401[record.ip].append(record)

    for ip, items in by_ip_404.items():
        distinct = {r.uri for r in items}
        if len(distinct) < 30:
            continue
        finding = make_finding(
            "TOMCAT-ENUM",
            f"Tomcat 路径枚举：{ip}（{len(distinct)} 个 404 路径）",
            Severity.MEDIUM,
            tactic="发现",
            technique="T1595.003 目录扫描",
            description=f"来源 {ip} 触发 {len(items)} 次 404，涉及 {len(distinct)} 个不同路径。",
            recommendation="封禁或限速来源；移除示例应用/管理控制台，部署 WAF。",
            entities={"ip": ip},
        )
        finding.key = f"tomcat-enum|{ip}"
        finding.count = len(items)
        for record in items[:6]:
            finding.add_evidence(f"{fmt_time(record.time)} {record.uri[:150]} -> 404")
        findings.append(finding)

    for ip, items in manager_401.items():
        if len(items) < 10:
            continue
        finding = make_finding(
            "TOMCAT-MANAGER-BRUTE",
            f"Manager 认证爆破：{ip}（{len(items)} 次 401/403）",
            Severity.HIGH,
            tactic="凭据访问",
            technique="T1110 暴力破解",
            description=f"来源 {ip} 对 Tomcat Manager 产生 {len(items)} 次认证失败，疑似口令爆破。",
            recommendation="立即封禁来源，检查 manager-users.xml 与访问日志中是否有成功登录，启用强口令/MFA。",
            entities={"ip": ip},
        )
        finding.key = f"tomcat-manager-brute|{ip}"
        finding.count = len(items)
        for record in items[:6]:
            finding.add_evidence(f"{fmt_time(record.time)} {record.method} {record.uri[:150]} -> {record.status}")
        findings.append(finding)

    # 管理控制台暴露
    manager_ok = [
        r for r in access if 200 <= r.status < 400 and "/manager" in r.uri.lower()
    ]
    if manager_ok:
        ips = Counter(r.ip for r in manager_ok)
        finding = make_finding(
            "TOMCAT-MANAGER-EXPOSED",
            "Tomcat Manager 控制台可访问",
            Severity.MEDIUM,
            tactic="初始访问",
            technique="T1078 有效账户",
            description=(
                f"检测到 {len(manager_ok)} 次 Manager 控制台成功访问，涉及 {len(ips)} 个来源。"
                "Manager 可直接部署 WAR 获取服务器权限，不应暴露给非运维网段。"
            ),
            recommendation="删除默认 manager/host-manager 应用或限制来源 IP，使用强口令并启用 HTTPS。",
        )
        finding.key = "tomcat-manager-exposed"
        finding.count = len(manager_ok)
        for record in manager_ok[:6]:
            finding.add_evidence(f"{fmt_time(record.time)} {record.ip} {record.uri[:140]} -> {record.status}")
        findings.append(finding)

    # PUT 写入 JSP（CVE-2017-12615 类）
    jsp_put = [
        r for r in access
        if r.method.upper() in {"PUT", "DELETE"} and r.uri.lower().endswith((".jsp", ".jspx", ".jsp/"))
    ]
    if jsp_put:
        finding = make_finding(
            "TOMCAT-JSP-PUT",
            "通过 PUT 写入 JSP（CVE-2017-12615 特征）",
            Severity.CRITICAL,
            tactic="初始访问",
            technique="T1190 利用面向公众的应用",
            description=(
                f"检测到 {len(jsp_put)} 次对 JSP 路径的 PUT/DELETE 请求，"
                "攻击者可利用 DefaultServlet 只读配置缺陷上传 WebShell。"
            ),
            recommendation="确认 webapps 目录是否新增 JSP；设置 readonly=true，升级 Tomcat 至修复版本。",
        )
        finding.key = "tomcat-jsp-put"
        finding.count = len(jsp_put)
        for record in jsp_put[:8]:
            finding.add_evidence(f"{fmt_time(record.time)} {record.method} {record.uri[:160]} -> {record.status}")
        findings.append(finding)
    return findings


def _catalina_findings(events: list[TomcatLogEvent]) -> list[Finding]:
    findings: list[Finding] = []
    version = _version(events)

    if version:
        major, minor, patch = version
        if major <= 7 or (major == 8 and minor <= 5):
            finding = make_finding(
                "TOMCAT-VERSION",
                f"Tomcat 版本已停止维护：{major}.{minor}.{patch}",
                Severity.LOW if (major, minor) < (8, 5) else Severity.MEDIUM,
                tactic="加固配置",
                technique="T1190 利用面向公众的应用",
                description=(
                    f"当前 Tomcat 版本 {major}.{minor}.{patch} 已停止安全更新，"
                    "存在多个已知反序列化/JNDI 漏洞。"
                ),
                recommendation="升级到受支持的 Tomcat 9.0/10.1/11 版本，并移除示例应用。",
            )
            finding.key = "tomcat-version"
            finding.add_evidence(f"Server version: {major}.{minor}.{patch}")
            findings.append(finding)

    deploy = [e for e in events if _DEPLOY_RE.search(e.message)]
    suspicious_deploy = []
    for event in deploy:
        match = _DEPLOY_RE.search(event.message)
        path = match.group(1) if match else ""
        if re.search(r"\\temp\\|\\tmp\\|\\appdata\\|\\users\\public|/tmp/|/var/tmp/", path, re.I):
            suspicious_deploy.append(event)
    if suspicious_deploy:
        finding = make_finding(
            "TOMCAT-DEPLOY",
            "从临时目录部署 Web 应用（可疑）",
            Severity.HIGH,
            tactic="持久化",
            technique="T1505.003 Web Shell",
            description=f"检测到 {len(suspicious_deploy)} 次从用户可写/临时目录部署 Web 应用，可能是攻击者投放 WAR。",
            recommendation="核对部署来源与 WAR 内容，删除非授权应用并检查 webapps 目录。",
        )
        finding.key = "tomcat-deploy-temp"
        finding.count = len(suspicious_deploy)
        for event in suspicious_deploy[:8]:
            finding.add_evidence(f"{fmt_time(event.time)} {event.message[:220]}")
        findings.append(finding)

    # 反序列化 / JNDI / 命令执行痕迹
    for label, pattern in _RISKY_STACK:
        matched = [
            e for e in events
            if e.level in {"SEVERE", "WARNING"}
            and re.search(pattern, e.text(), re.I)
        ]
        if not matched:
            continue
        finding = make_finding(
            f"TOMCAT-{label.upper()}",
            f"Tomcat 日志出现 {label} 相关异常",
            Severity.CRITICAL,
            tactic="初始访问",
            technique="T1190 利用面向公众的应用",
            description=(
                f"Catalina/localhost 日志中有 {len(matched)} 条异常堆栈包含 {label} 特征，"
                "可能是漏洞利用（JNDI 注入、反序列化、命令执行）的痕迹。"
            ),
            recommendation="提取完整堆栈与对应请求，排查 webapps 是否被植入后门；升级 Tomcat 与 JDK。",
        )
        finding.key = f"tomcat-stack|{label}"
        finding.count = len(matched)
        for event in matched[:5]:
            finding.add_evidence(f"{fmt_time(event.time)} {event.message[:240]}")
        findings.append(finding)

    oom = [e for e in events if "OutOfMemoryError" in e.text()]
    if oom:
        finding = make_finding(
            "TOMCAT-OOM",
            "Tomcat 出现内存溢出",
            Severity.MEDIUM,
            tactic="影响",
            technique="T1499 端点拒绝服务",
            description=f"Catalina 日志出现 {len(oom)} 次 OutOfMemoryError，可能导致服务不可用或被用于拒绝服务。",
            recommendation="检查堆内存配置与异常请求，保留堆转储分析是否存在内存马。",
        )
        finding.key = "tomcat-oom"
        finding.count = len(oom)
        findings.append(finding)

    invalid = [e for e in events if "Invalid character found in the request target" in e.message]
    if len(invalid) >= 5:
        finding = make_finding(
            "TOMCAT-BAD-REQUEST",
            "大量非法请求目标（扫描器特征）",
            Severity.LOW,
            tactic="发现",
            technique="T1595 主动扫描",
            description=f"检测到 {len(invalid)} 次非法请求目标告警，通常来自漏洞扫描器。",
            recommendation="封禁来源，检查 AccessLogValve 是否记录完整请求。",
        )
        finding.key = "tomcat-bad-request"
        finding.count = len(invalid)
        findings.append(finding)
    return findings


def _version(events: list[TomcatLogEvent]) -> Optional[tuple[int, int, int]]:
    for event in events:
        match = _VERSION_RE.search(event.message)
        if match:
            return int(match.group(1)), int(match.group(2)), int(match.group(3))
    return None


def _stats(
    access: list[TomcatAccess],
    catalina: list[TomcatLogEvent],
    hits: dict[str, list[TomcatAccess]],
    geo_lookup: Optional[Callable[[str], str]],
) -> dict:
    status_counter = Counter(r.status for r in access)
    ip_counter = Counter(r.ip for r in access if r.ip)
    url_counter = Counter(r.uri for r in access if r.uri)
    ua_counter = Counter(r.user_agent for r in access if r.user_agent)
    times = [r.time for r in access if r.time]
    deployments = []
    for event in catalina:
        match = _DEPLOY_RE.search(event.message)
        if match:
            deployments.append(
                {"time": event.time.isoformat() if event.time else None, "path": match.group(1)}
            )

    stats = {
        "total": len(access),
        "unique_ips": len(ip_counter),
        "status_distribution": status_counter.most_common(),
        "top_ips": ip_counter.most_common(15),
        "top_urls": url_counter.most_common(15),
        "top_user_agents": ua_counter.most_common(10),
        "first_seen": min(times) if times else None,
        "last_seen": max(times) if times else None,
        "error_4xx": sum(c for s, c in status_counter.items() if 400 <= s < 500),
        "error_5xx": sum(c for s, c in status_counter.items() if s >= 500),
        "attack_counts": {
            name: len(items) for name, items in hits.items() if items
        },
        "version": ".".join(map(str, _version(catalina))) if _version(catalina) else "",
        "deployments": deployments[:20],
        "catalina_events": len(catalina),
        "severe_events": sum(1 for e in catalina if e.level == "SEVERE"),
        "sources": sorted({r.source for r in access if r.source})[:20],
        "geo_top_ips": [],
    }
    if geo_lookup:
        for ip, count in ip_counter.most_common(10):
            if ip_kind(ip) == "public":
                location = geo_lookup(ip)
                if location:
                    stats["geo_top_ips"].append((ip, count, location))
    return stats
