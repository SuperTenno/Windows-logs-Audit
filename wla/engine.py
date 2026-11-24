"""检测编排、风险评估、IOC 提取与时间线构建。"""

from __future__ import annotations

import datetime as dt
import re
from collections import Counter
from typing import Callable, Iterable, Optional

from . import iis as iis_module
from . import tomcat as tomcat_module
from . import (
    rules_accounts,
    rules_auth,
    rules_defense,
    rules_execution,
    rules_persistence,
    rules_posture,
)
from .knowledge import LOG_LABELS
from .models import (
    TACTIC_ORDER,
    AuditReport,
    Event,
    Finding,
    Severity,
    fmt_time,
    ip_kind,
)
from .rules_base import RuleContext, RuleOptions, command_line, process_name

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
WIN_PATH_RE = re.compile(
    r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*"
    r"\.(?:exe|dll|ps1|bat|cmd|vbs|js|scr|sys|tmp|dat)",
    re.I,
)
HASH_RE = re.compile(r"\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b", re.I)

_RULE_MODULES = (
    rules_auth,
    rules_accounts,
    rules_persistence,
    rules_execution,
    rules_defense,
    rules_posture,
)


def analyze(
    events: Iterable[Event],
    *,
    iis_records: Optional[list] = None,
    tomcat_access: Optional[list] = None,
    tomcat_catalina: Optional[list] = None,
    posture: Optional[dict] = None,
    options: Optional[RuleOptions] = None,
    target: str = "",
    mode: str = "remote",
    collection: Optional[list[dict]] = None,
    parse_errors: int = 0,
    geo_lookup: Optional[Callable[[str], str]] = None,
) -> AuditReport:
    """对已采集的事件执行全部检测规则并返回审计报告。"""
    options = options or RuleOptions()
    started = dt.datetime.now(dt.timezone.utc)
    event_list = list(events)
    dropped = 0
    if options.since:
        kept = []
        for event in event_list:
            if event.time is None or event.time >= options.since:
                kept.append(event)
            else:
                dropped += 1
        event_list = kept

    ctx = RuleContext(event_list, options, posture)
    for module in _RULE_MODULES:
        try:
            module.run(ctx)
        except Exception as error:  # 单条规则异常不应中断整体审计
            ctx.note(f"规则模块 {module.__name__} 执行异常：{error}")

    iis_stats: dict = {"total": 0}
    iis_findings: list[Finding] = []
    if iis_records:
        try:
            iis_stats, iis_findings = iis_module.analyze(iis_records, geo_lookup)
        except Exception as error:
            ctx.note(f"IIS 日志分析异常：{error}")

    tomcat_stats: dict = {"total": 0}
    tomcat_findings: list[Finding] = []
    if tomcat_access or tomcat_catalina:
        try:
            tomcat_stats, tomcat_findings = tomcat_module.analyze(
                tomcat_access or [], tomcat_catalina or [], geo_lookup
            )
        except Exception as error:
            ctx.note(f"Tomcat 日志分析异常：{error}")

    findings = _merge_findings(list(ctx.findings) + iis_findings + tomcat_findings)
    findings = [f for f in findings if f.severity >= options.min_severity]

    report = AuditReport(
        target=target,
        mode=mode,
        started=started,
        finished=dt.datetime.now(dt.timezone.utc),
        host_info=_host_info(posture, target),
        event_counts=_count_events(event_list),
        parse_errors=parse_errors,
        findings=sorted(findings, key=lambda f: (-int(f.severity), -f.score, f.title)),
        posture=posture or {},
        iis_stats=iis_stats,
        tomcat_stats=tomcat_stats,
        collection=collection or [],
        options={
            "brute_threshold": options.brute_threshold,
            "brute_window_minutes": options.brute_window_minutes,
            "since": options.since.isoformat() if options.since else None,
            "dropped_events": dropped,
            "min_severity": options.min_severity.label,
        },
    )
    report.severity_counts = report.count_by_severity()
    tactic_counter = Counter(f.tactic for f in report.findings if f.tactic)
    report.tactics = {
        tactic: tactic_counter[tactic] for tactic in TACTIC_ORDER if tactic_counter[tactic]
    }
    for tactic, count in tactic_counter.items():
        if tactic not in report.tactics:
            report.tactics[tactic] = count
    report.logon_stats, report.top_source_ips, report.top_users = _logon_summary(event_list)
    if geo_lookup:
        for ip, _count in report.top_source_ips:
            if ip_kind(ip) == "public":
                try:
                    location = geo_lookup(ip)
                except Exception:  # noqa: BLE001
                    location = ""
                if location:
                    report.geo[ip] = location
    report.iocs = _extract_iocs(event_list, report.findings, iis_records or [], iis_stats)
    report.timeline = _build_timeline(report.findings)
    report.risk_score, report.verdict = _risk(report.findings)
    report.coverage = _coverage(event_list, report.collection, parse_errors, dropped, report)
    return report


# ---------------------------------------------------------------------------
# 汇总辅助
# ---------------------------------------------------------------------------
def _count_events(events: list[Event]) -> dict[str, int]:
    counter = Counter(event.log for event in events)
    return dict(sorted(counter.items(), key=lambda kv: -kv[1]))


def _host_info(posture: Optional[dict], fallback: str) -> dict:
    info = {"target": fallback}
    if posture:
        for key in ("hostname", "os", "domain", "uptime_days", "boot_time", "arch"):
            value = posture.get(key)
            if value:
                info[key] = value
        info["sysmon"] = posture.get("sysmon", "未知")
    return info


def _merge_findings(findings: list[Finding]) -> list[Finding]:
    merged: dict[str, Finding] = {}
    for finding in findings:
        ident = finding.ident
        if ident not in merged:
            merged[ident] = finding
            continue
        base = merged[ident]
        base.count = max(base.count, finding.count)
        base.severity = max(base.severity, finding.severity)
        if finding.first_seen and (base.first_seen is None or finding.first_seen < base.first_seen):
            base.first_seen = finding.first_seen
        if finding.last_seen and (base.last_seen is None or finding.last_seen > base.last_seen):
            base.last_seen = finding.last_seen
        for line in finding.evidence:
            base.add_evidence(line)
        for event in finding.events:
            base.add_event(event)
        base.description = base.description or finding.description
        base.recommendation = base.recommendation or finding.recommendation
    return list(merged.values())


def _risk(findings: list[Finding]) -> tuple[float, str]:
    score = round(sum(f.score for f in findings if f.severity >= Severity.LOW), 1)
    criticals = [f for f in findings if f.severity == Severity.CRITICAL]
    if score >= 100 or (criticals and score >= 60 and len(criticals) >= 2):
        verdict = "严重：高度疑似主机已被入侵"
    elif score >= 40 or criticals:
        verdict = "高危：存在明显入侵迹象"
    elif score >= 15:
        verdict = "中危：存在可疑行为，需进一步核实"
    elif score > 0:
        verdict = "低危：存在配置风险或弱迹象"
    else:
        verdict = "未发现明显风险"
    return score, verdict


def _logon_summary(
    events: list[Event],
) -> tuple[dict, list[tuple[str, int]], list[tuple[str, int]]]:
    success = [e for e in events if e.event_id == 4624]
    failure = [e for e in events if e.event_id == 4625]
    rdp = [e for e in success if e.logon_type == "10"] + [
        e for e in events if e.log in {"rdp_lsm", "rdp_rcm"} and e.event_id in {21, 1149}
    ]
    users = Counter(e.target for e in success if e.target and not e.is_machine_account)
    types = Counter(e.logon_type or "未知" for e in success)
    external_success = [e for e in success if ip_kind(e.ip) == "public"]
    external_failure = [e for e in failure if ip_kind(e.ip) == "public"]
    stats = {
        "success": len(success),
        "failure": len(failure),
        "failure_success_ratio": round(len(failure) / max(1, len(success)), 2),
        "rdp": len(rdp),
        "distinct_users": len(users),
        "logon_types": types.most_common(),
        "external_success": len(external_success),
        "external_failure": len(external_failure),
    }
    fail_ips = Counter(e.ip for e in failure if ip_kind(e.ip) == "public")
    fail_ips += Counter(e.ip for e in failure if ip_kind(e.ip) == "private")
    return stats, fail_ips.most_common(10), users.most_common(10)


# ---------------------------------------------------------------------------
# IOC
# ---------------------------------------------------------------------------
def _ioc(values: Iterable[str], limit: int = 50) -> list[str]:
    seen: list[str] = []
    for value in values:
        text = str(value or "").strip().strip("。，；,;")
        if not text or text in seen or len(text) > 260:
            continue
        seen.append(text)
        if len(seen) >= limit:
            break
    return seen


def _extract_iocs(
    events: list[Event],
    findings: list[Finding],
    iis_records: list,
    iis_stats: dict,
) -> dict[str, list[str]]:
    urls: list[str] = []
    files: list[str] = []
    hashes: list[str] = []
    processes: list[str] = []
    ips: list[str] = []
    users: list[str] = []
    services: list[str] = []
    tasks: list[str] = []
    registries: list[str] = []
    user_agents: list[str] = []

    for finding in findings:
        entities = finding.entities
        if entities.get("ip") and ip_kind(entities["ip"]) == "public":
            ips.append(entities["ip"])
        if entities.get("user"):
            users.append(entities["user"])
        if entities.get("service"):
            services.append(entities["service"])
        if entities.get("task"):
            tasks.append(entities["task"])
        if entities.get("registry"):
            registries.append(entities["registry"])
        if entities.get("process"):
            processes.append(entities["process"])

    for event in events:
        cmd = command_line(event) or ""
        for match in URL_RE.findall(cmd):
            urls.append(match)
        for match in WIN_PATH_RE.findall(cmd):
            files.append(match)
        if event.log == "sysmon" and event.event_id == 1:
            image = process_name(event)
            if image:
                processes.append(image)
        if event.event_id in {4625, 4624} and ip_kind(event.ip) == "public":
            ips.append(event.ip)
        for key, value in event.data.items():
            lower = key.lower()
            if lower in {"sha256", "sha1", "md5", "hashes", "filehash", "hash"} and value:
                for match in HASH_RE.findall(str(value)):
                    hashes.append(match)
        if event.log == "powershell" and event.event_id == 4104:
            text = event.get("ScriptBlockText", "ScriptBlock") or event.message
            for match in URL_RE.findall(text or ""):
                urls.append(match)

    for record in iis_records:
        if record.ip and ip_kind(record.ip) == "public":
            ips.append(record.ip)
        if record.user_agent and any(
            token in record.user_agent.lower()
            for token in ("sqlmap", "nikto", "nmap", "masscan", "gobuster", "dirbuster", "nuclei")
        ):
            user_agents.append(record.user_agent[:160])

    return {
        "ip": _ioc(ips),
        "url": _ioc(urls),
        "file": _ioc(files),
        "hash": _ioc(hashes),
        "process": _ioc(processes),
        "user": _ioc(users),
        "service": _ioc(services),
        "task": _ioc(tasks),
        "registry": _ioc(registries),
        "user_agent": _ioc(user_agents),
    }


# ---------------------------------------------------------------------------
# 时间线 & 覆盖率
# ---------------------------------------------------------------------------
def _build_timeline(findings: list[Finding]) -> list[dict]:
    entries = []
    for finding in findings:
        if finding.severity < Severity.MEDIUM or not finding.first_seen:
            continue
        entities = ", ".join(f"{k}={v}" for k, v in finding.entities.items() if v)
        entries.append(
            {
                "time": finding.first_seen.isoformat(),
                "display": fmt_time(finding.first_seen),
                "title": finding.title,
                "rule_id": finding.rule_id,
                "severity": finding.severity.label,
                "severity_value": int(finding.severity),
                "entities": entities,
            }
        )
    entries.sort(key=lambda item: item["time"])
    return entries[:120]


def _coverage(
    events: list[Event],
    collection: list[dict],
    parse_errors: int,
    dropped: int,
    report: AuditReport,
) -> list[str]:
    notes: list[str] = []
    status_notes: list[str] = []
    for item in collection:
        status = item.get("status")
        label = item.get("label") or item.get("log")
        if status == "ok":
            continue
        if status == "empty":
            status_notes.append(f"{label} 未采集到相关事件（可能日志为空或审核未开启）。")
        elif status in {"unavailable", "denied", "error", "skipped"}:
            error = item.get("error") or ""
            status_notes.append(f"{label} 采集状态：{status}。{error}".strip())

    total = len(events)
    if total == 0:
        notes.append(
            "未解析到任何事件，无法给出可靠结论。请检查采集权限、日志是否启用或导出文件是否正确。"
        )
        notes.extend(status_notes)
        return notes

    times = [event.time for event in events if event.time]
    if times:
        notes.append(
            f"事件时间范围：{fmt_time(min(times))} ~ {fmt_time(max(times))}（本地时区）。"
        )
    notes.append(
        "各日志解析条数："
        + "，".join(f"{LOG_LABELS.get(k, k)} {v}" for k, v in report.event_counts.items())
    )
    notes.extend(status_notes)

    process_events = [e for e in events if e.event_id == 4688]
    if process_events:
        with_cmd = [e for e in process_events if command_line(e)]
        if not with_cmd:
            notes.append(
                "事件 4688 未包含命令行参数，进程执行细节缺失；"
                "建议启用“审核进程创建 + 包含命令行”或部署 Sysmon。"
            )
        elif len(with_cmd) < len(process_events):
            notes.append(
                f"事件 4688 中仅 {len(with_cmd)}/{len(process_events)} 条包含命令行，命令审计不完整。"
            )

    if not any(e.log == "sysmon" for e in events):
        notes.append("未采集到 Sysmon 日志：进程访问、网络连接、文件落地等细粒度证据缺失。")
    if not any(e.log == "powershell" for e in events):
        notes.append("未采集到 PowerShell 脚本块日志：无文件攻击的可见性受限。")
    if not any(e.log == "security" for e in events):
        notes.append(
            "未采集到安全日志（Security）：登录、账户变更、进程创建等核心审计数据缺失，"
            "结论可能严重不完整，请以管理员权限重新采集。"
        )
    if parse_errors:
        notes.append(f"有 {parse_errors} 条事件 XML 解析失败（已跳过），可能存在日志损坏或编码异常。")
    if dropped:
        notes.append(f"按时间范围过滤掉 {dropped} 条历史事件。")

    if report.iis_stats.get("total"):
        notes.append(
            f"IIS 日志共 {report.iis_stats['total']} 条请求，"
            f"涉及 {report.iis_stats.get('unique_ips', 0)} 个来源 IP。"
        )
    if report.tomcat_stats.get("total") or report.tomcat_stats.get("catalina_events"):
        notes.append(
            f"Tomcat 日志共 {report.tomcat_stats.get('total', 0)} 条请求、"
            f"{report.tomcat_stats.get('catalina_events', 0)} 条容器日志"
            + (f"，版本 {report.tomcat_stats['version']}" if report.tomcat_stats.get("version") else "")
            + "。"
        )
    if report.posture:
        notes.append("已采集主机安全配置基线（Defender、RDP、SMB、审核策略等）。")
    return notes
