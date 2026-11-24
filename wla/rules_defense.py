"""防御规避与日志完整性检测：清日志、关防护、改审计/防火墙、时间变更。"""

from __future__ import annotations

from collections import Counter, defaultdict

from .models import Event, Severity, fmt_time
from .rules_base import RuleContext, evidence_lines, make_finding

TACTIC_DEFENSE = "防御规避"


def run(ctx: RuleContext) -> None:
    _log_cleared(ctx)
    _defender(ctx)
    _audit_policy(ctx)
    _firewall(ctx)
    _time_change(ctx)
    _devices(ctx)
    _log_service(ctx)
    _unexpected_shutdown(ctx)
    _application_errors(ctx)


def _log_cleared(ctx: RuleContext) -> None:
    events = list(ctx.get(1102))
    events += [
        e
        for e in ctx.get(104)
        if e.log == "system" and "eventlog" in (e.provider or "").lower()
    ]
    if not events:
        return
    finding = make_finding(
        "DEF-CLEARLOG",
        "审核日志被清除",
        Severity.CRITICAL,
        tactic=TACTIC_DEFENSE,
        technique="T1070.001 清除 Windows 事件日志",
        description=(
            "检测到安全/系统日志被清除。攻击者在获取权限后常清除日志以破坏取证链，"
            "这也可能是管理员误操作，必须结合操作者与时间点确认。"
        ),
        recommendation=(
            "立即启用日志转发（WEF/SIEM）并离线保全现有日志；核查清除操作者与登录来源，"
            "清除行为本身应视为高风险入侵迹象。"
        ),
    )
    finding.key = "log-cleared"
    finding.count = len(events)
    actors = Counter(e.actor for e in events if e.actor)
    if actors:
        finding.add_evidence("操作者: " + ", ".join(f"{a}({c})" for a, c in actors.most_common(5)))
    for line in evidence_lines(events, ("SubjectUserName", "SubjectDomainName"), 6):
        finding.add_evidence(line)
    for event in events[:10]:
        finding.add_event(event)
    ctx.add(finding)


def _defender(ctx: RuleContext) -> None:
    detections = [e for e in ctx.log("defender") if e.event_id in {1116, 1117, 1006, 1007}]
    if detections:
        by_threat: dict[str, list[Event]] = defaultdict(list)
        for event in detections:
            name = event.get("Threat Name", "ThreatName", "Detection Name") or "未知威胁"
            by_threat[name].append(event)
        for threat, items in sorted(by_threat.items(), key=lambda kv: -len(kv[1]))[:8]:
            finding = make_finding(
                "DEF-MALWARE",
                f"Defender 检出恶意软件：{threat}",
                Severity.CRITICAL,
                tactic="执行",
                technique="T1204 用户执行",
                description=(
                    f"Windows Defender 检出 {threat}（{len(items)} 条事件），"
                    "说明主机上存在或曾存在恶意文件/行为。"
                ),
                recommendation=(
                    "确认处置结果并全盘扫描；提取被检出文件哈希与路径作为 IOC，"
                    "排查其落地方式（下载、U 盘、邮件附件）与执行后的网络行为。"
                ),
                entities={"threat": threat},
            )
            finding.key = f"defender|{threat}"
            finding.count = len(items)
            for event in items[:8]:
                detail = "；".join(
                    f"{k}={v}"
                    for k, v in event.data.items()
                    if k in {"Path", "Process Name", "Action Name", "Severity", "Detection Type"}
                    and v
                )
                finding.add_evidence(f"{fmt_time(event.time)} {detail or event.brief(180)}")
            for event in items[:10]:
                finding.add_event(event)
            ctx.add(finding)

    disabled = [e for e in ctx.log("defender") if e.event_id == 5001]
    if disabled:
        finding = make_finding(
            "DEF-RTP-OFF",
            "Defender 实时保护被关闭",
            Severity.CRITICAL,
            tactic=TACTIC_DEFENSE,
            technique="T1562.001 禁用或修改安全工具",
            description=(
                f"检测到 {len(disabled)} 次实时保护被关闭。攻击者常先关闭杀毒软件再投放载荷，"
                "也可能是未授权的运维操作。"
            ),
            recommendation="立即恢复实时保护，核查关闭操作来源，并全盘扫描排查已投放的恶意文件。",
        )
        finding.key = "defender-rtp-off"
        finding.count = len(disabled)
        for line in evidence_lines(disabled, ("Product Name", "Product Version"), 5):
            finding.add_evidence(line)
        for event in disabled[:10]:
            finding.add_event(event)
        ctx.add(finding)

    config_changes = [e for e in ctx.log("defender") if e.event_id in {5007, 5004}]
    risky = []
    for event in config_changes:
        text = " ".join(str(v) for v in event.data.values()).lower()
        if any(
            token in text
            for token in (
                "disablerealtimemonitoring",
                "disableioavprotection",
                "disablebehaviormonitoring",
                "disableantispyware",
                "exclusion",
            )
        ):
            risky.append(event)
    if risky:
        finding = make_finding(
            "DEF-CONFIG",
            "Defender 配置被修改（关闭项或排除项）",
            Severity.HIGH,
            tactic=TACTIC_DEFENSE,
            technique="T1562.001 禁用或修改安全工具",
            description=(
                f"检测到 {len(risky)} 次 Defender 配置变更，涉及关闭防护或添加排除项，"
                "常被用于让恶意文件免于查杀。"
            ),
            recommendation="复核排除项与配置来源，删除非授权排除路径，恢复默认防护策略。",
        )
        finding.key = "defender-config"
        finding.count = len(risky)
        for event in risky[:8]:
            values = "；".join(
                f"{k}={v}" for k, v in event.data.items() if k in {"Old Value", "New Value", "Value Name"}
            )
            finding.add_evidence(f"{fmt_time(event.time)} {values or event.brief(180)}")
        for event in risky[:10]:
            finding.add_event(event)
        ctx.add(finding)

    failed = [e for e in ctx.log("defender") if e.event_id in {5010, 5012, 1118, 1119}]
    if failed:
        finding = make_finding(
            "DEF-SCAN-FAIL",
            "Defender 扫描/处置失败",
            Severity.MEDIUM,
            tactic=TACTIC_DEFENSE,
            technique="T1562.001 禁用或修改安全工具",
            description=(
                f"检测到 {len(failed)} 条扫描失败或处置失败事件，可能意味着防护被干扰，"
                "或存在无法清除的恶意文件。"
            ),
            recommendation="检查 Defender 服务状态与排除项，执行离线扫描。",
        )
        finding.key = "defender-scan-fail"
        finding.count = len(failed)
        for line in evidence_lines(failed, ("Product Name", "Reason", "Error Code"), 5):
            finding.add_evidence(line)
        ctx.add(finding)


def _audit_policy(ctx: RuleContext) -> None:
    events = ctx.get(4719) + ctx.get(4907)
    if not events:
        return
    finding = make_finding(
        "DEF-AUDIT",
        f"系统审核策略被修改（{len(events)} 次）",
        Severity.MEDIUM,
        tactic=TACTIC_DEFENSE,
        technique="T1562.002 禁用 Windows 事件日志",
        description=(
            "审核策略变更会直接影响日志可见性，攻击者可能通过降低审核级别来隐藏行为。"
        ),
        recommendation="核对变更内容与操作者，确保登录、进程创建、账户管理等关键审计保持启用。",
    )
    finding.key = "audit-policy"
    finding.count = len(events)
    actors = Counter(e.actor for e in events if e.actor)
    if actors:
        finding.add_evidence("操作者: " + ", ".join(f"{a}({c})" for a, c in actors.most_common(5)))
    for event in events[:8]:
        finding.add_evidence(event.brief(220))
    for event in events[:10]:
        finding.add_event(event)
    ctx.add(finding)


def _firewall(ctx: RuleContext) -> None:
    events = [
        e for e in ctx.get(4946) + ctx.get(4947) + ctx.get(4948) + ctx.get(4950)
    ]
    if not events:
        return
    finding = make_finding(
        "DEF-FIREWALL",
        f"Windows 防火墙规则/配置变更（{len(events)} 次）",
        Severity.MEDIUM,
        tactic=TACTIC_DEFENSE,
        technique="T1562.004 禁用或修改系统防火墙",
        description=(
            "防火墙规则变更可能被用于开放后门端口或允许攻击者持续访问。"
        ),
        recommendation="导出当前防火墙规则并与基线比对，删除非授权放行规则。",
    )
    finding.key = "firewall-change"
    finding.count = len(events)
    actors = Counter(e.actor for e in events if e.actor)
    if actors:
        finding.add_evidence("操作者: " + ", ".join(f"{a}({c})" for a, c in actors.most_common(5)))
    for event in events[:8]:
        finding.add_evidence(event.brief(220))
    for event in events[:10]:
        finding.add_event(event)
    ctx.add(finding)


def _time_change(ctx: RuleContext) -> None:
    # 只使用安全日志 4616（系统日志 1 号事件在 NTP 同步时每小时都会产生，噪声极大）
    events = ctx.get(4616)
    if not events:
        return
    finding = make_finding(
        "DEF-TIME",
        f"系统时间被修改（{len(events)} 次）",
        Severity.LOW,
        tactic=TACTIC_DEFENSE,
        technique="T1099 时间戳",
        description="系统时间变更可能影响日志时间线，也可能被用于绕过证书/票据有效期。",
        recommendation="确认时间同步配置（NTP）与变更来源，保证日志时间可信。",
    )
    finding.key = "time-change"
    finding.count = len(events)
    for event in events[:8]:
        finding.add_evidence(event.brief(200))
    for event in events[:10]:
        finding.add_event(event)
    ctx.add(finding)


def _devices(ctx: RuleContext) -> None:
    events = ctx.get(6416) + ctx.get(20003)
    if not events:
        return
    finding = make_finding(
        "DEF-DEVICE",
        f"检测到新外部设备接入（{len(events)} 次）",
        Severity.LOW,
        tactic="外带",
        technique="T1052.001 通过 USB 介质外带",
        description="新设备接入可能是正常外设，也可能是未经授权的 USB 存储设备用于数据外带。",
        recommendation="核对设备白名单；对敏感主机禁用可移动存储，并启用设备安装审计。",
    )
    finding.key = "new-device"
    finding.count = len(events)
    for event in events[:8]:
        finding.add_evidence(event.brief(200))
    ctx.add(finding)


def _log_service(ctx: RuleContext) -> None:
    events = ctx.get(1100)
    if not events:
        return
    finding = make_finding(
        "DEF-LOGSVC",
        "事件日志服务被关闭",
        Severity.LOW,
        tactic=TACTIC_DEFENSE,
        technique="T1562.002 禁用 Windows 事件日志",
        description=f"检测到 {len(events)} 次事件日志服务关闭，需确认是否为计划内维护。",
        recommendation="确保日志服务自启动，并配置日志转发避免本地日志缺失。",
    )
    finding.key = "log-service-stop"
    finding.count = len(events)
    for event in events[:5]:
        finding.add_event(event)
    ctx.add(finding)


def _unexpected_shutdown(ctx: RuleContext) -> None:
    events = ctx.get(41) + ctx.get(6008)
    if len(events) < 3:
        return
    finding = make_finding(
        "DEF-SHUTDOWN",
        f"多次异常关机/重启（{len(events)} 次）",
        Severity.LOW,
        tactic="影响",
        technique="T1529 系统关机/重启",
        description="频繁异常关机可能由硬件故障、驱动崩溃或攻击者强制重启导致。",
        recommendation="检查系统日志中的 BugCheck/驱动错误，排除硬件故障并保留崩溃转储。",
    )
    finding.key = "unexpected-shutdown"
    finding.count = len(events)
    for event in events[:6]:
        finding.add_evidence(event.brief(200))
    ctx.add(finding)


def _application_errors(ctx: RuleContext) -> None:
    """应用日志错误集中，可能是攻击工具崩溃、漏洞利用失败或环境异常。"""
    events = [e for e in ctx.log("application") if e.level is not None and e.level <= 2]
    if len(events) < 10:
        return
    providers = Counter(e.provider or "未知提供程序" for e in events)
    top_provider, top_count = providers.most_common(1)[0]
    severity = Severity.LOW
    if len(events) >= 100 and top_count < len(events) * 0.5:
        severity = Severity.MEDIUM
    finding = make_finding(
        "APP-STABILITY",
        f"应用错误/崩溃事件较多（{len(events)} 条）",
        severity,
        tactic="影响",
        technique="T1499 端点拒绝服务",
        description=(
            f"应用日志中共有 {len(events)} 条错误/严重级别事件，"
            f"涉及 {len(providers)} 个提供程序，最多的是 {top_provider}（{top_count} 条）。"
            "大量崩溃可能由攻击载荷不稳定、漏洞利用失败或资源耗尽导致。"
        ),
        recommendation="检查崩溃模块与时间点是否与可疑进程/服务相关，保留 WER 转储用于分析。",
    )
    finding.key = "app-errors"
    finding.count = len(events)
    finding.add_evidence(
        "提供程序 Top: "
        + ", ".join(f"{name}({count})" for name, count in providers.most_common(6))
    )
    for event in events[:6]:
        finding.add_event(event)
    ctx.add(finding)
