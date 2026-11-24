"""执行与凭据访问痕迹：可疑命令行、父子进程、PowerShell、LSASS 访问。"""

from __future__ import annotations

import datetime as dt
import re
from collections import Counter, defaultdict

from .knowledge import (
    PARENT_CHILD_PAIRS,
    POWERSHELL_PATTERNS,
    PROCESS_PATTERNS,
    USER_WRITABLE_PATH_RE,
)
from .models import Event, Severity, fmt_time
from .rules_base import (
    RuleContext,
    basename,
    command_line,
    evidence_lines,
    make_finding,
    parent_name,
    process_name,
)

TACTIC_EXECUTION = "执行"
TACTIC_CREDENTIAL = "凭据访问"
TACTIC_DEFENSE = "防御规避"

# 对 LSASS 的典型恶意访问掩码
_LSASS_SUSPICIOUS_ACCESS = {
    "0x1010",
    "0x1410",
    "0x1438",
    "0x143a",
    "0x1fffff",
    "0x1418",
    "0x40",
    "0x1000",
}


def run(ctx: RuleContext) -> None:
    process_events = _process_events(ctx)
    _suspicious_commands(ctx, process_events)
    _parent_child(ctx, process_events)
    _powershell_scriptblocks(ctx)
    _sysmon_lsass(ctx)
    _sysmon_remote_thread(ctx)
    _sysmon_tamper(ctx)
    _credential_manager(ctx)


def _process_events(ctx: RuleContext) -> list[Event]:
    events = []
    for event in ctx.get(4688):
        if command_line(event) or process_name(event):
            events.append(event)
    for event in ctx.log("sysmon"):
        if event.event_id == 1 and (command_line(event) or process_name(event)):
            events.append(event)
    events.sort(key=lambda e: e.time or dt.datetime.min.replace(tzinfo=dt.timezone.utc))
    return events


def _dedupe(events: list[Event]) -> list[Event]:
    """同一进程可能同时出现在 4688 与 Sysmon 中，按命令+秒去重。"""
    seen = set()
    result = []
    for event in events:
        cmd = command_line(event) or process_name(event)
        stamp = event.time.replace(microsecond=0) if event.time else None
        key = ((cmd or "").lower(), stamp)
        if key in seen:
            continue
        seen.add(key)
        result.append(event)
    return result


def _suspicious_commands(ctx: RuleContext, events: list[Event]) -> None:
    events = _dedupe(events)
    if not events:
        return

    matched: dict[str, list[tuple[Event, str]]] = defaultdict(list)
    for event in events:
        text = command_line(event) or process_name(event)
        for pattern in PROCESS_PATTERNS:
            if pattern.regex.search(text):
                matched[pattern.name].append((event, text))

    for pattern in PROCESS_PATTERNS:
        hits = matched.get(pattern.name)
        if not hits or pattern.severity <= Severity.INFO:
            continue
        commands = []
        for _event, text in hits:
            trimmed = text[:400]
            if trimmed not in commands:
                commands.append(trimmed)
        finding = make_finding(
            f"EXEC-{pattern.name.upper()}",
            f"可疑命令执行：{pattern.description}",
            pattern.severity,
            tactic=TACTIC_EXECUTION,
            technique=_technique_for(pattern.name),
            description=(
                f"检测到 {len(hits)} 次与“{pattern.description}”匹配的命令执行，"
                "命令内容与进程链已记录在证据中。"
            ),
            recommendation=(
                "确认执行者与业务用途；若为攻击行为，立即隔离主机、"
                "采集进程内存与磁盘证据，并重置在该主机使用过的凭据。"
            ),
        )
        finding.key = f"exec-{pattern.name}"
        finding.count = len(hits)
        for command in commands[:6]:
            finding.add_evidence(f"命令: {command}")
        users = Counter(e.get("SubjectUserName", "User") for e, _ in hits if e.get("SubjectUserName", "User"))
        if users:
            finding.add_evidence("执行账户: " + ", ".join(f"{u}({c})" for u, c in users.most_common(4)))
        for event, _text in hits[:10]:
            finding.add_event(event)
        ctx.add(finding)


def _parent_child(ctx: RuleContext, events: list[Event]) -> None:
    pairs: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in _dedupe(events):
        parent = basename(parent_name(event))
        child = basename(process_name(event))
        if not parent or not child:
            continue
        for expected_parent, expected_child, _reason in PARENT_CHILD_PAIRS:
            if parent == expected_parent and child == expected_child:
                pairs[(expected_parent, expected_child)].append(event)
                break

    reasons = {(p, c): r for p, c, r in PARENT_CHILD_PAIRS}
    for pair, items in pairs.items():
        reason = reasons.get(pair, "异常的父子进程关系")
        finding = make_finding(
            "EXEC-PARENT-CHILD",
            f"异常父子进程：{pair[0]} -> {pair[1]}",
            Severity.CRITICAL,
            tactic=TACTIC_EXECUTION,
            technique="T1204 用户执行 / T1059 命令执行",
            description=(
                f"检测到 {len(items)} 次 {pair[0]} 启动 {pair[1]}：{reason}。"
                "正常业务流程很少出现该组合，通常意味着宏病毒、钓鱼附件或 WebShell 命令执行。"
            ),
            recommendation=(
                "立即隔离主机并保存进程树与命令行；检查文档来源、Web 目录中的可疑脚本，"
                "以及该进程后续的网络连接与文件落地。"
            ),
            entities={"parent": pair[0], "child": pair[1]},
        )
        finding.key = f"exec-pc|{pair[0]}|{pair[1]}"
        finding.count = len(items)
        for event in items[:8]:
            finding.add_evidence(
                f"{fmt_time(event.time)} 父={parent_name(event)} 子={process_name(event)} "
                f"命令行={command_line(event)[:300]}"
            )
        for event in items[:10]:
            finding.add_event(event)
        ctx.add(finding)


def _powershell_scriptblocks(ctx: RuleContext) -> None:
    events = [
        e
        for e in ctx.log("powershell")
        if e.event_id in {4104, 4103} and (e.get("ScriptBlockText", "ScriptBlock", "Message") or e.message)
    ]
    if not events:
        return

    matched: dict[str, list[tuple[Event, str]]] = defaultdict(list)
    for event in events:
        text = event.get("ScriptBlockText", "ScriptBlock") or event.message
        for pattern in POWERSHELL_PATTERNS:
            if pattern.regex.search(text):
                matched[pattern.name].append((event, text))

    for pattern in POWERSHELL_PATTERNS:
        hits = matched.get(pattern.name)
        if not hits:
            continue
        snippets = []
        for _event, text in hits:
            snippet = re.sub(r"\s+", " ", text).strip()[:400]
            if snippet and snippet not in snippets:
                snippets.append(snippet)
        finding = make_finding(
            f"PS-{pattern.name.upper()}",
            f"PowerShell 可疑脚本块：{pattern.description}",
            pattern.severity,
            tactic=TACTIC_EXECUTION,
            technique="T1059.001 PowerShell",
            description=(
                f"PowerShell 脚本块日志（4104）中检测到 {len(hits)} 段内容匹配"
                f"“{pattern.description}”，说明执行过对应脚本。"
            ),
            recommendation=(
                "提取完整脚本块进行人工分析；启用约束语言模式与 AppLocker/WDAC，"
                "限制 PowerShell 仅允许签名脚本。"
            ),
        )
        finding.key = f"ps-{pattern.name}"
        finding.count = len(hits)
        for snippet in snippets[:5]:
            finding.add_evidence(f"脚本: {snippet}")
        for event, _text in hits[:8]:
            finding.add_event(event)
        ctx.add(finding)


def _sysmon_lsass(ctx: RuleContext) -> None:
    events = [
        e
        for e in ctx.log("sysmon")
        if e.event_id == 10 and basename(e.get("TargetImage")) == "lsass.exe"
    ]
    if not events:
        return
    by_source: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        by_source[event.get("SourceImage", "未知进程")].append(event)

    for source, items in sorted(by_source.items(), key=lambda kv: -len(kv[1]))[:8]:
        masks = {e.get("GrantedAccess") for e in items if e.get("GrantedAccess")}
        suspicious = bool(masks & _LSASS_SUSPICIOUS_ACCESS) or bool(
            USER_WRITABLE_PATH_RE.search(source)
        )
        finding = make_finding(
            "EXEC-LSASS-ACCESS",
            f"LSASS 进程内存访问：{source}",
            Severity.CRITICAL if suspicious else Severity.HIGH,
            tactic=TACTIC_CREDENTIAL,
            technique="T1003.001 LSASS 内存",
            description=(
                f"进程 {source} 访问了 LSASS 内存（{len(items)} 次），"
                f"访问掩码：{', '.join(sorted(masks)) or '未知'}。"
                "LSASS 保存着登录凭据哈希，正常业务进程极少访问它。"
            ),
            recommendation=(
                "立即采集该进程文件与内存证据，确认是否为 Mimikatz/Procdump 等工具；"
                "启用 LSA 保护（RunAsPPL）与 Credential Guard，重置已暴露账户口令。"
            ),
            entities={"process": source},
        )
        finding.key = f"lsass-access|{source}"
        finding.count = len(items)
        for event in items[:8]:
            finding.add_evidence(
                f"{fmt_time(event.time)} 访问掩码={event.get('GrantedAccess')} "
                f"调用栈={event.get('CallTrace', '')[:160]}"
            )
        for event in items[:10]:
            finding.add_event(event)
        ctx.add(finding)


def _sysmon_remote_thread(ctx: RuleContext) -> None:
    events = [
        e
        for e in ctx.log("sysmon")
        if e.event_id == 8 and basename(e.get("TargetImage")) != basename(e.get("SourceImage"))
    ]
    if not events:
        return
    grouped: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in events:
        grouped[(event.get("SourceImage", "?"), event.get("TargetImage", "?"))].append(event)
    for (source, target), items in sorted(grouped.items(), key=lambda kv: -len(kv[1]))[:5]:
        finding = make_finding(
            "EXEC-REMOTE-THREAD",
            f"远程线程注入：{basename(source)} -> {basename(target)}",
            Severity.CRITICAL,
            tactic=TACTIC_DEFENSE,
            technique="T1055 进程注入",
            description=(
                f"检测到 {len(items)} 次跨进程创建远程线程，"
                "是进程注入、无文件执行与凭据窃取的典型技术。"
            ),
            recommendation="隔离主机并转储相关进程内存，排查注入源进程的加载模块与网络行为。",
            entities={"source": source, "target": target},
        )
        finding.key = f"remote-thread|{source}|{target}"
        finding.count = len(items)
        for event in items[:6]:
            finding.add_evidence(
                f"{fmt_time(event.time)} start={event.get('StartAddress')} 调用栈={event.get('CallTrace','')[:160]}"
            )
        for event in items[:8]:
            finding.add_event(event)
        ctx.add(finding)


def _sysmon_tamper(ctx: RuleContext) -> None:
    events = [e for e in ctx.log("sysmon") if e.event_id == 25]
    if not events:
        return
    finding = make_finding(
        "EXEC-TAMPER",
        "Sysmon 检测到进程篡改",
        Severity.HIGH,
        tactic=TACTIC_DEFENSE,
        technique="T1562.001 禁用或修改安全工具",
        description=(
            f"检测到 {len(events)} 次进程篡改行为，攻击者可能试图对安全工具或监控进程下手。"
        ),
        recommendation="核查被篡改进程，重启 Sysmon 并检查其配置是否被修改。",
    )
    finding.key = "sysmon-tamper"
    finding.count = len(events)
    for event in events[:8]:
        finding.add_evidence(event.brief(200))
    ctx.add(finding)


def _credential_manager(ctx: RuleContext) -> None:
    events = ctx.get(5379)
    if not events:
        return
    finding = make_finding(
        "EXEC-CRED-READ",
        "凭据管理器中的凭据被读取",
        Severity.MEDIUM,
        tactic=TACTIC_CREDENTIAL,
        technique="T1555.004 Windows 凭据管理器",
        description=f"检测到 {len(events)} 次读取凭据管理器条目，可能是凭据收集行为。",
        recommendation="确认读取进程；限制保存的域凭据，启用 Credential Guard。",
    )
    finding.key = "cred-read"
    finding.count = len(events)
    for line in evidence_lines(events, ("SubjectUserName", "TargetName", "ProcessName"), 6):
        finding.add_evidence(line)
    for event in events[:8]:
        finding.add_event(event)
    ctx.add(finding)


_TECHNIQUE_MAP = {
    "mimikatz": "T1003 凭据转储",
    "lsass_dump": "T1003.001 LSASS 内存",
    "sam_dump": "T1003.002 安全账户管理器",
    "volume_shadow_destroy": "T1490 禁止系统恢复",
    "defender_tamper": "T1562.001 禁用或修改安全工具",
    "anti_forensics": "T1070 清除痕迹",
    "encoded_powershell": "T1059.001 PowerShell",
    "ps_download_exec": "T1105 传入工具",
    "mshta_remote": "T1218.005 Mshta",
    "regsvr32_scrobj": "T1218.010 Regsvr32",
    "rundll32_suspicious": "T1218.011 Rundll32",
    "wmic_process_create": "T1047 WMI",
    "schtasks_create": "T1053.005 计划任务",
    "service_create": "T1543.003 Windows 服务",
    "run_key": "T1547.001 注册表 Run 键",
    "local_admin_add": "T1098 账户操纵",
    "user_add": "T1136.001 创建本地账户",
    "firewall_tamper": "T1562.004 禁用或修改系统防火墙",
    "bcdedit_tamper": "T1542.003 启动配置修改",
    "remote_access_tunnel": "T1219 远程访问软件",
    "netcat": "T1059 命令执行",
    "credential_recon": "T1033 系统所有者/用户发现",
    "suspicious_path_exec": "T1204 用户执行",
    "psexec": "T1021.002 SMB/Windows 管理共享",
    "archive_stage": "T1560 归档收集的数据",
    "powershell_hidden": "T1059.001 PowerShell",
    "curl_download": "T1105 传入工具",
    "amsi_bypass": "T1562.001 禁用或修改安全工具",
}


def _technique_for(pattern_name: str) -> str:
    return _TECHNIQUE_MAP.get(pattern_name, "T1059 命令执行")
