"""持久化痕迹检测：服务、计划任务、注册表自启动、WMI 订阅、BITS、驱动。"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from xml.etree import ElementTree as ET

from .knowledge import (
    PROCESS_PATTERNS,
    RUN_KEY_RE,
    SUSPICIOUS_SERVICE_PATH_RE,
    USER_WRITABLE_PATH_RE,
)
from .models import Event, Severity, fmt_time
from .rules_base import RuleContext, evidence_lines, make_finding

TACTIC_PERSISTENCE = "持久化"
TACTIC_EXECUTION = "执行"

_CMD_TAG_RE = re.compile(
    r"<(Command|Arguments|CommandLine)>(.*?)</\1>", re.S | re.I
)
_TASK_NAME_RE = re.compile(r"<URI>(.*?)</URI>|<Name>(.*?)</Name>", re.S | re.I)
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)


def run(ctx: RuleContext) -> None:
    _service_installs(ctx)
    _service_config(ctx)
    _scheduled_tasks(ctx)
    _registry_autoruns(ctx)
    _wmi_subscriptions(ctx)
    _bits_jobs(ctx)
    _sysmon_files(ctx)
    _sysmon_registry(ctx)
    _driver_installs(ctx)


# ---------------------------------------------------------------------------
# 服务
# ---------------------------------------------------------------------------
def _service_fields(event: Event) -> tuple[str, str, str, str, str]:
    name = event.get("ServiceName", "param1")
    image = event.get("ImagePath", "ServiceFileName", "param2")
    service_type = event.get("ServiceType", "param3")
    start_type = event.get("StartType", "ServiceStartType", "param4")
    account = event.get("AccountName", "ServiceAccount", "param5")
    return name, image, service_type, start_type, account


def _is_unquoted_path(path: str) -> bool:
    value = (path or "").strip()
    if not value or value.startswith('"') or value.startswith("'"):
        return False
    if " " not in value:
        return False
    return bool(re.match(r"^[a-zA-Z]:\\[^\"]*?\s[^\"]*?\.(?:exe|com|bat|cmd|ps1)\b", value, re.I))


def _service_severity(name: str, image: str, service_type: str, account: str) -> tuple[Severity, list[str]]:
    reasons: list[str] = []
    severity = Severity.LOW
    lower_name = (name or "").lower()
    lower_image = (image or "").lower()
    lower_type = (service_type or "").lower()
    if any(tag in lower_name for tag in ("psexe", "meterpreter", "beacon", "backdoor", "shell", "hack")):
        severity = Severity.CRITICAL
        reasons.append("服务名具有攻击工具特征")
    if SUSPICIOUS_SERVICE_PATH_RE.search(image or ""):
        severity = Severity.CRITICAL
        reasons.append("服务映像位于用户可写目录或包含脚本/编码命令")
    is_driver = "driver" in lower_type or "kernel" in lower_type or "内核" in lower_type
    if is_driver:
        if "\\system32\\drivers\\" in lower_image:
            severity = max(severity, Severity.MEDIUM)
        else:
            severity = max(severity, Severity.HIGH)
            reasons.append("驱动文件位于非系统目录")
        reasons.append("安装了内核驱动服务")
    if _is_unquoted_path(image):
        severity = max(severity, Severity.HIGH)
        reasons.append("服务路径未加引号且包含空格（可被路径劫持）")
    if lower_image.startswith("\\\\"):
        severity = max(severity, Severity.HIGH)
        reasons.append("服务映像位于网络共享（UNC 路径）")
    if account and account.lower() not in {
        "localsystem",
        "local system",
        "nt authority\\localsystem",
        "nt authority\\localservice",
        "nt authority\\networkservice",
        "localservice",
        "networkservice",
        "",
    }:
        reasons.append(f"服务以非系统账户运行：{account}")
    return severity, reasons


def _service_installs(ctx: RuleContext) -> None:
    events = list(ctx.get(7045)) + list(ctx.get(4697))
    if not events:
        return
    grouped: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in events:
        name, image, _stype, _start, _account = _service_fields(event)
        grouped[(name or "<未知服务>", image)].append(event)

    for (name, image), items in sorted(grouped.items(), key=lambda kv: -len(kv[1]))[:12]:
        first = items[0]
        _n, _i, service_type, start_type, account = _service_fields(first)
        severity, reasons = _service_severity(name, image, service_type, account)
        finding = make_finding(
            "PERSIST-SVC",
            f"服务安装：{name}",
            severity,
            tactic=TACTIC_PERSISTENCE,
            technique="T1543.003 Windows 服务",
            description=(
                f"检测到服务 {name} 被安装（事件 {first.event_id}），"
                f"映像路径：{image or '未知'}，启动类型：{start_type or '未知'}。"
                + (" 风险点：" + "；".join(reasons) if reasons else "")
            ),
            recommendation=(
                "核实服务来源与签名；非授权服务应立即停止并删除，"
                "同时排查该服务的可执行文件哈希与网络连接。"
            ),
            entities={"service": name},
        )
        finding.key = f"svc|{name}|{image}"
        finding.count = len(items)
        finding.add_evidence(f"映像路径: {image or '未知'}")
        finding.add_evidence(
            f"账户: {account or '-'}；服务类型: {service_type or '-'}；启动类型: {start_type or '-'}"
        )
        if reasons:
            finding.add_evidence("风险因素: " + "；".join(reasons))
        for line in evidence_lines(items, ("SubjectUserName", "ServiceName", "ImagePath"), 6):
            finding.add_evidence(line)
        for event in items[:10]:
            finding.add_event(event)
        ctx.add(finding)


def _service_config(ctx: RuleContext) -> None:
    events = ctx.get(7040)
    if not events:
        return
    grouped: dict[tuple[str, str, str], list[Event]] = defaultdict(list)
    for event in events:
        name = event.get("ServiceName", "param1") or "<未知服务>"
        old = event.get("param2", "StartTypeOld")
        new = event.get("param3", "StartTypeNew")
        if not new or old == new:
            continue
        grouped[(name, old, new)].append(event)

    installed_services = {
        (event.get("ServiceName", "param1") or "").lower()
        for event in ctx.get(7045) + ctx.get(4697)
    }
    for (name, old, new), items in list(grouped.items())[:10]:
        severity = Severity.LOW
        reason = ""
        if name.lower() in installed_services:
            severity = Severity.HIGH
            reason = "该服务在审计窗口内被安装，随后修改启动类型，符合持久化配置特征。"
        elif any(
            tag in name.lower() for tag in ("psexe", "beacon", "backdoor", "shell")
        ):
            severity = Severity.MEDIUM
        finding = make_finding(
            "PERSIST-SVC-CONFIG",
            f"服务启动类型变更：{name}（{old} -> {new}）",
            severity,
            tactic=TACTIC_PERSISTENCE,
            technique="T1543.003 Windows 服务",
            description=(
                f"服务 {name} 的启动类型由 {old} 改为 {new}。"
                + reason
                + ("攻击者常将后门服务设置为自动启动以实现持久化。" if not reason else "")
            ),
            recommendation="确认变更来源；非授权变更应恢复原启动类型并排查服务映像。",
            entities={"service": name},
        )
        finding.key = f"svc-config|{name}|{new}"
        finding.count = len(items)
        finding.add_evidence(f"{old or '?'} -> {new}")
        for event in items[:2]:
            finding.add_event(event)
        ctx.add(finding)


# ---------------------------------------------------------------------------
# 计划任务
# ---------------------------------------------------------------------------
def _extract_task_command(content: str) -> str:
    if not content:
        return ""
    parts = [match.group(2).strip() for match in _CMD_TAG_RE.finditer(content)]
    if parts:
        return " ".join(part for part in parts if part)
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return content[:300]
    values = []
    for node in root.iter():
        tag = node.tag.rsplit("}", 1)[-1]
        if tag in {"Command", "Arguments", "CommandLine"} and (node.text or "").strip():
            values.append(node.text.strip())
    return " ".join(values)


def _extract_task_name(event: Event) -> str:
    name = event.get("TaskName")
    if name:
        return name
    content = event.get("TaskContent", "")
    match = _TASK_NAME_RE.search(content)
    if match:
        return (match.group(1) or match.group(2) or "").strip()
    return "<未知任务>"


def _scheduled_tasks(ctx: RuleContext) -> None:
    created = ctx.get(4698)
    updated = ctx.get(4702)
    deleted = ctx.get(4699)

    for event in created[:20]:
        name = _extract_task_name(event)
        content = event.get("TaskContent", "") or event.message
        command = _extract_task_command(content)
        matched = [p for p in PROCESS_PATTERNS if p.regex.search(command or content)]
        severity = Severity.MEDIUM
        reasons = []
        if matched:
            best = max(matched, key=lambda p: p.severity)
            severity = max(severity, best.severity)
            reasons.append(f"任务命令命中 {best.name}：{best.description}")
        if any(tag in name.lower() for tag in ("update", "svc", "system", "windows", "microsoft")):
            if severity < Severity.HIGH:
                severity = Severity.HIGH
            reasons.append("任务名伪装成系统/更新组件")
        finding = make_finding(
            "PERSIST-TASK",
            f"计划任务创建：{name}",
            severity,
            tactic=TACTIC_PERSISTENCE,
            technique="T1053.005 计划任务",
            description=(
                f"检测到计划任务 {name} 被创建，执行命令：{command[:400] or '（无法解析）'}。"
                + (" 风险点：" + "；".join(reasons) if reasons else "")
            ),
            recommendation=(
                "核对任务来源与执行命令；非授权任务应删除，"
                "并检查任务使用的可执行文件与账户权限。"
            ),
            entities={"task": name},
        )
        finding.key = f"task|{name}"
        finding.add_evidence(f"任务名: {name}")
        if command:
            finding.add_evidence(f"执行命令: {command[:400]}")
        if reasons:
            finding.add_evidence("风险因素: " + "；".join(reasons))
        for line in evidence_lines([event], ("SubjectUserName", "TaskName"), 3):
            finding.add_evidence(line)
        finding.add_event(event)
        ctx.add(finding)

    for event in updated[:10]:
        name = _extract_task_name(event)
        content = event.get("TaskContent", "") or event.message
        command = _extract_task_command(content)
        if not any(p.regex.search(command or content) for p in PROCESS_PATTERNS):
            continue
        finding = make_finding(
            "PERSIST-TASK-UPDATE",
            f"计划任务被修改：{name}",
            Severity.HIGH,
            tactic=TACTIC_PERSISTENCE,
            technique="T1053.005 计划任务",
            description=f"计划任务 {name} 被更新，且新命令包含可疑内容：{command[:300]}",
            recommendation="确认修改来源；恢复为可信任务定义并排查执行过的命令。",
            entities={"task": name},
        )
        finding.key = f"task-update|{name}"
        finding.add_event(event)
        ctx.add(finding)

    if deleted:
        finding = make_finding(
            "PERSIST-TASK-DELETE",
            f"计划任务被删除（{len(deleted)} 个）",
            Severity.LOW,
            tactic="防御规避",
            technique="T1070 清除痕迹",
            description="删除计划任务可能是攻击者清理持久化痕迹，也可能是正常运维。",
            recommendation="核对删除操作与操作者；结合其他反取证迹象判断。",
        )
        finding.key = "task-delete"
        finding.count = len(deleted)
        for line in evidence_lines(deleted, ("SubjectUserName", "TaskName"), 6):
            finding.add_evidence(line)
        ctx.add(finding)


# ---------------------------------------------------------------------------
# 注册表自启动
# ---------------------------------------------------------------------------
def _registry_autoruns(ctx: RuleContext) -> None:
    events = []
    for event in ctx.get(4657):
        object_name = event.get("ObjectName", "")
        if RUN_KEY_RE.search(object_name or ""):
            events.append(event)
    if not events:
        return
    grouped: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        grouped[event.get("ObjectName", "未知")].append(event)
    for object_name, items in sorted(grouped.items(), key=lambda kv: -len(kv[1]))[:10]:
        values = Counter(e.get("ObjectValueName") for e in items if e.get("ObjectValueName"))
        finding = make_finding(
            "PERSIST-REG",
            f"自启动注册表项被修改：{object_name}",
            Severity.HIGH,
            tactic=TACTIC_PERSISTENCE,
            technique="T1547.001 注册表 Run 键",
            description=(
                f"注册表 {object_name} 发生 {len(items)} 次值修改，"
                "该位置用于登录自启动，是常见的持久化位置。"
            ),
            recommendation="确认写入内容与来源；非授权值应删除并检查对应程序文件。",
            entities={"registry": object_name},
        )
        finding.key = f"reg|{object_name}"
        finding.count = len(items)
        if values:
            finding.add_evidence("值名: " + ", ".join(v or "-" for v in values))
        for line in evidence_lines(items, ("SubjectUserName", "NewValue", "ObjectValueName"), 6):
            finding.add_evidence(line)
        for event in items[:10]:
            finding.add_event(event)
        ctx.add(finding)


# ---------------------------------------------------------------------------
# WMI 事件订阅（无文件持久化）
# ---------------------------------------------------------------------------
def _wmi_subscriptions(ctx: RuleContext) -> None:
    events = ctx.get(5861) + ctx.get(5860) + ctx.get(5859)
    if not events:
        return
    text = " ".join(
        " ".join(str(v) for v in event.data.values()) for event in events
    ).lower()
    suspicious = any(
        token in text
        for token in (
            "commandlineeventconsumer",
            "activescripteventconsumer",
            "logfileeventconsumer",
            "powershell",
        )
    )
    finding = make_finding(
        "PERSIST-WMI",
        "WMI 永久事件订阅活动",
        Severity.HIGH if suspicious else Severity.MEDIUM,
        tactic=TACTIC_PERSISTENCE,
        technique="T1546.003 WMI 事件订阅",
        description=(
            f"检测到 {len(events)} 条 WMI 永久事件订阅相关事件，"
            "该机制可在不落地文件的情况下执行命令并持久化。"
            + (" 订阅内容包含命令执行消费者，高度可疑。" if suspicious else "")
        ),
        recommendation="使用 Autoruns/WMI 工具枚举 root\\subscription 下的 Filter/Consumer 并删除非授权订阅。",
    )
    finding.key = "wmi-subscription"
    finding.count = len(events)
    for event in events[:6]:
        finding.add_evidence(event.brief(220))
    for event in events[:10]:
        finding.add_event(event)
    ctx.add(finding)


# ---------------------------------------------------------------------------
# BITS 传输（隐蔽下载）
# ---------------------------------------------------------------------------
def _bits_jobs(ctx: RuleContext) -> None:
    events = [e for e in ctx.log("bits") if e.event_id in {59, 60, 3}]
    if not events:
        return
    urls: list[str] = []
    for event in events:
        for value in event.data.values():
            urls.extend(_URL_RE.findall(str(value)))
    suspicious = [
        url
        for url in urls
        if re.search(r"https?://\d{1,3}(?:\.\d{1,3}){3}", url)
        or re.search(r"\.(?:exe|dll|ps1|bat|vbs)(?:\?|$)", url, re.I)
    ]
    finding = make_finding(
        "PERSIST-BITS",
        "BITS 后台传输任务",
        Severity.MEDIUM if suspicious else Severity.LOW,
        tactic=TACTIC_PERSISTENCE,
        technique="T1197 BITS 作业",
        description=(
            f"检测到 {len(events)} 条 BITS 传输事件，BITS 常被滥用于隐蔽下载载荷"
            "并在网络中断后自动重试。"
        ),
        recommendation="使用 Get-BitsTransfer -AllUsers 检查并清除可疑任务，限制 BITS 对公网的访问。",
    )
    finding.key = "bits-job"
    finding.count = len(events)
    for url in urls[:8]:
        finding.add_evidence(f"URL: {url[:200]}")
    for event in events[:8]:
        finding.add_event(event)
    ctx.add(finding)


# ---------------------------------------------------------------------------
# Sysmon：文件与注册表
# ---------------------------------------------------------------------------
def _sysmon_files(ctx: RuleContext) -> None:
    events = [e for e in ctx.log("sysmon") if e.event_id == 11]
    if not events:
        return
    startup = []
    user_writable = []
    for event in events:
        target = event.get("TargetFilename")
        if re.search(r"\\start menu\\programs\\startup\\", target or "", re.I):
            startup.append(event)
        elif USER_WRITABLE_PATH_RE.search(target or "") and re.search(
            r"\.(?:exe|dll|scr|ps1|bat|vbs|js)$", target or "", re.I
        ):
            user_writable.append(event)

    if startup:
        finding = make_finding(
            "PERSIST-STARTUP",
            "启动目录写入可执行文件",
            Severity.HIGH,
            tactic=TACTIC_PERSISTENCE,
            technique="T1547.001 启动文件夹",
            description=f"检测到 {len(startup)} 个文件被写入用户启动目录，登录时会自动执行。",
            recommendation="删除非授权文件，检查创建进程与文件哈希。",
        )
        finding.key = "sysmon-startup"
        finding.count = len(startup)
        for event in startup[:8]:
            finding.add_evidence(
                f"{fmt_time(event.time)} {event.get('TargetFilename')} (进程: {event.get('Image')})"
            )
        for event in startup[:10]:
            finding.add_event(event)
        ctx.add(finding)

    if user_writable:
        finding = make_finding(
            "EXEC-TEMP-FILE",
            "在用户可写目录落地可执行文件",
            Severity.MEDIUM,
            tactic=TACTIC_EXECUTION,
            technique="T1105 传入工具",
            description=(
                f"检测到 {len(user_writable)} 个可执行文件被写入临时/用户目录，"
                "常见于载荷投放或 Webshell 落地。"
            ),
            recommendation="确认文件来源与哈希，必要时提交沙箱分析；限制临时目录执行策略。",
        )
        finding.key = "sysmon-temp-file"
        finding.count = len(user_writable)
        for event in user_writable[:8]:
            finding.add_evidence(
                f"{fmt_time(event.time)} {event.get('TargetFilename')} (进程: {event.get('Image')})"
            )
        for event in user_writable[:10]:
            finding.add_event(event)
        ctx.add(finding)


def _sysmon_registry(ctx: RuleContext) -> None:
    events = [
        e
        for e in ctx.log("sysmon")
        if e.event_id in {12, 13, 14}
        and RUN_KEY_RE.search(e.get("TargetObject", "") or "")
    ]
    if not events:
        return
    finding = make_finding(
        "PERSIST-REG-SYSMON",
        "Sysmon 捕获自启动注册表写入",
        Severity.HIGH,
        tactic=TACTIC_PERSISTENCE,
        technique="T1547.001 注册表 Run 键",
        description=f"Sysmon 记录到 {len(events)} 次自启动注册表写入，可用于建立持久化。",
        recommendation="核对写入值与进程；非授权项立即删除并排查父进程。",
    )
    finding.key = "sysmon-reg-run"
    finding.count = len(events)
    for event in events[:8]:
        finding.add_evidence(
            f"{fmt_time(event.time)} {event.get('TargetObject')}={event.get('Details')} "
            f"(进程: {event.get('Image')})"
        )
    for event in events[:10]:
        finding.add_event(event)
    ctx.add(finding)


# ---------------------------------------------------------------------------
# 驱动安装
# ---------------------------------------------------------------------------
def _driver_installs(ctx: RuleContext) -> None:
    events = ctx.get(20001)
    if not events:
        return
    finding = make_finding(
        "PERSIST-DRIVER",
        f"设备驱动安装（{len(events)} 次）",
        Severity.MEDIUM,
        tactic=TACTIC_PERSISTENCE,
        technique="T1543.001 内核驱动",
        description="检测到新驱动安装。攻击者可通过恶意驱动关闭安全软件或隐藏活动（BYOVD）。",
        recommendation="核对驱动签名与来源，启用驱动签名强制与 HVCI。",
    )
    finding.key = "driver-install"
    finding.count = len(events)
    for event in events[:8]:
        finding.add_evidence(event.brief(200))
    for event in events[:10]:
        finding.add_event(event)
    ctx.add(finding)
