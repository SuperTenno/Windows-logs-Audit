"""事件 ID 知识库、日志采集计划与可疑行为模式。

本模块只放静态知识与编译好的正则，便于在检测规则和报告中复用。
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Severity


@dataclass(frozen=True)
class Pattern:
    """一条可复用的行为特征。"""

    name: str
    regex: re.Pattern
    severity: Severity
    description: str


# ---------------------------------------------------------------------------
# 日志通道
# ---------------------------------------------------------------------------
# key -> (Windows 通道名, 中文名, 默认最大采集条数)
CHANNELS: dict[str, tuple[str, str, int]] = {
    "security": ("Security", "安全日志", 30000),
    "system": ("System", "系统日志", 15000),
    "application": ("Application", "应用日志", 3000),
    "powershell": (
        "Microsoft-Windows-PowerShell/Operational",
        "PowerShell 操作日志",
        10000,
    ),
    "rdp_lsm": (
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        "RDP 本地会话",
        5000,
    ),
    "rdp_rcm": (
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
        "RDP 远程连接",
        5000,
    ),
    "defender": (
        "Microsoft-Windows-Windows Defender/Operational",
        "Defender 防护日志",
        3000,
    ),
    "sysmon": ("Microsoft-Windows-Sysmon/Operational", "Sysmon", 20000),
    "wmi": ("Microsoft-Windows-WMI-Activity/Operational", "WMI 活动", 3000),
    "bits": ("Microsoft-Windows-Bits-Client/Operational", "BITS 传输", 2000),
    "taskscheduler": (
        "Microsoft-Windows-TaskScheduler/Operational",
        "计划任务",
        3000,
    ),
}

LOG_LABELS: dict[str, str] = {key: value[1] for key, value in CHANNELS.items()}

_CHANNEL_LOOKUP = {
    value[0].lower(): key for key, value in CHANNELS.items()
}

# 兼容旧版/别名通道名（全部小写）
_CHANNEL_ALIASES = {
    "windows powershell": "powershell",
    "microsoft-windows-powershell/operational": "powershell",
    "microsoft-windows-sysmon/operational": "sysmon",
    "microsoft-windows-windows defender/operational": "defender",
    "microsoft-windows-terminalservices-localsessionmanager/operational": "rdp_lsm",
    "microsoft-windows-terminalservices-remoteconnectionmanager/operational": "rdp_rcm",
    "microsoft-windows-wmi-activity/operational": "wmi",
    "microsoft-windows-bits-client/operational": "bits",
    "microsoft-windows-taskscheduler/operational": "taskscheduler",
}


def channel_key(channel: str) -> str:
    """把通道名映射为内部 key；未知通道返回空串。"""
    name = (channel or "").strip().lower()
    if not name:
        return ""
    if name in _CHANNEL_LOOKUP:
        return _CHANNEL_LOOKUP[name]
    return _CHANNEL_ALIASES.get(name, "")


# ---------------------------------------------------------------------------
# 事件名称
# ---------------------------------------------------------------------------
SECURITY_EVENT_NAMES: dict[int, str] = {
    104: "日志已清除",
    1100: "事件日志服务已关闭",
    1102: "审核日志已清除",
    4622: "安全包已加载",
    4624: "账户登录成功",
    4625: "账户登录失败",
    4634: "账户已注销",
    4647: "用户发起注销",
    4648: "使用显式凭据登录",
    4649: "检测到重放攻击",
    4656: "请求对象句柄",
    4657: "注册表值已修改",
    4661: "请求对象句柄（SAM/DS）",
    4662: "对对象执行了操作",
    4663: "尝试访问对象",
    4670: "对象的权限已更改",
    4672: "为新登录分配特殊特权",
    4673: "调用了特权服务",
    4674: "对特权对象执行了操作",
    4688: "已创建新进程",
    4689: "进程已退出",
    4697: "服务已安装（安全日志）",
    4698: "已创建计划任务",
    4699: "已删除计划任务",
    4700: "已启用计划任务",
    4701: "已禁用计划任务",
    4702: "已更新计划任务",
    4704: "已分配用户权限",
    4705: "已删除用户权限",
    4719: "系统审核策略已更改",
    4720: "已创建用户账户",
    4722: "已启用用户账户",
    4723: "尝试更改账户密码",
    4724: "尝试重置账户密码",
    4725: "已禁用用户账户",
    4726: "已删除用户账户",
    4728: "成员已添加到全局安全组",
    4729: "成员已从全局安全组删除",
    4732: "成员已添加到本地安全组",
    4733: "成员已从本地安全组删除",
    4735: "已更改启用的安全本地组",
    4738: "已更改用户账户",
    4740: "用户账户已被锁定",
    4756: "成员已添加到通用安全组",
    4757: "成员已从通用安全组删除",
    4764: "组类型已更改",
    4767: "已解锁用户账户",
    4768: "已请求 Kerberos TGT",
    4769: "已请求 Kerberos 服务票证",
    4770: "已续订 Kerberos 票证",
    4771: "Kerberos 预身份验证失败",
    4776: "NTLM 凭据验证",
    4778: "会话已重新连接",
    4779: "会话已断开",
    4781: "账户名称已更改",
    4798: "已枚举用户的本地组",
    4799: "已枚举本地组成员身份",
    4800: "工作站已锁定",
    4801: "工作站已解锁",
    4825: "用户被拒绝访问远程桌面",
    4907: "对象的审核设置已更改",
    4946: "已添加防火墙规则",
    4947: "已修改防火墙规则",
    4948: "已删除防火墙规则",
    4950: "防火墙设置已更改",
    5140: "已访问网络共享对象",
    5145: "已检查网络共享对象的访问权限",
    5379: "已读取凭据管理器中的凭据",
    6416: "已识别新外部设备",
}

SYSTEM_EVENT_NAMES: dict[int, str] = {
    1: "系统时间已更改",
    41: "内核电源意外关闭",
    104: "日志已清除",
    1001: "错误报告（BugCheck）",
    1074: "系统关机/重启（含发起者）",
    1076: "意外关机原因",
    6005: "事件日志服务已启动",
    6006: "事件日志服务已停止",
    6008: "系统意外关机",
    6013: "系统运行时间",
    7031: "服务意外终止",
    7034: "服务意外终止",
    7040: "服务启动类型已更改",
    7045: "服务已安装",
    20001: "已安装设备驱动程序",
    20003: "已安装设备",
}

POWERSHELL_EVENT_NAMES: dict[int, str] = {
    400: "PowerShell 引擎已启动",
    403: "PowerShell 引擎已停止",
    600: "PowerShell 提供程序已启动",
    800: "已执行管道命令",
    4103: "模块日志",
    4104: "脚本块日志",
    4105: "脚本块已开始",
    4106: "脚本块已结束",
}

DEFENDER_EVENT_NAMES: dict[int, str] = {
    1006: "恶意软件检测",
    1007: "恶意软件处置完成",
    1116: "检测到恶意软件",
    1117: "已对恶意软件执行操作",
    1118: "恶意软件扫描失败",
    1119: "恶意软件处置失败",
    5001: "实时保护已禁用",
    5004: "实时保护配置已更改",
    5007: "防病毒配置已更改",
    5010: "扫描失败",
    5012: "扫描已禁用",
}

RDP_LSM_EVENT_NAMES: dict[int, str] = {
    21: "会话登录成功",
    22: "Shell 启动",
    23: "会话注销",
    24: "会话已断开",
    25: "会话已重新连接",
    39: "会话被拒绝",
    40: "会话已断开（原因）",
}

RDP_RCM_EVENT_NAMES: dict[int, str] = {
    1148: "RDP 连接被拒绝",
    1149: "RDP 网络级身份验证成功",
    1150: "RDP 连接已建立",
}

WMI_EVENT_NAMES: dict[int, str] = {
    5857: "WMI 提供程序已加载",
    5858: "WMI 操作失败",
    5859: "WMI 永久订阅已创建",
    5860: "WMI 事件消费者已注册",
    5861: "WMI 永久事件订阅",
}

BITS_EVENT_NAMES: dict[int, str] = {
    3: "BITS 任务已创建",
    59: "BITS 任务已开始传输",
    60: "BITS 任务已停止",
}

TASK_EVENT_NAMES: dict[int, str] = {
    106: "计划任务已注册",
    140: "计划任务已更新",
    141: "计划任务已删除",
    200: "计划任务已执行",
    201: "计划任务执行完成",
}

SYSMON_EVENT_NAMES: dict[int, str] = {
    1: "进程创建",
    3: "网络连接",
    7: "映像已加载",
    8: "CreateRemoteThread",
    10: "进程访问",
    11: "文件创建",
    12: "注册表对象创建/删除",
    13: "注册表值已设置",
    14: "注册表键/值已重命名",
    22: "DNS 查询",
    23: "文件删除",
    25: "进程篡改",
}

EVENT_NAMES: dict[str, dict[int, str]] = {
    "security": SECURITY_EVENT_NAMES,
    "system": SYSTEM_EVENT_NAMES,
    "application": {},
    "powershell": POWERSHELL_EVENT_NAMES,
    "defender": DEFENDER_EVENT_NAMES,
    "rdp_lsm": RDP_LSM_EVENT_NAMES,
    "rdp_rcm": RDP_RCM_EVENT_NAMES,
    "wmi": WMI_EVENT_NAMES,
    "bits": BITS_EVENT_NAMES,
    "taskscheduler": TASK_EVENT_NAMES,
    "sysmon": SYSMON_EVENT_NAMES,
}


def event_label(event_id: int, log: str = "") -> str:
    """返回“事件ID 中文名”，未知事件只返回 ID。"""
    name = EVENT_NAMES.get(log, {}).get(event_id)
    if not name:
        for table in EVENT_NAMES.values():
            if event_id in table:
                name = table[event_id]
                break
    return f"{event_id} {name}" if name else str(event_id)


# ---------------------------------------------------------------------------
# 采集计划：每个通道只取与入侵分析相关的事件 ID
# ---------------------------------------------------------------------------
COLLECTION_PLAN: dict[str, list[int] | None] = {
    "security": [
        1102, 4622, 4624, 4625, 4634, 4647, 4648, 4649, 4656, 4657, 4661, 4662,
        4663, 4670, 4672, 4673, 4674, 4688, 4689, 4697, 4698, 4699, 4700, 4701,
        4702, 4704, 4705, 4719, 4720, 4722, 4723, 4724, 4725, 4726, 4728, 4729,
        4732, 4733, 4735, 4738, 4740, 4756, 4757, 4764, 4767, 4768, 4769, 4770,
        4771, 4776, 4778, 4779, 4781, 4798, 4799, 4800, 4801, 4825, 4907, 4946,
        4947, 4948, 4950, 5140, 5145, 5379, 6416,
    ],
    "system": [1, 41, 104, 1001, 1074, 1076, 6005, 6006, 6008, 6013, 7031,
               7034, 7040, 7045, 20001, 20003],
    "application": None,
    "powershell": [400, 403, 600, 800, 4103, 4104, 4105, 4106],
    "rdp_lsm": [21, 22, 23, 24, 25, 39, 40],
    "rdp_rcm": [1148, 1149, 1150],
    "defender": [1006, 1007, 1116, 1117, 1118, 1119, 5001, 5004, 5007, 5010, 5012],
    "sysmon": [1, 3, 7, 8, 10, 11, 12, 13, 14, 22, 23, 25],
    "wmi": [5857, 5858, 5859, 5860, 5861],
    "bits": [3, 59, 60],
    "taskscheduler": [106, 140, 141, 200, 201],
}


# ---------------------------------------------------------------------------
# 账户与组
# ---------------------------------------------------------------------------
SENSITIVE_GROUPS = (
    "administrators",
    "domain admins",
    "enterprise admins",
    "schema admins",
    "account operators",
    "server operators",
    "backup operators",
    "print operators",
    "dnsadmins",
    "exchange windows permissions",
    "group policy creator owners",
    "remote desktop users",
    "hyper-v administrators",
)

# 正常系统账户：出现在特权/登录事件里不算异常
NOISE_ACCOUNTS = (
    "system",
    "local service",
    "network service",
    "anonymous logon",
    "defaultuser0",
    "font driver host",
    "window manager",
    "dwm-",
    "umfd-",
    "nt authority\\system",
    "nt authority\\local service",
    "nt authority\\network service",
)


def is_noise_account(name: str) -> bool:
    value = (name or "").strip().lower()
    if not value or value == "-":
        return True
    if value.endswith("$"):
        return True
    return any(value == item or value.startswith(item) for item in NOISE_ACCOUNTS)


# ---------------------------------------------------------------------------
# 进程 / 命令行可疑模式
# ---------------------------------------------------------------------------
_PROCESS_SPECS: list[tuple[str, str, Severity, str]] = [
    # ---- 凭据窃取 ----
    (
        "mimikatz",
        r"\bmimikatz(?:\.exe)?\b|sekurlsa::|lsadump::|kerberos::golden|dpapi::masterkey",
        Severity.CRITICAL,
        "出现 Mimikatz 等凭据窃取工具特征",
    ),
    (
        "lsass_dump",
        r"procdump(?:64)?(?:\.exe)?[^\r\n]{0,100}lsass|comsvcs\.dll[^\r\n]{0,40}minidump|rundll32[^\r\n]{0,100}comsvcs[^\r\n]{0,40}minidump|lsass\.exe[^\r\n]{0,60}\.dmp",
        Severity.CRITICAL,
        "疑似转储 LSASS 内存（凭据提取）",
    ),
    (
        "sam_dump",
        r"reg(?:\.exe)?\s+save\s+hklm\\(?:sam|system|security)\b|ntdsutil|esentutl[^\r\n]{0,60}ntds\.dit",
        Severity.CRITICAL,
        "导出 SAM/SYSTEM/NTDS 等凭据数据库",
    ),
    (
        "volume_shadow_destroy",
        r"vssadmin(?:\.exe)?\s+delete\s+(?:shadows|shadowstorage)|wbadmin(?:\.exe)?\s+delete\s+(?:catalog|backup|systemstatebackup)|bcdedit(?:\.exe)?[^\r\n]{0,60}recoveryenabled\s+no|diskshadow[^\r\n]{0,60}delete",
        Severity.CRITICAL,
        "删除卷影副本/启动恢复项（典型勒索软件前置动作）",
    ),
    (
        "defender_tamper",
        r"(?:set|add)-mppreference[^\r\n]{0,160}(?:disablerealtimemonitoring|disableioavprotection|disablebehaviormonitoring|disableantispyware|exclusionpath|exclusionprocess|exclusionextension)|sc(?:\.exe)?\s+(?:stop|delete)\s+(?:windefend|sense)|net\s+stop\s+(?:windefend|sense)|reg(?:\.exe)?\s+add[^\r\n]{0,160}disableantispyware|taskkill[^\r\n]{0,80}msmpeng",
        Severity.CRITICAL,
        "关闭或篡改 Windows Defender 防护",
    ),
    (
        "anti_forensics",
        r"wevtutil(?:\.exe)?\s+(?:cl|clear-log)|clear-eventlog|auditpol[^\r\n]{0,40}/clear|fsutil[^\r\n]{0,60}usn\s+deletejournal|cipher(?:\.exe)?\s+/w\b",
        Severity.CRITICAL,
        "清除日志/审计记录等反取证操作",
    ),
    # ---- 执行与下载 ----
    (
        "encoded_powershell",
        r"powershell(?:\.exe)?[^\r\n]{0,240}?\s-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}|\s-e\s+[A-Za-z0-9+/=]{40,}",
        Severity.HIGH,
        "PowerShell 使用 Base64 编码命令（常见于无文件攻击）",
    ),
    (
        "ps_download_exec",
        r"(?:invoke-webrequest|iwr)[^\r\n]{0,160}-outfile|certutil(?:\.exe)?[^\r\n]{0,100}-urlcache[^\r\n]{0,100}\s-f|bitsadmin(?:\.exe)?[^\r\n]{0,100}/transfer|(?:new-object\s+(?:system\.)?net\.webclient)|downloadstring\(|downloadfile\(|start-bitstransfer",
        Severity.HIGH,
        "从网络下载并执行载荷",
    ),
    (
        "mshta_remote",
        r"mshta(?:\.exe)?\s+(?:https?://|javascript:|vbscript:)",
        Severity.HIGH,
        "mshta 加载远程/脚本内容",
    ),
    (
        "regsvr32_scrobj",
        r"regsvr32(?:\.exe)?[^\r\n]{0,140}(?:scrobj\.dll|/i:https?:)",
        Severity.HIGH,
        "regsvr32 远程脚本加载（Squiblydoo）",
    ),
    (
        "rundll32_suspicious",
        r"rundll32(?:\.exe)?[^\r\n]{0,140}(?:javascript:|https?://|\\(?:temp|appdata|programdata|users\\public)\\[^\r\n]{0,80}\.(?:dll|jpg|txt|dat))",
        Severity.HIGH,
        "rundll32 加载可疑路径或脚本",
    ),
    (
        "wmic_process_create",
        r"wmic(?:\.exe)?[^\r\n]{0,100}process\s+call\s+create",
        Severity.HIGH,
        "WMI 远程/本地创建进程",
    ),
    (
        "schtasks_create",
        r"schtasks(?:\.exe)?[^\r\n]{0,160}/create",
        Severity.HIGH,
        "创建计划任务（持久化）",
    ),
    (
        "service_create",
        r"sc(?:\.exe)?\s+create\s+\S+|sc(?:\.exe)?\s+config\s+\S+[^\r\n]{0,80}binpath",
        Severity.HIGH,
        "创建或修改 Windows 服务（持久化）",
    ),
    (
        "run_key",
        r"reg(?:\.exe)?\s+add[^\r\n]{0,200}\\(?:currentversion\\)?run(?:once)?\b",
        Severity.HIGH,
        "写入注册表 Run 自启动项（持久化）",
    ),
    (
        "local_admin_add",
        r"net(?:\.exe)?\s+localgroup\s+(?:administrators?|admin|remote\s+desktop\s+users)\s+\S+\s+/add",
        Severity.HIGH,
        "将账户加入管理员/远程桌面组（提权）",
    ),
    (
        "user_add",
        r"net(?:\.exe)?\s+user\s+\S+\s+\S+\s+/add",
        Severity.HIGH,
        "创建本地用户账户（持久化）",
    ),
    (
        "firewall_tamper",
        r"netsh(?:\.exe)?[^\r\n]{0,160}(?:advfirewall\s+set\s+\S+\s+state\s+off|firewall\s+set\s+opmode\s+disable|advfirewall\s+set\s+\S+\s+firewallpolicy\s+allowinbound)",
        Severity.HIGH,
        "关闭防火墙或放行全部入站流量",
    ),
    (
        "bcdedit_tamper",
        r"bcdedit(?:\.exe)?[^\r\n]{0,120}(?:set|delete)",
        Severity.HIGH,
        "修改启动配置（可能关闭驱动签名/恢复）",
    ),
    (
        "remote_access_tunnel",
        r"\b(?:ngrok|frpc(?:\.exe)?|nps(?:\.exe)?|chisel|socat|plink(?:\.exe)?)\b",
        Severity.HIGH,
        "出现隧道/远控工具，可能用于持久化外联",
    ),
    (
        "netcat",
        r"\b(?:nc|ncat)(?:\.exe)?\s+-[a-z]*e\b",
        Severity.HIGH,
        "Netcat 反弹 Shell",
    ),
    (
        "credential_recon",
        r"whoami\s+/all|nltest[^\r\n]{0,60}/domain_trusts|net\s+group\s+\"?domain\s+admins\"?\s+/domain",
        Severity.HIGH,
        "账户/域内侦察命令",
    ),
    # ---- 双用途 / 中等风险 ----
    (
        "suspicious_path_exec",
        r"(?:^|[\"\s])(?:[a-z]:\\|\\\\)[^\r\n]{0,140}\\(?:temp|tmp|appdata|programdata|users\\public|downloads|recycle)[^\r\n]{0,80}\.(?:exe|dll|scr|bat|cmd|ps1|vbs|js)\b",
        Severity.HIGH,
        "从用户可写临时目录执行程序",
    ),
    (
        "psexec",
        r"\bpsexec(?:64)?(?:\.exe)?\b",
        Severity.MEDIUM,
        "使用 PsExec（横向移动常用工具）",
    ),
    (
        "archive_stage",
        r"(?:7z|rar)(?:\.exe)?\s+a\s+|compress-archive[^\r\n]{0,160}-destinationpath",
        Severity.MEDIUM,
        "打包归档（可能用于数据外带）",
    ),
    (
        "powershell_hidden",
        r"powershell(?:\.exe)?[^\r\n]{0,240}(?:-nop\b|-noprofile|-w\s+hidden|-windowstyle\s+hidden|-executionpolicy\s+bypass)",
        Severity.MEDIUM,
        "PowerShell 隐藏窗口/绕过执行策略",
    ),
    (
        "curl_download",
        r"(?:curl|wget)(?:\.exe)?[^\r\n]{0,140}(?:-o|--output)\s+\S+",
        Severity.MEDIUM,
        "使用 curl/wget 下载文件",
    ),
    (
        "amsi_bypass",
        r"amsi(?:utils|\.dll)?[^\r\n]{0,100}(?:bypass|initfailed)|amsiinitfailed",
        Severity.HIGH,
        "尝试绕过 AMSI 扫描",
    ),
    (
        "whoami",
        r"\bwhoami(?:\.exe)?(?:\s|$)",
        Severity.INFO,
        "枚举当前账户",
    ),
    (
        "systeminfo",
        r"\bsysteminfo(?:\.exe)?\b",
        Severity.INFO,
        "收集主机信息",
    ),
]

PROCESS_PATTERNS: tuple[Pattern, ...] = tuple(
    Pattern(name, re.compile(regex, re.I), severity, description)
    for name, regex, severity, description in _PROCESS_SPECS
)


# ---------------------------------------------------------------------------
# PowerShell 脚本块可疑模式
# ---------------------------------------------------------------------------
_PS_SPECS: list[tuple[str, str, Severity, str]] = [
    (
        "ps_mimikatz",
        r"invoke-mimikatz|sekurlsa|kerberos::golden|lsadump",
        Severity.CRITICAL,
        "脚本块包含 Mimikatz 调用",
    ),
    (
        "ps_shellcode",
        r"invoke-shellcode|virtualalloc|createremotethread|marshal\]::copy|reflection\.emit",
        Severity.CRITICAL,
        "脚本块包含 Shellcode 注入代码",
    ),
    (
        "ps_encoded",
        r"frombase64string|encodedcommand|\benc\s+[a-z0-9+/=]{40,}",
        Severity.HIGH,
        "脚本块解码 Base64 内容",
    ),
    (
        "ps_iex",
        r"invoke-expression|\biex\b|\|\s*iex\b|\.\s*\(\s*new-object",
        Severity.HIGH,
        "脚本块使用动态执行（IEX）",
    ),
    (
        "ps_download",
        r"downloadstring|downloadfile|invoke-webrequest|start-bitstransfer|net\.webclient|invoke-restmethod",
        Severity.HIGH,
        "脚本块下载远程内容",
    ),
    (
        "ps_amsi",
        r"amsiutils|amsiinitfailed|\bamsi\s+bypass|amsi\.dll[^\r\n]{0,60}(?:bypass|0x0|failed)",
        Severity.HIGH,
        "脚本块尝试绕过 AMSI/关闭防护",
    ),
    (
        "ps_persistence",
        r"register-scheduledtask|new-service|schtasks|currentversion\\run|sc\.exe\s+create",
        Severity.HIGH,
        "脚本块建立持久化",
    ),
    (
        "ps_credential",
        r"convertto-securestring[^\r\n]{0,80}-asplaintext|get-credential[^\r\n]{0,80}-credential",
        Severity.MEDIUM,
        "脚本块处理明文凭据",
    ),
    (
        "ps_hidden",
        r"-windowstyle\s+hidden|-w\s+hidden|-noprofile|-nop\b|executionpolicy\s+bypass",
        Severity.MEDIUM,
        "脚本块使用隐藏/绕过参数",
    ),
]

POWERSHELL_PATTERNS: tuple[Pattern, ...] = tuple(
    Pattern(name, re.compile(regex, re.I), severity, description)
    for name, regex, severity, description in _PS_SPECS
)


# ---------------------------------------------------------------------------
# 可疑父子进程关系
# ---------------------------------------------------------------------------
PARENT_CHILD_PAIRS: tuple[tuple[str, str, str], ...] = (
    ("winword.exe", "cmd.exe", "Office 文档启动命令解释器（钓鱼宏）"),
    ("winword.exe", "powershell.exe", "Office 文档启动 PowerShell（钓鱼宏）"),
    ("winword.exe", "mshta.exe", "Office 文档启动 mshta（钓鱼宏）"),
    ("winword.exe", "wscript.exe", "Office 文档启动脚本宿主（钓鱼宏）"),
    ("excel.exe", "cmd.exe", "Excel 启动命令解释器（钓鱼宏）"),
    ("excel.exe", "powershell.exe", "Excel 启动 PowerShell（钓鱼宏）"),
    ("powerpnt.exe", "cmd.exe", "PowerPoint 启动命令解释器（钓鱼宏）"),
    ("outlook.exe", "cmd.exe", "Outlook 启动命令解释器（钓鱼附件）"),
    ("outlook.exe", "powershell.exe", "Outlook 启动 PowerShell（钓鱼附件）"),
    ("wps.exe", "cmd.exe", "WPS 启动命令解释器（钓鱼文档）"),
    ("w3wp.exe", "cmd.exe", "IIS 工作进程启动 cmd（WebShell 命令执行）"),
    ("w3wp.exe", "powershell.exe", "IIS 工作进程启动 PowerShell（WebShell）"),
    ("w3wp.exe", "cscript.exe", "IIS 工作进程启动 cscript（WebShell）"),
    ("w3wp.exe", "mshta.exe", "IIS 工作进程启动 mshta（WebShell）"),
    ("httpd.exe", "cmd.exe", "Web 服务进程启动 cmd（WebShell）"),
    ("nginx.exe", "cmd.exe", "Web 服务进程启动 cmd（WebShell）"),
    ("sqlservr.exe", "cmd.exe", "SQL Server 启动 cmd（命令执行）"),
    ("sqlservr.exe", "powershell.exe", "SQL Server 启动 PowerShell（命令执行）"),
)

# ---------------------------------------------------------------------------
# 路径 / 注册表
# ---------------------------------------------------------------------------
USER_WRITABLE_PATH_RE = re.compile(
    r"\\(?:temp|tmp|appdata|programdata|users\\public|downloads|recycle(?:r)?|perflogs)\\|"
    r"\\windows\\temp\\|\\\$recycle\.bin\\",
    re.I,
)

SUSPICIOUS_SERVICE_PATH_RE = re.compile(
    r"\\temp\\|\\tmp\\|\\appdata\\|\\programdata\\|\\users\\public\\|\\downloads\\|"
    r"\.bat\b|\.cmd\b|\.ps1\b|\.vbs\b|\.js\b|-enc\b|powershell",
    re.I,
)

RUN_KEY_RE = re.compile(
    r"\\(?:currentversion\\)?run(?:once)?\\|\\winlogon\\|\\image file execution options\\|"
    r"\\currentversion\\windows\\appinit_dlls",
    re.I,
)

# ---------------------------------------------------------------------------
# IIS / Web 攻击特征
# ---------------------------------------------------------------------------
_IIS_SPECS: list[tuple[str, str, Severity, str, str]] = [
    # (name, regex, severity, description, match_target: uri|ua|all)
    (
        "iis_sqli",
        r"union(?:\s|%20|\+)+select|information_schema|sleep\s*\(|benchmark\s*\(|waitfor\s+delay|"
        r"extractvalue\s*\(|updatexml\s*\(|'\s*or\s+'?1'?\s*=\s*'?1|or\s+1\s*=\s*1|"
        r";\s*select\s+|concat\s*\(|group_concat\s*\(",
        Severity.HIGH,
        "SQL 注入尝试",
        "uri",
    ),
    (
        "iis_xss",
        r"<script|%3cscript|onerror\s*=|onload\s*=|javascript:|document\.cookie|alert\s*\(",
        Severity.MEDIUM,
        "跨站脚本攻击尝试",
        "uri",
    ),
    (
        "iis_traversal",
        r"\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|%252e%252e|/etc/passwd|win\.ini|boot\.ini|"
        r"\\windows\\win\.ini",
        Severity.HIGH,
        "路径穿越尝试",
        "uri",
    ),
    (
        "iis_file_inclusion",
        r"=(?:https?|ftp)://|=\\\\|file://|php://|data:text|expect://",
        Severity.HIGH,
        "远程/本地文件包含尝试",
        "uri",
    ),
    (
        "iis_cmd_injection",
        r";\s*(?:id|whoami|cat|ls|ipconfig|net\s+user)\b|\|\s*(?:id|whoami|ipconfig)\b|"
        r"`(?:id|whoami)`|\$\(\s*(?:id|whoami)",
        Severity.HIGH,
        "命令注入尝试",
        "uri",
    ),
    (
        "iis_log4shell",
        r"\$\{jndi:|\$\{java:|\$\{lower:|\$\{env:",
        Severity.CRITICAL,
        "Log4Shell (CVE-2021-44228) 利用尝试",
        "uri",
    ),
    (
        "iis_webshell",
        r"/(?:shell|cmd|exec|backdoor|webshell|c99|r57|b374k|upload)\.(?:asp|aspx|php|jsp)|"
        r"[?&](?:cmd|exec|command|shell|pass|password)=",
        Severity.HIGH,
        "WebShell 访问/上传特征",
        "uri",
    ),
    (
        "iis_sensitive_file",
        r"/\.git/|/\.env\b|/web\.config|/appsettings\.json|/\.svn/|/phpmyadmin|/adminer|"
        r"/actuator|/backup\.|/db\.|\.(?:bak|sql|zip|rar|tar\.gz|7z)(?:\?|$)",
        Severity.MEDIUM,
        "探测敏感文件/备份",
        "uri",
    ),
    (
        "iis_encoded_payload",
        r"[?&][a-z0-9_]+=[a-z0-9+/]{60,}={0,2}",
        Severity.MEDIUM,
        "参数含超长 Base64 编码内容",
        "uri",
    ),
    (
        "iis_scanner_ua",
        r"sqlmap|nikto|nmap|masscan|zgrab|dirbuster|gobuster|wpscan|acunetix|nessus|openvas|"
        r"burp(?:suite)?|nuclei|ffuf|wfuzz|python-requests|go-http-client|curl/|wget/|"
        r"headlesschrome|phantomjs",
        Severity.MEDIUM,
        "自动化扫描器/工具特征",
        "ua",
    ),
    (
        "iis_put_upload",
        r"^/.*\.(?:asp|aspx|php|jsp|jspx|ashx|asmx)$",
        Severity.MEDIUM,
        "向可执行脚本路径发起非 GET 请求（疑似 WebShell 上传）",
        "put",
    ),
]

IIS_PATTERNS: tuple[Pattern, ...] = tuple(
    Pattern(name, re.compile(regex, re.I), severity, description)
    for name, regex, severity, description, _target in _IIS_SPECS
)

IIS_PATTERN_TARGETS: dict[str, str] = {
    name: target for name, _regex, _sev, _desc, target in _IIS_SPECS
}
