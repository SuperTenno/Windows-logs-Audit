"""主机安全配置基线检测（依赖采集端返回的 posture 数据）。"""

from __future__ import annotations

from .models import Severity
from .rules_base import RuleContext, make_finding

TACTIC_HARDENING = "加固配置"


def run(ctx: RuleContext) -> None:
    posture = getattr(ctx, "posture", None) or {}
    if not posture:
        return
    _defender(ctx, posture)
    _rdp(ctx, posture)
    _credentials(ctx, posture)
    _network(ctx, posture)
    _accounts(ctx, posture)
    _logging(ctx, posture)


def _truthy(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in {"true", "1", "yes", "on", "enabled"}


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [item for item in value if item]
    return [value]


def _defender(ctx: RuleContext, posture: dict) -> None:
    defender = posture.get("defender") or {}
    if not isinstance(defender, dict):
        return
    realtime = defender.get("realtime")
    antivirus = defender.get("antivirus")
    if realtime is not None and not _truthy(realtime):
        # Defender 未运行可能只是被第三方杀软接管，避免直接判定为严重
        third_party = antivirus is not None and not _truthy(antivirus)
        severity = Severity.MEDIUM if third_party else Severity.CRITICAL
        finding = make_finding(
            "POST-DEFENDER",
            "Defender 实时保护未开启",
            severity,
            tactic="防御规避",
            technique="T1562.001 禁用或修改安全工具",
            description=(
                "主机实时保护处于关闭状态。"
                + (
                    "同时 Defender 防病毒引擎也未运行，可能由第三方安全软件接管，"
                    "请确认第三方防护确实生效且未被关闭。"
                    if third_party
                    else "恶意文件可以在不被拦截的情况下执行。"
                )
            ),
            recommendation=(
                "确认主机是否有正常运行的第三方杀软；如无，请立即启用 Defender 实时保护与云保护。"
            ),
        )
        finding.key = "posture-defender-rtp"
        finding.add_evidence(f"AntivirusEnabled={antivirus}, RealTimeProtectionEnabled={realtime}")
        ctx.add(finding)

    exclusions = _as_list(posture.get("defender_exclusions"))
    exclusions = [str(x) for x in exclusions if str(x).strip() not in {"", "False", "None"}]
    if exclusions:
        finding = make_finding(
            "POST-EXCLUSION",
            "Defender 存在排除项",
            Severity.HIGH,
            tactic="防御规避",
            technique="T1562.001 禁用或修改安全工具",
            description=(
                f"Defender 配置了 {len(exclusions)} 个排除路径/进程。攻击者取得权限后常添加排除项，"
                "使恶意文件不被扫描。"
            ),
            recommendation="逐项确认排除项业务必要性，删除无法说明来源的排除路径。",
        )
        finding.key = "posture-defender-exclusion"
        finding.add_evidence("排除项: " + "；".join(exclusions[:10]))
        ctx.add(finding)


def _rdp(ctx: RuleContext, posture: dict) -> None:
    enabled = posture.get("rdp_enabled")
    if enabled is None:
        return
    nla = posture.get("rdp_nla")
    if _truthy(enabled) and nla is not None and not _truthy(nla):
        finding = make_finding(
            "POST-RDP-NLA",
            "远程桌面已启用但未要求网络级身份验证（NLA）",
            Severity.HIGH,
            tactic="初始访问",
            technique="T1021.001 远程桌面协议",
            description=(
                "RDP 未启用 NLA 时，攻击者可在建立会话前进行口令猜测，"
                "并且部分 RDP 漏洞（如 BlueKeep）无需认证即可利用。"
            ),
            recommendation="启用 NLA（UserAuthentication=1），通过 VPN/堡垒机限制访问来源，并启用 MFA。",
        )
        finding.key = "posture-rdp-nla"
        finding.add_evidence(f"RDP 端口: {posture.get('rdp_port', '3389')}")
        ctx.add(finding)


def _credentials(ctx: RuleContext, posture: dict) -> None:
    try:
        wdigest = int(posture.get("wdigest") or 0)
    except (TypeError, ValueError):
        wdigest = 0
    if wdigest == 1:
        finding = make_finding(
            "POST-WDIGEST",
            "WDigest 明文凭据缓存已启用",
            Severity.HIGH,
            tactic="凭据访问",
            technique="T1003 凭据转储",
            description=(
                "UseLogonCredential=1 会让 LSASS 在内存中保存明文口令，"
                "攻击者转储 LSASS 后可直接获得明文凭据。"
            ),
            recommendation="设置 HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential=0 并重启。",
        )
        finding.key = "posture-wdigest"
        ctx.add(finding)

    if posture.get("lsa_protection") is False:
        finding = make_finding(
            "POST-LSA",
            "LSA 保护（RunAsPPL）未启用",
            Severity.MEDIUM,
            tactic="凭据访问",
            technique="T1003.001 LSASS 内存",
            description=(
                "未启用 LSA 保护时，管理员权限进程可直接读取 LSASS 内存并提取凭据哈希。"
            ),
            recommendation="启用 RunAsPPL 与 Credential Guard（需评估兼容性），限制本地管理员数量。",
        )
        finding.key = "posture-lsa"
        ctx.add(finding)

    if _truthy(posture.get("always_install_elevated")):
        finding = make_finding(
            "POST-AIE",
            "AlwaysInstallElevated 已启用",
            Severity.HIGH,
            tactic="权限提升",
            technique="T1548.002 绕过用户账户控制",
            description=(
                "AlwaysInstallElevated 允许普通用户以 SYSTEM 权限安装 MSI 包，"
                "是经典的本地提权配置缺陷。"
            ),
            recommendation="删除 HKLM/HKCU 下 AlwaysInstallElevated 策略值。",
        )
        finding.key = "posture-aie"
        ctx.add(finding)

    if _truthy(posture.get("autoadminlogon")):
        finding = make_finding(
            "POST-AUTOLOGON",
            "配置了自动登录（AutoAdminLogon）",
            Severity.HIGH,
            tactic="凭据访问",
            technique="T1552.002 注册表中的凭据",
            description=(
                "自动登录会在注册表中保存（或可推导出）账户口令，物理接触或远程读取注册表即可获取。"
            ),
            recommendation="关闭自动登录，删除 Winlogon 下的 DefaultPassword，并使用 LSA Secret 审计。",
        )
        finding.key = "posture-autologon"
        ctx.add(finding)


def _network(ctx: RuleContext, posture: dict) -> None:
    if _truthy(posture.get("smb1")):
        finding = make_finding(
            "POST-SMB1",
            "SMBv1 协议已启用",
            Severity.MEDIUM,
            tactic="横向移动",
            technique="T1210 利用远程服务",
            description="SMBv1 存在 EternalBlue 等已知高危漏洞，且缺乏现代安全特性。",
            recommendation="禁用 SMBv1（Set-SmbServerConfiguration -EnableSMB1Protocol $false），并评估依赖。",
        )
        finding.key = "posture-smb1"
        ctx.add(finding)

    firewall = posture.get("firewall") or []
    disabled = [
        item
        for item in _as_list(firewall)
        if isinstance(item, dict) and item.get("enabled") is not None and not _truthy(item.get("enabled"))
    ]
    if disabled:
        finding = make_finding(
            "POST-FIREWALL",
            "部分防火墙配置文件未启用",
            Severity.MEDIUM,
            tactic="防御规避",
            technique="T1562.004 禁用或修改系统防火墙",
            description="存在未启用的 Windows 防火墙配置文件，主机暴露面增大。",
            recommendation="启用所有配置文件的防火墙，并按最小必要原则配置入站规则。",
        )
        finding.key = "posture-firewall-off"
        finding.add_evidence("未启用: " + ", ".join(str(i.get("name")) for i in disabled))
        ctx.add(finding)


def _accounts(ctx: RuleContext, posture: dict) -> None:
    admins = _as_list(posture.get("local_admins"))
    admin_names = [str(a) for a in admins if str(a).strip()]
    if len(admin_names) > 5:
        finding = make_finding(
            "POST-ADMINS",
            f"本地管理员组成员过多（{len(admin_names)} 个）",
            Severity.LOW,
            tactic="权限提升",
            technique="T1078.003 本地账户",
            description="管理员组成员越多，凭据泄露后的影响面越大，也难以追溯操作者。",
            recommendation="清理不必要的管理员成员，使用受控的运维账户与 LAPS 管理本地口令。",
        )
        finding.key = "posture-local-admins"
        finding.add_evidence("成员: " + ", ".join(admin_names[:15]))
        ctx.add(finding)

    if _truthy(posture.get("guest_enabled")):
        finding = make_finding(
            "POST-GUEST",
            "Guest 账户已启用",
            Severity.MEDIUM,
            tactic="初始访问",
            technique="T1078 有效账户",
            description="Guest 账户启用会扩大未授权访问面，且通常无法审计到具体使用者。",
            recommendation="禁用 Guest 账户并重命名，检查匿名访问相关策略。",
        )
        finding.key = "posture-guest"
        ctx.add(finding)


def _logging(ctx: RuleContext, posture: dict) -> None:
    logging_cfg = posture.get("powershell_logging") or {}
    if isinstance(logging_cfg, dict) and not _truthy(logging_cfg.get("script_block")):
        finding = make_finding(
            "POST-PSLOG",
            "未启用 PowerShell 脚本块日志",
            Severity.LOW,
            tactic="加固配置",
            technique="T1059.001 PowerShell",
            description=(
                "未启用 ScriptBlockLogging 时无法审计 PowerShell 执行的脚本内容，"
                "会显著削弱无文件攻击的发现能力。"
            ),
            recommendation="通过组策略启用脚本块日志与模块日志（含调用栈），并集中转发到 SIEM。",
        )
        finding.key = "posture-ps-logging"
        ctx.add(finding)

    audit = posture.get("audit") or {}
    if isinstance(audit, dict) and audit.get("command_line") is False:
        finding = make_finding(
            "POST-CMDLINE",
            "进程创建审计未记录命令行",
            Severity.LOW,
            tactic="加固配置",
            technique="T1059 命令执行",
            description=(
                "事件 4688 未包含命令行参数（ProcessCreationIncludeCmdLine_Enabled=0），"
                "导致无法还原攻击者执行的完整命令。"
            ),
            recommendation="启用“审核进程创建”并打开命令行包含策略，配合 Sysmon 事件 1 使用。",
        )
        finding.key = "posture-cmdline"
        ctx.add(finding)
