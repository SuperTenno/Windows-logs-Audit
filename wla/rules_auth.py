"""登录认证类入侵痕迹检测：爆破、撞库、RDP、Kerberos、NTLM、特权。"""

from __future__ import annotations

import datetime as dt
from collections import Counter, defaultdict

from .knowledge import is_noise_account
from .models import Event, Severity, fmt_time, ip_kind
from .rules_base import (
    RuleContext,
    evidence_lines,
    is_public_ip,
    make_finding,
    peak_in_window,
)

TACTIC_CREDENTIAL = "凭据访问"
TACTIC_INITIAL = "初始访问"
TACTIC_LATERAL = "横向移动"
TACTIC_PRIV = "权限提升"

FAILED_LOGON = 4625
SUCCESS_LOGON = 4624
EXPLICIT_CRED = 4648
SPECIAL_PRIV = 4672
SENSITIVE_PRIV_USE = 4673
LOCKOUT = 4740
KERB_TGS = 4769
KERB_PREAUTH_FAIL = 4771
NTLM_AUTH = 4776


def run(ctx: RuleContext) -> None:
    _detect_failed_logons(ctx)
    _detect_password_spray(ctx)
    _detect_lockouts(ctx)
    _detect_compromise(ctx)
    _detect_rdp(ctx)
    _detect_logon_anomalies(ctx)
    _detect_explicit_credentials(ctx)
    _detect_kerberos(ctx)
    _detect_ntlm(ctx)
    _detect_special_privileges(ctx)
    _detect_off_hours(ctx)
    _detect_share_access(ctx)


# ---------------------------------------------------------------------------
# 登录失败
# ---------------------------------------------------------------------------
def _detect_failed_logons(ctx: RuleContext) -> None:
    events = ctx.get(FAILED_LOGON)
    if not events:
        return
    options = ctx.options
    grouped: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        ip = event.ip
        key = ip if ip else "本地/未知来源"
        grouped[key].append(event)

    candidates = []
    for ip, items in grouped.items():
        users = Counter(e.target or "<未知>" for e in items)
        peak = peak_in_window((e.time for e in items), options.brute_window_minutes)
        if len(items) < options.brute_threshold and peak < options.brute_threshold:
            continue
        candidates.append((len(items), peak, ip, items, users))

    candidates.sort(key=lambda item: (-item[0], -item[1]))
    for count, peak, ip, items, users in candidates[:10]:
        severity = Severity.MEDIUM
        if peak >= options.brute_threshold * 3 or count >= 50:
            severity = Severity.HIGH
        if len(users) >= options.spray_distinct_users and count >= 10:
            severity = Severity.HIGH

        finding = make_finding(
            "AUTH-001",
            f"登录失败集中：{ip}（{count} 次）",
            severity,
            tactic=TACTIC_CREDENTIAL,
            technique="T1110.001 暴力破解",
            description=(
                f"来源 {ip} 在日志窗口内触发 {count} 次登录失败，"
                f"{options.brute_window_minutes} 分钟内峰值 {peak} 次，"
                f"涉及 {len(users)} 个账户。符合暴力破解或口令猜测特征。"
            ),
            recommendation=(
                "核查该来源 IP 是否可信；启用账户锁定策略与登录失败阈值告警，"
                "在边界防火墙封禁来源 IP，并对被尝试账户强制改密、启用 MFA。"
            ),
            entities={"ip": ip},
        )
        finding.key = f"auth-brute|{ip}"
        finding.count = count
        finding.add_evidence(
            f"失败 {count} 次，{options.brute_window_minutes} 分钟窗口峰值 {peak} 次"
        )
        finding.add_evidence(
            "目标账户 Top: " + ", ".join(f"{u}({c})" for u, c in users.most_common(6))
        )
        for line in evidence_lines(
            items,
            ("TargetUserName", "LogonType", "Status", "SubStatus", "WorkstationName"),
            limit=6,
        ):
            finding.add_evidence(line)
        for event in items:
            finding.add_event(event)
        ctx.add(finding)

    if len(candidates) > 10:
        ctx.note(
            f"另有 {len(candidates) - 10} 个来源 IP 存在登录失败，"
            "详见事件明细或调整阈值后重新分析。"
        )


def _detect_password_spray(ctx: RuleContext) -> None:
    events = ctx.get(FAILED_LOGON)
    if not events:
        return
    options = ctx.options
    grouped: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event.ip:
            grouped[event.ip].append(event)
    for ip, items in grouped.items():
        users = {e.target for e in items if e.target and not e.is_machine_account}
        if len(users) < options.spray_distinct_users or len(items) < 10:
            continue
        finding = make_finding(
            "AUTH-002",
            f"疑似密码喷洒：{ip} 尝试 {len(users)} 个账户",
            Severity.HIGH,
            tactic=TACTIC_CREDENTIAL,
            technique="T1110.003 密码喷洒",
            description=(
                f"来源 {ip} 使用少量口令尝试多个账户（{len(users)} 个），"
                "属于典型的密码喷洒行为，可绕过单账户锁定策略。"
            ),
            recommendation="对来源 IP 实施封禁/限速，检查是否有账户被成功登录，启用 MFA 与异常登录告警。",
            entities={"ip": ip},
        )
        finding.key = f"auth-spray|{ip}"
        finding.count = len(items)
        finding.add_evidence(f"尝试账户 {len(users)} 个：" + ", ".join(sorted(users)[:12]))
        for line in evidence_lines(items, ("TargetUserName", "LogonType", "WorkstationName"), 4):
            finding.add_evidence(line)
        for event in items[:20]:
            finding.add_event(event)
        ctx.add(finding)


def _detect_lockouts(ctx: RuleContext) -> None:
    events = ctx.get(LOCKOUT)
    if not events:
        return
    grouped: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        grouped[event.target or "<未知>"].append(event)
    for user, items in sorted(grouped.items(), key=lambda kv: -len(kv[1]))[:10]:
        severity = Severity.HIGH if len(items) >= 5 else Severity.MEDIUM
        finding = make_finding(
            "AUTH-003",
            f"账户被锁定：{user}",
            severity,
            tactic=TACTIC_CREDENTIAL,
            technique="T1110.001 暴力破解",
            description=(
                f"账户 {user} 在审计窗口内被锁定 {len(items)} 次，"
                "通常由连续登录失败触发，需确认是否为暴力破解或旧凭据残留。"
            ),
            recommendation="确认锁定原因，排查使用过期凭据的服务/计划任务，并评估账户锁定策略是否会被攻击者用于拒绝服务。",
            entities={"user": user},
        )
        finding.key = f"auth-lockout|{user}"
        finding.count = len(items)
        for line in evidence_lines(items, ("TargetUserName", "SubjectUserName", "CallerComputerName"), 5):
            finding.add_evidence(line)
        for event in items[:10]:
            finding.add_event(event)
        ctx.add(finding)


# ---------------------------------------------------------------------------
# 失败后成功 = 疑似已失陷
# ---------------------------------------------------------------------------
def _detect_compromise(ctx: RuleContext) -> None:
    failures = [e for e in ctx.get(FAILED_LOGON) if e.time and e.ip]
    successes = [e for e in ctx.get(SUCCESS_LOGON) if e.time and e.ip]
    if not failures or not successes:
        return

    options = ctx.options
    fail_map: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in failures:
        user = event.target or "<未知>"
        fail_map[(event.ip, user)].append(event)

    success_map: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in successes:
        user = event.target or "<未知>"
        success_map[(event.ip, user)].append(event)
        # 账户名大小写、域前缀差异时做一次模糊匹配
        short = user.split("\\")[-1].lower()
        if short and short != user.lower():
            success_map[(event.ip, short)].append(event)

    for (ip, user), fails in fail_map.items():
        if len(fails) < options.brute_threshold:
            continue
        candidates = success_map.get((ip, user)) or success_map.get(
            (ip, user.split("\\")[-1].lower())
        )
        if not candidates:
            continue
        fails.sort(key=lambda e: e.time)
        candidates.sort(key=lambda e: e.time)
        window = dt.timedelta(minutes=options.compromise_window_minutes)
        for success in candidates:
            recent = [f for f in fails if success.time - window <= f.time <= success.time]
            if len(recent) < options.brute_threshold:
                continue
            severity = Severity.CRITICAL
            if not is_public_ip(ip) and success.logon_type not in {"2", "10", "3"}:
                severity = Severity.HIGH
            finding = make_finding(
                "AUTH-004",
                f"疑似爆破成功：{ip} -> {success.target or user}",
                severity,
                tactic=TACTIC_INITIAL,
                technique="T1078 有效账户 / T1110 暴力破解",
                description=(
                    f"来源 {ip} 在 {options.compromise_window_minutes} 分钟内"
                    f"连续失败 {len(recent)} 次后成功登录账户 {success.target or user}，"
                    "高度疑似暴力破解成功，账户可能已被攻陷。"
                ),
                recommendation=(
                    "立即隔离该账户：强制改密、撤销会话与令牌、检查该来源的后续操作"
                    "（进程创建、服务安装、计划任务、数据访问），并保留证据用于溯源。"
                ),
                entities={"ip": ip, "user": success.target or user},
            )
            finding.key = f"auth-compromise|{ip}|{success.target or user}|{success.time}"
            finding.count = len(recent)
            finding.add_evidence(
                f"失败区间 {fmt_time(recent[0].time)} ~ {fmt_time(recent[-1].time)}"
                f"（{len(recent)} 次）"
            )
            finding.add_evidence(
                f"成功登录 {fmt_time(success.time)}，类型 {success.logon_type or '?'}，"
                f"工作站 {success.workstation or '-'}"
            )
            for line in evidence_lines(recent[-3:], ("TargetUserName", "Status", "SubStatus"), 3):
                finding.add_evidence("失败: " + line)
            finding.add_evidence("成功: " + success.brief(220))
            for event in recent[-5:] + [success]:
                finding.add_event(event)
            finding.first_seen = recent[0].time
            finding.last_seen = success.time
            ctx.add(finding)


# ---------------------------------------------------------------------------
# 远程桌面
# ---------------------------------------------------------------------------
def _rdp_events(ctx: RuleContext) -> list[tuple[Event, str, str]]:
    """汇总 4624(type10)、LSM 21、RCM 1149 三种 RDP 来源。"""
    result: list[tuple[Event, str, str]] = []
    for event in ctx.get(SUCCESS_LOGON):
        if event.logon_type == "10":
            result.append((event, event.ip, event.target))
    for event in ctx.log("rdp_lsm"):
        if event.event_id == 21:
            address = event.get("Address")
            user = event.get("User")
            result.append((event, address, user))
    for event in ctx.log("rdp_rcm"):
        if event.event_id == 1149:
            address = event.get("Param3", "Address")
            user = event.get("Param1", "User")
            result.append((event, address, user))
    return result


def _detect_rdp(ctx: RuleContext) -> None:
    sessions = _rdp_events(ctx)
    if not sessions:
        return

    external: list[tuple[Event, str, str]] = [
        item for item in sessions if is_public_ip(item[1])
    ]
    internal = [item for item in sessions if ip_kind(item[1]) in {"private", "linklocal"}]

    if external:
        grouped: dict[str, list[tuple[Event, str, str]]] = defaultdict(list)
        for item in external:
            grouped[item[1]].append(item)
        for ip, items in sorted(grouped.items(), key=lambda kv: -len(kv[1]))[:10]:
            users = Counter((user or "<未知>").split("\\")[-1] for _, _, user in items)
            severity = Severity.HIGH if len(items) >= 3 else Severity.MEDIUM
            finding = make_finding(
                "AUTH-005",
                f"公网 IP 远程桌面登录：{ip}",
                severity,
                tactic=TACTIC_LATERAL,
                technique="T1021.001 远程桌面协议",
                description=(
                    f"检测到来自公网地址 {ip} 的 {len(items)} 次 RDP 会话，"
                    f"涉及账户 {', '.join(sorted(users)[:6])}。"
                    "若该主机本不应直接暴露 RDP，则登录来源高度可疑。"
                ),
                recommendation=(
                    "确认 RDP 是否必须对公网开放；建议通过 VPN/堡垒机访问，"
                    "启用 NLA 与 MFA，限制来源 IP，并核查该来源的登录后行为。"
                ),
                entities={"ip": ip},
            )
            finding.key = f"auth-rdp-public|{ip}"
            finding.count = len(items)
            for event, _ip, user in items[:8]:
                finding.add_evidence(
                    f"{fmt_time(event.time)} 用户={user or '-'} 地址={_ip} 事件={event.event_id}"
                )
            for event, _ip, _user in items[:20]:
                finding.add_event(event)
            ctx.add(finding)

    # 内网 RDP 只做统计，不单独告警；公网 RDP 已在上方处理。
    if not external and internal:
        ctx.note(
            f"检测到 {len(internal)} 次内网 RDP 登录，未发现公网来源；"
            "如需评估横向移动风险，请结合内网资产清单分析。"
        )


# ---------------------------------------------------------------------------
# 登录类型异常
# ---------------------------------------------------------------------------
def _detect_logon_anomalies(ctx: RuleContext) -> None:
    events = ctx.get(SUCCESS_LOGON)
    if not events:
        return

    cleartext = [e for e in events if e.logon_type == "8"]
    if cleartext:
        finding = make_finding(
            "AUTH-006",
            "检测到明文网络登录（LogonType=8）",
            Severity.HIGH,
            tactic=TACTIC_CREDENTIAL,
            technique="T1078 有效账户",
            description=(
                "LogonType 8 表示凭据以明文形式通过网络发送。除非为特定兼容场景，"
                "否则说明认证配置存在严重风险，凭据可能已被嗅探。"
            ),
            recommendation="禁用明文认证（如 Basic 认证/未加密的 IIS 目录），改用 Kerberos/NTLM 协商或 TLS。",
        )
        finding.key = "auth-cleartext"
        finding.count = len(cleartext)
        for line in evidence_lines(cleartext, ("TargetUserName", "IpAddress", "WorkstationName"), 6):
            finding.add_evidence(line)
        for event in cleartext[:10]:
            finding.add_event(event)
        ctx.add(finding)

    new_credentials = [e for e in events if e.logon_type == "9"]
    if new_credentials:
        finding = make_finding(
            "AUTH-007",
            "检测到显式新凭据登录（LogonType=9）",
            Severity.MEDIUM,
            tactic=TACTIC_CREDENTIAL,
            technique="T1078 有效账户",
            description=(
                "LogonType 9 常见于 runas /netonly、PsExec 等使用另一套凭据的场景，"
                "攻击者取得凭据后也常用该方式横向移动。"
            ),
            recommendation="核对发起进程与操作人员；审计 runas/PsExec 使用，避免高权限凭据在低信任主机上使用。",
        )
        finding.key = "auth-newcred"
        finding.count = len(new_credentials)
        for line in evidence_lines(new_credentials, ("TargetUserName", "IpAddress", "ProcessName"), 6):
            finding.add_evidence(line)
        for event in new_credentials[:10]:
            finding.add_event(event)
        ctx.add(finding)

    anonymous = [
        e
        for e in events
        if e.logon_type == "3" and "anonymous" in (e.target or "").lower()
    ]
    if anonymous:
        finding = make_finding(
            "AUTH-008",
            "匿名网络登录（ANONYMOUS LOGON）",
            Severity.HIGH,
            tactic=TACTIC_LATERAL,
            technique="T1021.002 SMB/Windows 管理共享",
            description=(
                f"检测到 {len(anonymous)} 次匿名网络登录，可能来自空会话枚举、"
                "SMB 中继或配置不当的共享访问。"
            ),
            recommendation="禁用匿名访问与空会话，限制 SMB/RPC 暴露面，检查共享权限与 NTLM 中继防护（SMB 签名/EPA）。",
        )
        finding.key = "auth-anonymous"
        finding.count = len(anonymous)
        for line in evidence_lines(anonymous, ("IpAddress", "WorkstationName"), 6):
            finding.add_evidence(line)
        for event in anonymous[:10]:
            finding.add_event(event)
        ctx.add(finding)

    public_network = [
        e
        for e in events
        if e.logon_type == "3" and is_public_ip(e.ip)
    ]
    if public_network:
        finding = make_finding(
            "AUTH-009",
            "来自公网地址的网络登录（LogonType=3）",
            Severity.HIGH,
            tactic=TACTIC_LATERAL,
            technique="T1021 远程服务",
            description=(
                f"检测到 {len(public_network)} 次来自公网 IP 的网络登录，"
                "说明 SMB/WinRM/RPC 等服务可能直接暴露在互联网。"
            ),
            recommendation="立即收敛公网暴露的 SMB/WinRM/RPC 端口，仅允许受控管理网段访问，并核查登录后的操作。",
        )
        finding.key = "auth-public-network"
        finding.count = len(public_network)
        for line in evidence_lines(public_network, ("TargetUserName", "IpAddress", "WorkstationName"), 6):
            finding.add_evidence(line)
        for event in public_network[:10]:
            finding.add_event(event)
        ctx.add(finding)

    replay = ctx.get(4649)
    if replay:
        finding = make_finding(
            "AUTH-010",
            "检测到 Kerberos 重放攻击",
            Severity.HIGH,
            tactic=TACTIC_CREDENTIAL,
            technique="T1550 使用备用身份验证材料",
            description="事件 4649 表示检测到 Kerberos 重放攻击，通常意味着票据被窃取后重复使用。",
            recommendation="排查票据窃取来源，重置相关账户密码与 krbtgt（域环境），启用 AES 并禁用 RC4。",
        )
        finding.key = "auth-replay"
        finding.count = len(replay)
        for line in evidence_lines(replay, ("TargetUserName", "IpAddress"), 6):
            finding.add_evidence(line)
        ctx.add(finding)


def _detect_explicit_credentials(ctx: RuleContext) -> None:
    events = [e for e in ctx.get(EXPLICIT_CRED) if not is_noise_account(e.actor)]
    if not events:
        return
    grouped: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in events:
        grouped[(event.actor, event.get("TargetServerName", "TargetUserName"))].append(event)
    for (actor, target), items in sorted(grouped.items(), key=lambda kv: -len(kv[1]))[:8]:
        severity = Severity.MEDIUM
        if any(is_public_ip(e.ip) for e in items):
            severity = Severity.HIGH
        finding = make_finding(
            "AUTH-011",
            f"显式凭据使用：{actor} -> {target or '本地'}",
            severity,
            tactic=TACTIC_CREDENTIAL,
            technique="T1078 有效账户",
            description=(
                f"账户 {actor} 通过显式凭据登录目标 {target or '本地'}（{len(items)} 次），"
                "常见于 runas、计划任务或横向移动工具。"
            ),
            recommendation="确认操作来源与用途；限制高权限凭据在非受信主机上的使用，启用 Credential Guard/LSA 保护。",
            entities={"user": actor, "target": target},
        )
        finding.key = f"auth-explicit|{actor}|{target}"
        finding.count = len(items)
        for line in evidence_lines(items, ("TargetUserName", "TargetServerName", "ProcessName", "IpAddress"), 6):
            finding.add_evidence(line)
        for event in items[:10]:
            finding.add_event(event)
        ctx.add(finding)


def _detect_kerberos(ctx: RuleContext) -> None:
    rc4 = [
        e
        for e in ctx.get(KERB_TGS)
        if e.get("TicketEncryptionType").lower() in {"0x17", "23", "rc4-hmac"}
    ]
    if rc4:
        by_user: dict[str, list[Event]] = defaultdict(list)
        for event in rc4:
            by_user[event.target or "<未知>"].append(event)
        for user, items in sorted(by_user.items(), key=lambda kv: -len(kv[1]))[:5]:
            services = {e.get("ServiceName") for e in items if e.get("ServiceName")}
            severity = Severity.HIGH if len(services) >= 3 or len(items) >= 10 else Severity.MEDIUM
            finding = make_finding(
                "AUTH-012",
                f"疑似 Kerberoasting：{user} 请求 {len(services)} 个 RC4 服务票据",
                severity,
                tactic=TACTIC_CREDENTIAL,
                technique="T1558.003 Kerberoasting",
                description=(
                    f"账户 {user} 获取了 {len(items)} 个使用 RC4-HMAC 加密的 Kerberos 服务票据，"
                    "涉及多个 SPN。攻击者可离线破解这类票据获取服务账户明文口令。"
                ),
                recommendation="禁用 RC4，改用 AES；为服务账户使用托管服务账户（gMSA）并定期轮换口令；排查票据请求来源。",
                entities={"user": user},
            )
            finding.key = f"auth-kerberoast|{user}"
            finding.count = len(items)
            finding.add_evidence("服务: " + ", ".join(sorted(services)[:10]))
            for line in evidence_lines(items, ("ServiceName", "IpAddress", "TicketEncryptionType"), 5):
                finding.add_evidence(line)
            for event in items[:10]:
                finding.add_event(event)
            ctx.add(finding)

    preauth = [e for e in ctx.get(KERB_PREAUTH_FAIL) if e.ip]
    if preauth:
        by_ip: dict[str, list[Event]] = defaultdict(list)
        for event in preauth:
            by_ip[event.ip].append(event)
        for ip, items in sorted(by_ip.items(), key=lambda kv: -len(kv[1]))[:5]:
            if len(items) < 10:
                continue
            finding = make_finding(
                "AUTH-013",
                f"Kerberos 预身份验证失败集中：{ip}",
                Severity.HIGH if len(items) >= 30 else Severity.MEDIUM,
                tactic=TACTIC_CREDENTIAL,
                technique="T1110 暴力破解",
                description=(
                    f"来源 {ip} 在窗口内触发 {len(items)} 次 Kerberos 预认证失败，"
                    "可能是针对域账户的口令猜测，或账户口令已过期。"
                ),
                recommendation="核查来源主机与账户，封禁异常来源，检查是否存在弱口令服务账户。",
                entities={"ip": ip},
            )
            finding.key = f"auth-kerb-fail|{ip}"
            finding.count = len(items)
            for line in evidence_lines(items, ("TargetUserName", "Status", "ServiceName"), 5):
                finding.add_evidence(line)
            for event in items[:10]:
                finding.add_event(event)
            ctx.add(finding)


def _detect_ntlm(ctx: RuleContext) -> None:
    events = ctx.get(NTLM_AUTH)
    if not events:
        return
    bad = [
        e
        for e in events
        if e.get("Status").lower() in {"0xc000006a", "0xc0000064", "0xc0000234"}
    ]
    if not bad:
        return
    grouped: dict[str, list[Event]] = defaultdict(list)
    for event in bad:
        grouped[event.get("Workstation", "WorkstationName") or "未知工作站"].append(event)
    for station, items in sorted(grouped.items(), key=lambda kv: -len(kv[1]))[:5]:
        if len(items) < 10:
            continue
        finding = make_finding(
            "AUTH-014",
            f"NTLM 认证失败集中：{station}",
            Severity.HIGH if len(items) >= 30 else Severity.MEDIUM,
            tactic=TACTIC_CREDENTIAL,
            technique="T1110 暴力破解 / T1550 传递哈希",
            description=(
                f"工作站 {station} 产生 {len(items)} 次 NTLM 认证失败，"
                "可能是口令喷洒、过期凭据或 Pass-the-Hash 尝试。"
            ),
            recommendation="定位来源主机，排查恶意进程与保存的凭据；启用 NTLM 审核与受保护用户组，逐步禁用 NTLM。",
            entities={"workstation": station},
        )
        finding.key = f"auth-ntlm|{station}"
        finding.count = len(items)
        for line in evidence_lines(items, ("TargetUserName", "Status"), 5):
            finding.add_evidence(line)
        for event in items[:10]:
            finding.add_event(event)
        ctx.add(finding)


def _priv_user(event: Event) -> str:
    """4672/4673 的账户在 SubjectUserName 中。"""
    return event.get("SubjectUserName") or event.target


def _detect_special_privileges(ctx: RuleContext) -> None:
    events = [e for e in ctx.get(SPECIAL_PRIV) if not is_noise_account(_priv_user(e))]
    created_users = set()
    for created in ctx.get(4720):
        for name in (created.target, created.get("SamAccountName")):
            if name:
                created_users.add(name.lower())
    if events:
        by_user: dict[str, list[Event]] = defaultdict(list)
        for event in events:
            by_user[_priv_user(event)].append(event)

        suspicious = {
            user: items for user, items in by_user.items() if user.lower() in created_users
        }
        for user, items in suspicious.items():
            finding = make_finding(
                "AUTH-015",
                f"新建账户获得特殊特权：{user}",
                Severity.CRITICAL,
                tactic=TACTIC_PRIV,
                technique="T1134 访问令牌操纵 / T1078 有效账户",
                description=(
                    f"账户 {user} 在审计窗口内被创建，并很快获得特殊特权（事件 4672），"
                    "符合攻击者创建后门账户并提权的行为链。"
                ),
                recommendation="立即禁用并删除该账户，排查创建者来源与后续操作，重置相关管理员凭据。",
                entities={"user": user},
            )
            finding.key = f"auth-priv-new|{user}"
            finding.count = len(items)
            for line in evidence_lines(items, ("SubjectUserName", "PrivilegeList"), 6):
                finding.add_evidence(line)
            for event in items[:10]:
                finding.add_event(event)
            ctx.add(finding)

        normal = {
            u: v for u, v in by_user.items() if u.lower() not in created_users
        }
        if normal:
            finding = make_finding(
                "AUTH-016",
                "特殊特权指派基线（非系统账户）",
                Severity.LOW,
                tactic=TACTIC_PRIV,
                technique="T1134 访问令牌操纵",
                description=(
                    "以下非系统账户在登录时被分配特殊特权。管理员登录通常会产生该事件，"
                    "此处仅作基线记录，需结合账户授权范围判断是否异常。"
                ),
                recommendation="定期复核管理员组成员与特权指派，遵循最小权限原则。",
            )
            finding.key = "auth-priv-baseline"
            finding.count = sum(len(v) for v in normal.values())
            finding.add_evidence(
                "账户与次数: "
                + ", ".join(
                    f"{u}({len(v)})"
                    for u, v in sorted(normal.items(), key=lambda kv: -len(kv[1]))[:12]
                )
            )
            for user, items in sorted(normal.items(), key=lambda kv: -len(kv[1]))[:5]:
                for event in items[:2]:
                    finding.add_event(event)
            ctx.add(finding)

    sensitive_use = [
        e
        for e in ctx.get(SENSITIVE_PRIV_USE)
        if "sedebugprivilege" in (e.get("Privileges") or "").lower()
        or "setcbprivilege" in (e.get("Privileges") or "").lower()
    ]
    if sensitive_use:
        finding = make_finding(
            "AUTH-017",
            "敏感特权被调用（SeDebugPrivilege/SeTcbPrivilege）",
            Severity.MEDIUM,
            tactic=TACTIC_PRIV,
            technique="T1134 访问令牌操纵",
            description=(
                f"检测到 {len(sensitive_use)} 次敏感特权调用，可被用于读取其他进程内存"
                "（如 LSASS 凭据）或创建高权限令牌。"
            ),
            recommendation="确认调用进程与操作人员；限制 SeDebugPrivilege 授予范围，启用 LSA 保护与 Credential Guard。",
        )
        finding.key = "auth-priv-use"
        finding.count = len(sensitive_use)
        for line in evidence_lines(sensitive_use, ("SubjectUserName", "Privileges", "ProcessName"), 6):
            finding.add_evidence(line)
        for event in sensitive_use[:10]:
            finding.add_event(event)
        ctx.add(finding)


def _detect_share_access(ctx: RuleContext) -> None:
    """管理共享（ADMIN$/C$/IPC$）访问是横向移动与凭据窃取的常见迹象。"""
    events = [
        e
        for e in ctx.get(5140) + ctx.get(5145)
        if not is_noise_account(e.get("SubjectUserName"))
    ]
    if not events:
        return
    admin_shares = {"admin$", "c$", "d$", "e$", "ipc$", "print$"}
    grouped: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in events:
        share = (event.get("ShareName", "ShareName") or "").strip().lower()
        if share not in admin_shares:
            continue
        grouped[(share, event.get("SubjectUserName") or event.actor)].append(event)

    for (share, user), items in sorted(grouped.items(), key=lambda kv: -len(kv[1]))[:8]:
        public = any(is_public_ip(e.ip) for e in items)
        severity = Severity.HIGH if public or len(items) >= 5 else Severity.MEDIUM
        finding = make_finding(
            "LATERAL-SHARE",
            f"访问管理共享 {share.upper()}：{user}",
            severity,
            tactic=TACTIC_LATERAL,
            technique="T1021.002 SMB/Windows 管理共享",
            description=(
                f"账户 {user} 访问管理共享 {share.upper()}（{len(items)} 次），"
                "攻击者常通过 ADMIN$/C$ 投放工具、复制文件或执行远程命令。"
                + (" 访问来源包含公网地址，风险更高。" if public else "")
            ),
            recommendation=(
                "核对访问来源与操作人员；限制管理共享访问，启用 SMB 签名，"
                "排查共享目录中新增的可执行文件。"
            ),
            entities={"share": share, "user": user},
        )
        finding.key = f"lateral-share|{share}|{user}"
        finding.count = len(items)
        for line in evidence_lines(
            items, ("SubjectUserName", "ShareName", "RelativeTargetName", "IpAddress"), 6
        ):
            finding.add_evidence(line)
        for event in items[:10]:
            finding.add_event(event)
        ctx.add(finding)


def _detect_off_hours(ctx: RuleContext) -> None:
    events = [
        e
        for e in ctx.get(SUCCESS_LOGON)
        if e.time
        and e.logon_type in {"2", "10", "7"}
        and not is_noise_account(e.target)
    ]
    if not events:
        return
    by_user: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        try:
            hour = event.time.astimezone().hour
        except (ValueError, OSError):
            continue
        if 0 <= hour < 6:
            by_user[event.target or "<未知>"].append(event)
    for user, items in by_user.items():
        if len(items) < 2:
            continue
        finding = make_finding(
            "AUTH-018",
            f"异常时段登录：{user}（凌晨 0-6 点）",
            Severity.LOW,
            tactic=TACTIC_INITIAL,
            technique="T1078 有效账户",
            description=(
                f"账户 {user} 在凌晨 0-6 点发生 {len(items)} 次交互式/远程登录，"
                "若非运维值班安排，需警惕账号被他人使用。"
            ),
            recommendation="与账号使用人核实登录时间与地点；对非工作时段登录启用告警。",
            entities={"user": user},
        )
        finding.key = f"auth-offhours|{user}"
        finding.count = len(items)
        for line in evidence_lines(items, ("IpAddress", "WorkstationName", "LogonType"), 6):
            finding.add_evidence(line)
        for event in items[:10]:
            finding.add_event(event)
        ctx.add(finding)
