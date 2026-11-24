"""账户与权限变更检测：后门账户、组成员变更、用户权限分配。"""

from __future__ import annotations

from collections import Counter, defaultdict

from .knowledge import SENSITIVE_GROUPS, is_noise_account
from .models import Event, Severity, fmt_time, is_external_ip
from .rules_base import RuleContext, evidence_lines, make_finding

TACTIC_PERSISTENCE = "持久化"
TACTIC_PRIV = "权限提升"
TACTIC_DISCOVERY = "发现"

# 事件 ID -> (标题, 严重级别, 技术编号, 说明)
ACCOUNT_RULES = {
    4720: (
        "创建本地用户账户",
        Severity.HIGH,
        "T1136.001 创建本地账户",
        "新建账户常被攻击者用于建立后门访问。",
    ),
    4726: (
        "删除本地用户账户",
        Severity.HIGH,
        "T1531 账户访问移除",
        "删除账户可能是攻击者清理痕迹或破坏业务。",
    ),
    4781: (
        "账户名称被修改",
        Severity.HIGH,
        "T1036 伪装",
        "重命名账户可伪装成系统账户或隐藏后门账户。",
    ),
    4724: (
        "重置账户密码",
        Severity.MEDIUM,
        "T1098 账户操纵",
        "重置他人密码可被用于接管账户。",
    ),
    4723: (
        "账户修改自身密码",
        Severity.LOW,
        "T1098 账户操纵",
        "需结合操作人员判断是否为正常改密。",
    ),
    4722: (
        "启用用户账户",
        Severity.MEDIUM,
        "T1098 账户操纵",
        "启用长期禁用的账户可能是后门利用。",
    ),
    4725: (
        "禁用用户账户",
        Severity.LOW,
        "T1531 账户访问移除",
        "需确认是否为正常离职/安全处置。",
    ),
    4738: (
        "修改用户账户属性",
        Severity.LOW,
        "T1098 账户操纵",
        "需关注是否修改了权限相关属性。",
    ),
    4767: (
        "解锁用户账户",
        Severity.LOW,
        "T1098 账户操纵",
        "结合锁定事件判断是否为攻击链一环。",
    ),
}

GROUP_ADD_EVENTS = {
    4728: "全局安全组",
    4732: "本地安全组",
    4756: "通用安全组",
}


def run(ctx: RuleContext) -> None:
    created_findings = _account_changes(ctx)
    _group_changes(ctx, created_findings)
    _new_account_usage(ctx, created_findings)
    _user_rights(ctx)
    _enumeration(ctx)


def _account_changes(ctx: RuleContext) -> dict[str, object]:
    created: dict[str, object] = {}
    for event_id, (title, severity, technique, description) in ACCOUNT_RULES.items():
        events = [e for e in ctx.get(event_id) if e.target]
        if not events:
            continue
        grouped: dict[str, list[Event]] = defaultdict(list)
        for event in events:
            grouped[event.target].append(event)

        for user, items in sorted(grouped.items(), key=lambda kv: -len(kv[1]))[:10]:
            actors = Counter(e.actor for e in items if e.actor)
            finding = make_finding(
                f"ACCT-{event_id}",
                f"{title}：{user}",
                severity,
                tactic=TACTIC_PRIV if severity >= Severity.MEDIUM else TACTIC_PERSISTENCE,
                technique=technique,
                description=(
                    f"{description} 审计窗口内对账户 {user} 发生 {len(items)} 次该操作，"
                    f"操作者：{', '.join(f'{a}({c})' for a, c in actors.most_common(3)) or '未知'}。"
                ),
                recommendation=(
                    "核对变更工单与操作人员；非授权变更应立即回滚，"
                    "并检查该账户/操作者此后的登录与提权行为。"
                ),
                entities={"user": user},
            )
            finding.key = f"acct-{event_id}|{user}"
            finding.count = len(items)
            for line in evidence_lines(
                items, ("SubjectUserName", "TargetUserName", "SamAccountName", "MemberName"), 6
            ):
                finding.add_evidence(line)
            for event in items[:10]:
                finding.add_event(event)
            ctx.add(finding)
            if event_id == 4720:
                created[user.lower()] = finding
                sam = items[0].get("SamAccountName")
                if sam:
                    created[sam.lower()] = finding
    return created


def _is_sensitive_group(group: str) -> bool:
    value = (group or "").lower()
    return any(name in value for name in SENSITIVE_GROUPS)


def _member_account(member: str) -> str:
    """从 ``CN=user,CN=Users,DC=...`` 中取出账户名。"""
    text = (member or "").strip()
    if text.upper().startswith("CN="):
        first = text.split(",", 1)[0]
        return first[3:].strip()
    return text


def _group_changes(ctx: RuleContext, created: dict[str, object]) -> None:
    for event_id, group_type in GROUP_ADD_EVENTS.items():
        events = ctx.get(event_id)
        if not events:
            continue
        grouped: dict[tuple[str, str], list[Event]] = defaultdict(list)
        for event in events:
            group = event.get("TargetUserName", "GroupName") or "<未知组>"
            member = event.get("MemberName", "MemberSid") or event.get("TargetSid") or "<未知成员>"
            grouped[(group, member)].append(event)

        for (group, member), items in sorted(grouped.items(), key=lambda kv: -len(kv[1]))[:10]:
            sensitive = _is_sensitive_group(group)
            severity = Severity.HIGH if sensitive else Severity.MEDIUM
            display_member = _member_account(member)
            just_created = display_member.lower() in created
            if sensitive and just_created:
                severity = Severity.CRITICAL

            title = f"成员加入{group_type}：{display_member} -> {group}"
            if sensitive and just_created:
                title = f"后门账户提权：新建账户 {display_member} 加入 {group}"
            finding = make_finding(
                "ACCT-GROUP",
                title,
                severity,
                tactic=TACTIC_PRIV,
                technique="T1098 账户操纵 / T1069 权限组发现",
                description=(
                    f"账户 {display_member} 被加入{group_type} {group}（{len(items)} 次），"
                    "组成员变更会直接改变权限边界，是攻击者常用的提权与持久化手段。"
                ),
                recommendation=(
                    "立即核实变更授权；若为异常变更，将成员移出并禁用账户，"
                    "审查操作者来源与其他管理员组变更。"
                ),
                entities={"group": group, "member": display_member},
            )
            finding.key = f"acct-group|{group}|{display_member}"
            finding.count = len(items)
            actors = Counter(e.actor for e in items if e.actor)
            if actors:
                finding.add_evidence(
                    "操作者: " + ", ".join(f"{a}({c})" for a, c in actors.most_common(3))
                )
            if just_created:
                finding.add_evidence("该成员在审计窗口内刚被创建（事件 4720），构成完整后门账户链。")
            for line in evidence_lines(items, ("SubjectUserName", "MemberName", "TargetUserName"), 5):
                finding.add_evidence(line)
            for event in items[:10]:
                finding.add_event(event)
            ctx.add(finding)


def _new_account_usage(ctx: RuleContext, created: dict[str, object]) -> None:
    """新建账户在短时间内被登录，是后门账户被启用的直接证据。"""
    if not created:
        return
    logons = [e for e in ctx.get(4624) if e.time]
    if not logons:
        return
    for key, creation in list(created.items())[:15]:
        created_at = getattr(creation, "first_seen", None)
        display = getattr(creation, "entities", {}).get("user", key)
        matches = [
            e
            for e in logons
            if (e.target or "").lower() == key
            and (created_at is None or e.time >= created_at)
        ]
        if not matches:
            continue
        matches.sort(key=lambda e: e.time)
        first = matches[0]
        public = any(is_external_ip(e.ip) for e in matches)
        finding = make_finding(
            "ACCT-NEWLOGON",
            f"新建账户被登录：{display}",
            Severity.CRITICAL if first.logon_type == "10" and public else Severity.HIGH,
            tactic=TACTIC_PRIV,
            technique="T1078 有效账户 / T1136.001 创建本地账户",
            description=(
                f"账户 {display} 创建后被成功登录 {len(matches)} 次，"
                "说明该账户已投入使用，需确认是否为授权的运维账户。"
            ),
            recommendation="立即核实账户用途与登录来源；非授权账户应禁用、删除并重置相关凭据。",
            entities={"user": display},
        )
        finding.key = f"acct-newlogon|{key}"
        finding.count = len(matches)
        for event in matches[:6]:
            finding.add_evidence(
                f"{fmt_time(event.time)} 登录类型={event.logon_type or '?'} "
                f"来源={event.ip or '-'} 工作站={event.workstation or '-'}"
            )
        for event in matches[:10]:
            finding.add_event(event)
        ctx.add(finding)


def _user_rights(ctx: RuleContext) -> None:
    events = ctx.get(4704)
    if not events:
        return
    dangerous = [
        "sedebugprivilege",
        "setcbprivilege",
        "sebackupprivilege",
        "serestoreprivilege",
        "setakeownershipprivilege",
        "seloaddriverprivilege",
        "seimpersonateprivilege",
        "seassignprimarytokenprivilege",
    ]
    grouped: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in events:
        user = event.target or "<未知>"
        privilege = event.get("PrivilegeList", "Privileges") or "<未知权限>"
        grouped[(user, privilege)].append(event)

    for (user, privilege), items in sorted(grouped.items(), key=lambda kv: -len(kv[1]))[:10]:
        is_dangerous = any(p in privilege.lower() for p in dangerous)
        finding = make_finding(
            "ACCT-RIGHT",
            f"分配用户权限：{user} -> {privilege}",
            Severity.MEDIUM if is_dangerous else Severity.LOW,
            tactic=TACTIC_PRIV,
            technique="T1098 账户操纵",
            description=(
                f"账户 {user} 被分配权限 {privilege}。此类权限可绕过常规访问控制"
                "（读取任意进程内存、备份文件、加载驱动等）。"
            ),
            recommendation="按最小权限原则复核；对 SeDebugPrivilege 等高风险权限应仅授予受控运维账户。",
            entities={"user": user, "privilege": privilege},
        )
        finding.key = f"acct-right|{user}|{privilege}"
        finding.count = len(items)
        for line in evidence_lines(items, ("SubjectUserName", "PrivilegeList", "TargetUserName"), 5):
            finding.add_evidence(line)
        for event in items[:10]:
            finding.add_event(event)
        ctx.add(finding)


def _enumeration(ctx: RuleContext) -> None:
    for event_id, label in ((4798, "用户本地组枚举"), (4799, "本地组成员枚举")):
        events = [e for e in ctx.get(event_id) if not is_noise_account(e.actor)]
        if not events:
            continue
        targets = Counter(e.target for e in events if e.target)
        if sum(targets.values()) < 10:
            continue
        actors = Counter(e.actor for e in events if e.actor)
        finding = make_finding(
            "ACCT-ENUM",
            f"账户/组枚举行为：{label}",
            Severity.LOW,
            tactic=TACTIC_DISCOVERY,
            technique="T1069 权限组发现 / T1087 账户发现",
            description=(
                f"检测到 {sum(targets.values())} 次{label}，涉及 {len(targets)} 个目标，"
                "可能是攻击者收集权限信息的前置动作。"
            ),
            recommendation="确认是否为管理工具/巡检脚本行为；异常来源应排查其登录记录与后续操作。",
        )
        finding.key = f"acct-enum|{event_id}"
        finding.count = sum(targets.values())
        finding.add_evidence(
            "操作者: " + ", ".join(f"{a}({c})" for a, c in actors.most_common(5))
        )
        finding.add_evidence(
            "枚举目标: " + ", ".join(f"{t}({c})" for t, c in targets.most_common(8))
        )
        for event in events[:10]:
            finding.add_event(event)
        ctx.add(finding)
