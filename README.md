# Windows 主机日志深度安全审计工具

基于 Windows 事件日志、IIS/Tomcat 访问日志与主机安全配置，自动发现**暴力破解、后门账户、持久化、凭据窃取、WebShell、反取证**等入侵痕迹，并生成带证据、ATT&CK 映射、时间线与 IOC 的审计报告。提供命令行与图形界面两种交互方式。

支持三种采集方式：

| 模式 | 命令 | 说明 |
| --- | --- | --- |
| 远程 | `--host <IP>` | 通过 WinRM 采集，适合批量/远程审计 |
| 本机 | `--local` | 直接调用本机 PowerShell，建议管理员运行 |
| 离线 | `--offline <DIR>` | 分析已导出的 XML/EVTX/IIS/Tomcat 日志，可做取证复现 |
| 演示 | `--demo` | 内置完整入侵链数据，无需目标主机即可体验 |

```bash
python windows_log_audit.py --demo
python windows_log_audit.py --host 10.0.0.5 -u Administrator --ssl --format all
python windows_log_audit.py --local --since-hours 72
python windows_log_audit.py --offline .\exported_logs --format docx
```

不带参数运行会进入交互式向导。

---

## 一、本次修复的问题（对照 1.x 版本）

| # | 原问题 | 影响 | 修复方式 |
| --- | --- | --- | --- |
| 1 | `WinRMAgent` 接收 `port/use_ssl` 但从未使用 | 只能连 5985/HTTP，SSL 目标无法审计 | 拼接 `http(s)://host:port/wsman` 端点并校验 |
| 2 | RDP 会话事件（LSM 21/22/24/25）字段在 `UserData/EventXML`，原代码只读 `EventData` | **RDP 审计结果恒为空** | 解析器递归展开 `UserData`，兼容 `Address=本地` 等本地化值 |
| 3 | 定义的是 `analyze_iis_log()`，调用的是 `analyze_iis()` | **IIS 分析从未执行，运行即抛 AttributeError** | 重写 IIS 模块并统一入口 |
| 4 | 时间戳按 `fromisoformat` 解析 7 位小数秒 | Python 3.11 以下**所有事件时间变为 None**，时间线/窗口判断失效 | 手写时间解析，支持 1–9 位小数与 `Z`/时区偏移 |
| 5 | 暴力破解“失败后成功”取 `succ[0]`，不比较时间 | 把“成功后失败”也误判为已失陷，或漏掉真实成功点 | 按时间排序并只统计成功前窗口内的失败 |
| 6 | 安全日志只解析 4624/4625/4648/4672 | 账户、服务、计划任务、进程、日志清除等入侵痕迹全部漏检 | 建立 100+ 事件 ID 知识库与 40+ 条检测规则 |
| 7 | IIS 字段用 `parts[-1]` 兜底、`#Fields` 缺失时丢整份日志、只读最新一个文件 | 解析错位、日志轮转后无数据 | 按字段名安全取值、支持多文件与 `#Fields` 重置、`#Date` 旧格式 |
| 8 | 单条坏 XML 直接 `fromstring` 抛出 | 一条损坏事件导致整份日志解析失败 | 逐条容错并统计失败数 |
| 9 | `std_out.decode('utf-8')` | 中文 Windows 下事件字段乱码 | 多编码回退；传输改为 gzip+base64 分块，彻底规避管道编码 |
| 10 | `wevtutil` 一次拉取 5000 条 XML | 大日志易超时/超过 WinRM 响应上限 | `Get-WinEvent` 过滤 + 服务端 gzip + 分块读取（默认 200KB/块） |
| 11 | 图表中文显示为方框、报告章节号硬编码 | 报告不专业、章节缺失时编号错乱 | 自动选择中文字体、动态章节编号 |
| 12 | 只能输出 docx | 无法接入 SIEM/自动化 | 支持 Word / Markdown / JSON / HTML |

此外还修复了：`IpAddress` 为空串参与分组、GeoIP 失败无提示、IIS 状态码缺失、临时目录泄漏、`__del__` 资源释放等问题。

---

## 二、检测能力

### 2.1 规则总览

| 领域 | 规则 | 典型事件 |
| --- | --- | --- |
| 登录认证 | AUTH-001 ~ AUTH-018 | 4624/4625/4648/4649/4672/4673/4740/4768/4769/4771/4776/4825/5140/5145 |
| 账户与权限 | ACCT-4720/4722/4723/4724/4725/4726/4738/4781/4740/4767、ACCT-GROUP、ACCT-RIGHT、ACCT-ENUM、ACCT-NEWLOGON | 4720/4728/4732/4756/4704/4798/4799 |
| 持久化 | PERSIST-SVC / SVC-CONFIG / TASK / TASK-UPDATE / REG / REG-SYSMON / WMI / BITS / STARTUP / DRIVER | 7045/7040/4697/4698/4702/4657/5861/59/20001 |
| 执行与凭据 | EXEC-*（20+ 命令特征）、EXEC-PARENT-CHILD、PS-*（8 类脚本特征）、EXEC-LSASS-ACCESS、EXEC-REMOTE-THREAD | 4688/4104/4103/Sysmon 1/8/10 |
| 防御规避 | DEF-CLEARLOG / MALWARE / RTP-OFF / CONFIG / AUDIT / FIREWALL / TIME / DEVICE | 1102/104/1116/5001/5007/4719/4946-4950/6416 |
| Web 攻击 | WEB-SQLI / XSS / TRAVERSAL / LFI / CMD / LOG4SHELL / WEBSHELL / SENSITIVE-FILE / SCANNER / ENUM / AUTH-BRUTE / FLOOD | IIS W3C 日志 |
| Tomcat | TOMCAT-WEBSHELL / WAR / JSP-PUT / MANAGER / MANAGER-BRUTE / ENUM / VERSION / DEPLOY / JNDI / DESERIALIZATION / OOM | access log + catalina/localhost 日志 |
| 主机基线 | POST-DEFENDER / EXCLUSION / RDP-NLA / WDIGEST / LSA / AIE / SMB1 / FIREWALL / GUEST / PSLOG / CMDLINE / ADMINS | 注册表 / Get-MpPreference / auditpol |

每条结论都包含：**规则编号、严重级别、ATT&CK 技术、影响实体、出现次数、时间范围、可复核证据、处置建议**。

### 2.2 重点行为链

- 公网 RDP 爆破 → 成功登录 → 创建账户 → 加入管理员组 → 登录使用（完整后门链）
- 服务安装到 `Users\Public`/`AppData`/`ProgramData`，或 PSEXESVC 等横向工具
- 计划任务伪装成 Windows Update 并执行 Base64 PowerShell
- Mimikatz/Procdump 转储 LSASS、`reg save hklm\sam`、`ntdsutil`
- `vssadmin delete shadows`、`bcdedit recoveryenabled no` 等勒索前置动作
- 清除日志、关闭 Defender、修改审核策略/防火墙
- Office/Web 服务进程拉起 cmd/PowerShell（钓鱼宏、WebShell）
- Kerberoasting（RC4 服务票据）、密码喷洒、NTLM 失败集中、管理共享访问
- WebShell 访问、SQL 注入、路径穿越、Log4Shell、扫描器与目录枚举

### 2.3 风险与关联

- 风险评分：按级别与出现次数加权，输出“未发现 / 低危 / 中危 / 高危 / 严重”结论。
- 攻击链时间线：中危及以上发现的按时间排序，展示入侵推进顺序。
- ATT&CK 阶段覆盖：自动汇总初始访问 → 执行 → 持久化 → 提权 → 防御规避 → 凭据访问 → 横向移动 → 影响。
- IOC 提取：攻击来源 IP、URL、落地文件、服务、计划任务、注册表、账户、哈希、扫描器 UA。
- 覆盖度说明：安全日志缺失、4688 无命令行、无 Sysmon、PowerShell 日志未开启等会显式标注，避免“无发现=安全”的误判。

---

## 三、安装与运行

### 3.1 环境要求

- Python 3.9+
- 远程目标：Windows Server 2012+ / Windows 8+，已启用 WinRM，账号具备管理员权限
- 本机模式：建议以管理员身份运行（否则读不到 Security 日志）
- 目标 PowerShell 3.0+（`Get-WinEvent`、`Get-CimInstance`）

### 3.2 安装依赖

```bash
pip install -r requirements.txt
```

可选组件：

- `matplotlib`：报告图表（缺失则自动跳过图表）
- `geoip2` + `GeoLite2-City.mmdb`：IP 归属地
- `pywinrm`：仅远程模式需要

开发/测试：

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

### 3.3 远程 WinRM

```bash
# HTTP（5985）
python windows_log_audit.py --host 10.0.0.5 -u "CORP\administrator"

# HTTPS（5986）
python windows_log_audit.py --host 10.0.0.5 -u administrator --ssl --port 5986

# 密码从环境变量读取，避免命令历史泄露
set WLA_PASSWORD=******
python windows_log_audit.py --host 10.0.0.5 -u administrator

# 密码文件（UTF-8/UTF-16/GBK 均可）
python windows_log_audit.py --host 10.0.0.5 -u administrator --password-file .\pw.txt
```

目标端启用 WinRM：

```powershell
Enable-PSRemoting -Force
# HTTPS
New-NetFirewallRule -DisplayName "WinRM HTTPS" -Direction Inbound -LocalPort 5986 -Protocol TCP -Action Allow
```

### 3.4 本机

```powershell
# 以管理员身份打开 PowerShell
python windows_log_audit.py --local --since-hours 72 --format all
```

### 3.5 离线分析

先导出日志：

```powershell
wevtutil qe Security /f:RenderedXml /c:50000 > security.xml
wevtutil qe System   /f:RenderedXml /c:20000 > system.xml
wevtutil qe Microsoft-Windows-PowerShell/Operational /f:RenderedXml /c:20000 > powershell.xml
Copy-Item C:\inetpub\logs\LogFiles\W3SVC1\u_ex*.log .\iis\   # IIS 日志
```

然后：

```bash
python windows_log_audit.py --offline .\exported_logs --format all
```

离线目录支持：`*.xml`（事件 XML）、`*.evtx`（自动调用 wevtutil 转换）、`*.log`（IIS W3C / Tomcat access / catalina）、`posture.json`（主机基线）。
工具自身的 `--export-dir` 会把原始日志、IIS 文本、posture 与 manifest 一并保存，可直接用于复现：

```bash
python windows_log_audit.py --host 10.0.0.5 -u admin --export-dir .\case001
python windows_log_audit.py --offline .\case001 --format all
```

### 3.6 演示

```bash
python windows_log_audit.py --demo --format all
```

演示数据模拟：公网爆破 → 管理员登录 → 创建后门账户并提权 → 服务/计划任务持久化 → Base64 PowerShell → 清日志 → Defender 检出 → Kerberoasting → 管理共享 → WebShell/Log4Shell，另外包含 Tomcat Manager 爆破、JSP 上传、WAR 部署与 JNDI 利用日志。报告结论为“严重”，可用于验收与培训。

### 3.7 图形界面

```bash
python windows_log_audit_gui.py
# 或
python windows_log_audit.py --gui
```

界面支持：远程/本机/离线/演示四种模式、端口与 SSL、密码隐藏输入、报告格式与路径、最近 N 小时、跳过 IIS/Tomcat/主机基线、后台线程审计、实时日志与进度提示、完成后一键打开报告。审计在后台线程执行，不会阻塞界面。

### 3.8 Tomcat 日志

工具会自动发现 `%CATALINA_BASE%\logs`、`%CATALINA_HOME%\logs`、`C:\Program Files\Apache Software Foundation\Tomcat*\logs`、`C:\apache-tomcat*\logs`、`C:\tomcat\logs` 下的 `localhost_access_log*`、`catalina*`、`localhost.*`、`manager.*` 日志，也可手动指定：

```bash
python windows_log_audit.py --local --tomcat-path "D:\apps\tomcat\logs"
```

检测内容：JSP WebShell 访问、PUT 写 JSP（CVE-2017-12615）、Manager 控制台暴露/口令爆破、WAR 部署、WEB-INF 探测、SQLi/穿越/Log4Shell、扫描器与目录枚举、Tomcat 版本停服、临时目录部署、JNDI/反序列化/命令执行异常堆栈、内存溢出等。

---

## 四、常用参数

| 参数 | 说明 |
| --- | --- |
| `--host` / `--port` / `--ssl` | 远程目标与 WinRM 配置 |
| `-u` / `-p` / `--password-file` | 凭据（也支持 `WLA_PASSWORD` 环境变量） |
| `--local` / `--offline DIR` / `--demo` | 采集模式 |
| `--since-hours N` | 只分析最近 N 小时，默认 168；0 表示不限制 |
| `--max-events N` | 每个通道最大条数，0 使用内置默认值 |
| `--logs a,b,c` | 只采集指定通道 |
| `--no-iis` / `--iis-path DIR` / `--iis-files N` | IIS 日志控制 |
| `--no-tomcat` / `--tomcat-path DIR` | Tomcat 日志控制 |
| `--diagnose` | 诊断管理员权限、Security 日志可读性与审核策略 |
| `--no-elevate` | 本机模式不自动请求管理员权限 |
| `--gui` | 启动图形界面 |
| `--no-posture` | 跳过主机配置基线 |
| `--brute-threshold N` | 爆破判定阈值，默认 5 |
| `--brute-window N` | 滑动窗口分钟数，默认 10 |
| `--min-severity LOW..CRITICAL` | 报告中保留的最低级别 |
| `--geoip PATH` | GeoLite2-City.mmdb |
| `--format docx` / `md` / `json` / `html` / `all` | 输出格式，默认 docx |
| `--out PATH` | 输出路径 |
| `--export-dir DIR` | 保存原始日志，便于离线复现 |
| `--fail-on LEVEL` | 达到指定级别时退出码 3（自动化告警） |
| `--no-charts` / `--quiet` / `--debug` | 图表/日志/调试 |

退出码：`0` 成功；`1` 参数或采集失败；`3` 触发 `--fail-on`；`130` 用户中断。

---

## 五、报告说明

`--format all` 同时生成：

- `report.docx`：封面、目录、执行摘要、攻击链、详细发现、各领域分析、IOC、处置建议、附录（Word 中右键“更新域”生成目录）。
- `report.md`：便于 Git/工单系统归档。
- `report.json`：机器可读，含 `findings`、`iocs`、`timeline`、`collection`、`posture`。
- `report.html`：单文件、内嵌图表与样式，可直接浏览器打开/发送。

报告中的时间默认转换为**分析者本地时区**；事件原始时间为 UTC（Windows `SystemTime` 标准）。

---

## 六、项目结构

```
windows_log_audit/
├── windows_log_audit.py       # 入口（保持旧文件名/用法）
├── windows_log_audit_gui.py   # 图形界面入口
├── wla/
│   ├── models.py              # Event / Finding / AuditReport / 风险模型
│   ├── parser.py              # 事件 XML 解析（容错、时区、UserData）
│   ├── knowledge.py           # 事件 ID 知识库、采集计划、可疑模式
│   ├── collectors.py          # WinRM / 本地 / 离线 / 分块传输
│   ├── rules_base.py          # 规则上下文与公共工具
│   ├── rules_auth.py          # 登录、RDP、Kerberos、NTLM、共享
│   ├── rules_accounts.py      # 账户、组、权限、枚举
│   ├── rules_persistence.py   # 服务、任务、注册表、WMI、BITS、驱动
│   ├── rules_execution.py     # 进程、命令行、PowerShell、LSASS
│   ├── rules_defense.py       # 清日志、Defender、审计、防火墙
│   ├── rules_posture.py       # 主机配置基线
│   ├── iis.py                 # IIS W3C 解析与 Web 攻击检测
│   ├── tomcat.py              # Tomcat access/catalina 日志分析
│   ├── engine.py              # 规则编排、关联、评分、IOC、覆盖度
│   ├── charts.py              # 中文字体图表
│   ├── report.py              # docx / md / json / html
│   ├── demo.py                # 内置演示入侵链
│   ├── gui.py                 # Tkinter 图形界面
│   └── cli.py                 # 参数解析与交互向导
├── tests/                     # 55 项 pytest 用例
├── assets/                    # 图标（exe / GUI）
├── requirements.txt
├── requirements-dev.txt
├── requirements-build.txt     # PyInstaller / Pillow
├── build_exe.ps1              # 一键构建脚本
└── build_exe.spec             # PyInstaller 单文件打包配置
```

---

## 七、安全与取证注意事项

1. **只读操作**：工具仅读取事件日志、IIS/Tomcat 日志与注册表配置，不修改目标系统。WinRM 执行的 PowerShell 会临时写入 `%TEMP%\wla_*.b64` 并在读取后删除。
2. **权限**：安全日志必须管理员权限；非管理员会明确标注 `denied`，不会静默得出“安全”结论。
3. **证据链**：建议先 `--export-dir` 保存原始日志，再离线分析；报告中的证据行保留原始时间与关键字段。
4. **局限**：本工具做日志层分析，不替代内存/磁盘取证与 EDR。若日志已被清除或审核未开启，需结合其他证据源。
5. **凭据**：优先使用 `WLA_PASSWORD` 环境变量或 `--password-file`；避免 `-p` 明文留在命令历史。

### 7.1 提示“无法读取 Security 日志”怎么办

先运行环境诊断（GUI 中点击“环境诊断”按钮）：

```powershell
WindowsLogAudit.exe --diagnose
# 源码运行：python windows_log_audit.py --diagnose
```

诊断会输出：当前进程是否真正提升、Security 通道是否可访问/启用、记录数、抽样读取结果、EventLog 服务与审核策略。常见原因与处理：

| 诊断结果 | 原因 | 处理 |
| --- | --- | --- |
| `管理员权限: ✗ 否（UAC 过滤令牌）` | 管理员账户双击运行时仍是普通令牌，UAC 不会自动提升 | 右键 exe → “以管理员身份运行”；本工具在 `--local` 模式也会自动请求提升，GUI 顶部有“以管理员身份重启”按钮 |
| 已提升但 `可访问: ✗` | 组策略“配置日志访问”限制、账户不在 Event Log Readers、EDR 拦截、日志损坏 | 用管理员 PowerShell 执行 `Get-WinEvent -ListLog Security` 验证；检查 `wevtutil gl Security`、本地安全策略与安全软件 |
| `已启用: ✗` | Security 通道被禁用 | 管理员执行 `wevtutil sl Security /e:true`，并检查审核策略 |
| `记录数: 0` | 审核策略未开启，日志里没有事件 | 开启“审核登录/账户管理/进程创建”等策略，或等待事件产生 |
| `抽样读取: ✗` | 元数据可读但事件读取失败 | 检查日志文件权限/损坏，必要时备份后重建 Security 日志 |

程序已增加：本机模式自动请求管理员权限、GUI 提权按钮、`Get-WinEvent` 失败时自动回退 `wevtutil`、非提升进程的明确错误提示。

---

## 八、开发

```bash
python -m pytest -q
python -m ruff check wla tests windows_log_audit.py
python windows_log_audit.py --demo --format all --out build/demo.docx
```

新增规则：

1. 在 `knowledge.py` 补充事件 ID 或特征模式；
2. 在对应 `rules_*.py` 中实现并 `ctx.add(finding)`，带 `rule_id`、`tactic`、`technique`、`evidence`、`recommendation`；
3. 在 `tests/test_detections.py` 增加构造事件；
4. 重新运行 `--demo` 确认报告与新规则均正常。

---

## 九、单文件 exe 打包

```powershell
pip install -r requirements-build.txt
.\build_exe.ps1
# 等价于：python -m PyInstaller --clean --noconfirm build_exe.spec
```

产物：`dist\WindowsLogAudit.exe`（当前约 58 MB，单文件、无需安装 Python）。

打包内容与行为：

- **完整报告质量**：内置 matplotlib 与中文字体数据，Word/HTML 报告中的统计图正常生成，不降级。
- 内置 python-docx、pywinrm、GeoIP 库、Tkinter GUI、Tomcat/IIS 分析；Tomcat 日志自动发现与离线解析均可用。
- 仅排除 Qt、IPython、pytest、pandas/scipy 等无关体积项。
- **双击 exe（无参数）直接打开图形界面**，控制台窗口自动隐藏；带参数运行时为命令行模式。
- 首次启动会把运行时解压到临时目录，约 2–5 秒；之后启动更快。退出后临时目录自动清理。
- 未做代码签名，Windows SmartScreen 可能提示“未知发布者”；企业环境可自行签名。
- PyInstaller 单文件偶尔会被杀软误报，可加入白名单或改用目录模式打包。

命令行示例：

```powershell
.\dist\WindowsLogAudit.exe --version
.\dist\WindowsLogAudit.exe --demo --format all
.\dist\WindowsLogAudit.exe --local --since-hours 72 --format docx
.\dist\WindowsLogAudit.exe --offline .\case001 --format all
.\dist\WindowsLogAudit.exe --host 10.0.0.5 -u Administrator --ssl
```

GeoIP 归属地仍需自备 `GeoLite2-City.mmdb`（通过 `--geoip` 指定），exe 不内置该数据库。
