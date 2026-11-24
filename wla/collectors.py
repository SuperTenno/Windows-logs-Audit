"""日志采集：WinRM 远程、本机 PowerShell、离线导出文件。

所有数据通过“PowerShell 端 gzip + base64 → 分块读取”的方式传回，
既避免中文事件字段在管道中的编码损坏，也避免单次 WinRM 响应过大。
"""

from __future__ import annotations

import base64
import datetime as dt
import gzip
import json
import os
import re
import shutil
import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from . import knowledge
from .elevation import is_admin
from .iis import IISRecord, parse_iis_text
from .models import Event
from .parser import decode_text, parse_events
from .tomcat import parse_tomcat_text

try:  # pragma: no cover - 依赖运行环境
    import winrm

    WINRM_AVAILABLE = True
except ImportError:  # pragma: no cover
    WINRM_AVAILABLE = False


class CollectionError(RuntimeError):
    """采集失败。"""


PS_PRELUDE = "$ErrorActionPreference='Stop'\n$ProgressPreference='SilentlyContinue'\n"
CHUNK_SIZE = 200_000


def ps_quote(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _ps_script(command: str) -> str:
    return PS_PRELUDE + command + "\n"


@dataclass
class CollectOptions:
    since_hours: int = 168
    max_events: int = 0
    logs: list[str] = field(default_factory=lambda: list(knowledge.CHANNELS))
    iis: bool = True
    iis_paths: list[str] = field(default_factory=list)
    iis_max_files: int = 5
    iis_tail_lines: int = 20000
    iis_max_bytes: int = 20 * 1024 * 1024
    tomcat: bool = True
    tomcat_paths: list[str] = field(default_factory=list)
    tomcat_max_files: int = 10
    tomcat_tail_lines: int = 20000
    posture: bool = True
    keep_raw: bool = False
    timeout: int = 300
    progress: Optional[Callable[[str], None]] = None


@dataclass
class CollectionResult:
    events: list[Event] = field(default_factory=list)
    iis_records: list[IISRecord] = field(default_factory=list)
    posture: dict = field(default_factory=dict)
    collection: list[dict] = field(default_factory=list)
    parse_errors: int = 0
    hostname: str = ""
    raw: dict[str, str] = field(default_factory=dict)
    iis_text: str = ""
    tomcat_text: str = ""


def _classify_error(message: str) -> str:
    text = (message or "").lower()
    if any(
        token in text
        for token in ("denied", "unauthorized", "access is denied", "拒绝访问", "未经授权")
    ):
        return "denied"
    if any(
        token in text
        for token in (
            "not found",
            "could not be found",
            "could not find",
            "cannot find",
            "does not exist",
            "no events",
            "not an event log",
            "找不到",
            "不存在",
            "无法检索",
        )
    ):
        return "unavailable"
    if "logdisabled" in text or "disabled" in text:
        return "unavailable"
    return "error"


# ---------------------------------------------------------------------------
# 采集器基类
# ---------------------------------------------------------------------------
class BaseCollector:
    name = "base"
    supports_iis = True
    supports_tomcat = True
    supports_posture = True

    def run_ps(self, script: str, timeout: Optional[int] = None) -> str:
        raise NotImplementedError

    def close(self) -> None:
        pass

    # ---- 大文本传输 ----
    def _transfer_script(self, body: str, token: str) -> str:
        return (
            PS_PRELUDE
            + "$wla_path = Join-Path $env:TEMP 'wla_"
            + token
            + ".b64'\n"
            + "try {\n"
            + body
            + "\n"
            + "  $wla_bytes = [Text.Encoding]::UTF8.GetBytes($wla_text)\n"
            + "  $wla_ms = New-Object IO.MemoryStream\n"
            + "  $wla_gz = New-Object IO.Compression.GZipStream($wla_ms, [IO.Compression.CompressionMode]::Compress)\n"
            + "  $wla_gz.Write($wla_bytes, 0, $wla_bytes.Length)\n"
            + "  $wla_gz.Dispose()\n"
            + "  [IO.File]::WriteAllBytes($wla_path + '.gz', $wla_ms.ToArray())\n"
            + "  [Convert]::ToBase64String([IO.File]::ReadAllBytes($wla_path + '.gz')) | Set-Content -Path $wla_path -Encoding ASCII\n"
            + "  Remove-Item ($wla_path + '.gz') -Force -ErrorAction SilentlyContinue\n"
            + "  'WLAOK'\n"
            + "} catch {\n"
            + "  'WLAERR ' + ($_.Exception.Message -replace \"`r|`n\", ' ')\n"
            + "}\n"
        )

    def run_ps_chunked(self, body: str, timeout: Optional[int] = None) -> str:
        token = uuid.uuid4().hex
        temp_name = f"wla_{token}.b64"

        def read_script(offset: int) -> str:
            return (
                "$p = Join-Path $env:TEMP '"
                + temp_name
                + "'; try { $t = [IO.File]::ReadAllText($p) -replace '\\s',''; "
                + f"$s = {offset}; if ($s -ge $t.Length) {{ 'WLAEND' }} else {{ "
                + f"$t.Substring($s, [Math]::Min({CHUNK_SIZE}, $t.Length - $s)) }} }} "
                + "catch { 'WLAERR ' + $_.Exception.Message }"
            )

        try:
            output = self.run_ps(self._transfer_script(body, token), timeout=timeout)
            if "WLAOK" not in output:
                message = ""
                for line in output.splitlines():
                    if line.startswith("WLAERR"):
                        message = line[len("WLAERR"):].strip()
                        break
                raise CollectionError(message or "采集脚本执行失败")
            chunks: list[str] = []
            offset = 0
            while True:
                part = self.run_ps(read_script(offset), timeout=60).strip()
                if part == "WLAEND":
                    break
                if part.startswith("WLAERR"):
                    raise CollectionError(part[len("WLAERR"):].strip())
                if not part:
                    break
                chunks.append(part)
                offset += len(part)
                if offset > 200 * 1024 * 1024:
                    raise CollectionError("采集数据超过 200MB，请缩小时间范围或条数")
            if not chunks:
                return ""
            data = base64.b64decode("".join(chunks))
            return gzip.decompress(data).decode("utf-8", errors="replace")
        finally:
            try:
                self.run_ps(
                    "$p = Join-Path $env:TEMP '"
                    + temp_name
                    + "'; Remove-Item $p -Force -ErrorAction SilentlyContinue",
                    timeout=20,
                )
            except Exception:
                pass

    # ---- 事件日志 ----
    def event_script(
        self,
        channel: str,
        ids: Optional[list[int]],
        max_events: int,
        since: Optional[dt.datetime],
        level: Optional[list[int]] = None,
    ) -> str:
        lines = ["$filter = @{}", f"$filter['LogName'] = {ps_quote(channel)}"]
        if ids:
            lines.append("$filter['Id'] = @(" + ",".join(str(int(i)) for i in ids) + ")")
        if level:
            lines.append("$filter['Level'] = @(" + ",".join(str(int(i)) for i in level) + ")")
        if since:
            lines.append(
                "$filter['StartTime'] = [datetime]::Parse("
                + ps_quote(since.astimezone().replace(microsecond=0).isoformat())
                + ", [Globalization.CultureInfo]::InvariantCulture)"
            )
        lines.append(f"$wla_log = Get-WinEvent -ListLog {ps_quote(channel)} -ErrorAction Stop")
        # 通道被禁用时不直接报错：继续尝试读取，由解析结果决定是空还是异常
        lines.append(
            f"$wla_events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents {int(max_events)} -ErrorAction SilentlyContinue)"
        )
        lines.append('$wla_text = ($wla_events | ForEach-Object { $_.ToXml() }) -join "`n"')
        return "\n".join(lines)

    def wevtutil_script(self, channel: str, max_events: int) -> str:
        """Get-WinEvent 被策略/安全软件拦截时，回退到 wevtutil。"""
        return "\n".join(
            [
                "$out = & wevtutil qe "
                + ps_quote(channel)
                + f" /c:{int(max_events)} /rd:true /f:RenderedXml 2>&1",
                "if ($LASTEXITCODE -ne 0) { throw ('wevtutil 失败: ' + (($out | Out-String).Trim())) }",
                "$wla_text = ($out | Out-String)",
            ]
        )

    def collect_events(
        self,
        channel: str,
        ids: Optional[list[int]],
        max_events: int,
        since: Optional[dt.datetime],
        timeout: Optional[int] = None,
        level: Optional[list[int]] = None,
    ) -> str:
        try:
            return self.run_ps_chunked(
                self.event_script(channel, ids, max_events, since, level), timeout=timeout
            )
        except CollectionError as error:
            # Get-WinEvent 可能被安全软件/组策略拦截，或旧版 PowerShell 不支持
            # -FilterHashtable；统一尝试 wevtutil 回退（不按事件 ID 过滤）。
            try:
                return self.run_ps_chunked(
                    self.wevtutil_script(channel, max_events), timeout=timeout
                )
            except CollectionError as fallback_error:
                raise CollectionError(
                    f"{error}；已尝试 wevtutil 回退仍失败：{fallback_error}"
                ) from fallback_error

    # ---- IIS ----
    def iis_script(self, options: CollectOptions) -> str:
        roots = options.iis_paths or [
            r"C:\inetpub\logs\LogFiles",
            r"%SystemDrive%\inetpub\logs\LogFiles",
        ]
        root_lines = []
        for root in roots:
            if "%" in root:
                root_lines.append(
                    "  $roots += [Environment]::ExpandEnvironmentVariables(" + ps_quote(root) + ")"
                )
            else:
                root_lines.append("  $roots += " + ps_quote(root))
        return "\n".join(
            [
                "$roots = @()",
                *root_lines,
                "$files = @()",
                "foreach ($r in $roots) { if (Test-Path -LiteralPath $r) { "
                "$files += @(Get-ChildItem -LiteralPath $r -Recurse -Filter '*.log' -ErrorAction SilentlyContinue) } }",
                "$files = @($files | Sort-Object FullName -Unique | Sort-Object LastWriteTime -Descending | Select-Object -First "
                + str(int(options.iis_max_files))
                + ")",
                "$sb = New-Object Text.StringBuilder",
                "foreach ($f in $files) {",
                "  [void]$sb.AppendLine('@@@WLAFILE ' + $f.FullName)",
                "  try {",
                f"    if ($f.Length -le {int(options.iis_max_bytes)}) {{",
                "      [void]$sb.AppendLine(((Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8) -join \"`n\"))",
                "    } else {",
                "      [void]$sb.AppendLine(((Get-Content -LiteralPath $f.FullName -TotalCount 10 -Encoding UTF8) -join \"`n\"))",
                f"      [void]$sb.AppendLine(((Get-Content -LiteralPath $f.FullName -Tail {int(options.iis_tail_lines)} -Encoding UTF8) -join \"`n\"))",
                "    }",
                "  } catch { }",
                "}",
                "$wla_text = $sb.ToString()",
            ]
        )

    def collect_iis(self, options: CollectOptions) -> str:
        return self.run_ps_chunked(self.iis_script(options), timeout=options.timeout)

    # ---- Tomcat ----
    def tomcat_script(self, options: CollectOptions) -> str:
        roots = options.tomcat_paths or [
            r"%CATALINA_BASE%\logs",
            r"%CATALINA_HOME%\logs",
            r"C:\Program Files\Apache Software Foundation\Tomcat*\logs",
            r"C:\Program Files (x86)\Apache Software Foundation\Tomcat*\logs",
            r"C:\apache-tomcat*\logs",
            r"C:\tomcat\logs",
        ]
        root_lines = []
        for root in roots:
            if "%" in root:
                root_lines.append(
                    "  $roots += [Environment]::ExpandEnvironmentVariables(" + ps_quote(root) + ")"
                )
            else:
                root_lines.append("  $roots += " + ps_quote(root))
        return "\n".join(
            [
                "$roots = @()",
                *root_lines,
                "$files = @()",
                "foreach ($r in $roots) { if ($r -and (Test-Path -Path $r)) { "
                "$files += @(Get-ChildItem -Path $r -Filter '*.log' -File -ErrorAction SilentlyContinue) } }",
                "$files = @($files | Where-Object { $_.Name -match 'access|catalina|localhost|manager|tomcat' } | "
                "Sort-Object LastWriteTime -Descending | Select-Object -First " + str(int(options.tomcat_max_files)) + ")",
                "$sb = New-Object Text.StringBuilder",
                "foreach ($f in $files) {",
                "  [void]$sb.AppendLine('@@@WLAFILE ' + $f.FullName)",
                "  try {",
                "    $len = (Get-Item -LiteralPath $f.FullName).Length",
                "    if ($len -le 20971520) {",
                "      [void]$sb.AppendLine(((Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8) -join \"`n\"))",
                "    } else {",
                "      [void]$sb.AppendLine(((Get-Content -LiteralPath $f.FullName -TotalCount 20 -Encoding UTF8) -join \"`n\"))",
                "      [void]$sb.AppendLine(((Get-Content -LiteralPath $f.FullName -Tail " + str(int(options.tomcat_tail_lines)) + " -Encoding UTF8) -join \"`n\"))",
                "    }",
                "  } catch { }",
                "}",
                "$wla_text = $sb.ToString()",
            ]
        )

    def collect_tomcat(self, options: CollectOptions) -> str:
        return self.run_ps_chunked(self.tomcat_script(options), timeout=options.timeout)

    # ---- 主机基线 ----
    def collect_posture(self, timeout: Optional[int] = None) -> dict:
        text = self.run_ps_chunked(POSTURE_SCRIPT, timeout=timeout)
        if not text.strip():
            return {}
        try:
            data = json.loads(text)
        except json.JSONDecodeError as error:
            raise CollectionError(f"主机配置 JSON 解析失败: {error}") from error
        return data if isinstance(data, dict) else {}


# ---------------------------------------------------------------------------
# 主机配置采集脚本
# ---------------------------------------------------------------------------
POSTURE_SCRIPT = r"""
function Get-RegBool([string]$path, [string]$name) {
  try {
    $item = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
    $value = $item.$name
    if ($null -ne $value) { return [bool]$value }
  } catch { }
  return $false
}
$r = [ordered]@{}
try { $r.hostname = $env:COMPUTERNAME } catch { }
try {
  $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
  $r.os = $os.Caption
  $r.boot_time = $os.LastBootUpTime.ToString('s')
  $r.uptime_days = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 2)
} catch { try { $os = Get-WmiObject -Class Win32_OperatingSystem; $r.os = $os.Caption } catch { } }
try {
  $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
  $r.domain = $cs.Domain
  $r.arch = $cs.SystemType
} catch { try { $cs = Get-WmiObject -Class Win32_ComputerSystem; $r.domain = $cs.Domain } catch { } }
try {
  $mp = Get-MpComputerStatus -ErrorAction Stop
  $r.defender = [ordered]@{
    realtime = [bool]$mp.RealTimeProtectionEnabled
    antivirus = [bool]$mp.AntivirusEnabled
    behavior = [bool]$mp.BehaviorMonitorEnabled
    tamper = [bool]$mp.IsTamperProtected
  }
} catch { }
try {
  $pref = Get-MpPreference -ErrorAction Stop
  $exclusions = @()
  if ($pref.ExclusionPath) { $exclusions += @($pref.ExclusionPath) }
  if ($pref.ExclusionProcess) { $exclusions += @($pref.ExclusionProcess) }
  if ($pref.ExclusionExtension) { $exclusions += @($pref.ExclusionExtension) }
  $r.defender_exclusions = $exclusions
} catch { }
try {
  $ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop
  $r.rdp_enabled = (-not [bool]$ts.fDenyTSConnections)
  try {
    $rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction Stop
    $r.rdp_nla = [bool]$rdp.UserAuthentication
    if ($rdp.PortNumber) { $r.rdp_port = [int]$rdp.PortNumber }
  } catch { }
} catch { }
try { $r.smb1 = [bool](Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch { }
try { $r.lsa_protection = [bool](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction Stop).RunAsPPL } catch { }
try { $r.wdigest = [int](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -ErrorAction Stop).UseLogonCredential } catch { }
try { $r.always_install_elevated = [bool](Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -ErrorAction Stop).AlwaysInstallElevated } catch { }
try {
  $winlogon = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction Stop
  $r.autoadminlogon = ([string]$winlogon.AutoAdminLogon -eq '1')
} catch { }
try {
  $guest = Get-LocalUser -Name 'Guest' -ErrorAction Stop
  $r.guest_enabled = [bool]$guest.Enabled
} catch { }
try {
  $pslog = [ordered]@{}
  $pslog.script_block = Get-RegBool 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
  $pslog.module = Get-RegBool 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging'
  $pslog.transcription = Get-RegBool 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting'
  $r.powershell_logging = $pslog
} catch { }
try {
  $r.audit = [ordered]@{
    command_line = Get-RegBool 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled'
  }
} catch { }
try {
  $r.firewall = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { [ordered]@{ name = $_.Name; enabled = [bool]$_.Enabled } })
} catch { }
try {
  $svc = @(Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue)
  if ($svc.Count -gt 0) { $r.sysmon = [string]$svc[0].Status } else { $r.sysmon = 'NotInstalled' }
} catch { $r.sysmon = 'Unknown' }
try {
  $r.local_admins = @(Get-LocalGroupMember -SID S-1-5-32-544 -ErrorAction Stop | ForEach-Object { $_.Name })
} catch {
  try { $r.local_admins = @(net localgroup administrators | Select-Object -Skip 6 | Where-Object { $_ -and $_ -notmatch 'command completed' }) } catch { }
}
try {
  $r.logs = @(Get-WinEvent -ListLog Security,System,Application,'Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue | ForEach-Object {
    [ordered]@{ name = $_.LogName; enabled = [bool]$_.IsEnabled; records = [int64]$_.RecordCount; size = [int64]$_.FileSize }
  })
} catch { }
$wla_text = ($r | ConvertTo-Json -Depth 6 -Compress)
"""


# ---------------------------------------------------------------------------
# WinRM
# ---------------------------------------------------------------------------
class WinRMCollector(BaseCollector):
    name = "winrm"

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 5985,
        use_ssl: bool = False,
        timeout: int = 300,
    ):
        if not WINRM_AVAILABLE:
            raise CollectionError("未安装 pywinrm，请执行: pip install pywinrm")
        scheme = "https" if use_ssl else "http"
        endpoint = f"{scheme}://{host}:{port}/wsman"
        self.endpoint = endpoint
        self.session = winrm.Session(
            endpoint,
            auth=(username, password),
            transport="ntlm",
            server_cert_validation="ignore",
            operation_timeout_sec=max(30, timeout),
            read_timeout_sec=max(60, timeout + 30),
        )

    def run_ps(self, script: str, timeout: Optional[int] = None) -> str:
        try:
            result = self.session.run_ps(script)
        except Exception as error:  # noqa: BLE001 - pywinrm 抛出多种异常
            raise CollectionError(f"WinRM 执行失败: {error}") from error
        stdout = decode_text(result.std_out)
        if result.status_code != 0:
            stderr = decode_text(result.std_err)[:800]
            raise CollectionError(
                f"PowerShell 返回码 {result.status_code}: {stderr or stdout[:400]}"
            )
        return stdout


# ---------------------------------------------------------------------------
# 本地
# ---------------------------------------------------------------------------
class LocalCollector(BaseCollector):
    name = "local"

    def __init__(self, timeout: int = 900):
        self.timeout = timeout
        self.powershell = self._find_powershell()

    @staticmethod
    def _find_powershell() -> str:
        candidates = [
            shutil.which("powershell.exe"),
            shutil.which("powershell"),
            os.path.join(
                os.environ.get("SystemRoot", r"C:\Windows"),
                "System32",
                "WindowsPowerShell",
                "v1.0",
                "powershell.exe",
            ),
        ]
        for candidate in candidates:
            if candidate and os.path.exists(candidate):
                return candidate
        raise CollectionError("未找到 powershell.exe，无法在本机采集日志")

    def run_ps(self, script: str, timeout: Optional[int] = None) -> str:
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        command = [
            self.powershell,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            encoded,
        ]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                timeout=timeout or self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise CollectionError(f"PowerShell 执行超时（{timeout or self.timeout}s）") from error
        stdout = decode_text(result.stdout)
        if result.returncode != 0 and not stdout.strip():
            raise CollectionError(
                f"PowerShell 返回码 {result.returncode}: "
                + decode_text(result.stderr)[:600]
            )
        return stdout


# ---------------------------------------------------------------------------
# 离线
# ---------------------------------------------------------------------------
_OFFLINE_LOG_HINTS = (
    ("security", ("security", "安全")),
    ("system", ("system", "系统")),
    ("application", ("application", "应用")),
    ("powershell", ("powershell", "ps_", "ps-")),
    ("sysmon", ("sysmon",)),
    ("defender", ("defender",)),
    ("rdp_lsm", ("localsessionmanager", "rdp_lsm", "rdp-", "rdp_")),
    ("rdp_rcm", ("remoteconnectionmanager", "rdp_rcm")),
    ("wmi", ("wmi",)),
    ("bits", ("bits",)),
    ("taskscheduler", ("taskscheduler", "task-", "task_")),
)


def _guess_log_from_name(path: Path) -> str:
    name = path.name.lower()
    for key, tokens in _OFFLINE_LOG_HINTS:
        if any(token in name for token in tokens):
            return key
    return ""


class OfflineCollector(BaseCollector):
    """从导出的 XML / EVTX / IIS 日志目录做离线分析。"""

    name = "offline"
    supports_posture = False
    supports_iis = True

    def __init__(self, directory: str):
        self.directory = Path(directory).expanduser().resolve()
        if not self.directory.exists():
            raise CollectionError(f"离线目录不存在: {self.directory}")
        self.files = [p for p in sorted(self.directory.rglob("*")) if p.is_file()]
        if not self.files:
            raise CollectionError(f"离线目录中没有文件: {self.directory}")

    def run_ps(self, script: str, timeout: Optional[int] = None) -> str:  # pragma: no cover
        raise CollectionError("离线模式不支持执行 PowerShell")

    def collect_all(self, options: CollectOptions) -> CollectionResult:
        result = CollectionResult()
        for path in self.files:
            suffix = path.suffix.lower()
            if suffix in {".evtx"}:
                self._load_evtx(path, result)
            elif suffix in {".xml", ".txt", ".log", ".tsv", ".jsonl"}:
                self._load_text_file(path, result)
        if options.posture:
            for name in ("posture.json", "host.json", "posture.txt"):
                candidate = self.directory / name
                if candidate.exists():
                    try:
                        result.posture = json.loads(candidate.read_text("utf-8-sig"))
                    except (OSError, json.JSONDecodeError):
                        pass
                    break
        if not result.collection:
            result.collection.append(
                {
                    "log": "offline",
                    "label": f"离线目录 {self.directory}",
                    "count": 0,
                    "status": "error",
                    "error": "未识别到可解析的事件 XML 或 IIS 日志文件",
                }
            )
        return result

    def _load_evtx(self, path: Path, result: CollectionResult) -> None:
        entry = {
            "log": _guess_log_from_name(path) or "evtx",
            "label": path.name,
            "count": 0,
            "status": "ok",
            "error": "",
        }
        wevtutil = shutil.which("wevtutil")
        if not wevtutil:
            entry.update(status="error", error="当前系统没有 wevtutil，无法解析 EVTX，请先导出为 XML")
            result.collection.append(entry)
            return
        try:
            process = subprocess.run(
                [wevtutil, "qe", str(path), "/lf:true", "/f:RenderedXml"],
                capture_output=True,
                timeout=300,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            entry.update(status="error", error=str(error))
            result.collection.append(entry)
            return
        text = decode_text(process.stdout)
        default_log = _guess_log_from_name(path)
        stats = {"parsed": 0, "errors": 0}
        events = parse_events(text, default_log, stats)
        result.events.extend(events)
        result.parse_errors += stats["errors"]
        entry["count"] = len(events)
        entry["status"] = "ok" if events else "empty"
        if not events:
            entry["error"] = decode_text(process.stderr)[:200]
        result.collection.append(entry)

    @staticmethod
    def _looks_tomcat(path: Path, head: str) -> bool:
        name = path.name.lower()
        if any(token in name for token in ("catalina", "tomcat", "localhost_access", "manager.")):
            return True
        if re.search(r"\[\d{2}/[A-Za-z]{3}/\d{4}:", head) and re.search(
            r'"(?:GET|POST|PUT|HEAD|DELETE) ', head
        ):
            return True
        return bool(
            re.search(
                r"^\d{2}-[A-Za-z]{3}-\d{4} .*?(?:SEVERE|WARNING|INFO) \[",
                head,
                re.M,
            )
        )

    def _load_text_file(self, path: Path, result: CollectionResult) -> None:
        try:
            raw = path.read_bytes()
        except OSError as error:
            result.collection.append(
                {
                    "log": "offline",
                    "label": path.name,
                    "count": 0,
                    "status": "error",
                    "error": str(error),
                }
            )
            return
        text = decode_text(raw)
        head = text[:4096]
        if "<Event" in head or "<Events" in head:
            default_log = _guess_log_from_name(path)
            stats = {"parsed": 0, "errors": 0}
            events = parse_events(text, default_log, stats)
            result.events.extend(events)
            result.parse_errors += stats["errors"]
            result.collection.append(
                {
                    "log": default_log or "offline",
                    "label": path.name,
                    "count": len(events),
                    "status": "ok" if events else "empty",
                    "error": "" if events else "文件中没有可解析的事件",
                }
            )
            if len(events) == 0 and stats["errors"]:
                result.collection[-1]["error"] = f"{stats['errors']} 条事件解析失败"
        elif self._looks_tomcat(path, head):
            access, catalina = parse_tomcat_text(f"@@@WLAFILE {path}\n{text}")
            result.tomcat_text += f"\n@@@WLAFILE {path}\n{text}"
            count = len(access) + len(catalina)
            result.collection.append(
                {
                    "log": "tomcat",
                    "label": path.name,
                    "count": count,
                    "status": "ok" if count else "empty",
                    "error": "" if count else "未解析到 Tomcat 日志行",
                }
            )
        elif "#Fields:" in text or "cs-uri-stem" in text[:8192]:
            records = parse_iis_text(text, str(path))
            result.iis_records.extend(records)
            result.iis_text += f"\n@@@WLAFILE {path}\n{text}"
            result.collection.append(
                {
                    "log": "iis",
                    "label": path.name,
                    "count": len(records),
                    "status": "ok" if records else "empty",
                    "error": "" if records else "未解析到 IIS 请求",
                }
            )
        else:
            result.collection.append(
                {
                    "log": "offline",
                    "label": path.name,
                    "count": 0,
                    "status": "skipped",
                    "error": "未识别的文件格式（支持事件 XML、EVTX、IIS W3C 日志）",
                }
            )


# ---------------------------------------------------------------------------
# 编排
# ---------------------------------------------------------------------------
def collect(
    collector: BaseCollector,
    options: CollectOptions,
) -> CollectionResult:
    if isinstance(collector, OfflineCollector):
        return collector.collect_all(options)

    result = CollectionResult()
    since = (
        dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=options.since_hours)
        if options.since_hours and options.since_hours > 0
        else None
    )
    progress = options.progress or (lambda message: None)

    for key in options.logs:
        if key not in knowledge.CHANNELS:
            continue
        channel, label, default_max = knowledge.CHANNELS[key]
        max_events = options.max_events or default_max
        ids = knowledge.COLLECTION_PLAN.get(key)
        level = None
        if key == "application":
            ids = None
            level = [1, 2]
        entry = {
            "log": key,
            "channel": channel,
            "label": label,
            "count": 0,
            "status": "ok",
            "error": "",
            "limit": max_events,
        }
        started = dt.datetime.now()
        progress(f"采集 {label} ...")
        try:
            text = collector.collect_events(
                channel, ids, max_events, since, options.timeout, level
            )
        except CollectionError as error:
            message = str(error)
            status = _classify_error(message)
            entry.update(status=status, error=message[:300])
            if (
                key == "security"
                and status == "denied"
                and getattr(collector, "name", "") == "local"
                and not is_admin()
            ):
                entry["error"] = (
                    entry["error"].rstrip("。.")
                    + "；当前进程未提升，请以管理员身份运行（可用 --diagnose 检查）"
                )
            result.collection.append(entry)
            progress(f"  {label}: {status} {message[:120]}")
            continue
        except Exception as error:  # noqa: BLE001
            entry.update(status="error", error=str(error)[:300])
            result.collection.append(entry)
            progress(f"  {label}: error {error}")
            continue

        stats = {"parsed": 0, "errors": 0}
        events = parse_events(text, key, stats)
        result.events.extend(events)
        result.parse_errors += stats["errors"]
        entry["count"] = len(events)
        entry["elapsed"] = round((dt.datetime.now() - started).total_seconds(), 2)
        if not events:
            entry["status"] = "empty"
        if options.keep_raw:
            result.raw[key] = text
        result.collection.append(entry)
        progress(f"  {label}: {len(events)} 条")

    if options.iis and collector.supports_iis:
        entry = {
            "log": "iis",
            "label": "IIS Web 日志",
            "count": 0,
            "status": "ok",
            "error": "",
        }
        progress("采集 IIS 日志 ...")
        try:
            text = collector.collect_iis(options)
            if text.strip():
                records = parse_iis_text(text)
                result.iis_records.extend(records)
                result.iis_text = text
                entry["count"] = len(records)
                entry["status"] = "ok" if records else "empty"
                if options.keep_raw:
                    result.raw["iis"] = text
            else:
                entry["status"] = "empty"
                entry["error"] = "未找到 IIS 日志文件（站点可能未使用 IIS）"
        except CollectionError as error:
            entry.update(status=_classify_error(str(error)), error=str(error)[:300])
        except Exception as error:  # noqa: BLE001
            entry.update(status="error", error=str(error)[:300])
        result.collection.append(entry)
        progress(f"  IIS: {entry['count']} 条")

    if options.tomcat and collector.supports_tomcat:
        entry = {
            "log": "tomcat",
            "label": "Tomcat 中间件日志",
            "count": 0,
            "status": "ok",
            "error": "",
        }
        progress("采集 Tomcat 日志 ...")
        try:
            text = collector.collect_tomcat(options)
            if text.strip():
                access, catalina = parse_tomcat_text(text)
                result.tomcat_text = text
                entry["count"] = len(access) + len(catalina)
                entry["status"] = "ok" if entry["count"] else "empty"
                if options.keep_raw:
                    result.raw["tomcat"] = text
            else:
                entry["status"] = "empty"
                entry["error"] = "未找到 Tomcat 日志（可通过 --tomcat-path 指定）"
        except CollectionError as error:
            entry.update(status=_classify_error(str(error)), error=str(error)[:300])
        except Exception as error:  # noqa: BLE001
            entry.update(status="error", error=str(error)[:300])
        result.collection.append(entry)
        progress(f"  Tomcat: {entry['count']} 条")

    if options.posture and collector.supports_posture:
        progress("采集主机安全配置 ...")
        try:
            result.posture = collector.collect_posture(options.timeout)
            status = "ok" if result.posture else "empty"
        except Exception as error:  # noqa: BLE001
            result.posture = {}
            status = "error"
            result.collection.append(
                {
                    "log": "posture",
                    "label": "主机配置基线",
                    "count": 0,
                    "status": status,
                    "error": str(error)[:300],
                }
            )
        else:
            result.collection.append(
                {
                    "log": "posture",
                    "label": "主机配置基线",
                    "count": len(result.posture),
                    "status": status,
                    "error": "",
                }
            )
        progress(f"  主机配置: {status}")

    if not result.hostname:
        try:
            result.hostname = collector.run_ps("$env:COMPUTERNAME", timeout=30).strip()
        except Exception:  # noqa: BLE001
            result.hostname = ""
    return result
