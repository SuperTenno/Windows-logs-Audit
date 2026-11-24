"""环境诊断：检查管理员权限、Security 日志可读性与审核策略。

用于快速定位“管理员运行仍读不到安全日志”的原因：
  * 进程是否真正提升（UAC 过滤令牌）；
  * Security 通道是否可访问/是否启用/记录数；
  * 抽样读取是否成功，以及具体错误；
  * 事件日志服务、审核策略与通道配置。
"""

from __future__ import annotations

import json
from typing import Any

from .collectors import BaseCollector

DIAGNOSTIC_SCRIPT = r"""
$r = [ordered]@{}
try {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $r.user = $identity.Name
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  $r.elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { $r.elevated = $false }
try { $r.hostname = $env:COMPUTERNAME } catch { }
try { $r.ps_version = $PSVersionTable.PSVersion.ToString() } catch { }
try { $r.ps_edition = $PSVersionTable.PSEdition } catch { }
try {
  $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
  $r.os = "$($os.Caption) $($os.Version)"
} catch { }
try {
  $svc = Get-Service -Name EventLog -ErrorAction Stop
  $r.eventlog_service = [string]$svc.Status
} catch { $r.eventlog_service = "未知" }

try {
  $log = Get-WinEvent -ListLog Security -ErrorAction Stop
  $r.security_access = $true
  $r.security_enabled = [bool]$log.IsEnabled
  $r.security_records = [int64]$log.RecordCount
  $r.security_size = [int64]$log.FileSize
} catch {
  $r.security_access = $false
  $r.security_error = $_.Exception.Message
}

if ($r.security_access -eq $true) {
  try {
    $sample = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop
    $r.security_read = $true
    $r.security_sample_id = [int]$sample.Id
  } catch {
    $r.security_read = $false
    $r.security_read_error = $_.Exception.Message
  }
  try {
    $r.security_config = (wevtutil gl Security 2>&1 | Out-String).Trim()
  } catch { }
}

try {
  $audit = (auditpol /get /category:* 2>&1 | Out-String).Trim()
  if ($audit.Length -gt 3000) { $audit = $audit.Substring(0, 3000) }
  $r.audit_policy = $audit
} catch {
  $r.audit_error = $_.Exception.Message
}
$wla_text = ($r | ConvertTo-Json -Depth 4 -Compress)
"""


def run_diagnostics(collector: BaseCollector, timeout: int = 120) -> dict[str, Any]:
    text = collector.run_ps_chunked(DIAGNOSTIC_SCRIPT, timeout=timeout)
    if not text.strip():
        raise RuntimeError("诊断脚本没有返回数据")
    data = json.loads(text)
    if not isinstance(data, dict):
        raise RuntimeError("诊断结果格式异常")
    return data


def security_usable(data: dict[str, Any]) -> bool:
    return bool(data.get("security_access")) and bool(data.get("security_read", False))


def format_diagnostics(data: dict[str, Any]) -> str:
    elevated = bool(data.get("elevated"))
    access = bool(data.get("security_access"))
    read = bool(data.get("security_read"))

    def mark(value: bool) -> str:
        return "✓" if value else "✗"

    lines = [
        "=" * 60,
        "环境诊断结果",
        "=" * 60,
        f"主机名        : {data.get('hostname') or '-'}",
        f"操作系统      : {data.get('os') or '-'}",
        f"当前用户      : {data.get('user') or '-'}",
        f"管理员权限    : {mark(elevated)} {'是（已提升）' if elevated else '否（UAC 过滤令牌）'}",
        f"PowerShell    : {data.get('ps_version') or '-'} ({data.get('ps_edition') or '-'})",
        f"EventLog 服务 : {data.get('eventlog_service') or '-'}",
        "",
        "Security 日志：",
        f"  可访问      : {mark(access)}",
    ]
    if access:
        lines.append(f"  已启用      : {mark(bool(data.get('security_enabled')))}")
        lines.append(f"  记录数      : {data.get('security_records', 0):,}")
        lines.append(f"  文件大小    : {data.get('security_size', 0):,} 字节")
        lines.append(f"  抽样读取    : {mark(read)}")
        if not read:
            lines.append(f"  读取错误    : {data.get('security_read_error') or '-'}")
    else:
        lines.append(f"  访问错误    : {data.get('security_error') or '-'}")

    lines.append("")
    if not elevated:
        lines.append("诊断结论：当前进程未获得完整管理员令牌。")
        lines.append("  Windows 管理员账户在 UAC 下默认使用过滤令牌，普通双击无法读取 Security 日志。")
        lines.append("  解决：右键程序 → “以管理员身份运行”；或在本工具中点击“以管理员身份重启”。")
    elif not access:
        lines.append("诊断结论：进程已提升，但 Security 日志仍被拒绝。")
        lines.append("  请依次检查：")
        lines.append("  1) 本地安全策略/组策略中的“配置日志访问”是否限制了读取账户；")
        lines.append("  2) 当前账户是否在“Event Log Readers”或 Administrators 组中；")
        lines.append("  3) 安全软件/EDR 是否拦截了事件日志读取；")
        lines.append("  4) Security 通道是否被禁用或损坏（wevtutil gl Security）。")
    elif not read:
        lines.append("诊断结论：通道元数据可读，但抽样读取失败，可能是权限或日志损坏。")
        lines.append("  请以管理员 PowerShell 执行：Get-WinEvent -LogName Security -MaxEvents 1")
    elif not data.get("security_records"):
        lines.append("诊断结论：Security 日志可读但为空。")
        lines.append("  请检查审核策略（登录、账户管理、进程创建等）是否开启。")
    else:
        lines.append("诊断结论：Security 日志读取正常，可正常采集。")

    audit = data.get("audit_policy") or ""
    if audit:
        lines.append("")
        lines.append("审核策略（auditpol 摘要）：")
        for row in audit.splitlines()[:40]:
            if row.strip():
                lines.append("  " + row.strip())
    if data.get("security_config"):
        lines.append("")
        lines.append("Security 通道配置（wevtutil gl Security）：")
        for row in str(data["security_config"]).splitlines()[:15]:
            lines.append("  " + row)
    lines.append("=" * 60)
    return "\n".join(lines)
