# 构建单文件 WindowsLogAudit.exe（含图表、Word、WinRM、Tomcat）
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

python -m PyInstaller --clean --noconfirm build_exe.spec

$exe = Join-Path $PSScriptRoot "dist\WindowsLogAudit.exe"
if (-not (Test-Path $exe)) {
    throw "构建失败：未生成 $exe"
}
$size = [math]::Round((Get-Item $exe).Length / 1MB, 1)
Write-Host ""
Write-Host "构建完成：$exe（$size MB）" -ForegroundColor Green
Write-Host "双击运行打开图形界面；命令行示例：" -ForegroundColor Cyan
Write-Host "  .\dist\WindowsLogAudit.exe --demo"
Write-Host "  .\dist\WindowsLogAudit.exe --local --format all"
Write-Host "  .\dist\WindowsLogAudit.exe --host 10.0.0.5 -u Administrator --ssl"
