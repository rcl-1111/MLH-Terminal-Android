<#
.SYNOPSIS
    MLH-Terminal Windows 启动器
.DESCRIPTION
    在 Windows 上启动 MLH-Terminal 命令行环境
    自动设置 PATH 和虚拟环境
#>

# 获取脚本所在目录（MLH-Terminal 根目录）
$MLH_ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
$MLH_COMMANDS = Join-Path $MLH_ROOT "File\Commands"
$MLH_DATA = Join-Path $MLH_ROOT "Data"

# 颜色函数
function Write-Color($Text, $Color = "Cyan") {
    Write-Host $Text -ForegroundColor $Color
}

# 清屏
Clear-Host

# Banner
Write-Color ""
Write-Color "═══════════════════════════════════════════" "DarkCyan"
Write-Color "       MLH-Terminal  Windows 环境          " "Cyan"
Write-Color "═══════════════════════════════════════════" "DarkCyan"
Write-Color ""

# 环境信息
Write-Color " [*] 根目录: $MLH_ROOT" -Color Yellow
Write-Color " [*] 命令目录: $MLH_COMMANDS" -Color Yellow
Write-Color " [*] 数据目录: $MLH_DATA" -Color Yellow
Write-Color ""

# 设置环境变量
$env:MLH_ROOT = $MLH_ROOT
$env:MLH_COMMANDS = $MLH_COMMANDS
$env:MLH_DATA = $MLH_DATA

# 将命令目录加入 PATH
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
$currentPath = $env:PATH
if ($currentPath -notlike "*$MLH_COMMANDS*") {
    $env:PATH = "$MLH_COMMANDS;$env:PATH"
    Write-Color " [√] 已添加命令目录到 PATH" -Color Green
}

# 检查 Python
$pythonCmd = Get-Command "python" -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    $pythonCmd = Get-Command "python3" -ErrorAction SilentlyContinue
}
if ($pythonCmd) {
    Write-Color " [√] Python: $($pythonCmd.Source)" -Color Green
} else {
    Write-Color " [×] 未找到 Python，请安装 Python 3" -Color Red
}

# 可用命令
Write-Color ""
Write-Color " [*] 可用命令:" -Color Yellow
Write-Color "   wnad              WNAD 无线网络攻防工具" -Color White
Write-Color "   netcheck          网络检测工具" -Color White
Write-Color "   exit              退出 MLH-Terminal" -Color White
Write-Color ""
Write-Color " 也可以在 PowerShell 中直接运行 wnad 命令" -Color DarkGray
Write-Color ""
Write-Color "═══════════════════════════════════════════" "DarkCyan"
Write-Color ""

# 设置自定义提示符（在 profile 层面设置）
$env:MLH_ACTIVE = "1"
$script:MLHPrompt = {
    "MLH $($executionContext.SessionState.Path.CurrentLocation)> "
}

# 可选: 启动后立即执行一个命令
if ($args.Count -gt 0) {
    Write-Color " [>] 执行: $($args -join ' ')" -Color Cyan
    & $pythonCmd (Join-Path $MLH_ROOT "File\Commands\Tools\Wifi\WNAD\wnad.py") $args
    Write-Color ""
    Write-Color " [*] 命令执行完毕" -Color Yellow
    Write-Color " [*] 按 Enter 进入 MLH-Terminal 命令行..." -Color Yellow
    Read-Host | Out-Null
}
