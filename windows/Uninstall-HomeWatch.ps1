<#
.SYNOPSIS
    HomeWatch のタスクスケジューラ登録を解除し、任意でデータ（ベースライン/ログ）を削除する。

.PARAMETER RemoveData
    指定すると %ProgramData%\HomeWatch のベースライン・ログも削除する。
#>
[CmdletBinding()]
param(
    [switch]$RemoveData,
    [string]$ConfigPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# スクリプトの所在フォルダを堅牢に解決（一部環境では param 既定値内の $PSScriptRoot が空になるため）
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
if (-not $ConfigPath) { $ConfigPath = Join-Path $ScriptDir 'config\homewatch.config.psd1' }

$taskName = 'HomeWatch-Scan'
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    Write-Host "タスク '$taskName' を削除しました。"
} else {
    Write-Host "タスク '$taskName' は登録されていません。"
}

if ($RemoveData) {
    $cfg = Import-PowerShellDataFile -Path $ConfigPath
    # %ProgramData% などの環境変数を実際のパスに展開する
    $cfg.LogPath = [Environment]::ExpandEnvironmentVariables($cfg.LogPath)
    $cfg.BaselinePath = [Environment]::ExpandEnvironmentVariables($cfg.BaselinePath)
    foreach ($p in @($cfg.LogPath, $cfg.BaselinePath)) {
        if ($p -and (Test-Path $p)) { Remove-Item -Path $p -Force; Write-Host "削除: $p" }
    }
    $dir = Split-Path -Parent $cfg.BaselinePath
    if ($dir -and (Test-Path $dir) -and -not (Get-ChildItem -Path $dir -ErrorAction SilentlyContinue)) {
        Remove-Item -Path $dir -Force
    }
}

Write-Host "アンインストール完了。"
