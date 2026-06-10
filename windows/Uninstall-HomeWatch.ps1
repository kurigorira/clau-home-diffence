<#
.SYNOPSIS
    HomeWatch のタスクスケジューラ登録を解除し、任意でデータ（ベースライン/ログ）を削除する。

.PARAMETER RemoveData
    指定すると %ProgramData%\HomeWatch のベースライン・ログも削除する。
#>
[CmdletBinding()]
param(
    [switch]$RemoveData,
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config\homewatch.config.psd1')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$taskName = 'HomeWatch-Scan'
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    Write-Host "タスク '$taskName' を削除しました。"
} else {
    Write-Host "タスク '$taskName' は登録されていません。"
}

if ($RemoveData) {
    $cfg = Import-PowerShellDataFile -Path $ConfigPath
    foreach ($p in @($cfg.LogPath, $cfg.BaselinePath)) {
        if ($p -and (Test-Path $p)) { Remove-Item -Path $p -Force; Write-Host "削除: $p" }
    }
    $dir = Split-Path -Parent $cfg.BaselinePath
    if ($dir -and (Test-Path $dir) -and -not (Get-ChildItem -Path $dir -ErrorAction SilentlyContinue)) {
        Remove-Item -Path $dir -Force
    }
}

Write-Host "アンインストール完了。"
