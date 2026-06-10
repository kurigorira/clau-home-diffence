<#
.SYNOPSIS
    HomeWatch を初期セットアップする。現在の状態をベースラインとして保存し、
    タスクスケジューラに定期スキャンを登録する。

.DESCRIPTION
    管理者として実行すること。「いま正常な状態」をベースラインに取り込むので、
    マルウェアに感染していない確証がある状態で実行するのが望ましい。
.PARAMETER IntervalMinutes
    スキャンの実行間隔（分）。既定 15。
.EXAMPLE
    # 管理者 PowerShell で
    powershell -ExecutionPolicy Bypass -File .\Install-HomeWatch.ps1
#>
[CmdletBinding()]
param(
    [int]$IntervalMinutes = 15,
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config\homewatch.config.psd1')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# 管理者チェック
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "管理者として実行してください（セキュリティログ読み取りとタスク登録に必要）。"
    exit 1
}

Import-Module (Join-Path $PSScriptRoot 'modules\HomeWatch.psm1') -Force
$scanScript = Join-Path $PSScriptRoot 'Invoke-HomeWatchScan.ps1'
. $scanScript -ConfigPath $ConfigPath -ErrorAction SilentlyContinue 2>$null  # 収集関数を読み込むためのドットソース

$cfg = Import-PowerShellDataFile -Path $ConfigPath

Write-Host "現在の状態をベースラインとして取得しています..."
$baseline = @{
    Persistence = @(Get-CurrentPersistence)
    LocalUsers  = @(Get-CurrentLocalUsers)
}
Save-Baseline -Baseline $baseline -Path $cfg.BaselinePath
Write-Host "ベースライン保存: $($cfg.BaselinePath)"
Write-Host ("  自動起動エントリ {0} 件 / ローカルユーザー {1} 件" -f $baseline.Persistence.Count, $baseline.LocalUsers.Count)

# タスクスケジューラ登録（SYSTEM 権限で IntervalMinutes ごと）
$taskName = 'HomeWatch-Scan'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scanScript`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null

Write-Host "タスク登録完了: '$taskName' を $IntervalMinutes 分ごとに実行します。"
Write-Host "初回スキャンを実行します..."
& $scanScript -ConfigPath $ConfigPath
Write-Host "セットアップ完了。アラートは $($cfg.LogPath) と画面通知で確認できます。"
