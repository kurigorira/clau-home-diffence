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
    [string]$ConfigPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# スクリプトの所在フォルダを堅牢に解決（一部環境では param 既定値内の $PSScriptRoot が空になるため）
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
if (-not $ConfigPath) { $ConfigPath = Join-Path $ScriptDir 'config\homewatch.config.psd1' }

# 管理者チェック
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "管理者として実行してください（セキュリティログ読み取りとタスク登録に必要）。"
    exit 1
}

Import-Module (Join-Path $ScriptDir 'modules\HomeWatch.psm1') -Force
$scanScript = Join-Path $ScriptDir 'Invoke-HomeWatchScan.ps1'
. $scanScript -ConfigPath $ConfigPath -ErrorAction SilentlyContinue 2>$null  # 収集関数を読み込むためのドットソース

$cfg = Import-PowerShellDataFile -Path $ConfigPath
# %ProgramData% などの環境変数を実際のパスに展開する
$cfg.LogPath = [Environment]::ExpandEnvironmentVariables($cfg.LogPath)
$cfg.BaselinePath = [Environment]::ExpandEnvironmentVariables($cfg.BaselinePath)

# 先にタスクスケジューラへ登録する。こうすると直後に取るベースラインに HomeWatch 自身の
# タスクが含まれ、初回スキャンで自分自身を「新しい自動起動」と誤検知しない。
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

Write-Host "現在の状態をベースラインとして取得しています..."
$baseline = @{
    Persistence = @(Get-CurrentPersistence)
    LocalUsers  = @(Get-CurrentLocalUsers)
    # 現在の待ち受けポートを許可済みとして記録（以後は新規の待ち受けだけを検知）
    Listeners   = @(Get-CurrentListeners | ForEach-Object {
        [pscustomobject]@{ port = [int]$_.LocalPort; process = $_.OwningProcessName }
    })
}
Save-Baseline -Baseline $baseline -Path $cfg.BaselinePath
Write-Host "ベースライン保存: $($cfg.BaselinePath)"
Write-Host ("  自動起動エントリ {0} 件 / ローカルユーザー {1} 件 / 待ち受けポート {2} 件" -f `
    $baseline.Persistence.Count, $baseline.LocalUsers.Count, $baseline.Listeners.Count)

Write-Host "初回スキャンを実行します..."
& $scanScript -ConfigPath $ConfigPath
Write-Host "セットアップ完了。アラートは $($cfg.LogPath) と画面通知で確認できます。"
