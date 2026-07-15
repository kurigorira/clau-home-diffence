<#
.SYNOPSIS
    HomeWatch 本体スキャン。Windows のログ/状態を収集し、HomeWatch.psm1 の検知関数にかけ、
    異常があればトースト通知＋ローカルログに記録する。タスクスケジューラから定期実行される。

.DESCRIPTION
    実データの収集（Get-WinEvent / Get-NetTCPConnection / Get-LocalUser / レジストリ）はこのスクリプトが担い、
    検知判定そのものは HomeWatch.psm1 の純粋関数に委ねる（テスト可能性のための分離）。
    管理者権限（特にセキュリティイベントログの読み取り）が必要。
.NOTES
    収集データはローカル（%ProgramData%\HomeWatch）にのみ保存し、外部送信しない。
#>
[CmdletBinding()]
param(
    [string]$ConfigPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# スクリプトの所在フォルダを堅牢に解決（一部環境では param 既定値内の $PSScriptRoot が空になるため）
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
if (-not $ConfigPath) { $ConfigPath = Join-Path $ScriptDir 'config\homewatch.config.psd1' }

Import-Module (Join-Path $ScriptDir 'modules\HomeWatch.psm1') -Force
$cfg = Import-PowerShellDataFile -Path $ConfigPath
# %ProgramData% などの環境変数を実際のパスに展開する
$cfg.LogPath = [Environment]::ExpandEnvironmentVariables($cfg.LogPath)
$cfg.BaselinePath = [Environment]::ExpandEnvironmentVariables($cfg.BaselinePath)

# データ収集関数（Get-RecentLogonEvents / Get-CurrentListeners / Get-CurrentLocalUsers /
# Get-CurrentPersistence / Get-MicCameraAccess）は HomeWatch.psm1 から提供される。

# ---------------------------------------------------------------------------
# スキャン実行
# ---------------------------------------------------------------------------
$baseline = Get-Baseline -Path $cfg.BaselinePath
if (-not $baseline) {
    Write-Warning "ベースラインがありません。先に Install-HomeWatch.ps1 を実行してください。"
    exit 1
}

$alerts = [System.Collections.Generic.List[object]]::new()

# 検知関数が 0 件を返すと PowerShell では結果が $null になり得るため、@() で包み null 要素を除いて追加する
function Add-AlertBatch {
    param($Batch)
    foreach ($a in @($Batch)) {
        if ($null -ne $a) { [void]$alerts.Add($a) }
    }
}

# 旧バージョンのベースライン（フィールド欠落）でも動くよう StrictMode 安全に取り出す
$baselineListeners   = @(Get-PropOr $baseline 'Listeners' @())
$baselinePersistence = @(Get-PropOr $baseline 'Persistence' @())
$baselineUsers       = @(Get-PropOr $baseline 'LocalUsers' @())

Add-AlertBatch (Test-LogonEvents -Events @(Get-RecentLogonEvents -Minutes $cfg.EventLookbackMinutes) -Config $cfg)
Add-AlertBatch (Test-NetworkListeners -Listeners @(Get-CurrentListeners) -AllowedPorts $cfg.AllowedListeningPorts `
    -BaselinePorts $baselineListeners -EphemeralStart $cfg.EphemeralPortStart -IgnoreEphemeral $cfg.IgnoreEphemeralPorts)
Add-AlertBatch (Test-Persistence -Current @(Get-CurrentPersistence) -Baseline $baselinePersistence `
    -IgnorePatterns @(Get-PropOr $cfg 'PersistenceIgnorePatterns' @()))
Add-AlertBatch (Test-NewLocalUsers -Current @(Get-CurrentLocalUsers) -Baseline $baselineUsers)
Add-AlertBatch (Test-MicCameraAccess -AccessRecords @(Get-MicCameraAccess) -AllowedApps $cfg.AllowedMicCameraApps -SinceHours $cfg.MicCameraSinceHours)

$notified = 0
foreach ($a in $alerts) {
    $isNew = Write-HomeWatchLog -Alert $a -Path $cfg.LogPath -DedupeWindowMinutes $cfg.DedupeWindowMinutes
    if ($isNew) {
        Send-HomeWatchAlert -Alert $a
        $notified++
    }
}

# ハートビート：異常が無くても毎回 1 行残し、稼働していることを確認できるようにする
$dir = Split-Path -Parent $cfg.LogPath
if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
(@{ Time = (Get-Date).ToString('o'); event = 'scan_ok'; severity = 'info';
    detected = $alerts.Count; notified = $notified } | ConvertTo-Json -Compress) |
    Add-Content -Path $cfg.LogPath -Encoding UTF8

# HeartbeatToast が有効で、かつ今回アラート通知を出していなければ「監視OK」トーストを出す
if ($cfg.ContainsKey('HeartbeatToast') -and $cfg.HeartbeatToast -and $notified -eq 0) {
    Send-HomeWatchAlert -Alert (New-HomeWatchAlert -Category 'heartbeat' -Severity 'info' `
        -Message "PC監視OK（検知 $($alerts.Count) 件）")
}

Write-Output "HomeWatch スキャン完了: 検知 $($alerts.Count) 件 / 新規通知 $notified 件 (ログ: $($cfg.LogPath))"
