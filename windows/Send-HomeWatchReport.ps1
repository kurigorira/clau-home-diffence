<#
.SYNOPSIS
    HomeWatch 日次レポートをメール送信する。-Setup で初期設定（送信情報の保存＋毎日のタスク登録）。

.DESCRIPTION
    直近24時間の PC 監視ログとネットワーク監視ログを集計し、1通のメールにまとめて送る。
    パスワード（Gmail の場合はアプリパスワード）は DPAPI で暗号化してローカルに保存し、
    保存したユーザー本人しか復号できない（平文では保存しない）。

.PARAMETER Setup
    初期設定モード。送信元/送信先/SMTP を確認し、資格情報を暗号化保存し、
    毎日 -DailyAt 時刻に実行するタスク 'HomeWatch-DailyReport' を登録してテスト送信する。

.PARAMETER DailyAt
    日次レポートの送信時刻（既定 '08:00'）。-Setup 時のみ使用。

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Send-HomeWatchReport.ps1 -Setup
    powershell -ExecutionPolicy Bypass -File .\Send-HomeWatchReport.ps1        # 手動で今すぐ送る
#>
[CmdletBinding()]
param(
    [switch]$Setup,
    [string]$DailyAt = '08:00',
    [string]$ConfigPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
if (-not $ConfigPath) { $ConfigPath = Join-Path $ScriptDir 'config\homewatch.config.psd1' }

Import-Module (Join-Path $ScriptDir 'modules\HomeWatch.psm1') -Force

$cfg = Import-PowerShellDataFile -Path $ConfigPath
$cfg.LogPath = [Environment]::ExpandEnvironmentVariables($cfg.LogPath)
$cfg.BaselinePath = [Environment]::ExpandEnvironmentVariables($cfg.BaselinePath)

# メール設定（config に無い場合は既定値）
$smtpServer = [string](Get-PropOr $cfg 'ReportSmtpServer' 'smtp.gmail.com')
$smtpPort   = [int](Get-PropOr $cfg 'ReportSmtpPort' 587)
$mailFrom   = [string](Get-PropOr $cfg 'ReportFrom' '')
$mailTo     = [string](Get-PropOr $cfg 'ReportTo' '')
$credPath   = [Environment]::ExpandEnvironmentVariables(
                [string](Get-PropOr $cfg 'ReportCredentialPath' '%ProgramData%\HomeWatch\report-smtp.cred'))

# ネットワーク監視ログ（リポジトリの network フォルダ）
$netLogPath = Join-Path (Split-Path -Parent $ScriptDir) 'network\homewatch-netscan.log'

function Read-RecentJsonLines {
    <# JSON Lines ログから直近 $Hours 時間のレコードを読む（壊れた行はスキップ）。 #>
    param([string]$Path, [int]$Hours = 24)
    if (-not (Test-Path $Path)) { return @() }
    $cutoff = (Get-Date).AddHours(-1 * $Hours)
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($line in (Get-Content -Path $Path -Tail 2000 -ErrorAction SilentlyContinue)) {
        try { $rec = $line | ConvertFrom-Json } catch { continue }
        $t = Get-PropOr $rec 'Time' (Get-PropOr $rec 'time' $null)
        if ($null -eq $t) { continue }
        try { if ([datetime]::Parse($t) -ge $cutoff) { $out.Add($rec) } } catch { continue }
    }
    return $out.ToArray()
}

function Build-ReportBody {
    param([object[]]$PcRecords, [object[]]$NetRecords)

    $pcAlerts   = @($PcRecords  | Where-Object { (Get-PropOr $_ 'Severity' '') -in 'warning', 'alert' })
    $pcBeats    = @($PcRecords  | Where-Object { (Get-PropOr $_ 'event' '') -eq 'scan_ok' })
    $netAlerts  = @($NetRecords | Where-Object { (Get-PropOr $_ 'severity' '') -eq 'alert' })
    $netBeats   = @($NetRecords | Where-Object { (Get-PropOr $_ 'event' '') -eq 'scan_ok' })

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("HomeWatch 日次レポート — $(Get-Date -Format 'yyyy-MM-dd HH:mm')")
    [void]$sb.AppendLine(("=" * 46))
    [void]$sb.AppendLine("")
    $status = if ($pcAlerts.Count -eq 0 -and $netAlerts.Count -eq 0) { "✅ 異常なし" } else { "⚠️ 要確認のアラートがあります" }
    [void]$sb.AppendLine("総合判定: $status")
    [void]$sb.AppendLine("")

    # 同一内容のアラートは 1 行にまとめ、回数と最終時刻を付ける（読みやすさ優先）
    [void]$sb.AppendLine("■ PC 監視（直近24時間）")
    [void]$sb.AppendLine("  アラート: $($pcAlerts.Count) 件 / スキャン実行: $($pcBeats.Count) 回")
    $pcGroups = @($pcAlerts | Group-Object { "[{0}] {1}" -f (Get-PropOr $_ 'Severity' '?'), (Get-PropOr $_ 'Message' '') } |
                  Sort-Object Count -Descending)
    foreach ($g in $pcGroups) {
        $last = ($g.Group | ForEach-Object { Get-PropOr $_ 'Time' '' } | Sort-Object | Select-Object -Last 1)
        $suffix = if ($g.Count -gt 1) { "（$($g.Count) 回 / 最終 $last）" } else { "（$last）" }
        [void]$sb.AppendLine("  - $($g.Name) $suffix")
    }
    [void]$sb.AppendLine("")

    [void]$sb.AppendLine("■ ネットワーク監視（直近24時間）")
    [void]$sb.AppendLine("  アラート: $($netAlerts.Count) 件 / スキャン実行: $($netBeats.Count) 回")
    $netGroups = @($netAlerts | Group-Object { "{0} ({1})" -f (Get-PropOr $_ 'ip' '?'), (Get-PropOr $_ 'mac' '?') } |
                   Sort-Object Count -Descending)
    foreach ($g in $netGroups) {
        $last = ($g.Group | ForEach-Object { Get-PropOr $_ 'time' '' } | Sort-Object | Select-Object -Last 1)
        [void]$sb.AppendLine("  - 未知の端末 $($g.Name) — $($g.Count) 回検出 / 最終 $last")
        [void]$sb.AppendLine("      → 自分の機器なら network\known-devices.json に登録すると止まります")
    }
    [void]$sb.AppendLine("")

    # タスクの稼働状況
    [void]$sb.AppendLine("■ 監視タスクの稼働状況")
    foreach ($name in 'HomeWatch-Scan', 'HomeWatch-NetScan') {
        try {
            $info = Get-ScheduledTaskInfo -TaskName $name -ErrorAction Stop
            [void]$sb.AppendLine("  $name : 最終実行 $($info.LastRunTime) / 結果 $($info.LastTaskResult) (0=正常)")
        } catch {
            # SYSTEM 権限で登録したタスクは、非管理者のレポート実行からは参照できないことがある。
            # 実際に動いているかはスキャン実行回数（ハートビート）で判定する。
            [void]$sb.AppendLine("  $name : タスク情報を参照できません（権限の関係。稼働はスキャン実行回数で確認）")
        }
    }
    if ($pcBeats.Count -eq 0) {
        [void]$sb.AppendLine("  ※ PC 監視のスキャン記録が24時間ありません。稼働を確認してください。")
    }
    if ($netBeats.Count -eq 0) {
        [void]$sb.AppendLine("  ※ ネットワーク監視のスキャン記録が24時間ありません。稼働を確認してください。")
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("-- HomeWatch (このメールはあなたの PC から自動送信されています)")
    return $sb.ToString()
}

function Send-Report {
    if (-not $mailFrom -or -not $mailTo) {
        Write-Error "config の ReportFrom / ReportTo が未設定です。config\homewatch.config.psd1 を編集するか、-Setup を実行してください。"
        exit 1
    }
    if (-not (Test-Path $credPath)) {
        Write-Error "送信用の資格情報がありません。先に -Setup を実行してください。"
        exit 1
    }
    $cred = Import-Clixml -Path $credPath

    $pcRecords  = Read-RecentJsonLines -Path $cfg.LogPath -Hours 24
    $netRecords = Read-RecentJsonLines -Path $netLogPath -Hours 24
    $body = Build-ReportBody -PcRecords $pcRecords -NetRecords $netRecords

    $hasAlert = $body -match '要確認'
    $subject = if ($hasAlert) { "[HomeWatch] ⚠️ 要確認 — 日次レポート $(Get-Date -Format 'MM/dd')" }
               else { "[HomeWatch] ✅ 異常なし — 日次レポート $(Get-Date -Format 'MM/dd')" }

    Send-MailMessage -SmtpServer $smtpServer -Port $smtpPort -UseSsl `
        -From $mailFrom -To $mailTo -Subject $subject -Body $body `
        -Encoding ([System.Text.Encoding]::UTF8) -Credential $cred
    Write-Output "レポートを送信しました: $mailTo ($subject)"
}

function Invoke-Setup {
    Write-Host "=== HomeWatch 日次メールレポート 初期設定 ==="
    Write-Host "送信元(From): $mailFrom / 送信先(To): $mailTo / SMTP: ${smtpServer}:${smtpPort}"
    Write-Host "（変更したい場合は config\homewatch.config.psd1 の Report* を編集して再実行）"
    Write-Host ""
    Write-Host "SMTP のユーザー名（通常は送信元メールアドレス）とパスワードを入力してください。"
    Write-Host "Gmail の場合は通常のパスワードではなく『アプリパスワード』が必要です:"
    Write-Host "  https://myaccount.google.com/apppasswords （2段階認証の有効化が前提）"
    $cred = Get-Credential -UserName $mailFrom -Message "SMTP 認証情報（Gmail はアプリパスワード）"

    $dir = Split-Path -Parent $credPath
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $cred | Export-Clixml -Path $credPath
    Write-Host "資格情報を暗号化保存しました: $credPath（このユーザーのみ復号可能）"

    # 毎日のタスク登録（ログオン中ユーザーで実行。DPAPI 復号のため同一ユーザー必須）
    $self = Join-Path $ScriptDir 'Send-HomeWatchReport.ps1'
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$self`""
    $trigger = New-ScheduledTaskTrigger -Daily -At $DailyAt
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName 'HomeWatch-DailyReport' -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Force | Out-Null
    Write-Host "タスク登録完了: 'HomeWatch-DailyReport' を毎日 $DailyAt に実行します。"

    Write-Host "テスト送信します..."
    Send-Report
    Write-Host "設定完了。届いたメールを確認してください（迷惑メールフォルダも）。"
}

if ($Setup) { Invoke-Setup } else { Send-Report }
