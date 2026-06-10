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

# ---------------------------------------------------------------------------
# データ収集ヘルパー（実 Windows 環境でのみ動作。検知ロジックとは分離）
# ---------------------------------------------------------------------------
function Get-RecentLogonEvents {
    param([int]$Minutes)
    $start = (Get-Date).AddMinutes(-1 * $Minutes)
    $ids = 4624, 4625, 4720, 4728, 4732
    try {
        $raw = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $ids; StartTime = $start } -ErrorAction Stop
    } catch {
        # 該当イベント無しなどは空配列扱い
        return @()
    }
    foreach ($e in $raw) {
        $x = [xml]$e.ToXml()
        $data = @{}
        foreach ($d in $x.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
        [pscustomobject]@{
            Id             = [int]$e.Id
            TimeCreated    = $e.TimeCreated
            LogonType      = if ($data.ContainsKey('LogonType')) { [int]$data['LogonType'] } else { $null }
            TargetUserName = $data['TargetUserName']
            IpAddress      = $data['IpAddress']
        }
    }
}

function Get-CurrentListeners {
    try {
        Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
            $procName = try { (Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName } catch { '?' }
            [pscustomobject]@{ LocalPort = [int]$_.LocalPort; OwningProcessName = $procName }
        } | Sort-Object LocalPort -Unique
    } catch { @() }
}

function Get-CurrentLocalUsers {
    try { Get-LocalUser | ForEach-Object { [pscustomobject]@{ Name = $_.Name } } } catch { @() }
}

function Get-CurrentPersistence {
    $items = [System.Collections.Generic.List[object]]::new()
    # スケジュールタスク
    try {
        foreach ($t in (Get-ScheduledTask -ErrorAction Stop)) {
            $items.Add([pscustomobject]@{
                Id = "task:$($t.TaskPath)$($t.TaskName)"; Name = $t.TaskName; Type = 'ScheduledTask' })
        }
    } catch {}
    # レジストリ Run キー（HKLM/HKCU）
    $runKeys = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    )
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            $props = Get-ItemProperty -Path $key
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -like 'PS*') { continue }
                $items.Add([pscustomobject]@{
                    Id = "run:$key\$($p.Name)"; Name = "$($p.Name) = $($p.Value)"; Type = 'RunKey' })
            }
        }
    }
    # スタートアップフォルダ
    $startup = [Environment]::GetFolderPath('Startup')
    if ($startup -and (Test-Path $startup)) {
        foreach ($f in (Get-ChildItem -Path $startup -File -ErrorAction SilentlyContinue)) {
            $items.Add([pscustomobject]@{ Id = "startup:$($f.Name)"; Name = $f.Name; Type = 'StartupFolder' })
        }
    }
    return $items.ToArray()
}

function Get-MicCameraAccess {
    # ConsentStore に記録された、マイク/カメラを使ったアプリと最終使用時刻を読む。
    $stores = @{ microphone = 'microphone'; webcam = 'webcam' }
    $records = [System.Collections.Generic.List[object]]::new()
    foreach ($cap in $stores.Keys) {
        foreach ($hive in @('HKCU:', 'HKLM:')) {
            $base = "$hive\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\$cap"
            if (-not (Test-Path $base)) { continue }
            foreach ($appKey in (Get-ChildItem -Path $base -ErrorAction SilentlyContinue)) {
                # NonPackaged 配下も含めて末端キーを走査
                $leaves = @($appKey) + @(Get-ChildItem -Path $appKey.PSPath -Recurse -ErrorAction SilentlyContinue)
                foreach ($leaf in $leaves) {
                    $val = Get-ItemProperty -Path $leaf.PSPath -ErrorAction SilentlyContinue
                    if ($val -and $val.PSObject.Properties.Name -contains 'LastUsedTimeStop') {
                        $stop = [int64]$val.LastUsedTimeStop
                        if ($stop -gt 0) {
                            $records.Add([pscustomobject]@{
                                App        = ($leaf.PSChildName -replace '#', '\')
                                Capability = $cap
                                LastUsed   = [DateTime]::FromFileTime($stop)
                            })
                        }
                    }
                }
            }
        }
    }
    return $records.ToArray()
}

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

# 旧バージョンのベースライン（Listeners 無し）でも動くようにガードする
$baselineListeners = if ($baseline.PSObject.Properties.Name -contains 'Listeners') { @($baseline.Listeners) } else { @() }

Add-AlertBatch (Test-LogonEvents -Events @(Get-RecentLogonEvents -Minutes $cfg.EventLookbackMinutes) -Config $cfg)
Add-AlertBatch (Test-NetworkListeners -Listeners @(Get-CurrentListeners) -AllowedPorts $cfg.AllowedListeningPorts `
    -BaselinePorts $baselineListeners -EphemeralStart $cfg.EphemeralPortStart -IgnoreEphemeral $cfg.IgnoreEphemeralPorts)
Add-AlertBatch (Test-Persistence -Current @(Get-CurrentPersistence) -Baseline @($baseline.Persistence))
Add-AlertBatch (Test-NewLocalUsers -Current @(Get-CurrentLocalUsers) -Baseline @($baseline.LocalUsers))
Add-AlertBatch (Test-MicCameraAccess -AccessRecords @(Get-MicCameraAccess) -AllowedApps $cfg.AllowedMicCameraApps -SinceHours $cfg.MicCameraSinceHours)

$notified = 0
foreach ($a in $alerts) {
    $isNew = Write-HomeWatchLog -Alert $a -Path $cfg.LogPath -DedupeWindowMinutes $cfg.DedupeWindowMinutes
    if ($isNew) {
        Send-HomeWatchAlert -Alert $a
        $notified++
    }
}

Write-Output "HomeWatch スキャン完了: 検知 $($alerts.Count) 件 / 新規通知 $notified 件 (ログ: $($cfg.LogPath))"
