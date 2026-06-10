<#
.SYNOPSIS
    ベースラインを現在の状態で更新する。意図して新しいアプリ/自動起動/ユーザーを追加した後に実行する。

.DESCRIPTION
    新しい自動起動エントリやローカルユーザーが「正常な変更」だと確認できたら、これを実行して
    ベースラインに取り込むことで、以後その項目はアラートされなくなる。
    管理者として実行すること。実行前に、増えた項目に心当たりがあるか必ず確認すること。
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
# 収集関数（Get-Current* 等）はモジュールから提供される。スキャン本体は実行しない。

$cfg = Import-PowerShellDataFile -Path $ConfigPath
# %ProgramData% などの環境変数を実際のパスに展開する
$cfg.LogPath = [Environment]::ExpandEnvironmentVariables($cfg.LogPath)
$cfg.BaselinePath = [Environment]::ExpandEnvironmentVariables($cfg.BaselinePath)
$old = Get-Baseline -Path $cfg.BaselinePath

$current = @{
    Persistence = @(Get-CurrentPersistence)
    LocalUsers  = @(Get-CurrentLocalUsers)
    Listeners   = @(Get-CurrentListeners | ForEach-Object {
        [pscustomobject]@{ port = [int]$_.LocalPort; process = $_.OwningProcessName }
    })
}

if ($old) {
    # @() で配列に固定（0/1件でも .Count が使えるように）。$old のフィールドは安全に取り出す。
    $newPersist = @(Get-NewItems -Current $current.Persistence -Baseline @(Get-PropOr $old 'Persistence' @()) -KeyProperty 'Id')
    $newUsers   = @(Get-NewItems -Current $current.LocalUsers  -Baseline @(Get-PropOr $old 'LocalUsers' @())  -KeyProperty 'Name')
    Write-Host "ベースラインに新たに取り込まれる項目:"
    Write-Host ("  自動起動 {0} 件 / ユーザー {1} 件" -f $newPersist.Count, $newUsers.Count)
    $newPersist | ForEach-Object { Write-Host "   + [$($_.Type)] $($_.Name)" }
    $newUsers   | ForEach-Object { Write-Host "   + [User] $($_.Name)" }
    Write-Warning "上記に心当たりが無い項目がある場合は中断（Ctrl+C）して調査してください。"
}

Save-Baseline -Baseline $current -Path $cfg.BaselinePath
Write-Host "ベースラインを更新しました: $($cfg.BaselinePath)"
