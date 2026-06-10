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
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config\homewatch.config.psd1')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'modules\HomeWatch.psm1') -Force
$scanScript = Join-Path $PSScriptRoot 'Invoke-HomeWatchScan.ps1'
. $scanScript -ConfigPath $ConfigPath -ErrorAction SilentlyContinue 2>$null  # 収集関数の読み込み

$cfg = Import-PowerShellDataFile -Path $ConfigPath
$old = Get-Baseline -Path $cfg.BaselinePath

$current = @{
    Persistence = @(Get-CurrentPersistence)
    LocalUsers  = @(Get-CurrentLocalUsers)
}

if ($old) {
    $newPersist = Get-NewItems -Current $current.Persistence -Baseline @($old.Persistence) -KeyProperty 'Id'
    $newUsers   = Get-NewItems -Current $current.LocalUsers  -Baseline @($old.LocalUsers)  -KeyProperty 'Name'
    Write-Host "ベースラインに新たに取り込まれる項目:"
    Write-Host ("  自動起動 {0} 件 / ユーザー {1} 件" -f $newPersist.Count, $newUsers.Count)
    $newPersist | ForEach-Object { Write-Host "   + [$($_.Type)] $($_.Name)" }
    $newUsers   | ForEach-Object { Write-Host "   + [User] $($_.Name)" }
    Write-Warning "上記に心当たりが無い項目がある場合は中断（Ctrl+C）して調査してください。"
}

Save-Baseline -Baseline $current -Path $cfg.BaselinePath
Write-Host "ベースラインを更新しました: $($cfg.BaselinePath)"
