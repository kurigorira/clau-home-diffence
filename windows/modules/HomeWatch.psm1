<#
.SYNOPSIS
    HomeWatch — Windows PC の不正侵入・乗っ取り・盗聴の兆候を検知するロジック群。

.DESCRIPTION
    検知関数（Test-*）は Windows 専用 cmdlet を直接呼ばず、データを「引数」として受け取る
    純粋関数として実装してある。これにより Pester でモックデータを渡して検証できる。
    実際のデータ収集（Get-WinEvent 等）は Invoke-HomeWatchScan.ps1 側が行い、結果をここへ渡す。

    すべてのアラートは New-HomeWatchAlert が作る共通フォーマットのオブジェクトで返す。
    検知データはローカルにのみ保存し、外部へ送信しない。
#>

Set-StrictMode -Version Latest

# 重大度の語彙
$script:Severities = @('info', 'warning', 'alert')

function New-HomeWatchAlert {
    <# アラートを共通フォーマットで生成する。 #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][ValidateSet('info', 'warning', 'alert')][string]$Severity,
        [Parameter(Mandatory)][string]$Message,
        [hashtable]$Details = @{}
    )
    [pscustomobject]@{
        Time     = (Get-Date).ToString('o')
        Category = $Category
        Severity = $Severity
        Message  = $Message
        Details  = $Details
    }
}

function Test-LogonEvents {
    <#
    .SYNOPSIS
        ログオン関連のセキュリティイベントから不審な兆候を検知する。
    .PARAMETER Events
        以下のプロパティを持つオブジェクト配列:
          Id (int)            … 4624 成功 / 4625 失敗 / 4720 ユーザー作成 / 4728,4732 管理者グループ追加
          TimeCreated (datetime)
          LogonType (int)     … 3=ネットワーク, 10=RDP（任意）
          TargetUserName (string)（任意）
          IpAddress (string)（任意）
    .PARAMETER Config
        FailedLogonThreshold / FailedLogonWindowMinutes / NightHourStart / NightHourEnd /
        AlertOnRemoteLogon を含むハッシュテーブル。
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Events,
        [Parameter(Mandatory)][hashtable]$Config
    )

    $alerts = [System.Collections.Generic.List[object]]::new()

    # --- ブルートフォース: 一定時間内の 4625（ログオン失敗）多発 ---
    $failed = @($Events | Where-Object { $_.Id -eq 4625 })
    if ($failed.Count -ge $Config.FailedLogonThreshold) {
        $windowMin = [double]$Config.FailedLogonWindowMinutes
        $times = @($failed | ForEach-Object { [datetime]$_.TimeCreated } | Sort-Object)
        $span = ($times[-1] - $times[0]).TotalMinutes
        if ($span -le $windowMin) {
            $accounts = @($failed | ForEach-Object { $_.TargetUserName } |
                          Where-Object { $_ } | Select-Object -Unique) -join ', '
            $alerts.Add((New-HomeWatchAlert -Category 'logon' -Severity 'alert' `
                -Message "短時間にログオン失敗が $($failed.Count) 回（ブルートフォースの疑い）" `
                -Details @{ count = $failed.Count; windowMinutes = [math]::Round($span, 1); accounts = $accounts }))
        }
    }

    # --- リモート/RDP ログオン成功（LogonType 3 または 10）---
    if ($Config.AlertOnRemoteLogon) {
        foreach ($e in @($Events | Where-Object { $_.Id -eq 4624 })) {
            $lt = if ($e.PSObject.Properties.Name -contains 'LogonType') { $e.LogonType } else { $null }
            if ($lt -in 3, 10) {
                $kind = if ($lt -eq 10) { 'RDP(リモートデスクトップ)' } else { 'ネットワーク' }
                $alerts.Add((New-HomeWatchAlert -Category 'logon' -Severity 'warning' `
                    -Message "$kind ログオン成功（心当たりが無ければ要確認）" `
                    -Details @{ logonType = $lt; user = $e.TargetUserName; ip = $e.IpAddress }))
            }
        }
    }

    # --- 深夜帯のログオン成功 ---
    $nightStart = [int]$Config.NightHourStart
    $nightEnd = [int]$Config.NightHourEnd
    foreach ($e in @($Events | Where-Object { $_.Id -eq 4624 })) {
        $hour = ([datetime]$e.TimeCreated).Hour
        $isNight = if ($nightStart -le $nightEnd) {
            ($hour -ge $nightStart -and $hour -lt $nightEnd)
        } else {
            ($hour -ge $nightStart -or $hour -lt $nightEnd)  # 例: 23時〜5時 のように日付をまたぐ場合
        }
        if ($isNight) {
            $alerts.Add((New-HomeWatchAlert -Category 'logon' -Severity 'warning' `
                -Message "深夜帯（$hour 時）のログオン成功" `
                -Details @{ hour = $hour; user = $e.TargetUserName }))
        }
    }

    # --- 新規ローカルユーザー作成 / 管理者グループへの追加 ---
    foreach ($e in @($Events | Where-Object { $_.Id -eq 4720 })) {
        $alerts.Add((New-HomeWatchAlert -Category 'account' -Severity 'alert' `
            -Message "新しいユーザーアカウントが作成されました" `
            -Details @{ user = $e.TargetUserName }))
    }
    foreach ($e in @($Events | Where-Object { $_.Id -in 4728, 4732 })) {
        $alerts.Add((New-HomeWatchAlert -Category 'account' -Severity 'alert' `
            -Message "ユーザーが特権グループ（管理者等）に追加されました" `
            -Details @{ user = $e.TargetUserName }))
    }

    return $alerts.ToArray()
}

function Test-NetworkListeners {
    <#
    .SYNOPSIS
        待ち受け（Listen）中のポートのうち、許可リストに無いものを検知する。
    .PARAMETER Listeners
        LocalPort (int) と OwningProcessName (string, 任意) を持つオブジェクト配列。
    .PARAMETER AllowedPorts
        許可する待ち受けポート番号の配列。
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Listeners,
        [Parameter(Mandatory)][AllowEmptyCollection()][int[]]$AllowedPorts
    )
    $alerts = [System.Collections.Generic.List[object]]::new()
    foreach ($l in $Listeners) {
        if ($AllowedPorts -notcontains [int]$l.LocalPort) {
            $proc = if ($l.PSObject.Properties.Name -contains 'OwningProcessName') { $l.OwningProcessName } else { '?' }
            $alerts.Add((New-HomeWatchAlert -Category 'network' -Severity 'warning' `
                -Message "許可リストに無いポートが待ち受け中: $($l.LocalPort)" `
                -Details @{ port = [int]$l.LocalPort; process = $proc }))
        }
    }
    return $alerts.ToArray()
}

function Get-NewItems {
    <# Current から Baseline に無い項目（KeyProperty で比較）を返す共通ヘルパー。 #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Current,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Baseline,
        [Parameter(Mandatory)][string]$KeyProperty
    )
    $baselineKeys = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@($Baseline | ForEach-Object { [string]$_.$KeyProperty })
    )
    @($Current | Where-Object { -not $baselineKeys.Contains([string]$_.$KeyProperty) })
}

function Test-Persistence {
    <#
    .SYNOPSIS
        自動起動エントリ（スケジュールタスク・Run キー・スタートアップ）の新規追加を検知する。
        マルウェアの常駐（永続化）の典型的なサイン。
    .PARAMETER Current / .PARAMETER Baseline
        Id (一意キー: 種別+名前+対象) と Name, Type を持つオブジェクト配列。
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Current,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Baseline
    )
    $alerts = [System.Collections.Generic.List[object]]::new()
    foreach ($item in (Get-NewItems -Current $Current -Baseline $Baseline -KeyProperty 'Id')) {
        $type = if ($item.PSObject.Properties.Name -contains 'Type') { $item.Type } else { 'autostart' }
        $alerts.Add((New-HomeWatchAlert -Category 'persistence' -Severity 'alert' `
            -Message "新しい自動起動エントリを検出（$type）: $($item.Name)" `
            -Details @{ id = $item.Id; name = $item.Name; type = $type }))
    }
    return $alerts.ToArray()
}

function Test-NewLocalUsers {
    <# ベースラインに無いローカルユーザーを検知する。 #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Current,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Baseline
    )
    $alerts = [System.Collections.Generic.List[object]]::new()
    foreach ($u in (Get-NewItems -Current $Current -Baseline $Baseline -KeyProperty 'Name')) {
        $alerts.Add((New-HomeWatchAlert -Category 'account' -Severity 'alert' `
            -Message "ベースラインに無いローカルユーザー: $($u.Name)" `
            -Details @{ user = $u.Name }))
    }
    return $alerts.ToArray()
}

function Test-MicCameraAccess {
    <#
    .SYNOPSIS
        盗聴・盗撮対策。最近マイク/カメラにアクセスしたアプリのうち、許可リスト外のものを検知する。
    .PARAMETER AccessRecords
        App (string), Capability ('microphone' | 'webcam'), LastUsed (datetime) を持つ配列。
        レジストリ ...CapabilityAccessManager\ConsentStore\{microphone,webcam} 由来を想定。
    .PARAMETER AllowedApps
        利用を許可するアプリ名（部分一致）の配列。
    .PARAMETER SinceHours
        直近何時間以内のアクセスを対象とするか（既定 24）。
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$AccessRecords,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$AllowedApps,
        [int]$SinceHours = 24
    )
    $alerts = [System.Collections.Generic.List[object]]::new()
    $cutoff = (Get-Date).AddHours(-1 * $SinceHours)
    foreach ($r in $AccessRecords) {
        if ([datetime]$r.LastUsed -lt $cutoff) { continue }
        $allowed = $false
        foreach ($a in $AllowedApps) {
            if ($a -and $r.App -like "*$a*") { $allowed = $true; break }
        }
        if (-not $allowed) {
            $cap = if ($r.Capability -eq 'webcam') { 'カメラ' } else { 'マイク' }
            $alerts.Add((New-HomeWatchAlert -Category 'eavesdropping' -Severity 'alert' `
                -Message "許可リスト外のアプリが$cap を使用しました: $($r.App)" `
                -Details @{ app = $r.App; capability = $r.Capability; lastUsed = ([datetime]$r.LastUsed).ToString('o') }))
        }
    }
    return $alerts.ToArray()
}

function Write-HomeWatchLog {
    <# アラートを JSON Lines でローカルログに追記する（重複は直近ログとの照合で抑制）。 #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Alert,
        [Parameter(Mandatory)][string]$Path,
        [int]$DedupeWindowMinutes = 60
    )
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    if (Test-Path $Path) {
        $cutoff = (Get-Date).AddMinutes(-1 * $DedupeWindowMinutes)
        $recent = Get-Content -Path $Path -Tail 200 -ErrorAction SilentlyContinue
        foreach ($line in $recent) {
            try { $prev = $line | ConvertFrom-Json } catch { continue }
            if ($prev.Category -eq $Alert.Category -and $prev.Message -eq $Alert.Message `
                -and ([datetime]$prev.Time) -ge $cutoff) {
                return $false  # 直近に同一アラートあり → 抑制
            }
        }
    }
    ($Alert | ConvertTo-Json -Compress -Depth 6) | Add-Content -Path $Path -Encoding UTF8
    return $true
}

function Send-HomeWatchAlert {
    <# Windows トースト通知を出す。失敗時はイベントログ/標準出力にフォールバック。 #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Alert
    )
    $title = "HomeWatch: $($Alert.Category) [$($Alert.Severity)]"
    $body = $Alert.Message
    try {
        [void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
        $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent(
            [Windows.UI.Notifications.ToastTemplateType]::ToastText02)
        $texts = $template.GetElementsByTagName('text')
        $texts.Item(0).AppendChild($template.CreateTextNode($title)) | Out-Null
        $texts.Item(1).AppendChild($template.CreateTextNode($body)) | Out-Null
        $toast = [Windows.UI.Notifications.ToastNotification]::new($template)
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('HomeWatch').Show($toast)
    } catch {
        # フォールバック1: アプリケーションイベントログ
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists('HomeWatch')) {
                New-EventLog -LogName Application -Source 'HomeWatch' -ErrorAction Stop
            }
            Write-EventLog -LogName Application -Source 'HomeWatch' -EntryType Warning `
                -EventId 1 -Message "$title`n$body"
        } catch {
            # フォールバック2: 標準出力
            Write-Output "[$title] $body"
        }
    }
}

function Save-Baseline {
    <# ベースライン（許可状態のスナップショット）を JSON で保存する。 #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Baseline,
        [Parameter(Mandatory)][string]$Path
    )
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $Baseline['_updatedAt'] = (Get-Date).ToString('o')
    $Baseline | ConvertTo-Json -Depth 8 | Set-Content -Path $Path -Encoding UTF8
}

function Get-Baseline {
    <# 保存済みベースラインを読み込む。無ければ $null。 #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    return Get-Content -Path $Path -Raw | ConvertFrom-Json
}

Export-ModuleMember -Function `
    New-HomeWatchAlert, Test-LogonEvents, Test-NetworkListeners, Get-NewItems, `
    Test-Persistence, Test-NewLocalUsers, Test-MicCameraAccess, `
    Write-HomeWatchLog, Send-HomeWatchAlert, Save-Baseline, Get-Baseline
