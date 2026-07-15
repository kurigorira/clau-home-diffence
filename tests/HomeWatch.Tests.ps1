<#
HomeWatch.psm1 の検知関数の Pester テスト。

Windows 専用 cmdlet は呼ばず、合成（モック）データを各 Test-* 関数に渡して判定を検証する。
そのため Windows でなくても（PowerShell Core があれば）実行できる。

実行:
    Invoke-Pester -Path .\tests\HomeWatch.Tests.ps1
#>

BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..' 'windows' 'modules' 'HomeWatch.psm1'
    Import-Module $modulePath -Force

    $script:cfg = @{
        FailedLogonThreshold     = 5
        FailedLogonWindowMinutes = 10
        NightHourStart           = 0
        NightHourEnd             = 6
        AlertOnRemoteLogon       = $true
    }
}

Describe 'Test-LogonEvents' {
    It 'ブルートフォース（短時間に失敗多発）を検知する' {
        $base = Get-Date '2026-01-01T12:00:00'
        $events = 0..5 | ForEach-Object {
            [pscustomobject]@{ Id = 4625; TimeCreated = $base.AddMinutes($_); TargetUserName = 'admin'; LogonType = 3; IpAddress = '10.0.0.9' }
        }
        $alerts = Test-LogonEvents -Events $events -Config $script:cfg
        ($alerts | Where-Object { $_.Message -like '*ブルートフォース*' }).Count | Should -BeGreaterThan 0
    }

    It '失敗が時間窓を超えて分散していればブルートフォース判定しない' {
        $base = Get-Date '2026-01-01T12:00:00'
        $events = 0..5 | ForEach-Object {
            [pscustomobject]@{ Id = 4625; TimeCreated = $base.AddMinutes($_ * 30); TargetUserName = 'admin'; LogonType = 3 }
        }
        $alerts = Test-LogonEvents -Events $events -Config $script:cfg
        ($alerts | Where-Object { $_.Message -like '*ブルートフォース*' }).Count | Should -Be 0
    }

    It 'RDP(LogonType 10) の成功ログオンを警告する' {
        $events = @([pscustomobject]@{ Id = 4624; TimeCreated = (Get-Date '2026-01-01T12:00:00'); LogonType = 10; TargetUserName = 'user'; IpAddress = '203.0.113.5' })
        $alerts = Test-LogonEvents -Events $events -Config $script:cfg
        ($alerts | Where-Object { $_.Message -like '*RDP*' }).Count | Should -Be 1
    }

    It '深夜帯の対話ログオン(LogonType 2)を警告する' {
        $events = @([pscustomobject]@{ Id = 4624; TimeCreated = (Get-Date '2026-01-01T03:00:00'); LogonType = 2; TargetUserName = 'user' })
        $alerts = Test-LogonEvents -Events $events -Config $script:cfg
        ($alerts | Where-Object { $_.Message -like '*深夜*' }).Count | Should -Be 1
    }

    It '深夜帯でもバッチ(4)/サービス(5)ログオンは警告しない（定期タスクの誤検知防止）' {
        $events = @(
            [pscustomobject]@{ Id = 4624; TimeCreated = (Get-Date '2026-01-01T03:00:00'); LogonType = 4; TargetUserName = 'user' },
            [pscustomobject]@{ Id = 4624; TimeCreated = (Get-Date '2026-01-01T03:10:00'); LogonType = 5; TargetUserName = 'SYSTEM' }
        )
        $alerts = Test-LogonEvents -Events $events -Config $script:cfg
        ($alerts | Where-Object { $_.Message -like '*深夜*' }).Count | Should -Be 0
    }

    It '新規ユーザー作成(4720)と管理者グループ追加(4732)をアラートする' {
        $events = @(
            [pscustomobject]@{ Id = 4720; TimeCreated = (Get-Date); TargetUserName = 'hacker' },
            [pscustomobject]@{ Id = 4732; TimeCreated = (Get-Date); TargetUserName = 'hacker' }
        )
        $alerts = Test-LogonEvents -Events $events -Config $script:cfg
        $alerts.Count | Should -Be 2
        ($alerts | Where-Object { $_.Severity -eq 'alert' }).Count | Should -Be 2
    }

    It 'イベントが空でもエラーにならない' {
        { Test-LogonEvents -Events @() -Config $script:cfg } | Should -Not -Throw
    }
}

Describe 'Test-NetworkListeners' {
    It '許可リストにもベースラインにも無い新規ポートを検知する' {
        $listeners = @(
            [pscustomobject]@{ LocalPort = 445; OwningProcessName = 'System' },
            [pscustomobject]@{ LocalPort = 4444; OwningProcessName = 'evil' }
        )
        $alerts = Test-NetworkListeners -Listeners $listeners -AllowedPorts @(445, 139)
        $alerts.Count | Should -Be 1
        $alerts[0].Details.port | Should -Be 4444
    }

    It '全て許可ポートなら何も返さない' {
        $listeners = @([pscustomobject]@{ LocalPort = 445 })
        (Test-NetworkListeners -Listeners $listeners -AllowedPorts @(445)).Count | Should -Be 0
    }

    It 'ベースラインに記録済みの (ポート/プロセス) は検知しない' {
        $listeners = @([pscustomobject]@{ LocalPort = 7679; OwningProcessName = 'GoogleDriveFS' })
        $baseline = @([pscustomobject]@{ port = 7679; process = 'GoogleDriveFS' })
        (Test-NetworkListeners -Listeners $listeners -AllowedPorts @() -BaselinePorts $baseline).Count | Should -Be 0
    }

    It 'エフェメラル範囲(>=49152)の待ち受けは既定で無視する' {
        $listeners = @([pscustomobject]@{ LocalPort = 49669; OwningProcessName = 'svchost' })
        (Test-NetworkListeners -Listeners $listeners -AllowedPorts @()).Count | Should -Be 0
    }

    It 'ベースラインと違うプロセスが同じポートを使い始めたら検知する' {
        $listeners = @([pscustomobject]@{ LocalPort = 7679; OwningProcessName = 'evil' })
        $baseline = @([pscustomobject]@{ port = 7679; process = 'GoogleDriveFS' })
        $alerts = Test-NetworkListeners -Listeners $listeners -AllowedPorts @() -BaselinePorts $baseline
        $alerts.Count | Should -Be 1
        $alerts[0].Details.process | Should -Be 'evil'
    }
}

Describe 'Test-Persistence / Test-NewLocalUsers' {
    It 'ベースラインに無い自動起動を検知する' {
        $baseline = @([pscustomobject]@{ Id = 'run:HKLM\A'; Name = 'A'; Type = 'RunKey' })
        $current = @(
            [pscustomobject]@{ Id = 'run:HKLM\A'; Name = 'A'; Type = 'RunKey' },
            [pscustomobject]@{ Id = 'startup:evil.exe'; Name = 'evil.exe'; Type = 'StartupFolder' }
        )
        $alerts = Test-Persistence -Current $current -Baseline $baseline
        $alerts.Count | Should -Be 1
        $alerts[0].Details.name | Should -Be 'evil.exe'
    }

    It 'HomeWatch 自身のタスク群は検知しない（自作自演の誤検知防止）' {
        $baseline = @()
        $current = @(
            [pscustomobject]@{ Id = 'task:\HomeWatch-Scan'; Name = 'HomeWatch-Scan'; Type = 'ScheduledTask' },
            [pscustomobject]@{ Id = 'task:\HomeWatch-NetScan'; Name = 'HomeWatch-NetScan'; Type = 'ScheduledTask' },
            [pscustomobject]@{ Id = 'task:\HomeWatch-DailyReport'; Name = 'HomeWatch-DailyReport'; Type = 'ScheduledTask' }
        )
        (Test-Persistence -Current $current -Baseline $baseline).Count | Should -Be 0
    }

    It 'IgnorePatterns にマッチする名前変化タスクは検知しない' {
        $baseline = @()
        $current = @(
            [pscustomobject]@{ Id = 'task:\SoftLandingDeferralTask-{guid}'; Name = 'SoftLandingDeferralTask-{guid}'; Type = 'ScheduledTask' },
            [pscustomobject]@{ Id = 'task:\GoogleUpdaterTaskSystem152.0'; Name = 'GoogleUpdaterTaskSystem152.0'; Type = 'ScheduledTask' },
            [pscustomobject]@{ Id = 'task:\evil-task'; Name = 'evil-task'; Type = 'ScheduledTask' }
        )
        $alerts = Test-Persistence -Current $current -Baseline $baseline `
            -IgnorePatterns @('SoftLanding*Task*', 'GoogleUpdaterTask*')
        $alerts.Count | Should -Be 1
        $alerts[0].Details.name | Should -Be 'evil-task'
    }

    It 'ベースラインに無いローカルユーザーを検知する' {
        $baseline = @([pscustomobject]@{ Name = 'owner' })
        $current = @([pscustomobject]@{ Name = 'owner' }, [pscustomobject]@{ Name = 'backdoor' })
        $alerts = Test-NewLocalUsers -Current $current -Baseline $baseline
        $alerts.Count | Should -Be 1
        $alerts[0].Details.user | Should -Be 'backdoor'
    }
}

Describe 'Test-MicCameraAccess' {
    It '許可リスト外のアプリによる最近のマイク使用を検知する' {
        $records = @(
            [pscustomobject]@{ App = 'Microsoft.Teams'; Capability = 'microphone'; LastUsed = (Get-Date).AddHours(-1) },
            [pscustomobject]@{ App = 'sketchy-recorder'; Capability = 'microphone'; LastUsed = (Get-Date).AddHours(-2) }
        )
        $alerts = Test-MicCameraAccess -AccessRecords $records -AllowedApps @('Teams', 'Zoom') -SinceHours 24
        $alerts.Count | Should -Be 1
        $alerts[0].Details.app | Should -Be 'sketchy-recorder'
    }

    It '時間窓より古いアクセスは無視する' {
        $records = @([pscustomobject]@{ App = 'sketchy'; Capability = 'webcam'; LastUsed = (Get-Date).AddHours(-48) })
        (Test-MicCameraAccess -AccessRecords $records -AllowedApps @('Teams') -SinceHours 24).Count | Should -Be 0
    }
}

Describe 'Write-HomeWatchLog（重複抑制）' {
    It '同一アラートの連続記録は抑制する' {
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("hw-" + [guid]::NewGuid() + ".log")
        try {
            $alert = New-HomeWatchAlert -Category 'network' -Severity 'warning' -Message 'dup test'
            (Write-HomeWatchLog -Alert $alert -Path $tmp -DedupeWindowMinutes 60) | Should -BeTrue
            $alert2 = New-HomeWatchAlert -Category 'network' -Severity 'warning' -Message 'dup test'
            (Write-HomeWatchLog -Alert $alert2 -Path $tmp -DedupeWindowMinutes 60) | Should -BeFalse
            (Get-Content $tmp).Count | Should -Be 1
        } finally {
            if (Test-Path $tmp) { Remove-Item $tmp -Force }
        }
    }
}
