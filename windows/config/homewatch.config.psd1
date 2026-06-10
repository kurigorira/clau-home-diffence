@{
    # ---- ログオン検知 ----
    # この時間（分）以内にログオン失敗がこの回数以上 → ブルートフォースとしてアラート
    FailedLogonThreshold     = 5
    FailedLogonWindowMinutes = 10

    # 深夜帯の定義（24時間制）。NightHourStart 以降〜NightHourEnd 未満を深夜とみなす。
    # 例: 0時〜6時を深夜にしたい場合は Start=0, End=6。23時〜5時のように日付をまたぐ指定も可。
    NightHourStart           = 0
    NightHourEnd             = 6

    # ネットワーク/RDP ログオン成功（LogonType 3/10）でアラートを出すか
    AlertOnRemoteLogon       = $true

    # ---- ネットワーク待ち受けポート ----
    # 待ち受けを許可するポート。ここに無いポートが Listen していたらアラート。
    # 既定はよくある安全な範囲のみ。自宅環境に合わせて調整する。
    AllowedListeningPorts    = @(135, 139, 445, 5353, 5355, 137, 138, 1900)

    # ---- 盗聴・盗撮（マイク/カメラ）----
    # 利用を許可するアプリ名（部分一致）。ここに無いアプリがマイク/カメラを使ったらアラート。
    AllowedMicCameraApps     = @('Teams', 'Zoom', 'Camera', 'Skype', 'WhatsApp', 'Discord')
    MicCameraSinceHours      = 24

    # ---- 検知対象イベントの取得範囲 ----
    # 直近この分数のセキュリティイベントを走査（タスクの実行間隔より少し長めに）
    EventLookbackMinutes     = 20

    # ---- 出力先 ----
    # Import-PowerShellDataFile は変数展開（$env:...）を許可しないため、%ProgramData% 形式で記述する。
    # スクリプト側で実際のパスに展開する。
    LogPath                  = '%ProgramData%\HomeWatch\homewatch-alerts.log'
    BaselinePath             = '%ProgramData%\HomeWatch\baseline.json'

    # 同一内容のアラートをこの分数は再通知しない（通知疲れ防止）
    DedupeWindowMinutes      = 60
}
