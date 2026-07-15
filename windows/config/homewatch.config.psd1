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
    # 「新しく現れた」待ち受けだけを検知する（インストール時の状態はベースラインとして許可される）。
    # ここに挙げたポートは常に許可する（ベースラインに無くてもアラートしない）。
    AllowedListeningPorts    = @(135, 139, 445, 5353, 5355, 137, 138, 1900)

    # エフェメラル（動的）ポート範囲は無視する。Windows の RPC が起動毎に使い回す高位ポート
    # （49664 等）で番号が毎回変わり、許可リストでは管理できないため。
    IgnoreEphemeralPorts     = $true
    EphemeralPortStart       = 49152

    # ---- 盗聴・盗撮（マイク/カメラ）----
    # 利用を許可するアプリ名（部分一致）。ここに無いアプリがマイク/カメラを使ったらアラート。
    AllowedMicCameraApps     = @('Teams', 'Zoom', 'Camera', 'Skype', 'WhatsApp', 'Discord')
    MicCameraSinceHours      = 24

    # ---- 自動起動検知の除外パターン（ワイルドカード可）----
    # Windows/正規アプリが「毎回名前(GUID/バージョン)を変えて」作り直すタスクは、ベースライン方式では
    # 恒久的に誤検知になるため、名前パターンで除外する。HomeWatch-* は常に自動除外。
    PersistenceIgnorePatterns = @(
        'SoftLanding*Task*',          # Windows のおすすめ表示(コンテンツ配信)が随時作り直すタスク
        'GoogleUpdaterTask*',         # Google 更新タスク（バージョン番号入りで毎回名前が変わる）
        'MicrosoftEdgeUpdateTask*',   # Edge 更新タスク
        'OneDrive*Update*'            # OneDrive 更新タスク
    )

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

    # 異常が無くても毎回「監視OK」トーストを出すか（既定はオフ。オンにすると15分ごとに通知が出る）
    HeartbeatToast           = $false

    # ---- 日次メールレポート（Send-HomeWatchReport.ps1）----
    # Gmail の場合: SmtpServer は smtp.gmail.com / Port 587、パスワードは「アプリパスワード」
    # （https://myaccount.google.com/apppasswords ・2段階認証が前提）。
    # パスワードは -Setup 実行時に暗号化保存され、この設定ファイルには書かない。
    ReportSmtpServer         = 'smtp.gmail.com'
    ReportSmtpPort           = 587
    ReportFrom               = 'g5kurihara@gmail.com'
    ReportTo                 = 'g5kurihara@gmail.com'
    ReportCredentialPath     = '%ProgramData%\HomeWatch\report-smtp.cred'
}
