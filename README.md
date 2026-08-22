# HomeWatch — 自宅デバイス防御 & 不正検知キット

自宅の **Windows PC・スマホ（Android/iOS）・家族の端末・自宅ネットワーク** を、不正侵入・乗っ取り・盗聴から
守り、異常があれば **すぐ気づける** ようにするための、ガイドと軽量ツールのセットです。

- **守りを固める** … OS・ルーター・アカウントの設定見直し手順とチェックリスト（`docs/`）
- **異常に気づく** … Windows PC の常駐監視ツールと、自宅ネットワークの侵入検知スキャナ（`windows/`, `network/`）
- 検知時は **画面通知＋ローカルのログ** で知らせます。**収集データは外部に送信しません。**

## 大事な前提（安全・プライバシー）
- このキットは **自分と家族（全員が承知の上）の自宅デバイス・ネットワークを守る防御目的** のものです。
- **本人に無断で家族をのぞき見る監視（ストーカーウェア的な使い方）はできませんし、想定もしていません。**
  未成年の子の保護は、Apple「ファミリー共有/スクリーンタイム」・Google「ファミリーリンク」など
  **公式のペアレンタルコントロール**（本人にも分かる透明な仕組み）を使います → `docs/smartphone-hardening.md`。
- 収集する情報（ログオン履歴・在線端末の MAC など）は **手元のローカルにのみ保存** します。
  パスワード漏洩チェックも、パスワードそのものは送らない **k-匿名方式** を使います。

## 5分で始める
1. まず **`docs/quick-checklist.md`** の「今すぐやる」項目を上から実施（効果が大きい順）。
2. 自宅ネットワークの侵入検知を常時稼働機器（Raspberry Pi 等）で動かす → **`network/deploy.md`**。
3. Windows PC に監視ツールを入れる（管理者 PowerShell）：
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\windows\Install-HomeWatch.ps1
   ```
4. アカウントの乗っ取り対策（2段階認証・サインイン通知）→ **`docs/account-security.md`**。

## 中身の地図
| 場所 | 内容 |
| --- | --- |
| `Run-HomeWatch.bat` | **ダブルクリックで一括実行**（PCスキャン＋ネットスキャン＋最新アラート表示） |
| `docs/quick-checklist.md` | 全領域横断の優先チェックリスト |
| `docs/windows-hardening.md` | Windows PC の守りを固める手順 |
| `docs/smartphone-hardening.md` | Android/iOS 防御＋盗聴/スパイウェア点検＋公式ペアレンタルコントロール |
| `docs/iphone-spyware-check.md` | iPhone 盗聴・スパイウェア点検（画面操作レベルの手順） |
| `docs/router-iot-hardening.md` | Wi-Fi ルーター・IoT 機器（カメラ等）の防御 |
| `docs/account-security.md` | アカウント乗っ取り検知（2段階認証・サインイン通知・漏洩チェック） |
| `docs/how-it-works.md` | 各ツールが何を見るか・アラートの読み方・誤検知時の対処 |
| `windows/` | Windows PC 用 監視ツール（PowerShell・追加ソフト不要） |
| `windows/Send-HomeWatchReport.ps1` | **日次メールレポート**（直近24hの監視結果を毎朝メール。`-Setup` で初期設定） |
| `network/` | 自宅 LAN 侵入検知スキャナ（Python3・依存最小） |
| `tools/check-pwned-password.py` | 漏洩パスワード確認（HIBP k-匿名） |
| `tests/` | 検知ロジックの自動テスト（pytest / Pester） |

## 仕組みのあらまし
- **Windows 監視**（`windows/`）: 「正常な状態」をベースラインに記録し、タスクスケジューラで15分ごとに
  スキャン。ログオン失敗の多発（ブルートフォース）、不審なリモート/RDPログオン、新規ユーザー作成、
  未知の待ち受けポート、新しい自動起動（マルウェア常駐サイン）、許可外アプリのマイク/カメラ使用（盗聴）を検知。
- **ネットワーク監視**（`network/`）: 自宅 Wi-Fi の在線端末を既知リストと突き合わせ、**見覚えのない端末**が
  つながったらアラート＝侵入者・タダ乗りの発見。

詳しい検知内容・アラートの読み方・誤検知時の対処は `docs/how-it-works.md` を参照してください。

## テスト
```bash
python3 -m pytest tests/            # ネットスキャナ／漏洩チェックのロジック検証（要 pytest）
# PowerShell 側（Windows / PowerShell Core + Pester v5）
pwsh -c "Invoke-Pester -Path ./tests/HomeWatch.Tests.ps1"
```
