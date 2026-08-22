# 今すぐやるチェックリスト（優先度順）

効果が大きく、手間が小さいものから並べています。上から順にチェックを付けていってください。
詳しい手順は各リンク先（同じ `docs/` 内）にあります。

## ⭐ 最優先（30分でできて効果大）
- [ ] **全アカウントで2段階認証を有効化**（Google / Apple / Microsoft / SNS / 銀行）→ `account-security.md`
- [ ] **新規サインイン通知をON**（知らない端末からのログインをメール/通知で即検知）→ `account-security.md`
- [ ] **Wi-Fi ルーターの管理画面パスワードを初期値から変更**、**ファームウェア更新** → `router-iot-hardening.md`
- [ ] **PC・スマホ・ルーターの自動更新をON** → `windows-hardening.md` / `smartphone-hardening.md`
- [ ] **スマホとPCに強固な画面ロック**（PIN/パスワード＋生体認証）→ 各ガイド
- [ ] **使い回しパスワードをやめる**。まず重要アカウントだけでも固有のパスワードに → `account-security.md`

## 🔒 守りを固める（その日のうちに）
- [ ] Windows: 標準ユーザーで日常利用＋UAC有効、Defender とファイアウォール稼働確認 → `windows-hardening.md`
- [ ] Windows: BitLocker でディスク暗号化 → `windows-hardening.md`
- [ ] ルーター: WPA3（無ければWPA2-AES）、WPS無効、リモート管理無効、ゲストSSIDでIoT分離 → `router-iot-hardening.md`
- [ ] スマホ: 紛失追跡（iPhoneを探す/デバイスを探す）をON → `smartphone-hardening.md`
- [ ] スマホ: アプリ権限の棚卸し（マイク/カメラ/位置情報/連絡先）→ `smartphone-hardening.md`
- [ ] 各アカウントの「連携している外部アプリ（OAuth）」を点検し、不要なものを解除 → `account-security.md`

## 🛰 すぐ気づける状態にする（検知の仕込み）
- [ ] 自宅ネットワークの侵入検知スキャナを常時稼働機器に設定 → `../network/deploy.md`
- [ ] Windows PC に HomeWatch 監視ツールを導入 → `windows-hardening.md` / `how-it-works.md`
- [ ] 重要パスワードの漏洩チェック（`python3 tools/check-pwned-password.py`）→ `account-security.md`

## 🕵 盗聴・スパイウェアが心配なとき
- [ ] **iPhone: 専用の点検ガイドを上から実施** → `iphone-spyware-check.md`（構成プロファイル/MDM・セーフティチェック・App プライバシーレポート 他）
- [ ] iPhone: App プライバシーレポートでマイク/カメラ利用を確認、不明な構成プロファイルを点検 → `smartphone-hardening.md`
- [ ] Android: プライバシーダッシュボード、デバイス管理アプリ／ユーザー補助の不審な許可を点検 → `smartphone-hardening.md`
- [ ] Windows: 許可外アプリのマイク/カメラ使用を HomeWatch が監視（`Test-MicCameraAccess`）→ `how-it-works.md`

## 👨‍👩‍👧 家族のために（合意の上で）
- [ ] 家族それぞれが上記の「最優先」を自分の端末で実施
- [ ] 未成年の子は公式ペアレンタルコントロール（ファミリー共有/ファミリーリンク）を保護者として設定 → `smartphone-hardening.md`
