# ネットワーク侵入検知スキャナの設定（常時稼働機器向け）

`homewatch-netscan.py` を Raspberry Pi などの常時稼働機器で定期実行し、自宅 Wi-Fi に
**見覚えのない端末**がつながったら通知できるようにします。Python3 標準ライブラリのみで動き、
追加パッケージは不要です。

> **Windows 11 で動かす場合は、下の「Windows で動かす」セクションを参照してください。**
> 以下の「前提〜5」は主に Linux / Raspberry Pi 向けの説明です（Windows でも考え方は同じです）。

## 前提
- Python 3.8 以上。
- ARP テーブルや ping を使うため、**`sudo`（root）での実行**を推奨（特に `arp-scan` 利用時）。
- 任意：`arp-scan` を入れると検出が確実になります（`sudo apt install arp-scan`）。
  無くても `ip neigh` / `arp -a` ＋ ping スイープにフォールバックします。
- 任意：デスクトップ環境があれば `notify-send`（`libnotify-bin`）でポップアップ通知。

## 1. 初回：既知端末リストを作る
**自分の家の端末だけが Wi-Fi につながっている状態**で実行してください。

```bash
cd network
sudo python3 homewatch-netscan.py --cidr 192.168.1.0/24 init
```
- いま在線している端末を `known-devices.json` に登録します（`--cidr` は自宅のサブネットに合わせて変更）。
- 生成された `known-devices.json` を開き、各 MAC に分かりやすい名前を付けておくと、後で見やすくなります。
  （ひな形は `known-devices.example.json`。）

## 2. スキャン（手動確認）
```bash
sudo python3 homewatch-netscan.py --cidr 192.168.1.0/24 scan
```
- 既知リストに無い端末がいると **アラート** を表示・記録し、終了コード 2 を返します。
- 結果は `homewatch-netscan.log`（1行1件の JSON）にも残ります。

## 3. 定期実行にする
### 方法A: cron（手軽）
`sudo crontab -e` に追記（5分ごと）：
```cron
*/5 * * * * /usr/bin/python3 /home/pi/clau-home-diffence/network/homewatch-netscan.py --cidr 192.168.1.0/24 scan >> /var/log/homewatch-netscan.cron.log 2>&1
```

### 方法B: systemd timer（推奨・管理しやすい）
`/etc/systemd/system/homewatch-netscan.service`:
```ini
[Unit]
Description=HomeWatch network scan

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /home/pi/clau-home-diffence/network/homewatch-netscan.py --cidr 192.168.1.0/24 scan
```
`/etc/systemd/system/homewatch-netscan.timer`:
```ini
[Unit]
Description=Run HomeWatch network scan every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
```
有効化：
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now homewatch-netscan.timer
sudo systemctl list-timers | grep homewatch   # 動作確認
journalctl -u homewatch-netscan.service -f     # ログ確認
```

## 4. 新しい端末が増えたとき（誤検知の解消）
- 自分/家族の端末なら、`known-devices.json` の `devices` に `"aa:bb:cc:dd:ee:ff": "○○のスマホ"` の形で追記。
- まとめて取り込むなら、その端末を接続した状態で再度 `init` を実行（既存の名前は保持されます）。
- スマホの **ランダムMAC（プライベートアドレス）** 機能で MAC が変わる場合は、その端末の Wi-Fi 設定で固定にするか、
  新しい MAC を都度登録してください。

## 5. 通知の確認
- デスクトップ環境＋`notify-send` があればポップアップ。
- ヘッドレス（画面なし）の Pi では、ログ（`homewatch-netscan.log` / journalctl）で確認するか、
  別途メール/チャット通知に転送する仕組みを足すこともできます（ログはローカル保存が既定です）。

---

# Windows で動かす（Windows 11 端末を監視機にする）

常時起動している Windows PC があれば、それ自体を自宅ネットワークの見張り役にできます。
Windows では検知時に **トースト通知** が出ます（ログオン中のユーザーに表示）。
ARP の読み取りに管理者権限は不要です。

## W-1. Python を入れる
1. https://www.python.org/downloads/windows/ から Python 3 をインストール
   （インストーラの「**Add python.exe to PATH**」に必ずチェック）。Microsoft Store 版でも可。
2. 確認（PowerShell で）：
   ```powershell
   python --version
   ```

## W-2. 自宅のサブネット（--cidr）を調べる
PowerShell で：
```powershell
ipconfig
```
「IPv4 アドレス」（例 `192.168.1.23`）と「サブネット マスク」（例 `255.255.255.0`）を見ます。
マスクが `255.255.255.0` なら、CIDR は **アドレスの先頭3つ + `.0/24`**。
上の例なら `192.168.1.0/24` です（多くの家庭はこの形）。

## W-3. 初回：既知端末リストを作る
**自分の家の端末だけ**が Wi-Fi につながっている状態で、`network` フォルダに移動して：
```powershell
cd C:\Users\user\clau-home-diffence\network
python homewatch-netscan.py --cidr 192.168.1.0/24 init
```
生成された `known-devices.json` を開き、各 MAC に分かりやすい名前を付けておくと後で見やすくなります。

## W-4. スキャン（手動確認）
```powershell
python homewatch-netscan.py --cidr 192.168.1.0/24 scan
```
見覚えのない端末がいると **トースト通知** が出て、`homewatch-netscan.log` に記録されます。

## W-5. 定期実行（タスクスケジューラに登録）
**通知を出したいので、SYSTEM ではなく「ログオン中の自分のユーザー」で実行**します。
管理者 PowerShell で以下を実行（パスと CIDR は自分の環境に合わせて変更）：

```powershell
$py     = (Get-Command python).Source
$script = "C:\Users\user\clau-home-diffence\network\homewatch-netscan.py"
$cidr   = "192.168.1.0/24"

$action  = New-ScheduledTaskAction -Execute $py -Argument "`"$script`" --cidr $cidr scan"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
             -RepetitionInterval (New-TimeSpan -Minutes 5)
# 現在ログオン中のユーザーとして、対話セッションで実行（トースト通知のため）
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive
$settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName 'HomeWatch-NetScan' -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force
```
- 5分ごとにスキャンし、未知の端末が出たら通知＋ログ。
- 確認: `Get-ScheduledTask -TaskName HomeWatch-NetScan`、手動実行: `Start-ScheduledTask -TaskName HomeWatch-NetScan`。
- 解除: `Unregister-ScheduledTask -TaskName HomeWatch-NetScan -Confirm:$false`。
- **毎回「監視OK」トーストを出したい場合**は、`scan` の後ろに `--notify-ok` を足す
  （`-Argument "... scan --notify-ok"`）。※5分ごとに通知が出るので、間隔を15〜30分に延ばすのがおすすめ。

## W-6. 新しい端末が増えたとき（誤検知の解消）
- 自分/家族の端末なら、`known-devices.json` の `devices` に `"aa:bb:cc:dd:ee:ff": "○○のスマホ"` を追記。
- まとめて取り込むなら、その端末を接続した状態で再度 `... init` を実行（既存の名前は保持）。
- スマホの **プライベートアドレス（ランダムMAC）** で MAC が変わる場合は、その端末の Wi-Fi 設定で
  固定にするか、出た MAC を登録してください（このツールはマルチキャスト/ブロードキャストは自動で除外します）。
