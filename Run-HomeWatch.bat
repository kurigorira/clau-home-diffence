@echo off
chcp 65001 >nul
setlocal

rem ============================================================
rem  HomeWatch 一括実行 — ダブルクリックで以下を順に実行します
rem    1) Windows PC スキャン（要管理者 → 自動で昇格）
rem    2) 自宅ネットワーク侵入スキャン
rem    3) 最近のアラートを表示
rem  ※ 定期実行はタスクスケジューラ登録済み。これは「今すぐ確認」用。
rem ============================================================

rem ---- 設定（自宅のサブネットに合わせて変更） ----
set "CIDR=192.168.3.0/24"

set "ROOT=%~dp0"

rem ---- 管理者権限が無ければ昇格して再実行 ----
net session >nul 2>&1
if errorlevel 1 (
    echo 管理者権限が必要なため、確認ダイアログから昇格して再実行します...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo ============================================
echo  HomeWatch 一括スキャン
echo ============================================

echo.
echo [1/3] Windows PC スキャン...
powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%windows\Invoke-HomeWatchScan.ps1"

echo.
echo [2/3] 自宅ネットワーク スキャン (%CIDR%)...
where python >nul 2>&1
if errorlevel 1 (
    echo   python が見つからないため、ネットワークスキャンをスキップしました。
) else (
    python "%ROOT%network\homewatch-netscan.py" --cidr %CIDR% scan
)

echo.
echo [3/3] 最近のアラート（各ログの直近10件）...
echo --- PC 監視ログ ---
powershell -NoProfile -Command "$p=Join-Path $env:ProgramData 'HomeWatch\homewatch-alerts.log'; if(Test-Path $p){Get-Content $p -Tail 10}else{'  (まだアラートはありません)'}"
echo --- ネットワーク監視ログ ---
powershell -NoProfile -Command "$p='%ROOT%network\homewatch-netscan.log'; if(Test-Path $p){Get-Content $p -Tail 10}else{'  (まだログはありません)'}"

echo.
echo 完了。ウィンドウを閉じるには何かキーを押してください。
pause >nul
