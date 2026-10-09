@echo off
cd /d "%~dp0"
title ファイル受信サーバー

if not exist "server.py" goto no_server

set "PY="
py -3 --version >nul 2>&1
if not errorlevel 1 set "PY=py -3"
if defined PY goto run
python --version >nul 2>&1
if not errorlevel 1 set "PY=python"
if defined PY goto run
goto no_python

:run
echo 使用する Python:
%PY% --version
echo.
%PY% server.py
echo.
echo サーバーが停止しました。上にエラーが出ている場合は、その内容を確認してください。
pause
exit /b

:no_server
echo [エラー] server.py が見つかりません。
echo start.bat と server.py を同じフォルダに置いてください。
echo.
echo 現在のフォルダ: %cd%
echo このフォルダにあるファイル:
dir /b
echo.
pause
exit /b

:no_python
echo [エラー] Python がインストールされていません。
echo.
echo 次のどちらかの方法でインストールしてから、もう一度 start.bat を開いてください。
echo   1. Microsoft Store で「Python 3.13」を検索してインストール
echo   2. https://www.python.org/downloads/ からインストール
echo      ※ 最初の画面で「Add python.exe to PATH」にチェックを入れてください
echo.
echo 何かキーを押すと Python のダウンロードページを開きます。
pause >nul
start "" https://www.python.org/downloads/
exit /b
