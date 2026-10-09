@echo off
chcp 65001 > nul
cd /d "%~dp0"
where py > nul 2>&1 && (py server.py) || (python server.py)
pause
