@echo off
cd /d "%~dp0"
echo Starting Pro Workout...
python server.py
if errorlevel 1 py -3 server.py
pause
