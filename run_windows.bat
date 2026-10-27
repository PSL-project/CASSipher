@echo off
cd /d "%~dp0"
if exist .venv\Scripts\pythonw.exe (
  start "CASSipher" .venv\Scripts\pythonw.exe main.py
) else (
  echo Run setup_windows.bat once before launching.
  pause
)
