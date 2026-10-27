@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (set "PY=py") else (set "PY=python")
if not exist .venv\Scripts\python.exe (
  echo Creating isolated Python environment...
  %PY% -m venv .venv
  if errorlevel 1 goto fail
)
echo Installing minimal application dependency...
.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto fail
echo.
echo Setup complete. Double-click run_windows.bat to start the app.
pause
exit /b 0
:fail
echo Setup failed. Check Python 3.11+ and internet connectivity.
pause
exit /b 1
