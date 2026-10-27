$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
python -m pip install -e '.[full,build]'
python -m unittest discover -s tests -v
python -m PyInstaller --noconfirm --clean --onefile --windowed --name CASSipher --icon assets/icon.ico --paths src --collect-all tkinterdnd2 --collect-all zstandard main.py
Write-Host 'Build complete: dist/CASSipher.exe'
