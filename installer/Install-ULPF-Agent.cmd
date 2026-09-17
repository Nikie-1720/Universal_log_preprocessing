@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-Agent.ps1" %*
if errorlevel 1 (
  echo.
  echo ULPF Agent installation failed.
  exit /b 1
)
echo.
echo ULPF Agent installation completed successfully.
endlocal
