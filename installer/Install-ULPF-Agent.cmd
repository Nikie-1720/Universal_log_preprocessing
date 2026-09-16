@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\scripts\install-ulpf-agent-windows.ps1" %*
if errorlevel 1 (
  echo.
  echo ULPF Agent installation failed.
  exit /b 1
)
echo.
echo ULPF Agent installation completed successfully.
endlocal
