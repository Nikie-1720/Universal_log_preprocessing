@echo off
setlocal

echo.
echo ===========================================================
echo              ULPF AGENT PLUGIN INSTALLER
echo ===========================================================
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-Agent.ps1" %*

if errorlevel 1 (
    echo.
    echo ULPF Agent installation FAILED.
    echo.
    pause
    exit /b 1
)

echo.
echo ULPF Agent installation completed successfully.
echo.
pause

endlocal