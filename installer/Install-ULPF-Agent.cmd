@echo off
setlocal

:: ============================================================
:: ULPF AGENT PLUGIN INSTALLER
:: ============================================================

:: Check Administrator privileges
net session >nul 2>&1

if %errorlevel% neq 0 (
    echo.
    echo ============================================================
    echo ULPF Agent requires Administrator privileges.
    echo Opening UAC prompt...
    echo ============================================================
    echo.

    powershell.exe -NoProfile -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b 0
)

echo.
echo ============================================================
echo              ULPF AGENT PLUGIN INSTALLER
echo ============================================================
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-Agent.ps1" %*

if errorlevel 1 (
    echo.
    echo ============================================================
    echo ULPF Agent installation FAILED.
    echo ============================================================
    echo.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo       ULPF AGENT INSTALLATION COMPLETED SUCCESSFULLY
echo ============================================================
echo.
echo ULPF Agent service has been installed and started.
echo.
echo You can verify it from the ULPF dashboard under Agents.
echo.
pause

endlocal
exit /b 0