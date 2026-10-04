@echo off
REM ============================================================
REM  WinSecAudit - double-click launcher for Windows
REM  Runs the audit and opens the dashboard in your browser.
REM ============================================================
setlocal
title WinSecAudit - Windows Security Posture Audit
cd /d "%~dp0"

echo.
echo   Starting WinSecAudit...
echo   A User Account Control prompt may appear - click Yes for a
echo   full scan including BitLocker, Defender and firewall checks.
echo.

REM If not already elevated, relaunch this script elevated.
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -Verb RunAs -FilePath 'powershell' -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-File','%~dp0start.ps1'"
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -NoExit -File "%~dp0start.ps1"
endlocal
