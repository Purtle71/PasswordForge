\
@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0PasswordForge.ps1"
if errorlevel 1 (
    echo.
    echo PasswordForge closed with an error.
    pause
)
