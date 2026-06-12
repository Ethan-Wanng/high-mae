@echo off
setlocal

set "ROOT=%~dp0"
set "SCRIPT=%ROOT%scripts\mk.ps1"
set "OUTPUT=%ROOT%dist\wing-1.0.3-windows-x64-setup.exe"

title wing installer package
cd /d "%ROOT%"

echo ============================================================
echo  wing installer package
echo ============================================================
echo.
echo Project: %ROOT%
echo.

where powershell >nul 2>nul
if errorlevel 1 (
    echo [ERROR] PowerShell was not found.
    goto failed
)

if not exist "%SCRIPT%" (
    echo [ERROR] Build script was not found:
    echo %SCRIPT%
    goto failed
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" package
if errorlevel 1 goto failed

echo.
echo ============================================================
echo  Installer package completed
echo ============================================================
echo.
echo Output:
echo   %OUTPUT%
echo.

if exist "%ROOT%dist" (
    start "" "%ROOT%dist"
)

if /i "%~1"=="nopause" goto done
pause
goto done

:failed
echo.
echo ============================================================
echo  Installer package failed
echo ============================================================
echo.
echo Please check the messages above.
if /i "%~1"=="nopause" exit /b 1
pause
exit /b 1

:done
endlocal
