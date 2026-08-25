@echo off
setlocal enabledelayedexpansion
title LIGHTNING - Website Defense & Intrusion Detection System
color 0B
cls
echo =============================================================================
echo             LIGHTNING - NEXT-GEN WEBSITE DEFENSE & IDS SYSTEM
echo                     CREATED BY NEXO-TECH BY ALEXANDER
echo =============================================================================
echo.

:: 1. Try standard python command
where python >nul 2>nul
if %errorlevel% equ 0 (
    python main.py
    goto end
)

:: 2. Try py launcher
where py >nul 2>nul
if %errorlevel% equ 0 (
    py main.py
    goto end
)

:: 3. Try standard Windows Python install paths
if exist "C:\Program Files\Python312\python.exe" (
    "C:\Program Files\Python312\python.exe" main.py
    goto end
)
if exist "C:\Program Files\Python311\python.exe" (
    "C:\Program Files\Python311\python.exe" main.py
    goto end
)
if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
    "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" main.py
    goto end
)
if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
    "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" main.py
    goto end
)
if exist "C:\Program Files\Blender Foundation\Blender 4.0\4.0\python\bin\python.exe" (
    "C:\Program Files\Blender Foundation\Blender 4.0\4.0\python\bin\python.exe" main.py
    goto end
)

echo [!] Python executable was not found automatically.
echo Please install Python from https://www.python.org/downloads/ or add it to PATH.
pause

:end
