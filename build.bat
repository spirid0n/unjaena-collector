@echo off
REM Forensic Collector Build Script
REM Requires: Python 3.10+, PyInstaller

echo ========================================
echo Forensic Collector Build Script
echo ========================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    exit /b 1
)

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    exit /b 1
)

REM Install PyInstaller if not present
pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo Installing PyInstaller...
    pip install pyinstaller
)

REM Clean previous build
echo Cleaning previous build...
if exist dist rmdir /s /q dist
if exist build rmdir /s /q build

REM Build EXE
echo Building ForensicCollector.exe...
pyinstaller collector.spec --clean

if errorlevel 1 (
    echo ERROR: Build failed
    exit /b 1
)

echo.
echo ========================================
echo Build completed successfully!
echo EXE location: dist\ForensicCollector.exe
echo ========================================

REM Show file info
if exist dist\ForensicCollector.exe (
    for %%A in (dist\ForensicCollector.exe) do echo File size: %%~zA bytes
)

pause
