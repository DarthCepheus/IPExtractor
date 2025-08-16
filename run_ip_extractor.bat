@echo off
REM IP Extractor Runner for Windows
REM This batch file helps run the IP extractor script

echo IP Address Extractor
echo ===================
echo.

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% equ 0 (
    echo Python found! Running script...
    echo.
    python ip_extractor.py %*
    goto :end
)

python3 --version >nul 2>&1
if %errorlevel% equ 0 (
    echo Python3 found! Running script...
    echo.
    python3 ip_extractor.py %*
    goto :end
)

REM Check common Python installation paths
if exist "C:\Python*\python.exe" (
    echo Python found in C:\Python*\ directory
    for /d %%i in (C:\Python*) do (
        if exist "%%i\python.exe" (
            echo Using: %%i\python.exe
            "%%i\python.exe" ip_extractor.py %*
            goto :end
        )
    )
)

if exist "C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python*\python.exe" (
    echo Python found in user directory
    for /d %%i in (C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python*) do (
        if exist "%%i\python.exe" (
            echo Using: %%i\python.exe
            "%%i\python.exe" ip_extractor.py %*
            goto :end
        )
    )
)

if exist "C:\Program Files\Python*\python.exe" (
    echo Python found in Program Files
    for /d %%i in ("C:\Program Files\Python*") do (
        if exist "%%i\python.exe" (
            echo Using: %%i\python.exe
            "%%i\python.exe" ip_extractor.py %*
            goto :end
        )
    )
)

REM Python not found
echo.
echo ERROR: Python not found!
echo.
echo To use this script, you need to install Python:
echo.
echo Option 1: Install from Microsoft Store (Recommended for beginners)
echo   - Open Microsoft Store
echo   - Search for "Python 3.11" or "Python 3.12"
echo   - Install the latest version
echo.
echo Option 2: Install from python.org (Advanced users)
echo   - Go to https://www.python.org/downloads/
echo   - Download and install Python 3.11+ for Windows
echo   - Make sure to check "Add Python to PATH" during installation
echo.
echo After installation, restart this command prompt and try again.
echo.
pause

:end
echo.
echo Press any key to exit...
pause >nul
