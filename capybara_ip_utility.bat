@echo off
REM IP Address Parsing Solution - Interactive Utility
REM This batch file walks users through the complete IP parsing workflow

echo.
echo           / /__/ /
echo.
echo        /      _     \________________
echo.
echo      /                                                \
echo.
echo     ^| Y                                                \
echo.
echo      \____/ ^|                                       ^|
echo.
echo          ___/   \        / ______       _      \
echo.
echo        / /____/  ^|      ^|             \     ^|   \     /
echo.
echo ___________// __/  ________// __/ _/ / /_____
echo.
echo                    CAPYBARA
echo              IP Address Parsing Utility
echo.
echo  "Let me help you clean up those messy IP lists!"
echo.

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Python found! Running interactive utility...
    echo.
    goto :start_guide
)

python3 --version >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Python3 found! Running interactive utility...
    echo.
    goto :start_guide
)

REM Check common Python installation paths
if exist "C:\Python*\python.exe" (
    echo [OK] Python found in C:\Python*\ directory
    for /d %%i in (C:\Python*) do (
        if exist "%%i\python.exe" (
            echo Using: %%i\python.exe
            set PYTHON_CMD=%%i\python.exe
            goto :start_guide
        )
    )
)

if exist "C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python*\python.exe" (
    echo [OK] Python found in user directory
    for /d %%i in (C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python*) do (
        if exist "%%i\python.exe" (
            echo Using: %%i\python.exe
            set PYTHON_CMD=%%i\python.exe
            goto :start_guide
        )
    )
)

if exist "C:\Program Files\Python*\python.exe" (
    echo [OK] Python found in Program Files
    for /d %%i in ("C:\Program Files\Python*") do (
        if exist "%%i\python.exe" (
            echo Using: %%i\python.exe
            set PYTHON_CMD=%%i\python.exe
            goto :start_guide
        )
    )
)

REM Python not found
echo.
echo ERROR: Python not found!
echo.
echo To use this toolkit, you need to install Python:
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
exit /b 1

:start_guide
if not defined PYTHON_CMD set PYTHON_CMD=python

echo Welcome to the IP Address Parsing Solution!
echo This utility will walk you through the complete workflow.
echo.

REM Step 1: Get input file
echo Step 1: Input File Selection
echo =============================
echo.

set /p input_file="Enter the path to your IP list file (e.g., client_ips.txt or .\tests\test_data.txt): "
if "%input_file%"=="" (
    set input_file=.\tests\test_data.txt
    echo Using default test file: %input_file%
)
if not exist "%input_file%" (
    echo ERROR: File not found: %input_file%
    echo Please check the file path and try again.
    pause
    exit /b 1
)

echo [OK] Input file found: %input_file%
echo.

REM Step 2: Clean and deduplicate
echo Step 2: Clean ^& Deduplicate
echo ===========================
echo.

REM Get the directory and filename of the input file
for %%F in ("%input_file%") do set "input_dir=%%~dpF" && set "input_name=%%~nF"

set /p clean_file="What should we name the cleaned output file? (default: %input_name%_extrctd.txt): "
if "%clean_file%"=="" set clean_file=%input_dir%%input_name%_extrctd.txt
if not "%clean_file:~-4%"==".txt" set clean_file=%clean_file%.txt

echo [RUNNING] Cleaning and deduplicating IP addresses...
%PYTHON_CMD% ip_extractor.py "%input_file%" --output "%clean_file%"
if %errorlevel% neq 0 (
    echo ERROR: Failed to clean IP addresses. Please check your input file.
    pause
    exit /b 1
)
echo [OK] Cleaning completed successfully!
echo.

REM Step 3: Analyze and count
echo Step 3: Analyze ^& Count
echo =======================
echo.

echo Let's see what we're working with:
%PYTHON_CMD% ip_counter.py "%clean_file%" --detailed
echo.

REM Step 4: Filter by type
echo Step 4: Filter by Type
echo =====================
echo.

echo Now let's separate your IPs by type:
echo.

REM Public IPs
set /p public_file="What should we name the public IPs file? (default: %input_name%_public.txt): "
if "%public_file%"=="" set public_file=%input_dir%%input_name%_public.txt
if not "%public_file:~-4%"==".txt" set public_file=%public_file%.txt

echo [RUNNING] Extracting public IP addresses...
%PYTHON_CMD% public_ip_finder.py "%clean_file%" --output "%public_file%"
echo.

REM Private IPs
set /p private_file="What should we name the private IPs file? (default: %input_name%_private.txt): "
if "%private_file%"=="" set private_file=%input_dir%%input_name%_private.txt
if not "%private_file:~-4%"==".txt" set private_file=%private_file%.txt

echo [RUNNING] Extracting private IP addresses...
%PYTHON_CMD% private_ip_finder.py "%clean_file%" --output "%private_file%"
echo.

REM Summary
echo.
echo WORKFLOW COMPLETE!
echo ==================
echo.
echo Files created:
echo   [FILE] %clean_file% - Cleaned and deduplicated IP list
echo   [FILE] %public_file% - External/Internet-facing IPs  
echo   [FILE] %private_file% - Internal/private network IPs
echo.
echo You can now use these files for:
echo   • Security scanner configuration
echo   • Firewall rule creation
echo   • Network documentation
echo   • Compliance reporting
echo.

echo CAPYBARA says: "Your IP lists are now clean and organized!"
echo.

REM Offer to run scripts independently
echo Want to run scripts independently?
echo You can always use:
echo   %PYTHON_CMD% ip_extractor.py --help
echo   %PYTHON_CMD% ip_counter.py --help
echo   %PYTHON_CMD% public_ip_finder.py --help
echo   %PYTHON_CMD% private_ip_finder.py --help
echo.

pause
