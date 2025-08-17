# IP Address Parsing Solution - Interactive Utility
# This PowerShell script walks users through the complete IP parsing workflow

Write-Host ""
Write-Host "           / /__/ /"
Write-Host ""
Write-Host "        /      _     \________________"
Write-Host ""
Write-Host "      /                                                \"
Write-Host ""
Write-Host "     | Y                                                \"
Write-Host ""
Write-Host "      \____/ |                                       |"
Write-Host ""
Write-Host "          ___/   \        / ______       _      \"
Write-Host ""
Write-Host "        / /____/  |      |             \     |   \     /"
Write-Host ""
Write-Host " ___________// __/  ________// __/ _/ / /_____"
Write-Host ""
Write-Host "                    CAPYBARA"
Write-Host "              IP Address Parsing Utility"
Write-Host ""
Write-Host '  "Let me help you clean up those messy IP lists!"'
Write-Host ""

# Function to find Python executable
function Find-Python {
    $pythonPaths = @("python", "python3", "py")
    
    # Check if Python is in PATH
    foreach ($cmd in $pythonPaths) {
        try {
            $versionOutput = & $cmd --version 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "[OK] Python found: $versionOutput" -ForegroundColor Green
                return $cmd
            }
        }
        catch { continue }
    }
    
    # Check common installation paths
    $commonPaths = @(
        "C:\Python*",
        "C:\Users\$env:USERNAME\AppData\Local\Programs\Python\Python*",
        "C:\Program Files\Python*"
    )
    
    foreach ($pattern in $commonPaths) {
        $paths = Get-ChildItem -Path $pattern -Directory -ErrorAction SilentlyContinue
        foreach ($path in $paths) {
            $pythonExe = Join-Path $path.FullName "python.exe"
            if (Test-Path $pythonExe) {
                try {
                    $versionOutput = & $pythonExe --version 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        Write-Host "[OK] Python found: $versionOutput" -ForegroundColor Green
                        return $pythonExe
                    }
                }
                catch { continue }
            }
        }
    }
    
    return $null
}

# Function to get user input with default suggestion
function Get-UserInput {
    param(
        [string]$Prompt,
        [string]$DefaultSuggestion,
        [string]$FileType = "txt"
    )
    
    Write-Host "$Prompt" -ForegroundColor Yellow
    Write-Host "Suggested name: $DefaultSuggestion" -ForegroundColor Gray
    $input = Read-Host "Enter filename (or press Enter for suggestion)"
    
    if ([string]::IsNullOrWhiteSpace($input)) {
        $input = $DefaultSuggestion
    }
    
    # Ensure proper file extension
    if (-not $input.EndsWith(".$FileType")) {
        $input = "$input.$FileType"
    }
    
    return $input
}

# Function to run Python script with error handling
function Run-PythonScript {
    param(
        [string]$ScriptName,
        [string]$Arguments,
        [string]$Description
    )
    
    Write-Host ""
    Write-Host "[RUNNING] $Description" -ForegroundColor Cyan
    Write-Host "Running: $python $ScriptName $Arguments" -ForegroundColor Gray
    
    try {
        $argArray = $Arguments -split " "
        & $python $ScriptName @argArray
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[OK] $Description completed successfully!" -ForegroundColor Green
            return $true
        } else {
            Write-Host "[ERROR] $Description failed with exit code: $LASTEXITCODE" -ForegroundColor Red
            return $false
        }
    }
    catch {
        Write-Host "[ERROR] Error running $ScriptName - An error occurred" -ForegroundColor Red
        return $false
    }
}

# Main workflow
Write-Host "Welcome to the IP Address Parsing Solution!" -ForegroundColor Green
Write-Host "This utility will walk you through the complete workflow." -ForegroundColor White
Write-Host ""

# Find Python
$python = Find-Python
if (-not $python) {
    Write-Host "[ERROR] Python not found!" -ForegroundColor Red
    Write-Host ""
    Write-Host "To use this toolkit, you need to install Python:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Option 1: Install from Microsoft Store (Recommended)" -ForegroundColor Cyan
    Write-Host "  - Open Microsoft Store" -ForegroundColor White
    Write-Host "  - Search for 'Python 3.11' or 'Python 3.12'" -ForegroundColor White
    Write-Host "  - Install the latest version" -ForegroundColor White
    Write-Host ""
    Write-Host "Option 2: Install from python.org" -ForegroundColor Cyan
    Write-Host "  - Go to https://www.python.org/downloads/" -ForegroundColor White
    Write-Host "  - Download Python 3.11+ for Windows" -ForegroundColor White
    Write-Host "  - Check 'Add Python to PATH' during installation" -ForegroundColor White
    Write-Host ""
    Write-Host "After installation, restart PowerShell and try again." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "Python is ready! Let's start parsing IP addresses." -ForegroundColor Green
Write-Host ""

# Step 1: Get input file
Write-Host "Step 1: Input File Selection" -ForegroundColor Magenta
Write-Host "=============================" -ForegroundColor Magenta

$inputFile = Read-Host "Enter the path to your IP list file (e.g., client_ips.txt or .\tests\test_data.txt): "
if ([string]::IsNullOrWhiteSpace($inputFile)) {
    $inputFile = ".\tests\test_data.txt"
    Write-Host "Using default test file: $inputFile" -ForegroundColor Yellow
}
if (-not (Test-Path $inputFile)) {
    Write-Host "[ERROR] File not found: $inputFile" -ForegroundColor Red
    Write-Host "Please check the file path and try again." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "[OK] Input file found: $inputFile" -ForegroundColor Green
Write-Host ""

# Step 2: Clean and deduplicate
Write-Host "Step 2: Clean & Deduplicate" -ForegroundColor Magenta
Write-Host "===========================" -ForegroundColor Magenta

# Generate default filename by appending to input filename in the same directory
$inputDir = [System.IO.Path]::GetDirectoryName($inputFile)
$baseName = [System.IO.Path]::GetFileNameWithoutExtension($inputFile)
$defaultCleanFile = [System.IO.Path]::Combine($inputDir, "${baseName}_extrctd.txt")

$cleanFile = Get-UserInput "What should we name the cleaned output file?" $defaultCleanFile "txt"

$success = Run-PythonScript "ip_extractor.py" "$inputFile --output $cleanFile" "Cleaning and deduplicating IP addresses"
if (-not $success) {
    Write-Host "[ERROR] Failed to clean IP addresses. Please check your input file." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Step 3: Analyze and count
Write-Host ""
Write-Host "Step 3: Analyze & Count" -ForegroundColor Magenta
Write-Host "=======================" -ForegroundColor Magenta

Write-Host "Let's see what we're working with:" -ForegroundColor Yellow
Run-PythonScript "ip_counter.py" "$cleanFile --detailed" "Analyzing IP addresses"

# Step 4: Filter by type
Write-Host ""
Write-Host "Step 4: Filter by Type" -ForegroundColor Magenta
Write-Host "=====================" -ForegroundColor Magenta

Write-Host "Now let's separate your IPs by type:" -ForegroundColor Yellow
Write-Host ""

# Public IPs
$defaultPublicFile = [System.IO.Path]::Combine($inputDir, "${baseName}_public.txt")
$publicFile = Get-UserInput "What should we name the public IPs file?" $defaultPublicFile "txt"
Run-PythonScript "public_ip_finder.py" "$cleanFile --output $publicFile" "Extracting public IP addresses"

# Private IPs
$defaultPrivateFile = [System.IO.Path]::Combine($inputDir, "${baseName}_private.txt")
$privateFile = Get-UserInput "What should we name the private IPs file?" $defaultPrivateFile "txt"
Run-PythonScript "private_ip_finder.py" "$cleanFile --output $privateFile" "Extracting private IP addresses"

# Summary
Write-Host ""
Write-Host "[COMPLETE] Workflow Complete!" -ForegroundColor Green
Write-Host "===================" -ForegroundColor Green
Write-Host ""
Write-Host "Files created:" -ForegroundColor Yellow
Write-Host "  [FILE] $cleanFile - Cleaned and deduplicated IP list" -ForegroundColor White
Write-Host "  [FILE] $publicFile - External/Internet-facing IPs" -ForegroundColor White
Write-Host "  [FILE] $privateFile - Internal/private network IPs" -ForegroundColor White
Write-Host ""
Write-Host "You can now use these files for:" -ForegroundColor Cyan
Write-Host "  • Security scanner configuration" -ForegroundColor White
Write-Host "  • Firewall rule creation" -ForegroundColor White
Write-Host "  • Network documentation" -ForegroundColor White
Write-Host "  • Compliance reporting" -ForegroundColor White
Write-Host ""

Write-Host "CAPYBARA says: 'Your IP lists are now clean and organized!'" -ForegroundColor Cyan
Write-Host ""

# Offer to run scripts independently
Write-Host "Want to run scripts independently?" -ForegroundColor Yellow
Write-Host "You can always use:" -ForegroundColor Gray
Write-Host "  python ip_extractor.py --help" -ForegroundColor White
Write-Host "  python ip_counter.py --help" -ForegroundColor White
Write-Host "  python public_ip_finder.py --help" -ForegroundColor White
Write-Host "  python private_ip_finder.py --help" -ForegroundColor White
Write-Host ""

Read-Host "Press Enter to exit"
