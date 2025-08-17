# IP Extractor Runner for Windows PowerShell
# This script helps run the IP extractor script

Write-Host "IP Address Extractor" -ForegroundColor Green
Write-Host "===================" -ForegroundColor Green
Write-Host ""

# Function to find Python executable
function Find-Python {
    $pythonPaths = @(
        "python",
        "python3",
        "py"
    )
    
    # Check if Python is in PATH
    foreach ($cmd in $pythonPaths) {
        try {
            # Capture both output and error streams
            $versionOutput = & $cmd --version 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Found Python: $versionOutput" -ForegroundColor Green
                return $cmd
            }
        }
        catch {
            Write-Host "Command '$cmd' not found" -ForegroundColor Yellow
            continue
        }
    }
    
    # Check common installation paths
    $commonPaths = @(
        "C:\Python*",
        "C:\Users\$env:USERNAME\AppData\Local\Programs\Python\Python*",
        "C:\Program Files\Python*",
        "C:\Program Files (x86)\Python*"
    )
    
    foreach ($pattern in $commonPaths) {
        $paths = Get-ChildItem -Path $pattern -Directory -ErrorAction SilentlyContinue
        foreach ($path in $paths) {
            $pythonExe = Join-Path $path.FullName "python.exe"
            if (Test-Path $pythonExe) {
                try {
                    $versionOutput = & $pythonExe --version 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        Write-Host "Found Python: $versionOutput" -ForegroundColor Green
                        return $pythonExe
                    }
                }
                catch {
                    continue
                }
            }
        }
    }
    
    return $null
}

# Find Python
$python = Find-Python

if ($python) {
    Write-Host "Python found: $python" -ForegroundColor Green
    Write-Host "Running script..." -ForegroundColor Green
    Write-Host ""
    
    # Build arguments from script parameters (avoiding conflict with $args)
    $scriptArgs = $MyInvocation.UnboundArguments -join " "
    
    # Run the script
    try {
        if ($scriptArgs) {
            Write-Host "Running: $python ip_extractor.py $scriptArgs" -ForegroundColor Cyan
            & $python "ip_extractor.py" $scriptArgs.Split(" ")
        } else {
            Write-Host "Running: $python ip_extractor.py" -ForegroundColor Cyan
            & $python "ip_extractor.py"
        }
    }
    catch {
        Write-Host "Error running script: $_" -ForegroundColor Red
        Write-Host "Exit code: $LASTEXITCODE" -ForegroundColor Red
    }
}
else {
    Write-Host "ERROR: Python not found!" -ForegroundColor Red
    Write-Host ""
    Write-Host "To use this script, you need to install Python:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Option 1: Install from Microsoft Store (Recommended for beginners)" -ForegroundColor Cyan
    Write-Host "  - Open Microsoft Store" -ForegroundColor White
    Write-Host "  - Search for 'Python 3.11' or 'Python 3.12'" -ForegroundColor White
    Write-Host "  - Install the latest version" -ForegroundColor White
    Write-Host ""
    Write-Host "Option 2: Install from python.org (Advanced users)" -ForegroundColor Cyan
    Write-Host "  - Go to https://www.python.org/downloads/" -ForegroundColor White
    Write-Host "  - Download and install Python 3.11+ for Windows" -ForegroundColor White
    Write-Host "  - Make sure to check 'Add Python to PATH' during installation" -ForegroundColor White
    Write-Host ""
    Write-Host "After installation, restart PowerShell and try again." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Gray
try {
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
catch {
    # Fallback if RawUI is not available
    Read-Host "Press Enter to continue"
}
