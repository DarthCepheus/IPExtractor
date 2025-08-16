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
            $version = & $cmd --version 2>$null
            if ($LASTEXITCODE -eq 0) {
                return $cmd
            }
        }
        catch {
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
                return $pythonExe
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
    
    # Build arguments
    $args = $args -join " "
    
    # Run the script
    try {
        & $python "ip_extractor.py" $args
    }
    catch {
        Write-Host "Error running script: $_" -ForegroundColor Red
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
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
