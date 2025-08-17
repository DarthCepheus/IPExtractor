# Simple test script
Write-Host "Testing basic PowerShell functionality..." -ForegroundColor Green

# Test function definition
function Test-Function {
    param([string]$Name)
    Write-Host "Hello, $Name!" -ForegroundColor Yellow
}

# Test function call
Test-Function "World"

# Test basic operations
$testVar = "Test Value"
Write-Host "Variable test: $testVar" -ForegroundColor Cyan

Write-Host "Script completed successfully!" -ForegroundColor Green
Read-Host "Press Enter to continue"
