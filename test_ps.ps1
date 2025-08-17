# Simple test script to verify PowerShell execution
Write-Host "PowerShell execution test successful!" -ForegroundColor Green
Write-Host "Current execution policy: $(Get-ExecutionPolicy)" -ForegroundColor Yellow
Write-Host "Current user: $env:USERNAME" -ForegroundColor Cyan
Write-Host "Current directory: $(Get-Location)" -ForegroundColor White
Write-Host ""
Write-Host "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
