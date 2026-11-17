# Run the SecureQR test suite:  .\test.ps1   (extra arguments go to pytest, e.g. .\test.ps1 -v)
# Native tools write warnings to stderr; with "Stop", Windows PowerShell 5.1 would
# treat redirected stderr as fatal. Exit codes are checked explicitly instead.
$ErrorActionPreference = "Continue"
Set-Location -Path $PSScriptRoot
$venvPy = Join-Path $PSScriptRoot "venv\Scripts\python.exe"
if (-not (Test-Path $venvPy)) {
    Write-Host "Virtual environment not found. Run setup first:  powershell -ExecutionPolicy Bypass -File .\setup.ps1" -ForegroundColor Red
    exit 1
}
& $venvPy -m pytest @args
exit $LASTEXITCODE
