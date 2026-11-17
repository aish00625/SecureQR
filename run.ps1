# Start SecureQR:  .\run.ps1   (extra arguments are passed on, e.g. .\run.ps1 --port 8080)
# Native tools write warnings to stderr; with "Stop", Windows PowerShell 5.1 would
# treat redirected stderr as fatal. Exit codes are checked explicitly instead.
$ErrorActionPreference = "Continue"
Set-Location -Path $PSScriptRoot
$venvPy = Join-Path $PSScriptRoot "venv\Scripts\python.exe"
if (-not (Test-Path $venvPy)) {
    Write-Host "Virtual environment not found. Run setup first:  powershell -ExecutionPolicy Bypass -File .\setup.ps1" -ForegroundColor Red
    exit 1
}
& $venvPy run.py @args
