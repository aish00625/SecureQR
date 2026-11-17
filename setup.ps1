# SecureQR - one-time setup on Windows (PowerShell 5.1 or 7)
#   powershell -ExecutionPolicy Bypass -File .\setup.ps1
# Creates .\venv, installs requirements, creates .env with a random secret key
# and runs a health check. Safe to run again.

# Native tools write warnings to stderr; with "Stop", Windows PowerShell 5.1 would
# treat redirected stderr as fatal. Exit codes are checked explicitly instead.
$ErrorActionPreference = "Continue"
Set-Location -Path $PSScriptRoot

Write-Host "== SecureQR setup ==" -ForegroundColor Cyan

# 1. Find a supported Python (3.11 - 3.14). Prefer the py launcher.
$pyExe = $null
$pyArgs = @()
if (Get-Command py -ErrorAction SilentlyContinue) {
    foreach ($v in @("3.13", "3.12", "3.14", "3.11")) {
        & py "-$v" -c "import sys" 2>$null
        if ($LASTEXITCODE -eq 0) { $pyExe = "py"; $pyArgs = @("-$v"); break }
    }
}
if (-not $pyExe -and (Get-Command python -ErrorAction SilentlyContinue)) {
    & python -c "import sys; sys.exit(0 if (3,11) <= sys.version_info[:2] <= (3,14) else 1)" 2>$null
    if ($LASTEXITCODE -eq 0) { $pyExe = "python" }
}
if (-not $pyExe) {
    Write-Host "Python 3.11 - 3.14 was not found. Install Python 3.12 or 3.13 from https://www.python.org/downloads/ (tick 'Add python.exe to PATH') and run this script again." -ForegroundColor Red
    exit 1
}
$found = & $pyExe @pyArgs -c "import sys; print(sys.version.split()[0])"
Write-Host "Using Python $found"

# 2. Virtual environment
if (-not (Test-Path ".\venv\Scripts\python.exe")) {
    Write-Host "Creating virtual environment in .\venv ..."
    & $pyExe @pyArgs -m venv venv
    if ($LASTEXITCODE -ne 0) { Write-Host "Could not create the virtual environment." -ForegroundColor Red; exit 1 }
}
$venvPy = Join-Path $PSScriptRoot "venv\Scripts\python.exe"

# 3. Dependencies
Write-Host "Installing dependencies (a few minutes the first time) ..."
& $venvPy -m pip install --upgrade pip
& $venvPy -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { Write-Host "pip install failed - see the messages above." -ForegroundColor Red; exit 1 }

# 4. .env with a random secret key
if (-not (Test-Path ".\.env")) {
    $key = & $venvPy -c "import secrets; print(secrets.token_hex(32))"
    (Get-Content ".\.env.example") -replace '^SECUREQR_SECRET_KEY=.*$', "SECUREQR_SECRET_KEY=$key" |
        Set-Content ".\.env" -Encoding ascii
    Write-Host "Created .env with a random SECUREQR_SECRET_KEY"
}

# 5. Health check
& $venvPy scripts\check_setup.py
Write-Host ""
Write-Host "Start the app with:   .\run.ps1        (then open http://127.0.0.1:5000)" -ForegroundColor Green
Write-Host "Run the tests with:   .\test.ps1" -ForegroundColor Green
