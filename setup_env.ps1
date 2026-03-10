<#
PowerShell setup script for TraceX Guard backend.

This script will:
  1. Ensure Python 3 is installed (via winget if available).
  2. Create/activate a venv.
  3. Install dependencies from requirements.txt.
  4. Run a compile check and start uvicorn.

Usage:
  .\setup_env.ps1
#>

function Ensure-Python {
    Write-Host "Checking for Python..."
    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) {
        Write-Host "Python not found. Attempting to install via winget..."
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            winget install --id Python.Python.3 --source winget -e --silent
        } else {
            Write-Host "winget not found. Please install Python manually from https://www.python.org/downloads/"
            return $false
        }
    }
    return $true
}

function Run-Setup {
    if (-not (Ensure-Python)) {
        return
    }

    Write-Host "Creating virtual environment..."
    python -m venv .venv

    Write-Host "Activating virtual environment..."
    $activate = Join-Path $PWD ".venv\Scripts\Activate.ps1"
    if (Test-Path $activate) {
        . $activate
    }

    Write-Host "Installing dependencies..."
    python -m pip install --upgrade pip
    python -m pip install -r requirements.txt

    Write-Host "Running syntax check..."
    python -m compileall -q app

    Write-Host "Starting Uvicorn server (ctrl+c to stop)..."
    uvicorn app.main:app --reload
}

Run-Setup
