# Sprint 8 / PKG-1: сборка one-folder executable (PyInstaller)
# Usage (PowerShell, from repo root):
#   .\scripts\build_exe.ps1

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

Write-Host "Installing build dependencies..."
python -m pip install -r requirements.txt -q
python -m pip install -r requirements-build.txt -q

Write-Host "Building CryptoSafeManager (one-folder)..."
python -m PyInstaller --noconfirm --clean cryptosafe.spec

$OutDir = Join-Path $Root "dist" "CryptoSafeManager"
if (-not (Test-Path $OutDir)) {
    Write-Error "Build failed: $OutDir not found"
}

Write-Host ""
Write-Host "Done. Run:"
Write-Host "  $OutDir\CryptoSafeManager.exe"
