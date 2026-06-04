# Sprint 8 / PKG-1: сборка one-folder executable (PyInstaller) + ZIP для сдачи
# Usage (PowerShell, from repo root):
#   .\scripts\build_exe.ps1

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

function Resolve-Python {
    $venvPy = Join-Path $Root ".venv\Scripts\python.exe"
    if (Test-Path $venvPy) { return $venvPy }
    $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($pyLauncher) { return "py -3" }
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) { return "python" }
    throw "Python not found. Activate .venv or install Python 3.10+."
}

$Python = Resolve-Python
Write-Host "Using Python: $Python"

Write-Host "Installing build dependencies..."
Invoke-Expression "$Python -m pip install -r requirements.txt -q"
Invoke-Expression "$Python -m pip install -r requirements-build.txt -q"

Write-Host "Building CryptoSafeManager (one-folder)..."
Invoke-Expression "$Python -m PyInstaller --noconfirm --clean cryptosafe.spec"

$OutDir = Join-Path $Root "dist" "CryptoSafeManager"
$ExePath = Join-Path $OutDir "CryptoSafeManager.exe"
if (-not (Test-Path $ExePath)) {
    Write-Error "Build failed: $ExePath not found"
}

$ReadmePath = Join-Path $OutDir "README.txt"
@(
    "CryptoSafe Manager — Windows build (Sprint 8)"
    ""
    "Запуск: дважды щёлкните CryptoSafeManager.exe"
    "        (или из этой папки в PowerShell: .\CryptoSafeManager.exe)"
    ""
    "Важно: не удаляйте папку _internal — она нужна для работы."
    "База данных создаётся при первом запуске (см. docs/user_guide.md)."
    ""
    "Сборка: PyInstaller one-folder, Windows x64."
) | Set-Content -Path $ReadmePath -Encoding UTF8

$ZipPath = Join-Path $Root "dist" "CryptoSafeManager-Windows.zip"
if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }
Compress-Archive -Path $OutDir -DestinationPath $ZipPath -CompressionLevel Optimal

Write-Host ""
Write-Host "Done."
Write-Host "  Run:  $ExePath"
Write-Host "  ZIP:  $ZipPath"
