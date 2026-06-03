#!/usr/bin/env bash
# Sprint 8 / PKG-1: сборка one-folder executable (PyInstaller)
# Usage: ./scripts/build_exe.sh

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "Installing build dependencies..."
python3 -m pip install -r requirements.txt -q
python3 -m pip install -r requirements-build.txt -q

echo "Building CryptoSafeManager (one-folder)..."
python3 -m PyInstaller --noconfirm --clean cryptosafe.spec

OUT="$ROOT/dist/CryptoSafeManager"
if [[ ! -d "$OUT" ]]; then
  echo "Build failed: $OUT not found" >&2
  exit 1
fi

echo ""
echo "Done. Run:"
if [[ "$(uname -s)" == "Darwin" ]]; then
  echo "  open \"$OUT/CryptoSafeManager\""
else
  echo "  \"$OUT/CryptoSafeManager\""
fi
