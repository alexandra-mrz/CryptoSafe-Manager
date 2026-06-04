# -*- mode: python ; coding: utf-8 -*-
# Sprint 8 / PKG-1: PyInstaller — one-folder bundle (Windows/macOS/Linux)

from pathlib import Path

import pyzbar

block_cipher = None
root = Path(SPECPATH)

# pyzbar на Windows требует libiconv.dll и libzbar-64.dll рядом с пакетом
_pyzbar_dir = Path(pyzbar.__file__).resolve().parent
_pyzbar_binaries = []
for _dll_name in ("libiconv.dll", "libzbar-64.dll", "libzbar.dll"):
    _dll_path = _pyzbar_dir / _dll_name
    if _dll_path.is_file():
        _pyzbar_binaries.append((str(_dll_path), "pyzbar"))

a = Analysis(
    [str(root / "run.py")],
    pathex=[str(root)],
    binaries=_pyzbar_binaries,
    datas=[],
    hiddenimports=[
        "argon2",
        "argon2.low_level",
        "cryptography",
        "cryptography.hazmat.backends.openssl",
        "cryptography.hazmat.primitives.ciphers.aead",
        "cryptography.hazmat.primitives.asymmetric.ed25519",
        "cryptography.hazmat.primitives.asymmetric.ec",
        "cryptography.hazmat.primitives.asymmetric.rsa",
        "keyring",
        "keyring.backends",
        "keyring.backends.Windows",
        "keyring.backends.macOS",
        "keyring.backends.SecretService",
        "pyperclip",
        "PIL",
        "PIL.Image",
        "qrcode",
        "pyzbar",
        "pyzbar.pyzbar",
        "src",
        "src.bootstrap",
        "src.gui.main_window",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "pytest",
        "pytest_cov",
        "pytest_html",
        "pyautogui",
        "tkinter",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="CryptoSafeManager",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[Path(src).name for src, _dest in _pyzbar_binaries],
    name="CryptoSafeManager",
)
