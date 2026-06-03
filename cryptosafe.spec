# -*- mode: python ; coding: utf-8 -*-
# Sprint 8 / PKG-1: PyInstaller — one-folder bundle (Windows/macOS/Linux)

from pathlib import Path

block_cipher = None
root = Path(SPECPATH)

a = Analysis(
    [str(root / "run.py")],
    pathex=[str(root)],
    binaries=[],
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
    upx_exclude=[],
    name="CryptoSafeManager",
)
