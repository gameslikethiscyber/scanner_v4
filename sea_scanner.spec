# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for SEA Scanner Pro (v5.0.0) - Windows GUI executable.

Build:
    python -m PyInstaller --noconfirm --clean sea_scanner.spec

Produces dist/SeaScannerPro/ ("sea_scanner_pro.exe" + _internal/). The onedir
build is portable (no installation) and starts faster than a onefile bundle.
"""

import os

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('templates', 'templates'),          # report.html.j2
    ],
    hiddenimports=[
        # Optional / lazily-imported dependencies.
        'jinja2',
        'weasyprint',
        'interactsh',
        'playwright',
        # Qt bits sometimes missed by hooks.
        'PySide6.QtSvg',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'pandas', 'IPython', 'pytest'],
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
    name='SEA Scanner Pro',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,                 # GUI mode - no console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='dist_assets/app.ico',
    version='dist_assets/version_info.txt',
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='Sea Scanner Pro',
)