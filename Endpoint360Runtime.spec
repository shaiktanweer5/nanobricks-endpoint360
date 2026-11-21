
# -*- mode: python ; coding: utf-8 -*-

"""
Nanobricks Endpoint360 Free
Version: 0.5.0

PyInstaller Build Configuration

Purpose:
    Build Endpoint360Runtime.exe for Windows.

Build type:
    Folder-based executable (onedir).

The collector scripts, dashboard files, and other
application resources are distributed alongside the EXE.

The application performs read-only assessments.
"""

# --------------------------------------------------
# REQUIRED PYTHON MODULES
# --------------------------------------------------

HIDDEN_IMPORTS = [
    "webbrowser",
    "ctypes",
    "winreg",
    "socket",
    "platform",
    "shutil",
    "urllib.request",
    "http.server",
    "urllib.parse",
    "json",
    "subprocess",
    "runpy",
]


# --------------------------------------------------
# ANALYZE APPLICATION DEPENDENCIES
# --------------------------------------------------

a = Analysis(
    ["build_entry.py"],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=HIDDEN_IMPORTS,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)


# --------------------------------------------------
# PACKAGE PYTHON MODULES
# --------------------------------------------------

pyz = PYZ(a.pure)


# --------------------------------------------------
# CREATE THE WINDOWS EXECUTABLE
# --------------------------------------------------

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Endpoint360Runtime",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)


# --------------------------------------------------
# COLLECT EXECUTABLE AND DEPENDENCIES
# --------------------------------------------------

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="Endpoint360Runtime",
)
