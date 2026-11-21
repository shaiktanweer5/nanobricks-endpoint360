
# -*- mode: python ; coding: utf-8 -*-

"""
Nanobricks Endpoint360 Free
PyInstaller ONEFILE build.
"""

from pathlib import Path

PROJECT = Path(SPECPATH).resolve()

SCRIPT_FILES = [
    "launch_endpoint360.py",
    "endpoint360.py",
    "dashboard_server.py",
]

RESOURCE_FOLDERS = [
    "collector",
    "security",
    "software",
    "updates",
    "health",
    "network",
    "compliance",
    "dashboard",
]

datas = []

for name in SCRIPT_FILES:
    path = PROJECT / name
    if not path.is_file():
        raise FileNotFoundError(path)
    datas.append((str(path), "."))

for folder_name in RESOURCE_FOLDERS:
    folder = PROJECT / folder_name

    if not folder.is_dir():
        raise FileNotFoundError(folder)

    for path in folder.rglob("*"):
        if not path.is_file():
            continue

        relative = path.relative_to(PROJECT)

        # Reports are generated on the customer's computer.
        # Never include development reports or caches.
        if any(
            part.lower() in {
                "reports",
                "__pycache__",
                ".git",
                "build",
                "dist",
            }
            for part in relative.parts
        ):
            continue

        if path.suffix.lower() in {".pyc", ".pyo"}:
            continue

        datas.append((
            str(path),
            str(relative.parent),
        ))

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

a = Analysis(
    ["build_entry.py"],
    pathex=[str(PROJECT)],
    binaries=[],
    datas=datas,
    hiddenimports=HIDDEN_IMPORTS,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="NanobricksEndpoint360",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
)
