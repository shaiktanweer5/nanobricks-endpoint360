
"""
Nanobricks Endpoint360 Free
Windows EXE Entry Point

Purpose:
1. Start Endpoint360 when the user opens the EXE.
2. Execute approved Python assessment scripts.
3. Support both development and packaged modes.

This file is used by PyInstaller to build Endpoint360Runtime.exe.
"""

import os
import runpy
import sys

from pathlib import Path


# --------------------------------------------------
# APPLICATION LOCATION
# --------------------------------------------------

IS_PACKAGED = getattr(sys, "frozen", False)

if IS_PACKAGED:
    # When running from the Windows EXE.
    ROOT = Path(sys.executable).resolve().parent
else:
    # When running directly with Python.
    ROOT = Path(__file__).resolve().parent


# Run the application from its own folder.
os.chdir(ROOT)

# Make local Python modules discoverable.
sys.path.insert(0, str(ROOT))


# --------------------------------------------------
# APPROVED ASSESSMENT SCRIPTS
# --------------------------------------------------

ALLOWED_SCRIPTS = {
    "endpoint360.py",
    "compliance/compliance_engine.py",
    "dashboard_server.py",
    "collector/system_inventory.py",
    "security/windows_security.py",
    "software/software_assessment.py",
    "updates/windows_updates.py",
    "security/advanced_security.py",
    "health/device_health.py",
    "network/network_security.py",
}


# --------------------------------------------------
# RUN AN APPROVED SCRIPT
# --------------------------------------------------

def run_approved_script(script_name):
    """
    Execute one approved Endpoint360 Python script.
    """

    relative_path = Path(script_name)

    # Standardize the path before checking the allowlist.
    script_name = relative_path.as_posix()

    if script_name not in ALLOWED_SCRIPTS:
        raise SystemExit(
            f"Unsupported Endpoint360 module: {script_name}"
        )

    script_path = ROOT / relative_path

    if not script_path.is_file():
        raise SystemExit(
            f"Endpoint360 module not found: {script_name}"
        )

    sys.argv = [str(script_path)]

    runpy.run_path(
        str(script_path),
        run_name="__main__"
    )


# --------------------------------------------------
# START THE ENDPOINT360 APPLICATION
# --------------------------------------------------

def main():
    """
    Normal launch:
        Start the one-click Endpoint360 assessment.

    Internal launch:
        Run the specified approved module.
    """

    if len(sys.argv) == 3 and sys.argv[1] == "--run-script":
        run_approved_script(sys.argv[2])
        return

    # Normal double-click launch.
    launcher = ROOT / "launch_endpoint360.py"

    sys.argv = [str(launcher)]

    runpy.run_path(
        str(launcher),
        run_name="__main__"
    )


# --------------------------------------------------
# APPLICATION ENTRY POINT
# --------------------------------------------------

if __name__ == "__main__":
    main()
