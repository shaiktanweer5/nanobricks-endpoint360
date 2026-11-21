
"""
Nanobricks Endpoint360 Free
Single-EXE entry point.

Purpose:
1. Launch the Endpoint360 assessment.
2. Run approved assessment modules.
3. Start the local dashboard.
4. Support PyInstaller one-file packaging.
"""

import os
import runpy
import sys
from pathlib import Path


# --------------------------------------------------
# APPROVED APPLICATION SCRIPTS
# --------------------------------------------------

ALLOWED_SCRIPTS = {
    "launch_endpoint360.py",
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
# LOCATE APPLICATION RESOURCES
# --------------------------------------------------

def application_root():

    # Running directly through Python.
    if not getattr(sys, "frozen", False):
        return Path(__file__).resolve().parent

    # Child processes must use the same extracted
    # application directory as the main process.
    shared = os.environ.get(
        "NANOBRICKS_ENDPOINT360_ROOT"
    )

    if shared:
        shared_path = Path(shared).resolve()

        if shared_path.is_dir():
            return shared_path

    # PyInstaller one-file extraction directory.
    return Path(sys._MEIPASS).resolve()


ROOT = application_root()

os.environ[
    "NANOBRICKS_ENDPOINT360_ROOT"
] = str(ROOT)

os.chdir(ROOT)

sys.path.insert(0, str(ROOT))


# --------------------------------------------------
# EXECUTE AN APPROVED SCRIPT
# --------------------------------------------------

def run_script(name):

    name = Path(name).as_posix()

    if name not in ALLOWED_SCRIPTS:
        raise SystemExit(
            f"Unsupported Endpoint360 module: {name}"
        )

    script = ROOT / name

    if not script.is_file():
        raise SystemExit(
            f"Required application file missing: {name}"
        )

    sys.argv = [str(script)]

    runpy.run_path(
        str(script),
        run_name="__main__"
    )


# --------------------------------------------------
# APPLICATION STARTUP
# --------------------------------------------------

def main():

    # Internal subprocess execution.
    if (
        len(sys.argv) == 3
        and sys.argv[1] == "--run-script"
    ):
        run_script(sys.argv[2])
        return

    # Normal double-click execution.
    run_script("launch_endpoint360.py")


# --------------------------------------------------
# MAIN ENTRY POINT
# --------------------------------------------------

if __name__ == "__main__":
    main()
