
"""
Nanobricks Endpoint360 Free
Version: 0.5.0

Purpose:
1. Run the Windows endpoint assessment.
2. Run the security compliance checks.
3. Start the local dashboard.
4. Open the dashboard in the browser.

All assessments are read-only.
"""

import subprocess
import sys
import time
import webbrowser

from pathlib import Path
from urllib.request import urlopen


# --------------------------------------------------
# APPLICATION SETTINGS
# --------------------------------------------------

ROOT = Path(__file__).resolve().parent
DASHBOARD_URL = "http://127.0.0.1:8765/"

IS_PACKAGED = getattr(sys, "frozen", False)


# --------------------------------------------------
# BUILD THE COMMAND TO RUN A PYTHON SCRIPT
# --------------------------------------------------

def get_command(script_name):
    """
    Development:
        Run the script using Python.

    Packaged Windows EXE:
        Run the script using Endpoint360Runtime.exe.
    """

    if IS_PACKAGED:
        return [
            sys.executable,
            "--run-script",
            script_name
        ]

    return [
        sys.executable,
        str(ROOT / script_name)
    ]


# --------------------------------------------------
# RUN AN ASSESSMENT MODULE
# --------------------------------------------------

def run_script(script_name):

    print(f"\nRunning {script_name}...", flush=True)

    result = subprocess.run(
        get_command(script_name),
        cwd=str(ROOT),
        check=False
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"{script_name} failed: {result.returncode}"
        )


# --------------------------------------------------
# CHECK IF DASHBOARD IS AVAILABLE
# --------------------------------------------------

def dashboard_is_running():

    try:
        with urlopen(DASHBOARD_URL, timeout=2) as response:
            return response.status == 200

    except Exception:
        return False


# --------------------------------------------------
# START THE LOCAL DASHBOARD
# --------------------------------------------------

def start_dashboard():

    print("\nStarting local dashboard...", flush=True)

    if dashboard_is_running():
        print("A dashboard server is already running.")
        return

    server = subprocess.Popen(
        get_command("dashboard_server.py"),
        cwd=str(ROOT)
    )

    # Check if the server starts successfully.
    for _ in range(20):

        if server.poll() is not None:
            raise RuntimeError("Dashboard server exited.")

        if dashboard_is_running():
            return

        time.sleep(0.5)

    raise RuntimeError("Dashboard did not start.")


# --------------------------------------------------
# MAIN APPLICATION WORKFLOW
# --------------------------------------------------

def main():

    print("=" * 55)
    print(" NANOBRICKS ENDPOINT360 FREE")
    print("=" * 55)

    # Step 1: Collect Windows endpoint information.
    run_script("endpoint360.py")

    # Step 2: Evaluate security compliance.
    run_script("compliance/compliance_engine.py")

    # Step 3: Start the local dashboard.
    start_dashboard()

    # Step 4: Open the dashboard in the browser.
    webbrowser.open(DASHBOARD_URL)

    print("\nDashboard:", DASHBOARD_URL)
    print("Assessment completed successfully.")
    print(
        "Keep the dashboard server running "
        "while using Endpoint360."
    )


# --------------------------------------------------
# APPLICATION ENTRY POINT
# --------------------------------------------------

if __name__ == "__main__":

    try:
        main()

    except Exception as error:
        print(f"\nERROR: {error}")
        sys.exit(1)
