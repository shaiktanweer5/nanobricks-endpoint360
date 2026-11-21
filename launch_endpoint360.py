
"""
Nanobricks Endpoint360 Free
Single-EXE launcher.

Runs the assessment, compliance engine and local dashboard.
Assessments are read-only.
"""

import os
import shutil
import subprocess
import sys
import time
import webbrowser

from pathlib import Path
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parent
DASHBOARD_URL = "http://127.0.0.1:8765/"
IS_PACKAGED = getattr(sys, "frozen", False)


def get_command(script_name):
    if IS_PACKAGED:
        return [
            sys.executable,
            "--run-script",
            script_name,
        ]

    return [
        sys.executable,
        str(ROOT / script_name),
    ]


def run_script(script_name):
    print(f"\nRunning {script_name}...", flush=True)

    result = subprocess.run(
        get_command(script_name),
        cwd=str(ROOT),
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"{script_name} failed: {result.returncode}"
        )


def save_reports():
    """
    Preserve assessment reports outside the temporary
    extraction directory used by a one-file EXE.
    """

    local_appdata = os.environ.get("LOCALAPPDATA")

    if local_appdata:
        destination = (
            Path(local_appdata)
            / "Nanobricks"
            / "Endpoint360"
            / "reports"
        )
    else:
        destination = (
            Path.home()
            / "Nanobricks"
            / "Endpoint360"
            / "reports"
        )

    folders = [
        "reports",
        "collector/reports",
        "security/reports",
        "software/reports",
        "updates/reports",
        "health/reports",
        "network/reports",
        "compliance/reports",
    ]

    for folder in folders:
        source = ROOT / folder

        if not source.is_dir():
            continue

        output = destination / folder
        output.mkdir(parents=True, exist_ok=True)

        for report in source.glob("*.json"):
            shutil.copy2(report, output / report.name)

    print(f"\nReports saved to: {destination}", flush=True)


def dashboard_is_running():
    try:
        with urlopen(DASHBOARD_URL, timeout=2) as response:
            return response.status == 200
    except Exception:
        return False


def start_dashboard():
    print("\nStarting local dashboard...", flush=True)

    if dashboard_is_running():
        raise RuntimeError(
            "Port 8765 is already in use. "
            "Close the previous Endpoint360 dashboard "
            "before starting a new assessment."
        )

    server = subprocess.Popen(
        get_command("dashboard_server.py"),
        cwd=str(ROOT),
    )

    for _ in range(30):
        if server.poll() is not None:
            raise RuntimeError(
                "Dashboard server exited unexpectedly."
            )

        if dashboard_is_running():
            return server

        time.sleep(0.5)

    server.terminate()
    raise RuntimeError("Dashboard did not start.")


def main():
    print("=" * 55)
    print(" NANOBRICKS ENDPOINT360 FREE")
    print("=" * 55)
    print("Read-only Windows assessment")
    print()

    # Execute all seven assessment collectors.
    run_script("endpoint360.py")

    # Evaluate the 17 compliance controls.
    run_script("compliance/compliance_engine.py")

    # Preserve reports in the customer's local profile.
    if IS_PACKAGED:
        save_reports()

    # Start dashboard and keep the parent EXE running.
    # This is important for PyInstaller onefile mode.
    server = start_dashboard()

    webbrowser.open(DASHBOARD_URL)

    print(f"\nDashboard: {DASHBOARD_URL}")
    print("Assessment completed successfully.")
    print("Keep this window open while using Endpoint360.")
    print("Press Ctrl+C to stop the dashboard.")

    try:
        server.wait()
    except KeyboardInterrupt:
        print("\nStopping dashboard...")
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"\nERROR: {error}")
        sys.exit(1)
