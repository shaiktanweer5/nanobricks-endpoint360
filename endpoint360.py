
"""
Nanobricks Endpoint360
Unified Assessment Launcher v0.5.0

Runs seven Python assessment modules and combines their
JSON reports into one Endpoint360 report.

Read-only assessment. No remediation.
"""

import json
import platform
import subprocess
import sys
from datetime import datetime
from pathlib import Path


VERSION = "0.5.0"

BASE_DIR = Path(__file__).resolve().parent

MODULES = [
    {
        "Name": "System Inventory",
        "Script": BASE_DIR / "collector" / "system_inventory.py",
        "ReportDirectory": BASE_DIR / "collector" / "reports",
        "ReportPattern": "*-PythonInventory-*.json",
    },
    {
        "Name": "Windows Security",
        "Script": BASE_DIR / "security" / "windows_security.py",
        "ReportDirectory": BASE_DIR / "security" / "reports",
        "ReportPattern": "*-PythonSecurity-*.json",
    },
    {
        "Name": "Software Assessment",
        "Script": BASE_DIR / "software" / "software_assessment.py",
        "ReportDirectory": BASE_DIR / "software" / "reports",
        "ReportPattern": "*-PythonSoftware-*.json",
    },
    {
        "Name": "Windows Updates",
        "Script": BASE_DIR / "updates" / "windows_updates.py",
        "ReportDirectory": BASE_DIR / "updates" / "reports",
        "ReportPattern": "*-PythonUpdates-*.json",
    },
    {
        "Name": "Advanced Security",
        "Script": BASE_DIR / "security" / "advanced_security.py",
        "ReportDirectory": BASE_DIR / "security" / "reports",
        "ReportPattern": "*-AdvancedSecurity-*.json",
    },
    {
        "Name": "Device Health",
        "Script": BASE_DIR / "health" / "device_health.py",
        "ReportDirectory": BASE_DIR / "health" / "reports",
        "ReportPattern": "*-DeviceHealth-*.json",
    },
    {
        "Name": "Network Security",
        "Script": BASE_DIR / "network" / "network_security.py",
        "ReportDirectory": BASE_DIR / "network" / "reports",
        "ReportPattern": "*-NetworkSecurity-*.json",
    },
]


def find_latest_report(directory, pattern):
    if not directory.exists():
        return None

    reports = list(directory.glob(pattern))

    if not reports:
        return None

    return max(
        reports,
        key=lambda path: path.stat().st_mtime_ns,
    )


def run_module(module):
    name = module["Name"]
    script = module["Script"]

    print(f"\nRunning: {name}")
    print("-" * 48)

    if not script.is_file():
        print(f"ERROR: Module not found: {script}")

        return {
            "Status": "Failed",
            "Error": "Module script not found.",
            "Data": None,
        }

    previous_report = find_latest_report(
        module["ReportDirectory"],
        module["ReportPattern"],
    )

    previous_path = (
        str(previous_report.resolve())
        if previous_report else None
    )

    previous_modified = (
        previous_report.stat().st_mtime_ns
        if previous_report else None
    )

    try:
        result = subprocess.run(
            [sys.executable, str(script)],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=180,
            check=False,
        )

    except subprocess.TimeoutExpired:
        print("ERROR: Module timed out.")

        return {
            "Status": "Timeout",
            "Error": "Assessment exceeded 180 seconds.",
            "Data": None,
        }

    except OSError as error:
        print(f"ERROR: {error}")

        return {
            "Status": "Failed",
            "Error": str(error),
            "Data": None,
        }

    if result.stdout:
        print(result.stdout.rstrip())

    if result.stderr:
        print("\nModule diagnostics:")
        print(result.stderr.rstrip())

    if result.returncode != 0:
        return {
            "Status": "Failed",
            "Error": (
                result.stderr.strip()
                or f"Module exited with code {result.returncode}"
            ),
            "Data": None,
        }

    latest_report = find_latest_report(
        module["ReportDirectory"],
        module["ReportPattern"],
    )

    if latest_report is None:
        return {
            "Status": "Failed",
            "Error": "No module report was generated.",
            "Data": None,
        }

    current_path = str(latest_report.resolve())
    current_modified = latest_report.stat().st_mtime_ns

    if (
        current_path == previous_path
        and current_modified == previous_modified
    ):
        return {
            "Status": "Failed",
            "Error": "Module did not generate a new report.",
            "Data": None,
        }

    try:
        with latest_report.open("r", encoding="utf-8") as file:
            data = json.load(file)

    except (OSError, json.JSONDecodeError) as error:
        return {
            "Status": "Failed",
            "Error": f"Could not read module report: {error}",
            "Data": None,
        }

    return {
        "Status": "Completed",
        "Error": None,
        "SourceReport": str(latest_report),
        "Data": data,
    }


def main():
    print("=" * 60)
    print(" NANOBRICKS ENDPOINT360")
    print(f" Unified Assessment Launcher v{VERSION}")
    print("=" * 60)

    print("\nAssessment mode: READ ONLY")
    print(f"Running {len(MODULES)} Windows assessment modules...")

    started = datetime.now().astimezone()

    results = {}

    for module in MODULES:
        results[module["Name"]] = run_module(module)

    completed = datetime.now().astimezone()

    successful = sum(
        1
        for result in results.values()
        if result["Status"] == "Completed"
    )

    failed = len(results) - successful

    combined_report = {
        "Product": "Nanobricks Endpoint360",
        "Version": VERSION,
        "ComputerName": platform.node(),
        "AssessmentStarted": started.isoformat(),
        "AssessmentCompleted": completed.isoformat(),
        "AssessmentMode": "Read Only",
        "Summary": {
            "TotalModules": len(MODULES),
            "CompletedModules": successful,
            "FailedModules": failed,
            "Status": (
                "Completed"
                if failed == 0
                else "Partial"
                if successful > 0
                else "Failed"
            ),
        },
        "Modules": results,
    }

    reports_directory = BASE_DIR / "reports"
    reports_directory.mkdir(parents=True, exist_ok=True)

    timestamp = completed.strftime("%Y%m%d-%H%M%S")

    report_path = reports_directory / (
        f"{platform.node()}-Endpoint360-{timestamp}.json"
    )

    with report_path.open("w", encoding="utf-8") as file:
        json.dump(
            combined_report,
            file,
            indent=2,
            ensure_ascii=False,
        )

    print("\n" + "=" * 60)
    print(" ENDPOINT360 FINAL SUMMARY")
    print("=" * 60)

    for name, result in results.items():
        print(f"{name}: {result['Status']}")

        if result["Error"]:
            print(f"  Error: {result['Error']}")

    print("-" * 60)
    print(f"Computer: {combined_report['ComputerName']}")
    print(f"Modules Completed: {successful}/{len(MODULES)}")
    print(f"Modules Failed: {failed}")
    print(f"Overall Status: {combined_report['Summary']['Status']}")
    print(f"\nCombined Report: {report_path}")

    print("\nAssessment finished.")
    print("No Windows settings or applications were modified.")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
