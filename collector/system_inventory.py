
"""
Nanobricks Endpoint360
System Inventory Collector v0.1.0

Read-only Windows device inventory.
No system configuration changes.
"""

import ctypes
import json
import os
import platform
import shutil
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def run_windows_query(command):
    """Run a read-only Windows information query."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )

        if result.returncode != 0:
            return None

        return json.loads(result.stdout.strip())

    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def get_windows_details():
    """Collect Windows operating system information."""
    data = run_windows_query([
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        (
            "Get-CimInstance Win32_OperatingSystem | "
            "Select-Object Caption,Version,BuildNumber,OSArchitecture | "
            "ConvertTo-Json -Compress"
        ),
    ])

    return data or {
        "Caption": platform.platform(),
        "Version": platform.version(),
        "BuildNumber": None,
        "OSArchitecture": platform.machine(),
    }


def get_hardware_details():
    """Collect manufacturer, model, CPU and memory information."""
    computer = run_windows_query([
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        (
            "Get-CimInstance Win32_ComputerSystem | "
            "Select-Object Manufacturer,Model,TotalPhysicalMemory | "
            "ConvertTo-Json -Compress"
        ),
    ])

    processor = run_windows_query([
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        (
            "Get-CimInstance Win32_Processor | "
            "Select-Object -First 1 Name,NumberOfCores,"
            "NumberOfLogicalProcessors | ConvertTo-Json -Compress"
        ),
    ])

    computer = computer or {}
    processor = processor or {}

    ram_bytes = computer.get("TotalPhysicalMemory")

    return {
        "Manufacturer": computer.get("Manufacturer"),
        "Model": computer.get("Model"),
        "Processor": processor.get("Name") or platform.processor(),
        "PhysicalCores": processor.get("NumberOfCores"),
        "LogicalProcessors": processor.get("NumberOfLogicalProcessors"),
        "RAM_GB": round(ram_bytes / (1024 ** 3), 2)
        if isinstance(ram_bytes, (int, float)) else None,
    }


def get_storage_details():
    """Collect accessible fixed local drive capacity."""
    drives = []

    drive_mask = ctypes.windll.kernel32.GetLogicalDrives()

    for index in range(26):
        if not (drive_mask & (1 << index)):
            continue

        letter = chr(ord("A") + index)
        root = f"{letter}:\\"

        # DRIVE_FIXED = 3
        if ctypes.windll.kernel32.GetDriveTypeW(root) != 3:
            continue

        try:
            usage = shutil.disk_usage(root)

            drives.append({
                "Drive": f"{letter}:",
                "Total_GB": round(usage.total / (1024 ** 3), 2),
                "Used_GB": round(usage.used / (1024 ** 3), 2),
                "Free_GB": round(usage.free / (1024 ** 3), 2),
                "Free_Percent": round(
                    usage.free / usage.total * 100, 2
                ) if usage.total else None,
            })

        except OSError:
            drives.append({
                "Drive": f"{letter}:",
                "Status": "Unable to collect",
            })

    return drives


def main():
    if os.name != "nt":
        raise SystemExit("Endpoint360 currently supports Windows only.")

    print("=" * 44)
    print(" NANOBRICKS ENDPOINT360")
    print(" Python System Inventory v0.1.0")
    print("=" * 44)
    print()
    print("Collecting read-only device information...")

    report = {
        "Product": "Nanobricks Endpoint360",
        "Module": "System Inventory",
        "Version": "0.1.0",
        "ComputerName": socket.gethostname(),
        "AssessmentTimeUTC": datetime.now(timezone.utc).isoformat(),
        "OperatingSystem": get_windows_details(),
        "Hardware": get_hardware_details(),
        "Storage": get_storage_details(),
    }

    report_directory = Path(__file__).resolve().parent / "reports"
    report_directory.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_name = "".join(
        character for character in report["ComputerName"]
        if character.isalnum() or character in "-_"
    ) or "UnknownDevice"

    report_path = (
        report_directory /
        f"{safe_name}-PythonInventory-{timestamp}.json"
    )

    report_path.write_text(
        json.dumps(report, indent=4, ensure_ascii=False),
        encoding="utf-8",
    )

    print()
    print("Assessment completed.")
    print(f"Computer: {report['ComputerName']}")
    print(f"Windows: {report['OperatingSystem'].get('Caption')}")
    print(f"Processor: {report['Hardware'].get('Processor')}")
    print(f"RAM: {report['Hardware'].get('RAM_GB')} GB")
    print(f"Drives detected: {len(report['Storage'])}")
    print(f"Report: {report_path}")
    print()
    print("No system settings were modified.")


if __name__ == "__main__":
    main()
