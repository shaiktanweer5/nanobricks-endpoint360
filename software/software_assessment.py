
"""
Nanobricks Endpoint360
Windows Software Assessment v0.1.1

Read-only inventory and available-update assessment.
"""

import ctypes
import json
import platform
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
import winreg


VERSION = "0.1.1"

REGISTRY_PATH = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"

REGISTRY_LOCATIONS = [
    (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY),
    (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY),
    (winreg.HKEY_CURRENT_USER, 0),
]


def is_administrator():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def read_registry_value(key, name):
    try:
        return winreg.QueryValueEx(key, name)[0]
    except (OSError, ValueError):
        return None


def get_installed_software():
    applications = []
    errors = []
    seen = set()

    for root, view in REGISTRY_LOCATIONS:
        try:
            with winreg.OpenKey(
                root, REGISTRY_PATH, 0, winreg.KEY_READ | view
            ) as parent:

                count = winreg.QueryInfoKey(parent)[0]

                for index in range(count):
                    try:
                        subkey = winreg.EnumKey(parent, index)

                        with winreg.OpenKey(parent, subkey) as key:
                            name = read_registry_value(key, "DisplayName")

                            if not name or not str(name).strip():
                                continue

                            if read_registry_value(key, "SystemComponent") == 1:
                                continue

                            version = read_registry_value(key, "DisplayVersion")
                            publisher = read_registry_value(key, "Publisher")
                            install_date = read_registry_value(key, "InstallDate")

                            application = {
                                "Name": str(name).strip(),
                                "Version": str(version).strip()
                                if version else "Unknown",
                                "Publisher": str(publisher).strip()
                                if publisher else "Unknown",
                                "InstallDate": str(install_date)
                                if install_date else None,
                            }

                            identity = (
                                application["Name"].casefold(),
                                application["Version"].casefold(),
                                application["Publisher"].casefold(),
                            )

                            if identity not in seen:
                                seen.add(identity)
                                applications.append(application)

                    except OSError as error:
                        errors.append(str(error))

        except OSError as error:
            errors.append(str(error))

    applications.sort(key=lambda app: app["Name"].casefold())

    return {
        "Status": "Collected" if not errors else "Partial",
        "Count": len(applications),
        "Applications": applications,
        "Errors": errors,
    }


def get_winget_version():
    executable = shutil.which("winget")

    if not executable:
        return None

    try:
        result = subprocess.run(
            [executable, "--version"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=20,
            check=False,
        )

        if result.returncode == 0:
            return result.stdout.strip()

    except (OSError, subprocess.TimeoutExpired):
        pass

    return None


def parse_winget_updates(output):
    lines = output.splitlines()

    header_index = None
    positions = None

    for index, line in enumerate(lines):
        if (
            "Name" in line
            and "Id" in line
            and "Version" in line
            and "Available" in line
            and "Source" in line
        ):
            positions = {
                "Name": line.index("Name"),
                "Id": line.index("Id"),
                "Version": line.index("Version"),
                "Available": line.index("Available"),
                "Source": line.index("Source"),
            }

            if not (
                positions["Name"] < positions["Id"]
                < positions["Version"] < positions["Available"]
                < positions["Source"]
            ):
                continue

            header_index = index
            break

    if header_index is None:
        return [], False

    updates = []

    for line in lines[header_index + 1:]:
        stripped = line.strip()

        if not stripped:
            continue

        if re.match(r"^-{5,}$", stripped):
            continue

        if re.search(r"\bupgrades?\s+available\b", stripped, re.I):
            break

        name = line[
            positions["Name"]:positions["Id"]
        ].strip()

        package_id = line[
            positions["Id"]:positions["Version"]
        ].strip()

        installed = line[
            positions["Version"]:positions["Available"]
        ].strip()

        available = line[
            positions["Available"]:positions["Source"]
        ].strip()

        source = line[positions["Source"]:].strip()

        if not all((name, package_id, installed, available)):
            continue

        updates.append({
            "Name": name,
            "PackageId": package_id,
            "InstalledVersion": installed,
            "AvailableVersion": available,
            "Source": source or "Unknown",
            "VersionKnown": installed.casefold() != "unknown",
        })

    return updates, True


def get_available_updates():
    executable = shutil.which("winget")
    version = get_winget_version()

    if not executable or not version:
        return {
            "Status": "Unavailable",
            "WingetVersion": version,
            "Count": 0,
            "Updates": [],
            "Error": "Winget is unavailable.",
        }

    command = [
        executable,
        "upgrade",
        "--include-unknown",
        "--disable-interactivity",
        "--accept-source-agreements",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=120,
            check=False,
        )

        output = result.stdout or ""
        updates, header_found = parse_winget_updates(output)

        no_updates = bool(
            re.search(
                r"No applicable upgrade found|No available upgrade found",
                output,
                re.I,
            )
        )

        if result.returncode != 0:
            status = "Error"
            error = (
                result.stderr.strip()
                or f"Winget exited with code {result.returncode}"
            )
        elif not header_found and not no_updates:
            status = "Parse Error"
            error = "Could not identify Winget update columns."
        else:
            status = "Collected"
            error = None

        return {
            "Status": status,
            "WingetVersion": version,
            "Count": len(updates),
            "Updates": updates,
            "Error": error,
        }

    except subprocess.TimeoutExpired:
        return {
            "Status": "Timeout",
            "WingetVersion": version,
            "Count": 0,
            "Updates": [],
            "Error": "Winget assessment timed out.",
        }

    except OSError as error:
        return {
            "Status": "Error",
            "WingetVersion": version,
            "Count": 0,
            "Updates": [],
            "Error": str(error),
        }


def main():
    print("=" * 48)
    print(" NANOBRICKS ENDPOINT360")
    print(f" Python Software Assessment v{VERSION}")
    print("=" * 48)

    print("\nCollecting installed software...")
    installed = get_installed_software()

    print("Checking available software updates...")
    updates = get_available_updates()

    report = {
        "Product": "Nanobricks Endpoint360",
        "Module": "Software Assessment",
        "Version": VERSION,
        "ComputerName": platform.node(),
        "Timestamp": datetime.now().astimezone().isoformat(),
        "Administrator": is_administrator(),
        "InstalledSoftware": installed,
        "AvailableUpdates": updates,
        "AssessmentMode": "Read Only",
    }

    reports_directory = Path(__file__).resolve().parent / "reports"
    reports_directory.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    report_path = reports_directory / (
        f"{platform.node()}-PythonSoftware-{timestamp}.json"
    )

    with report_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2, ensure_ascii=False)

    print("\nASSESSMENT SUMMARY")
    print("-" * 48)
    print(f"Computer: {report['ComputerName']}")
    print(f"Administrator: {report['Administrator']}")
    print(f"Installed Applications: {installed['Count']}")
    print(f"Installed Inventory Status: {installed['Status']}")
    print(f"Winget Version: {updates['WingetVersion']}")
    print(f"Updates Found: {updates['Count']}")
    print(f"Update Assessment Status: {updates['Status']}")

    if updates["Error"]:
        print(f"Update Assessment Error: {updates['Error']}")

    for update in updates["Updates"]:
        print(
            f"  - {update['Name']}: "
            f"{update['InstalledVersion']} -> "
            f"{update['AvailableVersion']}"
        )

    print(f"\nReport: {report_path}")
    print("\nAssessment completed.")
    print("No applications were installed or updated.")


if __name__ == "__main__":
    main()
