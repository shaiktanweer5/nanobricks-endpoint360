
"""
Nanobricks Endpoint360
Windows Security Assessment v0.1.1

Read-only Windows security assessment.

Checks:
- Microsoft Defender
- Windows Firewall
- TPM
- Secure Boot
- BitLocker

No security settings are modified.
"""

import ctypes
import json
import os
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path


VERSION = "0.1.1"


def is_administrator():
    """Determine whether the current process is elevated."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def run_security_query(command):
    """Execute a read-only Windows query and return structured results."""

    try:
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command,
            ],
            capture_output=True,
            text=True,
            timeout=45,
            check=False,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )

        if completed.returncode != 0:
            error_message = completed.stderr.strip()

            if not error_message:
                error_message = completed.stdout.strip()

            if (
                "access denied" in error_message.lower()
                or "privilege" in error_message.lower()
                or "unauthorized" in error_message.lower()
            ):
                return {
                    "Status": "Access Denied",
                    "Reason": error_message,
                }

            return {
                "Status": "Unknown",
                "Reason": error_message or "Windows query failed.",
            }

        output = completed.stdout.strip()

        if not output:
            return {
                "Status": "Unknown",
                "Reason": "Windows returned no information.",
            }

        return json.loads(output)

    except subprocess.TimeoutExpired:
        return {
            "Status": "Unknown",
            "Reason": "Windows query timed out.",
        }

    except (OSError, ValueError) as error:
        return {
            "Status": "Unknown",
            "Reason": str(error),
        }


def get_defender():
    """Collect Microsoft Defender antivirus information."""

    command = """
    $ErrorActionPreference = 'Stop'

    Get-MpComputerStatus -ErrorAction Stop |
    Select-Object AMServiceEnabled,
                  AntivirusEnabled,
                  RealTimeProtectionEnabled,
                  AntivirusSignatureAge,
                  AntivirusSignatureLastUpdated |
    ConvertTo-Json -Compress
    """

    result = run_security_query(command)

    if not isinstance(result, dict):
        return {
            "Status": "Unknown",
            "Reason": "Unexpected Defender response.",
        }

    if result.get("Status") in ("Unknown", "Access Denied"):
        return result

    if result.get("AntivirusEnabled") is None:
        return {
            "Status": "Unknown",
            "Reason": "Defender returned incomplete information.",
        }

    result["Status"] = "Collected"

    return result


def get_firewall():
    """Collect Windows Firewall profile information."""

    command = """
    $ErrorActionPreference = 'Stop'

    @(
        Get-NetFirewallProfile -ErrorAction Stop |
        Select-Object Name,
                      Enabled,
                      DefaultInboundAction,
                      DefaultOutboundAction
    ) | ConvertTo-Json -Compress
    """

    result = run_security_query(command)

    if isinstance(result, dict):
        if result.get("Status") in ("Unknown", "Access Denied"):
            return result

        profiles = [result]

    elif isinstance(result, list):
        profiles = result

    else:
        return {
            "Status": "Unknown",
            "Reason": "Unexpected Firewall response.",
        }

    if not profiles:
        return {
            "Status": "Unknown",
            "Reason": "No firewall profiles were returned.",
        }

    if any(
        not isinstance(profile, dict)
        or profile.get("Name") is None
        or profile.get("Enabled") is None
        for profile in profiles
    ):
        return {
            "Status": "Unknown",
            "Reason": "Firewall returned incomplete profile information.",
        }

    return {
        "Status": "Collected",
        "Profiles": profiles,
    }


def get_tpm():
    """Collect TPM information when permitted."""

    if not is_administrator():
        return {
            "Status": "Access Denied",
            "Reason": (
                "Administrator privileges are required "
                "to query TPM information."
            ),
            "TpmPresent": None,
            "TpmReady": None,
            "TpmEnabled": None,
            "TpmActivated": None,
            "ManufacturerVersion": None,
        }

    command = """
    $ErrorActionPreference = 'Stop'

    Get-Tpm -ErrorAction Stop |
    Select-Object TpmPresent,
                  TpmReady,
                  TpmEnabled,
                  TpmActivated,
                  ManufacturerVersion |
    ConvertTo-Json -Compress
    """

    result = run_security_query(command)

    if not isinstance(result, dict):
        return {
            "Status": "Unknown",
            "Reason": "Unexpected TPM response.",
        }

    if result.get("Status") in ("Unknown", "Access Denied"):
        return result

    if result.get("TpmPresent") is None:
        return {
            "Status": "Unknown",
            "Reason": "TPM query returned no usable information.",
        }

    if result["TpmPresent"] is False:
        result["Status"] = "Not Present"
    else:
        result["Status"] = "Collected"

    return result


def get_secure_boot():
    """Check Secure Boot status without changing firmware settings."""

    command = """
    $ErrorActionPreference = 'Stop'

    $enabled = Confirm-SecureBootUEFI -ErrorAction Stop

    [PSCustomObject]@{
        Status = 'Collected'
        Enabled = [bool]$enabled
    } | ConvertTo-Json -Compress
    """

    result = run_security_query(command)

    if not isinstance(result, dict):
        return {
            "Status": "Unknown",
            "Reason": "Unexpected Secure Boot response.",
        }

    if result.get("Status") in ("Unknown", "Access Denied"):
        return result

    if result.get("Enabled") is None:
        return {
            "Status": "Unknown",
            "Reason": "Secure Boot returned no usable status.",
        }

    return result


def get_bitlocker():
    """Collect BitLocker volume status without modifying encryption."""

    command = """
    $ErrorActionPreference = 'Stop'

    @(
        Get-BitLockerVolume -ErrorAction Stop |
        Select-Object MountPoint,
                      VolumeStatus,
                      ProtectionStatus,
                      EncryptionPercentage
    ) | ConvertTo-Json -Compress
    """

    result = run_security_query(command)

    if isinstance(result, dict):
        if result.get("Status") in ("Unknown", "Access Denied"):
            return result

        volumes = [result]

    elif isinstance(result, list):
        volumes = result

    else:
        return {
            "Status": "Unknown",
            "Reason": "Unexpected BitLocker response.",
        }

    if not volumes:
        return {
            "Status": "Unknown",
            "Reason": "No BitLocker volume information returned.",
        }

    if any(
        not isinstance(volume, dict)
        or volume.get("MountPoint") is None
        or volume.get("VolumeStatus") is None
        for volume in volumes
    ):
        return {
            "Status": "Unknown",
            "Reason": "BitLocker returned incomplete volume information.",
        }

    return {
        "Status": "Collected",
        "Volumes": volumes,
    }


def get_check_status(result):
    """Return an accurate collection status for a security check."""

    if not isinstance(result, dict):
        return "Unknown"

    return result.get("Status", "Unknown")


def main():
    """Run the complete read-only security assessment."""

    if os.name != "nt":
        raise SystemExit(
            "Nanobricks Endpoint360 currently supports Windows only."
        )

    print("=" * 48)
    print(" NANOBRICKS ENDPOINT360")
    print(f" Python Windows Security Assessment v{VERSION}")
    print("=" * 48)

    print()
    print("Collecting read-only Windows security information...")
    print()

    computer_name = socket.gethostname()
    administrator = is_administrator()

    security_results = {
        "Defender": get_defender(),
        "Firewall": get_firewall(),
        "TPM": get_tpm(),
        "SecureBoot": get_secure_boot(),
        "BitLocker": get_bitlocker(),
    }

    report = {
        "Product": "Nanobricks Endpoint360",
        "Module": "Windows Security",
        "Version": VERSION,
        "ComputerName": computer_name,
        "AssessmentTimeUTC": datetime.now(
            timezone.utc
        ).isoformat(),
        "Administrator": administrator,
        "Security": security_results,
    }

    report_directory = (
        Path(__file__).resolve().parent / "reports"
    )

    report_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    timestamp = datetime.now().strftime(
        "%Y%m%d-%H%M%S"
    )

    safe_computer_name = "".join(
        character
        for character in computer_name
        if character.isalnum() or character in "-_"
    ) or "UnknownDevice"

    report_path = report_directory / (
        f"{safe_computer_name}-PythonSecurity-{timestamp}.json"
    )

    report_path.write_text(
        json.dumps(
            report,
            indent=4,
            ensure_ascii=False,
            default=str,
        ),
        encoding="utf-8",
    )

    print("ASSESSMENT SUMMARY")
    print("-" * 48)

    print(f"Computer: {computer_name}")
    print(f"Administrator: {administrator}")

    for check_name, result in security_results.items():
        status = get_check_status(result)

        print(f"{check_name}: {status}")

    print()
    print(f"Report: {report_path}")

    print()
    print("Assessment completed.")
    print("No security settings were modified.")
    print()


if __name__ == "__main__":
    main()
