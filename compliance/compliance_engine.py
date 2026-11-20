
"""
Nanobricks Endpoint360
Security Compliance Engine v0.1.0

Evaluates existing Windows Security assessment evidence.

Read-only:
- No Windows configuration changes
- No remediation
- No installations
- No automatic restarts

Results:
- Pass
- Fail
- Warning
- Not Assessed

This is a configurable baseline assessment, not a
formal regulatory compliance certification.
"""

import json
import socket
from datetime import datetime, timezone
from pathlib import Path


VERSION = "0.1.0"

ROOT = Path(__file__).resolve().parent.parent

SECURITY_REPORTS = ROOT / "security" / "reports"
COMPLIANCE_REPORTS = ROOT / "compliance" / "reports"

SIGNATURE_MAX_AGE_DAYS = 7


def result(control, status, evidence, recommendation):
    return {
        "Control": control,
        "Result": status,
        "Evidence": evidence,
        "Recommendation": recommendation,
    }


def not_assessed(control, reason):
    return result(
        control,
        "Not Assessed",
        reason,
        "Collect and verify the required security evidence.",
    )


def collected(data):
    return (
        isinstance(data, dict)
        and data.get("Status") == "Collected"
    )


def evaluate_defender(data):
    checks = []

    if not collected(data):
        reason = data.get("Reason", "Evidence unavailable")
        return [
            not_assessed("Microsoft Defender", reason),
            not_assessed("Defender Signatures", reason),
        ]

    service = data.get("AMServiceEnabled")
    antivirus = data.get("AntivirusEnabled")
    realtime = data.get("RealTimeProtectionEnabled")

    values = (service, antivirus, realtime)

    if any(value is False for value in values):
        checks.append(
            result(
                "Microsoft Defender",
                "Fail",
                "One or more Defender protection components are disabled.",
                "Review antivirus service and real-time protection.",
            )
        )
    elif all(value is True for value in values):
        checks.append(
            result(
                "Microsoft Defender",
                "Pass",
                "Antivirus service and real-time protection are enabled.",
                "Maintain active endpoint protection.",
            )
        )
    else:
        checks.append(
            not_assessed(
                "Microsoft Defender",
                "Defender returned incomplete protection evidence.",
            )
        )

    age = data.get("AntivirusSignatureAge")

    if isinstance(age, bool) or age is None:
        checks.append(
            not_assessed(
                "Defender Signatures",
                "Antivirus signature age was not available.",
            )
        )
    else:
        try:
            age = int(age)

            if age < 0:
                raise ValueError("Invalid signature age")

            if age <= SIGNATURE_MAX_AGE_DAYS:
                checks.append(
                    result(
                        "Defender Signatures",
                        "Pass",
                        f"Antivirus signatures are {age} day(s) old.",
                        "Continue regular signature updates.",
                    )
                )
            else:
                checks.append(
                    result(
                        "Defender Signatures",
                        "Warning",
                        f"Antivirus signatures are {age} day(s) old.",
                        "Review Defender signature update health.",
                    )
                )
        except (TypeError, ValueError):
            checks.append(
                not_assessed(
                    "Defender Signatures",
                    "Signature age could not be interpreted.",
                )
            )

    return checks


def evaluate_firewall(data):
    control = "Windows Firewall"

    if not collected(data):
        return not_assessed(
            control,
            data.get("Reason", "Firewall evidence unavailable"),
        )

    profiles = data.get("Profiles")

    if not isinstance(profiles, list) or not profiles:
        return not_assessed(
            control,
            "No usable firewall profiles were returned.",
        )

    expected = {"domain", "private", "public"}
    observed = {}

    for profile in profiles:
        if not isinstance(profile, dict):
            return not_assessed(
                control,
                "Invalid firewall profile evidence.",
            )

        name = str(profile.get("Name", "")).lower()

        if name not in expected or name in observed:
            return not_assessed(
                control,
                "Firewall profile evidence is incomplete or duplicated.",
            )

        enabled = profile.get("Enabled")

        if enabled is True or enabled == 1:
            observed[name] = True
        elif enabled is False or enabled == 0:
            observed[name] = False
        else:
            return not_assessed(
                control,
                f"Unknown enabled state for {name} profile.",
            )

    if set(observed) != expected:
        return not_assessed(
            control,
            "Domain, Private and Public profiles were not all returned.",
        )

    disabled = [
        name.title()
        for name, enabled in observed.items()
        if not enabled
    ]

    if disabled:
        return result(
            control,
            "Fail",
            "Disabled firewall profiles: " + ", ".join(disabled),
            "Review firewall configuration against the approved baseline.",
        )

    return result(
        control,
        "Pass",
        "Domain, Private and Public firewall profiles are enabled.",
        "Maintain firewall protection across all profiles.",
    )


def evaluate_tpm(data):
    control = "TPM"

    if not collected(data) and data.get("Status") != "Not Present":
        return not_assessed(
            control,
            data.get("Reason", "TPM evidence unavailable"),
        )

    if data.get("TpmPresent") is False:
        return result(
            control,
            "Fail",
            "TPM was reported as not present.",
            "Verify device hardware and TPM baseline requirements.",
        )

    if data.get("TpmPresent") is not True:
        return not_assessed(control, "TPM presence is unknown.")

    ready = data.get("TpmReady")
    enabled = data.get("TpmEnabled")
    activated = data.get("TpmActivated")

    if any(value is False for value in (ready, enabled, activated)):
        return result(
            control,
            "Warning",
            "TPM is present but not fully ready, enabled or activated.",
            "Review TPM configuration with authorized IT personnel.",
        )

    if all(value is True for value in (ready, enabled, activated)):
        return result(
            control,
            "Pass",
            "TPM is present, ready, enabled and activated.",
            "Maintain TPM configuration.",
        )

    return not_assessed(
        control,
        "TPM readiness evidence is incomplete.",
    )


def evaluate_secure_boot(data):
    control = "Secure Boot"

    if not collected(data):
        return not_assessed(
            control,
            data.get("Reason", "Secure Boot evidence unavailable"),
        )

    enabled = data.get("Enabled")

    if enabled is True:
        return result(
            control,
            "Pass",
            "Secure Boot is enabled.",
            "Maintain Secure Boot configuration.",
        )

    if enabled is False:
        return result(
            control,
            "Fail",
            "Secure Boot is disabled.",
            "Review firmware security requirements.",
        )

    return not_assessed(
        control,
        "Secure Boot enabled state is unknown.",
    )


def evaluate_bitlocker(data):
    control = "BitLocker"

    if not collected(data):
        return not_assessed(
            control,
            data.get("Reason", "Drive encryption evidence unavailable"),
        )

    volumes = data.get("Volumes")

    if not isinstance(volumes, list) or not volumes:
        return not_assessed(
            control,
            "No BitLocker volume evidence available.",
        )

    system_drive = next(
        (
            volume
            for volume in volumes
            if isinstance(volume, dict)
            and str(volume.get("MountPoint", "")).upper() == "C:"
        ),
        None,
    )

    if system_drive is None:
        return not_assessed(
            control,
            "System drive C: was not found in encryption evidence.",
        )

    status = str(system_drive.get("VolumeStatus", "")).lower()
    protection = str(
        system_drive.get("ProtectionStatus", "")
    ).lower()

    percentage = system_drive.get("EncryptionPercentage")

    try:
        percentage = float(percentage)
    except (TypeError, ValueError):
        percentage = None

    if (
        status == "fullyencrypted"
        and protection in ("on", "1")
        and percentage == 100
    ):
        return result(
            control,
            "Pass",
            "System drive C: is fully encrypted and protection is on.",
            "Maintain approved drive encryption.",
        )

    if status == "fullydecrypted" or protection in ("off", "0"):
        return result(
            control,
            "Fail",
            "System drive C: is decrypted or encryption protection is off.",
            "Review system drive encryption requirements.",
        )

    if status in ("encryptioninprogress", "decryptioninprogress"):
        return result(
            control,
            "Warning",
            "System drive encryption transition is in progress.",
            "Verify encryption completes successfully.",
        )

    return not_assessed(
        control,
        "System drive encryption evidence is incomplete or unsupported.",
    )


def load_latest_security_report():
    if not SECURITY_REPORTS.exists():
        raise FileNotFoundError(
            "Security reports directory does not exist."
        )

    files = sorted(
        SECURITY_REPORTS.glob("*-PythonSecurity-*.json"),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )

    if not files:
        raise FileNotFoundError(
            "No Windows Security assessment report was found."
        )

    # Select the newest valid JSON report.
    for path in files:
        try:
            with path.open("r", encoding="utf-8") as file:
                report = json.load(file)

            if (
                isinstance(report, dict)
                and report.get("Module") == "Windows Security"
                and isinstance(report.get("Security"), dict)
            ):
                return path, report

        except (OSError, ValueError):
            continue

    raise ValueError("No valid Windows Security report was found.")


def main():
    source_path, source = load_latest_security_report()

    security = source["Security"]

    checks = []
    checks.extend(
        evaluate_defender(security.get("Defender") or {})
    )

    checks.append(
        evaluate_firewall(security.get("Firewall") or {})
    )

    checks.append(
        evaluate_tpm(security.get("TPM") or {})
    )

    checks.append(
        evaluate_secure_boot(security.get("SecureBoot") or {})
    )

    checks.append(
        evaluate_bitlocker(security.get("BitLocker") or {})
    )

    summary = {
        "Total": len(checks),
        "Pass": sum(c["Result"] == "Pass" for c in checks),
        "Fail": sum(c["Result"] == "Fail" for c in checks),
        "Warning": sum(c["Result"] == "Warning" for c in checks),
        "NotAssessed": sum(
            c["Result"] == "Not Assessed" for c in checks
        ),
    }

    report = {
        "Product": "Nanobricks Endpoint360",
        "Module": "Security Compliance",
        "Version": VERSION,
        "ComputerName": source.get(
            "ComputerName",
            socket.gethostname(),
        ),
        "AssessmentTimeUTC": datetime.now(
            timezone.utc
        ).isoformat(),
        "AssessmentMode": "Read Only",
        "Baseline": "Nanobricks Endpoint Security Baseline v0.1",
        "SourceReport": str(source_path),
        "Summary": summary,
        "Checks": checks,
        "Disclaimer": (
            "Baseline assessment only. Not a regulatory "
            "compliance certification."
        ),
    }

    COMPLIANCE_REPORTS.mkdir(
        parents=True,
        exist_ok=True,
    )

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    output_path = COMPLIANCE_REPORTS / (
        f"{report['ComputerName']}-Compliance-{timestamp}.json"
    )

    output_path.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8",
    )

    print("=" * 55)
    print(" NANOBRICKS ENDPOINT360")
    print(" Security Compliance Engine v" + VERSION)
    print("=" * 55)

    print()
    print("Baseline: Nanobricks Endpoint Security Baseline v0.1")
    print("Mode: READ ONLY")
    print()

    for check in checks:
        print(f"{check['Control']}: {check['Result']}")

    print()
    print("SUMMARY")
    print("-" * 55)

    for name, value in summary.items():
        print(f"{name}: {value}")

    print()
    print(f"Source: {source_path}")
    print(f"Report: {output_path}")
    print()
    print("No Windows settings were modified.")


if __name__ == "__main__":
    main()
