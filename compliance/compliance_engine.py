
"""
Nanobricks Endpoint360
Security Compliance Engine v0.2.0

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


VERSION = "0.2.0"

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


# ============================================================
# Endpoint360 Compliance Engine v0.2.0
# Unified assessment evaluation
# ============================================================

UNIFIED_REPORTS = ROOT / "reports"

REQUIRED_MODULES = (
    "Windows Security",
    "Advanced Security",
    "Device Health",
    "Network Security",
)

SEVERITY = {
    "Microsoft Defender": "Critical",
    "Defender Signatures": "Medium",
    "Windows Firewall": "High",
    "TPM": "High",
    "Secure Boot": "High",
    "BitLocker": "High",
    "User Account Control": "High",
    "Remote Desktop": "High",
    "Guest Account": "Medium",
    "Built-in Administrator": "Medium",
    "Local Password Policy": "High",
    "SMBv1": "Critical",
    "SMB Signing": "Medium",
    "Physical Disk Health": "High",
    "Disk Free Space": "Medium",
    "Pending Restart": "Medium",
    "Listening Services": "Medium",
}


def verdict(control, status, evidence, recommendation):
    item = result(control, status, evidence, recommendation)
    item["Severity"] = SEVERITY.get(control, "Medium")
    return item


def unknown(control, reason):
    return verdict(
        control,
        "Not Assessed",
        reason,
        "Collect and verify the required evidence.",
    )


def section(report, name):
    modules = report.get("Modules", {})
    module = modules.get(name, {})

    if not isinstance(module, dict):
        return {}

    if module.get("Status") != "Completed":
        return {}

    data = module.get("Data")

    if not isinstance(data, dict):
        return {}

    if data.get("Module") != name:
        return {}

    if data.get("ComputerName") != report.get("ComputerName"):
        return {}

    return data


def evidence_item(container, name):
    item = container.get(name, {})

    if not isinstance(item, dict):
        return None

    if item.get("Status") != "Collected":
        return None

    data = item.get("Data")

    return data if isinstance(data, dict) else None


def evaluate_advanced(report):
    checks = []
    security = report.get("Security", {})

    uac = evidence_item(security, "UAC")

    if uac is None or type(uac.get("EnableLUA")) is not int:
        checks.append(unknown("User Account Control", "UAC evidence unavailable."))
    elif uac["EnableLUA"] == 0:
        checks.append(verdict(
            "User Account Control", "Fail",
            "UAC is disabled.",
            "Review UAC settings against the approved baseline.",
        ))
    elif uac["EnableLUA"] == 1:
        secure = uac.get("PromptOnSecureDesktop")
        checks.append(verdict(
            "User Account Control",
            "Pass" if secure == 1 else "Warning",
            f"UAC enabled; secure desktop setting: {secure}.",
            "Maintain UAC and review secure desktop configuration.",
        ))
    else:
        checks.append(unknown("User Account Control", "Unknown UAC setting."))

    rdp = evidence_item(security, "RemoteDesktop")

    if rdp is None or type(rdp.get("ConnectionsAllowed")) is not bool:
        checks.append(unknown("Remote Desktop", "RDP evidence unavailable."))
    elif rdp["ConnectionsAllowed"] is False:
        checks.append(verdict(
            "Remote Desktop", "Pass",
            "Remote Desktop connections are disabled.",
            "Keep RDP disabled unless business requirements justify access.",
        ))
    else:
        checks.append(verdict(
            "Remote Desktop", "Warning",
            f"RDP enabled; NLA required: {rdp.get('NLARequired')}.",
            "Restrict RDP to approved users and trusted networks.",
        ))

    users = evidence_item(security, "LocalUsers")

    for control, account in (
        ("Guest Account", "Guest"),
        ("Built-in Administrator", "Administrator"),
    ):
        if users is None or not isinstance(users.get("Users"), list):
            checks.append(unknown(control, "Local account inventory unavailable."))
            continue

        matching = [
            u for u in users["Users"]
            if isinstance(u, dict) and u.get("Name") == account
        ]

        if len(matching) != 1 or type(matching[0].get("Enabled")) is not bool:
            checks.append(unknown(control, "Account state could not be verified."))
        else:
            enabled = matching[0]["Enabled"]
            checks.append(verdict(
                control,
                "Warning" if enabled else "Pass",
                f"Built-in {account} account enabled: {enabled}.",
                "Keep built-in accounts disabled unless explicitly required.",
            ))

    policy = evidence_item(security, "PasswordPolicy")

    if policy is None:
        checks.append(unknown("Local Password Policy", "Policy evidence unavailable."))
    else:
        import re

        raw = policy.get("RawOutput", "")
        match = re.search(
            r"Minimum password length:\s*(\d+)",
            raw,
            re.IGNORECASE,
        )

        if not match:
            checks.append(unknown(
                "Local Password Policy",
                "Minimum password length could not be parsed.",
            ))
        else:
            length = int(match.group(1))
            checks.append(verdict(
                "Local Password Policy",
                "Warning" if length < 12 else "Pass",
                f"Local minimum password length: {length}. "
                "This does not establish Microsoft-account password policy.",
                "Review the approved local password baseline and "
                "applicable account authentication policies.",
            ))

    return checks


def evaluate_health(report):
    checks = []
    health = report.get("Health", {})

    restart = evidence_item(health, "PendingRestart")

    if restart is None or type(restart.get("Required")) is not bool:
        checks.append(unknown("Pending Restart", "Restart evidence unavailable."))
    else:
        required = restart["Required"]
        checks.append(verdict(
            "Pending Restart",
            "Warning" if required else "Pass",
            f"Restart required: {required}. "
            f"Indicators: {restart.get('Indicators', [])}.",
            "Schedule a restart after verifying operational requirements.",
        ))

    storage = evidence_item(health, "Storage")

    if storage is None or not isinstance(storage.get("Drives"), list) \
            or not storage["Drives"]:
        checks.append(unknown("Disk Free Space", "Storage evidence unavailable."))
    else:
        drives = storage["Drives"]
        percentages = []

        for drive in drives:
            if not isinstance(drive, dict):
                continue
            value = drive.get("FreePercentage")
            if type(value) in (int, float) and 0 <= value <= 100:
                percentages.append((drive.get("Drive", "?"), value))

        if len(percentages) != len(drives):
            checks.append(unknown("Disk Free Space", "Incomplete drive evidence."))
        else:
            low = [(name, value) for name, value in percentages if value < 15]
            checks.append(verdict(
                "Disk Free Space",
                "Warning" if low else "Pass",
                "Free space: " + ", ".join(
                    f"{name} {value:.1f}%" for name, value in percentages
                ),
                "Maintain at least 15% free space on assessed volumes.",
            ))

    disks = evidence_item(health, "PhysicalDisks")

    if disks is None or not isinstance(disks.get("Disks"), list) \
            or not disks["Disks"]:
        checks.append(unknown("Physical Disk Health", "Disk health unavailable."))
    else:
        entries = disks["Disks"]
        statuses = [
            str(d.get("HealthStatus", "")).lower()
            for d in entries if isinstance(d, dict)
        ]

        if len(statuses) != len(entries) or any(
            status in ("", "unknown") for status in statuses
        ):
            checks.append(unknown(
                "Physical Disk Health",
                "Incomplete Windows disk health evidence.",
            ))
        else:
            unhealthy = [s for s in statuses if s != "healthy"]
            checks.append(verdict(
                "Physical Disk Health",
                "Warning" if unhealthy else "Pass",
                "Windows-reported disk health: " + ", ".join(statuses)
                + ". Not a full SMART diagnostic.",
                "Investigate unhealthy disks and maintain verified backups.",
            ))

    return checks


def evaluate_network(report):
    checks = []
    network = report.get("Network", {})

    smb = evidence_item(network, "SMBConfiguration")

    if smb is None or type(smb.get("SMB1Enabled")) is not bool:
        checks.append(unknown("SMBv1", "SMBv1 evidence unavailable."))
    else:
        enabled = smb["SMB1Enabled"]
        checks.append(verdict(
            "SMBv1",
            "Fail" if enabled else "Pass",
            f"SMBv1 enabled: {enabled}.",
            "Disable SMBv1 after reviewing compatibility requirements.",
        ))

    if smb is None or type(smb.get("RequireSecuritySignature")) is not bool:
        checks.append(unknown("SMB Signing", "SMB signing evidence unavailable."))
    else:
        required = smb["RequireSecuritySignature"]
        checks.append(verdict(
            "SMB Signing",
            "Pass" if required else "Warning",
            f"SMB server signing required: {required}.",
            "Review SMB signing requirements and client compatibility.",
        ))

    ports = evidence_item(network, "ListeningPorts")

    if ports is None or not isinstance(ports.get("Connections"), list):
        checks.append(unknown(
            "Listening Services",
            "Listening socket evidence unavailable.",
        ))
    else:
        connections = ports["Connections"]
        sensitive = []

        for entry in connections:
            if not isinstance(entry, dict):
                continue

            address = entry.get("LocalAddress")
            port = entry.get("LocalPort")

            if address in ("0.0.0.0", "::") and port in (80, 135, 139, 445, 3389):
                sensitive.append(f"{address}:{port}")

        checks.append(verdict(
            "Listening Services",
            "Warning" if sensitive else "Pass",
            "Potentially sensitive wildcard listeners: "
            + (", ".join(sorted(set(sensitive))) if sensitive else "None observed")
            + ". Local listening does not prove external reachability.",
            "Verify service ownership, firewall restrictions and exposure.",
        ))

    return checks


def load_unified_report():
    files = sorted(
        UNIFIED_REPORTS.glob("*-Endpoint360-*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    if not files:
        raise FileNotFoundError("No unified Endpoint360 report found.")

    path = files[0]

    with path.open("r", encoding="utf-8") as stream:
        report = json.load(stream)

    if not isinstance(report, dict):
        raise ValueError("Invalid unified report.")

    if report.get("Product") != "Nanobricks Endpoint360":
        raise ValueError("Unexpected report product.")

    if not report.get("ComputerName"):
        raise ValueError("Computer name missing.")

    if not isinstance(report.get("Modules"), dict):
        raise ValueError("Module evidence missing.")

    return path, report


def main():
    source_path, source = load_unified_report()

    checks = []

    security_report = section(source, "Windows Security")
    security = security_report.get("Security", {})

    if not isinstance(security, dict):
        security = {}

    checks.extend(evaluate_defender(security.get("Defender") or {}))
    checks.append(evaluate_firewall(security.get("Firewall") or {}))
    checks.append(evaluate_tpm(security.get("TPM") or {}))
    checks.append(evaluate_secure_boot(security.get("SecureBoot") or {}))
    checks.append(evaluate_bitlocker(security.get("BitLocker") or {}))

    advanced = section(source, "Advanced Security")
    health = section(source, "Device Health")
    network = section(source, "Network Security")

    checks.extend(evaluate_advanced(advanced))
    checks.extend(evaluate_health(health))
    checks.extend(evaluate_network(network))

    for check in checks:
        check["Severity"] = SEVERITY.get(check["Control"], "Medium")

    summary = {
        "Total": len(checks),
        "Pass": sum(c["Result"] == "Pass" for c in checks),
        "Fail": sum(c["Result"] == "Fail" for c in checks),
        "Warning": sum(c["Result"] == "Warning" for c in checks),
        "NotAssessed": sum(c["Result"] == "Not Assessed" for c in checks),
    }

    evaluated = summary["Total"] - summary["NotAssessed"]

    score = round(100 * summary["Pass"] / evaluated, 1) if evaluated else None

    summary["Evaluated"] = evaluated
    summary["ComplianceScore"] = score
    summary["ScoreMethod"] = (
        "Pass / (Pass + Fail + Warning) * 100; "
        "Not Assessed excluded. All evaluated controls weighted equally."
    )

    report = {
        "Product": "Nanobricks Endpoint360",
        "Module": "Security Compliance",
        "Version": VERSION,
        "ComputerName": source["ComputerName"],
        "AssessmentTimeUTC": datetime.now(timezone.utc).isoformat(),
        "AssessmentMode": "Read Only",
        "Baseline": "Nanobricks Endpoint Security Baseline v0.2",
        "SourceReport": str(source_path),
        "Summary": summary,
        "Checks": checks,
        "Disclaimer": (
            "Configurable baseline assessment only. "
            "Not a regulatory compliance certification. "
            "Some findings require contextual validation."
        ),
    }

    COMPLIANCE_REPORTS.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output = COMPLIANCE_REPORTS / (
        f"{source['ComputerName']}-Compliance-{timestamp}.json"
    )

    output.write_text(json.dumps(report, indent=4), encoding="utf-8")

    print("=" * 60)
    print(" NANOBRICKS ENDPOINT360")
    print(f" Security Compliance Engine v{VERSION}")
    print("=" * 60)

    for check in checks:
        print(f"{check['Control']}: {check['Result']}")

    print("-" * 60)

    for key, value in summary.items():
        print(f"{key}: {value}")

    print(f"\nReport: {output}")
    print("No Windows settings were modified.")


if __name__ == "__main__":
    main()
