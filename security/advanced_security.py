
"""
Nanobricks Endpoint360
Advanced Windows Security Collector v0.1.0

Read-only assessment of:
- Local users
- Local administrators
- Password and lockout policy
- User Account Control
- Remote Desktop
- RDP firewall rules

No Windows configuration changes are performed.
"""

import ctypes
import json
import os
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path


VERSION = "0.1.0"
ROOT = Path(__file__).resolve().parent
REPORT_DIR = ROOT / "reports"


POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'

function Invoke-Check {
    param(
        [string]$Name,
        [scriptblock]$Script
    )

    try {
        $data = & $Script

        return @{
            Status = 'Collected'
            Data = $data
            Error = $null
        }
    }
    catch {
        return @{
            Status = 'Not Assessed'
            Data = $null
            Error = $_.Exception.Message
        }
    }
}

$result = @{}

# Local users
$result.LocalUsers = Invoke-Check 'LocalUsers' {
    $users = @(
        Get-LocalUser | ForEach-Object {
            @{
                Name = $_.Name
                Enabled = $_.Enabled
                LastLogon = if ($_.LastLogon) {
                    $_.LastLogon.ToString('o')
                } else {
                    $null
                }
                PasswordRequired = $_.PasswordRequired
                PasswordLastSet = if ($_.PasswordLastSet) {
                    $_.PasswordLastSet.ToString('o')
                } else {
                    $null
                }
                SID = $_.SID.Value
            }
        }
    )

    @{
        Count = $users.Count
        Users = $users
    }
}

# Administrators group identified by its built-in SID.
# This works even if the group has been renamed.
$result.Administrators = Invoke-Check 'Administrators' {
    $group = Get-LocalGroup -SID 'S-1-5-32-544'

    $members = @(
        Get-LocalGroupMember -Group $group.Name |
            ForEach-Object {
                @{
                    Name = $_.Name
                    ObjectClass = $_.ObjectClass
                    PrincipalSource = [string]$_.PrincipalSource
                    SID = if ($_.SID) {
                        $_.SID.Value
                    } else {
                        $null
                    }
                }
            }
    )

    @{
        GroupName = $group.Name
        Count = $members.Count
        Members = $members
    }
}

# Password and lockout policy.
# net accounts is language-dependent; preserve raw evidence.
$result.PasswordPolicy = Invoke-Check 'PasswordPolicy' {
    $output = & net.exe accounts 2>&1

    if ($LASTEXITCODE -ne 0) {
        throw "net accounts returned exit code $LASTEXITCODE"
    }

    @{
        RawOutput = ($output -join "`n")
        Interpretation = 'Raw evidence; policy evaluation pending'
    }
}

# User Account Control registry configuration.
$result.UAC = Invoke-Check 'UAC' {
    $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

    $settings = Get-ItemProperty -Path $path

    @{
        EnableLUA = $settings.EnableLUA
        ConsentPromptBehaviorAdmin = $settings.ConsentPromptBehaviorAdmin
        ConsentPromptBehaviorUser = $settings.ConsentPromptBehaviorUser
        PromptOnSecureDesktop = $settings.PromptOnSecureDesktop
        FilterAdministratorToken = $settings.FilterAdministratorToken
    }
}

# Remote Desktop configuration.
$result.RemoteDesktop = Invoke-Check 'RemoteDesktop' {
    $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'

    $settings = Get-ItemProperty -Path $path

    $rdp = @{
        fDenyTSConnections = $settings.fDenyTSConnections
        ConnectionsAllowed = ($settings.fDenyTSConnections -eq 0)
    }

    $rdpTcp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'

    try {
        $tcpSettings = Get-ItemProperty -Path $rdpTcp

        $rdp.NLARequired = ($tcpSettings.UserAuthentication -eq 1)
        $rdp.NLAValue = $tcpSettings.UserAuthentication
    }
    catch {
        $rdp.NLARequired = $null
        $rdp.NLAValue = $null
    }

    $rdp
}

# Remote Desktop firewall rule visibility.
$result.RDPFirewall = Invoke-Check 'RDPFirewall' {
    $rules = @(
        Get-NetFirewallRule -ErrorAction Stop |
            Where-Object {
                $_.Name -like 'RemoteDesktop-*'
            } |
            ForEach-Object {
                @{
                    Name = $_.Name
                    DisplayName = $_.DisplayName
                    Enabled = [string]$_.Enabled
                    Direction = [string]$_.Direction
                    Action = [string]$_.Action
                    Profile = [string]$_.Profile
                }
            }
    )

    @{
        Count = $rules.Count
        Rules = $rules
    }
}

$result | ConvertTo-Json -Depth 12 -Compress
"""


def is_administrator():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def run_powershell():
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            POWERSHELL_SCRIPT,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
        check=False,
        creationflags=getattr(
            subprocess,
            "CREATE_NO_WINDOW",
            0,
        ),
    )

    if completed.returncode != 0:
        raise RuntimeError(
            completed.stderr.strip()
            or "PowerShell assessment failed."
        )

    output = completed.stdout.strip()

    if not output:
        raise RuntimeError(
            "PowerShell returned no assessment data."
        )

    try:
        data = json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "PowerShell returned invalid JSON."
        ) from exc

    if not isinstance(data, dict):
        raise RuntimeError(
            "Unexpected assessment result structure."
        )

    return data


def main():
    print("=" * 58)
    print(" NANOBRICKS ENDPOINT360")
    print(f" Advanced Security Assessment v{VERSION}")
    print("=" * 58)
    print()
    print("Assessment mode: READ ONLY")
    print("Collecting advanced Windows security information...")
    print()

    computer = socket.gethostname()
    admin = is_administrator()

    try:
        checks = run_powershell()
    except (RuntimeError, subprocess.TimeoutExpired, OSError) as exc:
        print("Assessment could not complete.")
        print(f"Error: {exc}")
        return 1

    expected_checks = [
        "LocalUsers",
        "Administrators",
        "PasswordPolicy",
        "UAC",
        "RemoteDesktop",
        "RDPFirewall",
    ]

    for name in expected_checks:
        if name not in checks:
            checks[name] = {
                "Status": "Not Assessed",
                "Data": None,
                "Error": "Check returned no result.",
            }

    collected = sum(
        checks[name].get("Status") == "Collected"
        for name in expected_checks
    )

    not_assessed = len(expected_checks) - collected

    report = {
        "Product": "Nanobricks Endpoint360",
        "Module": "Advanced Security",
        "Version": VERSION,
        "ComputerName": computer,
        "AssessmentTimeUTC": datetime.now(
            timezone.utc
        ).isoformat(),
        "AssessmentMode": "Read Only",
        "Administrator": admin,
        "Summary": {
            "TotalChecks": len(expected_checks),
            "Collected": collected,
            "NotAssessed": not_assessed,
        },
        "Security": checks,
        "Note": (
            "Collection status is not a compliance verdict. "
            "This report contains local account information "
            "and should be handled as sensitive client data."
        ),
    }

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    timestamp = datetime.now().strftime(
        "%Y%m%d-%H%M%S"
    )

    output_path = REPORT_DIR / (
        f"{computer}-AdvancedSecurity-{timestamp}.json"
    )

    output_path.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8",
    )

    print("ASSESSMENT SUMMARY")
    print("-" * 58)
    print(f"Computer: {computer}")
    print(f"Administrator: {admin}")
    print()

    for name in expected_checks:
        check = checks[name]
        status = check.get("Status", "Not Assessed")
        print(f"{name}: {status}")

        if status != "Collected" and check.get("Error"):
            print(f"  Reason: {check['Error']}")

    print()
    print(f"Checks collected: {collected}/{len(expected_checks)}")
    print(f"Not assessed: {not_assessed}")
    print()
    print(f"Report: {output_path}")
    print()
    print("No Windows settings were modified.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
