
"""
Nanobricks Endpoint360
Network Security Collector v0.1.0

Read-only Windows network assessment.
"""

import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

VERSION = "0.1.0"
BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"

POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'

function Invoke-NetworkCheck {
    param([scriptblock]$Script)

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

$result.NetworkAdapters = Invoke-NetworkCheck {
    $adapters = @(
        Get-NetAdapter -ErrorAction Stop |
        ForEach-Object {
            @{
                Name = $_.Name
                Description = $_.InterfaceDescription
                Status = [string]$_.Status
                MacAddress = $_.MacAddress
                LinkSpeed = [string]$_.LinkSpeed
                InterfaceIndex = $_.ifIndex
            }
        }
    )

    @{
        Count = $adapters.Count
        Adapters = $adapters
    }
}

$result.IPConfiguration = Invoke-NetworkCheck {
    $interfaces = @(
        Get-NetIPConfiguration -ErrorAction Stop |
        ForEach-Object {
            @{
                InterfaceAlias = $_.InterfaceAlias
                InterfaceIndex = $_.InterfaceIndex
                IPv4 = @(
                    $_.IPv4Address |
                    ForEach-Object { $_.IPAddress }
                )
                IPv6 = @(
                    $_.IPv6Address |
                    ForEach-Object { $_.IPAddress }
                )
                IPv4Gateway = @(
                    $_.IPv4DefaultGateway |
                    ForEach-Object { $_.NextHop }
                )
                DNSServers = @(
                    $_.DNSServer.ServerAddresses
                )
            }
        }
    )

    @{
        Count = $interfaces.Count
        Interfaces = $interfaces
    }
}

$result.NetworkProfiles = Invoke-NetworkCheck {
    $profiles = @(
        Get-NetConnectionProfile -ErrorAction Stop |
        ForEach-Object {
            @{
                Name = $_.Name
                InterfaceAlias = $_.InterfaceAlias
                NetworkCategory = [string]$_.NetworkCategory
                IPv4Connectivity = [string]$_.IPv4Connectivity
                IPv6Connectivity = [string]$_.IPv6Connectivity
            }
        }
    )

    @{
        Count = $profiles.Count
        Profiles = $profiles
    }
}

$result.FirewallProfiles = Invoke-NetworkCheck {
    $profiles = @(
        Get-NetFirewallProfile -ErrorAction Stop |
        ForEach-Object {
            @{
                Name = $_.Name
                Enabled = $_.Enabled
                DefaultInboundAction = [string]$_.DefaultInboundAction
                DefaultOutboundAction = [string]$_.DefaultOutboundAction
            }
        }
    )

    @{
        Count = $profiles.Count
        Profiles = $profiles
    }
}

$result.ListeningPorts = Invoke-NetworkCheck {
    $ports = @(
        Get-NetTCPConnection -State Listen -ErrorAction Stop |
        ForEach-Object {
            @{
                LocalAddress = $_.LocalAddress
                LocalPort = $_.LocalPort
                OwningProcess = $_.OwningProcess
            }
        }
    )

    @{
        Count = $ports.Count
        Connections = $ports
        Note = 'Listening sockets only; not proof of external reachability'
    }
}

$result.SMBConfiguration = Invoke-NetworkCheck {
    $service = Get-Service LanmanServer -ErrorAction Stop
    $configuration = Get-SmbServerConfiguration -ErrorAction Stop

    @{
        ServiceStatus = [string]$service.Status
        SMB1Enabled = [bool]$configuration.EnableSMB1Protocol
        SMB2Enabled = [bool]$configuration.EnableSMB2Protocol
        RequireSecuritySignature = [bool]$configuration.RequireSecuritySignature
        EnableSecuritySignature = [bool]$configuration.EnableSecuritySignature
    }
}

$result.ProxyConfiguration = Invoke-NetworkCheck {
    $proxy = Get-ItemProperty `
        -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' `
        -ErrorAction Stop

    @{
        UserProxyEnabled = [bool]$proxy.ProxyEnable
        UserProxyServer = $proxy.ProxyServer
        AutoConfigURL = $proxy.AutoConfigURL
        Note = 'Current-user proxy settings; not WinHTTP configuration'
    }
}

$result | ConvertTo-Json -Depth 14 -Compress
"""


def main():
    print("=" * 60)
    print(" NANOBRICKS ENDPOINT360")
    print(f" Network Security Collector v{VERSION}")
    print("=" * 60)

    print("\nAssessment mode: READ ONLY")
    print("Collecting Windows network security information...\n")

    try:
        process = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                POWERSHELL_SCRIPT,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8-sig",
            errors="replace",
            timeout=180,
            check=False,
        )

        if process.returncode != 0:
            raise RuntimeError(
                process.stderr.strip()
                or f"PowerShell exited with code {process.returncode}"
            )

        checks = json.loads(process.stdout.strip())

        if not isinstance(checks, dict):
            raise ValueError("Unexpected PowerShell JSON structure")

    except (
        subprocess.TimeoutExpired,
        OSError,
        RuntimeError,
        ValueError,
    ) as error:
        print(f"ERROR: Network assessment failed: {error}")
        return 1

    expected_checks = [
        "NetworkAdapters",
        "IPConfiguration",
        "NetworkProfiles",
        "FirewallProfiles",
        "ListeningPorts",
        "SMBConfiguration",
        "ProxyConfiguration",
    ]

    for name in expected_checks:
        if not isinstance(checks.get(name), dict):
            checks[name] = {
                "Status": "Not Assessed",
                "Data": None,
                "Error": "Check did not return a valid result",
            }

    collected = sum(
        checks[name].get("Status") == "Collected"
        for name in expected_checks
    )

    not_assessed = len(expected_checks) - collected

    report = {
        "Product": "Nanobricks Endpoint360",
        "Module": "Network Security",
        "Version": VERSION,
        "ComputerName": platform.node(),
        "AssessmentTimeUTC": datetime.now(
            timezone.utc
        ).isoformat(),
        "AssessmentMode": "Read Only",
        "Summary": {
            "TotalChecks": len(expected_checks),
            "Collected": collected,
            "NotAssessed": not_assessed,
            "Status": (
                "Completed"
                if not_assessed == 0
                else "Partial"
                if collected > 0
                else "Not Assessed"
            ),
        },
        "Network": checks,
    }

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    report_path = REPORT_DIR / (
        f"{platform.node()}-NetworkSecurity-{timestamp}.json"
    )

    try:
        report_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except OSError as error:
        print(f"ERROR: Could not save report: {error}")
        return 1

    print("ASSESSMENT SUMMARY")
    print("-" * 60)

    for name in expected_checks:
        check = checks[name]
        status = check.get("Status", "Not Assessed")

        print(f"{name}: {status}")

        if status != "Collected" and check.get("Error"):
            print(f"  Reason: {check['Error']}")

    print("-" * 60)
    print(f"Computer: {report['ComputerName']}")
    print(f"Checks Collected: {collected}/{len(expected_checks)}")
    print(f"Not Assessed: {not_assessed}")
    print(f"Overall Collection Status: {report['Summary']['Status']}")
    print(f"\nReport: {report_path}")
    print("\nNo Windows network settings were modified.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
