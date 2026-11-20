
"""
Nanobricks Endpoint360
Device Health Collector v0.1.1

Read-only Windows device health assessment.
No remediation or configuration changes.
"""

import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

VERSION = "0.1.1"
BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"

POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'

function Invoke-HealthCheck {
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

$result.SystemUptime = Invoke-HealthCheck {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $boot = $os.LastBootUpTime

    if ($null -eq $boot) {
        throw 'Last boot time unavailable'
    }

    @{
        LastBootTime = $boot.ToString('o')
        UptimeHours = [math]::Round(
            ((Get-Date) - $boot).TotalHours, 2
        )
    }
}

$result.CPU = Invoke-HealthCheck {
    $cpus = @(
        Get-CimInstance Win32_Processor -ErrorAction Stop
    )

    if ($cpus.Count -eq 0) {
        throw 'No processor information returned'
    }

    @{
        Processor = ($cpus.Name -join ', ')
        LogicalProcessors = (
            $cpus |
            Measure-Object -Property NumberOfLogicalProcessors -Sum
        ).Sum
        LoadPercentage = @(
            $cpus | ForEach-Object {
                $_.LoadPercentage
            }
        )
    }
}

$result.Memory = Invoke-HealthCheck {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop

    $total = [double]$os.TotalVisibleMemorySize
    $free = [double]$os.FreePhysicalMemory

    if ($total -le 0) {
        throw 'Total physical memory unavailable'
    }

    @{
        TotalGB = [math]::Round($total / 1MB, 2)
        AvailableGB = [math]::Round($free / 1MB, 2)
        UsedGB = [math]::Round(($total - $free) / 1MB, 2)
        UsedPercentage = [math]::Round(
            (($total - $free) / $total) * 100, 2
        )
    }
}

$result.Storage = Invoke-HealthCheck {
    $drives = @(
        Get-CimInstance Win32_LogicalDisk `
            -Filter 'DriveType=3' `
            -ErrorAction Stop |
        ForEach-Object {
            $size = [double]$_.Size
            $free = [double]$_.FreeSpace

            @{
                Drive = $_.DeviceID
                TotalGB = [math]::Round($size / 1GB, 2)
                FreeGB = [math]::Round($free / 1GB, 2)
                UsedGB = [math]::Round(
                    ($size - $free) / 1GB, 2
                )
                FreePercentage = if ($size -gt 0) {
                    [math]::Round(
                        ($free / $size) * 100, 2
                    )
                } else {
                    $null
                }
                LowSpace = if ($size -gt 0) {
                    ($free / $size) -lt 0.10
                } else {
                    $null
                }
            }
        }
    )

    @{
        Count = $drives.Count
        Drives = $drives
    }
}

$result.PhysicalDisks = Invoke-HealthCheck {
    $disks = @(
        Get-PhysicalDisk -ErrorAction Stop |
        ForEach-Object {
            @{
                FriendlyName = $_.FriendlyName
                MediaType = [string]$_.MediaType
                HealthStatus = [string]$_.HealthStatus
                OperationalStatus = (
                    $_.OperationalStatus -join ', '
                )
                SizeGB = [math]::Round(
                    [double]$_.Size / 1GB, 2
                )
            }
        }
    )

    @{
        Count = $disks.Count
        Disks = $disks
        Note = 'Windows-reported health, not full SMART diagnostics'
    }
}

$result.Battery = Invoke-HealthCheck {
    $batteries = @(
        Get-CimInstance Win32_Battery -ErrorAction Stop |
        ForEach-Object {
            @{
                Name = $_.Name
                EstimatedChargeRemaining = (
                    $_.EstimatedChargeRemaining
                )
                BatteryStatus = $_.BatteryStatus
                EstimatedRunTime = $_.EstimatedRunTime
            }
        }
    )

    @{
        Count = $batteries.Count
        Batteries = $batteries
        Note = if ($batteries.Count -eq 0) {
            'No battery detected or reported'
        } else {
            'Windows battery telemetry; not battery wear diagnostics'
        }
    }
}

$result.PendingRestart = Invoke-HealthCheck {
    $indicators = @()
    $checked = @()

    $paths = @(
        @{
            Name = 'ComponentBasedServicing'
            Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        },
        @{
            Name = 'WindowsUpdate'
            Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        }
    )

    foreach ($item in $paths) {
        $checked += $item.Name

        if (Test-Path -LiteralPath $item.Path -ErrorAction Stop) {
            $indicators += $item.Name
        }
    }

    $checked += 'PendingFileRenameOperations'

    $session = Get-ItemProperty `
        -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
        -ErrorAction Stop

    if ($null -ne $session.PendingFileRenameOperations) {
        $indicators += 'PendingFileRenameOperations'
    }

    @{
        Required = ($indicators.Count -gt 0)
        Indicators = @($indicators)
        CheckedIndicators = @($checked)
        Note = 'Based on selected registry indicators only'
    }
}

$result | ConvertTo-Json -Depth 12 -Compress
"""


def main():
    print("=" * 60)
    print(" NANOBRICKS ENDPOINT360")
    print(f" Device Health Collector v{VERSION}")
    print("=" * 60)

    print("\nAssessment mode: READ ONLY")
    print("Collecting Windows device health information...\n")

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
        print(f"ERROR: Device Health assessment failed: {error}")
        return 1

    expected_checks = [
        "SystemUptime",
        "CPU",
        "Memory",
        "Storage",
        "PhysicalDisks",
        "Battery",
        "PendingRestart",
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
        "Module": "Device Health",
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
        "Health": checks,
    }

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    report_path = REPORT_DIR / (
        f"{platform.node()}-DeviceHealth-{timestamp}.json"
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
    print("\nNo Windows settings were modified.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
