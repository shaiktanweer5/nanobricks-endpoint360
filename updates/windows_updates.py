
"""
Nanobricks Endpoint360
Windows Updates Assessment v0.1.1

Read-only Windows Update assessment.

Collects:
- Pending Windows updates
- Recent Windows Update history
- Last successful update installation, where available
- Windows restart indicators
- Collection errors and visibility limitations

Uses Python standard library and Windows PowerShell.
Does not download or install updates, modify settings,
or restart Windows.
"""

import json
import os
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
$ProgressPreference = 'SilentlyContinue'

$result = [ordered]@{
    PendingUpdates = [ordered]@{
        Status = 'Unknown'
        Count = $null
        Updates = @()
        Error = $null
    }
    UpdateHistory = [ordered]@{
        Status = 'Unknown'
        Count = $null
        Entries = @()
        LastSuccessfulInstallation = $null
        Error = $null
    }
    RestartRequired = [ordered]@{
        Status = 'Unknown'
        Required = $null
        Indicators = @()
        CheckedIndicators = @()
        Errors = @()
    }
}

# -------------------------------------------------------
# 1. Pending Windows Updates
# -------------------------------------------------------

$searcher = $null

try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()

    $search = $searcher.Search(
        "IsInstalled=0 and IsHidden=0"
    )

    $pending = @(
        foreach ($update in $search.Updates) {
            [ordered]@{
                Title = [string]$update.Title
                KBArticles = @($update.KBArticleIDs)
                Severity = [string]$update.MsrcSeverity
                RebootRequired = [bool]$update.RebootRequired
                IsDownloaded = [bool]$update.IsDownloaded
                Categories = @(
                    foreach ($category in $update.Categories) {
                        [string]$category.Name
                    }
                )
            }
        }
    )

    $result.PendingUpdates.Status = 'Collected'
    $result.PendingUpdates.Count = $pending.Count
    $result.PendingUpdates.Updates = $pending
}
catch {
    $result.PendingUpdates.Status = 'Error'
    $result.PendingUpdates.Error = $_.Exception.Message
}

# -------------------------------------------------------
# 2. Windows Update History
# -------------------------------------------------------

try {
    if ($null -eq $searcher) {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
    }

    $total = $searcher.GetTotalHistoryCount()
    $limit = [Math]::Min($total, 30)
    $entries = @()

    if ($limit -gt 0) {
        $history = $searcher.QueryHistory(0, $limit)

        $entries = @(
            foreach ($entry in $history) {
                $operation = switch ([int]$entry.Operation) {
                    1 { 'Installation' }
                    2 { 'Uninstallation' }
                    default { 'Other' }
                }

                $status = switch ([int]$entry.ResultCode) {
                    0 { 'Not Started' }
                    1 { 'In Progress' }
                    2 { 'Succeeded' }
                    3 { 'Succeeded With Errors' }
                    4 { 'Failed' }
                    5 { 'Aborted' }
                    default { 'Unknown' }
                }

                [ordered]@{
                    Title = [string]$entry.Title
                    Date = $entry.Date.ToString('o')
                    Operation = $operation
                    Result = $status
                    HResult = [string]$entry.HResult
                }
            }
        )
    }

    $result.UpdateHistory.Status = 'Collected'
    $result.UpdateHistory.Count = $total
    $result.UpdateHistory.Entries = $entries

    $lastSuccess = $entries |
        Where-Object {
            $_.Operation -eq 'Installation' -and
            $_.Result -eq 'Succeeded'
        } |
        Sort-Object Date -Descending |
        Select-Object -First 1

    if ($null -ne $lastSuccess) {
        $result.UpdateHistory.LastSuccessfulInstallation = (
            $lastSuccess.Date
        )
    }
}
catch {
    $result.UpdateHistory.Status = 'Error'
    $result.UpdateHistory.Error = $_.Exception.Message
}

# -------------------------------------------------------
# 3. Restart Required Indicators
# -------------------------------------------------------

$indicators = @()
$checked = @()
$errors = @()

$paths = @(
    @{
        Name = 'Windows Update RebootRequired'
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    },
    @{
        Name = 'Component Based Servicing RebootPending'
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    },
    @{
        Name = 'Component Based Servicing RebootInProgress'
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootInProgress'
    },
    @{
        Name = 'Component Based Servicing PackagesPending'
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending'
    }
)

foreach ($item in $paths) {
    try {
        $exists = Test-Path `
            -LiteralPath $item.Path `
            -ErrorAction Stop

        $checked += $item.Name

        if ($exists) {
            $indicators += $item.Name
        }
    }
    catch {
        $errors += (
            "$($item.Name): $($_.Exception.Message)"
        )
    }
}

# -------------------------------------------------------
# 4. Pending File Rename Operations
#
# This registry value is optional.
# Its absence is normal and must not be treated
# as a Windows assessment error.
# -------------------------------------------------------

try {
    $sessionManager = Get-ItemProperty `
        -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
        -ErrorAction Stop

    $checked += 'Pending File Rename Operations'

    $property = $sessionManager.PSObject.Properties[
        'PendingFileRenameOperations'
    ]

    if (
        $null -ne $property -and
        $null -ne $property.Value -and
        @($property.Value).Count -gt 0
    ) {
        $indicators += 'Pending File Rename Operations'
    }
}
catch {
    $errors += (
        "Pending File Rename Operations: $($_.Exception.Message)"
    )
}

# -------------------------------------------------------
# 5. Restart Assessment Result
# -------------------------------------------------------

$result.RestartRequired.Indicators = @($indicators)
$result.RestartRequired.CheckedIndicators = @($checked)
$result.RestartRequired.Errors = @($errors)

if ($indicators.Count -gt 0) {
    $result.RestartRequired.Status = 'Collected'
    $result.RestartRequired.Required = $true
}
elseif ($errors.Count -eq 0) {
    $result.RestartRequired.Status = 'Collected'
    $result.RestartRequired.Required = $false
}
else {
    $result.RestartRequired.Status = 'Partial'
    $result.RestartRequired.Required = $null
}

$result | ConvertTo-Json -Depth 12 -Compress
"""


def collect_updates():
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            POWERSHELL_SCRIPT,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=150,
        check=False,
        env={
            **os.environ,
            "PYTHONIOENCODING": "utf-8",
        },
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip()
            or (
                "PowerShell exited with code "
                f"{result.returncode}"
            )
        )

    output = result.stdout.strip()

    if not output:
        raise RuntimeError(
            "Windows Update assessment returned no data."
        )

    try:
        return json.loads(output)

    except json.JSONDecodeError as error:
        raise RuntimeError(
            "Could not parse Windows Update response: "
            f"{error}"
        ) from error


def main():
    print("=" * 55)
    print(" NANOBRICKS ENDPOINT360")
    print(f" Windows Updates Assessment v{VERSION}")
    print("=" * 55)

    print("\nAssessment mode: READ ONLY")
    print("Checking Windows Update visibility...\n")

    timestamp = datetime.now(timezone.utc)

    report = {
        "Product": "Nanobricks Endpoint360",
        "Module": "Windows Updates",
        "Version": VERSION,
        "ComputerName": platform.node(),
        "AssessmentTimeUTC": timestamp.isoformat(),
        "AssessmentMode": "Read Only",
        "PendingUpdates": {
            "Status": "Unknown",
            "Count": None,
            "Updates": [],
            "Error": None,
        },
        "UpdateHistory": {
            "Status": "Unknown",
            "Count": None,
            "Entries": [],
            "LastSuccessfulInstallation": None,
            "Error": None,
        },
        "RestartRequired": {
            "Status": "Unknown",
            "Required": None,
            "Indicators": [],
            "CheckedIndicators": [],
            "Errors": [],
        },
        "CollectionError": None,
    }

    try:
        collected = collect_updates()

        for key in (
            "PendingUpdates",
            "UpdateHistory",
            "RestartRequired",
        ):
            if isinstance(collected.get(key), dict):
                report[key] = collected[key]

    except (
        OSError,
        RuntimeError,
        subprocess.TimeoutExpired,
    ) as error:
        report["CollectionError"] = str(error)
        print(f"Collection warning: {error}")

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    filename = (
        f"{platform.node()}-PythonUpdates-"
        f"{timestamp.strftime('%Y%m%d-%H%M%S')}.json"
    )

    report_path = REPORT_DIR / filename

    with report_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            report,
            file,
            indent=2,
            ensure_ascii=False,
        )

    pending = report["PendingUpdates"]
    history = report["UpdateHistory"]
    restart = report["RestartRequired"]

    print("ASSESSMENT SUMMARY")
    print("-" * 55)

    print(f"Computer: {report['ComputerName']}")
    print(f"Pending Updates Status: {pending['Status']}")
    print(f"Pending Updates: {pending['Count']}")
    print(f"Update History Status: {history['Status']}")
    print(
        "History Entries Available: "
        f"{len(history['Entries'])}"
    )
    print(f"Restart Check Status: {restart['Status']}")
    print(f"Restart Required: {restart['Required']}")

    if pending.get("Error"):
        print(
            "Pending Update Error: "
            f"{pending['Error']}"
        )

    if history.get("Error"):
        print(
            "Update History Error: "
            f"{history['Error']}"
        )

    if restart.get("Errors"):
        print("Restart Check Errors:")

        for error in restart["Errors"]:
            print(f"  - {error}")

    if report["CollectionError"]:
        print(
            "Collection Error: "
            f"{report['CollectionError']}"
        )

    print(f"\nReport: {report_path}")

    print("\nNo updates were downloaded or installed.")
    print("No Windows settings were modified.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
