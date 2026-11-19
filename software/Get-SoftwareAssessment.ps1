# ============================================================
# NANOBRICKS ENDPOINT360
# Software Inventory & Update Assessment
# Version: 0.1.0
#
# Read-only assessment.
# Does not install, uninstall or update applications.
# ============================================================

$ErrorActionPreference = "Stop"

$moduleVersion = "0.1.0"
$reportDirectory = Join-Path $PSScriptRoot "reports"

Write-Host ""
Write-Host "========================================"
Write-Host " NANOBRICKS ENDPOINT360"
Write-Host " Software Assessment v$moduleVersion"
Write-Host "========================================"
Write-Host ""

function Get-InstalledApplications {

    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $applications = @(
        foreach ($path in $registryPaths) {

            Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
                Where-Object {
                    -not [string]::IsNullOrWhiteSpace($_.DisplayName)
                } |
                ForEach-Object {

                    [PSCustomObject]@{
                        Name            = $_.DisplayName
                        Version         = $_.DisplayVersion
                        Publisher       = $_.Publisher
                        InstallDate     = $_.InstallDate
                        RegistryPath    = $_.PSPath
                    }
                }
        }
    )

    @(
        $applications |
            Sort-Object Name, Version, Publisher -Unique
    )
}

function Get-AvailableApplicationUpdates {

    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue

    if ($null -eq $winget) {
        return [PSCustomObject]@{
            Status  = "Unavailable"
            Message = "Windows Package Manager is not installed."
            Output  = @()
        }
    }

    try {
        $output = @(
            & $winget.Source upgrade --disable-interactivity 2>&1 |
                ForEach-Object { [string]$_ }
        )

        $exitCode = $LASTEXITCODE

        if ($exitCode -ne 0) {
            return [PSCustomObject]@{
                Status  = "UnableToAssess"
                Message = "winget returned exit code $exitCode."
                Output  = $output
            }
        }

        return [PSCustomObject]@{
            Status  = "Collected"
            Message = "winget update discovery completed."
            Output  = $output
        }
    }
    catch {
        return [PSCustomObject]@{
            Status  = "UnableToAssess"
            Message = $_.Exception.Message
            Output  = @()
        }
    }
}

Write-Host "Collecting installed applications..."

$installedApps = @(Get-InstalledApplications)

Write-Host "Checking available application updates..."

$updates = Get-AvailableApplicationUpdates

$assessment = [PSCustomObject]@{
    Product        = "Nanobricks Endpoint360"
    Module         = "Software Inventory and Update Assessment"
    ModuleVersion  = $moduleVersion
    CollectedAtUTC = (Get-Date).ToUniversalTime().ToString("o")
    ComputerName   = $env:COMPUTERNAME

    InstalledApplications = $installedApps
    ApplicationUpdates    = $updates
}

if (-not (Test-Path $reportDirectory)) {
    New-Item -ItemType Directory -Path $reportDirectory -Force |
        Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

$reportFile = Join-Path $reportDirectory (
    "$($env:COMPUTERNAME)-SoftwareAssessment-$timestamp.json"
)

$assessment |
    ConvertTo-Json -Depth 10 |
    Set-Content -Path $reportFile -Encoding UTF8

Write-Host ""
Write-Host "Assessment completed." -ForegroundColor Green
Write-Host "Report: $reportFile"
Write-Host ""
Write-Host "SOFTWARE SUMMARY"
Write-Host "Computer: $($env:COMPUTERNAME)"
Write-Host "Installed applications: $($installedApps.Count)"
Write-Host "Update discovery: $($updates.Status)"
Write-Host ""
Write-Host "No applications were installed or updated."
Write-Host ""