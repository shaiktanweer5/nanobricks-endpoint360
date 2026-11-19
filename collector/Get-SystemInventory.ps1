
# ============================================================
# NANOBRICKS ENDPOINT360
# Module: Windows System Inventory
# Version: 0.1.0
# Mode: Read-only
# ============================================================

$ErrorActionPreference = "Stop"

function Get-SafeCimInstance {
    param(
        [Parameter(Mandatory)]
        [string]$ClassName
    )

    try {
        return Get-CimInstance -ClassName $ClassName -ErrorAction Stop
    }
    catch {
        Write-Warning "Unable to query $ClassName : $($_.Exception.Message)"
        return $null
    }
}

function Convert-ToGB {
    param(
        [AllowNull()]
        [object]$Bytes
    )

    if ($null -eq $Bytes) {
        return $null
    }

    return [math]::Round(([double]$Bytes / 1GB), 2)
}

function Get-Endpoint360SystemInventory {

    $collectedAt = (Get-Date).ToUniversalTime().ToString("o")

    $computer = Get-SafeCimInstance -ClassName "Win32_ComputerSystem"
    $os = Get-SafeCimInstance -ClassName "Win32_OperatingSystem"
    $processors = @(Get-SafeCimInstance -ClassName "Win32_Processor")
    $bios = Get-SafeCimInstance -ClassName "Win32_BIOS"
    $physicalDisks = @(Get-SafeCimInstance -ClassName "Win32_DiskDrive")
    $logicalDisks = @(Get-SafeCimInstance -ClassName "Win32_LogicalDisk")

    $cpuDetails = @(
        foreach ($cpu in $processors) {
            if ($null -eq $cpu) {
                continue
            }

            [ordered]@{
                Name = $cpu.Name
                Manufacturer = $cpu.Manufacturer
                Cores = $cpu.NumberOfCores
                LogicalProcessors = $cpu.NumberOfLogicalProcessors
                MaxClockSpeedMHz = $cpu.MaxClockSpeed
            }
        }
    )

    $diskDetails = @(
        foreach ($disk in $physicalDisks) {
            if ($null -eq $disk) {
                continue
            }

            [ordered]@{
                Model = $disk.Model
                InterfaceType = $disk.InterfaceType
                MediaType = $disk.MediaType
                SizeGB = Convert-ToGB -Bytes $disk.Size
            }
        }
    )

    $volumeDetails = @(
        foreach ($drive in $logicalDisks) {
            if ($null -eq $drive) {
                continue
            }

            [ordered]@{
                Drive = $drive.DeviceID
                FileSystem = $drive.FileSystem
                DriveType = $drive.DriveType
                SizeGB = Convert-ToGB -Bytes $drive.Size
                FreeSpaceGB = Convert-ToGB -Bytes $drive.FreeSpace
            }
        }
    )

    $lastBoot = $null
    $uptimeHours = $null

    if ($null -ne $os -and $null -ne $os.LastBootUpTime) {
        $lastBoot = $os.LastBootUpTime.ToString("o")

        $uptimeHours = [math]::Round(
            ((Get-Date) - $os.LastBootUpTime).TotalHours,
            2
        )
    }

    $inventory = [ordered]@{
        Product = "Nanobricks Endpoint360"
        Module = "Windows System Inventory"
        ModuleVersion = "0.1.0"
        CollectedAtUTC = $collectedAt

        Computer = [ordered]@{
            Name = $env:COMPUTERNAME
            Manufacturer = if ($computer) { $computer.Manufacturer } else { $null }
            Model = if ($computer) { $computer.Model } else { $null }
            TotalMemoryGB = if ($computer) {
                Convert-ToGB -Bytes $computer.TotalPhysicalMemory
            } else {
                $null
            }
        }

        OperatingSystem = [ordered]@{
            Name = if ($os) { $os.Caption } else { $null }
            Version = if ($os) { $os.Version } else { $null }
            BuildNumber = if ($os) { $os.BuildNumber } else { $null }
            Architecture = if ($os) { $os.OSArchitecture } else { $null }
            InstallDate = if ($os -and $os.InstallDate) {
                $os.InstallDate.ToString("o")
            } else {
                $null
            }
            LastBootTime = $lastBoot
            UptimeHours = $uptimeHours
        }

        Processor = $cpuDetails

        BIOS = [ordered]@{
            Manufacturer = if ($bios) { $bios.Manufacturer } else { $null }
            Version = if ($bios) { $bios.SMBIOSBIOSVersion } else { $null }
            ReleaseDate = if ($bios -and $bios.ReleaseDate) {
                $bios.ReleaseDate.ToString("o")
            } else {
                $null
            }
        }

        PhysicalDisks = $diskDetails
        LogicalDrives = $volumeDetails
    }

    return [pscustomobject]$inventory
}

try {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host " NANOBRICKS ENDPOINT360" -ForegroundColor Green
    Write-Host " Windows System Inventory v0.1.0"
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""

    Write-Host "Collecting read-only system information..."

    $report = Get-Endpoint360SystemInventory

    $outputDirectory = Join-Path $PSScriptRoot "reports"

    if (-not (Test-Path -LiteralPath $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory -Force |
            Out-Null
    }

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

    $safeComputerName = $env:COMPUTERNAME -replace '[^a-zA-Z0-9_-]', '_'

    $outputFile = Join-Path $outputDirectory (
        "$safeComputerName-SystemInventory-$timestamp.json"
    )

    $report |
        ConvertTo-Json -Depth 10 |
        Set-Content -LiteralPath $outputFile -Encoding UTF8

    Write-Host ""
    Write-Host "Assessment completed." -ForegroundColor Green
    Write-Host "Report: $outputFile"
    Write-Host ""

    Write-Host "SYSTEM SUMMARY" -ForegroundColor Cyan
    Write-Host "Computer: $($report.Computer.Name)"
    Write-Host "Manufacturer: $($report.Computer.Manufacturer)"
    Write-Host "Model: $($report.Computer.Model)"
    Write-Host "Windows: $($report.OperatingSystem.Name)"
    Write-Host "Build: $($report.OperatingSystem.BuildNumber)"
    Write-Host "RAM: $($report.Computer.TotalMemoryGB) GB"
    Write-Host "Uptime: $($report.OperatingSystem.UptimeHours) hours"
    Write-Host ""
}
catch {
    Write-Error "Endpoint360 inventory failed: $($_.Exception.Message)"
    exit 1
}
