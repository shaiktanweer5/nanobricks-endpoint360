# ============================================================
# NANOBRICKS ENDPOINT360
# Windows Security Assessment
# Version: 0.1.0
#
# Read-only assessment.
# Does not change Windows security configurations.
# ============================================================

$ErrorActionPreference = "Stop"

$moduleVersion = "0.1.0"
$reportDirectory = Join-Path $PSScriptRoot "reports"

function Invoke-SecurityCheck {
    param(
        [scriptblock]$Action
    )

    try {
        & $Action
    }
    catch {
        [PSCustomObject]@{
            Status = "Unknown"
            Error  = $_.Exception.Message
        }
    }
}

function Get-DefenderAssessment {

    Invoke-SecurityCheck {

        $defender = Get-MpComputerStatus -ErrorAction Stop

        $signatureAge = $null

        if ($null -ne $defender.AntivirusSignatureLastUpdated) {
            $signatureAge = [math]::Round(
                ((Get-Date) - $defender.AntivirusSignatureLastUpdated).TotalDays,
                2
            )
        }

        [PSCustomObject]@{
            Status                         = "Collected"
            AntivirusEnabled               = $defender.AntivirusEnabled
            RealTimeProtectionEnabled      = $defender.RealTimeProtectionEnabled
            BehaviorMonitorEnabled         = $defender.BehaviorMonitorEnabled
            IoavProtectionEnabled          = $defender.IoavProtectionEnabled
            AntivirusSignatureVersion      = $defender.AntivirusSignatureVersion
            AntivirusSignatureLastUpdated  = $defender.AntivirusSignatureLastUpdated
            AntivirusSignatureAgeDays      = $signatureAge
            AMServiceEnabled               = $defender.AMServiceEnabled
        }
    }
}

function Get-FirewallAssessment {

    Invoke-SecurityCheck {

        $profiles = Get-NetFirewallProfile -ErrorAction Stop

        @(
            foreach ($firewallProfile in $profiles) {

                [PSCustomObject]@{
                    Name                  = $firewallProfile.Name
                    Enabled               = $firewallProfile.Enabled
                    DefaultInboundAction  = [string]$firewallProfile.DefaultInboundAction
                    DefaultOutboundAction = [string]$firewallProfile.DefaultOutboundAction
                }
            }
        )
    }
}

function Get-TPMAssessment {

    Invoke-SecurityCheck {

        $tpm = Get-Tpm -ErrorAction Stop

        [PSCustomObject]@{
            Status             = "Collected"
            TpmPresent         = $tpm.TpmPresent
            TpmReady           = $tpm.TpmReady
            TpmEnabled         = $tpm.TpmEnabled
            TpmActivated       = $tpm.TpmActivated
            ManufacturerId     = $tpm.ManufacturerId
            ManufacturerVersion = $tpm.ManufacturerVersion
        }
    }
}

function Get-SecureBootAssessment {

    Invoke-SecurityCheck {

        $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop

        [PSCustomObject]@{
            Status            = "Collected"
            SecureBootEnabled = [bool]$secureBoot
        }
    }
}

function Get-BitLockerAssessment {

    Invoke-SecurityCheck {

        $volumes = Get-BitLockerVolume -ErrorAction Stop

        @(
            foreach ($volume in $volumes) {

                [PSCustomObject]@{
                    MountPoint           = $volume.MountPoint
                    VolumeStatus         = [string]$volume.VolumeStatus
                    ProtectionStatus     = [string]$volume.ProtectionStatus
                    EncryptionPercentage = $volume.EncryptionPercentage
                    EncryptionMethod     = [string]$volume.EncryptionMethod
                }
            }
        )
    }
}

Write-Host ""
Write-Host "========================================"
Write-Host " NANOBRICKS ENDPOINT360"
Write-Host " Windows Security Assessment v$moduleVersion"
Write-Host "========================================"
Write-Host ""
Write-Host "Collecting read-only security information..."
Write-Host ""

$computerName = $env:COMPUTERNAME

$assessment = [PSCustomObject]@{
    Product        = "Nanobricks Endpoint360"
    Module         = "Windows Security Assessment"
    ModuleVersion  = $moduleVersion
    CollectedAtUTC = (Get-Date).ToUniversalTime().ToString("o")
    ComputerName   = $computerName

    Security       = [PSCustomObject]@{
        MicrosoftDefender = Get-DefenderAssessment
        WindowsFirewall   = Get-FirewallAssessment
        TPM               = Get-TPMAssessment
        SecureBoot        = Get-SecureBootAssessment
        BitLocker         = Get-BitLockerAssessment
    }
}

if (-not (Test-Path $reportDirectory)) {
    New-Item -ItemType Directory -Path $reportDirectory -Force |
        Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

$reportFile = Join-Path $reportDirectory (
    "$computerName-WindowsSecurity-$timestamp.json"
)

$assessment |
    ConvertTo-Json -Depth 10 |
    Set-Content -Path $reportFile -Encoding UTF8

Write-Host "Assessment completed." -ForegroundColor Green
Write-Host "Report: $reportFile"
Write-Host ""

Write-Host "SECURITY SUMMARY"
Write-Host "Computer: $computerName"
Write-Host "Defender: $($assessment.Security.MicrosoftDefender.Status)"
Write-Host "TPM: $($assessment.Security.TPM.Status)"
Write-Host "Secure Boot: $($assessment.Security.SecureBoot.Status)"
foreach ($volume in @($assessment.Security.BitLocker)) {
    if ($null -ne $volume.MountPoint) {
        Write-Host "Drive $($volume.MountPoint): $($volume.VolumeStatus) | Protection: $($volume.ProtectionStatus)"
    }
    elseif ($null -ne $volume.Status) {
        Write-Host "BitLocker: $($volume.Status)"
    }
}
Write-Host ""