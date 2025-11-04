#Requires -RunAsAdministrator

<#
.SYNOPSIS
  Configures Windows Storage Sense settings via Group Policy with full control.
.DESCRIPTION
  Enables or disables Storage Sense system-wide to automatically free up disk space by removing
  temporary files, items in the recycle bin, and files in the Downloads folder that
  haven't changed in a specified time period. Includes rollback capability.
.PARAMETER Disable
  Disables Storage Sense and removes all policy configurations
.PARAMETER RecycleBinDays
  Days before emptying recycle bin (default: 30, options: 1, 14, 30, 60)
.PARAMETER DownloadsDays
  Days before cleaning Downloads folder (default: 60, options: 1, 14, 30, 60, never)
.NOTES
  Requires Administrator privileges
  Storage Sense settings are controlled via Group Policy
  These settings will override user preferences in Windows Settings
.EXAMPLE
  .\05-Settings_Win11.ps1
  Enables Storage Sense with default settings
.EXAMPLE
  .\05-Settings_Win11.ps1 -RecycleBinDays 14 -DownloadsDays 30
  Enables Storage Sense with custom cleanup intervals
.EXAMPLE
  .\05-Settings_Win11.ps1 -Disable
  Disables Storage Sense and removes all policy configurations
#>

param(
    [switch]$Disable,
    [ValidateSet(1, 14, 30, 60)]
    [int]$RecycleBinDays,
    [ValidateSet(0, 1, 14, 30, 60)]
    [int]$DownloadsDays
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Set default values if not provided
if (-not $PSBoundParameters.ContainsKey('RecycleBinDays')) {
    $RecycleBinDays = 30
}
if (-not $PSBoundParameters.ContainsKey('DownloadsDays')) {
    $DownloadsDays = 60
}

function Write-StatusMessage {
    param([string]$Message, [ValidateSet('OK','WARNING','ERROR','INFO')] [string]$Status='INFO')
    $color = @{ OK='Green'; WARNING='Yellow'; ERROR='Red'; INFO='Cyan' }[$Status]
    Write-Host "[$Status] " -ForegroundColor $color -NoNewline
    Write-Host $Message
}

function Get-RegistryValue {
    param([Parameter(Mandatory)] [string]$Path, [Parameter(Mandatory)] [string]$Name)
    try {
        if (Test-Path $Path) {
            $prop = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            return $prop.$Name
        }
        return $null
    } catch { return $null }
}

function Set-RegistryDword {
    param([Parameter(Mandatory)] [string]$Path, [Parameter(Mandatory)] [string]$Name, [Parameter(Mandatory)] [int]$Value)
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
}

function Remove-RegistryValue {
    param([Parameter(Mandatory)] [string]$Path, [Parameter(Mandatory)] [string]$Name)
    try {
        if (Test-Path $Path) {
            Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        }
    } catch { }
}

function Test-WindowsVersion {
    $os = Get-CimInstance Win32_OperatingSystem
    $version = [System.Version]$os.Version
    
    if ($version.Major -lt 10) {
        Write-StatusMessage "Storage Sense requires Windows 10 or later. Current version: $($os.Caption)" 'ERROR'
        return $false
    }
    
    Write-StatusMessage "Windows version validated: $($os.Caption) (Build $($os.BuildNumber))" 'OK'
    return $true
}

# Registry Paths
$STORAGE_SENSE_POLICY = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense"

function Show-StorageSenseStatus {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Storage Sense Settings - Current Status" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    Write-Host "`n--- Storage Sense Policy Configuration ---" -ForegroundColor Yellow
    $storageSenseGlobal = Get-RegistryValue -Path $STORAGE_SENSE_POLICY -Name "AllowStorageSenseGlobal"
    
    $statusText = switch ($storageSenseGlobal) {
        1 { 'ENABLED'; break }
        0 { 'DISABLED'; break }
        default { 'NOT CONFIGURED'; break }
    }
    
    $statusLevel = switch ($storageSenseGlobal) {
        1 { 'OK'; break }
        0 { 'WARNING'; break }
        default { 'INFO'; break }
    }
    
    Write-StatusMessage ("Storage Sense (system-wide): $statusText") $statusLevel
    
    if ($storageSenseGlobal -eq 1) {
        # Show detailed configuration
        $recycleBinThreshold = Get-RegistryValue -Path $STORAGE_SENSE_POLICY -Name "ConfigStorageSenseRecycleBinCleanupThreshold"
        $downloadsThreshold = Get-RegistryValue -Path $STORAGE_SENSE_POLICY -Name "ConfigStorageSenseDownloadsCleanupThreshold"
        $cloudDehydration = Get-RegistryValue -Path $STORAGE_SENSE_POLICY -Name "ConfigStorageSenseCloudContentDehydrationThreshold"
        
        Write-Host "`n    ℹ️  Storage Sense Active Configuration:" -ForegroundColor Cyan
        Write-Host "       • Delete temporary files: " -ForegroundColor Gray -NoNewline
        Write-Host "ENABLED" -ForegroundColor Green
        
        if ($null -ne $recycleBinThreshold) {
            $rbText = if ($recycleBinThreshold -eq 0) { "Never" } else { "$recycleBinThreshold days" }
            Write-Host "       • Empty recycle bin after: " -ForegroundColor Gray -NoNewline
            Write-Host $rbText -ForegroundColor Green
        } else {
            Write-Host "       • Empty recycle bin: " -ForegroundColor Gray -NoNewline
            Write-Host "Not configured (user default)" -ForegroundColor Yellow
        }
        
        if ($null -ne $downloadsThreshold) {
            $dlText = if ($downloadsThreshold -eq 0) { "Never" } else { "$downloadsThreshold days" }
            Write-Host "       • Clean Downloads folder after: " -ForegroundColor Gray -NoNewline
            Write-Host $dlText -ForegroundColor Green
        } else {
            Write-Host "       • Clean Downloads folder: " -ForegroundColor Gray -NoNewline
            Write-Host "Not configured (user default)" -ForegroundColor Yellow
        }
        
        if ($null -ne $cloudDehydration) {
            $cdText = if ($cloudDehydration -eq 0) { "Never" } else { "$cloudDehydration days" }
            Write-Host "       • Dehydrate cloud content after: " -ForegroundColor Gray -NoNewline
            Write-Host $cdText -ForegroundColor Green
        }
        
    } elseif ($storageSenseGlobal -eq 0) {
        Write-Host "`n    ⚠️  Storage Sense is explicitly disabled via policy" -ForegroundColor Yellow
    } else {
        Write-Host "`n    ℹ️  Storage Sense is not configured via policy" -ForegroundColor Cyan
        Write-Host "       Users can configure it manually in Settings > System > Storage" -ForegroundColor Gray
    }
}

function Set-StorageSenseSettings {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Applying Storage Sense Settings" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    try {
        Write-Host "`nConfiguring Storage Sense policy..." -ForegroundColor Yellow
        
        # Enable Storage Sense globally
        Set-RegistryDword -Path $STORAGE_SENSE_POLICY -Name "AllowStorageSenseGlobal" -Value 1
        Write-StatusMessage "Storage Sense (system-wide): ENABLED" 'OK'
        
        # Configure Recycle Bin cleanup
        Set-RegistryDword -Path $STORAGE_SENSE_POLICY -Name "ConfigStorageSenseRecycleBinCleanupThreshold" -Value $RecycleBinDays
        Write-StatusMessage "Recycle Bin cleanup: Every $RecycleBinDays days" 'OK'
        
        # Configure Downloads folder cleanup
        if ($DownloadsDays -eq 0) {
            Set-RegistryDword -Path $STORAGE_SENSE_POLICY -Name "ConfigStorageSenseDownloadsCleanupThreshold" -Value 0
            Write-StatusMessage "Downloads folder cleanup: DISABLED" 'INFO'
        } else {
            Set-RegistryDword -Path $STORAGE_SENSE_POLICY -Name "ConfigStorageSenseDownloadsCleanupThreshold" -Value $DownloadsDays
            Write-StatusMessage "Downloads folder cleanup: Every $DownloadsDays days" 'OK'
        }
        
        # Configure cloud content dehydration (optional, set to 60 days)
        Set-RegistryDword -Path $STORAGE_SENSE_POLICY -Name "ConfigStorageSenseCloudContentDehydrationThreshold" -Value 60
        Write-StatusMessage "Cloud content dehydration: Every 60 days" 'OK'
        
        Write-Host "`n    ✓ Storage Sense fully configured and active" -ForegroundColor Green
        Write-Host "`n    ⚠️  NOTE: These Group Policy settings override user preferences" -ForegroundColor Yellow
        Write-Host "      Users cannot change Storage Sense settings in Windows Settings UI" -ForegroundColor Gray
        Write-Host "`n      To view current settings, users can go to:" -ForegroundColor Gray
        Write-Host "      Settings > System > Storage > Storage Sense" -ForegroundColor White
    }
    catch {
        Write-StatusMessage "Error applying Storage Sense settings: $($_.Exception.Message)" 'ERROR'
        throw
    }
}

function Remove-StorageSenseSettings {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Removing Storage Sense Policy Settings" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    try {
        Write-Host "`nRemoving Storage Sense policy configurations..." -ForegroundColor Yellow
        
        Remove-RegistryValue -Path $STORAGE_SENSE_POLICY -Name "AllowStorageSenseGlobal"
        Remove-RegistryValue -Path $STORAGE_SENSE_POLICY -Name "ConfigStorageSenseRecycleBinCleanupThreshold"
        Remove-RegistryValue -Path $STORAGE_SENSE_POLICY -Name "ConfigStorageSenseDownloadsCleanupThreshold"
        Remove-RegistryValue -Path $STORAGE_SENSE_POLICY -Name "ConfigStorageSenseCloudContentDehydrationThreshold"
        
        Write-StatusMessage "All Storage Sense policies removed" 'OK'
        Write-Host "`n    ✓ Storage Sense is no longer controlled by Group Policy" -ForegroundColor Green
        Write-Host "      Users can now configure it manually in Settings" -ForegroundColor Gray
    }
    catch {
        Write-StatusMessage "Error removing Storage Sense settings: $($_.Exception.Message)" 'ERROR'
        throw
    }
}

# --- Main ---
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Storage Sense Configuration Tool" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Validate Windows version
if (-not (Test-WindowsVersion)) {
    exit 1
}

Write-Host "`n=== BEFORE: Current State ===" -ForegroundColor Magenta
Show-StorageSenseStatus

if ($Disable) {
    Remove-StorageSenseSettings
} else {
    Set-StorageSenseSettings
}

Write-Host "`n=== AFTER: Updated State ===" -ForegroundColor Magenta
Show-StorageSenseStatus

# Footer
Write-Host "`n========================================" -ForegroundColor Cyan
$lastEditedTimestamp = "2025-11-03 12:45:00" 
Write-Host "Last Edited: $lastEditedTimestamp" -ForegroundColor Green
Write-Host "www.AIIT.support All rights reserved" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

if (-not $Disable) {
    Write-Host "`nADDITIONAL NOTES:" -ForegroundColor Yellow
    Write-Host "- Storage Sense will run automatically in the background" -ForegroundColor White
    Write-Host "- You can manually trigger it from Settings > System > Storage" -ForegroundColor White
    Write-Host "- These are Group Policy settings - users cannot override them" -ForegroundColor White
    Write-Host "- To disable, run this script with the -Disable parameter" -ForegroundColor White
    Write-Host "`nEXAMPLES:" -ForegroundColor Yellow
    Write-Host "  .\05-Settings_Win11.ps1 -Disable" -ForegroundColor Gray
    Write-Host "  .\05-Settings_Win11.ps1 -RecycleBinDays 14 -DownloadsDays 30" -ForegroundColor Gray
} else {
    Write-Host "`nADDITIONAL NOTES:" -ForegroundColor Yellow
    Write-Host "- Storage Sense policies have been removed" -ForegroundColor White
    Write-Host "- Users can now configure Storage Sense in Windows Settings" -ForegroundColor White
    Write-Host "- To re-enable with policy, run this script without -Disable" -ForegroundColor White
}