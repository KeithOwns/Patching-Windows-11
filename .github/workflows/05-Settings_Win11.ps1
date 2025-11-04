<#
.SYNOPSIS
  Configures Windows Storage Sense settings at the user level.
.DESCRIPTION
  Enables or disables Storage Sense for the current user to automatically free up disk space by removing
  temporary files, items in the recycle bin, and files in the Downloads folder that
  haven't changed in a specified time period. Includes rollback capability.
.PARAMETER Disable
  Resets Storage Sense settings to default by removing all configurations.
.PARAMETER RecycleBinDays
  Days before emptying recycle bin (default: 30, options: 1, 14, 30, 60)
.PARAMETER DownloadsDays
  Days before cleaning Downloads folder (default: 60, options: 0, 1, 14, 30, 60. Use 0 for 'Never')
.NOTES
  Storage Sense settings are configured in the user's registry hive (HKCU).
  These settings directly modify the user's preferences in Windows Settings.
.EXAMPLE
  .\05-Settings_Win11_User.ps1
  Enables Storage Sense with default settings for the current user.
.EXAMPLE
  .\05-Settings_Win11_User.ps1 -RecycleBinDays 14 -DownloadsDays 30
  Enables Storage Sense with custom cleanup intervals for the current user.
.EXAMPLE
  .\05-Settings_Win11_User.ps1 -Disable
  Resets Storage Sense configuration for the current user.
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

# --- CORRECTED FUNCTIONS ---
# Reverted to the simple, original functions. 
# They work perfectly with HKCU paths and do not require the complex path replacement.

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
# --- END CORRECTIONS ---


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

# Registry Path for Current User
$STORAGE_SENSE_USER_PATH = "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy"

function Show-StorageSenseStatus {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Storage Sense Settings - Current Status (User)" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    Write-Host "`n--- Storage Sense User Configuration ---" -ForegroundColor Yellow
    # "01" is the registry value for enabling/disabling Storage Sense
    $storageSenseGlobal = Get-RegistryValue -Path $STORAGE_SENSE_USER_PATH -Name "01"
    
    $statusText = switch ($storageSenseGlobal) {
        1 { 'ENABLED'; break }
        0 { 'DISABLED'; break }
        default { 'NOT CONFIGURED (Default)'; break }
    }
    
    $statusLevel = switch ($storageSenseGlobal) {
        1 { 'OK'; break }
        0 { 'WARNING'; break }
        default { 'INFO'; break }
    }
    
    Write-StatusMessage ("Storage Sense (current user): $statusText") $statusLevel
    
    if ($storageSenseGlobal -eq 1) {
        # Show detailed configuration
        # "04" = Recycle Bin threshold
        $recycleBinThreshold = Get-RegistryValue -Path $STORAGE_SENSE_USER_PATH -Name "04"
        # "08" = Downloads folder threshold
        $downloadsThreshold = Get-RegistryValue -Path $STORAGE_SENSE_USER_PATH -Name "08"
        # "32" = Cloud content dehydration threshold
        $cloudDehydration = Get-RegistryValue -Path $STORAGE_SENSE_USER_PATH -Name "32"
        
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
        Write-Host "`n    ⚠️  Storage Sense is explicitly disabled for this user" -ForegroundColor Yellow
    } else {
        Write-Host "`n    ℹ️  Storage Sense is not configured for this user" -ForegroundColor Cyan
        Write-Host "       User can configure it manually in Settings > System > Storage" -ForegroundColor Gray
    }
}

function Set-StorageSenseSettings {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Applying Storage Sense Settings (User)" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    try {
        Write-Host "`nConfiguring Storage Sense for current user..." -ForegroundColor Yellow
        
        # Enable Storage Sense ("01")
        Set-RegistryDword -Path $STORAGE_SENSE_USER_PATH -Name "01" -Value 1
        Write-StatusMessage "Storage Sense (current user): ENABLED" 'OK'

        # Enable "Delete temporary files" ("2048")
        Set-RegistryDword -Path $STORAGE_SENSE_USER_PATH -Name "2048" -Value 1
        Write-StatusMessage "Delete temporary files: ENABLED" 'OK'
        
        # Configure Recycle Bin cleanup ("04")
        Set-RegistryDword -Path $STORAGE_SENSE_USER_PATH -Name "04" -Value $RecycleBinDays
        Write-StatusMessage "Recycle Bin cleanup: Every $RecycleBinDays days" 'OK'
        
        # Configure Downloads folder cleanup ("08")
        Set-RegistryDword -Path $STORAGE_SENSE_USER_PATH -Name "08" -Value $DownloadsDays
        if ($DownloadsDays -eq 0) {
            Write-StatusMessage "Downloads folder cleanup: DISABLED" 'INFO'
        } else {
            Write-StatusMessage "Downloads folder cleanup: Every $DownloadsDays days" 'OK'
        }
        
        # Configure cloud content dehydration (optional, set to 60 days) ("32")
        Set-RegistryDword -Path $STORAGE_SENSE_USER_PATH -Name "32" -Value 60
        Write-StatusMessage "Cloud content dehydration: Every 60 days" 'OK'
        
        Write-Host "`n    ✓ Storage Sense configured for current user" -ForegroundColor Green
        Write-Host "      You can view these changes in:" -ForegroundColor Gray
        Write-Host "      Settings > System > Storage > Storage Sense" -ForegroundColor White
    }
    catch {
        Write-StatusMessage "Error applying Storage Sense settings: $($_.Exception.Message)" 'ERROR'
        throw
    }
}

function Remove-StorageSenseSettings {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Resetting Storage Sense User Settings" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    try {
        Write-Host "`nRemoving Storage Sense user configurations..." -ForegroundColor Yellow
        
        # Remove all configured keys to reset to default
        Remove-RegistryValue -Path $STORAGE_SENSE_USER_PATH -Name "01"
        Remove-RegistryValue -Path $STORAGE_SENSE_USER_PATH -Name "2048"
        Remove-RegistryValue -Path $STORAGE_SENSE_USER_PATH -Name "04"
        Remove-RegistryValue -Path $STORAGE_SENSE_USER_PATH -Name "08"
        Remove-RegistryValue -Path $STORAGE_SENSE_USER_PATH -Name "32"
        
        Write-StatusMessage "All Storage Sense user settings removed" 'OK'
        Write-Host "`n    ✓ Storage Sense is now reset to defaults" -ForegroundColor Green
        Write-Host "      User can configure it manually in Settings" -ForegroundColor Gray
    }
    catch {
        Write-StatusMessage "Error removing Storage Sense settings: $($_.Exception.Message)" 'ERROR'
        throw
    }
}

# --- Main ---
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Storage Sense Configuration Tool (User Level)" -ForegroundColor Cyan
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
$lastEditedTimestamp = "2025-11-04 12:18:00" 
Write-Host "Last Edited: $lastEditedTimestamp" -ForegroundColor Green
Write-Host "www.AIIT.support All rights reserved" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

if (-not $Disable) {
    Write-Host "`nADDITIONAL NOTES:" -ForegroundColor Yellow
    Write-Host "- Storage Sense will run automatically in the background" -ForegroundColor White
    Write-Host "- You can manually trigger it from Settings > System > Storage" -ForegroundColor White
    Write-Host "- These settings can be changed by the user in Settings" -ForegroundColor White
    Write-Host "- To reset, run this script with the -Disable parameter" -ForegroundColor White
    Write-Host "`nEXAMPLES:" -ForegroundColor Yellow
    Write-Host "  .\05-Settings_Win11_User.ps1 -Disable" -ForegroundColor Gray
    Write-Host "  .\05-Settings_Win11_User.ps1 -RecycleBinDays 14 -DownloadsDays 30" -ForegroundColor Gray
} else {
    Write-Host "`nADDITIONAL NOTES:" -ForegroundColor Yellow
    Write-Host "- Storage Sense user settings have been reset" -ForegroundColor White
    Write-Host "- User can now configure Storage Sense in Windows Settings" -ForegroundColor White
    Write-Host "- To re-enable, run this script without -Disable" -ForegroundColor White
}