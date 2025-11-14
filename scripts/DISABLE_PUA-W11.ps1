<#
.SYNOPSIS
    Disables Potentially Unwanted App (PUA) Protection at Device Level

.DESCRIPTION
    This script disables PUA Protection using Group Policy, which:
    1. Sets Group Policy registry value to 0 (disabled)
    2. Disables PUA Protection via Windows Defender
    3. Locks the setting as "managed by administrator"
    4. Prevents users from enabling it via Windows Security UI
    
    After running this script:
    - PUA Protection will be OFF
    - Setting will show "This setting is managed by your administrator"
    - Toggle will be greyed out
    - Users cannot change this setting
    
.NOTES
    Requires: Administrative privileges
    Author: AI+IT Support
    Version: 1.0
    
.PARAMETER Rollback
    Restores previous PUA Protection state from backup
    
.EXAMPLE
    .\Disable-PUAProtection-DeviceLevel.ps1
    Disables PUA Protection with Group Policy management
    
.EXAMPLE
    .\Disable-PUAProtection-DeviceLevel.ps1 -Rollback
    Restores PUA Protection to previous state
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$Rollback
)

#Requires -RunAsAdministrator

# ============================================================================
# CONFIGURATION
# ============================================================================

$Script:LogFile = "$env:TEMP\Disable-PUAProtection-DeviceLevel-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$Script:BackupFile = "$env:TEMP\PUAProtection-DeviceLevel-Backup-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"

# Registry paths
$Script:GroupPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
$Script:GroupPolicyValue = "PUAProtection"

$Script:EdgePath = "HKCU:\SOFTWARE\Microsoft\Edge\SmartScreenPuaEnabled"

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    $color = switch ($Level) {
        'Info'    { 'Cyan' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
        'Success' { 'Green' }
    }
    
    Write-Host $logMessage -ForegroundColor $color
    Add-Content -Path $Script:LogFile -Value $logMessage
}

# ============================================================================
# BACKUP FUNCTIONS
# ============================================================================

function Backup-CurrentState {
    Write-Log "Creating backup of current PUA Protection state..." -Level Info
    
    $backup = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        GroupPolicy = @{
            PathExists = Test-Path $Script:GroupPolicyPath
            Value = $null
            ValueExisted = $false
        }
        MpPreference = $null
        DefenderServiceStatus = $null
    }
    
    # Backup Group Policy value
    if ($backup.GroupPolicy.PathExists) {
        $gpValue = Get-ItemProperty -Path $Script:GroupPolicyPath -Name $Script:GroupPolicyValue -ErrorAction SilentlyContinue
        if ($null -ne $gpValue) {
            $backup.GroupPolicy.Value = $gpValue.$Script:GroupPolicyValue
            $backup.GroupPolicy.ValueExisted = $true
            
            $status = switch ($backup.GroupPolicy.Value) {
                0 { "Disabled" }
                1 { "Enabled" }
                2 { "Audit Mode" }
                default { $backup.GroupPolicy.Value }
            }
            Write-Log "  Current Group Policy: PUAProtection = $($backup.GroupPolicy.Value) ($status)" -Level Info
        } else {
            Write-Log "  Group Policy value does not exist (user-controlled)" -Level Info
        }
    } else {
        Write-Log "  Group Policy path does not exist" -Level Info
    }
    
    # Backup Windows Defender preference
    try {
        $mpPref = Get-MpPreference -ErrorAction SilentlyContinue
        if ($null -ne $mpPref) {
            $backup.MpPreference = $mpPref.PUAProtection
            
            $status = switch ($backup.MpPreference) {
                0 { "Disabled" }
                1 { "Enabled" }
                2 { "Audit Mode" }
                default { $backup.MpPreference }
            }
            Write-Log "  Current Windows Defender: PUAProtection = $($backup.MpPreference) ($status)" -Level Info
        }
        
        # Check Defender service status
        $defenderService = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
        if ($defenderService) {
            $backup.DefenderServiceStatus = $defenderService.Status
            Write-Log "  Windows Defender Service: $($backup.DefenderServiceStatus)" -Level Info
        }
    }
    catch {
        Write-Log "  Could not retrieve Windows Defender preference: $_" -Level Warning
    }
    
    $backup | ConvertTo-Json -Depth 10 | Out-File -FilePath $Script:BackupFile -Force
    Write-Log "Backup saved to: $Script:BackupFile" -Level Success
    
    return $Script:BackupFile
}

function Restore-PUAProtectionState {
    param([string]$BackupFilePath)
    
    if (-not (Test-Path $BackupFilePath)) {
        Write-Log "Backup file not found: $BackupFilePath" -Level Error
        return $false
    }
    
    Write-Log "Restoring PUA Protection state from backup..." -Level Info
    
    try {
        $backup = Get-Content -Path $BackupFilePath -Raw | ConvertFrom-Json
        
        # Restore Group Policy value
        if ($backup.GroupPolicy.ValueExisted) {
            # Restore original value
            if (-not (Test-Path $Script:GroupPolicyPath)) {
                New-Item -Path $Script:GroupPolicyPath -Force | Out-Null
                Write-Log "  Created Group Policy path" -Level Info
            }
            
            Set-ItemProperty -Path $Script:GroupPolicyPath -Name $Script:GroupPolicyValue -Value $backup.GroupPolicy.Value -Type DWord -Force
            Write-Log "  Restored Group Policy: PUAProtection = $($backup.GroupPolicy.Value)" -Level Success
        } else {
            # Remove the value we created
            if (Test-Path $Script:GroupPolicyPath) {
                Remove-ItemProperty -Path $Script:GroupPolicyPath -Name $Script:GroupPolicyValue -ErrorAction SilentlyContinue
                Write-Log "  Removed Group Policy value" -Level Info
            }
        }
        
        # Restore Windows Defender preference
        if ($null -ne $backup.MpPreference) {
            try {
                $prefValue = switch ($backup.MpPreference) {
                    0 { "Disabled" }
                    1 { "Enabled" }
                    2 { "AuditMode" }
                    default { "Disabled" }
                }
                
                Set-MpPreference -PUAProtection $prefValue -ErrorAction Stop
                Write-Log "  Restored Windows Defender: PUAProtection = $prefValue" -Level Success
            }
            catch {
                Write-Log "  Could not restore Windows Defender preference: $_" -Level Warning
            }
        }
        
        # Force Group Policy update
        Write-Log "  Forcing Group Policy update..." -Level Info
        & gpupdate /force 2>&1 | Out-Null
        
        Write-Log "PUA Protection state restored successfully" -Level Success
        return $true
    }
    catch {
        Write-Log "Failed to restore backup: $_" -Level Error
        return $false
    }
}

# ============================================================================
# DETECTION FUNCTIONS
# ============================================================================

function Get-PUAProtectionStatus {
    Write-Log "Detecting current PUA Protection status..." -Level Info
    
    $status = @{
        GroupPolicyExists = $false
        GroupPolicyValue = $null
        DefenderPreference = $null
        DefenderServiceStatus = $null
        OverallStatus = $null
    }
    
    # Check Group Policy
    if (Test-Path $Script:GroupPolicyPath) {
        $gpValue = Get-ItemProperty -Path $Script:GroupPolicyPath -Name $Script:GroupPolicyValue -ErrorAction SilentlyContinue
        if ($null -ne $gpValue) {
            $status.GroupPolicyExists = $true
            $status.GroupPolicyValue = $gpValue.$Script:GroupPolicyValue
            
            $gpStatus = switch ($status.GroupPolicyValue) {
                0 { "DISABLED" }
                1 { "ENABLED" }
                2 { "AUDIT MODE" }
                default { "UNKNOWN: $($status.GroupPolicyValue)" }
            }
            Write-Log "  Group Policy: PUAProtection = $($status.GroupPolicyValue) ($gpStatus)" -Level Info
        }
    }
    
    # Check Windows Defender preference
    try {
        $mpPref = Get-MpPreference -ErrorAction SilentlyContinue
        if ($null -ne $mpPref) {
            $status.DefenderPreference = $mpPref.PUAProtection
            
            $defStatus = switch ($status.DefenderPreference) {
                0 { "DISABLED" }
                1 { "ENABLED" }
                2 { "AUDIT MODE" }
                default { "UNKNOWN: $($status.DefenderPreference)" }
            }
            Write-Log "  Windows Defender: PUAProtection = $($status.DefenderPreference) ($defStatus)" -Level Info
        }
        
        # Check Defender service
        $defenderService = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
        if ($defenderService) {
            $status.DefenderServiceStatus = $defenderService.Status
            Write-Log "  Windows Defender Service: $($status.DefenderServiceStatus)" -Level Info
        }
    }
    catch {
        Write-Log "  Could not retrieve Windows Defender status: $_" -Level Warning
    }
    
    # Determine overall status
    if ($status.GroupPolicyExists) {
        if ($status.GroupPolicyValue -eq 0) {
            $status.OverallStatus = "DISABLED (Managed by Group Policy)"
        } elseif ($status.GroupPolicyValue -eq 1) {
            $status.OverallStatus = "ENABLED (Managed by Group Policy)"
        } elseif ($status.GroupPolicyValue -eq 2) {
            $status.OverallStatus = "AUDIT MODE (Managed by Group Policy)"
        }
    } else {
        if ($null -eq $status.DefenderPreference) {
            $status.OverallStatus = "Unknown (Windows Defender not accessible)"
        } elseif ($status.DefenderPreference -eq 0) {
            $status.OverallStatus = "DISABLED (User-controlled)"
        } elseif ($status.DefenderPreference -eq 1) {
            $status.OverallStatus = "ENABLED (User-controlled)"
        } elseif ($status.DefenderPreference -eq 2) {
            $status.OverallStatus = "AUDIT MODE (User-controlled)"
        }
    }
    
    Write-Log "  Overall Status: $($status.OverallStatus)" -Level Info
    
    return $status
}

# ============================================================================
# DISABLE FUNCTIONS
# ============================================================================

function Disable-PUAProtectionDeviceLevel {
    Write-Log "Disabling PUA Protection at device level..." -Level Info
    
    $success = $true
    
    # Step 1: Set Group Policy registry value to 0 (disabled)
    try {
        Write-Log "  Setting Group Policy registry value..." -Level Info
        
        # Create registry path if it doesn't exist
        if (-not (Test-Path $Script:GroupPolicyPath)) {
            New-Item -Path $Script:GroupPolicyPath -Force | Out-Null
            Write-Log "    Created registry path: $Script:GroupPolicyPath" -Level Info
        }
        
        # Set PUAProtection to 0 (disabled)
        Set-ItemProperty -Path $Script:GroupPolicyPath -Name $Script:GroupPolicyValue -Value 0 -Type DWord -Force
        Write-Log "    ✓ Set PUAProtection = 0 (DISABLED)" -Level Success
    }
    catch {
        Write-Log "    ✗ Failed to set Group Policy value: $_" -Level Error
        $success = $false
    }
    
    # Step 2: Disable via Windows Defender PowerShell
    try {
        Write-Log "  Disabling via Windows Defender..." -Level Info
        
        $defenderService = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
        
        if ($null -eq $defenderService) {
            Write-Log "    Windows Defender service not found" -Level Warning
            Write-Log "    (May be using third-party antivirus)" -Level Info
        } elseif ($defenderService.Status -ne 'Running') {
            Write-Log "    Windows Defender service is not running" -Level Warning
        } else {
            Set-MpPreference -PUAProtection Disabled -ErrorAction Stop
            Write-Log "    ✓ Windows Defender PUA Protection disabled" -Level Success
        }
    }
    catch {
        Write-Log "    ⚠ Could not disable via Windows Defender: $_" -Level Warning
        Write-Log "    (Group Policy setting will still apply)" -Level Info
    }
    
    return $success
}

function Verify-DisableOperation {
    Write-Log "Verifying disable operation..." -Level Info
    
    $success = $true
    
    # Verify Group Policy value
    $gpValue = Get-ItemProperty -Path $Script:GroupPolicyPath -Name $Script:GroupPolicyValue -ErrorAction SilentlyContinue
    
    if ($null -eq $gpValue) {
        Write-Log "  ✗ Group Policy value not found!" -Level Error
        $success = $false
    } elseif ($gpValue.$Script:GroupPolicyValue -eq 0) {
        Write-Log "  ✓ Group Policy: PUAProtection = 0 (DISABLED)" -Level Success
    } else {
        Write-Log "  ✗ Group Policy: PUAProtection = $($gpValue.$Script:GroupPolicyValue) (Expected: 0)" -Level Error
        $success = $false
    }
    
    # Verify Windows Defender preference
    try {
        $mpPref = Get-MpPreference -ErrorAction SilentlyContinue
        if ($null -ne $mpPref) {
            if ($mpPref.PUAProtection -eq 0) {
                Write-Log "  ✓ Windows Defender: PUAProtection = 0 (DISABLED)" -Level Success
            } else {
                Write-Log "  ⚠ Windows Defender: PUAProtection = $($mpPref.PUAProtection)" -Level Warning
                Write-Log "    (Group Policy will override this)" -Level Info
            }
        }
    }
    catch {
        Write-Log "  ⚠ Could not verify Windows Defender preference" -Level Warning
    }
    
    return $success
}

# ============================================================================
# MAIN SCRIPT
# ============================================================================

Write-Log "========================================" -Level Info
Write-Log "Disable PUA Protection - Device Level" -Level Info
Write-Log "========================================" -Level Info
Write-Log ""

# Check for rollback
if ($Rollback) {
    Write-Log "ROLLBACK MODE - Searching for backup files..." -Level Warning
    
    $backupFiles = Get-ChildItem -Path $env:TEMP -Filter "PUAProtection-DeviceLevel-Backup-*.json" | 
                   Sort-Object LastWriteTime -Descending
    
    if ($backupFiles.Count -eq 0) {
        Write-Log "No backup files found in $env:TEMP" -Level Error
        Write-Log "Cannot perform rollback without backup" -Level Error
        exit 1
    }
    
    $latestBackup = $backupFiles[0]
    Write-Log "Found backup: $($latestBackup.FullName)" -Level Info
    Write-Log "Backup date: $($latestBackup.LastWriteTime)" -Level Info
    Write-Log ""
    
    $restored = Restore-PUAProtectionState -BackupFilePath $latestBackup.FullName
    
    if ($restored) {
        Write-Log ""
        Write-Log "Rollback completed successfully" -Level Success
        Write-Log ""
        
        # Show current status
        Get-PUAProtectionStatus | Out-Null
    } else {
        Write-Log ""
        Write-Log "Rollback failed" -Level Error
        exit 1
    }
    
    exit 0
}

# Show current status
Write-Log "Current Configuration:" -Level Info
$currentStatus = Get-PUAProtectionStatus
Write-Log ""

# Security warning
Write-Log "========================================" -Level Warning
Write-Log "SECURITY WARNING" -Level Warning
Write-Log "========================================" -Level Warning
Write-Log "Disabling PUA Protection will:" -Level Warning
Write-Log "  - Allow potentially unwanted applications to run" -Level Warning
Write-Log "  - Remove protection against unwanted software" -Level Warning
Write-Log "  - Disable blocking of cryptominers and adware" -Level Warning
Write-Log "  - Lock the setting via Group Policy (users cannot enable)" -Level Warning
Write-Log ""
Write-Log "This should only be done for:" -Level Warning
Write-Log "  - Testing purposes" -Level Warning
Write-Log "  - Troubleshooting application compatibility" -Level Warning
Write-Log "  - Enterprise policy requirements" -Level Warning
Write-Log "  - When using third-party security solutions" -Level Warning
Write-Log "========================================" -Level Warning
Write-Log ""

# Create backup
$backupFile = Backup-CurrentState
Write-Log ""

# Perform disable operation
Write-Log "STEP 1: Disable PUA Protection" -Level Info
Write-Log "========================================" -Level Info

$disableSuccess = Disable-PUAProtectionDeviceLevel
Write-Log ""

# Verify operation
Write-Log "STEP 2: Verify Disable Operation" -Level Info
Write-Log "========================================" -Level Info

$verifySuccess = Verify-DisableOperation
Write-Log ""

# Force Group Policy update
Write-Log "STEP 3: Force Group Policy Update" -Level Info
Write-Log "========================================" -Level Info

try {
    Write-Log "Running: gpupdate /force" -Level Info
    $gpResult = & gpupdate /force 2>&1
    Write-Log "Group Policy update completed" -Level Success
}
catch {
    Write-Log "Failed to run gpupdate: $_" -Level Warning
}

Write-Log ""

# Show final status
Write-Log "STEP 4: Final Status" -Level Info
Write-Log "========================================" -Level Info

$finalStatus = Get-PUAProtectionStatus
Write-Log ""

# Final Summary
Write-Log "========================================" -Level Success
Write-Log "OPERATION COMPLETE" -Level Success
Write-Log "========================================" -Level Success
Write-Log ""

if ($disableSuccess -and $verifySuccess) {
    Write-Log "✓ PUA Protection has been DISABLED" -Level Success
    Write-Log "✓ Setting is managed by Group Policy" -Level Success
    Write-Log "✓ Users cannot enable this setting" -Level Success
    Write-Log ""
    Write-Log "Expected Windows Security UI behavior:" -Level Info
    Write-Log "  - 'Potentially unwanted app blocking' will show as OFF" -Level Info
    Write-Log "  - Toggle will be greyed out" -Level Info
    Write-Log "  - Message: 'This setting is managed by your administrator'" -Level Info
} else {
    Write-Log "⚠ Operation completed with warnings" -Level Warning
    Write-Log "Check the log for details" -Level Info
}

Write-Log ""
Write-Log "⚠️ A SYSTEM RESTART IS RECOMMENDED ⚠️" -Level Warning
Write-Log "Group Policy changes may require a restart to fully take effect" -Level Info
Write-Log ""

Write-Log "To restore previous settings:" -Level Info
Write-Log "  .\Disable-PUAProtection-DeviceLevel.ps1 -Rollback" -Level Cyan
Write-Log ""

Write-Log "Backup: $backupFile" -Level Info
Write-Log "Log: $Script:LogFile" -Level Info
Write-Log ""
Write-Log "========================================" -Level Info
Write-Log "Script completed" -Level Success
Write-Log "========================================" -Level Info
