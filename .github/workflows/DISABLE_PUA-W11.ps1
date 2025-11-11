#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Disables Potentially Unwanted App (PUA) blocking in Windows Security.

.DESCRIPTION
    This script disables the PUA protection feature in Windows Defender by setting
    the PUAProtection preference to 0 (Disabled). It includes rollback capability
    to restore the previous setting if needed.

.PARAMETER CreateRestorePoint
    If specified, creates a system restore point before making changes.

.EXAMPLE
    .\Disable-PUAProtection.ps1
    Disables PUA protection without creating a restore point.

.EXAMPLE
    .\Disable-PUAProtection.ps1 -CreateRestorePoint
    Disables PUA protection and creates a system restore point first.

.NOTES
    Author: AI+IT Support
    Requires: Windows 10/11, Administrator privileges
    
    PUA Protection Values:
    - 0 = Disabled
    - 1 = Enabled (Block mode)
    - 2 = Audit mode (Detect only)
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$CreateRestorePoint
)

# Script configuration
$ErrorActionPreference = 'Stop'
$ScriptName = 'Disable-PUAProtection'
$LogPath = Join-Path $env:TEMP "$ScriptName-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$RollbackFile = Join-Path $env:TEMP "$ScriptName-Rollback.txt"

# Logging function
function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )
    
    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $LogMessage = "[$Timestamp] [$Level] $Message"
    
    # Output to console with color
    switch ($Level) {
        'ERROR'   { Write-Host $LogMessage -ForegroundColor Red }
        'WARNING' { Write-Host $LogMessage -ForegroundColor Yellow }
        'SUCCESS' { Write-Host $LogMessage -ForegroundColor Green }
        default   { Write-Host $LogMessage }
    }
    
    # Output to log file
    Add-Content -Path $LogPath -Value $LogMessage
}

# Main execution
try {
    Write-Log "=== $ScriptName Script Started ===" -Level INFO
    Write-Log "Log file: $LogPath" -Level INFO
    Write-Log "Rollback file: $RollbackFile" -Level INFO
    
    # Verify Windows Defender is available
    Write-Log "Checking Windows Defender availability..." -Level INFO
    $defenderStatus = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
    
    if (-not $defenderStatus) {
        throw "Windows Defender service not found. This script requires Windows Defender."
    }
    
    if ($defenderStatus.Status -ne 'Running') {
        Write-Log "Windows Defender service is not running (Status: $($defenderStatus.Status))" -Level WARNING
    }
    
    # Get current PUA protection setting
    Write-Log "Retrieving current PUA protection setting..." -Level INFO
    $currentSetting = Get-MpPreference | Select-Object -ExpandProperty PUAProtection
    
    Write-Log "Current PUA Protection setting: $currentSetting" -Level INFO
    
    # Save current setting for rollback
    $rollbackData = @{
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        PreviousSetting = $currentSetting
    }
    $rollbackData | ConvertTo-Json | Set-Content -Path $RollbackFile
    Write-Log "Current setting saved to rollback file" -Level INFO
    
    # Create restore point if requested
    if ($CreateRestorePoint) {
        Write-Log "Creating system restore point..." -Level INFO
        try {
            $restoreDescription = "$ScriptName - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            Checkpoint-Computer -Description $restoreDescription -RestorePointType MODIFY_SETTINGS
            Write-Log "System restore point created successfully" -Level SUCCESS
        }
        catch {
            Write-Log "Failed to create restore point: $($_.Exception.Message)" -Level WARNING
            Write-Log "Continuing without restore point..." -Level WARNING
        }
    }
    
    # Check if change is needed
    if ($currentSetting -eq 0) {
        Write-Log "PUA Protection is already disabled (0). No changes needed." -Level SUCCESS
        exit 0
    }
    
    # Disable PUA protection
    if ($PSCmdlet.ShouldProcess("Windows Defender", "Disable PUA Protection")) {
        Write-Log "Disabling PUA Protection..." -Level INFO
        
        Set-MpPreference -PUAProtection 0
        
        # Verify the change
        Start-Sleep -Seconds 2
        $newSetting = Get-MpPreference | Select-Object -ExpandProperty PUAProtection
        
        if ($newSetting -eq 0) {
            Write-Log "PUA Protection successfully disabled" -Level SUCCESS
            Write-Log "Previous setting ($currentSetting) -> New setting ($newSetting)" -Level SUCCESS
        }
        else {
            throw "Failed to disable PUA Protection. Current setting is still: $newSetting"
        }
    }
    
    Write-Log "=== Script completed successfully ===" -Level SUCCESS
    Write-Log "" -Level INFO
    Write-Log "To verify the change, run: Get-MpPreference | Select-Object PUAProtection" -Level INFO
    Write-Log "To rollback this change, run: .\Rollback-PUAProtection.ps1" -Level INFO
    
}
catch {
    Write-Log "=== Script failed with error ===" -Level ERROR
    Write-Log "Error: $($_.Exception.Message)" -Level ERROR
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level ERROR
    exit 1
}