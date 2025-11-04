#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
    Enables System Protection and Creates a System Restore Point in Windows 11
.DESCRIPTION
    This script first enables System Protection on the C: drive if not already enabled,
    then creates a restore point with a custom description and timestamp.
    Must be run as Administrator.
#>

# --- Helper Functions (from 02-Update_Config-Win11.ps1) ---

function Write-StatusIcon {
    param(
        [Parameter(Mandatory)]
        [bool]$IsEnabled,
        
        [Parameter(Mandatory = $false)]
        [string]$Severity = "Warning"
    )
    
    if ($IsEnabled) {
        Write-Host " " -NoNewline -BackgroundColor DarkCyan -ForegroundColor Black
        Write-Host "✓" -NoNewline -BackgroundColor DarkCyan -ForegroundColor Black
        Write-Host " " -NoNewline -BackgroundColor DarkCyan -ForegroundColor Black
        Write-Host " " -NoNewline
    } else {
        $color = switch ($Severity) {
            "Critical" { "Red" }
            "Warning" { "Yellow" }
            "Info" { "Gray" }
            default { "Yellow" }
        }
        Write-Host " ✗ " -NoNewline -ForegroundColor $color
    }
}

function Write-SectionHeader {
    param(
        [Parameter(Mandatory)]
        [string]$Title,
        
        [Parameter(Mandatory = $false)]
        [string]$Icon = "⚙️"
    )
    
    Write-Host "`n$Icon " -NoNewline -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor White
    Write-Host ("─" * 60) -ForegroundColor DarkGray
}

# --- Main ---
Clear-Host
Write-Host "`n" -NoNewline
Write-Host ("═" * 60) -ForegroundColor Blue
Write-Host "  SYSTEM RESTORE POINT CREATOR" -ForegroundColor White
Write-Host ("═" * 60) -ForegroundColor Blue

# ============================================================================
# STEP 1: ENABLE SYSTEM PROTECTION
# ============================================================================
Write-SectionHeader "STEP 1: Enabling System Protection" -Icon "🛡️"
Write-Host "  Attempting to enable System Protection on the C: drive..." -ForegroundColor Gray

try {
    Enable-ComputerRestore -Drive "C:\"
    Write-Host "  " -NoNewline; Write-StatusIcon -IsEnabled $true
    Write-Host " Successfully enabled System Protection on C:\" -ForegroundColor White
    Write-Host "  You can verify this in: Control Panel > System > System Protection.`n" -ForegroundColor Gray
    
    # Wait a moment for the system to register the change
    Start-Sleep -Seconds 2
}
catch {
    Write-Host "  " -NoNewline; Write-StatusIcon -IsEnabled $false -Severity "Warning"
    Write-Host " Failed to enable System Protection." -ForegroundColor White
    Write-Host "  Note: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "  (This is often not an error if it's already enabled).`n" -ForegroundColor Yellow
}

# ============================================================================
# STEP 2: CREATE RESTORE POINT
# ============================================================================
Write-SectionHeader "STEP 2: Creating System Restore Point" -Icon "💾"

# Create restore point description with timestamp
$description = "Manual Restore Point - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "  Description: $description" -ForegroundColor Gray

try {
    # Create the restore point
    Checkpoint-Computer -Description $description -RestorePointType "MODIFY_SETTINGS"
    
    Write-Host "`n  " -NoNewline; Write-StatusIcon -IsEnabled $true
    Write-Host " Restore Point created successfully!" -ForegroundColor White
    Write-Host "  You can view it in: Control Panel > System > System Protection > System Restore" -ForegroundColor Gray
}
catch {
    Write-Host "`n  " -NoNewline; Write-StatusIcon -IsEnabled $false -Severity "Critical"
    Write-Host " Failed to create restore point." -ForegroundColor White
    Write-Host "  [ERROR] " -NoNewline -ForegroundColor Red
    Write-Host "Error details: $($_.Exception.Message)" -ForegroundColor White
    
    # Common issues and solutions
    Write-Host "`n  Possible solutions:" -ForegroundColor Yellow
    Write-Host "  1. Ensure you have sufficient disk space allocated for System Protection" -ForegroundColor Gray
    Write-Host "  2. Check if you've created a restore point recently (Windows limits frequency)" -ForegroundColor Gray
    Write-Host "  3. Restart your computer and try again" -ForegroundColor Gray
}

# --- Footer ---
Write-Host "`n" -NoNewline
Write-Host ("─" * 60) -ForegroundColor DarkGray
# Set the timestamp this script was last edited
$lastEditedTimestamp = "2025-11-03 16:16:00" 
Write-Host "Last Edited: $lastEditedTimestamp" -ForegroundColor Green
Write-Host "www.AIIT.support all rights reserved" -ForegroundColor Green
Write-Host ("─" * 60) -ForegroundColor DarkGray
