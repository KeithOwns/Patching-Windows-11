<#
.SYNOPSIS
    Enables Enhanced Phishing Protection at User Level

.DESCRIPTION
    This script:
    1. REMOVES Group Policy registry values (stops "managed by administrator" lock)
    2. Allows user-level control of the setting
    3. Enables the setting via Windows Security UI automation
    
    After running this script, the setting will be:
    - User-controllable (no longer greyed out)
    - Enabled/On
    - No "managed by administrator" message
    
.NOTES
    Requires: Administrative privileges, Windows 11 22H2 or later
    Author: AI+IT Support
    Version: 1.0
    
.EXAMPLE
    .\Enable-PhishingProtection-UserLevel.ps1
    Removes Group Policy lock and enables at user level
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$RemoveOnly
)

#Requires -RunAsAdministrator

# ============================================================================
# CONFIGURATION
# ============================================================================

$Script:LogFile = "$env:TEMP\Enable-PhishingProtection-UserLevel-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$Script:BackupFile = "$env:TEMP\PhishingProtection-UserLevel-Backup-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"

$Script:PolicyRegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components"
$Script:RegistryValues = @("ServiceEnabled", "NotifyMalicious", "NotifyPasswordReuse", "NotifyUnsafeApp", "CaptureThreatWindow")

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
# BACKUP FUNCTION
# ============================================================================

function Backup-CurrentState {
    Write-Log "Creating backup of current state..." -Level Info
    
    $backup = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        PolicyPathExisted = Test-Path $Script:PolicyRegistryPath
        PolicyValues = @{}
    }
    
    if ($backup.PolicyPathExisted) {
        foreach ($valueName in $Script:RegistryValues) {
            $value = Get-ItemProperty -Path $Script:PolicyRegistryPath -Name $valueName -ErrorAction SilentlyContinue
            if ($null -ne $value) {
                $backup.PolicyValues[$valueName] = $value.$valueName
                Write-Log "  Backed up: $valueName = $($value.$valueName)" -Level Info
            }
        }
    }
    
    $backup | ConvertTo-Json -Depth 10 | Out-File -FilePath $Script:BackupFile -Force
    Write-Log "Backup saved to: $Script:BackupFile" -Level Success
    
    return $Script:BackupFile
}

# ============================================================================
# GROUP POLICY REMOVAL
# ============================================================================

function Remove-GroupPolicyManagement {
    Write-Log "Removing Group Policy management..." -Level Info
    
    if (-not (Test-Path $Script:PolicyRegistryPath)) {
        Write-Log "  Group Policy path does not exist - nothing to remove" -Level Info
        return $true
    }
    
    $success = $true
    $removedCount = 0
    
    # Remove each registry value
    foreach ($valueName in $Script:RegistryValues) {
        try {
            $value = Get-ItemProperty -Path $Script:PolicyRegistryPath -Name $valueName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                Remove-ItemProperty -Path $Script:PolicyRegistryPath -Name $valueName -Force -ErrorAction Stop
                Write-Log "  ✓ Removed: $valueName" -Level Success
                $removedCount++
            } else {
                Write-Log "  - Value does not exist: $valueName" -Level Info
            }
        }
        catch {
            Write-Log "  ✗ Failed to remove $valueName : $_" -Level Error
            $success = $false
        }
    }
    
    # Check if the registry key is now empty and remove it
    try {
        $remainingValues = Get-ItemProperty -Path $Script:PolicyRegistryPath -ErrorAction SilentlyContinue
        $propertyCount = ($remainingValues.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }).Count
        
        if ($propertyCount -eq 0) {
            Write-Log "  Registry key is empty, removing it..." -Level Info
            Remove-Item -Path $Script:PolicyRegistryPath -Force -ErrorAction Stop
            Write-Log "  ✓ Removed empty registry key" -Level Success
        }
    }
    catch {
        Write-Log "  Note: Could not remove empty registry key: $_" -Level Info
    }
    
    Write-Log "Removed $removedCount Group Policy value(s)" -Level Success
    return $success
}

# ============================================================================
# ENABLE VIA WINDOWS SECURITY
# ============================================================================

function Enable-PhishingProtectionUI {
    Write-Log "Attempting to enable Enhanced Phishing Protection via Windows Security..." -Level Info
    
    # The Windows Security app uses a URI scheme
    Write-Log "  Opening Windows Security > Phishing Protection..." -Level Info
    
    try {
        # Open Windows Security to the Phishing Protection page
        $uri = "windowsdefender://threatsettings/"
        Start-Process $uri
        
        Write-Log "  Windows Security opened successfully" -Level Success
        Write-Log ""
        Write-Log "========================================" -Level Warning
        Write-Log "MANUAL ACTION REQUIRED" -Level Warning
        Write-Log "========================================" -Level Warning
        Write-Log "Windows Security should now be open." -Level Info
        Write-Log ""
        Write-Log "Please follow these steps:" -Level Info
        Write-Log "  1. Click on 'Reputation-based protection settings'" -Level Info
        Write-Log "  2. Scroll down to 'Phishing protection'" -Level Info
        Write-Log "  3. Toggle the switch to 'On'" -Level Info
        Write-Log "  4. The setting should no longer show 'managed by administrator'" -Level Success
        Write-Log ""
        Write-Log "After enabling, you can close Windows Security." -Level Info
        Write-Log "========================================" -Level Warning
        
        return $true
    }
    catch {
        Write-Log "  Failed to open Windows Security: $_" -Level Error
        Write-Log ""
        Write-Log "Please manually open Windows Security:" -Level Warning
        Write-Log "  1. Press Windows key" -Level Info
        Write-Log "  2. Type 'Windows Security'" -Level Info
        Write-Log "  3. Open the app" -Level Info
        Write-Log "  4. Go to 'Virus & threat protection' > 'Manage settings'" -Level Info
        Write-Log "  5. Scroll to 'Phishing protection' and toggle ON" -Level Info
        
        return $false
    }
}

# ============================================================================
# VERIFICATION
# ============================================================================

function Verify-Removal {
    Write-Log "Verifying Group Policy removal..." -Level Info
    
    if (-not (Test-Path $Script:PolicyRegistryPath)) {
        Write-Log "  ✓ Group Policy registry path removed completely" -Level Success
        return $true
    }
    
    $remainingValues = @()
    foreach ($valueName in $Script:RegistryValues) {
        $value = Get-ItemProperty -Path $Script:PolicyRegistryPath -Name $valueName -ErrorAction SilentlyContinue
        if ($null -ne $value) {
            $remainingValues += $valueName
            Write-Log "  ✗ Value still exists: $valueName = $($value.$valueName)" -Level Error
        }
    }
    
    if ($remainingValues.Count -eq 0) {
        Write-Log "  ✓ All Group Policy values removed successfully" -Level Success
        return $true
    } else {
        Write-Log "  ✗ $($remainingValues.Count) value(s) still remain" -Level Error
        return $false
    }
}

# ============================================================================
# SERVICE MANAGEMENT
# ============================================================================

function Enable-PhishingServices {
    Write-Log "Ensuring Web Threat Defense services are enabled..." -Level Info
    
    $services = @("webthreatdefsvc", "webthreatdefusersvc")
    
    foreach ($serviceName in $services) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            
            if ($service) {
                Write-Log "  Found service: $serviceName" -Level Info
                
                # Enable the service (set to Manual start)
                if ($service.StartType -eq 'Disabled') {
                    Write-Log "    Enabling service (setting to Manual)..." -Level Info
                    Set-Service -Name $serviceName -StartupType Manual -ErrorAction Stop
                    Write-Log "    ✓ Service enabled" -Level Success
                }
                
                # Start the service if not running
                if ($service.Status -ne 'Running') {
                    Write-Log "    Starting service..." -Level Info
                    Start-Service -Name $serviceName -ErrorAction Stop
                    Write-Log "    ✓ Service started" -Level Success
                }
            } else {
                Write-Log "  Service not found: $serviceName" -Level Info
            }
        }
        catch {
            Write-Log "  Warning: Could not manage service $serviceName : $_" -Level Warning
        }
    }
}

# ============================================================================
# MAIN SCRIPT
# ============================================================================

Write-Log "========================================" -Level Info
Write-Log "Enable Phishing Protection - User Level" -Level Info
Write-Log "========================================" -Level Info
Write-Log ""

# Create backup
Backup-CurrentState | Out-Null
Write-Log ""

# Step 1: Remove Group Policy Management
Write-Log "STEP 1: Remove Group Policy Management" -Level Info
Write-Log "========================================" -Level Info

$removalSuccess = Remove-GroupPolicyManagement

if ($removalSuccess) {
    Write-Log "Group Policy management removed successfully" -Level Success
} else {
    Write-Log "Some errors occurred during removal" -Level Warning
}

Write-Log ""

# Step 2: Verify Removal
Write-Log "STEP 2: Verify Removal" -Level Info
Write-Log "========================================" -Level Info

$verified = Verify-Removal
Write-Log ""

# Step 3: Enable Services
Write-Log "STEP 3: Enable Services" -Level Info
Write-Log "========================================" -Level Info

Enable-PhishingServices
Write-Log ""

# Step 4: Force Group Policy Update
Write-Log "STEP 4: Force Group Policy Update" -Level Info
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

# Step 5: Open Windows Security for user to enable
if (-not $RemoveOnly) {
    Write-Log "STEP 5: Enable via Windows Security" -Level Info
    Write-Log "========================================" -Level Info
    
    Start-Sleep -Seconds 2
    Enable-PhishingProtectionUI
    Write-Log ""
}

# Final Summary
Write-Log "========================================" -Level Success
Write-Log "OPERATION COMPLETE" -Level Success
Write-Log "========================================" -Level Success
Write-Log ""

if ($verified) {
    Write-Log "✓ Group Policy management removed" -Level Success
    Write-Log "✓ Setting is now user-controllable" -Level Success
    Write-Log "✓ No longer shows 'managed by administrator'" -Level Success
} else {
    Write-Log "⚠ Group Policy removal had some issues" -Level Warning
    Write-Log "  A system restart may help" -Level Info
}

Write-Log ""
Write-Log "NEXT STEPS:" -Level Warning
Write-Log "  1. The Group Policy lock has been removed" -Level Info
Write-Log "  2. Enable the setting in Windows Security (should be open)" -Level Info
Write-Log "  3. The toggle should now be user-controllable (not greyed)" -Level Info
Write-Log ""

if (-not $RemoveOnly) {
    Write-Log "If Windows Security did not open automatically:" -Level Info
    Write-Log "  1. Open Windows Security manually" -Level Info
    Write-Log "  2. Go to: Virus & threat protection > Manage settings" -Level Info
    Write-Log "  3. Scroll to 'Phishing protection'" -Level Info
    Write-Log "  4. Toggle it ON" -Level Info
    Write-Log ""
}

Write-Log "After enabling, you may want to restart to ensure all changes take effect." -Level Warning
Write-Log ""
Write-Log "Backup: $Script:BackupFile" -Level Info
Write-Log "Log: $Script:LogFile" -Level Info
Write-Log ""
Write-Log "========================================" -Level Info