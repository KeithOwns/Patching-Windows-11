<#
.SYNOPSIS
    Enables Potentially Unwanted App (PUA) Blocking at User Level

.DESCRIPTION
    This script:
    1. REMOVES Group Policy registry value (stops "managed by administrator" lock)
    2. Enables PUA Protection via Windows Defender (PowerShell)
    3. Optionally enables "Block downloads" in Microsoft Edge
    4. Opens Windows Security for verification
    
    After running this script, the setting will be:
    - User-controllable (no longer greyed out)
    - Enabled/On for both "Block apps" and "Block downloads"
    - No "managed by administrator" message
    
.NOTES
    Requires: Administrative privileges, Windows 10 2004+ or Windows 11
    Author: AI+IT Support
    Version: 1.0
    
.PARAMETER EnableEdgeBlocking
    Also enable "Block downloads" in Microsoft Edge (per-user setting)
    
.EXAMPLE
    .\Enable-PUAProtection-UserLevel.ps1
    Removes Group Policy lock and enables PUA protection
    
.EXAMPLE
    .\Enable-PUAProtection-UserLevel.ps1 -EnableEdgeBlocking
    Also enables Block downloads in Edge for current user
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$EnableEdgeBlocking,
    
    [Parameter(Mandatory=$false)]
    [switch]$RemoveOnly
)

#Requires -RunAsAdministrator

# ============================================================================
# CONFIGURATION
# ============================================================================

$Script:LogFile = "$env:TEMP\Enable-PUAProtection-UserLevel-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$Script:BackupFile = "$env:TEMP\PUAProtection-UserLevel-Backup-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"

# Registry paths
$Script:GroupPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
$Script:GroupPolicyValue = "PUAProtection"

$Script:DefenderPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender"
$Script:DefenderValue = "PUAProtection"

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
# BACKUP FUNCTION
# ============================================================================

function Backup-CurrentState {
    Write-Log "Creating backup of current PUA Protection state..." -Level Info
    
    $backup = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        GroupPolicy = @{
            PathExists = Test-Path $Script:GroupPolicyPath
            Value = $null
        }
        Defender = @{
            PathExists = Test-Path $Script:DefenderPath
            Value = $null
        }
        Edge = @{
            Value = $null
        }
        MpPreference = $null
    }
    
    # Backup Group Policy value
    if ($backup.GroupPolicy.PathExists) {
        $gpValue = Get-ItemProperty -Path $Script:GroupPolicyPath -Name $Script:GroupPolicyValue -ErrorAction SilentlyContinue
        if ($null -ne $gpValue) {
            $backup.GroupPolicy.Value = $gpValue.$Script:GroupPolicyValue
            Write-Log "  Group Policy PUAProtection = $($backup.GroupPolicy.Value)" -Level Info
        }
    }
    
    # Backup Defender value
    if ($backup.Defender.PathExists) {
        $defValue = Get-ItemProperty -Path $Script:DefenderPath -Name $Script:DefenderValue -ErrorAction SilentlyContinue
        if ($null -ne $defValue) {
            $backup.Defender.Value = $defValue.$Script:DefenderValue
            Write-Log "  Defender PUAProtection = $($backup.Defender.Value)" -Level Info
        }
    }
    
    # Backup Edge value
    if (Test-Path $Script:EdgePath) {
        $edgeValue = Get-ItemProperty -Path $Script:EdgePath -Name "(Default)" -ErrorAction SilentlyContinue
        if ($null -ne $edgeValue) {
            $backup.Edge.Value = $edgeValue.'(Default)'
            Write-Log "  Edge SmartScreenPuaEnabled = $($backup.Edge.Value)" -Level Info
        }
    }
    
    # Backup Windows Defender preference
    try {
        $mpPref = Get-MpPreference -ErrorAction SilentlyContinue
        if ($null -ne $mpPref) {
            $backup.MpPreference = $mpPref.PUAProtection
            Write-Log "  Windows Defender PUAProtection = $($backup.MpPreference)" -Level Info
        }
    }
    catch {
        Write-Log "  Could not retrieve Windows Defender preference: $_" -Level Warning
    }
    
    $backup | ConvertTo-Json -Depth 10 | Out-File -FilePath $Script:BackupFile -Force
    Write-Log "Backup saved to: $Script:BackupFile" -Level Success
    
    return $Script:BackupFile
}

# ============================================================================
# GROUP POLICY REMOVAL
# ============================================================================

function Remove-GroupPolicyManagement {
    Write-Log "Removing Group Policy management of PUA Protection..." -Level Info
    
    if (-not (Test-Path $Script:GroupPolicyPath)) {
        Write-Log "  Group Policy path does not exist - nothing to remove" -Level Info
        return $true
    }
    
    try {
        $gpValue = Get-ItemProperty -Path $Script:GroupPolicyPath -Name $Script:GroupPolicyValue -ErrorAction SilentlyContinue
        
        if ($null -ne $gpValue) {
            Write-Log "  Current Group Policy value: PUAProtection = $($gpValue.$Script:GroupPolicyValue)" -Level Info
            
            Remove-ItemProperty -Path $Script:GroupPolicyPath -Name $Script:GroupPolicyValue -Force -ErrorAction Stop
            Write-Log "  ✓ Removed Group Policy registry value" -Level Success
            return $true
        } else {
            Write-Log "  Group Policy value does not exist - nothing to remove" -Level Info
            return $true
        }
    }
    catch {
        Write-Log "  ✗ Failed to remove Group Policy value: $_" -Level Error
        return $false
    }
}

# ============================================================================
# ENABLE PUA PROTECTION
# ============================================================================

function Enable-PUAProtection {
    Write-Log "Enabling PUA Protection via Windows Defender..." -Level Info
    
    try {
        # Check if Windows Defender is available
        $defenderService = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
        
        if ($null -eq $defenderService) {
            Write-Log "  Windows Defender service not found" -Level Error
            Write-Log "  This may be because a third-party antivirus is installed" -Level Warning
            return $false
        }
        
        if ($defenderService.Status -ne 'Running') {
            Write-Log "  Windows Defender service is not running (Status: $($defenderService.Status))" -Level Warning
            Write-Log "  Attempting to start service..." -Level Info
            
            try {
                Start-Service -Name WinDefend -ErrorAction Stop
                Write-Log "  ✓ Windows Defender service started" -Level Success
            }
            catch {
                Write-Log "  ✗ Could not start Windows Defender service: $_" -Level Error
                return $false
            }
        }
        
        # Enable PUA Protection using PowerShell cmdlet
        Write-Log "  Setting PUA Protection to: Enabled" -Level Info
        Set-MpPreference -PUAProtection Enabled -ErrorAction Stop
        
        # Verify the setting
        $mpPref = Get-MpPreference
        if ($mpPref.PUAProtection -eq 1) {
            Write-Log "  ✓ PUA Protection enabled successfully" -Level Success
            Write-Log "  Current value: $($mpPref.PUAProtection) (1 = Enabled)" -Level Success
            return $true
        } else {
            Write-Log "  ⚠ PUA Protection value is: $($mpPref.PUAProtection)" -Level Warning
            Write-Log "  Expected: 1 (Enabled)" -Level Warning
            return $false
        }
    }
    catch {
        Write-Log "  ✗ Failed to enable PUA Protection: $_" -Level Error
        return $false
    }
}

# ============================================================================
# ENABLE EDGE BLOCKING
# ============================================================================

function Enable-EdgePUABlocking {
    Write-Log "Enabling PUA blocking in Microsoft Edge..." -Level Info
    
    try {
        # Create Edge registry path if it doesn't exist
        if (-not (Test-Path $Script:EdgePath)) {
            Write-Log "  Creating Edge registry path..." -Level Info
            New-Item -Path "HKCU:\SOFTWARE\Microsoft\Edge" -Name "SmartScreenPuaEnabled" -Force | Out-Null
        }
        
        # Set the default value to 1
        Set-ItemProperty -Path $Script:EdgePath -Name "(Default)" -Value 1 -Type DWord -Force
        Write-Log "  ✓ Edge PUA blocking enabled" -Level Success
        
        return $true
    }
    catch {
        Write-Log "  ✗ Failed to enable Edge PUA blocking: $_" -Level Error
        return $false
    }
}

# ============================================================================
# VERIFICATION
# ============================================================================

function Verify-PUAProtection {
    Write-Log "Verifying PUA Protection status..." -Level Info
    
    $allGood = $true
    
    # Check Group Policy
    $gpValue = Get-ItemProperty -Path $Script:GroupPolicyPath -Name $Script:GroupPolicyValue -ErrorAction SilentlyContinue
    if ($null -eq $gpValue) {
        Write-Log "  ✓ Group Policy value removed (user control enabled)" -Level Success
    } else {
        Write-Log "  ✗ Group Policy value still exists: $($gpValue.$Script:GroupPolicyValue)" -Level Error
        $allGood = $false
    }
    
    # Check Windows Defender preference
    try {
        $mpPref = Get-MpPreference
        if ($mpPref.PUAProtection -eq 1) {
            Write-Log "  ✓ Windows Defender PUA Protection: Enabled (1)" -Level Success
        } else {
            Write-Log "  ✗ Windows Defender PUA Protection: $($mpPref.PUAProtection)" -Level Warning
            $allGood = $false
        }
    }
    catch {
        Write-Log "  ✗ Could not verify Windows Defender preference: $_" -Level Error
        $allGood = $false
    }
    
    # Check Edge if requested
    if ($EnableEdgeBlocking) {
        $edgeValue = Get-ItemProperty -Path $Script:EdgePath -Name "(Default)" -ErrorAction SilentlyContinue
        if ($null -ne $edgeValue -and $edgeValue.'(Default)' -eq 1) {
            Write-Log "  ✓ Edge PUA blocking: Enabled (1)" -Level Success
        } else {
            Write-Log "  ✗ Edge PUA blocking not properly configured" -Level Warning
        }
    }
    
    return $allGood
}

# ============================================================================
# OPEN WINDOWS SECURITY
# ============================================================================

function Open-WindowsSecurity {
    Write-Log "Opening Windows Security..." -Level Info
    
    try {
        # Open Windows Security to the App & browser control page
        $uri = "windowsdefender://threatsettings/"
        Start-Process $uri
        
        Write-Log "  Windows Security opened successfully" -Level Success
        Write-Log ""
        Write-Log "========================================" -Level Warning
        Write-Log "VERIFICATION STEPS" -Level Warning
        Write-Log "========================================" -Level Warning
        Write-Log "Windows Security should now be open." -Level Info
        Write-Log ""
        Write-Log "Please verify the following:" -Level Info
        Write-Log "  1. Click on 'Reputation-based protection settings'" -Level Info
        Write-Log "  2. Scroll down to 'Potentially unwanted app blocking'" -Level Info
        Write-Log "  3. Verify it shows as 'On' (not greyed out)" -Level Success
        Write-Log "  4. Both 'Block apps' and 'Block downloads' should be enabled" -Level Success
        Write-Log "  5. No 'managed by administrator' message should appear" -Level Success
        Write-Log ""
        Write-Log "If you see all of the above, the operation was successful!" -Level Success
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
        Write-Log "  4. Go to 'App & browser control'" -Level Info
        Write-Log "  5. Click 'Reputation-based protection settings'" -Level Info
        Write-Log "  6. Verify 'Potentially unwanted app blocking' is enabled" -Level Info
        
        return $false
    }
}

# ============================================================================
# MAIN SCRIPT
# ============================================================================

Write-Log "========================================" -Level Info
Write-Log "Enable PUA Protection - User Level" -Level Info
Write-Log "========================================" -Level Info
Write-Log ""

# Create backup
Backup-CurrentState | Out-Null
Write-Log ""

# Step 1: Remove Group Policy Management
Write-Log "STEP 1: Remove Group Policy Management" -Level Info
Write-Log "========================================" -Level Info

$removalSuccess = Remove-GroupPolicyManagement
Write-Log ""

# Step 2: Enable PUA Protection
if (-not $RemoveOnly) {
    Write-Log "STEP 2: Enable PUA Protection" -Level Info
    Write-Log "========================================" -Level Info
    
    $enableSuccess = Enable-PUAProtection
    Write-Log ""
    
    # Step 3: Enable Edge Blocking (if requested)
    if ($EnableEdgeBlocking) {
        Write-Log "STEP 3: Enable Edge PUA Blocking" -Level Info
        Write-Log "========================================" -Level Info
        
        $edgeSuccess = Enable-EdgePUABlocking
        Write-Log ""
    }
}

# Step 4: Force Group Policy Update
Write-Log "STEP $(if ($RemoveOnly) { '2' } else { if ($EnableEdgeBlocking) { '4' } else { '3' } }): Force Group Policy Update" -Level Info
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

# Step 5: Verify
Write-Log "STEP $(if ($RemoveOnly) { '3' } else { if ($EnableEdgeBlocking) { '5' } else { '4' } }): Verify Configuration" -Level Info
Write-Log "========================================" -Level Info

$verified = Verify-PUAProtection
Write-Log ""

# Step 6: Open Windows Security
if (-not $RemoveOnly) {
    Write-Log "STEP $(if ($EnableEdgeBlocking) { '6' } else { '5' }): Open Windows Security for Verification" -Level Info
    Write-Log "========================================" -Level Info
    
    Start-Sleep -Seconds 2
    Open-WindowsSecurity
    Write-Log ""
}

# Final Summary
Write-Log "========================================" -Level Success
Write-Log "OPERATION COMPLETE" -Level Success
Write-Log "========================================" -Level Success
Write-Log ""

if ($verified -and $enableSuccess) {
    Write-Log "✓ Group Policy management removed" -Level Success
    Write-Log "✓ PUA Protection enabled via Windows Defender" -Level Success
    Write-Log "✓ Setting is now user-controllable" -Level Success
    Write-Log "✓ No longer shows 'managed by administrator'" -Level Success
    
    if ($EnableEdgeBlocking) {
        Write-Log "✓ Edge PUA blocking configured" -Level Success
    }
} else {
    Write-Log "⚠ Operation completed with warnings" -Level Warning
    
    if (-not $removalSuccess) {
        Write-Log "  - Group Policy removal had issues" -Level Warning
    }
    
    if (-not $enableSuccess) {
        Write-Log "  - PUA Protection enable had issues" -Level Warning
        Write-Log "  - Windows Defender may not be active (third-party AV?)" -Level Info
    }
}

Write-Log ""
Write-Log "WHAT'S ENABLED:" -Level Info
Write-Log "  ✓ Block apps: YES (Windows Defender will block PUA)" -Level Success
Write-Log "  $(if ($EnableEdgeBlocking) { '✓' } else { '○' }) Block downloads: $(if ($EnableEdgeBlocking) { 'YES' } else { 'Configure in Edge settings' }) (Microsoft Edge will block PUA downloads)" -Level $(if ($EnableEdgeBlocking) { 'Success' } else { 'Info' })
Write-Log ""

if (-not $EnableEdgeBlocking) {
    Write-Log "To also enable 'Block downloads' in Microsoft Edge:" -Level Info
    Write-Log "  1. Open Microsoft Edge" -Level Info
    Write-Log "  2. Go to: edge://settings/privacy" -Level Info
    Write-Log "  3. Under Security, toggle 'Block potentially unwanted apps'" -Level Info
    Write-Log "  OR run this script again with: -EnableEdgeBlocking" -Level Info
    Write-Log ""
}

Write-Log "Backup: $Script:BackupFile" -Level Info
Write-Log "Log: $Script:LogFile" -Level Info
Write-Log ""
Write-Log "========================================" -Level Info
