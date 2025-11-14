<#
.SYNOPSIS
    Sets 'SmartScreen for Microsoft Edge' to ON without locking the UI.

.DESCRIPTION
    1. Removes any existing Group Policy enforcing this setting (removes the "Managed" warning).
    2. Sets the User Preference registry key used by Windows Security.
    
    Result: SmartScreen is enabled, but the user can still toggle it manually if they wish.

.NOTES
    No Administrator rights required (modifies HKCU).
    Restart Microsoft Edge after running.
#>

# --- Configuration ---
# 1. The "Policy" path (We must delete this to remove the "Managed" warning)
$PolicyPath = "HKCU:\SOFTWARE\Policies\Microsoft\Edge"
$PolicyName = "SmartScreenEnabled"

# 2. The "Preference" path (We set this to toggle the setting naturally)
# This is the key Windows Security uses for 'Reputation-based protection'
$PrefPath   = "HKCU:\Software\Microsoft\Edge\SmartScreenEnabled"


Write-Host "Configuring Edge SmartScreen as a User Preference..." -ForegroundColor Cyan

# --- Step 1: Remove the 'Managed' Policy Lock ---
if (Test-Path $PolicyPath) {
    $CheckPolicy = Get-ItemProperty -Path $PolicyPath -Name $PolicyName -ErrorAction SilentlyContinue
    if ($CheckPolicy) {
        try {
            Remove-ItemProperty -Path $PolicyPath -Name $PolicyName -ErrorAction Stop
            Write-Host "[Cleanup] Removed 'Managed by organization' policy lock." -ForegroundColor Yellow
        }
        catch {
            Write-Host "[Error] Could not remove policy lock: $_" -ForegroundColor Red
        }
    }
}

# --- Step 2: Set the User Preference to ON ---
# We need to create the key if it doesn't exist
if (-not (Test-Path $PrefPath)) {
    try {
        New-Item -Path $PrefPath -Force | Out-Null
        Write-Host "[Setup] Created configuration registry key." -ForegroundColor Gray
    }
    catch {
        Write-Host "[Error] Failed to create registry key: $_" -ForegroundColor Red
        Exit
    }
}

# Set the (Default) value of this key to 1
try {
    # Setting the "(default)" value of a key requires specifying empty string for Name
    Set-ItemProperty -Path $PrefPath -Name "(default)" -Value 1 -Type DWord -Force
    Write-Host "[Success] SmartScreen set to 'On' (User Preference)." -ForegroundColor Green
}
catch {
    Write-Host "[Error] Failed to set preference: $_" -ForegroundColor Red
}

# --- Step 3: Verification ---
$Verify = Get-ItemProperty -Path $PrefPath -Name "(default)" -ErrorAction SilentlyContinue
if ($Verify.'(default)' -eq 1) {
    Write-Host "`nCurrent State: ENABLED" -ForegroundColor Green
    Write-Host "UI Status:     Editable (Not greyed out)" -ForegroundColor Gray
    Write-Host "Action:        Please restart Microsoft Edge." -ForegroundColor Yellow
} else {
    Write-Host "`nVerification Failed." -ForegroundColor Red
}
