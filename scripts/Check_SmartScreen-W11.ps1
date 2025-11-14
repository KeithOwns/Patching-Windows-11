#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Detects the enabled/disabled state of 'SmartScreen for Microsoft Edge' in Windows 11.

.DESCRIPTION
    This script checks the Windows Registry in the order of precedence:
    1. Machine Group Policy (HKLM) - Overrides everything.
    2. User Group Policy (HKCU) - Overrides user preferences.
    3. User Personal Settings (HKCU) - The setting toggled in Windows Security/Edge.
    
    If no configuration is found in the registry, the default state for Windows 11 is 'On'.

.NOTES
    Run as Administrator for best results (though readable by users).
#>

function Get-EdgeSmartScreenStatus {
    [CmdletBinding()]
    param()

    # Define Registry Paths
    $RegPath_MachinePolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $RegPath_UserPolicy    = "HKCU:\SOFTWARE\Policies\Microsoft\Edge"
    $RegPath_UserSetting   = "HKCU:\Software\Microsoft\Edge\SmartScreenEnabled" # Common tweak location
    $RegPath_UserSetting2  = "HKCU:\Software\Microsoft\Edge"                   # Alternative location
    
    $Status = "Unknown"
    $Source = "Default"
    $IsConfigured = $false

    # 1. Check Machine Group Policy (Highest Priority)
    if (Test-Path $RegPath_MachinePolicy) {
        $val = Get-ItemProperty -Path $RegPath_MachinePolicy -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue
        if ($null -ne $val) {
            $IsConfigured = $true
            $Source = "Group Policy (Machine)"
            if ($val.SmartScreenEnabled -eq 1) { $Status = "On" } else { $Status = "Off" }
        }
    }

    # 2. Check User Group Policy (If Machine Policy not set)
    if (-not $IsConfigured -and (Test-Path $RegPath_UserPolicy)) {
        $val = Get-ItemProperty -Path $RegPath_UserPolicy -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue
        if ($null -ne $val) {
            $IsConfigured = $true
            $Source = "Group Policy (User)"
            if ($val.SmartScreenEnabled -eq 1) { $Status = "On" } else { $Status = "Off" }
        }
    }

    # 3. Check User Personal Settings (If no Policy set)
    # Note: If SmartScreen is managed via the browser's internal JSON preferences, 
    # Registry keys might not exist. However, Windows Security toggles usually write here.
    if (-not $IsConfigured) {
        
        # Check Location A: Key is SmartScreenEnabled, Value is (Default)
        if (Test-Path $RegPath_UserSetting) {
            $val = Get-ItemProperty -Path $RegPath_UserSetting -Name "(default)" -ErrorAction SilentlyContinue
            if ($null -ne $val) {
                $IsConfigured = $true
                $Source = "User Setting (Registry Key)"
                if ($val.'(default)' -eq 1) { $Status = "On" } else { $Status = "Off" }
            }
        }
        
        # Check Location B: Key is Edge, Value is SmartScreenEnabled
        if (-not $IsConfigured -and (Test-Path $RegPath_UserSetting2)) {
            $val = Get-ItemProperty -Path $RegPath_UserSetting2 -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue
            if ($null -ne $val.SmartScreenEnabled) {
                $IsConfigured = $true
                $Source = "User Setting (Value)"
                if ($val.SmartScreenEnabled -eq 1) { $Status = "On" } else { $Status = "Off" }
            }
        }
    }

    # 4. Default Behavior
    # In Windows 11, if the key is missing entirely, the feature defaults to ON.
    if (-not $IsConfigured) {
        $Status = "On"
        $Source = "Windows Default (No config found)"
    }

    # Create Output Object
    [PSCustomObject]@{
        "Feature"        = "SmartScreen for Microsoft Edge"
        "EffectiveState" = $Status
        "ConfiguredBy"   = $Source
        "Timestamp"      = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }
}

# Run the function and display results
Write-Host "Checking Reputation-based protection settings..." -ForegroundColor Cyan
$Result = Get-EdgeSmartScreenStatus

# Formatting output for readability
Write-Host "`n--- Detection Results ---" -ForegroundColor Gray
Write-Host "Status: " -NoNewline
if ($Result.EffectiveState -eq "On") {
    Write-Host $Result.EffectiveState -ForegroundColor Green
} else {
    Write-Host $Result.EffectiveState -ForegroundColor Red
}
Write-Host "Source: $($Result.ConfiguredBy)"
Write-Host "-------------------------"
