<#
.SYNOPSIS
  Checks the status of the 'Check apps and files' (SmartScreen) setting
  in Windows Security.

.DESCRIPTION
  This script determines if Microsoft Defender SmartScreen for apps and files
  is 'On' or 'Off'.

  It first checks for an administrative Group Policy setting, as this
  overrides any user-configurable setting. If no policy is found,
  it checks the user's local setting.

.NOTES
  - Policy Path: HKLM:\SOFTWARE\Policies\Microsoft\Windows\System
  - Policy Value: EnableSmartScreen (DWORD: 1 = On, 0 = Off)
  - User Path: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer
  - User Value: SmartScreenEnabled (String: "Off" = Off)
#>

function Get-SmartScreenStatus {
    [CmdletBinding()]
    param ()

    $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    $policyProperty = "EnableSmartScreen"
    $userPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
    $userProperty = "SmartScreenEnabled"

    $status = "Unknown"
    $source = ""

    # 1. Check for an enforced Group Policy setting
    try {
        $policyValue = Get-ItemProperty -Path $policyPath -Name $policyProperty -ErrorAction SilentlyContinue
        
        if ($null -ne $policyValue) {
            $source = "(Enforced by Group Policy)"
            if ($policyValue.EnableSmartScreen -eq 1) {
                $status = "On"
            } elseif ($policyValue.EnableSmartScreen -eq 0) {
                $status = "Off"
            }
        }
    }
    catch {
        # Key likely doesn't exist, which is normal.
    }

    # 2. If no policy is set, check the user setting
    if ($status -eq "Unknown") {
        try {
            $userValue = Get-ItemProperty -Path $userPath -Name $userProperty -ErrorAction SilentlyContinue
            
            $source = "(User Setting)"
            # If the value exists and is literally "Off", it's off.
            if ($null -ne $userValue -and $userValue.$userProperty -eq "Off") {
                $status = "Off"
            } else {
                # If the value doesn't exist or is not "Off", it's considered On (default).
                $status = "On"
            }
        }
        catch {
            $status = "Error"
            $source = "(Could not read registry: $_.Exception.Message)"
        }
    }

    # Output the result
    Write-Output "Check apps and files: $status $source"
}

# --- Run the function ---
Get-SmartScreenStatus
