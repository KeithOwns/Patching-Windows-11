<#
.SYNOPSIS
    Checks the status of the Windows Security "Check apps and files"
    (SmartScreen) setting.

.DESCRIPTION
    This script reads the registry to determine if SmartScreen for apps and
    files is enabled or disabled.

    It checks in two locations:
    1. The Group Policy (GPO) location, which overrides any user setting.
    2. The local user setting location, if no GPO is applied.
#>

try {
    # Define registry paths and value names
    $gpoPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen"
    $gpoValueName = "EnableSmartScreen"
    $userPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
    $userValueName = "SmartScreenEnabled"

    $finalStatus = "Unknown"
    $controlMethod = "Unknown"

    # 1. Check for a Group Policy setting first.
    # This value overrides the user setting.
    $gpoSetting = Get-ItemProperty -Path $gpoPath -Name $gpoValueName -ErrorAction SilentlyContinue

    if ($null -ne $gpoSetting) {
        $controlMethod = "Group Policy"
        if ($gpoSetting.$gpoValueName -eq 1) {
            $finalStatus = "On"
        } elseif ($gpoSetting.$gpoValueName -eq 0) {
            $finalStatus = "Off"
        }
    } else {
        # 2. No GPO. Check the local user setting.
        $userSetting = Get-ItemProperty -Path $userPath -Name $userValueName -ErrorAction SilentlyContinue

        if ($null -ne $userSetting) {
            $controlMethod = "Local Setting"
            $value = $userSetting.$userValueName.ToLower()

            # 'Warn' or 'Block' both mean the feature is 'On'.
            if ($value -eq "warn" -or $value -eq "block") {
                $finalStatus = "On"
            } elseif ($value -eq "off") {
                $finalStatus = "Off"
            }
        } else {
            # 3. No setting found in either location.
            # This typically means it's on by default ("Warn").
            $controlMethod = "Default"
            $finalStatus = "On"
        }
    }

    # Output the result as an object for easy use
    [PSCustomObject]@{
        Setting        = "Check apps and files (SmartScreen)"
        Status         = $finalStatus
        ControlledBy   = $controlMethod
    }

} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
}