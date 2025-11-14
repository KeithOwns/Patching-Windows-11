#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Checks the status of Windows 11 Smart App Control.

.DESCRIPTION
    This script queries the registry to determine if Smart App Control is 
    On, Off, or in Evaluation Mode. It outputs a custom object with the status.

.NOTES
    File Name  : Check_SmartAppControl-W11.ps1
    Author     : Coding Partner
    Requirement: Windows 11 Version 22H2 or later.
#>

# Define the Registry Path and Value Name
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy"
$regName = "VerifiedAndReputablePolicyState"

# Initialize status variable
$sacStatus = "Unknown / Not Supported"

# Check if the registry path exists
if (Test-Path $regPath) {
    
    # Try to get the specific value
    $regItem = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue

    if ($regItem -and $regItem.$regName -ne $null) {
        switch ($regItem.$regName) {
            0 { $sacStatus = "Off" }
            1 { $sacStatus = "On" }
            2 { $sacStatus = "Evaluation Mode" }
            Default { $sacStatus = "Unknown Value: $($regItem.$regName)" }
        }
    } else {
        $sacStatus = "Off (Registry key missing)"
    }
} else {
    $sacStatus = "Not Supported (Path not found)"
}

# Output the result clearly
$result = [PSCustomObject]@{
    'Feature' = "Smart App Control"
    'Status'  = $sacStatus
}

# Display results to console
Write-Host "----------------------------------------" -ForegroundColor Cyan
Write-Host "Windows Security Setting Check" -ForegroundColor Cyan
Write-Host "----------------------------------------" -ForegroundColor Cyan
$result | Format-Table -AutoSize

# Optional: Pause so the window doesn't close immediately if double-clicked
if ($Host.Name -eq "ConsoleHost") {
    Read-Host "Press Enter to exit..."
}
