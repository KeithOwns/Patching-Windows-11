<#
.SYNOPSIS
    Enables Local Security Authority (LSA) protection by setting the
    required registry key.

.DESCRIPTION
    This script enables 'Local Security Authority protection' (RunAsPPL)
    by setting the 'RunAsPPL' DWORD value to 1 in the registry.
    
    This setting is system-wide and requires the script to be run
    with Administrator privileges.
    
    A system reboot is required for the change to take full effect.

.NOTES
    Author:      Gemini
    Requires:    Administrator privileges
#>

#Requires -RunAsAdministrator

# Set registry path and value details
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$regName = "RunAsPPL"
$regValue = 1 # 1 = On (Enabled)
$regType = "DWord"

try {
    Write-Verbose "Attempting to set LSA protection registry key..."
    
    # Check if the 'Lsa' key exists. If not, create it.
    if (-not (Test-Path $regPath)) {
        Write-Verbose "Registry path '$regPath' not found. Creating it..."
        New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
    }

    # Set the 'RunAsPPL' value
    # Using -Force to create the value if it doesn't exist or overwrite it if it does.
    Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Type $regType -Force -ErrorAction Stop
    
    Write-Host "Successfully enabled Local Security Authority protection."
    Write-Host "IMPORTANT: A reboot is required for this change to take effect."
}
catch {
    # Output any errors that occurred
    Write-Error "Failed to enable Local Security Authority protection."
    Write-Error "Error details: $($_.Exception.Message)"
}
