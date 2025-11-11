<#
.SYNOPSIS
    Disables 'Potentially unwanted app blocking' in Windows Security.
.DESCRIPTION
    This script sets the PUAProtection level to 'Off' (0) using the
    Set-MpPreference cmdlet.
.NOTES
    This script MUST be run as an Administrator to modify Windows Security settings.
#>

# Set the PUA (Potentially Unwanted App) protection level to 0 (Off)
try {
    Set-MpPreference -PUAProtection 0
    Write-Host "Successfully turned 'Off' Potentially unwanted app blocking."
}
catch {
    Write-Error "Failed to change setting. Please ensure you are running this script as an Administrator."
    Write-Error $_.Exception.Message
}
