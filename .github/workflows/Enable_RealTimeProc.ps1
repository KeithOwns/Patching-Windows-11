#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Enables Real-time Protection with Tamper Protection check

.DESCRIPTION
    Checks for Tamper Protection and attempts to enable Real-time protection.
    Provides guidance if Tamper Protection is blocking the change.

.NOTES
    Author: AI+IT Support
    Created: 2025-11-12
#>

[CmdletBinding()]
param()

try {
    Write-Host "Checking Tamper Protection status..." -ForegroundColor Cyan
    
    # Check Tamper Protection via registry
    $tamperProtection = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -ErrorAction SilentlyContinue
    
    if ($tamperProtection.TamperProtection -eq 5) {
        Write-Host "ERROR: Tamper Protection is ENABLED and blocking changes." -ForegroundColor Red
        Write-Host "`nTo fix this:" -ForegroundColor Yellow
        Write-Host "1. Open Windows Security" -ForegroundColor Yellow
        Write-Host "2. Go to: Virus & threat protection > Manage settings" -ForegroundColor Yellow
        Write-Host "3. Turn OFF 'Tamper Protection'" -ForegroundColor Yellow
        Write-Host "4. Then run this script again" -ForegroundColor Yellow
        Write-Host "5. Re-enable Tamper Protection afterwards" -ForegroundColor Yellow
        exit 1
    }
    
    Write-Host "Tamper Protection is not blocking. Proceeding..." -ForegroundColor Green
    Write-Host "`nEnabling Real-time Protection..." -ForegroundColor Cyan
    
    # Enable Real-time Protection
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
    
    Start-Sleep -Seconds 2
    
    # Verify the setting
    $status = Get-MpPreference | Select-Object -ExpandProperty DisableRealtimeMonitoring
    
    if ($status -eq $false) {
        Write-Host "SUCCESS: Real-time Protection is now enabled." -ForegroundColor Green
    } else {
        Write-Warning "Real-time Protection may not have been enabled. Check Group Policy or other restrictions."
    }
    
} catch {
    Write-Error "Failed to enable Real-time Protection: $_"
    exit 1
}
