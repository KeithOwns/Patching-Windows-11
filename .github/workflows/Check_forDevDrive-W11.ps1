#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Check for Dev Drive volumes on the system

.DESCRIPTION
    Detects if any Dev Drive volumes exist on the system.
    Dev Drives use the ReFS file system.

.NOTES
    Author: AI+IT Support
    Created: 2025-11-12
#>

[CmdletBinding()]
param()

Write-Host "Checking for Dev Drive volumes..." -ForegroundColor Cyan

# Check ReFS volumes (Dev Drives use ReFS)
$refsVolumes = Get-Volume | Where-Object { $_.FileSystem -eq "ReFS" -and $_.DriveLetter }

if ($refsVolumes) {
    Write-Host "`nDev Drive(s) detected:" -ForegroundColor Green
    $refsVolumes | Format-Table DriveLetter, FileSystemLabel, @{Name="Size (GB)"; Expression={[math]::Round($_.Size/1GB, 2)}}, @{Name="Free (GB)"; Expression={[math]::Round($_.SizeRemaining/1GB, 2)}} -AutoSize
    
    # Verify each with fsutil
    foreach ($vol in $refsVolumes) {
        if ($vol.DriveLetter) {
            $result = fsutil devdrv query "$($vol.DriveLetter):" 2>&1
            Write-Host "$($vol.DriveLetter): $result" -ForegroundColor White
        }
    }
    
    exit 0
} else {
    Write-Host "`nNo Dev Drive detected on this system." -ForegroundColor Yellow
    Write-Host "Dev Drives use the ReFS file system and are not present." -ForegroundColor Gray
    exit 1
}
