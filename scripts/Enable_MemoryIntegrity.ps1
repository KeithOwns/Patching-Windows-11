#Requires -Version 5.1
<#
.SYNOPSIS
    Enables Memory Integrity (Hypervisor-protected Code Integrity) in Windows Security.

.DESCRIPTION
    This script enables Memory Integrity (HVCI) through the registry, which is part of
    Core Isolation security features in Windows Security. The change requires a system
    restart to take effect.
    
    The script sets the feature to enabled while maintaining user-level control, meaning
    users can toggle Memory Integrity on/off through the Windows Security GUI without
    seeing "This setting is managed by your administrator."
    
    Memory Integrity uses hardware virtualization and Hyper-V to protect critical
    Windows kernel-mode processes against injection and execution of malicious code.

.PARAMETER Force
    Skips confirmation prompts.

.EXAMPLE
    .\Enable-MemoryIntegrity.ps1
    Enables Memory Integrity with confirmation prompt.

.EXAMPLE
    .\Enable-MemoryIntegrity.ps1 -Force
    Enables Memory Integrity without confirmation.

.NOTES
    Author: AI+IT Support
    Requirements:
    - Windows 10 (1803+) or Windows 11
    - Administrator privileges
    - Virtualization support in BIOS/UEFI (Intel VT-x or AMD-V)
    - SLAT-capable CPU (Second Level Address Translation)
    - A restart is required for changes to take effect
    
    Registry Path: HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity
    Values Set:
    - Enabled (DWORD) = 1 (turns on Memory Integrity)
    - WasEnabledBy (DWORD) = 2 (allows user control via Windows Security GUI)
    
    The WasEnabledBy value prevents the "managed by administrator" message and allows
    users to toggle the setting on/off through Windows Security without administrator override.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [switch]$Force
)

#region Functions

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $color = switch ($Level) {
        'Info'    { 'Cyan' }
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
    }
    
    Write-Host "[$timestamp] " -NoNewline -ForegroundColor Gray
    Write-Host "[$Level] " -NoNewline -ForegroundColor $color
    Write-Host $Message
}

function Test-AdministratorPrivileges {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-HypervisorSupport {
    try {
        $hypervisorPresent = (Get-ComputerInfo -Property HyperVisorPresent).HyperVisorPresent
        return $hypervisorPresent
    } catch {
        Write-Log "Unable to determine hypervisor support: $_" -Level Warning
        return $false
    }
}

function Test-MemoryIntegrityCompatibility {
    # Check Windows version
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -lt 10) {
        Write-Log "Memory Integrity requires Windows 10 version 1803 or later." -Level Error
        return $false
    }
    
    if ($osVersion.Major -eq 10 -and $osVersion.Build -lt 17134) {
        Write-Log "Memory Integrity requires Windows 10 build 17134 (version 1803) or later. Current build: $($osVersion.Build)" -Level Error
        return $false
    }
    
    return $true
}

function Get-MemoryIntegrityStatus {
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
    
    try {
        if (Test-Path $registryPath) {
            $enabled = Get-ItemProperty -Path $registryPath -Name "Enabled" -ErrorAction SilentlyContinue
            if ($null -ne $enabled) {
                return $enabled.Enabled
            }
        }
        return 0
    } catch {
        Write-Log "Error checking Memory Integrity status: $_" -Level Warning
        return -1
    }
}

function Enable-MemoryIntegrity {
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
    
    try {
        # Create the registry path if it doesn't exist
        if (-not (Test-Path $registryPath)) {
            Write-Log "Creating registry path: $registryPath" -Level Info
            New-Item -Path $registryPath -Force | Out-Null
        }
        
        # Set the Enabled value to 1
        Write-Log "Setting Memory Integrity to enabled..." -Level Info
        Set-ItemProperty -Path $registryPath -Name "Enabled" -Value 1 -Type DWord -Force
        
        # Set WasEnabledBy to 2 to allow user control via Windows Security GUI
        # This prevents the "managed by administrator" message and grayed-out toggle
        Write-Log "Configuring user-level control (WasEnabledBy = 2)..." -Level Info
        Set-ItemProperty -Path $registryPath -Name "WasEnabledBy" -Value 2 -Type DWord -Force
        
        # Verify the changes
        $enabledValue = (Get-ItemProperty -Path $registryPath -Name "Enabled").Enabled
        $wasEnabledByValue = (Get-ItemProperty -Path $registryPath -Name "WasEnabledBy").WasEnabledBy
        
        if ($enabledValue -eq 1 -and $wasEnabledByValue -eq 2) {
            Write-Log "Memory Integrity has been successfully enabled with user-level control." -Level Success
            return $true
        } else {
            Write-Log "Failed to verify Memory Integrity settings." -Level Error
            return $false
        }
    } catch {
        Write-Log "Error enabling Memory Integrity: $_" -Level Error
        return $false
    }
}

#endregion

#region Main Script

Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "  Enable Memory Integrity (HVCI)" -ForegroundColor Cyan
Write-Host "  Windows Security > Core Isolation" -ForegroundColor Cyan
Write-Host "================================================`n" -ForegroundColor Cyan

# Check for administrator privileges
Write-Log "Checking administrator privileges..." -Level Info
if (-not (Test-AdministratorPrivileges)) {
    Write-Log "This script requires administrator privileges." -Level Error
    Write-Log "Please run PowerShell as Administrator and try again." -Level Error
    exit 1
}
Write-Log "Administrator privileges confirmed." -Level Success

# Check Windows version compatibility
Write-Log "Checking Windows version compatibility..." -Level Info
if (-not (Test-MemoryIntegrityCompatibility)) {
    exit 1
}
Write-Log "Windows version is compatible." -Level Success

# Check hypervisor support
Write-Log "Checking hypervisor support..." -Level Info
if (-not (Test-HypervisorSupport)) {
    Write-Log "Hypervisor support is not detected or not enabled." -Level Warning
    Write-Log "Memory Integrity requires:" -Level Warning
    Write-Log "  - Virtualization enabled in BIOS/UEFI (Intel VT-x or AMD-V)" -Level Warning
    Write-Log "  - SLAT-capable CPU" -Level Warning
    Write-Log "You can still enable the setting, but it may not function until these requirements are met." -Level Warning
    
    if (-not $Force) {
        $continue = Read-Host "`nDo you want to continue anyway? (Y/N)"
        if ($continue -ne 'Y' -and $continue -ne 'y') {
            Write-Log "Operation cancelled by user." -Level Info
            exit 0
        }
    }
} else {
    Write-Log "Hypervisor support is available." -Level Success
}

# Check current status
Write-Log "Checking current Memory Integrity status..." -Level Info
$currentStatus = Get-MemoryIntegrityStatus

switch ($currentStatus) {
    1 {
        Write-Log "Memory Integrity is already enabled." -Level Info
        Write-Host "`nNo changes needed. Memory Integrity is already turned on." -ForegroundColor Green
        exit 0
    }
    0 {
        Write-Log "Memory Integrity is currently disabled." -Level Info
    }
    -1 {
        Write-Log "Unable to determine current status. Proceeding with enable operation." -Level Warning
    }
}

# Confirm action
if (-not $Force -and -not $PSCmdlet.ShouldProcess("Memory Integrity", "Enable")) {
    $confirmation = Read-Host "`nDo you want to enable Memory Integrity? This will require a restart. (Y/N)"
    if ($confirmation -ne 'Y' -and $confirmation -ne 'y') {
        Write-Log "Operation cancelled by user." -Level Info
        exit 0
    }
}

# Enable Memory Integrity
Write-Host ""
if (Enable-MemoryIntegrity) {
    Write-Host "`n================================================" -ForegroundColor Green
    Write-Host "  SUCCESS" -ForegroundColor Green
    Write-Host "================================================" -ForegroundColor Green
    Write-Log "Memory Integrity has been enabled with user-level control." -Level Success
    Write-Host "`nYou can now toggle Memory Integrity on/off through:" -ForegroundColor White
    Write-Host "  Windows Security > Device Security > Core isolation > Memory integrity" -ForegroundColor Cyan
    Write-Host "`nIMPORTANT: " -NoNewline -ForegroundColor Yellow
    Write-Host "A system restart is required for this change to take effect." -ForegroundColor White
    
    if (-not $Force) {
        Write-Host ""
        $restart = Read-Host "Would you like to restart now? (Y/N)"
        if ($restart -eq 'Y' -or $restart -eq 'y') {
            Write-Log "Initiating system restart..." -Level Info
            Restart-Computer -Force
        } else {
            Write-Log "Please restart your computer when convenient for the changes to take effect." -Level Warning
        }
    }
} else {
    Write-Host "`n================================================" -ForegroundColor Red
    Write-Host "  FAILED" -ForegroundColor Red
    Write-Host "================================================" -ForegroundColor Red
    Write-Log "Failed to enable Memory Integrity. Please check the errors above." -Level Error
    exit 1
}

#endregion
