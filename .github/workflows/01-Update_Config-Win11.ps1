#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
  Checks and sets Windows Update (WU) UX settings and reports before/after.
.NOTES
  UX keys can be overridden by policy under HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
  Core Isolation and PUA protection checks are handled by WindowsSecurityConfig.ps1
#>

# Global timer
# $script:StartTime = Get-Date

# --- New functions adapted from Security Script ---

function Write-StatusIcon {
    param(
        [Parameter(Mandatory)]
        [bool]$IsEnabled,
        
        [Parameter(Mandatory = $false)]
        [string]$Severity = "Warning"
    )
    
    if ($IsEnabled) {
        Write-Host " " -NoNewline -BackgroundColor DarkCyan -ForegroundColor Black
        Write-Host "✓" -NoNewline -BackgroundColor DarkCyan -ForegroundColor Black
        Write-Host " " -NoNewline -BackgroundColor DarkCyan -ForegroundColor Black
        Write-Host " " -NoNewline
    } else {
        $color = switch ($Severity) {
            "Critical" { "Red" }
            "Warning" { "Yellow" }
            "Info" { "Gray" }
            default { "Yellow" }
        }
        Write-Host " ✗ " -NoNewline -ForegroundColor $color
    }
}

function Write-SectionHeader {
    param(
        [Parameter(Mandatory)]
        [string]$Title,
        
        [Parameter(Mandatory = $false)]
        [string]$Icon = "⚙️"
    )
    
    Write-Host "`n$Icon " -NoNewline -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor White
    Write-Host ("─" * 60) -ForegroundColor DarkGray
}

# --- Original script functions ---

function Get-RegistryValue {
    param([Parameter(Mandatory)] [string]$Path, [Parameter(Mandatory)] [string]$Name)
    try {
        if (Test-Path $Path) {
            $prop = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            return $prop.$Name
        }
        return $null
    } catch { return $null }
}

function Set-RegistryDword {
    param([Parameter(Mandatory)] [string]$Path, [Parameter(Mandatory)] [string]$Name, [Parameter(Mandatory)] [int]$Value)
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
}

# Registry Paths
$WU_UX  = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
$WU_POL = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$WINLOGON_USER = "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" # HKEY_CURRENT_USER
$WINLOGON_MACHINE = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" # HKEY_LOCAL_MACHINE

function Show-WUStatus {
    Write-SectionHeader "Windows Update Settings"

    Write-Host "`n  --- More options ---" -ForegroundColor Cyan
    $continuous = Get-RegistryValue -Path $WU_UX -Name "IsContinuousInnovationOptedIn"
    Write-StatusIcon ($continuous -eq 1) -Severity "Warning"
    Write-Host "Get the latest updates as soon as they're available" -ForegroundColor White

    Write-Host "`n  --- Advanced options ---" -ForegroundColor Cyan
    $mu = Get-RegistryValue -Path $WU_UX  -Name "AllowMUUpdateService"
    Write-StatusIcon ($mu -eq 1) -Severity "Warning"
    Write-Host "Receive updates for other Microsoft products" -ForegroundColor White

    $expedite = Get-RegistryValue -Path $WU_UX -Name "IsExpedited"
    Write-StatusIcon ($expedite -eq 1) -Severity "Warning"
    Write-Host "Get me up to date" -ForegroundColor White

    $metered = Get-RegistryValue -Path $WU_UX -Name "AllowAutoWindowsUpdateDownloadOverMeteredNetwork"
    Write-StatusIcon ($metered -eq 1) -Severity "Info"
    Write-Host "Download updates over metered connections" -ForegroundColor White

    $restartNotify = Get-RegistryValue -Path $WU_UX -Name "RestartNotificationsAllowed2"
    Write-StatusIcon ($restartNotify -eq 1) -Severity "Info"
    Write-Host "Notify me when a restart is required" -ForegroundColor White

    $ahs = Get-RegistryValue -Path $WU_UX -Name "ActiveHoursStart"
    $ahe = Get-RegistryValue -Path $WU_UX -Name "ActiveHoursEnd"
    if ($ahs -ne $null -and $ahe -ne $null) {
        Write-Host "   " -NoNewline
        Write-Host ("Active hours: {0}:00 - {1}:00" -f $ahs,$ahe) -ForegroundColor Gray
    } else {
        Write-Host "   " -NoNewline
        Write-Host "Active hours: Auto (based on device activity)" -ForegroundColor Gray
    }
    
    Write-Host "`n  --- Sign-in options ---" -ForegroundColor Cyan
    $restartApps = Get-RegistryValue -Path $WINLOGON_USER -Name "RestartApps"
    Write-StatusIcon ($restartApps -eq 1) -Severity "Info"
    Write-Host "Automatically save restartable apps" -ForegroundColor White
    
    # Updated logic for "Use sign-in info" (ARSO)
    $arsoEnabled = $false
    try {
        $UserSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        if ($UserSID) {
            $userArsoPath = "$WINLOGON_MACHINE\UserARSO\$UserSID"
            $optOut = Get-RegistryValue -Path $userArsoPath -Name "OptOut"
            # Enabled if OptOut exists and is 0
            $arsoEnabled = ($optOut -ne $null -and $optOut -eq 0)
        }
        Write-StatusIcon $arsoEnabled -Severity "Info"
        Write-Host "Use sign-in info to finish setup after update" -ForegroundColor White
    } catch {
        Write-StatusIcon $false -Severity "Info"
        Write-Host "Use sign-in info to finish setup (Could not check user SID)" -ForegroundColor Gray
    }


    Write-Host "`n  --- Policy inspection (read-only) ---" -ForegroundColor Cyan
    $pol_mu = Get-RegistryValue -Path $WU_POL -Name "AllowMUUpdateService"
    if ($pol_mu -ne $null) { 
        Write-Host "   " -NoNewline
        Write-Host "Policy enforces Microsoft Update: $pol_mu" -ForegroundColor Gray
    } else { 
        Write-Host "   " -NoNewline
        Write-Host "No policy enforcement detected for Microsoft Update" -ForegroundColor Gray
    }
}

function Set-WUSettings {
    try {
        # Configuring More options
        Set-RegistryDword -Path $WU_UX -Name "IsContinuousInnovationOptedIn" -Value 1

        # Configuring Advanced options
        Set-RegistryDword -Path $WU_UX -Name "AllowMUUpdateService" -Value 1
        Set-RegistryDword -Path $WU_UX -Name "IsExpedited" -Value 1
        Set-RegistryDword -Path $WU_UX -Name "AllowAutoWindowsUpdateDownloadOverMeteredNetwork" -Value 1
        Set-RegistryDword -Path $WU_UX -Name "RestartNotificationsAllowed2" -Value 1
        
        # Configuring Sign-in options
        try {
            # 1. Set "Automatically save restartable apps" (in HKCU)
            Set-RegistryDword -Path $WINLOGON_USER -Name "RestartApps" -Value 1
            
            # 2. Set "Use sign-in info..." (ARSO) using new HKLM logic
            $policyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            $policyName = "DisableAutomaticRestartSignOn"
            $policyValue = Get-RegistryValue -Path $policyPath -Name $policyName

            if ($null -ne $policyValue -and $policyValue -eq 1) {
                # Policy is blocking this, so we skip
                # This state will be reflected in the Show-WUStatus check
            } else {
                # Policy is not blocking, proceed with soft-set
                $UserSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                if (-not $UserSID) {
                    throw "Could not determine current user's SID to set ARSO."
                }
                
                $userArsoPath = "$WINLOGON_MACHINE\UserARSO\$UserSID"
                
                # Set machine-wide prerequisite
                Set-RegistryDword -Path $WINLOGON_MACHINE -Name "ARSOUserConsent" -Value 1
                
                # Ensure user-specific path exists
                New-Item -Path $userArsoPath -Force -ErrorAction Stop | Out-Null
                
                # Set user's preference (OptOut=0 means Opt-In)
                Set-RegistryDword -Path $userArsoPath -Name "OptOut" -Value 0
            }
            
        } catch {
            Write-Host "`n[ERROR] " -NoNewline -ForegroundColor Red
            Write-Host "Failed to set user-level sign-in options: $($_.Exception.Message)" -ForegroundColor White
        }
    }
    catch {
        Write-Host "`n[ERROR] " -NoNewline -ForegroundColor Red
        Write-Host "Error applying settings: $($_.Exception.Message)" -ForegroundColor White
    }
}

# --- Main ---
Clear-Host
Write-Host "`n" -NoNewline
Write-Host ("═" * 60) -ForegroundColor Blue
Write-Host "  WINDOWS UPDATE CONFIGURATOR" -ForegroundColor White
Write-Host ("═" * 60) -ForegroundColor Blue

Set-WUSettings
Show-WUStatus

# --- Microsoft Store Updates ---
Write-SectionHeader "Microsoft Store Updates" "🏪"

Write-Host "`n  Opening Microsoft Store to check for app updates..." -ForegroundColor Yellow
Write-Host "  • Launching Microsoft Store..." -ForegroundColor Gray

# Open MS Store to Downloads and Updates page
Start-Process "ms-windows-store://downloadsandupdates"

# Run UI Automation in a SEPARATE PowerShell process to avoid assembly conflicts
# This prevents UIAutomation assemblies from loading in the current session
# which would conflict with Get-MpPreference in 02-Security_Config-Win11.ps1
Write-Host "  • Attempting to automate 'Get updates' click..." -ForegroundColor Gray

$automationScript = @'
try {
    Add-Type -AssemblyName UIAutomationClient -ErrorAction Stop
    Add-Type -AssemblyName UIAutomationTypes -ErrorAction Stop

    Start-Sleep -Seconds 3

    $desktop = [System.Windows.Automation.AutomationElement]::RootElement
    $condition = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::NameProperty,
        "Microsoft Store"
    )
    $storeWindow = $desktop.FindFirst([System.Windows.Automation.TreeScope]::Children, $condition)

    if ($storeWindow -eq $null) {
        Write-Output "NOTFOUND:Window not found"
        exit 1
    }

    Start-Sleep -Seconds 2

    $buttonTexts = @("Get updates", "Check for updates", "Update all")
    foreach ($buttonText in $buttonTexts) {
        $buttonCondition = New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::NameProperty,
            $buttonText
        )
        $button = $storeWindow.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $buttonCondition)

        if ($button -ne $null) {
            $invokePattern = $button.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
            if ($invokePattern -ne $null) {
                $invokePattern.Invoke()
                Write-Output "SUCCESS:$buttonText"
                exit 0
            }
        }
    }
    Write-Output "NOTFOUND:Button not found"
    exit 1
} catch {
    Write-Output "ERROR:$($_.Exception.Message)"
    exit 1
}
'@

try {
    # Execute automation in separate process with hidden window
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"$automationScript`""
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    $process.Start() | Out-Null

    # Wait up to 10 seconds
    $timeout = $process.WaitForExit(10000)
    $output = $process.StandardOutput.ReadToEnd()

    if ($output -match "SUCCESS:(.+)") {
        Write-Host "  ✓ Successfully clicked '$($matches[1])' button!" -ForegroundColor Green
    } elseif ($output -match "NOTFOUND:(.+)") {
        Write-Host "  ⚠ $($matches[1])" -ForegroundColor Yellow
        Write-Host "    Please manually click 'Get updates' in the Microsoft Store" -ForegroundColor Gray
    } elseif ($output -match "ERROR:(.+)") {
        Write-Host "  ⚠ Automation error: $($matches[1])" -ForegroundColor Yellow
        Write-Host "    Please manually click 'Get updates' in the Microsoft Store" -ForegroundColor Gray
    } elseif (-not $timeout) {
        Write-Host "  ⚠ Automation timed out" -ForegroundColor Yellow
        Write-Host "    Please manually click 'Get updates' in the Microsoft Store" -ForegroundColor Gray
        $process.Kill()
    } else {
        Write-Host "  ⚠ Automation completed with unknown status" -ForegroundColor Yellow
        Write-Host "    Please manually click 'Get updates' in the Microsoft Store" -ForegroundColor Gray
    }
} catch {
    Write-Host "  ⚠ Could not start automation process: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "    Please manually click 'Get updates' in the Microsoft Store" -ForegroundColor Gray
}

Write-Host "`n  ℹ️  Microsoft Store is open - verify updates are checking/installing" -ForegroundColor Cyan

# Footer
# $elapsed = ((Get-Date) - $script:StartTime).TotalSeconds
Write-Host "`n" -NoNewline
Write-Host ("─" * 60) -ForegroundColor DarkGray
# Write-Host "  ⏱️  Scan completed in " -NoNewline -ForegroundColor Gray
# Write-Host "$([math]::Round($elapsed, 2)) seconds" -ForegroundColor White
# Write-Host ""
# Write-Host ("─" * 60) -ForegroundColor DarkGray
# Set the timestamp this script was last edited
$lastEditedTimestamp = "2025-11-04"
Write-Host "Last Edited: $lastEditedTimestamp" -ForegroundColor Green
Write-Host "www.AIIT.support all rights reserved" -ForegroundColor Green
Write-Host ("─" * 60) -ForegroundColor DarkGray


