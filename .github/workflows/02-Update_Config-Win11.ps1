#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
  Checks and sets Windows Update (WU) UX settings and Windows Security settings, reporting before/after.
.NOTES
  UX keys can be overridden by policy under HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
  Combined script that configures both Windows Update and Windows Security settings
#>

# Global timer
$script:StartTime = Get-Date

# --- Shared utility functions ---

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

# --- Windows Update Functions ---

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
        Write-Host "Active hours: {0}:00 - {1}:00" -f $ahs,$ahe -ForegroundColor Gray
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

# --- Windows Security Functions (from WindowsSecurityConfig.ps1) ---

function Get-DefenderStatus {
    Write-SectionHeader "Virus & threat protection" "🛡️"

    $preferences = Get-MpPreference
    $realTimeOff = $preferences.DisableRealtimeMonitoring

    # Real-time protection (always shown)
    Write-StatusIcon (!$realTimeOff)
    Write-Host "Real-time protection" -ForegroundColor White

    # Only show Dev Drive protection and Controlled folder access when Real-time protection is enabled
    if (-not $realTimeOff) {
        Write-StatusIcon (!$preferences.DisableDevDriveScanning)
        Write-Host "Dev Drive protection" -ForegroundColor White

        Write-StatusIcon ($preferences.EnableControlledFolderAccess -eq 1)
        Write-Host "Controlled folder access" -ForegroundColor White
    }

    Write-StatusIcon ($preferences.MAPSReporting -ne 0)
    Write-Host "Cloud-delivered protection" -ForegroundColor White

    $ssc = $preferences.SubmitSamplesConsent
    Write-StatusIcon ($ssc -ne 0)
    Write-Host "Automatic sample submission" -ForegroundColor White

    # Tamper Protection
    try {
        $tamperProtection = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -ErrorAction Stop
        $tamperEnabled = ($tamperProtection -eq 1 -or $tamperProtection -eq 5)
        Write-StatusIcon $tamperEnabled
        Write-Host "Tamper protection" -ForegroundColor White
    } catch {
        Write-Host " ? " -NoNewline -ForegroundColor Yellow
        Write-Host "Tamper protection (Unable to determine)" -ForegroundColor Gray
    }
}

function Get-AccountProtection {
    Write-SectionHeader "Account protection" "👤"

    # --- New Windows Hello Logic ---
    $pinEnabled = $false
    $faceEnabled = $false
    $fingerprintEnabled = $false
    $userSID = ""

    try {
        $userSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    } catch {
         # If we can't get SID, we can't check biometrics.
         # We can still check for PIN.
    }

    # 1. Check for PIN
    # Check for user's AAD/NGC registration key. This is a common
    # check for a user-configured PIN or Hello setup.
    try {
        $helloKey = "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\AADNGC"
        if (Test-Path -Path $helloKey -ErrorAction SilentlyContinue) {
            $pinEnabled = $true
        }
    } catch { }

    # 2. Check for Biometrics (Face/Fingerprint)
    $enrolledFactors = 0
    if ($userSID) {
        try {
            $enrolledFactors = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo\$userSID" -Name "EnrolledFactors" -ErrorAction SilentlyContinue
        } catch { }
    }

    # EnrolledFactors is a bitmask: 1=Fingerprint, 2=Face
    if (($enrolledFactors -band 1) -eq 1) {
        $fingerprintEnabled = $true
    }
    if (($enrolledFactors -band 2) -eq 2) {
        $faceEnabled = $true
    }

    # 3. Final Check
    # Hello is considered "configured" if ANY of the three are set up.
    $helloConfigured = $pinEnabled -or $faceEnabled -or $fingerprintEnabled

    Write-StatusIcon $helloConfigured
    Write-Host "Windows Hello" -ForegroundColor White
    # --- End New Windows Hello Logic ---


    # Dynamic Lock Logic
    $dynamicLockEnabled = $false
    try {
        $dynamicLock = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "EnableGoodbye" -ErrorAction Stop
        if ($dynamicLock -eq 1) { $dynamicLockEnabled = $true }
    } catch { }
    Write-StatusIcon $dynamicLockEnabled
    Write-Host "Dynamic lock" -ForegroundColor White

    # Facial Recognition Logic
    # We can just reuse the $faceEnabled variable from the check above.
    Write-StatusIcon ($faceEnabled)
    Write-Host "Facial recognition" -ForegroundColor White
}

function Get-FirewallStatus {
    Write-SectionHeader "Firewall & network protection" "🔥"

    # Helper to get profile object safely
    function Get-Profile($Name) {
        try { return Get-NetFirewallProfile -Name $Name -ErrorAction Stop } catch { return $null }
    }

    $domainProfile  = Get-Profile -Name Domain
    $privateProfile = Get-Profile -Name Private
    $publicProfile  = Get-Profile -Name Public

    # Print each profile state using icons
    if ($domainProfile) {
        Write-StatusIcon $domainProfile.Enabled
        Write-Host "Domain network" -ForegroundColor White
    } else {
        Write-Host " ? Domain network (Unable to determine)" -ForegroundColor Gray
    }

    if ($privateProfile) {
        Write-StatusIcon $privateProfile.Enabled
        Write-Host "Private network" -ForegroundColor White
    } else {
        Write-Host " ? Private network (Unable to determine)" -ForegroundColor Gray
    }

    if ($publicProfile) {
        Write-StatusIcon $publicProfile.Enabled
        Write-Host "Public network" -ForegroundColor White
    } else {
        Write-Host " ? Public network (Unable to determine)" -ForegroundColor Gray
    }

    # Determine which profiles have the firewall enabled
    $activeProfiles = @()
    if ($domainProfile -and $domainProfile.Enabled)  { $activeProfiles += 'Domain' }
    if ($privateProfile -and $privateProfile.Enabled) { $activeProfiles += 'Private' }
    if ($publicProfile -and $publicProfile.Enabled)  { $activeProfiles += 'Public' }

    # Show active network names
    try {
        $activeConnections = Get-NetConnectionProfile -ErrorAction Stop
        if ($activeConnections) {
            Write-Host "`n   Active networks:" -ForegroundColor DarkGray
            foreach ($profile in $activeConnections) {
                Write-Host "   • $($profile.Name) ($($profile.NetworkCategory))" -ForegroundColor Gray
            }
        }
    } catch { }
}

function Get-ReputationProtection {
    Write-SectionHeader "App & browser control" "🌐"

    $preferences = Get-MpPreference

    Write-Host "`n  Reputation-based protection" -ForegroundColor Cyan

    # SmartScreen
    $checkApps = Get-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -DefaultValue "Warn"
    Write-StatusIcon ($checkApps -ne 'Off')
    Write-Host "Check apps and files" -ForegroundColor White

    $edgeSmartScreen = Get-RegistryValue -Path "HKCU:\Software\Microsoft\Edge\SmartScreen" -Name "Enabled" -DefaultValue 1
    Write-StatusIcon ($edgeSmartScreen -ne 0)
    Write-Host "SmartScreen for Microsoft Edge" -ForegroundColor White

    $storeSmartScreen = Get-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -DefaultValue 1
    Write-StatusIcon ($storeSmartScreen -ne 0)
    Write-Host "SmartScreen for Microsoft Store apps" -ForegroundColor White

    # Phishing protection
    Write-Host "`n  Phishing protection" -ForegroundColor Cyan

    $phishNotifyMalicious = Get-RegistryValue -Path "HKCU:\Software\Microsoft\PhishingProtection" -Name "NotifyMalicious" -DefaultValue 1
    Write-StatusIcon ($phishNotifyMalicious -ne 0)
    Write-Host "Warn about malicious apps and sites" -ForegroundColor White

    $phishNotifyPasswordReuse = Get-RegistryValue -Path "HKCU:\Software\Microsoft\PhishingProtection" -Name "NotifyPasswordReuse" -DefaultValue 1
    Write-StatusIcon ($phishNotifyPasswordReuse -ne 0)
    Write-Host "Warn about password reuse" -ForegroundColor White

    $phishNotifyUnsafeStorage = Get-RegistryValue -Path "HKCU:\Software\Microsoft\PhishingProtection" -Name "NotifyUnsafeStorage" -DefaultValue 1
    Write-StatusIcon ($phishNotifyUnsafeStorage -ne 0)
    Write-Host "Warn about unsafe password storage" -ForegroundColor White

    # Potentially unwanted app blocking
    Write-Host "`n  Potentially unwanted app blocking" -ForegroundColor Cyan

    $puaEnabled = $preferences.PUAProtection -eq 1
    Write-StatusIcon $puaEnabled
    Write-Host "Block apps" -ForegroundColor White

    # Determine Block downloads (Edge SmartScreen PUA setting).
    function Get-EdgePUABlockDownloadsEnabled {
        # 1) Check Group Policy path (system-wide policy)
        try {
            $policyVal = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'SmartScreenPuaEnabled' -ErrorAction Stop
            if ($null -ne $policyVal) { return ($policyVal -ne 0) }
        } catch { }

        # 2) Check named value under HKCU\Software\Microsoft\Edge
        try {
            $userNamed = Get-ItemPropertyValue -Path 'HKCU:\Software\Microsoft\Edge' -Name 'SmartScreenPuaEnabled' -ErrorAction Stop
            if ($null -ne $userNamed) { return ($userNamed -ne 0) }
        } catch { }

        # 3) Check legacy/per-user key where the key itself exists and its default value holds the DWORD:
        try {
            $subKey = 'Software\Microsoft\Edge\SmartScreenPuaEnabled'
            $rk = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($subKey)
            if ($rk -ne $null) {
                $defaultVal = $rk.GetValue("")   # default value of the key
                if ($null -ne $defaultVal) { return ($defaultVal -ne 0) }
            }
        } catch { }

        # 4) Fallback: check Edge SmartScreen Enabled flags that imply downloads blocking
        try {
            $edgeSmart = Get-RegistryValue -Path "HKCU:\Software\Microsoft\Edge\SmartScreen" -Name "Enabled" -DefaultValue 1
            # If SmartScreen for Edge is off then downloads blocking cannot be on.
            if ($edgeSmart -eq 0) { return $false }
        } catch { }

        return $false
    }

    $blockDownloads = Get-EdgePUABlockDownloadsEnabled
    Write-StatusIcon ($blockDownloads)
    Write-Host "Block downloads" -ForegroundColor White
}

function Get-CoreIsolationStatus {
    Write-SectionHeader "Device security" "🔒"

    $preferences = Get-MpPreference

    Write-Host "`n  Core isolation" -ForegroundColor Cyan

    $memIntegrity = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -DefaultValue 0
    Write-StatusIcon ($memIntegrity -eq 1)
    Write-Host "Memory integrity" -ForegroundColor White

    $kernelStackProt = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks" -Name "Enabled" -DefaultValue 0
    Write-StatusIcon ($kernelStackProt -eq 1)
    Write-Host "Kernel-mode Hardware-enforced Stack Protection" -ForegroundColor White

    Write-Host "`n  Security processor" -ForegroundColor Cyan

    $lsaProtection = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -DefaultValue 0
    Write-StatusIcon ($lsaProtection -ge 1)
    Write-Host "Local Security Authority protection" -ForegroundColor White

    Write-StatusIcon (!$preferences.DisableVulnerableDriverBlocklist)
    Write-Host "Microsoft Vulnerable Driver Blocklist" -ForegroundColor White
}

function Get-ScanInformation {
    Write-SectionHeader "Scan information" "🔍"

    $status = Get-MpComputerStatus

    Write-Host "  Last quick scan:      " -NoNewline -ForegroundColor Gray
    Write-Host $status.QuickScanStartTime -ForegroundColor White

    Write-Host "  Last full scan:       " -NoNewline -ForegroundColor Gray
    Write-Host $status.FullScanStartTime -ForegroundColor White

    Write-Host "  Signature version:    " -NoNewline -ForegroundColor Gray
    Write-Host $status.AntivirusSignatureVersion -ForegroundColor White

    Write-Host "  Last updated:         " -NoNewline -ForegroundColor Gray
    Write-Host $status.AntivirusSignatureLastUpdated -ForegroundColor White
}

# --- Main Execution ---
try {
    Clear-Host

    # Header
    Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Blue
    Write-Host "║     " -NoNewline -ForegroundColor Blue
    Write-Host "WINDOWS UPDATE & SECURITY CONFIGURATION" -NoNewline -ForegroundColor White
    Write-Host "        ║" -ForegroundColor Blue
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Blue

    # Windows Update Configuration
    Set-WUSettings
    Show-WUStatus

    # Windows Security Status
    Get-DefenderStatus
    Get-AccountProtection
    Get-FirewallStatus
    Get-ReputationProtection
    Get-CoreIsolationStatus
    Get-ScanInformation

    # Footer: print local date/time and elapsed time
    $elapsed = ((Get-Date) - $script:StartTime).TotalSeconds
    $now = Get-Date
    $localDate = $now.ToString('yyyy-MM-dd')
    $localTime = $now.ToString('hh:mm tt')
    $tz = Get-TimeZone

    if ($tz.Id -match 'UTC') {
        $tzAbbr = 'UTC'
    } else {
        $tzName = if ([System.TimeZoneInfo]::Local.IsDaylightSavingTime($now)) { $tz.DaylightName } else { $tz.StandardName }
        $clean = ($tzName -replace '[^A-Za-z\s]','').Trim()
        $tzAbbr = ($clean -split '\s+' | ForEach-Object { $_.Substring(0,1).ToUpper() }) -join ''
    }

    Write-Host "`n" -NoNewline
    Write-Host ("─" * 60) -ForegroundColor DarkGray
    Write-Host "  ⏱️  Scan completed in " -NoNewline -ForegroundColor Gray
    Write-Host "$([math]::Round($elapsed, 2)) seconds" -ForegroundColor White
    Write-Host ("─" * 60) -ForegroundColor DarkGray
    Write-Host "  Script last edited: " -NoNewline -ForegroundColor Gray
    Write-Host "$localDate $localTime $tzAbbr" -ForegroundColor White
    Write-Host "  www.AIIT.support all rights reserved" -ForegroundColor Green
    Write-Host ("─" * 60) -ForegroundColor DarkGray
    Write-Host ""

} catch {
    Write-Host "`n[ERROR] " -NoNewline -ForegroundColor Red
    Write-Host $_ -ForegroundColor White
    Write-Host "`nMake sure you're running this script as Administrator.`n" -ForegroundColor Yellow
}
