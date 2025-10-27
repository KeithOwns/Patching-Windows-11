#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Checks current Windows Defender Virus & Threat Protection settings
.DESCRIPTION
    Retrieves and displays all Virus & threat protection configurations with Windows Security styling
.NOTES
    Requires Administrator privileges
#>

function Get-RegValue($Path, $Name, $DefaultValue) {
    try { return Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop }
    catch { return $DefaultValue }
}

function Write-StatusIcon($IsEnabled) {
    if ($IsEnabled) {
        Write-Host " " -NoNewline -BackgroundColor DarkCyan -ForegroundColor Black
        Write-Host "✓" -NoNewline -BackgroundColor DarkCyan -ForegroundColor Black
        Write-Host " " -NoNewline -BackgroundColor DarkCyan -ForegroundColor Black
        Write-Host " " -NoNewline
    } else {
        Write-Host " ✗ " -NoNewline -ForegroundColor Red
    }
}

function Write-SectionHeader($Title, $Icon = "🛡️") {
    Write-Host "`n$Icon " -NoNewline -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor White
    Write-Host ("─" * 60) -ForegroundColor DarkGray
}

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

    # Print consolidated active-profile summary
    # if ($activeProfiles.Count -gt 0) {
    #     $list = $activeProfiles -join ', '
    #     Write-Host "`n  Firewall active on: " -NoNewline -ForegroundColor Gray
    #     Write-Host $list -ForegroundColor White
    # } else {
    #     Write-Host "`n  Firewall active on: " -NoNewline -ForegroundColor Gray
    #     Write-Host "None" -ForegroundColor Yellow
    # }

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
    $checkApps = Get-RegValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -DefaultValue "Warn"
    Write-StatusIcon ($checkApps -ne 'Off')
    Write-Host "Check apps and files" -ForegroundColor White

    $edgeSmartScreen = Get-RegValue -Path "HKCU:\Software\Microsoft\Edge\SmartScreen" -Name "Enabled" -DefaultValue 1
    Write-StatusIcon ($edgeSmartScreen -ne 0)
    Write-Host "SmartScreen for Microsoft Edge" -ForegroundColor White

    $storeSmartScreen = Get-RegValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -DefaultValue 1
    Write-StatusIcon ($storeSmartScreen -ne 0)
    Write-Host "SmartScreen for Microsoft Store apps" -ForegroundColor White

    # Phishing protection
    Write-Host "`n  Phishing protection" -ForegroundColor Cyan
    
    $phishNotifyMalicious = Get-RegValue -Path "HKCU:\Software\Microsoft\PhishingProtection" -Name "NotifyMalicious" -DefaultValue 1
    Write-StatusIcon ($phishNotifyMalicious -ne 0)
    Write-Host "Warn about malicious apps and sites" -ForegroundColor White

    $phishNotifyPasswordReuse = Get-RegValue -Path "HKCU:\Software\Microsoft\PhishingProtection" -Name "NotifyPasswordReuse" -DefaultValue 1
    Write-StatusIcon ($phishNotifyPasswordReuse -ne 0)
    Write-Host "Warn about password reuse" -ForegroundColor White

    $phishNotifyUnsafeStorage = Get-RegValue -Path "HKCU:\Software\Microsoft\PhishingProtection" -Name "NotifyUnsafeStorage" -DefaultValue 1
    Write-StatusIcon ($phishNotifyUnsafeStorage -ne 0)
    Write-Host "Warn about unsafe password storage" -ForegroundColor White

    # $phishServiceCollection = Get-RegValue -Path "HKCU:\Software\Microsoft\PhishingProtection" -Name "ServiceCollection" -DefaultValue 1
    # Write-StatusIcon ($phishServiceCollection -ne 0)
    # Write-Host "Automatically collect content for analysis" -ForegroundColor White

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
            $edgeSmart = Get-RegValue -Path "HKCU:\Software\Microsoft\Edge\SmartScreen" -Name "Enabled" -DefaultValue 1
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
    
    $memIntegrity = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -DefaultValue 0
    Write-StatusIcon ($memIntegrity -eq 1)
    Write-Host "Memory integrity" -ForegroundColor White

    $kernelStackProt = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks" -Name "Enabled" -DefaultValue 0
    Write-StatusIcon ($kernelStackProt -eq 1)
    Write-Host "Kernel-mode Hardware-enforced Stack Protection" -ForegroundColor White

    Write-Host "`n  Security processor" -ForegroundColor Cyan
    
    $lsaProtection = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -DefaultValue 0
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

try {
    Clear-Host
    
    # Header
    Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Blue
    Write-Host "║          " -NoNewline -ForegroundColor Blue
    Write-Host "WINDOWS SECURITY STATUS REPORT" -NoNewline -ForegroundColor White
    Write-Host "             ║" -ForegroundColor Blue
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Blue

    Get-DefenderStatus
    Get-AccountProtection
    Get-FirewallStatus
    Get-ReputationProtection
    Get-CoreIsolationStatus
    Get-ScanInformation
    
    # Footer: print local date/time like "Script last edited: 2025-10-27 10:14 AM PDT by Gemini 2.5 Pro"
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
    Write-Host "  Script last edited: " -NoNewline -ForegroundColor Gray
    Write-Host "$localDate $localTime $tzAbbr by Gemini 2.5 Pro" -ForegroundColor White
    Write-Host ""
    
} catch {
    Write-Host "`n[ERROR] " -NoNewline -ForegroundColor Red
    Write-Host $_ -ForegroundColor White
    Write-Host "`nMake sure you're running this script as Administrator.`n" -ForegroundColor Yellow
}
