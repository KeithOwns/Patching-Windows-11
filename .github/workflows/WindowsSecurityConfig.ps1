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

    Write-StatusIcon (!$realTimeOff)
    Write-Host "Real-time protection" -ForegroundColor White
    
    Write-StatusIcon (!$preferences.DisableDevDriveScanning)
    Write-Host "Dev Drive protection" -ForegroundColor White
    
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

    Write-StatusIcon ($preferences.EnableControlledFolderAccess -eq 1)
    Write-Host "Controlled folder access" -ForegroundColor White
}

function Get-AccountProtection {
    Write-SectionHeader "Account protection" "👤"

    # Windows Hello Logic
    $helloConfigured = $false
    try {
        $accountInfo = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo" -ErrorAction Stop
        if ($accountInfo.Count -gt 0) { $helloConfigured = $true }
    } catch { }
    Write-StatusIcon $helloConfigured
    Write-Host "Windows Hello" -ForegroundColor White

    # Dynamic Lock Logic
    $dynamicLockEnabled = $false
    try {
        $dynamicLock = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "EnableGoodbye" -ErrorAction Stop
        if ($dynamicLock -eq 1) { $dynamicLockEnabled = $true }
    } catch { }
    Write-StatusIcon $dynamicLockEnabled
    Write-Host "Dynamic lock" -ForegroundColor White

    # Facial Recognition Logic
    $userSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $enrolledFactors = 0
    try { $enrolledFactors = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo\$userSID" -Name "EnrolledFactors" -ErrorAction SilentlyContinue } catch { }
    
    Write-StatusIcon ($enrolledFactors -eq 2)
    Write-Host "Facial recognition" -ForegroundColor White
}

function Get-FirewallStatus {
    Write-SectionHeader "Firewall & network protection" "🔥"

    # Helper to print profile state
    function Print-FirewallProfile($Name, $DisplayName) {
        try {
            $profile = Get-NetFirewallProfile -Name $Name -ErrorAction Stop
            Write-StatusIcon $profile.Enabled
            Write-Host "$DisplayName network" -ForegroundColor White
        } catch {
            Write-Host " ? " -NoNewline -ForegroundColor Yellow
            Write-Host "$DisplayName network (Unable to determine)" -ForegroundColor Gray
        }
    }

    Print-FirewallProfile -Name Domain -DisplayName "Domain"
    Print-FirewallProfile -Name Private -DisplayName "Private"
    Print-FirewallProfile -Name Public -DisplayName "Public"

    # Get Active networks
    try {
        $activeProfiles = Get-NetConnectionProfile -ErrorAction Stop
        if ($activeProfiles) {
            Write-Host "`n   Active networks:" -ForegroundColor DarkGray
            foreach ($profile in $activeProfiles) {
                Write-Host "   • $($profile.Name)" -ForegroundColor Gray
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

    $phishServiceCollection = Get-RegValue -Path "HKCU:\Software\Microsoft\PhishingProtection" -Name "ServiceCollection" -DefaultValue 1
    Write-StatusIcon ($phishServiceCollection -ne 0)
    Write-Host "Automatically collect content for analysis" -ForegroundColor White

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
    
    # Footer
    Write-Host "`n" -NoNewline
    Write-Host ("─" * 60) -ForegroundColor DarkGray
    Write-Host "  Script last edited: " -NoNewline -ForegroundColor Gray
    Write-Host "2025-10-27 by Sonnet 4.5" -ForegroundColor White
    Write-Host ""
    
} catch {
    Write-Host "`n[ERROR] " -NoNewline -ForegroundColor Red
    Write-Host $_ -ForegroundColor White
    Write-Host "`nMake sure you're running this script as Administrator.`n" -ForegroundColor Yellow
}