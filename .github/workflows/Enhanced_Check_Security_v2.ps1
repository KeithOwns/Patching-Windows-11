#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Enhanced Comprehensive Security Checks with Modern Windows 11 Features
.DESCRIPTION
    Combines comprehensive enterprise security checks with modern Windows 11 security features.
    Includes security scoring, visual output, and deep Windows Defender integration.

    Features:
    - Traditional enterprise security checks (firewall, updates, policies, etc.)
    - Modern Windows 11 security (Core Isolation, Tamper Protection, etc.)
    - Security score calculation (0-100)
    - Visual status icons with color coding
    - Severity levels (Critical/Warning/Info)
    - Domain-specific checks for enterprise environments

.PARAMETER OutputPath
    (Optional) Path to save the security report as a text file.

.PARAMETER ShowScore
    Display security score summary at the end.

.EXAMPLE
    .\Enhanced_Check_Security_v2.ps1
    Runs all security checks and displays results.

.EXAMPLE
    .\Enhanced_Check_Security_v2.ps1 -OutputPath "C:\Reports\SecurityReport.txt" -ShowScore
    Runs checks, shows security score, and saves report.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [switch]$ShowScore
)

# Initialize results array
$script:Results = @()
$script:RealTimeProtectionEnabled = $true

# --- ENHANCED FUNCTIONS WITH MODERN FEATURES ---

function Add-Result {
    <#
    .SYNOPSIS
        Adds a security check result with severity level
    #>
    param (
        [Parameter(Mandatory)]
        [string]$TestName,

        [Parameter(Mandatory)]
        [ValidateSet('Passed','Failed','Error','Info')]
        [string]$Status,

        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Critical','Warning','Info')]
        [string]$Severity = 'Warning'
    )

    $script:Results += [PSCustomObject]@{
        Test     = $TestName
        Status   = $Status
        Message  = $Message
        Severity = $Severity
    }
}

function Write-StatusIcon {
    <#
    .SYNOPSIS
        Displays visual status indicator with color coding
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Status,

        [Parameter(Mandatory = $false)]
        [string]$Severity = "Warning"
    )

    if ($Status -eq 'Passed') {
        Write-Host " " -NoNewline -BackgroundColor DarkGreen -ForegroundColor White
        Write-Host "✓" -NoNewline -BackgroundColor DarkGreen -ForegroundColor White
        Write-Host " " -NoNewline -BackgroundColor DarkGreen -ForegroundColor White
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

function Get-SecurityScore {
    <#
    .SYNOPSIS
        Calculates overall security score based on all checks
    #>
    param()

    $totalChecks = $script:Results.Count
    if ($totalChecks -eq 0) { return 0 }

    $weightedScore = 0
    $maxWeight = 0

    foreach ($result in $script:Results) {
        $weight = switch ($result.Severity) {
            "Critical" { 3 }
            "Warning" { 2 }
            "Info" { 1 }
            default { 1 }
        }

        $maxWeight += $weight
        if ($result.Status -eq 'Passed') {
            $weightedScore += $weight
        }
    }

    if ($maxWeight -eq 0) { return 0 }

    return [math]::Round(($weightedScore / $maxWeight) * 100)
}

function Get-RegValue {
    param([string]$Path, [string]$Name, $DefaultValue = $null)
    try {
        if (Test-Path $Path) {
            return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
        }
        return $DefaultValue
    } catch { return $DefaultValue }
}

function Get-AntivirusStatus {
    <#
    .SYNOPSIS
        Interprets the productState value for Antivirus products
    #>
    param([int]$ProductState)

    # Decode the productState bitmask
    $currentState = $ProductState -band 0xFF
    $definitionState = ($ProductState -band 0xFF00) -shr 8
    $onAccessProtection = ($ProductState -band 0xFF0000) -shr 16

    # Determine current state
    switch ($currentState) {
        0 { $status = "OFF" }
        1 { $status = "SUSPENDED" }
        10 { $status = "RUNNING" }
        11 { $status = "OFFLINE" }
        default { $status = "UNKNOWN" }
    }

    # Determine definition state
    switch ($definitionState) {
        0 { $defState = "UNKNOWN" }
        1 { $defState = "OUT-OF-DATE" }
        2 { $defState = "UPDATED" }
        default { $defState = "UNKNOWN" }
    }

    # Determine on-access protection
    switch ($onAccessProtection) {
        0 { $onAccess = "OFF" }
        1 { $onAccess = "ON" }
        default { $onAccess = "UNKNOWN" }
    }

    return @{
        Status             = $status
        DefinitionStatus   = $defState
        OnAccessProtection = $onAccess
    }
}

# --- MODERN WINDOWS 11 SECURITY CHECKS ---

function Test-ModernDefenderFeatures {
    <#
    .SYNOPSIS
        Checks modern Windows 11 Defender features
    #>
    Write-Host "`n🛡️  Modern Windows Defender Features" -ForegroundColor Cyan
    Write-Host ("─" * 60) -ForegroundColor DarkGray

    try {
        $preferences = Get-MpPreference -ErrorAction Stop
        $computerStatus = Get-MpComputerStatus -ErrorAction Stop

        # Real-time Protection
        $rtpEnabled = !$preferences.DisableRealtimeMonitoring
        $script:RealTimeProtectionEnabled = $rtpEnabled
        Add-Result -TestName "Real-time Protection" -Status $(if($rtpEnabled){'Passed'}else{'Failed'}) `
            -Message $(if($rtpEnabled){"Enabled"}else{"Disabled"}) -Severity "Critical"

        # Tamper Protection
        try {
            $tamper = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -DefaultValue 0
            $tamperEnabled = ($tamper -eq 1 -or $tamper -eq 5)
            Add-Result -TestName "Tamper Protection" -Status $(if($tamperEnabled){'Passed'}else{'Failed'}) `
                -Message $(if($tamperEnabled){"Enabled"}else{"Disabled - Enable via Windows Security UI"}) -Severity "Critical"
        } catch {
            Add-Result -TestName "Tamper Protection" -Status "Error" -Message "Unable to determine status" -Severity "Critical"
        }

        # Controlled Folder Access
        $cfaEnabled = $preferences.EnableControlledFolderAccess -eq 1
        $cfaStatus = if (!$script:RealTimeProtectionEnabled) {
            Add-Result -TestName "Controlled Folder Access" -Status "Info" `
                -Message "Inactive - Requires Real-time Protection" -Severity "Warning"
        } else {
            Add-Result -TestName "Controlled Folder Access" -Status $(if($cfaEnabled){'Passed'}else{'Failed'}) `
                -Message $(if($cfaEnabled){"Enabled"}else{"Disabled"}) -Severity "Warning"
        }

        # Network Protection
        $npEnabled = $preferences.EnableNetworkProtection -eq 1
        if (!$script:RealTimeProtectionEnabled) {
            Add-Result -TestName "Network Protection (Exploit Protection)" -Status "Info" `
                -Message "Inactive - Requires Real-time Protection" -Severity "Warning"
        } else {
            Add-Result -TestName "Network Protection (Exploit Protection)" -Status $(if($npEnabled){'Passed'}else{'Failed'}) `
                -Message $(if($npEnabled){"Enabled"}else{"Disabled"}) -Severity "Warning"
        }

        # Cloud-delivered Protection
        $cloudEnabled = $preferences.MAPSReporting -ne 0
        Add-Result -TestName "Cloud-delivered Protection" -Status $(if($cloudEnabled){'Passed'}else{'Failed'}) `
            -Message $(if($cloudEnabled){"Enabled"}else{"Disabled"}) -Severity "Warning"

        # PUA Protection
        $puaEnabled = $preferences.PUAProtection -eq 1
        Add-Result -TestName "Potentially Unwanted App Blocking" -Status $(if($puaEnabled){'Passed'}else{'Failed'}) `
            -Message $(if($puaEnabled){"Enabled"}else{"Disabled"}) -Severity "Warning"

    } catch {
        Add-Result -TestName "Modern Defender Features" -Status "Error" `
            -Message "Failed to check: $($_.Exception.Message)" -Severity "Critical"
    }
}

function Test-CoreIsolation {
    <#
    .SYNOPSIS
        Checks Core Isolation and hardware security features
    #>
    Write-Host "`n🔒 Core Isolation & Hardware Security" -ForegroundColor Cyan
    Write-Host ("─" * 60) -ForegroundColor DarkGray

    try {
        # Memory Integrity (HVCI)
        $hvci = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" `
            -Name "Enabled" -DefaultValue 0
        $hvciEnabled = $hvci -eq 1
        Add-Result -TestName "Memory Integrity (Core Isolation)" -Status $(if($hvciEnabled){'Passed'}else{'Failed'}) `
            -Message $(if($hvciEnabled){"Enabled"}else{"Disabled - Requires compatible hardware"}) -Severity "Warning"

        # Kernel Stack Protection
        $kss = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks" `
            -Name "Enabled" -DefaultValue 0
        $kssEnabled = $kss -ge 1
        Add-Result -TestName "Kernel-mode Hardware-enforced Stack Protection" -Status $(if($kssEnabled){'Passed'}else{'Info'}) `
            -Message $(if($kssEnabled){"Enabled"}else{"Not enabled - Requires Windows 11 22H2+ and compatible CPU"}) -Severity "Info"

        # LSA Protection
        $lsa = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -DefaultValue 0
        $lsaEnabled = $lsa -ge 1
        Add-Result -TestName "Local Security Authority Protection" -Status $(if($lsaEnabled){'Passed'}else{'Failed'}) `
            -Message $(if($lsaEnabled){"Enabled"}else{"Disabled - Protects against credential theft"}) -Severity "Warning"

        # Vulnerable Driver Blocklist
        try {
            $preferences = Get-MpPreference -ErrorAction Stop
            $driverBlocklist = !$preferences.DisableVulnerableDriverBlocklist
            Add-Result -TestName "Microsoft Vulnerable Driver Blocklist" -Status $(if($driverBlocklist){'Passed'}else{'Failed'}) `
                -Message $(if($driverBlocklist){"Enabled"}else{"Disabled"}) -Severity "Warning"
        } catch {
            Add-Result -TestName "Vulnerable Driver Blocklist" -Status "Error" -Message "Unable to check" -Severity "Warning"
        }

    } catch {
        Add-Result -TestName "Core Isolation" -Status "Error" `
            -Message "Failed to check: $($_.Exception.Message)" -Severity "Warning"
    }
}

# --- MAIN EXECUTION ---

Clear-Host
Write-Host "`n" -NoNewline
Write-Host ("═" * 70) -ForegroundColor Blue
Write-Host "  ENHANCED WINDOWS SECURITY COMPREHENSIVE CHECK v2.0" -ForegroundColor White
Write-Host ("═" * 70) -ForegroundColor Blue
Write-Host "`n  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host "  Computer: $env:COMPUTERNAME" -ForegroundColor Gray
Write-Host "  User: $env:USERNAME" -ForegroundColor Gray

# Run modern Windows 11 security checks first
Test-ModernDefenderFeatures
Test-CoreIsolation

# --- COMPREHENSIVE ENTERPRISE SECURITY CHECKS ---

### 1. Check Windows Firewall Status ###
Write-Host "`n🔥 Windows Firewall Status" -ForegroundColor Cyan
Write-Host ("─" * 60) -ForegroundColor DarkGray

try {
    $firewallStatus = Get-NetFirewallProfile | Select-Object Name, Enabled
    foreach ($profile in $firewallStatus) {
        if ($profile.Enabled) {
            Add-Result -TestName "Windows Firewall ($($profile.Name))" -Status "Passed" `
                -Message "Firewall is enabled." -Severity "Critical"
        } else {
            Add-Result -TestName "Windows Firewall ($($profile.Name))" -Status "Failed" `
                -Message "Firewall is disabled." -Severity "Critical"
        }
    }
} catch {
    Add-Result -TestName "Windows Firewall Status" -Status "Error" `
        -Message $_.Exception.Message -Severity "Critical"
}

### 2. Check Antivirus Status (Any AV) ###
Write-Host "`n🛡️  Antivirus Status (All Products)" -ForegroundColor Cyan
Write-Host ("─" * 60) -ForegroundColor DarkGray

try {
    $antivirusProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntivirusProduct -ErrorAction SilentlyContinue

    if ($antivirusProducts) {
        foreach ($av in $antivirusProducts) {
            $statusInfo = Get-AntivirusStatus -ProductState $av.productState
            if ($statusInfo.Status -eq "RUNNING" -and $statusInfo.DefinitionStatus -eq "UPDATED" -and $statusInfo.OnAccessProtection -eq "ON") {
                Add-Result -TestName "Antivirus ($($av.displayName))" -Status "Passed" `
                    -Message "Antivirus is enabled, up-to-date, and real-time protection is active." -Severity "Critical"
            } else {
                Add-Result -TestName "Antivirus ($($av.displayName))" -Status "Failed" `
                    -Message "Status: $($statusInfo.Status), Definitions: $($statusInfo.DefinitionStatus), Real-Time: $($statusInfo.OnAccessProtection)." -Severity "Critical"
            }
        }
    } else {
        Add-Result -TestName "Antivirus Status" -Status "Failed" `
            -Message "No antivirus product found." -Severity "Critical"
    }
} catch {
    Add-Result -TestName "Antivirus Status" -Status "Error" `
        -Message $_.Exception.Message -Severity "Critical"
}

### 3. Check Windows Update Service Status ###
Write-Host "`n🔄 Windows Update Service" -ForegroundColor Cyan
Write-Host ("─" * 60) -ForegroundColor DarkGray

try {
    $wuSettings = Get-Service -Name wuauserv -ErrorAction Stop
    if ($wuSettings.Status -eq 'Running') {
        Add-Result -TestName "Windows Update Service" -Status "Passed" `
            -Message "Windows Update service is running." -Severity "Warning"
    } else {
        Add-Result -TestName "Windows Update Service" -Status "Failed" `
            -Message "Windows Update service is not running." -Severity "Warning"
    }
} catch {
    Add-Result -TestName "Windows Update Status" -Status "Error" `
        -Message $_.Exception.Message -Severity "Warning"
}

### 4. Check Pending Windows Updates ###
try {
    $updateSession = New-Object -ComObject Microsoft.Update.Session -ErrorAction SilentlyContinue
    if ($updateSession) {
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
        if ($searchResult.Updates.Count -gt 0) {
            Add-Result -TestName "Pending Windows Updates" -Status "Failed" `
                -Message "$($searchResult.Updates.Count) pending updates found." -Severity "Warning"
        } else {
            Add-Result -TestName "Pending Windows Updates" -Status "Passed" `
                -Message "No pending updates." -Severity "Warning"
        }
    }
} catch {
    Add-Result -TestName "Pending Windows Updates" -Status "Info" `
        -Message "Unable to check: $($_.Exception.Message)" -Severity "Info"
}

### 5. Check Account Lockout Policies ###
Write-Host "`n🔐 Account & Password Policies" -ForegroundColor Cyan
Write-Host ("─" * 60) -ForegroundColor DarkGray

try {
    $lockoutThreshold = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "LockoutThreshold"
    $lockoutDuration = (Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "LockoutDuration") / 60
    $resetCounter = (Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "LockoutObservationWindow") / 60

    $acceptableThreshold = 5
    $acceptableDuration = 15
    $acceptableReset = 15

    if (($lockoutThreshold -le $acceptableThreshold) -and ($lockoutDuration -ge $acceptableDuration) -and ($resetCounter -ge $acceptableReset)) {
        Add-Result -TestName "Account Lockout Policy" -Status "Passed" `
            -Message "Threshold: $lockoutThreshold, Duration: $lockoutDuration min, Reset: $resetCounter min." -Severity "Warning"
    } else {
        Add-Result -TestName "Account Lockout Policy" -Status "Failed" `
            -Message "Threshold: $lockoutThreshold, Duration: $lockoutDuration min, Reset: $resetCounter min." -Severity "Warning"
    }
} catch {
    Add-Result -TestName "Account Lockout Policies" -Status "Error" `
        -Message $_.Exception.Message -Severity "Warning"
}

### 6. Check Password Policies ###
try {
    $passwordLength = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "MinimumPasswordLength"
    $passwordHistory = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "PasswordHistorySize"
    $passwordComplexity = Get-RegValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PasswordComplexity"

    $acceptableLength = 12
    $acceptableHistory = 24

    if (($passwordLength -ge $acceptableLength) -and ($passwordHistory -ge $acceptableHistory) -and ($passwordComplexity -eq 1)) {
        Add-Result -TestName "Password Policy" -Status "Passed" `
            -Message "Min Length: $passwordLength, History: $passwordHistory, Complexity: Enabled." -Severity "Warning"
    } else {
        $complexityStatus = if ($passwordComplexity -eq 1) { "Enabled" } else { "Disabled" }
        Add-Result -TestName "Password Policy" -Status "Failed" `
            -Message "Min Length: $passwordLength, History: $passwordHistory, Complexity: $complexityStatus." -Severity "Warning"
    }
} catch {
    Add-Result -TestName "Password Policies" -Status "Error" `
        -Message $_.Exception.Message -Severity "Warning"
}

### 7. Check Audit Policies ###
Write-Host "`n📋 Audit Policies" -ForegroundColor Cyan
Write-Host ("─" * 60) -ForegroundColor DarkGray

try {
    $auditLogonEnabled = $false
    $auditObjectAccessEnabled = $false
    $auditPrivilegeUseEnabled = $false

    if (Get-Command AuditPol -ErrorAction SilentlyContinue) {
        $logon = AuditPol /get /category:"Logon/Logoff" 2>$null | Select-String "Audit Logon"
        $objectAccess = AuditPol /get /category:"Object Access" 2>$null | Select-String "Audit Object Access"
        $privilegeUse = AuditPol /get /category:"Privilege Use" 2>$null | Select-String "Audit Privilege Use"

        $auditLogonEnabled = $logon -and $logon.Line -match "Success and Failure"
        $auditObjectAccessEnabled = $objectAccess -and $objectAccess.Line -match "Success and Failure"
        $auditPrivilegeUseEnabled = $privilegeUse -and $privilegeUse.Line -match "Success and Failure"
    }

    if ($auditLogonEnabled -and $auditObjectAccessEnabled -and $auditPrivilegeUseEnabled) {
        Add-Result -TestName "Audit Policies" -Status "Passed" `
            -Message "Critical audit policies are enabled." -Severity "Warning"
    } else {
        Add-Result -TestName "Audit Policies" -Status "Failed" `
            -Message "Logon: $auditLogonEnabled, Object Access: $auditObjectAccessEnabled, Privilege Use: $auditPrivilegeUseEnabled." -Severity "Warning"
    }
} catch {
    Add-Result -TestName "Audit Policies" -Status "Error" `
        -Message $_.Exception.Message -Severity "Warning"
}

### 8. Check Unnecessary Services ###
Write-Host "`n⚙️  Security Services" -ForegroundColor Cyan
Write-Host ("─" * 60) -ForegroundColor DarkGray

try {
    $unnecessaryServices = @("Telnet", "RemoteRegistry", "Fax", "WMPNetworkSvc")

    foreach ($service in $unnecessaryServices) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc) {
            if ($svc.Status -ne 'Stopped') {
                Add-Result -TestName "Service ($service)" -Status "Failed" `
                    -Message "Service is running and may be unnecessary." -Severity "Warning"
            } else {
                Add-Result -TestName "Service ($service)" -Status "Passed" `
                    -Message "Service is stopped." -Severity "Warning"
            }
        } else {
            Add-Result -TestName "Service ($service)" -Status "Info" `
                -Message "Service is not installed." -Severity "Info"
        }
    }
} catch {
    Add-Result -TestName "Unnecessary Services" -Status "Error" `
        -Message $_.Exception.Message -Severity "Warning"
}

### 9. Check Network Security Settings ###
Write-Host "`n🌐 Network Security" -ForegroundColor Cyan
Write-Host ("─" * 60) -ForegroundColor DarkGray

try {
    # Check SMBv1 is disabled
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($smb1 -and $smb1.State -eq "Disabled") {
        Add-Result -TestName "SMBv1 Protocol" -Status "Passed" `
            -Message "SMBv1 is disabled." -Severity "Warning"
    } else {
        Add-Result -TestName "SMBv1 Protocol" -Status "Failed" `
            -Message "SMBv1 is enabled. Recommended to disable." -Severity "Warning"
    }

    # Check Remote Desktop
    $rdp = Get-Service -Name TermService -ErrorAction SilentlyContinue
    if ($rdp) {
        if ($rdp.Status -eq 'Running') {
            Add-Result -TestName "Remote Desktop Service" -Status "Info" `
                -Message "RDP is running. Ensure it's required and secured." -Severity "Info"
        } else {
            Add-Result -TestName "Remote Desktop Service" -Status "Passed" `
                -Message "RDP service is stopped." -Severity "Info"
        }
    }

    # Check WinRM
    $winrm = Get-Service -Name WinRM -ErrorAction SilentlyContinue
    if ($winrm) {
        if ($winrm.StartType -eq 'Automatic' -and $winrm.Status -eq 'Running') {
            Add-Result -TestName "Windows Remote Management (WinRM)" -Status "Info" `
                -Message "WinRM is running. Ensure it's secured properly." -Severity "Info"
        } else {
            Add-Result -TestName "Windows Remote Management (WinRM)" -Status "Passed" `
                -Message "WinRM is not running." -Severity "Info"
        }
    }
} catch {
    Add-Result -TestName "Network Security Settings" -Status "Error" `
        -Message $_.Exception.Message -Severity "Warning"
}

### 10. Check Firewall Rules ###
try {
    $defaultInbound = (Get-NetFirewallRule -Direction Inbound -Action Allow -ErrorAction SilentlyContinue | Measure-Object).Count
    $defaultOutbound = (Get-NetFirewallRule -Direction Outbound -Action Allow -ErrorAction SilentlyContinue | Measure-Object).Count

    if ($defaultInbound -eq 0 -and $defaultOutbound -eq 0) {
        Add-Result -TestName "Firewall Rules" -Status "Passed" `
            -Message "Default deny rules are in place." -Severity "Warning"
    } else {
        Add-Result -TestName "Firewall Rules" -Status "Info" `
            -Message "Allow rules present ($defaultInbound inbound, $defaultOutbound outbound). Review for least privilege." -Severity "Info"
    }
} catch {
    Add-Result -TestName "Firewall Rules" -Status "Error" `
        -Message $_.Exception.Message -Severity "Info"
}

### 11. Check Administrative Shares ###
Write-Host "`n📁 Administrative Shares & Software" -ForegroundColor Cyan
Write-Host ("─" * 60) -ForegroundColor DarkGray

try {
    $adminShares = Get-WmiObject -Class Win32_Share -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^\w+\$$' }
    if ($adminShares.Count -gt 0) {
        foreach ($share in $adminShares) {
            Add-Result -TestName "Administrative Share ($($share.Name))" -Status "Info" `
                -Message "Administrative share is present." -Severity "Info"
        }
    } else {
        Add-Result -TestName "Administrative Shares" -Status "Passed" `
            -Message "No administrative shares found." -Severity "Info"
    }
} catch {
    Add-Result -TestName "Administrative Shares" -Status "Error" `
        -Message $_.Exception.Message -Severity "Info"
}

### 12. Check Installed Software Vulnerabilities ###
try {
    $vulnerableSoftware = @("Adobe Acrobat Reader", "Java SE", "Mozilla Firefox", "Google Chrome")
    $installedSoftware = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
        Select-Object DisplayName, DisplayVersion |
        Where-Object { $_.DisplayName -and ($vulnerableSoftware -contains $_.DisplayName) }

    if ($installedSoftware) {
        foreach ($app in $installedSoftware) {
            Add-Result -TestName "Software ($($app.DisplayName))" -Status "Info" `
                -Message "Version: $($app.DisplayVersion). Consider updating." -Severity "Info"
        }
    } else {
        Add-Result -TestName "Vulnerable Software" -Status "Passed" `
            -Message "No commonly vulnerable software detected." -Severity "Info"
    }
} catch {
    Add-Result -TestName "Installed Software" -Status "Error" `
        -Message $_.Exception.Message -Severity "Info"
}

### 13. Check Drive Encryption ###
Write-Host "`n🔒 Drive Encryption" -ForegroundColor Cyan
Write-Host ("─" * 60) -ForegroundColor DarkGray

try {
    $bitLockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
    if ($bitLockerVolumes) {
        foreach ($vol in $bitLockerVolumes) {
            if ($vol.VolumeStatus -eq 'FullyEncrypted') {
                Add-Result -TestName "BitLocker ($($vol.MountPoint))" -Status "Passed" `
                    -Message "BitLocker is fully encrypted." -Severity "Warning"
            } elseif ($vol.VolumeStatus -eq 'EncryptionInProgress') {
                Add-Result -TestName "BitLocker ($($vol.MountPoint))" -Status "Info" `
                    -Message "Encryption in progress." -Severity "Info"
            } else {
                Add-Result -TestName "BitLocker ($($vol.MountPoint))" -Status "Failed" `
                    -Message "BitLocker is not enabled or not fully encrypted." -Severity "Warning"
            }
        }
    } else {
        # Check Device Encryption
        $deviceEncryption = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess" -Name "DeviceEncryptionEnabled"
        if ($deviceEncryption -eq 1) {
            Add-Result -TestName "Device Encryption" -Status "Passed" `
                -Message "Device encryption is enabled." -Severity "Warning"
        } else {
            Add-Result -TestName "Drive Encryption" -Status "Info" `
                -Message "Encryption status could not be determined." -Severity "Info"
        }
    }
} catch {
    Add-Result -TestName "Drive Encryption" -Status "Error" `
        -Message $_.Exception.Message -Severity "Warning"
}

### 14. Check Browser Security Settings ###
Write-Host "`n🌐 Browser Security" -ForegroundColor Cyan
Write-Host ("─" * 60) -ForegroundColor DarkGray

try {
    $edgeSettingsPath = "HKCU:\Software\Microsoft\Edge\Main"
    if (Test-Path $edgeSettingsPath) {
        $smartScreen = Get-RegValue -Path $edgeSettingsPath -Name "SmartScreenEnabled"
        if ($smartScreen -eq "Require") {
            Add-Result -TestName "Edge SmartScreen" -Status "Passed" `
                -Message "Edge SmartScreen is enabled." -Severity "Info"
        } else {
            Add-Result -TestName "Edge SmartScreen" -Status "Failed" `
                -Message "Edge SmartScreen is not enabled." -Severity "Info"
        }
    } else {
        Add-Result -TestName "Edge SmartScreen" -Status "Info" `
            -Message "Edge settings not found." -Severity "Info"
    }
} catch {
    Add-Result -TestName "Browser Security" -Status "Error" `
        -Message $_.Exception.Message -Severity "Info"
}

### 15. Check Domain Membership and Domain-Specific Checks ###
Write-Host "`n🏢 Domain & Enterprise Checks" -ForegroundColor Cyan
Write-Host ("─" * 60) -ForegroundColor DarkGray

function Is-DomainJoined {
    try {
        $computerSystem = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
        return $computerSystem.PartOfDomain
    } catch {
        return $false
    }
}

try {
    if (Is-DomainJoined) {
        Add-Result -TestName "Domain Membership" -Status "Passed" `
            -Message "System is joined to a domain." -Severity "Info"

        # Domain Controller Connectivity (simplified check)
        try {
            $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $domainName = $domain.Name
            Add-Result -TestName "Domain Controller Connectivity" -Status "Passed" `
                -Message "Connected to domain: $domainName" -Severity "Warning"
        } catch {
            Add-Result -TestName "Domain Controller Connectivity" -Status "Failed" `
                -Message "Unable to contact domain controller." -Severity "Warning"
        }
    } else {
        Add-Result -TestName "Domain Membership" -Status "Info" `
            -Message "System is not joined to a domain." -Severity "Info"
    }
} catch {
    Add-Result -TestName "Domain Membership" -Status "Error" `
        -Message $_.Exception.Message -Severity "Info"
}

Write-Host "`n" -NoNewline
Write-Host ("═" * 70) -ForegroundColor Blue
Write-Host "  📊 SECURITY CHECK SUMMARY" -ForegroundColor White
Write-Host ("═" * 70) -ForegroundColor Blue

# Calculate results
$passed = ($script:Results | Where-Object { $_.Status -eq 'Passed' }).Count
$failed = ($script:Results | Where-Object { $_.Status -eq 'Failed' }).Count
$errors = ($script:Results | Where-Object { $_.Status -eq 'Error' }).Count
$info = ($script:Results | Where-Object { $_.Status -eq 'Info' }).Count
$critical = ($script:Results | Where-Object { $_.Status -ne 'Passed' -and $_.Severity -eq 'Critical' }).Count

Write-Host "`n  Passed Tests       : " -NoNewline -ForegroundColor Gray
Write-Host $passed -ForegroundColor Green
Write-Host "  Failed Tests       : " -NoNewline -ForegroundColor Gray
Write-Host $failed -ForegroundColor $(if($failed -gt 0){'Red'}else{'Green'})
Write-Host "  Errors Encountered : " -NoNewline -ForegroundColor Gray
Write-Host $errors -ForegroundColor $(if($errors -gt 0){'Yellow'}else{'Green'})
Write-Host "  Information Notes  : " -NoNewline -ForegroundColor Gray
Write-Host $info -ForegroundColor Magenta
Write-Host "  Critical Issues    : " -NoNewline -ForegroundColor Gray
Write-Host $critical -ForegroundColor $(if($critical -gt 0){'Red'}else{'Green'})

if ($ShowScore) {
    $score = Get-SecurityScore
    $scoreColor = if ($score -ge 80) { "Green" } elseif ($score -ge 60) { "Yellow" } else { "Red" }
    $scoreRating = if ($score -ge 90) { "EXCELLENT" } elseif ($score -ge 80) { "GOOD" } elseif ($score -ge 60) { "FAIR" } else { "POOR" }

    Write-Host "`n" -NoNewline
    Write-Host ("─" * 70) -ForegroundColor DarkGray
    Write-Host "  SECURITY SCORE: " -NoNewline -ForegroundColor Gray
    Write-Host "$score/100" -NoNewline -ForegroundColor $scoreColor
    Write-Host "  [$scoreRating]" -ForegroundColor $scoreColor
    Write-Host ("─" * 70) -ForegroundColor DarkGray
}

# Display results with modern formatting
Write-Host "`n" -NoNewline
Write-Host ("═" * 70) -ForegroundColor Blue
Write-Host "  DETAILED RESULTS" -ForegroundColor White
Write-Host ("═" * 70) -ForegroundColor Blue

foreach ($result in $script:Results) {
    Write-StatusIcon -Status $result.Status -Severity $result.Severity
    Write-Host "$($result.Test): " -NoNewline -ForegroundColor White

    $messageColor = switch ($result.Status) {
        'Passed' { 'Green' }
        'Failed' { 'Red' }
        'Error' { 'Yellow' }
        'Info' { 'Cyan' }
    }
    Write-Host $result.Message -ForegroundColor $messageColor
}

# Show critical issues if any
if ($critical -gt 0) {
    Write-Host "`n⚠️  CRITICAL ISSUES FOUND:" -ForegroundColor Red
    Write-Host ("─" * 60) -ForegroundColor DarkGray
    $criticalResults = $script:Results | Where-Object { $_.Status -ne 'Passed' -and $_.Severity -eq 'Critical' }
    foreach ($result in $criticalResults) {
        Write-Host "   • $($result.Test): " -NoNewline -ForegroundColor Red
        Write-Host $result.Message -ForegroundColor White
    }
}

# Special warning if Real-time Protection is disabled
if (!$script:RealTimeProtectionEnabled) {
    Write-Host "`n🚨 REAL-TIME PROTECTION IS DISABLED" -ForegroundColor Red
    Write-Host ("─" * 60) -ForegroundColor DarkGray
    Write-Host "The following features are INACTIVE without Real-time Protection:" -ForegroundColor Yellow
    Write-Host "   • Controlled Folder Access (ransomware protection)" -ForegroundColor Gray
    Write-Host "   • Network Protection (exploit protection)" -ForegroundColor Gray
    Write-Host "   • Behavior Monitoring" -ForegroundColor Gray
    Write-Host "`n➜ Enable Real-time Protection first to activate these features" -ForegroundColor Cyan
}

Write-Host "`n" -NoNewline
Write-Host ("─" * 70) -ForegroundColor DarkGray
Write-Host "  Scan completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host "  Enhanced by: www.AIIT.support" -ForegroundColor Green
Write-Host ("─" * 70) -ForegroundColor DarkGray
Write-Host ""

# Save to file if OutputPath specified
if ($OutputPath) {
    try {
        $outputDir = Split-Path -Path $OutputPath -Parent
        if (!(Test-Path -Path $outputDir)) {
            New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
        }

        $reportContent = @"
Enhanced Windows Security Comprehensive Check Report v2.0
Date: $(Get-Date)
Computer: $env:COMPUTERNAME
User: $env:USERNAME

═══════════════════════════════════════════════════════════════
SUMMARY:
═══════════════════════════════════════════════════════════════
Passed Tests       : $passed
Failed Tests       : $failed
Errors Encountered : $errors
Information Notes  : $info
Critical Issues    : $critical

"@

        if ($ShowScore) {
            $score = Get-SecurityScore
            $reportContent += "Security Score     : $score/100`n`n"
        }

        $reportContent += @"
═══════════════════════════════════════════════════════════════
DETAILED RESULTS:
═══════════════════════════════════════════════════════════════

"@

        foreach ($result in $script:Results) {
            $statusSymbol = if ($result.Status -eq 'Passed') { '[PASS]' } else { '[FAIL]' }
            $reportContent += "{0,-10} {1,-50} {2}`n" -f $statusSymbol, $result.Test, $result.Message
        }

        $reportContent | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Host "✓ Report saved to: $OutputPath" -ForegroundColor Green
    } catch {
        Write-Host "✗ Failed to save report: $($_.Exception.Message)" -ForegroundColor Red
    }
}
