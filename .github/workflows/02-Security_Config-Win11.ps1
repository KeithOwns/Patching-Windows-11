#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Comprehensive Windows Security Status Checker with Reporting and Remediation
.DESCRIPTION
    Retrieves and displays all Windows Security configurations with visual formatting,
    security scoring, export capabilities, and remediation suggestions.

    Automatically detects whether Windows Defender or third-party antivirus software
    is managing virus protection, and adapts the report accordingly.

    Features:
    - Automatic third-party antivirus detection
    - Security score calculation (0-100)
    - Visual console output with color-coded status
    - HTML and JSON export options
    - Remediation suggestions for disabled features
    - Baseline comparison mode

.PARAMETER ExportHtml
    Export the report to an HTML file
.PARAMETER ExportJson
    Export the report to a JSON file
.PARAMETER OutputPath
    Path for exported reports (default: current directory)
.PARAMETER ShowRemediation
    Display PowerShell commands to fix disabled security features
.PARAMETER CompareToBaseline
    Compare current state to a saved baseline JSON file
.PARAMETER SaveAsBaseline
    Save current state as a baseline JSON file
.NOTES
    Requires Administrator privileges
    Encoding: UTF-8 (required for proper display of icons and special characters)
    Compatible with: Windows 10/11 with Windows Defender or third-party antivirus
    Automatically detects: Symantec, McAfee, Trend Micro, Norton, and other major AV products
.EXAMPLE
    .\02-Security_Config-Win11.ps1
    Displays the current Windows Security status
.EXAMPLE
    .\02-Security_Config-Win11.ps1 -ExportHtml -OutputPath "C:\Reports"
    Generates an HTML report in the specified directory
.EXAMPLE
    .\02-Security_Config-Win11.ps1 -ShowRemediation
    Shows remediation commands for disabled features
.EXAMPLE
    .\02-Security_Config-Win11.ps1 -SaveAsBaseline "C:\baseline.json"
    Saves current state as a baseline for future comparison
#>

param(
    [Parameter(Mandatory = $false)]
    [switch]$ExportHtml,
    
    [Parameter(Mandatory = $false)]
    [switch]$ExportJson,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".",
    
    [Parameter(Mandatory = $false)]
    [switch]$ShowRemediation,
    
    [Parameter(Mandatory = $false)]
    [string]$CompareToBaseline,
    
    [Parameter(Mandatory = $false)]
    [string]$SaveAsBaseline
)

# Global variables for tracking results
$script:SecurityChecks = @()
$script:BaselineData = $null
$script:RealTimeProtectionEnabled = $true  # Track if real-time protection is on

# Security check result class
class SecurityCheck {
    [string]$Category
    [string]$Name
    [bool]$IsEnabled
    [string]$Severity  # Critical, Warning, Info
    [string]$Remediation
    [string]$Details
}

function Get-RegValue {
    <#
    .SYNOPSIS
        Safely retrieves a registry value with error handling
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        $DefaultValue
    )
    
    try { 
        return Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop 
    }
    catch { 
        return $DefaultValue 
    }
}

function Add-SecurityCheck {
    <#
    .SYNOPSIS
        Adds a security check result to the global tracking array
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Category,
        
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [bool]$IsEnabled,
        
        [Parameter(Mandatory = $false)]
        [string]$Severity = "Warning",
        
        [Parameter(Mandatory = $false)]
        [string]$Remediation = "",
        
        [Parameter(Mandatory = $false)]
        [string]$Details = ""
    )
    
    $check = [SecurityCheck]@{
        Category = $Category
        Name = $Name
        IsEnabled = $IsEnabled
        Severity = $Severity
        Remediation = $Remediation
        Details = $Details
    }
    
    $script:SecurityChecks += $check
}

function Write-StatusIcon {
    <#
    .SYNOPSIS
        Displays a visual status indicator with severity color coding
    #>
    param(
        [Parameter(Mandatory = $true)]
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
    <#
    .SYNOPSIS
        Displays a formatted section header
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,
        
        [Parameter(Mandatory = $false)]
        [string]$Icon = "🛡️"
    )
    
    Write-Host "`n$Icon " -NoNewline -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor White
    Write-Host ("─" * 60) -ForegroundColor DarkGray
}

function Get-ThirdPartyAntivirus {
    <#
    .SYNOPSIS
        Detects if third-party antivirus software is managing virus protection
    .OUTPUTS
        Returns PSCustomObject with IsThirdParty (bool) and ProductName (string)
    #>
    try {
        # Query Windows Security Center for antivirus products
        $antivirusProducts = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction Stop

        foreach ($av in $antivirusProducts) {
            # Filter out Windows Defender (displayName contains "Defender" or "Windows Security")
            if ($av.displayName -notmatch "Defender|Windows Security") {
                # Check if the product is enabled (productState encoding)
                # Bit manipulation: productState contains status info
                # If productState indicates the AV is enabled, it's managing protection
                $productState = $av.productState

                # Extract enabled status (varies by product, but generally if productState > 0, it's installed)
                # More reliable: if a third-party product is listed and not disabled
                if ($productState) {
                    return [PSCustomObject]@{
                        IsThirdParty = $true
                        ProductName = $av.displayName
                    }
                }
            }
        }

        # No third-party AV found
        return [PSCustomObject]@{
            IsThirdParty = $false
            ProductName = "Windows Defender"
        }
    } catch {
        # If we can't query SecurityCenter2, assume Windows Defender
        # (SecurityCenter2 may not be available on some systems)
        return [PSCustomObject]@{
            IsThirdParty = $false
            ProductName = "Windows Defender"
        }
    }
}

function Get-DefenderStatus {
    <#
    .SYNOPSIS
        Retrieves and displays Windows Defender virus and threat protection status
        or detects third-party antivirus software
    #>
    param()

    Write-SectionHeader "Virus & threat protection" "🛡️"
    # Check for third-party antivirus software
    $avInfo = Get-ThirdPartyAntivirus

    if ($avInfo.IsThirdParty) {
        # Third-party antivirus detected
        Write-Host "`n  ℹ️  " -NoNewline -ForegroundColor Cyan
        Write-Host "Managed by third-party software: " -NoNewline -ForegroundColor White
        Write-Host "$($avInfo.ProductName)" -ForegroundColor Green
        Write-Host "    Windows Defender checks skipped (third-party antivirus active)" -ForegroundColor Gray

        # Set global flag to false since third-party AV is in use
        $script:RealTimeProtectionEnabled = $false

        Add-SecurityCheck -Category "Virus & Threat Protection" -Name "Third-party antivirus" -IsEnabled $true -Severity "Info" `
            -Remediation "N/A - Managed by $($avInfo.ProductName)" `
            -Details "Virus and threat protection is managed by third-party antivirus: $($avInfo.ProductName)"

        return
    }

    # Windows Defender is the primary AV - proceed with normal checks
    Write-Host "`n  ℹ️  " -NoNewline -ForegroundColor Cyan
    Write-Host "Using Windows Defender as primary antivirus" -ForegroundColor Gray

    # Get Windows Defender preferences with error handling
    try {
        $preferences = Get-MpPreference -ErrorAction Stop
    } catch {
        Write-Host "`n  ✗ " -NoNewline -ForegroundColor Red
        Write-Host "Unable to retrieve Windows Defender settings" -ForegroundColor Yellow
        Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Gray
        Write-Host "`n    ⚠️  TROUBLESHOOTING:" -ForegroundColor Yellow
        Write-Host "    • Ensure Windows Defender service is running: Get-Service WinDefend" -ForegroundColor White
        Write-Host "    • Try running: Start-Service WinDefend" -ForegroundColor White
        Write-Host "    • If issue persists, restart PowerShell and run this script alone" -ForegroundColor White

        Add-SecurityCheck -Category "Virus & Threat Protection" -Name "Defender Module Status" -IsEnabled $false -Severity "Critical" `
            -Remediation "Ensure Windows Defender service is running, then rerun this script" `
            -Details "Failed to load Windows Defender preferences: $($_.Exception.Message)"

        return
    }

    $realTimeOff = $preferences.DisableRealtimeMonitoring
    
    # Store real-time protection status globally for dependency checks
    $script:RealTimeProtectionEnabled = !$realTimeOff

    $enabled = !$realTimeOff
    Write-StatusIcon $enabled -Severity "Critical"
    Write-Host "Real-time protection" -ForegroundColor White
    Add-SecurityCheck -Category "Virus & Threat Protection" -Name "Real-time protection" -IsEnabled $enabled -Severity "Critical" `
        -Remediation "Set-MpPreference -DisableRealtimeMonitoring `$false" `
        -Details "Real-time scanning protects against malware in real-time. REQUIRED for: Controlled Folder Access, Behavior Monitoring, Dev Drive Protection, Network Protection"
    
    # Show warning if Real-time Protection is off
    if (!$enabled) {
        Write-Host "   ⚠️  " -NoNewline -ForegroundColor Red
        Write-Host "WARNING: Several features below will not work without Real-time protection" -ForegroundColor Yellow
    }
    
    $enabled = !$preferences.DisableDevDriveScanning
    # Dev Drive requires Real-time Protection
    if (!$script:RealTimeProtectionEnabled -and $enabled) {
        Write-StatusIcon $false -Severity "Info"
        Write-Host "Dev Drive protection " -NoNewline -ForegroundColor White
        Write-Host "(inactive - requires Real-time protection)" -ForegroundColor DarkGray
        Add-SecurityCheck -Category "Virus & Threat Protection" -Name "Dev Drive protection" -IsEnabled $false -Severity "Info" `
            -Remediation "First enable Real-time protection, then: Set-MpPreference -DisableDevDriveScanning `$false" `
            -Details "Scans developer drives for threats. REQUIRES Real-time protection to be enabled"
    } else {
        Write-StatusIcon $enabled -Severity "Info"
        Write-Host "Dev Drive protection" -ForegroundColor White
        Add-SecurityCheck -Category "Virus & Threat Protection" -Name "Dev Drive protection" -IsEnabled $enabled -Severity "Info" `
            -Remediation "Set-MpPreference -DisableDevDriveScanning `$false" `
            -Details "Scans developer drives for threats. Requires Real-time protection"
    }
    
    # MAPS (Microsoft Active Protection Service) Reporting
    $enabled = $preferences.MAPSReporting -ne 0
    Write-StatusIcon $enabled -Severity "Warning"
    Write-Host "Cloud-delivered protection" -NoNewline -ForegroundColor White
    if (!$script:RealTimeProtectionEnabled -and $enabled) {
        Write-Host " (limited effectiveness)" -ForegroundColor DarkGray
    } else {
        Write-Host ""
    }
    Add-SecurityCheck -Category "Virus & Threat Protection" -Name "Cloud-delivered protection" -IsEnabled $enabled -Severity "Warning" `
        -Remediation "Set-MpPreference -MAPSReporting Advanced" `
        -Details "Enables cloud-based protection for faster threat response. Works best with Real-time protection"

    # Submit Samples Consent
    $sampleSubmissionConsent = $preferences.SubmitSamplesConsent
    $enabled = $sampleSubmissionConsent -ne 0
    Write-StatusIcon $enabled -Severity "Warning"
    Write-Host "Automatic sample submission" -ForegroundColor White
    Add-SecurityCheck -Category "Virus & Threat Protection" -Name "Automatic sample submission" -IsEnabled $enabled -Severity "Warning" `
        -Remediation "Set-MpPreference -SubmitSamplesConsent SendAllSamples" `
        -Details "Automatically sends suspicious files to Microsoft for analysis"

    # Tamper Protection
    try {
        $tamperProtection = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -ErrorAction Stop
        $enabled = ($tamperProtection -eq 1 -or $tamperProtection -eq 5)
        Write-StatusIcon $enabled -Severity "Critical"
        Write-Host "Tamper protection" -ForegroundColor White
        Add-SecurityCheck -Category "Virus & Threat Protection" -Name "Tamper protection" -IsEnabled $enabled -Severity "Critical" `
            -Remediation "Enable via Windows Security UI (cannot be set via PowerShell)" `
            -Details "Prevents malicious apps from changing security settings"
    } catch {
        Write-Host " ? " -NoNewline -ForegroundColor Yellow
        Write-Host "Tamper protection (Unable to determine)" -ForegroundColor Gray
        Add-SecurityCheck -Category "Virus & Threat Protection" -Name "Tamper protection" -IsEnabled $false -Severity "Critical" `
            -Details "Unable to determine status"
    }

    # Controlled Folder Access - REQUIRES Real-time Protection
    $cfaEnabled = $preferences.EnableControlledFolderAccess -eq 1
    if (!$script:RealTimeProtectionEnabled) {
        # If Real-time Protection is off, Controlled Folder Access cannot work
        Write-StatusIcon $false -Severity "Warning"
        Write-Host "Controlled folder access " -NoNewline -ForegroundColor White
        Write-Host "(inactive - requires Real-time protection)" -ForegroundColor DarkGray
        Add-SecurityCheck -Category "Virus & Threat Protection" -Name "Controlled folder access" -IsEnabled $false -Severity "Warning" `
            -Remediation "First enable Real-time protection, then: Set-MpPreference -EnableControlledFolderAccess Enabled" `
            -Details "Protects important folders from ransomware. REQUIRES Real-time protection to function"
    } else {
        Write-StatusIcon $cfaEnabled -Severity "Warning"
        Write-Host "Controlled folder access" -ForegroundColor White
        Add-SecurityCheck -Category "Virus & Threat Protection" -Name "Controlled folder access" -IsEnabled $cfaEnabled -Severity "Warning" `
            -Remediation "Set-MpPreference -EnableControlledFolderAccess Enabled" `
            -Details "Protects important folders from ransomware. Requires Real-time protection"
    }
    
    # Removed: The "Advanced protection" header and "Behavior monitoring" check.
}

function Get-AccountProtection {
    <#
    .SYNOPSIS
        Retrieves and displays account protection settings
    #>
    param()
    
    Write-SectionHeader "Account protection" "👤"
    # Windows Hello
    $helloConfigured = $false
    try {
        $accountInfo = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo" -ErrorAction Stop
        if ($accountInfo.Count -gt 0) { 
            $helloConfigured = $true 
        }
    } catch { }
    
    Write-StatusIcon $helloConfigured -Severity "Warning"
    Write-Host "Windows Hello" -ForegroundColor White
    Add-SecurityCheck -Category "Account Protection" -Name "Windows Hello" -IsEnabled $helloConfigured -Severity "Warning" `
        -Remediation "Configure via Settings > Accounts > Sign-in options" `
        -Details "Biometric authentication for secure sign-in"

    # Dynamic Lock
    $dynamicLockEnabled = $false
    try {
        $dynamicLock = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "EnableGoodbye" -ErrorAction Stop
        if ($dynamicLock -eq 1) { 
            $dynamicLockEnabled = $true 
        }
    } catch { }
    
    Write-StatusIcon $dynamicLockEnabled -Severity "Info"
    Write-Host "Dynamic lock" -ForegroundColor White
    Add-SecurityCheck -Category "Account Protection" -Name "Dynamic lock" -IsEnabled $dynamicLockEnabled -Severity "Info" `
        -Remediation "Configure via Settings > Accounts > Sign-in options > Dynamic lock" `
        -Details "Automatically locks PC when paired Bluetooth device is out of range"

    # Facial Recognition
    $userSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $enrolledFactors = 0
    try { 
        $enrolledFactors = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo\$userSID" -Name "EnrolledFactors" -ErrorAction SilentlyContinue 
    } catch { }
    
    $enabled = $enrolledFactors -eq 2
    Write-StatusIcon $enabled -Severity "Info"
    Write-Host "Facial recognition" -ForegroundColor White
    Add-SecurityCheck -Category "Account Protection" -Name "Facial recognition" -IsEnabled $enabled -Severity "Info" `
        -Remediation "Configure via Settings > Accounts > Sign-in options > Windows Hello Face" `
        -Details "Face recognition for biometric authentication"
}

function Get-FirewallStatus {
    <#
    .SYNOPSIS
        Retrieves and displays Windows Firewall status
    #>
    param()
    
    Write-SectionHeader "Firewall & network protection" "🔥"
    # Build a dictionary of active networks to display next to their profile status
    $activeNetworks = @{}
    try {
        $profiles = Get-NetConnectionProfile -ErrorAction Stop
        foreach ($profile in $profiles) {
            # Map the connection profile type (e.g., Domain, Private, Public) to its name
            $profileName = switch ($profile.NetworkCategory) {
                'DomainAuthenticated' { 'Domain' }
                'Private'             { 'Private' }
                'Public'              { 'Public' }
            }
            if ($profileName) {
                # Store the network name/identifier, e.g., "noc.agron.com"
                $activeNetworks[$profileName] = $profile.Name
            }
        }
    } catch {
        # Error handling for Get-NetConnectionProfile can be silent, as we handle status below
    }

    # Helper function
    function Test-FirewallProfile {
        param(
            [string]$Name,
            [string]$DisplayName
        )
        
        try {
            $profile = Get-NetFirewallProfile -Name $Name -ErrorAction Stop
            $enabled = $profile.Enabled
            
            # Check if this profile has an active network associated with it
            $networkName = $activeNetworks[$Name]
            $suffix = ""
            if ($networkName) {
                $suffix = " (Active Network: $networkName)"
            }

            Write-StatusIcon $enabled -Severity "Critical"
            Write-Host "$DisplayName network" -NoNewline -ForegroundColor White
            Write-Host $suffix -ForegroundColor DarkGray
            
            Add-SecurityCheck -Category "Firewall & Network Protection" -Name "$DisplayName network firewall" -IsEnabled $enabled -Severity "Critical" `
                -Remediation "Set-NetFirewallProfile -Profile $Name -Enabled True" `
                -Details "Firewall protection for $DisplayName network profile"
        } catch {
            Write-Host " ? " -NoNewline -ForegroundColor Yellow
            Write-Host "$DisplayName network (Unable to determine)" -ForegroundColor Gray
            Add-SecurityCheck -Category "Firewall & Network Protection" -Name "$DisplayName network firewall" -IsEnabled $false -Severity "Critical" `
                -Details "Unable to determine status"
        }
    }

    Test-FirewallProfile -Name Domain -DisplayName "Domain"
    Test-FirewallProfile -Name Private -DisplayName "Private"
    Test-FirewallProfile -Name Public -DisplayName "Public"

    # Removed: Logic to display active networks list separately. It is now inline.
}

function Get-ReputationProtection {
    <#
    .SYNOPSIS
        Retrieves and displays app and browser control settings
    #>
    param()

    Write-SectionHeader "App & browser control" "🌐"
    # Get MpPreference only if not using third-party AV
    $preferences = $null
    if ($script:RealTimeProtectionEnabled) {
        try {
            $preferences = Get-MpPreference -ErrorAction Stop
        } catch {
            # Defender not available
        }
    }

    # Removed extra space
    Write-Host "`nReputation-based protection" -ForegroundColor Cyan
    # SmartScreen for Windows
    $checkApps = Get-RegValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -DefaultValue "Warn"
    $enabled = $checkApps -ne 'Off'
    Write-StatusIcon $enabled -Severity "Warning"
    Write-Host "Check apps and files" -ForegroundColor White
    Add-SecurityCheck -Category "App & Browser Control" -Name "Check apps and files" -IsEnabled $enabled -Severity "Warning" `
        -Remediation "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer' -Name 'SmartScreenEnabled' -Value 'Warn'" `
        -Details "SmartScreen checks downloads and apps for threats"

    # SmartScreen for Edge
    $edgeSmartScreen = Get-RegValue -Path "HKCU:\Software\Microsoft\Edge\SmartScreen" -Name "Enabled" -DefaultValue 1
    $enabled = $edgeSmartScreen -ne 0
    Write-StatusIcon $enabled -Severity "Warning"
    Write-Host "SmartScreen for Microsoft Edge" -ForegroundColor White
    Add-SecurityCheck -Category "App & Browser Control" -Name "SmartScreen for Microsoft Edge" -IsEnabled $enabled -Severity "Warning" `
        -Remediation "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Edge\SmartScreen' -Name 'Enabled' -Value 1" `
        -Details "SmartScreen protection in Microsoft Edge browser"

    # PUA Protection
    $enabled = $false
    if ($preferences) {
        $enabled = $preferences.PUAProtection -eq 1
    }
    Write-StatusIcon $enabled -Severity "Warning"
    Write-Host "Block potentially unwanted apps" -ForegroundColor White
    $remediation = if ($script:RealTimeProtectionEnabled) { "Set-MpPreference -PUAProtection Enabled" } else { "N/A - Managed by third-party antivirus" }
    Add-SecurityCheck -Category "App & Browser Control" -Name "Block potentially unwanted apps" -IsEnabled $enabled -Severity "Warning" `
        -Remediation $remediation `
        -Details "Blocks potentially unwanted applications"
    
    $blockDownloads = Get-EdgePUABlockDownloadsEnabled
    Write-StatusIcon $blockDownloads -Severity "Info"
    Write-Host "Block potentially unwanted downloads" -ForegroundColor White
    Add-SecurityCheck -Category "App & Browser Control" -Name "Block potentially unwanted downloads" -IsEnabled $blockDownloads -Severity "Info" `
        -Remediation "Configure via Edge settings or Group Policy" `
        -Details "Blocks downloads of potentially unwanted software"
    
    # SmartScreen for Store Apps
    $storeSmartScreen = Get-RegValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -DefaultValue 1
    $enabled = $storeSmartScreen -ne 0
    Write-StatusIcon $enabled -Severity "Info"
    Write-Host "SmartScreen for Microsoft Store apps" -ForegroundColor White
    Add-SecurityCheck -Category "App & Browser Control" -Name "SmartScreen for Microsoft Store apps" -IsEnabled $enabled -Severity "Info" `
        -Remediation "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost' -Name 'EnableWebContentEvaluation' -Value 1" `
        -Details "SmartScreen for apps from Microsoft Store"
}

function Get-EdgePUABlockDownloadsEnabled {
    <#
    .SYNOPSIS
        Determines if Microsoft Edge PUA download blocking is enabled
    #>
    param()
    
    # Check Group Policy
    try {
        $policyVal = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'SmartScreenPuaEnabled' -ErrorAction Stop
        if ($null -ne $policyVal) { 
            return ($policyVal -ne 0) 
        }
    } catch { }

    # Check user setting
    try {
        $userNamed = Get-ItemPropertyValue -Path 'HKCU:\Software\Microsoft\Edge' -Name 'SmartScreenPuaEnabled' -ErrorAction Stop
        if ($null -ne $userNamed) { 
            return ($userNamed -ne 0) 
        }
    } catch { }

    # Check legacy location
    try {
        $subKey = 'Software\Microsoft\Edge\SmartScreenPuaEnabled'
        $rk = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($subKey)
        if ($null -ne $rk) {
            $defaultVal = $rk.GetValue("")
            $rk.Close()
            if ($null -ne $defaultVal) { 
                return ($defaultVal -ne 0) 
            }
        }
    } catch { }

    # Fallback
    try {
        $edgeSmartScreen = Get-RegValue -Path "HKCU:\Software\Microsoft\Edge\SmartScreen" -Name "Enabled" -DefaultValue 1
        if ($edgeSmartScreen -eq 0) { 
            return $false 
        }
    } catch { }

    return $false
}

function Get-CoreIsolationStatus {
    <#
    .SYNOPSIS
        Retrieves and displays device security settings
    #>
    param()
    
    Write-SectionHeader "Device security" "🔒"
    # Get MpPreference only if not using third-party AV
    $preferences = $null
    if ($script:RealTimeProtectionEnabled) {
        try {
            $preferences = Get-MpPreference -ErrorAction Stop
        } catch {
            # Defender not available
        }
    }

    # Removed extra space
    Write-Host "`nCore isolation" -ForegroundColor Cyan
    # Memory Integrity
    $memIntegrity = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -DefaultValue 0
    $enabled = $memIntegrity -eq 1
    Write-StatusIcon $enabled -Severity "Warning"
    Write-Host "Memory integrity" -ForegroundColor White
    Add-SecurityCheck -Category "Device Security" -Name "Memory integrity" -IsEnabled $enabled -Severity "Warning" `
        -Remediation "Enable via Windows Security > Device security > Core isolation > Memory integrity" `
        -Details "Hardware-based code integrity protection (requires compatible hardware)"

    # Kernel Stack Protection
    $kernelStackProt = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks" -Name "Enabled" -DefaultValue 0
    $enabled = $kernelStackProt -ge 1
    Write-StatusIcon $enabled -Severity "Info"
    Write-Host "Kernel-mode Hardware-enforced Stack Protection" -ForegroundColor White
    Add-SecurityCheck -Category "Device Security" -Name "Kernel-mode Hardware-enforced Stack Protection" -IsEnabled $enabled -Severity "Info" `
        -Remediation "Requires compatible CPU and Windows 11 22H2+" `
        -Details "Hardware-based kernel stack protection"

    # Removed extra space
    Write-Host "`nSecurity processor" -ForegroundColor Cyan
    # LSA Protection
    $lsaProtection = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -DefaultValue 0
    $enabled = $lsaProtection -ge 1
    Write-StatusIcon $enabled -Severity "Warning"
    Write-Host "Local Security Authority protection" -ForegroundColor White
    Add-SecurityCheck -Category "Device Security" -Name "Local Security Authority protection" -IsEnabled $enabled -Severity "Warning" `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Value 1; Restart-Computer" `
        -Details "Protects LSA process from credential theft"

    # Vulnerable Driver Blocklist
    $enabled = $false
    if ($preferences) {
        $enabled = $preferences.DisableVulnerableDriverBlocklist -eq $false
    }
    Write-StatusIcon $enabled -Severity "Warning"
    Write-Host "Microsoft Vulnerable Driver Blocklist" -ForegroundColor White
    $remediation = if ($script:RealTimeProtectionEnabled) { "Set-MpPreference -DisableVulnerableDriverBlocklist `$false" } else { "N/A - Managed by third-party antivirus" }
    Add-SecurityCheck -Category "Device Security" -Name "Microsoft Vulnerable Driver Blocklist" -IsEnabled $enabled -Severity "Warning" `
        -Remediation $remediation `
        -Details "Blocks known vulnerable drivers from loading"
}

function Get-ScanInformation {
    <#
    .SYNOPSIS
        Retrieves and displays scan information
    #>
    param()
    
    Write-SectionHeader "Scan information" "🔍"
    $status = Get-MpComputerStatus
    $now = Get-Date

    # --- Last Quick Scan ---
    $quickScanTime = $status.QuickScanStartTime
    if ($quickScanTime) {
        $quickScanAge = $now - $quickScanTime
        $quickScanColor = "Green"
        if ($quickScanAge.Days -ge 30) { $quickScanColor = "Red" }
        elseif ($quickScanAge.Days -ge 7) { $quickScanColor = "Yellow" }
        
        Write-Host "  Last quick scan:      " -NoNewline -ForegroundColor Gray
        Write-Host "$($quickScanTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor $quickScanColor
    } else {
        Write-Host "  Last quick scan:      " -NoNewline -ForegroundColor Gray
        Write-Host "N/A" -ForegroundColor Red
    }
    
    # --- Last Full Scan ---
    $fullScanTime = $status.FullScanStartTime
    if ($fullScanTime) {
        $fullScanAge = $now - $fullScanTime
        $fullScanColor = "Green"
        # Red if older than 1 year (approx 365 days)
        if ($fullScanAge.Days -ge 365) { $fullScanColor = "Red" }
        # Yellow if older than 1 month (approx 30 days)
        elseif ($fullScanAge.Days -ge 30) { $fullScanColor = "Yellow" }
        
        Write-Host "  Last full scan:       " -NoNewline -ForegroundColor Gray
        Write-Host "$($fullScanTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor $fullScanColor
    } else {
        Write-Host "  Last full scan:       " -NoNewline -ForegroundColor Gray
        Write-Host "N/A" -ForegroundColor Red
    }

    # --- Signature Version ---
    Write-Host "  Signature version:    " -NoNewline -ForegroundColor Gray
    Write-Host $status.AntivirusSignatureVersion -ForegroundColor White

    # --- Last Updated (Full Timestamp) ---
    $lastUpdatedTime = $status.AntivirusSignatureLastUpdated
    if ($lastUpdatedTime) {
        $lastUpdateAge = $now - $lastUpdatedTime
        $lastUpdateColor = "Green"
        # Red if older than 1 month (approx 30 days)
        if ($lastUpdateAge.Days -ge 30) { $lastUpdateColor = "Red" }
        # Yellow if older than 1 week (approx 7 days)
        elseif ($lastUpdateAge.Days -ge 7) { $lastUpdateColor = "Yellow" }
        
        Write-Host "  Last updated:         " -NoNewline -ForegroundColor Gray
        Write-Host "$($lastUpdatedTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor $lastUpdateColor
    } else {
        Write-Host "  Last updated:         " -NoNewline -ForegroundColor Gray
        Write-Host "N/A" -ForegroundColor Red
    }
}

function Get-SecurityScore {
    <#
    .SYNOPSIS
        Calculates security score based on all checks
    #>
    param()
    
    $totalChecks = $script:SecurityChecks.Count
    if ($totalChecks -eq 0) { return 0 }
    
    $weightedScore = 0
    $maxWeight = 0
    
    foreach ($check in $script:SecurityChecks) {
        $weight = switch ($check.Severity) {
            "Critical" { 3 }
            "Warning" { 2 }
            "Info" { 1 }
            default { 1 }
        }
        
        $maxWeight += $weight
        if ($check.IsEnabled) {
            $weightedScore += $weight
        }
    }
    
    if ($maxWeight -eq 0) { return 0 }
    
    return [math]::Round(($weightedScore / $maxWeight) * 100)
}

function Write-PhishingMenu {
    <#
    .SYNOPSIS
        Helper function to draw the interactive menu
    #>
    param(
        [int]$selectedOption,
        [int]$menuTop
    )
    
    # Reset cursor to the top of the menu area
    [Console]::SetCursorPosition(0, $menuTop)
    
    # Define prefixes
    $prefix1 = "  [ ]"
    $prefix2 = "  [ ]"
    
    if ($selectedOption -eq 0) { 
        $prefix1 = "  [*]" 
    } else { 
        $prefix2 = "  [*]" 
    }
    
    # Draw options, clearing the rest of the line
    $clearLine = " " * ([Console]::WindowWidth - 50) # 50 is approx length of text
    
    Write-Host "$prefix1 Open Phishing protection" -NoNewline -ForegroundColor White
    Write-Host $clearLine
    
    [Console]::SetCursorPosition(0, $menuTop + 1)
    Write-Host "$prefix2 Continue without opening" -NoNewline -ForegroundColor White
    Write-Host $clearLine
}

function Show-SecuritySummary {
    <#
    .SYNOPSIS
        Displays security score and summary
    #>
    param()
    
    $score = Get-SecurityScore
    $enabled = ($script:SecurityChecks | Where-Object { $_.IsEnabled }).Count
    $disabled = ($script:SecurityChecks | Where-Object { !$_.IsEnabled }).Count
    $critical = ($script:SecurityChecks | Where-Object { !$_.IsEnabled -and $_.Severity -eq "Critical" }).Count
    
    $scoreColor = if ($score -ge 80) { "Green" } elseif ($score -ge 60) { "Yellow" } else { "Red" }
    $scoreRating = if ($score -ge 90) { "EXCELLENT" } elseif ($score -ge 80) { "GOOD" } elseif ($score -ge 60) { "FAIR" } else { "POOR" }
    
    Write-Host "`n" -NoNewline
    Write-Host ("═" * 60) -ForegroundColor Blue
    Write-Host "  SECURITY SCORE: " -NoNewline -ForegroundColor Gray
    Write-Host "$score/100" -NoNewline -ForegroundColor $scoreColor
    Write-Host "  [$scoreRating]" -ForegroundColor $scoreColor
    Write-Host "  ✓ $enabled Enabled" -NoNewline -ForegroundColor Green
    Write-Host "  ✗ $disabled Disabled" -NoNewline -ForegroundColor $(if ($disabled -gt 0) { "Yellow" } else { "Green" })
    if ($critical -gt 0) {
        Write-Host "  ⚠ $critical Critical" -ForegroundColor Red
    } else {
        Write-Host ""
    }
    Write-Host ("═" * 60) -ForegroundColor Blue
    
    # Updated Warning Text
    Write-Host "  *NOTE: Phishing protection for Edge must be manually set!" -ForegroundColor Yellow

    # --- Interactive Menu ---
    $selectedOption = 0 # 0 = Open, 1 = Skip
    $menuTop = [Console]::CursorTop # Store where the menu starts
    $choiceMade = $false

    # Hide cursor
    $oldCursorVisible = [Console]::CursorVisible
    [Console]::CursorVisible = $false
    
    while (!$choiceMade) {
        # Draw the menu
        Write-PhishingMenu -selectedOption $selectedOption -menuTop $menuTop
        
        # Get key press
        $key = [System.Console]::ReadKey($true)
        
        switch ($key.Key) {
            'UpArrow'   { $selectedOption = 0 }
            'DownArrow' { $selectedOption = 1 }
            # Enter confirms the currently selected option
            'Enter' {
                $choiceMade = $true
            }
            # Spacebar is now effectively the same as Enter on the second option
            'Spacebar' {
                if ($selectedOption -eq 1) {
                    $choiceMade = $true
                }
            }
        }
    }
    
    # Restore cursor
    [Console]::CursorVisible = $oldCursorVisible

    # Clear the menu area (2 lines)
    [Console]::SetCursorPosition(0, $menuTop)
    Write-Host (" " * [Console]::WindowWidth)
    [Console]::SetCursorPosition(0, $menuTop + 1)
    Write-Host (" " * [Console]::WindowSize.Width)
    [Console]::SetCursorPosition(0, $menuTop) # Reset cursor

    # --- End Interactive Menu ---

    # Perform action based on selection
    if ($selectedOption -eq 0) {
        if (Open-PhishingSettings) {
            $text = "[o] Open Windows Security > App & browser control > Reputation-based protection > Phishing protection (affects Edge browser)"
            $paddingWidth = [System.Math]::Max(0, $Host.UI.RawUI.WindowSize.Width - $text.Length)
            $paddedText = (" " * $paddingWidth) + $text
            Write-Host $paddedText -ForegroundColor Green
        } else {
            Write-Host "  ✗ Failed to open settings." -ForegroundColor Red
        }
    } else {
        # This branch is now reached by selecting option 1 and pressing Enter, or pressing Space on option 1
        Write-Host "  - Skipping Windows phishing protection setup." -ForegroundColor Gray
    }
    
    # Show critical issues if any
    if ($critical -gt 0) {
        Write-Host "`n⚠️  CRITICAL ISSUES:" -ForegroundColor Red
        $criticalChecks = $script:SecurityChecks | Where-Object { !$_.IsEnabled -and $_.Severity -eq "Critical" }
        foreach ($check in $criticalChecks) {
            Write-Host "   • $($check.Category): " -NoNewline -ForegroundColor Red
            Write-Host "$($check.Name)" -ForegroundColor White
        }
    }
    
    # Special warning if Real-time Protection is disabled
    if (!$script:RealTimeProtectionEnabled) {
        Write-Host "`n🚨 REAL-TIME PROTECTION IS DISABLED" -ForegroundColor Red
        Write-Host ("─" * 60) -ForegroundColor DarkGray
        Write-Host "The following features are " -NoNewline -ForegroundColor Yellow
        Write-Host "INACTIVE" -NoNewline -ForegroundColor Red
        Write-Host " or " -NoNewline -ForegroundColor Yellow
        Write-Host "LIMITED" -NoNewline -ForegroundColor Red
        Write-Host " without Real-time Protection:" -ForegroundColor Yellow
        Write-Host "   • Controlled Folder Access (ransomware protection)" -ForegroundColor DarkGray
        # Note: Behavior Monitoring logic was removed from Get-DefenderStatus but is still referenced here for completeness
        Write-Host "   • Behavior Monitoring" -ForegroundColor DarkGray 
        Write-Host "   • Dev Drive Protection" -ForegroundColor DarkGray
        Write-Host "   • Exploit Protection (Network protection)" -ForegroundColor DarkGray
        Write-Host "   • Cloud-delivered Protection (limited effectiveness)" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "➜ Enable Real-time Protection first to activate these features" -ForegroundColor Cyan
    }
}

function Open-PhishingSettings {
    <#
    .SYNOPSIS
        Opens the Windows Security 'App & browser control' page
        and attempts to send keystrokes to focus 'Reputation-based protection'.
    #>
    param()
    
    try {
        # This URI opens the "App & browser control" page directly.
        Start-Process -FilePath "windowsdefender://appbrowser"
        
        # Wait 2 seconds for the app to open and load
        Start-Sleep -Seconds 2

        # Attempt to send a 'TAB' key to move focus
        $wshell = New-Object -ComObject WScript.Shell
        
        # Try to activate the window first to ensure it receives the keystroke
        $activated = $wshell.AppActivate("Windows Security")
        
        if ($activated) {
            Start-Sleep -Milliseconds 500 # Brief pause after activation
            # Send 'TAB' twice to move focus
            $wshell.SendKeys("{TAB 2}")
        }
        # Even if activation fails, the Start-Process likely succeeded.
        return $true
    }
    catch {
        # This block will run if the Start-Process command fails
        Write-Host "`n[ERROR] Failed to open Windows Security. The URI scheme might not be supported on this system." -ForegroundColor Red
        Write-Host "Error details: $_" -ForegroundColor Red
        return $false
    }
}

function Show-RemediationSteps {
    <#
    .SYNOPSIS
        Displays remediation commands for disabled features
    #>
    param()
    
    $disabledChecks = $script:SecurityChecks | Where-Object { !$_.IsEnabled -and $_.Remediation -ne "" }
    
    if ($disabledChecks.Count -eq 0) {
        Write-Host "`n✓ All security features are enabled!" -ForegroundColor Green
        return
    }
    
    Write-Host "`n🔧 REMEDIATION STEPS" -ForegroundColor Cyan
    Write-Host ("─" * 60) -ForegroundColor DarkGray
    Write-Host "Run the following commands to enable disabled features:`n" -ForegroundColor Gray
    
    $criticalChecks = $disabledChecks | Where-Object { $_.Severity -eq "Critical" }
    if ($criticalChecks.Count -gt 0) {
        Write-Host "CRITICAL:" -ForegroundColor Red
        foreach ($check in $criticalChecks) {
            Write-Host "  # $($check.Name)" -ForegroundColor Gray
            Write-Host "  $($check.Remediation)" -ForegroundColor Yellow
            Write-Host ""
        }
    }
    
    $warningChecks = $disabledChecks | Where-Object { $_.Severity -eq "Warning" }
    if ($warningChecks.Count -gt 0) {
        Write-Host "RECOMMENDED:" -ForegroundColor Yellow
        foreach ($check in $warningChecks) {
            Write-Host "  # $($check.Name)" -ForegroundColor Gray
            Write-Host "  $($check.Remediation)" -ForegroundColor White
            Write-Host ""
        }
    }
}

function Export-ToHtml {
    <#
    .SYNOPSIS
        Exports security report to HTML file
    #>
    param(
        [string]$Path
    )
    
    $score = Get-SecurityScore
    $scoreColor = if ($score -ge 80) { "#28a745" } elseif ($score -ge 60) { "#ffc107" } else { "#dc3545" }
    $scoreRating = if ($score -ge 90) { "EXCELLENT" } elseif ($score -ge 80) { "GOOD" } elseif ($score -ge 60) { "FAIR" } else { "POOR" }
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows Security Status Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: #f5f5f5; 
            padding: 20px;
            color: #333;
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            background: white; 
            border-radius: 8px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            padding: 40px;
            text-align: center;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header .timestamp { opacity: 0.9; font-size: 0.9em; }
        .score-card {
            background: $scoreColor;
            color: white;
            padding: 30px;
            text-align: center;
            font-size: 1.2em;
        }
        .score-number { font-size: 3em; font-weight: bold; }
        .score-rating { font-size: 1.5em; margin-top: 10px; }
        .summary {
            display: flex;
            justify-content: space-around;
            padding: 30px;
            background: #f8f9fa;
        }
        .summary-item {
            text-align: center;
        }
        .summary-number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .summary-label {
            color: #666;
            font-size: 0.9em;
        }
        .category {
            padding: 30px;
            border-bottom: 1px solid #e0e0e0;
        }
        .category:last-child { border-bottom: none; }
        .category-title {
            font-size: 1.5em;
            margin-bottom: 20px;
            color: #667eea;
            display: flex;
            align-items: center;
        }
        .category-icon { margin-right: 10px; font-size: 1.2em; }
        .check-item {
            display: flex;
            align-items: center;
            padding: 12px;
            margin: 8px 0;
            background: #f8f9fa;
            border-radius: 6px;
            transition: all 0.2s;
        }
        .check-item:hover { background: #e9ecef; }
        .status-icon {
            width: 30px;
            height: 30px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 15px;
            font-weight: bold;
            font-size: 1.1em;
        }
        .status-enabled { background: #28a745; color: white; }
        .status-disabled-critical { background: #dc3545; color: white; }
        .status-disabled-warning { background: #ffc107; color: #333; }
        .status-disabled-info { background: #6c757d; color: white; }
        .check-name { flex: 1; font-weight: 500; }
        .severity-badge {
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
            margin-left: 10px;
        }
        .severity-critical { background: #dc3545; color: white; }
        .severity-warning { background: #ffc107; color: #333; }
        .severity-info { background: #17a2b8; color: white; }
        .remediation {
            padding: 30px;
            background: #fff3cd;
        }
        .remediation-title {
            font-size: 1.5em;
            margin-bottom: 20px;
            color: #856404;
        }
        .remediation-item {
            background: white;
            padding: 15px;
            margin: 10px 0;
            border-radius: 6px;
            border-left: 4px solid #ffc107;
        }
        .remediation-name {
            font-weight: bold;
            margin-bottom: 8px;
            color: #333;
        }
        .remediation-command {
            font-family: 'Courier New', monospace;
            background: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            font-size: 0.9em;
            overflow-x: auto;
        }
        .footer {
            padding: 20px;
            text-align: center;
            background: #f8f9fa;
            color: #666;
            font-size: 0.9em;
        }
        @media print {
            body { background: white; padding: 0; }
            .container { box-shadow: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Windows Security Status Report</h1>
            <div class="timestamp">Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div>
            <div class="timestamp">Computer: $env:COMPUTERNAME</div>
        </div>
        
        <div class="score-card">
            <div>Security Score</div>
            <div class="score-number">$score/100</div>
            <div class="score-rating">$scoreRating</div>
        </div>
        
        <div class="summary">
            <div class="summary-item">
                <div class="summary-number" style="color: #28a745;">$(($script:SecurityChecks | Where-Object { $_.IsEnabled }).Count)</div>
                <div class="summary-label">Enabled</div>
            </div>
            <div class="summary-item">
                <div class="summary-number" style="color: #ffc107;">$(($script:SecurityChecks | Where-Object { !$_.IsEnabled }).Count)</div>
                <div class="summary-label">Disabled</div>
            </div>
            <div class="summary-item">
                <div class="summary-number" style="color: #dc3545;">$(($script:SecurityChecks | Where-Object { !$_.IsEnabled -and $_.Severity -eq "Critical" }).Count)</div>
                <div class="summary-label">Critical Issues</div>
            </div>
        </div>
"@

    # Group checks by category
    $categories = $script:SecurityChecks | Group-Object -Property Category
    
    foreach ($category in $categories) {
        $html += @"
        
        <div class="category">
            <div class="category-title">
                <span class="category-icon">🔒</span>
                $($category.Name)
            </div>
"@
        
        foreach ($check in $category.Group) {
            $statusClass = if ($check.IsEnabled) { "status-enabled" } else { "status-disabled-$($check.Severity.ToLower())" }
            $statusIcon = if ($check.IsEnabled) { "✓" } else { "✗" }
            $severityClass = "severity-$($check.Severity.ToLower())"
            
            $html += @"
            
            <div class="check-item">
                <div class="status-icon $statusClass">$statusIcon</div>
                <div class="check-name">$($check.Name)</div>
                <span class="severity-badge $severityClass">$($check.Severity)</span>
            </div>
"@
        }
        
        $html += @"
        
        </div>
"@
    }
    
    # Add remediation section if there are disabled features
    $disabledChecks = $script:SecurityChecks | Where-Object { !$_.IsEnabled -and $_.Remediation -ne "" }
    if ($disabledChecks.Count -gt 0) {
        $html += @"
        
        <div class="remediation">
            <div class="remediation-title">🔧 Remediation Steps</div>
"@
        
        foreach ($check in $disabledChecks) {
            $html += @"
            
            <div class="remediation-item">
                <div class="remediation-name">$($check.Name)</div>
                <div class="remediation-command">$($check.Remediation)</div>
            </div>
"@
        }
        
        $html += @"
        
        </div>
"@
    }
    
    $html += @"
        
        <div class="footer">
            Windows Security Configuration Script v2.0<br>
            Report generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        </div>
    </div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $Path -Encoding UTF8
    Write-Host "`n✓ HTML report exported to: " -NoNewline -ForegroundColor Green
    Write-Host $Path -ForegroundColor White
}

function Export-ToJson {
    <#
    .SYNOPSIS
        Exports security report to JSON file
    #>
    param(
        [string]$Path
    )
    
    $report = @{
        Timestamp = Get-Date -Format 'o'
        Computer = $env:COMPUTERNAME
        Score = (Get-SecurityScore)
        Summary = @{
            TotalChecks = $script:SecurityChecks.Count
            Enabled = ($script:SecurityChecks | Where-Object { $_.IsEnabled }).Count
            Disabled = ($script:SecurityChecks | Where-Object { !$_.IsEnabled }).Count
            Critical = ($script:SecurityChecks | Where-Object { !$_.IsEnabled -and $_.Severity -eq "Critical" }).Count
            Warning = ($script:SecurityChecks | Where-Object { !$_.IsEnabled -and $_.Severity -eq "Warning" }).Count
        }
        Checks = $script:SecurityChecks
    }
    
    $report | ConvertTo-Json -Depth 5 | Out-File -FilePath $Path -Encoding UTF8
    Write-Host "`n✓ JSON report exported to: " -NoNewline -ForegroundColor Green
    Write-Host $Path -ForegroundColor White
}

function Compare-ToBaseline {
    <#
    .SYNOPSIS
        Compares current state to a baseline
    #>
    param(
        [string]$BaselinePath
    )
    
    if (!(Test-Path $BaselinePath)) {
        Write-Host "`n⚠️  Baseline file not found: $BaselinePath" -ForegroundColor Yellow
        return
    }
    
    try {
        $baseline = Get-Content $BaselinePath | ConvertFrom-Json
        Write-Host "`n📊 BASELINE COMPARISON" -ForegroundColor Cyan
        Write-Host ("─" * 60) -ForegroundColor DarkGray
        Write-Host "Baseline from: " -NoNewline -ForegroundColor Gray
        Write-Host $baseline.Timestamp -ForegroundColor White
        
        $changes = @()
        foreach ($currentCheck in $script:SecurityChecks) {
            $baselineCheck = $baseline.Checks | Where-Object { $_.Name -eq $currentCheck.Name }
            if ($baselineCheck -and $baselineCheck.IsEnabled -ne $currentCheck.IsEnabled) {
                $changes += @{
                    Name = $currentCheck.Name
                    Was = $baselineCheck.IsEnabled
                    Now = $currentCheck.IsEnabled
                }
            }
        }
        
        if ($changes.Count -eq 0) {
            Write-Host "`n✓ No changes detected from baseline" -ForegroundColor Green
        } else {
            Write-Host "`n⚠️  $($changes.Count) changes detected:" -ForegroundColor Yellow
            foreach ($change in $changes) {
                $arrow = if ($change.Now) { "↑" } else { "↓" }
                $color = if ($change.Now) { "Green" } else { "Red" }
                Write-Host "  $arrow " -NoNewline -ForegroundColor $color
                Write-Host "$($change.Name): " -NoNewline -ForegroundColor White
                Write-Host "$($change.Was) → $($change.Now)" -ForegroundColor $color
            }
        }
        
        $scoreDiff = (Get-SecurityScore) - $baseline.Score
        Write-Host "`nScore change: " -NoNewline -ForegroundColor Gray
        if ($scoreDiff -gt 0) {
            Write-Host "+$scoreDiff (Improved)" -ForegroundColor Green
        } elseif ($scoreDiff -lt 0) {
            Write-Host "$scoreDiff (Declined)" -ForegroundColor Red
        } else {
            Write-Host "No change" -ForegroundColor Gray
        }
        
    } catch {
        Write-Host "`n⚠️  Error reading baseline: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Main execution
try {
    # Removed: $script:StartTime initialization
    Clear-Host
    
    Write-Host "`n" -NoNewline
    Write-Host ("═" * 60) -ForegroundColor Blue
    Write-Host "  WINDOWS SECURITY STATUS REPORT" -ForegroundColor White
    Write-Host ("═" * 60) -ForegroundColor Blue

    # Run all security checks
    Get-DefenderStatus
    Get-AccountProtection
    Get-FirewallStatus
    Get-ReputationProtection
    Get-CoreIsolationStatus
    Get-ScanInformation
    
    # Show summary
    Show-SecuritySummary
    
    # Show remediation if requested
    if ($ShowRemediation) {
        Show-RemediationSteps
    }
    
    # Export reports
    if ($ExportHtml) {
        $htmlPath = Join-Path $OutputPath "SecurityReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        Export-ToHtml -Path $htmlPath
    }
    
    if ($ExportJson) {
        $jsonPath = Join-Path $OutputPath "SecurityReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        Export-ToJson -Path $jsonPath
    }
    
    # Save as baseline if requested
    if ($SaveAsBaseline) {
        $jsonPath = $SaveAsBaseline
        Export-ToJson -Path $jsonPath
        Write-Host "✓ Baseline saved successfully" -ForegroundColor Green
    }
    
    # Compare to baseline if requested
    if ($CompareToBaseline) {
        Compare-ToBaseline -BaselinePath $CompareToBaseline
    }
    
    # Footer
    # Removed: Elapsed time calculation
    Write-Host "`n" -NoNewline
    Write-Host ("─" * 60) -ForegroundColor DarkGray
    
    # Removed: Display scan time
    
    # Set the timestamp this script was last edited
    $lastEditedTimestamp = "2025-11-03 17:56:00" 
    Write-Host "  Last Edited: $lastEditedTimestamp" -ForegroundColor Green
    Write-Host "  www.AIIT.support All rights reserved" -ForegroundColor Green
    Write-Host ("─" * 60) -ForegroundColor DarkGray
    Write-Host ""
    
} catch {
    Write-Host "`n[ERROR] " -NoNewline -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor White
    Write-Host "`nMake sure you're running this script as Administrator.`n" -ForegroundColor Yellow
    Write-Host "Additional error details:" -ForegroundColor Yellow
    Write-Host $_.ScriptStackTrace -ForegroundColor Gray
    exit 1
}
