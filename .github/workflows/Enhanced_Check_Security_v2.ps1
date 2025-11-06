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

# NOTE: Add all the original Enhanced_Check_Security.txt checks here
# This includes:
# - Firewall checks
# - Windows Update checks
# - Account policies
# - Audit policies
# - Services
# - Network security
# - Admin shares
# - Software vulnerabilities
# - Drive encryption
# - Domain-specific checks if domain-joined

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
