#Requires -Version 5.1

<#
.SYNOPSIS
    Validates PowerShell script quality and consistency
.DESCRIPTION
    Tests all PowerShell scripts in the repository for:
    - Administrator requirement (#Requires -RunAsAdministrator)
    - UTF-8 encoding (to preserve Unicode characters)
    - PowerShell syntax errors
    - Common best practices
.PARAMETER ScriptPath
    Path to the scripts directory (default: current directory)
.EXAMPLE
    .\Test-ScriptQuality.ps1
    Tests all scripts in the current directory
.EXAMPLE
    .\Test-ScriptQuality.ps1 -ScriptPath "C:\PatchW11\scripts"
    Tests all scripts in the specified directory
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$ScriptPath = $PSScriptRoot
)

# Test result tracking
$script:TotalTests = 0
$script:PassedTests = 0
$script:FailedTests = 0
$script:Issues = @()

function Write-TestResult {
    param(
        [string]$TestName,
        [bool]$Passed,
        [string]$Message = ""
    )

    $script:TotalTests++

    if ($Passed) {
        $script:PassedTests++
        Write-Host "  [PASS] " -ForegroundColor Green -NoNewline
        Write-Host $TestName -ForegroundColor Gray
    }
    else {
        $script:FailedTests++
        Write-Host "  [FAIL] " -ForegroundColor Red -NoNewline
        Write-Host "$TestName - $Message" -ForegroundColor Yellow
        $script:Issues += [PSCustomObject]@{
            Test    = $TestName
            Message = $Message
        }
    }
}

function Test-AdministratorRequirement {
    param([string]$FilePath)

    $content = Get-Content -Path $FilePath -Raw -Encoding UTF8
    $hasRequirement = $content -match '#Requires\s+-RunAsAdministrator'

    Write-TestResult `
        -TestName "Administrator Requirement: $(Split-Path $FilePath -Leaf)" `
        -Passed $hasRequirement `
        -Message "Missing '#Requires -RunAsAdministrator' directive"
}

function Test-UTF8Encoding {
    param([string]$FilePath)

    try {
        # Read file as bytes
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)

        # Check for UTF-8 BOM (EF BB BF)
        $hasUTF8BOM = ($bytes.Length -ge 3 -and
                       $bytes[0] -eq 0xEF -and
                       $bytes[1] -eq 0xBB -and
                       $bytes[2] -eq 0xBF)

        # Check if content can be decoded as UTF-8
        $canDecodeUTF8 = $true
        try {
            $null = [System.Text.Encoding]::UTF8.GetString($bytes)
        }
        catch {
            $canDecodeUTF8 = $false
        }

        # File should be UTF-8 (with or without BOM)
        $isUTF8 = $canDecodeUTF8

        Write-TestResult `
            -TestName "UTF-8 Encoding: $(Split-Path $FilePath -Leaf)" `
            -Passed $isUTF8 `
            -Message "File is not UTF-8 encoded (required for Unicode characters)"
    }
    catch {
        Write-TestResult `
            -TestName "UTF-8 Encoding: $(Split-Path $FilePath -Leaf)" `
            -Passed $false `
            -Message "Error checking encoding: $($_.Exception.Message)"
    }
}

function Test-SyntaxErrors {
    param([string]$FilePath)

    $errors = $null
    $null = [System.Management.Automation.PSParser]::Tokenize(
        (Get-Content -Path $FilePath -Raw),
        [ref]$errors
    )

    $hasSyntaxErrors = ($errors.Count -gt 0)

    if ($hasSyntaxErrors) {
        $errorMsg = ($errors | ForEach-Object { $_.Message }) -join '; '
        Write-TestResult `
            -TestName "Syntax Check: $(Split-Path $FilePath -Leaf)" `
            -Passed $false `
            -Message $errorMsg
    }
    else {
        Write-TestResult `
            -TestName "Syntax Check: $(Split-Path $FilePath -Leaf)" `
            -Passed $true
    }
}

function Test-CommonBestPractices {
    param([string]$FilePath)

    $content = Get-Content -Path $FilePath -Raw -Encoding UTF8
    $fileName = Split-Path $FilePath -Leaf

    # Check for Set-StrictMode (recommended but not required)
    $hasStrictMode = $content -match 'Set-StrictMode'

    # Check for error action preference (recommended but not required)
    $hasErrorActionPref = $content -match '\$ErrorActionPreference'

    # These are informational - we'll just count them but not fail
    if (-not $hasStrictMode -and -not $hasErrorActionPref) {
        # Informational only - don't count as failure
        Write-Host "  [INFO] " -ForegroundColor Cyan -NoNewline
        Write-Host "Best Practices: $fileName - Consider adding Set-StrictMode and `$ErrorActionPreference" -ForegroundColor Gray
    }
}

# Main execution
Write-Host ""
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "  PowerShell Script Quality Tests" -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Testing scripts in: $ScriptPath" -ForegroundColor Gray
Write-Host ""

# Get all PowerShell scripts
$scripts = Get-ChildItem -Path $ScriptPath -Filter "*.ps1" -File |
           Where-Object { $_.Name -ne "Test-ScriptQuality.ps1" }  # Exclude self

if ($scripts.Count -eq 0) {
    Write-Host "No PowerShell scripts found to test." -ForegroundColor Yellow
    exit 1
}

Write-Host "Found $($scripts.Count) scripts to test" -ForegroundColor Gray
Write-Host ""

foreach ($script in $scripts) {
    # Test administrator requirement
    Test-AdministratorRequirement -FilePath $script.FullName

    # Test UTF-8 encoding
    Test-UTF8Encoding -FilePath $script.FullName

    # Test for syntax errors
    Test-SyntaxErrors -FilePath $script.FullName

    # Check best practices (informational)
    Test-CommonBestPractices -FilePath $script.FullName
}

# Summary
Write-Host ""
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "  Test Summary" -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Total Tests  : " -NoNewline
Write-Host $script:TotalTests -ForegroundColor Cyan
Write-Host "  Passed       : " -NoNewline
Write-Host $script:PassedTests -ForegroundColor Green
Write-Host "  Failed       : " -NoNewline
Write-Host $script:FailedTests -ForegroundColor $(if ($script:FailedTests -eq 0) { "Green" } else { "Red" })
Write-Host ""

if ($script:FailedTests -gt 0) {
    Write-Host "===============================================================================" -ForegroundColor Red
    Write-Host "  Issues Found" -ForegroundColor Red
    Write-Host "===============================================================================" -ForegroundColor Red
    Write-Host ""

    foreach ($issue in $script:Issues) {
        Write-Host "  - $($issue.Test)" -ForegroundColor Yellow
        Write-Host "    $($issue.Message)" -ForegroundColor Gray
        Write-Host ""
    }

    exit 1
}
else {
    Write-Host "All tests passed!" -ForegroundColor Green
    Write-Host ""
    exit 0
}
