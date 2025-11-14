#Requires -RunAsAdministrator

# File: Configure-StoreSmartScreen-User.ps1
# Purpose: Configure SmartScreen for Microsoft Store apps for the current user (HKCU).
# Requires: PowerShell 5.1+

# --- helpers ---
$Result = @()

function Log([string]$m){ $script:Result += $m }
function Ensure-Key([string]$Path){
  if(-not (Test-Path -LiteralPath $Path)){ New-Item -Path $Path -Force | Out-Null }
}
function Get-REG([string]$Path,[string]$Name){
  try{ (Get-ItemProperty -Path $Path -Name $Name -EA SilentlyContinue).$Name }catch{ $null }
}
function Set-DWORD([string]$Path,[string]$Name,[int]$Value){
  Ensure-Key $Path
  $cur = Get-REG $Path $Name
  if($cur -ne $Value){
    if($null -eq $cur){
      New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
    } else {
      Set-ItemProperty -Path $Path -Name $Name -Value $Value | Out-Null
    }
    return $true
  }
  return $false
}

# --- main ---
Write-Host "Run: $(Get-Date -Format 'u')"
Write-Host "User: $env:USERNAME"
Write-Host "------------------------------------------------------------"
Write-Host "Enabling SmartScreen for Store apps (Current User)..."

# --- SmartScreen for Microsoft Store apps (User only) ---
try{
  $user = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost"
  Set-DWORD $user 'EnableWebContentEvaluation' 1 | Out-Null

  $ucur = Get-REG $user 'EnableWebContentEvaluation'
  if($ucur -eq 1){
    Log "Store apps SmartScreen (User): Set to 'On' SUCCESS"
  } else {
    Log "Store apps SmartScreen (User): HKCU=$ucur FAILED"
  }
} catch { Log "Store apps SmartScreen (User): FAILED ($($_.Exception.Message))" }

# --- Summary ---
Write-Host "`n================ SUMMARY =================="
$Result | ForEach-Object { Write-Host "- $_" }
Write-Host "============================================`n"

$fail = $Result | Where-Object { $_ -like '*FAILED*' }
if($fail){
    $global:LASTEXITCODE = 1
} else {
    $global:LASTEXITCODE = 0
}