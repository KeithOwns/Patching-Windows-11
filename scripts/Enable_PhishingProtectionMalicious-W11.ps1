#Requires -RunAsAdministrator

# Enable "Warn me about malicious apps and sites" in Phishing Protection
# Windows Security > Reputation-based protection

# Registry path for Phishing Protection
$regPath = "HKCU:\Software\Microsoft\Windows Security Health\State"

# Registry path for SmartScreen settings under Explorer
$smartscreenPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost"

# Ensure registry keys exist
If (!(Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
If (!(Test-Path $smartscreenPath)) {
    New-Item -Path $smartscreenPath -Force | Out-Null
}

# Enable Phishing Protection (Warn me about malicious apps and sites)
# SmartScreenEnabled = 1  -> Enabled (Warn)
Set-ItemProperty -Path $smartscreenPath -Name "EnableWebContentEvaluation" -Value 1 -Type DWord
Set-ItemProperty -Path $smartscreenPath -Name "PreventOverride" -Value 0 -Type DWord
Set-ItemProperty -Path $smartscreenPath -Name "SmartScreenEnabled" -Value "Warn" -Type String

# Additional phishing protection enforcement
$phishKey = "HKCU:\Software\Microsoft\Windows Security Health\PhishingProtection"
If (!(Test-Path $phishKey)) {
    New-Item -Path $phishKey -Force | Out-Null
}
# Warn me about malicious apps and sites = Enabled (1)
Set-ItemProperty -Path $phishKey -Name "WarnMaliciousAppsAndSites" -Value 1 -Type DWord

Write-Host "[+] 'Warn me about malicious apps and sites' has been set to Enabled (Warn)."
