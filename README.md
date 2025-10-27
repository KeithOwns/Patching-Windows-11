WINDOWS SECURITY STATUS REPORT --- README

What this is A PowerShell script that reads and prints Windows Security
settings in a compact, human-friendly format. Designed to show Defender,
account protection, firewall, SmartScreen, core isolation, and recent
scan info.

Requirements - Windows 10 or 11. - Run as Administrator. - PowerShell
with built-in Defender cmdlets (Get-MpPreference, Get-MpComputerStatus,
Get-NetFirewallProfile, Get-NetConnectionProfile). PowerShell 5.1 or
later recommended. - Script relies on registry reads for some settings.

Files - Sonnet-StatusReport.ps1 --- the script (insert your filename).

Quick usage Open an elevated PowerShell prompt and run:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.`\Sonnet`{=tex}-StatusReport.ps1

Or run directly from an elevated session: powershell -NoProfile
-ExecutionPolicy Bypass -File .`\Sonnet`{=tex}-StatusReport.ps1

What the script checks - Virus & threat protection (real-time, cloud,
sample submission, tamper protection, controlled folder access). -
Account protection (Windows Hello, Dynamic Lock, facial recognition). -
Firewall & network protection (Domain/Private/Public profiles, active
networks). - App & browser control (SmartScreen states, phishing
protection, PUA blocking, Edge PUA downloads). - Device security (Core
isolation memory integrity, kernel stack protection, LSA protection,
vulnerable driver blocklist). - Scan information (last quick/full scan
times, signature version, last update).

Output conventions - A cyan section header and divider for each area. -
Status icons: ✓ = enabled/healthy. ✗ = disabled/not configured. ? =
unable to determine (permission/reg key missing). - Plain text lines
show the feature name beside the icon.

Notes and caveats - Some values are per-user. Run from the user session
that owns those settings when needed. - Edge SmartScreen PUA download
detection checks multiple registry locations and policies. False
negatives possible if Edge uses unusual configuration paths. - Tamper
protection detection uses registry keys that may vary by Windows build.
If detection fails the script reports "Unable to determine". - The
script prints values. It does not change system state. Use group policy
or official APIs to change settings.

Troubleshooting - If Get-MpPreference or Get-MpComputerStatus is
missing, ensure Windows Defender features are present and you are on a
compatible Windows build. - If the script outputs many ? entries,
confirm you ran PowerShell elevated. - If Get-NetFirewallProfile fails,
run in an environment with the NetSecurity module available (Windows
firewall feature).

Customization hints - Modify Write-StatusIcon to change symbols or
colors. - Add -Verbose or -Debug switches to functions for expanded
logging. - Export results to JSON by collecting fields into objects and
calling ConvertTo-Json.

Example output (abridged) 🛡️ Virus & threat protection ✓ Real-time
protection ✗ Dev Drive protection ✓ Cloud-delivered protection

👤 Account protection ✓ Windows Hello ✗ Dynamic lock

Safety and permissions Run only on systems you own or administer. The
script requires elevated privileges for accurate results.

License Use freely. No warranty. Modify at will.
