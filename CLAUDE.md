# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

PatchW11 is a Windows 11 security hardening and maintenance automation toolkit for enterprise environments. It provides comprehensive security configuration, monitoring, remediation, and system maintenance through modular PowerShell scripts.

## Directory Structure

```
PatchW11/
├── scripts/          # All PowerShell scripts and batch files
├── docs/            # Documentation (ENHANCEMENT_GUIDE.md)
├── CLAUDE.md        # AI development guidance (this file)
├── README.md        # User documentation
└── .gitignore
```

## Common Commands

### Development & Testing

```powershell
# Test individual scripts (must run as Administrator)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
cd scripts

# Run security check (read-only)
.\Check_SecurityOnly-W11.ps1

# Run security check with remediation options
.\Check_SecurityComprehensive-W11.ps1 -ShowRemediation

# Export security report
.\Check_SecurityComprehensive-W11.ps1 -ExportHtml -OutputPath "C:\Reports"
```

### Full System Hardening Workflow

```powershell
# Recommended execution order:
.\Create_RestorePoint-W11.ps1                     # 1. Safety first
.\Configure_Updates-W11.ps1                       # 2. Configure updates
.\Check_SecurityComprehensive-W11.ps1             # 3. Security audit + remediation
.\Run_Maintenance-W11.ps1                         # 4. Final optimization
```

## Architecture & Code Organization

### Script Categories

**Orchestration Scripts:**
- `Configure_Updates-W11.ps1` - Windows/Store update configuration & automation
- `Check_SecurityComprehensive-W11.ps1` - Security assessment with scoring and interactive remediation
- `Run_Maintenance-W11.ps1` - System optimization, cleanup, and diagnostics

**Check Scripts (Check_*.ps1):**
- Read-only status verification for specific features
- Examples: `Check_DevDrive-W11.ps1`, `Check_SmartAppControl-W11.ps1`, `Check_SecurityOnly-W11.ps1`

**Enable Scripts (Enable_*.ps1) / Disable Scripts (Disable_*.ps1):**
- Apply or remove specific security settings
- Examples: `Enable_RealTimeProtection-W11.ps1`, `Enable_LSA-W11.ps1`, `Disable_PUA-W11.ps1`

**Support Scripts:**
- `Create_RestorePoint-W11.ps1` - System restore point creator
- `Check_SecurityOnly-W11.ps1` - Read-only security audit
- `Test-ScriptQuality.ps1` - Script quality validation tool
- `MAINTENANCEruns.bat` - Legacy maintenance batch script

### Shared Utility Framework

All scripts follow consistent patterns:

**Visual Feedback Functions:**
```powershell
Write-StatusIcon()      # Visual status indicators (✓/✗) with color-coded severity
Write-SectionHeader()   # Formatted section headers with icons
```

**Registry Operations:**
```powershell
Get-RegistryValue()     # Safe read with null handling
Set-RegistryDword()     # Safe write with path creation
```

**Error Handling Pattern:**
```powershell
#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
```

## Key Architectural Patterns

### 1. Dependency Awareness

Scripts understand feature dependencies and check them before applying changes:

- **Real-time Protection** is required for:
  - Controlled Folder Access
  - Dev Drive Protection
  - Network Protection
- **Tamper Protection** blocks programmatic security changes (user must disable manually)
- **Third-party AV detection** skips Windows Defender checks when non-Microsoft AV is active

### 2. The Apply Settings Module (Check_SecurityComprehensive-W11.ps1)

The main security script has an integrated "Apply Settings" module with individual setters:
- Each setter is a self-contained function targeting one security feature
- Setters check dependencies before applying changes
- Recent additions: Real-time Protection, Tamper Protection, Controlled Folder Access, SmartScreen

**When adding new setters:**
1. Add the function to the Apply Settings section (~line 800+)
2. Include dependency checks (e.g., verify Real-time Protection is enabled)
3. Add error handling for Tamper Protection scenarios
4. Update the Apply Settings menu in `Show-ApplySettingsMenu()`

### 3. UI Automation Pattern

Multiple scripts automate Windows Settings/Store UI interactions:

```powershell
# Load UI Automation assemblies
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

# Find and click buttons programmatically
$button = $element.FindFirst($TreeScope, $condition)
$button.GetCurrentPattern($InvokePattern).Invoke()
```

Used in: `Configure_Updates-W11.ps1`, `Check_MSstoreUpdates-W11.ps1`, `Check_WinUpdates-W11.ps1`

### 4. Naming Convention

All scripts follow the pattern `[Verb]_[SettingName]-W11.ps1`:

- **Verbs**: Check, Enable, Disable, Configure, Run, Create, Open, Restart
- **Examples**: `Check_DevDrive-W11.ps1`, `Enable_RealTimeProtection-W11.ps1`, `Disable_PUA-W11.ps1`
- **Exception**: Test-ScriptQuality.ps1 (uses PowerShell Verb-Noun convention)

### 5. Application Installation Pattern (Removed)

The application installer (`04-Install_Apps-agron.ps1`) has been removed from the repository.

Previous installation methods included:

```powershell
# 1. WINGET (preferred) - with scope fallback and retry
Install-WithWingetRetry -Id "App.ID" -Scope "user" -FallbackScope "machine"

# 2. MSI - Download and silent install
Get-File -Url $url -OutFile $msiPath
msiexec.exe /i "$msiPath" /qn /norestart $silentArgs

# 3. EXE - Download and silent install
Get-File -Url $url -OutFile $exePath
Start-Process -FilePath $exePath -ArgumentList $silentArgs -Wait
```

**Installation workflow:**
1. Validate app configurations
2. Check prerequisites (interactive loop)
3. Disable Controlled Folder Access
4. Install missing apps (sorted by InstallOrder)
5. Verify installation with `Wait-UntilDetected()` (timeout-based retry loop)
6. Re-enable Controlled Folder Access
7. Generate summary logs

### 6. Security Scoring System

Security checks use weighted severity levels:

- **Critical** (3x weight): Firewall, Real-time Protection, Tamper Protection
- **Warning** (2x weight): Most security features, updates, policies
- **Info** (1x weight): Optional features, informational items

Score calculation: `(PassedWeight / TotalWeight) * 100`

Rating: EXCELLENT (90+) | GOOD (80+) | FAIR (60+) | POOR (<60)

## Common Development Tasks

### Adding a New Security Check to Check_SecurityComprehensive-W11.ps1

1. Add check function in appropriate section (Virus Protection, Firewall, etc.)
2. Use the `SecurityCheck` class to store results:
   ```powershell
   $check = [SecurityCheck]@{
       Category = "Virus & Threat Protection"
       Name = "Feature Name"
       IsEnabled = $true/$false
       Severity = "Critical"  # or Warning, Info
       Remediation = "Set-MpPreference -FeatureName 1"
       Details = "Additional context"
   }
   $script:SecurityChecks += $check
   ```

3. Add display logic in `Show-SecurityStatus()`

### Adding a New Enable Script

1. Copy template from existing Enable_*.ps1 script
2. Include Tamper Protection detection:
   ```powershell
   $tamperProtection = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection"
   if ($tamperProtection -eq 5) {
       Write-Warning "Tamper Protection is ON - user must disable manually in Windows Security"
       exit 1
   }
   ```

3. Add status verification after applying changes
4. Use consistent visual feedback (Write-StatusIcon)

### Adding Script Quality Tests

The `Test-ScriptQuality.ps1` script validates:

- `#Requires -RunAsAdministrator` in all scripts
- UTF-8 encoding preservation
- PowerShell syntax errors
- Best practices (informational)

Run with:
```powershell
cd scripts
.\Test-ScriptQuality.ps1
```

## Important Technical Notes

### Registry Paths (Frequently Accessed)

```powershell
# Windows Defender
HKLM:\SOFTWARE\Microsoft\Windows Defender\Features
HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender

# Windows Update
HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings

# SmartScreen
HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer
HKLM:\SOFTWARE\Policies\Microsoft\Windows\System

# Core Isolation
HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity
```

### Windows Defender Cmdlets

```powershell
Get-MpPreference          # Read current settings
Set-MpPreference          # Modify settings (blocked by Tamper Protection)
Get-MpComputerStatus      # Scan info, signature versions
```

### System Diagnostics Cascade (Run_Maintenance-W11.ps1)

Automated repair workflow:

```
IF Test-SystemFiles (SFC) fails:
  → Repair-WindowsImage (DISM /Online /Cleanup-Image /RestoreHealth)
    IF DISM fails:
      → Start-MemoryDiagnostics (scheduled for next boot)
```

### UI Automation Limitations

- Only works for UWP/Modern UI elements (Settings, Store)
- Requires specific AutomationID or ControlType matching
- Fragile - breaks if UI layout changes
- Add `Start-Sleep` delays to allow UI rendering

## Testing Considerations

### Before Committing

1. Test on clean Windows 11 VM (both Pro and Enterprise)
2. Test with Tamper Protection ON and OFF
3. Test with third-party AV installed (Symantec, McAfee)
4. Verify visual output in Windows Terminal and legacy console
5. Check UTF-8 encoding for icon characters (✓ ✗ 🛡️)

### Common Issues

**"Access Denied" errors:**
- Check `#Requires -RunAsAdministrator`
- Verify Tamper Protection status
- Check if third-party AV is blocking

**UI Automation failures:**
- Add longer `Start-Sleep` delays
- Verify AutomationID hasn't changed in Windows updates
- Test on both light/dark themes

**WINGET failures:**
- Ensure version 1.5.0+
- Try scope fallback (user → machine)
- Refresh sources: `winget source update`

## File Encoding

**Critical:** All `.ps1` files must be UTF-8 encoded for proper display of Unicode characters (✓ ✗ 🛡️ 👤 🔒).

```powershell
# Save files with UTF-8 encoding:
$content | Out-File -FilePath $path -Encoding UTF8
```

## Documentation References

- **docs/ENHANCEMENT_GUIDE.md** - Evolution from v1 to v2 security checking, severity guidelines
- **README.md** - User-facing documentation and quick start guide
