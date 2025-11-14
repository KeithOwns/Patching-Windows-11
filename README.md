# PatchW11 - Windows 11 Security Hardening Toolkit

A comprehensive PowerShell-based toolkit for automating Windows 11 security configuration, monitoring, and system maintenance in enterprise environments.

## Overview

PatchW11 provides modular scripts to harden Windows 11 security settings, automate updates, deploy applications, and perform system maintenance. Each script is designed to be run independently or as part of a complete system hardening workflow.

## Features

- **Security Assessment & Remediation** - Comprehensive security checks with scoring (0-100) and interactive fixes
- **Automated Updates** - Windows Update and Microsoft Store update automation
- **Application Deployment** - Intelligent installer with WINGET/MSI/EXE support
- **System Maintenance** - Disk optimization, cleanup, and diagnostics
- **Visual Feedback** - Color-coded status indicators and formatted reports
- **Export Capabilities** - HTML and JSON report generation

## Requirements

- **OS**: Windows 10 or Windows 11
- **Privileges**: Administrator rights required
- **PowerShell**: Version 5.1 or later
- **Dependencies**:
  - Windows Defender cmdlets (Get-MpPreference, Set-MpPreference)
  - NetSecurity module (Get-NetFirewallProfile)
  - WINGET (version 1.5.0+) for application installation

## Quick Start

### Recommended Full Workflow

Run these scripts in order for complete system hardening:

```powershell
# Open PowerShell as Administrator
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
cd scripts

# 1. Create restore point (safety first)
.\CreateRestorePoint_Win11.ps1

# 2. Configure Windows/Store updates
.\01-Update_Config-Win11.ps1

# 3. Security audit and remediation
.\02-Security_Config-Win11.ps1

# 4. Install required applications
.\04-Install_Apps-agron.ps1 -DeviceType Auto

# 5. Final optimization and cleanup
.\05-Finalize_Maintenance-Win11.ps1
```

### Individual Tasks

**Security Check (Read-Only):**
```powershell
.\SecurityCheckONLY-W11.ps1
```

**Security Check with Remediation:**
```powershell
.\02-Security_Config-Win11.ps1 -ShowRemediation
```

**Export Security Report:**
```powershell
.\02-Security_Config-Win11.ps1 -ExportHtml -OutputPath "C:\Reports"
```

**Enable Specific Features:**
```powershell
.\Enable_RealTimeProc.ps1
.\Enable_LSA-W11.ps1
.\Enable_MemoryIntegrity.ps1
```

## Main Scripts

### Orchestration Scripts (Numbered Sequence)

| Script | Description |
|--------|-------------|
| `01-Update_Config-Win11.ps1` | Configure and automate Windows/Microsoft Store updates |
| `02-Security_Config-Win11.ps1` | Comprehensive security assessment with interactive remediation |
| `04-Install_Apps-agron.ps1` | Automated application deployment with device-type detection |
| `05-Finalize_Maintenance-Win11.ps1` | System optimization, cleanup, and diagnostics |

### Check Scripts

Verify specific security feature status (read-only):
- `Check_forDevDrive-W11.ps1` - Dev Drive protection status
- `Check_SmartAppControl-W11.ps1` - Smart App Control status
- `Check_WinUpdates-W11.ps1` - Automate Windows Update check
- `CHECK_MSstore-Updates.ps1` - Automate Microsoft Store update check
- `CHECK_MS VDB.ps1` - Microsoft Vulnerable Driver Blocklist status

### Enable Scripts

Apply specific security settings:
- `Enable_RealTimeProc.ps1` - Enable real-time protection
- `Enable_LSA-W11.ps1` - Enable LSA protection (requires reboot)
- `Enable_MemoryIntegrity.ps1` - Enable memory integrity/HVCI
- `Enable_PUA-W11.ps1` - Enable potentially unwanted app blocking
- `Enable_StorageSense-W11.ps1` - Configure storage sense

### Support Scripts

- `CreateRestorePoint_Win11.ps1` - Create system restore point
- `SecurityCheckONLY-W11.ps1` - Security audit without remediation
- `MAINTENANCEruns.bat` - Legacy maintenance batch script

## Security Features Covered

### Virus & Threat Protection
- Real-time protection
- Cloud-delivered protection
- Tamper protection
- Controlled folder access
- Dev Drive protection
- Network protection / Exploit protection
- Potentially unwanted app (PUA) blocking

### Account Protection
- Windows Hello status
- Dynamic lock
- Facial recognition

### Firewall & Network Protection
- All firewall profiles (Domain/Private/Public)
- Active network status

### App & Browser Control
- SmartScreen for apps and files
- SmartScreen for Microsoft Edge
- Phishing protection
- Smart App Control

### Device Security
- Core Isolation (Memory Integrity / HVCI)
- Kernel-mode hardware-enforced stack protection
- Local Security Authority (LSA) protection
- Microsoft Vulnerable Driver Blocklist

### System Maintenance
- Windows Update configuration
- Disk optimization (SSD TRIM / HDD defrag)
- System file integrity (SFC / DISM)
- Storage cleanup
- Power settings optimization

## Security Scoring

The security assessment script (`02-Security_Config-Win11.ps1`) calculates a weighted security score (0-100):

- **Critical** issues (3x weight): Firewall, Real-time Protection, Tamper Protection
- **Warning** issues (2x weight): Most security features, updates, policies
- **Info** items (1x weight): Optional features

**Ratings:**
- 90-100: EXCELLENT
- 80-89: GOOD
- 60-79: FAIR
- <60: POOR

## Important Notes

### Tamper Protection
When Tamper Protection is enabled (recommended), security settings cannot be changed programmatically. Scripts will detect this and prompt you to disable it manually in Windows Security before applying changes.

### Third-Party Antivirus
Scripts automatically detect third-party antivirus software (Symantec, McAfee, Norton, etc.) and skip Windows Defender checks when appropriate.

### File Encoding
All PowerShell scripts use UTF-8 encoding to properly display Unicode characters (✓ ✗ 🛡️). Ensure your editor preserves this encoding when modifying scripts.

### Restore Points
Always create a restore point before making system changes. Use `CreateRestorePoint_Win11.ps1` for automated restore point creation.

## Troubleshooting

**"Access Denied" errors:**
- Verify PowerShell is running as Administrator
- Check if Tamper Protection is enabled
- Confirm third-party AV isn't blocking changes

**UI Automation failures:**
- Ensure Windows is fully loaded and responsive
- Try running scripts again after a few seconds
- Check if Windows Settings/Store UI has changed in recent updates

**WINGET installation failures:**
- Verify WINGET version 1.5.0 or later: `winget --version`
- Refresh sources: `winget source update`
- Check internet connectivity

**Module not found errors:**
- Ensure Windows Defender features are installed
- Verify NetSecurity module is available
- Confirm you're on Windows 10/11 (not Server)

## For Developers

See [CLAUDE.md](CLAUDE.md) for:
- Detailed architecture documentation
- Common development tasks
- Code patterns and conventions
- Testing guidelines

## Safety and Permissions

- Run only on systems you own or administer
- All scripts require elevated privileges
- Create restore points before making changes
- Review scripts before execution to understand their actions

## License

Use freely. No warranty. Modify at will.

## Support

For issues or questions, please review:
- [ENHANCEMENT_GUIDE.md](docs/ENHANCEMENT_GUIDE.md) - Security check evolution and guidelines
- Script comments and synopsis blocks for detailed usage

---

**Last Updated:** 2025-11-13
**Compatible With:** Windows 10/11 (Pro, Enterprise, Education)
