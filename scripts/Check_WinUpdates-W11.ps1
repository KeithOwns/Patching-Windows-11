<#
.SYNOPSIS
  Opens the Windows Update settings page and clicks the "Check for updates" button.
.NOTES
  Requires Windows 10/11 and administrator privileges to load assemblies
  if restricted.
#>

#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-WinUpdateCheck {
    Write-Host "`n" -NoNewline
    Write-Host ("═" * 60) -ForegroundColor Blue
    Write-Host "  WINDOWS UPDATE CHECKER" -ForegroundColor White
    Write-Host ("═" * 60) -ForegroundColor Blue

    try {
        # Load UI Automation assemblies
        Add-Type -AssemblyName UIAutomationClient
        Add-Type -AssemblyName UIAutomationTypes
    } catch {
        Write-Host "  ⚠ Failed to load UI Automation assemblies." -ForegroundColor Yellow
        Write-Host "    Cannot proceed with Windows Update check." -ForegroundColor Gray
        return
    }

    Write-Host "`n  Opening Windows Update settings..." -ForegroundColor Yellow
    Write-Host "  • Launching Settings..." -ForegroundColor Gray

    # Open MS Settings to the Windows Update page
    Start-Process "ms-settings:windowsupdate"

    # Wait for the Settings app to open and load
    Write-Host "  • Waiting for Settings to load (5 sec)..." -ForegroundColor Gray
    Start-Sleep -Seconds 5

    try {
        # Get the root automation element
        $desktop = [System.Windows.Automation.AutomationElement]::RootElement
        
        # Find the Settings window
        # Note: The window name is just "Settings"
        $condition = New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::NameProperty,
            "Settings"
        )
        
        $settingsWindow = $desktop.FindFirst(
            [System.Windows.Automation.TreeScope]::Children,
            $condition
        )
        
        if ($settingsWindow -eq $null) {
            Write-Host "  ⚠ Could not find Settings window. Please ensure it's open." -ForegroundColor Yellow
            return
        }
        
        Write-Host "  • Found Settings window. Looking for 'Check for updates' button..." -ForegroundColor Gray
        
        # Wait a bit more for the page to fully load
        Start-Sleep -Seconds 2
        
        # Search for the "Check for updates" button
        $buttonText = "Check for updates"
        $buttonFound = $false
        
        $buttonCondition = New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::NameProperty,
            $buttonText
        )
        
        $button = $settingsWindow.FindFirst(
            [System.Windows.Automation.TreeScope]::Descendants,
            $buttonCondition
        )
        
        if ($button -ne $null) {
            Write-Host "  • Found button: '$buttonText'" -ForegroundColor Gray
            
            # Get the Invoke pattern to click the button
            $invokePattern = $button.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
            
            if ($invokePattern -ne $null) {
                Write-Host "  ✓ Clicking '$buttonText' button..." -ForegroundColor Green
                $invokePattern.Invoke()
                Write-Host "  ✓ Successfully clicked the update button!" -ForegroundColor Green
                $buttonFound = $true
            }
        }
        
        if (-not $buttonFound) {
            Write-Host "  ⚠ Could not find the '$buttonText' button." -ForegroundColor Yellow
            Write-Host "    The button might be hidden, disabled (if updates are managed)," -ForegroundColor Gray
            Write-Host "    or an update is already in progress." -ForegroundColor Gray
        }
        
    } catch {
        Write-Host "  ⚠ Error during UI automation: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "    Please manually check for updates." -ForegroundColor Gray
    }

    Write-Host "`n  ℹ️  Settings is open - verify updates are checking." -ForegroundColor Cyan
    Write-Host ("─" * 60) -ForegroundColor DarkGray
}

# --- Main ---
Clear-Host
Invoke-WinUpdateCheck