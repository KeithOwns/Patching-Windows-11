#Requires -RunAsAdministrator

<#
.SYNOPSIS
  A stand-alone script to display an interactive menu
  for opening the Phishing Protection settings page.

.DESCRIPTION
  This script was extracted from '02-Security_Config-Win11.ps1'.
  It displays a simple console menu allowing the user to
  either open the Windows Security "App & browser control" page
  or skip and continue.
#>

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

# --- Main Script Logic (from Show-SecuritySummary) ---

Clear-Host
Write-Host "NOTE: Phishing protection for Edge must be manually set!" -ForegroundColor Yellow
Write-Host "Please choose an option:"

# --- Interactive Menu ---
$selectedOption = 0 # 0 = Open, 1 = Skip
$menuTop = [Console]::CursorTop # Store where the menu starts
$choiceMade = $false

# Hide cursor
$oldCursorVisible = $null
if ($Host.Name -eq 'ConsoleHost') {
    $oldCursorVisible = [Console]::CursorVisible
    [Console]::CursorVisible = $false
}

try {
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
}
finally {
    # Restore cursor
    if ($oldCursorVisible -ne $null) {
        [Console]::CursorVisible = $oldCursorVisible
    }
}

# Clear the menu area (2 lines)
[Console]::SetCursorPosition(0, $menuTop)
Write-Host (" " * [Console]::WindowWidth)
[Console]::SetCursorPosition(0, $menuTop + 1)
Write-Host (" " * [Console]::WindowWidth)
[Console]::SetCursorPosition(0, $menuTop) # Reset cursor

# --- End Interactive Menu ---

# Perform action based on selection
if ($selectedOption -eq 0) {
    if (Open-PhishingSettings) {
        Write-Host "[o] Opening Windows Security > App & browser control..." -ForegroundColor Green
    } else {
        Write-Host "  ✗ Failed to open settings." -ForegroundColor Red
    }
} else {
    # This branch is now reached by selecting option 1 and pressing Enter, or pressing Space on option 1
    Write-Host "  - Skipping Windows phishing protection setup." -ForegroundColor Gray
}

Write-Host "`nScript finished."
