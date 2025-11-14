#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Restarts the Windows Security application.

.DESCRIPTION
    This script stops all running instances of the Windows Security app and its related
    processes, then restarts the application. Useful for troubleshooting Windows Security
    interface issues or applying changes.

.PARAMETER NoRestart
    If specified, only stops the Windows Security app without restarting it.

.PARAMETER Verbose
    Displays detailed information about the restart process.

.EXAMPLE
    .\Restart-WindowsSecurity.ps1
    Restarts the Windows Security app.

.EXAMPLE
    .\Restart-WindowsSecurity.ps1 -NoRestart
    Stops the Windows Security app without restarting it.

.NOTES
    Author: Keith @ AI+IT Support
    Version: 1.0.2
    Last Updated: 2025-11-12
    
    Requirements:
    - Windows 10/11
    - PowerShell 5.1 or higher
    
    Processes targeted:
    - SecurityHealthSystray.exe (System tray icon)
    - SecHealthUI.exe (Main UI process)
    
    Change Log:
    1.0.1 - Removed explicit 'exit' calls and added Read-Host to keep the console window open.
    1.0.2 - Removed Read-Host command to allow the console window to close automatically upon completion.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$NoRestart
)

#Region Functions

function Write-Log {
    <#
    .SYNOPSIS
        Writes a timestamped log message.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        'Error'   { Write-Host $logMessage -ForegroundColor Red }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Success' { Write-Host $logMessage -ForegroundColor Green }
        default   { Write-Host $logMessage -ForegroundColor White }
    }
}

function Stop-WindowsSecurityProcesses {
    <#
    .SYNOPSIS
        Stops all Windows Security related processes.
    #>
    [CmdletBinding()]
    param()
    
    $processNames = @(
        'SecurityHealthSystray',
        'SecHealthUI'
    )
    
    $stoppedProcesses = @()
    
    foreach ($processName in $processNames) {
        try {
            $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
            
            if ($processes) {
                foreach ($process in $processes) {
                    Write-Log "Stopping process: $processName (PID: $($process.Id))" -Level Info
                    $process | Stop-Process -Force -ErrorAction Stop
                    $stoppedProcesses += $processName
                }
                Write-Log "Successfully stopped: $processName" -Level Success
            }
            else {
                Write-Log "Process not running: $processName" -Level Info
            }
        }
        catch {
            Write-Log "Failed to stop process $processName : $($_.Exception.Message)" -Level Warning
        }
    }
    
    # Give processes time to fully terminate
    if ($stoppedProcesses.Count -gt 0) {
        Write-Log "Waiting for processes to terminate..." -Level Info
        Start-Sleep -Seconds 2
    }
    
    return $stoppedProcesses
}

function Start-WindowsSecurityApp {
    <#
    .SYNOPSIS
        Starts the Windows Security application.
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Starting Windows Security app..." -Level Info
        
        # Method 1: Use the windowsdefender: protocol
        Start-Process "windowsdefender:"
        
        Write-Log "Windows Security app started successfully" -Level Success
        return $true
    }
    catch {
        Write-Log "Failed to start Windows Security app using primary method: $($_.Exception.Message)" -Level Warning
        
        # Method 2: Try launching via explorer
        try {
            Write-Log "Attempting alternate launch method..." -Level Info
            Start-Process "explorer.exe" -ArgumentList "windowsdefender:"
            Write-Log "Windows Security app started via alternate method" -Level Success
            return $true
        }
        catch {
            Write-Log "Failed to start Windows Security app: $($_.Exception.Message)" -Level Error
            return $false
        }
    }
}

function Test-WindowsSecurityRunning {
    <#
    .SYNOPSIS
        Checks if Windows Security app is running.
    #>
    [CmdletBinding()]
    param()
    
    $secHealthUI = Get-Process -Name "SecHealthUI" -ErrorAction SilentlyContinue
    return ($null -ne $secHealthUI)
}

#EndRegion Functions

#Region Main Script

try {
    Write-Log "================================" -Level Info
    Write-Log "Windows Security App Restart" -Level Info
    Write-Log "================================" -Level Info
    Write-Host ""
    
    # Check initial state
    $wasRunning = Test-WindowsSecurityRunning
    if ($wasRunning) {
        Write-Log "Windows Security app is currently running" -Level Info
    }
    else {
        Write-Log "Windows Security app is not currently running" -Level Info
    }
    
    Write-Host ""
    
    # Stop Windows Security processes
    Write-Log "Stopping Windows Security processes..." -Level Info
    $stoppedProcesses = Stop-WindowsSecurityProcesses
    
    if ($stoppedProcesses.Count -gt 0) {
        Write-Log "Stopped $($stoppedProcesses.Count) process(es)" -Level Success
    }
    else {
        Write-Log "No processes needed to be stopped" -Level Info
    }
    
    Write-Host ""
    
    # Restart unless NoRestart is specified
    if (-not $NoRestart) {
        $startSuccess = Start-WindowsSecurityApp
        
        if ($startSuccess) {
            # Wait a moment and verify the app started
            Start-Sleep -Seconds 3
            
            if (Test-WindowsSecurityRunning) {
                Write-Host ""
                Write-Log "Windows Security app restarted successfully!" -Level Success
            }
            else {
                Write-Host ""
                Write-Log "Windows Security app was launched, but UI process not detected" -Level Warning
                Write-Log "The app may take a moment to fully initialize" -Level Info
            }
        }
        else {
            Write-Host ""
            Write-Log "Failed to restart Windows Security app" -Level Error
        }
    }
    else {
        Write-Log "NoRestart specified - Windows Security app stopped but not restarted" -Level Info
    }
    
    Write-Host ""
    Write-Log "================================" -Level Info
    Write-Log "Operation completed successfully" -Level Info
    Write-Log "================================" -Level Info

    # Removed exit 0/1 calls here.
}
catch {
    Write-Host ""
    Write-Log "An unexpected error occurred: $($_.Exception.Message)" -Level Error
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level Error
    # Removed exit 1 call here.
}

# The Read-Host section was removed here to allow the window to close automatically.

#EndRegion Main Script
