<#
.SYNOPSIS
    A brief one-line description of what the script does.
.DESCRIPTION
    A more detailed description of the script's function, what it modifies,
    and any dependencies it might have.
.PARAMETER LogDirectory
    Specifies a custom directory to store the log files.
    Defaults to the current user's Downloads folder ($env:USERPROFILE\Downloads).
.EXAMPLE
    .\YourScript.ps1
    Runs the script with default parameters, logging to the user's Downloads folder.
.EXAMPLE
    .\YourScript.ps1 -LogDirectory "C:\Logs"
    Runs the script and stores the resulting log file in "C:\Logs".
.NOTES
    Author:      Keith Tibbitts
    Created:     2025-10-29
    Version:     2.13
#>

[CmdletBinding()]
param (
    # Default is set to empty; we assign the real default inside the script.
    [string]$LogDirectory = ""
)

# --- Sigma Requirement: Formatting Function ---

function Write-StatusLine {
    <#
    .SYNOPSIS
        Writes a line with a left-justified description and an aligned, colored status.
    #>
    [CmdletBinding()]
    param (
        [string]$Description,
        [string]$Status
    )

    # --- EDIT: Clip (truncate) Description and Status to new limits ---
    $MaxDescLength = 98
    $MaxStatusLength = 10

    if ($Description.Length -gt $MaxDescLength) {
        $Description = $Description.Substring(0, $MaxDescLength)
    }
    if ($Status.Length -gt $MaxStatusLength) {
        $Status = $Status.Substring(0, $MaxStatusLength)
    }

    $TargetIndent = 99 # Set a fixed position 99 characters from the left
    $FillerChar = "."
    
    # Calculate padding. This logic is now simpler.
    $PaddingWidth = $TargetIndent - $Description.Length
    
    if ($PaddingWidth -lt 1) { 
        # This handles cases where $Description is exactly 98 or 99 chars
        $PaddingWidth = 1 
    }
    
    $Padding = $FillerChar * $PaddingWidth
    # --- End of padding logic ---

    # Define status words and their colors
    $PositiveWords = "on", "active", "configured", "complete", "successful", "finish", "finished", "ok"
    $NegativeWords = "off", "inactive", "failed", "error", "incomplete", "not found"

    $Color = "White" # Default
    if ($PositiveWords -contains $Status.ToLower()) {
        $Color = "Green"
    }
    elseif ($NegativeWords -contains $Status.ToLower()) {
        $Color = "Red"
    }
    elseif ($Status.ToLower() -eq "warning") {
        $Color = "Yellow"
    }

    # Write the formatted line
    Write-Host $Description -NoNewline
    Write-Host $Padding -NoNewline
    Write-Host $Status -ForegroundColor $Color
}


# --- Alpha Requirement: Robust Logging ---

# Set default Log Directory using the $env:USERPROFILE variable
if ([string]::IsNullOrEmpty($LogDirectory)) {
    $LogDirectory = Join-Path -Path $env:USERPROFILE -ChildPath 'Downloads'
}

# 1. Define Log File Path
try {
    if (-not (Test-Path -Path $LogDirectory)) {
        Write-Warning "Log directory '$LogDirectory' does not exist. Attempting to create."
        New-Item -Path $LogDirectory -ItemType Directory -ErrorAction Stop | Out-Null
    }

    $LogBaseName = $MyInvocation.MyCommand.Name -replace '\.ps1$'
    $LogName = "${LogBaseName}_$(Get-Date -Format 'yyyyMMdd_HHmmss')_FILE.log"
    $LogPath = Join-Path -Path $LogDirectory -ChildPath $LogName

    # 2. Start Transcript
    Start-Transcript -Path $LogPath -ErrorAction Stop
}
catch {
    # This catch block handles errors *before* logging starts (e.g., permission error)
    Write-Error "CRITICAL: Failed to initialize log file at '$LogPath'. Script cannot continue."
    Write-Error $_.Exception.Message
    exit 1 # Exit script with a failure code
}

# 3. Main Script Body (wrapped in try/catch/finally)
try {
    # --- Sigma Requirement (Line Split) ---
    Write-Host "Script execution started. Logging to:"
    Write-Host $LogPath
    
    Write-Host "Running as user: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    Write-Host # Add a blank line for readability

    # --- START SCRIPT LOGIC (using Write-StatusLine) ---

    Write-StatusLine -Description "Checking system configuration" -Status "OK"
    Write-StatusLine -Description "Sample service check 1 (long name)" -Status "Active"
    Write-StatusLine -Description "Sample service check 2 (short)" -Status "Inactive"
    Write-StatusLine -Description "Testing alignment" -Status "Complete"
    # Test for a line that will be clipped
    Write-StatusLine -Description "This description is very long. In fact, it's over 98 characters long, so the text starting from 'so' should be clipped." -Status "Failed"
    # Test for a status that will be clipped
    Write-StatusLine -Description "Testing long status" -Status "ThisIsTooLong"
    
    # --- END SCRIPT LOGIC ---
    
    Write-Host # Add a blank line
    Write-StatusLine -Description "Script run" -Status "Successful"
}
catch {
    # 4. Error Handling
    Write-StatusLine -Description "A terminating error occurred" -Status "ERROR"
    Write-Host $_.Exception.Message # Print the raw error message
    # exit 1 
}
finally {
    # 5. Guaranteed Log Finalization
    Write-Host # Add a blank line
    Write-StatusLine -Description "Script finalization" -Status "Finished"
    Write-Host "Stopping transcript..."
    Stop-Transcript
}

# Add three empty lines for vertical space in the console
Write-Host
Write-Host
Write-Host

# --- Omega Requirement (Line for the PowerShell Window) ---
# This print happens *after* the transcript has stopped.

$Date = Get-Date -Format "yyyy/MM/dd"
$Time = Get-Date -Format "HH:mm"

# 1. Get TimeZone Abbreviation
$TZInfo = Get-TimeZone
$IsDaylight = [System.TimeZoneInfo]::Local.IsDaylightSavingTime((Get-Date))
if ($TZInfo.SupportsDaylightSavingTime -and $IsDaylight) {
    $FullName = $TZInfo.DaylightName
} else {
    $FullName = $TZInfo.StandardName
}
$TZAbbreviation = -join ($FullName -split ' ' | ForEach-Object { $_[0] })

# 2. Define text parts
$LeftPart1 = "Created with Gemini 2.5 Pro at "
$LeftPart2 = " ($TZAbbreviation) on $Date" # Time is handled separately
$RightPart1 = " - by "
$RightPart2 = "Keith Tibbitts"
$RightText = $RightPart1 + $RightPart2 # Used for length calculation

# 3. Calculate Padding
$FullLeftText = "$LeftPart1$Time$LeftPart2" 
try {
    $WindowWidth = $Host.UI.RawUI.WindowSize.Width
}
catch {
    $WindowWidth = 80 # Fallback
}
$PaddingWidth = $WindowWidth - $FullLeftText.Length - $RightText.Length - 1 # -1 for safety
if ($PaddingWidth -lt 1) { $PaddingWidth = 1 }
$Padding = " " * $PaddingWidth

# 4. Print the final line in multiple parts to allow for color
Write-Host $LeftPart1 -NoNewline
Write-Host $Time -ForegroundColor Cyan -NoNewline # Use Cyan for "Teal"
Write-Host $LeftPart2 -NoNewline
Write-Host $Padding -NoNewline
Write-Host $RightPart1 -NoNewline
Write-Host $RightPart2 -ForegroundColor Cyan # Use Cyan for "Teal"