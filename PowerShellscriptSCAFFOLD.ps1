<#
.SYNOPSIS
    PowerShell Script Scaffold - A reusable template for creating well-structured PowerShell scripts.
.DESCRIPTION
    This scaffold provides a professional foundation for PowerShell scripts with built-in logging,
    formatted status output using color-coded symbols, and robust error handling. It includes:
    - Automatic transcript logging with timestamps
    - Write-StatusLine function with [+] (success), [-] (failed), [!] (warning) symbols
    - Self-elevating admin privilege check
    - Try/catch/finally error handling
    - Professional header and footer output
    - Modern color output using $PSStyle (falls back for older consoles)
.PARAMETER LogDirectory
    Specifies a custom directory to store the log files.
    Defaults to the current user's Downloads folder ($env:USERPROFILE\Downloads).
.PARAMETER ShowDemo
    When present, displays sample output demonstrating the Write-StatusLine formatting.
    Omit this parameter in production to suppress demo output.
.EXAMPLE
    .\PowerShellScriptScaffold_v2.ps1
    Runs the script. If not admin, it will attempt to re-launch itself as admin.
.EXAMPLE
    .\PowerShellScriptScaffold_v2.ps1 -LogDirectory "C:\Logs"
    Runs the script as admin and stores the resulting log file in "C:\Logs".
.EXAMPLE
    .\PowerShellScriptScaffold_v2.ps1 -ShowDemo
    Runs the script as admin and displays sample formatted output.
.NOTES
    Author:     Keith Tibbitts
    Created:    2025-10-29
    Version:    2.16 (Gemini Edits)
    
    Status Symbol Legend:
    [+] = Success/Positive (Green)
    [-] = Failed/Negative (Red)
    [!] = Warning/Note (Yellow)
    [?] = Unknown (Gray)

    Scheduled Task Note:
    If running this script as a scheduled task, be aware that the default $LogDirectory
    ($env:USERPROFILE\Downloads) will resolve to the profile of the account running the task
    (e.g., C:\Windows\System32\config\systemprofile\Downloads for the SYSTEM account).
    It is recommended to use the -LogDirectory parameter to specify an explicit path.
#>

[CmdletBinding()]
param (
    # Default is set to empty; we assign the real default inside the script.
    [string]$LogDirectory = "",
    
    # Show demo output
    [switch]$ShowDemo
)

# --- Sigma Requirement: Formatting Function & Output Standards ---
# This requirement includes:
# 1. Write-StatusLine function for consistent formatted output
# 2. Use of common abbreviations in script output
# 3. Text wrapping rules: When multi-line text is needed, break lines at natural word boundaries.
# 4. Section headings: All section headings in script output should be displayed in Blue color.

# --- Define Colors (Use $PSStyle if available) ---
# These are defined early so the Write-StatusLine function can see them in this scope.
$cSuccess = if ($PSStyle) { $PSStyle.Foreground.Green } else { "Green" }
$cError   = if ($PSStyle) { $PSStyle.Foreground.Red } else { "Red" }
$cWarning = if ($PSStyle) { $PSStyle.Foreground.Yellow } else { "Yellow" }
$cUnknown = if ($PSStyle) { $PSStyle.Foreground.Gray } else { "Gray" }
$cHeader  = if ($PSStyle) { $PSStyle.Foreground.Blue } else { "Blue" }
$cCyan    = if ($PSStyle) { $PSStyle.Foreground.Cyan } else { "Cyan" }
$cDim     = if ($PSStyle) { $PSStyle.Foreground.DarkGray } else { "DarkGray" }
$cGray    = if ($PSStyle) { $PSStyle.Foreground.Gray } else { "Gray" }
$cReset   = if ($PSStyle) { $PSStyle.Reset } else { "" }


function Write-StatusLine {
    <#
    .SYNOPSIS
        Writes a line with a left-justified description and an aligned, colored status.
    .DESCRIPTION
        Formats output with a description, dotted padding, and a colored status indicator.
        Uses $PSStyle for modern terminals if available, otherwise falls back to -ForegroundColor.
    .PARAMETER Description
        The description text (max 60 characters, will be truncated if longer)
    .PARAMETER Status
        The status indicator (max 15 characters, will be truncated if longer)
    .EXAMPLE
        Write-StatusLine -Description "Windows Update svc status" -Status "[+]"
        Write-StatusLine -Description "Network conn test" -Status "[-]"
    #>
    [CmdletBinding()]
    param (
        [string]$Description,
        [string]$Status
    )

    # --- Clip (truncate) Description and Status to new limits ---
    $MaxDescLength = 60  # Max description before status (allowing for spacing to 67)
    $MaxStatusLength = 15  # Max status text length (e.g., "successful", "incomplete")

    if ($Description.Length -gt $MaxDescLength) {
        $Description = $Description.Substring(0, $MaxDescLength)
    }
    if ($Status.Length -gt $MaxStatusLength) {
        $Status = $Status.Substring(0, $MaxStatusLength)
    }

    $PreferredIndent = 50  # Preferred position for status symbols
    $MaxIndent = 67      # Maximum position for status symbols
    $FillerChar = "."
    
    # Calculate padding based on description length
    if ($Description.Length -lt $PreferredIndent) {
        $TargetIndent = $PreferredIndent
    }
    elseif ($Description.Length -lt $MaxIndent) {
        $TargetIndent = $MaxIndent
    }
    else {
        $TargetIndent = $Description.Length + 1
    }
    $PaddingWidth = $TargetIndent - $Description.Length
    
    if ($PaddingWidth -lt 1) {  
        $PaddingWidth = 1  
    }
    
    $Padding = $FillerChar * $PaddingWidth
    # --- End of padding logic ---

    # Define status words and their colors
    $PositiveWords = "on", "active", "configured", "complete", "successful", "finish", "finished", "ok"
    $NegativeWords = "off", "inactive", "failed", "error", "incomplete", "not found"
    $WarningWords = "warning"
    $UnknownWords = "unknown"

    # --- EDIT: Use variables defined in the script body ---
    $AnsiColor = $cUnknown # Default ANSI sequence
    $LegacyColor = "Gray"   # Default legacy color string

    # Check if status starts with a symbol
    if ($Status -match '^\[\+\]') {
        $AnsiColor = $cSuccess
        $LegacyColor = "Green"
    }
    elseif ($Status -match '^\[-\]') {
        $AnsiColor = $cError
        $LegacyColor = "Red"
    }
    elseif ($Status -match '^\[!\]') {
        $AnsiColor = $cWarning
        $LegacyColor = "Yellow"
    }
    elseif ($Status -match '^\[\?\]') {
        $AnsiColor = $cUnknown
        $LegacyColor = "Gray"
    }
    # Otherwise check text-based status
    elseif ($PositiveWords -contains $Status.ToLower()) {
        $AnsiColor = $cSuccess
        $LegacyColor = "Green"
    }
    elseif ($NegativeWords -contains $Status.ToLower()) {
        $AnsiColor = $cError
        $LegacyColor = "Red"
    }
    elseif ($WarningWords -contains $Status.ToLower()) {
        $AnsiColor = $cWarning
        $LegacyColor = "Yellow"
    }
    elseif ($UnknownWords -contains $Status.ToLower()) {
        $AnsiColor = $cUnknown
        $LegacyColor = "Gray"
    }

    # --- EDIT: Write the line using $PSStyle if available ---
    if ($PSStyle) {
        # $AnsiColor already contains the ANSI sequence
        Write-Host $Description -NoNewline
        Write-Host "$($AnsiColor)${Padding}${Status}$($cReset)"
    }
    else {
        # Fallback to legacy -ForegroundColor
        Write-Host $Description -NoNewline
        Write-Host $Padding -ForegroundColor $LegacyColor -NoNewline
        Write-Host $Status -ForegroundColor $LegacyColor
    }
}


# --- Alpha Requirement: Robust Logging ---

# Set default Log Directory using the $env:USERPROFILE variable
if (-not $LogDirectory) { # Use idiomatic PowerShell check
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
    
    # --- EDIT: REPLACED PRE-FLIGHT CHECK ---
    # --- PRE-FLIGHT CHECK: Admin Privileges (Self-Elevating) ---
    $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $IsAdmin) {
        Clear-Host
        # Note: Write-StatusLine is defined above, so we can use it here.
        Write-StatusLine -Description "Admin privs required" -Status "[!]"
        Write-Host "Attempting to re-launch as Administrator..." -ForegroundColor $cWarning
        Start-Sleep -Seconds 2
        
        try {
            # Get all script parameters and re-construct them for the new process
            $Params = @()
            if ($PSBoundParameters.Count -gt 0) {
                $Params = $PSBoundParameters.Keys | ForEach-Object {
                    # Handle switch parameters
                    if ($PSBoundParameters[$_] -is [bool] -and $PSBoundParameters[$_]) {
                        "-$_"
                    }
                    # Handle parameters with values
                    elseif ($PSBoundParameters[$_] -isnot [bool]) {
                        # Quote parameters with spaces
                        "-$_", "'$($PSBoundParameters[$_])'"
                    }
                }
            }
            
            # Re-launch the script with the same parameters, elevated
            Start-Process powershell -Verb RunAs -ArgumentList ("-NoProfile -File '{0}' {1}" -f $MyInvocation.MyCommand.Path, ($Params -join ' ')) -ErrorAction Stop
        }
        catch {
            Write-StatusLine -Description "Re-launch as admin failed" -Status "[-]"
            Write-Warning "Please re-run as Administrator."
            Write-Host "Press Enter to exit..." -ForegroundColor $cGray
            Read-Host | Out-Null
        }
        
        # This exit will trigger the 'finally' block to stop the transcript
        exit 1
    }
    # --- End Pre-flight Check ---


    # Clear the console before output begins
    Clear-Host
    
    # Display script title and description (centered)
    $Title = "PowerShell Script Scaffold"
    $Desc1 = "A reusable template for creating well-structured PowerShell scripts"
    $Desc2 = "with built-in logging, formatted status output, and professional error handling."
    
    try {
        $WindowWidth = $Host.UI.RawUI.WindowSize.Width
    }
    catch {
        $WindowWidth = 80 # Fallback
    }
    
    # Center the title
    $TitlePadding = [Math]::Max(0, [Math]::Floor(($WindowWidth - $Title.Length) / 2))
    Write-Host (" " * $TitlePadding) -NoNewline
    Write-Host $Title -ForegroundColor $cCyan
    
    # Center the description lines
    $Desc1Padding = [Math]::Max(0, [Math]::Floor(($WindowWidth - $Desc1.Length) / 2))
    Write-Host (" " * $Desc1Padding) -NoNewline
    Write-Host $Desc1 -ForegroundColor $cDim
    
    $Desc2Padding = [Math]::Max(0, [Math]::Floor(($WindowWidth - $Desc2.Length) / 2))
    Write-Host (" " * $Desc2Padding) -NoNewline
    Write-Host $Desc2 -ForegroundColor $cDim
    
    Write-Host # Add a blank line
    
    # --- Demo Output (controlled by -ShowDemo parameter) ---
    if ($ShowDemo) {
        Write-Host "Sample of default output format:" -ForegroundColor $cHeader
        Write-Host # Add a blank line for readability
        
        # Display legend
        Write-Host "Legend: " -NoNewline -ForegroundColor $cDim
        Write-Host "[+]" -NoNewline -ForegroundColor $cSuccess
        Write-Host " Success     " -NoNewline -ForegroundColor $cDim
        Write-Host "[-]" -NoNewline -ForegroundColor $cError
        Write-Host " Failed     " -NoNewline -ForegroundColor $cDim
        Write-Host "[!]" -NoNewline -ForegroundColor $cWarning
        Write-Host " Warning" -ForegroundColor $cDim
        Write-Host # Add a blank line

        # --- START DEMO SCRIPT LOGIC (using Write-StatusLine) ---

        Write-StatusLine -Description "Windows Update svc status" -Status "[+]"
        Write-StatusLine -Description "Disk space check (C: drive)" -Status "[+]"
        Write-StatusLine -Description "Network conn test" -Status "[-]"
        Write-StatusLine -Description "Antivirus def update" -Status "[+]"
        # Test for a line that will be clipped
        Write-StatusLine -Description "Descriptions of checks made by the script longer than 60 characters in length will be truncated!" -Status "[!]"
        
        # --- END DEMO SCRIPT LOGIC ---
        
        Write-Host # Add a blank line
    }
    
    # --- ACTUAL SYSTEM CHEKS ---
    Write-Host "System Health Checks:" -ForegroundColor $cHeader
    Write-Host # Add a blank line
    
    # Check 1: Disk Space on C: Drive
    try {
        $CDrive = Get-PSDrive C -ErrorAction Stop
        $FreeSpacePercent = ($CDrive.Free / ($CDrive.Used + $CDrive.Free)) * 100
        
        if ($FreeSpacePercent -lt 70) {
            Write-StatusLine -Description "C: drive free space (% avail)" -Status "[-]"
        }
        elseif ($FreeSpacePercent -lt 85) {
            Write-StatusLine -Description "C: drive free space (% avail)" -Status "[!]"
        }
        else {
            Write-StatusLine -Description "C: drive free space (% avail)" -Status "[+]"
        }
    }
    catch {
        Write-StatusLine -Description "C: drive free space check" -Status "[-]"
    }
    
    # Check 2: PowerShell Version
    $PSVersion = $PSVersionTable.PSVersion.Major
    if ($PSVersion -ge 7) {
        Write-StatusLine -Description "PS ver ($PSVersion.x detected)" -Status "[+]"
    }
    elseif ($PSVersion -ge 5) {
        Write-StatusLine -Description "PS ver ($PSVersion.x detected)" -Status "[-]"
    }
    else {
        Write-StatusLine -Description "PS ver ($PSVersion.x detected)" -Status "[-]"
    }
    
    # Check 3: Running as Administrator
    # Failure case is handled by pre-flight check at script start.
    Write-StatusLine -Description "Script running with admin privs" -Status "[+]"
    
    Write-Host # Add a blank line
    Write-Host # Add a blank line
    Write-StatusLine -Description "Script exec completed" -Status "[+]"
}
catch {
    # 4. Error Handling
    Write-StatusLine -Description "Script exec failed - terminating error occurred" -Status "[-]"
    Write-Error $_ # Print the full error object to the error stream
    exit 1  
}
finally {
    # 5. Guaranteed Log Finalization
    Write-Host # Add a blank line
    Write-StatusLine -Description "Transcript log stopped" -Status "[+]"
    Write-Host "Stopping transcript..."
    Stop-Transcript | Out-Null
}

# Display log file location after transcript stops
# Wrapping Rule: Do not split words (e.g., the path) across lines.

# --- Check width to prevent splitting path across lines ---
$LogPrefix = "Log file saved to: "
try {
    # Get window width
    $WindowWidth = $Host.UI.RawUI.WindowSize.Width
}
catch {
    $WindowWidth = 80 # Fallback
}

if (($LogPrefix.Length + $LogPath.Length + 1) -gt $WindowWidth) {
    # Path is too long, print on a new line to avoid word split
    Write-Host $LogPrefix -ForegroundColor $cDim
    Write-Host $LogPath -ForegroundColor $cGray
}
else {
    # Fits on one line
    Write-Host $LogPrefix -NoNewline -ForegroundColor $cDim
    Write-Host $LogPath -ForegroundColor $cGray
}

# Add three empty lines for vertical space in the console
Write-Host
Write-Host
Write-Host

# --- Omega Requirement (Line for the PowerShell Window) ---
# This print happens *after* the transcript has stopped.

# --- Helper function for alternating colors ---
function Write-AlternatingColors {
    param (
        [string]$Text,
        [array]$Colors # Pass array of colors
    )
    
    $ColorIndex = 0
    foreach ($char in $Text.ToCharArray()) {
        Write-Host $char -ForegroundColor $Colors[$ColorIndex] -NoNewline
        $ColorIndex = ($ColorIndex + 1) % $Colors.Length
    }
}
# --- End of helper function ---

# Static date/time of last script edit
$Date = "2025/10/30"
$Time = "14:35" # Updated time
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
$LastEdited = "Last edited"
$LeftPart1 = " with "
$LLMName = "Google Gemini"
# Define $PSStyle colors
$GeminiColors = "Green", "Yellow", "Red", "Blue" # Use legacy color strings for the rainbow effect

$LeftPart2 = " at "
$LeftPart3 = " ($TZAbbreviation) on $Date" # Time is handled separately
$RightPart1 = " - by "
$RightPart2 = "Keith Tibbitts"
$RightText = $RightPart1 + $RightPart2
$FullLeftText = "$LastEdited$LeftPart1$LLMName$LeftPart2$Time$LeftPart3"

# 3. Calculate Padding and Check Width
try {
    $WindowWidth = $Host.UI.RawUI.WindowSize.Width
}
catch {
    $WindowWidth = 80 # Fallback
}

$MinTotalLength = $FullLeftText.Length + $RightText.Length + 1 # +1 for a single space

# --- Check width to prevent splitting line ---
if ($MinTotalLength -gt $WindowWidth) {
    # Line is too long to fit, even with minimal padding.
    # Print left and right parts on separate lines to avoid splitting words.
    
    # Print Left Part (with colors)
    Write-Host $LastEdited -ForegroundColor $cCyan -NoNewline
    Write-Host $LeftPart1 -NoNewline
    Write-AlternatingColors -Text $LLMName -Colors $GeminiColors
    Write-Host $LeftPart2 -NoNewline
    Write-Host $Time -ForegroundColor $cCyan -NoNewline
    Write-Host $LeftPart3 # This prints a newline at the end

    # Print Right Part (right-aligned on its own line)
    $RightPaddingWidth = [Math]::Max(1, $WindowWidth - $RightText.Length - 1)
    $RightPadding = " " * $RightPaddingWidth
    
    Write-Host $RightPadding -NoNewline
    Write-Host $RightPart1 -NoNewline
    Write-Host $RightPart2 -ForegroundColor $cCyan
}
else {
    # Original logic: The line fits, so calculate dynamic padding.
    $PaddingWidth = $WindowWidth - $FullLeftText.Length - $RightText.Length - 1 # -1 for safety
    if ($PaddingWidth -lt 1) { $PaddingWidth = 1 }
    $Padding = " " * $PaddingWidth

    # 4. Print the final line in multiple parts to allow for color
    Write-Host $LastEdited -ForegroundColor $cCyan -NoNewline
    Write-Host $LeftPart1 -NoNewline
    Write-AlternatingColors -Text $LLMName -Colors $GeminiColors
    Write-Host $LeftPart2 -NoNewline
    Write-Host $Time -ForegroundColor $cCyan -NoNewline
    Write-Host $LeftPart3 -NoNewline
    Write-Host $Padding -NoNewline
    Write-Host $RightPart1 -NoNewline
    Write-Host $RightPart2 -ForegroundColor $cCyan
}

