<#
.SYNOPSIS
    PowerShell Script Scaffold - A reusable template for creating well-structured PowerShell scripts.
.DESCRIPTION
    This scaffold provides a professional foundation for PowerShell scripts with built-in logging,
    formatted status output using color-coded symbols, and robust error handling. It includes:
    - Automatic transcript logging with timestamps
    - Write-StatusLine function with [+] (success), [-] (failed), [!] (warning) symbols
    - Try/catch/finally error handling
    - Professional header and footer output
    Replace the sample script logic with your own code to create production-ready scripts.
.PARAMETER LogDirectory
    Specifies a custom directory to store the log files.
    Defaults to the current user's Downloads folder ($env:USERPROFILE\Downloads).
.PARAMETER ShowDemo
    When present, displays sample output demonstrating the Write-StatusLine formatting.
    Omit this parameter in production to suppress demo output.
.EXAMPLE
    .\PowerShellscriptSCAFFOLD.ps1
    Runs the script with default parameters, logging to the user's Downloads folder.
.EXAMPLE
    .\PowerShellscriptSCAFFOLD.ps1 -LogDirectory "C:\Logs"
    Runs the script and stores the resulting log file in "C:\Logs".
.EXAMPLE
    .\PowerShellscriptSCAFFOLD.ps1 -ShowDemo
    Runs the script and displays sample formatted output.
.NOTES
    Author:      Keith Tibbitts
    Created:     2025-10-29
    Version:     2.14
    
    Status Symbol Legend:
    [+] = Success/Positive (Green)
    [-] = Failed/Negative (Red)
    [!] = Warning/Note (Yellow)
    [?] = Unknown (Gray)
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
# 2. Use of common abbreviations in script output to maximize space within the 98-character description limit
# 3. Text wrapping rules: When multi-line text is needed, break lines at natural word boundaries.
#    Never split words across lines. Ensure each line is a complete phrase for readability.
# 4. Warning status details: When a [!] status is generated and additional information is available,
#    display it concisely to the right of the [!] symbol. Format: "[!] - Additional info"
#    Example: "[!] - Under 85%" or "[!] - Needs update"
# 5. Section headings: All section headings in script output should be displayed in Blue color.
#    Example: Write-Host "System Health Checks:" -ForegroundColor Blue
#
# Common abbreviations to use:
# - "config" or "cfg" instead of "configuration"
# - "svc" instead of "service"
# - "conn" instead of "connection"
# - "msg" instead of "message"
# - "info" instead of "information"
# - "cert" instead of "certificate"
# - "auth" instead of "authentication"
# - "admin" instead of "administrator"
# - "privs" instead of "privileges"
# - "exec" instead of "execution"
# - "log" instead of "logging"
# - "ver" instead of "version"
# - "PS" instead of "PowerShell" (except in titles)
# - "avail" instead of "available"
# - "temp" instead of "temporary"
# - "max" instead of "maximum"
# - "min" instead of "minimum"
# - "def" instead of "default"
# - "mgmt" instead of "management"
# - "perm" instead of "permission"
# - "proc" instead of "process"
# - "req" instead of "required/requirement"
# - Use standard tech abbreviations: RAM, CPU, DNS, IP, URL, API, etc.

function Write-StatusLine {
    <#
    .SYNOPSIS
        Writes a line with a left-justified description and an aligned, colored status.
    .DESCRIPTION
        Formats output with a description, dotted padding, and a colored status indicator.
        Supports both symbolic and text status values:
        - [+] = Success/Positive (Green)
        - [-] = Failed/Negative (Red)  
        - [!] = Warning/Note (Yellow)
        - [?] = Unknown (Gray)
        - Text values like "OK", "Active", "Failed", "Warning" are also supported
        
        SIGMA REQUIREMENT: 
        - Use common abbreviations in descriptions to stay within limits
        - Status symbols positioned at 50 characters (preferred) or up to 67 characters (max)
        - Keep descriptions concise for optimal readability
        - Warning details: For [!] status, append additional info after the symbol: "[!] - Details"
        Examples: "svc" (service), "config" (configuration), "conn" (connection), "auth" (authentication)
    .PARAMETER Description
        The description text (max 60 characters, will be truncated if longer)
    .PARAMETER Status
        The status indicator (max 10 characters, will be truncated if longer)
        For warnings with details, use format: "[!] - Additional info"
    .EXAMPLE
        Write-StatusLine -Description "Windows Update svc status" -Status "[+]"
        Write-StatusLine -Description "Network conn test" -Status "[-]"
        Write-StatusLine -Description "Disk space warning (C: drive)" -Status "[!] - Under 85%"
        Write-StatusLine -Description "Unknown state" -Status "[?]"
        Write-StatusLine -Description "Disk space warning (C: drive)" -Status "[!]"
        Write-StatusLine -Description "Unknown state" -Status "[?]"
    #>
    [CmdletBinding()]
    param (
        [string]$Description,
        [string]$Status
    )

    # --- EDIT: Clip (truncate) Description and Status to new limits ---
    $MaxDescLength = 60  # Max description before status (allowing for spacing to 67)
    $MaxStatusLength = 20  # Increased to accommodate warning details: "[!] - Additional info"

    if ($Description.Length -gt $MaxDescLength) {
        $Description = $Description.Substring(0, $MaxDescLength)
    }
    if ($Status.Length -gt $MaxStatusLength) {
        $Status = $Status.Substring(0, $MaxStatusLength)
    }

    $PreferredIndent = 50  # Preferred position for status symbols
    $MaxIndent = 67        # Maximum position for status symbols
    $FillerChar = "."
    
    # Calculate padding based on description length
    # If description is short, use preferred indent (50)
    # If description is longer, use up to max indent (67)
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
        # This handles cases where $Description is exactly 98 or 99 chars
        $PaddingWidth = 1 
    }
    
    $Padding = $FillerChar * $PaddingWidth
    # --- End of padding logic ---

    # Define status words and their colors
    $PositiveWords = "on", "active", "configured", "complete", "successful", "finish", "finished", "ok"
    $NegativeWords = "off", "inactive", "failed", "error", "incomplete", "not found"
    $WarningWords = "warning"
    $UnknownWords = "unknown"

    $Color = "White" # Default
    
    # Check if status starts with a symbol
    if ($Status -match '^\[\+\]') {
        $Color = "Green"
    }
    elseif ($Status -match '^\[-\]') {
        $Color = "Red"
    }
    elseif ($Status -match '^\[!\]') {
        $Color = "Yellow"
    }
    elseif ($Status -match '^\[\?\]') {
        $Color = "Gray"
    }
    # Otherwise check text-based status
    elseif ($PositiveWords -contains $Status.ToLower()) {
        $Color = "Green"
    }
    elseif ($NegativeWords -contains $Status.ToLower()) {
        $Color = "Red"
    }
    elseif ($WarningWords -contains $Status.ToLower()) {
        $Color = "Yellow"
    }
    elseif ($UnknownWords -contains $Status.ToLower()) {
        $Color = "Gray"
    }

    # Write the formatted line with colored padding and status
    Write-Host $Description -NoNewline
    Write-Host $Padding -ForegroundColor $Color -NoNewline
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
    Write-Host $Title -ForegroundColor Cyan
    
    # Center the description lines
    $Desc1Padding = [Math]::Max(0, [Math]::Floor(($WindowWidth - $Desc1.Length) / 2))
    Write-Host (" " * $Desc1Padding) -NoNewline
    Write-Host $Desc1 -ForegroundColor DarkGray
    
    $Desc2Padding = [Math]::Max(0, [Math]::Floor(($WindowWidth - $Desc2.Length) / 2))
    Write-Host (" " * $Desc2Padding) -NoNewline
    Write-Host $Desc2 -ForegroundColor DarkGray
    
    Write-Host # Add a blank line
    
    # --- Demo Output (controlled by -ShowDemo parameter) ---
    if ($ShowDemo) {
        Write-Host "Sample of default output format:" -ForegroundColor Blue
        Write-Host # Add a blank line for readability
        
        # Display legend
        Write-Host "Legend: " -NoNewline -ForegroundColor DarkGray
        Write-Host "[+]" -NoNewline -ForegroundColor Green
        Write-Host " Success  " -NoNewline -ForegroundColor DarkGray
        Write-Host "[-]" -NoNewline -ForegroundColor Red
        Write-Host " Failed  " -NoNewline -ForegroundColor DarkGray
        Write-Host "[!]" -NoNewline -ForegroundColor Yellow
        Write-Host " Warning" -ForegroundColor DarkGray
        Write-Host # Add a blank line

        # --- START DEMO SCRIPT LOGIC (using Write-StatusLine) ---

        Write-StatusLine -Description "Windows Update svc status" -Status "[+]"
        Write-StatusLine -Description "Disk space check (C: drive)" -Status "[+]"
        Write-StatusLine -Description "Network conn test" -Status "[-]"
        Write-StatusLine -Description "Antivirus def update" -Status "[+]"
        # Test for a line that will be clipped
        Write-StatusLine -Description "Descriptions of checks made by the script longer than 98 characters in length will be truncated!" -Status "[!]"
        
        # --- END DEMO SCRIPT LOGIC ---
        
        Write-Host # Add a blank line
    }
    
    # --- ACTUAL SYSTEM CHECKS ---
    Write-Host "System Health Checks:" -ForegroundColor Blue
    Write-Host # Add a blank line
    
    # Check 1: Disk Space on C: Drive
    try {
        $CDrive = Get-PSDrive C -ErrorAction Stop
        $FreeSpacePercent = ($CDrive.Free / ($CDrive.Used + $CDrive.Free)) * 100
        
        if ($FreeSpacePercent -lt 70) {
            Write-StatusLine -Description "C: drive free space (${FreeSpacePercent:N1}% avail)" -Status "[-]"
        }
        elseif ($FreeSpacePercent -lt 85) {
            Write-StatusLine -Description "C: drive free space (${FreeSpacePercent:N1}% avail)" -Status "[!] - Under 85%"
        }
        else {
            Write-StatusLine -Description "C: drive free space (${FreeSpacePercent:N1}% avail)" -Status "[+]"
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
        Write-StatusLine -Description "PS ver ($PSVersion.x detected)" -Status "[!] - Upgrade to 7+"
    }
    else {
        Write-StatusLine -Description "PS ver ($PSVersion.x detected)" -Status "[-]"
    }
    
    # Check 3: Running as Administrator
    $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($IsAdmin) {
        Write-StatusLine -Description "Script running with admin privs" -Status "[+]"
    }
    else {
        Write-StatusLine -Description "Script running without admin privs" -Status "[-]"
    }
    
    Write-Host # Add a blank line
    Write-Host # Add a blank line
    Write-StatusLine -Description "Script exec completed" -Status "[+]"
}
catch {
    # 4. Error Handling
    Write-StatusLine -Description "Script exec failed - terminating error occurred" -Status "[-]"
    Write-Host $_.Exception.Message # Print the raw error message
    # exit 1 
}
finally {
    # 5. Guaranteed Log Finalization
    Write-Host # Add a blank line
    Write-StatusLine -Description "Transcript log stopped" -Status "[+]"
    Write-Host "Stopping transcript..."
    Stop-Transcript | Out-Null
}

# Display log file location after transcript stops
Write-Host "Log file saved to: " -NoNewline -ForegroundColor DarkGray
Write-Host $LogPath -ForegroundColor Gray

# Add three empty lines for vertical space in the console
Write-Host
Write-Host
Write-Host

# --- Omega Requirement (Line for the PowerShell Window) ---
# This print happens *after* the transcript has stopped.

# Static date/time of last script edit
$Date = "2025/10/30"
$Time = "11:02"

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
$LLMName = "Claude Sonnet 4.5"
$LeftPart2 = " at "
$LeftPart3 = " ($TZAbbreviation) on $Date" # Time is handled separately
$RightPart1 = " - by "
$RightPart2 = "Keith Tibbitts"
$RightText = $RightPart1 + $RightPart2 # Used for length calculation

# 3. Calculate Padding
$FullLeftText = "$LastEdited$LeftPart1$LLMName$LeftPart2$Time$LeftPart3" 
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
Write-Host $LastEdited -ForegroundColor Cyan -NoNewline # "Last edited" in teal
Write-Host $LeftPart1 -NoNewline
Write-Host $LLMName -ForegroundColor DarkYellow -NoNewline # Claude's brand color (orange)
Write-Host $LeftPart2 -NoNewline
Write-Host $Time -ForegroundColor Cyan -NoNewline # Use Cyan for "Teal"
Write-Host $LeftPart3 -NoNewline
Write-Host $Padding -NoNewline
Write-Host $RightPart1 -NoNewline
Write-Host $RightPart2 -ForegroundColor Cyan # Use Cyan for "Teal"
