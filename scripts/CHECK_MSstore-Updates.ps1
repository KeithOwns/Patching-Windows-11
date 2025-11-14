# PowerShell script to open MS Store Downloads page and check for updates
# Requires Windows 10/11

# Load UI Automation assemblies
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

Write-Host "Opening Microsoft Store Downloads page..." -ForegroundColor Cyan

# Open MS Store to Downloads and Updates page
Start-Process "ms-windows-store://downloadsandupdates"

# Wait for the Store app to open and load
Write-Host "Waiting for Microsoft Store to load..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

# Try to find and click the "Get updates" button
try {
    # Get the root automation element
    $desktop = [System.Windows.Automation.AutomationElement]::RootElement
    
    # Find the Microsoft Store window
    $condition = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::NameProperty,
        "Microsoft Store"
    )
    
    $storeWindow = $desktop.FindFirst(
        [System.Windows.Automation.TreeScope]::Children,
        $condition
    )
    
    if ($storeWindow -eq $null) {
        Write-Host "Could not find Microsoft Store window. Please ensure it's open." -ForegroundColor Red
        exit 1
    }
    
    Write-Host "Found Microsoft Store window. Looking for 'Get updates' button..." -ForegroundColor Yellow
    
    # Wait a bit more for the page to fully load
    Start-Sleep -Seconds 2
    
    # Search for the "Get updates" button
    # The button text might be "Get updates" or similar
    $buttonTexts = @("Get updates", "Check for updates", "Update all")
    $buttonFound = $false
    
    foreach ($buttonText in $buttonTexts) {
        $buttonCondition = New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::NameProperty,
            $buttonText
        )
        
        $button = $storeWindow.FindFirst(
            [System.Windows.Automation.TreeScope]::Descendants,
            $buttonCondition
        )
        
        if ($button -ne $null) {
            Write-Host "Found button: '$buttonText'" -ForegroundColor Green
            
            # Get the Invoke pattern to click the button
            $invokePattern = $button.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
            
            if ($invokePattern -ne $null) {
                Write-Host "Clicking '$buttonText' button..." -ForegroundColor Cyan
                $invokePattern.Invoke()
                Write-Host "Successfully clicked the update button!" -ForegroundColor Green
                $buttonFound = $true
                break
            }
        }
    }
    
    if (-not $buttonFound) {
        Write-Host "Could not find the update button. It may have a different name or the page may still be loading." -ForegroundColor Yellow
        Write-Host "Try running the script again or manually check for updates." -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "Error occurred: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "You may need to manually click the 'Get updates' button." -ForegroundColor Yellow
}

Write-Host "`nScript completed." -ForegroundColor Cyan
