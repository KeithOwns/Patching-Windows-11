# This script must be run as Administrator to read the HKLM registry hive.

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config"
$regValueName = "VulnerableDriverBlocklistEnable"

Write-Host "Checking status of 'Microsoft Vulnerable Driver Blocklist'..."
Write-Host "Registry Path: $regPath"
Write-Host "Registry Value: $regValueName"
Write-Host "--------------------------------------------------"

try {
    # Try to get the specific registry value
    $value = Get-ItemProperty -Path $regPath -Name $regValueName -ErrorAction Stop
    
    if ($value.VulnerableDriverBlocklistEnable -eq 1) {
        $status = "Enabled"
    } elseif ($value.VulnerableDriverBlocklistEnable -eq 0) {
        $status = "Disabled"
    } else {
        $status = "Unknown (Value: $($value.VulnerableDriverBlocklistEnable))"
    }
}
catch [Microsoft.PowerShell.Commands.ItemPropertyNotFoundException] {
    # This error means the 'VulnerableDriverBlocklistEnable' value doesn't exist.
    # On modern systems (Win11 22H2+), if the value is missing, it is Enabled by default.
    $status = "Enabled (Default)"
}
catch {
    # Catch any other errors (e.g., path not found, permissions issue)
    $status = "Error: Could not read registry. Please ensure you are running as Administrator."
    Write-Warning $_.Exception.Message
}

Write-Host ""
Write-Host "Status: $status"