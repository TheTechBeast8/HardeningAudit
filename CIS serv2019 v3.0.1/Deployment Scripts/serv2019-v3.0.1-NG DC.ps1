$NGSection18DC = @{
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" = @{
        "LsaCfgFlags" = 0
    }
}
$NGSection18MSDC = @{
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" = @{
        "HVCIMATRequired" = 1
        "ConfigureSystemGuardLaunch" = 1
        "HypervisorEnforcedCodeIntegrity" = 1
        "RequirePlatformSecurityFeatures" = 3
        "EnableVirtualizationBasedSecurity" = 1
    }
}
function Set-RegistryKeys {
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$table
    )
    foreach ($key in $table.Keys) {
        try {
            # Convert HKLM to full path
            $fullPath = $key -replace '^HKLM\\', 'HKLM:\\'
            
            if (!(Test-Path $fullPath)) {
                New-Item -Path $fullPath -Force | Out-Null
            }
            $values = $table[$key]
            foreach ($valueName in $values.Keys) {
                $value = $values[$valueName]
                $type = if ($value -is [int]) { "DWord" } else { "String" }
                
                # Use New-ItemProperty instead of Set-ItemProperty
                if (Get-ItemProperty -Path $fullPath -Name $valueName -ErrorAction SilentlyContinue) {
                    Set-ItemProperty -Path $fullPath -Name $valueName -Value $value
                } else {
                    New-ItemProperty -Path $fullPath -Name $valueName -Value $value -PropertyType $type -Force | Out-Null
                }
            }
        }
        catch {
            Write-Error "Failed to process key '$fullPath': $_"
        }
    }
}
Set-RegistryKeys -Table $NGSection18DC
Set-RegistryKeys -Table $NGSection18MSDC
Write-Host "All registry settings applied"