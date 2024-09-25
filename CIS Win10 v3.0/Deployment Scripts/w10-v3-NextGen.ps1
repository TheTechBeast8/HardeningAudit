$SectionNG = @{
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" = @{
        "EnableVirtualizationBasedSecurity" = 1
        "RequirePlatformSecurityFeatures" = 3
        "HypervisorEnforcedCodeIntegrity" = 1
        "HVCIMATRequired" = 1
        "LsaCfgFlags" = 1
        "ConfigureSystemGuardLaunch" = 1
    }
    "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" = @{
        "RunAsPPL" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\AppHVSI" = @{
        "AuditApplicationGuard" = 1
        "AllowCameraMicrophoneRedirection" = 0
        "AllowPersistence" = 0
        "SaveFilesToHost" = 0
        "AppHVSIClipboardSettings" = 1
        "AllowAppHVSI_ProviderSet" = 1
    }
}
#function to create set the keys
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
Set-RegistryKeys -Table $SectionNG
Write-Host "All registry settings applied"