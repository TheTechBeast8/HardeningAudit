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
    #defining that there is a mandatory input of a hashtable for this fucntion
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$table
    )
    #loop through the keys IE "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    foreach ($key in $table.Keys) {
        #catch any errors in the test path process
        try {
        # Check if the registry key exists
            $keyExists = Test-Path $key
        }
        catch {
            Write-Error "Failed to check if registry key '$key' exists: $_"
            continue
        }
        if (!$keyExists) {
            try {
                # Create the key if it doesn't exist
                New-Item -Path $key -Force | Out-Null
                Write-Host "Created new registry key: $key"
            }
            catch {
                Write-Error "Failed to create registry key '$key': $_"
                continue
            }
        }

        #loop through the values in each key IE "SetDisablePauseUXAccess" = 1
        $values = $table[$key]

        foreach ($valueName in $values.Keys) {
            try {
                $value = $values[$valueName]

                # Determine the value type
                if ($value -is [string]) {
                    $type = "String"
                } else {
                    $type = "DWord"
                }

                # Set the registry value
                Set-ItemProperty -Path $key -Name $valueName -Value $value -Type $type
                Write-Host "Set value '$valueName' to '$value' (Type: $type) in key: $key"
            }
            catch {
                Write-Error "Failed to set value '$valueName' in key '$key'"
            }
        }
    }
}
Set-RegistryKeys -Table $SectionNG
Write-Host "All registry settings applied"