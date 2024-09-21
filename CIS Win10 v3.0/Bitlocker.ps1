$SectionBitlocker = @{
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" = @{
        "DenyDeviceIDs" = 1
        "DenyDeviceIDsRetroactive" = 1
        "DenyDeviceClasses" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs" = @{
        "1" = "PCI\CC_0C0A"
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses" = @{
        "1" = "{d48179be-ec20-11d1-b6b8-00c04fa372a7}"
        "2" = "{7ebefbc0-3200-11d2-b4c2-00a0C9697d07}"
        "3" = "{c06ff265-ae09-48f0-812c-16753d7cba83}"
        "4" = "{6bdd1fc1-810f-11d0-bec7-08002be2092f}"
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" = @{
        "DeviceEnumerationPolicy" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" = @{
        "DCSettingIndex" = 0
        "ACSettingIndex" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\FVE" = @{
        "FDVDiscoveryVolumeType" = ""
        "FDVRecovery" = 1
        "FDVManageDRA" = 1
        "FDVRecoveryPassword" = 2
        "FDVRecoveryKey" = 2
        "FDVHideRecoveryPage" = 1
        "FDVActiveDirectoryBackup" = 0
        "FDVActiveDirectoryInfoToStore" = 1
        "FDVRequireActiveDirectoryBackup" = 0
        "FDVHardwareEncryption" = 0
        "FDVPassphrase" = 0
        "FDVAllowUserCert" = 1
        "FDVEnforceUserCert" = 1
        "UseEnhancedPin" = 1
        "OSAllowSecureBootForIntegrity" = 1
        "OSRecovery" = 1
        "OSManageDRA" = 0
        "OSRecoveryPassword" = 1
        "OSRecoveryKey" = 0
        "OSHideRecoveryPage" = 1
        "OSActiveDirectoryBackup" = 1
        "OSActiveDirectoryInfoToStore" = 1
        "OSRequireActiveDirectoryBackup" = 1
        "OSHardwareEncryption" = 0
        "OSPassphrase" = 0
        "UseAdvancedStartup" = 1
        "EnableBDEWithNoTPM" = 0
        "RDVDiscoveryVolumeType" = ""
        "RDVRecovery" = 1
        "RDVManageDRA" = 1
        "RDVRecoveryPassword" = 0
        "RDVRecoveryKey" = 0
        "RDVHideRecoveryPage" = 1
        "RDVActiveDirectoryBackup" = 0
        "RDVActiveDirectoryInfoToStore" = 1
        "RDVRequireActiveDirectoryBackup" = 0
        "RDVHardwareEncryption" = 0
        "RDVPassphrase" = 0
        "RDVAllowUserCert" = 1
        "RDVEnforceUserCert" = 1
        "RDVDenyCrossOrg" = 0
        "DisableExternalDMAUnderLock" = 1
    }
    "HKLM\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE" = @{
        "RDVDenyWriteAccess" = 1
    }
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{
        "MaxDevicePasswordFailedAttempts" = 10
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
Set-RegistryKeys -Table $SectionBitlocker
Write-Host "All registry settings applied"