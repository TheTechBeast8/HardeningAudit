$SectionBitlocker = @{
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses" = @{
        "1" = "{6bdd1fc1-810f-11d0-bec7-08002be2092f}"
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs" = @{
        "1" = "PCI\CC_0C0A"
    }
    "HKLM\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE" = @{
        "RDVDenyWriteAccess" = 1
    }
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{
        "MaxDevicePasswordFailedAttempts" = 10
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" = @{
        "DenyDeviceIDs" = 1
        "DenyDeviceClasses" = 1
        "DenyDeviceIDsRetroactive" = 1
        "DenyDeviceClassesRetroactive" = "{7ebefbc0-3200-11d2-b4c2-00a0C9697d07}, {c06ff265-ae09-48f0-812c-16753d7cba83}, {6bdd1fc1-810f-11d0-bec7-08002be2092f}"
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" = @{
        "ACSettingIndex" = 0
        "DCSettingIndex" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\FVE" = @{
        "FDVRequireActiveDirectoryBackup" = 0
        "RDVDenyCrossOrg" = 0
        "OSRecoveryKey" = 0
        "RDVRequireActiveDirectoryBackup" = 0
        "RDVEnforceUserCert" = 1
        "UseTPM" = 0
        "FDVActiveDirectoryInfoToStore" = 1
        "FDVAllowUserCert" = 1
        "FDVDiscoveryVolumeType" = ""
        "OSRecovery" = 1
        "FDVRecovery" = 1
        "FDVEnforceUserCert" = 1
        "FDVHideRecoveryPage" = 1
        "FDVManageDRA" = 1
        "FDVRecoveryPassword" = 2
        "RDVActiveDirectoryBackup" = 0
        "FDVActiveDirectoryBackup" = 0
        "FDVRecoveryKey" = 2
        "RDVHardwareEncryption" = 0
        "OSPassphrase" = 0
        "RDVRecoveryKey" = 0
        "RDVPassphrase" = 0
        "OSManageDRA" = 0
        "EnableBDEWithNoTPM" = 0
        "OSHardwareEncryption" = 0
        "UseTPMKey" = 1
        "RDVAllowUserCert" = 1
        "OSActiveDirectoryBackup" = 1
        "OSAllowSecureBootForIntegrity" = 1
        "UseTPMKeyPIN" = 0
        "RDVManageDRA" = 1
        "RDVDiscoveryVolumeType" = ""
        "UseTPMPIN" = 1
        "UseEnhancedPin" = 1
        "FDVHardwareEncryption" = 0
        "RDVRecoveryPassword" = 0
        "RDVRecovery" = 1
        "DisableExternalDMAUnderLock" = 1
        "RDVHideRecoveryPage" = 1
        "FDVPassphrase" = 0
        "RDVActiveDirectoryInfoToStore" = 1
        "UseAdvancedStartup" = 1
        "OSActiveDirectoryInfoToStore" = 1
        "OSHideRecoveryPage" = 1
        "OSRequireActiveDirectoryBackup" = 1
        "OSRecoveryPassword" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" = @{
        "DeviceEnumerationPolicy" = 0
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
Set-RegistryKeys -Table $SectionBitlocker
Write-Host "All registry settings applied"