$L1Section1 = @{
    "HKLM\System\CurrentControlSet\Control\SAM" = @{
        "RelaxMinimumPasswordLengthLimits" = 1
    }
}
$L1Section2 = @{
    "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\pku2u" = @{
        "AllowOnlineID" = 0
    }
    "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" = @{
        "ObCaseInsensitive" = 1
    }
    "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths" = @{
        "Machine" = "System\CurrentControlSet\Control\ProductOptions, System\CurrentControlSet\Control\Server Applications, Software\Microsoft\Windows NT\CurrentVersion"
    }
    "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" = @{
        "PasswordExpiryWarning" = 14
        "ScRemoveOption" = 1
    }
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" = @{
        "SupportedEncryptionTypes" = 2147483640
    }
    "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" = @{
        "ForceGuest" = 0
        "RestrictAnonymousSAM" = 1
        "RestrictAnonymous" = 1
        "EveryoneIncludesAnonymous" = 0
        "LmCompatibilityLevel" = 5
        "DisableDomainCreds" = 1
        "restrictremotesam" = "O:BAG:BAD:(A;;RC;;;BA)"
        "CrashOnAuditFail" = 0
        "LimitBlankPasswordUse" = 1
        "UseMachineId" = 1
        "NoLMHash" = 1
        "SCENoApplyLegacyAuditPolicy" = 1
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" = @{
        "LDAPClientIntegrity" = 1
    }
    "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" = @{
        "AllowNullSessionFallback" = 0
        "NTLMMinServerSec" = 537395200
        "NTLMMinClientSec" = 537395200
        "AuditReceivingNTLMTraffic" = 2
        "RestrictSendingNTLMTraffic" = 1
    }
    "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" = @{
        "ProtectionMode" = 1
    }
    "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths" = @{
        "Machine" = " System\CurrentControlSet\Control\Print\Printers, System\CurrentControlSet\Services\Eventlog, Software\Microsoft\OLAP Server, Software\Microsoft\Windows NT\CurrentVersion\Print, Software\Microsoft\Windows NT\Curre
ntVersion\Windows, System\CurrentControlSet\Control\ContentIndex, System\CurrentControlSet\Control\Terminal Server, System\CurrentControlSet\Control\Terminal Server\UserConfig, System\CurrentControlSet\Control\Terminal Server\DefaultU
serConfiguration, Software\Microsoft\Windows NT\CurrentVersion\Perflib, System\CurrentControlSet\Services\SysmonLog"
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" = @{
        "EnablePlainTextPassword" = 0
        "EnableSecuritySignature" = 1
        "RequireSecuritySignature" = 1
    }
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{
        "LegalNoticeText" = "Sample Text"
        "NoConnectedUser" = 3
        "PromptOnSecureDesktop" = 1
        "ConsentPromptBehaviorAdmin" = 1
        "DisableCAD" = 0
        "FilterAdministratorToken" = 1
        "EnableInstallerDetection" = 1
        "EnableLUA" = 1
        "DontDisplayLastUserName" = 1
        "LegalNoticeCaption" = "Sample Text"
        "ConsentPromptBehaviorUser" = 0
        "EnableVirtualization" = 1
        "EnableSecureUIAPaths" = 1
        "InactivityTimeoutSecs" = 900
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" = @{
        "SMBServerNameHardeningLevel" = 1
        "NullSessionShares" = ""
        "NullSessionPipes" = ""
        "RestrictNullSessAccess" = 1
        "RequireSecuritySignature" = 1
        "enableforcedlogoff" = 1
        "EnableSecuritySignature" = 1
        "AutoDisconnect" = 15
    }
}
$L1Section5 = @{
    "HKLM\SYSTEM\CurrentControlSet\Services\RpcLocator" = @{
        "Start" = 4
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\simptcp" = @{
        "Start" = 4
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" = @{
        "Start" = 4
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC" = @{
        "Start" = 4
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\SSDPSRV" = @{
        "Start" = 4
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\upnphost" = @{
        "Start" = 4
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc" = @{
        "Start" = 4
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\irmon" = @{
        "Start" = 4
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\sshd" = @{
        "Start" = 4
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\sacsvr" = @{
        "Start" = 4
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\Browser" = @{
        "Start" = 4
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\IISADMIN" = @{
        "Start" = 4
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" = @{
        "Start" = 4
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\FTPSVC" = @{
        "Start" = 4
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\icssvc" = @{
        "Start" = 4
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\WMSvc" = @{
        "Start" = 4
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\LxssManager" = @{
        "Start" = 4
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager" = @{
        "Start" = 4
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave" = @{
        "Start" = 4
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess" = @{
        "Start" = 4
    }
}
$L1Section9 = @{
    "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" = @{
        "DisableNotifications" = 1
        "EnableFirewall" = 1
        "AllowLocalIPsecPolicyMerge" = 0
        "DefaultInboundAction" = 1
        "AllowLocalPolicyMerge" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" = @{
        "LogFileSize" = 40000
        "LogDroppedPackets" = 1
        "LogSuccessfulConnections" = 1
        "LogFilePath" = "%SystemRoot%\System32\logfiles\firewall\privatefw.log"
    }
    "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" = @{
        "LogFileSize" = 40000
        "LogDroppedPackets" = 1
        "LogSuccessfulConnections" = 1
        "LogFilePath" = "%SystemRoot%\System32\logfiles\firewall\publicfw.log"
    }
    "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" = @{
        "DisableNotifications" = 1
        "EnableFirewall" = 1
        "DefaultInboundAction" = 1
    }
}
$L1Section18 = @{
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" = @{
        "EnumerateAdministrators" = 0
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" = @{
        "DisableIPSourceRouting" = 0
    }
    "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" = @{
        "SafeDllSearchMode" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftAccount" = @{
        "DisableUserAuth" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" = @{
        "RpcProtocols" = 5
        "ForceKerberosForRpc" = 0
        "RpcAuthentication" = 0
        "RpcTcpPort" = 0
        "RpcUseNamedPipeProtocol" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" = @{
        "Retention" = 0
        "MaxSize" = 500000
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" = @{
        "Start" = 4
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" = @{
        "AllowBuildPreview" = 0
    }
    "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" = @{
        "ScreenSaverGracePeriod" = 5
        "AutoAdminLogon" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" = @{
        "DisableFileSyncNGSC" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" = @{
        "Enabled" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" = @{
        "DisableAntiSpyware" = 0
        "PUAProtection" = 1
    }
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" = @{
        "AllowEncryptionOracle" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" = @{
        "HypervisorEnforcedCodeIntegrity" = 1
        "LsaCfgFlags" = 1
        "RequirePlatformSecurityFeatures" = 3
        "HVCIMATRequired" = 1
        "ConfigureSystemGuardLaunch" = 1
        "ConfigureKernelShadowStacksLaunch" = 1
        "EnableVirtualizationBasedSecurity" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" = @{
        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = 1
        "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = 1
        "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = 1
        "e6db77e5-3df2-4cf1-b95a-636979351e5b" = 1
        "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = 1
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = 1
        "56a863a9-875e-4185-98a7-b882c64b5ce5" = 1
        "3b576869-a4ec-4529-8536-b80a7769e899" = 1
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = 1
        "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = 1
        "26190899-1602-49e8-8b27-eb1d0a1ce869" = 1
        "d3e037e1-3eb8-44c8-a917-57927947596d" = 1
        "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" = @{
        "ACSettingIndex" = 1
        "DCSettingIndex" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" = @{
        "AllowDigest" = 0
        "AllowUnencryptedTraffic" = 0
        "AllowBasic" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" = @{
        "AlwaysInstallElevated" = 0
        "EnableUserControl" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" = @{
        "LetAppsActivateWithVoiceAboveLock" = 2
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" = @{
        "EnableMSAppInstallerProtocol" = 0
        "EnableHashOverride" = 0
        "EnableExperimentalFeatures" = 0
        "EnableAppInstaller" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" = @{
        "Retention" = 0
        "MaxSize" = 500000
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" = @{
        "NoLockScreenCamera" = 1
        "NoLockScreenSlideshow" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" = @{
        "EnableFileHashComputation" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" = @{
        "AllowProtectedCreds" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" = @{
        "RestrictRemoteClients" = 1
        "EnableAuthEpResolution" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" = @{
        "AllowInputPersonalization" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" = @{
        "LimitDumpCollection" = 1
        "LimitDiagnosticLogCollection" = 1
        "EnableOneSettingsAuditing" = 1
        "AllowTelemetry" = 1
        "DoNotShowFeedbackNotifications" = 1
        "DisableOneSettingsDownloads" = 1
    }
    "HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" = @{
        "DriverLoadPolicy" = 3
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" = @{
        "ExploitGuard_ASR_Rules" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" = @{
        "DisableRunAs" = 1
        "AllowUnencryptedTraffic" = 0
        "AllowBasic" = 0
    }
    "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" = @{
        "RunAsPPL" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" = @{
        "NoUseStoreOpenWith" = 1
        "NoAutoplayfornonVolume" = 1
        "NoHeapTerminationOnCorruption" = 0
        "NoDataExecutionPrevention" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\windows Defender\Windows Defender Exploit Guard\Network Protection" = @{
        "EnableNetworkProtection" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" = @{
        "\\*\SYSVOL" = "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1"
        "\\*\NETLOGON" = "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1"
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" = @{
        "AllowCortanaAboveLock" = 0
        "AllowIndexingEncryptedStoresOrItems" = 0
        "AllowCortana" = 0
        "AllowSearchToUseLocation" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" = @{
        "DoHPolicy" = 2
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" = @{
        "AllowTemporaryEnterpriseFeatureControl" = 0
        "SetDisablePauseUXAccess" = 1
        "DeferQualityUpdates" = 1
        "DeferQualityUpdatesPeriodInDays" = 0
        "DeferFeatureUpdatesPeriodInDays" = 180
        "ManagePreviewBuildsPolicyValue" = 1
        "DeferFeatureUpdates" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI" = @{
        "DisablePasswordReveal" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" = @{
        "fAllowToGetHelp" = 0
        "fAllowUnsolicited" = 0
        "UserAuthentication" = 1
        "fPromptForPassword" = 1
        "MinEncryptionLevel" = 3
        "fEncryptRPCTraffic" = 1
        "DeleteTempDirsOnExit" = 1
        "DisablePasswordSaving" = 1
        "SecurityLayer" = 2
        "fDisableCdm" = 1
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" = @{
        "SMB1" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" = @{
        "LocalSettingOverrideSpynetReporting" = 0
    }
    "HKLM\SOFTWARE\Microsoft\Cryptography\Wintrust\Config" = @{
        "EnableCertPaddingCheck" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" = @{
        "ACSettingIndex" = 0
        "DCSettingIndex" = 0
    }
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{
        "DisableAutomaticRestartSignOn" = 1
        "EnableMPR" = 0
        "MSAOptional" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" = @{
        "DisableEnclosureDownload" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" = @{
        "Retention" = 0
        "MaxSize" = 500000
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" = @{
        "fMinimizeConnections" = 3
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" = @{
        "DisableConsumerAccountStateContent" = 1
        "DisableWindowsConsumerFeatures" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" = @{
        "EnhancedAntiSpoofing" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Dsh" = @{
        "AllowNewsAndInterests" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect" = @{
        "RequirePinForPairing" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" = @{
        "CaptureThreatWindow" = 1
        "NotifyPasswordReuse" = 1
        "NotifyMalicious" = 1
        "ServiceEnabled" = 1
        "NotifyUnsafeApp" = 1
    }
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" = @{
        "ProcessCreationIncludeCmdLine_Enabled" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" = @{
        "AllowGameDVR" = 1
    }
    "HKLM\SYSTEM\CurrentControlSet\Control\Print" = @{
        "RpcAuthnLevelPrivacyEnabled" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" = @{
        "DisablePackedExeScanning" = 0
        "DisableEmailScanning" = 0
        "DisableRemovableDriveScanning" = 0
    }
    "HKLM\SOFTWARE\Microsoft\Policies\PassportForWork\Biometrics" = @{
        "EnableESSwithSupportedPeripherals" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" = @{
        "ScheduledInstallDay" = 0
        "NoAutoUpdate" = 0
        "NoAutoRebootWithLoggedOnUsers" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\AppHVSI" = @{
        "AuditApplicationGuard" = 1
        "AllowCameraMicrophoneRedirection" = 0
        "AppHVSIClipboardSettings" = 1
        "AllowPersistence" = 0
        "AllowAppHVSI_ProviderSet" = 1
        "SaveFilesToHost" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" = @{
        "PreventDeviceMetadataFromNetwork" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\Sandbox" = @{
        "AllowClipboardRedirection" = 0
        "AllowNetworking" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" = @{
        "Retention" = 0
        "MaxSize" = 500000
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" = @{
        "AllowInsecureGuestAuth" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" = @{
        "DODownloadMode" = 1
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" = @{
        "NoNameReleaseOnDemand" = 1
        "NodeType" = 2
    }
    "HKLM\Software\Policies\Microsoft\Windows NT\Printers" = @{
        "DisableWebPnPDownload" = 1
        "CopyFilesPolicy" = 1
        "RegisterSpoolerRemoteRpcEndPoint" = 2
        "RedirectionguardPolicy" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" = @{
        "AllowWindowsInkWorkspace" = 0
    }
    "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" = @{
        "UseLogonCredential" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" = @{
        "NC_AllowNetBridge_NLA" = 0
        "NC_ShowSharedAccessUI" = 0
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security" = @{
        "WarningLevel" = 90
    }
    "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" = @{
        "AutoConnectAllowedOEM" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx" = @{
        "BlockNonAdminUserInstall" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" = @{
        "DisableIOAVProtection" = 0
        "DisableScriptScanning" = 0
        "DisableRealtimeMonitoring" = 0
        "DisableBehaviorMonitoring" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" = @{
        "NoLocalPasswordResetQuestions" = 1
        "EnableSmartScreen" = 1
        "DisableLockScreenAppNotifications" = 1
        "EnableCdp" = 0
        "AllowDomainPINLogon" = 0
        "BlockUserFromShowingAccountDetailsOnSignin" = 1
        "DontDisplayNetworkSelectionUI" = 1
        "AllowCustomSSPsAPs" = 0
        "ShellSmartScreenLevel" = 1
    }
    "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" = @{
        "DisableExceptionChainValidation" = 0
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" = @{
        "EnableICMPRedirect" = 0
        "DisableIPSourceRouting" = 2
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" = @{
        "DisallowExploitProtectionOverride" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" = @{
        "RequirePrivateStoreOnly" = 1
        "DisableOSUpgrade" = 1
        "AutoDownload" = 4
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" = @{
        "UpdatePromptSettings" = 0
        "NoWarningNoElevationOnInstall" = 0
        "RestrictDriverInstallationToAdministrators" = 1
    }
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" = @{
        "NoWebServices" = 1
        "PreXPSP2ShellProtocolBehavior" = 0
        "NoAutorun" = 1
        "NoDriveTypeAutoRun" = 255
    }
}
$L1Section19 = @{
    "HKU\[USER SID]\Software\Policies\Microsoft\Windows\Installer" = @{
        "AlwaysInstallElevated" = 0
    }
    "HKU\[USER SID]\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" = @{
        "SaveZoneInformation" = 2
        "ScanWithAntiVirus" = 3
    }
    "HKU\[USER SID]\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" = @{
        "TurnOffWindowsCopilot" = 1
    }
    "HKU\[USER SID]\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" = @{
        "NoToastApplicationNotificationOnLockScreen" = 1
    }
    "HKU\[USER SID]\Software\Policies\Microsoft\Windows\CloudContent" = @{
        "ConfigureWindowsSpotlight" = 2
        "DisableThirdPartySuggestions" = 1
        "DisableSpotlightCollectionOnDesktop" = 1
    }
    "HKU\[USER SID]\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" = @{
        "NoInplaceSharing" = 1
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
function Set-UserRegistryKeys {
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$Table
    )

    # Get all user SIDs from HKEY_USERS except system SIDs
    $userSIDs = Get-ChildItem -Path "Registry::HKEY_USERS" | Where-Object {
        $_.PSChildName -notmatch '^(S-1-5-18|S-1-5-19|S-1-5-20|\.DEFAULT)$'
    }

    foreach ($sid in $userSIDs) {
        foreach ($key in $Table.Keys) {
            # Replace the placeholder [USER SID] with the actual user SID
            $userKey = $key -replace '\[USER SID\]', $sid.PSChildName
            $userKey = "Registry::$userKey"  # Ensure we're using the Registry provider

            if (!(Test-Path $userKey)) {
                try {
                    New-Item -Path $userKey -Force | Out-Null
                }
                catch {
                    Write-Error "Failed to create registry key '$userKey': $_"
                    continue
                }
            }

            $values = $Table[$key]
            foreach ($valueName in $values.Keys) {
                $value = $values[$valueName]
                try {
                    $type = if ($value -is [int]) { "DWord" } else { "String" }
                    Set-ItemProperty -Path $userKey -Name $valueName -Value $value -Type $type
                }
                catch {
                    Write-Error "Failed to set value '$valueName' in key '$userKey': $_"
                }
            }
        }
    }
}
Set-RegistryKeys -Table $L1Section1
Set-RegistryKeys -Table $L1Section2
Set-RegistryKeys -Table $L1Section5
Set-RegistryKeys -Table $L1Section9
Set-RegistryKeys -Table $L1Section18
Set-UserRegistryKeys -Table $L1Section19
Write-Host "All registry settings applied"