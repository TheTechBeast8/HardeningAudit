$L1Section2MS = @{
    "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" = @{
        "ForceUnlockLogon" = 1
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" = @{
        "SMBServerNameHardeningLevel" = 1
        "NullSessionPipes" = 0
    }
    "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" = @{
        "RestrictAnonymousSAM" = 1
        "RestrictAnonymous" = 1
        "restrictremotesam" = "O:BAG:BAD:(A;;RC;;;BA)"
    }
}
$L1Section2DC = @{
    "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" = @{
        "SubmitControl" = 0
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" = @{
        "VulnerableChannelAllowList" = "does not exist"
        "RefusePasswordChange" = 0
        "AuditNTLMInDomain" = 7
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" = @{
        "LdapEnforceChannelBinding" = 2
        "LDAPServerIntegrity" = 2
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" = @{
        "NullSessionPipes" = "LSARPC, NETLOGON, SAMR"
    }
}
$L1Section2MSDC = @{
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{
        "NoConnectedUser" = 3
        "DisableCAD" = 0
        "DontDisplayLastUserName" = 1
        "InactivityTimeoutSecs" = 900
        "LegalNoticeText" = "Sample Text"
        "LegalNoticeCaption" = "Sample Text"
        "ShutdownWithoutLogon" = 0
        "FilterAdministratorToken" = 1
        "ConsentPromptBehaviorAdmin" = 1
        "ConsentPromptBehaviorUser" = 0
        "EnableInstallerDetection" = 1
        "EnableSecureUIAPaths" = 1
        "EnableLUA" = 1
        "PromptOnSecureDesktop" = 1
        "EnableVirtualization" = 1
    }
    "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" = @{
        "LimitBlankPasswordUse" = 1
        "SCENoApplyLegacyAuditPolicy" = 1
        "CrashOnAuditFail" = 0
        "TurnOffAnonymousBlock" = 1
        "EveryoneIncludesAnonymous" = 0
        "ForceGuest" = 0
        "UseMachineId" = 1
        "NoLMHash" = 1
        "LmCompatibilityLevel" = 5
    }
    "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" = @{
        "AddPrinterDrivers" = 1
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" = @{
        "RequireSignOrSeal" = 1
        "SealSecureChannel" = 1
        "SignSecureChannel" = 1
        "DisablePasswordChange" = 0
        "MaximumPasswordAge" = 30
        "RequireStrongKey" = 1
    }
    "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" = @{
        "PasswordExpiryWarning" = 14
        "ScRemoveOption" = 3
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" = @{
        "RequireSecuritySignature" = 1
        "EnableSecuritySignature" = 1
        "EnablePlainTextPassword" = 0
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" = @{
        "AutoDisconnect" = 15
        "RequireSecuritySignature" = 1
        "EnableSecuritySignature" = 1
        "enableforcedlogoff" = 1
        "RestrictNullSessAccess" = 1
        "NullSessionShares" = "<none>"
    }
    "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths" = @{
        "Machine" = "System\CurrentControlSet\Control\ProductOptions System\CurrentControlSet\C
ontrol\Server Applications Software\Microsoft\Windows NT\CurrentVersion"
    }
    "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths" = @{
        "Machine" = "System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\S
ervices\Eventlog,Software\Microsoft\OLAP Server,Software\Microsoft\Windows NT\CurrentVersion\Pr
int,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\Conte
ntIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Termi
nal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration
,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonL
og,System\CurrentControlSet\Services\CertSvc,System\CurrentControlSet\Services\WINS"
    }
    "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" = @{
        "AllowNullSessionFallback" = 0
        "NTLMMinClientSec" = 537395200
        "NTLMMinServerSec" = 537395200
        "AuditReceivingNTLMTraffic" = 2
        "RestrictSendingNTLMTraffic" = 2
    }
    "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\pku2u" = @{
        "AllowOnlineID" = 0
    }
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" = @{
        "SupportedEncryptionTypes" = 2147483640
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" = @{
        "LDAPClientIntegrity" = 1
    }
    "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" = @{
        "ObCaseInsensitive" = 1
    }
    "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" = @{
        "ProtectionMode" = 1
    }
}
$L1Section5DC = @{
    "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" = @{
        "Start" = 4
    }
}
$L1Section9MSDC = @{
    "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" = @{
        "EnableFirewall" = 1
        "DefaultInboundAction" = 1
        "DisableNotifications" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" = @{
        "LogFilePath" = "%SystemRoot%\System32\logfiles\firewall\domainfw.log"
        "LogFileSize" = 16384
        "LogDroppedPackets" = 1
        "LogSuccessfulConnections" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" = @{
        "EnableFirewall" = 1
        "DefaultInboundAction" = 1
        "DisableNotifications" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" = @{
        "LogFilePath" = "%SystemRoot%\System32\logfiles\firewall\privatefw.log"
        "LogFileSize" = 16384
        "LogDroppedPackets" = 1
        "LogSuccessfulConnections" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" = @{
        "EnableFirewall" = 1
        "DefaultInboundAction" = 1
        "DisableNotifications" = 1
        "AllowLocalPolicyMerge" = 0
        "AllowLocalIPsecPolicyMerge" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" = @{
        "LogFilePath" = "%SystemRoot%\System32\logfiles\firewall\publicfw.log"
        "LogFileSize" = 16384
        "LogDroppedPackets" = 1
        "LogSuccessfulConnections" = 1
    }
}
$L1Section18MS = @{
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{
        "LocalAccountTokenFilterPolicy" = 0
    }
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" = @{
        "BackupDirectory" = 1
        "PwdExpirationProtectionEnabled" = 1
        "ADPasswordEncryptionEnabled" = 1
        "PasswordComplexity" = 4
        "PasswordLength" = 15
        "PasswordAgeDays" = 30
        "PostAuthenticationResetDelay" = 8
        "PostAuthenticationActions" = 3
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" = @{
        "EnumerateLocalUsers" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" = @{
        "EnableAuthEpResolution" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer" = @{
        "Enabled" = 0
    }
}
$L1Section18DC = @{
    "HKLM\Software\Policies\Microsoft\Windows NT\Printers" = @{
        "RegisterSpoolerRemoteRpcEndPoint" = 2
    }
}
$L1Section18MSDC = @{
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" = @{
        "NoLockScreenCamera" = 1
        "NoLockScreenSlideshow" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" = @{
        "AllowInputPersonalization" = 0
    }
    "HKLM\SYSTEM\CurrentControlSet\Control\Print" = @{
        "RpcAuthnLevelPrivacyEnabled" = 1
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" = @{
        "Start" = 4
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" = @{
        "SMB1" = 0
    }
    "HKLM\SOFTWARE\Microsoft\Cryptography\Wintrust\Config" = @{
        "EnableCertPaddingCheck" = 1
    }
    "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" = @{
        "DisableExceptionChainValidation" = 0
    }
    "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" = @{
        "RunAsPPL" = 1
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" = @{
        "NodeType" = 2
        "NoNameReleaseOnDemand" = 1
    }
    "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" = @{
        "UseLogonCredential" = 0
    }
    "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" = @{
        "AutoAdminLogon" = 0
        "ScreenSaverGracePeriod" = 5
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" = @{
        "DisableIPSourceRouting" = 2
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" = @{
        "DisableIPSourceRouting" = 2
        "EnableICMPRedirect" = 0
    }
    "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" = @{
        "SafeDllSearchMode" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" = @{
        "EnableNetbios" = 0
        "EnableMulticast" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" = @{
        "AllowInsecureGuestAuth" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" = @{
        "NC_AllowNetBridge_NLA" = 0
        "NC_ShowSharedAccessUI" = 0
        "NC_StdDomainUserSetLocation" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" = @{
        "\\*\NETLOGON" = "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1"
        "\\*\SYSVOL" = "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1"
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" = @{
        "fMinimizeConnections" = 3
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" = @{
        "RedirectionguardPolicy" = 1
        "CopyFilesPolicy" = 1
        "DisableWebPnPDownload" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" = @{
        "RpcUseNamedPipeProtocol" = 0
        "RpcAuthentication" = 0
        "RpcProtocols" = 5
        "ForceKerberosForRpc" = 0
        "RpcTcpPort" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" = @{
        "RestrictDriverInstallationToAdministrators" = 1
        "NoWarningNoElevationOnInstall" = 0
        "UpdatePromptSettings" = 0
    }
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" = @{
        "ProcessCreationIncludeCmdLine_Enabled" = 1
    }
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" = @{
        "AllowEncryptionOracle" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" = @{
        "AllowProtectedCreds" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" = @{
        "PreventDeviceMetadataFromNetwork" = 1
    }
    "HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" = @{
        "DriverLoadPolicy" = 3
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA
2}" = @{
        "NoBackgroundPolicy" = 0
        "NoGPOListChanges" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83
A}" = @{
        "NoBackgroundPolicy" = 0
        "NoGPOListChanges" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" = @{
        "EnableCdp" = 0
        "BlockUserFromShowingAccountDetailsOnSignin" = 1
        "DontDisplayNetworkSelectionUI" = 1
        "DontEnumerateConnectedUsers" = 1
        "DisableLockScreenAppNotifications" = 1
        "BlockDomainPicturePassword" = 1
        "AllowDomainPINLogon" = 0
        "EnableSmartScreen" = 1
        "ShellSmartScreenLevel" = "Block"
    }
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{
        "DisableBkGndGroupPolicy" = "does not exist"
        "MSAOptional" = 1
        "DisableAutomaticRestartSignOn" = 1
    }
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" = @{
        "NoWebServices" = 1
        "NoAutorun" = 1
        "NoDriveTypeAutoRun" = 255
        "PreXPSP2ShellProtocolBehavior" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" = @{
        "DeviceEnumerationPolicy" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" = @{
        "DCSettingIndex" = 1
        "ACSettingIndex" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" = @{
        "fAllowUnsolicited" = 0
        "fAllowToGetHelp" = 0
        "DisablePasswordSaving" = 1
        "fDisableCdm" = 1
        "fPromptForPassword" = 1
        "fEncryptRPCTraffic" = 1
        "SecurityLayer" = 2
        "UserAuthentication" = 1
        "MinEncryptionLevel" = 3
        "DeleteTempDirsOnExit" = 1
        "PerSessionTempDir" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" = @{
        "Enabled" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" = @{
        "NoAutoplayfornonVolume" = 1
        "NoDataExecutionPrevention" = 0
        "NoHeapTerminationOnCorruption" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" = @{
        "EnhancedAntiSpoofing" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" = @{
        "DisableConsumerAccountStateContent" = 1
        "DisableWindowsConsumerFeatures" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect" = @{
        "RequirePinForPairing" = 2
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI" = @{
        "DisablePasswordReveal" = 1
    }
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" = @{
        "EnumerateAdministrators" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" = @{
        "AllowTelemetry" = 1
        "DisableOneSettingsDownloads" = 1
        "DoNotShowFeedbackNotifications" = 1
        "EnableOneSettingsAuditing" = 1
        "LimitDiagnosticLogCollection" = 1
        "LimitDumpCollection" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" = @{
        "AllowBuildPreview" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" = @{
        "EnableAppInstaller" = 0
        "EnableExperimentalFeatures" = 0
        "EnableHashOverride" = 0
        "EnableMSAppInstallerProtocol" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" = @{
        "Retention" = 0
        "MaxSize" = 32768
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" = @{
        "Retention" = 0
        "MaxSize" = 196608
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" = @{
        "Retention" = 0
        "MaxSize" = 32768
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" = @{
        "Retention" = 0
        "MaxSize" = 32768
    }
    "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftAccount" = @{
        "DisableUserAuth" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" = @{
        "LocalSettingOverrideSpynetReporting" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" = @{

        "ExploitGuard_ASR_Rules" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules
" = @{
        "26190899-1602-49e8-8b27-eb1d0a1ce869" = 1
        "3b576869-a4ec-4529-8536-b80a7769e899" = 1
        "56a863a9-875e-4185-98a7-b882c64b5ce5" = 1
        "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = 1
        "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = 1
        "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = 1
        "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = 1
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = 1
        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = 1
        "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = 1
        "d3e037e1-3eb8-44c8-a917-57927947596d" = 1
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = 1
        "e6db77e5-3df2-4cf1-b95a-636979351e5b" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network P
rotection" = @{
        "EnableNetworkProtection" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" = @{
        "EnableFileHashComputation" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" = @{
        "DisableIOAVProtection" = 0
        "DisableRealtimeMonitoring" = 0
        "DisableBehaviorMonitoring" = 0
        "DisableScriptScanning" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" = @{
        "DisablePackedExeScanning" = 0
        "DisableRemovableDriveScanning" = 0
        "DisableEmailScanning" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" = @{
        "PUAProtection" = 1
        "DisableAntiSpyware" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" = @{
        "DisableFileSyncNGSC" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" = @{
        "DisableEnclosureDownload" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" = @{
        "AllowIndexingEncryptedStoresOrItems" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" = @{
        "AllowWindowsInkWorkspace" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" = @{
        "EnableUserControl" = 0
        "AlwaysInstallElevated" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" = @{
        "AllowBasic" = 0
        "AllowUnencryptedTraffic" = 0
        "AllowDigest" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" = @{
        "AllowBasic" = 0
        "AllowUnencryptedTraffic" = 0
        "DisableRunAs" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protecti
on" = @{
        "DisallowExploitProtectionOverride" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" = @{
        "NoAutoRebootWithLoggedOnUsers" = 0
        "NoAutoUpdate" = 0
        "ScheduledInstallDay" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" = @{
        "ManagePreviewBuildsPolicyValue" = 1
        "DeferFeatureUpdates" = 1
        "DeferFeatureUpdatesPeriodInDays" = 180
        "DeferQualityUpdates" = 1
        "DeferQualityUpdatesPeriodInDays" = 0
    }
}
$L1Section19MSDC = @{
    "HKU\[USER SID]\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" = @{
        "NoToastApplicationNotificationOnLockScreen" = 1
    }
    "HKU\[USER SID]\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" = @{
        "SaveZoneInformation" = 2
        "ScanWithAntiVirus" = 3
    }
    "HKU\[USER SID]\Software\Policies\Microsoft\Windows\CloudContent" = @{
        "ConfigureWindowsSpotlight" = 2
        "DisableThirdPartySuggestions" = 1
        "DisableSpotlightCollectionOnDesktop" = 0
    }
    "HKU\[USER SID]\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" = @{
        "NoInplaceSharing" = 1
    }
    "HKU\[USER SID]\Software\Policies\Microsoft\Windows\Installer" = @{
        "AlwaysInstallElevated" = 0
    }
}
$L2Section2MS = @{
    "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" = @{
        "CachedLogonsCount" = 2
    }
}
$L2Section2MSDC = @{
    "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" = @{
        "DisableDomainCreds" = 1
    }
}
$L2Section5MS = @{
    "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" = @{
        "Start" = 4
    }
}
$L2Section18MS = @{
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" = @{
        "fBlockNonDomain" = 1
    }
    "HKLM\Software\Policies\Microsoft\Windows NT\Printers" = @{
        "RegisterSpoolerRemoteRpcEndPoint" = 2
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" = @{
        "RestrictRemoteClients" = 1
    }
}
$L2Section18MSDC = @{
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" = @{
        "AllowOnlineTips" = 0
        "NoOnlinePrintsWizard" = 1
        "NoPublishingWizard" = 1
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" = @{
        "KeepAliveTime" = 300000
        "PerformRouterDiscovery" = 0
        "TcpMaxDataRetransmissions" = 3
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" = @{
        "TcpMaxDataRetransmissions" = 3
        "DisabledComponents" = 255
    }
    "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security" = @{
        "WarningLevel" = 90
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" = @{
        "EnableFontProviders" = 0
        "AllowCrossDeviceClipboard" = 0
        "UploadUserActivities" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD" = @{
        "AllowLLTDIOOnDomain" = 0
        "AllowLLTDIOOnPublicNet" = 0
        "EnableLLTDIO" = 0
        "ProhibitLLTDIOOnPrivateNet" = 0
        "AllowRspndrOnDomain" = 0
        "AllowRspndrOnPublicNet" = 0
        "EnableRspndr" = 0
        "ProhibitRspndrOnPrivateNet" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Peernet" = @{
        "Disabled" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" = @{
        "EnableRegistrars" = 0
        "DisableUPnPRegistrar" = 0
        "DisableInBand802DOT11Registrar" = 0
        "DisableFlashConfigRegistrar" = 0
        "DisableWPDRegistrar" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\UI" = @{
        "DisableWcnUi" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" = @{
        "NoCloudApplicationNotification" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" = @{
        "PreventHandwritingDataSharing" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" = @{
        "PreventHandwritingErrorReports" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" = @{
        "ExitOnMSICW" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" = @{
        "DisableHTTPPrinting" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control" = @{
        "NoRegistration" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\SearchCompanion" = @{
        "DisableContentFileUpdates" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client" = @{
        "CEIP" = 2
    }
    "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" = @{
        "CEIPEnable" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" = @{
        "Disabled" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" = @{
        "DoReport" = 0
    }
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters" = @{
        "DevicePKInitBehavior" = 0
        "DevicePKInitEnabled" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Control Panel\International" = @{
        "BlockUserInputMethodsForSignIn" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" = @{
        "DCSettingIndex" = 0
        "ACSettingIndex" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" = @{
        "DisableQueryRemoteServer" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" = @{
        "ScenarioExecutionEnabled" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" = @{
        "DisabledByGroupPolicy" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager" = @{
        "AllowSharedLocalAppData" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Camera" = @{
        "AllowCamera" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" = @{
        "DisableEnterpriseAuthProxy" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" = @{
        "DisableLocation" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging" = @{
        "AllowMessageSync" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" = @{
        "SpynetReporting" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" = @{
        "DisableGenericRePorts" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\PushToInstall" = @{
        "DisablePushToInstall" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" = @{
        "fSingleSessionPerUser" = 1
        "fDisableCcm" = 1
        "fDisableLPT" = 1
        "fDisablePNPRedir" = 1
        "MaxIdleTime" = 900000
        "MaxDisconnectionTime" = 6000
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" = @{
        "AllowCloudSearch" = 0
        "EnableDynamicContentInWSB" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" =
 @{
        "NoGenTicket" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" = @{
        "AllowSuggestedAppsInWindowsInkWorkspace" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" = @{
        "SafeForScripting" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" = @{
        "EnableScriptBlockLogging" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" = @{
        "EnableTranscripting" = 1
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" = @{
        "AllowAutoConfig" = 0
    }
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" = @{
        "AllowRemoteShellAccess" = 0
    }
}
$L2Section19MSDC = @{
    "HKU\[USER SID]\Software\Policies\Microsoft\Assistance\Client\1.0" = @{
        "NoImplicitFeedback" = 1
    }
    "HKU\[USER SID]\Software\Policies\Microsoft\Windows\CloudContent" = @{
        "DisableTailoredExperiencesWithDiagnosticData" = 1
        "DisableWindowsSpotlightFeatures" = 1
    }
    "HKU\[USER SID]\Software\Policies\Microsoft\WindowsMediaPlayer" = @{
        "PreventCodecDownload" = 1
    }
}
$NGSection18MS = @{
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" = @{
        "HVCIMATRequired" = 1
        "LsaCfgFlags" = 1
    }
}
$NGSection18DC = @{
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" = @{
        "LsaCfgFlags" = 0
    }
}
$NGSection18MSDC = @{
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" = @{
        "EnableVirtualizationBasedSecurity" = 1
        "RequirePlatformSecurityFeatures" = 3
        "HypervisorEnforcedCodeIntegrity" = 1
        "HVCIMATRequired" = 1
        "ConfigureSystemGuardLaunch" = 1
    }
}