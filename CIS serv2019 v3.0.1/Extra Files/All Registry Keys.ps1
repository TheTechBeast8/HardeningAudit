#L1 Section 2 MS
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon:ForceUnlockLogon 1
HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters:SMBServerNameHardeningLevel 1##set to 1,2
HKLM\SYSTEM\CurrentControlSet\Control\Lsa:RestrictAnonymousSAM 1
HKLM\SYSTEM\CurrentControlSet\Control\Lsa:RestrictAnonymous 1
HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters:NullSessionPipes "0"
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa:restrictremotesam "O:BAG:BAD:(A;;RC;;;BA)"
#L1 Section 2 DC
HKLM\SYSTEM\CurrentControlSet\Control\Lsa:SubmitControl 0
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters:VulnerableChannelAllowList "does not exist"
HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters:LdapEnforceChannelBinding 2
HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters:LDAPServerIntegrity 2
HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters:RefusePasswordChange 0
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters:NullSessionPipes "LSARPC, NETLOGON, SAMR"
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters:AuditNTLMInDomain 7
#L1 Section 2 MS + DC
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:NoConnectedUser 3
HKLM\SYSTEM\CurrentControlSet\Control\Lsa:LimitBlankPasswordUse 1
HKLM\SYSTEM\CurrentControlSet\Control\Lsa:SCENoApplyLegacyAuditPolicy 1
HKLM\SYSTEM\CurrentControlSet\Control\Lsa:CrashOnAuditFail 0
HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers:AddPrinterDrivers 1
HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters:RequireSignOrSeal 1
HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters:SealSecureChannel 1
HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters:SignSecureChannel 1
HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters:DisablePasswordChange 0
HKLM\System\CurrentControlSet\Services\Netlogon\Parameters:MaximumPasswordAge 30##set 30>=x>0
HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters:RequireStrongKey 1
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:DisableCAD 0
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:DontDisplayLastUserName 1
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:InactivityTimeoutSecs 900##set 900>=x>0
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:LegalNoticeText "Sample Text"##set to *
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:LegalNoticeCaption "Sample Text"##set to *
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon:PasswordExpiryWarning 14##set to 14>=x>5
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon:ScRemoveOption "3"##set 1-3
HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters:RequireSecuritySignature 1
HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters:EnableSecuritySignature 1
HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters:EnablePlainTextPassword 0
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters:AutoDisconnect 15##set x<15
HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters:RequireSecuritySignature 1
HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters:EnableSecuritySignature 1
HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters:enableforcedlogoff 1
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa:TurnOffAnonymousBlock 1
HKLM\SYSTEM\CurrentControlSet\Control\Lsa:EveryoneIncludesAnonymous 0
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths:Machine "System\CurrentControlSet\Control\ProductOptions System\CurrentControlSet\Control\Server Applications Software\Microsoft\Windows NT\CurrentVersion"
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths:Machine "System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog,System\CurrentControlSet\Services\CertSvc,System\CurrentControlSet\Services\WINS"
HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters:RestrictNullSessAccess 1
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters:NullSessionShares "<none>"
HKLM\SYSTEM\CurrentControlSet\Control\Lsa:ForceGuest 0
HKLM\SYSTEM\CurrentControlSet\Control\Lsa:UseMachineId 1
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0:AllowNullSessionFallback 0
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\pku2u:AllowOnlineID 0
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters:SupportedEncryptionTypes 2147483640
HKLM\SYSTEM\CurrentControlSet\Control\Lsa:NoLMHash 1
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa:LmCompatibilityLevel 5
HKLM\SYSTEM\CurrentControlSet\Services\LDAP:LDAPClientIntegrity 1
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0:NTLMMinClientSec 537395200
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0:NTLMMinServerSec 537395200
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0:AuditReceivingNTLMTraffic 2
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0:RestrictSendingNTLMTraffic 2
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:ShutdownWithoutLogon 0
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel:ObCaseInsensitive 1
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager:ProtectionMode 1
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:FilterAdministratorToken 1
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:ConsentPromptBehaviorAdmin 1##set 1,2
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:ConsentPromptBehaviorUser 0
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:EnableInstallerDetection 1
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:EnableSecureUIAPaths 1
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:EnableLUA 1
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:PromptOnSecureDesktop 1
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:EnableVirtualization 1
#L1 Section 5 DC
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler:Start 4
#L1 Section 9 MS + DC
HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile:EnableFirewall 1
HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile:DefaultInboundAction 1
HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile:DisableNotifications 1
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging:LogFilePath "%SystemRoot%\System32\logfiles\firewall\domainfw.log"
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging:LogFileSize 16384##set x>=16384
HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging:LogDroppedPackets 1
HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging:LogSuccessfulConnections 1
HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile:EnableFirewall 1
HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile:DefaultInboundAction 1
HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile:DisableNotifications 1
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging:LogFilePath "%SystemRoot%\System32\logfiles\firewall\privatefw.log"
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging:LogFileSize 16384##set x>=16384
HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging:LogDroppedPackets 1
HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging:LogSuccessfulConnections 1
HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile:EnableFirewall 1
HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile:DefaultInboundAction 1
HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile:DisableNotifications 1
HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile:AllowLocalPolicyMerge 0
HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile:AllowLocalIPsecPolicyMerge 0
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging:LogFilePath "%SystemRoot%\System32\logfiles\firewall\publicfw.log"
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging:LogFileSize 16384##set x>=16384
HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging:LogDroppedPackets 1
HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging:LogSuccessfulConnections 1
#L1 Section 18 MS
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:LocalAccountTokenFilterPolicy 0
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS:BackupDirectory 1##set 1,2
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS:PwdExpirationProtectionEnabled 1
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS:ADPasswordEncryptionEnabled 1
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS:PasswordComplexity 4
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS:PasswordLength 15##set x>=15
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS:PasswordAgeDays 30##set x<=30
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS:PostAuthenticationResetDelay 8##set 8>=x>0
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS:PostAuthenticationActions 3##set 3,5
HKLM\SOFTWARE\Policies\Microsoft\Windows\System:EnumerateLocalUsers 0
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc:EnableAuthEpResolution 1
HKLM\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer:Enabled 0
#L1 Section 18 DC
HKLM\Software\Policies\Microsoft\Windows NT\Printers:RegisterSpoolerRemoteRpcEndPoint 2
#L1 Section 18 MS + DC
HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization:NoLockScreenCamera 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization:NoLockScreenSlideshow 1
HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization:AllowInputPersonalization 0
HKLM\SYSTEM\CurrentControlSet\Control\Print:RpcAuthnLevelPrivacyEnabled 1
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb10:Start 4 
HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters:SMB1 0
HKLM\SOFTWARE\Microsoft\Cryptography\Wintrust\Config:EnableCertPaddingCheck 1
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel:DisableExceptionChainValidation 0
HKLM\SYSTEM\CurrentControlSet\Control\Lsa:RunAsPPL 1
HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters:NodeType 2
HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest:UseLogonCredential 0
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon:AutoAdminLogon "0"
HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters:DisableIPSourceRouting 2
HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters:DisableIPSourceRouting 2
HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters:EnableICMPRedirect 0
HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters:NoNameReleaseOnDemand 1
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager:SafeDllSearchMode 1
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon:ScreenSaverGracePeriod "5"## set x<=5
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient:EnableNetbios 0##set 0,2
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient:EnableMulticast 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation:AllowInsecureGuestAuth 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections:NC_AllowNetBridge_NLA 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections:NC_ShowSharedAccessUI 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections:NC_StdDomainUserSetLocation 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections:NC_AllowNetBridge_NLA 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections:NC_ShowSharedAccessUI 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections:NC_StdDomainUserSetLocation 1
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths:\\*\NETLOGON "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1"
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths:\\*\SYSVOL "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1"
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy:fMinimizeConnections 3
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers:RedirectionguardPolicy 1
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC:RpcUseNamedPipeProtocol 0
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC:RpcAuthentication 0
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC:RpcProtocols 5
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC:ForceKerberosForRpc 0##set 0,1
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC:RpcTcpPort 0
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint:RestrictDriverInstallationToAdministrators 1
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers:CopyFilesPolicy 1
HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint:NoWarningNoElevationOnInstall 0
HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint:UpdatePromptSettings 0
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit:ProcessCreationIncludeCmdLine_Enabled 1
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters:AllowEncryptionOracle 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation:AllowProtectedCreds 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata:PreventDeviceMetadataFromNetwork 1
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch:DriverLoadPolicy 3
HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}:NoBackgroundPolicy 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}:NoGPOListChanges 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}:NoBackgroundPolicy 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}:NoGPOListChanges 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\System:EnableCdp 0
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:DisableBkGndGroupPolicy "does not exist"
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers:DisableWebPnPDownload 1 
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoWebServices 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection:DeviceEnumerationPolicy 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\System:BlockUserFromShowingAccountDetailsOnSignin 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\System:DontDisplayNetworkSelectionUI 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\System:DontEnumerateConnectedUsers 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\System:DisableLockScreenAppNotifications 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\System:BlockDomainPicturePassword 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\System:AllowDomainPINLogon 0
HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51:DCSettingIndex 1
HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51:ACSettingIndex 1
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:fAllowUnsolicited 0
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:fAllowToGetHelp 0
HKLM\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient:Enabled 1
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:MSAOptional 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer:NoAutoplayfornonVolume 1
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoAutorun 1
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoDriveTypeAutoRun 255
HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures:EnhancedAntiSpoofing 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent:DisableConsumerAccountStateContent 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent:DisableWindowsConsumerFeatures 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect:RequirePinForPairing 2##set 1,2
HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI:DisablePasswordReveal 1
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI:EnumerateAdministrators 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection:AllowTelemetry 1##set 0,1
HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection:DisableOneSettingsDownloads 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection:DoNotShowFeedbackNotifications 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection:EnableOneSettingsAuditing 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection:LimitDiagnosticLogCollection 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection:LimitDumpCollection 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds:AllowBuildPreview 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller:EnableAppInstaller 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller:EnableExperimentalFeatures 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller:EnableHashOverride 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller:EnableMSAppInstallerProtocol 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application:Retention "0"
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application:MaxSize 32768##set x>=32768
HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security:Retention "0"
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security:MaxSize 196608##set x>=196608
HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup:Retention "0"
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup:MaxSize 32768##set x>=32768
HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System:Retention "0"
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System:MaxSize 32768##set x>=32768
HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer:NoDataExecutionPrevention 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer:NoHeapTerminationOnCorruption 0
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer:PreXPSP2ShellProtocolBehavior 0
HKLM\SOFTWARE\Policies\Microsoft\MicrosoftAccount:DisableUserAuth 1
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet:LocalSettingOverrideSpynetReporting 0
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR:ExploitGuard_ASR_Rules 1
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules:26190899-1602-49e8-8b27-eb1d0a1ce869 "1"
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules:3b576869-a4ec-4529-8536-b80a7769e899 "1"
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules:56a863a9-875e-4185-98a7-b882c64b5ce5 "1"
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules:5beb7efe-fd9a-4556-801d-275e5ffc04cc "1"
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules:75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 "1"
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules:7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c "1"
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules:92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b "1"
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules:9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 "1"
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules:b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 "1"
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules:be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 "1"
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules:d3e037e1-3eb8-44c8-a917-57927947596d "1"
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules:d4f940ab-401b-4efc-aadc-ad5f3c50688a "1"
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules:e6db77e5-3df2-4cf1-b95a-636979351e5b "1"
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection:EnableNetworkProtection 1
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine:EnableFileHashComputation 1
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection:DisableIOAVProtection 0
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection:DisableRealtimeMonitoring 0
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection:DisableBehaviorMonitoring 0
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection:DisableScriptScanning 0
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan:DisablePackedExeScanning 0
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan:DisableRemovableDriveScanning 0
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan:DisableEmailScanning 0
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender:PUAProtection 1
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender:DisableAntiSpyware 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive:DisableFileSyncNGSC 1
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:DisablePasswordSaving 1
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:fDisableCdm 1
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:fPromptForPassword 1
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:fEncryptRPCTraffic 1
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:SecurityLayer 2
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:UserAuthentication 1
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:MinEncryptionLevel 3
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:DeleteTempDirsOnExit 1
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:PerSessionTempDir 1
HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds:DisableEnclosureDownload 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search:AllowIndexingEncryptedStoresOrItems 0
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System:EnableSmartScreen 1
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System:ShellSmartScreenLevel "Block"
HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace:AllowWindowsInkWorkspace 0##set 0,1
HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer:EnableUserControl 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer:AlwaysInstallElevated 0
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:DisableAutomaticRestartSignOn 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client:AllowBasic 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client:AllowUnencryptedTraffic 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client:AllowDigest 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service:AllowBasic 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service:AllowUnencryptedTraffic 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service:DisableRunAs 1
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection:DisallowExploitProtectionOverride 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU:NoAutoRebootWithLoggedOnUsers 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU:NoAutoUpdate 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU:ScheduledInstallDay 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate:ManagePreviewBuildsPolicyValue 1
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate:DeferFeatureUpdates 1
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate:DeferFeatureUpdatesPeriodInDays 180##set x>=180
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate:DeferQualityUpdates 1
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate:DeferQualityUpdatesPeriodInDays 0
#L1 Section 19 MS+ DC
HKU\[USER SID]\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications:NoToastApplicationNotificationOnLockScreen 1
HKU\[USER SID]\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments:SaveZoneInformation 2
HKU\[USER SID]\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments:ScanWithAntiVirus 3
HKU\[USER SID]\Software\Policies\Microsoft\Windows\CloudContent:ConfigureWindowsSpotlight 2
HKU\[USER SID]\Software\Policies\Microsoft\Windows\CloudContent:DisableThirdPartySuggestions 1
HKU\[USER SID]\SOFTWARE\Policies\Microsoft\Windows\CloudContent:DisableSpotlightCollectionOnDesktop 0
HKU\[USER SID]\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoInplaceSharing 1
HKU\[USER SID]\Software\Policies\Microsoft\Windows\Installer:AlwaysInstallElevated 0
#L2 Section 2 MS
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon:CachedLogonsCount 2##set 4>=x
#L2 Section 2 MS + DC
HKLM\SYSTEM\CurrentControlSet\Control\Lsa:DisableDomainCreds 1
#L2 Section 5 MS
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler:Start 4
#L2 Section 18 MS
HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy:fBlockNonDomain 1
HKLM\Software\Policies\Microsoft\Windows NT\Printers:RegisterSpoolerRemoteRpcEndPoint 2
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc:RestrictRemoteClients 1
#L2 Section 18 MS + DC
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer:AllowOnlineTips 0
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters:KeepAliveTime 300000
HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters:PerformRouterDiscovery 0
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters:TcpMaxDataRetransmissions 3
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters:TcpMaxDataRetransmissions 3 
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security:WarningLevel 90##set x<=90
HKLM\SOFTWARE\Policies\Microsoft\Windows\System:EnableFontProviders 0
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD:AllowLLTDIOOnDomain 0
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD:AllowLLTDIOOnPublicNet 0
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD:EnableLLTDIO 0
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD:ProhibitLLTDIOOnPrivateNet 0
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD:AllowRspndrOnDomain 0
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD:AllowRspndrOnPublicNet 0
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD:EnableRspndr 0
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD:ProhibitRspndrOnPrivateNet 0
HKLM\SOFTWARE\Policies\Microsoft\Peernet:Disabled 1
HKLM\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters:DisabledComponents 255
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars:EnableRegistrars 0
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars:DisableUPnPRegistrar 0
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars:DisableInBand802DOT11Registrar 0
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars:DisableFlashConfigRegistrar 0
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars:DisableWPDRegistrar 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\UI:DisableWcnUi 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications:NoCloudApplicationNotification 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC:PreventHandwritingDataSharing 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports:PreventHandwritingErrorReports 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard:ExitOnMSICW 1
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers:DisableHTTPPrinting 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control:NoRegistration 1
HKLM\SOFTWARE\Policies\Microsoft\SearchCompanion:DisableContentFileUpdates 1
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoOnlinePrintsWizard 1
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoPublishingWizard 1
HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client:CEIP 2
HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows:CEIPEnable 0
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting:Disabled 1
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting:DoReport 0
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters:DevicePKInitBehavior 0
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters:DevicePKInitEnabled 1
HKLM\SOFTWARE\Policies\Microsoft\Control Panel\International:BlockUserInputMethodsForSignIn 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\System:AllowCrossDeviceClipboard 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\System:UploadUserActivities 0
HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9:DCSettingIndex 0
HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9:ACSettingIndex 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy:DisableQueryRemoteServer 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}:ScenarioExecutionEnabled 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo:DisabledByGroupPolicy 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager:AllowSharedLocalAppData 0
HKLM\SOFTWARE\Policies\Microsoft\Camera:AllowCamera 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection:DisableEnterpriseAuthProxy 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors:DisableLocation 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging:AllowMessageSync 0
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet:SpynetReporting 0
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting:DisableGenericRePorts 1
HKLM\SOFTWARE\Policies\Microsoft\PushToInstall:DisablePushToInstall 1
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:fSingleSessionPerUser 1
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:fDisableCcm 1
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:fDisableLPT 1
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:fDisablePNPRedir 1
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:MaxIdleTime 900000##set 900000>=x>0
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:MaxDisconnectionTime 6000
HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search:AllowCloudSearch 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search:EnableDynamicContentInWSB 0
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform:NoGenTicket 1
HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace:AllowSuggestedAppsInWindowsInkWorkspace 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer:SafeForScripting 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging:EnableScriptBlockLogging 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription:EnableTranscripting 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service:AllowAutoConfig 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS:AllowRemoteShellAccess 0
#L2 Section 19 MS + DC
HKU\[USER SID]\Software\Policies\Microsoft\Assistance\Client\1.0:NoImplicitFeedback 1
HKU\[USER SID]\Software\Policies\Microsoft\Windows\CloudContent:DisableTailoredExperiencesWithDiagnosticData 1
HKU\[USER SID]\Software\Policies\Microsoft\Windows\CloudContent:DisableWindowsSpotlightFeatures 1
HKU\[USER SID]\Software\Policies\Microsoft\WindowsMediaPlayer:PreventCodecDownload  1
#NG Section 18 MS
HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard:HVCIMATRequired 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard:LsaCfgFlags 1
#NG Section 18 DC
HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard:LsaCfgFlags 0
#NG Section 18 MS + DC
HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard:EnableVirtualizationBasedSecurity 1
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard:RequirePlatformSecurityFeatures 3##set 1,3
HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard:HypervisorEnforcedCodeIntegrity 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard:HVCIMATRequired 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard:ConfigureSystemGuardLaunch 1






