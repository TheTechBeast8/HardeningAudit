#Set the path for the secedit into windows temp as its doesnt need to be retained
$seceditPath = Join-Path -Path $env:TEMP -ChildPath 'secedit.inf'
#export the file from secedit to the set path 
secedit.exe /export /cfg $seceditPath | Out-Null
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$AdminPriv = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
#Perform check for admin rights as it is require for this to function
if(-not $AdminPriv){
	throw "Administrator privileges required!"
}
$L1Section1 = @{
    'HKLM\System\CurrentControlSet\Control\SAM' = @(
        @{ 'key' = 'RelaxMinimumPasswordLengthLimits'; 'type' = 'exact'; 'value' = 1 }
    )
}
$L1Section2 = @{
    'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\pku2u' = @(
        @{ 'key' = 'AllowOnlineID'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel' = @(
        @{ 'key' = 'ObCaseInsensitive'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' = @(
        @{ 'key' = 'PasswordExpiryWarning'; 'range' = 'exact'; 'value' = 5,6,7,8,9,10,11,12,13,14 },
        @{ 'key' = 'ScRemoveOption'; 'type' = 'range'; 'value' = 1,2,3 }
    )
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' = @(
        @{ 'key' = 'SupportedEncryptionTypes'; 'type' = 'exact'; 'value' = 2147483640 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' = @(
        @{ 'key' = 'CrashOnAuditFail'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'RestrictAnonymousSAM'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'ForceGuest'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'EveryoneIncludesAnonymous'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'LmCompatibilityLevel'; 'type' = 'exact'; 'value' = 5 },
        @{ 'key' = 'DisableDomainCreds'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'SCENoApplyLegacyAuditPolicy'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'restrictremotesam'; 'type' = 'exact'; 'value' = "O:BAG:BAD:(A;;RC;;;BA)" },
        @{ 'key' = 'LimitBlankPasswordUse'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'RestrictAnonymous'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'NoLMHash'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'UseMachineId'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths' = @(
        @{ 'key' = 'Machine'; 'type' = 'exact'; 'value' = " System\CurrentControlSet\Control\Print\Printers, System\CurrentControlSet\Services\Eventlog, Software\Microsoft\OLAP Server, Software\Microsoft\Windows NT\CurrentVersion\Prin
t, Software\Microsoft\Windows NT\Curre
ntVersion\Windows, System\CurrentControlSet\Control\ContentIndex, System\CurrentControlSet\Control\Terminal Server, System\CurrentControlSet\Control\Terminal Server\UserConfig, System\CurrentControlSet\Control\Terminal Server\DefaultU

serConfiguration, Software\Microsoft\Windows NT\CurrentVersion\Perflib, System\CurrentControlSet\Services\SysmonLog" }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' = @(
        @{ 'key' = 'EnablePlainTextPassword'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'EnableSecuritySignature'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'RequireSecuritySignature'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths' = @(
        @{ 'key' = 'Machine'; 'type' = 'exact'; 'value' = "System\CurrentControlSet\Control\ProductOptions, System\CurrentControlSet\Control\Server Applications, Software\Microsoft\Windows NT\CurrentVersion" }
    )
    'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' = @(
        @{ 'key' = 'AllowNullSessionFallback'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'NTLMMinServerSec'; 'type' = 'exact'; 'value' = 537395200 },
        @{ 'key' = 'NTLMMinClientSec'; 'type' = 'exact'; 'value' = 537395200 },
        @{ 'key' = 'AuditReceivingNTLMTraffic'; 'type' = 'exact'; 'value' = 2 },
        @{ 'key' = 'RestrictSendingNTLMTraffic'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\LDAP' = @(
        @{ 'key' = 'LDAPClientIntegrity'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager' = @(
        @{ 'key' = 'ProtectionMode'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' = @(
        @{ 'key' = 'NoConnectedUser'; 'type' = 'exact'; 'value' = 3 },
        @{ 'key' = 'PromptOnSecureDesktop'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'DisableCAD'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'LegalNoticeText'; 'type' = 'exact'; 'value' = "*" },
        @{ 'key' = 'EnableSecureUIAPaths'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'EnableInstallerDetection'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'LegalNoticeCaption'; 'type' = 'exact'; 'value' = "*" },
        @{ 'key' = 'ConsentPromptBehaviorAdmin'; 'type' = 'range'; 'value' = 1,2 },
        @{ 'key' = 'InactivityTimeoutSecs'; 'type' = 'comparison'; 'value' = "x -le 900 -and x -gt 0" },
        @{ 'key' = 'DontDisplayLastUserName'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'EnableLUA'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'EnableVirtualization'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'FilterAdministratorToken'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'ConsentPromptBehaviorUser'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' = @(
        @{ 'key' = 'RestrictNullSessAccess'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'NullSessionShares'; 'type' = 'exact'; 'value' = "" },
        @{ 'key' = 'EnableSecuritySignature'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'enableforcedlogoff'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'NullSessionPipes'; 'type' = 'exact'; 'value' = "" },
        @{ 'key' = 'AutoDisconnect'; 'type' = 'comparison'; 'value' = "x -le 15" },
        @{ 'key' = 'RequireSecuritySignature'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'SMBServerNameHardeningLevel'; 'type' = 'range'; 'value' = 1,2 }
    )
}
$L1Section5 = @{
    'HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\simptcp' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\SSDPSRV' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\upnphost' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\RpcLocator' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\irmon' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\FTPSVC' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\sacsvr' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\sshd' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\Browser' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\IISADMIN' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\LxssManager' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\icssvc' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\WMSvc' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\W3SVC' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
}
$L1Section9 = @{
    'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' = @(
        @{ 'key' = 'DisableNotifications'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'EnableFirewall'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'AllowLocalIPsecPolicyMerge'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'DefaultInboundAction'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'AllowLocalPolicyMerge'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging' = @(
        @{ 'key' = 'LogFileSize'; 'type' = 'comparison'; 'value' = "x -ge 16384" },
        @{ 'key' = 'LogDroppedPackets'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'LogSuccessfulConnections'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'LogFilePath'; 'type' = 'exact'; 'value' = "%SystemRoot%\System32\logfiles\firewall\privatefw.log" }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging' = @(
        @{ 'key' = 'LogFileSize'; 'type' = 'comparison'; 'value' = "x -ge 16384" },
        @{ 'key' = 'LogDroppedPackets'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'LogSuccessfulConnections'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'LogFilePath'; 'type' = 'exact'; 'value' = "%SystemRoot%\System32\logfiles\firewall\publicfw.log" }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile' = @(
        @{ 'key' = 'DisableNotifications'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'EnableFirewall'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'DefaultInboundAction'; 'type' = 'exact'; 'value' = 1 }
    )
}
$L1Section18 = @{
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection' = @(
        @{ 'key' = 'DoNotShowFeedbackNotifications'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'EnableOneSettingsAuditing'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'LimitDiagnosticLogCollection'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'DisableOneSettingsDownloads'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'LimitDumpCollection'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'AllowTelemetry'; 'type' = 'range'; 'value' = 0,1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC' = @(
        @{ 'key' = 'RpcProtocols'; 'type' = 'exact'; 'value' = 5 },
        @{ 'key' = 'ForceKerberosForRpc'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'RpcTcpPort'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'RpcAuthentication'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'RpcUseNamedPipeProtocol'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' = @(
        @{ 'key' = 'EnumerateAdministrators'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' = @(
        @{ 'key' = 'ManagePreviewBuildsPolicyValue'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'DeferFeatureUpdates'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'DeferQualityUpdates'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'DeferQualityUpdatesPeriodInDays'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'AllowTemporaryEnterpriseFeatureControl'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'SetDisablePauseUXAccess'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'DeferFeatureUpdatesPeriodInDays'; 'type' = 'comparison'; 'value' = "x -ge 180" }
    )
    'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager' = @(
        @{ 'key' = 'SafeDllSearchMode'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization' = @(
        @{ 'key' = 'AllowInputPersonalization'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System' = @(
        @{ 'key' = 'Retention'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'MaxSize'; 'type' = 'comparison'; 'value' = "x -ge 32768" }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds' = @(
        @{ 'key' = 'AllowBuildPreview'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' = @(
        @{ 'key' = 'ScreenSaverGracePeriod'; 'type' = 'comparison'; 'value' = "x -le 5" },
        @{ 'key' = 'AutoAdminLogon'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive' = @(
        @{ 'key' = 'DisableFileSyncNGSC'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient' = @(
        @{ 'key' = 'Enabled'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' = @(
        @{ 'key' = 'DisableAntiSpyware'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'PUAProtection'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters' = @(
        @{ 'key' = 'AllowEncryptionOracle'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' = @(
        @{ 'key' = '5beb7efe-fd9a-4556-801d-275e5ffc04cc'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = '26190899-1602-49e8-8b27-eb1d0a1ce869'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = '56a863a9-875e-4185-98a7-b882c64b5ce5'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = '3b576869-a4ec-4529-8536-b80a7769e899'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'e6db77e5-3df2-4cf1-b95a-636979351e5b'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'd3e037e1-3eb8-44c8-a917-57927947596d'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' = @(
        @{ 'key' = 'DisableIPSourceRouting'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51' = @(
        @{ 'key' = 'DCSettingIndex'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'ACSettingIndex'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' = @(
        @{ 'key' = 'AllowDigest'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'AllowUnencryptedTraffic'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'AllowBasic'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer' = @(
        @{ 'key' = 'AlwaysInstallElevated'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'EnableUserControl'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' = @(
        @{ 'key' = 'LetAppsActivateWithVoiceAboveLock'; 'type' = 'exact'; 'value' = 2 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller' = @(
        @{ 'key' = 'EnableMSAppInstallerProtocol'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'EnableHashOverride'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'EnableExperimentalFeatures'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'EnableAppInstaller'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' = @(
        @{ 'key' = 'UpdatePromptSettings'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'NoWarningNoElevationOnInstall'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'RestrictDriverInstallationToAdministrators'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization' = @(
        @{ 'key' = 'NoLockScreenCamera'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'NoLockScreenSlideshow'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine' = @(
        @{ 'key' = 'EnableFileHashComputation'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' = @(
        @{ 'key' = 'AllowProtectedCreds'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc' = @(
        @{ 'key' = 'RestrictRemoteClients'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'EnableAuthEpResolution'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\MicrosoftAccount' = @(
        @{ 'key' = 'DisableUserAuth'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' = @(
        @{ 'key' = 'AllowInsecureGuestAuth'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch' = @(
        @{ 'key' = 'DriverLoadPolicy'; 'type' = 'exact'; 'value' = 3 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR' = @(
        @{ 'key' = 'ExploitGuard_ASR_Rules'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\Software\Policies\Microsoft\Windows NT\Printers' = @(
        @{ 'key' = 'RedirectionguardPolicy'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'DisableWebPnPDownload'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'RegisterSpoolerRemoteRpcEndPoint'; 'type' = 'exact'; 'value' = 2 },
        @{ 'key' = 'CopyFilesPolicy'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer' = @(
        @{ 'key' = 'NoUseStoreOpenWith'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'NoAutoplayfornonVolume'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'NoHeapTerminationOnCorruption'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'NoDataExecutionPrevention'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\windows Defender\Windows Defender Exploit Guard\Network Protection' = @(
        @{ 'key' = 'EnableNetworkProtection'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' = @(
        @{ 'key' = '\\*\SYSVOL'; 'type' = 'exact'; 'value' = "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1" },
        @{ 'key' = '\\*\NETLOGON'; 'type' = 'exact'; 'value' = "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1" }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' = @(
        @{ 'key' = 'AllowCortanaAboveLock'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'AllowIndexingEncryptedStoresOrItems'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'AllowCortana'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'AllowSearchToUseLocation'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' = @(
        @{ 'key' = 'DoHPolicy'; 'type' = 'range'; 'value' = 2,3 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI' = @(
        @{ 'key' = 'DisablePasswordReveal'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' = @(
        @{ 'key' = 'fAllowToGetHelp'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'fAllowUnsolicited'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'UserAuthentication'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'fPromptForPassword'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'MinEncryptionLevel'; 'type' = 'exact'; 'value' = 3 },
        @{ 'key' = 'fEncryptRPCTraffic'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'DeleteTempDirsOnExit'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'DisablePasswordSaving'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'SecurityLayer'; 'type' = 'exact'; 'value' = 2 },
        @{ 'key' = 'fDisableCdm'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent' = @(
        @{ 'key' = 'DisableConsumerAccountStateContent'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'DisableWindowsConsumerFeatures'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' = @(
        @{ 'key' = 'SMB1'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' = @(
        @{ 'key' = 'LocalSettingOverrideSpynetReporting'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Microsoft\Cryptography\Wintrust\Config' = @(
        @{ 'key' = 'EnableCertPaddingCheck'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9' = @(
        @{ 'key' = 'DCSettingIndex'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'ACSettingIndex'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' = @(
        @{ 'key' = 'DisableAutomaticRestartSignOn'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'EnableMPR'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'MSAOptional'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' = @(
        @{ 'key' = 'RunAsPPL'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds' = @(
        @{ 'key' = 'DisableEnclosureDownload'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup' = @(
        @{ 'key' = 'Retention'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'MaxSize'; 'type' = 'comparison'; 'value' = "x -ge 32768" }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures' = @(
        @{ 'key' = 'EnhancedAntiSpoofing'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Dsh' = @(
        @{ 'key' = 'AllowNewsAndInterests'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect' = @(
        @{ 'key' = 'RequirePinForPairing'; 'type' = 'range'; 'value' = 1,2 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components' = @(
        @{ 'key' = 'CaptureThreatWindow'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'NotifyPasswordReuse'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'NotifyMalicious'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'ServiceEnabled'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'NotifyUnsafeApp'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' = @(
        @{ 'key' = 'ProcessCreationIncludeCmdLine_Enabled'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR' = @(
        @{ 'key' = 'AllowGameDVR'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Control\Print' = @(
        @{ 'key' = 'RpcAuthnLevelPrivacyEnabled'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan' = @(
        @{ 'key' = 'DisablePackedExeScanning'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'DisableEmailScanning'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'DisableRemovableDriveScanning'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Microsoft\Policies\PassportForWork\Biometrics' = @(
        @{ 'key' = 'EnableESSwithSupportedPeripherals'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' = @(
        @{ 'key' = 'NoAutoUpdate'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'ScheduledInstallDay'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'NoAutoRebootWithLoggedOnUsers'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\AppHVSI' = @(
        @{ 'key' = 'AllowPersistence'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'AllowAppHVSI_ProviderSet'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'AppHVSIClipboardSettings'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'SaveFilesToHost'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'AllowCameraMicrophoneRedirection'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'AuditApplicationGuard'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata' = @(
        @{ 'key' = 'PreventDeviceMetadataFromNetwork'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Sandbox' = @(
        @{ 'key' = 'AllowClipboardRedirection'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'AllowNetworking'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' = @(
        @{ 'key' = 'Retention'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'MaxSize'; 'type' = 'comparison'; 'value' = "x -ge 196608" }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' = @(
        @{ 'key' = 'DisableRunAs'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'AllowUnencryptedTraffic'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'AllowBasic'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' = @(
        @{ 'key' = 'DODownloadMode'; 'type' = 'range'; 'value' = 0,1,2,99,100 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' = @(
        @{ 'key' = 'NoNameReleaseOnDemand'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'NodeType'; 'type' = 'exact'; 'value' = 2 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application' = @(
        @{ 'key' = 'Retention'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'MaxSize'; 'type' = 'comparison'; 'value' = "x -ge 32768" }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace' = @(
        @{ 'key' = 'AllowWindowsInkWorkspace'; 'type' = 'range'; 'value' = 0,1 }
    )
    'HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' = @(
        @{ 'key' = 'AutoConnectAllowedOEM'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' = @(
        @{ 'key' = 'fMinimizeConnections'; 'type' = 'exact'; 'value' = 3 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections' = @(
        @{ 'key' = 'NC_AllowNetBridge_NLA'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'NC_ShowSharedAccessUI'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security' = @(
        @{ 'key' = 'WarningLevel'; 'type' = 'comparison'; 'value' = "x -le 90" }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection' = @(
        @{ 'key' = 'DisallowExploitProtectionOverride'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' = @(
        @{ 'key' = 'UseLogonCredential'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx' = @(
        @{ 'key' = 'BlockNonAdminUserInstall'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' = @(
        @{ 'key' = 'DisableIOAVProtection'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'DisableScriptScanning'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'DisableRealtimeMonitoring'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'DisableBehaviorMonitoring'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' = @(
        @{ 'key' = 'NoLocalPasswordResetQuestions'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'EnableSmartScreen'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'AllowCustomSSPsAPs'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'DisableLockScreenAppNotifications'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'EnableCdp'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'DontDisplayNetworkSelectionUI'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'BlockUserFromShowingAccountDetailsOnSignin'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'AllowDomainPINLogon'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'ShellSmartScreenLevel'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' = @(
        @{ 'key' = 'DisableExceptionChainValidation'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' = @(
        @{ 'key' = 'EnableICMPRedirect'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'DisableIPSourceRouting'; 'type' = 'exact'; 'value' = 2 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' = @(
        @{ 'key' = 'LsaCfgFlags'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'ConfigureSystemGuardLaunch'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'EnableVirtualizationBasedSecurity'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'RequirePlatformSecurityFeatures'; 'type' = 'range'; 'value' = 1,3 },
        @{ 'key' = 'ConfigureKernelShadowStacksLaunch'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'HVCIMATRequired'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'HypervisorEnforcedCodeIntegrity'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\WindowsStore' = @(
        @{ 'key' = 'RequirePrivateStoreOnly'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'DisableOSUpgrade'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'AutoDownload'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' = @(
        @{ 'key' = 'NoWebServices'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'PreXPSP2ShellProtocolBehavior'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'NoAutorun'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'NoDriveTypeAutoRun'; 'type' = 'exact'; 'value' = 255 }
    )
}
$L1Section19 = @{
    'HKU\[USER SID]\Software\Policies\Microsoft\Windows\Installer' = @(
        @{ 'key' = 'AlwaysInstallElevated'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKU\[USER SID]\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' = @(
        @{ 'key' = 'TurnOffWindowsCopilot'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKU\[USER SID]\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' = @(
        @{ 'key' = 'NoToastApplicationNotificationOnLockScreen'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKU\[USER SID]\Software\Policies\Microsoft\Windows\CloudContent' = @(
        @{ 'key' = 'ConfigureWindowsSpotlight'; 'type' = 'exact'; 'value' = 2 },
        @{ 'key' = 'DisableThirdPartySuggestions'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'DisableSpotlightCollectionOnDesktop'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKU\[USER SID]\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments' = @(
        @{ 'key' = 'SaveZoneInformation'; 'type' = 'exact'; 'value' = 2 },
        @{ 'key' = 'ScanWithAntiVirus'; 'type' = 'exact'; 'value' = 3 }
    )
    'HKU\[USER SID]\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' = @(
        @{ 'key' = 'NoInplaceSharing'; 'type' = 'exact'; 'value' = 1 }
    )
}
$L2Section2 = @{
    'HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers' = @(
        @{ 'key' = 'AddPrinterDrivers'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Cryptography' = @(
        @{ 'key' = 'ForceKeyProtection'; 'type' = 'range'; 'value' = 1,2 }
    )
}
$L2Section5 = @{
    'HKLM\SYSTEM\CurrentControlSet\Services\BTAGService' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\TermService' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\Spooler' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\MapsBroker' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\SessionEnv' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\wercplsupport' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\p2pimsvc' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\WerSvc' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\MSiSCSI' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\PNRPsvc' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\RasAuto' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\Wecsvc' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\UmRdpService' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\PushToInstall' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\lltdsvc' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\lfsvc' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\bthserv' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\PNRPAutoReg' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\p2psvc' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\SNMP' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\WinRM' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\WpnService' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
}
$L2Section18 = @{
    'HKLM\SOFTWARE\Policies\Microsoft\Camera' = @(
        @{ 'key' = 'AllowCamera'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' = @(
        @{ 'key' = 'AllowAutoConfig'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds' = @(
        @{ 'key' = 'EnableFeeds'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting' = @(
        @{ 'key' = 'DisableGenericRePorts'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows' = @(
        @{ 'key' = 'CEIPEnable'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars' = @(
        @{ 'key' = 'DisableFlashConfigRegistrar'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'DisableUPnPRegistrar'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'DisableWPDRegistrar'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'DisableInBand802DOT11Registrar'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'EnableRegistrars'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' = @(
        @{ 'key' = 'NoCloudApplicationNotification'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging' = @(
        @{ 'key' = 'AllowMessageSync'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent' = @(
        @{ 'key' = 'DisableCloudOptimizedContent'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}' = @(
        @{ 'key' = 'ScenarioExecutionEnabled'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer' = @(
        @{ 'key' = 'SafeForScripting'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS' = @(
        @{ 'key' = 'AllowRemoteShellAccess'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' = @(
        @{ 'key' = 'KeepAliveTime'; 'type' = 'exact'; 'value' = 300000 },
        @{ 'key' = 'TcpMaxDataRetransmissions'; 'type' = 'exact'; 'value' = 3 },
        @{ 'key' = 'PerformRouterDiscovery'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD' = @(
        @{ 'key' = 'AllowLLTDIOOnPublicNet'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'EnableRspndr'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'EnableLLTDIO'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'AllowRspndrOnDomain'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'ProhibitLLTDIOOnPrivateNet'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'AllowRspndrOnPublicNet'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'ProhibitRspndrOnPrivateNet'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'AllowLLTDIOOnDomain'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' = @(
        @{ 'key' = 'EnableDynamicContentInWSB'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'AllowCloudSearch'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' = @(
        @{ 'key' = 'UploadUserActivities'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'EnableFontProviders'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'AllowCrossDeviceClipboard'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' = @(
        @{ 'key' = 'Disabled'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection' = @(
        @{ 'key' = 'DisableEnterpriseAuthProxy'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' = @(
        @{ 'key' = 'AllowOnlineTips'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'NoPublishingWizard'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'NoOnlinePrintsWizard'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' = @(
        @{ 'key' = 'EnableTranscripting'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' = @(
        @{ 'key' = 'fDisableLPT'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'fDisableCcm'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'fDisableWebAuthn'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'MaxDisconnectionTime'; 'type' = 'exact'; 'value' = 60000 },
        @{ 'key' = 'fDenyTSConnections'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'fDisablePNPRedir'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'MaxIdleTime'; 'type' = 'comparison'; 'value' = "x -le 900000 -and x -gt 0" },
        @{ 'key' = 'fDisableLocationRedir'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'EnableUiaRedirection'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\UI' = @(
        @{ 'key' = 'DisableWcnUi'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\WindowsStore' = @(
        @{ 'key' = 'DisableStoreApps'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'RemoveWindowsStore'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace' = @(
        @{ 'key' = 'AllowSuggestedAppsInWindowsInkWorkspace'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy' = @(
        @{ 'key' = 'DisableQueryRemoteServer'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\RasMan\Parameters' = @(
        @{ 'key' = 'DisableSavePassword'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' = @(
        @{ 'key' = 'EnableScriptBlockLogging'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' = @(
        @{ 'key' = 'DisabledByGroupPolicy'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Control Panel\International' = @(
        @{ 'key' = 'BlockUserInputMethodsForSignIn'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Peernet' = @(
        @{ 'key' = 'Disabled'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting' = @(
        @{ 'key' = 'DoReport'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard' = @(
        @{ 'key' = 'ExitOnMSICW'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' = @(
        @{ 'key' = 'BlockHostedAppAccessWinRT'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC' = @(
        @{ 'key' = 'PreventHandwritingDataSharing'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\PushToInstall' = @(
        @{ 'key' = 'DisablePushToInstall'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client' = @(
        @{ 'key' = 'CEIP'; 'type' = 'exact'; 'value' = 2 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform' = @(
        @{ 'key' = 'NoGenTicket'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control' = @(
        @{ 'key' = 'NoRegistration'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' = @(
        @{ 'key' = 'SpynetReporting'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' = @(
        @{ 'key' = 'DisableLocation'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports' = @(
        @{ 'key' = 'PreventHandwritingErrorReports'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers' = @(
        @{ 'key' = 'DisableHTTPPrinting'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters' = @(
        @{ 'key' = 'DevicePKInitBehavior'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'DevicePKInitEnabled'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters' = @(
        @{ 'key' = 'TcpMaxDataRetransmissions'; 'type' = 'exact'; 'value' = 3 },
        @{ 'key' = 'DisabledComponents'; 'type' = 'exact'; 'value' = 255 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager' = @(
        @{ 'key' = 'AllowSharedLocalAppData'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\SearchCompanion' = @(
        @{ 'key' = 'DisableContentFileUpdates'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer' = @(
        @{ 'key' = 'DisableGraphRecentItems'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'HideRecommendedPersonalizedSites'; 'type' = 'exact'; 'value' = 1 }
    )
    "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" = @(
        @{ 'key' = 'DisableCloudClipboardIntegration'; 'type' = 'exact'; 'value' = 1 }
    )    
}
$L2Section19 = @{
    'HKU\[USER SID]\Software\Policies\Microsoft\WindowsMediaPlayer' = @(
        @{ 'key' = 'PreventCodecDownload'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKU\[USER SID]\Software\Policies\Microsoft\Windows\CloudContent' = @(
        @{ 'key' = 'DisableTailoredExperiencesWithDiagnosticData'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'DisableWindowsSpotlightFeatures'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKU\[USER SID]\Software\Policies\Microsoft\Assistance\Client\1.0' = @(
        @{ 'key' = 'NoImplicitFeedback'; 'type' = 'exact'; 'value' = 1 }
    )
}
$SectionBitlocker = @{
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' = @(
        @{ 'key' = 'MaxDevicePasswordFailedAttempts'; 'type' = 'exact'; 'value' = 10 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs' = @(
        @{ 'key' = '1'; 'type' = 'exact'; 'value' = "PCI\CC_0C0A" }
    )
    'HKLM\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE' = @(
        @{ 'key' = 'RDVDenyWriteAccess'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses' = @(
        @{ 'key' = '1'; 'type' = 'exact'; 'value' = "{6bdd1fc1-810f-11d0-bec7-08002be2092f}" }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions' = @(
        @{ 'key' = 'DenyDeviceIDs'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'DenyDeviceClasses'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'DenyDeviceIDsRetroactive'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'DenyDeviceClassesRetroactive'; 'type' = 'exact'; 'value' = "{7ebefbc0-3200-11d2-b4c2-00a0C9697d07}, {c06ff265-ae09-48f0-812c-16753d7cba83}, {6bdd1fc1-810f-11d0-bec7-08002be2092f}" }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab' = @(
        @{ 'key' = 'DCSettingIndex'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'ACSettingIndex'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\FVE' = @(
        @{ 'key' = 'FDVEnforceUserCert'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'RDVDenyCrossOrg'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'FDVRecoveryKey'; 'type' = 'range'; 'value' = 1,2 },
        @{ 'key' = 'FDVAllowUserCert'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'RDVActiveDirectoryInfoToStore'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'OSRecoveryPassword'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'FDVDiscoveryVolumeType'; 'type' = 'exact'; 'value' = "<none>" },
        @{ 'key' = 'FDVPassphrase'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'FDVHideRecoveryPage'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'FDVActiveDirectoryBackup'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'EnableBDEWithNoTPM'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'FDVHardwareEncryption'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'RDVRequireActiveDirectoryBackup'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'OSManageDRA'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'OSAllowSecureBootForIntegrity'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'DisableExternalDMAUnderLock'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'RDVActiveDirectoryBackup'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'OSActiveDirectoryInfoToStore'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'RDVRecoveryKey'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'UseTPMKey'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'OSActiveDirectoryBackup'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'UseAdvancedStartup'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'FDVRecovery'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'OSRecovery'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'FDVManageDRA'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'OSRecoveryKey'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'RDVHardwareEncryption'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'RDVManageDRA'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'RDVHideRecoveryPage'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'FDVActiveDirectoryInfoToStore'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'UseTPMPIN'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'OSHideRecoveryPage'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'OSPassphrase'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'RDVRecoveryPassword'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'RDVAllowUserCert'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'UseEnhancedPin'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'RDVEnforceUserCert'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'FDVRecoveryPassword'; 'type' = 'range'; 'value' = 1,2 },
        @{ 'key' = 'UseTPM'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'OSHardwareEncryption'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'RDVRecovery'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'RDVDiscoveryVolumeType'; 'type' = 'exact'; 'value' = "<none>" },
        @{ 'key' = 'FDVRequireActiveDirectoryBackup'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'RDVPassphrase'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'UseTPMKeyPIN'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'OSRequireActiveDirectoryBackup'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection' = @(
        @{ 'key' = 'DeviceEnumerationPolicy'; 'type' = 'exact'; 'value' = 0 }
    )
}
function Format-Secedit {
    param (
        [Parameter(Mandatory = $true)]
        $seceditPath)
    #initilize the dictionary
    $secedit = @{}
    switch -regex -file $seceditPath {
        #Regex Expression "^\[(.+)\]" to search for brackets
        "^\[(.+)\]" { # Section
            $section = $matches[1]
            $secedit[$section] = @{}
        }
        #Regex Expression "(.+?)\s*=(.*)"" to search for content before and after "='s"
        "(.+?)\s*=(.*)" { # Key
            $name = $matches[1]
            $value = $matches[2] -replace "\*"
            $secedit[$section][$name] = $value
        }
    }
    #return the dictionary
    return $secedit
}
#Function to parse the user rights out of the secedit dictionary and into a seperate dictionary
function Format-UserRights {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$secedit
    )
    # Initialize the hashtable
    $UserRights = @{}
    
    # Loop through each key in the "Privilege Rights" section
    foreach ($key in $secedit["Privilege Rights"].Keys) {
        # Split the value by comma, trim whitespace, and exclude null entries
        $accounts = ($secedit["Privilege Rights"][$key] -split ",").Trim() | Where-Object { $_ -ne $null -and $_ -ne "" }
        
        # Convert the array of accounts to a comma-separated string
        $UserRights[$key] = $accounts -join ", "
    }
    
    # Return the hashtable
    return $UserRights
}
#helper function to convert SIDs to friendly names when the errors occur
function Convert-SidToFriendlyName {
    param (
        [Parameter(Mandatory = $true)]
        [string]$sid
    )
    $FriendlyNames = @{
    "Administrators" = "S-1-5-32-544"
    "Guests" = "S-1-5-32-546"
    "Local account" = "S-1-5-113"
    "Local Service" = "S-1-5-19"
    "Network Service" = "S-1-5-20"
    "NT AUTHORITY\Authenticated Users" = "S-1-5-11"
    "Remote Desktop Users" = "S-1-5-32-555"
    "Service" = "S-1-5-6"
    "Users" = "S-1-5-32-545"
    "NT VIRTUAL MACHINE\Virtual Machines" = "S-1-5-83-0"
    "Window Manager\Window Manager Group" = "S-1-5-90-0"
    "NT SERVICE\WdiServiceHost"= "S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"
    "Backup Operators"= "S-1-5-32-551"
    "Performance Log Users"= "S-1-5-32-559"
    "All Services" = "S-1-5-80-0"
    "Everyone" = "S-1-1-0"
    
}

    if ($FriendlyNames.ContainsValue($sid)) {
        return ($FriendlyNames.GetEnumerator() | Where-Object { $_.Value -eq $sid }).Name
    } else {
        return $sid
    }
}
function Compare-UserRights {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$currentRights
    )
    $expectedRights = @{
    "SeTrustedCredManAccessPrivilege" = $null
    "SeNetworkLogonRight" = "S-1-5-32-544, S-1-5-32-555"
    "SeTcbPrivilege" = $null
    "SeIncreaseQuotaPrivilege" = "S-1-5-32-544, S-1-5-19, S-1-5-20"
    "SeInteractiveLogonRight" = "S-1-5-32-544, S-1-5-32-545"
    "SeRemoteInteractiveLogonRight" = "S-1-5-32-544, S-1-5-32-555"
    "SeBackupPrivilege"= "S-1-5-32-544"
    "SeSystemtimePrivilege"= "S-1-5-32-544, S-1-5-19"
    "SeTimeZonePrivilege"= "S-1-5-32-544, S-1-5-19, S-1-5-32-545"
    "SeCreatePagefilePrivilege"= "S-1-5-32-544"
    "SeCreateTokenPrivilege"= $null
    "SeCreateGlobalPrivilege"= "S-1-5-32-544, S-1-5-19, S-1-5-20, S-1-5-6"
    "SeCreatePermanentPrivilege"= $null
    "SeCreateSymbolicLinkPrivilege"= "S-1-5-32-544"
    "SeDebugPrivilege"= "S-1-5-32-544"
    "SeDenyNetworkLogonRight"= "S-1-5-32-546"
    "SeDenyBatchLogonRight"= "S-1-5-32-546"
    "SeDenyServiceLogonRight"= "S-1-5-32-546"
    "SeDenyInteractiveLogonRight"= "S-1-5-32-546"
    "SeDenyRemoteInteractiveLogonRight"= "S-1-5-32-546"
    "SeEnableDelegationPrivilege"= $null
    "SeRemoteShutdownPrivilege"= "S-1-5-32-544"
    "SeAuditPrivilege"= "S-1-5-19, S-1-5-20"
    "SeImpersonatePrivilege"= "S-1-5-32-544, S-1-5-19, S-1-5-20, S-1-5-6"
    "SeIncreaseBasePriorityPrivilege"= "S-1-5-32-544, S-1-5-90-0"
    "SeLoadDriverPrivilege"= "S-1-5-32-544"
    "SeLockMemoryPrivilege"= $null
    "SeBatchLogonRight"= "S-1-5-32-544"
    "SeServiceLogonRight"= "WDAGUtilityAccount"
    "SeSecurityPrivilege"= "S-1-5-32-544"
    "SeRelabelPrivilege"= $null
    "SeSystemEnvironmentPrivilege"= "S-1-5-32-544"
    "SeManageVolumePrivilege"= "S-1-5-32-544"
    "SeProfileSingleProcessPrivilege"= "S-1-5-32-544"
    "SeSystemProfilePrivilege"= "S-1-5-32-544, S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"
    "SeAssignPrimaryTokenPrivilege"= "S-1-5-19, S-1-5-20"
    "SeRestorePrivilege"= "S-1-5-32-544"
    "SeShutdownPrivilege"= "S-1-5-32-544, S-1-5-32-545"
    "SeTakeOwnershipPrivilege"= "S-1-5-32-544"
}
    $errorCount = 0
    #function to reorginize the values so that they are in the same order for the comparison
    function Format-Value {
        param (
            [string]$value
        )
        #split out each SID then convert them to a friendly name sort them and write them back to a string and return it in the same format
        $format = ($value -split ",\s*").Trim() | ForEach-Object {
            Convert-SidToFriendlyName -sid $_ 
        } | Sort-Object | Out-String -Stream
        return ($format -join ", ").Trim()
    }
    #loop through the expected rights table 
    foreach ($key in $expectedRights.Keys) {
        #collect the current value when "noone" is confiugred it doesnt have they key in the secedit file so we slap a null so that it can still be evaluated
        $currentValue = if ($currentRights.ContainsKey($key)) { Format-Value $currentRights[$key]} else { $null }
        #collect the expected value if its not null then convert it if it is null then right null back to the value
        #for some reason it wouldnt correctly evaluate the hash table null as an actual null so i reset it here. Its messy but its how i got it to work
        $expectedValue = if(-not $null -eq $expectedRights[$key]) { Format-Value $expectedRights[$key]} else { $null }
        #evaluate and only write out the keys with problems 
        if ($currentValue -ne $expectedValue) {
            Write-Host "Discrepancy for key '$key':" -ForegroundColor Red
            Write-Host "  Current:  $currentValue" -ForegroundColor Red
            Write-Host "  Expected: $expectedValue" -ForegroundColor Red
            #increment the error count for "grading"
            $errorCount++
        } 
    }

    return $errorCount
}
function Compare-Sec-Acc-Policies {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$secedit)

    # Initialize an error counter
    $errorCount = 0
    # Iterate over the expected policies
    foreach ($key in $secedit["System Access"].Keys) {
    switch ($key) {
    'PasswordHistorySize' {
        $currentValue = $secedit["System Access"]["PasswordHistorySize"].Trim()
        if($currentValue -lt 24 -or $null -eq $currentValue){
            Write-host("$key is not compliant") -ForegroundColor Red
            $errorCount++
        }
    }
    'MaximumPasswordAge' {
        $currentValue = $secedit["System Access"]["MaximumPasswordAge"].Trim()
        if($currentValue -eq 0 -or $currentValue -gt 365 -or $null -eq $currentValue){
            Write-host("$key is not compliant") -ForegroundColor Red
            $errorCount++
        }
    }
    'MinimumPasswordAge' {
        $currentValue = $secedit["System Access"]["MinimumPasswordAge"].Trim()
        if($currentValue -eq 0 -or $null -eq $currentValue){
            Write-host("$key is not compliant") -ForegroundColor Red
            $errorCount++
        }
    }
    'MinimumPasswordLength' {
        $currentValue = $secedit["System Access"]["MinimumPasswordLength"].Trim()
        if($currentValue -lt 14 -or $null -eq $currentValue){
            Write-host("$key is not compliant") -ForegroundColor Red
            $errorCount++
        }
    }
    'PasswordComplexity' {
        $currentValue = $secedit["System Access"]["PasswordComplexity"].Trim()
        if($currentValue -eq 0 -or $null -eq $currentValue){
            Write-host("$key is not compliant") -ForegroundColor Red
            $errorCount++
        }
    }
    'ClearTextPassword' {
        $currentValue = $secedit["System Access"]["ClearTextPassword"].Trim()
        if($currentValue -ne 0 -or $null -eq $currentValue){
            Write-host("$key is not compliant") -ForegroundColor Red
            $errorCount++
        }
    }
    'LockoutDuration' {
        $currentValue = $secedit["System Access"]["LockoutDuration"].Trim()
        if($currentValue -lt 15 -or $null -eq $currentValue){
            Write-host("$key is not compliant") -ForegroundColor Red
            $errorCount++
        }
    }
    'LockoutBadCount' {
        $currentValue = $secedit["System Access"]["LockoutBadCount"].Trim()
        if($currentValue -eq 0 -or $currentValue -gt 5 -or $null -eq $currentValue){
            Write-host("$key is not compliant") -ForegroundColor Red
            $errorCount++
        }
    }
    'AllowAdministratorLockout' {
        $currentValue = $secedit["System Access"]["AllowAdministratorLockout"].Trim()
        if($currentValue -ne 1 -or $null -eq $currentValue){
            Write-host("$key is not compliant") -ForegroundColor Red
            $errorCount++
        }
    }
    'ResetLockoutCount' {
        $currentValue = $secedit["System Access"]["ResetLockoutCount"].Trim()
        if($currentValue -lt 15 -or $null -eq $currentValue){
            Write-host("$key is not compliant") -ForegroundColor Red
            $errorCount++
        }
    }
    'EnableGuestAccount' {
        $currentValue = $secedit["System Access"]["EnableGuestAccount"].Trim()
        if($currentValue -ne 0 -or $null -eq $currentValue){
            Write-host("$key is not compliant") -ForegroundColor Red
            $errorCount++
        }
    }
    'NewAdministratorName' {
        $currentValue = $secedit["System Access"]["NewAdministratorName"].Trim()
        if($currentValue -notmatch "^(?!.*\bAdministrator\b).*$" -or $null -eq $currentValue){
            Write-host("$key is not compliant") -ForegroundColor Red
            $errorCount++
        }
    }
    'NewGuestName' {
        $currentValue = $secedit["System Access"]["NewGuestName"].Trim()
        if($currentValue -notmatch "^(?!.*\bGuest\b).*$" -or $null -eq $currentValue){
            Write-host("$key is not compliant") -ForegroundColor Red
            $errorCount++
        }
        
    }
    'LSAAnonymousNameLookup' {
        $currentValue = $secedit["System Access"]["LSAAnonymousNameLookup"].Trim()
        if($currentValue -ne 0 -or $null -eq $currentValue){
            Write-host("$key is not compliant") -ForegroundColor Red
            $errorCount++
        }
    }
    'ForceLogoffWhenHourExpire' {
        $currentValue = $secedit["System Access"]["ForceLogoffWhenHourExpire"].Trim()
        if($currentValue -ne 1 -or $null -eq $currentValue){
            Write-host("$key is not compliant") -ForegroundColor Red
            $errorCount++
        }
    }
    default {
        #do nothing as there are some keys under system access we dont need to evaluate
    }
    }
}    

    # Return the total number of errors found
    return $errorCount
   

}
function Compare-Audit-Policies{
    $expectedAuditPolicies = @{
    "Credential Validation" = "Success and Failure"
    "Application Group Management" = "Success and Failure"
    "Security Group Management" = "Success"
    "User Account Management" = "Success and Failure"
    "Plug and Play Events" = "Success"
    "Process Creation" = "Success"
    "Account Lockout" = "Failure"
    "Group Membership" = "Success"
    "Logoff" = "Success"
    "Logon" = "Success and Failure"
    "Other Logon/Logoff Events" = "Success and Failure"
    "Special Logon" = "Success"
    "Detailed File Share" = "Failure"
    "File Share" = "Success and Failure"
    "Other Object Access Events" = "Success and Failure"
    "Removable Storage" = "Success and Failure"
    "Audit Policy Change" = "Success"
    "Authentication Policy Change" = "Success"
    "MPSSVC Rule-Level Policy Change" = "Success and Failure"
    "Other Policy Change Events" = "Failure"
    "Sensitive Privilege Use" = "Success and Failure"
    "IPsec Driver" = "Success and Failure"
    "Other System Events" = "Success and Failure"
    "Security State Change" = "Success"
    "Security System Extension" = "Success"
    "System Integrity" = "Success and Failure"
    }
    # Initialize an error counter
        $errorCount = 0
    
        # Loop through the expected audit policies
        foreach ($key in $expectedAuditPolicies.Keys) {
            # Run auditpol to get the current setting for the subcategory
            $auditpolOutput = auditpol /get /subcategory:"$key" /r | ConvertFrom-Csv
            $currentAuditPolicy = $auditpolOutput.'Inclusion Setting'
    
            # If no match is found or it's "No Auditing", set it to "None"
            if (-not $currentAuditPolicy -or $currentAuditPolicy -eq "No Auditing") {
                $currentAuditPolicy = "None"
            }
    
            # Get the expected value
            $expectedValue = $expectedAuditPolicies[$key]
    
            # Check if the current value matches the expected value
            if ($currentAuditPolicy -ne $expectedValue) {
                Write-Host "Discrepancy for '$key':" -ForegroundColor Red
                Write-Host "  Current:  $currentAuditPolicy" -ForegroundColor Red
                Write-Host "  Expected: $expectedValue" -ForegroundColor Red
                $errorCount++
            }
        }
    
        # Return the total number of errors found
        return $errorCount
    }
function Compare-RegistryKeys {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$RegistryConfig
    )
    $errorCount = 0
    $currentUserSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

    foreach ($path in $RegistryConfig.Keys) {
        $originalPath = $path
        if ($path -match '^HKU\\'){
            $regPath = $path -replace '\[USER SID\]', $currentUserSID
            $regPath = $regpath -replace '^HKU\\', 'Registry::HKEY_USERS\'
        }
        Else{
            $regPath = $path -replace '^HKLM\\', 'HKLM:\'
        }
        $keyInfoArray = $RegistryConfig[$originalPath]
        
        foreach ($keyInfo in $keyInfoArray) {
            try {
                $currentValue = Get-ItemProperty -Path $regPath -Name $keyInfo.key -ErrorAction Stop | 
                                    Select-Object -ExpandProperty $keyInfo.key
                switch ($keyInfo.type) {
                    'exact' {
                        if ($currentValue -ne $keyInfo.value) {
                            Write-Host "Discrepancy found in $regPath" -ForegroundColor Red
                            Write-Host "  Key: $($keyInfo.key)" -ForegroundColor Red
                            Write-Host "  Current Value: $currentValue" -ForegroundColor Red
                            Write-Host "  Expected Value: $($keyInfo.value)" -ForegroundColor Red
                            $errorCount++
                        }
                    }
                    'range' {
                        $acceptedValues = $keyInfo.value -split ','
                        if ($currentValue -notin $acceptedValues) {
                            Write-Host "Discrepancy found in $regPath" -ForegroundColor Red
                            Write-Host "  Key: $($keyInfo.key)" -ForegroundColor Red
                            Write-Host "  Current Value: $currentValue" -ForegroundColor Red
                            Write-Host "  Expected Values: $($keyInfo.value)" -ForegroundColor Red
                            $errorCount++
                        }
                    }
                    'comparison' {
                        $comparisonString = $keyInfo.value -replace 'x', $currentValue
                        if (!(Invoke-Expression $comparisonString)) {
                            Write-Host "Discrepancy found in $regPath" -ForegroundColor Red
                            Write-Host "  Key: $($keyInfo.key)" -ForegroundColor Red
                            Write-Host "  Current Value: $currentValue" -ForegroundColor Red
                            Write-Host "  Expected Condition: $($keyInfo.value)" -ForegroundColor Red
                            $errorCount++
                        }
                    }
                }
            }
            catch {
                Write-Host "Registry path does not exist: $regPath\$($keyInfo.key)" -ForegroundColor Yellow
                $errorCount++
            }
        }
    }
    return $errorCount
}
#
#
#
#
#run the Parse-secedit function
$secedit = Format-Secedit -seceditPath $seceditPath
#run the Parse-UserRights function
$UserRights = Format-UserRights -secedit $secedit
# Compare rights and get error count
$UserRightsErrors = Compare-UserRights -currentRights $UserRights
$SecAccErrors = Compare-Sec-Acc-Policies -secedit $secedit
$AuditPolicyErrors = Compare-Audit-Policies
$L1Section1Errors = Compare-RegistryKeys -RegistryConfig $L1Section1
$L1Section2Errors = Compare-RegistryKeys -RegistryConfig $L1Section2
$L1Section5Errors = Compare-RegistryKeys -RegistryConfig $L1Section5
$L1Section9Errors = Compare-RegistryKeys -RegistryConfig $L1Section9
$L1Section18Errors = Compare-RegistryKeys -RegistryConfig $L1Section18
$L1Section19Errors = Compare-RegistryKeys -RegistryConfig $L1Section19
$L2Section2Errors = Compare-RegistryKeys -RegistryConfig $L2Section2
$L2Section5Errors = Compare-RegistryKeys -RegistryConfig $L2Section5
$L2Section18Errors = Compare-RegistryKeys -RegistryConfig $L2Section18
$L2Section19Errors = Compare-RegistryKeys -RegistryConfig $L2Section19
$SectionBitlockerErrors = Compare-RegistryKeys -RegistryConfig $SectionBitlocker
$ErrorsArray = @(
    $UserRightsErrors, $SecAccErrors, $AuditPolicyErrors, $L1Section1Errors, 
    $L1Section2Errors, $L1Section5Errors, $L1Section9Errors, $L1Section18Errors,
    $L1Section19Errors, $L2Section2Errors, $L2Section5Errors, $L2Section18Errors,
    $L2Section19Errors, $SectionBitlockerErrors
)
$PossibleAnswers = @{
    UserRights = 39
    SecAcc = 15
    AuditPolicy = 26
    L1Section1 = 1
    L1Section2 = 51
    L1Section5 = 21
    L1Section9 = 16
    L1Section18 = 188
    L1Section19 = 9
    L2Section2 = 2
    L2Section5 = 24
    L2Section18 = 79
    L2Section19 = 4
    SectionBitlocker = 60
}
# Function to calculate the percentage for each section
function GetPercentage {
    param (
        [int]$Errors,
        [int]$Total
    )
    return [math]::Round((($Total - $Errors) / $Total) * 100, 2)
}
$Percentages = @{
    UserRights = GetPercentage $UserRightsErrors $PossibleAnswers.UserRights
    SecAcc = GetPercentage $SecAccErrors $PossibleAnswers.SecAcc
    AuditPolicy = GetPercentage $AuditPolicyErrors $PossibleAnswers.AuditPolicy
    L1Section1 = GetPercentage $L1Section1Errors $PossibleAnswers.L1Section1
    L1Section2 = GetPercentage $L1Section2Errors $PossibleAnswers.L1Section2
    L1Section5 = GetPercentage $L1Section5Errors $PossibleAnswers.L1Section5
    L1Section9 = GetPercentage $L1Section9Errors $PossibleAnswers.L1Section9
    L1Section18 = GetPercentage $L1Section18Errors $PossibleAnswers.L1Section18
    L1Section19 = GetPercentage $L1Section19Errors $PossibleAnswers.L1Section19
    L2Section2 = GetPercentage $L2Section2Errors $PossibleAnswers.L2Section2
    L2Section5 = GetPercentage $L2Section5Errors $PossibleAnswers.L2Section5
    L2Section18 = GetPercentage $L2Section18Errors $PossibleAnswers.L2Section18
    L2Section19 = GetPercentage $L2Section19Errors $PossibleAnswers.L2Section19
    SectionBitlocker = GetPercentage $SectionBitlockerErrors $PossibleAnswers.SectionBitlocker
}

# Calculate L1, L2, and Total percentages
$L1TotalErrors = $L1Section1Errors + $L1Section2Errors + $L1Section5Errors + $L1Section9Errors + $L1Section18Errors + $L1Section19Errors
$L1TotalPossible = $PossibleAnswers.L1Section1 + $PossibleAnswers.L1Section2 + $PossibleAnswers.L1Section5 + $PossibleAnswers.L1Section9 + $PossibleAnswers.L1Section18 + $PossibleAnswers.L1Section19
$L1Percentage = GetPercentage $L1TotalErrors $L1TotalPossible

$L2TotalErrors = $L2Section2Errors + $L2Section5Errors + $L2Section18Errors + $L2Section19Errors
$L2TotalPossible = $PossibleAnswers.L2Section2 + $PossibleAnswers.L2Section5 + $PossibleAnswers.L2Section18 + $PossibleAnswers.L2Section19
$L2Percentage = GetPercentage $L2TotalErrors $L2TotalPossible

$TotalErrors = $ErrorsArray | Measure-Object -Sum
$TotalPossible = $PossibleAnswers.Values | Measure-Object -Sum
$TotalPercentage = GetPercentage $TotalErrors.Sum $TotalPossible.Sum

# Create a table with the results
$Results = @()
$Results += [PSCustomObject]@{ Section = "User Rights"; Percentage = $Percentages.UserRights }
$Results += [PSCustomObject]@{ Section = "Sec Acc"; Percentage = $Percentages.SecAcc }
$Results += [PSCustomObject]@{ Section = "Audit Policy"; Percentage = $Percentages.AuditPolicy }
$Results += [PSCustomObject]@{ Section = "L1 Section 1"; Percentage = $Percentages.L1Section1 }
$Results += [PSCustomObject]@{ Section = "L1 Section 2"; Percentage = $Percentages.L1Section2 }
$Results += [PSCustomObject]@{ Section = "L1 Section 5"; Percentage = $Percentages.L1Section5 }
$Results += [PSCustomObject]@{ Section = "L1 Section 9"; Percentage = $Percentages.L1Section9 }
$Results += [PSCustomObject]@{ Section = "L1 Section 18"; Percentage = $Percentages.L1Section18 }
$Results += [PSCustomObject]@{ Section = "L1 Section 19"; Percentage = $Percentages.L1Section19 }
$Results += [PSCustomObject]@{ Section = "L2 Section 2"; Percentage = $Percentages.L2Section2 }
$Results += [PSCustomObject]@{ Section = "L2 Section 5"; Percentage = $Percentages.L2Section5 }
$Results += [PSCustomObject]@{ Section = "L2 Section 18"; Percentage = $Percentages.L2Section18 }
$Results += [PSCustomObject]@{ Section = "L2 Section 19"; Percentage = $Percentages.L2Section19 }
$Results += [PSCustomObject]@{ Section = "Bitlocker"; Percentage = $Percentages.SectionBitlocker }
$Results += [PSCustomObject]@{ Section = "L1 Total"; Percentage = $L1Percentage }
$Results += [PSCustomObject]@{ Section = "L2 Total"; Percentage = $L2Percentage }
$Results += [PSCustomObject]@{ Section = "Overall Total"; Percentage = $TotalPercentage }

# Output the table
$Results | Format-Table -AutoSize