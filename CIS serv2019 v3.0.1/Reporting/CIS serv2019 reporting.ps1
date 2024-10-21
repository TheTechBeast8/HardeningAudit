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
# Check if the system is a Domain Controller by querying the domain role
$domainRole = (Get-WmiObject Win32_ComputerSystem).DomainRole
if ($domainRole -eq 4 -or $domainRole -eq 5) {
    global:$IsDC = $true
}
$L1Section2DC = @{
    'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' = @(
        @{ 'key' = 'LDAPServerIntegrity'; 'type' = 'exact'; 'value' = 2 },
        @{ 'key' = 'LdapEnforceChannelBinding'; 'type' = 'exact'; 'value' = 2 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' = @(
        @{ 'key' = 'SubmitControl'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' = @(
        @{ 'key' = 'VulnerableChannelAllowList'; 'type' = 'exact'; 'value' = "does not exist" },
        @{ 'key' = 'AuditNTLMInDomain'; 'type' = 'exact'; 'value' = 7 }
    )
    'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' = @(
        @{ 'key' = 'NullSessionPipes'; 'type' = 'exact'; 'value' = "LSARPC, NETLOGON, SAMR" }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' = @(
        @{ 'key' = 'RefusePasswordChange'; 'type' = 'exact'; 'value' = 0 }
    )
}
$L1Section2MS = @{
    'HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' = @(
        @{ 'key' = 'NullSessionPipes'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'SMBServerNameHardeningLevel'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' = @(
        @{ 'key' = 'RestrictAnonymousSAM'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'RestrictAnonymous'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa' = @(
        @{ 'key' = 'restrictremotesam'; 'type' = 'exact'; 'value' = "O:BAG:BAD:(A;;RC;;;BA)" }
    )
    'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' = @(
        @{ 'key' = 'ForceUnlockLogon'; 'type' = 'exact'; 'value' = 1 }
    )
}
$L1Section2MSDC = @{
    'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' = @(
        @{ 'key' = 'EnablePlainTextPassword'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'EnableSecuritySignature'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'RequireSecuritySignature'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers' = @(
        @{ 'key' = 'AddPrinterDrivers'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel' = @(
        @{ 'key' = 'ObCaseInsensitive'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' = @(
        @{ 'key' = 'PasswordExpiryWarning'; 'type' = 'exact'; 'value' = 14 },
        @{ 'key' = 'ScRemoveOption'; 'type' = 'exact'; 'value' = 3 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\pku2u' = @(
        @{ 'key' = 'AllowOnlineID'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' = @(
        @{ 'key' = 'AutoDisconnect'; 'type' = 'exact'; 'value' = 15 },
        @{ 'key' = 'NullSessionShares'; 'type' = 'exact'; 'value' = "<none>" }
    )
    'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' = @(
        @{ 'key' = 'NoConnectedUser'; 'type' = 'exact'; 'value' = 3 },
        @{ 'key' = 'LegalNoticeText'; 'type' = 'exact'; 'value' = "Sample Text" },
        @{ 'key' = 'LegalNoticeCaption'; 'type' = 'exact'; 'value' = "Sample Text" },
        @{ 'key' = 'InactivityTimeoutSecs'; 'type' = 'exact'; 'value' = 900 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' = @(
        @{ 'key' = 'CrashOnAuditFail'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'ForceGuest'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'NoLMHash'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'LimitBlankPasswordUse'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'UseMachineId'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'SCENoApplyLegacyAuditPolicy'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'EveryoneIncludesAnonymous'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' = @(
        @{ 'key' = 'SupportedEncryptionTypes'; 'type' = 'exact'; 'value' = 2147483640 }
    )
    'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths' = @(
        @{ 'key' = 'Machine'; 'type' = 'exact'; 'value' = "System\CurrentControlSet\Control\ProductOptions System\CurrentControlSet\Control\Server Applications Software\Microsoft\Windows NT\CurrentVersion" }
    )
    'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' = @(
        @{ 'key' = 'AuditReceivingNTLMTraffic'; 'type' = 'exact'; 'value' = 2 },
        @{ 'key' = 'RestrictSendingNTLMTraffic'; 'type' = 'exact'; 'value' = 2 },
        @{ 'key' = 'AllowNullSessionFallback'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths' = @(
        @{ 'key' = 'Machine'; 'type' = 'exact'; 'value' = "System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Contr
ol\ContentIndex,System\CurrentControlS
et\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog,System\CurrentControlSet\Services\CertSvc,System\CurrentC

ontrolSet\Services\WINS" }
    )
    'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' = @(
        @{ 'key' = 'NTLMMinServerSec'; 'type' = 'exact'; 'value' = 537395200 },
        @{ 'key' = 'NTLMMinClientSec'; 'type' = 'exact'; 'value' = 537395200 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\LDAP' = @(
        @{ 'key' = 'LDAPClientIntegrity'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager' = @(
        @{ 'key' = 'ProtectionMode'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' = @(
        @{ 'key' = 'DontDisplayLastUserName'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'ShutdownWithoutLogon'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'ConsentPromptBehaviorAdmin'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'EnableInstallerDetection'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'ConsentPromptBehaviorUser'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'EnableSecureUIAPaths'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'FilterAdministratorToken'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'EnableLUA'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'EnableVirtualization'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'PromptOnSecureDesktop'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'DisableCAD'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa' = @(
        @{ 'key' = 'TurnOffAnonymousBlock'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'LmCompatibilityLevel'; 'type' = 'exact'; 'value' = 5 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' = @(
        @{ 'key' = 'SealSecureChannel'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'RequireSignOrSeal'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'DisablePasswordChange'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'SignSecureChannel'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'RequireStrongKey'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'MaximumPasswordAge'; 'type' = 'exact'; 'value' = 30 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' = @(
        @{ 'key' = 'EnableSecuritySignature'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'RequireSecuritySignature'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'RestrictNullSessAccess'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'enableforcedlogoff'; 'type' = 'exact'; 'value' = 1 }
    )
}
$L1Section5DC = @{
    'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
}
$L1Section9MSDC = @{
    'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging' = @(
        @{ 'key' = 'LogFilePath'; 'type' = 'exact'; 'value' = "%SystemRoot%\System32\logfiles\firewall\privatefw.log" },
        @{ 'key' = 'LogFileSize'; 'type' = 'exact'; 'value' = 16384 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging' = @(
        @{ 'key' = 'LogDroppedPackets'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'LogSuccessfulConnections'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging' = @(
        @{ 'key' = 'LogFilePath'; 'type' = 'exact'; 'value' = "%SystemRoot%\System32\logfiles\firewall\domainfw.log" },
        @{ 'key' = 'LogFileSize'; 'type' = 'exact'; 'value' = 16384 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile' = @(
        @{ 'key' = 'DisableNotifications'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'EnableFirewall'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'DefaultInboundAction'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging' = @(
        @{ 'key' = 'LogDroppedPackets'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'LogSuccessfulConnections'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging' = @(
        @{ 'key' = 'LogDroppedPackets'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'LogSuccessfulConnections'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging' = @(
        @{ 'key' = 'LogFilePath'; 'type' = 'exact'; 'value' = "%SystemRoot%\System32\logfiles\firewall\publicfw.log" },
        @{ 'key' = 'LogFileSize'; 'type' = 'exact'; 'value' = 16384 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile' = @(
        @{ 'key' = 'DisableNotifications'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'EnableFirewall'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'DefaultInboundAction'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' = @(
        @{ 'key' = 'DisableNotifications'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'EnableFirewall'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'AllowLocalIPsecPolicyMerge'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'DefaultInboundAction'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'AllowLocalPolicyMerge'; 'type' = 'exact'; 'value' = 0 }
    )
}
$L1Section18MS = @{
    'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc' = @(
        @{ 'key' = 'EnableAuthEpResolution'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' = @(
        @{ 'key' = 'EnumerateLocalUsers'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' = @(
        @{ 'key' = 'LocalAccountTokenFilterPolicy'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' = @(
        @{ 'key' = 'PasswordComplexity'; 'type' = 'exact'; 'value' = 4 },
        @{ 'key' = 'PasswordAgeDays'; 'type' = 'exact'; 'value' = 30 },
        @{ 'key' = 'ADPasswordEncryptionEnabled'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'BackupDirectory'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'PwdExpirationProtectionEnabled'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'PostAuthenticationResetDelay'; 'type' = 'exact'; 'value' = 8 },
        @{ 'key' = 'PasswordLength'; 'type' = 'exact'; 'value' = 15 },
        @{ 'key' = 'PostAuthenticationActions'; 'type' = 'exact'; 'value' = 3 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer' = @(
        @{ 'key' = 'Enabled'; 'type' = 'exact'; 'value' = 0 }
    )
}
$L1Section18DC = @{
    'HKLM\Software\Policies\Microsoft\Windows NT\Printers' = @(
        @{ 'key' = 'RegisterSpoolerRemoteRpcEndPoint'; 'type' = 'exact'; 'value' = 2 }
    )
}
$L1Section18MSDC = @{
    'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC' = @(
        @{ 'key' = 'ForceKerberosForRpc'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'RpcTcpPort'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'RpcAuthentication'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'RpcUseNamedPipeProtocol'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' = @(
        @{ 'key' = 'EnumerateAdministrators'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' = @(
        @{ 'key' = 'ManagePreviewBuildsPolicyValue'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager' = @(
        @{ 'key' = 'SafeDllSearchMode'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization' = @(
        @{ 'key' = 'AllowInputPersonalization'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System' = @(
        @{ 'key' = 'Retention'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds' = @(
        @{ 'key' = 'AllowBuildPreview'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' = @(
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
    'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' = @(
        @{ 'key' = 'ScreenSaverGracePeriod'; 'type' = 'exact'; 'value' = 5 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace' = @(
        @{ 'key' = 'AllowWindowsInkWorkspace'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' = @(
        @{ 'key' = 'DisableIPSourceRouting'; 'type' = 'exact'; 'value' = 2 }
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
    'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' = @(
        @{ 'key' = 'DisableExceptionChainValidation'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections' = @(
        @{ 'key' = 'NC_ShowSharedAccessUI'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'NC_StdDomainUserSetLocation'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'NC_AllowNetBridge_NLA'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller' = @(
        @{ 'key' = 'EnableMSAppInstallerProtocol'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'EnableHashOverride'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'EnableExperimentalFeatures'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'EnableAppInstaller'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' = @(
        @{ 'key' = 'BlockDomainPicturePassword'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'AllowDomainPINLogon'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'EnableCdp'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'DontDisplayNetworkSelectionUI'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'BlockUserFromShowingAccountDetailsOnSignin'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'DontEnumerateConnectedUsers'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'DisableLockScreenAppNotifications'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application' = @(
        @{ 'key' = 'Retention'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' = @(
        @{ 'key' = 'NoDriveTypeAutoRun'; 'type' = 'exact'; 'value' = 255 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine' = @(
        @{ 'key' = 'EnableFileHashComputation'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' = @(
        @{ 'key' = 'AllowProtectedCreds'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup' = @(
        @{ 'key' = 'MaxSize'; 'type' = 'exact'; 'value' = 32768 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\MicrosoftAccount' = @(
        @{ 'key' = 'DisableUserAuth'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection' = @(
        @{ 'key' = 'DoNotShowFeedbackNotifications'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'EnableOneSettingsAuditing'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'LimitDiagnosticLogCollection'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'DisableOneSettingsDownloads'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'LimitDumpCollection'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'AllowTelemetry'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' = @(
        @{ 'key' = 'NoNameReleaseOnDemand'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'NodeType'; 'type' = 'exact'; 'value' = 2 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR' = @(
        @{ 'key' = 'ExploitGuard_ASR_Rules'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb10' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' = @(
        @{ 'key' = 'RunAsPPL'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer' = @(
        @{ 'key' = 'NoAutoplayfornonVolume'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'NoHeapTerminationOnCorruption'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'NoDataExecutionPrevention'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}' = @(
        @{ 'key' = 'NoBackgroundPolicy'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'NoGPOListChanges'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer' = @(
        @{ 'key' = 'AlwaysInstallElevated'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'EnableUserControl'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' = @(
        @{ 'key' = 'AllowInsecureGuestAuth'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' = @(
        @{ 'key' = 'AllowIndexingEncryptedStoresOrItems'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' = @(
        @{ 'key' = 'EnableNetbios'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'EnableMulticast'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization' = @(
        @{ 'key' = 'NoLockScreenCamera'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'NoLockScreenSlideshow'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI' = @(
        @{ 'key' = 'DisablePasswordReveal'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' = @(
        @{ 'key' = 'fAllowToGetHelp'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'fAllowUnsolicited'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'UserAuthentication'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'fPromptForPassword'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'SecurityLayer'; 'type' = 'exact'; 'value' = 2 },
        @{ 'key' = 'fEncryptRPCTraffic'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'DeleteTempDirsOnExit'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'DisablePasswordSaving'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'PerSessionTempDir'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'fDisableCdm'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' = @(
        @{ 'key' = 'LocalSettingOverrideSpynetReporting'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Microsoft\Cryptography\Wintrust\Config' = @(
        @{ 'key' = 'EnableCertPaddingCheck'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' = @(
        @{ 'key' = 'DisableAutomaticRestartSignOn'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'MSAOptional'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' = @(
        @{ 'key' = '\\*\SYSVOL'; 'type' = 'exact'; 'value' = "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1" },
        @{ 'key' = '\\*\NETLOGON'; 'type' = 'exact'; 'value' = "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1" }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds' = @(
        @{ 'key' = 'DisableEnclosureDownload'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan' = @(
        @{ 'key' = 'DisablePackedExeScanning'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'DisableEmailScanning'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'DisableRemovableDriveScanning'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup' = @(
        @{ 'key' = 'Retention'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' = @(
        @{ 'key' = 'NoBackgroundPolicy'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'NoGPOListChanges'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent' = @(
        @{ 'key' = 'DisableConsumerAccountStateContent'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'DisableWindowsConsumerFeatures'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures' = @(
        @{ 'key' = 'EnhancedAntiSpoofing'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System' = @(
        @{ 'key' = 'MaxSize'; 'type' = 'exact'; 'value' = 32768 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect' = @(
        @{ 'key' = 'RequirePinForPairing'; 'type' = 'exact'; 'value' = 2 }
    )
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' = @(
        @{ 'key' = 'ProcessCreationIncludeCmdLine_Enabled'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Control\Print' = @(
        @{ 'key' = 'RpcAuthnLevelPrivacyEnabled'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' = @(
        @{ 'key' = 'DeferFeatureUpdatesPeriodInDays'; 'type' = 'exact'; 'value' = 180 },
        @{ 'key' = 'DeferFeatureUpdates'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'DeferQualityUpdatesPeriodInDays'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'DeferQualityUpdates'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC' = @(
        @{ 'key' = 'RpcProtocols'; 'type' = 'exact'; 'value' = 5 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' = @(
        @{ 'key' = 'NoAutoUpdate'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'ScheduledInstallDay'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'NoAutoRebootWithLoggedOnUsers'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata' = @(
        @{ 'key' = 'PreventDeviceMetadataFromNetwork'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' = @(
        @{ 'key' = 'MaxSize'; 'type' = 'exact'; 'value' = 196608 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' = @(
        @{ 'key' = 'Retention'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' = @(
        @{ 'key' = 'DisableRunAs'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'AllowUnencryptedTraffic'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'AllowBasic'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' = @(
        @{ 'key' = 'SMB1'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System' = @(
        @{ 'key' = 'ShellSmartScreenLevel'; 'type' = 'exact'; 'value' = "Block" },
        @{ 'key' = 'EnableSmartScreen'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers' = @(
        @{ 'key' = 'DisableWebPnPDownload'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'CopyFilesPolicy'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'RedirectionguardPolicy'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection' = @(
        @{ 'key' = 'DeviceEnumerationPolicy'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' = @(
        @{ 'key' = 'UseLogonCredential'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters' = @(
        @{ 'key' = 'AllowEncryptionOracle'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection' = @(
        @{ 'key' = 'DisallowExploitProtectionOverride'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' = @(
        @{ 'key' = 'DisableBkGndGroupPolicy'; 'type' = 'exact'; 'value' = "does not exist" }
    )
    'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application' = @(
        @{ 'key' = 'MaxSize'; 'type' = 'exact'; 'value' = 32768 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' = @(
        @{ 'key' = 'DisableIOAVProtection'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'DisableScriptScanning'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'DisableRealtimeMonitoring'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'DisableBehaviorMonitoring'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' = @(
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
    'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch' = @(
        @{ 'key' = 'DriverLoadPolicy'; 'type' = 'exact'; 'value' = 3 }
    )
    'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' = @(
        @{ 'key' = 'fMinimizeConnections'; 'type' = 'exact'; 'value' = 3 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection' = @(
        @{ 'key' = 'EnableNetworkProtection'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' = @(
        @{ 'key' = 'EnableICMPRedirect'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'DisableIPSourceRouting'; 'type' = 'exact'; 'value' = 2 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' = @(
        @{ 'key' = 'UpdatePromptSettings'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'NoWarningNoElevationOnInstall'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'RestrictDriverInstallationToAdministrators'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' = @(
        @{ 'key' = 'NoWebServices'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'PreXPSP2ShellProtocolBehavior'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'NoAutorun'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' = @(
        @{ 'key' = 'MinEncryptionLevel'; 'type' = 'exact'; 'value' = 3 }
    )
}
$L1Section19MSDC = @{
    'HKU\[USER SID]\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments' = @(
        @{ 'key' = 'SaveZoneInformation'; 'type' = 'exact'; 'value' = 2 },
        @{ 'key' = 'ScanWithAntiVirus'; 'type' = 'exact'; 'value' = 3 }
    )
    'HKU\[USER SID]\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' = @(
        @{ 'key' = 'NoInplaceSharing'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKU\[USER SID]\Software\Policies\Microsoft\Windows\Installer' = @(
        @{ 'key' = 'AlwaysInstallElevated'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKU\[USER SID]\Software\Policies\Microsoft\Windows\CloudContent' = @(
        @{ 'key' = 'ConfigureWindowsSpotlight'; 'type' = 'exact'; 'value' = 2 },
        @{ 'key' = 'DisableThirdPartySuggestions'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'DisableSpotlightCollectionOnDesktop'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKU\[USER SID]\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' = @(
        @{ 'key' = 'NoToastApplicationNotificationOnLockScreen'; 'type' = 'exact'; 'value' = 1 }
    )
}
$L2Section2MS = @{
    'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' = @(
        @{ 'key' = 'CachedLogonsCount'; 'type' = 'exact'; 'value' = 2 }
    )
}
$L2Section2MSDC = @{
    'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' = @(
        @{ 'key' = 'DisableDomainCreds'; 'type' = 'exact'; 'value' = 1 }
    )
}
$L2Section5MS = @{
    'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler' = @(
        @{ 'key' = 'Start'; 'type' = 'exact'; 'value' = 4 }
    )
}
$L2Section18MS = @{
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' = @(
        @{ 'key' = 'fBlockNonDomain'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc' = @(
        @{ 'key' = 'RestrictRemoteClients'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\Software\Policies\Microsoft\Windows NT\Printers' = @(
        @{ 'key' = 'RegisterSpoolerRemoteRpcEndPoint'; 'type' = 'exact'; 'value' = 2 }
    )
}
$L2Section18MSDC = @{
    'HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace' = @(
        @{ 'key' = 'AllowSuggestedAppsInWindowsInkWorkspace'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' = @(
        @{ 'key' = 'AllowAutoConfig'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting' = @(
        @{ 'key' = 'DisableGenericRePorts'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Peernet' = @(
        @{ 'key' = 'Disabled'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' = @(
        @{ 'key' = 'EnableScriptBlockLogging'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' = @(
        @{ 'key' = 'NoCloudApplicationNotification'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging' = @(
        @{ 'key' = 'AllowMessageSync'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters' = @(
        @{ 'key' = 'TcpMaxDataRetransmissions'; 'type' = 'exact'; 'value' = 3 }
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
        @{ 'key' = 'PerformRouterDiscovery'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars' = @(
        @{ 'key' = 'DisableFlashConfigRegistrar'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'DisableUPnPRegistrar'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'DisableWPDRegistrar'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'DisableInBand802DOT11Registrar'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'EnableRegistrars'; 'type' = 'exact'; 'value' = 0 }
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
    'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform' = @(
        @{ 'key' = 'NoGenTicket'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows' = @(
        @{ 'key' = 'CEIPEnable'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Control Panel\International' = @(
        @{ 'key' = 'BlockUserInputMethodsForSignIn'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC' = @(
        @{ 'key' = 'PreventHandwritingDataSharing'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\UI' = @(
        @{ 'key' = 'DisableWcnUi'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting' = @(
        @{ 'key' = 'DoReport'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy' = @(
        @{ 'key' = 'DisableQueryRemoteServer'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' = @(
        @{ 'key' = 'Disabled'; 'type' = 'exact'; 'value' = 1 }
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
        @{ 'key' = 'fDisableCcm'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'fDisableLPT'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'fDisablePNPRedir'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'fSingleSessionPerUser'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Camera' = @(
        @{ 'key' = 'AllowCamera'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters' = @(
        @{ 'key' = 'DevicePKInitBehavior'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'DevicePKInitEnabled'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9' = @(
        @{ 'key' = 'DCSettingIndex'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'ACSettingIndex'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard' = @(
        @{ 'key' = 'ExitOnMSICW'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' = @(
        @{ 'key' = 'TcpMaxDataRetransmissions'; 'type' = 'exact'; 'value' = 3 },
        @{ 'key' = 'KeepAliveTime'; 'type' = 'exact'; 'value' = 300000 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection' = @(
        @{ 'key' = 'DisableEnterpriseAuthProxy'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\PushToInstall' = @(
        @{ 'key' = 'DisablePushToInstall'; 'type' = 'exact'; 'value' = 1 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client' = @(
        @{ 'key' = 'CEIP'; 'type' = 'exact'; 'value' = 2 }
    )
    'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' = @(
        @{ 'key' = 'MaxDisconnectionTime'; 'type' = 'exact'; 'value' = 6000 },
        @{ 'key' = 'MaxIdleTime'; 'type' = 'exact'; 'value' = 900000 }
    )
    'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD' = @(
        @{ 'key' = 'AllowLLTDIOOnPublicNet'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'EnableRspndr'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'EnableLLTDIO'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'AllowRspndrOnDomain'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'ProhibitLLTDIOOnPrivateNet'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'AllowRspndrOnPublicNet'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'ProhibitRspndrOnPrivateNet'; 'type' = 'exact'; 'value' = 0 },
        @{ 'key' = 'AllowLLTDIOOnDomain'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' = @(
        @{ 'key' = 'DisabledByGroupPolicy'; 'type' = 'exact'; 'value' = 1 }
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
    'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security' = @(
        @{ 'key' = 'WarningLevel'; 'type' = 'exact'; 'value' = 90 }
    )
    'HKLM\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters' = @(
        @{ 'key' = 'DisabledComponents'; 'type' = 'exact'; 'value' = 255 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager' = @(
        @{ 'key' = 'AllowSharedLocalAppData'; 'type' = 'exact'; 'value' = 0 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\SearchCompanion' = @(
        @{ 'key' = 'DisableContentFileUpdates'; 'type' = 'exact'; 'value' = 1 }
    )
}
$L2Section19MSDC = @{
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
$NGSection18DC = @{
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' = @(
        @{ 'key' = 'LsaCfgFlags'; 'type' = 'exact'; 'value' = 0 }
    )
}
$NGSection18MS = @{
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' = @(
        @{ 'key' = 'HVCIMATRequired'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'LsaCfgFlags'; 'type' = 'exact'; 'value' = 1 }
    )
}
$NGSection18MSDC = @{
    'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' = @(
        @{ 'key' = 'RequirePlatformSecurityFeatures'; 'type' = 'exact'; 'value' = 3 }
    )
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' = @(
        @{ 'key' = 'HVCIMATRequired'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'EnableVirtualizationBasedSecurity'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'HypervisorEnforcedCodeIntegrity'; 'type' = 'exact'; 'value' = 1 },
        @{ 'key' = 'ConfigureSystemGuardLaunch'; 'type' = 'exact'; 'value' = 1 }
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
##Still need to review
function Compare-UserRights {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$currentRights
    )
    $expectedDCRights = @{
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
    $expectedMSRights = @{
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
    If (global:$IsDC = $true){
    #loop through the expected rights table 
    foreach ($key in $expectedDCRights.Keys) {
        #collect the current value when "noone" is confiugred it doesnt have they key in the secedit file so we slap a null so that it can still be evaluated
        $currentValue = if ($currentRights.ContainsKey($key)) { Format-Value $currentRights[$key]} else { $null }
        #collect the expected value if its not null then convert it if it is null then right null back to the value
        #for some reason it wouldnt correctly evaluate the hash table null as an actual null so i reset it here. Its messy but its how i got it to work
        $expectedValue = if(-not $null -eq $expectedDCRights[$key]) { Format-Value $expectedDCRights[$key]} else { $null }
        #evaluate and only write out the keys with problems 
        if ($currentValue -ne $expectedValue) {
            Write-Host "Discrepancy for key '$key':" -ForegroundColor Red
            Write-Host "  Current:  $currentValue" -ForegroundColor Red
            Write-Host "  Expected: $expectedValue" -ForegroundColor Red
            #increment the error count for "grading"
            $errorCount++
        } 
    }
    }
    Else{
    #loop through the expected rights table 
    foreach ($key in $expectedMSRights.Keys) {
        #collect the current value when "noone" is confiugred it doesnt have they key in the secedit file so we slap a null so that it can still be evaluated
        $currentValue = if ($currentRights.ContainsKey($key)) { Format-Value $currentRights[$key]} else { $null }
        #collect the expected value if its not null then convert it if it is null then right null back to the value
        #for some reason it wouldnt correctly evaluate the hash table null as an actual null so i reset it here. Its messy but its how i got it to work
        $expectedValue = if(-not $null -eq $expectedMSRights[$key]) { Format-Value $expectedMSRights[$key]} else { $null }
        #evaluate and only write out the keys with problems 
        if ($currentValue -ne $expectedValue) {
            Write-Host "Discrepancy for key '$key':" -ForegroundColor Red
            Write-Host "  Current:  $currentValue" -ForegroundColor Red
            Write-Host "  Expected: $expectedValue" -ForegroundColor Red
            #increment the error count for "grading"
            $errorCount++
        } 
    }
    }
    return $errorCount
}
##Still need to review
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
    $expectedDCAuditPolicies = @{
    "Credential Validation" = "Success and Failure"
    "Kerberos Authentication Service" = "Success and Failure"
    "Kerberos Service Ticket Operations" = "Success and Failure"
    "Application Group Management" = "Success and Failure"
    "Computer Account Management" = "Success"
    "Distribution Group Management" = "Success"
    "Other Account Management Events" = "Success"
    "Security Group Management" = "Success"
    "User Account Management" = "Success and Failure"
    "Plug and Play Events" = "Success"
    "Process Creation" = "Success"
    "Directory Service Access" = "Failure"
    "Directory Service Changes" = "Success"
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
    "Authorization Policy Change" = "Success"
    "MPSSVC Rule-Level Policy Change" = "Success and Failure"
    "Other Policy Change Events" = "Failure"
    "Sensitive Privilege Use" = "Success and Failure"
    "IPsec Driver" = "Success and Failure"
    "Other System Events" = "Success and Failure"
    "Security State Change" = "Success"
    "Security System Extension" = "Success"
    "System Integrity" = "Success and Failure"
    }
    $expectedMSAuditPolicies = @{
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
    "Authorization Policy Change" = "Success"
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
        IF (global:$IsDC = $true){
        # Loop through the expected audit policies
        foreach ($key in $expectedDCAuditPolicies.Keys) {
            # Run auditpol to get the current setting for the subcategory
            $auditpolOutput = auditpol /get /subcategory:"$key" /r | ConvertFrom-Csv
            $currentAuditPolicy = $auditpolOutput.'Inclusion Setting'

            # If no match is found or it's "No Auditing", set it to "None"
            if (-not $currentAuditPolicy -or $currentAuditPolicy -eq "No Auditing") {
                $currentAuditPolicy = "None"
            }

            # Get the expected value
            $expectedValue = $expectedDCAuditPolicies[$key]

            # Check if the current value matches the expected value
            if ($currentAuditPolicy -ne $expectedValue) {
                Write-Host "Discrepancy for '$key':" -ForegroundColor Red
                Write-Host "  Current:  $currentAuditPolicy" -ForegroundColor Red
                Write-Host "  Expected: $expectedValue" -ForegroundColor Red
                $errorCount++
            }
        }
        }
        Else{
            # Loop through the expected audit policies
        foreach ($key in $expectedMSAuditPolicies.Keys) {
            # Run auditpol to get the current setting for the subcategory
            $auditpolOutput = auditpol /get /subcategory:"$key" /r | ConvertFrom-Csv
            $currentAuditPolicy = $auditpolOutput.'Inclusion Setting'

            # If no match is found or it's "No Auditing", set it to "None"
            if (-not $currentAuditPolicy -or $currentAuditPolicy -eq "No Auditing") {
                $currentAuditPolicy = "None"
            }

            # Get the expected value
            $expectedValue = $expectedMSAuditPolicies[$key]

            # Check if the current value matches the expected value
            if ($currentAuditPolicy -ne $expectedValue) {
                Write-Host "Discrepancy for '$key':" -ForegroundColor Red
                Write-Host "  Current:  $currentAuditPolicy" -ForegroundColor Red
                Write-Host "  Expected: $expectedValue" -ForegroundColor Red
                $errorCount++
            }
        }
        }
        # Return the total number of errors found
        return $errorCount
}
##Still need to review
function Compare-RegistryKeys {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$RegistryConfig
    )
    #initialzie error count
    $errorCount = 0
    #collect current user SID for use in User specific keys
    $currentUserSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    #loop through each  hive path in each hashtable
    foreach ($path in $RegistryConfig.Keys) {
        #keep the original path
        $originalPath = $path
        #if it is a user key replace some variables with the proper info
        if ($path -match '^HKU\\'){
            $regPath = $path -replace '\[USER SID\]', $currentUserSID
            #also modify to specifically look at the registry 
            $regPath = $regpath -replace '^HKU\\', 'Registry::HKEY_USERS\'
        }
        Else{
            #if its a local machine key rewrite it to make sure they are all formated the same
            $regPath = $path -replace '^HKLM\\', 'HKLM:\'
        }
        #this is now peaking into the sub array under each hive path
        $keyInfoArray = $RegistryConfig[$originalPath]
        #loop through each registry value under each path
        foreach ($keyInfo in $keyInfoArray) {
            #have a try statement since some times it can fail to complete 
            try {
                #collect the current value if the path doesnt exist then error action stop to immediatly drop to the catch 
                $currentValue = Get-ItemProperty -Path $regPath -Name $keyInfo.key -ErrorAction Stop | 
                                    Select-Object -ExpandProperty $keyInfo.key
                #Legal notice title and body can be any text the company sees fit not a defined value
                #checks to make sure its not empty
                if ($keyInfo.value -eq '*' -or $keyInfo.value -eq 'any') {
                    # Skip comparison if any value is fine
                    continue
                }
                #looks at they type field in all the defind hashtables and performs a specific type of comparison
                switch ($keyInfo.type) {
                    #if the type is exact it does a normal 1=1 comparison
                    'exact' {
                        if ($currentValue -ne $keyInfo.value) {
                            Write-Host "Discrepancy found in $regPath" -ForegroundColor Red
                            Write-Host "  Key: $($keyInfo.key)" -ForegroundColor Red
                            Write-Host "  Current Value: $currentValue" -ForegroundColor Red
                            Write-Host "  Expected Value: $($keyInfo.value)" -ForegroundColor Red
                            $errorCount++
                        }
                    }
                    #if the type is range it accepts a range of values and splits them all and checks them 1 in 1,2,3 is a pass 0 in 1,2,3 is a fail
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
                    #if the type is comparison it does a exact lookup on the text i provided in the value where it replaces x with the current value 
                    #example x -gt 5 where x is 1 would fail since -gt is greater than
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
                    #if the type is text the it does a conversion of the current value to a string then compares them. 
                    'text' {
                    $ExpectedValue = $keyInfo.value
                    [string]$currentValueString = $currentValue
                    if ($currentValueString -ne $ExpectedValue) {
                        Write-Host "Discrepancy found in $regPath" -ForegroundColor Red
                        Write-Host "  Key: $($keyInfo.key)" -ForegroundColor Red
                        Write-Host "  Current Value: $currentValueString" -ForegroundColor Red
                        Write-Host "  Expected Value: $($keyInfo.value)" -ForegroundColor Red
                        $errorCount++
                      }
                    }
                }
            }
            catch {
                #the catch for all the errors in the current value lookup land here 
                #if the type is not noexistOK then it increments the error count
                #if it is noexistOK then nothing happnes as its fine it doesnt exist 
                If ($keyInfo.type -ne "noexistOK"){
                    Write-Host "Registry path does not exist: $regPath\$($keyInfo.key)" -ForegroundColor Yellow
                    $errorCount++
                }    


            }
        }
    }
    return $errorCount
}
#
#
#
#Code that acutally does stuff all above code are just definitions and functions
#
#run the Format-Secedit function
$secedit = Format-Secedit -seceditPath $seceditPath
#run the Format-UserRights function
$UserRights = Format-UserRights -secedit $secedit
# Compare rights and get error count for each section
$UserRightsErrors = Compare-UserRights -currentRights $UserRights
$SecAccErrors = Compare-Sec-Acc-Policies -secedit $secedit
$AuditPolicyErrors = Compare-Audit-Policies
$L1Section2DCErrors = Compare-RegistryKeys -RegistryConfig $L1Section2DC
$L1Section2MSErrors = Compare-RegistryKeys -RegistryConfig $L1Section2MS
$L1Section2MSDCErrors = Compare-RegistryKeys -RegistryConfig $L1Section2MSDC
$L1Section5DCErrors = Compare-RegistryKeys -RegistryConfig $L1Section5DC
$L1Section9MSDCErrors = Compare-RegistryKeys -RegistryConfig $L1Section9MSDC
$L1Section18MSErrors = Compare-RegistryKeys -RegistryConfig $L1Section18MS
$L1Section18DCErrors = Compare-RegistryKeys -RegistryConfig $L1Section18DC
$L1Section18MSDCErrors = Compare-RegistryKeys -RegistryConfig $L1Section18MSDC
$L1Section19MSDCErrors = Compare-RegistryKeys -RegistryConfig $L1Section19MSDC
$L2Section2MSErrors = Compare-RegistryKeys -RegistryConfig $L2Section2MS
$L2Section2MSDCErrors = Compare-RegistryKeys -RegistryConfig $L2Section2MSDC
$L2Section5MSErrors = Compare-RegistryKeys -RegistryConfig $L2Section5MS
$L2Section18MSErrors = Compare-RegistryKeys -RegistryConfig $L2Section18MS
$L2Section18MSDCErrors = Compare-RegistryKeys -RegistryConfig $L2Section18MSDC
$L2Section19MSDCErrors = Compare-RegistryKeys -RegistryConfig $L2Section19MSDC
$NGSection18DCErrors = Compare-RegistryKeys -RegistryConfig $NGSection18DC
$NGSection18MSErrors = Compare-RegistryKeys -RegistryConfig $NGSection18MS
$NGSection18MSDCErrors = Compare-RegistryKeys -RegistryConfig $NGSection18MSDC
#create a total possible controls array


#Quick Function to calculate the percentage for each section
function GetPercentage {
    param (
        [int]$Errors,
        [int]$Total
    )
    return [math]::Round((($Total - $Errors) / $Total) * 100, 2)
}
# Collect all the percentages

# Create a table with the results
IF (global:$IsDC = $true)  {
    $PossibleDCAnswers = @{
        UserRights = 39
        SecAcc = 15
        AuditPolicy = 34
        L1Section2DC = 7
        L1Section2MSDC = 54
        L1Section5DC = 1
        L1Section9MSDC = 23
        L1Section18DC = 1
        L1Section18MSDC = 154
        L1Section19MSDC = 8
        L2Section2MSDC = 1
        L2Section18MSDC = 69
        L2Section19MSDC = 4
        NGSection18DC = 1
        NGSection18MSDC = 5
    }

    $Percentages = @{
        UserRights = GetPercentage $UserRightsErrors $PossibleDCAnswers.UserRights
        SecAcc = GetPercentage $SecAccErrors $PossibleDCAnswers.SecAcc
        AuditPolicy = GetPercentage $AuditPolicyErrors $PossibleDCAnswers.AuditPolicy
        L1Section2DC = GetPercentage $L1Section2DCErrors $PossibleDCAnswers.L1Section2DC
        L1Section2MSDC = GetPercentage $L1Section2MSDCErrors $PossibleDCAnswers.L1Section2MSDC
        L1Section5DC = GetPercentage $L1Section5DCErrors $PossibleDCAnswers.L1Section5DC
        L1Section9MSDC = GetPercentage $L1Section9MSDCErrors $PossibleDCAnswers.L1Section9MSDC
        L1Section18DC = GetPercentage $L1Section18DCErrors $PossibleDCAnswers.L1Section18DC
        L1Section18MSDC = GetPercentage $L1Section18MSDCErrors $PossibleDCAnswers.L1Section18MSDC
        L1Section19MSDC = GetPercentage $L1Section19MSDCErrors $PossibleDCAnswers.L1Section19MSDC
        L2Section2MSDC = GetPercentage $L2Section2MSDCErrors $PossibleDCAnswers.L2Section2MSDC
        L2Section18MSDC = GetPercentage $L2Section18MSDCErrors $PossibleDCAnswers.L2Section18MSDC
        L2Section19MSDC = GetPercentage $L2Section19MSDCErrors $PossibleDCAnswers.L2Section19MSDC
        NGSection18DC = GetPercentage $NGSection18DCErrors $PossibleDCAnswers.NGSection18DC
        NGSection18MSDC = GetPercentage $NGSection18MSDCErrors $PossibleDCAnswers.NGSection18MSDC
    }
    # Calculate L1, L2, and Total percentages
    $L1TotalErrors = $L1Section2DCErrors + $L1Section2MSDCErrors + $L1Section5DCErrors + $L1Section9MSDCErrors + $L1Section18DCErrors + $L1Section18MSDCErrors + $L1Section19MSDCErrors
    $L1TotalPossible = $PossibleDCAnswers.L1Section2DC + $PossibleDCAnswers.L1Section2MSDC + $PossibleDCAnswers.L1Section5DC + $PossibleDCAnswers.L1Section9MSDC + $PossibleDCAnswers.L1Section18DC + $PossibleDCAnswers.L1Section18MSDC + $PossibleDCAnswers.L1Section19MSDC
    $L1Percentage = GetPercentage $L1TotalErrors $L1TotalPossible

    $L2TotalErrors = $L2Section2MSDCErrors + $L2Section18MSDCErrors + $L2Section19MSDCErrors
    $L2TotalPossible = $PossibleDCAnswers.L2Section2MSDC + $PossibleDCAnswers.L2Section18MSDC + $PossibleDCAnswers.L2Section19MSDC
    $L2Percentage = GetPercentage $L2TotalErrors $L2TotalPossible

    $NGTotalErrors = $NGSection18DC + $NGSection18MSDC
    $NGTotalPossible = $PossibleDCAnswers.NGSection18DC + $PossibleDCAnswers.NGSection18MSDC
    $NGPercentage = GetPercentage $NGTotalErrors $NGTotalPossible


    # Calculate DC total percentage (include DC and MSDC)
    $DCTotalErrors = $L1Section2DCErrors + $L1Section5DCErrors + $L1Section18DCErrors + $NGSection18DCErrors +
    $L1Section2MSDCErrors + $L1Section9MSDCErrors + $L1Section18MSDCErrors + $L1Section19MSDCErrors + $L2Section2MSDCErrors + $L2Section18MSDCErrors + $L2Section19MSDCErrors + $NGSection18MSDCErrors
    $DCTotalPossible = $PossibleDCAnswers.L1Section2DC + $PossibleDCAnswers.L1Section5DC + $PossibleDCAnswers.L1Section18DC + $PossibleDCAnswers.NGSection18DC +
    $PossibleDCAnswers.L1Section2MSDC + $PossibleDCAnswers.L1Section9MSDC + $PossibleDCAnswers.L1Section18MSDC + $PossibleDCAnswers.L1Section19MSDC + $PossibleDCAnswers.L2Section2MSDC + $PossibleDCAnswers.L2Section18MSDC + $PossibleDCAnswers.L2Section19MSDC + $PossibleDCAnswers.NGSection18MSDC
    $DCPercentage = GetPercentage $DCTotalErrors $DCTotalPossible

    $Results = @()
    $Results += [PSCustomObject]@{ Section = "User Rights"; Percentage = $Percentages.UserRights }
    $Results += [PSCustomObject]@{ Section = "Sec Acc"; Percentage = $Percentages.SecAcc }
    $Results += [PSCustomObject]@{ Section = "Audit Policy"; Percentage = $Percentages.AuditPolicy }
    $Results += [PSCustomObject]@{ Section = "L1 Section 2 DC"; Percentage = $Percentages.L1Section2DC }
    $Results += [PSCustomObject]@{ Section = "L1 Section 2 MS DC"; Percentage = $Percentages.L1Section2MSDC }
    $Results += [PSCustomObject]@{ Section = "L1 Section 5 DC"; Percentage = $Percentages.L1Section5DC }
    $Results += [PSCustomObject]@{ Section = "L1 Section 9 MS DC"; Percentage = $Percentages.L1Section9MSDC }
    $Results += [PSCustomObject]@{ Section = "L1 Section 18 DC"; Percentage = $Percentages.L1Section18DC }
    $Results += [PSCustomObject]@{ Section = "L1 Section 18 MS DC"; Percentage = $Percentages.L1Section18MSDC }
    $Results += [PSCustomObject]@{ Section = "L1 Section 19 MS DC"; Percentage = $Percentages.L1Section19MSDC }
    $Results += [PSCustomObject]@{ Section = "L2 Section 2 MS DC"; Percentage = $Percentages.L2Section2MSDC }
    $Results += [PSCustomObject]@{ Section = "L2 Section 18 MS DC"; Percentage = $Percentages.L2Section18MSDC }
    $Results += [PSCustomObject]@{ Section = "L2 Section 19 MS DC"; Percentage = $Percentages.L2Section19MSDC }
    $Results += [PSCustomObject]@{ Section = "Next Gen Section 18 DC"; Percentage = $Percentages.NGSection18DC }
    $Results += [PSCustomObject]@{ Section = "Next Gen Section 18 MS DC"; Percentage = $Percentages.NGSection18MSDC }
    $Results += [PSCustomObject]@{ Section = "L1 Total"; Percentage = $L1Percentage }
    $Results += [PSCustomObject]@{ Section = "L2 Total"; Percentage = $L2Percentage }
    $Results += [PSCustomObject]@{ Section = "NG Total"; Percentage = $NGPercentage }
    $Results += [PSCustomObject]@{ Section = "DC Total"; Percentage = $DCPercentage }
}
else {
    $PossibleAnswers = @{
        UserRights = 39
        SecAcc = 15
        AuditPolicy = 27
        L1Section2MS = 6
        L1Section2MSDC = 54
        L1Section9MSDC = 23
        L1Section18MS = 12
        L1Section18MSDC = 154
        L1Section19MSDC = 8
        L2Section2MS = 1
        L2Section2MSDC = 1
        L2Section5MS = 1
        L2Section18MS = 3
        L2Section18MSDC = 69
        L2Section19MSDC = 4
        NGSection18MS = 2
        NGSection18MSDC = 5
    }

    $Percentages = @{
        UserRights = GetPercentage $UserRightsErrors $PossibleAnswers.UserRights
        SecAcc = GetPercentage $SecAccErrors $PossibleAnswers.SecAcc
        AuditPolicy = GetPercentage $AuditPolicyErrors $PossibleAnswers.AuditPolicy
        L1Section2MS = GetPercentage $L1Section2MSErrors $PossibleAnswers.L1Section2MS
        L1Section2MSDC = GetPercentage $L1Section2MSDCErrors $PossibleAnswers.L1Section2MSDC
        L1Section9MSDC = GetPercentage $L1Section9MSDCErrors $PossibleAnswers.L1Section9MSDC
        L1Section18MS = GetPercentage $L1Section18MSErrors $PossibleAnswers.L1Section18MS
        L1Section18MSDC = GetPercentage $L1Section18MSDCErrors $PossibleAnswers.L1Section18MSDC
        L1Section19MSDC = GetPercentage $L1Section19MSDCErrors $PossibleAnswers.L1Section19MSDC
        L2Section2MS = GetPercentage $L2Section2MSErrors $PossibleAnswers.L2Section2MS
        L2Section2MSDC = GetPercentage $L2Section2MSDCErrors $PossibleAnswers.L2Section2MSDC
        L2Section5MS = GetPercentage $L2Section5MSErrors $PossibleAnswers.L2Section5MS
        L2Section18MS = GetPercentage $L2Section18MSErrors $PossibleAnswers.L2Section18MS
        L2Section18MSDC = GetPercentage $L2Section18MSDCErrors $PossibleAnswers.L2Section18MSDC
        L2Section19MSDC = GetPercentage $L2Section19MSDCErrors $PossibleAnswers.L2Section19MSDC
        NGSection18MS = GetPercentage $NGSection18MSErrors $PossibleAnswers.NGSection18MS
        NGSection18MSDC = GetPercentage $NGSection18MSDCErrors $PossibleAnswers.NGSection18MSDC
    }


    # Calculate L1, L2, and Total percentages
    $L1TotalErrors = $L1Section2MSErrors + $L1Section2MSDCErrors + $L1Section9MSDCErrors + $L1Section18MSErrors + $L1Section18MSDCErrors + $L1Section19MSDCErrors
    $L1TotalPossible = $PossibleAnswers.L1Section2MS + $PossibleAnswers.L1Section2MSDC + $PossibleAnswers.L1Section9MSDC + $PossibleAnswers.L1Section18MS + $PossibleAnswers.L1Section18MSDC + $PossibleAnswers.L1Section19MSDC
    $L1Percentage = GetPercentage $L1TotalErrors $L1TotalPossible

    $L2TotalErrors = $L2Section2MSErrors + $L2Section2MSDCErrors + $L2Section5MSErrors + $L2Section18MSErrors + $L2Section18MSDCErrors + $L2Section19MSDCErrors
    $L2TotalPossible = $PossibleAnswers.L2Section2MS + $PossibleAnswers.L2Section2MSDC + $PossibleAnswers.L2Section5MS + $PossibleAnswers.L2Section18MS + $PossibleAnswers.L2Section18MSDC + $PossibleAnswers.L2Section19MSDC
    $L2Percentage = GetPercentage $L2TotalErrors $L2TotalPossible

    $NGTotalErrors = $NGSection18MS + $NGSection18MSDC
    $NGTotalPossible = $PossibleAnswers.NGSection18MS + $PossibleAnswers.NGSection18MSDC
    $NGPercentage = GetPercentage $NGTotalErrors $NGTotalPossible

    # Calculate MS total percentage (include MS and MSDC)
    $MSTotalErrors = $L1Section2MSErrors + $L1Section18MSErrors + $L2Section2MSErrors + $L2Section5MSErrors + $L2Section18MSErrors + $NGSection18MSErrors +
    $L1Section2MSDCErrors + $L1Section9MSDCErrors + $L1Section18MSDCErrors + $L1Section19MSDCErrors + $L2Section2MSDCErrors + $L2Section18MSDCErrors + $L2Section19MSDCErrors + $NGSection18MSDCErrors
    $MSTotalPossible = $PossibleAnswers.L1Section2MS + $PossibleAnswers.L1Section18MS + $PossibleAnswers.L2Section2MS + $PossibleAnswers.L2Section5MS + $PossibleAnswers.L2Section18MS + $PossibleAnswers.NGSection18MS +
    $PossibleAnswers.L1Section2MSDC + $PossibleAnswers.L1Section9MSDC + $PossibleAnswers.L1Section18MSDC + $PossibleAnswers.L1Section19MSDC + $PossibleAnswers.L2Section2MSDC + $PossibleAnswers.L2Section18MSDC + $PossibleAnswers.L2Section19MSDC + $PossibleAnswers.NGSection18MSDC
    $MSPercentage = GetPercentage $MSTotalErrors $MSTotalPossible

    $Results = @()
    $Results += [PSCustomObject]@{ Section = "User Rights"; Percentage = $Percentages.UserRights }
    $Results += [PSCustomObject]@{ Section = "Sec Acc"; Percentage = $Percentages.SecAcc }
    $Results += [PSCustomObject]@{ Section = "Audit Policy"; Percentage = $Percentages.AuditPolicy }
    $Results += [PSCustomObject]@{ Section = "L1 Section 2 MS"; Percentage = $Percentages.L1Section2MS }
    $Results += [PSCustomObject]@{ Section = "L1 Section 2 MS DC"; Percentage = $Percentages.L1Section2MSDC }
    $Results += [PSCustomObject]@{ Section = "L1 Section 9 MS DC"; Percentage = $Percentages.L1Section9MSDC }
    $Results += [PSCustomObject]@{ Section = "L1 Section 18 MS"; Percentage = $Percentages.L1Section18MS }
    $Results += [PSCustomObject]@{ Section = "L1 Section 18 MS DC"; Percentage = $Percentages.L1Section18MSDC }
    $Results += [PSCustomObject]@{ Section = "L1 Section 19 MS DC"; Percentage = $Percentages.L1Section19MSDC }
    $Results += [PSCustomObject]@{ Section = "L2 Section 2 MS"; Percentage = $Percentages.L2Section2MS }
    $Results += [PSCustomObject]@{ Section = "L2 Section 2 MS DC"; Percentage = $Percentages.L2Section2MSDC }
    $Results += [PSCustomObject]@{ Section = "L2 Section 5 MS"; Percentage = $Percentages.L2Section5MS }
    $Results += [PSCustomObject]@{ Section = "L2 Section 18 MS"; Percentage = $Percentages.L2Section18MS }
    $Results += [PSCustomObject]@{ Section = "L2 Section 18 MS DC"; Percentage = $Percentages.L2Section18MSDC }
    $Results += [PSCustomObject]@{ Section = "L2 Section 19 MS DC"; Percentage = $Percentages.L2Section19MSDC }
    $Results += [PSCustomObject]@{ Section = "Next Gen Section 18 MS"; Percentage = $Percentages.NGSection18MS }
    $Results += [PSCustomObject]@{ Section = "Next Gen Section 18 MS DC"; Percentage = $Percentages.NGSection18MSDC }
    $Results += [PSCustomObject]@{ Section = "L1 Total"; Percentage = $L1Percentage }
    $Results += [PSCustomObject]@{ Section = "L2 Total"; Percentage = $L2Percentage }
    $Results += [PSCustomObject]@{ Section = "NG Total"; Percentage = $NGPercentage }
    $Results += [PSCustomObject]@{ Section = "MS Total"; Percentage = $MSPercentage }
}
# Output the table
$Results | Format-Table -AutoSize



