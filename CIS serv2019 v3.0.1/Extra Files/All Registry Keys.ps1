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

#L1 Section 19 
#L2 Section 2 MS
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon:CachedLogonsCount 2##set 4>=x

#L2 Section 2 MS + DC
HKLM\SYSTEM\CurrentControlSet\Control\Lsa:DisableDomainCreds 1
#L2 Section 5 MS
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler:Start 4
#L2 Section 19