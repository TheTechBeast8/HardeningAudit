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
$SectionNGErrors = Compare-RegistryKeys -RegistryConfig $SectionNG
$ErrorsArray = @(
    $UserRightsErrors, $SecAccErrors, $AuditPolicyErrors, $L1Section1Errors, 
    $L1Section2Errors, $L1Section5Errors, $L1Section9Errors, $L1Section18Errors,
    $L1Section19Errors, $L2Section2Errors, $L2Section5Errors, $L2Section18Errors,
    $L2Section19Errors, $SectionBitlockerErrors, $SectionNGErrors
)
$PossibleAnswers = @{
    UserRights = 39
    SecAcc = 15
    AuditPolicy = 26
    L1Section1 = 1
    L1Section2 = 51
    L1Section5 = 21
    L1Section9 = 16
    L1Section18 = 168
    L1Section19 = 8
    L2Section2 = 2
    L2Section5 = 24
    L2Section18 = 76
    L2Section19 = 4
    SectionBitlocker = 55
    SectionNG = 13
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
    SectionNG = GetPercentage $SectionNGErrors $PossibleAnswers.SectionNG
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
$Results += [PSCustomObject]@{ Section = "Next Gen"; Percentage = $Percentages.SectionNG }
$Results += [PSCustomObject]@{ Section = "L1 Total"; Percentage = $L1Percentage }
$Results += [PSCustomObject]@{ Section = "L2 Total"; Percentage = $L2Percentage }
$Results += [PSCustomObject]@{ Section = "Overall Total"; Percentage = $TotalPercentage }

# Output the table
$Results | Format-Table -AutoSize