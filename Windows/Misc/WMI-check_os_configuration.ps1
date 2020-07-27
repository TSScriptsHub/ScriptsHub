<#
DESCRIPTION:
This powershell script is used to check local OS Confirguration 
#Basic feature:
#check KB list, check specified KB list installed status
#check Anti-virus software, check 360/FEP/SCEP/DEFENDER, list all installed and uninstalled software name
#check account name, check whether have default "Administrator" and specified account
#list all account
#check password policy, complexity and minsize should be set to 8
#check audit policy
#check event log maxsize, all system,security and application logs maxsize should be set to 20M
#check start programe, list all start programe
#check AutoPlay Policy, default should be in disabled status
#check Telnet service, default should be in disabled status
#check SQL install status, if installed show SQL version 
#check IIS install status, if installed show IIS version, list Site and AppPool informations

System/Requirement：
Require to run on server 2012 R2 or above

USAGE:
N/A
#>#


$check360=0
$checkfep=0
$checkscep=0
$checkdefender=0
$checkAdministrator=0
$checkdefinedaccount=0
$check_pwd_minsize=0
$check_pwd_Complexity=0
$check_AuditSystemEvents=0
$check_AuditLogonEvents=0
$check_AuditObjectAccess=0
$check_AuditPrivilegeUse=0
$check_AuditPolicyChange=0
$check_AuditAccountManage=0
$check_AuditProcessTracking=0
$check_AuditDSAccess=0
$check_AuditAccountLogon=0
$check_applog_maxsize=0
$check_seclog_maxsize=0
$check_syslog_maxsize=0
$checkauoplay=0
$checktelnetstatus=0
$checksql=0
$SQLedtion=""
$SQLversion=""
$IISversion=""

#KB check spec
$check_kblist_path="C:\test\check_kblist.txt"  #KB CHECK LIST PATH
#account spec
$defined_account="testadmin" #specified account
#password spec
$pwdminsize_spec="8"
#audit spec
$AuditSystemEvents_spec="1" #SUCCESS
$AuditLogonEvents_spec="2" #FAIL  
$AuditObjectAccess_spec="3" #SUCCESS,FAIL
$AuditPrivilegeUse_spec="3" #SUCCESS,FAIL
$AuditPolicyChange_spec="1" #SUCCESS
$AuditAccountManage_spec="3" #SUCCESS,FAIL
$AuditProcessTracking_spec="0"
$AuditDSAccess_spec="0"
$AuditAccountLogon_spec="2" #FAIL
#eventlog spec
$logmaxsize=20 #20MB

$kbcheck_flag=0
$Anticheck_flag=0
$accountcheck_flag=0
$passwordcheck_flag=0
$auditcheck_flag=0
$logsizecheck_flag=0
$autoplaycheck_flag=0
$telnetcheck_flag=0
$sqlinstalled_flag=0
$iisinstalled_flag=0

$kbfaillist=""
$startupprogramelist=""
$localaccountlist=""
$apppoollist=""
$sitelist=""

$report_directory="C:\test\" #report file directory
$currenttime=Get-Date -Format 'yyyyMMddHHmm'
$report_file=$report_directory+"report_"+$currenttime+".txt"


function Get-RegistryValues($key) { 
    (Get-Item $key).GetValueNames() 
}

function Get-RegistryValue($key, $name) { 
    (Get-ItemProperty $key $name).$name
}


function Check_Program_Installed( $programName ) {
    $wmi_check = (Get-WMIObject -Query "SELECT * FROM Win32_Product Where Name Like '%$programName%'").Length -gt 0
    return $wmi_check;
}
write-host ""
write-host "Ready to check OS configuration"
write-host ""
"SUMMARY:" | Out-File -Filepath $report_file -Append
write-host "============================Process begins=============================="
"============================Process begins==============================" | Out-File -Filepath $report_file -Append

#check KB list
$kblist=@(Get-Content $check_kblist_path)

for($i=0;$i -lt $kblist.Length;$i++)
{
    try
	{
		$checkhotfix=""
        $checkhotfix=Get-HotFix |
		Where-Object { 
			$_.HotfixID -like $kblist[$i] 
		}
        #$kblist[$i]
        if($checkhotfix)
        {
            $temp_output=$kblist[$i]+" has been installed"
            #write-host $temp_output
        }
        else
        {
            $temp_output=$kblist[$i]+" has not been installed"
            #write-host $temp_output -ForegroundColor Red
            if($kbcheck_flag -eq 0)
            {
                $kbfaillist=$kblist[$i]
            }
            else
            {
                $kbfaillist=$kbfaillist+" "+$kblist[$i]
            }
            $kbcheck_flag=1
        }
	}
	catch
	{
        write-warning "check hotfix fail"
    }
}
write-host "====KB CHECK===="
"====KB CHECK====" | Out-File -Filepath $report_file -Append
if($kbcheck_flag -eq 0)
{
   write-host "RESULT: PASS" -ForegroundColor Green
   "RESULT: PASS" | Out-File -Filepath $report_file -Append
}
else
{
   write-host "RESULT: FAIL" -ForegroundColor Red
   write-host "FAIL LIST:" -ForegroundColor Red 
   write-host $kbfaillist -ForegroundColor Red
   "RESULT: FAIL" | Out-File -Filepath $report_file -Append
   "FAIL LIST:" | Out-File -Filepath $report_file -Append
   $kbfaillist | Out-File -Filepath $report_file -Append
}

write-host ""
"" | Out-File -Filepath $report_file -Append

#check Anti-virus software

$osversion=(Get-WmiObject -Class Win32_OperatingSystem).Caption

if($osversion.contains("Windows Server 2016") -or $osversion.contains("Windows 10")  )
{
    $keys="HKLM:SOFTWARE\Microsoft\360Safe\"
    $check360=Test-Path $keys
    #$checkscep=Get-WMIObject -Query "SELECT * FROM Win32_Product Where Name Like '%Microsoft Endpoint Protection Management Components%'"
    $checkdefender=Get-MpComputerStatus

    write-host "====Anti-virus CHECK===="
    "====Anti-virus CHECK====" | Out-File -Filepath $report_file -Append
    if($check360 -and $checkdefender)
    {
        write-host "RESULT: PASS" -ForegroundColor Green
        "RESULT: PASS" | Out-File -Filepath $report_file -Append
    }
    else
    {
        write-host "RESULT: FAIL" -ForegroundColor Red
        write-host "DETAIL LIST:" -ForegroundColor Red
        "RESULT: FAIL" | Out-File -Filepath $report_file -Append
        "DETAIL LIST:" | Out-File -Filepath $report_file -Append
    }

    if($check360)
    {
        write-host "360 has been installed"
        "360 has been installed" | Out-File -Filepath $report_file -Append
    }
    else
    {
        write-host "360 has not been installed" -ForegroundColor Red
        "360 has not been installed" | Out-File -Filepath $report_file -Append
    }

    if($checkdefender)
    {
        write-host "Windows Defender has been installed"
        "Windows Defender has been installed" | Out-File -Filepath $report_file -Append
    }
    else
    {
        write-host "Windows Defender has not been installed" -ForegroundColor Red
        "Windows Defender has not been installed" | Out-File -Filepath $report_file -Append
    }
}
else
{
    $keys="HKLM:SOFTWARE\Microsoft\360Safe\"
    $check360=Test-Path $keys 
    $checkfep=Get-WMIObject -Query "SELECT * FROM Win32_Product Where Name Like '%Microsoft Forefront Endpoint Protection 2010 Server Management%'"
    $checkscep=Get-WMIObject -Query "SELECT * FROM Win32_Product Where Name Like '%Microsoft Endpoint Protection Management Components%'"

    write-host "====Anti-virus CHECK===="
    "====Anti-virus CHECK====" | Out-File -Filepath $report_file -Append

    if($check360 -and $checkfep -and $checkscep)
    {
        write-host "RESULT: PASS" -ForegroundColor Green
        "RESULT: PASS" | Out-File -Filepath $report_file -Append
    }
    else
    {
        write-host "RESULT: FAIL" -ForegroundColor Red
        write-host "DETAIL LIST:" -ForegroundColor Red
        "RESULT: FAIL" | Out-File -Filepath $report_file -Append
        "DETAIL LIST:" | Out-File -Filepath $report_file -Append
    }

    if($check360)
    {
        write-host "360 has been installed"
        "360 has been installed" | Out-File -Filepath $report_file -Append
    }
    else
    {
        write-host "360 has not been installed" -ForegroundColor Red
        "360 has not been installed" | Out-File -Filepath $report_file -Append
    } 

    if($checkfep)
    {
        write-host "FEP has been installed"
        "FEP has been installed" | Out-File -Filepath $report_file -Append
    }
    else
    {
        write-host "FEP has not been installed" -ForegroundColor Red
        "FEP has not been installed" | Out-File -Filepath $report_file -Append
    }
    
    if($checkscep)
    {
        write-host "SCEP has been installed"
        "SCEP has been installed" | Out-File -Filepath $report_file -Append
    }
    else
    {
        write-host "SCEP has been installed" -ForegroundColor Red
        "SCEP has been installed" | Out-File -Filepath $report_file -Append
    }

}

write-host ""
"" | Out-File -Filepath $report_file -Append

#check account name
$localaccountlist=Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'" | Select Name, Status, Disabled
for($i=0;$i -lt $localaccountlist.Name.Length;$i++)
{
    if($localaccountlist.Name -eq "Administrator")
    {
        $checkAdministrator=1
    }
    if($localaccountlist.Name -eq $defined_account)
    {
        $checkdefinedaccount=1
    }
}


write-host "====ACCOUNT CHECK===="
"====ACCOUNT CHECK====" | Out-File -Filepath $report_file -Append

if($checkAdministrator -eq 0 -and $checkdefinedaccount -eq 1)
{
    $accountcheck_flag=1
    write-host "RESULT: PASS" -ForegroundColor Green
    "RESULT: PASS" | Out-File -Filepath $report_file -Append
}
else
{
    write-host "RESULT: FAIL" -ForegroundColor Red
    write-host "DETAIL LIST:" -ForegroundColor Red
    "RESULT: FAIL" | Out-File -Filepath $report_file -Append
    "DETAIL LIST:" | Out-File -Filepath $report_file -Append

    if($checkAdministrator -eq 1)
    {
        write-host "Has default account Administrator" -ForegroundColor Red
        "Has default account Administrator" | Out-File -Filepath $report_file -Append
    }
    if($checkdefinedaccount -eq 0)
    {
        write-host "Has no specified account" -ForegroundColor Red
        "Has no specified account" | Out-File -Filepath $report_file -Append
    }

}

#check all account list
#write-host "====ACCOUNT LIST===="
"====ACCOUNT LIST====" | Out-File -Filepath $report_file -Append
#$localaccountlist=Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'" | Select Name, Status, Disabled
$localaccountlist | Out-File -Filepath $report_file -Append

write-host ""
"" | Out-File -Filepath $report_file -Append

#check password policy
secedit /export /cfg c:\test\sec.txt | Out-Null
$tmpfcontent=Get-Content "C:\test\sec.txt"
$tmpstr=$tmpfcontent | findstr "PasswordComplexity"
$check_pwd_Complexity=($tmpstr -split '=')[1].Contains("1")
$tmpstr=$tmpfcontent | findstr "MinimumPasswordLength"
$check_pwd_minsize=($tmpstr -split '=')[1].Contains($pwdminsize_spec)

write-host "====PASSWORD CHECK===="
"====PASSWORD CHECK====" | Out-File -Filepath $report_file -Append

if($check_pwd_Complexity -and $check_pwd_minsize)
{
    $passwordcheck_flag=1
    write-host "RESULT: PASS" -ForegroundColor Green
    "RESULT: PASS" | Out-File -Filepath $report_file -Append

}
else
{
    write-host "RESULT: FAIL" -ForegroundColor Red
    write-host "DETAIL LIST:" -ForegroundColor Red
    "RESULT: FAIL" | Out-File -Filepath $report_file -Append
    "DETAIL LIST:" | Out-File -Filepath $report_file -Append

    if(-not $check_pwd_Complexity)
    {
        write-host "Password complexity required" -ForegroundColor Red
        "Password complexity required" | Out-File -Filepath $report_file -Append
    }
    if(-not $check_pwd_minsize)
    {
        write-host "Password minimun length should set to 8" -ForegroundColor Red
        "Password minimun length should set to 8" | Out-File -Filepath $report_file -Append
    }

}

write-host ""
"" | Out-File -Filepath $report_file -Append

#check audit policy
$tmpstr=$tmpfcontent | findstr "AuditSystemEvents"
$check_AuditSystemEvents=($tmpstr -split '=')[1].Contains($AuditSystemEvents_spec)
$tmpstr=$tmpfcontent | findstr "AuditLogonEvents"
$check_AuditLogonEvents=($tmpstr -split '=')[1].Contains($AuditLogonEvents_spec)
$tmpstr=$tmpfcontent | findstr "AuditObjectAccess"
$check_AuditObjectAccess=($tmpstr -split '=')[1].Contains($AuditObjectAccess_spec)
$tmpstr=$tmpfcontent | findstr "AuditPrivilegeUse"
$check_AuditPrivilegeUse=($tmpstr -split '=')[1].Contains($AuditPrivilegeUse_spec)
$tmpstr=$tmpfcontent | findstr "AuditPolicyChange"
$check_AuditPolicyChange=($tmpstr -split '=')[1].Contains($AuditPolicyChange_spec)
$tmpstr=$tmpfcontent | findstr "AuditAccountManage"
$check_AuditAccountManage=($tmpstr -split '=')[1].Contains($AuditAccountManage_spec)
$tmpstr=$tmpfcontent | findstr "AuditProcessTracking"
$check_AuditProcessTracking=($tmpstr -split '=')[1].Contains($AuditProcessTracking_spec)
$tmpstr=$tmpfcontent | findstr "AuditDSAccess"
$check_AuditDSAccess=($tmpstr -split '=')[1].Contains($AuditDSAccess_spec)
$tmpstr=$tmpfcontent | findstr "AuditAccountLogon"
$check_AuditAccountLogon=($tmpstr -split '=')[1].Contains($AuditAccountLogon_spec)

write-host "====Audit CHECK===="
"====Audit CHECK====" | Out-File -Filepath $report_file -Append

if($check_AuditSystemEvents -and $check_AuditLogonEvents -and $check_AuditObjectAccess -and $check_AuditPrivilegeUse -and $check_AuditPolicyChange -and $check_AuditAccountManage -and $check_AuditProcessTracking -and $check_AuditDSAccess -and $check_AuditAccountLogon)
{
    $passwordcheck_flag=1
    write-host "RESULT: PASS" -ForegroundColor Green
    "RESULT: PASS" | Out-File -Filepath $report_file -Append

}
else
{
    write-host "RESULT: FAIL" -ForegroundColor Red
    write-host "DETAIL LIST:" -ForegroundColor Red
    "RESULT: FAIL" | Out-File -Filepath $report_file -Append
    "DETAIL LIST:" | Out-File -Filepath $report_file -Append

    if(-not $check_AuditSystemEvents)
    {
        write-host "System Events Audit need check" -ForegroundColor Red
        "System Events Audit need check" | Out-File -Filepath $report_file -Append
    }
    if(-not $check_AuditLogonEvents)
    {
        write-host "Logon Events Audit need check" -ForegroundColor Red
        "Logon Events Audit need check" | Out-File -Filepath $report_file -Append
    }
    if(-not $check_AuditObjectAccess)
    {
        write-host "Object Access Audit need check" -ForegroundColor Red
        "Object Access Audit need check" | Out-File -Filepath $report_file -Append
    }
    if(-not $check_AuditPrivilegeUse)
    {
        write-host "PrivilegeUse Audit need check" -ForegroundColor Red
        "PrivilegeUse Audit need check" | Out-File -Filepath $report_file -Append
    }
    if(-not $check_AuditPolicyChange)
    {
        write-host "Policychange Audit need check" -ForegroundColor Red
        "Policychange Audit need check" | Out-File -Filepath $report_file -Append
    }
    if(-not $check_AuditAccountManage)
    {
        write-host "Account Manage Audit need check" -ForegroundColor Red
        "Account Manage Audit need check" | Out-File -Filepath $report_file -Append
    }
    if(-not $check_AuditProcessTracking)
    {
        write-host "Process Tracking Audit need check" -ForegroundColor Red
        "Process Tracking Audit need check" | Out-File -Filepath $report_file -Append
    }
    if(-not $check_AuditDSAccess)
    {
        write-host "DS Access Audit need check" -ForegroundColor Red
        "DS Access Audit need check" | Out-File -Filepath $report_file -Append
    }
    if(-not $check_AuditAccountLogon)
    {
        write-host "Account Logon Audit need check" -ForegroundColor Red
        "Account Logon Audit need check" | Out-File -Filepath $report_file -Append
    }

}


write-host ""
"" | Out-File -Filepath $report_file -Append

#check event log maxsize
write-host "====EVENT LOG SIZE CHECK===="
"====EVENT LOG SIZE CHECK====" | Out-File -Filepath $report_file -Append

$keys="HKLM:Software\Policies\Microsoft\Windows\EventLog\Application\"
$keys1="HKLM:System\CurrentControlSet\Services\EventLog\Application\"
$name="MaxSize"
if ((Test-Path $keys) -eq $false)
{
    if (Test-Path $keys1)
    {
        $tmpval=Get-RegistryValues $keys1
        if($tmpval.contains($name))
        {
            $tmpval=Get-RegistryValue $keys1 $name
        }
    }
}
else
{
    $tmpval=Get-RegistryValues $keys
    if($tmpval.contains($name))
    {
        $tmpval=Get-RegistryValue $keys $name
    }
}
$check_applog_maxsize=$tmpval -eq ($logmaxsize *1024*1024)

$keys="HKLM:Software\Policies\Microsoft\Windows\EventLog\Security\"
$keys1="HKLM:System\CurrentControlSet\Services\EventLog\Security\"
$name="MaxSize"
try
{
    if ((Test-Path $keys) -eq $false)
    {
        if (Test-Path $keys1)
        {
            $tmpval=Get-RegistryValues $keys1
            if($tmpval.contains($name))
            {
                $tmpval=Get-RegistryValue $keys1 $name
            }
        }
    }
    else
    {
        $tmpval=Get-RegistryValues $keys
        if($tmpval.contains($name))
        {
            $tmpval=Get-RegistryValue $keys $name
        }
    }
}
catch
{
    Write-Warning "You should run as Administrator when need check security Items"
}
$check_seclog_maxsize=$tmpval -eq ($logmaxsize *1024*1024)

$keys="HKLM:Software\Policies\Microsoft\Windows\EventLog\System\"
$keys1="HKLM:System\CurrentControlSet\Services\EventLog\System\"
$name="MaxSize"
if ((Test-Path $keys) -eq $false)
{
    if (Test-Path $keys1)
    {
        $tmpval=Get-RegistryValues $keys1
        if($tmpval.contains($name))
        {
            $tmpval=Get-RegistryValue $keys1 $name
        }
    }
}
else
{
    $tmpval=Get-RegistryValues $keys
    if($tmpval.contains($name))
    {
        $tmpval=Get-RegistryValue $keys $name
    }
}
$check_syslog_maxsize=$tmpval -eq ($logmaxsize *1024*1024)

if($check_syslog_maxsize -and $check_seclog_maxsize -and $check_applog_maxsize)
{
    $logsizecheck_flag=1
    write-host "RESULT: PASS" -ForegroundColor Green
    "RESULT: PASS" | Out-File -Filepath $report_file -Append
}
else
{
    write-host "RESULT: FAIL" -ForegroundColor Red
    write-host "DETAIL LIST:" -ForegroundColor Red
    "RESULT: FAIL" | Out-File -Filepath $report_file -Append
    "DETAIL LIST:" | Out-File -Filepath $report_file -Append

    if(-not $check_syslog_maxsize)
    {
        write-host "System Events Log Maxsize need check" -ForegroundColor Red
        "System Events Log Maxsize need check" | Out-File -Filepath $report_file -Append
    }
    if(-not $check_seclog_maxsize)
    {
        write-host "Security Events Log Maxsize need check" -ForegroundColor Red
        "Security Events Log Maxsize need check" | Out-File -Filepath $report_file -Append
    }
    if(-not $check_applog_maxsize)
    {
        write-host "Application Events Log Maxsize need check" -ForegroundColor Red
        "Application Events Log Maxsize need check" | Out-File -Filepath $report_file -Append
    }
}

write-host ""
"" | Out-File -Filepath $report_file -Append

#check start programe
$startupprogramelist=wmic startup get caption
write-host "====STARTUP PROGRAME CHECK===="
write-host "DETAIL LIST:"
"====STARTUP PROGRAME CHECK====" | Out-File -Filepath $report_file -Append
"DETAIL LIST:" | Out-File -Filepath $report_file -Append

for($i=2;$i -lt $startupprogramelist.Length;$i=$i+2)
{
    $startupprogramelist[$i]
    $startupprogramelist[$i] | Out-File -Filepath $report_file -Append
}

write-host ""
"" | Out-File -Filepath $report_file -Append

#check AutoPlay Policy
$keys="HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\"
$name="NoDriveTypeAutoRun"
if (Test-Path $keys)
{ 
    $tmpval=Get-RegistryValues $keys
    if($tmpval.contains($name))
    {
        $tmpval=Get-RegistryValue $keys $name
    }
}

$checkauoplay=$tmpval -eq "255"

write-host "====AUTOPLAY POLICY CHECK===="
"====AUTOPLAY POLICY CHECK====" | Out-File -Filepath $report_file -Append

if($checkauoplay)
{
    $autoplaycheck_flag =1
    write-host "RESULT: PASS" -ForegroundColor Green
    "RESULT: PASS" | Out-File -Filepath $report_file -Append
}
else
{
    write-host "RESULT: FAIL" -ForegroundColor Red
    "RESULT: FAIL" | Out-File -Filepath $report_file -Append
    if(-not $check_syslog_maxsize)
    {
        write-host "AutoPlay Policy need check" -ForegroundColor Red
        "AutoPlay Policy need check" | Out-File -Filepath $report_file -Append
    }
}

write-host ""
"" | Out-File -Filepath $report_file -Append

#check Telnet service
if(get-service | findstr "Telnet")
{
    $checktelnetstatus=(get-service -Name "Telnet").Status
}
write-host "====TELNET SERVICE CHECK===="
"====TELNET SERVICE CHECK====" | Out-File -Filepath $report_file -Append

if(-not $checktelnetstatus -or $checktelnetstatus -eq "Stopped")
{
    $telnetcheck_flag=1
    write-host "RESULT: PASS" -ForegroundColor Green
    "RESULT: PASS" | Out-File -Filepath $report_file -Append
}
else
{
    write-host "RESULT: FAIL" -ForegroundColor Red
    write-host "Telnet service current status is running" -ForegroundColor Red
    "RESULT: FAIL" | Out-File -Filepath $report_file -Append
    "Telnet service current status is running" | Out-File -Filepath $report_file -Append
}


write-host ""
"" | Out-File -Filepath $report_file -Append

#check SQL install status
$keys="HKLM:SOFTWARE\Microsoft\Microsoft SQL Server\"
$name="InstalledInstances"

if (Test-Path $keys)
{ 
    $tmpval=Get-RegistryValues $keys
    if($tmpval -and $tmpval.contains($name))
    {
        $inst=Get-RegistryValue $keys $name
        foreach ($i in $inst)
        {
            $p = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL').$i
            $SQLedtion=(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$p\Setup").Edition
            $SQLversion=(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$p\Setup").Version
            $checksql=1
        }
    }
}

#$checksql=Get-WMIObject -Query "SELECT * FROM Win32_Product Where Name Like '%Microsoft SQL Server%'"

write-host "====SQL INSTALLED CHECK===="
"====SQL INSTALLED CHECK====" | Out-File -Filepath $report_file -Append
    
if($checksql)
{ 
    write-host "RESULT: PASS" -ForegroundColor Green
    "RESULT: PASS" | Out-File -Filepath $report_file -Append
    $sqlinstalled_flag=1
    write-host "Edition: $SQLedtion"
    "Edition: $SQLedtion" | Out-File -Filepath $report_file -Append
    write-host "Version: $SQLversion"
    "Version: $SQLversion" | Out-File -Filepath $report_file -Append
}
else
{
    write-host "RESULT: FAIL" -ForegroundColor Red
    "RESULT: FAIL" | Out-File -Filepath $report_file -Append
    write-host "Has not install SQL Server" -ForegroundColor Red
    "Has not install SQL Server" | Out-File -Filepath $report_file -Append
}

write-host ""
"" | Out-File -Filepath $report_file -Append

#check IIS install status
$keys="HKLM:SOFTWARE\Microsoft\InetStp\"

write-host "====IIS INSTALLED CHECK===="
"====IIS INSTALLED CHECK====" | Out-File -Filepath $report_file -Append
if(TEST-PATH $keys)
{
    write-host "RESULT: PASS" -ForegroundColor Green
    "RESULT: PASS" | Out-File -Filepath $report_file -Append
    write-host ""
    "" | Out-File -Filepath $report_file -Append
    $iisInfo=get-itemproperty $keys 
    $iisInfopath=$iisInfo.InstallPath
    $IISversion =$iisInfo.SetupString
    cd $iisInfopath
    $apppoollist=.\appcmd.exe list apppool
    $sitelist=.\appcmd.exe list site
    write-host "Version: $IISversion"
    "Version: $IISversion" | Out-File -Filepath $report_file -Append
    write-host ""
    "" | Out-File -Filepath $report_file -Append
    $apppoollist
    $apppoollist | Out-File -Filepath $report_file -Append
    write-host ""
    "" | Out-File -Filepath $report_file -Append
    $sitelist
    $sitelist | Out-File -Filepath $report_file -Append
    $iisinstalled_flag=1
}
else
{
    $iisinstalled_flag=0
    write-host "RESULT: FAIL" -ForegroundColor Red
    "RESULT: FAIL" | Out-File -Filepath $report_file -Append
    write-host "Has not install IIS" -ForegroundColor Red
    "Has not install IIS" | Out-File -Filepath $report_file -Append
}

write-host "=============================Process ends==============================="
"=============================Process ends===============================" | Out-File -Filepath $report_file -Append

write-host ""
"" | Out-File -Filepath $report_file -Append

if($kbcheck_flag -and $Anticheck_flag -and $accountcheck_flag -and $passwordcheck_flag -and $auditcheck_flag -and $logsizecheck_flag -and $autoplaycheck_flag -and $telnetcheck_flag -and $sqlinstalled_flag -and $iisinstalled_flag)
{
   write-host "FINAL RESULT: PASS" -ForegroundColor Green
   "FINAL RESULT: PASS" | Out-File -Filepath $report_file -Append
}
else
{
   write-host "FINAL RESULT: FAIL" -ForegroundColor Red
   "FINAL RESULT: FAIL" | Out-File -Filepath $report_file -Append
}
"REPORT FILE: $report_file"

Write-Host ""
Write-Host ""
Write-Host "This script windows will exit in 2 min, you can find the detail info from the report file"	
Start-Sleep -s 120
exit
