<#
DESCRIPTION:
This powershell script is used to check update installed status on remote servers which are in non-domain environment and export the check results,in script we store the 
{IP,Username,Password} mapping table in excel file

System/Requirement：
Require to run on server 2012 R2 or above

USAGE:
1.Build {IP,Username,Password} mapping table
---Excel content---
     IP             Username            Password
10.190.154.173    Administrator1          pwd01
10.190.155.4      Administrator2          pwd02
10.190.155.19     Administrator3          pwd03
-------------------

#>

#Example 2: #Specific KB check in non-domain environment and export the result
Write-Host "This script only works for the host that ip address is known"
#You need build the {IP,Username,Password} mapping table to replace the value {iplist,username,password}
#$iplist="10.190.154.173","10.190.155.43","10.190.155.19"
#$username="Administrator","Administrator","Administrator"
#$password="pwd01!","pwd02!","pwd03"

#Auto parse all mapping information from excel file
$Mappingfilepath=Read-Host "Please Input the ip-account mapping excel file path (like C:\test\excelfile.xlsx)"
while((Test-Path -Path $Mappingfilepath) -eq $false)
{
    $Mappingfilepath = Read-Host "File $Mappingfilepath is not exsit,Please enter a valid file path"
}

$KBnumber=Read-Host "Please Input the KB number you want to check"
$currenttime=Get-Date -Format 'yyyyMMddHHmm'
#$fpath="C:\test\"+$KBnumber+"_"+$currenttime+".csv"
$fpath="C:\test\"+$KBnumber+"_"+$currenttime+".txt"
$fpath_fail="C:\test\"+$KBnumber+"_"+$currenttime+"_fail.txt"
$excel = New-Object -ComObject Excel.Application
# open Excel file
$workbook = $excel.Workbooks.Open($Mappingfilepath)
    
# uncomment next line to make Excel visible
#$excel.Visible = $true
    
$sheet = $workbook.ActiveSheet

$column = 2
$row = 1
$totalcount=0
$successcount=0
$failcount=0

while($sheet.cells.Item($column, $row).Text)
{	
	$totalcount=$totalcount+1
	Write-Host "================================Host $totalcount============================================"
	$iplist=$sheet.cells.Item($column, $row).Text
	Write-Host "Start parse host [$iplist] information"
	$row=$row+1
	$username=$sheet.cells.Item($column, $row).Text
	$row=$row+1
	$password=$sheet.cells.Item($column, $row).Text
	$row=1
	$column=$column+1
	$checkfailObject = New-Object -TypeName System.Object 
	
    #Check connectivity
	$Pingtest=Test-Connection -ComputerName $iplist -quiet
	if($Pingtest-like"$False"){
		$warningmsg="host ["+$iplist+"] can not reachable, please check the network for this host first"
		Write-Warning $warningmsg
		$failcount=$failcount+1
		$failreason="Host unreachable"
		$checkfailObject | Add-Member -MemberType NoteProperty -Name "IP Address" -Value $iplist
		$checkfailObject | Add-Member -MemberType NoteProperty -Name "Fail Reason" -Value $failreason
		$checkfailObject | Add-Member -MemberType NoteProperty -Name "IP Address" -Value $iplist
		$checkfailObject | Add-Member -MemberType NoteProperty -Name "Fail Reason" -Value $failreason
		Write-Output -InputObject $checkfailObject | Out-File -Filepath $fpath_fail -Append
		continue
	}
	Write-Host "Start check hot-fix in host [$iplist] username is $username and password is $password"
	$hashotfix = "False"

	#Get information from remote server 
	$pwd=ConvertTo-SecureString $password -AsPlainText -Force
	$cred=New-Object System.Management.Automation.PSCredential -ArgumentList $username,$pwd
	try
	{
		$checkhotfix=Get-HotFix -Credential $cred -ComputerName $iplist |
		Where-Object { 
			$_.HotfixID -like $KBnumber 
		}
	}
	catch
	{
		Write-Warning "Host [$iplist] account information may be wrong, you need check it from the source file later"
		$failcount=$failcount+1
		$failreason="Wrong account information"
		$checkfailObject | Add-Member -MemberType NoteProperty -Name "IP Address" -Value $iplist
		$checkfailObject | Add-Member -MemberType NoteProperty -Name "Fail Reason" -Value $failreason
		$checkfailObject | Add-Member -MemberType NoteProperty -Name "IP Address" -Value $iplist
		$checkfailObject | Add-Member -MemberType NoteProperty -Name "Fail Reason" -Value $failreason
		Write-Output -InputObject $checkfailObject | Out-File -Filepath $fpath_fail -Append
		continue
	}
	if($checkhotfix)
	{
		$hashotfix = "True"
	}

	$computername=(Get-WmiObject -Credential $cred -Class Win32_ComputerSystem -ComputerName $iplist).name
	$osversion=(Get-WmiObject -Credential $cred -Class Win32_OperatingSystem -ComputerName $iplist).Caption

	#Encapsulate specified member parameters to the target object   
	$checkObject = New-Object -TypeName System.Object 
	$checkObject | Add-Member -MemberType NoteProperty -Name "Computer Name" -Value $computername
	$checkObject | Add-Member -MemberType NoteProperty -Name "OSVersion" -Value $osversion
	$checkObject | Add-Member -MemberType NoteProperty -Name "IP Address" -Value $iplist
	$checkObject | Add-Member -MemberType NoteProperty -Name "KB Number" -Value $KBnumber
	$checkObject | Add-Member -MemberType NoteProperty -Name "Is Installed" -Value $hashotfix
	Write-Output "Ready to output the check result for host [$iplist]"
	#Output the target object to the specified file
	$successcount=$successcount+1
	#Write-Output -InputObject $checkObject | Export-Csv $fpath -Append -NoTypeInformation
	Write-Output -InputObject $checkObject | Out-File -Filepath $fpath -Append
}
	Write-Host "Check Report for $KBnumber"
	Write-Host "Total: $totalcount"
	Write-Host "Success: $successcount"
	Write-Host "Fail: $failcount"
	
$excel.Quit()

if($failcount -gt 0)
{
	Write-Host "You can find the check result from $fpath and $fpath_fail, this script windows will exit in 2 min"
}
else
{
	Write-Host "You can find the check result from $fpath , this script windows will exit in 2 min"	
}
Start-Sleep -s 120
exit 