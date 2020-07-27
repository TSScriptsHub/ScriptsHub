<#
DESCRIPTION:
This powershell script is used to check the server's RDS installed status in domain environment 

System/Requirement：
Require to run on server 2012 R2 or above

USAGE:
You can specify the check host list as follows
---host.txt---
host1
10.10.10.10
host2
host3
---------------
#>

$hostpath="C:\temp\host.txt"
$currenttime=Get-Date -Format 'yyyyMMddHHmm'
$outputcsv="C:\temp\rdscheck_"+$currenttime+".csv"
$checkfail_hostlist="C:\temp\rdscheckfail_unreachable"+$currenttime+".txt"
$checkfail_hostlist_winrm="C:\temp\rdscheckfail_winrm_"+$currenttime+".txt"
$rdsObject02=@()
$maincontent = {    
	Get-WindowsFeature | where name -like "rds*"
}
 

#parse check host list
$checkhost= @(get-content $hostpath)


write-host "============================Start the RDS check loop============================"
Write-host ""
#Check rds status
for($i=0;$i -lt $checkhost.Length;$i++)
{
    $tempstr="----------------------Start check host "+$checkhost[$i]+"----------------------"
    Write-Host $tempstr

#check if remote host is reachable
    $Pingtest=Test-Connection -ComputerName  $checkhost[$i] -quiet
    if($Pingtest -like "$False"){ 
        $tempstr="Host "+$checkhost[$i]+" unreachable, please check the network for this host first" 
        Write-host $tempstr -ForegroundColor Red
        $checkhost[$i] | Out-File -Filepath $checkfail_hostlist -Append
        Write-host "----------------------Check Failed----------------------"
        Write-host ""
        continue
    }
    Write-host "Collecting Data................"

#Get information from remote server       
    $temposversion=(Get-WmiObject -Class Win32_OperatingSystem -ComputerName $checkhost[$i]).Caption | findstr "2008"
    $temposversion
    if($temposversion)
    {
        $tempstr="Host OS version is 2008/2008 R2" 
        Write-host $tempstr     
        $rdsinfo=Invoke-Command –ComputerName $checkhost[$i] –ScriptBlock $maincontent
    }
    else
    {
        $rdsinfo=Get-WindowsFeature -ComputerName $checkhost[$i] | where name -like "rds*"
    }

    if($rdsinfo -ne $null)
    {
    #Encapsulate specified member parameters to the target object
        $rdsObject01 = new-object PSObject
        $rdsObject01 | add-member -membertype NoteProperty -name "Host" -Value $checkhost[$i]
        $rdsObject01 | add-member -membertype NoteProperty -name "RDS-Connection-Broker" -Value $rdsinfo[0].Installed
        $rdsObject01 | add-member -membertype NoteProperty -name "RDS-Gateway" -Value $rdsinfo[1].Installed
        $rdsObject01 | add-member -membertype NoteProperty -name "RDS-Licensing" -Value $rdsinfo[2].Installed
        $rdsObject01 | add-member -membertype NoteProperty -name "RDS-RD-Server" -Value $rdsinfo[3].Installed
        $rdsObject01 | add-member -membertype NoteProperty -name "RDS-Virtualization" -Value $rdsinfo[4].Installed
        $rdsObject01 | add-member -membertype NoteProperty -name "RDS-Web-Access" -Value $rdsinfo[5].Installed
        $rdsObject01 | add-member -membertype NoteProperty -name "RDS-Licensing-UI " -Value $rdsinfo[6].Installed


        $rdsObject02 += $rdsObject01
     }
     else
     {
        $tempstr="Can not Get RDS Status from remote host "+$checkhost[$i] 
        Write-host $tempstr -ForegroundColor Red
		$checkhost[$i] | Out-File -Filepath $checkfail_hostlist_winrm -Append
        Write-host "----------------------Check Failed----------------------" 
        continue 
     }
    Write-host "----------------------Check Finished----------------------"
    Write-host ""
}


$rdsObject02 | Export-Csv $outputcsv -NoTypeInformation
 

Write-host ""
write-host "============================Finish the RDS check loop============================"
write-host "Ouput List File: $outputcsv" -ForegroundColor Green
write-host "Fail List (Unreachable): $checkfail_hostlist" -ForegroundColor Red
write-host "Fail List (WINRM Service): $checkfail_hostlist_winrm" -ForegroundColor Red