<#
DESCRIPTION:
This powershell script is used to check the monitors information from win10 machines in domain environment 

System/Requirement：
Require to run on server 2012 R2 or above

USAGE:
You can specify the check host list as follows
---host.txt---
host1
10.10.10.10
host2
---------------
#>


$hostpath="C:\temp\host.txt"
$currenttime=Get-Date -Format 'yyyyMMddHHmm'
$outputcsv_win10="C:\temp\checklist_win10_"+$currenttime+".csv"
$unreachable_hostlist="C:\temp\checkfail_unreachable_"+$currenttime+".txt"
$checkfail_hostlist_win10="C:\temp\checkfail_win10_wmi_"+$currenttime+".txt"
$monitorObject02_win10=@()
$skip_hostlist_win7="C:\temp\skiphost_win7_"+$currenttime+".txt"

#parse check host list
$checkhost= get-content $hostpath

write-host "============================Start the host check loop============================"
Write-host ""
#Check host monitor info
for($i=0;$i -lt $checkhost.Length;$i++)
{
    $tempstr="----------------------Start check host "+$checkhost[$i]+"----------------------"
    Write-Host $tempstr       

    $Pingtest=Test-Connection -ComputerName  $checkhost[$i] -quiet
    if($Pingtest -like "$False"){ 
        $tempstr="Host "+$checkhost[$i]+" unreachable, please check the network for this host first" 
        Write-host $tempstr -ForegroundColor Red
        $checkhost[$i] | Out-File -Filepath $unreachable_hostlist -Append
        Write-host "----------------------Check Failed----------------------"
        Write-host ""
        continue
    }

#Collecting data
    Write-host "Collecting data................"

    $temposversion=(Get-WmiObject -Class Win32_OperatingSystem -ComputerName $checkhost[$i]).Caption
    $iswin7version=$temposversion | findstr "7"
    if($iswin7version)
    {
        $tempstr="Host OS version is Win 7, skip" 
        Write-host $tempstr -ForegroundColor Red
        $checkhost[$i] | Out-File -Filepath $skip_hostlist_win7 -Append
        Write-host "----------------------Skip Check----------------------"
        Write-host ""
        continue
    }
    
    try
    {
        $Monitors=Get-WmiObject WmiMonitorID -ComputerName $checkhost[$i] -Namespace root\wmi
        $vedioinfos=@(Get-WmiObject win32_videocontroller -ComputerName $checkhost[$i] | select caption, Current*Resolution)

    }
    catch
    {
        $tempstr="Fail to collet data from "+$checkhost[$i]+" , please check the permission on the remote host" 
        Write-host $tempstr -ForegroundColor Red
        $checkhost[$i] | Out-File -Filepath $checkfail_hostlist_win10 -Append
        continue
    }
        
    $Monitortmpobj=@($Monitors | select UserFriendlyName,SerialNumberID)

   
        
    for($k=0;$k -lt $Monitortmpobj.Length;$k++)
    {
        $monitorObject01_win10 = new-object PSObject
        $monitorObject01_win10 | add-member -membertype NoteProperty -name "Host" -Value $checkhost[$i]
        $monitorObject01_win10 | add-member -membertype NoteProperty -name "OS version" -Value $temposversion
        $Name = ($Monitortmpobj[$k].UserFriendlyName  -notmatch '^0$' | ForEach{[char]$_}) -join ""
	    $Serial = ($Monitortmpobj[$k].SerialNumberID  -notmatch '^0$' | ForEach{[char]$_}) -join ""
        $monitorObject01_win10 | add-member -membertype NoteProperty -name "Monitor Name" -Value $Name
        $monitorObject01_win10 | add-member -membertype NoteProperty -name "Monitor SerialNumber" -Value $Serial

        if($vedioinfos[$k] -ne $null)
        {
            $monitorObject01_win10 | add-member -membertype NoteProperty -name "Vedio Controller" -Value $vedioinfos[$k].caption
            $tempresolution=($vedioinfos[$k].CurrentHorizontalResolution).ToString()+"*"+($vedioinfos[$k].CurrentVerticalResolution).ToString()
            $monitorObject01_win10 | add-member -membertype NoteProperty -name "Resolution" -Value $tempresolution
        }
        else
        {
            $monitorObject01_win10 | add-member -membertype NoteProperty -name "Vedio Controller" -Value $vedioinfos[0].caption
            $tempresolution=($vedioinfos[0].CurrentHorizontalResolution).ToString()+"*"+($vedioinfos[0].CurrentVerticalResolution).ToString()
            $monitorObject01_win10 | add-member -membertype NoteProperty -name "Resolution" -Value $tempresolution
        }

        $monitorObject02_win10 += $monitorObject01_win10
    }
    Write-host "----------------------Check Finished----------------------"
    Write-host ""
        
}

$monitorObject02_win10 | Export-Csv $outputcsv_win10 -NoTypeInformation
Write-host ""
write-host "============================Finish the host check loop============================"
write-host "Output List File (Win10): $outputcsv_win10" -ForegroundColor Green
write-host "Fail List (Unreachable): $unreachable_hostlist" -ForegroundColor Red
write-host "Fail List (Win10--WINRM Service): $checkfail_hostlist_win10" -ForegroundColor Red
write-host "Skip check list (Win7): $skip_hostlist_win7" -ForegroundColor Red
