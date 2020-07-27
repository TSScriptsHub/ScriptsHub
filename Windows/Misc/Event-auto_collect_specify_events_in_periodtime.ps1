<#
DESCRIPTION:
This powershell script is used to auto collect the NPS related events in each 5min period and export to the file on remote server 

System/Requirement：
Require to run on server 2012 R2 or above

Usage：
1.Specify the outputfile and outputdebuglog
2.Default check period is 300s
#>

$outputfile="\\x.x.x.x\test\npslog.csv"  #output file for application analysis,you can set in local path or remote path
$outputdebuglog="\\x.x.x.x\test\npscollect_debuglog.txt"  #output trace log, you can set in local path or remote path
$checkperiod=300   #check interval,default value is 300s


function waitsec   #Calculate the actual wait time
{  
    $timecount=[int](get-date -uformat "%s")
    $checkperiod-($timecount%$checkperiod)
}

function getnpslogs  #Collect nps related logs
{
    $caltime=get-date
    $outputstring="======Start collect NPS log at "+$caltime+"======"
    $outputstring
    $outputstring |  Out-File -Filepath $outputdebuglog -Append  | out-null

    "Collecting NPS related log from security log"
    "Collecting NPS related log from security log" |  Out-File -Filepath $outputdebuglog -Append  | out-null
    Get-EventLog -LogName security | 
	Where-Object {
		($_.InstanceID -match "6272" -or $_.InstanceID -match "6273" -or $_.InstanceID -match "6274" -or $_.InstanceID -match "6275") -and ((New-TimeSpan $caltime -end $_.TimeGenerated).TotalSeconds -gt -$checkperiod)
	}|
	Select MachineName,TimeGenerated,EventID,EntryType,Source,Message | Export-CSV $outputfile -NoTypeInformation

    "Collecting NPS related log from system log"
    "Collecting NPS related log from system log" |  Out-File -Filepath $outputdebuglog -Append  | out-null
    Get-EventLog -LogName system | 
	Where-Object {
		($_.Source -match "NPS") -and ((New-TimeSpan $caltime -end $_.TimeGenerated).TotalSeconds -gt -300)
	}|
	Select MachineName,TimeGenerated,EventID,EntryType,Source,Message | Export-CSV $outputfile -NoTypeInformation -Append

    $outputstring="========Collecting complete========="
    $outputstring
    $outputstring |  Out-File -Filepath $outputdebuglog -Append  | out-null
    ""
    "" |  Out-File -Filepath $outputdebuglog -Append  | out-null
}

Start-Sleep -s (waitsec)  #wait for period time sync

while(1)
{
    (getnpslogs)
    Start-Sleep -s (waitsec)
    if(Test-path $outputfile)
    {
        del $outputfile
    }
}
