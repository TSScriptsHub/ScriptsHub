<#
DESCRIPTION:
This powershell script is used to auto collect the event 4624 and event 4625 informations in latest 1 hour and export to csv file

System/Requirement：
Require to run on server 2012 R2 or above

USAGE:
1.You can specify the checkrange, default is 3600s(1 hour) 
#>
$checkrange=3600
$caltime=Get-Date
$currenttime=Get-Date -Format 'yyyyMMddHHmmss'
#fpath="\\x.x.x.x\test\dclog+"+$currenttime+".csv"  #you can specify the output network path 
$fpath="C:\test\dclog_"+$currenttime+".csv"

Write-Warning "now is collecting the logs"
Get-EventLog -LogName Security |
	Where-Object {
		($_.InstanceID -match "4624" -or $_.InstanceID -match "4625") -and ((New-TimeSpan $caltime -end $_.TimeGenerated).TotalSeconds -gt -$checkrange)
	}|
	Select MachineName,TimeGenerated,EventID,EntryType,Source,Message | Export-CSV $fpath -NoTypeInformation