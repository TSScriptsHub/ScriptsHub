<#
DESCRIPTION:
This powershell script is used to export acl informaitions for specify directory and export to csv file 

System/Requirement：
Require to run on server 2012 R2 or above

USAGE:
N/A
#>#

$path="C:\test"
$currenttime=Get-Date -Format 'yyyyMMddHHmm'
$outputfilecsv="C:\test\diraccesslist_"+$currenttime+".csv"
$p = Get-Item $path
if ($p.Attributes -eq 'Directory')
{
    Get-ChildItem -Path $path -Recurse -ErrorAction:SilentlyContinue | 
        Where-Object -FilterScript { $_.PsISContainer -eq $True } | 
            ForEach-Object {
                $tmpobj =@(Get-Acl -Path $_.Fullname | Select -Property PSChildName, Owner -ExpandProperty Access)

                $tmpobj | ForEach-Object {
                $ResultObject = New-Object -TypeName System.Object 
                $ResultObject | Add-Member -MemberType NoteProperty -Name "Path" -Value $_.PSChildName
                $ResultObject | Add-Member -MemberType NoteProperty -Name "Owner" -Value $_.Owner
                $ResultObject | Add-Member -MemberType NoteProperty -Name "FileSystemRights" -Value $_.FileSystemRights
                $ResultObject | Add-Member -MemberType NoteProperty -Name "AccessControlType" -Value $_.AccessControlType
                $ResultObject | Add-Member -MemberType NoteProperty -Name "IdentityReference" -Value $_.IdentityReference
                $ResultObject | Add-Member -MemberType NoteProperty -Name "IsInherited" -Value $_.IsInherited
                $ResultObject | Add-Member -MemberType NoteProperty -Name "InheritanceFlags" -Value $_.InheritanceFlags
                $ResultObject | Add-Member -MemberType NoteProperty -Name "PropagationFlags" -Value $_.PropagationFlags
                $ResultObject | Export-Csv -Path $outputfilecsv -NoTypeInformation -Append                
                }
            } 
}