<#
DESCRIPTION:
This powershell script is used to check if all the Cluster Shared Volume useage reaches the specific percent value.
If the useage reaches the value, the script will send email to a specific mailbox。

System/Requirement：
Require to run on server 2012 or above
#>

$To = "destination@163.com"
$From = "source@qq.com"
$Subject = "Not Enough Space on Cluster Shared Volume" 

$smtpServer = "smtp.qq.com"
$smtpPort = 25
$username = "source@qq.com"
$password = "password"
[int]$MinFree = 30
 
$csvs = Get-ClusterSharedVolume 
foreach ($csv in $csvs) { 
    $csvinfos = $csv | Select-Object -Property Name -ExpandProperty SharedVolumeInfo 
    foreach ( $csvinfo in $csvinfos ) { 
        $obj = New-Object PSObject -Property @{ 
            Name        = $csv.Name 
            Path        = $csvinfo.FriendlyVolumeName 
            Size        = $csvinfo.Partition.Size 
            FreeSpace   = $csvinfo.Partition.FreeSpace 
            UsedSpace   = $csvinfo.Partition.UsedSpace 
            PercentFree = $csvinfo.Partition.PercentFree 
        } 

        if ($($obj.PercentFree) -lt $MinFree) { 
            $body = "WARNING: Free space on $($obj.Name) CSV is below warning threshold."
            $body += "Current free space: $($obj.PercentFree)%"

            #send email
            $SMTPMessage = New-Object System.Net.Mail.MailMessage($From, $To, $Subject, $body)
            $SMTPClient = New-Object Net.Mail.SmtpClient($smtpServer, $SmtpPort) 
            $SMTPClient.EnableSsl = $false 
            $SMTPClient.Credentials = New-Object System.Net.NetworkCredential($username, $password); 
            $SMTPClient.Send($SMTPMessage)
        }
    }
}