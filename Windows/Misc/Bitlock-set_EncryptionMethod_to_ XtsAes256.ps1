<#
DESCRIPTION:
This powershell script is used to set bitlock encryptionmethod to XtsAes256 

System/Requirement：
Require to run on server 2012 R2 or aboveUSAGE:

USAGE:
N/A
#>
$checkperiod=600   #check interval,default value is 600s

$encryptmethodstr = Get-BitLockerVolume -MountPoint C | Format-List | findstr "EncryptionMethod"
if($encryptmethodstr.Contains("XtsAes"))
{
    if(-not $encryptmethodstr.Contains("XtsAes256"))
    {
        #write-host "EncryptionMethod is not XtsAes256, need change to XtsAes256"
        #write-host "Start Disable BitLocker"
        Disable-BitLocker -MountPoint "C:"
        $disableaction = 1

        while($disableaction -eq 1)
        {
            $count =[int](get-date -uformat "%s")
            if($count % $checkperiod -eq 0)
            {
                $checkstatus=Get-BitLockerVolume -MountPoint C | Format-List | findstr "VolumeStatus"

                if($checkstatus.Contains("DecryptionInProgress"))
                {
                    #write-host "DecryptionInProgress......"
                }
                else
                {
                    #write-host "Finish Disable BitLocker"
                    $disableaction = 0
                }
            }
        }

        #write-host "Enable BitLocker with EncryptionMethod XtsAes256......"
        Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -RecoveryPasswordProtector
    }
    else
    {
        #write-host "EncryptionMethod is XtsAes256, no need change"
    }
}
else
{
    #write-host "Set encryptionMethod to XtsAes256"
    #write-host "Enable BitLocker with EncryptionMethod XtsAes256....."
    Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -RecoveryPasswordProtector   
}