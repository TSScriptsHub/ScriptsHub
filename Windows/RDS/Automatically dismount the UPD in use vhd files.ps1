<#

DESCRIPTION:
This powershell script runs on the RDSH to dismount the orphaned UPD disk for the users no RDP sessions.
It scans all of the mounted UPD disks first, get the user name through the UPD disk image path. 
It checks if the user name is in the RDP user list (no matter active or disconnected). 
For the UPD disks not having user name in the RDP user list, it will be dismounted. 

USAGE: 
-. Require to run on RDHS with 2012 R2 or above

NOTE: 
saweng, Oct 2017

#>

#Emunate all mounted VHDs
$VHDs = Get-WmiObject win32_diskdrive | Where {$_.Model -contains "Microsoft Virtual Disk"}
foreach($VHD in $VHDs)
{
    try {
        #Get the disk image path by uding DeviceID
        $VHDDetailedInfo = Get-DiskImage -DevicePath $VHD.DeviceID
        #Here we get ImagePath, which contains the SID

        #Get user SID from ImagePath, sample: \\dc-iscsi2016\upd\UVHD-S-1-5-21-316331092-3460643704-2307707921-2109.vhdx
        $tempResultArray = $VHDDetailedInfo.ImagePath.split("\")
        $UserSIDVHDX = $tempResultArray[$tempResultArray.Count -1 ]
        $UserSID = $UserSIDVHDX.Substring("UVHD-".Length, $UserSIDVHDX.Length - "UVHD-".Length - ".vhdx".Length)
        
        #convert SID to user name
        $objSID = New-Object System.Security.Principal.SecurityIdentifier($UserSID)
        $objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
        #remove domain name and just use username
        $objUsername = $objUser.value.split("\")[1]

        #get all of the RDP user by built-in command query user
        $NeedToDismountVHD = $true
        quser | Select-Object -Skip 1 | ForEach-Object {
            $CurrentLine = $_.Trim() -Replace '\s+',' ' -Split '\s'
            if($objUsername -eq $CurrentLine[0]) {
                #if the user still has a session, no matter if it is Active or Disconnected, we should not dismount the VHD   
                $NeedToDismountVHD = $false
            }
        }
        
        #dismount the VHD without a user session
        if($NeedToDismountVHD) {
            Dismount-DiskImage -ImagePath $VHDDetailedInfo.ImagePath
            write-host "Successfully dismount VHD" $VHDDetailedInfo.ImagePath
        }       
    } catch {
        #ignore the error and go with next
        write-host "Error dismount VHD" $VHD.DeviceID

    }
