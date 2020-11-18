<#

DESCRIPTION:
This script automatically dismount the UPD vhd files from the VDI VM if there are no logon user using this UPD. 
This can resolve the problem that user get temp profile since its UPD vhd disk is still in use. 

Since psexec needs to remotely connect to the target VDI first. Local test shows that Win7 VDI may not work since it doesn't have firewall port enabled for file share first.
To resolve the problem, now we query the session from RDCB.

USAGE: 
Create schedule job on HyerV host which hosting the VDI VMs.
Tested on 2012 R2/2016 HyperV host.
Tested with Win7 & Win10 VDI VM.

#>



#VDI VM name prefix string. It is used to find the VMs created by VDI template
$VDIVMNamePrefix = 'vdi'
$RDCBName = 'win2019-1.test.com'
#$VDICollecationName = @("vditest","Virtual Desktop Collection")
$VDICollecationName = @("vditest")


#Find all VMs running on Hyper-V
$VDIVMs = Get-VM | Where-Object { $_.Name -like $VDIVMNamePrefix +'*'}
foreach ($VDIVM in $VDIVMs)
{
    #Get the VM VHDx file information. For VDI UPD disk file, it is mounted on SCSI controller
    $VDIVMDisks = Get-VMHardDiskDrive -VMName $VDIVM.Name -ControllerType SCSI | Where-Object { $_.Path -like '*UVHD-S-*'}
    foreach ($VDIVMDisk in $VDIVMDisks)
    {
        try
        { 
            #Get user SID from Path, sample: \\dc-iscsi2016\upd\UVHD-S-1-5-21-316331092-3460643704-2307707921-2109.vhdx
            $tempResultArray = $VDIVMDisk.Path.split("\")
            $UserSIDVHDX = $tempResultArray[$tempResultArray.Count -1 ]
            $UserSID = $UserSIDVHDX.Substring("UVHD-".Length, $UserSIDVHDX.Length - "UVHD-".Length - ".vhdx".Length)
        
            #convert SID to user name
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($UserSID)
            $objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
            #remove domain name and just use username
            $objUsername = $objUser.value.split("\")[1]
        
            #If the VM State is Running, check if there are logon sessions in the VM. 
            $VDIVMState = $VDIVM.State
            $NeedToDismountVHD = $false

            if ($VDIVM.State -eq "Running")
            {
                #If the VM has logon session, get the current logon user SID. VM name is same as VDI computer name
                #Get all of the VDI RDP user from RDCB                
                $VDIUserSessions = Get-RDUserSession -ConnectionBroker $RDCBName -CollectionName $VDICollecationName
                $NeedToDismountVHD = $true

                foreach ($VDIUserSession in $VDIUserSessions)
                {                             
                    if($objUsername -eq $VDIUserSession.UserName) {
                        #if the user still has a session, no matter if it is Active or Disconnected, we should not dismount the VHD   
                        $NeedToDismountVHD = $false
                        break
                    }
                }
            }
            else
            {
                $NeedToDismountVHD = $true
            }
    
            #Dismount the VHDx from VDI VM
            if ($NeedToDismountVHD)
            {
                Write-Host "Dismount UPD " + $VDIVMDisk.Path + " of VM " + $VDIVM.Name
                $VDIVMDisk | Remove-VMHardDiskDrive
            }
        }
        catch
        {
            Write-Host $Error
        }
    }
}
