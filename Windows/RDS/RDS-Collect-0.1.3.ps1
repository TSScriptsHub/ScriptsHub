$version = "RDS-Collect (0.1.3-190828)"

# by Robert Viktor Klemencz - robert.klemencz@microsoft.com


# IMPORTANT NOTICE: RDS-Collect is designed to collect information that will help Microsoft Customer Support Services (CSS) 
# troubleshoot an issue you may be experiencing with Windows.
# 
# The collected data may contain Personally Identifiable Information (PII) and/or sensitive data, such as (but not limited to) 
# IP addresses, PC names and user names.
#
# Once data collection has been completed, RDS-Collect will compress the results into a CAB file.
# This CAB file is not automatically sent to Microsoft - you can send this file to Microsoft CSS using a secure file transfer 
# tool - please discuss this with your support professional and also any concerns you may have.
#
# For further information on Microsoft's Data Protection visit the following link: 
# http://msdpn.azurewebsites.net/default?LID=62 


# =============================================================================


# Functions

Function Write-Log {
  param( [string] $msg)
  $msg = (get-date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $msg
  Write-Host $msg -ForegroundColor Cyan
  $msg | Out-File -FilePath $outfile -Append
}

Function Write-LogDetails {
$status = 0 # <<< set it to "1" to enable verbose output of executed commands

if ($status -eq 1) {
  param( [string] $msg )
  $msg = (get-date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $msg
  Write-Host $msg -ForegroundColor DarkGray
  $msg | Out-File -FilePath $outfile -Append
  }
else {}
}

Function Write-LogError {
  param( [string] $msg )
  $msg = (get-date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $msg
  # Write-Host $msg -ForegroundColor Yellow
  $msg | Out-File -FilePath $outfile -Append
}

Function Write-LogNotes {
  param( [string] $msg )
  # $msg = (get-date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $msg
  Write-Host $msg -ForegroundColor Yellow
  $msg | Out-File -FilePath $outfile -Append
}

Function ExecQuery {
  param(
    [string] $NameSpace,
    [string] $Query
  )
  # Write-Log ("Executing query " + $Query)
  if ($PSVersionTable.psversion.ToString() -ge "3.0") {
    $ret = Get-CimInstance -Namespace $NameSpace -Query $Query -ErrorAction Continue 2>>$errfile
  } else {
    $ret = Get-WmiObject -Namespace $NameSpace -Query $Query -ErrorAction Continue 2>>$errfile
  }
  # Write-Log (($ret | measure).count.ToString() + " results")
  return $ret
}

Function ArchiveLog {
  param( [string] $LogName )
  $cmd = "wevtutil al """+ $resDir + "\Events_" + $LogName + ".evtx"" /l:en-us >>""" + $outfile + """ 2>>""" + $errfile + """"
  Write-LogDetails $cmd
  Invoke-Expression $cmd
}

Function Win10Ver {
  param(
    [string] $Build
  )
  if ($build -eq 14393) {
    return " (RS1 / 1607)"
  } elseif ($build -eq 15063) {
    return " (RS2 / 1703)"
  } elseif ($build -eq 16299) {
    return " (RS3 / 1709)"
  } elseif ($build -eq 17134) {
    return " (RS4 / 1803)"
  } elseif ($build -eq 17763) {
    return " (RS5 / 1809)"
  } elseif ($build -eq 18362) {
    return " (19H1 / 1903)"
  }
}

Add-Type -MemberDefinition @"
[DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern uint NetApiBufferFree(IntPtr Buffer);
[DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern int NetGetJoinInformation(
  string server,
  out IntPtr NameBuffer,
  out int BufferType);
"@ -Namespace Win32Api -Name NetApi32

Function GetNBDomainName {
  $pNameBuffer = [IntPtr]::Zero
  $joinStatus = 0
  $apiResult = [Win32Api.NetApi32]::NetGetJoinInformation(
    $null,               # lpServer
    [Ref] $pNameBuffer,  # lpNameBuffer
    [Ref] $joinStatus    # BufferType
  )
  if ( $apiResult -eq 0 ) {
    [Runtime.InteropServices.Marshal]::PtrToStringAuto($pNameBuffer)
    [Void] [Win32Api.NetApi32]::NetApiBufferFree($pNameBuffer)
  }
}

Function GetStore($store) {
  $certlist = Get-ChildItem ("Cert:\LocalMachine\" + $store)

  foreach ($cert in $certlist) {
    $EKU = ""
    foreach ($item in $cert.EnhancedKeyUsageList) {
      if ($item.FriendlyName) {
        $EKU += $item.FriendlyName + " / "
      } else {
        $EKU += $item.ObjectId + " / "
      }
    }

    $row = $tbcert.NewRow()

    foreach ($ext in $cert.Extensions) {
      if ($ext.oid.value -eq "2.5.29.14") {
        $row.SubjectKeyIdentifier = $ext.SubjectKeyIdentifier.ToLower()
      }
      if (($ext.oid.value -eq "2.5.29.35") -or ($ext.oid.value -eq "2.5.29.1")) { 
        $asn = New-Object Security.Cryptography.AsnEncodedData ($ext.oid,$ext.RawData)
        $aki = $asn.Format($true).ToString().Replace(" ","")
        $aki = (($aki -split '\n')[0]).Replace("KeyID=","").Trim()
        $row.AuthorityKeyIdentifier = $aki
      }
    }
    if ($EKU) {$EKU = $eku.Substring(0, $eku.Length-3)} 
    $row.Store = $store
    $row.Thumbprint = $cert.Thumbprint.ToLower()
    $row.Subject = $cert.Subject
    $row.Issuer = $cert.Issuer
    $row.NotAfter = $cert.NotAfter
    $row.EnhancedKeyUsage = $EKU
    $row.SerialNumber = $cert.SerialNumber.ToLower()
    $tbcert.Rows.Add($row)
  } 
}

Function FileVersion {
  param(
    [string] $FilePath,
    [bool] $Log = $false
  )
  if (Test-Path -Path $FilePath) {
    $fileobj = Get-item $FilePath
    $filever = $fileobj.VersionInfo.FileMajorPart.ToString() + "." + $fileobj.VersionInfo.FileMinorPart.ToString() + "." + $fileobj.VersionInfo.FileBuildPart.ToString() + "." + $fileobj.VersionInfo.FilePrivatepart.ToString()

    if ($log) {
      ($FilePath + "," + $filever + "," + $fileobj.CreationTime.ToString("yyyyMMdd HH:mm:ss")) | Out-File -FilePath ($resDir + "\FilesVersion.csv") -Append
    }
    return $filever | Out-Null
  } else {
    return ""
  }
}


# =============================================================================

$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $myWindowsPrincipal.IsInRole($adminRole)) {
  Write-Output "This script needs to be run as Administrator"
  exit
}

$Root = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path

$resName = "RDS-Results-" + $env:computername +"-" + $(get-date -f yyyyMMdd_HHmmss)
$resDir = $Root + "\" + $resName
$outfile = $resDir + "\_Script-Output.txt"
$errfile = $resDir + "\_Script-Errors.txt"
$RdrOut =  " >>""" + $outfile + """"
$RdrErr =  " 2>>""" + $errfile + """"
$fqdn = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName

$OSVer = ([environment]::OSVersion.Version.Major) + ([environment]::OSVersion.Version.Minor) /10

New-Item -itemtype directory -path $resDir | Out-Null

Write-Log $version

      

##### Disclaimer

Write-LogNotes "
=====================================================
IMPORTANT NOTICE: 

RDS-Collect is designed to collect information that will help Microsoft Customer Support Services (CSS) troubleshoot an 
issue you may be experiencing with Windows.

The collected data may contain Personally Identifiable Information (PII) and/or sensitive data, such as (but not limited to) 
IP addresses, PC names and user names.

Once data collection has been completed, RDS-Collect will compress the results into a CAB file.
This CAB file is not automatically sent to Microsoft - you can send this file to Microsoft CSS using a secure file transfer 
tool - please discuss this with your support professional and also any concerns you may have.

For further information on Microsoft's Data Protection visit the following link: 
http://msdpn.azurewebsites.net/default?LID=62
=====================================================
"


##### Collecting networking information

        Write-Log "[01/13] Collecting networking information"

        # Write-Log "..... Get-NetConnectionProfile output"
        Get-NetConnectionProfile | Out-File -FilePath ($resDir + "\NetConnectionProfile.txt") -Append

        # Write-Log "..... Exporting firewall rules"
        $cmd = "netsh advfirewall firewall show rule name=all >""" + $resDir + "\FirewallRules.txt""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

        # Write-Log "..... Exporting netstat output"
        $cmd = "netstat -anob >""" + $resDir + "\Netstat.txt""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

        # Write-Log "..... Exporting ipconfig /all output"
        $cmd = "ipconfig /all >""" + $resDir + "\Ipconfig.txt""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

        # Write-Log "..... Exporting proxy settings"
        "------------------" | Out-File -FilePath ($resDir + "\WinHTTP-Proxy.txt") -Append
        "NSLookup WPAD" | Out-File -FilePath ($resDir + "\WinHTTP-Proxy.txt") -Append
        "" | Out-File -FilePath ($resDir + "\WinHTTP-Proxy.txt") -Append
        $cmd = "nslookup wpad >>""" + $resDir + "\WinHTTP-Proxy.txt""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append


        #Write-Log "..... Exporting netsh http settings"
        $cmd = "netsh http show sslcert >>""" + $resDir + "\Netsh-http.txt""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd

        $cmd = "netsh http show urlacl >>""" + $resDir + "\Netsh-http.txt""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd

        $cmd = "netsh http show servicestate >>""" + $resDir + "\Netsh-http.txt""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd

        $cmd = "netsh http show iplisten >>""" + $resDir + "\Netsh-http.txt""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd



##### Exporting policy information

        Write-Log "[02/13] Collecting GPResult output"

        $cmd = "gpresult /h """ + $resDir + "\Gpresult.html""" + $RdrErr
        write-LogDetails $cmd
        Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append



##### Exporting group memberships

        Write-Log "[03/13] Exporting group memberships"

        # Write-Log "..... Exporting members of Remote Desktop Users group"
        $cmd = "net localgroup ""Remote Desktop Users"" >>""" + $resDir + "\GroupsMembership.txt""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

        # Write-Log "..... Exporting members of Administrators group"
        $cmd = "net localgroup ""Administrators"" >>""" + $resDir + "\GroupsMembership.txt""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

        # Write-Log "..... Exporting members of RDS Remote Access Servers group"
        $cmd = "net localgroup ""RDS Remote Access Servers"" >>""" + $resDir + "\GroupsMembership.txt""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

        # Write-Log "..... Exporting members of RDS Management Servers group"
        $cmd = "net localgroup ""RDS Management Servers"" >>""" + $resDir + "\GroupsMembership.txt""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

        # Write-Log "..... Exporting members of RDS Endpoint Servers group"
        $cmd = "net localgroup ""RDS Endpoint Servers"" >>""" + $resDir + "\GroupsMembership.txt""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

        # Write-Log "..... Exporting members of Offer Remote Assistance Helpers group"
        $cmd = "net localgroup ""Offer Remote Assistance Helpers"" >>""" + $resDir + "\GroupsMembership.txt""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append



##### Exporting registry keys

        Write-Log "[04/13] Exporting registry keys"

        if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server') {
        # Write-Log "..... Exporting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server"
        $cmd = "reg export 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server' """+ $resDir + "\Reg_TerminalServer-CCS.txt"" /y" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        } else {
          Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server' is not present"
        }
        
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server') {
        # Write-Log "..... Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server"
        $cmd = "reg export 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server' """+ $resDir + "\Reg_TerminalServer-WinNT.txt"" /y" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        } else {
          Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server' is not present"
        }

        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Terminal Server Client') {
        # Write-Log "..... Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Terminal Server Client"
        $cmd = "reg export 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Terminal Server Client' """+ $resDir + "\Reg_TerminalServerClient.txt"" /y" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        } else {
          Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Terminal Server Client' is not present"
        }

        if (Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies) {
        # Write-Log "..... Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies"
        $cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies """+ $resDir + "\Reg_System-Policies.txt"" /y" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        } else {
          Write-LogError "The registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies is not present"
        }

        if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL) {
        # Write-Log "..... Exporting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
        $cmd = "reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL """+ $resDir + "\Reg_SCHANNEL.txt"" /y" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        } else {
          Write-LogError "The registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL is not present"
        }

        if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography) {
        # Write-Log "..... Exporting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography"
        $cmd = "reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography """+ $resDir + "\Reg_Cryptography.txt"" /y" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        } else {
          Write-LogError "The registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography is not present"
        }

        if (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Cryptography) {
        # Write-Log "..... Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography"
        $cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography """+ $resDir + "\Reg_Cryptography-Policy.txt"" /y" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        } else {
          Write-LogError "The registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography is not present"
        }

        if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa) {
        # Write-Log "..... Exporting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
        $cmd = "reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa """+ $resDir + "\Reg_LSA.txt"" /y" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        } else {
          Write-LogError "The registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa is not present"
        }

        if (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation) {
          # Write-Log "..... Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
          $cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation """+ $resDir + "\Reg_CredentialDelegation-Policy.txt"" /y" + $RdrOut + $RdrErr
          Write-LogDetails $cmd
          Invoke-Expression $cmd
        } else {
          Write-LogError "The registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation is not present"
        }

        if (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') {
          # Write-Log "..... Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
          $cmd = "reg export 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' """+ $resDir + "\Reg_TerminalServices-Policy.txt"" /y" + $RdrOut + $RdrErr
          Write-LogDetails $cmd
          Invoke-Expression $cmd
        } else {
          Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' is not present"
        }       
               
       if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList') {
          # Write-Log "..... Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
          $cmd = "reg export 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' """+ $resDir + "\Reg_ProfileList.txt"" /y" + $RdrOut + $RdrErr
          Write-LogDetails $cmd
          Invoke-Expression $cmd
        } else {
          Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' is not present"
        }




##### Exporting event logs

        Write-Log "[05/13] Exporting event logs"

        # Write-Log "..... Exporting System log"
        $cmd = "wevtutil epl System """+ $resDir + "\Events_System.evtx""" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        ArchiveLog "System"

        # Write-Log "..... Exporting Application log"
        $cmd = "wevtutil epl Application """+ $resDir + "\Events_Application.evtx""" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        ArchiveLog "Application"

        # Write-Log "..... Exporting Security log"
        $cmd = "wevtutil epl Security """+ $resDir + "\Events_Security.evtx""" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        ArchiveLog "Security"

        # Write-Log "..... Exporting CAPI2 log"
        $cmd = "wevtutil epl Microsoft-Windows-CAPI2/Operational """+ $resDir + "\Events_CAPI2.evtx""" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        ArchiveLog "capi2"

        # Write-Log "..... Exporting Remote Desktop Services RdpCoreTS logs"
        $cmd = "wevtutil epl Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational """+ $resDir + "\Events_RemoteDesktopServicesRdpCoreTS-Operational.evtx""" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        ArchiveLog "RemoteDesktopServicesRdpCoreTS-Operational"

        $cmd = "wevtutil epl Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Admin """+ $resDir + "\Events_RemoteDesktopServicesRdpCoreTS-Admin.evtx""" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        ArchiveLog "RemoteDesktopServicesRdpCoreTS-Admin"

        # Write-Log "..... Exporting Remote Desktop Services RdpCoreCDV log"
        $cmd = "wevtutil epl Microsoft-Windows-RemoteDesktopServices-RdpCoreCDV/Operational """+ $resDir + "\Events_RemoteDesktopServicesRdpCoreCDV-Operational.evtx""" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        ArchiveLog "RemoteDesktopServicesRdpCoreCDV-Operational"

        # Write-Log "..... Exporting Terminal Services LocalSessionManager logs"
        $cmd = "wevtutil epl Microsoft-Windows-TerminalServices-LocalSessionManager/Operational """+ $resDir + "\Events_TerminalServicesLocalSessionManager-Operational.evtx""" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        ArchiveLog "TerminalServicesLocalSessionManager-Operational"

        $cmd = "wevtutil epl Microsoft-Windows-TerminalServices-LocalSessionManager/Admin """+ $resDir + "\Events_TerminalServicesLocalSessionManager-Admin.evtx""" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        ArchiveLog "TerminalServicesLocalSessionManager-Admin"

        # Write-Log "..... Exporting Terminal Services RemoteConnectionManager logs"
        $cmd = "wevtutil epl Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin """+ $resDir + "\Events_TerminalServicesRemoteConnectionManager-Admin.evtx""" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        ArchiveLog "TerminalServicesRemoteConnectionManager-Admin"

        $cmd = "wevtutil epl Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational """+ $resDir + "\Events_TerminalServicesRemoteConnectionManager-Operational.evtx""" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        ArchiveLog "TerminalServicesRemoteConnectionManager-Operational"

        # Write-Log "..... Exporting Terminal Services PnP Devices logs"
        $cmd = "wevtutil epl Microsoft-Windows-TerminalServices-PnPDevices/Admin """+ $resDir + "\Events_TerminalServicesPnPDevices-Admin.evtx""" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        ArchiveLog "TerminalServicesPnPDevices-Admin"

        $cmd = "wevtutil epl Microsoft-Windows-TerminalServices-PnPDevices/Operational """+ $resDir + "\Events_TerminalServicesPnPDevices-Operational.evtx""" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        ArchiveLog "TerminalServicesPnPDevices-Operational"

        # Write-Log "..... Exporting User Profile Service log"
        $cmd = "wevtutil epl 'Microsoft-Windows-User Profile Service/Operational' """+ $resDir + "\Events_UserProfileService-Operational.evtx""" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        ArchiveLog "UserProfileService-Operational"

        # Write-Log "..... Exporting Remote Assistance logs"
        $cmd = "wevtutil epl 'Microsoft-Windows-RemoteAssistance/Operational' """+ $resDir + "\Events_RemoteAssistance-Operational.evtx""" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        ArchiveLog "RemoteAssistance-Operational"

        $cmd = "wevtutil epl 'Microsoft-Windows-RemoteAssistance/Admin' """+ $resDir + "\Events_RemoteAssistance-Admin.evtx""" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        ArchiveLog "RemoteAssistance-Admin"

        # Write-Log "..... Exporting VHDMP logs"
        $cmd = "wevtutil epl 'Microsoft-Windows-VHDMP/Operational' """+ $resDir + "\Events_VHDMP-Operational.evtx""" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        ArchiveLog "VHDMP-Operational"

        # Write-Log "..... Exporting SMBclient and SMBserver logs"
        $cmd = "wevtutil epl 'Microsoft-Windows-SMBClient/Operational' """+ $resDir + "\Events_SMBClient-Operational.evtx""" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        ArchiveLog "SMBClient-Operational"

        $cmd = "wevtutil epl 'Microsoft-Windows-SMBClient/Connectivity' """+ $resDir + "\Events_SMBClient-Connectivity.evtx""" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        ArchiveLog "SMBClient-Connectivity"

        $cmd = "wevtutil epl 'Microsoft-Windows-SMBClient/Security' """+ $resDir + "\Events_SMBClient-Security.evtx""" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        ArchiveLog "SMBClient-Security"

        $cmd = "wevtutil epl 'Microsoft-Windows-SMBServer/Operational' """+ $resDir + "\Events_SMBServer-Operational.evtx""" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        ArchiveLog "SMBServer-Operational"

        $cmd = "wevtutil epl 'Microsoft-Windows-SMBServer/Connectivity' """+ $resDir + "\Events_SMBServer-Connectivity.evtx""" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        ArchiveLog "SMBServer-Connectivity"

        $cmd = "wevtutil epl 'Microsoft-Windows-SMBServer/Security' """+ $resDir + "\Events_SMBServer-Security.evtx""" + $RdrOut + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        ArchiveLog "SMBServer-Security"




##### Exporting SPN information

        Write-Log "[06/13] Exporting SPN information"

        $cmd = "setspn -L " + $env:computername + " >>""" + $resDir + "\SPN.txt""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        " " | Out-File ($resDir + "\SPN.txt") -Append

        "Searching WSMAN/" + $env:computername + " in the domain" | Out-File ($resDir + "\SPN.txt") -Append
        $cmd = "setspn -Q WSMAN/" + $env:computername + " >>""" + $resDir + "\SPN.txt""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        " " | Out-File ($resDir + "\SPN.txt") -Append

        "Searching WSMAN/" + $fqdn + " in the domain" | Out-File ($resDir + "\SPN.txt") -Append
        $cmd = "setspn -Q WSMAN/" + $fqdn + " >>""" + $resDir + "\SPN.txt""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        " " | Out-File ($resDir + "\SPN.txt") -Append

        "Searching WSMAN/" + $env:computername + " in the forest" | Out-File ($resDir + "\SPN.txt") -Append
        $cmd = "setspn -F -Q WSMAN/" + $env:computername + " >>""" + $resDir + "\SPN.txt""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        " " | Out-File ($resDir + "\SPN.txt") -Append

        "Searching WSMAN/" + $fqdn + " in the forest" | Out-File ($resDir + "\SPN.txt") -Append
        $cmd = "setspn -F -Q WSMAN/" + $fqdn + " >>""" + $resDir + "\SPN.txt""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        " " | Out-File ($resDir + "\SPN.txt") -Append

        "Searching TERMSRV/" + $env:computername + " in the domain" | Out-File ($resDir + "\SPN.txt") -Append
        $cmd = "setspn -Q TERMSRV/" + $env:computername + " >>""" + $resDir + "\SPN.txt""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        " " | Out-File ($resDir + "\SPN.txt") -Append

        "Searching TERMSRV/" + $fqdn + " in the domain" | Out-File ($resDir + "\SPN.txt") -Append
        $cmd = "setspn -Q TERMSRV/" + $fqdn + " >>""" + $resDir + "\SPN.txt""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        " " | Out-File ($resDir + "\SPN.txt") -Append

        "Searching TERMSRV/" + $env:computername + " in the forest" | Out-File ($resDir + "\SPN.txt") -Append
        $cmd = "setspn -F -Q TERMSRV/" + $env:computername + " >>""" + $resDir + "\SPN.txt""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        " " | Out-File ($resDir + "\SPN.txt") -Append

        "Searching TERMSRV/" + $fqdn + " in the forest" | Out-File ($resDir + "\SPN.txt") -Append
        $cmd = "setspn -F -Q TERMSRV/" + $fqdn + " >>""" + $resDir + "\SPN.txt""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        " " | Out-File ($resDir + "\SPN.txt") -Append



##### Exporting certificate information

        Write-Log "[07/13] Exporting certificate information"

        # Write-Log "..... Collecting certificates details"
        $cmd = "Certutil -verifystore -v MY > """ + $resDir + "\Certificates-My.txt""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd

        $tbCert = New-Object system.Data.DataTable
        $col = New-Object system.Data.DataColumn Store,([string]); $tbCert.Columns.Add($col)
        $col = New-Object system.Data.DataColumn Thumbprint,([string]); $tbCert.Columns.Add($col)
        $col = New-Object system.Data.DataColumn Subject,([string]); $tbCert.Columns.Add($col)
        $col = New-Object system.Data.DataColumn Issuer,([string]); $tbCert.Columns.Add($col)
        $col = New-Object system.Data.DataColumn NotAfter,([DateTime]); $tbCert.Columns.Add($col)
        $col = New-Object system.Data.DataColumn IssuerThumbprint,([string]); $tbCert.Columns.Add($col)
        $col = New-Object system.Data.DataColumn EnhancedKeyUsage,([string]); $tbCert.Columns.Add($col)
        $col = New-Object system.Data.DataColumn SerialNumber,([string]); $tbCert.Columns.Add($col)
        $col = New-Object system.Data.DataColumn SubjectKeyIdentifier,([string]); $tbCert.Columns.Add($col)
        $col = New-Object system.Data.DataColumn AuthorityKeyIdentifier,([string]); $tbCert.Columns.Add($col)

        GetStore "My"

        # Write-Log "..... Matching issuer thumbprints"
        $aCert = $tbCert.Select("Store = 'My' ")
        foreach ($cert in $aCert) {
          $aIssuer = $tbCert.Select("SubjectKeyIdentifier = '" + ($cert.AuthorityKeyIdentifier).tostring() + "'")
          if ($aIssuer.Count -gt 0) {
            $cert.IssuerThumbprint = ($aIssuer[0].Thumbprint).ToString()
          }
        }
        $tbcert | Export-Csv ($resDir + "\Certificates.tsv") -noType -Delimiter "`t"



##### Exporting installed Windows updates

        Write-Log "[08/13] Collecting the list of installed hotfixes"

        Get-HotFix -ErrorAction SilentlyContinue 2>>$errfile | Sort-Object -Property InstalledOn -ErrorAction SilentlyContinue | Out-File $resDir\Hotfixes.txt



##### Collecting file versions and system information

        if (Test-Path 'C:\Windows\system32\mstsc.exe') {
            FileVersion -Filepath ($env:windir + "\system32\mstsc.exe") -Log $true
        } else {
            Write-LogError "The file 'C:\Windows\system32\mstsc.exe' is not present"
        }

        if (Test-Path 'C:\Windows\system32\mstscax.dll') {
            FileVersion -Filepath ($env:windir + "\system32\mstscax.dll") -Log $true
        } else {
            Write-LogError "The file 'C:\Windows\system32\mstscax.dll' is not present"
        }

        if (Test-Path 'C:\Windows\system32\win32k.sys') {
            FileVersion -Filepath ($env:windir + "\system32\win32k.sys") -Log $true
        } else {
            Write-LogError "The file 'C:\Windows\system32\win32k.sys' is not present"
        }

        if (Test-Path 'C:\Windows\system32\rdpshell.exe') {
            FileVersion -Filepath ($env:windir + "\system32\rdpshell.exe") -Log $true
        } else {
            Write-LogError "The file 'C:\Windows\system32\rdpshell.exe' is not present"
        }

        if (Test-Path 'C:\Windows\system32\rdpinit.exe') {
            FileVersion -Filepath ($env:windir + "\system32\rdpinit.exe") -Log $true
        } else {
            Write-LogError "The file 'C:\Windows\system32\rdpinit.exe' is not present"
        }
        
        Write-Log "[09/13] Collecting details about currently running processes"
        $proc = ExecQuery -Namespace "root\cimv2" -Query "select Name, CreationDate, ProcessId, ParentProcessId, WorkingSetSize, UserModeTime, KernelModeTime, ThreadCount, HandleCount, CommandLine, ExecutablePath from Win32_Process"
        if ($PSVersionTable.psversion.ToString() -ge "3.0") {
          $StartTime= @{e={$_.CreationDate.ToString("yyyyMMdd HH:mm:ss")};n="Start time"}
        } else {
          $StartTime= @{n='StartTime';e={$_.ConvertToDateTime($_.CreationDate)}}
        }

        if ($proc) {
          $proc | Sort-Object Name |
          Format-Table -AutoSize -property @{e={$_.ProcessId};Label="PID"}, @{e={$_.ParentProcessId};n="Parent"}, Name,
          @{N="WorkingSet";E={"{0:N0}" -f ($_.WorkingSetSize/1kb)};a="right"},
          @{e={[DateTime]::FromFileTimeUtc($_.UserModeTime).ToString("HH:mm:ss")};n="UserTime"}, @{e={[DateTime]::FromFileTimeUtc($_.KernelModeTime).ToString("HH:mm:ss")};n="KernelTime"},
          @{N="Threads";E={$_.ThreadCount}}, @{N="Handles";E={($_.HandleCount)}}, $StartTime, CommandLine |
          Out-String -Width 500 | Out-File -FilePath ($resDir + "\RunningProcesses.txt")


          Write-Log "[10/13] Collecting file version of running and key binaries"
          $binlist = $proc | Group-Object -Property ExecutablePath
          foreach ($file in $binlist) {
            if ($file.Name) {
              FileVersion -Filepath ($file.name) -Log $true
            }
          }


          Write-Log "[11/13] Collecting services details"
          $svc = ExecQuery -NameSpace "root\cimv2" -Query "select  ProcessId, DisplayName, StartMode,State, Name, PathName, StartName from Win32_Service"

          if ($svc) {
            $svc | Sort-Object DisplayName | Format-Table -AutoSize -Property ProcessId, DisplayName, StartMode,State, Name, PathName, StartName |
            Out-String -Width 400 | Out-File -FilePath ($resDir + "\Services.txt")
          }


          Write-Log "[12/13] Collecting system information"
          $pad = 27
          $OS = ExecQuery -Namespace "root\cimv2" -Query "select Caption, CSName, OSArchitecture, BuildNumber, InstallDate, LastBootUpTime, LocalDateTime, TotalVisibleMemorySize, FreePhysicalMemory, SizeStoredInPagingFiles, FreeSpaceInPagingFiles from Win32_OperatingSystem"
          $CS = ExecQuery -Namespace "root\cimv2" -Query "select Model, Manufacturer, SystemType, NumberOfProcessors, NumberOfLogicalProcessors, TotalPhysicalMemory, DNSHostName, Domain, DomainRole from Win32_ComputerSystem"
          $BIOS = ExecQuery -Namespace "root\cimv2" -query "select BIOSVersion, Manufacturer, ReleaseDate, SMBIOSBIOSVersion from Win32_BIOS"
          $TZ = ExecQuery -Namespace "root\cimv2" -Query "select Description from Win32_TimeZone"
          $PR = ExecQuery -Namespace "root\cimv2" -Query "select Name, Caption from Win32_Processor"

          $ctr = Get-Counter -Counter "\Memory\Pool Paged Bytes" -ErrorAction Continue 2>>$errfile
          $PoolPaged = $ctr.CounterSamples[0].CookedValue 
          $ctr = Get-Counter -Counter "\Memory\Pool Nonpaged Bytes" -ErrorAction Continue 2>>$errfile
          $PoolNonPaged = $ctr.CounterSamples[0].CookedValue 

          "Computer name".PadRight($pad) + " : " + $OS.CSName | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
          "Model".PadRight($pad) + " : " + $CS.Model | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
          "Manufacturer".PadRight($pad) + " : " + $CS.Manufacturer | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
          "BIOS Version".PadRight($pad) + " : " + $BIOS.BIOSVersion | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
          "BIOS Manufacturer".PadRight($pad) + " : " + $BIOS.Manufacturer | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
          "BIOS Release date".PadRight($pad) + " : " + $BIOS.ReleaseDate | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
          "SMBIOS Version".PadRight($pad) + " : " + $BIOS.SMBIOSBIOSVersion | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
          "SystemType".PadRight($pad) + " : " + $CS.SystemType | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
          "Processor".PadRight($pad) + " : " + $PR.Name + " / " + $PR.Caption | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
          "Processors physical/logical".PadRight($pad) + " : " + $CS.NumberOfProcessors + " / " + $CS.NumberOfLogicalProcessors | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
          "Memory physical/visible".PadRight($pad) + " : " + ("{0:N0}" -f ($CS.TotalPhysicalMemory/1mb)) + " MB / " + ("{0:N0}" -f ($OS.TotalVisibleMemorySize/1kb)) + " MB" | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
          "Pool Paged / NonPaged".PadRight($pad) + " : " + ("{0:N0}" -f ($PoolPaged/1mb)) + " MB / " + ("{0:N0}" -f ($PoolNonPaged/1mb)) + " MB" | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
          "Free physical memory".PadRight($pad) + " : " + ("{0:N0}" -f ($OS.FreePhysicalMemory/1kb)) + " MB" | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
          "Paging files size / free".PadRight($pad) + " : " + ("{0:N0}" -f ($OS.SizeStoredInPagingFiles/1kb)) + " MB / " + ("{0:N0}" -f ($OS.FreeSpaceInPagingFiles/1kb)) + " MB" | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
          "Operating System".PadRight($pad) + " : " + $OS.Caption + " " + $OS.OSArchitecture | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
          "Build Number".PadRight($pad) + " : " + $OS.BuildNumber + (Win10Ver $OS.BuildNumber)| Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
          "Installation type".PadRight($pad) + " : " + (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").InstallationType | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
          "Time zone".PadRight($pad) + " : " + $TZ.Description | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
          "Install date".PadRight($pad) + " : " + $OS.InstallDate | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
          "Last boot time".PadRight($pad) + " : " + $OS.LastBootUpTime | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
          "Local time".PadRight($pad) + " : " + $OS.LocalDateTime | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
          "DNS Hostname".PadRight($pad) + " : " + $CS.DNSHostName | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
          "DNS Domain name".PadRight($pad) + " : " + $CS.Domain | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
          "NetBIOS Domain name".PadRight($pad) + " : " + (GetNBDomainName) | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
          $roles = "Standalone Workstation", "Member Workstation", "Standalone Server", "Member Server", "Backup Domain Controller", "Primary Domain Controller"
          "Domain role".PadRight($pad) + " : " + $roles[$CS.DomainRole] | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append

          $drives = @()
          $drvtype = "Unknown", "No Root Directory", "Removable Disk", "Local Disk", "Network Drive", "Compact Disc", "RAM Disk"
          $Vol = ExecQuery -NameSpace "root\cimv2" -Query "select * from Win32_LogicalDisk"
          foreach ($disk in $vol) {
            $drv = New-Object PSCustomObject
            $drv | Add-Member -type NoteProperty -name Letter -value $disk.DeviceID 
            $drv | Add-Member -type NoteProperty -name DriveType -value $drvtype[$disk.DriveType]
            $drv | Add-Member -type NoteProperty -name VolumeName -value $disk.VolumeName 
            $drv | Add-Member -type NoteProperty -Name TotalMB -Value ($disk.size)
            $drv | Add-Member -type NoteProperty -Name FreeMB -value ($disk.FreeSpace)
            $drives += $drv
          }
          $drives | 
          Format-Table -AutoSize -property Letter, DriveType, VolumeName, @{N="TotalMB";E={"{0:N0}" -f ($_.TotalMB/1MB)};a="right"}, @{N="FreeMB";E={"{0:N0}" -f ($_.FreeMB/1MB)};a="right"} |
          Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
        } else {
          $proc = Get-Process | Where-Object {$_.Name -ne "Idle"}
          $proc | Format-Table -AutoSize -property id, name, @{N="WorkingSet";E={"{0:N0}" -f ($_.workingset/1kb)};a="right"},
          @{N="VM Size";E={"{0:N0}" -f ($_.VirtualMemorySize/1kb)};a="right"},
          @{N="Proc time";E={($_.TotalProcessorTime.ToString().substring(0,8))}}, @{N="Threads";E={$_.threads.count}},
          @{N="Handles";E={($_.HandleCount)}}, StartTime, Path | 
          Out-String -Width 300 | Out-File -FilePath ($resDir + "\RunningProcesses.txt")
        }



##### Archive results

        Write-Log "[13/13] Archiving results"

        $destination = $Root + "\" + $resName + ".zip"
        $cmd = "Compress-Archive -Path $resDir -DestinationPath $destination -CompressionLevel Optimal -Force"
        Write-LogDetails $cmd
        Invoke-Expression $cmd
        $amsg = "Location of the collected and archived data: " + $Root + "\"
        Write-Log $amsg
