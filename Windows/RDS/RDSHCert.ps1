###################################################################################
#  File Name: RDSHCert.ps1														  #  
#  Description: Script to Configure RDSH Certificate in WMI RDP-TCP     	      #        
#  Version: 1.0		                                                              #
#  Creator: Ryan Mangan				                                              #
#  Emails: Ryan.mangan@systechitsolutions.co.uk									  #
#  Blog: Ryanmangansitblog.com		           					                  # 
# 				                                                                  #
#  Date: March 2014                                                               #
#  Notes: RDSH Certificate Deployment											  #
#                                                                                 #
###################################################################################  

param (
    [Parameter(Mandatory=$TRUE, HelpMessage="PFX Certificate file path eg c:\certs\test.pfx")]
    [String]
    $Filepath,
  [Parameter(Mandatory=$TRUE, HelpMessage="Certificate Password")]
    [String]
    $Password
    )

$pass = ConvertTo-SecureString $Password -AsPlainText -Force 
Import-PfxCertificate -FilePath $Filepath -Password $pass -CertStoreLocation cert:\localMachine\my
$path = (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").__path`

Get-ChildItem cert:\localmachine\my 
 write-host " ---------------------Copy The ThumbPrint and Paste Below----------------" -ForegroundColor Green 

$Thumbprint = Read-Host "Enter Thumbprint here"   

Set-WmiInstance -Path $path -argument @{SSLCertificateSHA1Hash=$Thumbprint}

