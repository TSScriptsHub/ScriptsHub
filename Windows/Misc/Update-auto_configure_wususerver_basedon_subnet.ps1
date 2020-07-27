<#
DESCRIPTION:
This powershell script is used to configure the WSUS server based on different subnets

System/Requirement：
Require to run on server 2012 R2 or above

USAGE
1.You should build subnets and wsus server mapping table as follows before you try to run the script, if you have multiport information for different WSUS server we can define the mapping port arraylist too
$subnetreflist= ("10.54.64.0/18", "10.54.128.0/17", "10.54.0.0/19")
$wsusreflist= ("10.54.249.20", "10.54.249.20", "10.54.0.208")
#>

#Basic mapping table and settings
$subnetreflist= ("10.54.64.0/18", "10.54.128.0/17", "10.54.0.0/19","10.128.7.0/24", "10.128.8.0/24", "10.128.12.0/24","192.168.219.0/24", "10.128.15.0/24", "10.128.0.0/24","172.18.0.0/22", "192.168.201.0/24", "10.128.36.0/24","10.128.196.0/24", "10.128.197.125/25", "10.128.198.0/24","10.52.16.0/22", "10.52.23.0/24", "10.52.24.0/24")
$wsusreflist= ("10.54.249.20", "10.54.249.20", "10.54.0.208","10.128.63.25", "10.128.63.25", "10.128.63.25", "10.128.63.25", "10.128.63.25", "10.128.63.25", "10.128.63.25", "10.128.63.25", "10.128.63.25", "10.128.63.25", "10.128.63.25", "10.128.63.25","10.52.25.212", "10.52.25.212", "10.52.25.212")
$port=8530   # when have multiport information for different WSUS server we can define port arraylist
$caltime=Get-Date
$currenttime=Get-Date -Format 'yyyyMMddHHmm'
$traceLog="C:\test\tracelog_"+$currenttime+".txt"  #used for tracing excution logs
$checkflag = -1  #used for recording the subnet fall-in index

#Registry set function
function Set-RegistryValue($key, $name, $value, $type) { 
    if ((Test-Path $key) -eq $false) 
    {
         md $key | Out-Null 
    } 
    Set-ItemProperty $key $name $value -type $type
} 

#Mask convert to bits function 
function MaskToBits ($MaskString)
{
  
    $mask = ([IPAddress] $MaskString).Address
    for ( $bitCount = 0; $mask -ne 0; $bitCount++ ) {
    $mask = $mask -band ($mask - 1)
    }
    $bitCount
}

#bits convert to Mask function 
function Get-IPv4SubnetMask ([int] $Length){
    $MaskBinary = ('1' * $Length).PadRight(32, '0')
    $DottedMaskBinary = $MaskBinary -replace '(.{8}(?!\z))', '${1}.'
    $SubnetMask = ($DottedMaskBinary.Split('.') | foreach { [Convert]::ToInt32($_, 2) }) -join '.'
    $SubnetMask
}
					   
#Subnet check function 
function checkfallinSubnet ($IPString, $MaskString, $subnetString)
{

    $tempbit = MaskToBits $MaskString
    if($subnetString -ne "")
    {
        $network, [int]$subnetlen = $subnetString.Split('/')
        $networkparse=([IPAddress] (([IPAddress] $IPString).Address -band ([IPAddress] $MaskString).Address)).IPAddressToString

        $sunnetmasktmp=Get-IPv4SubnetMask $subnetlen        
        $networktmp=([IPAddress] (([IPAddress] $networkparse).Address -band ([IPAddress] $sunnetmasktmp).Address)).IPAddressToString
        
        if($network -eq $networktmp){
            $True
        }
		else{
            $False			  
        }
    }
    else
    {
        $False
    }
}

#Main Function

"Execution time: "+$caltime | Out-File -Filepath $traceLog -Append  | out-null
"" | Out-File -Filepath $traceLog -Append  | out-null
"================Script Start================" | Out-File -Filepath $traceLog -Append  | out-null
"" | Out-File -Filepath $traceLog -Append  | out-null



#try to get host ipaddress and subnetmask
$Networktemp = Get-WmiObject Win32_NetworkAdapterConfiguration | ? {$_.IPEnabled}
$IPAddress  = $Networktemp.IpAddress[0]
$SubnetMask  = $Networktemp.IPSubnet[0]
									   

<#
#for test manually

$IPAddress ="10.54.24.74"
$SubnetMask= "255.255.252.0"
#>

"   Current IPAddress: "+$IPAddress | Out-File -Filepath $traceLog -Append  | out-null
"   Current SubnetMask: "+$SubnetMask | Out-File -Filepath $traceLog -Append  | out-null

#try to get host ipaddress and subnetmask
for($i=0; $i -lt $subnetreflist.Count; $i++)
{
    if($checkflag -eq -1)
    {
        $flag = checkfallinSubnet $IPAddress $SubnetMask $subnetreflist[$i]
        if($flag -eq $true)  #check subnet fall-in or not
        {
            $checkflag = $i;
            "   Current IP is belong to the subnet: "+$subnetreflist[$checkflag] | Out-File -Filepath $traceLog -Append  | out-null
            break
        }
    }
}

if($checkflag -ne -1)
{   
#fall-in one subent ,look for the mapping wsus server and set registry 
    $tempWUServer ="http://"+$wsusreflist[$checkflag]+":"+$port  
    "   Start check and set WSUS server："+$tempWUServer | Out-File -Filepath $traceLog -Append  | out-null

    $keys = "HKLM:SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
	$name = "WUServer"
	$type = "String"

	Set-RegistryValue $keys $name $tempWUServer $type

    $keys = "HKLM:SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
	$name = "WUStatusServer"
	$type = "String"

	Set-RegistryValue $keys $name $tempWUServer $type 

#restart Windows Update service
    "   Ready to restart Windows Update Service" | Out-File -Filepath $traceLog -Append  | out-null
    Start-Sleep -s 2
    Net stop wuauserv
    Net start wuauserv
    "   Restart Windows Update Service successful" | Out-File -Filepath $traceLog -Append  | out-null
						
}
else
{
    "   Current IP is not belong to any subnet according to the arraylist, you should check the network manualy" | Out-File -Filepath $traceLog -Append  | out-null
}

"" | Out-File -Filepath $traceLog -Append  | out-null
"=================Script END=================" | Out-File -Filepath $traceLog -Append  | out-null