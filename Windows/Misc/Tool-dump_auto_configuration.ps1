<#
DESCRIPTION:
This powershell script is used to automatic configure the dump file for BSOD, HANG issues debugging 

	Support below scenarios
	---BSOD issue dump config---
	1.check must use full dump or not , if yes, try to config full dump in avaliable disk
	2.check must use full dump or not , if no, config depend on the physical mememory
	a.If physical memory is above 32G, prefer to config kernel dump,pagefile use default value 20G,if has no enough disk free space to config 20G pagefile, try default value 6G
	b.If physical memory is below 32G, try to config full dump.If has no enough disk free space to config full dump, try to config kernel dump.If has no enough disk free space to config pagefile as physical memory size, try default value 6G
	---Hang issue dump config/Trigger dump requirement---
	1.check must use full dump or not , if yes, try to config full dump in avaliable disk
	2.check must use full dump or not , if no, config depend on the physical mememory
	a.If physical memory is above 32G, prefer to config kernel dump,pagefile use default value 20G,if has no enough disk free space to config 20G pagefile, try default value 6G
	b.If physical memory is below 32G, try to config full dump.If has no enough disk free space to config full dump, try to config kernel dump.If has no enough disk free space to config pagefile as physical memory size, try default value 6G
	---Restore Configuration which set by this script---
	Note:
	Add reserved_space option for disk usage protect,avoid performance risk
	Dumpflag: 0:nodump 1:fulldump 2:kernel dump
	Reportfile name: dumpconfig_##dateformat##.txt
	Orginal reg backup: orginalreg_backup.txt

System/Requirement：
Require to run on server 2012 R2 or above


USAGE:
1.Typical scenarios reference:
Scenario: BSOD + auto restart                                  Type: 1-1-2-2
Scenario: BSOD + disable auto restart                          Type: 1-1-2-1
Scenario: BSOD + full dump required+ auto restart              Type: 1-1-1-2
Scenario: BSOD + full dump required+ disable auto restart      Type: 1-1-1-1
Scenario: Hang + auto restart                                  Type: 1-2-2-2
Scenario: Hang + disable auto restart                          Type: 1-2-2-1
Scenario: Hang + full dump required+ auto restart              Type: 1-2-1-2
Scenario: Hang + full dump required+ disable auto restart      Type: 1-2-1-1
Scenario: Rollback dump auto configuration                     Type: 2

#>

$issuetype=0
$config_flag=0
$pagefile_size=0
$needfull=0
$disable_autostart=0
$output_phymem=""
$output_pagefile=""
$output_dumppath=""
$output_dumptype=""
$output_autorestart=""
$reserved_space=8192
$orginal_config_settings="C:\orginalreg_backup.txt"
$invalidinput=0

function Get-RegistryValues($key) { 
    (Get-Item $key).GetValueNames() 
}

function Get-RegistryValue($key, $name) { 
    (Get-ItemProperty $key $name).$name
} 

function Set-RegistryValue($key, $name, $value, $type) { 
    if ((Test-Path $key) -eq $false) 
    {
         md $key | Out-Null 
    } 
    Set-ItemProperty $key $name $value -type $type
 } 

function Remove-RegistryKey($key) { 
    Remove-Item $key -Force
}

function Remove-RegistryValue($key, $name) { 
    Remove-ItemProperty $key $name
}

function restore_config()
{
	if(Test-Path $orginal_config_settings)
	{
		$fcontent=get-content $orginal_config_settings	

		$tmp_val=$fcontent | findstr "CrashDumpEnabled"
        $org_dumpenable_val=($tmp_val -split "=")[1]

		$tmp_val=$fcontent | findstr "DumpFile"
        $org_dumpfile_val=($tmp_val -split "=")[1]

		$tmp_val=$fcontent | findstr "PagingFiles"
        $org_pagefiles_val=($tmp_val -split "=")[1]

		$tmp_val=$fcontent | findstr "kbdhid_CrashOnCtrlScroll"
        $org_kbdhidscroll_val=($tmp_val -split "=")[1]

		$tmp_val=$fcontent | findstr "i8042prt_CrashOnCtrlScroll"
        $org_i8042prt_val=($tmp_val -split "=")[1]

		$tmp_val=$fcontent | findstr "NMICrashDump"
        $org_NMICrashDump_val=($tmp_val -split "=")[1]

		$tmp_val=$fcontent | findstr "AutoReboot"
        $org_autorestart_val=($tmp_val -split "=")[1]

		#reg reset
		$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
		$name="CrashDumpEnabled"
		$value=$org_dumpenable_val
		$type="DWord"
						
		Set-RegistryValue $keys $name $value $type

		$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
		$name="DumpFile"
		$value=$org_dumpfile_val
		$type="ExpandString"

		Set-RegistryValue $keys $name $value $type

		$finalpath=$value

		$keys="HKLM:SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
		$name="PagingFiles"
		$value=$org_pagefiles_val
		$type="MultiString"

		Set-RegistryValue $keys $name $value $type
		
	    $keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
		$name="AutoReboot"
		$value=$org_autorestart_val
		$type="DWORD"

		Set-RegistryValue $keys $name $value $type
						
		$keys="HKLM:SYSTEM\CurrentControlSet\Services\kbdhid\Parameters\"
		$name="CrashOnCtrlScroll"
		$value=$org_kbdhidscroll_val
		$type="DWORD"
        
        if($org_kbdhidscroll_val -eq 0)
        {
	        $tmpval=Get-RegistryValues $keys
            if($tmpval -and $tmpval.contains($name))
	        {
		        Remove-RegistryValue $keys $name

	        }
        }else
        {
            Set-RegistryValue $keys $name $value $type
        }
        
		$keys="HKLM:SYSTEM\CurrentControlSet\Services\i8042prt\Parameters\"
		$name="CrashOnCtrlScroll"
		$value=$org_i8042prt_val
		$type="DWORD"

        if($org_i8042prt_val -eq 0)
        {
	        $tmpval=Get-RegistryValues $keys
            if($tmpval -and $tmpval.contains($name))
	        {
		        Remove-RegistryValue $keys $name

	        }
        }else
        {
            Set-RegistryValue $keys $name $value $type
        }
						
		$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
		$name="NMICrashDump"
		$value=$org_NMICrashDump_val
		$type="DWORD"

        if($org_NMICrashDump_val -eq 0)
        {
	        $tmpval=Get-RegistryValues $keys
            if($tmpval -and $tmpval.contains($name))
	        {
		        Remove-RegistryValue $keys $name

	        }
        }else
        {
            Set-RegistryValue $keys $name $value $type
        }
		
        del $orginal_config_settings
        Write-Host "=====Success restore dump configuration======"
		Write-Warning "=====You need restart the computer to make it work!!!====="
	}else
    {
        Write-Warning "=====You haven't configure the dump file by running this script====="
    }

}


Write-Host "Typical scenarios:" -ForegroundColor green
Write-Host "1.If you have Blue screen issue, you can choose like 1-1-2-2" -ForegroundColor green
Write-Host "2.If you have hang or slow performance issue, you can choose like 1-2-1-2" -ForegroundColor green
Write-Host "3.If you want to trigger dump when issue reproduced, you can choose like 1-2-1-2" -ForegroundColor green
Write-Host "4.If you want to restore the configuration which set by this script, you can choose like 2" -ForegroundColor green
Write-Host ""
Write-Host "=====This tool is used to configure dump file in normal mode======"
Write-Host ""
do
{
	$operationtype=Read-Host "Please select the action to perform: 1.Dump Config 2.Restore Dump Config"
}while($operationtype -ne 1 -and $operationtype -ne 2)
Write-Host ""
if($operationtype -eq 2)
{

    Write-Host "=====Start Restore Dump Configure Flow======"
    restore_config
    Write-Host ""	
    Write-Host "The script window will exit after 1 minutes"
    Start-Sleep -s 60
    exit
}else
{
    Write-Host "=====Start Dump Configure Flow======"
}

Write-Host ""
do{
	$issuetype=Read-Host "Please select which scenario the dump used for: 1.BSOD  2.Hang"
}while($issuetype -ne 1 -and $issuetype -ne 2)

Write-Host ""

#backup orginal settings
#-----------------------
#reg read
$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
$name="CrashDumpEnabled"
$dumpenable_val=Get-RegistryValue $keys $name

$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
$name="DumpFile"
$dumpfile_val=Get-RegistryValue $keys $name


$keys="HKLM:SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
$name="PagingFiles"
$pagefiles_val=Get-RegistryValue $keys $name

$keys="HKLM:SYSTEM\CurrentControlSet\Services\kbdhid\Parameters\"
$name="CrashOnCtrlScroll"
if (Test-Path $keys)
{
	$tmpval=Get-RegistryValues $keys
    if($tmpval -and $tmpval.contains($name))
	{
		$kbdhidscroll_val=Get-RegistryValue $keys $name
	}
}else
{
	$kbdhidscroll_val=0
}


$keys="HKLM:SYSTEM\CurrentControlSet\Services\i8042prt\Parameters\"
$name="CrashOnCtrlScroll"
if (Test-Path $keys)
{
	$tmpval=Get-RegistryValues $keys
    if($tmpval -and $tmpval.contains($name))
	{
		$i8042prt_val=Get-RegistryValue $keys $name
	}
}else
{
	$i8042prt_val=0
}

$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
$name="NMICrashDump"
$tmpval=Get-RegistryValues $keys
if($tmpval -and $tmpval.contains($name))
{
	$NMICrashDump_val=Get-RegistryValue $keys $name
}else
{
	$NMICrashDump_val=0
}


$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
$name="AutoReboot"
$autorestart_val=Get-RegistryValue $keys $name

if(Test-Path $orginal_config_settings)
{
    del $orginal_config_settings
}

"CrashDumpEnabled="+$dumpenable_val | Out-File -Filepath $orginal_config_settings -Append
"DumpFile="+$dumpfile_val | Out-File -Filepath $orginal_config_settings -Append
"PagingFiles="+$pagefiles_val | Out-File -Filepath $orginal_config_settings -Append
"kbdhid_CrashOnCtrlScroll="+$kbdhidscroll_val | Out-File -Filepath $orginal_config_settings -Append
"i8042prt_CrashOnCtrlScroll="+$i8042prt_val | Out-File -Filepath $orginal_config_settings -Append
"NMICrashDump="+$NMICrashDump_val | Out-File -Filepath $orginal_config_settings -Append
"AutoReboot="+ $autorestart_val | Out-File -Filepath $orginal_config_settings -Append
#-----------------------

if($autorestart_val -eq 0)
{
	$output_autorestart="False"
}else
{
	$output_autorestart="True"
}



if($issuetype -eq 1)
{
	Write-Host "=====Ready to Config Dump for BSOD Issue======"
	Write-Host "----------------------------------------------------------------------------------------"
	do
	{
		$needfull=Read-Host "Should we collect full dump file or not: 1.Yes 2.No"
	}while($needfull -ne 1 -and $needfull -ne 2)
	do
	{
		$disable_autostart=Read-Host "Should we disable auto restart funtion: 1.Yes 2.No"
	}while($disable_autostart -ne 1 -and $disable_autostart -ne 2)
	if($needfull -eq 1)
	{
		try{
			#Get the physical memory info
			$phymem_info=(Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory/1024/1024
			$temp_phymem=[int32]($phymem_info/1024)
			$output_phymem="$temp_phymem"+"GB"			
			#try to config full dump in avaliable disk partition
			Write-Host "=====Try to config full dump in avaliable disk partition====="
			#Get the storage info
			get-WmiObject win32_logicaldisk | Where-Object {$_.FreeSpace -gt 12000000000} | Select DeviceID,FreeSpace |
				ForEach-Object {
                if($config_flag -eq 0)
			    {
				#Parse each disk free space
					$deviceid = $_.DeviceID
					$freespace = $_.FreeSpace/1024/1024
					$needfreespace = $phymem_info*2+257+$reserved_space
					$pagefile_size = [int32]($phymem_info/1024)*1024+257
					if($freespace -gt $needfreespace)
					{
						Write-Host "=====Disk $deviceid has enough free space, start to config full dump====="
						#reg modify
						$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
						$name="CrashDumpEnabled"
						$value=1
						$type="DWord"
						
						Set-RegistryValue $keys $name $value $type

						$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
						$name="DumpFile"
						$value="$deviceid\WINDOWS\MEMORY.DMP"
						$type="ExpandString"

						Set-RegistryValue $keys $name $value $type

						$finalpath=$value

						$keys="HKLM:SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
						$name="PagingFiles"
						$value="$deviceid\pagefile.sys $pagefile_size $pagefile_size"
						$type="MultiString"

						Set-RegistryValue $keys $name $value $type
						
						$output_pagefile="$pagefile_size"+"MB"
						$output_dumppath=$finalpath
						$output_dumptype="Full Dump"
						
						if($disable_autostart -eq 1)
						{
							$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
							$name="AutoReboot"
							$value=0
							$type="DWORD"

							Set-RegistryValue $keys $name $value $type
							$output_autorestart="False"
						}
						else
						{
							$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
							$name="AutoReboot"
							$value=1
							$type="DWORD"

							Set-RegistryValue $keys $name $value $type
							$output_autorestart="True"							
						}
										
						$config_flag = 1

						Write-Host "=====Success config full dump file in $finalpath====="
						
					}
					else
					{
						#disk $deviceid has no more space
						Write-Warning "=====Disk $deviceid has no enough space to config full dump file====="
						
					}
            }
			}

			if($config_flag -gt 0)
			{
				Write-Warning "=====You need restart the computer to make it work!!!====="  
			}
			
			if($config_flag -eq 0)
			{
				Write-Warning "=====All disks have no enough free space, fail to config the full dump info, you need check manully =====" 
			}						
		}catch
		{
			Write-Warning "=====All disks have no enough free space, fail to config the full dump info, you need check manully====="
		}
	}
	else
	{
		try{	
			#Get the physical memory info
			$phymem_info=(Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory/1024/1024
			$temp_phymem=[int32]($phymem_info/1024)
			$output_phymem="$temp_phymem"+"GB"
			#Get the stroage info
			get-WmiObject win32_logicaldisk | Where-Object {$_.FreeSpace -gt 12000000000} | Select DeviceID,FreeSpace |
				ForEach-Object {
                if($config_flag -eq 0)
			    {
					#Parse each disk free space
					$deviceid = $_.DeviceID
					$freespace = $_.FreeSpace/1024/1024
					if($phymem_info -lt 32000)
					{
						#phical mememory is less than 32G , prefer to config full dump
						Write-Host "=====Phical mememory is less than 32G , prefer to config full dump====="
						$needfreespace = $phymem_info*2+257+$reserved_space
						$pagefile_size = [int32]($phymem_info/1024)*1024+257
						if($freespace -gt $needfreespace)
						{
							Write-Host "=====Disk $deviceid has enough free space, ready to config full dump====="
							#reg modify
							$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
							$name="CrashDumpEnabled"
							$value=1
							$type="DWord"
							
							Set-RegistryValue $keys $name $value $type

							$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
							$name="DumpFile"
							$value="$deviceid\WINDOWS\MEMORY.DMP"
							$type="ExpandString"

							Set-RegistryValue $keys $name $value $type

							$finalpath=$value
							
							$keys="HKLM:SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
							$name="PagingFiles"
							$value="$deviceid\pagefile.sys $pagefile_size $pagefile_size"
							$type="MultiString"

							Set-RegistryValue $keys $name $value $type
							
							if($disable_autostart -eq 1)
							{
								$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
								$name="AutoReboot"
								$value=0
								$type="DWORD"

								Set-RegistryValue $keys $name $value $type
								$output_autorestart="False"
							}
							else
							{
								$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
								$name="AutoReboot"
								$value=1
								$type="DWORD"

								Set-RegistryValue $keys $name $value $type
								$output_autorestart="True"							
							}
							
							$output_pagefile="$pagefile_size"+"MB"
							$output_dumptype="Full Dump"
							$output_dumppath=$finalpath
							
							$config_flag = 1

							Write-Host "=====Phical memory is less than 32G , success config full dump file in $finalpath====="
							
						}
						else
						{
							#disk $deviceid has no more space
							Write-Warning "=====Disk $deviceid has no enough space to config full dump file====="
							
						}
					}
					else
					{
						#phical mememory is above 32G , prefer to config kernel dump
						Write-Host "=====Phical mememory is above 32G , prefer to config kernel dump====="
						$needfreespace = 40000+$reserved_space
						$pagefile_size = 20000
						if($freespace -gt $needfreespace)
						{
							#reg modify
							$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
							$name="CrashDumpEnabled"
							$value=2
							$type="DWord"
							
							Set-RegistryValue $keys $name $value $type

							$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
							$name="DumpFile"
							$value="$deviceid\WINDOWS\MEMORY.DMP"
							$type="ExpandString"

							Set-RegistryValue $keys $name $value $type

							$finalpath=$value

							$keys="HKLM:SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
							$name="PagingFiles"
							$value="$deviceid\pagefile.sys $pagefile_size $pagefile_size"
							$type="MultiString"

							Set-RegistryValue $keys $name $value $type
							
							if($disable_autostart -eq 1)
							{
								$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
								$name="AutoReboot"
								$value=0
								$type="DWORD"

								Set-RegistryValue $keys $name $value $type
								$output_autorestart="False"
							}
							else
							{
								$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
								$name="AutoReboot"
								$value=1
								$type="DWORD"

								Set-RegistryValue $keys $name $value $type
								$output_autorestart="True"							
							}
							
							$output_pagefile="$pagefile_size"+"MB"
							$output_dumppath=$finalpath
							$output_dumptype="Kernel Dump"
							$config_flag = 2
							
							Write-Host "=====Phical memory is above 32G , success config kernel dump file with pagefile 20GB in $finalpath====="
							
						 }else
						 {
							#disk $deviceid has no more space
							Write-Warning "=====Disk $deviceid has no enough space to config kernel dump file====="
							
						 }

					}
                }
				}

				if($config_flag -eq 0)
				{
					Write-Warning "=====All disk has no more freespace, just try to config a kernel dump with smaller pagefile====="
					#try to config kernel dump again, hard code
					$needfreespace = 12000+$reserved_space
					$pagefile_size = 6000
					get-WmiObject win32_logicaldisk | Where-Object {$_.FreeSpace -gt 12000000000} | Select DeviceID,FreeSpace |
					ForEach-Object {
                    if($config_flag -eq 0)
			        {
						#Parse each disk free space
						$deviceid = $_.DeviceID
						$freespace = $_.FreeSpace/1024/1024
						if($freespace -gt $needfreespace)
						{
							#reg modify
							$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
							$name="CrashDumpEnabled"
							$value=2
							$type="DWord"
								
							Set-RegistryValue $keys $name $value $type

							$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
							$name="DumpFile"
							$value="$deviceid\WINDOWS\MEMORY.DMP"
							$type="ExpandString"

							Set-RegistryValue $keys $name $value $type

							$finalpath=$value

							$keys="HKLM:SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
							$name="PagingFiles"
							$value="$deviceid\pagefile.sys $pagefile_size $pagefile_size"
							$type="MultiString"

							Set-RegistryValue $keys $name $value $type
							
							if($disable_autostart -eq 1)
							{
								$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
								$name="AutoReboot"
								$value=0
								$type="DWORD"

								Set-RegistryValue $keys $name $value $type
								$output_autorestart="False"
							}
							else
							{
								$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
								$name="AutoReboot"
								$value=1
								$type="DWORD"

								Set-RegistryValue $keys $name $value $type
								$output_autorestart="True"							
							}
							
							$output_pagefile="$pagefile_size"+"MB"
							$output_dumppath=$finalpath
							$output_dumptype="Kernel Dump"
							$config_flag = 2
							
							Write-Host "=====Config kernel dump file with pagefile 6GB in $finalpath====="
							
						}else
						{
							return
						}
                    }
					}
					if($config_flag -eq 0)
					{
						Write-Warning "=====All disks have no enough free space, fail to config the dump info, you need check manully====="
					}
				}

			if($config_flag -gt 0)
			{
				Write-Warning "=====You need restart the computer to make it work!!====="  
			}
		}catch
		{
			Write-Warning "=====All disks have no enough free space,fail to config the dump info, you need check manully====="
		}
	}
	Write-Host "----------------------------------------------------------------------------------------"
}
else
{
	Write-Host "=====Ready to Config Dump for Hang Issue====="
	Write-Host "----------------------------------------------------------------------------------------"
	do
	{
		$needfull=Read-Host "Should we collect full dump file or not: 1.Yes 2.No"
	}while($needfull -ne 1 -and $needfull -ne 2)
	do
	{
		$disable_autostart=Read-Host "Should we disable auto restart funtion: 1.Yes 2.No"
	}while($disable_autostart -ne 1 -and $disable_autostart -ne 2)
	if($needfull -eq 1)
	{
		try{
			#Get the physical memory info
			$phymem_info=(Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory/1024/1024
			$temp_phymem=[int32]($phymem_info/1024)
			$output_phymem="$temp_phymem"+"GB"			
			#try to config full dump in avaliable disk partition
			Write-Host "=====Try to config full dump in avaliable disk partition====="
			#Get the stroage info
			get-WmiObject win32_logicaldisk | Where-Object {$_.FreeSpace -gt 12000000000} | Select DeviceID,FreeSpace |
				ForEach-Object {
                if($config_flag -eq 0)
			    {
				#Parse each disk free space
					$deviceid = $_.DeviceID
					$freespace = $_.FreeSpace/1024/1024
					$needfreespace = $phymem_info*2+257+$reserved_space
					$pagefile_size = [int32]($phymem_info/1024)*1024+257
					if($freespace -gt $needfreespace)
					{
						Write-Host "=====Disk $deviceid has enough free space, start to config full dump====="
						#reg modify
						$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
						$name="CrashDumpEnabled"
						$value=1
						$type="DWord"
						
						Set-RegistryValue $keys $name $value $type

						$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
						$name="DumpFile"
						$value="$deviceid\WINDOWS\MEMORY.DMP"
						$type="ExpandString"

						Set-RegistryValue $keys $name $value $type

						$finalpath=$value

						$keys="HKLM:SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
						$name="PagingFiles"
						$value="$deviceid\pagefile.sys $pagefile_size $pagefile_size"
						$type="MultiString"

						Set-RegistryValue $keys $name $value $type
						
						$output_pagefile="$pagefile_size"+"MB"
						$output_dumppath=$finalpath
						$output_dumptype="Full Dump"
						
						if($disable_autostart -eq 1)
						{
							$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
							$name="AutoReboot"
							$value=0
							$type="DWORD"

							Set-RegistryValue $keys $name $value $type
							$output_autorestart="False"
						}
						else
						{
							$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
							$name="AutoReboot"
							$value=1
							$type="DWORD"

							Set-RegistryValue $keys $name $value $type
							$output_autorestart="True"							
						}
						
						$keys="HKLM:SYSTEM\CurrentControlSet\Services\kbdhid\Parameters\"
						$name="CrashOnCtrlScroll"
						$value=1
						$type="DWORD"

						Set-RegistryValue $keys $name $value $type

						$keys="HKLM:SYSTEM\CurrentControlSet\Services\i8042prt\Parameters\"
						$name="CrashOnCtrlScroll"
						$value=1
						$type="DWORD"

						Set-RegistryValue $keys $name $value $type
						$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
						$name="NMICrashDump"
						$value=1
						$type="DWORD"

						Set-RegistryValue $keys $name $value $type
						
						$config_flag = 1

						Write-Host "=====Success config full dump file in $finalpath====="
						
					}
					else
					{
						#disk $deviceid has no more space
						Write-Warning "=====Disk $deviceid has no enough space to config full dump file====="
						
					}
            }
			}

			if($config_flag -gt 0)
			{
				Write-Warning "=====You need restart the computer to make it work!!!====="  
                Write-host "Note: After reboot, when the issue reappears, you can hold the right-side Ctrl key, hit the Scroll Lock key twice to trigger the dump, or you can press the NMI button to trigger the dump too!!!" -ForegroundColor yellow
			}
			
			if($config_flag -eq 0)
			{
				Write-Warning "=====All disks have no enough free space, fail to config the full dump info, you need check manully=====" 
			}						
		}catch
		{
			Write-Warning "=====All disks have no enough free space, fail to config the full dump info, you need check manully====="
		}
	}
	else
	{
		try{
			#Get the physical memory info
			$phymem_info=(Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory/1024/1024
			$temp_phymem=[int32]($phymem_info/1024)
			$output_phymem="$temp_phymem"+"GB"
			#Get the stroage info
			get-WmiObject win32_logicaldisk | Where-Object {$_.FreeSpace -gt 12000000000} | Select DeviceID,FreeSpace |
				ForEach-Object {
                if($config_flag -eq 0)
			    {
				#Parse each disk free space
				$deviceid = $_.DeviceID
				$freespace = $_.FreeSpace/1024/1024
				if($phymem_info -lt 32000)
				{
					#phical mememory is less than 32G , prefer to config full dump
					Write-Host "=====Phical mememory is less than 32G , prefer to config full dump====="
					$needfreespace = $phymem_info*2+257+$reserved_space
					$pagefile_size = [int32]($phymem_info/1024)*1024+257
					if($freespace -gt $needfreespace)
					{
						Write-Host "=====Disk $deviceid has enough free space, ready to config full dump====="
						#reg modify
						$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
						$name="CrashDumpEnabled"
						$value=1
						$type="DWord"
						
						Set-RegistryValue $keys $name $value $type

						$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
						$name="DumpFile"
						$value="$deviceid\WINDOWS\MEMORY.DMP"
						$type="ExpandString"

						Set-RegistryValue $keys $name $value $type

						$finalpath=$value

						$keys="HKLM:SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
						$name="PagingFiles"
						$value="$deviceid\pagefile.sys $pagefile_size $pagefile_size"
						$type="MultiString"

						Set-RegistryValue $keys $name $value $type
						
						$output_pagefile="$pagefile_size"+"MB"
						$output_dumppath=$finalpath
						$output_dumptype="Full Dump"
						
						if($disable_autostart -eq 1)
						{
							$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
							$name="AutoReboot"
							$value=0
							$type="DWORD"

							Set-RegistryValue $keys $name $value $type
							$output_autorestart="False"
						}
						else
						{
							$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
							$name="AutoReboot"
							$value=1
							$type="DWORD"

							Set-RegistryValue $keys $name $value $type	
							$outpur_autorestart="True"							
						}
						
						$keys="HKLM:SYSTEM\CurrentControlSet\Services\kbdhid\Parameters\"
						$name="CrashOnCtrlScroll"
						$value=1
						$type="DWORD"

						Set-RegistryValue $keys $name $value $type

						$keys="HKLM:SYSTEM\CurrentControlSet\Services\i8042prt\Parameters\"
						$name="CrashOnCtrlScroll"
						$value=1
						$type="DWORD"

						Set-RegistryValue $keys $name $value $type
						
						$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
						$name="NMICrashDump"
						$value=1
						$type="DWORD"

						Set-RegistryValue $keys $name $value $type

						$config_flag = 1

						Write-Host "=====Phical memory is less than 32G , success config full dump file in $finalpath====="
						
					}
					else
					{
						#disk $deviceid has no more space
						Write-Warning "=====Disk $deviceid has no enough space to config full dump file====="
						
					}
				}
				else
				{
					#phical mememory is above 32G , prefer to config kernel dump
					Write-Host "=====Phical mememory is above 32G , prefer to config kernel dump====="
					$needfreespace = 40000+$reserved_space
					$pagefile_size = 20000
					if($freespace -gt $needfreespace)
					{
						#reg modify
						$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
						$name="CrashDumpEnabled"
						$value=2
						$type="DWord"
						
						Set-RegistryValue $keys $name $value $type

						$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
						$name="DumpFile"
						$value="$deviceid\WINDOWS\MEMORY.DMP"
						$type="ExpandString"
						
						Set-RegistryValue $keys $name $value $type
						
						$finalpath=$value
						
						$keys="HKLM:SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
						$name="PagingFiles"
						$value="$deviceid\pagefile.sys $pagefile_size $pagefile_size"
						$type="MultiString"

						Set-RegistryValue $keys $name $value $type
						
						$output_pagefile="$pagefile_size"+"MB"
						$output_dumppath=$finalpath
						$output_dumptype="Kernel Dump"
						
						if($disable_autostart -eq 1)
						{
							$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
							$name="AutoReboot"
							$value=0
							$type="DWORD"

							Set-RegistryValue $keys $name $value $type
							$output_autorestart="False"
						}
						else
						{
							$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
							$name="AutoReboot"
							$value=1
							$type="DWORD"

							Set-RegistryValue $keys $name $value $type
							$output_autorestart="True"							
						}
						
						$keys="HKLM:SYSTEM\CurrentControlSet\Services\kbdhid\Parameters\"
						$name="CrashOnCtrlScroll"
						$value=1
						$type="DWORD"

						Set-RegistryValue $keys $name $value $type

						$keys="HKLM:SYSTEM\CurrentControlSet\Services\i8042prt\Parameters\"
						$name="CrashOnCtrlScroll"
						$value=1
						$type="DWORD"

						Set-RegistryValue $keys $name $value $type
						
						$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
						$name="NMICrashDump"
						$value=1
						$type="DWORD"

						Set-RegistryValue $keys $name $value $type

						$config_flag = 2

						Write-Host "=====Phical memory is above 32G , success config kernel dump file with pagefile 20GB in $finalpath====="
						
					 }else
					 {
						#disk $deviceid has no more space
						Write-Warning "=====Disk $deviceid has no enough space to config kernel dump file====="
						
					 }

				}
            }
			}

			if($config_flag -eq 0)
			{
				Write-Warning "=====All disk has no more freespace, just try to config a kernel dump with smaller pagefile====="
				#try to config kernel dump again, hard code
				$needfreespace = 12000+$reserved_space
				$pagefile_size = 6000
				get-WmiObject win32_logicaldisk | Where-Object {$_.FreeSpace -gt 12000000000} | Select DeviceID,FreeSpace |
					ForEach-Object {
                    if($config_flag -eq 0)
			        {
					#Parse each disk free space
					$deviceid = $_.DeviceID
					$freespace = $_.FreeSpace/1024/1024
					if($freespace -gt $needfreespace)
					{
						#reg modify
						$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
						$name="CrashDumpEnabled"
						$value=2
						$type="DWord"
							
						Set-RegistryValue $keys $name $value $type

						$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
						$name="DumpFile"
						$value="$deviceid\WINDOWS\MEMORY.DMP"
						$type="ExpandString"

						Set-RegistryValue $keys $name $value $type

						$finalpath=$value

						$keys="HKLM:SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
						$name="PagingFiles"
						$value="$deviceid\pagefile.sys $pagefile_size $pagefile_size"
						$type="MultiString"

						Set-RegistryValue $keys $name $value $type
						
						$output_pagefile="$pagefile_size"+"MB"
						$output_dumppath=$finalpath
						$output_dumptype="Kernel Dump"
						
						if($disable_autostart -eq 1)
						{
							$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
							$name="AutoReboot"
							$value=0
							$type="DWORD"

							Set-RegistryValue $keys $name $value $type
							$output_autorestart="False"
						}
						else
						{
							$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
							$name="AutoReboot"
							$value=1
							$type="DWORD"

							Set-RegistryValue $keys $name $value $type
							$output_autorestart="True"							
						}
						
						$keys="HKLM:SYSTEM\CurrentControlSet\Services\kbdhid\Parameters\"
						$name="CrashOnCtrlScroll"
						$value=1
						$type="DWORD"

						Set-RegistryValue $keys $name $value $type

						$keys="HKLM:SYSTEM\CurrentControlSet\Services\i8042prt\Parameters\"
						$name="CrashOnCtrlScroll"
						$value=1
						$type="DWORD"

						Set-RegistryValue $keys $name $value $type
						
						$keys="HKLM:SYSTEM\CurrentControlSet\Control\CrashControl\"
						$name="NMICrashDump"
						$value=1
						$type="DWORD"

						Set-RegistryValue $keys $name $value $type
						
						$config_flag = 2
						
						Write-Host "=====Config kernel dump file with pagefile 6GB in $finalpath====="

						
					}else
					{
						return
					}
				}
            }
				if($config_flag -eq 0)
				{
					Write-Warning "=====All disks have no enough free space,fail to config the dump info,you need check manully====="
				}
			}

			if($config_flag -gt 0)
			{
				Write-Warning "=====You need restart the computer to make it work!!!====="
                Write-host "Note: After reboot, when the issue reappears, you can hold the right-side Ctrl key, hit the Scroll Lock key twice to trigger the dump, or you can press the NMI button to trigger the dump too!!!" -ForegroundColor yellow
			}
		}catch
		{
			Write-Warning "=====All disks have no enough free space,fail to config the dump info,you need check manully====="
		}
	}
	Write-Host "----------------------------------------------------------------------------------------"
}
Write-Host ""
Write-Host ""
$currenttime=Get-Date -Format 'yyyyMMddHHmm'
$fpath="C:\dumpconfig_"+$currenttime+".txt"
if($config_flag -gt 0)
{
	Write-Host "=====Config Result: Success=====" -ForegroundColor Green
	Write-Host "------------------------------------------"
	Write-Host "Physical Memory: $output_phymem"
	Write-Host "Pagefile Size: $output_pagefile"
	Write-Host "Dump Type: $output_dumptype"
	Write-Host "Dump Path: $output_dumppath"
	Write-Host "Auto Reboot: $output_autorestart"
	Write-Host "------------------------------------------"
	Write-Host ""
	Write-Host ""
	Write-Host "=====Output Result File Path: $fpath====="	
	"=====Config Result: Success=====" | Out-File -Filepath $fpath
	"------------------------------------------" | Out-File -Filepath $fpath -Append
	"Physical Memory: $output_phymem" | Out-File -Filepath $fpath -Append
	"Pagefile Size: $output_pagefile" | Out-File -Filepath $fpath -Append
	"Dump Type: $output_dumptype" | Out-File -Filepath $fpath -Append
	"Dump Path: $output_dumppath" | Out-File -Filepath $fpath -Append
	"Auto Reboot: $output_autorestart" | Out-File -Filepath $fpath -Append
	"------------------------------------------" | Out-File -Filepath $fpath -Append
}
else
{
	Write-host "=====Config Result: Fail=====" -ForegroundColor Red
	Write-Host ""
	Write-Host ""
	Write-Host "=====Output Result File Path: $fpath====="		
	"=====Config Result: Fail=====" | Out-File -Filepath $fpath
}
Write-Host ""
Write-Host ""	
Write-Host "The script window will exit after 1 minutes"
Start-Sleep -s 60
exit