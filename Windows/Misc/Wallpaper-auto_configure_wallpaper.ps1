<#
DESCRIPTION:
This powershell script is used to configure the wallpaper, no matter the source wallpaper file is in local side or network file share

System/Requirement：
Require to run on server 2012 R2 or above

USAGE:
You should specify the wallpaper source path before you try to run the script 
#>

$picdir="C:\test"
$picpath="C:\test\test.JPG"
#you should specify the wallpaper source path 
$srcpath="\\x.x.x.x\test.JPG"

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

if(-not (Test-Path $picdir))
{
    mkdir $picdir
}

#copy the wallpaper picture form the file share path
if(-not (Test-Path $picptah)) 
{
    Copy-Item $srcpath -Destination $picpath
}

#configure the wallpaper for current user
$keys="HKCU:Software\Microsoft\Windows\CurrentVersion\Policies\System"
$name="Wallpaper"
$value=$picpath
$type="String"
     
if(Test-Path $keys)
{
    $tmpval=Get-RegistryValues $keys
    if($tmpval.contains($name))
    {
        $tmpval=Get-RegistryValue $keys $name

        if(-not ($tmpval -eq $picpath))
        {
            
            Set-RegistryValue $keys $name $value $type
        }                        
    }
    else
    {
        Set-RegistryValue $keys $name $value $type
    }    
}
else
{
    Set-RegistryValue $keys $name $value $type
}