<#

DESCRIPTION:
This script cleans the Printing Preference settings for all of the GPP printers. It gets the GPP printer information through the GPResult.exe. 

USAGE: 
Working on Windows 10. 
Tested on Windows 10 RS5

#>

#Get the GPP printer list from the GPResult /H %temp%\GPResult.htm file. 
$fileName = $env:TEMP +"\GPResult.htm"
GPResult /H $fileName /F

#Get the shared printer name which has the format: Shared Printer (Name: \\Server\PrinterName)
$strToFind = 'Shared Printer \(Name: '
$matchedContent = Get-Content -Path $fileName | Select-String -Pattern $strToFind
foreach ($line in $matchedContent)
{
    $substrToFind = 'Shared Printer \(Name: (.*)\)'
    $found = $line -match $substrToFind
    if ($found)
    {
        #The matched GPP printer share name is \\server\PrinterName, remove the registry keys to remove the Printing Preference
        #   HKEY_CURRENT_USER\Printers\DevModes2; \\server\PrinterName
        #   HKEY_CURRENT_USER\Printers\Connections\,,server,PrinterName; DevMode
                
        $regkeypath1= "HKCU:\Printers\DevModes2"
        $value1 = (Get-Item -Path $regkeypath1).GetValue($matches[1]) -ne $null

        If ($value1 -ne $false) 
        {
            #Remove \\server\PrinterName under HKEY_CURRENT_USER\Printers\DevModes2
            write-host "Delete key " $regkeypath1 ":" $matches[1].ToString()
            Remove-ItemProperty -path $regkeypath1 -name $matches[1]
        } 
        
        $regkeypath2= "HKCU:\Printers\Connections\" + $matches[1].Replace('\',',')
        $value1 = Test-Path -Path $regkeypath2
        If ($value1 -eq $true)
        {
            $value2 = (Get-Item -Path $regkeypath2).GetValue("DevMode") -ne $null
            If ($value2 -ne $false) 
            {
                #Remove DevMode under HKEY_CURRENT_USER\Printers\Connections\,,server,PrinterName
                write-host "Delete key " $regkeypath2 ": DevMode" 
                Remove-ItemProperty -path $regkeypath2 -name "DevMode"
            } 
        }                
   }   
}

