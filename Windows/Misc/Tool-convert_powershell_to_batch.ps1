<#
DESCRIPTION:
This powershell script is used to convert simple powershell script to bat file, you should verfier the function works or not when do convert 

System/Requirement：
Require to run on server 2012 R2 or above

USAGE:
N/A
#>

function Convert-PowerShellToBatch
{
    param
    (
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]
        [Alias("FullName")]
        $Path
    )
 
    process
    {
        $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes((Get-Content -Path $Path -Raw -Encoding UTF8)))
        $newPath = [Io.Path]::ChangeExtension($Path, ".bat")
        "@echo off`npowershell.exe -NoExit -encodedCommand $encoded" | Set-Content -Path $newPath -Encoding Ascii
    }
}
 
Get-ChildItem -Path C:\powershell\scripts -Filter *.ps1 | Convert-PowerShellToBatch