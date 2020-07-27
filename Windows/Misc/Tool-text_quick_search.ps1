<#
DESCRIPTION:
This powershell script is used to quick search the specific type files with the keyword and list the detail content (current support type like txt,script file ps1,bat)

System/Requirement：
Require to run on server 2012 R2 or above

USAGE:
Autosearch C:\demo\ txt Out-NULL 
Autosearch_detail C:\demo\ ps1 Credential
Autosearch_detail C:\demo\ * Invoke
Autosearch_detail C:\demo\ txt function
#>
#
function Autosearch_detail($checkdir, $type, $keywords){
    $filetype = "*."+$type
    $fileList = Get-ChildItem $checkdir -recurse $filetype | %{$_.FullName}

    $parsekeyword= "*"+$keywords+"*"

    Foreach($file in $fileList)
    {
       $fileflag=0
       if((Get-Item -Path $file).PSIsContainer -eq $false -and $file.Contains("Autosearch") -eq $false)
        {
            $tmpContent = Get-Content $file
        }
　　    for ($i=0; $i -lt $tmpContent.length; $i++)
　　    {
　　　　    if($tmpContent[$i])
           {
            if($tmpContent[$i] -like $parsekeyword)　
　　　　        {
                if($fileflag -eq 0)
                {
                    $filepath= "---------------------"+$file+"---------------------"
                    write-host $filepath -ForegroundColor Green
                    $fileflag = 1
                }
                $lineinfo= "Line "+$i+":  "
                write-host $lineinfo -ForegroundColor yellow -NoNewline
　　　　　　      write-host $tmpContent[$i] -background red 
　　　　        }
            }
　　     }
    }
}