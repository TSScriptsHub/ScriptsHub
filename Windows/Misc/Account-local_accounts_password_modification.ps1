<#
DESCRIPTION:
This powershell script is used to change the specific account password 

System/Requirement：
Require to run on server 2012 R2 or above

USAGE:
You should build account and password mapping array list as follows:
accountlist="tomcat", "admin",  "Administrator",  "itsm"
pwdlist=    "test1",  "test2",       "test3",     "test4"
#>

$accountlist=@("tomcat","admin","Administrator","itsm")
$pwdlist=@("test1","test2","test3","test4")

$userlist=@(Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True" |select Name)

for($i=0; $i -lt $userlist.Count;$i++)
{
    if($userlist[$i].Name -ceq $accountlist[0])
    {     
        net user $accountlist[0] $pwdlist[0]
    }
    elseif($userlist[$i].Name -ceq $accountlist[1])
    {      
        net user $accountlist[1] $pwdlist[1]
    }
    elseif($userlist[$i].Name -ceq $accountlist[2])
    {   
        net user $accountlist[2] $pwdlist[2]
    }
    elseif($userlist[$i].Name -ceq $accountlist[3])
    {  
        net user $accountlist[3] $pwdlist[3]
    }
}
