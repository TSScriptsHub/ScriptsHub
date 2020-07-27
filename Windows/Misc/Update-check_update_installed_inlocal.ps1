<#
DESCRIPTION:
This powershell script is used to check update installed or not for local side and report to txt file 

System/Requirement：
Require to run on server 2012 R2 or above

USAGE:
1.You should specify the full check list, in script we build a txt file like:
KB11111
KB22222
KB33333

#>

$check_kblist_path="C:\test\check_kblist1.txt"  #KB CHECK LIST PATH
$report_file="C:\test\report.txt"
#check KB list
$kblist=@(Get-Content $check_kblist_path)


for($i=0;$i -lt $kblist.Length;$i++)
{
    try
	{
		$checkhotfix=""
        $checkhotfix=Get-HotFix |
		Where-Object { 
			$_.HotfixID -like $kblist[$i] 
		}
        #$kblist[$i]
        if($checkhotfix)
        {
            $temp_output=$kblist[$i]+" has been installed"
            #write-host $temp_output
        }
        else
        {
            $temp_output=$kblist[$i]+" has not been installed"
            #write-host $temp_output -ForegroundColor Red
            if($kbcheck_flag -eq 0)
            {
                $kbfaillist=$kblist[$i]
            }
            else
            {
                $kbfaillist=$kbfaillist+" "+$kblist[$i]
            }
            $kbcheck_flag=1
        }
	}
	catch
	{
        write-warning "check hotfix fail"
    }
}
write-host "====KB CHECK===="
"====KB CHECK====" | Out-File -Filepath $report_file -Append
if($kbcheck_flag -eq 0)
{
   write-host "RESULT: PASS" -ForegroundColor Green
   "RESULT: PASS" | Out-File -Filepath $report_file -Append
}
else
{
   write-host "RESULT: FAIL" -ForegroundColor Red
   write-host "FAIL LIST:" -ForegroundColor Red 
   write-host $kbfaillist -ForegroundColor Red
   "RESULT: FAIL" | Out-File -Filepath $report_file -Append
   "FAIL LIST:" | Out-File -Filepath $report_file -Append
   $kbfaillist | Out-File -Filepath $report_file -Append
}

write-host ""
"" | Out-File -Filepath $report_file -Append