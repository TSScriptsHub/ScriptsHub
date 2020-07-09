cd "c:\Program Files\FSLogix\Apps\"
$folders = Get-ChildItem -Path "Z:" -Directory
foreach ($folder in $folders)
{
	$files = Get-ChildItem $folder.FullName
	foreach ($file in $files)
	{
		$new=$file.fullName
		$old=$new -replace ".vhd", "_old.vhd"
		Rename-Item -Path $new -NewName $old
		.\frx create-vhd -filename $new -size-mbs 30000
		$res = .\frx migrate-vhd -src $old -dest $new
		echo $res
		if ([String]$res -like "*Exit Code: 0*"){
			Remove-Item $old
		}
		else
		{
			Remove-Item $new
			Rename-Item -Path $old -NewName $new
		}
	}
}