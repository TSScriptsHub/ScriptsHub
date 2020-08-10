# Script to recreate FSLogix VHDX

# Define the path of frx.exe
cd "c:\Program Files\FSLogix\Apps\"

# Define the path of the VHDX location
$folders = Get-ChildItem -Path "Z:" -Directory

# Define the maximum size
# Note: the size is not the size of VHDX but the maximun size user can use
$size = 30000

# Recreate VHDX from all subfolders of VHDX location
foreach ($folder in $folders)
{
	$files = Get-ChildItem $folder.FullName
	foreach ($file in $files)
	{
		$new=$file.fullName
		$old=$new -replace ".vhd", "_old.vhd"
		Rename-Item -Path $new -NewName $old

		# Create new VHDX
		.\frx create-vhd -filename $new -size-mbs $size

		# Migrate VHDX
		$res = .\frx migrate-vhd -src $old -dest $new

		echo $res

		# Remove the old VHDX if migrate success
		if ([String]$res -like "*Operation completed successfully!*"){
			Remove-Item $old
		}
		# Revert the change if migrate failed
		else
		{
			Remove-Item $new
			Rename-Item -Path $old -NewName $new
		}
	}
}

# Note: Robcopy might failed with 9 while copying the files under, please delete them before run the script: %localappdata%\Microsoft\WindowsApps\
# https://ss64.com/nt/robocopy-exit.html