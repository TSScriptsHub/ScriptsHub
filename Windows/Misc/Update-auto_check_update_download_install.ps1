<#
DESCRIPTION:
This powershell script is used to check for update and automatic download and install, has four sections
1.Search update
2.Download update
3.Update installation
4.If Reboot is required, force reboot the server

System/Requirement：
Require to run on server 2012 R2 or above

USAGE:
N/A
#>#

# Search update section
$Session = New-Object -ComObject "Microsoft.update.session"  #Create update session
$Search= $session.CreateUpdateSearcher()  #create update searcher. 
$SearchResult=$Search.Search("IsInstalled=0 and IsHidden=0") #Performs a synchronous search for updates. The search uses the search options that are currently configured.
Write-Host "Find following updtes."
$SearchResult.Updates #Print the searched updates. 
$AvailableUpdates =$SearchResult.Updates 

#Download update seciton. 
$DownloadCollection = New-Object -com "Microsoft.Update.UpdateColl" 
$AvailableUpdates | ForEach-Object { if ($_.InstallationBehavior.CanRequestUserInput -ne $TRUE) { $DownloadCollection.Add($_) | Out-Null  } } #Add searched updates to download collection. 
$Downloader = $Session.CreateUpdateDownloader() 
$Downloader.Updates = $DownloadCollection 
Write-host "Downloading" $Downloader.Updates.Count  "updates."
if($Downloader.Updates.Count -ne 0){$Downloader.Download()} # If count not equal 0,execute the download job. 

#Update installation section. 
$InstallCollection = New-Object -com "Microsoft.Update.UpdateColl" 
$AvailableUpdates | ForEach-Object {if ($_.IsDownloaded) { $InstallCollection.add($_) | Out-Null}}
$Installer = $Session.CreateUpdateInstaller()
$Installer.Updates = $InstallCollection
Write-Host "Installing"  $Installer.Updates.count "updates."
If($Installer.Updates.count -ne 0){$Result= $Installer.Install()}

#If Reboot is required, force reboot the server. 
if($Result.RebootRequired){Restart-Computer -Force}

