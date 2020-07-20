:: This script is for rebuild the WMI repository
@echo off 

:: Navigate to WMI folder
cd /d %windir%\system32\wbem 

:: Disalbe WMI Service
sc config winmgmt start= disabled 

:: Stop WMI Service
net stop winmgmt /y 

:: Register all the DLL files
for /f %%s in ('dir /b *.dll') do regsvr32 /s %%s 

:: Register the WMI provider
wmiprvse /regserver 

:: Reset WMI repoistory
winmgmt /resetrepository 

:: Enable WMI Service
sc config winmgmt start= auto 

:: Start WMI Service
net start winmgmt 

:: Compile all the MOF files
for /f %%s in ('dir /s /b *.mof *.mfl') do mofcomp %%s

:: Backup MOF file list and Compile MOF file from the list
::dir /b *.mof *.mfl | findstr /v /i uninstall > moflist.txt & for /F %%s in (moflist.txt) do mofcomp %%s
::powershell -command "(Get-ItemProperty -path HKLM:SOFTWARE\Microsoft\Wbem\CIMOM -name 'Autorecover MOFs').'Autorecover MOFs'" > moflist.txt
::for /F %%s in (moflist.txt) do mofcomp %%s
