call :copyfolder Microsoft.VCLibs.140.00_14.0.27323.0
call :copyfolder Microsoft.NET.Native.Runtime.2.2_2.2.27328.0

exit /b

:copyfolder

REM take ownership for Administrators
takeown /F "C:\Program Files\WindowsApps" /A /R /D Y
takeown /F "C:\Program Files\WindowsApps\%~1_x86__8wekyb3d8bbwe" /A /R /D Y 
takeown /F "C:\Program Files\WindowsApps\%~1_x64__8wekyb3d8bbwe" /A /R /D Y 

REM grand Full Control permission
icacls "C:\Program Files\WindowsApps" /grant "SYSTEM":(OI)(CI)F
icacls "C:\Program Files\WindowsApps\%~1_x86__8wekyb3d8bbwe" /grant "SYSTEM":(OI)(CI)F
icacls "C:\Program Files\WindowsApps\%~1_x64__8wekyb3d8bbwe" /grant "SYSTEM":(OI)(CI)F
icacls "C:\Program Files\WindowsApps" /grant "Administrators":(OI)(CI)F
icacls "C:\Program Files\WindowsApps\%~1_x86__8wekyb3d8bbwe" /grant "Administrators":(OI)(CI)F
icacls "C:\Program Files\WindowsApps\%~1_x64__8wekyb3d8bbwe" /grant "Administrators":(OI)(CI)F
icacls "C:\Program Files\WindowsApps" /grant "Authenticated Users":(OI)(CI)F
icacls "C:\Program Files\WindowsApps\%~1_x86__8wekyb3d8bbwe" /grant "Authenticated Users":(OI)(CI)F
icacls "C:\Program Files\WindowsApps\%~1_x64__8wekyb3d8bbwe" /grant "Authenticated Users":(OI)(CI)F
icacls "c:\Program Files\WindowsApps" /grant MSSupport:(OI)(CI)F
icacls "c:\Program Files\WindowsApps\%~1_x64__8wekyb3d8bbwe" /grant MSSupport:(OI)(CI)F
icacls "c:\Program Files\WindowsApps\%~1_x86__8wekyb3d8bbwe" /grant MSSupport:(OI)(CI)F

REM rename corrupted folder
ren "C:\Program Files\WindowsApps\%~1_x86__8wekyb3d8bbwe" "C:\Program Files\WindowsApps\%~1_x86__8wekyb3d8bbwe_broken"
ren "C:\Program Files\WindowsApps\%~1_x64__8wekyb3d8bbwe" "C:\Program Files\WindowsApps\%~1_x64__8wekyb3d8bbwe_broken"

REM copy the folder
xcopy "%userprofile%\Desktop\WindowsApps" "C:\Program Files\WindowsApps" /S /H /C /Y

REM grand Full Control permission for ALL APPLICATION PACKAGES 
icacls "C:\Program Files\WindowsApps" /reset /t /c /q
icacls "C:\Program Files\WindowsApps" /grant "ALL APPLICATION PACKAGES":(OI)(CI)F
icacls "C:\Program Files\WindowsApps\%~1_x86__8wekyb3d8bbwe" /grant "ALL APPLICATION PACKAGES":(OI)(CI)F
icacls "C:\Program Files\WindowsApps\%~1_x64__8wekyb3d8bbwe" /grant "ALL APPLICATION PACKAGES":(OI)(CI)F

goto :eof
