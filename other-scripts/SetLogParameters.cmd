@echo off
CLS
::
::######################################################
::#                                                    #
::#             This script sets Log sizes             #
::#      and enables two logs that are disabled        #
::#       This fixes issues created by Win 10          #
::#                cumulative updates                  #
::#                                                    #
::######################################################
::
Time /t > Time_File.txt
::
::  Edit this script to set what you want, it is best to set via Group Policy,
::  but not all systems are controlled by GPO, so this script helps set some items.
::  The File Associations are included to help prevent malware and ransomware infections.
::  
::  Another optional PowerShell script is called to set Folder auditing on the C:\Users directories
::
echo.
echo  This script fixes or sets items cleared by the Windows 10 cumulative updates
echo.
::
::#######################################################################################
::
:: SET THE LOG SIZE - What local size they will be - 1GB Securirty log is roughly 7 days
:: --------------------------------------------------------------------------------------
::
wevtutil sl Security /ms:1048576000
::
wevtutil sl Application /ms:262144000
::
wevtutil sl Setup /ms:262144000
::
wevtutil sl System /ms:262144000
::
wevtutil sl "Windows Powershell" /ms:262144000
::
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:524288000
::
:: ---------------------------------------------------------------------
:: ENABLE The TaskScheduler and DNS Client log
:: ---------------------------------------------------------------------
::
wevtutil sl "Microsoft-Windows-TaskScheduler/Operational" /e:true
::
wevtutil sl "Microsoft-Windows-DNS-Client/Operational" /e:true
::
:: ---------------------------------------------------------------------
::
:: Change Default behavior of Word Documents automatically opening 
:: external links/URL's to block malicious content.  Latest DDE vulnerability
::
:: ---------------------------------------------------------------------
::
::  Added to v1.3
::
Reg add "HKCU\Software\Microsoft\Office\16.0\Word\Options" /v DontUpdateLinks /t REG_DWORD /d 1
Reg add "HKCU\Software\Microsoft\Office\15.0\Word\Options" /v DontUpdateLinks /t REG_DWORD /d 1
Reg add "HKCU\Software\Microsoft\Office\14.0\Word\Options" /v DontUpdateLinks /t REG_DWORD /d 1
::
Reg add "HKCU\Software\Microsoft\Office\16.0\Word\Options\WordMail" /v DontUpdateLinks /t REG_DWORD /d 1
Reg add "HKCU\Software\Microsoft\Office\15.0\Word\Options\WordMail" /v DontUpdateLinks /t REG_DWORD /d 1
Reg add "HKCU\Software\Microsoft\Office\14.0\Word\Options\WordMail" /v DontUpdateLinks /t REG_DWORD /d 1
::
Reg add "HKCU\Software\Microsoft\Office\16.0\OneNote\Options" /v DisableEmbeddedFiles /t REG_DWORD /d 1
Reg add "HKCU\Software\Microsoft\Office\15.0\OneNote\Options" /v DisableEmbeddedFiles /t REG_DWORD /d 1
Reg add "HKCU\Software\Microsoft\Office\14.0\OneNote\Options" /v DisableEmbeddedFiles /t REG_DWORD /d 1
::
Reg add "HKCU\Software\Microsoft\Office\16.0\Excel\Options" /v DontUpdateLinks /t REG_DWORD /d 1
Reg add "HKCU\Software\Microsoft\Office\15.0\Excel\Options" /v DontUpdateLinks /t REG_DWORD /d 1
Reg add "HKCU\Software\Microsoft\Office\14.0\Excel\Options" /v DontUpdateLinks /t REG_DWORD /d 1
::
Reg add "HKCU\Software\Microsoft\Office\16.0\Excel\Options" /v DDEAllowed /t REG_DWORD /d 0
Reg add "HKCU\Software\Microsoft\Office\15.0\Excel\Options" /v DDEAllowed /t REG_DWORD /d 0
Reg add "HKCU\Software\Microsoft\Office\14.0\Excel\Options" /v DDEAllowed /t REG_DWORD /d 0
::
Reg add "HKCU\Software\Microsoft\Office\16.0\Excel\Options" /v DDECleaned /t REG_DWORD /d 1
Reg add "HKCU\Software\Microsoft\Office\15.0\Excel\Options" /v DDECleaned /t REG_DWORD /d 1
Reg add "HKCU\Software\Microsoft\Office\14.0\Excel\Options" /v DDECleaned /t REG_DWORD /d 1
::
Reg add "HKCU\Software\Microsoft\Office\15.0\Excel\Options" /v Options /t REG_DWORD /d 117
Reg add "HKCU\Software\Microsoft\Office\14.0\Excel\Options" /v Options /t REG_DWORD /d 117
::
:: ---------------------------------------------------------------------
:: Change File Associations for dangerous file types to open Notepad.exe
::
:: Deletes the existing HKCU FileExt key if exists
:: Creates the HKCO FileExt key
:: Sets association to notepad
:: ---------------------------------------------------------------------
::
::  Change old .pif format
::
echo.
echo Changing .PIF
echo.
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pif" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pif\OpenWithList" /v a /d NOTEPAD.EXE /f
ftype piffile=c:\windows\system32\notepad.exe
::
::  Change old hypertext format
::
echo.
echo Changing .HTA
echo.
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.hta" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.hta\OpenWithList" /v a /d NOTEPAD.EXE /f
ftype htafile=c:\windows\system32\notepad.exe
::
::  Change javacript extentions
::
echo.
echo Changing .JSE
echo.
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jse" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jse\OpenWithList" /v a /d NOTEPAD.EXE /f
ftype jsefile=c:\windows\system32\notepad.exe
::
echo.
echo Changing .JS
echo.
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.js" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.js\OpenWithList" /v a /d NOTEPAD.EXE /f
ftype jsfile=c:\windows\system32\notepad.exe
::
::  Change Windows host scripting extentions
::
echo.
echo Changing .WSF
echo.
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wsf" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wsf\OpenWithList" /v a /d NOTEPAD.EXE /f
ftype wsffile=c:\windows\system32\notepad.exe
::
echo.
echo Changing .WSH
echo.
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wsh" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wsh\OpenWithList" /v a /d NOTEPAD.EXE /f
ftype wshfile=c:\windows\system32\notepad.exe
::
::  Change VB Script extentions
::
echo.
echo Changing .VBE
echo.
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.vbe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.vbe\OpenWithList" /v a /d c:\windows\system32\NOTEPAD.EXE /f
reg add "HKCU\vbefile\shell\edit\command" /ve /t REG_EXPAND_SZ /d %SystemRoot%\system32\NOTEPAD.EXE /f
reg add "HKCU\vbefile\shell\open\command" /ve /t REG_EXPAND_SZ /d %SystemRoot%\system32\NOTEPAD.EXE /f
reg add "HKCU\vbefile\shell\open2\command" /ve /t REG_EXPAND_SZ /d %SystemRoot%\system32\NOTEPAD.EXE /f
ftype vbefile=c:\windows\system32\notepad.exe
::
echo.
echo Changing .VBS
echo.
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.vbs" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.vbs\OpenWithList" /v a /d c:\windows\system32\NOTEPAD.EXE /f
reg add "HKCU\vbsfile\shell\edit\command" /ve /t REG_EXPAND_SZ /d %SystemRoot%\system32\NOTEPAD.EXE /f
reg add "HKCU\vbsfile\shell\open\command" /ve /t REG_EXPAND_SZ /d %SystemRoot%\system32\NOTEPAD.EXE /f
reg add "HKCU\vbsfile\shell\open2\command" /ve /t REG_EXPAND_SZ /d %SystemRoot%\system32\NOTEPAD.EXE /f
ftype vbsfile=c:\windows\system32\notepad.exe
::
:: -----------------------------------------------------------------------------------------------------------------
::
echo.
echo.
echo Done...
echo.
::
::#######################################################################
::
:: The End
::
Time /t >> Time_File.txt