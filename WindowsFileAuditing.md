# Windows File Auditing



## Folder and Files Only to Audit

> Do Note Audit Subfolders on these directories  

```
C:\Program Files
C:\Program Files\Internet Explorer
C:\Program Files\Common Files
C:\Program Files (x86)
C:\Program Files (x86) \Common Files
C:\ProgramData
C:\Windows
C:\Windows\System32
C:\Windows\System32\Drivers
C:\Windows\System32\Drivers\etc
C:\Windows\System32\Sysprep
C:\Windows\System32\wbem
C:\Windows\System32\WindowsPowerShell\v1.0
C:\Windows\Web
C:\Windows\SysWOW64
C:\Windows\SysWOW64\Drivers
C:\Windows\SysWOW64\wbem
C:\Windows\SysWOW64\WindowsPowerShell\v1.0
```



## Folders, Subfolders and Files To Audit

```
C:\Boot
C:\Perflogs
Any Anti-Virus folder(s) used for quarantine, etc.
C:\Users\All Users\Microsoft\Windows\Start Menu\Programs\Startup
C:\Users\Public
C:\Users\*\AppData\Local
C:\Users\*\AppData\Local\Temp
C:\Users\*\AppData\LocalLow
C:\Users\*\AppData\Roaming
C:\Windows\Scripts
C:\Windows\System
C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup ##Consider Scripts if no other dirs
C:\Windows\System32\GroupPolicy\Machine\Scripts\Shutdown
C:\Windows\System32\GroupPolicy\User\Scripts\Logon ##Consider Scripts if no other dirs
C:\Windows\System32\GroupPolicy\User\Scripts\Logoff
C:\Windows\System32\Repl 
```



## Exclude 

> These folders will create events that do not provide much value. After setting auditing on the parent folder, remove auditing from these folders and any other files and folders you find overly noisy with little security benefit. 

```
C:\ProgramData\Microsoft\RAC\Temp
C:\ProgramData\Microsoft\RAC\PublishedData\RacWmiDatabase.sdf
C:\ProgramData\Microsoft\RAC\StateData\RacDatabase.sdf
C:\ProgramData\<Anti-Virus>\Common Framework Insert your AV folder(s)
C:\ProgramData\Microsoft\Search\Data\Applications\Windows\MSS.chk
C:\ProgramData\Microsoft\Search\Data\Applications\Windows\MSS.log
C:\Users\*\AppData\Local\GDIPFONTCACHEV1.DAT
C:\Users\*\AppData\Local\Google\Chrome\User Data
C:\Users\*\AppData\Local\Microsoft\Windows\Explorer\thumbcache_*
C:\Users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5
C:\Users\*\AppData\Local\Microsoft\Office
C:\Users\*\AppData\Local\Microsoft\Outlook
C:\Users\*\AppData\Local\Microsoft\Windows\PowerShell\CommandAnalysis
C:\Users\*\AppData\Local\Mozilla\Firefox\Profiles
C:\Users\*\AppData\LocalLow\Microsoft\CryptnetUrlCache
C:\Users\*\AppData\Roaming\Microsoft\Excel
C:\Windows\SysWOW64\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache


```

> Any other normal applications that you have installed that produce a lot of log entries without significant security value.




