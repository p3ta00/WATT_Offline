
| Section                                       | Question Number | Answer                                         |
| --------------------------------------------- | --------------- | ---------------------------------------------- |
| Introduction to Windows                       | Question 1      | 19041                                          |
| Introduction to Windows                       | Question 2      | Windows 10                                     |
| Operating System Structure                    | Question 1      | c8fe8d977d3a0c655ed7cf81e4d13c75               |
| File System                                   | Question 1      | bob.smith                                      |
| NTFS vs. Share Permissions                    | Question 1      | SMB                                            |
| NTFS vs. Share Permissions                    | Question 2      | Event viewer                                   |
| NTFS vs. Share Permissions                    | Question 3      | C:\\Users\\htb-student\\Desktop\\Company Data  |
| Windows Services & Processes                  | Question 1      | FoxitReaderUpdateService.exe                   |
| Interacting with the Windows Operating System | Question 1      | ifconfig                                       |
| Interacting with the Windows Operating System | Question 2      | Unrestricted                                   |
| Windows Management Instrumentation (WMI)      | Question 1      | 00329-10280-00000-AA938                        |
| Windows Security                              | Question 1      | S-1-5-21-2614195641-1726409526-3792725429-1003 |
| Windows Security                              | Question 2      | NordVPN                                        |
| Skills Assessment - Windows Fundamentals      | Question 1      | Everyone                                       |
| Skills Assessment - Windows Fundamentals      | Question 2      | Security                                       |
| Skills Assessment - Windows Fundamentals      | Question 3      | wuauserv                                       |
| Skills Assessment - Windows Fundamentals      | Question 4      | S-1-5-21-2614195641-1726409526-3792725429-1006 |
| Skills Assessment - Windows Fundamentals      | Question 5      | S-1-5-21-2614195641-1726409526-3792725429-1007 |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Introduction to Windows

## Question 1

### "What is the Build Number of the target workstation?"

After spawning the Windows target machine, students need to use `xfreerdp` to connect to it using the credentials `htb-student:Academy_WinFun!` (and accept the certificate by providing `Y` when promoted to):

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:Academy_WinFun!
```

```
┌─[us-academy-1]─[10.10.14.215]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ xfreerdp /v:10.129.184.98 /u:htb-student /p:Academy_WinFun!

[15:57:49:806] [4099:4100] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[15:57:49:806] [4099:4100] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[15:57:49:806] [4099:4100] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
[15:57:49:806] [4099:4100] [INFO][com.freerdp.client.common.cmdline] - loading channelEx cliprdr
[15:57:49:121] [4099:4100] [INFO][com.freerdp.primitives] - primitives autodetect, using optimized
<SNIP>
[15:57:49:577] [4099:4100] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.184.98:3389 (RDP-Server):
	Common Name: WS01
	Subject:     CN = WS01
	Issuer:      CN = WS01
	Thumbprint:  c7:53:c8:76:45:0c:ba:59:a8:7c:a3:f9:a5:a5:4a:55:da:1b:06:76:b8:36:e3:97:04:59:19:63:7c:a1:07:b3
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y 
<SNIP>
```

![[HTB Solutions/Others/z. images/d012fcc6b7560897d962b8617a5b94da_MD5.jpg]]

After successfully connecting to the spawned target machine, students need to open `PowerShell` and use the `Get-WmiObject` `Cmdlet` with the `Win32_OperatingSystem` class and only show `BuildNumber`:

Code: powershell

```powershell
Get-WmiObject -Class Win32_OperatingSystem | select BuildNumber
```

```
PS C:\Users\htb-student> Get-WmiObject -Class Win32_OperatingSystem | select BuildNumber

BuildNumber
-----------
19041
```

The `Build Number` of the spawned target machine is `19041`.

Answer: `19041`

# Introduction to Windows

## Question 2

### "Which Windows NT version is installed on the workstation? (i.e. Windows X - case sensitive)"

Using the same RDP connection established from the previous question, students need to open `PowerShell` and use the `Get-WmiObject` `Cmdlet` with the `Win32_OperatingSystem` class and only show `Version`, to find out that the version is `Windows 10`:

Code: powershell

```powershell
Get-WmiObject -Class win32_OperatingSystem | select Version
```

```
PS C:\Users\htb-student> Get-WmiObject -Class win32_OperatingSystem | select Version

Version    
-------
10.0.19041 
```

Answer: `Windows 10`

# Operating System Structure

## Question 1

### "Find the non-standard directory in the C drive. Submit the contents of the flag file saved in this directory."

After spawning the Windows target machine, students need to use `xfreerdp` to connect to it using the credentials `htb-student:Academy_WinFun!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:Academy_WinFun!
```

```
┌─[us-academy-1]─[10.10.14.215]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ xfreerdp /v:10.129.184.98 /u:htb-student /p:Academy_WinFun!

[15:57:49:806] [4099:4100] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[15:57:49:806] [4099:4100] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[15:57:49:806] [4099:4100] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
[15:57:49:806] [4099:4100] [INFO][com.freerdp.client.common.cmdline] - loading channelEx cliprdr
[15:57:49:121] [4099:4100] [INFO][com.freerdp.primitives] - primitives autodetect, using optimized
<SNIP>
```

After successfully connecting to the spawned target machine, students need to open the `Command Prompt`:

![[HTB Solutions/Others/z. images/71446f1c61becb446683d9e4f7e9aeb1_MD5.jpg]]

Students then need to change directories to the root of the "C" directory:

Code: cmd

```cmd
cd C:\
```

```
C:\Users\htb-student>cd C:\

c:\>
```

When issuing the `dir` command, students will notice that the `Academy` directory is foreign to Windows:

```
c:\>dir

 Volume in drive C has no label.
 Volume Serial Number is 905B-28C3

 Directory of c:\

09/07/2020  01:41 PM    <DIR>          Academy
12/07/2019  02:14 AM    <DIR>          PerfLogs
01/31/2022  05:05 PM    <DIR>          Program Files
01/31/2022  04:01 PM    <DIR>          Program Files (x86)
01/31/2022  04:02 PM    <DIR>          Users
01/31/2022  05:07 PM    <DIR>          Windows
               0 File(s)              0 bytes
               7 Dir(s)   5,185,355,776 bytes free
```

Navigating to it and then issuing the `dir` command inside it, students will find a file named "flag.txt", thus they will need to use the `type` command on it to print its content:

Code: cmd

```cmd
cd Academy
dir
type flag.txt
```

```
c:\>cd Academy

c:\Academy>dir

 Volume in drive C has no label.
 Volume Serial Number is 905B-28C3

 Directory of c:\Academy

09/07/2020  01:41 PM    <DIR>          .
09/07/2020  01:41 PM    <DIR>          ..
09/07/2020  12:17 PM                32 flag.txt
               1 File(s)             32 bytes
               2 Dir(s)   5,180,059,648 bytes free

c:\Academy>type flag.txt

c8fe8d977d3a0c655ed7cf81e4d13c75
```

Answer: `c8fe8d977d3a0c655ed7cf81e4d13c75`

# File System

## Question 1

### "What system user has full control over the c:\\users directory?"

After spawning the Windows target machine, students need to use `xfreerdp` to connect to it using the credentials `htb-student:Academy_WinFun!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:Academy_WinFun!
```

```
┌─[us-academy-1]─[10.10.14.215]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ xfreerdp /v:10.129.184.98 /u:htb-student /p:Academy_WinFun!

[15:57:49:806] [4099:4100] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[15:57:49:806] [4099:4100] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[15:57:49:806] [4099:4100] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
[15:57:49:806] [4099:4100] [INFO][com.freerdp.client.common.cmdline] - loading channelEx cliprdr
[15:57:49:121] [4099:4100] [INFO][com.freerdp.primitives] - primitives autodetect, using optimized
<SNIP>
```

After successfully connecting to the spawned target machine, students need to open the `Command Prompt` and use the `icacls` utility on the "c:\\users" directory:

Code: cmd

```cmd
icacls c:\\users
```

```
c:\>icacls C:\users

c:\users Everyone:(OI)(CI)(RX)
         NT AUTHORITY\SYSTEM:(OI)(CI)(F)
         BUILTIN\Administrators:(OI)(CI)(F)
         WS01\bob.smith:(OI)(CI)(F)
         BUILTIN\Users:(OI)(CI)(RX)

Successfully processed 1 files; Failed processing 0 files
```

Students will notice that the system user `bob.smith` has full control over the directory.

Answer: `bob.smith`

# NTFS vs. Share Permissions

## Question 1

### "What protocol discussed in this section is used to share resources on the network using Windows? (Format: case sensitive)"

The `SMB` protocol is used to share resources on the network using Windows:

![[HTB Solutions/Others/z. images/34ab19c376f944278f2d12a218969579_MD5.jpg]]

Answer: `SMB`

# NTFS vs. Share Permissions

## Question 2

### "What is the name of the utility that can be used to view logs made by a Windows system? (Format: 2 words, 1 space, not case sensitive)"

The `Event Viewer` is the name of the utility that can be used to view logs made by a Windows operating system:

![[HTB Solutions/Others/z. images/377e537a3ad9f9dffe9c5dccf9a8d9b5_MD5.jpg]]

Answer: `Event Viewer`

# NTFS vs. Share Permissions

## Question 3

### "What is the full directory path to the Company Data share we created?"

Students can find the full directory path from the section's reading:

![[HTB Solutions/Others/z. images/ecc53a061a9c75a26e87d5d1e9e4e486_MD5.jpg]]

Answer: `C:\Users\htb-student\Desktop\Company Data`

# Windows Services & Processes

## Question 1

### "Identify one of the non-standard update services running on the host. Submit the full name of the service executable (not the DisplayName) as your answer."

After spawning the Windows target machine, students need to use `xfreerdp` to connect to it using the credentials `htb-student:Academy_WinFun!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:Academy_WinFun!
```

```
┌─[us-academy-1]─[10.10.14.215]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ xfreerdp /v:10.129.184.98 /u:htb-student /p:Academy_WinFun!

[15:57:49:806] [4099:4100] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[15:57:49:806] [4099:4100] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[15:57:49:806] [4099:4100] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
[15:57:49:806] [4099:4100] [INFO][com.freerdp.client.common.cmdline] - loading channelEx cliprdr
[15:57:49:121] [4099:4100] [INFO][com.freerdp.primitives] - primitives autodetect, using optimized
<SNIP>
```

After successfully connecting to the spawned target machine, students need to use the `Get-Service` `Cmdlet` to query for the running services:

Code: powershell

```powershell
Get-Service | ? {$_.Status -eq "Running"} | FL
```

```
PS C:\Users\htb-student> Get-Service | ? {$_.Status -eq "Running"} | FL

<SNIP>
Name                : AppXSvc
DisplayName         : AppX Deployment Service (AppXSVC)
Status              : Running
DependentServices   : {}
ServicesDependedOn  : {rpcss, staterepository}
CanPauseAndContinue : False
CanShutdown         : True
CanStop             : True
ServiceType         : Win32OwnProcess, Win32ShareProcess

Name                : FoxitReaderUpdateService
DisplayName         : Foxit Reader Update Service
Status              : Running
DependentServices   : {}
ServicesDependedOn  : {}
CanPauseAndContinue : False
CanShutdown         : True
CanStop             : True
ServiceType         : Win32OwnProcess, InteractiveProcess
<SNIP>
```

Students will notice that there is a Service with the name of `FoxitReaderUpdateService`. Students alternatively can use the Task Manager and view the services under the Services tab to find the non-standard update service:

![[HTB Solutions/Others/z. images/5b9c289822e6c52ce98c7a5949da6162_MD5.jpg]]

![[HTB Solutions/Others/z. images/87ca82eda83a13b21d45eedd4439cda0_MD5.jpg]]

![[HTB Solutions/Others/z. images/0db1cd96fc436338d930c6aa5733aab7_MD5.jpg]]

However, with the hint provided for the question, students could guess that the service has something to do with a "Reader" and find the answer quickly:

Code: powershell

```powershell
PS C:\> Get-Service '*Reader*' | Where-Object {$_.Status -eq "Running"} | FL
```

```
PS C:\> Get-Service '*Reader*' | Where-Object {$_.Status -eq "Running"} | FL

Name                : FoxitReaderUpdateService
DisplayName         : Foxit Reader Update Service
Status              : Running
DependentServices   : {}
ServicesDependedOn  : {}
CanPauseAndContinue : False
CanShutdown         : True
CanStop             : True
ServiceType         : Win32OwnProcess, InteractiveProcess
```

Answer: `FoxitReaderUpdateService.exe`

# Interacting with the Windows Operating System

## Question 1

### "What is the alias set for the ipconfig.exe command?"

After spawning the Windows target machine, students need to use `xfreerdp` to connect to it using the credentials `htb-student:Academy_WinFun!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:Academy_WinFun!
```

```
┌─[us-academy-1]─[10.10.14.215]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ xfreerdp /v:10.129.184.98 /u:htb-student /p:Academy_WinFun!

[15:57:49:806] [4099:4100] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[15:57:49:806] [4099:4100] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[15:57:49:806] [4099:4100] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
[15:57:49:806] [4099:4100] [INFO][com.freerdp.client.common.cmdline] - loading channelEx cliprdr
[15:57:49:121] [4099:4100] [INFO][com.freerdp.primitives] - primitives autodetect, using optimized
<SNIP>
```

After successfully connecting to the spawned target machine, students need to use the `Get-Alias` `Cmdlet` with the `-Definition` parameter and specify `ipconfig`, to find the alias `ifconfig`:

Code: powershell

```powershell
Get-Alias -Definition 'ipconfig'
```

```
PS C:\Users\htb-student> Get-Alias -Definition 'ipconfig'

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Alias           ifconfig -> ipconfig.exe
```

Answer: `ifconfig`

# Interacting with the Windows Operating System

## Question 2

### "Find the Execution Policy set for the LocalMachine scope."

Using the same RDP connection established in the previous question, students need to use the `Get-ExecutionPolicy` `Cmdlet` with the `-List` parameter:

Code: powershell

```powershell
Get-ExecutionPolicy -List
```

```
PS C:\Users\htb-student> Get-ExecutionPolicy -List

Scope 			ExecutionPolicy
----- 			---------------
MachinePolicy    Undefined
UserPolicy       Undefined
Process          Bypass
CurrentUser      Undefined
LocalMachine     Unrestricted
```

Alternatively, students can use the `-Scope` parameter on the `Get-ExecutionPolicy` `Cmdlet` and specify `LocalMachine`, to find `Unrestricted` set for the Execution Policy for the `LocalMachine` scope:

Code: powershell

```powershell
Get-ExecutionPolicy -Scope LocalMachine
```

```
PS C:\Users\htb-student> Get-ExecutionPolicy -Scope LocalMachine

Unrestricted
```

Answer: `Unrestricted`

# Windows Management Instrumentation (WMI)

## Question 1

### "Use WMI to find the serial number of the system."

After spawning the Windows target machine, students need to use `xfreerdp` to connect to it using the credentials `htb-student:Academy_WinFun!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:Academy_WinFun!
```

```
┌─[us-academy-1]─[10.10.14.215]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ xfreerdp /v:10.129.184.98 /u:htb-student /p:Academy_WinFun!

[15:57:49:806] [4099:4100] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[15:57:49:806] [4099:4100] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[15:57:49:806] [4099:4100] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
[15:57:49:806] [4099:4100] [INFO][com.freerdp.client.common.cmdline] - loading channelEx cliprdr
[15:57:49:121] [4099:4100] [INFO][com.freerdp.primitives] - primitives autodetect, using optimized
<SNIP>
```

After successfully connecting to the spawned target machine, students need to use the `Get-WmiObject` `Cmdlet` with the `-Class` parameter to specify the `Win32_OperatingSystem` WMI class name, and then only show `SerialNumber`:

Code: powershell

```powershell
Get-WmiObject -Class Win32_OperatingSystem | Select SerialNumber
```

```
PS C:\Users\htb-student> Get-WmiObject -Class Win32_OperatingSystem | Select SerialNumber

SerialNumber
------------
00329-10280-00000-AA938
```

Answer: `00329-10280-00000-AA938`

# Windows Security

## Question 1

### "Find the SID of the bob.smith user."

After spawning the Windows target machine, students need to use `xfreerdp` to connect to it using the credentials `htb-student:Academy_WinFun!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:Academy_WinFun!
```

```
┌─[us-academy-1]─[10.10.14.215]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ xfreerdp /v:10.129.184.98 /u:htb-student /p:Academy_WinFun!

[15:57:49:806] [4099:4100] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[15:57:49:806] [4099:4100] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[15:57:49:806] [4099:4100] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
[15:57:49:806] [4099:4100] [INFO][com.freerdp.client.common.cmdline] - loading channelEx cliprdr
[15:57:49:121] [4099:4100] [INFO][com.freerdp.primitives] - primitives autodetect, using optimized
<SNIP>
```

After successfully connecting to the spawned target machine, students need to use the `Get-Wmiobject` `Cmdlet` with the `Win32_Account` class and apply the filter for the `Name` of `bob.smith` (students can also use `Select SID` to show only the `SID`):

Code: powershell

```powershell
Get-WmiObject -Class Win32_Account -Filter "Name='bob.smith'"
```

```
PS C:\Users\htb-student> Get-WmiObject -Class Win32_Account -Filter "Name='bob.smith'"

AccountType : 512
Caption     : WS01\bob.smith
Domain      : WS01
SID         : S-1-5-21-2614195641-1726409526-3792725429-1003
FullName    :
Name        : bob.smith
```

Answer: `S-1-5-21-2614195641-1726409526-3792725429-1003`

# Windows Security

## Question 2

### "What 3rd party security application is disabled at startup for the current user? (The answer is case sensitive)."

Using the same RDP connection from the previous question, students need to run the `Reg Query` command on the registry hive `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run` to find out that `NordVPN`, a 3rd party security application, has the `Data` value starting with `03` for the Type `REG_BINARY`, which implies that it is disabled, because any other binary value not starting with `02` or `06` means that the application is disabled:

Code: powershell

```powershell
Reg Query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
```

```
PS C:\Users\htb-student> Reg Query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"

HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run
    OneDrive    REG_BINARY    03000000D674D894ED16D801
    NordVPN     REG_BINARY    03000000EABC5C91ED16D801
```

Alternatively, students can also search for `Startup Apps` to find `NordVPN` disabled.

Answer: `NordVPN`

# Skills Assessment - Windows Fundamentals

## Question 1

### "What is the name of the group that is present in the Company Data Share Permissions ACL by default?"

Before attempting to answer the questions, students need to carry out the eight steps provided in the section.

1. "`Creating a shared folder called Company Data`"

After spawning the Windows target machine, students need to use `xfreerdp` to connect to it using the credentials `htb-student:Academy_WinFun!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:Academy_WinFun! /dynamic-resolution
```

```
┌─[eu-academy-1]─[10.10.15.83]─[htb-ac413848@htb-dd0rdy2msl]─[~]
└──╼ [★]$ xfreerdp /v:10.129.62.233 /u:htb-student /p:Academy_WinFun! /dynamic-resolution

<SNIP>
[11:00:12:199] [10751:10752] [WARN][com.freerdp.crypto] - CN = WS01
[11:00:12:199] [10751:10752] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[11:00:12:199] [10751:10752] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[11:00:12:199] [10751:10752] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[11:00:12:199] [10751:10752] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.62.233:3389) 
[11:00:12:199] [10751:10752] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[11:00:12:199] [10751:10752] [ERROR][com.freerdp.crypto] - Common Name (CN):
[11:00:12:199] [10751:10752] [ERROR][com.freerdp.crypto] - 	WS01
[11:00:12:199] [10751:10752] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.62.233:3389 (RDP-Server):
	Common Name: WS01
	Subject:     CN = WS01
	Issuer:      CN = WS01
	Thumbprint:  95:77:cc:50:c9:c7:16:39:f6:be:2d:df:e1:5d:db:84:14:e6:e5:a5:b9:1b:05:33:c5:0e:61:54:45:76:d2:eb
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

![[HTB Solutions/Others/z. images/a9ccfcfeca8649ef04c04108c693f9c3_MD5.jpg]]

Then, students need to create a folder named `Company Data` and make it a `share`:

![[HTB Solutions/Others/z. images/f7f448982876ffcfdd0be84bd630921a_MD5.jpg]]

![[HTB Solutions/Others/z. images/137d6c5542bf138bfd3d08618944cd28_MD5.jpg]]

![[HTB Solutions/Others/z. images/a3be5e961e579f477c1b68b5683d5e53_MD5.jpg]]

![[HTB Solutions/Others/z. images/b1ffe7f37810afa929974b0f9fe41d44_MD5.jpg]]

![[HTB Solutions/Others/z. images/b8f16db4d336e296d52f991144fb261d_MD5.jpg]]

To find the answer for the first question, students need to open the `Sharing` tab of the folder's properties, click `Advanced Sharing`, then click `Permissions` tab to notice that the `Everyone` group is present in the share's ACL by default:

![[HTB Solutions/Others/z. images/8c71e6ea05156d0278c58304a0fa66b8_MD5.jpg]]

![[HTB Solutions/Others/z. images/1f1ed548101fb3eeda32518fb284c2f2_MD5.jpg]]

2. "`Creating a subfolder called HR inside of the Company Data folder`"

Within the `Company Data` folder, students need to create a subfolder called `HR` inside it and make it a share also:

![[HTB Solutions/Others/z. images/30a4bd8a7ee14ffc1b7a6fdd3ba13255_MD5.jpg]]

![[HTB Solutions/Others/z. images/57f58ff964bcb10e75ebddc79de011d3_MD5.jpg]]

![[HTB Solutions/Others/z. images/e2d6694a3c49fdec1e5c603abaef44b8_MD5.jpg]]

3. "`Creating a user called Jim`"

Subsequently, students need to create a user called `Jim`:

![[HTB Solutions/Others/z. images/687cf52421665755e864755317094572_MD5.jpg]]

![[HTB Solutions/Others/z. images/c4211503e7a95b03705267c53d5a174c_MD5.jpg]]

![[HTB Solutions/Others/z. images/ec4fe6ee714820fbc567bfc5ae12d14c_MD5.jpg]]

![[HTB Solutions/Others/z. images/7473731e6bbf54c18e4d3991703f3bda_MD5.jpg]]

4. "`Creating a security group called HR`"

Afterward, students need to create a security group called `HR`. To do so, students need to search for `Computer Management`:

![[HTB Solutions/Others/z. images/7fff8446acc13e139738e14b6214fe8f_MD5.jpg]]

Then, students need to select `Local Users and Groups`, select `Groups`, right-click and select `New Group`:

![[HTB Solutions/Others/z. images/9d0071c07bd52fa2bbfb70de56d7dda5_MD5.jpg]]

5. "`Adding Jim to the HR security group`"

Students also need to add the user `Jim` to the security group before creating it:

![[HTB Solutions/Others/z. images/b44d7d476ecbf98d38fd8595c60a8135_MD5.jpg]]

![[HTB Solutions/Others/z. images/05fc8b04bce228b4a6f9193d8322b72e_MD5.jpg]]

![[HTB Solutions/Others/z. images/585635ef02b12fe65e468833c2a87406_MD5.jpg]]

6. "`Adding the HR security group to the shared Company Data folder and NTFS permissions list`"
1. "`Remove the default group that is present`"
2. "`Share Permissions: Allow Change & Read`"
3. "`Disable Inheritance before issuing specific NTFS permissions`"
4. "`NTFS permissions: Modify, Read & Execute, List folder contents, Read, Write`"

Subsequently, on the `Company Data` share, students need to remove the `Everyone` group and then add the `HR` one:

![[HTB Solutions/Others/z. images/6e38e2a1a843b4a6166af50d336d1bc8_MD5.jpg]]

![[HTB Solutions/Others/z. images/270c2284d106560812b96d974ca40ff5_MD5.jpg]]

![[HTB Solutions/Others/z. images/e11c1170e4e21be4a45cb4a13c0321e3_MD5.jpg]]

Students need to assign the `Change` and `Read` permissions for the `HR` group:

![[HTB Solutions/Others/z. images/d202c00bba05ea9758e835696d144f12_MD5.jpg]]

Then, students need to `Disable inheritance`:

![[HTB Solutions/Others/z. images/8a9a05a9a5490adf17f6cf967bacdb45_MD5.jpg]]

![[HTB Solutions/Others/z. images/5e6a5a466791c4da3ccb320da2d2ee03_MD5.jpg]]

![[HTB Solutions/Others/z. images/b722f6ab94d6e437998b8af60afba60e_MD5.jpg]]

![[HTB Solutions/Others/z. images/db2c51d2414a644d13c71da6d726001f_MD5.jpg]]

After applying the changes, students need to set the `NTFS` permissions `Modify`, `Read`, `Execute`, `List folder contents`, and `Write` to the user `htb-student`:

![[HTB Solutions/Others/z. images/ad87e6950cfd610a0e34d41b379a8c6a_MD5.jpg]]

Then, students need to do the same for the share `HR` within `Company Data`:

![[HTB Solutions/Others/z. images/cd7f53d65e41101edc424bcea5d04045_MD5.jpg]]

![[HTB Solutions/Others/z. images/4987c53f6f40486b331230d19e7aad5a_MD5.jpg]]

![[HTB Solutions/Others/z. images/14adc6ce531cc148f4fe9928ba2ff769_MD5.jpg]]

![[HTB Solutions/Others/z. images/bff3a21df8ba6a0ef2732961df90134b_MD5.jpg]]

![[HTB Solutions/Others/z. images/d036052169108c912f1cc641e088e71b_MD5.jpg]]

![[HTB Solutions/Others/z. images/9afbc09c251efc59f6f9aab8fcd82f6e_MD5.jpg]]

![[HTB Solutions/Others/z. images/cf20dfcd17b8ccd599fbabab9ef58351_MD5.jpg]]

![[HTB Solutions/Others/z. images/5a316b10ca755a119a1ded7a5848e7bc_MD5.jpg]]

![[HTB Solutions/Others/z. images/43be584ff8365b7c5928e2f1cf3addba_MD5.jpg]]

![[HTB Solutions/Others/z. images/6b85dfec12e68cb78d8a4456fbf26e27_MD5.jpg]]

Students now can answer the subsequent questions that rely on performing these steps.

Answer: `Everyone`

# Skills Assessment - Windows Fundamentals

## Question 2

### "What is the name of the tab that allows you to configure NTFS permissions?"

`Security` is the name of the tab that allows configuring `NTFS` permissions, as students have seen when applying the steps in the previous section.

Answer: `Security`

# Skills Assessment - Windows Fundamentals

## Question 3

### "What is the name of the service associated with Windows Update?"

From the reading of the section `Service Permissions`, student know that the name of the service associated with `Windows Update` is `wuauserv`:

![[HTB Solutions/Others/z. images/395c663292cc111d8656f2f60b067b7f_MD5.jpg]]

Answer: `wuauserv`

# Skills Assessment - Windows Fundamentals

## Question 4

### "List the SID associated with the user account Jim you created."

Using the previously established RDP session, students need to use the `Get-Wmiobject` Cmdlet on the `Win32_UserAccount` class to find that the `SID` of the user `Jim` is `S-1-5-21-2614195641-1726409526-3792725429-1006`:

Code: powershell

```powershell
Get-Wmiobject -Class Win32_UserAccount
```

```
PS C:\Users\htb-student> Get-Wmiobject -Class Win32_UserAccount

<SNIP>

AccountType : 512
Caption     : WS01\Jim
Domain      : WS01
SID         : S-1-5-21-2614195641-1726409526-3792725429-1006
FullName    :
Name        : Jim

<SNIP>
```

Answer: `S-1-5-21-2614195641-1726409526-3792725429-1006`

# Skills Assessment - Windows Fundamentals

## Question 5

### "List the SID associated with the HR security group you created."

Using the previously established RDP session, students need to use the `Get-Wmiobject` Cmdlet on the `Win32_Group` class to find that the `SID` of the security group `HR` is `S-1-5-21-2614195641-1726409526-3792725429-1007`:

```powershell
Get-Wmiobject -Class Win32_Group
```
```
PS C:\Users\htb-student> Get-Wmiobject -Class Win32_Group

Caption                                  Domain Name                                SID
-------                                  ------ ----                                ---
WS01\Access Control Assistance Operators WS01   Access Control Assistance Operators S-1-5-32-579
WS01\Administrators                      WS01   Administrators                      S-1-5-32-544
WS01\Backup Operators                    WS01   Backup Operators                    S-1-5-32-551
WS01\Cryptographic Operators             WS01   Cryptographic Operators             S-1-5-32-569
WS01\Distributed COM Users               WS01   Distributed COM Users               S-1-5-32-562
WS01\Event Log Readers                   WS01   Event Log Readers                   S-1-5-32-573
WS01\Guests                              WS01   Guests                              S-1-5-32-546
WS01\Hyper-V Administrators              WS01   Hyper-V Administrators              S-1-5-32-578
WS01\IIS_IUSRS                           WS01   IIS_IUSRS                           S-1-5-32-568
WS01\Network Configuration Operators     WS01   Network Configuration Operators     S-1-5-32-556
WS01\Performance Log Users               WS01   Performance Log Users               S-1-5-32-559
WS01\Performance Monitor Users           WS01   Performance Monitor Users           S-1-5-32-558
WS01\Power Users                         WS01   Power Users                         S-1-5-32-547
WS01\Remote Desktop Users                WS01   Remote Desktop Users                S-1-5-32-555
WS01\Remote Management Users             WS01   Remote Management Users             S-1-5-32-580
WS01\Replicator                          WS01   Replicator                          S-1-5-32-552
WS01\System Managed Accounts Group       WS01   System Managed Accounts Group       S-1-5-32-581
WS01\Users                               WS01   Users                               S-1-5-32-545
WS01\HR                                  WS01   HR                                  S-1-5-21-2614195641-1726409526-3792725429-1007
```

Answer: `S-1-5-21-2614195641-1726409526-3792725429-1007`