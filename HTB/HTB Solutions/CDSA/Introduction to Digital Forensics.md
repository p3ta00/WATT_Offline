| Section | Question Number | Answer |
| --- | --- | --- |
| Evidence Acquisition Techniques & Tools | Question 1 | AutorunsToWinEventLog |
| Memory Forensics | Question 1 | tasksche.exe |
| Memory Forensics | Question 2 | hibsys.WNCRYT |
| Memory Forensics | Question 3 | 3012 |
| Rapid Triage Examination & Analysis Tools | Question 1 | microsoft.windowskits.feedback.exe |
| Rapid Triage Examination & Analysis Tools | Question 2 | Microsoft-Windows-DiagnosticDataCollector |
| Rapid Triage Examination & Analysis Tools | Question 3 | cmdkey.exe |
| Practical Digital Forensics Scenario | Question 1 | PowerView |
| Practical Digital Forensics Scenario | Question 2 | rundll32.exe |
| Skills Assessment | Question 1 | reverse.exe |
| Skills Assessment | Question 2 | 3.19.219.4 |
| Skills Assessment | Question 3 | HKEY\_LOCAL\_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run |
| Skills Assessment | Question 4 | C:\\Users\\j0seph\\AppData\\Local\\mimik |
| Skills Assessment | Question 5 | insurance.DOCX |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Evidence Acquisition Techniques & Tools

## Question 1

### "Visit the URL "https://127.0.0.1:8889/app/index.html#/search/all" and log in using the credentials: admin/password. After logging in, click on the circular symbol adjacent to "Client ID". Subsequently, select the displayed "Client ID" and click on "Collected". Initiate a new collection and gather artifacts labeled as "Windows.KapeFiles.Targets" using the \_SANS\_Triage configuration. Lastly, examine the collected artifacts and enter the name of the scheduled task that begins with 'A' and concludes with 'g' as your answer."

Students need to first connect to the spawned target with remote desktop protocol, using `Administrator:password` as the login credentials:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:password /dynamic-resolution
```

```
─[us-academy-1]─[10.10.15.220]─[htb-ac-594497@htb-pywgrcqrpf]─[~]
└──╼ [★]$ xfreerdp /v:10.129.216.182 /u:Administrator /p:password /dynamic-resolution 

[18:14:54:853] [3282:3283] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[18:14:54:853] [3282:3283] [WARN][com.freerdp.crypto] - CN = E-CORP
[18:14:54:854] [3282:3283] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[18:14:54:854] [3282:3283] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[18:14:54:854] [3282:3283] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[18:14:54:854] [3282:3283] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.216.182:3389) 
[18:14:54:854] [3282:3283] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
```

Then, students need to launch `Chrome` using the shortcut on the desktop, and proceed to navigate to `https://127.0.0.1:8889/app/index.html#/search/all`. To bypass the "Your connection is not private" message, students need to click `Advanced` -> `Proceed to 127.0.0.1 (unsafe)`.

![[HTB Solutions/CDSA/z. images/f7d862a1896853ee3631ce23f99b980b_MD5.jpg]]

When prompted, students need provide `admin:password` as the credentials to log in. After logging in, students click on the circular symbol adjacent to "Client ID".

![[HTB Solutions/CDSA/z. images/a70a2a74197f658937c6c8612def5a3b_MD5.jpg]]

Subsequently, students need to select the displayed "Client ID" and click on "Collected".

![[HTB Solutions/CDSA/z. images/a795092adb7e9f41786af0eb812806d7_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/2cb991e355b4b398a4b79c8cd65009a3_MD5.jpg]]

Now, students need to click the `+` symbol to initiate a new collection:

![[HTB Solutions/CDSA/z. images/4852996013fed42d4346ee540668221a_MD5.jpg]]

Students need to scroll down the list, choosing `Windows.KapeFiles.Targets`:

![[HTB Solutions/CDSA/z. images/4228a5951e014bf938ef52da5898d166_MD5.jpg]]

Then, students need to select `Configure Parameters` -> `Configure`:

![[HTB Solutions/CDSA/z. images/74b4dfe2f201da579ca150f765d0ac30_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/179770ec9dc98feaa2bb50f759a68cac_MD5.jpg]]

Students need to check the `_SANS_Triage` configuration, then press `Launch`:

![[HTB Solutions/CDSA/z. images/113f8463b03db57d9d4566d9479980f0_MD5.jpg]]

Students will have to wait several moments for the collection to complete. Once the collection has finished, students need to select it and prepare to download the collected artifacts:

![[HTB Solutions/CDSA/z. images/791dee90462eacfc7dd1c65f3adaaa9f_MD5.jpg]]

The download will take a few moments to prepare. Once it's ready, students need to download the artifacts for further analysis:

![[HTB Solutions/CDSA/z. images/9118c601045dbd07531526623a2836d3_MD5.jpg]]

When the download finishes, students need to open File Explorer and navigate to the Downloads directory, where the filr will be unzipped:

![[HTB Solutions/CDSA/z. images/bacd13bcb91ad2b52538bca1ce58f786_MD5.jpg]]

Students should extract the archive to the Desktop:

![[HTB Solutions/CDSA/z. images/16f32610b5eee8909207c39885e50746_MD5.jpg]]

Exploring the newly extracted archive for forensic artifacts, students will find desired scheduled task located within `\uploads\auto\C%3A\Windows\System32\Tasks`:

![[HTB Solutions/CDSA/z. images/7d87744845206db82709e5d32fbee5e1_MD5.jpg]]

Answer: `AutorunsToWinEventLog`

# Memory Forensics

## Question 1

### "Examine the file "/home/htb-student/MemoryDumps/Win7-2515534d.vmem" with Volatility. Enter the parent process name for @WanaDecryptor (Pid 1060) as your answer. Answer format: \_.exe"

Students need to first connect to the spawned target with SSH, providing `htb-student:HTB_@cademy_stdnt!` as the credentials:

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[us-academy-1]─[10.10.15.220]─[htb-ac-594497@htb-pywgrcqrpf]─[~]
└──╼ [★]$ ssh htb-student@10.129.123.185

The authenticity of host '10.129.123.185 (10.129.123.185)' can't be established.
ECDSA key fingerprint is SHA256:0loReoHRiJTAMnDSjRnm+AKJqFgmSa3nrD7TT8SC/qI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.123.185' (ECDSA) to the list of known hosts.
htb-student@10.129.123.185's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-122-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Thu Sep 14 04:35:48 2023 from 10.10.14.23

htb-student@remnux:~$ 
```

Then, students need to examine the `Win7-2515534d.vmem` file using Volatility, choosing the `Win7SP1x64` profile along with the `pstree` plugin:

Code: shell

```shell
vol.py -f /home/htb-student/MemoryDumps/Win7-2515534d.vmem --profile=Win7SP1x64 pstree
```

```
htb-student@remnux:~$ vol.py -f /home/htb-student/MemoryDumps/Win7-2515534d.vmem --profile=Win7SP1x64 pstree

Volatility Foundation Volatility Framework 2.6.1
/usr/local/lib/python2.7/dist-packages/volatility/plugins/community/YingLi/ssh_agent_key.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
  from cryptography.hazmat.backends.openssl import backend
Name                                                  Pid   PPid   Thds   Hnds Time
-------------------------------------------------- ------ ------ ------ ------ ----
 0xfffffa8002a51730:wininit.exe                       404    344      3     76 2023-06-22 12:04:41 UTC+0000
. 0xfffffa8002ae6b00:lsm.exe                          524    404      9    149 2023-06-22 12:04:41 UTC+0000
. 0xfffffa8002adbb00:lsass.exe                        516    404      6    585 2023-06-
<SNIP>
22 12:04:46 UTC+0000
.. 0xfffffa8002d2f060:svchost.exe                    1268    508     11    165 2023-06-22 12:04:45 UTC+0000
 0xfffffa80028a39a0:csrss.exe                         352    344      8    626 2023-06-22 12:04:40 UTC+0000
. 0xfffffa8000f90b00:conhost.exe                     3292    352      0 ------ 2023-06-22 12:34:03 UTC+0000
. 0xfffffa8001ddb060:conhost.exe                     2348    352      1     32 2023-06-22 12:31:29 UTC+0000
 0xfffffa8001d22b00:tasksche.exe                     1792   1044      8     82 2023-06-22 12:31:13 UTC+0000
. 0xfffffa8002572060:@WanaDecryptor                  1060   1792      2     71 2023-06-22 12:31:27 UTC+0000
.. 0xfffffa8001568060:taskhsvc.exe                   3012   1060      4    101 2023-06-22 12:31:29 UTC+0000
 0xfffffa800141e9a0:@WanaDecryptor                   3252   3212      1     75 2023-06-22 12:31:45 UTC+0000
 0xfffffa8000ca8860:System                              4      0     97    446 2023-06-22 12:04:39 UTC+0000
. 0xfffffa8001a64920:smss.exe                         264      4      2     29 2023-06-22 12:04:39 UTC+0000
 0xfffffa8001d27b00:explorer.exe                     2508   2472     24    843 2023-06-22 12:05:13 UTC+0000
. 0xfffffa80123fc590:vmtoolsd.exe                    2600   2508      8    182 2023-06-22 12:05:14 UTC+0000
. 0xfffffa80023e7750:cmd.exe                         3040   2508      1     21 2023-06-22 12:05:39 UTC+0000
. 0xfffffa80022af430:ida64.exe                       2248   2508      7    340 2023-06-22 12:16:18 UTC+0000
. 0xfffffa8000e0fb00:ProcessHacker.                   716   2508      9    476 2023-06-22 12:06:29 UTC+0000
. 0xfffffa8001420300:x32dbg.exe                      2820   2508     20    480 2023-06-22 12:23:34 UTC+0000
.. 0xfffffa8000ee96d0:Ransomware.wan                 1512   2820     11    167 2023-06-22 12:23:41 UTC+0000
... 0xfffffa8001d0f8b0:tasksche.exe                  2972   1512      0 ------ 2023-06-22 12:31:13 UTC+0000
 0xfffffa800291eb00:csrss.exe                         416    396      9    307 2023-06-22 12:04:41 UTC+0000
. 0xfffffa8001d19060:conhost.exe                     3048    416      2     53 2023-06-22 12:05:39 UTC+0000
 0xfffffa8002a86340:winlogon.exe                      464    396      3    113 2023-06-22 12:04:41 UTC+0000
 0xfffffa80014e4a70:MpCmdRun.exe                     3436   3412      5    116 2023-06-22 12:32:12 UTC+0000
```

Students will identify the `@WanaDecryptor` process has a parent process ID of `1792`, which corresponds to `tasksche.exe`.

Answer: `tasksche.exe`

# Memory Forensics

## Question 2

### "Examine the file "/home/htb-student/MemoryDumps/Win7-2515534d.vmem" with Volatility. tasksche.exe (Pid 1792) has multiple file handles open. Enter the name of the suspicious-looking file that ends with .WNCRYT as your answer. Answer format: \_.WNCRYT"

From the previously established SSH session, students need to examine the `Win7-2515534d.vmem` file with volatility, specifying the `handles` plugin along with the pid of `1729`. Additionally, students should use the `-t` option to filter for handles relating to file and file operations:

Code: shell

```shell
vol.py -f /home/htb-student/MemoryDumps/Win7-2515534d.vmem --profile=Win7SP1x64 handles -p 1792 -t file
```

```
htb-student@remnux:~$ vol.py -f /home/htb-student/MemoryDumps/Win7-2515534d.vmem --profile=Win7SP1x64 handles -p 1792 -t file

Volatility Foundation Volatility Framework 2.6.1
/usr/local/lib/python2.7/dist-packages/volatility/plugins/community/YingLi/ssh_agent_key.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
  from cryptography.hazmat.backends.openssl import backend
Offset(V)             Pid             Handle             Access Type             Details
------------------ ------ ------------------ ------------------ ---------------- -------
0xfffffa8000ea8f20   1792               0x10           0x100020 File             \Device\HarddiskVolume2\Windows
0xfffffa8002d5b8c0   1792               0x1c           0x100001 File             \Device\KsecDD
0xfffffa8000e2e070   1792               0x5c           0x100020 File             \Device\HarddiskVolume2\ProgramData\ggzstcat367
0xfffffa8002ca7390   1792               0x64           0x100001 File             \Device\KsecDD
0xfffffa8011bfd070   1792               0xf8           0x120196 File             \Device\HarddiskVolume2\ProgramData\ggzstcat367\00000000.eky
0xfffffa8001e1e070   1792              0x148           0x120196 File             \Device\HarddiskVolume2\Windows\Temp\hibsys.WNCRYT
```

Students will find the suspicious file `hibsys.WNCRYT`.

Answer: `hibsys.WNCRYT`

# Memory Forensics

## Question 3

### "Examine the file "/home/htb-student/MemoryDumps/Win7-2515534d.vmem" with Volatility. Enter the Pid of the process that loaded zlib1.dll as your answer."

From the previously established SSH session, students need to examine the `Win7-2515534d.vmem` file with volatility while specifying the `dlllist` plugin. Additionally, students need to use grep to search for instances of `zlib1.dll` that occur in the command output:

Code: shell

```shell
vol.py -f /home/htb-student/MemoryDumps/Win7-2515534d.vmem --profile=Win7SP1x64 dlllist | grep zlib1.dll -A 5 -B 35
```

```
htb-student@remnux:~$ vol.py -f /home/htb-student/MemoryDumps/Win7-2515534d.vmem --profile=Win7SP1x64 dlllist | grep zlib1.dll -A 5 -B 35

Volatility Foundation Volatility Framework 2.6.1
/usr/local/lib/python2.7/dist-packages/volatility/plugins/community/YingLi/ssh_agent_key.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
  from cryptography.hazmat.backends.openssl import backend
WARNING : volatility.debug    : NoneObject as string: Invalid Address 0x0182E048, instantiating LoadTime
WARNING : volatility.debug    : NoneObject as string: Invalid Address 0x00487018, instantiating LoadTime
WARNING : volatility.debug    : NoneObject as string: Invalid Address 0x019AF018, instantiating LoadTime
************************************************************************
taskhsvc.exe pid:   3012
Command line : TaskData\Tor\taskhsvc.exe

Base                             Size          LoadCount LoadTime                       Path
------------------ ------------------ ------------------ ------------------------------ ----
0x0000000001230000           0x2fe000             0xffff 1970-01-01 00:00:00 UTC+0000   C:\ProgramData\ggzstcat367\TaskData\Tor\taskhsvc.exe
0x00000000773f0000           0x19f000             0xffff 1970-01-01 00:00:00 UTC+0000   C:\Windows\SYSTEM32\ntdll.dll
0x00000000739d0000            0x3f000                0x3 2023-06-22 12:31:29 UTC+0000   C:\Windows\SYSTEM32\wow64.dll
0x0000000073970000            0x5c000                0x1 2023-06-22 12:31:29 UTC+0000   C:\Windows\SYSTEM32\wow64win.dll
0x0000000073960000             0x8000                0x1 2023-06-22 12:31:29 UTC+0000   C:\Windows\SYSTEM32\wow64cpu.dll
0x0000000001230000           0x2fe000             0xffff 1970-01-01 00:00:00 UTC+0000   C:\ProgramData\ggzstcat367\TaskData\Tor\taskhsvc.exe
0x00000000775b0000           0x180000             0xffff 1970-01-01 00:00:00 UTC+0000   C:\Windows\SysWOW64\ntdll.dll
0x0000000075b50000           0x110000             0xffff 2023-06-22 12:31:29 UTC+0000   C:\Windows\syswow64\kernel32.dll
0x00000000770c0000            0x47000             0xffff 2023-06-22 12:31:29 UTC+0000   C:\Windows\syswow64\KERNELBASE.dll
0x000000006b630000            0x82000             0xffff 2023-06-22 12:31:30 UTC+0000   C:\ProgramData\ggzstcat367\TaskData\Tor\libevent-2-0-5.dll
0x000000006b610000            0x1c000             0xffff 2023-06-22 12:31:30 UTC+0000   C:\ProgramData\ggzstcat367\TaskData\Tor\libssp-0.dll
0x0000000074d30000            0xa1000             0xffff 2023-06-22 12:31:30 UTC+0000   C:\Windows\syswow64\ADVAPI32.dll
0x0000000077110000            0xac000             0xffff 2023-06-22 12:31:30 UTC+0000   C:\Windows\syswow64\msvcrt.dll
0x0000000075b30000            0x19000             0xffff 2023-06-22 12:31:30 UTC+0000   C:\Windows\SysWOW64\sechost.dll
0x0000000074de0000            0xf0000             0xffff 2023-06-22 12:31:30 UTC+0000   C:\Windows\syswow64\RPCRT4.dll
0x0000000074cd0000            0x60000             0xffff 2023-06-22 12:31:30 UTC+0000   C:\Windows\syswow64\SspiCli.dll
0x0000000074cc0000             0xc000             0xffff 2023-06-22 12:31:30 UTC+0000   C:\Windows\syswow64\CRYPTBASE.dll
0x000000006b590000            0x77000             0xffff 2023-06-22 12:31:30 UTC+0000   C:\ProgramData\ggzstcat367\TaskData\Tor\libgcc_s_sjlj-1.dll
0x0000000076450000           0xc4c000             0xffff 2023-06-22 12:31:30 UTC+0000   C:\Windows\syswow64\SHELL32.dll
0x0000000075c60000            0x57000             0xffff 2023-06-22 12:31:30 UTC+0000   C:\Windows\syswow64\SHLWAPI.dll
0x0000000074ee0000            0x90000             0xffff 2023-06-22 12:31:30 UTC+0000   C:\Windows\syswow64\GDI32.dll
0x0000000075e60000           0x100000             0xffff 2023-06-22 12:31:30 UTC+0000   C:\Windows\syswow64\USER32.dll
0x00000000770a0000             0xa000             0xffff 2023-06-22 12:31:30 UTC+0000   C:\Windows\syswow64\LPK.dll
0x00000000750c0000            0x9d000             0xffff 2023-06-22 12:31:30 UTC+0000   C:\Windows\syswow64\USP10.dll
0x00000000755f0000            0x35000             0xffff 2023-06-22 12:31:30 UTC+0000   C:\Windows\syswow64\WS2_32.dll
0x0000000074f70000             0x6000             0xffff 2023-06-22 12:31:30 UTC+0000   C:\Windows\syswow64\NSI.dll
0x000000006b370000           0x21c000             0xffff 2023-06-22 12:31:30 UTC+0000   C:\ProgramData\ggzstcat367\TaskData\Tor\LIBEAY32.dll
0x000000006b2e0000            0x82000             0xffff 2023-06-22 12:31:30 UTC+0000   C:\ProgramData\ggzstcat367\TaskData\Tor\SSLEAY32.dll
0x000000006b2b0000            0x22000             0xffff 2023-06-22 12:31:30 UTC+0000   C:\ProgramData\ggzstcat367\TaskData\Tor\zlib1.dll
0x0000000071ac0000            0x17000                0x1 2023-06-22 12:31:30 UTC+0000   C:\Windows\system32\CRYPTSP.dll
0x000000006d420000            0x3b000                0x1 2023-06-22 12:31:30 UTC+0000   C:\Windows\system32\rsaenh.dll
0x0000000075ad0000            0x60000                0x2 2023-06-22 12:31:30 UTC+0000   C:\Windows\system32\IMM32.DLL
0x00000000760b0000            0xcd000                0x1 2023-06-22 12:31:30 UTC+0000   C:\Windows\syswow64\MSCTF.dll
0x0000000075850000           0x15f000                0x9 2023-06-22 12:31:31 UTC+0000   C:\Windows\syswow64\ole32.dll
```

Students will find that the suspicious process, `taskhsvc.exe`, was responsible for loading the aforementioned dll; and its corresponding Pid is `3012`.

Answer: `3012`

# Rapid Triage Examination & Analysis Tools

## Question 1

### "During our examination of the USN Journal within Timeline Explorer, we observed "uninstall.exe". The attacker subsequently renamed this file. Use Zone.Identifier information to determine its new name and enter it as your answer."

Students need to first connect to the spawned target using RDP, authenticating as `johndoe:password`:

Code: shell

```shell
xfreerdp /v:STMIP /u:johndoe /p:password /dynamic-resolution 
```

```
┌─[us-academy-1]─[10.10.15.157]─[htb-ac-594497@htb-qsa6zx31td]─[~]
└──╼ [★]$ xfreerdp /v:10.129.228.173 /u:johndoe /p:password /dynamic-resolution 

[18:28:37:205] [2554:2555] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-594497/.config/freerdp
[18:28:37:205] [2554:2555] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-594497/.config/freerdp/certs]
[18:28:37:205] [2554:2555] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-594497/.config/freerdp/server]
[18:28:38:282] [2554:2555] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[18:28:38:282] [2554:2555] [WARN][com.freerdp.crypto] - CN = DESKTOP-6H5T7AF
```

Once connected, students need to open powershell and navigate to `C:\Users\johndoe\Desktop\Get-ZimmermanTools\net6`:

Code: powershell

```powershell
cd C:\Users\johndoe\Desktop\Get-ZimmermanTools\net6
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Users\johndoe> cd C:\Users\johndoe\Desktop\Get-ZimmermanTools\net6
```

Then, students need to use `MFTCMD.exe` to create CSV files for both the USN Journal and MFT.

Code: powershell

```powershell
.\MFTECmd.exe -f 'C:\Users\johndoe\Desktop\forensic_data\kape_output\D\$Extend\$J' --csv C:\Users\johndoe\Desktop\forensic_data\mft_analysis\ --csvf MFT-J.csv
.\MFTECmd.exe -f 'C:\Users\johndoe\Desktop\forensic_data\kape_output\D\$MFT' --csv C:\Users\johndoe\Desktop\forensic_data\mft_analysis\ --csvf MFT.csv
```

```
PS C:\Users\johndoe\Desktop\Get-ZimmermanTools\net6> .\MFTECmd.exe -f 'C:\Users\johndoe\Desktop\forensic_data\kape_output\D\$Extend\$J' --csv C:\Users\johndoe\Desktop\forensic_data\mft_analysis\ --csvf MFT-J.csv
MFTECmd version 1.2.2.1

Author: Eric Zimmerman (saericzimmerman@gmail.com)
https://github.com/EricZimmerman/MFTECmd

Command line: -f C:\Users\johndoe\Desktop\forensic_data\kape_output\D\$Extend\$J --csv C:\Users\johndoe\Desktop\forensic_data\mft_analysis\ --csvf MFT-J.csv

Warning: Administrator privileges not found!

File type: UsnJournal

Processed C:\Users\johndoe\Desktop\forensic_data\kape_output\D\$Extend\$J in 0.3090 seconds

Usn entries found in C:\Users\johndoe\Desktop\forensic_data\kape_output\D\$Extend\$J: 89,704
        CSV output will be saved to C:\Users\johndoe\Desktop\forensic_data\mft_analysis\MFT-J.csv

PS C:\Users\johndoe\Desktop\Get-ZimmermanTools\net6> .\MFTECmd.exe -f 'C:\Users\johndoe\Desktop\forensic_data\kape_output\D\$MFT' --csv C:\Users\johndoe\Desktop\forensic_data\mft_analysis\ --csvf MFT.csv
MFTECmd version 1.2.2.1

Author: Eric Zimmerman (saericzimmerman@gmail.com)
https://github.com/EricZimmerman/MFTECmd

Command line: -f C:\Users\johndoe\Desktop\forensic_data\kape_output\D\$MFT --csv C:\Users\johndoe\Desktop\forensic_data\mft_analysis\ --csvf MFT.csv

Warning: Administrator privileges not found!

File type: Mft

Processed C:\Users\johndoe\Desktop\forensic_data\kape_output\D\$MFT in 3.1463 seconds

C:\Users\johndoe\Desktop\forensic_data\kape_output\D\$MFT: FILE records found: 93,615 (Free records: 287) File size: 91.8MB
        CSV output will be saved to C:\Users\johndoe\Desktop\forensic_data\mft_analysis\MFT.csv
```

Students need to examine both CSV files inside `Timeline Explorer` and search (`ctrl+F`) for "uninstall.exe".

![[HTB Solutions/CDSA/z. images/9a772d2929c94e544a023ac05582c55b_MD5.jpg]]

Inside the MFT-related CSV, students will notice "uninstall.exe" in the Zone.Identifier information while the filename field displays "microsoft.windowskits.feedback.exe:Zone.Identifier". Therefore, students can determine the file was renamed to `microsoft.windowskits.feedback.exe`.

Answer: `microsoft.windowskits.feedback.exe`

# Rapid Triage Examination & Analysis Tools

## Question 2

### "Review the file at "C:\\Users\\johndoe\\Desktop\\forensic\_data\\kape\_output\\D\\Windows\\System32\\winevt\\logs\\Microsoft-Windows-Sysmon%4Operational.evtx" using Timeline Explorer. It documents the creation of two scheduled tasks. Enter the name of the scheduled task that begins with "M" and concludes with "r" as your answer."

From the previously established RDP session, students to open powershell and navigate to `C:\Users\johndoe\Desktop\Get-ZimmermanTools\net6\EvtxeCmd`:

Code: powershell

```powershell
cd C:\Users\johndoe\Desktop\Get-ZimmermanTools\net6\EvtxeCmd
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Users\johndoe> cd C:\Users\johndoe\Desktop\Get-ZimmermanTools\net6\EvtxeCmd
PS C:\Users\johndoe\Desktop\Get-ZimmermanTools\net6\EvtxeCmd> 
```

Then, students need to use `EvtCmd.exe` to convert the aforementioned `Microsoft-Windows-Sysmon%4Operational.evtx` log file into a CSV file:

Code: powershell

```powershell
.\EvtxECmd.exe -f "C:\Users\johndoe\Desktop\forensic_data\kape_output\D\Windows\System32\winevt\logs\Microsoft-Windows-Sysmon%4Operational.evtx" --csv "C:\Users\johndoe\Desktop\forensic_data\event_logs\csv_timeline" --csvf kape_event_log.csv
```

```
PS C:\Users\johndoe\Desktop\Get-ZimmermanTools\net6\EvtxeCmd> .\EvtxECmd.exe -f "C:\Users\johndoe\Desktop\forensic_data\kape_output\D\Windows\System32\winevt\logs\Microsoft-Windows-Sysmon%4Operational.evtx" --csv "C:\Users\johndoe\Desktop\forensic_data\event_logs\csv_timeline" --csvf kape_event_log.csv

EvtxECmd version 1.5.0.0

Author: Eric Zimmerman (saericzimmerman@gmail.com)
https://github.com/EricZimmerman/evtx

Command line: -f C:\Users\johndoe\Desktop\forensic_data\kape_output\D\Windows\System32\winevt\logs\Microsoft-Windows-Sysmon%4Operational.evtx --csv C:\Users\johndoe\Desktop\forensic_data\event_logs\csv_timeline --csvf kape_event_log.csv

Warning: Administrator privileges not found!

CSV output will be saved to C:\Users\johndoe\Desktop\forensic_data\event_logs\csv_timeline\kape_event_log.csv

<SNIP>

Event log details
Flags: None
Chunk count: 28
Stored/Calculated CRC: 3EF9F1C/3EF9F1C
Earliest timestamp: 2023-09-07 08:23:18.4430130
Latest timestamp:   2023-09-07 08:33:00.0069805
Total event log records found: 1,920

Records included: 1,920 Errors: 0 Events dropped: 0

Metrics (including dropped events)
Event ID        Count
1               95
2               76
3               346
4               1
8               44
10              6
11              321
12              674
13              356
16              1

Processed 1 file in 7.5477 seconds
```

Students need to view the newly created `kape_event_log.csv` file with `Timeline Explorer`, and subsequently search (`Ctrl+F`) for "schtasks":

![[HTB Solutions/CDSA/z. images/27c10c82efb8790a498097ed9fcef8c5_MD5.jpg]]

Analyzing the two results, students need to use the scrollbar to navigate to the `Executable Info` column:

![[HTB Solutions/CDSA/z. images/773c792e8f50d7542f9ab8dc14275b5d_MD5.jpg]]

Students will find evidence of a scheduled task named `Microsoft-Windows-DiagnosticDataCollector`.

Answer: `Microsoft-Windows-DiagnosticDataCollector`

# Rapid Triage Examination & Analysis Tools

## Question 3

### "Examine the contents of the file located at "C:\\Users\\johndoe\\Desktop\\forensic\_data\\APMX64\\discord.apmx64" using API Monitor. "discord.exe" performed process injection against another process as well. Identify its name and enter it as your answer."

From the previously established RDP session, students need to first launch API Monitor (available at `C:\Program Files\rohitab.com\API Monitor`). Then, students need to select `File` -> `Open`, selecting the `discord.apmx64` file to be analyzed:

![[HTB Solutions/CDSA/z. images/3b0c8c99106b0bbe0b11d188f63e0623_MD5.jpg]]

Now, students need to perform a search (`Ctrl+F`) for the "CreateProcess" function. The first result reveals evidence of the process `comp.exe`:

![[HTB Solutions/CDSA/z. images/dee0b3d9693e884b628964d74481c23e_MD5.jpg]]

Students need to return to the search window and select `Find Next`:

![[HTB Solutions/CDSA/z. images/25ef56ce2e1819c90d225f7134b15c9f_MD5.jpg]]

Subsequently, students will identify `cmdkey.exe` as the other process involved with the process injection.

Answer: `cmdkey.exe`

# Practical Digital Forensics Scenario

## Question 1

### "Extract and scrutinize the memory content of the suspicious PowerShell process which corresponds to PID 6744. Determine which tool from the PowerSploit repository (accessible at https://github.com/PowerShellMafia/PowerSploit) has been utilized within the process, and enter its name as your answer."

Students need to examine the repository for `Powersploit`, finding various references to the tools/features that are now part of the project (i.e. `Powerview`and `PowerUp`):

![[HTB Solutions/CDSA/z. images/505f8f30bae498009f7c02430b85b769_MD5.jpg]]

For this exercise, students will need to use `strings.exe` to search for occurrences of these tool names within the designated process memory dump. Therefore, students need to download `sysinternals` to their attack host:

Code: shell

```shell
wget https://download.sysinternals.com/files/SysinternalsSuite.zip
```

```
┌─[us-academy-1]─[10.10.15.157]─[htb-ac-594497@htb-rl36tjgtdm]─[~]
└──╼ [★]$ wget https://download.sysinternals.com/files/SysinternalsSuite.zip

--2023-09-27 00:38:41--  https://download.sysinternals.com/files/SysinternalsSuite.zip
Resolving download.sysinternals.com (download.sysinternals.com)... 152.199.4.33
Connecting to download.sysinternals.com (download.sysinternals.com)|152.199.4.33|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 47349036 (45M) [application/x-zip-compressed]
Saving to: ‘SysinternalsSuite.zip’

SysinternalsSuite.z 100%[===================>]  45.16M   113MB/s    in 0.4s    

2023-09-27 00:38:42 (113 MB/s) - ‘SysinternalsSuite.zip’ saved [47349036/47349036]
```

Now, students need to connect to the spawned target using RDP, authenticating as `johndoe:password` while using the `/drive` option to specify a shared drive (to be used for the transfer of `sysinternals.zip`):

Code: shell

```shell
xfreerdp /v:STMIP /u:johndoe /p:password /dynamic-resolution /drive:share,/home/htb-ac-XXXXXX
```

```
┌─[us-academy-1]─[10.10.15.157]─[htb-ac-594497@htb-qsa6zx31td]─[~]
└──╼ [★]$ xfreerdp /v:10.129.228.173 /u:johndoe /p:password /dynamic-resolution /drive:share,/home/htb-ac-594497 

[18:28:37:205] [2554:2555] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-594497/.config/freerdp
[18:28:37:205] [2554:2555] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-594497/.config/freerdp/certs]
[18:28:37:205] [2554:2555] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-594497/.config/freerdp/server]
[18:28:38:282] [2554:2555] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[18:28:38:282] [2554:2555] [WARN][com.freerdp.crypto] - CN = DESKTOP-6H5T7AF
```

Upon connecting, students need to open `File Explorer` and copy the `sysinternals.zip` archive from the shared drive to the Desktop. Subsequently, students need to extract the archive, then launch `strings.exe` and accept the `EULA`.

![[HTB Solutions/CDSA/z. images/dcedd12c964229f43aaf916c87f36de8_MD5.jpg]] ![[HTB Solutions/CDSA/z. images/c30e38bb5510c5a62e768314b796e330_MD5.jpg]]

Next, students need to open command prompt and run `volatility` with the `windows.memmap` plugin to extract all memory resident pages from process `6744`:

Code: cmd

```cmd
cd Desktop\volatility3-develop
python vol.py -q -f ..\memdump\PhysicalMemory.raw windows.memmap --pid 6744 --dump
```

```
Microsoft Windows [Version 10.0.19045.3448]
(c) Microsoft Corporation. All rights reserved.

C:\Users\johndoe>cd Desktop\volatility3-develop

C:\Users\johndoe\Desktop\volatility3-develop>python vol.py -q -f ..\memdump\PhysicalMemory.raw windows.memmap --pid 6744 --dump
Volatility 3 Framework 2.5.0

Virtual Physical        Size    Offset in File  File output

0x7ffe0000      0x10af000       0x1000  0x0     pid.6744.dmp
0x7ffec000      0xd000  0x1000  0x1000  pid.6744.dmp
0x75e12ab000    0x28394000      0x1000  0x2000  pid.6744.dmp
0x75e12c6000    0x2690f000      0x1000  0x3000  pid.6744.dmp
0x75e12c7000    0x3f80e000      0x1000  0x4000  pid.6744.dmp
0x75e12ce000    0x43c71000      0x1000  0x5000  pid.6744.dmp
0x75e12cf000    0x623f0000      0x1000  0x6000  pid.6744.dmp
0x75e12dc000    0x3381000       0x1000  0x7000  pid.6744.dmp
<SNIP>
0xf801d3636000  0x5b083000      0x1000  0x1b7b8000      pid.6744.dmp
0xf801d363a000  0x73407000      0x1000  0x1b7b9000      pid.6744.dmp
0xf801d363b000  0x35f08000      0x1000  0x1b7ba000      pid.6744.dmp
0xf801d363c000  0x31189000      0x1000  0x1b7bb000      pid.6744.dmp
0xf801d8c70000  0x6b02a000      0x1000  0x1b7bc000      pid.6744.dmp
```

Students need to use `strings.exe` against the newly created `pid.6744.dmp` file, saving the output to a text file. Once complete, students need to view the text file with `notepad`:

Code: cmd

```cmd
C:\Users\johndoe\Desktop\SysinternalsSuite\strings.exe pid.6744.dmp >> a.txt
notepad a.txt
```

```
C:\Users\johndoe\Desktop\volatility3-develop>C:\Users\johndoe\Desktop\SysinternalsSuite\strings.exe pid.6744.dmp >> a.txt

Strings v2.54 - Search for ANSI and Unicode strings in binary images.
Copyright (C) 1999-2021 Mark Russinovich
Sysinternals - www.sysinternals.com

C:\Users\johndoe\Desktop\volatility3-develop>notepad a.txt
```

Examining the extracted strings within `notepad`, students need to search (`Ctrl+F`) to look for instances of the tool names mentioned in the Powersploit repository:

![[HTB Solutions/CDSA/z. images/530fa247d5794d335bc0b9fd5082a6dd_MD5.jpg]]

Students will find evidence of `PowerView` being utilized within the process.

Additionally, students can perform similar analysis by way of YARA rules. To test the functionality, students need to use a rule with the following format:

Code: yaml

```yaml
rule ExampleRule
{
	strings:
		$my_text_string = "PowerView" wide ascii
		$my_text_string2 = "Invoke-Shellcode" wide ascii
	conditionL
		1 of ($my_text_string*)
}
```

To perform the analysis, students need to use this example rule along with `yara64.exe`, supplying the `-s` option to print matching strings:

Code: cmd

```cmd
yara64.exe -s a.yar C:\Users\johndoe\Desktop\volatility3-develop\pid.6744.dmp
```

![[HTB Solutions/CDSA/z. images/8b89789e26d020a20c28a699fc61a77a_MD5.jpg]]

The YARA rule confirms three instances of `PowerView` occurring within the memory dump.

Answer: `PowerView`

# Practical Digital Forensics Scenario

## Question 2

### "Investigate the USN Journal located at "C:\\Users\\johndoe\\Desktop\\kapefiles\\ntfs\\%5C%5C.%5CC%3A\\$Extend\\$UsnJrnl%3A$J" to determine how "advanced\_ip\_scanner.exe" was introduced to the compromised system. Enter the name of the associated process as your answer. Answer format: \_.exe"

From the previously established RDP session, students need to use open command prompt then use `usn.py` to convert the aforementioned USN Journal to a CSV file:

Code: cmd

```cmd
python C:\Users\johndoe\Desktop\files\USN-Journal-Parser-master\usnparser\usn.py -f C:\Users\johndoe\Desktop\kapefiles\ntfs\%5C%5C.%5CC%3A\$Extend\$UsnJrnl%3A$J -o C:\Users\johndoe\Desktop\usn_output.csv -c
```

```
Microsoft Windows [Version 10.0.19045.3448]
(c) Microsoft Corporation. All rights reserved.

C:\Users\johndoe>python C:\Users\johndoe\Desktop\files\USN-Journal-Parser-master\usnparser\usn.py -f C:\Users\johndoe\Desktop\kapefiles\ntfs\%5C%5C.%5CC%3A\$Extend\$UsnJrnl%3A$J -o C:\Users\johndoe\Desktop\usn_output.csv -c
```

Then, students need to view the newly created CSV file with `LibreOffice`, selecting `Fixed Width` when prompted:

![[HTB Solutions/CDSA/z. images/53d2c244edaa646d2876592c560755a8_MD5.jpg]]

Subsequently, students need to search for "advanced\_ip\_scanner.exe". The results reveal another file, `advanced.zip`, appearing right before it:

![[HTB Solutions/CDSA/z. images/46047ba3f55c422ab28bbd4d94c60a28_MD5.jpg]]

For further analysis, students need to launch `Autopsy`, selecting `C:\Users\johndoe\Desktop\MalwareAttack\MalwareAttack.aut` as the case file. Then, students need to do a keyword search for "advanced.zip":

![[HTB Solutions/CDSA/z. images/2d15f590155600b474eac81843dc78b6_MD5.jpg]]

Students need to right-click and `Extract File`, saving `advanced.zip` to the Export directory. Exploring the archive, students will be able to confirm that it is indeed the source of the `advanced_ip_scanner.exe`:

![[HTB Solutions/CDSA/z. images/8646e147b520a0cc1b689af421e5f2de_MD5.jpg]]

Subsequently, students need to return to `Autopsy` and further analyze the `Microsoft-Windows-Sysmon%4Operational.evtx` file that was returned from the search query:

![[HTB Solutions/CDSA/z. images/74093e6ba5cc1082de568f2ab255bd4c_MD5.jpg]]

Students will find that the syslog file confirms the parent process `rundll32.exe` being responsible for the creation of `advanced.zip`

Answer: `rundll32.exe`

# Skills Assessment

## Question 1

### "Using VAD analysis, pinpoint the suspicious process and enter its name as your answer. Answer format: \_.exe"

Students need to first connect to the spawned target with remote desktop protocol, using `Administrator:password` as the login credentials:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:password /dynamic-resolution
```

```
─[us-academy-1]─[10.10.15.220]─[htb-ac-594497@htb-pywgrcqrpf]─[~]
└──╼ [★]$ xfreerdp /v:10.129.216.182 /u:Administrator /p:password /dynamic-resolution 

[18:14:54:853] [3282:3283] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[18:14:54:853] [3282:3283] [WARN][com.freerdp.crypto] - CN = E-CORP
[18:14:54:854] [3282:3283] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[18:14:54:854] [3282:3283] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[18:14:54:854] [3282:3283] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[18:14:54:854] [3282:3283] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.216.182:3389) 
[18:14:54:854] [3282:3283] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
```

Then, students need to launch `Chrome` using the shortcut on the desktop, and proceed to navigate to `https://127.0.0.1:8889/app/index.html#/search/all`. To bypass the "Your connection is not private" message, students need to click `Advanced` -> `Proceed to 127.0.0.1 (unsafe)`.

![[HTB Solutions/CDSA/z. images/f7d862a1896853ee3631ce23f99b980b_MD5.jpg]]

When prompted, students need provide `admin:password` as the credentials to log in. After logging in, students click on the circular symbol adjacent to "Client ID".

![[HTB Solutions/CDSA/z. images/a70a2a74197f658937c6c8612def5a3b_MD5.jpg]]

Subsequently, students need to select the displayed "Client ID" and click on "Collected".

![[HTB Solutions/CDSA/z. images/a795092adb7e9f41786af0eb812806d7_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/2cb991e355b4b398a4b79c8cd65009a3_MD5.jpg]]

Now, students need to click the `+` symbol to initiate a new collection:

![[HTB Solutions/CDSA/z. images/4852996013fed42d4346ee540668221a_MD5.jpg]]

Students need to scroll down the list, choosing `Exchange.Windows.Detection.Malfind`:

![[HTB Solutions/CDSA/z. images/86210e88cea009f0a706d800957e87b4_MD5.jpg]]

Students need to press `Launch`, then wait a few moments for the collection to complete. When finished, students need to inspect the `Results`:

![[HTB Solutions/CDSA/z. images/3e3c319b793430c80b2351fba5fc4cbf_MD5.jpg]]

Here, students will identify `reverse.exe` as the suspicious process.

Answer: `reverse.exe`

# Skills Assessment

## Question 2

### "Determine the IP address of the C2 (Command and Control) server and enter it as your answer."

From the previously established RDP session, students need to use Velociraptor to perform a new collection, this time specifying `Windows.Carving.CobaltStrike` as the artifact to collect:

![[HTB Solutions/CDSA/z. images/3b38d6b2c5f0eb27dbe8798b4cf80aef_MD5.jpg]]

Students need to press `Launch`, then wait a few moments for the collection to complete. When finished, students need to inspect the `Results`:

![[HTB Solutions/CDSA/z. images/922cdf75d57bc5350767a76bece3054f_MD5.jpg]]

Students will find the C2 Server has been identified as `3.19.219.4`.

Answer: `3.19.219.4`

# Skills Assessment

## Question 3

### "Determine the registry key used for persistence and enter it as your answer."

From the previously established RDP session, students need to use Velociraptor to perform a new collection, this time specifying `Windows.Sys.StartupItems` as the artifact to collect:

![[HTB Solutions/CDSA/z. images/7b0a454bc3098e7d278538b7b639ba5a_MD5.jpg]]

Students need to press `Launch`, then wait a few moments for the collection to complete. When finished, students need to inspect the `Results`:

![[HTB Solutions/CDSA/z. images/1163a0f204ac23c40fe8b116ebedcdbe_MD5.jpg]]

Here, students will identify the `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` key is being used for persistence.

Answer: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

# Skills Assessment

## Question 4

### "Determine the folder that contains all Mimikatz-related files and enter the full path as your answer."

From the previously established RDP session, students need to use Velociraptor to perform a new collection, this time specifying `Windows.Search.Yara` as the artifact to collect::

![[HTB Solutions/CDSA/z. images/8247ecb31bdb21ddcffb28334c889b49_MD5.jpg]]

Students need to select `Configure Paramters`, then select the wrench icon to configure the artifact.

Subsequently, students need to craft a YARA rule detect mimikatz on disk. This can be achieve with the following rule, as shown in the mimikatz [repository](https://github.com/gentilkiwi/mimikatz/blob/master/kiwi_passwords.yar):

```yaml
rule mimikatz
{
	meta:
		description		= "mimikatz"
		author			= "Benjamin DELPY (gentilkiwi)"
		tool_author		= "Benjamin DELPY (gentilkiwi)"

	strings:
		$exe_x86_1		= { 89 71 04 89 [0-3] 30 8d 04 bd }
		$exe_x86_2		= { 8b 4d e? 8b 45 f4 89 75 e? 89 01 85 ff 74 }
		
		$exe_x64_1		= { 33 ff 4? 89 37 4? 8b f3 45 85 c? 74}
		$exe_x64_2		= { 4c 8b df 49 [0-3] c1 e3 04 48 [0-3] 8b cb 4c 03 [0-3] d8 }

		$dll_1			= { c7 0? 00 00 01 00 [4-14] c7 0? 01 00 00 00 }
		$dll_2			= { c7 0? 10 02 00 00 ?? 89 4? }
		
		$sys_x86		= { a0 00 00 00 24 02 00 00 40 00 00 00 [0-4] b8 00 00 00 6c 02 00 00 40 00 00 00 }
		$sys_x64		= { 88 01 00 00 3c 04 00 00 40 00 00 00 [0-4] e8 02 00 00 f8 02 00 00 40 00 00 00 }

	condition:
		(all of ($exe_x86_*)) or (all of ($exe_x64_*)) or (all of ($dll_*)) or (any of ($sys_*))
}
```

![[HTB Solutions/CDSA/z. images/4102a8adb07fb622085cae3f95c39264_MD5.jpg]]

With the YARA rule configured, students need to select `Launch` and then wait a few moments for the collection to complete: When complete, students need to examine the `Results` :

![[HTB Solutions/CDSA/z. images/a84580e90b11f06922a7853ce6ba9186_MD5.jpg]]

The collection reveals the location of mimikatz as `C:\Users\j0seph\AppData\Local\mimik`.

Answer: `C:\Users\j0seph\AppData\Local\mimik`

# Skills Assessment

## Question 5

### "Determine the Microsoft Word document that j0seph recently accessed and enter its name as your answer. Answer format: \_.DOCX"

From the previously established RDP session, students need to use Velociraptor to perform a new collection, this time specifying `Windows.Registry.RecentDocs` as the artifact to collect:

![[HTB Solutions/CDSA/z. images/dea53ca7d8ed44fe07828292ce7149d1_MD5.jpg]]

Students need to press `Launch`, then wait a few moments for the collection to complete. When finished, students need to inspect the `Results`:

![[HTB Solutions/CDSA/z. images/2a2d4a3fce4d329711209c316247f06b_MD5.jpg]]

Students will find that the j0seph user accessed the document titled `insurance.DOCX`.

Answer: `insurance.DOCX`