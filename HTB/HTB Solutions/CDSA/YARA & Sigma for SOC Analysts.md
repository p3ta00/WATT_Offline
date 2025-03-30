| Section                                    | Question Number | Answer                                                      |
| ------------------------------------------ | --------------- | ----------------------------------------------------------- |
| Developing YARA Rules                      | Question 1      | TSMSISrv.dll                                                |
| Hunting Evil with YARA (Windows Edition)   | Question 1      | 53616E64626F78206465746563746564                            |
| Hunting Evil with YARA (Linux Edition)     | Question 1      | @WanaDecryptor@                                             |
| Developing Sigma Rules                     | Question 1      | mimidrv.sys                                                 |
| Hunting Evil with Sigma (Chainsaw Edition) | Question 1      | c:\\document\\virus\                                        |
| Hunting Evil with Sigma (Splunk Edition)   | Question 1      | C:\\Users\\waldo\\Downloads\\20221108112718\_BloodHound.zip |
| Skills Assessment                          | Question 1      | LsaWrapper                                                  |
| Skills Assessment                          | Question 2      | faaeba08-01f0-4a32-ba48-bd65b24afd28                        |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Developing YARA Rules

## Question 1

### "Perform string analysis on the "DirectX.dll" sample that resides in the "/home/htb-student/Samples/YARASigma" directory of this section's target. Then, study the "apt\_apt17\_mal\_sep17\_1.yar" YARA rule that resides in the "/home/htb-student/Rules/yara" directory and replace "X.dll" with the correct DLL name to ensure the rule will identify "DirectX.dll". Enter the correct DLL name as your answer. Answer format: \_.dll"

Students need to first connect to the spawned target with SSH, using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[us-academy-1]─[10.10.15.211]─[htb-ac-594497@htb-aguiwowdat]─[~]
└──╼ [★]$ ssh htb-student@10.129.139.240

The authenticity of host '10.129.139.240 (10.129.139.240)' can't be established.
ECDSA key fingerprint is SHA256:0loReoHRiJTAMnDSjRnm+AKJqFgmSa3nrD7TT8SC/qI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.139.240' (ECDSA) to the list of known hosts.
htb-student@10.129.139.240's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-122-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Fri Sep  1 08:13:50 2023 from 10.10.14.23

htb-student@remnux:~$
```

Then, students need to perform a strings analysis of the `DirectX.dll` sample, filtering for any instances of `dll`:

Code: shell

```shell
strings /home/htb-student/Samples/YARASigma/DirectX.dll | grep dll
```

```
htb-student@remnux:~$ strings /home/htb-student/Samples/YARASigma/DirectX.dll | grep dll

KERNEL32.dll
ADVAPI32.dll
MSVCRT.dll
kernel32.dll
\msvcrt.dll
\spool\prtprocs\w32x86\localspl.dll
\spool\prtprocs\x64\localspl.dll
\TSMSISrv.dll
```

Students need to compare this with what is defined in the `apt_apt17_mal_sep17_1.yar` rule:

Code: shell

```shell
cat Rules/yara/apt_apt17_mal_sep17_1.yar | grep dll
```

```
htb-student@remnux:~$ cat Rules/yara/apt_apt17_mal_sep17_1.yar | grep dll

      $s1 = "\\spool\\prtprocs\\w32x86\\localspl.dll" ascii
      $s2 = "\\spool\\prtprocs\\x64\\localspl.dll" ascii
      $s3 = "\\msvcrt.dll" ascii
      $s4 = "\\X.dll" ascii
```

Students will determine that the correct replacement for `X.dll` is `TSMSISrv.dll`.

Answer: `TSMSISrv.dll`

# Hunting Evil with YARA (Windows Edition)

## Question 1

### "Study the "C:\\Rules\\yara\\shell\_detector.yar" YARA rule that aims to detect "C:\\Samples\\MalwareAnalysis\\shell.exe" inside process memory. Then, specify the appropriate hex values inside the "$sandbox" variable to ensure that the "Sandbox detected" message will also be detected. Enter the correct hex values as your answer. Answer format: Remove any spaces"

Students need to connect to the spawned target using RDP, with the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:HTB_@cademy_stdnt! /dynamic-resolution 
```

```
┌─[us-academy-1]─[10.10.15.211]─[htb-ac-594497@htb-tkdis5pjc7]─[~]
└──╼ [★]$ xfreerdp /v:10.129.200.166 /u:htb-student /p:HTB_@cademy_stdnt! /dynamic-resolution 

[00:15:13:569] [4038:4039] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[00:15:13:569] [4038:4039] [WARN][com.freerdp.crypto] - CN = DESKTOP-VJF8GH8
[00:15:13:569] [4038:4039] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:15:13:569] [4038:4039] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[00:15:13:569] [4038:4039] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
<SNIP>
```

Students need to first launch `HxD`, then open the `shell.exe` malware sample inside the hex editor:

![[HTB Solutions/CDSA/z. images/dd09c93eee8121dad5d67b67d4dbc1a5_MD5.jpg]]

Next, students need to select `Search` -> `Find` , then enter "sandbox detected" as the text-string to search for:

![[HTB Solutions/CDSA/z. images/5fd965b56b2af206d65fd15e04840150_MD5.jpg]]

The string is found, and it's corresponding bytes will be displayed in the hex editor:

![[HTB Solutions/CDSA/z. images/1bb6a791492c25a278978b0bae560175_MD5.jpg]]

Here, students will determine that the hex values to add to the rule are `53616E64626F78206465746563746564`. Subsequently, the adjusted `shell_detector.yar` rule will appear as follows:

```
rule shell_detected
{
	meta:
		description		= "Detect Domain & Sandbox Message In Process Memory"
		author			= "Dimitrios Bougioukas"

	strings:
		$domain		= { 69 75 71 65 72 66 73 6f 64 70 39 69 66 6a 61 70 6f 73 64 66 6a 68 67 6f 73 75 72 69 6a 66 61 65 77 72 77 65 72 67 77 65 61 2e 63 6f 6d }
		$sandbox	= { 53 61 6E 64 62 6F 78 20 64 65 74 65 63 74 65 64 }
	condition:
		$domain and $sandbox
}
```

Finally, students need test the rule by opening the `shell.exe` malware sample, then launching a privileged powershell session and running the following command:

Code: powershell

```powershell
Get-Process | ForEach-Object { "Scanning with Yara for shell on PID "+$_.id; & "yara64.exe" "C:\Rules\yara\shell_detector.yar" $_.id }
```

```
PS C:\Windows\system32> Get-Process | ForEach-Object { "Scanning with Yara for shell on PID "+$_.id; & "yara64.exe" "C:\Rules\yara\shell_detector.yar" $_.id }
Scanning with Yara for shell on PID 1608
Scanning with Yara for shell on PID 3352
Scanning with Yara for shell on PID 632
<SNIP>
error scanning 632: can not attach to process (try running as root)
Scanning with Yara for shell on PID 8428
error scanning 8428: can not attach to process (try running as root)
Scanning with Yara for shell on PID 6368
shell_detected 6368
```

Confirming the functionality of the YARA rule, students need to submit the previously identified hex values as the answer.

Answer: `53616E64626F78206465746563746564`

# Hunting Evil with YARA (Linux Edition)

## Question 1

### "Study the following resource https://blogs.vmware.com/security/2022/09/threat-report-illuminating-volume-shadow-deletion.html to learn how WannaCry performs shadow volume deletion. Then, use yarascan when analyzing "/home/htb-student/MemoryDumps/compromised\_system.raw" to identify the process responsible for deleting shadows. Enter the name of the process as your answer."

Students need to first examine the provided [article](https://blogs.vmware.com/security/2022/09/threat-report-illuminating-volume-shadow-deletion.html) to learn about Volume Shadow Deletion:

![[HTB Solutions/CDSA/z. images/2733144663b1b64c43258d97916f083d_MD5.jpg]]

Students will find evidence that `Wana Decrypt0r 2.0` , an ancestor of `WannaCry`, utilizes `vssadmin` and `wmic shadowcopy` to delete shadows.

Subsequently, students need to connect to the spawned target with SSH, providing the credentials `htb-student:HTB_@cademy_stdnt!`

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[us-academy-1]─[10.10.15.211]─[htb-ac-594497@htb-djk8ewclxp]─[~]
└──╼ [★]$ ssh htb-student@10.129.139.240

The authenticity of host '10.129.139.240 (10.129.139.240)' can't be established.
ECDSA key fingerprint is SHA256:0loReoHRiJTAMnDSjRnm+AKJqFgmSa3nrD7TT8SC/qI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.139.240' (ECDSA) to the list of known hosts.
htb-student@10.129.139.240's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-122-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Fri Sep  1 08:13:50 2023 from 10.10.14.23

htb-student@remnux:~$ 
```

Once connected to the target machine, students need to use `Volatility` with the `yarascan` plugin to examine the memory dump of the compromised machine, choosing `vssadmin` as the search pattern:

Code: shell

```shell
vol.py -f /home/htb-student/MemoryDumps/compromised_system.raw yarascan -U "vssadmin"
```

```
htb-student@remnux:~$ vol.py -f /home/htb-student/MemoryDumps/compromised_system.raw yarascan -U "vssadmin"

Volatility Foundation Volatility Framework 2.6.1
/usr/local/lib/python2.7/dist-packages/volatility/plugins/community/YingLi/ssh_agent_key.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
  from cryptography.hazmat.backends.openssl import backend
Rule: r1
Owner: Process @WanaDecryptor@ Pid 3200
0x00420fdb  76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20   vssadmin.delete.
0x00420feb  73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75   shadows./all./qu
0x00420ffb  69 65 74 20 26 20 77 6d 69 63 20 73 68 61 64 6f   iet.&.wmic.shado
0x0042100b  77 63 6f 70 79 20 64 65 6c 65 74 65 20 26 20 62   wcopy.delete.&.b
0x0042101b  63 64 65 64 69 74 20 2f 73 65 74 20 7b 64 65 66   cdedit./set.{def
0x0042102b  61 75 6c 74 7d 20 62 6f 6f 74 73 74 61 74 75 73   ault}.bootstatus
0x0042103b  70 6f 6c 69 63 79 20 69 67 6e 6f 72 65 61 6c 6c   policy.ignoreall
0x0042104b  66 61 69 6c 75 72 65 73 20 26 20 62 63 64 65 64   failures.&.bcded
0x0042105b  69 74 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74   it./set.{default
0x0042106b  7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65   }.recoveryenable
0x0042107b  64 20 6e 6f 20 26 20 77 62 61 64 6d 69 6e 20 64   d.no.&.wbadmin.d
0x0042108b  65 6c 65 74 65 20 63 61 74 61 6c 6f 67 20 2d 71   elete.catalog.-q
0x0042109b  75 69 65 74 00 76 73 00 00 63 6f 00 00 66 69 00   uiet.vs..co..fi.
0x004210ab  00 31 33 41 4d 34 56 57 32 64 68 78 59 67 58 65   .13AM4VW2dhxYgXe
0x004210bb  51 65 70 6f 48 6b 48 53 51 75 79 36 4e 67 61 45   QepoHkHSQuy6NgaE
0x004210cb  62 39 34 00 00 45 6e 67 6c 69 73 68 00 6d 5f 25   b94..English.m_%
Rule: r1
Owner: Process @WanaDecryptor@ Pid 3100
0x00420fdb  76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20   vssadmin.delete.
0x00420feb  73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75   shadows./all./qu
0x00420ffb  69 65 74 20 26 20 77 6d 69 63 20 73 68 61 64 6f   iet.&.wmic.shado
0x0042100b  77 63 6f 70 79 20 64 65 6c 65 74 65 20 26 20 62   wcopy.delete.&.b
0x0042101b  63 64 65 64 69 74 20 2f 73 65 74 20 7b 64 65 66   cdedit./set.{def
0x0042102b  61 75 6c 74 7d 20 62 6f 6f 74 73 74 61 74 75 73   ault}.bootstatus
0x0042103b  70 6f 6c 69 63 79 20 69 67 6e 6f 72 65 61 6c 6c   policy.ignoreall
0x0042104b  66 61 69 6c 75 72 65 73 20 26 20 62 63 64 65 64   failures.&.bcded
0x0042105b  69 74 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74   it./set.{default
0x0042106b  7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65   }.recoveryenable
0x0042107b  64 20 6e 6f 20 26 20 77 62 61 64 6d 69 6e 20 64   d.no.&.wbadmin.d
0x0042108b  65 6c 65 74 65 20 63 61 74 61 6c 6f 67 20 2d 71   elete.catalog.-q
0x0042109b  75 69 65 74 00 76 73 00 00 63 6f 00 00 66 69 00   uiet.vs..co..fi.
0x004210ab  00 31 33 41 4d 34 56 57 32 64 68 78 59 67 58 65   .13AM4VW2dhxYgXe
0x004210bb  51 65 70 6f 48 6b 48 53 51 75 79 36 4e 67 61 45   QepoHkHSQuy6NgaE
0x004210cb  62 39 34 00 00 45 6e 67 6c 69 73 68 00 6d 5f 25   b94..English.m_%=
```

The process name is revealed to be `@WanaDecryptor@`.

Answer: `@WanaDecryptor@`

# Developing Sigma Rules

## Question 1

### "Using sigmac translate the "C:\\Tools\\chainsaw\\sigma\\rules\\windows\\builtin\\windefend\\win\_defender\_threat.yml" Sigma rule into the equivalent PowerShell command. Then, execute the PowerShell command against "C:\\Events\\YARASigma\\lab\_events\_4.evtx" and enter the malicious driver as your answer. Answer format: \_.sys"

Students need to connect to the spawned target using RDP, with the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:HTB_@cademy_stdnt! /dynamic-resolution 
```

```
┌─[us-academy-1]─[10.10.15.211]─[htb-ac-594497@htb-fhxoopfsdm]─[~]
└──╼ [★]$ xfreerdp /v:10.129.228.137 /u:htb-student /p:HTB_@cademy_stdnt! /dynamic-resolution 

[17:41:18:582] [2644:2645] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-594497/.config/freerdp
[17:41:18:582] [2644:2645] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-594497/.config/freerdp/certs]
[17:41:18:582] [2644:2645] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-594497/.config/freerdp/server]
[17:41:18:593] [2644:2645] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
<SNIP>
```

Then, students need to open powershell and use `sigmac` to translate the aforementioned Sigma rule into the equivalent powershell command:

Code: powershell

```powershell
cd C:\Tools\sigma-0.21\tools
python sigmac -t powershell C:\Tools\chainsaw\sigma\rules\windows\builtin\windefend\win_defender_threat.yml
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Users\htb-student> cd C:\Tools\sigma-0.21\tools
PS C:\Tools\sigma-0.21\tools> python sigmac -t powershell C:\Tools\chainsaw\sigma\rules\windows\builtin\windefend\win_defender_threat.yml

Get-WinEvent | where {($_.ID -eq "1006" -or $_.ID -eq "1116" -or $_.ID -eq "1015" -or $_.ID -eq "1117") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```

Students need to run the generated powershell command against the `lab_events_4.evtx` log file:

Code: powershell

```powershell
Get-WinEvent -Path 'C:\Events\YARASigma\lab_events_4.evtx' | where {($_.ID -eq "1006" -or $_.ID -eq "1116" -or $_.ID -eq "1015" -or $_.ID -eq "1117") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```

```
PS C:\Tools\sigma-0.21\tools> Get-WinEvent -Path 'C:\Events\YARASigma\lab_events_4.evtx' | where {($_.ID -eq "1006" -or $_.ID -eq "1116" -or $_.ID -eq "1015" -or $_.ID -eq "1117") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

TimeCreated : 12/11/2020 4:28:44 AM
Id          : 1116
RecordId    : 177
ProcessId   : 4172
MachineName : WIN10-client01.offsec.lan
Message     : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
               For more information please see the following:
              1
                Name: High
                ID: 4
                Severity: Tool
                Category: 1
                Path: Suspended
                Detection Origin: Concrete
                Detection Type: 0x00000000
                Detection Source: file:_C:\Users\admmig\Documents\mimikatz.exe
                User: Local machine
                Process Name: 1
                Security intelligence Version: %41
                Engine Version: %42
<SNIP>
TimeCreated : 12/11/2020 4:28:01 AM
Id          : 1116
RecordId    : 171
ProcessId   : 4172
MachineName : WIN10-client01.offsec.lan
Message     : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
               For more information please see the following:
              1
                Name: High
                ID: 4
                Severity: Tool
                Category: 1
                Path: Suspended
                Detection Origin: Concrete
                Detection Type: 0x00000000
                Detection Source: file:_C:\Users\admmig\Documents\mimidrv.sys
                User: Local machine
                Process Name: 1
                Security intelligence Version: %41
                Engine Version: %42
```

From the output, students will identify `mimidrv.sys` as the malicious driver.

Answer: `mimidrv.sys`

# Hunting Evil with Sigma (Chainsaw Edition)

## Question 1

### "Use Chainsaw with the "C:\\Tools\\chainsaw\\sigma\\rules\\windows\\powershell\\powershell\_script\\posh\_ps\_win\_defender\_exclusions\_added.yml" Sigma rule to hunt for suspicious Defender exclusions inside "C:\\Events\\YARASigma\\lab\_events\_5.evtx". Enter the excluded directory as your answer."

Students need to connect to the spawned target using RDP, with the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:HTB_@cademy_stdnt! /dynamic-resolution 
```

```
┌─[us-academy-1]─[10.10.15.211]─[htb-ac-594497@htb-fhxoopfsdm]─[~]
└──╼ [★]$ xfreerdp /v:10.129.228.137 /u:htb-student /p:HTB_@cademy_stdnt! /dynamic-resolution 

[17:41:18:582] [2644:2645] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-594497/.config/freerdp
[17:41:18:582] [2644:2645] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-594497/.config/freerdp/certs]
[17:41:18:582] [2644:2645] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-594497/.config/freerdp/server]
[17:41:18:593] [2644:2645] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
<SNIP>
```

Then, students need to open powershell and use chainsaw with the `posh_ps_win_defender_exclusions_added.yml` rule to hunt for suspicious Defender exclusions within the `lab_events_5.evtx` log file:

Code: powershell

```powershell
cd C:\Tools\chainsaw\
.\chainsaw_x86_64-pc-windows-msvc.exe hunt C:\Events\YARASigma\lab_events_5.evtx -s C:\Tools\chainsaw\sigma\rules\windows\powershell\powershell_script\posh_ps_win_defender_exclusions_added.yml --mapping .\mappings\sigma-event-logs-all.yml
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Users\htb-student> cd C:\Tools\chainsaw\
PS C:\Tools\chainsaw> .\chainsaw_x86_64-pc-windows-msvc.exe hunt C:\Events\YARASigma\lab_events_5.evtx -s C:\Tools\chainsaw\sigma\rules\windows\powershell\powershell_script\posh_ps_win_defender_exclusions_added.yml --mapping .\mappings\sigma-event-logs-all.yml

 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
    By Countercept (@FranticTyping, @AlexKornitzer)

[+] Loading detection rules from: C:\Tools\chainsaw\sigma\rules\windows\powershell\powershell_script\posh_ps_win_defender_exclusions_added.yml
[+] Loaded 1 detection rules
[+] Loading forensic artefacts from: C:\Events\YARASigma\lab_events_5.evtx (extensions: .evt, .evtx)
[+] Loaded 1 forensic artefacts (1.1 MB)
[+] Hunting: [========================================] 1/1 -
[+] Group: Sigma
┌─────────────────────┬───────────────────────────────┬───────┬───────────────────────┬──────────┬───────────┬─────────────────────┬──────────────────────┐
│      timestamp      │          detections           │ count │ Event.System.Provider │ Event ID │ Record ID │      Computer       │      Event Data      │
├─────────────────────┼───────────────────────────────┼───────┼───────────────────────┼──────────┼───────────┼─────────────────────┼──────────────────────┤
│ 2021-10-06 11:14:56 │ + Windows Defender Exclusions │ 1     │ Microsoft-Windows-Po  │ 4104     │ 1329309   │ win10-02.offsec.lan │ MessageNumber: 1     │
│                     │ Added - PowerShell            │       │ werShell              │          │           │                     │ MessageTotal: 1      │
│                     │                               │       │                       │          │           │                     │ Path: ''             │
│                     │                               │       │                       │          │           │                     │ ScriptBlockId: f5f4c │
│                     │                               │       │                       │          │           │                     │ 079-094d-4248-acbb-b │
│                     │                               │       │                       │          │           │                     │ d8bb5746c99          │
│                     │                               │       │                       │          │           │                     │ ScriptBlockText: Set │
│                     │                               │       │                       │          │           │                     │ -MpPreference -Exclu │
│                     │                               │       │                       │          │           │                     │ sionPath c:\document │
│                     │                               │       │                       │          │           │                     │ \virus\              │
├─────────────────────┼───────────────────────────────┼───────┼───────────────────────┼──────────┼───────────┼─────────────────────┼──────────────────────┤
│ 2021-10-06 11:15:06 │ + Windows Defender Exclusions │ 1     │ Microsoft-Windows-Po  │ 4104     │ 1329315   │ win10-02.offsec.lan │ MessageNumber: 1     │
│                     │ Added - PowerShell            │       │ werShell              │          │           │                     │ MessageTotal: 1      │
│                     │                               │       │                       │          │           │                     │ Path: ''             │
│                     │                               │       │                       │          │           │                     │ ScriptBlockId: a89a7 │
│                     │                               │       │                       │          │           │                     │ f18-a97c-4272-b7d2-6 │
│                     │                               │       │                       │          │           │                     │ 81769defe7c          │
│                     │                               │       │                       │          │           │                     │ ScriptBlockText: Set │
│                     │                               │       │                       │          │           │                     │ -MpPreference -Exclu │
│                     │                               │       │                       │          │           │                     │ sionExtension '.exe' │
└─────────────────────┴───────────────────────────────┴───────┴───────────────────────┴──────────┴───────────┴─────────────────────┴──────────────────────┘

[+] 2 Detections found on 2 documents
```

From the output, students will find `C:\document\virus\` as the excluded directory.

Answer: `C:\document\virus\`

# Hunting Evil with Sigma (Splunk Edition)

## Question 1

### Using sigmac translate the "C:\\Rules\\sigma\\file\_event\_win\_app\_dropping\_archive.yml" Sigma rule into the equivalent Splunk search. Then, navigate to http://\[Target IP\]:8000, open the "Search & Reporting" application, and submit the Splunk search sigmac provided. Enter the TargetFilename value of the returned event as your answer.

Using the target machine from the previous section, students need to open powershell and navigate to `C:\Tools\sigma-0.21\tools`. Then, students need to use `sigmac` to translate the `file_event_win_app_dropping_archive.yml` Sigma rule into its equivalent Splunk search:

```powershell
cd C:\Tools\sigma-0.21\tools\
python sigmac -t splunk C:\Rules\sigma\file_event_win_app_dropping_archive.yml --config .\config\splunk-windows.yml
```
```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Users\htb-student> cd C:\Tools\sigma-0.21\tools\
PS C:\Tools\sigma-0.21\tools> python sigmac -t splunk C:\Rules\sigma\file_event_win_app_dropping_archive.yml --config .\config\splunk-windows.yml

((Image="*\\winword.exe" OR Image="*\\excel.exe" OR Image="*\\powerpnt.exe" OR Image="*\\msaccess.exe" OR Image="*\\mspub.exe" OR Image="*\\eqnedt32.exe" OR Image="*\\visio.exe" OR Image="*\\wordpad.exe" OR Image="*\\wordview.exe" OR Image="*\\certutil.exe" OR Image="*\\certoc.exe" OR Image="*\\CertReq.exe" OR Image="*\\Desktopimgdownldr.exe" OR Image="*\\esentutl.exe" OR Image="*\\finger.exe" OR Image="*\\notepad.exe" OR Image="*\\AcroRd32.exe" OR Image="*\\RdrCEF.exe" OR Image="*\\mshta.exe" OR Image="*\\hh.exe" OR Image="*\\sharphound.exe") (TargetFilename="*.zip" OR TargetFilename="*.rar" OR TargetFilename="*.7z" OR TargetFilename="*.diagcab" OR TargetFilename="*.appx"))
```

Students need to save this query, then move on to spawning the target machine for the current section. Once the target has spawned, students need to browse to `http://STMIP:8000` to access the Splunk dashboard:

![[HTB Solutions/CDSA/z. images/7575b66e1345ed588dbcebfe927f11c3_MD5.webp]]

From the dashboard, students need to select `Search & Reporting`. Subsequently, students need to set the time range picker to `All time`:

![[HTB Solutions/CDSA/z. images/a64aff12fdfd1e53b37789cc963c41e8_MD5.webp]]

Now, students need to enter the previously generated Splunk query into the search bar:

```
((Image="*\\winword.exe" OR Image="*\\excel.exe" OR Image="*\\powerpnt.exe" OR Image="*\\msaccess.exe" OR Image="*\\mspub.exe" OR Image="*\\eqnedt32.exe" OR Image="*\\visio.exe" OR Image="*\\wordpad.exe" OR Image="*\\wordview.exe" OR Image="*\\certutil.exe" OR Image="*\\certoc.exe" OR Image="*\\CertReq.exe" OR Image="*\\Desktopimgdownldr.exe" OR Image="*\\esentutl.exe" OR Image="*\\finger.exe" OR Image="*\\notepad.exe" OR Image="*\\AcroRd32.exe" OR Image="*\\RdrCEF.exe" OR Image="*\\mshta.exe" OR Image="*\\hh.exe" OR Image="*\\sharphound.exe") (TargetFilename="*.zip" OR TargetFilename="*.rar" OR TargetFilename="*.7z" OR TargetFilename="*.diagcab" OR TargetFilename="*.appx"))
```

![[HTB Solutions/CDSA/z. images/1cad28926bce9548907049029e15ac17_MD5.webp]]

The query returns a single event, which students need to inspect further:

![[HTB Solutions/CDSA/z. images/2bfa87ad74d45fd1515e60bd4316f8a4_MD5.webp]]

Students will see that the TargetFileName value is set to `C:\Users\waldo\Downloads\20221108112718_BloodHound.zip`.

Answer: `C:\Users\waldo\Downloads\20221108112718_BloodHound.zip`

# Skills Assessment

## Question 1

### "The "C:\\Rules\\yara\\seatbelt.yar" YARA rule aims to detect instances of the "Seatbelt.exe" .NET assembly on disk. Analyze both "C:\\Rules\\yara\\seatbelt.yar" and "C:\\Samples\\YARASigma\\Seatbelt.exe" and specify the appropriate string inside the "$class2" variable so that the rule successfully identifies "C:\\Samples\\YARASigma\\Seatbelt.exe". Answer format: L\_\_\_\_\_\_\_\_r"

Students need to connect to the spawned target using RDP, with the credentials `htb-student:HTB_@cademy_stdnt!`:

```shell
xfreerdp /v:STMIP /u:htb-student /p:HTB_@cademy_stdnt! /dynamic-resolution 
```
```
┌─[us-academy-1]─[10.10.15.211]─[htb-ac-594497@htb-usrdo4uax1]─[~]
└──╼ [★]$ xfreerdp /v:10.129.228.137 /u:htb-student /p:HTB_@cademy_stdnt! /dynamic-resolution 

[21:20:15:536] [2597:2598] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[21:20:15:536] [2597:2598] [WARN][com.freerdp.crypto] - CN = DESKTOP-VJF8GH8
[21:20:15:536] [2597:2598] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[21:20:15:536] [2597:2598] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[21:20:15:536] [2597:2598] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[21:20:15:536] [2597:2598] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.228.137:3389) 
[21:20:15:536] [2597:2598] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[21:20:15:536] [2597:2598] [ERROR][com.freerdp.crypto] - Common Name (CN):
[21:20:15:536] [2597:2598] [ERROR][com.freerdp.crypto] - 	DESKTOP-VJF8GH8
[21:20:15:536] [2597:2598] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
```

Once connected, students need use the windows search bar to open `dnSpy`:

![[HTB Solutions/CDSA/z. images/2c5c35d6074d04cd1d7017047f53233e_MD5.webp]]

![[HTB Solutions/CDSA/z. images/4ba50ef619cc2098f61c969203bdc7f1_MD5.webp]]

From within `dnSpy`, students need to click `File` -> `Open` and select the `Seatbelt.exe` file. Then, they need to drill into the `Seatbelt.Util` namespace and examine the classes:

![[HTB Solutions/CDSA/z. images/61b7765bcc40dea7df2df3652f0bfdbf_MD5.webp]]

Students need to compare these classes with what is listed in the `seatbelt.yar` rule:

```
rule seatbelt_detected {
 meta:
   description = "Rule for detecting Seatbelt"
   author = "Dimitrios Bougioukas"
 strings:
   $class1 = "WMIUtil"
   $class2 = ""
   $class3 = "SecurityUtil"
   $class4 = "MiscUtil"
   $dotnetMagic = "BSJB" ascii
 condition:
   (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and $dotnetMagic and 4 of them
}
```

Given the answer format stated in the challenge question, students will know that the appropriate string to place inside the `$class2` variable is `LsaWrapper` (which was revealed as one of the classes via dnSpy).

Therefore, students need to open the `seatbelt.yar` file with `notepad++` and make the appropriate change:

```
rule seatbelt_detected {
 meta:
   description = "Rule for detecting Seatbelt"
   author = "Dimitrios Bougioukas"
 strings:
   $class1 = "WMIUtil"
   $class2 = "LsaWrapper"
   $class3 = "SecurityUtil"
   $class4 = "MiscUtil"
   $dotnetMagic = "BSJB" ascii
 condition:
   (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and $dotnetMagic and 4 of them
}
```

![[HTB Solutions/CDSA/z. images/c9b94a4f49f78fddea08e280d674d9c6_MD5.webp]]

Saving the changes, students need to open powershell, navigate to `C:\Rules\yara`, and then test the rule against the `C:\Samples\YARASigma\` directory:

```powershell
cd C:\Rules\yara
yara64.exe .\seatbelt.yar C:\Samples\YARASigma\
```
```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Users\htb-student> cd C:\Rules\yara\
PS C:\Rules\yara> yara64.exe .\seatbelt.yar C:\Samples\YARASigma\

seatbelt_detected C:\Samples\YARASigma\\Seatbelt.exe
```

Students will confirm the rule works as intended, due to the `LsaWrapper` class being added.

Answer: `LsaWrapper`

# Skills Assessment

## Question 2

### "Use Chainsaw with the "C:\\Tools\\chainsaw\\sigma\\rules\\windows\\powershell\\powershell\_script\\posh\_ps\_susp\_win32\_shadowcopy.yml" Sigma rule to hunt for shadow volume deletion inside "C:\\Events\\YARASigma\\lab\_events\_6.evtx". Enter the identified ScriptBlock ID as your answer."

From the previously established RDP session, students need to open powershell and navigate to `C:\tools\chainsaw`:

```powershell
cd C:\Tools\chainsaw\
```
```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Users\htb-student> cd C:\Tools\chainsaw\
PS C:\Tools\chainsaw>
```

Then, students need to use chainsaw with the `posh_ps_susp_win32_shadowcopy.yml` Sigma rule against the `lab_events_6.evtx` log file:

```powershell
.\chainsaw_x86_64-pc-windows-msvc.exe hunt C:\Events\YARASigma\lab_events_6.evtx -s C:\Tools\chainsaw\sigma\rules\windows\powershell\powershell_script\posh_ps_susp_win32_shadowcopy.yml --mapping .\mappings\sigma-event-logs-all.yml
```
```
PS C:\Tools\chainsaw> .\chainsaw_x86_64-pc-windows-msvc.exe hunt C:\Events\YARASigma\lab_events_6.evtx -s C:\Tools\chainsaw\sigma\rules\windows\powershell\powershell_script\posh_ps_susp_win32_shadowcopy.yml --mapping .\mappings\sigma-event-logs-all.yml

 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
    By Countercept (@FranticTyping, @AlexKornitzer)

[+] Loading detection rules from: C:\Tools\chainsaw\sigma\rules\windows\powershell\powershell_script\posh_ps_susp_win32_shadowcopy.yml
[+] Loaded 1 detection rules
[+] Loading forensic artefacts from: C:\Events\YARASigma\lab_events_6.evtx (extensions: .evt, .evtx)
[+] Loaded 1 forensic artefacts (69.6 KB)
[+] Hunting: [========================================] 1/1 -
[+] Group: Sigma
┌─────────────────────┬────────────────────────────────┬───────┬───────────────────────┬──────────┬───────────┬─────────────────┬──────────────────────┐
│      timestamp      │           detections           │ count │ Event.System.Provider │ Event ID │ Record ID │    Computer     │      Event Data      │
├─────────────────────┼────────────────────────────────┼───────┼───────────────────────┼──────────┼───────────┼─────────────────┼──────────────────────┤
│ 2021-12-19 15:13:49 │ + Delete Volume Shadow         │ 1     │ Microsoft-Windows-Po  │ 4104     │ 153158    │ FS03.offsec.lan │ MessageNumber: 1     │
│                     │ Copies via WMI with PowerShell │       │ werShell              │          │           │                 │ MessageTotal: 1      │
│                     │ - PS Script                    │       │                       │          │           │                 │ ScriptBlockId: faaeb │
│                     │                                │       │                       │          │           │                 │ a08-01f0-4a32-ba48-b │
│                     │                                │       │                       │          │           │                 │ d65b24afd28          │
│                     │                                │       │                       │          │           │                 │ ScriptBlockText: Get │
│                     │                                │       │                       │          │           │                 │ -WmiObject Win32_Sha │
│                     │                                │       │                       │          │           │                 │ dowcopy | ForEach-Ob │
│                     │                                │       │                       │          │           │                 │ ject {$_.Delete();}  │
└─────────────────────┴────────────────────────────────┴───────┴───────────────────────┴──────────┴───────────┴─────────────────┴──────────────────────┘

[+] 1 Detections found on 1 documents
```

Students will see find the ScriptBlock ID of `faaeba08-01f0-4a32-ba48-bd65b24afd28` in the event data.

Answer: `faaeba08-01f0-4a32-ba48-bd65b24afd28`