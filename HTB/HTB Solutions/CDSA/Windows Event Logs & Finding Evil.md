| Section | Question Number | Answer |
| --- | --- | --- |
| Windows Event Logs | Question 1 | TiWorker.exe |
| Windows Event Logs | Question 2 | 10:23:50 |
| Analyzing Evil With Sysmon & Event Logs | Question 1 | 51F2305DCF385056C68F7CCF5B1B3B9304865CEF1257947D4AD6EF5FAD2E3B13 |
| Analyzing Evil With Sysmon & Event Logs | Question 2 | 8A3CD3CF2249E9971806B15C75A892E6A44CCA5FF5EA5CA89FDA951CD2C09AA9 |
| Analyzing Evil With Sysmon & Event Logs | Question 3 | 5e4ffd54b3849aa720ed39f50185e533 |
| Tapping Into ETW | Question 1 | GetTokenInformation |
| Get-WinEvent | Question 1 | 12:30:30 |
| Skills Assessment | Question 1 | Dism.exe |
| Skills Assessment | Question 2 | Calculator.exe |
| Skills Assessment | Question 3 | rundll32.exe |
| Skills Assessment | Question 4 | ProcessHacker.exe |
| Skills Assessment | Question 5 | No |
| Skills Assessment | Question 6 | WerFault.exe |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Windows Event Logs

## Question 1

### "Analyze the event with ID 4624, that took place on 8/3/2022 at 10:23:25. Conduct a similar investigation as outlined in this section and provide the name of the executable responsible for the modification of the auditing settings as your answer. Answer format: T\_W\_\_\_\_\_.exe"

Students need to connect to the spawned target using RDP:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'HTB_@cad3my_lab_W1n10_r00t!@0' /dynamic-resolution
```

```shell
┌─[us-academy-1]─[10.10.14.223]─[htb-ac-594497@htb-op1rwqzkzh]─[~]
└──╼ [★]$ xfreerdp /v:10.129.205.123 /u:Administrator /p:'HTB_@cad3my_lab_W1n10_r00t!@0' /dynamic-resolution 

[17:33:50:105] [5458:5459] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-594497/.config/freerdp
[17:33:50:106] [5458:5459] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-594497/.config/freerdp/certs]
[17:33:50:106] [5458:5459] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-594497/.config/freerdp/server]
[17:33:50:134] [5458:5459] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
<SNIP>
```

Then, students need launch Event Viewer:

![[HTB Solutions/CDSA/z. images/3c46c67796cec3beb657d2207799faf5_MD5.jpg]]

Students need to choose `Security` logs, and then right-click to `Filter Current Log`:

![[HTB Solutions/CDSA/z. images/fd2d81c27f5a50b5989ac526a31648af_MD5.jpg]]

Filtering for Event ID 4624:

![[HTB Solutions/CDSA/z. images/b772103ac11e124fe158bfba990fc8fa_MD5.jpg]]

With the filter applied, students need to look for the event that took place on 8/3/2022 at 10:23:25:

![[HTB Solutions/CDSA/z. images/0cb82d65bf95c9704dacdd058aa4e1bf_MD5.jpg]]

Identifying the SubjectLogonID of 0x3e7, students need to filter the logs again, this time using a custom XML query to look for Event ID 4907 AND the discovered SubjectLogonID:

```shell
\`<QueryList>   <Query Id="0" Path="Security">     <Select Path="Security">*[System[EventID=4907] and EventData[Data[@Name='SubjectLogonID']='0x3E7']]     </Select>   </Query> </QueryList>\`
```

![[HTB Solutions/CDSA/z. images/fab47625b4f65d9dd24a2cd0998ccbff_MD5.jpg]]

Finally, students need to look at the event on 8/30/2022 10:23:49 AM:

![[HTB Solutions/CDSA/z. images/ad39ab6ba2993d36f037beeaf2660cb2_MD5.jpg]]

There, it is revealed that the process responsible for modifying the auditing settings is `TiWorker.exe`.

Answer: `TiWorker.exe`

# Windows Event Logs

## Question 2

### "Build an XML query to determine if the previously mentioned executable modified the auditing settings of C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\WPF\\wpfgfx\_v0400.dll. Enter the time of the identified event in the format HH:MM:SS as your answer."

Students need to apply the following XML query:

```shell
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
*[EventData[Data[@Name='ProcessName']='C:\Windows\WinSxS\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.19041.1790_none_7df2aec07ca10e81\TiWorker.exe']] and *[EventData[Data[@Name='ObjectName']='C:\Windows\Microsoft.NET\Framework64\v4.0.30319\WPF\wpfgfx_v0400.dll']]
</Select>
  </Query>
</QueryList>
```

Utilizing both the ProcessName and ObjectName fields, the logs are narrowed down to a single event:

![[HTB Solutions/CDSA/z. images/a4d2c839fbb2189ff2719ce0ff8ba5ad_MD5.jpg]]

Students will see the time the event occurred at `10:23:50`, confirming that `TiWorker.exe` modified the audit settings of `wpfgfx_v0400.dll`.

Answer: `10:23:50`

# Analyzing Evil With Sysmon & Event Logs

## Question 1

### "Replicate the DLL hijacking attack described in this section and provide the SHA256 hash of the malicious WININET.dll as your answer. "C:\\Tools\\Sysmon" and "C:\\Tools\\Reflective DLLInjection" on the spawned target contain everything you need."

Students need to connect to the spawned target using RDP:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'HTB_@cad3my_lab_W1n10_r00t!@0' /dynamic-resolution
```

```shell
┌─[us-academy-1]─[10.10.14.223]─[htb-ac-594497@htb-op1rwqzkzh]─[~]
└──╼ [★]$ xfreerdp /v:10.129.205.123 /u:Administrator /p:'HTB_@cad3my_lab_W1n10_r00t!@0' /dynamic-resolution 

[18:40:08:161] [6977:6978] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[18:40:08:161] [6977:6978] [WARN][com.freerdp.crypto] - CN = DESKTOP-NU10MTO
[18:40:10:466] [6977:6978] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[18:40:10:466] [6977:6978] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[18:40:10:603] [6977:6978] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[18:40:10:603] [6977:6978] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[18:40:10:604] [6977:6978] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
<SNIP>
```

Then, students need to open Task Manager and check under the Services tab to verify that Sysmon is running:

![[HTB Solutions/CDSA/z. images/8c91f0bee8b0f09c65948f2932705bae_MD5.jpg]]

Next, students need to open File Explorer, navigate to C:\\Tools\\Sysmon, and then right click to Edit the `sysmonconfig-export.xml` file:

![[HTB Solutions/CDSA/z. images/5af215a7d774be6c3408290ab59d35e5_MD5.jpg]]

Opening the file in Notepad, students need to Ctrl-F to search for "SYSMON EVENT ID 7":

![[HTB Solutions/CDSA/z. images/773562fa81ada4541a15dd10c7644d46_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/42be6c62b60c8af8c83337cb07178d0c_MD5.jpg]]

Students change the "include" to "exclude" to ensure that nothing is excluded, allowing for the capture of the necessary data:

![[HTB Solutions/CDSA/z. images/aeee16f8fda1555f4eef4dafac8d35f8_MD5.jpg]]

Now, students need to open a Command Prompt and use `sysmon.exe` to load the updated Sysmon configuration:

Code: cmd

```cmd
cd C:\Tools\Sysmon
sysmon.exe -c sysmonconfig-export.xml
```

```shell
Microsoft Windows [Version 10.0.19044.1826]
(c) Microsoft Corporation. All rights reserved.

C:\Users\Administrator>cd C:\Tools\Sysmon

C:\Tools\Sysmon>sysmon.exe -c sysmonconfig-export.xml

System Monitor v14.16 - System activity monitor
By Mark Russinovich and Thomas Garnier
Copyright (C) 2014-2023 Microsoft Corporation
Using libxml2. libxml2 is Copyright (C) 1998-2012 Daniel Veillard. All Rights Reserved.
Sysinternals - www.sysinternals.com

Loading configuration file with schema version 4.50
Sysmon schema version: 4.83
Configuration file validated.
Configuration updated.
```

With the modified Sysmon configuration, students need to navigate to the Event Viewer and access `Applications and Services` --> `Microsoft` --> `Windows` --> `Sysmon`. This will reveal the presence of the targeted event ID:

![[HTB Solutions/CDSA/z. images/73dd93b33ffcd9a7ea70996f4e03dfc3_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/e5aad33855d0fda5401ee28b8bddd2eb_MD5.jpg]]

Verifying that DLL loads are now being logged by `sysmon`, students need to perform the reflective DLL attack. First, they need to use Command Prompt to copy calc.exe and reflective\_dll.x64.dll to the desktop:

Code: cmd

```cmd
copy C:\Windows\System32\calc.exe 
copy "C:\Tools\Reflective DLLInjection\reflective_dll.x64.dll" C:\Users\Administrator\Desktop\WININET.dll
```

```shell
C:\Tools\Sysmon>copy C:\Windows\System32\calc.exe C:\Users\Administrator\Desktop\calc.exe
        1 file(s) copied.

C:\Tools\Sysmon>copy "C:\Tools\Reflective DLLInjection\reflective_dll.x64.dll" C:\Users\Administrator\Desktop\WININET.dll
        1 file(s) copied.
```

![[HTB Solutions/CDSA/z. images/55676a1cacb61a79feb3958f346b6db3_MD5.jpg]]

Then, students need to run `calc.exe`:

![[HTB Solutions/CDSA/z. images/9c941d06d50f6cecd13f5161cf1ffcc1_MD5.jpg]]

Now, students need to go back to `Event Viewer` and filter the Sysmon Operational logs by Event ID 7:

![[HTB Solutions/CDSA/z. images/76d230b7c8c727df03e06c5120d8d408_MD5.jpg]]

Additionally, students need to `Find` any instances of `calc.exe`:

![[HTB Solutions/CDSA/z. images/31fd089a31cd627719a0eea8be74b3a6_MD5.jpg]]

Clicking `Find Next`, eventually, students will find the Event, which shows the loading of `WININET.dll`, and its corresponding hashes:

![[HTB Solutions/CDSA/z. images/e82e81419c98899a5623c484a28fb21f_MD5.jpg]]

The SHA256 hash is shown to be `51F2305DCF385056C68F7CCF5B1B3B9304865CEF1257947D4AD6EF5FAD2E3B13`.

Answer: `51F2305DCF385056C68F7CCF5B1B3B9304865CEF1257947D4AD6EF5FAD2E3B13`

# Analyzing Evil With Sysmon & Event Logs

## Question 2

### "Replicate the Unmanaged PowerShell attack described in this section and provide the SHA256 hash of clrjit.dll that spoolsv.exe will load as your answer. "C:\\Tools\\Sysmon" and "C:\\Tools\\PSInject" on the spawned target contain everything you need."

From the previously established RDP session, students need to open `PowerShell` as administrator, and then launch `ProcessHacker.exe`:

Code: powershell

```powershell
& C:\Tools\processhacker\x64\ProcessHacker.exe
```

```shell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Users\Administrator> & C:\Tools\processhacker\x64\ProcessHacker.exe
```

![[HTB Solutions/CDSA/z. images/adea571611310fda64871422396895cd_MD5.jpg]]

Next, students need to identify the `PID` of `spoolsv.exe`:

![[HTB Solutions/CDSA/z. images/38d44acc91c8785381569a8a3aa965f5_MD5.jpg]]

Students now need to perform the Unmanaged `PowerShell` attack, using the discovered `PID` of `spoolsv.exe`:

Code: powershell

```powershell
Set-ExecutionPolicy Unrestricted -Scope CurrentUser
cd C:\Tools\PSInject\
Import-Module .\Invoke-PSInject.ps1
Invoke-PSInject -ProcId <PID> -PoshCode "V3JpdGUtSG9zdCAiSGVsbG8sIEd1cnU5OSEi"
```

```shell
PS C:\Users\Administrator> Set-ExecutionPolicy Unrestricted -Scope CurrentUser

Execution Policy Change
The execution policy helps protect you from scripts that you do not trust. Changing the execution policy might expose
you to the security risks described in the about_Execution_Policies help topic at
https:/go.microsoft.com/fwlink/?LinkID=135170. Do you want to change the execution policy?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "N"): A
PS C:\Users\Administrator> cd C:\Tools\PSInject\
PS C:\Tools\PSInject> Import-Module .\Invoke-PSInject.ps1

Security warning
Run only scripts that you trust. While scripts from the internet can be useful, this script can potentially harm your
computer. If you trust this script, use the Unblock-File cmdlet to allow the script to run without this warning
message. Do you want to run C:\Tools\PSInject\Invoke-PSInject.ps1?
[D] Do not run  [R] Run once  [S] Suspend  [?] Help (default is "D"): R
PS C:\Tools\PSInject> Invoke-PSInject -ProcId 2300 -PoshCode "V3JpdGUtSG9zdCAiSGVsbG8sIEd1cnU5OSEi"
```

In Process Hacker, students will observe that `spoolsv.exe` is now green, indicating a managed process:

![[HTB Solutions/CDSA/z. images/13f50e5b1c6137ba2ce498950008a276_MD5.jpg]]

Students need to now find the event in Event Viewer. Navigating to the Sysmon logs, students need to filter for Event ID 7, and then perform a `Find` for `clrjit.dll`:

![[HTB Solutions/CDSA/z. images/7c00caf747a07070c708902df92f3a18_MD5.jpg]]

The SHA256 hash is shown to be `8A3CD3CF2249E9971806B15C75A892E6A44CCA5FF5EA5CA89FDA951CD2C09AA9`.

Answer: `8A3CD3CF2249E9971806B15C75A892E6A44CCA5FF5EA5CA89FDA951CD2C09AA9`

# Analyzing Evil With Sysmon & Event Logs

## Question 3

### "Replicate the Credential Dumping attack described in this section and provide the NTLM hash of the Administrator user as your answer. "C:\\Tools\\Sysmon" and "C:\\Tools\\Mimikatz" on the spawned target contain everything you need."

Using the previously established RDP sessions, students need to go into the `sysmonconfig-export.xml` file and modify SYSMON EVENT ID 10 ProcessAccess onMatch from "include" to "exclude:"

![[HTB Solutions/CDSA/z. images/7c3ace84097d831cef981010279117fd_MD5.jpg]]

Next, students need to open Command Prompt as administrator and apply the new changes:

Code: cmd

```cmd
cd C:\Tools\Sysmon
Sysmon.exe -c sysmonconfig-export.xml
```

```shell
Microsoft Windows [Version 10.0.19044.1826]
(c) Microsoft Corporation. All rights reserved.

C:\Users\Administrator>cd C:\Tools\Sysmon

C:\Tools\Sysmon>Sysmon.exe -c sysmonconfig-export.xml

System Monitor v14.16 - System activity monitor
By Mark Russinovich and Thomas Garnier
Copyright (C) 2014-2023 Microsoft Corporation
Using libxml2. libxml2 is Copyright (C) 1998-2012 Daniel Veillard. All Rights Reserved.
Sysinternals - www.sysinternals.com

Loading configuration file with schema version 4.50
Sysmon schema version: 4.83
Configuration file validated.
Configuration updated.
```

With the changes applied, students need to dump password hashes using` mimikatz.exe` (which has been renamed to `AgentEXE.exe`):

Code: cmd

```cmd
cd C:\Tools\Mimikatz
AgentEXE.exe
privilege::debug
sekurlsa::logonpasswords
```

```shell
Microsoft Windows [Version 10.0.19044.1826]
(c) Microsoft Corporation. All rights reserved.

C:\Tools\Sysmon>cd C:\Tools\Mimikatz

C:\Tools\Mimikatz>AgentEXE.exe

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 506354 (00000000:0007b9f2)
Session           : RemoteInteractive from 2
User Name         : Administrator
Domain            : DESKTOP-NU10MTO
Logon Server      : DESKTOP-NU10MTO
Logon Time        : 6/7/2023 7:33:52 PM
SID               : S-1-5-21-2712802632-2324259492-1677155984-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : DESKTOP-NU10MTO
         * NTLM     : 5e4ffd54b3849aa720ed39f50185e533
         * SHA1     : e6cd3020bb3da2cd8f02dfeaf5c9f6d50812156b
```

The output reveals the NTLM hash of the Administrator is `5e4ffd54b3849aa720ed39f50185e533`.

Additionally, students should locate this event in Event Viewer, filtering by ID 10 and using the Find feature to look for `lsass.exe`:

![[HTB Solutions/CDSA/z. images/4816f01b4a33c2bb3337e9c000123d4e_MD5.jpg]]

Students can confirm the event was successfully logged and should take note of the `TargetImage` field, which indicates the interaction with `lsass.exe`.

Answer: `5e4ffd54b3849aa720ed39f50185e533`

# Tapping Into ETW

## Question 1

### "Replicate executing Seatbelt and SilkETW as described in this section and provide the ManagedInteropMethodName that starts with "G" and ends with "ion" as your answer. "c:\\Tools\\SilkETW\_SilkService\_v8\\v8" and "C:\\Tools\\GhostPack Compiled Binaries" on the spawned target contain everything you need."

Students need to connect to the spawned target using RDP:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'HTB_@cad3my_lab_W1n10_r00t!@0' /dynamic-resolution
```

```shell
┌─[us-academy-1]─[10.10.14.223]─[htb-ac-594497@htb-op1rwqzkzh]─[~]
└──╼ [★]$ xfreerdp /v:10.129.181.55 /u:Administrator /p:'HTB_@cad3my_lab_W1n10_r00t!@0' /dynamic-resolution 

[18:40:08:161] [6977:6978] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[18:40:08:161] [6977:6978] [WARN][com.freerdp.crypto] - CN = DESKTOP-NU10MTO
[18:40:10:466] [6977:6978] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[18:40:10:466] [6977:6978] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[18:40:10:603] [6977:6978] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[18:40:10:603] [6977:6978] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[18:40:10:604] [6977:6978] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
<SNIP>
```

Then, students need to edit `sysmonconfig-export.xml` to allow logging for `Event ID 7`:

```shell
	<!--SYSMON EVENT ID 7 : DLL (IMAGE) LOADED BY PROCESS [ImageLoad]-->
		<!--COMMENT:	Can cause high system load, disabled by default.-->
		<!--COMMENT:	[ https://attack.mitre.org/wiki/Technique/T1073 ] [ https://attack.mitre.org/wiki/Technique/T1038 ] [ https://attack.mitre.org/wiki/Technique/T1034 ] -->

		<!--DATA: UtcTime, ProcessGuid, ProcessId, Image, ImageLoaded, Hashes, Signed, Signature, SignatureStatus-->
	<RuleGroup name="" groupRelation="or">
		<ImageLoad onmatch="exclude">
			<!--NOTE: Using "include" with no rules means nothing in this section will be logged-->
		</ImageLoad>
	</RuleGroup>
```

![[HTB Solutions/CDSA/z. images/b5f3c2f5ed7bd38589c1d89d8cdbdbdd_MD5.jpg]]

Now, students need to open a Command Prompt, instructing `sysmon.exe` to utilize the newly updated Sysmon configuration file:

Code: cmd

```cmd
cd C:\Tools\Sysmon
sysmon.exe -c sysmonconfig-export.xml
```

```shell
Microsoft Windows [Version 10.0.19044.1826]
(c) Microsoft Corporation. All rights reserved.

C:\Users\Administrator>cd C:\Tools\Sysmon

C:\Tools\Sysmon>sysmon.exe -c sysmonconfig-export.xml

System Monitor v14.16 - System activity monitor
By Mark Russinovich and Thomas Garnier
Copyright (C) 2014-2023 Microsoft Corporation
Using libxml2. libxml2 is Copyright (C) 1998-2012 Daniel Veillard. All Rights Reserved.
Sysinternals - www.sysinternals.com

Loading configuration file with schema version 4.50
Sysmon schema version: 4.83
Configuration file validated.
Configuration updated.

C:\Tools\Sysmon>
```

Subsequently, students need to open a PowerShell as administrator and then run Seatbelt.exe:

Code: powershell

```powershell
cd 'C:\tools\GhostPack Compiled Binaries\'
.\Seatbelt.exe TokenPrivileges
```

```shell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Users\Administrator> cd 'C:\tools\GhostPack Compiled Binaries\'
PS C:\tools\GhostPack Compiled Binaries> .\Seatbelt.exe TokenPrivileges

                        %&&@@@&&
                        &&&&&&&%%%,                       #&&@@@@@@%%%%%%###############%
                        &%&   %&%%                        &////(((&%%%%%#%################//((((###%%%%%%%%%%%%%%%
%%%%%%%%%%%######%%%#%%####%  &%%**#                      @////(((&%%%%%%######################(((((((((((((((((((
#%#%%%%%%%#######%#%%#######  %&%,,,,,,,,,,,,,,,,         @////(((&%%%%%#%#####################(((((((((((((((((((
#%#%%%%%%#####%%#%#%%#######  %%%,,,,,,  ,,.   ,,         @////(((&%%%%%%%######################(#(((#(#((((((((((
#####%%%####################  &%%......  ...   ..         @////(((&%%%%%%%###############%######((#(#(####((((((((
#######%##########%#########  %%%......  ...   ..         @////(((&%%%%%#########################(#(#######((#####
###%##%%####################  &%%...............          @////(((&%%%%%%%%##############%#######(#########((#####
#####%######################  %%%..                       @////(((&%%%%%%%################
                        &%&   %%%%%      Seatbelt         %////(((&%%%%%%%%#############*
                        &%%&&&%%%%%        v1.2.1         ,(((&%%%%%%%%%%%%%%%%%,
                         #%%%%##,

====== TokenPrivileges ======

Current Token's Privileges

                     SeIncreaseQuotaPrivilege:  DISABLED
                          SeSecurityPrivilege:  DISABLED
                     SeTakeOwnershipPrivilege:  DISABLED
                        SeLoadDriverPrivilege:  DISABLED
                     SeSystemProfilePrivilege:  DISABLED
                        SeSystemtimePrivilege:  DISABLED
              SeProfileSingleProcessPrivilege:  DISABLED
              SeIncreaseBasePriorityPrivilege:  DISABLED
                    SeCreatePagefilePrivilege:  DISABLED
                            SeBackupPrivilege:  DISABLED
                           SeRestorePrivilege:  DISABLED
                          SeShutdownPrivilege:  DISABLED
                             SeDebugPrivilege:  SE_PRIVILEGE_ENABLED
                 SeSystemEnvironmentPrivilege:  DISABLED
                      SeChangeNotifyPrivilege:  SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
                    SeRemoteShutdownPrivilege:  DISABLED
                            SeUndockPrivilege:  DISABLED
                      SeManageVolumePrivilege:  DISABLED
                       SeImpersonatePrivilege:  SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
                      SeCreateGlobalPrivilege:  SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
                SeIncreaseWorkingSetPrivilege:  DISABLED
                          SeTimeZonePrivilege:  DISABLED
                SeCreateSymbolicLinkPrivilege:  DISABLED
    SeDelegateSessionUserImpersonatePrivilege:  DISABLED

[*] Completed collection in 0.053 seconds
```

Checking Event Viewer and filtering the logs by ID 7, students can confirm that Sysmon is capturing Seatbelt.exe's interaction with .NET dll's.

![[HTB Solutions/CDSA/z. images/cb3f0ef29d9e3f78ac8c68c026e434fe_MD5.jpg]]

Additionally, students need to use SilkETW to collect data from the `Microsoft-Windows-DotNETRuntime` provider via Command Prompt:

Code: cmd

```cmd
cd c:\Tools\SilkETW_SilkService_v8\v8\SilkETW
SilkETW.exe -t user -pn Microsoft-Windows-DotNETRuntime -uk 0x2038 -ot file -p C:\windows\temp\etw.json
```

```shell
C:\Tools\Sysmon>cd c:\Tools\SilkETW_SilkService_v8\v8\SilkETW

c:\Tools\SilkETW_SilkService_v8\v8\SilkETW>SilkETW.exe -t user -pn Microsoft-Windows-DotNETRuntime -uk 0x2038 -ot file -p C:\windows\temp\etw.json

███████╗██╗██╗   ██╗  ██╗███████╗████████╗██╗    ██╗
██╔════╝██║██║   ██║ ██╔╝██╔════╝╚══██╔══╝██║    ██║
███████╗██║██║   █████╔╝ █████╗     ██║   ██║ █╗ ██║
╚════██║██║██║   ██╔═██╗ ██╔══╝     ██║   ██║███╗██║
███████║██║█████╗██║  ██╗███████╗   ██║   ╚███╔███╔╝
╚══════╝╚═╝╚════╝╚═╝  ╚═╝╚══════╝   ╚═╝    ╚══╝╚══╝
                  [v0.8 - Ruben Boonen => @FuzzySec]

[+] Collector parameter validation success..
[>] Starting trace collector (Ctrl-c to stop)..
[?] Events captured: 31
```

Students need to replay the `Seatbelt.exe` attack:

Code: powershell

```powershell
.\Seatbelt.exe TokenPrivileges
```

```shell
PS C:\tools\GhostPack Compiled Binaries> .\Seatbelt.exe TokenPrivileges

<SNIP>

====== TokenPrivileges ======

Current Token's Privileges

                     SeIncreaseQuotaPrivilege:  DISABLED
                          SeSecurityPrivilege:  DISABLED
                     SeTakeOwnershipPrivilege:  DISABLED
                        SeLoadDriverPrivilege:  DISABLED
                     SeSystemProfilePrivilege:  DISABLED
                        SeSystemtimePrivilege:  DISABLED
              SeProfileSingleProcessPrivilege:  DISABLED
              SeIncreaseBasePriorityPrivilege:  DISABLED
                    SeCreatePagefilePrivilege:  DISABLED
                            SeBackupPrivilege:  DISABLED
                           SeRestorePrivilege:  DISABLED
                          SeShutdownPrivilege:  DISABLED
                             SeDebugPrivilege:  SE_PRIVILEGE_ENABLED
                 SeSystemEnvironmentPrivilege:  DISABLED
                      SeChangeNotifyPrivilege:  SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
                    SeRemoteShutdownPrivilege:  DISABLED
                            SeUndockPrivilege:  DISABLED
                      SeManageVolumePrivilege:  DISABLED
                       SeImpersonatePrivilege:  SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
                      SeCreateGlobalPrivilege:  SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
                SeIncreaseWorkingSetPrivilege:  DISABLED
                          SeTimeZonePrivilege:  DISABLED
                SeCreateSymbolicLinkPrivilege:  DISABLED
    SeDelegateSessionUserImpersonatePrivilege:  DISABLED

[*] Completed collection in 0.115 seconds
```

Finally, students need to check the `etw.json` file located in `C:\Windows\Temp`:

![[HTB Solutions/CDSA/z. images/85f306b50094e085c2f1ea64b556683d_MD5.jpg]]

Examination of the log reveals that `ManagedInteropMethodName` is set to `GetTokenInformation`.

Answer: `GetTokenInformation`

# Get-WinEvent

## Question 1

### "Utilize the Get-WinEvent cmdlet to traverse all event logs located within the "C:\\Tools\\chainsaw\\EVTX-ATTACK-SAMPLES\\Lateral Movement" directory and determine when the \\\\PRINT share was added. Enter the time of the identified event in the format HH:MM:SS as your answer."

Students need to connect to the spawned target using RDP:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'HTB_@cad3my_lab_W1n10_r00t!@0' /dynamic-resolution
```

```shell
┌─[us-academy-1]─[10.10.14.223]─[htb-ac-594497@htb-op1rwqzkzh]─[~]
└──╼ [★]$ xfreerdp /v:10.129.181.55 /u:Administrator /p:'HTB_@cad3my_lab_W1n10_r00t!@0' /dynamic-resolution 

[18:40:08:161] [6977:6978] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[18:40:08:161] [6977:6978] [WARN][com.freerdp.crypto] - CN = DESKTOP-NU10MTO
[18:40:10:466] [6977:6978] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[18:40:10:466] [6977:6978] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[18:40:10:603] [6977:6978] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[18:40:10:603] [6977:6978] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[18:40:10:604] [6977:6978] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
<SNIP>
```

Then, students need to open `PowerShell` and utilize the `Get-WinEvent` Cmdlet. Specifically, students need to search for events where the `Share Name` field contains the value `PRINT`:

Code: powershell

```powershell
Get-WinEvent -Path 'C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Lateral Movement\*' | Where-Object {$_.Properties[4].Value -like "*PRINT*"} | Format-List
```

```shell
PS C:\Users\Administrator> Get-WinEvent -Path 'C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Lateral Movement\*' | Where-Object {$_.Properties[4].Value -like "*PRINT*"} | Format-List

TimeCreated  : 3/17/2019 12:30:30 PM
ProviderName : Microsoft-Windows-Security-Auditing
Id           : 5142
Message      : A network share object was added.

               Subject:
                Security ID:            S-1-5-21-3583694148-1414552638-2922671848-1000
                Account Name:           IEUser
                Account Domain:         PC04
                Logon ID:               0x128A9

               Share Information:
                Share Name:             \\*\PRINT
                Share Path:             c:\windows\system32
```

The event logs reveal that the share was added at `12:30:30`.

Answer: `12:30:30`

# Skills Assessment

## Question 1

### "By examining the logs located in the "C:\\Logs\\DLLHijack" directory, determine the process responsible for executing a DLL hijacking attack. Enter the process name as your answer. Answer format: \_.exe"

Students need to connect to the spawned target using RDP, utilizing the credentials `Administrator:HTB_@cad3my_lab_W1n10_r00t!@0`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'HTB_@cad3my_lab_W1n10_r00t!@0' /dynamic-resolution
```

```shell
┌─[us-academy-1]─[10.10.14.223]─[htb-ac-594497@htb-7hqbxrdnrv]─[~]
└──╼ [★]$ xfreerdp /v:10.129.205.123 /u:Administrator /p:'HTB_@cad3my_lab_W1n10_r00t!@0' /dynamic-resolution 

[02:15:41:799] [2259:2260] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-594497/.config/freerdp
[02:15:41:799] [2259:2260] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-594497/.config/freerdp/certs]
[02:15:41:799] [2259:2260] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-594497/.config/freerdp/server]
[02:15:41:815] [2259:2260] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[02:15:41:815] [2259:2260] [WARN][com.freerdp.crypto] - CN = DESKTOP-NU10MTO
```

Then, students need to analyze the `DLLHijack.evtx` event file using `PowerShell` and the `Get-WinEvent` Cmdlet. To detect a DLL hijack, students need to focus on `Event Type 7`, which corresponds to module load events. Additionally, students should search for events triggered by unsigned DLLs.

Code: powershell

```powershell
Get-WinEvent -Path 'C:\Logs\DLLHijack\DLLHijack.evtx' | Where-Object {$_.Id -eq 7} | Where-Object {$_.Properties[12].Value -like "false"} | Format-List
```

```shell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Users\Administrator> Get-WinEvent -Path 'C:\Logs\DLLHijack\DLLHijack.evtx' | Where-Object {$_.Properties[12].Value -like "false"} | Format-List

Get-WinEvent : The maximum number of replacements has been reached
At line:1 char:1
+ Get-WinEvent -Path 'C:\Logs\DLLHijack\DLLHijack.evtx' | Where-Object  ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Get-WinEvent], EventLogException
    + FullyQualifiedErrorId : The maximum number of replacements has been reached,Microsoft.PowerShell.Commands.GetWin
   EventCommand

<SNIP>

TimeCreated  : 4/27/2022 6:39:11 PM
ProviderName : Microsoft-Windows-Sysmon
Id           : 7
Message      : Image loaded:
               RuleName: -
               UtcTime: 2022-04-28 01:39:11.859
               ProcessGuid: {67e39d39-f03f-6269-9b01-000000000300}
               ProcessId: 6868
               Image: C:\ProgramData\Dism.exe
               ImageLoaded: C:\ProgramData\DismCore.dll
               FileVersion: 0.0.0.0
               Description: FILEDESCRIPTIONGOESHERE
               Product: PRODUCTNAMEGOESHERE
               Company: -
               OriginalFileName: ORIGINALFILENAMEGOESHERE
               Hashes: SHA1=524945EE2CC863CDB57C7CCCD89607B9CD6E0524,MD5=9B5056E10FCF5959F70637553E5C1577,SHA256=6AB9D9
               4E6888FB808E7FBBE93F8F60A0D7A021D6080923A1D8596C3C8CD6B7F7,IMPHASH=5393B78894398013B4127419F1A93894
               Signed: false
               Signature: -
               SignatureStatus: Unavailable
               User: DESKTOP-R4PEEIF\waldo
```

By filtering the logs specifically for `unsigned DLL files` being loaded, it is revealed that `Dism.exe` was responsible for the `DLL hijacking attack`. This was accomplished by using `.Properties[12]`, and students can look at `Event ID 7` in `Event Viewer` to better understand the object structure:

![[HTB Solutions/CDSA/z. images/a4cf8803ce7ae91cdfe4dbd4baebf126_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/1e4e4c7d2c714e9e033aa5ce8ac0792c_MD5.jpg]]

Answer: `Dism.exe`

# Skills Assessment

## Question 2

### "By examining the logs located in the "C:\\Logs\\PowershellExec" directory, determine the process that executed unmanaged PowerShell code. Enter the process name as your answer. Answer format: \_.exe"

Using the previously established RDP session, students need to use `PowerShell` and the `Get-WinEvent` Cmdlet to analyze `PowerShellExec.evtx`. Specifically, students need to look for events where the `Image Loaded` property is set to `clr.dll`:

Code: powershell

```powershell
Get-WinEvent -Path 'C:\Logs\PowershellExec\PowershellExec.evtx' | Where-Object {$_.Properties[5].Value -like "*clr.dll*"} | Format-List
```

```shell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Users\Administrator> Get-WinEvent -Path 'C:\Logs\PowershellExec\PowershellExec.evtx' | Where-Object {$_.Properties[5].Value -like "*clr.dll*"} | Format-List

TimeCreated  : 4/27/2022 6:59:42 PM
ProviderName : Microsoft-Windows-Sysmon
Id           : 7
Message      : Image loaded:
               RuleName: -
               UtcTime: 2022-04-28 01:59:42.194
               ProcessGuid: {67e39d39-f4cc-6269-3203-000000000300}
               ProcessId: 3776
               Image: C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_10.1906.55.0_x64__8wekyb3d8bbwe\Calculator.exe
               ImageLoaded: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll
               FileVersion: 4.8.4470.0 built by: NET48REL1LAST_C
               Description: Microsoft .NET Runtime Common Language Runtime - WorkStation
               Product: Microsoft® .NET Framework
               Company: Microsoft Corporation
               OriginalFileName: clr.dll
               Hashes: SHA1=C5A99CE7425E1A2245A4C0FAC6FFD725508A6897,MD5=3C242B76E36DAB6C0B1E300AE7BC3D2E,SHA256=99ED3CC3A8CA5938783C0CAA052AC72A104FB6C7777A56D3AD7D6BBA32D52969,IMPHASH=6851068577998FF473E5933122867348
               Signed: true
               Signature: Microsoft Corporation
               SignatureStatus: Valid
               User: DESKTOP-R4PEEIF\waldo
```

Students will find `Calculator.exe` as the process responsible for executing unmanaged `PowerShell` code.

Answer: `Calculator.exe`

# Skills Assessment

## Question 3

### "By examining the logs located in the "C:\\Logs\\PowershellExec" directory, determine the process that injected into the process that executed unmanaged PowerShell code. Enter the process name as your answer. Answer format: \_.exe"

Using the previously established RDP session, students need to use `PowerShell` and the `Get-WinEvent` Cmdlet to analyze `PowerShellExec.evtx`. Specifically, students need to look for `Event ID 8` (The `CreateRemoteThread` event detects when a process creates a thread in another process) and find events where the `TargetImage` property contains `Calculator.exe`:

Code: powershell

```powershell
Get-WinEvent -FilterHashtable @{Path='C:\Logs\PowershellExec\PowershellExec.evtx'; ID=8} | Where-Object {$_.message -like "*Calculator.exe*"} | Format-List
```

![[HTB Solutions/CDSA/z. images/745679cfb2cc0cb976b707645e1759df_MD5.jpg]]

```shell
PS C:\Users\Administrator> Get-WinEvent -FilterHashtable @{Path='C:\Logs\PowershellExec\PowershellExec.evtx'; ID=8} | Where-Object {$_.message -like "*Calculator.exe*"} | Format-List

TimeCreated  : 4/27/2022 7:00:13 PM
ProviderName : Microsoft-Windows-Sysmon
Id           : 8
Message      : CreateRemoteThread detected:
               RuleName: -
               UtcTime: 2022-04-28 02:00:13.593
               SourceProcessGuid: {67e39d39-f0f6-6269-b601-000000000300}
               SourceProcessId: 8364
               SourceImage: C:\Windows\System32\rundll32.exe
               TargetProcessGuid: {67e39d39-f4cc-6269-3203-000000000300}
               TargetProcessId: 3776
               TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_10.1906.55.0_x64__8wekyb3d8bbwe\Calculator.exe
               NewThreadId: 4816
               StartAddress: 0x00000253B2180000
               StartModule: -
               StartFunction: -
               SourceUser: DESKTOP-R4PEEIF\waldo
               TargetUser: DESKTOP-R4PEEIF\waldo

TimeCreated  : 4/27/2022 6:59:42 PM
ProviderName : Microsoft-Windows-Sysmon
Id           : 8
Message      : CreateRemoteThread detected:
               RuleName: -
               UtcTime: 2022-04-28 01:59:42.176
               SourceProcessGuid: {67e39d39-f0f6-6269-b601-000000000300}
               SourceProcessId: 8364
               SourceImage: C:\Windows\System32\rundll32.exe
               TargetProcessGuid: {67e39d39-f4cc-6269-3203-000000000300}
               TargetProcessId: 3776
               TargetImage: C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_10.1906.55.0_x64__8wekyb3d8bbwe\Calculator.exe
               NewThreadId: 3980
               StartAddress: 0x0000025398BD0000
               StartModule: -
               StartFunction: -
               SourceUser: DESKTOP-R4PEEIF\waldo
               TargetUser: DESKTOP-R4PEEIF\waldo
```

Students will find `rundll32.exe` injected into `Calculator.exe`.

Answer: `rundll32.exe`

# Skills Assessment

## Question 4

### "By examining the logs located in the "C:\\Logs\\Dump" directory, determine the process that performed an LSASS dump. Enter the process name as your answer. Answer format:\_.exe"

Using the previously established RDP session, students need to use `PowerShell` and the `Get-WinEvent` Cmdlet to analyze `LsassDump.evtx`. Specifically, students need to look for event ID 10 (the Process Accessed event reports when a process opens another process) and find events where the `TargetImage` property is `lsass.exe`:

```shell
Get-WinEvent -FilterHashtable @{Path='C:\Logs\Dump\LsassDump.evtx'; ID=10} | Where-Object {$_.Properties[8].Value -like "*lsass*"} | Format-List
```

```shell
PS C:\Users\Administrator> Get-WinEvent -FilterHashtable @{Path='C:\Logs\Dump\LsassDump.evtx'; ID=10} | Where-Object {$_.Properties[8].Value -like "*lsass*"} | Format-List

<SNIP>

TimeCreated  : 4/27/2022 7:08:47 PM
ProviderName : Microsoft-Windows-Sysmon
Id           : 10
Message      : Process accessed:
               RuleName: -
               UtcTime: 2022-04-28 02:08:47.827
               SourceProcessGUID: {67e39d39-f72f-6269-6203-000000000300}
               SourceProcessId: 5560
               SourceThreadId: 3936
               SourceImage: C:\Users\waldo\Downloads\processhacker-3.0.4801-bin\64bit\ProcessHacker.exe
               TargetProcessGUID: {67e39d39-ecd9-6269-0c00-000000000300}
               TargetProcessId: 696
               TargetImage: C:\Windows\system32\lsass.exe
               GrantedAccess: 0x1400
               CallTrace: C:\Windows\SYSTEM32\ntdll.dll+9d234|C:\Users\waldo\Downloads\processhacker-3.0.4801-bin\64bit\ProcessHacker.exe+9373b|C:\Users\waldo\Downloads\processhacker-3.0.4801-bin\64bit\ProcessHacker.exe+95a1b|C:\Users\waldo\Downloads\processhacker-3.0.4
               801-bin\64bit\ProcessHacker.exe+175751|C:\Users\waldo\Downloads\processhacker-3.0.4801-bin\64bit\ProcessHacker.exe+10952b|C:\Windows\System32\KERNEL32.DLL+17034|C:\Windows\SYSTEM32\ntdll.dll+52651
               SourceUser: DESKTOP-R4PEEIF\waldo
            
```

Students will find `ProcessHacker.exe` as the process that performed the `lsass` dump.

Answer: `ProcessHacker.exe`

# Skills Assessment

## Question 5

### "By examining the logs located in the "C:\\Logs\\Dump" directory, determine if an ill-intended login took place after the LSASS dump. Answer format: Yes or No"

From the previous exercise, students will know that the `lsass` dump took place on `4/27/2022 7:08:47 PM`. Therefore, students need to open `C:\Logs\Dump\SecurityLogs.evtx` in Event Viewer to compare the time stamps:

![[HTB Solutions/CDSA/z. images/ec0a01219805ed245f0db230916e8409_MD5.jpg]]

Students will find that no additional logon events have occurred.

Answer: `No`

# Skills Assessment

## Question 6

### "By examining the logs located in the "C:\\Logs\\StrangePPID" directory, determine a process that was used to temporarily execute code based on a strange parent-child relationship. Enter the process name as your answer. Answer format: \_.exe"

Students need to open the `C:\Logs\StrangePPID\StrangePPID.evtx` file in `Event Viewer` and filter for `Event ID 1`:

![[HTB Solutions/CDSA/z. images/e5aef6502f2076ff3fcf52a639f54ec3_MD5.jpg]]

Observing only four events, students will find `werfault.exe` creating a `cmd /c whoami` command.

Additionally, students can perform the analysis using `Get-WinEvent`, searching for instances of `Event ID 1` where the `Image` field contains "cmd" (the idea being to identify cases where cmd.exe is being spawned by another process):

![[HTB Solutions/CDSA/z. images/745679cfb2cc0cb976b707645e1759df_MD5.jpg]]

Code: powershell

```powershell
Get-WinEvent -Path 'C:\Logs\StrangePPID\*' -FilterXPath "*[System[EventID=1]]" | where-object {$_.Properties[4].Value -like "*cmd*"} | fl
```

```shell
PS C:\Users\Administrator> Get-WinEvent -Path 'C:\Logs\StrangePPID\*' -FilterXPath "*[System[EventID=1]]" | where-object {$_.Properties[4].Value -like "*cmd*"} | fl

TimeCreated  : 4/27/2022 7:18:06 PM
ProviderName : Microsoft-Windows-Sysmon
Id           : 1
Message      : Process Create:
               RuleName: -
               UtcTime: 2022-04-28 02:18:06.611
               ProcessGuid: {67e39d39-f95e-6269-8303-000000000300}
               ProcessId: 472
               Image: C:\Windows\System32\cmd.exe
               FileVersion: 10.0.19041.746 (WinBuild.160101.0800)
               Description: Windows Command Processor
               Product: Microsoft® Windows® Operating System
               Company: Microsoft Corporation
               OriginalFileName: Cmd.Exe
               CommandLine: cmd.exe /c whoami
               CurrentDirectory: C:\ProgramData\
               User: DESKTOP-R4PEEIF\waldo
               LogonGuid: {67e39d39-ed25-6269-7000-170000000000}
               LogonId: 0x170070
               TerminalSessionId: 1
               IntegrityLevel: Medium
               Hashes: SHA1=F1EFB0FDDC156E4C61C5F78A54700E4E7984D55D,MD5=8A2122E8162DBEF04694B9C3E0B6CDEE,SHA256=B99D61D874728EDC0918CA0EB10EAB93D381E7367E377406E65963366C874450,IMPHASH=272245E2988E1E430500B852C4FB5E18
               ParentProcessGuid: {67e39d39-f935-6269-8203-000000000300}
               ParentProcessId: 7780
               ParentImage: C:\Windows\System32\WerFault.exe
               ParentCommandLine: "C:\\Windows\\System32\\werfault.exe"
               ParentUser: DESKTOP-R4PEEIF\waldo
```

Answer: `werfault.exe`