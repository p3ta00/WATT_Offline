
## Section Questions and their Answers

| Section                            | Question Number | Answer                                               |
| ---------------------------------- | --------------- | ---------------------------------------------------- |
| Command Prompt Basics              | Question 1      | System32                                             |
| Getting Help                       | Question 1      | ipconfig /?                                          |
| Getting Help                       | Question 2      | man                                                  |
| Getting Help                       | Question 3      | f7                                                   |
| System Navigation                  | Question 1      | tree /f                                              |
| System Navigation                  | Question 2      | cd                                                   |
| Working with Directories and Files | Question 1      | type                                                 |
| Working with Directories and Files | Question 2      | mkdir apples                                         |
| Gathering System Information       | Question 1      | systeminfo                                           |
| Gathering System Information       | Question 2      | icl-win11                                            |
| Finding Files and Directories      | Question 1      | findstr                                              |
| Finding Files and Directories      | Question 2      | RmxhZ3MgYXJlbid0IGhhcmQgdG8gZmluZCBub3csIHJpZ2h0Pw== |
| Environment Variables              | Question 1      | global                                               |
| Managing Services                  | Question 1      | sc stop red-light                                    |
| Managing Services                  | Question 2      | sc                                                   |
| Working With Scheduled Tasks       | Question 1      | True                                                 |
| Working With Scheduled Tasks       | Question 2      | complete                                             |
| CMD Vs. PowerShell                 | Question 1      | Get-Help Get-Location                                |
| CMD Vs. PowerShell                 | Question 2      | Get-Location                                         |
| CMD Vs. PowerShell                 | Question 3      | escape                                               |
| All About Cmdlets and Modules      | Question 1      | Get-Module                                           |
| All About Cmdlets and Modules      | Question 2      | PowerShellGet                                        |
| All About Cmdlets and Modules      | Question 3      | complete                                             |
| User and Group Management          | Question 1      | active directory                                     |
| User and Group Management          | Question 2      | Get-LocalUser                                        |
| User and Group Management          | Question 3      | loxley                                               |
| Working with Files and Directories | Question 1      | get-content                                          |
| Working with Files and Directories | Question 2      | new-item                                             |
| Working with Files and Directories | Question 3      | COMPLETE                                             |
| Finding & Filtering Content        | Question 1      | methods                                              |
| Finding & Filtering Content        | Question 2      | get-member                                           |
| Finding & Filtering Content        | Question 3      | -recurse                                             |
| Working with Services              | Question 1      | get-service                                          |
| Working with Services              | Question 2      | start-service windefend                              |
| Working with Services              | Question 3      | invoke-command                                       |
| Working with the Registry          | Question 1      | values                                               |
| Working with the Registry          | Question 2      | hkcu                                                 |
| Working with the Registry          | Question 3      | complete                                             |
| Working with the Windows Event Log | Question 1      | complete                                             |
| Networking Management from The CLI | Question 1      | dns                                                  |
| Networking Management from The CLI | Question 2      | get-netipaddress                                     |
| Networking Management from The CLI | Question 3      | winrm quickconfig                                    |
| Skills Assessment                  | Question 1      | D0wn\_the\_rabbit\_H0!3                              |
| Skills Assessment                  | Question 2      | Nice and Easy!                                       |
| Skills Assessment                  | Question 3      | Academy-ICL11                                        |
| Skills Assessment                  | Question 4      | 101                                                  |
| Skills Assessment                  | Question 5      | Digging in The nest                                  |
| Skills Assessment                  | Question 6      | 14                                                   |
| Skills Assessment                  | Question 7      | htb-student                                          |
| Skills Assessment                  | Question 8      | Modules\_make\_pwsh\_run!                            |
| Skills Assessment                  | Question 9      | rick                                                 |
| Skills Assessment                  | Question 10     | vmtoolsd.exe                                         |
| Skills Assessment                  | Question 11     | justalocaladmin                                      |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Command Prompt Basics

## Question 1

### "In what directory can the cmd executable be found? (full path and executable name as answer)"

The `CMD` executable can be found within the `System32` directory:

![[HTB Solutions/Others/z. images/2dd61dd9bfd5014399374b1e11fcf2f5_MD5.jpg]]

Answer: `System32`

# Getting Help

## Question 1

### "If I wanted to view the help documentation for 'ipconfig', what command and/or modifier would I use? (full command string)"

The `ipconfig` command with the modifier `/?` provides information that is needed to utilize the command correctly:

![[HTB Solutions/Others/z. images/1eb0e6aa8dfcceb7fc8aa06a025901fd_MD5.jpg]]

Answer: `ipconfig /?`

# Getting Help

## Question 2

### "What CLI equivalent "Help utility" exists on Linux hosts? (one word)"

The `man` (short for `manual`) pages are the CLI equivalent for the `help` utility:

![[HTB Solutions/Others/z. images/a2f5eb0462c7127ed6d65d138c77d1e8_MD5.jpg]]

Answer: `man`

# Getting Help

## Question 3

### "Which CMD hotkey will open an interactive list of the previous commands we have ran?"

The `F7` `CMD` hotkey will open an interactive list of the previous commands ran:

![[HTB Solutions/Others/z. images/6f2671f50ec5a43da8f44ffbfef15152_MD5.jpg]]

Answer: `F7`

# System Navigation

## Question 1

### "What command will give us a listing of all files and folders in a specified path?"

The `tree /F` command will give the listing of all files and folders in a specified path:

![[HTB Solutions/Others/z. images/d143d7ea507fad4b8e37942e20175e5f_MD5.jpg]]

Answer: `tree /F`

# System Navigation

## Question 2

### "What command will print my current working directory onto the console?"

The `cd` command prints out the current working directory onto the console:

![[HTB Solutions/Others/z. images/872fac41bd995a7f9b58e4d861efe829_MD5.jpg]]

Answer: `cd`

# Working With Files and Directories

## Question 1

### "What command can display the contents of a file and redirect the contents of the file into another file or to the console?"

The `type` command can display the contents of a file and redirect the contents of the file into another file or the console:

![[HTB Solutions/Others/z. images/47eaee9a1ce98e6190bb31cb0ce51d16_MD5.jpg]]

Answer: `type`

# Working With Files and Directories

## Question 2

### "What command can be used to make the 'apples' directory? (full command as answer, not the alias)"

The command `mkdir apples` can be used to make a directory called "apples".

![[HTB Solutions/Others/z. images/1a0fa8997a9333d8cba13b17fb189c95_MD5.jpg]]

Answer: `mkdir apples`

# Gathering System Information

## Question 1

### "What command will output verbose system information such as OS configuration, security info, hardware info, and more?"

The `systeminfo` command outputs verbose system information such as OS configuration, security info, hardware info, and more:

![[HTB Solutions/Others/z. images/94f0e7edc649348b21e0114824b79392_MD5.jpg]]

Answer: `systeminfo`

# Gathering System Information

## Question 2

### "Access the target host and run the 'hostname' command. What is the hostname?"

Students first need to connect to the target using SSH and authenticating as `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[us-academy-2]─[10.10.14.169]─[htb-ac594497@htb-e4irszwlfg]─[~]
└──╼ [★]$ ssh htb-student@10.129.203.105

The authenticity of host '10.129.203.105 (10.129.203.105)' can't be established.
ECDSA key fingerprint is SHA256:zY7bAJ1O47ZibFBNsrU5fLzGIikYetbIyKAAc3B3K88.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.203.105' (ECDSA) to the list of known hosts.
htb-student@10.129.203.105's password: 

Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\htb-student>
```

Then, students need to enumerate host name with the `hostname` command, finding it to be `ICL-WIN11`:

Code: powershell

```powershell
hostname
```

```
PS C:\Users\htb-student> hostname

ICL-WIN11
```

Answer: `ICL-WIN11`

# Finding Files and Directories

## Question 1

### "What command can be used to search for regular expression strings from command prompt?"

The `findstr` command can be used to search for regular expression strings from command prompt:

![[HTB Solutions/Others/z. images/dae0083a248ee4c5845855b771dba404_MD5.jpg]]

Answer: `findstr`

# Finding Files and Directories

## Question 2

### "Using the skills acquired in this and previous sections, access the target host and search for the file named 'waldo.txt'. Submit the flag found within the file."

Students first need to connect with SSH to the target machine, authenticating as `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[us-academy-2]─[10.10.14.169]─[htb-ac594497@htb-e4irszwlfg]─[~]
└──╼ [★]$ ssh htb-student@10.129.203.105

The authenticity of host '10.129.203.105 (10.129.203.105)' can't be established.
ECDSA key fingerprint is SHA256:zY7bAJ1O47ZibFBNsrU5fLzGIikYetbIyKAAc3B3K88.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.203.105' (ECDSA) to the list of known hosts.
htb-student@10.129.203.105's password: 

Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\htb-student>
```

Then, students need utilize the `tree` command on the `C:\Users\` directory to search for `waldo.txt`, finding it to be within the `Favorities` directory of the user `MTanaka`:

Code: powershell

```powershell
tree /F C:\Users\
```

```
PS C:\Users\htb-student> tree /F C:\Users\

Folder PATH listing
Volume serial number is F684-763E
C:\USERS
├───administrator
│   │   remove
│   │   start
│   │
│   ├───.ssh
│   │       known_hosts
<SNIP>
├───MTanaka
<SNIP>
│   ├───Favorites
│   │   │   Bing.url
│   │   │   waldo.txt
<SNIP>
```

Finally, students need to read the contents of `waldo.txt` with `type`:

Code: powershell

```powershell
type C:\Users\MTanaka\Favorites\waldo.txt
```

```
PS C:\Users\htb-student> type C:\Users\MTanaka\Favorites\waldo.txt

RmxhZ3MgYXJlbid0IGhhcmQgdG8gZmluZCBub3csIHJpZ2h0Pw==
```

Answer: `RmxhZ3MgYXJlbid0IGhhcmQgdG8gZmluZCBub3csIHJpZ2h0Pw==`

# Environment Variables

## Question 1

### "What variable scope allows for universal access?"

The `Global` variable scope allows for universal access:

![[HTB Solutions/Others/z. images/d291cebdfc0134692f6dc7e79d43d1de_MD5.jpg]]

Answer: `Global`

# Managing Services

## Question 1

### "What command string will stop a process named 'red-light'? (full command as the answer)"

Students need to refer to the various examples provided in the section. For example, the following example command stops the `Print Spooler` service, thus, the command to stop `red-light` will be `sc stop red-light`:

![[HTB Solutions/Others/z. images/a5e9b0f7f561f9b07fbba1acfbff2eeb_MD5.jpg]]

Answer: `sc stop red-light`

# Managing Services

## Question 2

### "What Windows executable will allow us to create, query, and modify services on a host?"

The `sc` Windows executable allows to create, query, and modify services on a host:

![[HTB Solutions/Others/z. images/69ac1ea518735c6c4ff5d292d4d93736_MD5.jpg]]

Answer: `sc`

# Working With Scheduled Tasks

## Question 1

### "True or False, A scheduled task can be set to run when a user logs onto a host?"

`True`; a scheduled task can be set to run when a user logs onto a host:

![[HTB Solutions/Others/z. images/6ca7c069fc1c7cbefb342d117b67e08a_MD5.jpg]]

Answer: `True`

# Working With Scheduled Tasks

## Question 2

### "Access the target host and take some time to practice working with Scheduled Tasks. Type COMPLETE as the answer when you are ready to move on."

Students are highly encouraged to access the target host and practice working with Scheduled Tasks, then once done, type `COMPLETE`.

Answer: `COMPLETE`

# CMD vs PowerShell

## Question 1

### "What command string can we use to view the help documentation for the command Get-Location? (full string)"

The `Get-Help Get-Location` command string can be used to view the help documentation for the command `Get-Location`.

![[HTB Solutions/Others/z. images/300d1617acb90fe133d8d2611892596f_MD5.jpg]]

Answer: `Get-Help Get-Location`

# CMD vs PowerShell

## Question 2

### "What command can we use to show us our current location on the host system?"

The `Get-Location` command can be used to show the current location on the host system:

![[HTB Solutions/Others/z. images/8dbd0f435bafe4b53402b7d3788c5b20_MD5.jpg]]

Answer: `Get-Location`

# CMD vs PowerShell

## Question 3

### "What hotkey can be used to clear our input line completely?"

The `escape` hotkey can be used to clear the input line completely:

![[HTB Solutions/Others/z. images/1f4b09228652085780eae497b6b02222_MD5.jpg]]

Answer: `escape`

# All About Cmdlets and Modules

## Question 1

### "What cmdlet can help us find modules that are loaded into our session?"

The `Get-Module` `cmdlet` can help find modules that are loaded into the current session:

![[HTB Solutions/Others/z. images/992f84b18bc50611a8670230f2697001_MD5.jpg]]

Answer: `Get-Module`

# All About Cmdlets and Modules

## Question 2

### "What module provides us with cmdlets built to manage package installation from the PowerShell Gallery?"

The `PowerShellGet` module provides `cmdlets` built to manage package installation from the PowerShell Gallery:

![[HTB Solutions/Others/z. images/16ea48e06619395540ef0efe48e9e8b3_MD5.jpg]]

Answer: `PowerShellGet`

# All About Cmdlets and Modules

## Question 3

### "Take a moment to practice installing and loading modules on the target host. Answer "COMPLETE" when done."

Students are highly encouraged to practice installing and loading modules on the target host, then once done, type `COMPLETE`.

Answer: `COMPLETE`

# User and Group Management

## Question 1

### "What resource can provide Windows environments with directory services to manage users, computers, and more? (full name not abbreviation)"

`Active Directory` is the resource that provides Windows environments with directory services to manage users, computers, and more:

![[HTB Solutions/Others/z. images/40ebe9ef7577e79d9269b0ff3846af9a_MD5.jpg]]

Answer: `Active Directory`

# User and Group Management

## Question 2

### "What PowerShell Cmdlet will display all LOCAL users on a host?"

The `Get-LocalUser` `cmdlet` displays all local users on a host:

![[HTB Solutions/Others/z. images/ed5a481fdc8097b2eb3ad272e551cfc3_MD5.jpg]]

Answer: `Get-LocalUser`

# User and Group Management

## Question 3

### "Connect to the target host and search for a domain user with the given name of Robert. What is this users Surname?"

Students first need to connect to the target host with SSH, authenticating as `mtanaka:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh mtanaka@STMIP
```

```
┌─[us-academy-2]─[10.10.14.169]─[htb-ac594497@htb-e4irszwlfg]─[~]
└──╼ [★]$ ssh mtanaka@10.129.77.25

mtanaka@10.129.77.25's password: 

Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\MTanaka> 
```

Then, students need to import the `ActiveDirectory` PowerShell module and run the `Get-ADUser` `cmdlet`, filtering for `GivenName` that is like `robert`:

Code: powershell

```powershell
Import-Module ActiveDirectory 
Get-ADUser -Filter {GivenName -like 'robert'}
```

```
PS C:\Users\MTanaka> Import-Module ActiveDirectory                  
PS C:\Users\MTanaka> Get-ADUser -Filter {GivenName -like 'robert'}                                           

DistinguishedName : CN=Robert Loxley,CN=Users,DC=greenhorn,DC=corp
Enabled           : False
GivenName         : Robert
Name              : Robert Loxley
ObjectClass       : user
ObjectGUID        : 2c4507e4-f1d0-4622-b73b-8bfc8847dfd7
SamAccountName    : RLoxley
SID               : S-1-5-21-1480833693-1324064541-2711030367-1604
Surname           : Loxley
UserPrincipalName : RLoxley@greenhorn.corp
```

The user's surname is shown to be `Loxley`.

Answer: `Loxley`

# Working with Files and Directories

## Question 1

### "What Cmdlet has an alias of "cat" ?"

The `Get-Content` `cmdlet` has an alias of `cat`:

![[HTB Solutions/Others/z. images/35de55fc02f610116c208fea9f81e77c_MD5.webp]]

Answer: `Get-Content`

# Working with Files and Directories

## Question 2

### "What Cmdlet can we use to create new files and folders?"

The `New-Item` `cmdlet` can be used to create new files and folders:

![[HTB Solutions/Others/z. images/d2b808857768532c63d229fc88b4f745_MD5.webp]]

Answer: `New-Item`

# Working with Files and Directories

## Question 3

### "Using the skills discussed in this section, practice creating, editing, and removing files and directories on the target host provided. Type COMPLETE as the answer below when you are ready to move on."

Students are highly encouraged to practice creating, editing, and removing files and directories on the target host provided, then once done, type `COMPLETE`.

Answer: `COMPLETE`

# Finding & Filtering Content

## Question 1

### "What defines the functions our objects have?"

`Methods` define the functions that objects have:

![[HTB Solutions/Others/z. images/5cf102e3b6706dc593b4465e3c64e4a1_MD5.webp]]

Answer: `Methods`

# Finding & Filtering Content

## Question 2

### "What Cmdlet can show us the properties and methods of an object?"

The `Get-Member` `cmdlet` can show the properties and methods of an object:

!![[HTB Solutions/Others/z. images/54d1ca40f2a3d4a94ff0f7c87f4e977f_MD5.webp]] Answer: `Get-Member`

# Finding & Filtering Content

## Question 3

### "If we wanted to look through a directory and all sub-directories for something, what modifier would we use with the Get-ChildItem Cmdlet?"

The `-Recurse` modifier of the `cmdlet` `Get-Children` allows looking through a directory and all sub-directories:

![[HTB Solutions/Others/z. images/329dedd3bc2f59fabc3c92ecc3ad9f07_MD5.webp]]

Answer: `-Recurse`

# Working with Services

## Question 1

### "What Cmdlet will show us the current services of a host?"

The `Get-Service` `cmdlet` show the current services of a host:

![[HTB Solutions/Others/z. images/d0be6ab770f9eb118ef48a08f6aaefba_MD5.webp]]

Answer: `Get-Service`

# Working with Services

## Question 2

### "If we wanted to start the Windows Defender Service, what command would we use?"

The command `Start-Service WinDefend` starts the `Windows Defender Service`:

![[HTB Solutions/Others/z. images/8f089f30685b2782d623d78233a25af3_MD5.webp]]

Answer: `Start-Service WinDefend`

# Working with Services

## Question 3

### "What Cmdlet will allow us to execute a command on a remote host?"

The `Invoke-Command` `cmdlet` allows executing commands on a remote host:

![[HTB Solutions/Others/z. images/2d438e88bc8cf3c5717445ea6ee66bdd_MD5.webp]]

Answer: `Invoke-Command`

# Working with the Registry

## Question 1

### "A registry entry is made up of two pieces, a 'Key' and ' ' . What is the second piece?"

A registry entry is made up of two pieces, a `Key` and `Values`:

![[HTB Solutions/Others/z. images/db122d797b19eb390653cc57dcbe497e_MD5.webp]]

Answer: `values`

# Working with the Registry

## Question 2

### "What is the abbreviation for "HKey\_Current\_User"."

`HKCU` is the abbreviation for `HKey_Current_User`:

![[HTB Solutions/Others/z. images/b3827465699965f870b164ce6ca960f5_MD5.webp]]

Answer: `HKCU`

# Working with the Registry

## Question 3

### "Take some time to practice adding and modifying the registry. Use the target host as a testbed and type "COMPLETE" as the answer below when you are done."

Students are highly encouraged to practice adding and modifying the registry on the target host, and once done, type `COMPLETE`.

Answer: `COMPLETE`

# Working with the Windows Event Log

## Question 1

### "Explore the targets provided and practice your Event Log PowerShell Kung-Fu. Type COMPLETE as the answer when finished."

Students are highly encouraged to explore the target provided and practice their Windows Event Log PowerShell Kung-Fu, and once done, type `COMPLETE`.

Answer: `COMPLETE`

# Networking Management from The CLI

## Question 1

### "What common protocol is used to resolve names to IP addresses."

The `DNS` protocol is used to resolve names to IP addresses:

![[HTB Solutions/Others/z. images/7837a0c997b08e7e793e87e45e747255_MD5.webp]]

Answer: `DNS`

# Networking Management from The CLI

## Question 2

### "What PowerShell cmdlet will show us the IP configurations of the hosts network adapters."

The PowerShell `cmdlet` `Get-NetIPAddress` will show the IP configurations of the host's network adapters:

![[HTB Solutions/Others/z. images/0e2807453548037366fb12f6f9a6ced6_MD5.webp]]

Answer: `Get-NetIPAddress`

# Networking Management from The CLI

## Question 3

### "What command can enable and configure Windows Remote Management on a host?"

The command `winrm quickconfig` can enable and configure `Windows Remote Management` on a host:

![[HTB Solutions/Others/z. images/fd20b982858eee2bab7a7d41acacb2a5_MD5.webp]]

Answer: `winrm quickconfig`

# Skills Assessment

## Question 1

### "The flag will print in the banner upon successful login on the host via SSH."

Students need to connect with SSH to the target host, authenticating as `user0:Start!`, to find the flag `D0wn_the_rabbit_H0!3` inside the SSH banner:

Code: shell

```shell
ssh user0@STMIP
```

```
┌─[us-academy-2]─[10.10.14.169]─[htb-ac594497@htb-jnedinqm1v]─[~]
└──╼ [★]$ ssh user0@10.129.204.9

The authenticity of host '10.129.204.9 (10.129.204.9)' can't be established.
ECDSA key fingerprint is SHA256:qYZB2SYyE6eErvaUc17OozYtmIaUKYK9j+tmigKWTVM.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.204.9' (ECDSA) to the list of known hosts.
#################################################################
#                   _    _           _   _                      #
#                  / \  | | ___ _ __| |_| |                     #
#                 / _ \ | |/ _ \ '__| __| |                     #
#                / ___ \| |  __/ |  | |_|_|                     #
#               /_/   \_\_|\___|_|   \__(_)                     #
#                                                               #
#  You are entering into a secured area! Your IP, Login Time,   #
#   Username has been noted and has been sent                   #
#              D0wn_the_rabbit_H0!3 to the server               #
#                       administrator!                          #
#   This service is restricted to authorized users only. All    #
#            activities on this system are logged.              #
#  Unauthorized access will be fully investigated and reported  #
#        to the appropriate law enforcement agencies.           #
#################################################################

user0@10.129.204.9's password: 

Microsoft Windows [Version 10.0.22000.1219]
(c) Microsoft Corporation. All rights reserved.

user0@ACADEMY-ICL11 C:\Users\user0>
```

Answer: `D0wn_the_rabbit_H0!3`

# Skills Assessment

## Question 2

### "Access the host as user1 and read the contents of the file "flag.txt" located in the users Desktop."

Students need to connect with SSH to the target host, authenticating as the user `user1` and the password `D0wn_the_rabbit_H0!3` that was attained in the previous question:

Code: shell

```shell
ssh user1@STMIP
```

```
┌─[us-academy-2]─[10.10.14.169]─[htb-ac594497@htb-jnedinqm1v]─[~]
└──╼ [★]$ ssh user1@10.129.204.9

<SNIP>
user1@10.129.204.9's password: 

Microsoft Windows [Version 10.0.22000.1219]
(c) Microsoft Corporation. All rights reserved.

user1@ACADEMY-ICL11 C:\Users\user1>
```

Then, students need to print out the flag from "flag.txt" which is under the `Desktop` directory for `user1`:

Code: cmd

```cmd
type Desktop\flag.txt
```

```
user1@ACADEMY-ICL11 C:\Users\user1>type Desktop\flag.txt

Nice and Easy!
```

Answer: `Nice and Easy!`

# Skills Assessment

## Question 3

### "If you search and find the name of this host, you will find the flag for user2."

Students first need to connect to the target host with SSH, authenticating as `user2:Nice and Easy!`:

Code: shell

```shell
ssh user2@STMIP
```

```
┌─[us-academy-2]─[10.10.14.169]─[htb-ac594497@htb-jnedinqm1v]─[~]
└──╼ [★]$ ssh user2@10.129.204.9

<SNIP>

user2@10.129.204.9's password: 

Microsoft Windows [Version 10.0.22000.1219]
(c) Microsoft Corporation. All rights reserved.

user2@ACADEMY-ICL11 C:\Users\user2>
```

Then, students need to enumerate the host name using the `hostname` command, finding it to be `ACADEMY-ICL11`:

Code: cmd

```cmd
hostname
```

```
Microsoft Windows [Version 10.0.22000.1219]
(c) Microsoft Corporation. All rights reserved.

user2@ACADEMY-ICL11 C:\Users\user2>hostname

ACADEMY-ICL11
```

Answer: `ACADEMY-ICL11`

# Skills Assessment

## Question 4

### "How many hidden files exist on user3's Desktop?"

Students need to connect to the target host with SSH and authenticate as `user3:ACADEMY-ICL11`:

Code: shell

```shell
ssh user@STMIP
```

```
┌─[us-academy-2]─[10.10.14.169]─[htb-ac594497@htb-jnedinqm1v]─[~]
└──╼ [★]$ ssh user3@10.129.204.9

<SNIP>

user3@10.129.204.9's password: 

Microsoft Windows [Version 10.0.22000.1219]
(c) Microsoft Corporation. All rights reserved.

user3@ACADEMY-ICL11 C:\Users\user3>
```

Then, students need to navigate to the Desktop directory for the current user and enumerate all hidden files with `dir /A:H`, finding `101` files:

Code: cmd

```cmd
cd Desktop
dir /A:H
```

```
user3@ACADEMY-ICL11 C:\Users\user3>cd Desktop

user3@ACADEMY-ICL11 C:\Users\user3\Desktop>dir /A:H

 Volume in drive C has no label.
 Volume Serial Number is F684-763E

 Directory of C:\Users\user3\Desktop

06/29/2022  01:40 PM               282 desktop.ini
07/18/2022  06:53 AM                 0 file-1.txt
07/18/2022  07:30 AM                 0 file10.txt
07/18/2022  07:30 AM                 0 file11.txt
<SNIP>
07/18/2022  07:30 AM                 0 file98.txt
07/18/2022  07:30 AM                 0 file99.txt
06/29/2022  01:41 PM             2,354 Microsoft Edge.lnk
             101 File(s)          2,636 bytes
               0 Dir(s)  10,212,569,088 bytes free
```

Answer: `101`

# Skills Assessment

## Question 5

### "User4 has a lot of files and folders in their Documents folder. The flag can be found within one of them."

Students first need to connect to the target host with SSH and authenticate as `user4:ACADEMY-101`:

Code: shell

```shell
ssh user4@STMIP
```

```
┌─[us-academy-2]─[10.10.14.169]─[htb-ac594497@htb-jnedinqm1v]─[~]
└──╼ [★]$ ssh user4@10.129.204.9

<SNIP>

user3@10.129.204.9's password: 

Microsoft Windows [Version 10.0.22000.1219]
(c) Microsoft Corporation. All rights reserved.

user4@ACADEMY-ICL11 C:\Users\user4>
```

The flag is located in a file within a nested directory, therefore, students can use `Get-ChildItem` and utilize the `-Recurse` modifier:

Code: powershell

```powershell
Get-ChildItem -recurse -Include *.txt | where{$_.Length -ne 0}
```

```
PS C:\Users\user4> Get-ChildItem -recurse -Include *.txt | where{$_.Length -ne 0}

    Directory: C:\Users\user4\Documents\3\4

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         7/26/2022   2:18 PM             44 flag.txt
```

With the location of the flag revealed `C:\Users\user4\Documents\3\4\`, students can now read its contents:

Code: powershell

```powershell
type C:\Users\user4\Documents\3\4\flag.txt
```

```
PS C:\Users\user4> type C:\Users\user4\Documents\3\4\flag.txt

Digging in The nest
```

Answer: `Digging in The nest`

# Skills Assessment

## Question 6

### "How many users exist on this host? (Excluding the DefaultAccount and WDAGUtility)"

Students need to connect to the target host with SSH and authenticate as `user5:Digging in The nest`:

Code: shell

```shell
ssh user5@STMIP
```

```
┌─[us-academy-2]─[10.10.14.169]─[htb-ac594497@htb-jnedinqm1v]─[~]
└──╼ [★]$ ssh user5@10.129.204.9

<SNIP>

user3@10.129.204.9's password: 

Microsoft Windows [Version 10.0.22000.1219]
(c) Microsoft Corporation. All rights reserved.

user5@ACADEMY-ICL11 C:\Users\user5>
```

Subsequently, students need to run `Get-LocalUser` to find that there are 14 accounts:

Code: powershell

```powershell
Get-LocalUser
```

```
PS C:\Users\user5> Get-LocalUser

Name               Enabled Description
----               ------- -----------
Administrator      True    Built-in account for administering the computer/d...
DefaultAccount     False   A user account managed by the system.
Guest              False   Built-in account for guest access to the computer...
htb-student        True
user0              True
user1              True
user100            True
user2              True
user3              True
user4              True
user5              True
user66             False
user77             False
user88             False
user99             False
WDAGUtilityAccount False   A user account managed and used by the system for... 
```

Answer: `14`

# Skills Assessment

## Question 7

### "For this level, you need to find the Registered Owner of the host. The Owner name is the flag."

Students first need to connect to the target host with SSH and authenticate as `user6:14`:

Code: shell

```shell
ssh user6@STMIP
```

```
┌─[us-academy-2]─[10.10.14.169]─[htb-ac594497@htb-jnedinqm1v]─[~]
└──╼ [★]$ ssh user6@10.129.204.9

<SNIP>

user6@10.129.204.9's password: 

Microsoft Windows [Version 10.0.22000.1219]
(c) Microsoft Corporation. All rights reserved.

greenhorn\user6@ACADEMY-ICL11 C:\Users\user6.GREENHORN>
```

Then, to enumerate the registered owner, students need to run `systeminfo`, finding the registered owner to be `htb-student`:

Code: cmd

```cmd
systeminfo
```

```
greenhorn\user6@ACADEMY-ICL11 C:\Users\user6.GREENHORN>systeminfo

Host Name:                 ACADEMY-ICL11
OS Name:                   Microsoft Windows 11 Pro
OS Version:                10.0.22000 N/A Build 22000
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Member Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          htb-student
Registered Organization:   
Product ID:                00331-20309-59368-AA413
Original Install Date:     6/14/2022, 8:21:28 PM
System Boot Time:          12/7/2022, 12:38:31 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
                           [02]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.16707776.B64.2008070230, 8/7/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     8,191 MB
Available Physical Memory: 6,712 MB
Virtual Memory: Max Size:  9,471 MB
Virtual Memory: Available: 8,200 MB
Virtual Memory: In Use:    1,271 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    greenhorn.corp
Logon Server:              N/A
Hotfix(s):                 4 Hotfix(s) Installed.
                           [01]: KB5020617
                           [02]: KB5012170
                           [03]: KB5019961
                           [04]: KB5017850
Network Card(s):           2 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.204.9
                                 [02]: fe80::d577:d282:8f6e:6a00
                                 [03]: dead:beef::2434:8c48:4de:a5ce
                                 [04]: dead:beef::bc03:f010:676b:fea7
                                 [05]: dead:beef::17
                           [02]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet1
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 172.16.5.43
                                 [02]: fe80::b160:95c6:94d0:cc02
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

Answer: `htb-student`

# Skills Assessment

## Question 8

### "For this level, you must successfully authenticate to the Domain Controller host at 172.16.5.155 via SSH after first authenticating to the target host. This host seems to have several PowerShell modules loaded, and this user's flag is hidden in one of them."

Students need to connect to the target host with SSH and authenticate as `user7:htb-student`:

Code: shell

```shell
ssh user7@STMIP
```

```
┌─[us-academy-2]─[10.10.14.169]─[htb-ac594497@htb-jnedinqm1v]─[~]
└──╼ [★]$ ssh user7@16.129.204.9

<SNIP>

user7@10.129.204.9's password: 

Microsoft Windows [Version 10.0.22000.1219]
(c) Microsoft Corporation. All rights reserved.

greenhorn\user7@ACADEMY-ICL11 C:\Users\user7.GREENHORN>
```

Then, using PowerShell, students can SSH again from the target host directly to the Domain Controller:

Code: powershell

```powershell
ssh user7@172.16.5.155
```

```
PS C:\Users\user7.GREENHORN> ssh user7@172.16.5.155

user7@172.16.5.155's password: 

Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

greenhorn\user7@ACADEMY-ICL-DC C:\Users\user7>powershell

Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\user7>  
```

Students now need to enumerate available PowerShell modules, then, they need to import the module `Flag-Finder` and run its `cmdlet` `Get-Flag` to retrieve the flag:

Code: powershell

```powershell
Get-Module
Import-Module Flag-Finder
Get-Flag
```

```
PS C:\Users\user7> Get-Module

ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Script     0.0        Flag-Finder                         Get-Flag
Manifest   3.1.0.0    Microsoft.PowerShell.Utility        {Add-Member, Add-Type, Clear-Variable, Compare-O... 
Script     2.0.0      PSReadline                          {Get-PSReadLineKeyHandler, Get-PSReadLineOption,... 

PS C:\Users\user7> Import-Module Flag-Finder
PS C:\Users\user7> Get-Flag

The  
Flag you are looking for is {Modules_make_pwsh_run!}
```

Answer: `Modules_make_pwsh_run!`

# Skills Assessment

## Question 9

### "This flag is the GivenName of a domain user with the Surname "Flag"."

Students first need to connect to the target host with SSH and authenticate as `user8:Modules_make_pwsh_run!`:

Code: shell

```shell
ssh user8@STMIP
```

```
┌─[us-academy-2]─[10.10.14.169]─[htb-ac594497@htb-jnedinqm1v]─[~]
└──╼ [★]$ ssh user8@16.129.204.9

<SNIP>

user7@10.129.204.9's password: 

Microsoft Windows [Version 10.0.22000.1219]
(c) Microsoft Corporation. All rights reserved.

greenhorn\user8@ACADEMY-ICL11 C:\Users\user8.GREENHORN>
```

Subsequently, students need to run PowerShell, import the module `AcitveDirectory`, and utilize the `Get-ADUser` `cmdlet`:

Code: powershell

```powershell
powershell
Import-Module ActiveDirectory
Get-ADUser -filter * | select GivenName,Surname
```

```
greenhorn\user8@ACADEMY-ICL11 C:\Users\user8.GREENHORN>powershell  

Windows PowerShell                                                                                            Copyright (C) Microsoft Corporation. All rights reserved.                                                                                                                                                                   
Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\user8.GREENHORN> Import-Module ActiveDirectory
PS C:\Users\user8.GREENHORN> Get-ADUser -filter * | select GivenName,Surname

GivenName Surname
--------- -------

Rick      Flag
user6
```

Students will find the value for `GivenName` to be `Rick` for the `Surname` "Flag".

Answer: `Rick`

# Skills Assessment

## Question 10

### "Use the tasklist command to print running processes and then sort them in reverse order by name. The name of the process that begins with "vm" is the flag for this user."

Students need to connect to the target host with SSH, authenticating as `user9:Rick`:

Code: shell

```shell
ssh user9@STMIP
```

```
┌─[us-academy-2]─[10.10.14.169]─[htb-ac594497@htb-jnedinqm1v]─[~]
└──╼ [★]$ ssh user9@10.129.118.65

user9@10.129.118.65's password: 

Microsoft Windows [Version 10.0.22000.1219]
(c) Microsoft Corporation. All rights reserved.

greenhorn\user9@ACADEMY-ICL11 C:\Users\user9.GREENHORN>
```

Afterward, students need to use `tasklist` and pipe its output to `sort` passing along the `/R` modifier; students will find that the fourth service is `vmtoolsd.exe`:

Code: cmd

```cmd
tasklist | sort /R
```

```
greenhorn\user9@ACADEMY-ICL11 C:\Users\user9.GREENHORN>tasklist | sort /R

WmiPrvSE.exe                  4272 Services                   0     20,724 K
winlogon.exe                   672 Console                    1     17,628 K
wininit.exe                    620 Services                   0      7,088 K
vmtoolsd.exe                  3300 Services                   0     21,912 K
<SNIP>
```

Answer: `vmtoolsd.exe`

# Skills Assessment

## Question 11

### "To grab this final flag, what user account has many Event ID (4625) logon failures generated in rapid succession for it which is indicative of a password brute forcing attack (flag is the name of the user account)?"

Students first need to connect to the target machine using SSH, authenticating as `user10:vmtoolsd.exe`:

Code: shell

```shell
ssh user10@STMIP
```

```
┌─[us-academy-2]─[10.10.14.169]─[htb-ac594497@htb-jnedinqm1v]─[~]
└──╼ [★]$ ssh user10@10.129.118.65

<SNIP>

user10@10.129.118.65's password: 

Microsoft Windows [Version 10.0.22000.1219]
(c) Microsoft Corporation. All rights reserved.

greenhorn\user10@ACADEMY-ICL11 C:\Users\user10>
```

Then, students need to SSH once again into the Domain Controller and run PowerShell:

Code: cmd

```cmd
ssh user10@172.16.5.155
powershell
```

```
greenhorn\user10@ACADEMY-ICL11 C:\Users\user10>ssh user10@172.16.5.155

The authenticity of host '172.16.5.155 (172.16.5.155)' can't be established.
ECDSA key fingerprint is SHA256:0Uuw7efAWzL39QabbgoWf3AFR0GZBtXfhylSJXm5bG4.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.16.5.155' (ECDSA) to the list of known hosts.
user10@172.16.5.155's password: 

Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

greenhorn\user10@ACADEMY-ICL-DC C:\Users\user10>powershell

Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\user10>
```

At last, students need to use the `Get-WinEvent` `cmdlet` to enumerate the user who has been bruteforcing the system, finding it to be `justalocaladmin`:

```powershell
Get-WinEvent -FilterHashTable @{LogName='Security';ID='4625'} | Select-Object -ExpandProperty Message
```
```
PS C:\Users\user10> Get-WinEvent -FilterHashTable @{LogName='Security';ID='4625'
} | Select-Object -ExpandProperty Message

An account failed to log on.

Subject:
        Security ID:            S-1-0-0 
        Account Name:           -       
        Account Domain:         -       
        Logon ID:               0x0     

Logon Type:                     3  

<SNIP>

Account For Which Logon Failed:
        Security ID:            S-1-0-0
        Account Name:           justalocaladmin
        Account Domain:         GREENHORN

Failure Information:
        Failure Reason:         Unknown user name or bad password.
        Status:                 0xC000006D
        Sub Status:             0xC000006A
```

Answer: `justalocaladmin`