| Section | Question Number | Answer |
| --- | --- | --- |
| Windows File Transfer Methods | Question 1 | b1a4ca918282fcd96004565521944a3b |
| Windows File Transfer Methods | Question 2 | f458303ea783c224c6b4e7ef7f17eb9d |
| Linux File Transfer Methods | Question 1 | 5d21cf3da9c0ccb94f709e2559f3ea50 |
| Linux File Transfer Methods | Question 2 | 159cfe5c65054bbadb2761cfa359c8b0 |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Windows File Transfer Methods

## Question 1

### "Download the file flag.txt from the web root using wget from the Pwnbox. Submit the contents of the file as your answer."

Many approaches can be taken to solve this question.

A first approach is whereby students use the .NET `System.Net.WebClient DownloadFile` method through the `PowerShell` terminal provided in `Pwnbox`/`PMVPN` (the second parameter of the method must be changed accordingly to match an existing directory name, followed by the name to be given for the downloaded file):

Code: powershell

```powershell
(New-Object System.Net.WebClient).DownloadFile('http://STMIP/flag.txt', "/home/htb-ac413848/flag.txt")
```

```
┌[htb-mwcr7xr7fn@htb-ac413848]-[11:07-14/10]-[/home/htb-ac413848]
└╼$ (New-Object System.Net.WebClient).DownloadFile('http://10.129.201.55/flag.txt', '/home/htb-ac413848/flag.txt')
```

Another approach is by using `wget`:

Code: powershell

```powershell
wget http://STMIP/flag.txt
```

```
┌[htb-mwcr7xr7fn@htb-ac413848]-[11:07-14/10]-[/home/htb-ac413848]
└╼$ wget http://10.129.201.55/flag.txt

2022-02-22 12:50:20 (3.43 MB/s) - ‘flag.txt’ saved [32/32]
```

Students then need to print out the contents of the flag file "flag.txt", finding it to be `b1a4ca918282fcd96004565521944a3b`:

Code: powershell

```powershell
type ./flag.txt
```

```
┌[htb-mwcr7xr7fn@htb-ac413848]-[11:07-14/10]-[/home/htb-ac413848]
└╼$ type ./flag.txt

b1a4ca918282fcd96004565521944a3b
```

Answer: `b1a4ca918282fcd96004565521944a3b`

# Windows File Transfer Methods

## Question 2

### "Upload the attached file named upload\_win.zip to the target using the method of your choice. Once uploaded, unzip the archive, and run "hasher upload\_win.txt" from the command line. Submit the generated hash as your answer."

Students first need to download the [upload\_win.zip](https://academy.hackthebox.com/storage/modules/24/upload_win.zip) file into `Pwnbox`/`PMVPN` using `wget`:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/24/upload_win.zip
```

```
┌[htb-mwcr7xr7fn@htb-ac413848]-[11:07-14/10]-[/home/htb-ac413848]
└╼$ wget https://academy.hackthebox.com/storage/modules/24/upload_win.zip

--2022-02-22 13:09:45-- https://academy.hackthebox.com/storage/
modules/24/upload_win.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)
104.18.20.126, 104.18.21.126
Connecting to academy.hackthebox.com (academy.hackthebox.com)
|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 194 [application/zip]
Saving to: ‘upload_win.zip’

upload_win.zip	100%[=================>]  194  --.-KB/s in 0s      

2022-02-22 13:09:46 (3.60 MB/s)-‘upload_win.zip’saved [194/194]
```

Then, students need to RDP into the spawned Windows target by using any Remote Desktop Protocol (RDP) client, such as `xfreerdp` (it is important that students provide as input `Y`, when prompted for the certificate trust), using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:HTB_@cademy_stdnt!
```

```
┌─[us-academy-1]─[10.10.14.4]─[htb-ac413848@htb-mwcr7xr7fn]─[~]
└──╼ [★]$ xfreerdp /v:10.129.201.55 /u:htb-student /p:HTB_@cademy_stdnt!

[13:14:44:883] [3689:3690] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
<SNIP>
[13:14:44:299] [3689:3690] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
<SNIP>
Do you trust the above certificate? (Y/T/N) Y
```

![[HTB Solutions/CPTS/z. images/d7254d58095bc9075eb9353c80acbf04_MD5.jpg]]

Subsequently, students need to start an HTTP server on `Pwnbox`/`PMVPN` in the same directory where the "upload\_win.zip" file was downloaded:

Code: shell

```shell
python3 -m http.server PWNPO
```

```
┌─[us-academy-1]─[10.10.14.4]─[htb-ac413848@htb-mwcr7xr7fn]─[~]
└──╼ [★]$ python3 -m http.server PWNPO

Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

Students then need to transfer the "upload\_win.zip" file from `Pwnbox`/`PMVPN` to the spawned Windows target machine using `iwr`:

Code: powershell

```powershell
iwr http://PWNIP:PWNPO/upload_win.zip -OutFile upload_win.zip
```

```
PS C:\Users\htb-student\Desktop> iwr http://10.10.15.151:8080/upload_win.zip -OutFile upload_win.zip
```

![[HTB Solutions/CPTS/z. images/b1006fad0715789a0b5a949740cdb447_MD5.jpg]]

After successfully transferring the file, students need to unzip it, and at last, use `hasher.exe` on "upload\_win.txt", to attain the flag `f458303ea783c224c6b4e7ef7f17eb9d`:

Code: powershell

```powershell
Expand-Archive .\upload_win.zip
hasher.exe .\upload_win\upload_win.txt
```

```
PS C:\Users\htb-student\Desktop> Expand-Archive .\upload_win.zip
PS C:\Users\htb-student\Desktop> hasher.exe .\upload_win\upload_win.txt

f458303ea783c224c6b4e7ef7f17eb9d
```

Answer: `f458303ea783c224c6b4e7ef7f17eb9d`

# Windows File Transfer Methods

## Question 3

### "Connect to the target machine via RDP and practice various file transfer operations (upload and download) with your attack host. Type "DONE" when finished."

Students are highly encouraged to practice various file transfer operations with the myriad of methods demonstrated in the section then, once done, type `DONE`.

Answer: `DONE`

# Linux File Transfer Methods

## Question 1

### "Download the file flag.txt from the web root using Python from the Pwnbox. Submit the contents of the file as your answer."

Using Python, students need to utilize the `urlretrieve` function from the `urllib.request` module to download the file from the spawned target machine:

Code: shell

```shell
python3
import urllib.request as request
request.urlretrieve("http://STMIP/flag.txt", "flag.txt");
```

```
┌─[us-academy-1]─[10.10.14.4]─[htb-ac413848@htb-mwcr7xr7fn]─[~]
└──╼ [★]$ python3

Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
>>> import urllib.request as request
>>> request.urlretrieve("http://10.129.181.183/flag.txt", "flag.txt");
('flag.txt', <http.client.HTTPMessage object at 0x7f7585d7b160>)
```

Then, students need to read the contents of the file, to attain the flag `5d21cf3da9c0ccb94f709e2559f3ea50`:

Code: shell

```shell
cat flag.txt
```

```
┌─[us-academy-1]─[10.10.14.4]─[htb-ac413848@htb-mwcr7xr7fn]─[~]
└──╼ [★]$ cat flag.txt

5d21cf3da9c0ccb94f709e2559f3ea50
```

Answer: `5d21cf3da9c0ccb94f709e2559f3ea50`

# Linux File Transfer Methods

## Question 2

### "Upload the attached file named upload\_nix.zip to the target using the method of your choice. Once uploaded, SSH to the box, unzip the file, and run "hasher upload\_nix.txt" from the command line. Submit the generated hash as your answer."

Students first need to SSH into the spawned target machine using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[us-academy-1]─[10.10.14.4]─[htb-ac413848@htb-mwcr7xr7fn]─[~]
└──╼ [★]$ ssh htb-student@10.129.181.183

htb-student@10.129.181.183's password: 
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-47-generic x86_64)

<SNIP>

htb-student@nix04:~$
```

Then, students need to download the [upload\_nix.zip](https://academy.hackthebox.com/storage/modules/24/upload_nix.zip) file into `Pwnbox`/`PMVPN` using `wget` and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/24/upload_nix.zip
unzip upload_nix.zip
```

```
┌─[us-academy-1]─[10.10.14.4]─[htb-ac413848@htb-mwcr7xr7fn]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/24/upload_nix.zip

--2022-02-22 14:13:47--  https://academy.hackthebox.com/storage/modules/24/upload_nix.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 194 [application/zip]
Saving to: ‘upload_nix.zip’

upload_nix.zip	100%[=================>]  194  --.-KB/s in 0s      
2022-02-22 14:13:47 (2.64 MB/s) - ‘upload_nix.zip’ saved [194/194]

┌─[us-academy-1]─[10.10.14.4]─[htb-ac413848@htb-mwcr7xr7fn]─[~]
└──╼ [★]$ unzip upload_nix.zip

Archive:  upload_nix.zip
extracting: upload_nix.txt
```

Subsequently, students need to transfer the "upload\_nix.txt" file from `Pwnbox`/`PMVPN` to the Linux spawned target machine. A first method is whereby students use `scp` (i.e., `OpenSSH secure file copy`), utilizing the credentials `htb-student:HTB_@cademy_stdnt!`:

```shell
scp upload_nix.txt htb-student@STMIP:~/
```
```
┌─[us-academy-1]─[10.10.14.4]─[htb-ac413848@htb-mwcr7xr7fn]─[~]
└──╼ [★]$ scp upload_nix.txt htb-student@10.129.181.183:~/

htb-student@10.129.181.183's password: 
upload_nix.txt	100%   32    10.3KB/s   00:00
```

Another easy and quick method is whereby students use `nc`. First, the receiving host (i.e. the Linux spawned target machine) listens on a port and redirects the input it receives (which is "upload\_nix.txt" in this case):

```shell
nc -lp STMPO > upload_nix.txt
```
```
htb-student@nix04:~$ nc -lp 9999 > upload_nix.txt
```

Then, the sending host (i.e. `Pwnbox`/`PMVPN`) sends the "upload\_nix.txt" file by redirecting it as output through the `nc` connection socket:

```shell
nc -w 3 STMIP STMPO < upload_nix.txt
```
```
┌─[us-academy-1]─[10.10.14.4]─[htb-ac413848@htb-mwcr7xr7fn]─[~]
└──╼ [★]$ nc -w 3 10.129.181.183 9999 < upload_nix.txt
```

At last, students need to use `hasher` on the "upload\_nix.txt" file, to attain the flag `159cfe5c65054bbadb2761cfa359c8b0`:

```
hasher upload_nix.txt
```
```
htb-student@nix04:~$ hasher upload_nix.txt

159cfe5c65054bbadb2761cfa359c8b0
```

Answer: `159cfe5c65054bbadb2761cfa359c8b0`

# Linux File Transfer Methods

## Question 3

### "Connect to the target machine via SSH and practice various file transfer operations (upload and download) with your attack host. Type "DONE" when finished."

Students are highly encouraged to practice various file transfer operations with the myriad of methods demonstrated in the section, then once done, type `DONE`.

Answer: `DONE`

# Transferring Files with Code

## Question 1

### "Connect to the target machine via SSH (Username: htb-student | Password:HTB\_@cademy\_stdnt!) and practice various file transfer operations (upload and download) with your attack host. Type "DONE" when finished."

Students are highly encouraged to practice various file transfer operations with the myriad of methods demonstrated in the section, then once done, type `DONE`.

Answer: `DONE`

# Miscellaneous File Transfer Methods

## Question 1

### "Use xfreerdp or rdesktop to connect to the target machine via RDP (Username: htb-student | Password:HTB\_@cademy\_stdnt!) and mount a Linux directory to practice file transfer operations (upload and download) with your attack host. Type "DONE" when finished."

Students are highly encouraged to practice various file transfer operations with the myriad of methods demonstrated in the section then, once done, type `DONE`.

Answer: `DONE`

# Living off The Land

## Question 1

### "Connect to the target machine via RDP ((Username: htb-student | Password:HTB\_@cademy\_stdnt!)) and use Living Off The Land techniques presented in this section or any other found on the LOLBAS and GTFOBins websites to transfer files between the Pwnbox and the Windows target. Type "DONE" when finished."

Students are highly encouraged to use Living Off The Land techniques to practice various file transfer operations, and once done, type `DONE`.

Answer: `DONE`