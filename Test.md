# WEB07.DEV.JIJISTUDIO.COM

- found a repository Downloader with a commit 'removed secrets' that contained creds for dev01 user

- .110 is vulnerable to RCE via vulnerable github v13.10

- used gitlab-rake to reset gitlab 'root' password

- gitlab root project 'monitor' contained ssh key for monitor user

- monitor is a member of sudo

- WEB07 is a pivot to 172.16.116.110/24

- found ricky.davies ssh key in /root

- cracked the password for ricky.davies ssh key

  

# SRV01.DEV.JIJISTUDIO.COM

- found ricky.davies ssh key logs into SRV01

- ricky.davies has SeBackupPrivilege on SRV01 and used to priv esc

- found SRV01 has constrained delegation to FILE01

  

# FILE01.DEV.JIJISTUDIO.COM

- abused SRV01 constrained delegation to FILE01 to obtain foothold and privilege escalation on FILE01

- dumped credentials from FILE01 using secretsdump which revealed mohammad.francis plain text password

- bloodhound showed mohammad.francis is a member of LAPS-Readers AD group and can read the LAPS password for WEB01

  

# WEB01.DEV.JIJISTUDIO.COM

- abused mohammad.francis membership of LAPS-Readers AD group to read the LAPS password for WEB01

- found a Web.config file using a db connection to DB03

  

# DB04.CORE-JIJISTUDIO.COM

- connecting to DB03 as WEB01$ allows impersonate as bridge_dev

- bridge_dev has a link to DB04 sql server

- using the link to DB04 the remote login is bridge_core and can impersonate sa

- enabled xp_cmdshell and loaded meterpreter

- identified mssql user has SeImpersonatePrivilege and used getsystem to priv esc

- found credentials in the administrator powershell history for pamela.james for ps-remoting into CLIENT02

  

# CLIENT02.CORE-JIJISTUDIO.COM

- used the discovered creds to ps-remote into CLIENT02 and obtain local.txt flag

- ==now have 10 flags==

- used PrivescCheck to identify a service binary that can be overwritten

- used c# revshell to obtain priv esc

- create a backdoor tester account as local admin

- use rdp to open an admin cmd prompt

- copy over lazagne.exe to obtain local admin hash

- use secretsdump with local admin hash to obtain saved service credentials for sally.jenkins (domain admin for core-jijistudio.com)

  

# DC03.CORE-JIJISTUDIO.COM

- used sally.jenkins to winrm into dc03.core-jijistudio.com but no flags were found

  

# WEB05.JIJISTUDIO.COM

- used the dev01 user creds discovered on WEB07 to log in to the web page

- enumerated embedded javascript that queries for retrieving license keys and found it vulnerable to command injection

- used the command injection vuln to download and execute a meterpreter payload and gained a shell

- shell user possessed the SeImpersonatePrivilege; used meterpreter getsystem to priv esc

  

# FILE02.JIJISTUDIO.COM

- WEB05 has 'AllowedToAct' privileges to FILE02

- abused the privilege to obtain administrator access to FILE02

- found a mail.eml file with reference to a user expecting a .docx file

  

# CLIENT01.JIJISTUDIO.COM

- phishing michael.adams@jijistudio.com achieves foothold on CLIENT01

- used fodhelper uac bypass to priv esc on CLIENT01

- found a keepass file on the administrator desktop

- cracked the keepass password

- keepass file contains a ssh key for VAULT02

  

# VAULT02.JIJISTUDIO.COM

- ssh key provided ssh access as vault to VAULT02

- found an ansible vault, cracked the password, and decrypted the vault

- used the decrypted vault password to priv esc as root

- found ansible hosts file reference to connecting to DB05

- found the ssh key for connecting to DB05

- ==15 flags==

  

# DB05.JIJISTUDIO.COM

- used the discovered ssh key from VAULT02 to ssh in as root

- found a kerberos ticket in /tmp for rhys.lucas

- bloodhound revealed rhys.lucas is a domain admin for` jijistudio.com`

- exfiltrated the ticket to kali

- used the ticket to obtain privileged access to DC01 and dump secrets

  

# DC01.JIJISTUDIO.COM

- used the kerberos ticket from DB05 as rhys.lucas to dump secrets from DC01 and gain domain admin access

- ==no flags on this host==

  

# MAIL01.JIJISTUDIO.COM

- used the kerberos ticket from DB05 as rhys.lucas to gain access via smbexec but ==no flags on this host==