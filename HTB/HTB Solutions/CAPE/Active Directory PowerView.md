| Section | Question Number | Answer |
| --- | --- | --- |
| PowerView/SharpView Overview & Usage | Question 1 | S-1-5-21-2974783224-3764228556-2640795941-1705 |
| PowerView/SharpView Overview & Usage | Question 2 | LOGISTICS.INLANEFREIGHT.LOCAL |
| PowerView/SharpView Overview & Usage | Question 3 | rita.grant |
| Enumerating AD Users | Question 1 | svc-scan |
| Enumerating AD Users | Question 2 | W4y\_am\_I\_d0ing\_Th1s? |
| Enumerating AD Users | Question 3 | WSUSupdatesvc |
| Enumerating AD Users | Question 4 | bob.barker |
| Enumerating AD Groups | Question 1 | jennifer.chandler |
| Enumerating AD Groups | Question 2 | samantha.patel |
| Enumerating AD Computers | Question 1 | 5 |
| Enumerating AD Computers | Question 2 | ec252fbd-765d-4833-9f9d-f1eaf712089e |
| Enumerating AD Computers | Question 3 | Staff Workstations |
| Enumerating Domain ACLs | Question 1 | douglas.bull |
| Enumerating Domain ACLs | Question 2 | Client\_Invoices |
| Enumerating Domain ACLs | Question 3 | gillian.fisher |
| Enumerating Group Policy Objects (GPOs) | Question 1 | 8bb15712-8a05-47e7-9dcf-897999d695fe |
| Enumerating AD Trusts | Question 1 | LOGISTICS.INLANEFREIGHT.LOCAL |
| Enumerating AD Trusts | Question 2 | freightlogistics.local |
| Enumerating AD Trusts | Question 3 | Bidirectional |
| Active Directory PowerView - Skills Assessment | Question 1 | 24 |
| Active Directory PowerView - Skills Assessment | Question 2 | S-1-5-21-3394586996-1871716043-2583881113-1105 |
| Active Directory PowerView - Skills Assessment | Question 3 | 5 |
| Active Directory PowerView - Skills Assessment | Question 4 | Disable Defender |
| Active Directory PowerView - Skills Assessment | Question 5 | HTB{r3v1ew\_s4ar3\_p3Rms!} |
| Active Directory PowerView - Skills Assessment | Question 6 | Just\_f0r\_adm1n\_@cess! |
| Active Directory PowerView - Skills Assessment | Question 7 | poppy.louis |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# PowerView/SharpView Overview & Usage

## Question 1

### "Find the SID of the user liam.jones."

Students first need to connect to the spawned target with `xfreerdp` using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:HTB_@cademy_stdnt!
```

```
┌─[us-academy-1]─[10.10.15.2]─[htb-ac330204@htb-qa4azfluxu]─[~]
└──╼ [★]$ xfreerdp /v:10.129.2.174 /u:htb-student /p:Academy_student_AD!

[17:08:04:502] [6951:6952] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[17:08:04:502] [6951:6952] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[17:08:04:502] [6951:6952] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
<SNIP>
```

Then, students need to open `PowerShell` as administrator, navigate to `C:\Tools`, and import the `PowerView` module:

Code: powershell

```powershell
Import-Module .\PowerView.ps1
```

```
PS C:\tools> Import-Module .\PowerView.ps1
```

Subsequently, students need to use `Convert-NametoSid` on `liam.jones` to find the SID to be `S-1-5-21-2974783224-3764228556-2640795941-1705`:

Code: powershell

```powershell
Convert-NametoSid liam.jones
```

```
PS C:\tools> Convert-NametoSid liam.jones

S-1-5-21-2974783224-3764228556-2640795941-1705
```

Answer: `S-1-5-21-2974783224-3764228556-2640795941-1705`

# PowerView/SharpView Overview & Usage

## Question 2

### "What is the child domain of our current domain?"

Using the previously established RDP session and the PowerShell session with `PowerView` imported, students need to run `Get-DomainTrustMapping`:

Code: powershell

```powershell
Get-DomainTrustMapping
```

```
PS C:\tools> Get-DomainTrustMapping

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : LOGISTICS.INLANEFREIGHT.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 7/27/2020 2:06:07 AM
WhenChanged     : 2/3/2022 8:25:32 PM

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : freightlogistics.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Bidirectional
WhenCreated     : 7/28/2020 4:46:40 PM
WhenChanged     : 2/3/2022 9:26:18 PM
```

From the output, students will know that the child domain is `LOGISTICS.INLANEFREIGHT.LOCAL`.

Answer: `LOGISTICS.INLANEFREIGHT.LOCAL`

# PowerView/SharpView Overview & Usage

## Question 3

### "What user maps to the SID S-1-5-21-2974783224-3764228556-2640795941-1893?"

Using the established RDP and the PowerShell sessions with `PowerView` imported from question 1 of this section, students need to run `Get-DomainTrustMapping` on the SID `S-1-5-21-2974783224-3764228556-2640795941-1893`:

Code: powershell

```powershell
Convert-SidToName S-1-5-21-2974783224-3764228556-2640795941-1893
```

```
PS C:\tools> Convert-SidToName S-1-5-21-2974783224-3764228556-2640795941-1893

INLANEFREIGHT\rita.grant
```

From the output, students will know that the user is `rita.grant`.

Answer: `rita.grant`

# Enumerating AD Users

## Question 1

### "Find another user configured with Kerberos constrained delegation."

Students first need to connect to the spawned target with `xfreerdp` using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:Academy_student_AD!
```

```
┌─[us-academy-1]─[10.10.15.2]─[htb-ac330204@htb-qa4azfluxu]─[~]
└──╼ [★]$ xfreerdp /v:10.129.2.174 /u:htb-student /p:Academy_student_AD!

[17:08:04:502] [6951:6952] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[17:08:04:502] [6951:6952] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[17:08:04:502] [6951:6952] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
```

Then, students need to open PowerShell as administrator, navigate to `C:\Tools`, and import `PowerView`:

Code: powershell

```powershell
Import-Module .\PowerView.ps1
```

```
PS C:\tools> Import-Module .\PowerView.ps1
```

Subsequently, students need to run `Get-DomainUser` with the `-TrustedtoAuth` option:

Code: powershell

```powershell
Get-DomainUser -TrustedtoAuth
```

```
PS C:\tools> Get-DomainUser -TrustedtoAuth

<SNIP>
logoncount               : 0
badpasswordtime          : 12/31/1600 4:00:00 PM
distinguishedname        : CN=svc-scan,OU=Service Accounts,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL
objectclass              : {top, person, organizationalPerson, user}
name                     : svc-scan
objectsid                : S-1-5-21-2974783224-3764228556-2640795941-1114
samaccountname           : svc-scan
codepage                 : 0
samaccounttype           : USER_OBJECT
accountexpires           : 12/31/1600 4:00:00 PM
countrycode              : 0
whenchanged              : 9/10/2020 7:08:26 AM
instancetype             : 4
objectguid               : d9434a03-e47b-436f-8a03-56b016944fd4
lastlogon                : 12/31/1600 4:00:00 PM
lastlogoff               : 12/31/1600 4:00:00 PM
msds-allowedtodelegateto : {cifs/EXCHG01.INLANEFREIGHT.LOCAL, cifs/EXCHG01}
objectcategory           : CN=Person,CN=Schema,CN=Configuration,DC=INLANEFREIGHT,DC=LOCAL
dscorepropagationdata    : {7/30/2020 3:09:16 AM, 7/30/2020 3:09:16 AM, 7/28/2020 1:45:00 AM, 7/28/2020 1:34:13 AM...}
serviceprincipalname     : scantest/inlanefreight.local
whencreated              : 7/27/2020 6:46:48 PM
badpwdcount              : 0
cn                       : svc-scan
useraccountcontrol       : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
usncreated               : 14668
primarygroupid           : 513
pwdlastset               : 7/27/2020 11:46:48 AM
usnchanged               : 176870
```

From the output, students will know that the other user configured with Kerberos constrained delegation is `svc-scan`.

Answer: `svc-scan`

# Enumerating AD Users

## Question 2

### "Find the second user with a password in the description field. Submit the password as the answer."

From the previously established RDP session, students need to use `Get-DomainUser` with the `-Properties` option:

Code: powershell

```powershell
Get-DomainUser -Properties samaccountname,description | Where {$_.description -ne $null}
```

```
PS C:\tools> Get-DomainUser -Properties samaccountname,description | Where {$_.description -ne $null}

samaccountname description
-------------- -----------
Administrator  Built-in account for administering the computer/domain
Guest          Built-in account for guest access to the computer/domain
DefaultAccount A user account managed by the system.
krbtgt         Key Distribution Center Service Account
svc-sccm       **Do not change password** 03/04/2015 N3ssu$_svc2014!
joel.johnson   **Saving this here** 3/02/2011 - W4y_am_I_d0ing_Th1s?
```

From the output, students will find the password `W4y_am_I_d0ing_Th1s?` in the description field of the `samaccountname` `joel.johnson`.

Answer: `W4y_am_I_d0ing_Th1s?`

# Enumerating AD Users

## Question 3

### "Find another user with an SPN set that is not listed in the section command output (case-sensitive)."

Using the same RDP session established in the first question of this section, students need to utilize `Get-DomainUser`:

Code: powershell

```powershell
Get-DomainUser * -SPN | select samaccountname
```

```
PS C:\tools> Get-DomainUser * -SPN | select samaccountname

samaccountname
--------------
sqldev
WSUSupdatesvc
adam.jones
krbtgt
sqlqa
sql-test
sqlprod
svc-scan
```

From the output, students will know that other user is `WSUSupdatesvc`.

Answer: `WSUSupdatesvc`

# Enumerating AD Users

## Question 4

### "Find another user in the administrators group from another domain."

Using the same RDP session established previously, students need to utilize `Get-DomainGroup`, passing `administrators` to the `-Identity` option:

Code: powershell

```powershell
Get-DomainGroup -Identity administrators | select member
```

```
PS C:\Tools> Get-DomainGroup -Identity administrators | select member

member
------
{CN=bob.barker,CN=Users,DC=LOGISTICS,DC=INLANEFREIGHT,DC=LOCAL, CN=S-1-5-21-888139820-103978830-333442103-1602,CN=Fo...
```

From the output, students will find the user `bob.barker`.

Answer: `bob.barker`

# Enumerating AD Groups

## Question 1

### "Find the user in the Records Management group (first.last)."

Students first need to connect to the spawned target with `xfreerdp` using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:Academy_student_AD!
```

```
┌─[us-academy-1]─[10.10.15.2]─[htb-ac330204@htb-qa4azfluxu]─[~]
└──╼ [★]$ xfreerdp /v:10.129.2.174 /u:htb-student /p:Academy_student_AD!

[17:08:04:502] [6951:6952] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[17:08:04:502] [6951:6952] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[17:08:04:502] [6951:6952] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
```

Subsequently, students need to open PowerShell as administrator, navigate to `C:\Tools`, and then import `PowerView`:

Code: powershell

```powershell
Import-Module .\PowerView.ps1
```

```
PS C:\Tools> Import-Module .\PowerView.ps1
```

Students then need to use `Get-DomainGroup` and set the `-Identity` option to `Records Management`, to find `jennifer.chandler`:

Code: powershell

```powershell
Get-DomainGroup -Identity 'Records Management' | select member
```

```
PS C:\Tools> Get-DomainGroup -Identity 'Records Management' | select member

member
------
CN=Jennifer Chandler,OU=Help Desk,DC=INLANEFREIGHT,DC=LOCAL
```

Answer: `jennifer.chandler`

# Enumerating AD Groups

## Question 2

### "Find the member of the Remote Management Users group on WS01."

Using the previously established RDP session, students need to run `Find-DomainLocalGroupMember`, passing `WS01` to the `-Computer` option and `Remote Management Users` to `-GroupName`, to find `samantha.patel`:

Code: powershell

```powershell
Find-DomainLocalGroupMember -ComputerName WS01 -GroupName "Remote Management Users"
```

```
PS C:\Tools> Find-DomainLocalGroupMember -ComputerName WS01 -GroupName "Remote Management Users"

ComputerName : WS01
GroupName    : Remote Management Users
MemberName   : INLANEFREIGHT\samantha.patel
SID          : S-1-5-21-2974783224-3764228556-2640795941-1235
IsGroup      : False
IsDomain     : UNKNOWN
```

Answer: `samantha.patel`

# Enumerating AD Computers

## Question 1

### "How many hosts are present in the domain?"

Students first need to connect to the spawned target with `xfreerdp` using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:Academy_student_AD!
```

```
┌─[us-academy-1]─[10.10.15.2]─[htb-ac330204@htb-qa4azfluxu]─[~]
└──╼ [★]$ xfreerdp /v:10.129.2.174 /u:htb-student /p:Academy_student_AD!

[17:08:04:502] [6951:6952] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[17:08:04:502] [6951:6952] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[17:08:04:502] [6951:6952] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
```

Then, students need to open PowerShell, navigate to `C:\Tools` and import `PowerView`:

Code: powershell

```powershell
Import-Module .\PowerView.ps1
```

```
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Users\htb-student> cd C:\Tools\
PS C:\Tools> Import-Module .\PowerView.ps1
```

Subsequently, students need to run `(Get-DomainComputer).count` to find that there are five computers:

Code: powershell

```powershell
(Get-DomainComputer).count
```

```
PS C:\Tools> (Get-DomainComputer).count

5
```

Answer: `5`

# Enumerating AD Computers

## Question 2

### "What is the objectguid value of the EXCHG01 host?"

Using the previously established RDP session, students need to use PowerShell to run `Get-domainComputer`, passing `EXCHG01` to the `-Identity` option, finding the `objectguid` to be `ec252fbd-765d-4833-9f9d-f1eaf712089e`:

Code: powershell

```powershell
Get-domainComputer -Identity EXCHG01 -Properties * | select objectguid
```

```
PS C:\Tools> Get-domainComputer -Identity EXCHG01 -Properties * | select objectguid

objectguid
----------
ec252fbd-765d-4833-9f9d-f1eaf712089e
```

Answer: `ec252fbd-765d-4833-9f9d-f1eaf712089e`

# Enumerating AD Computers

## Question 3

### "What OU does the WS01 host belong to? (2 words, case sensitive)"

Using the previously established RDP session, students need to use PowerShell to run `Get-DomainComputer`, passing `WS01` to the `-Identity` option, to find the OU `Staff Workstations`:

Code: powershell

```powershell
Get-DomainComputer -Identity WS01
```

```
PS C:\Tools> Get-DomainComputer -Identity WS01

logoncount                    : 233
badpasswordtime               : 12/31/1600 4:00:00 PM
distinguishedname             : CN=WS01,OU=Staff Workstations,OU=Workstations,DC=INLANEFREIGHT,DC=LOCAL
objectclass                   : {top, person, organizationalPerson, user...}
badpwdcount                   : 0
lastlogontimestamp            : 10/14/2022 8:24:47 AM
objectsid                     : S-1-5-21-2974783224-3764228556-2640795941-1105
samaccountname                : WS01$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
countrycode                   : 0
<SNIP>
```

Answer: `Staff Workstations`

# Enumerating Domain ACLs

## Question 1

### "Find a user (first.last) who has GenericAll rights over the joe.evans user."

Students first need to connect to the spawned target with `xfreerdp` using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:Academy_student_AD!
```

```
┌─[us-academy-1]─[10.10.15.2]─[htb-ac330204@htb-qa4azfluxu]─[~]
└──╼ [★]$ xfreerdp /v:10.129.2.174 /u:htb-student /p:Academy_student_AD!

[17:08:04:502] [6951:6952] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[17:08:04:502] [6951:6952] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[17:08:04:502] [6951:6952] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
```

Then, students to need open PowerShell, navigate to `C:\Tools` and import `PowerView`:

Code: powershell

```powershell
Import-Module .\PowerView.ps1
```

```
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Users\htb-student> cd C:\Tools\
PS C:\Tools> Import-Module .\PowerView.ps1
```

Students then need to run the following `Get-ACL` query, to find the user `douglas.bull`:

Code: powershell

```powershell
(Get-ACL "AD:$((Get-ADUser joe.evans).distinguishedname)").access  | ? {$_.ActiveDirectoryRights -match "WriteProperty" -or $_.ActiveDirectoryRights -match "GenericAll"} | Select IdentityReference,ActiveDirectoryRights -unique | ft -W
```

```
PS C:\Tools> (Get-ACL "AD:$((Get-ADUser joe.evans).distinguishedname)").access  | ? {$_.ActiveDirectoryRights -match "WriteProperty" -or $_.ActiveDirectoryRights -match "GenericAll"} | Select IdentityReference,ActiveDirectoryRights -unique | ft -W

IdentityReference                                                                                                ActiveDirectoryRights
-----------------                                                                                                ---------------------
NT AUTHORITY\SYSTEM                                                                                                         GenericAll
S-1-5-32-548                                                                                                                GenericAll
INLANEFREIGHT\Domain Admins                                                                                                 GenericAll
INLANEFREIGHT\douglas.bull                                                                                                  GenericAll
NT AUTHORITY\SELF                                                                                          ReadProperty, WriteProperty
S-1-5-32-561                                                                                               ReadProperty, WriteProperty
INLANEFREIGHT\Cert Publishers                                                                              ReadProperty, WriteProperty
INLANEFREIGHT\Organization Management                                                                                    WriteProperty
INLANEFREIGHT\Exchange Trusted Subsystem                                                                                 WriteProperty
INLANEFREIGHT\Exchange Windows Permissions                                                                               WriteProperty
INLANEFREIGHT\Exchange Servers                                                                                           WriteProperty
INLANEFREIGHT\Key Admins                                                                                   ReadProperty, WriteProperty
INLANEFREIGHT\Enterprise Key Admins                                                                        ReadProperty, WriteProperty
INLANEFREIGHT\Exchange Trusted Subsystem               CreateChild, DeleteChild, ListChildren, ReadProperty, WriteProperty, ListObject
INLANEFREIGHT\Exchange Servers                         CreateChild, DeleteChild, ListChildren, ReadProperty, WriteProperty, ListObject
INLANEFREIGHT\Organization Management                                                                                       GenericAll
INLANEFREIGHT\Exchange Trusted Subsystem                                                                                    GenericAll
NT AUTHORITY\SELF                                                                                                        WriteProperty
NT AUTHORITY\SELF                                                                           ReadProperty, WriteProperty, ExtendedRight
INLANEFREIGHT\Enterprise Admins                                                                                             GenericAll
BUILTIN\Administrators                     CreateChild, Self, WriteProperty, ExtendedRight, Delete, GenericRead, WriteDacl, WriteOwner
NT AUTHORITY\ANONYMOUS LOGON                                                               ReadProperty, WriteProperty, GenericExecute
```

Answer: `douglas.bull`

# Enumerating Domain ACLs

## Question 2

### "Find the name of a non-standard share on the WS01 computer."

Using the previously established RDP session, students need to use PowerShell to run `Get-NetShare`, finding `Client_Invoices`:

Code: powershell

```powershell
Get-NetShare
```

```
PS C:\Tools> Get-NetShare

Name                  Type Remark        ComputerName
----                  ---- ------        ------------
ADMIN$          2147483648 Remote Admin  localhost
C$              2147483648 Default share localhost
Client_Invoices          0               localhost
Financials               0               localhost
IPC$            2147483651 Remote IPC    localhost
Old_reports              0               localhost
```

Answer: `Client_Invoices`

# Enumerating Domain ACLs

## Question 3

### "Find another user with DCSync rights (first.last)."

Using the previously established RDP session, students need to use PowerShell to run the following queries, finding `gillian.fisher`:

Code: powershell

```powershell
$dcsync = Get-ObjectACL "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ObjectAceType -match 'Replication-Get')} | Select-Object -ExpandProperty SecurityIdentifier | Select -ExpandProperty value
Convert-SidtoName $dcsync
```

```
PS C:\Tools> $dcsync = Get-ObjectACL "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ObjectAceType -match 'Replication-Get')} | Select-Object -ExpandProperty SecurityIdentifier | Select -ExpandProperty value
PS C:\Tools> Convert-SidtoName $dcsync

INLANEFREIGHT\frederick.walton
INLANEFREIGHT\gillian.fisher
INLANEFREIGHT\frederick.walton
INLANEFREIGHT\gillian.fisher
INLANEFREIGHT\Enterprise Read-only Domain Controllers
INLANEFREIGHT\Domain Controllers
INLANEFREIGHT\frederick.walton
INLANEFREIGHT\gillian.fisher
INLANEFREIGHT\Organization Management
INLANEFREIGHT\Exchange Trusted Subsystem
INLANEFREIGHT\Exchange Trusted Subsystem
INLANEFREIGHT\Exchange Trusted Subsystem
BUILTIN\Administrators
BUILTIN\Administrators
BUILTIN\Administrators
Enterprise Domain Controllers
Enterprise Domain Controllers
INLANEFREIGHT\Enterprise Admins
Local System
PS C:\Tools>
```

Answer: `gillian.fisher`

# Enumerating Group Policy Objects (GPOs)

## Question 1

### "Find the GUID of the Audit Policy GPO."

Using the previously established RDP session, students need to use PowerShell to run `Get-DomainGPO`, passing `Audit Policy` to `-Identity`, finding `8bb15712-8a05-47e7-9dcf-897999d695fe`:

Code: powershell

```powershell
Get-DomainGPO -Identity "Audit Policy" | select displayname,objectguid
```

```
PS C:\Tools> Get-DomainGPO -Identity "Audit Policy" | select displayname,objectguid

displayname  objectguid
-----------  ----------
Audit Policy 8bb15712-8a05-47e7-9dcf-897999d695fe
```

Students will find the `GUID` in the query output.

Answer: `8bb15712-8a05-47e7-9dcf-897999d695fe`

# Enumerating AD Trusts

## Question 1

### "What is the name of the child domain our current domain has a trust with? (answer is case-sensitive)"

Students first need to connect to the spawned target with `xfreerdp` using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:Academy_student_AD!
```

```
┌─[us-academy-1]─[10.10.15.2]─[htb-ac330204@htb-qa4azfluxu]─[~]
└──╼ [★]$ xfreerdp /v:10.129.2.174 /u:htb-student /p:Academy_student_AD!

[17:08:04:502] [6951:6952] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[17:08:04:502] [6951:6952] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[17:08:04:502] [6951:6952] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
```

Then, students need to open PowerShell, navigate to `C:\Tools` and import `PowerView`:

Code: powershell

```powershell
cd C:\Tools
Import-Module .\PowerView.ps1
```

```
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Users\htb-student> cd C:\Tools\
PS C:\Tools> Import-Module .\PowerView.ps1
```

Then, students need to then run `Get-DomainTrustMapping`, finding that `LOGISTCS.INLANEFREIGHT.LOCAL` is the child domain having a trust with `INLANEFREIGHT.LOCAL`:

Code: powershell

```powershell
Get-DomainTrustMapping
```

```
PS C:\Tools> Get-DomainTrustMapping

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : LOGISTICS.INLANEFREIGHT.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 7/27/2020 2:06:07 AM
WhenChanged     : 2/3/2022 8:25:32 PM

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : freightlogistics.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Bidirectional
WhenCreated     : 7/28/2020 4:46:40 PM
WhenChanged     : 2/3/2022 9:26:18 PM
```

Answer: `LOGISTICS.INLANEFREIGHT.LOCAL`

# Enumerating AD Trusts

## Question 2

### "What other forest does the current domain have a trust with? (answer is case-sensitive)"

Using the previously established RDP session, students need to use PowerShell to run `Get-DomainTrustMapping`, finding that `freightlogistics.local` is the forest that `INLANEFREIGHT.LOCAL` has a trust with:

```powershell
Get-DomainTrustMapping
```
```
PS C:\Tools> Get-DomainTrustMapping

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : LOGISTICS.INLANEFREIGHT.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 7/27/2020 2:06:07 AM
WhenChanged     : 2/3/2022 8:25:32 PM

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : freightlogistics.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Bidirectional
WhenCreated     : 7/28/2020 4:46:40 PM
WhenChanged     : 2/3/2022 9:26:18 PM
```

Answer: `freightlogistics.local`

# Enumerating AD Trusts

## Question 3

### "What is the trust direction for this trust? (answer is case-sensitive)"

Using the previously established RDP session, students need to use PowerShell to run `Get-DomainTrustMapping`, finding that the trust direction is `Bidirectional`:

```powershell
Get-DomainTrustMapping
```
```
PS C:\Tools> Get-DomainTrustMapping

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : LOGISTICS.INLANEFREIGHT.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 7/27/2020 2:06:07 AM
WhenChanged     : 2/3/2022 8:25:32 PM

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : freightlogistics.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Bidirectional
WhenCreated     : 7/28/2020 4:46:40 PM
WhenChanged     : 2/3/2022 9:26:18 PM
```

Answer: `Bidirectional`.

# Active Directory PowerView - Skills Assessment

## Question 1

### "What is the passwordhistorysize of the domain?"

Students first need connect to the spawned target using `xfreerdp` and authenticating as `htb-student:Acad_ad_enum_skillz!` :

```shell
xfreerdp /v:STMIP /u:htb-student /p:'Acad_ad_enum_skillz!' /dynamic-resolution
```
```
┌─[us-academy-2]─[10.10.14.72]─[htb-ac330204@htb-fsmpnwrzko]─[~]
└──╼ [★]$ xfreerdp /v:10.129.202.128 /u:htb-student /p:'Acad_ad_enum_skillz!' /dynamic-resolution

[21:17:08:429] [2536:2537] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[21:17:08:429] [2536:2537] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[21:17:08:429] [2536:2537] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
<SNIP>
```

Then, students need to open PowerShell, navigate to `C:\Users\htb-student\Desktop`, and import the `PowerView` module:

```powershell
cd C:\Users\htb-student\Desktop
Import-Module .\PowerView.ps1
```
```
PS C:\Users\htb-student\Desktop> import-module .\PowerView.ps1
```

Subsequently, students need to enumerate the domain policy using `Get-DomainPolicy`:

```powershell
Get-DomainPolicy
```
```
PS C:\Users\htb-student\Desktop> Get-DomainPolicy

Unicode        : @{Unicode=yes}
SystemAccess   : @{MinimumPasswordAge=1; MaximumPasswordAge=42; MinimumPasswordLength=7; PasswordComplexity=0;
                 PasswordHistorySize=24; LockoutBadCount=0; RequireLogonToChangePassword=0;
                 ForceLogoffWhenHourExpire=0; ClearTextPassword=0; LSAAnonymousNameLookup=0}
KerberosPolicy : @{MaxTicketAge=10; MaxRenewAge=7; MaxServiceAge=600; MaxClockSkew=5; TicketValidateClient=1}
Version        : @{signature="$CHICAGO$"; Revision=1}
RegistryValues : @{MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=System.Object[]}
Path           : \\INLANEFREIGHTENUM2.LOCAL\sysvol\INLANEFREIGHTENUM2.LOCAL\Policies\{31B2F340-016D-11D2-945F-00C04FB98
                 4F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf
GPOName        : {31B2F340-016D-11D2-945F-00C04FB984F9}
GPODisplayName : Default Domain Policy
```

Students will know that `PasswordHistorySize` is `24`.

Answer: `24`

# Active Directory PowerView - Skills Assessment

## Question 2

### "What is the SID of the user rachel.flemmings?"

Using the previously established RDP session, students need to run `Convert-NameToSid` on `rachel.flemmings`:

```powershell
Convert-NameToSid rachel.flemmings
```
```
PS C:\Users\htb-student\Desktop> Convert-NameToSid rachel.flemmings

S-1-5-21-3394586996-1871716043-2583881113-1105
```

Students will find that the SID of `rachel.flemmings` is `S-1-5-21-3394586996-1871716043-2583881113-1105`.

Answer: `S-1-5-21-3394586996-1871716043-2583881113-1105`

# Active Directory PowerView - Skills Assessment

## Question 3

### "What is the domain functional level? (1 single number)"

Using the previously established RDP session, students need to run `Get-Domain`, to find that the domain functional level is `5`:

```powershell
Get-Domain
```
```
PS C:\Users\htb-student\Desktop> Get-Domain

Forest                  : INLANEFREIGHTENUM2.LOCAL
DomainControllers       : {ENUM2-DC01.INLANEFREIGHTENUM2.LOCAL}
Children                : {}
DomainMode              : Windows8Domain
DomainModeLevel         : 5
Parent                  :
PdcRoleOwner            : ENUM2-DC01.INLANEFREIGHTENUM2.LOCAL
RidRoleOwner            : ENUM2-DC01.INLANEFREIGHTENUM2.LOCAL
InfrastructureRoleOwner : ENUM2-DC01.INLANEFREIGHTENUM2.LOCAL
Name                    : INLANEFREIGHTENUM2.LOCAL
```

Answer: `5`

# Active Directory PowerView - Skills Assessment

## Question 4

### "What GPO is applied to the ENUM2-MS01 host? (case sensitive)"

Using the previously established RDP session, students need to run `Get-DomainGPO`, passing `ENUM2-MS01` to the `-ComputerIdentity` option:

```powershell
 Get-DomainGPO -ComputerIdentity ENUM2-MS01 | select displayname
```
```
PS C:\Users\htb-student\Desktop> Get-DomainGPO -ComputerIdentity ENUM2-MS01 | select displayname

displayname
-----------
Disable Defender
Default Domain Policy
```

Students will find `Disable Defender` applied.

Answer: `Disable Defender`

# Active Directory PowerView - Skills Assessment

## Question 5

### "Find a non-standard share on the ENUM2-DC01 host. Access it and submit the contents of share.txt."

Using the previously established RDP session, students need to enumerate shares on ENUM2-DC01 using `Get-NetShare`:

```powershell
Get-NetShare -ComputerName ENUM2-DC01
```
```
PS C:\Users\htb-student\Desktop> Get-NetShare -ComputerName ENUM2-DC01

Name           Type Remark              ComputerName
----           ---- ------              ------------
ADMIN$   2147483648 Remote Admin        ENUM2-DC01
C$       2147483648 Default share       ENUM2-DC01
IPC$     2147483651 Remote IPC          ENUM2-DC01
NETLOGON          0 Logon server share  ENUM2-DC01
Payroll           0                     ENUM2-DC01
SYSVOL            0 Logon server share  ENUM2-DC01
```

Subsequently, students need to open File Explorer and navigate to `\\ENUM2-DC01`:

![[HTB Solutions/CAPE/z. images/34cb3b8aa6f860b4108523eb4d49840f_MD5.jpg]]

Then, students need to navigate to the Payroll directory and read the contents of "share.txt":

![[HTB Solutions/CAPE/z. images/8c3f9c07f9cc590cf67e1157bd5413a4_MD5.jpg]]

Answer: `HTB{r3v1ew_s4ar3_p3Rms!}`

# Active Directory PowerView - Skills Assessment

## Question 6

### "Find a domain computer with a password in the description field. Submit the password as your answer."

Using the previously established RDP session, students need to run `Get-DomainComputer`, passing `dnshostname` and `description` to the `-Properties` option:

```powershell
Get-DomainComputer -Properties dnshostname,description | ? {$_.description -ne $null}
```
```
PS C:\Users\htb-student\Desktop> Get-DomainComputer -Properties dnshostname,description | ? {$_.description -ne $null}

description
-----------
** Jump to Citrix farm ** ctrx_adm:Just_f0r_adm1n_@cess!
```

From the output, students will know that the password is `Just_f0r_adm1n_@cess!`.

Answer: `Just_f0r_adm1n_@cess!`

# Active Directory PowerView - Skills Assessment

## Question 7

### "Who is the group manager of the Citrix Admins group?"

Using the previously established RDP session, students need to run `Get-DomainComputer`, passing `*` to the `-Properties` option and `Citrix Admins` to the `-Identity` option:

```powershell
Get-DomainGroup -Properties * -Identity 'Citrix Admins' | select cn,managedby
```
```
PS C:\Users\htb-student\Desktop> Get-DomainGroup -Properties * -Identity 'Citrix Admins' | select cn,managedby

cn            managedby
--            ---------
Citrix Admins CN=poppy.louis,CN=Users,DC=INLANEFREIGHTENUM2,DC=LOCAL
```

From the output, students will find that `poppy.louis` is the group manager of the Citrix Admins group.

Answer: `poppy.louis`