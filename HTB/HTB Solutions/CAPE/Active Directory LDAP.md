| Section | Question Number | Answer |
| --- | --- | --- |
| Rights and Privileges in AD | Question 1 | hazel.lamb |
| Rights and Privileges in AD | Question 2 | 3 |
| Rights and Privileges in AD | Question 3 | Microsoft Exchange Security Groups |
| LDAP Overview | Question 1 | luke.gibbons |
| LDAP Overview | Question 2 | 1044 |
| LDAP Overview | Question 3 | 5 |
| LDAP Overview | Question 4 | 73 |
| Active Directory Search Filters | Question 1 | ross.begum |
| Active Directory Search Filters | Question 2 | S-1-5-21-2974783224-3764228556-2640795941-1105 |
| Active Directory Search Filters | Question 3 | sqlprod |
| LDAP Search Filters | Question 1 | Network Operations |
| LDAP Search Filters | Question 2 | sql-test |
| LDAP Search Filters | Question 3 | 118 |
| Enumerating Active Directory with Built-in Tools | Question 1 | 4194304 |
| Enumerating Active Directory with Built-in Tools | Question 2 | clark.thompson |
| LDAP Anonymous Bind | Question 1 | 2016 |
| LDAP Anonymous Bind | Question 2 | sqldev |
| LDAP Anonymous Bind | Question 3 | Finance |
| Credentialed LDAP Enumeration | Question 1 | 7 |
| Credentialed LDAP Enumeration | Question 2 | sarah.lafferty |
| Credentialed LDAP Enumeration | Question 3 | 5 |
| Credentialed LDAP Enumeration | Question 4 | wilford.stewart |
| Credentialed LDAP Enumeration | Question 5 | 640 |
| Active Directory LDAP - Skills Assessment | Question 1 | abigail.henry |
| Active Directory LDAP - Skills Assessment | Question 2 | clive.jones |
| Active Directory LDAP - Skills Assessment | Question 3 | Server Technicians |
| Active Directory LDAP - Skills Assessment | Question 4 | sally.andrews |
| Active Directory LDAP - Skills Assessment | Question 5 | 103 |
| Active Directory LDAP - Skills Assessment | Question 6 | RDS01.INLANEFREIGHTENUM1.LOCAL |
| Active Directory LDAP - Skills Assessment | Question 7 | 13 |
| Active Directory LDAP - Skills Assessment | Question 8 | wilbur.douglas |
| Active Directory LDAP - Skills Assessment | Question 9 | mssqlprod |
| Active Directory LDAP - Skills Assessment | Question 10 | SeBackupPrivilege |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Rights and Privileges in AD

## Question 1

### "Find the user in the DNSAdmins group (first.last)."

Students first need to connect to the spawned target with `xfreerdp` using the credentials `htb-student:Academy_student_AD!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:Academy_student_AD!
```

```
┌─[us-academy-1]─[10.10.15.2]─[htb-ac330204@htb-asbdawyyzl]─[~]
└──╼ [★]$ xfreerdp /v:10.129.73.141 /u:htb-student /p:Academy_student_AD! /dynamic-resolution

[21:52:14:323] [6952:6953] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[21:52:14:323] [6952:6953] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[21:52:14:323] [6952:6953] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
```

Then, students need to open `PowerShell` and run `Get-ADGroup`:

Code: powershell

```powershell
Get-ADGroup -Identity "DNSAdmins" -Properties *
```

Code: powershell

```powershell
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Users\htb-student> Get-ADGroup -Identity "DNSAdmins" -Properties *

CanonicalName                   : INLANEFREIGHT.LOCAL/Users/DnsAdmins
CN                              : DnsAdmins
Created                         : 7/26/2020 1:15:17 PM
createTimeStamp                 : 7/26/2020 1:15:17 PM
Deleted                         :
Description                     : DNS Administrators Group
DisplayName                     :
DistinguishedName               : CN=DnsAdmins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
dSCorePropagationData           : {7/29/2020 8:09:16 PM, 7/27/2020 6:45:00 PM, 7/27/2020 6:34:13 PM, 1/1/1601 10:16:33 AM}
GroupCategory                   : Security
GroupScope                      : DomainLocal
groupType                       : -2147483644
HomePage                        :
instanceType                    : 4
isDeleted                       :
LastKnownParent                 :
ManagedBy                       :
member                          : {CN=Hazel Lamb,OU=Server Team,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL}
MemberOf                        : {}
Members                         : {CN=Hazel Lamb,OU=Server Team,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL}
Modified                        : 9/9/2020 9:42:29 PM
modifyTimeStamp                 : 9/9/2020 9:42:29 PM
Name                            : DnsAdmins
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  : CN=Group,CN=Schema,CN=Configuration,DC=INLANEFREIGHT,DC=LOCAL
ObjectClass                     : group
ObjectGUID                      : 9ca8ad30-2c5d-4c5f-b624-ca1769d16d63
objectSid                       : S-1-5-21-2974783224-3764228556-2640795941-1101
ProtectedFromAccidentalDeletion : False
SamAccountName                  : DnsAdmins
sAMAccountType                  : 536870912
sDRightsEffective               : 0
SID                             : S-1-5-21-2974783224-3764228556-2640795941-1101
SIDHistory                      : {}
uSNChanged                      : 176510
uSNCreated                      : 12483
whenChanged                     : 9/9/2020 9:42:29 PM
whenCreated                     : 7/26/2020 1:15:17 PM
```

The user is `hazel.lamb`.

Answer: `hazel.lamb`

# Rights and Privileges in AD

## Question 2

### "How many users are in the Help Desk group?"

Using the previously established RDP session, students need to use `PowerShell` to run `Get-ADGroup`:

Code: powershell

```powershell
Get-ADGroup -Identity "Help Desk" -Properties * | select Members | fl
```

```
PS C:\Users\htb-student> Get-ADGroup -Identity "Help Desk" -Properties * | select Members | fl

Members : {CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL, CN=Amber Smith,OU=Contractors,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL, CN=Pamela
          Brown,OU=Server Team,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL}
```

Students can see the users `Harry Jones`, `Amber Smith`, and `Pamela Brown`, which adds up to `3`.

Alternatively students can run the command:

Code: powershell

```powershell
(Get-ADGroup "Help Desk" -Properties *).Member.Count
```

```
PS C:\Users\htb-student> (Get-ADGroup "Help Desk" -Properties *).Member.Count

3
```

Answer: `3`

# Rights and Privileges in AD

## Question 3

### "What OU is the Help Desk group managed by?"

Using the previously established RDP session, students need to use `PowerShell` to run `Get-ADGroup`:

Code: powershell

```powershell
Get-ADGroup "Help Desk" -Properties * | select Managedby
```

Code: powershell

```powershell
PS C:\Users\htb-student> Get-ADGroup "Help Desk" -Properties * | select Managedby

Managedby
---------
CN=Organization Management,OU=Microsoft Exchange Security Groups,DC=INLANEFREIGHT,DC=LOCAL
```

The output reveals that the `Microsoft Exchange Security Groups` is the `OU` managed by `Help Desk`.

Answer: `Microsoft Exchange Security Groups`

# LDAP Overview

## Question 1

### "Find another disabled user (first.last)."

Students first need to connect to the spawned target with `xfreerdp` using the credentials `htb-student:Academy_student_AD!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:Academy_student_AD!
```

```
┌─[us-academy-1]─[10.10.15.2]─[htb-ac330204@htb-asbdawyyzl]─[~]
└──╼ [★]$ xfreerdp /v:10.129.73.141 /u:htb-student /p:Academy_student_AD! /dynamic-resolution

[21:52:14:323] [6952:6953] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[21:52:14:323] [6952:6953] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[21:52:14:323] [6952:6953] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
```

Then, students need to use `PowerShell` to run `Get-ADObject`:

Code: powershell

```powershell
Get-ADObject -LDAPFilter "(&(objectclass=user)(objectcategory=user)(useraccountcontrol:1.2.840.
113556.1.4.803:=2))" -Properties * | select samaccountname,useraccountcontrol
```

```
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Users\htb-student> Get-ADObject -LDAPFilter "(&(objectclass=user)(objectcategory=user)(useraccountcontrol:1.2.840.
113556.1.4.803:=2))" -Properties * | select samaccountname,useraccountcontrol

samaccountname       useraccountcontrol
--------------       ------------------
Guest                             66082
DefaultAccount                    66082
krbtgt                            66050
caroline.ali                        546
luke.gibbons                        546
$SH2000-FPNHUU487JP0                546
SM_00390f38b41e488ab                514
SM_e081bc60d79c4597b                514
SM_a9a4eed7ad2d4369a                514
SM_d836f82078bf4cf89                514
SM_6a24f488535649558                514
SM_08a2324990674a87b                514
SM_d1fea2710dc146b1b                514
SM_b56189681baa441db                514
SM_b72a918d27554863b                514
```

Students will have observed from the output that `caroline.ali` was the first disabled user, making `luke.gibbons` the other.

Answer: `luke.gibbons`

# LDAP Overview

## Question 2

### "How many users exist in the INLANFREIGHT.LOCAL domain?"

Using the previously established RDP session, students need to use `PowerShell` to run `Get-ADUser`:

Code: powershell

```powershell
(Get-ADUser -Filter *).count
```

```
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Users\htb-student> (Get-ADUser -Filter *).count

1044
```

Students will see that the query shows there are `1044` users.

Answer: `1044`

# LDAP Overview

## Question 3

### "How many computers exist in the INLANFREIGHT.LOCAL domain?"

Using the previously established RDP session, students will use `PowerShell` to `Get-ADComputer`:

Code: powershell

```powershell
(Get-ADComputer -Filter *).count
```

```
PS C:\Users\htb-student> (Get-ADComputer -Filter *).count

5
```

The query returns a value of `5` for the number of computers.

Answer: `5`

# LDAP Overview

## Question 4

### "How many groups exist in the INLANFREIGHT.LOCAL domain?"

Using the previously established RDP session, students need to use `PowerShell` to run the `Get-ADGroup`:

Code: powershell

```powershell
(Get-ADGroup -Filter *).count
```

```
PS C:\Users\htb-student> (Get-ADGroup -Filter *).count

73
```

Students will see that the query returns a value of `73` for the number of groups.

Answer: `73`

# Active Directory Search Filters

## Question 1

### "Find another user with DoesNotRequirePreAuth set (first.last)."

Students first need to connect to the spawned target with `xfreerdp` using the credentials `htb-student:Academy_student_AD!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:Academy_student_AD!
```

```
┌─[us-academy-1]─[10.10.15.2]─[htb-ac330204@htb-asbdawyyzl]─[~]
└──╼ [★]$ xfreerdp /v:10.129.73.141 /u:htb-student /p:Academy_student_AD! /dynamic-resolution

[21:52:14:323] [6952:6953] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[21:52:14:323] [6952:6953] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[21:52:14:323] [6952:6953] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
<SNIP>
```

Students then need to use `PowerShell` to run `Get-ADuser`:

Code: powershell

```powershell
Get-ADuser -Filter {DoesNotRequirePreAuth -eq 'True'}
```

```
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Users\htb-student> Get-ADuser -Filter {DoesNotRequirePreAuth -eq 'True'}

DistinguishedName : CN=Ross Begum,OU=Operations,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL
Enabled           : True
GivenName         : ross
Name              : Ross Begum
ObjectClass       : user
ObjectGUID        : e3ab16cb-44b8-4c01-a292-68a963976c57
SamAccountName    : ross.begum
SID               : S-1-5-21-2974783224-3764228556-2640795941-1678
Surname           : begum
UserPrincipalName : ross.begum@inlanefreight

DistinguishedName : CN=Amber Smith,OU=Contractors,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL
Enabled           : True
GivenName         : amber
Name              : Amber Smith
ObjectClass       : user
ObjectGUID        : f4493b78-55f0-488f-b21b-1dfd9069407d
SamAccountName    : amber.smith
SID               : S-1-5-21-2974783224-3764228556-2640795941-1859
Surname           : smith
UserPrincipalName : amber.smith@inlanefreight

DistinguishedName : CN=Jenna Smith,OU=Server Team,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL
Enabled           : True
GivenName         : jenna
Name              : Jenna Smith
ObjectClass       : user
ObjectGUID        : ea3c930f-aa8e-4fdc-987c-4a9ee1a75409
SamAccountName    : jenna.smith
SID               : S-1-5-21-2974783224-3764228556-2640795941-1999
Surname           : smith
UserPrincipalName : jenna.smith@inlanefreight
```

Students may need to try multiple users, but ultimately `ross.begum` is accepted.

Answer: `ross.begum`

# Active Directory Search Filters

## Question 2

### "Find the SID of the WS01 host."

Using the previously established RDP session, students need to use `PowerShell` to run `Get-ADComputer`:

Code: powershell

```powershell
Get-ADComputer -Filter "DNSHostname -like 'WS*'" | select SID
```

```
PS C:\Users\htb-student> Get-ADComputer -Filter "DNSHostname -like 'WS*'" | select SID

SID
---
S-1-5-21-2974783224-3764228556-2640795941-1105
```

Students will clearly see the SID in the query output.

Answer: `S-1-5-21-2974783224-3764228556-2640795941-1105`

# Active Directory Search Filters

## Question 3

### "Find the name of an account with a ServicePrincipalName set that is also a member of the Protected Users group."

Using the previously established RDP session, students need to use `PowerShell` to run `Get-ADUser`:

Code: powershell

```powershell
Get-ADUser -Filter * -Properties * | where servicePrincipalName -ne $null | select SamAccountName,MemberOf,ServicePrincipalName
```

```
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Users\htb-student> Get-ADUser -Filter * -Properties * | where servicePrincipalName -ne $null | select SamAccountName,MemberOf,ServicePrincipalName

SamAccountName MemberOf                                                                       ServicePrincipalName
-------------- --------                                                                       --------------------
krbtgt         {CN=Denied RODC Password Replication Group,CN=Users,DC=INLANEFREIGHT,DC=LOCAL} {kadmin/changepw}
sqldev         {CN=Protected Users,CN=Users,DC=INLANEFREIGHT,DC=LOCAL}                        {CIFS/roguecomputer.in...
sqlprod        {CN=Protected Users,CN=Users,DC=INLANEFREIGHT,DC=LOCAL}                        {MSSQLSvc/sql01:1433}
sqlqa          {CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL}                          {MSSQL_svc_qa/inlanefr...
svc-scan       {}                                                                             {scantest/inlanefreigh...
sql-test       {}                                                                             {MSSQL_svc_test/inlane...
adam.jones     {}                                                                             {IIS_dev/inlanefreight...
WSUSupdatesvc  {}                                                                             {HTTP/WSUS01.inlanefre...
```

Students will see that `sqlprod` meets the criteria of the question.

Answer: `sqlprod`

# LDAP Search Filters

## Question 1

### "Find another group, not listed in the section output, that harry.jones is a member of (case sensitive)."

Students first need to connect to the spawned target with `xfreerdp` using the credentials `htb-student:Academy_student_AD!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:Academy_student_AD!
```

```
┌─[us-academy-1]─[10.10.15.2]─[htb-ac330204@htb-asbdawyyzl]─[~]
└──╼ [★]$ xfreerdp /v:10.129.2.174 /u:htb-student /p:Academy_student_AD! /dynamic-resolution

[21:52:14:323] [6952:6953] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[21:52:14:323] [6952:6953] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[21:52:14:323] [6952:6953] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
```

Students then need to use `PowerShell` to run `Get-ADGroup`:

Code: powershell

```powershell
Get-ADGroup -LDAPFilter '(member:1.2.840.113556.1.4.1941:=CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL)' | select Name
```

```
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Users\htb-student> Get-ADGroup -LDAPFilter '(member:1.2.840.113556.1.4.1941:=CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL)' | select Name

Name
----
Administrators
Backup Operators
Domain Admins
Denied RODC Password Replication Group
LAPS Admins
Security Operations
Help Desk
Network Team
Network Operations
```

Students will find from the output that `Harry Jones` is part of the `Network Operations` group.

Answer: `Network Operations`

# LDAP Search Filters

## Question 2

### "Find another user marked as trusted for delegation"

Using the previously established RDP session, students need to use `PowerShell` to run `Get-ADUser`:

Code: powershell

```powershell
Get-ADUser -Properties * -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' | select Name,memberof, servicePrincipalName,TrustedForDelegation | ? {$_.TrustedForDelegation -eq 'True'}
```

```
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Users\htb-student> Get-ADUser -Properties * -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' | select Name,memberof, servicePrincipalName,TrustedForDelegation | ? {$_.TrustedForDelegation -eq 'True'}

Name     memberof                                                servicePrincipalName
----     --------                                                --------------------
sqldev   {CN=Protected Users,CN=Users,DC=INLANEFREIGHT,DC=LOCAL} {CIFS/roguecomputer.inlanefreight.local, MSSQL_svc_...
sql-test {}                                                      {MSSQL_svc_test/inlanefreight.local:1443}
```

Students will find that the query returns `sql-test` as the user marked for trusted delegation.

Answer: `sql-test`

# LDAP Search Filters

## Question 3

### "Find the number of users in the IT OU."

Using the previously established RDP session, students need to use `PowerShell` to run `Get-ADUser`:

Code: powershell

```powershell
(Get-ADUser -SearchBase "OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -Filter *).count
```

Code: powershell

```powershell
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Users\htb-student> (Get-ADUser -SearchBase "OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -Filter *).count

118
```

Students will see that the query returns `118` employees.

Answer: `118`

# Enumerating Active Directory with Built-in Tools

## Question 1

### "What is the UAC value for DONT\_REQ\_PREAUTH?"

Students can find the answer `4194304` by reading the module's section:

![[HTB Solutions/CAPE/z. images/fd97e2f1a8a72e1ac51ff8f2944c0c33_MD5.jpg]]

Answer: `4194304`

# Enumerating Active Directory with Built-in Tools

## Question 2

### "List the user in the Pentest OU (first.last)."

Students first need to connect to the spawned target with `xfreerdp` using the credentials `htb-student:Academy_student_AD!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:Academy_student_AD!
```

```
┌─[us-academy-1]─[10.10.15.2]─[htb-ac330204@htb-asbdawyyzl]─[~]
└──╼ [★]$ xfreerdp /v:10.129.2.174 /u:htb-student /p:Academy_student_AD! /dynamic-resolution

[21:52:14:323] [6952:6953] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[21:52:14:323] [6952:6953] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[21:52:14:323] [6952:6953] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
```

Students then need to use `PowerShell` to run `Get-ADUser`:

Code: powershell

```powershell
Get-ADUser -Filter * -SearchBase 'OU=Pentest,OU=Employees,DC=inlanefreight,dc=local'
```

```
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Users\htb-student> Get-ADUser -Filter * -SearchBase 'OU=Pentest,OU=Employees,DC=inlanefreight,dc=local'

DistinguishedName : CN=clark.thompson,OU=Pentest,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL
Enabled           : True
GivenName         :
Name              : clark.thompson
ObjectClass       : user
ObjectGUID        : 619c4651-6d01-4c4b-bc6f-d3a1650094e8
SamAccountName    : clark.thompson
SID               : S-1-5-21-2974783224-3764228556-2640795941-2656
Surname           :
UserPrincipalName :
```

The query returns `clark.thompson`.

Answer: `clark.thompson`

# LDAP Anonymous Bind

## Question 1

### "What is the domain functional level?"

Students first need to download `windapsearch.py`:

Code: shell

```shell
git clone https://github.com/ropnop/windapsearch.git
```

```
┌─[htb-ac330204@htb-vpci2zpkts]─[~]
└──╼ $git clone https://github.com/ropnop/windapsearch.git

Cloning into 'windapsearch'...
remote: Enumerating objects: 83, done.
remote: Counting objects: 100% (14/14), done.
remote: Compressing objects: 100% (14/14), done.
remote: Total 83 (delta 0), reused 0 (delta 0), pack-reused 69
Receiving objects: 100% (83/83), 44.61 KiB | 1.78 MiB/s, done.
Resolving deltas: 100% (48/48), done.
```

After cloning the repository, students need to navigate into the directory and use the `windapsearch.py` tool to enumerate the domain functional level:

Code: shell

```shell
python3 windapsearch.py --dc-ip STMIP -u "" --functionality
```

```
┌─[htb-ac330204@htb-vpci2zpkts]─[~/windapsearch]
└──╼ $python3 windapsearch.py --dc-ip 10.129.42.188 -u "" --functionality

[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 10.129.42.188
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=INLANEFREIGHT,DC=LOCAL
[+] Functionality Levels:
[+]      domainControllerFunctionality: 2016
[+]      forestFunctionality: 2016
[+]      domainFunctionality: 2016
[+] Attempting bind
[+]     ...success! Binded as: 
[+]      None

[*] Bye!
```

Students will see that the domain functional level is `2016`.

Answer: `2016`

# LDAP Anonymous Bind

## Question 2

### "Find a user with unconstrained delegation who is also part of the Protected Users group"

Students need to run `windapsearch.py` from the Pwnbox/`PMVPN`:

Code: shell

```shell
python3 windapsearch.py --dc-ip STMIP -u "" --unconstrained-user --full | grep -A 5 Protected
```

```
┌─[us-academy-1]─[10.10.15.2]─[htb-ac330204@htb-wpsv2mjmuu]─[~/ldapsearch-ad]
└──╼ $python3 windapsearch.py --dc-ip 10.129.42.188 -u "" --unconstrained-user --full | grep -A 5 Protected

memberOf: CN=Protected Users,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
uSNChanged: 12904
name: sqldev
objectGUID: xsI7iohJJEuU3L9ddDQaZQ==
userAccountControl: 590336
badPwdCount: 0
```

Students will find that `sqldev` is the user that meets the criteria.

Answer: `sqldev`

# LDAP Anonymous Bind

## Question 3

### "What OU is the user Kevin Gregory part of (one word, case sensitive, i.e. Marketing)?"

Students need to run `windapsearch.py` from the Pwnbox/`PMVPN`:

Code: shell

```shell
python3 windapsearch.py --dc-ip STMIP -u "" -s kevin.gregory
```

```
┌─[htb-ac330204@htb-vpci2zpkts]─[~/windapsearch]
└──╼ $python3 windapsearch.py --dc-ip 10.129.42.188 -u "" -s kevin.gregory

[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 10.129.42.188
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=INLANEFREIGHT,DC=LOCAL
[+] Attempting bind
[+]     ...success! Binded as: 
[+]      None
[+] Doing fuzzy search for: "kevin.gregory"
[+]     Found 1 results:

CN=kevin.gregory,OU=Finance,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL

[*] Bye!
```

Students will find the `Finance` organizational unit from the query output.

Answer: `Finance`

# Credentialed LDAP Enumeration

## Question 1

### "What is the minimum password length for user accounts in the INLANEFREIGHT.LOCAL domain?"

Students first need to download `ldapsearch-ad.py`:

Code: shell

```shell
git clone https://github.com/yaap7/ldapsearch-ad.git
```

```
┌─[htb-ac330204@htb-wpsv2mjmuu]─[~]
└──╼ $git clone https://github.com/yaap7/ldapsearch-ad.git

Cloning into 'ldapsearch-ad'...
remote: Enumerating objects: 189, done.
remote: Counting objects: 100% (189/189), done.
remote: Compressing objects: 100% (114/114), done.
remote: Total 189 (delta 105), reused 143 (delta 70), pack-reused 0
Receiving objects: 100% (189/189), 90.71 KiB | 2.93 MiB/s, done.
Resolving deltas: 100% (105/105), done.
```

Students will then navigate into the cloned directory and run `ldapsearch-ad.py`:

Code: shell

```shell
python3 ldapsearch-ad.py -l STMIP -d inlanefreight -u james.cross -p Academy_Student!  -t pass-pols
```

```
┌─[htb-ac330204@htb-wpsv2mjmuu]─[~/ldapsearch-ad]
└──╼ $python3 ldapsearch-ad.py -l 10.129.42.188 -d inlanefreight -u james.cross -p Academy_Student!  -t pass-pols

## Result of "pass-pols" command ##
[+] Default password policy:
[+] |___Minimum password length = 7
[+] |___Password complexity = Disabled
[*] |___Lockout threshold = Disabled
[*] |___Password history length = 5
[+] |___Max password age = 1000000000 days, 0 hours, 0 minutes, 0 seconds
[+] |___Min password age = 0 seconds
[+] No fine grained password policy found (high privileges are required).
```

Students will see that the minimum password length is `7`.

Answer: `7`

# Credentialed LDAP Enumeration

## Question 2

### "What user account requires a smart card for interactive logon (SMARTCARD\_REQUIRED)?"

Students need to use `ldapsearch-ad.py`:

Code: shell

```shell
python3 ldapsearch-ad.py -l STMIP -d inlanefreight -u james.cross -p Academy_Student!  -t search -s '(useraccountcontrol:1.2.840.113556.1.4.803:=262144)'
```

```
┌─[us-academy-1]─[10.10.15.2]─[htb-ac330204@htb-wpsv2mjmuu]─[~/ldapsearch-ad]
└──╼ [★]$ python3 ldapsearch-ad.py -l 10.129.42.188 -d inlanefreight -u james.cross -p Academy_Student!  -t search -s '(useraccountcontrol:1.2.840.113556.1.4.803:=262144)'

## Result of "search" command ##
[+] |___accountExpires = 1601-01-01 00:00:00+00:00
[+] |___badPasswordTime = 1601-01-01 00:00:00+00:00
[+] |___badPwdCount = 0
[+] |___cn = sarah.lafferty
[+] |___codePage = 0
[+] |___countryCode = 0
[+] |___distinguishedName = CN=sarah.lafferty,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
[+] |___instanceType = 4
[+] |___lastLogoff = 1601-01-01 00:00:00+00:00
[+] |___lastLogon = 1601-01-01 00:00:00+00:00
[+] |___logonCount = 0
[+] |___msDS-SupportedEncryptionTypes = 0
[+] |___name = sarah.lafferty
[+] |___objectCategory = CN=Person,CN=Schema,CN=Configuration,DC=INLANEFREIGHT,DC=LOCAL
[+] |___objectClass = ['top', 'person', 'organizationalPerson', 'user']
[+] |___objectGUID = {89f93478-cedc-40c3-a465-6e884da67d16}
[+] |___objectSid = S-1-5-21-1314345416-1384098791-2567330002-1107
[+] |___primaryGroupID = 513
[+] |___pwdLastSet = 2020-12-07 19:08:57.013687+00:00
[+] |___sAMAccountName = sarah.lafferty
[+] |___sAMAccountType = SAM_USER_OBJECT
[+] |___userAccountControl = NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, SMARTCARD_REQUIRED
[+] |___whenChanged = 2020-12-07 19:09:17+00:00
[+] |___whenCreated = 2020-12-07 19:08:57+00:00
```

Students will see the script return `sarah.lafferty`.

Answer: `sarah.lafferty`

# Credentialed LDAP Enumeration

## Question 3

### "What is the password history size of the domain? (How many passwords remembered.)"

Students need to use `ldapsearch-ad.py`:

Code: shell

```shell
python3 ldapsearch-ad.py -l 10.129.42.188 -d inlanefreight -u james.cross -p Academy_Student! -t search -s '(&(objectClass=domainDNS)(objectClass=domain)) '| grep -B 5 -A 5 pwdHistoryLength
```

```
┌─[us-academy-1]─[10.10.15.2]─[htb-ac330204@htb-wpsv2mjmuu]─[~/ldapsearch-ad]
└──╼ [★]$ python3 ldapsearch-ad.py -l 10.129.42.188 -d inlanefreight -u james.cross -p Academy_Student! -t search -s '(&(objectClass=domainDNS)(objectClass=domain)) '| grep -B 5 -A 5 pwdHistoryLength

[+] |___objectCategory = CN=Domain-DNS,CN=Schema,CN=Configuration,DC=INLANEFREIGHT,DC=LOCAL
[+] |___objectClass = ['top', 'domain', 'domainDNS']
[+] |___objectGUID = {6cdd3ff1-0d61-4596-9dc8-0c1e1bcb3590}
[+] |___objectSid = S-1-5-21-1314345416-1384098791-2567330002
[+] |___otherWellKnownObjects = [b'B:32:683A24E2E8164BD3AF86AC3C2CF3F981:CN=Keys,DC=INLANEFREIGHT,DC=LOCAL', b'B:32:1EB93889E40C45DF9F0C64D23BBB6237:CN=Managed Service Accounts,DC=INLANEFREIGHT,DC=LOCAL']
[+] |___pwdHistoryLength = 5
[+] |___pwdProperties = 0
[+] |___rIDManagerReference = CN=RID Manager$,CN=System,DC=INLANEFREIGHT,DC=LOCAL
[+] |___replUpToDateVector = b'\x02\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\xe9k8G\x8fKaE\xa5\xee^\x88\xfd\x0ckX\x03P\x00\x00\x00\x00\x00\x007\xc7\x0c\x18\x03\x00\x00\x00E\xb2a\`\x07\xf8\x94F\xad\xddM\xf0\xd5\x01\xb4\xb3\x05p\x00\x00\x00\x00\x00\x00?\x93W\x19\x03\x00\x00\x00'
[+] |___serverState = 1
[+] |___subRefs = ['DC=ForestDnsZones,DC=INLANEFREIGHT,DC=LOCAL', 'DC=DomainDnsZones,DC=INLANEFREIGHT,DC=LOCAL', 'CN=Configuration,DC=INLANEFREIGHT,DC=LOCAL']
```

Students will see from the output that the password history length is `5`.

Answer: `5`

# Credentialed LDAP Enumeration

## Question 4

### "What user account has their userAccountControl value set to ENCRYPTED\_TEXT\_PWD\_ALLOWED (store passwords using reversible encryption)?"

Students need to run the following command with `ldapsearch-ad.py`:

Code: shell

```shell
python3 ldapsearch-ad.py -l STMIP -d inlanefreight -u james.cross -p Academy_Student!  -t search -s '(useraccountcontrol:1.2.840.113556.1.4.803:=128)'
```

```
┌─[us-academy-1]─[10.10.15.2]─[htb-ac330204@htb-wpsv2mjmuu]─[~/ldapsearch-ad]
└──╼ [★]$ python3 ldapsearch-ad.py -l 10.129.42.188 -d inlanefreight -u james.cross -p Academy_Student!  -t search -s '(useraccountcontrol:1.2.840.113556.1.4.803:=128)'

## Result of "search" command ##
[+] |___accountExpires = 1601-01-01 00:00:00+00:00
[+] |___badPasswordTime = 1601-01-01 00:00:00+00:00
[+] |___badPwdCount = 0
[+] |___cn = wilford.stewart
[+] |___codePage = 0
[+] |___countryCode = 0
[+] |___distinguishedName = CN=wilford.stewart,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
[+] |___instanceType = 4
[+] |___lastLogoff = 1601-01-01 00:00:00+00:00
[+] |___lastLogon = 1601-01-01 00:00:00+00:00
[+] |___logonCount = 0
[+] |___msDS-SupportedEncryptionTypes = 0
[+] |___name = wilford.stewart
[+] |___objectCategory = CN=Person,CN=Schema,CN=Configuration,DC=INLANEFREIGHT,DC=LOCAL
[+] |___objectClass = ['top', 'person', 'organizationalPerson', 'user']
[+] |___objectGUID = {3b77117b-5ac2-4599-b148-a9ac0d18d363}
[+] |___objectSid = S-1-5-21-1314345416-1384098791-2567330002-1108
[+] |___primaryGroupID = 513
[+] |___pwdLastSet = 2020-12-07 19:10:14.701176+00:00
[+] |___sAMAccountName = wilford.stewart
[+] |___sAMAccountType = SAM_USER_OBJECT
[+] |___userAccountControl = ENCRYPTED_TEXT_PWD_ALLOWED, NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
[+] |___whenChanged = 2020-12-07 19:10:33+00:00
[+] |___whenCreated = 2020-12-07 19:10:14+00:00
```

Students will find that it returns `wilford.stewart`

Answer: `wilford.stewart`

# Credentialed LDAP Enumeration

## Question 5

### "What is the userAccountControl bitmask for NORMAL\_ACCOUNT and ENCRYPTED\_TEXT\_PWD\_ALLOWED? (decimal value)"

Students need to consult [Microsoft documentation](https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties). The `bitmask` can be calculated by adding the values seen on the chart:

![[HTB Solutions/CAPE/z. images/bc82ad5dc2f1e05d247379332d714849_MD5.jpg]]

Students need to add `128` and `512`, for a total of `640`.

Answer: `640`

# Active Directory LDAP - Skills Assessment

## Question 1

### "Find the one user who has a useraccountcontrol attribute equivalent to 262656."

Students first connect to the spawned target using `xfreerdp` and authenticating as `htb-student:Acad_ad_enum_skillz!` :

Code: shell

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

Then, students need to open PowerShell and run `Get-ADUser`:

Code: powershell

```powershell
Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=262656)'
```

```
PS C:\Users\htb-student> Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=262656)'

DistinguishedName : CN=abigail.henry,CN=Users,DC=INLANEFREIGHTENUM1,DC=LOCAL
Enabled           : True
GivenName         :
Name              : abigail.henry
ObjectClass       : user
ObjectGUID        : 15b870bb-e71e-43a2-9b8e-8ce62b9a6098
SamAccountName    : abigail.henry
SID               : S-1-5-21-1572947012-227590625-1650757115-1815
Surname           :
UserPrincipalName :
```

The query returns `abigail.henry`

Answer: `abigail.henry`

# Active Directory LDAP - Skills Assessment

## Question 2

### "Using built-in tools enumerate a user that has the PASSWD\_NOTREQD UAC value set."

Using the previously established RDP session, students need to use PowerShell to run `Get-ADUser`:

Code: powershell

```powershell
Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=544)'
```

```
PS C:\Users\htb-student> Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=544)'

DistinguishedName : CN=clive.jones,CN=Users,DC=INLANEFREIGHTENUM1,DC=LOCAL
Enabled           : True
GivenName         :
Name              : clive.jones
ObjectClass       : user
ObjectGUID        : 752f8fbc-6f31-4774-b8ed-9f20ec03ff98
SamAccountName    : clive.jones
SID               : S-1-5-21-1572947012-227590625-1650757115-1802
Surname           :
UserPrincipalName :
```

The query returns `clive.jones`

Answer: `clive.jones`

# Active Directory LDAP - Skills Assessment

## Question 3

### "What group is the IT Support group nested into?"

Using the previously established RDP session, students need to use PowerShell to run `Get-ADGroup`:

Code: powershell

```powershell
Get-ADGroup 'IT Support' -Properties * | select MemberOf
```

```
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Users\htb-student> Get-ADGroup 'IT Support'  -Properties * | select MemberOf

MemberOf
--------
{CN=Server Technicians,CN=Users,DC=INLANEFREIGHTENUM1,DC=LOCAL}
```

The query returns the `Server Technicans` group.

Answer: `Server Technicians`

# Active Directory LDAP - Skills Assessment

## Question 4

### "Who is a part of this group through nested group membership?"

Using the previously established RDP session, students need to use PowerShell to run `Get-ADGroupMember`:

Code: powershell

```powershell
Get-ADGroupMember 'IT Support'
```

```
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Users\htb-student> Get-ADGroupMember 'IT Support'

distinguishedName : CN=sally.andrews,CN=Users,DC=INLANEFREIGHTENUM1,DC=LOCAL
name              : sally.andrews
objectClass       : user
objectGUID        : 4ca0747d-6be9-4711-81dc-020dbf2c2516
SamAccountName    : sally.andrews
SID               : S-1-5-21-1572947012-227590625-1650757115-1108
```

The query returns `sally.andrews`

Answer: `sally.andrews`

# Active Directory LDAP - Skills Assessment

## Question 5

### "How many users are in the Former Employees OU?"

Using the previously established RDP session, students need to use PowerShell to run the following query:

Code: powershell

```powershell
(Get-ADUser -Filter * -SearchBase 'OU=Former Employees,DC=inlanefreightenum1,dc=local').count
```

```
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Users\htb-student> (Get-ADUser -Filter * -SearchBase 'OU=Former Employees,DC=inlanefreightenum1,dc=local').count

103
```

The query returns `103`.

Answer: `103`

# Active Directory LDAP - Skills Assessment

## Question 6

### "What is the name of the computer that starts with RD? (Submit the FQDN in all capital letters)"

Using the previously established RDP session, students need to use PowerShell to `Get-ADComputer`:

Code: powershell

```powershell
Get-ADComputer -Filter * | ? {$_.Name -like "RD*"} | select DistinguishedName
```

```
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Users\htb-student> Get-ADComputer -Filter * | ? {$_.Name -like "RD*"} | select DistinguishedName

DistinguishedName
-----------------
CN=RDS01,CN=Computers,DC=INLANEFREIGHTENUM1,DC=LOCAL
```

Answer: `RDS01.INLANEFREIGHTENUM1.LOCAL`

# Active Directory LDAP - Skills Assessment

## Question 7

### "How many groups exist where the admincount attribute is set to 1?"

Using the previously established RDP session, students need to use PowerShell to run `Get-ADGroup`:

Code: powershell

```powershell
(Get-ADGroup -Filter "adminCount -eq 1" ).count
```

```
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Users\htb-student> (Get-ADGroup -Filter "adminCount -eq 1" ).count

13
```

Answer: `13`

# Active Directory LDAP - Skills Assessment

## Question 8

### "What user could be subjected to an ASREPRoasting attack and is NOT a protected user? (first.last)"

Using the previously established RDP session, students need to use PowerShell to run `Get-ADUser`:

Code: powershell

```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq 'True'} -Properties * | select SamAccountName,MemberOf
```

```
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Users\htb-student> Get-ADUser -Filter {DoesNotRequirePreAuth -eq 'True'} -Properties * | select SamAccountName,MemberOf

SamAccountName MemberOf
-------------- --------
Adrian.Clark   {CN=Protected Users,CN=Users,DC=INLANEFREIGHTENUM1,DC=LOCAL}
wilbur.douglas {}

PS C:\Users\htb-student>
```

Answer: `wilbur.douglas`

# Active Directory LDAP - Skills Assessment

## Question 9

### "What is the samaccountname of the one SPN set in the domain?"

Using the previously established RDP session, students need to use PowerShell to run `Get-ADUser`:

```powershell
Get-ADUser -filter *  -Properties * | where servicePrincipalName -ne $null | select SamAccountName
```
```
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Users\htb-student> Get-ADUser -filter *  -Properties * | where servicePrincipalName -ne $null | select SamAccountName

SamAccountName
--------------
krbtgt
mssqlprod
```

Answer: `mssqlprod`

# Active Directory LDAP - Skills Assessment

## Question 10

### "What non-default privilege does the htb-student user have?"

Using the previously established RDP session, students need to open an elevated PowerShell and enumerate privileges:

```powershell
whoami /priv
```
```
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeBackupPrivilege             Back up files and directories  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

Students will find out that `SeBackupPrivilege` is the non-default privilege that the `htb-student` user has.

Answer: `SeBackupPrivilege`