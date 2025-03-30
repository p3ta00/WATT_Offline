
| Section                                | Question Number | Answer                       |
| -------------------------------------- | --------------- | ---------------------------- |
| Active Directory Structure             | Question 1      | forest                       |
| Active Directory Structure             | Question 2      | True                         |
| Active Directory Structure             | Question 3      | authorization                |
| Active Directory Terminology           | Question 1      | Schema                       |
| Active Directory Terminology           | Question 2      | Service Principal Name       |
| Active Directory Terminology           | Question 3      | True                         |
| Active Directory Terminology           | Question 4      | Tombstone                    |
| Active Directory Terminology           | Question 5      | ntds.dit                     |
| Active Directory Objects               | Question 1      | true                         |
| Active Directory Objects               | Question 2      | Organizational Units         |
| Active Directory Objects               | Question 3      | Domain Controller            |
| Active Directory Functionality         | Question 1      | PDC Emulator                 |
| Active Directory Functionality         | Question 2      | Windows Server 2008 R2       |
| Active Directory Functionality         | Question 3      | Cross-link                   |
| Active Directory Functionality         | Question 4      | Relative ID Master           |
| Kerberos, DNS, LDAP, MSRPC             | Question 1      | 88                           |
| Kerberos, DNS, LDAP, MSRPC             | Question 2      | DNS                          |
| Kerberos, DNS, LDAP, MSRPC             | Question 3      | LDAP                         |
| NTLM Authentication                    | Question 1      | Kerberos                     |
| NTLM Authentication                    | Question 2      | Authenticate                 |
| NTLM Authentication                    | Question 3      | 10                           |
| User and Machine Accounts              | Question 1      | false                        |
| User and Machine Accounts              | Question 2      | Administrator                |
| User and Machine Accounts              | Question 3      | SYSTEM                       |
| User and Machine Accounts              | Question 4      | ObjectGUID                   |
| Active Directory Groups                | Question 1      | Security                     |
| Active Directory Groups                | Question 2      | true                         |
| Active Directory Groups                | Question 3      | yes                          |
| Active Directory Rights and Privileges | Question 1      | Administrators               |
| Active Directory Rights and Privileges | Question 2      | SeBackupPrivilege            |
| Active Directory Rights and Privileges | Question 3      | whoami /priv                 |
| Security in Active Directory           | Question 1      | integrity                    |
| Security in Active Directory           | Question 2      | Application Control Policies |
| Examining Group Policy                 | Question 1      | 90                           |
| Examining Group Policy                 | Question 2      | False                        |
| Examining Group Policy                 | Question 3      | Default Domain Policy        |
| AD Administration: Guided Lab Part I   | Question 1      | COMPLETE                     |
| AD Administration: Guided Lab Part II  | Question 1      | COMPLETE                     |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Active Directory Structure

## Question 1

### "What Active Directory structure can contain one or more domains?"

A `forest` may contain one or more domains:

![[HTB Solutions/Others/z. images/e3bfa265d593975a59d4ab47e479ec71_MD5.jpg]]

Answer: `Forest`

# Active Directory Structure

## Question 2

### "True or False; It can be common to see multiple domains linked together by trust relationships?"

`True`; it is common that multiple domains are linked together via trust relationships:

![[HTB Solutions/Others/z. images/f36ccf6c5d8e1d6d9535c08e8e442df1_MD5.jpg]]

Answer: `True`

# Active Directory Structure

## Question 3

### "Active Directory provides authentication and \_\_\_\_\_\_ within a Windows domain environment."

Active Directory provides authentication and `authorization` within a Windows domain environment:

![[HTB Solutions/Others/z. images/ece834f82753e91237d29ef1da16e9f3_MD5.jpg]]

Answer: `authorization`

# Active Directory Terminology

## Question 1

### "What is known as the "Blueprint" of an Active Directory environment?"

The `Schema` of an Active Directory environment is known as its Blueprint:

![[HTB Solutions/Others/z. images/e56e78c03471df853e40fd7e56b69a24_MD5.jpg]]

Answer: `Schema`

# Active Directory Terminology

## Question 2

### "What uniquely identifies a Service instance? (full name, not abbreviation)"

A `Service Principal Name` uniquely identifies a Service instance:

![[HTB Solutions/Others/z. images/2d1661045e11484f7d4ff03fab1c56e9_MD5.jpg]]

Answer: `Service Principal Name`

# Active Directory Terminology

## Question 3

### "True or False; Group Policy objects can be applied to user and computer objects."

`True`; `Group Policy` objects can be applied to user and computer objects:

![[HTB Solutions/Others/z. images/1445489823261079883d6ecfdc4d0475_MD5.jpg]]

Answer: `True`

# Active Directory Terminology

## Question 4

### "What container in AD holds deleted objects?"

A `Tombstone` is a container that holds deleted objects:

![[HTB Solutions/Others/z. images/d389e7a4323117c832127fbfad3b83f8_MD5.jpg]]

Answer: `Tombstone`

# Active Directory Terminology

## Question 5

### "What file contains the hashes of passwords for all users in a domain?"

The `NTDS.DIT` file contains the hashes of passwords for all users in a domain:

![[HTB Solutions/Others/z. images/1b2da083a578e679cb8fd75f3406f69d_MD5.jpg]]

Answer: `NTDS.DIT`

# Active Directory Objects

## Question 1

### "True or False; Computers are considered leaf objects."

`True`; computers are considered as leaf objects:

![[HTB Solutions/Others/z. images/f428ead2bb57e3375e938e1d69dc8414_MD5.jpg]]

Answer: `True`

# Active Directory Objects

## Question 2

### "\_\_\_\\ are objects that are used to store similar objects for ease of administration. (Fill in the blank)"

`Organizational Units` are objects that are used to store similar objects for ease of administration.

![[HTB Solutions/Others/z. images/2bd5eae071b85e46ecacef73d9c554ba_MD5.jpg]]

Answer: `Organizational Units`

# Active Directory Objects

## Question 3

### "What AD object handles all authentication requests for a domain?"

A `Domain Controller` handles all authentication requests for a domain:

![[HTB Solutions/Others/z. images/5e882d938b81342e33265978884c91aa_MD5.jpg]]

Answer: `Domain Controller`

# Active Directory Functionality

## Question 1

### "What role maintains time for a domain?"

The `PDC Emulator` maintains time within a domain:

![[HTB Solutions/Others/z. images/c4a0fa28424c04926ba20a531e2ed824_MD5.jpg]]

Answer: `PDC Emulator`

# Active Directory Functionality

## Question 2

### "What domain functional level introduced Managed Service Accounts?"

The `Windows Server 2008 R2` domain functional level introduced Managed Service Accounts:

![[HTB Solutions/Others/z. images/c0c9b81fd9d479d6f6f5f149a38f9d58_MD5.jpg]]

Answer: `Windows Server 2008 R2`

# Active Directory Functionality

## Question 3

### "What type of trust is a link between two child domains in a forest?"

The `Cross-link` trust type is a trust between child domains in a forest:

![[HTB Solutions/Others/z. images/aa25a3dd22a39e3efb92506741aa9bb0_MD5.jpg]]

Answer: `Cross-link`

# Active Directory Functionality

## Question 4

### "What role ensures that objects in a domain are not assigned the same SID? (full name)"

The `Relative ID Master` role ensures that objects in a domain are not assigned the same SID:

![[HTB Solutions/Others/z. images/34577c06795b0419aba4191f15c8bf73_MD5.jpg]]

Answer: `Relative ID Master`

# Kerberos, DNS, LDAP, MSRPC

## Question 1

### "What networking port does Kerberos use?"

Kerberos uses port `88`:

![[HTB Solutions/Others/z. images/0272b4565d5cc69cb2bc991729c67110_MD5.jpg]]

Answer: `88`

# Kerberos, DNS, LDAP, MSRPC

## Question 2

### "What protocol is utilized to translate names into IP addresses? (acronym)"

The `DNS` protocol is utilized to translate/resolve hostnames to IP addresses:

![[HTB Solutions/Others/z. images/bbbb489dbd203a7e1d3c8ef76e090d1f_MD5.jpg]]

Answer: `DNS`

# Kerberos, DNS, LDAP, MSRPC

## Question 3

### "What protocol does RFC 4511 specify? (acronym)"

The `LDAP` protocol is specified in [RFC 4511](https://datatracker.ietf.org/doc/html/rfc4511):

![[HTB Solutions/Others/z. images/2f34ed5735a983eee3999bb0ffe21684_MD5.jpg]]

Answer: `LDAP`

# NTLM Authentication

## Question 1

### "What Hashing protocol is capable of symmetric and asymmetric cryptography?"

`Kerberos` is capable of symmetric and asymmetric cryptography:

![[HTB Solutions/Others/z. images/5708286e805d3894affba38bfe491281_MD5.jpg]]

Answer: `Kerberos`

# NTLM Authentication

## Question 2

### "NTLM uses three messages to authenticate; Negotiate, Challenge, and \_\_\_\_\_\_. What is the missing message? (fill in the blank)"

The third missing message is `AUTHENTICATE_MESSAGE`:

![[HTB Solutions/Others/z. images/ef965a888cc2c4485fbd932da67f2263_MD5.jpg]]

Answer: `Authenticate`

# NTLM Authentication

## Question 3

### "How many hashes does the Domain Cached Credentials mechanism save to a host by default?"

By default, hosts save the last `10` hashes:

![[HTB Solutions/Others/z. images/9beaf6d9edbdd1585d9e864f49985c74_MD5.jpg]]

Answer: `10`

# User and Machine Accounts

## Question 1

### "True or False; A local user account can be used to login to any domain connected host."

`False`; only domain user accounts can be used to login to any domain connected host:

![[HTB Solutions/Others/z. images/788e59d092facff628b55f0ddc857fed_MD5.jpg]]

Answer: `False`

# User and Machine Accounts

## Question 2

### "What default user account has the SID "S-1-5-domain-500" ?"

The `Administrator` default user account has the SID of "S-1-5-domain-500":

![[HTB Solutions/Others/z. images/8d72af23d59ee954d5d79c61e1cef7c4_MD5.jpg]]

Answer: `Administrator`

# User and Machine Accounts

## Question 3

### "What account has the highest permission level possible on a Windows host"

The `SYSTEM` account has the highest permission level possible on a Windows host:

![[HTB Solutions/Others/z. images/f5ba9865d440799738afc093eba3c03b_MD5.jpg]]

Answer: `SYSTEM`

# User and Machine Accounts

## Question 4

### "What user naming attribute is unique to the user and will remain so even if the account is deleted?"

The `ObjectGUID` naming attribute is unique to a user and will remain so even if the account is deleted:

![[HTB Solutions/Others/z. images/b947a99964f34c8cb62c9ce5d3af0213_MD5.jpg]]

Answer: `ObjectGUID`

# Active Directory Groups

## Question 1

### "What group type is best utilized for assigning permissions and right to users?"

The `Security` group type is best utilized for assigning permissions and rights to users:

![[HTB Solutions/Others/z. images/a72e438a66b971277e319860b4b7142e_MD5.jpg]]

Answer: `Security`

# Active Directory Groups

## Question 2

### "True or False; A "Global Group" can only contain accounts from the domain where it was created."

`True`; a Global Group can only contain accounts from the domain where it was created:

![[HTB Solutions/Others/z. images/4f0fd7bba141489eb1901ba082ec47b2_MD5.jpg]]

Answer: `True`

# Active Directory Groups

## Question 3

### "Can a Universal group be converted to a Domain Local group? (yes or no)"

`Yes`; a Universal group can be converted to a Domain Local group without any restrictions:

![[HTB Solutions/Others/z. images/b37c3c4f3ad78a91328697dd98434b6e_MD5.jpg]]

Answer: `Yes`

# Active Directory Rights and Privileges

## Question 1

### "What built-in group will grant a user full and unrestricted access to a computer?"

The `Administrators` built-in group grants a user full and unrestricted access to a computer:

![[HTB Solutions/Others/z. images/5768c37b8c4c888c6ea35517ec17f1a3_MD5.jpg]]

Answer: `Administrators`

# Active Directory Rights and Privileges

## Question 2

### "What user right grants a user the ability to make backups of a system?"

The `SeBackupPrivilege` right grants a user the ability to make backups of a system:

![[HTB Solutions/Others/z. images/96ce49c447adca94ff47fa6369b801a4_MD5.jpg]]

Answer: `SeBackupPrivilege`

# Active Directory Rights and Privileges

## Question 3

### "What Windows command can show us all user rights assigned to the current user?"

The `whoami /priv` Windows command can show all user rights assigned to the current user issuing the command:

![[HTB Solutions/Others/z. images/857172b7f0cd2f47b7e1742dad94df69_MD5.jpg]]

Answer: `whoami /priv`

# Security In Active Directory

## Question 1

### "Confidentiality, \_\_\_\_\_\_\_, and Availability are the pillars of the CIA Triad. What term is missing? (fill in the blank)"

The CIA Triad's missing term is `Integrity`. The `DAD Triad` is the exact opposite of the CIA Triad.

![[HTB Solutions/Others/z. images/6b276c620e15126e7745ea7aa5bb1f25_MD5.jpg]]

Answer: `Integrity`

# Security In Active Directory

## Question 2

### "What security policies can block certain users from running all executables?"

The `Application Control Policies` can block certain user from running all executables:

![[HTB Solutions/Others/z. images/4cc44042ddd8119ee8dd4155ec940615_MD5.jpg]]

Answer: `Application Control Policies`

# Examining Group Policy

## Question 1

### "Computer settings for Group Policies are gathered and applied at a \_\_\_\_\_\_\_ minute interval? (answer is a number, fill in the blank )"

Computer settings for Group Policies are gathered and applied at a `90` minute interval:

![[HTB Solutions/Others/z. images/5da552880ec060f64d910fa69116c8cd_MD5.jpg]]

Answer: `90`

# Examining Group Policy

## Question 2

### "True or False: A policy applied to a user at the domain level would be overwritten by a policy at the site level."

`False`; `Group Policy settings` are processed from the top down starting from the OU level. A GPO applied to an object at the domain level would take precedence over settings at the site level, meaning that any settings in the Domain Policy would overwrite settings in the Site Policy. If it is intend for settings to be applied a certain way, then it must be assured that they are in the correct position in the domain hierarchy or they could run the risk of being overwritten and potentially cause a disruption or result in a security flaw (depending on the nature of the settings in the GPO in question).

Answer: `False`

# Examining Group Policy

## Question 3

### "What Group Policy Object is created when the domain is created?"

The `Default Domain Policy` is created when a domain is created:

![[HTB Solutions/Others/z. images/ea94073ba51003a709b89fff7e26346f_MD5.jpg]]

Answer: `Default Domain Policy`

# AD Administration: Guided Lab Part I

## Question 1

### "Once you have finished the tasks, type "COMPLETE" to move on."

For `Task 1: Manage Users`, students need to begin by authenticating to the target as `htb-student:Academy_student_DA!` with RDP:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student_adm /p:Academy_student_DA! /dynamic-resolution
```

```
┌─[us-academy-1]─[10.10.15.147]─[htb-ac594497@htb-gitnshtoch]─[~]
└──╼ [★]$ xfreerdp /v:10.129.202.146 /u:htb-student_adm /p:Academy_student_DA! /dynamic-resolution

[17:48:47:698] [3223:3226] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[17:48:47:698] [3223:3226] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
<SNIP>
```

Then, students need to open PowerShell as administrator and use the `New-ADUser` `Cmdlet` to create the first new domain user (remembering to set a password that meets the complexity requirements):

Code: powershell

```powershell
New-ADUser -Name "Orion Starchaser" -Accountpassword (ConvertTo-SecureString -AsPlainText (Read-Host "Enter a secure password") -Force ) -Enabled $true -OtherAttributes @{'title'="Analyst";'mail'="o.starchaser@inlanefreight.local"}
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Loading personal and system profiles took 1228ms.
PS C:\Windows\system32> New-ADUser -Name "Orion Starchaser" -Accountpassword (ConvertTo-SecureString -AsPlainText (Read-Host "Enter a secure password") -Force ) -Enabled $true -OtherAttributes @{'title'="Analyst";'mail'="o.starchaser@inlanefreight.local"}

Enter a secure password: P@ssw0rd!
```

For the next user, students need to utilize the `Active Directory Users and Computers` desktop app, also referred to as the `ADUC` or `ADUC MMC`:

![[HTB Solutions/Others/z. images/92697eedf74820b321571805225ffa1c_MD5.jpg]]

Students need to right click the `IT` group and select `New` --> `User`:

![[HTB Solutions/Others/z. images/d75318c6d3f1c440ffe66a3c37036502_MD5.jpg]]

From this interface, students need to enter appropriate information (First Name, Last Name, and User Logon Name) for the second domain user:

![[HTB Solutions/Others/z. images/41b7eee1da8df07206a16289cc6f9d79_MD5.jpg]]

Supplying the password as `NewP@ssw0rd123!`, and checking the box for User must change password at next login:

![[HTB Solutions/Others/z. images/1dc9f0e9cfc6177fc5ad500fc20ac2ff_MD5.jpg]]

After clicking `Next` --> `Finish`, the second user has now been created. Using `ADUC`, students need to check and confirm that the user exists. Additionally, students need to set the email address for this new user, which can be done by right-clicking the user and selecting `Properties`. The email can be entered into the appropriate field:

![[HTB Solutions/Others/z. images/ef37b0a9d31f79758333abf99497ea6e_MD5.jpg]]

![[HTB Solutions/Others/z. images/1553fd325d26137d33a03cc27164cf7b_MD5.jpg]]

Students are free to choose their own method to add the third domain user. However, it is recommended students use ADUC (as they will see in a future task.)

Now, students must remove the users `Mike O'Hare` and `Paul Valencia`. Using the previously established PowerShell session, students need to use the `Remove-ADUser` `Cmdlet`:

Code: powershell

```powershell
Remove-ADUser -Identity pvalencia
```

```
PS C:\Windows\system32> Remove-ADUser -Identity pvalencia

Confirm
Are you sure you want to perform this action?
Performing the operation "Remove" on target "CN=Paul
Valencia,OU=Sales,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL".
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): A
```

Alternatively, students can use the `ADUC MMC`, right clicking on `Employees` --> `Find` , and searching for the user:

![[HTB Solutions/Others/z. images/61bac594a17a314e0e561a8b90aa0ecb_MD5.jpg]]

![[HTB Solutions/Others/z. images/f82b1958480b6bb7618a3913d41d2d74_MD5.jpg]]

After pressing `Find Now`, students will be able to right click the user and delete them:

![[HTB Solutions/Others/z. images/8e3b15a3c76a5626ba004116c87db686_MD5.jpg]]

Now, nearing the end of the first task, students need to unlock the user `amasters` using PowerShell and the `Unlock-ADAccount` `Cmdlet`. Additionally, they must use the `Set-ADAccountPassword` `Cmdlet` to reset his password:

Code: powershell

```powershell
 Unlock-ADAccount -Identity amasters
 Set-ADAccountPassword -Identity 'amasters' -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "NewP@ssw0rdReset!" -Force)
```

```
PS C:\Windows\system32> Unlock-ADAccount -Identity amasters
PS C:\Windows\system32> Set-ADAccountPassword -Identity 'amasters' -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "NewP@ssw0rdReset!" -Force)
```

Finally, students need to place the `Force Password Change` setting on the account:

Code: powershell

```powershell
Set-ADUser -Identity amasters -ChangePasswordAtLogon $true
```

```
PS C:\htb> Set-ADUser -Identity amasters -ChangePasswordAtLogon $true
```

This concludes all of steps for Task I.

For `Task 2: Manage Groups and Other Organizational Units`, students need to use the same RDP session they used to complete `Task 1: Manage Users`.

To begin, students need to open PowerShell as administrator, and then create a both a new `AD OU` and `Security Group`. This will be accomplished with the `New-ADOrganizationalUnit` and `New-ADGroup` `Cmdlets`:

Code: powershell

```powershell
New-ADOrganizationalUnit -Name "Security Analysts" -Path "OU=IT,OU=HQ-NYC,OU=Employees,OU=CORP,DC=INLANEFREIGHT,DC=LOCAL"
```

```
PS C:\Windows\system32> New-ADOrganizationalUnit -Name "Security Analysts" -Path "OU=IT,OU=HQ-NYC,OU=Employees,OU=CORP,DC=INLANEFREIGHT,DC=LOCAL"

PS C:\Windows\system32> New-ADGroup -Name "Security Analysts" -SamAccountName analysts -GroupCategory Security -GroupScope Global -DisplayName "Security Analysts" -Path "OU=Security Analysts,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL" -Description "Members of this group are Security Analysts under the IT OU"
```

Secondly, students need to add the three new users to the Group. They will see an error regarding the user that was first created in `Task 1`.

Code: powershell

```powershell
Add-ADGroupMember -Identity analysts -Members ACepheus
Add-ADGroupMember -Identity analysts -Members ACallisto
Add-ADGroupMember -Identity analysts -Members OStarchaser
```

```
PS C:\> Add-ADGroupMember -Identity analysts -Members ACepheus
PS C:\> Add-ADGroupMember -Identity analysts -Members ACallisto
PS C:\> Add-ADGroupMember -Identity analysts -Members OStarchaser

Add-ADGroupMember : Cannot find an object with identity: 'OStarchaser' under: 'DC=INLANEFREIGHT,DC=LOCAL'.
At line:1 char:1
+ Add-ADGroupMember -Identity analysts -Members OStarchaser
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (OStarchaser:ADPrincipal) [Add-ADGroupMember], ADIdentityNotFoundExcepti
   on
    + FullyQualifiedErrorId : SetADGroupMember.ValidateMembersParameter,Microsoft.ActiveDirectory.Management.Commands.
   AddADGroupMember
```

This is because when the first user was created with the `New-ADUser` `Cmdlet`, the flag `-SamAccountName` was not specified. But, this can easily be corrected.

Using the `ADUS MMC`, students need to right click on `INLANEFREIGHT.LOCAL` and select `Find...`, searching for `Orion Starchaser`. Students must not search under `Employees`, but rather at the top of the domain hierarchy:

![[HTB Solutions/Others/z. images/2a361c8e8aebd1b9fbd6aa39e69fc6f1_MD5.jpg]]

![[HTB Solutions/Others/z. images/c51e1fd2ed3fed0e948d97f05f5bc8ea_MD5.jpg]]

Students need to double click `Orion Starchaser`, go to the `Account` tab, and input a username then press enter when finished:

![[HTB Solutions/Others/z. images/4d9e0cbdba52fed3316a7a75d229dc3a_MD5.jpg]]

Finally, students need to right click `Orion Starchaser` and select `Add to a group...`:

![[HTB Solutions/Others/z. images/10c0be4da4b314a7bb80e17e6174d304_MD5.jpg]]

Under `Object Types`, students need to select `Groups`:

![[HTB Solutions/Others/z. images/ab6dd9ea4ac9306a7599c4b84320870e_MD5.jpg]]

Now, students need to enter `Security Analysts` and press `OK`:

![[HTB Solutions/Others/z. images/f45220834fa1931f2933426a966ca5f4_MD5.jpg]]

There should be a prompt confirmed that operation was successful:

![[HTB Solutions/Others/z. images/921615ea8faf49041a7f5edefd68f4dc_MD5.jpg]]

All users have now been added to the `Security Analysts` group, allowing students to move on to `Task 3`.

For `Task 3: Manage Group Policy Objects`, students need to continue their administrative duties from the previously established RDP session.

To begin, students need to duplicate the group policy `Logon Banner` and rename it `Security Analysts Control`. This is best accomplished with an elevated PowerShell and the `Copy-GPO` `Cmdlet`:

Code: powershell

```powershell
Copy-GPO -SourceName "Logon Banner" -TargetName "Security Analysts Control"
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Loading personal and system profiles took 749ms.
PS C:\Windows\system32> Copy-GPO -SourceName "Logon Banner" -TargetName "Security Analysts Control"

DisplayName      : Security Analysts Control
DomainName       : INLANEFREIGHT.LOCAL
Owner            : INLANEFREIGHT\Domain Admins
Id               : 66645182-9568-4b6d-a1eb-e807f7e65491
GpoStatus        : AllSettingsEnabled
Description      :
CreationTime     : 3/1/2023 8:55:15 AM
ModificationTime : 3/1/2023 8:55:16 AM
UserVersion      : AD Version: 1, SysVol Version: 1
ComputerVersion  : AD Version: 1, SysVol Version: 1
WmiFilter        :
```

Next, students need to open `Group Policy Management` so they can check to confirm that the `GPO` was created:

![[HTB Solutions/Others/z. images/c2c98130fa5b75bfe141d13e67227a4f_MD5.jpg]]

![[HTB Solutions/Others/z. images/f29f1d47557c421863ce91c44e5c6a76_MD5.jpg]]

Back to the previously opened PowerShell, students now need to link the `GPO` to the `Security Analysts` `OU`:

Code: powershell

```powershell
New-GPLink -Name "Security Analysts Control" -Target "ou=Security Analysts,ou=IT,OU=HQ-NYC,OU=Employees,OU=Corp,dc=INLANEFREIGHT,dc=LOCAL" -LinkEnabled Yes
```

```
PS C:\Windows\system32> New-GPLink -Name "Security Analysts Control" -Target "ou=Security Analysts,ou=IT,OU=HQ-NYC,OU=Employees,OU=Corp,dc=INLANEFREIGHT,dc=LOCAL" -LinkEnabled Yes

GpoId       : 66645182-9568-4b6d-a1eb-e807f7e65491
DisplayName : Security Analysts Control
Enabled     : True
Enforced    : False
Target      : OU=Security Analysts,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
Order       : 1
```

With the link now established, students need to revisit the `Group Policy Management` dashboard, right clicking on the `Security Analysts Control` object and selecting `Edit`:

![[HTB Solutions/Others/z. images/6be2938939df69301bfccfb0d9f99e4a_MD5.jpg]]

Using the directories on the left hand side, students need to drill down into `User Configuration` --> `Policies` --> `Administrative Templates` --> `System` --> `Removable Storage Access`:

![[HTB Solutions/Others/z. images/f9f65d2589820ffc8e8a9c15cacaa81b_MD5.jpg]]

Students first need to configure the `All Removable Storage classes` setting, by right clicking and selecting `Edit`:

![[HTB Solutions/Others/z. images/be0e381c3a9a5c82ed00e16d1b7826f3_MD5.jpg]]

Then, students need to enable it and click `Apply` --> `OK`:

![[HTB Solutions/Others/z. images/1e1c60a4099899c42c22eefcc2aad3a5_MD5.jpg]]

This successfully completes the `User Configuration`.

Moving onto the computer configuration, students will again navigate the `Group Policy Management` editor, drilling down into `Computer Configuration` --> `Policies` --> `Windows Settings` --> `Security Settings` --> `Account Policies` --> `Password Policy`:

![[HTB Solutions/Others/z. images/f7fd223003f2c16d5ab6796f578107be_MD5.jpg]]

Right clicking on `Minimum password age`, students need to select `Properties`:

![[HTB Solutions/Others/z. images/8b4debcf2bbe3c2e01adc3e990b9c24f_MD5.jpg]]

From here, students need to check the box for `Define this policy setting` and setting the time to 10 days:

![[HTB Solutions/Others/z. images/6dbbf9444ba825071cee78e326cdeb8a_MD5.jpg]]

Students need to click `Apply`, and then `OK` to confirm the change (alternatively, in case of display issues, students can press enter on the keyboard.)

Afterward, students need to repeat these steps, configuring the properties for the `Password History policy` and `Enforce password history` policies:

![[HTB Solutions/Others/z. images/92c51e2816c913872851dcf65d5c4dcc_MD5.jpg]]

![[HTB Solutions/Others/z. images/ebf4b164fbfa2368f0ef5b4075ee5a93_MD5.jpg]]

After finish all of the above tasks, students need to type `COMPLETE` for the answer.

Answer: `COMPLETE`

# AD Administration: Guided Lab Part II

## Question 1

### "Once you have finished the tasks, type "COMPLETE" to move on."

For `Task 4: Add and Remove Computers To The Domain`, students need to add a computer to a domain and change the `OU` it resides in.

To begin, students need to authenticate to the target as `image:Academy_student_AD!` with RDP:

Code: shell

```shell
xfreerdp /v:STMIP /u:image /p:Academy_student_AD! /dynamic-resolution
```

```
┌─[us-academy-1]─[10.10.15.147]─[htb-ac594497@htb-ayrqtp3fgu]─[~]
└──╼ [★]$ xfreerdp /v:10.129.42.198 /u:image /p:Academy_student_AD! /dynamic-resolution

[14:48:48:776] [2095:2096] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[14:48:48:776] [2095:2096] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[14:48:48:776] [2095:2096] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
<SNIP>
```

After the connection has been established, students need to open an elevated PowerShell. Using the `Add-Computer` `Cmdlet`, students will add the local machine to the domain and then restart it:

Code: powershell

```powershell
Add-Computer -DomainName INLANEFREIGHT.LOCAL -Credential INLANEFREIGHT\HTB-student_adm -Restart
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

WARNING: Error initializing default drive: 'Unable to find a default server with Active Directory Web Services
running.'.
Loading personal and system profiles took 1159ms.

PS C:\Windows\system32> Add-Computer -DomainName INLANEFREIGHT.LOCAL -Credential INLANEFREIGHT\HTB-student_adm -Restart
```

Subsequently, students need to enter the password for `HTB-Student_adm` when prompted (`Academy_student_DA!`). The machine will restart, requiring students connect once again with RDP. However, now that the machine is on the domain, students should authenticate as `htb-student_adm:Academy_student_DA!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student_adm /p:Academy_student_DA! /dynamic-resolution
```

```
┌─[us-academy-1]─[10.10.15.147]─[htb-ac594497@htb-ayrqtp3fgu]─[~]
└──╼ [★]$ xfreerdp /v:10.129.42.198 /u:htb-student_adm /p:Academy_student_DA! /dynamic-resolution

[15:25:06:796] [2708:2709] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[15:25:06:796] [2708:2709] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[15:25:06:796] [2708:2709] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
[15:25:06:796] [2708:2709] [INFO][com.freerdp.client.common.cmdline] - loading channelEx cliprdr
<SNIP>
```

Additionally, while the RDP session is connecting, students will notice the certificate details have changed (verifying the machine has joined the domain):

```
New Certificate details:
	Common Name: ACADEMY-IAD-W10.INLANEFREIGHT.LOCAL
	Subject:     CN = ACADEMY-IAD-W10.INLANEFREIGHT.LOCAL
	Issuer:      CN = ACADEMY-IAD-W10.INLANEFREIGHT.LOCAL
	Thumbprint:  e3:b4:1a:9d:07:18:0f:53:42:1d:48:6a:5a:e2:27:9c:2d:2d:6c:fe:d4:0c:75:19:31:1f:89:a6:48:a2:8b:66

Old Certificate details:
	Subject:     CN = ACADEMY-IAD-W10
	Issuer:      CN = ACADEMY-IAD-W10
	Thumbprint:  7a:86:c9:7c:d5:d3:b8:03:f2:35:ce:ea:e0:70:c7:39:d4:ed:25:80:81:74:d9:b7:82:19:ce:1b:6c:db:ff:22
```

Now, students need to open the `ADUC MMC`, navigate to `Computers`, and confirm the `ACADEMY-IAD-W10` machine is there:

![[HTB Solutions/Others/z. images/5c40ed21e73bae22c842f2856a969ec2_MD5.jpg]]

Afterward, students need to right click the `ACADEMY-IAD-W10` machine, select `Move...`, and then add it to the `Security Analysts` `OU`:

![[HTB Solutions/Others/z. images/797f52489db81c83acc5b185723e6937_MD5.jpg]]

![[HTB Solutions/Others/z. images/7afd83d14b08922dccd925e94c8674b0_MD5.jpg]]

An administrator PowerShell can be used to confirm the `OU` membership, which is presented as the canonical name:

Code: powershell

```powershell
Get-ADComputer -Identity "ACADEMY-IAD-W10" -Properties * | select CN,CanonicalName,IPv4Address
```

```
PS C:\Windows\system32> Get-ADComputer -Identity "ACADEMY-IAD-W10" -Properties * | select CN,CanonicalName,IPv4Address

CN              CanonicalName                                                                  IPv4Address
--              -------------                                                                  -----------
ACADEMY-IAD-W10 INLANEFREIGHT.LOCAL/Corp/Employees/HQ-NYC/IT/Security Analysts/ACADEMY-IAD-W10 172.16.6.135
```

With the machine now joined to the domain as well as an OU, students have successfully completed the requirements of `Task 4`, thus, they need to type `COMPLETE` as the answer.

Answer: `COMPLETE`