| Section | Question Number | Answer |
| --- | --- | --- |
| SharpHound - Data Collection from Windows (Part 2) | Question 1 | DONE |
| Nodes | Question 1 | SRV01 |
| Nodes | Question 2 | HTB-STUDENT |
| Nodes | Question 3 | SERVERS |
| Nodes | Question 4 | FIREWALL\_MANAGER |
| Analyzing BloodHound Data | Question 1 | BACKUPS |
| Analyzing BloodHound Data | Question 2 | AddKeyCredentialLink |
| Analyzing BloodHound Data | Question 3 | DCSync |
| Analyzing BloodHound Data | Question 4 | Workstations |
| Analyzing BloodHound Data | Question 5 | 7 |
| Analyzing BloodHound Data | Question 6 | DC01 |
| Analyzing BloodHound Data | Question 7 | htb-student |
| BloodHound for BlueTeams | Question 1 | 30 |
| BloodHound for BlueTeams | Question 2 | WS01 |
| BloodHound for BlueTeams | Question 3 | SCREENSAVER |
| BloodHound for BlueTeams | Question 4 | MemberOf |
| Skills Assessment | Question 1 | jorge |
| Skills Assessment | Question 2 | ENTERPRISE ADMINS |
| Skills Assessment | Question 3 | WriteOwner |
| Skills Assessment | Question 4 | ESTER |
| Skills Assessment | Question 5 | JORGE |
| Skills Assessment | Question 6 | 30.76 |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# SharpHound - Data Collection from Windows

## Question 1

### "Repeat the examples in the section and type DONE as the answer when you are finished."

Students will begin by initiating an RDP session (`htb-student:HTBRocks!`) to connect to the target:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:HTBRocks! /dynamic-resolution
```

```
┌─[eu-academy-1]─[10.10.15.73]─[htb-ac594497@htb-8lhfwtxnmo]─[~]
└──╼ [★]$ xfreerdp /v:10.129.204.228 /u:htb-student /p:HTBRocks! /dynamic-resolution

[20:19:15:760] [2092:2093] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[20:19:15:760] [2092:2093] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[20:19:15:760] [2092:2093] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
[20:19:15:760] [2092:2093] [INFO][com.freerdp.client.common.cmdline] - loading channelEx cliprdr
<SNIP>
```

Then, students need to launch an elevated Command Prompt and navigate to `C:\Tools`, where the SharpHound.exe is located and can then be ran:

Code: cmd

```cmd
cd C:\tools
SharpHound.exe
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd C:\Tools\

C:\Tools>SharpHound.exe

2023-03-02T14:30:01.8643045-06:00|INFORMATION|This version of SharpHound is compatible with the 4.2 Release of BloodHound
2023-03-02T14:30:02.0674608-06:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-03-02T14:30:02.1144271-06:00|INFORMATION|Initializing SharpHound at 2:30 PM on 3/2/2023
2023-03-02T14:30:50.5205672-06:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts,

<SNIP>

2023-03-02T14:32:26.8799226-06:00|INFORMATION|Status: 141 objects finished (+141 1.46875)/s -- Using 41 MB RAM
2023-03-02T14:32:26.8799226-06:00|INFORMATION|Enumeration finished in 00:01:36.1041246
2023-03-02T14:32:27.0049183-06:00|INFORMATION|Saving cache with stats: 101 ID to type mappings.
 105 name to SID mappings.
 1 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2023-03-02T14:32:27.0205503-06:00|INFORMATION|SharpHound Enumeration Completed at 2:32 PM on 3/2/2023! Happy Graphing!
```

Because the neo4j database is already running on the target, students are free to simply launch Bloodhound from the current Command Prompt:

Code: cmd

```cmd
cd Bloodhound
BloodHound.exe
```

```
C:\Tools>cd BloodHound

C:\Tools\BloodHound>BloodHound.exe

C:\Tools\BloodHound>
(node:3040) electron: The default of contextIsolation is deprecated and will be changing from false to true in a future release of Electron.  See https://github.com/electron/electron/issues/23506 for more information
(node:5052) [DEP0005] DeprecationWarning: Buffer() is deprecated due to security and usability issues. Please use the Buffer.alloc(), Buffer.allocUnsafe(), or Buffer.from() methods instead.
```

From the newly launched Bloodhound dashboard, students must enter credentials (`neo4j:Password123`) and then Login:

![[HTB Solutions/CAPE/z. images/f77de68c3a530419bbe55ed82d1d7640_MD5.webp]]

Upon being greeted by the dashboard, students need to click the Upload Data button on the right hand side.

![[HTB Solutions/CAPE/z. images/1baf9a034b2a83a4ac2480905f774f98_MD5.jpg]]

And select the newly created BloodHound zip file:

![[HTB Solutions/CAPE/z. images/f5c054155a24d0be558114234d273dbc_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/3aaaa1624d15d926b90571567cbc94c4_MD5.jpg]]

After a brief moment, the data will be imported. Students are encouraged to explore the BloodHound tool and acquired domain data, familiarizing themselves with the tool and its interface.

Answer: `DONE`

# SharpHound - Data Collection from Windows (Part 2)

## Question 1

### "Connect to the target machine using haris credentials port 13389. Try to collect BloodHound data from a non-domain joined machine. Use DONE as answer when finished."

Students will begin by initiating an RDP session (`haris:Hackthebox`) to connect to the target on the alternate port 13389:

Code: shell

```shell
xfreerdp /v:STMIP:13389 /u:haris /p:Hackthebox /dynamic-resolution
```

```
┌─[eu-academy-1]─[10.10.15.73]─[htb-ac594497@htb-8lhfwtxnmo]─[~]
└──╼ [★]$ xfreerdp /v:10.129.204.226:13389 /u:haris /p:Hackthebox /dynamic-resolution

[21:03:19:105] [3555:3556] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[21:03:19:105] [3555:3556] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[21:03:19:105] [3555:3556] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
[21:03:19:105] [3555:3556] [INFO][com.freerdp.client.common.cmdline] - loading channelEx cliprdr
<SNIP>
```

Then, students need to determine if they are on a domain-joined machine or not, utilizing an elevated Command Prompt:

Code: cmd

```cmd
echo %USERDOMAIN%
hostname
```

```
Microsoft Windows [Version 10.0.19044.1826]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>echo %USERDOMAIN%
WS02

C:\Windows\system32>hostname
WS02
```

Seeing that the `%USERDOMAIN%` environment variable matches the hostname of the machine, students will know that the machine is not on a domain but rather a basic workgroup.

Therefore, students may to configure the DNS server to the IP 172.16.230.3. Using the current RDP session, students will navigate to Control Panel -> Network and Internet -> Network Connections. By right clicking on Ethernet0, students will click Properties:

![[HTB Solutions/CAPE/z. images/ed615c0aab5ece88b3e6e4f02b113495_MD5.jpg]]

Choosing IPv4 and clicking Properties once again:

![[HTB Solutions/CAPE/z. images/55be88acf3e15b86ac4c0dde5dd8b6c2_MD5.jpg]]

Students need to ensure the DNS server is set to 172.16.130.3 and press OK:

![[HTB Solutions/CAPE/z. images/94264c122bf53335756ab7b1fca0f048_MD5.jpg]]

Using the Command Prompt from prior, students need to spawn a new instance of cmd.exe as a domain user:

Code: cmd

```cmd
runas /netonly /user:INLANEFREIGHT\htb-student cmd.exe
```

```
C:\Windows\system32>runas /netonly /user:INLANEFREIGHT\htb-student cmd.exe

Enter the password for INLANEFREIGHT\htb-student:
Attempting to start cmd.exe as user "INLANEFREIGHT\htb-student" ...
```

Forcing a new Command Prompt to appear:

![[HTB Solutions/CAPE/z. images/46815dfb6614f69c3352085b2721b16b_MD5.jpg]]

Students need to confirm that they can interact with the Domain Controller via hostname:

Code: cmd

```cmd
net view \\inlanefreight.htb\
```

```
Microsoft Windows [Version 10.0.19044.1826]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>net view \\inlanefreight.htb\
Shared resources at \\inlanefreight.htb\

Share name  Type  Used as  Comment

-------------------------------------------------------------------------------
CertEnroll  Disk           Active Directory Certificate Services share
NETLOGON    Disk           Logon server share
SYSVOL      Disk           Logon server share
The command completed successfully.
```

Now, students should be able to run the SharpHound against the inlanefreight.htb domain:

Code: cmd

```cmd
SharpHound.exe -d inlanefreight.htb
```

```
C:\Windows\system32>C:\Tools\SharpHound.exe -d inlanefreight.htb

2023-03-02T14:01:28.0213701-08:00|INFORMATION|This version of SharpHound is compatible with the 4.2 Release of BloodHound
2023-03-02T14:01:28.2728057-08:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-03-02T14:01:28.3025190-08:00|INFORMATION|Initializing SharpHound at 2:01 PM on 3/2/2023
<SNIP>
2023-03-02T14:04:02.9273460-08:00|INFORMATION|Enumeration finished in 00:02:34.0393251
2023-03-02T14:04:03.0523373-08:00|INFORMATION|Saving cache with stats: 101 ID to type mappings.
 105 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2023-03-02T14:04:03.0679648-08:00|INFORMATION|SharpHound Enumeration Completed at 2:04 PM on 3/2/2023! Happy Graphing!
```

Students are encourage to explore other tactics shown in the section, such as writing the SharpHound output to a shared folder.

Answer: `DONE`

# BloodHound.py - Data Collection from Linux

## Question 1

### "Repeat the examples in the section and type DONE as the answer when you are finished."

Students need to download `bloodhound.py` and install it:

Code: shell

```shell
git clone https://github.com/fox-it/BloodHound.py -q & cd BloodHound.py/
sudo python3 setup.py install
```

```
┌─[eu-academy-1]─[10.10.14.221]─[htb-ac594497@htb-bnhfri97nr]─[~]
└──╼ [★]$ git clone https://github.com/fox-it/BloodHound.py -q & cd BloodHound.py/
┌─[eu-academy-1]─[10.10.14.221]─[htb-ac594497@htb-bnhfri97nr]─[~/BloodHound.py]
└──╼ [★]$ sudo python3 setup.py install

running install
running bdist_egg
running egg_info
creating bloodhound.egg-info
writing bloodhound.egg-info/PKG-INFO
<SNIP>
Using /usr/lib/python3/dist-packages
Finished processing dependencies for bloodhound==1.6.1
```

Then, students need to use `bloodhound.py` to gather data from the domain controller only, using kerberos to authenticate as (`htb-student:HTBRocks!`):

Code: shell

```shell
python3 bloodhound.py -d inlanefreight.htb -c DCOnly -u htb-student -p HTBRocks! -ns 10.129.204.226 --kerberos
```

```
┌─[eu-academy-1]─[10.10.14.221]─[htb-ac594497@htb-bnhfri97nr]─[~/BloodHound.py]
└──╼ [★]$ python3 bloodhound.py -d inlanefreight.htb -c DCOnly -u htb-student -p HTBRocks! -ns 10.129.204.226 --kerberos
INFO: Found AD domain: inlanefreight.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.inlanefreight.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Connecting to LDAP server: dc01.inlanefreight.htb
INFO: Found 34 users
INFO: Found 60 groups
INFO: Found 5 gpos
INFO: Found 6 ous
INFO: Found 19 containers
INFO: Found 8 computers
INFO: Found 0 trusts
INFO: Done in 00M 02S
```

Once finished, students need to confirm the data was gathered and saved on their attack host:

Code: shell

```shell
ls | grep .json
```

```
┌─[eu-academy-1]─[10.10.14.221]─[htb-ac594497@htb-bnhfri97nr]─[~/BloodHound.py]
└──╼ [★]$ ls | grep .json

20230304165415_computers.json
20230304165415_containers.json
20230304165415_domains.json
20230304165415_gpos.json
20230304165415_groups.json
20230304165415_ous.json
20230304165415_users.json
```

Students are encouraged to explore both NTLM and kerberos authentication methods using `bloodhound.py`.

Answer: `DONE`

# Nodes

## Question 1

### "To which computer is user Sarah, an administrator?"

Students need to first start the `neo4j` service prior to using `Bloodhound`:

Code: shell

```shell
sudo service neo4j start
bloodhound
```

```
┌─[eu-academy-1]─[10.10.14.221]─[htb-ac594497@htb-bnhfri97nr]─[~]
└──╼ [★]$ sudo service neo4j start
┌─[eu-academy-1]─[10.10.14.221]─[htb-ac594497@htb-bnhfri97nr]─[~]
└──╼ [★]$ bloodhound
(node:6531) electron: The default of contextIsolation is deprecated and will be changing from false to true in a future release of Electron.  See https://github.com/electron/electron/issues/23506 for more information
```

Giving it a few moments to launch, students will be greeted by the login screen where they can authenticate as `neo4j:neo4j`.

![[HTB Solutions/CAPE/z. images/42062b6e74ec3135d1270c3ea1827898_MD5.jpg]]

Then, students need to upload the `BH.zip` file:

![[HTB Solutions/CAPE/z. images/4f265390778747b5d0d5b0473440ca53_MD5.jpg]]

Upon the completion of the Upload, students need to search for Sarah and go to the `Node Info` tab, scrolling down to `First Degree Local Admin` within the LOCAL ADMIN RIGHTS:

![[HTB Solutions/CAPE/z. images/b5025d7b7519bc603b2d7948fb087b6f_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/516b71ae7b8513d0eff38f870bc7b775_MD5.jpg]]

From the graphic generated, students will see that Sarah is AdminTo SRV01.

Answer: `SRV01`

# Nodes

## Question 2

### "Who is a first-degree remote desktop user on the computer WS01?"

Using the previously uploaded Bloodhound data, students need to search for WS01 and go to the `Node Info` tab, eventually scrolling down to `First Degree Remote Desktop Users` within the INBOUND EXECUTION RIGHTS:

![[HTB Solutions/CAPE/z. images/23979ad33a0520c32d1eb6d2fc005dbd_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/f5359caac97c2e6716bfdc9a3ed53ed1_MD5.jpg]]

From the graphic generated, students will see that `htb-student` is AdminTo WS01.

Answer: `htb-student`

# Nodes

## Question 3

### "Within which OU the computer SRV01 is located?"

Using the previously uploaded Bloodhound data, students need to search for SRV01 and go to the `Node Info` tab, selecting `See Computer within Domain/OU Tree` within OVERVIEW:

![[HTB Solutions/CAPE/z. images/2f89a3e48ce583c640dcc38e056f3536_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/b8713e1378388b1d8f6506b0d898e321_MD5.jpg]]

From the graphic generated, students will see that `SRV01` is within `SERVERS` OU.

Answer: `SERVERS`

# Nodes

## Question 4

### "Which non-default Group Policy affects all users?"

Using the previously uploaded Bloodhound data, students need to search for `Users` (making sure to select the container rather than group). From the `Node Info` tab, students need to select `GPOs Affecting This Container` within Affecting GPOs:

![[HTB Solutions/CAPE/z. images/1d4bcaf7083000046646c0f5c9adc60f_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/5075cf4885cc759438755d79fdfe2f01_MD5.jpg]]

From the graphic generated, students will see that `FIREWALL_MANAGER` `GPO` affecting USERS containers

Answer: `FIREWALL_MANAGER`

# Edges

## Question 1

### "Repeat the examples in the section and type DONE as the answer when you are finished."

Students are highly encouraged to repeat the examples in the section, and once finished, type `DONE` as the answer.

Answer: `DONE`

# Analyzing BloodHound Data

## Question 1

### "What's the name of a non-default GPO that affects the Domain Controller container and can be used to escalate privileges in the Domain?"

Students need to first start the `neo4j` service prior to using `Bloodhound`:

Code: shell

```shell
sudo service neo4j start
bloodhound
```

```
┌─[eu-academy-1]─[10.10.14.221]─[htb-ac594497@htb-bnhfri97nr]─[~]
└──╼ [★]$ sudo service neo4j start
┌─[eu-academy-1]─[10.10.14.221]─[htb-ac594497@htb-bnhfri97nr]─[~]
└──╼ [★]$ bloodhound
(node:6531) electron: The default of contextIsolation is deprecated and will be changing from false to true in a future release of Electron.  See https://github.com/electron/electron/issues/23506 for more information
```

Giving it a few moments to launch, students will be greeted by the login screen where they can authenticate as `neo4j:neo4j`.

![[HTB Solutions/CAPE/z. images/42062b6e74ec3135d1270c3ea1827898_MD5.jpg]]

Then, students need to upload the `BH.zip` file:

![[HTB Solutions/CAPE/z. images/4f265390778747b5d0d5b0473440ca53_MD5.jpg]]

After the upload has finished, students need to search for `DOMAIN CONTROLLERS` container and go to the `Node Info` tab, clicking `GPOs Affecting This OU` within Affecting GPOS:

![[HTB Solutions/CAPE/z. images/3490b41b54fc352bd2100102acafc5b3_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/04bb652e1c97646d03600a35695b867d_MD5.jpg]]

From the graphic generated, students will see that `BACKUPS` `GPO` affecting `DOMAIN CONTROLLERS` `containers`.

Answer: `BACKUPS`

# Analyzing BloodHound Data

## Question 2

### "Using the attached data, find what rights the user Sarah has over the user Nicole."

Using the previously uploaded `BloodHound` data, students need to utilize the `Pathfind` feature, setting the start node as `SARAH` and the target note `NICOLE`:

![[HTB Solutions/CAPE/z. images/32d98ab8a0ede098e998ec4b39fb3213_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/02b7161f5719bb77e1b919a30f378165_MD5.jpg]]

From the graphic generated, students will know that `AddKeyCredentialLink` is the edge `SARAH` can use to compromise `NICOLE`.

Answer: `AddKeyCredentialLink`

# Analyzing BloodHound Data

## Question 3

### "Find what attack the Enterprise Admins group can execute over the Domain object."

Using the previously uploaded BloodHound data `BH.zip`, students need to utilize the `Pathfind` feature, setting the start node as `ENTERPRISE ADMINS` and the target note `INLANEFREIGHT.HTB`:

![[HTB Solutions/CAPE/z. images/581a6cc37798786842fcc3a220d2956e_MD5.jpg]]

Followed by students right clicking on the Help option for `GenericAll` and selecting the `Abuse Info` tab:

![[HTB Solutions/CAPE/z. images/ec5aea19588e4b9e36e1987dd10b6981_MD5.jpg]]

There, students will find that `BloodHound` reveals the exact usage of a `DCSync` attack as a result of the `GenericAll` edge.

Answer: `DCSync`

# Analyzing BloodHound Data

## Question 4

### "Which OU is affected by the GPO ScreenSaver?"

Using the previously uploaded Bloodhound data `BH.zip`, students need to search for the `SCREENSAVER` GPO and go to the Node info tab, selecting `Directly Affected OUs` within AFFECTED OBJECTS:

![[HTB Solutions/CAPE/z. images/055baa2febf204eb75b6eee6a00d7ced_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/671975631f977db8aaeb3abc9c48948a_MD5.jpg]]

From the graphic generated, students will know that `SCREENSAVER` GPO has a `GPLink` to the `OU` `WORKSTATIONS`.

Answer: `WORKSTATIONS`

# Analyzing BloodHound Data

## Question 5

### "How many incoming explicit object controllers exist in the Domain Users group?"

Using the previously uploaded Bloodhound data `BH.zip`, students need to search for the `Domain Users` group and go to the `Node Info` tab, selecting `Explicit Object Controllers` within `INBOUND CONTROL RIGHTS`:

![[HTB Solutions/CAPE/z. images/ccc394c854299e6669d9824288c8cfef_MD5.jpg]]

Students will find `7` incoming explicit object controllers on the `DOMAIN USERS` group.

Answer: `7`

# Analyzing BloodHound Data

## Question 6

### "Which host is Julio's user connected to? (only hostname)"

Using the previously uploaded Bloodhound data `BH.zip`, students need to search for the `JULIO` user and go to the Node info tab, selecting `SESSIONS` within OVERVIEW:

![[HTB Solutions/CAPE/z. images/aa8de0b3a6645300642e5cb42c1176e3_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/1399f8546f7082aaedc6cc21620bf5c4_MD5.jpg]]

From the graphic generated, students will see that JULIO HasSession to `DC01`.

Answer: `DC01`

# Analyzing BloodHound Data

## Question 7

### "Which other user has a session on another computer?"

Using the previously uploaded Bloodhound data (`BH.zip`), students need to search for the `DOMAIN USERS` user and go to the Node info tab, selecting `SESSIONS` within OVERVIEW:

![[HTB Solutions/CAPE/z. images/545fe392737256b613639a67ef6412b4_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/85b68ca393a81eadd6bcd6957503a7a7_MD5.jpg]]

From the graphic generated, students will know that `HTB-STUDENT` HasSession to `WS01`.

Answer: `HTB-STUDENT`

# Cypher Queries

## Question 1

### "Use the file BH.zip from previous section and repeat the examples in the section and type DONE as the answer when you are finished."

Students are highly encouraged to repeat the examples in the section, and once finished, type `DONE` as the answer.

Answer: `DONE`

# BloodHound for BlueTeams

## Question 1

### "Using BlueHound custom dashboard. What percentage of users have a path to Domain Admins? (Do not include %)

Students need to first connect to the spawned target (`htb-student:HTBRocks!`) using RDP:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:HTBRocks! /dynamic-resolution
```

```
┌─[eu-academy-1]─[10.10.15.19]─[htb-ac594497@htb-5876putejx]─[~]
└──╼ [★]$ xfreerdp /v:10.129.204.228 /u:htb-student /p:HTBRocks! /dynamic-resolution

[15:47:06:030] [2767:2768] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[15:47:06:031] [2767:2768] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[15:47:06:031] [2767:2768] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
[15:47:06:031] [2767:2768] [INFO][com.freerdp.client.common.cmdline] - loading channelEx cliprdr
<SNIP>
```

Once the connection has been established, students will open File Explorer , navigate to `C:\Tools\BlueHound` and launch BlueHound.exe as administrator:

![[HTB Solutions/CAPE/z. images/4697b0adc6aea3230699af812600e9c3_MD5.jpg]]

Upon clicking Login, students need to authenticate (`neo4j:Password123`) to the database:

![[HTB Solutions/CAPE/z. images/a25f17eda4cd459049c5b391e34640b9_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/a23fcfdd6db348473d5db367c3850dd0_MD5.jpg]]

Now, students have access to the `BlueHound` dashboard, but they still need to import a configuration file. Therefore, students need to Click on `Import Config` -> `Select From File` -> `C:\Tools\bluehound_dashboard_htb.txt` and `LOAD DASHBOARD`:

![[HTB Solutions/CAPE/z. images/d599059d660ac0ef95176ae501536873_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/6658c70e5de6b044b824104ad02f2ed8_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/5abd7ae2e709b06fba0eda3dba7825ff_MD5.jpg]]

Subsequently, students need to click `Data Import` --> `RUN ALL`:

![[HTB Solutions/CAPE/z. images/d040ff065322ddf6ddc3820ed3980e75_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/98a6c302ea062129c1e07c2d147045a5_MD5.jpg]]

Students need to wait a few moments to allow the import to finish. Once completed, students must go to the Configuration Tab and fill out the corresponding information:

`Domain Controllers`: `DOMAIN CONTROLLERS@INLANEFREIGHT.HTB` `Domain Admins Group`: `DOMAIN ADMINS@INLANEFREIGHT.HTB` `CROWN JEWELS`: `SRV01.INLANEFREIGHT.HTB`

![[HTB Solutions/CAPE/z. images/a4ba031273bf162f36099023326f8a28_MD5.jpg]]

Once complete, students need to click on `Query Runner` and `RUN ALL` (waiting a few moments for it to finish):

![[HTB Solutions/CAPE/z. images/6ba05eb08020c42a68d31aa5362c5504_MD5.jpg]]

Finally, students need to go to the `Dashboard` tab:

![[HTB Solutions/CAPE/z. images/3412c9f296bc435ca413cf80c16801c9_MD5.jpg]]

There, they will see the `Users with Paths to DA`, which is `30`%.

Answer: `30`

# BloodHound for BlueTeams

## Question 2

### "Using BlueHound custom dashboard. Which computer has more Administrators?"

After completing the data import and collection from the previous questions, students need to navigate to Dashboard and look at `Computers by # of User's Admins`:

![[HTB Solutions/CAPE/z. images/8742ee228d3ddea88b784983dff2c401_MD5.jpg]]

Students will find `WS01` has a higher `ADMIN_COUNT` than the domain controller.

Answer: `WS01`

# BloodHound for BlueTeams

## Question 3

### "Using BlueHound custom dashboard. Domain User's group has dangerous permission over 3 objects, a user, a computer and a gpo. What's the name of the GPO?"

From the current `BlueHound` session, students need to go to the `Dashboard` tab and see the `Dangerous permissions "Domain Users"`:

![[HTB Solutions/CAPE/z. images/b4349db7fd32f8ace66c98bfaac0bf86_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/69493aefa24b727dc152ea0e9bc7a3dd_MD5.jpg]]

There, students will see the user `Elieser`, the Computer SRV01 and the GPO `SCREENSAVER`.

Answer: `SCREENSAVER`

# BloodHound for BlueTeams

## Question 4

### "Which relationship (edge) do we need to remove to break the path between David and Domain Admins?"

From the previously established RDP session, students need to open Command Prompt as administrator and execute `Plumhound.py`:

Code: cmd

```cmd
cd C:\Tools\PlumHound
python PlumHound.py -p Password123 -ap "DAVID@INLANEFREIGHT.HTB" "DOMAIN ADMINS@INLANEFREIGHT.HTB"
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd C:\Tools\PlumHound

C:\Tools\PlumHound>python PlumHound.py -p Password123 -ap "DAVID@INLANEFREIGHT.HTB" "DOMAIN ADMINS@INLANEFREIGHT.HTB"

        PlumHound 1.5.2
        For more information: https://github.com/plumhound
        --------------------------------------
        Server: bolt://localhost:7687
        User: neo4j
        Password: *****
        Encryption: False
        Timeout: 300
        --------------------------------------
        Task: Analyzer Path
        Start Node: DAVID@INLANEFREIGHT.HTB
---------------------------------------------------------------------
Analyzing paths between DAVID@INLANEFREIGHT.HTB and DOMAIN ADMINS@INLANEFREIGHT.HTB
---------------------------------------------------------------------
Removing the relationship MemberOf between DAVID@INLANEFREIGHT.HTB and DOMAIN ADMINS@INLANEFREIGHT.HTB breaks the path!
INFO    Tasks Generation Completed
Tasks: []
Executing Tasks |██████████████████████████████████████████████████| Tasks 0 / 0  in 0.1s (0.00/s)

        Completed 0 of 0 tasks.
```

From the output, students will see that removing the relationship `MemberOf` between `David` and `Domain Admins` breaks the path.

Answer: `MemberOf`

# Skills Assessment

## Question 1

### "Which user, with the exception of the Administrator and Intern user, does not explicitly have the ForceChangePassword edge but can change the password of the Active Directory user Sarah?"

Students first need to download [SA.zip](https://academy.hackthebox.com/storage/modules/69/SA.zip):

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/69/SA.zip
```

```
┌─[us-academy-1]─[10.10.14.200]─[htb-ac413848@htb-qdtjrp0ojw]─[/tmp]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/69/SA.zip

--2023-03-07 14:43:58--  https://academy.hackthebox.com/storage/modules/69/SA.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.21.126, 104.18.20.126, 2606:4700::6812:157e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.21.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 98008 (96K) [application/zip]
Saving to: ‘SA.zip’

SA.zip              100%[===================>]  95.71K  --.-KB/s    in 0.004s  

2023-03-07 14:43:58 (24.4 MB/s) - ‘SA.zip’ saved [98008/98008]
```

Subsequently, students need to start `neoj4` and then launch `BloodHound`:

Code: shell

```shell
sudo neo4j start
bloodhound
```

```
┌─[eu-academy-1]─[10.10.15.19]─[htb-ac594497@htb-hdrahhexud]─[~]
└──╼ [★]$ sudo neo4j start

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
Started neo4j (pid:5801). It is available at http://localhost:7474
There may be a short delay until the server is ready.
┌─[eu-academy-1]─[10.10.15.19]─[htb-ac594497@htb-hdrahhexud]─[~]
└──╼ [★]$ bloodhound
```

Then, students need to upload `SA.zip` to begin the analysis:

![[HTB Solutions/CAPE/z. images/b412077335faaa087d4a6982631e9353_MD5.jpg]]

Once the data has been uploaded, students need to search for `SARAH` and select the green user (which is the Active Directory account), right clicking and selecting `Shortest Path Here`:

![[HTB Solutions/CAPE/z. images/be8e5c8bb5605f8fb828201c87044569_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/d1d804037da83f37dbc1983a86ad9592_MD5.jpg]]\`

From the graphic generated, students will find that `JORGE` member of `DOMAIN ADMINS` has `GenericAll`, which also allow `JORGE` to change `Sarah`'s password.

Answer: `JORGE`

# Skills Assessment

## Question 2

### "Which group, other than Domain Admins, has direct WriteOwner privileges over the GPO "VPN CONFIGURATION"?"

Using the previously uploaded `SA.zip`, students need to first enable `Query Debug Mode` under `Settings`:

![[HTB Solutions/CAPE/z. images/70501ce9190ac7286106a981204f9888_MD5.jpg]]

Now, students need to search for `VPN CONFIGURATION` `GPO`, right click and select `Shortest Path to Here`:

![[HTB Solutions/CAPE/z. images/4bb1ca2d054e8f2d5d2206a1fe09fff2_MD5.jpg]]

However, students need to modify the Raw Query, replacing `shortestPath` with `allshortestPaths`:

![[HTB Solutions/CAPE/z. images/4afb90550f6d9a380b487e567192938f_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/f1ea555bfc7e07ebc26567e27e4fb973_MD5.jpg]]

Alternatively, students can use another cypher query:

Code: cmd

```cmd
Cypher Query: MATCH p=((g:Group)-[r:WriteOwner]->(o:GPO {name: "VPN CONFIGURATION@INLANEFREIGHT.HTB"})) WHERE NOT g.name CONTAINS "DOMAIN ADMINS" RETURN p
```

This query returns the variable `p`, which meets the criteria of being a group possessing the `WriteOwner` edge in a one-way relationship to the GPO `VPN CONFIGURATION@INLANEFREIGHT.HTB`. The group `g` must also not be `Domain Admins`:

![[HTB Solutions/CAPE/z. images/d9bc01c0de17fc794f032c18838ecba0_MD5.jpg]]

From the graphic generated, students will see the group `ENTERPRISE ADMINS` has direct `WriteOwner` over `VPN CONFIGURATION` `GPO`.

Answer: `ENTERPRISE ADMINS`

# Skills Assessment

## Question 3

### "The intern Active Directory user has DCSync rights. What other first-degree rights does he have in another object that he can use to compromise the Active Directory? (Use the edge as the answer)"

Using the previously uploaded `SA.zip`, students need to utilize a cypher query to find the other edge representing a possible domain compromise:

```cmd
MATCH p = allshortestPaths((n)-[*1..]->(c))  WHERE n.name =~ '(?i)INTERN.*' AND NOT c=n  RETURN p
```

This query looks for the shortest paths between nodes `n` and `c`, where the name of the node matches a regular expression for names starting with `INTERN`. It returns the entire path `p` for every path found. And if nodes `n` and `c` are the same, it returns nothing:

![[HTB Solutions/CAPE/z. images/db33949433234e67de313cb6a1fe4596_MD5.jpg]]

From the graphic generated, students will know the other object `DC01` to which the `INTERN` user has `WriteOwner` and can be used to compromise the Domain.

Answer: `WriteOwner`

# Skills Assessment

## Question 4

### "Which Azure user, who has no Azure AD admin roles assigned, can execute commands on the DB002 machine?"

Using the previously uploaded `SA.zip`, students need search for `DB002`, right click and select `Shortest Path to Here`:

![[HTB Solutions/CAPE/z. images/a52c0c9d52db7abb1f2f9c14bed3bee5_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/a1e6add8d608d02c0be4cd8392285538_MD5.jpg]]

From the graphic generated, students will know that the user `ESTER` which has the edge `AZOwns` over `DB002`. Subsequently, students need to click the user `ESTER` and go to the `Node Info` tab:

![[HTB Solutions/CAPE/z. images/e97b2755622da4d421b45fddb6c2b9a5_MD5.jpg]]

Within `OVERVIEW`, students will know the `Azure AD Admin Roles` is `0`, which means `ESTER` is not member of any `Azure Role`.

Answer: `Ester`

# Skills Assessment

## Question 5

### "Which Azure user has a path to add himself as Global Administrator?"

Using the previously uploaded `SA.zip`, students need to search for `GLOBAL ADMINISTRATORS`, right clicking to select `Shortest Path to Here`:

![[HTB Solutions/CAPE/z. images/153089e209504d726cfdac88b1760e48_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/1edfbc22797522da358d07c80f6555e8_MD5.jpg]]

From the graphic generated, students will know that the user `JORGE` which has the edge `AZOwns` over `Azure_Manager` `Service Principal`.

Looking closely, students will find `Azure_Manager` has `AZPrivilegedRoleAdmin`. Consequently, they need to click the edge and see the `ABUSE` info tab:

![[HTB Solutions/CAPE/z. images/c78827787f9987d88a53d25cf6f8380d_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/cf900a82ce34855da8cd3aaa2558b905_MD5.jpg]]

This means that the user, `Jorge`, can add himself as `Global Administrator`.

Answer: `Jorge`

# Skills Assessment

## Question 6

### "Find the percentage of users with a path to GLOBAL ADMINISTRATOR. Submit the number as your answer (to two decimal points, i.e., 11.78)."

Students need to utilize a cypher query from within the `neo4j` console.

Navigating to http://localhost:7474/browser, students will need to enter their username and password:

![[HTB Solutions/CAPE/z. images/88386f7ea3dc6dbb5c20caf5336d97bb_MD5.jpg]]

Then, students need to use a cypher query to search for nodes labeled `AZUser` and `AZRole`, specifying that the results contain only nodes whose name starts with `GLOBAL ADMIN`, then performing a count of the number of `AZUser` nodes and finding the shortest paths, to return the percentage of `AZUser` nodes that have a path to `GLOBAL ADMIN`:

```cmd
MATCH (u:AZUser) MATCH (g:AZRole) WHERE g.name STARTS WITH 'GLOBAL ADMIN' WITH g, COUNT(u) as userCount MATCH p = shortestPath((u:AZUser)-[*1..]->(g)) RETURN 100.0 * COUNT(DISTINCT u) / userCount as percent
```

![[HTB Solutions/CAPE/z. images/03e3d216724243e1773344f206eefd0a_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/dc2ab420450a3d9020e8ea2ca38c414f_MD5.jpg]]

Alternatively, students can use a different cypher query, attaining the same value `30.76`:

```cmd
MATCH (totalUsers:AZUser) MATCH p=shortestPath((UsersWithPath:AZUser)-[r*1..]->(o:AZRole {name:'GLOBAL ADMINISTRATOR@DEFAULT DIRECTORY'})) WITH COUNT(DISTINCT(totalUsers)) as totalUsers, COUNT(DISTINCT(UsersWithPath)) as UsersWithPath RETURN 100.0 * UsersWithPath / totalUsers AS percentUsersToDA
```

Answer: `30.76`