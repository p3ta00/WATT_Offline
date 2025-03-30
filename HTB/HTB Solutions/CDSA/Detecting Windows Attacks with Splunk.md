| Section | Question Number | Answer |
| --- | --- | --- |
| Detecting Common User/Domain Recon | Question 1 | rundll32 |
| Detecting Password Spraying | Question 1 | sa |
| Detecting Responder-like Attacks | Question 1 | f1nancefileshare |
| Detecting Kerberoasting/AS-REProasting | Question 1 | CORP\\LANDON\_HINES |
| Detecting Pass-the-Hash | Question 1 | BLUE.corp.local |
| Detecting Pass-the-Ticket | Question 1 | YOUNG\_WILKINSON |
| Detecting Overpass-the-Hash | Question 1 | rundll32.exe |
| Detecting Golden Tickets/Silver Tickets | Question 1 | CIFS |
| Detecting Unconstrained Delegation/Constrained Delegation Attacks | Question 1 | DC01.corp.local |
| Detecting DCSync/DCShadow | Question 1 | GC |
| Detecting RDP Brute Force Attacks | Question 1 | 192.168.152.140 |
| Detecting Beaconing Malware | Question 1 | timechart |
| Detecting Nmap Port Scanning | Question 1 | Yes |
| Detecting Kerberos Brute Force Attacks | Question 1 | Yes |
| Detecting Kerberoasting | Question 1 | 88 |
| Detecting Golden Tickets | Question 1 | 88 |
| Detecting Cobalt Strike's PSExec | Question 1 | 192.168.38.104 |
| Detecting Zerologon | Question 1 | False |
| Detecting Exfiltration (HTTP) | Question 1 | 192.168.151.181 |
| Detecting Exfiltration (DNS) | Question 1 | letsgohunt.online |
| Detecting Ransomware | Question 1 | 4588 |
| Skills Assessment | Question 1 | 4.680851063829787 |
| Skills Assessment | Question 2 | 192.168.1.149 |
| Skills Assessment | Question 3 | 192.168.109.105 |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Detecting Common User/Domain Recon

## Question 1

### "Modify and employ the Splunk search provided at the end of this section on all ingested data (All time) to find all process names that made LDAP queries where the filter includes the string \*(samAccountType=805306368)\*. Enter the missing process name from the following list as your answer. N/A, Rubeus, SharpHound, mmc, powershell, \_"

Students need to use Firefox, browsing to http://STMIP:8000 where they can access the Search & Reporting Splunk application:

![[HTB Solutions/CDSA/z. images/3e53dcf76a7bc54b332deeaf424dc9dd_MD5.webp]]

Next, students need to set the time range picker to `all time`, then enter a modified version of the SPL query shown at the bottom of the section:

```
index=main source="WinEventLog:SilkService-Log"
| spath input=Message 
| rename XmlEventData.* as * 
| table _time, ComputerName, ProcessName, ProcessId, DistinguishedName, SearchFilter
| sort 0 _time
| search SearchFilter="*(samAccountType=805306368)*"
| stats count by ProcessName
```

The new SPL query omits the time filter and simplifies the output to only show a count of events grouped by `ProcessName`:

![[HTB Solutions/CDSA/z. images/33d94c2ce044e242494d65832d42959b_MD5.webp]]

Students will find the missing process name is `rundll32`.

Answer: `rundll32`

# Detecting Password Spraying

## Question 1

### "Employ the Splunk search provided at the end of this section on all ingested data (All time) and enter the targeted user on SQLSERVER.corp.local as your answer."

Students need to use Firefox, browsing to http://STMIP:8000 where they can access the Search & Reporting Splunk application:

![[HTB Solutions/CDSA/z. images/3e53dcf76a7bc54b332deeaf424dc9dd_MD5.webp]]

Next, students need set the time range picker to `all time`, then use a modified version of the SPL query shown at the bottom of the section:

```
index=main  source="WinEventLog:Security" EventCode=4625
| bin span=15m _time
| stats values(user) as Users, dc(user) as dc_user by src, Source_Network_Address, dest, EventCode, Failure_Reason
```

The modified query removes the time range filters, allowing for all events within the data set to be analyzed:

![[HTB Solutions/CDSA/z. images/5c385dbec2a1261098f446d4391eaddc_MD5.webp]]

Here, students will find the targeted user is `sa`.

Answer: `sa`

# Detecting Responder-like Attacks

## Question 1

### "Modify and employ the provided Sysmon Event 22-based Splunk search on all ingested data (All time) to identify all share names whose location was spoofed by 10.10.0.221. Enter the missing share name from the following list as your answer. myshare, myfileshar3, \_"

Students need to use Firefox, browsing to http://STMIP:8000 where they can access the Search & Reporting Splunk application:

![[HTB Solutions/CDSA/z. images/3e53dcf76a7bc54b332deeaf424dc9dd_MD5.webp]]

Then, students need to set the time range picker to `all time` and employ a modified version of the provided Sysmon Event 22-based Splunk query shown in the section:

```
index=main EventCode=22 10.10.0.221
| table _time, Computer, user, Image, QueryName, QueryResult
```

The updated query filters only by "EventCode=22" and includes the IP address of `10.10.0.221`:

![[HTB Solutions/CDSA/z. images/dd094c87a9fbd0f6c0a1b74ec25775d5_MD5.webp]]

The missing share is shown to be `f1nancefileshare`.

Answer: `f1nancefileshare`

# Detecting Kerberoasting/AS-REProasting

## Question 1

### "Modify and employ the Splunk search provided at the "Detecting Kerberoasting - SPN Querying" part of this section on all ingested data (All time). Enter the name of the user who initiated the process that executed an LDAP query containing the "\*(&(samAccountType=805306368)(servicePrincipalName=\*)\*" string at 2023-07-26 16:42:44 as your answer. Answer format: CORP\\\_"

Students need to use Firefox, browsing to http://STMIP:8000 where they can access the Search & Reporting Splunk application:

![[HTB Solutions/CDSA/z. images/3e53dcf76a7bc54b332deeaf424dc9dd_MD5.webp]]

Next, students need set the time range picker to `all time`, then use a modified version of the SPL query seen in the `Detecting Kerberoasting - SPN Querying` section:

```
index=main source="WinEventLog:SilkService-Log" 
| spath input=Message 
| rename XmlEventData.* as * 
| table _time, ComputerName, ProcessName, DistinguishedName, SearchFilter, PID
| search SearchFilter="*(&(samAccountType=805306368)(servicePrincipalName=*)*"
```

The new query omits the time filter and adds an additional field, `PID`, to the table. Both queries are otherwise similar in extracting information and searching based on the LDAP filter in `SearchFilter`.

![[HTB Solutions/CDSA/z. images/ca48c280ed78f56fb381942bfb0fa60b_MD5.jpg]]

Identifying the PID associated with the attack, students need to utilize another SPL query, searching the main index for events containing `7136` with an EventCode of 1 (indicating process creation) while displaying a table with the `user` field:

![[HTB Solutions/CDSA/z. images/b98895d5beddec5f8e36e7457436e487_MD5.jpg]]

Students will find the `CORP\LANDON_HINES` user is responsible for initiating the process.

Answer: `CORP\LANDON_HINES`

# Detecting Pass-the-Hash

Students need to use Firefox, browsing to http://STMIP:8000 where they can access the Search & Reporting Splunk application:

![[HTB Solutions/CDSA/z. images/3e53dcf76a7bc54b332deeaf424dc9dd_MD5.webp]]

Next, students need set the time range picker to `all time`, then enter a modified version of the SPL query shown under the `Detecting Pass-the-Hash With Slunk` sub-section:

```
index=main earliest=1690543380 latest=1690545180 source="WinEventLog:Security" EventCode=4624 Logon_Type=9 Logon_Process=seclogo
| table _time, ComputerName, EventCode, user, Network_Account_Domain, Network_Account_Name, Logon_Type, Logon_Process
```

The new query uses the custom time frame `earliest=1690543380` and `latest=1690545180`.

![[HTB Solutions/CDSA/z. images/0e4d6be94ad7789594481b65dd50fe79_MD5.jpg]]

The computer name involved with this particular event is shown to be `BLUE.corp.local`.

Answer: `Blue.corp.local`

# Detecting Pass-the-Ticket

## Question 1

### "Execute the Splunk search provided at the end of this section to find all usernames that may be have executed a Pass-the-Ticket attack. Enter the missing username from the following list as your answer. Administrator, \_"

Students need to use Firefox, browsing to http://STMIP:8000 where they can access the Search & Reporting Splunk application:

![[HTB Solutions/CDSA/z. images/3e53dcf76a7bc54b332deeaf424dc9dd_MD5.webp]]

Next, students need set the time range picker to `all time`, and enter in the provided SPL query shown within the `Detecting Pass-the-Ticket With Splunk` section:

```
index=main earliest=1690392405 latest=1690451745 source="WinEventLog:Security" user!=*$ EventCode IN (4768,4769,4770) 
| rex field=user "(?<username>[^@]+)"
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip_4>[0-9\.]+)"
| transaction username, src_ip_4 maxspan=10h keepevicted=true startswith=(EventCode=4768)
| where closed_txn=0
| search NOT user="*$@*"
| table _time, ComputerName, username, src_ip_4, service_name, category
```

![[HTB Solutions/CDSA/z. images/c981aa7c57e0cd22135e9be2ade37d74_MD5.jpg]]

Students will find the `YOUNG_WILKINSON` username, which identifies them as the other user who may have executed a Pass-the-Ticket attack.

Answer: `YOUNG_WILKINSON`

# Detecting Overpass-the-Hash

## Question 1

### "Employ the Splunk search provided at the end of this section on all ingested data (All time) to find all involved images (Image field). Enter the missing image name from the following list as your answer. Rubeus.exe, \_.exe"

Students need to use Firefox, browsing to http://STMIP:8000 where they can access the Search & Reporting Splunk application. Then, they need to set the time range picker to `all time`, and examine the results of the SPL query shown at the end of the section (removing the specified time ranges from the original query):

```
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=3 dest_port=88 Image!=*lsass.exe) OR EventCode=1
| eventstats values(process) as process by process_id
| where EventCode=3
| stats count by _time, Computer, dest_ip, dest_port, Image, process
| fields - count
```

![[HTB Solutions/CDSA/z. images/45c9140295f5942f77f79632fc1b5f3e_MD5.jpg]]

Students will observe `rundll32.exe` as the missing image name.

Answer: `rundll32.exe`

# Detecting Golden Tickets/Silver Tickets

## Question 1

### "For which "service" did the user named Barbi generate a silver ticket?"

First, students need to download the `users.csv` file (found in the module Resources) to their attack host:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/resources/Splunk_Resources.zip && unzip Splunk_Resources.zip
```

```
┌─[us-academy-1]─[10.10.14.233]─[htb-ac-594497@htb-i0yzsotw3w]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/resources/Splunk_Resources.zip && unzip Splunk_Resources.zip

--2023-08-21 18:54:51--  https://academy.hackthebox.com/storage/resources/Splunk_Resources.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 45641 (45K) [application/zip]
Saving to: ‘Splunk_Resources.zip’

Splunk_Resources.zi 100%[===================>]  44.57K  --.-KB/s    in 0s      

2023-08-21 18:54:51 (167 MB/s) - ‘Splunk_Resources.zip’ saved [45641/45641]

Archive:  Splunk_Resources.zip
 extracting: Detection-of-Active-Directory-Attacks.tar.gz.tar  
  inflating: users.csv           
```

Next, students need to browse to http://STMIP:8000 , and subsequently upload the `users.csv` file into Splunk by clicking `Settings` -> `Lookups` -> `Lookup table files` -> `New Lookup Table File`:

![[HTB Solutions/CDSA/z. images/bdbbeb20c6dc183493a1afda99f0b56d_MD5.jpg]]

After pressing save, students need to return to the `Search & Reporting` app and use the query shown in the section, comparing the aforementioned list of users with users who are currently logged in:

```
index=main latest=1690545656 EventCode=4624
| stats min(_time) as firstTime, values(ComputerName) as ComputerName, values(EventCode) as EventCode by user
| eval last24h = 1690451977
| where firstTime > last24h
\`\`\`| eval last24h=relative_time(now(),"-24h@h")\`\`\`
| convert ctime(firstTime)
| convert ctime(last24h)
| lookup users.csv user as user OUTPUT EventCode as Events
| where isnull(Events)
```

![[HTB Solutions/CDSA/z. images/a38fa799c2be5944be09167bfbd70529_MD5.jpg]]

Students will find evidence that the user, `Barbi`, had a successful login on the `SQLSERVER.corp.local` machine. Additionally, students will note that the `Barbi` user did not appear in the `users.csv` list, warranting further investigation. Therefore, student's need to search all ingested data for events relating to that particular user and workstation:

```
index=main "Barbi" "SQLSERVER" 
| stats count by EventCode
```

![[HTB Solutions/CDSA/z. images/90fb042a9d770684aaccc8c2f49e60bd_MD5.jpg]]

Of particular interest is event code `4648` , which corresponds to a logon attempt using explicit credentials. Therefore, students need to click the event and select and `View Events`:

![[HTB Solutions/CDSA/z. images/8805d595f6799229284ad3f756df7b40_MD5.jpg]]

The event shows that the `cifs` service was requested.

Answer: `cifs`

# Detecting Unconstrained Delegation/Constrained Delegation Attacks

## Question 1

### "Employ the Splunk search provided at the "Detecting Unconstrained Delegation Attacks With Splunk" part of this section on all ingested data (All time). Enter the name of the other computer on which there are traces of reconnaissance related to Unconstrained Delegation as your answer. Answer format: \_.corp.local"

Students need to use Firefox, browsing to http://STMIP:8000 where they can access the Search & Reporting Splunk application:

![[HTB Solutions/CDSA/z. images/3e53dcf76a7bc54b332deeaf424dc9dd_MD5.webp]]

Next, students need set the time range picker to `all time`, then employ the search query shown in the `Detecting Unconstrained Delegation Attacks With Splunk` section. Additionally, the query should be adjusted to remove the `earliest=` and `latest=` search modifiers:

```
index=main source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 Message="*TrustedForDelegation*" OR Message="*userAccountControl:1.2.840.113556.1.4.803:=524288*" 
| table _time, ComputerName, EventCode, Message
```

![[HTB Solutions/CDSA/z. images/296353ccb851b42b31ee616f1e80ac0a_MD5.jpg]]

Students will that the `DC01.corp.local` computer has traces of reconnaissance related to Unconstrained Delegation.

Answer: `DC01.corp.local`

# Detecting DCSync/DCShadow

## Question 1

### "Modify the last Splunk search in this section by replacing the two hidden characters (XX) to align the results with those shown in the screenshot. Enter the correct characters as your answer."

Students need to use Firefox, browsing to http://STMIP:8000 where they can access the Search & Reporting Splunk application:

![[HTB Solutions/CDSA/z. images/3e53dcf76a7bc54b332deeaf424dc9dd_MD5.webp]]

Next, students need set the time range picker to `all time`, then enter a modified version of last search query shown within the section's reading:

```
index=main earliest=1690623888 latest=1690623890 EventCode=4742 
| rex field=Message "(?P<gcspn>GC\/[a-zA-Z0-9\.\-\/]+)" 
| table _time, ComputerName, Security_ID, Account_Name, user, gcspn 
| search gcspn=*
```

Students will note that the `XX` has been replaced with `GC`, to coincide with the `global catalog ServicePrincipalName`:

![[HTB Solutions/CDSA/z. images/e4ce3cf3d3e1033f8149f33a9a22db7d_MD5.jpg]]

Answer: `GC`

# Detecting RDP Brute Force Attacks

## Question 1

### "Construct a Splunk query targeting the "ssh\_bruteforce" index and the "bro:ssh:json" sourcetype. The resulting output should display the time bucket, source IP, destination IP, client, and server, together with the cumulative count of authentication attempts where the total number of attempts surpasses 30 within a 5-minute time window. Enter the IP of the client that performed the SSH brute attack as your answer."

Students need to browse to the Splunk Web interface at https://STMIP:8000/ , then navigate to the `Search & Reporting` app:

![[HTB Solutions/CDSA/z. images/461d36b1289a029ff889c38e162bf35e_MD5.jpg]]

Next, students need to set the time range picker to `all time`:

![[HTB Solutions/CDSA/z. images/18724901251acb3828d47457625a1bf4_MD5.jpg]]

Now, students need to construct a query to find the account that surpassed thirty SSH attempts within a five-minute time window:

```
index="ssh_bruteforce" sourcetype="bro:ssh:json"
auth_success="false"
| bin _time span=5m
| stats sum(auth_attempts) as num_attempts by _time, id.orig_h, id.resp_h, client, server
| where num_attempts>30
```

![[HTB Solutions/CDSA/z. images/9349301a8c36389c63881e2bd8340453_MD5.jpg]]

Students will identify `192.168.152.140` as the IP address of the client that performed the attack.

Answer: `192.168.152.140`

# Detecting Beaconing Malware

## Question 1

### Use the "cobaltstrike\_beacon" index and the "bro:http:json" sourcetype. What is the most straightforward Splunk command to pinpoint beaconing from the 10.0.10.20 source to the 192.168.151.181 destination? Answer format: One word

Students need to browse to the Splunk Web interface at https://STMIP:8000/ , then navigate to the `Search & Reporting` app:

![[HTB Solutions/CDSA/z. images/461d36b1289a029ff889c38e162bf35e_MD5.jpg]]

Next, students need to set the time range picker to `all time`:

![[HTB Solutions/CDSA/z. images/18724901251acb3828d47457625a1bf4_MD5.jpg]]

Now, students need use a search query specifying `10.0.10.20` as the source IP, and `192.168.151.181` as the destination IP:

```
index="cobaltstrike_beacon" sourcetype="bro:http:json" src=10.0.10.20 dest=192.168.151.181
```

![[HTB Solutions/CDSA/z. images/0f63933206b81801e45a83ec868572d5_MD5.jpg]]

Subsequently, to pinpoint the beaconing, students need to use the `timechart` command to create a time-based chart that counts the number of matching events:

```
index="cobaltstrike_beacon" sourcetype="bro:http:json" src=10.0.10.20 dest=192.168.151.181
| timechart count
```

![[HTB Solutions/CDSA/z. images/e019fc1c000358054e9326feb1da0b04_MD5.jpg]]

Therefore, students can conclude that the most straight forward command is `timechart`.

Answer: `timechart`

# Detecting Nmap Port Scanning

## Question 1

### "Use the "cobaltstrike\_beacon" index and the "bro:conn:json" sourcetype. Did the attacker scan port 505? Answer format: Yes, No"

Students need to first browse to the Splunk Web interface at https://STMIP:8000/ , then navigate to the `Search & Reporting` app:

![[HTB Solutions/CDSA/z. images/461d36b1289a029ff889c38e162bf35e_MD5.jpg]]

Next, students need to set the time range picker to `all time`:

![[HTB Solutions/CDSA/z. images/18724901251acb3828d47457625a1bf4_MD5.jpg]]

Now, students need to enter a modified version of the query shown at the end of the section:

```
index="cobaltstrike_beacon" sourcetype="bro:conn:json" dest_ip IN (192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8) 
| bin span=5m _time
| stats dc(dest_port) as num_dest_port, values(dest_port) as dest_port by _time, src_ip, dest_ip
| where num_dest_port >= 3
```

The query has been adjusted to show more detail in the aggregated results, due to capturing the actual `dest_port` values:

![[HTB Solutions/CDSA/z. images/432aa00281ab3a2031655635a05a34d8_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/6037e118afd5cfd86d9aecd48656cc3e_MD5.jpg]]

After examining the output, students will see that port `505` was indeed scanned by the attacker.

Answer: `Yes`

# Detecting Kerberos Brute Force Attacks

## Question 1

### "Use the "kerberos\_bruteforce" index and the "bro:kerberos:json" sourcetype. Was the "accrescent/windomain.local" account part of the Kerberos user enumeration attack? Answer format: Yes, No"

Students need to first browse to the Splunk Web interface at https://STMIP:8000/ , then navigate to the `Search & Reporting` app:

![[HTB Solutions/CDSA/z. images/461d36b1289a029ff889c38e162bf35e_MD5.jpg]]

Next, students need to set the time range picker to `all time`:

![[HTB Solutions/CDSA/z. images/18724901251acb3828d47457625a1bf4_MD5.jpg]]

Now, students need to use a query to search within the `kerberos_bruteforce` index for events of type `bro:kerberos:json`, filtering those events down to ones where the client is "accrescent/windomain.local" and the Kerberos request type is "AS" (Authentication Service):

```
index="kerberos_bruteforce" sourcetype="bro:kerberos:json" client="accrescent/windomain.local" request_type=AS
```

![[HTB Solutions/CDSA/z. images/373cdfebedf36ee5638ca55045c731af_MD5.jpg]]

The query returns an event indicating a failed Kerberos Authentication Service request tied to the user in question. Therefore, the answer is `Yes`, the "accrescent/windomain.local" was part of the attack.

Answer: `Yes`

# Detecting Kerberoasting

## Question 1

### "What port does the attacker use for communication during the Kerberoasting attack?"

Students need to first browse to the Splunk Web interface at https://STMIP:8000/ , then navigate to the `Search & Reporting` app:

![[HTB Solutions/CDSA/z. images/461d36b1289a029ff889c38e162bf35e_MD5.jpg]]

Next, students need to set the time range picker to `all time`:

![[HTB Solutions/CDSA/z. images/18724901251acb3828d47457625a1bf4_MD5.jpg]]

Now, students need to enter a modified version of the search query shown in the section:

```
index="sharphound" sourcetype="bro:kerberos:json" request_type=TGS cipher="rc4-hmac" forwardable="true" renewable="true" 
| table _time, id.orig_h, id.resp_h, request_type, cipher, forwardable, renewable, client, service, id.orig_p , id.resp_p
```

The new query includes the addition of the `id.orig_p` and `id_resp_p` fields to the table, allowing students to see the port numbers associated with the event, they will scrutinize the results in the `id.resp_p` column:

![[HTB Solutions/CDSA/z. images/454588487a39bbcf09439aa4d2abf9e8_MD5.jpg]]

Students will find that port `88` (the default port for Kerberos) was used during the attack.

Answer: `88`

# Detecting Golden Tickets

## Question 1

### "What port does the attacker use for communication during the Golden Ticket attack?"

Students need to first browse to the Splunk Web interface at https://STMIP:8000/ , then navigate to the `Search & Reporting` app:

![[HTB Solutions/CDSA/z. images/461d36b1289a029ff889c38e162bf35e_MD5.jpg]]

Next, students need to set the time range picker to `all time`:

![[HTB Solutions/CDSA/z. images/18724901251acb3828d47457625a1bf4_MD5.jpg]]

Now, students need to enter a modified version of the search query shown in the section:

```
index="golden_ticket_attack" sourcetype="bro:kerberos:json"
| where client!="-"
| bin _time span=1m 
| stats values(client), values(request_type) as request_types, dc(request_type) as unique_request_types by _time, id.orig_h, id.resp_h, id.orig_p, id.resp_p
| where request_types=="TGS" AND unique_request_types==1
```

Similar to the previous exercise, this new query includes the addition of the `id.orig_p` and `id_resp_p` fields to the table, allowing students to see the port numbers associated with the event:

![[HTB Solutions/CDSA/z. images/33b9e77f4f0d58f7a03a5395d8d86f68_MD5.jpg]]

Students will find port `88` was used for communication during the Golden Ticket attack.

Answer: `88`

# Detecting Cobalt Strike's PSExec

## Question 1

### "Use the "change\_service\_config" index and the "bro:dce\_rpc:json" sourcetype to create a Splunk search that will detect SharpNoPSExec (https://gist.github.com/defensivedepth/ae3f882efa47e20990bc562a8b052984). Enter the IP included in the "id.orig\_h" field as your answer."

Students need to first browse to the Splunk Web interface at https://STMIP:8000/ , then navigate to the `Search & Reporting` app:

![[HTB Solutions/CDSA/z. images/461d36b1289a029ff889c38e162bf35e_MD5.jpg]]

Next, students need to set the time range picker to `all time`:

![[HTB Solutions/CDSA/z. images/18724901251acb3828d47457625a1bf4_MD5.jpg]]

Now, students need to enter a query that searches for logs in the "change\_service\_config" index, where the `endpoint` field is "svcctl" and the `operation` is one of "CreateServiceW", "CreateServiceA", "StartServiceW", "StartServiceA", or "ChangeServiceConfigW" (as shown in the screenshot of the network traffic in the section). Additionally, this information should be presented in a table with columns for the timestamp (`_time`), originating host (`id.orig_h`), responding host (`id.resp_h`), endpoint, and operation.

```
index="change_service_config" endpoint=svcctl sourcetype="bro:dce_rpc:json"
operation IN ("CreateServiceW", "CreateServiceA", "StartServiceW", "StartServiceA", "ChangeServiceConfigW")
| table _time, id.orig_h, id.resp_h, endpoint, operation
```

![[HTB Solutions/CDSA/z. images/1ce2bb586255ac3e7d939590d8aebdf6_MD5.jpg]]

Students will discover the IP included in the `id.orig_h` field is `192.168.38.104`.

Answer: `192.168.38.104`

# Detecting Zerologon

## Question 1

### "In a Zerologon attack, the primary port of communication for the attacker is port 88. Answer format: True, False."

Students need to first browse to the Splunk Web interface at https://STMIP:8000/ , then navigate to the `Search & Reporting` app:

![[HTB Solutions/CDSA/z. images/461d36b1289a029ff889c38e162bf35e_MD5.jpg]]

Next, students need to set the time range picker to `all time`:

![[HTB Solutions/CDSA/z. images/18724901251acb3828d47457625a1bf4_MD5.jpg]]

Now, students need to enter the SPL query shown in the section, albeit with a minor adjustment:

```
index="zerologon" endpoint="netlogon" sourcetype="bro:dce_rpc:json"
| bin _time span=1m
| where operation == "NetrServerReqChallenge" OR operation == "NetrServerAuthenticate3" OR operation == "NetrServerPasswordSet2"
| stats count values(operation) as operation_values dc(operation) as unique_operations values(id.resp_p) as destination_port by _time, id.orig_h, id.resp_h
| where unique_operations >= 2 AND count>100
```

The modified query includes the capture of the responding port numbers (`id.resp_p`) for each group and lists them as "destination\_port":

![[HTB Solutions/CDSA/z. images/14d49d3974794e06779ed063d71466d0_MD5.jpg]]

Students will find the primary port of communication is `49668` and not `88`; therefore, the answer is `False`.

Answer: `False`

# Detecting Exfiltration (HTTP)

## Question 1

### "Use the "cobaltstrike\_exfiltration\_https" index and the "bro:conn:json" sourcetype. Create a Splunk search to identify exfiltration through HTTPS. Enter the identified destination IP as your answer."

Students need to first browse to the Splunk Web interface at https://STMIP:8000/ , then navigate to the `Search & Reporting` app:

![[HTB Solutions/CDSA/z. images/461d36b1289a029ff889c38e162bf35e_MD5.jpg]]

Next, students need to set the time range picker to `all time`:

![[HTB Solutions/CDSA/z. images/18724901251acb3828d47457625a1bf4_MD5.jpg]]

Now, students need to enter a modified version of the SPL query shown in the section:

```
index="cobaltstrike_exfiltration_https" sourcetype="bro:conn:json" dest_port=443
| stats sum(orig_bytes) as TotalBytes by src, dest, dest_port
| eval TotalBytes = TotalBytes/1024/1024
```

Because students need to identify data exfiltration through HTTPS, the query has been adjusted to filter for events where `dest_port=443` (the default port used for the HTTPS service):

![[HTB Solutions/CDSA/z. images/898c6489c0f3e9c2d18c20f360a66ec0_MD5.jpg]]

The destination IP of `192.168.151.181` will be revealed.

Answer: `192.168.151.181`

# Detecting Exfiltration (DNS)

## Question 1

### "Use the "dns\_exf" index and the "bro:dns:json" sourcetype. Enter the attacker-controlled domain as your answer. Answer format: \_.\_"

Students need to first browse to the Splunk Web interface at https://STMIP:8000/ , then navigate to the `Search & Reporting` app:

![[HTB Solutions/CDSA/z. images/461d36b1289a029ff889c38e162bf35e_MD5.jpg]]

Next, students need to set the time range picker to `all time`:

![[HTB Solutions/CDSA/z. images/18724901251acb3828d47457625a1bf4_MD5.jpg]]

Now, students need to enter the SPL query shown in the section, albeit with the slight modification of adding the `values(query) as domains` to the `stats` line. This allows the query to collect the actual domain names queried.

```
index=dns_exf sourcetype="bro:dns:json"
| eval len_query=len(query)
| search len_query>=40 AND query!="*.ip6.arpa*" AND query!="*amazonaws.com*" AND query!="*._googlecast.*" AND query!="_ldap.*"
| bin _time span=24h
| stats count(query) as req_by_day, values(query) as domains by _time, id.orig_h, id.resp_h
| where req_by_day>60
```

![[HTB Solutions/CDSA/z. images/afa301edb6a401b09f086ada98cb701e_MD5.jpg]]

The query reveals that the attacker controls the `letsgohunt.online` domain.

Answer: `letsgohunt.online`

# Detecting Ransomware

## Question 1

### "Modify the action-related part of the Splunk search of this section that detects excessive file overwrites so that it detects ransomware that delete the original files instead of overwriting them. Run this search against the "ransomware\_excessive\_delete\_aleta" index and the "bro:smb\_files:json" sourcetype. Enter the value of the "count" field as your answer."

Students need to first browse to the Splunk Web interface at https://STMIP:8000/ , then navigate to the `Search & Reporting` app:

![[HTB Solutions/CDSA/z. images/461d36b1289a029ff889c38e162bf35e_MD5.jpg]]

Next, students need to set the time range picker to `all time`:

![[HTB Solutions/CDSA/z. images/18724901251acb3828d47457625a1bf4_MD5.jpg]]

Now, students need to use a slightly modified version of the SPL query shown in the `Detecting Ransomware With Splunk & Zeek Logs (Excessive Overwriting)` section:

```
index="ransomware_excessive_delete_aleta" sourcetype="bro:smb_files:json" 
| where action IN ("SMB::FILE_OPEN", "SMB::FILE_DELETE")
| bin _time span=5m
| stats count by _time, source, action
| where count>30 
| stats sum(count) as count values(action) dc(action) as uniq_actions by _time, source
| where uniq_actions==2 AND count>100
```

The adjusted query, besides searching a different index, filters for events where the `action` is either "SMB::FILE\_OPEN" or "SMB::FILE\_DELETE", rather than "SMB::FILE\_RENAME".

![[HTB Solutions/CDSA/z. images/90215d891cf2bfcb68ec4c925a5076c7_MD5.jpg]]

Students will find the count of events is `4588`.

Answer: `4588`

# Skills Assessment

## Question 1

### "Use the "empire" index and the "bro:http:json" sourcetype. Identify beaconing activity by modifying the Splunk search of the "Detecting Beaconing Malware" section and enter the value of the "TimeInterval" field as your answer."

Students need to first browse to the Splunk Web interface at https://STMIP:8000/ , then navigate to the `Search & Reporting` app:

![[HTB Solutions/CDSA/z. images/461d36b1289a029ff889c38e162bf35e_MD5.jpg]]

Next, students need to set the time range picker to `all time`:

![[HTB Solutions/CDSA/z. images/18724901251acb3828d47457625a1bf4_MD5.jpg]]

Now, students need to use a slightly modified version of the SPL query shown in the `Detecting Beaconing Malware` section:

```
index="empire" sourcetype="bro:http:json" 
| sort 0 _time
| streamstats current=f last(_time) as prevtime by src, dest, dest_port
| eval timedelta = _time - prevtime
| eventstats avg(timedelta) as avg, count as total by src, dest, dest_port
| eval upper=avg*1.1
| eval lower=avg*0.9
| where timedelta > lower AND timedelta < upper
| stats count, values(avg) as TimeInterval by src, dest, dest_port, total
| eval prcnt = (count/total)*100
| where prcnt > 85 AND total > 10
```

While similar to the original provided in the aforementioned section, students need to adjust the threshold for the percentage of events that must fall within the acceptable time interval range, becoming more lenient and reducing it from `90` to `85`.

![[HTB Solutions/CDSA/z. images/98f552b8c41d0b353449a18b997c5c3d_MD5.jpg]]

The `TimeInterval` field returns with a value of `4.680851063829787`.

Answer: `4.680851063829787`

# Skills Assessment

## Question 2

### "Use the "empire" index and the "bro:http:json" sourcetype. Identify beaconing activity by modifying the Splunk search of the "Detecting Beaconing Malware" section and enter the value of the "TimeInterval" field as your answer."

From the Splunk Search & Reporting app, students need to first enter a basic SPL query to get an overview of the various fields present within the events of the `empire` index:

```
index="printnightmare" sourcetype="bro:dce_rpc:json"
```

![[HTB Solutions/CDSA/z. images/15b274f8b53948f6c2116bfe7385ce0b_MD5.jpg]]

After identifying the available fields, students can now supply a more detailed search query to detect possible exploitation of PrintNightmare:

```
index="printnightmare" endpoint=spoolss operation=RpcAddPrinterDriverEx
| table _time, id.orig_h, id.resp_h, endpoint, operation
```

![[HTB Solutions/CDSA/z. images/532a811d5e5755e90feccd96ca82af8a_MD5.jpg]]

Using the `table` command, students will be able to visualize the fields and determine the origin IP address is `192.168.1.149`.

Answer: `192.168.1.149`

# Skills Assessment

## Question 3

### "Use the "bloodhound\_all\_no\_kerberos\_sign" index and the "bro:dce\_rpc:json" sourcetype to create a Splunk search that will detect possible BloodHound activity (https://www.lares.com/blog/active-directory-ad-attacks-enumeration-at-the-network-layer/). Enter the IP included in the "id.orig\_h" field as your answer."

From the Splunk Search & Reporting app, students need to begin with an SPL query to obtain an overview of the different values present in the `operation` field:

```
index="bloodhound_all_no_kerberos_sign" sourcetype="bro:dce_rpc:json"
| stats values(operation) as Operations
```

![[HTB Solutions/CDSA/z. images/b6d05d11a3b68c2acbb30cd3b829c4f2_MD5.jpg]]

Next, students need to compare these values with the data shown in the `Sharphound` section of the [link](https://www.lares.com/blog/active-directory-ad-attacks-enumeration-at-the-network-layer/) mentioned in the challenge question:

![[HTB Solutions/CDSA/z. images/4df42a832cadb75ba33970929aa4d332_MD5.jpg]]

Therefore, using this information, students need to construct an SPL query that filters for these particular RPC calls, while displaying the event data in a table for better analysis:

```
index="bloodhound_all_no_kerberos_sign" sourcetype="bro:dce_rpc:json"
operation IN ("NetrSessionEnum", "NetrWkstaUserEnum", "SamrGetMembersInAlias", "SamrOpenDomain", "SamrConnect5", "SamrCloseHandle")
| table _time, id.orig_h, id.resp_h, endpoint, operation
```

![[HTB Solutions/CDSA/z. images/892a5adaf2cc9fcef723927435a31fd4_MD5.jpg]]

The value of the `id.orig_h` will quickly be observed as `192.168.109.105`.

Answer: `192.168.109.105`