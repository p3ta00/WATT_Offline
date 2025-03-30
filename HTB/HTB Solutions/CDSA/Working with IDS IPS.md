| Section | Question Number | Answer |
| --- | --- | --- |
| Suricata Fundamentals | Question 1 | 1252204100696793 |
| Suricata Fundamentals | Question 2 | app.php |
| Suricata Rule Development Part 1 | Question 1 | 4 |
| Suricata Rule Development Part 2 (Encrypted Traffic) | Question 1 | 72a589da586844d7f0818ce684948eea |
| Snort Fundamentals | Question 1 | 234 |
| Snort Rule Development | Question 1 | http\_header; |
| Intrusion Detection With Zeek | Question 1 | dce\_rpc.log |
| Intrusion Detection With Zeek | Question 2 | 2311 |
| Skills Assessment - Suricata | Question 1 | Create |
| Skills Assessment - Snort | Question 1 | 17 |
| Skills Assessment - Zeek | Question 1 | certificate.subject |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Suricata Fundamentals

## Question 1

### "Filter out only HTTP events from /var/log/suricata/old\_eve.json using the jq command-line JSON processor. Enter the flow\_id that you will come across as your answer."

Students need to log in using the provided credentials `htb-student:HTB_@cademy_stdnt!` via SSH:

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[us-academy-3]─[10.10.14.139]─[htb-ac-8414@htb-psbllub6rp]─[~]
└──╼ [★]$ ssh htb-student@10.129.205.193
The authenticity of host '10.129.205.193 (10.129.205.193)' can't be established.
ECDSA key fingerprint is SHA256:3I77Le3AqCEUd+1LBAraYTRTF74wwJZJiYcnwfF5yAs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes

<SNIP>

Last login: Tue Jul 18 06:24:37 2023 from 10.10.14.23
$ 
```

Subsequently, once they have successfully logged in, students must print out the contents of `/var/log/suricata/old_eve.json` while specifying the `.event_type` HTTP property and the key `flow_id` using the `jq` JSON processor and its compact output `-c`:

Code: shell

```shell
cat /var/log/suricata/old_eve.json | jq -c 'select(.event_type == "http").flow_id'
```

```
$ cat /var/log/suricata/old_eve.json | jq -c 'select(.event_type == "http").flow_id'

1252204100696793
1252204100696793
1252204100696793
```

Answer: `1252204100696793`

# Suricata Fundamentals

## Question 2

### "Enable the http-log output in suricata.yaml and run Suricata against /home/htb-student/pcaps/suspicious.pcap. Enter the requested PHP page as your answer. Answer format: `_.php`"

Students need to log in using the provided credentials `htb-student:HTB_@cademy_stdnt!` via SSH:

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[us-academy-3]─[10.10.14.139]─[htb-ac-8414@htb-psbllub6rp]─[~]
└──╼ [★]$ ssh htb-student@10.129.205.193
The authenticity of host '10.129.205.193 (10.129.205.193)' can't be established.
ECDSA key fingerprint is SHA256:3I77Le3AqCEUd+1LBAraYTRTF74wwJZJiYcnwfF5yAs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes

<SNIP>

Last login: Tue Jul 18 06:24:37 2023 from 10.10.14.23
$ 
```

Subsequently, students need to enable the `http.log` output in Suricata's YAML configuration file (`/etc/suricata/suricata.yaml`); when prompted for a password, students need to use `HTB_@cademy_stdnt!`.

Code: shell

```shell
sudo sed -i '308s#enabled: no#enabled: yes#' /etc/suricata/suricata.yaml
```

```
$ sudo sed -i '308s#enabled: no#enabled: yes#' /etc/suricata/suricata.yaml
[sudo] password for htb-student: 
```

Once the students have added the required configurational option, they will have to specify the path to the `.pcap` file (`/home/htb-student/pcaps/suspicious.pcap`) with the `-r` option in `suricata`, which will replay the packets in offline mode from the file and output the results in the current working directory.

Code: shell

```shell
suricata -r /home/htb-student/pcaps/suspicious.pcap
ls
```

```
$ suricata -r /home/htb-student/pcaps/suspicious.pcap

11/3/2024 -- 07:17:35 - <Notice> - This is Suricata version 6.0.13 RELEASE running in USER mode
11/3/2024 -- 07:17:35 - <Notice> - all 3 packet processing threads, 4 management threads initialized, engine started.
11/3/2024 -- 07:17:35 - <Notice> - Signal Received.  Stopping engine.
11/3/2024 -- 07:17:35 - <Notice> - Pcap-file module read 1 files, 5172 packets, 3941260 bytes

$ ls

eve.json  fast.log  http.log  local.rules  pcaps  stats.log  suricata.log
```

Upon running the command, students will notice that an `http.log` file was created in their current working directory. Subsequently, the student will have to use `grep` and its extended regular expression option `-E` to filter for entries that have anything related to `.php` in them.

Code: shell

```shell
grep -E "*.php" http.log
```

```
$ grep -E "*.php" http.log

12/24/2022-17:31:06.242839 adv.epostoday.uk[**]/app.php[**]Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36 Edg/85.0.564.63[**]10.9.24.101:60511 -> 192.185.57.242:80
12/24/2022-17:31:11.899970 adv.epostoday.uk[**]/app.php[**]Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36 Edg/85.0.564.63[**]10.9.24.101:60511 -> 192.185.57.242:80
```

Answer: `app.php`

# Suricata Rule Development Part 1

## Question 1

### "In the /home/htb-student directory of this section's target, there is a file called local.rules. Within this file, there is a rule with sid 2024217, which is associated with the MS17-010 exploit. Additionally, there is a PCAP file named eternalblue.pcap in the /home/htb-student/pcaps directory, which contains network traffic related to MS17-010. What is the minimum offset value that can be set to trigger an alert?"

Students need to log in using the provided credentials `htb-student:HTB_@cademy_stdnt!` via SSH:

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[us-academy-3]─[10.10.14.139]─[htb-ac-8414@htb-psbllub6rp]─[~]
└──╼ [★]$ ssh htb-student@10.129.113.209
The authenticity of host '10.129.113.209 (10.129.113.209)' can't be established.
ECDSA key fingerprint is SHA256:3I77Le3AqCEUd+1LBAraYTRTF74wwJZJiYcnwfF5yAs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes

<SNIP>

Last login: Tue Jul 18 06:24:37 2023 from 10.10.14.23
$ 
```

Subsequently, they will have to edit the `local.rules` file in their current working directory using any text editor of choice or using `sed`. Opening the file, students will have to uncomment the 19th line, where the alert rule for Eternalblue resides. Simultaneously, students need to experiment with the `offset` value in the mentioned alert and subsequently, they need to test the `offset` trigger that will produce an alert. Students will come to know that the minimum `offset` value for this particular alert is `4`.

Code: shell

```shell
sed -i '19 s/^#//; 19 s/offset:9/offset:4/' local.rules
```

```
$ sed -i '19 s/^#//; 19 s/offset:9/offset:4/' local.rules
```

Subsequently, once the students have saved the changes in the `local.rules` file, they will have to test modification using the `enternalblue.pcap` file located in `/home/htb-student/pcaps/enternalblue.pcap` directory. Students will have to use the `-r` option to replay the packets in the captured network traffic and to specify the directory using `-l` where the logs are going to be saved, and the `-k none` which disables the checksum validation to ignore specific packets that could have been altered.

Code: shell

```shell
suricata -r /home/htb-student/pcaps/eternalblue.pcap -l . -k none
```

```
$ suricata -r /home/htb-student/pcaps/eternalblue.pcap -l . -k none

Error opening file /var/log/suricata/suricata.log
11/3/2024 -- 00:30:28 - <Notice> - This is Suricata version 4.0.0-beta1 RELEASE
11/3/2024 -- 00:30:28 - <Error> - [ERRCODE: SC_ERR_FOPEN(44)] - Error opening file: "/etc/suricata/classification.config": Permission denied
11/3/2024 -- 00:30:28 - <Error> - [ERRCODE: SC_ERR_OPENING_FILE(40)] - please check the "classification-file" option in your suricata.yaml file
11/3/2024 -- 00:30:28 - <Error> - [ERRCODE: SC_ERR_FOPEN(44)] - Error opening file: "/etc/suricata/reference.config": Permission denied
11/3/2024 -- 00:30:28 - <Error> - [ERRCODE: SC_ERR_OPENING_FILE(40)] - please check the "reference-config-file" option in your suricata.yaml file
11/3/2024 -- 00:30:28 - <Warning> - [ERRCODE: SC_ERR_FOPEN(44)] - Error opening file: "/etc/suricata//threshold.config": Permission denied
11/3/2024 -- 00:30:28 - <Notice> - all 5 packet processing threads, 4 management threads initialized, engine started.
11/3/2024 -- 00:30:29 - <Notice> - Signal Received.  Stopping engine.
11/3/2024 -- 00:30:30 - <Notice> - Pcap-file module read 46654 packets, 37044839 bytes
```

Subsequently, after running the command, students will notice that various log files have been generated in their current working directory. One of the files that students must emphasize is `fast.log` which contains the alerts that have been triggered for that packet capture.

Code: shell

```shell
ls
cat fast.log
```

```
$ ls

Desktop    eve.json  keyword_perf.log  packet_stats.log  rule_group_perf.log  stats.log
Downloads  fast.log  local.rules       pcaps		 rule_perf.log	      tools

$ cat fast.log

05/18/2017-01:12:13.428436  [**] [1:2024217:3] ETERNALBLUE MS17-010 [**] [Classification: (null)] [Priority: 3] {TCP} 192.168.116.149:49472 -> 192.168.116.138:445
05/18/2017-01:12:48.732666  [**] [1:2024217:3] ETERNALBLUE MS17-010 [**] [Classification: (null)] [Priority: 3] {TCP} 192.168.116.149:50240 -> 192.168.116.138:445
05/18/2017-01:13:28.061603  [**] [1:2024217:3] ETERNALBLUE MS17-010 [**] [Classification: (null)] [Priority: 3] {TCP} 192.168.116.138:1366 -> 192.168.116.149:445
05/18/2017-01:13:22.563076  [**] [1:2024217:3] ETERNALBLUE MS17-010 [**] [Classification: (null)] [Priority: 3] {TCP} 192.168.116.149:51495 -> 192.168.116.172:445
```

If students, decide to experiment and go below the threshold for the `offset` of four (4), they will notice that the `fast.log` is going to be empty.

Answer: `4`

# Suricata Rule Development Part 2 (Encrypted Traffic)

## Question 1

### "There is a file named trickbot.pcap in the /home/htb-student/pcaps directory, which contains network traffic related to a certain variation of the Trickbot malware. Enter the precise string that should be specified in the content keyword of the rule with sid 100299 within the local.rules file so that an alert is triggered as your answer."

Students need to log in using the provided credentials `htb-student:HTB_@cademy_stdnt!` via SSH:

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[us-academy-3]─[10.10.14.139]─[htb-ac-8414@htb-psbllub6rp]─[~]
└──╼ [★]$ ssh htb-student@10.129.48.79
The authenticity of host '10.129.48.79 (10.129.48.79)' can't be established.
ECDSA key fingerprint is SHA256:3I77Le3AqCEUd+1LBAraYTRTF74wwJZJiYcnwfF5yAs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes

<SNIP>

Last login: Tue Jul 18 06:24:37 2023 from 10.10.14.23
$ 
```

Subsequently, students need to utilize the `ja3` command line utility that will extract the JA3 fingerprints from the specified `.pcap` file (`trickbot.pcap`) located in the `/home/htb-student/pcaps/trickbot.pcap` directory, using the `-a` option to look for TLS/SSL client `HELLO` messages on any port instead of targeting only port 443, and to use the `--json` option for the output to be in JSON format. Once the students have extracted the `HELLO` messages from the packet capture, they will notice that the `ja3_digest` field is populated with a hash. Students will also notice that there is traffic on port 443 and on an unusual port 449, which is used by `Trickbot` in this packet capture.

Code: shell

```shell
ja3 -a --json /home/htb-student/pcaps/trickbot.pcap | grep -A 5 '449' | head -5
```

```
$ ja3 -a --json /home/htb-student/pcaps/trickbot.pcap | grep -A 5 '449' | head -5
        "destination_port": 449,
        "ja3": "771,49196-49195-49200-49199-49188-49187-49192-49191-49162-49161-49172-49171-157-156-61-60-53-47-10,5-10-11-13-35-23-65281,29-23-24,0",
        "ja3_digest": "72a589da586844d7f0818ce684948eea",
        "source_ip": "10.22.33.145",
        "source_port": 49811,
```

Answer: `72a589da586844d7f0818ce684948eea`

# Snort Fundamentals

## Question 1

### "There is a file named wannamine.pcap in the /home/htb-student/pcaps directory. Run Snort on this PCAP file and enter how many times the rule with sid 1000001 was triggered as your answer."

Students need to log in using the provided credentials `htb-student:HTB_@cademy_stdnt!` via SSH:

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[us-academy-3]─[10.10.14.139]─[htb-ac-8414@htb-psbllub6rp]─[~]
└──╼ [★]$ ssh htb-student@10.129.196.13
The authenticity of host '10.129.196.13 (10.129.196.13)' can't be established.
ECDSA key fingerprint is SHA256:3I77Le3AqCEUd+1LBAraYTRTF74wwJZJiYcnwfF5yAs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.196.13' (ECDSA) to the list of known hosts.
htb-student@10.129.196.13's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-153-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 11 Mar 2024 08:03:12 AM UTC

  System load:             0.65
  Usage of /:              61.0% of 11.35GB
  Memory usage:            8%
  Swap usage:              0%
  Processes:               260
  Users logged in:         0
  IPv4 address for ens160: 10.129.196.13
  IPv6 address for ens160: dead:beef::250:56ff:feb9:1385

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

96 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Jul 18 08:58:10 2023 from 10.10.14.23
$ 
```

Subsequently, they will have to utilize Snort's functionality, combining the rules from the `local.rules` file located at `/home/htb-student/local.rules`. Students will have to specify the configuration file for Snort using `-c` and its location `/root/snorty/etc/snort/snort.lua`, the `--daq-dir` Data Acquisition library (DAQ) option for replacing direct calls to libcap functions facilitating operations on variety of hardware and software interfaces without requiring changes, the `-R` for specifying the local rule file `local.rules`, and the option `-A cmg` for displaying alert information along with packet headers and payloads. Students will discover that the rule in the `local.rules` file is commented out for the alert based on sid `1000001`.

Students will come to know, that they will have to scrutinize carefully the results using `grep`, `cut`, and `uniq` command line utilities.

```
sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -r /home/htb-student/pcaps/wannamine.pcap -R /home/htb-student/local.rules -A cmg | grep 1000001 | cut -d ":" -f 4 | uniq -c
```

```
$ sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -r /home/htb-student/pcaps/wannamine.pcap -R /home/htb-student/local.rules -A cmg | grep 1000001 | cut -d ":" -f 4 | uniq -c
[sudo] password for htb-student: 
    234 1000001
```

Answer: `234`

# Snort Rule Development

## Question 1

### "There is a file named log4shell.pcap in the /home/htb-student/pcaps directory, which contains network traffic related to log4shell exploitation attempts, where the payload is embedded within the user agent. Enter the keyword that should be specified right before the content keyword of the rule with sid 10000098 within the local.rules file so that an alert is triggered as your answer. Answer format: \[keyword\];"

Students need to log in using the provided credentials `htb-student:HTB_@cademy_stdnt!` via SSH:

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[us-academy-3]─[10.10.14.139]─[htb-ac-8414@htb-psbllub6rp]─[~]
└──╼ [★]$ ssh htb-student@10.129.205.192
The authenticity of host '10.129.205.192 (10.129.205.192)' can't be established.
ECDSA key fingerprint is SHA256:3I77Le3AqCEUd+1LBAraYTRTF74wwJZJiYcnwfF5yAs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.205.192' (ECDSA) to the list of known hosts.
htb-student@10.129.205.192's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-153-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 11 Mar 2024 07:37:50 AM UTC

  System load:             0.58
  Usage of /:              61.0% of 11.35GB
  Memory usage:            9%
  Swap usage:              0%
  Processes:               262
  Users logged in:         0
  IPv4 address for ens160: 10.129.205.192
  IPv6 address for ens160: dead:beef::250:56ff:feb9:2aa1

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

96 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Jul 18 08:58:10 2023 from 10.10.14.23
$ 
```

Subsequently, they will have to uncomment the 16th line in the `local.rules` file located in `/home/htb-student/` directory using a text editor of their choice. Students need to familiarize themselves with the Log4Shell exploitation. The common attack vector is to use HTTP headers to place the malicious payload and the threat actors abused mostly the `User-Agent` header to place the `jndi` payload. By researching white papers or blog posts about the vulnerability, students will stumble across multiple ones that unify the same approach used by the threat actors. Some of the many resources are [Wikipedia.org](https://en.wikipedia.org/wiki/Log4Shell#Behavior) and [Identify and exploit Log4Shell](https://bishopfox.com/blog/identify-and-exploit-log4shell). Having obtained information about the vulnerability, or at the time called zero-day, students need to accustom themselves to Snort's documentation about [HTTP requests and responses](https://docs.snort.org/rules/options/payload/http/req_resp_detection). They will stumble across the [http\_header](https://docs.snort.org/rules/options/payload/http/header), which has the capability of investigating the headers of requests and responses.

Students will come to know that the uncommented rule is missing the `http_header;` keyword argument, which inspects the HTTP (normalized request/response including the User-Agent one) headers of the network traffic. Students will also have to comment out the first line.

![[HTB Solutions/CDSA/z. images/fe25fd3783a544fb7f7f456917156835_MD5.jpg]]

Once the students have made the necessary edits, they will run snort against the `log4shell.pcap` packet capture file located in `/home/htb-student/pcaps` directory. Subsequently, students will have to run Snort using `-c` and its location `/root/snorty/etc/snort/snort.lua`, the `--daq-dir` Data Acquisition library (DAQ) option for replacing direct calls to libcap functions facilitating operations on a variety of hardware and software interfaces without requiring changes, the `-R` for specifying the local rule file `local.rules`, and the option `-A cmg` for displaying alert information along with packet headers and payloads, and the `-r` specifying the packet capture `/home/htb-student/pcaps/lo4shell.pcap`. Right after, they have run the command, students will notice that alerts have been produced.

```
sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -R /home/htb-student/local.rules -r /home/htb-student/pcaps/log4shell.pcap -A cmg
```
```
$ sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -R /home/htb-student/local.rules -r /home/htb-student/pcaps/log4shell.pcap -A cmg
--------------------------------------------------
o")~   Snort++ 3.1.64.0
--------------------------------------------------
Loading /root/snorty/etc/snort/snort.lua:
Loading snort_defaults.lua:
Finished snort_defaults.lua:
	trace
	ftp_data
	http_inspect
<SNIP>
++ [0] /home/htb-student/pcaps/log4shell.pcap
12/11-02:46:37.161834 [**] [1:10000098:1] "Log4shell Attempt Detected" [**] [Priority: 0] {TCP} 45.137.21.9:38790 -> 198.71.247.91:80

<SNIP>
```

Answer: `http_header;`

# Intrusion Detection With Zeek

## Question 1

### "There is a file named printnightmare.pcap in the /home/htb-student/pcaps directory, which contains network traffic related to the PrintNightmare (https://labs.jumpsec.com/printnightmare-network-analysis/) vulnerability. Enter the zeek log that can help us identify the suspicious spooler functions as your answer. Answer format: `_.log`"

Students need to log in using the provided credentials `htb-student:HTB_@cademy_stdnt!` via SSH:

```shell
ssh htb-student@STMIP
```
```
┌─[us-academy-3]─[10.10.14.139]─[htb-ac-8414@htb-psbllub6rp]─[~]
└──╼ [★]$ ssh htb-student@10.129.205.188
The authenticity of host '10.129.205.188 (10.129.205.188)' can't be established.
ECDSA key fingerprint is SHA256:3I77Le3AqCEUd+1LBAraYTRTF74wwJZJiYcnwfF5yAs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes

<SNIP>

Last login: Tue Jul 18 08:35:28 2023 from 10.10.14.23
$ 
```

Subsequently, they will have to run `Zeek` using the option `-C`, which will ignore invalid IP checksums, and the `-r` followed by the captured packet trace, which can be found in `/home/htb-student/pcaps/printnightmare.pcap`.

```
/usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/printnightmare.pcap
ls
```
```
$ /usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/printnightmare.pcap
$ ls
conn.log  dce_rpc.log  files  kerberos.log  ntlm.log  packet_filter.log  pcaps	smb_mapping.log  spicy-ldap  zeek-tls-log-alternative
```

Right after students run the command, a few log files will be generated in their current working directory. Students must have acknowledged that `PrintNightmare` is utilizing `Spoolss`, which uses the `DCE/RPC` and `SMB` protocols for remote printing. Zeek will produce a `dce_rpc.log` file containing the traffic for that protocol including the name pipes used.

![[HTB Solutions/CDSA/z. images/6157a6f9696190578d72a659c20953ab_MD5.jpg]]

Answer: `dce_rpc.log`

# Intrusion Detection With Zeek

## Question 2

### "There is a file named revil\_kaseya.pcap in the /home/htb-student/pcaps directory, which contains network traffic related to the REvil ransomware Kaseya supply chain attack. Enter the total number of bytes that the victim has transmitted to the IP address 178.23.155.240 as your answer."

Students need to log in using the provided credentials `htb-student:HTB_@cademy_stdnt!` via SSH:

```shell
ssh htb-student@STMIP
```
```
┌─[us-academy-3]─[10.10.14.139]─[htb-ac-8414@htb-psbllub6rp]─[~]
└──╼ [★]$ ssh htb-student@10.129.205.188
htb-student@10.129.205.188's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-153-generic x86_64)

<SNIP>

Last login: Mon Mar 11 07:40:30 2024 from 10.10.14.139
$
```

Subsequently, they will have to run `Zeek` against the `revil_kaseya.pcap` packet capture file located in `/home/htb-student/pcaps` which will generate the `conn.log` containing the connection logs. Students will have to utilize the `-C` option, which will ignore invalid IP checksums, and the `-r` followed by the captured packet trace.

```shell
/usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/revilkaseya.pcap
```
```
$ /usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/revilkaseya.pcap

1623906441.178691 error: connection does not have analyzer specified to disable
1623906441.296930 error: connection does not have analyzer specified to disable
1623906482.449649 error: connection does not have analyzer specified to disable
1623906482.559396 error: connection does not have analyzer specified to disable
1623906491.549771 error: connection does not have analyzer specified to disable
1623906492.154193 error: connection does not have analyzer specified to disable
1623906501.841714 error: connection does not have analyzer specified to disable
1623906501.958803 error: connection does not have analyzer specified to disable
```

Students will notice that log files have been generated in their current working directory, one of which is `conn.log`, containing the logs about the connections. They will utilize `zeek-cut` functionality to extract the originating host (`id.orig_h`), responding host (`id.resp_h`), and the number of bytes sent by the originating host (`orig_bytes`) fields while simultaneously scrutinizing the information in the log file using `sort`, `grep`, `datamash` that is going to be used for numeric, textual and statistical operations, and `head`.

```shell
cat conn.log | /usr/local/zeek/bin/zeek-cut id.orig_h id.resp_h orig_bytes | sort | grep -v -e '^$' | grep -v '-' | grep '178.23.155.240' | datamash -g 1,2 sum 3 | sort -k 3 -rn | head -10
```
```
$ cat conn.log | /usr/local/zeek/bin/zeek-cut id.orig_h id.resp_h orig_bytes | sort | grep -v -e '^$' | grep -v '-' | grep '178.23.155.240' | datamash -g 1,2 sum 3 | sort -k 3 -rn | head -10

192.168.100.154	178.23.155.240	2311
```

Answer: `2311`

# Skills Assessment - Suricata

## Question 1

### "There is a file named pipekatposhc2.pcap in the /home/htb-student/pcaps directory, which contains network traffic related to WMI execution. Add yet another content keyword right after the msg part of the rule with sid 2024233 within the local.rules file so that an alert is triggered and enter the specified payload as your answer. Answer format: C\_\_\_\_e"

Students need to log in using the provided credentials `htb-student:HTB_@cademy_stdnt!` via SSH:

```shell
ssh htb-student@STMIP
```
```
┌─[us-academy-3]─[10.10.14.139]─[htb-ac-8414@htb-psbllub6rp]─[~]
└──╼ [★]$ ssh htb-student@10.129.140.128
The authenticity of host '10.129.140.128 (10.129.140.128)' can't be established.
ECDSA key fingerprint is SHA256:iG4GT+w7nRDuMXSUp8sb767/GoNbP/cAyg5HcSBlDJo.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes

<SNIP>

Last login: Mon Jul 17 23:18:43 2023 from 10.10.14.23
$ 
```

Subsequently, they need to familiarise themselves with the following [publication](https://labs.withsecure.com/publications/attack-detection-fundamentals-discovery-and-lateral-movement-lab-5), where the students will notice that a reference with a GUID entry using `Win32_Process` is being generated, correlating to `CIM_Process` DCOM object tasked for running a single instance of a program, referring as a process, as an application or a task. Students will notice that the `Win32_Process` calls `Create`. They will have to utilize the value for the rule in the `local.rules` file located in their current working directory on the target. Subsequently, students need to open the rule file with a text editor of their choice, go to line `23`, and modify the rule to be:

```
alert tcp any any -> any any (msg:"WMI Execution Detected"; content:"Create"; content:"Win32_ProcessStartup"; content:"powershell"; sid:2024233; rev:2;)
```

![[HTB Solutions/CDSA/z. images/bb732d4595fdfbd482475d747a26e61a_MD5.jpg]]

Once modified, the students need to save the change in the rule file. Subsequently, students need to run the `Suricata` with the `-r` option specifying the path to the packet capture `pipkatposhc2.pcap` located in the `/home/htb-student/pcaps` directory, the `-l` specifying the directory where the log files are going to be saved, and the `-k none` option which is disabling the checksum validation to ignore specific packets that could have been altered.

```
sudo suricata -r /home/htb-student/pcaps/pipekatposhc2.pcap -l . -k none
ls
cat fast.log
```
```
$ sudo suricata -r /home/htb-student/pcaps/pipekatposhc2.pcap -l . -k none

[sudo] password for htb-student: 
11/3/2024 -- 00:51:12 - <Notice> - This is Suricata version 4.0.0-beta1 RELEASE
11/3/2024 -- 00:51:12 - <Notice> - all 5 packet processing threads, 4 management threads initialized, engine started.
11/3/2024 -- 00:51:14 - <Notice> - Signal Received.  Stopping engine.
11/3/2024 -- 00:51:14 - <Notice> - Pcap-file module read 84121 packets, 14899668 bytes
$ ls

Desktop    eve.json  keyword_perf.log  packet_stats.log  rule_group_perf.log  stats.log
Downloads  fast.log  local.rules       pcaps		 rule_perf.log	      tools
$ cat fast.log

12/26/2019-08:04:55.353819  [**] [1:2024233:2] WMI Execution Detected [**] [Classification: (null)] [Priority: 3] {TCP} 192.168.1.46:58198 -> 192.168.1.62:49154
```

Subsequently, the students will notice that the `fast.log` has been populated with alerts related to `WMI Execution`.

Answer: `Create`

# Skills Assessment - Snort

## Question 1

### "There is a file named wannamine.pcap in the /home/htb-student/pcaps directory, which contains network traffic related to the Overpass-the-hash technique which involves Kerberos encryption type downgrading. Replace XX with the appropriate value in the last content keyword of the rule with sid XXXXXXX within the local.rules file so that an alert is triggered as your answer."

Students need to log in using the provided credentials `htb-student:HTB_@cademy_stdnt!` via SSH:

```shell
ssh htb-student@STMIP
```
```
┌─[us-academy-3]─[10.10.14.139]─[htb-ac-8414@htb-psbllub6rp]─[~]
└──╼ [★]$ ssh htb-student@10.129.109.134
The authenticity of host '10.129.109.134 (10.129.109.134)' can't be established.
ECDSA key fingerprint is SHA256:3I77Le3AqCEUd+1LBAraYTRTF74wwJZJiYcnwfF5yAs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes

<SNIP>

Last login: Tue Jul 18 08:58:10 2023 from 10.10.14.23
$ 
```

Subsequently, they will have to open the `local.rules` rule file located in their current working directory with a text editor of choice. Once the students have opened the rule file, they will have to add a (`#`) comment to the first rule on the first line and uncomment the rule on the 19th line. Right after, they will notice that the rule is missing a set of bytes in the last content keyword masked with `XX`.

![[HTB Solutions/CDSA/z. images/ac17916b3bd1755a0c8770d80c1a8a59_MD5.jpg]]

Students will have to transfer the packet capture `wannamine.pcap` from the `/home/htb-student/pcaps` directory to their workstations using `scp`:

```
scp htb-student@STMIP:~/pcaps/wannamine.pcap .
```
```
┌─[eu-academy-1]─[10.10.14.112]─[htb-ac-8414@htb-fesoydut9v]─[~]
└──╼ [★]$ scp htb-student@10.129.205.192:~/pcaps/wannamine.pcap .

The authenticity of host '10.129.205.192 (10.129.205.192)' can't be established.
ECDSA key fingerprint is SHA256:3I77Le3AqCEUd+1LBAraYTRTF74wwJZJiYcnwfF5yAs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.205.192' (ECDSA) to the list of known hosts.
htb-student@10.129.205.192's password: 
wannamine.pcap                                100%  912KB  14.8MB/s   00:00
```

Once the file has been successfully transferred, students must find the specific set of bytes in the data corresponding to `A0 03 02 01`. Subsequently, students will have to open the packet capture using `wireshark`.

```
wireshark
```
```
┌─[eu-academy-1]─[10.10.14.112]─[htb-ac-8414@htb-fesoydut9v]─[~]
└──╼ [★]$ wireshark wannamine.pcap

 ** (wireshark:2952) 04:20:12.672318 [GUI WARNING] -- QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-htb-ac-8414'
```

They will have to utilize the Kerberos-related filters in `Wireshark` based on the information from the section. Students will come to know that they need to look for authentication requests for Ticket-Grant-Ticket from the KDC, more specifically, the AS-REP request. Students need to go through RFC4120 and its section [KRB\_KDC\_REQ Definition](https://datatracker.ietf.org/doc/html/rfc4120#section-5.4.1) showcasing the definitions and focusing on the `AS-REQ` and `KDC-REQ`, the latter having information on the `msg-type` header indicating the type of protocol - `kerberos.msg_type == 10` related to `AS-REQ` and `kerberos.etype` to filter for the header containing `etype` encryption algorithm. Students will be left with a few packet captures, where they need to analyze the data byte frame, searching for the byte sequence `A0 03 02 01` . Students will stumble across the packet (`3758`), where they will see the missing byte `17`.

![[HTB Solutions/CDSA/z. images/3fb283239cdd08c5510365150acd155d_MD5.jpg]]

Subsequently, students, will have to replace the `XX` byte in the `local.rules` rule file on the target with the one found - `17`.

![[HTB Solutions/CDSA/z. images/9a456cab34c8018a09c532efaaa2309e_MD5.jpg]]

Once they have made the changes and saved the rule file students will have to run Snort against that packet capture (`wannamine.pcap`). Subsequently, students will have to use the `--daq-dir` Data Acquisition library (DAQ) option for replacing direct calls to libcap functions facilitating operations on a variety of hardware and software interfaces without requiring changes, `-R` for the rules, `-r` for specifying the packet capture, and `-A cmg` for displaying alert information along with packet headers and payloads.

When students have run the command, they will notice an alert is being produced.

```
sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -R /home/htb-student/local.rules -r /home/htb-student/pcaps/wannamine.pcap -A cmg
```
```
$ sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -R /home/htb-student/local.rules -r /home/htb-student/pcaps/wannamine.pcap -A cmg

[sudo] password for htb-student: 
--------------------------------------------------
o")~   Snort++ 3.1.64.0
--------------------------------------------------
Loading /root/snorty/etc/snort/snort.lua:
Loading snort_defaults.lua:
<SNIP>
Commencing packet processing
++ [0] /home/htb-student/pcaps/wannamine.pcap
03/05-11:19:30.310384 [**] [1:9999999:0] "Kerberos Ticket Encryption Downgrade to RC4 Detected" [**] [Priority: 0] {TCP} 192.168.183.101:65135 -> 192.168.183.100:88
00:0C:29:0F:26:E1 -> 00:0C:29:54:64:A9 type:0x800 len:0x171
192.168.183.101:65135 -> 192.168.183.100:88 TCP TTL:128 TOS:0x0 ID:13641 IpLen:20 DgmLen:355 DF
***AP*** Seq: 0xC1549845  Ack: 0xCBE6A50A  Win: 0x100  TcpLen: 20

snort.raw[315]:
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -
00 00 01 37 6A 82 01 33  30 82 01 2F A1 03 02 01  ...7j..3 0../....
05 A2 03 02 01 0A A3 5F  30 5D 30 48 A1 03 02 01  ......._ 0]0H....
02 A2 41 04 3F 30 3D A0  03 02 01 17 A2 36 04 34  ..A.?0=. .....6.4
3B CE F3 39 59 69 CA B9  AF 56 DD 99 B4 1A 35 43  ;..9Yi.. .V....5C
CF EB 14 7E F7 75 28 9C  EC 58 CF 8D 13 49 37 9B  ...~.u(. .X...I7.
08 A1 93 5B 65 56 14 4C  DF 6F 33 EE 8B 62 47 ED  ...[eV.L .o3..bG.
2C 0E 9F E3 30 11 A1 04  02 02 00 80 A2 09 04 07  ,...0... ........
30 05 A0 03 01 01 FF A4  81 C1 30 81 BE A0 07 03  0....... ..0.....
05 00 40 81 00 10 A1 1A  30 18 A0 03 02 01 01 A1  ..@..... 0.......
11 30 0F 1B 0D 61 64 6D  69 6E 69 73 74 72 61 74  .0...adm inistrat
6F 72 A2 0F 1B 0D 4E 45  47 41 54 49 56 45 2E 54  or....NE GATIVE.T
45 43 48 A3 22 30 20 A0  03 02 01 02 A1 19 30 17  ECH."0 . ......0.
1B 06 6B 72 62 74 67 74  1B 0D 4E 45 47 41 54 49  ..krbtgt ..NEGATI
56 45 2E 54 45 43 48 A5  11 18 0F 32 30 33 37 30  VE.TECH. ...20370
39 31 33 30 32 34 38 30  35 5A A6 11 18 0F 32 30  91302480 5Z....20
33 37 30 39 31 33 30 32  34 38 30 35 5A A7 06 02  37091302 4805Z...
04 08 10 C6 B2 A8 15 30  13 02 01 12 02 01 11 02  .......0 ........
01 17 02 01 18 02 02 FF  79 02 01 03 A9 1D 30 1B  ........ y.....0.
30 19 A0 03 02 01 14 A1  12 04 10 41 43 43 20 20  0....... ...ACC  
20 20 20 20 20 20 20 20  20 20 20                             
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -
```

Answer: `17`

# Skills Assessment - Zeek

## Question 1

### "There is a file named neutrinogootkit.pcap in the /home/htb-student/pcaps directory, which contains network traffic related to the Neutrino exploit kit sending Gootkit malware. Enter the x509.log filed name that includes the 'MyCompany Ltd.' trace as your answer."

Students need to log in using the provided credentials `htb-student:HTB_@cademy_stdnt!` via SSH:

```shell
ssh htb-student@STMIP
```
```
┌─[us-academy-3]─[10.10.14.139]─[htb-ac-8414@htb-psbllub6rp]─[~]
└──╼ [★]$ ssh htb-student@10.129.221.60
The authenticity of host '10.129.221.60 (10.129.221.60)' can't be established.
ECDSA key fingerprint is SHA256:3I77Le3AqCEUd+1LBAraYTRTF74wwJZJiYcnwfF5yAs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes

<SNIP>

Last login: Tue Jul 18 08:35:28 2023 from 10.10.14.23
$ 
```

Once connected, students will have to run Zeek against the packet capture `neutrinogootkit.pcap` located in the `/home/htb-student/pcaps/` directory. They will have to utilize the `-C` option, which will ignore invalid IP checksums and the `-r` followed by the captured packet trace.

```
/usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/neutrinogootkit.pcap
ls
```
```
$ /usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/neutrinogootkit.pcap
$ ls

analyzer.log  dns.log  files.log  packet_filter.log  spicy-ldap  weird.log  zeek-tls-log-alternative
conn.log      files    http.log   pcaps		     ssl.log	 x509.log
```

Right after, students will notice that a few files have been created in their current working directory, one of which is `x509.log` which contains information about the certificate exchange during certain TLS negotiations.

Students will have to use `less` command-line utility followed by `-S` option, allowing them to scroll horizontally. Right after, they have opened the log file, students will have to count the number of strings on the line below `#types`, and they will notice that the `MyCompany Ltd.` string is on the fifth (5) column, which corresponds to `certificate.subject` above that.

```
less -S x509.log
```

![[HTB Solutions/CDSA/z. images/9c4765f825c9dd63880992aa5a2ac2fc_MD5.jpg]]

Answer: `certificate.subject`