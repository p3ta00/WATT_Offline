| Section | Question Number | Answer |
| --- | --- | --- |
| ARP Spoofing & Abnormality Detection | Question 1 | 507 |
| ARP Scanning & Denial-of-Service | Question 1 | 2c:30:33:e2:d5:c3 |
| 802.11 Denial-of-Service | Question 1 | 14592 |
| Rogue Access Point & Evil-Twin Attacks | Question 1 | 2c:6d:c1:af:eb:91 |
| Fragmentation Attacks | Question 1 | 66535 |
| IP Source & Destination Spoofing Attacks | Question 1 | 1 |
| TCP Handshake Abnormalities | Question 1 | 429 |
| TCP Connection Resets & Hijacking | Question 1 | administrator |
| ICMP Tunneling | Question 1 | This is a secure key: Key123456789 |
| HTTP/HTTPs Service Enumeration Detection | Question 1 | 204 |
| Strange HTTP Headers | Question 1 | 7 |
| Cross-Site Scripting (XSS) & Code Injection Detection | Question 1 | mZjQ17NLXY8ZNBbJCS0O |
| SSL Renegotiation Attacks | Question 1 | 16 |
| Peculiar DNS Traffic | Question 1 | HTB{Would\_you\_forward\_me\_this\_pretty\_please} |
| Strange Telnet & UDP Connections | Question 1 | HTB(Ipv6\_is\_my\_best\_friend) |
| Skills Assessment | Question 1 | DNS Tunneling |
| Skills Assessment | Question 2 | ICMP Tunneling |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# ARP Spoofing & Abnormality Detection

## Question 1

### "Inspect the ARP\_Poison.pcapng file, part of this module's resources, and submit the total count of ARP requests (opcode 1) that originated from the address 08:00:27:53:0c:ba as your answer."

Students will have to download the files containing the network captures that can be found in the "Resources" of the section. Once downloaded, they will have to unzip the zip archive and open the `ARP_Poisong.pcapng` network capture file that can be found in the `Intermediate_Network_Traffic_Analysis` directory.

Code: shell

```shell
wget https://academy.hackthebox.com/storage/resources/pcap_files.zip
unzip pcap_files.zip
```

```
┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/resources/pcap_files.zip
--2024-06-24 06:08:35--  https://academy.hackthebox.com/storage/resources/pcap_files.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 19078200 (18M) [application/zip]
Saving to: ‘pcap_files.zip’

pcap_files.zip    100%[============>]  18.19M  --.-KB/s    in 0.1s    

2024-06-24 06:08:36 (169 MB/s) - ‘pcap_files.zip’ saved [19078200/19078200]

┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ unzip pcap_files.zip 
Archive:  pcap_files.zip
   creating: Intermediate_Network_Traffic_Analysis/
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Poison.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Scan.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Spoof.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/basic_fuzzing.pcapng  
<SNIP>
```

Subsequently, students need to examine the network packet capture using `Wireshark`.

Code: shell

```shell
wireshark Intermediate_Network_Traffic_Analysis/ARP_Poison.pcapng
```

```
┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ wireshark Intermediate_Network_Traffic_Analysis/ARP_Poison.pcapng

 ** (wireshark:5478) 06:32:21.284528 [GUI WARNING] -- QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-htb-ac-8414'
```

Students must use the `arp.opcode` filter to look for only `ARP Requests` (`arp.opcode == 1`) and to filter based on the given mac address `08:00:27:53:0c:ba` using the `eth.src` filter option (`eth.src == 08:00:27:53:0c:ba`). The number of displayed packets will be at the bottom right of Wireshark's window.

Code: shell

```shell
arp.opcode == 1 && eth.src == 08:00:27:53:0c:ba
```

![[HTB Solutions/CDSA/z. images/71488ffabadaba964a4cdc29f9982c05_MD5.webp]]

Answer: `507`

# ARP Scanning & Denial-of-Service

## Question 1

### "Inspect the ARP\_Poison.pcapng file, part of this module's resources, and submit the first MAC address that was linked with the IP 192.168.10.1 as your answer."

Students will have to download the files containing the network captures that can be found in the "Resources" of the section. Once downloaded, they will have to unzip the zip archive and open the `ARP_Poisong.pcapng` network capture file that can be found in the `Intermediate_Network_Traffic_Analysis` directory.

Code: shell

```shell
wget https://academy.hackthebox.com/storage/resources/pcap_files.zip
unzip pcap_files.zip
```

```
┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/resources/pcap_files.zip
--2024-06-24 06:08:35--  https://academy.hackthebox.com/storage/resources/pcap_files.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 19078200 (18M) [application/zip]
Saving to: ‘pcap_files.zip’

pcap_files.zip    100%[============>]  18.19M  --.-KB/s    in 0.1s    

2024-06-24 06:08:36 (169 MB/s) - ‘pcap_files.zip’ saved [19078200/19078200]

┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ unzip pcap_files.zip 
Archive:  pcap_files.zip
   creating: Intermediate_Network_Traffic_Analysis/
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Poison.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Scan.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Spoof.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/basic_fuzzing.pcapng  
<SNIP>
```

Subsequently, students need to examine the network packet capture using `Wireshark`.

Code: shell

```shell
wireshark Intermediate_Network_Traffic_Analysis/ARP_Poison.pcapng
```

```
┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ wireshark Intermediate_Network_Traffic_Analysis/ARP_Poison.pcapng

 ** (wireshark:5478) 06:32:21.284528 [GUI WARNING] -- QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-htb-ac-8414'
```

Once they have opened the network capture of `ARP_Poison.pcapng` in `Wireshark`, students must use the `arp.opcode` filter to look for only `ARP Replies` (`arp.opcode == 2`) and the filter for `Sender IP Address` , e.g. `arp.src.proto_ipv4` (`arp.src.proto_ipv4 == 192.168.10.1`) that has replied to the ARP request.

Code: shell

```shell
arp.opcode == 2 && arp.src.proto_ipv4 == 192.168.10.1
```

Right after students have filtered the packets, they will notice in the first frame a packet with an ARP replay containing the information `192.168.10.1 is at {hidden}` to the destination `PcsCompu_53:0c:ba`.

![[HTB Solutions/CDSA/z. images/435fe3297f3ef7e64f74c5f53d6f8d7a_MD5.jpg]]

Answer: `2c:30:33:e2:d5:c3`

# 802.11 Denial-of-Service

## Question 1

### "Inspect the deauthandbadauth.cap file, part of this module's resources, and submit the total count of deauthentication frames as your answer."

Students will have to download the files containing the network captures that can be found in the "Resources" of the section. Once downloaded, they will have to unzip the zip archive and open the `deauthandbadauth.cap` network capture file that can be found in the `Intermediate_Network_Traffic_Analysis` directory.

Code: shell

```shell
wget https://academy.hackthebox.com/storage/resources/pcap_files.zip
unzip pcap_files.zip
```

```
┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/resources/pcap_files.zip
--2024-06-24 06:08:35--  https://academy.hackthebox.com/storage/resources/pcap_files.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 19078200 (18M) [application/zip]
Saving to: ‘pcap_files.zip’

pcap_files.zip    100%[============>]  18.19M  --.-KB/s    in 0.1s    

2024-06-24 06:08:36 (169 MB/s) - ‘pcap_files.zip’ saved [19078200/19078200]

┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ unzip pcap_files.zip 
Archive:  pcap_files.zip
   creating: Intermediate_Network_Traffic_Analysis/
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Poison.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Scan.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Spoof.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/basic_fuzzing.pcapng  
<SNIP>
```

Subsequently, students need to examine the network packet capture using `Wireshark`.

Code: shell

```shell
wireshark Intermediate_Network_Traffic_Analysis/deauthandbadauth.cap
```

```
┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ wireshark Intermediate_Network_Traffic_Analysis/deauthandbadauth.cap

 ** (wireshark:5813) 06:43:40.502890 [GUI WARNING] -- QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-htb-ac-8414'
```

Once they have opened the packet capture, students will take a look at the de-authentication frames using the filter to specify the type of the frame `management` using `wlan.fc.type == 00` and the subtype filter for `deauthentication` requests `wlan.fc.type_subtype == 12`:

Code: shell

```shell
(wlan.fc.type == 00) and (wlan.fc.type_subtype == 12)
```

The filter will display the frames containing `Deauthentication` requests.

![[HTB Solutions/CDSA/z. images/8e10a3fca5a77645ae9f23872e820b0e_MD5.jpg]]

Subsequently, students must utilize the `Protocol Hierarchy` statistics from the `Statistics` menu.

![[HTB Solutions/CDSA/z. images/b57c58aaacfc5f2478901ecc779b9f6a_MD5.jpg]]

Once they have opened the `Protocol Hierarchy` statistics, students will notice that the number of packets associated with `Deauthentication` requests is `{hidden}`.

Answer: `14592`

# Rogue Access Point & Evil-Twin Attacks

## Question 1

### "Inspect the rogueap.cap file, part of this module's resources, and enter the MAC address of the Evil Twin attack's victim as your answer."

Students will have to download the files containing the network captures that can be found in the "Resources" of the section. Once downloaded, they will have to unzip the zip archive and open the `rogueap.cap` network capture file that can be found in the `Intermediate_Network_Traffic_Analysis` directory.

Code: shell

```shell
wget https://academy.hackthebox.com/storage/resources/pcap_files.zip
unzip pcap_files.zip
```

```
┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/resources/pcap_files.zip
--2024-06-24 06:08:35--  https://academy.hackthebox.com/storage/resources/pcap_files.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 19078200 (18M) [application/zip]
Saving to: ‘pcap_files.zip’

pcap_files.zip    100%[============>]  18.19M  --.-KB/s    in 0.1s    

2024-06-24 06:08:36 (169 MB/s) - ‘pcap_files.zip’ saved [19078200/19078200]

┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ unzip pcap_files.zip 
Archive:  pcap_files.zip
   creating: Intermediate_Network_Traffic_Analysis/
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Poison.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Scan.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Spoof.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/basic_fuzzing.pcapng  
<SNIP>
```

Subsequently, students need to examine the network packet capture using `Wireshark`.

Code: shell

```shell
wireshark Intermediate_Network_Traffic_Analysis/rogueap.cap
```

```
┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ wireshark Intermediate_Network_Traffic_Analysis/rogueap.cap

 ** (wireshark:5944) 06:47:21.260948 [GUI WARNING] -- QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-htb-ac-8414'
```

Once they have opened the packet capture, students must use the `wlan.fc.type == 00` and the `wlan.fc.type_subtype == 8` filters to filter out for `Beacons`:

Code: shell

```shell
(wlan.fc.type == 00) and (wlan.fc.type_subtype == 8)
```

![[HTB Solutions/CDSA/z. images/019bbd25178c67c809568a0c18273a48_MD5.jpg]]

Students will notice that the second `Beacon` frame lacks information about the Robust Security Network (RSN), which indicates a rouge access point. Subsequently, they will have to note down the MAC address of that rogue access point, which can be found in the Transmitter address or Source Address fields of the IEEE 802.11 Beacon frame header. Students can copy the MAC address by right-clicking on either field and selecting `Copy`, then `Value`, which will save the MAC address of the rogue access point in their clipboards.

![[HTB Solutions/CDSA/z. images/0b71c0de30569ad241ae2aeda360869a_MD5.jpg]]

Subsequently, students must utilize the `wlan.bssid` display filter with the MAC address that they have gathered, combining the filter for ARP requests `arp.opcode` which will provide the frames that contain information about the device connected to the rouge access point:

Code: shell

```shell
(wlan.bssid == f8:14:f3:4d:e6:f2) && arp.opcode
```

![[HTB Solutions/CDSA/z. images/7dcd457ee65892a387907c5363e9518b_MD5.jpg]]

Right after they have specified the above-mentioned display filters, students will inspect the first frame with the number `179`. Students will learn that the `Source address` belongs to the victim `IntelCor_af:eb:91`, which has a MAC address of `{hidden}`.

![[HTB Solutions/CDSA/z. images/247e2d55f907cd42cc0d60957bda056e_MD5.jpg]]

Answer: `2c:6d:c1:af:eb:91`

# Fragmentation Attacks

## Question 1

### Inspect the nmap\_frag\_fw\_bypass.pcapng file, part of this module's resources, and enter the total count of packets that have the TCP RST flag set as your answer.

Students will have to download the files containing the network captures that can be found in the "Resources" of the section. Once downloaded, they will have to unzip the zip archive and open the `nmap_frag_fw_bypass.pcapng` network capture file that can be found in the `Intermediate_Network_Traffic_Analysis` directory.

Code: shell

```shell
wget https://academy.hackthebox.com/storage/resources/pcap_files.zip
unzip pcap_files.zip
```

```
┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/resources/pcap_files.zip
--2024-06-24 06:08:35--  https://academy.hackthebox.com/storage/resources/pcap_files.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 19078200 (18M) [application/zip]
Saving to: ‘pcap_files.zip’

pcap_files.zip    100%[============>]  18.19M  --.-KB/s    in 0.1s    

2024-06-24 06:08:36 (169 MB/s) - ‘pcap_files.zip’ saved [19078200/19078200]

┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ unzip pcap_files.zip 
Archive:  pcap_files.zip
   creating: Intermediate_Network_Traffic_Analysis/
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Poison.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Scan.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Spoof.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/basic_fuzzing.pcapng  
<SNIP>
```

Subsequently, students need to examine the network packet capture using `Wireshark`.

Code: shell

```shell
wireshark Intermediate_Network_Traffic_Analysis/nmap_frag_fw_bypass.pcapng
```

```
┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ wireshark Intermediate_Network_Traffic_Analysis/nmap_frag_fw_bypass.pcapng

 ** (wireshark:6223) 06:56:47.918099 [GUI WARNING] -- QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-htb-ac-8414'
```

Once they have opened the packet capture, students will need to use the `tcp.flags.reset == 1` display filter which will display only packets containing the connection reset (`RST`) flag:

Code: shell

```shell
tcp.flags.reset == 1
```

![[HTB Solutions/CDSA/z. images/8155ef0b90aa88e6aff83e4484adb301_MD5.jpg]]

Subsequently, the students will have to utilize the statistics functionality from `Statistics`, and `Conversations` which contains a summary of the number of packets that have been sent across.

![[HTB Solutions/CDSA/z. images/26aa674c5e772e804ac14e9ba5b5fa46_MD5.jpg]]

Right after, students have opened the `Conversations`, they will notice the number of packets that contain the `RST` packet for the `TCP` protocol in the `Packets` column.

Answer: `66535`

# IP Source & Destination Spoofing Attacks

## Question 1

### "Inspect the ICMP\_smurf.pcapng file, part of this module's resources, and enter the total number of attacking hosts as your answer."

Students will have to download the files containing the network captures that can be found in the "Resources" of the section. Once downloaded, they will have to unzip the zip archive and open the `ICMP_smurf.pcapng` network capture file that can be found in the `Intermediate_Network_Traffic_Analysis` directory.

Code: shell

```shell
wget https://academy.hackthebox.com/storage/resources/pcap_files.zip
unzip pcap_files.zip
```

```
┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/resources/pcap_files.zip
--2024-06-24 06:08:35--  https://academy.hackthebox.com/storage/resources/pcap_files.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 19078200 (18M) [application/zip]
Saving to: ‘pcap_files.zip’

pcap_files.zip    100%[============>]  18.19M  --.-KB/s    in 0.1s    

2024-06-24 06:08:36 (169 MB/s) - ‘pcap_files.zip’ saved [19078200/19078200]

┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ unzip pcap_files.zip 
Archive:  pcap_files.zip
   creating: Intermediate_Network_Traffic_Analysis/
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Poison.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Scan.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Spoof.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/basic_fuzzing.pcapng  
<SNIP>
```

Subsequently, students need to examine the network packet capture using `Wireshark`.

Code: shell

```shell
wireshark Intermediate_Network_Traffic_Analysis/ICMP_smurf.pcapng
```

```
┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ wireshark Intermediate_Network_Traffic_Analysis/ICMP_smurf.pcapng

 ** (wireshark:6354) 07:00:32.109960 [GUI WARNING] -- QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-htb-ac-8414'
```

Once they have opened the packet capture, students need to go to `Statistics` and `Conversations`, which contains information about the packets based on hosts.

![[HTB Solutions/CDSA/z. images/0f4f5e71ae1e8e880b35d2a0a1633bf3_MD5.jpg]]

Subsequently, students will be presented with the `Conversations` window containing information per MAC address (`Ethernet` tab) or per IPv4 (`IPv4` tab). They will notice that only `{hidden}` has generated traffic to another host (`192.168.10.1`).

Answer: `1`

# TCP Handshake Abnormalities

## Question 1

### "Inspect the nmap\_syn\_scan.pcapng file, part of this module's resources, and enter the total count of packets that have the TCP ACK flag set as your answer."

Students will have to download the files containing the network captures that can be found in the "Resources" of the section. Once downloaded, they will have to unzip the zip archive and open the `nmap_syn_scan.pcapng` network capture file that can be found in the `Intermediate_Network_Traffic_Analysis` directory.

Code: shell

```shell
wget https://academy.hackthebox.com/storage/resources/pcap_files.zip
unzip pcap_files.zip
```

```
┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/resources/pcap_files.zip
--2024-06-24 06:08:35--  https://academy.hackthebox.com/storage/resources/pcap_files.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 19078200 (18M) [application/zip]
Saving to: ‘pcap_files.zip’

pcap_files.zip    100%[============>]  18.19M  --.-KB/s    in 0.1s    

2024-06-24 06:08:36 (169 MB/s) - ‘pcap_files.zip’ saved [19078200/19078200]

┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ unzip pcap_files.zip 
Archive:  pcap_files.zip
   creating: Intermediate_Network_Traffic_Analysis/
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Poison.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Scan.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Spoof.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/basic_fuzzing.pcapng  
<SNIP>
```

Subsequently, students need to examine the network packet capture using `Wireshark`.

Code: shell

```shell
wireshark Intermediate_Network_Traffic_Analysis/nmap_syn_scan.pcapng
```

```
┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ wireshark Intermediate_Network_Traffic_Analysis/nmap_syn_scan.pcapng

 ** (wireshark:6529) 07:08:37.700835 [GUI WARNING] -- QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-htb-ac-8414'
```

Once they have opened the packet capture, students need to utilize the `tcp.flags.ack == 1` filter, which will display only frames that contain the `ACK` flag:

Code: shell

```shell
tcp.flags.ack == 1
```

![[HTB Solutions/CDSA/z. images/5feffb21e988d5fbdc3582476356d0fd_MD5.jpg]]

Subsequently, students will have to utilize the statistics functionality from `Statistics` and `Protocol Hierarchy` statistics, which contains a summary of the number of packets sent across.

![[HTB Solutions/CDSA/z. images/e4dd2db5dfabb5e57b5f8c84ddb5d8be_MD5.jpg]]

Upon opening the `Protocol Hierarchy` statistics, students will notice that `{hidden}` packets contain the `TCP ACK` flag.

Answer: `429`

# TCP Connection Reset & Hijacking

## Question 1

### "Inspect the TCP-hijacking.pcap file, part of this module's resources, and enter the username that has been used through the telnet protocol as your answer."

Students will have to download the files containing the network captures that can be found in the "Resources" of the section. Once downloaded, they will have to unzip the zip archive and open the `TCP-hijacking.pcap` network capture file that can be found in the `Intermediate_Network_Traffic_Analysis` directory.

Code: shell

```shell
wget https://academy.hackthebox.com/storage/resources/pcap_files.zip
unzip pcap_files.zip
```

```
┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/resources/pcap_files.zip
--2024-06-24 06:08:35--  https://academy.hackthebox.com/storage/resources/pcap_files.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 19078200 (18M) [application/zip]
Saving to: ‘pcap_files.zip’

pcap_files.zip    100%[============>]  18.19M  --.-KB/s    in 0.1s    

2024-06-24 06:08:36 (169 MB/s) - ‘pcap_files.zip’ saved [19078200/19078200]

┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ unzip pcap_files.zip 
Archive:  pcap_files.zip
   creating: Intermediate_Network_Traffic_Analysis/
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Poison.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Scan.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Spoof.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/basic_fuzzing.pcapng  
<SNIP>
```

Subsequently, students need to examine the network packet capture using `Wireshark`.

Code: shell

```shell
wireshark Intermediate_Network_Traffic_Analysis/TCP-hijacking.pcap
```

```
┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ wireshark Intermediate_Network_Traffic_Analysis/TCP-hijacking.pcap

 ** (wireshark:6704) 07:11:33.744503 [GUI WARNING] -- QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-htb-ac-8414'
```

Once they have opened the packet capture, students will notice a bunch of `TELNET` protocol-related frames. Subsequently, students will have to right-click on the first frame within the `TELNET` protocol and `Follow` then `TCP Stream` or with the key combination of `Ctrl + Alt + Shift + T`.

![[HTB Solutions/CDSA/z. images/95dcc3a275b7bd65170350da8e8b20b2_MD5.jpg]]

Students will be presented with a new window containing the TCP stream, where in `red` color is the clients' packet, and in `blue` color respectively are the packets from the server. They will come to know that the traffic is in plain text, meaning that they can see the commands issued by the client to the server and vice versa regarding the replies from the server. Students will come to know that the username of the user that has issued the commands is present - `{hidden}`.

Answer: `administrator`

# ICMP Tunneling

## Question 1

### "Enter the decoded value of the base64-encoded string that was mentioned in this section as your answer."

Students will have to copy the entire contents of the command from the section. Right after they have copied it, they will have to spawn a terminal, where they will place the copied command. Once they have run the command, a decoded output of the base64 string will be presented.

Code: shell

```shell
echo 'VGhpcyBpcyBhIHNlY3VyZSBrZXk6IEtleTEyMzQ1Njc4OQo=' | base64 -d
```

```
┌─[eu-academy-1]─[10.10.14.150]─[htb-ac-8414@htb-tuqpcnn3ak]─[~]
└──╼ [★]$ echo 'VGhpcyBpcyBhIHNlY3VyZSBrZXk6IEtleTEyMzQ1Njc4OQo=' | base64 -d

{hidden}
```

Answer: `This is a secure key: Key123456789`

# HTTP/HTTPs Service Enumeration

## Question 1

### "Inspect the basic\_fuzzing.pcapng file, part of this module's resources, and enter the total number of HTTP packets that are related to GET requests against port 80 as your answer."

Students will have to download the files containing the network captures that can be found in the "Resources" of the section. Once downloaded, they will have to unzip the zip archive and open the `basic_fuzzing.pcapng` network capture file that can be found in the `Intermediate_Network_Traffic_Analysis` directory.

Code: shell

```shell
wget https://academy.hackthebox.com/storage/resources/pcap_files.zip
unzip pcap_files.zip
```

```
┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/resources/pcap_files.zip
--2024-06-24 06:08:35--  https://academy.hackthebox.com/storage/resources/pcap_files.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 19078200 (18M) [application/zip]
Saving to: ‘pcap_files.zip’

pcap_files.zip    100%[============>]  18.19M  --.-KB/s    in 0.1s    

2024-06-24 06:08:36 (169 MB/s) - ‘pcap_files.zip’ saved [19078200/19078200]

┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ unzip pcap_files.zip 
Archive:  pcap_files.zip
   creating: Intermediate_Network_Traffic_Analysis/
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Poison.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Scan.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Spoof.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/basic_fuzzing.pcapng  
<SNIP>
```

Subsequently, students need to examine the network packet capture using `Wireshark`.

Code: shell

```shell
wireshark Intermediate_Network_Traffic_Analysis/basic_fuzzing.pcapng
```

```
┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ wireshark Intermediate_Network_Traffic_Analysis/basic_fuzzing.pcapng

 ** (wireshark:6843) 07:15:29.341841 [GUI WARNING] -- QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-htb-ac-8414'
```

Once they have opened the packet capture, students need to utilize the `http.request.method == GET` display filter to show packets related to a `GET` request:

Code: shell

```shell
http.request.method == GET
```

![[HTB Solutions/CDSA/z. images/861210f12417ea087792dc1b5d48a542_MD5.jpg]]

Subsequently, students will utilize the `Protocol Hierarchy` statistics located at `Statistics` and `Protocol Hierarchy`.

![[HTB Solutions/CDSA/z. images/85a91c777d9f05f8826265ffdeb0e159_MD5.jpg]]

Once they have opened the `Protocol Hierarchy` statistics, students will be presented with the number of packets (requests) related to a `GET` request within the `Hypertext Transfer Protocol` and the `Packets` column.

Answer: `204`

# Strange HTTP Headers

## Question 1

### "Inspect the CRLF\_and\_host\_header\_manipulation.pcapng file, part of this module's resources, and enter the total number of HTTP packets with response code 400 as your answer."

Students will have to download the files containing the network captures that can be found in the "Resources" of the section. Once downloaded, they will have to unzip the zip archive and open the `CRLF_and_host_header_manipulation.pcapng` network capture file that can be found in the `Intermediate_Network_Traffic_Analysis` directory.

Code: shell

```shell
wget https://academy.hackthebox.com/storage/resources/pcap_files.zip
unzip pcap_files.zip
```

```
┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/resources/pcap_files.zip
--2024-06-24 06:08:35--  https://academy.hackthebox.com/storage/resources/pcap_files.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 19078200 (18M) [application/zip]
Saving to: ‘pcap_files.zip’

pcap_files.zip    100%[============>]  18.19M  --.-KB/s    in 0.1s    

2024-06-24 06:08:36 (169 MB/s) - ‘pcap_files.zip’ saved [19078200/19078200]

┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ unzip pcap_files.zip 
Archive:  pcap_files.zip
   creating: Intermediate_Network_Traffic_Analysis/
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Poison.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Scan.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Spoof.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/basic_fuzzing.pcapng  
<SNIP>
```

Subsequently, students need to examine the network packet capture using `Wireshark`.

Code: shell

```shell
wireshark Intermediate_Network_Traffic_Analysis/CRLF_and_host_header_manipulation.pcapng
```

```
┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ wireshark Intermediate_Network_Traffic_Analysis/CRLF_and_host_header_manipulation.pcapng

 ** (wireshark:6986) 07:19:23.090504 [GUI WARNING] -- QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-htb-ac-8414'
```

Once they have opened the packet capture, students need to utilize the `http.response.code == 400` display filter to show packets related to a `400` (Bad Request) response code:

```
http.response.code == 400
```

Subsequently, students will notice that there are `{hidden}` packets that correspond to the above-mentioned response code.

Answer: `7`

# Cross-Site Scripting (XSS) & Code Injection Detection

## Question 1

### "Inspect the first packet of the XSS\_Simple.pcapng file, part of this module's resources, and enter the cookie value that was exfiltrated as your answer."

Students will have to download the files containing the network captures that can be found in the "Resources" of the section. Once downloaded, they will have to unzip the zip archive and open the `XSS_Simple.pcapng` network capture file that can be found in the `Intermediate_Network_Traffic_Analysis` directory.

Code: shell

```shell
wget https://academy.hackthebox.com/storage/resources/pcap_files.zip
unzip pcap_files.zip
```

```
┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/resources/pcap_files.zip
--2024-06-24 06:08:35--  https://academy.hackthebox.com/storage/resources/pcap_files.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 19078200 (18M) [application/zip]
Saving to: ‘pcap_files.zip’

pcap_files.zip    100%[============>]  18.19M  --.-KB/s    in 0.1s    

2024-06-24 06:08:36 (169 MB/s) - ‘pcap_files.zip’ saved [19078200/19078200]

┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ unzip pcap_files.zip 
Archive:  pcap_files.zip
   creating: Intermediate_Network_Traffic_Analysis/
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Poison.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Scan.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Spoof.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/basic_fuzzing.pcapng  
<SNIP>
```

Subsequently, students need to examine the network packet capture using `Wireshark`.

Code: shell

```shell
wireshark Intermediate_Network_Traffic_Analysis/XSS_Simple.pcapng
```

```
┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ wireshark Intermediate_Network_Traffic_Analysis/XSS_Simple.pcapng

 ** (wireshark:7593) 07:23:35.573910 [GUI WARNING] -- QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-htb-ac-8414'
```

Once they have opened the packet capture, students will have to follow either the `TCP Stream` or the `HTTP Stream` from the `Follow` menu by right-clicking on the first frame.

![[HTB Solutions/CDSA/z. images/97388585c8d66ac12b5ebebdd3a722aa_MD5.jpg]]

Subsequently, students will be presented with a window containing information about the connection between the server and the client's request/response. They will notice that in the GET header, there is a parameter called a `cookie` that holds the cookie value.

Answer: `mZjQ17NLXY8ZNBbJCS0O`

# SSL Renegotiation Attacks

## Question 1

### "Inspect the SSL\_renegotiation\_edited.pcapng file, part of this module's resources, and enter the total count of "Client Hello" requests as your answer."

Students will have to download the files containing the network captures that can be found in the "Resources" of the section. Once downloaded, they will have to unzip the zip archive and open the `SSL_renegotiation_edited.pcapng` network capture file that can be found in the `Intermediate_Network_Traffic_Analysis` directory.

Code: shell

```shell
wget https://academy.hackthebox.com/storage/resources/pcap_files.zip
unzip pcap_files.zip
```

```
┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/resources/pcap_files.zip
--2024-06-24 06:08:35--  https://academy.hackthebox.com/storage/resources/pcap_files.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 19078200 (18M) [application/zip]
Saving to: ‘pcap_files.zip’

pcap_files.zip    100%[============>]  18.19M  --.-KB/s    in 0.1s    

2024-06-24 06:08:36 (169 MB/s) - ‘pcap_files.zip’ saved [19078200/19078200]

┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ unzip pcap_files.zip 
Archive:  pcap_files.zip
   creating: Intermediate_Network_Traffic_Analysis/
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Poison.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Scan.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Spoof.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/basic_fuzzing.pcapng  
<SNIP>
```

Subsequently, students need to examine the network packet capture using `Wireshark`.

Code: shell

```shell
wireshark Intermediate_Network_Traffic_Analysis/SSL_renegotiation_edited.pcapng
```

```
┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ wireshark Intermediate_Network_Traffic_Analysis/SSL_renegotiation_edited.pcapng

 ** (wireshark:7793) 07:31:35.165148 [GUI WARNING] -- QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-htb-ac-8414'
```

Once they have opened the packet capture, students will have to use the `ssl.handshake.type == 1` display filter to show packets related to `Client Hello`:

Code: shell

```shell
ssl.handshake.type == 1
```

![[HTB Solutions/CDSA/z. images/6e87abd8ac46eb9e86c6dc1ac794a5f8_MD5.jpg]]

After students have used the filter, they can navigate to `Protocol Hierarchy` from the Statistics menu and notice that the total number of packets sent is `{hidden}`.

![[HTB Solutions/CDSA/z. images/98a11bf58871a737a0f378cc9a433d33_MD5.jpg]]

Answer: `30`

# Peculiar DNS Traffic

## Question 1

### "Enter the decoded value of the triple base64-encoded string that was mentioned in this section as your answer. Answer format: HTB{\_\_\_}"

Students will have to copy the entire contents of the command from the section. Right after they have copied it, they will have to spawn a terminal, where they will place the copied command. Once they have run the command, a decoded output of the base64 string will be presented.

Code: shell

```shell
echo 'VTBaU1EyVXhaSFprVjNocldETnNkbVJXT1cxaU0wb3pXVmhLYTFneU1XeFlNMUp2WVZoT1ptTklTbXhrU0ZJMVdETkNjMXBYUm5wYQpXREJMQ2c9PQo=' | base64 -d | base64 -d | base64 -d
```

```
┌─[eu-academy-1]─[10.10.15.184]─[htb-ac-8414@htb-z9vethnzde]─[~]
└──╼ [★]$ echo 'VTBaU1EyVXhaSFprVjNocldETnNkbVJXT1cxaU0wb3pXVmhLYTFneU1XeFlNMUp2WVZoT1ptTklTbXhrU0ZJMVdETkNjMXBYUm5wYQpXREJMQ2c9PQo=' | base64 -d | base64 -d | base64 -d

{hidden}
```

Answer: `HTB{Would_you_forward_me_this_pretty_please}`

# Strange Telnet & UDP Connections

## Question 1

### "Inspect the telnet\_tunneling\_ipv6.pcapng file, part of this module's resources, and enter the hidden flag as your answer. Answer format: HTB(\_\_) (Replace all spaces with underscores)"

Students will have to download the files containing the network captures that can be found in the "Resources" of the section. Once downloaded, they will have to unzip the zip archive and open the `telnet_tunneling_ipv6.pcapng` network capture file that can be found in the `Intermediate_Network_Traffic_Analysis` directory.

Code: shell

```shell
wget https://academy.hackthebox.com/storage/resources/pcap_files.zip
unzip pcap_files.zip
```

```
┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/resources/pcap_files.zip
--2024-06-24 06:08:35--  https://academy.hackthebox.com/storage/resources/pcap_files.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 19078200 (18M) [application/zip]
Saving to: ‘pcap_files.zip’

pcap_files.zip    100%[============>]  18.19M  --.-KB/s    in 0.1s    

2024-06-24 06:08:36 (169 MB/s) - ‘pcap_files.zip’ saved [19078200/19078200]

┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ unzip pcap_files.zip 
Archive:  pcap_files.zip
   creating: Intermediate_Network_Traffic_Analysis/
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Poison.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Scan.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Spoof.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/basic_fuzzing.pcapng  
<SNIP>
```

Subsequently, students need to examine the network packet capture using `Wireshark`.

Code: shell

```shell
wireshark Intermediate_Network_Traffic_Analysis/telnet_tunneling_ipv6.pcapng
```

```
┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ wireshark Intermediate_Network_Traffic_Analysis/telnet_tunneling_ipv6.pcapng

 ** (wireshark:7964) 07:36:36.253357 [GUI WARNING] -- QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-htb-ac-8414'
```

Once they have opened the packet capture, students will be presented with traffic related to `TELNET data`. Subsequently, students need to right-click on the first frame of the packet capture, then Follow the `TCP Stream` or use the key combination of `Ctrl + Alt + Shift + T`.

![[HTB Solutions/CDSA/z. images/6f455864101b21ebc516a05af7707e21_MD5.jpg]]

As `telnet` is an insecure protocol, upon following the `TCP Stream`, students will be presented with the plain text conversation of the client.

Answer: `HTB(Ipv6_is_my_best_friend)`

# Skills Assessment

## Question 1

### "Inspect the funky\_dns.pcap file, part of this module's resources, and enter the related attack as your answer. Answer format: "DNS Flooding", "DNS Amplification", "DNS Tunneling""

Students will have to download the files containing the network captures that can be found in the "Resources" of the section. Once downloaded, they will have to unzip the zip archive and open the `funky_dns.pcap` network capture file that can be found in the `Intermediate_Network_Traffic_Analysis` directory.

Code: shell

```shell
wget https://academy.hackthebox.com/storage/resources/pcap_files.zip
unzip pcap_files.zip
```

```
┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/resources/pcap_files.zip
--2024-06-24 06:08:35--  https://academy.hackthebox.com/storage/resources/pcap_files.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 19078200 (18M) [application/zip]
Saving to: ‘pcap_files.zip’

pcap_files.zip    100%[============>]  18.19M  --.-KB/s    in 0.1s    

2024-06-24 06:08:36 (169 MB/s) - ‘pcap_files.zip’ saved [19078200/19078200]

┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ unzip pcap_files.zip 
Archive:  pcap_files.zip
   creating: Intermediate_Network_Traffic_Analysis/
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Poison.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Scan.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Spoof.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/basic_fuzzing.pcapng  
<SNIP>
```

Subsequently, students need to examine the network packet capture using `Wireshark`.

Code: shell

```shell
wireshark Intermediate_Network_Traffic_Analysis/funky_dns.pcap
```

```
┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ wireshark Intermediate_Network_Traffic_Analysis/funky_dns.pcap

 ** (wireshark:8175) 07:43:51.336126 [GUI WARNING] -- QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-htb-ac-8414'
```

Once they have opened the packet capture, students will notice that the traffic is related to `DNS`, and the attacker attempts to do `DNS` responses related to bogus domains. Students will come to know that this is a usual behavior of Command and Control (C2) frameworks, where the beacon/agent of the C2 framework is waiting for a command/task to be executed.

![[HTB Solutions/CDSA/z. images/f05684c156229d9de28479c05cd3b42e_MD5.jpg]]

They will come to the conclusion that this traffic is related to `{hidden}`.

Answer: `DNS Tunneling`

# Skills Assessment

## Question 2

### "Inspect the funky\_icmp.pcap file, part of this module's resources, and enter the related attack as your answer. Answer format: "ICMP Flooding", "ICMP Tunneling", "ICMP SMURF Attack""

Students will have to download the files containing the network captures that can be found in the "Resources" of the section. Once downloaded, they will have to unzip the zip archive and open the `funky_icmp.pcap` network capture file that can be found in the `Intermediate_Network_Traffic_Analysis` directory.

```shell
wget https://academy.hackthebox.com/storage/resources/pcap_files.zip
unzip pcap_files.zip
```
```
┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/resources/pcap_files.zip
--2024-06-24 06:08:35--  https://academy.hackthebox.com/storage/resources/pcap_files.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 19078200 (18M) [application/zip]
Saving to: ‘pcap_files.zip’

pcap_files.zip    100%[============>]  18.19M  --.-KB/s    in 0.1s    

2024-06-24 06:08:36 (169 MB/s) - ‘pcap_files.zip’ saved [19078200/19078200]

┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ unzip pcap_files.zip 
Archive:  pcap_files.zip
   creating: Intermediate_Network_Traffic_Analysis/
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Poison.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Scan.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/ARP_Spoof.pcapng  
  inflating: Intermediate_Network_Traffic_Analysis/basic_fuzzing.pcapng  
<SNIP>
```

Subsequently, students need to examine the network packet capture using `Wireshark`.

```shell
wireshark Intermediate_Network_Traffic_Analysis/funky_icmp.pcap
```
```
┌─[eu-academy-5]─[10.10.14.65]─[htb-ac-8414@htb-ggiypsvex8]─[~]
└──╼ [★]$ wireshark Intermediate_Network_Traffic_Analysis/funky_icmp.pcap

 ** (wireshark:8321) 07:45:50.553123 [GUI WARNING] -- QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-htb-ac-8414'
```

Once they have opened the packet capture, students will notice that there are quite a few frames related to `ICMP`. Subsequently, they will have to use the `icmp and frame.len > 42` display filters to reduce the volume of data they need to go through and to focus on the packets/frames that have above the reasonable length of `42` for the `ICMP` protocol.

![[HTB Solutions/CDSA/z. images/408778b6a4938597db4f9d83e6be14d6_MD5.jpg]]

Upon further reviewing the packets/frames, students will come to know a packet at frame `No.` of `15`, and its data contains a GET request to `/shell.php?ip=10.0.3.2`, which is an indication of a reverse shell or remote code execution, and the User-Agent is `Winget`. By further going through the packet capture, students will notice packets/frames with a length of `1514`, which is also an unusual length for the `ICMP` protocol, where the transmitted data seems to be encrypted by the adversaries. Students will come to know that this overall behavior is related to `{hidden}`.

Answer: `ICMP Tunneling`