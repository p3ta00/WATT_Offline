| Section | Question Number | Answer |
| --- | --- | --- |
| Networking Primer - Layers 1-4 | Question 1 | 7 |
| Networking Primer - Layers 1-4 | Question 2 | 4 |
| Networking Primer - Layers 1-4 | Question 3 | false |
| Networking Primer - Layers 1-4 | Question 4 | MAC-address |
| Networking Primer - Layers 1-4 | Question 5 | 3 |
| Networking Primer - Layers 1-4 | Question 6 | IPv4 |
| Networking Primer - Layers 1-4 | Question 7 | TCP |
| Networking Primer - Layers 1-4 | Question 8 | UDP |
| Networking Primer - Layers 1-4 | Question 9 | ACK |
| Networking Primer - Layers 5-7 | Question 1 | Active |
| Networking Primer - Layers 5-7 | Question 2 | 20 21 |
| Networking Primer - Layers 5-7 | Question 3 | TCP |
| Networking Primer - Layers 5-7 | Question 4 | 445 |
| Networking Primer - Layers 5-7 | Question 5 | 80 |
| Networking Primer - Layers 5-7 | Question 6 | GET |
| Networking Primer - Layers 5-7 | Question 7 | HTTPS |
| Networking Primer - Layers 5-7 | Question 8 | true |
| Tcpdump Fundamentals | Question 1 | 174.143.213.184 |
| Tcpdump Fundamentals | Question 2 | relative |
| Tcpdump Fundamentals | Question 3 | \-nvXc 100 |
| Tcpdump Fundamentals | Question 4 | sudo tcpdump -Xr /tmp/capture.pcap |
| Tcpdump Fundamentals | Question 5 | \-v |
| Tcpdump Fundamentals | Question 6 | man |
| Tcpdump Fundamentals | Question 7 | \-w |
| Capturing With Tcpdump (Fundamentals Labs) | Question 1 | \-l |
| Capturing With Tcpdump (Fundamentals Labs) | Question 2 | true |
| Capturing With Tcpdump (Fundamentals Labs) | Question 3 | not ICMP |
| Capturing With Tcpdump (Fundamentals Labs) | Question 4 | which tcpdump |
| Capturing With Tcpdump (Fundamentals Labs) | Question 5 | tcpdump -i eth0 |
| Capturing With Tcpdump (Fundamentals Labs) | Question 6 | \-v |
| Capturing With Tcpdump (Fundamentals Labs) | Question 7 | \-w |
| Capturing With Tcpdump (Fundamentals Labs) | Question 8 | \-r |
| Capturing With Tcpdump (Fundamentals Labs) | Question 9 | \-X |
| Tcpdump Packet Filtering | Question 1 | host 10.10.20.1 |
| Tcpdump Packet Filtering | Question 2 | or |
| Tcpdump Packet Filtering | Question 3 | True |
| Interrogating Network Traffic With Capture and Display Filters | Question 1 | 80 43806 |
| Interrogating Network Traffic With Capture and Display Filters | Question 2 | 172.16.146.1 |
| Analysis with Wireshark | Question 1 | True |
| Analysis with Wireshark | Question 2 | Packet List |
| Analysis with Wireshark | Question 3 | packet bytes |
| Analysis with Wireshark | Question 4 | \-D |
| Analysis with Wireshark | Question 5 | \-f |
| Analysis with Wireshark | Question 6 | before |
| Wireshark Advanced Usage | Question 1 | statistics |
| Wireshark Advanced Usage | Question 2 | analyze |
| Wireshark Advanced Usage | Question 3 | TCP |
| Wireshark Advanced Usage | Question 4 | true |
| Wireshark Advanced Usage | Question 5 | false |
| Packet Inception, Dissecting Network Traffic With Wireshark | Question 1 | Rise-Up.jpg |
| Packet Inception, Dissecting Network Traffic With Wireshark | Question 2 | Bob |
| Guided Lab: Traffic Analysis Workflow | Question 1 | hacker |
| Guided Lab: Traffic Analysis Workflow | Question 2 | 44 |
| Guided Lab: Traffic Analysis Workflow | Question 3 | 4444 |
| Decrypting RDP connections | Question 1 | bucky |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Networking Primer - Layers 1-4

## Question 1

### "How many layers does the OSI model have?"

The OSI model has `7` layers:

![[HTB Solutions/CDSA/z. images/dad3e03365d6fc19a1d7d1e412217c1a_MD5.webp]]

Answer: `7`

# Networking Primer - Layers 1-4

## Question 2

### "How many layers are there in the TCP/IP model?"

The TCP/IP model has `4` layers:

![[HTB Solutions/CDSA/z. images/dad3e03365d6fc19a1d7d1e412217c1a_MD5.webp]]

Answer: `4`

# Networking Primer - Layers 1-4

## Question 3

### "True or False: Routers operate at layer 2 of the OSI model?"

`False`; routers operate at `layer 3` of the OSI model and not layer 2:

![[HTB Solutions/CDSA/z. images/863e168002cee4eeaab129ee2d097319_MD5.jpg]]

Answer: `False`

# Networking Primer - Layers 1-4

## Question 4

### "What addressing mechanism is used at the Link Layer of the TCP/IP model?"

The addressing mechanism used at the Link Layer of the TCP/IP model utilizes `MAC-Address`(es):

![[HTB Solutions/CDSA/z. images/684463b8739fec3aef5252656a2b8e43_MD5.jpg]]

Answer: `MAC-Address`

# Networking Primer - Layers 1-4

## Question 5

### "At what layer of the OSI model is a PDU encapsulated into a packet? ( the number )"

At the Network layer, layer `3`, a PDU gets encapsulated into a packet.

![[HTB Solutions/CDSA/z. images/6d0f8aaa77705b21e889fb8b210981dc_MD5.jpg]]

Answer: `3`

# Networking Primer - Layers 1-4

## Question 6

### "What addressing mechanism utilizes a 32-bit address?"

`IPv4` utilizes 32-bit addresses as an addressing mechanism:

![[HTB Solutions/CDSA/z. images/058c7e2264cfd2411d48a700b370b48d_MD5.jpg]]

Answer: `IPv4`

# Networking Primer - Layers 1-4

## Question 7

### "What Transport layer protocol is connection oriented?"

`TCP` is a connection-oriented Transport layer protocol:

![[HTB Solutions/CDSA/z. images/1e0e2c062e304a2f542e28349045bb61_MD5.jpg]]

Answer: `TCP`

# Networking Primer - Layers 1-4

## Question 8

### "What Transport Layer protocol is considered unreliable?"

`UDP` is a connection-less and unreliable Transport layer protocol:

![[HTB Solutions/CDSA/z. images/9bd4cef3c0a6545c687e8a86816b74ad_MD5.jpg]]

Answer: `UDP`

# Networking Primer - Layers 1-4

## Question 9

### "TCP's three-way handshake consists of 3 packets: 1.Syn, 2.Syn & ACK, 3. \_? What is the final packet of the handshake?"

The final packet has the `ACK` flag set:

![[HTB Solutions/CDSA/z. images/0b3d70b5473df40609d5f5f69424b9c9_MD5.jpg]]

Answer: `ACK`

# Networking Primer - Layers 5-7

## Question 1

### "What is the default operational mode method used by FTP?"

The default operational mode method utilized by FTP is `Active`:

![[HTB Solutions/CDSA/z. images/33ddeec5338ce3854ae1d1b901c7ce94_MD5.jpg]]

Answer: `Active`

# Networking Primer - Layers 5-7

## Question 2

### "FTP utilizes what two ports for command and data transfer? (separate the two numbers with a space)"

FTP utilizes ports `20` and `21` for data and commands transfer, respectively:

![[HTB Solutions/CDSA/z. images/bf1872838d662f0506b2dcd302a81d33_MD5.jpg]]

Answer: `20 21`

# Networking Primer - Layers 5-7

## Question 3

### "Does SMB utilize TCP or UDP as its transport layer protocol?"

SMB utilizes `TCP` as its transport layer protocol:

![[HTB Solutions/CDSA/z. images/ade598cf517d235779b519bd9382dfcc_MD5.jpg]]

Answer: `TCP`

# Networking Primer - Layers 5-7

## Question 4

### "SMB has moved to using what TCP port?"

SMB has moved to using port `445`:

![[HTB Solutions/CDSA/z. images/ade598cf517d235779b519bd9382dfcc_MD5.jpg]]

Answer: `445`

# Networking Primer - Layers 5-7

## Question 5

### "Hypertext Transfer Protocol uses what well known TCP port number?"

HTTP uses the well known TCP port `80`:

![[HTB Solutions/CDSA/z. images/32a3db05030f448958e474a54040d134_MD5.jpg]]

Answer: `80`

# Networking Primer - Layers 5-7

## Question 6

### "What HTTP method is used to request information and content from the webserver?"

`GET` is the HTTP method used to request information and content from the webserver:

![[HTB Solutions/CDSA/z. images/d670c78e957e4224e1743313d029b9be_MD5.jpg]]

Answer: `GET`

# Networking Primer - Layers 5-7

## Question 7

### "What web based protocol uses TLS as a security measure?"

`HTTPS` is the web based protocol that uses TLS as a security measure:

![[HTB Solutions/CDSA/z. images/c9628e45748f01490fe4e79c035f4f32_MD5.jpg]]

Answer: `HTTPS`

# Networking Primer - Layers 5-7

## Question 8

### "True or False: when utilizing HTTPS, all data sent across the session will appear as TLS Application data?”

`True`; all data sent across the session will appear as TLS Application data:

![[HTB Solutions/CDSA/z. images/708951a5685325cc7e5b6baae2bd613a_MD5.jpg]]

Answer: `True`

# Tcpdump Fundamentals

## Question 1

### "Utilizing the output shown in question-1.png, who is the server in this communication? (IP Address)"

Students first need to download [question-1.zip](https://academy.hackthebox.com/storage/modules/81/question-1.zip) provided in the question and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/81/question-1.zip
unzip question-1.zip
```

```
┌─[us-academy-1]─[10.10.14.215]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/81/question-1.zip

--2022-04-23 09:06:39--  https://academy.hackthebox.com/storage/modules/81/question-1.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 531072 (519K) [application/zip]
Saving to: ‘question-1.zip’

question-1.zip 100%[==========================================================================>] 518.62K  --.-KB/s    in 0.008s  

2022-04-23 09:06:39 (63.1 MB/s) - ‘question-1.zip’ saved [531072/531072]

┌─[us-academy-1]─[10.10.14.215]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ unzip question-1.zip

Archive:  question-1.zip
  inflating: question-1.PNG
```

Then, students need to view/open the extracted PNG image either via the file system's GUI or using the `xdg-open` utility:

Code: shell

```shell
xdg-open question-1.png
```

```
┌─[us-academy-1]─[10.10.14.215]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ xdg-open question-1.PNG
```

![[HTB Solutions/CDSA/z. images/3fb037de1246bfceae9f05b48787eec5_MD5.jpg]]

From the picture, students can deduce that `174.143.213.184` is the server for many reasons, including:

- Red Rectangle: "192.168.1.140" initiated the TCP Three-Way Handshake by sending "174.143.213.184" the "SYN" flag \[S\], for which then "174.143.213.184" replied with "SYN ACK" \[S.\] (a dot "." in here is a placeholder for "ACK").
- Cyan Rectangle: "192.168.1.140" made a HTTP GET request to "174.143.213.184".
- Yellow Rectangle: "192.168.1.140" initiated connection termination by sending "174.143.213.184" the "FIN ACK" flags \[F.\], for which then "174.143.213.184" replied with "FIN ACK" \[FIN.\].

Answer: `174.143.213.184`

# Tcpdump Fundamentals

## Question 2

### "Were absolute or relative sequence numbers used during the capture? (see question-1.zip to answer)"

`Relative` sequence numbers were used during the capture. By default, `tcpdump` prints relative sequence numbers, unless provided the `-S` (short version of `--absolute-tcp-sequence-numbers`) switch:

![[HTB Solutions/CDSA/z. images/0ac3480270ebfa481cb8ca6002d7497f_MD5.jpg]]

The command in the picture below does not use the `-S` switch:

Code: shell

```shell
tcpdump -nnr HTTP.cap
```

![[HTB Solutions/CDSA/z. images/e55150867ccb589d44a2b8c9f586c637_MD5.jpg]]

Thus, the sequence numbers are `relative`.

Answer: `Relative`

# Tcpdump Fundamentals

## Question 3

### "If I wish to start a capture without hostname resolution, verbose output, showing contents in ASCII and hex, and grab the first 100 packets; what are the switches used? please answer in the order the switches are asked for in the question."

The `-n` switch makes `tcpdump` not convert addresses (such as host addresses and port numbers) to names; the `-v` switch provides slightly more verbose output; the `-X` switch shows data of each packet in ASCII and hex; and the `-c` switch exits after receiving a certain number of packets:

![[HTB Solutions/CDSA/z. images/11169471c282e43fdb7b6c61ce77f4c2_MD5.jpg]]

Combined all together, the switches are:

Code: shell

```shell
-nvXc 100
```

Answer: `-nvXc 100`

# Tcpdump Fundamentals

## Question 4

### "Given the capture file at /tmp/capture.pcap, what tcpdump command will enable you to read from the capture and show the output contents in Hex and ASCII? (Please use best practices when using switches)"

The `-X` switch will show data of each packet in ASCII and hex, while the `-r` switch will make `tcpdump` read packets from the `/tmp/capture.pcap` file:

![[HTB Solutions/CDSA/z. images/88d3520f43fd6dccb7f6bc1d2bfdf9c3_MD5.jpg]]

Combined with `sudo` to attain root/sudo privileges, the full command becomes:

Code: shell

```shell
sudo tcpdump -Xr /tmp/capture.pcap
```

Answer: `sudo tcpdump -Xr /tmp/capture.pcap`

# Tcpdump Fundamentals

## Question 5

### "What TCPDump switch will increase the verbosity of our output? ( Include the - with the proper switch )"

The `-v` switch will increase the verbosity of `tcpdump`'s output:

![[HTB Solutions/CDSA/z. images/fee29c9f2d534d63d5186feda1d6ce43_MD5.jpg]]

Answer: `-v`

# Tcpdump Fundamentals

## Question 6

### "What built in terminal help reference can tell us more about TCPDump?"

The man page of `tcpdump` acts as a help reference that provides information about it:

![[HTB Solutions/CDSA/z. images/a2c69f36eac401e26b7f1bf0e2b67bbb_MD5.jpg]]

Answer: `man`

# Tcpdump Fundamentals

## Question 7

### "What TCPDump switch will let me write my output to a file?"

The `-w` switch enables writing output to a file:

![[HTB Solutions/CDSA/z. images/0858bdebf6606b88d3c12df35d46c51d_MD5.jpg]]

Answer: `-w`

# Fundamentals Lab

## Question 1

### "What TCPDump switch will allow us to pipe the contents of a pcap file out to another function such as 'grep'?"

Students need to consult the man page of `tcpdump` to find out that the `-l` switch allows piping the contents of a pcap file:

```
-l     Make stdout line buffered.  Useful if you want to see the data while capturing it.  E.g.,

	 tcpdump -l | tee dat

	or

	 tcpdump -l > dat & tail -f dat

Note that on Windows,\`\`line buffered'' means \`\`unbuffered'', so that WinDump will write each 
character individually if -l is specified.
```

Answer: `-l`

# Fundamentals Lab

## Question 2

### "True or False: The filter "port" looks at source and destination traffic."

`True`; by referring to the [IBM BPF](https://www.ibm.com/docs/en/qsip/7.4?topic=queries-berkeley-packet-filters) reference mentioned in the section `Network Traffic Analysis`, students will know that the `port` filter looks at source and destination traffic:

![[HTB Solutions/CDSA/z. images/87ea2725db58baf18b675d7a05604e7b_MD5.jpg]]

Answer: `True`

# Fundamentals Lab

## Question 3

### "If I wished to filter out ICMP traffic from out capture, what filter could we use? ( word only, not symbol please.)"

From the examples given in the [IBM BPF](https://www.ibm.com/docs/en/qsip/7.4?topic=queries-berkeley-packet-filters) reference, students will deduce that `not ICMP` will filter out ICMP traffic from out a capture.

Answer: `not ICMP`

# Fundamentals Lab

## Question 4

### "What command will show you where / if TCPDump is installed?"

The `which` command will show where `tcpdump` is installed:

Code: shell

```shell
which tcpdump
```

![[HTB Solutions/CDSA/z. images/0f1d47c52bd6e8f7073964bdb945aebd_MD5.jpg]]

Answer: `which tcpdump`

# Fundamentals Lab

## Question 5

### "How do you start a capture with TCPDump to capture on eth0?"

`tcpdump` needs to be invoked with the `-i` switch followed by the interface `eth0` to start a capture on it:

![[HTB Solutions/CDSA/z. images/c99f56cd3acda35f1fa48fd9c6d10612_MD5.jpg]]

Answer: `tcpdump -i eth0`

# Fundamentals Lab

## Question 6

### "What switch will provide more verbosity in your output?"

The `-v` switch will provide more verbose output for `tcpdump`:

![[HTB Solutions/CDSA/z. images/3c5c9e9f080d44ebbc70adcf94e0667b_MD5.jpg]]

Answer: `-v`

# Fundamentals Lab

## Question 7

### "What switch will write your capture output to a .pcap file?"

The `-w` switch will write the capture output to a `.pcap` file:

![[HTB Solutions/CDSA/z. images/3455958dda598165b52f2c7fd60af9f2_MD5.jpg]]

Answer: `-w`

# Fundamentals Lab

## Question 8

### "What switch will read a capture from a .pcap file?"

The `-r` switch will read a capture from a `.pcap` file:

![[HTB Solutions/CDSA/z. images/d1cd47c665b356ea1a996ff2cf2e4ea8_MD5.jpg]]

Answer: `-r`

# Fundamentals Lab

## Question 9

### "What switch will show the contents of a capture in Hex and ASCII?"

The `-X` switch will show the contents of a capture in Hex and ASCII:

![[HTB Solutions/CDSA/z. images/37d620707e420c6e5b641809ffd600e9_MD5.jpg]]

Answer: `-X`

# Tcpdump Packet Filtering

## Question 1

### "What filter will allow me to see traffic coming from or destined to the host with an ip of 10.10.20.1?"

`host` is a bidirectional filter that filters visible traffic to show anything involving the designated host:

![[HTB Solutions/CDSA/z. images/19f58be6c19b037ffa67d109b55a2671_MD5.jpg]]

Thus, the answer is `host 10.10.20.1`.

Answer: `host 10.10.20.1`

# Tcpdump Packet Filtering

## Question 2

### "What filter will allow me to capture based on either of two options?"

The `OR` filter allows to capture based on either of two options:

![[HTB Solutions/CDSA/z. images/a28d508827dc67cb40ff789321fa2687_MD5.jpg]]

Answer: `OR`

# Tcpdump Packet Filtering

## Question 3

### "True or False: TCPDump will resolve IPs to hostnames by default."

`True`; `tcpdump` by default does resolve IPs to hostnames, unless supplied the `-n` switch:

![[HTB Solutions/CDSA/z. images/7cffd72becf06b6561ecf439c974c87b_MD5.jpg]]

Answer: `True`

# Interrogating Network Traffic With Capture and Display Filters

## Question 1

### "What are the client and server port numbers used in first full TCP three-way handshake? (low number first then high number)"

Students first need to download [tcpdump-lab-2.zip](https://academy.hackthebox.com/storage/resources/tcpdump-lab2.zip) file and then extract it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/resources/tcpdump-lab2.zip
unzip tcpdump-lab2.zip
```

```
┌─[us-academy-1]─[10.10.14.215]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/resources/tcpdump-lab2.zip

--2022-04-26 22:36:58--  https://academy.hackthebox.com/storage/resources/tcpdump-lab2.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.21.126, 104.18.20.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.21.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 163520 (160K) [application/zip]
Saving to: ‘tcpdump-lab2.zip’

tcpdump-lab2.zip 100%[===========================================>] 159.69K  --.-KB/s    in 0.005s  

2022-04-26 22:36:58 (31.0 MB/s) - ‘tcpdump-lab2.zip’ saved [163520/163520]

┌─[us-academy-1]─[10.10.14.215]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ unzip tcpdump-lab2.zip

Archive:  tcpdump-lab2.zip
  inflating: TCPDump-lab-2.pcap      
  inflating: __MACOSX/._TCPDump-lab-2.pcap  
  inflating: tcpdump-lab-2-answers.md
```

Afterwards, students need to filter out anything except the TCP protocol and port 80 from the "TCPDump-lab-2.pcap" file. Instead of scrolling through the entire capture, students can truncate the output using the `-c` flag and gradually increase the packets number, until they find the answer:

Code: shell

```shell
tcpdump -nnr TCPDump-lab-2.pcap tcp port 80 -c 20
```

![[HTB Solutions/CDSA/z. images/1b2d500374eb134cdb9062983ec284e4_MD5.jpg]]

The first full `TCP three-way handshake` (identified in `tcpdump` by \[S\] \[S.\] \[.\]) is between the client 172.16.146.2 on port 43806 and the server 95.216.26.30 on port 80:

```
┌─[us-academy-1]─[10.10.14.215]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ tcpdump -nnr TCPDump-lab-2.pcap tcp port 80 -c 20

reading from file TCPDump-lab-2.pcap, link-type EN10MB (Ethernet), snapshot length 262144
<SNIP>
16:34:01.246293 IP 172.16.146.2.43806 > 95.216.26.30.80: Flags [S], seq 3078186339, win 64240, options [mss 1460,sackOK,TS val 3101551040 ecr 0,nop,wscale 7], length 0
16:34:01.389479 IP 95.216.26.30.80 > 172.16.146.2.43804: Flags [S.], seq 2667566931, ack 749874085, win 65160, options [mss 1460,sackOK,TS val 1169094229 ecr 3101551032,nop,wscale 7], length 0
<SNIP>
16:34:01.401270 IP 172.16.146.2.43806 > 95.216.26.30.80: Flags [.], ack 1, win 502, options [nop,nop,TS val 3101551195 ecr 1169094240], length 0
```

Answer: `80 43806`

# Interrogating Network Traffic With Capture and Display Filters

## Question 2

### "Based on the traffic seen in the pcap file, who is the DNS server in this network segment? (ip address)"

Students need to filter for packets where the source port is 53 only:

```shell
tcpdump -nnr TCPDump-lab-2.pcap src port 53 -c 10
```
```
┌─[us-academy-1]─[10.10.14.215]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ tcpdump -nnr TCPDump-lab-2.pcap src port 53 -c 10

reading from file TCPDump-lab-2.pcap, link-type EN10MB (Ethernet), snapshot length 262144
16:34:01.237443 IP 172.16.146.1.53 > 172.16.146.2.57752: 41819 2/0/0 A 95.216.26.30, A 207.244.88.140 (60)
16:34:01.237444 IP 172.16.146.1.53 > 172.16.146.2.57752: 46943 0/1/0 (112)
16:34:02.217577 IP 172.16.146.1.53 > 172.16.146.2.56506: 42121 1/0/0 A 172.217.164.74 (54)
16:34:02.217577 IP 172.16.146.1.53 > 172.16.146.2.56506: 37006 1/0/0 AAAA 2607:f8b0:4002:c06::5f (66)
16:34:02.241342 IP 172.16.146.1.53 > 172.16.146.2.50587: 18737 6/0/0 A 64.233.177.100, A 64.233.177.101, A 64.233.177.138, A 64.233.177.139, A 64.233.177.102, A 64.233.177.113 (128)
16:34:02.241342 IP 172.16.146.1.53 > 172.16.146.2.50587: 48695 4/0/0 AAAA 2607:f8b0:4002:c08::8b, AAAA 2607:f8b0:4002:c08::66, AAAA 2607:f8b0:4002:c08::8a, AAAA 2607:f8b0:4002:c08::65 (144)
16:34:02.249114 IP 172.16.146.1.53 > 172.16.146.2.37580: 2236 3/0/0 CNAME apache.org., A 95.216.26.30, A 207.244.88.140 (91)
16:34:02.249114 IP 172.16.146.1.53 > 172.16.146.2.37580: 62143 1/1/0 CNAME apache.org. (140)
16:34:02.386835 IP 172.16.146.1.53 > 172.16.146.2.50588: 64771 1/0/0 A 108.177.122.95 (61)
16:34:02.416084 IP 172.16.146.1.53 > 172.16.146.2.34235: 55566 2/0/0 CNAME gstaticadssl.l.google.com., AAAA 2607:f8b0:4002:c09::5e (99)
```

Thus, the DNS server is `172.16.146.1`.

Answer: `172.16.146.1`

# Analysis with Wireshark

## Question 1

### "True or False: Wireshark can run on both Windows and Linux."

`True`; both Windows and Linux can run `Wireshark`:

![[HTB Solutions/CDSA/z. images/2a51dda830422a58bec5b02b270721b9_MD5.jpg]]

Answer: `True`

# Analysis with Wireshark

## Question 2

### "Which Pane allows a user to see a summary of each packet grabbed during the capture?"

The `Packet List` pane allows a user to see a summary of each packet grabbed during the capture:

![[HTB Solutions/CDSA/z. images/57e7eed242c4fda4ed26e9a99de501b6_MD5.jpg]]

Answer: `Packet List`

# Analysis with Wireshark

## Question 3

### "Which pane provides you insight into the traffic you captured and displays it in both ASCII and Hex?"

The `Packet Bytes` pane shows insight into the traffic captured and displays it in both ASCII and Hex:

![[HTB Solutions/CDSA/z. images/9407edb136a7b9e7037e3a9840704fe1_MD5.jpg]]

Answer: `Packet Bytes`

# Analysis with Wireshark

## Question 4

### "What switch is used with TShark to list possible interfaces to capture on?"

The `-D` switch is used with `TShark` to list possible interfaces to capture traffic on:

![[HTB Solutions/CDSA/z. images/083407b1a852fed847a60ebf2ad20d87_MD5.jpg]]

Answer: `-D`

# Analysis with Wireshark

## Question 5

### "What switch allows us to apply filters in TShark?"

The `-f` switch allows to apply filters in `TShark`:

![[HTB Solutions/CDSA/z. images/1713783b7c6e722f8fc6ea4beed977b5_MD5.jpg]]

Answer: `-f`

# Analysis with Wireshark

## Question 6

### "Is a capture filter applied before the capture starts or after? (answer before or after)"

Capture filters are applied `before` a capture starts:

![[HTB Solutions/CDSA/z. images/0243944843795c45886fc221d75c5d32_MD5.jpg]]

Answer: `before`

# Wireshark Advanced Usage

## Question 1

### "Which plugin tab can provide us with a way to view conversation metadata and even protocol breakdowns for the entire PCAP file?"

The `Statistics` plugin tab provides a view to conversations metadata and protocol breakdowns for the entire `PCAP` file:

![[HTB Solutions/CDSA/z. images/5a46c51dbcccd60eb7c7a1c4c1c9b3ef_MD5.jpg]]

Answer: `Statistics`

# Wireshark Advanced Usage

## Question 2

### "What plugin tab will allow me to accomplish tasks such as applying filters, following streams, and viewing expert info?"

The `Analyze` plugin tab allows applying filters, following streams, and viewing expert info:

![[HTB Solutions/CDSA/z. images/ebfd7f476d476a1c09ab59bceb0e840a_MD5.jpg]]

Answer: `Analyze`

# Wireshark Advanced Usage

## Question 3

### "What stream oriented Transport protocol enables us to follow and rebuild conversations and the included data?"

The `TCP` protocol enables following and rebuilding of conversations and their included data:

![[HTB Solutions/CDSA/z. images/c31c14862126dfe6e402db136c30ca42_MD5.jpg]]

Answer: `TCP`

# Wireshark Advanced Usage

## Question 4

### "True or False: Wireshark can extract files from HTTP traffic."

`True`; `Wireshark` can extract files from HTTP traffic:

![[HTB Solutions/CDSA/z. images/7779ed5fdc731eecb420d0d6e2ee8feb_MD5.jpg]]

Answer: `True`

# Wireshark Advanced Usage

## Question 5

### "True or False: The ftp-data filter will show us any data sent over TCP port 21."

`False`; the `ftp-data` filter shows any data sent over TCP port 20:

![[HTB Solutions/CDSA/z. images/4fe9c20f5d892b53f4aa45c474067823_MD5.jpg]]

Answer: `False`

# Packet Inception, Dissecting Network Traffic With Wireshark

## Question 1

### "What was the filename of the image that contained a certain Transformer Leader? (name.filetype)"

Students first need to download the [Wireshark-lab-2.zip](https://academy.hackthebox.com/storage/resources/Wireshark-lab-2.zip) file and then unzip it:

```shell
wget https://academy.hackthebox.com/storage/resources/Wireshark-lab-2.zip
unzip Wireshark-lab-2.zip
```
```
┌─[us-academy-1]─[10.10.14.215]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/resources/Wireshark-lab-2.zip

--2022-04-27 12:15:24--  https://academy.hackthebox.com/storage/resources/Wireshark-lab-2.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:157e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 752738 (735K) [application/zip]
Saving to: ‘Wireshark-lab-2.zip’

Wireshark-lab-2.zip 100%[===================>] 735.10K  --.-KB/s    in 0.02s   

2022-04-27 12:15:24 (39.8 MB/s) - ‘Wireshark-lab-2.zip’ saved [752738/752738]

┌─[us-academy-1]─[10.10.14.215]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ unzip Wireshark-lab-2.zip

Archive:  Wireshark-lab-2.zip
  inflating: Wireshark-lab-2.pcap    
  inflating: __MACOSX/._Wireshark-lab-2.pcap 
```

Then, students need to open it in `WireShark` by clicking on `File` --> `Open` then choosing the "Wireshark-lab-2.pcap" file:

![[HTB Solutions/CDSA/z. images/2c4da67084ace37368c60f198dba89b6_MD5.jpg]]

Subsequently, students need to apply the filter `http && image-jfjf` to include only HTTP (80/TCP) packets along with a filter to include JPEG files only:

![[HTB Solutions/CDSA/z. images/e24426705d38a8c9b51670028b7f3ebb_MD5.jpg]]

Then, students need to click on `File` --> `Export Objects` --> `HTTP ...`:

![[HTB Solutions/CDSA/z. images/4115d9a0d75dcf3d93722232e09a8998_MD5.jpg]]

When selecting the "Rise-Up.jpg" image and clicking on Preview, it shows an image that contains a Transformers leader:

![[HTB Solutions/CDSA/z. images/58b482f34b63cde51d445d3895604eff_MD5.jpg]]

Answer: `Rise-Up`

# Packet Inception, Dissecting Network Traffic With Wireshark

## Question 2

### "Which employee is suspected of performing potentially malicious actions in the live environment?"

Students first need to connect to the spawned target machine using `xfreerdp`, utilizing the credentials `htb-student:HTB_@cademy_stdnt!`:

```shell
xfreerdp /v:STMIP /u:htb-student /p:HTB_@cademy_stdnt!
```
```
┌─[us-academy-1]─[10.10.14.169]─[htb-ac413848@htb-qlwjpm51jg]─[~]
└──╼ [★]$ xfreerdp /v:10.129.43.4 /u:htb-student /p:HTB_@cademy_stdnt!

[11:54:41:411] [7705:7706] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[11:54:41:411] [7705:7706] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[11:54:41:411] [7705:7706] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
[11:54:41:411] [7705:7706] [INFO][com.freerdp.client.common.cmdline] - loading channelEx cliprdr
```

![[HTB Solutions/CDSA/z. images/66eda481b66a07ce163ba0c8f8bdcb6a_MD5.jpg]]

Once done, they will now be able to use the spawned target machine and launch `Wireshark`:

![[HTB Solutions/CDSA/z. images/5dc21ef0fc336aae91093147f43ff29d_MD5.jpg]]

Students need to double-click on the interface `ENS224` to start capturing:

![[HTB Solutions/CDSA/z. images/ee18f2101615afb999a2992eeb994863_MD5.jpg]]

Students then need to allow `Wirewhark` to capture traffic for a while before applying any filters. Afterward, students need to apply the `http` filter and look for the packet that performs a POST request to `/login.php`:

![[HTB Solutions/CDSA/z. images/3b4f581eb7285b03a8e5478bede876bc_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/90db50f6ba1ee8eb912b49a4fbb4ed08_MD5.jpg]]

Once identified, students need to right-click it, then click on `Follow` --> `HTTP Stream`:

![[HTB Solutions/CDSA/z. images/e681a8828eed24781b04df98b5f371f8_MD5.jpg]]

Students will notice that the username submitted in the login form is `bob`:

![[HTB Solutions/CDSA/z. images/32c566b315d564439a0827bd6468874f_MD5.jpg]]

Answer: `bob`

# Guided Lab: Traffic Analysis Workflow

## Question 1

### "What was the name of the new user created on Mr. Ben's host?"

Students first need to download the [guided-analysis.zip](https://academy.hackthebox.com/storage/resources/guided-analysis.zip) file and then unzip it:

```shell
wget https://academy.hackthebox.com/storage/resources/guided-analysis.zip
unzip guided-analysis.zip
```
```
┌─[us-academy-1]─[10.10.14.215]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/resources/guided-analysis.zip

--2022-04-27 14:25:22--  https://academy.hackthebox.com/storage/resources/guided-analysis.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5414 (5.3K) [application/zip]
Saving to: ‘guided-analysis.zip’

guided-analysis.zip        100%[========================================>]   5.29K  --.-KB/s    in 0s      

2022-04-27 14:25:23 (27.7 MB/s) - ‘guided-analysis.zip’ saved [5414/5414]

┌─[us-academy-1]─[10.10.14.215]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ unzip guided-analysis.zip

Archive:  guided-analysis.zip
  inflating: guided-analysis.pcap    
  inflating: __MACOSX/._guided-analysis.pcap  
  inflating: Walkthrough Answers.md
```

Then, students can open the `pcap` file directly from the command-line using the `Wireshark` command:

```shell
wireshark guided-analysis.pcap
```

Once `Wireshark` has opened, students need to click on the 3rd packet, right-click, and then click on `Follow` --> `TCP Stream`:

![[HTB Solutions/CDSA/z. images/dace16713baf1211d967daebd3d8f4dd_MD5.jpg]]

Students will notice that the user added on Mr. Ben's host has the username of `hacker`:

![[HTB Solutions/CDSA/z. images/01b878beeb954a88446abb73873f7eb2_MD5.jpg]]

Answer: `hacker`

# Guided Lab: Traffic Analysis Workflow

## Question 2

### "How many total packets were there in the Guided-analysis PCAP?"

Students can see the total number of packets at the bottom-right of `Wireshark`:

![[HTB Solutions/CDSA/z. images/1c45d864376d1d7cbc9d47c0680ed678_MD5.jpg]]

Answer: `44`

# Guided Lab: Traffic Analysis Workflow

## Question 3

### "What was the suspicious port that was being used?"

Students will notice that the suspicious port is `4444`, since it is the port that the compromised host 10.129.43.4 is communicating to with the attacker's machine 10.129.43.29.

Answer: `4444`

# Decrypting RDP connections

## Question 1

### "What user account was used to initiate the RDP connection?"

Students first need to download the [RDP-analysis.zip](https://academy.hackthebox.com/storage/resources/RDP-analysis.zip) file, unzip it, and then open it with `Wireshark` :

```shell
wget https://academy.hackthebox.com/storage/resources/RDP-analysis.zip
unzip RDP-analysis.zip
wireshark guided-rdp.pcapng
```
```
┌─[us-academy-1]─[10.10.14.215]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/resources/RDP-analysis.zip

--2022-04-28 10:33:25--  https://academy.hackthebox.com/storage/resources/RDP-analysis.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 116802 (114K) [application/zip]
Saving to: ‘RDP-analysis.zip’

RDP-analysis.zip      100%[========================>] 114.06K  --.-KB/s    in 0.004s  

2022-04-28 10:33:25 (27.3 MB/s) - ‘RDP-analysis.zip’ saved [116802/116802]

┌─[us-academy-1]─[10.10.14.215]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ unzip RDP-analysis.zip

Archive:  RDP-analysis.zip
  inflating: guided-rdp.pcapng       
  inflating: server.key
  
┌─[us-academy-1]─[10.10.14.215]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ wireshark guided-rdp.pcapng
```

As described in the module's section, students need to import the RDP-key "server.key" to `Wireshark` to decrypt the traffic. Students need to click on Edit -> Preferences -> TLS, then click on Edit:

![[HTB Solutions/CDSA/z. images/f86b742d12cfce0c90518b4077fb0e39_MD5.jpg]]

As the section describes, students need to follow the below steps to import the key:

![[HTB Solutions/CDSA/z. images/dd6e73c1c069c42b543b62a5421acf93_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/715845cf0162057131eaf7ec5094b102_MD5.jpg]]

After successfully importing the key, students need to refresh the `pcapng` file:

![[HTB Solutions/CDSA/z. images/965c8cd9ebe9ba027eaf329726cb06da_MD5.jpg]]

Students then need to apply the `rdp` filter, and follow the TCP Stream of the first packet of the filtered output:

![[HTB Solutions/CDSA/z. images/174f8f471f1a774750b623540710244c_MD5.jpg]]

On the first line, students will notice the RDP cookie `mstshash` has the value `bucky`, which is the user account used to initiate the RDP connection:

![[HTB Solutions/CDSA/z. images/1406cd8f8f65b6d641d31ec0fae31001_MD5.jpg]]

Answer: `bucky`