

| Section                                              | Question Number | Answer                                     |
| ---------------------------------------------------- | --------------- | ------------------------------------------ |
| Hashing vs. Encryption                               | Question 1      | 87946d0585ba62c0671b734cada46b41           |
| Hashing vs. Encryption                               | Question 2      | \\x0e\\x13\\x04\\n\\x16^\\n\\x00\\x0e\\x04 |
| Identifying Hashes                                   | Question 1      | Drupal > v7.x                              |
| Hashcat Overview                                     | Question 1      | 2410                                       |
| Dictionary Attack                                    | Question 1      | cricket1                                   |
| Combination Attack                                   | Question 1      | frozenapple                                |
| Mask Attack                                          | Question 1      | HASHCATqrstu2020                           |
| Hybrid Mode                                          | Question 1      | hybridmaster9$                             |
| Working with Rules                                   | Question 1      | R@c3c@r2020                                |
| Cracking Common Hashes                               | Question 1      | Password22$                                |
| Cracking Miscellaneous Files & Hashes                | Question 1      | 3c0e87a0396cb26d5b80dc03eeef8ea0           |
| Cracking Wireless (WPA/WPA2) Handshakes with Hashcat | Question 1      | 1212312121                                 |
| Cracking Wireless (WPA/WPA2) Handshakes with Hashcat | Question 2      | 1password                                  |
| Skills Assessment - Hashcat                          | Question 1      | SHA-1                                      |
| Skills Assessment - Hashcat                          | Question 2      | flower1                                    |
| Skills Assessment - Hashcat                          | Question 3      | bubbles1                                   |
| Skills Assessment - Hashcat                          | Question 4      | p@ssw0rdadmin                              |
| Skills Assessment - Hashcat                          | Question 5      | welcome1                                   |
| Skills Assessment - Hashcat                          | Question 6      | freight1                                   |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Hashing vs. Encryption

## Question 1

### "Generate an MD5 hash of the password 'HackTheBox123!'."

Students can use `md5sum` to generate the MD5 hash of the string/password:

Code: shell

```shell
echo -n "HackTheBox123!" | md5sum
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ echo -n "HackTheBox123!" | md5sum

87946d0585ba62c0671b734cada46b41  -
```

To remove the trailing `-` character, students can use `tr`:

Code: shell

```shell
echo -n "HackTheBox123!" | md5sum | tr -d "-"
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ echo -n "HackTheBox123!" | md5sum | tr -d "-"

87946d0585ba62c0671b734cada46b41
```

Answer: `87946d0585ba62c0671b734cada46b41`

# Hashing vs. Encryption

## Question 2

### "Create the XOR ciphertext of the password 'opens3same' using the key 'academy'."

Students can use the `xor` module from `pwntools` of Python 3:

Code: shell

```shell
python3
from pwn import xor
xor(b"opens3same", b"academy").decode("utf-8")
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ python3

Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import xor
>>> xor(b"opens3same", b"academy").decode("utf-8")
'\x0e\x13\x04\n\x16^\n\x00\x0e\x04'
```

Answer: `\x0e\x13\x04\n\x16^\n\x00\x0e\x04`

# Identifying Hashes

## Question 1

### "Identify the following hash: $S$D34783772bRXEx1aCsvY.bqgaaSu75XmVlKrW9Du8IQlvxHlmzLc"

Students can use `hashid` to identify the hash type:

Code: shell

```shell
hashid '$S$D34783772bRXEx1aCsvY.bqgaaSu75XmVlKrW9Du8IQlvxHlmzLc'
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ hashid '$S$D34783772bRXEx1aCsvY.bqgaaSu75XmVlKrW9Du8IQlvxHlmzLc'

Analyzing '$S$D34783772bRXEx1aCsvY.bqgaaSu75XmVlKrW9Du8IQlvxHlmzLc'
[+] Drupal > v7.x
```

Answer: `Drupal > v7.x`

# Hashcat Overview

## Question 1

### "What is the hash mode of the hash type Cisco-ASA MD5?"

Students can use the `--expample-hashes` option of `Hashcat` and use `grep` to filter for the hash mode of `Cisco-ASA MD5`:

Code: shell

```shell
hashcat --example-hashes | grep -B 1 'Cisco-ASA MD5'
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ hashcat --example-hashes | grep -B 1 'Cisco-ASA MD5'

MODE: 2410
TYPE: Cisco-ASA MD5
```

Answer: `2410`

# Dictionary Attack

## Question 1

### "Crack the following hash using the rockyou.txt wordlist: 0c352d5b2f45217c57bef9f8452ce376"

Students first need to identify the hash type, and when using `hashid`, it outputs many possibilities:

Code: shell

```shell
hashid '0c352d5b2f45217c57bef9f8452ce376'
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ hashid '0c352d5b2f45217c57bef9f8452ce376'

Analyzing '0c352d5b2f45217c57bef9f8452ce376'
[+] MD2
[+] MD5
[+] MD4

<SNIP>
```

To narrow down the possibilities, students can use another tool, `hash-identifier`:

Code: shell

```shell
hash-identifier '0c352d5b2f45217c57bef9f8452ce376'
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ hash-identifier '0c352d5b2f45217c57bef9f8452ce376'

   #################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ \`\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__\`\   / ,__\ \ \  _ \`\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, \`\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #################################
--------------------------------------------------

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))

Least Possible Hashs:
[+] RAdmin v2.x
[+] NTLM

<SNIP>
```

The hash is most probably an MD5 hash; to know the `Hashcat` mode of MD5 hashes, students can either use the `--example-hashes` option of `Hashcat` and pipe the output to `grep` as done in Question 1 of the "Hashcat Overview" section, or they can use `hashid` with the `-m` option:

Code: shell

```shell
hashid '0c352d5b2f45217c57bef9f8452ce376' -m
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ hashid '0c352d5b2f45217c57bef9f8452ce376' -m

Analyzing '0c352d5b2f45217c57bef9f8452ce376'
[+] MD2 
[+] MD5 [Hashcat Mode: 0]

<SNIP>
```

Thus, the `Hashcat` mode is 0:

Code: shell

```shell
hashcat -m 0 '0c352d5b2f45217c57bef9f8452ce376' /usr/share/wordlists/rockyou.txt
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ hashcat -m 0 '0c352d5b2f45217c57bef9f8452ce376' /usr/share/wordlists/rockyou.txt 

hashcat (v6.1.1) starting...

<SNIP>

Host memory required for this attack: 65 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

0c352d5b2f45217c57bef9f8452ce376:cricket1        

<SNIP>
```

After successfully cracking the hash, students will know that the plaintext of it is `cricket1`.

Answer: `cricket1`

# Combination Attack

## Question 1

### "Using the Hashcat combination attack find the cleartext password of the following md5 hash: 19672a3f042ae1b592289f8333bf76c5. Use the supplementary wordlists shown at the end of this section."

Students first need to save "Supplementary word list #1" and "Supplementary word list #2" into text files:

Code: shell

```shell
cat << EOF > list1.txt
sunshine
happy
frozen
golden
EOF
```

Code: shell

```shell
cat << EOF > list2.txt
hello
joy
secret
apple
EOF
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ cat << EOF > list1.txt
> sunshine
happy
frozen
golden
> EOF
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ cat << EOF > list2.txt
> hello
joy
secret
apple
> EOF
```

Afterward, students need to use attack-mode 1 and hash-type 0 along with the two wordlists:

Code: shell

```shell
hashcat -a 1 -m 0 '19672a3f042ae1b592289f8333bf76c5' list1.txt list2.txt
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ hashcat -a 1 -m 0 '19672a3f042ae1b592289f8333bf76c5' list1.txt list2.txt

hashcat (v6.1.1) starting...

<SNIP>

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates

Host memory required for this attack: 65 MB

Dictionary cache hit:
* Filename..: list1.txt
* Passwords.: 4
* Bytes.....: 29
* Keyspace..: 16

<SNIP>

19672a3f042ae1b592289f8333bf76c5:frozenapple     

<SNIP>
```

After successfully cracking the hash, students will know that the plaintext of it is `frozenapple`.

Answer: `frozenapple`

# Mask Attack

## Question 1

### "Crack the following MD5 hash using a mask attack: 50a742905949102c961929823a2e8ca0. Use the following mask: -1 02 'HASHCAT?l?l?l?l?l20?1?d'"

Students need to use attack-mode 3, hash-type 0, and apply the mask given in the question:

Code: shell

```shell
hashcat -a 3 -m 0 '50a742905949102c961929823a2e8ca0' -1 02 'HASHCAT?l?l?l?l?l20?1?d'
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ hashcat -a 3 -m 0 '50a742905949102c961929823a2e8ca0' -1 02 'HASHCAT?l?l?l?l?l20?1?d'

hashcat (v6.1.1) starting...

<SNIP>

Host memory required for this attack: 65 MB

50a742905949102c961929823a2e8ca0:HASHCATqrstu2020
```

After successfully cracking the hash, students will know that the plaintext of it is `HASHCATqrstu2020`.

Answer: `HASHCATqrstu2020`

# Hybrid Mode

## Question 1

### "Crack the following hash: 978078e7845f2fb2e20399d9e80475bc1c275e06 using the mask ?d?s."

Students first need to identify the hash type and its `Hashcat` mode using `hashid`:

Code: shell

```shell
hashid '978078e7845f2fb2e20399d9e80475bc1c275e06' -m
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ hashid '978078e7845f2fb2e20399d9e80475bc1c275e06' -m

Analyzing '978078e7845f2fb2e20399d9e80475bc1c275e06'
[+] SHA-1 [Hashcat Mode: 100]
[+] Double SHA-1 [Hashcat Mode: 4500]
[+] RIPEMD-160 [Hashcat Mode: 6000]
[+] Haval-160 
[+] Tiger-160 
[+] HAS-160 
[+] LinkedIn [Hashcat Mode: 190]
[+] Skein-256(160) 
[+] Skein-512(160)
```

Thus, most probably it is a SHA-1 hash. Students subsequently need to use attack-mode 6 and hash-type 100 on the hash with the `?d?s` mask along with specifying the "rockyou.txt" wordlist:

Code: shell

```shell
hashcat -a 6 -m 100 '978078e7845f2fb2e20399d9e80475bc1c275e06' /usr/share/wordlists/rockyou.txt '?d?s'
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ hashcat -a 6 -m 100 '978078e7845f2fb2e20399d9e80475bc1c275e06' /usr/share/wordlists/rockyou.txt '?d?s'

<SNIP>

Host memory required for this attack: 65 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 4733647050

978078e7845f2fb2e20399d9e80475bc1c275e06:hybridmaster9$
```

After successfully cracking the hash, students will know that the plaintext of it is `hybridmaster9$`.

Answer: `hybridmaster9$`

# Working with Rules

## Question 1

### "Crack the following SHA1 hash using the techniques taught for generating a custom rule: 46244749d1e8fb99c37ad4f14fccb601ed4ae283. Modify the example rule in the beginning of the section to append 2020 to the end of each password attempt."

Students first need to modify the `c so0 si1 se3 ss5 sa@ $2 $0 $1 $9` rule to append `2020` instead of `2019`:

Code: shell

```shell
echo 'so0 si1 se3 ss5 sa@ c $2 $0 $2 $0' > rule.txt
```

Subsequently, students need to use hash-type 100 and specify the "rule.txt" file using the `-r` option along with specifying `/usr/share/wordlists/rockyou.txt` as the wordlist to be used:

Code: shell

```shell
hashcat -m 100 '46244749d1e8fb99c37ad4f14fccb601ed4ae283' /usr/share/wordlists/rockyou.txt -r rule.txt
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ hashcat -m 100 '46244749d1e8fb99c37ad4f14fccb601ed4ae283' /usr/share/wordlists/rockyou.txt -r rule.txt

hashcat (v6.1.1) starting...

<SNIP>

Host memory required for this attack: 65 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

46244749d1e8fb99c37ad4f14fccb601ed4ae283:R@c3c@r2020

<SNIP>
```

After successfully cracking the hash, students will know that the plaintext of it is `R@c3c@r2020`.

Answer: `R@c3c@r2020`

# Cracking Common Hashes

## Question 1

### "Crack the following hash: 7106812752615cdfe427e01b98cd4083"

Students first need to identify the hash type using `hash-identifier`:

Code: shell

```shell
hash-identifier '7106812752615cdfe427e01b98cd4083'
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ hash-identifier '7106812752615cdfe427e01b98cd4083'

   #################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ \`\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__\`\   / ,__\ \ \  _ \`\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, \`\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #################################
--------------------------------------------------

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))

Least Possible Hashs:
[+] RAdmin v2.x
[+] NTLM

<SNIP>
```

However for this hash, it is not what `hash-identiifer` suggests as "possible hashes", but instead it is an NTLM hash. Thus, to know its `Hashcat` hash mode, students can use the `--expample-hashes` option of `Hashcat` and use `grep` to filter for the hash mode of NTLM:

Code: shell

```shell
hashcat --example-hashes | grep -B 1 'NTLM'
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ hashcat --example-hashes | grep -B 1 'NTLM'

MODE: 1000
TYPE: NTLM
--
MODE: 5500
TYPE: NetNTLMv1 / NetNTLMv1+ESS
--
MODE: 5600
TYPE: NetNTLMv2
```

Thus, students need to use hash-type 1000 and attack-mode 6 with the `?d?s` mask along with specifying the "rockyou.txt" wordlist:

Code: shell

```shell
hashcat -a 6 -m 1000 '7106812752615cdfe427e01b98cd4083' /usr/share/wordlists/rockyou.txt '?d?s'
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ hashcat -a 6 -m 1000 '7106812752615cdfe427e01b98cd4083' /usr/share/wordlists/rockyou.txt '?d?s'
hashcat (v6.1.1) starting...

<SNIP>

Host memory required for this attack: 65 MB

Dictionary cache building /usr/share/wordlists/rockyou.txt: 33553434 bytes (23.9Dictionary cache building /usr/share/wordlists/rockyou.txt: 100660302 bytes (71.Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 4733647050
* Runtime...: 2 secs

7106812752615cdfe427e01b98cd4083:Password22$ 
```

After successfully cracking the hash, students will know that the plaintext of it is `Password22$`.

Answer: `Password22$`

# Cracking Miscellaneous Files & Hashes

## Question 1

### "Extract the hash from the attached 7-Zip file, crack the hash, and submit the value of the flag.txt file contained inside the archive."

Students first need to download the Zip file [Misc\_hashes.zip](https://academy.hackthebox.com/storage/modules/20/Misc_hashes.zip) using `wget` and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/20/Misc_hashes.zip
unzip Misc_hashes.zip
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/20/Misc_hashes.zip

--2022-07-27 03:28:03--  https://academy.hackthebox.com/storage/modules/20/Misc_hashes.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 348 [application/zip]
Saving to: ‘Misc_hashes.zip’

Misc_hashes.zip     100%[===================>]     348  --.-KB/s    in 0s      

2022-07-27 03:28:03 (5.66 MB/s) - ‘Misc_hashes.zip’ saved [348/348]
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ unzip Misc_hashes.zip

Archive:  Misc_hashes.zip
 extracting: hashcat.7z
```

Students then need to run `7z2john.py` (which can be found under `/opt/7z2john/` in Pwnbox) using `Python2.7` on the extracted "hashcat.7z" file and use `cut` to strip out "hashcat.7z" from the beginning of the output that `7z2john.py` produces:

Code: shell

```shell
python2.7 /opt/7z2john/7z2john.py hashcat.7z | cut -f2 -d ":" > 7zipHash
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ python2.7 /opt/7z2john/7z2john.py hashcat.7z | cut -f2 -d ":" > 7zipHash
```

Subsequently, students need to know the `Hashcat` hash mode for `7zip`, students can use the `--expample-hashes` option of `Hashcat` and use `grep` to filter for the hash mode of `7-Zip`:

Code: shell

```shell
hashcat --example-hashes | grep -B 1 '7-Zip'
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ hashcat --example-hashes | grep -B 1 '7-Zip'

MODE: 11600
TYPE: 7-Zip
```

Thus, students need to use hash-type 11600 on the file containing the hash and specify the "rockyou.txt" wordlist to be use:

Code: shell

```shell
hashcat -m 11600 7zipHash /usr/share/wordlists/rockyou.txt
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ hashcat -m 11600 7zipHash /usr/share/wordlists/rockyou.txt
hashcat (v6.1.1) starting...

<SNIP>

Host memory required for this attack: 65 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$7z$0$19$0$1122$8$9c7684c204c437fa0000000000000000$1098215690$112$106$7395978cad9ad8b18aef51ba2f9dcf909a1bff70d240b1c8e98dffabd352d69a1f37978e5df0179860d0fe4754721ae3cbbee1b558d93cd27e0b2959efe44a00305f982527d19584d62bcf8c23cf89e24fd19db844108e452a26d4a8343d504fc3063744d081db1492ea1cdef7a9b983:123456789a

<SNIP>
```

After successfully cracking the hash, students will know that the plaintext of it is `123456789a`. Subsequently, students need to use the plaintext of the cracked hash when extracting the file(s) from within the original "hashcat.7z" file that was downloaded:

Code: shell

```shell
7z e hashcat.7z
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ 7z e hashcat.7z 

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_GB.UTF-8,Utf16=on,HugeFiles=on,64 bits,4 CPUs DO-Regular (306F2),ASM,AES-NI)

Scanning the drive for archives:
1 file, 230 bytes (1 KiB)

Extracting archive: hashcat.7z

Enter password (will not be echoed):
--
Path = hashcat.7z
Type = 7z
Physical Size = 230
Headers Size = 182
Method = LZMA2:12 7zAES
Solid = -
Blocks = 1

Everything is Ok

Size:       33
Compressed: 230
```

At last, students need to print out the contents of the file "flag.txt" to attain the flag:

Code: shell

```shell
cat flag.txt
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ cat flag.txt

3c0e87a0396cb26d5b80dc03eeef8ea0
```

Answer: `3c0e87a0396cb26d5b80dc03eeef8ea0`

# Cracking Wireless (WPA/WPA2) Handshakes with Hashcat

## Question 1

### "Perform MIC cracking using the attached .cap file."

Students first need to download [Hashcat\_wireless1.zip](https://academy.hackthebox.com/storage/modules/20/Hashcat_wireless1.zip) using `wget` and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/20/Hashcat_wireless1.zip
unzip Hashcat_wireless1.zip
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/20/Hashcat_wireless1.zip

--2022-07-27 04:15:56--  https://academy.hackthebox.com/storage/modules/20/Hashcat_wireless1.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 556163 (543K) [application/zip]
Saving to: ‘Hashcat_wireless1.zip’

Hashcat_wireless1. 100%[================>] 543.13K  --.-KB/s    in 0.01s   

2022-07-27 04:15:56 (55.2 MB/s) - ‘Hashcat_wireless1.zip’ saved [556163/556163]
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ unzip Hashcat_wireless1.zip

Archive:  Hashcat_wireless1.zip
  inflating: corp_question1-01.cap
```

Subsequently, students need to convert the file "corp\_question1-01.cap" into a `Hashcat` compatible format `.hccapx`, for which they can utilize the [cap2hashcat](https://hashcat.net/cap2hashcat/):

![[HTB Solutions/Others/z. images/4285c05204b1905955db4dc4f36639a3_MD5.jpg]]

After loading the `.cap` file and clicking on "Convert", students need to click on "Download" when redirected to the next page:

![[HTB Solutions/Others/z. images/56b41522352152aa4ea63ee7c3c98557_MD5.jpg]]

Students can utilize `hashid` to analyze the hash from the extracted file, however, there is no need in this case; the file downloaded already reveals the hash-type that should be used with `Hashcat`, which is 22000:

Code: shell

```shell
mv ~/Downloads/18435_1658893522.hc22000 ./
hashcat -m 22000 18435_1658893522.hc22000 /usr/share/wordlists/rockyou.txt
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ mv ~/Downloads/18435_1658893522.hc22000 ./
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ hashcat -m 22000 18435_1658893522.hc22000 /usr/share/wordlists/rockyou.txt
hashcat (v6.1.1) starting...

<SNIP>

Host memory required for this attack: 65 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

92a9fe85d5656281517162c33c0f62b6:cc40d0a4d096:48e244a7c4fb:CORP-WIFI:1212312121
b7703fd2171bec7933ffc900faa6eb5b:cc40d0a4d096:80822381a9c8:CORP-WIFI:rockyou1

<SNIP>
```

Students need to submit the password `1212312121` as the flag.

Answer: `1212312121`

# Cracking Wireless (WPA/WPA2) Handshakes with Hashcat

## Question 2

### "Extract the pkmid hash from the attached .cap file and crack it."

Students first need to download the Zip file [Hashcat\_wireless2.zip](https://academy.hackthebox.com/storage/modules/20/Hashcat_wireless2.zip) using `wget` and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/20/Hashcat_wireless2.zip
unzip Hashcat_wireless2.zip
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/20/Hashcat_wireless2.zip

--2022-07-27 04:57:44--  https://academy.hackthebox.com/storage/modules/20/Hashcat_wireless2.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3090 (3.0K) [application/zip]
Saving to: ‘Hashcat_wireless2.zip’

Hashcat_wireless2.zip  100%[============================>]   3.02K  --.-KB/s    in 0s      

2022-07-27 04:57:44 (18.5 MB/s) - ‘Hashcat_wireless2.zip’ saved [3090/3090]

┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ unzip Hashcat_wireless2.zip

Archive:  Hashcat_wireless2.zip
  inflating: cracking_pmkid_question2.cap
```

Students then need to extract the `PMKID` hash from the `.cap` file using `hcxpcaptool` or `hcxpcapngtool`, for this question, the former will be used:

Code: shell

```shell
hcxpcaptool -z PMKIDHash cracking_pmkid_question2.cap
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ hcxpcaptool -z PMKIDHash cracking_pmkid_question2.cap

reading from cracking_pmkid_question2.cap

summary capture file:                           
---------------------
file name........................: cracking_pmkid_question2.cap
file type........................: pcapng 1.0
file hardware information........: x86_64
capture device vendor information: 00c0ca
file os information..............: Linux 5.7.0-kali1-amd64
file application information.....: hcxdumptool 6.0.7-22-g2f82e84 (custom options)
network type.....................: DLT_IEEE802_11_RADIO (127)
endianness.......................: little endian
read errors......................: flawless
minimum time stamp...............: 17.07.2020 16:28:48 (GMT)
maximum time stamp...............: 17.07.2020 16:34:59 (GMT)
packets inside...................: 75
skipped damaged packets..........: 0
packets with GPS NMEA data.......: 0
packets with GPS data (JSON old).: 0
packets with FCS.................: 75
beacons (total)..................: 1
probe requests...................: 4
probe responses..................: 1
association responses............: 1
EAPOL packets (total)............: 68
EAPOL packets (WPA2).............: 68
PMKIDs (not zeroed - total)......: 2
PMKIDs (WPA2)....................: 45
PMKIDs from access points........: 2
best handshakes (total)..........: 1 (ap-less: 0)
best PMKIDs (total)..............: 2

summary output file(s):
-----------------------
2 PMKID(s) written to PMKIDHash
```

Subsequently, students need to crack the hash file ("PMKIDHash" in this case) using `Hashcat`, specifying 2200 for the hash-type and "rockyou.txt" as the wordlist:

Code: shell

```shell
hashcat -m 22000 PMKIDHash /usr/share/wordlists/rockyou.txt
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ hashcat -m 22000 PMKIDHash /usr/share/wordlists/rockyou.txt 
hashcat (v6.1.1) starting...

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

b5849dab3bd0553413ed96453019e6a0:10da43bef746:80822381a9c8:CORP-WIFI:1password
609b77a10d933419201f49f25bfe222e:10da43bef746:e4e0a66592a7:CORP-WIFI:1password

<SNIP>
```

Students need to submit the password `1password` as the flag.

Answer: `1password`

# Skills Assessment

## Question 1

### "What type of hash did your colleague obtain from the SQL injection attack?"

Students need to utilize `hashid` on the hash `0c67ac18f50c5e6b9398bfe1dc3e156163ba10ef` to find out that it is a `SHA-1` hash:

Code: shell

```shell
hashid '0c67ac18f50c5e6b9398bfe1dc3e156163ba10ef' --mode
```

```
┌─[us-academy-1]─[10.10.14.41]─[htb-ac413848@htb-lqivvrhgqk]─[~]
└──╼ [★]$ hashid '0c67ac18f50c5e6b9398bfe1dc3e156163ba10ef' --mode

Analyzing '0c67ac18f50c5e6b9398bfe1dc3e156163ba10ef'
[+] SHA-1 [Hashcat Mode: 100]
[+] Double SHA-1 [Hashcat Mode: 4500]
[+] RIPEMD-160 [Hashcat Mode: 6000]
[+] Haval-160 
[+] Tiger-160 
[+] HAS-160 
[+] LinkedIn [Hashcat Mode: 190]
[+] Skein-256(160) 
[+] Skein-512(160)
```

Answer: `SHA-1`

# Skills Assessment

## Question 2

### "What is the cleartext password for the hash obtained from SQL injection in example 1?"

From the previous question, students need to know that the hashmode for `SHA-1` is 100, therefore, they need to use `Hashcat` to crack it, finding the cleartext password `flower1`:

Code: shell

```shell
hashcat -w 3 -O '0c67ac18f50c5e6b9398bfe1dc3e156163ba10ef' -m 100 /usr/share/wordlists/rockyou.txt 
```

```
┌─[us-academy-1]─[10.10.14.41]─[htb-ac413848@htb-lqivvrhgqk]─[~]
└──╼ [★]$ hashcat -w 3 -O '0c67ac18f50c5e6b9398bfe1dc3e156163ba10ef' -m 100 /usr/share/wordlists/rockyou.txt 

hashcat (v6.1.1) starting...
<SNIP>

0c67ac18f50c5e6b9398bfe1dc3e156163ba10ef:flower1 

<SNIP>
```

Answer: `flower1`

# Skills Assessment

## Question 3

### "What is the cleartext password value for the NetNTLMv2 hash?"

Students first need to determine the `Hashcat` hashmode for `NetNTLMv2`, which is 5600:

Code: shell

```shell
hashcat --example | grep "NetNTLMv2" -B 2
w\`\`\`

\`\`\`shell-session
┌─[us-academy-1]─[10.10.14.41]─[htb-ac413848@htb-lqivvrhgqk]─[~]
└──╼ [★]$ hashcat --example | grep "NetNTLMv2" -B 2

MODE: 5600
TYPE: NetNTLMv2
```

Subsequently, students need to crack the hash with `Hashcat`, finding the cleartext password `bubbles1`:

Code: shell

```shell
hashcat -w 3 -O -m 5600 'bjones::INLANEFREIGHT:699f1e768bd69c00:5304B6DB9769D974A8F24C4F4309B6BC:0101000000000000C0653150DE09D2010409DF59F277926E000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D20106000400020000000800300030000000000000000000000000300000B14866125D55255DD82C994C0D8AC3D9FF1A3EFDAECBE908F1F91C7BD4B05CF50A001000000000000000000000000000000000000900280063006900660073002F003100390032002E003100360038002E003100390035002E00310032003900000000000000000000000000' /usr/share/wordlists/rockyou.txt
```

```
┌─[us-academy-1]─[10.10.14.41]─[htb-ac413848@htb-lqivvrhgqk]─[~]
└──╼ [★]$ hashcat -w 3 -O -m 5600 'bjones::INLANEFREIGHT:699f1e768bd69c00:5304B6DB9769D974A8F24C4F4309B6BC:0101000000000000C0653150DE09D2010409DF59F277926E000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D20106000400020000000800300030000000000000000000000000300000B14866125D55255DD82C994C0D8AC3D9FF1A3EFDAECBE908F1F91C7BD4B05CF50A001000000000000000000000000000000000000900280063006900660073002F003100390032002E003100360038002E003100390035002E00310032003900000000000000000000000000' /usr/share/wordlists/rockyou.txt

hashcat (v6.1.1) starting...

<SNIP>

BJONES::INLANEFREIGHT:699f1e768bd69c00:5304b6db9769d974a8f24c4f4309b6bc:0101000000000000c0653150de09d2010409df59f277926e000000000200080053004d004200330001001e00570049004e002d00500052004800340039003200520051004100460056000400140053004d00420033002e006c006f00630061006c0003003400570049004e002d00500052004800340039003200520051004100460056002e0053004d00420033002e006c006f00630061006c000500140053004d00420033002e006c006f00630061006c0007000800c0653150de09d20106000400020000000800300030000000000000000000000000300000b14866125d55255dd82c994c0d8ac3d9ff1a3efdaecbe908f1f91c7bd4b05cf50a001000000000000000000000000000000000000900280063006900660073002f003100390032002e003100360038002e003100390035002e00310032003900000000000000000000000000:bubbles1

<SNIP>
```

Answer: `bubbles1`

# Skills Assessment

## Question 4

### "Crack the TGS ticket obtained from the Kerberoasting attack."

Students first need to determine the `Hashcat` hashmode for the `TGS` ticket, which is 13100:

Code: shell

```shell
hashcat --example | grep "TGS" -B 2 -m 1
```

```
┌─[us-academy-1]─[10.10.14.41]─[htb-ac413848@htb-lqivvrhgqk]─[~]
└──╼ [★]$ hashcat --example | grep "TGS" -B 2 -m 1

MODE: 13100
TYPE: Kerberos 5, etype 23, TGS-REP
```

Subsequently, students need to crack the hash with `Hashcat`, finding the cleartext password `p@ssw0rdadmin`:

Code: shell

```shell
 hashcat -w 3 -O -m 13100 '$krb5tgs$23$*sql_svc$INLANEFREIGHT.LOCAL$mssql/inlanefreight.local~1443*$80be357f5e68b4f64a185397bf72cf1c$579d028f0f91f5791683844c3a03f48972cb9013eddf11728fc19500679882106538379cbe1cb503677b757bcb56f9e708cd173a5b04ad8fc462fa380ffcb4e1b4feed820fa183109e2653b46faee565af76d5b0ee8460a3e0ad48ea098656584de67974372f4a762daa625fb292556b407c0c97fd629506bd558dede0c950a039e2e3433ee956fc218a54b148d3e5d1f99781ad4e419bc76632e30ea2c1660663ba9866230c790ba166b865d5153c6b85a184fbafd5a4af6d3200d67857da48e20039bbf31853da46215cbbc5ebae6a3b0225b6651ec8cc792c8c3d5893a8d014f9d297ac297288e76d27a1ed2942d6997f6b24198e64fea9ff5a94badd53cc12a73e9505e4dab36e4bd1ef7fe5a08e527d9046b49e730d83d8af395f06fe35d360c59ab8ebe2c3b7553acf8d40c296b86c1fb26fdf43fa8be2ac4a92152181b81afb1f4773936b0ccc696f21e8e0fe7372252b3c24d82038c62027abc34a4204fb6e52bf71290fdf0db60b1888f8369a7917821f6869b6e51bda15f1fd7284ca1c37fb2dc46c367046a15d093cc501f3155f1e63040313cc8db2a8437ee6dc8ceb04bf924427019b396667f0532d995e3d655b9fb0ef8e61b31e523d81914d9eb177529783c29788d486139e1f3d29cbe4d2f881c61f74ff32a9233134ec69f26082e8aaa0c0e99006a5666c24fccfd195796a0be97cecb257259a640641f8c2d58d2d94452ec00ad84078afc1f7f72f3b9e8210b5db73bf70cd13ef172ef3b233c987d5ec7ea12a4d4921a43fb670c9f48aaae9e1d48ec7be58638a8b2f89a62b56775deddbbc971803316470ee416d8a6c0c8d17982396f6c0c0eeec425d5c599fb60b5c39f8e9ceff4ee25c5bc953178972de616edae61586bb868e463f420e9e09c083662bcf6f0f522f78630792e02e6986f5dd042dfb70100ab59d8a01093b3d89949ea19fe9c596a8681e2a71abe75debd62b985d03d488442aa41cc8993eff0224de62221d39be8bf1d8b26f8f8768e90e5b4b886adaf02a19f55e6d1fd11b004d4e7b170c4f7feaa04b8dad207d6f863d50a251d9a9ce66951de41a3690fec6144e73428d4718cc7ec5eeeff841b4329a7ba51624f678557b6eafc55af026314cbf9dd9ca232977da3cce204899f3048101e0010f42d0076cd494526beea862c72ee48749ba071bcdd1a96c64a0d8f48c6acad7730121021be6323f69505aad8fb6281b7ac4a607d1d241f1fbffc70c4a74c997bb2fb77c452c0077efdea2a6c00704a8bee28326b5e554e1faa48a33963ce2c2e0e2446b4504a05d541bbaf531e1644ad92a2feae5b2eb8851b067e7bd8d7d23d82e63d368983ba44f52901cba7e05cfa35e832ec445a7de50eca670fa90' /usr/share/wordlists/rockyou.txt
```

```
┌─[us-academy-1]─[10.10.14.41]─[htb-ac413848@htb-lqivvrhgqk]─[~]
└──╼ [★]$ hashcat -w 3 -O -m 13100 '$krb5tgs$23$*sql_svc$INLANEFREIGHT.LOCAL$mssql/inlanefreight.local~1443*$80be357f5e68b4f64a185397bf72cf1c$579d028f0f91f5791683844c3a03f48972cb9013eddf11728fc19500679882106538379cbe1cb503677b757bcb56f9e708cd173a5b04ad8fc462fa380ffcb4e1b4feed820fa183109e2653b46faee565af76d5b0ee8460a3e0ad48ea098656584de67974372f4a762daa625fb292556b407c0c97fd629506bd558dede0c950a039e2e3433ee956fc218a54b148d3e5d1f99781ad4e419bc76632e30ea2c1660663ba9866230c790ba166b865d5153c6b85a184fbafd5a4af6d3200d67857da48e20039bbf31853da46215cbbc5ebae6a3b0225b6651ec8cc792c8c3d5893a8d014f9d297ac297288e76d27a1ed2942d6997f6b24198e64fea9ff5a94badd53cc12a73e9505e4dab36e4bd1ef7fe5a08e527d9046b49e730d83d8af395f06fe35d360c59ab8ebe2c3b7553acf8d40c296b86c1fb26fdf43fa8be2ac4a92152181b81afb1f4773936b0ccc696f21e8e0fe7372252b3c24d82038c62027abc34a4204fb6e52bf71290fdf0db60b1888f8369a7917821f6869b6e51bda15f1fd7284ca1c37fb2dc46c367046a15d093cc501f3155f1e63040313cc8db2a8437ee6dc8ceb04bf924427019b396667f0532d995e3d655b9fb0ef8e61b31e523d81914d9eb177529783c29788d486139e1f3d29cbe4d2f881c61f74ff32a9233134ec69f26082e8aaa0c0e99006a5666c24fccfd195796a0be97cecb257259a640641f8c2d58d2d94452ec00ad84078afc1f7f72f3b9e8210b5db73bf70cd13ef172ef3b233c987d5ec7ea12a4d4921a43fb670c9f48aaae9e1d48ec7be58638a8b2f89a62b56775deddbbc971803316470ee416d8a6c0c8d17982396f6c0c0eeec425d5c599fb60b5c39f8e9ceff4ee25c5bc953178972de616edae61586bb868e463f420e9e09c083662bcf6f0f522f78630792e02e6986f5dd042dfb70100ab59d8a01093b3d89949ea19fe9c596a8681e2a71abe75debd62b985d03d488442aa41cc8993eff0224de62221d39be8bf1d8b26f8f8768e90e5b4b886adaf02a19f55e6d1fd11b004d4e7b170c4f7feaa04b8dad207d6f863d50a251d9a9ce66951de41a3690fec6144e73428d4718cc7ec5eeeff841b4329a7ba51624f678557b6eafc55af026314cbf9dd9ca232977da3cce204899f3048101e0010f42d0076cd494526beea862c72ee48749ba071bcdd1a96c64a0d8f48c6acad7730121021be6323f69505aad8fb6281b7ac4a607d1d241f1fbffc70c4a74c997bb2fb77c452c0077efdea2a6c00704a8bee28326b5e554e1faa48a33963ce2c2e0e2446b4504a05d541bbaf531e1644ad92a2feae5b2eb8851b067e7bd8d7d23d82e63d368983ba44f52901cba7e05cfa35e832ec445a7de50eca670fa90' /usr/share/wordlists/rockyou.txt 

hashcat (v6.1.1) starting...

<SNIP>

$krb5tgs$23$*sql_svc$INLANEFREIGHT.LOCAL$mssql/inlanefreight.local~1443*$80be357f5e68b4f64a185397bf72cf1c$579d028f0f91f5791683844c3a03f48972cb9013eddf11728fc19500679882106538379cbe1cb503677b757bcb56f9e708cd173a5b04ad8fc462fa380ffcb4e1b4feed820fa183109e2653b46faee565af76d5b0ee8460a3e0ad48ea098656584de67974372f4a762daa625fb292556b407c0c97fd629506bd558dede0c950a039e2e3433ee956fc218a54b148d3e5d1f99781ad4e419bc76632e30ea2c1660663ba9866230c790ba166b865d5153c6b85a184fbafd5a4af6d3200d67857da48e20039bbf31853da46215cbbc5ebae6a3b0225b6651ec8cc792c8c3d5893a8d014f9d297ac297288e76d27a1ed2942d6997f6b24198e64fea9ff5a94badd53cc12a73e9505e4dab36e4bd1ef7fe5a08e527d9046b49e730d83d8af395f06fe35d360c59ab8ebe2c3b7553acf8d40c296b86c1fb26fdf43fa8be2ac4a92152181b81afb1f4773936b0ccc696f21e8e0fe7372252b3c24d82038c62027abc34a4204fb6e52bf71290fdf0db60b1888f8369a7917821f6869b6e51bda15f1fd7284ca1c37fb2dc46c367046a15d093cc501f3155f1e63040313cc8db2a8437ee6dc8ceb04bf924427019b396667f0532d995e3d655b9fb0ef8e61b31e523d81914d9eb177529783c29788d486139e1f3d29cbe4d2f881c61f74ff32a9233134ec69f26082e8aaa0c0e99006a5666c24fccfd195796a0be97cecb257259a640641f8c2d58d2d94452ec00ad84078afc1f7f72f3b9e8210b5db73bf70cd13ef172ef3b233c987d5ec7ea12a4d4921a43fb670c9f48aaae9e1d48ec7be58638a8b2f89a62b56775deddbbc971803316470ee416d8a6c0c8d17982396f6c0c0eeec425d5c599fb60b5c39f8e9ceff4ee25c5bc953178972de616edae61586bb868e463f420e9e09c083662bcf6f0f522f78630792e02e6986f5dd042dfb70100ab59d8a01093b3d89949ea19fe9c596a8681e2a71abe75debd62b985d03d488442aa41cc8993eff0224de62221d39be8bf1d8b26f8f8768e90e5b4b886adaf02a19f55e6d1fd11b004d4e7b170c4f7feaa04b8dad207d6f863d50a251d9a9ce66951de41a3690fec6144e73428d4718cc7ec5eeeff841b4329a7ba51624f678557b6eafc55af026314cbf9dd9ca232977da3cce204899f3048101e0010f42d0076cd494526beea862c72ee48749ba071bcdd1a96c64a0d8f48c6acad7730121021be6323f69505aad8fb6281b7ac4a607d1d241f1fbffc70c4a74c997bb2fb77c452c0077efdea2a6c00704a8bee28326b5e554e1faa48a33963ce2c2e0e2446b4504a05d541bbaf531e1644ad92a2feae5b2eb8851b067e7bd8d7d23d82e63d368983ba44f52901cba7e05cfa35e832ec445a7de50eca670fa90:p@ssw0rdadmin
```

Answer: `p@ssw0rdadmin`

# Skills Assessment

## Question 5

### "What is the cleartext password value for the MS Cache 2 hash?"

Students first need to determine the `Hashcat` hashmode for `MS Cache 2`, which is 2100:

Code: shell

```shell
hashcat --example | grep "MS Cache 2" -B 2
```

```
┌─[us-academy-1]─[10.10.14.41]─[htb-ac413848@htb-lqivvrhgqk]─[~]
└──╼ [★]$ hashcat --example | grep "MS Cache 2" -B 2

MODE: 2100
TYPE: Domain Cached Credentials 2 (DCC2), MS Cache 2
```

Subsequently, students need to crack the hash with `Hashcat`, finding the cleartext password `welcome1`:

Code: shell

```shell
hashcat -w 3 -O -m 2100 '$DCC2$10240#backup_admin#62dabbde52af53c75f37df260af1008e' /usr/share/wordlists/rockyou.txt
```

```
┌─[us-academy-1]─[10.10.14.41]─[htb-ac413848@htb-lqivvrhgqk]─[~]
└──╼ [★]$ hashcat -w 3 -O -m 2100 '$DCC2$10240#backup_admin#62dabbde52af53c75f37df260af1008e' /usr/share/wordlists/rockyou.txt

hashcat (v6.1.1) starting...

<SNIP>

$DCC2$10240#backup_admin#62dabbde52af53c75f37df260af1008e:welcome1

<SNIP>
```

Answer: `welcome1`

# Skills Assessment

## Question 6

### "After cracking the NTLM password hashes contained in the NTDS.dit file, perform an analysis of the results and find out the MOST common password in the INLANEFREIGHT.LOCAL domain."

Students first need to download [Hashcat\_NTDS.zip](https://academy.hackthebox.com/storage/modules/20/Hashcat_NTDS.zip) and unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/20/Hashcat_NTDS.zip && unzip Hashcat_NTDS.zip
```

```
┌─[us-academy-1]─[10.10.14.41]─[htb-ac413848@htb-lqivvrhgqk]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/20/Hashcat_NTDS.zip && unzip Hashcat_NTDS.zip

--2022-11-29 02:15:57--  https://academy.hackthebox.com/storage/modules/20/Hashcat_NTDS.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 30715 (30K) [application/zip]
Saving to: ‘Hashcat_NTDS.zip’

Hashcat_NTDS.zip                        100%[=============================================================================>]  30.00K  --.-KB/s    in 0.001s  

2022-11-29 02:15:57 (53.1 MB/s) - ‘Hashcat_NTDS.zip’ saved [30715/30715]

Archive:  Hashcat_NTDS.zip
  inflating: DC01.inlanefreight.local.ntds 
```

Then, students need to determine the `Hashcat` hashmode for `NTLM` hashes, which is 1000:

Code: shell

```shell
hashcat --example | grep "NTLM" -B 2 -m 1
```

```
┌─[us-academy-1]─[10.10.14.41]─[htb-ac413848@htb-lqivvrhgqk]─[~]
└──╼ [★]$ hashcat --example | grep "NTLM" -B 2 -m 1

MODE: 1000
TYPE: NTLM
```

Subsequently, students need to crack the hashes within `DC01.inlanefreight.local.ntds` using `Hashcat`:

```shell
hashcat -w 3 -O -m 1000 DC01.inlanefreight.local.ntds /usr/share/wordlists/rockyou.txt
```
```
┌─[us-academy-1]─[10.10.14.41]─[htb-ac413848@htb-lqivvrhgqk]─[~]
└──╼ [★]$ hashcat -w 3 -O -m 1000 DC01.inlanefreight.local.ntds /usr/share/wordlists/rockyou.txt

hashcat (v6.1.1) starting..

<SNIP>

328727b81ca05805a68ef26acb252039:1234567         
c52abb1e14677d7ea228fcc1171ed7b7:daniel          
5835048ce94ad0564e29a924a03510ef:password1       
94ebf4c21e29d139fd332a535626ad6e:sebastian       
cd401a40ae92face50b8e4fe1911060e:blink182
```

Once `Hashcat` has finished, students need to do terminal-fu to determine the most common password in the `inlanefreight.local` domain, finding it to be `freight1`:

```shell
hashcat -m 1000 DC01.inlanefreight.local.ntds --show --username | cut -f3 -d":" | sort -n | uniq -c | sort -n | tail -1
```
```
┌─[us-academy-1]─[10.10.14.41]─[htb-ac413848@htb-lqivvrhgqk]─[~]
└──╼ [★]$ hashcat -m 1000 DC01.inlanefreight.local.ntds --show --username | cut -f3 -d":" | sort -n | uniq -c | sort -n | tail -1

     43 freight1
```

Answer: `freight1`