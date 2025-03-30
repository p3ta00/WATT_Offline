| Section | Question Number | Answer |
| --- | --- | --- |
| Intercepting Web Requests | Question 1 | HTB{1n73rc3p73d\_1n\_7h3\_m1ddl3} |
| Repeating Requests | Question 1 | HTB{qu1ckly\_r3p3471n6\_r3qu3575} |
| Encoding/Decoding | Question 1 | HTB{3nc0d1n6\_n1nj4} |
| Proxying Tools | Question 1 | msf test file |
| Burp Intruder | Question 1 | HTB{burp\_1n7rud3r\_fuzz3r!} |
| ZAP Fuzzer | Question 1 | HTB{fuzz1n6\_my\_f1r57\_c00k13} |
| ZAP Scanner | Question 1 | HTB{5c4nn3r5\_f1nd\_vuln5\_w3\_m155} |
| Skills Assessment - Using Web Proxies | Question 1 | HTB{d154bl3d\_bu770n5\_w0n7\_570p\_m3} |
| Skills Assessment - Using Web Proxies | Question 2 | 3dac93b8cd250aa8c1a36fffc79a17a |
| Skills Assessment - Using Web Proxies | Question 3 | HTB{burp\_1n7rud3r\_n1nj4!} |
| Skills Assessment - Using Web Proxies | Question 4 | CFIDE |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Intercepting Web Requests

## Question 1

### "Try intercepting the ping request on the server shown above, and change the post data similarly to what we did in this section. Change the command read flag.txt"

After spawning the target machine and navigating to its websites's root page, students need to run either `Burp Suite` or `ZAP` (`Burp Suite` will be used for this question; students also need to make sure that `FoxyProxy` is set to the preconfigured option "Burp (8080)" in `Firefox`), and then provide any number (such as 1) in the IP field and click on "Ping":

![[HTB Solutions/CPTS/z. images/44c5e6ad156160f46aa5cdd38303d2e4_MD5.jpg]]

Students then need to open `Burp Suite` and send the intercepted `POST` request to the endpoint `/ping` to `Repeater` (`Ctrl + R`):

![[HTB Solutions/CPTS/z. images/3ecee672469f99c3cdcc8305118b70fb_MD5.jpg]]

Then, students need to change the value of the `ip` parameter to be `;cat flag.txt` instead of the value they supplied from the front end and URL-encode it by highlighting it and clicking/pressing `Ctrl + U`:

Code: shell

```shell
ip=%3bcat+flag.txt
```

![[HTB Solutions/CPTS/z. images/0c488f1353e435ca51fa73d9c6ae3bc7_MD5.jpg]]

At last, students need to send the modified request to attain the flag `HTB{1n73rc3p73d_1n_7h3_m1ddl3}` in the response:

![[HTB Solutions/CPTS/z. images/d3a8d63f2cd24ee2cdd91486b55629b7_MD5.jpg]]

Answer: `HTB{1n73rc3p73d_1n_7h3_m1ddl3}`

# Repeating Requests

## Question 1

### "Try using request repeating to be able to quickly test commands. With that, try looking for the other flag"

After spawning the target machine and navigating to its website's root page, students need to run either `Burp Suite` or `ZAP` (`Burp Suite` will be used for this question; students also need to make sure that `FoxyProxy` is set to the preconfigured option "Burp (8080)" in `Firefox`), and then provide any number (such as 1) in the IP field and click on "Ping":

![[HTB Solutions/CPTS/z. images/cbce2c09b67de001617832a717cb8ee2_MD5.jpg]]

Students then need to open `Burp Suite` and send the intercepted `POST` request to `/ping` to `Repeater` (`Ctrl + R`):

![[HTB Solutions/CPTS/z. images/3f4d8a5c9f2166ee3a342104fb185118_MD5.jpg]]

Then, students need to use the `ls` command after the semi-colon and perform a path traversal to list the contents of the root directory:

Code: shell

```shell
ip=;ls+../../../
```

![[HTB Solutions/CPTS/z. images/0f7ce12a3860a11f76e13433cdfc817e_MD5.jpg]]

From the response, students will notice that the flag file "flag.txt" exists in the root directory; therefore, they need to use `cat` to print out its contents, finding it to be `HTB{qu1ckly_r3p3471n6_r3qu3575}`:

Code: shell

```shell
ip=;cat /flag.txt
```

![[HTB Solutions/CPTS/z. images/47d11c691bce98b61103101b24a3b3a7_MD5.jpg]]

Answer: `HTB{qu1ckly_r3p3471n6_r3qu3575}`

# Encoding/Decoding

## Question 1

### "The string found in the attached file has been encoded several times with various encoders. Try to use the decoding tools we discussed to decode it and get the flag."

Students first need to download the file [encoded\_flag.zip](https://academy.hackthebox.com/storage/modules/110/encoded_flag.zip), unzip it, and print out the encoded flag:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/110/encoded_flag.zip
unzip encoded_flag.zip
cat encoded_flag.txt
```

```
┌─[us-academy-1]─[10.10.14.76]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/110/encoded_flag.zip

--2022-07-19 04:21:28--  https://academy.hackthebox.com/storage/modules/110/encoded_flag.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 340 [application/zip]
Saving to: ‘encoded_flag.zip’

encoded_flag.zip    100%[===================>]     340  --.-KB/s    in 0s      

2022-07-19 04:21:28 (6.26 MB/s) - ‘encoded_flag.zip’ saved [340/340]

┌─[us-academy-1]─[10.10.14.76]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ unzip encoded_flag.zip 
Archive:  encoded_flag.zip
  inflating: encoded_flag.txt
┌─[us-academy-1]─[10.10.14.76]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ cat encoded_flag.txt

VTJ4U1VrNUZjRlZXVkVKTFZrWkdOVk5zVW10aFZYQlZWRmh3UzFaR2NITlRiRkphWld0d1ZWUllaRXRXUm10M1UyeFNUbVZGY0ZWWGJYaExWa1V3ZVZOc1VsZGlWWEJWVjIxNFMxWkZNVFJUYkZKaFlrVndWVmR0YUV0V1JUQjNVMnhTYTJGM1BUMD0=
```

Students will notice that the flag ends in `=`, thus, it is most probably base64-encoded. Therefore, students need to copy the encoded flag and paste it into `Burp Suite`'s `Decoder` and decode it as Base64:

![[HTB Solutions/CPTS/z. images/b6d390c92d361f6d38fa63440ecee0ad_MD5.jpg]]

Subsequently, students will also notice that the decoded string is also base64-encoded:

![[HTB Solutions/CPTS/z. images/8449f5613992ba31633a945d4b0f4a5d_MD5.jpg]]

Therefore, students will need to perform base64 decoding on the encoded string four times, and at last, they will find a URL-encoded string:

![[HTB Solutions/CPTS/z. images/d4c930c12078c42ca94feea18fd67e6d_MD5.jpg]]

Thus, students need to decode the string as a URL-encoded string to attain the flag `HTB{3nc0d1n6_n1nj4}`:

![[HTB Solutions/CPTS/z. images/4b6ce535df990078e53e79a46a36ad8f_MD5.jpg]]

Answer: `HTB{3nc0d1n6_n1nj4}`

# Proxying Tools

## Question 1

### "Try running 'auxiliary/scanner/http/http\_put' in metasploit on any website, while having the traffic routed through Burp. Once you view the requests sent, what is the last line in the request?"

Students first need to launch `msfconsole` and use the `auxiliary/scanner/http/http_put` module:

Code: shell

```shell
msfconsole -q
use auxiliary/scanner/http/http_put
```

```
┌─[us-academy-1]─[10.10.14.76]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ msfconsole -q

msf6 > use auxiliary/scanner/http/http_put 
msf6 auxiliary(scanner/http/http_put) >
```

Subsequently, students need to set the `PROXIES`, `RHOSTS`, and `RPORT` options, making sure that `PROXIES` is set to the same IP and port that `Burp Suite` listens on (the defaults being `127.0.0.1:8080`), while for the other two options, any actual website's IP address and port 443 would suffice:

Code: shell

```shell
set PROXIES HTTP:127.0.0.1:8080
set RHOSTS STMIP
set RPORT 443
```

```
msf6 auxiliary(scanner/http/http_put) > set PROXIES HTTP:127.0.0.1:8080

PROXIES => HTTP:127.0.0.1:8080
msf6 auxiliary(scanner/http/http_put) > set RHOSTS 104.18.20.126

RHOSTS => 104.18.20.126
msf6 auxiliary(scanner/http/http_put) > set RPORT 443

RPORT => 443
```

Students now need to open `Burp Suite` and make sure that the proxy is intercepting requests and then run the `msfconsole` module with the `run` or `exploit` command:

Code: shell

```shell
run
```

```
msf6 auxiliary(scanner/http/http_put) > run
```

Afterward, students will notice that `Burp Suite` has intercepted the `msfconsole` request sent, and the last line in the request is on line 8, `msf test file`:

![[HTB Solutions/CPTS/z. images/91944389bd0bd96ed8aa967814cb1791_MD5.jpg]]

Answer: `msf test file`

# Burp Intruder

## Question 1

### "Use Burp Intruder to fuzz for '.html' files under the /admin directory, to find a file containing the flag."

After spawning the target machine, students need to run `Burp Suite`, make sure that `FoxyProxy` is set to the preconfigured option "Burp (8080)" in `Firefox`, and then navigate to the `/admin/` directory to capture the request in `Burp Suite`:

![[HTB Solutions/CPTS/z. images/7baec72fd085192cef2dae38bc1ba460_MD5.jpg]]

Students then need to send the intercepted request to `Intruder` by pressing `Ctrl + I`, and set the first line of the request in the `Position` tab to:

Code: shell

```shell
GET /admin/§FILE§.html HTTP/1.1
```

![[HTB Solutions/CPTS/z. images/d6fc2e53b81acf8510a0ae1362bca619_MD5.jpg]]

Subsequently, students need to move to the `Payloads` tab and load the wordlist `/opt/useful/SecLists/Discovery/Web-Content/common.txt`:

![[HTB Solutions/CPTS/z. images/869cef3687869e8ddd5b5cc7fe2710f8_MD5.jpg]]

At last, students need to click on `Start Attack` and wait for a bit until a request with the 200 status appears, in which they will find the flag `HTB{burp_1n7rud3r_fuzz3r!}` within its response:

![[HTB Solutions/CPTS/z. images/86ea30af568d843c8f1a36113a40cdbb_MD5.jpg]]

Answer: `HTB{burp_1n7rud3r_fuzz3r!}`

# ZAP Fuzzer

## Question 1

### "The directory we found above sets the cookie to the md5 hash of the username, as we can see the md5 cookie in the request for the (guest) user. Visit '/skills/' to get a request with a cookie, then try to use ZAP Fuzzer to fuzz the cookie for different md5 hashed usernames to get the flag. (You may use the wordlist: /opt/useful/SecLists/Usernames/top-usernames-shortlist.txt)"

After spawning the target machine, students need to navigate to the `/skills/` directory, run `ZAP`, make sure that `FoxyProxy` is set to the preconfigured option "Burp (8080)" in `Firefox`, refresh the page on `/skills/` to capture the request in `ZAP` and view the cookie within the request:

![[HTB Solutions/CPTS/z. images/4d98840edab2d3c2cca7c9569539aefa_MD5.jpg]]

Students need to right-click on the request and select `Attack` -> `Fuzz`:

![[HTB Solutions/CPTS/z. images/0b0fc0b8c300d72cd4ab5847051f9cbb_MD5.jpg]]

Afterward, students need to select the value after `cookie=` and click on `Add` -> `Add`:

![[HTB Solutions/CPTS/z. images/86943cc2dff82eb4e47aabdf20616181_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/c5b0c637128202b4996dfbb2e7e33f23_MD5.jpg]]

Subsequently, students need to choose `File` for `Type` and load the `/opt/useful/SecLists/Usernames/top-usernames-shortlist.txt` wordlist after clicking on `Select`:

![[HTB Solutions/CPTS/z. images/b72d069afee5694dc20314307cc7b690_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/1af6349d7b4bb72cc681686d70af6500_MD5.jpg]]

After the wordlist is loaded, students need to click on `Add`:

![[HTB Solutions/CPTS/z. images/0ee81ea810ccf069d39b0d18a455d904_MD5.jpg]]

Subsequently, students need to click on `Processors`:

![[HTB Solutions/CPTS/z. images/a48df804711eaef29ccca4d0f76d8089_MD5.jpg]]

And then click on `Add`:

![[HTB Solutions/CPTS/z. images/42271ae4fb8fe6c46736c7ad34307e41_MD5.jpg]]

For `Type`, students need to choose `MD5 Hash` and then click on `Add`:

![[HTB Solutions/CPTS/z. images/2512797e1aaf3deaf13fcaccc40bed57_MD5.jpg]]

After clicking on the two subsequent `OK` buttons, students need to click on `Start Fuzzer`:

![[HTB Solutions/CPTS/z. images/2b130ab3cde195996e0d022b1d5a5112_MD5.jpg]]

After fuzzing has finished, students need to sort the responses by body size and will find that one of the responses has a response size of 450 bytes; viewing the response body will reveal the flag `HTB{fuzz1n6_my_f1r57_c00k13}`:

![[HTB Solutions/CPTS/z. images/3eb28351c41eaece5ffb1f98be7c76ad_MD5.jpg]]

Answer: `HTB{fuzz1n6_my_f1r57_c00k13}`

# ZAP Scanner

## Question 1

### "Run ZAP Scanner on the exercise above to identify directories and potential vulnerabilities. Once you find the high-level vulnerability, try to use it to read the flag at '/flag.txt'"

After spawning the target machine, students need to run `ZAP`, make sure that `FoxyProxy` is set to the preconfigured option "Burp (8080)" in `Firefox`, and capture a request to the machine's website root page by navigating to it:

![[HTB Solutions/CPTS/z. images/8d20ed9e997e3bcb2f240bb62032f568_MD5.jpg]]

Then, students need to right-click on the request and select `Attack` -> `Spider`:

![[HTB Solutions/CPTS/z. images/6c3a2e715aba9685fb72978712c19540_MD5.jpg]]

Students can keep the default configurations as is and click on `Start Scan`:

![[HTB Solutions/CPTS/z. images/e1278593299fa11ed503fa75c36a9cba_MD5.jpg]]

Once the scan has finished, students need to click on the website's folder and click on `Attack` -> `Active Scan`:

![[HTB Solutions/CPTS/z. images/66200bddfc386e0388d94e1247601d98_MD5.jpg]]

Students can keep the default configurations as is and click on `Start Scan`:

![[HTB Solutions/CPTS/z. images/f1019676b427bf2e1fda15591ff1fbad_MD5.jpg]]

Students need not to wait until the scan finishes completely, instead, once they see 1 for the `High Priority Alerts` flag, they need to click on `Alerts`:

![[HTB Solutions/CPTS/z. images/d3169f5f5d7ccf8b573f4be55b1c9368_MD5.jpg]]

Subsequently, students will find that the vulnerability is a `Remote OS Command Injection`:

![[HTB Solutions/CPTS/z. images/b43e9ecbee9254841f3003347f32ee33_MD5.jpg]]

Then, students need to right-click on the `GET` request under `Remote OS Command Injection` and click on `Open/Resend with Request Editor...`:

![[HTB Solutions/CPTS/z. images/4d261368db707cdf25bd648cb96677c1_MD5.jpg]]

The payload used for the original request prints out the contents of the `/etc/passwd` file:

![[HTB Solutions/CPTS/z. images/292fd224cdf7c9abce6e4a6ff66fc543_MD5.jpg]]

However, students need to change the payload so that it prints out the contents of the flag file "flag.txt", making sure that the whitespace is URL-encoded:

Code: shell

```shell
;cat%20/flag.txt
```

![[HTB Solutions/CPTS/z. images/e809f251f7866f473e0299d117ffbf2f_MD5.jpg]]

After clicking on `Send`, students will find the flag `HTB{5c4nn3r5_f1nd_vuln5_w3_m155}` within the response:

![[HTB Solutions/CPTS/z. images/0f3ad394a0199a994df946af65e93a7f_MD5.jpg]]

Answer: `HTB{5c4nn3r5_f1nd_vuln5_w3_m155}`

# Skills Assessment - Using Web Proxies

## Question 1

### "The /lucky.php page has a button that appears to be disabled. Try to enable the button, and then click it to get the flag."

After spawning the target machine, students need to navigate to its website's `/lucky.php` page and notice that the "Click for a chance to win a flag!" button is disabled:

![[HTB Solutions/CPTS/z. images/85905543b3210adf8da6a6db25110847_MD5.jpg]]

Therefore, students need to run `ZAP` (`Burp Suite` can also be used), make sure that `FoxyProxy` is set to the preconfigured option "Burp (8080)" in `Firefox`, and refresh the page on `/lucky.php` to capture the request in `ZAP`. When viewing the response for the `GET` response sent to `/lucky.php`, students will notice that the button has the attribute `disabled`:

![[HTB Solutions/CPTS/z. images/067d906c8be6dbbe3e6c2e9a68f32604_MD5.jpg]]

Therefore, students need to open `Replacer` by clicking `Ctrl + R` and then `Add...`:

![[HTB Solutions/CPTS/z. images/f3a8080d7a27526270027451976e8084_MD5.jpg]]

Subsequently, students need to set `Match Type` to `Response Body String`, `Match String` to `disabled>`, `Replacement String` to `>`, check `Enable`, and click on `Save`:

![[HTB Solutions/CPTS/z. images/eb29358992872ce11f2de292d2afa10a_MD5.jpg]]

Then, students need to select the `GET` request and click on `Open/Resend with Request Editor...`:

![[HTB Solutions/CPTS/z. images/79bcea2d16fc38ffdd2326e5d62e2c79_MD5.jpg]]

For easier usability, students can click on `Combined display for header and body`, `Request shown above Response` for the `Request` tab, and `Combined display for header and body` for the `Response` tab:

![[HTB Solutions/CPTS/z. images/be10fb052baec01a13e536d6af80bd77_MD5.jpg]]

Thereafter, after clicking `Send`, students will notice that the response body no longer contains `disabled`:

![[HTB Solutions/CPTS/z. images/0474ba6e939374f66dfb1b8a361a9a06_MD5.jpg]]

Thus, students now need to right-click on the response and choose `Open URL in System Browser`, to notice that they can click the button as it is not disabled anymore (in case it is, it might be from cached pages, thus, students can press `Ctrl + Shift + R` to force refresh the page):

![[HTB Solutions/CPTS/z. images/dad97a2dc993852b69195b6b16913eff_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/1873e667c9cad0399d86ab47c6d9a0eb_MD5.jpg]]

After clicking on the button around 8 times, students will attain the flag `HTB{d154bl3d_bu770n5_w0n7_570p_m3}`:

![[HTB Solutions/CPTS/z. images/965e33e5c83fb7ca0b74d3f524d781c0_MD5.jpg]]

Answer: `HTB{d154bl3d_bu770n5_w0n7_570p_m3}`

# Skills Assessment - Using Web Proxies

## Question 2

### "The /admin.php page uses a cookie that has been encoded multiple time. Try to decode the cookie until you get a value with 31-characters. Submit the value as the answer."

After spawning the target machine, students need to run `ZAP` (`Burp Suite` can also be used), make sure that `FoxyProxy` is set to the preconfigured option "Burp (8080)" in `Firefox`, and navigate to `/admin.php` to capture the request in `ZAP` and notice the cookie value within the `Cookie` header:

![[HTB Solutions/CPTS/z. images/bf706d750b8a9e6cb6c716c40cafe462_MD5.jpg]]

Students need to select the hash after `cookie=`, right-click and select `Encode/Decode/Hash...`:

![[HTB Solutions/CPTS/z. images/bb50dff21c244a9698a3da6c2480e6cf_MD5.jpg]]

Then, students need to click on the `Decode` tab and copy the `ASCII Hex Decode` value then paste it in the `Text to be encoded/decode/hashed`. The `Base64 Decode` will contain the 31-characters value `3dac93b8cd250aa8c1a36fffc79a17a`::

![[HTB Solutions/CPTS/z. images/e41c3b5980666ddb63789cf5e69c9d52_MD5.jpg]]

Answer: `3dac93b8cd250aa8c1a36fffc79a17a`

# Skills Assessment - Using Web Proxies

## Question 3

### "Once you decode the cookie, you will notice that it is only 31 characters long, which appears to be an md5 hash missing its last character. So, try to fuzz the last character of the decoded md5 cookie with all alpha-numeric characters, while encoding each request with the encoding methods you identified above. (You may use the "alphanum-case.txt" wordlist from SecLists for the payload)"

After spawning the target machine, students need to run `Burp Suite` (`ZAP` can also be used, however, it is more involved as it lacks an `ASCII-Hex` fuzzer processor, meaning that students are required to create a script for it manually), make sure that `FoxyProxy` is set to the preconfigured option "Burp (8080)" in `Firefox`, and navigate to `/admin.php` to capture the request in `Burp Suite` and notice the cookie value within the `Cookie` header. Students need to right-click on it and select `Send to Intruder`:

![[HTB Solutions/CPTS/z. images/4e920e8d5fddd4a2595763606a725e64_MD5.jpg]]

Within `Intruder`, students first need to click on `Clear §`, replace the default cookie with the `MD5` hash `3dac93b8cd250aa8c1a36fffc79a17a` attained in the previous question, select it, and click on `Add §`:

![[HTB Solutions/CPTS/z. images/daa9192ac21cc415423c1922b11a1c17_MD5.jpg]]

Subsequently, students need to click on the `Payloads` tab then on `Load ...` under `Payload Options` and load the file `alphanum-case.txt` from `/opt/useful/SecLists/Fuzzing/`:

![[HTB Solutions/CPTS/z. images/ec052da23a66313d52c600a8aed76c06_MD5.jpg]]

Then, under `Payload Processing`, students need to click on `Add`, select `Add prefix` as the processing rule, and paste in the `MD5` hash `3dac93b8cd250aa8c1a36fffc79a17a` for `Prefix`:

![[HTB Solutions/CPTS/z. images/2146bab55b7225c4c25b6e929af4777f_MD5.jpg]]

Additionally, students need to add the `Base64-encode` and `Encode as ASCII hex` processing rules:

![[HTB Solutions/CPTS/z. images/4dfcaefd3bff044101ce390792ee7c67_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/b9dfb0dfeb36abd349a246083e8c30f0_MD5.jpg]]

Thereafter, students need to click on `Start attack`:

![[HTB Solutions/CPTS/z. images/a6c4a6530598127c3d05cfb96a527184_MD5.jpg]]

After fuzzing has completed, students can click on the `Length` column to sort by response size, and any response with the size of 1248 will contain the flag `HTB{burp_1n7rud3r_n1nj4!}` on line 42 in the response body:

![[HTB Solutions/CPTS/z. images/5d245a5af274e6c6a8437c40f76b4335_MD5.jpg]]

Answer: `HTB{burp_1n7rud3r_n1nj4!}`

# Skills Assessment - Using Web Proxies

## Question 4

### "You are using the 'auxiliary/scanner/http/coldfusion\_locale\_traversal' tool within Metasploit, but it is not working properly for you. You decide to capture the request sent by Metasploit so you can manually verify it and repeat it. Once you capture the request, what is the 'XXXXX' directory being called in '/XXXXX/administrator/..'?"

Students first need to launch `msfconsole`:

Code: shell

```shell
msfconsole -q
```

```
┌─[eu-academy-1]─[10.10.14.153]─[htb-ac413848@htb-xx2fcfymke]─[~]
└──╼ [★]$ msfconsole -q

[msf](Jobs:0 Agents:0) >>
```

Subsequently, students need to use the module `auxiliary/scanner/http/coldfusion_locale_traversal`:

Code: shell

```shell
use auxiliary/scanner/http/coldfusion_locale_traversal
```

```
[msf](Jobs:0 Agents:0) >> use auxiliary/scanner/http/coldfusion_locale_traversal
[msf](Jobs:0 Agents:0) auxiliary(scanner/http/coldfusion_locale_traversal) >>
```

Then students need to set `PROXIES` to be the same as the one `Burp Suite`/`ZAP` listens on, while for `RHOST` and `RPORT` any random valid values can be used:

Code: shell

```shell
set PROXIES HTTP:127.0.0.1:8080
set RHOST STMIP
set RPORT STMPO
```

```
[msf](Jobs:0 Agents:0) auxiliary(scanner/http/coldfusion_locale_traversal) >> set PROXIES HTTP:127.0.0.1:8080

PROXIES => HTTP:127.0.0.1:8080
[msf](Jobs:0 Agents:0) auxiliary(scanner/http/coldfusion_locale_traversal) >> set RHOSTS 159.65.63.151
RHOSTS => 159.65.63.151
[msf](Jobs:0 Agents:0) auxiliary(scanner/http/coldfusion_locale_traversal) >> set RPORT 31845
RPORT => 31845
```

Before running the exploit, students need to make sure that `Burp Suite`/`ZAP` are intercepting requests, and then run the exploit:

Code: shell

```shell
run
```

```
auxiliary(scanner/http/coldfusion_locale_traversal) >> run
```

From the intercepted request, students will know that the directory the `msfconsole` module is sending a request to is `CFIDE`:

![[HTB Solutions/CPTS/z. images/2bc110c72c96b2e075eb228353c4b460_MD5.jpg]]

Answer: `CFIDE`