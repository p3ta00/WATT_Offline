
| Section                            | Question Number | Answer                              |
| ---------------------------------- | --------------- | ----------------------------------- |
| Directory and File Fuzzing         | Question 1      | HTB{w3b\_f1l3\_fuzz1ng\_fl4g}       |
| Recursive Fuzzing                  | Question 1      | HTB{d33p3r\_d1rector1es\_ar3\_c00l} |
| Parameter and Value Fuzzing        | Question 1      | HTB{g3t\_fuzz1ng\_succ3ss}          |
| Parameter and Value Fuzzing        | Question 2      | HTB{p0st\_fuzz1ng\_succ3ss}         |
| Virtual Host and Subdomain Fuzzing | Question 1      | web-beans.inlanefreight.htb         |
| Virtual Host and Subdomain Fuzzing | Question 2      | support.inlanefreight.com           |
| Validating Findings                | Question 1      | Content-Length: 210                 |
| API Fuzzing                        | Question 1      | h1dd3n\_r357                        |
| Skills Assessment                  | Question 1      | HTB{w3b\_fuzz1ng\_sk1lls}           |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Directory and File Fuzzing

## Question 1

### "Within the "webfuzzing\_hidden\_path" path on the target system (ie http://IP:PORT/webfuzzing\_hidden\_path/), fuzz for folders and then files to find the flag."

After spawning the target, students will open the terminal and use `ffuf` to perform a recursive directory and file fuzzing using the `common.txt` wordlist while specifying `.php`, `.html`, and `.txt` as file extensions:

Code: shell

```shell
ffuf -u http://STMIP:STMPO/webfuzzing_hidden_path/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -recursion -e .php,.txt,.html
```

```
┌─[eu-academy-6]─[10.10.14.52]─[htb-ac-8414@htb-wi667lwl7u]─[~]
└──╼ [★]$ ffuf -u http://94.237.59.193:45848/webfuzzing_hidden_path/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -recursion -e .php,.txt,.html

<SNIP>

 :: Method           : GET
 :: URL              : http://94.237.59.193:45848/webfuzzing_hidden_path/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Extensions       : .php .txt .html 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

flag                    [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 16ms]
[INFO] Adding a new job to the queue: http://94.237.59.193:45848/webfuzzing_hidden_path/flag/FUZZ

[INFO] Starting queued job on target: http://94.237.59.193:45848/webfuzzing_hidden_path/flag/FUZZ

flag.html               [Status: 200, Size: 100, Words: 2, Lines: 2, Duration: 16ms]
index.html              [Status: 200, Size: 104, Words: 6, Lines: 2, Duration: 16ms]
index.html              [Status: 200, Size: 104, Words: 6, Lines: 2, Duration: 15ms]
```

Students will send a request to the `/webfuzzing_hidden_path/flag/flag.html` using `cURL` to attain the flag in the `h1` HTML tag of the response:

Code: shell

```shell
curl http://STMIP:STMPO/webfuzzing_hidden_path/flag/flag.html
```

```
┌─[eu-academy-6]─[10.10.14.52]─[htb-ac-8414@htb-wi667lwl7u]─[~]
└──╼ [★]$ curl http://94.237.59.193:45848/webfuzzing_hidden_path/flag/flag.html

<html><head><title>Index page</title></head><body><h1>{hidden}</h1></body></html>
```

Answer: `HTB{w3b_f1l3_fuzz1ng_fl4g}`

# Recursive Fuzzing

## Question 1

### "Recursively fuzz the "recursive\_fuzz" path on the target system (ie http://IP:PORT/recursive\_fuzz/) to find the flag."

After spawning the target, students will open the terminal and use `ffuf` to perform a recursive directory and file fuzzing using the `directory-list-2.3-medium.txt` wordlist while specifying `.php`, `.html`, and `.txt` as file extensions:

Code: shell

```shell
ffuf -u http://STMIP:STMPO/recursive_fuzz/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -recursion -e .php,.txt,.html -ic -t 80
```

```
┌─[eu-academy-6]─[10.10.14.52]─[htb-ac-8414@htb-wi667lwl7u]─[~]
└──╼ [★]$ ffuf -u http://94.237.59.63:30128/recursive_fuzz/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -recursion -e .html -ic -t 80

<SNIP>

:: Method           : GET
 :: URL              : http://94.237.59.63:30128/recursive_fuzz/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .html 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 80
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 403, Size: 158, Words: 17, Lines: 11, Duration: 16ms]
level1                  [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 16ms]
[INFO] Adding a new job to the queue: http://94.237.59.63:30128/recursive_fuzz/level1/FUZZ

                        [Status: 403, Size: 158, Words: 17, Lines: 11, Duration: 16ms]
[INFO] Starting queued job on target: http://94.237.59.63:30128/recursive_fuzz/level1/FUZZ

index.html              [Status: 200, Size: 111, Words: 8, Lines: 2, Duration: 16ms]
                        [Status: 200, Size: 111, Words: 8, Lines: 2, Duration: 16ms]
level2                  [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 16ms]
[INFO] Adding a new job to the queue: http://94.237.59.63:30128/recursive_fuzz/level1/level2/FUZZ

                        [Status: 200, Size: 111, Words: 8, Lines: 2, Duration: 16ms]
[INFO] Starting queued job on target: http://94.237.59.63:30128/recursive_fuzz/level1/level2/FUZZ

index.html              [Status: 200, Size: 111, Words: 8, Lines: 2, Duration: 16ms]
                        [Status: 200, Size: 111, Words: 8, Lines: 2, Duration: 16ms]
level3                  [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 16ms]
[INFO] Adding a new job to the queue: http://94.237.59.63:30128/recursive_fuzz/level1/level2/level3/FUZZ

                        [Status: 200, Size: 111, Words: 8, Lines: 2, Duration: 16ms]
[INFO] Starting queued job on target: http://94.237.59.63:30128/recursive_fuzz/level1/level2/level3/FUZZ

                        [Status: 200, Size: 111, Words: 8, Lines: 2, Duration: 17ms]
index.html              [Status: 200, Size: 111, Words: 8, Lines: 2, Duration: 17ms]
threatcon_level2        [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 16ms]
[INFO] Adding a new job to the queue: http://94.237.59.63:30128/recursive_fuzz/level1/level2/level3/threatcon_level2/FUZZ

                        [Status: 200, Size: 111, Words: 8, Lines: 2, Duration: 16ms]
[INFO] Starting queued job on target: http://94.237.59.63:30128/recursive_fuzz/level1/level2/level3/threatcon_level2/FUZZ

index.html              [Status: 200, Size: 146, Words: 10, Lines: 2, Duration: 17ms]
                        [Status: 200, Size: 146, Words: 10, Lines: 2, Duration: 17ms]
                        [Status: 200, Size: 146, Words: 10, Lines: 2, Duration: 16ms]
:: Progress: [441094/441094] :: Job [5/5] :: 5000 req/sec :: Duration: [0:01:30] :: Errors: 0 ::
```

Students will send a request to `/recursive_fuzz/level1/level2/level3/threatcon_level2/index.html` using `cURL` to attain the flag in the `h1` HTML tag of the response:

Code: shell

```shell
curl http://STMIP:STMPO/recursive_fuzz/level1/level2/level3/threatcon_level2/index.html
```

```
┌─[eu-academy-6]─[10.10.14.52]─[htb-ac-8414@htb-wi667lwl7u]─[~]
└──╼ [★]$ curl http://94.237.59.63:30128/recursive_fuzz/level1/level2/level3/threatcon_level2/index.html

<html><head><title>Level 4 Directory</title></head><body><h1>This is Recursive Fuzz Level 4 - {hidden}</h1></body></html>
```

Answer: `HTB{d33p3r_d1rector1es_ar3_c00l}`

# Parameter and Value Fuzzing

## Question 1

### "What flag do you find when successfully fuzzing the GET parameter?"

After spawning the target, students will install `wenum` and its requirements using `pipx`:

Code: shell

```shell
pipx install git+https://github.com/WebFuzzForge/wenum
pipx runpip wenum install setuptools
```

```
┌─[eu-academy-6]─[10.10.14.52]─[htb-ac-8414@htb-pfnixnd8ei]─[~]
└──╼ [★]$ pipx install git+https://github.com/WebFuzzForge/wenum
pipx runpip wenum install setuptools

  installed package wenum 0.1.0, installed using Python 3.11.2
  These apps are now globally available
    - wenum
done! ✨ 🌟 ✨
Requirement already satisfied: setuptools in ./.local/share/pipx/shared/lib/python3.11/site-packages (66.1.1)
```

Subsequently, students will use `wenum` to enumerate the `GET` parameter of the target using the `common.txt` wordlist targeting the `?x=` parameter from the section:

Code: shell

```shell
wenum -w /usr/share/seclists/Discovery/Web-Content/common.txt --hc 404 -u "http://STMIP:STMPO/get.php?x=FUZZ"
```

```
┌─[eu-academy-6]─[10.10.14.52]─[htb-ac-8414@htb-pfnixnd8ei]─[~]
└──╼ [★]$ wenum -w /usr/share/seclists/Discovery/Web-Content/common.txt --hc 404 -u "http://94.237.55.0:40813/get.php?x=FUZZ"

<SNIP>

 Code    Lines     Words        Size  Method   URL 
───────────────────────────────────────────────────── Response number 293: ──────────────────────────────────────────────────────
 200       1 L       1 W        25 B  GET      http://94.237.55.0:40813/get.php?x=OA_HTML 

Total time: 0:00:02
Processed Requests: 4724
Filtered Requests: 4723
Requests/s: 1622

<SNIP>
```

Students will send a request to `/get.php?x=OA_HTML` using `cURL` to attain the flag:

Code: shell

```shell
curl http://STMIP:STMPO/get.php?x=OA_HTML 
```

```
┌─[eu-academy-6]─[10.10.14.52]─[htb-ac-8414@htb-pfnixnd8ei]─[~]
└──╼ [★]$ curl http://94.237.55.0:40813/get.php?x=OA_HTML 

{hidden}
```

Answer: `HTB{g3t_fuzz1ng_succ3ss}`

# Parameter and Value Fuzzing

## Question 2

### "What flag do you find when successfully fuzzing the POST parameter?"

Students will reuse the previously spawned target and use `ffuf` to fuzz the `post.php` endpoint by configuring the tool to send `POST` requests, specifying the `Content-Type` to encode both the parameter `y` and its value with `application/x-www-form-urlencoded`, and specifying the `common.txt` wordlist:

Code: shell

```shell
ffuf -u http://STMIP:STMPO/post.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "y=FUZZ" -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200 -v
```

```
┌─[eu-academy-6]─[10.10.14.52]─[htb-ac-8414@htb-pfnixnd8ei]─[~]
└──╼ [★]$ ffuf -u http://94.237.55.0:40813/post.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "y=FUZZ" -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200 -v

<SNIP>
________________________________________________

 :: Method           : POST
 :: URL              : http://94.237.55.0:40813/post.php
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : y=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

[Status: 200, Size: 26, Words: 1, Lines: 2, Duration: 16ms]
| URL | http://94.237.55.0:40813/post.php
    * FUZZ: SUNWmc

:: Progress: [4723/4723] :: Job [1/1] :: 2409 req/sec :: Duration: [0:00:02] :: Errors: 0 ::
```

With the attained value of the `y` parameter students use `cURL` to send a request to the `post.php` endpoint to get the flag:

Code: shell

```shell
curl -d "y=SUNWmc" http://STMIP:STMPO/post.php
```

```
┌─[eu-academy-6]─[10.10.14.52]─[htb-ac-8414@htb-pfnixnd8ei]─[~]
└──╼ [★]$ curl -d "y=SUNWmc" http://94.237.55.0:40813/post.php

{hidden}
```

Answer: `HTB{p0st_fuzz1ng_succ3ss}`

# Virtual Host and Subdomain Fuzzing

## Question 1

### "Using GoBuster against the target system to fuzz for vhosts using the common.txt wordlist, which vhost starts with the prefix "web-"? Respond with the full vhost, eg web-123.inlanefreight.htb."

After spawning the target, students will add an entry to `inlanefreight.htb` to their `/etc/hosts` file:

Code: shell

```shell
echo "STMIP inlanefreight.htb" | sudo tee -a /etc/hosts
```

```
┌─[eu-academy-6]─[10.10.14.52]─[htb-ac-8414@htb-pfnixnd8ei]─[~]
└──╼ [★]$ echo "94.237.59.63 inlanefreight.htb" | sudo tee -a /etc/hosts

94.237.59.63 inlanefreight.htb
```

Subsequently, students will utilize `gobuster` with the `vhost` command to perform VHost enumeration against the target using the `common.txt` wordlist to obtain the answer:

Code: shell

```shell
gobuster vhost -u http://inlanefreight.htb:STMPO -w /usr/share/seclists/Discovery/Web-Content/common.txt --append-domain
```

```
┌─[eu-academy-6]─[10.10.14.52]─[htb-ac-8414@htb-pfnixnd8ei]─[~]
└──╼ [★]$ gobuster vhost -u http://inlanefreight.htb:44481 -w /usr/share/seclists/Discovery/Web-Content/common.txt --append-domain

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://inlanefreight.htb:44481
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/seclists/Discovery/Web-Content/common.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: ADMIN.inlanefreight.htb:44481 Status: 200 [Size: 100]
Found: Admin.inlanefreight.htb:44481 Status: 200 [Size: 100]
Found: admin.inlanefreight.htb:44481 Status: 200 [Size: 100]
Found: awmdata.inlanefreight.htb:44481 Status: 200 [Size: 104]
Found: ipdata.inlanefreight.htb:44481 Status: 200 [Size: 102]
Found: web-{hidden}.inlanefreight.htb:44481 Status: 200 [Size: 108]
Progress: 4723 / 4724 (99.98%)
===============================================================
Finished
===============================================================
```

Answer: `web-beans.inlanefreight.htb`

# Virtual Host and Subdomain Fuzzing

## Question 2

### "Using GoBuster against inlanefreight.com to fuzz for subdomains using the subdomains-top1million-5000.txt wordlist, which subdomain starts with the prefix "su"? Respond with the full vhost, eg web.inlanefreight.com"

Students will utilize `gobuster` to perform subdomain bruteforce using the `subdomains-top1million-5000.txt` wordlist against `inlanefreight.com` and attain the answer:

Code: shell

```shell
gobuster dns -d inlanefreight.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

```
┌─[eu-academy-6]─[10.10.14.52]─[htb-ac-8414@htb-pfnixnd8ei]─[~]
└──╼ [★]$ gobuster dns -d inlanefreight.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     inlanefreight.com
[+] Threads:    10
[+] Timeout:    1s
[+] Wordlist:   /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Starting gobuster in DNS enumeration mode
===============================================================
Found: ns1.inlanefreight.com
Found: ns2.inlanefreight.com
Found: www.inlanefreight.com
Found: ns3.inlanefreight.com
Found: {hidden}
Found: blog.inlanefreight.com
Found: my.inlanefreight.com
Found: customer.inlanefreight.com

Progress: 4989 / 4990 (99.98%)
===============================================================
Finished
===============================================================
```

Answer: `support.inlanefreight.com`

# Validating Findings

## Question 1

### "Fuzz the target system using directory-list-2.3-medium.txt, looking for a hidden directory. Once you have found the hidden directory, responsibly determine the validity of the vulnerability by analyzing the tar.gz file in the directory. Answer using the full Content-Length header, eg "Content-Length: 1337""

After spawning the target, students will open the terminal and use `ffuf` to perform a recursive directory and file fuzzing, targeting the `.tar.gz` file extension using the `directory-list-2.3-medium.txt` wordlist:

Code: shell

```shell
ffuf -u http://STMIP:STMPO/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic --recursion -e .tar.gz -t 80
```

```
┌─[eu-academy-6]─[10.10.14.52]─[htb-ac-8414@htb-tz3uj1h3xd]─[~]
└──╼ [★]$ ffuf -u http://94.237.59.199:31169/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic --recursion -e .tar.gz -t 80

<SNIP>
________________________________________________

 :: Method           : GET
 :: URL              : http://94.237.59.199:31169/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .tar.gz 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 80
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 28, Words: 1, Lines: 2, Duration: 16ms]
backup                  [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 16ms]
[INFO] Adding a new job to the queue: http://94.237.59.199:31169/backup/FUZZ

                        [Status: 200, Size: 28, Words: 1, Lines: 2, Duration: 16ms]
ur-hiddenmember         [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 16ms]
[INFO] Adding a new job to the queue: http://94.237.59.199:31169/ur-hiddenmember/FUZZ

[INFO] Starting queued job on target: http://94.237.59.199:31169/backup/FUZZ

                        [Status: 200, Size: 6787, Words: 873, Lines: 226, Duration: 16ms]
                        [Status: 200, Size: 6787, Words: 873, Lines: 226, Duration: 16ms]
[INFO] Starting queued job on target: http://94.237.59.199:31169/ur-hiddenmember/FUZZ

                        [Status: 200, Size: 7146, Words: 885, Lines: 228, Duration: 16ms]
backup.tar.gz           [Status: 200, Size: 210, Words: 1, Lines: 2, Duration: 16ms]
                        [Status: 200, Size: 7146, Words: 885, Lines: 228, Duration: 16ms]
:: Progress: [441094/441094] :: Job [3/3] :: 5000 req/sec :: Duration: [0:01:30] :: Errors: 0 ::
```

Students will find the hidden directory and `backup.tar.gz` file. Subsequently, they will use `cURL` to send a request, fetching only the headers, including the `Content-Length` header:

Code: shell

```shell
curl -I http://STMIP:STMPO/ur-hiddenmember/backup.tar.gz
```

```
┌─[eu-academy-6]─[10.10.14.52]─[htb-ac-8414@htb-tz3uj1h3xd]─[~]
└──╼ [★]$ curl -I http://94.237.59.199:31169/ur-hiddenmember/backup.tar.gz

HTTP/1.1 200 OK
Content-Type: application/x-gtar-compressed
ETag: "269241008"
Last-Modified: Thu, 01 Aug 2024 13:38:21 GMT
Content-Length: {hidden}
Accept-Ranges: bytes
Date: Tue, 03 Sep 2024 06:02:46 GMT
Server: lighttpd/1.4.76
```

Answer: `Content-Length: 210`

# API Fuzzing

## Question 1

### "What is the value returned by the endpoint that the api fuzzer has identified?"

After spawning the target, students will clone `webfuzz_api` and install the requirements:

Code: shell

```shell
git clone https://github.com/PandaSt0rm/webfuzz_api.git
cd webfuzz_api
pip3 install -r requirements.txt
```

```
┌─[eu-academy-6]─[10.10.14.52]─[htb-ac-8414@htb-v6q66cnjd8]─[~]
└──╼ [★]$ git clone https://github.com/PandaSt0rm/webfuzz_api.git
cd webfuzz_api
pip3 install -r requirements.txt

Cloning into 'webfuzz_api'...
remote: Enumerating objects: 8, done.
remote: Counting objects: 100% (8/8), done.
remote: Compressing objects: 100% (5/5), done.
remote: Total 8 (delta 0), reused 0 (delta 0), pack-reused 0 (from 0)
<SNIP>
```

Subsequently, students will use the Python3 script `api_fuzzer.py` against the target, while piping it to `grep` omitting any result that matches the `404` status code:

Code: shell

```shell
python3 api_fuzzer.py http://STMIP:STPO | grep -v 404
```

```
┌─[eu-academy-6]─[10.10.14.52]─[htb-ac-8414@htb-v6q66cnjd8]─[~/webfuzz_api]
└──╼ [★]$ python3 api_fuzzer.py http://94.237.58.173:55351 | grep -v 404

Fetching remote wordlist from https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt...
Successfully fetched remote wordlist.
Starting fuzzing with 4734 words.
[+] Valid endpoint found: http://94.237.58.173:55351/czcmdcvt (Status code: 200)
[+] Valid endpoint found: http://94.237.58.173:55351/docs (Status code: 200)
[!] Unusual status code for http://94.237.58.173:55351/items (Status code: 405)
[!] Unusual status code for http://94.237.58.173:55351/search (Status code: 422)

Fuzzing completed.
Total requests: 4734
Failed requests: 0
Retries: 0
Status code counts:
200: 2
405: 1
422: 1
Found valid endpoints:
- http://94.237.58.173:55351/czcmdcvt
- http://94.237.58.173:55351/docs
Unusual status codes:
405: http://94.237.58.173:55351/items
422: http://94.237.58.173:55351/search
```

Students will uncover the `/czcmdcvt` endpoint, and will use `cURL` to send a request to it to obtain the flag:

Code: shell

```shell
curl http://STMIP:STPO/czcmdcvt
```

```
┌─[eu-academy-6]─[10.10.14.52]─[htb-ac-8414@htb-v6q66cnjd8]─[~/webfuzz_api]
└──╼ [★]$ curl http://94.237.58.173:55351/czcmdcvt

{"flag":"{hidden}"}
```

Answer: `h1dd3n_r357`

# Skills Assessment

## Question 1

### "After completing all steps in the assessment, you will be presented with a page that contains a flag in the format of HTB{...}. What is that flag?"

After spawning the target, students will open the terminal and use `ffuf` to perform a recursive directory and file fuzzing using the `common.txt` wordlist while specifying `.php`, `.html`, and `.txt` as file extensions:

Code: shell

```shell
ffuf -u http://STMIP:STMPO/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -recursion -e .php,.txt,.html
```

```
┌─[eu-academy-6]─[10.10.14.52]─[htb-ac-8414@htb-rmib8snkrn]─[~]
└──╼ [★]$ ffuf -u http://83.136.251.59:33679/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -recursion -e .php,.txt,.html -ac

<SNIP>
________________________________________________

 :: Method           : GET
 :: URL              : http://83.136.251.59:33679/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Extensions       : .php .txt .html 
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

admin                   [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 16ms]
[INFO] Adding a new job to the queue: http://83.136.251.59:33679/admin/FUZZ

[INFO] Starting queued job on target: http://83.136.251.59:33679/admin/FUZZ

index.php               [Status: 200, Size: 13, Words: 2, Lines: 1, Duration: 16ms]
index.php               [Status: 200, Size: 13, Words: 2, Lines: 1, Duration: 17ms]
panel.php               [Status: 200, Size: 58, Words: 8, Lines: 1, Duration: 18ms]
:: Progress: [18892/18892] :: Job [2/2] :: 2469 req/sec :: Duration: [0:00:07] :: Errors: 0 ::
```

Students will uncover the `/admin/` endpoint alongside `index.php` and `panel.php`. Subsequently, they will send a request using `cURL` to both PHP pages to understand that `panel.php` requires the `accessID` parameter and respective value:

Code: shell

```shell
curl http://STMIP:STMPO/admin/panel.php
```

```
┌─[eu-academy-6]─[10.10.14.52]─[htb-ac-8414@htb-rmib8snkrn]─[~]
└──╼ [★]$ curl http://83.136.251.59:33679/admin/panel.php

Invalid parameter, please ensure accessID is set correctly
```

Therefore students will proceed to fuzz the `accessID` parameter value using `ffuf` and the `common.txt` wordlist, and filter the words:

Code: shell

```shell
ffuf -u http://STMIP:STMPO/admin/panel.php?accessID=FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -fw 8
```

```
┌─[eu-academy-6]─[10.10.14.52]─[htb-ac-8414@htb-rmib8snkrn]─[~]
└──╼ [★]$ ffuf -u http://83.136.251.59:33679/admin/panel.php?accessID=FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -fw 8

<SNIP>
________________________________________________

 :: Method           : GET
 :: URL              : http://83.136.251.59:33679/admin/panel.php?accessID=FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 8
________________________________________________

getaccess               [Status: 200, Size: 68, Words: 12, Lines: 1, Duration: 16ms]
:: Progress: [4723/4723] :: Job [1/1] :: 2469 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

Students will use `cURL` to send a request to the uncovered endpoint and value of the `accessID` parameter to unveil a virtual host:

Code: shell

```shell
curl http://STMIP:STMPO/admin/panel.php?accessID=getaccess
```

```
┌─[eu-academy-6]─[10.10.14.52]─[htb-ac-8414@htb-rmib8snkrn]─[~]
└──╼ [★]$ curl http://83.136.251.59:33679/admin/panel.php?accessID=getaccess

Head on over to the fuzzing_fun.htb vhost for some more fuzzing fun!
```

Subsequently, students will update their `/etc/hosts` file based on the VHost:

Code: shell

```shell
echo "STMIP fuzzing_fun.htb" | sudo tee -a /etc/hosts
```

```
┌─[eu-academy-6]─[10.10.14.52]─[htb-ac-8414@htb-rmib8snkrn]─[~]
└──╼ [★]$ echo "83.136.251.59 fuzzing_fun.htb" | sudo tee -a /etc/hosts

83.136.251.59 fuzzing_fun.htb
```

Students will use `cURL` to send a request to the virtual host to obtain information about a directory named `/godeep`:

Code: shell

```shell
curl http://fuzzing_fun.htb:STMPO
```

```
┌─[eu-academy-6]─[10.10.14.52]─[htb-ac-8414@htb-rmib8snkrn]─[~]
└──╼ [★]$ curl http://fuzzing_fun.htb:33679

Welcome to fuzzing_fun.htb!
Your next starting point is in the godeep folder - but it might be on this vhost, it might not, who knows...
```

With the obtained information, students will perform a subdomain fuzzing using `ffuf` and the `common.txt` wordlist:

Code: shell

```shell
ffuf -u http://fuzzing_fun.htb:STMPO -w /usr/share/seclists/Discovery/Web-Content/common.txt -H 'Host: FUZZ.fuzzing_fun.htb:STMPO' -ac
```

```
┌─[eu-academy-6]─[10.10.14.52]─[htb-ac-8414@htb-rmib8snkrn]─[~]
└──╼ [★]$ ffuf -u http://fuzzing_fun.htb:33679 -w /usr/share/seclists/Discovery/Web-Content/common.txt -H 'Host: FUZZ.fuzzing_fun.htb:33679' -ac

<SNIP>
________________________________________________

 :: Method           : GET
 :: URL              : http://fuzzing_fun.htb:33679
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Header           : Host: FUZZ.fuzzing_fun.htb:33679
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

hidden                  [Status: 200, Size: 45, Words: 8, Lines: 1, Duration: 16ms]
:: Progress: [4723/4723] :: Job [1/1] :: 2469 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```

Subsequently, students will update their `/etc/hosts` file with the newly found subdomain for `fuzzing_fun.htb`:

Code: shell

```shell
echo "STMIP hidden.fuzzing_fun.htb" | sudo tee -a /etc/hosts 
```

```
┌─[eu-academy-6]─[10.10.14.52]─[htb-ac-8414@htb-rmib8snkrn]─[~]
└──╼ [★]$ echo "83.136.251.59 hidden.fuzzing_fun.htb" | sudo tee -a /etc/hosts

83.136.251.59 hidden.fuzzing_fun.htb
```

Students will perform recursive directory brute-force against the `hidden.fuzzing_fun.htb/godeep` endpoint using the `common.txt` wordlist:

Code: shell

```shell
ffuf -u http://hidden.fuzzing_fun.htb:STMPO/godeep/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -recursion
```

```
┌─[eu-academy-6]─[10.10.14.52]─[htb-ac-8414@htb-rmib8snkrn]─[~]
└──╼ [★]$ ffuf -u http://hidden.fuzzing_fun.htb:33679/godeep/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -recursion

<SNIP>
________________________________________________

 :: Method           : GET
 :: URL              : http://hidden.fuzzing_fun.htb:33679/godeep/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

<SNIP>

[INFO] Adding a new job to the queue: http://hidden.fuzzing_fun.htb:33679/godeep/stoneedge/bbclone/typo3/FUZZ

[INFO] Starting queued job on target: http://hidden.fuzzing_fun.htb:33679/godeep/stoneedge/bbclone/typo3/FUZZ

.htpasswd               [Status: 403, Size: 290, Words: 20, Lines: 10, Duration: 16ms]
.hta                    [Status: 403, Size: 290, Words: 20, Lines: 10, Duration: 16ms]
.htaccess               [Status: 403, Size: 290, Words: 20, Lines: 10, Duration: 17ms]
index.php               [Status: 200, Size: 23, Words: 1, Lines: 1, Duration: 17ms]
:: Progress: [4723/4723] :: Job [4/4] :: 2469 req/sec :: Duration: [0:00:02] :: Errors: 0 ::
```

Students will notice the found subdirectories `/godeep/stoneedge/bbclone/typo3` and the `index.php` file. Subsequently, students will send a request using `cURL` against the URI found to attain the flag:

```shell
curl http://hidden.fuzzing_fun.htb:STMPO/godeep/stoneedge/bbclone/typo3/index.php
```
```
┌─[eu-academy-6]─[10.10.14.52]─[htb-ac-8414@htb-rmib8snkrn]─[~]
└──╼ [★]$ curl  http://hidden.fuzzing_fun.htb:33679/godeep/stoneedge/bbclone/typo3/index.php

{hidden}
```

Answer: `HTB{w3b_fuzz1ng_sk1lls}`