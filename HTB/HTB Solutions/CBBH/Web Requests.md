

| Section | Question Number | Answer |
| --- | --- | --- |
| HyperText Transfer Protocol (HTTP) | Question 1 | HTB{64$!c\_cURL\_u$3r} |
| HTTP Requests and Responses | Question 1 | GET |
| HTTP Requests and Responses | Question 2 | 2.4.41 |
| HTTP Headers | Question 1 | HTB{p493\_r3qu3$t$\_m0n!t0r} |
| GET | Question 1 | HTB{curl\_g3773r} |
| POST | Question 1 | HTB{p0$t\_r3p34t3r} |
| CRUD API | Question 1 | HTB{crud\_4p!\_m4n!pul4t0r} |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# HyperText Transfer Protocol (HTTP)

## Question 1

### "To get the flag, use cURL to download the file returned by '/download.php' in the above server."

Students need to use `cURL` with the `-O` (short version of `--remote-name`) flag to write output to a local file named like the remote file "download.php":

Code: shell

```shell
curl -O -s STMIP:STMPO/download.php
```

```
┌─[us-academy-1]─[10.10.14.48]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl -O -s 161.35.47.235:31852/download.php

┌─[us-academy-1]─[10.10.14.48]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ cat download.php

HTB{64$!c_cURL_u$3r}
```

Alternatively, students can invoke `cURL` without downloading the file, and the contents of "download.php" will be displayed directly (the `-w` flag allows information to be displayed on `stdout` after a completed transfer, thus, the format `\n` will insert a newline character after the downloaded file's content is displayed):

Code: shell

```shell
curl -w "\n" STMIP:STMPO/download.php
```

```
┌─[us-academy-1]─[10.10.14.48]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl -w "\n" 161.35.47.235:31852/download.php

HTB{64$!c_cURL_u$3r}
```

Answer: `HTB{64$!c_cURL_u$3r}`

# HTTP Requests and Responses

## Question 1

### "What is the HTTP method used while intercepting the request? (case-sensitive)"

After spawning the target machine and visiting its web root page, students need to open the browser's DevTools (Web Developer Tools in Firefox), specifically the Network tab:

![[HTB Solutions/CBBH/z. images/a5bfbfee8f0d63c182b4658cb3cee3a4_MD5.jpg]]

Students subsequently need to refresh the page and notice that the HTTP method being used is `GET`:

![[HTB Solutions/CBBH/z. images/7caec066fe81d1b74f432f94cf5ff9a5_MD5.jpg]]

Answer: `GET`

# HTTP Requests and Responses

## Question 2

### "Send a GET request to the above server, and read the response headers to find the version of Apache running on the server? (answer format: X.Y.ZZ)"

Students can either use `cURL` or do it directly from the browser. The browser method involves the same steps as in the previous question, afterwards, students need to click on the request and read the "Response Headers" to find out the version of Apache running on the server:

![[HTB Solutions/CBBH/z. images/069280fd9d97274363e297f18b497f65_MD5.jpg]]

The same can be achieved with `cURL`, using its `-l` (short version of `--head`) flag which fetches the headers only:

Code: shell

```shell
curl -s -I STMIP:STMPO | grep 'Server'
```

```
┌─[us-academy-1]─[10.10.14.67]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl -s -I 134.209.28.38:31752 | grep 'Server'

Server: Apache/2.4.41 (Ubuntu)
```

Answer: `2.4.41`

# HTTP Headers

## Question 1

### The server above loads the flag after the page is loaded. Use the Network tab in the browser devtools to see what requests are made by the page, and find the request to the flag."

After spawning the target machine and browsing to its web root page, students need to open the Network tab of the Web Developer Tools in the browser:

![[HTB Solutions/CBBH/z. images/ded051cc2ac700e193630125e8f57fc0_MD5.jpg]]

Students then need to refresh the page to notice that there is GET request to `http://STMIP:STMPO/flag_327a6c4304ad5938eaf0efb6cc3e53dc.txt`:

![[HTB Solutions/CBBH/z. images/7fc40f78102ce55cadc040a32b5175a6_MD5.jpg]]

Students at last need to click on the request, then view its response to find the flag:

![[HTB Solutions/CBBH/z. images/13cd74ad409d338cd79456bee3e42c02_MD5.jpg]]

Answer: `HTB{p493_r3qu3$t$_m0n!t0r}`

# GET

## Question 1

### "The exercise above seems to be broken, as it returns incorrect results. Use the browser devtools to see what is the request it is sending when we search, and use cURL to search for 'flag' and obtain the flag."

Students first need to browse to the web root page of the spawned target machine's website and they will be confronted with Basic HTTP Authentication:

![[HTB Solutions/CBBH/z. images/b209a4323372e9b782a9e767e7558b0a_MD5.jpg]]

Students need to supply the credentials `admin:admin`:

![[HTB Solutions/CBBH/z. images/afa16a515500fd90aae95938f2736a79_MD5.jpg]]

The web page search functionality is broken, as it returns the same result(s) regardless of the given search keyword, for example, when providing the term "flag", it returns the following:

![[HTB Solutions/CBBH/z. images/66f4533f42a321f79e15f672d4254e30_MD5.jpg]]

Thus, students need to use the Networking tab of the Web Developer Tools of the browser to identify the GET request being made:

![[HTB Solutions/CBBH/z. images/797ed1bc7c8e2b35045672251b577a7d_MD5.jpg]]

Once students identify the request, they need to right-click on it and click on "Copy > Copy as cURL":

![[HTB Solutions/CBBH/z. images/5f7b2eed8f7a03580c5ea54de668ba5c_MD5.jpg]]

Now that students have attained the request as a `cURL` command, they can take multiple approaches to fetch the flag. For example students can use the Authorization header and pass to it the credentials `admin:admin` as base64-encoded value:

Code: shell

```shell
curl 'http://STMIP:STMPO/search.php?search=flag' -H 'Authorization: Basic YWRtaW46YWRtaW4='
```

```
┌─[us-academy-1]─[10.10.14.67]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl 'http://178.128.163.152:32277/search.php?search=flag' -H 'Authorization: Basic YWRtaW46YWRtaW4='

flag: HTB{curl_g3773r}
```

Alternatively, students can supply the credentials in the URL directly:

Code: shell

```shell
curl 'http://admin:admin@STMIP:STMPO/search.php?search=flag'
```

```
┌─[us-academy-1]─[10.10.14.67]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl 'http://admin:admin@178.128.163.152:32277/search.php?search=flag'

flag: HTB{curl_g3773r}
```

One more last option is supplying the credentials using `cURL` with its `-u` (short version of `--user`) flag:

Code: shell

```shell
curl -u admin:admin 'http://STMIP:STMPO/search.php?search=flag'
```

```
┌─[us-academy-1]─[10.10.14.67]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl -u admin:admin 'http://178.128.163.152:32277/search.php?search=flag'

flag: HTB{curl_g3773r}
```

Answer: `HTB{curl_g3773r}`

# POST

## Question 1

### "Obtain a session cookie through a valid login, and then use the cookie with cURL to search for the flag through a JSON POST request to '/search.php'"

To obtain a session cookie through a valid login, students need to either use `cURL` or the browser.

For `cURL`, students first need to know the data being sent in the login form request.

![[HTB Solutions/CBBH/z. images/acf320f56021905820b11a82c2e00434_MD5.jpg]]

Supplying the credentials `admin:admin` reveals that the two parameters are `username` and `password`:

![[HTB Solutions/CBBH/z. images/0aca01645e03b951afda8a57de979186_MD5.jpg]]

Students can grab the session cookie from the Storage tab of the Web Developer Tools:

![[HTB Solutions/CBBH/z. images/51ab052cd71e766328779ef0384a0a30_MD5.jpg]]

Or, they can use `cURL` along with its `-i` (short version of `--include`) flag to include the HTTP response headers in the output:

Code: shell

```shell
curl -i -s -X POST -d 'username=admin&password=admin' http://STMIP:STMPO | head -n5
```

```
┌─[us-academy-1]─[10.10.14.67]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl -i -s -X POST -d 'username=admin&password=admin' http://134.209.186.158:32390 | head -n5

HTTP/1.1 200 OK
Date: Sat, 09 Apr 2022 02:19:39 GMT
Server: Apache/2.4.41 (Ubuntu)
Set-Cookie: PHPSESSID=ih43a5pcf7th0uhv0ru37sntf3; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
```

Students now need to identify the parameter(s) used in the search form. Any arbitrary search keyword can be supplied and the request sent after clicking the search icon reveals that there is only one parameter being utilized, named "search":

![[HTB Solutions/CBBH/z. images/fee4289bba57f7a2d5a51239a90e6354_MD5.jpg]]

Armed with the session cookie and the search form parameter, students at last need to use `cURL` with the `-X` (short version of `--request`) flag specifying for it the `POST` method; the `-d` (short version of `--data`) flag specifying for it the `JSON` data, i.e. the `search` parameter with `flag` being the value; the `-b` (short version of `--cookie`) flag specifying for it the value of the session cookie; and the `-H` (short version of `--header`) flag specifying for it the `Content-Type` header with `application/json` being its value:

Code: shell

```shell
curl -s -w "\n" -X POST -d '{"search":"flag"}' -b 'PHPSESSID=ih43a5pcf7th0uhv0ru37sntf3' -H 'Content-Type: application/json' http://STMIP:STMPO/search.php
```

```
┌─[us-academy-1]─[10.10.14.67]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl -s -w "\n" -X POST -d '{"search":"flag"}' -b 'PHPSESSID=ih43a5pcf7th0uhv0ru37sntf3' -H 'Content-Type: application/json' http://161.35.47.235:31145/search.php

["flag: HTB{p0$t_r3p34t3r}"]
```

Answer: `HTB{p0$t_r3p34t3r}`

# CRUD API

## Question 1

### "First, try to update any city's name to be 'flag'. Then, delete any city. Once done, search for a city named 'flag' to get the flag."

Students first need to update any city's name to be "flag". For example, they can update the city "london":

Code: shell

```shell
curl -X PUT http://STMIP:STMPO/api.php/city/london -d '{"city_name":"flag", "country_name":""}' -H 'Content-Type: application/json'
```

```
┌─[us-academy-1]─[10.10.14.67]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl -X PUT http://161.35.47.235:30164/api.php/city/london -d '{"city_name":"flag", "country_name":""}' -H 'Content-Type: application/json'
```

Then, students need to delete any city. For example, they can delete the city "leeds":

```shell
curl -X DELETE http://STMIP:STMPO/api.php/city/leeds
```
```
┌─[us-academy-1]─[10.10.14.67]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl -X DELETE http://161.35.47.235:30164/api.php/city/leeds
```

At last, students need to read the city with the name "flag" to attain the answer `HTB{crud_4p!_m4n!pul4t0r}` by sending a `GET` request:

```shell
curl -w "\n" http://STMIP:STMPO/api.php/city/flag
```
```
┌─[us-academy-1]─[10.10.14.67]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl -w "\n" http://161.35.47.235:30164/api.php/city/flag

[{"city_name":"flag","country_name":"HTB{crud_4p!_m4n!pul4t0r}"}]
```

Answer: `HTB{crud_4p!_m4n!pul4t0r}`