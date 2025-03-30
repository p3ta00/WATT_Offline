
| Section                            | Question Number | Answer                 |
| ---------------------------------- | --------------- | ---------------------- |
| System Information                 | Question 1      | x86\_64                |
| System Information                 | Question 2      | /home/htb-student      |
| System Information                 | Question 3      | /var/mail/htb-student  |
| System Information                 | Question 4      | /bin/bash              |
| System Information                 | Question 5      | 4.15.0                 |
| System Information                 | Question 6      | ens192                 |
| Navigation                         | Question 1      | .bash\_history         |
| Navigation                         | Question 2      | 147627                 |
| Working with Files and Directories | Question 1      | apt.extended\_states.0 |
| Working with Files and Directories | Question 2      | 265293                 |
| Find Files and Directories         | Question 1      | 00-mesa-defaults.conf  |
| Find Files and Directories         | Question 2      | 4                      |
| Find Files and Directories         | Question 3      | /usr/bin/xxd           |
| File Descriptors and Redirections  | Question 1      | 32                     |
| File Descriptors and Redirections  | Question 2      | 737                    |
| Filter Contents                    | Question 1      | 7                      |
| Filter Contents                    | Question 2      | proftpd                |
| Filter Contents                    | Question 3      | 34                     |
| User Management                    | Question 1      | \-m                    |
| User Management                    | Question 2      | \--lock                |
| User Management                    | Question 3      | \--command             |
| Service and Process Management     | Question 1      | snapd.apparmor.service |
| Task Scheduling                    | Question 1      | dbus                   |
| Working with Web Services          | Question 1      | http-server -p 8080    |
| Working with Web Services          | Question 2      | php -S 127.0.0.1:8080  |
| File System Management             | Question 1      | 3                      |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# System Information

## Question 1

### "Find out the machine hardware name and submit it as the answer."

Students first need to SSH into the spawned target machine using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[eu-academy-2]─[10.10.14.46]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ssh htb-student@10.129.141.238

The authenticity of host '10.129.141.238 (10.129.141.238)' 
can't be established. Are you sure you want to continue 
connecting (yes/no/[fingerprint])? Yes
htb-student@10.129.141.238's password:

Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-123-generic x86_64)
<SNIP>
```

Then, students need to use the `uname` command with the `-m` flag to print the hardware machine name, which is `x86_64`:

Code: shell

```shell
uname -m
```

```
htb-student@nixfund:~$ uname -m

x86_64
```

Answer: `x86_64`

# System Information

## Question 2

### "What is the path to htb-student's home directory?"

Using the same SSH connection established from the previous question, many approaches can be taken to solve this question.

A first approach is whereby students use the `pwd` command:

Code: shell

```shell
pwd
```

```
htb-student@nixfund:~$ pwd

/home/htb-student
```

A second approach is whereby students use the `env` command to list the current environment variables and then use `grep` to filter the output for the `HOME` variable, finding the path `/home/htb-student`:

Code: shell

```shell
env | grep 'HOME'
```

```
htb-student@nixfund:~$ env | grep 'HOME'

HOME=/home/htb-student
```

Answer: `/home/htb-student`

# System Information

## Question 3

### "What is the path to the htb-student's mail?"

Using the same SSH connection established from the first question of this section, students need to use the `env` command to list the current environment variables and then use `grep` to filter the output for the `MAIL` variable, finding the path `/var/mail/htb-student`:

Code: shell

```shell
env | grep 'MAIL'
```

```
htb-student@nixfund:~$ env | grep 'MAIL'

MAIL=/var/mail/htb-student
```

Answer: `/var/mail/htb-student`

# System Information

## Question 4

### "Which shell is specified for the htb-student user?"

Using the same SSH connection established from the first question of this section, students need to use the `env` command to list the current environment variables and then use `grep` to filter the output for the `SHELL` variable, finding the shell `/bin/bash`:

Code: shell

```shell
env | grep 'SHELL'
```

```
htb-student@nixfund:~$ env | grep 'SHELL'

SHELL=/bin/bash
```

Answer: `/bin/bash`

# System Information

## Question 5

### "Which kernel version is installed on the system? (Format: 1.22.3)"

Using the same SSH connection established from the first question of this section, students need to use the the `uname` command with the the `-r` flag to print the operating system release, which is `4.15.0`:

Code: shell

```shell
uname -r
```

```
htb-student@nixfund:~$ uname -r

4.15.0-123-generic
```

Answer: `4.15.0`

# System Information

## Question 6

### "What is the name of the network interface that MTU is set to 1500?"

Using the same SSH connection established from the first question of this section, many approaches can be taken to solve this question.

A first approach is whereby students use the `ifconfig` command and notice that the first network interface has an MTU of 1500 (students could also use `grep` to filter the answer):

Code: shell

```shell
ifconfig
```

```
htb-student@nixfund:~$ ifconfig

ens192: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.141.238  netmask 255.255.0.0  broadcast 
		10.129.255.255
        inet6 fe80::250:56ff:feb9:11e1  prefixlen 64  
		scopeid 0x20<link>
        inet6 dead:beef::250:56ff:feb9:11e1  prefixlen 64
		<SNIP>
<SNIP>
```

A second approach is whereby students use the `ip` command with the `a` object and then use `grep` to filter the output for `mtu 1500` to find the answer (since only one interface with an `MTU` of 1500 exists) `ens192`:

Code: shell

```shell
ip a | grep 'mtu 1500'
```

```
htb-student@nixfund:~$ ip a | grep 'mtu 1500'

2: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
qdisc mq state UP group default qlen 1000
```

Answer: `ens192`

# Navigation

## Question 1

### "What is the name of the hidden "history" file in the htb-user's home directory?"

Students first need to SSH into the spawned target machine using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[eu-academy-2]─[10.10.14.46]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ssh htb-student@10.129.141.238

The authenticity of host '10.129.141.238 (10.129.141.238)' 
can't be established. Are you sure you want to continue 
connecting (yes/no/[fingerprint])? Yes
htb-student@10.129.141.238's password:

Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-123-generic x86_64)
<SNIP>
```

Subsequently, students need to use the `ls` command with the `-A` (short version of `--almost-all`) or the `-a` (short version of `--all`) flag to list the hidden files/directories in `/home/htb-student`, finding `.bash_history`:

Code: shell

```shell
ls -A
```

```
htb-student@nixfund:~$ ls -A

.bash_history  .bash_logout  .bashrc  .cache  .gnupg  .profile
```

Answer: `.bash_history`

# Navigation

## Question 2

### "What is the index number of the "sudoers" file in the "/etc" directory?"

Using the same SSH connection established from the previous question, students need to use the `ls` command with the `-i` (short version of `--inode`) flag to print the index number of files under the `/etc/` directory, which is `147627` for `sudoers`:

```
htb-student@nixfund:~$ ls -i /etc/ | grep 'sudoers'

147627 sudoers
146948 sudoers.d
```

Answer: `147627`

# Working with Files and Directories

## Question 1

### "What is the name of the last modified file in the "/var/backups" directory?"

Students first need to SSH into the spawned target machine using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[eu-academy-2]─[10.10.14.46]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ssh htb-student@10.129.141.238

The authenticity of host '10.129.141.238 (10.129.141.238)' 
can't be established. Are you sure you want to continue 
connecting (yes/no/[fingerprint])? Yes
htb-student@10.129.141.238's password:

Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-123-generic x86_64)
<SNIP>
```

Afterward, students need to either consult the man page of the `tree` command or use the `--help` flag to find out that the `-t` flag is used to sort files by last modification time and the `-r` flag sorts the output in reverse order:

Code: shell

```shell
tree --help | grep 'last modification'
tree --help | grep 'Reverse'
```

```
htb-student@nixfund:~$ tree --help | grep 'last modification'

  -D            Print the date of last modification or (-c) status change.
  -t            Sort files by last modification time.
  
htb-student@nixfund:~$ tree --help | grep 'Reverse'

  -r            Reverse the order of the sort.
```

Thus, to output the last modified file as the first result, students need to use both the `-t` and `-r` flags of `tree` (`-r` is not mandatory, however, if not used, the last modified file will be at the end of the list instead), to find that the name of the last modified file is `apt.extended_states.0`:

Code: shell

```shell
tree -r -t /var/backups | head -n5
```

```
htb-student@nixfund:~$ tree -r -t /var/backups | head -n5

/var/backups
├── apt.extended_states.0
├── apt.extended_states.1.gz
├── dpkg.status.1.gz
├── dpkg.status.0
```

Answer: `apt.extended_states.0`

# Working with Files and Directories

## Question 2

### "What is the inode number of the "shadow.bak" file in the "/var/backups" directory?"

Using the same SSH connection established from the previous question, many approaches can be taken to solve this question.

A first approach is whereby students use the `--inodes` flag (which prints the `inode` number of each file) of the `tree` command and use `grep` to filter out the answer:

Code: shell

```shell
tree --inodes /var/backups | grep -w 'shadow.bak'
```

```
htb-student@nixfund:~$ tree --inodes /var/backups | grep -w 'shadow.bak'

[ 265293]  shadow.bak
```

A second approach is whereby students use the `ls` command along with its `-i` flag and use `grep` to filter out the answer, which is `265293`:

Code: shell

```shell
ls -i /var/backups/ | grep -w 'shadow.bak'
```

```
htb-student@nixfund:~$ ls -i /var/backups/ | grep -w 'shadow.bak'

265293 shadow.bak
```

Answer: `265293`

# Find Files and Directories

## Question 1

### "What is the name of the config file that has been created after 2020-03-03 and is smaller than 28k but larger than 25k?"

Students first need to SSH into the spawned target machine using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[eu-academy-2]─[10.10.14.46]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ssh htb-student@10.129.141.238

The authenticity of host '10.129.141.238 (10.129.141.238)' 
can't be established. Are you sure you want to continue 
connecting (yes/no/[fingerprint])? Yes
htb-student@10.129.141.238's password:

Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-123-generic x86_64)
<SNIP>
```

Subsequently, students need to use the `find` command on the root directory `/` with the `-type` flag specifying for it `f` (files); the `-name` flag specifying for it `*.conf` (i.e. only files that end with `.conf`); the `-size` flag two times, first specifying for it `+25k` (i.e. only files larger than 25k in size) and for the second `-28k` (i.e. only files less than 28k in size), and the `-newermt` flag specifying for it the date `2020-03-03` (i.e. only files created after `2020-03-03`); the name of the config file that students will attain is `00-mesa-defaults.conf`:

Code: shell

```shell
find / -type f -name *.conf -size +25k -size -28k -newermt 2020-03-03 2>/dev/null
```

```
htb-student@nixfund:~$ find / -type f -name *.conf -size +25k -size -28k -newermt 2020-03-03 2>/dev/null

/usr/share/drirc.d/00-mesa-defaults.conf
```

Answer: `00-mesa-defaults.conf`

# Find Files and Directories

## Question 2

### "How many files exist on the system that have the ".bak" extension?"

Using the same SSH connection established from the previous question, students need to use the `find` command on the root directory `/` with the `-type` flag specifying for it `f` (files) and the `-name` flag specifying for it `*.bak` (i.e. only files that end with `.bak`). From the output, students can see that there are only `4` files:

Code: shell

```shell
find / -type f -name *.bak 2>/dev/null
```

```
htb-student@nixfund:~$ find / -type f -name *.bak 2>/dev/null

/var/backups/shadow.bak
/var/backups/gshadow.bak
/var/backups/group.bak
/var/backups/passwd.bak
```

However, if the number was substantially greater, students can pipe the output to `wc` with the `-l` flag to attain the number of files:

Code: shell

```shell
find / -type f -name *.bak 2>/dev/null | wc -l
```

```
htb-student@nixfund:~$ find / -type f -name *.bak 2>/dev/null | wc -l

4
```

Answer: `4`

# Find Files and Directories

## Question 3

### "Submit the full path of the "xxd" binary."

Using the same SSH connection established from the first question of the section, students need to use the `which` command to find the full path of the `xxd` binary to be `/usr/bin/xxd`:

Code: shell

```shell
which xxd
```

```
htb-student@nixfund:~$ which xxd

/usr/bin/xxd
```

Answer: `/usr/bin/xxd`

# File Descriptors and Redirections

## Question 1

### "How many files exist on the system that have the ".log" file extension?"

Students first need to SSH into the spawned target machine using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[eu-academy-2]─[10.10.14.46]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ssh htb-student@10.129.141.238

The authenticity of host '10.129.141.238 (10.129.141.238)' 
can't be established. Are you sure you want to continue 
connecting (yes/no/[fingerprint])? Yes
htb-student@10.129.141.238's password:

Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-123-generic x86_64)
<SNIP>
```

Afterward, students need to use the `find` command on the root directory `/` with the `-type` flag specifying for it `f` (files) and the `-name` flag specifying for it `*.log` (i.e. only files that end with `.log`) and piping the output to the `wc` command with the `-l` flag (which prints the newline counts) to print the number of files (this question is not intended for students to use `grep` to solve it), which is `33`:

Code: shell

```shell
find / -type f -name '*.log' 2>/dev/null | wc -l
```

```
htb-student@nixfund:~$ find / -type f -name '*.log' 2>/dev/null | wc -l

32
```

Answer: `32`

# File Descriptors and Redirections

## Question 2

### "How many total packages are installed on the target system?"

Using the same SSH connection established from the previous question, students need to either consult the man page of `dpkg` or use the `--help` flag to find out that the `-l` (short version of `--list`) flag is used to list the installed packages:

Code: shell

```shell
dpkg --help | grep 'List packages'
```

```
htb-student@nixfund:~$ dpkg --help | grep 'List packages'

-l|--list [<pattern> ...]  List packages concisely.
```

When listing the installed packages, students need to notice that the first few lines of the output are not actual packages:

Code: shell

```shell
dpkg -l | head
```

```
htb-student@nixfund:~$ dpkg -l | head

Desired=Unknown/Install/Remove/Purge/Hold 
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend 
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||/ Name     Version		Architecture    Description
+++-=======-============================-==============================
ii  acl      2.2.52-3build1  amd64       Access control list utilities
<SNIP>
```

Additionally, students need to notice that installed packages begin with `ii`, therefore, they need to use `grep` to filter for packages only, then at last, pipe the output to the `wc` command along with the `-l` flag, finding `737` installed packages in total:

Code: shell

```shell
dpkg -l | grep 'ii' | wc -l
```

```
htb-student@nixfund:~$ dpkg -l | grep 'ii' | wc -l

737
```

Answer: `737`

# Filter Contents

## Question 1

### "How many services are listening on the target system on all interfaces? (Not on localhost and IPv4 only)"

Students first need to SSH into the spawned target machine using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[eu-academy-2]─[10.10.14.46]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ssh htb-student@10.129.141.238

The authenticity of host '10.129.141.238 (10.129.141.238)' 
can't be established. Are you sure you want to continue 
connecting (yes/no/[fingerprint])? Yes
htb-student@10.129.141.238's password:

Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-123-generic x86_64)
<SNIP>
```

Many approaches can be taken to solve this question.

A first approach is whereby students use the `netstat` command with the `-t` (short version of `--tcp`) flag, the `-u` (short version of `--udp`) flag, the `-l` (short version of `--listening`) flag to list listening sockets, and the `-n` flag (short version of `--numeric`) to show numerical addresses instead of trying to determine symbolic hosts, ports or user names:

Code: shell

```shell
netstat -tuln
```

```
htb-student@nixfund:~$ netstat -tuln

Active Internet connections (only servers)
P. Recv-Q Send-Q Local Add.  Foreign Add. State      
tcp 0      0    0.0.0.0:993  0.0.0.0:*    LISTEN
<SNIP>
udp 0      0    127.0.0.53:53 0.0.0.0:*
```

However, students will notice that there are some sockets listed at the end that are not listening, thus, they need to filter them out using `grep`:

Code: shell

```shell
netstat -tuln | grep 'LISTEN'
```

```
htb-student@nixfund:~$ netstat -tuln | grep 'LISTEN'

tcp  0  0 0.0.0.0:993     0.0.0.0:*  LISTEN      
tcp  0  0 127.0.0.1:3306  0.0.0.0:*  LISTEN
<SNIP>
```

At last, students need to exclude (filter out) using `grep` any socket that is listening on localhost (i.e. 127.0.0.\*) or uses IPv6, and then use the `wc` command with the `-l` flag to print the number of desired interfaces, which is `7`:

Code: shell

```shell
netstat -tuln | grep 'LISTEN' | grep -v "127.0.0\|tcp6" | wc -l
```

```
htb-student@nixfund:~$ netstat -tuln | grep 'LISTEN' | grep -v "127.0.0\|tcp6" | wc -l
7
```

Answer: `7`

# Filter Contents

## Question 2

### "Determine what user the ProFTPd server is running under. Submit the username as the answer."

Using the same SSH connection established from the previous question, students need to use the `find` command on the root directory `/` and use the `-name` flag specifying for it `proftpd.conf`, since users and related information can be found in configuration files:

Code: shell

```shell
find / -name 'proftpd.conf' 2>/dev/null
```

```
htb-student@nixfund:~$ find / -name 'proftpd.conf' 2>/dev/null

/etc/proftpd/proftpd.conf
/usr/share/proftpd/templates/proftpd.conf
```

Students now need to use the `-execute` flag of `find` specifying for it the `cat` command (as taught in the `Find Files and Directories` section):

Code: shell

```shell
find / -name 'proftpd.conf' -exec cat {} \; 2>/dev/null
```

```
htb-student@nixfund:~$ find / -name 'proftpd.conf' -exec cat {} \; 2>/dev/null

# /etc/proftpd/proftpd.conf -- This is a basic ProFTPD
# configuration file.
<SNIP>
```

Since only the user is asked for, students need to use `grep` to filter out the lines with `user`, and then at last, use `grep` again to remove all commented lines (ones starting with `#`), to find the username `proftpd`:

Code: shell

```shell
find / -name 'proftpd.conf' -exec cat {} \; 2>/dev/null | grep -i 'user' | grep -v '#'
```

```
tb-student@nixfund:~$ find / -name 'proftpd.conf' -exec cat {} \; 2>/dev/null | grep -i 'user' | grep -v '#'

User	proftpd
User	proftpd
```

Answer: `proftpd`

# Filter Contents

## Question 3

### "Use cURL from your Pwnbox (not the target machine) to obtain the source code of the "https://www.inlanefreight.com" website and filter all unique paths (https://www.inlanefreight.com/directory" or "/another/directory") of that domain. Submit the number of these paths as the answer."

Students first need to fetch the source code of "https://www.inlanefreight.com" using `curl` along with the `-k` flag to allow insecure connections (ignore SSL/TLS warnings) and the `-s` flag to operate in silent mode:

Code: shell

```shell
curl https://www.inlanefreight.com -k -s
```

```
┌─[eu-academy-2]─[10.10.14.38]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl https://www.inlanefreight.com -k -s

<!DOCTYPE html>
<html lang="en-US">
<head>
<meta charset="UTF-8">
<SNIP>
<script type='text/javascript' src='https://www.inlanefreight.com
/wp-includes/js/wp-embed.min.js?ver=5.6.8' id='wp-embed-js'>
</script>
<SNIP>
```

Since the `src` attribute of the `script` tag wraps around URLs single apostrophes, students need to use `tr` to replace them with the newline character:

Code: shell

```shell
curl https://www.inlanefreight.com -k -s | tr "'" "\n"
```

```
┌─[eu-academy-2]─[10.10.14.38]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl https://www.inlanefreight.com -k -s | tr "'" "\n"

<!DOCTYPE html>
<html lang="en-US">
<SNIP>
src=
https://www.inlanefreight.com/wp-includes/
js/wp-embed.min.js?ver=5.6.8
<SNIP>
<link rel="canonical" href="https://www.inlanefreight.com/" />
<SNIP>
```

Students will also notice from output that the `href` attribute of the `link` tag wraps around URLs double quotes, thus, they need to pipe the output once more to `tr` to replace them with the newline character:

Code: shell

```shell
curl https://www.inlanefreight.com -k -s | tr "'" "\n" | tr '"' "\n"
```

Now, students need run the same command and pipe its output for `grep` to filter out the paths of the domain "inlanefreight":

Code: shell

```shell
curl https://www.inlanefreight.com -k -s | tr "'" "\n" | tr '"' '\n' | grep "https://www.inlanefreight.com"
```

```
┌─[eu-academy-2]─[10.10.14.38]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl https://www.inlanefreight.com -k -s | tr "'" "\n" | tr '"' '\n' | grep "https://www.inlanefreight.com"

https://www.inlanefreight.com/index.php/feed/
https://www.inlanefreight.com/index.php/comments/feed/
<SNIP>
```

At last, since the question asks for only the unique paths, students need to sort the paths using the `sort` command with the `-u` (short version of `--unique`) flag and pipe the output to `wc` along with its `-l` flag, finding `34` unique paths of the domain "www.inlanefreight.com":

Code: shell

```shell
curl https://www.inlanefreight.com -k -s | tr "'" "\n" | tr '"' '\n' | grep "https://www.inlanefreight.com" | sort -u | wc -l
```

```
┌─[eu-academy-2]─[10.10.14.38]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ curl https://www.inlanefreight.com -k -s | tr "'" "\n" | tr '"' '\n' | grep "https://www.inlanefreight.com" | sort -u | wc -l

34
```

Answer: `34`

# User Management

## Question 1

### "Which option needs to be set to create a home directory for a new user using "useradd" command?"

Students need to either consult the man page of `useradd` or use the `--help` flag to find out that the `-m` (short version of `--create-home`) flag is used to create the user's home directory:

Code: shell

```shell
useradd --help | grep 'home directory'
```

```
┌─[eu-academy-2]─[10.10.14.46]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ useradd --help | grep 'home directory'

  <SNIP>
  -m, --create-home     create the user's home directory
  -M, --no-create-home  do not create the user's home directory
```

Answer: `-m`

# User Management

## Question 2

### "Which option needs to be set to lock a user account using the "usermod" command? (long version of the option)"

Students need to either consult the man page of `usermod` or use the `--help` flag to find out that the `--lock` (long version of `-L`) flag is used to lock a user's account:

Code: shell

```shell
usermod --help | grep 'lock'
```

```
┌─[eu-academy-2]─[10.10.14.46]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ usermod --help | grep 'lock'

  -L, --lock                    lock the user account
  -U, --unlock                  unlock the user account
```

Answer: `--lock`

# User Management

## Question 3

### "Which option needs to be set to execute a command as a different user using the "su" command? (long version of the option)"

Students need to either consult the man page of `su` or use the `--help` flag to find out that the `--command` (long version of `-c`) flag is used to execute a command as a different user:

Code: shell

```shell
su --help | grep 'command'
```

```
┌─[eu-academy-2]─[10.10.14.46]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ su --help | grep 'command'

 -c, --command <command>   pass a single command to the shell with -c
 --session-command <command> pass a single command to the shell with -c
```

Answer: `--command`

# Service and Process Management

## Question 1

### "Use the "systemctl" command to list all units of services and submit the unit name with the description "Load AppArmor profiles managed internally by snapd" as the answer."

Students first need to SSH into the spawned target machine using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[eu-academy-2]─[10.10.14.46]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ssh htb-student@10.129.141.238

htb-student@10.129.141.238's password:

Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-123-generic x86_64)
<SNIP>
```

Afterward, students need to use the `systemctl` command along with the `list-units` unit command, apply the `--type=service` filter, and at last use `grep` to filter out the answer, which is `snapd.apparmor.service`:

Code: shell

```shell
systemctl list-units --type=service | grep 'Load AppArmor .*'
```

```
htb-student@nixfund:~$ systemctl list-units --type=service | grep 'Load AppArmor .*'

snapd.apparmor.service loaded active exited  Load AppArmor
profiles managed internally by snapd
```

Answer: `snapd.apparmor.service`

# Task Scheduling

## Question 1

### "What is the Type of the service of the "dconf.service"?"

The type of the service `dconf.service` under the directory `/usr/lib/systemd/user/` is `dbus`:

Code: shell

```shell
cat /usr/lib/systemd/user/dconf.service | grep "Type"
```

```
┌─[us-academy-1]─[10.10.15.2]─[htb-ac413848@htb-c2gbiz5wq3]─[~]
└──╼ [★]$ cat /usr/lib/systemd/user/dconf.service | grep "Type"

Type=dbus
```

Answer: `dbus`

# Working with Web Services

## Question 1

### "Find a way to start a simple HTTP server inside Pwnbox or your local VM using "npm". Submit the command that starts the web server on port 8080 (use the short argument to specify the port number)."

Students first need to attain the `http-server` package from [npmjs](https://www.npmjs.com/package/http-server) (the `--global` flag allows `http-server` to be run from the command line anywhere):

Code: shell

```shell
sudo npm install --global http-server
```

```
┌─[eu-academy-2]─[10.10.14.46]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ sudo npm install --global http-server

added 11 packages, removed 1 package, changed 28 packages,
and audited 40 packages in 4s
found 0 vulnerabilities
```

Then, students can use the package and specify port 8080 to start an HTTP server with it:

Code: shell

```shell
http-server -p 8080
```

```
┌─[eu-academy-2]─[10.10.14.46]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ http-server -p 8080

Starting up http-server, serving ./

http-server version: 14.1.0
<SNIP>
```

Answer: `http-server -p 8080`

# Working with Web Services

## Question 2

### "Find a way to start a simple HTTP server inside Pwnbox or your local VM using "php". Submit the command that starts the web server on the localhost (127.0.0.1) on port 8080."

Students need to either consult the man page of PHP or use the `--help` flag to find out that a web server can be started using the `-S` flag:

```shell
php --help | grep 'server'
```
```
┌─[eu-academy-2]─[10.10.14.46]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ php --help | grep 'server'

  -S <addr>:<port> Run with built-in web server.
  -t <docroot>     Specify document root <docroot> for built-in web server.
```

Subsequently, students can run the server by specifying 127.0.0.1 as the address and 8080 for the port:

```shell
php -S 127.0.0.1:8080
```
```
┌─[eu-academy-2]─[10.10.14.46]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ php -S 127.0.0.1:8080

[Wed Mar 30 07:46:17 2022] PHP 7.4.21 Development Server
(http://127.0.0.1:8080) started
```

Answer: `php -S 127.0.0.1:8080`

# File System Management

## Question 1

### "How many partitions exist in our Pwnbox? (Format: 0)"

Students need to use `fdisk` with the `-l` (short version of `--list`) to list the partition tables, finding three partitions on Pwnbox:

```shell
sudo fdisk -l 
```
```
┌─[eu-academy-5]─[10.10.14.97]─[htb-ac-8414@htb-sydlpwppkd]─[~]
└──╼ [★]$ sudo fdisk -l
Disk /dev/vda: 40 GiB, 42949672960 bytes, 83886080 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0xbe9de24c

Device     Boot    Start      End  Sectors  Size Id Type
/dev/vda1  *        2048 81885183 81883136   39G 83 Linux
/dev/vda2       81887230 83884031  1996802  975M  5 Extended
/dev/vda5       81887232 83884031  1996800  975M 82 Linux swap / Solaris
```

Answer: `3`