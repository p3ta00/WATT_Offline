
| Section                        | Question Number | Answer                |
| ------------------------------ | --------------- | --------------------- |
| What Is macOS?                 | Question 1      | Darwin                |
| What Is macOS?                 | Question 2      | Finder                |
| Graphical User Interface       | Question 1      | 13.0.1                |
| Navigating Around The OS       | Question 1      | HTB{F1l3s\_c@n\_Hide} |
| System Hierarchy               | Question 1      | /System/Applications  |
| File and Directory Permissions | Question 1      | 666                   |
| Application Management         | Question 1      | tmuxinator            |
| MacOS Terminal                 | Question 1      | ls -l                 |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# What Is macOS?

## Question 1

### "What BSD derivative is the basis of the macOS operating system?"

`Darwin` is the BSD derivative that is the basis of the macOS operating system:

![[HTB Solutions/Others/z. images/bbbc1bd89e4b28dd1385123b45100069_MD5.jpg]]

Answer: `Darwin`

# What Is macOS?

## Question 2

### "What provides the desktop experience and file management capabilities within macOS?"

`Finder` provides the desktop experience and file management capabilities within macOS:

![[HTB Solutions/Others/z. images/1c081c1240e35c0e93108c5b04867446_MD5.jpg]]

Answer: `Finder`

# Graphical User Interface

## Question 1

### "Find the numeric version running on your machine and submit it as the answer."

Students need to view the numeric version by clicking on the Apple Menu -> About This Mac to find the version in the macOS field, which is in the form of XX.X.X, where X denotes a number:

![[HTB Solutions/Others/z. images/cb6d1f65547ad50f2c1bc8e3986a0d22_MD5.jpg]]

Any numeric version inputted by students that matches the correct format will be accepted.

Answer: `13.0.1`

# Navigating Around The OS

## Question 1

### "Download the above file and double click on it to unzip it. The extracted folder may appear empty, but in reality it has a hidden file with the flag. Can you find the flag?"

Students first need to download [flag.zip](https://academy.hackthebox.com/storage/modules/157/flag.zip) then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/157/flag.zip && unzip flag.zip
```

```
┌─[eu-academy-1]─[10.10.14.81]─[htb-ac413848@htb-qajmrz6czh]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/157/flag.zip && unzip flag.zip

--2022-12-21 08:41:08--  https://academy.hackthebox.com/storage/modules/157/flag.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 336 [application/zip]
Saving to: ‘flag.zip’

flag.zip                                100%[=============================================================================>]     336  --.-KB/s    in 0s      

2022-12-21 08:41:08 (6.76 MB/s) - ‘flag.zip’ saved [336/336]

Archive:  flag.zip
   creating: flag/
 extracting: flag/.flag.txt
```

Then, since the file is stated to be hidden, it will start with a dot, i.e., ".flag.txt"; thus, students need to use the `cat` command on it to print its contents:

Code: shell

```shell
cat flag/.flag.txt
```

```
┌─[eu-academy-1]─[10.10.14.81]─[htb-ac413848@htb-qajmrz6czh]─[~]
└──╼ [★]$ cat flag/.flag.txt

HTB{F1l3s_c@n_Hide}
```

Answer: `HTB{F1l3s_c@n_Hide}`

# System Hierarchy

## Question 1

### "Where are the Applications related to the system stored at?"

The Applications related to the system are stored at the `/System/Applications` directory:

![[HTB Solutions/Others/z. images/7fd5f9b07e3bf6303fb40ad73197fae7_MD5.jpg]]

Answer: `/System/Applications`

# File and Directory Permissions

## Question 1

### "If a file has a permission set of "rw-rw-rw-" applied, what would that equal in Octal format? (number only)"

Since it is `r` (`read` = `4`) and `w` (`write` = `2`), adding their octal values results in `6`, thus, for all of them, the file's permission is `666`.

Answer: `666`

# Application Management

## Question 1

### "Search 'homebrew' for 'tmux', and one of the results ends in 'nator'. What is the full name of this package?"

Students can use [Homebrew Formulae](https://formulae.brew.sh/) to search for `tmux`, finding [tmuxinator](https://formulae.brew.sh/formula/tmuxinator#default) to end with "nator":

![[HTB Solutions/Others/z. images/ebb83d0b07b0cb322d448de229f85908_MD5.jpg]]

Answer: `tmuxinator`

# MacOS Terminal

## Question 1

### "Read the zsh configuration shown in the section above to find what command is mapped to 'll'. Submit the command as the answer."

`ll` is mapped to `ls -l` in the `zsh` configuration shown in the section:

![[HTB Solutions/Others/z. images/873d4ee8d8ac4e58e4c1ddaa5082b7ec_MD5.jpg]]

Answer: `ls -l`