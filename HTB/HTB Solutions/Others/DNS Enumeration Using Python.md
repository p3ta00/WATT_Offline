
| Section                 | Question Number | Answer                         |
| ----------------------- | --------------- | ------------------------------ |
| DNS Records and Queries | Question 1      | HTB{5Fz6UPNUFFzqjdg0AzXyxCjMZ} |
| DNS Records and Queries | Question 2      | 2a03:b0c0:1:e0::32c:b001       |
| DNS Enumeration         | Question 1      | 2                              |
| DNS Enumeration         | Question 2      | 10.129.2.55                    |
| DNS Enumeration         | Question 3      | 10.129.2.58                    |
| DNS Enumeration         | Question 4      | HTB{mgraRNhvDCPcKpzAXHA6cJUhW} |
| Main Function           | Question 1      | 14                             |
| Argparse                | Question 1      | 14                             |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# DNS Records and Queries

## Question 1

### "Investigate all records for the domain "inlanefreight.com" with the help of dig or nslookup and submit the one unique record in double quotes as the answer."

Students can use either `dig` or `nslookup`, specifying the query type as `TXT`.

With `dig`:

Code: shell

```shell
dig TXT inlanefreight.com
```

```
┌─[us-academy-1]─[10.10.14.126]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ dig txt inlanefreight.com

; <<>> DiG 9.16.15-Debian <<>> txt inlanefreight.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 25292
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; EDE: 23 (Network Error): (178.128.39.165:53 rcode=REFUSED for inlanefreight.com TXT)
;; QUESTION SECTION:
;inlanefreight.com.		IN	TXT

;; ANSWER SECTION:
inlanefreight.com.	300	IN	TXT	"HTB{5Fz6UPNUFFzqjdg0AzXyxCjMZ}"

;; Query time: 32 msec
;; SERVER: 1.1.1.1#53(1.1.1.1)
;; WHEN: Mon Jun 27 09:17:26 BST 2022
;; MSG SIZE  rcvd: 152
```

Or, with `nslookup`:

Code: shell

```shell
nslookup -type=TXT inlanefreight.com
```

```
┌─[us-academy-1]─[10.10.14.126]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ nslookup -type=TXT inlanefreight.com

Server:		1.1.1.1
Address:	1.1.1.1#53

Non-authoritative answer:
inlanefreight.com	text = "HTB{5Fz6UPNUFFzqjdg0AzXyxCjMZ}"

Authoritative answers can be found from:
```

Answer: `HTB{5Fz6UPNUFFzqjdg0AzXyxCjMZ}`

# DNS Records and Queries

## Question 2

### "Find out the corresponding IPv6 address of the domain "inlanefreight.com" and submit it as the answer."

Students can use either `dig` or `nslookup`, specifying the query type as `AAAA`.

With `dig`:

Code: shell

```shell
dig AAAA inlanefreight.com
```

```
┌─[us-academy-1]─[10.10.14.126]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ dig AAAA inlanefreight.com

; <<>> DiG 9.16.15-Debian <<>> AAAA inlanefreight.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 8763
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; EDE: 23 (Network Error): (178.128.39.165:53 rcode=REFUSED for inlanefreight.com DNSKEY)
;; QUESTION SECTION:
;inlanefreight.com.		IN	AAAA

;; ANSWER SECTION:
inlanefreight.com.	300	IN	AAAA	2a03:b0c0:1:e0::32c:b001

;; Query time: 140 msec
;; SERVER: 1.1.1.1#53(1.1.1.1)
;; WHEN: Mon Jun 27 09:28:41 BST 2022
;; MSG SIZE  rcvd: 140
```

Or, with `nslookup`:

Code: shell

```shell
nslookup -type=AAAA inlanefreight.com
```

```
┌─[us-academy-1]─[10.10.14.126]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ nslookup -type=AAAA inlanefreight.com

Server:		1.1.1.1
Address:	1.1.1.1#53

Non-authoritative answer:
Name:	inlanefreight.com
Address: 2a03:b0c0:1:e0::32c:b001
```

Answer: `2a03:b0c0:1:e0::32c:b001`

# DNS Enumeration

## Question 1

### "Perform a zone transfer for the "inlanefreight.htb" domain against your target and determine how many nameservers the company has. Submit the total number of nameservers as the answer."

Students need to perform a zone transfer with `dig` and use `grep` to filter the output for the `nameservers`:

Code: shell

```shell
dig axfr inlanefreight.htb @STMIP | grep ns
```

```
┌─[us-academy-1]─[10.10.14.126]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ dig axfr inlanefreight.htb @10.129.164.115 | grep "ns"

;; global options: +cmd
inlanefreight.htb.		3600	IN	SOA	ns1.inlanefreight.htb. adm.inlanefreight.htb. 8 3600 300 86400 600
inlanefreight.htb.		3600	IN	NS	ns1.inlanefreight.htb.
inlanefreight.htb.		3600	IN	NS	ns2.inlanefreight.htb.
ns1.inlanefreight.htb.	3600	IN	A	10.129.2.55
ns2.inlanefreight.htb.	3600	IN	A	10.129.2.58
inlanefreight.htb.		3600	IN	SOA	ns1.inlanefreight.htb. adm.inlanefreight.htb. 8 3600 300 86400 600
```

An alternative method would be without performing a zone transfer:

Code: shell

```shell
dig NS +short inlanefreight.htb @STMIP
```

```
┌─[us-academy-1]─[10.10.14.126]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ dig NS +short inlanefreight.htb @10.129.164.115

ns1.inlanefreight.htb.
ns2.inlanefreight.htb.
```

From the output of either methods, students will know that there are `2 nameservers`.

Answer: `2`

# DNS Enumeration

## Question 2

### "Determine the IPv4 address of "ns1.inlanefreight.htb" from your target and submit it as the answer."

Students need to perform a zone transfer with `dig` and use `grep` to filter the output for the `ns1.inlanefreight.htb` entry:

Code: shell

```shell
dig axfr inlanefreight.htb @STMIP | grep "ns1.inlanefreight.htb" | grep "A"
```

```
┌─[us-academy-1]─[10.10.14.126]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ dig axfr inlanefreight.htb @10.129.164.115 | grep "ns1.inlanefreight.htb" | grep "A"

inlanefreight.htb.		3600	IN	SOA	ns1.inlanefreight.htb. adm.inlanefreight.htb. 8 3600 300 86400 600
ns1.inlanefreight.htb.	3600	IN	A	10.129.2.55
inlanefreight.htb.		3600	IN	SOA	ns1.inlanefreight.htb. adm.inlanefreight.htb. 8 3600 300 86400 600
```

An alternative method would be without performing a zone transfer:

Code: shell

```shell
dig A +short ns1.inlanefreight.htb @STMIP
```

```
┌─[us-academy-1]─[10.10.14.126]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ dig A +short ns1.inlanefreight.htb @10.129.164.115

10.129.2.55
```

Answer: `10.129.2.55`

# DNS Enumeration

## Question 3

### "Perform a zone transfer against the target "inlanefreight.htb" domain and determine the IPv4 address of ns2.inlanefreight.htb and submit it as the answer."

Students need to perform a zone transfer with `dig` and use `grep` to filter the output for the `ns2.inlanefreight.htb` entry:

Code: shell

```shell
dig axfr inlanefreight.htb @STMIP | grep "ns2.inlanefreight.htb" | grep "A"
```

```
┌─[us-academy-1]─[10.10.14.126]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ dig axfr inlanefreight.htb @10.129.164.115 | grep "ns2.inlanefreight.htb" | grep "A"

ns2.inlanefreight.htb.	3600	IN	A	10.129.2.58
```

An alternative method would be without performing a zone transfer:

Code: shell

```shell
dig A +short ns2.inlanefreight.htb @STMIP
```

```
┌─[us-academy-1]─[10.10.14.126]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ dig A +short ns2.inlanefreight.htb @10.129.164.115

10.129.2.58
```

Answer: `10.129.2.58`

# DNS Enumeration

## Question 4

### "Check if a zone transfer against the target "inlanefreight.htb" domain because we could hear from the conversations with the administrators that they are not very familiar with DNS. As a proof of concept, a TXT record was left there to serve as evidence. Submit this TXT record as the answer."

Students need to perform a zone transfer with `dig` and use `grep` to filter the output for the `TXT` record:

Code: shell

```shell
dig axfr inlanefreight.htb @STMIP | grep "TXT"
```

```
┌─[us-academy-1]─[10.10.14.126]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ dig axfr inlanefreight.htb @10.129.164.115 | grep "TXT"

key.inlanefreight.htb.	3600	IN	TXT	"HTB{mgraRNhvDCPcKpzAXHA6cJUhW}"
```

Answer: `HTB{mgraRNhvDCPcKpzAXHA6cJUhW}`

# Main Function

## Question 1

### "Perform a zone transfer using the DNS-AXFR.py script against your target for the "inlanefreight.htb" domain and submit the total number of unique subdomains found."

After saving the "dnx-AXFR.py" Python script into a file, students need to use it against the domain `inlanefreight.htb`, setting the nameserver to be `STMIP`, as in the "NS.nameservers" variable:

Code: python

```python
NS.nameservers = ['STMIP']
```

Code: python

```python
#!/usr/bin/env python3

# Dependencies:
# python3-dnspython

# Used Modules:
import dns.zone as dz
import dns.query as dq
import dns.resolver as dr
import argparse

# Initialize Resolver-Class from dns.resolver as "NS"
NS = dr.Resolver()

# Target domain
Domain = 'inlanefreight.htb'

# Set the nameservers that will be used
NS.nameservers = ['10.129.164.162']

<SNIP>
```

Once students have saved the script file, they need to run it:

Code: shell

```shell
python3 dns-AXFR.py
```

```
┌─[us-academy-1]─[10.10.14.31]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ python3 dns-AXFR.py

[*] Successful Zone Transfer from 10.129.164.162
-------- Found Subdomains:
@.inlanefreight.htb
adm.inlanefreight.htb
blog.inlanefreight.htb
calvin.inlanefreight.htb
customer.inlanefreight.htb
dev.inlanefreight.htb
help.inlanefreight.htb
my.inlanefreight.htb
nadine.inlanefreight.htb
ns1.inlanefreight.htb
ns2.inlanefreight.htb
sarah.inlanefreight.htb
support.inlanefreight.htb
tom.inlanefreight.htb
www.inlanefreight.htb
```

To count the number of unique subdomains, students can use `grep` to exclude the entry starting with "@" and require that `.htb` is in each entry using regex, then pipe the output to `wc`:

```shell
python3 dns-AXFR.py | grep -o "^[^@].*htb" | wc -l
```
```
┌─[us-academy-1]─[10.10.14.50]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ python3 dns-AXFR.py | grep -o "^[^@].*htb" | wc -l

14
```

Thus, there are `14` unique subdomains.

Answer: `14`

# Argparse

## Question 1

### "Use this script against your target as the nameserver for the inlanefreight.htb domain and submit the total number of subdomains found as the answer."

After saving the "dnx-axfr.py" Python script into a file, students need to use it against the domain `inlanefreight.htb` utilizing the `-d` option, setting the nameserver to be `STMIP` using the `-n` option, using `grep` to filter out any unwanted string, and then piping the output to `wc`:

```shell
python3 dns-AXFR.py -d 'inlanefreight.htb' -n STMIP | grep -o "^[^@].*htb" | wc -l
```
```
┌─[us-academy-1]─[10.10.14.50]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ python3 dns-AXFR.py -d 'inlanefreight.htb' -n 10.129.185.157 | grep -o "^[^@].*htb" | wc -l

14
```

Similar to the previous question, there are `14` unique subdomains.

Answer: `14`