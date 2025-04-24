```rust
❯ nmap -sN 10.10.110.0/24

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-14 21:14 EDT
Nmap scan report for 10.10.110.1
Host is up (0.024s latency).
All 1000 scanned ports on 10.10.110.1 are in ignored states.
Not shown: 1000 open|filtered tcp ports (no-response)

Nmap scan report for 10.10.110.2
Host is up (0.023s latency).
All 1000 scanned ports on 10.10.110.2 are in ignored states.
Not shown: 1000 open|filtered tcp ports (no-response)

Nmap scan report for 10.10.110.21
Host is up (0.035s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE         SERVICE
22/tcp   open|filtered ssh
80/tcp   open|filtered http
3000/tcp open|filtered ppp

Nmap scan report for 10.10.110.100
Host is up (0.081s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE         SERVICE
22/tcp open|filtered ssh

Nmap done: 256 IP addresses (4 hosts up) scanned in 41.92 seconds
```

# Internal 
```rust
Scanning 172.16.0.1 for the top 100 ports...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-15 21:54 EDT
Nmap scan report for 172.16.0.1
Host is up (0.020s latency).
Not shown: 96 filtered tcp ports (no-response)
PORT    STATE SERVICE
22/tcp  open  ssh
53/tcp  open  domain
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 1.99 seconds
Scanning 172.16.0.2 for the top 100 ports...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-15 21:54 EDT
Nmap scan report for 172.16.0.2
Host is up (0.033s latency).
Not shown: 88 closed tcp ports (reset)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 0.38 seconds
Scanning 172.16.0.3 for the top 100 ports...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-15 21:54 EDT
Nmap scan report for 172.16.0.3
Host is up (0.079s latency).
Not shown: 98 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 0.42 seconds
Scanning 172.16.0.20 for the top 100 ports...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-15 21:54 EDT
Nmap scan report for 172.16.0.20
Host is up (0.077s latency).
Not shown: 98 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.42 seconds
Scanning 172.16.0.21 for the top 100 ports...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-15 21:54 EDT
Nmap scan report for 172.16.0.21
Host is up (0.058s latency).
Not shown: 97 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp

Nmap done: 1 IP address (1 host up) scanned in 0.38 seconds
Scanning 172.16.0.32 for the top 100 ports...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-15 21:54 EDT
Nmap scan report for 172.16.0.32
Host is up (0.046s latency).
Not shown: 97 closed tcp ports (reset)
PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 0.41 seconds
Scanning 172.16.0.33 for the top 100 ports...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-15 21:54 EDT
Nmap scan report for 172.16.0.33
Host is up (0.061s latency).
Not shown: 96 closed tcp ports (reset)
PORT     STATE SERVICE
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 0.39 seconds

```
