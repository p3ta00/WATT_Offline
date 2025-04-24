```rust
│172.17.0.1
│172.17.0.3
│172.17.0.10
│172.17.0.11
│172.17.0.34
│172.17.0.50
```

```rust
Scanning 172.17.0.1 for the top 100 ports...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-17 00:38 EDT
Nmap scan report for 172.17.0.1
Host is up (0.000029s latency).
Not shown: 98 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
8443/tcp open  https-alt

Nmap done: 1 IP address (1 host up) scanned in 0.17 seconds
Scanning 172.17.0.3 for the top 100 ports...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-17 00:38 EDT
Nmap scan report for 172.17.0.3
Host is up (0.058s latency).
Not shown: 98 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 0.43 seconds
Scanning 172.17.0.10 for the top 100 ports...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-17 00:38 EDT
Nmap scan report for 172.17.0.10
Host is up (0.053s latency).
Not shown: 98 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp

Nmap done: 1 IP address (1 host up) scanned in 0.36 seconds
Scanning 172.17.0.11 for the top 100 ports...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-17 00:38 EDT
Nmap scan report for 172.17.0.11
Host is up (0.37s latency).
Not shown: 99 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 1.67 seconds
Scanning 172.17.0.34 for the top 100 ports...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-17 00:38 EDT
Nmap scan report for 172.17.0.34
Host is up (0.068s latency).
Not shown: 92 closed tcp ports (reset)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 0.44 seconds
Scanning 172.17.0.50 for the top 100 ports...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-17 00:38 EDT
Nmap scan report for 172.17.0.50
Host is up (0.046s latency).
Not shown: 98 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
9100/tcp open  jetdirect

Nmap done: 1 IP address (1 host up) scanned in 0.37 seconds

```

```rust
 ./smb_sweep.sh
unning smbclient for IP: 172.17.0.1
o_connect: Connection to 172.17.0.1 failed (Error NT_STATUS_CONNECTION_REFUSED)
unning smbclient for IP: 172.17.0.3
o_connect: Connection to 172.17.0.3 failed (Error NT_STATUS_CONNECTION_REFUSED)
unning smbclient for IP: 172.17.0.10
o_connect: Connection to 172.17.0.10 failed (Error NT_STATUS_CONNECTION_REFUSED)
unning smbclient for IP: 172.17.0.11
o_connect: Connection to 172.17.0.11 failed (Error NT_STATUS_CONNECTION_REFUSED)
unning smbclient for IP: 172.17.0.34

       Sharename       Type      Comment
       ---------       ----      -------
       ADMIN$          Disk      Remote Admin
       C$              Disk      Default share
       IPC$            IPC       Remote IPC
       Share           Disk      
econnecting with SMB1 for workgroup listing.
o_connect: Connection to 172.17.0.34 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
nable to connect with SMB1 -- no workgroup available
unning smbclient for IP: 172.17.0.50
o_connect: Connection to 172.17.0.50 failed (Error NT_STATUS_CONNECTION_REFUSED)

```