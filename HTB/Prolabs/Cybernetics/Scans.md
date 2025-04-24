## Hosts
```
10.10.110.12    certenroll.cyber.local
10.10.110.15    cygw.cyber.local 10.10.110.12 gateway.cyber.local
```

## Nmap ping sweep
```rust
nmap -sn 10.10.110.0/24 -oG - | grep "Up" | cut -d " " -f 2 > alive_hosts.txt
```

## Python Ping Sweep
```
 python pingsweep.py
Attempting to ping 10.10.110.1...
Failure: 10.10.110.1 did not respond.
Attempting to ping 10.10.110.2...
Success: 10.10.110.2 responded.
```
Two is designated for the lab ignore

```rust
❯ cat alive_hosts.txt
10.10.110.10
10.10.110.11
10.10.110.12
10.10.110.15
10.10.110.250
```

## Rustscan
```rust
rustscan -a 10.10.110.[ip] -- -A -sC -sV -Pn
```
### 10.10.110.10
```rust
PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Microsoft IIS httpd 10.0
|_http-favicon: Unknown favicon MD5: 2DE6897008EB657D2EC770FE5B909439
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
| http-robots.txt: 30 disallowed entries 
| /admin/ /App_Browsers/ /App_Code/ /App_Data/ 
| /App_GlobalResources/ /bin/ /Components/ /Config/ /contest/ /controls/ 
| /DesktopModules/ /Documentation/ /HttpModules/ /images/ /Install/ /js/ 
| /Portals/ /Providers/ /Resources/ContentRotator/ 
| /Resources/ControlPanel/ /Resources/Dashboard/ /Resources/FeedBrowser/ 
| /Resources/OpenForceAd/ /Resources/Search/ /Resources/Shared/ 
| /Resources/SkinWidgets/ /Resources/TabStrip/ /Resources/Widgets/ 
|_/Activity-Feed/userId/ /*/ctl/
|_http-title: Home
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

### 10.10.110.11
```rust
PORT    STATE SERVICE  REASON  VERSION
80/tcp  open  http     syn-ack Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
443/tcp open  ssl/http syn-ack Microsoft IIS httpd 10.0
| tls-alpn: 
|   h2
|_  http/1.1
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
|_ssl-date: 2024-02-06T05:31:22+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=certenroll.cyber.local
| Issuer: commonName=Cyber-CA/domainComponent=cyber
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: ecdsa-with-SHA256
| Not valid before: 2024-01-13T06:54:32
| Not valid after:  2026-01-12T06:54:32
| MD5:   5083:51d1:f465:a511:ef2d:9186:ace3:9ffd
| SHA-1: 2320:5c90:75f1:1a1f:f85d:1825:7162:786b:8baa:a3fb
| -----BEGIN CERTIFICATE-----
| MIIEcDCCBBegAwIBAgITJgAACYghqv6ahMKNTgAAAAAJiDAKBggqhkjOPQQDAjBB
| MRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxFTATBgoJkiaJk/IsZAEZFgVjeWJlcjER
| MA8GA1UEAxMIQ3liZXItQ0EwHhcNMjQwMTEzMDY1NDMyWhcNMjYwMTEyMDY1NDMy
| WjAhMR8wHQYDVQQDExZjZXJ0ZW5yb2xsLmN5YmVyLmxvY2FsMIIBIjANBgkqhkiG
| 9w0BAQEFAAOCAQ8AMIIBCgKCAQEAptD1UvUhpThYNVxjA+8KBmXmER42LAlNzRze
| oxmuxfH1O6co7XMhTQUnWLRVtiuFatPilqOv8nCY8y4/6rzvZvSPk9xJVelY7qEW
| Vtlvphsqup+ZB6S+nJQ1CMcS+NocyhwVaFbyevL2LZoud6PEjVq1chFOQcbieojL
| AWwgLj1Xmu8WqOwOaSbXaB9vOl2/BfEyfDGTpu14PbihrcVsIjnFP5y69D/AI6FK
| hwS9DpduO7pXDU4zBZeSoO9ae1dtCA2o/QlmkMA0/CKdt4yj/3ZVXCyt8kRvgQ7I
| dSbzbIEI4uDDJKFvzLy9k0Tq/2RSF6Bxoa3qbY8MmfBnaBE/YQIDAQABo4ICQTCC
| Aj0wNgYJKwYBBAGCNxUHBCkwJwYfKwYBBAGCNxUIh7uVNJ+RM4aJjTiE1p1mgdXE
| I2kBIwIBZAIBATATBgNVHSUEDDAKBggrBgEFBQcDATAOBgNVHQ8BAf8EBAMCBaAw
| GwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUFPJE8tNaWyaS
| P81Wpm7s8j7exG4wHwYDVR0jBBgwFoAUMQqjBPCHsx61oqXqqcLpYWOQrCIwgcMG
| A1UdHwSBuzCBuDCBtaCBsqCBr4aBrGxkYXA6Ly8vQ049Q3liZXItQ0EsQ049Y3lk
| YyxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMs
| Q049Q29uZmlndXJhdGlvbixEQz1jeWJlcixEQz1sb2NhbD9jZXJ0aWZpY2F0ZVJl
| dm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9p
| bnQwgboGCCsGAQUFBwEBBIGtMIGqMIGnBggrBgEFBQcwAoaBmmxkYXA6Ly8vQ049
| Q3liZXItQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Y3liZXIsREM9bG9jYWw/Y0FDZXJ0
| aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkw
| CgYIKoZIzj0EAwIDRwAwRAIgFEg83TWnxwe4lL8oUpJYtVIE1q4YvzoDCgO6h2qP
| tnsCID48kVoQRkypvSpOaNKebzefXjFHJw/g+kcDGhoDes4X
|_-----END CERTIFICATE-----
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 0s
```

## 10.10.110.12
```rust
nmap -sCV -T4 -p- 10.10.110.12
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-05 21:39 PST
Nmap scan report for 10.10.110.12
Host is up (0.090s latency).
Not shown: 65531 filtered tcp ports (no-response)
PORT      STATE  SERVICE VERSION
80/tcp    open   http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
443/tcp   closed https
3391/tcp  closed savant
49443/tcp closed unknown
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

### 10.10.110.15
```rust
PORT    STATE SERVICE  REASON  VERSION
80/tcp  open  http     syn-ack Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
443/tcp open  ssl/http syn-ack Microsoft IIS httpd 10.0
| ssl-cert: Subject: commonName=cygw.cyber.local
| Subject Alternative Name: DNS:gateway.cyber.local
| Issuer: commonName=Cyber-CA/domainComponent=cyber
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: ecdsa-with-SHA256
| Not valid before: 2020-06-03T03:39:02
| Not valid after:  2022-06-03T03:39:02
| MD5:   acbd:38b1:c67f:07ee:0b9b:76a6:d71e:96f1
| SHA-1: 1974:25b5:aeac:91c9:404e:f243:e0cd:0488:b649:927b
| -----BEGIN CERTIFICATE-----
| MIIEizCCBDGgAwIBAgITJgAAADv1gFPTZQCCkgAAAAAAOzAKBggqhkjOPQQDAjBB
| MRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxFTATBgoJkiaJk/IsZAEZFgVjeWJlcjER
| MA8GA1UEAxMIQ3liZXItQ0EwHhcNMjAwNjAzMDMzOTAyWhcNMjIwNjAzMDMzOTAy
| WjAbMRkwFwYDVQQDExBjeWd3LmN5YmVyLmxvY2FsMIIBIjANBgkqhkiG9w0BAQEF
| AAOCAQ8AMIIBCgKCAQEA1Cf5cPThNbw2Ne1M83n4wWKAMcLVQ0CuJo9na1F6d8s2
| j5wg0cVYMiD7yy8FdNyqphi52H/q0vpOZYGzf1DmRpjSnTeQH6UgcwWczi04IRht
| WjAok56Dmt8IIdK0J5MtsOLws5IF3KXtZ1xxp4Uf9c8ZYQo4lfTNFXC0mCEK4FET
| SviNRsW4923YSiGZjWHWoXlc/jv0PhGQOLX/kDi2LqPkwgdnyL8wyffveUbcuTS6
| sAONylvSjft/7vp/pNqaW/DraPzZA+nlk9HC0KOzJX9YQCbx8jb4XOGOiAf8oR3I
| aJz5dPliXFwLP0+3T1CVRFGM4mD+ujyNO1CHvhAiLQIDAQABo4ICYTCCAl0wNgYJ
| KwYBBAGCNxUHBCkwJwYfKwYBBAGCNxUIh7uVNJ+RM4aJjTiE1p1mgdXEI2kBIwIB
| ZAIBATAbBgkrBgEEAYI3FQoEDjAMMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIF
| oDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUJjhiijN4gfUHu0MaN1o9
| B7MqXvwwHgYDVR0RBBcwFYITZ2F0ZXdheS5jeWJlci5sb2NhbDAfBgNVHSMEGDAW
| gBQxCqME8IezHrWipeqpwulhY5CsIjCBwwYDVR0fBIG7MIG4MIG1oIGyoIGvhoGs
| bGRhcDovLy9DTj1DeWJlci1DQSxDTj1jeWRjLENOPUNEUCxDTj1QdWJsaWMlMjBL
| ZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWN5
| YmVyLERDPWxvY2FsP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmpl
| Y3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBugYIKwYBBQUHAQEEga0wgaow
| gacGCCsGAQUFBzAChoGabGRhcDovLy9DTj1DeWJlci1DQSxDTj1BSUEsQ049UHVi
| bGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv
| bixEQz1jeWJlcixEQz1sb2NhbD9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xh
| c3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTAKBggqhkjOPQQDAgNIADBFAiBT7eCA
| OSL1ztJNc4nPBBxPpEd//aeHNjWpAwXzquevhAIhAN9SDNl7Z3tqlt416xQoJrRM
| mFEdd3iW7LV79XxKvXaG
|_-----END CERTIFICATE-----
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
|_ssl-date: 2024-02-06T05:35:38+00:00; -1s from scanner time.
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
| tls-alpn: 
|_  http/1.1
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1s
```