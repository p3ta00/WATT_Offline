| Section               | Question Number | Answer                                 |
| --------------------- | --------------- | -------------------------------------- |
| Locations             | Question 1      | 51.47311 6.88074                       |
| Locations             | Question 2      | 50.82838 -0.13947                      |
| Locations             | Question 3      | 39.73915 -104.9847                     |
| Locations             | Question 4      | Germany                                |
| Locations             | Question 5      | 14                                     |
| Staff                 | Question 1      | Max Cartmoon                           |
| Staff                 | Question 2      | 15                                     |
| Staff                 | Question 3      | 40                                     |
| Contact Information   | Question 1      | john.smith4@inlanefreight.com          |
| Contact Information   | Question 2      | enterprise-support@inlanefreight.com   |
| Business Records      | Question 1      | USD 276,000,000                        |
| Services              | Question 1      | InlaneConnect                          |
| Services              | Question 2      | 72                                     |
| Social Networks       | Question 1      | 4                                      |
| Public Domain Records | Question 1      | 2                                      |
| Public Domain Records | Question 2      | mail1.inlanefreight.com                |
| Public Domain Records | Question 3      | 2420436757\_DOMAIN\_COM-VRSN           |
| Public Domain Records | Question 4      | Amazon Registrar, Inc.                 |
| Public Domain Records | Question 5      | HTB{5Fz6UPNUFFzqjdg0AzXyxCjMZ}         |
| Domain Structure      | Question 1      | 2.4.41                                 |
| Domain Structure      | Question 2      | DigitalOcean, LLC (DO-13)              |
| Domain Structure      | Question 3      | AS14061                                |
| Domain Structure      | Question 4      | Ubuntu                                 |
| Domain Structure      | Question 5      | 9                                      |
| Cloud Storage         | Question 1      | inlanefreight-comp133.s3.amazonaws.htb |
| Email Addresses       | Question 1      | jeremy-ceo@inlanefreight.com           |
| Third Parties         | Question 1      | AWS                                    |
| Technologies in Use   | Question 1      | 5.6.14                                 |
| Technologies in Use   | Question 2      | ben\_theme                             |
| Technologies in Use   | Question 3      | WordFence                              |
| Internal Leaks        | Question 1      | HTB{1nt3rn4LL34Ks4r3C0mm0n}            |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Locations

## Question 1

### "What are the city's coordinates where one of the company's offices, "inlanefreight.com" has its headquarters in Germany? We suggest to use https://latitude.to for this. (DD Coordinates format: 00.00000 0.00000)"

Students need to browse to www.inlanefreight.com and click on `Offices`, to find three locations, `Brighton`, `Oberhausen`, and `Denver`:

![[HTB Solutions/Others/z. images/73d099c5febbc8da1d0f0c021caaa3ed_MD5.jpg]]

Subsequently, students need to search for `Oberhausen, Germany Coordinates latitude.io` (using any search engine), finding the coordinates in [latitude.to](https://latitude.to/map/de/germany/cities/oberhausen) to be `51.47311 6.88074`:

![[HTB Solutions/Others/z. images/2b4262a90531de3af9b0aeb04d04e741_MD5.jpg]]

Answer: `51.47311 6.88074`

# Locations

## Question 2

### "What are the city's coordinates where one of the company's offices, "inlanefreight.com" has its headquarters in United Kingdom? We suggest to use https://latitude.to for this. (DD Coordinates format: 00.00000 0.00000)"

Students need to search for `Brighton, UK Coordinates latitude.to` (using any search engine), finding the coordinates in [latitude.io](https://latitude.to/map/gb/united-kingdom/cities/brighton) to be `50.82838 -0.13947`:

![[HTB Solutions/Others/z. images/6fa0906c58e2b589f15552e0025aecaa_MD5.jpg]]

Answer: `50.82838 -0.13947`

# Locations

## Question 3

### "What are the city's coordinates where one of the company's offices, "inlanefreight.com" has its headquarters in USA? We suggest to use https://latitude.to for this. (DD Coordinates format: 00.00000 000.00000)"

Students need to search for `USA Denver Coordinates latitude.to` (using any search engine), finding the coordinates in [latitude.to](https://latitude.to/map/us/united-states/cities/denver) to be `39.73915 -104.9847`:

![[HTB Solutions/Others/z. images/096283e8d52b483c58be65ae25e65151_MD5.jpg]]

Answer: `39.73915 -104.9847`

# Locations

## Question 4

### "In which country is the chief financial officer located?"

Students need to navigate to www.inlanefreight.com and click on `About Us`:

![[HTB Solutions/Others/z. images/8f95adf8fb9efc1ff0150b8fa4f90d17_MD5.jpg]]

Students will know that the CFO is based in `Germany`:

![[HTB Solutions/Others/z. images/8dde157af9a6f7abfa300bd7dda4db1d_MD5.jpg]]

Answer: `Germany`

# Locations

## Question 5

### "How many locations does the company have in total?"

Students need to read the `About Us` page to find that there are `14` offices:

![[HTB Solutions/Others/z. images/13ab6cdb628c08986c3c6c53761a8cd0_MD5.jpg]]

Answer: `14`

# Staff

## Question 1

### "Check the website www.inlanefreight.com and find out the name of the chief operating officer and submit his full name as the answer."

First, students need to use a browser to view `http://www.inlanefreight.com`:

![[HTB Solutions/Others/z. images/8f95adf8fb9efc1ff0150b8fa4f90d17_MD5.jpg]]

Students need to click `About Us` and notice that `Max Cartmoon` is listed as the `COO`:

![[HTB Solutions/Others/z. images/1e94489265baa127f12d56fc5e1c8cf0_MD5.jpg]]

Answer: `Max Cartmoon`

# Staff

## Question 2

### "How many positions does the company Inlanefreight want to have filled in the future?"

Students need to click `Career`, scroll to the bottom and calculate the number of positions available:

![[HTB Solutions/Others/z. images/8a5e701746e1f4b1954759e6b131f5e0_MD5.jpg]]

There are a total of `15` positions available.

Answer: `15`

# Staff

## Question 3

### "How many logistics and software specialists does the Inlanefreight company employ at least?"

Students need to click on `Services` and scroll to the bottom:

![[HTB Solutions/Others/z. images/2160ae31e36f49c93ac912501b0c95fc_MD5.jpg]]

Students will find that there are `40` employees.

Answer: `40`

# Contact Information

## Question 1

### "Check the website www.inlanefreight.com and find out the email address of John Smith and submit it as the answer."

Students will browse to www.inlanefreight.com and click `contact`, to find the email of `John Smith` to be `john.smith4@inlanefreight.com`:

![[HTB Solutions/Others/z. images/1a29602436647682baafb747ff072ee8_MD5.jpg]]

Answer: `john.smith4@inlanefreight.com`

# Contact Information

## Question 2

### "What is the email address for enterprise customer support?"

Students need read the `Contact` page, scroll down to the bottom, and hover the mouse over the email address `enterprise@inlanefrieght.local` to find the email to be `enterprise-support@inlanefreight.com`:

![[HTB Solutions/Others/z. images/236a979b0b179fd3e406f5f6f13e39b7_MD5.jpg]]

Answer: `enterprise-support@inlanefreight.com`

# Business Records

## Question 1

### "Investigate the website www.inlanefreight.com and find out how much EBIT they recorded for the third quarter of 2020 and submit it as the answer. (Format example: USD 000,000,000)"

Students need to navigate to www.inlanefreight.com in a browser and click `News`:

![[HTB Solutions/Others/z. images/fdf851f0fd46348e0500f23613dba1ad_MD5.jpg]]

Students will find the EBIT value to be `USD 276,000,000`.

Answer: `USD 276,000,000`

# Services

## Question 1

### "Investigate the website www.inlanefreight.com and find out the name of the API application the company uses and submit it as the answer."

Students need to navigate to www.inlanefreight.com with a browser and click `Services`:

![[HTB Solutions/Others/z. images/48485bc7d1c3f3c6779b8e14f411307d_MD5.jpg]]

The website shows that the API is `InlaneConnect`.

Answer: `InlaneConnect`

# Services

## Question 2

### "How many liners does the company own in total?"

Students need to navigate to `About Us` to find that the total of `72` liners:

![[HTB Solutions/Others/z. images/334f9a780304c1f1353b7f2c11eb6ba7_MD5.jpg]]

Answer: `72`

# Social Networks

## Question 1

### "How many social networks are shown on the website of the company Inlanefreight?"

Students need to navigate to www.inlanefreight.com, scroll to the bottom of the page and view its footer:

![[HTB Solutions/Others/z. images/3f9efcab249ce4cf6d3d5fd3a06cc682_MD5.jpg]]

Students will see that there are `4` social media services in use.

Answer: `4`

# Public Domain Records

## Question 1

### "Find out how many nameservers are responsible for the inlanefreight.com domain and submit the number as the answer."

Students need to use `dig` on `inlanefreight.com` and specify `ns` as the query type to enumerate the nameservers:

Code: shell

```shell
dig ns inlanefreight.com | grep "inlane" | grep -v ";" | wc -l
```

```
┌─[us-academy-1]─[10.10.15.2]─[htb-ac330204@htb-vejm3fpawf]─[~]
└──╼ [★]$ dig ns inlanefreight.com | grep "inlane" | grep -v ";" | wc -l

2
```

Students will find that there are `2` nameservers.

Answer: `2`

# Public Domain Records

## Question 2

### "Find out the FQDN of the mail server of the inlanefreight.com domain and submit it as the answer."

Students need to use `dig` on `inlanefreight.com` and specify `mx` as the query type to enumerate the mail server of `inlanefreight.com`:

Code: shell

```shell
dig mx inlanefreight.com | grep mail | cut -d " " -f2
```

```
┌─[us-academy-1]─[10.10.15.2]─[htb-ac330204@htb-vejm3fpawf]─[~]
└──╼ [★]$ dig mx inlanefreight.com | grep mail | cut -d " " -f2

mail1.inlanefreight.com.
```

Students will see that the `FQDN` to be `mail1.inlanefreight.com`.

Answer: `mail1.inlanefreight.com`

# Public Domain Records

## Question 3

### "What is the registry domain ID of inlanefreight.com?"

Students need to use `whois` on `inlanefreight.com` and `grep` for `Registry Domain`:

Code: shell

```shell
whois inlanefreight.com | grep "Registry Domain" | cut -d " " -f 7
```

```
┌─[us-academy-2]─[10.10.14.9]─[htb-ac594497@htb-weirqzlvhe]─[~]
└──╼ [★]$ whois inlanefreight.com | grep "Registry Domain" | cut -d " " -f 7

2420436757_DOMAIN_COM-VRSN
```

Answer: `2420436757_DOMAIN_COM-VRSN`

# Public Domain Records

## Question 4

### "What is the name of the registrar of this domain?"

Students need to use `whois` on `inlanefreight.com` and `grep` for `Registrar`:

Code: shell

```shell
whois inlanefreight.com | grep "Registrar:" | cut -d" " -f5-7
```

```
┌─[us-academy-2]─[10.10.14.9]─[htb-ac594497@htb-weirqzlvhe]─[~]
└──╼ [★]$ whois inlanefreight.com | grep "Registrar:" | cut -d " " -f 5-7

Amazon Registrar, Inc.
```

Answer: `Amazon Registrar, Inc.`

# Public Domain Records

## Question 5

### "Examine the DNS records and submit the TXT record as the answer."

Students need to use `dig` on `inlanefreight.com` and specify `TXT` as the query type:

Code: shell

```shell
dig txt inlanefreight.com | grep com. | grep -v ";"
```

```
┌─[us-academy-2]─[10.10.14.9]─[htb-ac594497@htb-weirqzlvhe]─[~]
└──╼ [★]$ dig txt inlanefreight.com | grep com. | grep -v ";"

inlanefreight.com.	300	IN	TXT	"HTB{5Fz6UPNUFFzqjdg0AzXyxCjMZ}"
```

Answer: `HTB{5Fz6UPNUFFzqjdg0AzXyxCjMZ}`

# Domain Structure

## Question 1

### "Investigate the website www.inlanefreight.com and find out the Apache version of the webserver and submit it as the answer. (Format: 0.0.00)"

Students need to run `curl` with the `-l` option on `www.inlanefreight.com`:

Code: shell

```shell
curl -l www.inlanefreight.com
```

```
┌─[us-academy-2]─[10.10.14.9]─[htb-ac594497@htb-weirqzlvhe]─[~]
└──╼ [★]$ curl -l www.inlanefreight.com

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>301 Moved Permanently</title>
</head><body>
<h1>Moved Permanently</h1>
<p>The document has moved <a href="https://www.inlanefreight.com/">here</a>.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at www.inlanefreight.com Port 80</address>
</body></html>
```

From the output, students will know that the Apache version is `2.4.41`.

Answer: `2.4.41`

# Domain Structure

## Question 2

### "What is the hosting provider for the inlanefreight.com domain?"

First, students need to determine the IP address of `inlanefreight.com` using the command `host`:

Code: shell

```shell
host inlanefreight.com
```

```
┌─[us-academy-2]─[10.10.14.9]─[htb-ac594497@htb-tipu63nvq2]─[~]
└──╼ [★]$ host inlanefreight.com

inlanefreight.com has address 134.209.24.248
inlanefreight.com has IPv6 address 2a03:b0c0:1:e0::32c:b001
inlanefreight.com mail is handled by 10 mail1.inlanefreight.com.
```

The IP address is `134.209.24.248`. Thereafter, students need to use `whois` on the IP address and `grep` for "Organization":

Code: shell

```shell
whois 134.209.24.248 | grep Organization
```

```
┌─[us-academy-2]─[10.10.14.9]─[htb-ac594497@htb-tipu63nvq2]─[~]
└──╼ [★]$ whois 134.209.24.248 | grep Organization

Organization:   DigitalOcean, LLC (DO-13)
```

From the output of `whois`, students will know that the organization is `DigitalOcean, LLC`.

Answer: `DigitalOcean, LLC (DO-13)`

# Domain Structure

## Question 3

### "What is the ASN for the inlanefreight.com domain?"

From the previous question, students know that the IP address of `inlanefreight.com` is `134.209.24.248`, thus, they need to use `whois` on the IP address and `grep` for `OriginAS`:

Code: shell

```shell
whois 134.209.24.248 | grep OriginAS
```

```
┌─[us-academy-2]─[10.10.14.9]─[htb-ac594497@htb-tipu63nvq2]─[~]
└──╼ [★]$ whois 134.209.24.248 | grep OriginAS

OriginAS:       AS14061
```

Answer: `AS14061`

# Domain Structure

## Question 4

### "On which operating system is the webserver www.inlanefreight.com running?"

Students need to browse to www.inlanefreight.com and check `Wappalyzer`, to know that the OS is `Ubuntu`:

![[HTB Solutions/Others/z. images/a662fbe7886d85e66a684ed1503c4883_MD5.jpg]]

Answer: `Ubuntu`

# Domain Structure

## Question 5

### "How many JS resources are there on the Inlanefreight website?"

Students need to use [SEOptimer](https://enterprise.hackthebox.com/academy-lab/43009/3329/modules/28/www.seoptimer.com) and search for www.inlanefreight.com:

![[HTB Solutions/Others/z. images/57e1bbbc40ed4bcf40e695ca56b1d424_MD5.jpg]]

![[HTB Solutions/Others/z. images/d3360a4053895d8f36c15b0fd2ac9770_MD5.jpg]]

Students will find that there are `9` Javascript resources being utilized by `inlanefreight.local`.

Answer: `9`

# Cloud Storage

## Question 1

### "Investigate the website and find the bucket name of AWS that the company used and submit it as the answer. (Format: sub.domain.tld)"

Students need to browse to www.inlanefreight.com/index.php/news/, and view the page's source to find the bucket name `inlanefreight-comp133.s3.amazonaws.htb` in a HTML comment at line 241:

![[HTB Solutions/Others/z. images/fdce1947ff845b9019dad8e0a9d485c3_MD5.jpg]]

Answer: `inlanefreight-comp133.s3.amazonaws.htb`

# Email Addresses

## Question 1

### "What is the email address of the CEO?"

Students need to browse to https://www.inlanefreight.com/index.php/about-us/, and view the page's source to find the email address `jeremy-ceo@inlanefreight.com`:

![[HTB Solutions/Others/z. images/c3be9c5e809aded75ce50426a0ef68a9_MD5.jpg]]

Answer: `jeremy-ceo@inlanefreight.com`

# Third Parties

## Question 1

### "Investigate the website www.inlanefreight.com and find out which cloud provider the company most likely focuses on and submit it as the answer."

Students need to browse to https://www.inlanefreight.com/index.php/career/ and observe open positions for "AWS Networking" and "AWS Architect":

![[HTB Solutions/Others/z. images/8f804686f01ad3dfaaf1c8f8e18c43b7_MD5.jpg]]

Answer: `AWS`

# Technologies in Use

## Question 1

### "Which version of WordPress is used on the Inlanefreight domain page?"

Students need to use `curl` on `www.inlanefreight.com` and find the WordPress version in the `meta` tag.

Code: shell

```shell
curl -s -X GET https://www.inlanefreight.com | grep '<meta name="generator"'
```

```
┌─[us-academy-3]─[10.10.14.209]─[htb-ac-8414@htb-dmnczcu8by]─[~]
└──╼ [★]$ curl -s -X GET https://www.inlanefreight.com | grep '<meta name="generator"'

<meta name="generator" content="WordPress 5.6.14" />
```

Answer: `5.6.14`

# Technologies in Use

## Question 2

### "What is the name of the theme that is used on the WordPress site?"

Students need to browse to www.inlanefreight.com and view the page source to find several references to `ben_theme`:

![[HTB Solutions/Others/z. images/41750381b71e7d47a880d1a06a196e7c_MD5.jpg]]

Answer: `ben_theme`

# Technologies in Use

## Question 3

### Which WAF is being used? (Format: <name>)

Students need to browse to www.inlanefreight.com and notice that under the website's name, it says that it is "Protected by `Wordfence`":

![[HTB Solutions/Others/z. images/d77f7f6584c2de32d4a5ff6e1c318f28_MD5.jpg]]

Answer: `Wordfence`

# Internal Leaks

## Question 1

### "Investigate the website www.inlanefreight.com and try to find any additional information that a file might contain and submit the found flag as the answer."

First, students need to browse to www.inlanefreight.com and navigate to News:

![[HTB Solutions/Others/z. images/bfc533a4e1e90cb5764fef3b3de6abc7_MD5.jpg]]

Then, students need to scroll to the bottom of the page to notice that there is a downloadable "Inlanefreight-Goals" document:

![[HTB Solutions/Others/z. images/fa2fbf6983a7355737c16f2cd1168fc6_MD5.jpg]]

Students need to download [goals.pdf](https://www.inlanefreight.com/wp-content/uploads/2020/09/goals.pdf):

Code: shell

```shell
get https://www.inlanefreight.com/wp-content/uploads/2020/09/goals.pdf
```

```
┌─[us-academy-1]─[10.10.14.244]─[htb-ac594497@htb-xbyj0nqeoa]─[~]
└──╼ [★]$ wget https://www.inlanefreight.com/wp-content/uploads/2020/09/goals.pdf

--2023-02-02 16:31:57--  https://www.inlanefreight.com/wp-content/uploads/2020/09/goals.pdf
Resolving www.inlanefreight.com (www.inlanefreight.com)... 134.209.24.248, 2a03:b0c0:1:e0::32c:b001
Connecting to www.inlanefreight.com (www.inlanefreight.com)|134.209.24.248|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 52483 (51K) [application/pdf]
Saving to: ‘goals.pdf’

goals.pdf           100%[===================>]  51.25K  --.-KB/s    in 0.02s   

2023-02-02 16:31:57 (2.10 MB/s) - ‘goals.pdf’ saved [52483/52483]
```

Subsequently, students need to run `exiftool` against "goals.pdf", to attain the flag `HTB{1nt3rn4LL34Ks4r3C0mm0n}` as the value for the `Creator` field:

Code: shell

```shell
exiftool goals.pdf 
```

```
┌─[us-academy-1]─[10.10.14.244]─[htb-ac594497@htb-xbyj0nqeoa]─[~]
└──╼ [★]$ exiftool goals.pdf 

ExifTool Version Number         : 12.16
File Name                       : goals.pdf
Directory                       : .
File Size                       : 51 KiB
File Modification Date/Time     : 2020:09:10 22:46:55+01:00
File Access Date/Time           : 2023:02:02 16:31:57+00:00
File Inode Change Date/Time     : 2023:02:02 16:31:57+00:00
File Permissions                : rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Producer                        : Skia/PDF m87
Page Count                      : 2
XMP Toolkit                     : Image::ExifTool 12.00
Creator                         : HTB{1nt3rn4LL34Ks4r3C0mm0n}
```

Answer: `HTB{1nt3rn4LL34Ks4r3C0mm0n}`