
| Section | Question Number | Answer |
| --- | --- | --- |
| HTML | Question 1 | <img> |
| Cascading Style Sheets (CSS) | Question 1 | text-align: left; |
| Sensitive Data Exposure | Question 1 | HiddenInPlainSight |
| HTML Injection | Question 1 | Your name is Click Me |
| Cross-Site Scripting (XSS) | Question 1 | XSSisFun |
| Back End Servers | Question 1 | Windows |
| Web Servers | Question 1 | Created |
| Databases | Question 1 | NoSQL |
| Development Frameworks & APIs | Question 1 | superadmin |
| Common Web Vulnerabilities | Question 1 | Command Injection |
| Public Vulnerabilities | Question 1 | 9.3 |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Basic Tools

## Question 1

### "What is the HTML tag used to show an image?"

According to [W3Schools](https://www.w3schools.com/tags/tag_img.asp), the HTML tag used for showing images is `<img>`.

Answer: `<img>`

# Cascading Style Sheets (CSS)

## Question 1

### "What is the CSS "property: value" used to make an HTML element's text aligned to the left?"

According to [W3Schools](https://www.w3schools.com/cssref/pr_text_text-align.ASP), `text-align: left;` is used to make an HTML element's text aligned to the left.

Answer: `text-align: left;`

# Sensitive Data Exposure

## Question 1

### "Check the above login form for exposed passwords. Submit the password as the answer."

After spawning the target machine and navigating to the login form located in the root webpage, students need to view the webpage's source to find the exposed password `HiddenInPlainSight` on line 58:

![[HTB Solutions/CBBH/z. images/892ae0a9dadebea37829b15ecbccbe07_MD5.jpg]]

Answer: `HiddenInPlainSight`

# HTML Injection

## Question 1

### "What text would be displayed on the page if we use the following payload as our input: <a href="http://www.hackthebox.com">Click Me</a>".

After spawning the target machine and navigating to its web page, students need to click on the "Click to enter your name" button, then provide `<a href="http://www.hackthebox.com">Click Me</a>` as input:

![[HTB Solutions/CBBH/z. images/47d4d0013b5761838b16d88e86d35981_MD5.jpg]]

Subsequently, students will get "Your name is Click Me" on the web page, which is the answer:

![[HTB Solutions/CBBH/z. images/4c2345a56ed7888c82eba64b8250b8e4_MD5.jpg]]

Answer: `Your name is Click Me`

# Cross-Site Scripting (XSS)

## Question 1

### "Try to use XSS to get the cookie value in the above page"

After spawning the target machine and navigating to its root webpage, students need to click on the "Click to enter your name" button, then provide as input:

```javascript
#"<img src=/ onerror=alert(document.cookie)>
```

![[HTB Solutions/CBBH/z. images/47bda6ca825c49640f487be2eba16aac_MD5.jpg]]

Subsequently, students will get the JS alert dialog, with the flag `XSSisFun` provided as the value of the cookie:

![[HTB Solutions/CBBH/z. images/0c5e86e397472e3034e29ffa8e3ca5f3_MD5.jpg]]

Answer: `XSSisFun`

# Back End Servers

## Question 1

### "What operating system is 'WAMP' used with?"

`WAMP` is a web solution stack consisting of `Windows`, `Apache`, `MySQL`, and `PHP`.

Answer: `Windows`

# Web Servers

## Question 1

### "If a web server returns an HTTP code 201, what does it stand for?"

According to the [MDN Web Docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/201), the `201 Created success status response` "indicates that the request has succeeded and has led to the creation of a resource".

Answer: `Created`

# Databases

## Question 1

### "What type of databases is Google's Firebase Database?"

[Firebase Realtime Database](https://firebase.google.com/docs/database) is a `NoSQL` database.

Answer: `NoSQL`

# Development Frameworks & APIs

## Question 1

### "Use GET request '/index.php?id=0' to search for the name of the user with id number 1?"

After spawning the target machine, students need to use a GET request that requests the user with `id` number one, to attain the username `superadmin`:

```
http://STMIP:STMPO/index.php?id=1
```

![[HTB Solutions/CBBH/z. images/da82c68104dac4ecbdf100a0f0180f4f_MD5.jpg]]

Answer: `superadmin`

# Common Web Vulnerabilities

## Question 1

### "To which of the above categories does public vulnerability 'CVE-2014-6271' belongs to?"

According to [CVE MITRE](https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2014-6271), `CVE-2014-6271` is a `Command Injection` vulnerability.

Answer: `Command Injection`

# Public Vulnerabilities

## Question 1

### "What is the CVSS score of the public vulnerability CVE-2017-0144?"

According to [CVE Details](https://www.cvedetails.com/cve/CVE-2017-0144/), `CVE-2017-0144` has a CVSS score of `9.3`.

Answer: `9.3`