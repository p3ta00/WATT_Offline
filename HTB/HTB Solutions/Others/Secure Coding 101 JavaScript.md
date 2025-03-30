| Section           | Question Number | Answer                                                    |
| ----------------- | --------------- | --------------------------------------------------------- |
| Unpacking         | Question 1      | HTB{y0u\_5h0uld\_n3v3r\_run\_un7ru573d\_0bfu5c473d\_c0d3} |
| Dead Code         | Question 1      | \_0xeaa3                                                  |
| Encrypted Array   | Question 1      | 23                                                        |
| OtherFunction     | Question 1      | thPbnu16zZjnmG==                                          |
| Custom Decoder    | Question 1      | GET                                                       |
| Decoding          | Question 1      | 2b20b9095653112d362d673bd7ddb2f8                          |
| SendCode          | Question 1      | unSqyU7wQc7uFRBV                                          |
| Skills Assessment | Question 1      | HTB{p4ck3d\_w17h\_d34d\_c0d3}                             |
| Skills Assessment | Question 2      | HTB{574y\_54f3\_w17h\_57471c\_4n4ly515}                   |
| Skills Assessment | Question 3      | HTB{dyn4m1c4lly\_br34k1n6\_4nd\_w47ch1n6}                 |
| Skills Assessment | Question 4      | HTB{j4v45cr1p7\_r3v3r51n6\_m4573r}                        |
| Skills Assessment | Question 5      | HTB{J4v45cr1p7\_53cur3\_c0d1n6\_m4573r!}                  |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Unpacking

## Question 1

### "Run the example shown above, and try to access it. Using what you learned in this section, try to unpack the JavaScript code, and retrieve the flag."

After spawning the target machine, students need to open the root page of its website and view its source `view-source:http://STMIP:STMPO/`, to find the JavaScript file `flag.js` being included as a script:

![[HTB Solutions/Others/z. images/b91f60bde1f76b4c6f1e2ba24352b81e_MD5.jpg]]

Students need to open the file and copy the JavaScript code within it:

![[HTB Solutions/Others/z. images/4fb03bd4dac8391fbfbb1d4938ff6010_MD5.jpg]]

Code: javascript

```javascript
eval(function (p, a, c, k, e, d) { e = function (c) { return c.toString(36) }; if (!''.replace(/^/, String)) { while (c--) { d[c.toString(a)] = k[c] || c.toString(a) } k = [function (e) { return d[e] }]; e = function () { return '\\w+' }; c = 1 }; while (c--) { if (k[c]) { p = p.replace(new RegExp('\\b' + e(c) + '\\b', 'g'), k[c]) } } return p }('d 0(){c 0=\'b{a\'+\'9\'+\'8\'+\'7\'+\'6\'+\'5\'+\'4\'+\'3\'+\'2\'+\'1\'+\'}\'}', 14, 14, 'flag|_c0d3|c473d|0bfu5|573d_|un7ru|_run_|n3v3r|0uld_|0u_5h|y|HTB|var|function'.split('|'), 0, {}))
```

Then, students need to paste the JavaScript code into [JSConsole](https://jsconsole.com/), replacing `return p` with `console.log(p)`:

Code: javascript

```javascript
eval(function (p, a, c, k, e, d) { e = function (c) { return c.toString(36) }; if (!''.replace(/^/, String)) { while (c--) { d[c.toString(a)] = k[c] || c.toString(a) } k = [function (e) { return d[e] }]; e = function () { return '\\w+' }; c = 1 }; while (c--) { if (k[c]) { p = p.replace(new RegExp('\\b' + e(c) + '\\b', 'g'), k[c]) } } console.log(p) }('d 0(){c 0=\'b{a\'+\'9\'+\'8\'+\'7\'+\'6\'+\'5\'+\'4\'+\'3\'+\'2\'+\'1\'+\'}\'}', 14, 14, 'flag|_c0d3|c473d|0bfu5|573d_|un7ru|_run_|n3v3r|0uld_|0u_5h|y|HTB|var|function'.split('|'), 0, {}))
```

![[HTB Solutions/Others/z. images/ed14e5550949dcf552bec228e26aa692_MD5.jpg]]

Students need to copy the variable `flag` and paste it in the console again, subsequently printing it out:

Code: javascript

```javascript
var flag='HTB{y'+'0u_5h'+'0uld_'+'n3v3r'+'_run_'+'un7ru'+'573d_'+'0bfu5'+'c473d'+'_c0d3'+'}'
console.log(flag)
```

![[HTB Solutions/Others/z. images/ba232475801b8637b2c7c79154bfbeaa_MD5.jpg]]

Answer: `HTB{y0u_5h0uld_n3v3r_run_un7ru573d_0bfu5c473d_c0d3}`

# Dead Code

## Question 1

### "Try to replicate what you learned so far to completely unpack 'sendCode.js' and strip all dead code and unnecessary functions. What is the name of the very last dead function you removed?"

After spawning the target machine, students need to open the root page of its website and view its source `view-source:http://STMIP:STMPO/`, to find the JavaScript file `sendCode.js` being included as a script:

![[HTB Solutions/Others/z. images/60a28900d5c45d2ed84f908f2ec41d52_MD5.jpg]]

![[HTB Solutions/Others/z. images/668f5bdf11780bc32f88cef971135f3d_MD5.jpg]]

Students then need to perform recursive unpacking, following the steps:

- Finding a packer function that starts with `eval(function (p, a, c, k, e, <SNIP>))`
- Cutting the function from Prettier
- Going to JS Console and running the command `console.log(p)`
- Copying the output back into Prettier, in place of the function that was cut
- Copy the beautified code on the right side to the left
- Repeat all the previous steps

Therefore, students need to first paste the JavaScript code into [Prettier](https://prettier.io/playground) and notice that the command `return p;` is on line 28:

![[HTB Solutions/Others/z. images/06ad03d2203f94b8d97839461d89bc11_MD5.jpg]]

Students need to copy the prettified `JavaScript` code and paste it in `JSConsole`, replacing `return p;` with `console.log(p);`:

![[HTB Solutions/Others/z. images/210f6e9fd343705e266358a0795be645_MD5.jpg]]

After hitting Enter on the keyboard, students will notice that the original function is printed:

![[HTB Solutions/Others/z. images/1887cf84304609b7979095c01c9a9046_MD5.jpg]]

Subsequently, students need to copy the printed original function and paste it into [Prettier](https://prettier.io/playground):

![[HTB Solutions/Others/z. images/06c5f3fdaf32beb24338bdb26521dc7c_MD5.jpg]]

However, the code is still highly obfuscated, thus, students need to perform the previous steps all again, starting with copying the prettified code and pasting it into [JSConsole](https://jsconsole.com/), and replacing `return p;` on line 184 with `console.log(p);`:

![[HTB Solutions/Others/z. images/ee023ba6ed4387a4fd1ad7a40d1f0451_MD5.jpg]]

![[HTB Solutions/Others/z. images/da40c2e143d8f19083fde5583f72a4fa_MD5.jpg]]

After hitting Enter on the keyboard, students will notice that the original function is printed:

![[HTB Solutions/Others/z. images/97bda0e83f9ddcce66185f4c1be1d92e_MD5.jpg]]

Subsequently, students need to copy the printed original function and paste it into [Prettier](https://prettier.io/playground):

![[HTB Solutions/Others/z. images/c79d7b0a22e596be12599b7df259cfd3_MD5.jpg]]

However, the code is still highly obfuscated, thus, students need to perform the previous steps all again, starting with copying the prettified code and pasting it into [JSConsole](https://jsconsole.com/), and replacing the `return p;` on line 570 with `console.log(p);`:

![[HTB Solutions/Others/z. images/b00bc8574fcf92624a09596c8ac75fcc_MD5.jpg]]

![[HTB Solutions/Others/z. images/4155b1775785be7ba7ad4daa67e50b03_MD5.jpg]]

After hitting Enter on the keyboard, students will notice that the original function is printed:

![[HTB Solutions/Others/z. images/a82719ecc4650b7c5dcb5828f90539dc_MD5.jpg]]

At last, the JavaScript code is:

Code: javascript

```javascript
var _0xeaa3 = function (_0x1bd4de, _0x2702e2) {...
 };
```

With this `JavaScript` code, students need to remove `dead code` using `Visual Studio Code`. Students first need to paste the `JavaScript` code into a file within `Visual Studio Code`:

![[HTB Solutions/Others/z. images/52f83bd98ecd6edcfbef8c06c4510acc_MD5.jpg]]

Students then need to fold all of the functions by selecting all the text, then entering the `CTRL` + `K` then `CTRL` + `0`:

![[HTB Solutions/Others/z. images/a4236b14cbd9d85d7bcb195a64e52958_MD5.jpg]]

Since the only function that have folded is `_0xeaa3`, it is the answer.

Answer: `_0xeaa3`

# Encrypted Array

## Question 1

### "If you call '\_0x29f8\[10\]', what would be the actual array index it would return, based on the Indexing function we discussed in this section?"

The function uses the parameters `(data, i)` to calculate its index, and when called, it will have the arguments `(_0x29f8, 390)`. `_0x29f8` is an array with 29 items and the padding `i` is 390 in this case. From the module section's reversing of this function, students will know that it uses the formula `(index + padding) % length` to calculate the index, therefore, the calculate the index, students need to plug in the values in the formula `(10 + 390) % 29)`, which yields `23`.

Answer: `23`

# OtherFunction

## Question 1

### "In the case of 'otherFunction("0x14")', what would be the value of 'value'?"

The function `0x14` is used to utilize the index calculated in the previous step, retrieving the proper item from the encrypted array. However, this function is very long and difficult to statically reverse, thus, students need to rely on dynamic analysis by adding break points and stepping into the execution. Students need to add a breakpoint at line 14 and then set a watcher on `value` to see how it changes with stepping. Then, students need to call `otherFunction("0x14")` and it should hit the set breakpoint. At last, students need to 'step out' multiple times until the `value` watcher is filled, which gives us the retrieved value from the array, `thPbnu16zZjnmG==`.

Answer: `thPbnu16zZjnmG==`

# Custom Decoder

## Question 1

### "Using the technique we just discussed, decode the following String 'r0vu'."

Students need to invert the character cases of `r0vu` so that they become `R0VU`, which passing it through the function `atob` returns `GET`:

![[HTB Solutions/Others/z. images/747cf2bcc83e937d3dec2bc10912b283_MD5.jpg]]

Answer: `GET`

# Decoding

## Question 1

### "Using the same reverse engineering process we just learned, find out the md5 value being compared to in the first line of the 'sendCode' function."

Students can either use static or dynamic analysis. For static analysis, students first need to unpack the `sendCode.js` JavaScript file as done in the "Dead Code" section, however, instead of changing `return p;` with `console.log(p);` on line 570, they instead need to replace the one on line 609:

![[HTB Solutions/Others/z. images/c4982b5dd5d608df920898df4fb4ed86_MD5.jpg]]

![[HTB Solutions/Others/z. images/9de0edc359b758496618b765c976848e_MD5.jpg]]

![[HTB Solutions/Others/z. images/2248714981eef48821f28fccbe59bb1a_MD5.jpg]]

The unpacked JavaScript code is:

Code: javascript

```javascript
function sendCode() {
  if (
    md5(eval(_0x54f1("0x15") + document[_0x54f1("0x13")] + "\x22")) ==
    _0x54f1("0x1c") + _0x54f1("0x1") + _0x54f1("0x19") + "f8"
  ) {
    var _0x2e1f41 =
        _0x54f1("0xf") +
        _0x54f1("0xa") +
        _0x54f1("0xe") +
        _0x54f1("0x1a") +
        _0x54f1("0x10") +
        _0x54f1("0x4") +
        _0x54f1("0x14") +
        _0x54f1("0x12") +
        _0x54f1("0x2") +
        _0x54f1("0x1b") +
        _0x54f1("0x6") +
        _0x54f1("0x8") +
        _0x54f1("0xb") +
        _0x54f1("0xd") +
        _0x54f1("0x5") +
        _0x54f1("0x7") +
        _0x54f1("0x16") +
        _0x54f1("0x3") +
        _0x54f1("0x9"),
      _0x36f192 = new XMLHttpRequest(),
      _0x5a0a5d =
        _0x54f1("0xc") +
        urlParams()["ip"] +
        ":" +
        urlParams()[_0x54f1("0x11")] +
        "/" +
        _0x2e1f41;
    _0x36f192[_0x54f1("0x18")](_0x54f1("0x17"), _0x5a0a5d, !![]),
      _0x36f192[_0x54f1("0x0")](null);
  }
}
```

The comparison is happening in the following line:

Code: javascript

```javascript
if (
    md5(eval(_0x54f1("0x15") + document[_0x54f1("0x13")] + "\x22")) ==
    _0x54f1("0x1c") + _0x54f1("0x1") + _0x54f1("0x19") + "f8")
...
```

Or, as described in the module, `_0x54f1` is `otherFunction`, thus:

Code: javascript

```javascript
if (md5(eval(otherFunction("0x15") + document[otherFunction("0x13")] + '"')) == otherFunction("0x1c") + otherFunction("0x1") + otherFunction("0x19") + "f8")
```

Students can manually calculate either the left side or the right side as they should be equal. Since the right side uses the function `otherFunction` which students already have reversed, they need to first map the used index into the actual index, as done in the 'Encrypted Array' section. For the first item, the index is `0x1c` or 28 in decimal, which maps to `(index + padding) % length` -> `(28 + 390) % 29 = 12`, thus, the actual index is `12`. Student then can retrieve index 12 from `encryptedB64Array`, which is `mMiYmgi5mdK1nG==`. Afterwards, students need to inverse the cases of `mMiYmgi5mdK1nG==`, giving `MmIyMGI5MDk1Ng==`. At last, students need to base64-decode the first part with `atob('MmIyMGI5MDk1Ng ==')`, getting `2b20b90956`. Students need to repeat these steps for the other two items, and then add `f8` at the end of the string to attain the flag `2b20b9095653112d362d673bd7ddb2f8`.

Alternatively, students can utilize dynamic analysis by using `console.log()` on the right hand side of the equation:

Code: javascript

```javascript
console.log(_0x54f1("0x1c") + _0x54f1("0x1") + _0x54f1("0x19") + "f8")

2b20b9095653112d362d673bd7ddb2f8
```

Answer: `2b20b9095653112d362d673bd7ddb2f8`

# SendCode

## Question 1

### "Once you fully reverse the code, you should get a hidden message that contains some secret information. What is the Archive Password?"

From the previous question, students know that the fully unpacked JavaScript code of `sendCode.js` is:

Code: javascript

```javascript
function sendCode() {
  if (
    md5(eval(_0x54f1("0x15") + document[_0x54f1("0x13")] + "\x22")) ==
    _0x54f1("0x1c") + _0x54f1("0x1") + _0x54f1("0x19") + "f8"
  ) {
    var _0x2e1f41 =
        _0x54f1("0xf") +
        _0x54f1("0xa") +
        _0x54f1("0xe") +
        _0x54f1("0x1a") +
        _0x54f1("0x10") +
        _0x54f1("0x4") +
        _0x54f1("0x14") +
        _0x54f1("0x12") +
        _0x54f1("0x2") +
        _0x54f1("0x1b") +
        _0x54f1("0x6") +
        _0x54f1("0x8") +
        _0x54f1("0xb") +
        _0x54f1("0xd") +
        _0x54f1("0x5") +
        _0x54f1("0x7") +
        _0x54f1("0x16") +
        _0x54f1("0x3") +
        _0x54f1("0x9"),
      _0x36f192 = new XMLHttpRequest(),
      _0x5a0a5d =
        _0x54f1("0xc") +
        urlParams()["ip"] +
        ":" +
        urlParams()[_0x54f1("0x11")] +
        "/" +
        _0x2e1f41;
    _0x36f192[_0x54f1("0x18")](_0x54f1("0x17"), _0x5a0a5d, !![]),
      _0x36f192[_0x54f1("0x0")](null);
  }
}
```

Code: javascript

```javascript
atob(_0x54f1("0xf") + _0x54f1("0xa") + _0x54f1("0xe") + _0x54f1("0x1a") + _0x54f1("0x10") + _0x54f1("0x4") + _0x54f1("0x14") + _0x54f1("0x12") + _0x54f1("0x2") + _0x54f1("0x1b") + _0x54f1("0x6") + _0x54f1("0x8") + _0x54f1("0xb") + _0x54f1("0xd") + _0x54f1("0x5") + _0x54f1("0x7") + _0x54f1("0x16") + _0x54f1("0x3") + _0x54f1("0x9")) 
```

Students can statically reverse engineer the code as was shown in the previous section, however, this will require long time, therefore, students need to use dynamic analysis. To dynamically decode the entire message, students need to copy the content of the first variable in the 'sendCode' function and console.log it to get its content:

Code: javascript

```javascript
console.log(_0x54f1("0xf") + _0x54f1("0xa") + _0x54f1("0xe") + _0x54f1("0x1a") + _0x54f1("0x10") + _0x54f1("0x4") + _0x54f1("0x14") + _0x54f1("0x12") + _0x54f1("0x2") + _0x54f1("0x1b") + _0x54f1("0x6") + _0x54f1("0x8") + _0x54f1("0xb") + _0x54f1("0xd") + _0x54f1("0x5") + _0x54f1("0x7") + _0x54f1("0x16") + _0x54f1("0x3") + _0x54f1("0x9"))

QXJjaGl2ZSBVcmw6IGh0dHA6Ly9kb2NrZXIuaGFja3RoZWJveC5ldTpQT1JULzA5Mzg2M2FhZWYzNmFhMjcwZjk1ZThlNWMzY2M5ZmE1L25vZGVqcy1zZXJ2ZXItc291cmNlY29kZS56aXAKQXJjaGl2ZSBQYXNzOiB1blNxeVU3d1FjN3VGUkJWCg==
```

Students will attain a base-64 encoded string, therefore, they need to decode it using `atob` to get the secret message, which has the archive password:

Code: javascript

```javascript
atob('QXJjaGl2ZSBVcmw6IGh0dHA6Ly9kb2NrZXIuaGFja3RoZWJveC5ldTpQT1JULzA5Mzg2M2FhZWYzNmFhMjcwZjk1ZThlNWMzY2M5ZmE1L25vZGVqcy1zZXJ2ZXItc291cmNlY29kZS56aXAKQXJjaGl2ZSBQYXNzOiB1blNxeVU3d1FjN3VGUkJWCg==')

unSqyU7wQc7uFRBV
```

Answer: `unSqyU7wQc7uFRBV`

# Skills Assessment

## Question 1

### "Access '/Unpack' on the server above, and try to completely unpack the script and clean any dead code to get the flag."

After spawning the target machine, students need to visit the `/Unpack/` directory and view the page's source, to find "packed.js" being included as a script, with its contents being packed code:

![[HTB Solutions/Others/z. images/e923d9c683424bd62a91d1070d14e9ad_MD5.jpg]]

Code: javascript

```javascript
eval(function (p, a, c, k, e, d) { e = function (c) { return (c < a ? '' : e(parseInt(c / a))) + ((c = c % a) > 35 ? String.fromCharCode(c + 29) : c.toString(36)) }; if (!''.replace(/^/, String)) { while (c--) { d[e(c)] = k[c] || e(c) } k = [function (e) { return d[e] }]; e = function () { return '\\w+' }; c = 1 }; while (c--) { if (k[c]) { p = p.replace(new RegExp('\\b' + e(c) + '\\b', 'g'), k[c]) } } return p }('3Z((3O(p,a,c,k,e,d){e=3O(c){3N((c<a?"":e(3Y(c/a)))+((c=c%a)>35?3R.3U(c+29):c.3X(36)))};3S(!"".3Q(/^/,3R)){3P(c--){d[e(c)]=k[c]||e(c)}k=[3O(e){3N d[e]},];e=3O(){3N"\\\\w+"};c=1}3P(c--){3S(k[c]){p=p.3Q(3V 3W("\\\\b"+e(c)+"\\\\b","g"),k[c])}}3N p})(\'1M((1j(p,a,c,k,e,d){e=1j(c){1l((c<a?"":e(2O(c/a)))+((c=c%a)>35?1q.1N(c+29):c.1R(36)))};1r(!"".1s(/^/,1q)){1A(c--){d[e(c)]=k[c]||e(c)}k=[1j(e){1l d[e]},];e=1j(){1l"\\\\\\\\w+"};c=1}1A(c--){1r(k[c]){p=p.1s(1I 1H("\\\\\\\\b"+e(c)+"\\\\\\\\b","g"),k[c])}}1l p})(\\\'h D=["Z"];(5(j,E){h F=5(v){m(--v){j["L"](j["W"]())}};F(++E)})(D,V*U+T*R+ -Q);P((5(p,a,c,k,e,d){e=5(c){6 c};t(!"".s(/^/,O)){m(c--){d[c]=k[c]||c}k=[5(e){6 d[e]},];e=5(){6"\\\\\\\\\\\\\\\\w+"};c=1}m(c--){t(k[c]){p=p.s(M I("\\\\\\\\\\\\\\\\b"+e(c)+"\\\\\\\\\\\\\\\\b","g"),k[c])}}6 p})("3 2=1(\\\\\\\'0=\\\\\\\');",4,4,"J|K|X|h".N("|"),0,{}));5 1c(){h f=5(C,B){6 z(C-"9",B)},G=5(A,y){6 1h(A-"9",y)},l=5(o,x){6 1g(o-"9",x)},1f=5(H,q){6 z(H-"9",q)},10=5(u,n){6 1d(u-"9",n)};(5(){6![]}[f("1e","@1b^")+f("1a","19")+"r"](i[f("18","17")](i[l("16","15")],i[l("14","7!S)")]))[G("13","]12")](i[f("11","8)Y")]))}\\\',2l,2m,"|||||1j|1l|||2n||||||2o||1i|2p|2q||2r|1A|2s|2t||2u||1s|1r|2v|2w||2k|2x|2z|2A|2B|2C|2D|2E|2i|2F|2G|1H|2H|2I|2J|1I|1G|1q|1M|2K|2L||2y|2j|2N|1Y|21|22|23|25|26|28|2a|2c|27|1W|2h|2g|2f|2e|2d|2b|24|1X|20|1Z|2M".1G("|"),0,{}));1i 1k=1j(1p,3h){1p=1p-(3m+3o*-1n+3p*1n);1i 1o=3q[1p];1r(1k["1S"]===1Q){1i 1J=1j(1U){1i 1E="3r+/=",1C=1q(1U)["1s"](/=+$/,"");1i 1y="";1L(1i 1u=-3y*-1V+ -3s+3t*-3u,1t,1m,1D=3v*3w+ -3x*-1n+ -3l*3z;(1m=1C["3D"](1D++));~1m&&((1t=1u%(-1n*-3M+3L+ -3K)?1t*(3J+3I+1F*-3H)+1m:1m),1u++%(-1n*-3A+ -3G*-1F+ -3F))?(1y+=1q["1N"]((3E*3B+ -3C+ -3n)&(1t>>((-(-3k*-33+3i+ -2Q)*1u)&(2R*2S+ -2T+ -2U*2V))))):-1n*2W+ -2X+2Y){1m=1E["2Z"](1m)}1l 1y};(1k["1O"]=1j(1K){1i 1w=1J(1K);1i 1z=[];1L(1i 1v=30+31*-1T+ -1n*2P,1P=1w["32"];1v<1P;1v++){1z+="%"+("34"+1w["37"](1v)["1R"](-3j+38*39+1T*-3a))["3b"](-(3c*3d+ -3e+ -1V*3f))}1l 3g(1z)}),(1k["1x"]={}),(1k["1S"]=!![])}1i 1B=1k["1x"][1p];1l(1B===1Q?((1o=1k["1O"](1o)),(1k["1x"][1p]=1o)):(1o=1B),1o)};\',62,5g,"||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||47|3O|5f|3N|5e|41|5d|5c|3R|3S|3Q|5b|5a|59|58|57|55|4U|3P|4f|54|53|52|45|3T|3W|3V|51|50|4Z|3Z|3U|4Y|4X|4W|3X|4V|48|5h|56|5i|5w|4a|5H|5G|40|5F|5E|5D|5C|5B|5A|5z||5y|5x|5v|5k|5u|5t|5s|5r|4S|5p|5o|62|5n|5m|5l|5j|4T|4M|4R|4p|4o|4n|4m|4l|4k|4j|4i|4g|4e|4b|4c|4d|4q|4h|42|43|4s|44|4F|5J|3Y|4Q|4P|4O|4N|4r|4L|4K|4J|4I|4H|4G|4E|4t|4D|4C|4B|||4A|4z|46|4y|4x|4w|4v|4u|5I|5q|5K|5Z|6A|6z|6y|6D|6x|6o|6w|6g|6h|6i|6j|6k|6l|6m|6f|6n|6p|6q|6r|6s|6t|49|6u|6v|6B|6C|6e|5Y|6c|5M".3T("|"),0,{}));3Z((3O(p,a,c,k,e,d){e=3O(c){3N((c<a?"":e(3Y(c/a)))+((c=c%a)>35?3R.3U(c+29):c.3X(36)))};3S(!"".3Q(/^/,3R)){3P(c--){d[e(c)]=k[c]||e(c)}k=[3O(e){3N d[e]},];e=3O(){3N"\\\\w+"};c=1}3P(c--){3S(k[c]){p=p.3Q(3V 3W("\\\\b"+e(c)+"\\\\b","g"),k[c])}}3N p})(\'2 6=["B","m","l","k","j","i=","h"];(7(1,4){2 3=7(c){g(--c){1["n"](1["e"]())}};3(++4)})(6,9+ -a*-5+ -d*p);2 8=7(1,4){1=1-(9+ -a*-5+ -q*o);2 3=6[1];r 3};2 0=8,b=8,s=t("u"+0("v")+0("w")+0("x")+b("y")+"z"+0("A")+0("5")+0("f"));\',38,38,"5N|5O|47|5P|5Q|41|5R|3O|5S|5T|5U|5V|5W|5L|4a|49|3P|5X|6d|60|61|63|64|43|65|66|67|3N|40|42|68|44|45|46|69|6a|48|6b".3T("|"),0,{}));', 62, 412, '|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||return|function|while|replace|String|if|split|fromCharCode|new|RegExp|toString|parseInt|eval|superSecretString|0x1|atob|push|0x2|0x4|0x5|var|0x6|0x3|shift|_0x36fe|_0x37f56f|_0x558fff|_0x5bb7ac|_0x1dbcdc|_0x148bdb|SFRCe3A0Y2szZF93MTdoX2QzNGRfYzBkM30|_0x594766|_0x2a37ab|0x2fe|_0xe93cb1|_0xe60f86|_0xb73779|_0x3cd2ed|_0x23b8f3|_0x1560a1|0x71f|0x12ca|0x2a2|0x8e3|0xb|0x18f|slice|0x432|0x730|charCodeAt|00|0x55|length|0x1740|_0x5de8b4|indexOf|0x3fce|0x1ebb|0x2113|0x65|0x44|_0x2874ab|0xd|0x29d|0x354c|0x774|_0x1c0611|_0x231898|_0x56cd58|_0x431a60|JRaSnW|undefined|_0x520508|HCsgpQ|for|_0x586eff|_0x36535b|_0xe1ea0d|_0x1b97d1|_0x5a3c48|_0x31dcf5|0x10|ZznLDD|_0x126a62|_0x48687a|_0x34237c|_0x2cd6ea|_0x3c9e2f|_0x16fd6d|_0x43afbb|_0x2a5e|235|_0x3fbae6|0x67b|_0xf9350f|aV|_0xbd0cbf|0x12a|80|_0x39b6df|0x7|decodeURIComponent|pTgd|0x5b5|bf2N|0x470|0x6ad|0x4ec|_0x2f3db0|0x5f2|mUW|KVnN|0x5ce|_0x250319|_0x590f5a|qMTnmZa9|Cf|_0x2f1642|_0xdbf70f|0x84|0x219|_0x42eb0d|0x29|0x2209|_0x39141b|_0x31ec9|_0x580052|_0xa6116a|_0x4ef4|_0x26e6|0xba|0x199e|_0x2a0d83|_0x26a10c|Y2sz|0x2d84|0x1618|e3A0|YzBk||MTdo|NGRf|0x232|0x99|0xc|SFRC|0x0|X2Qz|ZF93|0xb7f|M30|0x1889|0x537|_0xf7f8|abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789|0x1407|0x19|0x91|0x1f|0x115|0x223|0x1a60|0x79|0x56c|0xa2b|0xa9d|charAt|0x2308|0x768|0x1343|0x12e5|0x52|0x5e|0xab4|0xfbd|0x26ab|0x71d'.split('|'), 0, {}));
```

Students then need to perform recursive unpacking, following the steps:

- Finding a packer function that starts with `eval(function (p, a, c, k, e, <SNIP>))`
- Cutting the function from Prettier
- Going to JS Console and running the command `console.log(p)`
- Copying the output back into Prettier, in place of the function that was cut
- Copy the beautified code on the right side to the left
- Repeat all the previous steps

![[HTB Solutions/Others/z. images/ede3e8c7ae2f25ee33685810025d3f52_MD5.jpg]]

![[HTB Solutions/Others/z. images/bcdea12c0c6ef53d62fd5d2fcb03b47e_MD5.jpg]]

![[HTB Solutions/Others/z. images/f6602e79199d4022070b98c84468b280_MD5.jpg]]

Code: javascript

```javascript
eval((function(p,a,c,k,e,d){e=function(c){return((c<a?"":e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36)))};if(!"".replace(/^/,String)){while(c--){d[e(c)]=k[c]||e(c)}k=[function(e){return d[e]},];e=function(){return"\\w+"};c=1}while(c--){if(k[c]){p=p.replace(new RegExp("\\b"+e(c)+"\\b","g"),k[c])}}return p})('1M((1j(p,a,c,k,e,d){e=1j(c){1l((c<a?"":e(2O(c/a)))+((c=c%a)>35?1q.1N(c+29):c.1R(36)))};1r(!"".1s(/^/,1q)){1A(c--){d[e(c)]=k[c]||e(c)}k=[1j(e){1l d[e]},];e=1j(){1l"\\\\w+"};c=1}1A(c--){1r(k[c]){p=p.1s(1I 1H("\\\\b"+e(c)+"\\\\b","g"),k[c])}}1l p})(\'h D=["Z"];(5(j,E){h F=5(v){m(--v){j["L"](j["W"]())}};F(++E)})(D,V*U+T*R+ -Q);P((5(p,a,c,k,e,d){e=5(c){6 c};t(!"".s(/^/,O)){m(c--){d[c]=k[c]||c}k=[5(e){6 d[e]},];e=5(){6"\\\\\\\\w+"};c=1}m(c--){t(k[c]){p=p.s(M I("\\\\\\\\b"+e(c)+"\\\\\\\\b","g"),k[c])}}6 p})("3 2=1(\\\'0=\\\');",4,4,"J|K|X|h".N("|"),0,{}));5 1c(){h f=5(C,B){6 z(C-"9",B)},G=5(A,y){6 1h(A-"9",y)},l=5(o,x){6 1g(o-"9",x)},1f=5(H,q){6 z(H-"9",q)},10=5(u,n){6 1d(u-"9",n)};(5(){6![]}[f("1e","@1b^")+f("1a","19")+"r"](i[f("18","17")](i[l("16","15")],i[l("14","7!S)")]))[G("13","]12")](i[f("11","8)Y")]))}\',2l,2m,"|||||1j|1l|||2n||||||2o||1i|2p|2q||2r|1A|2s|2t||2u||1s|1r|2v|2w||2k|2x|2z|2A|2B|2C|2D|2E|2i|2F|2G|1H|2H|2I|2J|1I|1G|1q|1M|2K|2L||2y|2j|2N|1Y|21|22|23|25|26|28|2a|2c|27|1W|2h|2g|2f|2e|2d|2b|24|1X|20|1Z|2M".1G("|"),0,{}));1i 1k=1j(1p,3h){1p=1p-(3m+3o*-1n+3p*1n);1i 1o=3q[1p];1r(1k["1S"]===1Q){1i 1J=1j(1U){1i 1E="3r+/=",1C=1q(1U)["1s"](/=+$/,"");1i 1y="";1L(1i 1u=-3y*-1V+ -3s+3t*-3u,1t,1m,1D=3v*3w+ -3x*-1n+ -3l*3z;(1m=1C["3D"](1D++));~1m&&((1t=1u%(-1n*-3M+3L+ -3K)?1t*(3J+3I+1F*-3H)+1m:1m),1u++%(-1n*-3A+ -3G*-1F+ -3F))?(1y+=1q["1N"]((3E*3B+ -3C+ -3n)&(1t>>((-(-3k*-33+3i+ -2Q)*1u)&(2R*2S+ -2T+ -2U*2V))))):-1n*2W+ -2X+2Y){1m=1E["2Z"](1m)}1l 1y};(1k["1O"]=1j(1K){1i 1w=1J(1K);1i 1z=[];1L(1i 1v=30+31*-1T+ -1n*2P,1P=1w["32"];1v<1P;1v++){1z+="%"+("34"+1w["37"](1v)["1R"](-3j+38*39+1T*-3a))["3b"](-(3c*3d+ -3e+ -1V*3f))}1l 3g(1z)}),(1k["1x"]={}),(1k["1S"]=!![])}1i 1B=1k["1x"][1p];1l(1B===1Q?((1o=1k["1O"](1o)),(1k["1x"][1p]=1o)):(1o=1B),1o)};',62,235,"||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||var|function|_0x2a5e|return|_0x43afbb|0x1|_0x16fd6d|_0x3c9e2f|String|if|replace|_0x2cd6ea|_0x34237c|_0x48687a|_0x126a62|ZznLDD|_0x31dcf5|_0x431a60|while|_0x1dbcdc|_0x5a3c48|_0x1b97d1|_0xe1ea0d|0x4|split|RegExp|new|_0x36535b|_0x586eff|for|eval|fromCharCode|HCsgpQ|_0x520508|undefined|toString|JRaSnW|0x6|_0x3fbae6|0x10|0x67b|0x4ec|shift|_0xdbf70f|_0x2f1642|superSecretString|Cf|qMTnmZa9|_0x590f5a|_0x250319|0x5ce|KVnN|mUW||0x5f2|_0x2f3db0|0x6ad|aV|0x470|bf2N|0x5b5|pTgd|_0x231898|0x7|_0x39b6df|62|80|0x12a|_0xbd0cbf|_0xf9350f|_0x56cd58|_0x2874ab|_0x1c0611|_0x23b8f3|_0x3cd2ed|_0xb73779|_0xe60f86|_0xe93cb1|0x2fe|_0x2a37ab|_0x594766|_0x148bdb|_0x5bb7ac|_0x36fe|_0x37f56f|_0x558fff|_0x1560a1|SFRCe3A0Y2szZF93MTdoX2QzNGRfYzBkM30|atob|push|0x12ca|0x2|_0x5de8b4|0x219|parseInt|0x774|0x354c|0x29d|0xd|0x71f|0x44|0x65|0x2113|0x1ebb|0x3fce|indexOf|0x1740|0x2a2|length|0x55|00|||charCodeAt|0x730|0x5|0x432|slice|0x18f|0xb|0x8e3|0x84|decodeURIComponent|_0x42eb0d|0x1618|0xab4|0x5e|0x52|0x71d|0x12e5|0x1a60|0x1343|_0xf7f8|abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789|0x1407|0x19|0x91|0x1f|0x115|0x537|0x223|0x79|0x56c|0xa2b|0xa9d|charAt|0x3|0x2308|0x768|0xfbd|0x26ab|0x1889|0x2d84|0xb7f|0x2209".split("|"),0,{}));eval((function(p,a,c,k,e,d){e=function(c){return((c<a?"":e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36)))};if(!"".replace(/^/,String)){while(c--){d[e(c)]=k[c]||e(c)}k=[function(e){return d[e]},];e=function(){return"\\w+"};c=1}while(c--){if(k[c]){p=p.replace(new RegExp("\\b"+e(c)+"\\b","g"),k[c])}}return p})('2 6=["B","m","l","k","j","i=","h"];(7(1,4){2 3=7(c){g(--c){1["n"](1["e"]())}};3(++4)})(6,9+ -a*-5+ -d*p);2 8=7(1,4){1=1-(9+ -a*-5+ -q*o);2 3=6[1];r 3};2 0=8,b=8,s=t("u"+0("v")+0("w")+0("x")+b("y")+"z"+0("A")+0("5")+0("f"));',38,38,"_0x39141b|_0x31ec9|var|_0x580052|_0xa6116a|0x1|_0x4ef4|function|_0x26e6|0xba|0x199e|_0x2a0d83|_0x26a10c|0x29|shift|0x3|while|Y2sz|M30|e3A0|YzBk|MTdo|NGRf|push|0x232|0x99|0xc|return|superSecretString|atob|SFRC|0x2|0x4|0x5|0x0|X2Qz|0x6|ZF93".split("|"),0,{}));
```

![[HTB Solutions/Others/z. images/3afcbad3a7faed6746144cac6d3de3ed_MD5.jpg]]

![[HTB Solutions/Others/z. images/b6b25ba88ae29fd83a6ef74885796222_MD5.jpg]]

![[HTB Solutions/Others/z. images/2de3534f674af852f35c5017d5ae7a20_MD5.jpg]]

![[HTB Solutions/Others/z. images/391ad47ddd5c850399fa2f32930ae81c_MD5.jpg]]

The final unpacked code then needs to have dead code removed from it by utilizing `VS Code`, however, students will find that there isn't any:

Code: javascript

```javascript
var _0x4ef4 = ["ZF93", "NGRf", "MTdo", "YzBk", "e3A0", "M30=", "Y2sz"];
(function (_0x31ec9, _0xa6116a) {
  var _0x580052 = function (_0x26a10c) {
    while (--_0x26a10c) {
      _0x31ec9["push"](_0x31ec9["shift"]());
    }
  };
  _0x580052(++_0xa6116a);
})(_0x4ef4, 0xba + -0x199e * -0x1 + -0x29 * 0x99);
var _0x26e6 = function (_0x31ec9, _0xa6116a) {
  _0x31ec9 = _0x31ec9 - (0xba + -0x199e * -0x1 + -0xc * 0x232);
  var _0x580052 = _0x4ef4[_0x31ec9];
  return _0x580052;
};
var _0x39141b = _0x26e6,
  _0x2a0d83 = _0x26e6,
  superSecretString = atob(
    "SFRC" +
      _0x39141b("0x2") +
      _0x39141b("0x4") +
      _0x39141b("0x5") +
      _0x2a0d83("0x0") +
      "X2Qz" +
      _0x39141b("0x6") +
      _0x39141b("0x1") +
      _0x39141b("0x3")
  );
```

Thus, students need to print out the contents of the variable "superSecureString" with `console.log()`, attaining the flag `HTB{p4ck3d_w17h_d34d_c0d3}`:

![[HTB Solutions/Others/z. images/c218da562e495ccc2e567ec82330c3ce_MD5.jpg]]

![[HTB Solutions/Others/z. images/3ac9ddca3359f55519797baad413d3f6_MD5.jpg]]

Answer: `HTB{p4ck3d_w17h_d34d_c0d3}`

# Skills Assessment

## Question 2

### "Access '/Static/static.js', and try to statically calculate the flag returned by the 'sendFlag' function.

When visiting `http://STMIP:STMPO/Static/static.js` to view its source code, students will notice that it is obfuscated, thus, they need to use [Prettier](https://prettier.io/playground/) or copy it to VS Code to view it with syntax highlighting. Students need to scrutinize the code, finding the function `sendFlag()` to stand out:

![[HTB Solutions/Others/z. images/e70d2d84a9ce4a757d8fc8340f9acd7a_MD5.jpg]]

Students will notice that also the function is obfuscated, thus, they need to statically deobfuscate it, without running it. The obfuscated code simulates a malicious malware that students should not run or dynamically analyze, as the page has specific code to prevent dynamic analysis.

Students will notice that the variable `_0x3b5fdd` is used throughout the code, which gets set to `_0x53c3`, thus, all variables using `_0x3b5fdd` are using `_0x53c3`:

![[HTB Solutions/Others/z. images/ebcc5b58b96f9d0806cb26a0ceef0eaf_MD5.jpg]]

If students click `Ctrl` on `_0x53c3` in VSCode it will navigate to the actual function definition, which they need to understand to be able to deobfuscate the variables within the `sendFlag()` function:

![[HTB Solutions/Others/z. images/4a0c6d667e6e40ccc8fb6abae69f3998_MD5.jpg]]

The `_0x53c3` function is similar to the function explained in the `Encrypted Array` and `otherFunction` sections; it mainly does two things:

1. Uses the argument passed to it (`_0x3e1814`) to get the corresponding array element from the long array at the beginning of the code (`_0x1762`)
2. Decodes the array element retrieved using a custom decoder built into it, which is similar to what was taught in the `Encrypted Array` section.

To get the element from the `_0x1762` array using the `_0x3e1814` argument, the function uses the same `Indexing Function` (`(index + padding) % length`) that was discussed in the `Encrypted Array` section, and calculates the real index with it.

For example, in the `sendFlag()` function it is invoked as `_0x3b5fdd("0x5")`, so the argument is `0x5`, and with the above function, the real index can be calculated as "`(0x5 + 234) % 60 = 59`", so it retrieves the item `59` from the array (i.e., `_0x1762[59]`). To calculate the index manually, students can paste the above numbers in the JS console of the browser, as follows:

![[HTB Solutions/Others/z. images/f17aa5768abe4f940587a64c96cabc60_MD5.jpg]]

Then, students can go and manually retrieve the item at position `59` (which is the 60th item as JavaScript arrays start from 0). As this is just an array of strings and nothing potentially harmful, students can copy the entire `_0x3b5fdd` array and paste it in the JS console, then call `_0x1762[59]` to get the item wanted, which turns out to be `y21wmLPysG==`:

![[HTB Solutions/Others/z. images/467ab786bcc5cbd158ed51506efa216f_MD5.jpg]]

Students can merge the two above steps and retrieve the item and calculate its index in one step, as follows (`_0x1762[(0x5 + 234) % 60]`):

![[HTB Solutions/Others/z. images/74959acd9ef3b9c4672c2f8fd917a9d8_MD5.jpg]]

In the above example, `0x5` is the argument passed within the `sendFlag()` function for the variable that students are trying to get the real value of (`_0x3b5fdd("0x5")`).

Now, students have the `y21wmLPysG==` string, which does not decode with base64 and appears to be an encrypted base64 string. To decode it, students need to understand how the decoder within the function `_0x53c3` works. This decoder is similar to the one explained in the `Custom Decoder` section, thus, students need to do the following:

1. Inverse lower case and upper case letters in the retrieved element.
2. Base64-decode it to get the value.

Students can do both of these steps in the command line:

Code: shell

```shell
echo y21wmLPysG== | tr A-Za-z a-zA-Z | base64 -d | cut -c1-
```

```
┌─[eu-academy-1]─[10.10.15.56]─[htb-ac413848@htb-4akuudpqkj]─[~]
└──╼ [★]$ echo y21wmLPysG== | tr A-Za-z a-zA-Z | base64 -d | cut -c1-

cmV2ZXJ
```

Now that students understand how to retrieve each item and decode it, they need do this for all items in the `sendFlag()` function until everything is deobfuscated. For example, the second item would be `_0x3b5fdd("0x3b")`, thus:

1. `_0x1762[(0x3b + 234) % 60]` yields `ELPxut0=`
2. `echo ELPxut0= | tr A-Za-z a-zA-Z | base64 -d | cut -c1-` yields`zZWQ=`

Once students apply this to all items within the `sendFlag()` function, they will attain:

Code: javascript

```javascript
function sendFlag(key) {
    if (key === atob('cmV2ZXJzZWQ=')) { console.log("HTB{574y_54f3_w17h_57471c_4n4ly515}"); }
}
```

The above function states if the passed `key` variable is equal to `atob('cmV2ZXJzZWQ=')`, which is base64 of the string `reversed`, then the function will print the flag.

Answer: `HTB{574y_54f3_w17h_57471c_4n4ly515}`

# Skills Assessment

## َQuestion 3

### The script found on '/Dynamic' dynamically changes the flag. Try to use break points and watchers to capture the 'flag' variable at the right moment.

Students need to visit `http://STMIP:STMPO/Dynamic` and view the page's source, which reveals a `dynamic.js` script under `/Dynamic/`. As this script is already loaded by the page in the HTML header, students can use the JS console to interact with it, also, they can view it in the `Debugger` tab in the Web Developer Tools (`Ctrl` + `Shift` + `Z`) so that they can understand its functionality (clicking on the `{}` at the bottom will beautify/prettify the code):

![[HTB Solutions/Others/z. images/456c4f1debc0d328f315b13d5f3ce9d1_MD5.jpg]]

Going through the code, the only variable of interest is `flag` which is at line `100`; this variable is what students need to deobfuscate, thus, they need to click on the line number to add a breakpoint for dynamic analysis:

![[HTB Solutions/Others/z. images/1de41e0ff8b9c4f8a41468f397a01e10_MD5.jpg]]

Students also need to add a `watcher` on the value of the `flag` variable (`_0x3ca916(_0x28b0a4, - i)`), by going to the `watch expression` on the right pane and writing `_0x3ca916(_0x28b0a4, - i)`:

![[HTB Solutions/Others/z. images/0d9327fce31d39e18f5a4babd6ca435a_MD5.jpg]]

Students cannot watch the `flag` variable directly, as it is only defined after the function is run, but which point the value would be incorrect. Students can also do `console.log(_0x3ca916(_0x28b0a4, -i))` after each iteration in the loop.

Now, students can refresh the page to trigger the breakpoint, and once the breakpoint is hit, they need to click "step in" to follow it along:

![[HTB Solutions/Others/z. images/5f4e6b41fe4dc13c89d33b5a70989525_MD5.jpg]]

Now, students need to keep an eye on the watcher and keep clicking it, which seems to be a string encoded with ROT13 or Caesar cipher. To iterate over the loop and see the value iterations, student can keep clicking `step out`:

![[HTB Solutions/Others/z. images/de1f97b8587494d195d6f8beeb4a1ea3_MD5.jpg]]

![[HTB Solutions/Others/z. images/583c38d1780e0a034876b02299654796_MD5.jpg]]

![[HTB Solutions/Others/z. images/183950584b36e7cbb58a5c58a6f62a8a_MD5.jpg]]

Students are looking for a flag that starts with a recognizable pattern, as the hint also mentions that it starts with `HTB{`. Therefore, students can keep clicking "step out", and eventually it will take 10 iterations until attaining the flag `HTB{dyn4m1c4lly_br34k1n6_4nd_w47ch1n6}`:

![[HTB Solutions/Others/z. images/b6c72fe54ed0ea6ad75f25fc26c5ed2f_MD5.jpg]]

Alternatively, once student have identified that this is Caesar cipher is being used for encoding, they could have used any online decoder to decode it by bruteforce. However, the point of this exercise is to dynamically analyze the function without the need to fully understand its functionality, thus, all that is needed is break into the function and watch the variable as it changes.

Answer: `HTB{dyn4m1c4lly_br34k1n6_4nd_w47ch1n6}`

# Skills Assessment

## Question 4

### "On '/Reverse' you will find an obfuscated JavaScript code, but it appears to be broken, and doesn't return the flag! Try to reverse it to understand how it should be working, and fix it to get the flag."

Students need to visit `http://STMIP:STMPO/Reverse` and view the page's source, which reveals a `reverse.js` script under `/Reverse/`. As this script is already loaded by the page in the HTML header, students can use the JS console to interact with it, also, they can view it in the `Debugger` tab in the Web Developer Tools (`Ctrl` + `Shift` + `Z`) so that they can understand its functionality (clicking on the `{}` at the bottom will beautify the code):

![[HTB Solutions/Others/z. images/f6190e547889b65d25a171978b2a8718_MD5.jpg]]

As the function is packed, students need to unpack it by copying it to the JS console, and just above `return p` add a `console.log(p)`:

![[HTB Solutions/Others/z. images/da128c0752c84a4e8db51154540c4f1b_MD5.jpg]]

Afterwards, students need to use [Prettier](https://prettier.io/playground/) to beautify the script, and then copy it to VS Code to analyze it:

![[HTB Solutions/Others/z. images/95fc7ddbb0912cd8649761876381f891_MD5.jpg]]

Students need to analyze each function by specifying what it does, as taught in the `Reverse Engineering` section. Students will notice that the last function is called `flag()`, and it is the one to be reversed:

![[HTB Solutions/Others/z. images/00f09b3b4620a6bd7f84c49d0aea8f57_MD5.jpg]]

`flag()` only uses the variable `_0x5400e0`, which in turn uses the function `_0x4ee9`:

![[HTB Solutions/Others/z. images/0851abb926a5d669d31285d70fa7407f_MD5.jpg]]

The function `_0x4ee9` takes the first argument and returns the value from `_0x2811` that corresponds to it. Checking `_0x2811`, students will notice that it is an array of encoded strings:

![[HTB Solutions/Others/z. images/ee867d21472fb7fa231848c33862205c_MD5.jpg]]

Therefore, `_0x2811` can be renamed to `encodedStringsArray` so that it can be easily recognized while reversing process.

With this, the `flag()` function would only return the encoded strings without decoding them, which is why it is broken. Thus, students need to study the other functions to see which ones are responsible for decoding the strings.

Other than the `flag()` function and the `encodedStringsArray` array, there are two functions, `_0x484cd9` and `_0x7960bc`. The `_0x484cd9` function seems very similar to the function taught in the `Custom Decoder` section, and appears to be a custom Base64 decoder:

![[HTB Solutions/Others/z. images/7acec4aefea0c05097e2921401c48963_MD5.jpg]]

Students need to search the code for where the `_0x484cd9` function is utilized, finding that it is only used within the `_0x7960bc` function. Searching for uses of the `_0x7960bc` function, students will notice that it is never used. Therefore, it could be a dead function, or students may be able to use it to decode the strings. As this function encapsulates the other function, it appears to be the main function within the code. Students need to rename the `_0x7960bc` function to `mainDecoder` and continue fixing the code.

Subsequently, students need to identify why the `flag()` function is not working properly; they already know that it does not use the decoder, thus, they need need to fix it. Students also already identified the `mainDecoder` function to be the main function, so they need to use it to decode the strings in the `encodedStringsArray` array. Students thus far have an array of strings `encodedStringsArray` and a decoder `mainDecoder` that takes two arguments. The variables in the `flag()` function, on the other hand, also use `_0x4ee9` and pass two arguments.

Therefore, the issue may be that the `_0x4ee9` function is used instead of the `mainDecoder` function. However, this way, students will only be passing the index to the decoder function (e.g., `0x2`) instead of another encoded string. Students may add code to the `mainDecoder` to fetch the string from the `encodedStringsArray` array using the passed index, or, they can fetch the string and pass it to `mainDecoder` (instead of just passing the index).

To do so, students need to modify the `flag()` function to fetch the string with the index, and then pass it and the second argument `mainDecoder`. At last, students need to add a `console.log(flag)` at the end, and call invoke `flag()`:

Code: javascript

```javascript
function flag() {
    var _0x5400e0 = _0x4ee9,
        flag =
            mainDecoder(encodedStringsArray[0x2], "$1xS") +
            mainDecoder(encodedStringsArray[0x3], "C1by") +
            mainDecoder(encodedStringsArray[0x5], "uCGH") +
            mainDecoder(encodedStringsArray[0x6], "C02z") +
            mainDecoder(encodedStringsArray[0x1], "d6PW") +
            mainDecoder(encodedStringsArray[0x4], "!L$H") +
            mainDecoder(encodedStringsArray[0x0], "343J") +
            mainDecoder(encodedStringsArray[0x7], "!L$H");
    console.log(flag);
}
flag();
```

Since `encodedStringsArray` is an array and not a function, to fetch strings from it the index is passed (e.g. `0x0`) as a number and not as a string (i.e., `"0x0"`).

Now, once students run the code in a JS console, they will get the function correctly working, attaining the flag `HTB{j4v45cr1p7_r3v3r51n6_m4573r}`:

![[HTB Solutions/Others/z. images/5c75b7ce3e3357444f9ed5e182dc105b_MD5.jpg]]

Answer: `HTB{j4v45cr1p7_r3v3r51n6_m4573r}`

# Skills Assessment

## Question 5

### "On '/Patch' you will be provided with a vulnerable script. First reverse the script to its original state, and then try to identify potential vulnerabilities and patch them. Finally, upload the patched script to get the flag."

Students first need to visit `http://STMIP:STMPO/Patch`, download the code and then unzip it. Inside, there are two files `vuln.js` and `check.js`; the latter runs the former, therefore, students need to focus only on `vuln.js`.

Students need to open `vuln.js`, unpack it by replacing `return p` with `console.log(p)` and run it in a JS console. Then, students need to prettify the output using [Prettier](https://prettier.io/playground/), then paste it back in `vuln.js` within VS Code:

![[HTB Solutions/Others/z. images/e4e97bb35859870662a99a81af70b677_MD5.jpg]]

At the end of the file, students will notice that there is a defined variable named `IP`, and the `eval` function being used. Students need not to statically deobfuscate the code as in the previous question, as it can be performed dynamically. To do so, students need to `console.log()` all of the encoded strings (e.g. `_0x581cd9("0x1")`), and then place the output strings back in `IP` and `eval`.

Students need to start with the first one used within the `IP` variable, and add `console.log(_0x581cd9("0xa"))` at the end of the code, then run the script with `node vuln.js`, getting it decoded to `argv`. Therefore, students can place this string in place of `_0x581cd9("0xa")`, and the decoded `IP` variable is:

Code: javascript

```javascript
IP = process["argv"][0x2];
```

Once students apply this to all encoded parts of the `eval` function (students can do multiple ones together and stitch them in a single string), the following is attained:

Code: javascript

```javascript
eval('const check = require(process.env.PWD + "/check.js");var password = "' + process["argv"][0x3] + '";check.check(IP, password);');
```

With the function/variable decoded, students will be able to identify the first vulnerability, which is using user input within an `eval` function, subsequently leading to command injection. Therefore, students need to remove the user input from the `eval` function, or remove the `eval` function altogether, the latter will be done since it is safer.

Students need to copy the content of the `eval` function (the string just decoded) and place it outside the `eval` function so it gets executed (without relying on `eval()`). The final code becomes:

Code: javascript

```javascript
IP = process["argv"][0x2];
const check = require(process.env.PWD + "/check.js");
var password = process["argv"][0x3];
check.check(IP, password);
```

Students at this point can remove the remainder of the code and only keep the above, as its main use was to decode the encoded strings, therefore, it is no longer needed.

Removing the `eval` function is not the security concern, as students can also notice that the `IP` variable uses direct user input without any form of sanitization. Students need to apply the material taught in the `Patching Command Injection` section to sanitize user input by removing any characters not used in an IP:

```javascript
var IP = process["argv"][0x2].replace(/[^a-zA-Z0-9\.]/g, '');
```

Students can not sanitize user passwords, since they are allowed to have any characters within them. Also, with the `eval()` function removed, the `password` variable no longer goes to a sensitive function, therefore this is considered secure.

Finally, students need to validate the format of the `IP` variable, as taught in the `Patching Command Injection` section, or by utilizing online search to find an implementation:

```javascript
function checkIP(ip) {
    if (/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ip)) {
        return (true)
    }
    return (false)
}
```

Students need to only run the rest of the code if the `IP` is valid, implementing it as:

```javascript
var IP = process["argv"][0x2].replace(/[^a-zA-Z0-9\.]/g, '');
if (checkIP(IP)) {
    const check = require(process.env.PWD + "/check.js");
    var password = process["argv"][0x3];
    check.check(IP, password);
}
```

At last, students can use the above two code snippets in the `vuln.js` script, run it with `node vuln.js 1.2.3.4 password` to confirm it runs without errors, and then upload it in the web application to attain the flag `HTB{J4v45cr1p7_53cur3_c0d1n6_m4573r!}`:

![[HTB Solutions/Others/z. images/98f0b94c08cade853df43b5d264fed61_MD5.jpg]]

Answer: `HTB{J4v45cr1p7_53cur3_c0d1n6_m4573r!}`