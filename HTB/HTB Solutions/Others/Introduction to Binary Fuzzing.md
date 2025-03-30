
| Section               | Question Number | Answer                                                    |
| --------------------- | --------------- | --------------------------------------------------------- |
| Fuzzing in Action     | Question 1      | 112                                                       |
| Sanitizers            | Question 1      | TSan                                                      |
| Sanitizers            | Question 2      | 4                                                         |
| Radamsa               | Question 1      | strcpy-param-overlap                                      |
| Radamsa               | Question 2      | 'big\_buffer\_dont\_need\_bigger' (line 44)               |
| Glee with Klee        | Question 1      | 35                                                        |
| Glee with Klee        | Question 2      | object read only                                          |
| Actually libFuzzing   | Question 1      | headingLevelMax                                           |
| Actually libFuzzing   | Question 2      | libMDPParser::parseHeading()                              |
| Actually libFuzzing   | Question 3      | heap-use-after-free                                       |
| Actually libFuzzing   | Question 4      | Hello, B! Your room number is 1337. Welcome to Hotel HTB! |
| Fuzzing with AFL++    | Question 1      | 256                                                       |
| Fuzzing with AFL++    | Question 2      | libTXML2::StrPair::SetStr()                               |
| Skills Assessment One | Question 1      | stack-buffer-overflow                                     |
| Skills Assessment One | Question 2      | 500                                                       |
| Skills Assessment One | Question 3      | 9                                                         |
| Skills Assessment Two | Question 1      | stack-buffer-overflow                                     |
| Skills Assessment Two | Question 2      | headlineparser.h                                          |
| Skills Assessment Two | Question 3      | parseBlock()                                              |
| Skills Assessment Two | Question 4      | 105                                                       |
| Skills Assessment Two | Question 5      | underDraw                                                 |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Fuzzing in Action

## Question 1

### "What input size starts causing crashes? Answer with an integer, eg 123."

To begin, students need to reproduce the vulnerable C program shown in the [Simple Demonstration](https://academy.hackthebox.com/module/258/section/2869) section. Using a text editor of their choosing, students need to create a new file, `simple.c`, and have it contain the code shown below:

Code: c

```c
#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[100];
    strcpy(buffer, input);
    printf("Received input: %s\n", buffer);
}

int main() {
    char input[256];
    printf("Enter some text: ");
    fgets(input, 256, stdin);
    vulnerable_function(input);
    return 0;
}
```

Subsequently, students need to compile the aforementioned C program, selecting the name of the output file as `simple`:

Code: shell

```shell
gcc -g -fno-stack-protector -z execstack simple.c -o simple 
```

```
┌─[eu-academy-2]─[10.10.15.34]─[htb-ac-594497@htb-omx8fguwq4]─[~]
└──╼ [★]$ gcc -g -fno-stack-protector -z execstack simple.c -o simple 
```

Now, students need to replicate the Python-based fuzzing tool shown in the [Simple Demonstration](https://academy.hackthebox.com/module/258/section/2869) section. Therefore, students need to use a text editor of their choosing to create a new file, `fuzz.py`, containing the following python code:

Code: python

```python
import subprocess
import random
import string
import sys

def random_string(length):
    characters = string.ascii_letters + string.digits + string.punctuation
    return "".join(random.choice(characters) for i in range(length))

def fuzz(target_binary, max_length=150):
    crash_inputs = []

    for length in range(1, max_length + 1):
        input_string = random_string(length)
        print(f"Testing with input length: {length}")
        try:
            result = subprocess.run(
                [target_binary],
                input=input_string.encode(),
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
            )
        except subprocess.CalledProcessError as e:
            print(f"Input length {length} causing crash (exit code {e.returncode})\n")
            crash_inputs.append((length, input_string, e.returncode))
        except subprocess.TimeoutExpired:
            print(
                f"Timeout expired for input length: {length}, potentially causing a hang. Logging input."
            )
            crash_inputs.append((length, input_string, "Timeout"))

    if crash_inputs:
        with open("crash_inputs.log", "w") as log_file:
            for length, input_data, code in crash_inputs:
                log_file.write(
                    f"Input length {length} causing crash (exit code {code}): {input_data}\n"
                )
        print("Crashes logged to crash_inputs.log")
    else:
        print("No crashes detected.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python fuzz.py <target_binary>")
    else:
        target_binary = sys.argv[1]
        fuzz(target_binary)
```

Students need to ensure that the `fuzz.py` script and `simple` executable are in the same directory.

Finally, students need to run `fuzz.py` against the `simple` binary:

```
┌─[eu-academy-2]─[10.10.15.34]─[htb-ac-594497@htb-omx8fguwq4]─[~]
└──╼ [★]$ python3 fuzz.py ./simple

Testing with input length: 1
Testing with input length: 2
Testing with input length: 3
Testing with input length: 4
Testing with input length: 5
Testing with input length: 6
Testing with input length: 7
Testing with input length: 8
Testing with input length: 9
Testing with input length: 10
Testing with input length: 11
Testing with input length: 12
Testing with input length: 13
Testing with input length: 14
Testing with input length: 15
Testing with input length: 16
Testing with input length: 17
Testing with input length: 18
Testing with input length: 19
Testing with input length: 20
Testing with input length: 21
Testing with input length: 22
Testing with input length: 23
Testing with input length: 24
Testing with input length: 25
Testing with input length: 26
Testing with input length: 27
Testing with input length: 28
Testing with input length: 29
<SNIP>
Testing with input length: 100
Testing with input length: 101
Testing with input length: 102
Testing with input length: 103
Testing with input length: 104
Testing with input length: 105
Testing with input length: 106
Testing with input length: 107
Testing with input length: 108
Testing with input length: 109
Testing with input length: 110
Testing with input length: 111
Testing with input length: 112

Input length 112 causing crash (exit code -11)
<SNIP>
```

Students will find that an input length of `112` causes the program to crash.

Answer: `112`

# Sanitizers

## Question 1

### "Which Sanitizer can be used to help catch race conditions? Answer with the 4 letter abbreviation"

Based on the section's reading, students will know that the `Tsan` sanitizer is used to help catch race conditions:

![[HTB Solutions/Others/z. images/a7a31f7037affaaffa4d24af175ee571_MD5.jpg]]

Answer: `TSan`

# Sanitizers

## Question 2

### "Download the asan\_demo binary and run it. What line of the source code does the vulnerable variable exist? Answer only with an integer, eg 123."

For this exercise, students need to utilize the docker environment shown in the [Pwnbox Setup](https://academy.hackthebox.com/module/258/section/2908) section. This can be accomplished via automation; students need to use a text editor of their choosing to create a bash script, `fuzzydocker.sh`, containing the following commands:

Code: bash

```bash
#!/bin/bash

sudo apt-get update && sudo apt-get install -y docker-ce docker-ce-cli containerd.io
sudo systemctl start docker
cd ~/Desktop
wget https://academy.hackthebox.com/storage/modules/258/Dockerfile.zip
unzip Dockerfile.zip
mkdir htbfuzz
sudo docker build --build-arg USER_ID=$(id -u) --build-arg GROUP_ID=$(id -g) -t htbfuzz .
sudo docker run -it --network host -v ~/Desktop/htbfuzz:/data htbfuzz 
```

Subsequently, students need to run the script:

Code: shell

```shell
bash fuzzydocker.sh
```

```
┌─[eu-academy-2]─[10.10.15.34]─[htb-ac-594497@htb-omx8fguwq4]─[~]
└──╼ [★]$ bash fuzzydocker.sh

Hit:1 https://download.docker.com/linux/debian bullseye InRelease
Get:2 https://packages.microsoft.com/debian/10/prod buster InRelease [6,538 B]                                                                               
Hit:3 https://debian.neo4j.com stable InRelease             
<SNIP>
 => [15/16] WORKDIR /data                                                                                                                                                               0.0s 
 => [16/16] RUN afl-system-config &&     echo "set encoding=utf-8" > ~/.vimrc &&     echo ". /etc/bash_completion" >> ~/.bashrc &&     echo 'alias joe="joe --wordwrap --joe_state -no  2.2s 
 => exporting to image                                                                                                                                                                  4.5s 
 => => exporting layers                                                                                                                                                                 4.5s 
 => => writing image sha256:c912f846571a22e006d0acc895fa6023625117ba12f008c8df6a59763a42d5e3                                                                                            0.0s 
 => => naming to docker.io/library/htbfuzz                                                                                                                                              0.0s 
 
[HTBFuzz htb-rcaz6kmvb8] /data $
```

With the docker environment now active, students need to open a new tab in their terminal and navigate to `~/Desktop/htbfuzz`. Then, students need to download and unzip the provided `asan_demo.zip` file:

Code: shell

```shell
cd ~/Desktop/htbfuzz/
wget https://academy.hackthebox.com/storage/modules/258/asan_demo.zip
unzip asan_demo.zip
```

```
┌─[eu-academy-2]─[10.10.15.34]─[htb-ac-594497@htb-omx8fguwq4]─[~]
└──╼ [★]$ cd ~/Desktop/htbfuzz/

┌─[eu-academy-2]─[10.10.15.34]─[htb-ac-594497@htb-omx8fguwq4]─[~/Desktop/htbfuzz]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/258/asan_demo.zip

--2024-05-05 19:56:52--  https://academy.hackthebox.com/storage/modules/258/asan_demo.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 14230 (14K) [application/zip]
Saving to: ‘asan_demo.zip’

asan_demo.zip                                   100%[====================================================================================================>]  13.90K  --.-KB/s    in 0s      

2024-05-05 19:56:52 (48.8 MB/s) - ‘asan_demo.zip’ saved [14230/14230]

┌─[eu-academy-2]─[10.10.15.34]─[htb-ac-594497@htb-omx8fguwq4]─[~/Desktop/htbfuzz]
└──╼ [★]$ unzip asan_demo.zip 

Archive:  asan_demo.zip
  inflating: asan_demo 
```

Students need to return the previous terminal tab where the docker image is running, then check to make sure that the `asan_demo` program exists within the `/data` directory (confirming that the mount directory, `htbfuzz`, is indeed sharing files between the host machine and docker container):

Code: shell

```shell
ls
```

```
[HTBFuzz htb-omx8fguwq4] /data $ ls

asan_demo  asan_demo.zip
```

Finally, students need to run the `asan_demo` binary and examine the information displayed in the crash dump:

Code: shell

```shell
./asan_demo 
```

```
[HTBFuzz htb-omx8fguwq4] /data $ ./asan_demo 

=================================================================
==14==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fffae940ac8 at pc 0x557df9b8750f bp 0x7fffae940a60 sp 0x7fffae940a50
READ of size 4 at 0x7fffae940ac8 thread T0
    #0 0x557df9b8750e in main /tmp/asan.cpp:6
    #1 0x7f7b33559d8f  (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f)
    #2 0x7f7b33559e3f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x29e3f)
    #3 0x557df9b87244 in _start (/data/asan_demo+0x1244)

Address 0x7fffae940ac8 is located in stack of thread T0 at offset 72 in frame
    #0 0x557df9b87318 in main /tmp/asan.cpp:3

  This frame has 1 object(s):
    [32, 52) 'vulnerableArray' (line 4) <== Memory access at offset 72 overflows this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow /tmp/asan.cpp:6 in main
Shadow bytes around the buggy address:
  0x100075d20100: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x100075d20110: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x100075d20120: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x100075d20130: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x100075d20140: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x100075d20150: f1 f1 f1 f1 00 00 04 f3 f3[f3]f3 f3 00 00 00 00
  0x100075d20160: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x100075d20170: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x100075d20180: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x100075d20190: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x100075d201a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
  Shadow gap:              cc
==14==ABORTING
```

Students will find that line `4` contains the vulnerable variable:

Code: sessopm

```
This frame has 1 object(s):
    [32, 52) 'vulnerableArray' (line 4) <== Memory access at offset 72 overflows this variable
```

Answer: `4`

# Radamsa

## Question 1

### "Download the attached binary and use radamsa to fuzz it in order to answer this question and the next. What vulnerability has ASan identified? Copy only the vulnerability name, for-example-text."

For this exercise, students need to utilize the docker environment shown in the [Pwnbox Setup](https://academy.hackthebox.com/module/258/section/2908) section. This can be accomplished via automation; students need to use a text editor of their choosing to create a bash script, `fuzzydocker.sh`, containing the following commands:

Code: bash

```bash
#!/bin/bash

sudo apt-get update && sudo apt-get install -y docker-ce docker-ce-cli containerd.io
sudo systemctl start docker
cd ~/Desktop
wget https://academy.hackthebox.com/storage/modules/258/Dockerfile.zip
unzip Dockerfile.zip
mkdir htbfuzz
sudo docker build --build-arg USER_ID=$(id -u) --build-arg GROUP_ID=$(id -g) -t htbfuzz .
sudo docker run -it --network host -v ~/Desktop/htbfuzz:/data htbfuzz 
```

Subsequently, students need to run the script:

Code: shell

```shell
bash fuzzydocker.sh
```

```
┌─[eu-academy-2]─[10.10.15.34]─[htb-ac-594497@htb-omx8fguwq4]─[~]
└──╼ [★]$ bash fuzzydocker.sh

Hit:1 https://download.docker.com/linux/debian bullseye InRelease
Get:2 https://packages.microsoft.com/debian/10/prod buster InRelease [6,538 B]                                                                               
Hit:3 https://debian.neo4j.com stable InRelease             
<SNIP>
 => [15/16] WORKDIR /data                                                                                                                                                               0.0s 
 => [16/16] RUN afl-system-config &&     echo "set encoding=utf-8" > ~/.vimrc &&     echo ". /etc/bash_completion" >> ~/.bashrc &&     echo 'alias joe="joe --wordwrap --joe_state -no  2.2s 
 => exporting to image                                                                                                                                                                  4.5s 
 => => exporting layers                                                                                                                                                                 4.5s 
 => => writing image sha256:c912f846571a22e006d0acc895fa6023625117ba12f008c8df6a59763a42d5e3                                                                                            0.0s 
 => => naming to docker.io/library/htbfuzz                                                                                                                                              0.0s 
 
[HTBFuzz htb-rcaz6kmvb8] /data $
```

Once the docker image is running, students need to open a new terminal tab, then navigate to `~/Desktop/htbfuzz`. From here, students need to download and extract the attached `radamsa_target.zip` file:

With the archive now extracted to their host machine, students need to switch back to the docker image, running the `radamza_fuzz` binary and examining the behavior:

Code: shell

```shell
./radamsa_fuzz
```

```
[HTBFuzz htb-omx8fguwq4] /data $ ./radamsa_fuzz 

Listening on port 8737...
```

Students will find that the `radamsa_fuzz` binary begins to listen on port 8737. Therefore, students will need to utilize `radamsa` and its built in TCP client/server functionalities to send fuzzed data, aimed directly at the aforementioned port. However, first students need to end the currently running `radamsa_fuzz` process:

Code: shell

```shell
Ctrl+C
```

```
Listening on port 8737...
^C

[HTBFuzz htb-omx8fguwq4] /data $ 
```

Then, students need to launch the `radamsa_fuzz` binary again; this time backgrounding the process and using a `while` loop to have `radamsa` fuzz port 8737 on the localhost:

Code: shell

```shell
./radamsa_fuzz & while true; do echo "test data" | radamsa -n 1 -o 127.0.0.1:8737 ; done
```

```
[HTBFuzz htb-omx8fguwq4] /data $ ./radamsa_fuzz & while true; do echo "test data" | radamsa -n 1 -o 127.0.0.1:8737 ; done

[1] 18

Listening on port 8737...
string: ttdt�a

string: t�t�
string: test da�a

string: test\`data
test\`data
test\`data
tes\`data

<SNIP>
string: tes�daua�s fs

string: teest data

string: 󠀽test da�󠀠�tta

=================================================================
==18==ERROR: AddressSanitizer: strcpy-param-overlap: memory ranges [0x7ffc13fac700,0x7ffc13facafe) and [0x7ffc13fac702, 0x7ffc13facb00) overlap
==18==WARNING: invalid path to external symbolizer!
==18==WARNING: Failed to use and restart external symbolizer!
    #0 0x489699  (/data/radamsa_fuzz+0x489699) (BuildId: 79abda5be2da603c97e7794750fae9fcf97c73bb)
    #1 0x4da3d9  (/data/radamsa_fuzz+0x4da3d9) (BuildId: 79abda5be2da603c97e7794750fae9fcf97c73bb)
    #2 0x7f1bb3353d8f  (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f) (BuildId: 962015aa9d133c6cbcfb31ec300596d7f44d3348)
    #3 0x7f1bb3353e3f  (/lib/x86_64-linux-gnu/libc.so.6+0x29e3f) (BuildId: 962015aa9d133c6cbcfb31ec300596d7f44d3348)
    #4 0x41c384  (/data/radamsa_fuzz+0x41c384) (BuildId: 79abda5be2da603c97e7794750fae9fcf97c73bb)

Address 0x7ffc13fac700 is located in stack of thread T0 at offset 96 in frame
    #0 0x4d9f2f  (/data/radamsa_fuzz+0x4d9f2f) (BuildId: 79abda5be2da603c97e7794750fae9fcf97c73bb)

  This frame has 4 object(s):
    [32, 48) 'address' (line 41)
    [64, 68) 'opt' (line 42)
    [80, 84) 'addrlen' (line 43)
    [96, 1120) 'big_buffer_dont_need_bigger' (line 44) <== Memory access at offset 96 is inside this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
Address 0x7ffc13fac702 is located in stack of thread T0 at offset 98 in frame
    #0 0x4d9f2f  (/data/radamsa_fuzz+0x4d9f2f) (BuildId: 79abda5be2da603c97e7794750fae9fcf97c73bb)

  This frame has 4 object(s):
    [32, 48) 'address' (line 41)
    [64, 68) 'opt' (line 42)
    [80, 84) 'addrlen' (line 43)
    [96, 1120) 'big_buffer_dont_need_bigger' (line 44) <== Memory access at offset 98 is inside this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: strcpy-param-overlap (/data/radamsa_fuzz+0x489699) (BuildId: 79abda5be2da603c97e7794750fae9fcf97c73bb) 
==18==ABORTING
```

Eventually, the program will crash. Examining the output of the crash, students will see that the `strcpy-param-overlap` vulnerability was identified by Asan.

Answer: `strcpy-param-overlap`

# Radamsa

## Question 2

### "What is the name of the vulnerable variable that ASan has identified and what line does it exist on? Answer by copying the exact ASan output, 'variable\_name' (line 123)"

Students need to examine the Asan output generated from the `strcpy-param-overlap` vulnerability identified during the previous challenge question:

```
=================================================================
==18==ERROR: AddressSanitizer: strcpy-param-overlap: memory ranges [0x7ffc13fac700,0x7ffc13facafe) and [0x7ffc13fac702, 0x7ffc13facb00) overlap
==18==WARNING: invalid path to external symbolizer!
==18==WARNING: Failed to use and restart external symbolizer!
    #0 0x489699  (/data/radamsa_fuzz+0x489699) (BuildId: 79abda5be2da603c97e7794750fae9fcf97c73bb)
    #1 0x4da3d9  (/data/radamsa_fuzz+0x4da3d9) (BuildId: 79abda5be2da603c97e7794750fae9fcf97c73bb)
    #2 0x7f1bb3353d8f  (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f) (BuildId: 962015aa9d133c6cbcfb31ec300596d7f44d3348)
    #3 0x7f1bb3353e3f  (/lib/x86_64-linux-gnu/libc.so.6+0x29e3f) (BuildId: 962015aa9d133c6cbcfb31ec300596d7f44d3348)
    #4 0x41c384  (/data/radamsa_fuzz+0x41c384) (BuildId: 79abda5be2da603c97e7794750fae9fcf97c73bb)

Address 0x7ffc13fac700 is located in stack of thread T0 at offset 96 in frame
    #0 0x4d9f2f  (/data/radamsa_fuzz+0x4d9f2f) (BuildId: 79abda5be2da603c97e7794750fae9fcf97c73bb)

  This frame has 4 object(s):
    [32, 48) 'address' (line 41)
    [64, 68) 'opt' (line 42)
    [80, 84) 'addrlen' (line 43)
    [96, 1120) 'big_buffer_dont_need_bigger' (line 44) <== Memory access at offset 96 is inside this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
Address 0x7ffc13fac702 is located in stack of thread T0 at offset 98 in frame
    #0 0x4d9f2f  (/data/radamsa_fuzz+0x4d9f2f) (BuildId: 79abda5be2da603c97e7794750fae9fcf97c73bb)

  This frame has 4 object(s):
    [32, 48) 'address' (line 41)
    [64, 68) 'opt' (line 42)
    [80, 84) 'addrlen' (line 43)
    [96, 1120) 'big_buffer_dont_need_bigger' (line 44) <== Memory access at offset 98 is inside this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: strcpy-param-overlap (/data/radamsa_fuzz+0x489699) (BuildId: 79abda5be2da603c97e7794750fae9fcf97c73bb) 
==18==ABORTING
```

Specifically, students need to focus on the stack frame:

```
This frame has 4 object(s):
    [32, 48) 'address' (line 41)
    [64, 68) 'opt' (line 42)
    [80, 84) 'addrlen' (line 43)
    [96, 1120) 'big_buffer_dont_need_bigger' (line 44) <== Memory access at offset 96 is inside this variable
```

The vulnerable variable, and the line it exists on, it shown to be `'big_buffer_dont_need_bigger' (line 44)`

Answer: `'big_buffer_dont_need_bigger' (line 44)`

# Glee with Klee

## Question 1

### "Based on the contents of test000002.ptr.err, which line of the intermediate language (IL) file assembly.ll does the vulnerability appear on? Provide only an integer, eg 123."

Students need to begin by starting the docker daemon, then pull the docker image for KLEE:

Code: shell

```shell
sudo systemctl start docker
sudo docker pull klee/klee
```

```
┌─[eu-academy-2]─[10.10.15.34]─[htb-ac-594497@htb-n5ztxrifys]─[~]
└──╼ [★]$ sudo systemctl start docker
┌─[eu-academy-2]─[10.10.15.34]─[htb-ac-594497@htb-n5ztxrifys]─[~]
└──╼ [★]$ sudo docker pull klee/klee

Using default tag: latest
latest: Pulling from klee/klee
677076032cca: Pull complete 
f93ea967c86a: Pull complete 
f88ab0029a96: Pull complete 
f383dbd111f8: Pull complete 
fc0648276376: Pull complete 
599db19d3e9a: Pull complete 
385f9b503343: Pull complete 
a90a52ed2d62: Pull complete 
2b2d83bfd086: Pull complete 
3073480fe468: Pull complete 
bb62eb57a2cb: Pull complete 
4f4fb700ef54: Pull complete 
f71fa94b0601: Pull complete 
03335a21adc6: Pull complete 
a2a3841cf5d6: Pull complete 
f11b1347b85e: Pull complete 
Digest: sha256:a21eaae5870cad1e8e22fd6a82c384a6f0a09cc57d84ab4b3fe89a55ea684f45
Status: Downloaded newer image for klee/klee:latest
docker.io/klee/klee:latest
```

Next, students need to create a mount directory, `~/Desktop/klee` and subsequently start the container for the KLEE environment:

Code: shell

```shell
mkdir ~/Desktop/klee
sudo docker run --rm -ti --ulimit='stack=-1:-1' -v ~/Desktop/klee:/data klee/klee:latest
```

```
┌─[eu-academy-2]─[10.10.15.34]─[htb-ac-594497@htb-n5ztxrifys]─[~]
└──╼ [★]$ mkdir ~/Desktop/klee

┌─[eu-academy-2]─[10.10.15.34]─[htb-ac-594497@htb-n5ztxrifys]─[~]
└──╼ [★]$ sudo docker run --rm -ti --ulimit='stack=-1:-1' -v ~/Desktop/klee:/data klee/klee:latest

klee@75c1262f53e1:~$ 
```

Now with access to a command shell inside the KLEE container, students need to use `vim` to create a new a file, `checkValue.c`. Students need to reproduce the sample code shown in the [Glee with KLEE](https://academy.hackthebox.com/module/258/section/2878) section:

Code: shell

```shell
vim checkValue.c
```

```
klee@0a8961a56ac4:~$ vim checkValue.c
```

Code: c

```c
#include "klee/klee.h"

int checkValue(int x)
{
    int result = 10 / (x - 10);

    int array[5] = {0, 1, 2, 3, 4};
    int value = array[x];

    return result + value;
}

int main()
{
    int x;
    klee_make_symbolic(&x, sizeof(x), "x");
    return checkValue(x);
}
```

Subsequently, students need to compile the newly created `checkValue.c` into LLVM bytecode:

Code: shell

```shell
clang -emit-llvm -c -g -O0 -Xclang -disable-O0-optnone checkValue.c -o checkValue.bc
```

```
klee@0a8961a56ac4:~$ clang -emit-llvm -c -g -O0 -Xclang -disable-O0-optnone checkValue.c -o checkValue.bc
```

Then, students need to execute KLEE on the LLVM bytecode:

Code: shell

```shell
klee --only-output-states-covering-new checkValue.bc
```

```
klee@0a8961a56ac4:~$ klee --only-output-states-covering-new checkValue.bc

KLEE: output directory is "/home/klee/klee-out-0"
KLEE: Using STP solver backend
KLEE: SAT solver: MiniSat
KLEE: Deterministic allocator: Using quarantine queue size 8
KLEE: Deterministic allocator: globals (start-address=0x14fcceada000 size=10 GiB)
KLEE: Deterministic allocator: constants (start-address=0x14fa4eada000 size=10 GiB)
KLEE: Deterministic allocator: heap (start-address=0x13fa4eada000 size=1024 GiB)
KLEE: Deterministic allocator: stack (start-address=0x13da4eada000 size=128 GiB)
KLEE: ERROR: checkValue.c:5: divide by zero
KLEE: NOTE: now ignoring this error at this location
KLEE: ERROR: checkValue.c:8: memory error: out of bound pointer
KLEE: NOTE: now ignoring this error at this location

KLEE: done: total instructions = 348
KLEE: done: completed paths = 1
KLEE: done: partially completed paths = 2
KLEE: done: generated tests = 3
```

Students will observe that KLEE has found two issues: a `divide by zero` error, and an `out of bounds pointer` memory error.

With this in mind, students need to examine the contents of the `test000002.ptr.err` error file, located in the `klee-last` directory:

Code: shell

```shell
cat klee-last/test000002.ptr.err 
```

```
klee@0a8961a56ac4:~$ cat klee-last/test000002.ptr.err 

Error: memory error: out of bound pointer
File: checkValue.c
Line: 8
assembly.ll line: 35
State: 3
Stack: 
	#000000035 in checkValue(x=symbolic) at checkValue.c:8
	#100000059 in main() at checkValue.c:17
Info: 
	address: (Add w64 21866998505472
          (Mul w64 4
                   (SExt w64 (ReadLSB w32 0 x))))
	example: 21867065614336
	range: [21858408570880, 21875588440060]
	next: object at 21838007476224 of size 4
		MO27[4] allocated at checkValue():  %result = alloca i32, align 4
```

The error file states that the vulnerability appears on line `35` of the `assembly.ll` file.

Answer: `35`

# Glee with Klee

## Question 2

### "Create a KLEE fuzzer for the C program attached to this question. KLEE will find 2 vulnerabilities, answer using the name of the vulnerability that is not "out of bound pointer"."

Students need to first navigate to the mount directory , `~/Desktop/klee`, then download and extract the `klee_fuzz.zip` archive:

Code: shell

```shell
cd Desktop/klee/
wget https://academy.hackthebox.com/storage/modules/258/klee_fuzz.zip
unzip klee_fuzz.zip
```

```
┌─[eu-academy-2]─[10.10.14.172]─[htb-ac-594497@htb-035am0j4bt]─[~]
└──╼ [★]$ cd Desktop/klee/

┌─[eu-academy-2]─[10.10.14.172]─[htb-ac-594497@htb-035am0j4bt]─[~/Desktop/klee]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/258/klee_fuzz.zip

--2024-05-06 15:48:50--  https://academy.hackthebox.com/storage/modules/258/klee_fuzz.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 241 [application/zip]
Saving to: ‘klee_fuzz.zip’

klee_fuzz.zip                                   100%[====================================================================================================>]     241  --.-KB/s    in 0s      

2024-05-06 15:48:50 (194 MB/s) - ‘klee_fuzz.zip’ saved [241/241]

┌─[eu-academy-2]─[10.10.14.172]─[htb-ac-594497@htb-035am0j4bt]─[~/Desktop/klee]
└──╼ [★]$ unzip klee_fuzz.zip 

Archive:  klee_fuzz.zip
  inflating: klee_fuzz.c          
```

Then, students need to open the `klee_fuzz.c` file using a text editor of their choosing, and examine the code:

Code: c

```c
#include <stdio.h>

int main()
{
    int *ptr = NULL;

    *ptr = 10;

    return 0;
}
```

Analyzing the code, students will see that it first declares a pointer to an integer, `ptr`, and initializes it to `NULL` (indicating that it points to no valid memory location.) Then it declares `*ptr = 10;` which attempts to store the integer value `10` at the memory location pointed to by `ptr`. However, since `ptr` is `NULL`, this is not possible.

Students need to modify the code, utilizing the `klee_make_symbolic` function to make both the the value for `ptr` symbolic, as well as any possible `value` that the program tries to store in the memory location `ptr` points to:

Code: c

```c
#include <klee/klee.h>

int main() {
    int *ptr;
    int value;
    klee_make_symbolic(&ptr, sizeof(ptr), "ptr");
    klee_make_symbolic(&value, sizeof(value), "value");

    if (ptr != NULL) {
        *ptr = value;
    }

    return 0;
}
```

Having saved the changes to `klee_fuzz.c`, students need to return to the KLEE shell, navigate to `/data`, then compile it into LLVM bytecode:

Code: shell

```shell
cd /data
clang -emit-llvm -c -g -O0 -Xclang -disable-O0-optnone klee_fuzz.c -o klee_fuzz.bc 
```

```
klee@0a8961a56ac4:~$ cd /data
klee@0a8961a56ac4:/data$ clang -emit-llvm -c -g -O0 -Xclang -disable-O0-optnone klee_fuzz.c -o klee_fuzz.bc 
```

Finally, students need to run KLEE against the newly compiled `klee_fuzz.bc`:

Code: shell

```shell
klee --only-output-states-covering-new klee_fuzz.bc
```

```
klee@0a8961a56ac4:/data$ klee --only-output-states-covering-new klee_fuzz.bc 

KLEE: output directory is "/data/klee-out-0"
KLEE: Using STP solver backend
KLEE: SAT solver: MiniSat
KLEE: Deterministic allocator: Using quarantine queue size 8
KLEE: Deterministic allocator: globals (start-address=0x14dd93efe000 size=10 GiB)
KLEE: Deterministic allocator: constants (start-address=0x14db13efe000 size=10 GiB)
KLEE: Deterministic allocator: heap (start-address=0x13db13efe000 size=1024 GiB)
KLEE: Deterministic allocator: stack (start-address=0x13bb13efe000 size=128 GiB)
KLEE: ERROR: klee_fuzz.c:10: memory error: object read only
KLEE: NOTE: now ignoring this error at this location
KLEE: ERROR: klee_fuzz.c:10: memory error: out of bound pointer
KLEE: NOTE: now ignoring this error at this location

KLEE: done: total instructions = 25
KLEE: done: completed paths = 5
KLEE: done: partially completed paths = 9
KLEE: done: generated tests = 4
```

Students will find that KLEE determines the other vulnerability to be `object read only`.

Answer: `object read only`

# Actually libFuzzing

## Question 1

### "What is the name of the variable that is overflowing? Provide only a string, eg variableName."

For this exercise, students need to utilize the docker environment shown in the [Pwnbox Setup](https://academy.hackthebox.com/module/258/section/2908) section. This can be accomplished via automation; students need to use a text editor of their choosing to create a bash script, `fuzzydocker.sh`, containing the following commands:

Code: bash

```bash
#!/bin/bash

sudo apt-get update && sudo apt-get install -y docker-ce docker-ce-cli containerd.io
sudo systemctl start docker
cd ~/Desktop
wget https://academy.hackthebox.com/storage/modules/258/Dockerfile.zip
unzip Dockerfile.zip
mkdir htbfuzz
sudo docker build --build-arg USER_ID=$(id -u) --build-arg GROUP_ID=$(id -g) -t htbfuzz .
sudo docker run -it --network host -v ~/Desktop/htbfuzz:/data htbfuzz 
```

Code: shell

```shell
bash fuzzydocker.sh
```

```
┌─[us-academy-1]─[10.10.15.99]─[htb-ac-594497@htb-axsckefwua]─[~]
└──╼ [★]$ bash fuzzydocker.sh 

Get:1 https://debian.neo4j.com stable InRelease [44.2 kB]
Get:2 https://download.docker.com/linux/debian bullseye InRelease [43.3 kB]    
Get:3 https://packages.microsoft.com/debian/10/prod buster InRelease [6,538 B] 
Get:4 https://repos.insights.digitalocean.com/apt/do-agent main InRelease [5,518 B]
Ign:5 https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/6.0 InRelease      
Get:6 https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/6.0 Release [3,094 B]
<SNIP>
 => [15/16] WORKDIR /data                                                                                                                                                               0.1s 
 => [16/16] RUN afl-system-config &&     echo "set encoding=utf-8" > ~/.vimrc &&     echo ". /etc/bash_completion" >> ~/.bashrc &&     echo 'alias joe="joe --wordwrap --joe_state -no  2.3s 
 => exporting to image                                                                                                                                                                 15.4s 
 => => exporting layers                                                                                                                                                                15.4s 
 => => writing image sha256:3a1532221025e533c61cb32a7316bfaf77c2cfdfd1e9a390d57be11f85e7083d                                                                                            0.0s 
 => => naming to docker.io/library/htbfuzz                                                                                                                                              0.0s 
 
[HTBFuzz htb-axsckefwua] /data $ 
```

With the docker environment now active, students need to open a new tab in their terminal and navigate to `~/Desktop/htbfuzz`. Then, students need create another a new directory, `libMDP` , to download and extract the contents of the libMDP library:

```
┌─[eu-academy-2]─[10.10.14.172]─[htb-ac-594497@htb-035am0j4bt]─[~]
└──╼ [★]$ cd ~/Desktop/htbfuzz/

┌─[eu-academy-2]─[10.10.14.172]─[htb-ac-594497@htb-035am0j4bt]─[~/Desktop/htbfuzz]
└──╼ [★]$ mkdir libMDP; cd libMDP

┌─[eu-academy-2]─[10.10.14.172]─[htb-ac-594497@htb-035am0j4bt]─[~/Desktop/htbfuzz/libMDP]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/258/libMDP.zip

--2024-05-06 16:22:58--  https://academy.hackthebox.com/storage/modules/258/libMDP.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4167 (4.1K) [application/zip]
Saving to: ‘libMDP.zip’

libMDP.zip                                      100%[====================================================================================================>]   4.07K  --.-KB/s    in 0s      

2024-05-06 16:22:58 (47.2 MB/s) - ‘libMDP.zip’ saved [4167/4167]

┌─[eu-academy-2]─[10.10.14.172]─[htb-ac-594497@htb-035am0j4bt]─[~/Desktop/htbfuzz/libMDP]
└──╼ [★]$ unzip libMDP.zip 

Archive:  libMDP.zip
  inflating: libMDP.cpp              
  inflating: libMDP.hpp              
  inflating: README.md  
```

Students need to navigate back to the `~/Desktop/htbfuzz` directory. Then students need to prepare the harness, using a text editor of their choice to create a file called `mdp_fuzzer.cpp` containing the following code (as shown in the [libFuzzer](https://academy.hackthebox.com/module/258/section/2880)section):

Code: c

```c
#include <stdint.h>
#include <string>
#include "libMDP.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
   std::string inputString(reinterpret_cast<const char*>(Data), Size);
   libMDPParser parser;
   parser.parse(inputString); 
   return 0; 
}
```

With the `mdp_fuzzer.cpp` file now created, and the aforementioned code saved to it, students need to confirm the directory layout seen below:

Code: shell

```shell
tree
```

```
┌─[eu-academy-2]─[10.10.14.172]─[htb-ac-594497@htb-035am0j4bt]─[~/Desktop/htbfuzz]
└──╼ [★]$ tree
.
├── libMDP
│   ├── libMDP.cpp
│   ├── libMDP.hpp
│   ├── libMDP.zip
│   └── README.md
└── mdp_fuzzer.cpp
```

Now, students are ready to compile the `mdp_fuzzer` program. Therefore, students need to return to the terminal tab where the docker image is running, ensuring that they are in the `/data` directory (which is mapped to `~/Desktop/htbfuzz` on the the attack host), and compile the harness with `clang++-16`:

Code: shell

```shell
clang++-16 -std=c++11 -g -O1 -fsanitize=fuzzer,address -I./libMDP mdp_fuzzer.cpp libMDP/libMDP.cpp -o mdp_fuzzer
```

```
[HTBFuzz htb-035am0j4bt] /data $ clang++-16 -std=c++11 -g -O1 -fsanitize=fuzzer,address -I./libMDP mdp_fuzzer.cpp libMDP/libMDP.cpp -o mdp_fuzzer

libMDP/libMDP.cpp:136:17: warning: enumeration value 'Link' not handled in switch [-Wswitch]
        switch (element.type)
                ^~~~~~~~~~~~
1 warning generated.
```

Finally, students need to start the fuzzing process by running the compiled `mdp_fuzzer` binary directly:

Code: shell

```shell
./mdp_fuzzer
```

```
[HTBFuzz htb-035am0j4bt] /data $ ./mdp_fuzzer 

INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 4052301020
INFO: Loaded 1 modules   (622 inline 8-bit counters): 622 [0x55a50e9a5500, 0x55a50e9a576e), 
INFO: Loaded 1 PC tables (622 PCs): 622 [0x55a50e9a5770,0x55a50e9a7e50), 
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: A corpus is not provided, starting from an empty corpus
#2	INITED cov: 51 ft: 52 corp: 1/1b exec/s: 0 rss: 38Mb
#3	NEW    cov: 55 ft: 56 corp: 2/3b lim: 4 exec/s: 0 rss: 39Mb L: 2/2 MS: 1 CopyPart-
#5	NEW    cov: 56 ft: 57 corp: 3/4b lim: 4 exec/s: 0 rss: 39Mb L: 1/2 MS: 2 CopyPart-ChangeBit-
#7	NEW    cov: 57 ft: 61 corp: 4/7b lim: 4 exec/s: 0 rss: 39Mb L: 3/3 MS: 2 CopyPart-CopyPart-
#8	NEW    cov: 57 ft: 62 corp: 5/9b lim: 4 exec/s: 0 rss: 39Mb L: 2/3 MS: 1 

<SNIP>

=================================================================
==25==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fc9ff329c79 at pc 0x55a50e95c3c5 bp 0x7ffe33494e70 sp 0x7ffe33494e68
WRITE of size 1 at 0x7fc9ff329c79 thread T0
    #0 0x55a50e95c3c4 in libMDPParser::parseHeading(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>> const&) /data/libMDP/libMDP.cpp:164:32
    #1 0x55a50e9556f9 in libMDPParser::parse(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>> const&) /data/libMDP/libMDP.cpp:43:84
    #2 0x55a50e95393c in LLVMFuzzerTestOneInput /data/mdp_fuzzer.cpp:8:11
    #3 0x55a50e863ba0 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/data/mdp_fuzzer+0x42ba0) (BuildId: f05536798663480c9c3d4a5797dfd811f787910b)
    #4 0x55a50e863315 in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool, bool*) (/data/mdp_fuzzer+0x42315) (BuildId: f05536798663480c9c3d4a5797dfd811f787910b)
    #5 0x55a50e864af5 in fuzzer::Fuzzer::MutateAndTestOne() (/data/mdp_fuzzer+0x43af5) (BuildId: f05536798663480c9c3d4a5797dfd811f787910b)
    #6 0x55a50e865705 in fuzzer::Fuzzer::Loop(std::vector<fuzzer::SizedFile, std::allocator<fuzzer::SizedFile>>&) (/data/mdp_fuzzer+0x44705) (BuildId: f05536798663480c9c3d4a5797dfd811f787910b)
    #7 0x55a50e853680 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/data/mdp_fuzzer+0x32680) (BuildId: f05536798663480c9c3d4a5797dfd811f787910b)
    #8 0x55a50e87c9c2 in main (/data/mdp_fuzzer+0x5b9c2) (BuildId: f05536798663480c9c3d4a5797dfd811f787910b)
    #9 0x7fca00d87d8f  (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f) (BuildId: 962015aa9d133c6cbcfb31ec300596d7f44d3348)
    #10 0x7fca00d87e3f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x29e3f) (BuildId: 962015aa9d133c6cbcfb31ec300596d7f44d3348)
    #11 0x55a50e8489a4 in _start (/data/mdp_fuzzer+0x279a4) (BuildId: f05536798663480c9c3d4a5797dfd811f787910b)

Address 0x7fc9ff329c79 is located in stack of thread T0 at offset 121 in frame
    #0 0x55a50e95acaf in libMDPParser::parseHeading(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>> const&) /data/libMDP/libMDP.cpp:157

 <SNIP>
```

Students need to focus on the data present in the stack frame:

```
  This frame has 11 object(s):
    [32, 40) '__dnew.i.i133'
    [64, 72) '__dnew.i.i83'
    [96, 121) 'headingLevelMax' (line 158) <== Memory access at offset 121 overflows this variable
```

The name of the variable that is overflowing is shown to be `headingLevelMax`.

Answer: `headingLevelMax`

# Actually libFuzzing

## Question 2

### "What is the full function signature, with empty arguments, where the vulnerability is being triggered? Example, libClass::functionName()."

Students need to examine the output generated by Asan, via the `mdp_fuzzer` used in the previous question:

```
Address 0x7fc9ff329c79 is located in stack of thread T0 at offset 121 in frame
    #0 0x55a50e95acaf in libMDPParser::parseHeading(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>> const&) /data/libMDP/libMDP.cpp:157

  This frame has 11 object(s):
    [32, 40) '__dnew.i.i133'
    [64, 72) '__dnew.i.i83'
    [96, 121) 'headingLevelMax' (line 158) <== Memory access at offset 121 overflows this variable
    [160, 192) 'heading_text' (line 179)
    [224, 256) 'ref.tmp8' (line 181)
    [288, 320) 'ref.tmp9' (line 181)
    [352, 384) 'ref.tmp10' (line 181)
    [416, 448) 'ref.tmp11' (line 181)
    [480, 512) 'ref.tmp12' (line 181)
    [544, 576) 'ref.tmp13' (line 181)
    [608, 640) 'ref.tmp26' (line 181)
```

It is revealed that the function that triggered the vulnerability is `libMDPParser::parseHeading()`.

Answer: `libMDPParser::parseHeading()`

# Actually libFuzzing

## Question 3

### "For these next two questions, download the attached welcome.c.zip and implement a libFuzzer harness for the program. What vulnerability does ASan identify in the welcome.c code?"

For this exercise, students need to utilize the docker environment shown in the [Pwnbox Setup](https://academy.hackthebox.com/module/258/section/2908) section. This can be accomplished via automation; students need to use a text editor of their choosing to create a bash script, `fuzzydocker.sh`, containing the following commands:

Code: bash

```bash
#!/bin/bash

sudo apt-get update && sudo apt-get install -y docker-ce docker-ce-cli containerd.io
sudo systemctl start docker
cd ~/Desktop
wget https://academy.hackthebox.com/storage/modules/258/Dockerfile.zip
unzip Dockerfile.zip
mkdir htbfuzz
sudo docker build --build-arg USER_ID=$(id -u) --build-arg GROUP_ID=$(id -g) -t htbfuzz .
sudo docker run -it --network host -v ~/Desktop/htbfuzz:/data htbfuzz 
```

Code: shell

```shell
bash fuzzydocker.sh
```

```
┌─[us-academy-1]─[10.10.15.99]─[htb-ac-594497@htb-axsckefwua]─[~]
└──╼ [★]$ bash fuzzydocker.sh 

Get:1 https://debian.neo4j.com stable InRelease [44.2 kB]
Get:2 https://download.docker.com/linux/debian bullseye InRelease [43.3 kB]    
Get:3 https://packages.microsoft.com/debian/10/prod buster InRelease [6,538 B] 
Get:4 https://repos.insights.digitalocean.com/apt/do-agent main InRelease [5,518 B]
Ign:5 https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/6.0 InRelease      
Get:6 https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/6.0 Release [3,094 B]
<SNIP>
 => [15/16] WORKDIR /data                                                                                                                                                               0.1s 
 => [16/16] RUN afl-system-config &&     echo "set encoding=utf-8" > ~/.vimrc &&     echo ". /etc/bash_completion" >> ~/.bashrc &&     echo 'alias joe="joe --wordwrap --joe_state -no  2.3s 
 => exporting to image                                                                                                                                                                 15.4s 
 => => exporting layers                                                                                                                                                                15.4s 
 => => writing image sha256:3a1532221025e533c61cb32a7316bfaf77c2cfdfd1e9a390d57be11f85e7083d                                                                                            0.0s 
 => => naming to docker.io/library/htbfuzz                                                                                                                                              0.0s 
 
[HTBFuzz htb-axsckefwua] /data $ 
```

With the docker image active, students need to open a new terminal tab, navigating to `~/Desktop/htbfuzz/` on their host machine. Here, students need to download and extract the attached `welcome.c.zip` archive:

Code: shell

```shell
cd ~/Desktop/htbfuzz/
wget https://academy.hackthebox.com/storage/modules/258/welcome.c.zip && unzip welcome.c.zip
```

```
┌─[us-academy-1]─[10.10.15.99]─[htb-ac-594497@htb-cl3zazhzfz]─[~]
└──╼ [★]$ cd ~/Desktop/htbfuzz/

┌─[us-academy-1]─[10.10.15.99]─[htb-ac-594497@htb-cl3zazhzfz]─[~/Desktop/htbfuzz]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/258/welcome.c.zip && unzip welcome.c.zip

--2024-05-25 06:51:58--  https://academy.hackthebox.com/storage/modules/258/welcome.c.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 808 [application/zip]
Saving to: ‘welcome.c.zip’

welcome.c.zip                                   100%[====================================================================================================>]     808  --.-KB/s    in 0s      

2024-05-25 06:51:58 (14.8 MB/s) - ‘welcome.c.zip’ saved [808/808]

Archive:  welcome.c.zip
  inflating: welcome.c      
```

Once extracted, students will need to analyze the contents of the `welcome.c` file with a text editor of their choosing. `VSCode` is particularly effective, with the `C/C++ extension pack` enabled:

Code: shell

```shell
code welcome.c
```

![[HTB Solutions/Others/z. images/521d14ea442da9b07ec41c1563779be6_MD5.jpg]]

Students will find the source code is for a guest management system of a hotel:

Code: c

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
    char *name;
    int room_number;
} Guest;

void free_guest(Guest *guest)
{
    free(guest->name);
    free(guest);
}

void greet_guest(Guest *guest)
{
    if (guest == NULL)
        return;

    // Calculate the required length dynamically
    int name_length = strlen(guest->name);
    int room_number_length = snprintf(NULL, 0, "%d", guest->room_number);
    int total_length = name_length + room_number_length + 50; // Extra space for message text and safety margin

    char *greeting = malloc(total_length);
    if (!greeting)
    {
        printf("Failed to allocate memory for greeting.\n");
        return;
    }

    // Format the greeting message
    snprintf(greeting, total_length, "Hello, %s! Your room number is %d. Welcome to Hotel HTB!",
             guest->name, guest->room_number);

    printf("%s\n", greeting);
    free(greeting);

    if (guest->room_number == 1337)
    {
        printf("Special greeting: %s\n", greeting);
        free(greeting);
    }
}

Guest *create_guest(const char *name, int room_number)
{
    Guest *guest = malloc(sizeof(Guest));
    if (!guest)
    {
        printf("Failed to allocate memory for guest.\n");
        return NULL;
    }

    guest->name = strdup(name);
    guest->room_number = room_number;
    return guest;
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s <name> <room_number>\n", argv[0]);
        return 1;
    }

    int room_number = atoi(argv[2]);
    Guest *guest = create_guest(argv[1], room_number);

    if (guest)
    {
        greet_guest(guest);
        free_guest(guest);
    }

    return 0;
}
```

Analyzing the code deeper, students first see it defines a structure called `Guest`, with two members: `name` (a pointer to a character array) and `room` (an integer):

Code: c

```c
typedef struct
{
    char *name;
    int room_number;
} Guest;
```

Next, it defines a function ,`free_guest`, that takes a `Guest*` argument and frees the memory allocated for for the guest's name, and the memory allocated for the guest structure itself:

Code: c

```c
void free_guest(Guest *guest)
{
    free(guest->name);
    free(guest);
}
```

On to the next function, `greet_guest`, which also takes a `Guest*` argument. The function attempts to greet the guest with a message stating the guest's name and room number, welcoming them to Hotel HTB. The `greeting` itself is a pointer to a character array, with the amount of memory allocated determined by `malloc` and `total_length` (an integer calculated by adding the lengths of the guest's name and room number, converted to a string, plus an additional 50 bytes for padding and safety margin). If for some reason the memory allocation for the `greeting` fails, a message is printed to inform the user of the memory allocation failure:

Code: c

```c
void greet_guest(Guest *guest)
{
    if (guest == NULL)
        return;

    // Calculate the required length dynamically
    int name_length = strlen(guest->name);
    int room_number_length = snprintf(NULL, 0, "%d", guest->room_number);
    int total_length = name_length + room_number_length + 50; // Extra space for message text and safety margin

    char *greeting = malloc(total_length);
    if (!greeting)
    {
        printf("Failed to allocate memory for greeting.\n");
        return;
    }
```

The function also formats the guests greeting using `snprintf`, then frees the allocated memory for `greeting`. However, if the guest's room number is equal to `1337`, a special message is printed instead, followed by freeing memory for `greeting`.:

Code: c

```c
    // Format the greeting message
    snprintf(greeting, total_length, "Hello, %s! Your room number is %d. Welcome to Hotel HTB!",
             guest->name, guest->room_number);

    printf("%s\n", greeting);
    free(greeting);

    if (guest->room_number == 1337)
    {
        printf("Special greeting: %s\n", greeting);
        free(greeting);
    }
}
```

Students need to note the unusual nature of the `greet_guest` function, specifically that memory for `greeting` is allocated only once. Yet within the function are two separate conditions for the memory of `greeting` to be freed.

Subsequently, we have the function `create_guest`; this function takes a `const char *name` and an `int room_number`, and returns a `Guest*` (a pointer to a `Guest` structure, commonly used when wanting to allocate memory dynamically). Using `malloc` to allocate memory for the new `Guest`, it checks for success and prints a message in the case of memory allocation failure, similar to the `greet_guest` function discussed earlier.

After the memory for the `guest` has been allocated, the guest's `name` is set using `strdup`, which allocates memory for the string and copies the content of `name`. The `room_number` is then set as well. Finally, it returns a pointer to the newly created guest:

Code: c

```c
Guest *create_guest(const char *name, int room_number)
{
    Guest *guest = malloc(sizeof(Guest));
    if (!guest)
    {
        printf("Failed to allocate memory for guest.\n");
        return NULL;
    }

    guest->name = strdup(name);
    guest->room_number = room_number;
    return guest;
}
```

Nearing the end of the program, the `main` function is defined, checking for command-line arguments to be used for the guest's name and room number. The room number argument is converted from a string to an integer using `atoi`. The `create_guest` function is then called, creating a guest using the provided name and room number. If a guest is successfully created, `greet_guest` is called to greet the guest. After greeting the guest, the `free_guest` function is used to free the guest's memory.

Additionally, the `main` function returns `0` to indicate successful execution and may print a success message. If incorrect command-line arguments are provided, the `main` function prints a usage message to guide the user on how to use the program:

Code: c

```c
int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s <name> <room_number>\n", argv[0]);
        return 1;
    }

    int room_number = atoi(argv[2]);
    Guest *guest = create_guest(argv[1], room_number);

    if (guest)
    {
        greet_guest(guest);
        free_guest(guest);
    }

    return 0;
}
```

Having studied the source code, students now need to use libFuzzer to find potential vulnerabilities in the Guest Management program. Referring back to the [libFuzzer](https://academy.hackthebox.com/module/258/section/2880) section, students will see they must replace the `main` function in `welcome.c` with the `LLVMFuzzerTestOneInput` function. Additionally, students will need to include the `<stdint.h>` header to allow for the use of the `uint8_t` data type used for the fuzzer's `Data` argument.

Therefore, to begin the implementation of libFuzzer, students need to copy the original `welcome.c` to a new file, `welcome_fuzzer.c`. Subsequently, students need to use this file to begin the design of the upcoming fuzzing tool:

Code: c

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>    
// header added

// original contents of welcome.c 
// remain unchanged
// <SNIP>

// Replace main with LLVMFuzzerTestOneInput
void LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{

	// Additional code to be inserted here
    
    
}
```

In the context of fuzzing the `welcome.c` program, which takes two inputs (guest name and guest room number), students aim to fuzz the guest room number. Initially setting `int room_number = 0` to avoid a `NULL` value, students need to use `memcpy` to copy bytes generated by the fuzzer's `data` into the memory location of `room_number`. It's crucial to ensure that the size of each byte being copied matches the size of an integer to prevent memory corruption or overflow. Here is the code snippet implementing this logic:

Code: c

```c
void LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < sizeof(int))
        return; // Ensure at least sizeof(int) bytes are available in data

    int room_number = 0;
    memcpy(&room_number, data, sizeof(int)); // Copy sizeof(int) bytes from data to room_number

    Guest *guest = create_guest("User", room_number);
    if (guest)
    {
        greet_guest(guest);
        free_guest(guest);
    }
}
```

Therefore, the final source code for the `welcome_fuzzer.c` file ends up being:

Code: c

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct
{
    char *name;
    int room_number;
} Guest;

void free_guest(Guest *guest)
{
    free(guest->name);
    free(guest);
}

void greet_guest(Guest *guest)
{
    if (guest == NULL)
        return;

    // Calculate the required length dynamically
    int name_length = strlen(guest->name);
    int room_number_length = snprintf(NULL, 0, "%d", guest->room_number);
    int total_length = name_length + room_number_length + 50; // Extra space for message text and safety margin

    char *greeting = malloc(total_length);
    if (!greeting)
    {
        printf("Failed to allocate memory for greeting.\n");
        return;
    }

    // Format the greeting message
    snprintf(greeting, total_length, "Hello, %s! Your room number is %d. Welcome to Hotel HTB!",
             guest->name, guest->room_number);

    printf("%s\n", greeting);
    free(greeting);

    if (guest->room_number == 1337)
    {
        printf("Special greeting: %s\n", greeting);
        free(greeting);
    }
}

Guest *create_guest(const char *name, int room_number)
{
    Guest *guest = malloc(sizeof(Guest));
    if (!guest)
    {
        printf("Failed to allocate memory for guest.\n");
        return NULL;
    }

    guest->name = strdup(name);
    guest->room_number = room_number;
    return guest;
}

void LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < sizeof(int))
        return; // Ensure at least sizeof(int) bytes are available in data

    int room_number = 0;
    memcpy(&room_number, data, sizeof(int)); // Copy sizeof(int) bytes from data to room_number

    Guest *guest = create_guest("User", room_number);
    if (guest)
    {
        greet_guest(guest);
        free_guest(guest);
    }
}
```

Verifying that the `welcome_fuzzer.c` file contains the code seen above, students need to save it to the `~/Desktop/htbfuzz/` directory, and subsequently switch terminal tabs back to the docker environment. Here, students will navigate to `/data/` then compile the fuzzer with `clang-16`:

Code: shell

```shell
clang-16 -g -fsanitize=fuzzer,address welcome_fuzzer.c -o welcome_fuzzer
```

```
[HTBFuzz htb-pqu5noyrcv] /data/ $ clang-16 -g -fsanitize=fuzzer,address welcome_fuzzer.c -o welcome_fuzzer
```

Finally, students need to run the newly compiled `welcome_fuzzer` binary:

Code: shell

```shell
./welcome_fuzzer
```

```
HTBFuzz htb-cl3zazhzfz] /data $ ./welcome_fuzzer

INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 3478193386
INFO: Loaded 1 modules   (15 inline 8-bit counters): 15 [0x55f8553ae090, 0x55f8553ae09f), 
INFO: Loaded 1 PC tables (15 PCs): 15 [0x55f8553ae0a0,0x55f8553ae190), 
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: A corpus is not provided, starting from an empty corpus
#2	INITED exec/s: 0 rss: 34Mb
WARNING: no interesting inputs were found so far. Is the code instrumented for coverage?
This may also happen if the target rejected all inputs we tried so far
Hello, User! Your room number is 60426. Welcome to Hotel H
Hello, User! Your room number is 60426. Welcome to Hotel H
Hello, User! Your room number is 16138. Welcome to Hotel H
Hello, User! Your room number is 671498. Welcome to Hotel H
<SNIP>
Hello, User! Your room number is 10. Welcome to Hotel H
Hello, User! Your room number is 58. Welcome to Hotel H
Hello, User! Your room number is 1337. Welcome to Hotel H
=================================================================
==44==ERROR: AddressSanitizer: heap-use-after-free on address 0x606000001be0 at pc 0x55f8552bb532 bp 0x7ffefeea8960 sp 0x7ffefeea80e8
READ of size 2 at 0x606000001be0 thread T0
    #0 0x55f8552bb531 in printf_common(void*, char const*, __va_list_tag*) asan_interceptors.cpp.o
    #1 0x55f8552bce3a in __interceptor_printf (/data/welcome_fuzzer+0x7de3a) (BuildId: 126ef9ccdf1467cd8193dd37dbf912500017e860)
    #2 0x55f85536b30f in greet_guest /data/welcome_fuzzer.c:44:9
    #3 0x55f85536b6ee in LLVMFuzzerTestOneInput /data/welcome_fuzzer.c:74:9
    #4 0x55f85527dba0 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/data/welcome_fuzzer+0x3eba0) (BuildId: 126ef9ccdf1467cd8193dd37dbf912500017e860)
    #5 0x55f85527d315 in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool, bool*) (/data/welcome_fuzzer+0x3e315) (BuildId: 126ef9ccdf1467cd8193dd37dbf912500017e860)
    #6 0x55f85527eaf5 in fuzzer::Fuzzer::MutateAndTestOne() (/data/welcome_fuzzer+0x3faf5) (BuildId: 126ef9ccdf1467cd8193dd37dbf912500017e860)
    #7 0x55f85527f705 in fuzzer::Fuzzer::Loop(std::vector<fuzzer::SizedFile, std::allocator<fuzzer::SizedFile>>&) (/data/welcome_fuzzer+0x40705) (BuildId: 126ef9ccdf1467cd8193dd37dbf912500017e860)
    #8 0x55f85526d680 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/data/welcome_fuzzer+0x2e680) (BuildId: 126ef9ccdf1467cd8193dd37dbf912500017e860)
    #9 0x55f8552969c2 in main (/data/welcome_fuzzer+0x579c2) (BuildId: 126ef9ccdf1467cd8193dd37dbf912500017e860)
    #10 0x7f52cf30dd8f  (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f) (BuildId: 962015aa9d133c6cbcfb31ec300596d7f44d3348)
    #11 0x7f52cf30de3f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x29e3f) (BuildId: 962015aa9d133c6cbcfb31ec300596d7f44d3348)
    #12 0x55f8552629a4 in _start (/data/welcome_fuzzer+0x239a4) (BuildId: 126ef9ccdf1467cd8193dd37dbf912500017e860)

0x606000001be0 is located 0 bytes inside of 58-byte region [0x606000001be0,0x606000001c1a)
freed by thread T0 here:
    #0 0x55f855330486 in __interceptor_free (/data/welcome_fuzzer+0xf1486) (BuildId: 126ef9ccdf1467cd8193dd37dbf912500017e860)
    #1 0x55f85536b262 in greet_guest /data/welcome_fuzzer.c:40:5
    #2 0x55f85536b6ee in LLVMFuzzerTestOneInput /data/welcome_fuzzer.c:74:9
    #3 0x55f85527dba0 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/data/welcome_fuzzer+0x3eba0) (BuildId: 126ef9ccdf1467cd8193dd37dbf912500017e860)
    #4 0x55f85527d315 in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool, bool*) (/data/welcome_fuzzer+0x3e315) (BuildId: 126ef9ccdf1467cd8193dd37dbf912500017e860)
    #5 0x55f85527eaf5 in fuzzer::Fuzzer::MutateAndTestOne() (/data/welcome_fuzzer+0x3faf5) (BuildId: 126ef9ccdf1467cd8193dd37dbf912500017e860)
    #6 0x55f85527f705 in fuzzer::Fuzzer::Loop(std::vector<fuzzer::SizedFile, std::allocator<fuzzer::SizedFile>>&) (/data/welcome_fuzzer+0x40705) (BuildId: 126ef9ccdf1467cd8193dd37dbf912500017e860)
    #7 0x55f85526d680 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/data/welcome_fuzzer+0x2e680) (BuildId: 126ef9ccdf1467cd8193dd37dbf912500017e860)
    #8 0x55f8552969c2 in main (/data/welcome_fuzzer+0x579c2) (BuildId: 126ef9ccdf1467cd8193dd37dbf912500017e860)
    #9 0x7f52cf30dd8f  (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f) (BuildId: 962015aa9d133c6cbcfb31ec300596d7f44d3348)

previously allocated by thread T0 here:
    #0 0x55f85533072e in malloc (/data/welcome_fuzzer+0xf172e) (BuildId: 126ef9ccdf1467cd8193dd37dbf912500017e860)
    #1 0x55f85536b171 in greet_guest /data/welcome_fuzzer.c:28:22
    #2 0x55f85536b6ee in LLVMFuzzerTestOneInput /data/welcome_fuzzer.c:74:9
    #3 0x55f85527dba0 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/data/welcome_fuzzer+0x3eba0) (BuildId: 126ef9ccdf1467cd8193dd37dbf912500017e860)
    #4 0x55f85527d315 in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool, bool*) (/data/welcome_fuzzer+0x3e315) (BuildId: 126ef9ccdf1467cd8193dd37dbf912500017e860)
    #5 0x55f85527eaf5 in fuzzer::Fuzzer::MutateAndTestOne() (/data/welcome_fuzzer+0x3faf5) (BuildId: 126ef9ccdf1467cd8193dd37dbf912500017e860)
    #6 0x55f85527f705 in fuzzer::Fuzzer::Loop(std::vector<fuzzer::SizedFile, std::allocator<fuzzer::SizedFile>>&) (/data/welcome_fuzzer+0x40705) (BuildId: 126ef9ccdf1467cd8193dd37dbf912500017e860)
    #7 0x55f85526d680 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/data/welcome_fuzzer+0x2e680) (BuildId: 126ef9ccdf1467cd8193dd37dbf912500017e860)
    #8 0x55f8552969c2 in main (/data/welcome_fuzzer+0x579c2) (BuildId: 126ef9ccdf1467cd8193dd37dbf912500017e860)
    #9 0x7f52cf30dd8f  (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f) (BuildId: 962015aa9d133c6cbcfb31ec300596d7f44d3348)

SUMMARY: AddressSanitizer: heap-use-after-free asan_interceptors.cpp.o in printf_common(void*, char const*, __va_list_tag*)
Shadow bytes around the buggy address:
  0x606000001900: fd fd fd fd fa fa fa fa fd fd fd fd fd fd fd fd
  0x606000001980: fa fa fa fa fd fd fd fd fd fd fd fd fa fa fa fa
  0x606000001a00: fd fd fd fd fd fd fd fa fa fa fa fa fd fd fd fd
  0x606000001a80: fd fd fd fa fa fa fa fa fd fd fd fd fd fd fd fd
  0x606000001b00: fa fa fa fa fd fd fd fd fd fd fd fa fa fa fa fa
=>0x606000001b80: fd fd fd fd fd fd fd fa fa fa fa fa[fd]fd fd fd
  0x606000001c00: fd fd fd fd fa fa fa fa fa fa fa fa fa fa fa fa
  0x606000001c80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x606000001d00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x606000001d80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x606000001e00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==44==ABORTING
MS: 3 CopyPart-ChangeByte-CMP- DE: "9\005\000\000"-; base unit: adc83b19e793491b1c6ea0fd8b46cd9f32e592fc
0x39,0x5,0x0,0x0,0x25,
9\005\000\000%
artifact_prefix='./'; Test unit written to ./crash-e27c3e99eb2031cd3bfd63aaf56598be7852447a
Base64: OQUAACU=
```

Students will find that Asan identifies a `heap-use-after-free` vulnerability.

Answer: `heap-use-after-free`

# Actually libFuzzing

## Question 4

### "Copy the full libFuzzer harness output (the printf output from the program in otherwords) that crashed the program, for example "Hello, User!, Your room ...""

Students need to examine the Asan output that was generated from the vulnerability discovered in the previous challenge question:

```
Hello, User! Your room number is 1337. Welcome to Hotel H
=================================================================
==44==ERROR: AddressSanitizer: heap-use-after-free on address 0x606000001be0 at pc 0x55f8552bb532 bp 0x7ffefeea8960 sp 0x7ffefeea80e8
READ of size 2 at 0x606000001be0 thread T0
    #0 0x55f8552bb531 in printf_common(void*, char const*, __va_list_tag*) asan_interceptors.cpp.o
```

Students will find the the output that crashed the program to be `Hello, User! Your room number is 1337. Welcome to Hotel H`

Answer: `Hello, User! Your room number is 1337. Welcome to Hotel H`

# Fuzzing with AFL++

## Question 1

### "How many bytes is the size of the heap region that is overflowing? Answer with an integer, eg 123."

For this lab, students need to utilize the docker environment shown in the [Pwnbox Setup](https://academy.hackthebox.com/module/258/section/2908) section, which can be automated with the bash script shown below:

Code: bash

```bash
#!/bin/bash

sudo apt-get update && sudo apt-get install -y docker-ce docker-ce-cli containerd.io
sudo systemctl start docker
cd ~/Desktop
wget https://academy.hackthebox.com/storage/modules/258/Dockerfile.zip
unzip Dockerfile.zip
mkdir htbfuzz
sudo docker build --build-arg USER_ID=$(id -u) --build-arg GROUP_ID=$(id -g) -t htbfuzz .
sudo docker run -it --network host -v ~/Desktop/htbfuzz:/data htbfuzz 
```

After running the script (named `fuzzydock.sh` in the example seen below), students will land straight into a command shell inside the container:

Code: shell

```shell
bash fuzzydocker.sh
```

```
┌─[us-academy-1]─[10.10.14.111]─[htb-ac-594497@htb-rcaz6kmvb8]─[~]
└──╼ [★]$ bash fuzzydocker.sh

Hit:1 https://download.docker.com/linux/debian bullseye InRelease
Get:2 https://packages.microsoft.com/debian/10/prod buster InRelease [6,538 B]
Hit:3 https://repos.insights.digitalocean.com/apt/do-agent main InRelease                   
Hit:4 https://debian.neo4j.com stable InRelease                                    <SNIP>
 => [15/16] WORKDIR /data                                                                                                                                                               0.0s 
 => [16/16] RUN afl-system-config &&     echo "set encoding=utf-8" > ~/.vimrc &&     echo ". /etc/bash_completion" >> ~/.bashrc &&     echo 'alias joe="joe --wordwrap --joe_state -no  2.2s 
 => exporting to image                                                                                                                                                                  4.5s 
 => => exporting layers                                                                                                                                                                 4.5s 
 => => writing image sha256:c912f846571a22e006d0acc895fa6023625117ba12f008c8df6a59763a42d5e3                                                                                            0.0s 
 => => naming to docker.io/library/htbfuzz                                                                                                                                              0.0s 
 
[HTBFuzz htb-rcaz6kmvb8] /data $ 
```

With the docker container now active, students need to open a new terminal tab, so they may interact with their host machine.

Once again, students need to navigate to `~/Desktop/htbfuzz`, followed by the creation of a new directory, `libTXML2`. Furthermore, students need to navigate into the newly created `libTXML2` directory, where they need to then download and unzip the contents of the `libTXML2.zip` file.

Code: shell

```shell
cd ~/Desktop/htbfuzz/ ; mkdir libTXML2 ; cd libTXML2/; wget -q https://academy.hackthebox.com/storage/modules/258/libTXML2.zip && unzip libTXML2.zip
```

```
┌─[us-academy-1]─[10.10.14.111]─[htb-ac-594497@htb-rcaz6kmvb8]─[~]
└──╼ [★]$ cd ~/Desktop/htbfuzz/ ; mkdir libTXML2 ; cd libTXML2/; wget -q https://academy.hackthebox.com/storage/modules/258/libTXML2.zip && unzip libTXML2.zip

Archive:  libTXML2.zip
  inflating: libTXML2.cpp            
  inflating: libTXML2.h              
  inflating: README.md           
```

With the `libTXML2` library, and it's corresponding `libTXML2.cpp` and `libTXML2h` files now accessible, students are ready to create the fuzzer. To accomplish this, students need reproduce the fuzz harness shown in the section's reading:

Code: c

```c
#include "libTXML2.h" // Include the libTXML2 header for XML parsing functionality
#include <iostream>   // For standard input/output and error messages
#include <fstream>    // For potential future file manipulations in the harness

using namespace libTXML2; // Introduce the libTXML2 namespace for easier usage

int main(int argc, char **argv)
{

    // AFL will mutate the input XML file provided as argv[1]
    // This harness is responsible for feeding the mutated input to libTXML2
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <xml_file>" << std::endl;
        return 1; // Indicate failure if no input file is provided
    }

    // XML Parsing with libTXML2:
    XMLDocument doc;       // Create an XML document object
    doc.LoadFile(argv[1]); // Load the fuzzed XML file
    
    // Basic Validation
    doc.Print(); // Print the content of the parsed XML
    
    return 0; // Indicate successful execution
}
```

Using a text editor of their choosing, students need to create a new file and insert the code seen above, saving tit as `txml2_fuzzer.cpp`.

Almost ready to compile the fuzzer, students now need to switch back to the terminal tab where the docker shell is available. Students need to first check the contents of the `/data` folder recursively, ensuring that the `libTXML2` directory and corresponding files are all accessible:

Code: shell

```shell
ls -lR /data/
```

```
[HTBFuzz htb-rjw7ymvfpi] /data $ ls -lR /data/

/data/:
total 4
drwxr-xr-x 2 htbfuzz htbfuzz 4096 May 21 22:21 libTXML2

/data/libTXML2:
total 220
-rw-r--r-- 1 htbfuzz htbfuzz  3421 Apr  9 12:07 README.md
-rw-r--r-- 1 htbfuzz htbfuzz 92508 Apr 10 19:19 libTXML2.cpp
-rw-r--r-- 1 htbfuzz htbfuzz 85835 Apr  9 12:02 libTXML2.h
-rw-r--r-- 1 htbfuzz htbfuzz 34976 Apr 14 17:21 libTXML2.zip
-rw-r--r-- 1 htbfuzz htbfuzz   947 May 21 22:21 txml2_fuzzer.cpp
```

Once verified, students need to navigate to `/data/libTXML2`, followed using `afl-clang-fast++` to compile the fuzzer:

Code: shell

```shell
cd /data/libTXML2
afl-clang-fast++ -fsanitize=address -o txml2_fuzzer txml2_fuzzer.cpp libTXML2.cpp -I. -std=c++11
```

```
[HTBFuzz htb-rjw7ymvfpi] /data/ $ cd /data/libTXML2

[HTBFuzz htb-rjw7ymvfpi] /data/libTXML2 $ afl-clang-fast++ -fsanitize=address -o txml2_fuzzer txml2_fuzzer.cpp libTXML2.cpp -I. -std=c++11

afl-cc++4.21a by Michal Zalewski, Laszlo Szekeres, Marc Heuse - mode: LLVM-PCGUARD
SanitizerCoveragePCGUARD++4.21a
Note: Found constructor function _GLOBAL__sub_I_txml2_fuzzer.cpp with prio 65535, we will not instrument this, putting it into a block list.
[+] Instrumented 9 locations with no collisions (non-hardened mode) of which are 0 handled and 0 unhandled selects.
SanitizerCoveragePCGUARD++4.21a
[+] Instrumented 1907 locations with no collisions (non-hardened mode) of which are 48 handled and 0 unhandled selects.
```

With the newly compiled `txml2_fuzzer` at their disposal, students need to prepare two additional directories. The first being the `Input Directory` containing the `seed corpus` (files used to as initial inputs for AFL, and act as starting point for its fuzzing operators). The other being the `Output Directory`, containing `crashes`, `hangs`, `detailed logs`, and more.

From within the `/data/libTXML2/` directory, students need to create the two new directories, then check to make sure that they exist in the same directory as `txml2_fuzzer`:

Code: shell

```shell
mkdir in out
ls -l
```

```
[HTBFuzz htb-rjw7ymvfpi] /data/libTXML2 $ mkdir in out
[HTBFuzz htb-rjw7ymvfpi] /data/libTXML2 $ ls -l

total 2424
-rw-r--r-- 1 htbfuzz htbfuzz    3421 Apr  9 12:07 README.md
drwxr-xr-x 2 htbfuzz htbfuzz    4096 May 21 23:07 in
-rw-r--r-- 1 htbfuzz htbfuzz   92508 Apr 10 19:19 libTXML2.cpp
-rw-r--r-- 1 htbfuzz htbfuzz   85835 Apr  9 12:02 libTXML2.h
-rw-r--r-- 1 htbfuzz htbfuzz   34976 Apr 14 17:21 libTXML2.zip
drwxr-xr-x 2 htbfuzz htbfuzz    4096 May 21 23:07 out
-rwxr-xr-x 1 htbfuzz htbfuzz 2247360 May 21 22:50 txml2_fuzzer
-rw-r--r-- 1 htbfuzz htbfuzz     947 May 21 22:21 txml2_fuzzer.cpp
```

Almost ready to begin the fuzzing process, students need to create a file for the `Seed Corpus`, placing it inside the `in/` directory:

Code: shell

```shell
echo '<example><test>value</test></example>' > in/test.xml
```

```
[HTBFuzz htb-rjw7ymvfpi] /data/libTXML2 $ echo '<example><test>value</test></example>' > in/test.xml
```

At last, students need to run `afl-fuzz` , specifying the `Input Directory`, `Output Directory`, and the `txml2_fuzzer` executable:

Code: shell

```shell
afl-fuzz -i in -o out -- ./txml2_fuzzer @@
```

```
[HTBFuzz htb-rjw7ymvfpi] /data/libTXML2 $ afl-fuzz -i in -o out -- ./txml2_fuzzer @@
```

Students need to allow AFL++ to run for several minutes, until a crash is found:

![[HTB Solutions/Others/z. images/ed151527abb1d934079d2084d44cf2b0_MD5.jpg]]

Once the crash is triggered, students need to exit the fuzzer by pressing `Ctrl+C`. Consequently, students need to list the contents of`/data/libTXML2/out/default/crashes`, so they may identify the file name of the crash dump. When ready to begin the analysis, students need to run the `txml2_fuzzer` program against the identified crash dump file:

Code: shell

```shell
ls out/default/crashes
./txml2_fuzzer ./out/default/crashes/id\:000000\<SNIP>
```

```
[HTBFuzz htb-rjw7ymvfpi] /data/libTXML2 $ ls out/default/crashes/

README.txt  id:000000,sig:06,src:000333,time:101580,execs:139976,op:havoc,rep:16

[HTBFuzz htb-rjw7ymvfpi] /data/libTXML2 $ ./txml2_fuzzer ./out/default/crashes/id\:000000\,sig\:06\,src\:000333\,time\:101580\,execs\:139976\,op\:havoc\,rep\:16 

=================================================================
==317046==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x611000000280 at pc 0x5645db2280e5 bp 0x7ffce27402b0 sp 0x7ffce273fa70
<SNIP
0x611000000280 is located 0 bytes after 256-byte region [0x611000000180,0x611000000280)
```

According to the crash dump, the `Asan` sanitizer was able to detect a heap buffer overflow, and the address it occurred at (`0x611000000280` in the example shown above). Further into the crash file, we can see that `0x611000000280` is located 0 bytes after 256-byte region, indicating that the size of the heap region is `256` bytes.

Answer: `256`

# Fuzzing with AFL++

## Question 2

### "What is the full function signature, with empty arguments, where the vulnerability is being triggered? Example, libClass::functionName()."

Students need to continue to examine the crash file that was generated by the heap buffer overflow found in the previous question.

Code: shell

```shell
./txml2_fuzzer ./out/default/crashes/id\:000000\<SNIP>
```

Specifically, students need to look at the numbered stack frames:

```
==317046==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x611000000280 at pc 0x5645db2280e5 bp 0x7ffce27402b0 sp 0x7ffce273fa70
WRITE of size 323 at 0x611000000280 thread T0
    #0 0x5645db2280e4 in __interceptor_strcpy (/data/libTXML2/txml2_fuzzer+0xa70e4) (BuildId: 8194a037240b6cfb18634675991d5619cb3c8d28)
    #1 0x5645db28c25e in libTXML2::StrPair::SetStr(char const*, int) /data/libTXML2/libTXML2.cpp:206:9
    #2 0x5645db28c25e in libTXML2::XMLDocument::SetError(libTXML2::XMLError, int, char const*, ...) /data/libTXML2/libTXML2.cpp:2660:19
<SNIP>
```

Although stack frame `#0` is where the actual overflow occurs (in a call to `strcpy`), students need to recognize what led to this, and examine stack frame `#1`:

```
#1 0x5645db28c25e in libTXML2::StrPair::SetStr(char const*, int) /data/libTXML2/libTXML2.cpp:206:9
```

Here, we see `SetStr` being called, a member function of the `StrPair` class which belongs to the `libTXML2` namespace. Students can examine line 209 of `libTXML2.cpp` file for greater context:

![[HTB Solutions/Others/z. images/2d4432e9868d715c127e376d2cc9549c_MD5.jpg]]

Therefore, the full function signature that triggered the vulnerability is `libTXML2::StrPair::SetStr() ` Answer: `libTXML2::StrPair::SetStr()`

# Skills Assessment One

## Question 1

### "What type of vulnerability is contained in the first input? Copy the exact name of the identified vulnerability from ASan."

For this lab, students need to utilize the docker environment shown in the [Pwnbox Setup](https://academy.hackthebox.com/module/258/section/2908) section, which can be automated with the bash script shown below:

Code: bash

```bash
#!/bin/bash

sudo apt-get update && sudo apt-get install -y docker-ce docker-ce-cli containerd.io
sudo systemctl start docker
cd ~/Desktop
wget https://academy.hackthebox.com/storage/modules/258/Dockerfile.zip
unzip Dockerfile.zip
mkdir htbfuzz
sudo docker build --build-arg USER_ID=$(id -u) --build-arg GROUP_ID=$(id -g) -t htbfuzz .
sudo docker run -it --network host -v ~/Desktop/htbfuzz:/data htbfuzz 
```

After running the script (named `fuzzydock.sh` in the example seen below), students will land straight into a command shell inside the container:

Code: shell

```shell
bash fuzzydocker.sh
```

```
┌─[us-academy-1]─[10.10.14.111]─[htb-ac-594497@htb-rcaz6kmvb8]─[~]
└──╼ [★]$ bash fuzzdyocker.sh

Hit:1 https://download.docker.com/linux/debian bullseye InRelease
Get:2 https://packages.microsoft.com/debian/10/prod buster InRelease [6,538 B]
Hit:3 https://repos.insights.digitalocean.com/apt/do-agent main InRelease                                              <SNIP>
 => [15/16] WORKDIR /data                                                                                                                                                               0.0s 
 => [16/16] RUN afl-system-config &&     echo "set encoding=utf-8" > ~/.vimrc &&     echo ". /etc/bash_completion" >> ~/.bashrc &&     echo 'alias joe="joe --wordwrap --joe_state -no  2.2s 
 => exporting to image                                                                                                                                                                  4.5s 
 => => exporting layers                                                                                                                                                                 4.5s 
 => => writing image sha256:c912f846571a22e006d0acc895fa6023625117ba12f008c8df6a59763a42d5e3                                                                                            0.0s 
 => => naming to docker.io/library/htbfuzz                                                                                                                                              0.0s 
 
[HTBFuzz htb-rcaz6kmvb8] /data $ 
```

With the docker now active, students need to open a new terminal tab, then navigate to the mount directory `~/Desktop/htbfuzz`. Here, students need to download and unzip the attached `sa-one.zip` file:

Code: shell

```shell
cd Desktop/htbfuzz/
wget https://academy.hackthebox.com/storage/modules/258/sa-one.zip && unzip sa-one.zip
```

```
┌─[us-academy-1]─[10.10.14.111]─[htb-ac-594497@htb-gmivy4vkl4]─[~]
└──╼ [★]$ cd Desktop/htbfuzz/

┌─[us-academy-1]─[10.10.14.111]─[htb-ac-594497@htb-gmivy4vkl4]─[~/Desktop/htbfuzz]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/258/sa-one.zip && unzip sa-one.zip && chmod +x sa-one

--2024-05-22 04:39:38--  https://academy.hackthebox.com/storage/modules/258/sa-one.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 454244 (444K) [application/zip]
Saving to: ‘sa-one.zip’

sa-one.zip                                      100%[====================================================================================================>] 443.60K  --.-KB/s    in 0.007s  

2024-05-22 04:39:38 (64.6 MB/s) - ‘sa-one.zip’ saved [454244/454244]

Archive:  sa-one.zip
  inflating: sa-one  
```

Now, students need to switch back to the first terminal tab, where the docker image was deployed. Students need to examine the contents of the `/data` directory, where the user should be by default, to verify that the `sa-one` binary is available and can be executed:

Code: shell

```shell
ls -l
```

```
[HTBFuzz htb-gmivy4vkl4] /data $ ls -l

total 1812
-rwxrwxrwx 1 htbfuzz htbfuzz 1399232 Apr 25 14:44 sa-one
-rw-r--r-- 1 htbfuzz htbfuzz  454244 Apr 25 14:56 sa-one.zip
```

Students need to execute the `sa-one` binary and examine it's behavior; the lab scenario stats that the binary has a new feature to reject any input that does not include a special prefix, `<<in<<`.

Code: shell

```shell
./sa-one
# Input
./sa-one
# Input with <<in<< prefix
```

```
[HTBFuzz htb-gmivy4vkl4] /data $ ./sa-one 

Enter input: 
Hello World!
Invalid input

[HTBFuzz htb-gmivy4vkl4] /data $ ./sa-one 

Enter input: 
<<in<<Hello World!
Processed input: Hello World!
```

Students will find that the program only accepts input that contains the `<<in<<` prefix. Therefore, the best tool for the job is `radamsa`, specifically by way of its `--output-template` option.

Code: shell

```shell
radamsa --help
```

```
[HTBFuzz htb-gmivy4vkl4] /data $ radamsa --help

Usage: radamsa [arguments] [file ...]
  -h | --help, show this thing
  -a | --about, what is this thing?
<SNIP>
--output-template <arg>, Output template. %f is fuzzed data. e.g. "<html>%f</html>"
```

The `--output-template` option allows users to potentially prefix the fuzzed data. Therefore, students need to use `radamsa` to fuzz the `sa-one` binary using data with the `<<in<<` prefix. Students can refer to the last example shown in the [Radamsa](https://academy.hackthebox.com/module/258/section/2873) section, for an idea of how to approach the problem:

```
// Sample command from "Radamsa" section:

htb-ac-59449[/htb]$ while true; do echo "a" | radamsa -n 1 | ./simple %; if [[ $? -gt 127 ]]; then break; fi; done

Enter some text: Received input: A

Enter some text: Received input:
Enter some text: Received input: a�򠀡�

Enter some text: Received input: \`
```

Combining elements from the aforementioned sample command (such as using a `while` loop, and an `if` statement to break the loop based on program exit status), students need to use the following command to fuzz the `sa-one` binary:

Code: shell

```shell
echo test data > input.txt; while true; do radamsa input.txt --output-template "<<in<<%f" | ./sa-one %; if [[ $? -eq 1 ]]; then break; fi; done
```

```
[HTBFuzz htb-gmivy4vkl4] /data $ echo test data > input.txt; while true; do radamsa input.txt --output-template "<<in<<%f" | ./sa-one %; if [[ $? -eq 1 ]]; then break; fi; done

Enter input: 
Processed input: test daua
Enter input: 
Processed input: test dat+inf%s;xcalc$!!\0\`xcalc\`'xcalc$!!NaN'xcalcNaN%d$1$&$(xcalc)\x0d%na
Enter input: 
Processed input: �dLtest data
Enter input: 
Processed input: t
Enter input: 
Processed input: t󠀤est data
Enter input: 
Processed input: te��st data
Enter input: 
Processed input: �1�3t!data
Enter input: 
Processed input: tist da[a
Enter input: 
Processed input: test data
Enter input: 
Processed input: t 
Enter input: 
=================================================================
==2857==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffca53be0b4 at pc 0x0000004898e7 bp 0x7ffca53bde90 sp 0x7ffca53bd658
WRITE of size 506 at 0x7ffca53be0b4 thread T0
==2857==WARNING: invalid path to external symbolizer!
==2857==WARNING: Failed to use and restart external symbolizer!
    #0 0x4898e6  (/data/sa-one+0x4898e6) (BuildId: 676e44cd6a4131576a360bc519f491b60ffc8601)
    #1 0x4da061  (/data/sa-one+0x4da061) (BuildId: 676e44cd6a4131576a360bc519f491b60ffc8601)
    #2 0x4da32c  (/data/sa-one+0x4da32c) (BuildId: 676e44cd6a4131576a360bc519f491b60ffc8601)
    #3 0x7f2e3a073d8f  (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f) (BuildId: 962015aa9d133c6cbcfb31ec300596d7f44d3348)
    #4 0x7f2e3a073e3f  (/lib/x86_64-linux-gnu/libc.so.6+0x29e3f) (BuildId: 962015aa9d133c6cbcfb31ec300596d7f44d3348)
    #5 0x41c304  (/data/sa-one+0x41c304) (BuildId: 676e44cd6a4131576a360bc519f491b60ffc8601)

Address 0x7ffca53be0b4 is located in stack of thread T0 at offset 532 in frame
    #0 0x4d9eaf  (/data/sa-one+0x4d9eaf) (BuildId: 676e44cd6a4131576a360bc519f491b60ffc8601)

  This frame has 1 object(s):
    [32, 532) 'buffer' (line 9) <== Memory access at offset 532 overflows this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow (/data/sa-one+0x4898e6) (BuildId: 676e44cd6a4131576a360bc519f491b60ffc8601) 
Shadow bytes around the buggy address:
  0x100014a6fbc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x100014a6fbd0: 00 00 00 00 f1 f1 f1 f1 00 00 00 00 00 00 00 00
  0x100014a6fbe0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x100014a6fbf0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x100014a6fc00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x100014a6fc10: 00 00 00 00 00 00[04]f3 f3 f3 f3 f3 f3 f3 f3 f3
  0x100014a6fc20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x100014a6fc30: 00 00 00 00 f1 f1 f1 f1 00 00 00 00 00 00 00 00
  0x100014a6fc40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x100014a6fc50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x100014a6fc60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==2857==ABORTING
```

After some quick fuzzing, students will find that the program exits, while Asan has identified a `stack-buffer-overflow` vulnerability.

Answer: `stack-buffer-overflow`

# Skills Assessment One

## Question 2

### "Determine the size of the memory allocation involved in the error in the first input? This is not the size of the input and provide an integer, eg 123."

Students need to examine the Asan output generated after fuzzing the `sa-one` binary, being sure to inspect what was recorded in in the stack frame:

```
This frame has 1 object(s):
    [32, 532) 'buffer' (line 9) <== Memory access at offset 532 overflows this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow (/data/sa-one+0x4898e6) (BuildId: 676e44cd6a4131576a360bc519f491b60ffc8601) 
Shadow bytes around the buggy address:
  0x100014a6fbc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x100014a6fbd0: 00 00 00 00 f1 f1 f1 f1 00 00 00 00 00 00 00 00
  0x100014a6fbe0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x100014a6fbf0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x100014a6fc00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x100014a6fc10: 00 00 00 00 00 00[04]f3 f3 f3 f3 f3 f3 f3 f3 f3
  0x100014a6fc20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x100014a6fc30: 00 00 00 00 f1 f1 f1 f1 00 00 00 00 00 00 00 00
  0x100014a6fc40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x100014a6fc50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x100014a6fc60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==2857==ABORTING
```

Specifically, the students need to focus on the starting offset being `32`, and the ending offset being `532`:

```
This frame has 1 object(s):
    [32, 532) 'buffer' (line 9) <== Memory access at offset 532 overflows this variable
```

Subtracting the starting offset from the end offset, students will determine the size of the allocated memory region is `500`.

Answer: `500`

# Skills Assessment One

## Question 3

### "What line does the problem exist on? Answer with an integer, eg 123."

Students need to analyze previously generated Asan output, specifically the information regarding the stack frame object(s):

Code: shell

```shell
This frame has 1 object(s):
    [32, 532) 'buffer' (line 9) <== Memory access at offset 532 overflows this variable
```

It will be apparent that the problem occurs on line `9`.

Answer: `9`

# Skills Assessment Two

## Question 1

### "What is the identified vulnerability?"

For this lab, students need to utilize the docker environment shown in the [Pwnbox Setup](https://academy.hackthebox.com/module/258/section/2908) section, which can be automated with the bash script shown below:

Code: bash

```bash
#!/bin/bash

sudo apt-get update && sudo apt-get install -y docker-ce docker-ce-cli containerd.io
sudo systemctl start docker
cd ~/Desktop
wget https://academy.hackthebox.com/storage/modules/258/Dockerfile.zip
unzip Dockerfile.zip
mkdir htbfuzz
sudo docker build --build-arg USER_ID=$(id -u) --build-arg GROUP_ID=$(id -g) -t htbfuzz .
sudo docker run -it --network host -v ~/Desktop/htbfuzz:/data htbfuzz 
```

After running the script (named `fuzzydocker.sh`), students will land straight into a command shell inside the container:

Code: shell

```shell
bash fuzzydocker.sh
```

```
┌─[us-academy-1]─[10.10.14.111]─[htb-ac-594497@htb-rcaz6kmvb8]─[~]
└──╼ [★]$ bash fuzzdyocker.sh

Hit:1 https://download.docker.com/linux/debian bullseye InRelease
Get:2 https://packages.microsoft.com/debian/10/prod buster InRelease [6,538 B]
Hit:3 https://repos.insights.digitalocean.com/apt/do-agent main InRelease                   
Hit:4 https://debian.neo4j.com stable InRelease                                    <SNIP>
 => [15/16] WORKDIR /data                                                                                                                                                               0.0s 
 => [16/16] RUN afl-system-config &&     echo "set encoding=utf-8" > ~/.vimrc &&     echo ". /etc/bash_completion" >> ~/.bashrc &&     echo 'alias joe="joe --wordwrap --joe_state -no  2.2s 
 => exporting to image                                                                                                                                                                  4.5s 
 => => exporting layers                                                                                                                                                                 4.5s 
 => => writing image sha256:c912f846571a22e006d0acc895fa6023625117ba12f008c8df6a59763a42d5e3                                                                                            0.0s 
 => => naming to docker.io/library/htbfuzz                                                                                                                                              0.0s 
 
[HTBFuzz htb-rcaz6kmvb8] /data $ 
```

With the docker now active, students need to open a new terminal tab, then navigate to the mount directory `~/Desktop/htbfuzz`. Then, students need to make another new directory, `fuzz`. This directory is where students need to download and extract the `MaddyX.zip` file:

Code: shell

```shell
cd ~/Desktop/htbfuzz
mkdir fuzz; cd fuzz; wget -q https://academy.hackthebox.com/storage/modules/258/maddyX.zip && unzip maddyX.zip
```

```
┌─[us-academy-1]─[10.10.14.111]─[htb-ac-594497@htb-2l4nwwbcqk]─[~]
└──╼ [★]$ cd Desktop/htbfuzz/
┌─[us-academy-1]─[10.10.14.111]─[htb-ac-594497@htb-2l4nwwbcqk]─[~/Desktop/htbfuzz]
└──╼ [★]$ mkdir fuzz; cd fuzz; wget -q https://academy.hackthebox.com/storage/modules/258/maddyX.zip && unzip maddyX.zip

Archive:  maddyX.zip
  inflating: CMakeLists.txt          
   creating: include/
   creating: include/maddy/
  inflating: include/maddy/blockparser.h  
  inflating: include/maddy/breaklineparser.h  
  inflating: include/maddy/checklistparser.h  
  inflating: include/maddy/codeblockparser.h  
  inflating: include/maddy/emphasizedparser.h  
  inflating: include/maddy/headlineparser.h  
  inflating: include/maddy/horizontallineparser.h  
  inflating: include/maddy/htmlparser.h  
  inflating: include/maddy/imageparser.h  
  inflating: include/maddy/inlinecodeparser.h  
  inflating: include/maddy/italicparser.h  
<SNIP>            
```

Students need to examine the contents of their current directory and sub-directories:

Code: shell

```shell
tree
```

```
┌─[us-academy-1]─[10.10.14.111]─[htb-ac-594497@htb-2l4nwwbcqk]─[~/Desktop/htbfuzz/fuzz]
└──╼ [★]$ tree
.
├── CMakeLists.txt
├── include
│   └── maddy
│       ├── blockparser.h
│       ├── breaklineparser.h
<SNIP?
├── LICENSE
└── maddyX.zip

2 directories, 26 files
```

Students need to take note of the numerous C++ source files found within `include/maddy/`:

Code: shell

```shell
file include/maddy/*
```

```
┌─[us-academy-1]─[10.10.14.111]─[htb-ac-594497@htb-2l4nwwbcqk]─[~/Desktop/htbfuzz/fuzz]
└──╼ [★]$ file include/maddy/*

include/maddy/blockparser.h:          C++ source, ASCII text
include/maddy/breaklineparser.h:      C++ source, ASCII text
include/maddy/checklistparser.h:      C++ source, ASCII text
include/maddy/codeblockparser.h:      C++ source, ASCII text
include/maddy/emphasizedparser.h:     C++ source, ASCII text
include/maddy/headlineparser.h:       C++ source, ASCII text
include/maddy/horizontallineparser.h: C++ source, ASCII text
include/maddy/htmlparser.h:           C++ source, ASCII text
include/maddy/imageparser.h:          C++ source, ASCII text
include/maddy/inlinecodeparser.h:     C++ source, ASCII text
include/maddy/italicparser.h:         C++ source, ASCII text
include/maddy/latexblockparser.h:     C++ source, ASCII text
include/maddy/lineparser.h:           C++ source, ASCII text
include/maddy/linkparser.h:           C++ source, ASCII text
include/maddy/orderedlistparser.h:    C++ source, ASCII text
include/maddy/paragraphparser.h:      C++ source, ASCII text
include/maddy/parserconfig.h:         C++ source, ASCII text
include/maddy/parser.h:               C++ source, ASCII text
include/maddy/quoteparser.h:          C++ source, ASCII text
include/maddy/strikethroughparser.h:  C++ source, ASCII text
include/maddy/strongparser.h:         C++ source, ASCII text
include/maddy/tableparser.h:          C++ source, ASCII text
include/maddy/unorderedlistparser.h:  C++ source, ASCII text
```

With the lab scenario stating "the owner's son decided to try and improve a **Markdown library** used throughout your projects..." , students need to do a Google search for `maddy Markdown library`, which will quickly return a link to the [maddy Github repository](https://github.com/progsource/maddy). Incidentally, students need to look at the [README.md](https://github.com/progsource/maddy/blob/master/README.md) to learn how to use maddy:

![[HTB Solutions/Others/z. images/783070a8a0cbab7612926ea5a4bbb8e0_MD5.jpg]]

Students will see that the way to implement maddy in their project is to include the `parser.h` header file, then utilize a `maddy::Parser` object that will parse the contents of the `markdownInput` stringstream (which is empty in the example shown above). Therefore, students need to find a way to fuzz the value of `markdownInput`.

Additionally, students need to take note of the `CMakeLists.txt` file, indicating that the maddy project is compatible with [CMake](https://cmake.org/cmake/help/latest/). If students are unfamiliar, they are encouraged to complete the [CMake Tutorial](https://cmake.org/cmake/help/latest/guide/tutorial/index.html) (the required files for the various steps in the tutorial can be downloaded [here](https://cmake.org/cmake/help/latest/_downloads/81273695ba1d1f1755e7d3bf9d149ba2/cmake-3.29.3-tutorial-source.zip).)

Therefore, students need to create their own `C++` file for the fuzz harness, along with their own `CMakeLists.txt` file to compile a single binary that also includes the maddy library. Students need to first move all of the extracted contents of the `maddyX.zip` file into a new directory. The `maddyX.zip` file itself can be deleted as well:

Code: shell

```shell
pwd # confirm students are in ~~/Desktop/htbfuzz/fuzz
ls # confirm the presences of MaddyX.zip and its extracted contents
rm maddyX.zip; mkdir maddy # delete the zip file, then make a new directory
mv * maddy/ # Move all of the files into the newly created maddy directory
```

```
┌─[us-academy-1]─[10.10.15.99]─[htb-ac-594497@htb-dpdeq8uctz]─[~/Desktop/htbfuzz/fuzz]
└──╼ [★]$ pwd

/home/htb-ac-594497/Desktop/htbfuzz/fuzz

┌─[us-academy-1]─[10.10.15.99]─[htb-ac-594497@htb-dpdeq8uctz]─[~/Desktop/htbfuzz/fuzz]
└──╼ [★]$ ls

CMakeLists.txt  include  LICENSE  maddyX.zip

┌─[us-academy-1]─[10.10.15.99]─[htb-ac-594497@htb-dpdeq8uctz]─[~/Desktop/htbfuzz/fuzz]
└──╼ [★]$ rm maddyX.zip; mkdir maddy

┌─[us-academy-1]─[10.10.15.99]─[htb-ac-594497@htb-dpdeq8uctz]─[~/Desktop/htbfuzz/fuzz]
└──╼ [★]$ mv * maddy/
mv: cannot move 'maddy' to a subdirectory of itself, 'maddy/maddy'
```

Afterwards, students need to create two files in their working directory, `fuzz.cpp` and `CMakeLists.txt`. Students will use their own CMake file to build a single binary based off the contents of `fuzz.cpp`. Again, students need to confirm the project structure appears as it does below:

Code: shell

```shell
touch fuzz.cpp CMakeLists.txt
tree
```

```
┌─[us-academy-1]─[10.10.15.99]─[htb-ac-594497@htb-dpdeq8uctz]─[~/Desktop/htbfuzz/fuzz]
└──╼ [★]$ tree
.
├── CMakeLists.txt
├── fuzz.cpp
└── maddy
    ├── CMakeLists.txt
    ├── include
    │   └── maddy
    │       ├── blockparser.h
    │       ├── breaklineparser.h
    │       ├── checklistparser.h
    │       ├── codeblockparser.h
    │       ├── emphasizedparser.h
    │       ├── headlineparser.h
    │       ├── horizontallineparser.h
    │       ├── htmlparser.h
    │       ├── imageparser.h
    │       ├── inlinecodeparser.h
    │       ├── italicparser.h
    │       ├── latexblockparser.h
    │       ├── lineparser.h
    │       ├── linkparser.h
    │       ├── orderedlistparser.h
    │       ├── paragraphparser.h
    │       ├── parserconfig.h
    │       ├── parser.h
    │       ├── quoteparser.h
    │       ├── strikethroughparser.h
    │       ├── strongparser.h
    │       ├── tableparser.h
    │       └── unorderedlistparser.h
    └── LICENSE
```

Now, students need to write the fuzz harness; in this example, we will build one to be compatible with `AFL++`. Students need to open `fuzz.cpp` with a text editor of their choosing, and first import the necessary header files (including `parser.h` from the maddy library). Second, because `AFL++` requires an input file (the `seed corpus`) , students need to have the harness take command line arguments, so the contents of the fuzzed input file can be fed to the maddy parser:

Code: c

```c
#include "maddy/parser.h"
#include <string>
#include <iostream>
#include <memory>
#include <sstream>
#include <fstream>

int main(int argc, char *argv[])
{

    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <markdown_file>" << std::endl;
        return 1;
    }

    std::ifstream file(argv[1]);
    if (!file.is_open())
    {
        std::cerr << "Error: Could not open file " << argv[1] << std::endl;
        return 1;
    }
```

Students need to then have the contents of the file saved into saved to a string. Using `std::istreambuf_iterator`, students can read the characters from an input stream buffer (in this case, from the file provided in `argv[1]`).

Code: c

```c
#include "maddy/parser.h"
#include <string>
#include <iostream>
#include <memory>
#include <sstream>
#include <fstream>

int main(int argc, char *argv[])
{

    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <markdown_file>" << std::endl;
        return 1;
    }

    std::ifstream file(argv[1]);
    if (!file.is_open())
    {
        std::cerr << "Error: Could not open file " << argv[1] << std::endl;
        return 1;
    }
        std::string inputMarkdown((std::istreambuf_iterator<char>(file)),
                              std::istreambuf_iterator<char>());

    file.close();
```

With contents of the input file saved (as the string `inputMarkdown`), students now need to set up a maddy parser, and feed into it the contents of the file provided. Referring back to the `Parse` function found in `parser.h`, students will see that the `Parse` function takes an input stream as an argument:

![[HTB Solutions/Others/z. images/f99086fbd57d47954ff2cc793f00faee_MD5.jpg]]

Therefore, students need to initialize a stringstream called `markdownInput` containing the string found in `inputMarkdown`, and pass it as an argument to `parser.Parse`. Upon a successful parsing, the program will `return 0`. Thus, the final contents of `fuzz.cpp` will appear as follows:

Code: c

```c
#include "maddy/parser.h"
#include <string>
#include <iostream>
#include <memory>
#include <sstream>
#include <fstream>

int main(int argc, char *argv[])
{

    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <markdown_file>" << std::endl;
        return 1;
    }

    std::ifstream file(argv[1]);
    if (!file.is_open())
    {
        std::cerr << "Error: Could not open file " << argv[1] << std::endl;
        return 1;
    }
        std::string inputMarkdown((std::istreambuf_iterator<char>(file)),
                              std::istreambuf_iterator<char>());

    file.close();

    std::shared_ptr<maddy::Parser> parser = std::make_shared<maddy::Parser>();
    std::stringstream markdownInput(inputMarkdown);
    parser->Parse(markdownInput);
    
    // Return 0 on successful parsing
    return 0;
}
```

Now, students need to compile the program; however, it must include all of the classes and methods from the maddy namespace, while being compatible with `AFL++` fuzzing. To accomplish this, students will need utilize [CMake](https://cmake.org/cmake/help/latest/index.html), editing their `CMakeLists.txt` file to meet the following criteria:

- Setting the necessary [cmake\_minimum\_required](https://cmake.org/cmake/help/latest/command/cmake_minimum_required.html#command:cmake_minimum_required) version, along with a [project](https://cmake.org/cmake/help/latest/command/project.html#command:project) name.
- Inclusion of the maddy C++ source files by way of [include\_directories](https://cmake.org/cmake/help/latest/prop_tgt/INCLUDE_DIRECTORIES.html#include-directories)
- Using [set](https://cmake.org/cmake/help/latest/command/set.html#set) to specify environment variables relating to the C++ standard, as well as language-wide compilation flags.
- Defining the name of the executable to be created, as well as the source code it came from, by way of [add\_executable](https://cmake.org/cmake/help/latest/command/add_executable.html#normal-executables) .
- Linking the compiled binary with `Asan` via [target\_link\_libraries](https://cmake.org/cmake/help/latest/command/target_link_libraries.html#linking-object-libraries-via-target-objects).

Therefore, the final contents of the `CMakeLists.txt` will appear as follows:

```
cmake_minimum_required(VERSION 3.15)
project(MyFuzzerProject)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fsanitize=address -fno-omit-frame-pointer")

# Add the maddy header path
include_directories(${CMAKE_SOURCE_DIR}/maddy/include)

# Add your fuzzer target
add_executable(fuzz fuzz.cpp)

# Link with libFuzzer
target_link_libraries(fuzz -fsanitize=address)
```

Almost ready to build project, students need to switch terminal tabs, back to the tab where docker is active. From there they need to create a new directory, `build`, then navigate into it:

Code: shell

```shell
mkdir fuzz/build
cd fuzz/build
```

```
[HTBFuzz htb-dpdeq8uctz] /data $ mkdir fuzz/build
[HTBFuzz htb-dpdeq8uctz] /data $ cd fuzz/build/
```

Students need to run the `cmake` command, targeting the location of the `CMakeLists.txt` file while setting the environment variable `CXX` to `afl-clang-fast++`, specifying the compiler:

Code: shell

```shell
CXX=afl-clang-fast++ cmake ..
```

```
[HTBFuzz htb-dpdeq8uctz] /data/fuzz/build $ CXX=afl-clang-fast++ cmake ..

-- The C compiler identification is GNU 11.4.0
-- The CXX compiler identification is Clang 16.0.6
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Check for working C compiler: /usr/bin/cc - skipped
-- Detecting C compile features
-- Detecting C compile features - done
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Check for working CXX compiler: /usr/local/bin/afl-clang-fast++ - skipped
-- Detecting CXX compile features
-- Detecting CXX compile features - done
-- Configuring done
-- Generating done
-- Build files have been written to: /data/fuzz/build
```

Now, students need to create the intended `fuzz` binary, by running `make` in the current directory:

Code: shell

```shell
make
```

```
[HTBFuzz htb-dpdeq8uctz] /data/fuzz/build $ make

[ 50%] Building CXX object CMakeFiles/fuzz.dir/fuzz.cpp.o
afl-cc++4.21a by Michal Zalewski, Laszlo Szekeres, Marc Heuse - mode: LLVM-PCGUARD
SanitizerCoveragePCGUARD++4.21a
Note: Found constructor function _GLOBAL__sub_I_fuzz.cpp with prio 65535, we will not instrument this, putting it into a block list.
[+] Instrumented 6637 locations with no collisions (non-hardened mode) of which are 141 handled and 0 unhandled selects.
[100%] Linking CXX executable fuzz
afl-cc++4.21a by Michal Zalewski, Laszlo Szekeres, Marc Heuse - mode: LLVM-PCGUARD
[100%] Built target fuzz
```

With the fuzzer now compiled, students need to create`input` and `output` directories, as well as the `seed corpus` used as the initial input for the fuzzer. For the `seed corpus`, students need to create a file, `test.md`, and have it contain common elements of Markdown, such as the `#` character used for Headings:

```
#test
##test
###test
####test
```

Students need to navigate back to `/data/fuzz`, then proceed to create the aforementioned directories, while saving the `test.md` file to the selected input directory.

Code: shell

```shell
cd ..; mkdir in out ; echo -e "#test\n##test\n###test\n####test" > in/test.md
```

```
[HTBFuzz htb-dpdeq8uctz] /data/fuzz/build $ cd ..; mkdir in out ; echo -e "#test\n##test\n###test\n####test" > in/test.md
```

Students need to verify the contents of their working directory, ensuring that it contains the `fuzz` binary as well as `in` and `out` directories. The contents of the `seed corpus` should be verified as well.

Code: shell

```shell
ls ; echo; cat in/test.md 
```

```
[HTBFuzz htb-dpdeq8uctz] /data/fuzz $ ls ; echo; cat in/test.md 
CMakeLists.txt  build  fuzz  fuzz.cpp  in  maddy  out

#test
##test
###test
####test
```

With the environment now ready, students need to begin fuzzing with `afl-plus`:

Code: shell

```shell
afl-fuzz -i in -o out -- ./fuzz @@
```

```
[HTBFuzz htb-dpdeq8uctz] /data/fuzz $ afl-fuzz -i in -o out -- ./fuzz @@

[+] Enabled environment variable AFL_SKIP_CPUFREQ with value 1
[+] Enabled environment variable AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES with value 1
[+] Enabled environment variable AFL_TRY_AFFINITY with value 1
afl-fuzz++4.21a based on afl by Michal Zalewski and a large online community
[+] AFL++ is maintained by Marc "van Hauser" Heuse, Dominik Maier, Andrea Fioraldi and Heiko "hexcoder" Eißfeldt
[+] AFL++ is open source, get it at https://github.com/AFLplusplus/AFLplusplus
[+] NOTE: AFL++ >= v3 has changed defaults and behaviours - see README.md
[+] No -M/-S set, autoconfiguring for "-S default"
[*] Getting to work...
[+] Using exploration-based constant power schedule (EXPLORE)
[+] Enabled testcache with 50 MB
[+] Generating fuzz data with a length of min=1 max=1048576
[*] Checking core_pattern...
[+] You have 4 CPU cores and 4 runnable tasks (utilization: 100%).
[*] Setting up output directories...
[*] Checking CPU core loadout...
[+] Found a free CPU core, try binding to #0.
[*] Scanning 'in'...
[+] Loaded a total of 1 seeds.
[*] Creating hard links for all input files...
[*] Validating target binary...
[*] Spinning up the fork server...
[+] All right - new fork server model v1 is up.
[*] Target map size: 6644
[*] No auto-generated dictionary tokens to reuse.
[*] Attempting dry run with 'id:000000,time:0,execs:0,orig:test.md'...
    len = 30, map size = 771, exec speed = 10000 us, hash = 869e756ee1e18815
[+] All test cases processed.
[+] Here are some useful stats:

    Test case count : 1 favored, 0 variable, 0 ignored, 1 total
       Bitmap range : 771 to 771 bits (average: 771.00 bits)
        Exec timing : 10.0k to 10.0k us (average: 10.0k us)

[*] No -t option specified, so I'll use an exec timeout of 60 ms.
[+] All set and ready to roll!
```

![[HTB Solutions/Others/z. images/f1ba12e3677cea5a755053a87397386a_MD5.jpg]]

Once a crash appears, students need to `Ctrl+C` to exit the AFL fuzzer. Subsequently, students need to look at the crash dumps saved to `out/default/crashes`:

Code: shell

```shell
Ctrl+C
ls out/default/crashes/
```

```
+++ Testing aborted by user +++
[+] We're done here. Have a nice day!

[HTBFuzz htb-dpdeq8uctz] /data/fuzz $ ls out/default/crashes/

README.txt                                                                id:000002,sig:06,src:000061,time:85030,execs:8127,op:havoc,rep:12
id:000000,sig:06,src:000000+000091,time:14600,execs:1468,op:splice,rep:1  id:000003,sig:06,src:000061,time:90047,execs:8789,op:havoc,rep:2
id:000001,sig:06,src:000061,time:73654,execs:6702,op:havoc,rep:16
```

Students need to examine the crash files, which can be done by running the `fuzz` binary against the chosen crash file:

```shell
./fuzz out/default/crashes/id\:000000<REST OF SELECTED FILE NAME>
```
```
[HTBFuzz htb-dpdeq8uctz] /data/fuzz $ ./fuzz out/default/crashes/id\:000000\,sig\:06\,src\:000000+000091\,time\:14600\,execs\:1468\,op\:splice\,rep\:1 

=================================================================
==10943==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fe78b600b2f at pc 0x55efc78918d6 bp 0x7ffc29b08970 sp 0x7ffc29b08138
WRITE of size 31 at 0x7fe78b600b2f thread T0
<SNIP>
```

Instantly, students will recognize the vulnerability being a `stack-buffer-overflow`.

Answer: `stack-buffer-overflow`

# Skills Assessment Two

## Question 2

### "What file is the vulnerability contained within? Give only the file name, including the extension, eg file.h"

Students need to examine the crash file generated after causing the stack buffer overflow:

```shell
./fuzz out/default/crashes/id\:000000<REST OF SELECTED FILE NAME>
```
```
[HTBFuzz htb-dpdeq8uctz] /data/fuzz $ ./fuzz out/default/crashes/id\:000000\,sig\:06\,src\:000000+000091\,time\:14600\,execs\:1468\,op\:splice\,rep\:1 

=================================================================
==10943==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fe78b600b2f at pc 0x55efc78918d6 bp 0x7ffc29b08970 sp 0x7ffc29b08138
WRITE of size 31 at 0x7fe78b600b2f thread T0
    #0 0x55efc78918d5 in __asan_memcpy (/data/fuzz/fuzz+0xc28d5) (BuildId: ae408c5e6f23fdcc4e036d17af3f6949effd4c28)
    #1 0x55efc7951136 in maddy::HeadlineParser::parseBlock(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>&) /data/fuzz/maddy/include/maddy/headlineparser.h:120:21
    #2 0x55efc7949fea in maddy::BlockParser::AddLine(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>&) /data/fuzz/maddy/include/maddy/blockparser.h:62:19
    #3 0x55efc78d15d6 in maddy::Parser::Parse[abi:cxx11](std::istream&) const /data/fuzz/maddy/include/maddy/parser.h:131:41
    #4 0x55efc78cfe79 in main /data/fuzz/fuzz.cpp:31:13
    #5 0x7fe78cf11d8f  (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f) (BuildId: 962015aa9d133c6cbcfb31ec300596d7f44d3348)
    #6 0x7fe78cf11e3f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x29e3f) (BuildId: 962015aa9d133c6cbcfb31ec300596d7f44d3348)
    #7 0x55efc77f87c4 in _start (/data/fuzz/fuzz+0x297c4) (BuildId: ae408c5e6f23fdcc4e036d17af3f6949effd4c28)

Address 0x7fe78b600b2f is located in stack of thread T0 at offset 815 in frame
    #0 0x55efc795040f in maddy::HeadlineParser::parseBlock(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>&) /data/fuzz/maddy/include/maddy/headlineparser.h:99

  This frame has 20 object(s):
    [32, 40) '__dnew.i.i.i.i.i'
    [64, 72) '__dnew.i.i.i.i194'
    [96, 104) '__dnew.i.i.i.i'
    [128, 136) '__dnew.i.i'
    [160, 352) 'ref.tmp' (line 100)
    [416, 417) 'ref.tmp12' (line 100)
    [432, 624) 'ref.tmp32' (line 103)
    [688, 689) 'ref.tmp35' (line 103)
    [704, 705) 'ref.tmp39' (line 103)
    [720, 721) 'ref.tmp43' (line 103)
    [736, 737) 'ref.tmp47' (line 103)
    [752, 753) 'ref.tmp51' (line 103)
    [768, 769) 'ref.tmp55' (line 103)
    [784, 785) 'ref.tmp61' (line 103)
    [800, 815) 'underDraw' (line 105)
    [832, 864) 'matches' (line 109) <== Memory access at offset 815 partially underflows this variable
    [896, 928) 'tag' (line 111)
    [960, 992) 'closingTag' (line 112)
    [1024, 1056) 'content' (line 114)
    [1088, 1120) 'ref.tmp144' (line 128)
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow (/data/fuzz/fuzz+0xc28d5) (BuildId: ae408c5e6f23fdcc4e036d17af3f6949effd4c28) in __asan_memcpy
Shadow bytes around the buggy address:
  0x7fe78b600880: f8 f2 f2 f2 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
  0x7fe78b600900: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f2 f2 f2 f2
  0x7fe78b600980: f2 f2 f2 f2 f8 f2 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
  0x7fe78b600a00: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f2 f2
  0x7fe78b600a80: f2 f2 f2 f2 f2 f2 f8 f2 f8 f2 f8 f2 f8 f2 f8 f2
=>0x7fe78b600b00: f8 f2 f8 f2 00[07]f2 f2 00 00 00 00 f2 f2 f2 f2
  0x7fe78b600b80: 00 00 00 00 f2 f2 f2 f2 00 00 00 00 f2 f2 f2 f2
  0x7fe78b600c00: 00 00 00 00 f2 f2 f2 f2 f8 f8 f8 f8 f3 f3 f3 f3
  0x7fe78b600c80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7fe78b600d00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7fe78b600d80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==10943==ABORTING
```

Students need to focus on the information displayed immediately before the section regarding stack frame objects:

```
Address 0x7fe78b600b2f is located in stack of thread T0 at offset 815 in frame
    #0 0x55efc795040f in maddy::HeadlineParser::parseBlock(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>&) /data/fuzz/maddy/include/maddy/headlineparser.h:99

  This frame has 20 object(s):
    [32, 40) '__dnew.i.i.i.i.i'
    [64, 72) '__dnew.i.i.i.i194'
<SNIP>
```

Students will see the vulnerability was found within the`headlineparser.h` file.

Answer: `headlineparser.h`

# Skills Assessment Two

## Question 3

### "What function is the vulnerability in? Just give the name with empty arguments, not the full signature, eg func()"

Students need to fully examine the information displayed in the crash file, focusing on what is shown right before the information regarding the stack frame objects:

```
Address 0x7fe78b600b2f is located in stack of thread T0 at offset 815 in frame
    #0 0x55efc795040f in maddy::HeadlineParser::parseBlock(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>&) /data/fuzz/maddy/include/maddy/headlineparser.h:99

  This frame has 20 object(s):
    [32, 40) '__dnew.i.i.i.i.i'
    [64, 72) '__dnew.i.i.i.i194'
<SNIP>
```

The `parseBlock()` function is shown to be the vulnerable function.

Answer: `parseBlock()`

# Skills Assessment Two

## Question 4

### "What is the offending origin line number? Answer with an integer, eg 123"

Students need to continue to inspect the crash file, taking note of the address where the stack buffer overflow occurred:

```
==10943==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fe78b600b2f at pc 0x55efc78918d6 bp 0x7ffc29b08970 sp 0x7ffc29b08138
WRITE of size 31 at 0x7fe78b600b2f thread T0
    #0 0x55efc78918d5 in __asan_memcpy (/data/fuzz/fuzz+0xc28d5) (BuildId: ae408c5e6f23fdcc4e036d17af3f6949effd4c28)
    #1 0x55efc7951136 in maddy::HeadlineParser::parseBlock(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>&) /data/fuzz/maddy/include/maddy/headlineparser.h:120:21
    #2 0x55efc7949fea in maddy::BlockParser::AddLine(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>&) /data/fuzz/maddy/include/maddy/blockparser.h:62:19
    #3 0x55efc78d15d6 in maddy::Parser::Parse[abi:cxx11](std::istream&) const /data/fuzz/maddy/include/maddy/parser.h:131:41
    #4 0x55efc78cfe79 in main /data/fuzz/fuzz.cpp:31:13
    #5 0x7fe78cf11d8f  (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f) (BuildId: 962015aa9d133c6cbcfb31ec300596d7f44d3348)
    #6 0x7fe78cf11e3f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x29e3f) (BuildId: 962015aa9d133c6cbcfb31ec300596d7f44d3348)
    #7 0x55efc77f87c4 in _start (/data/fuzz/fuzz+0x297c4) (BuildId: ae408c5e6f23fdcc4e036d17af3f6949effd4c28)

Address 0x7fe78b600b2f is located in stack of thread T0 at offset 815 in frame
    #0 0x55efc795040f in maddy::HeadlineParser::parseBlock(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>&) /data/fuzz/maddy/include/maddy/headlineparser.h:99

  This frame has 20 object(s):
    [32, 40) '__dnew.i.i.i.i.i'
    [64, 72) '__dnew.i.i.i.i194'
    [96, 104) '__dnew.i.i.i.i'
    [128, 136) '__dnew.i.i'
    [160, 352) 'ref.tmp' (line 100)
    [416, 417) 'ref.tmp12' (line 100)
    [432, 624) 'ref.tmp32' (line 103)
    [688, 689) 'ref.tmp35' (line 103)
    [704, 705) 'ref.tmp39' (line 103)
    [720, 721) 'ref.tmp43' (line 103)
    [736, 737) 'ref.tmp47' (line 103)
    [752, 753) 'ref.tmp51' (line 103)
    [768, 769) 'ref.tmp55' (line 103)
    [784, 785) 'ref.tmp61' (line 103)
    [800, 815) 'underDraw' (line 105)
    [832, 864) 'matches' (line 109) <== Memory access at offset 815 partially underflows this variable
    [896, 928) 'tag' (line 111)
    [960, 992) 'closingTag' (line 112)
    [1024, 1056) 'content' (line 114)
    [1088, 1120) 'ref.tmp144' (line 128)
```

Students need to piece together multiple pieces of information. Asan states that the stack buffer overflow occurred at `address 0x7fe78b600b2f`. While at the same time `address 0x7fe78b600b2f` is located in stack of `thread T0 at offset 815 in frame #0`. Given these conditions, students will determine the offending origin line to be `105` (which corresponds to offset `815` in the stack frame.)

Answer: `105`

# Skills Assessment Two

## Question 5

### "What is the name of the identified problematic object within the stack?"

Having identified the both the offending origin line of `105`, at the offset of `815` in the stack frame, students will deduce that the problematic object in the stack is `underDraw`:

```
Address 0x7fe78b600b2f is located in stack of thread T0 at offset 815 in frame
    #0 0x55efc795040f in maddy::HeadlineParser::parseBlock(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>&) /data/fuzz/maddy/include/maddy/headlineparser.h:99

  This frame has 20 object(s):
    [32, 40) '__dnew.i.i.i.i.i'
    [64, 72) '__dnew.i.i.i.i194'
    [96, 104) '__dnew.i.i.i.i'
    [128, 136) '__dnew.i.i'
    [160, 352) 'ref.tmp' (line 100)
    [416, 417) 'ref.tmp12' (line 100)
    [432, 624) 'ref.tmp32' (line 103)
    [688, 689) 'ref.tmp35' (line 103)
    [704, 705) 'ref.tmp39' (line 103)
    [720, 721) 'ref.tmp43' (line 103)
    [736, 737) 'ref.tmp47' (line 103)
    [752, 753) 'ref.tmp51' (line 103)
    [768, 769) 'ref.tmp55' (line 103)
    [784, 785) 'ref.tmp61' (line 103)
    [800, 815) 'underDraw' (line 105)
    [832, 864) 'matches' (line 109) <== Memory access at offset 815 partially underflows this variable
    [896, 928) 'tag' (line 111)
    [960, 992) 'closingTag' (line 112)
    [1024, 1056) 'content' (line 114)
    [1088, 1120) 'ref.tmp144' (line 128)
```

Answer: `underDraw`