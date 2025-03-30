Many modern systems are deployed using public cloud provider infrastructure. Parts or all of the networking may be orchestrated with cloud provider services or cloud native software. Modern networking is far more open-ended than previously, enabling complex optimization, defense, and offense techniques.

In this Learning Module, we'll explore the task of collecting network forensic data from cloud native systems and cloud providers.

This Learning Module contains the following Learning Units:

- About the Public Cloud Labs
- Using eBPF Data
- Cloud Native Forensics

This Learning Module expects that we have already studied AWS, Kubernetes, networking, Linux, and OCI containers. Knowledge about eBPF is helpful, although we'll provide some context for those less familiar with the subject.

## 1. About the Public Cloud Labs

Before we jump in, let's run through a standard disclaimer.

We will use the _OffSec Public Cloud Labs_ for challenges and walkthroughs throughout this module. OffSec's Public Cloud Labs complement the learning experience with hands-on practice. In contrast to the VPN-connected VM labs we use in some of our materials, the Public Cloud Labs do not require a VPN connection as learners interact with them directly through the internet.

The OffSec Public Cloud labs are another expression of the OffSec core belief that hands-on training provides an excellent opportunity to sharpen training skills.

Please note the following:

1. The lab environment should not be used for any activities that are not described or specifically requested in the learning materials you have been provided with. It is not designed to serve as a playground to test additional items that are out of the scope of the Learning Module.
    
2. Do not use the lab environment to target any external assets. This is noteworthy because some Modules may describe or demonstrate attacks against vulnerable cloud deployments for illustrative purposes. To be clear, these illustrative demonstrations or discussions do not condone the use of the lab for the targeting of external assets.
    
3. Existing rules and requirements against sharing OffSec training materials still apply. Do not share credentials and other details of the lab. OffSec oversees activity in the Public Cloud Labs, including monitoring resource usage and detecting abnormal events that do not align with the activities outlined in the Learning Modules.
    

Caution

Activities that are flagged as suspicious will be investigated. If the investigation determines that a student acted outside of the guidelines described above, or otherwise intentionally abused the OffSec Public Cloud Labs, OffSec may choose to rescind that user's access to the OffSec Public Cloud Labs and/or terminate the user's account.

Note that progress between sessions is not saved. Restarting a Public Cloud Lab will reset it to its original state. After an hour has elapsed, the Public Cloud Lab will prompt to determine if the session is still active. If there is no response, the lab session will end. Learners can continue to manually extend a session for up to ten hours.

The learning material is designed to accommodate the limitations of the environment. No learner is expected or required to complete all of the activities in a Module within a single lab session. Even so, learners may choose to break up their learning into multiple sessions with the labs. We recommend learners document performed actions so they can restore the state of the lab environment should the session reset. This is especially important when working through complex labs that require multiple actions.

## 1.1. Accessing the Lab

In this lab, we have four EC2 nodes. They can be accessed by an SSH key that we have stored in AWS Secrets Manager. We will need to extract the SSH key, then connect using SSH as the _ubuntu_ user. Two of the nodes we'll use the most have IP addresses in the lab information that is displayed after the lab starts. The other two public IP addresses can be found using **aws ec2 describe-instances**.

We're currently using our graphical workstation (such as a VM on our PC) or [_bastion host_](https://www.strongdm.com/what-is/bastion-host) (such as a VM somewhere else). Next, let's configure the AWS CLI to use the credentials provided with the lab. We'll use `aws configure` on our bastion host or workstation, entering the _Key ID_ and _Secret Key_ provided for the lab. We'll use _us-east-1_ region, and we can output as _json_ format.

```
┌──(kali㉿kali)-[~/workspace/]
└─$ aws configure
AWS Access Key ID [****************XBW2]: AKIARLO3TVYSHW2THWHH
AWS Secret Access Key [****************HWW4]: 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
Default region name [us-east-1]:
Default output format [json]:
```

> Listing 1 - Configure AWS CLI

Once the AWS CLI is configured, we'll interact with the Secrets Manager API by passing the `secretsmanager` argument to `aws`. The second argument is `list-secrets` to display all of the secrets in AWS Secrets Manager we have access to. We'll pipe this to `grep` to retrieve the data we are interested in, the "Name" value.

```
┌──(kali㉿kali)-[~/workspace/]
└─$ aws secretsmanager list-secrets | grep "Name"
        	"Name": "ubuntu-ssh-access-key-20240124085001",
```

> Listing 2 - Listing AWS Secrets Manager example

Next, let's extract the key file. We'll copy the value of _Name_ to the clipboard and replace the value used in `--secret-id` with the copied name. We'll run this rather long command to extract the data from the JSON, base64 decode it, and write it to a new file with 600 permissions.

```
┌──(kali㉿kali)-[~/workspace/]
└─$ aws secretsmanager get-secret-value --secret-id="ubuntu-ssh-access-key-20240124085001" | \
grep SecretString | cut -d':' -f2 | cut -c3- | rev | cut -c3- | rev | base64 -d > \
lab_id.pem && chmod 600 lab_id.pem
```

> Listing 3 - Extracting from AWS Secrets Manager example

We could have used [_jq_](https://jqlang.github.io/jq/) to replace some of the shell pipes in the last example, but we demonstrated the action without needing jq software installed. Now that we have our SSH identity extracted, we'll connect to the EC2 instances, and explore the lab environment as we work through the Learning Module.

The lab resources view has the IP addresses of two of our EC2 instances, but we can also quickly extract all four IP addresses to a text file on our workstation or bastion host.

We'll demonstrate checking for the IP addresses using **aws ec2 describe-instances** piped to a **grep** to filter what we want, and then a **tee** to have STDOUT additionally write to a file named **ips.txt**. We'll then use **ssh -i lab_id.pem**, leveraging the extracted credentials to connect. We have a user on these [_Amazon Machine Images_](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html) named _ubuntu_ we can connect with. We'll also set the IP address to the values we received from AWS.

```
┌──(kali㉿kali)-[~/workspace/]
└─$ aws ec2 describe-instances | grep PublicIpAddress | tee ips.txt
                    "PublicIpAddress": "3.239.7.108",
                    "PublicIpAddress": "44.210.109.232",
                    "PublicIpAddress": "54.89.191.71",
                    "PublicIpAddress": "50.16.66.185",                	
┌──(kali㉿kali)-[~/workspace/]
└─$ ssh -i lab_id.pem ubuntu@54.89.191.71

The authenticity of host '54.89.191.71 (54.89.191.71)' can't be established.
ED25519 key fingerprint is SHA256:QG3Wcl5trwv4P6JQDYaAZU7PVshbGbdA6UfKpqgjyN8.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes

Warning: Permanently added '54.89.191.71' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 6.2.0-1017-aws x86_64)
...
```

> Listing 4 - Initial SSH to EC2 instance

Let's confirm successful access to each lab machine, adding the fingerprint to the **known_hosts** file by typing "yes" when prompted. Next, we'll use this access to investigate the network forensics of a fictional lab case.

We can set the EC2 instances in our **hosts** file if we would like to use the names instead of the IP addresses when executing the commands.

Let's start the lab and investigate the resources within as we progress through this Learning Module. We'll encounter questions that require analysis of the data and files from the EC2 instances.

## 2. Using eBPF Data

With the features of eBPF (extended Berkeley Packet Filter), we can capture packets in new and optimized ways without needing to run tcpdump or operate expensive proxy devices. Tcpdump is the original BPF user program, but modern eBPF can be further optimized in performance and data use.

In our lab case, we'll research both user space malware and eBPF malware that sends or modifies network traffic. First, we'll spend some time understanding system inner workings and reverse engineering the user space malware. We'll then work up to reverse engineering some eBPF malware in our lab.

This Learning Unit covers the following Learning Objectives:

- Getting Data from eBPF
- Understand Data Completeness Risks

We are working on the "Network-Forensics-Ubuntu" EC2 instance of the lab in this Learning Unit.

## 2.1. Syscalls and Networks

A [_syscall_](https://www.man7.org/linux/man-pages/man2/syscall.2.html) is how processes from user space utilize operating system functionality provided by the kernel.

Tracing syscalls can help us better understand network forensic data. Every connection made from within the operating system originated with a _syscall_: a request to the kernel to access network resources.

|Syscall|Description|
|---|---|
|socket()|Creates a new socket, returning a file descriptor.|
|bind()|Binds a socket to a local address and port.|
|listen()|Marks a socket as passive, ready to accept incoming TCP connections (TCP only).|
|accept()|Accepts an incoming connection on a listening socket (TCP only).|
|connect()|Initiates a connection to a remote server (TCP only).|
|send()|Sends data over a connected TCP socket.|
|sendto()|Sends data to a specified destination (used in UDP).|
|sendmsg()|Sends a message over a socket with more control over message properties.|
|recv()|Receives data from a connected TCP socket.|
|recvfrom()|Receives data from a specific sender (used in UDP).|
|recvmsg()|Receives a message from a socket with additional metadata.|
|shutdown()|Shuts down part or all of the connection (e.g., sending, receiving).|
|close()|Closes the socket, releasing its resources.|
|poll()|Monitors multiple file descriptors for events (ready to read/write).|
|select()|Waits for a set of file descriptors to become ready for I/O operations.|
|epoll_wait()|Efficiently monitors multiple file descriptors for I/O readiness.|
|getsockopt()|Retrieves options for a socket (e.g., buffer size, timeouts).|
|setsockopt()|Sets options for a socket (e.g., enabling keepalive).|

> Listing 5 - Table of common network syscalls for Linux

Every network connection from within the operating system originated with a syscall to the kernel, _unless_ it uses _extended Berkeley Packet Filter_ [_eBPF_](https://ebpf.io/). The use of eBPF enables us to program the kernel during runtime for efficient networking, security, and much more. In some situations, eBPF can operate _in front_ of the rest of the system and respond directly with network activity that does not require a syscall to the kernel. User space programs still make syscalls to eBPF programs; but syscalls can be skipped by eBPF, since eBPF operates in kernel space.

In the diagram below, we have simplified the relationships between programs, the kernel, hardware drivers, and the network hardware itself in four different scenarios. While both kernel modules and eBPF run in kernel space, eBPF can also _extend_ kernel space to the hardware memory. This _offloading_ requires that both the hardware and kernel support and enable it.

![[OffSec/Cloud/Cloud Computing Network Forensics/z. images/fdd9620ef74a7a1353ed5a0faa57652e_MD5.jpg]]

Figure 1:

In scenarios where [express data path](https://www.tigera.io/learn/guides/ebpf/ebpf-xdp/) (XDP) is offloaded to hardware, we might miss some of the network activity if we only are checking in the kernel for syscalls.

While eBPF can be used to hide, it can also be used to _trace_ syscalls. Tracing all syscalls is uncommon, as that amount of data could become very large and expensive to store. Tracing is often utilized when debugging or investigating an important event. Many types of security software, such as _endpoint detection and response_ (EDR), can typically trace processes' syscalls. This can be done from within the kernel using a kernel module (like [_Crowdstrike Falcon_](https://www.crowdstrike.com/platform/)), or with eBPF (like [_Tetragon_](https://tetragon.io/)), or using both (such as [_Falco_](https://falco.org/)).

Syscall tracing can also be used with syscall enforcement to block or disrupt syscalls that might be malicious, another feature that EDR and security system agents tend to utilize. This means that we can load eBPF programs to mitigate or disrupt attacks directly. Similarly, an adversary with superuser or eBPF loading capability can load malicious eBPFs. This is important to understand because classical methods of gathering network forensic data may not apply exactly the same in a system with eBPF-based networking. Collecting a packet capture on the host using tcpdump could miss traffic forking exfiltration created by an attacker's eBPF program loaded into hardware instructions.

To ensure we capture all of the data, it is ideal to take packet captures from network equipment such as a firewall, switch, or load balancer that is on separate hardware and controls traffic ingress. We also need to consider that XDP may be used on the firewall as well. Because of this, we'll want to keep track of whether eBPF is in use on each device and use tools to measure such usage.

On our lab machine with the IP labelled "Network-Forensics-Ubuntu", we can find a running malware process that we'll trace to demonstrate system call tracing manually from user space. We can accomplish this by using the _ptrace_ syscall via the [_strace_](https://strace.io/) tool. Typically only a superuser account is able to execute ptrace syscalls to the kernel, as this level of access can leak sensitive data and application internal configurations.

In our lab case, we have a program running in user space, and we are going to use _strace_ on it to search for network related activity and develop further forensic understanding.

For user space programs, we can find the _process id_ (PID) of the malware using **ps auxwww**.

```
ubuntu@ip-10-0-0-180:~$ ps auxwww
...(CUT)...
root    	16960  0.0  0.0   1248   896 ?    	S	19:32   0:00 /tmp/.health 149.56.244.87
...(CUT)...
ubuntu@ip-10-0-0-180:~$
```

> Listing 6 - Finding the PID of the malware process

Advanced adversaries may attempt to hide the process from us, making it more difficult to detect the activity and find the PID. If we don't find any processes running, we should consider whether the process is able to hide from us. As a root user without any [_Mandatory Access Controls_](https://csrc.nist.gov/glossary/term/mandatory_access_control) (MAC) applied (such as from selinux), we should be able to observe all processes. If an attacker is able to use Mandatory Access Controls against us so that even root cannot observe the process, they may be able to hide activity.

Another mechanism to hide is by manipulating **/proc** and **/sys**, since **ps** and others extract information from there. If an attacker can prevent the **ps** program from reading data from **/proc**, they might be able to hide from us.

In our case, no such hiding took place, and we observed the running process. Next, we'll investigate it.

In AWS, the Ubuntu AMI does not require a password to become root, so we can enter **sudo su -** as our _ubuntu_ user and become the root user. While it's generally a bad practice to work as root in normal server use, when performing system forensic and debugging tasks, it can be beneficial or even necessary to utilize the root shell. In some situations we will not have a root shell, and might not have a shell at all. In some cases, we only have the SIEM, or centralized storage of data. In other scenarios, we may have _immutable_ and _reduced_ systems that don't allow _ptrace_ syscalls at all.

In this Learning Module, we will have root access and the ability to explore deeply to improve our awareness.

```
ubuntu@ip-10-0-0-180:~$ sudo su -
root@ip-10-0-0-180:~#
```

> Listing 7 - Sudo to root

Let's use the program **strace** in our lab environment to trace system calls of some malware on the system. We'll attach a tracing _probe_ to the _process id_ with **-p**, specifying **-t** for timestamps. We should note that we've replaced the actual payload with "...(CUT)...". We'll need to collect that value from our lab machine. It is the payload data that the malware is sending out to **149.56.244.87**.

The PID value will be different in each lab, so we need to use the PID from the malware process found inside the lab EC2 instance. The malware starts and stops, so we'll have to act quickly to gather the PID and trace it before it stops running.

```
root@ip-10-0-0-180:~# strace -t -p 16960
strace: Process 16960 attached
23:49:42 restart_syscall(<... resuming interrupted read ...>) = 0
23:49:48 statx(AT_FDCWD, "/tmp/.sys.8.lock", AT_STATX_SYNC_AS_STAT, STATX_ALL, 0x7ffe10f210e0) = -1 ENOENT (No such file or directory)
23:49:48 sendto(3, "...(CUT)...", 26, MSG_NOSIGNAL, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("149.56.244.87")}, 16) = 26
23:49:48 write(1, "Message sent: ...(CUT)..."..., 41) = 41
23:49:48 write(1, "Sleeping for 20 seconds...\n", 27) = 27
23:49:48 clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=20, tv_nsec=0}, ^Cstrace: Process 16960 detached
 <detached ...>
```

> Listing 8 - Tracing syscalls of the malware

The process only runs for half of each minute before stopping. We may need to wait or trace twice in order to capture the network-related activity in this case.

In addition to being able to find both the payload and the IP address using the syscalls, we also discovered another aspect about this malware regarding a lock file. This lock file might be further explored by reverse engineering this malware component. For our network forensics case, we've collected what we need from our syscall tracing: we found a _sendto()_ syscall to the unauthorized 149.56.244.87 address.

Details about the malware activity would be included in the forensic case. We want to include how the syscall traces were made, the computer or computers the trace was performed on, and all of the details in the trace data. We have further evidence of potentially-malicious activity relating to the IP address 149.56.244.87, which resolves to www.megacorpone.com, a website controlled by the attacker in our lab.

We might not be permitted to perform a syscall trace on a given system. It also may be designed so that no one is able to perform such a trace. If we cannot collect any syscall trace data, we'll have to rely on other methods for collecting forensic evidence. In cloud native computing, increasingly we utilize various APIs for forensics. We commonly need superuser access to the host in order to perform syscall tracing. Many organizations use security software to automatically trace syscalls, forwarding events or data to central systems.

#### Labs

1. Which identifier do we commonly want when we trace syscalls?

Answer

2. Which syscall was used in the example malware exfiltration?

Answer

3. What is the 26-byte payload that the malware was sending out to www.megacorpone.com?

Answer

## 2.2. eBPF Forensic Data

A brief review of eBPF itself will help us prepare for forensic data collection. Understanding the protocols, tools, and uses helps us more effectively gather network forensic data. There are many possible ways that eBPF can be designed and used, but they share a few common limitations currently. These limitations include the lack of for-loops and iteration, as well as size and field count limitations. The programs are checked by the just-in-time verifier before being loaded, then loaded as a constant _filter_ or _effect_ on syscalls. But eBPF can do more than simply filter and modify - with XDP, we can effectively skip areas of processing in the kernel. XDP is a feature of the Linux kernel that enables network packets to bypass the network stack and memory allocation to optimize performance. This can reduce the use of NAT, eliminate more complex networking, eliminate some syscalls, and even load instructions into network interface hardware, known as _XDP offloading_.

Tools like **bpftool** can be used to inspect programs that are loaded into the kernel, including XDP items. We can, in theory, always find what is loaded by using tools like **bpftool**. It's very challenging for adversaries to hide eBPF programs from **bpftool** on Linux, but we should also consider if an eBPF that is normally-loaded has been maliciously modified to perform an additional duty, such as data exfiltration or hiding.

Let's use **bpftool** to list all of the loaded _eBPF maps_ on our lab machine. In eBPF, _maps_ are a mechanism to enable communication between eBPF programs, as well as between eBPF programs and user space. The CLI option **map** can interact with maps. In our case we have an XDP program, so we'll want to use **prog**. Let's list all of the maps and programs using **show**.

This helps us understand all of the program names, sizes, ids, and the times that they were loaded.

```
root@ip-10-0-0-180:~# bpftool map show
...(CUT)...
root@ip-10-0-0-180:~# bpftool prog show
...(CUT)...
```

> Listing 9 - Finding all eBPF programs with bpftool

If we know the maps and programs that are _intended_ to be loaded, we can find items with anomalous names. Beyond that, we can check the integrity of each individual loaded map and program. We'll use **bpftool** again, this time to dump the program of a specific name. If we know each program requirements, or we have hashes of them, we can compare that to what is loaded to attempt to identify if a normal eBPF has been tampered with.

In our lab machine, we'll find an XDP eBPF program attempting to manipulate network traffic. We may first notice that we have XDP on the NIC in the **ip -detail a** command.

On our NIC _eth0_, we could have a line that can show the program id of the XDP. In our lab, the Ubuntu defaults currently prevent the program from being pinned to the interface. If that changes in the future, we might observe the malware pinning the program to the interface.

```
root@ip-10-0-0-180:~# ip -detail a
...(CUT)...
prog/xdp id 78 tag 08df2b9153977259 jited
...(CUT)...
```

> Listing 10 - Review interface XDP pin

With the program id of "78" in our example, we can dump the instructions of the program. We can also collect these id's from the **bpftool prog show** output.

We'll pass a few options to **bpftool** to **dump** the eBPF program instructions. Using these assembly instructions, we can reverse engineer the program.

```
root@ip-10-0-0-180:~# bpftool prog dump xlated id 78
int mirror_packets(struct xdp_md * ctx):
; int mirror_packets(struct xdp_md *ctx) {
   0: (b7) r0 = 2
; void *data_start = (void *)(long)ctx->data;
   1: (79) r2 = *(u64 *)(r1 +0)
; void *data_end = (void *)(long)ctx->data_end;
   2: (79) r1 = *(u64 *)(r1 +8)
; if (data_start + sizeof(struct ethhdr) > data_end) {
   3: (bf) r3 = r2
   4: (07) r3 += 14
; if (data_start + sizeof(struct ethhdr) > data_end) {
   5: (2d) if r3 > r1 goto pc+8
   6: (bf) r3 = r2
   7: (07) r3 += 34
   8: (2d) if r3 > r1 goto pc+5
   9: (b7) r0 = 1
  10: (18) r1 = 0x9538f457
;
  12: (1d) if r2 == r1 goto pc+1
  13: (b7) r0 = 2
; }
  14: (95) exit
```

> Listing 11 - Review XDP machine instructions

The first instruction, _instruction 0_, in the example XDP dump is "0: (b7) r0 = 2", which is an XDP_PASS of all traffic on the interface to the regular system. This allows all of the traffic to flow as expected to the system. The instructions 1-2 then check for packet payload data.

```
1: (79) r2 = *(u64 *)(r1 +0)   ; r2 = ctx->data
2: (79) r1 = *(u64 *)(r1 +8)   ; r1 = ctx->data_end

```

> Listing 12 - Instructions 1 and 2

The next set of instructions, 3-8, determine if the packet data and header sizes match rules and route those packets differently.

```
3: (bf) r3 = r2             	; r3 = data_start
4: (07) r3 += 14            	; r3 += 14 (Ethernet header size)
5: (2d) if r3 > r1 goto pc+8	; if (r3 > data_end) goto exit
6: (bf) r3 = r2             	; r3 = data_start
7: (07) r3 += 34            	; r3 += 34 (Ethernet + IP header size)
8: (2d) if r3 > r1 goto pc+5	; if (r3 > data_end) goto exit

```

> Listing 13 - Instructions 3 through 8

Next, the program prepares to drop packets. It checks if the packet is destined for the big-endian hex representation of **149.56.244.87**.

```
9: (b7) r0 = 1              	; r0 = XDP_DROP
10: (18) r1 = 0x9538f457
12: (1d) if r2 == r1 goto pc+1  ; if (data_start == 0x9538f457) skip next
13: (b7) r0 = 2             	; else, r0 = XDP_PASS
```

> Listing 14 - Instructions 9 through 13

This IP address is a critical point of evidence for our case, assuming that this program is not intentionally in use by the organization. Let's say that the program is not expected for the scenario in our lab. This IP address has been associated with other malware, in our case.

To manually convert the hex value to an IP address, we can use a number of different mechanisms. We'll use a Python script to do it this time:

```
root@ip-10-0-0-180:~# python3 /root/convert.py -d 0x9538f457
Hex 0x9538f457 -> IP: "149.56.244.87"
```

> Listing 15 - Example conversion of hex IPv4 addresses

We have learned that the eBPF program is preventing some types of payloads from going back to the attacker IP address. We can't be sure why the attacker wants to drop packets, so we don't want to draw conclusions we can't support with evidence. Instead, we'll take note of the functionality and move on carefully. It may be that the eBPF program is waiting to be found, and by removing it, we'll allow out some type of packet the attacker is waiting for. This eBPF program is similar to one we might utilize for a defensive measure, like a small and specific firewall.

In some scenarios, we might intentionally insert an XDP program like this as defenders within the organization in reaction to an attack. This would enable us to drop specific packets without needing to stop the running malware so that further analysis can be completed.

In this case, the XDP program is not exfiltrating any data, and may actually be preventing exfiltration of data. We know that it isn't dropping normal traffic or the UDP payload that we found going out from the lab VM, so the exact reason for the eBPF is unknown at this time in our lab case.

If the organization has captured all that it needs and taken all of the appropriate live system investigation steps, we can move forward with removing it. These XDP programs are loaded into the **/sys/fs/bpf/** directory. We can use **rm** or **mv** to disable an XDP program, although additional steps may be needed depending on the situation and system in use.

```
root@ip-10-0-0-180:~# rm -rf /sys/fs/bpf/mirror_packets

```

> Listing 16 - Delete malware XDP program

We are also going to use **ip** to disable XDP on the NIC. In scenarios where XDP is used intentionally by the organization, we might skip this step, as it could break the networking.

```
root@ip-10-0-0-180:~# ip link set dev eth0 xdp off
```

> Listing 17 - Disable XDP on the interface

In the case of our lab, a new XDP program was inserted. If the organization uses XDP normally, an advanced attacker might instead update the instructions of an already-running program. It may not always be obvious. Some attacks come from expected IP sources, and even may appear to send to an expected location. Such examples may be missed or misunderstood during an incident.

Thankfully, we can detect both kernel module loading and eBPF loading in the _kernel message buffer_, which is commonly also sent to _systemd journals_ or log files, and may be forwarded to centralized logging such as the SIEM. The times at which each eBPF program is loaded may be useful in detecting malicious activity as well as understanding changes to upstream providers.

Not all systems are set up to log XDP loading. This can result in missed evidence. Other aspects of the operating system's audit logging might help capture such events. By default, many Linux systems do not provide sufficient logging around eBPF activity.

Let's observe what happens when an eBPF program is inserted by performing a **dmesg -T** to print the kernel message buffer and include timestamps in the output. We are searching for any mention of bpf or ebpf in the message buffer.

```
root@ip-10-0-0-180:~# dmesg -T
```

> Listing 18 - Check the kernel message buffer

In some versions of Ubuntu, we may not observe a message for each time that **bpftool** manipulated the XDP programs. This indicates that the configuration may lack sufficient audit logging for eBPF.

It is important that we understand syscalls and eBPF for network forensic work, both on-prem and in cloud systems. Next, we'll examine a few additional aspects to supporting a forensic case in cloud computing.

#### Labs

1. What is the name of the XDP program that was loaded on the lab EC2 instance?

Answer

2. Which XDP instruction in the lab XDP allows the traffic?

Answer

## 3. Cloud Native Forensics

There is a vast amount of cloud native software, and we can also make our own. Cloud native network forensics builds on what we have already learned about network forensics, adding additional platforms, abstractions, technologies, software, and designs. This added technical complexity is typically desirable to simplify operations by abstracting or hiding the more complex under-workings. To use a public cloud provider-managed Kubernetes service is a heavily abstracted experience, but we still may have some access and control over the worker nodes, depending on the type of worker nodes utilized.

Some cloud systems do not have any CLI SSH access, and APIs must be used for all activity. This complete lack of SSH may be surprising, but it's an increasingly popular style. When we only have APIs, we rely on the features of those APIs to do everything we need to do, and that includes gathering forensic data and debugging. Currently, most systems still use a more traditional POSIX-style shell in addition to APIs. We'll review leveraging both SSH access to the cluster nodes and Kubernetes API access in a K3S lab environment.

This Learning Unit covers the following Learning Objectives:

- Review Gathering Network Forensic Data from OCI Containers
- Explore Network Forensic Data from Kubernetes
- Collect Forensic Data from Cloud Service Providers

We are working on the "K3S-Controller" EC2 instance and the two EC2 worker nodes joined with it for the first part of this Learning Unit. In the last section, we'll return to the "Network-Forensics-Ubuntu" instance in the lab.

## 3.1. Container Network Forensics

Gathering forensic data from container-based systems can be challenging because of how _ephemeral_ containers may be. Containers may be automatically destroyed, potentially destroying forensic evidence along with them. Nevertheless, there are techniques we can utilize to capture, collect, and isolate containers for forensic investigation.

There are many types of containers, but we'll be focusing on [_Open Container Initiative_](https://opencontainers.org/) (OCI) containers, the same type of containers we currently use by default in Docker, Podman, and Kubernetes. Docker and Podman are commonly used to build new container images, which are typically then run inside a Kubernetes cluster, so we'll be focusing on Kubernetes for our lab. Kubernetes makes adoption of eBPF easy, and in some cases automatic. The cluster we are exploring in this lab does not have eBPF-based networking implemented, however. And unlike the malicious XDP program we explored earlier, the network forensics task is much less obvious in this Kubernetes cluster.

Let's work through an example process to isolate and research the activity, although there is little network forensic evidence readily available. A lack of evidence is just as important to be able to handle as when there is an abundance of evidence. Because we don't have clear network evidence in this cluster, we have the opportunity to cover many areas of container forensics and incident response while systematically seeking network evidence.

In our lab environment, we have a Kubernetes control plane node, the EC2 with the public IP labelled as "K3S-Controller", and two worker nodes attached to it in a cluster. In that cluster, we'll find two applied Helm charts and a malicious manifest. One of the Helm charts is Falco, the security system in place. The other Helm chart is the purpose of the cluster, a stream processor system called [_Arroyo_](https://www.arroyo.dev/). The Arroyo system is accessed for testing and development purposes in this example, but it's still important to research for malicious activity. Development environments are often easier for attackers to reach and exploit because they may lack security system integration.

In this case, we find that the security system only has the default Falco rules applied, and there is no aggregation of the Falco logs in a central location. The attacker was also able to apply the manifest in a way that may avoid detection, at least for the initial phase of the attack.

It appears that the attacker may have only made it to the initial phase of the attack on this cluster, but as network forensics analysts, we are tasked with collecting any network evidence on the live system in our lab. As we have learned from studying network forensics, we want to collect any _source_ and _destination_ IP addresses that are important to the case. We'll start by accessing the control node of the cluster via SSH. This cluster uses K3S, and we can access the cluster admin with superuser permissions from the control node.

Using **k3s kubectl**, we can review the status of the cluster. We want to list and describe aspects of the cluster state to initially triage what is happening. We start with **sudo k3s kubectl get pods -A -o wide**:

```
ubuntu@ip-172-31-42-75:~$ sudo k3s kubectl get pods -A -o wide
NAMESPACE 	NAME                                  	READY   STATUS  	RESTARTS   AGE 	IP      	NODE           	NOMINATED NODE   READINESS GATES
default   	arroyo-controller-5d4bbdbf85-vhmxj    	1/1 	Running 	0      	5m6s	10.42.1.4   ip-172-31-41-246   <none>       	<none>
default   	arroyo-postgresql-0                   	1/1 	Running 	0      	5m6s	10.42.2.6   ip-172-31-32-194   <none>       	<none>
falco     	falco-2s5t6                           	2/2 	Running 	0      	5m9s	10.42.0.8   ip-172-31-42-75	<none>       	<none>
falco     	falco-2vhhk                           	2/2 	Running 	0      	5m9s	10.42.1.3   ip-172-31-41-246   <none>       	<none>
falco     	falco-6ln9q                           	2/2 	Running 	0      	5m9s	10.42.2.4   ip-172-31-32-194   <none>       	<none>
kube-system   coredns-ccb96694c-257jt               	1/1 	Running 	0      	6m20s   10.42.0.2   ip-172-31-42-75	<none>       	<none>
kube-system   helm-install-traefik-bhfxr            	0/1 	Completed   2      	6m20s   10.42.0.6   ip-172-31-42-75	<none>       	<none>
kube-system   helm-install-traefik-crd-68zmq        	0/1 	Completed   0      	6m20s   10.42.0.3   ip-172-31-42-75	<none>       	<none>
kube-system   local-path-provisioner-5cf85fd84d-lkmm2   1/1 	Running 	0      	6m20s   10.42.0.5   ip-172-31-42-75	<none>       	<none>
kube-system   metrics-server-5985cbc9d7-jxt66       	1/1 	Running 	0      	6m20s   10.42.0.4   ip-172-31-42-75	<none>       	<none>
kube-system   svclb-traefik-92109db2-c85m4          	2/2 	Running 	0      	5m45s   10.42.0.7   ip-172-31-42-75	<none>       	<none>
kube-system   svclb-traefik-92109db2-dnxzg          	2/2 	Running 	0      	5m45s   10.42.2.3   ip-172-31-32-194   <none>       	<none>
kube-system   svclb-traefik-92109db2-r5cjb          	2/2 	Running 	0      	5m45s   10.42.1.2   ip-172-31-41-246   <none>       	<none>
kube-system   traefik-57b79cf995-mxvg2              	1/1 	Running 	0      	5m46s   10.42.2.2   ip-172-31-32-194   <none>       	<none>
red       	admin-b47569574-5ltmh                 	1/1 	Running 	0      	5m5s	10.42.1.5   ip-172-31-41-246   <none>       	<none>
ubuntu@ip-172-31-42-75:~$
```

> Listing 19 - Review the Pods in the cluster

In the output, we find the unexpected Pod named **admin**. In order to know what is expected and what is not expected, we need to review the expected state of the system using the code and documentation for our organization. In this case, we learned from the organization that Falco and Arroyo are the only expected applications in this cluster. Since we found something else, let's learn more about this Pod using **sudo k3s kubectl describe pods -n red**, as there is only one Pod in the **red** namespace:

```
ubuntu@ip-172-31-42-75:~$ sudo k3s kubectl describe pods -n red
Name:         	admin-b47569574-5ltmh
Namespace:    	red
Priority:     	0
Service Account:  default
Node:         	ip-172-31-41-246/172.31.41.246
Start Time:   	Thu, 02 Jan 2025 21:23:07 +0000
Labels:       	app=arroyo
              	pod-template-hash=b47569574
Annotations:  	<none>
Status:       	Running
IP:           	10.42.1.5
IPs:
  IP:       	10.42.1.5
Controlled By:  ReplicaSet/admin-b47569574
Containers:
  admin:
	Container ID:  containerd://025d5f00afff65e457eef04bcd373097387015501f3d5d793090452507bc545c
	Image:     	alpine:latest
	Image ID:  	docker.io/library/alpine@sha256:21dc6063fd678b478f57c0e13f47560d0ea4eeba26dfc947b2a4f81f686b9f45
	Port:      	<none>
	Host Port: 	<none>
	Command:
  	/bin/sleep
	Args:
  	9999
	State:      	Running
  	Started:  	Thu, 02 Jan 2025 21:23:10 +0000
	Ready:      	True
	Restart Count:  0
	Environment:	<none>
	Mounts:
  	/var/run/secrets/kubernetes.io/serviceaccount from kube-api-access-975d4 (ro)
  	/var/tmp from adminroot (rw)
Conditions:
  Type                    	Status
  PodReadyToStartContainers   True
  Initialized             	True
  Ready                   	True
  ContainersReady         	True
  PodScheduled            	True
Volumes:
  adminroot:
	Type:      	HostPath (bare host directory volume)
	Path:      	/
	HostPathType:  Directory
  kube-api-access-975d4:
	Type:                	Projected (a volume that contains injected data from multiple sources)
	TokenExpirationSeconds:  3607
	ConfigMapName:       	kube-root-ca.crt
	ConfigMapOptional:   	<nil>
	DownwardAPI:         	true
QoS Class:               	BestEffort
Node-Selectors:          	<none>
Tolerations:             	node.kubernetes.io/not-ready:NoExecute op=Exists for 300s
                         	node.kubernetes.io/unreachable:NoExecute op=Exists for 300s
Events:
  Type	Reason 	Age   From           	Message
  ----	------ 	----  ----           	-------
  Normal  Scheduled  17m   default-scheduler  Successfully assigned red/admin-b47569574-5ltmh to ip-172-31-41-246
  Normal  Pulling	17m   kubelet        	Pulling image "alpine:latest"
  Normal  Pulled 	17m   kubelet        	Successfully pulled image "alpine:latest" in 1.398s (1.398s including waiting). Image size: 3655264 bytes.
  Normal  Created	17m   kubelet        	Created container admin
  Normal  Started	17m   kubelet        	Started container admin
```

> Listing 20 - Describing Pods to learn details

We learn that this Pod has a container with a shell, and that the container has mounted the root file system of the underlying node. We know that it has a shell because it is the standard latest Alpine Linux container image that is commonly used and contains a shell.

Mounting the entire disk of the underlying node is a container escape, enabling the attacker to carry out many types of further attacks or adversarial objectives. The same technique is sometimes used by administrators to debug. As network forensic investigators, this is good to know and helps us understand the attack, and is forensic evidence, but it isn't network forensic evidence in itself. What we need as network forensic analysts is to examine the _source_, where this malicious manifest came from, or if there have been any connections _to_ this malicious container or _to_ any other resources.

If we have the [container runtime interface](https://kubernetes.io/docs/concepts/architecture/cri/) (CRI) [checkpoint API functionality](https://kubernetes.io/docs/reference/node/kubelet-checkpoint-api/) available, we could utilize that to create a container snapshot that captures all of the active network connections and the container image.

Feel free to explore this option, however, it may not result in a snapshot if the checkpoint API is not enabled.

In order for this example to authenticate, we need to extract administrative cluster credentials to **/home/ubuntu/admin**, although any directory may be used, and populate the URI context of a POST request with the values required by the checkpoint API. After "/checkpoint/", we have the namespace and the Pod, followed by the container ID. The container ID is found in the output when we describe the Pod as we did previously.

The location of the authenticating certificate and key for kubelet varies between Kubernetes implementations, but for k3s, we can find them in **/var/lib/rancher/**:

```
root@ip-172-31-46-63:/var/lib/rancher/k3s/server/tls# cat client-admin.crt
-----BEGIN CERTIFICATE-----
MIIBkTCCATegAwIBAgIITrUjRtS9pecwCgYIKoZIzj0EAwIwIzEhMB8GA1UEAwwY
azNzLWNsaWVudC1jYUAxNzM2MzgwODA3MB4XDTI1MDEwOTAwMDAwN1oXDTI2MDEw
OTAwMDAwN1owMDEXMBUGA1UEChMOc3lzdGVtOm1hc3RlcnMxFTATBgNVBAMTDHN5
c3RlbTphZG1pbjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMMpPpauPwh+E+Rf
n0yic3nm9lzYEXwFHlQic4OmplF/ODUIcDDfRCTtxFzSQz5mxxUKx+mvgvYDyTsd
SkJfz2yjSDBGMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDAjAf
BgNVHSMEGDAWgBTjE0z9FzuHwz+qXHVIqmdkZv1DqTAKBggqhkjOPQQDAgNIADBF
AiEAkj6WmSbjRwcsYxbG8zxTcUaeSieotduKs7oTG5rCZhoCIEcpKfiGcvcWszZH
PYA36u0f1fA/mMHP2nhd7rCjq+CY
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBdjCCAR2gAwIBAgIBADAKBggqhkjOPQQDAjAjMSEwHwYDVQQDDBhrM3MtY2xp
ZW50LWNhQDE3MzYzODA4MDcwHhcNMjUwMTA5MDAwMDA3WhcNMzUwMTA3MDAwMDA3
WjAjMSEwHwYDVQQDDBhrM3MtY2xpZW50LWNhQDE3MzYzODA4MDcwWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAAQfp4NVInshMobwuhW4ARUPEMmLkY4e/zhz4Ybu81LO
gfB/haOiA1uScOeHsr/nqttxIfBTA1IRZ2iGRMR8sFwNo0IwQDAOBgNVHQ8BAf8E
BAMCAqQwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU4xNM/Rc7h8M/qlx1SKpn
ZGb9Q6kwCgYIKoZIzj0EAwIDRwAwRAIgboSgpZz/m0Kw0b956Qazn8sQn2gGrWkl
izlEyfLy7YUCIHNDFQHyP7jRxSUn7YGAAkYG9vN80yOO0so3Iw8OVrM7
-----END CERTIFICATE-----
root@ip-172-31-46-63:/var/lib/rancher/k3s/server/tls# cat client-admin.key
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINqAlns/CA/oDoInlqgkDLa2i8TaNbJRjNwARvS7ef3RoAoGCCqGSM49
AwEHoUQDQgAEwyk+lq4/CH4T5F+fTKJzeeb2XNgRfAUeVCJzg6amUX84NQhwMN9E
JO3EXNJDPmbHFQrH6a+C9gPJOx1KQl/PbA==
-----END EC PRIVATE KEY-----
root@ip-172-31-46-63:/var/lib/rancher/k3s/server/tls#
```

> Listing 21 - Example extract kubelet client auth

Those values can then be copy and pasted or transferred with **sftp** to the compromised node. In the following example, a directory was created with the path of **/home/ubuntu/admin/**, the certificate pasted into **client-admin.crt**, and the key pasted into **client-admin.key**. The other file needed for the snapshot API authentication is already present on the worker nodes in **/var/lib/rancher/k3s/agent/server-ca.crt**.

We can try practicing this process. We should note that the kubelet certificate and key pair can be considered sensitive as they are credentials, and should be treated appropriately to protect them from exposure.

```
┌──(kali㉿kali)-[~/workspace/]
└─$ ssh -i lab_id.pem ubuntu@98.84.175.119 "sudo curl -L --cacert /var/lib/rancher/k3s/agent/server-ca.crt --cert /home/ubuntu/admin/client-admin.crt --key /home/ubuntu/admin/client-admin.key -X POST 'https://localhost:10250/checkpoint/red/admin-b47569574-5ltmh/containerd://025d5f00afff65e457eef04bcd373097387015501f3d5d793090452507bc545c'"
404: Page Not Found

```

> Listing 22 - Example checkpoint API use when API not enabled

The 404 response in this case means that the checkpoint API is not enabled. If we received a 200 OK response, we could find a tar archive checkpoint of the container that includes any network data and the container file data. Currently, we can't expect this technique to always be available, so we should prepare to operate without it. Similarly with Docker, there is an [_experimental feature_](https://docs.docker.com/reference/cli/docker/checkpoint/) to enable checkpoints, and Podman has a [_checkpoint feature_](https://podman.io/docs/checkpoint) as well. The benefit of these checkpoint techniques compared to simply exporting or saving the container image is that the state of the TCP connections is preserved, which can be useful for network forensics.

In this situation, thankfully, the container doesn't have any interesting active network connections and is purely the "alpine:latest" container image, with no malicious files. We can confirm this by exploring the container, but may suspect it by reviewing how the container was created. First, however, let's ensure that the container is not automatically destroyed and is properly isolated.

There are several steps we can take to isolate a malicious Pod in a Kubernetes cluster. The first is to _cordon_ the node that the Pod is on. The cordon tells the scheduler to stop scheduling new Pods to that node, but does not prevent processing for Pods already on that node.

The name for the node is unique per lab, so we need to use the node name from the lab rather than the node name in the example shown.

```
ubuntu@ip-172-31-42-75:~$ sudo k3s kubectl cordon ip-172-31-41-246
node/ip-172-31-41-2461 cordoned
```

> Listing 23 - Cordon a Kubernetes node

Our next step is to change the Pod label to a forensic label and apply a forensic network policy to isolate it. Before we sandbox the networking of the container, let's quickly collect the current state of the network connections from the underlying node that the malicious Pod is mounted to. From the **get pods -A -o wide** output, we have the node that each Pod is on. Let's SSH to the underlying node and gather our **ss** and **ip** information.

To make the SSH connection, we want to connect from our Kali host, or the location we have the SSH private key we extracted from AWS secrets manager, **lab_id.pem**. We need to connect to the nodes and check the private IP address assigned to them. This cluster is not _aware_ of the public IP addresses that AWS has assigned, since it leverages private IP addresses for the node-to-node connections.

```
┌──(kali㉿kali)-[~/workspace/]
└─$ ssh -i lab_id.pem ubuntu@54.92.129.117 "ip a"
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
	link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
	inet 127.0.0.1/8 scope host lo
   	valid_lft forever preferred_lft forever
	inet6 ::1/128 scope host
   	valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
	link/ether 0e:c7:8a:a2:47:05 brd ff:ff:ff:ff:ff:ff
	inet 172.31.47.171/20 metric 100 brd 172.31.47.255 scope global dynamic eth0
   	valid_lft 2058sec preferred_lft 2058sec
	inet6 fe80::cc7:8aff:fea2:4705/64 scope link
   	valid_lft forever preferred_lft forever
3: flannel.1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 8951 qdisc noqueue state UNKNOWN group default
	link/ether 32:50:51:30:67:2d brd ff:ff:ff:ff:ff:ff
	inet 10.42.2.0/32 scope global flannel.1
   	valid_lft forever preferred_lft forever
	inet6 fe80::3050:51ff:fe30:672d/64 scope link
   	valid_lft forever preferred_lft forever
4: cni0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 8951 qdisc noqueue state UP group default qlen 1000
	link/ether ca:62:b8:2a:bc:78 brd ff:ff:ff:ff:ff:ff
	inet 10.42.2.1/24 brd 10.42.2.255 scope global cni0
   	valid_lft forever preferred_lft forever
	inet6 fe80::c862:b8ff:fe2a:bc78/64 scope link
   	valid_lft forever preferred_lft forever
5: vethdfe5e408@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 8951 qdisc noqueue master cni0 state UP group default qlen 1000
	link/ether 0a:ca:8c:64:11:2d brd ff:ff:ff:ff:ff:ff link-netns cni-8b9f5e1f-129a-7885-940f-01ea1489f41b
	inet6 fe80::8ca:8cff:fe64:112d/64 scope link
   	valid_lft forever preferred_lft forever
6: veth390db1f4@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 8951 qdisc noqueue master cni0 state UP group default qlen 1000
	link/ether 12:ef:ee:b5:fc:3f brd ff:ff:ff:ff:ff:ff link-netns cni-71fe2d27-a1c6-a6da-0497-6d5b846dd726
	inet6 fe80::10ef:eeff:feb5:fc3f/64 scope link
   	valid_lft forever preferred_lft forever
7: veth1085859c@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 8951 qdisc noqueue master cni0 state UP group default qlen 1000
	link/ether b6:a5:8e:54:33:2c brd ff:ff:ff:ff:ff:ff link-netns cni-a1ea26e8-c52b-c7ce-0f6e-84e54fd0b07b
	inet6 fe80::b4a5:8eff:fe54:332c/64 scope link
   	valid_lft forever preferred_lft forever
8: veth8847ea96@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 8951 qdisc noqueue master cni0 state UP group default qlen 1000
	link/ether 0a:01:cc:51:ba:25 brd ff:ff:ff:ff:ff:ff link-netns cni-c1218de3-a937-b10a-74e0-7734927d0808
	inet6 fe80::801:ccff:fe51:ba25/64 scope link
   	valid_lft forever preferred_lft forever
```

> Listing 24 - Gathering interface information

Using this output from each worker node, we can identify the private network IP in the **ip a** output that matches the node IP in the **sudo k3s kubectl get nodes -o wide** output for the node we have cordoned.

Next, we can collect socket statistics for this node. We are passing the **-tulpane** options to **ss** to print out detailed information about local sockets. We'll pipe the output to **tee** to collect STDOUT to a file for collection and reference.

```
┌──(kali㉿kali)-[~/workspace/]
└─$ ssh -i lab_id.pem ubuntu@54.92.129.117 "ss -tulpane" | tee node_$(date +%Y%m%d%H%M%S)_ss-tulapne.txt
Netid State 	Recv-Q Send-Q      	Local Address:Port        	Peer Address:Port Process
udp   UNCONN	0  	0           	127.0.0.53%lo:53               	0.0.0.0:* 	uid:101 ino:4079 sk:1 cgroup:/system.slice/systemd-resolved.service <->
udp   UNCONN	0  	0      	172.31.47.171%eth0:68               	0.0.0.0:* 	uid:100 ino:4048 sk:2 cgroup:/system.slice/systemd-networkd.service <->
udp   UNCONN	0  	0                 	0.0.0.0:8472             	0.0.0.0:* 	ino:8742 sk:3 cgroup:/system.slice/k3s-agent.service <->
udp   UNCONN	0  	0               	127.0.0.1:323              	0.0.0.0:* 	ino:4776 sk:4 cgroup:/system.slice/chrony.service <->
udp   UNCONN	0  	0                   	[::1]:323                 	[::]:* 	ino:4777 sk:5 cgroup:/system.slice/chrony.service v6only:1 <->
tcp   LISTEN	0  	128               	0.0.0.0:22               	0.0.0.0:* 	ino:5430 sk:6 cgroup:/system.slice/ssh.service <->
tcp   LISTEN	0  	4096            	127.0.0.1:6444             	0.0.0.0:* 	ino:7305 sk:7 cgroup:/system.slice/k3s-agent.service <->
tcp   LISTEN	0  	4096            	127.0.0.1:10249            	0.0.0.0:* 	ino:7836 sk:8 cgroup:/system.slice/k3s-agent.service <->
tcp   LISTEN	0  	4096            	127.0.0.1:10248            	0.0.0.0:* 	ino:7495 sk:9 cgroup:/system.slice/k3s-agent.service <->
tcp   LISTEN	0  	4096            	127.0.0.1:10256            	0.0.0.0:* 	ino:7834 sk:a cgroup:/system.slice/k3s-agent.service <->
tcp   LISTEN	0  	4096        	127.0.0.53%lo:53               	0.0.0.0:* 	uid:101 ino:4080 sk:b cgroup:/system.slice/systemd-resolved.service <->
tcp   LISTEN	0  	4096            	127.0.0.1:10010            	0.0.0.0:* 	ino:7402 sk:c cgroup:/system.slice/k3s-agent.service <->
tcp   TIME-WAIT 0  	0               	10.42.2.1:51566          	10.42.2.2:9000  timer:(timewait,55sec,0) ino:0 sk:d
tcp   ESTAB 	0  	0               	127.0.0.1:45090          	127.0.0.1:6444  timer:(keepalive,22sec,0) ino:7793 sk:e cgroup:/system.slice/k3s-agent.service <->
tcp   ESTAB 	0  	0               	127.0.0.1:6444           	127.0.0.1:45090 timer:(keepalive,22sec,0) ino:7794 sk:f cgroup:/system.slice/k3s-agent.service <->
tcp   ESTAB 	0  	0               	127.0.0.1:45054          	127.0.0.1:6444  timer:(keepalive,28sec,0) ino:7448 sk:10 cgroup:/system.slice/k3s-agent.service <->
tcp   ESTAB 	0  	0           	172.31.47.171:55386      	172.31.45.193:6443  timer:(keepalive,28sec,0) ino:7451 sk:11 cgroup:/system.slice/k3s-agent.service <->
tcp   ESTAB 	0  	0           	172.31.47.171:55314      	172.31.45.193:6443  timer:(keepalive,7.684ms,0) ino:7429 sk:12 cgroup:/system.slice/k3s-agent.service <->
tcp   TIME-WAIT 0  	0               	10.42.2.1:51574          	10.42.2.2:9000  timer:(timewait,58sec,0) ino:0 sk:13
tcp   ESTAB 	0  	0               	127.0.0.1:6444           	127.0.0.1:44998 timer:(keepalive,19sec,0) ino:7423 sk:14 cgroup:/system.slice/k3s-agent.service <->
tcp   TIME-WAIT 0  	0               	10.42.2.1:47872          	10.42.2.2:9000  timer:(timewait,28sec,0) ino:0 sk:15
tcp   ESTAB 	0  	0           	172.31.47.171:55300      	172.31.45.193:6443  timer:(keepalive,8.630ms,0) ino:7425 sk:16 cgroup:/system.slice/k3s-agent.service <->
tcp   ESTAB 	0  	0           	172.31.47.171:33456      	172.31.45.193:6443  timer:(keepalive,18sec,0) ino:7313 sk:17 cgroup:/system.slice/k3s-agent.service <->
tcp   TIME-WAIT 0  	0               	10.42.2.1:51320          	10.42.2.2:9000  timer:(timewait,18sec,0) ino:0 sk:18
tcp   ESTAB 	0  	0               	127.0.0.1:6444           	127.0.0.1:45040 timer:(keepalive,13sec,0) ino:7441 sk:19 cgroup:/system.slice/k3s-agent.service <->
tcp   TIME-WAIT 0  	0               	10.42.2.1:37490          	10.42.2.2:9000  timer:(timewait,8.217ms,0) ino:0 sk:1a
tcp   ESTAB 	0  	0               	127.0.0.1:6444           	127.0.0.1:45054 timer:(keepalive,48sec,0) ino:7449 sk:1b cgroup:/system.slice/k3s-agent.service <->
tcp   ESTAB 	0  	0               	127.0.0.1:44998          	127.0.0.1:6444  timer:(keepalive,8.630ms,0) ino:7422 sk:1c cgroup:/system.slice/k3s-agent.service <->
tcp   ESTAB 	0  	0           	172.31.47.171:55370      	172.31.45.193:6443  timer:(keepalive,18sec,0) ino:7443 sk:1d cgroup:/system.slice/k3s-agent.service <->
tcp   TIME-WAIT 0  	0               	10.42.2.1:33234          	10.42.2.2:9000  timer:(timewait,38sec,0) ino:0 sk:1e
tcp   TIME-WAIT 0  	0               	10.42.2.1:33230          	10.42.2.2:9000  timer:(timewait,35sec,0) ino:0 sk:1f
tcp   ESTAB 	0  	0               	127.0.0.1:45040          	127.0.0.1:6444  timer:(keepalive,13sec,0) ino:7440 sk:20 cgroup:/system.slice/k3s-agent.service <->
tcp   TIME-WAIT 0  	0               	10.42.2.1:51310          	10.42.2.2:9000  timer:(timewait,15sec,0) ino:0 sk:21
tcp   ESTAB 	0  	0               	127.0.0.1:6444           	127.0.0.1:40082 timer:(keepalive,13sec,0) ino:7311 sk:22 cgroup:/system.slice/k3s-agent.service <->
tcp   TIME-WAIT 0  	0               	10.42.2.1:47870          	10.42.2.2:9000  timer:(timewait,25sec,0) ino:0 sk:23
tcp   TIME-WAIT 0  	0               	10.42.2.1:47286          	10.42.2.2:9000  timer:(timewait,48sec,0) ino:0 sk:24
tcp   ESTAB 	0  	0               	127.0.0.1:40082          	127.0.0.1:6444  timer:(keepalive,13sec,0) ino:7310 sk:25 cgroup:/system.slice/k3s-agent.service <->
tcp   ESTAB 	0  	0           	172.31.47.171:55434      	172.31.45.193:6443  timer:(keepalive,22sec,0) ino:7796 sk:26 cgroup:/system.slice/k3s-agent.service <->
tcp   ESTAB 	0  	0           	172.31.47.171:22           	50.16.66.13:35358 timer:(keepalive,119min,0) ino:32442 sk:27 cgroup:/system.slice/ssh.service <->
tcp   LISTEN	0  	128                  	[::]:22                  	[::]:* 	ino:5441 sk:28 cgroup:/system.slice/ssh.service v6only:1 <->
tcp   LISTEN	0  	4096                    	*:10250                  	*:* 	ino:7491 sk:29 cgroup:/system.slice/k3s-agent.service v6only:0 <->
tcp   ESTAB 	0  	0  	[::ffff:172.31.47.171]:10250 [::ffff:172.31.45.193]:5229  timer:(keepalive,5.193ms,0) ino:12774 sk:2a cgroup:/system.slice/k3s-agent.service <->
```

> Listing 25 - Gathering socket statistics over SSH

The output shows that we don't have any current unexpected connections on the node. This may indicate that the attacker is not active within the network. We could verify this further by collecting packet captures, but we don't have a packet capture tool installed on these nodes. It may be the case that installing additional software is not allowed or desired by the organization. This may also indicate that we don't have a strong enough reason to run captures, because there is no reason to believe the attacker has active connections. Let's move ahead with this scenario, and progress to the next steps.

Realizing that the attacker doesn't have active network connections and that they evaded security logging can make our task of network forensics increasingly difficult. However, there is still more we can do to seek out evidence from the underlying system.

Before we resume the search for more evidence, we'll use the Kubernetes API to isolate the malicious Pod. Because a Pod cannot move between namespaces without being recreated, and because the namespace in question was created by the attacker and is not used by the normal application, we'll isolate within that namespace. In other scenarios, we might make a separate forensic namespace and reconstruct the Pod within that.

When we performed **k3s kubectl describe pods -n red**, we found that the malicious Pod had labels that seemed like the labels for the intended application. This tactic might be utilized to leverage any allowances granted to Pods with that label. In this case, there seems to be no apparent value to the attacker by using the label, as the cluster doesn't have any network policy restrictions and the attacker Pod is in a separate namespace from the standard applications. We can confirm that there are no existing NetworkPolicies in this cluster by executing **k3s kubectl get networkpolicy -A** to print all network policies in all namespaces.

```
ubuntu@ip-172-31-40-52:~$ sudo k3s kubectl get networkpolicy -A
No resources found
```

> Listing 26 - Check for Kubernetes networkpolicy

While there is no evidence of network activity in or out of the malicious container, we might move forward with isolating it with a forensic NetworkPolicy. We will block all ingress and egress for specific Pods in the "red" namespace, just as we would do in a "forensic" namespace, as a general approach to contain any malicious activity for a running Pod.

```
ubuntu@ip-172-31-40-52:~$ sudo k3s kubectl apply -f - <<EOF
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: forensic-locker-policy
  namespace: red
spec:
  podSelector:
    matchLabels:
      app: forensic
  policyTypes:
    - Egress
    - Ingress
EOF

networkpolicy.networking.k8s.io/forensic-locker-policy created
```

> Listing 27 - Forensic network policy

Now that we have created the NetworkPolicy, we can attach it by changing the label from the label set on the Pod to our forensic label.

```
ubuntu@ip-172-31-40-52:~$ sudo k3s kubectl label \
--overwrite pods admin-b47569574-5ltmh app=forensic -n red
pod/admin-b47569574-5ltmh labeled
```

> Listing 28 - Change label and namespace for forensic isolation

With the example "forensic-locker-policy" applied and the Pod "app" label set to "forensic", no network traffic is allowed to and from the compromised Pod, and the changed label further reduces the chance that a container lifecycle action would remove the Pod.

Alternatively, or additionally, we can create a NetworkPolicy that applies to the existing label the adversary set, or all Pods within the namespace. We'll apply a second NetworkPolicy to block all network traffic in the "red" namespace, in the case other activity occurs there.

```
ubuntu@ip-172-31-40-52:~$ sudo k3s kubectl apply -f - <<EOF
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: forensic-red-locker-policy
  namespace: red
spec:
  podSelector: {}
  policyTypes:
    - Egress
    - Ingress
EOF

networkpolicy.networking.k8s.io/forensic-red-locker-policy created
```

> Listing 29 - Full namespace lockdown network policy

It might not always be "app" that is used, and it may not be appropriate to switch the "app" label on a Pod - it depends on the cluster design. We need to check the labels actually used and overwrite or add labels to detach the Pod from normal lifecycles and enable more granular isolation rules. In some cases, we'll just isolate an entire namespace instead, such as our "forensic-red-locker-policy", or work on isolation at the node-level.

We can confirm isolation worked by performing an _exec_ into the Pod and attempting to reach a website online.

```
ubuntu@ip-172-31-40-52:~$ sudo k3s kubectl exec -n red\ 
-it admin-b47569574-5ltmh -- /bin/ash
/ # ping google.com
ping: bad address 'google.com'
/ # exit
```

> Listing 30 - Verify network isolation

The "bad address" message helps confirm that our NetworkPolicy is applied and working as expected by validating that egress is blocked.

It is important for us to keep in mind that if the compromised Pod is not re-labelled in such a way that it is detached from its regular deployment, it might automatically be destroyed, such as by a Pod lifecycle activity. Successfully detaching the Pod so that it is not automatically removed can be important to a forensic case.

Many security systems automatically delete malicious Pods. A standard configuration in Kubernetes known as a _Falco response engine_ may attempt to automatically detect and delete Pods that have shells or that meet other conditions, for example.

The _Falco response engine_ is made of several components. A component that can be used for creating _forensic sidecars_ is called _falcosidekick_. We can enable sidekick in Falco during the install time, or while running. In our lab scenario, we've installed Falco in a default state, but it is not configured as a response engine.

The image below illustrates the Falco response engine with a generic placeholder in the box for _Kubernetes function_. This aspect might vary between different systems, but is typically a function-as-a-service (FaaS) component that is integrated with Kubernetes. With Falco and falcosidekick, we can make YAML-controlled functions with rules that react to eBPF syscall traces. The example rule is to delete Pods with shells. In a forensic case, we might not want to delete the Pod, but rather remove it from processing as we've practiced in our lab.

![[OffSec/Cloud/Cloud Computing Network Forensics/z. images/c97bd521579d072ff3d10e5f60e97772_MD5.jpg]]

Figure 2: Falco Response Engine

While this type of response is a useful security measure, it may also delete forensic evidence. A well-implemented response engine might also automatically collect forensic evidence before deletion, or isolate the Pod automatically as we are performing manually.

With the Pod moved into isolation, we continue to collect more information in search of any network forensic evidence. We have two more aspects to examine further: the Kubernetes API use that created the Pod in the first place, and the underlying node that the malicious Pod mounted. In order to have Kubernetes API source IP addresses logged, the cluster needs _Kubernetes API audit logging_ enabled. The cluster in this case does not have API audit logs enabled, so that data is not captured. That API audit logging isn't important in this case because, as we'll find out, the Kubernetes API was not used remotely, but instead used locally on the control plane node.

The way this cluster was set up, the organization didn't export the cluster credentials, so the attacker must have either used a timing attack on the source code or had SSH access. If they had SSH access already, there would likely be no reason to perform a container escape to mount the underlying node. Since we don't believe any running application was exploited inside the cluster, this leads us to a higher probability of lateral movement, a timing attack, or supply chain attack that enabled the attacker to instruct Kubernetes.

In this case, while exploring the systemd journals on the compromised node, we get closer to understanding how the attacker placed the malicious Pod.

```
ubuntu@ip-172-31-40-52:~$ sudo journalctl -xe
...(CUT)...
Jan 08 17:56:58 ip-172-31-40-52 apply-manifest.sh[3951]: namespace/red created
Jan 08 17:56:58 ip-172-31-40-52 apply-manifest.sh[3951]: deployment.apps/admin created
Jan 08 17:56:58 ip-172-31-40-52 systemd[1]: Finished Apply Kubernetes Manifest after cluster readiness.
...(CUT)...
```

> Listing 31 - Reading through systemd journals

Within the output, we'll find that there is a [_systemd unit file_](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_systemd_unit_files_to_customize_and_optimize_your_system/assembly_working-with-systemd-unit-files_working-with-systemd) that applies a Kubernetes manifest. After examining the unit file, we learn that the manifest is applied from a location in **/usr/local/bin/apply-manifest.sh**.

```
ubuntu@ip-172-31-40-52:~$ cat /etc/systemd/system/apply-manifest.service
[Unit]
Description=Apply Kubernetes Manifest after cluster readiness
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/apply-manifest.sh && /usr/local/bin/apply-manifest.sh
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
ubuntu@ip-172-31-40-52:~$
```

> Listing 32 - Examining the unit file

The systemd unit file leads us to a script that systemd executes twice after the system is started. In this case, the unit file and script are intentional features the organization put into place to automatically set the configuration for the cluster. What the attacker did was overwrite or add declarations to part of the existing automation.

```
#!/bin/bash
configmaker() {
  sleep 2
  /usr/local/bin/k3s kubectl config view --raw > /root/.kube/config || configmaker
}
configmaker &&
chmod 600 /root/.kube/config &&
export KUBECONFIG=/root/.kube/config
while [[ $(/usr/local/bin/k3s kubectl get nodes --no-headers | grep -c "Ready") -lt 3 ]]; do
	echo "Waiting for all nodes to be ready..."
	sleep 10
done
while [ ! -f /tmp/values.yml ]; do
	echo "Waiting for values file to be uploaded..."
	sleep 5
done
while [ ! -f /tmp/manifest.yml ]; do
	echo "Waiting for manifest to be uploaded..."
	sleep 5
done
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash &&
/usr/local/bin/helm repo add arroyo https://arroyosystems.github.io/helm-repo
/usr/local/bin/helm repo add falcosecurity https://falcosecurity.github.io/charts
/usr/local/bin/helm repo update &&
/usr/local/bin/helm install --replace falco --namespace falco --create-namespace --set tty=true falcosecurity/falco &&
/usr/local/bin/helm install arroyo arroyo/arroyo -f /tmp/values.yml
/usr/local/bin/k3s kubectl apply -f /tmp/manifest.yml
```

> Listing 33 - Reading through a deployment script

This manifest file is stored in an insecure file path, because /tmp is globally writable and readable, so the manifest could be inserted or manipulated by another application that was exploited. In this scenario, it seems as though the manifest should be applied after Falco, but because the attacker's manifest is faster to create than Falco, it ends up getting deployed _before_ the normal applications on the system, avoiding initial detection from Falco. This is a timing attack that works for evading numerous Kubernetes security measures.

```
ubuntu@ip-172-31-40-52:~$ cat /tmp/manifest.yml
---
apiVersion: v1
kind: Namespace
metadata:
  name: red
...
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: admin
  namespace: red
spec:
  replicas: 1
  selector:
	matchLabels:
  	app: arroyo
  template:
	metadata:
  	labels:
    	app: arroyo
	spec:
  	containers:
  	- name: admin
    	image: alpine:latest
    	command: ["/bin/sleep"]
    	args: ["9999"]
    	volumeMounts:
    	- mountPath: /var/tmp
      	name: adminroot
  	volumes:
   	- name: adminroot
     	hostPath:
       	path: /
       	type: Directory
...
```

> Listing 34 - Review the malicious manifest

The most malicious aspect of this manifest is that it gains root access to an underlying node. However, the container does nothing with that access. We might expect that the container would be using **nc** to exfiltrate information from the node in the **command** section, rather than just sleeping. This indicates that further actions or steps in the attack were likely planned to come after this. The attacker may have wanted to use an **exec** and interactively review the node files and data.

This can be a frustrating situation for network forensics teams because we don't have any real forensic data to support the case. The next step in the example would likely be to work with the organization to identify where the **apply-manifest.sh** and **/tmp/manifest.yml** come from, as those systems or software may be compromised or have been manipulated by the attacker.

#### Labs

1. Which action do we typically want to take at the Kubernetes node level with the Kubernetes API when we are investigating security events on that node?

Answer

2. Which Kubernetes functionality is critical for understanding source IP addresses of Kubernetes API clients?

Answer

3. Which mechanism did the attacker use to escape a container to the underlying node?

Answer

4. If the manifest file is normally used, name an attack type that we should be investigating next in this scenario?

Answer

5. Container security systems might cause what type of negative impact to forensics?

Answer

6. Which container API or functionality collects both the container image and the TCP connections from that container?

Answer

## 3.2. Cloud Service Provider Network Data

Beyond the operating systems, containers, kernels, and container orchestration, we also need to consider any service provider systems. Depending on the scenario, an attacker may use the cloud provider services against the organization. In such a case, cloud provider data becomes critical network data, too.

The most important aspect of cloud provider network data is the API audit logs. These logs contain the source IP addresses of all connections that used our organization's cloud provider API. We may have millions of events in this data under normal conditions, or we could have very rare events, depending on how heavily an organization utilizes the cloud provider API.

One of the common patterns in AWS is to have AWS API logs stored in S3 buckets. These buckets are commonly created automatically by the _CloudTrail_ service. In other cloud provider systems, the API audit data may only be available from a logging API or may be sent to centralized storage or data lakes.

We can create a _CloudTrail_ for our lab environment, but we already have the data we need for our case stored in the lab VM. In order to access the source of this data, we can use the AWS web console (website) and navigate to the CloudTrail product page.

![[OffSec/Cloud/Cloud Computing Network Forensics/z. images/bbf65ccfacf821cd486f49aa7fb55e16_MD5.jpg]]

Figure 3: CloudTrail

From there, we'll open the bucket that the data is stored in and download the files. We could create CloudTrail instances with [_Terraform_](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail) or another programmatic method instead of the web console.

Many enterprises have more sophisticated views of this same data. However, it is this raw JSON with AWS API access data we'll need to save for evidence. The default CloudTrail settings will log requests to our AWS account.

![[OffSec/Cloud/Cloud Computing Network Forensics/z. images/1a04d447cb34887b92b82cce2c4edb0c_MD5.jpg]]

Figure 4: Cloud Trail Default

Returning to the "Network-Forensics-Ubuntu" EC2 instance of the lab in this section, we'll notice some Cloud Trail data that was collected during the incident. In the **/root** directory on that node, we have a directory named **aws**. Let's review its contents in this section.

Within this data, we can find the source IP of each connection to our AWS account functionality, which can be useful forensically. The data can become overwhelming, especially if the organization is large, with many people and systems constantly active. In order to more effectively sift through the data, we can use dashboard visualizations, data lakes, and SIEMs, as well as scripts.

Let's leverage some scripting to search for items of interest. We'll use **grep** to filter out lines of the JSON matching IPs we are interested in.

```
root@ip-10-0-0-180:~# grep "149.56.244.87" /root/aws/*.json
root@ip-10-0-0-180:~#
```

> Listing 35 - Searching in CSP access logs

We didn't find the IP from the malware in the AWS API. It is common that we might observe a separate address for attacks coming inbound and data going outbound. To check which addresses were found, we'll also extract all IPv4 addresses for further review.

We may want to additionally search for IPv6 addresses. We'll need to use a different regular expression to match IPv6 addresses.

```
root@ip-10-0-0-180:~# grep -ho "IPAddress...[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\"" /root/aws/*.json | sort -u
IPAddress":"44.211.213.69"
```

> Listing 36 - Filtering all IPv4 addresses from AWS logs

We only discovered a single IP address in the event data. If we investigate this IP address further, we'll find that it is an AWS IP address. This means that the access to our AWS API during the event was coming from _us-east-1_ in AWS. However, just because we have an IP does not mean we have the attacker's real IP. It is common that attackers use a cloud machine as a bastion host and attack from the bastion. This way, when we research the connection, we only find the cloud service provider network source. We would likely need to get AWS to disclose the owner of the account that created the IP in question. Such an action is only likely to be taken when absolutely required, but we can always contact AWS if we do have a legal case.

Even if AWS provided the connecting IP address, it may be a _sock puppet account_ that is run with a false or stolen identity or is a compromised machine. It may be that the attacker connected to that machine from a [_tor_](https://www.torproject.org/) network or virtual private network. There are many more possible layers that we are unlikely to gain insight to without the attacker making a mistake, or the help of governments, legal systems, and coordination with internet service, network, software, and cloud service providers. Some technologies are designed not to be able to easily trace connections for privacy. These technologies include tor, [_Signal_](https://signal.org/download/), [_tox_](https://tox.chat/), and others.

For our cloud forensic data, we are not likely going to get all the way back to an adversary's true source IP unless they are naive or make [_OPSEC_](https://www.nsa.gov/portals/75/documents/news-features/declassified-documents/cryptologic-histories/purple_dragon.pdf) mistakes that disclose information. Such a mistake might be as simple as clicking the wrong button or missing a configuration step.

In this example, we would record the evidence that we've collected in our case file. We are not managing the case file in this Learning Module, as that is covered in other Learning Modules.

For more study related to forensic data collection and incident case files, see the OffSec Learning Modules titled "Forensic Collection" and "Incident Response Case Management".

We are now ready, however, to examine the network evidence we have collected during this Learning Module and consider notes we can make about the case.

Although we did not find evidence of significant data exfiltration, we _did_ find data exfiltration and potential unauthorized computer and network use. Currently, the exfiltration payload appears to be a fixed payload sent repeatedly and may be a component of a larger attack. In addition to the exfiltration IP address, which we have identified as **www.megacorpone.com**, we also have a second IP address that was only observed in the AWS API data and was the only IP address observed in the captured AWS API event data.

Some information disclosed in the AWS API access logs includes the browser agent header data of the client we observed. Although these values can be manipulated, they may also provide useful evidence. Examining the data in our lab, we find that the client appears to have been an Ubuntu EC2 instance. This may be an expected bastion host within the organization. If we had access to this EC2 instance, we could use our Linux network forensic skills to research there as well.

More research can be done to determine if the EC2 was part of the organization, but we'll stop at this point for this Learning Module. We'll take note of the types of API actions the AWS IP made in our practice lab case, marked as "unknown if related" until further research is done.

Very rarely does network forensics provide a 100% conclusive result. As in our lab case, some aspects may be clear, such as the exfiltration destination, but we don't yet have a strong conclusion on the source of the attack. It's fairly common to have some unknowns remaining, especially on the source. It is important not to make assumptions or be overly conclusive about the source of the attack, especially using only the network data.

#### Labs

1. What is the most important IP address in our lab case so far?

Answer

2. In the fictional case for our lab, which _ingress_ address needs further investigation?

Answer

3. In the collected AWS API data, how many API client source IPs are found?

Answer

## 4. Wrapping Up

After completing this Learning Module, we have spent time deeply exploring what it takes to understand modern security tools in the context of network forensics. We have learned about tracing syscalls, reverse engineering and investigating eBPF, isolating and extracting container data, and extracting CSP API data. While uncovering the complexity of operating systems and security, we have strengthened our awareness of how to find digital forensic network data, whether on-prem or via a cloud service provider.