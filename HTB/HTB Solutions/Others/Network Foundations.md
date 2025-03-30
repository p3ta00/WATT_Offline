
| Section                                    | Question Number | Answer                             |
| ------------------------------------------ | --------------- | ---------------------------------- |
| Introduction to Networks                   | Question 1      | network                            |
| Introduction to Networks                   | Question 2      | node                               |
| Introduction to Networks                   | Question 3      | internet                           |
| Introduction to Networks                   | Question 4      | LAN                                |
| Introduction to Networks                   | Question 5      | links                              |
| Network Concepts                           | Question 1      | Physical Layer                     |
| Network Concepts                           | Question 2      | Network Layer                      |
| Network Concepts                           | Question 3      | TCP                                |
| Network Concepts                           | Question 4      | Data Link Layer                    |
| Network Concepts                           | Question 5      | Application Layer                  |
| Network Concepts                           | Question 6      | Presentation Layer                 |
| Network Concepts                           | Question 7      | HTTP                               |
| Network Concepts                           | Question 8      | Transport Layer                    |
| Network Concepts                           | Question 9      | UDP                                |
| Components of a Network                    | Question 1      | Fiber-optic                        |
| Components of a Network                    | Question 2      | TCP/IP                             |
| Components of a Network                    | Question 3      | Network management software.       |
| Components of a Network                    | Question 4      | firewall                           |
| Components of a Network                    | Question 5      | Ethernet                           |
| Components of a Network                    | Question 6      | Router                             |
| Network Communication                      | Question 1      | ARP                                |
| Network Communication                      | Question 2      | IPv6                               |
| Network Communication                      | Question 3      | Transport Layer                    |
| Network Communication                      | Question 4      | 80                                 |
| Network Communication                      | Question 5      | DNS Lookup                         |
| Dynamic Host Configuration Protocol (DHCP) | Question 1      | DHCP                               |
| Dynamic Host Configuration Protocol (DHCP) | Question 2      | DORA                               |
| Dynamic Host Configuration Protocol (DHCP) | Question 3      | Request                            |
| Network Address Translation (NAT)          | Question 1      | PAT                                |
| Network Address Translation (NAT)          | Question 2      | RFC 1918                           |
| Network Address Translation (NAT)          | Question 3      | Static NAT                         |
| Network Address Translation (NAT)          | Question 4      | Dynamic NAT                        |
| Network Address Translation (NAT)          | Question 5      | Router                             |
| Domain Name System (DNS)                   | Question 1      | Top-Level Domain                   |
| Domain Name System (DNS)                   | Question 2      | Second-Level Domain                |
| Domain Name System (DNS)                   | Question 3      | DNS cache                          |
| Domain Name System (DNS)                   | Question 4      | Recursive DNS server               |
| Domain Name System (DNS)                   | Question 5      | Root server                        |
| Domain Name System (DNS)                   | Question 6      | IP Address                         |
| Domain Name System (DNS)                   | Question 7      | Subdomain                          |
| Internet Architecture                      | Question 1      | Peer-to-Peer                       |
| Internet Architecture                      | Question 2      | Hybrid                             |
| Internet Architecture                      | Question 3      | SaaS                               |
| Internet Architecture                      | Question 4      | Software-Defined Networking        |
| Internet Architecture                      | Question 5      | Peer-to-Peer                       |
| Internet Architecture                      | Question 6      | Hybrid                             |
| Wireless Networks                          | Question 1      | Radio waves                        |
| Wireless Networks                          | Question 2      | Wireless router                    |
| Wireless Networks                          | Question 3      | Cellular data                      |
| Wireless Networks                          | Question 4      | Cell tower                         |
| Wireless Networks                          | Question 5      | Base Station Controller            |
| Wireless Networks                          | Question 6      | 2.4 GHz                            |
| Network Security                           | Question 1      | Firewall                           |
| Network Security                           | Question 2      | Packet Filtering                   |
| Network Security                           | Question 3      | Deep packet inspection             |
| Network Security                           | Question 4      | IDS                                |
| Network Security                           | Question 5      | IPS                                |
| Network Security                           | Question 6      | Signature-based detection          |
| Skills Assessment                          | Question 1      | 127.0.0.1                          |
| Skills Assessment                          | Question 2      | Xtigervnc                          |
| Skills Assessment                          | Question 3      | tun0                               |
| Skills Assessment                          | Question 4      | RETR                               |
| Skills Assessment                          | Question 5      | HTB{S00n\_2\_B\_N3tw0rk1ng\_GURU!} |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Introduction to Networks

## Question 1

### "What is the term for a collection of interconnected devices that can communicate and share resources with each other?"

A `network` is a collection of interconnected devices that can communicate - sending and receiving data, and also sharing resources with each other.

![[HTB Solutions/Others/z. images/17c1b107fe8a73c646d20eb2136e523c_MD5.jpg]]

Answer: `Network`

# Introduction to Networks

## Question 2

### "In network terminology, what is the term for individual devices connected to a network?"

These individual endpoint devices, often called `nodes`, include computers, smartphones, printers, and servers.

![[HTB Solutions/Others/z. images/ff723b9d969f8001bfb9680158889736_MD5.jpg]]

Answer: `nodes`

# Introduction to Networks

## Question 3

### "What is the largest Wide Area Network (WAN) that connects millions of Local Area Networks (LANs) globally?"

The Internet is the largest example of a `WAN`, connecting millions of `LANs` globally.

![[HTB Solutions/Others/z. images/911ec8d813fba891f7138bcd09713afd_MD5.jpg]]

Answer: `internet`

# Introduction to Networks

## Question 4

### "What is the acronym for a network that connects devices over a short distance, such as within a home, school, or small office building?"

A `Local Area Network (LAN)` connects devices over a short distance, such as within a home, school, or small office building.

![[HTB Solutions/Others/z. images/e59bb11ebbf06a11aef021c6498a500f_MD5.jpg]]

Answer: `LAN`

# Introduction to Networks

## Question 5

### "In networking, what term describes the communication pathways (wired or wireless) that connect nodes?"

`Links` - Communication pathways that connect nodes (wired or wireless).

![[HTB Solutions/Others/z. images/2ddfb9464e4560b44bae7aaa6b00e706_MD5.jpg]]

Answer: `Links`

# Network Concepts

## Question 1

### "What layer of the OSI model is responsible for physical connections like Ethernet cables? (Format: two words)"

The `Physical Layer` is the first and lowest layer of the OSI model. It is responsible for transmitting raw bitstreams over a physical medium. This layer deals with the physical connection between devices, including the hardware components like Ethernet cables, hubs, and repeaters.

![[HTB Solutions/Others/z. images/e1022a44753137cdca799cd06a9ea5e2_MD5.jpg]]

Answer: `Physical Layer`

# Network Concepts

## Question 2

### "Name the OSI layer that deals with logical addressing and routing. (Format: two words)"

The `Network Layer` handles packet forwarding, including the routing of packets through different routers to reach the destination network. It is responsible for logical addressing and path determination, ensuring that data reaches the correct destination across multiple networks.

![[HTB Solutions/Others/z. images/825a4f159fb2788ce6137805c09030af_MD5.jpg]]

Answer: `Network Layer`

# Network Concepts

## Question 3

### "Which protocol ensures reliable delivery of data and operates at the Transport Layer?"

TCP offers reliable, connection-oriented transmission with error recovery, while UDP provides faster, connectionless communication without guaranteed delivery.

![[HTB Solutions/Others/z. images/245774124fcf03cc4433bf49f931169c_MD5.jpg]]

Answer: `TCP`

# Network Concepts

## Question 4

### "At what layer do switches operate within the OSI model? (Format: three words)"

The `Data Link Layer` provides node-to-node data transfer - a direct link between two physically connected nodes. It ensures that data frames are transmitted with proper synchronization, error detection, and correction. Devices such as switches and bridges operate at this layer, using [MAC (Media Access Control)](https://en.wikipedia.org/wiki/MAC_address) addresses to identify network devices.

![[HTB Solutions/Others/z. images/87967132f7a5f1d9bc03ee7aa951fc75_MD5.jpg]]

Answer: `Data Link Layer`

# Network Concepts

## Question 5

### "What layer of the TCP/IP model corresponds to the OSI model’s Application, Presentation, and Session layers? (Format: two words)"

The `Application Layer` of the TCP/IP model contains protocols that offer specific data communication services to applications. Protocols such as HTTP (Hypertext Transfer Protocol), FTP (File Transfer Protocol), and SMTP (Simple Mail Transfer Protocol) enable functionalities like web browsing, file transfers, and email services. This layer corresponds to the top three layers of the OSI model (Session, Presentation, and Application), providing interfaces and protocols necessary for data exchange between systems.

![[HTB Solutions/Others/z. images/d5a1c583b65a4ade911648d7793409e2_MD5.jpg]]

Answer: `Application Layer`

# Network Concepts

## Question 6

### "Which layer of the OSI model manages data encryption and data format conversion? (Format: two words)"

The `Presentation Layer` acts as a translator between the application layer and the network format. It handles data representation, ensuring that information sent by the application layer of one system is readable by the application layer of another. This includes data encryption and decryption, data compression, and converting data formats. Encryption protocols and data compression techniques operate at this layer to secure and optimize data transmission.

![[HTB Solutions/Others/z. images/ead1c88d7aeb175d1c334f62079cf1e8_MD5.jpg]]

Answer: `Presentation Layer`

# Network Concepts

## Question 7

### "Name a protocol used for web browsing that operates at the Application Layer."

Common protocols operating at this layer include `HTTP (Hypertext Transfer Protocol)` for web browsing.

![[HTB Solutions/Others/z. images/a591dc794f4bb18b5fb75b93a0c1114f_MD5.jpg]]

Answer: `HTTP`

# Network Concepts

## Question 8

### "Which OSI layer ensures the segments are transferred reliably and in sequence? (Format: two words)"

At the `Transport Layer`, the file is broken down into segments to ensure error-free transmission.

![[HTB Solutions/Others/z. images/d9d7c1a5d6831afd9422294a9dfb4d11_MD5.jpg]]

Answer: `Transport Layer`

# Network Concepts

## Question 9

### "Which protocol provides fast, connectionless communication and operates at the Transport Layer?"

TCP offers reliable, connection-oriented transmission with error recovery, while UDP provides faster, connectionless communication without guaranteed delivery.

![[HTB Solutions/Others/z. images/743c1e0e2da487d90dfd8a4cbf0ee9f0_MD5.jpg]]

Answer: `UDP`

# Components of a Network

## Question 1

### "What type of network cable is used to transmit data over long distances with minimal signal loss?"

This includes wired media like Ethernet cables and fiber-optic cables, which offer high-speed connections, as well as wireless media like Wi-Fi and Bluetooth, which provide mobility and flexibility. Additionally, students can refer to the [Fiber-optic cable](https://en.wikipedia.org/wiki/Fiber-optic_cable) Wikipedia resource to find that the `fiber-optic` cable is suitable for long-distance and provides high-speed connections.

![[HTB Solutions/Others/z. images/7b78c7d80868225aace521694daf575e_MD5.jpg]]

Answer: `fiber-optic`

# Components of a Network

## Question 2

### "Which protocol manages data routing and delivery across networks?"

Students will use the knowledge obtained from the previous section (`Network Concepts`) and will understand that the `TCP/IP` protocol is responsible for data routing and ensuring the delivery across networks.

Answer: `TCP/IP`

# Components of a Network

## Question 3

### "What software is used to oversee and administer network operations? (Format: 3 words)"

`Network management software` consists of tools and applications used to monitor, control, and maintain network components and operations. They help network administrators ensure that the network operates efficiently, remains secure, and can quickly address any issues that arise. For example, in a corporate environment, the IT department might use network management software to oversee all devices connected to the company network.

![[HTB Solutions/Others/z. images/a5b1ab25dc6ef0799a332158bfc93046_MD5.jpg]]

Answer: `Network management software`

# Components of a Network

## Question 4

### "What software is used to protect individual devices from unauthorized network access? (Format: 1 word)"

For example, most operating systems include a built-in software firewall that can be set up to block incoming connections from untrusted sources, ensuring that only legitimate network traffic reaches the device.

![[HTB Solutions/Others/z. images/a81a4fbde9c6b21afad8a60fdf2b4511_MD5.jpg]]

Answer: `firewall`

# Components of a Network

## Question 5

### "What type of cable is used to connect components within a local area network for high-speed data transfer?"

For example, a desktop computer might use a wired NIC, along with an Ethernet cable, to connect to a local network, while a laptop uses a wireless NIC to connect via Wi-Fi.

![[HTB Solutions/Others/z. images/fb7643dc7308b9f6c1838aa85c76a5fd_MD5.jpg]]

Answer: `Ethernet`

# Components of a Network

## Question 6

### "Which device connects multiple networks and manages data traffic to optimize performance?"

By `connecting multiple networks`, routers enable devices on different networks to communicate. They also manage network traffic by selecting optimal paths for data transmission, which helps prevent congestion—a process known as `traffic management`.

![[HTB Solutions/Others/z. images/2bf72b44327041eea0e262b94e3ff260_MD5.jpg]]

Answer: `router`

# Network Communication

## Question 1

### "What protocol maps IP addresses to MAC addresses?"

Additionally, the `Address Resolution Protocol (ARP)` plays a crucial role by mapping IP addresses to MAC addresses, allowing devices to find the MAC address associated with a known IP address within the same network.

![[HTB Solutions/Others/z. images/65da8b1e694c4fc5448a41ff31aab0db_MD5.jpg]]

Answer: `ARP`

# Network Communication

## Question 2

### "Which IP version uses 128-bit addressing?"

In contrast, IPv6 addresses, which were developed to address the depletion of IPv4 addresses, have a 128-bit address space and are formatted in eight groups of four hexadecimal digits.

![[HTB Solutions/Others/z. images/a3d89edb6b4bdc857e36e6b83834e3f4_MD5.jpg]]

Answer: `IPv6`

# Network Communication

## Question 3

### "At which layer of the OSI model do ports operate? (Format: two words)"

A `port` is a number assigned to specific processes or services on a network to help computers sort and direct network traffic correctly. It functions at the `Transport Layer (Layer 4)` of the OSI model and works with protocols such as TCP and UDP.

![[HTB Solutions/Others/z. images/4dfcfdd50ec1418766ffe9abc29d855f_MD5.jpg]]

Answer: `Transport Layer`

# Network Communication

## Question 4

### "What is the designated port number for HTTP?"

The user’s browser initiates a connection to the server's IP address on port 80, which is designated for HTTP.

![[HTB Solutions/Others/z. images/9b60599a4df4acd16f6a56132b6bbdb9_MD5.jpg]]

Answer: `80`

# Network Communication

## Question 5

### "What is the first step in the process of a web browsing session? (Format: two words)"

DNS Lookup is the first step in the process of a web browsing session.

![[HTB Solutions/Others/z. images/cdf7fa6c452f45c157e8f6c886fc0644_MD5.jpg]]

Answer: `DNS Lookup`

# Dynamic Host Configuration Protocol (DHCP)

## Question 1

### "What protocol automates IP address configuration for devices on a network?"

`DHCP` is a network management protocol used to automate the process of configuring devices on IP networks.

![[HTB Solutions/Others/z. images/a25ed2280082e84955740d3900357db9_MD5.jpg]]

Answer: `DHCP`

# Dynamic Host Configuration Protocol (DHCP)

## Question 2

### "What acronym describes the sequence of messages exchanged during the DHCP process?"

The DHCP process involves a series of interactions between the client (the device requesting an IP address) and the DHCP server (the service running on a network device that assigns IP addresses). This process is often referred to as `DORA`.

![[HTB Solutions/Others/z. images/b0154a07a0d0ee3ddb9e8edf72904964_MD5.jpg]]

Answer: `DORA`

# Dynamic Host Configuration Protocol (DHCP)

## Question 3

### "What type of message does a client send to accept an IP address from a DHCP server?"

`3. Request`: The client receives the offer and replies with a **DHCP Request** message, indicating that it accepts the offered IP address.

![[HTB Solutions/Others/z. images/12436f19736fd8adea06624cc8931e7a_MD5.jpg]]

Answer: `Request`

# Network Address Translation (NAT)

## Question 1

### "What type of NAT allows multiple private IP addresses to share one public IP address using unique port numbers?"

`Port Address Translation (PAT)`: Also known as NAT Overload, is the most common form of NAT in home networks. Multiple private IP addresses share a single public IP address, differentiating connections by using unique port numbers. This method is widely used in home and small office networks, allowing multiple devices to share a single public IP address for internet access.

![[HTB Solutions/Others/z. images/2d2c0a0883fc430f64b22fbc48f15ee9_MD5.jpg]]

Answer: `PAT`

# Network Address Translation (NAT)

## Question 2

### "What RFC specifies private IP ranges?"

Defined by RFC 1918, common IPv4 private address ranges include 10.0.0.0 to 10.255.255.255, 172.16.0.0 to 172.31.255.255, and 192.168.0.0 to 192.168.255.255.

![[HTB Solutions/Others/z. images/02dca41e8364a01385afaabc28da7380_MD5.jpg]]

Answer: `RFC 1918`

# Network Address Translation (NAT)

## Question 3

### "Which NAT type involves a one-to-one mapping of private IP addresses to public IP addresses?"

`Static NAT`: Involves a one-to-one mapping, where each private IP address corresponds directly to a public IP address.

![[HTB Solutions/Others/z. images/d77217c90a641dca36a934d5437d3b69_MD5.jpg]]

Answer: `Static NAT`

# Network Address Translation (NAT)

## Question 4

### "What type of NAT assigns a public IP from a pool as needed?"

`Dynamic NAT`: Assigns a public IP from a pool of available addresses to a private IP as needed, based on network demand.

![[HTB Solutions/Others/z. images/d6fa5a1da74ad5af462bc1c46c5779b5_MD5.jpg]]

Answer: `Dynamic NAT`

# Network Address Translation (NAT)

## Question 5

### "What device typically performs NAT in a home network?"

![[HTB Solutions/Others/z. images/e81d34ab49c254806104e97a60782d88_MD5.jpg]]

Answer: `router`

# Domain Name System (DNS)

## Question 1

### "What type of domain is `.com` considered as? (Format: Three words, example: One-Two Three)"

`Top-Level Domain` (TLDs): Such as .com, .org, .net, or country codes like .uk, .de.

![[HTB Solutions/Others/z. images/9700f34f41124643175a4278d6770b98_MD5.jpg]]

Answer: `Top-Level Domaain`

# Domain Name System (DNS)

## Question 2

### "In the domain `www.example.com`, what is `example` called?"

`Second-Level Domain`: For example, example in example.com.

![[HTB Solutions/Others/z. images/291e4c980588369717d5e7d1ac96e7c8_MD5.jpg]]

Answer: `Second-Level Domain`

# Domain Name System (DNS)

## Question 3

### "What is checked first in the DNS resolution process when you enter a domain name into a browser? (Format: Two words)"

Our computer checks its local DNS cache (a small storage area) to see if it already knows the IP address.

![[HTB Solutions/Others/z. images/826f1ec460d1ba2d729c795eef41a19a_MD5.jpg]]

Answer: `DNS cache`

# Domain Name System (DNS)

## Question 4

### "What type of DNS server is typically provided by an Internet Service Provider?"

If not found locally, it queries a `recursive DNS server`. This is often provided by our Internet Service Provider or a third-party DNS service like Google DNS.

![[HTB Solutions/Others/z. images/59b8df9baabd5773dd724ecb15bce21f_MD5.jpg]]

Answer: `recursive DNS server`

# Domain Name System (DNS)

## Question 5

### "Which server directs the recursive DNS server to the appropriate TLD name server?"

The recursive DNS server contacts a `root server`, which points it to the appropriate TLD name server (such as the .com domains, for instance).

![[HTB Solutions/Others/z. images/cc6a480eb9288e37c26aa4c06b6664f2_MD5.jpg]]

Answer: `root server`

# Domain Name System (DNS)

## Question 6

### "What numerical label uniquely identifies a device on a network?"

`IP Address`

![[HTB Solutions/Others/z. images/2168593df4ce0f2849d515f42533202c_MD5.jpg]]

Answer: `IP Address`

# Domain Name System (DNS)

## Question 7

### "In the URL "accounts.google.com", what is `accounts` considered as?"

`Subdomain (or Hostname)`: For instance, www in www.example.com, or accounts in accounts.google.com.

![[HTB Solutions/Others/z. images/425040c7be2c07eb654fc808cbffdfa6_MD5.jpg]]

Answer: `subdomain`

# Internet Architecture

## Question 1

### "What type of architecture allows nodes to act as both client and server?"

In a `Peer-to-Peer (P2P)` network, each node, whether it's a computer or any other device, acts as both a client and a server.

![[HTB Solutions/Others/z. images/259cb2143004a60a92fdeb3b0f17617d_MD5.jpg]]

Answer: `Peer-to-Peer`

# Internet Architecture

## Question 2

### "What architecture combines elements of both Client-Server and Peer-to-Peer models?"

A `Hybrid` model blends elements of both `Client-Server` and `Peer-to-Peer (P2P)` architectures.

![[HTB Solutions/Others/z. images/61bbe6879e9dd0cce3f01017db2a10c5_MD5.jpg]]

Answer: `Hybrid`

# Internet Architecture

## Question 3

### "Which cloud service model involves accessing applications over the internet without managing the underlying infrastructure?"

Services like Google Drive or Dropbox are some examples of Cloud Architecture operating under the `SaaS` (Software as a Service) model, where we access applications over the internet without managing the underlying hardware. Below are five essential characteristics that define a Cloud Architecture.

![[HTB Solutions/Others/z. images/8a4405ad69849aab0819e87250ef9afa_MD5.jpg]]

Answer: `SaaS`

# Internet Architecture

## Question 4

### "In which architecture is the control plane separated from the data plane? (Format: two words, one of which is hyphenated)"

`Software-Defined Networking (SDN)` is a modern networking approach that separates the control plane, which makes decisions about where traffic is sent, from the data plane, which actually forwards the traffic.

![[HTB Solutions/Others/z. images/dea13cae34140d9641b64060e3f32e4f_MD5.jpg]]

Answer: `Software-Defined Networking`

# Internet Architecture

## Question 5

### "Which architecture is known for decentralized data sharing without a central server?"

The `Peer-to-Peer` architecture is decentralized without having a central server.

![[HTB Solutions/Others/z. images/2a45395360ee1a4f5a5f2513445e2414_MD5.jpg]]

Answer: `placeholder`

# Internet Architecture

## Question 6

### "What model is used by video conferencing apps to combine centralized coordination with peer-to-peer data transfer?"

The `Hybrid` architecture is typically used in messaging apps and video conferencing.

![[HTB Solutions/Others/z. images/2912ef04f992d143adb597255b8966f9_MD5.jpg]]

Answer: `Hybrid`

# Wireless Networks

## Question 1

### "What type of waves do wireless networks use to connect devices? (Format: two words)"

A `wireless network` is a sophisticated communication system that employs radio waves or other wireless signals to connect various devices such as computers, smartphones, and IoT gadgets, enabling them to communicate and exchange data without the need for physical cables.

![[HTB Solutions/Others/z. images/b0ddd03b1f4843347c8b6c3cff4b1102_MD5.jpg]]

Answer: `radio waves`

# Wireless Networks

## Question 2

### "What device combines the functions of routing and providing Wi-Fi coverage in a home network? (Format: two words)"

A `router` is a device that forwards data packets between computer networks. In a home or small office setting, a `wireless router` combines the functions of:

- Routing
- Wireless Access Point

![[HTB Solutions/Others/z. images/9cc1af8ea492f1968f387e0e02b44727_MD5.jpg]]

Answer: `wireless router`

# Wireless Networks

## Question 3

### "What is used by a mobile hotspot to connect devices to the internet? (Format: two words)"

A `mobile hotspot` allows a smartphone (or other hotspot devices) to share its cellular data connection via Wi-Fi.

![[HTB Solutions/Others/z. images/9d573f85ec2780636ab49a09778aea9b_MD5.jpg]]

Answer: `cellular data`

# Wireless Networks

## Question 4

### "What structure supports antennas and communications equipment to create cellular network coverage? (Format: two words)"

A `cell tower` (or `cell site`) is a structure where antennas and electronic communications equipment are placed to create a cellular network cell.

![[HTB Solutions/Others/z. images/63556228117b234a603302e23f0e0ceb_MD5.jpg]]

Answer: `cell tower`

# Wireless Networks

## Question 5

### "What manages multiple cell towers in cellular networks? (Format: three words)"

These towers are managed by a `Base Station Controller` (BSC), which oversees the operation of multiple towers.

![[HTB Solutions/Others/z. images/37d84ed8214f6b4596626047c26d38f0_MD5.jpg]]

Answer: `Base Station Controller`

# Wireless Networks

## Question 6

### "Which frequency band is known for better wall penetration but more prone to interference?"

`2.4 GHz` (Gigahertz) – Used by older Wi-Fi standards (802.11b/g/n). Better at penetrating walls, but can be more prone to interference (e.g., microwaves, Bluetooth).

![[HTB Solutions/Others/z. images/79ee64dfd527e6163c18634c57fc8273_MD5.jpg]]

Answer: `2.4 GHz`

# Network Security

## Question 1

### "What device monitors network traffic and enforces rules to allow or block specific traffic?"

A `Firewall` is a network security device, either hardware, software, or a combination of both, that monitors incoming and outgoing network traffic. Firewalls enforce a set of rules (known as `firewall policies` or `access control lists`) to determine whether to `allow` or `block` specific traffic.

![[HTB Solutions/Others/z. images/8b394bf606939f2d001b98cd47b31ec8_MD5.jpg]]

Answer: `Firewall`

# Network Security

## Question 2

### "Which type of firewall operates at the network and transport layers of the OSI model? (Format: two words)"

`Packet Filtering`: Operates at Layer 3 (Network) and Layer 4 (Transport) of the OSI model.

![[HTB Solutions/Others/z. images/a90066dad9d5c7f850ecf7e7b777eeb3_MD5.jpg]]

Answer: `Packet Filtering`

# Network Security

## Question 3

### "What advanced feature does a Next-Generation Firewall include beyond stateful inspection? (Format: three words)"

`Next Generation Firewall (NGFW)`: Combines stateful inspection with advanced features like deep packet inspection.

![[HTB Solutions/Others/z. images/b5e81cc719b7ac429ead9c2c9f235ebb_MD5.jpg]]

Answer: `deep packet inspection`

# Network Security

## Question 4

### "Which system generates alerts for suspicious network activity without blocking it? (Format: acronym)"

An Intrusion Detection System (`IDS`) observes traffic or system events to identify malicious behavior or policy violations, generating alerts but not blocking the suspicious traffic.

![[HTB Solutions/Others/z. images/1a9b7117b3b0267f89083b5bf037f52d_MD5.jpg]]

Answer: `IDS`

# Network Security

## Question 5

### "Which system not only detects but also prevents suspicious network activity by blocking it? (Format: acronym)"

In contrast, an Intrusion Prevention System (`IPS`) operates similarly to an IDS but takes an additional step by preventing or rejecting malicious traffic in real time.

![[HTB Solutions/Others/z. images/330f4e336f7dfbf6d71d4930fd8853a4_MD5.jpg]]

Answer: `IPS`

# Network Security

## Question 6

### "What detection method involves comparing network traffic against a database of known exploits? (Format: three words)"

`Signature-based detection`: Matches traffic against a database of known exploits.

![[HTB Solutions/Others/z. images/d29853f08f8e6ec75a52a7922185d261_MD5.jpg]]

Answer: `Signature-based detection`

# Skills Assessment

## Question 1

### "What IPv4 address is used when a host wants to send and receive network traffic to itself?"

After spawning the workstation, students will open a terminal and use the `ifconfig -a` command to display the available network interfaces and find the loopback interface (`lo`) used to send network traffic (data) to itself on the `127.0.0.1` IP address:

Code: shell

```shell
ifconfig -a
```

```
┌─[us-academy-6]─[10.10.14.107]─[htb-ac-8414@htb-cmkfefnb7l]─[~]
└──╼ [★]$ ifconfig -a

<SNIP>

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 14987  bytes 15076991 (14.3 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 14987  bytes 15076991 (14.3 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

<SNIP>
```

Answer: `127.0.0.1`

# Skills Assessment

## Question 2

### "What is the the name of the Program listening on localhost:5901 of the Pwnbox?"

Students will use the `netstat` command with the `tulp4` parameter to display the open ports on the workstation and find the service `Xtigervnc` listening on port `5901`:

Code: shell

```shell
netstat -tulp4
```

```
┌─[us-academy-6]─[10.10.14.107]─[htb-ac-8414@htb-cmkfefnb7l]─[~]
└──╼ [★]$ netstat -tulp4

(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 localhost:ipp           0.0.0.0:*               LISTEN      -                   
tcp        0      0 localhost:5901          0.0.0.0:*               LISTEN      2804/Xtigervnc   

<SNIP>
```

Answer: `Xtigervnc`

# Skills Assessment

## Question 3

### "Which network interface allows us to interact with target machines in the HTB lab environment?"

Students will spawn the target machine and will use the previously opened terminal to determine the routing of a network packet to a given IP address. Upon scrutinizing the output, students will notice that the packet is being routed through the `tun0` network interface:

Code: shell

```shell
ip route get STMIP
```

```
┌─[us-academy-6]─[10.10.14.107]─[htb-ac-8414@htb-cmkfefnb7l]─[~]
└──╼ [★]$ ip route get 10.129.233.197

10.129.233.197 via 10.10.14.1 dev tun0 src 10.10.14.107 uid 1002 
    cache 
```

Answer: `tun0`

# Skills Assessment

## Question 4

### "What is the FTP command used to retrieve a file? (Format: XXXX)"

Students can refer to the [RFC959](https://datatracker.ietf.org/doc/html/rfc959) documentation to find information about the retrieval of files, where they will stumble across the `RETRIEVE` (`RETR`) command on page 30 in the documentation. Additionally, students can use the guided approach in `Chapter 2. - Having Tuns of Fun` of the Skills Assessment.

![[HTB Solutions/Others/z. images/38f93a6acffc7115f1e760dbac3a4833_MD5.jpg]]

Answer: `RETR`

# Skills Assessment

## Question 5

### "Bypass the request filtering found on the target machine's HTTP service, and submit the flag found in the response. The flag will be in the format: HTB{...}"

Students will connect to the FTP service as the user `anonymous` and password `anonymous` and download the `Notes-From-IT.txt` file to find that the website is under construction and requires the `Server Administrator` value for the `User-Agent`:

Code: shell

```shell
ftp STMIP
ls
get Note-From-IT.txt
!cat Note-From-IT.txt
```

```
┌─[us-academy-6]─[10.10.14.107]─[htb-ac-8414@htb-cmkfefnb7l]─[~]
└──╼ [★]$ ftp 10.129.233.197

Connected to 10.129.233.197.
220 Microsoft FTP Service
Name (10.129.233.197:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.

ftp> ls
229 Entering Extended Passive Mode (|||49674|)
125 Data connection already open; Transfer starting.
02-08-25  08:37PM                  438 Note-From-IT.txt
226 Transfer complete.

ftp> get Note-From-IT.txt
local: Note-From-IT.txt remote: Note-From-IT.txt
229 Entering Extended Passive Mode (|||49676|)
150 Opening ASCII mode data connection.
100% |***********************************************************************************************|   438        4.72 KiB/s    00:00 ETA
226 Transfer complete.
438 bytes received in 00:00 (4.71 KiB/s)

ftp> !cat Note-From-IT.txt
Bertolis,

The website is still under construction. To stop users from poking their nose where it doesn't belong, I've configured IIS to only allow requests containing a specific user-agent header. If you'd like to test it out, please provide the following header to your HTTP request.

User-Agent: Server Administrator

The site should be finished within the next couple of weeks. I'll keep you posted.

Cheers,
jarednexgent
```

Next, students will open a new terminal tab or exit the established session to the FTP service using the `exit` command. Subsequently, students will use `curl` to send a request to the HTTP service by specifying the `Server Administrator` for the user agent using the `-A` parameter and obtain the flag:

Code: shell

```shell
curl http://STMIP/ -A 'Server Administrator' | grep 'HTB{'
```

```
┌─[us-academy-6]─[10.10.14.107]─[htb-ac-8414@htb-cmkfefnb7l]─[~]
└──╼ [★]$ curl http://10.129.233.197/ -A 'Server Administrator' | grep 'HTB{'

  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   746  100   746    0     0   4060      0 --:--:-- --:--:-- --:--:--  4076
<!-- {hidden} -->
```

Answer: `HTB{S00n_2_B_N3tw0rk1ng_GURU!}`