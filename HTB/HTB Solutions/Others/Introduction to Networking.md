
| Section    | Question Number | Answer          |
| ---------- | --------------- | --------------- |
| Subnetting | Question 1      | 255.255.255.224 |
| Subnetting | Question 2      | 10.200.20.31    |
| Subnetting | Question 3      | 10.200.20.16    |
| Subnetting | Question 4      | 10.200.20.15    |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Subnetting

## Question 1

### "Submit the decimal representation of the subnet mask from the following CIDR: 10.200.20.0/27"

The subnet mask /27 is in slash notation, thus, it implies that there are 27 1's for the subnet bits out of the 32 bits in the four octets, `11111111.11111111.11111111.11100000`. Converting this from binary to decimal yields: `255.255.255.224`.

Students can also use [Calculator.net](https://www.calculator.net/ip-subnet-calculator.html) to find out the answer:

![[HTB Solutions/Others/z. images/83329a98c7f2cb355163325672ce5c49_MD5.jpg]]

Answer: `255.255.255.224`

# Subnetting

## Question 2

### "Submit the broadcast address of the following CIDR: 10.200.20.0/27"

Since the subnet mask /27 supports a maximum of 32 addresses, the broadcast address would be the one right after the last usable host address 10.200.20.30, which is `10.200.20.31`.

Students can also use [Calculator.net](https://www.calculator.net/ip-subnet-calculator.html?cclass=any&csubnet=27&cip=10.200.20.0&ctype=ipv4&printit=0&x=66&y=16) to find out the answer:

![[HTB Solutions/Others/z. images/89d346c1c63bdabcff95eb274bf27a07_MD5.jpg]]

Answer: `10.200.20.31`

# Subnetting

## Question 3

### "Split the network 10.200.20.0/27 into 4 subnets and submit the network address of the 3rd subnet as the answer."

Subnetting 10.200.20.0/27 into 4 smaller subnets equates to borrowing 2 bits from the network host bits to the subnet bits, thus, /27 becomes /29: `11111111.11111111.11111111.11111000`.

The number of hosts in each subnet increases by a factor of 8 (this can be easily identified by knowing the decimal value of the least significant bit of the subnet bits), therefore, the 4 subnets are:

1. `10.200.20.0/29`
2. `10.200.20.8/29`
3. `10.200.20.16/29`
4. `10.200.20.24/29`

The network address of the 3rd subnet is `10.200.20.16`.

Alternatively, students can also use [Calculator.net](https://www.calculator.net/ip-subnet-calculator.html?cclass=any&csubnet=29&cip=10.200.20.0&ctype=ipv4&printit=0&x=56&y=23) to find out the answer:

![[HTB Solutions/Others/z. images/034501674eb89fac6ffc646a8c782ec3_MD5.jpg]]

Answer: `10.200.20.16`

# Subnetting

## Question 4

### "Split the network 10.200.20.0/27 into 4 subnets and submit the broadcast address of the 2nd subnet as the answer."

The four subnets have been identified in the previous question, thus, the broadcast address of the second subnet is the address just after the last usable host address (`10.200.20.14`), i.e., `10.200.20.15`. From [Calculator.net](https://www.calculator.net/ip-subnet-calculator.html?cclass=any&csubnet=29&cip=10.200.20.0&ctype=ipv4&printit=0&x=56&y=23):

![[HTB Solutions/Others/z. images/d47e4f722d4fcaeeaf566d20d0748a0e_MD5.jpg]]

Answer: `10.200.20.15`