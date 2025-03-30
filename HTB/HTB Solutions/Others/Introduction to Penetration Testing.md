| Section                      | Question Number | Answer                         |
| ---------------------------- | --------------- | ------------------------------ |
| Types of Penetration Tests   | Question 1      | Black box                      |
| Areas and Domains of Testing | Question 1      | Network infrastructure testing |
| Ethics of a Penetration Test | Question 1      | Do no harm                     |
| Cloud Security Testing       | Question 1      | Identity and Access Management |
| Physical Security Testing    | Question 1      | OSINT                          |
| Social Engineering           | Question 1      | Tailgating                     |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Types of Penetration Tests

## Question 1

### "Which type of a penetration test do we simulate with no prior knowledge of company's infrastructure? (Format: two words))"

The team began with a black box test, simulating an external attacker with `no prior knowledge` of the bank's systems.

![[HTB Solutions/Others/z. images/d08ae4b91c8fcff5ff6a96086db7c28d_MD5.jpg]]

Answer: `Black Box`

# Areas and Domains of Testing

## Question 1

### "Which domain of testing is the most fundamental for every penetration tester? (Format: three words)"

Network infrastructure testing is one of the most fundamental areas of penetration testing.

![[HTB Solutions/Others/z. images/64f02897e208318127638ea74fab54a7_MD5.jpg]]

Answer: `Network Infrastructure Testing`

# Ethics of a Penetration Test

## Question 1

### "What is the first ethic principle? (Format: three words)"

1. `"Do No Harm"` - testers must not damage systems, corrupt data, or disrupt business operations. Every action needs careful evaluation to avoid negative impacts on the target systems, both short-term and long-term.

![[HTB Solutions/Others/z. images/3a2c3bd17fcf4e34cc3191e2c8ebaa8a_MD5.jpg]]

Answer: `Do No Harm`

# Cloud Security Testing

## Question 1

### "What does IAM stands for in terms of cloud infrastructure? (Format: four words)"

The next phase is `access control` testing, where you assess the implementation of `Identity and Access Management` (`IAM`) policies.

![[HTB Solutions/Others/z. images/1c13700ae5aabce1d248ec5278f6dd8d_MD5.jpg]]

Answer: `Identity and Access Management`

# Physical Security Testing

## Question 1

### "What technique is used for the initial phase of information gathering? (Format: one word)"

The initial phase involves gathering information about the target facility through `open-source intelligence` (`OSINT`).

![[HTB Solutions/Others/z. images/e6db655a47901afef65df45458cd19f1_MD5.jpg]]

Answer: `OSINT`

# Social Engineering

## Question 1

### "What is the name of the technique that is used in social engineering where you are following authorized personnel through secure doors? (Format: one word)"

While many social engineering attacks occur digitally, physical social engineering is equally important in penetration testing. This involves gaining unauthorized physical access to facilities through various techniques such as `tailgating` (following authorized personnel through secure doors), impersonating delivery personnel, or claiming to be a new employee who forgot their access card.

![[HTB Solutions/Others/z. images/db446b19a5c85c21d1278bff107fc5fd_MD5.jpg]]

Answer: `tailgating`