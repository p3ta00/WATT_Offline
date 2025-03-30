

| Section                                 | Question Number | Answer                 |
| --------------------------------------- | --------------- | ---------------------- |
| Bluetooth Legacy Attacks                | Question 1      | Bluesmacking           |
| Modern Bluetooth Attacks and Mitigation | Question 1      | 8                      |
| Cryptanalysis Side-Channel Attacks      | Question 1      | Timing Attacks         |
| Microprocessor Vulnerabilities          | Question 1      | Speculative Execution  |
| Microprocessor Vulnerabilities          | Question 2      | Out-of-Order Execution |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Bluetooth Legacy Attacks

## Question 1

### What is the term used to describe a denial-of-service (DoS) attack that targets Bluetooth-enabled devices by exploiting a vulnerability in the L2CAP Bluetooth protocol to transfer large packets?

`Bluesmacking` is a `denial-of-service` (DoS) attack targeting Bluetooth-enabled devices.

![[HTB Solutions/Others/z. images/67738d2313184afaaf079d1cae0b593c_MD5.jpg]]

Answer: `BlueSmacking`

# Modern Bluetooth Attacks and Mitigation

## Question 1

### How many 0-day exploits formed part of BlueBorne?

The research team at `Armis Labs`, who unearthed this vulnerability, identified `eight zero-day` vulnerabilities associated with `BlueBorne`.

![[HTB Solutions/Others/z. images/a9518c774274c7bd2b2c869bf530b454_MD5.jpg]]

Answer: `8`

# Cryptanalysis Side-Channel Attacks

## Question 1

### What is the term for a type of side-channel attack in which an attacker derives information about a cryptographic system measuring the amount of time the system takes to process different inputs, making informed guesses about the secret key based on observed variations?

`Timing attacks` are a type of side-channel attack where an attacker gains information about cryptographic system based on the `amount of time the system takes to process different inputs`.

![[HTB Solutions/Others/z. images/5e5a3018c281b00db4cd24a6962c016d_MD5.jpg]]

Answer: `timing attacks`

# Microprocessor Vulnerabilities

## Question 1

### What performance optimisation technique did Spectre leverage for exploitation?

Spectre takes advantage of the `speculative execution` technique used in modern processors.

![[HTB Solutions/Others/z. images/ba7a2ebbeb1f3e84bd741d1e20330970_MD5.jpg]]

Answer: `speculative execution`

# Microprocessor Vulnerabilities

## Question 2

### What performance optimisation technique did Meltdown leverage for exploitation

The key to the Meltdown vulnerability is its exploitation of modern microprocessors known as `out-of-order exection`. This is a performance-enhancing technique.

![[HTB Solutions/Others/z. images/c5f7971fbdac16d99dfe7953ea103f97_MD5.jpg]]

Answer: `out-of-order execution`