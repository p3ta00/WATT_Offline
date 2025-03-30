
| Section | Question Number | Answer |
| --- | --- | --- |
| Cyber Kill Chain | Question 1 | weaponize |
| Incident Handling Process Overview | Question 1 | False |
| Preparation Stage (Part 1) | Question 1 | Jump bag |
| Preparation Stage (Part 1) | Question 2 | True |
| Preparation Stage (Part 2) | Question 1 | DMARC |
| Preparation Stage (Part 2) | Question 2 | True |
| Detection & Analysis Stage (Part 1) | Question 1 | True |
| Detection & Analysis Stage (Part 2) | Question 1 | IOC |
| Containment, Eradication, & Recovery Stage | Question 1 | False |
| Post-Incident Activity Stage | Question 1 | True |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Cyber Kill Chain

## Question 1

### "In which stage of the cyber kill chain is malware developed?"

Malware is developed in the `weaponize` stage of the Cyber Kill Chain.

![[HTB Solutions/CDSA/z. images/77d814da7b07f6e5a850f80ec8b700ae_MD5.webp]]

Answer: `Weaponize`

# Incident Handling Process Overview

## Question 1

### "True or False: Incident handling contains two main activities. These are investigating and reporting."

False; the `incident handling` process contains two main activities `investigating` and `recovering`.

![[HTB Solutions/CDSA/z. images/fe33b3129e0136247515ca8869612f15_MD5.webp]]

Answer: `False`

# Preparation Stage (Part 1)

## Question 1

### "What should we have prepared and always ready to 'grab and go'?"

An incident responder's `jump bag` should always be ready for usage at all times.

![[HTB Solutions/CDSA/z. images/d64ae4974bae2da5eb2151a737be4b48_MD5.webp]]

Answer: `Jump bag`

# Preparation Stage (Part 1)

## Question 2

### "True or False: Using baselines, we can discover deviations from the golden image, which aids us in discovering suspicious or unwanted changes to the configuration."

`True`; establishing baselines helps discover deviations from the "golden image".

Answer: `True`

# Preparation Stage (Part 2)

## Question 1

### "What can we use to block phishing emails pretending to originate from our mail server?"

`DMARC` can block phishing emails pretending to originate from an organization.

![[HTB Solutions/CDSA/z. images/c5b36cd029235271c496351dbe0b1327_MD5.webp]]

Answer: `DMARC`

# Preparation Stage (Part 2)

## Question 2

### "True or False: "Summer2021!" is a complex password."

`True`; `Summer2021!` is a complex password because it contains an upper-case letter, lower-case letters, digits, and a special character.

Answer: `True`

# Detection & Analysis Stage (Part 1)

## Question 1

### "True or False: Can a third party vendor be a source of detecting a compromise?"

`True`; notifications from third-party vendors can be a source of detecting compromises.

![[HTB Solutions/CDSA/z. images/e9793932a66048ed94953b5be0feffa8_MD5.webp]]

Answer: `True`

# Detection & Analysis Stage (Part 2)

## Question 1

### "During an investigation, we discovered a malicious file with an MD5 hash value of 'b40f6b2c167239519fcfb2028ab2524a'. How do we usually call such a hash value in investigations? Answer format: Abbreviation"

An MD5 hash value such as "b40f6b2c167239519fcfb2028ab2524a" is an example of an `Indicator of Compromise` (`IoC`).

![[HTB Solutions/CDSA/z. images/88c4a6bb3600313ef70b891209c558d0_MD5.webp]]

Answer: `IoC`

# Containment, Eradication, & Recovery Stage

## Question 1

### "True or False: Patching a system is considered a short term containment."

`False`; Patching systems is considered a long-term containment:

![[HTB Solutions/CDSA/z. images/2b4eeb93e8c7001ca5cd1d35a0b191a1_MD5.jpg]]

Answer: `False`

# Post-Incident Activity Stage

## Question 1

### "True or False: We should train junior team members as part of these post-incident activities."

`True`; Junior team members should be trained on how senior members have handled an incident as part of post-incident activities.

![[HTB Solutions/CDSA/z. images/154848c6fdde4a3c33918ff469d1f2ed_MD5.jpg]]

Answer: `True`