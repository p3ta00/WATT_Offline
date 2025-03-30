
| Section                                                                                               | Question Number | Answer                         |
| ----------------------------------------------------------------------------------------------------- | --------------- | ------------------------------ |
| Introduction To The Elastic Stack                                                                     | Question 1      | anni                           |
| Introduction To The Elastic Stack                                                                     | Question 2      | 8                              |
| SOC Definition & Fundamentals                                                                         | Question 1      | true                           |
| SIEM Visualization Example 1: Failed Logon Attempts (All Users)                                       | Question 1      | 2                              |
| SIEM Visualization Example 2: Failed Logon Attempts (Disabled Users)                                  | Question 1      | interactive                    |
| SIEM Visualization Example 2: Failed Logon Attempts (Disabled Users)                                  | Question 2      | *admin*                        |
| SIEM Visualization Example 3: Successful RDP Logon Related To Service Accounts                        | Question 1      | 192.168.28.130                 |
| SIEM Visualization Example 4: Users Added Or Removed From A Local Group (Within A Specific Timeframe) | Question 1      | 2023-03-05                     |
| Skills Assessment                                                                                     | Question 1      | Consult with IT Operations     |
| Skills Assessment                                                                                     | Question 2      | Escalate to a Tier 2/3 analyst |
| Skills Assessment                                                                                     | Question 3      | Nothing suspicious             |
| Skills Assessment                                                                                     | Question 4      | Escalate to a Tier 2/3 analyst |
| Skills Assessment                                                                                     | Question 5      | Consult with IT Operations     |
| Skills Assessment                                                                                     | Question 6      | Consult with IT Operations     |
| Skills Assessment                                                                                     | Question 7      | Escalate to a Tier 2/3 analyst |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Introduction To The Elastic Stack

## Question 1

### "Navigate to http://\[Target IP\]:5601, click on the side navigation toggle, and click on "Discover". Then, click on the calendar icon, specify "last 15 years", and click on "Apply". Finally, choose the "windows\*" index pattern. Now, execute the KQL query that is mentioned in the "Comparison Operators" part of this section and enter the username of the disabled account as your answer. Just the username; no need to account for the domain."

After spawning the target machine, students need to navigate to `Elastic` listening on port `5601` and click on `Discover`:

![[HTB Solutions/CDSA/z. images/5bf4982a19acbf17707e9bed1b1a8a3e_MD5.jpg]]

Subsequently, students need to set the index pattern to `windows*` and the time picker to `Last 15 years`:

![[HTB Solutions/CDSA/z. images/21312db4e0f3c54eb30c5ec9e874141d_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/ec144c626f298a1b12bdeb44aab36b3c_MD5.jpg]]

At last, when running the query mentioned under "Comparison Operators", students will come to know that the username of the disabled account is `anni` within `message`:

```kql
event.code:4625 AND winlog.event_data.SubStatus:0xC0000072 AND @timestamp >= "2023-03-03T00:00:00.000Z" AND @timestamp <= "2023-03-06T23:59:59.999Z"
```

![[HTB Solutions/CDSA/z. images/3b5290638231913d01d14e7a2eb49331_MD5.jpg]]

Answer: `anni`

# Introduction To The Elastic Stack

## Question 2

### "Now, execute the KQL query that is mentioned in the "Wildcards and Regular Expressions" part of this section and enter the number of returned results (hits) as your answer."

Using the same `Elastic` session from the previous question, students need to run the query under "Wildcards and Regular Expressions" to attain `8` results:

```kql
event.code:4625 AND user.name: admin*
```

![[HTB Solutions/CDSA/z. images/129b22e488cb5adcef4d989bc92f5441_MD5.jpg]]

Answer: `8`

# SOC Definition & Fundamentals

## Question 1

### "True or false? SOC 2.0 follows a proactive defense approach."

`True`; SOC 2.0 follows a proactive defense approach.

![[HTB Solutions/CDSA/z. images/775c8f703e2c2b11c4381fd4f02c4f9d_MD5.jpg]]

Answer: `True`

# SIEM Visualization Example 1: Failed Logon Attempts (All Users)

## Question 1

### "Navigate to http://\[Target IP\]:5601, click on the side navigation toggle, and click on "Dashboard". Browse the refined visualization we created or the "Failed logon attempts \[All users\]" visualization, if it is available, and enter the number of logins for the sql-svc1 account as your answer."

After spawning the target machine, students need to navigate to `Elastic` on port `5601` and click on `Dashboard`:

![[HTB Solutions/CDSA/z. images/8949ca4ff9f1d3248e86f68bd89d71c0_MD5.jpg]]

Subsequently, students need to click on the `SOC-Alerts` dashboard:

![[HTB Solutions/CDSA/z. images/876583269de36021bc324b66177632eb_MD5.jpg]]

Students will find that the number of logins for the user `sql-svc1` is `2` from the `Failed logon attempts [All users]` visualization:

![[HTB Solutions/CDSA/z. images/3c2273ea4f5ff73698d8ed054de1e299_MD5.jpg]]

Answer: `2`

# SIEM Visualization Example 2: Failed Logon Attempts (Disabled Users)

## Question 1

### "Navigate to http://\[Target IP\]:5601, click on the side navigation toggle, and click on "Dashboard". Either create a new visualization or edit the "Failed logon attempts \[Disabled user\]" visualization, if it is available, so that it includes failed logon attempt data related to disabled users including the logon type. What is the logon type in the returned document?"

After spawning the target machine, students need to navigate to `Elastic` on port `5601` and click on `Dashboard`:

![[HTB Solutions/CDSA/z. images/8949ca4ff9f1d3248e86f68bd89d71c0_MD5.jpg]]

Subsequently, students need to click on the `SOC-Alerts` dashboard:

![[HTB Solutions/CDSA/z. images/876583269de36021bc324b66177632eb_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/42506d0d9770c72a6602f19e8a86e313_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/7f041d281fdc22a16820fd59e9055f1c_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/253850f9ab5e2afe3c966256468ce535_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/14cc7bcdfc2dd22cabf61ae8043c82f6_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/0c2f04c51c103ee0ce18f2ea12187d68_MD5.jpg]]

Answer: `Interactive`

# SIEM Visualization Example 2: Failed Logon Attempts (Disabled Users)

## Question 2

### "Navigate to http://\[Target IP\]:5601, click on the side navigation toggle, and click on "Dashboard". Either create a new visualization or edit the "Failed logon attempts \[Admin users only\]" visualization, if it is available, so that it includes failed logon attempt data where the username field contains the keyword "admin" anywhere within it. What should you specify after user.name: in the KQL query?"

Using the same `Elastic` session from the previous question, students need to first edit the lens of the `Failed logon attempts [Admin users only]` visualization:

![[HTB Solutions/CDSA/z. images/2aaca36f76703f1caf72fd97e5f8a25f_MD5.jpg]]

Subsequently, to edit the visualization such that it includes failed logon attempt data where the username field contains the keyword "admin" anywhere within it, students need specify `*admin*` after `user.name` in the KQL query:

```kql
user.name:*admin*
```

![[HTB Solutions/CDSA/z. images/c50d9365ef7fa600d990fadb5d51077f_MD5.jpg]]

Answer: `*admin*`

# SIEM Visualization Example 3: Successful RDP Logon Related To Service Accounts

## Question 1

### "Navigate to http://\[Target IP\]:5601, click on the side navigation toggle, and click on "Dashboard". Browse the visualization we created or the "RDP logon for service account" visualization, if it is available, and enter the IP of the machine that initiated the successful RDP logon using service account credentials as your answer."

After spawning the target machine, students need to navigate to `Elastic` on port `5601` and click on `Dashboard`:

![[HTB Solutions/CDSA/z. images/8949ca4ff9f1d3248e86f68bd89d71c0_MD5.jpg]]

Then, students need to click on the edit button of the `SOC-Alerts` dashboard:

![[HTB Solutions/CDSA/z. images/5717d2167eecee3bbb4a0e2fe2d838d0_MD5.jpg]]

Subsequently, students need to create a new visualization for `Successful RDP Logon Related To Service Accounts`:

![[HTB Solutions/CDSA/z. images/54834e61c7d9ba6f60a1b2fd17fc9c0c_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/a5f0f6fd1cd53edd543c0231ca3b932f_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/0a1ceec975fede946a1307bf7d345caa_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/856008d69c73f7a44f145893c5637c32_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/09e8245c6c69557cd9d77dd49c36dabd_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/7c0e79c22c677a9ee9b8c1c73c92df7b_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/ed268ab27a50203e7f377f2ca45da078_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/f1e94349d17303bbf621ca50aad4c5bd_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/bf63dfe353b427e05a8428514acf5ba8_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/29ca208621b565f5f5e9b2dc36e56797_MD5.jpg]]

After creating the visualization, students will come to know that the IP of the machine that initiated the successful RDP logon using service account credentials is `192.168.28.130`:

![[HTB Solutions/CDSA/z. images/e5a20f444979d24db9f198125b00e56a_MD5.jpg]]

Answer: `192.168.28.130`

# SIEM Visualization Example 4: Users Added Or Removed From A Local Group (Within A Specific Timeframe)

## Question 1

### "Navigate to http://\[Target IP\]:5601, click on the side navigation toggle, and click on "Dashboard". Extend the visualization we created or the "User added or removed from a local group" visualization, if it is available, and enter the common date on which all returned events took place as your answer. Answer format: 20XX-0X-0X"

After spawning the target machine, students need to navigate to `Elastic` on port `5601` and click on `Dashboard`:

![[HTB Solutions/CDSA/z. images/8949ca4ff9f1d3248e86f68bd89d71c0_MD5.jpg]]

Then, students need to click on the edit button of the `SOC-Alerts` dashboard:

![[HTB Solutions/CDSA/z. images/cd2b057e2cb8459617714bc7e6849d88_MD5.jpg]]

Subsequently, students need to create a new visualization to `monitor user additions or removals from the local "Administrators" group from March 5th 2023 to date`:

![[HTB Solutions/CDSA/z. images/7f43400816debf232ca4480c824f5a80_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/e2543be971a013aa3da01024dc7e56c3_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/bc9c34211d0c3db93d021e9128ea42c1_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/6aed26a094d62e4b4a84ecc2cf9c0922_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/a7b539ad337342b9e181bc162e69247c_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/8dc5df545ceb45e209b41395b8ba8b1e_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/18847a35fa26b622c1ccf5274004df93_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/4b99620d2faf0dfad47832d9f4d0bd09_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/401e018141530cdfef9fa5bf9a1490a5_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/de5dcbb233acd2cbb0740413102a8e49_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/6b38ecca04434145e75e33b19c99c40c_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/ebf46c6fd642ec502abd9641db0056d6_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/e85d2b1c8507257a5ec7fb3245549d83_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/33a53b8cfd59b4d0b60c86625f577ded_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/78e3d6756796d86d0b822acd609df0fd_MD5.jpg]]

Lastly, students will set the time range from `March 1st 2023` to `31st of March 2023` both as `Absolute` time ranges. Students must apply the change in the time range by clicking on the `Update` button:

![[HTB Solutions/CDSA/z. images/9dd4c60c077fb6f9b717308e9c6a1deb_MD5.jpg]]

After adding all the required rows and adjusting the time range, students need to save the visualization. When checking the visualization within the dashboard, students will notice that the common date the event took place is `2023-03-05`:

![[HTB Solutions/CDSA/z. images/fa6b7e413609edefd0bc0963be582ca6_MD5.jpg]]

Answer: `2023-03-05`

# Skills Assessment

## Question 1

### "Navigate to http://\[Target IP\]:5601, click on the side navigation toggle, and click on "Dashboard". Review the "Failed logon attempts \[All users\]" visualization of the "SOC-Alerts" dashboard. Choose one of the following as your answer: "Nothing suspicious", "Consult with IT Operations", "Escalate to a Tier 2/3 analyst""

After spawning the target machine, students need to navigate to `Elastic` on port `5601` and click on `Dashboard`:

![[HTB Solutions/CDSA/z. images/7ffd8da9860f16b0d1d029d12e42e753_MD5.jpg]]

Then, students need to select the `SOC-Alerts` dashboard:

![[HTB Solutions/CDSA/z. images/162606753313e407c12093eda724ae29_MD5.jpg]]

Now, students need to analyze the `Failed logon attempts [All users]` visualization:

![[HTB Solutions/CDSA/z. images/04c30793a6aa05a1e62dfbb953716e87_MD5.jpg]]

Such a visualization might reveal potential brute-force attacks. It's essential to identify any single user with numerous failed attempts or various users connecting to (or from) the same endpoint device. However, the current data does not point toward any such scenario. One noticeable anomaly is that `sql-svc1` has had an unsuccessful network login attempt:

![[HTB Solutions/CDSA/z. images/3d943114eb78dc953e55351b03249856_MD5.jpg]]

This is unusual because service accounts like this seldom have their passwords modified. Interestingly, the event details show that the logon type for authentication was `network`. This is peculiar for a SQL service account as it is typically expected to operate services locally on a server, not engaging in remote logins.

Therefore, the best choice would be to `Consult with IT Operations`.

Answer: `Consult with IT Operations`

# Skills Assessment

## Question 2

### "Navigate to http://\[Target IP\]:5601, click on the side navigation toggle, and click on "Dashboard". Review the "Failed logon attempts \[Disabled user\]" visualization of the "SOC-Alerts" dashboard. Choose one of the following as your answer: "Nothing suspicious", "Consult with IT Operations", "Escalate to a Tier 2/3 analyst""

Students need to return to `SOC-Alerts` dashboard, this time choosing the `Failed logon attempts [Disabled user]` visualization:

![[HTB Solutions/CDSA/z. images/3df08de3be80c6e7ffc2f4e44325459c_MD5.jpg]]

There seems to be one incident where the user "anni" has tried to authenticate, despite the account being disabled. This activity is highly questionable. Activity from disabled user accounts often suggests a threat actor who has gained access to login credentials and is trying to sign in using the account.

Consequently, the best course of action is to `Escalate to a Tier 2/3 analyst`.

Answer: `Escalate to a Tier 2/3 analyst`

# Skills Assessment

## Question 3

### "Navigate to http://\[Target IP\]:5601, click on the side navigation toggle, and click on "Dashboard". Review the "Failed logon attempts \[Admin users only\]" visualization of the "SOC-Alerts" dashboard. Choose one of the following as your answer: "Nothing suspicious", "Consult with IT Operations", "Escalate to a Tier 2/3 analyst""

Students need to return to `SOC-Alerts` dashboard, this time choosing the `Failed logon attempts [Admin users only]` visualization:

![[HTB Solutions/CDSA/z. images/cfd0f06eb35769538094de5d4f3b7db9_MD5.jpg]]

There isn't anything unusual in this visual representation. Administrative accounts originate from Privileged Access Workstations (PAW) or are being interactively used on Domain Controllers (DC1 and DC2).

Therefore, it is correct for students to consider this as `Nothing suspicious`.

Answer: `Nothing suspicious`

# Skills Assessment

## Question 4

### "Navigate to http://\[Target IP\]:5601, click on the side navigation toggle, and click on "Dashboard". Review the "RDP logon for service account" visualization of the "SOC-Alerts" dashboard. Choose one of the following as your answer: "Nothing suspicious", "Consult with IT Operations", "Escalate to a Tier 2/3 analyst""

Students need to return to `SOC-Alerts` dashboard, this time choosing the `RDP logon for service account` visualization:

![[HTB Solutions/CDSA/z. images/ec4d07d97c9595186185902fc0ee29e8_MD5.jpg]]

The depicted data immediately trigger red flags, given our understanding that service accounts in this ecosystem serve a very specialized function. Seeing even one instance of an RDP logon linked to a service account warrants suspicion.

Subsequently, students need to `Escalate to a Tier 2/3 analyst`.

Answer: `Escalate to a Tier 2/3 analyst`

# Skills Assessment

## Question 5

### "Navigate to http://\[Target IP\]:5601, click on the side navigation toggle, and click on "Dashboard". Review the "User added or removed from a local group" visualization of the "SOC-Alerts" dashboard. Choose one of the following as your answer: "Nothing suspicious", "Consult with IT Operations", "Escalate to a Tier 2/3 analyst""

Students need to return to `SOC-Alerts` dashboard, this time choosing the `User added or removed from a local group` visualization:

![[HTB Solutions/CDSA/z. images/e00e35d8432781e5a2307dc3120fc57c_MD5.jpg]]

Upon the initial assessment, the behavior showcased doesn't immediately arouse suspicion. An administrator has incorporated an individual (only represented by the SID value) into the administrators' group on the `PKI.eagle.local` server, which could be for a valid reason. Further examination is crucial to confirm whether this activity was expected or known. If a person's addition to the administrators' group was warranted, the change management records should reflect this. The next course of action is to review the modifications made that day before concluding the nature of this alert (whether it's benign or potentially suspicious).

Students should know the best course of action is to `Consult with IT Operations`.

Answer: `Consult with IT Operations`

# Skills Assessment

## Question 6

### "Navigate to http://\[Target IP\]:5601, click on the side navigation toggle, and click on "Dashboard". Review the "Admin logon not from PAW" visualization of the "SOC-Alerts" dashboard. Choose one of the following as your answer: "Nothing suspicious", "Consult with IT Operations", "Escalate to a Tier 2/3 analyst""

Students need to return to `SOC-Alerts` dashboard, this time choosing the `Admin logon not from PAW` visualization:

![[HTB Solutions/CDSA/z. images/97259bc05c9e751d052bf9206ad0826e_MD5.jpg]]

The alerts showcased here certainly raise eyebrows, given the policy that administrators should exclusively utilize PAW for server remote connections. A significant volume of connections can be traced back to the IP address 192.168.28.132, the identity and function currently unknown to us. Consequently, we must liaise with the IT Operation team to gain a more comprehensive understanding of this device and to ascertain whether it's commonplace for them to bypass the PAW machine and establish connections from other devices instead.

Therefore, students need to `Consult with IT Operations`.

Answer: `Consult with IT Operations`

# Skills Assessment

## Question 7

### "Navigate to http://\[Target IP\]:5601, click on the side navigation toggle, and click on "Dashboard". Review the "SSH Logins" visualization of the "SOC-Alerts" dashboard. Choose one of the following as your answer: "Nothing suspicious", "Consult with IT Operations", "Escalate to a Tier 2/3 analyst""

Students need to return to `SOC-Alerts` dashboard, this time choosing the `SSH Logins` visualization:

![[HTB Solutions/CDSA/z. images/f5cad3c57d943a272c7728e678bacf3c_MD5.jpg]]

The actions illustrated in the final visualizations strike us as unusual, given our understanding that the root user account is not typically in use. Several unsuccessful login attempts involving this account suggest a potential security concern.

Ultimately, students need to `Escalate to a Tier 2/3 analyst`.

Answer: `Escalate to a Tier 2/3 analyst`