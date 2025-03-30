| Section | Question Number | Answer |
| --- | --- | --- |
| Threat Hunting Fundamentals | Question 1 | proactively and reactively |
| Threat Hunting Fundamentals | Question 2 | False |
| Threat Hunting Fundamentals | Question 3 | True |
| The Threat Hunting Process | Question 1 | False |
| Threat Intelligence Fundamentals | Question 1 | False |
| Threat Intelligence Fundamentals | Question 2 | Reach out to the Incident Handler/Incident Responder |
| Threat Intelligence Fundamentals | Question 3 | Provide further IOCs and TTPs associated with the incident |
| Threat Intelligence Fundamentals | Question 4 | provide insight into adversary operations |
| Hunting For Stuxbot | Question 1 | XceGuhkzaTrOy.vbs |
| Hunting For Stuxbot | Question 2 | lsadump::dcsync /domain:eagle.local /all /csv, exit |
| Hunting For Stuxbot | Question 3 | PowerView |
| Skills Assessment | Question 1 | svc-sql1 |
| Skills Assessment | Question 2 | LgvHsviAUVTsIN |
| Skills Assessment | Question 3 | svc-sql1 |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Threat Hunting Fundamentals

## Question 1

### "Threat hunting is used ... Choose one of the following as your answer: "proactively", "reactively", "proactively and reactively"."

Threat hunting is used `proactively and reactively`.

![[HTB Solutions/CDSA/z. images/5f406a45d1e467c2bef91c7977d2c004_MD5.jpg]]

Answer: `proactively and reactively`

# Threat Hunting Fundamentals

## Question 2

### "Threat hunting and incident handling are two processes that always function independently. Answer format: True, False."

`False`; whether threat hunting and incident handling should function independently is a strategic decision contingent upon each organization's unique threat landscape, risk, etc.

![[HTB Solutions/CDSA/z. images/1d25769baef2a798a7e08c7ae11082c1_MD5.jpg]]

Answer: `False`

# Threat Hunting Fundamentals

## Question 3

### "Threat hunting and incident response can be conducted simultaneously. Answer format: True, False."

`True`; threat hunting and incident response can be conducted simultaneously.

![[HTB Solutions/CDSA/z. images/64324daff26e653fd215d4f4d19ae351_MD5.jpg]]

Answer: `True`

# The Threat Hunting Process

## Question

### "It is OK to formulate hypotheses that are not testable. Answer format: True, False."

`False`; formulated hypotheses should be specific and testable.

![[HTB Solutions/CDSA/z. images/7b13c5cfc75a5f76f25a7de811f80dc7_MD5.jpg]]

Answer: `False`

# Threat Intelligence Fundamentals

## Question 1

### " It’s useful for the CTI team to provide a single IP with no context to the SOC team. Answer format: True, False."

`False`; it's not useful

![[HTB Solutions/CDSA/z. images/dcfb1e661f2101e7c9438c8eca73e7f7_MD5.jpg]]

Answer: `False`

# Threat Intelligence Fundamentals

## Question 2

### "When an incident occurs on the network and the CTI team is made aware, what should they do? Choose one of the following as your answer: "Do Nothing", "Reach out to the Incident Handler/Incident Responder", "Provide IOCs on all research being conducted, regardless if the IOC is verified"."

`Reach out to the Incident Handler/Incident Responder` is the recommended response. Incident handlers or responders are trained and equipped to handle security incidents effectively. They possess the necessary expertise and tools to assess the situation, coordinate the response, and minimize the impact of the incident. By notifying the incident handler or responder promptly, the CTI team enables a coordinated and timely incident response.

Answer: `Reach out to the Incident Handler/Incident Responder`

# Threat Intelligence Fundamentals

## Question 3

### "When an incident occurs on the network and the CTI team is made aware, what should they do? Choose one of the following as your answer: "Provide IOCs on all research being conducted, regardless if the IOC is verified", "Do Nothing", "Provide further IOCs and TTPs associated with the incident"."

When they become aware of a network incident, the appropriate action for the CTI (Cyber Threat Intelligence) team is to `provide further IOCs and TTPs associated with the incident.` IOCs are artifacts that indicate potential malicious activity, while TTPs (Tactics, Techniques, and Procedures) describe the methods used by threat actors. By providing additional IOCs and TTPs associated with the incident, the CTI team can enhance the incident response process and aid in identifying, mitigating, and preventing similar incidents in the future. This information can be shared with incident handlers, responders, and other relevant security teams to improve their situational awareness and response capabilities.

Answer: `Provide further IOCs and TTPs associated with the incident`

# Threat Intelligence Fundamentals

## Question 4

### "Cyber Threat Intelligence, if curated and analyzed properly, can ... ? Choose one of the following as your answer: "be used for security awareness", "be used for fine-tuning network segmentation", "provide insight into adversary operations"."

Cyber Threat Intelligence, if curated and analyzed properly, can `provide insight into adversary operations`:

![[HTB Solutions/CDSA/z. images/e4cbfd2f9208e3d2254653a42840cd67_MD5.jpg]]

Answer: `Provide insight into adversary operations`

# Hunting For Stuxbot

## Question 1

### "Navigate to http://\[Target IP\]:5601 and follow along as we hunt for Stuxbot. In the part where default.exe is under investigation, a VBS file is mentioned. Enter its full name as your answer, including the extension."

Students need to spawn the target and browse to `http://[Target IP]:5601/app/management/kibana/settings` , where they will specify the `Europe/Copenhagen` time zone:

![[HTB Solutions/CDSA/z. images/5498cb3a18a71df984a91abf9d28f84b_MD5.jpg]]

Next, students need to click the hamburger icon and choose Discover. Then, they need to perform a search for Sysmon Event ID 15 (which represents a browser file download event) while also filtering for files named "invoice.one" :

Code: kql

```kql
event.code:15 AND file.name:invoice.one*
```

![[HTB Solutions/CDSA/z. images/8f6c1f6d38697e02df0ac41f151745f1_MD5.jpg]]

These events could have serious implications, however, it's not yet confirmed if this file is the same one mentioned in the report. Therefore, students need to note the timestamp `March 26, 2023 @ 22:05:47` and then attempt to corroborate the information by examining Sysmon Event ID 11 (which corresponds to a FileCreate event) along with the "invoice.one" file name:

Code: kql

```kql
event.code:11 AND file.name:*invoice.one
```

![[HTB Solutions/CDSA/z. images/c4c9443616547ec24b38afdd0712c667_MD5.jpg]]

Inspecting the log, students will see the machine that reported the "invoice.one" file is WS001:

![[HTB Solutions/CDSA/z. images/13a18428f17a28669fca8643a5e64a46_MD5.jpg]]

The machine's IP address should also be identified, so students need to filter for Sysmon Event ID 3 (which logs any network connection) along with the hostname of WS001:

Code: kql

```kql
event.code:3 AND host.hostname:WS001
```

![[HTB Solutions/CDSA/z. images/872810b57bf3a8185e1c5bfd5f7f05fa_MD5.jpg]]

The IP address of `192.168.28.130` can be confirmed by looking at the `source.ip` field.

Now, students need to analyze the `Zeek` logs. Students should filter and examine the DNS queries that `Zeek` has captured from WS001 during the interval from `22:05:00` to `22:05:48`, when the file was downloaded.

Specifically, the `Zeek` query will search for a source IP matching `192.168.28.130` while only picking logs that have a value in the `dns.question.name` field:

Code: kql

```kql
source.ip:192.168.28.130 AND dns.question.name:*
```

![[HTB Solutions/CDSA/z. images/3d7151bc5060cade3d81d34c7c4e8a13_MD5.jpg]]

Additional filters should be added to reduce the noise from domains such as google.com. Also, students need to add `dns.question.name` as a column:

![[HTB Solutions/CDSA/z. images/9b4faf62408951f1f24d788bed8070f2_MD5.jpg]]

The following activities will be observed:

![[HTB Solutions/CDSA/z. images/6676a3a3c4be95518dd668f038e6877a_MD5.jpg]]

From this data, students can infer that the user accessed Google Mail, followed by interaction with "file.io", a known hosting provider. Subsequently, Microsoft Defender SmartScreen initiated a file scan, typically triggered when a file is downloaded via Microsoft Edge. Expanding the log entry for file.io reveals the returned IP addresses `34.197.10.85` and `3.213.216.16`.

Now, students need to run a search for any connections to these IP addresses during the same timeframe as the DNS query:

![[HTB Solutions/CDSA/z. images/f2bc338244ba22f560b82f0fcd536ecb_MD5.jpg]]

This information corroborates that a user, Bob, successfully downloaded the file "invoice.one" from the hosting provider "file.io". If "invoice.one" was accessed, it would be opened with the OneNote application. Therefore, students need to use the following query to flag the event:

Code: kql

```kql
event.code:1 AND process.command_line:*invoice.one*
```

![[HTB Solutions/CDSA/z. images/8504e6e98d3fc1ea70069abeb2b04a6c_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/ab9a600f789e65c00d89e34f03ee19f1_MD5.jpg]]

Students will find that the OneNote file was accessed shortly after its download, with a delay of roughly 6 seconds. Now, with OneNote.exe in operation and the file open, students can speculate that it either contains a malicious link or a malevolent file attachment. In either case, OneNote.exe will initiate either a browser or a malicious file. Subsequently, students should scrutinize any new processes where OneNote.exe is the parent process.

Code: kql

```kql
event.code:1 AND process.parent.name:"ONENOTE.EXE"
```

![[HTB Solutions/CDSA/z. images/44d31f153259d4dcaa46596d9f25f941_MD5.jpg]]

The results of this query present three hits. However, one of these (the bottom one) falls outside the relevant time frame and can be dismissed.

The middle entry documents a new process, OneNoteM.exe, which is a component of OneNote and assists in launching files:

![[HTB Solutions/CDSA/z. images/caba2ce8baa3b7cfb01181bae94263cf_MD5.jpg]]

While the top entry reveals "cmd.exe" in operation, executing a file named "invoice.bat":

![[HTB Solutions/CDSA/z. images/4dde3740c9db56b11299c9d40521e1f7_MD5.jpg]]

Students can establish a connection between "OneNote.exe", the suspicious "invoice.one", and the execution of "cmd.exe" that initiates "invoice.bat" from a temporary location. Now, students need to search if a parent process (with a command line argument pointing to the batch file) has spawned any child processes:

Code: kql

```kql
event.code:1 AND process.parent.command_line:*invoice.bat*
```

![[HTB Solutions/CDSA/z. images/1c1994b356cccddebf30e38ba8278b7c_MD5.jpg]]

This returns a single result: the initiation of `PowerShell`, along with suspicious arguments being passed to it. Specifically, a command to download and execute content from Pastebin (an open text hosting provider.) Students need to check the URL (`https://pastebin.com/raw/33Z1jP6J`) in their browser, confirming the endpoint still exists:

![[HTB Solutions/CDSA/z. images/233acfd73783968dee93e7e071e0234b_MD5.jpg]]

Back to `Kibana`, students should add `process.name`, `process.args`, and `process.pid` as columns:

![[HTB Solutions/CDSA/z. images/c912e87b07b2ced3f6299e3f6374f9b7_MD5.jpg]]

To assess exactly what `PowerShell` did, students need a filter based on the process ID and process name. Additionally, students need to add `event.code` as a column prior to running the query:

Code: kql

```kql
process.pid:"9944" and process.name:"powershell.exe"
```

![[HTB Solutions/CDSA/z. images/b6974a3767c6d2ce29b099a65adca781_MD5.jpg]]

Observing the output, students will see indications of file creation, attempted network connections, and some DNS resolutions leveraging Sysmon Event ID 22 (DNSEvent). For better visualization, students should remove `process.pid` while adding the `file.path`, `dns.question.name`, and `destination.ip` as columns:

![[HTB Solutions/CDSA/z. images/f83ba20093f1e4af24259bc764f6efa9_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/8933cbf7c642861bff6ebf4bab741283_MD5.jpg]]

Students can conclude that `Ngrok` was likely employed as C2 (to mask malicious traffic to a known domain). Examining the connections above the DNS resolution for `Ngrok`, it points to the destination IP address 443, implying that the traffic was encrypted.

The dropped EXE is likely intended for persistence. Its distinctive name should facilitate determining whether it was ever executed. Students should note the timestamps – there is some time lapse between different activities, suggesting it's less likely to have been scripted, but perhaps an actual human interaction took place (unless random sleep occurred between the executed actions). The final actions that this process points to are a DNS query for DC1 and connections to it.

Therefore, students need to review `Zeek` data for information on the destination IP address `18.158.249.75` that was discovered, while adding the fields `source.ip`, `destination.ip`, and `destination.port` as columns:

![[HTB Solutions/CDSA/z. images/3b7260a5655a204aa3ac8b9aa1a21227_MD5.jpg]]

Students will observe that the activity seems to have extended into the subsequent day. The reason for the termination of the activity is unclear. Consequently, students need to inspect DNS queries for "ngrok.io" while adding `dns.answers.data` as a column:

![[HTB Solutions/CDSA/z. images/c8676fe0d15d6a347ae78e9ff8d16385_MD5.jpg]]

The newly discovered IP `3.125.102.39` also indicates that connections continued consistently over the following days:

![[HTB Solutions/CDSA/z. images/54b0bdf50661187b907164cdd6b7edc0_MD5.jpg]]

Thus, it's apparent that there is sustained network activity, and students can deduce that the C2 has been accessed continually. Now, students need to switch back to the `windows*` index and probe the logs to investigate the previously discovered executable file "default.exe". The `process.name`, `process.args`, `event.code`, `file.path`, `destination.ip`, and `dns.question.name` fields should be added as columns:

Code: kql

```kql
process.name:"default.exe"
```

![[HTB Solutions/CDSA/z. images/152cee179e5b2c04822b7f98ae0ac416_MD5.jpg]]

Confirming that "default.exe" has been executed, students should discern that the executable initiated DNS queries for `Ngrok` and established connections with the C2 IP addresses. It also uploaded two files, "svchost.exe" and "SharpHound.exe". Further activity from this executable includes the uploading of "payload.exe", a VBS file, and repeated uploads of "svchost.exe":

![[HTB Solutions/CDSA/z. images/ee14a0e683b647fcf777a578a4d20a7c_MD5.jpg]]

Students will find the VBS file named `XceGuhkzaTrOy.vbs`.

Answer: `XceGuhkzaTrOy.vbs`

# Hunting For Stuxbot

## Question 2

### "Stuxbot uploaded and executed mimikatz. Provide the process arguments (what is after .\\mimikatz.exe, ...) as your answer."

Students need to use a KQL query to search for a `process.name` of `mimikatz.exe`:

Code: kql

```kql
process.name:"mimikatz.exe"
```

![[HTB Solutions/CDSA/z. images/5280d208f88afa23cb421cc970517a44_MD5.jpg]]

Then, students need to add the `process.args` field as a column, which shows `mimikatz.exe` was run with the following command line arguments:

```
lsadump::dcsync /domain:eagle.local /all /csv, exit
```

![[HTB Solutions/CDSA/z. images/d8e025e0d4a8f0f8b9e1a3e8964503fb_MD5.jpg]]

Students can confirm the attacker attempted to perform a `DCSync` attack, trying to gain the password hashes for all domain users.

Answer: `lsadump::dcsync /domain:eagle.local /all /csv, exit`

# Hunting For Stuxbot

## Question 3

### "Some PowerShell code has been loaded into memory that scans/targets network shares. Leverage the available PowerShell logs to identify from which popular hacking tool this code derives. Answer format (one word): P\_\_\_\_V\_\_\_ "

Students need to use a KQL query to inspect the logs for `powershell.file.script_block_text` , specifically script blocks that contain the string "share":

Code: kql

```kql
powershell.file.script_block_text : "*share"
```

![[HTB Solutions/CDSA/z. images/fe0805da93aa29f7f6f420aee5a882d0_MD5.jpg]]

When ingesting `PowerShell` logs into the ELK stack, the `powershell.file.script_block_text` field is typically populated with the content of a `PowerShell` script block that was executed. This field enables search, analysis, and visualization of `PowerShell` commands and scripts within the log data.

Subsequently, students need to copy and paste the highlighted code block into Google. Students will find the code sample being referenced comes from `PowerView`:

![[HTB Solutions/CDSA/z. images/e553147378adfa03ab7d5d90ed3edf3d_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/c6bb6ff65859b7736b4520533d837c27_MD5.jpg]]

Answer: `PowerView`

# Skills Assessment

## Question 1

### "Enter your answer for Hunt 1."

Students need to query for `event.code` `11` and the `file.directory` `C:\Users\Public`, in addition to applying `user.name` and `file.name` as columns:

Code: kql

```kql
event.code:11 AND file.directory: "C:\Users\Public"
```

![[HTB Solutions/CDSA/z. images/3075d18139d11be8faabb349f210d19b_MD5.jpg]]

Sysmon event ID 11 corresponds to the "FileCreate" event in Sysmon. When this event is logged, it indicates that a file creation operation has occurred on the system. Subsequently, students will find the user `svc-sql1` associated with the `Rubeus.exe` file name:

![[HTB Solutions/CDSA/z. images/4a905debc284e18330f6cb669246b638_MD5.jpg]]

Answer: `svc-sql1`

# Skills Assessment

## Question 2

### "Enter your answer for Hunt 2."

According to the requirements given for `Hunt 2`, students need to utilize the below query in addition to applying `registry.value` as a column:

Code: kql

```kql
event.code:13 AND registry.path: (HKU\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\* OR HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*)
```

![[HTB Solutions/CDSA/z. images/241fbbcfc72fb9265dda7401c8b77549_MD5.jpg]]

Sysmon event ID 13 corresponds to the "RegistryEvent (Value Set)" event in Sysmon. This event is triggered when a registry value is modified on the system. Multiple events indicate the bob user has written to the registry. Students need to look for evidence of persistence:

![[HTB Solutions/CDSA/z. images/358bea51e284b4524d87850897666e7b_MD5.jpg]]

Expanding the log, students will encounter references to both `powershell.exe` and `default.exe`:

![[HTB Solutions/CDSA/z. images/c37bc88ffe01b4e2d67cd83e88ea048e_MD5.jpg]]

The content of the `registry.value` field shows `LgvHsviAUVTsIN`.

Answer: `LgvHsviAUVTsIN`

# Skills Assessment

## Question 3

### "Enter your answer for Hunt 3."

Students need to identify instances of `PowerShell` remoting sessions in addition to adding `winlog.user.name`, `powershell.file.script_block_test` and `host.name` as columns:

Code: kql

```kql
event.code:4104 and powershell.file.script_block_text: "*enter-pssession*"
```

![[HTB Solutions/CDSA/z. images/bc51cb51743b13ee7fe0be6509d6dca4_MD5.jpg]]

The event ID 4104 refers to the execution of a remote PowerShell command. Students will find evidence that the `svc-sql1` user initiated a PS Remote session from `PKI.eagle.local` to `DC1`.

Answer: `svc-sql1`