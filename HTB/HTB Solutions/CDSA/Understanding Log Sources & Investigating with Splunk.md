| Section | Question Number | Answer |
| --- | --- | --- |
| Introduction To Splunk & SPL | Question 1 | waldo |
| Introduction To Splunk & SPL | Question 2 | 10 |
| Introduction To Splunk & SPL | Question 3 | aparsa |
| Using Splunk Applications | Question 1 | net view /DOMAIN:uniwaldo.local |
| Using Splunk Applications | Question 2 | 6 |
| Intrusion Detection With Splunk (Real-world Scenario) | Question 1 | rundll32.exe |
| Intrusion Detection With Splunk (Real-world Scenario) | Question 2 | comsvcs.dll |
| Intrusion Detection With Splunk (Real-world Scenario) | Question 3 | rundll32.exe |
| Intrusion Detection With Splunk (Real-world Scenario) | Question 4 | 10.0.0.186 and 10.0.0.91 |
| Intrusion Detection With Splunk (Real-world Scenario) | Question 5 | 3389 |
| Detecting Attacker Behavior With Splunk Based On TTPs | Question 1 | Password@123 |
| Detecting Attacker Behavior With Splunk Based On Analytics | Question 1 | randomfile.exe |
| Skills Assessment | Question 1 | randomfile.exe |
| Skills Assessment | Question 2 | rundll32.exe |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Introduction To Splunk & SPL

## Question 1

### "Navigate to http://\[Target IP\]:8000, open the "Search & Reporting" application, and find through an SPL search against all data the account name with the highest amount of Kerberos authentication ticket requests. Enter it as your answer."

Students need to first navigate to http://STMIP:8000 and open the "Search & Reporting" application:

![[HTB Solutions/CDSA/z. images/6bd46970e7b190f0d661d2d883837d11_MD5.jpg]]

Next, students need to adjust the time period from `Last 24 hours` to `all time`:

![[HTB Solutions/CDSA/z. images/56b2b2073c67f514d39ef7278e91bc4a_MD5.jpg]]

Then, students need to search for events in the "main" index where the EventCode is `4768`, while using the `stats` command to count the occurrences of each unique value in the Account\_Name field:

```
index="main" EventCode=4768 | stats count by Account_Name
```

![[HTB Solutions/CDSA/z. images/384efa49af43fcc3090ba459ccfb6533_MD5.jpg]]

Students will find `waldo` has the highest number of TGT requests, with 12 total.

Answer: `waldo`

# Introduction To Splunk & SPL

## Question 2

### "Navigate to http://\[Target IP\]:8000, open the "Search & Reporting" application, and find through an SPL search against all 4624 events the count of distinct computers accessed by the account name SYSTEM. Enter it as your answer."

Students need to first navigate to http://STMIP:8000 and open the "Search & Reporting" application:

![[HTB Solutions/CDSA/z. images/6bd46970e7b190f0d661d2d883837d11_MD5.jpg]]

Next, students need to adjust the time period from `Last 24 hours` to `all time`:

![[HTB Solutions/CDSA/z. images/56b2b2073c67f514d39ef7278e91bc4a_MD5.jpg]]

Then, students need a query that searches for event code `4624` in the "main" index. Additionally, students need to use the `stats dc` command to calculate the distinct count of workstations (unique values of "ComputerName") and grouping by the values in the Account\_Name field:

```
index="main" EventCode=4624 | stats dc(ComputerName) as unique_workstations by Account_Name
```

![[HTB Solutions/CDSA/z. images/7a0f5d75761c2f9773a7b000b6bae639_MD5.jpg]]

Students will see the SYSTEM user has accessed `10` unique workstations.

Answer: `10`

# Introduction To Splunk & SPL

## Question 3

### "Navigate to http://\[Target IP\]:8000, open the "Search & Reporting" application, and find through an SPL search against all 4624 events the account name that made the most login attempts within a span of 10 minutes. Enter it as your answer."

Students need to first navigate to http://STMIP:8000 and open the "Search & Reporting" application:

![[HTB Solutions/CDSA/z. images/6bd46970e7b190f0d661d2d883837d11_MD5.jpg]]

Next, students need to adjust the time period from `Last 24 hours` to `all time`:

![[HTB Solutions/CDSA/z. images/56b2b2073c67f514d39ef7278e91bc4a_MD5.jpg]]

Then, students need to search for events in the "main" index where the EventCode is `4624`. Additionally, students need to use the `stats` command to calculate the count of events as "login\_attempts", and the range of time as "period" and grouping by the Account\_Name field. Finally, the results must be filtered to only include those records where the time range is less than 600 seconds (10 minutes):

```
index="main" EventCode=4624 | stats count as login_attempts, range(_time) as period by Account_Name | where period < 600
```

![[HTB Solutions/CDSA/z. images/ffee39feaa1daf36a1c43527bea22a28_MD5.jpg]]

Students will find the `aparsa` user has the most login attempts.

Answer: `asparsa`

# Using Splunk Applications

## Question 1

### "Access the Sysmon App for Splunk and go to the "Reports" tab. Fix the search associated with the "Net - net view" report and provide the complete executed command as your answer. Answer format: net view /Domain:\_.local"

Students need to navigate to https://splunkbase.splunk.com/app/3544 and download the Sysmon App for Splunk:

![[HTB Solutions/CDSA/z. images/af878a709ed4add4c8089e193b75a0fb_MD5.jpg]]

Then, students need to then navigate to http://STMIP:8000 and select `manage apps`:

![[HTB Solutions/CDSA/z. images/cc2ca5a03baf7f7f6078aad18a845ce9_MD5.jpg]]

Subsequently, students need to select `Install app from file` :

![[HTB Solutions/CDSA/z. images/55ee118470be7ace5d24839fa5d5d242_MD5.jpg]]

And then browse for the newly downloaded `sysmom-app-for-splunk_200.gz` file:

![[HTB Solutions/CDSA/z. images/e96d2c1c16da1ca799e62fc00564285a_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/849c048cbb14747ed463c0168138302d_MD5.jpg]]

After clicking `upload`, students will be prompted to restart Splunk:

![[HTB Solutions/CDSA/z. images/a63b69e2143eceeba9a9ac2d6c269cd7_MD5.jpg]]

Giving the software a few moments, once the restart is complete, students need to adjust the application's macro so that events are loaded:

![[HTB Solutions/CDSA/z. images/0c6e421b24f298ad2deb9232b9c7a347_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/5e59e8c87254168f7a57362bc301e8b2_MD5.jpg]]

Students need to select `Sysmon App for Splunk` as the app, and `sysmon` as the macro:

![[HTB Solutions/CDSA/z. images/dee76e55f6d5166f74a64b8d9122b461_MD5.jpg]]

Consequently, students need to adjust the Definition and Save:

```shell
index="main" sourcetype="WinEventLog:Sysmon"
```

![[HTB Solutions/CDSA/z. images/e42be2884eebb53a86cea50e5c38fc29_MD5.jpg]]

Now, students need to go to the Sysmon App for Splunk App:

![[HTB Solutions/CDSA/z. images/ada3aa7c3f9daf9ac2794d7fb498bf28_MD5.jpg]]

Students need to select the Reports tab, identifying the `Net - net view` report and choosing to Open in Search:

![[HTB Solutions/CDSA/z. images/58f31b0151fc82e2325c588866947eca_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/014f758006c4b89508f4201d17b5e0ae_MD5.jpg]]

After clicking Edit -> open in Search, students will see the current query returns no events:

![[HTB Solutions/CDSA/z. images/b7782f557c43b70fc69dba35ba33cf1b_MD5.jpg]]

Students need to first use a simple, modified version of the original query in order to generate an event, removing any fields that might be causing an error:

```
\`sysmon\` CommandLine="net  view"
```

![[HTB Solutions/CDSA/z. images/ff328200c98557338c29cea3e6b9e85a_MD5.jpg]]

Subsequently, students need to inspect the field names, identifying that the error is due incorrect fields being referenced in the initial query:

`process` should be changed to `Image`

`Computer` should be changed to `ComputerName`

![[HTB Solutions/CDSA/z. images/07d66e309b01978ac70f1d0cb134c90e_MD5.jpg]]

Therefore, students need to correct the command accordingly:

```
\`sysmon\` Image="*net.exe" (CommandLine="net  view*") | stats count by ComputerName,CommandLine
```

![[HTB Solutions/CDSA/z. images/42816633e793c150687e577a121d7599_MD5.jpg]]

Adjusting for white spaces, the complete executed command is shown to be `net view /Domain:uniwaldo.local`.

Answer: `net view /Domain:uniwaldo.local`

# Using Splunk Applications

## Question 2

### "Access the Sysmon App for Splunk, go to the "Network Activity" tab, and choose "Network Connections". Fix the search and provide the number of connections that SharpHound.exe has initiated as your answer."

Students need to navigate to https://splunkbase.splunk.com/app/3544 and download the Sysmon App for Splunk:

![[HTB Solutions/CDSA/z. images/af878a709ed4add4c8089e193b75a0fb_MD5.jpg]]

Then, students need to then navigate to http://STMIP:8000 and select `manage apps`:

![[HTB Solutions/CDSA/z. images/cc2ca5a03baf7f7f6078aad18a845ce9_MD5.jpg]]

Subsequently, students need to select `Install app from file` :

![[HTB Solutions/CDSA/z. images/55ee118470be7ace5d24839fa5d5d242_MD5.jpg]]

And then browse for the newly downloaded `sysmom-app-for-splunk_200.gz` file:

![[HTB Solutions/CDSA/z. images/e96d2c1c16da1ca799e62fc00564285a_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/849c048cbb14747ed463c0168138302d_MD5.jpg]]

After clicking `upload`, students will be prompted to restart Splunk:

![[HTB Solutions/CDSA/z. images/a63b69e2143eceeba9a9ac2d6c269cd7_MD5.jpg]]

Giving the software a few moments, once the restart is complete, students need to adjust the application's macro so that events are loaded:

![[HTB Solutions/CDSA/z. images/6a3a79cbb59777dcfef963844a452a5b_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/5e59e8c87254168f7a57362bc301e8b2_MD5.jpg]]

Students need to select `Sysmon App for Splunk` as the app, and `sysmon` as the macro:

![[HTB Solutions/CDSA/z. images/dee76e55f6d5166f74a64b8d9122b461_MD5.jpg]]

Consequently, students need to adjust the Definition and Save:

```
index="main" sourcetype="WinEventLog:Sysmon"
```

![[HTB Solutions/CDSA/z. images/e42be2884eebb53a86cea50e5c38fc29_MD5.jpg]]

Now, students need to navigate to the Sysmon App for Splunk App:

![[HTB Solutions/CDSA/z. images/ada3aa7c3f9daf9ac2794d7fb498bf28_MD5.jpg]]

After accessing the app, students need to go to the "Network Activity" tab, and choose "Network Connections":

![[HTB Solutions/CDSA/z. images/809c8dde84e380654956bedbca888efa_MD5.jpg]]

Then, students need to Open in Search:

![[HTB Solutions/CDSA/z. images/58171b8497bab4810a0c3ac8d682544e_MD5.jpg]]

Adjusting the time range to `All time`, students will see there are still no results:

![[HTB Solutions/CDSA/z. images/de31b4621d8f3a09ad30b91a5d155686_MD5.jpg]]

Students need to use a simpler query to generate some events, then identify what fields exist in a typical event (Event ID 3):

```
\`sysmon\` EventCode=3 Image="*"
```

Exploring the events, students will see the errors are due to:

`dest_port` should be `DestinationPort`

`dest_ip` should be `DestinationIP`

`dest_host` should be `DestinationHostname`

![[HTB Solutions/CDSA/z. images/515cb4e3532a9024e3d0096b525f62a3_MD5.jpg]]

Therefore, the adjusted command becomes:

```
\`sysmon\` EventCode=3 Image="*" Protocol="*" DestinationPort="*" "*" | eval Destination=coalesce(DestinationHostname,DestinationIp) | stats count, values(Destination) AS "Destinations", values(DestinationPort) AS "Ports", values(Protocol) AS "Protocols" by Image | fields Image Destinations Ports Protocols count
```

After populating the results, students need to browse page `2` of the results:

![[HTB Solutions/CDSA/z. images/4ff19934f0a47263bdb0ca2ce8670da5_MD5.jpg]]

The query shows there have been `6` connections associated with Sharphound.exe.

Answer: `6`

# Intrusion Detection With Splunk (Real-world Scenario)

## Question 1

### "Navigate to http://\[Target IP\]:8000, open the "Search & Reporting" application, and find through an SPL search against all data the other process that dumped lsass. Enter its name as your answer. Answer format: \_.exe"

Students need to first navigate to http://STMIP:8000 and open the "Search & Reporting" application:

![[HTB Solutions/CDSA/z. images/6bd46970e7b190f0d661d2d883837d11_MD5.jpg]]

Next, students need to adjust the time period from `Last 24 hours` to `all time`:

![[HTB Solutions/CDSA/z. images/56b2b2073c67f514d39ef7278e91bc4a_MD5.jpg]]

Now, students need to enter a nSPL query to search Sysmon events in the "main" index with `EventCode 10` (ProcessAccess), where the TargetImage is `lsass.exe` and the CallTrace information contains `*UNKNOWN*` (which is indicative of shellcode execution):

```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=10 TargetImage="C:\\Windows\\system32\\lsass.exe" CallTrace="*UNKNOWN*" | stats count by SourceImage, CallTrace
```

![[HTB Solutions/CDSA/z. images/30cfced248159834c5c69c55ee05ec38_MD5.jpg]]

Students will see that `rundll32.exe` is the other process that dumped lsass.

Answer: `rundll32.exe`

# Intrusion Detection With Splunk (Real-world Scenario)

## Question 2

### "Navigate to http://\[Target IP\]:8000, open the "Search & Reporting" application, and find through SPL searches against all data the method through which the other process dumped lsass. Enter the misused DLL's name as your answer. Answer format: \_.dll"

Students need to first navigate to http://STMIP:8000 and open the "Search & Reporting" application:

![[HTB Solutions/CDSA/z. images/6bd46970e7b190f0d661d2d883837d11_MD5.jpg]]

Next, students need to adjust the time period from `Last 24 hours` to `all time`:

![[HTB Solutions/CDSA/z. images/56b2b2073c67f514d39ef7278e91bc4a_MD5.jpg]]

From the previous exercises, students should know that `rundll32.exe` was identified as the process that dumped lsass. Therefore, students need run a query searching for `EventCode 10` (ProcessAccess), specifically looking for events where the TargetImage is lsass.exe, the SourceImage contains "rundll32," and the CallTrace information is not UNKNOWN. This is to allow for individual analysis of affected .dll files during the event:

```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=10 TargetImage="C:\\Windows\\system32\\lsass.exe" SourceImage="*rundll32*" CallTrace!="*UNKNOWN*"
```

![[HTB Solutions/CDSA/z. images/a59567e6771924c28c415c225ccaeb88_MD5.jpg]]

![[HTB Solutions/CDSA/z. images/dad7e4b70f11456f558fbdcd0de2d238_MD5.jpg]]

Students will have to understand what the different shown dynamic link libraries (DLL) are used for. After conducting external [research](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz), students will identify that `comsvcs.dll` is the misused dynamic link library.

Answer: `comsvcs.dll`

# Intrusion Detection With Splunk (Real-world Scenario)

## Question 3

### "Navigate to http://\[Target IP\]:8000, open the "Search & Reporting" application, and find through an SPL search against all data any suspicious loads of clr.dll that could indicate a C# injection/execute-assembly attack. Then, again through SPL searches, find if any of the suspicious processes that were returned in the first place was used to temporarily execute code. Enter its name as your answer. Answer format: \_.exe"

Students need to first navigate to http://STMIP:8000 and open the "Search & Reporting" application:

![[HTB Solutions/CDSA/z. images/6bd46970e7b190f0d661d2d883837d11_MD5.jpg]]

Next, students need to adjust the time period from `Last 24 hours` to `all time`:

![[HTB Solutions/CDSA/z. images/56b2b2073c67f514d39ef7278e91bc4a_MD5.jpg]]

Now, students need to use a query that searches for events with `EventCode 7` containing term "clr.dll", then calculates the count of occurrences based on the "Image" field:

```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=7 clr.dll | stats count by Image
```

![[HTB Solutions/CDSA/z. images/4149954ae842773ebbd056934eb6c107_MD5.jpg]]

From here, students need to analyze events with `EventCode 1` (corresponding to a ProcessCreate event), sorting by count to find the images with the least amount of `clr.dll` loads (as processes with a large number of clr.dll loads would likely be considered normal behavior.)

```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 Image="*rundll32.exe*" | stats count by ParentImage
```

![[HTB Solutions/CDSA/z. images/b1495a17bef1316368f5b042f4e9178f_MD5.jpg]]

Students will find several "unusual" processes such `SharpHound.exe`, `randomfile.exe`, `rundll32.exe`, and `notepad.exe`. Subsequently, students need to identify the parents of the abovementioned processes one by one:

```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 Image="*rundll32.exe*" | stats count by ParentImage
```

![[HTB Solutions/CDSA/z. images/18b043c2f0c4d39eb3e2cf6e519a4945_MD5.jpg]]

Students should notice that among the parents of` rundll32.exe` are `randomfile.exe` and `PSEXECSCVCS.exe` (which most probably tries to blend in by misspelling the legitimate psexesvc.exe). This is a strong indication that `rundll32.exe` was used as a sacrificial process.

Answer: `rundll32.exe`

# Intrusion Detection With Splunk (Real-world Scenario)

## Question 4

### "Navigate to http://\[Target IP\]:8000, open the "Search & Reporting" application, and find through SPL searches against all data the two IP addresses of the C2 callback server. Answer format: 10.0.0.1XX and 10.0.0.XX"

Students need to first navigate to http://STMIP:8000 and open the "Search & Reporting" application:

![[HTB Solutions/CDSA/z. images/6bd46970e7b190f0d661d2d883837d11_MD5.jpg]]

Next, students need to adjust the time period from `Last 24 hours` to `all time`:

![[HTB Solutions/CDSA/z. images/56b2b2073c67f514d39ef7278e91bc4a_MD5.jpg]]

Now, students need to use a query that searches for events with an `EventCode of 3` (corresponding to network connections) and the file name "randomfile.exe" (which was previously identified being potentially malicious). Additionally, students need to calculates the count of occurrences for each unique Destination IP address associated with the events:

```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=3 randomfile.exe | stats count by DestinationIp <-- We focus on randomfile.exe and rundll32.exe 
```

![[HTB Solutions/CDSA/z. images/ad8f780e8b8e9c5c8c6ffdae20bab674_MD5.jpg]]

The logs show that that a network connection was established with `10.0.0.91`. Students need to repeat this query, testing it against the other potentially malicious files:

```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=3 rundll32.exe | stats count by DestinationIp
```

![[HTB Solutions/CDSA/z. images/f00bd635aa25608ec26afc4e09d562ad_MD5.jpg]]

After inspecting the network connections associated with `rundll32.exe`, students will find both IP addresses of the C2 : `10.0.0.186 and 10.0.0.91`.

Answer: `10.0.0.186 and 10.0.0.91`

# Intrusion Detection With Splunk (Real-world Scenario)

## Question 5

### "Navigate to http://\[Target IP\]:8000, open the "Search & Reporting" application, and find through SPL searches against all data the port that one of the two C2 callback server IPs used to connect to one of the compromised machines. Enter it as your answer."

Students need to first navigate to http://STMIP:8000 and open the "Search & Reporting" application:

![[HTB Solutions/CDSA/z. images/6bd46970e7b190f0d661d2d883837d11_MD5.jpg]]

Next, students need to adjust the time period from `Last 24 hours` to `all time`:

![[HTB Solutions/CDSA/z. images/56b2b2073c67f514d39ef7278e91bc4a_MD5.jpg]]

Now, students need to use an SPL query that searches for events with of `EventCode 3`, and the specific Source IP address of 10.0.0.186 (previously identified as a C2 endpoint). Additionally, students need to calculate the count of occurrences for each unique combination of Destination IP address and Destination Port associated with those events.

```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=3 SourceIp=10.0.0.186 | stats count by DestinationIp, DestinationPort
```

![[HTB Solutions/CDSA/z. images/6177492fbbc97f3da9a58ddfbfc767f6_MD5.jpg]]

Students will find that the C2 server was interacting with the compromised host, 10.0.0.47, on port `3389`.

Answer: `3389`

# \# Detecting Attacker Behavior With Splunk Based On TTPs

## Question 1

### "Navigate to http://\[Target IP\]:8000, open the "Search & Reporting" application, and find through SPL searches against all data the password utilized during the PsExec activity. Enter it as your answer."

Students need to first navigate to http://STMIP:8000 and open the "Search & Reporting" application:

![[HTB Solutions/CDSA/z. images/6bd46970e7b190f0d661d2d883837d11_MD5.jpg]]

Next, students need to adjust the time period from `Last 24 hours` to `all time`:

![[HTB Solutions/CDSA/z. images/56b2b2073c67f514d39ef7278e91bc4a_MD5.jpg]]

Then, students need to resume the investigation, using a query to search events while excluding any native API calls being done on the system. Additionally Students will have to exclude any native processes such as `Microsoft.NET` and `Explorer.exe` . Subsequently, students need to recognize that SourceImage is the parent process and the TargetImage is the child process:

```
index="main" CallTrace="*UNKNOWN*" SourceImage!="*Microsoft.NET*" CallTrace!=*ni.dll* CallTrace!=*clr.dll* CallTrace!=*wow64* SourceImage!="C:\\Windows\\Explorer.EXE" | where SourceImage!=TargetImage | stats count by SourceImage
```

![[HTB Solutions/CDSA/z. images/edd4e3676a73c1e56f77b38865c200fc_MD5.jpg]]

The `PSEXECSVCS.exe` stands out as unusual. Students need to use a query to search events in the "main" index with the sourcetype "WinEventLog:Sysmon", while filtering for events containing "psexecscvcs.exe" and then calculating the count of events by their EventCode:

```
index="main" sourcetype="WinEventLog:Sysmon" psexecscvcs.exe | stats count by EventCode
```

![[HTB Solutions/CDSA/z. images/a3fbd8475d93f7a1d35f79d583a3b888_MD5.jpg]]

Students will have to recall the meaning behind the event codes. Of particular interest is `EventCode 11` (which corresponds to FileCreate), allowing students to trace files back to the server that dropped it. Therefore, students need to use an additional query to provide a summary of the number of FileCreate events associated with the "psexecscvcs.exe" process, along with the corresponding file details and the host where these events were recorded:

```
index="main" sourcetype="WinEventLog:Sysmon" psexecscvcs.exe EventCode=11 | stats count by Image, TargetFilename, host
```

![[HTB Solutions/CDSA/z. images/6b17294a4a5403e1fda667200f648701_MD5.jpg]]

Students will note the host where the binary was dropped - `DESKTOP-UN7T4R8`. Therefore, students need to identify and count the number of different event codes tied to it. Students need to focus on `EventCode 1` (corresponding to process creation), and utilize a query for CommandLine arguments containing "*psexec*" :

```
index="main" sourcetype="WinEventLog:Sysmon" DESKTOP-UN7T4R8 CommandLine="*psexec*" EventCode=1 | stats count by CommandLine
```

![[HTB Solutions/CDSA/z. images/cbf6fa46b70122c3381f914e2c39e55c_MD5.jpg]]

Students will see the password `Password@123` was used during the execution of the `psexec64.exe` binary. Subsequently, to understand from where binary was ran, students need to append the host field to the query:

```
index="main" sourcetype="WinEventLog:Sysmon" DESKTOP-UN7T4R8 CommandLine="*psexec*" EventCode=1 | stats count by CommandLine, host
```

![[HTB Solutions/CDSA/z. images/f0351a40cead2bb49ce52b8f9d6e8860_MD5.jpg]]

Students will find that the host from which the command was ran is DESKTOP-EGSS5IS .

Answer: `Password@123`

# Detecting Attacker Behavior With Splunk Based On Analytics

## Question 1

### "Navigate to http://\[Target IP\]:8000, open the "Search & Reporting" application, and find through an analytics-driven SPL search against all data the source process images that are creating an unusually high number of threads in other processes. Enter the outlier process name as your answer where the number of injected threads is greater than two standard deviations above the average. Answer format: \_.exe"

Students need to first navigate to http://STMIP:8000 and open the "Search & Reporting" application:

![[HTB Solutions/CDSA/z. images/6bd46970e7b190f0d661d2d883837d11_MD5.jpg]]

Next, students need to adjust the time period from `Last 24 hours` to `all time`:

![[HTB Solutions/CDSA/z. images/56b2b2073c67f514d39ef7278e91bc4a_MD5.jpg]]

Students need to use an SPL query for Sysmon `EventCode 8` (CreateRemoteThread) that calculates the number of threads (renamed to numThreads) for each SourceImage, then calculates the average and standard deviation of numThreads. Additionally, it needs to identify outliers by comparing the numThreads value to the average, plus two times the standard deviation. Finally, the results need to be filtered to only show events where numThreads is considered an outlier (isOutlier=1):

```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=8 | stats count as numThreads by SourceImage | eventstats avg(numThreads) as avg stdev(numThreads) as stdev | eval isOutlier = if(numThreads > avg + (2*stdev), 1, 0) | where isOutlier=1
```

![[HTB Solutions/CDSA/z. images/5e76621635477a844abf670848ced2c6_MD5.jpg]]

The query reveals that `randomfile.exe` is the outlier process.

Answer: `randomfile.exe`

# Skills Assessment

# Question 1

### "Navigate to http://\[Target IP\]:8000, open the "Search & Reporting" application, and find through SPL searches against all data the process that created remote threads in rundll32.exe. Answer format: \_.exe"

Students need to first navigate to http://STMIP:8000 and open the "Search & Reporting" application:

![[HTB Solutions/CDSA/z. images/6bd46970e7b190f0d661d2d883837d11_MD5.jpg]]

Next, students need to adjust the time period from `Last 24 hours` to `all time`:

![[HTB Solutions/CDSA/z. images/56b2b2073c67f514d39ef7278e91bc4a_MD5.jpg]]

Now, students need to use a query, targeting Sysmon logs with `EventCode 8` (CreateRemoteThread), while calculating the count of the events and grouping them by the "SourceImage" and "TargetImage" fields:

```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=8 | stats count by SourceImage TargetImage
```

![[HTB Solutions/CDSA/z. images/ebbb35d132f2c7917716a53ffe1c712e_MD5.jpg]]

Students will find find that `randomfile.exe` created remote threads in rundll32.exe.

Answer: `randomfile.exe`

# Skills Assessment

## Question 2

### "Navigate to http://\[Target IP\]:8000, open the "Search & Reporting" application, and find through SPL searches against all data the process that started the infection. Answer format: \_.exe"

Students need to first navigate to http://STMIP:8000 and open the "Search & Reporting" application:

![[HTB Solutions/CDSA/z. images/6bd46970e7b190f0d661d2d883837d11_MD5.jpg]]

Next, students need to adjust the time period from `Last 24 hours` to `all time`:

![[HTB Solutions/CDSA/z. images/56b2b2073c67f514d39ef7278e91bc4a_MD5.jpg]]

To start the analysis, students need to identify all events that make use of either of the two C2 endpoints, `10.0.0.91 and 19.0.0.186`. Additionally, students need to reverse the order of the search results, so that the first result is the oldest:

```
index="main" sourcetype="WinEventLog:Sysmon" (DestinationIp=10.0.0.91 OR DestinationIp=10.0.0.186) | reverse
```

![[HTB Solutions/CDSA/z. images/5bddd6009af36755837b517e6ae7732d_MD5.jpg]]

Analyzing the first event, students will find reference to `demon.exe`. Consequently, students need to run an additional query look at all available event codes associated with this suspicious file:

```
index="main" sourcetype="WinEventLog:Sysmon" "demon.exe" | stats count by EventCode
```

![[HTB Solutions/CDSA/z. images/bb311b689099bddd5d8bd68dedfe57bd_MD5.jpg]]

Students will see there are numerous events types. Moving forward, there are two approaches students can take.

### Approach #1 : EventCode 11 (FileCreate)

For the first approach. students need to focus on `EventCode 11`, using another query to find all of the events that contain "demon.exe". Additionally, the query needs to be sorted so the first result is the oldest:

```
index="main" sourcetype="WinEventLog:Sysmon" "demon.exe" EventCode=11 | table Image, TargetFilename, _time | sort + _time
```

![[HTB Solutions/CDSA/z. images/ec27a1719d313bfbceacd0cde3a63660_MD5.jpg]]

These events only show that `demon.exe` was downloaded around `2022-10-015 13:39:40`, and did not directly create any other files. However, students need to consider that other files that may have been downloaded around this same time period.

Subsequently, students need to perform another search, filtering for SmartScreen (a software related to Microsoft Edge that is ran during file downloads):

```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=11 "*SmartScreen"| table Image, TargetFilename, _time | sort + _time
```

![[HTB Solutions/CDSA/z. images/b25324d195209cbe6ddacbe36993f6b9_MD5.jpg]]

Looking through the events, students will see multiple file downloads took place, between `2022-10-05 13:32:35` and `2022-10-05 13:38:21`. Thus, students need to search events again (still using EventCode11), and manually inspect the events within the aforementioned time frame. Of particular interest is the download that occurred at `2022-10-05 13:33:13`:

```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=11 earliest="10/05/2022:13:32:35" latest="10/05/2022:13:38:21" | table Image, TargetFilename, _time | sort + _time
```

![[HTB Solutions/CDSA/z. images/606965d6b263a854d5b1d7f5e3019f41_MD5.jpg]]

By narrowing down this "needle in a haystack" approach, students will ultimately discover the downloaded file `demon.dll` (as denoted by the Zone.Identifier). As another potential indicator of compromise, students need to perform a search against all Sysmon logs looking for occurrences of `demon.dll`:

```
index="main" sourcetype="WinEventLog:Sysmon" "*demon.dll*"
```

![[HTB Solutions/CDSA/z. images/ae9653b5032948dd0cb0641f4ed34dd1_MD5.jpg]]

Immediately, students will find evidence of EventCode 1 (ProcessCreation), with `rundll32.exe` being used against the `demon.dll`.

![[HTB Solutions/CDSA/z. images/e4c3f9a4eb1478bec8122a918650087c_MD5.jpg]]

Ultimately, students can determine that `rundll32.exe` is the process that started the initial infection, by way of injecting the `demon.dll` .

Answer: `rundll32.exe`

### Approach #2 : EventCode 1 (ProcessCreate)

Using the second approach, students need begin by targeting `EventCode 1`, using a query to create a table with the Image, CommandLine, ParentImage, ParentCommandLine, and *time* fields. Additionally, it should be sorted in ascending order by \_time:

```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | table Image, CommandLine, ParentImage, ParentCommandLine, _time | sort + _time
```

![[HTB Solutions/CDSA/z. images/bddd258939dae1db92269b733d07b873_MD5.jpg]]

While this produces a useful visualization of process creation events, it is still a large number of events to go through, and might prove difficult to find the first suspicious file. Therefore, students need to adjust the query , looking for any events containing "*demon*" and not "*demon.exe*". This is to look for potential stagers (DLL, VBS, HTA, etc.) called demon\* that may have been associated with the previously discovered demon.exe:

```
index="main" sourcetype="WinEventLog:Sysmon" ("*demon*" NOT "*demon.exe*") EventCode=1 | table Image, CommandLine, ParentImage, ParentCommandLine, _time | sort + _time <-- Search for occurrences of "demon"
```

![[HTB Solutions/CDSA/z. images/7ba6f5ef753f4398d405470267755039_MD5.jpg]]

Students will quickly discover evidence of `demon.dll` being loaded by `rundll32.exe` , confirming the initial infection.

Answer: `rundll32.exe`