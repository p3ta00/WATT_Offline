
```
Loaded Commands In Agent:

assembly_inject
	Usage: assembly_inject [pid] [assembly] [args]
	Description: Inject the unmanaged assembly loader into a remote process. The loader will then execute the .NET binary in the context of the injected process.
blockdlls
	Usage: blockdlls [on|off]
	Description: Block non-Microsoft DLLs from loading into sacrificial processes.
cat
	Usage: cat [file]
	Description: Print the contents of a file specified by [file]
cd
	Usage: cd [path]
	Description: Change directory to [path]. Path relative identifiers such as ../ are accepted.
cp
	Usage: cp [source] [dest]
	Description: Copy a file from one location to another.
dcsync
	Usage: dcsync -Domain [domain] -User [user]
	Description: Sync a user's Kerberos keys to the local machine.
download
	Usage: download -Path [path/to/file] [-Host [hostname]]
	Description: Download a file off the target system.
execute_assembly
	Usage: execute_assembly [Assembly.exe] [args]
	Description: Executes a .NET assembly with the specified arguments. This assembly must first be known by the agent using the `register_assembly` command.
execute_pe
	Usage: execute_pe [PE.exe] [args]
	Description: Executes a .NET assembly with the specified arguments. This assembly must first be known by the agent using the `register_assembly` command.
exit
	Usage: exit
	Description: Task the implant to exit.
get_injection_techniques
	Usage: get_injection_techniques
	Description: List the currently available injection techniques the agent knows about.
getprivs
	Usage: getprivs
	Description: Enable as many privileges as we can on our current thread token.
ifconfig
	Usage: ifconfig
	Description: Get interface information associated with the target.
inject
	Usage: inject (modal popup)
	Description: Inject agent shellcode into a remote process.
inline_assembly
	Usage: inline_assembly [Assembly.exe] [args]
	Description: Executes a .NET assembly with the specified arguments in a disposable AppDomain. This assembly must first be known by the agent using the `register_assembly` command.
jobkill
	Usage: jobkill [jid]
	Description: Kill a job specified by the job identifier (jid).
jobs
	Usage: jobs
	Description: List currently executing jobs, excluding the "jobs" and "jobkill" commands.
keylog_inject
	Usage: keylog_inject [pid]
	Description: Start a keylogger in a remote process.
kill
	Usage: kill [pid]
	Description: Kill a process specified by [pid]
link
	Usage: link
	Description: Link to a new agent on a remote host or re-link back to a specified callback that's been unlinked via the `unlink` commmand.
load
	Usage: load [cmd1] [cmd2] [...]
	Description: Load one or more new commands into the agent.
ls
	Usage: ls [path]
	Description: List files and folders in a specified directory (defaults to your current working directory.)
make_token
	Usage: make_token (modal popup)
	Description: Creates a new logon session and applies it to the agent. Modal popup for options. Credentials must be populated in the credential store.
mimikatz
	Usage: mimikatz [command1] [command2] [...]
	Description: Execute one or more mimikatz commands (e.g. `mimikatz coffee sekurlsa::logonpasswords`).
mkdir
	Usage: mkdir [path]
	Description: Make a directory specified by [path]
mv
	Usage: mv [source] [dest]
	Description: Move a file from source to destination.
net_dclist
	Usage: net_dclist [domain]
	Description: Get domain controllers belonging to [domain]. Defaults to current domain.
net_localgroup
	Usage: net_localgroup [computer]
	Description: Get local groups of [computer]. Defaults to localhost.
net_localgroup_member
	Usage: net_localgroup_member [computer] [group]
	Description: Retrieve local group membership of the group specified by [group]. If [computer] is omitted, defaults to localhost.
net_shares
	Usage: net_shares [computer]
	Description: List remote shares and their accessibility of [computer]
netstat
	Usage: netstat
	Description: View netstat entries
powerpick
	Usage: powerpick [command]
	Description: Inject PowerShell loader assembly into a sacrificial process and execute [command].
powershell
	Usage: powershell [command]
	Description: Run a PowerShell command in the currently executing process.
powershell_import
	Usage: powershell_import (modal popup)
	Description: Import a new .ps1 into the agent cache.
ppid
	Usage: ppid [pid]
	Description: Change the parent process for post-ex jobs by the specified pid.
printspoofer
	Usage: printspoofer [args]
	Description: Execute one or more PrintSpoofer commands
ps
	Usage: ps
	Description: Get a brief process listing with basic information.
psinject
	Usage: psinject [pid] [command]
	Description: Executes PowerShell in the process specified by `[pid]`. Note: Currently stdout is not captured of child processes if not explicitly captured into a variable or via inline execution (such as `$(whoami)`).
pth
	Usage: pth -Domain [domain] -User [user] -NTLM [ntlm] [-AES128 [aes128] -AES256 [aes256] -Run [cmd.exe]]
	Description: Spawn a new process using the specified domain user's credential material.
pwd
	Usage: pwd
	Description: Print working directory.
reg_query
	Usage: reg_query [key]
	Description: Query registry keys and values for an associated registry key [key].
reg_write_value
	Usage: reg_write_value [key] [value_name] [new_value]
	Description: Write a new value to the [value_name] value under the specified registry key [key].

Ex: reg_write_value HKLM:\ '' 1234
register_assembly
	Usage: register_assembly (modal popup)
	Description: Import a new Assembly into the agent cache.
register_file
	Usage: register_assembly (modal popup)
	Description: Register a file to later use in the agent.
rev2self
	Usage: rev2self
	Description: Revert token to implant's primary token.
rm
	Usage: rm [path]
	Description: Delete a file specified by [path]
run
	Usage: run [binary] [arguments]
	Description: Execute a binary on the target system. This will properly use %PATH% without needing to specify full locations.
sc
	Usage: sc
	Description: Service control manager wrapper function
screenshot
	Usage: screenshot
	Description: Take a screenshot of the current desktop.
screenshot_inject
	Usage: screenshot_inject [pid] [count] [interval]
	Description: Take a screenshot in the session of the target PID
set_injection_technique
	Usage: set_injection_technique [technique]
	Description: Set the injection technique used in post-ex jobs that require injection. Must be a technique listed in the output of `list_injection_techniques`.
shell
	Usage: shell [command] [arguments]
	Description: Run a shell command which will translate to a process being spawned with command line: `cmd.exe /C [command]`
shinject
	Usage: shinject (modal popup)
	Description: Inject shellcode into a remote process.
sleep
	Usage: sleep [seconds] [jitter]
	Description: Change the implant's sleep interval.
socks
	Usage: socks [port number]
	Description: Enable SOCKS 5 compliant proxy to send data to the target network. Compatible with proxychains and proxychains4.
spawn
	Usage: spawn (modal popup)
	Description: Spawn a new session in the executable specified by the spawnto_x86 or spawnto_x64 commands. The payload template must be shellcode.
spawnto_x64
	Usage: spawnto_x64 [path] [args]
	Description: Change the default binary used in post exploitation jobs to [path]. If [args] provided, the process is launched with those arguments.
spawnto_x86
	Usage: spawnto_x86 [path]
	Description: Change the default binary used in post exploitation jobs to [path]. If [args] provided, the process is launched with those arguments.
steal_token
	Usage: steal_token [pid]
	Description: Steal a primary token from another process. If no arguments are provided, this will default to winlogon.exe.
unlink
	Usage: unlink (modal popup)
	Description: Unlinks a callback from the agent.
upload
	Usage: upload (modal popup)
	Description: Upload a file from the Mythic server to the remote host.
whoami
	Usage: whoami
	Description: Get the username associated with your current thread token.
```