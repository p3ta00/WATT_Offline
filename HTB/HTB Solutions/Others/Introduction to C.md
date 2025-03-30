
| Section                                            | Question Number | Answer                                                                                                      |
| -------------------------------------------------- | --------------- | ----------------------------------------------------------------------------------------------------------- |
| Understanding Variables, Constants, and Data Types | Question 1      | byte aByte = 255;                                                                                           |
| Understanding Variables, Constants, and Data Types | Question 2      | int? itemsCount = null;                                                                                     |
| Operators and Type Conversion                      | Question 1      | int remainder = 10 % 3;                                                                                     |
| Operators and Type Conversion                      | Question 2      | count++;                                                                                                    |
| Namespaces                                         | Question 1      | using System.Collections.Generic;                                                                           |
| Control Statements and Loops                       | Question 1      | 0123456789                                                                                                  |
| Control Statements and Loops                       | Question 2      | abcdefghijklm                                                                                               |
| Arrays                                             | Question 1      | grid\[2,1\];                                                                                                |
| Strings                                            | Question 1      | 15                                                                                                          |
| Strings                                            | Question 2      | The quick brown fox jumps over the lazy dog and then writes Academy modules...Weird right? Strange times... |
| Methods and Exception Handling                     | Question 1      | IndexOutOfRangeException: Index was outside the bounds of the array.                                        |
| Libraries                                          | Question 1      | HTB{L1br4ry\_FL4g}                                                                                          |
| Skills Assessment                                  | Question 1      | HTB{CSh4rp\_Pr0gr4mm1ng}                                                                                    |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Understanding Variables, Constants, and Data Types

## Question 1

### "Declare a byte variable `aByte` and assign it the maximum value that a byte can hold."

Students need to refer to the `Data Types` chart shown in the section:

![[HTB Solutions/Others/z. images/5ba76a06718c36b47c42dd039fce715c_MD5.jpg]]

Based off the provided examples, students will determine the correct way to declare the variable is `byte aByte = 255;`.

Answer: `byte aByte = 255;`

# Understanding Variables, Constants, and Data Types

## Question 2

### "How would you declare a nullable integer named `itemsCount` and assign it the `null` value?"

Students need to refer to the information regarding `Nullable Types` shown in the section:

![[HTB Solutions/Others/z. images/da2a6bfd565cc06345cc57413647920e_MD5.jpg]]

Subsequently, students will determine that the way to declare the nullable integer is `int? nullableInt = null;`

Answer: `int? nullableInt = null;`

# Operators and Type Conversion

## Question 1

### "Write a piece of code that performs and assigns the modulus of 10 divided by 3 to an integer named `remainder`."

Students need to refer to the information regarding `Arithmetic Operators` shown in the section:

![[HTB Solutions/Others/z. images/a5895e9f750e3442b996912d6c67d500_MD5.jpg]]

Consequently, students will determine that the correct code to write is `int remainder = 10 % 3;`.

Answer: `int remainder = 10 % 3;`

# Operators and Type Conversion

## Question 2

### "How would you increment the value of an integer variable `count` using a unary operator?"

Students need to refer to what is shown in the section regarding `Unary Operators`:

![[HTB Solutions/Others/z. images/54958d4e9d3cc14ee397cca97e01e420_MD5.jpg]]

Based off this information, students will determine that the way to increment the integer variable with a unary operator is `count++;`.

Answer: `count++;`

# Namespaces

## Question 1

### "How would you import the `System.Collections.Generic` namespace in a C# program?"

Students need to examine the examples provided in the section's reading:

![[HTB Solutions/Others/z. images/8808f3b78d98bedb9425fa4f9db2adeb_MD5.jpg]]

Subsequently, students will know that the correct way to import the namespace is `using System.Collections.Generic;`.

Answer: `using System.Collections.Generic;`

# Control Statements and Loops

# Question 1

### "Paste the output of the first ten numbers generated by the code in the attached file."

Students need to first create a new console application and open it with Visual Studio Code:

Code: shell

```shell
mkdir csharp; cd csharp
dotnet new console
code .
```

```
┌─[eu-academy-1]─[10.10.14.185]─[htb-ac-594497@htb-7wzgzllv6i]─[~]
└──╼ [★]$ mkdir csharp; cd csharp

┌─[eu-academy-1]─[10.10.14.185]─[htb-ac-594497@htb-7wzgzllv6i]─[~/csharp]
└──╼ [★]$ dotnet new console

Welcome to .NET 6.0!
---------------------
SDK Version: 6.0.408

Telemetry
---------
The .NET tools collect usage data in order to help us improve your experience. It is collected by Microsoft and shared with the community. You can opt-out of telemetry by setting the DOTNET_CLI_TELEMETRY_OPTOUT environment variable to '1' or 'true' using your favorite shell.

Read more about .NET CLI Tools telemetry: https://aka.ms/dotnet-cli-telemetry

----------------
Installed an ASP.NET Core HTTPS development certificate.
To trust the certificate run 'dotnet dev-certs https --trust' (Windows and macOS only).
Learn about HTTPS: https://aka.ms/dotnet-https
----------------
Write your first app: https://aka.ms/dotnet-hello-world
Find out what's new: https://aka.ms/dotnet-whats-new
Explore documentation: https://aka.ms/dotnet-docs
Report issues and find source on GitHub: https://github.com/dotnet/core
Use 'dotnet --help' to see available commands or visit: https://aka.ms/dotnet-cli
--------------------------------------------------------------------------------------
The template "Console App" was created successfully.

Processing post-creation actions...
Running 'dotnet restore' on /home/htb-ac-594497/csharp/csharp.csproj...
  Determining projects to restore...
  Restored /home/htb-ac-594497/csharp/csharp.csproj (in 81 ms).
Restore succeeded.

┌─[eu-academy-1]─[10.10.14.185]─[htb-ac-594497@htb-7wzgzllv6i]─[~/csharp]
└──╼ [★]$ code .
```

Upon the launch of Visual Studio Code, students need to select `Yes, I trust the authors` and proceed to enable the `Auto-Save` feature:

![[HTB Solutions/Others/z. images/811b91dfa356cd1266cf9f244475562d_MD5.jpg]]

![[HTB Solutions/Others/z. images/4d3d53936eb39ba8daa25f6cb44763c4_MD5.jpg]]

Now, students need to copy and paste the code from `Control-Question-1.md` into the `Program.cs` file:

Code: csharp

```csharp
for (int i = 0; i < 100; i++)
{
    Console.Write(i);
}
```

![[HTB Solutions/Others/z. images/fcd81f73159521c39afbd5517a1bc9ad_MD5.jpg]]

Finally, from the terminal, students need to run the console application:

Code: shell

```shell
dotnet run
```

```
┌─[eu-academy-1]─[10.10.14.185]─[htb-ac-594497@htb-7wzgzllv6i]─[~/csharp]
└──╼ [★]$ dotnet run

0123456789101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899
```

Answer: `0123456789`

# Control Statements and Loops

## Question 2

### "Fix, and then paste output of the code in the attached file"

Students need to copy and paste the code from `Control-Question` into their `Program.cs` file:

Code: csharp

```csharp
for (char c = 'a'; c <= 'z'; c++)
{
    if (c == '\u006E')
    {
        // stop the loop
    }
    Console.Write(c);
}
```

Then, based off the section's reading, students will see that they need to add the `break` statement to stop the loop:

![[HTB Solutions/Others/z. images/7d19f6231358eee8145ab6d1cb330f62_MD5.jpg]]

Students need to make the necessary adjustment to the code:

Code: csharp

```csharp
for (char c = 'a'; c <= 'z'; c++)
{
    if (c == '\u006E')
    {
        break; // stop the loop
    }
    Console.Write(c);
}
```

Running the code, students will find the final output:

Code: shell

```shell
dotnet run
```

```
┌─[eu-academy-1]─[10.10.14.185]─[htb-ac-594497@htb-x0jtqsbe0p]─[~/csharp]
└──╼ [★]$ dotnet run

abcdefghijklm
```

Answer: `abcdefghijklm`

# Arrays

## Question 1

### "How can you access the element in the third row and second column of a two-dimensional array named grid in C#?"

Students need to refer to the section's reading in regards to accessing arrays:

![[HTB Solutions/Others/z. images/899b03f7fcab09f8c1c40aba904097ef_MD5.jpg]]

Therefore, students will know that the third row and second column would be accessed by `grid[2,1];`.

Answer: `grid[2,1];`

# Strings

## Question 1

### "Download the attached file, what is the output when you run the code?"

Students need to first create a new console application and open it with Visual Studio Code:

Code: shell

```shell
mkdir csharp; cd csharp
dotnet new console
code .
```

```
┌─[eu-academy-1]─[10.10.14.185]─[htb-ac-594497@htb-7wzgzllv6i]─[~]
└──╼ [★]$ mkdir csharp; cd csharp

┌─[eu-academy-1]─[10.10.14.185]─[htb-ac-594497@htb-7wzgzllv6i]─[~/csharp]
└──╼ [★]$ dotnet new console

Welcome to .NET 6.0!
---------------------
SDK Version: 6.0.408

Telemetry
---------
The .NET tools collect usage data in order to help us improve your experience. It is collected by Microsoft and shared with the community. You can opt-out of telemetry by setting the DOTNET_CLI_TELEMETRY_OPTOUT environment variable to '1' or 'true' using your favorite shell.

Read more about .NET CLI Tools telemetry: https://aka.ms/dotnet-cli-telemetry

----------------
Installed an ASP.NET Core HTTPS development certificate.
To trust the certificate run 'dotnet dev-certs https --trust' (Windows and macOS only).
Learn about HTTPS: https://aka.ms/dotnet-https
----------------
Write your first app: https://aka.ms/dotnet-hello-world
Find out what's new: https://aka.ms/dotnet-whats-new
Explore documentation: https://aka.ms/dotnet-docs
Report issues and find source on GitHub: https://github.com/dotnet/core
Use 'dotnet --help' to see available commands or visit: https://aka.ms/dotnet-cli
--------------------------------------------------------------------------------------
The template "Console App" was created successfully.

Processing post-creation actions...
Running 'dotnet restore' on /home/htb-ac-594497/csharp/csharp.csproj...
  Determining projects to restore...
  Restored /home/htb-ac-594497/csharp/csharp.csproj (in 81 ms).
Restore succeeded.

┌─[eu-academy-1]─[10.10.14.185]─[htb-ac-594497@htb-7wzgzllv6i]─[~/csharp]
└──╼ [★]$ code .
```

Upon the launch of Visual Studio Code, students need to select `Yes, I trust the authors` and proceed to enable the `Auto-Save` feature:

![[HTB Solutions/Others/z. images/811b91dfa356cd1266cf9f244475562d_MD5.jpg]]

![[HTB Solutions/Others/z. images/4d3d53936eb39ba8daa25f6cb44763c4_MD5.jpg]]

Now, students need to copy and paste the code from `Strings-Question-1.md` into the `Program.cs` file:

Code: csharp

```csharp
string message = "The quick brown fox jumps over the lazy dog and then writes Academy modules...Weird right?";
string[] words = message.Split(' ');
Console.WriteLine(words.Length);
```

![[HTB Solutions/Others/z. images/2da57a37d9705c3fff722825650256c0_MD5.jpg]]

Students need to then run the application from the terminal:

Code: shell

```shell
dotnet run
```

```
┌─[eu-academy-1]─[10.10.14.185]─[htb-ac-594497@htb-x0jtqsbe0p]─[~/csharp]
└──╼ [★]$ dotnet run

15
```

Answer: `15`

# Strings

## Question 2

### "Download the attached file, what is the reversed output of the string?"

Students need to copy and paste the code from `Strings-Question-1.md` into the `Program.cs` file:

Code: csharp

```csharp
string message = "The quick brown fox jumps over the lazy dog and then writes Academy modules...Weird right?";
string[] words = message.Split(' ');
Console.WriteLine(words.Length);
```

Then, students need to modify the code so it reverses the `charArray` array and prints it to the console:

Code: csharp

```csharp
string message = "...semit egnartS ?thgir drieW...seludom ymedacA setirw neht dna god yzal eht revo spmuj xof nworb kciuq ehT";
char[] charArray = message.ToCharArray();
Array.Reverse(charArray);
Console.WriteLine(new string(charArray));
```

Consequently, students need to run the application to find the reversed output:

Code: shell

```shell
dotnet run
```

```
┌─[eu-academy-1]─[10.10.14.185]─[htb-ac-594497@htb-x0jtqsbe0p]─[~/csharp]
└──╼ [★]$ dotnet run

The quick brown fox jumps over the lazy dog and then writes Academy modules...Weird right? Strange times...
```

Answer: `The quick brown fox jumps over the lazy dog and then writes Academy modules...Weird right? Strange times...`

# Methods and Exception Handling

## Question 1

### "Copy and paste the exception output from the attached code"

Students need to first create a new console application and open it with Visual Studio Code:

Code: shell

```shell
mkdir csharp; cd csharp
dotnet new console
code .
```

```
┌─[eu-academy-1]─[10.10.14.185]─[htb-ac-594497@htb-7wzgzllv6i]─[~]
└──╼ [★]$ mkdir csharp; cd csharp

┌─[eu-academy-1]─[10.10.14.185]─[htb-ac-594497@htb-7wzgzllv6i]─[~/csharp]
└──╼ [★]$ dotnet new console

Welcome to .NET 6.0!
---------------------
SDK Version: 6.0.408

Telemetry
---------
The .NET tools collect usage data in order to help us improve your experience. It is collected by Microsoft and shared with the community. You can opt-out of telemetry by setting the DOTNET_CLI_TELEMETRY_OPTOUT environment variable to '1' or 'true' using your favorite shell.

Read more about .NET CLI Tools telemetry: https://aka.ms/dotnet-cli-telemetry

----------------
Installed an ASP.NET Core HTTPS development certificate.
To trust the certificate run 'dotnet dev-certs https --trust' (Windows and macOS only).
Learn about HTTPS: https://aka.ms/dotnet-https
----------------
Write your first app: https://aka.ms/dotnet-hello-world
Find out what's new: https://aka.ms/dotnet-whats-new
Explore documentation: https://aka.ms/dotnet-docs
Report issues and find source on GitHub: https://github.com/dotnet/core
Use 'dotnet --help' to see available commands or visit: https://aka.ms/dotnet-cli
--------------------------------------------------------------------------------------
The template "Console App" was created successfully.

Processing post-creation actions...
Running 'dotnet restore' on /home/htb-ac-594497/csharp/csharp.csproj...
  Determining projects to restore...
  Restored /home/htb-ac-594497/csharp/csharp.csproj (in 81 ms).
Restore succeeded.

┌─[eu-academy-1]─[10.10.14.185]─[htb-ac-594497@htb-7wzgzllv6i]─[~/csharp]
└──╼ [★]$ code .
```

Then, students need to copy and paste the code from `Method-Question-1.md` into their `Program.cs` file:

Code: csharp

```csharp
try
{
    int[] arr = new int[8];
    arr[11] = 69;
}
catch (IndexOutOfRangeException ex)
{
    // Handle specific exception first
    Console.WriteLine("IndexOutOfRangeException: " + ex.Message);
}
```

Saving the changes to the `Program.cs` file, student need to then run the application from the terminal:

Code: shell

```shell
dotnet run
```

```
┌─[eu-academy-1]─[10.10.14.185]─[htb-ac-594497@htb-x0jtqsbe0p]─[~/csharp]
└──╼ [★]$ dotnet run

IndexOutOfRangeException: Index was outside the bounds of the array.
```

Answer: `IndexOutOfRangeException: Index was outside the bounds of the array.`

# Libraries

## Question 1

### "Import the Library-Question library appropriate for your OS and dotNet version, using the HTBLibrary namespace. What is the output of the `Flag.GetFlag()` method from the library?"

Students need to install download and install [VSCode for 64-bit Debian](https://code.visualstudio.com/docs/?dv=linux64_deb):

Code: shell

```shell
sudo dpkg -i code_1.80.1-1689183569_amd64.deb
```

```
┌─[eu-academy-1]─[10.10.14.185]─[htb-ac-594497@htb-x0jtqsbe0p]─[~]
└──╼ [★]$ sudo dpkg -i code_1.80.1-1689183569_amd64.deb

Selecting previously unselected package code.
(Reading database ... 505940 files and directories currently installed.)
Preparing to unpack code_1.80.1-1689183569_amd64.deb ...
Unpacking code (1.80.1-1689183569) ...
Setting up code (1.80.1-1689183569) ...
Processing triggers for desktop-file-utils (0.26-1) ...
Processing triggers for bamfdaemon (0.5.4-2) ...
Rebuilding /usr/share/applications/bamf-2.index...
Processing triggers for mailcap (3.69) ...
Processing triggers for shared-mime-info (2.0-1) ...
```

Next, students need to extract the contents of the attached `Library-Question.zip` file:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/228/Library-Question.zip
unzip Library-Question.zip
```

```
┌─[eu-academy-1]─[10.10.14.185]─[htb-ac-594497@htb-x0jtqsbe0p]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/228/Library-Question.zip

--2023-07-22 00:24:04--  https://academy.hackthebox.com/storage/modules/228/Library-Question.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 26845 (26K) [application/zip]
Saving to: ‘Library-Question.zip’

Library-Question.zip                            100%[=====================================================================================================>]  26.22K  --.-KB/s    in 0s      

2023-07-22 00:24:04 (183 MB/s) - ‘Library-Question.zip’ saved [26845/26845]

┌─[eu-academy-1]─[10.10.14.185]─[htb-ac-594497@htb-x0jtqsbe0p]─[~]
└──╼ [★]$ unzip Library-Question.zip 

Archive:  Library-Question.zip
   creating: net6.0/linux-x64/
  inflating: net6.0/linux-x64/Library-Question.deps.json  
  inflating: net6.0/linux-x64/Library-Question.dll  
   creating: net6.0/linux-x86/
  inflating: net6.0/linux-x86/Library-Question.deps.json  
  inflating: net6.0/linux-x86/Library-Question.dll  
   creating: net6.0/osx-x64/
  inflating: net6.0/osx-x64/Library-Question.deps.json  
  inflating: net6.0/osx-x64/Library-Question.dll  
   creating: net6.0/win-x64/
  inflating: net6.0/win-x64/Library-Question.deps.json  
  inflating: net6.0/win-x64/Library-Question.dll  
   creating: net6.0/win-x86/
  inflating: net6.0/win-x86/Library-Question.deps.json  
  inflating: net6.0/win-x86/Library-Question.dll  
   creating: net7.0/linux-x64/
  inflating: net7.0/linux-x64/Library-Question.deps.json  
  inflating: net7.0/linux-x64/Library-Question.dll  
   creating: net7.0/linux-x86/
  inflating: net7.0/linux-x86/Library-Question.deps.json  
  inflating: net7.0/linux-x86/Library-Question.dll  
   creating: net7.0/osx-x64/
  inflating: net7.0/osx-x64/Library-Question.deps.json  
  inflating: net7.0/osx-x64/Library-Question.dll  
   creating: net7.0/win-x64/
  inflating: net7.0/win-x64/Library-Question.deps.json  
  inflating: net7.0/win-x64/Library-Question.dll  
   creating: net7.0/win-x86/
  inflating: net7.0/win-x86/Library-Question.deps.json  
  inflating: net7.0/win-x86/Library-Question.dll  
```

Students need to create a new directory for their project, along with a sub-directory `libs` containing the appropriate DLL file. Consequently, students need to also make a new console app and open it with VSCode:

Code: shell

```shell
mkdir csharp; cd csharp
mkdir libs
cp ~/net6.0/linux-x64/Library-Question.dll libs/
dotnet new console
code .
```

```
┌─[eu-academy-1]─[10.10.14.185]─[htb-ac-594497@htb-7wzgzllv6i]─[~]
└──╼ [★]$ mkdir csharp; cd csharp

┌─[eu-academy-1]─[10.10.14.185]─[htb-ac-594497@htb-x0jtqsbe0p]─[~/csharp]
└──╼ [★]$ mkdir libs

┌─[eu-academy-1]─[10.10.14.185]─[htb-ac-594497@htb-x0jtqsbe0p]─[~/csharp]
└──╼ [★]$ cp ~/net6.0/linux-x64/Library-Question.dll libs/

┌─[eu-academy-1]─[10.10.14.185]─[htb-ac-594497@htb-7wzgzllv6i]─[~/csharp]
└──╼ [★]$ dotnet new console

Welcome to .NET 6.0!
---------------------
SDK Version: 6.0.408

Telemetry
---------
The .NET tools collect usage data in order to help us improve your experience. It is collected by Microsoft and shared with the community. You can opt-out of telemetry by setting the DOTNET_CLI_TELEMETRY_OPTOUT environment variable to '1' or 'true' using your favorite shell.

Read more about .NET CLI Tools telemetry: https://aka.ms/dotnet-cli-telemetry

----------------
Installed an ASP.NET Core HTTPS development certificate.
To trust the certificate run 'dotnet dev-certs https --trust' (Windows and macOS only).
Learn about HTTPS: https://aka.ms/dotnet-https
----------------
Write your first app: https://aka.ms/dotnet-hello-world
Find out what's new: https://aka.ms/dotnet-whats-new
Explore documentation: https://aka.ms/dotnet-docs
Report issues and find source on GitHub: https://github.com/dotnet/core
Use 'dotnet --help' to see available commands or visit: https://aka.ms/dotnet-cli
--------------------------------------------------------------------------------------
The template "Console App" was created successfully.

Processing post-creation actions...
Running 'dotnet restore' on /home/htb-ac-594497/csharp/csharp.csproj...
  Determining projects to restore...
  Restored /home/htb-ac-594497/csharp/csharp.csproj (in 81 ms).
Restore succeeded.

┌─[eu-academy-1]─[10.10.14.185]─[htb-ac-594497@htb-x0jtqsbe0p]─[~/csharp]
└──╼ [★]$ code .
```

When prompted, students need to choose `Yes, I trust the authors` and enable Auto-Save under `File`:

![[HTB Solutions/Others/z. images/a72d7ec73abe139722530a172a41ecd5_MD5.jpg]]

Then, students need to select `Extensions` and install the `Base Language Support for C#` extension:

![[HTB Solutions/Others/z. images/95477e674a16fac6d344633c6a7dfa94_MD5.jpg]]

Subsequently, students need to add a reference for DLL's in the `libs` directory to their `csharp.csproj` file:

```xml
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net6.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>
  <ItemGroup>
    <Reference Include="libs\*.dll" /> 
  </ItemGroup>
</Project>
```

To generate the flag, students need to import the `HTBLibrary` namespace and assign the result of `Flag.GetFlag` to a string , which is then printed to the console. Therefore, students need to write the following code into their `Program.cs` file:

```csharp
using HTBLibrary;

string flag = Flag.GetFlag();
Console.WriteLine(flag);
```

At last, students need to run the program:

```shell
dotnet run
```
```
┌─[eu-academy-1]─[10.10.14.185]─[htb-ac-594497@htb-x0jtqsbe0p]─[~/csharp]
└──╼ [★]$ dotnet run

/usr/share/dotnet/sdk/6.0.408/Microsoft.Common.CurrentVersion.targets(2302,5): warning MSB3270: There was a mismatch between the processor architecture of the project being built "MSIL" and the processor architecture of the reference "libs/Library-Question.dll", "AMD64". This mismatch may cause runtime failures. Please consider changing the targeted processor architecture of your project through the Configuration Manager so as to align the processor architectures between your project and references, or take a dependency on references with a processor architecture that matches the targeted processor architecture of your project. [/home/htb-ac-594497/csharp/csharp.csproj]

HTB{L1br4ry_FL4g}
```

Answer: `HTB{L1br4ry_FL4g}`

# Skills Assessment

## Question 1

### "What is the content of the `flag.txt` file found in the subdirectory you scanned for?"

After downloading and extracting the contents of the attached `Assessment.zip` file, students need to create a new `Console` application and then open it in `VS Code`.

```shell
wget https://academy.hackthebox.com/storage/modules/228/Assessment.zip
unzip Assessment.zip
```
```
┌─[eu-academy-1]─[10.10.14.57]─[htb-ac-594497@htb-hgh4xnefks]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/228/Assessment.zip

--2023-07-26 02:18:03--  https://academy.hackthebox.com/storage/modules/228/Assessment.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.21.126, 104.18.20.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.21.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 162585 (159K) [application/zip]
Saving to: ‘Assessment.zip’

Assessment.zip                                  100%[=====================================================================================================>] 158.77K  --.-KB/s    in 0.004s  

2023-07-26 02:18:03 (44.2 MB/s) - ‘Assessment.zip’ saved [162585/162585]

┌─[eu-academy-1]─[10.10.14.57]─[htb-ac-594497@htb-hgh4xnefks]─[~]
└──╼ [★]$ unzip Assessment.zip 

Archive:  Assessment.zip
   creating: net6.0/linux-x64/
  inflating: net6.0/linux-x64/Assessment.deps.json  
  inflating: net6.0/linux-x64/Assessment.dll  
   creating: net6.0/linux-x86/
  inflating: net6.0/linux-x86/Assessment.deps.json  
  inflating: net6.0/linux-x86/Assessment.dll  
   creating: net6.0/osx-x64/
  inflating: net6.0/osx-x64/Assessment.deps.json  
  inflating: net6.0/osx-x64/Assessment.dll  
   creating: net6.0/win-x64/
  inflating: net6.0/win-x64/Assessment.deps.json  
  inflating: net6.0/win-x64/Assessment.dll  
   creating: net6.0/win-x86/
  inflating: net6.0/win-x86/Assessment.deps.json  
  inflating: net6.0/win-x86/Assessment.dll  
   creating: net7.0/linux-x64/
  inflating: net7.0/linux-x64/Assessment.deps.json  
  inflating: net7.0/linux-x64/Assessment.dll  
   creating: net7.0/linux-x86/
  inflating: net7.0/linux-x86/Assessment.deps.json  
  inflating: net7.0/linux-x86/Assessment.dll  
   creating: net7.0/osx-x64/
  inflating: net7.0/osx-x64/Assessment.deps.json  
  inflating: net7.0/osx-x64/Assessment.dll  
   creating: net7.0/win-x64/
  inflating: net7.0/win-x64/Assessment.deps.json  
  inflating: net7.0/win-x64/Assessment.dll  
   creating: net7.0/win-x86/
  inflating: net7.0/win-x86/Assessment.deps.json  
  inflating: net7.0/win-x86/Assessment.dll  
```

Next, students need to create a directory for the project, along with a sub-directory `libs` containing the assessment DLL file. Once complete, students need to open the project with VSCode:

```shell
mkdir csharp; cd csharp
mkdir libs
cp ~/net6.0/linux-x64/Assessment.dll libs/
dotnet new console
code .
```
```
┌─[eu-academy-1]─[10.10.14.185]─[htb-ac-594497@htb-7wzgzllv6i]─[~]
└──╼ [★]$ mkdir csharp; cd csharp

┌─[eu-academy-1]─[10.10.14.185]─[htb-ac-594497@htb-x0jtqsbe0p]─[~/csharp]
└──╼ [★]$ mkdir libs

┌─[eu-academy-1]─[10.10.14.185]─[htb-ac-594497@htb-x0jtqsbe0p]─[~/csharp]
└──╼ [★]$ cp ~/net6.0/linux-x64/Assessment.dll libs/

┌─[eu-academy-1]─[10.10.14.185]─[htb-ac-594497@htb-7wzgzllv6i]─[~/csharp]
└──╼ [★]$ dotnet new console

Welcome to .NET 6.0!
---------------------
SDK Version: 6.0.408

Telemetry
---------
The .NET tools collect usage data in order to help us improve your experience. It is collected by Microsoft and shared with the community. You can opt-out of telemetry by setting the DOTNET_CLI_TELEMETRY_OPTOUT environment variable to '1' or 'true' using your favorite shell.

Read more about .NET CLI Tools telemetry: https://aka.ms/dotnet-cli-telemetry

----------------
Installed an ASP.NET Core HTTPS development certificate.
To trust the certificate run 'dotnet dev-certs https --trust' (Windows and macOS only).
Learn about HTTPS: https://aka.ms/dotnet-https
----------------
Write your first app: https://aka.ms/dotnet-hello-world
Find out what's new: https://aka.ms/dotnet-whats-new
Explore documentation: https://aka.ms/dotnet-docs
Report issues and find source on GitHub: https://github.com/dotnet/core
Use 'dotnet --help' to see available commands or visit: https://aka.ms/dotnet-cli
--------------------------------------------------------------------------------------
The template "Console App" was created successfully.

Processing post-creation actions...
Running 'dotnet restore' on /home/htb-ac-594497/csharp/csharp.csproj...
  Determining projects to restore...
  Restored /home/htb-ac-594497/csharp/csharp.csproj (in 81 ms).
Restore succeeded.

┌─[eu-academy-1]─[10.10.14.185]─[htb-ac-594497@htb-x0jtqsbe0p]─[~/csharp]
└──╼ [★]$ code .
```

When prompted, students need to choose `Yes, I trust the authors` and then enable Auto-Save under `File`:

![[HTB Solutions/Others/z. images/a72d7ec73abe139722530a172a41ecd5_MD5.jpg]]

Additionally, students need to select `Extensions` and install the `Base Language Support for C#` extension.

![[HTB Solutions/Others/z. images/95477e674a16fac6d344633c6a7dfa94_MD5.jpg]]

Now, students need to add a reference to the `libs` directory on their `csharp.csproj` file:

```xml
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net6.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>
  <ItemGroup>
    <Reference Include="libs\*.dll" /> 
  </ItemGroup>
</Project>
```

Onto the actual code, students need to first declare the namespaces inside their `Program.cs` file. To complete the assessment task, students need to use `System`, `System.Net.Http`, and `Assessment`:

```csharp
using System;
using System.Net.Http;
using Assessment;
```

Students will need to utilize `asynchronous programming`, as the program will be making web requests and awaiting the response. Therefore, inside the `Program` class, students need first set the `Main` method as asynchronous. Secondly, students need to define a separate asynchronous method `GetWebsiteContentAsync` for executing web requests and returning the response:

```csharp
using System;
using System.Net.Http;
using Assessment;

class Program
{
    static async Task Main(string[] args)
    {

    }

    static async Task<HttpResponseMessage> GetWebsiteContentAsync(string url)
    {
        using (HttpClient client = new HttpClient())
        {
            HttpResponseMessage response = await client.GetAsync(url);
            return response;
        }
    }
}
```

- The method `GetWebsiteContentAsync` is defined with a return type of `Task<HttpResponseMessage>`, indicating that it is an asynchronous method that will return an `HttpResponseMessage` when completed.
- It takes a `string` parameter named `url`, representing the URL of the website from which we want to fetch content.
- Inside the method, a new instance of `HttpClient` is created using the `using` statement. This class is provided by the `System.Net.Http` namespace.
- With `HttpClient`, the method calls the `GetAsync` method passing the `url` as a parameter. This performs an asynchronous HTTP GET request to the specified URL.
- The `await` keyword is used before the `client.GetAsync` method call. This indicates that the method should wait asynchronously for the response to complete before proceeding further.
- The result of the `GetAsync` call, which is an `HttpResponseMessage`, is stored in the `response` variable.
- The method returns the `response` variable, which contains the HTTP response from the server.

Also, as mentioned in the lab scenario, students will need use the `GetWordList` method from the `Words` class in order to access the word list.

```csharp
Words assessmentWords = new Words();
var wordList = assessmentWords.GetWordList();
```

Therefore, within the Main method, students need to iterate through this wordlist and make a web request to the target machine for each word (as each word is a possible directory containing the flag.txt). Also, upon a successful request, it needs to print out the flag along with the directory in which it was found:

```csharp
using System;
using System.Net.Http;
using Assessment;

class Program
{
    static async Task Main(string[] args)
    {
        Words assessmentWords = new Words();
        var wordList = assessmentWords.GetWordList();

        foreach (string word in wordList)
        {
            try
            {
                HttpResponseMessage response = await GetWebsiteContentAsync($"http://10.129.205.211/{word}/flag.txt");

                if (response.IsSuccessStatusCode)
                {
                    string responseBody = await response.Content.ReadAsStringAsync();
                    Console.WriteLine("The flag has been discovered in the " + word + " directory, and it reads:");
                    Console.WriteLine("\n" + responseBody);
                }
            }
            catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                continue;
            }
        }
    }

    static async Task<HttpResponseMessage> GetWebsiteContentAsync(string url)
    {
        using (HttpClient client = new HttpClient())
        {
            HttpResponseMessage response = await client.GetAsync(url);
            return response;
        }
    }
}
```

- The program iterates through each word in the `wordList` using a `foreach` loop.
- Within the loop, the program tries to fetch the content of a specific URL constructed using the current `word` by way of the`GetWebsiteContentAsync` method.
- The `GetWebsiteContentAsync` method fetches the content of the given URL using the `HttpClient` class and returns the `HttpResponseMessage` containing the server's response.
- Back to the Main method, the program awaits the response from `GetWebsiteContentAsync` using the `await` keyword.
- Once the response is obtained, the program checks whether the response was successful (status code 200) using the `IsSuccessStatusCode` property of the `HttpResponseMessage`.
- If the response was successful, the program reads the response content using `ReadAsStringAsync()` and stores it in the `responseBody` variable.
- The program then displays a message indicating that the flag has been discovered in the specific `word` directory, and prints the contents of the flag.
- If the HTTP request returns a "Not Found" status code (404), the program catches the `HttpRequestException`, and the `continue` statement is used to skip to the next iteration of the loop, trying the next `word` from the `wordList`.
- The loop continues until all words in the `wordList` have been tested.

Running the program, students will find the flag exists in the `htbhacks` directory, along with the contents of the flag:

```
┌─[eu-academy-1]─[10.10.14.57]─[htb-ac-594497@htb-hgh4xnefks]─[~/csharp]
└──╼ [★]$ dotnet run

/usr/share/dotnet/sdk/6.0.408/Microsoft.Common.CurrentVersion.targets(2302,5): warning MSB3270: There was a mismatch between the processor architecture of the project being built "MSIL" and the processor architecture of the reference "libs/Assessment.dll", "AMD64". This mismatch may cause runtime failures. Please consider changing the targeted processor architecture of your project through the Configuration Manager so as to align the processor architectures between your project and references, or take a dependency on references with a processor architecture that matches the targeted processor architecture of your project. [/home/htb-ac-594497/csharp/csharp.csproj]

The flag has been discovered in the htbhacks directory, and it reads:

HTB{CSh4rp_Pr0gr4mm1ng}
```

Answer: `HTB{CSh4rp_Pr0gr4mm1ng}`