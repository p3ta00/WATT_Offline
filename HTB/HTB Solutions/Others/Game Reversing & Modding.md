
| Section                 | Question Number | Answer                                                   |
| ----------------------- | --------------- | -------------------------------------------------------- |
| Scripting AoB           | Question 1      | 7urn5\_0u7\_4rr4y5\_4r3\_p0w3rful                        |
| Creating a Mod          | Question 1      | HTB{M0ds\_4r3\_C00l}                                     |
| Building a Runtime Hook | Question 1      | HTB{h00k5\_4r3\_C00l3r}                                  |
| MITM Game Hacking       | Question 1      | HTB{N3twork\_T4mp3r1ng}                                  |
| Skills Assessment       | Question 1      | HTB{I\_w15h\_c0mp4n135\_w0uld\_m4k3\_g00d\_g4m35\_4g41n} |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Scripting AoB

## Question 1

### "What is the text that gets displayed when you set your lives to over 5 within the new game timer?"

To begin, students need to launch Hackman and attach it to Cheat Engine. Then, students need to perform a `First Scan` with a value of `3`, matching the number of lives Hackman currently has:

![[HTB Solutions/Others/z. images/b39372d730ac7c7e5a6f59022b528334_MD5.jpg]]

Next, students need to lose a life, then perform a `Next Scan` with a value of `2`. Students need to perform this process iteratively, performing scans to match the current life value. Once the correct address for the lives counter has been found, students need to add it to their `Cheat Table`:

![[HTB Solutions/Others/z. images/21a76146a74a4ba07675321b6a56db68_MD5.jpg]]

Subsequently, students need to set the value to `10`, then proceed to lose another life:

![[HTB Solutions/Others/z. images/5f33248ea500de7e43a27e7fa561be8b_MD5.jpg]]

Students will see the lives counter jump to `9`. Confirming the lives counter has been hacked, students need to right click in their `Cheat Table` and `Find out what writes to this address`. Then, they need to lose another life, and once the instruction appears, select `Show Disassembler`:

![[HTB Solutions/Others/z. images/35bcaf948e3daf8208ae6b14317add74_MD5.jpg]]

Now, to automate a script for hacking the lives counter, students need to go to `Tools` -> `Auto Assemble`:

![[HTB Solutions/Others/z. images/9d61b1f1ed0ae74410ccd6bc5dae7517_MD5.jpg]]

Students need to select `Template` -> `AoB Injection`, press Ok to choose the defaults:

![[HTB Solutions/Others/z. images/2d871eb61bb502766a67035b2b808323_MD5.jpg]]

To adjust the script, students need to add the `mov eax,9` instruction under `newmem`, while copy and pasting the first two instructions from the `code` section into the `INJECT` section:

![[HTB Solutions/Others/z. images/85b72cbdc111164ae26b0c1f19130d3a_MD5.jpg]]

Once the changes have been made, students need to go to `File` -> `Assign to current cheat table`, adding the script to the cheat table. Subsequently, students need to close Hackman.

Finally, students need to launch a new instance of Hackman, attaching it to Cheat Engine and enabling the script. After quickly being eaten, students will see the flag pop on screen:

![[HTB Solutions/Others/z. images/619570b01a2bc512d8790f69918c56c5_MD5.jpg]]

Answer: `7urn5_0u7_4rr4y5_4r3_p0w3rful`

# Creating a Mod

## Question 1

### "What is the text hiding behind the purple block?"

Students need to open dnSpy, then select `File` -> `Open`, navigating to the `Assembly-CSharp.dll` file for the `Modman` game:

![[HTB Solutions/Others/z. images/458fead66ebe4be09a9fd4e28adbf115_MD5.jpg]]

Subsequently, students need to drill into the root namespace, selecting the `jb` method found within the `Modman` class:

![[HTB Solutions/Others/z. images/c8f09e9696f3c14d3f08cabc33a414cb_MD5.jpg]]

Students need to right click within the method and select the `Edit Method (C#)...` option. This will open the code editor: To apply the modification, students need to change the `this.cll.enabled` line to `false` while commenting out one of the attribute tags:

![[HTB Solutions/Others/z. images/3b9215448deca50796abd507a8714696_MD5.jpg]]

Students need to select `File` -> `Save Module...`. to save the changes. Then, students need to run Modman, where the purple block will be removed and the flag visible:

![[HTB Solutions/Others/z. images/0c35ea53441ebfebcbd36852c2bd29a2_MD5.jpg]]

Answer: `HTB{M0ds_4r3_C00l}`

# Building a Runtime Hook

## Question 1

### "What is the text hiding behind the purple block?"

Students need to copy all of the files for `BepInEx` into the `Hookman` directory:

![[HTB Solutions/Others/z. images/86228ddb83584fff4e8a790a6f961cee_MD5.jpg]]

Then, students need to use powershell to create a folder named `Mod` inside the `Hookman` directory. Subsequently, a new `classlib` needs to be made:

Code: powershell

```powershell
mkdir mod
cd mod
dotnet new classlib
dotnet new sln -n Mod
dotnet sln Mod.sln add .\mod.csproj
```

```
PS C:\Users\htb-student\Desktop\Hookman> mkdir mod

    Directory: C:\Users\htb-student\Desktop\Hookman

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         9/11/2023  10:39 AM                mod

PS C:\Users\htb-student\Desktop\Hookman> cd mod

PS C:\Users\htb-student\Desktop\Hookman\mod> dotnet new classlib

The template "Class Library" was created successfully.

Processing post-creation actions...
Restoring C:\Users\htb-student\Desktop\Hookman\mod\mod.csproj:
  Determining projects to restore...
  Restored C:\Users\htb-student\Desktop\Hookman\mod\mod.csproj (in 70 ms).
Restore succeeded.

PS C:\Users\htb-student\Desktop\Hookman\mod> dotnet new sln -n Mod

The template "Solution File" was created successfully.

PS C:\Users\htb-student\Desktop\Hookman\mod> dotnet sln Mod.sln add .\mod.csproj

Project \`mod.csproj\` added to the solution.
```

Students need to edit the `Mod.csproj` to reference the required BepInEx libraries from the parent directory:

```xml
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <TargetFramework>netstandard2.1</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <LangVersion>latest</LangVersion>
  </PropertyGroup>
  <!-- reference all libraries in the libs folder -->
  <ItemGroup>
    <Reference Include="$(MSBuildProjectDirectory)\..\BepInEx\core\*.dll" />
    <Reference Include="$(MSBuildProjectDirectory)\..\Hookman_Data\Managed\Assembly-CSharp.dll" />
    <Reference Include="$(MSBuildProjectDirectory)\..\Hookman_Data\Managed\Unity.*.dll" />
    <Reference Include="$(MSBuildProjectDirectory)\..\Hookman_Data\Managed\UnityEngine.dll" />
    <Reference Include="$(MSBuildProjectDirectory)\..\Hookman_Data\Managed\UnityEngine.*.dll" />

  </ItemGroup>
  <Target Name="CopyDll" AfterTargets="Build">
    <Copy SourceFiles="$(OutputPath)\Mod.dll"
      DestinationFolder="$(MSBuildProjectDirectory)\..\BepInEx\plugins" />
  </Target>
</Project>
```

Now, to configure the mod, students need to edit the `Class1.cs` file with the following code:

```csharp
using BepInEx;
using BepInEx.Unity.Mono;

namespace GameMod;
// defined under the namespace, as to override System.Object with UnityEngine.Object
using UnityEngine;
using UnityEngine.SceneManagement;

// defines BepInEx plugin info
[BepInPlugin("GH", "GameMod", "1.0.0")]
public class GameMod : BaseUnityPlugin
{
    private static KeyCode _toggleKey = KeyCode.T;

    private GameObject? _block;

    public void Start()
    {
        GetSceneNames();
    }

    public void Update()
    {
        // if the toggle key is not pressed, return
        if (!Input.GetKeyDown(_toggleKey)) return;
        // toggle the active state of the ChallengeBlock in the scene
        _block?.SetActive(!_block.activeInHierarchy);
    }

    /// <summary>
    /// Recursively prints the name of a GameObject and its children with an increasing depth of indentation.
    /// </summary>
    /// <param name="gObject">The GameObject to print.</param>
    /// <param name="depth">The current depth of the GameObject in the hierarchy.</param>
    void PrintGameObjectAndChildren(GameObject gObject, int depth)
    {
        string indent = new string('-', depth);
        Debug.Log(indent + "Object: " + gObject.name);
        foreach (Transform child in gObject.transform)
        {
            PrintGameObjectAndChildren(child.gameObject, depth + 1);
        }
    }

    /// <summary>
    /// Gets the names of all scenes in the build settings and logs them using the Logger class.
    /// </summary>
    public void GetSceneNames()
    {
        List<string> sceneNames = new List<string>();
        for (int i = 0; i < SceneManager.sceneCountInBuildSettings; i++)
        {
            string scenePath = SceneUtility.GetScenePathByBuildIndex(i);
            string sceneName = Path.GetFileNameWithoutExtension(scenePath);
            sceneNames.Add(sceneName);
        }
        Logger.LogInfo("Scenes in build settings: " + string.Join(", ", sceneNames.ToArray()));
    }

    /// <summary>
    /// Called when the script instance is being loaded.
    /// </summary>
    private void OnEnable()
    {
        // Register the event listener when the script is enabled
        SceneManager.sceneLoaded += OnSceneLoaded;
    }

    /// <summary>
    /// Called when the MonoBehaviour is disabled.
    /// </summary>
    private void OnDisable()
    {
        // Unregister the event listener when the script is disabled
        SceneManager.sceneLoaded -= OnSceneLoaded;
    }

    /// <summary>
    /// This method is called every time a new scene is loaded.
    /// </summary>
    /// <param name="scene">The scene that was loaded.</param>
    /// <param name="mode">The mode in which the scene was loaded.</param>
    private void OnSceneLoaded(Scene scene, LoadSceneMode mode)
    {
        // This code will run every time a new scene is loaded
        Logger.LogInfo("Scene loaded: " + scene.name);
        // Call any other functions you want to run when the scene changes
        // loop through every game object in the scene
        foreach (var gObject in scene.GetRootGameObjects())
        {
            // print the name of the game object and all of its children, starting at depth 0
            PrintGameObjectAndChildren(gObject, 0);
        }
	// check that the current scene is Level_1
        if (scene.name == "Level_1")
        {
            // find the ChallengeBlock in the scene
            _block = GameObject.Find("ChallengeBlock");
            if (_block != null)
            {
                // if the ChallengeBlock was found, log its position
                Logger.LogInfo("=== HOOKED CHALLENGEBLOCK ===");
            }
            else
            {
                // if the ChallengeBlock was not found, log an error
                Logger.LogError("=== FAILED TO HOOK CHALLENGEBLOCK ===");
            }
        }
    }
}
```

Using powershell, students need to build the class library:

```powershell
dotnet build
```
```
PS C:\Users\htb-student\Desktop\Hookman\mod> dotnet build

MSBuild version 17.7.1+971bf70db for .NET
  Determining projects to restore...
  Restored C:\Users\htb-student\Desktop\Hookman\mod\mod.csproj (in 115 ms).
  mod -> C:\Users\htb-student\Desktop\Hookman\mod\bin\Debug\netstandard2.1\mod.dll

Build succeeded.
    0 Warning(s)
    0 Error(s)

Time Elapsed 00:00:05.71
```

Finally, students need to launch `Hookman` and press `T` to reveal the flag:

![[HTB Solutions/Others/z. images/52dbe9b102cd5472a29351cbbb7b50be_MD5.jpg]]

Answer: `HTB{h00k5_4r3_C00l3r}`

# MITM Game Hacking

## Question 1

### "What is the value of the flag from the getscore endpoint, after you successfully set the score to a value greater than 1'000'000?"

Students need to first edit the `config.json` file for the `Netman` game so that it directs traffic to Burpsuite:

```json
{
  "baseUrl": "http://localhost:5001"
}
```

Then, students need to launch Burpsuite and navigate to `Proxy` -> `Settings`, then click `Edit` on the proxy shown in the `Proxy listeners` section:

![[HTB Solutions/Others/z. images/7ce36c1c2aeb905f08bbab6c944c5df9_MD5.jpg]]

Students need to set the bind port to `5001` , while selecting `all interfaces` as the bind address:

![[HTB Solutions/Others/z. images/303ed4090feaf93d48a1ed5adb2acd75_MD5.jpg]]

Additionally, students need to go to `Request handling` and enter the IP and port number of the spawned target:

![[HTB Solutions/Others/z. images/2a6659b03492b2a90d077b919bb8fbd8_MD5.jpg]]

Pressing `OK` to save the changes, students need to now launch Netman and collect some cubes. Then, students need to go back to Burpsuite and navigate to `Target` -> `Sitemap`:

![[HTB Solutions/Others/z. images/47b8bbfa454ebba014571db1fb77d477_MD5.jpg]]

Students need to examine the POST requests being sent to the `/scoreboard/score/1337` endpoint, and then send one of the requests to `Repeater`:

![[HTB Solutions/Others/z. images/8bd8f1330b2e80fdca92fec0c1e4f424_MD5.jpg]]

Subsequently, students need to edit the value of score in the POST request, setting it to a value greater than `1000000` before sending the request:

![[HTB Solutions/Others/z. images/08448c856cf7711c54376e1d8869ae06_MD5.jpg]]

Now, students need to go back to `Target` -> `Sitemap`, selecting the request to the `getflag` endpoint and sending it to `Repeater`:

![[HTB Solutions/Others/z. images/41bf0cf26e595da109e1eb467ac4949b_MD5.jpg]]

After sending the request, the flag will be revealed:

![[HTB Solutions/Others/z. images/ae19da7a01379566360dd424b5e5c140_MD5.jpg]]

Answer: `HTB{N3twork_T4mp3r1ng}`

# Skills Assessment

## Question 1

### "After you have fixed the game, and modified the score to a value greater than 1'000'000, what is the flag returned via the getflag endpoint?"

Students need to use dnSpy to open the `Assembly-CSharp.dll` file located inside `Fixman\Fixman_Data\Managed`:

![[HTB Solutions/Others/z. images/fb27db60ffef91b20663d9397dfa5442_MD5.jpg]]

Next, students need to examine the `Start` method found within the `MenuManager` class:

![[HTB Solutions/Others/z. images/28033fd9f5b0b2c9e75cb4f5aacb58c2_MD5.jpg]]

Subsequently, students need to right click and select `Edit Method (C#)`. Then, from the Edit Code screen, students need to comment out one of the attributes while setting `this.CheckStart` to `false`:

![[HTB Solutions/Others/z. images/691c13f2823b993201377ef7077ca555_MD5.jpg]]

Students need to select `File` -> `Save Module`, then close out of dnSpy.

Moving to the Man-in-the-Middle component of the assessent, students need to edit the `config.json` file for Fixman, having it point to the Burp proxy:

```xml
{
  "baseUrl": "http://localhost:5001"
}
```

Then, students need to launch Burpsuite and navigate to `Proxy` -> `Settings`, then click `Edit` on the proxy shown in the `Proxy listeners` section:

![[HTB Solutions/Others/z. images/7ce36c1c2aeb905f08bbab6c944c5df9_MD5.jpg]]

Students need to set the bind port to `5001` , while selecting `all interfaces` as the bind address:

![[HTB Solutions/Others/z. images/303ed4090feaf93d48a1ed5adb2acd75_MD5.jpg]]

Additionally, students need to go to `Request handling` and enter the IP and port number of the spawned target:

![[HTB Solutions/Others/z. images/45346cd9c37c105c154828b600e2637f_MD5.jpg]]

Confirming the changes, students need to press `OK` and then launch the Fixman game. Once the connection to the server has been established, students need to eat some cubes and then check Burpsuite:

![[HTB Solutions/Others/z. images/adab2d802a19f3b930a44173befe15a1_MD5.jpg]]

![[HTB Solutions/Others/z. images/8ca781ec7e787e3fbd34e28a824542ce_MD5.jpg]]

Students need to examine the POST requests being sent to the `/scoreboard/score/1337` endpoint, and then send one of the requests to `Repeater`:

![[HTB Solutions/Others/z. images/f9c38d7b2e34f8a5ff47176961285a27_MD5.jpg]]

Subsequently, students need to edit the value of score in the POST request, setting it to a value greater than `1000000` before sending the request:

![[HTB Solutions/Others/z. images/280c494614537e1c707212f9da0f4557_MD5.jpg]]

Now, students need to go back to `Target` -> `Sitemap`, selecting the request to the `getflag` endpoint and sending it to `Repeater`:

![[HTB Solutions/Others/z. images/9a9395351dd48a8c9e0844c2f9475781_MD5.jpg]]

After sending the request, the flag will be revealed:

![[HTB Solutions/Others/z. images/01c247e3c2b172084f2843c6e344ae51_MD5.jpg]]

Answer: `HTB{I_w15h_c0mp4n135_w0uld_m4k3_g00d_g4m35_4g41n}`