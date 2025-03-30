
| Section                              | Question Number | Answer         |
| ------------------------------------ | --------------- | -------------- |
| Scanning and Modifying Memory        | Question 1      | n3v32\_d13     |
| Scanning and Modifying Memory        | Question 2      | 90d1y          |
| Identify and Dissect Data Structures | Question 1      | h19h\_5c023    |
| Identify and Dissect Data Structures | Question 2      | 57ruC7UR3      |
| Skills Assessment                    | Question 1      | Ch41L3n93\_90d |
| Skills Assessment                    | Question 2      | n1Nj4\_V4Lu32  |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Scanning and Modifying Memory

## Question 1

### "What is the text that is displayed in-game when the Lives counter holds a value greater than 3?"

Students need to launch both Cheat Engine and Hackman, ensuring that both programs are running on the virtual machine:

![[HTB Solutions/Others/z. images/bd9a63773cd503755c397eac1a2669cd_MD5.jpg]]

From Cheat Engine, students need to select File -> Open Process, choosing Hackman from the list of applications:

![[HTB Solutions/Others/z. images/1c41572c27a354eec6679ce882efe74d_MD5.jpg]]

Additionally, students need to go into Settings -> Hotkeys, choosing the `~` key as the shortcut to pause the selected process:

![[HTB Solutions/Others/z. images/56b9bb29e55645b28ea5e24dc5afbfa7_MD5.jpg]]

Once the game begins, students need to pause using the `~` key, then in Cheat Engine, and then perform the First Scan with a value of `3` (to match the current number of lives):

![[HTB Solutions/Others/z. images/65116ff73b2762705d76da9df1f28656_MD5.jpg]]

![[HTB Solutions/Others/z. images/79fbd12b93a3462c4472ee692d1f48f5_MD5.jpg]]

Next, students need to resume the game, allowing the monsters to eat Hackman and lose a life (resulting in two lives remaining.)

![[HTB Solutions/Others/z. images/88e9affe09ca7dd2a4a1a55612695557_MD5.jpg]]

Back to Cheat Engine, students need to perform a Next Scan with a value of `2`. Students will observe the number of found addresses will reduce further:

![[HTB Solutions/Others/z. images/feca22275d68eca364e909f5fe873bbb_MD5.jpg]]

Resuming the game, students need to lose another life, resulting in a single life remaining. Then, students need to perform Next Scan in Cheat Engine with a value of `1`:

![[HTB Solutions/Others/z. images/afa3194b93fb4e0a939324314d924dc3_MD5.jpg]]

Narrowing down the found addresses even further, students need to play Hackman and collect an orange cube, which provides Hackman with an additional life:

![[HTB Solutions/Others/z. images/480f3005a8e62f2603d0002749af3630_MD5.jpg]]

Students need to perform one final Next Scan, choosing a value of `2`. This will result in a single address found, and students need to add it to the address list:

![[HTB Solutions/Others/z. images/d43488d5cac35382bfc5ec9c85da0ab2_MD5.jpg]]

Having successfully discovered the memory location of the Lives counter, students need to set the Value to `10` , then resume the game and lose a life:

![[HTB Solutions/Others/z. images/469d3122ec98285a4cabe0f9ee9da714_MD5.jpg]]

![[HTB Solutions/Others/z. images/65d045d96a3641afc13e857d573544a0_MD5.jpg]]

After hacking the lives counter, the flag `n3v32_d13` will be displayed on the screen.

Answer: `n3v32_d13`

# Scanning and Modifying Memory

## Question 2

### "Using the same memory searching techniques, what is the text that is displayed when you successfully modify the round counter and set it to a value over 9??"

Students need to perform a new First scan, selecting a value of `1` (to match the current round number):

![[HTB Solutions/Others/z. images/3af9b725184053581f700abb3bdeced6_MD5.jpg]]

Playing the game, students need to collect all the cubes to progress to the next round:

![[HTB Solutions/Others/z. images/e137bc285724b39ccbb70e69bc3ff86b_MD5.jpg]]

When round 2 begins, students need to pause the game and run a Next Scan with a value of `2`:

![[HTB Solutions/Others/z. images/e8ec94f2fa6f949f4291ff263f7ed6a0_MD5.jpg]]

Reducing the number of found addresses, students need to resume the game and continue playing to round three. Then, students need to perform an additional Next Scan with a value of `3`:

![[HTB Solutions/Others/z. images/3e2618902004b30d9a333d7e822268c9_MD5.jpg]]

Repeating this process, students need to progress through the game and perform a scan for each round:

![[HTB Solutions/Others/z. images/cdabc6a28347810051f9bc955fe67f18_MD5.jpg]]

![[HTB Solutions/Others/z. images/8a9332a7e72faa5892c829588844717d_MD5.jpg]]

With only a handful of remaining addresses, students need to add them to the Cheat Table, and set the values in increments of `10`:

![[HTB Solutions/Others/z. images/b59a36bfa5145c98b0b0e5bef999e40b_MD5.jpg]]

When students resume the game, the flag will be shown on the screen:

![[HTB Solutions/Others/z. images/078b1cb27fb02e1a58c82f42c606dbe9_MD5.jpg]]

The flag is revealed to be `90d1y`.

Answer: `90d1y`

# Identify and Dissect Data Structures

## Question 1

### "What is the text displayed in-game when you successfully modify the score value over 100'000'000?"

Students are recommended to begin a new game (if continuing from the previous section) as modifications to the game's memory can create instability and cause crashes.

Thus, students need to repeat the steps from the `Scanning and Modifying Memory` section, once again discovering the address of the Lives counter:

![[HTB Solutions/Others/z. images/a7ecef8cbe06ae8e9b270d4cf6952e76_MD5.jpg]]

Then, students need to right-click the record in the Cheat Table -> Browse this Memory Region:

![[HTB Solutions/Others/z. images/c452b8bec906d00feab763cf513205fc_MD5.jpg]]

Looking at the Memory Viewer, students need to identify the start of the data structure by looking at the hex values, seeing where the padding begins and ends:

![[HTB Solutions/Others/z. images/46a428bd7b8265942c1289f54b890ab6_MD5.jpg]]

Students need to right-click -> Open in dissect data/structure:

![[HTB Solutions/Others/z. images/bf236b24410bd6ed79ddcff026d5d1d5_MD5.jpg]]

Selecting Structures -> Define new structure, and leaving the Structure Name as `unnamed structure`:

![[HTB Solutions/Others/z. images/dd27b1f4003c96045e3d4d5f9448f3b8_MD5.jpg]]

![[HTB Solutions/Others/z. images/4db9511c48ce1cec900c909182f8543a_MD5.jpg]]

Now, students need to resume the game and collect cubes, analyzing which addresses/values change to coincide with the number of in-game points:

![[HTB Solutions/Others/z. images/e3b11655792ff0c13ce530c5737fe688_MD5.jpg]]

Students need to adjust the top two score values, setting the first value to a number over `100000000`, and the second value to the same number (minus two digits):

![[HTB Solutions/Others/z. images/d522553f1399f883d4882e4a63c11da1_MD5.jpg]]

![[HTB Solutions/Others/z. images/f5b9c3275527c826f9a1d45c39fea27d_MD5.jpg]]

Subsequently, students need to resume the game and collect some points:

![[HTB Solutions/Others/z. images/b363913b93b73f477cf4ff6b6c33d77d_MD5.jpg]]

The flag is revealed to be `h19h_5c023`.

Answer: `h19h_5c023`

# Identify and Dissect Data Structures

## Question 2

### "There is another value that can be located via the structure dissector, that if modified to a value over 200'000'000 will display text in-game, what is that text?"

Using the previously created Game Structure, students need to modify the Value of the two locations controlling the in-game score:

![[HTB Solutions/Others/z. images/0ab526a93f990f5704306e64b92fb6f6_MD5.jpg]]

Therefore, students need to set the first value to `20000000000` and the second value to `200000000`, then resume the game to collect some points:

![[HTB Solutions/Others/z. images/f851abd5158fc40b61b1f71501e3cb07_MD5.jpg]]

The flag is revealed to be `57ruC7UR3`.

Answer: `57ruC7UR3`

# Skills Assessment

## Question 1

### "What flag is displayed when you successfully modify the Lives counter to a value greater than 5?"

Students need to launch both Cheat Engine and the Hackman Assessment, ensuring that both programs are running on the virtual machine:

![[HTB Solutions/Others/z. images/d4b0cbfbf4cc348bc4f10543595fbf72_MD5.jpg]]

From Cheat Engine, students need to select File -> Open Process, choosing Hackman Assessment from the list of applications:

![[HTB Solutions/Others/z. images/8f3ef0e2a4c3a10e0befa16c9ad8afe0_MD5.jpg]]

Then, students need to start the game and perform a First Scan in Cheat Engine with a value of `3`:

![[HTB Solutions/Others/z. images/3e3075c7965253299c46d2598d99a7d8_MD5.jpg]]

Continuing to play the game, students need to lose a life and perform a Next Scan with a value of `2` (to match the number of lives Hackman currently has):

![[HTB Solutions/Others/z. images/436ae6b96a4d8742fb19860999ae6c55_MD5.jpg]]

Students need to repeat this process, performing a New Scan whenever Hackman loses or gains a life. Narrowing down to a single address, students need to right click and add the address to the address list:

![[HTB Solutions/Others/z. images/0467ee5931c3793eb014f5038e5042fa_MD5.jpg]]

Providing a description such as "Lives", students need to set the Value to `10`:

![[HTB Solutions/Others/z. images/dac22e7dd661d14986f78f80d58efeb3_MD5.jpg]]

![[HTB Solutions/Others/z. images/3265cfc98c6daeeed1194dc969fa3803_MD5.jpg]]

Once the value has been modified, students need to resume the game:

![[HTB Solutions/Others/z. images/e569f045b6dd39d49d9dc516783b2926_MD5.jpg]]

The flag is revealed to be `Ch41L3n93_90d`.

Answer: `Ch41L3n93_90d`

# Skills Assessment

## Question 2

### "What flag is displayed when you successfully modify the HiddenScore counter to a value greater than 200'000'000?"

Continuing the game from the previous challenge question, students need to right-click the Lives entry inside the cheat table and Browse this memory region:

![[HTB Solutions/Others/z. images/5e333ca7323e82e28312dfd809af5941_MD5.jpg]]

Looking at the Memory Viewer, students need to identify the start of the data structure by looking at the hex values, and seeing where the padding begins and ends:

![[HTB Solutions/Others/z. images/373d3d575a375dcee17ec6ac4c911de1_MD5.jpg]]

Thus, students need to right-click -> Open in dissect data/structure:

![[HTB Solutions/Others/z. images/2136791ad3a5e4037388947611068281_MD5.jpg]]

Selecting Structures -> Define new structure, and leave the Structure Name as `unnamed structure`:

![[HTB Solutions/Others/z. images/618ec11f35cb8c3a5ff696b7b8edfa82_MD5.jpg]]

Now, students need to resume the game and collect cubes, analyzing which addresses/values change to coincide with the number of in-game points:

![[HTB Solutions/Others/z. images/ba28ac98072a62dc23c224ff33c6c0fa_MD5.jpg]]

Having discovered the two visible addresses tied to the score, students need to modify the top value to `200000000` and the lower value to `2000000`:

![[HTB Solutions/Others/z. images/f3ebaec6f1af74ef5966dddadb8bb89b_MD5.jpg]]

![[HTB Solutions/Others/z. images/b0581304586b82e27aead968ee5842b9_MD5.jpg]]

Finally, students need to resume the game and collect some points:

![[HTB Solutions/Others/z. images/df731efc4849510e27483abbb926cceb_MD5.jpg]]

Completing the module, the final flag reads `n1Nj4_v4Lu32`.

Answer: `n1Nj4_v4Lu32`