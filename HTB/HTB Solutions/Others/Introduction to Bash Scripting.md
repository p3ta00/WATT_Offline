
| Section                          | Question Number | Answer               |
| -------------------------------- | --------------- | -------------------- |
| Conditional Execution            | Question 1      | 1197735              |
| Arguments, Variables, and Arrays | Question 1      | echo ${domains\[1\]} |
| Comparison Operators             | Question 1      | 2paTlJYTkxDZz09Cg==  |
| Flow Control - Loops             | Question 1      | HTBL00p5r0x          |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Conditional Execution

## Question 1

### "Create an "If-Else" condition in the "For"-Loop of the "Exercise Script" that prints you the number of characters of the 35th generated value of the variable "var". Submit the number as the answer."

Students need to use an if statement that prints the number of characters of the variable `var` when it is the `35th` generated value:

```bash
#!/bin/bash

# Variable to encode
var="nef892na9s1p9asn2aJs71nIsm"

for counter in {1..35}
do
	var=$(echo $var | base64)

	if [ $counter -eq 35 ];then
		echo $var | wc -c
	fi
done
```

Students then need to make the script executable and run it:

```shell
chmod +x q1.sh
./q1.sh
```
```
┌─[us-academy-1]─[10.10.14.19]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ chmod +x script1.sh
┌─[us-academy-1]─[10.10.14.19]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ./script1.sh

1197735
```

Answer: `1197735`

# Arguments, Variables, and Arrays

## Question 1

### "Submit the echo statement that would print "www2.inlanefreight.com" when running the last "Arrays.sh" script."

Students need to increase the number in the array index, such that it becomes 1:

```shell
echo ${domains[1]}
```

Answer: `echo ${domains[1]}`

# Comparison Operators

## Question 1

### "Create an "If-Else" condition in the "For"-Loop that checks if the variable named "var" contains the contents of the variable named "value". Additionally, the variable "var" must contain more than 113,469 characters. If these conditions are met, the script must then print the last 20 characters of the variable "var". Submit these last 20 characters as the answer."

There are multiple approaches that can be taken to solve this question, one of them is shown below:

```bash
#!/bin/bash

var="8dm7KsjU28B7v621Jls"
value="ERmFRMVZ0U2paTlJYTkxDZz09Cg"

for i in {1..40}
do
	var=$(echo $var | base64)
	chars=$(echo $var | wc -c)

	if [[ "$var" == *"$value"* && $chars -gt 113469 ]];then
		echo $var | tail -c 20
	fi

done
```

Students then need to make the script executable and run it:

```shell
chmod +x q3.sh
./q3.sh
```
```
┌─[us-academy-1]─[10.10.14.19]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ chmod +x q3.sh 
┌─[us-academy-1]─[10.10.14.19]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ./q3.sh

2paTlJYTkxDZz09Cg==
```

Answer: `2paTlJYTkxDZz09Cg==`

# Flow Control - Loops

## Question 1

### "Create a "For" loop that encodes the variable "var" 28 times in "base64". The number of characters in the 28th hash is the value that must be assigned to the "salt" variable."

The for loop logic can be as below:

```bash
for i in {1..28};do
    var=$(echo "$var" | base64)
done

salt=$(echo $var | wc -c | tr -d ' ')
```

Thus, the full script becomes:

```bash
#!/bin/bash

# Decrypt function
function decrypt {
	MzSaas7k=$(echo $hash | sed 's/988sn1/83unasa/g')
	Mzns7293sk=$(echo $MzSaas7k | sed 's/4d298d/9999/g')
	MzSaas7k=$(echo $Mzns7293sk | sed 's/3i8dqos82/873h4d/g')
	Mzns7293sk=$(echo $MzSaas7k | sed 's/4n9Ls/20X/g')
	MzSaas7k=$(echo $Mzns7293sk | sed 's/912oijs01/i7gg/g')
	Mzns7293sk=$(echo $MzSaas7k | sed 's/k32jx0aa/n391s/g')
	MzSaas7k=$(echo $Mzns7293sk | sed 's/nI72n/YzF1/g')
	Mzns7293sk=$(echo $MzSaas7k | sed 's/82ns71n/2d49/g')
	MzSaas7k=$(echo $Mzns7293sk | sed 's/JGcms1a/zIm12/g')
	Mzns7293sk=$(echo $MzSaas7k | sed 's/MS9/4SIs/g')
	MzSaas7k=$(echo $Mzns7293sk | sed 's/Ymxj00Ims/Uso18/g')
	Mzns7293sk=$(echo $MzSaas7k | sed 's/sSi8Lm/Mit/g')
	MzSaas7k=$(echo $Mzns7293sk | sed 's/9su2n/43n92ka/g')
	Mzns7293sk=$(echo $MzSaas7k | sed 's/ggf3iunds/dn3i8/g')
	MzSaas7k=$(echo $Mzns7293sk | sed 's/uBz/TT0K/g')

	flag=$(echo $MzSaas7k | base64 -d | openssl enc -aes-128-cbc -a -d -salt -pass pass:$salt)
}

# Variables
var="9M"
salt=""
hash="VTJGc2RHVmtYMTl2ZnYyNTdUeERVRnBtQWVGNmFWWVUySG1wTXNmRi9rQT0K"

# Base64 Encoding Example:
#        $ echo "Some Text" | base64

# <- For-Loop here
for i in {1..28};do
    var=$(echo "$var" | base64)
done

salt=$(echo $var | wc -c | tr -d ' ')

# Check if $salt is empty
if [[ ! -z "$salt" ]]
then
	decrypt
	echo $flag
else
	exit 1
fi
```

Students then need to make the script executable and run it:

```shell
chmod +x q4.sh
./q4.sh
```
```
┌─[us-academy-1]─[10.10.14.19]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ chmod +x q4.sh 
┌─[us-academy-1]─[10.10.14.19]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ./q4.sh 
<SNIP>

HTBL00p5r0x
```

Answer: `HTBL00p5r0x`