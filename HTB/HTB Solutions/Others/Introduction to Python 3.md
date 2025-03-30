
| Section                                  | Question Number | Answer          |
| ---------------------------------------- | --------------- | --------------- |
| Conditional Statements and Loops         | Question 1      | 6               |
| Conditional Statements and Loops         | Question 2      | print(num)      |
| Conditional Statements and Loops         | Question 3      | Ac4deMY!        |
| Defining Functions                       | Question 1      | def foo(bar):   |
| Defining Functions                       | Question 2      | named           |
| Defining Functions                       | Question 3      | positional      |
| The First Iterations                     | Question 1      | Turbine         |
| Further Improvements                     | Question 1      | Unlimited       |
| Managing Libraries in Python (Continued) | Question 1      | 3               |
| Managing Libraries in Python (Continued) | Question 2      | <class 'tuple'> |
| Managing Libraries in Python (Continued) | Question 3      | PYTHONPATH      |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Conditional Statements and Loops

## Question 1

### "How long is list\_1 ?"

Students can count the elements of the list `list_1  = [5, 3, 'Cake', True, 4, 5]` manually or use the `len` function of Python, finding it to be 6 elements long:

Code: python

```python
list_1  = [5, 3, 'Cake', True, 4, 5]
print(len(list_1))
```

```
┌─[us-academy-1]─[10.10.14.26]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ python3

Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
>>> list_1  = [5, 3, 'Cake', True, 4, 5]
>>> print(len(list_1))

6
```

Answer: `6`

# Conditional Statements and Loops

## Question 2

### "In "Code block 2" the blank should be filled with what, to output all numbers in a terminal?"

As the element is named "num", students can use `print(num)` to output all numbers.

Answer: `print(num)`

# Conditional Statements and Loops

## Question 3

### "What is the result of running the code in "Code block 3"?"

Students need to either figure out what the output is mentally, which in this case the code is taking the first two characters only of each item in the list and concatenating them to make the string `Ac4deMY!`. Or, alternatively, students can run the code in Python and see the output:

```python
list_3 = ['Accidental', '4daa7fe9', 'eM131Me', 'Y!.90']
secret = []
for x in list_3:
	secret.append(x[:2])
print(''.join(secret))
```
```python
>>> list_3 = ['Accidental', '4daa7fe9', 'eM131Me', 'Y!.90']
>>> secret = []	
>>> 
>>> for x in list_3:
...     secret.append(x[:2])
... 
>>> print(''.join(secret))

Ac4deMY!
```

Answer: `Ac4deMY!`

# Defining Functions

## Question 1

### "Write the function signature (def ...) for a function "foo" that has one argument "bar", including the trailing colon."

The function "foo" that takes one argument "bar" has the the signature of `def foo(bar):`.

Answer: `def foo(bar):`

# Defining Functions

## Question 2

### "When we call a function and explicitly set the value of a parameter, e.g. foo(bar=42), this parameter is called a \_\_\_\_\_ parameter. (Fill the blank)"

This parameter is called a `named` parameter.

Answer: `named`

# Defining Functions

## Question 3

### "Functions which parameters are not named explicitly are called \_\_\_\_\_\_\_\_\_\_ parameters. (Fill the blank)"

Parameters that are not named explicitly are called `positional` parameters:

![[HTB Solutions/Others/z. images/79a3e88c9c07dfec661e29b295111a22_MD5.jpg]]

Answer: `positional`

# The First Iterations

## Question 1

### "What is the 3rd most used word on the exercise target website?"

After spawning the target machine, students first need to save the final code provided in the section inside a Python file, most importantly changing the variable "PAGE\_URL" with `STMIP:STMPO`:

```python3
PAGE_URL = 'http://STMIP:STMPO'
```

Then, the script can then be saved into a file using `echo`:

```shell
echo "import requests
import re
from bs4 import BeautifulSoup

PAGE_URL = 'http://STMIP:STMPO'

def get_html_of(url):
    resp = requests.get(url)

    if resp.status_code != 200:
        print(f'HTTP status code of {resp.status_code} returned, but 200 was expected. Exiting...')
        exit(1)

    return resp.content.decode()

html = get_html_of(PAGE_URL)
soup = BeautifulSoup(html, 'html.parser')
raw_text = soup.get_text()
all_words = re.findall(r'\w+', raw_text)

word_count = {}

for word in all_words:
    if word not in word_count:
        word_count[word] = 1
    else:
        current_count = word_count.get(word)
        word_count[word] = current_count + 1

top_words = sorted(word_count.items(), key=lambda item: item[1], reverse=True)

for i in range(10):
    print(top_words[i][0])" > wordsExtractor.py
```
```
┌─[us-academy-1]─[10.10.14.43]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ echo "import requests
import re
from bs4 import BeautifulSoup

PAGE_URL = 'http://165.227.224.55:31200'

def get_html_of(url):
    resp = requests.get(url)

    if resp.status_code != 200:
        print(f'HTTP status code of {resp.status_code} returned, but 200 was expected. Exiting...')
        exit(1)

    return resp.content.decode()

html = get_html_of(PAGE_URL)
soup = BeautifulSoup(html, 'html.parser')
raw_text = soup.get_text()
all_words = re.findall(r'\w+', raw_text)

word_count = {}

for word in all_words:
    if word not in word_count:
        word_count[word] = 1
    else:
        current_count = word_count.get(word)
        word_count[word] = current_count + 1

top_words = sorted(word_count.items(), key=lambda item: item[1], reverse=True)

for i in range(10):
    print(top_words[i][0])" > wordsExtractor.py
```

After running the script with Python3, students will find that the third most used word is `Turbine`:

```shell
python3 wordsExtractor.py
```
```
┌─[us-academy-1]─[10.10.14.43]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ python3 wordsExtractor.py

and
StarGusts
Turbine
in
for
your
Sign
solutions
you
the
```

Answer: `Turbine`

# Further Improvements

## Question 1

### "Given a minimum word length of 9, what is the 3rd most frequent word on the target"

After spawning the target machine, students need to save the Python code under "The Final Script" inside a file using `echo`:

```shell
echo "import click
import requests
import re
from bs4 import BeautifulSoup

def get_html_of(url):
    resp = requests.get(url)

    if resp.status_code != 200:
        print(f'HTTP status code of {resp.status_code} returned, but 200 was expected. Exiting...')
        exit(1)

    return resp.content.decode()

def count_occurrences_in(word_list, min_length):
    word_count = {}

    for word in word_list:
        if len(word) < min_length:
            continue
        if word not in word_count:
            word_count[word] = 1
        else:
            current_count = word_count.get(word)
            word_count[word] = current_count + 1
    return word_count

def get_all_words_from(url):
    html = get_html_of(url)
    soup = BeautifulSoup(html, 'html.parser')
    raw_text = soup.get_text()
    return re.findall(r'\w+', raw_text)

def get_top_words_from(all_words, min_length):
    occurrences = count_occurrences_in(all_words, min_length)
    return sorted(occurrences.items(), key=lambda item: item[1], reverse=True)

@click.command()
@click.option('--url', '-u', prompt='Web URL', help='URL of webpage to extract from.')
@click.option('--length', '-l', default=0, help='Minimum word length (default: 0, no limit).')
def main(url, length):
    the_words = get_all_words_from(url)
    top_words = get_top_words_from(the_words, length)

    for i in range(10):
        print(top_words[i][0])

if __name__ == '__main__':
    main()" > finalScript.py
```
```
┌─[us-academy-1]─[10.10.14.43]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ echo "import click
import requests
import re
from bs4 import BeautifulSoup

def get_html_of(url):
    resp = requests.get(url)

    if resp.status_code != 200:
        print(f'HTTP status code of {resp.status_code} returned, but 200 was expected. Exiting...')
        exit(1)

    return resp.content.decode()

def count_occurrences_in(word_list, min_length):
    word_count = {}

    for word in word_list:
        if len(word) < min_length:
            continue
        if word not in word_count:
            word_count[word] = 1
        else:
            current_count = word_count.get(word)
            word_count[word] = current_count + 1
    return word_count

def get_all_words_from(url):
    html = get_html_of(url)
    soup = BeautifulSoup(html, 'html.parser')
    raw_text = soup.get_text()
    return re.findall(r'\w+', raw_text)

def get_top_words_from(all_words, min_length):
    occurrences = count_occurrences_in(all_words, min_length)
    return sorted(occurrences.items(), key=lambda item: item[1], reverse=True)

@click.command()
@click.option('--url', '-u', prompt='Web URL', help='URL of webpage to extract from.')
@click.option('--length', '-l', default=0, help='Minimum word length (default: 0, no limit).')
def main(url, length):
    the_words = get_all_words_from(url)
    top_words = get_top_words_from(the_words, length)

    for i in range(10):
        print(top_words[i][0])

if __name__ == '__main__':
    main()" > finalScript.py
```

Subsequently, students need to run the script with the `--url` (feeding it `http://STMIP:STMPO`) and `--length` (feeding it `9`) options, to find that the third most used word is `Unlimited`:

```shell
python3 finalScript.py --url http://STMIP:STMPO --length 9
```
```
┌─[us-academy-1]─[10.10.14.43]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ python3 finalScript.py --url http://134.209.178.167:30153 --length 9

StarGusts
solutions
Unlimited
Solutions
Affordable
performance
satisfaction
protected
modernize
Enterprise
```

Answer: `Unlimited`

# Managing Libraries in Python (Continued)

## Question 1

### "How long is foo?"

Students can copy and paste the code under "Question 1" into the Python interpreter and use the function "len" on "foo". Because "foo" is a set, identical items are not duplicated and only unique items are accounted for. Therefore, students will find that there are `3` items only:

```python
>>> foo = set()
>>> for i in range(42):
...     foo.add('Cake')
... 
>>> foo.add('Hello')
>>> foo.add('World')
>>> len(foo)
```
```
┌─[us-academy-1]─[10.10.14.43]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ python3

Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> foo = set()
>>> 
>>> for i in range(42):
...     foo.add('Cake')
... 
>>> foo.add('Hello')
>>> foo.add('World')
>>> len(foo)

3
```

Answer: `3`

# Managing Libraries in Python (Continued)

## Question 2

### "The type of foo from question 1 is <class 'set'>. What is the type of x\_coordinate?"

Students need to run the `type` function on the variable "x\_coordinate" found under "Question 2" in a Python interpreter, finding its type to be `<class 'tuple'>`:

```python
>>> x_coordinate = (42,)
>>> type(x_coordinate)

<class 'tuple'>
```

Answer: `<class 'tuple'>`

# Managing Libraries in Python (Continued)

## Question 3

### "What is the environment variable called which lets us define a search path for external libraries?"

The `PYTHONPATH` environment variable allows defining a search path for external libraries:

![[HTB Solutions/Others/z. images/a324315978872b775445971b81b0cac9_MD5.jpg]]

Answer: `PYTHONPATH`