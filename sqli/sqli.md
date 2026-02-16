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
/filter?category='+AND+released=0s
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

## SQL injection in different contexts

**Lab: SQL injection with filter bypass via XML encoding**
