---
title: OSINT
sidebar: mydoc_sidebar
permalink: osint.html
folder: mydoc
---



## Evaluation of information on project management boards

```text
inurl:https://trello.com AND intext:@gmail.com AND intext:password
inurl:https://trello.com AND intext:ftp AND intext:password
inurl:https://trello.com AND intext:ssh AND intext:password
inurl:jira AND intitle:login AND inurl:[company_name]
```

## Collect domain emails

```text
python3 theHarvester.py -d sbmu.ac.ir -b all -l 200
```

## osint framework

https://www.spiderfoot.net/documentation/

### Use through the web

```text
python3 sf.py -l 127.0.0.1:8070
```

### Collect domain emails

```text
python3 sf.py -m sfp_spider,sfp_hunter,sfp_fullcontact,sfp_pgp,sfp_clearbit,sfp_emailformat,sfp_email -s tesla.com -q -F EMAILADDR
```

### Evaluation of user account information

```text
python3 ./sf.py -m sfp_accounts -s "elonmusk" -q
```

### Evaluation of metadata information of domain files

```text
python3 ./sf.py -m sfp_intfiles,sfp_spider,sfp_filemeta -s tesla.com -q -F RAW_FILE_META_DATA
```

{% include links.html %}
