---
title: Social Engineering
sidebar: mydoc_sidebar
permalink: phish.html
folder: mydoc
---

# Social Engineering

Social engineering is a powerful tool that can be used to manipulate individuals and organizations. 

## Pretexting

This is when an attacker creates a fictional scenario to gain someone's trust and convince them to divulge sensitive information. For example, an attacker might pose as a bank employee and ask for a customer's account information.

Some tools that can be used for pretexting include:

`Social media`: Information about a target's personal life can be obtained through social media platforms, such as Facebook, Instagram, and Twitter.

`Caller ID spoofing`: This technique can be used to display a fake caller ID on the target's phone, making it appear as if the call is coming from a legitimate source.

`Phishing emails`: Emails can be crafted to appear as if they are coming from a legitimate source, such as a bank or company, in an attempt to trick the target into revealing sensitive information.

`Pretexting kits`: These kits can include scripts, templates, and other tools to aid in pretexting attacks.




## Phishing

This is when an attacker sends a fraudulent email or text message that appears to come from a legitimate source, such as a bank or social media platform, to trick the recipient into clicking on a link or entering personal information.

template for a phishing email:

```
Subject: Urgent: Security Alert
Body:
Dear [Target],

We have detected suspicious activity on your account and need to verify your information to prevent unauthorized access. Please click on the following link to update your account details: [Malicious Link]

Thank you for your cooperation.

Sincerely,
[Legitimate-Sounding Sender Name]```

Remember to replace the [Spoofed Email Address], [Target], [Malicious Link], and [Legitimate-Sounding Sender Name] with appropriate values for your specific phishing campaign. However, I must remind you that using Gophish or any social engineering tactics for malicious purposes is illegal and unethical. Always use these tools responsibly and with proper legal authorization.
```

### Gophish

```
./gophish
```

### SET

To launch a spear phishing campaign, run the following command:

```
setoolkit --campaign=spearphish
```

To launch a website attack campaign, run the following command:

```
setoolkit --campaign=webattack
```

To launch a credential harvesting campaign, run the following command:

```
setoolkit --campaign=credential_harvester
```

To launch a SMS spoofing campaign, run the following command:

```
setoolkit --campaign=smsSpoofing
```



### BeEF 

This starts the BeEF server and launches the web interface in the default browser.

```
beef-xss
```

This starts the BeEF server using a specific configuration file.

```
beef -c /path/to/config.yaml
```


This starts BeEF on a custom port (in this case, port 8080).

```
beef -p 8080
```



### Evilginx

Displays a list of available phishing templates, which can be used to create convincing fake login pages for different websites.

```
evilginx templates
```

Adds a domain to the list of monitored domains, allowing Evilginx to intercept traffic to that domain.

```
evilginx domain add [domain_name]
```

Removes a domain from the list of monitored domains.

```
evilginx domain delete [domain_name]:
```

Displays the log file for Evilginx, which includes information about intercepted traffic and successful phishing attempts.

```
evilginx log
```

Sends a test phishing email to the specified email address, using the specified phishing template.

```
evilginx test [phishing_template] [email_address]
```



## Baiting

This is when an attacker leaves a physical device, such as a USB drive or CD, in a public place where someone will find it and take it home. The device is usually infected with malware that allows the attacker to access the victim's computer or network.



### USB Hacking Toolkit


-   USB Rubber Ducky: A keystroke injection tool that can be disguised as a USB drive and used to automatically execute scripts on a target computer.

-   BadUSB: A malicious firmware that can be installed on a USB device to execute arbitrary code and take over a target computer.



### Fake Wi-Fi Access Points




### Social Media Scams

Attackers can use social media to create fake accounts and pages that offer enticing rewards or benefits. Victims may be asked to fill out a survey or provide personal information in exchange for the promised reward. These scams can be created using basic HTML and JavaScript code.



### Free Software Downloads

Attackers can create fake software downloads that promise free or premium versions of popular software. Once downloaded and installed, the software may be used to deliver malware or steal sensitive information. Websites like GitHub and SourceForge can be used to host these downloads.






## Tailgating

This is when an attacker gains access to a restricted area by following someone who has legitimate access. For example, an attacker might wait outside a secure door and then follow an employee who swipes their access card to enter.




## Impersonation

This is when an attacker poses as someone else, such as a senior executive or IT administrator, to trick an employee into giving them access to sensitive information or systems.

Another method is to physically impersonate someone by wearing a uniform or ID badge. This can be especially effective when trying to gain access to a restricted area or building. In some cases, impersonating a high-level executive can be used to convince others to take certain actions, such as transferring funds or providing confidential information.




## Piggybacking

This involves gaining access to a secure area or system by following closely behind someone who has authorized access. For example, an attacker might wait outside a secure building and ask someone to hold the door for them, then quickly enter behind them.

In this example, the program prompts the user to swipe an access card to enter a restricted area. If the card is authorized, the program opens the door using a motor and allows the user to enter. The program then waits for a few seconds before closing the door again. However, if the card is not authorized, the program denies access.

```
import RPi.GPIO as GPIO
import time

# Set up the Raspberry Pi to control a motor
GPIO.setmode(GPIO.BOARD)
GPIO.setup(7, GPIO.OUT)
motor = GPIO.PWM(7, 50)

# Define the function to open the door
def open_door():
    motor.start(7.5)
    time.sleep(1)
    motor.stop()

# Define the function to close the door
def close_door():
    motor.start(2.5)
    time.sleep(1)
    motor.stop()

# Main program
while True:
    authorized_person = input("Please swipe your access card: ")
    if is_authorized(authorized_person):
        open_door()
        time.sleep(5)
        close_door()
    else:
        print("Access denied.")
```

An attacker could use piggybacking to gain access to the restricted area by following closely behind an authorized person as they enter. By doing so, the attacker can bypass the access control system and gain unauthorized access to the area.



## Reverse Social Engineering

This involves convincing an attacker that they have successfully targeted a system or individual, when in fact they have been identified and monitored by security personnel. For example, a security team might set up a fake target and intentionally make it easy for an attacker to breach their system, in order to gain intelligence about the attacker's tactics and techniques.


## Physical Social Engineering

This involves using physical means to gain access to a secure area or system, such as picking locks or bypassing physical security measures. For example, an attacker might use a fake ID to gain access to a secure building, or use a device to jam the signal of a keycard reader in order to gain access.




{% include links.html %}
