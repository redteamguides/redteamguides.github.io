---
title: Hardware
sidebar: mydoc_sidebar
permalink: hardware.html
folder: mydoc
---


## BadUSB

### Digispark

1. Open the Arduino IDE and select "Digispark (Default - 16.5MHz)" from the "Tools" > "Board" menu.

2. Write a script that will be executed by the Digispark. This script can be written in the Arduino IDE using the "Sketch" > "New Sketch" menu. Here is an example script that opens the command prompt and types in a series of commands:


```
#include "DigiKeyboard.h"

void setup() {
  // Start the keyboard
  DigiKeyboard.delay(2000); // wait for 2 seconds
  DigiKeyboard.sendKeyStroke(0); // windows key
  DigiKeyboard.delay(1000);
  DigiKeyboard.print("cmd"); // open command prompt
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(1000);
  DigiKeyboard.print("echo Hello World!"); // type command
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(1000);
  DigiKeyboard.print("exit"); // exit command prompt
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
}

void loop() {
}
```

3. Upload the script to the Digispark by clicking the "Upload" button in the Arduino IDE.






{% include links.html %}
