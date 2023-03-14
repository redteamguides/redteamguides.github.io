---
title: Steg
sidebar: mydoc_sidebar
permalink: steg.html
folder: mydoc
---

# Steganography

## Useful websites

| Address | Explanation
| :--- | :--- |
| https://secsy.net/easy_stegoCTF | steganography tools
| https://www.branah.com/braille-translator | Braille interpreter
| http://bigwww.epfl.ch/demo/ip/demos/FFT/ | Decode TTF |
| https://www.dcode.fr/brainfuck-language | translator brainfuck |
| https://www.boxentriq.com/code-breaking/morse-code | Morse code translator
| https://georgeom.net/StegOnline/image | Display LSB HALF mode


## Extract the file inside the file

```text
steghide info <filename> -p <password>
steghide extract -sf <filename> -p <password>
```

## Extract the file inside the wav file

```text
java -jar turgen.jar
```

## Convert binary codes to qrcode

```text
https://www.dcode.fr/binary-image
https://online-barcode-reader.inliteresarchy.com/
```

## transformations of photos

```text
java -jar Stegsolve.jar
```

## Check the file

```text
binwalk -e <file>
strings <file>
```

## Guess the password of the file in the file

```text
./steg_brute.py -b -d /usr/share/wordlists/rockyou.txt -f ../meow.wav
```


{% include links.html %}
