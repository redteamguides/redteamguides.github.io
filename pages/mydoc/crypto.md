---
title: Crypto
sidebar: mydoc_sidebar
permalink: crypto.html
folder: mydoc
---

# Encryption

## Useful websites

| Address | Explanation
| :--- | :--- |
| https://www.dcode.fr/ | encryption and decryption
| https://crackstation.net/ | Decoding
| https://gchq.github.io/CyberChef/ | encryption and decryption and ... |
| https://www.base64encode.org/ | base64 encoding |
| https://www.base64decode.org/ | base64 decoding |
| http://rumkin.com/tools/cipher/caesar.php | Decode caesar |
| https://www.unphp.net | deobfuscate php code |


## Decode Fernet

```text
https://asecuritysite.com/encryption/ferdecode
```

Or
  
```text
from cryptography.fernet import Fernet
key = ""
token = ""
cipher = Fernet(key)
decoded = cipher.decrypt(token)
```

## Decode the Malbolge language

```text
http://www.malbolge.doleczek.pl/
https://zb3.me/malbolge-tools/
```

## Decode Dvorak format keyboards

```text
https://www.geocachingtoolbox.com/index.php?lang=en&page=dvorakKeyboard
```

## Decode DTFM

```text
http://dl.djsoft.net/DTMFChecker.zip
https://www.dcode.fr/prime-numbers-cipher
```

## Decrypt bcrypt

```text
git clone https://github.com/BREAKTEAM/Debcrypt.git
python3 crack.py
```

## Decode Cistercian numbers

```text
https://www.dcode.fr/cistercian-numbers
```

## Convert Multi-tap Phone Code to letters

```text
https://www.dcode.fr/code-multitap-abc
http://rumkin.com/tools/cipher/atbash.php
```

## Decode xor message

```text
python3 crack_repeating_key_xor.py -f <file> -x
```

## Attack on PKCS#1 in RSA

```text
https://programtalk.com/vs2/python/9053/featherduster/tests/test_bleichenbacher.py/
```

## Types of attacks on RSA

For example, decryption of flag.enc file by public key without private key

```text
python3 ./RsaCtfTool/RsaCtfTool.py --publickey ./key.pub --private
openssl rsautl -decrypt -inkey key.pri -in flag.enc -out flag.txt
```

## Decode Vigenere Decoder

```text
https://www.dcode.fr/vigenere-cipher
```

## Base64 decoding in terminal

```text
echo "YToxOntzOjQ6Im5hbWUiO2E6MTp7czoxMDoicGF1bC1jb2xlcyI7YTo5OntzOjI6ImlkIjtzOjEwOiIxNTkyNDgzMjM2IjtzOjQ6Im5hbWUiO3M6 | base64 -d
```


{% include links.html %}
