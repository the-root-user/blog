---
title: "NCC CTF 2022 - Reversing Challenges Writeup"
author: "Signore"
date: 2022-07-20
summary: "Walkthrough of Reversing & Binary Exploitation challenges presented at NED Cyber Community CTF 2022"
description: ""
categories: ["CTF Writeups"]
tags: ["r2", "reverse engineering"]
series: [""]
keywords: ["rev", "binary", "r2", "radare2", "rizin", "reverse engineering", "ghidra"]
ShowToc: true
cover:
  image: "images/cover-ncc-ctf-2022.png"
  caption: "cover"

---

:bulb: Rizin is a fork of radare2, one of the most popular reverse engineering tools.

## Reversing Warmup

We run `strings` on the binary and get our flag:

{{< terminal title="Terminal" >}}
![](chall-1.png)
{{< /terminal >}}

I later ran the binary, and it just gave the flag. Silly me!
{{< terminal title="Terminal">}}
![](chall-11.png)
{{< /terminal >}}
## Can You C Me

Running the binary asks us for correct password which we don't know yet.

Upon opening the binary with rizin, we can see our flag right there but it's scattered. We can also see another string which resembles a password.
{{< terminal title="Terminal" >}}
![](chall-20.png)
{{< /terminal >}}

Providing that password to the binary, we get our flag:
{{< terminal title="Terminal" >}}
![](chall-21.png)
{{< /terminal >}}

## Modulus Encryption

The flag for the challenge has been encrypted using the `encryption.py` python script and the generated output is the `output.txt` file. Our goal is to decrypt the flag.

The script is taking input data as `flag.txt`. The `encrypt` function gets the unicode code of each character present in the file with `ord()` and adds some integers to it. Then, it converts the characters back to ASCII with `chr()`.
{{< terminal title="Terminal" >}}
![](chall-30.png)
{{< /terminal >}}

We take the encrypted data `output.txt` as input. After getting the unicode, instead of adding, we modify the original technique a bit by subtracting the integers and then converting back to ASCII.

Upon running the modified script, we get the flag.
{{< terminal title="Terminal" >}}
![](chall-31.png)
{{< /terminal >}}

## Make it Go!

Running the binary asks us to enter password.

Opening the challenge file in `rizin`, we `seek` to `main` function and disassemble it. 
{{< terminal title="Terminal" >}}
![](chall-40.png)
{{< /terminal >}}

Going a bit down, we can see the `Enter_Password` string which is later being printed in the console with a `call` to `Fprint`:
{{< terminal title="Terminal" >}}
![](chall-41.png)
{{< /terminal >}}

Going futher down, we see there is the call to `Fscanln` which is taking user input. In the next instructions, there's a string comparison being made and then there is the `jne` (jump if not equal) instruction from which we can deduce that there's a condition being checked.

We can see that the user input is being compared to `0x45ea856`.
{{< terminal title="Terminal" >}}
![](chall-42.png)
{{< /terminal >}}

On providing the hex number to our binary, we get the flag:
{{< terminal title="Terminal" >}}
![](chall-43.png)
{{< /terminal >}}
