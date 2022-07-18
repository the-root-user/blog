---
title: "Pwn 0x01: Buffer Overflow"
author: "Signore"
date: 2022-07-18
summary: "WTH is a buffer overflow? Let's do it"
description: ""
categories: [""]
tags: ["pwn", "buffer overflow"]
series: ["Binary Exploitation Adventures"]
keywords: ["pwn", "binary", "memory", "x32", "x64", "gdb", "memory corruption", "binary exploitation", "exploit development"]
ShowToc: true
cover:
  image: "images/cover-binexp-01.png"
  caption: "cover"

---

In this post, we will see what is a buffer overflow and will exploit it to get code execution.
Do Not feel overwhelmed. Just follow along and we'll have fun.

If you are new to the series, check out my previous posts [here](/blog/series/binary-exploitation-adventures)

## The Stack

Take this C program:

{{< terminal title="program.c" >}}
```c
#include <stdio.h>
#include <unistd.h>

int helper(){
    system("/bin/sh");      // executes system shell
}

int overflow(){
    char buffer[500];       // declaring buffer variable with specified size
    int userinput;
    userinput = read(0, buffer, 700);   // reading user input into buffer variable
    printf("\nUser provided %d bytes. Buffer content is: %s\n", userinput, buffer);
    return 0; 
}

int main(int argc, char *argv[]){
    overflow();
    return 0;
}
```
{{< /terminal >}}

If we break down the program from the `main` function, it calls the `overflow` function which declares a variable of size 500 bytes and then, reads user input into that variable. Later, it prints the size of the provided input along with the input itself.

After compiling, here's what the program does:
{{< terminal title="Terminal" >}}
![code](code.png)
{{< /terminal >}}

We have to compile the program with the following command:
{{< terminal title="Terminal" >}}
```shell
gcc -m32 -fno-stack-protector -z execstack program.c -o program
```
{{< /terminal >}}

Also, we need to disable ASLR with the following command:
{{< terminal title="Terminal" >}}
```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```
{{< /terminal >}}
Everytime you reboot your machine, you'll have to do this step again.

<details><summary><b>What's going on?</b></summary>

> Modern programs come with a bunch of exploit mitigations.
> For example, we can see the protections on the `ping` binary which is mostly present on linux as well as windows, with [`checksec`](https://github.com/slimm609/checksec.sh) script.
> {{< terminal title="Terminal" >}}
![checksec-ping](checksec1.png)
> {{< /terminal >}}
>
> So, initially we'll be working with those protections disabled and that is why we're giving those extra flags to gcc.
>
> Here we can see the protections on our (compiled) program:
> {{< terminal title="Terminal" >}}
![checksec-program](checksec2.png)
> {{< /terminal >}}
> For now, you don't need to care about them. We'll learn to bypass some anti-exploit mechanisms later on.
</details><br>

<br>

In general, the stack is aligned this way:
![Stack Layout](memory-layout0.png)

Since our program is not dealing with any arguments, so, in our case, it's like this:
![Program Stack Layout](memory-layout1.png)


## Stack Abuse

What if we give the program some unexpected input? <br>
What if we give an input, more in magnitude than the defined buffer is supposed to handle? :thinking:

Let's take a look.

### Concept

When we give an input bigger than a defined buffer, if the program is vulnerable, we overwrite other stuff that is already present on the stack.

Our goal is to overwrite the `return address` of the function so that we can point the EIP to a memory address of our own choice.
![Memory Overflow](memory-layout-overflow.png)

Normally, one can just get creative and give a program random inputs until something desirable is received back :) 

### Deep Dive

Let's give our program some random inputs, with the help of Python.<br>
(You know we can `pipe` the output of one command to another, right?)

{{< terminal title="Terminal" >}}
![input](program-input.png)
{{< /terminal >}}

Hnmm.. so, eventually, we broke the program!

Let's generate a pattern with `cyclic` utility and analyse the program with gdb to determine the offset of EIP.
<details><summary>Alternative</summary>

One can also use metasploit's `msf-pattern_create` and `msf-pattern_offset` to achieve the same result.
</details><br>

{{< terminal title="Terminal" >}}
![](program-offset.png)
{{< /terminal >}}

We get the offset to be `516`.

Now, we will send calculated input to see if we can control the EIP.

{{< terminal title="Terminal" >}}
![](program-eip.png)
{{< /terminal >}}

And.. Yes! We can see `0x42424242`, the hex code for the 4 B's we sent.

## EIP Control

When we have EIP under control, one of the first things we can do is to reuse the dead code present inside a binary.

**Dead Code** is a piece of code within a program which is not used when the program executes.

### Code Reuse

We can see that the `helper` function isn't called during the program execution. Since we have control over the EIP, we can point it to the `helper` function to get it executed.

For that purpose, we need the memory address of the `helper` function.
We can find it with gdb as:

{{< terminal title="Terminal" >}}
![](function-addr.png)
{{< /terminal >}}

Our binary is 32-bit and 32-bit programs use [little-endian](https://chortle.ccsu.edu/assemblytutorial/Chapter-15/ass15_3.html), due to which we have to provide the memory address in reverse bytes order.

{{< terminal title="Terminal" >}}
![](function-addr-error.png)
{{< /terminal >}}

But.. we still get `segmentation fault`.

No need to worry. This is a common thing in exploit dev. Let's arrange the bytes a bit and see what happens.

{{< terminal title="Terminal" >}}
![](function-addr-no-error.png)
{{< /terminal >}}

Yay! Did you see? a new process `/usr/bin/dash` started.. Our Shell!

But, wait.. it also did `exit` even before we could interact with it.

What happens under the hood is that a child process `dash` is started which operates by getting input from user (like `bash` or `sh`) but the parent process (our `program`) is done with its job and exits. The child process with no input, consequently, also exits.

We can take help of `cat` command to make the terminal wait for input.<br>
But, for convenience, we are going to use an awesome tool, a python library, `pwntools` to make our exploitation process easy.

**[Pwntools](https://github.com/Gallopsled/pwntools)**

Here's a nice little exploit:

{{< terminal title="vim - exploit.py" >}}
```py {linenos=true}
#!/bin/python3
from pwn import *

exe = './program'
elf = context.binary = ELF(exe, checksec=False)

payload=flat("A"*516,0x565561b9)

io = process(exe)
io.sendline(payload)
io.interactive()
```
![](pwn-vim.png)
{{< /terminal >}}

Upon running the exploit, we successfully get a system shell and can execute arbitrary commands :fire:

{{< terminal title="Terminal" >}}
![](pwn.png)
{{< /terminal >}}

## Shellcode
