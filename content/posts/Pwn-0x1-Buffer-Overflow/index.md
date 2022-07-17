---
title: "Pwn 0x1: Buffer Overflow"
author: "Signore"
date: 2022-07-17
summary: "WTH is a buffer overflow? Let's do it"
description: ""
categories: [""]
tags: ["pwn", "buffer overflow"]
series: ["Binary Exploitation Adventures"]
keywords: ["pwn", "binary", "memory", "x32", "x64", "gdb", "memory corruption", "binary exploitation", "exploit development"]
ShowToc: true
cover:
  image: "images/cover_binexp.png"
  caption: "cover"

---

In this post, we are going to learn what is a buffer overflow and will exploit it to get code execution.

! Disable ASLR

Checksec

## Stack Smashing

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

The program reads user input... .

Compile it this way:
{{< terminal title="Terminal" >}}
```shell
gcc -m32 -fno-stack-protector -z execstack program.c -o program
```
{{< /terminal >}}

#### Why those extra flags?

<details>
<summary>After compiling the code</summary>

with <abbr title="GNU C Compiler">gcc</abbr> as:
```shell
gcc code.c -o code
```
or
```shell
make code
```
make command is just another shortcut for us (for gcc)
</details>

it does something.

## EIP Control

### Code Reuse

```shell
gdb code            # 'code' is the name of our binary
b main              # instructing gdb to break at main function
disassemble main    # disassemble the main function
```

![arguments-32](args-x32.png)

## Shellcode
