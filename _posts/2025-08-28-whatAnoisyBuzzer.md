---
layout: post
title: "What a Noisy Buzzer"
date: 2025-08-29
---

## Challenge Description
This was a cool reverse challenge. The description of this challenge is the following: In the cacophony of noise lies the potential for a clear message.

## Solution
First of all lets run the executable and gain some information regarding the program. 

`./Hubbub`

`bash: ./Hubbub: cannot execute binary file: Exec format error`


`file Hubbub`

`Hubbub: ELF 32-bit LSB executable, Atmel AVR 8-bit, version 1 (SYSV), statically linked, with debug_info, not stripped`

`readelf -h Hubbub`
`ELF Header:`
`  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00 `
`  Class:                             ELF32`
`  Data:                              2's complement, little endian`
`  Version:                           1 (current)`
`  OS/ABI:                            UNIX - System V`
`  ABI Version:                       0`
`  Type:                              EXEC (Executable file)`
`  Machine:                           Atmel AVR 8-bit microcontroller`
`  Version:                           0x1`
`  Entry point address:               0x0`
`  Start of program headers:          52 (bytes into file)`
`  Start of section headers:          34896 (bytes into file)`
`  Flags:                             0x5, avr:5`
`  Size of this header:               52 (bytes)`
`  Size of program headers:           32 (bytes)`
`  Number of program headers:         3`
`  Size of section headers:           40 (bytes)`
`  Number of section headers:         17`
`  Section header string table index: 14`

These informations will help use later on for choosing the right language for opening the program with Ghidra.

Now if you run strings and you look closely you can have some hints on what the challenge will be about:

`atmega328p`
`delay`
`tone_pins`
`loop`
`tone`

We can start digging online for something related to this information, so the `ATmega328` is a single-chip microcontroller and in the strings we have `tone`, `loop`, `delays`, `pins`. So something related to a sound? A melody? Who knows. Lets open it with Ghidra and find out.

Lets move to the `main` function and we can see these functions called over and over:

`_Z4tonehjm.constprop.1(0,0x2c);`
`delay(0,0x90);`
`delay(0,0xe8);`
`delay(0,0x90);`
`_Z4tonehjm.constprop.1(0,0x58);`
`delay(0,0x90);`
`delay(0,0xe8);`
`delay(0,0x90);`
`_Z4tonehjm.constprop.1(0,0x58);`
`delay(0,0x90);`
`delay(0,0x90);`

We can see that there are two types of tone 0x2c and 0x58.

`0x2c -> dot`
`0x58 -> dash`

And the delay function uses value like 0x90 0xe8 or 0xd0 that corresponds i guess to the ms.

`0x90 -> 144ms`
`0xe8 -> 208ms`
`0xd0 -> 232ms`

Now we can start thinking its something related to a morse code. So we can deduct that might correspond to the spacing of the secret phrase (letter/word gap).

Now lets move to the practical part, lets extract the main function and save it into a .txt file.
With the use of a python script we will go through each line, and we will check if its a tone (dot or dash) or delay.

Once we have those information we can easily translate it from morse code into readable text.

`MORSE_TABLE = {`
`    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",`
`    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",`
`    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",`
`    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",`
`    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",`
`    "--..": "Z",`
`    "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4",`
`    ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9"`
`}`

And we will found our flag.
