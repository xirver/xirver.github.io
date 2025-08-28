---
layout: post
title: "easyReverse"
date: 2025-08-28
---

## Challenge Description
This was an easy reverse challenge, perfect for a beginner. The description of this challange is the following: All the coolest ghosts in town are going to a Haunted Houseparty - can you prove you deserve to get in?

## Solution
First of all run the executable to understand what it is asking for.

`Welcome to the SPOOKIEST party of the year. Before we let you in, you'll need to give us the password: ` 

Now that we know that it is asking for a password, lets move to how we can retrive it. The are two easy solutions to this challenge:

Run the `strings` command and the magic string required to collect the flag it will be in clear.

Otherwise just open the executable with Ghidra and move to the main function, there will be the snippet of code where it says if the input is equal to this string you will get the flag.

This is the string you are looking for:

`s3cr3t_p455_f0r_gh05t5_4nd_gh0ul5`
