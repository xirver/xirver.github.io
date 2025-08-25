---
layout: post
title: "Spookifier"
date: 2025-08-25
---

## Challenge Description
This was a cool web challenge from Hack The Box, called **Spookifier**. The description of this challange is the following: There's a new trend of an application that generates a spooky name for you. Users of that application later discovered that their real names were also magically changed, causing havoc in their life. Could you help bring down this application?

## Solution
When you start the challenge, you’re presented with a form. Whatever you insert gets transformed into a spooky-looking font. The first thing I tried was some HTML injection, XSS or SSTI. I tested with `${7*7}` and as result, I got `49`. This confirmed me that the app is indeed vulnerable to Server-Side Template Injection (SSTI).

I started crafting some payloads. I started with this one: `${__import__('os').popen('ls -la /').read()}`
This printed the list of files on the server. Among them, I spotted a file called `flag.txt`.
So I updated the payload to read its contents: `${__import__('os').popen('cat /flag.txt').read()}`.



