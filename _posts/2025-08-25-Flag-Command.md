---
layout: post
title: "Flag Command"
date: 2025-08-25
---

## Challenge Description
This was a cool web challenge, called **Flag Command**. The description of this challange is the following: Embark on the "Dimensional Escape Quest" where you wake up in a mysterious forest maze that's not quite of this world. Navigate singing squirrels, mischievous nymphs, and grumpy wizards in a whimsical labyrinth that may lead to otherworldly surprises. Will you conquer the enchanted maze or find yourself lost in a different dimension of magical challenges? The journey unfolds in this mystical escape!

## Solution
Inspect the source code, found three files `commands.js`, `main.js` and `game.js`. Read carefully the code and i crafted a curl command on the endpoint `/api/options` that gave me the full list of the all possible commands, in fact there was a fith hidden command under the name of "secret". I crafted another curl command: 
`curl -X POST http://94.237.60.55:58851/api/monitor -H "Content-Type: application/json" -d '{"command":"Blip-blop, in a pickle with a hiccup! Shmiggity-shmack"}'` and i managed to retrive the flag.
