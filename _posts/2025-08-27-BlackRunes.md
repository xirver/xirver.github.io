---
layout: post
title: "BlackRunes"
date: 2025-08-27
---

## Challenge Description
This was a cool web challenge from Hack The Box, called **BlackRunes**. The description of this challange is the following: Survivors find a battered laptop in the rubble. Powering it up, they discover a cryptic software interface from an ancient architecture firm, hinting at vital blueprints. They must crack its security protocols. Undeterred, they race against time.

## Solution
I initially runned dirsearch:

`200 /login`
`200 /register`
`401 /documents`
`301 /css -> /css/`

I registered and logged in. The app lets you create documents and later view/delete them. Each document shows a signature that is content-dependent and case-sensitive (e.g., "a" ≠ "A"). I tried various inputs to see what the sanitizer allows, for example `<h1>Test</h1>` was allowed but `<script>alert(1)</script>` was completely removed, snippet of code like `<a href="javascript:…">` becomes `<a></a>`, I also tried to encode part of them by using `&lt;` , `&quot;` and `&gt;` but nothing seems to execute, at least for now.

I moved to reviewing the source code, in order to have a better understanding on what was happening. I focused particularly on the signature of the documents and authentication. I noticed that by decoding the cookies signature of my user,

`eyJ1c2VybmFtZSI6ImFzZCIsImlkIjoxfQ%3D%3D-a09c533200ee23a632d357e781980d23a7578e5d4586990e51a7646b1378a940`

this string was popping out:

`{"username":"asd","id":1}`

The first part of the string until `-` its a base64 encoded string. So i modified it and crafted my own:

`{"username":"admin","id":1}`

I encoded it in base64 and I created a new docoment with the encoded string. By doing so a signature was created so i merged the base64 string and the document signature and i changed the cookie value. This allowed me to access two new endpoints that were granted only to the admin.

I started playing with the endpoint /document/export/document_id and I noticed that when the document is exported the code inside the documents was executed. 
This because `/document/export/document_id` (admin-only) loads `document.content`. `NodeHtmlMarkdown().translate(document.content)` converts the HTML into Markdown. And finally `markdown-pdf({ remarkable: { html: true }})` turns Markdown into PDF with HTML enabled. This renderer executes HTML/JS during PDF generation. Even though creation used sanitize-html, the pipeline plus html:true let us land a working image-error handler that runs JavaScript when exporting (not when viewing).

So i crafted a more specific payload:

`&lt;img src onerror=&quot; var x=new XMLHttpRequest(); x.onload=function(){ var pre=document.createElement('pre'); pre.textContent=this.responseText; document.body.innerHTML=''; document.body.appendChild(pre); }; x.open('GET','file:///etc/passwd'); x.send(); &quot;&gt;`

I created a new document with it inside and i exported the document, by doing so this was the content of the exported pdf.

![Output payload Screenshot](/assets/images/DarkRoses/output_darkrunes.png)

This hinted me that by applying some more changes to the payload i was able to use it to retrive the file containing the flag.

