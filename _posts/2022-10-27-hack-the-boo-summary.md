---
layout: post
title: "Hack The Boo 2022 - Summary"
categories: ["ctf", "HackTheBoo2022"]
---

## Introduction

Hack The Boo 2022 was the halloween-themed single player CTF competition hosted by HackTheBox designed to be begginer/entry level friendly. It was driven by motivating motto **"Don't be afraid of hackers. Become one!"**. I had pleasure to take part of the event as my first ever CTF competition.

## Results and conclusions

![results](/assets/img/HackTheBoo2022/results.png)

I learned a lot not only by solving challenges with found attack vector, but also by googling and testing attack vectors that challenges were not vulnerable, which increased my overall cybersecurity awarness. I have noted few interesting findings:

- You can actually exfiltrate data over DNS and capture it for Data Leakage
- A Word document is actually a zip archive, and has the same file signature
- Custom encryption schemas are scarry
- Yet another proof that PHP is vulnerable by design :)
- If a scheduled task/bot accesses a web page with admin permissions, that is vulnerable to XSS, you can steal its cookie by hosting a cookie stealer online.
- There are much easier method to write shellcodes and pwn vulnerable services than msfvenom/writing custom assembly code
- Python dependencies for unmaintained/old packages are pain to deal with on Arch...


## Writeups

Still learning jekyll, will include links here later (for now see my blog posts)
