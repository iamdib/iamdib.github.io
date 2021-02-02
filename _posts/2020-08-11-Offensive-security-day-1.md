---
layout: post
title: "Offensive Security Part 1"
categories: offsec
tags: offsec
permalink: /offsec/ospt1/
author: "dib"
---
> "Arguing that you don’t care about the right to privacy because you have nothing to hide is no different than saying you don’t care about free speech because you have nothing to say." <br>-- Edward Snowden


Today is about gauging our knowledge how well we know about networking, linux skills, web apps, etc.

It is a requirement that you should know some basic fundamentals before taking this class such as

Networking:
- OSI Model
- TCP/IP
- Classification of networks
- TCP flags/headers, ICMP flags/headers
- IP Subnets

On acquiring Linux skills you should know the following:
- Basic commands
- Advanced commands (awk, cut, grep, xxd, bzip, gzip, tar, find, sed, etc.)
- Have done exercises such as "Bandit"
- Linux administration

Windows skills
- Basic commands
- Windows administration
- Known exploits (mimikatz, impacket, etc.)

Web Application Security:
- How client and server side works
- Web servers
- CMS
- Critical Vulns

Databases:
- SQL (Tutorialpoint)
- MSSQL
- MySQL
- Postgresql
- Oracle SQL

Active directory:
- AD implementation
- Kerberos
- TGT, TGS

Buffer overflow:
- Stack based

Red team:
social engg +Spear phishing + physical breach + identiy theft + from unkown user to AD + Database admin with evading the SOC systems

**When you type google.com from your laptop/computer  in the browser, how exactly does it work ??**

1. Browser cache 
2. ISP - DNSserver --> google.com --> A/AAA records  
3. Server  -->  Web server --> (Guard1 CGI)-> (slave-SSI) --? files/folders inside web servers -->> (Slave SSI will pick the info ) >> CGI --> (Second guard DOM) -- DOM will organize the data as per the user agent and screensize
4. Page loaded on browser screen 

Recommended to learn: https://www.lynda.com/Web-Foundations-tutorials/Web-Technology-Fundamentals/158666-2.html

**How NMAP really works?**

1. nmap will ping the target
2. nmap send a DNS resolution
3. arp ping
4. send a syn packet
5. by default nmap is doing a stealth scan (half open scan - means when syn-ack is finished it will stop sending ack packet)
6. send bunch of probes in top 1000 ports
7. based on the response, you will see if ports are open or closed

nmap designed by lua language - database - contains bunch of packet reserves


nmap -Pn - means no ping
nmap -n - means no dns resolution - even save your time
--disable -arping - save time
