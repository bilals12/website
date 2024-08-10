---
title: "violaTor"
date: 2023-12-21T11:17:54-05:00
draft: false
type: "post"
---

![art](/violaTorArt.png)

since splurging on a new macbook m3 pro, that came with a 12-core CPU, 18-core GPU, 16-core neural engine, and 36GB of RAM, i thought to myself: i should probably use this to train some version of a local AI (LLM) i can use to boost my security and hacking toolchains, namely SAST/DAST and vulnerability scanning. thus began my journey into acquiring the perfect flavours of AI that were ideal for how i work (iteratively but in bursts, and lots of back and forth). i won't go into too much detail about my exact setups, as that's more appropriate for a separate post, but here's a general overview:

1. LLM #1: [deepseek-coder-6.7b](https://huggingface.co/deepseek-ai/deepseek-coder-6.7b-instruct) over [codellama-13b-instruct](https://huggingface.co/codellama/CodeLlama-13b-Instruct-hf)

2. LLM #2: [mixtral-7b-instruct](https://huggingface.co/mistralai/Mistral-7B-Instruct-v0.2)

3. LLM #3: [qwen-7b-chat](https://huggingface.co/Qwen/Qwen-7B-Chat-Int4)

4. prompt all three LLMs, and then use a majority consensus script to rate the highest answer (works only for reasoning questions, not so much programming...yet)

5. when it comes to analyzing and/or writing attackware, the LLMs are rightfully hesitant, and may also outright refuse. in this case, it helps to know how to write it yourself and get advice/suggestions on specific functions that may need to be refactored. a harsh attitude may sometimes work in forcing the LLM to respond, but with a personalized setup like mine, a slower, gentler attitude seems to work, for now.

here's a (very) basic example of how deepseek responds when prompted to create a simple botnet.

![deepseek](/deepseek.png)

**disclaimer**: this was an incredibly interesting and exciting project, but i wrote this post with some hesitation. for legal reasons, the code provided on my github is intentionally broken/truncated in parts to stop it from working off rip. however, i've left most of the functionality intact so the public can learn from it, and the security community can learn to protect themselves from it and similar attacks. 

**disclaimer**: this post was authored with the help of my 3 LLMs (all models found on huggingface).

you can view the code on my [github](https://github.com/bilals12/violaTor). have a look and read alongside the blog to get a better understanding!

# the violaTor network

i wrote this botnet program in 3 parts:

1. `violaBot.c`: the main bot client script responsible for controlling the compromised systems (`zombies`).

2. `Tor.c`: the zombie master, aka the command-and-control (C2) server.

3. `builder.py`: a python script that compiles the botnet code for various architectures and sets up the necessary environment for the botnet to operate.

i wanted to create a program that built on and expanded my understanding of network programming and system-level operations, so there are a few characteristics that make this program particularly nasty.

1. **distributed architecture**: most botnets utilize a distributed architecture. this allows them to control a large number of infected machines without overloading the central server (`Tor.c`) while the clients (`violaBot.c`) execute the commands and report back to the server. this architecture also provides resilience against takedowns, as removing one zombie doesn't affect the rest of the botnet.

2. **customizable + dynamic payloads**: the `builder.py` generates payloads dynamically, allowing the attacker to customize the payloads with different IP addresses and bot filenames. this makes it difficult for security systems to detect and block the payloads, as they can change with each generation. the generated payloads include shell scripts that download and execute the zombie on the target, connecting it to the C2 server. 

3. **multi-layered attack capabilities**: the botnet is equipped with multiple types of attack functions, which can launch a variety of attacks. for example, attacks like `ZDP` can be used to flood targets with traffic, potentially causing a denial-of-service. this versatility allows the botnet to adapt to different targets and situations, making it more potent than botnets with a single type of attack.

4. **robust connection management**: the C2 server (`Tor.c`) handles user authentication, command processing, and connection loss effectively. if the connection is lost, the server handles the disconnection and continues operating.

5. **stealth + persistence**: the client `violaBot.c` employs several techniques to maintain stealth and persistence on the infected machine (`zombie`). it changes the working directory to `/`, ignoring the `SIGPIPE` signal, and sets up a new session, all of which help the zombie evade detection and removal. 

6. **real-time monitoring**: the continuous update of the title in the terminal with the number of zombies and online users provides a real-time snapshot of the botnet's size and activity.

7. **multi-threaded design**: the `Tor.c` script uses multi-threading to handle multiple zombies simultaneously. this design allows the C2 server to scale and manage a large number of bots without blocking or slowing down.

8. **command encoding**: the `violaBot.c` script uses command encoding (`decode`) to interpret commands from the C2 server. this adds an extra layer of obfuscation, making it harder for security analysts to understand the botnet's behaviour.

9. **resource management**: example: the `violaBot.c` script frees up memory allocated for command parameters after processing the command. this helps to prevent memory leaks, which can otherwise slow down the zombie and potentially reveal the bot's presence.

10. **error handling**: the program includes error handling mechanisms, such as checking the return values of functions and handling failed operations appropriately. this helps make the botnet more robust and less likely to crash due to errors.

11. **low-level network programming**: the program uses low-level network programming libraries (`sys/socket.h`, `netinet/in.h`, `arpa/inet.h`) to establish network connections and send/receive data. this gives the botnet fine-grained control over network operations and makes it more efficient.

# violaBot.c

this script is designed to connect to the C2 server, receive commands, and execute them.

it includes a variety of libraries necessary for its operation:

- network communication: `<sys/socket.h>`, `<netinet/in.h>`, `<arpa/inet.h>`

- system calls: `<unistd.h>`, `<fcntl.h>`, `<sys/wait.h>`

- string manipulation: `<string.h>`, `<strings.h>`

it also sets the sizes for the various buffers used in network communication and command processing (`BUFFER_SIZE`, `SOCKBUF_SIZE`, `PRINT_BUF_LEN`). 

the script defines several global variables that store the state of the bot client. 
- the `mainCommSock` variable stores the main communication socket descriptor, which is used for communicating with the C2 server. 

- the `currentServer` variable stores the index of the current server in the server list.

- the `gotIP` flag indicates whether the bot has obtained its IP address.

- the `pids` pointer and `numpids` counter are used to store and track the PIDs of child processes created by the bot.

- the `MyIP` struct stores the bot's IP address.

the client needs to interpret and execute commands received from the C2 server, so i created a function `processCmd`, which takes a command string, tokenizes it into parameters using the `strtok` function, and checks the command name against a list of known commands. if a match is found, it calls the corresponding function to execute the command.

launching multiple attacks simultaneously is integral to a botnet's effectiveness. for this purpose, there are several functions (`sendZgo`, `send0vhBypass__`, `sendZDP`) that launch different types of attacks. they take parameters like the target's IP, port, and duration of the attack, then use the `listFork()` to create a new process for each attack.

the main loop of the script is responsible for maintaining the connection to the C2 server and processing commands. it uses `initConnection` to establish a connection to the server, and waits 5 seconds before trying again if the connection fails. once the connection is established, it continuously reads from the socket, trims the received command, and passes it to `processCmd` for execution.

the bot client uses several techniques to maintain stealth and persistence on the zombie. it changes its working directory to `/`, making it harder to find the bot client's files. it ignores the `SIGPIPE` signal, preventing the bot client from terminating if it tries to write to a disconnected socket. it also sets up a new session using the `setsid` function, detaching the bot client from its parent process and making it harder to terminate.

finally, the script includes proper error handling and resource management. this just means it checks the return values of functions and handles failed operations so it doesn't crash due to errors. it then frees up memory allocated for command parameters after processing the command, preventing memory leaks that can slow down the zombie and reveal the bot.

# Tor.c

the `Tor.c` script serves as the zombie master (C2) server in the botnet system. it manages connections from clients, processes commands from users, and sends commands to its zombies.

1. **user authentication**: the script uses a simple but effective authentication mechanism to ensure that only authorized users can interact with the botnet. the `strcmp` function is used to compare the entered password (`buf`) with the stored password (`accounts[find_line].password`). if the passwords don't match, the `goto` statement jumps to the `failed` label, which then disconnects the client. this mechanism is implemented in the `clientWorker` function, which handles interactions with each connected client.

2. **`TitleWriter`**: this function is a separate thread that runs in an infinite loop, updating the title in the terminal every second. it uses the `sprintf` function to format a string that includes the number of connected bots (`clientCount`) and the number of clients (`managersCount`). the `write` function is used to update the terminal title with this string, which provides a real-time update on the size of the botnet.

3. **command handling**: implemented in the `clientWorker` function. it uses the `FD_ISSET` function to check if there's data to read from the client's socket. if there is, it reads the data into a buffer (`buf`) and then uses a series of `if` statements to check for specific command. for example, if the `STATS` command is detected, it uses the `sprintf` and `send` functions to send back a string that includes the number of connected bots and the number of clients.

4. **banner display**: self-explanatory. once authentication is successful, a banner is sent to the client. this is just to provide a user-friendly interface.

5. **connection management**: handled in the `main` function. it uses the `socket`, `setsockopt`, `bind`, and `listen` functions to set up a socket that listens for incoming connections. when a bot client connects (`accept`), the server adds the client's IP address to its list of connected clients (`clientList`) and starts a new thread (`pthread_create`). [*note*: for concurrency control, a mutex (`pthread_mutex_t`) is used to control access to shared resources (like `clientList`) among multiple threads. this prevents race conditions and ensures that the server operates correctly when handling multiple clients simultaneously.] 

6. **multi-threading**: the `pthread` library is used for this.

7. **signal handling**: a signal handler for the `SIGPIPE` signal is included. this signal is sent to a process when it tries to write to a socket that has been closed on the other end. by ignoring this signal (`signal(SIGPIPE, SIG_IGN)`), the script prevens the server from crashing when it tries to write to a disconnected client socket.

8. **error handling**: error handling mechanisms to make the botnet more robust. for example, `socket`, `bind`, `listen`, `accept` all return a value that is checked against `-1` (error). if an error is detected, the `perror` function is used to print a descriptive error message and the `exit` function is used to terminate the program.

# builder.py

this is a builder script for generating payloads. it's designed to create customized payloads that, when executed on a target, install and run the bot client.

1. **imports + constants**: the script imports necessary python libraries such as `os` for interacting with the operating system, `sys` for accessing system-specific parameters and functions, and `random` for generating random numbers. it also defines several constants used in the script. for instance, `PAYLOAD_NAME` specifies the name of the payload file, `PAYLOAD_DIR` specifies the directory where the payload files will be stored, `SERVER_LIST` is a list of server IP addresses and ports, and `ARCHS` is a list of architectures for which the payloads will be generated.

2. **payload generation**: the `generate_payload` function generates a shell script that, when executed on a target machine, downloads and runs the bot client. it uses python's string formatting to insert the server IP, port, and architecture into the shell script. the shell script uses `wget` and `curl` to download the bot client from the server, `chmod` to make the downloaded file executable, and `./` to run the executable file.

3. **main function**: the main function of the script loops over each server in the server list and each architecture in the architecture list, calling the `generate_payload` function with the server IP, port, and architecture as parameters. it then writes the generated payload to a file using python's built-in `open` function with the 'write' mode (`w`).

4. **file operations**: the script uses the `os.path.exists` function to check if the payload directory exists, and the `os.makedirs` function to create the directory if it doesn't exist. it then uses the `open` function to create a file in the payload directory for each payload, and the `write` method to write the payload to the file.

5. **randomization**: the script uses the `random.choice` function to randomly select a server from the server list for each payload. this adds an element of unpredictability to the payloads, making it harder for security systems to predict and block them.

# remediation

a botnet like this isn't particularly unique. there are thousands, if not millions, just like it floating around on the internet, just looking for victims. 

1. **network monitoring and intrusion detection systems (IDS)**: network monitoring involves analyzing network traffic to identify anomalies or suspicious activities. an IDS can automatically detect potential threats based on predefined rules or unusual patterns. for instance, repeated attempts to connect to the same IP address or port, or a sudden spike in outbound traffic, could indicate botnet activity. IDS solutions can be signature-based (detecting known threats) or anomaly-based (detecting deviations from normal behavior).

2. **endpoint protection solutions**: endpoint protection solutions provide a suite of security capabilities for individual devices (endpoints), such as antivirus, antispyware, firewall, and intrusion detection functionalities. they can detect and block malicious activities, including the installation and operation of bot clients. advanced solutions may also include behavioral analysis to detect unknown threats.

3. **firewall configuration**: firewalls can be configured to block outgoing connections to the IP addresses and ports used by the C2 servers. this can be done by setting up outbound rules in the firewall to deny traffic to these addresses and ports. by blocking these connections, the bot client is prevented from receiving commands, effectively neutralizing it.

4. **regular system scans**: regular system scans can help detect the presence of the bot client on the system. antivirus software or other malware detection tools can be used for this purpose. these tools scan the system's files and memory for known malicious signatures or suspicious behavior. if the bot client is detected, it should be removed immediately using the tool's removal function.

5. **user education**: users should be educated about the dangers of downloading and running unknown files, as this is a common way for bot clients to be installed. they should be taught to only download files from trusted sources and to avoid clicking on suspicious links. phishing attempts, which can deliver the bot client via email attachments or malicious links, should also be covered in security awareness training.

6. **software updates and patching**: keeping all systems and software updated with the latest patches is crucial for preventing botnet infections. many bot clients exploit known vulnerabilities in software to gain unauthorized access or escalate privileges. regular updates and patches fix these vulnerabilities, making these exploits ineffective.

7. **access controls**: implementing strict access controls can limit the potential impact of a bot client. this includes using least privilege principles, where users are given the minimum levels of access necessary to perform their duties. this can prevent the bot client from gaining access to sensitive data or critical systems.

8. **incident response plan**: an incident response plan provides a structured approach for dealing with botnet infections. it should include steps for detecting the infection, containing the damage, eradicating the bot client, and recovering from the attack. the plan should also include communication protocols for notifying affected parties and reporting the incident to relevant authorities.