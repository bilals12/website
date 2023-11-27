---
title: "gdbExtract"
date: 2023-11-27T13:43:26-05:00
draft: false
---

over the past few days, i've been writing tools that automate cumbersome manual tasks and make my workflow/toolchain cleaner and pushing them to my personal github. the latest one in this series is a tool i call **![gdbExtract](https://github.com/bilals12/gdbExtract)**.

as a security researcher, i spend a lot of time diving deep into the worlds of software security and system analysis. in these domains, binary analysis and reverse engineering are critical tasks, but their challenging and complex nature can come across as intimidating. hackers rely on this fact to conceal a myriad of functions inside binaries that perform unwanted actions, but this tool can help shed some light on them. it's not exactly a replacement for popular and powerful applications like IDA Pro, but it's a quick way to reveal hidden and integral information about binaries. 

## gdbExtract

gdbExtract is, first and foremost, an automation tool. it was created to streamline the tedious process of binary analysis. manually examining binaries using tools like `GDB` requires significant effort and expertise. `gdbExtract` automates the extraction of crucial function information, transforming a potentially labour-intensive task into a quicker and more reliable process.

- efficiency: automating the extraction process saves time but also ensures consistent results (crucial when dealing with multiple or large binaries).
- structured output: by outputting data in a JSON format, the script turns raw, hard-to-parse information into a structured form, paving the way for more advanced analysis techniques.
- versatility and accessibility: the script is designed to be noob-friendly but can also help seasoned professionals.

## core functionalities
**note**: before running, edit the script to point to your specific binary file and output file. there's also a list of "unsafe" function strings, that you can edit to fit your criteria.

# analysis
the script is great for quickly sifting through binaries to identify potential vulnerabilities. 
1. run `python gdbExtract.py search` to extract a comprehensive list of functions from the binary.
2. running `python gdbExtract.py remove-safe` afterwards will filter out the "known" safe functions, narrowing the focus toward more critical areas.

extracted data might look something like this.
```json
[
    {
        "address": "0x00401350",
        "name": "main",
        "signature": "int main()"
    },
    {
        "address": "0x00401390",
        "name": "helper_function",
        "signature": "void helper_function(int)"
    }
]
```

# reverse engineering
it can also dissect a binary so the user can understand its behavior or uncover hidden functionalities.

after extracting function data, run `python gdbExtract.py combine` to identify duplicate functions, which might indicate areas of complexity or reuse of code worth exploring.

# education
it can aid instructors or teachers in explaining the structure and intricacies of binaries in a practical manner.
1. run `python gdbExtract.py list` to explore the different functions within a binary.

the output can look something like this.
```bash
0x00401350: main
0x00401390: helper_function
```

2. run `python gdbExtract.py find` to search for specific functions. this can demonstrate how functions relate to each other.

```bash
enter a function address or name: main
found 0x00401350: main
```

## corner cases
every tool has its limitations. `gdbExtract` might not effectively parse binaries that utilize heavily obfuscated code. also, its reliance on GDB means it inherits any limitations present within GDB, such as handling certain types of binaries or specific configs.

## thought experiment
let's say i'm a security researcher (i am lol), and i want to assess the security of a legacy communications software that my organization has been using for over a decade. i suspect that the software might contain undiscovered vulnerabilities.

1. running the script
- i quickly `python gdbExtract.py search` to analyze the binary (specified in `BINARY_PATH`).
- it will output a comprehensive list of all functions within the binary, complete with their memory addresses and signatures.
- i now have a clear and structured overview of the binary's functions + hours of saved time.

2. filtering safe functions
- run `python gdbExtract.py remove-safe` to streamline the dataset.
- this will isolate functions that warrant closer scrutiny.
- it filters out functions that were pre-identified as "safe", based on individual critieria (in this case, i've excluded standard library functions and those without direct external input handling).
- i now have a manageable list of functions that are labeled "high-risk" (related to network data handling, memory manipulation, etc).

3. identification
- i come across a function called `processClientRequest`.
- this function handles incoming data packets from network clients, interacting directly with external data.

diving into the source code of the `processClientRequest` function, i discover that it uses `strcpy` to data from the network buffer to a local buffer. this is an immediate red flag, as `strcpy` doesn't check the size of the destination buffer, making it vulnerable to buffer overflow attacks if the source data exceeds the buffer's capacity. even worse, `processClientRequest` lacked any checks on the size of the incoming data, meaning it blindly copied whatever was sent over the network into the local buffer.

4. constructing a proof-of-concept
- i create a network packet with data significantly larger than the buffer size inside the `processClientRequest` function (have it contain a specific pattern that's easily identifiable in the memory if it overflows, like `AAAAAAAA`).
- i then send the packet to a controlled environment (VM) using the legacy software and monitor the memory state of the software as it processes the packet (Immunity Debugger is great for this).
- as expected, the packet causes a buffer overflow and overwrites the adjacent memory.
- this can be confirmed by checking for the pattern in memory locations outside the buffer.
- the packet can be modified to include a simple payload that would then write itself into the program memory.

5. remediation
- replace `strcpy` with `strncpy`, which includes buffer size as an argument, ensuring copied data does not exceed buffer limit.
- use checks to validate the size of incoming data before processing it.
- review the code with the help of 1 or more code reviewers, and test it using various packet sizes.


hope this tool finds you well! feel free to leave comments on my github and explore some of my other programs as well. 