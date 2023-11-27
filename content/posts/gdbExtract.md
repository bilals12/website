---
title: "gdbExtract"
date: 2023-11-27T13:43:26-05:00
draft: false
---

over the past few days, i've been writing tools that automate cumbersome manual tasks and make my workflow/toolchain cleaner and pushing them to my personal github. the latest one in this series is a tool i call **[gdbExtract](https://github.com/bilals12/gdbExtract)**.

as a security researcher, i spend a lot of time diving deep into the worlds of software security and system analysis. in these domains, binary analysis and reverse engineering are critical tasks, but their challenging and complex nature can come across as intimidating. hackers rely on this fact to conceal a myriad of functions inside binaries that perform unwanted actions, but this tool can help shed some light on them. it's not exactly a replacement for popular and powerful applications like IDA Pro, but it's a quick way to reveal hidden and integral information about binaries. 

**gdbExtract** is, first and foremost, an automation tool. it was created to streamline the tedious process of binary analysis. manually examining binaries using tools like `GDB` requires significant effort and expertise. `gdbExtract` automates the extraction of crucial function information, transforming a potentially labour-intensive task into a quicker and more reliable process.

- efficiency: automating the extraction process saves time but also ensures consistent results (crucial when dealing with multiple or large binaries).
- structured output: by outputting data in a JSON format, the script turns raw, hard-to-parse information into a structured form, paving the way for more advanced analysis techniques.
- versatility and accessibility: the script is designed to be noob-friendly but can also help seasoned professionals.

# core functionalities
**note**: before running, edit the script to point to your specific binary file and output file. there's also a list of "unsafe" function strings, that you can edit to fit your criteria.

here's the script in its entirety.

```python
import os
import sys
import json
import subprocess
import logging
from typing import List, Dict


# configure basic logging to display errors and info
logging.basicConfig(level=logging.INFO)

# constants for file paths and binary to be analyzed
BINARY_PATH = "/path/to/binary"
DATA_FILE = "path/to/file.json"
riskyFunctions = ['strcpy', 'strncpy', 'memcpy', 'memset', 'send', 'recv']

# GDB command to list all functions in binary
# returns output from GDB as string
def run_gdb_command(binary_path: str) -> str:
	try:
		return subprocess.check_output(["gdb", "-batch", "-ex", "info functions", binary_path])
	except subprocess.CalledProcessError as e:
		logging.error(f"GDB command failed: {e}")
		sys.exit(1)

# parse output from GDB to extract function info
# returns list of dicts, each containing details of single function
def parse_gdb_output(gdb_output: str) -> List[Dict]:
	json_data = []
	for line in gdb_output.splitlines():
		if not line.startswith("0x"): continue
		address, name, signature = line.strip().split()
		json_data.append({"address": address, "name": name, "signature": signature})
	return json_data

# reads json file and returns content
def read_json_file(file_path: str) -> List[Dict]:
	try:
		with open(file_path, "r") as file:
			return json.load(file)
	except IOError as e:
		logging.error(f"error reading file {file_path}: {e}")
		return []
	except json.JSONDecodeError as e:
		logging.error(f"error decoding JSON from file {file_path}: {e}")

# writes list of dicts to json file
def write_json_file(file_path: str, data: List[Dict]):
	try:
		with open(file_path, "w") as file:
			json.dump(data, file, indent=4) # indentation for readability
	except IOError as e:
		logging.error(f"error writing to file {file_path}: {e}")

# main function that extracts function info from binary via GDB
def main_search_code():
	gdb_output = run_gdb_command(BINARY_PATH)
	json_data = parse_gdb_output(gdb_output)
	write_json_file(DATA_FILE, json_data)

# filters out functions deemed "safe" and writes the rest to new json file
def remove_safe_functions():
	json_data = read_json_file(DATA_FILE)
	filtered_json_data = [func for func in json_data if func['name'] not in riskyFunctions]
	write_json_file("filtered_file.json", filtered_json_data)

# combines multiple entries of the same function into a single record
# tracks number of occurrences of each function
def combine_data_for_same_function():
	json_data = read_json_file("filtered_file.json")
	combined_json_data = {}
	for func in json_data:
		if func["name"] not in combined_json_data:
			combined_json_data[func["name"]] = {
			"addresses": [func["address"]],
			"signature": func["signature"],
			"count": 1,
			}
		else:
			combined_json_data[func["name"]]["addresses"].append(func["address"])
			combined_json_data[func["name"]]["count"] += 1

	write_json_file("combined_file.json", combined_json_data)

# lists all functions in json data file
def list_functions():
	json_data = read_json_file(DATA_FILE)
	for func in json_data:
		print(f"{func['address']}: {func['name']}")

# searches for specific function in json data file by address or name
def search_function():
	json_data = read_json_file(DATA_FILE)
	func_addr_name = input("enter a function address or name: ")
	found = False
	for func in json_data:
		if func["address"] == func_addr_name or func["name"] == func_addr_name:
			print(f"found {func['address']}: {func['name']}")
			found = True
			break
	if not found:
		print(f"could not find function with address or name '{func_addr_name}'.")

# main entry point
# handles cli args and calls corresponding functions
def main():
	# check if correct number of args are passed
	if len(sys.argv) == 2:
		command = sys.argv[1]
		# execute function based on arg
		if command == "search":
			main_search_code()
		elif command == "remove-safe":
			remove_safe_functions()
		elif command == "combine":
			combine_data_for_same_function()
		elif command == "list":
			list_functions()
		else:
			logging.error("unknown command. please enter a valid option.")
			sys.exit(1)
	else:
		logging.error("incorrect number of args.")
		sys.exit(1)

# run script only if script is executed as main program
if __name__ == "__main__":
	main()
```

## analysis
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

## reverse engineering
it can also dissect a binary so the user can understand its behavior or uncover hidden functionalities.

after extracting function data, run `python gdbExtract.py combine` to identify duplicate functions, which might indicate areas of complexity or reuse of code worth exploring.

## education
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

# corner cases
every tool has its limitations. `gdbExtract` might not effectively parse binaries that utilize heavily obfuscated code. also, its reliance on GDB means it inherits any limitations present within GDB, such as handling certain types of binaries or specific configs.

# thought experiment
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