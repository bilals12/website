---
title: "evasion techniques in macOS"
date: 2024-10-22T11:24:15-04:00
draft: true
type: "post"
---

expanding upon red-teaming macOS from the previous post, i've been learning how evasion (and detection) works on macs. as you may know, apple is notorious for not documenting their internals (not surprising given how aggressively closed-source they are), so public knowledge around this topic is nebulous, and relies a lot on either outdated information or expensive courses taught by experts in the field.

security folks used to rely on EDRs and `auditd` for logging/IR insights (<10.15), but Apple has since then deprecated kernel extensions. this is mostly to increase kernel stability.

there exists now an Endpoint Security Framework (ESF), which provides an API for different capabilities. to access ESF data, a developer's application must possess the `com.apple.developer.endpoint-security.client` entitlement, which is only given out by Apple themselves.

Apple uses "Event Types" in messages to determine the details of specific Endpoint Security events. you can see the complete list [here](https://developer.apple.com/documentation/endpointsecurity/event_types).

most of these focus heavily on process/file related events, and less so into network related ones. devs are directed to using networking extensions, instead.

one of these events is `es_event_uipc_connect_t`, which describes the socket domain, type, protocol, and file bound to the socket.

there are also no event types for IPC communications. this results in attackers using XPC (more on this later) to control `LaunchAgents` or daemons, or RPCs. 

sidebar: XPC (XNU inter-Process Communication) is a macOS framework that enables secure and efficient communication between processes. it enhances security by isolating functionalities into separate processes, limiting permissions, and ensuring that crashes in one component do not affect the entire system. XPC is widely used by Apple and third-party applications, such as Safari and Xcode, to improve stability and performance through concurrent task execution. devs create XPC services by setting up a listener and client, defining service interfaces with protocols, and managing connections, all while benefiting from modular design and enhanced security features.

RPC stands for Remote Procedure Call, which is a protocol that allows a program to request a service from a program located on another computer within a network. this communication method enables one computer to execute code on behalf of another, effectively allowing local programs to offload tasks to remote servers and receive results as if they were processed locally. RPCs operate using a client-server model, where the client sends instructions and parameters to the server, which executes the requested procedure and returns the result. Various protocols, such as XML-RPC and JSON-RPC, implement RPCs by formatting messages in specific ways. Despite being used to facilitate distributed systems, RPCs maintain the appearance of local procedure calls, offering transparency in execution while managing complexities like data marshaling and network communication behind the scenes.

other ways attackers work is by spawning new processes with a parent PID of 1, or by avoiding command-line logging, as some commands trigger alerts:

```bash
screencapture
kcc
id /whoami /launchctl -w load
python -c 'import base64;...'
curl | sh
echo "base64" | base64 -D | sh
osascript -l JavaScript
```



