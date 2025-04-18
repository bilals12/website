---
title: "reverse engineering malware in a container - part 1"
date: 2025-04-17T19:02:19Z
draft: false
toc: true
next: true
nomenu: false
notitle: false
---

![r2](/r2.png)

part of the attack sim from the [last post](https://bsssq.xyz/posts/kube/) was an eBPF module that provided extended kernel-level monitoring and interference with processes. i thought it would be fun to reverse engineer it in a restricted environment, like a docker container.

## container

the Dockerfile for the container is loaded with analysis tools.

```dockerfile
FROM ubuntu:20.04

# avoid interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

# install essential tools for binary analysis
RUN apt-get update && apt-get install -y \
    binutils \
    file \
    strace \
    ltrace \
    gdb \
    radare2 \
    python3 \
    python3-pip \
    python3-venv \
    bsdutils \
    xxd \
    build-essential \
    procps \
    elfutils \
    libcapstone-dev \
    curl \
    wget \
    unzip \
    git \
    nano \
    vim \
    tcpdump \
    tshark \
    iputils-ping \
    net-tools \
    sudo \
    golang \
    binutils-dev \
    libbfd-dev \
    libz-dev \
    python3-dev \
    default-jre-headless \
    cmake \
    # add these eBPF analysis tools
    bpfcc-tools \
    linux-headers-generic \
    linux-tools-generic \
    bpftrace \
    util-linux \
    # add dependencies for building bpftool
    libelf-dev \
    # install bsdmainutils for hexdump
    bsdmainutils \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# install bpftool (if not included in linux-tools)
RUN git clone --recurse-submodules https://github.com/libbpf/bpftool.git /opt/tools/bpftool && \
    cd /opt/tools/bpftool/src && \
    make && make install && \
    cd / && rm -rf /opt/tools/bpftool

# install Python tools for analysis
RUN pip3 install frida-tools pwntools capstone unicorn r2pipe bcc pyroute2

# create analysis directories
RUN mkdir -p /analysis/samples /analysis/output

# create a non-root user for analysis with sudo privileges
RUN useradd -m -s /bin/bash analyst && \
    echo "analyst ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/analyst && \
    chmod 0440 /etc/sudoers.d/analyst

# setup additional analysis tools
RUN mkdir -p /opt/tools && \
    chmod 777 /opt/tools

# set up Go environment
ENV GOPATH=/opt/go
RUN mkdir -p $GOPATH/bin $GOPATH/src $GOPATH/pkg && \
    chmod -R 777 $GOPATH

# install Go tools
RUN go install github.com/sibears/IDAGolangHelper@latest || echo "Failed to install Go helper"
RUN go install github.com/goretk/redress@latest || echo "Failed to install redress"

# create an entrypoint script to handle privileges for eBPF analysis
RUN echo '#!/bin/bash\n\
if [ -f /analysis/samples/www ]; then\n\
  sudo setcap cap_bpf,cap_sys_admin,cap_sys_resource=+eip /analysis/samples/www 2>/dev/null || echo "Note: www binary not found or capabilities could not be set"\n\
fi\n\
exec "$@"' > /entrypoint.sh && \
    chmod +x /entrypoint.sh

USER analyst
WORKDIR /analysis

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/bin/bash"]
```

## initial analysis

once the container was spun up, i started with some very basic analysis.

```bash
root@2cd71e85b7e8:/analysis# file www

www: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=b575e4593e6b5f037629b61f88bdc43bdec918d5, for GNU/Linux 3.2.0, not stripped
```

this `www` binary (the malicious eBPF program) is an ELF 64-bit LSB executable, for x86-64 architecture. it's statically linked, which means it contains all the libraries within itself, and it doesn't depend on external libraries to run. it's also not stripped, which is good for us because the symbol information is preserved. 

let's take a look at some of the strings from the binary.

```bash
strings -n 8 www | grep -E '(http|socket|connect|execv|system|fork)' | head -20
```

the `strings` command extracts all sequences of at least 8 printable characters from the binary. the `grep` filters the extracted strings that match the keywords. since i know this is an eBPF module, i'm looking for strings associated with networking and process execution. the `head` command only displays the first 20 (matching) lines.

```bash
root@2cd71e85b7e8:/analysis# strings -n 8 www | grep -E '(http|socket|connect|execv|system|fork)' | head -20
Interrupted system call
Too many open files in system
Read-only file system
Interrupted system call should be restarted
Socket operation on non-socket
Protocol wrong type for socket
Network dropped connection on reset
Software caused connection abort
Transport endpoint is already connected
Transport endpoint is not connected
system bytes     = %10u
<system type="current" size="%zu"/>
<system type="max" size="%zu"/>
<system type="current" size="%zu"/>
<system type="max" size="%zu"/>
/sys/devices/system/cpu/online
/sys/devices/system/cpu
system search path
TLS generation counter wrapped!  Please report as described in <https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
system_dirs
```

pretty standard error messages and paths. the lines containing the tags are probably just from memory management or reporting functions. the path `/sys/devices/system/cpu` is clearly related to CPU information gathering.

let's check for strings that may contain "eBPF".

```bash
root@2cd71e85b7e8:/analysis# strings www | grep -E '(bpf|eBPF)'
eBPF program loaded successfully
ebpf.c
```

again, confirmation that this is definitely eBPF related.

## sections and headers

here i'll run the `readelf` command. the `readelf -a` command displays all available information about an ELF files. this includes headers, sections, segments, symbols, dynamic linking information, relocation entries, and more. we'll try to narrow down the output.

```bash
root@2cd71e85b7e8:/analysis# readelf -h www
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 03 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - GNU
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x401650
  Start of program headers:          64 (bytes into file)
  Start of section headers:          907608 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         10
  Size of section headers:           64 (bytes)
  Number of section headers:         32
  Section header string table index: 31
```

we can see that some information that we got from the `file` command, but we some more stuff: 

1. the entry point is at `0x401650`

2. the binary contains 32 section headers and 10 program headers

let's take a look at the headers. 

```bash
root@2cd71e85b7e8:/analysis# readelf -S www
There are 32 section headers, starting at offset 0xdd958:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .note.gnu.propert NOTE             0000000000400270  00000270
       0000000000000030  0000000000000000   A       0     0     8
  [ 2] .note.gnu.build-i NOTE             00000000004002a0  000002a0
       0000000000000024  0000000000000000   A       0     0     4
  [ 3] .note.ABI-tag     NOTE             00000000004002c4  000002c4
       0000000000000020  0000000000000000   A       0     0     4
  [ 4] .rela.plt         RELA             00000000004002e8  000002e8
       0000000000000240  0000000000000018  AI      29    20     8
  [ 5] .init             PROGBITS         0000000000401000  00001000
       000000000000001b  0000000000000000  AX       0     0     4
  [ 6] .plt              PROGBITS         0000000000401020  00001020
       0000000000000180  0000000000000000  AX       0     0     16
  [ 7] .text             PROGBITS         00000000004011c0  000011c0
       0000000000095ab8  0000000000000000  AX       0     0     64
  [ 8] __libc_freeres_fn PROGBITS         0000000000496c80  00096c80
       00000000000014cd  0000000000000000  AX       0     0     16
  [ 9] .fini             PROGBITS         0000000000498150  00098150
       000000000000000d  0000000000000000  AX       0     0     4
  [10] .rodata           PROGBITS         0000000000499000  00099000
       000000000001cb6c  0000000000000000   A       0     0     32
  [11] .stapsdt.base     PROGBITS         00000000004b5b6c  000b5b6c
       0000000000000001  0000000000000000   A       0     0     1
  [12] .eh_frame         PROGBITS         00000000004b5b70  000b5b70
       000000000000bb78  0000000000000000   A       0     0     8
  [13] .gcc_except_table PROGBITS         00000000004c16e8  000c16e8
       0000000000000124  0000000000000000   A       0     0     1
  [14] .tdata            PROGBITS         00000000004c37b0  000c27b0
       0000000000000020  0000000000000000 WAT       0     0     8
  [15] .tbss             NOBITS           00000000004c37d0  000c27d0
       0000000000000048  0000000000000000 WAT       0     0     8
  [16] .init_array       INIT_ARRAY       00000000004c37d0  000c27d0
       0000000000000008  0000000000000008  WA       0     0     8
  [17] .fini_array       FINI_ARRAY       00000000004c37d8  000c27d8
       0000000000000008  0000000000000008  WA       0     0     8
  [18] .data.rel.ro      PROGBITS         00000000004c37e0  000c27e0
       0000000000003788  0000000000000000  WA       0     0     32
  [19] .got              PROGBITS         00000000004c6f68  000c5f68
       0000000000000098  0000000000000000  WA       0     0     8
  [20] .got.plt          PROGBITS         00000000004c7000  000c6000
       00000000000000d8  0000000000000008  WA       0     0     8
  [21] .data             PROGBITS         00000000004c70e0  000c60e0
       00000000000019e0  0000000000000000  WA       0     0     32
  [22] __libc_subfreeres PROGBITS         00000000004c8ac0  000c7ac0
       0000000000000048  0000000000000000 WAo       0     0     8
  [23] __libc_IO_vtables PROGBITS         00000000004c8b20  000c7b20
       0000000000000768  0000000000000000  WA       0     0     32
  [24] __libc_atexit     PROGBITS         00000000004c9288  000c8288
       0000000000000008  0000000000000000 WAo       0     0     8
  [25] .bss              NOBITS           00000000004c92a0  000c8290
       0000000000005980  0000000000000000  WA       0     0     32
  [26] __libc_freeres_pt NOBITS           00000000004cec20  000c8290
       0000000000000020  0000000000000000  WA       0     0     8
  [27] .comment          PROGBITS         0000000000000000  000c8290
       000000000000002b  0000000000000001  MS       0     0     1
  [28] .note.stapsdt     NOTE             0000000000000000  000c82bc
       0000000000001648  0000000000000000           0     0     4
  [29] .symtab           SYMTAB           0000000000000000  000c9908
       000000000000c798  0000000000000018          30   773     8
  [30] .strtab           STRTAB           0000000000000000  000d60a0
       0000000000007761  0000000000000000           0     0     1
  [31] .shstrtab         STRTAB           0000000000000000  000dd801
       0000000000000157  0000000000000000           0     0     1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  l (large), p (processor specific)
```

the `.text` section is at offset `0x4011c0`. this contains the executable code, and it's roughly 611 kB in size.

the `.rodata` section contains only read-only data, roughly 117 kB in size. we also have `.data` and `.bss` sections for writable data, and some debugging sections and symbol tables.

to look more carefully at the symbols:

```bash
readelf -s www
```

the output is too large to include here:

```bash
Symbol table '.symtab' contains 2129 entries
```

but it's not stripped! meaning all the symbolic debugging information is preserved. this will make reverse engineering significantly easier.

i'll share some notable sections from the table.

```bash
160: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS ebpf.c
```

this shows that an `ebpf.c` source file was compiled into the binary.

```bash
1092: 000000000041fd60   828 FUNC    GLOBAL HIDDEN     7 malloc
```

this shows the `malloc` function at address `0x41fd60`. very standard C library function.

```bash
1631: 0000000000401775   268 FUNC    GLOBAL DEFAULT    7 main
```

the `main()` function is at address `0x401775`, with a size of 268 B. this is relatively small, implying it might be primarily used to set up and invoke other components.


```bash
752: 000000000048ec10    59 FUNC    LOCAL  DEFAULT    7 openaux
753: 000000000048ec50   914 FUNC    LOCAL  DEFAULT    7 _dl_build_local_scope
754: 00000000004b5710    20 OBJECT  LOCAL  DEFAULT   10 __PRETTY_FUNCTION__.0
755: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS dl-init.o
756: 0000000000490250   232 FUNC    LOCAL  DEFAULT    7 call_init.part.0
757: 00000000004b57a0    10 OBJECT  LOCAL  DEFAULT   10 __PRETTY_FUNCTION__.0
758: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS dl-sym.o
759: 0000000000490b40    51 FUNC    LOCAL  DEFAULT    7 call_dl_lookup
760: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS crtstuff.c
761: 00000000004c16e4     0 OBJECT  LOCAL  DEFAULT   12 __FRAME_END__
```

this shows several `_dl_` symbols, which relate to dynamic loading. it confirms that the malware loads additional components at runtime.

```bash
1990: 0000000000499628     9 OBJECT  GLOBAL HIDDEN    10 _nl_default_default_domai
```

`_nl_default_default_domain` is related to GNU `gettext` libraries (or similar). these libraries are used for internationalization by managing translations and language domains.

side-not: internationalization (`i18n`) is the process of designing and developing software applications so they can be easily adapted to different languages and regions without requiring engineering changes to the source code. this typically involves:

1. separating user-facing text and locale-specific data (like date, time, currency formats) from the application logic

2. using resource files or message catalogs that can be translated into different languages

3. supporting various character encodings and cultural conventions

```bash
2005: 00000000004c6a78     8 OBJECT  GLOBAL HIDDEN    18 _dl_vdso_time
2006: 000000000044f980   256 FUNC    WEAK   HIDDEN     7 __fcntl
```

`VDSO` is virtual dynamic shared object, and it can be used to interface with the kernel directly.

## program discovery

i'll use the `bpftool` command to reveal the eBPF programs loaded in the kernel as a result of the malware.

```bash
root@2cd71e85b7e8:/analysis# bpftool prog list
2: cgroup_skb  name egress  tag 1da4f366d16522e1  gpl
        loaded_at 2609-11-06T12:03:29+0000  uid 0
        xlated 696B  jited 648B  memlock 4096B  map_ids 3,7,5,4,9
```

this program is of type `cgroup_skb` with the name `egress`. it's attached to `cgroups` to filter outgoing network traffic, and uses 5 maps (`3`, `7`, `5`, `4`, `9`) for configuration or data storage. this program probably controls what network connections are allowed out.

```bash
3: sched_cls  name compute_udpv6_csum  tag 39fa3d10bc12c297  gpl
        loaded_at 2609-11-06T12:03:29+0000  uid 0
        xlated 1192B  jited 920B  memlock 4096B
        btf_id 6
```

this is a `sched_cls` program called `compute_udpv6_csum`. it handles traffic classification for Quality of Service (QoS) with UDPv6 checksum computation, meaning it can be used for custom packet manipulation and/or monitoring.

```bash
4: kprobe  name kprobe__oom_kill_process  tag c62690bae6f7d239  gpl
        loaded_at 2025-04-17T12:28:56+0000  uid 0
        xlated 328B  jited 376B  memlock 4096B  map_ids 8
        btf_id 15
```

this is a `kprobe` program that hooks into the kernel's OOM (Out-Of-Memory) process killer. it monitors when processes are killed due to memory pressure, and uses map ID `8` to store information.

```bash
5: lsm  name socket_connect  tag a6e73d5ef821c560  gpl
        loaded_at 2025-04-17T12:28:56+0000  uid 0
        xlated 312B  jited 360B  memlock 4096B  map_ids 10,11
        btf_id 14
```

this program is a `lsm` (Linux Security Module) hook for `socket_connect`. it's extremely powerful because it can monitor and block any connection attempts. 

```bash
7: kprobe  name kprobe_mmap  tag 53f774b57c3c00fc  gpl
        loaded_at 2025-04-17T12:28:56+0000  uid 0
        xlated 840B  jited 776B  memlock 4096B  map_ids 13,12
        btf_id 16
```

here, `kprobe` hook the `mmap` syscall, which controls and monitors memory locations.

```bash
10: cgroup_device  tag 3918c82a5f4c0360
        loaded_at 2025-04-17T12:28:56+0000  uid 0
        xlated 64B  jited 136B  memlock 4096B

94: cgroup_device  tag 3918c82a5f4c0360
        loaded_at 2025-04-17T12:47:13+0000  uid 0
        xlated 64B  jited 136B  memlock 4096B
```

these 2 programs are of type `cgroup_device`, and they control the access to device files (i.e. device access permissions in `cgroups`). 

### VSOCK

we can get even more detail here by refining the `bpftool` command:

```bash
bpftool prog dump xlated id <ID>
```

this gives us the translated bytecode of the specific eBPF program respective to the ID. it's the compiled form of the eBPF program after being processed by the kernel's verifier but before being JIT-compiled to the native machine code. 

let's start with the LSM:

```bash
root@2cd71e85b7e8:/analysis# bpftool prog dump xlated id 5

int socket_connect(unsigned long long * ctx):
; int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
   0: (b7) r0 = 0
; int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
   1: (79) r1 = *(u64 *)(r1 +8)
; if (address->sa_family != AF_VSOCK)
   2: (69) r2 = *(u16 *)(r1 +0)
; if (address->sa_family != AF_VSOCK)
   3: (55) if r2 != 0x28 goto pc+34
; if (vm_addr->svm_cid != VMADDR_CID_HOST)
   4: (61) r1 = *(u32 *)(r1 +8)
; if (vm_addr->svm_cid != VMADDR_CID_HOST)
   5: (55) if r1 != 0x2 goto pc+32
; struct event_t *event = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
   6: (18) r1 = map[id:10]
   8: (b7) r2 = 8
   9: (b7) r3 = 0
  10: (85) call bpf_ringbuf_reserve#323384
  11: (bf) r6 = r0
  12: (18) r0 = 0xfffffff5
; if (!event) {
  14: (15) if r6 == 0x0 goto pc+23
; u64 id = bpf_get_current_pid_tgid();
  15: (85) call bpf_get_current_pid_tgid#221352
; u32 pid = id >> 32; // PID is higher part
  16: (77) r0 >>= 32
; u32 pid = id >> 32; // PID is higher part
  17: (63) *(u32 *)(r10 -4) = r0
  18: (bf) r2 = r10
; u64 id = bpf_get_current_pid_tgid();
  19: (07) r2 += -4
; bool pass = bpf_map_lookup_elem(&allowed_pids, &pid) != NULL;
  20: (18) r1 = map[id:11]
  22: (85) call __htab_map_lookup_elem#268976
  23: (15) if r0 == 0x0 goto pc+1
  24: (07) r0 += 56
  25: (bf) r7 = r0
; event->pid = pid;
  26: (61) r1 = *(u32 *)(r10 -4)
; event->pid = pid;
  27: (63) *(u32 *)(r6 +0) = r1
  28: (b7) r1 = 1
; bool pass = bpf_map_lookup_elem(&allowed_pids, &pid) != NULL;
  29: (55) if r7 != 0x0 goto pc+1
  30: (b7) r1 = 0
; event->pass = pass;
  31: (73) *(u8 *)(r6 +4) = r1
; bpf_ringbuf_submit(event, 0);
  32: (bf) r1 = r6
  33: (b7) r2 = 0
  34: (85) call bpf_ringbuf_submit#322288
  35: (b7) r0 = -1
;
  36: (15) if r7 == 0x0 goto pc+1
  37: (b7) r0 = 0
; int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
  38: (95) exit
```

**note**: each line here follows: `instruction_offset: (opcode) operation`. the comments (after the semicolons) show the original C code that generated the bytecode. the register operations (`r0` - `r10`) show how data moves through the program.

essentially, this program enforces security policies on `VSOCK` socket connections by checking if the connection is directed to the host CID (`VMADDR_CID_HOST`), logging connection attempts to a ring buffer, and allowing/blocking based on an allowlist of process IDs.

```bash
; int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
   0: (b7) r0 = 0
; int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
   1: (79) r1 = *(u64 *)(r1 +8)
; if (address->sa_family != AF_VSOCK)
   2: (69) r2 = *(u16 *)(r1 +0)
; if (address->sa_family != AF_VSOCK)
   3: (55) if r2 != 0x28 goto pc+34
; if (vm_addr->svm_cid != VMADDR_CID_HOST)
   4: (61) r1 = *(u32 *)(r1 +8)
; if (vm_addr->svm_cid != VMADDR_CID_HOST)
   5: (55) if r1 != 0x2 goto pc+32
```

this is the parameter loading and family check (`AF_VSOCK = 0x28`). it also cerifies target Context ID (CID) is host (`VMADDR_CID_HOST=0x2`).

```bash
; struct event_t *event = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
   6: (18) r1 = map[id:10]
   8: (b7) r2 = 8
   9: (b7) r3 = 0
  10: (85) call bpf_ringbuf_reserve#323384
  11: (bf) r6 = r0
  12: (18) r0 = 0xfffffff5
; if (!event) {
  14: (15) if r6 == 0x0 goto pc+23
```

this bit allocates the ringbuffer. it uses `bpf_ringbuf_reserve` to allocate event storage. the line `r1 = map[id:10]` references the ringbuffer for logging.

```bash
; u64 id = bpf_get_current_pid_tgid();
  15: (85) call bpf_get_current_pid_tgid#221352
; u32 pid = id >> 32; // PID is higher part
  16: (77) r0 >>= 32
; u32 pid = id >> 32; // PID is higher part
  17: (63) *(u32 *)(r10 -4) = r0
```

this gets the current PID (`bpf_get_current_pid_tgid`).

```bash
  18: (bf) r2 = r10
; u64 id = bpf_get_current_pid_tgid();
  19: (07) r2 += -4
; bool pass = bpf_map_lookup_elem(&allowed_pids, &pid) != NULL;
  20: (18) r1 = map[id:11]
  22: (85) call __htab_map_lookup_elem#268976
  23: (15) if r0 == 0x0 goto pc+1
  24: (07) r0 += 56
  25: (bf) r7 = r0
```

this checks if the PID is in the allowlist. the line `r1 = map[id:11]` references the allowlist of permitted PIDs.

```bash
; event->pid = pid;
  26: (61) r1 = *(u32 *)(r10 -4)
; event->pid = pid;
  27: (63) *(u32 *)(r6 +0) = r1
  28: (b7) r1 = 1
; bool pass = bpf_map_lookup_elem(&allowed_pids, &pid) != NULL;
  29: (55) if r7 != 0x0 goto pc+1
  30: (b7) r1 = 0
; event->pass = pass;
  31: (73) *(u8 *)(r6 +4) = r1
; bpf_ringbuf_submit(event, 0);
  32: (bf) r1 = r6
  33: (b7) r2 = 0
  34: (85) call bpf_ringbuf_submit#322288
```

this records the event data. `bpf_ringbuf_submit` submits the event to the ringbuffer.

```bash
  35: (b7) r0 = -1
;
  36: (15) if r7 == 0x0 goto pc+1
  37: (b7) r0 = 0
; int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
  38: (95) exit
```

this returns the appropriate result (allow/deny).

using this, we can reconstruct the C code.

```c
#include <linux/bpf.h>
#include <linux/socket.h>
#include <linux/vm_sockets.h>

struct event_t {
    __u32 pid;    // PID making the connection
    __u8 pass;    // whether connection was allowed (1) or denied (0)
};

SEC("lsm/socket_connect")
int socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
{
    // only interested in VSOCK connections
    if (address->sa_family != AF_VSOCK)  // 0x28
        return 0;  // allow non-VSOCK connections
        
    struct sockaddr_vm *vm_addr = (struct sockaddr_vm *)address;
    // only check connections targeting the host
    if (vm_addr->svm_cid != VMADDR_CID_HOST)  // 0x2
        return 0;  // llow connections to non-host destinations
        
    // log the connection attempt
    struct event_t *event = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
    if (!event) {
        return -EPERM;  // fail closed if we can't log
    }
    
    // get PID information
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;  // extract PID from higher 32 bits
    
    // check if process is in the allowlist
    bool pass = bpf_map_lookup_elem(&allowed_pids, &pid) != NULL;
    
    // record details about the connection attempt
    event->pid = pid;
    event->pass = pass;
    bpf_ringbuf_submit(event, 0);
    
    // only allow connections from authorized processes
    return pass ? 0 : -EPERM;
}
```

this is effectively the security gate that controls which processes can establish `VSOCK` connections from a VM to its host. 

### kprobe_mmap

```bash
bpftool prog dump xlated id 7
```

this entire program attaches to the `mmap` syscall using a `kprobe` and examines memory allocation requests.

```bash
int kprobe_mmap(struct pt_regs * ctx):
; int BPF_KSYSCALL(kprobe_mmap, void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
   0: (bf) r6 = r1
; int BPF_KSYSCALL(kprobe_mmap, void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
   1: (18) r1 = map[id:13][0]+0
   3: (71) r1 = *(u8 *)(r1 +0)
   4: (79) r7 = *(u64 *)(r6 +0)
   5: (b7) r1 = 272
   6: (bf) r3 = r7
   7: (0f) r3 += r1
   8: (bf) r1 = r10
   9: (07) r1 += -264
; int BPF_KSYSCALL(kprobe_mmap, void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
  10: (b7) r2 = 8
  11: (85) call bpf_probe_read_kernel#-86976
  12: (b7) r1 = 8
  13: (bf) r3 = r7
  14: (0f) r3 += r1
  15: (bf) r1 = r10
; int BPF_KSYSCALL(kprobe_mmap, void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
  16: (07) r1 += -264
; int BPF_KSYSCALL(kprobe_mmap, void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
  17: (b7) r2 = 8
  18: (85) call bpf_probe_read_kernel#-86976
  19: (b7) r1 = 16
  20: (bf) r3 = r7
  21: (0f) r3 += r1
  22: (bf) r1 = r10
; int BPF_KSYSCALL(kprobe_mmap, void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
  23: (07) r1 += -264
; int BPF_KSYSCALL(kprobe_mmap, void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
  24: (b7) r2 = 8
  25: (85) call bpf_probe_read_kernel#-86976
  26: (b7) r1 = 24
  27: (bf) r3 = r7
  28: (0f) r3 += r1
  29: (bf) r1 = r10
; int BPF_KSYSCALL(kprobe_mmap, void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
  30: (07) r1 += -264
; int BPF_KSYSCALL(kprobe_mmap, void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
  31: (b7) r2 = 8
  32: (85) call bpf_probe_read_kernel#-86976
  33: (b7) r1 = 32
  34: (bf) r3 = r7
  35: (0f) r3 += r1
; int BPF_KSYSCALL(kprobe_mmap, void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
  36: (79) r8 = *(u64 *)(r10 -264)
  37: (bf) r1 = r10
; int BPF_KSYSCALL(kprobe_mmap, void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
  38: (07) r1 += -264
; int BPF_KSYSCALL(kprobe_mmap, void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
  39: (b7) r2 = 8
  40: (85) call bpf_probe_read_kernel#-86976
  41: (b7) r1 = 40
  42: (0f) r7 += r1
; int BPF_KSYSCALL(kprobe_mmap, void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
  43: (79) r9 = *(u64 *)(r10 -264)
  44: (bf) r1 = r10
; int BPF_KSYSCALL(kprobe_mmap, void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
  45: (07) r1 += -264
; int BPF_KSYSCALL(kprobe_mmap, void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
  46: (b7) r2 = 8
  47: (bf) r3 = r7
  48: (85) call bpf_probe_read_kernel#-86976
```

this reads the syscall arguments from the `pt_regs` structure. it retrieves the `flags`, `fd`, and `offset` arguments. it then uses the `bpf_probe_read_kernel` to read the kernel memory safely.

```bash
; if ((flags & MAP_HUGETLB) != MAP_HUGETLB || fd != -1 || offset != 0) {
  49: (57) r8 &= 262144
; if ((flags & MAP_HUGETLB) != MAP_HUGETLB || fd != -1 || offset != 0) {
  50: (15) if r8 == 0x0 goto pc+52
  51: (67) r9 <<= 32
  52: (77) r9 >>= 32
  53: (18) r1 = 0xffffffff
  55: (5d) if r9 != r1 goto pc+47
  56: (79) r1 = *(u64 *)(r10 -264)
  57: (55) if r1 != 0x0 goto pc+45
```

here, it checks specific conditions for the memory allocation. first, it checks if the `MAP_HUGETLB` flag (`0x40000` or `262144`) is set. it then checks if the file descriptor is `-1`, and checks if the offset is `0`.

```bash
; struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  58: (85) call bpf_get_current_task#-88480
  59: (b7) r1 = 928
  60: (0f) r0 += r1
  61: (bf) r7 = r10
  62: (07) r7 += -8
; const unsigned char *name = BPF_CORE_READ(t, mm, exe_file, f_path.dentry, d_name.name);
  63: (bf) r1 = r7
  64: (b7) r2 = 8
  65: (bf) r3 = r0
  66: (85) call bpf_probe_read_kernel#-86976
  67: (b7) r1 = 960
  68: (79) r3 = *(u64 *)(r10 -8)
  69: (0f) r3 += r1
  70: (bf) r1 = r7
  71: (b7) r2 = 8
  72: (85) call bpf_probe_read_kernel#-86976
  73: (b7) r1 = 160
  74: (79) r3 = *(u64 *)(r10 -8)
  75: (0f) r3 += r1
  76: (bf) r1 = r7
  77: (b7) r2 = 8
  78: (85) call bpf_probe_read_kernel#-86976
  79: (b7) r1 = 40
  80: (79) r3 = *(u64 *)(r10 -8)
  81: (0f) r3 += r1
  82: (bf) r1 = r10
; struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  83: (07) r1 += -264
; const unsigned char *name = BPF_CORE_READ(t, mm, exe_file, f_path.dentry, d_name.name);
  84: (b7) r2 = 8
  85: (85) call bpf_probe_read_kernel#-86976
; const unsigned char *name = BPF_CORE_READ(t, mm, exe_file, f_path.dentry, d_name.name);
  86: (79) r3 = *(u64 *)(r10 -264)
  87: (bf) r1 = r10
; struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  88: (07) r1 += -264
; if (bpf_probe_read_kernel_str(executable, sizeof(executable), name) < 0) {
  89: (b7) r2 = 256
  90: (85) call bpf_probe_read_kernel_str#-86712
```

this part retrieves the process name information. it gets the current task with `bpf_get_current_task` and then traverses the task structure to get the executable name. it uses `BPF_CORE_READ` to navigate the nested kernel structures.

```bash
  91: (b7) r1 = 0
; if (bpf_probe_read_kernel_str(executable, sizeof(executable), name) < 0) {
  92: (6d) if r1 s> r0 goto pc+10
  93: (bf) r1 = r10
; if (bpf_strncmp(executable, 8, "rosetta\0") == 0) {
  94: (07) r1 += -264
  95: (b7) r2 = 8
  96: (18) r3 = map[id:12][0]+0
  98: (85) call bpf_strncmp#222776
; if (bpf_strncmp(executable, 8, "rosetta\0") == 0) {
  99: (55) if r0 != 0x0 goto pc+3
; bpf_override_return(ctx, -1);
 100: (bf) r1 = r6
 101: (b7) r2 = -1
 102: (85) call bpf_override_return#-87256
```

this part checks the proces name and takes the appropriate action. it verifies if the string read was successful, compares the process name with `rosetta\0`, and calls `bpf_overrride_return` if a match was found to force the syscall to fail.

```c
#include <linux/bpf.h>
#include <linux/mman.h>

SEC("kprobe/mmap")
int kprobe_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset)
{
    // only interested in huge page allocations with specific parameters
    if ((flags & MAP_HUGETLB) != MAP_HUGETLB || fd != -1 || offset != 0) {
        return 0;  // allow normal allocations to proceed
    }

    // get information about the current process
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    
    // get the executable name
    char executable[256];
    const unsigned char *name = BPF_CORE_READ(t, mm, exe_file, f_path.dentry, d_name.name);
    
    // check if we could read the name successfully
    if (bpf_probe_read_kernel_str(executable, sizeof(executable), name) < 0) {
        return 0;  // allow if we can't determine the process name
    }

    // block huge page allocations specifically for "rosetta" process
    if (bpf_strncmp(executable, 8, "rosetta\0") == 0) {
        // force the syscall to return -1 (failure)
        bpf_override_return(ctx, -1);
    }
    
    return 0;  // allow for all other processes
}
```

this program targets the `rosetta` process, which is Apple's translation layer that allows x86_64 binaries to run on ARM. it only triggers on memory mappings with the `MAP_HUGETLB` flag that have no backing file (`fd=1`) and zero offset. 

`rosetta` uses huge pages for performance, so it blocks the allocations to degrade performance and cause failures.

### oom_kill_process

```bash
bpftool prog dump xlated id 4
```

this program attaches to the kernel function `oom_kill_process` using a `kprobe`. its purpose is to capture detailed information whenever the Linux Out-Of-Memory (OOM) killer selects a process to terminate due to low system memory.

for each OOM event, the program extracts and logs the victim process's PID, the victim's command name (`comm`), the victim's total virtual memory size (`total_vm`), and other details from the victim's `task_struct` and `mm_struct` (memory descriptor).

```bash
int kprobe__oom_kill_process(struct pt_regs * ctx):
; int BPF_KPROBE(kprobe__oom_kill_process, struct task_struct *victim, const char *message) {
   0: (79) r7 = *(u64 *)(r1 +0)
; oom_victim_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
   1: (18) r1 = map[id:8]
   3: (b7) r2 = 24
   4: (b7) r3 = 0
   5: (85) call bpf_ringbuf_reserve#323384
   6: (bf) r6 = r0
; if (!oom_victim_info) {
   7: (15) if r6 == 0x0 goto pc+31
```

this block sets up the logging for OOM kill events. it gets the context from the `kprobe`, reserves space in a ringbuffer, and checks if the reservation was successful.

```bash
   8: (b7) r1 = 1056
   9: (bf) r3 = r7
  10: (0f) r3 += r1
; BPF_CORE_READ_INTO(&oom_victim_info->Pid, victim, pid);
  11: (bf) r1 = r6
  12: (b7) r2 = 4
  13: (85) call bpf_probe_read_kernel#-86976
  14: (b7) r1 = 1544
  15: (bf) r3 = r7
  16: (0f) r3 += r1
; BPF_CORE_READ_STR_INTO(&oom_victim_info->Comm, victim, comm);
  17: (bf) r1 = r6
  18: (07) r1 += 8
  19: (b7) r2 = 16
  20: (85) call bpf_probe_read_kernel_str#-86712
```

here, the program reads the PID of the victim process, then reads the command name `comm` of the victim process. 

```bash
  21: (b7) r1 = 928
  22: (0f) r7 += r1
  23: (bf) r1 = r10
;
  24: (07) r1 += -8
; struct mm_struct *mm = BPF_CORE_READ(victim, mm);
  25: (b7) r2 = 8
  26: (bf) r3 = r7
  27: (85) call bpf_probe_read_kernel#-86976
; struct mm_struct *mm = BPF_CORE_READ(victim, mm);
  28: (79) r3 = *(u64 *)(r10 -8)
; if (!mm) {
  29: (15) if r3 == 0x0 goto pc+6
  30: (b7) r1 = 232
  31: (0f) r3 += r1
; BPF_CORE_READ_INTO(&oom_victim_info->TotalVM , mm, total_vm);
  32: (bf) r1 = r6
  33: (07) r1 += 4
  34: (b7) r2 = 4
  35: (85) call bpf_probe_read_kernel#-86976
```

this gets the memory management structure (`mm`). if `mm` exists, it reads the total virtual memory allocated. 

```bash
; bpf_ringbuf_submit(oom_victim_info, 0);
  36: (bf) r1 = r6
  37: (b7) r2 = 0
  38: (85) call bpf_ringbuf_submit#322288
; int BPF_KPROBE(kprobe__oom_kill_process, struct task_struct *victim, const char *message) {
  39: (b7) r0 = 0
  40: (95) exit
```

finally, it submits the collected data to the ringbuffer.

```c
#include <linux/bpf.h>

struct event {
    __u32 Pid;             // PID of OOM victim
    __u32 TotalVM;         // total virtual memory used by the process
    char Comm[16];         // command/process name (16 bytes is standard size)
};

SEC("kprobe/oom_kill_process")
int kprobe__oom_kill_process(struct task_struct *victim, const char *message)
{
    // allocate space for event data in the ringbuffer
    struct event *oom_victim_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!oom_victim_info) {
        return 0;  // exit if reservation fails
    }

    // collect process identification information
    BPF_CORE_READ_INTO(&oom_victim_info->Pid, victim, pid);
    BPF_CORE_READ_STR_INTO(&oom_victim_info->Comm, victim, comm);

    // collect memory usage information if available
    struct mm_struct *mm = BPF_CORE_READ(victim, mm);
    if (!mm) {
        // process may be a kernel thread (no mm)
        oom_victim_info->TotalVM = 0;
    } else {
        // get the total virtual memory used
        BPF_CORE_READ_INTO(&oom_victim_info->TotalVM, mm, total_vm);
    }

    // submit the event to userspace
    bpf_ringbuf_submit(oom_victim_info, 0);
    
    return 0;
}
```

unlike the other components, this program doesn't modify behavior; it only collects information. we can use it for gathering data about memory pressure and process termination patterns. 

it's also useful for monitoring if malware components get killed by OOM and verifying whether critical processes are terminated. the collected data is sent to a ringbuffer, which the userspace component of the malware can access.

### egress

```bash
bpftool prog dump xlated id 2
```

this is a `cgroup_skb` type filter attached to the `egress` hook. it's responsible for controlling outbound network traffic.

```bash
   0: (bf) r7 = r1
   1: (b7) r6 = 0
   2: (bf) r3 = r10
   3: (07) r3 += -20
   4: (b7) r2 = 0
   5: (b7) r4 = 20
   6: (85) call bpf_skb_load_bytes#13354056
   7: (18) r1 = 0x80000000
   9: (5f) r0 &= r1
  10: (55) if r0 != 0x0 goto pc+74
```

this initializes and checks if the packet is IPv4. it loads the first 20 bytes of the packet and checks if the most significant bit is set (to filter non-IPv4/IPv6).

```bash
  11: (71) r1 = *(u8 *)(r10 -20)
  12: (77) r1 >>= 4
  13: (15) if r1 == 0x6 goto pc+35
  14: (55) if r1 != 0x4 goto pc+70
```

this determines the IP version. it extracts the IP version (bits 4-7 of the first byte) and checks if it's IPv6 before jumping if true. it continues if it's IPv4. 

```bash
  15: (b7) r1 = 32
  16: (63) *(u32 *)(r10 -60) = r1
  17: (61) r1 = *(u32 *)(r10 -4)
  18: (63) *(u32 *)(r10 -56) = r1
  19: (bf) r2 = r10
  20: (07) r2 += -60
  21: (18) r1 = map[id:3]
  23: (85) call trie_lookup_elem#310224
  24: (b7) r6 = 1
  25: (55) if r0 != 0x0 goto pc+59
  26: (bf) r2 = r10
  27: (07) r2 += -4
  28: (18) r1 = map[id:7]
  30: (85) call __htab_map_lookup_elem#268976
  31: (15) if r0 == 0x0 goto pc+1
  32: (07) r0 += 56
  33: (55) if r0 != 0x0 goto pc+51
```

now it prepares checks if the destination IP is in allowed IPv4 trie (map ID 3) and also checks if it's in a hash table (map ID 7).

```bash
  34: (b7) r6 = 0
  35: (18) r1 = map[id:5]
  37: (b7) r2 = 8
  38: (b7) r3 = 0
  39: (85) call bpf_ringbuf_reserve#323384
  40: (15) if r0 == 0x0 goto pc+44
  41: (61) r1 = *(u32 *)(r10 -8)
  42: (63) *(u32 *)(r0 +4) = r1
  43: (61) r1 = *(u32 *)(r10 -4)
  44: (63) *(u32 *)(r0 +0) = r1
  45: (bf) r1 = r0
  46: (b7) r2 = 0
  47: (85) call bpf_ringbuf_submit#322288
  48: (05) goto pc+36
```

this logs blocked IPv4 packets. it allocates the space in the ringbuffer and records the source and destination IPs for blocked packets.

```bash
  49: (bf) r3 = r10
  50: (07) r3 += -60
  51: (bf) r1 = r7
  52: (b7) r2 = 0
  53: (b7) r4 = 40
  54: (85) call bpf_skb_load_bytes#13354056
  55: (18) r1 = 0x80000000
  57: (5f) r0 &= r1
  58: (55) if r0 != 0x0 goto pc+26
  59: (b7) r1 = 128
  60: (63) *(u32 *)(r10 -80) = r1
  61: (61) r1 = *(u32 *)(r10 -36)
  62: (73) *(u8 *)(r10 -76) = r1
  63: (61) r1 = *(u32 *)(r10 -32)
  64: (73) *(u8 *)(r10 -75) = r1
  65: (61) r1 = *(u32 *)(r10 -28)
  66: (73) *(u8 *)(r10 -74) = r1
  67: (61) r1 = *(u32 *)(r10 -24)
  68: (73) *(u8 *)(r10 -73) = r1
  69: (bf) r2 = r10
  70: (07) r2 += -80
  71: (18) r1 = map[id:4]
  73: (85) call trie_lookup_elem#310224
  74: (b7) r6 = 1
  75: (55) if r0 != 0x0 goto pc+9
  76: (bf) r2 = r10
  77: (07) r2 += -36
  78: (18) r1 = map[id:9]
  80: (85) call __htab_map_lookup_elem#268976
  81: (15) if r0 == 0x0 goto pc+1
  82: (07) r0 += 64
  83: (55) if r0 != 0x0 goto pc+1
  84: (b7) r6 = 0
  85: (bf) r0 = r6
  86: (95) exit
```

this repeats the same steps for IPv6 packet processing.

```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>

struct ipv4_event {
    __u32 dst_ip;    // destination IP address
    __u32 src_ip;    // source IP address
};

SEC("cgroup_skb/egress")
int egress(struct __sk_buff *skb)
{
    __u8 ip_header[20];
    __u8 ipv6_header[40];
    __u8 allow_packet = 0;
    
    // read the first part of the packet (IP header)
    if (bpf_skb_load_bytes(skb, 0, ip_header, sizeof(ip_header)) < 0)
        return 1;  // allow if we can't read the header
    
    // check IP version (IPv4 or IPv6)
    __u8 ip_version = (ip_header[0] >> 4);
    
    if (ip_version == 4) {  // IPv4
        // extract destination IP from header
        __u32 dst_ip = *(__u32*)&ip_header[16];
        
        // check if destination IP is allowed (in trie)
        struct {
            __u32 prefixlen;
            __u32 ip;
        } ipv4_key = {
            .prefixlen = 32,
            .ip = dst_ip
        };
        
        // check IPv4 trie for exact matches
        if (bpf_map_lookup_elem(&ipv4_allowed_trie, &ipv4_key))
            allow_packet = 1;
        // check IPv4 hash table for specific allowed IPs
        else if (bpf_map_lookup_elem(&ipv4_allowed_ips, &dst_ip))
            allow_packet = 1;
        else {
            // log blocked IPv4 connection attempts
            struct ipv4_event *event = bpf_ringbuf_reserve(&ipv4_events, sizeof(struct ipv4_event), 0);
            if (event) {
                event->dst_ip = dst_ip;
                event->src_ip = *(__u32*)&ip_header[12];  // source IP
                bpf_ringbuf_submit(event, 0);
            }
        }
    }
    else if (ip_version == 6) {  // IPv6
        // read the IPv6 header
        if (bpf_skb_load_bytes(skb, 0, ipv6_header, sizeof(ipv6_header)) < 0)
            return 1;  // allow if we can't read the header
        
        // extract destination IPv6 address (bytes 24-39 of header)
        struct {
            __u32 prefixlen;
            __u8 ip[16];
        } ipv6_key = {
            .prefixlen = 128,
        };
        
        // copy IPv6 address bytes
        __builtin_memcpy(ipv6_key.ip, &ipv6_header[24], 16);
        
        // check IPv6 trie for network/prefix matches
        if (bpf_map_lookup_elem(&ipv6_allowed_trie, &ipv6_key))
            allow_packet = 1;
        // check IPv6 hash table for specific allowed IPs
        else if (bpf_map_lookup_elem(&ipv6_allowed_ips, &ipv6_header[24]))
            allow_packet = 1;
    }
    else {
        // non-IPv4/IPv6 traffic (e.g., ARP) - allow
        return 1;
    }
    
    return allow_packet;  // 1 to allow, 0 to drop
}
```

the program essentially functions as a custom firewall at the `cgroup` level. it isolates the compromised system to prevent it from connecting to security/update servers and makes sure connections only go to authorized C2 infrastructure.

## BTF

we can also try to extract the BTF (BPF Type Format) debug information if it's available.

```bash
root@2cd71e85b7e8:/analysis# bpftool btf dump id 14 format c
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

#ifndef __ksym
#define __ksym __attribute__((section(".ksyms")))
#endif

#ifndef __weak
#define __weak __attribute__((weak))
#endif

#ifndef __bpf_fastcall
#if __has_attribute(bpf_fastcall)
#define __bpf_fastcall __attribute__((bpf_fastcall))
#else
#define __bpf_fastcall
#endif
#endif


/* BPF kfuncs */
#ifndef BPF_NO_KFUNC_PROTOTYPES
#endif

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __VMLINUX_H__ */
```

for the `socket_connect` program (ID 14), the BTF data seems minimal or incomplete. BTF is a format that stores debugging information about types used in BPF programs (similar to `DWARF` for normal executables). in this case, we only get back a basic skeleton header without any actual type definitions. weird because we know the `socket_connect` program exists (and runs), which could only mean that the malware is deliberately stripping or limiting BTF information for anti-analysis. 

however, the BTF dump for the `kprobe_mmap` program contains a bit more information.

```bash
root@2cd71e85b7e8:/analysis# bpftool btf dump id 16 format c
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

#ifndef __ksym
#define __ksym __attribute__((section(".ksyms")))
#endif

#ifndef __weak
#define __weak __attribute__((weak))
#endif

#ifndef __bpf_fastcall
#if __has_attribute(bpf_fastcall)
#define __bpf_fastcall __attribute__((bpf_fastcall))
#else
#define __bpf_fastcall
#endif
#endif

typedef int __s32;

typedef __s32 s32;

typedef unsigned int __u32;

typedef __u32 u32;

typedef unsigned long long __u64;

typedef __u64 u64;

struct user_pt_regs {
        __u64 regs[31];
        __u64 sp;
        __u64 pc;
        __u64 pstate;
};

struct pt_regs {
        union {
                struct user_pt_regs user_regs;
                struct {
                        u64 regs[31];
                        u64 sp;
                        u64 pc;
                        u64 pstate;
                };
        };
        u64 orig_x0;
        s32 syscallno;
        u32 unused2;
        u64 sdei_ttbr1;
        u64 pmr_save;
        u64 stackframe[2];
        u64 lockdep_hardirqs;
        u64 exit_rcu;
};


/* BPF kfuncs */
#ifndef BPF_NO_KFUNC_PROTOTYPES
#endif

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __VMLINUX_H__ */
```

we have some basic type definitions (`s32`, `u32`, `u64`) and some register state structures:

- `struct user_pt_regs`: this is a user-accessible version of CPU register data

- `struct pt_regs`: this is a full kernel register state structure.

the real interesting part is that this BTF contains ARM64-specific register structures.

```c
struct user_pt_regs {
    __u64 regs[31];  // ARM64 has 31 general-purpose registers
    __u64 sp;        // stack pointer
    __u64 pc;        // program counter
    __u64 pstate;    // processor state flags
};
```

this confirms that the malware specifically targets ARM64 architecture! it also reinforces our earlier finding that the `kprobe_mmap` component specifically targets the Rosetta 2 translation layer. 

## maps

we can use `bpftool map list` to check the data structures used by the programs.

```bash
root@2cd71e85b7e8:/analysis# bpftool map list
3: lpm_trie  name allowed_trie  flags 0x1
        key 8B  value 8B  max_entries 1024  memlock 312B
4: lpm_trie  name allowed_trie6  flags 0x1
        key 20B  value 8B  max_entries 1024  memlock 0B
5: ringbuf  name blocked_packets  flags 0x0
        key 0B  value 0B  max_entries 4096  memlock 16664B
6: ringbuf  name blocked_packets  flags 0x0
        key 0B  value 0B  max_entries 4096  memlock 16664B
7: hash  name allowed_map  flags 0x0
        key 4B  value 4B  max_entries 10000  memlock 904576B
8: ringbuf  name events  flags 0x0
        key 0B  value 0B  max_entries 4096  memlock 16664B
9: hash  name allowed_map6  flags 0x0
        key 16B  value 4B  max_entries 10000  memlock 984704B
10: ringbuf  name events  flags 0x0
        key 0B  value 0B  max_entries 4096  memlock 16664B
11: hash  name allowed_pids  flags 0x0
        key 4B  value 1B  max_entries 32  memlock 4992B
        btf_id 7
12: array  name .rodata  flags 0x80
        key 4B  value 9B  max_entries 1  memlock 264B
        btf_id 13  frozen
13: array  name .kconfig  flags 0x80
        key 4B  value 1B  max_entries 1  memlock 256B
        btf_id 17  frozen
```

we can categorize these maps into the following.

### network filtering maps

IPv4 filtering maps:

- map 3: `lpm_trie` named "allowed_trie" - this stores IPv4 network prefixes (8-byte keys with prefixlen + IPv4)

- map 7: `hash` named "allowed_map" - this stores individual IPv4 addresses (4-byte keys)

these work together to implement allowlist-based filtering (networks via `trie`, individual IPs via `hash`).


IPv6 filtering maps:

- map 4: `lpm_trie` named "allowed_trie6" - this stores IPv6 network prefixes (20-byte keys with prefixlen + IPv6)

- map 9: `hash` named "allowed_map6" - this stores individual IPv6 addresses (16-byte keys)

similar to IPv4 maps but for IPv6 traffic.

network logging:
- map 5 & 6: `ringbuf` named "blocked_packets" - this stores information about blocked network connections

these are two identical ringbuffers, possibly for redundancy or different monitoring components.

### process control maps

PID allowlist:

- map 11: `hash` named "allowed_pids" - this stores process IDs allowed to make `VSOCK` connections (4-byte keys)

it has BTF information (ID 7) for additional type context and small max entries (32) (maintains a tight list of authorized processes).

### event logging

monitoring ringbuffers:

- map 8 & 10: `ringbuf` named "events" - a general purpose event logging for OOM and socket operations

the 4KB size suggests they're used for high-speed event recording. it has two identical ringbuffers, likely one for OOM events (map 8) and one for socket events (map 10)

### configuration maps

read-only configuration:

- map 12: `array` named ".rodata" - this contains constant data (9-byte values)

it has a frozen flag indicating it's immutable after loading and contains hardcoded values used by the programs (likely strings like "rosetta\0").

kernel configuration:

- map 13: `array` named ".kconfig" - this stores kernel configuration flags

it has BTF information (ID 17) and is also frozen.

### security

the combination of `trie` and hash maps creates a sophisticated network filtering system. `tries` enable prefix/network-based filtering (e.g., 192.168.1.0/24) and hash tables allow efficient individual IP lookups. this creates a precise network allowlist capability.

the maps implement a "default deny" policy where only explicitly allowed network destinations (IPs and networks) and processes (via `allowed_pids`) can perform certain operations.

rhe ringbuffers provide a continuous stream of events to userspace, including blocked network connections, OOM events, and VM socket connection attempts. the read-only configuration maps show that the malware is designed to be configured at load time and then lock its settings.

let's check the `allowed_pids` map content.

```bash
root@2cd71e85b7e8:/analysis# bpftool map dump id 11
[{
        "key": 181,
        "value": 1
    }
]
```

the map contains a single entry. it means only one process (PID 181) is allowed to make `VSOCK` connections to the host. this is the malware's C2 component or a communication process that connects back to the attacker's infrastructure. the restriction here also prevents other processes from establshing `VSOCK` connections, meaning limited detection by security tools that might try to communicate out and prevention of victim-controller processes bypassing the malware controls. 


## persistence

the string analysis also revealed some interesting artifacts about how the malware maintains persistence and covers its tracks.

```bash
root@2cd71e85b7e8:/analysis# strings www | grep -E '(/etc|/var|/home|/root)'
/etc/suid-debug
/var/tmp
/var/profile
/etc/ld.so.cache
```

`/etc/suid-debug` is a custom file created with SUID permissions (for privesc). `/var/tmp` is a common location for storing persistent files that survive reboots. `/var/profile` is an unusual location that mimics legit system files.

```bash
root@2cd71e85b7e8:/analysis# strings www | grep -E '(unlink|remove|delete)'
unlink
%s deleted successfully.
Identifier removed
remove_from_free_list
imap->l_type == lt_loaded && !imap->l_nodelete_active
remove_slotinfo
unlink_chunk.constprop.0
remove_slotinfo
_dlfo_nodelete_mappings_size
_dlfo_nodelete_mappings
_dlfo_nodelete_mappings_end
_IO_remove_marker
__unlink
_nl_remove_locale
__tdelete
```

it directly uses the `unlink()` syscall for file deletion. the success message string `%s deleted successfully` and `Identifier removed` confirms that it removes any identifying markers.

finally, checking for hardcoded IP addresses:

```bash
root@2cd71e85b7e8:/analysis# strings www | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}'
```

this returned nothing. so either the IP addresses are encrypted/encoded, or the C2 infrastructure details are stored in the maps from earlier. 


## summary

the analysis of this malware reveals a concerning evolution in threat capabilities through the weaponization of eBPF technology. by loading eBPF programs into the kernel, the malware maintains persistence even after removing its on-disk components, creating a nearly invisible footprint.

the implementation of custom network filtering for both IPv4 and IPv6 through eBPF allows precise control over outbound connections, limiting detection while maintaining command and control capabilities and with components targeting both x86_64 and ARM64 architectures, particularly focusing on Apple's Rosetta 2 translation layer, the malware demonstrates a sophisticated understanding of modern computing environments.

these findings highlight a significant shift in the threat landscape: as eBPF adoption grows in legitimate security and observability tools, malicious actors are similarly leveraging this powerful technology for their purposes. organizations must adapt their security posture by:

- implementing strict eBPF program loading controls

- monitoring for unexpected eBPF programs and maps

- deploying kernel-aware security solutions

- regularly auditing loaded eBPF programs

this sample represents what will likely be an emerging trend of kernel-level threats that exploit the power and flexibility of eBPF. 
