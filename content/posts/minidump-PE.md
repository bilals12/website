---
title: "advanced evasions, part 1: PE maps + custom minidumpers"
date: 2024-10-07T13:36:59-04:00
toc: true
next: true
nomenu: false
notitle: false
---

imagine if your computer kept a journal. a journal not merely consisting of poetic silicon muses, but moment-by-moment accounts of all its inner workings. these journals exist, and they're called **minidumps**. minidumps are compact snapshots of a computer's memory, and they capture the essence of what's happening inside your machine at any given moment.


![bluescreenview](/bluescreenview.gif)

![bluescreenview](/bluescreenview2.gif)


to the unitiated (or uninterested), minidumps would just look like cryptic glyphs, with maybe a vague understanding that these glyphs represent something "important". indeed, minidumps are extremely valuable, and at the heart of a hidden conflict inside the digital world: they're prized by software engineers hunting elusive bugs, revered by security/forensics experts trying to track down phantoms, and eyed warily by the very security systems designed to protect your computer.

think of your computer as if it were a bustling city, with programs + data zipping along like vehicles + people. a **minidump** is akin to a **CCTV camera** on a street corner that can freeze a moment in time, capturing everything in its view. now, imagine if someone could use that frozen image to understand traffic patterns, spot accidents before they've happened, or even identify "troublemakers". 

here's where it gets interesting. just as a city might restrict where cameras can be placed, to protect residents' privacy, your computer has security systems that keep an eye on who's taking these memory snapshots and why. it's a delicate balance between the need for insight and the demand for security.

## AV/EDR

most of us have had experience use AV (**antivirus**) tools in the past. EDR (**endpoint detection + response**) systems are an extension of traditional AVs, in that they have a heightened level of access to the underlying OS and, in some cases, even the kernel. i won't bore you too much with how exactly EDRs work, but there are some important points to remember:

1. EDRs use **behavioural** analysis to detect threats, while AVs traditionally rely on signature matching.

2. EDRs leverage AI/ML for more sophisticated threat (**0-day**) detection + automated response capabilities.

3. EDRs provide **continuous, real-time monitoring** of endpoints and their activites.


## AV/EDR + minidumps

![edrminidump](/edrminidump.png)

creating minidumps that won't trigger native security systems is of paramount importance to EDRs. to do this, many EDRs (and even some AVs) use **custom minidumpers** to capture specific memory regions of interest when a suspicious event occurs. 

take the crudely illustrated example above. the entire process is enclosed within the EDR's system, and starts at **minidump creation**, where the EDR creates memory snapshots of running processes. these minidumps are then sent to the **analysis engine**, which examines the contents of the dumpfile for signs of malicious activity. the **threat detection** component receives these analysis results and **identifies** potential threats, based on the ruleset that it was fed during the design process. 

as you can see, this is a cyclical process: continuous monitoring feeds back into the minidump creation, and so on. but how exactly do EDRs achieve this?

## custom minidumpers

EDRs have a vested interest in monitoring + controlling minidump creation. since minidumps contain snapshots of process memory, EDRs need to be able to prevent unauthorized data extraction, credential harvesting (like dumping `lsass.exe`), and attacks like process injection. this is done by EDRs leveraging **custom minidumpers**. ironically, attackers use **custom minidumpers** to evade detection and make reverse engineering malware more convoluted, but more on that later.

basically, everything malware might use custom minidumpers for is used by EDRs to foil it in the first place.

let's look at **memory forensics**, for example. custom minidumpers are used to capture specific memory regions, which is crucial for gathering IoCs and analyzing malware behaviour **in-memory** (while it's running in RAM as opposed to being stored as a static file on disk; this is also incredibly helpful for [fileless malware](https://intezer.com/blog/incident-response/memory-analysis-forensic-tools/**)).

- some more ways custom minidumpers are used by EDRs:

1. optimizing egress bandwidth + reducing system overhead during analysis.

2. identifying memory regions where malware attempts to hide (code injection, process hollowing).

3. capturing kernel-mode memory regions for rootkit analysis (driver-based malware, malicious kernel mods).

if you haven't already guessed, i'm going to be creating my own custom minidumper to see if i can exploit some EDR blindspots! now, let's dive into some technical details about minidumpers.

## minidumpers: the boring stuff

minidumps are typically stored as binary files with a structd format, often with the `.dmp` extension on Windows systems, and they contain a curated subset of the full process memory:

1. critical memory regions, like stacks + heaps.

2. system + process information: this includes the **process ID** (identifying the specific process that the dump belongs to), **timestamp** (for correlating with system events + logs), **OS version**, and **CPU architecture**.

3. thread contexts (register states): provide snapshots of CPU registers for each thread (get exact state of execution), **thread stacks** (call history + local variables), **thread-local storage** (holds thread-specific data, analyzing **thread isolation** and potential **race conditions**)

4. loaded module details: identifying potential malicious injections, version conflicts, and provides the basis for symbol resolution during analysis.

5. exception information (if triggered by an exception): exception code, exception address, exception parameters, first-chance/second-chance status.

6. memory regions: stack memory for each thread, selected heap regions.

7. handle information: open handles (resources currently in use by process), handle types + permissions.

8. system information.

## advanced minidump techniques

advanced techniques for minidump creation go beyond standard API calls. the goal is to procure greater control, evasion capabilities, with full customization. let's take a look at some of them.

**direct memory access**: use low-level memory access functions like `ReadProcessMemory`. this bypasses higher-level APIs that may be hooked or monitored. it allows for selective memory capture (evading detection), but requires a pretty thorough understanding of the memory layout + protection mechanisms.

**PEB parsing**: directly accessing + parsing the PEB (**Process Environment Block**) struct. this also avoids easily-monitored APIs, and reveals information about loaded modules that might be hidden from standard APIs. 

**custom thread enumeration**: use low-level APIs like `NtQuerySystemInformation` or parsing the kernel structs directly. this can reveal hidden or injected threads.

**manual stack walking**: implementing custom stack walking algorithms use architecture-specific techniques. this can allow for custom filtering + analysis, bypassing debugger APIs that may be detected or hooked. 

**kernel-mode dumping**: creating minidumps from kernel mode by use a custom driver. this allows us to dump protected process and bypass user-mode restrictions + detections.

**in-memory dump creation**: creating dumps entirely in-memory without writing to disk. this is crucial if you want to avoid leaving artifacts on disk that can be detected, but you need custom analysis tools along with careful memory management to handle potentially large dumps.

**selective component dumping**: creating highly targeted dumps, and significantly reducing dump size + creation time.

**encryption + obfuscation**: evading signature-based detection of dump files by encrypting the dump data during or immediately after creation.

as you might have guessed, there are many different ways of leveraging custom minidumpers to dump `lsass.exe`. for this project, however, i'm going to start with understanding + mapping the **portable executable**.

## PE: Portable Executable

**PE** is a file format used in Windows for executables, object code, and **dynamic link libraries** (DLLs). simply put, it's the standard format for binary programs on Windows and is used by the OS to manage the **execution** of applications.

when a **process** is created (a kernel-level operation), the creation of the PE is the second step, following the initialization of the address space. before i get into how the PE is created, let's take a look at what it consists of.

![PE](/PE.png)

the PE file begins with an **MS-DOS header**, which includes a magic number (`MZ`) that identifies the file as a DOS executable. this header is primarily for backward compatibility and includes a pointer to the PE header.

the **PE header** defines the program's binary code, images, number of sections, the **entry point address** of the program, the target machine architecture, and more. it also contains a **timestamp**, which attackers can sometimes remove.

the **Optional header**, despite its name, is not optional. it defines the size of the code, the preferred base address, and the OS version.

the **Section headers** contain chunks of data mapped into memory, and instructions about how the program should be loaded into the memory (e.g., a contiguous string of bytes in memory?). they also contain the permissions to be granted to the sections (**read**, **write**, **execute**).

the `.text` section contains the executable program code. the `.idata` section contains the **IAT** (Import Address Table), which lists the DLLs + their functions (i.e., the library calls a program makes). the `.rsrc` section contains the resources used by the PE. these could be printable character strings, graphical images, and other assets. 

finally, we have the `.reloc` section. since the PE binary is not "position-independent" (i.e., it won't work if moved from the intended location to a new location), `.reloc` tells the OS to translate memory addresses in the PE code if the PE has been moved (by adding/subtracting the offset from the memory address). 

![PE-sections](/PE-sections.png)

- the section headers. you can see the **virtual address** and the **raw address** (the offset where the mapping starts).

![PE-sections-chars](/PE-sections-chars.png)

- the characteristics breakdown of each section.

![PE-imports](/PE-imports.png)

- the import directory. this PE imports from two libraries: `testlib.dll` and `KERNEL32.dll`. 

![PE-kernel32APIs](/PE-kernel32APIs.png)

- the `KERNEL32.dll` contains all of the Windows APIs.

![PE-exports](/PE-exports.png)

- the exports directory.

by now you might be wondering: who cares? or, at the very least, why is the PE so important? and what does it have to do with creating custom minidumpers? i'm not going to answer the first question, and i think i've already answered the second question. so, i'm going to address the third question.

## PE + minidumpers

the PE format provides detailed information about the modules (**executables** + **DLLs**) loaded into a process's memory. this includes their base addresses, sizes, and sections. custom minidumpers need this information to capture the state of a process and its dependencies.

the PE also includes data directories that point to **export + import tables**. these tables describe which functions a module provides, and which external functions it relies on. this information is often included in minidumps to help engineers trace function calls + dependencies. the data directories also contain **relocation information**, which describe how a module's code/data are relocated in memory. the relocation entries help to adjust addresses when a module is loaded at a different base address than expected.

custom minidumpers will also need the **debugging information** (symbol tables, line number data), **security analysis** (checksums, integrity), and everything else that the PE format provides. the PE format is a blueprint, so the logical first-step is to create a tool that parses + manipulates it. 

### mapping out the PE format in Rust

our custom minidumper starts with understanding + mapping out the the PE format. this is because we'll eventually be analyzing/manipulating Windows executables. we'll also be extracting specific information from the process's memory. then, we'll define custom structs that **mirror** the PE format, since we'll be serializing/deserializing data in a specific way.

before i get into the code, i'll provide a 1000-foot view of how this program works. 

a variety of data structs that represent different parts of the PE format (`ImageDosHeader`, `ImageNtHeaders64`, `ImageOptionalHeader64`, `ImageDataDirectory`, etc.) will be defined. these will allow us to parse the headers + sections of a PE file.

we'll also have to create **RVA (Relative Virtual Address)** handling, specifically with `RVA32` + `RVA64` types. these types will provide methods to resolve RVAs to actual memory addresses. 

we'll also have to access the export/import tables of a module (`get_export_table`, `get_import_directory_table`), to verify which functions are available or not.

to handle COFF symbols + section headers, a module will be needed to extract the symbol information and section characteristics. this is for debugging + analysis.

by defining my own structs + parsing logic, we can tailor the minidump to include exactly what we need and evade detection that looks for standard minidump patterns. custom parsing + dumping techniques are less detectable than use standard APIs, and stealth is always a priority in offensive security. 

a note on why i chose Rust: Rust's combination of performance, safety, and modernity  makes it an excellent choice for developing a custom minidumper. its ability to provide low-level control without sacrificing safety is advantageous in security-focused projects, where both performance + reliability are paramount. this project can now achieve high efficiency and robustness, making it a powerful tool offensive security.

### code

```rs

#![allow(dead_code)]

use core::mem::transmute;
use std::slice;

use bitflags::bitflags;

// parsed PE32+ struct
pub struct PE64 {
    pub pe64: Box<Pe64C>,
    pub base_address: usize,
    pub data_directories: ImageDataDirectoryVec,
}

// return reference to ImageDataDirectoryVec
impl PE64 {
    pub fn get_data_directories(&self) -> &ImageDataDirectoryVec {
        &self.data_directories
    }
}

// "C" style representation of a parsed PE32+ struct
#[derive(Clone)]
#[repr(C)]
pub struct Pe64C {
    pub dos_header: ImageDosHeader,
}

impl Pe64C {
    pub fn get_nt_headers(&self) -> &ImageNtHeaders64 {
        let nt_headers = self.dos_header.e_lfanew.get(self as *const _ as usize);
        &*(nt_headers)
    }
}

// constant representing valid MS-DOS sig
pub const IMAGE_DOS_SIGNATURE: u16 = u16::from_le_bytes(*b"MZ");

/// MS-DOS sig (MZ)
#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct ImageDosSignature(u16);

// impl ImageDosSignature + verify sig is valid
impl ImageDosSignature {
    pub fn is_valid(&self) -> bool {
        self.0 == IMAGE_DOS_SIGNATURE
    }
}

#[derive(Clone)]
#[repr(C)]
pub struct ImageDosHeader {
    pub e_magic: ImageDosSignature,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    // offset from module base to ImageNtHeaders64 struct
    pub e_lfanew: RVA32<ImageNtHeaders64>,
}

#[derive(Clone)]
#[repr(C)]
pub struct ImageNtHeaders64 {
    pub signature: PESignature,
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeader64,
}

// PEType is an enum representing pe32 or pe32+ identifiers
#[derive(PartialEq, Eq, Copy, Clone)]
#[repr(u16)]
pub enum PEType {
    PE32 = 0x10b,
    PE64 = 0x20b,
}

// ImageOptionalHeader64 struct
#[derive(Clone)]
#[repr(C)]
pub struct ImageOptionalHeader64 {
    pub magic: PEType,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: RVA32<extern "C" fn()>,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: WindowsSubsystem,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    // data directory is an array of ImageDataDirectory structs
    // size is based on number_of_rva_and_sizes field in this struct
    pub data_directory: [ImageDataDirectory; 0],
}

// ImageDataDirectory struct
pub struct ImageDataDirectoryVec(pub Vec<ImageDataDirectoryInfo>);

impl ImageDataDirectoryVec {
    // get entry corresponding to export table
    pub fn get_export_table(&self) -> Option<&ExportDirectoryTable> {
        // loop thru data dirs + find entry with matching type
        for entry in self.0.iter() {
            if entry.name == ImageDataDirectoryEntry::ExportTable {
                // get table pointer by converting the RVA32 to actual address
                // use .getd the virtual_address base, then cast to ExportDirectoryTable pointer type
                let table = entry.virtual_address.get(entry.base_address);
                // cast table to reference to ExportDirectoryTable
                let table = unsafe { transmute(table) };
                // return table
                return Some(table);
            }
        }
        None
    }

    pub fn get_import_directory_table(&self) -> Option<&ImportDirectoryTable> {
        // loop thru data directories and find the entry with matching type
        for entry in self.0.iter() {
            if entry.name == ImageDataDirectoryEntry::ImportTable {
                // get table pointer by converting the RVA32 to actual address
                // use .getd the virtual_address base, then cast to ImportDirectoryTable pointer type
                let table = entry.virtual_address.get(entry.base_address);
                // cast table to ref to ImportDirectoryTable
                let table = unsafe { transmute(table) };
                // return table
                return Some(table);
            }
        }
        None
    }

    pub fn get_import_lookup_table(&self) -> Option<&ImportLookupTable> {
        // loop thru data directories + find entry with matching type
        for entry in self.0.iter() {
            if entry.name == ImageDataDirectoryEntry::ImportTable {
                // get table pointer by converting the RVA32 to actual address
                // use .getd the virtual_address base, then cast to ImportDirectoryTable pointer type
                let table = entry.virtual_address.get(entry.base_address);
                // cast table to reference to ImportDirectoryTable
                let table: &ImportDirectoryTable = unsafe { transmute(table) };
                let import_lookup_table = table.import_lookup_table_rva.get(entry.base_address);
                let import_lookup_table = unsafe { transmute(import_lookup_table) };
                // return table
                return Some(import_lookup_table);
            }
        }
        None
    }
    // gets entry corresponding to import table
    pub fn get_import_address_table(&self) -> Option<ImportAddressTableR> {
        // get pointer to ImportLookupTable
        let import_lookup_table = self.get_import_lookup_table().unwrap();

        //  loop thru data directories + find the entry with matching type
        for entry in self.0.iter() {
            if entry.name == ImageDataDirectoryEntry::IAT {
                // get table pointer by converting the RVA32 to actual address
                // use .getd the virtual_address base, then cast to ImportDirectoryTable pointer type
                let table = entry.virtual_address.get(entry.base_address);
                // cast table to reference to ImportDirectoryTable
                let table: &ImportAddressTable = unsafe { transmute(table) };
                // create ImportAddressTableR struct and fill it with entries from ImportAddressTable
                let mut table_r = ImportAddressTableR::default();
                // get count of entries in table by dividing entry.size by size of u64
                let count = entry.size as usize / core::mem::size_of::<u64>();
                //  loop thru entries in table and add them to table_r
                for i in 0..count {
                    let entry = unsafe { table.addresses.get_unchecked(i) };
                    let import_lookup_table_entry =
                        unsafe { import_lookup_table.entry.get_unchecked(i) };
                    // if entries are identical, target has not been bound
                    // could handle this, but skip it instead
                    if *entry == *import_lookup_table_entry {
                        continue;
                    }
                    // ensure entry is not null
                    assert_ne!(entry as *const u64 as *const _ as u64, 0);
                    // create ImportAddressEntry struct
                    let entry_r = ImportAddressEntry {
                        iat_entry_address: entry as *const _ as u64,
                        target_function_address: *entry,
                    };
                    // add entry to ImportAddressTableR
                    table_r.addresses.push(entry_r);
                }

                // return table
                return Some(table_r);
            }
        }
        None
    }
    pub fn is_within_range(
        &self,
        target_type: ImageDataDirectoryEntry,
        address: usize,
    ) -> Option<bool> {
        //  loop thru data directories and find the entry with matching type
        for entry in self.0.iter() {
            if entry.name == target_type {
                // get table pointer by converting the RVA32 to actual address
                // use .getd the virtual_address base, then cast to ExportDirectoryTable pointer type
                let start_addr = entry.virtual_address.get(entry.base_address) as *const _ as usize;
                let end_addr = start_addr + entry.size as usize;
                return Some(address >= start_addr && address < end_addr);
            }
        }
        None
    }
}

// define ImageDataDirectory struct
#[derive(Clone)]
#[repr(C)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

pub struct ImageDataDirectoryInfo {
    pub virtual_address: RVA32<()>,
    pub size: u32,
    pub base_address: usize,
    pub name: ImageDataDirectoryEntry,
}

impl ImageDataDirectoryInfo {
    // checks if provided usize is within range of this section described by the combination of the base_address and our virtual_address RVA
    pub fn is_within_range(&self, address: usize) -> bool {
        let base_address = self.base_address;
        let virtual_address = self.virtual_address.get(base_address) as *const _ as usize;
        address >= virtual_address && address < virtual_address + self.size as usize
    }
}

// export Directory Table as described in PE format
#[derive(Clone)]
#[repr(C)]
pub struct ExportDirectoryTable {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32,
    pub ordinal_base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub export_address_table_rva: RVA32<ExportAddressTable>,
    pub name_ptr_rva: RVA32<ExportNamePtrTable>,
    pub ordinal_table_rva: RVA32<ExportOrdinalTable>,
}

// define import directory table as described in PE format
#[derive(Clone)]
#[repr(C)]
pub struct ImportDirectoryTable {
    pub import_lookup_table_rva: RVA32<ImportLookupTable>,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name_rva: RVA32<ASCIIString>,
    pub import_address_table_rva: RVA32<ImportAddressTable>,
}

// define import address table
#[derive(Clone)]
#[repr(C)]
pub struct ImportAddressTable {
    pub addresses: [u64; 0],
}

#[derive(Clone)]
#[repr(C)]
pub struct ImportAddressEntry {
    pub iat_entry_address: u64,
    pub target_function_address: u64,
}

#[derive(Clone, Default)]
pub struct ImportAddressTableR {
    pub addresses: Vec<ImportAddressEntry>,
}

// define import lookup table
#[derive(Clone)]
#[repr(C)]
pub struct ImportLookupTable {
    pub entry: [u64; 0],
}

// define ExportOrdinalTable (array of u16)
#[derive(Clone)]
#[repr(C)]
pub struct ExportOrdinalTable {
    pub ordinals: [ExportAddressTableIndex; 0],
}

// ExportNamePtrTable is an array of RVA32s to ASCII strings
#[derive(Clone)]
#[repr(C)]
pub struct ExportNamePtrTable {
    pub name_ptr: [RVA32<ASCIIString>; 0],
}

// defines ASCIIString type (null terminated ASCII string)
#[derive(Clone)]
#[repr(C)]
pub struct ASCIIString {
    pub string: [u8; 0],
}

impl ASCIIString {
    // enumerates bytes of string until it finds a null byte, returns the length.
    // manually count bytes as type has no associated size information
    pub fn len(&self) -> usize {
        let mut len = 0;
        loop {
            if unsafe { *self.string.get_unchecked(len) } == 0 {
                return len;
            }
            len += 1;
        }
    }
    // converts ASCIIString to Rust String
    pub fn to_string(&self) -> String {
        let len = self.len();
        let mut string = String::with_capacity(len);
        for i in 0..len {
            string.push(unsafe { *self.string.get_unchecked(i) } as char);
        }
        string
    }
}

impl ExportDirectoryTable {
    // get entry from the export_address_table_rva by obtaining ExportAddressTable + indexing into it with provided index, checking that index is within bounds based on the number_of_functions field
    pub fn get_export_address_table_entry(
        &self,
        index: ExportAddressTableIndex,
        base_address: usize,
    ) -> Option<&ExportAddressTableEntry> {
        let index = index.0 as usize;
        if index >= self.number_of_functions as usize {
            return None;
        }
        // get underlying ExportAddressTable by applying the base_address to RVA32
        let export_address_table = self.export_address_table_rva.get(base_address);
        // index into table, use an unchecked index as the table is defined as a 0-size array + and index is checked above
        let entry = unsafe { export_address_table.entries.get_unchecked(index) };
        Some(entry)
    }
    // gets entry from ExportOrdinalTable, similar to how we get entries from ExportAddressTable
    pub fn get_export_ordinal_table_entry(
        &self,
        index: OrdinalTableIndex,
        base_address: usize,
    ) -> Option<&ExportAddressTableIndex> {
        let index = index.0 as usize;
        if index >= self.number_of_names as usize {
            return None;
        }
        let export_ordinal_table = self.ordinal_table_rva.get(base_address);
        Some(unsafe { export_ordinal_table.ordinals.get_unchecked(index) })
    }
    // enumerates ExportNamePtrTable looking for String match with provided name
    // gets ExportNamePtrTable use the provided base_address, similar to how we get tables in get_export_address_table_entry +get_export_ordinal_table_entry. 
    // return value is option around index corresponding to String match found (if any)
    pub fn get_export_name_ptr_table_entry(
        &self,
        name: &str,
        base_address: usize,
    ) -> Option<OrdinalTableIndex> {
        let export_name_ptr_table = self.name_ptr_rva.get(base_address);
        for i in 0..self.number_of_names {
            let export_name_ptr =
                unsafe { export_name_ptr_table.name_ptr.get_unchecked(i as usize) };
            let export_name = export_name_ptr.get(base_address);
            if export_name.to_string().to_lowercase() == name.to_lowercase() {
                return Some(OrdinalTableIndex(i));
            }
        }
        None
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct ExportAddressTableIndex(u16);

#[derive(Clone, Copy)]
#[repr(C)]
pub struct OrdinalTableIndex(u32);

// define ExportAddressTableEntry which is a RVA32 to either a function or a string
#[derive(Clone)]
#[repr(transparent)]
pub struct ExportAddressTableEntry(pub RVA32<()>);

// ExportAddressTable
#[derive(Clone)]
#[repr(C)]
pub struct ExportAddressTable {
    // export address table is array of u32 values
    // size based on number_of_functions field in ExportDirectoryTable
    pub entries: [ExportAddressTableEntry; 0],
}

// enum representing ImageDataDirectory entries
#[derive(PartialEq, Eq, Copy, Clone)]
pub enum ImageDataDirectoryEntry {
    ExportTable = 0,
    ImportTable = 1,
    ResourceTable = 2,
    ExceptionTable = 3,
    CertificateTable = 4,
    BaseRelocationTable = 5,
    Debug = 6,
    Architecture = 7,
    GlobalPtr = 8,
    TLSTable = 9,
    LoadConfigTable = 10,
    BoundImport = 11,
    IAT = 12,
    DelayImportDescriptor = 13,
    CLRRuntimeHeader = 14,
    Reserved = 15,
}

// impl ImageDataDirectoryEntry to convert index into enum
impl ImageDataDirectoryEntry {
    pub fn from_index(index: usize) -> Option<ImageDataDirectoryEntry> {
        match index {
            0 => Some(ImageDataDirectoryEntry::ExportTable),
            1 => Some(ImageDataDirectoryEntry::ImportTable),
            2 => Some(ImageDataDirectoryEntry::ResourceTable),
            3 => Some(ImageDataDirectoryEntry::ExceptionTable),
            4 => Some(ImageDataDirectoryEntry::CertificateTable),
            5 => Some(ImageDataDirectoryEntry::BaseRelocationTable),
            6 => Some(ImageDataDirectoryEntry::Debug),
            7 => Some(ImageDataDirectoryEntry::Architecture),
            8 => Some(ImageDataDirectoryEntry::GlobalPtr),
            9 => Some(ImageDataDirectoryEntry::TLSTable),
            10 => Some(ImageDataDirectoryEntry::LoadConfigTable),
            11 => Some(ImageDataDirectoryEntry::BoundImport),
            12 => Some(ImageDataDirectoryEntry::IAT),
            13 => Some(ImageDataDirectoryEntry::DelayImportDescriptor),
            14 => Some(ImageDataDirectoryEntry::CLRRuntimeHeader),
            15 => Some(ImageDataDirectoryEntry::Reserved),
            _ => None,
        }
    }
    // convert enum into usize index
    pub fn to_index(&self) -> usize {
        match self {
            ImageDataDirectoryEntry::ExportTable => 0,
            ImageDataDirectoryEntry::ImportTable => 1,
            ImageDataDirectoryEntry::ResourceTable => 2,
            ImageDataDirectoryEntry::ExceptionTable => 3,
            ImageDataDirectoryEntry::CertificateTable => 4,
            ImageDataDirectoryEntry::BaseRelocationTable => 5,
            ImageDataDirectoryEntry::Debug => 6,
            ImageDataDirectoryEntry::Architecture => 7,
            ImageDataDirectoryEntry::GlobalPtr => 8,
            ImageDataDirectoryEntry::TLSTable => 9,
            ImageDataDirectoryEntry::LoadConfigTable => 10,
            ImageDataDirectoryEntry::BoundImport => 11,
            ImageDataDirectoryEntry::IAT => 12,
            ImageDataDirectoryEntry::DelayImportDescriptor => 13,
            ImageDataDirectoryEntry::CLRRuntimeHeader => 14,
            ImageDataDirectoryEntry::Reserved => 15,
        }
    }
}

// enum representing valid Windows Subsystem values
#[derive(PartialEq, Eq, Copy, Clone)]
#[repr(u16)]
pub enum WindowsSubsystem {
    ImageSubsystemUnknown = 0,
    ImageSubsystemNative = 1,
    ImageSubsystemWindowsGui = 2,
    ImageSubsystemWindowsCui = 3,
    ImageSubsystemOs2Cui = 5,
    ImageSubsystemPosixCui = 7,
    ImageSubsystemNativeWindows = 8,
    ImageSubsystemWindowsCeGui = 9,
    ImageSubsystemEfiApplication = 10,
    ImageSubsystemEfiBootServiceDriver = 11,
    ImageSubsystemEfiRuntimeDriver = 12,
    ImageSubsystemEfiRom = 13,
    ImageSubsystemXbox = 14,
    ImageSubsystemWindowsBootApplication = 16,
}

bitflags! {
    /// `SectionCharacteristics` bitflags used to describe characteristics of sections
    pub struct SectionCharacteristics: u32 {
        const IMAGE_SCN_TYPE_NO_PAD = 0x00000008;
        const IMAGE_SCN_CNT_CODE = 0x00000020;
        const IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040;
        const IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080;
        const IMAGE_SCN_LNK_OTHER = 0x00000100;
        const IMAGE_SCN_LNK_INFO = 0x00000200;
        const IMAGE_SCN_LNK_REMOVE = 0x00000800;
        const IMAGE_SCN_LNK_COMDAT = 0x00001000;
        const IMAGE_SCN_GPREL = 0x00008000;
        const IMAGE_SCN_MEM_PURGEABLE = 0x00020000;
        const IMAGE_SCN_MEM_16BIT = 0x00020000;
        const IMAGE_SCN_MEM_LOCKED = 0x00040000;
        const IMAGE_SCN_MEM_PRELOAD = 0x00080000;
        const IMAGE_SCN_ALIGN_1BYTES = 0x00100000;
        const IMAGE_SCN_ALIGN_2BYTES = 0x00200000;
        const IMAGE_SCN_ALIGN_4BYTES = 0x00300000;
        const IMAGE_SCN_ALIGN_8BYTES = 0x00400000;
        const IMAGE_SCN_ALIGN_16BYTES = 0x00500000;
        const IMAGE_SCN_ALIGN_32BYTES = 0x00600000;
        const IMAGE_SCN_ALIGN_64BYTES = 0x00700000;
        const IMAGE_SCN_ALIGN_128BYTES = 0x00800000;
        const IMAGE_SCN_ALIGN_256BYTES = 0x00900000;
        const IMAGE_SCN_ALIGN_512BYTES = 0x00A00000;
        const IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000;
        const IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000;
        const IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000;
        const IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000;
        const IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000;
        const IMAGE_SCN_MEM_DISCARDABLE = 0x02000000;
        const IMAGE_SCN_MEM_NOT_CACHED = 0x04000000;
        const IMAGE_SCN_MEM_NOT_PAGED = 0x08000000;
        const IMAGE_SCN_MEM_SHARED = 0x10000000;
        const IMAGE_SCN_MEM_EXECUTE = 0x20000000;
        const IMAGE_SCN_MEM_READ = 0x40000000;
        const IMAGE_SCN_MEM_WRITE = 0x80000000;
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct PEB {
    junk1: u32,
    junk2: usize,
    junk3: usize,
    pub ldr: *const PebLdrData,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct ListEntry {
    pub flink: *const ListEntry,
    pub blink: *const ListEntry,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct PebLdrData {
    pub junk: [usize; 4],
    pub in_memory_order_module_list: ListEntry,
}
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct LdrDataTableEntry {
    pub in_load_order_links: ListEntry,
    pub in_memory_order_links: ListEntry,
    pub in_initialization_order_links: ListEntry,
    pub dll_base: usize,
    pub entry_point: usize,
    pub size_of_image: usize,
    pub full_dll_name: UnicodeString,
    pub base_dll_name: UnicodeString,
    pub flags: u32,
    pub load_count: u16,
    pub tls_index: u16,
    pub hash_links: ListEntry,
    pub time_date_stamp: u32,
}

#[derive(Copy, Clone)]
#[repr(packed)]
pub struct CoffX64Relocation {
    pub virtual_address: u32,
    pub symbol_table_index: u32,
    pub typ: CoffX64RelocationType,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[repr(u16)]
pub enum CoffX64RelocationType {
    ImageRelAmd64Absolute = 0x0000,
    ImageRelAmd64Addr64 = 0x0001,
    ImageRelAmd64Addr32 = 0x0002,
    ImageRelAmd64Addr32nb = 0x0003,
    ImageRelAmd64Rel32 = 0x0004,
    ImageRelAmd64Rel321 = 0x0005,
    ImageRelAmd64Rel322 = 0x0006,
    ImageRelAmd64Rel323 = 0x0007,
    ImageRelAmd64Rel324 = 0x0008,
    ImageRelAmd64Rel325 = 0x0009,
    ImageRelAmd64Section = 0x000A,
    ImageRelAmd64Secrel = 0x000B,
    ImageRelAmd64Secrel7 = 0x000C,
    ImageRelAmd64Token = 0x000D,
    ImageRelAmd64Srel32 = 0x000E,
    ImageRelAmd64Pair = 0x000F,
    ImageRelAmd64Sspan32 = 0x0010,
}

#[derive(Clone)]
#[repr(packed)]
pub struct SectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_line_numbers: u32,
    pub number_of_relocations: u16,
    pub number_of_line_numbers: u16,
    pub characteristics: SectionCharacteristics,
}

impl SectionHeader {
    pub fn get_name(&self, str_table: usize) -> String {
        if self.name[0] == b'/' {
            let mut offset = String::new();
            for i in 1..8 {
                if self.name[i] == 0 {
                    break;
                }
                offset.push(self.name[i] as char);
            }
            // convert ASCII representation of offset into u64
            let offset: usize = usize::from_str_radix(&offset, 10).unwrap();
            // get string from string table
            let name_ptr = offset as usize + str_table;
            // Convert name_ptr to a null-terminated str
            // collect all bytes in name_ptr until null byte is reached
            let mut name_bytes = Vec::new();
            loop {
                let byte = unsafe { *((name_ptr + name_bytes.len()) as *const u8) };
                if byte == 0 {
                    break;
                }
                name_bytes.push(byte);
            }
            // convert the bytes to a str
            // **unsafe if object is corrupted
            // safety: remove unwrap + return Result
            return core::str::from_utf8(&name_bytes).unwrap().to_string();
        }
        let mut name = String::new();
        for i in 0..8 {
            if self.name[i] == 0 {
                break;
            }
            name.push(self.name[i] as char);
        }
        name
    }
}

#[derive(Clone)]
#[repr(packed)]
pub struct ImageFileHeader {
    pub machine: ImageFileMachine,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

impl ImageFileHeader {
    pub fn get_symbols(&self, base_address: usize) -> Option<&[CoffSymbol]> {
        if self.pointer_to_symbol_table == 0 {
            return None;
        }
        let symbol_table_ptr =
            (base_address + self.pointer_to_symbol_table as usize) as *const CoffSymbol;
        let symbol_table =
            unsafe { slice::from_raw_parts(symbol_table_ptr, self.number_of_symbols as usize) };
        Some(symbol_table)
    }

    pub fn get_string_table(&self, base_address: usize) -> Option<&[u8]> {
        let symbol_table_ptr = base_address + self.pointer_to_symbol_table as usize;
        let str_table_ptr = symbol_table_ptr
            + (self.number_of_symbols as usize * core::mem::size_of::<CoffSymbol>());
        let str_table_len = unsafe { *(str_table_ptr as *const u32) } as usize;
        if str_table_len == 0 {
            return None;
        }
        let str_table = unsafe { slice::from_raw_parts(str_table_ptr as *const u8, str_table_len) };
        Some(str_table)
    }
    pub fn get_symbol_name(&self, base_address: usize, symbol: CoffSymbol) -> Option<String> {
        let symbol_table_ptr = base_address + self.pointer_to_symbol_table as usize;
        let str_table_ptr = symbol_table_ptr
            + (self.number_of_symbols as usize * core::mem::size_of::<CoffSymbol>());
        let str_table_len = unsafe { *(str_table_ptr as *const u32) } as usize;
        if str_table_len == 0 {
            return None;
        }
        Some(symbol.name.get_name(str_table_ptr))
    }
}

/// COFF Symbol table (packed to prevent padding)
#[repr(packed)]
#[derive(Clone, Copy)]
pub struct CoffSymbol {
    pub name: CoffSymbolName,
    pub value: u32,
    pub section_number: i16,
    pub type_: CoffSymbolType,
    pub storage_class: CoffSymbolStorageClass,
    pub number_of_aux_symbols: u8,
}

/// COFF symbol type
#[derive(Clone, Copy, Debug)]
#[repr(u16)]
pub enum CoffSymbolType {
    ImageSymTypeNull = 0x0000,
    ImageSymTypeVoid = 0x0001,
    ImageSymTypeChar = 0x0002,
    ImageSymTypeShort = 0x0003,
    ImageSymTypeInt = 0x0004,
    ImageSymTypeLong = 0x0005,
    ImageSymTypeFloat = 0x0006,
    ImageSymTypeDouble = 0x0007,
    ImageSymTypeStruct = 0x0008,
    ImageSymTypeUnion = 0x0009,
    ImageSymTypeEnum = 0x000A,
    ImageSymTypeMoe = 0x000B,
    ImageSymTypeByte = 0x000C,
    ImageSymTypeWord = 0x000D,
    ImageSymTypeUint = 0x000E,
    ImageSymTypeDword = 0x000F,
}

/// COFF symbol storage class
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CoffSymbolStorageClass {
    ImageSymClassEndOfFunction = 0xFF,
    ImageSymClassNull = 0x00,
    ImageSymClassAutomatic = 0x01,
    ImageSymClassExternal = 0x02,
    ImageSymClassStatic = 0x03,
    ImageSymClassRegister = 0x04,
    ImageSymClassExternalDef = 0x05,
    ImageSymClassLabel = 0x06,
    ImageSymClassUndefinedLabel = 0x07,
    ImageSymClassMemberOfStruct = 0x08,
    ImageSymClassArgument = 0x09,
    ImageSymClassStructTag = 0x0A,
    ImageSymClassMemberOfUnion = 0x0B,
    ImageSymClassUnionTag = 0x0C,
    ImageSymClassTypeDefinition = 0x0D,
    ImageSymClassUndefinedStatic = 0x0E,
    ImageSymClassEnumTag = 0x0F,
    ImageSymClassMemberOfEnum = 0x10,
    ImageSymClassRegisterParam = 0x11,
    ImageSymClassBitField = 0x12,
    ImageSymClassBlock = 0x64,
    ImageSymClassFunction = 0x65,
    ImageSymClassEndOfStruct = 0x66,
    ImageSymClassFile = 0x67,
    ImageSymClassSection = 0x68,
    ImageSymClassWeakExternal = 0x69,
    ImageSymClassClrToken = 0x6B,
}

#[repr(packed)]
#[derive(Clone, Copy)]
pub struct CoffSymbolName(pub [u8; 8]);

impl CoffSymbolName {
    fn get_name(&self, str_table_ptr: usize) -> String {
        let name = &self.0[..];
        if name[0] == 0 {
            let name_offset = u32::from_le_bytes(name[4..8].try_into().unwrap());
            // name_offset + str_table_ptr = UTF8 null-terminated string
            let name_ptr = name_offset as usize + str_table_ptr;
            // convert name_ptr to null-terminated str
            // collect all bytes in name_ptr until null byte is reached
            let mut name_bytes = Vec::new();
            loop {
                let byte = unsafe { *((name_ptr + name_bytes.len()) as *const u8) };
                if byte == 0 {
                    break;
                }
                name_bytes.push(byte);
            }
            // convert bytes to str
            // **unsafe, if object is corrupted
            // safety: remove unwrap + return Result
            return core::str::from_utf8(&name_bytes).unwrap().to_string();
        }
        // convert first 8 bytes to a str
        let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        String::from_utf8_lossy(&name[..len]).to_string()
    }
}

// enum representing valid ImageFileMachine values
#[derive(PartialEq, Eq, Clone, Copy)]
#[repr(u16)]
pub enum ImageFileMachine {
    // all possible Machine Types
    Unknown = 0x0,
    Am33 = 0x1d3,
    Amd64 = 0x8664,
    Arm = 0x1c0,
    Arm64 = 0xaa64,
    ArmNT = 0x1c4,
    Ebc = 0xebc,
    I386 = 0x14c,
    Ia64 = 0x200,
    M32R = 0x9041,
    Mips16 = 0x266,
    MipsFpu = 0x366,
    MipsFpu16 = 0x466,
    PowerPC = 0x1f0,
    PowerPCFP = 0x1f1,
    R4000 = 0x166,
    RiscV32 = 0x5032,
    RiscV64 = 0x5064,
    RiscV128 = 0x5128,
    SH3 = 0x1a2,
    SH3DSP = 0x1a3,
    SH4 = 0x1a6,
    SH5 = 0x1a8,
    Thumb = 0x1c2,
    WceMipsV2 = 0x169,
}

// constant representing a PE signature, e.g. "PE\0\0"
pub const PE_SIGNATURE: u32 = u32::from_le_bytes(*b"PE\0\0");

#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct PESignature(u32);

// implement PESignature + verify sig is valid
impl PESignature {
    pub fn is_valid(&self) -> bool {
        self.0 == PE_SIGNATURE
    }
}

// RVA32 is a relative virtual address to an underlying type
#[derive(Copy, Clone, Default)]
#[repr(transparent)]
pub struct RVA32<T: ?Sized>(pub u32, pub core::marker::PhantomData<T>);

// impl RVA32 with a function that adds usize base_address then derefs the pointer
impl<T> RVA32<T> {
    pub fn get(&self, base_address: usize) -> &T {
        unsafe { &*((base_address + self.0 as usize) as *const T) }
    }
    pub fn get_mut(&mut self, base_address: usize) -> &mut T {
        unsafe { &mut *((base_address + self.0 as usize) as *mut T) }
    }
}

#[derive(Copy, Clone, Default)]
#[repr(transparent)]
pub struct RVA64<T: ?Sized>(pub u64, pub core::marker::PhantomData<T>);

// impl RVA64 with function that adds usize base_address + then derefs the pointer
impl<T> RVA64<T> {
    pub fn get(&self, base_address: usize) -> &T {
        unsafe { &*((base_address + self.0 as usize) as *const T) }
    }
    pub fn get_mut(&mut self, base_address: usize) -> &mut T {
        unsafe { &mut *((base_address + self.0 as usize) as *mut T) }
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *const u16,
}

// impl Default for UnicodeString
impl Default for UnicodeString {
    fn default() -> Self {
        Self {
            length: 0,
            maximum_length: 0,
            buffer: core::ptr::null(),
        }
    }
}

impl UnicodeString {
    // convert buffer to utf16 string based on length field
    pub fn extract_string(&self) -> Option<String> {
        if self.length == 0 || self.buffer as *const _ as usize == 0 {
            return None;
        }
        let slice = unsafe { slice::from_raw_parts(self.buffer, self.length as usize / 2) };
        // convert slice to String
        core::char::decode_utf16(slice.iter().cloned())
            .collect::<Result<String, _>>()
            .ok()
    }
}
```

now that we've mapped + define the structures and layouts of a PE file, as well as how to handle RVAs, we can move ahead with writing our custom minidumper! stay tuned for part 2.
