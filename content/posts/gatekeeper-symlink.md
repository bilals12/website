---
title: "bypassing Gatekeeper via symlinks"
date: 2026-01-12T20:14:11Z
draft: false
toc: true
next: true
nomenu: false
notitle: false
---

## tl;dr

i found that when macOS's Archive Utility extracts a ZIP archive containing symlinks, the symlinks themselves do not inherit the `com.apple.quarantine` extended attribute. when a user executes the symlink, Gatekeeper checks the symlink's quarantine status (absent) rather than resolving the symlink and checking the target's status (present). this allows unsigned/un-notarized code to execute without any security prompt. 

## background

### quarantine: the extended attribute

macOS uses extended attributes (`xattrs`) to attach metadata to files without modifying their contents. the `com.apple.quarantine` attribute is one such `xattr`, and it is the foundation of macOS's download security model. 

when Safari (or any quarantine-aware application) downloads a file, it calls the `LSQuarantineDataSetValue()` function from `LaunchServices` to attach the quarantine `xattr`:


```c
void LSQuarantineDataSetValue(CFURLRef url, CFStringRef key, CFTypeRef value) {
    // construct quarantine data and calls
    setxattr(path, "com.apple.quarantine", data, len, 0, XATTR_NOFOLLOW);
}
```

the quarantine attribute itself is a semicolon-delimited string:

```
0081;67890abc;Safari;12345678-1234-1234-1234-123456789012
│    │        │      │
│    │        │      └─ UUID (tracking identifier)
│    │        └─ originating application
│    └─ timestamp (hex seconds since epoch)
└─ flags (bitfield)
```

the `flags` field is a 16-bit value where:
- bit 0 (`0x0001`): file was downloaded from the internet
- bit 6 (`0x0040`): user has approved execution
- bit 7 (`0x0080`): file has been evaluated by Gatekeeper

so: `0081` would mean that the file was downloaded from the internet (`0x0001`) + evaluated by Gatekeeper (`0x0080`).

you can inspect quarantine with:

```bash
xattr -p com.apple.quarantine ~/Downloads/example.zip
0083;6940741b;Safari;B691160F-E9CE-4115-8B80-217F2DE8706B
```

```bash
xattr -p com.apple.quarantine ~/Downloads/malicious_download.zip | xxd | head -5
00000000: 3030 3833 3b36 3934 3037 3431 623b 5361  0083;6940741b;Sa
00000010: 6661 7269 3b42 3639 3131 3630 462d 4539  fari;B691160F-E9
00000020: 4345 2d34 3131 352d 3842 3830 2d32 3137  CE-4115-8B80-217
00000030: 4632 4445 3837 3036 420a                 F2DE8706B.
```

### quarantine propagation

whenever you extract an archive, the quarantine attribute must propagate from the archive to its contents. this is handled via the extracting application itself, not the kernel.

Archive Utility (`/System/Library/CoreServices/Applications/Archive Utility.app`) uses the `Archive` private framework to extract files. during extraction, it calls `copyfile()` with the `COPYFILE_XATTR` flag to preserve extended attributes, then explicitly propagates quarantine, somewhat like:

```c
for (each_file in archive) {
    extract_file(each_file, destination);

    if (archive_has_quarantine) {
        // propagate quarantine to extracted file
        char qdata[256];
        getxattr(archive_path, "com.apple.quarantine", qdata, sizeof(qdata), 0, 0);
        setxattr(extracted_path, "com.apple.quarantine", qdata, strlen(qdata), 0, 0);
    }
}
```

important: `setxattr()` by default follows symlinks. the `XATTR_NOFOLLOW` flag prevents this, so when Archive Utility calls `setxattr()` on a symlink **without** `XATTR_NOFOLLOW`, the attribute is applied to the symlink's target, not the symlink itself.

but...there's a problem here. symlinks on macOS can't have extended attributes at all (in the traditional sense). the `setxattr()` call on a symlink path will apply `xattr` to the target (if `XATTR_NOFOLLOW` is not set) or fail with `EPERM` (if `XATTR_NOFOLLOW` is set, since symlinks don't support `xattrs`).

this is a fundamental limitation of the filesystem. for reference, HFS+ and APFS both store extended attributes in a separate B-tree associated with the file's inode. symlinks, being "special" inode types, don't have the same `xattr` storage mechanism.

### gatekeeper: enforcement layer

Gatekeeper isn't a single component, but a collection of enforcement mechanisms:
1. `syspolicyd`: policy daemon that evaluates code signing and notarization
2. `Security.framework`: provides `SecAssessmentCreate()` API for policy evaluation
3. `LaunchServices`: hooks file opens and triggers an assessment
4. kernel (`AMFI`): Apple Mobile File Integrity enforces code signing at execution time.

when you double-click a file in Finder, the flow becomes:

```
Finder.app
    │
    ▼
LaunchServices (LSOpenURL)
    │
    ├─► check quarantine xattr on target path
    │   │
    │   ▼
    │   if quarantined:
    │       │
    │       ▼
    │   SecAssessmentCreate(path, kSecAssessmentDefaultFlags)
    │       │
    │       ▼
    │   syspolicyd evaluates:
    │       - code signature validity
    │       - notarization status (via Apple's servers)
    │       - user approval status
    │       │
    │       ▼
    │   if assessment fails:
    │       show Gatekeeper dialog
    │       block execution
    │
    ▼
posix_spawn() / execve()
    │
    ▼
kernel (AMFI)
    │
    ▼
process execution
```

the critical function here is `LaunchServices`. 

```c
OSStatus _LSOpenURLsWithRole(CFArrayRef urls, LSRolesMask roles, ...) {
    for (CFURLRef url in urls) {
        char path[PATH_MAX];
        CFURLGetFileSystemRepresentation(url, true, path, sizeof(path));

        //BUG: checks quarantine on the literal path with XATTR_NOFOLLOW
        // this means symlinks are checked for xattrs they can't have
        char qdata[256];
        ssize_t qlen = getxattr(path, "com.apple.quarantine", qdata, sizeof(qdata), 0, XATTR_NOFOLLOW);
        
        if (qlen > 0) {
            // file quarantined -> trigger assesssment
            SecAssessmentRef assessment = SecAssessmentCreate(url, flags, NULL, &error);
            if (!SecAssessmentResultIsAcceptable(assessment)) {
                return kLSApplicationNotFoundErr;
            }
        }

        _LSLaunchApplication(url, ...);
    }
}
```

`getxattr()` is called wth `XATTR_NOFOLLOW`, meaning it checks the `xattr` on the literal path (symlink) rather than the target. since symlinks can't have extended attributes, this check will always return `ENOATTR` for symlinks, regardless of whether their target is quarantined or not. 

## execution

say you have a .zip that has this directory structure post-extraction:

```
extracted/
├── payload.command     # xattr: com.apple.quarantine = "0081;..."
└── run.command -> payload.command    # xattr: (none - symlinks can't have xattrs)
```

when a user double-clicks `run.command`, the Finder sends an `open` request to `LaunchServices`, with the path `/Users/user/Downloads/extracted/run.command`. `LaunchServices` calls `getxattr(path, "com.apple.quarantine", ..., XATTR_NOFOLLOW)`. again, `XATTR_NOFOLLOW` means to check the symlink itself, **don't follow it**. `getxattr()` returns `-1` (`ENOATTR`) and `LaunchServices` sees no quarantine -> skip Gatekeeper assessment. 

but `LaunchServices` **will** resolve the symlink for execution: `realpath("/Users/user/Downloads/extracted/run.command")` -> `"/Users/user/Downloads/extracted/payload.command"`. `posix_spawan()` then executes `payload.command`, even though it *is* quarantined, but was never checked.

this is possibly because `LaunchServices` uses the `-s` flag to check the symlink itself, instead of just the `-p` flag. so: `xattr -s -p` instead of `xattr -p`.

## exploitation

in this demo, i'm serving a malicious ZIP from a linux server on my local network. the ZIP contains:
- `payload.command`: unsigned bash script that displays a dialog
- `install.command`: symlink pointing to `payload.command`

```
archive_contents/
├── payload.command          # the actual script
└── install.command -> payload.command   # symlink
```

the flow:
1. Safari downloads `software_update.zip` and applies `com.apple.quarantine`
2. double-clicking the ZIP triggers Archive Utility, which extracts both files
3. `payload.command` inherits quarantine from the ZIP
4. `install.command` (the symlink) does not—symlinks can't hold xattrs
5. double-clicking `install.command` in Finder triggers LaunchServices
6. `LaunchServices` checks quarantine on the symlink path with `XATTR_NOFOLLOW`
7. symlink has no quarantine → Gatekeeper assessment skipped
8. `LaunchServices` resolves the symlink and executes `payload.command`

{{< youtube U8IpUWqV7SQ >}}

no code signing. no notarization. no right-click "Open". no terminal. just click.
