# Metallus
### Enumeration
```
# Nmap 7.92 scan initiated Tue Apr 19 04:17:51 2022 as: nmap -sCV -v -p- -oN tcp.out 192.168.51.96
Nmap scan report for 192.168.51.96
Host is up (0.00037s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
12000/tcp open  cce4x?
22222/tcp open  ssh           OpenSSH for_Windows_8.1 (protocol 2.0)
| ssh-hostkey:
|   3072 5b:1b:c7:30:66:22:2a:22:fd:a3:68:6e:56:1c:6d:86 (RSA)
|_  256 57:9d:ca:b4:93:7d:cd:5e:3f:b7:b1:a5:bd:f5:44:bf (ED25519)
40443/tcp open  unknown
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help:
|     HTTP/1.1 500
|     Transfer-Encoding: chunked
|     Date: Tue, 19 Apr 2022 08:20:03 GMT
|     Connection: close
|     Server: AppManager
|   GetRequest:
|     HTTP/1.1 200
|     Set-Cookie: JSESSIONID_APM_40443=58D54A57EF1A4C30CC1FC7BD3403F7C5; Path=/; HttpOnly
|     Accept-Ranges: bytes
|     ETag: W/"261-1591621693000"
|     Last-Modified: Mon, 08 Jun 2020 13:08:13 GMT
|     Content-Type: text/html
|     Content-Length: 261
|     Date: Tue, 19 Apr 2022 08:19:48 GMT
|     Connection: close
|     Server: AppManager
|     <!-- $Id$ -->
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
|     <html>
|     <head>
|     <!-- This comment is for Instant Gratification to work applications.do -->
|     <script>
|     window.open("/webclient/common/jsp/home.jsp", "_top");
|     </script>
|     </head>
|     </html>
|   Kerberos, SMBProgNeg, TLSSessionReq:
|     HTTP/1.1 500
|     Transfer-Encoding: chunked
|     Date: Tue, 19 Apr 2022 08:20:16 GMT
|     Connection: close
|     <!-- $Id$ -->
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
|     <html>
|     <head>
|     <!-- This comment is for Instant Gratification to work applications.do -->
|     <script>
|     window.open("/webclient/common/jsp/home.jsp", "_top");
|     </script>
|     </head>
|     </html>
|   Kerberos, SMBProgNeg, TLSSessionReq:
|     HTTP/1.1 500
|     Transfer-Encoding: chunked
|     Date: Tue, 19 Apr 2022 08:20:16 GMT
|     Connection: close
|     Server: AppManager
|   TerminalServerCookie:
|     HTTP/1.1 500
|     Transfer-Encoding: chunked
|     Date: Tue, 19 Apr 2022 08:20:13 GMT
|     Connection: close
|_    Server: AppManager
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  tcpwrapped
49691/tcp open  java-rmi      Java RMI
49717/tcp open  unknown
49780/tcp open  unknown
| fingerprint-strings:
|   ms-sql-s:
|_    CLOSE_SESSION
49781/tcp open  unknown
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port40443-TCP:V=7.92%I=7%D=4/19%Time=625E70A4%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,246,"HTTP/1\.1\x20200\x20\r\nSet-Cookie:\x20JSESSIONID_APM_40
SF:443=58D54A57EF1A4C30CC1FC7BD3403F7C5;\x20Path=/;\x20HttpOnly\r\nAccept-
SF:Ranges:\x20bytes\r\nETag:\x20W/\"261-1591621693000\"\r\nLast-Modified:\
SF:x20Mon,\x2008\x20Jun\x202020\x2013:08:13\x20GMT\r\nContent-Type:\x20tex
SF:t/html\r\nContent-Length:\x20261\r\nDate:\x20Tue,\x2019\x20Apr\x202022\
SF:x2008:19:48\x20GMT\r\nConnection:\x20close\r\nServer:\x20AppManager\r\n
SF:\r\n<!--\x20\$Id\$\x20-->\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD
SF:\x20HTML\x204\.01\x20Transitional//EN\">\n<html>\n<head>\n<!--\x20This\
SF:x20comment\x20is\x20for\x20Instant\x20Gratification\x20to\x20work\x20ap
SF:plications\.do\x20-->\n<script>\n\n\twindow\.open\(\"/webclient/common/
SF:jsp/home\.jsp\",\x20\"_top\"\);\n\n</script>\n\n</head>\n</html>\n")%r(
SF:DNSVersionBindReqTCP,7E,"HTTP/1\.1\x20500\x20\r\nTransfer-Encoding:\x20
SF:chunked\r\nDate:\x20Tue,\x2019\x20Apr\x202022\x2008:20:03\x20GMT\r\nCon
SF:nection:\x20close\r\nServer:\x20AppManager\r\n\r\n0\r\n\r\n")%r(DNSStat
SF:usRequestTCP,7E,"HTTP/1\.1\x20500\x20\r\nTransfer-Encoding:\x20chunked\
SF:r\nDate:\x20Tue,\x2019\x20Apr\x202022\x2008:20:03\x20GMT\r\nConnection:
SF:\x20close\r\nServer:\x20AppManager\r\n\r\n0\r\n\r\n")%r(Help,7E,"HTTP/1
SF:\.1\x20500\x20\r\nTransfer-Encoding:\x20chunked\r\nDate:\x20Tue,\x2019\
SF:x20Apr\x202022\x2008:20:03\x20GMT\r\nConnection:\x20close\r\nServer:\x2
SF:0AppManager\r\n\r\n0\r\n\r\n")%r(TerminalServerCookie,7E,"HTTP/1\.1\x20
SF:500\x20\r\nTransfer-Encoding:\x20chunked\r\nDate:\x20Tue,\x2019\x20Apr\
SF:x202022\x2008:20:13\x20GMT\r\nConnection:\x20close\r\nServer:\x20AppMan
SF:ager\r\n\r\n0\r\n\r\n")%r(TLSSessionReq,7E,"HTTP/1\.1\x20500\x20\r\nTra
SF:nsfer-Encoding:\x20chunked\r\nDate:\x20Tue,\x2019\x20Apr\x202022\x2008:
SF:20:16\x20GMT\r\nConnection:\x20close\r\nServer:\x20AppManager\r\n\r\n0\
SF:r\n\r\n")%r(Kerberos,7E,"HTTP/1\.1\x20500\x20\r\nTransfer-Encoding:\x20
SF:chunked\r\nDate:\x20Tue,\x2019\x20Apr\x202022\x2008:20:16\x20GMT\r\nCon
SF:nection:\x20close\r\nServer:\x20AppManager\r\n\r\n0\r\n\r\n")%r(SMBProg
SF:Neg,7E,"HTTP/1\.1\x20500\x20\r\nTransfer-Encoding:\x20chunked\r\nDate:\
SF:x20Tue,\x2019\x20Apr\x202022\x2008:20:16\x20GMT\r\nConnection:\x20close
SF:\r\nServer:\x20AppManager\r\n\r\n0\r\n\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port49780-TCP:V=7.92%I=7%D=4/19%Time=625E712A%P=x86_64-pc-linux-gnu%r(m
SF:s-sql-s,1A,"\0\0\0\x16\0\rCLOSE_SESSION\0\x010\0\0\0\0");
MAC Address: 00:50:56:BF:AB:FD (VMware)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2022-04-19T08:22:15
|_  start_date: N/A
```

##### SMB
No anonymous access.

##### RPC
No anonymous access.

##### 40443
Webserver running Zoho ManageEngine Application Manager Build 14710. We're able to login with `admin:admin`. Searching for exploits, we find an authenticated RCE (CVE-2020-14008).

Using the exploit specifically with local port 443, we get a shell as `nt authority\system`.

I tried to work out why only port 443 worked using the below command:

```powershell
get-netfirewallrule | ? {$_.Enabled -eq 'True' -and $_.Action -eq 'Allow' -and $_.Direction -eq 'Outbound'} | Format-Table -Property @{Name='Protocol';Expression={($PSItem | Get-NetFirewallPortFilter).Protocol}},@{Name='LocalPort';Expression={($PSItem | Get-NetFirewallPortFilter).LocalPort}},@{Name='RemotePort';Expression={($PSItem | Get-NetFirewallPortFilter).RemotePort}},@{Name='RemoteAddress';Expression={($PSItem | Get-NetFirewallAddressFilter).RemoteAddress}},Profile
```

There were a couple of entries where only `443` was allowed as a `RemotePort`, but there were also a number of entries, some of which seemed to permit `80` and others which allowed `Any` as the remote port, so still unclear.