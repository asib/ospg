# Algernon
### Enumeration
```
# Nmap 7.92 scan initiated Sun Apr 24 14:12:43 2022 as: nmap -sCV -v -oN tcp_1000.out 192.168.61.65
Nmap scan report for ip-192-168-61-65.eu-west-1.compute.internal (192.168.61.65)
Host is up (0.013s latency).
Not shown: 994 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
9998/tcp open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| uptime-agent-info: HTTP/1.1 400 Bad Request\x0D
| Content-Type: text/html; charset=us-ascii\x0D
| Server: Microsoft-HTTPAPI/2.0\x0D
| Date: Sun, 24 Apr 2022 14:13:06 GMT\x0D
| Connection: close\x0D
| Content-Length: 326\x0D
| \x0D
| <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd">\x0D
| <HTML><HEAD><TITLE>Bad Request</TITLE>\x0D
| <META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD>\x0D
| <BODY><h2>Bad Request - Invalid Verb</h2>\x0D
| <hr><p>HTTP Error 400. The request verb is invalid.</p>\x0D
|_</BODY></HTML>\x0D
| http-title: Site doesn't have a title (text/html; charset=utf-8).
|_Requested resource was /interface/root
|_http-favicon: Unknown favicon MD5: 9D7294CAAB5C2DF4CD916F53653714D5
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1s
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2022-04-24T14:13:13
|_  start_date: N/A

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Apr 24 14:13:52 2022 -- 1 IP address (1 host up) scanned in 69.32 seconds
```

No access to SMB. FTP hung when I tried to `ls`. Server on port 80 didn't seem to have anything interesting.

##### 9998
Running an instance of SmarterMail. Default credentials of `admin:admin` didn't work.

I checked searchsploit and saw a few things but nothing I was fully confident in, so I tried poking at the api `:9998/api/v1/`. Nothing really useful I could do though at first glance.

Searchsploit showed an [unauthenticated RCE for build 6985](https://www.exploit-db.com/exploits/49216). I couldn't find any version number, but the exploit takes advantage of a service running on port `17001`, so I nmap'd to check it was open and something was listening:

```
PORT      STATE SERVICE  VERSION
17001/tcp open  remoting MS .NET Remoting services
```

So it might be vulnerable. I started a netcat listener on 9001 and changed `RHOST`, `RPORT`, `LHOST` and `LPORT` in the script, and ran. Nothing back. I tried with a port number that was open on the target (e.g. `17001` or `9998`), and I got a powershell session as administrator.