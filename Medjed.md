# Medjed
### Enumeration
```
# Nmap 7.92 scan initiated Tue Apr 26 18:29:15 2022 as: nmap -sCV -v -oA nmap/tcp_1000 192.168.198.127
Nmap scan report for ip-192-168-198-127.eu-west-1.compute.internal (192.168.198.127)
Host is up (0.019s latency).
Not shown: 995 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3306/tcp open  mysql?
| fingerprint-strings:
|   NULL:
|_    Host '192.168.49.198' is not allowed to connect to this MariaDB server
8000/tcp open  http-alt      BarracudaServer.com (Windows)
| http-methods:
|   Supported Methods: OPTIONS GET HEAD PROPFIND PUT COPY DELETE MOVE MKCOL PROPPATCH LOCK UNLOCK POST
|_  Potentially risky methods: PROPFIND PUT COPY DELETE MOVE MKCOL PROPPATCH LOCK UNLOCK
| fingerprint-strings:
|   FourOhFourRequest, Socks5:
|     HTTP/1.1 200 OK
|     Date: Tue, 26 Apr 2022 18:29:29 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|   GenericLines, GetRequest:
|     HTTP/1.1 200 OK
|     Date: Tue, 26 Apr 2022 18:29:24 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|   HTTPOptions, RTSPRequest:
|     HTTP/1.1 200 OK
|     Date: Tue, 26 Apr 2022 18:29:34 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|   SIPOptions:
|     HTTP/1.1 400 Bad Request
|     Date: Tue, 26 Apr 2022 18:30:36 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|     Content-Type: text/html
|     Cache-Control: no-store, no-cache, must-revalidate, max-age=0
|_    <html><body><h1>400 Bad Request</h1>Can't parse request<p>BarracudaServer.com (Windows)</p></body></html>
| http-webdav-scan:
|   WebDAV type: Unknown
|   Server Date: Tue, 26 Apr 2022 18:31:27 GMT
|   Server Type: BarracudaServer.com (Windows)
|_  Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, PUT, COPY, DELETE, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK
|_http-title: Home
|_http-favicon: Unknown favicon MD5: FDF624762222B41E2767954032B6F1FF
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: BarracudaServer.com (Windows)
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3306-TCP:V=7.92%I=7%D=4/26%Time=626839FD%P=x86_64-pc-linux-gnu%r(NU
SF:LL,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.198'\x20is\x20not\x20al
SF:lowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8000-TCP:V=7.92%I=7%D=4/26%Time=62683A03%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,72,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Tue,\x2026\x20Apr\x20
SF:2022\x2018:29:24\x20GMT\r\nServer:\x20BarracudaServer\.com\x20\(Windows
SF:\)\r\nConnection:\x20Close\r\n\r\n")%r(GetRequest,72,"HTTP/1\.1\x20200\
SF:x20OK\r\nDate:\x20Tue,\x2026\x20Apr\x202022\x2018:29:24\x20GMT\r\nServe
SF:r:\x20BarracudaServer\.com\x20\(Windows\)\r\nConnection:\x20Close\r\n\r
SF:\n")%r(FourOhFourRequest,72,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Tue,\x2
SF:026\x20Apr\x202022\x2018:29:29\x20GMT\r\nServer:\x20BarracudaServer\.co
SF:m\x20\(Windows\)\r\nConnection:\x20Close\r\n\r\n")%r(Socks5,72,"HTTP/1\
SF:.1\x20200\x20OK\r\nDate:\x20Tue,\x2026\x20Apr\x202022\x2018:29:29\x20GM
SF:T\r\nServer:\x20BarracudaServer\.com\x20\(Windows\)\r\nConnection:\x20C
SF:lose\r\n\r\n")%r(HTTPOptions,72,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Tue
SF:,\x2026\x20Apr\x202022\x2018:29:34\x20GMT\r\nServer:\x20BarracudaServer
SF:\.com\x20\(Windows\)\r\nConnection:\x20Close\r\n\r\n")%r(RTSPRequest,72
SF:,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Tue,\x2026\x20Apr\x202022\x2018:29
SF::34\x20GMT\r\nServer:\x20BarracudaServer\.com\x20\(Windows\)\r\nConnect
SF:ion:\x20Close\r\n\r\n")%r(SIPOptions,13C,"HTTP/1\.1\x20400\x20Bad\x20Re
SF:quest\r\nDate:\x20Tue,\x2026\x20Apr\x202022\x2018:30:36\x20GMT\r\nServe
SF:r:\x20BarracudaServer\.com\x20\(Windows\)\r\nConnection:\x20Close\r\nCo
SF:ntent-Type:\x20text/html\r\nCache-Control:\x20no-store,\x20no-cache,\x2
SF:0must-revalidate,\x20max-age=0\r\n\r\n<html><body><h1>400\x20Bad\x20Req
SF:uest</h1>Can't\x20parse\x20request<p>BarracudaServer\.com\x20\(Windows\
SF:)</p></body></html>");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2022-04-26T18:31:30
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Apr 26 18:31:42 2022 -- 1 IP address (1 host up) scanned in 147.10 seconds
```

##### SMB
No anonymous access allowed.

##### MySQL
Can't connect, probably only bastion host allowed or something.

##### 8000
Webserver running BarracudaDrive. When we visit the homepage, we are quickly redirected and asked to create the admin account. I used `admin:password` for credentials. Now we can click on `Web-File-Server` (http://192.168.198.127:8000/rtl/protected/wfslinks.lsp) and see that WebDAV is enabled. After a bit of fumbling, I found that on the filesystem page (http://192.168.198.127:8000/fs/), there was a button with the tooltip `Mount current directory using a WebDAV session URL`. Clicking that button made a request to http://192.168.198.127:8000/fs/?cmd=sesuri, which gave a path (`/fs/fde8925062683aee/`) to connect to with `cadaver`:

```
cadaver http://192.168.198.127:8000/fs/fde8925062683aee/
```

The filesystem page had shown two folders, `C` and `D`. We could now go into `C`, and unsurprisingly it's the `C:\` drive of the host machine. We had enough permissions to get the local flag from `Jerren`'s desktop and also the root flag!