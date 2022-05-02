# Butch
### Enumeration
```
# Nmap 7.92 scan initiated Sat Apr 30 11:06:05 2022 as: nmap -sCV -p- -v -oA nmap/tcp_all 192.168.65.63
Nmap scan report for ip-192-168-65-63.eu-west-1.compute.internal (192.168.65.63)
Host is up (0.016s latency).
Not shown: 65528 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
25/tcp   open  smtp          Microsoft ESMTP 10.0.17763.1
| smtp-commands: butch Hello [192.168.49.65], TURN, SIZE 2097152, ETRN, PIPELINING, DSN, ENHANCEDSTATUSCODES, 8bitmime, BINARYMIME, CHUNKING, VRFY, OK
|_ This server supports the following commands: HELO EHLO STARTTLS RCPT DATA RSET MAIL QUIT HELP AUTH TURN ETRN BDAT VRFY
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
450/tcp  open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Butch
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: butch; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2022-04-30T11:08:20
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Apr 30 11:08:58 2022 -- 1 IP address (1 host up) scanned in 173.24 seconds
```

##### FTP, SMB
Neither allow anonymous access.

### Foothold
Webserver running some sort of custom software. The name field is vulnerable to an SQL injection attack via a single quote character `'`. Initially, I tried the obvious login bypass injection `' or 1=1`, and a couple of variants, but none worked. After doing some reading, I began to suspect that the query was not checking both username and password, but fetching a password hash for the given username, which it then checked by hashing the provided password in memory and comparing. Evidence towards this hypothesis was the fact that the query returned 2 columns, verified using the injection below:

```
' union select 1,2--
```

Any other number of columns generated an exception. I tried an injection to return an MD5 hash, but it didn't work, so instead of trying to guess the hashing algorithm being used, I used `sqlmap` to retrieve data:

```
sqlmap -p 'ctl00%24ContentPlaceHolder1%24UsernameTextBox' -u 'http://192.168.65.63:450/' --data "__VIEWSTATE=%2FwEPDwUKLTQ0NDEwMDQ5Mg9kFgJmD2QWAgIDD2QWAgIBD2QWAgIHDw8WAh4EVGV4dAUeSW52YWxpZCB1c2VybmFtZSBvciBwYXNza2V5Li4uZGRkikLoDB%2B%2FpXdQqiz9h%2Bj5nHjE4OqEYro7hz%2FkDYh48fQ%3D&__VIEWSTATEGENERATOR=CA0B0334&__EVENTVALIDATION=%2FwEdAAQ5uNqOYHbIeyi7LRhe1%2B7mG8sL8VA5%2Fm7gZ949JdB2tEE%2BRwHRw9AX2%2FIZO4gVaaKVeG6rrLts0M7XT7lmdcb69X6Gyh7W5UwTVXhfLT4lC%2FUYzzbo01YDuyOekjcuLek%3D&ctl00%24ContentPlaceHolder1%24PasswordTextBox=a&ctl00%24ContentPlaceHolder1%24LoginButton=Enter&ctl00%24ContentPlaceHolder1%24UsernameTextBox=test" --batch --random-agent --current-db
```

The database was called `butch`. Enumerating tables, there was only one of interest: `users`. Dumping data from `users`, I got found one user:


| user_id | username | password_hash                                                    |
|---------|----------|------------------------------------------------------------------|
| 1       | butch    | e7b2b06dd8acded117d6d075673274c4ecdc75a788e09e81bffd84f11af6d267 |

`hashid` said the hash was SHA-256, so I attempted to crack it using `hashcat` in mode `1400`. It quickly retrieved the password `awesomedude`, so the login credentials were `butch:awesomedude`.

### RCE

Logging into the website, we're presented with a file upload form. I tried uploading random files and then visiting them from the path root, e.g. uploading `example.php` and visiting `http://192.168.65.63/example.php`, but I got a 404, despite the page saying the file upload was successful. I tried fuzzing for an uploads directory, but didn't find anything. I tried using the credentials with other services (FTP, SMB, RPC), but they didn't work.

Then I thought to try uploading an `aspx` shell, specifically `/usr/share/webshells/aspx/cmdasp.aspx`. The form showed an error: `Invalid file format...`. So potentially there's a file extension blacklist that we can bypass. I tried using the null byte trick by intercepting the request with Burp and changing the extension to `.txt%00.aspx`, but that didn't work.

Ultimately, I changed the name to `cmdasp.aspx.`. When checking the extension against the blacklist, this was fine because of the trailing `.`. However, when saving the file, Windows removes the trailing `.` in the name, producing a valid `.aspx` file. Now I could visit `/cmdasp.aspx` in the browser to get a webshell. Checking the user, we had a webshell as system, so I grabbed both flags.

I wanted to poke around the box a bit, so I downloaded [an aspx webshell](https://github.com/borjmz/aspx-reverse-shell/blob/master/shell.aspx) and used the same extension trick to upload. I had to set the port to `450`.

### Post exploitation

The SQL query the application used:

```
"SELECT username, password_hash FROM users WHERE username = '" + UsernameTextBox.Text.ToString() + "';"
```