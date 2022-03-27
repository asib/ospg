# Gaara
### Enumeration
Nmap shows open ports 22 and 80.

Running gobuster on the webserver, we find `/Cryoserver` (case-sensitive!), which looks empty:

```shell-session
$ wget http://192.168.67.142/Cryoserver
$ grep -vr '^$' Cryoserver | cat -n
     1  /Temari
     2  /Kazekage
     3  /iamGaara

$ wget http://192.168.67.142/{Temari,Kazekage,iamGaara}
```

We notice the string `f1MgN9mTf9SNbzRygcU` in `iamGaara`. `Temari` and `Kazekage` are identical.

Attempting to decode the string as base64 gives garbage, but base58 decoding gives `gaara:ismyname`.

### Foothold

Trying to use these credentials to login (both as username/password) doesn't work. I added both to `users.txt` and ran hydra on SSH using `rockyou.txt` as the password list. The cracked password was `iloveyou2`.

### Privilege Escalation

Once we're in, we run linpeas. We notice that `gdb` is executable by us and is SUID. Looking it up on GTFO bins, we see we can run the following to get a root shell:

```shell-session
$ gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit
```