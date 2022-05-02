# WebCal
### Enumeration
We find ports 21, 25, 80 open. 21 does not allow anonymous access, so we leave it for now. 25 is a Postfix SMTP server which is not vulnerable to shellshock.

### Foothold
We find a `send.php` file which doesn't seem to do much, and also `/webcalendar/index.php`. We see that WebCalendar v1.2.3 is running. Checking `searchsploit` for exploits, we see that v1.2.4 has a code execution vulnerability, which is worth trying. We're able to get a shell as `www-data` using the script under `/usr/share/exploitdb/exploits/php/webapps/18775.php`. We then turn this into a proper shell using the netcat OpenBSD reverse shell one-liner. At this point, we grab the user flag.

### Privilege Escalation

We find MySQL credentials `wc:edjfbxMT7KKo2PPC@localhost/intranet`, which give us a hash for the WebCalendar admin password, but we fail to crack it.

Linpeas suggests that the version of linux that is used is highly likely to be vulnerable to [mempodipper](https://git.zx2c4.com/CVE-2012-0056/about/), so we check searchsploit for a script. There are two, both authored by the same person, with the second being an updated version (which hopefully is more stable). I copied the second into a `www` directory and raised a webserver, requested the file on the target in `/dev/shm` and then compiled using `gcc`. After running the exploit, I had a root shell!