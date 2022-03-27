# CyberSploit1
### Enumeration
Ports 22 and 80 are open.

Inspecting the source code of the web page, we see `username:itsskv` in a comment. Also, in `/robots` there is a base64 string, which when decoded gives `cybersploit{youtube.com/c/cybersploit}`. This is the SSH password for the user `itsskv`.

### Privilege Escalation

We run linpeas after SSHing in. It tells us that Linux 3.13.0 is vulnerable. It also mentions a handful of exploits, of which one is dirtycow, and another is overlayfs. I tried dirtycow without luck, but overlayfs worked and I got a root shell.