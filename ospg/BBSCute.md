# BBSCute
### Enumeration
Nmap shows a number of open ports:

```
# Nmap 7.92 scan initiated Tue Mar  8 17:53:50 2022 as: nmap -sC -sV -v -oN nmap/tcp.out -p- 192.168.52.128
Nmap scan report for 192.168.52.128
Host is up (0.00024s latency).
Not shown: 65530 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 04:d0:6e:c4:ba:4a:31:5a:6f:b3:ee:b8:1b:ed:5a:b7 (RSA)
|   256 24:b3:df:01:0b:ca:c2:ab:2e:e9:49:b0:58:08:6a:fa (ECDSA)
|_  256 6a:c4:35:6a:7a:1e:7e:51:85:5b:81:5c:7c:74:49:84 (ED25519)
80/tcp  open  http     Apache httpd 2.4.38 ((Debian))
|_http-favicon: Unknown favicon MD5: 759585A56089DB516D1FBBBE5A8EEA57
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.38 (Debian)
88/tcp  open  http     nginx 1.14.2
|_http-title: 404 Not Found
|_http-server-header: nginx/1.14.2
110/tcp open  pop3     Courier pop3d
|_pop3-capabilities: USER LOGIN-DELAY(10) IMPLEMENTATION(Courier Mail Server) PIPELINING TOP UTF8(USER) STLS UIDL
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Issuer: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-09-17T16:28:06
| Not valid after:  2021-09-17T16:28:06
| MD5:   5ee2 40c8 66d1 b327 71e6 085a f50b 7e28
|_SHA-1: 28a3 acc0 86a7 cd64 8f09 78fa 1792 7032 0ecc b154
|_ssl-date: TLS randomness does not represent time
995/tcp open  ssl/pop3 Courier pop3d
|_pop3-capabilities: USER LOGIN-DELAY(10) PIPELINING TOP IMPLEMENTATION(Courier Mail Server) UTF8(USER) UIDL
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Issuer: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-09-17T16:28:06
| Not valid after:  2021-09-17T16:28:06
| MD5:   5ee2 40c8 66d1 b327 71e6 085a f50b 7e28
|_SHA-1: 28a3 acc0 86a7 cd64 8f09 78fa 1792 7032 0ecc b154
MAC Address: 00:50:56:BF:2C:E8 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Visited both servers. The one on `88` had no page. Port `80` had an apache default install page. Then I ran gobuster on both the HTTP servers. The one on `88` doesn't seem to hold anything. The one on `80` had some files, including an `index.php` which was a login page. There was a button to register, so I registered an account, entering `test` as the value for all fields (`test@example.com` for the email). The captcha image did not show, so I took a look at the code in the devtools inspector. Hitting regenerate captcha, I could see the `src` of the captcha `img` tag changing, so I opened a new tab to visit that URL (`http://192.168.52.128/captcha.php?r=0.07921940943441075`) and copied the text-valued captcha and hit register. Success!

### Foothold

Hitting `Personal options`, there's an avatar upload, so I'll see if we can upload a reverse shell. Actually, googling the version of CuteNews that appears to be running (`2.1.2`), we see there's an exploit that takes advantage of exactly this vulnerability. We can use any webshell and place the value `GIF8;` on its own on the first line to trick the webserver into thinking the file is a GIF. We name the file `test.php` (the server doesn't appear to check extension) and upload successfully! Then we can right click the avatar and open in new tab to get access to the webshell. We run `id` to check it works, and when it does, we execute a reverse shell.

The user flag is in `/var/www`. There's one user home directory: `/home/fox`.

### Privilege Escalation

Running linpeas, it flags `hping3` as an executable SUID binary. Looking up this program on GTFO bins, we see we just need to execute it and then run `/bin/bash -p` at the prompt:

```
www-data@cute:/dev/shm$ hping3 
hping3> /bin/bash -p
bash-5.0# id
uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)
```