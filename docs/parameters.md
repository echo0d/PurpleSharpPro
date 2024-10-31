# PurpleSharp参数记录

## 命令行参数

> 使用 PurpleSharp 使用命令行参数执行模拟并不能利用所有可用功能。如果您希望更灵活地自定义模拟，则应使用 JSON playbook。

* Remote Host (**/rhost**): 定义将运行模拟的远程主机。

* Remote User (**/ruser**): 定义用于部署模拟的域用户。此用户需要是远程主机上的“Administrators”组的一部分。

* Domain (**/d**): 定义模拟目标所属的域

* Technique(s) (**/t**): 定义要在模拟中使用的 MITRE ATT&CK Framework 技术 ID。使用多种技术时，请使用逗号分隔它们，并且它们之间没有空格，例如：

  ```
  PurpleSharp.exe /t T1055.002,T1055.003,T1055.004
  ```

* Remote Password (**/rpwd**)：定义用于部署模拟的用户的密码。如果不存在，PurpleSharp 将提示输入密码。

* Domain Controller (**/dc**)：指定要在其上运行 LDAP 查询的域控制器。

* Verbose (**/v**)：设置后，Scout 日志将作为输出的一部分显示。

* Playbook Sleep Time (**/pbsleep**)：当模拟多个技术时，此参数定义每次技术执行之间休眠的时间（以秒为单位）。

* Technique Sleep Time (**/tsleep**)：某些技术还支持使用此参数定义的内部休眠时间（以秒为单位）。

* Scout Path (**/scoutpath**)：定义 Scout 将在远程主机上上传到的绝对路径。如果未设置，PurpleSharp 将使用默认路径：C：\Windows\Scout.exe。

* Simulator Path (**/simpath**)：定义 Simulator 将在远程主机上上传到的相对路径。如果未设置，PurpleSharp 将使用默认路径：\Downloads\Firefox_Installer.exe。

* No Clean Up (**/nocleanup**)： 默认情况下，PurpleSharp 将在模拟完成后删除工件，作为清理过程的一部分。设置此参数后，将跳过特定技术的 clean 阶段。

* No Opsec (**/noopsec**)：设置后，PurpleSharp 将不会使用父进程 ID 欺骗技术来执行模拟器。这将导致模拟器在用于部署模拟的服务帐户的上下文中运行。

* Scout (**/scout**)：PurpleSharp 可以在远程主机上执行侦察任务，目的是在运行模拟之前为操作员提供有关它们的相关信息。

  * auditpol：此操作将检索远程终端节点的高级审核策略设置。
  * wef：此操作将检索远程终端节点的 Windows 事件订阅设置。
  * pws：此操作将检索远程端点的 Module Logging、Transcription Logging 和 SecriptBlock Logging PowerShell settints。
  * ps：此操作将检索远程端点正在运行的进程。
  * svcs：此操作将检索远程终端节点正在运行的 Windows 服务。
  * all：此选项将执行上述所有任务。

  ```
  PurpleSharp.exe PurpleSharp.exe /scout all /rhost host /ruser user /d domain
  ```

* Playbook (**/pb**): 此参数定义要用作模拟输入的 JSON Playbook。

  ```
  PurpleSharp.exe /pb SimulationPlaybook.json
  ```

## JSON 剧本

使用 JSON 文件还使我们能够使用特定于技术的参数进一步自定义模拟。每种技术都可以利用多个参数。这些参数也可以用于多种技术。例如，serviceName 参数仅与 Create Service 技术相关，但 filePath参数可用于 Rundll32.exe 和 Regsvr32.exe 等多种技术。如果未明确定义，则使用默认值来执行技术。

以下 JSON playbook 指示 PurpleShap 按顺序执行 4 种技术，每种技术之间的睡眠时间为 10 秒。（"description"只用于了解这个任务的信息，不会传入PurpleShap）

```json
{
"type": "local",
"sleep": 10,
"playbooks": [
   {
      "name": "Simulation Playbook",
      "enabled": true,
      "tasks": [
      {
         "technique_name": "Create or Modify System Process: Windows Service",
         "technique_id": "T1543.003",
         "serviceName": "Legit Service",
         "servicePath": "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe",
         "cleanup": true,
         "variation": 1,
         "description": "This variation uses the Win32 APIs: CreateService, OpenService and DeleteService to create a service",
      },
      {
         "technique_name": "Create or Modify System Process: Windows Service",
         "technique_id": "T1543.003",
         "serviceName": "Legit Service",
         "servicePath": "C:\\Windows\\System32\\msiexec.exe",
         "cleanup": false,
         "variation": 2,
         "description": "This variation executes the command 'sc create Legit Service binpath= C:\\Windows\\System32\\msiexec.exe' to create a service",
         "description2": "The service will not be deleted as per the cleanup variable",

      }
   }
]
}
```

我们可以使用 /pb 参数执行此 playbook，如下所示。如果要完全避免使用命令行参数并让 PurpleSharp 自动执行 playbook，则可以将 JSON playbook 作为资源嵌入到 PurpleSharp 程序集中。PurpleSharp 将自动读取并执行Playbook.json嵌入的资源。目前，实现此目的的唯一方法是手动将 playbook 添加到项目中，并使用 Visual Studio 构建它。更多详情请见此处。

```json
PurpleSharp.exe /pb simulation_playbook.json
```

具体每个技术执行时候的参数信息，请查看文档。