# T1548-002-win-绕过用户账户控制-Eventvwr.exe(白名单)
## 来自ATT&CK的描述
攻击者可能会绕过UAC机制来提升系统上的进程权限。 Windows用户帐户控制(UAC)允许程序提升其权限（跟踪为从低到高的完整性级别）以在管理员级别权限下执行任务，可能通过提示用户确认。对用户的影响范围从拒绝高强制执行的操作到允许用户在本地管理员组中执行操作并单击提示或允许他们输入管理员密码以完成操作。

如果计算机的UAC保护级别设置为最高级别以外的任何级别，则某些Windows程序可以提升权限或执行某些提升的组件对象模型对象，而无需通过UAC通知框提示用户。这方面的一个例子是使用Rundll32加载一个特制的DLL，该 DLL加载一个自动提升的组件对象模型对象并在受保护的目录中执行文件操作，这通常需要提升的访问权限。恶意软件也可能被注入到受信任的进程中，以在不提示用户的情况下获得提升的权限。

已经发现了许多绕过UAC的方法。UACME的Github自述文件页面包含大量已发现和实施的方法列表，但可能不是完整的绕过列表。经常发现其他绕过方法，其中一些在野外使用，例如：eventvwr.exe可以自动提升和执行指定的二进制文件或脚本。

如果知道具有管理员权限的帐户的凭据，则可以通过一些横向移动技术进行另一种绕过，因为UAC是一种单一系统安全机制，并且在远程系统上运行的进程的权限或完整性在一个系统上将是未知的，并且默认为高完整性。

## 测试案例
Eventvwr.exe在GUI窗口中显示Windows事件日志。
路径:
```
-   C:\Windows\System32\eventvwr.exe
-   C:\Windows\SysWOW64\eventvwr.exe
```

在启动过程中，eventvwr.exe 会检查注册表值HKCU\Software\Classes\mscfile\shell\open\command中mmc.exe的位置，该位置用于打开eventvwr.msc保存的控制台文件。如果将另一个二进制文件或脚本的位置添加到此注册表值，它将作为高完整性进程执行，而不会向用户显示 UAC 提示。
```
eventvwr.exe
```
用例：在没有UAC提示的情况下将二进制文件或脚本作为高完整性进程执行。  
所需权限： 用户  
操作系统：Windows vista、Windows 7、Windows 8、Windows 8.1、Windows 10
## 检测日志
Windows安全日志
## 测试复现
无
## 测试留痕
无
## 检测规则/规则
这里直接参看Sigma官方规则：
### sigma规则
```yml
title: UAC Bypass via Event Viewer

id: 7c81fec3-1c1d-43b0-996a-46753041b1b6

status: experimental

description: Detects UAC bypass method using Windows event viewer

references:

- https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/

- https://www.hybrid-analysis.com/sample/e122bc8bf291f15cab182a5d2d27b8db1e7019e4e96bb5cdbd1dfe7446f3f51f?environmentId=100

author: Florian Roth

date: 2017/03/19

modified: 2021/09/12

tags:

- attack.defense_evasion

- attack.privilege_escalation

- attack.t1088 # an old one

- attack.t1548.002

- car.2019-04-001

logsource:

product: windows

category: registry_event

detection:

methregistry:

TargetObject|startswith: 'HKCU\'

TargetObject|endswith: '\mscfile\shell\open\command'

condition: methregistry

falsepositives:

- unknown

level: critical
```
## 参考推荐
MITRE-ATT&CK-T1548-002

<https://attack.mitre.org/techniques/T1548/002/>

使用 EVENTVWR.EXE 和注册表劫持的“无文件”UAC绕过

<https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/>
 
