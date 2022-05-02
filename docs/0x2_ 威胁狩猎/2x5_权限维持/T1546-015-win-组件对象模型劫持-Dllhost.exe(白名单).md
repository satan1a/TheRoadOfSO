# T1546-015-win-组件对象模型劫持-Dllhost.exe(白名单)

## 来自ATT&CK描述
攻击者可以通过执行由对组件对象模型 (COM) 对象的劫持引用触发的恶意内容来建立持久性。COM是Windows中的一个系统，用于通过操作系统实现软件组件之间的交互。对各种COM对象的引用存储在注册表中。

攻击者可以使用COM系统插入恶意代码，这些代码可以通过劫持COM引用和关系作为持久性手段来代替合法软件执行。劫持COM对象需要更改注册表以替换对合法系统组件的引用，这可能导致该组件在执行时无法工作。当通过正常系统操作执行该系统组件时，将执行对手的代码。攻击者可能会劫持经常使用的对象以保持一致的持久性水平，但不太可能破坏系统内的明显功能，以避免可能导致检测的系统不稳定。

## 测试案例
dllhost.exe是微软Windows操作系统的一部分。dllhost.exe用于管理DLL应用。这个程序对你系统的正常运行是非常重要的。dllhost.exe是运行COM+的组件，即COM代理，运行Windows中的Web和FTP服务器必须有该进程。

路径：
```
- C:\Windows\System32\dllhost.exe
- C:\Windows\SysWOW64\dllhost.exe
```

使用dllhost.exe加载已注册或被劫持的COM服务器负载。
```
dllhost.exe /Processid:{CLSID}
```

用例：执行DLL代理COM对象。
所需权限：用户
操作系统：Windows 10（可能还有以前的版本）
## 检测日志

Windows 安全日志

## 测试复现
无
## 测试留痕
无
## 检测规则/思路
参考Sigma官方规则：
```yml
title: Dllhost Internet Connection

id: cfed2f44-16df-4bf3-833a-79405198b277

status: experimental

description: Detects Dllhost that communicates with public IP addresses

references:

- https://github.com/Neo23x0/sigma/blob/master/rules/windows/network_connection/sysmon_rundll32_net_connections.yml

author: bartblaze

date: 2020/07/13

modified: 2020/08/24

tags:

- attack.defense_evasion

- attack.t1218

- attack.execution

- attack.t1559.001

- attack.t1175 # an old one

logsource:

category: network_connection

product: windows

detection:

selection:

Image|endswith: '\dllhost.exe'

Initiated: 'true'

filter:

DestinationIp|startswith:

- '10.'

- '192.168.'

- '172.16.'

- '172.17.'

- '172.18.'

- '172.19.'

- '172.20.'

- '172.21.'

- '172.22.'

- '172.23.'

- '172.24.'

- '172.25.'

- '172.26.'

- '172.27.'

- '172.28.'

- '172.29.'

- '172.30.'

- '172.31.'

- '127.'

condition: selection and not filter

falsepositives:

- Communication to other corporate systems that use IP addresses from public address spaces

level: medium
```
## 参考推荐

MITRE-ATT&CK-T1546-015

<https://attack.mitre.org/techniques/T1546/015>

Dllhost.exe

<https://lolbas-project.github.io/lolbas/Binaries/Dllhost/>

