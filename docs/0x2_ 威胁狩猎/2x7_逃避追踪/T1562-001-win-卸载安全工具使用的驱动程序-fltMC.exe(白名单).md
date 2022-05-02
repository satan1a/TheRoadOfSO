# T1562-001-win-卸载安全工具使用的驱动程序-fltMC.exe(白名单)

## 来自ATT&CK的描述

攻击者可能试图阻止由监测软件或进程捕获到的告警，以及事件日志被收集和分析。这可能包括修改配置文件或注册表项中的监测软件的设置，以达到逃避追踪的目的。

在基于特征监测的情况下，攻击者可以阻止监测特征相关的数据被发送出去，以便于阻止安全人员进行分析。这可以有很多方式实现，例如停止负责转发的进程（splunk转发器、Filebate、rsyslog等）。

## 测试案例

Fltmc.exe程序是系统提供的用于常见微筛选器驱动程序管理操作的命令行实用程序。 开发人员可以使用 Fltmc.exe来加载和卸载微筛选器驱动程序、附加或分离微筛选器驱动程序和枚举微筛选器驱动程序、实例和卷。 在具有管理员权限的命令提示符下，键入 `fltmc help` 以查看完整的命令列表。

路径：
```
-   C:\Windows\System32\fltMC.exe
```

卸载安全代理使用的驱动程序:
```bash
fltMC.exe unload SysmonDrv
```

用例：防御规避
所需权限：管理员
操作系统：Windows Vista、Windows 7、Windows 8、Windows 8.1、Windows 10
## 检测日志

Windows安全日志、Sysmon日志

## 测试复现
Windows 10，测试机未安装Sysmon，故测试过程中，卸载失败。
```bash
C:\Windows\system32>fltMC.exe unload SysmonDrv

卸载失败，出现错误: 0x801f0013
系统无法找到指定的筛选器。
```

## 测试留痕
```log
已创建新进程。

  

创建者主题:

安全 ID: DESKTOP-PT656L6\liyang

帐户名: liyang

帐户域: DESKTOP-PT656L6

登录 ID: 0x470C5

  

目标主题:

安全 ID: NULL SID

帐户名: -

帐户域: -

登录 ID: 0x0

  

进程信息:

新进程 ID: 0xea4

新进程名称: C:\Windows\System32\fltMC.exe

令牌提升类型: %%1937

强制性标签: Mandatory Label\High Mandatory Level

创建者进程 ID: 0x1acc

创建者进程名称: C:\Windows\System32\cmd.exe

进程命令行: fltMC.exe  unload SysmonDrv
```
## 检测规则/思路
参考Sigma官方规则
```
title: Sysmon Driver Unload

id: 4d7cda18-1b12-4e52-b45c-d28653210df8

status: experimental

author: Kirill Kiryanov, oscd.community

description: Detect possible Sysmon driver unload

date: 2019/10/23

modified: 2021/09/27

references:

- https://www.darkoperator.com/blog/2018/10/5/operating-offensively-against-sysmon

logsource:

product: windows

category: process_creation

tags:

- attack.defense_evasion

- attack.t1070

- attack.t1562

- attack.t1562.002

detection:

selection:

Image|endswith: '\fltmc.exe'

CommandLine|contains|all:

- 'unload'

- 'sys'

condition: selection

falsepositives:

- Unknown

level: high

fields:

- CommandLine

- Details
```

### 建议
Sigma官方规则还是比较简单的，针对进程和命令行参数进行监测。
## 相关TIP
[[T1562-001-win-停止windows防御服务]]
[[T1562-003-linux-Histcontrol]]
[[T1562-006-win-停止日志采集]]

## 参考推荐

MITRE-ATT&CK-T1562-001

<https://attack.mitre.org/techniques/T1562/001/>

如何规避Sysmon

<https://www.anquanke.com/post/id/161630>

fltMC.exe

<https://lolbas-project.github.io/lolbas/Binaries/FltMC/>

用于微筛选器开发和测试的工具

<https://docs.microsoft.com/zh-cn/windows-hardware/drivers/ifs/development-and-testing-tools>
