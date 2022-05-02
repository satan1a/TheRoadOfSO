# T1562-001-windows-绕过sysmon

## 来自ATT&CK的描述

攻击者可能试图阻止由监测软件或进程捕获到的告警，以及事件日志被收集和分析。这可能包括修改配置文件或注册表项中的监测软件的设置，以达到逃避追踪的目的。

在基于特征监测的情况下，攻击者可以阻止监测特征相关的数据被发送出去，以便于阻止安全人员进行分析。这可以有很多方式实现，例如停止负责转发的进程（splunk转发器、Filebate、rsyslog等）。

## 测试案例

众所周知，sysmon可以帮助安全人员记录很多安全事件，目前sysmon最新版本已经是10.X版本。对于攻击者来讲，他们可能需要确定目标主机是否存在sysmon。通常，攻击者是不会去检测他们入侵的主机上是否存在sysmon。

如何检测被入侵的主机是否存在sysmon，很多攻击者一般执行以下的一种操作：

枚举进程；

枚举服务；

枚举C:\Windows\System32\Drivers下的驱动；

但是，你应该知道sysmon可以实现以下功能：用户可以在其中更改可执行文件和驱动文件的名称，以便其在系统中的存在进行模糊处理。

不过攻击者可以利用fltmc.exe查看其altitude号码，sysmon的altitude号码是385201，固定不变的。

使用fltmc.exe得到的altitude号：

```dos
Windows PowerShell
版权所有 (C) 2009 Microsoft Corporation。保留所有权利。

PS C:\Users\Administrator> fltmc.exe

筛选器名称                      数字实例       高度          框架

------

SysmonDrv                               2       385201         0
luafv                                   1       135000         0
```

在Mimikatz中使用misc::mflt命令得到的altitude号：

```dos
mimikatz # misc::mflt
0 2     385201 SysmonDrv
0 1     135000 luafv
```

关于更多的如何检测被入侵的主机是否存在sysmon，你可以参考：<https://anquan.baidu.com/article/350，如何检测sysmon不是本文的重点.>

### **绕过Sysmon的两种方法**

目前，攻击者有2个绕过sysmon的方法，第一个是在利用sysmon进程中的盲点，第二种则是直接禁用sysmon。

#### 删除配置项

攻击者可以删除注册表中的规则项，此时， Sysmon在发现注册表被更改后，它将自动重新加载配置。由于此时没有任何安全检测规则存在，它将暂时失去防护能力，不过失效时间，取决于配置的维护方式。如果配置由Ansible，Chef或DSC等配置管理系统管理，可能需要几秒到几分钟才能将配置更改回原始状态，如果使用GPO来管理，那么当GPO更新时，可以在90分钟内恢复原始状态。为了解决这个问题，攻击者可以使用各种Windows技术（如.Net、VBS、PE文件等）创建VMI临时性Consumer监控相应的注册表项，当发现修改操作时，则会删除修改数据或者重新设置表项内容。之所以使用临时的Consumer，是因为大多数防护解决方案会重点关注正在创建或修改的WMI永久事件。

#### 卸载SysmonDrv驱动

我们可以采取的另一个操作就是卸载SysmonDrv驱动，该驱动可以为Sysmon提供关于所有磁盘操作的信息，然后将信息写入事件日志中。如前文所述，该驱动有个唯一的altitude编号，如果我们以管理员权限运行，就可以卸载该驱动，然后Sysmon基本上就会完全处于失效状态。我们可以使用`fltmc.exe`工具来卸载驱动，如下所示，我们通过altitudde编号识别出了隐藏驱动，并成功卸载该驱动。

#### 关闭sysmon服务（管理员权限）

通过windows任务管理器，管理员权限关闭sysmon服务。

## 检测日志

sysmon日志、Windows-WMI-Activity日志，system日志

## 测试复现

### 删除配置项1

```dos
$query = "SELECT * FROM RegistryKeyChangeEvent " +
    "WHERE Hive ='HKEY_LOCAL_MACHINE' " +
    "AND KeyPath ='SYSTEM\\CurrentControlSet\\Services\\SysmonDrv\\Parameters'"

Register-WMIEvent -Query $query -Action {
    Write-host "Sysmon config updated, deleting config."
    Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters" -Name "Rules" }
```

需要注意一点，此时Sysmon会恢复默认配置，因此会记录进程创建和进程终止事件。

### 卸载SysmonDrv驱动1

```dos
Windows PowerShell
版权所有 (C) 2009 Microsoft Corporation。保留所有权利。

PS C:\Users\Administrator> fltMC.exe

筛选器名称                      数字实例       高度          框架
------------------------------  -------------  ------------  -----
SysmonDrv                               2       385201         0
luafv                                   1       135000         0
PS C:\Users\Administrator> fltMC.exe unload SysmonDrv
PS C:\Users\Administrator> fltMC.exe

筛选器名称                      数字实例       高度          框架
------------------------------  -------------  ------------  -----
luafv                                   1       135000         0
PS C:\Users\Administrator>
```

### 关闭sysmon服务

任务管理器>服务>sysmon服务>停止

## 测试留痕

暂无

## 检测规则/思路

### sigma规则

#### 删除配置项2

```yml
title: 删除sysmon配置项
description: win7 模拟测试结果
status: experimental
author: 12306Bro
logsource:
    product: windows
    service: WMI日志
detection:
    selection:
        EventID: 5860
        keyword: '命名空间 = root\cimv2；NotificationQuery = SELECT * FROM RegistryKeyChangeEvent WHERE Hive ='HKEY_LOCAL_MACHINE' AND KeyPath ='SYSTEM\\CurrentControlSet\\Services\\SysmonDrv\\Parameters'；PossibleCause = Temporary'
    timeframe: last 1m
    condition: selection
level: medium
```

#### 卸载SysmonDrv驱动—sysmon

```yml
title: fltmc卸载sysmon
description: windows server 2008 模拟测试结果
status: experimental
author: 12306Bro
logsource:
    product: windows
    service: sysmon
detection:
    selection1:
        EventID: 1
        Image: 'C:\Windows\SysWOW64\fltMC.exe'
        CommandLine: '"C:\Windows\system32\fltMC.exe"  unload Sysmon*'
        ParentImage: C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
    selection2:
        EventID: 255
        ID: 'DriverCommunication'
        Description: 'Failed to retrieve events - Last error: 由于线程退出或应用程序请求，已中止 I/O 操作。'
    timeframe: last 1m
    condition: all of them
level: medium
```

#### 关闭sysmon服务2

```yml
title: 以其他方式关闭sysmon服务
description: win7 模拟测试结果
status: experimental
author: 12306Bro
logsource:
    product: windows
    service: system、sysmon
detection:
    selection1:
        EventID: 4 #sysmon日志
        State: Stopped
    selection2: 7036 #system日志
        keyword: 'Sysmon* 服务处于 停止 状态。'
    selection3: 7040  #system日志
        keyword: 'Sysmon64 服务的启动类型从 自动启动 更改为 已禁用。'
    selection4: 7034 #system
    condition: selection or selection2 or selection3 or selection4
level: medium
```

### 建议

暂无

## 相关TIP
[[T1562-001-win-停止windows防御服务]]
[[T1562-003-linux-Histcontrol]]
[[T1562-006-win-停止日志采集]]
[[T1562-001-win-卸载安全工具使用的驱动程序-fltMC.exe(白名单)]]
## 参考推荐

MITRE-ATT&CK-T1562-001

<https://attack.mitre.org/techniques/T1562/001/>

审核策略相关介绍

<https://www.malwarearchaeology.com/logging>

如何规避sysmon

<https://www.anquanke.com/post/id/161630>
