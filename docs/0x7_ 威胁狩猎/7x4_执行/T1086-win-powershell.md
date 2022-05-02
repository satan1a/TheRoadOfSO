# T1086-windows-powerhsell

## 来自ATT&CK的描述

PowerShell是Windows操作系统中包含的功能强大的交互式命令行界面和脚本环境。攻击者可以使用PowerShell执行许多操作，包括发现信息和执行代码。

PowerShell也可以用于从Internet下载并运行可执行文件，这些可执行文件可以从磁盘或内存中执行而无需接触磁盘。

使用PowerShell连接到远程系统需要管理员权限。

网络上提供了许多基于PowerShell的攻击性测试工具，包括Empire，PowerSploit和PSAttack。

还可以执行PowerShell命令/脚本，而无需通过.NET框架和Windows公共语言接口公开的PowerShell底层System.Management.Automation程序集的接口直接调用powershell.exe二进制文件。

## 测试案例

模拟场景：攻击者通过其视图窗口打开powershell

## 检测日志

windows 安全日志 进程创建事件

## 测试复现

暂无

## 测试留痕

windows 安全日志，事件ID4688

## 检测规则/思路

### sigma规则

```yml
title: T1086  非交互式PowerShell
description: 通过将powershell.exe以explorer.exe作为父级，来检测非交互式PowerShell活动。
status: experimental
author: 12306Bro
references: 无
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4688
        NewProcessName: '*\powershell.exe'
        ParentProcessName: '*\explorer.exe'
    condition: selection
falsepositives:
    - Unknown
level: critical
```

### 建议

该检测方式存在大量误报，不建议使用。可对进程命令行参数信息进行有效的监控。

## 参考推荐

MITRE-ATT&CK-T1086

<https://attack.mitre.org/techniques/T1086/>
