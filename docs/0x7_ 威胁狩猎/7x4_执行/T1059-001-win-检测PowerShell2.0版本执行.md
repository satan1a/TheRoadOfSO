# T1059-001-win-检测Powershell2.0版本执行情况

## 来自ATT&CK的描述

攻击者可能滥用PowerShell来执行命令和脚本。PowerShell是Windows操作系统中包含的功能强大的交互式命令行界面和脚本环境。攻击者可以使用PowerShell执行许多操作，包括发现信息和执行恶意代码。示例包括Start-Process可用于运行可执行文件的Invoke-Commandcmdlet和可在本地或远程计算机上运行命令的cmdlet（尽管使用PowerShell连接到远程系统需要管理员权限）。

PowerShell也可以用于从Internet下载并运行可执行文件，这些可执行文件可以从磁盘或内存中执行而无需接触磁盘。

许多基于PowerShell的攻击性测试工具，包括Empire，PowerSploit，PoshC2和PSAttack。

还可以执行PowerShell命令脚本，而无需通过.NET框架和Windows公共语言接口（CLI）公开的powershell.exePowerShell底层System.Management.Automation程序集DLL的接口直接调用二进制文件。

## 测试案例

查找PowerShell版本2.0的执行情况，而不是查找使用版本2的旧脚本，或查找试图从脚本日志记录和AMSI中隐藏的攻击者。

### Powershell v2.0

该版本较旧且不安全，在安装版本5时不会删除。如果未被删除，攻击者仍可以利用这个不安全的版本。(powershell.exe -Version 2.0 -Command {<block>} -ExecutionPolicy <ExecutionPolicy>)

## 检测日志

Windows powershell日志审核策略

- 按Win+R打开Windows运行窗口,在输入框里输入gepdit.msc,打开Windows本地组策略编辑器;
- 找到计算机配置/管理模板/Windows组件/Windows Powershell，根据需求打开右侧所需要的日志功能；

## 测试复现

```yml
Microsoft Windows [版本 10.0.14393]
(c) 2016 Microsoft Corporation。保留所有权利。

C:\Users\12306br0>powershell -v 2
未安装 .NET Framework 版本 v2.0.50727，运行 Windows PowerShell 版本 2 需要此版本的 .NET Framework。
```

## 测试留痕

```yml
事件ID：4688
已创建新进程。

创建者主题:
 安全 ID:  361A\12306br0
 帐户名:  12306br0
 帐户域:  361A
 登录 ID:  0x507DC

目标主题:
 安全 ID:  NULL SID
 帐户名:  -
 帐户域:  -
 登录 ID:  0x0

进程信息:
 新进程 ID:  0x1158
 新进程名称: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
 令牌提升类型: %%1938
 强制性标签:  Mandatory Label\Medium Mandatory Level
 创建者进程 ID: 0x17cc
 创建者进程名称: C:\Windows\System32\cmd.exe
 进程命令行: powershell  -v 2

“令牌提升类型”表示根据用户帐户控制策略分配给新进程的令牌类型。

类型 1 是未删除特权或未禁用组的完全令牌。完全令牌仅在禁用了用户帐户控制或者用户是内置管理员帐户或服务帐户的情况下使用。

类型 2 是未删除特权或未禁用组的提升令牌。当启用了用户帐户控制并且用户选择使用“以管理员身份运行”选项启动程序时，会使用提升令牌。当应用程序配置为始终需要管理特权或始终需要最高特权并且用户是管理员组的成员时，也会使用提升令牌。

类型 3 是删除了管理特权并禁用了管理组的受限令牌。当启用了用户帐户控制，应用程序不需要管理特权并且用户未选择使用“以管理员身份运行”选项启动程序时，会使用受限令牌。
```

## 检测规则/思路

### sigma规则

```yml
title: 检测PowerShell 2.0版本执行情况
status: experimental
description: 检测在powershell降级使用，windows server 2016测试
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
            - '-v 2'
            - '-v 2.0'
            - '-version 2'
            - '-version 2.0'
    condition: selection
level: medium
```

### 建议

可使用windows安全日志、Powershell日志、Sysmon日志进行检测。

## 参考推荐

MITRE-ATT&CK-T1059-001

<https://attack.mitre.org/techniques/T1059/001/>

检测和缓解PowerShell攻击的方法

<https://blog.csdn.net/qq_36334464/article/details/101519839>

PowerShell版本2.0执行

<https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Execution/powershell-version-2.0-execution.md>

Powershell与威胁狩猎

<https://www.freebuf.com/articles/terminal/267080.html>
