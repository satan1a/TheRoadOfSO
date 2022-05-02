# T1027-005-windows-SDelete删除文件

## 来自ATT&CK的描述

攻击者可能会删除或更改主机系统上的生成物，包括日志和捕获的文件，例如隔离的恶意软件。尽管日志的位置和格式会有所不同，但典型的有机系统日志会被捕获为Windows事件或Linux/MacOS文件，如Bash History和/var/log/*。

事件干扰操作和其他可用于检测入侵活动的通知可能会损害安全解决方案的完整性，导致事件无法报告。它们也可能会导致取证分析和事件响应变得更加困难，因为它们缺乏足够的数据来确定发生了什么。

清除Windows事件日志

Windows事件日志是计算机警报和通知记录。微软将事件定义为“系统或程序中需要通知用户或将条目添加到日志中的任何重要事件”。有三个系统定义的事件源：系统、应用和安全。

执行账号管理、账号登录和目录服务访问等相关操作的攻击者可以选择清除事件来隐藏其活动。

可以使用以下实用程序命令清除事件日志：

· wevtutil cl system

· wevtutil cl application

· wevtutil cl security

也可以使用其他机制（如PowerShell）清除日志。

## 测试案例

SDelete是一个带有许多选项的命令行实用工具。按照任何给定用法，都可以使用它删除一个或多个文件或目录，或者清理逻辑磁盘上的可用空间。SDelete将通配符接受为目录或文件说明符的一部分。

## 检测日志

windows security

## 测试复现

### 下载SDelete文件

下载地址: https://docs.microsoft.com/zh-cn/sysinternals/downloads/sdelete

### 执行删除操作

```bash
C:\Users\12306Br0\Desktop\SDelete>sdelete64.exe -s SDelete.zip

SDelete v2.02 - Secure file delete
Copyright (C) 1999-2018 Mark Russinovich
Sysinternals - www.sysinternals.com

SDelete is set for 1 pass.
No files/folders found that match SDelete.zip.
```

## 测试留痕

```log
Event-ID: 4663
试图访问对象。

对象:
 安全 ID: SYSTEM
 帐户名: 12306BR0-PC$
 帐户域: WORKGROUP
 登录 ID: 0x3e7

对象:
 对象服务器: Security
 对象类型: File
 对象名: C:\Windows\System32\mapi32.dll
 句柄 ID: 0x4e8

进程信息:
 进程 ID: 0x128
 进程名: C:\Windows\servicing\TrustedInstaller.exe

访问请求信息:
 访问: DELETE

 访问掩码: 0x10000
```

## 检测规则/思路

### sigma规则

```yml
title: 使用SDelete安全删除
status: experimental
description: 使用SDelete工具删除文件时检测文件重命名
author: 12306Br0(测试+翻译)
date: 2020/06/09
references:
    - https://jpcertcc.github.io/ToolAnalysisResultSheet
    - https://www.jpcert.or.jp/english/pub/sr/ir_research.html
    - https://technet.microsoft.com/en-us/en-en/sysinternals/sdelete.aspx
tags:
    - attack.defense_evasion
    - attack.t1027
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4656
            - 4663
            - 4658
        ObjectName:
            - '*.AAA'
            - '*.ZZZ'
    condition: selection
falsepositives:
    - 合法使用SDelete，测试结果不如人意，建议谨慎使用
level: low
```

### 建议

暂无

## 参考推荐

MITRE-ATT&CK-T1027-005

<https://attack.mitre.org/techniques/T1027/005/>

MITRE-ATT&CK-T1066

<https://attack.mitre.org/techniques/T1066/>
