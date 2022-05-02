# T1021-006-win-远程powershell会话

## 来自ATT&CK的描述

攻击者可以使用“ 有效帐户”使用Windows远程管理（WinRM）与远程系统进行交互。然后，攻击者可以以登录用户的身份执行操作。

WinRM是Windows服务和协议的名称，该协议允许用户与远程系统进行交互（例如，运行可执行文件，修改注册表，修改服务）。可以使用winrm命令或任何数量的程序（例如PowerShell）来调用它。

## 测试案例

本测试案例主要模拟powershell Enter-PSSession -ComputerName \<RemoteHost\>创建一个远程PowerShell会话。

## 检测日志

windows安全日志 OR windows powershell日志

## 测试复现

![test](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/Q0npmd.png)

## 测试留痕

事件ID，命令行参数，子父进程等信息（对系统版本要求较高）

## 检测规则/思路

### sigma规则

```yml
title: win_远程powershell会话
description: windows server 2016
tags: T1021-006
status: experimental
author: 12306Bro
logsource:
    product: windows
    service: security
detection:
    selection1:
        EventID: 4688 #已创建新的进程。
        Newprocessname: 'C:\Windows\System32\dllhost.exe' #新进程名称
        Creatorprocessname: 'C:\Windows\System32\svchost.exe' #创建者进程名称
    selection2:
        EventID: 4688 #已创建新的进程。
        Newprocessname: 'C:\Windows\System32\wsmprovhost.exe' #新进程名称
        Creatorprocessname: 'C:\Windows\System32\svchost.exe' #创建者进程名称
        Processcommandline: 'C:\Windows\system32\wsmprovhost.exe -Embedding' #进程命令行参数
    timeframe: last 2s
    condition: selection
level: medium
```

### 建议

暂无

## 参考推荐

MITRE-ATT&CK-T1021-006

<https://attack.mitre.org/techniques/T1021/006/>

winrm service

<https://www.cnblogs.com/gamewyd/p/6805595.html>
