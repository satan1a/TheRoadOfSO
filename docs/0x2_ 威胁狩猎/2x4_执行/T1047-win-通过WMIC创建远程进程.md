# T1047-win-通过WMIC创建远程进程

## 来自ATT&CK的描述

Windows管理规范（WMI）是Windows管理功能，它为本地和远程访问Windows系统组件提供了统一的环境。它依靠WMI服务进行本地和远程访问，并依靠服务器消息块（SMB）和远程过程调用服务（RPCS）进行远程访问。RPCS通过端口135运行。

攻击者可以使用WMI与本地和远程系统进行交互，并将其用作执行许多战术功能的手段，例如收集信息以进行发现和远程执行文件（作为横向移动的一部分）。

## 测试案例

攻击者可以使用Windows Management Instrumentation（WMI）通过远程启动可执行文件来横向移动。本案例描述了如何使用网络流量监视和目标主机上的进程监视来检测这些进程。但是，如果在源主机上使用了命令行实用程序wmic.exe，则可以在分析中另外检测到它。源主机上的命令行被构建为类似wmic.exe /node:"\<hostname\>" process call create "\<command line\>"。也可以通过IP地址进行连接，在这种情况下，字符串"\<hostname\>"修改为IP地址。

## 检测日志

windows安全日志

## 测试复现

源主机执行：wmic.exe /node:"\<hostname\>" process

![test](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/QDncB4.png)

## 测试留痕

事件ID，进程命令行参数，进程名称

## 检测规则/思路

```yml
title: 通过wmic创建远程进程
description: windows server 2016
status: experimental
author: 12306Bro
logsource:
​    product: windows
​    service: system
detection:
​    selection:
​        EventID: 4688 #进程创建
​        Newprocessname: 'C:\Windows\System32\wbem\WMIC.exe' #新进程名称
        Creatorprocessname: 'C:\Windows\System32\cmd.exe' #创建者进程名称
        Processcommandline: 'wmic.exe /node:* process *' #进程命令行
​    condition: selection
level: medium
```

## 参考推荐

MITRE-ATT&CK-T1047

<https://attack.mitre.org/techniques/T1047/>

CAR-2016-03-002通过WMIC创建远程进程

<https://car.mitre.org/analytics/CAR-2016-03-002/>

wmic命令收集与整理

<https://blog.csdn.net/qq_20307987/article/details/7322203>

wmic内网使用

<https://www.cnblogs.com/0xdd/p/11393392.html>
