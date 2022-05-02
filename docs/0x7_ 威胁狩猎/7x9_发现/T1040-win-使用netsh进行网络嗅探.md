# T1040-win-使用netsh进行网络嗅探

## 来自ATT&CK的描述

网络嗅探是指使用系统上的网络接口来监视或捕获通过有线或无线连接发送的信息。攻击者可以将网络接口置于混杂模式以通过网络被动地访问传输中的数据，或者使用跨接端口来捕获更大量的数据。

通过该技术可以捕获的数据包括用户凭证，尤其是通过不安全的未加密协议发送的凭证；网络嗅探还可以获取到配置细节，例如运行服务，版本号以及后续横向移动或防御逃避活动所需的其他网络特征（例如：IP寻址，主机名，VLAN ID）。

## 测试案例

### 测试1 Windows Internal Packet Capture

使用内置的Windows数据包捕获执行后，你应该在临时目录中找到一个名为trace.etl和trace.cab的文件。

攻击命令，用命令提示符运行，需要提升等级（如root或admin）。

```
netsh trace start capture=yes tracefile=%temp%\trace.etl maxsize=10
```

清除命令：

```
netsh trace stop >nul 2>&1
TIMEOUT /T 5 >nul 2>&1
del %temp%\trace.etl >nul 2>&1
del %temp%\trace.cab >nul 2>&1
```

## 检测日志

Windows Sysmon日志

## 测试复现

### 测试1 Windows Internal Packet Capture
```
C:\Users\Administrator.ZHULI\Desktop\TevoraAutomatedRTGui>netsh trace start capture=yes tracefile=C:\Users\Administrator.ZHULI\Desktop\TevoraAutomatedRTGui\trace.etl maxsize=10

跟踪配置:
-------------------------------------------------------------------
状态:             正在运行
跟踪文件:         C:\Users\Administrator.ZHULI\Desktop\TevoraAutomatedRTGui\trace.etl
附加:             关闭
循环:           启用
最大大小:           10 MB
报告:             关闭


C:\Users\Administrator.ZHULI\Desktop\TevoraAutomatedRTGui>netsh trace stop >nul 2>&1

C:\Users\Administrator.ZHULI\Desktop\TevoraAutomatedRTGui>TIMEOUT /T 5 >nul 2>&1

```


## 测试留痕

### 测试1 Windows Internal Packet Capture
```Sysmon日志事件ID1
Process Create:

RuleName: technique_id=T1063,technique_name=Security Software Discovery

UtcTime: 2022-01-10 10:37:00.611

ProcessGuid: {78c84c47-0c4c-61dc-1217-000000000800}

ProcessId: 4280

Image: C:\Windows\System32\netsh.exe

FileVersion: 10.0.17763.1 (WinBuild.160101.0800)

Description: Network Command Shell

Product: Microsoft® Operating System

Company: Microsoft Corporation

OriginalFileName: netsh.exe

CommandLine: netsh trace start capture=yes tracefile=C:\Users\Administrator.ZHULI\Desktop\TevoraAutomatedRTGui\trace.etl maxsize=10

CurrentDirectory: C:\Users\Administrator.ZHULI\Desktop\TevoraAutomatedRTGui\

User: ZHULI\Administrator

LogonGuid: {78c84c47-f665-61db-95da-440100000000}

LogonId: 0x144DA95

TerminalSessionId: 3

IntegrityLevel: High

Hashes: SHA1=21190DE3629B7A40409897CAF9563EB1EE1944B2,MD5=758B8449357017A158163ECC0E5E52B2,SHA256=D70D165B6706C61C56F2CA91307F4BBDB9846ACAE1DA3CFD84BF978FFB21AF23,IMPHASH=90B4317BE51850B8EF9F14EB56FB7DDC

ParentProcessGuid: {78c84c47-fc8c-61db-9c11-000000000800}

ParentProcessId: 2512

ParentImage: C:\Windows\System32\cmd.exe

ParentCommandLine: "C:\Windows\System32\cmd.exe" 

ParentUser: ZHULI\Administrator
```

```Sysmon日志事件ID11 #创建文件
File created:

RuleName: -

UtcTime: 2022-01-10 10:37:00.904

ProcessGuid: {78c84c47-0c4c-61dc-1217-000000000800}

ProcessId: 4280

Image: C:\Windows\system32\netsh.exe

TargetFilename: C:\Users\Administrator.ZHULI\Desktop\TevoraAutomatedRTGui\trace.etl

CreationUtcTime: 2022-01-10 10:34:51.410

User: ZHULI\Administrator
```

## 检测规则/思路

### splunk检测规则

```yml
title: Windows使用netsh命令进行网络嗅探
description: 通过netsh命令进行网络嗅探在Windows Server 2019上进行测试。
tags: T1040
status: experimental
author: 12306Bro
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1 #进程创建
        Image: C:\Windows\System32\netsh.exe
        CommandLine: trace start capture=yes
    condition: selection
level: high
```

### 建议

检测嗅探网络流量的事件可能是最好的检测方法。从主机层面来看，攻击者很可能需要对有线网络上的其他设备进行中间入侵攻击，以捕获不属于当前被攻击系统的流量。这种信息流的变化在网络层面是可以检测到的。监测ARP欺骗和无偿ARP广播。检测被破坏的网络设备是一个比较大的挑战。需要对管理员登录、配置变化和设备图像进行审计，以检测恶意的变化。

## 相关TIP
[[Threathunting-book/9-发现/T1040-linux-网络嗅探]]

## 参考推荐

MITRE-ATT&CK-T1040

<https://attack.mitre.org/techniques/T1040/>

Atomic-red-team-T1040

<https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1040/T1040.md>
