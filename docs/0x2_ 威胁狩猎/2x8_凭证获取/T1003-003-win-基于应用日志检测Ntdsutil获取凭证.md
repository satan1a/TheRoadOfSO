# T1003-003-win-基于应用日志检测Ntdsutil获取凭证

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

参考链接：
域渗透——获得域控服务器的NTDS.dit文件：<https://blog.csdn.net/Fly_hps/article/details/80641987>

## 检测日志

windows 应用日志

## 测试复现

![ntds0](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/lqUbDJ.png)

## 测试留痕

windows 应用日志留痕文件：<https://github.com/12306Bro/Threathunting-book/blob/master/Eventdata/ntds.evtx>

## 检测规则/思路

### sigma规则

```yml
title: 应用日志检测ntdsutil获取NTDS.dit文件
description: windows server 2008 + AD域控
references: https://blog.csdn.net/Fly_hps/article/details/80641987
tags: T1003-003
status: experimental
author: 12306Bro
logsource:
    product: windows
    service: application
detection:
    selection1:
        EventID: 2005
        Message: 'lsass (*) 卷影复制实例 * 正在启动。这将是一次完整的卷影复制。' #*号代表任意数值匹配
    selection2:
        EventID: 2001
        Message: 'lsass (*) 卷影副本实例 * 冻结已开始。' #*号代表任意数值匹配
    selection3:
        EventID: 2003
        Message: 'lsass (*) 卷影副本实例 * 冻结已停止。' #*号代表任意数值匹配
    selection4:
        EventID: 2006
        Message: 'lsass (*) 卷影复制实例 * 已成功完成。' #*号代表任意数值匹配
    selection5:
        EventID: 300
        Message: lsass (*) 数据库引擎正在初始化恢复步骤。 #*号代表任意数值匹配
    selection6:
        EventID: 216 #期间触发大量216事件
        Message: 'lsass (*) 检测到数据库位置从“C:\Windows\NTDS\ntds.dit”更改为“\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy*1*\Windows\NTDS\ntds.dit”。' #*号代表任意数值匹配
    selection7:
        EventID: 302
        Message: 'lsass (*) 数据库引擎已成功完成恢复步骤。' #*号代表任意数值匹配
​    timeframe: last 10S #自定义时间范围
    condition: all of them
level: medium
```

### 建议

此检测特征仅适用于windows AD域控主机。

## 参考推荐

MITRE-ATT&CK-T1003-003

<https://attack.mitre.org/techniques/T1003/003>

域渗透——获得域控服务器的NTDS.dit文件

<https://xz.aliyun.com/t/2187>

NTDS.dit密码快速提取工具

<https://www.secpulse.com/archives/6301.html>

MITRE ATT&CK攻击知识库（企业）中文版

<https://hansight.github.io/#/>
