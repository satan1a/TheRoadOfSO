# T1018-win-检测nbtscan活动

## 来自ATT&CK的描述

攻击者可能试图通过IP地址，主机名或网络上其他可用于从当前系统进行横向移动的逻辑标识符来获取其他系统的列表。远程访问工具中存在类似的功能来可以实现此目的，但是也可以使用操作系统上可用的实用程序，例如Ping或net view。攻击者还可以使用本地主机文件（例如：C:\Windows\System32\Drivers\etc\hosts或/etc/hosts）来发现主机名到远程系统的IP地址的映射。

bonjour协议特定于macOS，用于在同一广播域中发现其他基于Mac的系统。

## 测试案例

Nbtscan.exe是一款用于扫描Windows网络上NetBIOS名字信息的程序。该程序对给出范围内的每一个地址发送NetBIOS状态查询，并且以易读的表格列出接收到的信息，对于每个响应的主机，NBTScan列出它的IP地址、NetBIOS计算机名、登录用户名和MAC地址。但只能用于局域网,NBTSCAN可以取到PC的真实IP地址和MAC地址，如果有”ARP攻击”在做怪，可以找到装有ARP攻击的PC的IP/和MAC地址。但只能用于局域网,NBTSCAN可以取到PC的真实IP地址和MAC地址，如果有”ARP攻击”在做怪，可以找到装有ARP攻击的PC的IP/和MAC地址。NBTSCAN可以取到PC的真实IP地址和MAC地址，如果有”ARP攻击”在做怪，可以找到装有ARP攻击的PC的IP/和MAC地址。总之，NBTSCAN可以取到PC的真实IP地址和MAC地址。

## 检测日志

windows 安全日志

## 测试复现

```yml
C:\Users\12306br0\Desktop\test>nbtscan-1.0.35.exe 10.211.55.1/24
10.211.55.2     \MACBOOKPRO-3EAA
*timeout (normal end of scan)
```

## 测试留痕

```yml
4688，已创建新进程。

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
 新进程 ID:  0x135c
 新进程名称: C:\Users\12306br0\Desktop\test\nbtscan-1.0.35.exe
 令牌提升类型: %%1938
 强制性标签:  Mandatory Label\Medium Mandatory Level
 创建者进程 ID: 0xc68
 创建者进程名称: C:\Windows\System32\cmd.exe
 进程命令行: nbtscan-1.0.35.exe  10.211.55.1/24
```

## 检测规则/思路

### sigma规则

```yml
title: 检测nbtscan活动
description: windows server 2016、本检测规则参考Microsoft威胁防护团队发布的Operation Soft Cell威胁分析报告，Soft Cell行动是一系列针对全球电信提供商的用户呼叫日志的运动。这些攻击最早可以追溯到2012年。nbtscan.exe是一种合法的MS-DOS命令行工具，用于发现本地或远程TCP/IP网络上的任何NETBIOS名称服务器。
references: https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Discovery/detect-nbtscan-activity.md
tags: T1018
status: experimental
author: 12306Bro
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4688 #进程创建
        Newprocessname: '*nbtscan*.exe' #进程信息>新进程名称
    condition: selection
level: low
```

### 建议

基于非系统自带进程名称的检测方法始终是不太靠谱的，当攻击者修改进程名称后，就无法通过进程名称进行检测；可以通过部署Sysmon，利用进程hash值进行检测。

## 相关TIP
[[T1018-win-远程系统发现]]

## 参考推荐

MITRE-ATT&CK-T1018

<https://attack.mitre.org/techniques/T1018/>

检测nbtscan活动

<https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Discovery/detect-nbtscan-activity.md>

Nbtscan下载

<http://unixwiz.net/tools/nbtscan.html>

软蜂窝行动:针对电信提供商的全球运动

<https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers>
