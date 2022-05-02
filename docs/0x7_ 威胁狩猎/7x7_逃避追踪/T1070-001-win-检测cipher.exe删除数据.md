# T1070-001-win-检测cipher.exe删除数据

## 来自ATT&CK的描述

攻击者可能试图阻止由监测软件或进程捕获到的告警，以及事件日志被收集和分析。这可能包括修改配置文件或注册表项中的监测软件的设置，以达到逃避追踪的目的。

在基于特征监测的情况下，攻击者可以阻止监测特征相关的数据被发送出去，以便于阻止安全人员进行分析。这可以有很多方式实现，例如停止负责转发的进程（splunk转发器、Filebate、rsyslog等）。

在正常的操作期间内，事件日志不太可能会被刻意清除。但是恶意攻击者可能会通过清除事件日志来尝试掩盖自己的踪迹。当事件日志被清除时，它是可疑的。发现“清除事件日志”时可能意味着有恶意攻击者利用了此项技术。

集中收集事件日志的一个好处就是使攻击者更难以掩盖他们的踪迹，事件转发允许将收集到的系统事件日志发送给多个收集器（splunk、elk等），从而实现冗余事件收集。使用冗余事件收集，可以最大限度的帮助我们发现威胁。

## 测试案例

在windows 2000以上版本都内置了一个这样的工具——cipher.exe。cipher使用方法很简单，在命令行窗口中，键入： cipher /w:盘符:/目录

其中，目录是可选的，用于卷挂接点。一般情况下，只写磁盘盘符就行了。比如清除e盘，就用“cipher /w:e”。

命令开始运行后，会依次用0x00、 0xff和随意数字覆盖该分区中的全部空闲空间，能够消除任何已删除文件的痕迹。

## 检测日志

windows 安全日志/sysmon日志

## 测试复现

```yml
测试环境：windows server 2016

测试命令： C:\Users\123>cipher /w:C:/Users/123/Desktop/test 
```

## 测试留痕

### windows_security_log

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
 新进程 ID:  0x11e0
 新进程名称: C:\Windows\System32\cipher.exe
 令牌提升类型: %%1938
 强制性标签:  Mandatory Label\Medium Mandatory Level
 创建者进程 ID: 0x10f0
 创建者进程名称: C:\Windows\System32\cmd.exe
 进程命令行: cipher  /w:C:/Users/12306br0/Desktop/test #需要单独配置
```

## 检测规则/思路

### sigma

```yml
title: 检测cipher.exe删除数据
description: windows server 2016模拟测试。该检测方式来源于Microsoft 365 Defender威胁情报团队威胁分析报告中，勒索软件继续冲击医疗保健和关键服务。
status: experimental
author: 12306Bro
logsource:
​    product: windows
​    service: security
detection:
​    selection:
​        EventID:
​                - 1 #sysmon日志
​                - 4688 #Windows 安全日志
        Process_name: 'cipher.exe' #Application Name
    Commanline: '/w'
​    condition: selection
level: medium
```

### 建议

如果基于windows安全日志进行检测，需要注意操作系统版本问题，部分操作系统并不支持开启审核过程创建。

## 相关TIP
[[T1070-001-win-清除事件日志]]
[[T1070-001-win-使用wevtutil命令删除日志]]
[[T1070-003-linux-清除历史记录]]
[[T1070-004-linux-文件删除]]
[[T1070-001-win-使用wevtutil命令删除日志]]
[[T1070-003-linux-清除历史记录]]
[[T1070-004-linux-文件删除]]
[[T1070-004-win-使用Fsutil删除卷USN日志]]
[[T1070-004-win-文件删除]]
[[T1070-005-win-删除网络共享连接]]
[[T1070-006-win-Timestamp]]

## 参考推荐

MITRE-ATT&CK-T1070-001

<https://attack.mitre.org/techniques/T1070/001/>

勒索软件组织继续以医疗保健，关键服务为目标——Microsoft 365 Defender威胁情报团队

<https://www.microsoft.com/security/blog/2020/04/28/ransomware-groups-continue-to-target-healthcare-critical-services-heres-how-to-reduce-risk/>
