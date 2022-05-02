# T1053-005-win-schtasks本地计划任务

## 来自ATT&CK的描述

诸如at和schtasks之类的实用程序可与Windows Task Scheduler一起使用来调度程序或脚本在某日期和时间执行。只要身份认证通过可以使用RPC，并且打开了文件和打印机共享功能，就可以在远程系统上调度任务。在远程系统上调度任务通常需要远程系统管理员群组的成员执行。

攻击者可能会通过任务调度在系统启动时或在计划的基础上执行程序以实现持久性，作为横向移动的一部分进行远程执行，获得系统权限，或者在指定账号的上下文下运行进程。

## 测试案例

安排命令和程序定期运行或在指定时间内运行。从计划表中添加和删除任务，按需要启动和停止任务，显示和更改计划任务。

## 检测日志

windows安全日志/sysmon日志

## 测试复现

暂无，参考：[Schtasks命令详解](https://www.cnblogs.com/daimaxuejia/p/12957644.html)

## 测试留痕

暂无，可参看windows 4688进程创建日志样例，辅助理解。

```yml
Pre-Windows 2016/10
A new process has been created.

Subject:

   Security ID:  WIN-R9H529RIO4Y\Administrator
   Account Name:  Administrator
   Account Domain:  WIN-R9H529RIO4Y
   Logon ID:  0x1fd23

Process Information:

   New Process ID:  0xed0
   New Process Name: C:\Windows\System32\notepad.exe
   Token Elevation Type: TokenElevationTypeDefault (1)
   Mandatory Label: Mandatory Label\Medium Mandatory Level
   Creator Process ID: 0x8c0
   Creator Process Name: c:\windows\system32\explorer.exe
   Process Command Line: C:\Windows\System32\notepad.exe c:\sys\junk.txt
```

## 检测规则/思路

### Sigma

```yml
title: schtasks本地计划任务
description: 检测可疑的schtasks本地计划任务
author: 12306Br0
references:
    - https://www.elastic.co/guide/en/siem/guide/current/local-scheduled-task-commands.html
tags:
    - attack.persistence
    - attack.t1053-005
logsource:
    product: windows
    service: sysmon / 安全日志 #自行配置
detection:
    selection:
        EventID: 
              - 4688 #windows安全日志 进程创建
              - 1 #windows sysmon日志 进程创建
        Process Name: 'schtasks.exe'
        CommandLine: 
              - '/create'
              - '-create'
              - '/S'
              - '-s'
              - '/run'
              - '-run'
              - '/change'
              - '-change'
    condition: selection
level: low
```

### Elastic rule query

```yml
event.action:"Process Create (rule: ProcessCreate)" and
process.name:schtasks.exe and process.args:(-change or -create or -run
or -s or /S or /change or /create or /run)
```

## 建议

除了基于sysmon日志之外，高版本的Windows操作系统，也可以通过系统安全日志中4688进行检测。

## 参考推荐

MITRE-ATT&CK-T1053-005

<https://attack.mitre.org/techniques/T1053/005/>
