# T1546-007-win-通过netsh key持久化

## 来自ATT&CK的描述

攻击者可以通过执行Netsh Helper DLL触发的恶意内容来建立持久性。Netsh.exe是一个管理员可以用来在命令提示符处配置并监视基于Windows的计算机的工具。使用Netsh.exe工具，可以将输入的上下文命令定向到适当的帮助器，然后帮助器将执行命令。帮助器是个动态链接库(.dll)文件，它通过提供配置、监视和支持一种或多种服务、实用工具或协议，来扩展Netsh.exe工具的功能。

已注册的netsh.exe帮助程序DLL的路径在Windows注册表HKLM\SOFTWARE\Microsoft\Netsh中

攻击者可以使用netsh.exe帮助程序DLL以持久的方式触发任意代码的执行。该执行将在执行netsh.exe的任何时间执行，该操作可能会自动发生，使用另一种持久性技术，在执行netsh.exe作为其正常功能的一部分的系统上存在其他软件（例如VPN）的情况下。

## 测试案例

建议参考Bypass师傅的[Window权限维持（十）：Netsh Helper DLL](https://zhuanlan.zhihu.com/p/108020339)

## 检测日志

windows sysmon日志

## 测试复现

建议参考Bypass师傅的[Window权限维持（十）：Netsh Helper DLL](https://zhuanlan.zhihu.com/p/108020339)

## 测试留痕

当执行“ 添加帮助程序 ”命令以加载DLL文件时，将在以下位置创建注册表项。

```yml
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NetSh
```

## 检测规则/思路

### sigma检测规则

```YML
title: 通过netsh key持久化
status: experimental
description: 攻击者可以使用netsh.exe帮助程序DLL以持久的方式触发任意代码的执行
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/910a2a764a66b0905065d8bdedb04b37049a85db/atomics/T1546.007/T1546.007.md#atomic-test-1---netsh-helper-dll-registration
    - https://eqllib.readthedocs.io/en/latest/analytics/5f9a71f4-f5ef-4d35-aff8-f67d63d3c896.html
date: 2020-11-29
tags:
    - attack.t1546-007
author: 12306Br0
logsource:
    product: windows
    service: sysmon
detection:
    selection_registry:
        EventID: 13 #创建注册表值 sysmon日志
        Registry_path: "*\\Software\\Microsoft\\NetSh\\*"
    condition: selection
level: medium
```

### 其他建议

暂无

## 参考推荐

MITRE-ATT&CK-T1546-007

<https://attack.mitre.org/techniques/T1546/007/>

Window权限维持（十）：Netsh Helper DLL

<https://www.cnblogs.com/xiaozi/p/11834533.html>
