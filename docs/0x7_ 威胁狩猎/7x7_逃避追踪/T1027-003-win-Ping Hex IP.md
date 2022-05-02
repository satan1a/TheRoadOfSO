# T1027-003-win-Ping Hex IP

## 来自ATT&CK的描述

攻击者可能试图通过加密，编码或其他方式混淆可执行文件或文件在系统中或传输中的内容，从而使其难以发现或分析。这是常见的行为，可以跨不同的平台和网络使用，用于逃避追踪。

有效载荷可能被压缩，存档或加密，以避免被检测到。这些有效载荷可以在“初始访问”期间或以后使用，以减轻检测。有时，可能需要用户采取行动才能打开和反混淆/解码文件信息以供用户执行。可能还要求用户输入密码以打开由攻击者提供的受密码保护的压缩/加密文件。攻击者也可以使用压缩或存档脚本，例如Javascript。

还可以对文件的某些部分进行编码以隐藏纯文本字符串，否则它们将有助于防御者发现。有效载荷也可能被拆分为看似良性的单独文件，这些文件仅在重新组合后才会显示恶意功能。

攻击者还可能混淆从有效载荷执行的命令或直接通过命令行界面执行的命令。环境变量，别名，字符和其他平台/语言特定的语义可用于规避基于签名的检测和白名单机制。

## 测试案例

攻击者使用十六进制编码的IP地址进行ping命令探测主机。

## 检测日志

windows 安全日志/sysmon日志

## 测试复现

windows 2012以上操作系统

![ping1](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/1.png)

## 测试留痕

![ping2](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/ping2.png)

## 检测规则/思路

### sigma规则

```yml
title: Ping Hex IP
description: win7 模拟测试结果
references:
    - https://github.com/Neo23x0/sigma/blob/master/rules/windows/process_creation/win_susp_ping_hex_ip.yml
status: experimental
author: 12306Bro
logsource:
​    product: windows
​    service: security
detection:
    selection:
        CommandLine:
            - '*\ping.exe 0x*'
            - '*\ping 0x*'
    condition: selection
level: high
```

### 建议

暂无

## 相关TIP
[[T1027-004-win-传输后编译csc.exe(白名单)]]
[[T1027-005-linux-主机上的监测组件删除]]
[[T1027-005-win-SDelete删除文件]]

## 参考推荐

MITRE-ATT&CK-T1027-003

<https://attack.mitre.org/techniques/T1027/003/>

IP地址进制转换

<https://tool.520101.com/wangluo/jinzhizhuanhuan/>
