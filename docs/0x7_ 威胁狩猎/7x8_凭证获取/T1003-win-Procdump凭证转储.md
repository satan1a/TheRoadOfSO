# T1003-windows-Procdump明文凭证

## 来自ATT&CK的描述

凭证获取是从操作系统和软件中获取登录信息和密码的过程，通常为HASH散列或明文密码。然后使用凭证进行横向移动访问其他系统。

用户登录系统后，会生成各种凭据并将其存储在内存中的本地安全机构子系统服务（LSASS）进程中。这些凭证可以由管理用户或SYSTEM进行管理。

SSPI是Security Support Provider Interface（Microsoft安全支持提供器接口）的英文缩写。安全支持提供程序接口（SSPI）允许应用程序使用计算机或网络上可用的各种安全模型，而无需更改安全系统的接口。SSPI不会记录登录凭据，因为这通常是操作系统处理的特权操作。

一个安全支持提供商（SSP）包含在一个动态链接库，通过使一个或多个实现SSPI（DLL）安全包提供给应用程序。每个安全包都提供应用程序的SSPI函数调用和实际安全模型的功能之间的映射。

以下SSP可用于获取凭证：

Msv：交互式登录，批量登录和服务登录通过MSV身份验证包完成；

Wdigest：摘要认证协议设计用于超文本传输协议（HTTP）和简单认证安全层（SASL）交换；

Kerberos：Kerberos V5身份验证协议提供一个在客户端跟服务器端之间或者服务器与服务器之间的身份验证机制 （并且是相互的身份验证机制）；

CredSSP：为远程桌面服务提供SSO和网络级别身份验证；

## 测试案例

以下工具可用于枚举凭据：

- Windows凭据编辑器
- Mimikatz

除了内存技术，LSASS进程内存可以从目标主机转储并在本地系统上进行分析。

例如，在目标主机上使用procdump：

- procdump -ma lsass.exe lsass_dump

在本地，运行mimikatz：

- sekurlsa::Minidump lsassdump.dmp
- sekurlsa::logonPasswords

## 检测日志

sysmon日志

## 测试复现

场景：攻击者利用Procdump获取lsass进程内存文件，本地使用mimikatz获取密码(administrator)。

```dos
Microsoft Windows [版本 6.1.7601]
版权所有 (c) 2009 Microsoft Corporation。保留所有权利。

C:\Users\Administrator>cd C:\Users\Administrator\Desktop\Procdump

C:\Users\Administrator\Desktop\Procdump>procdump64.exe -ma lsass.exe 1.dmp

ProcDump v8.0 - Writes process dump files
Copyright (C) 2009-2016 Mark Russinovich
Sysinternals - www.sysinternals.com
With contributions from Andrew Richards

[13:42:47] Dump 1 initiated: C:\Users\Administrator\Desktop\Procdump\1.dmp
[13:42:50] Dump 1 writing: Estimated dump file size is 50 MB.
[13:42:51] Dump 1 complete: 50 MB written in 3.3 seconds
[13:42:51] Dump count reached.

C:\Users\Administrator\Desktop\Procdump>

```

## 测试留痕

sysmon事件，进程创建、进程访问、进程结束

## 检测规则/思路

### sigma规则

```yml
title: 明文获取凭证——Procdump
description: windows server 2008 模拟测试结果
status: experimental
author: 12306Bro
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        OriginalFileName: 'procdump'
    filter:
        Image: 
            - '*\procdump.exe'
            - '*\procdump64.exe'
    condition: selection and not filter
falsepositives:
    - Procdump illegaly bundled with legitimate software
    - Weird admins who renamed binaries
level: critical
    timeframe: last 1m
    condition: all of them
```

### 建议

建议您关注一下sysmon10.2的新特性OriginalFileName，经过安全人员研究测试发现，在进程创建事件中，procdump修改为ABC，但OriginalFileName依旧能够清晰的识别出该款工具是procdump。

## 参考推荐

MITRE-ATT&CK-T1003

<https://attack.mitre.org/techniques/T1003/>

windows SSPI模型

<https://docs.microsoft.com/zh-cn/windows/win32/secauthn/sspi-model>

MSV身份验证包

<https://blog.csdn.net/lionzl/article/details/7725116>

Wdigest摘要认证协议

<https://www.4hou.com/info/news/8126.html>

Kerberos身份认证协议技术参考

<https://www.cnblogs.com/adylee/articles/893448.html>

CredSSP凭证安全支持提供程序协议

<https://docs.microsoft.com/zh-cn/windows/win32/secauthn/credential-security-support-provider>
