# T1127-win-受信任的开发者实用程序代理执行(白名单)

## 来自ATT&CK的描述
攻击者可能会利用受信任的开发人员使用的程序来代理执行恶意载荷。有许多用于软件开发相关任务的实用程序可用于执行各种形式的代码，以协助开发、调试和逆向工程。这些实用程序通常可能使用合法证书进行签名，允许它们在系统上执行并通过有效绕过应用程序控制解决方案的受信任进程代理执行恶意代码。

## 测试案例
ASP.NET 编译工具 Aspnet_compiler.exe

路径：
```
- c:\Windows\Microsoft.NET\Framework\v4.0.30319\aspnet_compiler.exe
- c:\Windows\Microsoft.NET\Framework64\v4.0.30319\aspnet_compiler.exe
```

使用Build Provider和适当的文件夹结构执行C#代码。
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\aspnet_compiler.exe -v none -p C:\users\cpl.internal\desktop\asptest\ -f C:\users\cpl.internal\desktop\asptest\none -u
```

用例：使用Microsoft签名的二进制文件执行代理负载以绕过应用程序控制解决方案
所需权限：用户
操作系统：Windows 10

## 检测日志

windows security

## 测试复现
```
C:\Users\liyang>C:\Windows\Microsoft.NET\Framework64\v4.0.30319\aspnet_compiler.exe -v none -p C:\users\liyang\desktop\asptest\ -f C:\users\liyang\desktop\asptest\none -u
Microsoft (R) ASP.NET 编译工具版本 4.8.3752.0
要用来预编译 ASP.NET 应用程序的实用工具
版权所有(C) Microsoft Corporation。保留所有权利。
```

## 测试留痕
```
创建新进程。

  

创建者主题:

安全 ID: DESKTOP-PT656L6\liyang

帐户名: liyang

帐户域: DESKTOP-PT656L6

登录 ID: 0x47126

  

目标主题:

安全 ID: NULL SID

帐户名: -

帐户域: -

登录 ID: 0x0

  

进程信息:

新进程 ID: 0x744

新进程名称: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\aspnet_compiler.exe

令牌提升类型: %%1938

强制性标签: Mandatory Label\Medium Mandatory Level

创建者进程 ID: 0x1d04

创建者进程名称: C:\Windows\System32\cmd.exe

进程命令行: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\aspnet_compiler.exe  -v none -p C:\users\liyang\desktop\asptest\ -f C:\users\liyang\desktop\asptest\none -u
```

## 检测规则/思路
参考Sigma官方检测规则，基于进程名称进行检测。
```
title: Suspicious aspnet_compiler.exe Execution

id: a01b8329-5953-4f73-ae2d-aa01e1f35f00

status: experimental

description: Execute C# code with the Build Provider and proper folder structure in place.

references:

- https://lolbas-project.github.io/lolbas/Binaries/Aspnet_Compiler/

tags:

- attack.defense_evasion

- attack.t1127

author: frack113

date: 2021/11/24

logsource:

category: process_creation

product: windows

detection:

selection:

Image|contains|all:

- C:\Windows\Microsoft.NET\Framework

- aspnet_compiler.exe

condition: selection

falsepositives:

- unknown

level: medium
```

### 建议
如果在服务器上看到启动此进程，可能是可疑的。

## 参考推荐

MITRE-ATT&CK-T1127

<https://attack.mitre.org/techniques/T1127>

Aspnet_Compiler.exe

<https://lolbas-project.github.io/lolbas/Binaries/Aspnet_Compiler/>

ASP.NET 编译工具 (Aspnet_compiler.exe

<https://www.cnblogs.com/nmcfshang/articles/451265.html>
