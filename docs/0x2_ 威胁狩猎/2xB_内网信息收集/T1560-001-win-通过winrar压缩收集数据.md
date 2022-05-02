# T1560-001-win-通过winrar压缩数据

## 来自ATT&CK的描述

攻击者可以使用第三方工具压缩或加密之前收集的数据。存在许多可以压缩数据的实用程序，包括7-Zip，WinRAR和WinZip。大多数实用程序都包含加密或压缩数据的功能。

可能已预先安装了一些第三方工具，例如tar在Linux和macOS或zipWindows系统上。

## 测试案例

windows下安装winrar程序，通过winrar命令行的方式进行数据压缩。

winrar相关命令解释，可参考官方解释说明。

## 检测日志

windows 安全日志

## 测试复现

```yml
C:\Users\Administrator>winrar a  C:\Users\Administrator\qax.rar C:\Users\Administrator\qax.pst
# 注意，如果在使用winrar命令提示“winrar不是内部或外部命令，也不是可运行的程序或批处理文件“。请记得添加环境变量
```

## 测试留痕

windows 安全日志、进程创建、命令行参数等

```yml
已创建新进程。

创建者主题:
 安全 ID:  QAX\Administrator
 帐户名:  Administrator
 帐户域:  QAX
 登录 ID:  0x7169C

目标主题:
 安全 ID:  NULL SID
 帐户名:  -
 帐户域:  -
 登录 ID:  0x0

进程信息:
 新进程 ID:  0xe20
 新进程名称: C:\Program Files\WinRAR\WinRAR.exe
 令牌提升类型: %%1936
 强制性标签:  Mandatory Label\High Mandatory Level
 创建者进程 ID: 0x378
 创建者进程名称: C:\Windows\System32\cmd.exe
 进程命令行: winrar  a  C:\Users\Administrator\qax.rar C:\Users\Administrator\qax.pst
```

## 检测规则/思路

### sigma规则

```yml
title: windows-winrar压缩数据
description: windows server 2016模拟测试，攻击者通过winrar压缩收集到的数据
tags: T1560-001
status: experimental
author: 12306Bro
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4688 #已创建新的进程。
        Newprocessname: '*RAR.exe' #进程信息>新进程名称
        Processcommandline: 'a' #进程信息>进程命令行
    condition: selection
level: medium
```

## 建议

可以通过进程监视和监视已知压缩程序的命令行参数来检测可能存在于系统中的攻击者利用压缩程序压缩数据文件的行为。这可能会产生大量的良性事件，具体取决于环境中系统的使用方式。

## 参考推荐

MITRE-ATT&CK-T1560-001

<https://attack.mitre.org/techniques/T1560/001/>

windows 命令行中使用winrar

<https://blog.csdn.net/findmyself_for_world/article/details/39292181>

利用WinRAR命令行压缩文件或文件夹

<https://www.cnblogs.com/xzlive/p/10508940.html>
