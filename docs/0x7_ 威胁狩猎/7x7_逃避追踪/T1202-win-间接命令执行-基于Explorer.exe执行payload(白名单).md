# T1202-win-间接命令执行-基于Explorer.exe执行payload(白名单)

## 来自ATT&CK的描述

可以使用各种Windows实用程序来执行命令，而不需要调用cmd。例如，Forfiles、程序兼容性助手（pcalua.exe）、WSL（WindowsSubsystem for Linux）组件以及其他实用程序可以从命令行界面、运行窗口或通过脚本来调用程序和命令的执行。

攻击者可能会滥用这些功能来规避防御，尤其是在破坏检测和/或缓解控制（如组策略）的同时执行任意动作。（这些控制限制/阻止了cmd或恶意负载相关文件扩展名的使用。）

## 测试案例

Explorer.exe用于在Windows中管理文件和系统组件的二进制文件。

路径
```
C:\Windows\explorer.exe
C:\Windows\SysWOW64\explorer.exe
```

使用从explorer.exe的新实例生成的父进程执行calc.exe
```bash
explorer.exe /root,"C:\Windows\System32\calc.exe"
```

用例：在explorer父进程破坏进程树的情况下执行指定文件，可用于防御规避。
所需权限： 用户
操作系统：Windows XP、Windows 7、Windows 8、Windows 8.1、Windows 10

使用从explorer.exe的新实例生成的父进程执行notepad.exe
```bash
explorer.exe C:\Windows\System32\notepad.exe
```

用例：在explorer父进程破坏进程树的情况下执行指定文件，可用于防御规避。
所需权限：用户
操作系统：Windows 10（已测试）

## 检测日志

windows 安全日志（需要自行配置）

## 测试复现

```bash
C:\Users\liyang\Desktop\asptest>explorer.exe /root,"C:\Windows\System32\calc.exe"
C:\Users\liyang\Desktop\asptest>explorer.exe C:\Windows\System32\notepad.exe
```

## 测试留痕

```log

```

## 检测规则/思路
这里参看Sigma官方规则：
```yml
title: Explorer Root Flag Process Tree Break
id: 949f1ffb-6e85-4f00-ae1e-c3c5b190d605
description: Detects a command line process that uses explorer.exe /root, which is similar to cmd.exe /c, only it breaks the process tree and makes its parent a new instance of explorer
status: experimental
references:
    - https://twitter.com/CyberRaiju/status/1273597319322058752
    - https://twitter.com/bohops/status/1276357235954909188?s=12
author: Florian Roth
date: 2019/06/29
modified: 2020/08/30
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all: 
            - 'explorer.exe'
            - ' /root,'
    condition: selection
falsepositives:
    - Unknown how many legitimate software products use that method
level: medium
```

## 相关TIP
[[T1202-win-间接命令执行-基于Forfiles执行payload(白名单)]]
[[T1202-win-间接命令执行-基于Pcalua执行payload(白名单)]]
## 参考推荐

MITRE-ATT&CK-T1202

<https://attack.mitre.org/techniques/T1202/>

Explorer.exe

<https://lolbas-project.github.io/lolbas/Binaries/Explorer/>
