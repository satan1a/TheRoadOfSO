# T1218-win-基于Atbroker.exe执行恶意载荷(白名单)

## 来自ATT&CK的描述

许多软件开发相关的实用程序可用于执行各种形式的代码用以协助开发、调试和逆向工程。这些实用程序通常可以使用合法证书进行签名。签名后，它们就可以在系统上执行，并通过可信的进程代理执行恶意代码，从而有效地绕过应用白名单防御解决方案。

## 测试案例
 atbroker.exe（C:\Windows\System32目录下），源于微软的“轻松访问中心”。”轻松访问中心”的一项功能是帮助用户启动辅助功能应用程序，常用的包括讲述人，屏幕键盘和放大镜。同时，这意味着第三方程序也可以通过注册“轻松访问中心”的方式来启动。
 
 路径：
 ```
- C:\Windows\System32\Atbroker.exe
- C:\Windows\SysWOW64\Atbroker.exe
 ```

开始使用辅助技术 (AT)
```
ATBroker.exe /start malware
```


用例：执行在注册表中为新 AT 定义的代码。 必须对系统注册表进行修改以注册或修改现有的 Assistibe Technology (AT) 服务条目。
所需权限：用户
操作系统：Windows 8、Windows 8.1、Windows 10

## 检测日志

windows 安全日志（需要自行配置）

## 测试复现
```
Microsoft Windows [版本 10.0.18363.418]
(c) 2019 Microsoft Corporation。保留所有权利。

C:\Users\liyang>
C:\Users\liyang>atbroker.exe /start malware
```

### 测试环境

Windows 10

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

新进程 ID: 0x21e4

新进程名称: C:\Windows\System32\AtBroker.exe

令牌提升类型: %%1938

强制性标签: Mandatory Label\Medium Mandatory Level

创建者进程 ID: 0x24b4

创建者进程名称: C:\Windows\System32\cmd.exe

进程命令行: atbroker.exe  /start malware
```

## 检测规则/思路

参考Sigma官方检测规则

### sigma规则

```yml
title: Suspicious Atbroker Execution

id: f24bcaea-0cd1-11eb-adc1-0242ac120002

description: Atbroker executing non-deafualt Assistive Technology applications

references:

- http://www.hexacorn.com/blog/2016/07/22/beyond-good-ol-run-key-part-42/

- https://lolbas-project.github.io/lolbas/Binaries/Atbroker/

status: experimental

author: Mateusz Wydra, oscd.community

date: 2020/10/12

modified: 2021/08/14

tags:

- attack.defense_evasion

- attack.t1218

logsource:

category: process_creation

product: windows

detection:

selection:

Image|endswith: 'AtBroker.exe'

CommandLine|contains: 'start'

filter:

CommandLine|contains:

- animations

- audiodescription

- caretbrowsing

- caretwidth

- colorfiltering

- cursorscheme

- filterkeys

- focusborderheight

- focusborderwidth

- highcontrast

- keyboardcues

- keyboardpref

- magnifierpane

- messageduration

- minimumhitradius

- mousekeys

- Narrator

- osk

- overlappedcontent

- showsounds

- soundsentry

- stickykeys

- togglekeys

- windowarranging

- windowtracking

- windowtrackingtimeout

- windowtrackingzorder

condition: selection and not filter

falsepositives:

- Legitimate, non-default assistive technology applications execution

level: high
```


## 参考推荐

MITRE-ATT&CK-T1218

<https://attack.mitre.org/techniques/T1218>

Atbroker.exe

<https://lolbas-project.github.io/lolbas/Binaries/Atbroker/>

ATBroker.exe：一个被病毒利用的微软进程

<https://www.freebuf.com/articles/system/171437.html>
