# T1555-005-win-cmdkey获取凭据(白名单)

## 来自ATT&CK的描述

攻击者可能从第三方密码管理器中获取用户凭证。密码管理器是存储用户凭证的应用程序，通常是在一个加密的数据库中。在用户提供主密码解锁数据库后，通常可以获得凭证。数据库被解锁后，这些凭证可以被复制到内存中。这些数据库可以以文件形式存储在磁盘上。

攻击者可以通过从内存中提取主密码或纯文本凭证，从密码管理器中获取用户凭证。攻击者可以通过密码猜解获得主密码从内存提取凭证。

## 测试案例

Windows系统上获取缓存明文凭证方法的过程中，发现了一个非常有趣的工具：cmdkey.exe。Cmdkey是一个内置的Windows工具，可以用来缓存在特定目标机器上使用的域用户凭证。你可以从下列地址查看来自Microsoft的相关文档：<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc754243(v=ws.11)?redirectedfrom=MSDN>

cmdkey具有下列特点：

1. 允许我们以普通域用户的身份来显示和创建凭证

2. 通常用于在远程系统上执行管理任务

## 检测日志

Windows安全日志 4688

## 测试复现

```yml
C:\Users\Administrator>cmdkey /list

当前保存的凭据:

    目标: MicrosoftAccount:target=SSO_POP_Device
    类型: 域扩展的凭据
    用户: 02bdiisjiovu
    仅为此登录保存

    目标: WindowsLive:target=virtualapp/didlogical
    类型: 普通
    用户: 02bdiisjiovu
    本地机器持续时间


C:\Users\Administrator>
```

## 测试留痕

windows安全日志

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
 新进程 ID:  0xd3c
 新进程名称: C:\Windows\System32\cmdkey.exe
 令牌提升类型: %%1936
 强制性标签:  Mandatory Label\High Mandatory Level
 创建者进程 ID: 0x15d0
 创建者进程名称: C:\Windows\System32\cmd.exe
 进程命令行: cmdkey  /list
```

## 检测规则/思路

```yml
title: widnows下利用cmdkey获取凭证
status: 测试阶段
tags:
    - attack.t1555-005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Eventid:
            - 4688 #进程创建，windows 安全日志，Windows server 2012及以上版本配置相关审核策略，可记录系统命令行参数
        CommandLine|contains|all: 
            - 'cmdkey /list'
    condition: selection
level: medium
```

## 建议

建议基于命令行参数+进程名称检测，但对操作系统版本要求较高。谨慎使用！

## 参考推荐

MITRE-ATT&CK-T1555-005

<https://attack.mitre.org/techniques/T1555/005/>

红蓝对抗之Windows内网渗透

<https://blog.csdn.net/Tencent_SRC/article/details/107853395?utm_medium=distribute.pc_relevant.none-task-blog-2~default~baidujs_title~default-4.readhide&spm=1001.2101.3001.4242>

利用Windows系统内置的域用户密钥缓存工具cmdkey辅助渗透提权

<https://www.secpulse.com/archives/66084.html>

cmdkey微软说明

<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc754243(v=ws.11)?redirectedfrom=MSDN>
