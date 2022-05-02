# T1003-005-win-DCC2-mimikatz凭证获取

## 来自ATT&CK的描述

攻击者可能试图访问缓存的域凭据，该凭据用于在域控制器不可用的情况下进行身份验证。

在Windows Vista及更高版本上，哈希格式为DCC2（域缓存凭据版本2）哈希，也称为MS-Cache v2哈希。默认缓存凭据的数量各不相同，并且每个系统都可以更改。该散列不允许通过散列样式的攻击，而是需要使用密码破解来恢复纯文本密码。

通过SYSTEM访问，可以使用诸如Mimikatz，Reg和secretsdump.py之类的工具/实用程序来提取缓存的凭据。

注意：Windows Vista的缓存凭据是使用PBKDF2派生的

### DCC2（Domain Cached Credentials version 2）

Domain Cached Credentials 简称 DDC域缓存凭据，是缓存的域登录信息，这些信息本地存储在Windows操作系统的windows注册表中，可以通过以下键中的regedit（以SYSTEM特权运行）来查看。

```dos
HKEY_LOCAL_MACHINE\SECURITY\Cache
```

随着Windows Vista操作系统的发布，Microsoft引入了一种新的哈希算法来生成这些域缓存的凭据。这种新算法（即DCC2）将密码猜测攻击的成本提高了几个数量级。

DCC2（域缓存凭据版本2），Windows Vista和更新版本的操作系统使用此算法来缓存和验证相关服务器（域控）不可用时的远程凭据。它有许多其他名称，包括“ mscache2”和“ mscash2”（Microsoft CAched haSH）。它取代了Windows 早期版本中使用的较弱的msdcc v1哈希。从安全角度来看，它并不是特别弱，但是由于它使用了用户名作为盐，因此除了验证现有的缓存凭据之外，不应将其用于任何其他用途。简单来说：它是缓存在操作系统本地注册表中的域凭据+域授权信息，后面简称授权凭据。

举个例子：你的个人办公电脑加入了公司的办公域，你一直使用域账户进行登录，而不是本地账户登录。你利用域账户登录时所输入的账户密码由域控进行验证，当域控验证成功后你可以登录这台办公电脑；但当你的个人办公电脑处于断网或者在其他地方办公（非公司办公域环境）时，你依然可以使用域账户登录这台办公电脑。也就是说，当这台电脑根本无法连接到域控的时候，你也可以使用域账户登陆这台电脑，那这个时候是由谁来负责验证你输入的域账号密码是否正确呢？就是MSCACHE！。

### MSCACHE工作原理介绍

当终端或其他设备可以连上域控的时候，你用域账号去登陆这台终端或其他设备，在登陆成功后（域控验证了你的身份后），操作系统会将你的授权凭据以及授权信息保存在注册表里面。默认是保存 10 个授权凭据（可以对这个值进行更改）。当被保存的授权凭据已经超过 10 个的话，新的授权凭据会覆盖掉老的授权凭据。

授权凭据被缓存在注册表里的这些用户，在机器连不上域控的时候也可以登陆这台机器（只能交互式登陆，比如控制台或远程桌面。远程桌面的时候要注意，不能使用带有 NLA（网络级别身份验证 ） 功能的 RDP 客户端，要用老的比如 XP 上默认 RDP 客户端），但是没有被缓存在注册表里的用户是无法登陆的。

### 网络级别身份验证 (NLA)

在这里简单介绍一下NLA是什么？

网络级别身份验证 (NLA)  是一项新的身份验证方法，即在您建立完整的远程桌面连接前就完成了用户身份验证并显示登录屏幕。它是一项更加安全的身份验证方法，可以防止远程计算机受到黑客或恶意软件的攻击。NLA  的优点是：

- 最初只需要少量的远程计算机资源。对用户进行身份验证之前，远程计算机仅使用有限的资源，而不是像在先前版本中启动整个远程桌面连接。  
- 可以通过降低拒绝服务攻击（尝试限制或阻止访问 Internet）的风险提供更高的安全保障。  
- 使用远程计算机身份验证可以防止我们连接到因恶意目的而安装的远程计算机。

### MSCACHE 解密 - Bootkey, LSA Key, NLKM Key

所以，我们要想解密 MSCACHE，要进行以下步骤：

1. 得到 bootkey
2. 利用 bootkey 解密 LSA Key
3. 利用 LSA Key 解密 NLKM Key
4. 利用 NLKM Key 解密 MSCACHE

以上内容引用自：<https://baijiahao.baidu.com/s?id=1611304657392579351>

## 测试案例

值得注意的是：MSCACHE 保存的是 DCC hash，而并不是 NTLM 的 HASH。所以你导出的域缓存的 hash 是不能用于 PTH 的，只能用来破解。可以使用许多工具通过内存技术检索SAM文件：

- pwdumpx.exe
- gsecdump
- mimikatz
- cachedump
- ......

或者，可以使用reg.exe从Registry收集凭据，在本地使用Creddump7进行破解哈希。

## 检测日志

windows sysmon日志

## 测试复现

场景：攻击者利用mimikatz读取mscash密码哈希

```dos
mimikatz.exe  "privilege::debug"  "token::whoami" "token::elevate"   "LSADUMP::Cache"
```

注意权限问题（administrator），如果权限存在问题需要执行以上命令。如果权限没有问题建议执行以下命名：

```dos
mimikatz.exe  "privilege::debug"   "LSADUMP::Cache"
```

## 测试留痕

暂无

## 检测规则/思路

### sigma规则

```yml
title: Mimikatz使用
tags:
    - attack.s0002
    - attack.t1003
    - attack.lateral_movement
logsource:
    product: windows
detection:
    keywords:
        Message:
        - "* mimikatz *"
        - "* mimilib *"
        - "* <3 eo.oe *"
        - "* eo.oe.kiwi *"
        - "* privilege::debug *"
        - "* sekurlsa::logonpasswords *"
        - "* lsadump::sam *"
        - "* mimidrv.sys *"
        - "* p::d *"
        - "* s::l *"
    condition: keywords
falsepositives:
    - Naughty administrators
    - Penetration test
level: critical
```

### 建议

暂无

## 参考推荐

MITRE-ATT&CK-T1003-005

<https://attack.mitre.org/techniques/T1003/005>

你并不懂 Mimikatz Part 2 - MSCACHE

<https://baijiahao.baidu.com/s?id=1611304657392579351>

DCC2算法介绍

<https://openwall.info/wiki/john/MSCash2>

Windows密码缓存（mscache / mscash）v2

<https://www.jedge.com/wordpress/windows-password-cache-mscache-mscash-v2/>

转储和破解mscash-缓存的域凭据

<https://ired.team/offensive-security/credential-access-and-credential-dumping/dumping-and-cracking-mscash-cached-domain-credentials>
