# T1134-001-win-访问令牌操作-Runas命令

## 来自ATT&CK的描述

攻击者可能会复制，然后冒充另一个用户的令牌用于提升特权并绕过访问控制。攻击者可以创建一个新的访问令牌，该令牌使用来复制现有令牌DuplicateToken(Ex)。然后可以将该令牌用于ImpersonateLoggedOnUser允许调用线程模拟已登录用户的安全上下文，或者SetThreadToken用于将模拟令牌分配给线程。

当攻击者具有要将新令牌分配给的特定现有进程时，他们可以执行此操作。例如，当目标用户在系统上具有非网络登录会话时，这可能很有用。

## 测试案例

runas是Windows系统上自带的一个命令，通过此命令可以以指定权限级别间接启动我们的程序，而不止是继承父进程的权限。

打开cmd或者PowerShell，输入runas命令可以看到其用法。

```yml
C:\Users\Administrator>runas
RUNAS 用法:

RUNAS [ [/noprofile | /profile] [/env] [/savecred | /netonly] ]
        /user:<UserName> program

RUNAS [ [/noprofile | /profile] [/env] [/savecred] ]
        /smartcard [/user:<UserName>] program

RUNAS /trustlevel:<TrustLevel> program

   /noprofile        指定不应该加载用户的配置文件。
                     这会加速应用程序加载，但
                     可能会造成一些应用程序运行不正常。
   /profile          指定应该加载用户的配置文件。
                     这是默认值。
   /env              要使用当前环境，而不是用户的环境。
   /netonly          只在指定的凭据限于远程访问的情况下才使用。
   /savecred         用用户以前保存的凭据。
   /smartcard        如果凭据是智能卡提供的，则使用这个选项。
   /user             <UserName> 应使用 USER@DOMAIN 或 DOMAIN\USER 形式
   /showtrustlevels  显示可以用作 /trustlevel 的参数的
                     信任级别。
   /trustlevel       <Level> 应该是在 /showtrustlevels 中枚举
                     的一个级别。
   program           EXE 的命令行。请参阅下面的例子

示例:
> runas /noprofile /user:mymachine\administrator cmd
> runas /profile /env /user:mydomain\admin "mmc %windir%\system32\dsa.msc"
> runas /env /user:user@domain.microsoft.com "notepad \"my file.txt\""

注意:  只在得到提示时才输入用户的密码。
注意:  /profile 跟 /netonly 不兼容。
注意:  /savecred 跟 /smartcard 不兼容。
```

## 检测日志

Windows 安全日志

## 测试复现

演示降权操作：域环境下测试，提权为域管理员权限执行时，需要输入域管理员密码。

![演示](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/Ua9e325e4c1c844bebe09b94ee244d0b9Q.jpg)

## 测试留痕

注意：演示主机与日志留痕主机，非相同主机。仅为了证明Windows server 12以上版本操作系统可记录操作命令行及其参数。

```yml
已创建新进程。

创建者主题:
 安全 ID:  QAX\Administrator
 帐户名:  Administrator
 帐户域:  QAX
 登录 ID:  0x4463EA

目标主题:
 安全 ID:  NULL SID
 帐户名:  -
 帐户域:  -
 登录 ID:  0x0

进程信息:
 新进程 ID:  0x12ac
 新进程名称: C:\Windows\System32\runas.exe
 令牌提升类型: %%1936
 强制性标签:  Mandatory Label\High Mandatory Level
 创建者进程 ID: 0x12b0
 创建者进程名称: C:\Windows\System32\cmd.exe
 进程命令行: runas  /user:qax\weixin cmd
```

## 检测规则/思路

### sigma规则

```yml
title: Runas命令进行权限提升
description: 攻击Runas命令：能让域用户/普通User用户以管理员身份运行指定程序。
status: experimental
references:
    - https://walterlv.blog.csdn.net/article/details/89838982
logsource:
​    product: windows
​    service: security
detection:
​    selection:
​        EventID:
​                - 4688 #Windows 安全日志
        New Process Name: 'runas.exe' #Application Name
        Commanline: 
                - '/user'
​    condition: selection
level: high
```

### 建议

如果攻击者使用标准cmd或者powershell，则分析人员可以通过审核命令行活动来检测令牌操纵。具体地说，分析人员应寻找该runas命令的使用。Windows默认情况下不启用详细的命令行日志记录。

分析师还可以监视Windows API（例如DuplicateToken(Ex)）的使用 ImpersonateLoggedOnUser ，并将 SetThreadToken 活动与其他可疑行为相关联，以减少可能由于用户和管理员的正常良性使用而导致的误报。

## 相关TIP
[[T1134-001-win-CVE-2020-1472]]
[[T1134-005-win-SID历史记录注入]]

## 参考推荐

MITRE-ATT&CK-T1134-001

<https://attack.mitre.org/techniques/T1134/001/>

Runas命令：能让域用户/普通User用户以管理员身份运行指定程序

<https://walterlv.blog.csdn.net/article/details/89838982>
