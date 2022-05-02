# T1110-003-linux-ssh爆破

## 来自ATT&CK的描述

当密码未知时，攻击者可以使用暴力破解尝试获取访问帐户密码。攻击者在操作期间尝试暴力破解登录，这是一个风险较高的选项，因为它可能导致大量身份验证失败记录以及帐户锁定，账户锁定具体取决于所设置的登录失败策略。

通常，可以对使用常用端口上的服务进行密码喷射攻击。常见linux服务包括以下内容：

- SSH（22/TCP）
- Telnet（23/TCP）
- FTP（21/ TCP）

## 测试案例

以下经典工具可用于端口爆破：

- Hydra
- Medusa
- Patator
- Brutepray
- ……

## 检测日志

linux 系统日志（auth.log）

linux audit日志

## 测试复现

```shell
root@icbc:/hacker/mima# hydra -l root -P passwd.txt  ssh://192.168.159.132 -V
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.
```

## 测试留痕

auth.log

```log
Failed password for root from 192.168.159.129 port 43728 ssh2
```

audit.log

```log
type=USER_AUTH msg=audit(1572163129.581:316): pid=2165 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication acct="root" exe="/usr/sbin/sshd" hostname=192.168.159.129 addr=192.168.159.129 terminal=ssh res=failed'
```

## 检测规则/思路

### sigma规则

```yml
title: linux下ssh暴力破解
description: Ubuntu18.04、kali
references:
tags: T1110-003
status: experimental
author: 12306Bro
logsource:
    product: linux
    service: auth.log/audit.log
detection:
    keywords:
       - 'Failed password for * ssh2' #linux auth.log
       - '* exe="/usr/sbin/sshd" * terminal=ssh res=failed'  #linux audit.log
    condition: keywords
level: medium
```

### 建议

暂无

## 参考推荐

MITRE-ATT&CK-T1110-003

<https://attack.mitre.org/techniques/T1110/003>
