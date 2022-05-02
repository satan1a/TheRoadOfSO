# T1558-003-win-kerberosing

## 来自ATT&CK的描述

服务主体名称（SPN）用于唯一标识Windows服务的每个实例。为了启用身份验证，Kerberos要求SPN与至少一个服务登录帐户（专门用于运行服务的帐户）相关。

拥有有效的Kerberos票证授予票证（TGT）的攻击者可以向域控制器（DC）请求任何SPN的一个或多个Kerberos票证授予服务（TGS）服务票证。可以使用RC4算法对这些票证的一部分进行加密，这意味着与SPN相关联的服务帐户的Kerberos 5 TGS-REP etype 23哈希将用作私钥，因此容易受到离线暴力破解攻击可能暴露明文凭据的攻击。

可以使用从网络流量中捕获的服务票证执行相同的攻击。

## 测试案例

PowerSploit
Empire

## 检测日志

windows 安全日志

netflow流量

## 测试复现

暂无

## 测试留痕

暂无

## 检测规则/思路

### sigma规则

```yml
title: kerberos 弱加密
description: 域环境测试
references: https://adsecurity.org/?p=3458
status: experimental
author: 12306Bro
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769  #kerberos服务票证请求
        TicketOptions: 0x40810000  #附加信息>票证选项
        TicketEncryptiontype: 0x17 #附加信息>票证加密类型
    reduction:
        - ServiceName: '$*' #服务名称>服务信息
    condition: selection and not reduction
level: medium
```

### 建议

暂无

## 相关TIP
[[T1558-003-win-SPN-凭证转储]]

## 参考推荐

MITRE-ATT&CK-T1558-003

<https://attack.mitre.org/techniques/T1558/003>

检测kerberosing活动

<https://adsecurity.org/?p=3458>
