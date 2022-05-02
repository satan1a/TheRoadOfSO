# T1212-windows-MS14-068-KEKEO

## 来自ATT&CK的描述

票据传递攻击（PtT）是一种不访问账号密码而使用Kerberos凭据对用户进行身份认证的方法。Kerberos身份认证可以是横向移动到远程系统的第一步。

在使用PtT技术时，可通过凭据导出技术获取有效账号的Kerberos票据。PtT可能会获取到用户的服务票据或票据授予票据（TGT），具体取决于访问级别。服务票据允许访问特定资源，而TGT可用于从票据授予服务（TGS）请求服务票据，用来访问用户有权访问的任何资源。

PtT技术可以为使用Kerberos作为身份认证机制的服务获取白银票据，并用于生成票据来访问特定资源和承载该资源的系统（例如，SharePoint）。

PtT技术还可以使用密钥分发服务账号KRBTGT帐户NTLM哈希来获得域的黄金票据，从而为活动目录中的任一账号生成TGT。

## 测试案例

可参考：[内网渗透之PTH&PTT&PTK](https://www.bbsmax.com/A/A7zgkjRPz4/)

## 检测日志

windows 安全日志（AD域控日志）

## 测试复现

暂无

## 测试留痕

测试留痕文件：暂无

## 检测规则/思路

### sigma规则

```yml
title: MS14-068-PYKEK
description: windows server 2008 / windows 7
references: https://www.blackhat.com/docs/us-15/materials/us-15-Metcalf-Red-Vs-Blue-Modern-Active-Directory-Attacks-Detection-And-Protection-wp.pdf
tags: T1212
status: experimental
author: 12306Bro
logsource:
    product: windows
    service: Security
detection:
    selection1:
        EventID: 4624 #账户登录
        Account Domain: '*.*' #新登录>账户域(正常情况下，账户域应为ABC，当存在KEKEO攻击时，账户域为ABC.COM)
    selection2:
        EventID: 4672 #管理员登录
        Account Domain:  #账户域(正常情况下，账户域应为ABC，当存在KEKEO攻击时，账户域为空)
    selection3:
        EventID: 4768 #Kerberos TGS请求
        Supplied Realm Name: '*.*' #已提供的领域名称(正常情况下，已提供的领域名称应为ABC，当存在KEKEO攻击时，已提供的领域名称为ABC.COM)
    timeframe: last 5s
    condition: all of them
level: medium
```

其中4768需要排除正常条件，比如服务 ID:S-1-0-0或者用户名为ntp$ 计算机时间同步

### 建议

本规则未经过实际环境测试，谨慎使用

## 相关TIP
[[T1212-win-ms14-068-PYKEK]]

## 参考推荐

MITRE-ATT&CK-T1212

<https://attack.mitre.org/techniques/T1212/>

内网渗透之PTH&PTT&PTK

<https://www.bbsmax.com/A/A7zgkjRPz4/>
