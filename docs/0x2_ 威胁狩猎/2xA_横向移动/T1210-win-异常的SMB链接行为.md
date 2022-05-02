# T1210-win-异常的SMB链接行为

## 来自ATT&CK的描述

攻击者一旦进入网络，便可能利用远程服务获得对内部系统的未授权访问。当攻击者利用程序，服务或操作系统软件或内核本身内的编程错误来执行攻击者控制的代码时，就会利用软件漏洞。建立立足点后利用远程服务的目标是横向移动以实现对远程系统的访问。

攻击者可能需要确定远程系统是否处于易受攻击状态，这可以通过网络服务扫描或其他发现方法来完成，以寻找在网络中部署的常见易受攻击软件，检测或包含远程利用的漏洞或安全软件。服务器可能是横向移动中的高价值目标，但是如果端点系统提供访问其他资源的方式，则端点系统也可能处于危险之中。

常见服务（例如SMB和RDP）以及可能在内部网络（例如MySQL）和Web服务器服务中使用的应用程序中存在多个众所周知的漏洞。

根据易受攻击的远程服务的权限级别，攻击者也可能由于横向移动利用而实现对特权升级的利用。

## 测试案例

识别通过端口445进行网络连接的可疑进程。Windows文件共享通常通过服务器消息块（SMB）实现，SMB使用端口445在主机之间进行通信。当合法时，这些网络连接由内核建立。建立445/tcp连接的进程可能是端口扫描程序、漏洞利用或横向移动的可疑用户级进程。

仅提供简单案例：

[在Windows中删除/切换已建立的Samba共享连接](https://blog.csdn.net/u013038461/article/details/39934061)

## 检测日志

windows安全日志

## 测试复现

暂无

## 测试留痕

暂无，仅提供检测规则相关的日志示例

windows server 2016/win10

```yml
The Windows Filtering Platform has allowed a connection.

Application Information:

   Process ID:  1752
   Application Name: \device\harddiskvolume1\windows\system32\dns.exe

Network Information:

   Direction:  Inbound
   Source Address:  10.45.45.103
   Source Port:  53
   Destination Address: 10.45.45.103
   Destination Port:  50146
   Protocol:  17

Filter Information:

   Filter Run-Time ID: 5
   Layer Name:  Receive/Accept
   Layer Run-Time ID: 44
```

## 检测规则/思路

### sigma规则

```yml
title: 检测异常的SMB链接行为
description: 通过windows日志检测异常的SMB链接行为
tags: T1210
status: experimental
references:
    - https://www.elastic.co/guide/en/siem/guide/current/direct-outbound-smb-connection.html
logsource:
    product: windows
    service: security
detection:
    selection1:
          EventID: 5156
          Destination Port: 445
    selection2:
          Destination Address:
                       - 127.0.0.1
                       - ::1
    selection3:
          Process ID: 4
    condition: selection1 and not selection2 and not selection3)
level: medium
```

### Elastic rule query

```yml
event.action:"Network connection detected (rule: NetworkConnect)" and
destination.port:445 and not process.pid:4 and not
destination.ip:(127.0.0.1 or "::1")
```

### 建议

规则未经线上测试，谨慎使用，但是我相信它能够很好的帮助你发现网内的威胁。

## 参考推荐

MITRE-ATT&CK-T1210

<https://attack.mitre.org/techniques/T1210>

检测异常的SMB链接行为

<https://www.elastic.co/guide/en/siem/guide/current/direct-outbound-smb-connection.html>

windows事件ID-5156样例

<https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=5156>

在Windows中删除/切换已建立的Samba共享连接

<https://blog.csdn.net/u013038461/article/details/39934061>