# T1049/1069-bloodhound使用

## 来自ATT&CK的描述

T1049:攻击者可能会通过查询网络上的信息来尝试获取与他们当前正在访问的受感染系统之间或从远程系统获得的网络连接的列表。

T1069:攻击者可能会尝试查找本地系统或域级别的组和权限设置。

## 测试案例

BloodHound是一种单页的JavaScript的Web应用程序，构建在Linkurious上，用Electron编译，NEO4J数据库是PowerShell/C# ingesto。

BloodHound使用可视化图来显示Active Directory环境中隐藏的和相关联的主机内容。攻击者可以使用BloodHound轻松识别高度复杂的攻击路径，否则很难快速识别。防御者可以使用BloodHound来识别和防御那些相同的攻击路径。蓝队和红队都可以使用BloodHound轻松深入了解Active Directory环境中的权限关系。

## 检测日志

windows 安全日志

## 测试复现

```dos
 SharpHound.exe -c ALL
```

## 测试留痕

windows安全日志、5145

## 检测规则/思路

### sigma规则

```yml
title: Bloodhound and Sharphound Hack Tool
description: Detects command line parameters used by Bloodhound and Sharphound hack tools
references:
    - https://github.com/BloodHoundAD/BloodHound
    - https://github.com/BloodHoundAD/SharpHound
tags:
    - attack.discovery
    - attack.t1049
logsource:
    category: process_creation
    product: windows
detection:
    selection1: 
        Image|contains: 
            - '\Bloodhound.exe'
            - '\SharpHound.exe'
    selection2:
        CommandLine|contains: 
            - ' -CollectionMethod All '
            - '.exe -c All -d '
            - 'Invoke-Bloodhound'
            - 'Get-BloodHoundData'
    selection3:
        CommandLine|contains|all: 
            - ' -JsonFolder '
            - ' -ZipFileName '
    selection4:
        CommandLine|contains|all: 
            - ' DCOnly '
            - ' --NoSaveCache '
    condition: 1 of them
falsepositives:
    - Other programs that use these command line option and accepts an 'All' parameter
level: high
```

### 建议

基于进程命令名称进行检测，准确率极低，谨慎使用检测条件1.

## 参考推荐

MITRE-ATT&CK-T1049

<https://attack.mitre.org/techniques/T1049/>

MITRE-ATT&CK-T1069

<https://attack.mitre.org/techniques/T1069/>

bloodhound

<https://github.com/BloodHoundAD/BloodHound>

域分析神器

<https://www.cnblogs.com/KevinGeorge/p/10513211.html>
