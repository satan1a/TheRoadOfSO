# T1105-Windows Update被发现可滥用于执行恶意程序行为检测

## 来自ATT&CK的描述

攻击者可能会将工具或其他文件从外部系统转移到被攻陷的环境中。可以通过命令控制通道从外部攻击者控制的系统中复制文件，以便将工具带入被攻陷的网络环境中，或通过与另一个工具（如FTP）的替代协议复制文件。文件也可以在Mac和Linux上使用scp、rsync和sftp等本机工具进行复制。

## 测试案例

援引外媒Bleeping Computer报道，MDSec研究人员David Middlehurst发现，攻击者可以通过使用以下命令行选项从任意特制的DLL加载wuauclt，从而在Windows 10系统上执行恶意代码：

```yml
wuauclt.exe /UpdateDeploymentProvider [path_to_dll] /RunHandlerComServer
```

该技巧绕过Windows用户帐户控制（UAC）或Windows Defender应用程序控制（WDAC），可用于在已经受到威胁的系统上获得持久性。之所以能够发现，是因为他发现已经有黑客利用这个漏洞执行攻击行为。

## 检测日志

windows安全日志、其他EDR类产品

## 测试复现

暂无

## 测试留痕

暂无

## 检测规则/思路

### sigma规则

```yml

title: Windows Update Client滥用检测
status: experimental
description: Detects code execution via the Windows Update client (wuauclt)
references:
    - https://www.nruan.com/75037.html
tags:
    - attack.command_and_control
    - attack.execution
    - attack.t1105
    - attack.t1218
logsource:
    product: windows #windows
    service: process_creation #安全事件，进程创建
detection:
    selection:
        ProcessCommandline|contains|all: #进程命令行参数包含以下任意一项
            - '/UpdateDeploymentProvider'
            - '/RunHandlerComServer'
        Image|endswith: 
            - '\wuauclt.exe' #进程路径为以wuauclt.exe
    condition: selection
falsepositives:
    - Unknown
level: high
```

### 建议

低版本操作系统无法记录命令行参数及子父进程，建议通过Sysmon进行监控。

## 参考推荐

MITRE-ATT&CK-T1105

<https://attack.mitre.org/techniques/T1105>

Windows Update被发现可滥用于执行恶意程序

<https://www.nruan.com/75037.html>