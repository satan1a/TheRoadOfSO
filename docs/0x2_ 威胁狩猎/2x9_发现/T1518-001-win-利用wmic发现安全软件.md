# T1518-001-win-利用wmic发现安全软件

## 来自ATT&CK的描述

攻击者可能会尝试获取安装在系统或云环境中的安全软件，配置，防御工具和传感器的列表。这可能包括诸如防火墙规则和防病毒之类的内容。攻击者可以在自动发现过程中使用来自安全软件发现的信息来塑造后续行为，包括攻击者是否完全感染目标和/或尝试执行特定操作。

可用于获得安全软件的信息例如命令的netsh，reg query，dir与CMD，和任务列表，但发现行为其他指标可以是更具体的软件或安全系统的攻击者正在寻找的类型。看到macOS恶意软件对LittleSnitch和KnockKnock软件执行检查已变得越来越普遍。

## 测试案例

枚举出目标系统安装的反病毒产品信息，包括安装位置和版本：

```wmic
wmic /namespace:\\root\securitycenter2 path antivirusproduct GET displayName,productState, pathToSignedProductExe
```

## 检测日志

windows 安全日志

## 测试复现

```dos
C:\Users\Administrator>wmic /namespace:\\root\securitycenter2 path antivirusproduct GET displayName,productState, pathToSignedProductExe
错误:
描述 = 找不到
```

## 测试留痕

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" />
    <EventID>4688</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>13312</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2021-08-08T12:11:06.644030100Z" />
    <EventRecordID>249140</EventRecordID>
    <Correlation />
    <Execution ProcessID="4" ThreadID="212" />
    <Channel>Security</Channel>
    <Computer>WIN-1CIA2BP8VBJ.qax.com</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-1180088053-4000917822-266516913-500</Data>
    <Data Name="SubjectUserName">Administrator</Data>
    <Data Name="SubjectDomainName">QAX</Data>
    <Data Name="SubjectLogonId">0x187cd2</Data>
    <Data Name="NewProcessId">0x1384</Data>
    <Data Name="NewProcessName">C:\Windows\System32\wbem\WMIC.exe</Data>
    <Data Name="TokenElevationType">%%1936</Data>
    <Data Name="ProcessId">0x151c</Data>
    <Data Name="CommandLine">wmic  /namespace:\\root\securitycenter2 path antivirusproduct GET displayName,productState, pathToSignedProductExe</Data>
    <Data Name="TargetUserSid">S-1-0-0</Data>
    <Data Name="TargetUserName">-</Data>
    <Data Name="TargetDomainName">-</Data>
    <Data Name="TargetLogonId">0x0</Data>
    <Data Name="ParentProcessName">C:\Windows\System32\cmd.exe</Data>
    <Data Name="MandatoryLabel">S-1-16-12288</Data>
  </EventData>
</Event>
```

## 检测规则/思路

### sigma规则

```yml
title: windows wmi发现本地安全软件
description: windows server 2016
references: 暂无
tags: T1518-001
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4688 #进程创建
        Newprocessname: 'C:\Windows\System32\wbem\WMIC.exe' #进程信息>新进程名称
        Processcommandline: '/namespace:\\root\SecurityCenter2 * GET *'  #进程信息>进程命令行
    condition: selection
level: low
```

### 建议

系统和网络发现技术通常发生在攻击者了解环境的整个行动中。不应孤立地看待数据和事件，而应根据获得的信息，将其视为可能导致其他活动（如横向运动）的行为链的一部分。

监视进程和命令行参数，以了解为收集系统和网络信息而可能采取的操作。具有内置功能的远程访问工具可以直接与Windows API交互以收集信息。还可以通过Windows系统管理工具（如Windows management Instrumentation和PowerShell）获取信息。

## 参考推荐

MITRE-ATT&CK-T1518-001

<https://attack.mitre.org/techniques/T1518/001>

比CMD更强大的命令行：WMIC后渗透利用（系统命令）

<https://blog.csdn.net/discover2210212455/article/details/82711930>

discovery_security_software_wmic

<https://github.com/elastic/detection-rules/blob/main/rules/windows/discovery_security_software_wmic.toml>