# T1505-003-windows下webshell检测

## 来自ATT&CK的描述

攻击者可能会通过Web Shell为web服务器创建后门，以便实现对系统的持久访问。Web Shell是攻击者放置在可公开访问的web服务器上的web脚本，以便通过web服务器进入网络。Web Shell可以提供一套待执行的函数，或是为web服务器所在系统提供命令行界面。

除服务器端脚本之外，Web Shell可能还有客户端接口程序，用于与web服务器通信，例如：[China Chopper](https://attack.mitre.org/software/S0020)（引自：Lee 2013）

## webshell简介

webshell就是以asp、php、jsp或者cgi等网页文件形式存在的一种代码执行环境，也可以将其称做为一种网页后门。黑客在入侵了一个网站后，通常会将asp或php后门文件与网站服务器WEB目录下正常的网页文件混在一起，然后就可以使用浏览器来访问asp或者php后门，得到一个命令执行环境，以达到控制网站服务器的目的。

顾名思义，“web”的含义是显然需要服务器开放web服务，“shell”的含义是取得对服务器某种程度上操作权限。webshell常常被称为入侵者通过网站端口对网站服务器的某种程度上操作的权限。由于webshell其大多是以动态脚本的形式出现，也有人称之为网站的后门工具。

## 测试案例

暂无

## 检测日志

windows、sysmon日志、以及其他可记录进程、命令行参数的EDR产品

## 测试复现

暂无

## 测试留痕

```yml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
 <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
 <EventID>4688</EventID> 
 <Version>2</Version> 
 <Level>0</Level> 
 <Task>13312</Task> 
 <Opcode>0</Opcode> 
 <Keywords>0x8020000000000000</Keywords> 
 <TimeCreated SystemTime="2015-11-12T02:24:52.377352500Z" /> 
 <EventRecordID>2814</EventRecordID> 
 <Correlation /> 
 <Execution ProcessID="4" ThreadID="400" /> 
 <Channel>Security</Channel> 
 <Computer>WIN-GG82ULGC9GO.contoso.local</Computer> 
 <Security /> 
 </System>
- <EventData>
 <Data Name="SubjectUserSid">S-1-5-18</Data> 
 <Data Name="SubjectUserName">WIN-GG82ULGC9GO$</Data> 
 <Data Name="SubjectDomainName">CONTOSO</Data> 
 <Data Name="SubjectLogonId">0x3e7</Data> 
 <Data Name="NewProcessId">0x2bc</Data> 
 <Data Name="NewProcessName">C:\\Windows\\System32\\rundll32.exe</Data> 
 <Data Name="TokenElevationType">%%1938</Data> 
 <Data Name="ProcessId">0xe74</Data> 
 <Data Name="CommandLine" /> 
 <Data Name="TargetUserSid">S-1-5-21-1377283216-344919071-3415362939-1104</Data> 
 <Data Name="TargetUserName">dadmin</Data> 
 <Data Name="TargetDomainName">CONTOSO</Data> 
 <Data Name="TargetLogonId">0x4a5af0</Data> 
 <Data Name="ParentProcessName">C:\\Windows\\explorer.exe</Data> 
 <Data Name="MandatoryLabel">S-1-16-8192</Data> 
 </EventData>
</Event>
```

## 检测规则/思路

### sigma规则

```yml
title: 通过常见的命令行参数检测webshell行为
description: 通过web shell侦察活动中经常使用的某些命令行参数来检测边界web服务器是否存在webshell
references:
    - https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-ii.html
    - https://unit42.paloaltonetworks.com/bumblebee-webshell-xhunt-campaign/
tags:
    - attack.persistence
    - attack.t1505.003
    - attack.t1018
    - attack.t1033
    - attack.t1087
    - attack.privilege_escalation       # an old one
    - attack.t1100      # an old one
logsource:
    category: process_creation #进程创建
    product: windows #windows数据源
detection:
    selection:
        ParentImage:
            - '*\apache*'
            - '*\tomcat*'
            - '*\w3wp.exe'
            - '*\php-cgi.exe'
            - '*\nginx.exe'
            - '*\httpd.exe'
        CommandLine:
            - '*whoami*'
            - '*net user *'
            - '*net use *'
            - '*net group *'
            - '*quser*'
            - '*ping -n *'
            - '*systeminfo'
            - '*&cd&echo*'
            - '*cd /d*'  # https://www.computerhope.com/cdhlp.htm
            - '*ipconfig*' 
            - '*pathping*' 
            - '*tracert*' 
            - '*netstat*' 
            - '*schtasks*' 
            - '*vssadmin*' 
            - '*wevtutil*' 
            - '*tasklist*' 
            - '*wmic /node:*' 
            - '*Test-NetConnection*' 
            - '*dir \*'  # remote dir: dir \<redacted IP #3>\C$:\windows\temp\*.exe
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown #有效性，未知
level: high #等级较高
```

## 备注

整体检测思路，攻击者通过webshell执行一些信息收集的命令，如ipconfig等命令。此类行为在windows日志上的表现形式为，用户调用了常见的中间件的进程，执行了某些命令。此规则检测思路便是来源于此，仅仅适用于windows平台，可自行添加常见的用于信息收集或者其他目的的命令行参数，不断完善规则。

## 参考推荐

MITRE-ATT&CK-T1505-003

<https://attack.mitre.org/techniques/T1505/003/>
