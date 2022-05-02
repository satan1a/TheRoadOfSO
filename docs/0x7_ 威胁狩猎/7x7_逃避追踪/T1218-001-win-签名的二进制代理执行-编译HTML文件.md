# T1218-001-win-编译HTML文件

## 来自ATT&CK的描述

攻击者可能会滥用编译的HTML文件（.chm）来掩盖恶意代码。CHM文件通常作为微软HTML帮助系统的一部分分发。CHM文件是各种内容的压缩汇编，如HTML文档、图像和脚本/网络相关编程语言，如VBA、JScript、Java和ActiveX。CHM内容的显示是使用由HTML帮助可执行程序（hh.exe）加载的Internet Explorer浏览器的底层组件。

一个包含有效载荷的自定义CHM文件可以被传递给目标，然后由用户执行触发。在不考虑通过hh.exe执行二进制文件的旧系统或未打补丁的系统上，CHM执行也可能绕过应用程序控制。

## 测试案例

编译的html文件(.chm)可运行如下:HTML documents， images，and scripting/web related programming languages such VBA，JScript，Java，and ActiveX。并通过hh.exe来打开他们，红队可用chm文件来隐藏一段payload，此技术也可以来绕过一些检测病毒检测。

## 检测日志

windows security

windows sysmon

## 测试复现

```
C:\Users\zhuli>hh.exe C:\Users\zhuli\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1218.001\src\T1218.001.chm
```

执行成功

## 测试留痕

Windows Sysmon记录
```
日志名称:          Microsoft-Windows-Sysmon/Operational
来源:            Microsoft-Windows-Sysmon
日期:            2022/1/9 21:18:49
事件 ID:         1
任务类别:          Process Create (rule: ProcessCreate)
级别:            信息
关键字:           
用户:            SYSTEM
计算机:           zhuli.qax.com
描述:
Process Create:
RuleName: -
UtcTime: 2022-01-09 13:18:49.717
ProcessGuid: {78c84c47-e0b9-61da-c409-000000000800}
ProcessId: 3576
Image: C:\Windows\hh.exe
FileVersion: 10.0.17763.1 (WinBuild.160101.0800)
Description: Microsoft® HTML Help Executable
Product: HTML Help
Company: Microsoft Corporation
OriginalFileName: HH.exe
CommandLine: hh.exe  C:\Users\zhuli\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1218.001\src\T1218.001.chm
CurrentDirectory: C:\Users\zhuli\
User: QAX\zhuli
LogonGuid: {78c84c47-3b57-61d8-525f-090000000000}
LogonId: 0x95F52
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA1=4B1E2F8EFBECB677080DBB26876311D9E06C5020,MD5=1CECEE8D02A8E9B19D3A1A65C7A2B249,SHA256=8AB2F9A4CA87575F03F554AEED6C5E0D7692FA9B5D420008A1521F7F7BD2D0A5,IMPHASH=D3D9C3E81A404E7F5C5302429636F04C
ParentProcessGuid: {78c84c47-e09d-61da-b909-000000000800}
ParentProcessId: 3500
ParentImage: C:\Windows\System32\cmd.exe
ParentCommandLine: "C:\Windows\system32\cmd.exe" 
ParentUser: QAX\zhuli
事件 Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
    <EventID>1</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Task>1</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2022-01-09T13:18:49.718598100Z" />
    <EventRecordID>7093</EventRecordID>
    <Correlation />
    <Execution ProcessID="2764" ThreadID="3668" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>zhuli.qax.com</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2022-01-09 13:18:49.717</Data>
    <Data Name="ProcessGuid">{78c84c47-e0b9-61da-c409-000000000800}</Data>
    <Data Name="ProcessId">3576</Data>
    <Data Name="Image">C:\Windows\hh.exe</Data>
    <Data Name="FileVersion">10.0.17763.1 (WinBuild.160101.0800)</Data>
    <Data Name="Description">Microsoft® HTML Help Executable</Data>
    <Data Name="Product">HTML Help</Data>
    <Data Name="Company">Microsoft Corporation</Data>
    <Data Name="OriginalFileName">HH.exe</Data>
    <Data Name="CommandLine">hh.exe  C:\Users\zhuli\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1218.001\src\T1218.001.chm</Data>
    <Data Name="CurrentDirectory">C:\Users\zhuli\</Data>
    <Data Name="User">QAX\zhuli</Data>
    <Data Name="LogonGuid">{78c84c47-3b57-61d8-525f-090000000000}</Data>
    <Data Name="LogonId">0x95f52</Data>
    <Data Name="TerminalSessionId">1</Data>
    <Data Name="IntegrityLevel">Medium</Data>
    <Data Name="Hashes">SHA1=4B1E2F8EFBECB677080DBB26876311D9E06C5020,MD5=1CECEE8D02A8E9B19D3A1A65C7A2B249,SHA256=8AB2F9A4CA87575F03F554AEED6C5E0D7692FA9B5D420008A1521F7F7BD2D0A5,IMPHASH=D3D9C3E81A404E7F5C5302429636F04C</Data>
    <Data Name="ParentProcessGuid">{78c84c47-e09d-61da-b909-000000000800}</Data>
    <Data Name="ParentProcessId">3500</Data>
    <Data Name="ParentImage">C:\Windows\System32\cmd.exe</Data>
    <Data Name="ParentCommandLine">"C:\Windows\system32\cmd.exe" </Data>
    <Data Name="ParentUser">QAX\zhuli</Data>
  </EventData>
</Event>
```

## 检测规则/思路

### sigma规则

```yml
title: 使用编译的恶意html文件(.chm)
status: experimental
logsource:
​    product: windows
​    service: sysmon
detection:
​    selection:
​        EventID: 1 #Windows sysmon日志
         Image: C:\Windows\hh.exe
         Commanline: '*.chm'
​    condition: selection
level: low
```

### 建议

暂无

## 相关TIP
[[T1218-002-win-签名的二进制代理执行-Control.exe(白名单)]]
[[T1218-007-win-签名的二进制代理执行-Msiexec]]

## 参考推荐

MITRE-ATT&CK-T1218-001

<https://attack.mitre.org/techniques/T1218/001/>

跟着ATT&CK学安全之defense-evasion

<https://snappyjack.github.io/articles/2020-01/%E8%B7%9F%E7%9D%80ATT&CK%E5%AD%A6%E5%AE%89%E5%85%A8%E4%B9%8Bdefense-evasion>
