# T1218-002-win-签名的二进制代理执行：控制面板

## 来自ATT&CK的描述

攻击者可能滥用control.exe代理恶意负载的执行。 Windows“控制面板”进程二进制文件（control.exe）处理“控制面板”项的执行，“控制面板”项是使用户可以查看和调整计算机设置的实用程序。

控制面板项目是注册的可执行文件（.exe）或控制面板（.cpl）文件，后者实际上是重命名的动态链接库（.dll）文件，它们导出CPlApplet函数。为了易于使用，“控制面板”项通常包括在注册并加载到“控制面板”中后可供用户使用的图形菜单。可以从命令行直接执行控制面板项目，可以通过应用程序编程接口（API）调用以编程方式执行，也可以直接双击文件来执行。

恶意控制面板项目可以通过网络钓鱼活动传递，也可以作为多阶段恶意软件的一部分执行。控制面板项目，尤其是CPL文件，也可能会绕过应用程序或文件扩展名允许列表。

攻击者还可能使用控制面板文件扩展名（.cpl）重命名恶意DLL文件（.dll），并将其注册到HKCU\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls。即使这些注册的DLL不符合CPL文件规范并且不导出CPlApplet函数，在执行“控制面板”时也会通过其DllEntryPoint加载并执行它们。不导出CPlApplet的CPL文件不能直接执行。

## 测试案例

Control.exe是微软Windows操作系统自带的程序。用于访问控制面板。这不是纯粹的系统程序，但是如果终止它，可能会导致不可知的问题。

暂无测试案例

## 检测日志

windows security

windows sysmon

## 测试复现

```
C:\Users\zhuli>control.exe C:\Users\zhuli\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1218.002\bin\calc.cpl
```

执行成功

## 测试留痕

Windows Sysmon记录
```
日志名称:          Microsoft-Windows-Sysmon/Operational
来源:            Microsoft-Windows-Sysmon
日期:            2022/1/9 21:05:44
事件 ID:         1
任务类别:          Process Create (rule: ProcessCreate)
级别:            信息
关键字:           
用户:            SYSTEM
计算机:           zhuli.qax.com
描述:
Process Create:
RuleName: technique_id=T1218.002,technique_name=rundll32.exe
UtcTime: 2022-01-09 13:05:44.050
ProcessGuid: {78c84c47-dda8-61da-4e09-000000000800}
ProcessId: 6288
Image: C:\Windows\SysWOW64\rundll32.exe
FileVersion: 10.0.17763.1 (WinBuild.160101.0800)
Description: Windows host process (Rundll32)
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: RUNDLL32.EXE
CommandLine: "C:\Windows\SysWOW64\rundll32.exe" "C:\Windows\SysWOW64\shell32.dll",#44 C:\Users\zhuli\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1218.002\bin\calc.cpl
CurrentDirectory: C:\Users\zhuli\
User: QAX\zhuli
LogonGuid: {78c84c47-3b57-61d8-525f-090000000000}
LogonId: 0x95F52
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA1=6778DAD71C8B06264CF2929A5242D2612D3EB026,MD5=2F633406BC9875AA48D6CC5884B70862,SHA256=26E68D4381774A6FD0BF5CA2EACEF55F2AB28536E3176A1C6362DFFC68B22B8A,IMPHASH=BB17B2FBBFF4BBF5EBDCA7D0BB9E4A5B
ParentProcessGuid: {78c84c47-dda8-61da-4d09-000000000800}
ParentProcessId: 704
ParentImage: C:\Windows\System32\rundll32.exe
ParentCommandLine: "C:\Windows\system32\rundll32.exe" Shell32.dll,Control_RunDLL C:\Users\zhuli\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1218.002\bin\calc.cpl
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
    <TimeCreated SystemTime="2022-01-09T13:05:44.051470500Z" />
    <EventRecordID>7001</EventRecordID>
    <Correlation />
    <Execution ProcessID="2764" ThreadID="3668" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>zhuli.qax.com</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="RuleName">technique_id=T1218.002,technique_name=rundll32.exe</Data>
    <Data Name="UtcTime">2022-01-09 13:05:44.050</Data>
    <Data Name="ProcessGuid">{78c84c47-dda8-61da-4e09-000000000800}</Data>
    <Data Name="ProcessId">6288</Data>
    <Data Name="Image">C:\Windows\SysWOW64\rundll32.exe</Data>
    <Data Name="FileVersion">10.0.17763.1 (WinBuild.160101.0800)</Data>
    <Data Name="Description">Windows host process (Rundll32)</Data>
    <Data Name="Product">Microsoft® Windows® Operating System</Data>
    <Data Name="Company">Microsoft Corporation</Data>
    <Data Name="OriginalFileName">RUNDLL32.EXE</Data>
    <Data Name="CommandLine">"C:\Windows\SysWOW64\rundll32.exe" "C:\Windows\SysWOW64\shell32.dll",#44 C:\Users\zhuli\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1218.002\bin\calc.cpl</Data>
    <Data Name="CurrentDirectory">C:\Users\zhuli\</Data>
    <Data Name="User">QAX\zhuli</Data>
    <Data Name="LogonGuid">{78c84c47-3b57-61d8-525f-090000000000}</Data>
    <Data Name="LogonId">0x95f52</Data>
    <Data Name="TerminalSessionId">1</Data>
    <Data Name="IntegrityLevel">Medium</Data>
    <Data Name="Hashes">SHA1=6778DAD71C8B06264CF2929A5242D2612D3EB026,MD5=2F633406BC9875AA48D6CC5884B70862,SHA256=26E68D4381774A6FD0BF5CA2EACEF55F2AB28536E3176A1C6362DFFC68B22B8A,IMPHASH=BB17B2FBBFF4BBF5EBDCA7D0BB9E4A5B</Data>
    <Data Name="ParentProcessGuid">{78c84c47-dda8-61da-4d09-000000000800}</Data>
    <Data Name="ParentProcessId">704</Data>
    <Data Name="ParentImage">C:\Windows\System32\rundll32.exe</Data>
    <Data Name="ParentCommandLine">"C:\Windows\system32\rundll32.exe" Shell32.dll,Control_RunDLL C:\Users\zhuli\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1218.002\bin\calc.cpl</Data>
    <Data Name="ParentUser">QAX\zhuli</Data>
  </EventData>
</Event>
```

## 检测规则/思路

监视和分析与CPL文件相关的项目相关的活动，例如Windows Control Panel进程二进制文件（control.exe）以及shell32.dll中的Control_RunDLL和ControlRunDLLAsUser API函数。从命令行执行或单击时，在使用Rundll32调用CPL的API函数（例如：rundll32.exe shell32.dll，Control_RunDLL文件）之前，control.exe将执行CPL文件（例如：control.exe file.cpl）.cpl）。仅使用后一个Rundll32命令就可以通过CPL API函数直接执行CPL文件，该命令可能会绕过control.exe的检测和/或执行过滤器。

### splunk规则

```yml
index=windows source=”WinEventLog:Microsoft-Windows-Sysmon/Operational” (EventCode=1 Image=”\\control.exe” CommandLine=”.cpl*”) OR (EventCode=1 Image=”\\rundll32.exe” CommandLine =”shell32.dll,Control_RunDLL” CommandLine=”.cpl”) OR (EventCode=1 Image=”\\rundll32.exe” CommandLine =”shell32.dll,ControlRunDLLAsUse” CommandLine=”.cpl”) OR (EventCode=1 Image=”\\rundll32.exe” CommandLine =”.cpl*”) OR (EventCode IN (12,13) TargetObject IN (“HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ControlPanel\\NameSpace*” , “HKCR\\CLSID*” , “HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\ControlPanel*” , “*Shellex\\PropertySheetHandlers”))
```

### 建议

暂无

## 参考推荐

MITRE-ATT&CK-T1218-002

<https://attack.mitre.org/techniques/T1218/002/>

跟着ATT&CK学安全之defense-evasion

<https://snappyjack.github.io/articles/2020-01/%E8%B7%9F%E7%9D%80ATT&CK%E5%AD%A6%E5%AE%89%E5%85%A8%E4%B9%8Bdefense-evasion>