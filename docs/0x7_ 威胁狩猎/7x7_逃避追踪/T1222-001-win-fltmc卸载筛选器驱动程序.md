# T1222-001-win-fltmc卸载筛选器驱动程序

## 来自ATT&CK的描述

文件和目录权限通常由文件或目录所有者指定的任意访问控制列表（DACL）管理。文件和目录DACL的实现因平台而异，但通常会明确指定它们，以便用户/组可以执行操作，例如读取，写入，执行等。

攻击者可以修改文件或目录的权限或属性，以逃避预期的DACL。修改可能包括更改特定的访问权限，这可能需要获取文件或目录的所有权或提升的权限（例如Administrator/root），具体取决于文件或目录的现有权限以启用恶意活动，例如修改，替换或删除特定文件目录。特定文件和目录修改可能是许多技术所必需的步骤，例如，通过可访问性功能，登录脚本建立持久性，或污染、劫持其他工具二进制配置文件。

## 测试案例

Fltmc.exe命令

Fltmc.exe程序是系统提供的用于常见微筛选器驱动程序管理操作的命令行实用程序。 开发人员可以使用Fltmc.exe来加载和卸载微筛选器驱动程序、附加或分离微筛选器驱动程序和枚举微筛选器驱动程序、实例和卷。在具有管理员权限的命令提示符下，键入fltmc help以查看完整的命令列表。

```yml
C:\Users\Administrator>FLTMC HELP
有效命令:
    load        加载筛选器驱动程序
    unload      卸载筛选器驱动程序
    filters     列出系统中当前注册的筛选器
    instances   列出系统中当前注册的筛选器或卷的实例
    volumes     列出系统中所有卷/RDR
    attach      为卷创建筛选器实例
    detach      从卷删除筛选器实例

    使用 fltmc help [ 命令 ] 获取特定命令的帮助
```

## 检测日志

windows security

windows sysmon

## 测试复现

```yml
C:\Users\Administrator>FLTMC UNLOAD SYSMON

卸载失败，出现错误: 0x801f0013
系统无法找到指定的筛选器。
```

## 测试留痕

```yml
事件 Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" />
    <EventID>4688</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>13312</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2021-08-08T11:52:03.429773000Z" />
    <EventRecordID>248258</EventRecordID>
    <Correlation />
    <Execution ProcessID="4" ThreadID="280" />
    <Channel>Security</Channel>
    <Computer>WIN-1CIA2BP8VBJ.qax.com</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-1180088053-4000917822-266516913-500</Data>
    <Data Name="SubjectUserName">Administrator</Data>
    <Data Name="SubjectDomainName">QAX</Data>
    <Data Name="SubjectLogonId">0x187cd2</Data>
    <Data Name="NewProcessId">0x14dc</Data>
    <Data Name="NewProcessName">C:\Windows\System32\fltMC.exe</Data>
    <Data Name="TokenElevationType">%%1936</Data>
    <Data Name="ProcessId">0x151c</Data>
    <Data Name="CommandLine">FLTMC  UNLOAD SYSMON</Data>
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

### splunk规则

```yml
index=client (EventCode=1 OR EventCode=4688) CommandLine="*unload*" (Image="C:\\Windows\\SysWOW64\\fltMC.exe" OR Image="C:\\Windows\\System32\\fltMC.exe") 
```

### 建议

如果你对windows有足够多的了解，那么相信你也知道应该如何去用Windows日志进行分析此类攻击行为，比如依靠4688中的进程和命令行参数进行检测分析。

## 参考推荐

MITRE-ATT&CK-T1222-001

<https://attack.mitre.org/techniques/T1222/001/>

Fltmc.exe命令

<https://docs.microsoft.com/zh-cn/windows-hardware/drivers/ifs/development-and-testing-tools>
