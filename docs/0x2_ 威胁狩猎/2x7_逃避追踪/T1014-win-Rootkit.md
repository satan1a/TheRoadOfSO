# T1014-win-Rootkit

## 来自ATT&CK的描述

攻击者可能使用rootkits来隐藏程序、文件、网络连接、服务、驱动程序和其他系统组件的存在。Rootkits是通过拦截、钩住和修改提供系统信息的操作系统API调用来隐藏恶意软件的存在的程序。

Rootkits或启用Rootkit的功能可能存在于操作系统的用户或内核层面，或更低的层面，包括管理程序、主引导记录或系统固件。在Windows、Linux和Mac OS X系统中，已经出现了rootkits。

##  测试案例

Windows签名的驱动程序 Rootkit测试

该测试利用已签名的驱动程序在Kernel中执行代码。这个例子来自一个博客，它利用puppetstrings.exe和易受攻击的（已签名的驱动程序）capcom.sys。capcom.sys驱动可以在github上找到。一个很好的参考是在这里： http://www.fuzzysecurity.com/tutorials/28.html SHA1 C1D5CF8C43E7679B782630E93F5E6420CA1749A7 我们利用这里的工作： https://zerosum0x0.blogspot.com/2017/07/puppet-strings-dirty-secret-for-free.html 我们的PoC漏洞的哈希值是SHA1 DD8DA630C00953B6D5182AA66AF999B1E117F441 这将模拟隐藏一个进程。

攻击命令：
使用command_prompt运行! 需要提升权限（如root或admin）。
```
#{puppetstrings_path} #{driver_path}
```

driver_path：C:\Drivers\driver.sys
puppetstrings_path：PathToAtomicsFolder\T1014\bin\puppetstrings.exe

依赖性: 使用 powershell 运行!
说明：puppetstrings.exe必须存在于磁盘的指定位置（#{puppetstrings_path}）。
检查先决条件命令。
```
if (Test-Path #{puppetstrings_path}) {exit 0} else {exit 1}
```

获得先决条件的命令：
```
Invoke-WebRequest "https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1014/bin/puppetstrings.exe" -OutFile "#{puppetstrings_path}"
```

## 检测日志

暂无，经过本地复现，Windows安全日志、Powershell操作日志、Sysmon日志未记录到此命令的执行情况。

## 测试复现

### 测试1 Windows Signed Driver Rootkit Test

```
PS C:\Windows\system32> C:\Users\zhuli\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1014\bin\puppetstrings.exe C:\Drivers\driver.sys
Look for process in tasklist.exe
请按任意键继续. . .
puppetstrings failed - error: 00000003
请按任意键继续. . .
```

Windows Server 2019未能成功复现。

## 日志留痕

Windows Sysmon日志可记录此测试行为。

```
日志名称:          Microsoft-Windows-Sysmon/Operational
来源:            Microsoft-Windows-Sysmon
日期:            2022/1/10 14:58:52
事件 ID:         1
任务类别:          Process Create (rule: ProcessCreate)
级别:            信息
关键字:           
用户:            SYSTEM
计算机:           zhuli.qax.com
描述:
Process Create:
RuleName: technique_id=T1086,technique_name=PowerShell
UtcTime: 2022-01-10 06:58:52.494
ProcessGuid: {78c84c47-d92c-61db-450c-000000000800}
ProcessId: 7608
Image: C:\Users\zhuli\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1014\bin\puppetstrings.exe
FileVersion: -
Description: -
Product: -
Company: -
OriginalFileName: -
CommandLine: "C:\Users\zhuli\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1014\bin\puppetstrings.exe" C:\Drivers\driver.sys
CurrentDirectory: C:\Windows\system32\
User: QAX\Administrator
LogonGuid: {78c84c47-d270-61db-d56a-010100000000}
LogonId: 0x1016AD5
TerminalSessionId: 1
IntegrityLevel: High
Hashes: SHA1=DD8DA630C00953B6D5182AA66AF999B1E117F441,MD5=676ED2C5D31006FC4CBC1B0E0D564F4F,SHA256=1184228AC822F0F8C7C8242325052F91B500AD7C08E4A9B266211E8E623CAE8E,IMPHASH=1B1B5BBC1BB70593CD761304457481AC
ParentProcessGuid: {78c84c47-d270-61db-4a0b-000000000800}
ParentProcessId: 4560
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentCommandLine: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" 
ParentUser: QAX\Administrator
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
    <TimeCreated SystemTime="2022-01-10T06:58:52.495942600Z" />
    <EventRecordID>9861</EventRecordID>
    <Correlation />
    <Execution ProcessID="2764" ThreadID="3668" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>zhuli.qax.com</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="RuleName">technique_id=T1086,technique_name=PowerShell</Data>
    <Data Name="UtcTime">2022-01-10 06:58:52.494</Data>
    <Data Name="ProcessGuid">{78c84c47-d92c-61db-450c-000000000800}</Data>
    <Data Name="ProcessId">7608</Data>
    <Data Name="Image">C:\Users\zhuli\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1014\bin\puppetstrings.exe</Data>
    <Data Name="FileVersion">-</Data>
    <Data Name="Description">-</Data>
    <Data Name="Product">-</Data>
    <Data Name="Company">-</Data>
    <Data Name="OriginalFileName">-</Data>
    <Data Name="CommandLine">"C:\Users\zhuli\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1014\bin\puppetstrings.exe" C:\Drivers\driver.sys</Data>
    <Data Name="CurrentDirectory">C:\Windows\system32\</Data>
    <Data Name="User">QAX\Administrator</Data>
    <Data Name="LogonGuid">{78c84c47-d270-61db-d56a-010100000000}</Data>
    <Data Name="LogonId">0x1016ad5</Data>
    <Data Name="TerminalSessionId">1</Data>
    <Data Name="IntegrityLevel">High</Data>
    <Data Name="Hashes">SHA1=DD8DA630C00953B6D5182AA66AF999B1E117F441,MD5=676ED2C5D31006FC4CBC1B0E0D564F4F,SHA256=1184228AC822F0F8C7C8242325052F91B500AD7C08E4A9B266211E8E623CAE8E,IMPHASH=1B1B5BBC1BB70593CD761304457481AC</Data>
    <Data Name="ParentProcessGuid">{78c84c47-d270-61db-4a0b-000000000800}</Data>
    <Data Name="ParentProcessId">4560</Data>
    <Data Name="ParentImage">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="ParentCommandLine">"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" </Data>
    <Data Name="ParentUser">QAX\Administrator</Data>
  </EventData>
</Event>
```

## 检测规则/思路

### 建议

一些rootkit保护措施可能内置于反病毒或操作系统软件中。有一些专门的rootkit检测工具可以寻找特定类型的rootkit行为。监测是否存在未被识别的DLLs、设备、服务以及对MBR的改变。

## 参考推荐
MITRE-ATT&CK-T1014

<https://attack.mitre.org/techniques/T1014>

Atomic-red-team-T1014

<https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1014>
