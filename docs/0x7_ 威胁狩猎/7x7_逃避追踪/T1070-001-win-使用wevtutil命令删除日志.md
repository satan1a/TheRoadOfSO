# T1070-001-win-使用wevtutil命令删除日志

## 来自ATT&CK的描述

攻击者可能试图阻止由监测软件或进程捕获到的告警，以及事件日志被收集和分析。这可能包括修改配置文件或注册表项中的监测软件的设置，以达到逃避追踪的目的。

在基于特征监测的情况下，攻击者可以阻止监测特征相关的数据被发送出去，以便于阻止安全人员进行分析。这可以有很多方式实现，例如停止负责转发的进程（splunk转发器、Filebate、rsyslog等）。

在正常的操作期间内，事件日志不太可能会被刻意清除。但是恶意攻击者可能会通过清除事件日志来尝试掩盖自己的踪迹。当事件日志被清除时，它是可疑的。发现“清除事件日志”时可能意味着有恶意攻击者利用了此项技术。

集中收集事件日志的一个好处就是使攻击者更难以掩盖他们的踪迹，事件转发允许将收集到的系统事件日志发送给多个收集器（splunk、elk等），从而实现冗余事件收集。使用冗余事件收集，可以最大限度的帮助我们发现威胁。

## 测试案例

```yml
wevtutil.exe cl "ACEEventLog"
wevtutil.exe cl "Application"
wevtutil.exe cl "HardwareEvents"
wevtutil.exe cl "Internet Explorer"
wevtutil.exe cl "Key Management Service"
wevtutil.exe cl "Media Center"
wevtutil.exe cl "Microsoft-Windows-API-Tracing/Operational"
wevtutil.exe cl "Microsoft-Windows-AppID/Operational"
wevtutil.exe cl "Microsoft-Windows-Application-Experience/Problem-Steps-Recorder"
wevtutil.exe cl "Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant"
wevtutil.exe cl "Microsoft-Windows-Application-Experience/Program-Compatibility-Troubleshooter"
wevtutil.exe cl "Microsoft-Windows-Application-Experience/Program-Inventory"
wevtutil.exe cl "Microsoft-Windows-Application-Experience/Program-Telemetry"
wevtutil.exe cl "Microsoft-Windows-AppLocker/EXE and DLL"
wevtutil.exe cl "Microsoft-Windows-AppLocker/MSI and Script"
wevtutil.exe cl "Microsoft-Windows-Audio/CaptureMonitor"
wevtutil.exe cl "Microsoft-Windows-Audio/Operational"
wevtutil.exe cl "Microsoft-Windows-Authentication User Interface/Operational"
wevtutil.exe cl "Microsoft-Windows-Backup"
wevtutil.exe cl "Microsoft-Windows-BitLocker-DrivePreparationTool/Admin"
wevtutil.exe cl "Microsoft-Windows-BitLocker-DrivePreparationTool/Operational"
wevtutil.exe cl "Microsoft-Windows-Bits-Client/Operational"
wevtutil.exe cl "Microsoft-Windows-Bluetooth-MTPEnum/Operational"
wevtutil.exe cl "Microsoft-Windows-BranchCache/Operational"
wevtutil.exe cl "Microsoft-Windows-BranchCacheSMB/Operational"
wevtutil.exe cl "Microsoft-Windows-CodeIntegrity/Operational"
wevtutil.exe cl "Microsoft-Windows-CorruptedFileRecovery-Client/Operational"
wevtutil.exe cl "Microsoft-Windows-CorruptedFileRecovery-Server/Operational"
wevtutil.exe cl "Microsoft-Windows-DateTimeControlPanel/Operational"
wevtutil.exe cl "Microsoft-Windows-DeviceSync/Operational"
wevtutil.exe cl "Microsoft-Windows-Dhcp-Client/Admin"
wevtutil.exe cl "Microsoft-Windows-DhcpNap/Admin"
wevtutil.exe cl "Microsoft-Windows-Dhcpv6-Client/Admin"
wevtutil.exe cl "Microsoft-Windows-Diagnosis-DPS/Operational"
wevtutil.exe cl "Microsoft-Windows-Diagnosis-PCW/Operational"
wevtutil.exe cl "Microsoft-Windows-Diagnosis-PLA/Operational"
wevtutil.exe cl "Microsoft-Windows-Diagnosis-Scheduled/Operational"
wevtutil.exe cl "Microsoft-Windows-Diagnosis-Scripted/Admin"
wevtutil.exe cl "Microsoft-Windows-Diagnosis-Scripted/Operational"
wevtutil.exe cl "Microsoft-Windows-Diagnosis-ScriptedDiagnosticsProvider/Operational"
wevtutil.exe cl "Microsoft-Windows-Diagnostics-Networking/Operational"
wevtutil.exe cl "Microsoft-Windows-Diagnostics-Performance/Operational"
wevtutil.exe cl "Microsoft-Windows-DiskDiagnostic/Operational"
wevtutil.exe cl "Microsoft-Windows-DiskDiagnosticDataCollector/Operational"
wevtutil.exe cl "Microsoft-Windows-DiskDiagnosticResolver/Operational"
wevtutil.exe cl "Microsoft-Windows-DriverFrameworks-UserMode/Operational"
wevtutil.exe cl "Microsoft-Windows-EapHost/Operational"
wevtutil.exe cl "Microsoft-Windows-EventCollector/Operational"
wevtutil.exe cl "Microsoft-Windows-Fault-Tolerant-Heap/Operational"
wevtutil.exe cl "Microsoft-Windows-FMS/Operational"
wevtutil.exe cl "Microsoft-Windows-Folder Redirection/Operational"
wevtutil.exe cl "Microsoft-Windows-Forwarding/Operational"
wevtutil.exe cl "Microsoft-Windows-GroupPolicy/Operational"
wevtutil.exe cl "Microsoft-Windows-Help/Operational"
wevtutil.exe cl "Microsoft-Windows-HomeGroup Control Panel/Operational"
wevtutil.exe cl "Microsoft-Windows-HomeGroup Listener Service/Operational"
wevtutil.exe cl "Microsoft-Windows-HomeGroup Provider Service/Operational"
wevtutil.exe cl "Microsoft-Windows-IKE/Operational"
wevtutil.exe cl "Microsoft-Windows-International/Operational"
wevtutil.exe cl "Microsoft-Windows-International-RegionalOptionsControlPanel/Operational"
wevtutil.exe cl "Microsoft-Windows-Iphlpsvc/Operational"
wevtutil.exe cl "Microsoft-Windows-Kernel-EventTracing/Admin"
wevtutil.exe cl "Microsoft-Windows-Kernel-Power/Thermal-Operational"
wevtutil.exe cl "Microsoft-Windows-Kernel-StoreMgr/Operational"
wevtutil.exe cl "Microsoft-Windows-Kernel-WDI/Operational"
wevtutil.exe cl "Microsoft-Windows-Kernel-WHEA/Errors"
wevtutil.exe cl "Microsoft-Windows-Kernel-WHEA/Operational"
wevtutil.exe cl "Microsoft-Windows-Known Folders API Service"
wevtutil.exe cl "Microsoft-Windows-LanguagePackSetup/Operational"
wevtutil.exe cl "Microsoft-Windows-MCT/Operational"
wevtutil.exe cl "Microsoft-Windows-MemoryDiagnostics-Results/Debug"
wevtutil.exe cl "Microsoft-Windows-MUI/Admin"
wevtutil.exe cl "Microsoft-Windows-MUI/Operational"
wevtutil.exe cl "Microsoft-Windows-NCSI/Operational"
wevtutil.exe cl "Microsoft-Windows-NetworkAccessProtection/Operational"
wevtutil.exe cl "Microsoft-Windows-NetworkAccessProtection/WHC"
wevtutil.exe cl "Microsoft-Windows-NetworkLocationWizard/Operational"
wevtutil.exe cl "Microsoft-Windows-NetworkProfile/Operational"
wevtutil.exe cl "Microsoft-Windows-NlaSvc/Operational"
wevtutil.exe cl "Microsoft-Windows-NTLM/Operational"
wevtutil.exe cl "Microsoft-Windows-OfflineFiles/Operational"
wevtutil.exe cl "Microsoft-Windows-ParentalControls/Operational"
wevtutil.exe cl "Microsoft-Windows-PeopleNearMe/Operational"
wevtutil.exe cl "Microsoft-Windows-PowerShell/Operational"
wevtutil.exe cl "Microsoft-Windows-PrintService/Admin"
wevtutil.exe cl "Microsoft-Windows-ReadyBoost/Operational"
wevtutil.exe cl "Microsoft-Windows-ReadyBoostDriver/Operational"
wevtutil.exe cl "Microsoft-Windows-Recovery/Operational"
wevtutil.exe cl "Microsoft-Windows-ReliabilityAnalysisComponent/Operational"
wevtutil.exe cl "Microsoft-Windows-RemoteApp and Desktop Connections/Admin"
wevtutil.exe cl "Microsoft-Windows-RemoteAssistance/Admin"
wevtutil.exe cl "Microsoft-Windows-RemoteAssistance/Operational"
wevtutil.exe cl "Microsoft-Windows-Resource-Exhaustion-Detector/Operational"
wevtutil.exe cl "Microsoft-Windows-Resource-Exhaustion-Resolver/Operational"
wevtutil.exe cl "Microsoft-Windows-Resource-Leak-Diagnostic/Operational"
wevtutil.exe cl "Microsoft-Windows-RestartManager/Operational"
wevtutil.exe cl "Microsoft-Windows-Security-Audit-Configuration-Client/Operational"
wevtutil.exe cl "Microsoft-Windows-TerminalServices-LocalSessionManager/Admin"
wevtutil.exe cl "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
wevtutil.exe cl "Microsoft-Windows-TerminalServices-PnPDevices/Admin"
wevtutil.exe cl "Microsoft-Windows-TerminalServices-PnPDevices/Operational"
wevtutil.exe cl "Microsoft-Windows-TerminalServices-RDPClient/Operational"
wevtutil.exe cl "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin"
wevtutil.exe cl "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
wevtutil.exe cl "Microsoft-Windows-TZUtil/Operational"
wevtutil.exe cl "Microsoft-Windows-UAC/Operational"
wevtutil.exe cl "Microsoft-Windows-UAC-FileVirtualization/Operational"
wevtutil.exe cl "Microsoft-Windows-User Profile Service/Operational"
wevtutil.exe cl "Microsoft-Windows-VDRVROOT/Operational"
wevtutil.exe cl "Microsoft-Windows-VHDMP/Operational"
wevtutil.exe cl "Microsoft-Windows-WER-Diag/Operational"
wevtutil.exe cl "Microsoft-Windows-WFP/Operational"
wevtutil.exe cl "Microsoft-Windows-Windows Defender/Operational"
wevtutil.exe cl "Microsoft-Windows-Windows Defender/WHC"
wevtutil.exe cl "Microsoft-Windows-Windows Firewall With Advanced Security/ConnectionSecurity"
wevtutil.exe cl "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
wevtutil.exe cl "Microsoft-Windows-WindowsBackup/ActionCenter"
wevtutil.exe cl "Microsoft-Windows-WindowsSystemAssessmentTool/Operational"
wevtutil.exe cl "Microsoft-Windows-WindowsUpdateClient/Operational"
wevtutil.exe cl "Microsoft-Windows-Winlogon/Operational"
wevtutil.exe cl "Microsoft-Windows-WinRM/Operational"
wevtutil.exe cl "Microsoft-Windows-Winsock-WS2HELP/Operational"
wevtutil.exe cl "Microsoft-Windows-Wired-AutoConfig/Operational"
wevtutil.exe cl "Microsoft-Windows-WLAN-AutoConfig/Operational"
wevtutil.exe cl "Microsoft-Windows-WPD-ClassInstaller/Operational"
wevtutil.exe cl "Microsoft-Windows-WPD-CompositeClassDriver/Operational"
wevtutil.exe cl "Microsoft-Windows-WPD-MTPClassDriver/Operational"
wevtutil.exe cl "ODiag"
wevtutil.exe cl "OSession"
wevtutil.exe cl "Security"
wevtutil.exe cl "Setup"
wevtutil.exe cl "System"
wevtutil.exe cl "Windows PowerShell"
```

## 检测日志

windows sysmon

## 测试复现

```yml
C:\Windows\system32>wevtutil cl security
```

## 测试留痕

### sysmon_log

```yml
Process Create:
RuleName: -
UtcTime: 2020-11-29 13:15:07.077
ProcessGuid: {bb1f7c32-9edb-5fc3-8100-000000001900}
ProcessId: 1908
Image: C:\Windows\System32\wevtutil.exe
FileVersion: 6.1.7600.16385 (win7_rtm.090713-1255)
Description: Eventing Command Line Utility
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: wevtutil.exe
CommandLine: wevtutil  cl security
CurrentDirectory: C:\Windows\system32\
User: 12306Br0-PC\12306Br0
LogonGuid: {bb1f7c32-7b3c-5fc3-f960-060000000000}
LogonId: 0x660f9
TerminalSessionId: 1
IntegrityLevel: High
Hashes: SHA1=BDCF4B78B6D6F45EDC9D226CE05B7ADC3B366248
ParentProcessGuid: {bb1f7c32-7b69-5fc3-5000-000000001900}
ParentProcessId: 3328
ParentImage: C:\Windows\System32\cmd.exe
ParentCommandLine: "C:\Windows\System32\cmd.exe" 
```

### windows_security_log

```yml
已创建新进程。

使用者:
 安全 ID:  12306Br0-PC\12306Br0
 帐户名称:  12306Br0
 帐户域:  12306Br0-PC
 登录 ID:  0x660f9

进程信息:
 新进程 ID:  0x774
 新进程名称: C:\Windows\System32\wevtutil.exe
 令牌提升类型: TokenElevationTypeFull (2)
 创建者进程 ID: 0xd00
 进程命令行:   #未开启记录命令行参数审核，所以此处为空
```

## 检测规则/思路

### sigma

```yml
title: windows 日志清除
description: win7模拟测试结果
status: experimental
author: 12306Bro
logsource:
​    product: windows
​    service: security
detection:
​    selection1:
​        EventID:
​                - 1 #sysmon
​                - 4688 #Windows 安全日志
        Process.name: 'wevtutil.exe' #Application Name
        Commanline: 'cl'
    selection2:
        Process.name: 'powershell.exe' #Application Name
        Commanline: 'Clear-EventLog'
​condition: selection1 OR selection2
level: medium
```

### 建议

如果你想基于windows日志进行检测，那么你需要留意在产生了1102（日志清除）后，wevtutil进程（4688/4689）的调用情况。至少，它在我的测试环境中是这么展示的。

## 参考推荐

MITRE-ATT&CK-T1070-001

<https://attack.mitre.org/techniques/T1070/001/>

powershell:Clear-EventLog

<https://blog.csdn.net/weixin_30800807/article/details/97087311>
