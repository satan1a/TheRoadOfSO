# T1137-002-win-office应用启动程序-office test

## 来自ATT&CK的描述

攻击者可能会滥用微软Office的 "Office Test "注册表键，在被攻击的系统上获得持久性。存在一个Office测试注册表位置，允许用户指定一个任意的DLL，在每次启动Office应用程序时执行。这个注册表键被认为是微软在开发Office应用程序时用来加载DLLs以进行测试和调试的。在Office安装过程中，该注册表键并不是默认创建的。

存在用于Office测试功能的用户和全局注册表键。
```
HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf
HKEY_LOCAL_MACHINE\Software\MicrosoftOffice test\Special\Perf
```

攻击者可能会添加此注册表项并指定将在 Office 应用程序（如 Word 或 Excel）启动时执行的恶意 DLL。

## 测试案例

### 测试1 Office Application Startup Test Persistence

使用Windows 命令行执行攻击命令：
```
reg add "HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf" /t REG_SZ /d "#{thing_to_execute}"
```

thing_to_execute：恶意dll位置
清理命令：
```
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf" /f >nul 2>&1
```
## 检测日志

Windows 安全日志、Sysmon日志

## 测试复现

### 测试1 Office Application Startup Test Persistence
```
C:\Users\Administrator.ZHULI>reg add "HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf" /t REG_SZ /d "C:\Users\Administrator.ZHULI\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1137.002\test.dll"
操作成功完成。

C:\Users\Administrator.ZHULI>reg delete "HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf" /f >nul 2>&1
```

## 测试留痕
### 测试1 Office Application Startup Test Persistence
```
Sysmon 事件ID 1 进程创建      
Process Create:

RuleName: technique_id=T1112,technique_name=Modify Registry

UtcTime: 2022-01-11 06:27:59.157

ProcessGuid: {78c84c47-236f-61dd-cf20-000000000800}

ProcessId: 3312

Image: C:\Windows\System32\reg.exe

FileVersion: 10.0.17763.1 (WinBuild.160101.0800)

Description: Registry Console Tool

Product: Microsoft® Operating System

Company: Microsoft Corporation

OriginalFileName: reg.exe

CommandLine: reg add "HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf" /t REG_SZ /d "C:\Users\Administrator.ZHULI\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1137.002\test.dll"

CurrentDirectory: C:\Users\Administrator.ZHULI\

User: ZHULI\Administrator

LogonGuid: {78c84c47-f665-61db-95da-440100000000}

LogonId: 0x144DA95

TerminalSessionId: 3

IntegrityLevel: High

Hashes: SHA1=429DF8371B437209D79DC97978C33157D1A71C4B,MD5=8A93ACAC33151793F8D52000071C0B06,SHA256=19316D4266D0B776D9B2A05D5903D8CBC8F0EA1520E9C2A7E6D5960B6FA4DCAF,IMPHASH=BE482BE427FE212CFEF2CDA0E61F19AC

ParentProcessGuid: {78c84c47-22c4-61dd-b020-000000000800}

ParentProcessId: 6312

ParentImage: C:\Windows\System32\cmd.exe

ParentCommandLine: "C:\Windows\system32\cmd.exe" 

ParentUser: ZHULI\Administrator
```

```
Sysmon 事件ID 13      
Registry value set:

RuleName: -

EventType: SetValue

UtcTime: 2022-01-11 06:27:59.168

ProcessGuid: {78c84c47-236f-61dd-cf20-000000000800}

ProcessId: 3312

Image: C:\Windows\system32\reg.exe

TargetObject: HKU\S-1-5-21-2729552704-1545692732-1695105048-500\Software\Microsoft\Office test\Special\Perf\(Default)

Details: C:\Users\Administrator.ZHULI\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1137.002\test.dll

User: ZHULI\Administrator
```

## 检测规则/思路

### Sigma规则

```yml
title: office test加载恶意dll
status: 稳定
description: 利用office应用启动程序office test加载恶意dll，以达到持久化。
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1137.002/T1137.002.yaml
tags:
    - attack.t1137.002
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
		TargetObject：' HKU\*\Software\Microsoft\Office test\Special\Perf'
    condition: selection
level: high
```

### 建议
监控Office测试注册表键的创建。许多与office有关的持久性机制需要修改注册表，并需要将二进制文件、脚本写入磁盘或修改现有文件包括恶意脚本。收集与注册表键的创建和修改有关的事件，这些键可用于基于office的持久性。

考虑监控Office进程中的异常DLL加载。

## 相关TIP
[[T1137-004-win-office应用启动程序-outlook主页]]

## 参考推荐

MITRE-ATT&CK-T1137-002

<https://attack.mitre.org/techniques/T1137/002/>

Atomic-red-team-T1137.002

<https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1137.002/T1137.002.yaml>

