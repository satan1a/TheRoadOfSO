# T1037-001-win-Boot或logon初始化脚本-登录脚本

## 来自ATT&CK描述

攻击者可以利用在登录初始化时自动执行的Windows登录脚本来建立持久性。Windows允许在特定用户或用户组登录系统时运行登录脚本。这可以通过在HKU\*\Environment\UserInitMprLogonScript注册表键中添加脚本路径来实现。

攻击者可以使用这些脚本来维持单一系统的持久性。根据登录脚本的访问配置，可能需要本地凭证或管理员账户。

## 测试案例

### 测试1 Logon Scripts

添加一个注册表值来运行在%temp%目录下创建的批处理脚本。执行后，在HKCU\Environment键中会有一个新的环境变量，可以在注册表编辑器中查看。

攻击命令，用命令提示符运行：
```
echo "#{script_command}" > #{script_path}
REG.exe ADD HKCU\Environment /v UserInitMprLogonScript /t REG_SZ /d "#{script_path}" /f
```

清理命令：
```
REG.exe DELETE HKCU\Environment /v UserInitMprLogonScript /f >nul 2>&1
del #{script_path} >nul 2>&1
del "%USERPROFILE%\desktop\T1037.001-log.txt" >nul 2>&1
```

## 检测日志

Windows Sysmon日志

## 测试复现
### 测试1 Logon Scripts
```
C:\Users\Administrator.ZHULI\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1037.001>echo Art "Logon Script" atomic test was successful. >> %USERPROFILE%\desktop\T1037.001-log.txt

C:\Users\Administrator.ZHULI\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1037.001>REG.exe ADD HKCU\Environment /v UserInitMprLogonScript /t REG_SZ /d "C:\Users\Administrator.ZHULI\Desktop\TevoraAutomatedRTGui\T1037.001-log.txt" /f
操作成功完成。
```


## 测试留痕
### 测试1 Logon Scripts
Windows sysmon日志
```事件ID:1
Process Create:

RuleName: technique_id=T1112,technique_name=Modify Registry

UtcTime: 2022-01-10 09:32:09.002

ProcessGuid: {78c84c47-fd19-61db-b511-000000000800}

ProcessId: 7112

Image: C:\Windows\System32\reg.exe

FileVersion: 10.0.17763.1 (WinBuild.160101.0800)

Description: Registry Console Tool

Product: Microsoft® Operating System

Company: Microsoft Corporation

OriginalFileName: reg.exe

CommandLine: REG.exe ADD HKCU\Environment /v UserInitMprLogonScript /t REG_SZ /d "C:\Users\Administrator.ZHULI\Desktop\TevoraAutomatedRTGui\T1037.001-log.txt" /f

CurrentDirectory: C:\Users\Administrator.ZHULI\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1037.001\

User: ZHULI\Administrator

LogonGuid: {78c84c47-f665-61db-95da-440100000000}

LogonId: 0x144DA95

TerminalSessionId: 3

IntegrityLevel: High

Hashes: SHA1=429DF8371B437209D79DC97978C33157D1A71C4B,MD5=8A93ACAC33151793F8D52000071C0B06,SHA256=19316D4266D0B776D9B2A05D5903D8CBC8F0EA1520E9C2A7E6D5960B6FA4DCAF,IMPHASH=BE482BE427FE212CFEF2CDA0E61F19AC

ParentProcessGuid: {78c84c47-fc8c-61db-9c11-000000000800}

ParentProcessId: 2512

ParentImage: C:\Windows\System32\cmd.exe

ParentCommandLine: "C:\Windows\System32\cmd.exe" 

ParentUser: ZHULI\Administrator

Sysmon事件ID:13
Registry value set:

RuleName: UACMe Dir Prep

EventType: SetValue

UtcTime: 2022-01-10 09:32:09.003

ProcessGuid: {78c84c47-fd19-61db-b511-000000000800}

ProcessId: 7112

Image: C:\Windows\system32\reg.exe

TargetObject: HKU\S-1-5-21-2729552704-1545692732-1695105048-500\Environment\UserInitMprLogonScript

Details: C:\Users\Administrator.ZHULI\Desktop\TevoraAutomatedRTGui\T1037.001-log.txt

User: ZHULI\Administrator
```

## 检测规则/思路

### sigma规则

```yml
title: window主机使用登录脚本进行持久化
description: 添加一个注册表值来运行在%temp%目录下创建的批处理脚本。执行后，在HKCU\Environment键中会有一个新的环境变量，可以在注册表编辑器中查看。
author: 12306Br0
date: 2021/01/10
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1037.001/T1037.001.md
tags:
    - attack.t1037-001
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        Image: '*\reg.exe'
		TargetObject: 'HKU\*\Environment\UserInitMprLogonScript'
    condition: selection
level: high
```


### 建议

监测与Windows登录脚本相关的注册表值的变化，特别是HKU\Environment\UserInitMprLogonScript。

监测运行中的进程，以发现可能表明登录时运行的异常程序或可执行文件的行为。

## 参考推荐

MITRE-ATT&CK-T1037-001

<https://attack.mitre.org/techniques/T1037/001>

Atomic-red-team-T1037-001

<https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1037.001/T1037.001.md>
