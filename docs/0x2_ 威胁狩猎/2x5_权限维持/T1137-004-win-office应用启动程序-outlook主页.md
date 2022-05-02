# T1137-004-win-office应用启动程序-outlook主页

## 来自ATT&CK的描述

攻击者可能会滥用 Microsoft Outlook 的主页功能来获得被攻击的系统的持久性。Outlook 主页是一项旧功能，用于自定义 Outlook 文件夹的呈现方式。此功能允许在打开文件夹时加载和显示内部或外部 URL。可以制作恶意 HTML 页面，在 Outlook 主页加载时执行代码。

一旦恶意主页被添加到用户的邮箱中，它们将在Outlook启动时被加载。恶意主页将在正确的Outlook文件夹被加载或重新加载时执行。

## 测试案例

### 测试1 Install Outlook Home Page Persistence

该测试模拟通过Outlook主页功能被添加恶意代码，达到持久化的目的。这导致Outlook在每次查看目标文件夹时检索包含恶意有效载荷的URL。

触发有效载荷需要手动打开Outlook并查看目标文件夹（例如收件箱）。

使用Windows 命令行执行攻击命令：
```
reg.exe add HKCU\Software\Microsoft\Office\#{outlook_version}\Outlook\WebView\#{outlook_folder} /v URL /t REG_SZ /d #{url} /f
```
Url：file:atomic-red-team-master\atomics\T1137.004\src\T1137.004.html
outlook_version：16.0
outlook_folder：  Inbox #要修改主页设置的Outlook文件夹的名称
清理命令：
```
reg.exe delete HKCU\Software\Microsoft\Office\#{outlook_version}\Outlook\WebView\#{outlook_folder} /v URL /f >nul 2>&1
```
## 检测日志

Windows Sysmon日志

## 测试复现

### 测试1 Install Outlook Home Page Persistence
```
C:\Users\Administrator.ZHULI>reg.exe add HKCU\Software\Microsoft\Office\16.0\Outlook\WebView\Inbox /v URL /t REG_SZ /d C:\Users\Administrator.ZHULI\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1137.004\src\T1137.004.html /f
操作成功完成。

C:\Users\Administrator.ZHULI>reg.exe delete HKCU\Software\Microsoft\Office\#{outlook_version}\Outlook\WebView\#{outlook_folder} /v URL /f >nul 2>&1

```

## 测试留痕
### 测试1 Install Outlook Home Page Persistence
```
Sysmon 事件ID 1 进程创建      
Process Create:

RuleName: technique_id=T1112,technique_name=Modify Registry

UtcTime: 2022-01-11 06:54:50.664

ProcessGuid: {78c84c47-29ba-61dd-b821-000000000800}

ProcessId: 6040

Image: C:\Windows\System32\reg.exe

FileVersion: 10.0.17763.1 (WinBuild.160101.0800)

Description: Registry Console Tool

Product: Microsoft® Operating System

Company: Microsoft Corporation

OriginalFileName: reg.exe

CommandLine: reg.exe add HKCU\Software\Microsoft\Office\16.0\Outlook\WebView\Inbox /v URL /t REG_SZ /d C:\Users\Administrator.ZHULI\Desktop\TevoraAutomatedRTGui\atomic-red-team-master\atomics\T1137.004\src\T1137.004.html /f

CurrentDirectory: C:\Users\Administrator.ZHULI\

User: ZHULI\Administrator

LogonGuid: {78c84c47-f665-61db-95da-440100000000}

LogonId: 0x144DA95

TerminalSessionId: 3

IntegrityLevel: High

Hashes: SHA1=429DF8371B437209D79DC97978C33157D1A71C4B,MD5=8A93ACAC33151793F8D52000071C0B06,SHA256=19316D4266D0B776D9B2A05D5903D8CBC8F0EA1520E9C2A7E6D5960B6FA4DCAF,IMPHASH=BE482BE427FE212CFEF2CDA0E61F19AC

ParentProcessGuid: {78c84c47-2489-61dd-f120-000000000800}

ParentProcessId: 4392

ParentImage: C:\Windows\System32\cmd.exe

ParentCommandLine: "C:\Windows\system32\cmd.exe" 

ParentUser: ZHULI\Administrator
```


## 检测规则/思路

### Sigma规则

```yml
title: 滥用Outlook主页功能加载恶意代码
description: 滥用Outlook主页功能加载恶意代码，以达到持久化。
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1137.004/T1137.004.md
tags:
    - attack.t1137.004
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1 #进程创建
        CommandLine: HKCU\Software\Microsoft\Office\（outlook_version）\Outlook\WebView\(outlook_folder)
    condition: selection
level: high
```

### 建议
微软发布了一个 PowerShell 脚本，用于在您的邮件环境中安全地收集邮件转发规则和自定义表单，以及解释输出的步骤。该工具可用于检测和修复 Outlook 自定义表单注入攻的规则。

收集进程执行信息，包括进程 ID (PID) 和父进程 ID (PPID)，并查找 Office 进程导致的异常活动链。非标准流程执行树也可能表明存在可疑或恶意行为

## 参考推荐

MITRE-ATT&CK-T1137-004

<https://attack.mitre.org/techniques/T1137/004/>

Atomic-red-team-T1137.004

<https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1137.004/T1137.004.yaml>

检测和修复 Outlook 自定义表单注入攻击的规则

<https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-outlook-rules-forms-attack?view=o365-worldwide>

