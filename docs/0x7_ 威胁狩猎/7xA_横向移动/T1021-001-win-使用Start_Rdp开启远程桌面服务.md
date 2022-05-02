# T1021-001-win-使用Start_Rdp开启远程桌面服务

## 来自ATT&CK的描述

攻击者可以利用有效帐户使用远程桌面协议 (RDP) 登录计算机。然后攻击者可以作为登录用户执行操作。

远程桌面是操作系统中的常见功能。它允许用户使用远程系统上的系统桌面图形用户界面登录到交互式会话。Microsoft 将其远程桌面协议 (RDP) 的实现称为远程桌面服务 (RDS)。

如果启用该服务并允许访问具有已知凭据的帐户，攻击者可能会通过RDP/RDS连接到远程系统以扩展访问权限。攻击者可能会使用凭据访问技术来获取与RDP一起使用的凭据。攻击者还可以利用RDP做持久化操作。

## 测试案例

参考下文中提到的Start_Rdp.exe程序开启RDP服务。

<https://github.com/Ryze-T/Windows_API_Tools>

作用：开启rdp服务

用法： Start_Rdp.exe

## 检测日志

 windows sysmon

## 测试复现

测试环境说明：Windows server 2012

```shell
C:\Windows_API_Tools-main>Start_Rdp.exe
success
```

## 测试留痕

windows sysmon

事件ID：1，进程创建。进程创建事件提供有关新创建进程的扩展信息。完整的命令行提供了有关进程执行的上下文。ProcessGUID字段是整个域中此过程的唯一值，以简化事件关联。哈希是文件的完整哈希，其中包含HashType字段中的算法。

```log
Process Create:
RuleName: technique_id=T1059,technique_name=Command-Line Interface
UtcTime: 2022-03-24 08:11:46.909
ProcessGuid: {4a363fee-27c2-623c-decd-3f0000000000}
ProcessId: 2796
Image: C:\Windows_API_Tools-main\Start_Rdp.exe
FileVersion: -
Description: -
Product: -
Company: -
OriginalFileName: -
CommandLine: Start_Rdp.exe
CurrentDirectory: C:\Windows_API_Tools-main\
User: WEIDONG\Administrator
LogonGuid: {4a363fee-2447-623c-df16-080000000000}
LogonId: 0x816DF
TerminalSessionId: 1
IntegrityLevel: High
Hashes: SHA1=9805144590D86D7BF4D6D01BB368047BC94EF174,MD5=14148598AD98D05A820462F0BBD07B9F,SHA256=98579200636025AA468A3EEC8B217273630FD4658F6ABDBB035C8A094650311A,IMPHASH=60A0824F60935C033352E518E6CDA834
ParentProcessGuid: {4a363fee-246e-623c-4a6d-0f0000000000}
ParentProcessId: 3472
ParentImage: C:\Windows\System32\cmd.exe
ParentCommandLine: "C:\Windows\System32\cmd.exe" 
ParentUser: WEIDONG\Administrator
```

事件ID：13，值集。此注册表事件类型标识注册表值修改。该事件记录为DWORD和QWORD类型的注册表值写入的值。

```log
Registry value set:
RuleName: technique_id=T1112,technique_name=Modify Registry
EventType: SetValue
UtcTime: 2022-03-24 08:11:46.909
ProcessGuid: {4a363fee-27c2-623c-decd-3f0000000000}
ProcessId: 2796
Image: C:\Windows_API_Tools-main\Start_Rdp.exe
TargetObject: HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections
Details: DWORD (0x00000000)
User: WEIDONG\Administrator
```

## 检测规则/思路

### Sigma

```yml
title: 检测Start_Rdp开启windows远程桌面连接
tags: T1021_001
status: experimental
references:
    - https://github.com/Ryze-T/Windows_API_Tools
logsource:
    product: windows
    service: Sysmon
detection:
    selection:
          EventID: 13
          TargetObject: HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections
          Details: DWORD (0x00000000)
    condition: selection
level: medium
```

## 相关TIP
[[T1021-002-win-管理员共享]]
[[T1021-002-win-基于PsExec执行payload(白名单)]]
[[T1021-006-win-远程powershell会话]]

## 参考推荐

MITRE-ATT&CK-T1021-001

<https://attack.mitre.org/techniques/T1021/001/>

系统监视器(Sysmon)工具的使用

<https://blog.csdn.net/ducc20180301/article/details/119350200>

Windows_API_Tools

<https://github.com/Ryze-T/Windows_API_Tools>
