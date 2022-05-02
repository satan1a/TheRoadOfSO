# T1119-win-Seatbelt自动收集信息

## 来自ATT&CK的描述

一旦在系统或网络中建立立足点，攻击者就可以使用自动化技术来收集内部信息。执行此技术的方法可以包括使用命令和脚本解释器来搜索和复制适合标准的信息（指符合攻击者收集的数据），例如在特定时间间隔的文件类型，位置或名称。此功能也可以内置到远程访问工具中。

该技术可以结合使用其他技术，例如文件和目录发现以及横向工具传输，以识别和移动文件。

## 测试案例

Seatbelt是一个C＃项目，可以用来对主机进行安全检查，在进攻和防御的角度都能发挥作用。

通过一条命令，就能够获得当前主机的多项配置信息，方便实用。

在实际渗透测试环境中可以利用Seatbelt工具做一些自动化的信息收集，收集的信息很多，包括不限于google历史记录、用户等等。当有了chrome的访问历史时，就可以知道该用户访问的一些内部站点的域名/IP，可以提高内网资产的摸索效率。

## 检测日志

Windows安全日志、sysmon日志

## 测试复现

Seatbelt的编译和使用

1.编译

工程地址：

<https://github.com/GhostPack/Seatbelt>

支持.NET 3.5和4.0

需要使用Visual Studio2017或者更高的版本进行编译。

2.使用

需要传入参数指定具体的命令，例如运行所有检查并返回所有输出：

Seatbelt.exe -group=all -full

详细的命令可参考项目的说明：

<https://github.com/GhostPack/Seatbelt#command-line-usage>

## 测试留痕

数据集来源：<https://github.com/OTRF/Security-Datasets/blob/master/datasets/atomic/windows/discovery/host/cmd_seatbelt_group_user.zip>


```yml
{ [-]
   @timestamp: 2020-11-02T04:39:11.671Z
   Channel: Security
   CommandLine: Seatbelt.exe  -group=user
   EventID: 4688
   Hostname: WORKSTATION5
   Keywords: 0x8020000000000000
   Level: 0
   MandatoryLabel: S-1-16-12288
   Message: A new process has been created.

Creator Subject:
 Security ID:  S-1-5-21-3940915590-64593676-1414006259-500
 Account Name:  wardog
 Account Domain:  WORKSTATION5
 Logon ID:  0xC61D9

Target Subject:
 Security ID:  S-1-0-0
 Account Name:  -
 Account Domain:  -
 Logon ID:  0x0

Process Information:
 New Process ID:  0x2f04
 New Process Name: C:\Users\wardog\Desktop\Seatbelt.exe
 Token Elevation Type: %%1936
 Mandatory Label:  S-1-16-12288
 Creator Process ID: 0x3048
 Creator Process Name: C:\Windows\System32\cmd.exe
 Process Command Line: Seatbelt.exe  -group=user
   NewProcessId: 0x2f04
   NewProcessName: C:\Users\wardog\Desktop\Seatbelt.exe
   ParentProcessName: C:\Windows\System32\cmd.exe
   ProcessId: 0x3048
   ProviderGuid: {54849625-5478-4994-a5ba-3e3b0328c30d}
   SourceName: Microsoft-Windows-Security-Auditing
   SubjectDomainName: WORKSTATION5
   SubjectLogonId: 0xc61d9
   SubjectUserName: wardog
   SubjectUserSid: S-1-5-21-3940915590-64593676-1414006259-500
   TargetDomainName: -
   TargetLogonId: 0x0
   TargetUserName: -
   TargetUserSid: S-1-0-0
   Task: 13312
   TimeCreated: 2020-11-02T04:39:11.671Z
   TokenElevationType: %%1936
}

新的事件 4663产生
{ [-]
   @timestamp: 2020-11-02T04:39:11.847Z
   AccessList: %%4432
    
   AccessMask: 0x1
   Channel: Security
   EventID: 4663
   HandleId: 0x2b4
   Hostname: WORKSTATION5
   Keywords: 0x8020000000000000
   Level: 0
   Message: An attempt was made to access an object.

Subject:
 Security ID:  S-1-5-21-3940915590-64593676-1414006259-500
 Account Name:  wardog
 Account Domain:  WORKSTATION5
 Logon ID:  0xC61D9

Object:
 Object Server:  Security
 Object Type:  Key
 Object Name:  \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe
 Handle ID:  0x2b4
 Resource Attributes: -

Process Information:
 Process ID:  0x2f04
 Process Name:  C:\Users\wardog\Desktop\Seatbelt.exe

Access Request Information:
 Accesses:  Query key value
    
 Access Mask:  0x1
   ObjectName: \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe
   ObjectServer: Security
   ObjectType: Key
   ProcessId: 0x2f04
   ProcessName: C:\Users\wardog\Desktop\Seatbelt.exe
   ProviderGuid: {54849625-5478-4994-a5ba-3e3b0328c30d}
   ResourceAttributes: -
   SourceName: Microsoft-Windows-Security-Auditing
   SubjectDomainName: WORKSTATION5
   SubjectLogonId: 0xc61d9
   SubjectUserName: wardog
   SubjectUserSid: S-1-5-21-3940915590-64593676-1414006259-500
   Task: 12801
   TimeCreated: 2020-11-02T04:39:11.847Z
}
```

## 检测规则/思路

无论是Windows安全日志还是sysmon日志我们都能够看到Seatbelt+参数执行的特征，windows 4688(sysmon 1)。

推荐最简单的检测方法即为进程命令行参数监控，其次可以通过调用.net、chrome等行为进行监控。

### 建议

以上检测方法未经实际测试，谨慎使用。

## 参考推荐

MITRE-ATT&CK-T1119

<https://attack.mitre.org/techniques/T1119/>

工程地址：

<https://github.com/GhostPack/Seatbelt>

内存加载Seatbelt的实现

<https://anquan.baidu.com/article/1153>
