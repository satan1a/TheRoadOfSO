# T1190-检测SQL server滥用

## 来自ATT&CK的描述

使用软件，数据或命令来利用面向Internet的计算机系统或程序中的弱点，从而导致意外或无法预期的行为。系统的弱点可能是错误、故障或设计漏洞。这些应用程序通常是网站，但是可以包括数据库（例如SQL），标准服务（例如SMB 或SSH）以及具有Internet可访问开放的任何其他应用程序，例如Web服务器和相关服务。根据所利用的缺陷，这可能包括“利用防御防卫”。

如果应用程序托管在基于云的基础架构上，则对其进行利用可能会导致基础实际应用受到损害。这可以使攻击者获得访问云API或利用弱身份和访问管理策略的路径。

对于网站和数据库，OWASP排名前10位和CWE排名前25位突出了最常见的基于Web的漏洞。

## 测试案例

SQLServer提供了大量用于自动化任务、导出数据和运行脚本的工具。攻击者可以重新利用这些合法工具。由于攻击者可能会利用许多强大的命令进行攻击，因此查找涉及SQL Server的恶意活动可能会很复杂。

此查询检测SQL Server进程启动shell以运行一个或多个可疑命令的实例。

## 检测日志

未经测试，初步判断为windows安全日志或者Sysmon日志

## 测试复现

参考 如何通过SQL Server执行系统命令？

<https://zhuanlan.zhihu.com/p/25254794>

## 测试留痕

暂无实测，故无留痕

## 检测规则/思路

```yml
DeviceProcessEvents 
| where Timestamp  >= ago(10d)
| where InitiatingProcessFileName in~ ("sqlservr.exe", "sqlagent.exe",  "sqlps.exe", "launchpad.exe") //当初始化进程为"sqlservr.exe", "sqlagent.exe",  "sqlps.exe", "launchpad.exe"
| summarize tostring(makeset(ProcessCommandLine))  //进程命令行中包含以下进程名称OR命令行参数时，可能是异常的。
by DeviceId, bin(Timestamp, 2m)
| where
set_ProcessCommandLine has "certutil" or 
set_ProcessCommandLine has "netstat" or 
set_ProcessCommandLine has "ping" or 
set_ProcessCommandLine has "sysinfo" or 
set_ProcessCommandLine has "systeminfo" or 
set_ProcessCommandLine has "taskkill" or 
set_ProcessCommandLine has "wget" or 
set_ProcessCommandLine has "whoami" or 
set_ProcessCommandLine has "Invoke-WebRequest" or 
set_ProcessCommandLine has "Copy-Item" or 
set_ProcessCommandLine has "WebClient" or 
set_ProcessCommandLine has "advpack.dll" or 
set_ProcessCommandLine has "appvlp.exe" or 
set_ProcessCommandLine has "atbroker.exe" or 
set_ProcessCommandLine has "bash.exe" or 
set_ProcessCommandLine has "bginfo.exe" or 
set_ProcessCommandLine has "bitsadmin.exe" or 
set_ProcessCommandLine has "cdb.exe" or 
set_ProcessCommandLine has "certutil.exe" or 
set_ProcessCommandLine has "cl_invocation.ps1" or 
set_ProcessCommandLine has "cl_mutexverifiers.ps1" or 
set_ProcessCommandLine has "cmstp.exe" or 
set_ProcessCommandLine has "csi.exe" or 
set_ProcessCommandLine has "diskshadow.exe" or 
set_ProcessCommandLine has "dnscmd.exe" or 
set_ProcessCommandLine has "dnx.exe" or 
set_ProcessCommandLine has "dxcap.exe" or 
set_ProcessCommandLine has "esentutl.exe" or 
set_ProcessCommandLine has "expand.exe" or 
set_ProcessCommandLine has "extexport.exe" or 
set_ProcessCommandLine has "extrac32.exe" or 
set_ProcessCommandLine has "findstr.exe" or 
set_ProcessCommandLine has "forfiles.exe" or 
set_ProcessCommandLine has "ftp.exe" or 
set_ProcessCommandLine has "gpscript.exe" or 
set_ProcessCommandLine has "hh.exe" or 
set_ProcessCommandLine has "ie4uinit.exe" or 
set_ProcessCommandLine has "ieadvpack.dll" or 
set_ProcessCommandLine has "ieaframe.dll" or 
set_ProcessCommandLine has "ieexec.exe" or 
set_ProcessCommandLine has "infdefaultinstall.exe" or 
set_ProcessCommandLine has "installutil.exe" or 
set_ProcessCommandLine has "makecab.exe" or 
set_ProcessCommandLine has "manage-bde.wsf" or 
set_ProcessCommandLine has "mavinject.exe" or 
set_ProcessCommandLine has "mftrace.exe" or 
set_ProcessCommandLine has "microsoft.workflow.compiler.exe" or 
set_ProcessCommandLine has "mmc.exe" or 
set_ProcessCommandLine has "msbuild.exe" or 
set_ProcessCommandLine has "msconfig.exe" or 
set_ProcessCommandLine has "msdeploy.exe" or 
set_ProcessCommandLine has "msdt.exe" or 
set_ProcessCommandLine has "mshta.exe" or 
set_ProcessCommandLine has "mshtml.dll" or 
set_ProcessCommandLine has "msiexec.exe" or 
set_ProcessCommandLine has "msxsl.exe" or 
set_ProcessCommandLine has "odbcconf.exe" or 
set_ProcessCommandLine has "pcalua.exe" or 
set_ProcessCommandLine has "pcwrun.exe" or 
set_ProcessCommandLine has "pcwutl.dll" or 
set_ProcessCommandLine has "pester.bat" or 
set_ProcessCommandLine has "presentationhost.exe" or 
set_ProcessCommandLine has "pubprn.vbs" or 
set_ProcessCommandLine has "rcsi.exe" or 
set_ProcessCommandLine has "regasm.exe" or 
set_ProcessCommandLine has "register-cimprovider.exe" or 
set_ProcessCommandLine has "regsvcs.exe" or 
set_ProcessCommandLine has "regsvr32.exe" or 
set_ProcessCommandLine has "replace.exe" or 
set_ProcessCommandLine has "rundll32.exe" or 
set_ProcessCommandLine has "runonce.exe" or 
set_ProcessCommandLine has "runscripthelper.exe" or 
set_ProcessCommandLine has "schtasks.exe" or 
set_ProcessCommandLine has "scriptrunner.exe" or 
set_ProcessCommandLine has "setupapi.dll" or 
set_ProcessCommandLine has "shdocvw.dll" or 
set_ProcessCommandLine has "shell32.dll" or 
set_ProcessCommandLine has "slmgr.vbs" or 
set_ProcessCommandLine has "sqltoolsps.exe" or 
set_ProcessCommandLine has "syncappvpublishingserver.exe" or 
set_ProcessCommandLine has "syncappvpublishingserver.vbs" or 
set_ProcessCommandLine has "syssetup.dll" or 
set_ProcessCommandLine has "te.exe" or 
set_ProcessCommandLine has "tracker.exe" or 
set_ProcessCommandLine has "url.dll" or 
set_ProcessCommandLine has "verclsid.exe" or 
set_ProcessCommandLine has "vsjitdebugger.exe" or 
set_ProcessCommandLine has "wab.exe" or 
set_ProcessCommandLine has "winrm.vbs" or 
set_ProcessCommandLine has "wmic.exe" or 
set_ProcessCommandLine has "xwizard.exe" or 
set_ProcessCommandLine has "zipfldr.dll"
| sort by DeviceId  , Timestamp asc
```

解释：当初始化进程为"sqlservr.exe"，"sqlagent.exe"，"sqlps.exe"，"launchpad.exe"，进程命令行中包含以上进程名称OR命令行参数时，可能是异常的。

## 建议

未经实际测试，仅具备一定的参考价值。

## 参考推荐

MITRE-ATT&CK-T1190

<https://attack.mitre.org/techniques/T1190/>
