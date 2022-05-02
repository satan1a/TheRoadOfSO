# T1059-windows-进程生成CMD

## 来自ATT&CK的描述

命令行界面提供了一种与计算机系统交互的方式，并且是许多类型的操作系统平台的常见功能。windows系统上的一个示例命令行界面是[cmd](https://attack.mitre.org/software/S0106)，它可用于执行许多任务，包括执行其他软件。可以通过远程桌面应用程序本地或远程交互，反向shell会话等方式运行命令行界面。执行的命令以命令行界面进程的当前权限级别运行，除非该命令包含更改权限上下文的进程调用执行（例如[计划任务](https://attack.mitre.org/techniques/T1053)）。

攻击者可以使用命令行界面与系统交互并在操作过程中执行其他软件。

## 测试案例

Windows [命令提示符](https://en.wikipedia.org/wiki/cmd.exe)（`cmd.exe`）是一个为Windows操作系统提供命令行界面的实用程序。它提供了运行其他程序的能力，也有几个内置命令，例如`dir`，`copy`，`mkdir`，和`type`，以及批处理脚本（`.bat`）。通常，当用户运行命令提示符时，父进程`explorer.exe`或该提示的另一个实例。可能存在自动程序，登录脚本或管理工具，用于启动命令提示符的实例以运行脚本或其他内置命令。产生这个过程`cmd.exe`来自某些父母可能更能说明恶意。例如，如果Adobe Reader或Outlook启动命令shell，则可能表示已加载恶意文档并应进行调查。因此，通过寻找异常的父进程`cmd.exe`，可以检测攻击者。

## 检测日志

windows 安全日志

## 测试复现

Windows 7

在命令提示符或powershell中，运行cmd.exe

## 测试留痕

如果你熟悉windows事件ID或者经常留意你的windows日志的话，你可以很清晰的看到，每个一个进程的创建，系统都会进行记录产生一个事件。比如windows的进程创建事件ID为4688，进程关闭事件ID为4689.当然在win7中，你还可以看到详细的进程路径，但是，你没有办法看到父进程是什么？所以你可能需要sysmon。在最新版本的windows操作系统中（win10）事件ID4688是记录了父进程与子进程的，这有助于更好的进行威胁狩猎。

## 检测规则/思路

### elk规则

```elk
process = search Process:Create
cmd = filter process where (exe == "cmd.exe")
output cmd
```

### 建议

暂无

## 参考推荐

MITRE-ATT&CK-T1059

<https://attack.mitre.org/techniques/T1059/>

windows重点监控事件ID表

<https://www.96007.club/2019/08/21/21/>
