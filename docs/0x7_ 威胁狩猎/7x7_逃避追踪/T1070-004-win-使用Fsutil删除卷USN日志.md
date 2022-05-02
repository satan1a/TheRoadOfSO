# T1070-004-win-使用Fsutil删除卷USN日志

## 来自ATT&CK的描述

攻击者可能会删除其入侵活动所留下的文件。攻击者在系统上丢弃创建的恶意软件、工具或其他可能会留下痕迹的非本机文件。这些文件的删除可以在入侵过程中进行，也可以作为入侵后的过程中进行，以最大程度地减少攻击者留下的足迹。

主机操作系统中提供了一些工具来执行清除，但攻击者也可以使用其他工具。其中包括本机cmd函数（例如DEL），安全删除工具（例如Windows Sysinternals SDelete）或其他第三方文件删除工具。

## 测试案例

识别使用fsutil.exe删除USN JRNL卷。攻击者使用此技术来消除利用漏洞后创建的文件的活动证据。

更多姿势可参考：[渗透技巧——Windows下NTFS文件的USN Journal](http://app.myzaker.com/news/article.php?pk=5c6e106577ac642d40290442)

## 检测日志

windows security

windows sysmon

## 测试复现

```yml
关闭NTFS日志功能：

在cmd中运行 fsutil:

fsutil usn createjournal m=1000 a=100 c:  //创建日志

fsutil usn deletejournal /d c:  //删除日志
```

## 测试留痕

暂无，仅提供4688进程创建事件样例。

windows server 2016/win10

```yml
A new process has been created.

Subject:

   Security ID:  WIN-R9H529RIO4Y\Administrator
   Account Name:  Administrator
   Account Domain:  WIN-R9H529RIO4Y
   Logon ID:  0x1fd23

Process Information:

   New Process ID:  0xed0
   New Process Name: C:\Windows\System32\notepad.exe
   Token Elevation Type: TokenElevationTypeDefault (1)
   Mandatory Label: Mandatory Label\Medium Mandatory Level
   Creator Process ID: 0x8c0
   Creator Process Name: c:\windows\system32\explorer.exe
   Process Command Line: C:\Windows\System32\notepad.exe c:\sys\junk.txt
```

## 检测规则/思路

### Sigma

```yml
title: 使用Fsutil删除卷USN日志
description: 识别使用fsutil.exe删除USN JRNL卷。攻击者使用此技术来消除利用漏洞后创建的文件的活动证据。
status: experimental
references:
    - https://www.elastic.co/guide/en/siem/guide/current/delete-volume-usn-journal-with-fsutil.html#delete-volume-usn-journal-with-fsutil
logsource:
​    product: windows
​    service: security
detection:
​    selection:
​       EventID:
​            - 1 #sysmon
​            - 4688 #Windows 安全日志
        New Process Name: 'fsutil.exe' #Application Name
        Commanline: 'usn deletejournal'
​    condition: selection
level: low
```

### Elastic rule query

```yml
event.action:"Process Create (rule: ProcessCreate)" and
process.name:fsutil.exe and process.args:(deletejournal and usn)
```

### 建议

如果你对windows有足够多的了解，那么相信你也知道应该如何去用Windows日志进行分析此类攻击行为，比如依靠4688中的进程和命令行参数进行检测分析。

## 参考推荐

MITRE-ATT&CK-T1070-004

<https://attack.mitre.org/techniques/T1070/004/>

渗透技巧——Windows下NTFS文件的USN Journal

<http://app.myzaker.com/news/article.php?pk=5c6e106577ac642d40290442>

使用Fsutil删除卷USN日志 Elastic rule query

<https://www.elastic.co/guide/en/siem/guide/current/delete-volume-usn-journal-with-fsutil.html#delete-volume-usn-journal-with-fsutil>

4688事件样例

<https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688>
