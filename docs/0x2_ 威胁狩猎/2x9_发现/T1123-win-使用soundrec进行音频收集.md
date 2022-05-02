# T1123-win-使用soundrec音频收集

## 来自ATT&CK的描述

攻击者可以利用计算机的外围设备（例如，麦克风和网络摄像头）或应用程序（例如，语音和视频呼叫服务）来捕获音频记录，以便侦听敏感的对话用以收集信息。

恶意软件或脚本可能用于通过操作系统或应用程序提供的可用API与设备进行交互以捕获音频。音频文件可能会写入磁盘并在以后被泄漏。

## 测试案例

soundrec可以通过开发板采集声音，并通过电脑端显示波形，适用于 5402 dsp开发板。

## 检测日志

Windows安全日志、sysmon日志

## 测试复现

暂无

## 测试留痕

暂无

## 检测规则/思路

### splunk规则

由于可能会使用各种AP​​I，因此很难检测到此技术。取决于正常使用系统的方式，有关API使用的遥测数据可能没有用，但可以为发生在系统上的其他潜在恶意活动提供上下文。

可能指示技术使用的行为包括未知或异常的进程访问与与麦克风，录音设备或录音软件交互的设备或软件相关联的API，以及周期性地将包含音频数据的文件写入磁盘的进程。

```yml
“index=windows SourceName=””Microsoft-Windows-PowerShell”” “”*WindowsAudioDevice-Powershell-Cmdlet*”” //use voice cmdlet in powershell  index=windows source=””WinEventLog:Microsoft-Windows-Sysmon/Operational”” (EventCode=1 Image=””*\\explorer.exe”” CommandLine=””*WindowsSoundRecorder*””) OR (EventCode=1 Image=””*\\soundrec.exe””) // soundrecorder started with this command:explorer.exe shell:appsFolder\Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe!App

index=windows source=””WinEventLog:Microsoft-Windows-Sysmon/Operational”” (EventCode=1 CommandLine=””*/DURATION*””) OR (EventCode=1 CommandLine=””*/FILE*””) // check all commandlines that used /DURATION and /FILE as a output file in it”
```

### 建议

如果你对windows以及powershell比较了解的话，你可以使用Windows日志来完成监视检测，当然最好的方法是使用Sysmon日志。


## 相关TIP
[[T1123-win-使用AudioDeviceCmdlets进行音频收集]]


## 参考推荐

MITRE-ATT&CK-T1123

<https://attack.mitre.org/techniques/T1123/>
