# T1123-win-使用AudioDeviceCmdlets音频收集

## 来自ATT&CK的描述

攻击者可以利用计算机的外围设备（例如，麦克风和网络摄像头）或应用程序（例如，语音和视频呼叫服务）来捕获音频记录，以便侦听敏感的对话用以收集信息。

恶意软件或脚本可能用于通过操作系统或应用程序提供的可用API与设备进行交互以捕获音频。音频文件可能会写入磁盘并在以后被泄漏。

## 测试案例

### 测试1 using device audio capture commandlet
[AudioDeviceCmdlets](https://github.com/frgnca/AudioDeviceCmdlets)

```
powershell.exe -Command WindowsAudioDevice-Powershell-Cmdlet
```

## 检测日志

无

## 测试复现

```
PS C:\> Install-Module -Name AudioDeviceCmdlets
PS C:\> Get-AudioDevice  -list
```

虚拟机环境，未获取到音频相关信息
## 测试留痕

暂无

## 检测规则/思路

### 建议

由于可能使用各种API，对这种技术的检测是很困难。关于API使用的遥测数据可能没有太大作用，这取决于系统的正常使用方式，但可能为系统上发生的其他潜在的恶意活动提供支持。

可能表明技术使用的行为包括一个未知或不寻常的进程访问与设备或软件相关的API，这些设备或软件与麦克风、录音设备或录音软件互动，以及一个进程定期向磁盘写入包含音频数据的文件。

## 参考推荐

MITRE-ATT&CK-T1123

<https://attack.mitre.org/techniques/T1123/>

Atomic-red-team-T1123

<https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1123/T1123.md>


AudioDeviceCmdlets

<https://github.com/frgnca/AudioDeviceCmdlets>
