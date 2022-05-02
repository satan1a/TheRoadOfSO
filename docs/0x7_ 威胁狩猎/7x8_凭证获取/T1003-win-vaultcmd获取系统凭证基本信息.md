# T1003-win-vaultcmd获取系统凭据基本信息

## 来自ATT&CK的描述

凭据导出是从操作系统和软件获取账号登录名和密码（哈希或明文密码）信息的过程。然后可以使用凭据来执行横向移动并访问受限制的信息。

攻击者和专业安全测试人员都可能会使用此技术中提到的几种工具。也可能存在其他自定义工具。

## 测试案例

获得系统凭据的基本信息
工具1： vaultcmd(windows系统自带)

常用命令：
列出保管库(vault)列表：
vaultcmd /list
注：不同类型的凭据保存在不同的保管库(vault)下

列出保管库(vault)概要，凭据名称和GUID：
vaultcmd /listschema
注：GUID对应路径%localappdata%/Microsoft\Vault\{GUID}下的文件

列出名为”Web Credentials”的保管库(vault)下的所有凭据信息：
vaultcmd /listcreds:"Web Credentials"
注：如果是中文操作系统，可将名称替换为对应的GUID，命令如下

列出GUID为{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}的保管库(vault)下的所有凭据：
vaultcmd /listcreds:{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}

列出GUID为{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}的保管库(vault)的属性，包括文件位置、包含的凭据数量、保护方法：
vaultcmd /listproperties:{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}

## 检测日志

- windows 安全日志
- windows Sysmon日志

## 测试复现

自行测试即可，略简单

## 测试留痕

无

## 检测规则/思路

### sigma规则

```yml
title: win-vaultcmd获取系统凭据基本信息
description: windows server 2016
tags: T1003
status: experimental
author: 12306Bro
logsource:
    product: windows
    service: security/Sysmon
detection:
    selection:
        EventID:
           - 4688 #windows安全日志，已创建新的进程。
           - 1 #windows Sysmon日志，创建新的进程
        New processname: C:\Windows\System32\VaultCmd.exe #新进程名称/image
        Parent processname: C:\Windows\System32\cmd.exe #创建者进程名称/ParentImage
        Process commandline:
           - vaultcmd  /list  #列出保管库(vault)列表
           - vaultcmd  /listschema #列出保管库(vault)概要，凭据名称和GUID
           - vaultcmd  /listcreds:{*} #中文系统，列出GUID为{* }的保管库(vault)下的所有凭据
           - vaultcmd /listcreds:"*"  #英文系统 ，列出名为”*”的保管库(vault)下的所有凭据信息
           - vaultcmd  /listproperties:{*} #中文系统，列出GUID为{*}的保管库(vault)的属性，包括文件位置、包含的凭据数量、保护方法
    condition: selection
```

### 建议

注：可使用windows 安全日志4688，进程VaultCmd.exe进行检测分析；也可使用Sysmon进行行为记录，分析检测。

## 参考推荐

MITRE-ATT&CK-T1003

<https://attack.mitre.org/techniques/T1003/>

渗透技巧——Windows中Credential Manager的信息获取

<https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-Windows%E4%B8%ADCredential-Manager%E7%9A%84%E4%BF%A1%E6%81%AF%E8%8E%B7%E5%8F%96/>
