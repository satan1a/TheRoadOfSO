# T1552-003-linux-Bash历史记录

## 来自ATT&CK的描述

Bash使用“history”实用程序跟踪用户在命令行上键入的命令。用户注销后，会将历史记录刷新到用户的`.bash_history`文件中。对于每个用户，此文件位于同一位置：`~/.bash_history`。通常，此文件会跟踪用户的最近500个命令。用户通常在命令行上键入用户名和密码作为程序的参数，然后在注销时将其保存到此文件中。攻击者可以通过滥用此功能来查看文件来查看潜在凭据。

## 测试案例

cat #{bash历史命令名字} | grep #{bash历史命令关键词检索} > #{输出文件名}

sudo cat  ~/.bash_history | grep password > bash.txt

## 检测日志

linux audit日志 （值得注意的是：Ubuntu默认情况下没有audit，需要下载安装并配置相关策略）

bash历史记录

## 测试复现

icbc@icbc:/$ sudo cat ~/.bash_history | grep password > bash.txt

## 测试留痕

### audit日志

```bash
icbc@icbc:/$ sudo cat ~/.bash_history | grep password > bash.txt

type=PATH msg=audit(1563528127.048:1097): item=0 name="/usr/bin/cat" inode=2228383 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0
type=PATH msg=audit(1563528127.048:1097): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=2237074 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0
type=PROCTITLE msg=audit(1563528127.048:1097): proctitle=636174002F726F6F742F2E626173685F686973746F7279
type=SYSCALL msg=audit(1563528127.056:1099): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7ffd4ebbb73b a2=0 a3=0 items=1 ppid=5249 pid=5258 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="cat" exe="/usr/bin/cat" key="bash_history_110"
type=CWD msg=audit(1563528127.056:1099): cwd="/root"
```

值得注意的是：这里只提取出了异常日志，故省略了很多日志细节。

### bash历史记录

```bash
icbc@icbc:/$ history

1  sudo cat ~/.bash_history | grep password > bash.txt
```

## 检测规则/思路

### splunk规则

audit 日志

```yml
index=linux sourcetype="linux_audit" syscall=257 key=bash_history_110 | table host,auid,syscall,syscall_name,exe
```

值得注意的是：你需要自行配置Audit审核规则

```history
sudo auditctl -w ~/.bash_history -k bash_history_110
```

### splunk规则

bash 历史记录

```yml
index=linux sourcetype=bash_history cat bash_history | table _time,host,user_name,bash_command
```

### sigma规则

```yml
title: 攻击者读取linux下~/.bash_history文件，查看是否包含相关凭据密码
description: Ubuntu18.04
references: https://github.com/12306Bro/Threat-hunting/blob/master/T1139-linux-Bash历史记录.md
tags: T1552-003
status: experimental
author: 12306Bro
logsource:
​    product: linux
​    service: audit
detection:
​    keywords:
​       - syscall=257 key=bash_history_110
​    condition: keywords
----------------------------------------------------------------------------------------
logsource:
​    product: linux
​    service: history
detection:
​    selection:
​    keywords:
​       - cat bash_history
​    condition: keywords
level: medium
```

### 建议

暂无

## 参考推荐

MITRE-ATT&CK-T1552-003

<https://attack.mitre.org/techniques/T1552/003/>

Audit配置手册

<https://www.cnblogs.com/bldly1989/p/7204358.html>
