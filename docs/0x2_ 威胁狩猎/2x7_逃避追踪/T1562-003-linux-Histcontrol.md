# T1562-003-linux-Histcontrol

## 来自ATT&CK的描述

在HISTCONTROL环境变量决定了是否保存history命令，并最终进入~/.bash_history用户登录时出的文件。可以将此设置配置为忽略以空格开头的命令，只需将其设置为“ignorespace”即可。HISTCONTROL也可以设置为忽略重复命令，其使用方法是将其设置为“ignoredups”。在某些Linux系统中，默认设置为“ignoreboth”，它涵盖了前面的两个示例。这意味着“ls”将不会被保存，但“ls”将被历史保存。HISTCONTROL默认情况下在macOS上不存在，但可以由用户设置并且将受到保护。攻击者可以通过简单的在其所有终端命令之前添加空格来使用它进行操作操作而不留下痕迹。

## 测试案例

export HISTCONTROL=ignoreboth

## 检测日志

bash历史记录

## 测试复现

```bash
icbc@icbc:/$ ls

icbc@icbc:/$ history
    1  ls

icbc@icbc:/$ export HISTCONTROL=ignoreboth
icbc@icbc:/$  ls
```
## 测试留痕

```bash
icbc@icbc:/$ history
    1  ls
    2  export HISTCONTROL=ignoreboth
    3  history
```

## 检测规则/思路

### splunk规则

index=linux sourcetype="bash_history" export HISTCONTROL | table host, user_name, bash_command

### 建议

暂无

## 参考推荐

MITRE-ATT&CK-T1562-003

<https://attack.mitre.org/techniques/T1562/003/>

linux history命令详解

<https://www.cnblogs.com/keithtt/p/7040549.html>
