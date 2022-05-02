# T1169-linux-Sudo

## 来自ATT&CK的描述

sudoers文件`/etc/sudoers`描述了哪些用户可以运行哪些命令以及从哪些终端运行。这还描述了用户可以作为其他用户或组运行的命令。这提供了最小特权的概念，使得用户在大多数时间以最低可能的权限运行，并且仅在需要时提升到其他用户或权限，通常通过提示输入密码。但是，sudoers文件还可以指定何时不提示用户输入类似`user1 ALL=(ALL) NOPASSWD: ALL` [[1\]](https://blog.malwarebytes.com/threat-analysis/2017/04/new-osx-dok-malware-intercepts-web-traffic/)的行的密码。

攻击者可以利用这些配置来执行其他用户的命令或生成具有更高权限的进程。您必须具有提升权限才能编辑此文件。

## 测试案例

 cat /etc/sudoers

 vim /etc/sudoers

值得注意的是：攻击者可以利用这些配置来执行其他用户的命令或生成具有更高权限的进程。您必须具有提升权限才能编辑此文件。

## 检测日志

linux audit日志 （值得注意的是：Ubuntu默认情况下没有audit，需要下载安装并配置相关策略）

## 测试复现

### 场景一

```bash
icbc@icbc:/$ sudo cat /etc/sudoers
```

### 场景二

```bash
icbc@icbc:/$ sudo vim /etc/sudoers
```

## 测试留痕

```bash
type=USER_CMD msg=audit(1563520773.609:436): pid=3530 uid=1000 auid=1000 ses=3 msg='cwd="/" cmd=636174202F6574632F7375646F657273 terminal=pts/0 res=success'
```

值得注意的是：这里只提取出了异常日志，故省略了很多日志细节。

## 检测规则/规则

### splunk规则

```yml
index=linux sourcetype="linux_audit" sudoers_110
```

值得注意的是：你需要自行配置Audit审核规则：root@icbc:~# auditctl -w /etc/sudoers -p war -k sudoers_110

### 建议

暂无

## 参考推荐

MITRE-ATT&CK-T1548-003

<https://attack.mitre.org/techniques/T1548/003/>

Audit配置手册

<https://www.cnblogs.com/bldly1989/p/7204358.html>
