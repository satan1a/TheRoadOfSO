# T1562-001-windows-停止Windows防御服务

## 来自ATT&CK的描述

攻击者可能试图阻止由监测软件或进程捕获到的告警，以及事件日志被收集和分析。这可能包括修改配置文件或注册表项中的监测软件的设置，以达到逃避追踪的目的。

间谍软件和恶意软件仍然是一个严重的问题，微软开发了安全服务即Windows Defender和Windows防火墙，协助用户对抗这种威胁。如果关闭Windows Defender或Windows防火墙，应当引起管理员的注意，立即恢复windows Defender或windows防火墙，使其处于正常工作状态，调查并确定异常情况是否由用户正常操作引起的。

## 测试案例

windows 7

DOS命令关闭windows防火墙：netsh advfilewall set publicprofile state off

## 检测日志

windows system

## 测试复现

windows关闭防火墙的方法有很多，但事件ID只有一个。

- net start mpssvc
- netsh advfilewall set publicprofile state off

## 测试留痕

windows system事件ID7036

## 检测规则/思路

### sigma规则

```yml
title: 停止Windows防御服务
description: win7 模拟测试结果
status: experimental
author: 12306Bro
logsource:
​    product: windows
​    service: system
detection:
​    selection:
​        EventID: 7036
​        Message: 'Windows Firewall 服务处于 停止 状态。'
​    condition: selection
level: medium
```

### 建议

暂无

## 参考推荐

MITRE-ATT&CK-T1562-001

<https://attack.mitre.org/techniques/T1562/001/>
