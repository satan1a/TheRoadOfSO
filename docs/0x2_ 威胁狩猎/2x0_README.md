# 威胁狩猎章节概要

## 概述

**致谢：该部分威胁狩猎的文章，是在[12306Bro](https://github.com/12306Bro/Threathunting-book/commits?author=12306Bro)师傅的[Threathunting-book](https://github.com/12306Bro/Threathunting-book)项目基础上进行完善，感谢原作者们的努力！**

本章节将整理威胁狩猎（Threat Hunting）的相关内容，原先该内容与`0x1_威胁情报`是一起的，但由于更多的学习，发现威胁情报和威胁狩猎本身说的是事件响应（Incident Response）的两种方案。威胁情报是更多是基于攻击的假设，而威胁狩猎更多是基于失陷的假设。换一种角度来说，就是威胁情报是偏向于“检测”，而威胁狩猎是偏向于“响应”。

简单来说，威胁情报目的是为了知道“我们这里啥情况”，手段之一是要知道“你们那里啥情况”；而威胁狩猎是为了知道“你们那里啥情况”，手段之一是要知道“我们这里啥情况”。

再说到推进落地方的问题，部分认为威胁情报是数据驱动的，部分认为是case驱动（攻击者模型驱动，依赖于专家经验），其实这两种说法都没错，都说得通。目前从落地上来看，case驱动具有操作性，而且未来也不会完全被取代，但是数据驱动的观念，全自动化的方向也是搞工程化建设的人所向往的银弹。数据+专家经验，是未来安全的一个大方向。纠结于口号对不对，不如做点实际的工作去看看哪个更有意思。

## 威胁狩猎

### 数据源

本项目中涉及到的日志主要为Windows安全日志、Windows powershell日志、Windows sysmon日志、linux audit日志、Http_log以及其他日志(中间件日志，iis等)。其中需要值得注意的是相关日志需要开启相关审核策略或进行相关配置后，方可使用。

### 数据采集

数据采集部分可采用各类日志转发组件，如nxlog、rsyslog、winlogbeat、splunk日志转发器等。可根据自身需求及实际情况出发，选择适合自己的日志采集方法。

### 规则说明

Web_Attck检测规则为Suricata、Sigma两种格式，端点检测规则为Sigma格式。

### 相关项目

-   [attack.mitre](https://attack.mitre.org/)
-   [sigma](https://github.com/Neo23x0/sigma) (by Neo23x0)
-   [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) (by Red Canary)
-   [Atomic Blue Detections](https://eqllib.readthedocs.io/en/latest/atomicblue.html)
-   [Detecting ATT&CK techniques & tactics for Linux](https://github.com/Kirtar22/Litmus_Test) (by Kirtar22)
-   [RedTeam-Tactics-and-Techniques](https://github.com/mantvydasb/RedTeam-Tactics-and-Techniques) (by Mantvydas)
-   [Microsoft-365-Defender-Hunting-Queries](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries) (Microsoft Threat Protection team)
-   [Security-Datasets](https://github.com/OTRF/Security-Datasets/)
-   [elastic_detection-rules](https://github.com/elastic/detection-rules/tree/main/rules)
