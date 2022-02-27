# 威胁情报库建设

持续性建设模式成为了现在企业安全的一个大方向，其中情报常常成为安全建设的中心。本篇内容总总结威胁情报库建设相关内容。

让我们先来回顾一下威胁情报的定义：

> SANS：针对安全威胁、威胁者、利用、恶意软件、漏洞和危害指标、所收集的用于评估的应用**数据集**。

威胁情报的本职是一个数据集，针对数据集我们不免会发问：如何获取、如何分析、如何存储、如何共享、如何应用

建设威胁情报库主要就是要解决其中：如何生产、如何存储、如何共享的问题，如果用威胁情报的生命周期来定义，我们所需要解决的步骤有：制定情报计划，情报收集，威胁情报预处理与利用环节，威胁情报分析与生产，情报输送，威胁情报的计划优化与修订。



## MISP部署与使用

### 项目介绍

MISP(Malware Information Sharing Platform)是一个很好用的开源威胁情报源采集、存储、分发平台，为开源项目。支持的部署方式多，且与OpenCTI、TheHive等项目均有集成插件。

项目地址：https://github.com/MISP/MISP

项目文档：https://www.circl.lu/doc/misp/

### 项目部署



### 情报源整合



### 集成ES

使用filebeat的MISP模块进行情报拉取和ES导入，编写filebeat管道文件：

```yaml
filebeat.config.modules:
  enabled: true
  path: /modules.d/*.yml

filebeat.modules:
- module: misp
  threat:
    enabled: true
    # API key to access MISP
    var.api_key: ""

    # Array object in MISP response
    var.json_objects_array: "response.Attribute"

    # URL of the MISP REST API
    var.url: "https://misp/attributes/restSearch/last:15m"
    var.http_client_timeout: 60s
    var.interval: 15m
    var.ssl: |-
      {
        verification_mode: none
      }
output.elasticsearch:
  hosts: ["elasticdfir01:9200"]

setup.kibana:
  host: "kibana:5601"
```















## 其他方案

![](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/20200821122607.png)

图：威胁情报上下游对接[1]

![image.png](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/15760797325090.png!small)

图：现有威胁情报库层级[1]



## 现有产品

### 开源

-   [ThreatMiner](https://www.threatminer.org/)是一个威胁情报门户，旨在使威胁情报分析师能够在快速发现威胁情报。[2]





## References

\[1] 威胁情报的私有化生产和级联：威胁狩猎及情报共享, [狴犴安全团队 ], (https://www.freebuf.com/author/狴犴安全团队) https://www.freebuf.com/articles/es/222359.html

\[2] 威胁情报平台分享, [我不是大神](https://www.zhihu.com/people/asmrshe-qu), https://zhuanlan.zhihu.com/p/101978718