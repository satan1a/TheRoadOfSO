# 论文日读：From TTP to IoC- Advanced Persistent Graphs for Threat Hunting



## 概要

论文：Berady, Aimad, Mathieu Jaume, Valerie Viet Triem Tong and Gilles Guette. From TTP to IoC: Advanced Persistent Graphs for Threat Hunting. *IEEE Transactions on Network and Service Management* 18, 2 (6/2021): 1321–33. https://doi.org/10.1109/TNSM.2021.3056999.

该论文主要是围绕威胁狩猎的事件响应阶段提出一个高级持久图模型，用以评估和改进检测策略、提取可用的威胁情报（IOCs）。如题所示，即使用图模型将TTP型情报转化为IOC型情报，本质上是利用图模型挖掘攻击实体关系，将高维度数据进行降维的一个过程。同时，论文使用APT29的攻击行为来验证和评估模型。

主要的研究步骤是：

-   在全知视角下，对比攻击者和防御者的感知差距
-   对比攻击者意识到的，留在网络上的痕迹

-   防御者通过识别误报、调整检测策略来提升识别质量

使用APT29的真实攻击活动进行验证的过程：

-   模拟攻击：模型APT29的TTPs，测试防御架构质量
-   分析日志：通过分析误报和告警，调整检测策略
-   提取IOC：提取可用的CTI，主要为IOC类型

该论文认为威胁狩猎是一个敏捷迭代的过程，使用该套高级持久图模型可以快速从模拟攻击行为的高维度TTP中，提取可落地检测的IOC型情报。



## 笔记

![image-20211110112136692](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/image-20211110112136692.png)

图：模型结构展示



![image-20211110113338617](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/image-20211110113338617.png)

图：通过APT模拟攻击行为所得的图**G**𝐴

