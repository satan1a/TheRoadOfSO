# 论文日读：Last Line of Defense: Reliability Through Inducing Cyber Threat Hunting With Deception in SCADA Networks


## 概要

-   Offensive Security: Towards Proactive Threat Hunting via Adversary Emulation
-   Last Line of Defense: Reliability Through Inducing Cyber Threat Hunting With Deception
     in SCADA Networks


Abdul Basit Ajmal等人的两篇论文，主题是对“威胁狩猎”和“攻击仿真”的应用实践。第一篇主要介绍提出一种新型的混合模型，通过发起模拟攻击进行威胁狩猎来验证威胁假设（hypotheses）、帮助理解攻击模式。第二篇主要实践了威胁狩猎和网络欺骗、杀伤链相结合来检测SCADA系统（监控和数据采集）中的威胁，并且提出了一种关注于未知威胁、在SCADA网络中的威胁检测和预防方法。



## 笔记

### 威胁狩猎与攻击仿真

以下是论文中给出的一个对手仿真方法和威胁狩猎模型。第一阶段，是通过对全网威胁情报的感知，提取其中的TTPs，通过对手仿真方法组合攻击技术，实施具体的攻击。第二阶段，基于攻击仿真获取的数据进行威胁狩猎。威胁狩猎的过程主要为：（感知攻击，根据已有能力获取检测的数据）——建立失陷假设——验证假设——证明假设——成功狩猎，告知组织相关TTPs。

<img src="https://image-host-toky.oss-cn-shanghai.aliyuncs.com/image-20211108113017420.png" alt="image-20211108113017420" style="zoom: 67%;" />

图：威胁狩猎和攻击仿真的模型

<img src="https://image-host-toky.oss-cn-shanghai.aliyuncs.com/image-20211108114238568.png" alt="image-20211108114238568" style="zoom:67%;" />

图：威胁狩猎与攻击仿真的流程图

<img src="https://image-host-toky.oss-cn-shanghai.aliyuncs.com/image-20211108114402177.png" alt="image-20211108114402177"  />

图：简化版狩猎模型



![image-20211108115612144](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/image-20211108115612144.png)

图：威胁狩猎过程



### 诱捕农场

论文中另外给出一个重要框架是一个基于SCADA网络环境下的诱捕农场（Decoy Farm）系统。该系统主要是集合安全检测和容器技术构建出一套在SCADA网络下的攻击仿真系统（蜜罐+检测）。

![image-20211108115212555](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/image-20211108115212555.png)

图：SCADA系统诱捕农场





## 概念补充

### SCADA

>   SCADA 系统是由不同组件组成的网络，负责关键工业过程的可靠和准确工作。 SCADA 系统收集和组织来自不同执行器的数据以进行实时监控。 SCADA 由 PLC（可编程逻辑控制器）、HMI（人机交互）、MTU（主终端单元）、Historian 和 RTU（远程终端单元）等组件组成。他们结合并构建了一个完整的网络。

简单来说就是在工业控制领域的一个监控和数据采集方案。以下是SCADA系统的一个网络结构图：

<img src="https://image-host-toky.oss-cn-shanghai.aliyuncs.com/image-20211108115025930.png" alt="image-20211108115025930" style="zoom: 67%;" />

图：SCADA系统的网络结构
