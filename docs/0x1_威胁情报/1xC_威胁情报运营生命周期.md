# 威胁情报运营生命周期

![](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/20200814121735.png)

https://zhuanlan.zhihu.com/p/38532724



## 一个中心

## 五个环节

### Collection

情报收集

-   按照情报计划，收集我们需要情报数据和原始数据

### Pre-Processing & Utilization

威胁情报预处理与利用环节

-   对原始情报信息进行预处理和应用场景分析，确定适用的范围和目标

### Analysis & Production

威胁情报分析与生产

-   按照情报计划，分析与处理之后的数据，生产最终的情报（也就是所谓的FINTEL）

### Transmission

情报输送

-   输送FINTEL至客户（也就是安全运营团队）并使用情报

在情报传输阶段，需要考虑的几个问题：

-   我需要输送何种类型的情报：YARA规则？MD5？IPtables规则？etc.？hotfix补丁？
-   我需要输送面向何种目标的情报：中间件？核心技术？etc.？
-   我需要收集目标的何种信息：中间件版本？操作系统版本？所用技术的名称和版本？
-   我需要用何种介质输送终端情报：Agent？规则列表？运维脚本？

### Planning & Direction

威胁情报的计划优化与修订

-   制定情报计划，确定我们需要交付何种类型的情报
-   情报有效期结束，重新制定或修正现有的情报计划，进入下一个循环



## 参考

-   https://zhuanlan.zhihu.com/p/129064940
-   https://zhuanlan.zhihu.com/p/38532724
-   https://zhuanlan.zhihu.com/binandhex



## References

\[1] https://zhuanlan.zhihu.com/p/38009342

\[2] 