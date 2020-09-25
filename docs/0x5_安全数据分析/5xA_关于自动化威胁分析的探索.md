# 关于自动化威胁分析的探索

~~开个新坑，慢慢填😂~~

自动化的威胁分析，主要关注的点在于“威胁”。我们回顾一下概念：

-   Vulnerability
    -   本质上讲就是一类 "error"
-   Threat
    -   本质上讲就是一种 "event"
-   Exploit
    -   本质上讲是关于攻击的一种 "behavior" 或者说 "way"
-   Risk
    -   本质上讲，是描述一种 "situation"

从这些概念中可以知道，我们要进行自动化的威胁分析，就是要对威胁，这个"event"进行分析。那对”事件“进行分析，产出就不能是0或1 的向量形式，而是要以一种"knowledge"的方式描述。再说得实际点，我们不仅需要知道某个点是否有问题，还需要知道 who what  when where how。

因此难度上来讲，还是比较高的。所以我们实际进行落地时，确实可以先进行特征判断，再进行模型检查，最后进行自动化分析。本篇主要是根据这个思路来进行整理。



## 计算引擎

### AIEngine

https://bitbucket.org/camp0/aiengine/src/master/