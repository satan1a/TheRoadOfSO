# 基于机器学习的恶意URL检测

## 目录

[TOC]



## 概述

本次实践虽题为”基于机器学习“，但目前也只更新到使用TF-IDF提取特征，使用逻辑回归和SVM模型的进度。不过千里之行始于足下嘛，后面再更啦🐦



## 提出问题

首先我们需要将安全问题进行抽象，也就是针对现状提出问题。在假定的这个业务背景下，我们发现：

-   恶意URL存在特定几种类型1

-   特定类型恶意URL在文本上存在普遍的**词汇特征**，例如钓鱼URL中常见"login", "account", "sigin"等关键词

因此我们尝试使用机器学习算法对恶意URL进行检测分析。



## 数据处理

### 样本选择

-   [malicious-URLs](https://github.com/faizann24/Using-machine-learning-to-detect-malicious-URLs)
    -   **malicious-URLs** 在Github上面一个 使用机器学习去检测恶意URL的项目 ，里面有一个训练集，有做标记是正常的URL还是恶意的URL
    -   内容类型：文本样本
    -   是否标记：是
    -   是否特征化：否
    -   使用范围：入侵检测、异常流量、WAF

### 数据清洗

由于样本本身为处理好的标记数据，所以在数据格式和脏数据上无需处理（真实情况下可能正好相反:-(）。

编写数据帧提取函数：

```python
def csv_data_read(csv_file_path):
    # 为减少训练时间，可只取头部10W条，但一定需要先打乱样本）
    # df_csv = pd.read_csv(csv_file_path).head(100000)
    df_csv = pd.read_csv(csv_file_path)
    urls = []
    labels = []
    for index, row in df_csv.iterrows():
        urls.append(row["url"])
        labels.append(row["label"])
    return urls, labels
```

编写对URL的数据清洗函数：
```python
def url_tokenize(url):
    """
    对URL进行清洗，删除斜线、点、和com，进行分词
    :param url:
    :return:
    """
    web_url = url.lower()
    dot_slash = []
    slash = str(web_url).split('/')
    for i in slash:
        r1 = str(i).split('-')
        token_slash = []
        for j in range(0,len(r1)):
            r2 = str(r1[j]).split('.')
            token_slash = token_slash + r2
        dot_slash = dot_slash + r1 + token_slash
    urltoken_list = list(set(dot_slash))
    white_words = ["com", "http:", "https:", ""]
    for white_word in white_words:
        if white_word in urltoken_list:
            urltoken_list.remove(white_word)
    return urltoken_list
```



## 特征提取

我们首先加载数据集：

```python
    grep_csv_file_path = "../../data/data-0x3/grey-url.csv"
    black_csv_file_path = "../../data/data-0x3/black-url.csv"
    grey_urls, y = csv_data_read(grep_csv_file_path)
```

我们使用TF-IDF算法提取URL的特征，并将数据帧划分为训练集和测试集：

```python
    url_vectorizer = TfidfVectorizer(tokenizer=url_tokenize)
    x = url_vectorizer.fit_transform(grey_urls)
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42)
```

### 注：TF-IDF

TF-IDF(Term Frequency – Inverse Document Frequency)，即词频-逆文档频率。在计算上为词频和逆文档频率的乘积。计算方法如下：

-   计算词频（TF）
    -   某个词在文章中出现的次数/文章的总词数
    -   即某个词在这段文字中出现得越多，TF就越大
-   计算逆文档频率（IDF）
    -   log(语料库的文档总数/包含该词的文档数+1)
    -   某个词在普遍情况下越常见，分母大，IDF也约趋于0
-   计算TF-IDF
    -   TF-IDF = TF * IDF
    -   TF-IDF越大，说明词在这段文章中越重要，但因为有IDF的存在，又能避免把“是”、”的“、“和”等停用词的TF-IDF值降低

在应用上：将文章分词，计算TF-IDF，按照其值大小降序排列，排名靠前的即文章的关键词



## 模型选择

接下来，我们对数据集使用**逻辑回归模型**，并将将拟合后的模型和向量保存为本地文件，便于重复使用

```python
    # 对训练集和测试集执行逻辑回归
    l_regress = LogisticRegression(solver='liblinear')
    l_regress.fit(x_train, y_train)
    l_score = l_regress.score(x_test, y_test)
    # print("测试拟合分数为：{0}".format(l_score))

    file_mode = "../../model/model-0x3/model.pkl"
    dump_model_object(file_mode)
    file_vector = "../../model/model-0x3/vector.pl"
    dump_model_object(file_vector)
```

此外，我们也可以使用支持向量机模型：

```python
def practice_svm(x_train, x_test, y_train, y_test):
    """
    实践SVM算法识别恶意URL
    :param x_train:
    :param x_test:
    :param y_train:
    :param y_test:
    :return:
    """
    model_svm = SVC()
    # 注意：SVM训练可能较慢，注意样本的数量
    model_svm.fit(x_train, y_train)
    svm_score = model_svm.score(x_test, y_test)
    print("测试拟合分数为：{0}".format(svm_score))
    model_svm_save = model_svm

    """
    保存训练好的模型和向量
    """
    file_mode = "../../model/model-0x3/model_svm.pkl"
    dump_model_object(file_mode, model_svm_save)
```





## 效果评估

在“特征提取”部分我们采用`train_test_split`方法进行随机划分训练集和测试集，进行**交叉验证**，再次回顾代码为：

```python
x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42)
```

使用线性回归模型，最后得到测试拟合分数为：**0.9599966703530615**

注，参数介绍：

-   `test_size`：测试集在总样本中的占比
-   `random_state`：随机数的种子，也可以理解为该组随机数的编号。规则是：种子不同时，产生不同的随机数；种子相同时，在不同实例下也产生相同的随机数。比如在上面的语句中，`test_size`为0.2，即选择总样本的20%作为测试集，但是如何选择呢？`random_state`就指定了：按照“第42种”规则选择这20%随机的数据。

使用支持向量机模型时，发现在数据量较大的情况下，该模型的运算速度较慢，因此在实验环境下不得已减少了训练样本的数量，但也导致了拟合分数的降低，所以就不展示在样本缩水情况下的测试拟合分数了。同时，也了解到这是传统二分类SVM在面对大数据量时的弊端，并且随着集成学习的成熟，SVM现在“普遍用于集成学习中基模型的构建”[2]，而不是作为唯一的分类模型使用。





## 完整代码

```python
"""
Author: Toky
Description: 基于机器学习的恶意URL检测
"""
import copy
import pickle

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression


def csv_data_read(csv_file_path):
    # 为减少训练时间，可只取头部10W条，但一定需要先打乱样本）
    # df_csv = pd.read_csv(csv_file_path).head(100000)
    df_csv = pd.read_csv(csv_file_path)
    urls = []
    labels = []
    for index, row in df_csv.iterrows():
        urls.append(row["url"])
        labels.append(row["label"])
    return urls, labels


def url_tokenize(url):
    """
    对URL进行清洗，删除斜线、点、和com，进行分词
    :param url:
    :return:
    """
    web_url = url.lower()
    dot_slash = []
    slash = str(web_url).split('/')
    for i in slash:
        r1 = str(i).split('-')
        token_slash = []
        for j in range(0,len(r1)):
            r2 = str(r1[j]).split('.')
            token_slash = token_slash + r2
        dot_slash = dot_slash + r1 + token_slash
    urltoken_list = list(set(dot_slash))
    white_words = ["com", "http:", "https:", ""]
    for white_word in white_words:
        if white_word in urltoken_list:
            urltoken_list.remove(white_word)
    return urltoken_list


def dump_model_object(file_path, model_object):
    """
    使用pickle将内存中的对象转换为文本流保存为本地文件
    :param file_path:
    :return:
    """
    with open(file_path, "wb") as f:
        pickle.dump(model_object, f)
    f.close()


if __name__ == '__main__':
    """
    加载数据集
    """
    grep_csv_file_path = "../../data/data-0x3/grey-url.csv"
    black_csv_file_path = "../../data/data-0x3/black-url.csv"
    grey_urls, y = csv_data_read(grep_csv_file_path)

    """
    使用TF-IDF算法提取关键词特征，并将数据帧划分为训练集和测试集
    """
    url_vectorizer = TfidfVectorizer(tokenizer=url_tokenize)
    url_vectorizer_save = copy.deepcopy(url_vectorizer)
    x = url_vectorizer.fit_transform(grey_urls)
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42)

    """
    对数据帧执行逻辑回归，将拟合后的模型和向量保存
    """
    # 对训练集和测试集执行逻辑回归
    l_regress = LogisticRegression(solver='liblinear')
    l_regress.fit(x_train, y_train)
    l_score = l_regress.score(x_test, y_test)
    print("测试拟合分数为：{0}".format(l_score))

    file_mode = "../../model/model-0x3/model.pkl"
    dump_model_object(file_mode, l_regress)
    file_vector = "../../model/model-0x3/vector.pl"
    dump_model_object(file_vector, url_vectorizer_save)
    
```



##  概念补充

### 逻辑回归

逻辑回归模型通过逻辑函数对数据进行**分类**，通常包括用于估计逻辑模型结果的独立二元变量。相比于线性回归，逻辑回归处理的分类问题，输出的结果为离散值；而线性回归解决的是回归问题输出的是连续值。

详细解读可以参考文章[1]，注意，虽然该算法在用起来时显得非常简单，但是其原理中的细节部分还是很多的，感兴趣可以仔细研究一下。



### 支持向量机（SVM）

支持向量机（Surport Vector Machine, SVM）同样用于分类，是一个二元分类算法，但修改后也支持多分类问题。支持向量机通过在高维空间中创建最佳超平面来实现，这个超平面创建的划分被称为类。

对于分类问题本质的理解，就是我们需要找到一个划分的超平面，让数据尽可能多地分布在这个平面的两侧，从而实现分类的效果。但在实际数据下，往往存在多个超平面，那么此时我们怎么取舍呢？就是比较容易分类错误的数据点，而这些点就是离平面很近的点，因为离平面很远的点是相差很大的，基本不会存在分类错误的情况。而SVM的核心思想就是如此，找到离平面很近的、容易分类错误的点，然后想办法让这些数据点离平面距离变远。那些离超平面很近的点也就被称为支持向量（Support Vector）。

详细的数学原理，可以参考文章[2]，该算法有比较完备的数学理论支撑的，但详细的数理和推倒也相对比较复杂，因此也可以看自己需要进行学习（~~其实就是我看不懂，不献丑来推导了~~）。





## Reference

\[1]【机器学习】逻辑回归（非常详细），[阿泽](https://www.zhihu.com/people/is-aze)，https://zhuanlan.zhihu.com/p/74874291

\[2] 05 SVM - 支持向量机 - 概念、线性可分，[白尔摩斯](https://www.jianshu.com/u/a9f6de37f77b)，https://www.jianshu.com/p/410a56129757