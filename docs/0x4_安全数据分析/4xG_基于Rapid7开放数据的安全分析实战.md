# 基于Rapid7数据集的安全分析实战



## 目标概要

-   数据搭建：
    -   基于Rapid7数据集，搭建一套安全数据系统
-   安全分析：
    -   使用该数据集进行具体场景下的安全分析，主要关注于：
        -   从FDNS数据中挖掘恶意域名
        -   从RDNS中挖掘动态IP
-   数据评估：
    -   对恶意域名进行手动验证，并输入到MISP中进行情报关联
    -   对动态IP，使用IPinfo查询画像数据



##  数据系统搭建

数据系统搭建需要考虑到数据总量、并发量、数据实时性等。由于不是工程化项目，一切从简，数据系统搭建主要是为了后面更高效率的分析。

考虑到Rapid7开放数据集的以下特点：

-   数据总量大，单天某类型一个数据包最高能到几百GB
-   国内下载速度慢，且暂无镜像源
-   官方没有提供管理框架或集成的CLI

考虑到我们使用这部分的数据，最开始是一个探索和实验性质的，所以直接找一些云上的服务/接口，例如AWS的[Rapid7 FDNS ANY](https://registry.opendata.aws/rapid7-fdns-any/)。

### 使用AWS服务

-   数据服务介绍：[Rapid7 FDNS ANY Dataset](https://registry.opendata.aws/rapid7-fdns-any/)
-   使用案例：[How to Conduct DNS Reconnaissance for $.02 Using Rapid7 Open Data and AWS](https://www.rapid7.com/blog/post/2018/10/16/how-to-conduct-dns-reconnaissance-for-02-using-rapid7-open-data-and-aws/)

使用aws cli可以直接查看数据包的情况：

```bash
$ aws s3 ls s3://rapid7-opendata/ --no-sign-request
```

其中`s3://`后面的路径就可以理解为相对路径。但是在s3中的数据是打包好的，有利于存储，但不适用于查询，所以需要使用数据查询平台，这里配套使用AWS的AWS Athena。

注：AWS Athena是一项无服务查询服务，可让使用标准SQL查询，按查询次数付费。

登入[AWS Athena控制台](https://us-east-2.console.aws.amazon.com/athena/):

![image-20210710215717783](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/image-20210710215717783.png)

图：AWS Athena控制面板



设置查询结果的路径为：`s3://rapid7-opendata/fdns/any/v1/`，在编辑器中，创建查询的表：

```sql
CREATE EXTERNAL TABLE IF NOT EXISTS rapid7_fdns_any (
  `timestamp` timestamp,
  `name` string,
  `type` string,
  `value` string 
) PARTITIONED BY (
  date string 
)
ROW FORMAT SERDE 'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe'
WITH SERDEPROPERTIES (
  'serialization.format' = '1'
) LOCATION 's3://rapid7-opendata/fdns/any/v1/'
TBLPROPERTIES ('has_encrypted_data'='false');
```

点击执行后，发生错误：

```bash
Unable to verify/create output bucket rapid7 (Service: AmazonAthena; Status Code: 400; Error Code: InvalidRequestException; Request ID: XXX; Proxy: null)
```

考虑是否是s3资源位置不对应：

```bash
亚马逊资源名称 (ARN)
arn:aws:s3:::rapid7-opendata/fdns/any/v1/
AWS 区域
us-east-1
```

后经排查，发现自己漏掉了建立查询API的过程，也就是建库和表、部署查询语句的过程，教程参考：[Creating a Project Sonar FDNS API with AWS](https://sra.io/blog/creating-a-project-sonar-fdns-api-with-aws/)

先查看一下集群中的数据资源：

```bash
$ aws s3 ls s3://rapid7-opendata/fdns/any/v1/date=202106 --no-sign-request
```

注意时间，看的是6月份的。

利用 AWS Glue可以现有数据源，我们通过这个功能建立一个对FDNS数据的爬虫，在AWS面板上的入口为：`Glue - crawlers - add crawler`

// TODO，此处显示爬虫报错，暂未解决，待更新



### 使用本地ELK

为方便配置，直接使用[bitnami的ELK虚拟机](https://docs.bitnami.com/virtual-machine/apps/elk/)，将虚拟机配置好后，开始对Rapid7开放数据集进行导入。

此处我们选用的数据集类型包括：

-   fdns
-   ...

logstash配置文件：

```yml
input {
    beats {
        port => "5044"
        type => "json"
    }
}
filter {
    json {
        source => "message"
    }
}
output {
    elasticsearch {
        hosts => [ "localhost:9200" ]
        index => "2021-06-27-1624758421-http_get_8888"
    }
}
```



🚩加上对data字段的Base64解密`decode64-http_get_8888.yml`，参考：[filebeat + logstash 日志采集链路配置](https://www.cnblogs.com/JealousSky/p/14077178.html)：

```yml
input {
    beats {
        port => "5044"
        type => "json"
    }
}
filter{
	json{
        source => "message"
        remove_field => ["message"]
    }
    ruby {
        init => "require 'base64'"
        code => "event.set('b64_decoded', Base64.decode64(event.get('data'))) if event.include?('data')"
        remove_field => ["data","request"]
    }
    json {
        source => "b64_decoded"
        remove_field => ["b64_decoded"]
    }
}
output {
    elasticsearch {
        hosts => [ "localhost:9200" ]
        index => "decode64-http_get_8888"
    }
}
```



🚩filebeat配置文件`decode64-http_get_8888.yml`：

```yml
filebeat.inputs:
- type: log
  paths:
    - /home/bitnami/data/decode64-http_get_8888.json
output.logstash:
  hosts: ["localhost:5044"]
```


通过filebeat插件转换，已作废！
```yml
filebeat.inputs:
- type: json
  paths:
    - /home/bitnami/data/example4-http_get_8888.json
  processors:
    - decode_base64_field:
        field:
          from: "data"
          to: "decode.data"
        ignore_missing: false
        fail_on_error: true
output.logstash:
  hosts: ["localhost:5044"]
```



先运行logstash

```bash
sudo logstash -f ./decode64-http_get_8888.yml --config.reload.automatic
```

再跑filebeat

```bash
sudo filebeat -e -c ./decode64-http_get_8888.yml -d "publish"
```

另外，需要注意两者配置文件的用户、用户组以及所在文件夹权限的问题，否则也会报错。

以下是成功导入，并且将data字段进行base64解码后的结果（b64_decodedz字段）：

![image-20210711222848429](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/image-20210711222848429.png)

图：导入FDNS数据后的Kibana面板

我们在Kibana的Dev Tools中进行DSL语法查询，尝试进行检索：

```json
GET _search
{
  "size": 0, 
  "query": {
    "bool": {
      "should": [
        {
          "query_string": {
            "default_field": "b64_decoded.keyword",
            "query": "*管理*"
          }
        }
      ],
      "minimum_should_match": 1
    }
  },
  "aggs": {
    "attacker_ip_aggs": {
      "terms": {
        "field": "host.keyword",
        "size": 1000
      }
    }
  }
}
```

以上的DSL语句，即检索解码后的HTTP数据中是否包含“管理”关键词，并且查找的记录中聚合host地址显示：

<img src="https://image-host-toky.oss-cn-shanghai.aliyuncs.com/image-20210711223248983.png" alt="image-20210711223248983" style="zoom:50%;" />

图：检索并聚合和Host字段值



## 安全分析过程

// TODO

-   基于DNS数据的动态IP、恶意



## 数据评估方法

// TODO
