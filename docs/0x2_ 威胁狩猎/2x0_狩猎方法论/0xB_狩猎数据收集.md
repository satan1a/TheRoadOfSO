# 狩猎数据收集



## OSINT数据

// ToDo



## 蜜罐数据采集

### 部署Fapro节点

自动化运维工具可以参考：[Ansible](https://www.cnblogs.com/jijiguowang/p/10406063.html)

配置文件可参考：[fapro.json](https://github.com/satan1a/TheRoadOfSO/tree/master/docs/assets/fapro.json)


### 采集日志数据

#### 编写logstash管道文件

文件名为：`honeypot-seoul01-2022-01-30.yml`

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
        remove_field => ["message"]
    }
}
output {
    elasticsearch {
        hosts => ["XXXXXX:9200"]
        index => "honeypot-2022-01-30"
        user => "elastic"
        password => "YOUR_PASSWORD"
    }
}
```



#### 编写filebeat管道文件

其中`paths`字段为需要导入的数据文件路径，其中的`hosts`字段为ES的主机地址和端口，文件名为：`filebeat-honeypot-seoul01-2022-01-30.yml`

```yml
filebeat.inputs:
- type: log
  paths:
    - /home/ubuntu/fapro.log
output.logstash:
  hosts: ["XXXXXX:5044"]
```

#### 加载管道文件

先运行logstash

```bash
/usr/share/logstash/bin/logstash -f honeypot-2022-01-30.yml --config.reload.automatic
```

再跑filebeat

```bash
/usr/share/filebeat/filebeat -e -c /home/ubuntu/filebeat-honeypot-2022-01-30.yml -d "publish"
```



## 系统日志采集

// ToDo

-   Windows安全日志

-   Windows powershell日志
-   Windows sysmon日志
-   linux audit日志
-   HTTP_log
-   应用日志(例如中间件日志)
